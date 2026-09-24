import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyChain, verifyChainText, verifyCheckpoint, verifyHistoricalChain } from "../src/verify.js";
import { safeParse } from "../src/safe-json.js";
import { generateKeyPair, signEd25519 } from "../src/keys.js";
import { buildReceipt, buildCheckpoint, type BuildInput } from "../src/builder.js";
import { sha256Prefixed } from "../src/hash.js";
import { receiptHashInput } from "../src/canonicalize.js";
import { signingMessage, RECEIPT_SIG_DOMAIN } from "../src/signing.js";
import type { Keyring, Checkpoint, Receipt } from "../src/index.js";
import { b } from "./helpers/bytes.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const VEC = join(__dirname, "..", "..", "conformance", "vectors");

function load(rel: string): unknown {
  return JSON.parse(readFileSync(join(VEC, rel), "utf8"));
}
function raw(rel: string): string {
  return readFileSync(join(VEC, rel), "utf8");
}
/**
 * A conformance vector as the DOCUMENT it is: the file's own bytes, unparsed and unmodified.
 *
 * This is what every entry point now takes (ADR §3.1), and reading the file straight into bytes is
 * strictly more faithful than the old `JSON.parse`-then-hand-over-the-object: the verifier sees the
 * exact bytes the vector ships, so the suite exercises the same input a CLI or a wire consumer
 * would hand it, `safeParse` guarantees included.
 */
function doc(rel: string): Uint8Array {
  return readFileSync(join(VEC, rel));
}

/** The trust root and the signed checkpoint as documents — neither has an object form at the boundary. */
const keyring = doc("keyring.json");
const checkpoint = doc("checkpoint.json");
/** ...and the checkpoint's parsed form, used ONLY to derive malformed variants that are re-encoded to bytes. */
const checkpointObj = load("checkpoint.json") as Checkpoint;

test("valid chain + keyring -> VALID, signatures verified", () => {
  const r = verifyChain(doc("valid-chain.json"), { keyring });
  assert.equal(r.status, "VALID", r.reason ?? "");
  assert.equal(r.signaturesVerified, true);
  assert.equal(r.count, 3);
  // honest caveat: tail truncation not checked without a checkpoint
  assert.equal(r.tailChecked, false);
  assert.ok(r.warnings.some((w) => /tail-truncation/.test(w)));
});

test("valid chain + keyring + checkpoint -> VALID, tail checked", () => {
  const r = verifyChain(doc("valid-chain.json"), { keyring, checkpoint });
  assert.equal(r.status, "VALID", r.reason ?? "");
  assert.equal(r.tailChecked, true);
});

test("valid chain WITHOUT keyring -> UNVERIFIED (honest: signatures not authenticated)", () => {
  const r = verifyChain(doc("valid-chain.json"), {});
  assert.equal(r.status, "UNVERIFIED");
  assert.equal(r.signaturesVerified, false);
  assert.ok(r.warnings.some((w) => /not authenticated/i.test(w)));
});

// Every attack vector MUST be rejected. This is the core security property.
const ATTACKS = [
  "attack/tampered-content.json",
  "attack/forged-genesis.json",
  "attack/key-swap.json",
  "attack/key-swap-resigned.json",
  "attack/unknown-kid.json",
  "attack/seq-gap.json",
  "attack/head-truncated.json",
  "attack/cross-chain-splice.json",
  "attack/dup-seq.json",
  "attack/wrong-signature.json",
  "attack/relinked.json",
];
for (const a of ATTACKS) {
  test(`attack rejected (with keyring): ${a}`, () => {
    const r = verifyChain(doc(a), { keyring, checkpoint });
    assert.notEqual(r.status, "VALID", `${a} must not verify as VALID`);
    assert.notEqual(r.status, "UNVERIFIED", `${a} must not pass as UNVERIFIED`);
    assert.equal(r.status, "TAMPERED", `${a} -> expected TAMPERED, got ${r.status}: ${r.reason}`);
  });
}

// Strict public-key validation (scripts/gen-vectors.ts 11, conformance/vectors/strict-ed25519/):
// a keyring whose key is a non-canonical, off-curve, small-order or mixed-order encoding makes the
// valid chain TAMPERED (the verdict does not show the stage; test/keys.test.ts pins key-load refusal);
// a signature scalar S >= L is refused as well.
const STRICT_ED25519_KEYRINGS = [
  "keyring-low-order-0.json", "keyring-low-order-1.json", "keyring-low-order-2.json", "keyring-low-order-3.json",
  "keyring-low-order-4.json", "keyring-low-order-5.json", "keyring-low-order-6.json", "keyring-low-order-7.json",
  "keyring-x0-sign-y-1.json", "keyring-x0-sign-y-p-minus-1.json", "keyring-y-p-sign.json", "keyring-y-p-plus-1.json",
  "keyring-off-curve-y-2.json", "keyring-mixed-order.json",
];
test("strict-ed25519: every refused key encoding makes the genuine chain TAMPERED", () => {
  for (const name of STRICT_ED25519_KEYRINGS) {
    const r = verifyChain(doc("valid-chain.json"), { keyring: doc(`strict-ed25519/${name}`) });
    assert.equal(r.status, "TAMPERED", `${name} -> expected TAMPERED, got ${r.status}: ${r.reason}`);
    assert.equal(r.signaturesVerified, false, name);
  }
});
test("strict-ed25519: a signature with a non-canonical scalar (S >= L) is TAMPERED", () => {
  const r = verifyChain(doc("strict-ed25519/chain-s-not-canonical.json"), { keyring });
  assert.equal(r.status, "TAMPERED", `${r.status}: ${r.reason}`);
  assert.equal(r.signaturesVerified, false);
});

test("unknown-kid: TAMPERED with keyring, UNVERIFIED without (no silent TOFU on attacker input)", () => {
  const withKey = verifyChain(doc("attack/unknown-kid.json"), { keyring });
  assert.equal(withKey.status, "TAMPERED");
  assert.match(withKey.reason ?? "", /unknown signing key/);
  const noKey = verifyChain(doc("attack/unknown-kid.json"), {});
  assert.equal(noKey.status, "UNVERIFIED");
});

test("signed body commits to seq + scope.chain: head-truncation and cross-chain splice are caught", () => {
  const ht = verifyChain(doc("attack/head-truncated.json"), { keyring });
  assert.equal(ht.status, "TAMPERED");
  assert.match(ht.reason ?? "", /seq|genesis/i);
  const xc = verifyChain(doc("attack/cross-chain-splice.json"), { keyring });
  assert.equal(xc.status, "TAMPERED");
  assert.match(xc.reason ?? "", /chain partition|duplicate seq/i);
});

test("key-swap-resigned is caught by key-pinning, not signature presence", () => {
  // attacker controls a real keypair; pinning per agent.id still rejects.
  const r = verifyChain(doc("attack/key-swap-resigned.json"), { keyring });
  assert.equal(r.status, "TAMPERED");
  assert.match(r.reason ?? "", /key swap/);
});

test("relinked is caught by linkage check (hash + sig are internally valid)", () => {
  const r = verifyChain(doc("attack/relinked.json"), { keyring });
  assert.equal(r.status, "TAMPERED");
  assert.match(r.reason ?? "", /linkage/);
});

test("wrong-signature requires a keyring to detect", () => {
  // without keyring, sig can't be authenticated → UNVERIFIED (honest)
  const noKey = verifyChain(doc("attack/wrong-signature.json"), {});
  assert.equal(noKey.status, "UNVERIFIED");
  // with keyring → TAMPERED
  const withKey = verifyChain(doc("attack/wrong-signature.json"), { keyring });
  assert.equal(withKey.status, "TAMPERED");
  assert.match(withKey.reason ?? "", /signature/);
});

test("forged checkpoint (out-of-keyring key) cannot fake a tail check — trust root applies to checkpoints", () => {
  const truncated = doc("attack/forged-checkpoint-chain.json");
  const forgedCp = doc("attack/forged-checkpoint-cp.json");
  // with keyring → TAMPERED (checkpoint must authenticate against the same trust root as receipts)
  const withKey = verifyChain(truncated, { keyring, checkpoint: forgedCp });
  assert.equal(withKey.status, "TAMPERED");
  assert.match(withKey.reason ?? "", /checkpoint not authenticated/);
  // without keyring → UNVERIFIED, and tailChecked MUST be false (no silently-faked tail check)
  const noKey = verifyChain(truncated, { checkpoint: forgedCp });
  assert.equal(noKey.status, "UNVERIFIED");
  assert.equal(noKey.tailChecked, false);
});

test("verifyChain returns MALFORMED (never throws) on a lone-surrogate receipt", () => {
  // Historically this fixture was handed over as an OBJECT precisely to bypass safeParse and reach the
  // canonicalizer with a lone surrogate. Bytes-in removes that route: `JSON.stringify` escapes the
  // unpaired code unit to the six ASCII characters `\ud800`, and safeParse rejects the escape at the
  // boundary. The verdict the test pins is unchanged (MALFORMED, never a throw); what changed is that
  // it is now unreachable-by-construction rather than caught downstream.
  const r = load("valid-chain.json") as Array<Record<string, any>>;
  r[0]!.action.canonical = "transfer\uD800";
  const res = verifyChain(b(r), { keyring });
  assert.equal(res.status, "MALFORMED");
  assert.match(res.reason ?? "", /surrogate/i);
});

test("tail-truncation: undetectable without checkpoint, detected with checkpoint", () => {
  const noCp = verifyChain(doc("attack/tail-truncated.json"), { keyring });
  // honest: without a checkpoint a truncated-but-otherwise-valid prefix verifies, WITH a warning
  assert.equal(noCp.status, "VALID");
  assert.ok(noCp.warnings.some((w) => /tail-truncation/.test(w)));
  const withCp = verifyChain(doc("attack/tail-truncated.json"), { keyring, checkpoint });
  assert.equal(withCp.status, "TAMPERED");
  assert.match(withCp.reason ?? "", /tail|head/);
});

// Malformed inputs: the strict parser or the verifier rejects them.
test("malformed: duplicate key rejected by safeParse", () => {
  assert.throws(() => safeParse(raw("malformed/duplicate-key.json")));
});
test("malformed: float rejected by safeParse", () => {
  assert.throws(() => safeParse(raw("malformed/float-number.json")));
});
test("malformed: proto-pollution rejected by safeParse", () => {
  assert.throws(() => safeParse(raw("malformed/proto-pollution.json")));
});
test("malformed: trailing garbage rejected by safeParse", () => {
  assert.throws(() => safeParse(raw("malformed/trailing-garbage.json")));
});
test("malformed: deep nesting rejected by safeParse", () => {
  assert.throws(() => safeParse(raw("malformed/deep-nest.json")));
});
test("malformed: unpaired surrogates rejected by safeParse (forgery channel closed)", () => {
  assert.throws(() => safeParse(raw("malformed/lone-high-surrogate.json")));
  assert.throws(() => safeParse(raw("malformed/lone-low-surrogate.json")));
  assert.throws(() => safeParse(raw("malformed/reversed-surrogate-pair.json")));
});
test("malformed: pii-smuggle (unknown field) -> MALFORMED at verify", () => {
  // The vector parses cleanly (it is well-formed JSON); the smuggled field is caught by the receipt
  // schema, not by the parser. Feeding the file's own bytes routes through the SAME safeParse the
  // test used to call by hand, so the verdict is unchanged.
  assert.doesNotThrow(() => safeParse(raw("malformed/pii-smuggle.json")));
  const r = verifyChain(doc("malformed/pii-smuggle.json"), { keyring });
  assert.equal(r.status, "MALFORMED");
  assert.match(r.reason ?? "", /unknown field/);
});

test("verifyChainText routes through the strict parser: duplicate keys -> MALFORMED at the library level", () => {
  // the strict-parse guarantee (dup-key reject) is a property of verifyChainText, not just the CLI
  const dup = raw("malformed/duplicate-key.json");
  assert.equal(verifyChainText(dup).status, "MALFORMED");
  // and a valid chain text verifies
  assert.equal(verifyChainText(raw("valid-chain.json"), { keyring }).status, "VALID");
});

test("non-array input -> MALFORMED", () => {
  assert.equal(verifyChain(b({ not: "an array" })).status, "MALFORMED");
});
test("empty array -> MALFORMED", () => {
  assert.equal(verifyChain(b([])).status, "MALFORMED");
});
test("a caller-owned OBJECT is refused at the boundary, never silently serialized", () => {
  // The same two documents in their pre-migration form. `[]` and `{not:"an array"}` are perfectly
  // ordinary JavaScript values, which is the point: the boundary does not ask whether an object is
  // hostile, it declines to take an object at all (ADR §3.1). Both still land on MALFORMED, so no
  // caller learns about this by getting a DIFFERENT verdict class — only a different reason.
  for (const bad of [[], { not: "an array" }, 42, null, undefined, true, new Date()]) {
    const r = verifyChain(bad as never);
    assert.equal(r.status, "MALFORMED", `verifyChain accepted ${String(typeof bad)}`);
    assert.match(r.reason ?? "", /expected Uint8Array or string/);
  }
});

// ── structural fail-closed regressions ───────────────────────────────────────
test("verifyCheckpoint is fail-closed on null/non-object (malformed, never throws)", () => {
  // BOTH forms. As BYTES the document parses to a non-object and the structural validator rejects it;
  // as a raw JavaScript value it never gets past the byte boundary. One verdict either way, so the
  // fail-closed contract this test exists to pin is preserved on both routes.
  for (const bad of [null, "x", []]) {
    assert.equal(verifyCheckpoint(b(bad), keyring), "malformed checkpoint", `bytes: ${JSON.stringify(bad)}`);
  }
  for (const bad of [null, undefined, "x" as unknown, [], { spec: "noa.checkpoint/0.1" }]) {
    assert.equal(verifyCheckpoint(bad as never, keyring), "malformed checkpoint", `raw value: ${String(bad)}`);
  }
});

test("checkpoint is strictly schema-validated (unknown field / bad ts / bad headHash → malformed)", () => {
  assert.equal(verifyCheckpoint(checkpoint, keyring), "ok"); // genuine checkpoint still authenticates
  const extra = { ...checkpointObj, smuggled: "ssn=123-45-6789" };
  assert.equal(verifyCheckpoint(b(extra), keyring), "malformed checkpoint"); // additionalProperties:false even in the SIGNED surface
  const badTs = { ...checkpointObj, ts: 1718000000 };
  assert.equal(verifyCheckpoint(b(badTs), keyring), "malformed checkpoint"); // numeric ts rejected
  const badHead = { ...checkpointObj, headHash: "deadbeef" };
  assert.equal(verifyCheckpoint(b(badHead), keyring), "malformed checkpoint"); // headHash must be sha256:<64hex>
});

test("a non-canonical base64 signature is TAMPERED (sig.value must round-trip to canonical)", () => {
  const chain = load("valid-chain.json") as Array<Record<string, any>>;
  // embedded whitespace: Buffer.from decodes leniently to the SAME 64 bytes, but it is not canonical base64.
  chain[0]!.sig.value = chain[0]!.sig.value.slice(0, 4) + " " + chain[0]!.sig.value.slice(4);
  assert.equal(verifyChain(b(chain), { keyring }).status, "TAMPERED");
});

test("T14: a malleated signature (S' = S+L) on an otherwise-genuine receipt is TAMPERED", () => {
  // Same technique as impl-py/conformance.mjs's S-malleability vector, exercised at the verifyChain level:
  // R stays genuine, S is replaced by the congruent-mod-L S+L — the same equation, a non-canonical encoding.
  const L = 2n ** 252n + 27742317777372353535851937790883648493n;
  const chain = load("valid-chain.json") as Array<Record<string, any>>;
  const sigBytes = Buffer.from(chain[0]!.sig.value, "base64");
  let S = 0n;
  for (let i = 63; i >= 32; i--) S = (S << 8n) | BigInt(sigBytes[i]!);
  let Sp = S + L;
  const spBytes = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) { spBytes[i] = Number(Sp & 0xffn); Sp >>= 8n; }
  chain[0]!.sig.value = Buffer.concat([sigBytes.subarray(0, 32), spBytes]).toString("base64");
  assert.equal(verifyChain(b(chain), { keyring }).status, "TAMPERED");
});

test("verifyChain on a receipt with a throwing accessor → MALFORMED (never throws out), and the accessor never fires", () => {
  // A getter is not expressible as bytes — that is the whole content of this migration, so the test
  // now pins the stronger property it always wanted: not "the throw was caught" but "the caller's
  // code was never invoked". `fired` must stay 0. A probe that cannot prove it fired proves nothing,
  // so the counter is asserted rather than assumed.
  let fired = 0;
  const hostile = [{ get spec() { fired++; throw new Error("boom"); } }];
  let res!: ReturnType<typeof verifyChain>;
  assert.doesNotThrow(() => { res = verifyChain(hostile as never, { keyring }); });
  assert.equal(res.status, "MALFORMED");
  assert.match(res.reason ?? "", /expected Uint8Array or string/);
  assert.equal(fired, 0, "the boundary read a caller-owned accessor — bytes-in is decorative");
});

test("an array-like with a throwing `length` getter → MALFORMED (never throws out), and no trap fires", () => {
  // BEFORE bytes-in this modelled a real hazard: the early length/maxReceipts bounds read
  // `receipts.length` on the LIVE array, `Array.isArray` sees THROUGH a Proxy to its array target, and
  // the Proxy's `length` get-trap threw — so a raw Error escaped. The fix then was a guarded one-shot
  // capture that reported `length is not readable`.
  //
  // That reason no longer exists, because the read no longer exists. `decodeDocument`'s type test is the
  // %TypedArray% `Symbol.toStringTag` getter, which consults an INTERNAL SLOT: a Proxy has no
  // [[TypedArrayName]] slot, so the getter returns `undefined` without dispatching a single trap. The
  // assertion is updated from the old reason-string to the boundary's own, and a trap counter is added —
  // `traps === 0` is a strictly stronger statement than "the throw was caught".
  let traps = 0;
  const hostile = new Proxy([] as unknown[], {
    get(t, k, r) { traps++; if (k === "length") throw new Error("boom"); return Reflect.get(t, k, r); },
  });
  let res!: ReturnType<typeof verifyChain>;
  assert.doesNotThrow(() => { res = verifyChain(hostile as never, { keyring }); });
  assert.equal(res.status, "MALFORMED");
  assert.match(res.reason ?? "", /expected Uint8Array or string/);
  assert.equal(traps, 0, "a Proxy trap ran inside the boundary");
});

test("a `length` getter that returns a VALID number on the first read, then throws on every later read → MALFORMED, and is read ZERO times", () => {
  // THE ATTACK THIS TEST DESCRIBES IS A TOCTOU: a length-accessor that lies clean on read #1 (satisfying
  // every bounds check) and throws afterward, so the fail-closed catch — whose entire job is "never
  // throw" — became the thing that throws. The old fix captured `n` from ONE guarded read and never
  // re-read `receipts.length`; the invariant it pinned was "read at most once".
  //
  // Bytes-in retires the premise rather than the defence. A byte sequence has no `length` accessor to
  // flip, and the Proxy carrying one is refused by an internal-slot type test that dispatches no trap.
  // So the assertion changes from `reads >= 1` ("the guarded capture happened") to `reads === 0` ("there
  // was nothing to guard"). This is the migration's central claim stated as a test: the TOCTOU class is
  // not mitigated, it is unrepresentable — the object that would carry it never enters.
  //
  // Everything else the test pinned is retained verbatim: never a raw throw, and a safe captured count.
  let reads = 0;
  const flipping = new Proxy([{ id: "r0" }], {
    get(t, k, r) {
      if (k === "length") {
        reads++;
        if (reads === 1) return Reflect.get(t, k, r); // valid on the guarded first read
        throw new Error("boom-on-later-read");
      }
      return Reflect.get(t, k, r);
    },
  });
  let res!: ReturnType<typeof verifyChain>;
  assert.doesNotThrow(() => { res = verifyChain(flipping as never, { keyring }); });
  assert.equal(res.status, "MALFORMED");
  assert.ok(Number.isSafeInteger(res.count) && res.count >= 0, `count must be a safe captured number, got ${res.count}`);
  assert.equal(reads, 0, "the boundary read the caller's `length` — it must never touch the object at all");

  // Same hostile array-like, PLUS a throwing identityManifest entry-getter in opts. Options are still
  // objects, so this half stays a genuine hostile-OBJECT probe: `inertOptions` runs first and refuses the
  // manifest because a document member must be bytes, WITHOUT reading the `a1` entry. Neither hostile
  // input is ever touched.
  reads = 0;
  let manifestReads = 0;
  const evilManifest: Record<string, unknown> = {};
  Object.defineProperty(evilManifest, "a1", { enumerable: true, configurable: true, get() { manifestReads++; throw new Error("boom-manifest"); } });
  let res2!: ReturnType<typeof verifyChain>;
  assert.doesNotThrow(() => { res2 = verifyChain(flipping as never, { keyring, identityManifest: evilManifest as never }); });
  assert.equal(res2.status, "MALFORMED");
  assert.equal(reads, 0, "opts is admitted before receipts is ever touched, so the length getter must not fire here");
  assert.equal(manifestReads, 0, "the manifest entry-getter fired — the options boundary read caller code");
});

test("checkpoint sig sub-object is strict (extra field / bad alg → malformed)", () => {
  const sigExtra = { ...checkpointObj, sig: { ...checkpointObj.sig, smuggled: "ssn=123" } };
  assert.equal(verifyCheckpoint(b(sigExtra), keyring), "malformed checkpoint"); // additionalProperties on sig
  const badAlg = { ...checkpointObj, sig: { ...checkpointObj.sig, alg: "rsa" } };
  assert.equal(verifyCheckpoint(b(badAlg), keyring), "malformed checkpoint"); // unvalidated alg closed
});

test("throwing identityManifest / array-element accessors → MALFORMED (never throws), and neither accessor fires", () => {
  let elemReads = 0;
  const arr: unknown[] = [];
  Object.defineProperty(arr, "0", { enumerable: true, configurable: true, get() { elemReads++; throw new Error("boom"); } });
  let r1!: ReturnType<typeof verifyChain>;
  assert.doesNotThrow(() => { r1 = verifyChain(arr as never, { keyring }); });
  assert.equal(r1.status, "MALFORMED");
  assert.equal(elemReads, 0, "an array-element accessor fired inside the boundary");
  let manReads = 0;
  const man: Record<string, unknown> = {};
  Object.defineProperty(man, "a1", { enumerable: true, configurable: true, get() { manReads++; throw new Error("boom"); } });
  let r2!: ReturnType<typeof verifyChain>;
  assert.doesNotThrow(() => { r2 = verifyChain(doc("valid-chain.json"), { keyring, identityManifest: man as never }); });
  assert.equal(r2.status, "MALFORMED");
  assert.equal(manReads, 0, "a manifest entry accessor fired inside the options boundary");
});

// ── live-object TOCTOU snapshot-once + non-object keyring regressions ────────────────
test("a flipping checkpoint accessor cannot yield VALID over a truncated tail (the boundary refuses it unread)", () => {
  // The chain presents seq 0..2; the legit checkpoint asserts head=seq2. A truncating attacker presents a
  // checkpoint whose highestSeq/headHash FLIP on read: returning the legit head (seq2/realHash) to the
  // signature/validation path, but the truncated head to the tail-match. Snapshotting the checkpoint ONCE
  // means both reads see the SAME bytes → no VALID-over-erased-tail.
  const validChain = load("valid-chain.json") as Array<Record<string, any>>;
  const truncated = validChain.slice(0, 1); // attacker drops seq 1..2, presents only seq 0
  const realCp = checkpointObj as any;
  const truncatedHead = truncated[0]!.chain;
  let seqReads = 0, hashReads = 0;
  const flip: any = {
    spec: realCp.spec, chain: realCp.chain, ts: realCp.ts, sig: realCp.sig,
    // First read (validation/preimage) returns the legit head; later read (tail-match) returns the truncated head.
    get highestSeq() { return seqReads++ === 0 ? realCp.highestSeq : truncatedHead.seq; },
    get headHash() { return hashReads++ === 0 ? realCp.headHash : truncatedHead.hash; },
  };
  // A checkpoint that answers differently to two reads is not expressible as bytes, so the attack is
  // now refused one step earlier: the options boundary declines the object outright. Both original
  // assertions are unchanged (not VALID, tail not checked); the accessor counters are added to prove
  // the refusal happened WITHOUT executing the flip, which is the property that makes it total.
  const res = verifyChain(b(truncated), { keyring, checkpoint: flip });
  assert.notEqual(res.status, "VALID", `flipping checkpoint must not verify VALID (got ${res.status})`);
  assert.equal(res.tailChecked, false, "tail must not be reported as checked over a flipped/truncated head");
  assert.equal(seqReads + hashReads, 0, "the flipping accessors fired — the options boundary read caller code");

  // THE SECURITY PROPERTY ITSELF, over bytes: an attacker who can only present a FIXED document cannot
  // pair a truncated chain with the legitimate checkpoint and be told the tail was checked. Without the
  // flip there is no split to exploit, and the genuine checkpoint over an erased tail is TAMPERED.
  const overBytes = verifyChain(b(truncated), { keyring, checkpoint });
  assert.equal(overBytes.status, "TAMPERED", overBytes.reason ?? "");
  assert.equal(overBytes.tailChecked, false);
});

test("verifyCheckpoint with a throwing accessor → 'malformed checkpoint' (never throws a raw Error), and the accessor never fires", () => {
  let fired = 0;
  const evil: any = {
    spec: "noa.checkpoint/0.1", chain: "c", highestSeq: 0, ts: "2026-06-21T10:00:00.000Z",
    sig: { alg: "ed25519", kid: "k", value: "x" },
    get headHash(): string { fired++; throw new Error("boom"); },
  };
  let verdict!: ReturnType<typeof verifyCheckpoint>;
  assert.doesNotThrow(() => { verdict = verifyCheckpoint(evil as never, keyring); });
  assert.equal(verdict, "malformed checkpoint");
  assert.equal(fired, 0, "the checkpoint accessor fired inside the boundary");
});

test("a flipping agent.id accessor cannot produce a false VALID attribution — the boundary refuses it unread", () => {
  // A genuine single-receipt chain whose agent.id FLIPS between reads: returns the real (manifest-authorized)
  // id to the structural/sig path, but a different id later. The old defence was `structuredClone`, which
  // read each field exactly once so that the value ENFORCED was the value VALIDATED — the branchy assertion
  // below ("VALID with idReads<=1, else TAMPERED") existed because the outcome depended on whether the
  // snapshot happened to land before or after the hash check.
  //
  // ASSERTION CHANGED, deliberately and in the strict direction: there is no longer a VALID branch and no
  // longer a TAMPERED branch. A live accessor cannot be delivered through a byte boundary, so the verdict
  // is MALFORMED and `idReads` is 0 — the getter is not read once, it is not read at all. The property
  // under test ("no false VALID attribution from a mid-flip read") is preserved and strengthened; what is
  // gone is the conditional, which only made sense while the object was being traversed.
  const validChain = load("valid-chain.json") as Array<Record<string, any>>;
  const r0 = validChain[0]! as any;
  const realAgentId = r0.agent.id;
  let idReads = 0;
  const agentNoId: any = { model: r0.agent.model, principal: r0.agent.principal };
  Object.defineProperty(agentNoId, "id", {
    enumerable: true, configurable: true,
    get() { return idReads++ === 0 ? realAgentId : "attacker-spoofed"; },
  });
  const flipReceipt: any = { ...r0, agent: agentNoId };
  let res!: ReturnType<typeof verifyChain>;
  assert.doesNotThrow(() => { res = verifyChain([flipReceipt] as never, { keyring }); });
  assert.equal(res.status, "MALFORMED");
  assert.match(res.reason ?? "", /expected Uint8Array or string/);
  assert.equal(idReads, 0, "agent.id must never be read — the boundary does not traverse caller objects");

  // THE SAME ATTACK EXPRESSED AS BYTES, which is the only form an attacker has left: a FIXED spoofed
  // agent.id. It cannot flip, so it cannot show one id to the signature check and another to attribution —
  // it simply breaks the signed body and is caught as TAMPERED. Never a false VALID either way.
  const spoofed = { ...r0, agent: { ...r0.agent, id: "attacker-spoofed" } };
  const spoofRes = verifyChain(b([spoofed]), { keyring });
  assert.equal(spoofRes.status, "TAMPERED", spoofRes.reason ?? "");
});

test("a non-object keyring (array / null) → MALFORMED (parity with the Python verifier)", () => {
  // The cross-impl property this test defends is that a malformed TRUST FILE gets the same verdict CLASS
  // in TS and in Python. A trust file is a document, so the faithful form is now its bytes: `[]` and
  // `null` as JSON. Both parse and are then rejected by the same non-object keyring guard, with the same
  // reason string as before — the assertion is carried over unchanged.
  for (const bad of [[], null]) {
    const r = verifyChain(doc("valid-chain.json"), { keyring: b(bad) });
    assert.equal(r.status, "MALFORMED", `keyring=${JSON.stringify(bad)}`);
    assert.match(r.reason ?? "", /keyring must be an object/);
  }
  // The same values as raw JavaScript never reach that guard: a keyring supplied as an object is refused
  // by the options boundary itself. Same verdict class, earlier and for a stronger reason.
  for (const bad of [[], null, {}, 5]) {
    const r = verifyChain(doc("valid-chain.json"), { keyring: bad as never });
    assert.equal(r.status, "MALFORMED", `raw keyring=${JSON.stringify(bad)}`);
    assert.match(r.reason ?? "", /expected Uint8Array or string/);
  }
  // sanity: a genuine keyring still verifies VALID (no regression on the happy path)
  assert.equal(verifyChain(doc("valid-chain.json"), { keyring }).status, "VALID");
});

// ── keyring/opts snapshot regressions ─────────────────────────────────────────
test("a flipping keyring getter cannot authenticate the walk with one key and a forged checkpoint with another (the boundary refuses it unread)", () => {
  // Real signed material: a 3-receipt chain signed by the LEGIT key. An attacker truncates the tail (keeps
  // the legit prefix, intact + legit-signed), then forges a checkpoint over the TRUNCATED head signed by its
  // OWN (attacker) key but LABELED with the legit kid. A flipping `keyring[legitKid]` getter returns the legit
  // pubkey to the receipt walk (the prefix authenticates) and the attacker pubkey to verifyCheckpoint (the
  // forged checkpoint authenticates) → VALID + tailChecked over an ERASED tail, key-continuity pin satisfied.
  // Reading the keyring ONCE (snapshot) means the SAME pubkey serves both → the forged checkpoint cannot pass.
  const legitKid = "legit-key";
  const legit = generateKeyPair(legitKid);
  const attacker = generateKeyPair("attacker-key"); // different keypair, SAME kid label used in the checkpoint

  const mk = (id: string, seqAmount: number, prev: ReturnType<typeof buildReceipt> | null) => {
    const input: BuildInput = {
      id, ts: "2026-06-21T10:00:0" + seqAmount + ".000Z", scope: { tenant: "t", chain: "c16" },
      agent: { id: "agent-1", model: null, principal: "SERVICE" },
      action: { id: "payment.refund", canonical: "payment.refund", riskClass: "HIGH", paramsHash: sha256Prefixed("p" + seqAmount), reversible: false, rollbackRef: null },
      governance: { mode: "on", verdict: "EXECUTED", ruleId: "r", approval: null, sandboxed: false },
    };
    return buildReceipt(input, prev, { kid: legitKid, privateKey: legit.privateKey });
  };
  const r0 = mk("rc16_0", 0, null);
  const r1 = mk("rc16_1", 1, r0);
  const r2 = mk("rc16_2", 2, r1);
  const full = [r0, r1, r2];
  const truncated = [r0, r1]; // attacker drops r2 (the incriminating tail); head is now r1

  // Forge a checkpoint over the truncated head (r1), signed by the ATTACKER key, labeled with the legit kid.
  const forgedCp = buildCheckpoint(truncated[truncated.length - 1]!, "2026-06-21T11:00:00.000Z", { kid: legitKid, privateKey: attacker.privateKey });

  // Flipping keyring: read #1..N (the receipt walk over the 2-receipt prefix) → legit pubkey; the NEXT read
  // (verifyCheckpoint) → attacker pubkey. The walk reads keyring[legitKid] once per receipt (2 reads here),
  // then verifyCheckpoint reads it once more (read #3) — flip on the 3rd read.
  let reads = 0;
  const flipKeyring: Record<string, string> = {};
  Object.defineProperty(flipKeyring, legitKid, {
    enumerable: true, configurable: true,
    get() { return ++reads <= truncated.length ? legit.publicKey : attacker.publicKey; },
  });

  // Both original assertions stand unchanged. What is added: the flipping accessor is never invoked, so
  // "one pubkey serves both surfaces" is no longer a property the kernel maintains by snapshotting — it
  // is a property of the input, which is a fixed byte string with exactly one value per kid.
  const res = verifyChain(b(truncated), { keyring: flipKeyring as never, checkpoint: b(forgedCp) });
  assert.notEqual(res.status, "VALID", `flipping keyring must not authenticate a forged checkpoint over a truncated tail (got ${res.status})`);
  assert.equal(res.tailChecked, false, "the erased tail must NOT be reported as checked");
  assert.equal(reads, 0, "the flipping keyring accessor fired inside the options boundary");

  // THE ATTACK AS BYTES: the attacker's best remaining move is a FIXED keyring naming the legit kid. It
  // authenticates either the receipts or the forged checkpoint, never both — so the forged checkpoint
  // over the erased tail cannot pass, and the tail is not reported as checked.
  const fixed = verifyChain(b(truncated), { keyring: b({ [legitKid]: legit.publicKey }), checkpoint: b(forgedCp) });
  assert.notEqual(fixed.status, "VALID", `a fixed keyring must not authenticate the forged checkpoint (got ${fixed.status})`);
  assert.equal(fixed.tailChecked, false, "the erased tail must NOT be reported as checked");

  // Controls: the full legit chain + a genuinely legit checkpoint still verify VALID + tailChecked (no
  // happy-path regression from the migration).
  const legitKeyring = { [legitKid]: legit.publicKey };
  const legitCp = buildCheckpoint(full[full.length - 1]!, "2026-06-21T11:00:00.000Z", { kid: legitKid, privateKey: legit.privateKey });
  const good = verifyChain(b(full), { keyring: b(legitKeyring), checkpoint: b(legitCp) });
  assert.equal(good.status, "VALID", good.reason ?? "");
  assert.equal(good.tailChecked, true);
});

test("verifyChain / verifyChainText with null (or garbage) opts do not throw", () => {
  // A default-param only fills a MISSING arg, not an explicit null/garbage → reading opts.maxReceipts off null
  // used to raise a raw TypeError (and verifyChainText forwards opts, inheriting the throw). The
  // never-throws contract is what this test exists for and it is unchanged.
  let r1!: ReturnType<typeof verifyChain>;
  assert.doesNotThrow(() => { r1 = verifyChain(doc("valid-chain.json"), null as never); });
  assert.equal(r1.status, "UNVERIFIED"); // explicit null still means "no options" → honest UNVERIFIED

  // ASSERTION CHANGED (UNVERIFIED → MALFORMED) for the NON-NULL garbage case, and the change is the
  // point of the exact-options schema. `verifyChain(chain, 5)` is a caller mistake; silently discarding
  // it means the caller who wrote `5` where `{keyring}` belonged is told the chain is UNVERIFIED and
  // never learns their options were dropped on the floor. `null`/`undefined` keep meaning "no options"
  // (that is the documented empty case in src/opts.ts); anything else is a misconfiguration, reported
  // loudly and still without a throw.
  let r2!: ReturnType<typeof verifyChain>;
  assert.doesNotThrow(() => { r2 = verifyChain(doc("valid-chain.json"), 5 as never); });
  assert.equal(r2.status, "MALFORMED");
  assert.match(r2.reason ?? "", /options must be a plain object/);
  for (const junk of ["x", true, [], () => ({})]) {
    const r = verifyChain(doc("valid-chain.json"), junk as never);
    assert.equal(r.status, "MALFORMED", `opts=${String(junk)} must be a loud misconfiguration`);
  }

  let r3!: ReturnType<typeof verifyChainText>;
  assert.doesNotThrow(() => { r3 = verifyChainText(raw("valid-chain.json"), null as never); });
  assert.equal(r3.status, "UNVERIFIED");
  // sanity: a genuine opts object still works (no regression)
  assert.equal(verifyChain(doc("valid-chain.json"), { keyring }).status, "VALID");
});

test("a throwing-getter opts OR a Symbol maxReceipts → MALFORMED (never a raw throw), and the getter never fires", () => {
  // a hostile accessor on ANY opts field (read before/outside the old guarded clones) used to escape as a
  // raw TypeError. The old fix fired every getter ONCE into accessor-free data; `inertOptions` instead
  // refuses an accessor by DESCRIPTOR, so the getter is never invoked at all — the counter proves it.
  for (const field of ["maxReceipts", "keyring", "checkpoint", "identityManifest"] as const) {
    let fired = 0;
    const evil: Record<string, unknown> = {};
    Object.defineProperty(evil, field, { enumerable: true, configurable: true, get() { fired++; throw new Error("boom"); } });
    let r!: ReturnType<typeof verifyChain>;
    assert.doesNotThrow(() => { r = verifyChain(doc("valid-chain.json"), evil as never); }, `opts.${field} throwing getter must not escape`);
    assert.equal(r.status, "MALFORMED", `opts.${field} throwing getter → MALFORMED`);
    assert.match(r.reason ?? "", /is an accessor/, `opts.${field} must be refused as an accessor, not merely caught`);
    // verifyChainText forwards opts, so it inherits the fix.
    let rt!: ReturnType<typeof verifyChainText>;
    assert.doesNotThrow(() => { rt = verifyChainText(raw("valid-chain.json"), evil as never); });
    assert.equal(rt.status, "MALFORMED", `verifyChainText opts.${field} throwing getter → MALFORMED`);
    assert.equal(fired, 0, `opts.${field} getter fired ${fired} times inside the boundary`);
  }

  // A Symbol-typed maxReceipts: it is not a non-negative safe integer, so the schema refuses it. (It used
  // to be caught only incidentally, because a Symbol is non-cloneable and `structuredClone(opts)` threw.)
  let rSym!: ReturnType<typeof verifyChain>;
  assert.doesNotThrow(() => { rSym = verifyChain(doc("valid-chain.json"), { maxReceipts: Symbol("x") } as never); });
  assert.equal(rSym.status, "MALFORMED");

  // A symbol-KEYED option is likewise refused: a channel invisible to every string-keyed reader.
  const symKeyed: Record<string | symbol, unknown> = { keyring };
  symKeyed[Symbol("smuggled")] = "x";
  assert.equal(verifyChain(doc("valid-chain.json"), symKeyed as never).status, "MALFORMED");

  // An unknown member is a misconfiguration, not a default — the typo'd-security-flag failure mode.
  assert.equal(verifyChain(doc("valid-chain.json"), { keyring, requireTenantConsistancy: false } as never).status, "MALFORMED");

  // sanity: a numeric maxReceipts still bounds normally (no regression).
  assert.equal(verifyChain(doc("valid-chain.json"), { keyring, maxReceipts: 1 }).status, "MALFORMED"); // 3 receipts > 1
  assert.equal(verifyChain(doc("valid-chain.json"), { keyring, maxReceipts: 10 }).status, "VALID");
});

test("a non-object checkpoint → MALFORMED (parity with the Python CLI, not TAMPERED)", () => {
  // TS used to route a non-object checkpoint into verifyCheckpoint → 'malformed checkpoint' → TAMPERED (exit 2),
  // while the Python _main guard returns MALFORMED (exit 3) — a cross-impl split on the SAME malformed input.
  // verifyChain now rejects a non-object checkpoint as MALFORMED BEFORE routing, mirroring Python.
  // As BYTES — the form a CLI or a Python peer actually hands over — the reason string is unchanged, so
  // the cross-impl parity this test defends is intact.
  for (const bad of [null, [], 5, "x"]) {
    const r = verifyChain(doc("valid-chain.json"), { keyring, checkpoint: b(bad) });
    assert.equal(r.status, "MALFORMED", `checkpoint=${JSON.stringify(bad)} → MALFORMED`);
    assert.match(r.reason ?? "", /checkpoint must be an object/);
  }
  // The same values as raw JavaScript are refused by the options boundary before any of that runs —
  // same verdict class, so no caller sees a different OUTCOME, only a more precise reason.
  for (const bad of [null, [], 5, {}]) {
    const r = verifyChain(doc("valid-chain.json"), { keyring, checkpoint: bad as never });
    assert.equal(r.status, "MALFORMED", `raw checkpoint=${JSON.stringify(bad)} → MALFORMED`);
    assert.match(r.reason ?? "", /expected Uint8Array or string/);
  }
  // sanity: the legit checkpoint still VALID + tailChecked (no regression).
  const good = verifyChain(doc("valid-chain.json"), { keyring, checkpoint });
  assert.equal(good.status, "VALID", good.reason ?? "");
  assert.equal(good.tailChecked, true);
});

// --- A1 hardening: chain-wide scope.tenant consistency (additive; see THREAT-MODEL.md "namespace / context binding") ---

const tenantSigner = generateKeyPair("tenant-key");
const tenantKeyring = b({ [tenantSigner.kid]: tenantSigner.publicKey } satisfies Keyring);
const tenantSignerRef = { kid: tenantSigner.kid, privateKey: tenantSigner.privateKey };

function mkTenantReceipt(id: string, tenant: string | undefined, prev: ReturnType<typeof buildReceipt> | null): ReturnType<typeof buildReceipt> {
  const input: BuildInput = {
    id,
    ts: "2026-07-10T10:00:00.000Z",
    scope: tenant === undefined ? { chain: "c-tenant-drift" } : { chain: "c-tenant-drift", tenant },
    agent: { id: "svc", model: null, principal: "SERVICE" },
    action: { id: "a", canonical: "a", riskClass: "LOW", paramsHash: sha256Prefixed("x"), reversible: true, rollbackRef: null },
    governance: { mode: "on", verdict: "EXECUTED", ruleId: null, approval: null, sandboxed: false },
  };
  return buildReceipt(input, prev, tenantSignerRef);
}

test("A1: mixed scope.tenant across one chain -> TAMPERED BY DEFAULT (fail-closed; was VALID+warning before the default flipped)", () => {
  const r0 = mkTenantReceipt("r0", "acme", null);
  const r1 = mkTenantReceipt("r1", "acme", r0);
  const r2 = mkTenantReceipt("r2", "globex", r1);
  const r = verifyChain(b([r0, r1, r2]), { keyring: tenantKeyring });
  // Tenant isolation is a security boundary; the DEFAULT now enforces it. The failure is loud and
  // machine-readable, never a quietly different answer.
  assert.equal(r.status, "TAMPERED", r.reason ?? "");
  assert.match(r.reason ?? "", /tenant-drift: seq 1 "acme" -> seq 2 "globex"/);
  assert.equal(r.badSeq, 2, "badSeq must point at the FIRST drifting receipt");
});

test("A1: consistent scope.tenant across one chain -> NO tenant-drift warning", () => {
  const r0 = mkTenantReceipt("r0", "acme", null);
  const r1 = mkTenantReceipt("r1", "acme", r0);
  const r2 = mkTenantReceipt("r2", "acme", r1);
  const r = verifyChain(b([r0, r1, r2]), { keyring: tenantKeyring });
  assert.equal(r.status, "VALID", r.reason ?? "");
  assert.ok(!r.warnings.some((w) => /tenant-drift/.test(w)), `unexpected tenant-drift warning: ${JSON.stringify(r.warnings)}`);
});

test("A1: scope.tenant absent on every receipt -> NO tenant-drift warning (absence is consistency, not drift)", () => {
  const r0 = mkTenantReceipt("r0", undefined, null);
  const r1 = mkTenantReceipt("r1", undefined, r0);
  const r = verifyChain(b([r0, r1]), { keyring: tenantKeyring });
  assert.equal(r.status, "VALID", r.reason ?? "");
  assert.ok(!r.warnings.some((w) => /tenant-drift/.test(w)), `unexpected tenant-drift warning: ${JSON.stringify(r.warnings)}`);
});

test("A1: absent<->present tenant is REPORTED but not TAMPERED (an optional field appearing is not a splice)", () => {
  // scope.tenant is OPTIONAL in the schema and the frozen spec never declared it immutable, so a
  // deployment that starts (or stops) emitting it mid-chain is a producer-version change, not a
  // cross-tenant splice. Calling that tampering would tell an operator to hunt a forgery that does
  // not exist — and would collapse two failures with different responses onto one verdict, which is
  // exactly what this profile's chain-level-axis rule forbids.
  const r0 = mkTenantReceipt("r0", "acme", null);
  const r1 = mkTenantReceipt("r1", undefined, r0);
  const r = verifyChain(b([r0, r1]), { keyring: tenantKeyring });
  assert.equal(r.status, "VALID", r.reason ?? "");
  assert.ok(
    r.warnings.includes('tenant-drift: seq 0 "acme" -> seq 1 (none)'),
    `the transition must still be REPORTED, got: ${JSON.stringify(r.warnings)}`,
  );
});

// ── THE OMISSION MUST NOT RESET THE BOUNDARY (cross-family review round 3) ───────────────────────
// The relaxation above is right in principle and was wrong in its state machine. Comparing only
// ADJACENT receipts meant `acme -> globex` was TAMPERED while `acme -> absent -> globex` — the same
// splice, with one optional field left out of the receipt in between — was VALID, in all five
// implementations. Omitting an optional field is not a capability an attacker lacks, so the
// tolerated transition became a laundering step for the very thing the check exists to catch.
//
// The fix carries the last PRESENT tenant across absences. These four tests pin BOTH halves: the
// attack must fail, and the legitimate transitions the relaxation protects must keep passing (a
// "fix" that simply re-banned absence would pass the first two and fail the last two).

test("A1: acme -> absent -> globex is the SAME splice as acme -> globex -> TAMPERED (an omission cannot launder a cross-tenant change)", () => {
  const r0 = mkTenantReceipt("r0", "acme", null);
  const r1 = mkTenantReceipt("r1", undefined, r0);
  const r2 = mkTenantReceipt("r2", "globex", r1);
  const r = verifyChain(b([r0, r1, r2]), { keyring: tenantKeyring });
  assert.equal(r.status, "TAMPERED", r.reason ?? "");
  assert.match(
    r.reason ?? "",
    /tenant-drift: seq 0 "acme" -> seq 2 "globex"/,
    "the reason must name the LAST PRESENT value and the receipt that contradicts it — not the omission that hid it",
  );
  assert.equal(r.badSeq, 2);
});

test("A1: MORE omissions do not help — acme -> absent -> absent -> globex is still TAMPERED", () => {
  const r0 = mkTenantReceipt("r0", "acme", null);
  const r1 = mkTenantReceipt("r1", undefined, r0);
  const r2 = mkTenantReceipt("r2", undefined, r1);
  const r3 = mkTenantReceipt("r3", "globex", r2);
  const r = verifyChain(b([r0, r1, r2, r3]), { keyring: tenantKeyring });
  assert.equal(r.status, "TAMPERED", r.reason ?? "");
  assert.match(r.reason ?? "", /tenant-drift: seq 0 "acme" -> seq 3 "globex"/);
});

test("A1: acme -> absent -> acme stays VALID — the same tenant resuming is the producer-version change the relaxation protects", () => {
  const r0 = mkTenantReceipt("r0", "acme", null);
  const r1 = mkTenantReceipt("r1", undefined, r0);
  const r2 = mkTenantReceipt("r2", "acme", r1);
  const r = verifyChain(b([r0, r1, r2]), { keyring: tenantKeyring });
  assert.equal(r.status, "VALID", r.reason ?? "");
  assert.ok(
    r.warnings.includes('tenant-drift: seq 0 "acme" -> seq 1 (none)'),
    `the absent transitions must still be REPORTED: ${JSON.stringify(r.warnings)}`,
  );
});

test("A1: absent -> absent -> acme stays VALID (enrichment: a producer that STARTS emitting the field commits the chain from there on)", () => {
  const r0 = mkTenantReceipt("r0", undefined, null);
  const r1 = mkTenantReceipt("r1", undefined, r0);
  const r2 = mkTenantReceipt("r2", "acme", r1);
  const r = verifyChain(b([r0, r1, r2]), { keyring: tenantKeyring });
  assert.equal(r.status, "VALID", r.reason ?? "");
});

test("A1: the opt-out still reports the laundered splice against the LAST PRESENT tenant, never silently drops it", () => {
  // requireTenantConsistency:false must not mean "see nothing": the operator who opted out is
  // exactly the one who needs the machine-readable record of what drifted.
  const r0 = mkTenantReceipt("r0", "acme", null);
  const r1 = mkTenantReceipt("r1", undefined, r0);
  const r2 = mkTenantReceipt("r2", "globex", r1);
  const r = verifyChain(b([r0, r1, r2]), { keyring: tenantKeyring, requireTenantConsistency: false });
  assert.equal(r.status, "VALID", r.reason ?? "");
  assert.ok(
    r.warnings.includes('tenant-drift: seq 0 "acme" -> seq 2 "globex"'),
    `the splice itself must be reported, not only the two adjacent transitions: ${JSON.stringify(r.warnings)}`,
  );
});

test("A1: present -> DIFFERENT present IS a cross-tenant splice -> TAMPERED by default", () => {
  const r0 = mkTenantReceipt("r0", "acme", null);
  const r1 = mkTenantReceipt("r1", "globex", r0);
  const r = verifyChain(b([r0, r1]), { keyring: tenantKeyring });
  assert.equal(r.status, "TAMPERED", r.reason ?? "");
  assert.match(r.reason ?? "", /tenant-drift: seq 0 "acme" -> seq 1 "globex"/);
});

test("A1: requireTenantConsistency:true + drift -> fail-closed TAMPERED (same verdict class as the scope.chain partition-split check), badSeq points at the first drifting receipt", () => {
  const r0 = mkTenantReceipt("r0", "acme", null);
  const r1 = mkTenantReceipt("r1", "acme", r0);
  const r2 = mkTenantReceipt("r2", "globex", r1);
  const r = verifyChain(b([r0, r1, r2]), { keyring: tenantKeyring, requireTenantConsistency: true });
  assert.equal(r.status, "TAMPERED", r.reason ?? "");
  assert.match(r.reason ?? "", /tenant-drift: seq 1 "acme" -> seq 2 "globex"/);
  assert.equal(r.badSeq, 2);
});

test("A1: requireTenantConsistency:true + NO drift -> VALID (opt-in enforcement never fires a false positive)", () => {
  const r0 = mkTenantReceipt("r0", "acme", null);
  const r1 = mkTenantReceipt("r1", "acme", r0);
  const r = verifyChain(b([r0, r1]), { keyring: tenantKeyring, requireTenantConsistency: true });
  assert.equal(r.status, "VALID", r.reason ?? "");
  assert.deepEqual(r.warnings.filter((w) => /tenant-drift/.test(w)), []);
});

test("A1: requireTenantConsistency:false restores the EXACT previous behaviour (the documented migration path)", () => {
  // The default flipped to fail-closed. A caller that genuinely verifies mixed-tenant chains has one
  // documented escape hatch, and it must reproduce the old result byte for byte — verdict AND the
  // machine-readable warning — or the migration note in CHANGELOG.md would be a lie.
  const r0 = mkTenantReceipt("r0", "acme", null);
  const r1 = mkTenantReceipt("r1", "globex", r0);

  const enforced = verifyChain(b([r0, r1]), { keyring: tenantKeyring });
  assert.equal(enforced.status, "TAMPERED", "the new default is fail-closed");

  const optOut = verifyChain(b([r0, r1]), { keyring: tenantKeyring, requireTenantConsistency: false });
  assert.equal(optOut.status, "VALID", optOut.reason ?? "");
  assert.ok(
    optOut.warnings.includes('tenant-drift: seq 0 "acme" -> seq 1 "globex"'),
    `the opt-out must still REPORT the drift, got: ${JSON.stringify(optOut.warnings)}`,
  );
});

test("P0-14: every root chain/checkpoint surface refuses a lifecycle-retired key without consulting signer timestamps", () => {
  const retired = generateKeyPair("p0-14-chain-retired");
  const current = generateKeyPair("p0-14-chain-current");
  const unknown = generateKeyPair("p0-14-chain-unknown");
  const retirement = "2026-08-01T08:36:12.643Z";

  const makeSegment = (id: string, ts: string, signer: typeof retired) => buildReceipt({
    id,
    ts,
    scope: { chain: `chain-${id}`, tenant: "tenant-p0-14" },
    agent: { id: "proxy-p0-14", model: null, principal: "SERVICE" },
    action: { id: "wire.transfer", canonical: "wire.transfer", riskClass: "HIGH", paramsHash: sha256Prefixed(id), reversible: false, rollbackRef: null },
    governance: { mode: "on", verdict: "EXECUTED", ruleId: null, approval: null, sandboxed: false },
  }, null, { kid: signer.kid, privateKey: signer.privateKey });

  const lifecycle = b({
    spec: "noa.signing-key-lifecycle/0.1",
    keys: {
      [retired.kid]: { publicKey: retired.publicKey, retiredAt: retirement },
      [current.kid]: { publicKey: current.publicKey, retiredAt: null },
    },
  });
  const currentSegment = makeSegment("current-control", "2026-08-01T08:36:12.644Z", current);
  const currentControl = verifyChain(
    b([currentSegment]),
    { keyring: lifecycle },
  );
  const unknownControl = verifyChain(
    b([makeSegment("unknown-control", "2026-08-01T08:36:12.644Z", unknown)]),
    { keyring: lifecycle },
  );
  const freshRetiredAttack = verifyChain(
    b([makeSegment("retired-attack", "2026-08-01T08:36:12.644Z", retired)]),
    { keyring: lifecycle },
  );
  const backdatedRetiredAttack = verifyChain(
    b([makeSegment("retired-history", "2026-08-01T08:36:12.642Z", retired)]),
    { keyring: lifecycle },
  );
  const backdatedRetiredTextAttack = verifyChainText(
    JSON.stringify([makeSegment("retired-history-text", "2026-08-01T08:36:12.642Z", retired)]),
    { keyring: lifecycle },
  );
  const staticSigner = generateKeyPair("p0-14-chain-static");
  const staticControl = verifyChain(
    b([makeSegment("static-control", "2026-08-01T08:36:12.644Z", staticSigner)]),
    { keyring: b({ [staticSigner.kid]: staticSigner.publicKey } satisfies Keyring) },
  );
  const staticKeysKid = generateKeyPair("keys");
  const staticKeysKidControl = verifyChain(
    b([makeSegment("static-keys-kid", "2026-08-01T08:36:12.644Z", staticKeysKid)]),
    { keyring: b({ [staticKeysKid.kid]: staticKeysKid.publicKey } satisfies Keyring) },
  );
  const retiredCheckpointAttack = verifyChain(b([currentSegment]), {
    keyring: lifecycle,
    checkpoint: b(buildCheckpoint(
      currentSegment,
      "2026-08-01T08:36:12.644Z",
      { kid: retired.kid, privateKey: retired.privateKey },
    )),
  });
  const backdatedRetiredCheckpoint = buildCheckpoint(
    currentSegment,
    "2026-08-01T08:36:12.642Z",
    { kid: retired.kid, privateKey: retired.privateKey },
  );
  const standaloneCurrentCheckpoint = verifyCheckpoint(
    b(buildCheckpoint(currentSegment, "2026-08-01T08:36:12.644Z", current)),
    lifecycle,
  );
  const standaloneBackdatedRetiredCheckpoint = verifyCheckpoint(b(backdatedRetiredCheckpoint), lifecycle);
  const chainWithBackdatedRetiredCheckpoint = verifyChain(b([currentSegment]), {
    keyring: lifecycle,
    checkpoint: b(backdatedRetiredCheckpoint),
  });
  const currentCheckpointControl = verifyChain(b([currentSegment]), {
    keyring: lifecycle,
    checkpoint: b(buildCheckpoint(
      currentSegment,
      "2026-08-01T08:36:12.644Z",
      { kid: current.kid, privateKey: current.privateKey },
    )),
  });
  const missingLifecycleData = verifyChain(
    b([makeSegment("missing-lifecycle", "2026-08-01T08:36:12.644Z", current)]),
    { keyring: b({
      spec: "noa.signing-key-lifecycle/0.1",
      keys: { [current.kid]: { publicKey: current.publicKey } },
    }) },
  );

  assert.equal(currentControl.status, "VALID", currentControl.reason ?? "");
  assert.equal(unknownControl.status, "TAMPERED");
  assert.match(unknownControl.reason ?? "", /unknown signing key/);
  // A retired key's authentic signature is refused with its own status (G2-R1), never accepted:
  // KEY_RETIRED is not VALID and carries no positive sub-claim, whatever timestamp the signer chose.
  for (const [name, refused] of [
    ["fresh", freshRetiredAttack],
    ["backdated", backdatedRetiredAttack],
    ["backdated text", backdatedRetiredTextAttack],
  ] as const) {
    assert.equal(refused.status, "KEY_RETIRED", `${name}, retired at ${retirement}: ${refused.reason ?? "accepted"}`);
    assert.match(refused.reason ?? "", /retired/i);
    assert.equal(refused.signaturesVerified, false, name);
    assert.equal(refused.tailChecked, false, name);
  }
  assert.equal(staticControl.status, "VALID", staticControl.reason ?? "");
  assert.equal(staticKeysKidControl.status, "VALID", staticKeysKidControl.reason ?? "");
  assert.equal(currentCheckpointControl.status, "VALID", currentCheckpointControl.reason ?? "");
  assert.equal(currentCheckpointControl.tailChecked, true);
  assert.equal(retiredCheckpointAttack.status, "KEY_RETIRED");
  assert.match(retiredCheckpointAttack.reason ?? "", /checkpoint signing key.*retired/i);
  assert.equal(retiredCheckpointAttack.tailChecked, false);
  assert.equal(standaloneCurrentCheckpoint, "ok");
  assert.equal(standaloneBackdatedRetiredCheckpoint, "retired signing key");
  assert.equal(chainWithBackdatedRetiredCheckpoint.status, "KEY_RETIRED");
  assert.match(chainWithBackdatedRetiredCheckpoint.reason ?? "", /retired/i);
  assert.equal(chainWithBackdatedRetiredCheckpoint.tailChecked, false);
  assert.equal(missingLifecycleData.status, "MALFORMED");
  assert.match(missingLifecycleData.reason ?? "", /publicKey \+ retiredAt/);
});

// ── G2-R1 — a retired key's authentic signature has its own current-use outcome ─────────────────
//
// Before this, the default path answered TAMPERED both for "these bytes were altered / this
// signature is forged" and for "this signature is authentic, but the trust root has since retired
// the key". A relying party could only tell them apart by matching `reason` text. KEY_RETIRED is
// the distinct token: still a refusal (never VALID, both sub-claims false), reported only when every
// other check passed, and it points in-band to the historical purpose. The negative half proves the
// new branch cannot absorb tampering: every forgery that names a retired kid, and every later
// integrity/identity failure in a chain that also carries a retired signature, stays where it was.
test("G2-R1: default path reports an authentic retired-key signature as KEY_RETIRED, never as TAMPERED or VALID", () => {
  const retired = generateKeyPair("g2r1-retired");
  const current = generateKeyPair("g2r1-current");
  const attacker = generateKeyPair("g2r1-attacker");
  const retirement = "2026-02-01T00:00:00.000Z";
  const lifecycle = b({
    spec: "noa.signing-key-lifecycle/0.1",
    keys: {
      [retired.kid]: { publicKey: retired.publicKey, retiredAt: retirement },
      [current.kid]: { publicKey: current.publicKey, retiredAt: null },
    },
  });
  const input = (id: string, agentId: string, ts = "2026-01-01T00:00:00.000Z"): BuildInput => ({
    id,
    ts,
    scope: { chain: "g2r1", tenant: "tenant-g2r1" },
    agent: { id: agentId, model: null, principal: "SERVICE" },
    action: { id: "inventory.read", canonical: "inventory.read", riskClass: "LOW", paramsHash: sha256Prefixed(id), reversible: true, rollbackRef: null },
    governance: { mode: "on", verdict: "EXECUTED", ruleId: null, approval: null, sandboxed: false },
  });
  const byRetired = { kid: retired.kid, privateKey: retired.privateKey };
  const byCurrent = { kid: current.kid, privateKey: current.privateKey };
  const r0 = buildReceipt(input("g2r1-0", "old-agent"), null, byRetired);
  const r1 = buildReceipt(input("g2r1-1", "old-agent"), r0, byRetired);
  const r2 = buildReceipt(input("g2r1-2", "new-agent"), r1, byCurrent);
  const honest = [r0, r1, r2];
  const clone = <T>(v: T): T => JSON.parse(JSON.stringify(v)) as T;

  const assertKeyRetired = (
    label: string,
    res: ReturnType<typeof verifyChain>,
    seq: number,
    subject: RegExp,
    inputs: { checkpoint?: boolean; manifest?: boolean } = {},
  ) => {
    assert.equal(res.status, "KEY_RETIRED", `${label}: ${res.status} ${res.reason ?? ""}`);
    assert.equal(res.signaturesVerified, false, `${label}: a refusal must not carry a positive sub-claim`);
    assert.equal(res.tailChecked, false, label);
    assert.equal(res.badSeq, seq, label);
    assert.match(res.reason ?? "", subject, label);
    assert.match(res.reason ?? "", /--purpose historical/, `${label}: the reason must point to the historical purpose`);
    const retiredWarnings = res.warnings.filter((w) => w.startsWith("key-retired:"));
    assert.equal(retiredWarnings.length, 1, `${label}: exactly one key-retired warning: ${JSON.stringify(res.warnings)}`);
    const steer = retiredWarnings[0]!;
    assert.match(steer, new RegExp(`^key-retired: seq ${seq} kid "`), label);
    assert.match(steer, /--purpose historical/, label);
    assert.match(steer, /verifyHistoricalChain/, label);
    assert.match(steer, /does not establish when/, `${label}: the steer must not imply the signature predates retirement`);
    // Caveat texts written for a VALID result (tailChecked:true, "a VALID result proves") are scoped.
    assert.ok(!res.warnings.some((w) => /a VALID result|tailChecked:true/.test(w)), `${label}: VALID-only caveat text: ${JSON.stringify(res.warnings)}`);
    // The run was complete, so the completeness caveats a VALID result would carry are carried too.
    assert.ok(res.warnings.some((w) => w.startsWith("fork/equivocation is not detectable offline")), `${label}: fork caveat dropped`);
    assert.equal(
      res.warnings.some((w) => w.startsWith("no checkpoint supplied")),
      inputs.checkpoint !== true,
      `${label}: truncation caveat`,
    );
    assert.equal(
      res.warnings.some((w) => w.startsWith("no identityManifest supplied")),
      inputs.manifest !== true,
      `${label}: attribution caveat`,
    );
  };
  const assertRefusedNotRetired = (label: string, res: ReturnType<typeof verifyChain>, status: string, reason: RegExp) => {
    assert.equal(res.status, status, `${label}: ${res.status} ${res.reason ?? ""}`);
    assert.match(res.reason ?? "", reason, label);
    assert.doesNotMatch(res.reason ?? "", /--purpose historical/, `${label}: the historical steer is for the retired-key case only`);
    assert.equal(res.warnings.some((w) => /key-retired|--purpose historical/.test(w)), false, `${label}: ${JSON.stringify(res.warnings)}`);
    assert.equal(res.signaturesVerified, false, label);
  };

  // ── POSITIVE: the new outcome ────────────────────────────────────────────────────────────────
  assertKeyRetired("retired-signed prefix + current-signed head", verifyChain(b(honest), { keyring: lifecycle }), 0, /signing key "g2r1-retired" is retired/);
  assertKeyRetired("text entry point", verifyChainText(JSON.stringify(honest), { keyring: lifecycle }), 0, /is retired/);
  const late = [buildReceipt(input("g2r1-late-0", "new-agent"), null, byCurrent)];
  late.push(buildReceipt(input("g2r1-late-1", "old-agent"), late[0]!, byRetired));
  assertKeyRetired("first retired signature is mid-chain", verifyChain(b(late), { keyring: lifecycle }), 1, /is retired/);
  const currentOnly = [buildReceipt(input("g2r1-cp-0", "new-agent"), null, byCurrent)];
  const retiredCheckpoint = buildCheckpoint(currentOnly[0]!, "2026-01-01T00:00:01.000Z", byRetired);
  assertKeyRetired(
    "authentic checkpoint by a retired key",
    verifyChain(b(currentOnly), { keyring: lifecycle, checkpoint: b(retiredCheckpoint) }),
    0,
    /checkpoint signing key "g2r1-retired" is retired/,
    { checkpoint: true },
  );
  // A receipt finding outranks a checkpoint finding: both the receipts at seq 0-1 and the checkpoint
  // over the head are authentic under the retired key, and the FIRST (receipt, seq 0) is reported.
  const bothRetired = verifyChain(b(honest), {
    keyring: lifecycle,
    checkpoint: b(buildCheckpoint(r2, "2026-01-01T00:00:01.000Z", byRetired)),
  });
  assertKeyRetired("retired receipt and retired checkpoint", bothRetired, 0, /^signing key "g2r1-retired" is retired/, { checkpoint: true });
  assert.match(bothRetired.warnings.find((w) => w.startsWith("key-retired:"))!, /^key-retired: seq 0 kid "g2r1-retired" \(receipt\)/);

  // Controls: the identical bytes under a static root are VALID, and without a keyring the retired
  // state is unknowable, so the result stays UNVERIFIED.
  const staticRoot = b({ [retired.kid]: retired.publicKey, [current.kid]: current.publicKey } satisfies Keyring);
  assert.equal(verifyChain(b(honest), { keyring: staticRoot }).status, "VALID");
  assert.equal(verifyChain(b(currentOnly), { keyring: staticRoot, checkpoint: b(retiredCheckpoint) }).status, "VALID");
  assert.equal(verifyChain(b(honest), {}).status, "UNVERIFIED");

  // ── NEGATIVE: tampering that names a retired kid is still TAMPERED ───────────────────────────
  const altered = clone(honest);
  altered[0]!.action.paramsHash = sha256Prefixed("g2r1-altered");
  assertRefusedNotRetired("byte alteration of a retired-key receipt", verifyChain(b(altered), { keyring: lifecycle }), "TAMPERED", /hash mismatch/);

  const rehashed = clone(honest);
  rehashed[0]!.action.paramsHash = sha256Prefixed("g2r1-altered");
  rehashed[0]!.chain.hash = sha256Prefixed(receiptHashInput(rehashed[0]!));
  assertRefusedNotRetired("altered + re-hashed, original retired-key signature", verifyChain(b(rehashed), { keyring: lifecycle }), "TAMPERED", /invalid signature/);

  const forged = [buildReceipt(input("g2r1-forged", "old-agent"), null, { kid: retired.kid, privateKey: attacker.privateKey })];
  assertRefusedNotRetired("signature by another key under the retired kid", verifyChain(b(forged), { keyring: lifecycle }), "TAMPERED", /invalid signature/);

  const laterTamper = clone(honest);
  laterTamper[2]!.action.paramsHash = sha256Prefixed("g2r1-altered");
  assertRefusedNotRetired("retired signature at seq 0, altered bytes at seq 2", verifyChain(b(laterTamper), { keyring: lifecycle }), "TAMPERED", /hash mismatch/);

  const laterForgery = [r0, r1, buildReceipt(input("g2r1-2", "new-agent"), r1, { kid: current.kid, privateKey: attacker.privateKey })];
  assertRefusedNotRetired("retired signature at seq 0, forged signature at seq 2", verifyChain(b(laterForgery), { keyring: lifecycle }), "TAMPERED", /invalid signature/);

  // Every signature authentic (seq 2 honestly re-signed by the current key), linkage broken.
  const relinked = clone(honest);
  relinked[2]!.chain.prevHash = r0.chain.hash;
  relinked[2]!.chain.hash = sha256Prefixed(receiptHashInput(relinked[2]!));
  relinked[2]!.sig.value = signEd25519(current.privateKey, signingMessage(RECEIPT_SIG_DOMAIN, receiptHashInput(relinked[2]!)));
  assertRefusedNotRetired("retired signature at seq 0, authentic receipt with broken linkage at seq 2", verifyChain(b(relinked), { keyring: lifecycle }), "TAMPERED", /broken linkage at seq 2/);

  const unknownKid = [buildReceipt(input("g2r1-unknown", "old-agent"), null, { kid: attacker.kid, privateKey: attacker.privateKey })];
  assertRefusedNotRetired("unknown key", verifyChain(b(unknownKid), { keyring: lifecycle }), "TAMPERED", /unknown signing key/);

  const swapped = [r0, buildReceipt(input("g2r1-swap", "old-agent"), r0, byCurrent)];
  assertRefusedNotRetired("retired then current key for one agent.id", verifyChain(b(swapped), { keyring: lifecycle }), "TAMPERED", /key swap/);

  const forgedCheckpoint = clone(retiredCheckpoint);
  forgedCheckpoint.highestSeq = 0;
  forgedCheckpoint.ts = "2026-01-01T00:00:02.000Z";
  assertRefusedNotRetired(
    "retired checkpoint kid over bytes it did not sign",
    verifyChain(b(currentOnly), { keyring: lifecycle, checkpoint: b(forgedCheckpoint) }),
    "TAMPERED",
    /checkpoint not authenticated against keyring \(bad checkpoint signature\)/,
  );
  const truncating = buildCheckpoint(r1, "2026-01-01T00:00:01.000Z", byCurrent);
  assertRefusedNotRetired(
    "retired receipts, authentic checkpoint over a different head",
    verifyChain(b(honest), { keyring: lifecycle, checkpoint: b(truncating) }),
    "TAMPERED",
    /tail truncated/,
  );
  const retiredTruncating = buildCheckpoint(r1, "2026-01-01T00:00:01.000Z", byRetired);
  assertRefusedNotRetired(
    "authentic retired checkpoint over a truncated head",
    verifyChain(b(honest), { keyring: lifecycle, checkpoint: b(retiredTruncating) }),
    "TAMPERED",
    /tail truncated/,
  );

  // Identity binding outranks the retired-key finding: an unauthorized pairing is UNTRUSTED.
  const manifest = b({ "old-agent": [current.kid], "new-agent": [current.kid] });
  assertRefusedNotRetired("retired signature by a key the manifest does not authorize", verifyChain(b(honest), { keyring: lifecycle, identityManifest: manifest }), "UNTRUSTED", /not authorized/);
  const authorizingManifest = b({ "old-agent": [retired.kid], "new-agent": [current.kid] });
  assertKeyRetired("authorized retired signer", verifyChain(b(honest), { keyring: lifecycle, identityManifest: authorizingManifest }), 0, /is retired/, { manifest: true });

  // ── HISTORICAL PURPOSE UNCHANGED ─────────────────────────────────────────────────────────────
  const historical = verifyHistoricalChain(b(honest.slice(0, 2)), { keyring: lifecycle });
  assert.equal(historical.classification, "UNVERIFIED");
  assert.equal(historical.code, "NO_WITNESS");
  assert.equal(historical.dimensions.integrity, "INTACT");
  const historicalDamaged = verifyHistoricalChain(b(altered.slice(0, 2)), { keyring: lifecycle });
  assert.equal(historicalDamaged.code, "RECEIPT_INTEGRITY_FAILURE");
});

// ── G2-R1 — every label the reorder moved ────────────────────────────────────────────────────────
//
// Authenticating a retired key BEFORE refusing it moves that refusal later in the walk, so checks
// that used to be unreachable now answer first. Each row is one input class whose label changed; the
// `before` column is what the verifier at the parent commit returned for the same input (measured,
// recorded in CHANGELOG.md and VERSIONING.md §3.2), and this test pins the `after` column. No row
// moves to or from VALID.
test("G2-R1: every label transition created by authenticating retired keys first is pinned", () => {
  const retired = generateKeyPair("g2r1t-retired");
  const current = generateKeyPair("g2r1t-current");
  const attacker = generateKeyPair("g2r1t-attacker");
  const lifecycle = b({
    spec: "noa.signing-key-lifecycle/0.1",
    keys: {
      [retired.kid]: { publicKey: retired.publicKey, retiredAt: "2026-02-01T00:00:00.000Z" },
      [current.kid]: { publicKey: current.publicKey, retiredAt: null },
    },
  });
  const input = (id: string, seq: number, agentId = "agent-t"): BuildInput => ({
    id,
    ts: `2026-01-01T00:00:0${seq}.000Z`,
    scope: { chain: "g2r1t", tenant: "tenant-g2r1t" },
    agent: { id: agentId, model: null, principal: "SERVICE" },
    action: { id: "inventory.read", canonical: "inventory.read", riskClass: "LOW", paramsHash: sha256Prefixed(id), reversible: true, rollbackRef: null },
    governance: { mode: "on", verdict: "EXECUTED", ruleId: null, approval: null, sandboxed: false },
  });
  const byRetired = { kid: retired.kid, privateKey: retired.privateKey };
  const byCurrent = { kid: current.kid, privateKey: current.privateKey };
  const reseal = (r: Receipt, privateKey: string): Receipt => {
    r.chain.hash = sha256Prefixed(receiptHashInput(r));
    r.sig.value = signEd25519(privateKey, signingMessage(RECEIPT_SIG_DOMAIN, receiptHashInput(r)));
    return r;
  };
  const r0 = buildReceipt(input("t-0", 0), null, byRetired);
  const r1 = buildReceipt(input("t-1", 1), r0, byRetired);
  const retiredChain = [r0, r1];
  const currentChain = [buildReceipt(input("c-0", 0), null, byCurrent)];
  const currentChain2 = [currentChain[0]!, buildReceipt(input("c-1", 1), currentChain[0]!, byCurrent)];
  const retiredCheckpoint = (head: Receipt) => b(buildCheckpoint(head, "2026-01-01T00:00:05.000Z", byRetired));

  // requireNFC: the retired seq 0 is clean; seq 1 (another agent.id, honestly re-signed) is not NFC.
  const nfcTail = JSON.parse(JSON.stringify(buildReceipt(input("t-nfc", 1), r0, byRetired))) as Receipt;
  nfcTail.agent.id = "agent-e\u0301"; // decomposed e + combining acute; NFC composes it to U+00E9
  reseal(nfcTail, retired.privateKey);
  const forgedKid = [buildReceipt(input("t-forged", 0), null, { kid: retired.kid, privateKey: attacker.privateKey })];
  const altered = JSON.parse(JSON.stringify(retiredChain)) as Receipt[];
  altered[1]!.action.paramsHash = sha256Prefixed("altered");
  const forgedCheckpoint = JSON.parse(JSON.stringify(buildCheckpoint(currentChain[0]!, "2026-01-01T00:00:05.000Z", byRetired))) as Checkpoint;
  forgedCheckpoint.ts = "2026-01-01T00:00:06.000Z";
  // Cross-phase rows: retired RECEIPTS with a CURRENT-key checkpoint, and retired receipts followed
  // by a current-key receipt (another agent.id) that fails its own identity, signature or linkage.
  const currentCheckpoint = (head: Receipt) => b(buildCheckpoint(head, "2026-01-01T00:00:05.000Z", byCurrent));
  const forgedCurrentCheckpoint = JSON.parse(JSON.stringify(buildCheckpoint(r1, "2026-01-01T00:00:05.000Z", byCurrent))) as Checkpoint;
  forgedCurrentCheckpoint.ts = "2026-01-01T00:00:06.000Z";
  const tail = buildReceipt(input("t-2", 2, "agent-u"), r1, byCurrent);
  const tailForged = buildReceipt(input("t-2", 2, "agent-u"), r1, { kid: current.kid, privateKey: attacker.privateKey });
  const tailRelinked = JSON.parse(JSON.stringify(tail)) as Receipt;
  tailRelinked.chain.prevHash = r0.chain.hash;
  reseal(tailRelinked, current.privateKey);

  const rows: ReadonlyArray<{
    name: string; before: string; after: string; badSeq: number | undefined; reason: RegExp;
    run: () => ReturnType<typeof verifyChain>;
  }> = [
    { name: "authentic retired receipts", before: "TAMPERED (exit 2)", after: "KEY_RETIRED", badSeq: 0, reason: /^signing key "g2r1t-retired" is retired/,
      run: () => verifyChain(b(retiredChain), { keyring: lifecycle }) },
    { name: "retired seq-0 receipt, manifest does not authorize its kid", before: "TAMPERED (exit 2)", after: "UNTRUSTED", badSeq: 0, reason: /not authorized for signing key "g2r1t-retired"/,
      run: () => verifyChain(b(retiredChain), { keyring: lifecycle, identityManifest: b({ "agent-t": [current.kid] }) }) },
    { name: "authentic retired checkpoint, kid not authorized for the opener", before: "TAMPERED (exit 2)", after: "UNTRUSTED", badSeq: 0, reason: /checkpoint signing key "g2r1t-retired" is not authorized for chain opener/,
      run: () => verifyChain(b(currentChain), { keyring: lifecycle, checkpoint: retiredCheckpoint(currentChain[0]!), identityManifest: b({ "agent-t": [current.kid] }) }) },
    { name: "retired seq 0, requireNFC, non-NFC string at seq 1", before: "TAMPERED (exit 2)", after: "MALFORMED", badSeq: 1, reason: /non-NFC string\(s\) at seq 1: agent\.id/,
      run: () => verifyChain(b([r0, nfcTail]), { keyring: lifecycle, requireNFC: true }) },
    { name: "retired receipts, checkpoint document is a JSON array", before: "TAMPERED (exit 2)", after: "MALFORMED", badSeq: undefined, reason: /^checkpoint must be an object$/,
      run: () => verifyChain(b(retiredChain), { keyring: lifecycle, checkpoint: "[]" }) },
    { name: "retired receipts, checkpoint document is JSON null", before: "TAMPERED (exit 2)", after: "MALFORMED", badSeq: undefined, reason: /^checkpoint must be an object$/,
      run: () => verifyChain(b(retiredChain), { keyring: lifecycle, checkpoint: "null" }) },
    { name: "retired kid carrying another key's signature", before: "TAMPERED badSeq 0 (retired)", after: "TAMPERED", badSeq: 0, reason: /^invalid signature \(kid g2r1t-retired\)$/,
      run: () => verifyChain(b(forgedKid), { keyring: lifecycle }) },
    { name: "authentic retired seq 0, altered bytes at seq 1", before: "TAMPERED badSeq 0 (retired)", after: "TAMPERED", badSeq: 1, reason: /^hash mismatch/,
      run: () => verifyChain(b(altered), { keyring: lifecycle }) },
    { name: "retired checkpoint kid over bytes it did not sign", before: "TAMPERED badSeq head (retired)", after: "TAMPERED", badSeq: undefined, reason: /bad checkpoint signature/,
      run: () => verifyChain(b(currentChain), { keyring: lifecycle, checkpoint: b(forgedCheckpoint) }) },
    { name: "authentic retired checkpoint over a truncated head", before: "TAMPERED badSeq head (retired)", after: "TAMPERED", badSeq: 1, reason: /tail truncated/,
      run: () => verifyChain(b(currentChain2), { keyring: lifecycle, checkpoint: retiredCheckpoint(currentChain2[0]!) }) },
    { name: "retired receipts, forged current-key checkpoint", before: "TAMPERED badSeq 0 (retired)", after: "TAMPERED", badSeq: undefined, reason: /checkpoint not authenticated against keyring \(bad checkpoint signature\)/,
      run: () => verifyChain(b(retiredChain), { keyring: lifecycle, checkpoint: b(forgedCurrentCheckpoint) }) },
    { name: "retired receipts, authentic current-key checkpoint over a truncated head", before: "TAMPERED badSeq 0 (retired)", after: "TAMPERED", badSeq: 1, reason: /tail truncated/,
      run: () => verifyChain(b(retiredChain), { keyring: lifecycle, checkpoint: currentCheckpoint(r0) }) },
    { name: "retired receipts, current-key checkpoint not authorized for the opener", before: "TAMPERED (exit 2)", after: "UNTRUSTED", badSeq: 1, reason: /checkpoint signing key "g2r1t-current" is not authorized for chain opener/,
      run: () => verifyChain(b(retiredChain), { keyring: lifecycle, checkpoint: currentCheckpoint(r1), identityManifest: b({ "agent-t": [retired.kid] }) }) },
    { name: "retired receipts, later receipt not authorized by the manifest", before: "TAMPERED (exit 2)", after: "UNTRUSTED", badSeq: 2, reason: /agent "agent-u" is not authorized for signing key "g2r1t-current"/,
      run: () => verifyChain(b([r0, r1, tail]), { keyring: lifecycle, identityManifest: b({ "agent-t": [retired.kid] }) }) },
    { name: "retired receipts, later receipt with another key's signature", before: "TAMPERED badSeq 0 (retired)", after: "TAMPERED", badSeq: 2, reason: /^invalid signature \(kid g2r1t-current\)$/,
      run: () => verifyChain(b([r0, r1, tailForged]), { keyring: lifecycle }) },
    { name: "retired receipts, later authentic receipt with broken linkage", before: "TAMPERED badSeq 0 (retired)", after: "TAMPERED", badSeq: 2, reason: /^broken linkage at seq 2$/,
      run: () => verifyChain(b([r0, r1, tailRelinked]), { keyring: lifecycle }) },
  ];
  for (const row of rows) {
    const res = row.run();
    const label = `${row.name}: was ${row.before}`;
    assert.equal(res.status, row.after, `${label}; got ${res.status} ${res.reason ?? ""}`);
    assert.equal(res.badSeq, row.badSeq, label);
    assert.match(res.reason ?? "", row.reason, label);
    assert.equal(res.signaturesVerified, false, label);
    assert.equal(res.warnings.some((w) => w.startsWith("key-retired:")), row.after === "KEY_RETIRED", label);
  }
});
