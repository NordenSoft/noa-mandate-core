/**
 * Deterministic conformance-vector generator.
 *
 * Produces a known-good chain + a checkpoint + keyring, then derives every attack variant
 * from it. Output is committed so anyone can independently re-derive and diff. The keypair
 * below is a TEST-ONLY fixture (its private key is intentionally public) — NEVER a real key.
 */

import { mkdirSync, writeFileSync, rmSync, readdirSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { buildReceipt, buildCheckpoint, type Signer } from "../src/builder.js";
import { sha256Prefixed, sha256Hex } from "../src/hash.js";
import { receiptHashInput } from "../src/canonicalize.js";
import { signEd25519 } from "../src/keys.js";
import { signingMessage, RECEIPT_SIG_DOMAIN } from "../src/signing.js";
import { opaqueApproverId } from "../src/pii.js";
import { canonicalize } from "../src/jcs.js";
import { coseSign1 } from "../src/cose/cose-sign1.js";
import { createHash } from "node:crypto";
import type { Receipt, BuildInput } from "../src/index.js";

/** Re-hash + re-sign a hand-mutated receipt so it is self-consistent (valid hash + sig under
 *  the domain-separated scheme). Used to test the linkage/pinning/genesis branches in
 *  isolation — the receipt is internally valid, so only the intended check can reject it. */
function reseal(r: Receipt, privateKey: string): Receipt {
  const hi = receiptHashInput(r);
  r.chain.hash = "sha256:" + sha256Hex(hi);
  r.sig.value = signEd25519(privateKey, signingMessage(RECEIPT_SIG_DOMAIN, hi));
  return r;
}

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUT = join(__dirname, "..", "..", "conformance", "vectors");

// --- TEST-ONLY fixture key (private key is public on purpose; do not reuse) ---
const KID = "noa-test-key-2026";
const PUBLIC_KEY = "MCowBQYDK2VwAyEAfCMjakcMSx1Azeehv+DU2bchtPTvB+uoloJ0kJNWI24=";
const PRIVATE_KEY = "MC4CAQAwBQYDK2VwBCIEIIE3nsJTdj5WI7d3Nzp6qggQXOgsaAIofegG3vTrvwf4";
const signer: Signer = { kid: KID, privateKey: PRIVATE_KEY };

// TEST-ONLY attacker key — represents an adversary who controls *a* valid keypair but is
// not the pinned chain key. Proves key-pinning, not just signature presence.
const ATTACKER_KID = "kid-attacker";
const ATTACKER_PRIVATE_KEY = "MC4CAQAwBQYDK2VwBCIEIMqFDluCpTmlDEfud4fWHosahDyk9XFkcikj8dsP7X3e";

// agent.model is a vendor-neutral free string in the spec; use a generic example.
const EXAMPLE_MODEL = "example-provider/llm-v1";
const CHAIN = "store_demo_chain";

function ph(s: string): string {
  return sha256Prefixed(s);
}

const inputs: BuildInput[] = [
  {
    id: "rcpt_0000000000000000000000000A",
    ts: "2026-06-20T07:30:54.000Z",
    scope: { tenant: "store_demo", chain: CHAIN },
    agent: { id: "agent-refunds", model: EXAMPLE_MODEL, principal: "SERVICE" },
    action: { id: "payment.refund", canonical: "payment.refund", riskClass: "HIGH", paramsHash: ph("amount=4200;currency=DKK"), reversible: false, rollbackRef: null },
    governance: { mode: "on", verdict: "DEFERRED", ruleId: "high-risk-deferral", approval: null, sandboxed: false },
  },
  {
    id: "rcpt_0000000000000000000000000B",
    ts: "2026-06-20T07:31:10.000Z",
    scope: { tenant: "store_demo", chain: CHAIN },
    agent: { id: "agent-refunds", model: EXAMPLE_MODEL, principal: "HUMAN" },
    action: { id: "payment.refund", canonical: "payment.refund", riskClass: "HIGH", paramsHash: ph("amount=4200;currency=DKK"), reversible: false, rollbackRef: null },
    // D8: the approver id in a SIGNED receipt is the OPAQUE, tenant-scoped pseudonym — never a raw
    // email. (Was `HUMAN:owner@store.example` — a raw email in signed bytes, contradicting D8.)
    governance: { mode: "on", verdict: "EXECUTED", ruleId: "human-approved", approval: { by: "HUMAN:" + opaqueApproverId("owner@store.example", "store_demo"), at: "2026-06-20T07:31:08.000Z" }, sandboxed: false },
  },
  {
    id: "rcpt_0000000000000000000000000C",
    ts: "2026-06-20T07:45:00.000Z",
    scope: { tenant: "store_demo", chain: CHAIN },
    agent: { id: "agent-refunds", model: EXAMPLE_MODEL, principal: "POLICY" },
    action: { id: "email.send", canonical: "email.send", riskClass: "LOW", paramsHash: ph("template=refund_confirm"), reversible: true, rollbackRef: null },
    governance: { mode: "on", verdict: "EXECUTED", ruleId: "low-risk-auto", approval: null, sandboxed: false },
  },
];

const chain: Receipt[] = [];
let prev: Receipt | null = null;
for (const inp of inputs) {
  const r = buildReceipt(inp, prev, signer);
  chain.push(r);
  prev = r;
}
const head = chain[chain.length - 1]!;
const checkpoint = buildCheckpoint(head, "2026-06-20T07:46:00.000Z", signer);
const keyring = { [KID]: PUBLIC_KEY };

function clone<T>(v: T): T {
  return structuredClone(v);
}

function write(rel: string, data: unknown): void {
  const path = join(OUT, rel);
  mkdirSync(dirname(path), { recursive: true });
  // Bytes are written exactly as given (strict-bytes fixtures); strings and objects as before.
  const text = data instanceof Uint8Array || typeof data === "string" ? data : JSON.stringify(data, null, 2) + "\n";
  writeFileSync(path, text);
}

// VENDORED, NOT GENERATED: strict-bytes/attest-cc0/ holds an outside implementer's CC0 corpus
// (mrpkk/attest conformance/ at e6ec711b5da367d91d1e8489106d406f47d98cd7; see its README.md). This
// generator cannot re-derive those bytes, so the clean rebuild below carries them across unchanged and
// refuses to run when an upstream file is missing or differs from its SHA-256 pin.
const ATTEST_CC0 = "strict-bytes/attest-cc0";
const ATTEST_CC0_FILES: ReadonlyArray<{ name: string; sha256: string | null }> = [
  { name: "receipt-vectors.json", sha256: "d57b0673b7cf1320ab06ca84459e208855dc981ab7ca493d4425dcd800916261" },
  { name: "LICENSE", sha256: "03c6c2d74d88d05f4a0ed216aeb088e22b828388ed82672cd426ac53a57d31bd" },
  { name: "README.md", sha256: null },
];
const attestCc0 = ATTEST_CC0_FILES.map(({ name, sha256 }) => {
  const bytes = readFileSync(join(OUT, ATTEST_CC0, name));
  if (sha256 !== null && createHash("sha256").update(bytes).digest("hex") !== sha256) {
    throw new Error(`${ATTEST_CC0}/${name}: the vendored bytes differ from the upstream SHA-256 pin`);
  }
  return { name, bytes };
});

rmSync(OUT, { recursive: true, force: true });
mkdirSync(OUT, { recursive: true });
for (const { name, bytes } of attestCc0) write(`${ATTEST_CC0}/${name}`, bytes);

// --- valid fixtures ---
write("valid-chain.json", chain);
write("keyring.json", keyring);
write("checkpoint.json", checkpoint);

// --- attack variants (structurally valid JSON, integrity broken) ---

// 1. content tampered (alter a field without recomputing hash)
const tampered = clone(chain);
tampered[1]!.action.paramsHash = ph("amount=999999;currency=DKK");
write("attack/tampered-content.json", tampered);

// 2. tail truncated (drop the head) — only detectable with checkpoint
write("attack/tail-truncated.json", clone(chain).slice(0, 2));

// 3. forged genesis (prevHash not null at seq 0), re-sealed so only the genesis rule catches it
const forged = clone(chain);
forged[0]!.chain.prevHash = ph("fake-genesis");
reseal(forged[0]!, PRIVATE_KEY);
write("attack/forged-genesis.json", forged);

// 4a. key swap by hash-binding: change sig.kid without re-sealing -> hash mismatch
//     (proves sig.kid is bound into the hash)
const keyswap = clone(chain);
keyswap[2]!.sig.kid = ATTACKER_KID;
write("attack/key-swap.json", keyswap);

// 4b. key swap by a real adversary key: re-seal head with attacker key+kid.
//     Hash + signature are internally valid, but key-pinning per agent.id rejects it.
const keyswapResigned = clone(chain);
keyswapResigned[2]!.sig.kid = ATTACKER_KID;
reseal(keyswapResigned[2]!, ATTACKER_PRIVATE_KEY);
write("attack/key-swap-resigned.json", keyswapResigned);

// 4c. unknown signing key: a fully self-consistent chain signed by an adversary key whose kid
//     is NOT in the trusted keyring. Internally valid (hash+sig+pinning all consistent) but
//     unauthenticated → TAMPERED when a keyring is supplied, UNVERIFIED when none is.
const attackerSigner: Signer = { kid: ATTACKER_KID, privateKey: ATTACKER_PRIVATE_KEY };
const unknownKid: Receipt[] = [];
let pAtk: Receipt | null = null;
for (const inp of inputs) {
  const r = buildReceipt(inp, pAtk, attackerSigner);
  unknownKid.push(r);
  pAtk = r;
}
write("attack/unknown-kid.json", unknownKid);

// 5. seq gap (missing middle)
write("attack/seq-gap.json", [clone(chain[0]!), clone(chain[2]!)]);

// 5b. head truncation: drop the GENESIS receipt and present seq 1.. as the whole chain.
//     Caught because seq is in the signed body and the verifier requires contiguous 0..n-1.
write("attack/head-truncated.json", clone(chain).slice(1));

// 5c. cross-chain splice: a receipt from a DIFFERENT chain lifted into this input.
//     Caught because scope.chain is in the signed body (single-chain-partition check).
const otherGenesis = buildReceipt(
  { ...inputs[0]!, id: "rcpt_other_genesis", scope: { tenant: "store_other", chain: "store_other_chain" } },
  null,
  signer,
);
write("attack/cross-chain-splice.json", [clone(chain[0]!), otherGenesis]);

// 5d. CROSS-TENANT SPLICE LAUNDERED THROUGH AN OMISSION (cross-family review, 2026-07-27).
//     `scope.tenant` is OPTIONAL, so absent<->present drift is reported and not fatal — a producer
//     that starts or stops emitting the field is a version change, not a forgery. But when the
//     comparison was ADJACENT, that tolerance became a laundering step: `acme -> globex` was
//     TAMPERED in all five verifiers, while `acme -> absent -> globex` — the SAME splice with one
//     optional field left out of the receipt in between — was VALID in all five. Omitting an
//     optional field is not a capability an attacker lacks.
//
//     The verifiers now carry the last PRESENT tenant across absences, so both are TAMPERED. The
//     companion "legit" vector below pins the other half of the rule: the relaxation itself must
//     SURVIVE — an omission that never contradicts the committed tenant stays VALID.
function tenantChain(tenants: Array<string | undefined>, idPrefix: string): ReturnType<typeof buildReceipt>[] {
  const out: ReturnType<typeof buildReceipt>[] = [];
  let prev: ReturnType<typeof buildReceipt> | null = null;
  tenants.forEach((t, i) => {
    const base = inputs[0]!;
    const r = buildReceipt(
      {
        ...base,
        id: `${idPrefix}_${i}`,
        ts: `2026-06-20T09:0${i}:00.000Z`,
        scope: t === undefined ? { chain: "tenant-boundary-chain" } : { chain: "tenant-boundary-chain", tenant: t },
      },
      prev,
      signer,
    );
    out.push(r);
    prev = r;
  });
  return out;
}
// TAMPERED: the splice is hidden behind one tenant-less receipt.
write("attack/tenant-splice-via-absent.json", tenantChain(["acme", undefined, "globex"], "tsa"));
// TAMPERED: hiding it behind MORE omissions must not help either.
write("attack/tenant-splice-via-absent-long.json", tenantChain(["acme", undefined, undefined, "globex"], "tsal"));
// VALID: an optional field stops being emitted and the same tenant later resumes — the legitimate
// producer-version change the relaxation exists to protect. A verifier that "fixed" the attack by
// re-banning absence would fail THIS vector.
write("tenant-omission-then-same-tenant.json", tenantChain(["acme", undefined, "acme"], "tos"));
// VALID: a producer that only STARTS emitting the field mid-chain (enrichment).
write("tenant-enrichment-absent-first.json", tenantChain([undefined, undefined, "acme"], "ten"));

// 6. duplicate seq
const dupseq = clone(chain);
dupseq[2]!.chain.seq = 1;
write("attack/dup-seq.json", dupseq);

// 7. corrupted signature value (valid structure, bad sig bytes)
const badsig = clone(chain);
const v = badsig[1]!.sig.value;
badsig[1]!.sig.value = v.slice(0, -4) + (v.endsWith("AAAA") ? "BBBB" : "AAAA");
write("attack/wrong-signature.json", badsig);

// 8. broken linkage, re-sealed: head points prevHash at genesis instead of seq 1.
//    Hash + signature valid → ONLY the linkage check catches it.
const relinked = clone(chain);
relinked[2]!.chain.prevHash = chain[0]!.chain.hash;
reseal(relinked[2]!, PRIVATE_KEY);
write("attack/relinked.json", relinked);

// 9. forged checkpoint: attacker truncates the chain (hides seq 2) and signs a checkpoint over
//    the fake head with an OUT-OF-KEYRING key. The receipts still authenticate, so without the
//    trust-root rule for checkpoints this would falsely report VALID + tailChecked:true. Must be
//    TAMPERED when a keyring is supplied. Companion checkpoint written alongside.
const forgedCpChain = clone(chain).slice(0, 2);
const forgedCheckpoint = buildCheckpoint(forgedCpChain[1]!, "2026-06-20T07:50:00.000Z", attackerSigner);
write("attack/forged-checkpoint-chain.json", forgedCpChain);
write("attack/forged-checkpoint-cp.json", forgedCheckpoint);

// 10. CROSS-FIELD COHERENCE — A SIGNED RECEIPT THAT CONTRADICTS ITSELF (2026-08-14).
//     Every one of these is cryptographically PERFECT: hash recomputed, signature genuine under the
//     pinned key, linkage intact. Five of them, run through all five shipped verifiers on identical
//     bytes, came back VALID 25 times out of 25 before the coherence rules landed — signed,
//     chain-valid, fully-verifying receipts for a CRITICAL action that can be argued BOTH WAYS
//     after the fact. Each mutates the HEAD (seq 2) and re-seals, so nothing downstream is
//     disturbed and ONLY the intended rule can reject: the vector proves the rule, not the linkage.
//
//     The paired "must STAY VALID" vectors are written at top level below — a rule that refuses
//     every receipt is not a rule, it is an outage.
function coherenceVector(name: string, mutate: (r: Receipt) => void): void {
  const c = clone(chain);
  mutate(c[2]!);
  reseal(c[2]!, PRIVATE_KEY);
  write(`attack/${name}.json`, c);
}
// R1: the receipt names the SANDBOX SIMULATOR as the actor while denying it was a simulation.
coherenceVector("coherence-sandbox-principal", (r) => {
  r.agent.principal = "SANDBOX_SIM";
});
// R2: the receipt records a SIMULATED outcome while denying it was a simulation.
coherenceVector("coherence-simulated-not-sandboxed", (r) => {
  r.governance.verdict = "SIMULATED";
});
// R3: an action declared impossible to undo, carrying the reference used to undo it.
coherenceVector("coherence-irreversible-with-rollbackref", (r) => {
  r.action.reversible = false;
  r.action.rollbackRef = "snap_1";
});
// R4: the receipt says the action WAS undone while declaring it could not be.
coherenceVector("coherence-rolled-back-irreversible", (r) => {
  r.governance.verdict = "ROLLED_BACK";
  r.action.reversible = false;
});
// R5: a `ts` with the SHAPE of an RFC 3339 timestamp that denotes no instant — month 13, day 45,
//     hour 99. Unorderable against its neighbours, so the non-monotonic-ts warning is blind to it.
coherenceVector("coherence-ts-not-an-instant", (r) => {
  r.ts = "2026-13-45T99:99:99.000Z";
});

// 10b. THE OTHER HALF OF THE COHERENCE RULES — these MUST STAY VALID.
//      A verifier that "fixed" the vectors above by refusing sandboxes, rollbacks or leap seconds
//      would fail here. Written at top level (not under attack/) exactly like the tenant-relaxation
//      companions in 5d.
//      Every field agrees: SANDBOX_SIM acting, sandboxed true, a SIMULATED outcome, and a
//      reversible action that legitimately carries its rollback reference.
write("coherence-consistent-sandbox.json", [
  buildReceipt(
    {
      id: "rcpt_coherence_sandbox_ok",
      ts: "2026-06-20T08:00:00.000Z",
      scope: { tenant: "store_demo", chain: "coherence_ok_chain" },
      agent: { id: "agent-rehearsal", model: EXAMPLE_MODEL, principal: "SANDBOX_SIM" },
      action: { id: "payment.refund", canonical: "payment.refund", riskClass: "CRITICAL", paramsHash: ph("amount=1000000;currency=DKK"), reversible: true, rollbackRef: "snap_rehearsal" },
      governance: { mode: "on", verdict: "SIMULATED", ruleId: "critical-rehearsal", approval: null, sandboxed: true },
    },
    null,
    signer,
  ),
]);
//      A rollback that really happened: ROLLED_BACK on an action that really was reversible.
write("coherence-rolled-back-consistent.json", [
  buildReceipt(
    {
      id: "rcpt_coherence_rollback_ok",
      ts: "2026-06-20T08:01:00.000Z",
      scope: { tenant: "store_demo", chain: "coherence_ok_chain_2" },
      agent: { id: "agent-refunds", model: EXAMPLE_MODEL, principal: "SERVICE" },
      action: { id: "payment.refund", canonical: "payment.refund", riskClass: "HIGH", paramsHash: ph("amount=4200;currency=DKK"), reversible: true, rollbackRef: "snap_before_refund" },
      governance: { mode: "on", verdict: "ROLLED_BACK", ruleId: "auto-rollback", approval: null, sandboxed: false },
    },
    null,
    signer,
  ),
]);
//      THE LEAP SECOND IS A REAL INSTANT. 23:59:60 has really occurred 27 times; a verifier that
//      rejects it refuses a truthful receipt, which is its own bug. Pinned here so a later
//      "tightening" of the R5 rule cannot quietly remove the acceptance.
write("ts-leap-second.json", [
  buildReceipt(
    {
      id: "rcpt_leap_second",
      ts: "2026-06-30T23:59:60.000Z",
      scope: { tenant: "store_demo", chain: "leap_second_chain" },
      agent: { id: "agent-refunds", model: EXAMPLE_MODEL, principal: "SERVICE" },
      action: { id: "email.send", canonical: "email.send", riskClass: "LOW", paramsHash: ph("template=refund_confirm"), reversible: true, rollbackRef: null },
      governance: { mode: "on", verdict: "EXECUTED", ruleId: "low-risk-auto", approval: null, sandboxed: false },
    },
    null,
    signer,
  ),
]);

// 10c. TIMESTAMP ORDER — WARNINGS, NEVER VERDICTS (ts-order/). Spec §5 promises a warning when `ts`
//      goes backwards between consecutive receipts, compared at full precision (nanoseconds) after
//      offset normalization. Every chain below is genuine and MUST stay VALID with the keyring in
//      every verifier; what each pins is the run's timestamp-order warnings ("ts-backwards: seq N",
//      "ts-not-comparable: seq N"). impl-py/conformance.mjs pins the expected warnings for TS and
//      Python; the Go, Rust and C# runners compare theirs with Python's.
function tsOrderChain(stamps: string[], idPrefix: string): Receipt[] {
  const out: Receipt[] = [];
  let prev: Receipt | null = null;
  stamps.forEach((ts, i) => {
    const r = buildReceipt(
      { ...inputs[2]!, id: `${idPrefix}_${i}`, ts, scope: { tenant: "store_demo", chain: `ts-order-${idPrefix}` } },
      prev,
      signer,
    );
    out.push(r);
    prev = r;
  });
  return out;
}
// One second back.
write("ts-order/backwards-one-second.json", tsOrderChain(["2026-06-20T10:00:01Z", "2026-06-20T10:00:00Z"], "tob1s"));
// One nanosecond back: equal at millisecond precision, so a millisecond comparison misses it.
write(
  "ts-order/backwards-one-nanosecond.json",
  tsOrderChain(["2026-06-20T10:00:00.000000002Z", "2026-06-20T10:00:00.000000001Z"], "tob1n"),
);
// Forwards as written, backwards after offset normalization: 11:30+02:00 is 09:30Z.
write("ts-order/backwards-after-offset.json", tsOrderChain(["2026-06-20T10:00:00Z", "2026-06-20T11:30:00+02:00"], "toboff"));
// One instant spelled three ways (as is, lowercase t/z, +02:00 with a zero fraction): no warning.
write(
  "ts-order/equal-instant.json",
  tsOrderChain(["2026-06-20T10:00:00Z", "2026-06-20t10:00:00z", "2026-06-20T12:00:00.000+02:00"], "toeq"),
);
// A second 60 that both readings (a leap second; second 0 of the next minute) order the same way:
// no warning. Whether 2026-06-30 carried a leap second is irrelevant to the order rule.
write(
  "ts-order/second-60-ordered.json",
  tsOrderChain(["2026-06-30T23:59:59.5Z", "2026-06-30T23:59:60.2Z", "2026-07-01T00:00:01Z"], "to60"),
);
// A second 60 whose order depends on the reading: as a leap second 10:00:60.5 is before 10:01:00.1,
// read as 10:01:00.5 it is after it. The bytes cannot decide, so the pair is not comparable.
write("ts-order/not-comparable-second-60.json", tsOrderChain(["2026-06-20T10:01:00.1Z", "2026-06-20T10:00:60.5Z"], "tonc"));
// The equality boundary of the two readings. 10:00:60 then 10:01:00 is later as a leap second and
// equal as an overflow: neither reading puts it earlier, so no warning. The reverse order is earlier as
// a leap second and equal as an overflow: exactly one reading puts it earlier, so not comparable.
write("ts-order/second-60-then-next-minute.json", tsOrderChain(["2026-06-20T10:00:60Z", "2026-06-20T10:01:00Z"], "to60n"));
write("ts-order/not-comparable-second-60-equal.json", tsOrderChain(["2026-06-20T10:01:00Z", "2026-06-20T10:00:60Z"], "tonce"));
// A correctly ordered pair across a real leap second (the one at the end of 2016): in order as a leap
// second, backwards as an overflow, so not comparable. The code says the bytes cannot order the pair,
// not that a clock is wrong. It also pins the year boundary: the result holds only if 2017-01-01T00:00
// is the minute right after 2016-12-31T23:59.
write(
  "ts-order/not-comparable-real-leap-second.json",
  tsOrderChain(["2016-12-31T23:59:60.5Z", "2017-01-01T00:00:00.2Z"], "toleap"),
);
// CALENDAR AND OFFSET BRANCHES. Each chain puts a receipt whose LOCAL date lies across a boundary from
// its UTC date between two neighbours a fraction of a second away, so a calendar or offset error of a
// minute or more in either direction turns one of the expected results around.
// Year boundary through a positive offset: 2027-01-01T00:59:59.5+01:00 is 2026-12-31T23:59:59.5Z, and
// the last step goes back 0.1 s across the boundary.
write(
  "ts-order/year-boundary-positive-offset.json",
  tsOrderChain(
    ["2026-12-31T23:59:59Z", "2027-01-01T00:59:59.5+01:00", "2026-12-31T23:59:59.75Z", "2027-01-01T00:00:00Z", "2027-01-01T00:59:59.9+01:00"],
    "toyear",
  ),
);
// Month boundary of a common year through a negative offset with minutes: 2027-02-28T20:30:00.5-03:30
// is 2027-03-01T00:00:00.5Z, and the last step goes back 0.1 s.
write(
  "ts-order/month-boundary-negative-offset.json",
  tsOrderChain(["2027-03-01T00:00:00Z", "2027-02-28T20:30:00.5-03:30", "2027-03-01T00:00:01Z", "2027-02-28T20:30:00.9-03:30"], "tomonth"),
);
// Leap day through a positive offset with minutes: 2028-03-01T05:29:59.5+05:30 is 2028-02-29T23:59:59.5Z.
// In order throughout: no warning.
write(
  "ts-order/leap-day-positive-offset.json",
  tsOrderChain(["2028-02-29T23:59:59Z", "2028-03-01T05:29:59.5+05:30", "2028-02-29T23:59:59.75Z"], "toleapday"),
);
// Two steps back in one chain: the run reports both, in seq order ("ts-backwards: seq 1", then seq 2).
// A run that kept one of them, or reported them in another order, differs from this pin. The second
// file stores the same three receipts in the array order seq 1, seq 2, seq 0, a fixed permutation that
// moves every receipt (a random one would make the corpus irreproducible). Verifiers order receipts by
// chain.seq (spec §5), so its result and its warnings, in the same order, are those of the first file;
// a verifier that compared array neighbours instead would report one warning, not two.
const backwardsTwice = tsOrderChain(["2026-06-20T10:00:02Z", "2026-06-20T10:00:01Z", "2026-06-20T10:00:00Z"], "tob2");
write("ts-order/backwards-twice.json", backwardsTwice);
write("ts-order/backwards-twice-shuffled.json", [backwardsTwice[1]!, backwardsTwice[2]!, backwardsTwice[0]!]);

// 10d. INDEPENDENT FIELDS — these MUST STAY VALID (independent-fields/). Spec §2 "Independent fields":
//      R1-R4 are one-directional, and the pairs below are deliberately not coupled, so a verifier that
//      refused any of these receipts would refuse an input this version accepts. Every chain is genuine,
//      stays VALID with the keyring and carries no timestamp-order warning; impl-py/conformance.mjs pins
//      that for TS and Python, and the Go, Rust and C# runners compare theirs with Python's.
function independentChain(idPrefix: string, receipts: Array<Pick<BuildInput, "ts" | "action" | "governance">>): Receipt[] {
  const out: Receipt[] = [];
  let prev: Receipt | null = null;
  receipts.forEach((r, i) => {
    const built = buildReceipt(
      {
        id: `${idPrefix}_${i}`,
        ts: r.ts,
        scope: { tenant: "store_demo", chain: `independent-fields-${idPrefix}` },
        agent: inputs[0]!.agent,
        action: r.action,
        governance: r.governance,
      },
      prev,
      signer,
    );
    out.push(built);
    prev = built;
  });
  return out;
}
// The highest authorization-risk tier beside an action that can be undone: reversibility is read from
// `reversible` (and `rollbackRef`) only.
write(
  "independent-fields/risk-class-vs-reversible.json",
  independentChain("ifrisk", [
    {
      ts: "2026-06-20T09:00:00.000Z",
      action: { id: "payment.refund", canonical: "payment.refund", riskClass: "IRREVERSIBLE", paramsHash: ph("amount=4200;currency=DKK"), reversible: true, rollbackRef: "snap_before_refund" },
      governance: { mode: "on", verdict: "EXECUTED", ruleId: "irreversible-tier-review", approval: null, sandboxed: false },
    },
  ]),
);
// The mode labels the producer's enforcement mode and prescribes no verdict: EXECUTED under approvals_on
// with the approval evidenced outside the receipt, then BLOCKED under off and under shadow.
write(
  "independent-fields/mode-vs-verdict-and-approval.json",
  independentChain("ifmode", [
    { ts: "2026-06-20T09:00:00.000Z", action: inputs[0]!.action, governance: { mode: "approvals_on", verdict: "EXECUTED", ruleId: "approved-out-of-band", approval: null, sandboxed: false } },
    { ts: "2026-06-20T09:01:00.000Z", action: inputs[0]!.action, governance: { mode: "off", verdict: "BLOCKED", ruleId: "blocked-mode-off", approval: null, sandboxed: false } },
    { ts: "2026-06-20T09:02:00.000Z", action: inputs[0]!.action, governance: { mode: "shadow", verdict: "BLOCKED", ruleId: "blocked-mode-shadow", approval: null, sandboxed: false } },
  ]),
);
// An execution recorded beside a recorded policy denial (an execution despite a DENY is evidence worth
// keeping). The three digests are shape-correct stand-ins: chain verification checks the commitment's
// shape only, and the offline L2 check (spec §9) needs the policy and inputs out of band.
write(
  "independent-fields/compliance-deny-vs-executed.json",
  independentChain("ifdeny", [
    {
      ts: "2026-06-20T09:00:00.000Z",
      action: inputs[0]!.action,
      governance: {
        mode: "on",
        verdict: "EXECUTED",
        ruleId: "executed-despite-deny",
        approval: null,
        sandboxed: false,
        compliance: { policyHash: ph("policy:refund-guard"), readSetHash: ph("read-set:action,amountMinor"), inputsHash: ph("inputs:payment.refund,4200"), verdict: "DENY" },
      },
    },
  ]),
);
// An approval stamped after its receipt's `ts`, by another clock. The first approval.at is also later
// than the second receipt's ts, so a verifier that ordered receipts by approval.at would warn here.
write(
  "independent-fields/approval-at-after-ts.json",
  independentChain("ifappr", [
    {
      ts: "2026-06-20T09:00:00.000Z",
      action: inputs[0]!.action,
      governance: { mode: "on", verdict: "EXECUTED", ruleId: "human-approved", approval: { by: inputs[1]!.governance.approval!.by, at: "2026-06-20T09:05:00.000Z" }, sandboxed: false },
    },
    { ts: "2026-06-20T09:01:00.000Z", action: inputs[0]!.action, governance: { mode: "on", verdict: "EXECUTED", ruleId: "low-risk-auto", approval: null, sandboxed: false } },
  ]),
);

// 10e. RECEIPT ID UNIQUENESS — WARNINGS, NEVER VERDICTS (duplicate-id/). Spec §2: every receipt of one
//      `scope.chain` MUST carry a distinct `id`, compared as exact strings after JSON parsing (no
//      Unicode normalization, case-sensitive). Spec §5 step 6c: a 0.1 verifier reports
//      "duplicate-id: seq N" for every receipt whose id equals the id of a LOWER seq, in seq order and
//      after that seq's timestamp-order code, and never refuses the chain for it. Every chain below is
//      genuine and MUST stay VALID with the keyring in every verifier; impl-py/conformance.mjs pins the
//      expected warnings for TS and Python, and the Go, Rust and C# runners compare theirs with Python's.
function idChain(ids: string[], name: string, stamps?: string[]): Receipt[] {
  const out: Receipt[] = [];
  let prev: Receipt | null = null;
  ids.forEach((id, i) => {
    const r = buildReceipt(
      { ...inputs[2]!, id, ts: stamps?.[i] ?? `2026-06-20T11:00:0${i}Z`, scope: { tenant: "store_demo", chain: `duplicate-id-${name}` } },
      prev,
      signer,
    );
    out.push(r);
    prev = r;
  });
  return out;
}
// Two receipts share an id: the later one (seq 2) is reported, the first holder (seq 1) is not.
const dupPair = idChain(["rcpt_dup_pair_0", "rcpt_dup_pair_1", "rcpt_dup_pair_1"], "pair");
write("duplicate-id/pair.json", dupPair);
// One id at seq 0, 2 and 3: every later holder is reported, in seq order ("duplicate-id: seq 2", then
// seq 3). The second file stores the same four receipts in the array order seq 1, seq 3, seq 0, seq 2, a
// fixed permutation that moves every receipt. Verifiers order receipts by chain.seq, so its result and
// warnings are those of the first file; a verifier that compared ids in array order would report the
// holders at array positions 2 and 3 (seq 0 and seq 2) instead.
const dupTriple = idChain(["rcpt_dup_triple", "rcpt_dup_triple_other", "rcpt_dup_triple", "rcpt_dup_triple"], "triple");
write("duplicate-id/three-holders.json", dupTriple);
write("duplicate-id/three-holders-shuffled.json", [dupTriple[1]!, dupTriple[3]!, dupTriple[0]!, dupTriple[2]!]);
// Ids that differ only in letter case are different ids: no warning.
write("duplicate-id/case-differs.json", idChain(["rcpt_dup_case_A", "rcpt_dup_case_a"], "case"));
// The same visible id in NFC (U+00E9) and in NFD (e + U+0301) is two different strings: no warning.
// The builder refuses a non-NFC payload, so the NFD receipt (the last one, so no prevHash depends on its
// hash) is built under the NFC id and resealed; it is genuine and signed. Producers MUST emit NFC (§4),
// so the reference verifier also reports this receipt's non-NFC id; that warning is not compared here.
const dupNormalization = idChain(["rcpt_dup_café", "rcpt_dup_café_nfd"], "normalization");
dupNormalization[1]!.id = "rcpt_dup_café";
reseal(dupNormalization[1]!, PRIVATE_KEY);
write("duplicate-id/nfc-vs-nfd.json", dupNormalization);
// One receipt carries both warnings: its ts goes back one second and its id repeats seq 0's. Within one
// seq the timestamp-order code comes first ("ts-backwards: seq 1", then "duplicate-id: seq 1").
write(
  "duplicate-id/with-ts-backwards.json",
  idChain(["rcpt_dup_both", "rcpt_dup_both"], "both", ["2026-06-20T11:00:01Z", "2026-06-20T11:00:00Z"]),
);
// Ids are compared after JSON parsing: seq 1 spells seq 0's id with a JSON escape (e for "e").
// The hash and the signature cover the parsed value (JCS), so the receipt is genuine, and the two ids are
// one id: "duplicate-id: seq 1".
{
  const escapedId = idChain(["rcpt_dup_escaped", "rcpt_dup_escaped"], "escaped");
  const plain = '"id": "rcpt_dup_escaped"';
  const text = JSON.stringify(escapedId, null, 2) + "\n";
  const last = text.lastIndexOf(plain);
  if (text.indexOf(plain) === last) throw new Error("duplicate-id/escaped-spelling: expected two id members");
  write("duplicate-id/escaped-spelling.json", text.slice(0, last) + '"id": "rcpt_dup_\\u0065scaped"' + text.slice(last + plain.length));
}

// 11. STRICT Ed25519 KEY AND SCALAR VALIDATION (strict-ed25519/). Every verifier refuses
//     non-canonical, small-order and mixed-order public-key encodings at key load (RFC 8032 §5.1.3
//     decoding + small-order rejection + prime-order subgroup) and a non-canonical signature scalar
//     (S >= L, RFC 8032 §5.1.7). Each keyring maps the corpus kid to one refused key; run with
//     valid-chain.json every verifier must return TAMPERED. The verdict alone does not show WHERE the
//     refusal happened — the receipts are signed by a different key, so signature verification would
//     refuse them too. The key-load stage is pinned separately: impl-py/conformance.mjs (TS + Python),
//     the Go and Rust unit tests, and the C# self-check (impl-csharp/selfcheck) call each port's
//     key-load function on these keys directly.
//     Kept out of attack/ on purpose: these are keyring fixtures, not receipt vectors.
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const STRICT_ED25519_REFUSED_KEYS: Array<[string, string]> = [
  ["keyring-low-order-0.json", "0100000000000000000000000000000000000000000000000000000000000000"], // identity
  ["keyring-low-order-1.json", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"], // order 2
  ["keyring-low-order-2.json", "0000000000000000000000000000000000000000000000000000000000000000"], // order 4
  ["keyring-low-order-3.json", "0000000000000000000000000000000000000000000000000000000000000080"], // order 4
  ["keyring-low-order-4.json", "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"], // order 8
  ["keyring-low-order-5.json", "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"], // order 8
  ["keyring-low-order-6.json", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"], // order 8
  ["keyring-low-order-7.json", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"], // order 8
  ["keyring-x0-sign-y-1.json", "0100000000000000000000000000000000000000000000000000000000000080"], // x = 0, sign bit set
  ["keyring-x0-sign-y-p-minus-1.json", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"], // x = 0, sign bit set
  ["keyring-y-p-sign.json", "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"], // y = p (not < p)
  ["keyring-y-p-plus-1.json", "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"], // y = p + 1 (not < p)
  ["keyring-off-curve-y-2.json", "0200000000000000000000000000000000000000000000000000000000000000"], // no x for y = 2
];
// The corpus key plus the order-2 point, (x, y) -> (-x, -y): a curve point outside the prime-order
// subgroup (mixed order).
{
  const raw = Buffer.from(PUBLIC_KEY, "base64").subarray(12);
  const p = (1n << 255n) - 19n;
  let y = 0n;
  for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(i === 31 ? raw[i]! & 0x7f : raw[i]!);
  const mixed = Buffer.alloc(32);
  let v = p - y;
  for (let i = 0; i < 32; i++) {
    mixed[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  mixed[31] = (mixed[31]! & 0x7f) | ((raw[31]! & 0x80) ^ 0x80);
  STRICT_ED25519_REFUSED_KEYS.push(["keyring-mixed-order.json", mixed.toString("hex")]);
}
for (const [name, rawHex] of STRICT_ED25519_REFUSED_KEYS) {
  write(`strict-ed25519/${name}`, { [KID]: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(rawHex, "hex")]).toString("base64") });
}
// A genuine signature re-encoded with S + L: the same group element, a non-canonical scalar.
const ED25519_L = 2n ** 252n + 27742317777372353535851937790883648493n;
const sNotCanonical = clone(chain);
{
  const sig = Buffer.from(sNotCanonical[1]!.sig.value, "base64");
  let s = 0n;
  for (let i = 63; i >= 32; i--) s = (s << 8n) | BigInt(sig[i]!);
  s += ED25519_L;
  for (let i = 32; i < 64; i++) {
    sig[i] = Number(s & 0xffn);
    s >>= 8n;
  }
  sNotCanonical[1]!.sig.value = sig.toString("base64");
}
write("strict-ed25519/chain-s-not-canonical.json", sNotCanonical);
write(
  "strict-ed25519/README.md",
  [
    "# Strict Ed25519 key and scalar validation",
    "",
    "Generated by `scripts/gen-vectors.ts` (section 11); do not hand-edit.",
    "",
    "**Rule.** Every verifier in this repository applies strict public-key validation at key load,",
    "from the key bytes alone and before signature verification: it refuses non-canonical and",
    "small-order Ed25519 key encodings (RFC 8032 §5.1.3 decoding + small-order rejection) and keys",
    "outside the prime-order subgroup. A keyring public key is refused when",
    "",
    "1. its y coordinate (the low 255 bits) is not canonical (y >= p);",
    "2. y does not decode to a curve point (x^2 = (y^2 - 1) / (d*y^2 + 1) has no square root);",
    "3. x = 0 and the sign bit is set (RFC 8032 §5.1.3 step 4);",
    "4. the point is in the small-order torsion subgroup (any of the 8 points, in any spelling);",
    "5. the point is not in the prime-order subgroup ([L]A is not the identity: a mixed-order key).",
    "",
    "A signature is refused when its R is not canonically encoded (steps 1-3) or is small-order",
    "(step 4), or when its scalar S is not canonical (S >= L, RFC 8032 §5.1.7). Verification uses the",
    "cofactorless equation [S]B = R + [k]A with k reduced mod L.",
    "",
    "A key produced by Ed25519 key generation passes every step, so no valid key or signature changes",
    "verdict.",
    "",
    "**Vectors.** Each `keyring-*.json` maps the corpus kid to one refused public key. Verified with",
    "`../valid-chain.json` every keyring must yield `TAMPERED` (exit 2) in all five verifiers: a",
    "small-order public key must be refused at key load, and so must every non-canonical, off-curve or",
    "mixed-order encoding. `chain-s-not-canonical.json` is `../valid-chain.json` with the second",
    "receipt's signature re-encoded as S + L; with `../keyring.json` it must yield `TAMPERED`.",
    "",
    "A `TAMPERED` verdict does not show WHERE the refusal happened: these receipts are signed by a",
    "different key, so signature verification would refuse them as well. The key-load stage is pinned",
    "separately by each port's own check of its key-load function (`impl-py/conformance.mjs` for",
    "TypeScript and Python, the Go and Rust unit tests, and `impl-csharp/selfcheck`).",
    "",
  ].join("\n"),
);

// --- malformed (raw text / structural rejects) ---

// duplicate object key (cannot be expressed with JS objects → raw text)
write(
  "malformed/duplicate-key.json",
  '[{"spec":"noa.receipt/0.1","id":"x","id":"y","ts":"2026-06-20T00:00:00Z"}]\n',
);
// float number (receipts are integer-only)
write("malformed/float-number.json", '[{"chain":{"seq":1.5}}]\n');
// prototype pollution
write("malformed/proto-pollution.json", '{"__proto__":{"polluted":true}}\n');
// unknown extra field (PII smuggle)
const smuggle = clone(chain) as unknown as Array<Record<string, unknown>>;
smuggle[0]!["customerEmail"] = "victim@example.com";
write("malformed/pii-smuggle.json", smuggle);
// trailing garbage
write("malformed/trailing-garbage.json", "[]trailing\n");
// deeply nested (depth bomb)
let deep = "0";
for (let i = 0; i < 200; i++) deep = "[" + deep + "]";
write("malformed/deep-nest.json", deep + "\n");
// unpaired surrogates (forgery channel — must be rejected, not collapsed to U+FFFD)
write("malformed/lone-high-surrogate.json", '["transfer\\ud800"]\n');
write("malformed/lone-low-surrogate.json", '["transfer\\udfff"]\n');
write("malformed/reversed-surrogate-pair.json", '["x\\udc00\\ud800y"]\n');

// --- 12. STRICT-BYTES PROFILE (opt-in `--profile strict-bytes`; native acceptance unchanged) ---
//
// Byte-exact chain files over the genuine 3-receipt chain above, written as BYTES (never through the
// pretty-printing object branch of `write`). The expectations below are AUTHORED CONSTANTS, the
// contract every consumer asserts; nothing here runs a verifier. Native: the parsed-value verdict,
// with the corpus keyring. Strict: the same keyring under --profile strict-bytes, where the WHOLE file
// must equal UTF8(JCS(parse(file))) — the complete array in presented order — before any receipt
// check, and a mismatch is MALFORMED (exit 3) carrying NON_CANONICAL_BYTES. `native: null` marks a
// transport-invalid input whose existing per-language native outcome is preserved, not asserted.
{
  const SB = "strict-bytes";
  const utf8 = (s: string): Buffer => Buffer.from(s, "utf8");
  const members = (c: Receipt[]): string[] => c.map((r) => canonicalize(r));
  const canonicalText = canonicalize(chain);
  const rj = members(chain);
  if (canonicalText !== "[" + rj.join(",") + "]") throw new Error("strict-bytes: array JCS is not the bracketed member join");

  /** A formatting mutation must keep the parsed value and must change the bytes — else it pins nothing. */
  const formatting = (name: string, bytes: Buffer, valueCanonical: string): Buffer => {
    if (bytes.equals(utf8(valueCanonical))) throw new Error(`strict-bytes/${name}: the mutation did not change the bytes`);
    if (canonicalize(JSON.parse(bytes.toString("utf8"))) !== valueCanonical) throw new Error(`strict-bytes/${name}: the mutation changed the parsed value`);
    return bytes;
  };
  /** One space after the FIRST separator BETWEEN RECEIPTS — invisible to a per-receipt comparison. */
  const interReceiptSpace = (m: string[]): string => "[" + m[0] + ", " + m.slice(1).join(",") + "]";

  // Genesis receipt with its first two members (action, agent) swapped, each member's bytes kept.
  const g = chain[0] as unknown as Record<string, unknown>;
  const gKeys = Object.keys(g).sort();
  if (gKeys[0] !== "action" || gKeys[1] !== "agent") throw new Error("strict-bytes/member-order: unexpected genesis member order");
  const swapped = ["agent", "action", ...gKeys.slice(2)];
  const genesisSwapped = "{" + swapped.map((k) => canonicalize(k) + ":" + canonicalize(g[k])).join(",") + "}";

  const specMember = '"spec":"noa.receipt/0.1"';
  const specAt = canonicalText.indexOf(specMember);
  if (specAt < 0) throw new Error("strict-bytes/escaped-string: spec member not found");
  const escaped = canonicalText.slice(0, specAt) + '"spec":"\\u006eoa.receipt/0.1"' + canonicalText.slice(specAt + specMember.length);

  const invalidUtf8 = Buffer.from(utf8(canonicalText));
  const agentAt = invalidUtf8.indexOf(utf8("agent-refunds"));
  if (agentAt < 0) throw new Error("strict-bytes/invalid-utf8: agent id not found");
  invalidUtf8[agentAt] = 0xff; // 0xFF is never valid UTF-8

  // The genesis chain.seq written as the integer token -0: the same parsed value (JCS(0) = "0"), different
  // bytes. Native handling of -0 differs between ports today (Rust refuses it as a float), so only the
  // strict expectation is authored.
  const seqMember = '"seq":0';
  const seqAt = canonicalText.indexOf(seqMember);
  if (seqAt < 0 || /[0-9]/.test(canonicalText.charAt(seqAt + seqMember.length))) throw new Error("strict-bytes/negative-zero: genesis seq member not found");
  const negativeZero = canonicalText.slice(0, seqAt) + '"seq":-0' + canonicalText.slice(seqAt + seqMember.length);

  const reversed = canonicalize([chain[2], chain[1], chain[0]]);
  const badsigText = canonicalize(badsig);

  type Outcome = { status: string; exit: number };
  type StrictOutcome = Outcome & { discriminator: "NON_CANONICAL_BYTES" | null };
  const VALID: Outcome = { status: "VALID", exit: 0 };
  const TAMPERED: Outcome = { status: "TAMPERED", exit: 2 };
  const NCB: StrictOutcome = { status: "MALFORMED", exit: 3, discriminator: "NON_CANONICAL_BYTES" };
  const cases: Array<{ name: string; bytes: Buffer; native: Outcome | null; strict: StrictOutcome; construction: string }> = [
    { name: "canonical", bytes: utf8(canonicalText), native: VALID, strict: { ...VALID, discriminator: null }, construction: "UTF8(JCS(chain))" },
    { name: "extra-space", bytes: formatting("extra-space", utf8(interReceiptSpace(rj)), canonicalText), native: VALID, strict: NCB, construction: "U+0020 after the first array separator between receipts" },
    { name: "member-order", bytes: formatting("member-order", utf8("[" + genesisSwapped + "," + rj.slice(1).join(",") + "]"), canonicalText), native: VALID, strict: NCB, construction: "the genesis receipt's action/agent members swapped, member bytes kept" },
    { name: "escaped-string", bytes: formatting("escaped-string", utf8(escaped), canonicalText), native: VALID, strict: NCB, construction: "the first \"noa.receipt/0.1\" written as \"\\u006eoa.receipt/0.1\"" },
    { name: "trailing-lf", bytes: formatting("trailing-lf", utf8(canonicalText + "\n"), canonicalText), native: VALID, strict: NCB, construction: "canonical bytes followed by 0A" },
    { name: "pretty", bytes: formatting("pretty", utf8(JSON.stringify(JSON.parse(canonicalText), null, 2)), canonicalText), native: VALID, strict: NCB, construction: "two-space pretty serialization of parse(canonical), no final newline" },
    { name: "leading-space", bytes: formatting("leading-space", utf8(" " + canonicalText), canonicalText), native: VALID, strict: NCB, construction: "guard: one U+0020 before the canonical bytes" },
    { name: "trailing-crlf", bytes: formatting("trailing-crlf", utf8(canonicalText + "\r\n"), canonicalText), native: VALID, strict: NCB, construction: "guard: canonical bytes followed by 0D 0A" },
    { name: "bom", bytes: Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), utf8(canonicalText)]), native: null, strict: { status: "MALFORMED", exit: 3, discriminator: null }, construction: "guard: EF BB BF before the canonical bytes (refused at input admission)" },
    { name: "invalid-utf8", bytes: invalidUtf8, native: null, strict: { status: "MALFORMED", exit: 3, discriminator: null }, construction: "guard: canonical bytes with the first byte of the genesis agent.id replaced by FF (refused at input admission)" },
    { name: "reversed-order", bytes: utf8(reversed), native: VALID, strict: { ...VALID, discriminator: null }, construction: "guard: UTF8(JCS([seq 2, seq 1, seq 0])) — canonical in presented order; the verifier orders by seq afterwards" },
    { name: "wrong-signature-canonical", bytes: utf8(badsigText), native: TAMPERED, strict: { ...TAMPERED, discriminator: null }, construction: "guard: UTF8(JCS(attack/wrong-signature chain)) — canonical bytes, bad signature" },
    { name: "wrong-signature-noncanonical", bytes: formatting("wrong-signature-noncanonical", utf8(interReceiptSpace(members(badsig))), badsigText), native: TAMPERED, strict: NCB, construction: "guard: the wrong-signature chain with the extra-space mutation — the byte mismatch outranks the bad signature" },
    { name: "negative-zero", bytes: formatting("negative-zero", utf8(negativeZero), canonicalText), native: null, strict: NCB, construction: "guard: the genesis chain.seq written as the integer token -0 (native per-language handling differs and is not asserted)" },
  ];
  const sha256 = (b: Buffer): string => createHash("sha256").update(b).digest("hex");
  for (const c of cases) write(`${SB}/${c.name}.json`, c.bytes);

  // COSE: the complete genesis receipt as the attached payload. The space is inserted BEFORE signing,
  // so the outer COSE signature and the receipt's own native signature are both genuine; only the
  // whole-payload canonical check (src/cose/receipt-cose.ts) can refuse it.
  const genesisText = canonicalize(chain[0]);
  const coseCanonical = coseSign1(utf8(genesisText), signer);
  const coseExtraSpace = coseSign1(formatting("extra-space.cose", utf8("{ " + genesisText.slice(1)), genesisText), signer);
  write(`${SB}/canonical.cose`, coseCanonical);
  write(`${SB}/extra-space.cose`, coseExtraSpace);

  // JCS literal bytes (decision 3): an authored input and its authored RFC 8785 output. Keys U+1F600
  // (a surrogate pair, D83D...) and U+E000 pin UTF-16 order (astral BEFORE U+E000); the values pin
  // the short escapes, lowercase \u00XX controls, a literal DEL, a literal "/", literal non-ASCII,
  // decomposed text kept decomposed (no normalization), and the safe-integer bounds.
  const jcsInput =
    '{"\\ue000":1,"\\ud83d\\ude00":2,"a":["\\"\\\\\\/","\\u0001\\u001f\\u007f","\\u00e9","e\\u0301","\\u2028\\u2029","\\b\\f\\n\\r\\t"],"n":[9007199254740991,-9007199254740991]}';
  const jcsExpected =
    '{"a":["\\"\\\\/","\\u0001\\u001f\u007f","\u00e9","e\u0301","\u2028\u2029","\\b\\f\\n\\r\\t"],"n":[9007199254740991,-9007199254740991],"\ud83d\ude00":2,"\ue000":1}';
  if (canonicalize(JSON.parse(jcsInput)) !== jcsExpected) throw new Error("strict-bytes: the authored JCS literal does not match the reference canonicalizer");
  write(`${SB}/jcs-literal-input.json`, utf8(jcsInput));
  write(`${SB}/jcs-literal-expected.json`, utf8(jcsExpected));

  write(`${SB}/manifest.json`, {
    spec: "noa.strict-bytes-vectors/0.1",
    keyring: "../keyring.json",
    note:
      "Authored expectations for the opt-in strict-bytes verifier profile; never derived from verifier output. " +
      "native = the default profile with the keyring; strict = --profile strict-bytes with the keyring. " +
      "native null = an input whose existing per-language native outcome is preserved and not asserted (transport-invalid bytes, and the -0 token, whose native handling differs between ports). " +
      "strict.discriminator NON_CANONICAL_BYTES must lead the TS reason / the port's detail; null = not asserted.",
    cases: cases.map((c) => ({ name: c.name, file: `${c.name}.json`, sha256: sha256(c.bytes), construction: c.construction, native: c.native, strict: c.strict })),
    cose: [
      { file: "canonical.cose", sha256: sha256(coseCanonical), coseSign1Verify: true, receiptFromCose: true },
      { file: "extra-space.cose", sha256: sha256(coseExtraSpace), coseSign1Verify: true, receiptFromCose: false },
    ],
    coseCoverage: "TypeScript only (test/cose/cose.test.ts); Python, Go, Rust and C# have no COSE implementation — unavailable, not passed.",
    jcsLiteral: {
      input: "jcs-literal-input.json",
      inputSha256: sha256(utf8(jcsInput)),
      expected: "jcs-literal-expected.json",
      expectedSha256: sha256(utf8(jcsExpected)),
    },
  });
}

const attackCount = readdirSync(join(OUT, "attack")).length;
const malformedCount = readdirSync(join(OUT, "malformed")).length;
process.stdout.write(
  `generated ${chain.length}-receipt chain + checkpoint + ${attackCount} attack + ${malformedCount} malformed vectors -> ${OUT}\n`,
);
