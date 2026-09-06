import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { buildCheckpoint, buildReceipt, type BuildInput, type Signer } from "../src/builder.js";
import { generateKeyPair, signEd25519 } from "../src/keys.js";
import { checkpointHashInput } from "../src/canonicalize.js";
import { signingMessage, CHECKPOINT_SIG_DOMAIN } from "../src/signing.js";
import { sha256Prefixed } from "../src/hash.js";
import { verifyChain, verifyHistoricalChain } from "../src/verify.js";
import type { Checkpoint, Receipt, SigningKeyLifecycle } from "../src/index.js";
import { b } from "./helpers/bytes.js";

const RECEIPT_AT = "2026-01-01T00:00:00.000Z";
const WITNESS_AT = "2026-01-01T00:00:01.000Z";
const RETIRED_AT = "2026-01-02T00:00:00.000Z";

function input(id: string, ts: string, action = "inventory.read"): BuildInput {
  return {
    id,
    ts,
    scope: { tenant: "historical-test", chain: "g2-survivable-retirement" },
    agent: { id: "historical-agent", model: null, principal: "SERVICE" },
    action: {
      id: action,
      canonical: action,
      riskClass: "LOW",
      paramsHash: sha256Prefixed(`id=${id}`),
      reversible: true,
      rollbackRef: null,
    },
    governance: { mode: "on", verdict: "EXECUTED", ruleId: "historical-test", approval: null, sandboxed: false },
  };
}

function lifecycle(
  kid: string,
  publicKey: string,
  retiredAt: string | null,
  validFrom?: string | null,
): SigningKeyLifecycle {
  const entry: { publicKey: string; validFrom?: string | null; retiredAt: string | null } = {
    publicKey,
    retiredAt,
  };
  if (validFrom !== undefined) entry.validFrom = validFrom;
  return {
    spec: "noa.signing-key-lifecycle/0.1",
    keys: { [kid]: entry },
  };
}

function resealCheckpoint(cp: Checkpoint, signer: Signer): Checkpoint {
  cp.sig.kid = signer.kid;
  cp.sig.value = signEd25519(
    signer.privateKey,
    signingMessage(CHECKPOINT_SIG_DOMAIN, checkpointHashInput(cp)),
  );
  return cp;
}

function fixture() {
  const receiptKey = generateKeyPair("receipt-retired");
  const witnessKey = generateKeyPair("checkpoint-current");
  const wrongKey = generateKeyPair("checkpoint-current");
  const receiptSigner = { kid: receiptKey.kid, privateKey: receiptKey.privateKey };
  const witnessSigner = { kid: witnessKey.kid, privateKey: witnessKey.privateKey };
  const r0 = buildReceipt(input("historical-0", RECEIPT_AT), null, receiptSigner);
  const r1 = buildReceipt(input("historical-1", "2026-01-01T00:00:00.500Z"), r0, receiptSigner);
  const r2 = buildReceipt(input("historical-2", "2026-01-01T00:00:00.750Z"), r1, receiptSigner);
  return {
    receiptKey,
    witnessKey,
    wrongKey,
    receiptSigner,
    witnessSigner,
    chain: [r0, r1, r2],
    retiredRoot: b(lifecycle(receiptKey.kid, receiptKey.publicKey, RETIRED_AT)),
    currentRoot: b(lifecycle(receiptKey.kid, receiptKey.publicKey, null)),
    witnessRoot: b({ [witnessKey.kid]: witnessKey.publicKey }),
  };
}

test("historical side API preserves intact retired-key history without reviving current authority", () => {
  const f = fixture();
  const receipts = b(f.chain.slice(0, 2));
  const currentUse = verifyChain(receipts, { keyring: f.retiredRoot });
  const historical = verifyHistoricalChain(receipts, { keyring: f.retiredRoot });

  assert.equal(currentUse.status, "TAMPERED");
  assert.match(currentUse.reason ?? "", /retired/);
  assert.equal(historical.classification, "UNVERIFIED");
  assert.equal(historical.code, "NO_WITNESS");
  assert.deepEqual(historical.dimensions, {
    integrity: "INTACT",
    completeness: "UNANSWERED",
    attribution: "UNATTRIBUTABLE",
    organizationalIndependence: "UNVERIFIED",
    evidence: { retirement: "PROVIDED", witness: "NOT_PROVIDED", availability: "NOT_PROVIDED" },
  });
});

test("separately trusted checkpoint before retirement anchors an exact head", () => {
  const f = fixture();
  const receipts = f.chain.slice(0, 2);
  const cp = buildCheckpoint(receipts[1]!, WITNESS_AT, f.witnessSigner);
  const result = verifyHistoricalChain(b(receipts), {
    keyring: f.retiredRoot,
    checkpoint: b(cp),
    checkpointKeyring: f.witnessRoot,
  });

  assert.equal(result.classification, "VERIFIED");
  assert.equal(result.code, "HEAD_ANCHORED");
  assert.equal(result.dimensions.integrity, "INTACT");
  assert.equal(result.dimensions.completeness, "HEAD_ANCHORED");
  assert.equal(result.dimensions.attribution, "ATTRIBUTABLE_AS_OF");
  assert.equal(result.attributedThroughSeq, 1);
  assert.equal(result.asOf, WITNESS_AT);
});

test("an authenticated lower checkpoint maps the former DEGRADED label to PARTIAL + PREFIX_ANCHORED", () => {
  const f = fixture();
  const cp = buildCheckpoint(f.chain[0]!, WITNESS_AT, f.witnessSigner);
  const result = verifyHistoricalChain(b(f.chain), {
    keyring: f.retiredRoot,
    checkpoint: b(cp),
    checkpointKeyring: f.witnessRoot,
  });

  assert.equal(result.classification, "PARTIAL", "PREFIX_ANCHORED is the documented DEGRADED migration");
  assert.equal(result.code, "PREFIX_ANCHORED");
  assert.equal(result.dimensions.completeness, "PREFIX_ANCHORED");
  assert.equal(result.dimensions.attribution, "ATTRIBUTABLE_AS_OF");
  assert.equal(result.attributedThroughSeq, 0);
});

test("checkpoint at or after retirement cannot attribute the retired signature", () => {
  const f = fixture();
  for (const ts of [RETIRED_AT, "2026-01-02T00:00:00.001Z"]) {
    const cp = buildCheckpoint(f.chain[2]!, ts, f.witnessSigner);
    const result = verifyHistoricalChain(b(f.chain), {
      keyring: f.retiredRoot,
      checkpoint: b(cp),
      checkpointKeyring: f.witnessRoot,
    });
    assert.equal(result.classification, "UNVERIFIED", ts);
    assert.equal(result.code, "CHECKPOINT_AFTER_RETIREMENT", ts);
    assert.equal(result.dimensions.integrity, "INTACT", ts);
    assert.equal(result.dimensions.completeness, "HEAD_ANCHORED", ts);
    assert.equal(result.dimensions.attribution, "UNATTRIBUTABLE", ts);
  }
});

test("checkpoint one nanosecond before retirement remains attributable", () => {
  const f = fixture();
  const checkpointAt = "2026-01-01T00:00:01.000000001Z";
  const retirementAt = "2026-01-01T00:00:01.000000002Z";
  const cp = buildCheckpoint(f.chain[2]!, checkpointAt, f.witnessSigner);
  const result = verifyHistoricalChain(b(f.chain), {
    keyring: b(lifecycle(f.receiptKey.kid, f.receiptKey.publicKey, retirementAt)),
    checkpoint: b(cp),
    checkpointKeyring: f.witnessRoot,
  });
  assert.equal(result.classification, "VERIFIED");
  assert.equal(result.dimensions.attribution, "ATTRIBUTABLE_AS_OF");
  assert.equal(result.asOf, checkpointAt);
});

test("historical attribution enforces the explicit inclusive activation bound without inventing one for legacy records", () => {
  const f = fixture();
  const checkpointAt = "2026-01-01T00:00:01.000000001Z";
  const cp = buildCheckpoint(f.chain[2]!, checkpointAt, f.witnessSigner);
  const evaluate = (validFrom?: string | null) => verifyHistoricalChain(b(f.chain), {
    keyring: b(lifecycle(f.receiptKey.kid, f.receiptKey.publicKey, RETIRED_AT, validFrom)),
    checkpoint: b(cp),
    checkpointKeyring: f.witnessRoot,
  });

  const legacy = evaluate();
  assert.equal(legacy.classification, "VERIFIED", "legacy two-field lifecycle gained a fabricated lower bound");
  assert.deepEqual(
    Object.keys(lifecycle(f.receiptKey.kid, f.receiptKey.publicKey, RETIRED_AT).keys[f.receiptKey.kid]!).sort(),
    ["publicKey", "retiredAt"],
    "compatibility control is not the original two-field lifecycle shape",
  );

  const afterActivation = evaluate("2026-01-01T00:00:01.000000000Z");
  assert.equal(afterActivation.classification, "VERIFIED");
  assert.equal(afterActivation.dimensions.attribution, "ATTRIBUTABLE_AS_OF");

  const atActivation = evaluate(checkpointAt);
  assert.equal(atActivation.classification, "VERIFIED", "validFrom must be inclusive");
  assert.equal(atActivation.dimensions.attribution, "ATTRIBUTABLE_AS_OF");

  const beforeActivation = evaluate("2026-01-01T00:00:01.000000002Z");
  assert.equal(beforeActivation.classification, "UNVERIFIED");
  assert.equal(beforeActivation.code, "CHECKPOINT_BEFORE_ACTIVATION");
  assert.equal(beforeActivation.dimensions.integrity, "INTACT");
  assert.equal(beforeActivation.dimensions.completeness, "HEAD_ANCHORED");
  assert.equal(beforeActivation.dimensions.attribution, "UNATTRIBUTABLE");
  assert.equal(beforeActivation.asOf, null);
});

test("lifecycle timestamps share lowercase RFC 3339 grammar and invalid explicit intervals fail closed", () => {
  const f = fixture();
  const checkpointAt = "2026-01-01t00:00:01.000000001z";
  const cp = buildCheckpoint(f.chain[2]!, checkpointAt, f.witnessSigner);
  const lowercase = verifyHistoricalChain(b(f.chain), {
    keyring: b(lifecycle(
      f.receiptKey.kid,
      f.receiptKey.publicKey,
      "2026-01-02t00:00:00.000000002z",
      checkpointAt,
    )),
    checkpoint: b(cp),
    checkpointKeyring: f.witnessRoot,
  });
  assert.equal(lowercase.classification, "VERIFIED");
  assert.equal(lowercase.asOf, checkpointAt);

  for (const validFrom of [RETIRED_AT, "2026-01-02T00:00:00.000000001Z"]) {
    const invalid = verifyHistoricalChain(b(f.chain), {
      keyring: b(lifecycle(f.receiptKey.kid, f.receiptKey.publicKey, RETIRED_AT, validFrom)),
      checkpoint: b(cp),
      checkpointKeyring: f.witnessRoot,
    });
    assert.equal(invalid.classification, "INVALID", validFrom);
    assert.equal(invalid.code, "RECEIPT_ROOT_INVALID", validFrom);
  }
});

test("checkpoint trust is separate by root and decoded key material", () => {
  const f = fixture();
  const cp = buildCheckpoint(f.chain[2]!, WITNESS_AT, f.witnessSigner);

  const missingRoot = verifyHistoricalChain(b(f.chain), { keyring: f.retiredRoot, checkpoint: b(cp) });
  assert.equal(missingRoot.code, "WITNESS_ROOT_NOT_PROVIDED");

  const wrongRoot = verifyHistoricalChain(b(f.chain), {
    keyring: f.retiredRoot,
    checkpoint: b(cp),
    checkpointKeyring: b({ [f.wrongKey.kid]: f.wrongKey.publicKey }),
  });
  assert.equal(wrongRoot.code, "WITNESS_INTEGRITY_FAILURE");
  assert.equal(wrongRoot.dimensions.integrity, "BROKEN");

  const aliasSigner = { kid: "checkpoint-alias", privateKey: f.receiptKey.privateKey };
  const aliasCp = buildCheckpoint(f.chain[2]!, WITNESS_AT, aliasSigner);
  const sameMaterial = verifyHistoricalChain(b(f.chain), {
    keyring: f.retiredRoot,
    checkpoint: b(aliasCp),
    checkpointKeyring: b({ [aliasSigner.kid]: f.receiptKey.publicKey }),
  });
  assert.equal(sameMaterial.code, "WITNESS_KEY_NOT_SEPARATE");
  assert.equal(sameMaterial.dimensions.attribution, "UNATTRIBUTABLE");
  assert.equal(sameMaterial.dimensions.organizationalIndependence, "UNVERIFIED");

  // The signature verifier requires canonical base64/SPKI before the decoded-material comparison.
  // A second spelling of the same bytes therefore cannot bypass separation by reaching it as an
  // accepted but textually different key.
  const nonCanonicalSameMaterial = f.receiptKey.publicKey.replace(/=$/, "");
  assert.notEqual(nonCanonicalSameMaterial, f.receiptKey.publicKey);
  const stringAlias = verifyHistoricalChain(b(f.chain), {
    keyring: f.retiredRoot,
    checkpoint: b(aliasCp),
    checkpointKeyring: b({ [aliasSigner.kid]: nonCanonicalSameMaterial }),
  });
  assert.equal(stringAlias.code, "WITNESS_INTEGRITY_FAILURE");
  assert.equal(stringAlias.dimensions.integrity, "BROKEN");
});

test("authenticated ahead and same-seq mismatches are conflicts, never inferred suppression", () => {
  const f = fixture();
  const presented = f.chain.slice(0, 2);
  const ahead = buildCheckpoint(f.chain[2]!, WITNESS_AT, f.witnessSigner);
  const aheadResult = verifyHistoricalChain(b(presented), {
    keyring: f.retiredRoot,
    checkpoint: b(ahead),
    checkpointKeyring: f.witnessRoot,
  });
  assert.equal(aheadResult.classification, "CONFLICT");
  assert.equal(aheadResult.code, "CHECKPOINT_AHEAD");
  assert.equal(aheadResult.dimensions.evidence.availability, "MISSING_RELATIVE_TO_CHECKPOINT");
  assert.notEqual(aheadResult.dimensions.evidence.availability, "PROVEN_SUPPRESSED");

  const contradiction = structuredClone(ahead);
  contradiction.highestSeq = 1;
  contradiction.headHash = "sha256:" + "0".repeat(64);
  resealCheckpoint(contradiction, f.witnessSigner);
  const conflictResult = verifyHistoricalChain(b(presented), {
    keyring: f.retiredRoot,
    checkpoint: b(contradiction),
    checkpointKeyring: f.witnessRoot,
  });
  assert.equal(conflictResult.classification, "CONFLICT");
  assert.equal(conflictResult.code, "CHECKPOINT_CONFLICT");
  assert.equal(conflictResult.dimensions.completeness, "CONFLICT");
});

test("cryptographic damage stays an integrity failure and evidence additions are monotone", () => {
  const f = fixture();
  const chainBytes = b(f.chain);
  const staticRoot = b({ [f.receiptKey.kid]: f.receiptKey.publicKey });
  const e = verifyHistoricalChain(chainBytes, { keyring: staticRoot });
  const eRetirement = verifyHistoricalChain(chainBytes, { keyring: f.retiredRoot });
  const cp = buildCheckpoint(f.chain[2]!, WITNESS_AT, f.witnessSigner);
  const eBoth = verifyHistoricalChain(chainBytes, {
    keyring: f.retiredRoot,
    checkpoint: b(cp),
    checkpointKeyring: f.witnessRoot,
  });
  assert.equal(e.dimensions.integrity, "INTACT");
  assert.equal(eRetirement.dimensions.integrity, "INTACT");
  assert.equal(eBoth.dimensions.integrity, "INTACT");
  assert.equal(e.dimensions.attribution, "UNATTRIBUTABLE");
  assert.equal(eBoth.dimensions.attribution, "ATTRIBUTABLE_AS_OF");

  const damaged = structuredClone(f.chain) as Receipt[];
  damaged[1]!.action.paramsHash = sha256Prefixed("damaged");
  const broken = verifyHistoricalChain(b(damaged), {
    keyring: f.retiredRoot,
    checkpoint: b(cp),
    checkpointKeyring: f.witnessRoot,
  });
  assert.equal(broken.classification, "INVALID");
  assert.equal(broken.code, "RECEIPT_INTEGRITY_FAILURE");
  assert.equal(broken.dimensions.integrity, "BROKEN");
});

test("historical verification parses receipt and checkpoint bytes once and reuses each exact tree", () => {
  // A SharedArrayBuffer-backed Uint8Array can change between reads. This source-level invariant is
  // deliberate: a behavioural race test would be timing-dependent, while the security property is
  // exact and mechanical — one receipt parse, then module-private verification of that parsed tree.
  const source = readFileSync(join(process.cwd(), "src", "verify.ts"), "utf8");
  const start = source.indexOf("export function verifyHistoricalChain(");
  const end = source.indexOf("type CheckpointVerdict", start);
  assert.ok(start >= 0 && end > start, "could not isolate verifyHistoricalChain source");
  const body = source.slice(start, end);
  assert.equal(
    [...body.matchAll(/parseDocument\(receipts,/g)].length,
    1,
    "historical verification re-read caller-controlled receipt bytes",
  );
  assert.match(body, /verifyParsedChain\(receiptsParsed\.value, integrityOptions\)/);
  assert.doesNotMatch(body, /^\s*const chainResult = verifyChain\(receipts,/m);
  assert.equal(
    [...body.matchAll(/parseDocument\(o\.checkpoint,/g)].length,
    1,
    "historical verification re-read caller-controlled checkpoint bytes",
  );
  assert.match(body, /verifyCheckpointParsed\(checkpoint, retainedWitnessTrust\)/);
  assert.doesNotMatch(body, /^\s*const checkpointVerdict = verifyCheckpoint\(o\.checkpoint,/m);
});

test("historical internal options ignore poisoned absent Object.prototype fields", () => {
  const f = fixture();
  const cp = buildCheckpoint(f.chain[2]!, WITNESS_AT, f.witnessSigner);
  const evaluate = () => verifyHistoricalChain(b(f.chain), {
    keyring: f.retiredRoot,
    checkpoint: b(cp),
    checkpointKeyring: f.witnessRoot,
  });
  const expected = evaluate();
  assert.equal(expected.classification, "VERIFIED");

  const poisons: Array<[string, unknown]> = [
    ["maxReceipts", 0],
    ["identityManifest", JSON.stringify({ "historical-agent": ["untrusted-kid"] })],
  ];
  for (const [name, value] of poisons) {
    const prior = Object.getOwnPropertyDescriptor(Object.prototype, name);
    Object.defineProperty(Object.prototype, name, { value, configurable: true });
    try {
      assert.deepEqual(evaluate(), expected, `inherited ${name} changed the historical verdict`);
    } finally {
      if (prior === undefined) delete (Object.prototype as Record<string, unknown>)[name];
      else Object.defineProperty(Object.prototype, name, prior);
    }
  }
});
