/**
 * Deterministic `noa.historical-verification/0.1` conformance corpus.
 *
 * Every verifier consumes these exact JSON bytes. The private keys are public test fixtures and
 * MUST NOT be used outside conformance. Expected results are written explicitly below rather than
 * copied from the TypeScript result, so generation cannot silently redefine the oracle.
 */
import assert from "node:assert/strict";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildCheckpoint, buildReceipt, type BuildInput, type Signer } from "../src/builder.js";
import { checkpointHashInput } from "../src/canonicalize.js";
import { sha256Prefixed } from "../src/hash.js";
import { signEd25519 } from "../src/keys.js";
import { signingMessage, CHECKPOINT_SIG_DOMAIN } from "../src/signing.js";
import {
  HISTORICAL_VERIFICATION_SPEC,
  verifyHistoricalChain,
  type HistoricalVerificationDimensions,
  type HistoricalVerificationResult,
} from "../src/verify.js";
import type { Checkpoint, Receipt, SigningKeyLifecycle } from "../src/index.js";
import { keyFromSeed } from "../test/federation/_seeded-keys.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUT = join(__dirname, "..", "..", "conformance", "survivable-retirement");
const CHAIN = "g2-survivable-retirement";
const RETIRED_AT = "2026-01-02T00:00:00.000000002Z";
const BEFORE_RETIREMENT = "2026-01-01T00:00:01.000Z";
const NANOS_BEFORE_RETIREMENT = "2026-01-02T00:00:00.000000001Z";
const ACTIVATION_BEFORE_CHECKPOINT = "2026-01-01T00:00:00.000Z";
const ACTIVATION_AT_CHECKPOINT = BEFORE_RETIREMENT;
const ACTIVATION_ONE_NANOSECOND_AFTER_CHECKPOINT = "2026-01-01T00:00:01.000000001Z";
const LOWERCASE_ACTIVATION = "2026-01-01t00:00:01.000z";
const LOWERCASE_RETIREMENT = "2026-01-02t00:00:00.000000002z";

const receiptKey = keyFromSeed("g2-receipt-retired", "11".repeat(32));
const witnessKey = keyFromSeed("g2-checkpoint-current", "22".repeat(32));
const wrongKey = keyFromSeed("g2-wrong-root", "33".repeat(32));
const receiptSigner: Signer = { kid: receiptKey.kid, privateKey: receiptKey.privateKey };
const witnessSigner: Signer = { kid: witnessKey.kid, privateKey: witnessKey.privateKey };

function input(seq: number): BuildInput {
  return {
    id: `g2-receipt-${seq}`,
    ts: `2026-01-01T00:00:00.${String(seq * 250).padStart(3, "0")}Z`,
    scope: { tenant: "g2-test", chain: CHAIN },
    agent: { id: "g2-historical-agent", model: null, principal: "SERVICE" },
    action: {
      id: "inventory.read",
      canonical: "inventory.read",
      riskClass: "LOW",
      paramsHash: sha256Prefixed(`seq=${seq}`),
      reversible: true,
      rollbackRef: null,
    },
    governance: { mode: "on", verdict: "EXECUTED", ruleId: "g2-test", approval: null, sandboxed: false },
  };
}

function lifecycle(retiredAt: string | null, validFrom?: string | null): SigningKeyLifecycle {
  const entry: { publicKey: string; validFrom?: string | null; retiredAt: string | null } = {
    publicKey: receiptKey.publicKey,
    retiredAt,
  };
  // Omission is intentional: most corpus cases pin compatibility with the original two-field
  // lifecycle record. An absent lower bound must never be replaced with a generated timestamp.
  if (validFrom !== undefined) entry.validFrom = validFrom;
  return {
    spec: "noa.signing-key-lifecycle/0.1",
    keys: { [receiptKey.kid]: entry },
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

function write(rel: string, value: unknown): void {
  const path = join(OUT, rel);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(value, null, 2) + "\n");
}

const chain: Receipt[] = [];
let previous: Receipt | null = null;
for (let seq = 0; seq < 3; seq++) {
  const receipt = buildReceipt(input(seq), previous, receiptSigner);
  chain.push(receipt);
  previous = receipt;
}

const exact = buildCheckpoint(chain[2]!, BEFORE_RETIREMENT, witnessSigner);
const exactNanos = buildCheckpoint(chain[2]!, NANOS_BEFORE_RETIREMENT, witnessSigner);
const prefix = buildCheckpoint(chain[0]!, BEFORE_RETIREMENT, witnessSigner);
const ahead = buildCheckpoint(chain[2]!, BEFORE_RETIREMENT, witnessSigner);
const atRetirement = buildCheckpoint(chain[2]!, RETIRED_AT, witnessSigner);
const afterRetirement = buildCheckpoint(chain[2]!, "2026-01-02T00:00:00.000000003Z", witnessSigner);
const lowercaseBoundary = buildCheckpoint(chain[2]!, LOWERCASE_ACTIVATION, witnessSigner);
const conflict = structuredClone(exact);
conflict.headHash = "sha256:" + "0".repeat(64);
resealCheckpoint(conflict, witnessSigner);
const forged = structuredClone(exact);
forged.sig.value = Buffer.alloc(64).toString("base64");
const aliasSigner: Signer = { kid: "g2-checkpoint-alias", privateKey: receiptKey.privateKey };
const sameKey = buildCheckpoint(chain[2]!, BEFORE_RETIREMENT, aliasSigner);
const damaged = structuredClone(chain);
damaged[1]!.action.paramsHash = sha256Prefixed("damaged");

const receiptStatic = { [receiptKey.kid]: receiptKey.publicKey };
const receiptRetired = lifecycle(RETIRED_AT);
const receiptWindow = lifecycle(RETIRED_AT, ACTIVATION_BEFORE_CHECKPOINT);
const receiptAtActivation = lifecycle(RETIRED_AT, ACTIVATION_AT_CHECKPOINT);
const receiptBeforeActivation = lifecycle(RETIRED_AT, ACTIVATION_ONE_NANOSECOND_AFTER_CHECKPOINT);
const receiptLowercaseWindow = lifecycle(LOWERCASE_RETIREMENT, LOWERCASE_ACTIVATION);
const receiptInvalidInterval = lifecycle(RETIRED_AT, "2026-01-02T00:00:00.000000003Z");
const checkpointRoot = { [witnessKey.kid]: witnessKey.publicKey };
const wrongRoot = { [wrongKey.kid]: wrongKey.publicKey };
const sameKeyRoot = { [aliasSigner.kid]: receiptKey.publicKey };

rmSync(OUT, { recursive: true, force: true });
mkdirSync(OUT, { recursive: true });
write("chain.json", chain);
write("chain-prefix.json", chain.slice(0, 2));
write("chain-damaged.json", damaged);
write("receipt-keyring-static.json", receiptStatic);
write("receipt-keyring-retired.json", receiptRetired);
write("receipt-keyring-current.json", lifecycle(null));
write("receipt-keyring-window.json", receiptWindow);
write("receipt-keyring-at-activation.json", receiptAtActivation);
write("receipt-keyring-before-activation.json", receiptBeforeActivation);
write("receipt-keyring-lowercase-window.json", receiptLowercaseWindow);
write("receipt-keyring-invalid-interval.json", receiptInvalidInterval);
write("checkpoint-keyring.json", checkpointRoot);
write("checkpoint-keyring-wrong.json", wrongRoot);
write("checkpoint-keyring-same-material.json", sameKeyRoot);
write("checkpoints/exact-before-retirement.json", exact);
write("checkpoints/exact-nanos-before-retirement.json", exactNanos);
write("checkpoints/prefix-before-retirement.json", prefix);
write("checkpoints/ahead-before-retirement.json", ahead);
write("checkpoints/at-retirement.json", atRetirement);
write("checkpoints/after-retirement.json", afterRetirement);
write("checkpoints/lowercase-at-activation.json", lowercaseBoundary);
write("checkpoints/conflict.json", conflict);
write("checkpoints/forged-signature.json", forged);
write("checkpoints/same-key-alias.json", sameKey);

type Availability = HistoricalVerificationDimensions["evidence"]["availability"];
type Retirement = HistoricalVerificationDimensions["evidence"]["retirement"];

function dimensions(
  integrity: HistoricalVerificationDimensions["integrity"],
  completeness: HistoricalVerificationDimensions["completeness"],
  attribution: HistoricalVerificationDimensions["attribution"],
  retirement: Retirement,
  witness: "NOT_PROVIDED" | "PROVIDED",
  availability: Availability,
): HistoricalVerificationDimensions {
  return {
    integrity,
    completeness,
    attribution,
    organizationalIndependence: "UNVERIFIED",
    evidence: { retirement, witness, availability },
  };
}

function expected(
  classification: HistoricalVerificationResult["classification"],
  code: HistoricalVerificationResult["code"],
  d: HistoricalVerificationDimensions,
  count: number,
  attributedThroughSeq: number | null = null,
  asOf: string | null = null,
  chainId: string | null = CHAIN,
): HistoricalVerificationResult {
  return {
    spec: HISTORICAL_VERIFICATION_SPEC,
    policy: { verifierVersion: HISTORICAL_VERIFICATION_SPEC, purpose: "historical-audit" },
    classification,
    code,
    dimensions: d,
    chain: chainId,
    count,
    attributedThroughSeq,
    asOf,
  };
}

interface CorpusCase {
  readonly id: string;
  readonly receipts: string;
  readonly keyring: string;
  readonly checkpoint?: string;
  readonly checkpointKeyring?: string;
  readonly expected: HistoricalVerificationResult;
}

const cases: CorpusCase[] = [
  {
    id: "e-static-no-witness",
    receipts: "chain.json",
    keyring: "receipt-keyring-static.json",
    expected: expected("UNVERIFIED", "NO_WITNESS", dimensions("INTACT", "UNANSWERED", "UNATTRIBUTABLE", "NOT_PROVIDED", "NOT_PROVIDED", "NOT_PROVIDED"), 3),
  },
  {
    id: "e-plus-retirement-no-witness",
    receipts: "chain.json",
    keyring: "receipt-keyring-retired.json",
    expected: expected("UNVERIFIED", "NO_WITNESS", dimensions("INTACT", "UNANSWERED", "UNATTRIBUTABLE", "PROVIDED", "NOT_PROVIDED", "NOT_PROVIDED"), 3),
  },
  {
    id: "e-plus-witness-exact-head",
    receipts: "chain.json",
    keyring: "receipt-keyring-static.json",
    checkpoint: "checkpoints/exact-before-retirement.json",
    checkpointKeyring: "checkpoint-keyring.json",
    expected: expected("VERIFIED", "HEAD_ANCHORED", dimensions("INTACT", "HEAD_ANCHORED", "ATTRIBUTABLE_AS_OF", "NOT_PROVIDED", "PROVIDED", "AVAILABLE"), 3, 2, BEFORE_RETIREMENT),
  },
  {
    id: "e-plus-retirement-and-witness",
    receipts: "chain.json",
    keyring: "receipt-keyring-window.json",
    checkpoint: "checkpoints/exact-nanos-before-retirement.json",
    checkpointKeyring: "checkpoint-keyring.json",
    expected: expected("VERIFIED", "HEAD_ANCHORED", dimensions("INTACT", "HEAD_ANCHORED", "ATTRIBUTABLE_AS_OF", "PROVIDED", "PROVIDED", "AVAILABLE"), 3, 2, NANOS_BEFORE_RETIREMENT),
  },
  {
    id: "checkpoint-after-explicit-activation",
    receipts: "chain.json",
    keyring: "receipt-keyring-window.json",
    checkpoint: "checkpoints/exact-before-retirement.json",
    checkpointKeyring: "checkpoint-keyring.json",
    expected: expected("VERIFIED", "HEAD_ANCHORED", dimensions("INTACT", "HEAD_ANCHORED", "ATTRIBUTABLE_AS_OF", "PROVIDED", "PROVIDED", "AVAILABLE"), 3, 2, BEFORE_RETIREMENT),
  },
  {
    id: "checkpoint-at-explicit-activation",
    receipts: "chain.json",
    keyring: "receipt-keyring-at-activation.json",
    checkpoint: "checkpoints/exact-before-retirement.json",
    checkpointKeyring: "checkpoint-keyring.json",
    expected: expected("VERIFIED", "HEAD_ANCHORED", dimensions("INTACT", "HEAD_ANCHORED", "ATTRIBUTABLE_AS_OF", "PROVIDED", "PROVIDED", "AVAILABLE"), 3, 2, BEFORE_RETIREMENT),
  },
  {
    id: "checkpoint-one-nanosecond-before-activation",
    receipts: "chain.json",
    keyring: "receipt-keyring-before-activation.json",
    checkpoint: "checkpoints/exact-before-retirement.json",
    checkpointKeyring: "checkpoint-keyring.json",
    expected: expected("UNVERIFIED", "CHECKPOINT_BEFORE_ACTIVATION", dimensions("INTACT", "HEAD_ANCHORED", "UNATTRIBUTABLE", "PROVIDED", "PROVIDED", "AVAILABLE"), 3),
  },
  {
    id: "lowercase-rfc3339-activation-boundary",
    receipts: "chain.json",
    keyring: "receipt-keyring-lowercase-window.json",
    checkpoint: "checkpoints/lowercase-at-activation.json",
    checkpointKeyring: "checkpoint-keyring.json",
    expected: expected("VERIFIED", "HEAD_ANCHORED", dimensions("INTACT", "HEAD_ANCHORED", "ATTRIBUTABLE_AS_OF", "PROVIDED", "PROVIDED", "AVAILABLE"), 3, 2, LOWERCASE_ACTIVATION),
  },
  {
    id: "invalid-lifecycle-interval",
    receipts: "chain.json",
    keyring: "receipt-keyring-invalid-interval.json",
    checkpoint: "checkpoints/exact-before-retirement.json",
    checkpointKeyring: "checkpoint-keyring.json",
    expected: expected("INVALID", "RECEIPT_ROOT_INVALID", dimensions("UNANSWERED", "UNANSWERED", "UNATTRIBUTABLE", "NOT_PROVIDED", "PROVIDED", "AVAILABLE"), 0, null, null, null),
  },
  {
    id: "honest-stale-prefix",
    receipts: "chain.json",
    keyring: "receipt-keyring-retired.json",
    checkpoint: "checkpoints/prefix-before-retirement.json",
    checkpointKeyring: "checkpoint-keyring.json",
    expected: expected("PARTIAL", "PREFIX_ANCHORED", dimensions("INTACT", "PREFIX_ANCHORED", "ATTRIBUTABLE_AS_OF", "PROVIDED", "PROVIDED", "AVAILABLE"), 3, 0, BEFORE_RETIREMENT),
  },
  {
    id: "checkpoint-not-trust-root",
    receipts: "chain.json",
    keyring: "receipt-keyring-retired.json",
    checkpoint: "checkpoints/exact-before-retirement.json",
    expected: expected("UNVERIFIED", "WITNESS_ROOT_NOT_PROVIDED", dimensions("UNANSWERED", "UNANSWERED", "UNATTRIBUTABLE", "PROVIDED", "PROVIDED", "AVAILABLE"), 3),
  },
  {
    id: "authenticated-checkpoint-ahead",
    receipts: "chain-prefix.json",
    keyring: "receipt-keyring-retired.json",
    checkpoint: "checkpoints/ahead-before-retirement.json",
    checkpointKeyring: "checkpoint-keyring.json",
    expected: expected("CONFLICT", "CHECKPOINT_AHEAD", dimensions("INTACT", "CONFLICT", "UNATTRIBUTABLE", "PROVIDED", "PROVIDED", "MISSING_RELATIVE_TO_CHECKPOINT"), 2),
  },
  {
    id: "forged-witness",
    receipts: "chain.json",
    keyring: "receipt-keyring-retired.json",
    checkpoint: "checkpoints/forged-signature.json",
    checkpointKeyring: "checkpoint-keyring.json",
    expected: expected("INVALID", "WITNESS_INTEGRITY_FAILURE", dimensions("BROKEN", "UNANSWERED", "UNATTRIBUTABLE", "PROVIDED", "PROVIDED", "AVAILABLE"), 3),
  },
  {
    id: "wrong-witness-root",
    receipts: "chain.json",
    keyring: "receipt-keyring-retired.json",
    checkpoint: "checkpoints/exact-before-retirement.json",
    checkpointKeyring: "checkpoint-keyring-wrong.json",
    expected: expected("UNVERIFIED", "WITNESS_KEY_NOT_TRUSTED", dimensions("UNANSWERED", "UNANSWERED", "UNATTRIBUTABLE", "PROVIDED", "PROVIDED", "AVAILABLE"), 3),
  },
  {
    id: "same-key-witness-alias",
    receipts: "chain.json",
    keyring: "receipt-keyring-retired.json",
    checkpoint: "checkpoints/same-key-alias.json",
    checkpointKeyring: "checkpoint-keyring-same-material.json",
    expected: expected("UNVERIFIED", "WITNESS_KEY_NOT_SEPARATE", dimensions("INTACT", "UNANSWERED", "UNATTRIBUTABLE", "PROVIDED", "PROVIDED", "AVAILABLE"), 3),
  },
  {
    id: "checkpoint-at-retirement",
    receipts: "chain.json",
    keyring: "receipt-keyring-retired.json",
    checkpoint: "checkpoints/at-retirement.json",
    checkpointKeyring: "checkpoint-keyring.json",
    expected: expected("UNVERIFIED", "CHECKPOINT_AFTER_RETIREMENT", dimensions("INTACT", "HEAD_ANCHORED", "UNATTRIBUTABLE", "PROVIDED", "PROVIDED", "AVAILABLE"), 3),
  },
  {
    id: "checkpoint-after-retirement",
    receipts: "chain.json",
    keyring: "receipt-keyring-retired.json",
    checkpoint: "checkpoints/after-retirement.json",
    checkpointKeyring: "checkpoint-keyring.json",
    expected: expected("UNVERIFIED", "CHECKPOINT_AFTER_RETIREMENT", dimensions("INTACT", "HEAD_ANCHORED", "UNATTRIBUTABLE", "PROVIDED", "PROVIDED", "AVAILABLE"), 3),
  },
  {
    id: "authenticated-same-seq-contradiction",
    receipts: "chain.json",
    keyring: "receipt-keyring-retired.json",
    checkpoint: "checkpoints/conflict.json",
    checkpointKeyring: "checkpoint-keyring.json",
    expected: expected("CONFLICT", "CHECKPOINT_CONFLICT", dimensions("INTACT", "CONFLICT", "UNATTRIBUTABLE", "PROVIDED", "PROVIDED", "AVAILABLE"), 3),
  },
  {
    id: "damaged-receipt",
    receipts: "chain-damaged.json",
    keyring: "receipt-keyring-retired.json",
    checkpoint: "checkpoints/exact-before-retirement.json",
    checkpointKeyring: "checkpoint-keyring.json",
    expected: expected("INVALID", "RECEIPT_INTEGRITY_FAILURE", dimensions("BROKEN", "UNANSWERED", "UNATTRIBUTABLE", "PROVIDED", "PROVIDED", "AVAILABLE"), 3),
  },
];

write("cases.json", { spec: "noa.historical-verification-corpus/0.1", cases });
write("README.json", {
  status: "NORMATIVE CONFORMANCE FIXTURE",
  note: "Historical attribution uses an independently authenticated checkpoint inside each covered signer's explicit [validFrom, retiredAt) interval. The lower bound is inclusive, the upper bound is exclusive, and an absent validFrom in a legacy two-field lifecycle record stays unbounded rather than being fabricated. RFC 3339 T/Z are case-insensitive. Signer-authored receipt timestamps are never lifecycle evidence. PARTIAL + PREFIX_ANCHORED replaces the earlier informal DEGRADED label. PROVEN_SUPPRESSED is not emitted without presenter-possession/omission proof.",
});

const receiptRoots: Readonly<Record<string, unknown>> = {
  "receipt-keyring-static.json": receiptStatic,
  "receipt-keyring-retired.json": receiptRetired,
  "receipt-keyring-window.json": receiptWindow,
  "receipt-keyring-at-activation.json": receiptAtActivation,
  "receipt-keyring-before-activation.json": receiptBeforeActivation,
  "receipt-keyring-lowercase-window.json": receiptLowercaseWindow,
  "receipt-keyring-invalid-interval.json": receiptInvalidInterval,
};
const checkpoints: Readonly<Record<string, Checkpoint>> = {
  "checkpoints/exact-before-retirement.json": exact,
  "checkpoints/exact-nanos-before-retirement.json": exactNanos,
  "checkpoints/prefix-before-retirement.json": prefix,
  "checkpoints/ahead-before-retirement.json": ahead,
  "checkpoints/at-retirement.json": atRetirement,
  "checkpoints/after-retirement.json": afterRetirement,
  "checkpoints/lowercase-at-activation.json": lowercaseBoundary,
  "checkpoints/conflict.json": conflict,
  "checkpoints/forged-signature.json": forged,
  "checkpoints/same-key-alias.json": sameKey,
};
const checkpointRoots: Readonly<Record<string, unknown>> = {
  "checkpoint-keyring.json": checkpointRoot,
  "checkpoint-keyring-wrong.json": wrongRoot,
  "checkpoint-keyring-same-material.json": sameKeyRoot,
};

for (const c of cases) {
  const actual = verifyHistoricalChain(
    JSON.stringify(c.receipts === "chain-prefix.json" ? chain.slice(0, 2) : c.receipts === "chain-damaged.json" ? damaged : chain),
    {
      keyring: JSON.stringify(receiptRoots[c.keyring]),
      ...(c.checkpoint === undefined ? {} : {
        checkpoint: JSON.stringify(checkpoints[c.checkpoint]),
      }),
      ...(c.checkpointKeyring === undefined ? {} : {
        checkpointKeyring: JSON.stringify(checkpointRoots[c.checkpointKeyring]),
      }),
    },
  );
  assert.deepEqual(actual, c.expected, c.id);
}

process.stdout.write(`generated ${cases.length} survivable-retirement cases\n`);
