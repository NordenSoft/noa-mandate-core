/**
 * Deterministic `noa.historical-verification/0.1` conformance corpus.
 *
 * Every verifier consumes these exact JSON bytes. The private keys are public test fixtures and
 * MUST NOT be used outside conformance. Expected results are written explicitly below rather than
 * copied from the TypeScript result, so generation cannot silently redefine the oracle.
 */
import assert from "node:assert/strict";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildCheckpoint, buildReceipt, type BuildInput, type Signer } from "../src/builder.js";
import { checkpointHashInput } from "../src/canonicalize.js";
import { sha256Prefixed } from "../src/hash.js";
import { signEd25519 } from "../src/keys.js";
import { signingMessage, CHECKPOINT_SIG_DOMAIN } from "../src/signing.js";
import {
  HISTORICAL_VERIFICATION_SPEC,
  verifyChain,
  verifyHistoricalChain,
  type HistoricalVerificationDimensions,
  type HistoricalVerificationResult,
  type VerifyStatus,
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
// Current-use corpus only: a second receipt signer that stays current, so a chain can place its
// FIRST retired signature somewhere other than seq 0.
const currentReceiptKey = keyFromSeed("g2-receipt-current", "44".repeat(32));
const receiptSigner: Signer = { kid: receiptKey.kid, privateKey: receiptKey.privateKey };
const witnessSigner: Signer = { kid: witnessKey.kid, privateKey: witnessKey.privateKey };
const currentReceiptSigner: Signer = { kid: currentReceiptKey.kid, privateKey: currentReceiptKey.privateKey };

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

function lifecycle(retiredAt: string | null, validFrom?: string | null, key = receiptKey): SigningKeyLifecycle {
  const entry: { publicKey: string; validFrom?: string | null; retiredAt: string | null } = {
    publicKey: key.publicKey,
    retiredAt,
  };
  // Omission is intentional: most corpus cases pin compatibility with the original two-field
  // lifecycle record. An absent lower bound must never be replaced with a generated timestamp.
  if (validFrom !== undefined) entry.validFrom = validFrom;
  return {
    spec: "noa.signing-key-lifecycle/0.1",
    keys: { [key.kid]: entry },
  };
}

/** A multi-key lifecycle root; entries keep the original two-field form (no invented validFrom). */
function lifecycleOf(entries: ReadonlyArray<readonly [typeof receiptKey, string | null]>): SigningKeyLifecycle {
  const keys: Record<string, { publicKey: string; retiredAt: string | null }> = {};
  for (const [key, retiredAt] of entries) keys[key.kid] = { publicKey: key.publicKey, retiredAt };
  return { spec: "noa.signing-key-lifecycle/0.1", keys };
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

// Current-use fixtures. `mixed` opens with a current signer (another agent.id, so key continuity is
// not the check that fires) and continues with the retired one: its first retired signature is seq 1.
const mixed: Receipt[] = [];
let mixedPrevious: Receipt | null = null;
for (let seq = 0; seq < 3; seq++) {
  const base = input(seq);
  const receipt = buildReceipt(
    { ...base, id: `g2-mixed-receipt-${seq}`, agent: { ...base.agent, id: seq === 0 ? "g2-current-agent" : base.agent.id } },
    mixedPrevious,
    seq === 0 ? currentReceiptSigner : receiptSigner,
  );
  mixed.push(receipt);
  mixedPrevious = receipt;
}
// A receipt that NAMES the retired kid but carries another key's signature: intact hash, forged signature.
const forgedRetiredKid = [buildReceipt(input(0), null, { kid: receiptKey.kid, privateKey: wrongKey.privateKey })];

const receiptStatic = { [receiptKey.kid]: receiptKey.publicKey };
const receiptRetired = lifecycle(RETIRED_AT);
const receiptWindow = lifecycle(RETIRED_AT, ACTIVATION_BEFORE_CHECKPOINT);
const receiptAtActivation = lifecycle(RETIRED_AT, ACTIVATION_AT_CHECKPOINT);
const receiptBeforeActivation = lifecycle(RETIRED_AT, ACTIVATION_ONE_NANOSECOND_AFTER_CHECKPOINT);
const receiptLowercaseWindow = lifecycle(LOWERCASE_RETIREMENT, LOWERCASE_ACTIVATION);
const receiptInvalidInterval = lifecycle(RETIRED_AT, "2026-01-02T00:00:00.000000003Z");
const checkpointRoot = { [witnessKey.kid]: witnessKey.publicKey };
const checkpointLifecycle = lifecycle(null, undefined, witnessKey);
const checkpointNullActivation = lifecycle(null, null, witnessKey);
const checkpointWindow = lifecycle(null, ACTIVATION_BEFORE_CHECKPOINT, witnessKey);
const checkpointAtActivation = lifecycle(null, ACTIVATION_AT_CHECKPOINT, witnessKey);
const checkpointBeforeActivation = lifecycle(null, ACTIVATION_ONE_NANOSECOND_AFTER_CHECKPOINT, witnessKey);
const checkpointRetired = lifecycle(RETIRED_AT, ACTIVATION_BEFORE_CHECKPOINT, witnessKey);
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
write("checkpoint-keyring-lifecycle.json", checkpointLifecycle);
write("checkpoint-keyring-null-activation.json", checkpointNullActivation);
write("checkpoint-keyring-window.json", checkpointWindow);
write("checkpoint-keyring-at-activation.json", checkpointAtActivation);
write("checkpoint-keyring-before-activation.json", checkpointBeforeActivation);
write("checkpoint-keyring-retired.json", checkpointRetired);
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
write("checkpoints/not-an-object.json", []);
write("chain-mixed.json", mixed);
write("chain-forged-retired-kid.json", forgedRetiredKid);
write("current-keyring-mixed.json", lifecycleOf([[receiptKey, RETIRED_AT], [currentReceiptKey, null]]));
write("current-keyring-checkpoint-retired.json", lifecycleOf([[receiptKey, null], [witnessKey, RETIRED_AT]]));
write("current-keyring-both-retired.json", lifecycleOf([[receiptKey, RETIRED_AT], [witnessKey, RETIRED_AT]]));
write("identity-receipt-unauthorized.json", { "g2-historical-agent": [wrongKey.kid] });
write("identity-checkpoint-unauthorized.json", { "g2-historical-agent": [receiptKey.kid] });

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
    id: "witness-legacy-lifecycle-no-activation",
    receipts: "chain.json",
    keyring: "receipt-keyring-retired.json",
    checkpoint: "checkpoints/exact-before-retirement.json",
    checkpointKeyring: "checkpoint-keyring-lifecycle.json",
    expected: expected("VERIFIED", "HEAD_ANCHORED", dimensions("INTACT", "HEAD_ANCHORED", "ATTRIBUTABLE_AS_OF", "PROVIDED", "PROVIDED", "AVAILABLE"), 3, 2, BEFORE_RETIREMENT),
  },
  {
    id: "witness-null-activation",
    receipts: "chain.json",
    keyring: "receipt-keyring-retired.json",
    checkpoint: "checkpoints/exact-before-retirement.json",
    checkpointKeyring: "checkpoint-keyring-null-activation.json",
    expected: expected("VERIFIED", "HEAD_ANCHORED", dimensions("INTACT", "HEAD_ANCHORED", "ATTRIBUTABLE_AS_OF", "PROVIDED", "PROVIDED", "AVAILABLE"), 3, 2, BEFORE_RETIREMENT),
  },
  {
    id: "witness-after-explicit-activation",
    receipts: "chain.json",
    keyring: "receipt-keyring-retired.json",
    checkpoint: "checkpoints/exact-before-retirement.json",
    checkpointKeyring: "checkpoint-keyring-window.json",
    expected: expected("VERIFIED", "HEAD_ANCHORED", dimensions("INTACT", "HEAD_ANCHORED", "ATTRIBUTABLE_AS_OF", "PROVIDED", "PROVIDED", "AVAILABLE"), 3, 2, BEFORE_RETIREMENT),
  },
  {
    id: "witness-at-explicit-activation",
    receipts: "chain.json",
    keyring: "receipt-keyring-retired.json",
    checkpoint: "checkpoints/exact-before-retirement.json",
    checkpointKeyring: "checkpoint-keyring-at-activation.json",
    expected: expected("VERIFIED", "HEAD_ANCHORED", dimensions("INTACT", "HEAD_ANCHORED", "ATTRIBUTABLE_AS_OF", "PROVIDED", "PROVIDED", "AVAILABLE"), 3, 2, BEFORE_RETIREMENT),
  },
  {
    id: "witness-one-nanosecond-before-activation",
    receipts: "chain.json",
    keyring: "receipt-keyring-retired.json",
    checkpoint: "checkpoints/exact-before-retirement.json",
    checkpointKeyring: "checkpoint-keyring-before-activation.json",
    expected: expected("UNVERIFIED", "CHECKPOINT_BEFORE_ACTIVATION", dimensions("INTACT", "HEAD_ANCHORED", "UNATTRIBUTABLE", "PROVIDED", "PROVIDED", "AVAILABLE"), 3),
  },
  {
    id: "witness-retired",
    receipts: "chain.json",
    keyring: "receipt-keyring-retired.json",
    checkpoint: "checkpoints/exact-before-retirement.json",
    checkpointKeyring: "checkpoint-keyring-retired.json",
    expected: expected("UNVERIFIED", "WITNESS_KEY_RETIRED", dimensions("INTACT", "UNANSWERED", "UNATTRIBUTABLE", "PROVIDED", "PROVIDED", "AVAILABLE"), 3),
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

// ── CURRENT USE (default purpose) under the same lifecycle roots ──────────────────────────────────
// `verifyChain` refuses every retired key. An AUTHENTIC retired signature is KEY_RETIRED (exit 9),
// and only when nothing else is wrong: each case below pins one adjacent pair of that refusal order
// (KEY_RETIRED below signature/hash/linkage/checkpoint TAMPERED, below UNTRUSTED, below MALFORMED;
// the first retired signature is the one reported; a receipt finding outranks a checkpoint finding).
// `scripts/check-survivable-retirement-knockout.mjs` swaps each pair in a disposable copy of the
// built verifier and requires the named case to turn red, so the corpus — not prose — defines it.
interface CurrentUseExpected {
  readonly status: VerifyStatus;
  readonly exit: number;
  readonly badSeq: number | null;
  /** The one `key-retired:` warning, or null when the result must carry none. */
  readonly keyRetired: { readonly seq: number; readonly kid: string; readonly subject: "receipt" | "checkpoint" } | null;
  /** Whether the output names `--purpose historical`: only a KEY_RETIRED result may. */
  readonly historicalPointer: boolean;
}
interface CurrentUseCase {
  readonly id: string;
  readonly pins: string;
  readonly receipts: string;
  readonly keyring: string;
  readonly checkpoint?: string;
  readonly identity?: string;
  readonly expected: CurrentUseExpected;
}
function refused(status: Exclude<VerifyStatus, "VALID" | "UNVERIFIED" | "KEY_RETIRED">, badSeq: number | null): CurrentUseExpected {
  const exit = { TAMPERED: 2, MALFORMED: 3, UNTRUSTED: 5 }[status];
  return { status, exit, badSeq, keyRetired: null, historicalPointer: false };
}
function retiredKey(seq: number, kid: string, subject: "receipt" | "checkpoint"): CurrentUseExpected {
  return { status: "KEY_RETIRED", exit: 9, badSeq: seq, keyRetired: { seq, kid, subject }, historicalPointer: true };
}
const currentUseCases: CurrentUseCase[] = [
  {
    id: "current-retired-receipts",
    pins: "authentic retired receipt signatures and nothing else wrong -> KEY_RETIRED",
    receipts: "chain.json",
    keyring: "receipt-keyring-retired.json",
    expected: retiredKey(0, receiptKey.kid, "receipt"),
  },
  {
    id: "current-first-retired-signature-mid-chain",
    pins: "the FIRST retired signature is reported (seq 1, not the last one at seq 2)",
    receipts: "chain-mixed.json",
    keyring: "current-keyring-mixed.json",
    expected: retiredKey(1, receiptKey.kid, "receipt"),
  },
  {
    id: "current-retired-kid-forged-signature",
    pins: "KEY_RETIRED below signature authentication: a retired kid with another key's signature is TAMPERED",
    receipts: "chain-forged-retired-kid.json",
    keyring: "receipt-keyring-retired.json",
    expected: refused("TAMPERED", 0),
  },
  {
    id: "current-retired-then-altered",
    pins: "KEY_RETIRED below TAMPERED: an authentic retired seq 0 does not hide altered bytes at seq 1",
    receipts: "chain-damaged.json",
    keyring: "receipt-keyring-retired.json",
    expected: refused("TAMPERED", 1),
  },
  {
    id: "current-retired-receipt-unauthorized-identity",
    pins: "KEY_RETIRED below UNTRUSTED: the identity manifest does not authorize the retired receipt kid",
    receipts: "chain.json",
    keyring: "receipt-keyring-retired.json",
    identity: "identity-receipt-unauthorized.json",
    expected: refused("UNTRUSTED", 0),
  },
  {
    id: "current-retired-checkpoint-not-an-object",
    pins: "KEY_RETIRED below MALFORMED: retired receipts with a checkpoint document that is not an object",
    receipts: "chain.json",
    keyring: "receipt-keyring-retired.json",
    checkpoint: "checkpoints/not-an-object.json",
    expected: refused("MALFORMED", null),
  },
  {
    id: "current-retired-checkpoint",
    pins: "an authentic checkpoint by a retired key and nothing else wrong -> KEY_RETIRED (checkpoint)",
    receipts: "chain.json",
    keyring: "current-keyring-checkpoint-retired.json",
    checkpoint: "checkpoints/exact-before-retirement.json",
    expected: retiredKey(2, witnessKey.kid, "checkpoint"),
  },
  {
    id: "current-retired-checkpoint-forged",
    pins: "KEY_RETIRED below checkpoint authentication: a retired checkpoint kid over bytes it did not sign is TAMPERED",
    receipts: "chain.json",
    keyring: "current-keyring-checkpoint-retired.json",
    checkpoint: "checkpoints/forged-signature.json",
    expected: refused("TAMPERED", null),
  },
  {
    id: "current-retired-checkpoint-truncated-head",
    pins: "KEY_RETIRED below TAMPERED: an authentic retired checkpoint over a truncated head",
    receipts: "chain.json",
    keyring: "current-keyring-checkpoint-retired.json",
    checkpoint: "checkpoints/prefix-before-retirement.json",
    expected: refused("TAMPERED", 2),
  },
  {
    id: "current-retired-checkpoint-unauthorized-identity",
    pins: "KEY_RETIRED below UNTRUSTED: the retired checkpoint kid is not authorized for the chain opener",
    receipts: "chain.json",
    keyring: "current-keyring-checkpoint-retired.json",
    checkpoint: "checkpoints/exact-before-retirement.json",
    identity: "identity-checkpoint-unauthorized.json",
    expected: refused("UNTRUSTED", 2),
  },
  {
    id: "current-receipt-finding-outranks-checkpoint",
    pins: "a retired receipt finding (seq 0) is reported before a retired checkpoint finding (head seq 2)",
    receipts: "chain.json",
    keyring: "current-keyring-both-retired.json",
    checkpoint: "checkpoints/exact-before-retirement.json",
    expected: retiredKey(0, receiptKey.kid, "receipt"),
  },
];

write("cases.json", {
  spec: "noa.historical-verification-corpus/0.1",
  cases,
  currentUse: {
    spec: "noa.current-use-lifecycle-corpus/0.1",
    // Declared, never inferred: a NOT_IMPLEMENTED port reads a lifecycle document as a static kid
    // map on its current-use path. The checker still runs it on every case and requires a refusal
    // that is never KEY_RETIRED / exit 9, so a port that starts implementing this must flip its entry.
    ports: {
      typescript: "IMPLEMENTED",
      python: "NOT_IMPLEMENTED",
      go: "NOT_IMPLEMENTED",
      rust: "NOT_IMPLEMENTED",
      csharp: "NOT_IMPLEMENTED",
    },
    cases: currentUseCases,
  },
});
write("README.json", {
  status: "NORMATIVE CONFORMANCE FIXTURE",
  note: "Historical attribution uses an independently authenticated checkpoint inside each covered receipt signer's explicit [validFrom, retiredAt) interval and at or after the witness key's explicit validFrom. The lower bounds are inclusive, the receipt retirement bound is exclusive, and an absent/null validFrom stays unbounded rather than being fabricated. A retired witness key remains refused: its own checkpoint timestamp cannot establish pre-retirement existence. RFC 3339 T/Z are case-insensitive. Signer-authored receipt timestamps are never lifecycle evidence. PARTIAL + PREFIX_ANCHORED replaces the earlier informal DEGRADED label. PROVEN_SUPPRESSED is not emitted without presenter-possession/omission proof.",
  currentUseNote: "cases.json currentUse pins the default (current-use) purpose under the same lifecycle roots. An authentic retired-key signature is KEY_RETIRED (exit 9) only when every other check passes; each case pins one adjacent pair of that refusal order, and only a KEY_RETIRED result names --purpose historical. currentUse.ports declares which verifiers implement lifecycle roots on the current-use path; NOT_IMPLEMENTED ports are still run on every case and must refuse without ever reporting KEY_RETIRED.",
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
  "checkpoint-keyring-lifecycle.json": checkpointLifecycle,
  "checkpoint-keyring-null-activation.json": checkpointNullActivation,
  "checkpoint-keyring-window.json": checkpointWindow,
  "checkpoint-keyring-at-activation.json": checkpointAtActivation,
  "checkpoint-keyring-before-activation.json": checkpointBeforeActivation,
  "checkpoint-keyring-retired.json": checkpointRetired,
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

// Cross-check the explicit current-use oracle against the library (the CLI exit is the checker's job).
for (const c of currentUseCases) {
  const doc = (rel: string): string => readFileSync(join(OUT, rel), "utf8");
  const actual = verifyChain(doc(c.receipts), {
    keyring: doc(c.keyring),
    ...(c.checkpoint === undefined ? {} : { checkpoint: doc(c.checkpoint) }),
    ...(c.identity === undefined ? {} : { identityManifest: doc(c.identity) }),
  });
  assert.equal(actual.status, c.expected.status, c.id);
  assert.equal(actual.badSeq ?? null, c.expected.badSeq, c.id);
  const retiredWarnings = actual.warnings.filter((w) => w.startsWith("key-retired:"));
  const k = c.expected.keyRetired;
  assert.equal(retiredWarnings.length, k === null ? 0 : 1, c.id);
  if (k !== null) assert.ok(retiredWarnings[0]!.startsWith(`key-retired: seq ${k.seq} kid "${k.kid}" (${k.subject})`), c.id);
  const pointer = [actual.reason ?? "", ...actual.warnings].some((text) => text.includes("--purpose historical"));
  assert.equal(pointer, c.expected.historicalPointer, c.id);
}

process.stdout.write(`generated ${cases.length} survivable-retirement cases + ${currentUseCases.length} current-use cases\n`);
