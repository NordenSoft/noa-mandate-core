/**
 * NOA Gate — the in-process EFFECT OWNER for `noa.ledger.transfer` (docs/gate-effect-owner.md).
 *
 * ── WHAT THIS CLOSES ─────────────────────────────────────────────────────────────────────────────
 * For `noa.command.exec` the gate issues a grant and the agent's wrapper executes the command: the
 * gate never sees the effect. For an EFFECT-OWNED action (`projections.ts`, `EFFECT_OWNED`) the gate
 * commits the effect itself. The owner below is the component that writes the ledger row, and
 * writing that row consumes the authority in the same synchronous step. Before the row exists the
 * agent never holds a usable transfer authority: the grant is withheld from every view, and
 * `reserve`/`report` refuse it.
 *
 * ── THE THREAT MODEL ─────────────────────────────────────────────────────────────────────────────
 * The owner defends against a HOSTILE CALLER of `commit()`: any in-process holder of a reference to it,
 * with hostile input objects (getters, throwing members) and a hostile sealer. Only the owner's own
 * CODE, and an embedder-supplied owner's code, is trusted (NON-CLAIMS.md §S9).
 *
 * ── WHAT THE OWNER VERIFIES ITSELF ───────────────────────────────────────────────────────────────
 * `commit()` does not take the engine's word that a hold was approved. Against its own trust root it
 * checks the hold's boot (the stored identifier, and the signed freeze time against the boot's start),
 * then (O1) the hold envelope (signature, tenant, gate, hold id, epoch, mode, the deferred receipt it
 * binds, the projection identities), the deferred and approval receipts (signatures, linkage, an
 * ALLOWED verdict, the held action), the execution grant (signature and its four bindings), the
 * approver's decision (signature, tier, envelope and tenant binding, APPROVE), that the approval
 * receipt was signed by the deciding approver under the same key the decision keyring names, and that
 * the display the envelope binds was sealed to that approver. It re-derives the params hash from the
 * stored canonical text, signs, VERIFIES what it signed — bound to this commit's instant — and only
 * then writes. What it cannot check from the artifacts it holds is listed in NON-CLAIMS.md §S9.
 *
 * READ ONCE (ADR-0005). Every member of the caller's input is read exactly once, at entry, into a frozen
 * snapshot (strings must be strings); every artifact is encoded exactly once and the bytes go to the
 * verifier; every value a later step reads — including everything handed to the sealer and everything
 * recorded in the row — comes from that snapshot or from the strict parse of those bytes.
 *
 * ── ONE SYNCHRONOUS BLOCK, NO RE-ENTRY ───────────────────────────────────────────────────────────
 * `commit()` contains no `await`, but it calls out: to the caller's getters while it snapshots, to
 * encoders, and to the sealer. From its first line to its last, every other commit on this owner is
 * refused (EFFECT_COMMIT_REENTRANT), and the uniqueness keys are checked again just before the row is
 * written, so a callback cannot obtain a second row or a stale balance write. The attestation is
 * signed and verified BEFORE anything is written; nothing after the first write can throw. A signer
 * failure writes nothing and may be retried.
 *
 * WHAT THIS DOES NOT ESTABLISH (NON-CLAIMS.md §S9): the ledger lives in this process's memory, so the
 * effect and its record die together; a compromised gate process holds the keys and the ledger; the
 * owner is the witness of its own effect.
 */

import { parseDocument, refHash, receiptRefHash, verifyArtifact, virtualHash } from "noa-approval-artifacts";
import { intrinsics, projectLedgerTransfer, verifyChain, LEDGER_TRANSFER_CANONICAL } from "noa-receipt";
import { encodeDocument } from "./bytes.js";
import { getProjection } from "./projections.js";
import { loadSchemas } from "./schemas.js";
import { buildAttemptReceipt } from "./receipts.js";
import { buildConsumption } from "./grants.js";
import type { ExecutionSigner } from "./exec-signer.js";
import type { GateKeyPair, GateTrust } from "./trust.js";
import type { EncryptedDisplay, ExecutionConsumption, ExecutionGrant, HoldEnvelope, Receipt, RiskClass } from "./types.js";

const { hasOwn } = intrinsics;
// PRISTINE TIME: an expiry comparison is an authorization decision, so it does not dispatch through
// the globally mutable `Date.parse` at call time (the same capture `engine.ts` makes).
const gateDateParse = Date.parse;

/** The artifacts one commit consumes. All of them are gate-held store state, re-verified here. */
export interface EffectCommitInput {
  holdId: string;
  /** The `bootId` recorded on the hold. Store state: the owner compares it with its own boot. */
  holdBootId: string;
  /** The canonical params text the adapter hashed when the hold was frozen. */
  canonicalParams: string;
  holdEnvelope: HoldEnvelope;
  deferredReceipt: Receipt;
  /** The sealed display the envelope binds by `displayCiphertextHash`. */
  encryptedDisplay: EncryptedDisplay;
  decisionArtifact: Record<string, unknown>;
  /** The approver's ALLOWED verdict receipt, bound into the grant by `approvalReceiptHash`. */
  approvalReceipt: Receipt;
  grant: ExecutionGrant;
}

/** The owner's own verified parses of the authority, frozen: all a sealer is given to sign from. */
export interface VerifiedAuthority {
  readonly envelope: Readonly<Record<string, unknown>>;
  readonly deferred: Readonly<Record<string, unknown>>;
  readonly approval: Readonly<Record<string, unknown>>;
  readonly decision: Readonly<Record<string, unknown>>;
  readonly grant: Readonly<Record<string, unknown>>;
}

/** What the gate signs for an executed effect: the attempt receipt and the grant's consumption. */
export interface EffectAttestation {
  executedReceipt: Receipt;
  executionConsumption: ExecutionConsumption;
}

/** A refusal that writes no row: the authority is left unconsumed. */
export type EffectRefusalCode =
  | "HOLD_FROM_DEAD_BOOT"
  | "COMMIT_AUTHORITY_INVALID"
  | "EFFECT_COMMIT_REENTRANT"
  | "EFFECT_AUTHORITY_CONSUMED"
  | "GRANT_EXPIRED"
  | "PARAMS_SNAPSHOT_MISMATCH"
  | "LEDGER_NOT_OWNED"
  | "LEDGER_SAME_ACCOUNT"
  | "EFFECT_SIGNER_UNAVAILABLE"
  | "EFFECT_ATTESTATION_INVALID";

/** A refusal that writes a terminal, unsigned REFUSED row: the authority is consumed without an effect. */
export type LedgerRefusalCode = "LEDGER_ACCOUNT_UNKNOWN" | "LEDGER_INSUFFICIENT_FUNDS";

/** One ledger row. Frozen and null-prototype; `amount` is the validated digit string. */
export interface LedgerRow {
  readonly effectId: string;
  readonly sequence: number;
  readonly outcome: "EXECUTED" | "REFUSED";
  readonly refusalCode: LedgerRefusalCode | null;
  readonly ledger: string;
  readonly fromAccount: string;
  readonly toAccount: string;
  readonly amount: string;
  readonly unit: string;
  readonly paramsHash: string;
  readonly canonicalParams: string;
  readonly holdId: string;
  readonly holdEnvelopeHash: string;
  readonly decisionRefHash: string;
  readonly grantId: string;
  readonly committedAt: string;
  /** Present on EXECUTED rows only: the owner's verified parses of what the gate signed. */
  readonly attestation: EffectAttestation | null;
}

export type EffectOutcome =
  | { kind: "EXECUTED" | "REFUSED"; idempotent: boolean; row: LedgerRow }
  | { kind: "NOT_COMMITTED"; code: EffectRefusalCode; effectId: string | null; detail: string };

/** Signs the attestation of an effect at the owner's instant, from the owner's verified parses only. */
export type EffectSealer = (atMs: number, verified: VerifiedAuthority) => EffectAttestation;

/**
 * The owner contract. The engine accepts ANY object implementing it: an embedder-supplied owner is
 * trusted code, while its callers are not (NON-CLAIMS.md NC-S9.11).
 */
export interface EffectOwner {
  /** The effect-owned `action.canonical` this owner commits. */
  readonly canonical: string;
  /** The ledger identifier this owner commits to; a transfer naming any other ledger is refused. */
  readonly ledger: string;
  /** The `bootId` of the trust root this owner verifies against. The engine refuses any other. */
  readonly bootId: string;
  /** True once an engine has bound this owner. */
  readonly bound: boolean;
  /** Bind this owner to one engine; a second engine is refused (EFFECT_OWNER_ALREADY_BOUND). */
  bindEngine(engine: object): void;
  /** createHold-time admission: does this owner commit the ledger the transfer names? No account check. */
  admit(canonicalParams: string): { ok: true } | { ok: false; code: "LEDGER_NOT_OWNED"; detail: string };
  /** The row, if any, recorded for the hold envelope with this refHash. */
  find(holdEnvelopeHash: string): LedgerRow | undefined;
  /** Verify, then write exactly one row or nothing. `seal` signs the attestation, which is then verified. */
  commit(input: EffectCommitInput, seal: EffectSealer): EffectOutcome;
  /** Copies of the rows and balances, for tests and inspection. No route exposes it. */
  inspect(): { rows: readonly LedgerRow[]; balances: Readonly<Record<string, number>> };
}

/**
 * THE ONE PINNED-TRUST RULE, shared by the owner factory and the engine constructor. An effect owner
 * commits real effects on the strength of approver signatures, and an alpha trust root keeps the
 * approver's private half on this process's heap — so under alpha trust anyone in the process could
 * approve and commit. The owner therefore exists only over a pinned trust root, whose approver keys
 * come from an operator-provisioned roster and never from this process.
 */
export function assertEffectOwnerTrust(trust: GateTrust): void {
  if (trust.pinned === undefined) {
    throw new Error(
      "EFFECT_OWNER_REQUIRES_PINNED_TRUST: an effect owner commits on approver signatures, and this trust root is " +
        "not pinned (an alpha trust root holds the approver's private key in this process). Build the gate from a " +
        "pinned roster (docs/gate-pinned-trust.md).",
    );
  }
}

function ledgerInvalid(detail: string): Error {
  return new Error(`EFFECT_OWNER_LEDGER_INVALID: ${detail}`);
}

/** A 32-hex probe salt: the probe only asks whether identifiers pass the wire rules. */
const PROBE_SALT = "00000000000000000000000000000000";

/**
 * Do `ledger` and `account` pass the `noa.ledger.transfer/1` identifier rules? The kernel exports no
 * standalone identifier validator, so the question is asked through the one public derivation: a
 * probe transfer from `account` to a different valid identifier. One rule, one implementation.
 */
function identifiersAccepted(ledger: string, account: string): boolean {
  const partner = account === "a" ? "b" : "a";
  const r = projectLedgerTransfer(
    JSON.stringify({ amount: "1", fromAccount: account, ledger, salt: PROBE_SALT, toAccount: partner, unit: "XTS" }),
  );
  return r.ok && r.value.ledger === ledger && r.value.fromAccount === account;
}

/**
 * The validated 1..15-digit amount as an integer, by a digit walk over the string the kernel already
 * validated. Exact: 10^15 - 1 is below 2^53. Never `Number()` or `parseInt` of caller text.
 */
function amountOf(amount: string): number {
  let n = 0;
  for (let i = 0; i < amount.length; i++) {
    n = n * 10 + (amount.charCodeAt(i) - 48);
  }
  return n;
}

/** Encode once and strict-parse the same bytes: the verified bytes and the read snapshot are one value. */
function snapshotOf(value: unknown, label: string): { bytes: Uint8Array; doc: Record<string, unknown> } | null {
  let bytes: Uint8Array;
  try {
    bytes = encodeDocument(value);
  } catch {
    return null;
  }
  const parsed = parseDocument(bytes, label);
  if (!parsed.ok) return null;
  const v = parsed.value;
  if (typeof v !== "object" || v === null || Array.isArray(v)) return null;
  return { bytes, doc: v as Record<string, unknown> };
}

/**
 * THE ENTRY SNAPSHOT: every member of the caller's input read exactly once, into a frozen object whose
 * three string members are type-checked. A getter on the input therefore runs once, at entry, while
 * the owner is already marked busy; nothing later reads the input again.
 */
function snapshotInput(input: EffectCommitInput): EffectCommitInput | null {
  if (typeof input !== "object" || input === null) return null;
  const holdId: unknown = input.holdId;
  const holdBootId: unknown = input.holdBootId;
  const canonicalParams: unknown = input.canonicalParams;
  if (typeof holdId !== "string" || typeof holdBootId !== "string" || typeof canonicalParams !== "string") return null;
  return Object.freeze({
    holdId,
    holdBootId,
    canonicalParams,
    holdEnvelope: input.holdEnvelope,
    deferredReceipt: input.deferredReceipt,
    encryptedDisplay: input.encryptedDisplay,
    decisionArtifact: input.decisionArtifact,
    approvalReceipt: input.approvalReceipt,
    grant: input.grant,
  });
}

/** The five action members an approval must carry exactly as the held action does (decide's R8-16 rule). */
const ACTION_FIELDS = ["id", "canonical", "riskClass", "paramsHash", "reversible"] as const;

function recordAt(doc: Record<string, unknown> | null, key: string): Record<string, unknown> | null {
  const v = doc !== null && hasOwn(doc, key) ? doc[key] : undefined;
  return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}

function stringAt(doc: Record<string, unknown> | null, key: string): string | null {
  if (doc === null || !hasOwn(doc, key)) return null;
  const v = doc[key];
  return typeof v === "string" ? v : null;
}

function valueAt(doc: Record<string, unknown> | null, key: string): unknown {
  return doc !== null && hasOwn(doc, key) ? doc[key] : undefined;
}

/** Does a signed projection identity equal the registered one, member by member? */
function sameIdentity(signed: Record<string, unknown> | null, registered: { id: string; version: number; hash: string }): boolean {
  return (
    signed !== null &&
    stringAt(signed, "id") === registered.id &&
    valueAt(signed, "version") === registered.version &&
    stringAt(signed, "hash") === registered.hash
  );
}

/** Is `kid` one of the parties a sealed display names as a recipient? Own-property reads, index walk. */
function displayNames(display: Record<string, unknown>, kid: string | null): boolean {
  if (kid === null) return false;
  const rcpts = valueAt(display, "recipients");
  if (!Array.isArray(rcpts)) return false;
  for (let i = 0; i < rcpts.length; i++) {
    const r: unknown = rcpts[i];
    if (typeof r === "object" && r !== null && stringAt(r as Record<string, unknown>, "kid") === kid) return true;
  }
  return false;
}

/**
 * The attestation a sealer builds for the gate: an EXECUTED attempt receipt chained onto the verified
 * approval receipt, carrying the verified deferred action and scope, and the grant's consumption. It
 * reads ONLY the owner's verified parses, never live store objects.
 */
export function buildEffectAttestation(a: {
  verified: VerifiedAuthority;
  atMs: number;
  receiptId: string;
  gate: GateKeyPair;
  signer: ExecutionSigner;
}): EffectAttestation {
  const d = a.verified.deferred as Record<string, unknown>;
  const scope = recordAt(d, "scope");
  const agent = recordAt(d, "agent");
  const action = recordAt(d, "action");
  const ts = new Date(a.atMs).toISOString();
  const executedReceipt = buildAttemptReceipt({
    id: a.receiptId,
    ts,
    tenant: stringAt(scope, "tenant") ?? "",
    chain: stringAt(scope, "chain") ?? "",
    agentId: stringAt(agent, "id") ?? "",
    action: {
      id: stringAt(action, "id") ?? "",
      canonical: stringAt(action, "canonical") ?? "",
      riskClass: (stringAt(action, "riskClass") ?? "IRREVERSIBLE") as RiskClass,
      paramsHash: stringAt(action, "paramsHash") ?? "",
      reversible: valueAt(action, "reversible") === true,
    },
    outcome: "EXECUTED",
    prev: a.verified.approval as unknown as Receipt,
    gate: a.gate,
  });
  const executionConsumption = buildConsumption({
    grant: a.verified.grant as unknown as ExecutionGrant,
    consumedAt: ts,
    attemptReceipt: executedReceipt,
    result: "DISPATCHED",
    signer: a.signer,
  });
  return { executedReceipt, executionConsumption };
}

type AuthorityCheck =
  | { ok: true; verified: VerifiedAuthority; keys: { envelope: string; decision: string; grant: string } }
  | { ok: false; token: string };

/**
 * Build an in-memory reference ledger and its effect owner. Balances are whole `XTS` units.
 *
 * Construction refuses, and nothing is built, when the trust root is not pinned
 * (EFFECT_OWNER_REQUIRES_PINNED_TRUST), when the ledger or an account identifier fails the
 * `noa.ledger.transfer/1` identifier rules, when a balance is not a non-negative safe integer, or
 * when the balances sum past `Number.MAX_SAFE_INTEGER` (EFFECT_OWNER_LEDGER_INVALID). A transfer
 * conserves the total, so that bound rules out overflow for the owner's whole life.
 *
 * REFERENCE ONLY: the ledger resets with the process. It is not a system of record (NON-CLAIMS.md §S9).
 */
export function createInMemoryLedgerEffectOwner(o: {
  trust: GateTrust;
  now: () => number;
  ledger: string;
  accounts: Readonly<Record<string, number>>;
}): EffectOwner {
  assertEffectOwnerTrust(o.trust);
  const trust = o.trust;
  const now = o.now;
  const ledger = o.ledger;
  const canonical = LEDGER_TRANSFER_CANONICAL;
  const registered = getProjection(canonical);
  if (registered === undefined) {
    throw new Error(`EFFECT_OWNER_CANONICAL_INVALID: ${canonical} has no registered adapter`);
  }

  if (typeof ledger !== "string" || !identifiersAccepted(ledger, "a")) {
    throw ledgerInvalid(`the ledger identifier ${JSON.stringify(ledger)} fails the noa.ledger.transfer/1 identifier rules`);
  }
  const balances = Object.create(null) as Record<string, number>;
  const accountIds = Object.keys(o.accounts);
  let total = 0;
  for (let i = 0; i < accountIds.length; i++) {
    const id = accountIds[i] as string;
    const balance: unknown = o.accounts[id];
    if (!identifiersAccepted(ledger, id)) {
      throw ledgerInvalid(`the account identifier ${JSON.stringify(id)} fails the noa.ledger.transfer/1 identifier rules`);
    }
    if (typeof balance !== "number" || !Number.isSafeInteger(balance) || balance < 0) {
      throw ledgerInvalid(`the balance of ${JSON.stringify(id)} is not a non-negative safe integer`);
    }
    total += balance;
    if (total > Number.MAX_SAFE_INTEGER) {
      throw ledgerInvalid("the balances sum past Number.MAX_SAFE_INTEGER");
    }
    balances[id] = balance;
  }

  const schemas = loadSchemas();
  const rows: LedgerRow[] = [];
  const rowsById = new Map<string, LedgerRow>();
  // The three unique keys, each mapped to the effectId of the row that consumed it.
  const envelopeIndex = new Map<string, string>();
  const decisionIndex = new Map<string, string>();
  const grantIndex = new Map<string, string>();
  // True for the whole of a commit: every other commit on this owner is refused meanwhile.
  let busy = false;
  let boundEngine: object | null = null;
  // The EXECUTED receipt ids already recorded: a recorded attestation is never recorded again.
  const recordedReceiptIds = new Set<string>();
  // This boot's start, from the trust root: a hold whose gate-signed freeze time precedes it is not this boot's.
  const bootStartMs = gateDateParse(trust.uptimeResetAt);

  /** The ONE verification context, so the trust root's keyring is consumed at exactly one site. */
  function verificationContext(extra: Record<string, unknown>): Uint8Array {
    return encodeDocument({
      schemas,
      keyring: trust.keyring,
      ...extra,
    });
  }

  /** The ONE receipt-chain check: signatures under the trust root's receipt keyring, linkage, one tenant. */
  function chainValid(receipts: readonly unknown[]): boolean {
    return verifyChain(encodeDocument(receipts), { keyring: encodeDocument(trust.receiptKeyring), requireTenantConsistency: true }).status === "VALID";
  }

  /** O1 — every signed byte the commit rests on, verified here, in a fixed order. First failure wins. */
  function verifyAuthority(input: EffectCommitInput, nowIso: string): AuthorityCheck {
    // (1) the hold envelope: signed by this gate's hold-signer, for this tenant and gate, at this epoch.
    const env = snapshotOf(input.holdEnvelope, "hold envelope");
    if (env === null) return { ok: false, token: "envelope" };
    if (!verifyArtifact(env.bytes, verificationContext({ now: nowIso })).ok) return { ok: false, token: "envelope" };
    if (stringAt(env.doc, "tenant") !== trust.tenant || stringAt(env.doc, "gateKid") !== trust.gate.kid) {
      return { ok: false, token: "envelope-audience" };
    }
    if (stringAt(env.doc, "holdId") !== input.holdId) return { ok: false, token: "envelope-hold" };
    if (valueAt(env.doc, "keyManifestVersion") !== trust.keyManifestVersion || stringAt(env.doc, "keyManifestHash") !== trust.keyManifestHash) {
      return { ok: false, token: "envelope-epoch" };
    }

    // (2) the deferred receipt is the one the envelope binds, for this owner's canonical, and the
    //     envelope names the registered projection identities.
    const deferred = snapshotOf(input.deferredReceipt, "deferred receipt");
    if (deferred === null) return { ok: false, token: "deferred-binding" };
    const deferredAction = recordAt(deferred.doc, "action");
    if (
      receiptRefHash(deferred.doc) !== stringAt(env.doc, "deferredReceiptHash") ||
      stringAt(deferredAction, "canonical") !== canonical
    ) {
      return { ok: false, token: "deferred-binding" };
    }
    if (
      stringAt(env.doc, "mode") !== "ENFORCED" ||
      !sameIdentity(recordAt(env.doc, "actionSchema"), registered!.actionSchema) ||
      !sameIdentity(recordAt(env.doc, "displayProjection"), registered!.displayProjection)
    ) {
      return { ok: false, token: "projection-identity" };
    }

    // (3) the approval receipt: the deferred and approval receipts verify under the receipt keyring
    //     and link, and the verdict is ALLOWED.
    const approval = snapshotOf(input.approvalReceipt, "approval receipt");
    if (approval === null) return { ok: false, token: "receipt-chain" };
    if (!chainValid([deferred.doc, approval.doc])) return { ok: false, token: "receipt-chain" };
    if (stringAt(recordAt(approval.doc, "governance"), "verdict") !== "ALLOWED") return { ok: false, token: "approval-verdict" };
    const approvalAction = recordAt(approval.doc, "action");
    for (let i = 0; i < ACTION_FIELDS.length; i++) {
      const f = ACTION_FIELDS[i]!;
      if (valueAt(approvalAction, f) === undefined || valueAt(approvalAction, f) !== valueAt(deferredAction, f)) return { ok: false, token: "approval-action" };
    }

    // (4) the execution grant, signed by the execution-signer, bound to this hold, this envelope,
    //     this approval receipt and this action's params hash.
    const grant = snapshotOf(input.grant, "execution grant");
    if (grant === null) return { ok: false, token: "grant" };
    if (!verifyArtifact(grant.bytes, verificationContext({ now: nowIso })).ok) return { ok: false, token: "grant" };
    const envelopeHash = refHash(env.doc);
    const bindings: ReadonlyArray<readonly [string, string | null]> = [
      ["holdId", input.holdId],
      ["holdEnvelopeHash", envelopeHash],
      ["approvalReceiptHash", receiptRefHash(approval.doc)],
      ["paramsHash", stringAt(deferredAction, "paramsHash")],
    ];
    for (let i = 0; i < bindings.length; i++) {
      const [field, expected] = bindings[i]!;
      if (expected === null || stringAt(grant.doc, field) !== expected) {
        return { ok: false, token: `grant-binding:${field}` };
      }
    }

    // (5) the approver's decision: signed by a roster approver of the tier this action's risk class
    //     needs, bound to THIS envelope and tenant, evaluated at the decide-time instant the grant
    //     carries (`issuedAt`, the value the gate signed when it verified the same decision).
    const decision = snapshotOf(input.decisionArtifact, "decision artifact");
    if (decision === null) return { ok: false, token: "decision" };
    const decisionCheck = verifyArtifact(decision.bytes, verificationContext({
      now: nowIso,
      authorizationTime: stringAt(grant.doc, "issuedAt"),
      riskClass: stringAt(deferredAction, "riskClass"),
      refHashChecks: [
        { path: "holdEnvelopeHash", rule: "side", artifact: env.doc, refEquals: [{ path: "tenant", value: trust.tenant }] },
      ],
    }));
    if (!decisionCheck.ok) return { ok: false, token: "decision" };
    if (stringAt(decision.doc, "decision") !== "APPROVE") return { ok: false, token: "decision-not-approve" };

    // (6) the approval receipt is the deciding approver's own: signed by that kid, naming it, by a HUMAN.
    const approverKid = stringAt(decision.doc, "approverKid");
    const approvalBy = stringAt(recordAt(recordAt(approval.doc, "governance"), "approval"), "by");
    if (
      approverKid === null ||
      stringAt(recordAt(approval.doc, "sig"), "kid") !== approverKid ||
      approvalBy !== approverKid ||
      stringAt(recordAt(approval.doc, "agent"), "principal") !== "HUMAN"
    ) {
      return { ok: false, token: "approver-identity" };
    }
    // The decision keyring and the receipt keyring must name ONE key for that approver (decide's
    // TRUST_KEYRING_INCONSISTENT rule): an injected trust root must not verify each half under a different key.
    const decisionKey = stringAt(recordAt(trust.keyring as unknown as Record<string, unknown>, approverKid), "publicKey");
    const receiptKey = stringAt(recordAt(recordAt(trust.receiptKeyring as unknown as Record<string, unknown>, "keys"), approverKid), "publicKey");
    if (decisionKey === null || decisionKey !== receiptKey) return { ok: false, token: "keyring-consistency" };

    // (7) the display the envelope binds was sealed to that approver.
    const display = snapshotOf(input.encryptedDisplay, "encrypted display");
    if (display === null || virtualHash(display.doc) !== stringAt(env.doc, "displayCiphertextHash")) {
      return { ok: false, token: "display-binding" };
    }
    if (!displayNames(display.doc, approverKid)) return { ok: false, token: "display-recipient" };

    const verified: VerifiedAuthority = Object.freeze({
      envelope: env.doc,
      deferred: deferred.doc,
      approval: approval.doc,
      decision: decision.doc,
      grant: grant.doc,
    });
    return {
      ok: true,
      verified,
      keys: { envelope: envelopeHash, decision: refHash(decision.doc), grant: stringAt(grant.doc, "grantId") ?? "" },
    };
  }

  /**
   * O8 (after signing) — the attestation the sealer returned is what the gate is about to record as
   * its own signed evidence, so it is verified like any other input: the EXECUTED receipt is signed
   * by this gate, links onto the verified approval receipt and carries exactly the verified action and
   * scope; the consumption is signed by the execution signer and binds the verified grant and that
   * receipt. The row keeps the verified parses, never the returned objects.
   */
  function checkAttestation(raw: unknown, v: VerifiedAuthority, nowIso: string): { problem: string | null; attestation: EffectAttestation } {
    const rec = typeof raw === "object" && raw !== null ? (raw as Record<string, unknown>) : null;
    const ex = rec === null ? null : snapshotOf(valueAt(rec, "executedReceipt"), "executed receipt");
    const cons = rec === null ? null : snapshotOf(valueAt(rec, "executionConsumption"), "execution consumption");
    const attestation: EffectAttestation = Object.freeze({
      executedReceipt: (ex === null ? null : ex.doc) as unknown as Receipt,
      executionConsumption: (cons === null ? null : cons.doc) as unknown as ExecutionConsumption,
    });
    const fail = (problem: string) => ({ problem, attestation });
    if (ex === null) return fail("executed-receipt");
    if (cons === null) return fail("consumption");
    // Bound to THIS commit: signed at this commit's instant (the owner's clock, no skew allowed — the
    // sealer is handed that instant), with a receipt id never recorded before.
    if (stringAt(ex.doc, "ts") !== nowIso || stringAt(cons.doc, "consumedAt") !== nowIso) return fail("attestation-time");
    const exId = stringAt(ex.doc, "id");
    if (exId === null || recordedReceiptIds.has(exId) || exId === stringAt(v.deferred as Record<string, unknown>, "id") || exId === stringAt(v.approval as Record<string, unknown>, "id")) {
      return fail("executed-receipt-fresh");
    }
    if (!chainValid([v.deferred, v.approval, ex.doc])) return fail("executed-receipt-chain");
    if (stringAt(recordAt(ex.doc, "sig"), "kid") !== trust.gate.kid) return fail("executed-receipt-signer");
    if (stringAt(recordAt(ex.doc, "governance"), "verdict") !== "EXECUTED") return fail("executed-receipt-verdict");
    // Every other member is exactly what the gate's own sealer writes: a SERVICE agent with no model,
    // the approvals mode, no rule, no approval, not sandboxed, no rollback reference.
    const exAgent = recordAt(ex.doc, "agent");
    const exGov = recordAt(ex.doc, "governance");
    if (
      valueAt(exAgent, "model") !== null || stringAt(exAgent, "principal") !== "SERVICE" ||
      stringAt(exGov, "mode") !== "approvals_on" || valueAt(exGov, "ruleId") !== null ||
      valueAt(exGov, "approval") !== null || valueAt(exGov, "sandboxed") !== false ||
      valueAt(recordAt(ex.doc, "action"), "rollbackRef") !== null
    ) {
      return fail("executed-receipt-shape");
    }
    const exAction = recordAt(ex.doc, "action");
    const dAction = recordAt(v.deferred as Record<string, unknown>, "action");
    const fields = ["id", "canonical", "riskClass", "paramsHash", "reversible"] as const;
    for (let i = 0; i < fields.length; i++) {
      const f = fields[i]!;
      if (valueAt(exAction, f) === undefined || valueAt(exAction, f) !== valueAt(dAction, f)) return fail("executed-receipt-action");
    }
    const exScope = recordAt(ex.doc, "scope");
    const dScope = recordAt(v.deferred as Record<string, unknown>, "scope");
    if (
      stringAt(exScope, "tenant") !== stringAt(dScope, "tenant") ||
      stringAt(exScope, "chain") !== stringAt(dScope, "chain") ||
      stringAt(recordAt(ex.doc, "agent"), "id") !== stringAt(recordAt(v.deferred as Record<string, unknown>, "agent"), "id")
    ) {
      return fail("executed-receipt-scope");
    }
    if (!verifyArtifact(cons.bytes, verificationContext({ now: nowIso })).ok) return fail("consumption");
    if (
      stringAt(cons.doc, "grantHash") !== refHash(v.grant) ||
      stringAt(cons.doc, "attemptReceiptHash") !== receiptRefHash(ex.doc) ||
      stringAt(cons.doc, "result") !== "DISPATCHED"
    ) {
      return fail("consumption-binding");
    }
    return { problem: null, attestation };
  }

  function notCommitted(code: EffectRefusalCode, effectId: string | null, detail: string): EffectOutcome {
    return { kind: "NOT_COMMITTED", code, effectId, detail };
  }

  /** Write one row and its three index entries. Nothing here can throw. */
  function writeRow(row: LedgerRow): void {
    rows[rows.length] = row;
    rowsById.set(row.effectId, row);
    envelopeIndex.set(row.holdEnvelopeHash, row.effectId);
    decisionIndex.set(row.decisionRefHash, row.effectId);
    grantIndex.set(row.grantId, row.effectId);
  }

  /** One commit, with the owner marked busy for its whole duration. */
  function commitOnce(input: EffectCommitInput, seal: EffectSealer): EffectOutcome {
    const at = now();
    const atIso = new Date(at).toISOString();

    // ENTRY SNAPSHOT — the caller's input is read here, once, and never again.
    let snap: EffectCommitInput | null;
    try {
      snap = snapshotInput(input);
    } catch {
      snap = null;
    }
    if (snap === null) return notCommitted("COMMIT_AUTHORITY_INVALID", null, "input");

    // BOOT — a hold frozen by another boot of the gate is never committed by this one.
    if (snap.holdBootId !== trust.bootId) {
      return notCommitted("HOLD_FROM_DEAD_BOOT", null, "this hold was frozen by an earlier boot of the gate");
    }

    // O1 — the signed bytes.
    const authority = verifyAuthority(snap, atIso);
    if (!authority.ok) {
      return notCommitted("COMMIT_AUTHORITY_INVALID", null, authority.token);
    }
    const keys = authority.keys;
    const verified = authority.verified;

    // SIGNED BOOT — the gate-signed freeze time is not earlier than this boot's start, whatever boot
    // identifier the caller supplied.
    const frozenAtMs = gateDateParse(stringAt(verified.deferred as Record<string, unknown>, "ts") ?? "");
    if (!(frozenAtMs >= bootStartMs)) {
      return notCommitted("HOLD_FROM_DEAD_BOOT", null, "this hold was frozen before this boot of the gate began");
    }

    // O2 — uniqueness, before any time or funds check, so a replay always gets the recorded result.
    const byEnvelope = envelopeIndex.get(keys.envelope);
    const byDecision = decisionIndex.get(keys.decision);
    const byGrant = grantIndex.get(keys.grant);
    if (byEnvelope !== undefined && byEnvelope === byDecision && byEnvelope === byGrant) {
      const recorded = rowsById.get(byEnvelope);
      if (recorded !== undefined) return { kind: recorded.outcome, idempotent: true, row: recorded };
    }
    const consumedBy = byEnvelope ?? byDecision ?? byGrant;
    if (consumedBy !== undefined) {
      return notCommitted("EFFECT_AUTHORITY_CONSUMED", consumedBy, "this authority has already been consumed by another row");
    }

    // O3 — the grant's own expiry, clamped here to the envelope's: the issuance clamp is not trusted.
    const grantExpiry = gateDateParse(stringAt(verified.grant as Record<string, unknown>, "expiresAt") ?? "");
    const envelopeExpiry = gateDateParse(stringAt(verified.envelope as Record<string, unknown>, "expiresAt") ?? "");
    const expiresAtMs = Math.min(grantExpiry, envelopeExpiry);
    if (!(at < expiresAtMs)) {
      return notCommitted("GRANT_EXPIRED", null, "the grant or its hold has expired");
    }

    // O4 — re-derive the params hash from the snapshot's canonical text; later steps read only `r.value`.
    const r = projectLedgerTransfer(snap.canonicalParams);
    if (!r.ok || r.canonical !== snap.canonicalParams || r.paramsHash !== stringAt(verified.grant as Record<string, unknown>, "paramsHash")) {
      return notCommitted("PARAMS_SNAPSHOT_MISMATCH", null, "the stored params do not re-derive the params hash the grant binds");
    }
    const transfer = r.value;

    // O5 — this owner's ledger only. No row: the authority belongs to another ledger.
    if (transfer.ledger !== ledger) {
      return notCommitted("LEDGER_NOT_OWNED", null, "the transfer names a ledger this owner does not commit");
    }
    // Conservation does not rest on the kernel alone: a self-transfer would credit what it debits.
    if (transfer.fromAccount === transfer.toAccount) {
      return notCommitted("LEDGER_SAME_ACCOUNT", null, "a transfer must move between two accounts");
    }

    const committedAt = atIso;
    const base = {
      ledger: transfer.ledger,
      fromAccount: transfer.fromAccount,
      toAccount: transfer.toAccount,
      amount: transfer.amount,
      unit: transfer.unit,
      paramsHash: r.paramsHash,
      canonicalParams: snap.canonicalParams,
      holdId: stringAt(verified.envelope as Record<string, unknown>, "holdId") ?? snap.holdId,
      holdEnvelopeHash: keys.envelope,
      decisionRefHash: keys.decision,
      grantId: keys.grant,
      committedAt,
    };
    const refusedRow = (refusalCode: LedgerRefusalCode): EffectOutcome => {
      const row: LedgerRow = Object.freeze(Object.assign(Object.create(null) as LedgerRow, {
        effectId: trust.newId(),
        sequence: rows.length + 1,
        outcome: "REFUSED" as const,
        refusalCode,
        ...base,
        attestation: null,
      }));
      writeRow(row);
      return { kind: "REFUSED", idempotent: false, row };
    };

    // O6 — both accounts exist on this ledger.
    if (!hasOwn(balances, transfer.fromAccount) || !hasOwn(balances, transfer.toAccount)) {
      return refusedRow("LEDGER_ACCOUNT_UNKNOWN");
    }
    // O7 — funds, on the exact integer walked from the validated digit string.
    const amount = amountOf(transfer.amount);
    const fromBalance = balances[transfer.fromAccount] as number;
    const toBalance = balances[transfer.toAccount] as number;
    if (fromBalance < amount) {
      return refusedRow("LEDGER_INSUFFICIENT_FUNDS");
    }

    // O8 — sign FIRST, from the verified parses only, then verify what was signed. A signer failure
    // or a bad (or unreadable) attestation writes nothing.
    const effectId = trust.newId();
    let raw: unknown;
    try {
      raw = seal(at, verified);
    } catch {
      return notCommitted("EFFECT_SIGNER_UNAVAILABLE", null, "the execution signer did not sign the attestation; nothing was written");
    }
    let sealed: { problem: string | null; attestation: EffectAttestation };
    try {
      sealed = checkAttestation(raw, verified, atIso);
    } catch {
      return notCommitted("EFFECT_ATTESTATION_INVALID", null, "attestation-unreadable");
    }
    if (sealed.problem !== null) return notCommitted("EFFECT_ATTESTATION_INVALID", null, sealed.problem);
    // The uniqueness keys, once more, immediately before the write: nothing recorded them meanwhile.
    if (envelopeIndex.has(keys.envelope) || decisionIndex.has(keys.decision) || grantIndex.has(keys.grant)) {
      return notCommitted("EFFECT_AUTHORITY_CONSUMED", null, "this authority was consumed while this commit was signing");
    }
    const row: LedgerRow = Object.freeze(Object.assign(Object.create(null) as LedgerRow, {
      effectId,
      sequence: rows.length + 1,
      outcome: "EXECUTED" as const,
      refusalCode: null,
      ...base,
      attestation: sealed.attestation,
    }));

    // O9 — the effect and the consumption of its authority, in one step. Nothing below can throw.
    balances[transfer.fromAccount] = fromBalance - amount;
    balances[transfer.toAccount] = toBalance + amount;
    recordedReceiptIds.add(stringAt(sealed.attestation.executedReceipt as unknown as Record<string, unknown>, "id") ?? "");
    writeRow(row);
    return { kind: "EXECUTED", idempotent: false, row };
  }

  const owner: EffectOwner = {
    canonical,
    ledger,
    bootId: trust.bootId,

    get bound() {
      return boundEngine !== null;
    },

    bindEngine(engine: object) {
      if (boundEngine !== null && boundEngine !== engine) {
        throw new Error("EFFECT_OWNER_ALREADY_BOUND: this effect owner already serves another engine");
      }
      boundEngine = engine;
    },

    admit(canonicalParams: string) {
      const r = projectLedgerTransfer(canonicalParams);
      if (!r.ok || r.value.ledger !== ledger) {
        return { ok: false as const, code: "LEDGER_NOT_OWNED" as const, detail: "the transfer names a ledger this gate's effect owner does not commit" };
      }
      return { ok: true as const };
    },

    find(holdEnvelopeHash: string) {
      const effectId = envelopeIndex.get(holdEnvelopeHash);
      return effectId === undefined ? undefined : rowsById.get(effectId);
    },

    commit(input: EffectCommitInput, seal: EffectSealer): EffectOutcome {
      // NO RE-ENTRY, FROM THE FIRST LINE TO THE LAST: a getter on the input, an encoder callback or the
      // sealer that calls commit() again — for this authority or any other — is refused.
      if (busy) {
        return notCommitted("EFFECT_COMMIT_REENTRANT", null, "another commit on this owner is in progress; retry after it completes");
      }
      busy = true;
      try {
        return commitOnce(input, seal);
      } finally {
        busy = false;
      }
    },

    inspect() {
      const copy = Object.create(null) as Record<string, number>;
      const ids = Object.keys(balances);
      for (let i = 0; i < ids.length; i++) copy[ids[i] as string] = balances[ids[i] as string] as number;
      return { rows: Object.freeze(rows.slice()), balances: Object.freeze(copy) };
    },
  };
  return Object.freeze(owner);
}
