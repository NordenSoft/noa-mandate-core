/**
 * NOA Gate — the pinned roster `noa.gate-roster/1`, validated from BYTES.
 *
 * WHAT THIS IS. Reference-gate configuration, not wire language: the one file on the gate host that
 * names the gate key, the execution signer, the approver devices, the audit recipient, the key-manifest
 * epoch the approver devices hold, and the quorum per risk class. It replaces the per-boot, self-minted
 * trust root of `createAlphaTrust` for a gate that must keep one identity across restarts and must not
 * take its approvers from environment variables. No interoperability or conformance claim is made for
 * this format (docs/gate-pinned-trust.md).
 *
 * WHAT THIS FILE DOES AND DOES NOT DO. It is PURE: bytes (and, for the clock stage, an instant) in, a
 * verdict out. No file system, no ambient clock, no environment. The descriptor discipline that decides
 * whether the bytes may be trusted at all lives in `pinned-file.ts`; the stage order that composes both
 * lives in `trust.ts` (`loadPinnedTrust`). Every refusal carries a stable code, and the FIRST failure
 * wins, in this order:
 *
 *   3  parse            ROSTER_PARSE · ROSTER_NOT_OBJECT
 *   4  pin              ROSTER_DIGEST_MISMATCH (only when an expected digest is supplied)
 *   5  shape            ROSTER_SPEC_UNSUPPORTED, then every member in JCS key order at every level
 *                       (approvers, audit, epoch, executionSigner, expiresAt, gate, quorum,
 *                       rosterVersion, tenant, validFrom), then ROSTER_UNRECOGNIZED_MEMBER at every
 *                       level — members before the closed world, the order `src/ledger-transfer.ts`
 *                       uses on the public core
 *   6  cross-member     ROSTER_DUPLICATE_KID · ROSTER_KEY_REUSE · ROSTER_NO_ACTIVE_APPROVER /
 *                       ROSTER_APPROVER_COUNT_UNSUPPORTED · ROSTER_TIME_INVALID · ROSTER_ROLE_INSUFFICIENT
 *   8  clock            (`checkRosterClock`) ROSTER_NOT_YET_VALID · ROSTER_EXPIRED ·
 *                       ROSTER_VALIDITY_TOO_LONG · ROSTER_APPROVER_NOT_YET_VALID · ROSTER_TIME_INVALID
 *
 * (Stages 0-2, 7 and 9-11 are environment, file and key-file checks and live in `trust.ts`.)
 *
 * DISCIPLINE. Reads are own-property probes on the strict parser's frozen, null-prototype output;
 * builtins come from the kernel's module-load capture (`intrinsics`); there is no regular expression.
 * Times are read with `rfc3339Nanos` under the key-manifest schema's grammar, never `Date.parse`. Key
 * acceptance is the verifier's own rule (`isStrictEd25519PublicKey`), so the roster accepts exactly the
 * Ed25519 keys a decision will later verify under. The digest is `virtualHash` over the parsed value —
 * `"sha256:" + hex(SHA-256(JCS(roster)))` — so whitespace, key order and escape spelling cannot move it.
 * No new cryptography.
 */

import { diffieHellman, generateKeyPairSync } from "node:crypto";
import { intrinsics } from "noa-receipt";
import {
  frozenTable,
  isStrictEd25519PublicKey,
  parseDocument,
  requiredApproverRole,
  rfc3339Nanos,
  virtualHash,
} from "noa-approval-artifacts";
import { loadSchemas } from "./schemas.js";

const {
  hasOwn,
  isArray,
  isSafeInteger,
  objectKeys,
  objectCreateNull,
  objectFreeze,
  arraySort,
  arrayIncludes,
  strCharCodeAt,
  bufferFrom,
  bufToString,
  bufEquals,
  createPublicKeyCaptured,
  keyExportSpkiDer,
  jsonStringify,
} = intrinsics;

export const GATE_ROSTER_SPEC = "noa.gate-roster/1" as const;

/** Longest roster validity window: bounds how stale a revocation can be. */
export const MAX_ROSTER_VALIDITY_MS = 90 * 24 * 60 * 60 * 1000;

export type RosterRefusalCode =
  | "ROSTER_PARSE"
  | "ROSTER_NOT_OBJECT"
  | "ROSTER_DIGEST_MISMATCH"
  | "ROSTER_SPEC_UNSUPPORTED"
  | "ROSTER_MEMBER_INVALID"
  | "ROSTER_KID_INVALID"
  | "ROSTER_KEY_INVALID"
  | "ROSTER_HPKE_KEY_INVALID"
  | "ROSTER_ROLE_INVALID"
  | "ROSTER_TIME_INVALID"
  | "ROSTER_EPOCH_INVALID"
  | "ROSTER_QUORUM_INVALID"
  | "QUORUM_UNSUPPORTED"
  | "ROSTER_VERSION_INVALID"
  | "ROSTER_TENANT_INVALID"
  | "ROSTER_UNRECOGNIZED_MEMBER"
  | "ROSTER_DUPLICATE_KID"
  | "ROSTER_KEY_REUSE"
  | "ROSTER_NO_ACTIVE_APPROVER"
  | "ROSTER_APPROVER_COUNT_UNSUPPORTED"
  | "ROSTER_ROLE_INSUFFICIENT";

export type RosterClockRefusalCode =
  | "ROSTER_NOT_YET_VALID"
  | "ROSTER_EXPIRED"
  | "ROSTER_VALIDITY_TOO_LONG"
  | "ROSTER_APPROVER_NOT_YET_VALID"
  | "ROSTER_TIME_INVALID";

export type RosterApproverRole = "approve-high" | "approve-critical";

export interface RosterApprover {
  readonly role: RosterApproverRole;
  /** base64(DER SPKI) Ed25519 — signs decisions and verdict receipts. */
  readonly publicKey: string;
  /** base64(DER SPKI) X25519 — receives the sealed display. */
  readonly hpkePublicKey: string;
  readonly validFrom: string;
  readonly revokedAt: string | null;
}

export interface GateRoster {
  readonly spec: typeof GATE_ROSTER_SPEC;
  readonly tenant: string;
  readonly rosterVersion: number;
  readonly validFrom: string;
  readonly expiresAt: string;
  readonly epoch: { readonly keyManifestVersion: number; readonly keyManifestHash: string };
  readonly gate: { readonly kid: string; readonly publicKey: string };
  readonly executionSigner: { readonly kid: string; readonly publicKey: string } | null;
  readonly approvers: Readonly<Record<string, RosterApprover>>;
  readonly audit: { readonly kid: string; readonly hpkePublicKey: string };
  readonly quorum: Readonly<Record<string, number>>;
}

export type RosterParseResult =
  | {
      readonly ok: true;
      readonly roster: GateRoster;
      /** `"sha256:" + hex(SHA-256(JCS(roster)))` over the parsed value. */
      readonly digest: string;
      /** The one approver whose `revokedAt` is null (exactly one is supported). */
      readonly activeApproverKid: string;
      /** `expiresAt` in whole milliseconds, rounded DOWN (the gate stops authorizing no later than declared). */
      readonly expiresAtMs: number;
    }
  | { readonly ok: false; readonly code: RosterRefusalCode; readonly reason: string };

export type RosterClockResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly code: RosterClockRefusalCode; readonly reason: string };

/** A frozen, null-prototype membership table. */
function table(entries: readonly string[], path: string): Readonly<Record<string, true>> {
  const t = objectCreateNull<Record<string, true>>();
  for (let i = 0; i < entries.length; i++) t[entries[i] as string] = true;
  return frozenTable(t, path);
}
function charTable(chars: string, path: string): Readonly<Record<string, true>> {
  const t = objectCreateNull<Record<string, true>>();
  for (let i = 0; i < chars.length; i++) t[chars[i] as string] = true;
  return frozenTable(t, path);
}

const ID_FIRST = charTable("abcdefghijklmnopqrstuvwxyz", "<gate-roster ID_FIRST>");
const ID_LAST = charTable("abcdefghijklmnopqrstuvwxyz0123456789", "<gate-roster ID_LAST>");
const ID_BODY = charTable("abcdefghijklmnopqrstuvwxyz0123456789-", "<gate-roster ID_BODY>");
const LOWER_HEX = charTable("0123456789abcdef", "<gate-roster LOWER_HEX>");

/** The five risk classes of the gate's lattice (`types.ts` RiskClass; `engine.ts` RISK_CLASSES). */
const RISK_CLASS_TABLE = table(["LOW", "MEDIUM", "HIGH", "CRITICAL", "IRREVERSIBLE"], "<gate-roster RISK_CLASS>");
const ROLE_TABLE = table(["approve-high", "approve-critical"], "<gate-roster ROLE>");

const TOP_MEMBERS = table(
  ["approvers", "audit", "epoch", "executionSigner", "expiresAt", "gate", "quorum", "rosterVersion", "spec", "tenant", "validFrom"],
  "<gate-roster TOP_MEMBERS>",
);
const APPROVER_MEMBERS = table(["hpkePublicKey", "publicKey", "revokedAt", "role", "validFrom"], "<gate-roster APPROVER_MEMBERS>");
const AUDIT_MEMBERS = table(["hpkePublicKey", "kid"], "<gate-roster AUDIT_MEMBERS>");
const EPOCH_MEMBERS = table(["keyManifestHash", "keyManifestVersion"], "<gate-roster EPOCH_MEMBERS>");
const SIGNER_MEMBERS = table(["kid", "publicKey"], "<gate-roster SIGNER_MEMBERS>");

const MAX_ID = 64;
const MAX_TENANT = 256;
const HASH_PREFIX = "sha256:";
const HASH_LENGTH = HASH_PREFIX.length + 64;
/** X25519 SubjectPublicKeyInfo DER is exactly 12 bytes of prefix plus the 32-byte key. */
const X25519_SPKI_DER_LENGTH = 44;

let keyManifestSchema: unknown;
/** The grammar the approver devices' key manifest reads its instants under; loaded once. */
function timeSchema(): unknown {
  if (keyManifestSchema === undefined) keyManifestSchema = loadSchemas()["noa.key-manifest/0.1"];
  return keyManifestSchema;
}

const q = (v: string): string => jsonStringify(v) ?? "\"\"";

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !isArray(v);
}
function own(o: Record<string, unknown>, k: string): unknown {
  return hasOwn(o, k) ? o[k] : undefined;
}
/** Own string keys in JCS order (UTF-16 code-unit order, which is `Array.prototype.sort`'s default). */
function sortedKeys(o: Record<string, unknown>): string[] {
  const keys = objectKeys(o);
  const copy: string[] = [];
  for (let i = 0; i < keys.length; i++) copy[copy.length] = keys[i] as string;
  return arraySort(copy);
}

/**
 * ⚠ THE `v[i]` READS BELOW ARE NOT PROTOTYPE DISPATCH: each validator establishes
 * `typeof v === "string"` first, so an index below `length` is answered by the String object's own
 * [[GetOwnProperty]] (the note `src/ledger-transfer.ts` carries for the same walks).
 */

/** 1..64 characters of [a-z0-9-], first [a-z], last [a-z0-9]. Case variants are refused, never folded. */
export function isRosterId(v: unknown): v is string {
  if (typeof v !== "string") return false;
  const n = v.length;
  if (n === 0 || n > MAX_ID) return false;
  if (!hasOwn(ID_FIRST, v[0] as string)) return false;
  if (!hasOwn(ID_LAST, v[n - 1] as string)) return false;
  for (let i = 1; i < n - 1; i++) {
    if (!hasOwn(ID_BODY, v[i] as string)) return false;
  }
  return true;
}

/** 1..256 printable ASCII characters (0x21-0x7E): no space, no control, no non-ASCII. */
export function isTenant(v: unknown): v is string {
  if (typeof v !== "string") return false;
  const n = v.length;
  if (n === 0 || n > MAX_TENANT) return false;
  for (let i = 0; i < n; i++) {
    const c = strCharCodeAt(v, i);
    if (c < 0x21 || c > 0x7e) return false;
  }
  return true;
}

function isPositiveSafeInteger(v: unknown): v is number {
  return typeof v === "number" && isSafeInteger(v) && v >= 1;
}

/** `sha256:` followed by exactly 64 lowercase hex characters. */
function isHash256(v: unknown): v is string {
  if (typeof v !== "string" || v.length !== HASH_LENGTH) return false;
  for (let i = 0; i < HASH_PREFIX.length; i++) {
    if (v[i] !== HASH_PREFIX[i]) return false;
  }
  for (let i = HASH_PREFIX.length; i < HASH_LENGTH; i++) {
    if (!hasOwn(LOWER_HEX, v[i] as string)) return false;
  }
  return true;
}

/** An instant under the key-manifest grammar, as nanoseconds; `null` for anything else. */
function instantNs(v: unknown): bigint | null {
  return rfc3339Nanos(v, timeSchema());
}

/**
 * An X25519 recipient key: canonical base64 of a DER SubjectPublicKeyInfo of type `x25519` that
 * re-encodes byte for byte, whose 32-byte u-coordinate is a CANONICAL field element: bit 255 clear and
 * u < p. The raw-hex spelling `decodeX25519PublicKey` also accepts is refused here.
 *
 * WHY THE FIELD-ELEMENT RULE. RFC 7748 decoding masks bit 255 and reduces u mod p, so `u` with bit 255
 * set, or `u + p`, is the SAME key under a DIFFERENT string: DER, base64 and the re-encoding check all
 * pass, and the key-reuse check below — which compares strings — saw two identities where there is one
 * (QA round 1 reproduced an audit key equal to the approver's). With one spelling per key, string
 * equality is key equality.
 *
 * A LOW-ORDER point is refused too, by one trial agreement against a fresh ephemeral key: the
 * derivation refuses exactly the points of small order (their shared secret is all zero). The display
 * sealer refuses such a recipient on its own, so this is liveness — a roster naming one would boot and
 * then fail every hold — and it moves that failure to load time, where an operator is looking.
 */
export function isRosterX25519Key(v: unknown): v is string {
  if (typeof v !== "string" || v.length === 0 || v.length > 1024) return false;
  try {
    const der = bufferFrom(v, "base64");
    if (bufToString(der, "base64") !== v) return false;
    if (der.length !== X25519_SPKI_DER_LENGTH) return false;
    const key = createPublicKeyCaptured({ key: der, format: "der", type: "spki" });
    if (key.asymmetricKeyType !== "x25519") return false;
    if (!bufEquals(keyExportSpkiDer(key), der)) return false;
    if (!isCanonicalFieldElement(der)) return false;
    diffieHellman({ privateKey: generateKeyPairSync("x25519").privateKey, publicKey: key });
    return true;
  } catch {
    return false;
  }
}

/** The 2^255 - 19 field prime. */
const FIELD_P = (1n << 255n) - 19n;

/** The SPKI's 32-byte little-endian u-coordinate has bit 255 clear and is below p. */
function isCanonicalFieldElement(der: Uint8Array): boolean {
  const last = der[X25519_SPKI_DER_LENGTH - 1] as number;
  if ((last & 0x80) !== 0) return false;
  let u = 0n;
  for (let i = X25519_SPKI_DER_LENGTH - 1; i >= X25519_SPKI_DER_LENGTH - 32; i--) u = (u << 8n) | BigInt(der[i] as number);
  return u < FIELD_P;
}

function refuse(code: RosterRefusalCode, detail: string): RosterParseResult {
  return { ok: false, code, reason: `${code}: ${detail}` };
}
function clockRefuse(code: RosterClockRefusalCode, detail: string): RosterClockResult {
  return { ok: false, code, reason: `${code}: ${detail}` };
}

type SignerCheck =
  | { ok: true; value: { readonly kid: string; readonly publicKey: string } }
  | { ok: false; res: RosterParseResult };

/** `{ kid, publicKey }` in JCS order: kid, then publicKey. */
function checkSigner(v: unknown, path: string): SignerCheck {
  if (!isPlainObject(v)) return { ok: false, res: refuse("ROSTER_MEMBER_INVALID", `${path} must be a JSON object { kid, publicKey }`) };
  const kid = own(v, "kid");
  if (!isRosterId(kid)) return { ok: false, res: refuse("ROSTER_KID_INVALID", `${path}.kid must be 1-64 characters of [a-z0-9-], first [a-z], last [a-z0-9]`) };
  const publicKey = own(v, "publicKey");
  if (!isStrictEd25519PublicKey(publicKey)) {
    return { ok: false, res: refuse("ROSTER_KEY_INVALID", `${path}.publicKey is not a canonical base64 DER SPKI Ed25519 key the decision verifier accepts`) };
  }
  return { ok: true, value: objectFreeze({ kid, publicKey: publicKey as string }) };
}

/** Closed world for one nested object: the first own key not in `allowed`, or null. */
function unrecognized(o: Record<string, unknown>, allowed: Readonly<Record<string, true>>): string | null {
  const keys = sortedKeys(o);
  for (let i = 0; i < keys.length; i++) {
    if (!hasOwn(allowed, keys[i] as string)) return keys[i] as string;
  }
  return null;
}

/**
 * Stages 3-6: parse, optional digest pin, shape (members, then closed world), cross-member rules.
 * `expectedDigest`, when supplied, is compared EXACTLY with the computed `"sha256:<hex>"` digest before
 * any semantic rule runs, so a pinned deployment never interprets a roster it did not pin.
 */
export function parseGateRoster(bytes: Uint8Array, opts: { expectedDigest?: string } = {}): RosterParseResult {
  // ── stage 3: parse ─────────────────────────────────────────────────────────────────────────────
  const parsed = parseDocument(bytes, "roster");
  if (!parsed.ok) return refuse("ROSTER_PARSE", parsed.reason);
  const doc = parsed.value;
  if (!isPlainObject(doc)) return refuse("ROSTER_NOT_OBJECT", "the roster must be a JSON object");
  const digest = virtualHash(doc);

  // ── stage 4: second-channel pin ────────────────────────────────────────────────────────────────
  if (opts.expectedDigest !== undefined && opts.expectedDigest !== digest) {
    return refuse("ROSTER_DIGEST_MISMATCH", `roster digest ${digest} is not the pinned ${q(opts.expectedDigest)}`);
  }

  // ── stage 5: shape ─────────────────────────────────────────────────────────────────────────────
  if (own(doc, "spec") !== GATE_ROSTER_SPEC) {
    return refuse("ROSTER_SPEC_UNSUPPORTED", `spec must be exactly ${q(GATE_ROSTER_SPEC)}; this gate reads no other roster version`);
  }

  // approvers
  const approversRaw = own(doc, "approvers");
  if (!isPlainObject(approversRaw)) return refuse("ROSTER_MEMBER_INVALID", "approvers must be a JSON object keyed by kid");
  const approverKids = sortedKeys(approversRaw);
  const approvers = objectCreateNull<Record<string, RosterApprover>>();
  for (let i = 0; i < approverKids.length; i++) {
    const kid = approverKids[i] as string;
    const path = `approvers[${q(kid)}]`;
    if (!isRosterId(kid)) return refuse("ROSTER_KID_INVALID", `${path}: an approver kid must be 1-64 characters of [a-z0-9-], first [a-z], last [a-z0-9]`);
    const a = approversRaw[kid];
    if (!isPlainObject(a)) return refuse("ROSTER_MEMBER_INVALID", `${path} must be a JSON object`);
    const hpkePublicKey = own(a, "hpkePublicKey");
    if (!isRosterX25519Key(hpkePublicKey)) return refuse("ROSTER_HPKE_KEY_INVALID", `${path}.hpkePublicKey is not a canonical base64 DER SPKI X25519 key`);
    const publicKey = own(a, "publicKey");
    if (!isStrictEd25519PublicKey(publicKey)) return refuse("ROSTER_KEY_INVALID", `${path}.publicKey is not a canonical base64 DER SPKI Ed25519 key the decision verifier accepts`);
    const revokedAt = own(a, "revokedAt");
    if (revokedAt !== null && instantNs(revokedAt) === null) return refuse("ROSTER_TIME_INVALID", `${path}.revokedAt must be null or an RFC 3339 instant`);
    const role = own(a, "role");
    if (typeof role !== "string" || !hasOwn(ROLE_TABLE, role)) return refuse("ROSTER_ROLE_INVALID", `${path}.role must be exactly "approve-high" or "approve-critical"`);
    const validFrom = own(a, "validFrom");
    if (instantNs(validFrom) === null) return refuse("ROSTER_TIME_INVALID", `${path}.validFrom must be an RFC 3339 instant`);
    approvers[kid] = objectFreeze(objectAssignNull({
      role: role as RosterApproverRole,
      publicKey: publicKey as string,
      hpkePublicKey,
      validFrom: validFrom as string,
      revokedAt: revokedAt as string | null,
    }));
  }

  // audit
  const auditRaw = own(doc, "audit");
  if (!isPlainObject(auditRaw)) return refuse("ROSTER_MEMBER_INVALID", "audit must be a JSON object { hpkePublicKey, kid }");
  const auditHpke = own(auditRaw, "hpkePublicKey");
  if (!isRosterX25519Key(auditHpke)) return refuse("ROSTER_HPKE_KEY_INVALID", "audit.hpkePublicKey is not a canonical base64 DER SPKI X25519 key");
  const auditKid = own(auditRaw, "kid");
  if (!isRosterId(auditKid)) return refuse("ROSTER_KID_INVALID", "audit.kid must be 1-64 characters of [a-z0-9-], first [a-z], last [a-z0-9]");

  // epoch
  const epochRaw = own(doc, "epoch");
  if (!isPlainObject(epochRaw)) return refuse("ROSTER_EPOCH_INVALID", "epoch must be a JSON object { keyManifestHash, keyManifestVersion }");
  const keyManifestHash = own(epochRaw, "keyManifestHash");
  if (!isHash256(keyManifestHash)) return refuse("ROSTER_EPOCH_INVALID", "epoch.keyManifestHash must be sha256: followed by 64 lowercase hex characters");
  const keyManifestVersion = own(epochRaw, "keyManifestVersion");
  if (!isPositiveSafeInteger(keyManifestVersion)) return refuse("ROSTER_EPOCH_INVALID", "epoch.keyManifestVersion must be a safe integer >= 1");

  // executionSigner — required, and null means "no external execution signer"
  if (!hasOwn(doc, "executionSigner")) {
    return refuse("ROSTER_MEMBER_INVALID", "executionSigner is required: null, or { kid, publicKey } of the out-of-process grant signer");
  }
  const execRaw = own(doc, "executionSigner");
  let executionSigner: { readonly kid: string; readonly publicKey: string } | null = null;
  if (execRaw !== null) {
    const exec = checkSigner(execRaw, "executionSigner");
    if (!exec.ok) return exec.res;
    executionSigner = exec.value;
  }

  // expiresAt
  const expiresAt = own(doc, "expiresAt");
  const expiresAtNs = instantNs(expiresAt);
  if (expiresAtNs === null) return refuse("ROSTER_TIME_INVALID", "expiresAt must be an RFC 3339 instant");

  // gate
  const gateCheck = checkSigner(own(doc, "gate"), "gate");
  if (!gateCheck.ok) return gateCheck.res;
  const gate = gateCheck.value;

  // quorum
  const quorumRaw = own(doc, "quorum");
  if (!isPlainObject(quorumRaw)) return refuse("ROSTER_QUORUM_INVALID", "quorum must be a JSON object keyed by risk class");
  const quorumKeys = sortedKeys(quorumRaw);
  if (quorumKeys.length === 0) return refuse("ROSTER_QUORUM_INVALID", "quorum must name at least one risk class");
  const quorum = objectCreateNull<Record<string, number>>();
  for (let i = 0; i < quorumKeys.length; i++) {
    const cls = quorumKeys[i] as string;
    if (!hasOwn(RISK_CLASS_TABLE, cls)) {
      return refuse("ROSTER_QUORUM_INVALID", `quorum[${q(cls)}]: not a risk class (LOW, MEDIUM, HIGH, CRITICAL, IRREVERSIBLE)`);
    }
    const n = quorumRaw[cls];
    if (!isPositiveSafeInteger(n)) return refuse("ROSTER_QUORUM_INVALID", `quorum[${q(cls)}] must be an integer >= 1`);
    // A /1 gate has exactly one decision path, so a quorum of 2 cannot be honoured — and must never be
    // silently read as 1, which would let one approval authorize what the roster says needs two.
    if (n !== 1) return refuse("QUORUM_UNSUPPORTED", `quorum[${q(cls)}] is ${n}; this gate implements a quorum of exactly 1`);
    quorum[cls] = n;
  }

  // rosterVersion
  const rosterVersion = own(doc, "rosterVersion");
  if (!isPositiveSafeInteger(rosterVersion)) return refuse("ROSTER_VERSION_INVALID", "rosterVersion must be a safe integer >= 1");

  // tenant
  const tenant = own(doc, "tenant");
  if (!isTenant(tenant)) return refuse("ROSTER_TENANT_INVALID", "tenant must be 1-256 printable ASCII characters (0x21-0x7E)");

  // validFrom
  const validFrom = own(doc, "validFrom");
  const validFromNs = instantNs(validFrom);
  if (validFromNs === null) return refuse("ROSTER_TIME_INVALID", "validFrom must be an RFC 3339 instant");

  // ── stage 5 (cont.): the closed world, at every level ───────────────────────────────────────────
  // A member this version does not define is REFUSED, never ignored — including `sig`: a /1 roster is
  // not signed, and a gate that skipped an unknown `sig` would let a reader believe it was.
  const extraTop = unrecognized(doc, TOP_MEMBERS);
  if (extraTop !== null) return refuse("ROSTER_UNRECOGNIZED_MEMBER", `${q(extraTop)} is not a noa.gate-roster/1 member`);
  for (let i = 0; i < approverKids.length; i++) {
    const kid = approverKids[i] as string;
    const extra = unrecognized(approversRaw[kid] as Record<string, unknown>, APPROVER_MEMBERS);
    if (extra !== null) return refuse("ROSTER_UNRECOGNIZED_MEMBER", `approvers[${q(kid)}].${extra} is not an approver member`);
  }
  const extraAudit = unrecognized(auditRaw, AUDIT_MEMBERS);
  if (extraAudit !== null) return refuse("ROSTER_UNRECOGNIZED_MEMBER", `audit.${extraAudit} is not an audit member`);
  const extraEpoch = unrecognized(epochRaw, EPOCH_MEMBERS);
  if (extraEpoch !== null) return refuse("ROSTER_UNRECOGNIZED_MEMBER", `epoch.${extraEpoch} is not an epoch member`);
  if (execRaw !== null) {
    const extraExec = unrecognized(execRaw as Record<string, unknown>, SIGNER_MEMBERS);
    if (extraExec !== null) return refuse("ROSTER_UNRECOGNIZED_MEMBER", `executionSigner.${extraExec} is not an executionSigner member`);
  }
  const extraGate = unrecognized(own(doc, "gate") as Record<string, unknown>, SIGNER_MEMBERS);
  if (extraGate !== null) return refuse("ROSTER_UNRECOGNIZED_MEMBER", `gate.${extraGate} is not a gate member`);

  // ── stage 6: cross-member rules ─────────────────────────────────────────────────────────────────
  // Duplicate kid: the keyring is a kid-keyed map, so a collision would silently OVERWRITE one entry
  // with another (an approver named like the gate would replace the gate's own entry).
  const kids: string[] = [gate.kid];
  if (executionSigner !== null) kids[kids.length] = executionSigner.kid;
  for (let i = 0; i < approverKids.length; i++) kids[kids.length] = approverKids[i] as string;
  kids[kids.length] = auditKid;
  for (let i = 0; i < kids.length; i++) {
    for (let j = i + 1; j < kids.length; j++) {
      if (kids[i] === kids[j]) return refuse("ROSTER_DUPLICATE_KID", `kid ${q(kids[i] as string)} is declared more than once`);
    }
  }
  // Key reuse: one Ed25519 key under two roles is one principal wearing two hats — an approver whose key
  // is the gate key lets the gate approve itself. Same for X25519 recipients: an audit key that is also
  // an approver key is not an independent recipient. Canonical encodings make string equality exact.
  const signing: string[] = [gate.publicKey];
  if (executionSigner !== null) signing[signing.length] = executionSigner.publicKey;
  for (let i = 0; i < approverKids.length; i++) signing[signing.length] = (approvers[approverKids[i] as string] as RosterApprover).publicKey;
  for (let i = 0; i < signing.length; i++) {
    for (let j = i + 1; j < signing.length; j++) {
      if (signing[i] === signing[j]) return refuse("ROSTER_KEY_REUSE", "one Ed25519 public key is declared under two roster identities");
    }
  }
  const recipients: string[] = [];
  for (let i = 0; i < approverKids.length; i++) recipients[recipients.length] = (approvers[approverKids[i] as string] as RosterApprover).hpkePublicKey;
  recipients[recipients.length] = auditHpke;
  for (let i = 0; i < recipients.length; i++) {
    for (let j = i + 1; j < recipients.length; j++) {
      if (recipients[i] === recipients[j]) return refuse("ROSTER_KEY_REUSE", "one X25519 public key is declared under two roster identities");
    }
  }
  // Exactly one active approver: the sealed display has one approver recipient today.
  let activeApproverKid: string | null = null;
  let active = 0;
  for (let i = 0; i < approverKids.length; i++) {
    const kid = approverKids[i] as string;
    if ((approvers[kid] as RosterApprover).revokedAt === null) {
      active++;
      activeApproverKid = kid;
    }
  }
  if (active === 0 || activeApproverKid === null) return refuse("ROSTER_NO_ACTIVE_APPROVER", "no approver has revokedAt null");
  if (active > 1) return refuse("ROSTER_APPROVER_COUNT_UNSUPPORTED", `${active} approvers are active; this gate supports exactly one`);
  if (validFromNs >= expiresAtNs) return refuse("ROSTER_TIME_INVALID", "validFrom must be earlier than expiresAt");
  const activeRole = (approvers[activeApproverKid] as RosterApprover).role;
  for (let i = 0; i < quorumKeys.length; i++) {
    const cls = quorumKeys[i] as string;
    if (!arrayIncludes(requiredApproverRole(cls), activeRole)) {
      return refuse("ROSTER_ROLE_INSUFFICIENT", `the active approver's role ${q(activeRole)} cannot approve ${cls}; the quorum names a class nobody here can clear`);
    }
  }

  const roster: GateRoster = objectFreeze(objectAssignNull({
    spec: GATE_ROSTER_SPEC,
    tenant,
    rosterVersion,
    validFrom: validFrom as string,
    expiresAt: expiresAt as string,
    epoch: objectFreeze(objectAssignNull({ keyManifestVersion, keyManifestHash })),
    gate,
    executionSigner,
    approvers: objectFreeze(approvers),
    audit: objectFreeze(objectAssignNull({ kid: auditKid, hpkePublicKey: auditHpke })),
    quorum: objectFreeze(quorum),
  }));
  return {
    ok: true,
    roster,
    digest,
    activeApproverKid,
    expiresAtMs: Number(expiresAtNs / 1_000_000n),
  };
}

/** A null-prototype copy of a plain literal, so no roster object inherits from `Object.prototype`. */
function objectAssignNull<T extends object>(src: T): T {
  const out = objectCreateNull<T>();
  const keys = objectKeys(src);
  for (let i = 0; i < keys.length; i++) {
    const k = keys[i] as string;
    (out as Record<string, unknown>)[k] = (src as Record<string, unknown>)[k];
  }
  return out;
}

/**
 * Stage 8: the roster against the gate's clock. `nowMs` is the gate's own instant (whole milliseconds).
 * A revocation dated in the future is refused rather than scheduled: the decision verifier refuses any
 * non-null `revokedAt` at once, so a "future" revocation would read as scheduled and act as immediate.
 */
export function checkRosterClock(roster: GateRoster, activeApproverKid: string, nowMs: number): RosterClockResult {
  const nowNs = BigInt(nowMs) * 1_000_000n;
  const validFromNs = instantNs(roster.validFrom);
  const expiresAtNs = instantNs(roster.expiresAt);
  if (validFromNs === null || expiresAtNs === null) return clockRefuse("ROSTER_TIME_INVALID", "roster validity instants are unreadable");
  if (nowNs < validFromNs) return clockRefuse("ROSTER_NOT_YET_VALID", `the roster is valid from ${roster.validFrom}`);
  if (nowNs >= expiresAtNs) return clockRefuse("ROSTER_EXPIRED", `the roster expired at ${roster.expiresAt}`);
  if (expiresAtNs - validFromNs > BigInt(MAX_ROSTER_VALIDITY_MS) * 1_000_000n) {
    return clockRefuse("ROSTER_VALIDITY_TOO_LONG", "validFrom to expiresAt exceeds 90 days; re-issue the roster with a shorter window");
  }
  const activeApprover = roster.approvers[activeApproverKid] as RosterApprover;
  const activeFromNs = instantNs(activeApprover.validFrom);
  if (activeFromNs === null || nowNs < activeFromNs) {
    return clockRefuse("ROSTER_APPROVER_NOT_YET_VALID", `the active approver ${q(activeApproverKid)} is valid from ${activeApprover.validFrom}`);
  }
  const kids = sortedKeys(roster.approvers as Record<string, unknown>);
  for (let i = 0; i < kids.length; i++) {
    const revokedAt = (roster.approvers[kids[i] as string] as RosterApprover).revokedAt;
    if (revokedAt === null) continue;
    const revokedNs = instantNs(revokedAt);
    if (revokedNs === null || revokedNs > nowNs) {
      return clockRefuse("ROSTER_TIME_INVALID", `approvers[${q(kids[i] as string)}].revokedAt is in the future; a revocation takes effect when the roster is loaded, not later`);
    }
  }
  return { ok: true };
}
