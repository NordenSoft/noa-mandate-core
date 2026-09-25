/**
 * `noa.gate-pin/1` — the human comparison string for a Gate key (docs/gate-pin-spec.md).
 *
 * A person pinning a Gate on a device compares two strings: the one the Gate host prints (the pinned
 * serve banner and `roster-check`, member `gatePin`) and the one the device computes from the Gate
 * identity it was offered. Equal strings mean the same tenant, Gate kid and Gate key. The string is a
 * DISPLAY, never an authority input: nothing verifies a signature against it and nothing accepts a
 * key because of it.
 *
 *   fingerprint = "NOAGP1-" ‖ five groups of 4 lowercase hex, joined by "-", of the first 20 hex
 *                 characters of SHA-256(JCS({"spec":"noa.gate-pin/1","tenant":T,"gateKid":K,"publicKey":P}))
 *
 * T follows the roster's tenant rule (1-256 of 0x21-0x7E), K the roster's id rule, and P is a canonical
 * base64 DER SPKI Ed25519 key that passes the strict key rule every verifier here applies. A raw
 * 32-byte key in unpadded base64url (43 characters) converts to that P first (`gatePinPublicKeyFromRaw`).
 *
 * DISCIPLINE. Own-property reads, captured builtins, no regular expression, the kernel's JCS and
 * SHA-256 (`virtualHash`), the existing rules (`isTenant`, `isRosterId`, `isStrictEd25519PublicKey`).
 * No new cryptography.
 */
import { intrinsics } from "noa-receipt";
import { isStrictEd25519PublicKey, virtualHash } from "noa-approval-artifacts";
import { isRosterId, isTenant } from "./roster.js";

const { hasOwn, isArray, strCharCodeAt, strSlice, bufferFrom, bufToString } = intrinsics;

export const GATE_PIN_SPEC = "noa.gate-pin/1" as const;
export const GATE_PIN_PREFIX = "NOAGP1-" as const;

/** The DER prefix of an Ed25519 SubjectPublicKeyInfo (RFC 8410): the 32 raw key bytes follow it. */
const ED25519_SPKI_PREFIX_HEX = "302a300506032b6570032100";

/** Refusals, in the order they are checked; the first failure wins. `GATE_PIN_RAW_KEY_INVALID` only for a raw-key input. */
export type GatePinRefusalCode =
  | "GATE_PIN_INPUT_INVALID"
  | "GATE_PIN_TENANT_INVALID"
  | "GATE_PIN_KID_INVALID"
  | "GATE_PIN_RAW_KEY_INVALID"
  | "GATE_PIN_KEY_INVALID";

/** Refusals of the raw-key conversion, in the order they are checked. */
export type GatePinRawKeyRefusalCode = "GATE_PIN_RAW_KEY_INVALID" | "GATE_PIN_KEY_INVALID";

export type GatePinResult =
  | {
      readonly ok: true;
      /** `NOAGP1-xxxx-xxxx-xxxx-xxxx-xxxx`. */
      readonly fingerprint: string;
      /** `sha256:` + 64 lowercase hex of the canonical bytes: the full digest the fingerprint truncates. */
      readonly digest: string;
    }
  | { readonly ok: false; readonly code: GatePinRefusalCode; readonly detail: string };

export type GatePinKeyResult =
  | { readonly ok: true; readonly publicKey: string }
  | { readonly ok: false; readonly code: GatePinRawKeyRefusalCode; readonly detail: string };

function member(input: object, key: string): unknown {
  return hasOwn(input, key) ? (input as Record<string, unknown>)[key] : undefined;
}

type Members = { ok: true; tenant: string; gateKid: string; key: unknown } | { ok: false; code: GatePinRefusalCode; detail: string };

/**
 * Steps 1-3 of the refusal order, shared by both entry points: the input is an object (not an array,
 * RFC 8259) whose members can be read, then the tenant, then the kid. `keyMember` names the member the
 * key step reads (`publicKey`, or `publicKeyRaw`). Each member is read once.
 */
function readMembers(input: unknown, keyMember: "publicKey" | "publicKeyRaw"): Members {
  if (typeof input !== "object" || input === null || isArray(input)) {
    return { ok: false, code: "GATE_PIN_INPUT_INVALID", detail: `the input must be a JSON object with tenant, gateKid and ${keyMember}` };
  }
  let tenant: unknown;
  let gateKid: unknown;
  let key: unknown;
  try {
    tenant = member(input, "tenant");
    gateKid = member(input, "gateKid");
    key = member(input, keyMember);
  } catch {
    return { ok: false, code: "GATE_PIN_INPUT_INVALID", detail: "a member of the input could not be read" };
  }
  if (!isTenant(tenant)) {
    return { ok: false, code: "GATE_PIN_TENANT_INVALID", detail: "tenant must be 1-256 printable ASCII characters (0x21-0x7E)" };
  }
  if (!isRosterId(gateKid)) {
    return { ok: false, code: "GATE_PIN_KID_INVALID", detail: "gateKid must be 1-64 of [a-z0-9-], first [a-z], last [a-z0-9]" };
  }
  return { ok: true, tenant, gateKid, key };
}

/** The last step and the digest: the key rule, then the fingerprint of the three validated facts. */
function fingerprintOf(tenant: string, gateKid: string, publicKey: unknown): GatePinResult {
  if (typeof publicKey !== "string" || !isStrictEd25519PublicKey(publicKey)) {
    return { ok: false, code: "GATE_PIN_KEY_INVALID", detail: "publicKey must be a canonical base64 DER SPKI Ed25519 key that passes strict key validation" };
  }
  const digest = virtualHash({ spec: GATE_PIN_SPEC, tenant, gateKid, publicKey });
  const hex = strSlice(digest, 7, 27);
  const fingerprint =
    GATE_PIN_PREFIX +
    strSlice(hex, 0, 4) + "-" + strSlice(hex, 4, 8) + "-" + strSlice(hex, 8, 12) + "-" + strSlice(hex, 12, 16) + "-" + strSlice(hex, 16, 20);
  return { ok: true, fingerprint, digest };
}

/**
 * The fingerprint of a Gate identity. Reads exactly the members `tenant`, `gateKid` and `publicKey`
 * (own properties, each read once; any other member is ignored). Checks, in order: the input is a JSON
 * object (not an array) whose three members can be read, then the tenant, then the kid, then the key.
 * Never throws.
 */
export function gatePinFingerprint(input: unknown): GatePinResult {
  const m = readMembers(input, "publicKey");
  return m.ok ? fingerprintOf(m.tenant, m.gateKid, m.key) : m;
}

/**
 * The fingerprint of a Gate identity whose key is the raw base64url key (`tenant`, `gateKid`,
 * `publicKeyRaw`). The same order, the key step being the raw conversion: input, tenant, kid, then
 * `GATE_PIN_RAW_KEY_INVALID`, then `GATE_PIN_KEY_INVALID`. Never throws.
 */
export function gatePinFingerprintFromRaw(input: unknown): GatePinResult {
  const m = readMembers(input, "publicKeyRaw");
  if (!m.ok) return m;
  const k = gatePinPublicKeyFromRaw(m.key);
  return k.ok ? fingerprintOf(m.tenant, m.gateKid, k.publicKey) : k;
}

/** Is `c` a character of the unpadded base64url alphabet (RFC 4648 §5)? */
function isBase64UrlChar(c: number): boolean {
  return (
    (c >= 0x41 && c <= 0x5a) || // A-Z
    (c >= 0x61 && c <= 0x7a) || // a-z
    (c >= 0x30 && c <= 0x39) || // 0-9
    c === 0x2d || // -
    c === 0x5f // _
  );
}

/**
 * A raw 32-byte Ed25519 key in unpadded base64url — exactly 43 characters of `[A-Za-z0-9_-]`, in its
 * one canonical spelling (the unused low bits of the last character are zero) — to the canonical
 * base64 DER SPKI form the fingerprint takes. The result must also pass the strict key rule. Never throws.
 */
export function gatePinPublicKeyFromRaw(raw: unknown): GatePinKeyResult {
  if (typeof raw !== "string" || raw.length !== 43) {
    return { ok: false, code: "GATE_PIN_RAW_KEY_INVALID", detail: "a raw key must be exactly 43 characters of unpadded base64url" };
  }
  for (let i = 0; i < 43; i++) {
    if (!isBase64UrlChar(strCharCodeAt(raw, i))) {
      return { ok: false, code: "GATE_PIN_RAW_KEY_INVALID", detail: "a raw key must be exactly 43 characters of unpadded base64url" };
    }
  }
  const bytes = bufferFrom(raw, "base64url");
  if (bytes.length !== 32 || bufToString(bytes, "base64url") !== raw) {
    return { ok: false, code: "GATE_PIN_RAW_KEY_INVALID", detail: "the raw key is not the canonical base64url spelling of 32 bytes" };
  }
  const spki = bufToString(bufferFrom(ED25519_SPKI_PREFIX_HEX + bufToString(bytes, "hex"), "hex"), "base64");
  if (!isStrictEd25519PublicKey(spki)) {
    return { ok: false, code: "GATE_PIN_KEY_INVALID", detail: "the key fails strict Ed25519 key validation" };
  }
  return { ok: true, publicKey: spki };
}
