/**
 * `noa.encrypted-display/0.1` — the D15-v2 encrypted approval display (build spec §8/§9/§12).
 *
 * This is the REAL sealer/opener the gate injects (the gate itself never reimplements HPKE — the reuse-first rule;
 * it only BINDS the sealed object via the Hold Envelope's `displayCiphertextHash`, F2). It replaces
 * the earlier structural stub: the human-readable display is genuinely HPKE-AEAD encrypted to the
 * approver device key(s) and can only be read on a device holding the matching X25519 secret.
 *
 * SCHEMA IS FROZEN (build spec §8 — do NOT add fields):
 *   { spec, tenant, holdId, deferredReceiptHash, expiresAt,
 *     suite:{kem,kdf,aead},
 *     payload:{ nonce, ciphertext },              // ONE display blob under a random CEK
 *     recipients:[ { kid, enc, wrappedCek } ],    // CEK HPKE-wrapped per registered device
 *     aadHash }                                   // AAD binds tenant‖holdId‖deferredReceiptHash‖expiresAt
 *
 * Construction (multi-recipient hybrid / envelope encryption):
 *   1. AAD = JCS({tenant,holdId,deferredReceiptHash,expiresAt}); aadHash = "sha256:"+SHA256(AAD).
 *   2. CEK = 32 random bytes; payload = ChaCha20Poly1305(CEK, random 12-byte nonce, AAD).encrypt(JCS(display)).
 *   3. per recipient: HPKE-SealBase(recipientPubKey, info=spec, aad=AAD, pt=CEK) → { enc, wrappedCek }.
 * The AAD is bound into BOTH layers, so a swapped tenant/holdId/expiry breaks decryption; the WHOLE
 * object (incl. recipients[]) is covered by the gate-signed `displayCiphertextHash` (F2), so a
 * relay-added recipient breaks the envelope binding (a device added after the hold can't read it).
 *
 * Red Line 1/11: the recipient SECRET key is supplied by the caller (the device) at open time only;
 * the sealer sees public keys, never secrets, and the plaintext is returned to the caller, never
 * logged/persisted here.
 */

import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { canonicalize } from "./jcs.js";
import { sha256Prefixed } from "./hash.js";
import { hexToBytes, base64ToBytes, bytesToBase64 } from "./bytes.js";
import {
  capturedTextEncode,
  cryptoByteLength,
  ownDataValue,
  zeroCryptoBytes,
} from "./runtime-integrity.js";
import {
  assertHpkeRuntimeIntegrity,
  copyHpkeBytes,
  hpkeSealBase,
  hpkeOpenBase,
  hpkeRandomBytes,
  HPKE_SUITE,
} from "./hpke.js";

// ── #77-C: THE APPROVAL PATH IS CAPTURED AT MODULE LOAD ────────────────────────────────────────
// A post-load poison must not be able to change who receives a CEK, which bytes are authenticated,
// or what a human sees after decryption. A pre-load poison is a host/bootstrap concern.
const ReflectObject = Reflect;
const ArrayCtor = Array;
const NumberCtor = Number;
const JSONObject = JSON;
const reflectApply = ReflectObject.apply;
const Uint8ArrayCtor = Uint8Array;
const arrayIsArray = ArrayCtor.isArray;
const numberIsSafeInteger = NumberCtor.isSafeInteger;
const regexpExec = RegExp.prototype.exec;
const textDecoderDecode = TextDecoder.prototype.decode;
const jsonParse = JSONObject.parse;
const sharedDecoder = new TextDecoder();
const RAW_X25519_HEX = /^[0-9a-fA-F]{64}$/;

function ownString(target: unknown, key: PropertyKey, label: string): string {
  const value = ownDataValue(target, key, label, true);
  if (typeof value !== "string") throw new Error(`${label}: ${String(key)} must be a string`);
  return value;
}

function exactArrayLength(value: unknown, label: string): number {
  // Captured Array.isArray is the cross-realm brand check. Requiring this realm's Array.prototype
  // rejects legitimate browser/webview arrays without adding safety: every index and `length` is
  // still read as an own data property before the final pre-secret integrity fence.
  if (!(reflectApply(arrayIsArray, ArrayCtor, [value]) as boolean)) {
    throw new Error(`${label}: expected an Array`);
  }
  const length = ownDataValue(value, "length", label, true);
  if (!(reflectApply(numberIsSafeInteger, NumberCtor, [length]) as boolean) || (length as number) < 0) {
    throw new Error(`${label}: invalid array length`);
  }
  return length as number;
}

/** The HPKE `info` (key-schedule domain separation) for the encrypted display. */
const DISPLAY_HPKE_INFO = capturedTextEncode("noa.encrypted-display/0.1");
const CEK_LEN = 32; // ChaCha20Poly1305 content-encryption key
const PAYLOAD_NONCE_LEN = 12;

/** The frozen §8 wire shape. Structurally identical to the gate's `EncryptedDisplay` (which carries
 *  an index signature) so a sealed object is assignable to the gate's `DisplaySealer` return type. */
export interface EncryptedDisplay {
  spec: "noa.encrypted-display/0.1";
  tenant: string;
  holdId: string;
  deferredReceiptHash: string;
  expiresAt: string;
  suite: { kem: number; kdf: number; aead: number };
  payload: { nonce: string; ciphertext: string };
  recipients: Array<{ kid: string; enc: string; wrappedCek: string }>;
  aadHash: string;
}

export interface DisplayRecipient {
  kid: string;
  /** X25519 public key — raw lowercase hex (64 chars, the §3 wire shape) OR base64(DER SPKI). */
  hpkePublicKey: string;
}

export interface SealDisplayInput {
  tenant: string;
  holdId: string;
  deferredReceiptHash: string;
  expiresAt: string;
  /** The human-readable display object (RAW-supplied or ENFORCED-derived). Encrypted whole. */
  display: Record<string, unknown>;
  recipients: DisplayRecipient[];
  /** TEST ONLY — pin CEK/payload-nonce/ephemeral scalars for deterministic vectors. */
  deterministic?: {
    cek: Uint8Array;
    payloadNonce: Uint8Array;
    ephemeralSecretKey: Uint8Array;
  };
}

/**
 * Decode an X25519 public key from either the raw lowercase-hex wire shape (64 chars = 32 bytes, the
 * §3/D15-v2 canonical form generated by the phone) or base64(DER SPKI) (the shape node:crypto emits,
 * used by the gate's alpha trust). Fail-closed on anything else — a mis-shaped key is never guessed.
 */
export function decodeX25519PublicKey(s: string): Uint8Array {
  // Calling captured RegExp.prototype.test is insufficient: native `test` performs a live
  // `Get(rx, "exec")`. Invoke the captured native exec directly so a post-load `exec` replacement
  // cannot misroute a valid raw key into the base64/SPKI branch.
  if (reflectApply(regexpExec, RAW_X25519_HEX, [s]) !== null) {
    return hexToBytes(s);
  }
  let raw: Uint8Array;
  try {
    raw = base64ToBytes(s);
  } catch {
    throw new Error("decodeX25519PublicKey: not 32-byte hex nor base64");
  }
  // Never consult the writable %TypedArray%.prototype.length slot here. A recipients Proxy can
  // install a self-restoring getter after the entry fence; that getter previously rewrote the
  // decoded SPKI to an attacker key and restored itself before copyHpkeBytes/final integrity checks.
  const rawLength = cryptoByteLength(raw);
  if (rawLength === 32) return raw;
  // X25519 SubjectPublicKeyInfo DER = 12-byte prefix (302a300506032b656e032100) || 32-byte key.
  if (rawLength === 44) {
    const PREFIX = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00];
    for (let i = 0; i < PREFIX.length; i++) {
      if (raw[i] !== PREFIX[i]) throw new Error("decodeX25519PublicKey: bad X25519 SPKI DER prefix");
    }
    const key = new Uint8ArrayCtor(32);
    for (let i = 0; i < 32; i++) key[i] = raw[i + 12] as number;
    return key;
  }
  throw new Error(`decodeX25519PublicKey: unexpected key length ${rawLength} (want 32 raw or 44 SPKI-DER)`);
}

/** The AAD bytes + aadHash for a display (binds tenant‖holdId‖deferredReceiptHash‖expiresAt). */
// ── #77-C (2026-07-31): THE APPROVAL-RENDER PATH IS CAPTURED AT MODULE LOAD ────────────────────
// What the human SEES was decided AFTER the AEAD verified, by two writable slots. MEASURED with a
// real seal->open and a real x25519 device key:
//     CONTROL  "Wire EUR 2,400,000 to NEW payee GmbH"
//     ATTACK   "Refund EUR 1.00 to Alice"   via TextDecoder.prototype.decode
//     ATTACK   "Refund EUR 1.00 to Alice"   via the global JSON.parse
// Every cryptographic check passed in both cases. This is the product's core failure mode reached
// with prototype pollution alone — no key, no forged signature, no network position.
//
function displayAad(args: { tenant: string; holdId: string; deferredReceiptHash: string; expiresAt: string }): {
  aadBytes: Uint8Array;
  aadHash: string;
} {
  const canonical = canonicalize({
    tenant: args.tenant,
    holdId: args.holdId,
    deferredReceiptHash: args.deferredReceiptHash,
    expiresAt: args.expiresAt,
  });
  return { aadBytes: capturedTextEncode(canonical), aadHash: sha256Prefixed(canonical) };
}

/**
 * Seal a display into a `noa.encrypted-display/0.1` object (real HPKE-AEAD). Each recipient's entry
 * carries an independent HPKE encapsulation of the shared CEK, so N devices can each decrypt the
 * single payload blob without the gate ever holding a secret key.
 */
export function sealEncryptedDisplay(input: SealDisplayInput): EncryptedDisplay {
  // Normalize every caller-controlled descriptor before generating a CEK. Accessors are refused,
  // not invoked; a getter therefore cannot mutate the crypto realm after an entry-only check.
  assertHpkeRuntimeIntegrity();
  const tenant = ownString(input, "tenant", "sealEncryptedDisplay");
  const holdId = ownString(input, "holdId", "sealEncryptedDisplay");
  const deferredReceiptHash = ownString(input, "deferredReceiptHash", "sealEncryptedDisplay");
  const expiresAt = ownString(input, "expiresAt", "sealEncryptedDisplay");
  const display = ownDataValue(input, "display", "sealEncryptedDisplay", true);
  if (!isRecord(display)) throw new Error("sealEncryptedDisplay: display must be an object");
  const recipientsInput = ownDataValue(input, "recipients", "sealEncryptedDisplay", true);
  const recipientCount = exactArrayLength(recipientsInput, "sealEncryptedDisplay.recipients");
  if (recipientCount === 0) {
    throw new Error("sealEncryptedDisplay: at least one recipient is required (fail-closed; never ship plaintext)");
  }
  const normalizedRecipients: Array<{ kid: string; publicKey: Uint8Array }> = [];
  for (let i = 0; i < recipientCount; i++) {
    // Template substitution uses the language's internal number-to-string operation. A live
    // `String(i)` lookup lets a recipients Proxy replace globalThis.String, redirect this index,
    // self-restore, and leave the final integrity fence looking clean.
    const recipient = ownDataValue(recipientsInput, `${i}`, "sealEncryptedDisplay.recipients", true);
    const kid = ownString(recipient, "kid", `sealEncryptedDisplay.recipients[${i}]`);
    const publicKeyText = ownString(recipient, "hpkePublicKey", `sealEncryptedDisplay.recipients[${i}]`);
    normalizedRecipients[i] = {
      kid,
      publicKey: copyHpkeBytes(decodeX25519PublicKey(publicKeyText), `sealEncryptedDisplay.recipients[${i}].hpkePublicKey`),
    };
  }

  const deterministicInput = ownDataValue(input, "deterministic", "sealEncryptedDisplay", false);
  // ── THE CLEANUP SCOPE OPENS BEFORE THE FIRST SECRET EXISTS ────────────────────────────────────
  // It used to open after canonicalization, the integrity fence and the CEK/nonce draw. Each of
  // those can throw — `canonicalize` refuses shapes it cannot represent, the fence refuses a
  // poisoned intrinsic, and the RNG can refuse — and by then this invocation already held the
  // injected deterministic secrets and the canonical display bytes, so those paths cleared nothing.
  // Each secret gets its OWN variable rather than being built inside one object literal: if the
  // second `copyHpkeBytes` throws, the first copy is still reachable from the `finally` instead of
  // being stranded in a half-constructed object.
  let deterministicCek: Uint8Array | undefined;
  let deterministicNonce: Uint8Array | undefined;
  let deterministicScalar: Uint8Array | undefined;
  let deterministic: { cek: Uint8Array; payloadNonce: Uint8Array; ephemeralSecretKey: Uint8Array } | undefined;
  let displayBytes: Uint8Array | undefined;
  let cek: Uint8Array | undefined;
  let nonce: Uint8Array | undefined;
  try {
    if (deterministicInput !== undefined) {
      deterministicCek = copyHpkeBytes(
        ownDataValue(deterministicInput, "cek", "sealEncryptedDisplay.deterministic", true),
        "sealEncryptedDisplay.deterministic.cek",
      );
      deterministicNonce = copyHpkeBytes(
        ownDataValue(deterministicInput, "payloadNonce", "sealEncryptedDisplay.deterministic", true),
        "sealEncryptedDisplay.deterministic.payloadNonce",
      );
      deterministicScalar = copyHpkeBytes(
        ownDataValue(deterministicInput, "ephemeralSecretKey", "sealEncryptedDisplay.deterministic", true),
        "sealEncryptedDisplay.deterministic.ephemeralSecretKey",
      );
      deterministic = {
        cek: deterministicCek,
        payloadNonce: deterministicNonce,
        ephemeralSecretKey: deterministicScalar,
      };
    }

    // Canonicalization inspects caller-owned display data and can throw, and the canonical bytes it
    // produces ARE approval content — so it runs inside the cleanup scope rather than ahead of it.
    // An earlier revision of this comment said it finished "before any secret exists"; that stopped
    // being true when the deterministic snapshots moved above it, and it was never true of
    // `displayBytes` itself.
    const { aadBytes, aadHash } = displayAad({ tenant, holdId, deferredReceiptHash, expiresAt });
    displayBytes = capturedTextEncode(canonicalize(display));
    // Final TOCTOU fence: after this point the function uses normalized strings/bytes only.
    assertHpkeRuntimeIntegrity();
    cek = deterministic ? deterministic.cek : hpkeRandomBytes(CEK_LEN);
    nonce = deterministic ? deterministic.payloadNonce : hpkeRandomBytes(PAYLOAD_NONCE_LEN);
    if (cek.length !== CEK_LEN) throw new Error(`sealEncryptedDisplay: CEK must be ${CEK_LEN} bytes`);
    if (nonce.length !== PAYLOAD_NONCE_LEN) throw new Error(`sealEncryptedDisplay: payload nonce must be ${PAYLOAD_NONCE_LEN} bytes`);

    // Encrypt the WHOLE display (always) under the CEK, AAD-bound.
    const ciphertext = chacha20poly1305(cek, nonce, aadBytes).encrypt(displayBytes);

    // Wrap the CEK to each normalized device via HPKE.
    const recipients: Array<{ kid: string; enc: string; wrappedCek: string }> = [];
    for (let i = 0; i < recipientCount; i++) {
      const recipient = normalizedRecipients[i] as { kid: string; publicKey: Uint8Array };
      const sealed = hpkeSealBase({
        recipientPublicKey: recipient.publicKey,
        info: DISPLAY_HPKE_INFO,
        aad: aadBytes,
        plaintext: cek,
        ...(deterministic ? { ephemeralSecretKey: deterministic.ephemeralSecretKey } : {}),
      });
      recipients[i] = {
        kid: recipient.kid,
        enc: bytesToBase64(sealed.enc),
        wrappedCek: bytesToBase64(sealed.ciphertext),
      };
    }

    return {
      spec: "noa.encrypted-display/0.1",
      tenant,
      holdId,
      deferredReceiptHash,
      expiresAt,
      suite: { kem: HPKE_SUITE.kem, kdf: HPKE_SUITE.kdf, aead: HPKE_SUITE.aead },
      payload: { nonce: bytesToBase64(nonce), ciphertext: bytesToBase64(ciphertext) },
      recipients,
      aadHash,
    };
  } finally {
    // The payload nonce is deliberately NOT cleared: it is published verbatim in the envelope, so
    // calling it a secret here would be a claim this code does not get to make.
    if (cek !== undefined) zeroCryptoBytes(cek);
    if (displayBytes !== undefined) zeroCryptoBytes(displayBytes);
    if (deterministicCek !== undefined) zeroCryptoBytes(deterministicCek);
    if (deterministicScalar !== undefined) zeroCryptoBytes(deterministicScalar);
  }
}

export interface OpenRecipient {
  kid: string;
  /** Raw 32-byte X25519 secret key — the device key. Stays on device (Red Line 1). */
  secretKey: Uint8Array;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !(reflectApply(arrayIsArray, ArrayCtor, [v]) as boolean);
}

/**
 * Open a `noa.encrypted-display/0.1` object with the device's X25519 secret key → the plaintext
 * display. Fail-closed at every step: wrong spec/suite, aadHash mismatch (tampered tenant/hold
 * binding), no recipient entry for this device, or any AEAD tag failure (wrong key / tampered
 * ciphertext) throws — there is no partial-plaintext path.
 */
export function openEncryptedDisplay(ed: unknown, recipient: OpenRecipient): Record<string, unknown> {
  // Normalize every accessor-controlled envelope field before copying or using the device secret.
  // Accessors are refused and a final integrity fence follows all remaining caller interaction.
  assertHpkeRuntimeIntegrity();
  if (!isRecord(ed)) throw new Error("openEncryptedDisplay: encrypted-display is not an object");
  if (ownDataValue(ed, "spec", "openEncryptedDisplay", true) !== "noa.encrypted-display/0.1") {
    throw new Error("openEncryptedDisplay: unexpected spec");
  }

  const suite = ownDataValue(ed, "suite", "openEncryptedDisplay", true);
  if (
    !isRecord(suite)
    || ownDataValue(suite, "kem", "openEncryptedDisplay.suite", true) !== HPKE_SUITE.kem
    || ownDataValue(suite, "kdf", "openEncryptedDisplay.suite", true) !== HPKE_SUITE.kdf
    || ownDataValue(suite, "aead", "openEncryptedDisplay.suite", true) !== HPKE_SUITE.aead
  ) {
    throw new Error("openEncryptedDisplay: unsupported HPKE suite (decrypter never guesses)");
  }

  const tenant = ownString(ed, "tenant", "openEncryptedDisplay");
  const holdId = ownString(ed, "holdId", "openEncryptedDisplay");
  const deferredReceiptHash = ownString(ed, "deferredReceiptHash", "openEncryptedDisplay");
  const expiresAt = ownString(ed, "expiresAt", "openEncryptedDisplay");
  // Recompute + verify the AAD binding (tenant‖holdId‖deferredReceiptHash‖expiresAt).
  const { aadBytes, aadHash } = displayAad({ tenant, holdId, deferredReceiptHash, expiresAt });
  if (ownDataValue(ed, "aadHash", "openEncryptedDisplay", true) !== aadHash) {
    throw new Error("openEncryptedDisplay: aadHash does not bind the display fields (tampered)");
  }

  const recipientKid = ownString(recipient, "kid", "openEncryptedDisplay.recipient");
  const recipientsRaw = ownDataValue(ed, "recipients", "openEncryptedDisplay", true);
  const recipientCount = exactArrayLength(recipientsRaw, "openEncryptedDisplay.recipients");
  let wrappedEnc: string | undefined;
  let wrappedCek: string | undefined;
  for (let i = 0; i < recipientCount; i++) {
    const candidate = ownDataValue(recipientsRaw, `${i}`, "openEncryptedDisplay.recipients", true);
    if (isRecord(candidate) && ownString(candidate, "kid", `openEncryptedDisplay.recipients[${i}]`) === recipientKid) {
      wrappedEnc = ownString(candidate, "enc", `openEncryptedDisplay.recipients[${i}]`);
      wrappedCek = ownString(candidate, "wrappedCek", `openEncryptedDisplay.recipients[${i}]`);
      break;
    }
  }
  if (wrappedEnc === undefined || wrappedCek === undefined) {
    throw new Error(`openEncryptedDisplay: no recipient entry for kid ${recipientKid} (device added after this hold, or wrong device)`);
  }

  const payload = ownDataValue(ed, "payload", "openEncryptedDisplay", true);
  if (!isRecord(payload)) throw new Error("openEncryptedDisplay: missing payload");
  const payloadNonce = base64ToBytes(ownString(payload, "nonce", "openEncryptedDisplay.payload"));
  const payloadCiphertext = base64ToBytes(ownString(payload, "ciphertext", "openEncryptedDisplay.payload"));
  const enc = base64ToBytes(wrappedEnc);
  const wrappedCekBytes = base64ToBytes(wrappedCek);
  // The device-secret snapshot, the recovered CEK and the decrypted display bytes are owned by this
  // invocation. They are cleared on the success path and on every failure path — a tag mismatch, a
  // non-JSON payload and a poisoned-decoder refusal must not leave approval plaintext or a content
  // key behind in heap memory. The snapshot is taken INSIDE the scope so that no sensitive copy can
  // exist while an uncovered statement is still able to throw. The decoded string cannot be zeroed;
  // that limit is the language's.
  let recipientSecretKey: Uint8Array | undefined;
  let cek: Uint8Array | undefined;
  let plaintext: Uint8Array | undefined;
  try {
    recipientSecretKey = copyHpkeBytes(
      ownDataValue(recipient, "secretKey", "openEncryptedDisplay.recipient", true),
      "openEncryptedDisplay.recipient.secretKey",
    );
    assertHpkeRuntimeIntegrity();

    // 1. HPKE-open the wrapped CEK with the device secret key.
    cek = hpkeOpenBase({
      recipientSecretKey,
      enc,
      info: DISPLAY_HPKE_INFO,
      aad: aadBytes,
      ciphertext: wrappedCekBytes,
    });

    // 2. AEAD-open the display payload under the recovered CEK.
    plaintext = chacha20poly1305(cek, payloadNonce, aadBytes).decrypt(payloadCiphertext);

    // #77-C: captured decoder and captured parser. The plaintext is authenticated by this point, so
    // anything that can still change the RESULT here changes what the human approves without touching
    // the ciphertext.
    const plaintextText = reflectApply(textDecoderDecode, sharedDecoder, [plaintext]) as string;
    const parsed = reflectApply(jsonParse, JSONObject, [plaintextText]) as unknown;
    if (!isRecord(parsed)) throw new Error("openEncryptedDisplay: decrypted display is not a JSON object");
    return parsed;
  } finally {
    if (recipientSecretKey !== undefined) zeroCryptoBytes(recipientSecretKey);
    if (cek !== undefined) zeroCryptoBytes(cek);
    if (plaintext !== undefined) zeroCryptoBytes(plaintext);
  }
}
