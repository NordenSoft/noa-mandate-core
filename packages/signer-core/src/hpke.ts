/**
 * HPKE (RFC 9180) base-mode single-shot Seal/Open — the ONE encryption primitive the NOA approval
 * protocol uses for the D15-v2 encrypted display (§8/§9/§12) and, later, the D23 encrypted reason.
 *
 * Ciphersuite is LOCKED (build spec §4, RFC 9180 base mode):
 *   KEM  = DHKEM(X25519, HKDF-SHA256)  (0x0020)
 *   KDF  = HKDF-SHA256                 (0x0001)
 *   AEAD = ChaCha20Poly1305            (0x0003)
 *
 * Zero platform-SDK imports (same posture as the rest of noa-signer): `@noble/curves` supplies
 * X25519, `@noble/hashes` supplies HKDF-SHA256, `@noble/ciphers` supplies ChaCha20Poly1305 — so this
 * runs unmodified in a browser/webview/service-worker (the phone) and in Node (the gate). This is a
 * FROM-PRIMITIVES implementation of RFC 9180 §4 (DHKEM) + §5.1 (key schedule) + §6.1 (single-shot),
 * NOT a wrapper around a monolithic HPKE lib — validated byte-exact against RFC 9180 Appendix A.2.1
 * (see test/hpke.test.ts: enc / shared_secret / key / base_nonce / ciphertext all match the vector).
 *
 * It answers exactly two operations and nothing else: seal a plaintext TO a recipient public key,
 * and open a ciphertext WITH a recipient secret key. The recipient secret key is the caller's; this
 * module never generates, stores, logs, or transmits it (Red Line 1 lives at the call sites).
 */

import { x25519 } from "@noble/curves/ed25519.js";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { Poly1305, poly1305 } from "@noble/ciphers/_poly1305.js";
import { extract, expand } from "@noble/hashes/hkdf.js";
import { SHA256_IV } from "@noble/hashes/_md.js";
import { _HMAC, hmac } from "@noble/hashes/hmac.js";
import { _SHA256, sha256 } from "@noble/hashes/sha2.js";
import {
  capturedTextEncode,
  capturedCryptoRandomBytes,
  copyUnsharedUint8Array,
  createCryptoRuntimeIntegrityFence,
  cryptoByteLength,
  ownDataValue,
  prototypeChainTargets,
  zeroCryptoBytes,
} from "./runtime-integrity.js";

// ── locked suite ids (RFC 9180 §7) — carried in the encrypted-display envelope so a decrypter never
//    guesses the suite. { kem:32, kdf:1, aead:3 }. ──────────────────────────────────────────────
export const HPKE_KEM_ID = 0x0020;
export const HPKE_KDF_ID = 0x0001;
export const HPKE_AEAD_ID = 0x0003;
export const HPKE_SUITE = Object.freeze({ kem: HPKE_KEM_ID, kdf: HPKE_KDF_ID, aead: HPKE_AEAD_ID }) as Readonly<{
  kem: typeof HPKE_KEM_ID;
  kdf: typeof HPKE_KDF_ID;
  aead: typeof HPKE_AEAD_ID;
}>;

const HPKE_VERSION = "HPKE-v1";
const N_SECRET = 32; // DHKEM(X25519,HKDF-SHA256) shared-secret length
const N_K = 32; // ChaCha20Poly1305 key length
const N_N = 12; // ChaCha20Poly1305 nonce length
const MODE_BASE = 0x00;

// HPKE labels are key-schedule domain separation. A post-load TextEncoder replacement must never
// rewrite them. Capture the writable intrinsic once and invoke it through captured Reflect.apply.
const Uint8ArrayCtor = Uint8Array;
const x25519ScalarMult = x25519.scalarMult;
const EMPTY = new Uint8ArrayCtor(0);
const X25519_BASEPOINT = new Uint8ArrayCtor(32);
X25519_BASEPOINT[0] = 9;
const hpkeIntegrityTargets: ReadonlyArray<readonly [string, object]> = [
  ["@noble/hashes.sha256", sha256],
  ["@noble/hashes.hmac", hmac],
  ["@noble/hashes._HMAC.prototype", _HMAC.prototype],
  // `_SHA256` and each derived base constructor resolve `super()` through their live [[Prototype]]
  // link. Snapshot the complete constructor chain so a self-restoring construct Proxy cannot run
  // after the final fence and mutate an already-verified HMAC hook before raw DH is extracted.
  ...prototypeChainTargets("@noble/hashes._SHA256.constructor-chain", _SHA256),
  ...prototypeChainTargets("@noble/hashes._SHA256.prototype-chain", _SHA256.prototype),
  // SHA-256 constructors copy this exported mutable table on every invocation. Its words are part
  // of the algorithm identity carried by the fixed HPKE suite id, not replaceable runtime config.
  ["@noble/hashes.SHA256_IV", SHA256_IV],
  ["@noble/ciphers.poly1305", poly1305],
  ["@noble/ciphers.Poly1305.prototype", Poly1305.prototype],
];

/**
 * Fail closed if a post-load mutation reaches a secret-bearing primordial that this module or its
 * audited dependencies still has to consult. Capturing individual helpers cannot protect values
 * read inside dependency code, and mutating global prototypes during a synchronous HPKE operation
 * is not a healthy-liveness condition. A pre-load mutation remains a host/bootstrap concern.
 */
export const assertHpkeRuntimeIntegrity = createCryptoRuntimeIntegrityFence("HPKE", hpkeIntegrityTargets);

/** Normalize a branded Uint8Array (including Node Buffer) without invoking caller code or accepting
 * shared memory. Captured intrinsic getters work across realms/subclasses and reject proxies and
 * non-Uint8 typed arrays; the ArrayBuffer getter rejects SharedArrayBuffer-backed views so another
 * agent cannot race the byte snapshot. */
export function copyHpkeBytes(value: unknown, label: string): Uint8Array {
  assertHpkeRuntimeIntegrity();
  return copyUnsharedUint8Array(value, label);
}

function i2osp2(n: number): Uint8Array {
  const out = new Uint8ArrayCtor(2);
  out[0] = (n >>> 8) & 0xff;
  out[1] = n & 0xff;
  return out;
}

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  let total = 0;
  for (let ai = 0; ai < arrays.length; ai++) total += cryptoByteLength(arrays[ai] as Uint8Array);
  const out = new Uint8ArrayCtor(total);
  // Raw DH enters labeled extract here. Index assembly avoids a live `.set`; the runtime-integrity
  // gate additionally refuses every mutable TypedArray/DataView lookup used by audited dependencies.
  let off = 0;
  for (let ai = 0; ai < arrays.length; ai++) {
    const a = arrays[ai] as Uint8Array;
    const n = cryptoByteLength(a);
    for (let i = 0; i < n; i++) out[off + i] = a[i] as number;
    off += n;
  }
  return out;
}

// suite_id for the KEM labeled KDF (RFC 9180 §4.1): "KEM" || I2OSP(kem_id, 2).
const KEM_SUITE_ID = concatBytes(capturedTextEncode("KEM"), i2osp2(HPKE_KEM_ID));
// suite_id for the HPKE key schedule (RFC 9180 §5.1): "HPKE" || kem_id || kdf_id || aead_id.
const HPKE_SUITE_ID = concatBytes(
  capturedTextEncode("HPKE"),
  i2osp2(HPKE_KEM_ID),
  i2osp2(HPKE_KDF_ID),
  i2osp2(HPKE_AEAD_ID),
);

// RFC 9180 §4.0 LabeledExtract / LabeledExpand. `extract(hash, ikm, salt)` / `expand(hash, prk,
// info, L)` are @noble/hashes' HKDF — arg order verified against the vector.
function labeledExtract(suiteId: Uint8Array, salt: Uint8Array, label: string, ikm: Uint8Array): Uint8Array {
  // `labeledIkm` is a fresh buffer that CONTAINS a copy of `ikm`. On the DHKEM path that ikm is the
  // raw X25519 result, so this buffer holds raw DH under a different name — and nothing was clearing
  // it. It is invocation-local (nothing else can reach it), so it is cleared on every exit path.
  let labeledIkm: Uint8Array | undefined;
  try {
    labeledIkm = concatBytes(capturedTextEncode(HPKE_VERSION), suiteId, capturedTextEncode(label), ikm);
    return extract(sha256, labeledIkm, salt);
  } finally {
    if (labeledIkm !== undefined) zeroCryptoBytes(labeledIkm);
  }
}
function labeledExpand(suiteId: Uint8Array, prk: Uint8Array, label: string, info: Uint8Array, length: number): Uint8Array {
  const labeledInfo = concatBytes(
    i2osp2(length),
    capturedTextEncode(HPKE_VERSION),
    suiteId,
    capturedTextEncode(label),
    info,
  );
  return expand(sha256, prk, labeledInfo, length);
}

// RFC 9180 §4.1 ExtractAndExpand (inside DHKEM).
function extractAndExpand(dh: Uint8Array, kemContext: Uint8Array): Uint8Array {
  // The extract PRK is key material derived from raw DH; it dies with this invocation, on both the
  // success and the throw path. Only the returned shared secret outlives this frame. It is derived
  // INSIDE the scope so no derivation failure can leave it behind.
  let eaePrk: Uint8Array | undefined;
  try {
    eaePrk = labeledExtract(KEM_SUITE_ID, EMPTY, "eae_prk", dh);
    return labeledExpand(KEM_SUITE_ID, eaePrk, "shared_secret", kemContext, N_SECRET);
  } finally {
    if (eaePrk !== undefined) zeroCryptoBytes(eaePrk);
  }
}

/** DHKEM(X25519, HKDF-SHA256) Encap (RFC 9180 §4.1). `ephemeralSecretKey` is injectable for
 *  deterministic tests / RFC vectors; in production it is a fresh CSPRNG scalar. */
function encap(recipientPublicKey: Uint8Array, ephemeralSecretKey?: Uint8Array): { sharedSecret: Uint8Array; enc: Uint8Array } {
  // The ephemeral scalar and the raw DH result are owned by this invocation and by nothing else:
  // `skE` is either freshly drawn here or the private copy `hpkeSealBase` already made, so zeroing
  // both on every exit path never reaches a caller's buffer. Both are created INSIDE the scope so a
  // failing RNG draw or a failing ladder cannot leave either of them uncleared.
  let skE: Uint8Array | undefined;
  let dh: Uint8Array | undefined;
  try {
    // Do not call x25519.keygen(): Noble resolves globalThis.crypto.getRandomValues at call time.
    // All randomness in this module must come through the module-load captured native CSPRNG.
    skE = ephemeralSecretKey ?? hpkeRandomBytes(32);
    // Deliberately use the captured Montgomery ladder for BOTH public-key derivation and DH. Noble's
    // faster getPublicKey() route crosses the Edwards ScalarMultiplier and draws a live blinding RNG
    // after our final integrity fence. The ladder is deterministic, has the same RFC 7748 result, and
    // removes that secret-bearing callback/prototype surface from this module's TCB.
    const enc = x25519ScalarMult(skE, X25519_BASEPOINT);
    dh = x25519ScalarMult(skE, recipientPublicKey);
    const kemContext = concatBytes(enc, recipientPublicKey);
    const sharedSecret = extractAndExpand(dh, kemContext);
    return { sharedSecret, enc };
  } finally {
    if (skE !== undefined) zeroCryptoBytes(skE);
    if (dh !== undefined) zeroCryptoBytes(dh);
  }
}

/** DHKEM(X25519, HKDF-SHA256) Decap (RFC 9180 §4.1). */
function decap(enc: Uint8Array, recipientSecretKey: Uint8Array): Uint8Array {
  // Raw DH is invocation-owned; the device secret itself stays the caller's to clear. The scope
  // opens BEFORE the first ladder call: it used to open after all three statements, so a failing
  // second ladder call or a failing concat returned with raw DH resident and nothing to clear it.
  let dh: Uint8Array | undefined;
  try {
    dh = x25519ScalarMult(recipientSecretKey, enc);
    const pkRm = x25519ScalarMult(recipientSecretKey, X25519_BASEPOINT);
    const kemContext = concatBytes(enc, pkRm);
    return extractAndExpand(dh, kemContext);
  } finally {
    if (dh !== undefined) zeroCryptoBytes(dh);
  }
}

/** RFC 9180 §5.1 KeySchedule for mode_base (psk = psk_id = ""). Returns the AEAD key + the seq-0
 *  base nonce (single-shot: nonce = base_nonce XOR I2OSP(0) = base_nonce). */
function keyScheduleBase(sharedSecret: Uint8Array, info: Uint8Array): { key: Uint8Array; baseNonce: Uint8Array } {
  const pskIdHash = labeledExtract(HPKE_SUITE_ID, EMPTY, "psk_id_hash", EMPTY);
  const infoHash = labeledExtract(HPKE_SUITE_ID, EMPTY, "info_hash", info);
  const mode = new Uint8ArrayCtor(1);
  mode[0] = MODE_BASE;
  const keyScheduleContext = concatBytes(mode, pskIdHash, infoHash);
  // RFC 9180 §5.1 `secret` is the key-schedule PRK: it can regenerate both the AEAD key and the
  // base nonce, so it must not outlive the frame that derived them, on success or on a throw.
  //
  // The AEAD key is derived BEFORE the base nonce, so there is an instant where a fully derived
  // content key exists and the function can still fail. `transferred` marks the exact point where
  // ownership of both outputs passes to the caller: until then a failure clears the partial output,
  // and after it the caller's buffers are left alone. Clearing unconditionally here would hand back
  // 32 zero bytes as an AEAD key, which is why the flag exists rather than a blanket zeroization.
  let secret: Uint8Array | undefined;
  let key: Uint8Array | undefined;
  let baseNonce: Uint8Array | undefined;
  let transferred = false;
  try {
    secret = labeledExtract(HPKE_SUITE_ID, sharedSecret, "secret", EMPTY);
    key = labeledExpand(HPKE_SUITE_ID, secret, "key", keyScheduleContext, N_K);
    baseNonce = labeledExpand(HPKE_SUITE_ID, secret, "base_nonce", keyScheduleContext, N_N);
    const schedule = { key, baseNonce };
    transferred = true;
    return schedule;
  } finally {
    if (secret !== undefined) zeroCryptoBytes(secret);
    if (!transferred) {
      if (key !== undefined) zeroCryptoBytes(key);
      if (baseNonce !== undefined) zeroCryptoBytes(baseNonce);
    }
  }
}

export interface HpkeSealInput {
  /** Raw 32-byte X25519 recipient public key (RFC 9180 SerializePublicKey = the raw key). */
  recipientPublicKey: Uint8Array;
  /** HPKE `info` (key-schedule context binding). Defaults to empty. */
  info?: Uint8Array;
  /** AEAD associated data (authenticated, not encrypted). Defaults to empty. */
  aad?: Uint8Array;
  plaintext: Uint8Array;
  /** TEST/vector ONLY — pin the KEM ephemeral scalar for determinism. Never set in production. */
  ephemeralSecretKey?: Uint8Array;
}

export interface HpkeSealOutput {
  /** The KEM encapsulated key (the ephemeral X25519 public key, 32 bytes). */
  enc: Uint8Array;
  /** AEAD ciphertext (plaintext.length + 16-byte Poly1305 tag). */
  ciphertext: Uint8Array;
}

/** RFC 9180 §6.1 single-shot SealBase: (enc, ct) = Seal(pkR, info, aad, pt). */
export function hpkeSealBase(input: HpkeSealInput): HpkeSealOutput {
  const recipientPublicKey = copyHpkeBytes(
    ownDataValue(input, "recipientPublicKey", "hpkeSealBase", true),
    "hpkeSealBase.recipientPublicKey",
  );
  // ── THE CLEANUP SCOPE OPENS AT THE FIRST SENSITIVE COPY, NOT AT THE FIRST DERIVATION ──────────
  // It used to open after the integrity fence and the two length checks. Those three sites can all
  // throw, and by then this invocation already held a private copy of the plaintext (the display
  // CEK on the production path) and of any injected ephemeral scalar — so a poisoned-intrinsic
  // refusal or a wrong-length argument returned through a path that cleared nothing. Every variable
  // below is declared before the `try` and tested for `undefined` in the `finally`, so a throw
  // inside `copyHpkeBytes` itself leaves the cleanup correct rather than reading a partly built
  // scope. The recipient public key is deliberately outside: it is public, and nothing is owed it.
  let plaintext: Uint8Array | undefined;
  let ephemeralSecretKey: Uint8Array | undefined;
  let sharedSecret: Uint8Array | undefined;
  let key: Uint8Array | undefined;
  let baseNonce: Uint8Array | undefined;
  try {
    plaintext = copyHpkeBytes(
      ownDataValue(input, "plaintext", "hpkeSealBase", true),
      "hpkeSealBase.plaintext",
    );
    const infoValue = ownDataValue(input, "info", "hpkeSealBase", false);
    const aadValue = ownDataValue(input, "aad", "hpkeSealBase", false);
    const ephemeralValue = ownDataValue(input, "ephemeralSecretKey", "hpkeSealBase", false);
    const info = infoValue === undefined ? EMPTY : copyHpkeBytes(infoValue, "hpkeSealBase.info");
    const aad = aadValue === undefined ? EMPTY : copyHpkeBytes(aadValue, "hpkeSealBase.aad");
    ephemeralSecretKey = ephemeralValue === undefined
      ? undefined
      : copyHpkeBytes(ephemeralValue, "hpkeSealBase.ephemeralSecretKey");
    // Final TOCTOU fence: all caller-controlled descriptors and bytes are now normalized, and no
    // caller getter/proxy is consulted after this point.
    assertHpkeRuntimeIntegrity();
    if (cryptoByteLength(recipientPublicKey) !== 32) {
      throw new Error(`hpkeSealBase: recipient public key must be 32 bytes, got ${cryptoByteLength(recipientPublicKey)}`);
    }
    if (ephemeralSecretKey !== undefined && cryptoByteLength(ephemeralSecretKey) !== 32) {
      throw new Error(`hpkeSealBase: ephemeral secret key must be 32 bytes, got ${cryptoByteLength(ephemeralSecretKey)}`);
    }
    const encapsulated = encap(recipientPublicKey, ephemeralSecretKey);
    sharedSecret = encapsulated.sharedSecret;
    const schedule = keyScheduleBase(sharedSecret, info);
    key = schedule.key;
    baseNonce = schedule.baseNonce;
    const ciphertext = chacha20poly1305(key, baseNonce, aad).encrypt(plaintext);
    return { enc: encapsulated.enc, ciphertext };
  } finally {
    if (plaintext !== undefined) zeroCryptoBytes(plaintext);
    if (ephemeralSecretKey !== undefined) zeroCryptoBytes(ephemeralSecretKey);
    if (sharedSecret !== undefined) zeroCryptoBytes(sharedSecret);
    if (key !== undefined) zeroCryptoBytes(key);
    if (baseNonce !== undefined) zeroCryptoBytes(baseNonce);
  }
}

export interface HpkeOpenInput {
  /** Raw 32-byte X25519 recipient secret key — the caller's device key. Never leaves the device. */
  recipientSecretKey: Uint8Array;
  /** The KEM encapsulated key from the sealer. */
  enc: Uint8Array;
  info?: Uint8Array;
  aad?: Uint8Array;
  ciphertext: Uint8Array;
}

/** RFC 9180 §6.1 single-shot OpenBase: pt = Open(enc, skR, info, aad, ct). Throws if the AEAD tag
 *  fails (wrong recipient key, tampered ciphertext, or wrong aad/info) — fail-closed, never a
 *  partial/plaintext-on-error path. */
export function hpkeOpenBase(input: HpkeOpenInput): Uint8Array {
  // The device-secret snapshot is the FIRST thing this function makes, so the cleanup scope opens
  // before it exists. The integrity fence and both length checks now sit inside it: previously a
  // wrong-length key or a poisoned intrinsic threw while a complete private X25519 device key was
  // already resident, and nothing cleared it. The returned plaintext stays the caller's to clear —
  // `openEncryptedDisplay` does exactly that.
  let recipientSecretKey: Uint8Array | undefined;
  let sharedSecret: Uint8Array | undefined;
  let key: Uint8Array | undefined;
  let baseNonce: Uint8Array | undefined;
  try {
    recipientSecretKey = copyHpkeBytes(
      ownDataValue(input, "recipientSecretKey", "hpkeOpenBase", true),
      "hpkeOpenBase.recipientSecretKey",
    );
    const enc = copyHpkeBytes(ownDataValue(input, "enc", "hpkeOpenBase", true), "hpkeOpenBase.enc");
    const ciphertext = copyHpkeBytes(
      ownDataValue(input, "ciphertext", "hpkeOpenBase", true),
      "hpkeOpenBase.ciphertext",
    );
    const infoValue = ownDataValue(input, "info", "hpkeOpenBase", false);
    const aadValue = ownDataValue(input, "aad", "hpkeOpenBase", false);
    const info = infoValue === undefined ? EMPTY : copyHpkeBytes(infoValue, "hpkeOpenBase.info");
    const aad = aadValue === undefined ? EMPTY : copyHpkeBytes(aadValue, "hpkeOpenBase.aad");
    assertHpkeRuntimeIntegrity();
    if (cryptoByteLength(recipientSecretKey) !== 32) {
      throw new Error(`hpkeOpenBase: recipient secret key must be 32 bytes, got ${cryptoByteLength(recipientSecretKey)}`);
    }
    if (cryptoByteLength(enc) !== 32) {
      throw new Error(`hpkeOpenBase: enc must be 32 bytes, got ${cryptoByteLength(enc)}`);
    }
    sharedSecret = decap(enc, recipientSecretKey);
    const schedule = keyScheduleBase(sharedSecret, info);
    key = schedule.key;
    baseNonce = schedule.baseNonce;
    // .decrypt throws on Poly1305 tag mismatch — the AEAD failure IS the security boundary.
    return chacha20poly1305(key, baseNonce, aad).decrypt(ciphertext);
  } finally {
    if (recipientSecretKey !== undefined) zeroCryptoBytes(recipientSecretKey);
    if (sharedSecret !== undefined) zeroCryptoBytes(sharedSecret);
    if (key !== undefined) zeroCryptoBytes(key);
    if (baseNonce !== undefined) zeroCryptoBytes(baseNonce);
  }
}

/** CSPRNG bytes (WebCrypto via @noble). Exposed so the display sealer draws its CEK/nonce from the
 *  same audited source; injectable at the display layer for deterministic tests. */
export function hpkeRandomBytes(n: number): Uint8Array {
  assertHpkeRuntimeIntegrity();
  return capturedCryptoRandomBytes(n, "hpkeRandomBytes");
}
