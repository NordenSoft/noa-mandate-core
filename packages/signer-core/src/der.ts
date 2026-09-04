import { base64ToBytes, bytesToBase64, bytesToHex } from "./bytes.js";
import {
  copyUnsharedUint8Array as normalizeDerBytes,
  cryptoByteLength,
  zeroCryptoBytes,
} from "./runtime-integrity.js";

/**
 * Minimal, fixed-shape DER codec for Ed25519 keys — deliberately NOT a general ASN.1 parser.
 *
 * `noa-receipt`'s `Signer.privateKey` / keyring public keys are base64(DER) (PKCS8 for private,
 * SPKI for public), produced by `node:crypto`'s `generateKeyPairSync("ed25519")` (see
 * `noa-receipt/src/keys.ts`). This package's signing driver is `@noble/curves/ed25519`, which
 * operates on the RAW 32-byte seed/point, not DER — so to accept the SAME key material every
 * other noa-receipt-ecosystem package already passes around (keyrings, key-files, the
 * `noa-approve` CLI), this file extracts the raw 32 bytes from that DER wrapper.
 *
 * Ed25519 PKCS8/SPKI DER (RFC 8410 §7, no attributes, no embedded public key in the PKCS8 case)
 * is a FIXED-LENGTH, FIXED-PREFIX encoding — there is exactly one valid byte layout, so a full
 * ASN.1 parser is unnecessary complexity/attack-surface; a prefix-and-length check is both
 * sufficient and strictly stricter (anything that doesn't match this exact shape is rejected,
 * never "parsed leniently"). Verified empirically against real `node:crypto` output:
 *
 *   node -e 'const{generateKeyPairSync}=require("node:crypto");
 *     const{publicKey,privateKey}=generateKeyPairSync("ed25519");
 *     console.log(privateKey.export({type:"pkcs8",format:"der"}).length,
 *                 publicKey.export({type:"spki",format:"der"}).length)'
 *   -> 48 44
 *
 * (48-byte PKCS8: 16-byte fixed prefix + 32-byte raw seed. 44-byte SPKI: 12-byte fixed prefix +
 * 32-byte raw public key — the same 12-byte SPKI prefix `noa-receipt/src/keys.ts` itself relies
 * on, see its `verifyEd25519`.) Both are pure byte-array operations — no ASN.1 library, no
 * `node:crypto` — so this file stays inside the package's zero-platform-SDK compile boundary.
 */

export class DerCodecError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DerCodecError";
  }
}

const PKCS8_ED25519_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);
const PKCS8_ED25519_TOTAL_LEN = 48; // 16-byte prefix + 32-byte seed

const SPKI_ED25519_PREFIX = Uint8Array.from([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]);
const SPKI_ED25519_TOTAL_LEN = 44; // 12-byte prefix + 32-byte raw public key
const Uint8ArrayCtor = Uint8Array;

function matchesPrefix(der: Uint8Array, prefix: Uint8Array): boolean {
  const prefixLength = cryptoByteLength(prefix);
  for (let i = 0; i < prefixLength; i++) if (der[i] !== prefix[i]) return false;
  return true;
}

function copyByteRange(source: Uint8Array, start: number, length: number): Uint8Array {
  const out = new Uint8ArrayCtor(length);
  for (let i = 0; i < length; i++) out[i] = source[start + i] as number;
  return out;
}

/**
 * Extract the raw 32-byte Ed25519 seed from a base64(DER PKCS8) private key — the same string
 * type as `noa-receipt`'s `Signer.privateKey` / `KeyPair.privateKey`. Fails CLOSED: any DER that
 * isn't exactly this fixed 48-byte canonical shape is rejected, never tolerated/truncated.
 */
export function pkcs8Ed25519ToRawSeed(privateKeyB64: string): Uint8Array {
  const der = base64ToBytes(privateKeyB64);
  try {
    const derLength = cryptoByteLength(der);
    if (derLength !== PKCS8_ED25519_TOTAL_LEN) {
      throw new DerCodecError(
        `pkcs8Ed25519ToRawSeed: expected a ${PKCS8_ED25519_TOTAL_LEN}-byte PKCS8 DER Ed25519 private key, got ${derLength} bytes`,
      );
    }
    if (!matchesPrefix(der, PKCS8_ED25519_PREFIX)) {
      throw new DerCodecError(
        `pkcs8Ed25519ToRawSeed: not a canonical Ed25519 PKCS8 DER private key (ASN.1 prefix mismatch); got prefix ${bytesToHex(copyByteRange(der, 0, 16))}`,
      );
    }
    return copyByteRange(der, 16, 32);
  } finally {
    zeroCryptoBytes(der);
  }
}

/**
 * Extract the raw 32-byte Ed25519 public key from a base64(DER SPKI) public key — the same
 * string type as `noa-receipt`'s `KeyPair.publicKey` / keyring values. Used only to
 * cross-check a locally-derived public key against noa-receipt's own output (see the G2
 * golden-parity test) — `signReceipt` itself never needs the public key.
 */
export function spkiEd25519ToRawPublicKey(publicKeyB64: string): Uint8Array {
  const der = base64ToBytes(publicKeyB64);
  const derLength = cryptoByteLength(der);
  if (derLength !== SPKI_ED25519_TOTAL_LEN) {
    throw new DerCodecError(
      `spkiEd25519ToRawPublicKey: expected a ${SPKI_ED25519_TOTAL_LEN}-byte SPKI DER Ed25519 public key, got ${derLength} bytes`,
    );
  }
  if (!matchesPrefix(der, SPKI_ED25519_PREFIX)) {
    throw new DerCodecError(
      `spkiEd25519ToRawPublicKey: not a canonical Ed25519 SPKI DER public key (ASN.1 prefix mismatch); got prefix ${bytesToHex(copyByteRange(der, 0, 12))}`,
    );
  }
  return copyByteRange(der, 12, 32);
}

/**
 * The reverse direction: wrap a raw 32-byte Ed25519 seed as base64(DER PKCS8) — the same
 * string shape `noa-receipt`'s own `generateKeyPair` emits for `KeyPair.privateKey`. Used by
 * `./keygen.js` so a key generated by THIS package is a byte-identical drop-in for a
 * `noa-receipt` keyring/key-file entry. Pure concatenation of the fixed prefix + the seed —
 * there is no encoding ambiguity to get wrong (unlike the decode direction, there is nothing to
 * validate about caller-supplied input here beyond the seed's length).
 */
export function rawSeedToPkcs8Der(seed: Uint8Array): string {
  // This encoder is itself a public export, so callers can bypass generateKeyPair's normalization.
  // Work only from an invocation-local snapshot: another worker must not race private seed bytes.
  const source = normalizeDerBytes(seed, "rawSeedToPkcs8Der.seed");
  try {
    const seedLength = cryptoByteLength(source);
    if (seedLength !== 32) throw new DerCodecError(`rawSeedToPkcs8Der: expected a 32-byte seed, got ${seedLength} bytes`);
    const der = new Uint8ArrayCtor(PKCS8_ED25519_TOTAL_LEN);
    // P1-9: integer-index assembly invokes no writable `.set()` hook with the private seed.
    const p = 16;
    for (let i = 0; i < p; i++) der[i] = PKCS8_ED25519_PREFIX[i] as number;
    for (let i = 0; i < seedLength; i++) der[p + i] = source[i] as number;
    try {
      return bytesToBase64(der);
    } finally {
      zeroCryptoBytes(der);
    }
  } finally {
    zeroCryptoBytes(source);
  }
}

/** The reverse direction for the public key: wrap a raw 32-byte Ed25519 public key as
 *  base64(DER SPKI) — the same string shape `noa-receipt`'s own `generateKeyPair` emits for
 *  `KeyPair.publicKey` / keyring values. */
export function rawPublicKeyToSpkiDer(publicKey: Uint8Array): string {
  const source = normalizeDerBytes(publicKey, "rawPublicKeyToSpkiDer.publicKey");
  try {
    const publicKeyLength = cryptoByteLength(source);
    if (publicKeyLength !== 32) throw new DerCodecError(`rawPublicKeyToSpkiDer: expected a 32-byte public key, got ${publicKeyLength} bytes`);
    const der = new Uint8ArrayCtor(SPKI_ED25519_TOTAL_LEN);
    const p = 12;
    for (let i = 0; i < p; i++) der[i] = SPKI_ED25519_PREFIX[i] as number;
    for (let i = 0; i < publicKeyLength; i++) der[p + i] = source[i] as number;
    try {
      return bytesToBase64(der);
    } finally {
      zeroCryptoBytes(der);
    }
  } finally {
    zeroCryptoBytes(source);
  }
}
