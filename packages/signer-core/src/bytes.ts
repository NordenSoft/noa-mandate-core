/**
 * Portable byte <-> string codecs. Deliberately built on ONLY `atob`/`btoa` (ambient globals in
 * every browser AND in Node >= 16 — no `Buffer` import, so this file has zero Node-specific
 * surface and runs unmodified in a browser/webview/service-worker bundle). This is the "hard
 * compile-time boundary" the parent build spec requires: this package's tsconfig `lib` excludes
 * `"dom"`, so any accidental `window`/`document`/`Buffer` reference fails `tsc`, not just a
 * runtime check — see ../README.md "Compile-time boundary".
 */

import {
  copyUnsharedUint8Array,
  cryptoByteLength,
  zeroCryptoBytes,
} from "./runtime-integrity.js";

// Approval ciphertext and recipient keys pass through these codecs. Keep the same explicit
// post-load-poisoning boundary as JCS/hash: capture writable ambient slots once, then call them only
// through captured Reflect.apply. A pre-load poison remains a host/bootstrap concern.
const globalObject = globalThis;
const ReflectObject = Reflect;
const StringCtor = String;
const reflectApply = ReflectObject.apply;
const Uint8ArrayCtor = Uint8Array;
const stringFromCharCode = StringCtor.fromCharCode;
const stringCharCodeAt = StringCtor.prototype.charCodeAt;
const base64Encode = globalObject.btoa;
const base64Decode = globalObject.atob;

function normalizeCodecBytes(value: Uint8Array, label: string): Uint8Array {
  return copyUnsharedUint8Array(value, label);
}

function hexNibble(code: number): number {
  if (code >= 0x30 && code <= 0x39) return code - 0x30;
  if (code >= 0x41 && code <= 0x46) return code - 0x41 + 10;
  if (code >= 0x61 && code <= 0x66) return code - 0x61 + 10;
  return -1;
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error(`hexToBytes: odd-length hex string (${hex.length} chars)`);
  const byteLength = hex.length / 2;
  const out = new Uint8ArrayCtor(byteLength);
  for (let i = 0; i < byteLength; i++) {
    const high = hexNibble(reflectApply(stringCharCodeAt, hex, [i * 2]) as number);
    const low = hexNibble(reflectApply(stringCharCodeAt, hex, [i * 2 + 1]) as number);
    if (high < 0 || low < 0) {
      throw new Error(`hexToBytes: invalid hex byte at offset ${i * 2}`);
    }
    out[i] = (high << 4) | low;
  }
  return out;
}

const HEX_CHARS = "0123456789abcdef";

export function bytesToHex(bytes: Uint8Array): string {
  const source = normalizeCodecBytes(bytes, "bytesToHex.bytes");
  try {
    let out = "";
    const length = cryptoByteLength(source);
    for (let i = 0; i < length; i++) {
      const b = source[i]!;
      out += HEX_CHARS[(b >> 4) & 0xf]! + HEX_CHARS[b & 0xf]!;
    }
    return out;
  } finally {
    zeroCryptoBytes(source);
  }
}

/** Encode raw bytes as standard (RFC 4648 §4) base64 — no Buffer, `btoa` operates on a
 *  "binary string" (one JS char per byte, 0-255), so we build that string ourselves first. */
export function bytesToBase64(bytes: Uint8Array): string {
  const source = normalizeCodecBytes(bytes, "bytesToBase64.bytes");
  try {
    let binary = "";
    const length = cryptoByteLength(source);
    for (let i = 0; i < length; i++) {
      binary += reflectApply(stringFromCharCode, StringCtor, [source[i]!]) as string;
    }
    return reflectApply(base64Encode, globalObject, [binary]) as string;
  } finally {
    zeroCryptoBytes(source);
  }
}

export function base64ToBytes(b64: string): Uint8Array {
  const binary = reflectApply(base64Decode, globalObject, [b64]) as string;
  const out = new Uint8ArrayCtor(binary.length);
  for (let i = 0; i < binary.length; i++) {
    out[i] = reflectApply(stringCharCodeAt, binary, [i]) as number;
  }
  return out;
}
