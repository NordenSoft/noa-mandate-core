/**
 * TEST-ONLY Ed25519 arithmetic for key-holder signatures with a chosen R. A copy of the root
 * test/helpers/ed25519-keyholder.ts (this package cannot import the root test tree).
 *
 * The signature-R rule (R canonically encoded, not small-order) is pinned by signatures that the
 * KEY HOLDER produces at test time with a fresh key: S = r + k*a mod L over a chosen R. Nothing here
 * is committed as bytes, and every case needs the private scalar. Plain BigInt; never used by src/.
 */
import { createHash } from "node:crypto";

const P = (1n << 255n) - 19n;
const L = (1n << 252n) + 27742317777372353535851937790883648493n;
const D = 37095705934669439343138083508754565189542113879843219016388785533085940283555n;
const SQRT_M1 = 19681161376707505956807079304988542015446066515923890162744021073123829784752n;

type Point = [bigint, bigint, bigint, bigint];
const mod = (a: bigint, m: bigint = P): bigint => ((a % m) + m) % m;

function modPow(b: bigint, e: bigint, m: bigint): bigint {
  let r = 1n;
  b = mod(b, m);
  while (e > 0n) {
    if (e & 1n) r = (r * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return r;
}

function add(p: Point, q: Point): Point {
  const a = mod((p[1] - p[0]) * (q[1] - q[0]));
  const b = mod((p[1] + p[0]) * (q[1] + q[0]));
  const c = mod(2n * p[3] * q[3] * D);
  const d = mod(2n * p[2] * q[2]);
  const e = b - a, f = d - c, g = d + c, h = b + a;
  return [mod(e * f), mod(g * h), mod(f * g), mod(e * h)];
}

function mul(s: bigint, p: Point): Point {
  let acc: Point = [0n, 1n, 1n, 0n];
  for (let i = BigInt(s.toString(2).length) - 1n; i >= 0n; i--) {
    acc = add(acc, acc);
    if ((s >> i) & 1n) acc = add(acc, p);
  }
  return acc;
}

function le(bytes: Uint8Array): bigint {
  let v = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(bytes[i]!);
  return v;
}

function toLe32(v: bigint): Buffer {
  const out = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

export function encodePoint(p: Point): Buffer {
  const zi = modPow(p[2], P - 2n, P);
  const x = mod(p[0] * zi);
  const out = toLe32(mod(p[1] * zi));
  if (x & 1n) out[31] = out[31]! | 0x80;
  return out;
}

export function decodePoint(bytes: Uint8Array): Point {
  const sign = (bytes[31]! & 0x80) !== 0;
  const y = le(Uint8Array.from(bytes, (v, i) => (i === 31 ? v & 0x7f : v)));
  const u = mod(y * y - 1n), v = mod(D * y * y + 1n);
  let x = mod(u * modPow(v, 3n, P) * modPow(u * modPow(v, 7n, P), (P - 5n) / 8n, P));
  if (mod(v * x * x) !== u) x = mod(x * SQRT_M1);
  if ((x & 1n) === 1n !== sign) x = mod(-x);
  return [x, y, 1n, mod(x * y)];
}

const BASE = decodePoint(Buffer.from("5866666666666666666666666666666666666666666666666666666666666666", "hex"));
const sha512 = (...parts: Uint8Array[]): Buffer => {
  const h = createHash("sha512");
  for (const part of parts) h.update(part);
  return h.digest();
};

/** RFC 8032 §5.1.5 key expansion from a 32-byte seed: the private scalar a and the public key bytes. */
export function keyHolder(seed: Uint8Array): { a: bigint; publicRaw: Buffer } {
  const h = sha512(seed);
  const s = Buffer.from(h.subarray(0, 32));
  s[0] = s[0]! & 248;
  s[31] = (s[31]! & 127) | 64;
  const a = le(s);
  return { a, publicRaw: encodePoint(mul(a, BASE)) };
}

/** A key-holder signature over `message` whose R is `rBytes` = encoding of [r]B (+ any extra point). */
export function signWithR(a: bigint, publicRaw: Uint8Array, message: Uint8Array, rBytes: Uint8Array, r: bigint): Buffer {
  const k = mod(le(sha512(rBytes, publicRaw, message)), L);
  return Buffer.concat([Buffer.from(rBytes), toLe32(mod(r + k * a, L))]);
}

/**
 * The key-holder signatures the signature-R rule must refuse, plus an ordinary signature that must
 * verify (the control that proves this arithmetic is right).
 */
export function keyHolderRCases(seed: Uint8Array, message: Uint8Array): {
  publicRaw: Buffer;
  control: Buffer;
  refused: Array<[string, Buffer]>;
} {
  const { a, publicRaw } = keyHolder(seed);
  const r = mod(le(sha512(seed, Buffer.from("r"))), L);
  const identity = encodePoint([0n, 1n, 1n, 0n]);
  const identitySigned = Buffer.from(identity);
  identitySigned[31] = identitySigned[31]! | 0x80;
  const order8 = decodePoint(Buffer.from("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", "hex"));
  return {
    publicRaw,
    control: signWithR(a, publicRaw, message, encodePoint(mul(r, BASE)), r),
    refused: [
      ["R = identity", signWithR(a, publicRaw, message, identity, 0n)],
      ["R = identity spelled with the sign bit", signWithR(a, publicRaw, message, identitySigned, 0n)],
      ["R = rB + small-order point", signWithR(a, publicRaw, message, encodePoint(add(mul(r, BASE), order8)), r)],
    ],
  };
}
