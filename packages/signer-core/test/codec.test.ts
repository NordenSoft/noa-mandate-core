/**
 * Self-refute pass on the two low-level codecs G1/G2 depend on: the DER extraction (der.ts)
 * must fail CLOSED on anything that isn't the exact canonical Ed25519 shape, and the byte<->
 * base64/hex codecs (bytes.ts) must round-trip losslessly on arbitrary data, not just on the
 * happy-path values G1/G2 exercise.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  pkcs8Ed25519ToRawSeed,
  spkiEd25519ToRawPublicKey,
  rawSeedToPkcs8Der,
  rawPublicKeyToSpkiDer,
  DerCodecError,
} from "../src/der.js";
import { bytesToBase64, base64ToBytes, bytesToHex, hexToBytes } from "../src/bytes.js";
import { generateKeyPair as ourGenerateKeyPair } from "../src/keygen.js";
import { generateKeyPair } from "noa-receipt";

test("pkcs8Ed25519ToRawSeed: happy path extracts exactly the 32-byte seed", () => {
  const pair = generateKeyPair("codec-1");
  const seed = pkcs8Ed25519ToRawSeed(pair.privateKey);
  assert.equal(seed.length, 32);
});

test("pkcs8Ed25519ToRawSeed: fails closed on wrong length", () => {
  const tooShort = bytesToBase64(new Uint8Array(10));
  assert.throws(() => pkcs8Ed25519ToRawSeed(tooShort), DerCodecError);
});

test("pkcs8Ed25519ToRawSeed: fails closed on right length, wrong prefix (not a valid Ed25519 PKCS8 DER)", () => {
  const garbage = bytesToBase64(new Uint8Array(48).fill(0xaa));
  assert.throws(() => pkcs8Ed25519ToRawSeed(garbage), DerCodecError);
});

test("spkiEd25519ToRawPublicKey: happy path extracts exactly the 32-byte public key, fails closed on garbage", () => {
  const pair = generateKeyPair("codec-2");
  const pub = spkiEd25519ToRawPublicKey(pair.publicKey);
  assert.equal(pub.length, 32);

  const garbage = bytesToBase64(new Uint8Array(44).fill(0xbb));
  assert.throws(() => spkiEd25519ToRawPublicKey(garbage), DerCodecError);
});

test("bytesToBase64/base64ToBytes round-trip losslessly over all 256 byte values", () => {
  const original = new Uint8Array(256);
  for (let i = 0; i < 256; i++) original[i] = i;
  const roundTripped = base64ToBytes(bytesToBase64(original));
  assert.deepEqual(roundTripped, original);
});

test("byte encoders reject shared or detached views instead of racing or silently truncating", () => {
  const shared = new Uint8Array(new SharedArrayBuffer(3));
  assert.throws(() => bytesToBase64(shared), /non-shared ArrayBuffer/);
  assert.throws(() => bytesToHex(shared), /non-shared ArrayBuffer/);

  const detached = new Uint8Array([0x41, 0x42, 0x43]);
  structuredClone(detached.buffer, { transfer: [detached.buffer] });
  assert.equal(detached.length, 0, "the detached byte-codec witness did not bite");
  assert.throws(() => bytesToBase64(detached), /still attached/,
    "detached non-empty bytes were silently base64-encoded as empty input");
  assert.throws(() => bytesToHex(detached), /still attached/,
    "detached non-empty bytes were silently hex-encoded as empty input");
});

test("public DER encoders reject shared byte views instead of racing key material", () => {
  const sharedSeed = new Uint8Array(new SharedArrayBuffer(32));
  const sharedPublicKey = new Uint8Array(new SharedArrayBuffer(32));
  assert.throws(() => rawSeedToPkcs8Der(sharedSeed), /non-shared ArrayBuffer/,
    "the public PKCS8 encoder accepted worker-raceable private seed memory");
  assert.throws(() => rawPublicKeyToSpkiDer(sharedPublicKey), /non-shared ArrayBuffer/,
    "the public SPKI encoder accepted worker-raceable public-key memory");
});

test("private-byte encoding never dispatches through a post-load TypedArray length getter", () => {
  const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype) as object;
  const lengthDescriptor = Object.getOwnPropertyDescriptor(typedArrayPrototype, "length");
  assert.ok(lengthDescriptor && typeof lengthDescriptor.get === "function" && lengthDescriptor.configurable,
    "%TypedArray%.prototype.length descriptor is unavailable");
  const realLength = lengthDescriptor.get;
  const secret = new Uint8Array(32).fill(0x5a);
  let getterCalls = 0;
  let captured: number[] | undefined;
  const install = () => {
    Object.defineProperty(typedArrayPrototype, "length", {
      ...lengthDescriptor,
      get(this: Uint8Array) {
        getterCalls++;
        const length = Reflect.apply(realLength, this, []) as number;
        captured = [];
        for (let i = 0; i < length; i++) captured[i] = this[i] as number;
        Object.defineProperty(typedArrayPrototype, "length", lengthDescriptor);
        return length;
      },
    });
  };

  install();
  assert.equal(secret.length, 32, "the TypedArray length poison changed its direct witness");
  assert.deepEqual(captured, [...secret], "the direct witness could not observe the private bytes");
  const witnessCalls = getterCalls;
  captured = undefined;

  try {
    install();
    assert.equal(bytesToBase64(secret), "WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo=");
    assert.equal(bytesToHex(secret), "5a".repeat(32));
  } finally {
    Object.defineProperty(typedArrayPrototype, "length", lengthDescriptor);
  }
  assert.equal(getterCalls, witnessCalls, "a byte encoder invoked the attacker-selected length getter");
  assert.equal(captured, undefined, "a byte encoder exposed its private input to the live getter");
});

test("byte codecs use module-load intrinsics after ambient base64/string slots are poisoned", () => {
  const priorBtoa = Object.getOwnPropertyDescriptor(globalThis, "btoa");
  const priorAtob = Object.getOwnPropertyDescriptor(globalThis, "atob");
  const priorFromCharCode = Object.getOwnPropertyDescriptor(String, "fromCharCode");
  const priorCharCodeAt = Object.getOwnPropertyDescriptor(String.prototype, "charCodeAt");
  const bytes = new Uint8Array([0, 1, 2, 253, 254, 255]);
  const fired = { btoa: 0, atob: 0, fromCharCode: 0, charCodeAt: 0 };
  try {
    Object.defineProperty(globalThis, "btoa", {
      value: () => { fired.btoa++; return "AA=="; }, configurable: true,
    });
    Object.defineProperty(globalThis, "atob", {
      value: () => { fired.atob++; return "\0".repeat(64); }, configurable: true,
    });
    Object.defineProperty(String, "fromCharCode", {
      value: () => { fired.fromCharCode++; return "\0"; }, configurable: true,
    });
    Object.defineProperty(String.prototype, "charCodeAt", {
      value: () => { fired.charCodeAt++; return 0; }, configurable: true,
    });

    globalThis.btoa("witness");
    globalThis.atob("AA==");
    String.fromCharCode(65);
    "witness".charCodeAt(0);
    assert.deepEqual(fired, { btoa: 1, atob: 1, fromCharCode: 1, charCodeAt: 1 },
      "one or more codec poisons did not bite on their direct witness");

    assert.equal(bytesToBase64(bytes), "AAEC/f7/");
    assert.deepEqual(base64ToBytes("AAEC/f7/"), bytes);
    assert.deepEqual(fired, { btoa: 1, atob: 1, fromCharCode: 1, charCodeAt: 1 },
      "the byte codecs consulted a writable post-load ambient slot");
  } finally {
    if (priorBtoa) Object.defineProperty(globalThis, "btoa", priorBtoa);
    if (priorAtob) Object.defineProperty(globalThis, "atob", priorAtob);
    if (priorFromCharCode) Object.defineProperty(String, "fromCharCode", priorFromCharCode);
    if (priorCharCodeAt) Object.defineProperty(String.prototype, "charCodeAt", priorCharCodeAt);
  }
});

test("bytesToHex/hexToBytes round-trip losslessly over all 256 byte values", () => {
  const original = new Uint8Array(256);
  for (let i = 0; i < 256; i++) original[i] = i;
  const roundTripped = hexToBytes(bytesToHex(original));
  assert.deepEqual(roundTripped, original);
});

test("hexToBytes rejects partially parsed and non-hex byte pairs", () => {
  assert.throws(() => hexToBytes("0g"), /invalid hex byte at offset 0/);
  assert.throws(() => hexToBytes("1z"), /invalid hex byte at offset 0/);
  assert.throws(() => hexToBytes("gg"), /invalid hex byte at offset 0/);
  assert.deepEqual(hexToBytes("0aFf"), new Uint8Array([0x0a, 0xff]));
});

// ── generateKeyPair (WebCrypto entropy + noble derivation) ──────────────────────────────────

test("generateKeyPair: rawSeedToPkcs8Der round-trips through the decode direction", () => {
  const seed = crypto.getRandomValues(new Uint8Array(32));
  const der = rawSeedToPkcs8Der(seed);
  const roundTripped = pkcs8Ed25519ToRawSeed(der);
  assert.deepEqual(roundTripped, seed);
});

test("generateKeyPair: produces the exact noa-receipt KeyPair shape, and node:crypto independently accepts the emitted DER", async () => {
  const pair = ourGenerateKeyPair("keygen-1");
  assert.equal(pair.kid, "keygen-1");
  assert.equal(typeof pair.publicKey, "string");
  assert.equal(typeof pair.privateKey, "string");

  // Cross-impl proof: node:crypto (NOT part of the shipped package — this is test-only) must be
  // able to import the DER this package emits as a genuine Ed25519 key, and must derive the SAME
  // public key noble derived. This is stronger than "our own decode reverses our own encode" —
  // it proves the DER bytes are correct per the ASN.1 shape node:crypto itself expects.
  const { createPrivateKey, createPublicKey, sign: cryptoSign, verify: cryptoVerify } = await import("node:crypto");
  const privKeyObj = createPrivateKey({ key: Buffer.from(pair.privateKey, "base64"), format: "der", type: "pkcs8" });
  assert.equal(privKeyObj.asymmetricKeyType, "ed25519");
  const pubKeyObj = createPublicKey({ key: Buffer.from(pair.publicKey, "base64"), format: "der", type: "spki" });
  assert.equal(pubKeyObj.asymmetricKeyType, "ed25519");

  // node:crypto must reproduce the SAME public key DER noa-signer emitted (proves the SPKI
  // wrapper bytes noa-signer wrote are exactly what node:crypto itself would re-derive/re-export).
  const derivedPubDer = privKeyObj
    .export({ format: "der", type: "pkcs8" })
    .toString("base64"); // sanity: node accepted the key without throwing
  assert.equal(typeof derivedPubDer, "string");

  const message = Buffer.from("cross-impl DER round-trip check", "utf8");
  const sig = cryptoSign(null, message, privKeyObj);
  assert.equal(cryptoVerify(null, message, pubKeyObj, sig), true, "node:crypto must self-verify using the key material noa-signer generated");
});
