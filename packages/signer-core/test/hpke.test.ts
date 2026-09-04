/**
 * HPKE (RFC 9180 base mode) correctness + the encrypted-display seal/open round-trip.
 *
 * The load-bearing proof is G3-style: `hpkeSealBase`/`hpkeOpenBase` reproduce RFC 9180 Appendix A.2.1
 * (DHKEM(X25519,HKDF-SHA256) / HKDF-SHA256 / ChaCha20Poly1305) byte-exact — enc, shared-secret-derived
 * key/nonce, and ciphertext all match the published vector. That anchors the primitive to the
 * standard, not to our own re-derivation. On top of it: display seal→open round-trips, and every
 * tamper (wrong key, flipped ciphertext byte, swapped tenant/recipient) fails CLOSED.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { x25519 } from "@noble/curves/ed25519.js";
import { ScalarMultiplier } from "@noble/curves/abstract/curve.js";
import { Poly1305, poly1305 } from "@noble/ciphers/_poly1305.js";
import { SHA256_IV } from "@noble/hashes/_md.js";
import { _HMAC, hmac } from "@noble/hashes/hmac.js";
import { _SHA256, sha256 } from "@noble/hashes/sha2.js";
import {
  hpkeSealBase,
  hpkeOpenBase,
  sealEncryptedDisplay,
  openEncryptedDisplay,
  decodeX25519PublicKey,
  HPKE_SUITE,
} from "../src/index.js";
import { hexToBytes, bytesToHex, bytesToBase64, base64ToBytes } from "../src/bytes.js";
import { canonicalize } from "../src/jcs.js";
import { sha256Prefixed } from "../src/hash.js";
import { RFC9180_A2_1 as A21 } from "./fixtures/rfc9180-a2-1.js";

// ── RFC 9180 Appendix A.2.1 (mode_base, sequence 0) vector ────────────────────────────────────────────────────

test("hpkeSealBase reproduces RFC 9180 A.2.1 byte-exact (enc + ciphertext)", () => {
  const out = hpkeSealBase({
    recipientPublicKey: hexToBytes(A21.pkRm),
    info: hexToBytes(A21.info),
    aad: hexToBytes(A21.aad),
    plaintext: hexToBytes(A21.plaintext),
    ephemeralSecretKey: hexToBytes(A21.skEm),
  });
  assert.equal(bytesToHex(out.enc), A21.pkEm, "enc must equal the vector pkEm");
  assert.equal(bytesToHex(out.ciphertext), A21.ciphertext, "ciphertext must equal the vector ct");
});

test("HPKE preserves byte-view compatibility without accepting non-byte, shared, or detached views", () => {
  const sealed = hpkeSealBase({
    recipientPublicKey: Buffer.from(A21.pkRm, "hex"),
    info: Buffer.from(A21.info, "hex"),
    aad: Buffer.from(A21.aad, "hex"),
    plaintext: Buffer.from(A21.plaintext, "hex"),
    ephemeralSecretKey: Buffer.from(A21.skEm, "hex"),
  });
  assert.equal(bytesToHex(sealed.enc), A21.pkEm, "Buffer input changed the RFC encapsulated key");
  assert.equal(bytesToHex(sealed.ciphertext), A21.ciphertext, "Buffer input changed the RFC ciphertext");
  const opened = hpkeOpenBase({
    recipientSecretKey: Buffer.from(A21.skRm, "hex"),
    enc: Buffer.from(A21.pkEm, "hex"),
    info: Buffer.from(A21.info, "hex"),
    aad: Buffer.from(A21.aad, "hex"),
    ciphertext: Buffer.from(A21.ciphertext, "hex"),
  });
  assert.equal(bytesToHex(opened), A21.plaintext, "Buffer input changed the RFC plaintext");

  assert.throws(
    () => hpkeSealBase({
      recipientPublicKey: new Int8Array(32) as unknown as Uint8Array,
      plaintext: new Uint8Array(),
    }),
    /expected a Uint8Array/,
    "a different typed-array brand was accepted as bytes",
  );
  const sharedKey = new Uint8Array(new SharedArrayBuffer(32));
  assert.throws(
    () => hpkeSealBase({ recipientPublicKey: sharedKey, plaintext: new Uint8Array() }),
    /expected a Uint8Array backed by a non-shared ArrayBuffer/,
    "shared memory was accepted as an immutable byte snapshot",
  );

  const detachedPlaintext = new Uint8Array([0x41, 0x42, 0x43]);
  structuredClone(detachedPlaintext.buffer, { transfer: [detachedPlaintext.buffer] });
  assert.equal(detachedPlaintext.length, 0, "the detached-input witness did not bite");
  assert.throws(
    () => hpkeSealBase({
      recipientPublicKey: hexToBytes(A21.pkRm),
      plaintext: detachedPlaintext,
      ephemeralSecretKey: hexToBytes(A21.skEm),
    }),
    /non-shared ArrayBuffer that is still attached/,
    "a detached non-empty plaintext was silently reinterpreted as an authentic empty plaintext",
  );

  const callerBuffer = new ArrayBuffer(3);
  const callerPlaintext = new Uint8Array(callerBuffer);
  callerPlaintext[0] = 0x41;
  callerPlaintext[1] = 0x42;
  callerPlaintext[2] = 0x43;
  let constructorReads = 0;
  Object.defineProperty(callerBuffer, "constructor", {
    configurable: true,
    get() {
      constructorReads++;
      throw new Error("caller-controlled ArrayBuffer constructor was invoked");
    },
  });
  const noSpeciesDispatch = hpkeSealBase({
    recipientPublicKey: hexToBytes(A21.pkRm),
    plaintext: callerPlaintext,
    ephemeralSecretKey: hexToBytes(A21.skEm),
  });
  assert.equal(noSpeciesDispatch.ciphertext.length, 19, "the attached caller buffer changed length");
  assert.equal(constructorReads, 0, "the attachment check invoked caller constructor/@@species code");
});

test("HPKE labeled extract never exposes raw DH through Array.prototype iteration", () => {
  const prior = Object.getOwnPropertyDescriptor(Array.prototype, Symbol.iterator);
  assert.ok(prior && typeof prior.value === "function", "Array.prototype iterator is unavailable");
  const realIterator = prior.value as (this: unknown[]) => Iterator<unknown>;
  let poisonCalls = 0;
  let sawRawDhLabeledExtract = false;
  let caught: unknown;

  function matchesAscii(value: unknown, ascii: string): boolean {
    if (!(value instanceof Uint8Array) || value.length !== ascii.length) return false;
    for (let i = 0; i < ascii.length; i++) {
      if (value[i] !== ascii.charCodeAt(i)) return false;
    }
    return true;
  }

  function* poisonedIterator(this: unknown[]): Generator<unknown> {
    poisonCalls++;
    if (
      this.length === 4 &&
      matchesAscii(this[0], "HPKE-v1") &&
      this[1] instanceof Uint8Array && this[1].length === 5 &&
      matchesAscii(this[2], "eae_prk") &&
      this[3] instanceof Uint8Array && this[3].length === 32
    ) {
      sawRawDhLabeledExtract = true;
    }
    const iterator = Reflect.apply(realIterator, this, []) as Iterator<unknown>;
    for (;;) {
      const item = iterator.next();
      if (item.done) return;
      yield item.value;
    }
  }

  Object.defineProperty(Array.prototype, Symbol.iterator, {
    value: poisonedIterator,
    writable: true,
    configurable: true,
  });
  try {
    const witness = ["iterator-poison-witness"];
    const witnessIterator = witness[Symbol.iterator]();
    assert.equal(witnessIterator.next().value, "iterator-poison-witness");
    try {
      hpkeSealBase({
        recipientPublicKey: hexToBytes(A21.pkRm),
        info: hexToBytes(A21.info),
        aad: hexToBytes(A21.aad),
        plaintext: hexToBytes(A21.plaintext),
        ephemeralSecretKey: hexToBytes(A21.skEm),
      });
    } catch (error) {
      caught = error;
    }
  } finally {
    Object.defineProperty(Array.prototype, Symbol.iterator, prior);
  }

  assert.ok(poisonCalls > 0, "the Array iterator poison did not bite on its direct witness");
  assert.equal(sawRawDhLabeledExtract, false, "raw X25519 DH entered an attacker-controlled Array iterator");
  assert.match(String(caught), /runtime intrinsic integrity check failed/,
    "HPKE continued in a realm whose Array iterator changed after module load");
});

test("HPKE refuses a post-load ArrayIterator.next hook before derived AEAD secrets exist", () => {
  const iteratorPrototype = Object.getPrototypeOf([][Symbol.iterator]());
  const prior = Object.getOwnPropertyDescriptor(iteratorPrototype, "next");
  assert.ok(prior && typeof prior.value === "function", "%ArrayIteratorPrototype%.next is unavailable");
  const realNext = prior.value as (this: Iterator<unknown>) => IteratorResult<unknown>;
  const expectedKey = hexToBytes("ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91");
  const expectedBaseNonce = hexToBytes("5c4d98150661b848853b547f");
  let poisonCalls = 0;
  let sawDerivedSecret = false;
  let sealCaught: unknown;
  let openCaught: unknown;

  function equalsExpected(value: unknown, expected: Uint8Array): boolean {
    if (!(value instanceof Uint8Array) || value.length !== expected.length) return false;
    for (let i = 0; i < expected.length; i++) {
      if (value[i] !== expected[i]) return false;
    }
    return true;
  }

  Object.defineProperty(iteratorPrototype, "next", {
    ...prior,
    value: function poisonedArrayIteratorNext(this: Iterator<unknown>): IteratorResult<unknown> {
      poisonCalls++;
      const item = Reflect.apply(realNext, this, []) as IteratorResult<unknown>;
      if (!item.done && (
        equalsExpected(item.value, expectedKey)
        || equalsExpected(item.value, expectedBaseNonce)
      )) {
        sawDerivedSecret = true;
      }
      return item;
    },
  });
  try {
    const witness = ["iterator-next-poison-witness"][Symbol.iterator]();
    assert.equal(witness.next().value, "iterator-next-poison-witness");
    try {
      hpkeSealBase({
        recipientPublicKey: hexToBytes(A21.pkRm),
        info: hexToBytes(A21.info),
        aad: hexToBytes(A21.aad),
        plaintext: hexToBytes(A21.plaintext),
        ephemeralSecretKey: hexToBytes(A21.skEm),
      });
    } catch (error) {
      sealCaught = error;
    }
    try {
      hpkeOpenBase({
        recipientSecretKey: hexToBytes(A21.skRm),
        enc: hexToBytes(A21.pkEm),
        info: hexToBytes(A21.info),
        aad: hexToBytes(A21.aad),
        ciphertext: hexToBytes(A21.ciphertext),
      });
    } catch (error) {
      openCaught = error;
    }
  } finally {
    Object.defineProperty(iteratorPrototype, "next", prior);
  }

  assert.ok(poisonCalls > 0, "the ArrayIterator.next poison did not bite on its direct witness");
  assert.equal(sawDerivedSecret, false, "a derived AEAD key or base nonce entered ArrayIterator.next");
  assert.match(String(sealCaught), /runtime intrinsic integrity check failed/,
    "HPKE seal continued after ArrayIterator.next changed post-load");
  assert.match(String(openCaught), /runtime intrinsic integrity check failed/,
    "HPKE open continued after ArrayIterator.next changed post-load");

  const sealed = hpkeSealBase({
    recipientPublicKey: hexToBytes(A21.pkRm),
    info: hexToBytes(A21.info),
    aad: hexToBytes(A21.aad),
    plaintext: hexToBytes(A21.plaintext),
    ephemeralSecretKey: hexToBytes(A21.skEm),
  });
  assert.equal(bytesToHex(sealed.enc), A21.pkEm, "clean seal drifted from the RFC encapsulated key");
  assert.equal(bytesToHex(sealed.ciphertext), A21.ciphertext, "clean seal drifted from the RFC ciphertext");
  const opened = hpkeOpenBase({
    recipientSecretKey: hexToBytes(A21.skRm),
    enc: hexToBytes(A21.pkEm),
    info: hexToBytes(A21.info),
    aad: hexToBytes(A21.aad),
    ciphertext: hexToBytes(A21.ciphertext),
  });
  assert.equal(bytesToHex(opened), A21.plaintext, "clean open drifted from the RFC plaintext");
});

test("HPKE refuses a post-load TypedArray length getter before raw DH exists", () => {
  const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
  const prior = Object.getOwnPropertyDescriptor(typedArrayPrototype, "length");
  assert.ok(prior && typeof prior.get === "function", "%TypedArray%.prototype.length getter is unavailable");
  const realLength = prior.get;
  const expectedDh = x25519.getSharedSecret(hexToBytes(A21.skEm), hexToBytes(A21.pkRm));
  let poisonCalls = 0;
  let sawRawDh = false;
  let caught: unknown;

  Object.defineProperty(typedArrayPrototype, "length", {
    get: function poisonedTypedArrayLength(this: Uint8Array) {
      poisonCalls++;
      let equal = true;
      for (let i = 0; i < 32; i++) {
        if (this[i] !== expectedDh[i]) {
          equal = false;
          break;
        }
      }
      if (equal) sawRawDh = true;
      return Reflect.apply(realLength, this, []) as number;
    },
    configurable: prior.configurable,
    enumerable: prior.enumerable,
  });
  try {
    assert.equal(new Uint8Array([1]).length, 1, "the poisoned length getter changed its direct witness");
    try {
      hpkeSealBase({
        recipientPublicKey: hexToBytes(A21.pkRm),
        info: hexToBytes(A21.info),
        aad: hexToBytes(A21.aad),
        plaintext: hexToBytes(A21.plaintext),
        ephemeralSecretKey: hexToBytes(A21.skEm),
      });
    } catch (error) {
      caught = error;
    }
  } finally {
    Object.defineProperty(typedArrayPrototype, "length", prior);
  }

  assert.ok(poisonCalls > 0, "the TypedArray length poison did not bite on its direct witness");
  assert.equal(sawRawDh, false, "a post-load TypedArray length getter observed the raw X25519 DH");
  assert.match(String(caught), /runtime intrinsic integrity check failed/,
    "HPKE continued in a realm whose TypedArray length getter changed after module load");
});

test("HPKE refuses an inherited ephemeral test scalar without invoking its getter", () => {
  const prior = Object.getOwnPropertyDescriptor(Object.prototype, "ephemeralSecretKey");
  let getterCalls = 0;
  let caught: unknown;
  Object.defineProperty(Object.prototype, "ephemeralSecretKey", {
    configurable: true,
    get() {
      getterCalls++;
      return hexToBytes(A21.skEm);
    },
  });
  try {
    assert.deepEqual(({} as { ephemeralSecretKey?: Uint8Array }).ephemeralSecretKey, hexToBytes(A21.skEm),
      "the inherited getter did not bite on its direct witness");
    try {
      hpkeSealBase({
        recipientPublicKey: hexToBytes(A21.pkRm),
        info: hexToBytes(A21.info),
        aad: hexToBytes(A21.aad),
        plaintext: hexToBytes(A21.plaintext),
      });
    } catch (error) {
      caught = error;
    }
  } finally {
    if (prior === undefined) Reflect.deleteProperty(Object.prototype, "ephemeralSecretKey");
    else Object.defineProperty(Object.prototype, "ephemeralSecretKey", prior);
  }

  assert.equal(getterCalls, 1, "HPKE invoked the inherited ephemeralSecretKey getter after its direct witness");
  assert.match(String(caught), /runtime intrinsic integrity check failed: Object\.prototype/);
});

test("HPKE rejects an own accessor before it can open a post-check TOCTOU window", () => {
  const input: Record<string, unknown> = {
    recipientPublicKey: hexToBytes(A21.pkRm),
    info: hexToBytes(A21.info),
    aad: hexToBytes(A21.aad),
    plaintext: hexToBytes(A21.plaintext),
  };
  let getterCalls = 0;
  Object.defineProperty(input, "ephemeralSecretKey", {
    configurable: true,
    get() {
      getterCalls++;
      return hexToBytes(A21.skEm);
    },
  });
  assert.throws(
    () => hpkeSealBase(input as unknown as Parameters<typeof hpkeSealBase>[0]),
    /ephemeralSecretKey must be an own data property/,
  );
  assert.equal(getterCalls, 0, "the rejected input accessor executed");
});

test("HPKE refuses live TypedArray from/set/subarray hooks before any crypto bytes reach them", () => {
  const typedArrayConstructor = Object.getPrototypeOf(Uint8Array);
  const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
  const cases: Array<{
    target: object;
    key: string;
    witness: () => void;
    poison: (real: (...args: unknown[]) => unknown, increment: () => void) => (...args: unknown[]) => unknown;
  }> = [
    {
      target: typedArrayConstructor,
      key: "from",
      witness: () => { void Uint8Array.from([1]); },
      poison: (real, increment) => function (this: unknown, ...args: unknown[]) {
        increment();
        return Reflect.apply(real, this, args);
      },
    },
    {
      target: typedArrayPrototype,
      key: "set",
      witness: () => { new Uint8Array(1).set(new Uint8Array([1])); },
      poison: (real, increment) => function (this: unknown, ...args: unknown[]) {
        increment();
        return Reflect.apply(real, this, args);
      },
    },
    {
      target: typedArrayPrototype,
      key: "subarray",
      witness: () => { void new Uint8Array([1]).subarray(0); },
      poison: (real, increment) => function (this: unknown, ...args: unknown[]) {
        increment();
        return Reflect.apply(real, this, args);
      },
    },
  ];

  for (const attack of cases) {
    const prior = Object.getOwnPropertyDescriptor(attack.target, attack.key);
    assert.ok(prior && typeof prior.value === "function", `${attack.key} descriptor is unavailable`);
    let poisonCalls = 0;
    let caught: unknown;
    Object.defineProperty(attack.target, attack.key, {
      ...prior,
      value: attack.poison(prior.value as (...args: unknown[]) => unknown, () => { poisonCalls++; }),
    });
    try {
      attack.witness();
      try {
        hpkeSealBase({
          recipientPublicKey: hexToBytes(A21.pkRm),
          info: hexToBytes(A21.info),
          aad: hexToBytes(A21.aad),
          plaintext: hexToBytes(A21.plaintext),
          ephemeralSecretKey: hexToBytes(A21.skEm),
        });
      } catch (error) {
        caught = error;
      }
    } finally {
      Object.defineProperty(attack.target, attack.key, prior);
    }
    assert.equal(poisonCalls, 1, `${attack.key} received crypto material after its direct witness`);
    assert.match(String(caught), /runtime intrinsic integrity check failed/,
      `HPKE continued after ${attack.key} changed`);
  }
});

test("HPKE refuses live scalar, string, object, math, number, and set intrinsics before crypto", () => {
  const attacks: Array<{
    target: object;
    key: PropertyKey;
    witness: () => void;
  }> = [
    { target: globalThis, key: "BigInt", witness: () => { void BigInt(1); } },
    { target: BigInt.prototype, key: "toString", witness: () => { void (1n).toString(16); } },
    { target: String.prototype, key: "padStart", witness: () => { void "1".padStart(2, "0"); } },
    { target: Object, key: "getPrototypeOf", witness: () => { void Object.getPrototypeOf({}); } },
    { target: Math, key: "min", witness: () => { void Math.min(1, 2); } },
    { target: Number, key: "isSafeInteger", witness: () => { void Number.isSafeInteger(1); } },
    { target: Set.prototype, key: "has", witness: () => { void new Set([1]).has(1); } },
  ];

  for (const attack of attacks) {
    const prior = Object.getOwnPropertyDescriptor(attack.target, attack.key);
    assert.ok(prior && typeof prior.value === "function", `${String(attack.key)} descriptor is unavailable`);
    const real = prior.value as (...args: unknown[]) => unknown;
    let poisonCalls = 0;
    let caught: unknown;
    Object.defineProperty(attack.target, attack.key, {
      ...prior,
      value: function poisonedIntrinsic(this: unknown, ...args: unknown[]) {
        poisonCalls++;
        return Reflect.apply(real, this, args);
      },
    });
    try {
      attack.witness();
      try {
        hpkeSealBase({
          recipientPublicKey: hexToBytes(A21.pkRm),
          info: hexToBytes(A21.info),
          aad: hexToBytes(A21.aad),
          plaintext: hexToBytes(A21.plaintext),
          ephemeralSecretKey: hexToBytes(A21.skEm),
        });
      } catch (error) {
        caught = error;
      }
    } finally {
      Object.defineProperty(attack.target, attack.key, prior);
    }
    assert.equal(poisonCalls, 1, `${String(attack.key)} received secret-bearing crypto material`);
    assert.match(String(caught), /runtime intrinsic integrity check failed/,
      `HPKE continued after ${String(attack.key)} changed`);
  }
});

test("HPKE integrity comparison never invokes an inherited descriptor-field getter", () => {
  const prior = Object.getOwnPropertyDescriptor(Object.prototype, "value");
  let getterCalls = 0;
  let caught: unknown;
  Object.defineProperty(Object.prototype, "value", {
    configurable: true,
    get() {
      getterCalls++;
      return undefined;
    },
  });
  try {
    void ({} as { value?: unknown }).value;
    try {
      hpkeSealBase({
        recipientPublicKey: hexToBytes(A21.pkRm),
        info: hexToBytes(A21.info),
        aad: hexToBytes(A21.aad),
        plaintext: hexToBytes(A21.plaintext),
        ephemeralSecretKey: hexToBytes(A21.skEm),
      });
    } catch (error) {
      caught = error;
    }
  } finally {
    if (prior === undefined) Reflect.deleteProperty(Object.prototype, "value");
    else Object.defineProperty(Object.prototype, "value", prior);
  }
  assert.equal(getterCalls, 1, "integrity comparison invoked an inherited Object.prototype getter");
  assert.match(String(caught), /runtime intrinsic integrity check failed: Object\.prototype/);
});

test("HPKE refuses mutable dependency prototypes and wrapper hooks before secret use", () => {
  const sha256ParentPrototype = Object.getPrototypeOf(_SHA256.prototype) as object;
  const attacks: Array<{
    target: object;
    key: PropertyKey;
    witness: () => void;
  }> = [
    {
      target: WeakMap.prototype,
      key: "get",
      witness: () => {
        const key = {};
        void new WeakMap([[key, 1]]).get(key);
      },
    },
    {
      target: sha256ParentPrototype,
      key: "process",
      witness: () => { void sha256(new Uint8Array(64)); },
    },
    {
      target: hmac,
      key: "create",
      witness: () => { hmac.create(sha256, new Uint8Array(32)).destroy(); },
    },
    {
      target: _HMAC.prototype,
      key: "update",
      witness: () => { new _HMAC(sha256, new Uint8Array(32)).update(new Uint8Array()).destroy(); },
    },
    {
      target: poly1305,
      key: "create",
      witness: () => { poly1305.create(new Uint8Array(32)).destroy(); },
    },
    {
      target: Poly1305.prototype,
      key: "update",
      witness: () => { new Poly1305(new Uint8Array(32)).update(new Uint8Array()).destroy(); },
    },
  ];

  for (const attack of attacks) {
    const prior = Object.getOwnPropertyDescriptor(attack.target, attack.key);
    assert.ok(prior && typeof prior.value === "function", `${String(attack.key)} descriptor is unavailable`);
    const real = prior.value as (...args: unknown[]) => unknown;
    let poisonCalls = 0;
    let caught: unknown;
    Object.defineProperty(attack.target, attack.key, {
      ...prior,
      value: function poisonedDependencyHook(this: unknown, ...args: unknown[]) {
        poisonCalls++;
        return Reflect.apply(real, this, args);
      },
    });
    let witnessCalls = 0;
    try {
      attack.witness();
      witnessCalls = poisonCalls;
      try {
        hpkeSealBase({
          recipientPublicKey: hexToBytes(A21.pkRm),
          info: hexToBytes(A21.info),
          aad: hexToBytes(A21.aad),
          plaintext: hexToBytes(A21.plaintext),
          ephemeralSecretKey: hexToBytes(A21.skEm),
        });
      } catch (error) {
        caught = error;
      }
    } finally {
      Object.defineProperty(attack.target, attack.key, prior);
    }
    assert.ok(witnessCalls > 0, `${String(attack.key)} poison did not bite on its direct witness`);
    assert.equal(poisonCalls, witnessCalls, `${String(attack.key)} received secret-bearing crypto material`);
    assert.match(String(caught), /runtime intrinsic integrity check failed/,
      `HPKE continued after dependency hook ${String(attack.key)} changed`);
  }
});

test("HPKE refuses a dependency prototype-chain replacement before inherited crypto methods run", () => {
  const originalParent = Object.getPrototypeOf(_SHA256.prototype) as object;
  const replacementParent = Object.create(originalParent) as Record<PropertyKey, unknown>;
  const originalProcess = (originalParent as Record<PropertyKey, unknown>).process as (...args: unknown[]) => unknown;
  let poisonCalls = 0;
  let caught: unknown;
  Object.defineProperty(replacementParent, "process", {
    configurable: true,
    value: function poisonedHashProcess(this: unknown, ...args: unknown[]) {
      poisonCalls++;
      return Reflect.apply(originalProcess, this, args);
    },
  });
  Object.setPrototypeOf(_SHA256.prototype, replacementParent);
  let witnessCalls = 0;
  try {
    void sha256(new Uint8Array(64));
    witnessCalls = poisonCalls;
    try {
      hpkeSealBase({
        recipientPublicKey: hexToBytes(A21.pkRm),
        info: hexToBytes(A21.info),
        aad: hexToBytes(A21.aad),
        plaintext: hexToBytes(A21.plaintext),
        ephemeralSecretKey: hexToBytes(A21.skEm),
      });
    } catch (error) {
      caught = error;
    }
  } finally {
    Object.setPrototypeOf(_SHA256.prototype, originalParent);
  }
  assert.ok(witnessCalls > 0, "replacement SHA-256 prototype did not bite on its direct witness");
  assert.equal(poisonCalls, witnessCalls, "replacement SHA-256 prototype received secret-bearing hash state");
  assert.match(String(caught), /runtime intrinsic integrity check failed: @noble\/hashes\._SHA256\.prototype-chain/);
});

test("HPKE refuses self-restoring SHA-256 constructor-chain traps before raw DH reaches HMAC", () => {
  const updateDescriptor = Object.getOwnPropertyDescriptor(_HMAC.prototype, "update");
  assert.ok(updateDescriptor && typeof updateDescriptor.value === "function", "_HMAC.update descriptor is unavailable");
  const realUpdate = updateDescriptor.value as (...args: unknown[]) => unknown;
  const sha256BaseConstructor = Object.getPrototypeOf(_SHA256) as object;
  const constructorLinks = [
    { label: "derived", target: _SHA256 as object, expectedDepth: 0 },
    { label: "base", target: sha256BaseConstructor, expectedDepth: 1 },
  ] as const;
  const operations = [
    {
      label: "seal",
      rawDh: x25519.scalarMult(hexToBytes(A21.skEm), hexToBytes(A21.pkRm)),
      run: () => hpkeSealBase({
        recipientPublicKey: hexToBytes(A21.pkRm),
        info: hexToBytes(A21.info),
        aad: hexToBytes(A21.aad),
        plaintext: hexToBytes(A21.plaintext),
        ephemeralSecretKey: hexToBytes(A21.skEm),
      }),
    },
    {
      label: "open",
      rawDh: x25519.scalarMult(hexToBytes(A21.skRm), hexToBytes(A21.pkEm)),
      run: () => hpkeOpenBase({
        recipientSecretKey: hexToBytes(A21.skRm),
        enc: hexToBytes(A21.pkEm),
        info: hexToBytes(A21.info),
        aad: hexToBytes(A21.aad),
        ciphertext: hexToBytes(A21.ciphertext),
      }),
    },
  ] as const;

  for (const operation of operations) {
    for (const link of constructorLinks) {
      const originalParent = Object.getPrototypeOf(link.target) as new (...args: unknown[]) => object;
      let constructCalls = 0;
      let hmacCalls = 0;
      let sawRawDh = false;
      const installHmacHook = () => {
        Object.defineProperty(_HMAC.prototype, "update", {
          ...updateDescriptor,
          value: function poisonedHmacUpdate(this: unknown, ...args: unknown[]) {
            hmacCalls++;
            const bytes = args[0];
            if (bytes instanceof Uint8Array && bytes.length >= operation.rawDh.length) {
              let equal = true;
              const offset = bytes.length - operation.rawDh.length;
              for (let i = 0; i < operation.rawDh.length; i++) {
                if (bytes[offset + i] !== operation.rawDh[i]) {
                  equal = false;
                  break;
                }
              }
              if (equal) sawRawDh = true;
            }
            return Reflect.apply(realUpdate, this, args);
          },
        });
      };
      const replacementParent = new Proxy(originalParent, {
        construct(target, args, newTarget) {
          constructCalls++;
          Object.setPrototypeOf(link.target, originalParent);
          installHmacHook();
          return Reflect.construct(target, args, newTarget);
        },
      });

      let witnessConstructCalls = 0;
      let witnessHmacCalls = 0;
      let caught: unknown;
      try {
        Object.setPrototypeOf(link.target, replacementParent);
        new _SHA256().destroy();
        witnessConstructCalls = constructCalls;
        new _HMAC(sha256, new Uint8Array(32)).update(new Uint8Array([1])).destroy();
        witnessHmacCalls = hmacCalls;
        Object.defineProperty(_HMAC.prototype, "update", updateDescriptor);

        Object.setPrototypeOf(link.target, replacementParent);
        try {
          operation.run();
        } catch (error) {
          caught = error;
        }
      } finally {
        Object.setPrototypeOf(link.target, originalParent);
        Object.defineProperty(_HMAC.prototype, "update", updateDescriptor);
      }

      assert.equal(witnessConstructCalls, 1, `${operation.label}/${link.label}: construct trap witness did not bite`);
      assert.ok(witnessHmacCalls > 0, `${operation.label}/${link.label}: installed HMAC hook witness did not bite`);
      assert.equal(constructCalls, witnessConstructCalls,
        `${operation.label}/${link.label}: self-restoring construct trap ran after the final integrity fence`);
      assert.equal(hmacCalls, witnessHmacCalls,
        `${operation.label}/${link.label}: construct trap installed a secret-bearing HMAC hook`);
      assert.equal(sawRawDh, false, `${operation.label}/${link.label}: construct trap exposed raw X25519 DH`);
      assert.match(
        String(caught),
        new RegExp(`runtime intrinsic integrity check failed: @noble/hashes\\._SHA256\\.constructor-chain\\[${link.expectedDepth}\\]`),
        `${operation.label}/${link.label}: HPKE continued with a changed SHA-256 constructor link`,
      );
    }
  }
});

test("HPKE refuses post-load SHA-256 IV drift under the fixed suite identifier", () => {
  const originalWord = SHA256_IV[0] as number;
  const changedWord = (originalWord ^ 1) >>> 0;
  const cleanDigest = bytesToHex(sha256(new Uint8Array()));
  let changedDigest: string;
  try {
    SHA256_IV[0] = changedWord;
    changedDigest = bytesToHex(sha256(new Uint8Array()));
  } finally {
    SHA256_IV[0] = originalWord;
  }
  assert.equal(
    changedDigest,
    cleanDigest,
    "the exact dependency hardening still let an exported IV table change the SHA-256 algorithm",
  );

  const operations = [
    {
      label: "seal",
      run: () => hpkeSealBase({
        recipientPublicKey: hexToBytes(A21.pkRm),
        info: hexToBytes(A21.info),
        aad: hexToBytes(A21.aad),
        plaintext: hexToBytes(A21.plaintext),
        ephemeralSecretKey: hexToBytes(A21.skEm),
      }),
    },
    {
      label: "open",
      run: () => hpkeOpenBase({
        recipientSecretKey: hexToBytes(A21.skRm),
        enc: hexToBytes(A21.pkEm),
        info: hexToBytes(A21.info),
        aad: hexToBytes(A21.aad),
        ciphertext: hexToBytes(A21.ciphertext),
      }),
    },
  ] as const;

  for (const operation of operations) {
    let caught: unknown;
    try {
      SHA256_IV[0] = changedWord;
      try {
        operation.run();
      } catch (error) {
        caught = error;
      }
    } finally {
      SHA256_IV[0] = originalWord;
    }
    assert.match(
      String(caught),
      /runtime intrinsic integrity check failed: @noble\/hashes\.SHA256_IV/,
      `${operation.label}: HPKE continued under a mutated SHA-256 initialization vector`,
    );
  }
});

test("HPKE keeps fixed-base ScalarMultiplier hooks outside both seal and open", () => {
  const operations = [
    {
      label: "seal",
      expected: A21.ciphertext,
      run: () => bytesToHex(hpkeSealBase({
          recipientPublicKey: hexToBytes(A21.pkRm),
          info: hexToBytes(A21.info),
          aad: hexToBytes(A21.aad),
          plaintext: hexToBytes(A21.plaintext),
          ephemeralSecretKey: hexToBytes(A21.skEm),
        }).ciphertext),
    },
    {
      label: "open",
      expected: A21.plaintext,
      run: () => bytesToHex(hpkeOpenBase({
        recipientSecretKey: hexToBytes(A21.skRm),
        enc: hexToBytes(A21.pkEm),
        info: hexToBytes(A21.info),
        aad: hexToBytes(A21.aad),
        ciphertext: hexToBytes(A21.ciphertext),
      })),
    },
  ] as const;

  for (const operation of operations) {
    for (const key of ["mulSecret", "runCT"] as const) {
      const prior = Object.getOwnPropertyDescriptor(ScalarMultiplier.prototype, key);
      assert.ok(prior && typeof prior.value === "function", `ScalarMultiplier.${key} descriptor is unavailable`);
      const real = prior.value as (...args: unknown[]) => unknown;
      let poisonCalls = 0;
      Object.defineProperty(ScalarMultiplier.prototype, key, {
        ...prior,
        value: function poisonedScalarMultiplier(this: unknown, ...args: unknown[]) {
          poisonCalls++;
          return Reflect.apply(real, this, args);
        },
      });
      let witnessCalls = 0;
      let actual: string | undefined;
      try {
        try {
          Reflect.apply(
            (ScalarMultiplier.prototype as unknown as Record<string, (...args: unknown[]) => unknown>)[key]!,
            null,
            [null, 1n, 1n, undefined],
          );
        } catch {
          // The wrapper ran; the original method is expected to reject the deliberately invalid receiver.
        }
        witnessCalls = poisonCalls;
        actual = operation.run();
      } finally {
        Object.defineProperty(ScalarMultiplier.prototype, key, prior);
      }
      assert.equal(witnessCalls, 1, `${operation.label}/${key}: poison did not bite on its direct witness`);
      assert.equal(poisonCalls, witnessCalls, `${operation.label}/${key}: fixed-base code received secret material`);
      assert.equal(actual, operation.expected, `${operation.label}/${key}: Montgomery result drifted from RFC 9180 A.2.1`);
    }
  }
});

test("HPKE pins the original global object before Noble can select a post-fence blinding RNG", () => {
  const realGlobal = globalThis;
  const globalThisDescriptor = Object.getOwnPropertyDescriptor(realGlobal, "globalThis");
  const runCtDescriptor = Object.getOwnPropertyDescriptor(ScalarMultiplier.prototype, "runCT");
  assert.ok(globalThisDescriptor?.configurable, "globalThis binding is unavailable for the attack witness");
  assert.ok(runCtDescriptor && typeof runCtDescriptor.value === "function", "ScalarMultiplier.runCT descriptor is unavailable");
  const realRunCt = runCtDescriptor.value as (...args: unknown[]) => unknown;
  const operations = [
    {
      label: "seal",
      run: () => hpkeSealBase({
        recipientPublicKey: hexToBytes(A21.pkRm),
        info: hexToBytes(A21.info),
        aad: hexToBytes(A21.aad),
        plaintext: hexToBytes(A21.plaintext),
        ephemeralSecretKey: hexToBytes(A21.skEm),
      }),
    },
    {
      label: "open",
      run: () => hpkeOpenBase({
        recipientSecretKey: hexToBytes(A21.skRm),
        enc: hexToBytes(A21.pkEm),
        info: hexToBytes(A21.info),
        aad: hexToBytes(A21.aad),
        ciphertext: hexToBytes(A21.ciphertext),
      }),
    },
  ] as const;

  for (const operation of operations) {
    let forceFakeGlobal = false;
    let globalGetterCalls = 0;
    let fakeRngCalls = 0;
    let hookCalls = 0;
    const fakeGlobal = {
      crypto: {
        getRandomValues(array: Uint8Array) {
          fakeRngCalls++;
          for (let i = 0; i < array.length; i++) array[i] = 0;
          Object.defineProperty(ScalarMultiplier.prototype, "runCT", {
            ...runCtDescriptor,
            value: function poisonedRunCt(this: unknown, ...args: unknown[]) {
              hookCalls++;
              return Reflect.apply(realRunCt, this, args);
            },
          });
          return array;
        },
      },
    };
    Object.defineProperty(realGlobal, "globalThis", {
      configurable: true,
      enumerable: globalThisDescriptor.enumerable,
      get() {
        globalGetterCalls++;
        const stack = new Error().stack ?? "";
        return forceFakeGlobal || stack.includes("@noble/hashes/utils.js") ? fakeGlobal : realGlobal;
      },
    });
    let caught: unknown;
    try {
      forceFakeGlobal = true;
      const witness = globalThis.crypto.getRandomValues(new Uint8Array(1));
      forceFakeGlobal = false;
      assert.equal(witness[0], 0, `${operation.label}: fake RNG direct witness did not run`);
      Object.defineProperty(ScalarMultiplier.prototype, "runCT", runCtDescriptor);
      try {
        operation.run();
      } catch (error) {
        caught = error;
      }
    } finally {
      Object.defineProperty(ScalarMultiplier.prototype, "runCT", runCtDescriptor);
      Object.defineProperty(realGlobal, "globalThis", globalThisDescriptor);
    }
    assert.ok(globalGetterCalls > 0, `${operation.label}: globalThis getter did not bite on its direct witness`);
    assert.equal(fakeRngCalls, 1, `${operation.label}: Noble reached the attacker-selected post-fence RNG`);
    assert.equal(hookCalls, 0, `${operation.label}: post-fence ScalarMultiplier hook received a blinded secret scalar`);
    assert.match(
      String(caught),
      /runtime intrinsic integrity check failed: globalThis\.globalThis/,
      `${operation.label}: HPKE continued after the original globalThis binding changed`,
    );
  }
});

test("HPKE integrity verification never re-enters self-restoring Reflect or Object accessors", () => {
  const realGlobal = globalThis;
  const realReflect = Reflect;
  const realObject = Object;
  const apply = realReflect.apply;
  const defineProperty = realObject.defineProperty;
  const getOwnPropertyDescriptor = realObject.getOwnPropertyDescriptor;
  const hookDescriptor = getOwnPropertyDescriptor(_HMAC.prototype, "update");
  assert.ok(hookDescriptor && typeof hookDescriptor.value === "function", "_HMAC.update descriptor is unavailable");
  const realHook = hookDescriptor.value as (...args: unknown[]) => unknown;
  const operations = [
    {
      label: "seal",
      rawDh: x25519.getSharedSecret(hexToBytes(A21.skEm), hexToBytes(A21.pkRm)),
      run: () => hpkeSealBase({
        recipientPublicKey: hexToBytes(A21.pkRm),
        info: hexToBytes(A21.info),
        aad: hexToBytes(A21.aad),
        plaintext: hexToBytes(A21.plaintext),
        ephemeralSecretKey: hexToBytes(A21.skEm),
      }),
    },
    {
      label: "open",
      rawDh: x25519.getSharedSecret(hexToBytes(A21.skRm), hexToBytes(A21.pkEm)),
      run: () => hpkeOpenBase({
        recipientSecretKey: hexToBytes(A21.skRm),
        enc: hexToBytes(A21.pkEm),
        info: hexToBytes(A21.info),
        aad: hexToBytes(A21.aad),
        ciphertext: hexToBytes(A21.ciphertext),
      }),
    },
  ] as const;

  for (const operation of operations) {
    for (const binding of ["Reflect", "Object"] as const) {
      const bindingDescriptor = getOwnPropertyDescriptor(realGlobal, binding);
      assert.ok(bindingDescriptor?.configurable && "value" in bindingDescriptor,
        `${binding} binding is unavailable for the attack witness`);
      let attackEnabled = false;
      let getterCalls = 0;
      let hookCalls = 0;
      let sawRawDh = false;
      const restoreBinding = () => {
        apply(defineProperty, realObject, [realGlobal, binding, bindingDescriptor]);
      };
      const restoreHook = () => {
        apply(defineProperty, realObject, [_HMAC.prototype, "update", hookDescriptor]);
      };
      const installHook = () => {
        apply(defineProperty, realObject, [_HMAC.prototype, "update", {
          ...hookDescriptor,
          value: function poisonedHmacUpdate(this: unknown, ...args: unknown[]) {
            hookCalls++;
            const bytes = args[0];
            if (bytes instanceof Uint8Array && bytes.length >= operation.rawDh.length) {
              let equal = true;
              const offset = bytes.length - operation.rawDh.length;
              for (let i = 0; i < operation.rawDh.length; i++) {
                if (bytes[offset + i] !== operation.rawDh[i]) {
                  equal = false;
                  break;
                }
              }
              if (equal) sawRawDh = true;
            }
            return apply(realHook, this, args);
          },
        }]);
      };
      const accessorDescriptor: PropertyDescriptor = {
        configurable: true,
        enumerable: bindingDescriptor.enumerable,
        get() {
          getterCalls++;
          if (attackEnabled) {
            restoreBinding();
            installHook();
          }
          return bindingDescriptor.value;
        },
      };

      apply(defineProperty, realObject, [realGlobal, binding, accessorDescriptor]);
      void (realGlobal as unknown as Record<string, unknown>)[binding];
      const witnessGetterCalls = getterCalls;
      restoreBinding();
      installHook();
      new _HMAC(sha256, new Uint8Array(32)).update(new Uint8Array([1])).destroy();
      const witnessHookCalls = hookCalls;
      restoreHook();

      apply(defineProperty, realObject, [realGlobal, binding, accessorDescriptor]);
      attackEnabled = true;
      let caught: unknown;
      try {
        operation.run();
      } catch (error) {
        caught = error;
      } finally {
        restoreHook();
        restoreBinding();
      }
      assert.equal(witnessGetterCalls, 1, `${operation.label}/${binding}: accessor witness did not bite`);
      assert.equal(witnessHookCalls, 1, `${operation.label}/${binding}: HMAC hook witness did not bite`);
      assert.equal(getterCalls, witnessGetterCalls, `${operation.label}/${binding}: verifier invoked a live global accessor`);
      assert.equal(hookCalls, witnessHookCalls, `${operation.label}/${binding}: self-restoring hook reached HMAC`);
      assert.equal(sawRawDh, false, `${operation.label}/${binding}: self-restoring hook observed raw DH`);
      assert.match(
        String(caught),
        new RegExp(`runtime intrinsic integrity check failed: globalThis\\.${binding}`),
        `${operation.label}/${binding}: HPKE did not fail on the changed binding descriptor`,
      );
    }
  }
});

test("hpkeOpenBase reproduces RFC 9180 A.2.1 decryption", () => {
  const pt = hpkeOpenBase({
    recipientSecretKey: hexToBytes(A21.skRm),
    enc: hexToBytes(A21.pkEm),
    info: hexToBytes(A21.info),
    aad: hexToBytes(A21.aad),
    ciphertext: hexToBytes(A21.ciphertext),
  });
  assert.equal(bytesToHex(pt), A21.plaintext);
});

test("HPKE seal→open round-trips with a fresh random ephemeral", () => {
  const rcpt = x25519.keygen();
  const info = new TextEncoder().encode("ctx");
  const aad = new TextEncoder().encode("aad");
  const plaintext = new TextEncoder().encode("the quick brown fox");
  const sealed = hpkeSealBase({ recipientPublicKey: rcpt.publicKey, info, aad, plaintext });
  const opened = hpkeOpenBase({ recipientSecretKey: rcpt.secretKey, enc: sealed.enc, info, aad, ciphertext: sealed.ciphertext });
  assert.equal(new TextDecoder().decode(opened), "the quick brown fox");
});

test("HPKE open fails closed with the WRONG recipient key", () => {
  const rcpt = x25519.keygen();
  const wrong = x25519.keygen();
  const sealed = hpkeSealBase({ recipientPublicKey: rcpt.publicKey, plaintext: new Uint8Array([1, 2, 3]) });
  assert.throws(() => hpkeOpenBase({ recipientSecretKey: wrong.secretKey, enc: sealed.enc, ciphertext: sealed.ciphertext }));
});

test("HPKE open fails closed on tampered ciphertext (AEAD tag)", () => {
  const rcpt = x25519.keygen();
  const sealed = hpkeSealBase({ recipientPublicKey: rcpt.publicKey, plaintext: new Uint8Array([9, 9, 9, 9]) });
  const tampered = Uint8Array.from(sealed.ciphertext);
  tampered[0] = (tampered[0] ?? 0) ^ 0x01;
  assert.throws(() => hpkeOpenBase({ recipientSecretKey: rcpt.secretKey, enc: sealed.enc, ciphertext: tampered }));
});

test("HPKE open fails closed on mismatched AAD", () => {
  const rcpt = x25519.keygen();
  const sealed = hpkeSealBase({ recipientPublicKey: rcpt.publicKey, aad: new TextEncoder().encode("A"), plaintext: new Uint8Array([1]) });
  assert.throws(() => hpkeOpenBase({ recipientSecretKey: rcpt.secretKey, enc: sealed.enc, aad: new TextEncoder().encode("B"), ciphertext: sealed.ciphertext }));
});

// ── encrypted-display seal/open ────────────────────────────────────────────────────────────────

const DISPLAY = { title: "Deploy api to production", risk: "HIGH", summary: ["service: api", "env: production"] };
function baseArgs(recipients: Array<{ kid: string; hpkePublicKey: string }>) {
  return {
    tenant: "acme-tenant",
    holdId: "hold-abc",
    deferredReceiptHash: "sha256:" + "a".repeat(64),
    expiresAt: "2026-07-15T12:05:00.000Z",
    display: DISPLAY,
    recipients,
  };
}

test("encrypted-display seal→open returns the exact plaintext display (hex device key)", () => {
  const device = x25519.keygen();
  const kid = "approver-1-device-1";
  const ed = sealEncryptedDisplay(baseArgs([{ kid, hpkePublicKey: bytesToHex(device.publicKey) }]));
  assert.equal(ed.spec, "noa.encrypted-display/0.1");
  assert.deepEqual(ed.suite, HPKE_SUITE);
  assert.equal(ed.recipients.length, 1);
  const opened = openEncryptedDisplay(ed, { kid, secretKey: device.secretKey });
  assert.deepEqual(opened, DISPLAY);
});

test("encrypted-display accepts a base64 SPKI-DER X25519 recipient key too", () => {
  const device = x25519.keygen();
  // hand-build the 12-byte X25519 SPKI DER prefix + raw key → base64
  const prefix = Uint8Array.from([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00]);
  const spki = new Uint8Array(44);
  spki.set(prefix, 0);
  spki.set(device.publicKey, 12);
  const kid = "device-spki";
  const ed = sealEncryptedDisplay(baseArgs([{ kid, hpkePublicKey: bytesToBase64(spki) }]));
  const opened = openEncryptedDisplay(ed, { kid, secretKey: device.secretKey });
  assert.deepEqual(opened, DISPLAY);
  assert.deepEqual(decodeX25519PublicKey(bytesToBase64(spki)), device.publicKey);
});

test("encrypted-display multi-recipient: each device opens the same payload", () => {
  const a = x25519.keygen();
  const b = x25519.keygen();
  const ed = sealEncryptedDisplay(
    baseArgs([
      { kid: "dev-a", hpkePublicKey: bytesToHex(a.publicKey) },
      { kid: "dev-b", hpkePublicKey: bytesToHex(b.publicKey) },
    ]),
  );
  assert.deepEqual(openEncryptedDisplay(ed, { kid: "dev-a", secretKey: a.secretKey }), DISPLAY);
  assert.deepEqual(openEncryptedDisplay(ed, { kid: "dev-b", secretKey: b.secretKey }), DISPLAY);
});

test("encrypted-display open fails closed with the WRONG device key", () => {
  const device = x25519.keygen();
  const attacker = x25519.keygen();
  const kid = "approver-1-device-1";
  const ed = sealEncryptedDisplay(baseArgs([{ kid, hpkePublicKey: bytesToHex(device.publicKey) }]));
  assert.throws(() => openEncryptedDisplay(ed, { kid, secretKey: attacker.secretKey }));
});

test("encrypted-display open fails closed on a tampered payload ciphertext", () => {
  const device = x25519.keygen();
  const kid = "approver-1-device-1";
  const ed = sealEncryptedDisplay(baseArgs([{ kid, hpkePublicKey: bytesToHex(device.publicKey) }]));
  const ct = base64ToBytes(ed.payload.ciphertext);
  ct[0] = (ct[0] ?? 0) ^ 0x80;
  ed.payload.ciphertext = bytesToBase64(ct);
  assert.throws(() => openEncryptedDisplay(ed, { kid, secretKey: device.secretKey }));
});

test("encrypted-display open fails closed when the AAD-bound tenant is altered (aadHash mismatch)", () => {
  const device = x25519.keygen();
  const kid = "approver-1-device-1";
  const ed = sealEncryptedDisplay(baseArgs([{ kid, hpkePublicKey: bytesToHex(device.publicKey) }]));
  ed.tenant = "evil-tenant"; // aadHash no longer binds
  assert.throws(() => openEncryptedDisplay(ed, { kid, secretKey: device.secretKey }), /aadHash/);
});

test("encrypted-display open rejects a device with no recipient entry", () => {
  const device = x25519.keygen();
  const other = x25519.keygen();
  const ed = sealEncryptedDisplay(baseArgs([{ kid: "dev-a", hpkePublicKey: bytesToHex(device.publicKey) }]));
  assert.throws(() => openEncryptedDisplay(ed, { kid: "dev-b", secretKey: other.secretKey }), /no recipient/);
});

test("F2 binding: swapping/adding a recipient changes the whole-object displayCiphertextHash", () => {
  const a = x25519.keygen();
  const b = x25519.keygen();
  const ed = sealEncryptedDisplay(baseArgs([{ kid: "dev-a", hpkePublicKey: bytesToHex(a.publicKey) }]));
  const before = sha256Prefixed(canonicalize(ed));
  // a relay-added recipient — the exact attack F2 defends against
  ed.recipients.push({ kid: "dev-b", enc: bytesToBase64(x25519.keygen().publicKey), wrappedCek: bytesToBase64(new Uint8Array(48)) });
  const after = sha256Prefixed(canonicalize(ed));
  assert.notEqual(before, after, "displayCiphertextHash must cover recipients[] (F2)");
  void b;
});

test("encrypted-display is deterministic under pinned CEK/nonce/ephemeral (vector-friendly)", () => {
  const device = x25519.keygen();
  const kid = "approver-1-device-1";
  const deterministic = {
    cek: hexToBytes("11".repeat(32)),
    payloadNonce: hexToBytes("22".repeat(12)),
    ephemeralSecretKey: hexToBytes(A21.skEm),
  };
  const ed1 = sealEncryptedDisplay({ ...baseArgs([{ kid, hpkePublicKey: bytesToHex(device.publicKey) }]), deterministic });
  const ed2 = sealEncryptedDisplay({ ...baseArgs([{ kid, hpkePublicKey: bytesToHex(device.publicKey) }]), deterministic });
  assert.deepEqual(ed1, ed2, "same inputs + pinned randomness → identical envelope");
  assert.deepEqual(openEncryptedDisplay(ed1, { kid, secretKey: device.secretKey }), DISPLAY);
});
