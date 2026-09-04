import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";

import { createCipher } from "@noble/ciphers/_arx.js";
import { Poly1305 } from "@noble/ciphers/_poly1305.js";
import { _poly1305_aead, chacha20, chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { expand } from "@noble/hashes/hkdf.js";
import { SHA224_IV, SHA256_IV, SHA384_IV, SHA512_IV } from "@noble/hashes/_md.js";
import {
  _SHA224,
  _SHA256,
  _SHA384,
  _SHA512,
  _SHA512_224,
  _SHA512_256,
  sha224,
  sha256,
  sha384,
  sha512,
  sha512_224,
  sha512_256,
} from "@noble/hashes/sha2.js";

import { bytesToHex, hexToBytes } from "../dist/src/bytes.js";
import { hpkeOpenBase, hpkeSealBase } from "../dist/src/hpke.js";
import { RFC9180_A2_1 as A21 } from "../dist/test/fixtures/rfc9180-a2-1.js";

function assertRfcHpke(label) {
  const sealed = hpkeSealBase({
    recipientPublicKey: hexToBytes(A21.pkRm),
    info: hexToBytes(A21.info),
    aad: hexToBytes(A21.aad),
    plaintext: hexToBytes(A21.plaintext),
    ephemeralSecretKey: hexToBytes(A21.skEm),
  });
  assert.equal(bytesToHex(sealed.enc), A21.pkEm, `${label}: RFC encapsulated key drifted`);
  assert.equal(bytesToHex(sealed.ciphertext), A21.ciphertext, `${label}: RFC ciphertext drifted`);

  const opened = hpkeOpenBase({
    recipientSecretKey: hexToBytes(A21.skRm),
    enc: hexToBytes(A21.pkEm),
    info: hexToBytes(A21.info),
    aad: hexToBytes(A21.aad),
    ciphertext: hexToBytes(A21.ciphertext),
  });
  assert.equal(bytesToHex(opened), A21.plaintext, `${label}: RFC open drifted`);
}

function descriptor(target, key) {
  const value = Object.getOwnPropertyDescriptor(target, key);
  assert.ok(value && typeof value.value === "function", `${String(key)} descriptor unavailable`);
  return value;
}

test("retaining custom ARX sigma input cannot corrupt later HPKE seal or open", () => {
  let captured;
  let coreCalls = 0;
  const probe = createCipher((sigma, _key, _nonce, output) => {
    coreCalls++;
    captured = sigma;
    output.fill(0);
  }, { counterLength: 4 });

  probe(new Uint8Array(32), new Uint8Array(12), new Uint8Array([1]));
  assert.ok(coreCalls > 0, "custom ARX core did not receive its sigma argument");
  assert.ok(captured instanceof Uint32Array && captured.length === 4, "custom ARX core did not retain sigma bytes");
  captured[0] ^= 1;

  assertRfcHpke("retained ARX sigma");
});

test("a post-load Uint32Array construct hook cannot retain the private ChaCha sigma table", () => {
  const NativeUint32Array = globalThis.Uint32Array;
  let captured;
  let constructCalls = 0;
  const trap = new Proxy(NativeUint32Array, {
    construct(target, args, newTarget) {
      constructCalls++;
      if (
        args.length === 1 && args[0] instanceof NativeUint32Array &&
        args[0].length === 4
      ) {
        captured = args[0];
        globalThis.Uint32Array = NativeUint32Array;
      }
      return Reflect.construct(target, args, newTarget);
    },
  });

  globalThis.Uint32Array = trap;
  try {
    chacha20(new Uint8Array(32), new Uint8Array(12), new Uint8Array(64));
  } finally {
    globalThis.Uint32Array = NativeUint32Array;
  }
  assert.ok(constructCalls > 0, "the post-load construct hook did not observe the direct ChaCha call");
  assert.equal(captured, undefined, "a live constructor received the module-private ChaCha sigma table");
  assertRfcHpke("post-load ChaCha constructor hook");
});

test("retaining custom ChaCha auth input cannot corrupt later HPKE seal or open", () => {
  let captured;
  let authCalls = 0;
  const captureStream = (_key, _nonce, input, output, counter = 0) => {
    const result = output ?? new Uint8Array(input.length);
    if (output !== input) result.set(input);
    if (counter === 0 && input.length === 32) {
      authCalls++;
      captured = input;
    }
    return result;
  };
  const aead = _poly1305_aead(captureStream)(new Uint8Array(32), new Uint8Array(12), new Uint8Array([1]));
  aead.encrypt(new Uint8Array([2]));
  assert.equal(authCalls, 1, "custom ChaCha stream did not receive the Poly1305 auth input");
  assert.ok(captured instanceof Uint8Array && captured.length === 32, "custom ChaCha stream retained no auth input");
  captured[0] = 1;

  assertRfcHpke("retained ChaCha auth input");
});

test("retaining Poly1305 padding cannot corrupt later HPKE seal or open", () => {
  const prior = descriptor(Poly1305.prototype, "update");
  const realUpdate = prior.value;
  let captured;
  let paddingCalls = 0;
  Object.defineProperty(Poly1305.prototype, "update", {
    ...prior,
    value: function capturePadding(input) {
      if (input instanceof Uint8Array && input.length === 15) {
        paddingCalls++;
        captured = input;
      }
      return Reflect.apply(realUpdate, this, [input]);
    },
  });
  try {
    chacha20poly1305(new Uint8Array(32), new Uint8Array(12), new Uint8Array([1]))
      .encrypt(new Uint8Array([2]));
  } finally {
    Object.defineProperty(Poly1305.prototype, "update", prior);
  }
  assert.ok(paddingCalls >= 2, "Poly1305 update hook did not observe both unaligned padding calls");
  assert.ok(captured instanceof Uint8Array && captured.length === 15, "Poly1305 update hook retained no padding");
  for (let i = 0; i < captured.length; i++) captured[i] = 1;

  assertRfcHpke("retained Poly1305 padding");
});

test("X25519 low-order policy is not exposed through a mutable Set dispatch", () => {
  const prior = descriptor(Set.prototype, "has");
  const realHas = prior.value;
  let captured;
  let hasCalls = 0;
  Object.defineProperty(Set.prototype, "has", {
    ...prior,
    value: function captureLowOrderSet(value) {
      hasCalls++;
      if (typeof value === "bigint") captured = this;
      return Reflect.apply(realHas, this, [value]);
    },
  });
  let witnessCalls;
  try {
    assert.equal(new Set([1]).has(1), true, "Set.has direct witness changed behavior");
    witnessCalls = hasCalls;
    const shared = x25519.scalarMult(hexToBytes(A21.skEm), hexToBytes(A21.pkRm));
    assert.equal(shared.length, 32, "X25519 direct witness did not execute");
  } finally {
    Object.defineProperty(Set.prototype, "has", prior);
  }

  if (captured instanceof Set) captured.add(9n);
  assertRfcHpke("X25519 low-order collection probe");
  assert.equal(hasCalls, witnessCalls, "X25519 exposed its low-order policy through Set.prototype.has");
  assert.equal(captured, undefined, "X25519 exposed an add/remove-capable low-order collection");
  assert.throws(
    () => x25519.scalarMult(hexToBytes(A21.skEm), new Uint8Array(32)),
    /invalid private or public key received/,
    "X25519 accepted a known low-order public coordinate",
  );
});

function findMethodDescriptor(start, key) {
  let current = start;
  while (current !== null) {
    const found = Object.getOwnPropertyDescriptor(current, key);
    if (found !== undefined) return { owner: current, descriptor: found };
    current = Object.getPrototypeOf(current);
  }
  throw new Error(`${String(key)} method not found in prototype chain`);
}

function captureHashSchedules(hash, scheduleLength) {
  const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
  const prior = descriptor(typedArrayPrototype, "fill");
  const realFill = prior.value;
  const captured = [];
  Object.defineProperty(typedArrayPrototype, "fill", {
    ...prior,
    value: function captureSchedule(...args) {
      if (this instanceof Uint32Array && this.length === scheduleLength) captured.push(this);
      return Reflect.apply(realFill, this, args);
    },
  });
  try {
    hash(new Uint8Array(129));
  } finally {
    Object.defineProperty(typedArrayPrototype, "fill", prior);
  }
  return captured;
}

function detachDistinctBuffers(arrays) {
  const buffers = [];
  for (const array of arrays) {
    if (!buffers.includes(array.buffer)) buffers.push(array.buffer);
  }
  assert.ok(buffers.length > 0, "no private schedule backing buffer was retained");
  for (const buffer of buffers) structuredClone(buffer, { transfer: [buffer] });
}

test("detaching a retained SHA-256 instance schedule cannot disable later HPKE", () => {
  const schedules = captureHashSchedules(sha256, 64);
  assert.ok(schedules.length > 0, "SHA-256 fill hook retained no instance schedule");
  detachDistinctBuffers(schedules);

  assert.equal(
    bytesToHex(sha256(new Uint8Array([97, 98, 99]))),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    "a detached prior SHA-256 schedule poisoned a new hash instance",
  );
  assertRfcHpke("detached prior SHA-256 schedule");
});

test("detaching retained SHA-512 instance schedules cannot disable later signing hashes", () => {
  const schedules = captureHashSchedules(sha512, 80);
  assert.ok(schedules.length >= 2, "SHA-512 fill hook did not retain both instance schedules");
  detachDistinctBuffers(schedules);

  assert.equal(
    bytesToHex(sha512(new Uint8Array([97, 98, 99]))),
    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    "detached prior SHA-512 schedules poisoned a new hash instance",
  );
  assertRfcHpke("detached prior SHA-512 schedules");
});

test("detaching a retained HKDF counter cannot disable later HPKE seal or open", () => {
  const { owner, descriptor: prior } = findMethodDescriptor(_SHA256.prototype, "update");
  assert.equal(typeof prior.value, "function", "SHA-256 update descriptor is not callable");
  const realUpdate = prior.value;
  let captured;
  let counterCalls = 0;
  Object.defineProperty(owner, "update", {
    ...prior,
    value: function captureCounter(input) {
      if (input instanceof Uint8Array && input.length === 1) {
        counterCalls++;
        captured = input;
      }
      return Reflect.apply(realUpdate, this, [input]);
    },
  });
  try {
    const okm = expand(sha256, new Uint8Array(32), new Uint8Array([5, 6, 7]), 64);
    assert.equal(okm.length, 64, "HKDF direct witness did not expand two blocks");
  } finally {
    Object.defineProperty(owner, "update", prior);
  }
  assert.ok(counterCalls >= 2, "hash update hook did not observe the HKDF block counter");
  assert.ok(captured instanceof Uint8Array && captured.length === 1, "hash update hook retained no HKDF counter");
  structuredClone(captured.buffer, { transfer: [captured.buffer] });

  assertRfcHpke("detached prior HKDF counter");
});

test("mutating exported SHA-2 IV tables cannot change later hashes or Ed25519 signatures", () => {
  const message = new Uint8Array([97, 98, 99]);
  const seed = new Uint8Array(32);
  for (let i = 0; i < seed.length; i++) seed[i] = i + 1;
  const baselinePublicKey = ed25519.getPublicKey(seed);
  const baselineSignature = ed25519.sign(message, seed);
  const cases = [
    { algorithm: "sha224", hash: sha224, iv: SHA224_IV },
    { algorithm: "sha256", hash: sha256, iv: SHA256_IV },
    { algorithm: "sha384", hash: sha384, iv: SHA384_IV },
    { algorithm: "sha512", hash: sha512, iv: SHA512_IV },
  ];
  const originals = cases.map(({ iv }) => new Uint32Array(iv));

  try {
    for (let i = 0; i < cases.length; i++) {
      const iv = cases[i].iv;
      iv[0] = (iv[0] ^ (i + 1)) >>> 0;
    }
    for (const { algorithm, hash } of cases) {
      const expected = createHash(algorithm).update(message).digest("hex");
      assert.equal(
        bytesToHex(hash(message)),
        expected,
        `${algorithm} still consumed its post-load mutable exported IV table`,
      );
    }
    assert.deepEqual(
      ed25519.getPublicKey(seed),
      baselinePublicKey,
      "post-load SHA-512 IV drift changed the Ed25519 public key",
    );
    assert.deepEqual(
      ed25519.sign(message, seed),
      baselineSignature,
      "post-load SHA-512 IV drift changed a standard Ed25519 signature",
    );
  } finally {
    for (let ci = 0; ci < cases.length; ci++) {
      const iv = cases[ci].iv;
      const original = originals[ci];
      for (let i = 0; i < iv.length; i++) iv[i] = original[i];
    }
  }

  assert.equal(
    ed25519.verify(baselineSignature, message, baselinePublicKey),
    true,
    "the clean Ed25519 baseline was not independently usable after IV restoration",
  );
});

test("retaining SHA-2 superclass IV arguments cannot mutate any later hash instance", () => {
  const message = new Uint8Array([97, 98, 99]);
  const cases = [
    { algorithm: "sha224", Hash: _SHA224, hash: sha224 },
    { algorithm: "sha256", Hash: _SHA256, hash: sha256 },
    { algorithm: "sha384", Hash: _SHA384, hash: sha384 },
    { algorithm: "sha512", Hash: _SHA512, hash: sha512 },
    { algorithm: "sha512-224", Hash: _SHA512_224, hash: sha512_224 },
    { algorithm: "sha512-256", Hash: _SHA512_256, hash: sha512_256 },
  ];

  for (const { algorithm, Hash, hash } of cases) {
    const Parent = Object.getPrototypeOf(Hash);
    let captured;
    const trap = new Proxy(Parent, {
      construct(target, args, newTarget) {
        captured = args[1];
        Object.setPrototypeOf(Hash, Parent);
        return Reflect.construct(target, args, newTarget);
      },
    });
    Object.setPrototypeOf(Hash, trap);
    try {
      new Hash().destroy();
    } finally {
      Object.setPrototypeOf(Hash, Parent);
    }

    assert.ok(Array.isArray(captured), `${algorithm}: superclass did not receive an inert primitive array`);
    assert.equal(Object.isFrozen(captured), true, `${algorithm}: retained IV argument remained mutable`);
    assert.throws(() => { captured[0] ^= 1; }, TypeError, `${algorithm}: retained IV accepted a write`);
    assert.equal(
      bytesToHex(hash(message)),
      createHash(algorithm).update(message).digest("hex"),
      `${algorithm}: a retained superclass argument changed a later hash`,
    );
  }

  assertRfcHpke("retained frozen SHA-2 constructor arguments");
});
