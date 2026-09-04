import assert from "node:assert/strict";
import { createPublicKey, verify } from "node:crypto";
import { test } from "node:test";

import { ScalarMultiplier } from "@noble/curves/abstract/curve.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { SHA512_IV } from "@noble/hashes/_md.js";
import { _SHA512, sha512 } from "@noble/hashes/sha2.js";

import { base64ToBytes } from "../src/bytes.js";
import { spkiEd25519ToRawPublicKey } from "../src/der.js";
import { generateKeyPair } from "../src/keygen.js";
import { receiptHashInput } from "../src/receipt-hash.js";
import { withZeroedCryptoBytes } from "../src/runtime-integrity.js";
import { signReceipt } from "../src/sign.js";
import { RECEIPT_SIG_DOMAIN, signingMessageBytes } from "../src/signing.js";
import type { Receipt } from "../src/types.js";

test("private-byte cleanup runs when the protected operation throws", () => {
  const secret = new Uint8Array(32);
  for (let i = 0; i < secret.length; i++) secret[i] = i + 1;
  let retained: Uint8Array | undefined;

  assert.throws(
    () => withZeroedCryptoBytes(secret, (bytes) => {
      retained = bytes;
      assert.equal(bytes[0], 1, "the protected operation did not receive the private bytes");
      throw new Error("malformed receipt after private-key extraction");
    }),
    /malformed receipt after private-key extraction/,
  );
  assert.equal(retained, secret, "the test did not retain the exact protected allocation");
  assert.deepEqual([...secret], new Array(32).fill(0), "the throw path retained raw private bytes");
});

function unsignedReceipt(kid: string): Receipt {
  return {
    spec: "noa.receipt/0.1",
    id: "rcpt-ed25519-runtime-integrity",
    ts: "2026-08-24T00:00:00.000Z",
    scope: { tenant: "tenant-ed25519", chain: "chain-ed25519" },
    agent: { id: "agent-ed25519", model: null, principal: "HUMAN" },
    action: {
      id: "payment.refund",
      canonical: "payment.refund",
      riskClass: "HIGH",
      paramsHash: "sha256:" + "a".repeat(64),
      reversible: false,
      rollbackRef: null,
    },
    governance: {
      mode: "approvals_on",
      verdict: "ALLOWED",
      sandboxed: false,
      approval: { by: kid, at: "2026-08-24T00:00:00.000Z" },
    },
    chain: { prev: null, hash: "sha256:" + "b".repeat(64) },
    sig: { alg: "ed25519", kid, value: "" },
  } as unknown as Receipt;
}

function findMethodOwner(start: object, key: PropertyKey): {
  owner: object;
  descriptor: PropertyDescriptor & { value: (...args: never[]) => unknown };
} {
  let current: object | null = start;
  while (current !== null) {
    const descriptor = Object.getOwnPropertyDescriptor(current, key);
    if (descriptor !== undefined && typeof descriptor.value === "function") {
      return {
        owner: current,
        descriptor: descriptor as PropertyDescriptor & { value: (...args: never[]) => unknown },
      };
    }
    current = Object.getPrototypeOf(current) as object | null;
  }
  throw new Error(`${String(key)} method owner was not found`);
}

function dataViewContains(view: DataView, bytes: Uint8Array): boolean {
  if (bytes.length === 0 || view.byteLength < bytes.length) return false;
  for (let start = 0; start <= view.byteLength - bytes.length; start++) {
    let equal = true;
    for (let i = 0; i < bytes.length; i++) {
      if (view.getUint8(start + i) !== bytes[i]) {
        equal = false;
        break;
      }
    }
    if (equal) return true;
  }
  return false;
}

test("Ed25519 fence stops a post-load SHA-512 process hook before it can read a signing seed", () => {
  const seed = new Uint8Array(32);
  for (let i = 0; i < seed.length; i++) seed[i] = i + 1;
  const pair = generateKeyPair("kid-ed25519-process-hook", seed);
  const core = unsignedReceipt(pair.kid);
  const { owner, descriptor } = findMethodOwner(_SHA512.prototype, "process");
  const realProcess = descriptor.value;
  let processCalls = 0;
  let sawExactSeed = false;

  Object.defineProperty(owner, "process", {
    ...descriptor,
    value: function captureSha512Block(view: DataView, offset: number) {
      processCalls++;
      if (dataViewContains(view, seed)) sawExactSeed = true;
      return Reflect.apply(realProcess, this, [view, offset]);
    },
  });

  try {
    // Anti-vacuity: this exact hook reaches the raw seed when SHA-512 is called without the product
    // fence. A test that installed a hook incapable of observing the defect would prove nothing.
    sha512(seed);
    assert.ok(processCalls > 0, "the SHA-512 process hook did not execute on its direct witness");
    assert.equal(sawExactSeed, true, "the direct witness hook could not observe the exact seed bytes");
    processCalls = 0;
    sawExactSeed = false;

    assert.throws(
      () => signReceipt(core, { kid: pair.kid, privateKey: pair.privateKey }),
      /Ed25519 runtime intrinsic integrity check failed: @noble\/hashes\._SHA512\.prototype-chain/,
      "signReceipt passed a long-lived private seed into a replaced SHA-512 process method",
    );
    assert.throws(
      () => generateKeyPair("kid-ed25519-guarded-keygen", seed),
      /Ed25519 runtime intrinsic integrity check failed: @noble\/hashes\._SHA512\.prototype-chain/,
      "generateKeyPair passed a private seed into a replaced SHA-512 process method",
    );
    assert.equal(processCalls, 0, "a protected Ed25519 entry point invoked the poisoned process method");
    assert.equal(sawExactSeed, false, "a protected Ed25519 entry point disclosed the exact private seed");
  } finally {
    Object.defineProperty(owner, "process", descriptor);
  }

  const signed = signReceipt(core, { kid: pair.kid, privateKey: pair.privateKey });
  const message = signingMessageBytes(RECEIPT_SIG_DOMAIN, receiptHashInput(signed));
  assert.equal(
    ed25519.verify(
      base64ToBytes(signed.sig.value),
      message,
      spkiEd25519ToRawPublicKey(pair.publicKey),
    ),
    true,
    "the clean signing path no longer produces a standard-verifiable Ed25519 signature",
  );
});

test("Ed25519 fence refuses exported SHA-512 IV drift before signing or key derivation", () => {
  const seed = new Uint8Array(32).fill(42);
  const pair = generateKeyPair("kid-ed25519-iv", seed);
  const core = unsignedReceipt(pair.kid);
  const original = SHA512_IV[0] as number;
  try {
    SHA512_IV[0] = (original ^ 1) >>> 0;
    assert.throws(
      () => signReceipt(core, { kid: pair.kid, privateKey: pair.privateKey }),
      /Ed25519 runtime intrinsic integrity check failed: @noble\/hashes\.SHA512_IV/,
    );
    assert.throws(
      () => generateKeyPair("kid-ed25519-iv-keygen", seed),
      /Ed25519 runtime intrinsic integrity check failed: @noble\/hashes\.SHA512_IV/,
    );
  } finally {
    SHA512_IV[0] = original;
  }

  const signed = signReceipt(core, { kid: pair.kid, privateKey: pair.privateKey });
  assert.notEqual(signed.sig.value, "", "the restored honest signing path produced no signature");
  assert.deepEqual(seed, new Uint8Array(32).fill(42), "generateKeyPair mutated the caller-owned seed");
});

test("private-key DER never reaches self-restoring TypedArray length or slice hooks", () => {
  const seed = new Uint8Array(32);
  for (let i = 0; i < seed.length; i++) seed[i] = i + 1;
  const pair = generateKeyPair("kid-ed25519-der-dispatch", seed);
  const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype) as object;
  const lengthDescriptor = Object.getOwnPropertyDescriptor(typedArrayPrototype, "length");
  const sliceDescriptor = Object.getOwnPropertyDescriptor(typedArrayPrototype, "slice");
  assert.ok(lengthDescriptor && typeof lengthDescriptor.get === "function" && lengthDescriptor.configurable);
  assert.ok(sliceDescriptor && typeof sliceDescriptor.value === "function" && sliceDescriptor.configurable);
  const realLength = lengthDescriptor.get;
  const realSlice = sliceDescriptor.value as (start?: number, end?: number) => Uint8Array;

  for (const attack of ["length", "slice"] as const) {
    let leaked: number[] | undefined;
    const restore = () => {
      Object.defineProperty(
        typedArrayPrototype,
        attack,
        attack === "length" ? lengthDescriptor : sliceDescriptor,
      );
    };
    const captureIfPkcs8 = (value: Uint8Array): void => {
      const length = Reflect.apply(realLength, value, []) as number;
      if (
        length === 48
        && value[0] === 0x30
        && value[1] === 0x2e
        && value[14] === 0x04
        && value[15] === 0x20
      ) {
        leaked = [];
        for (let i = 0; i < 32; i++) leaked[i] = value[16 + i] as number;
        restore();
      }
    };
    const install = () => {
      if (attack === "length") {
        Object.defineProperty(typedArrayPrototype, "length", {
          ...lengthDescriptor,
          get(this: Uint8Array) {
            const length = Reflect.apply(realLength, this, []) as number;
            captureIfPkcs8(this);
            return length;
          },
        });
      } else {
        Object.defineProperty(typedArrayPrototype, "slice", {
          ...sliceDescriptor,
          value: function poisonedSlice(this: Uint8Array, start?: number, end?: number) {
            captureIfPkcs8(this);
            return Reflect.apply(realSlice, this, [start, end]) as Uint8Array;
          },
        });
      }
    };

    const witness = base64ToBytes(pair.privateKey);
    install();
    if (attack === "length") void witness.length;
    else witness.slice(16);
    assert.deepEqual(leaked, [...seed], `${attack}: direct witness could not observe the exact signing seed`);
    restore();
    leaked = undefined;

    const core = unsignedReceipt(pair.kid);
    let proxyCalls = 0;
    let armed = false;
    const hostileCore = new Proxy(core, {
      getOwnPropertyDescriptor(target, key) {
        proxyCalls++;
        if (!armed) {
          armed = true;
          install();
        }
        return Reflect.getOwnPropertyDescriptor(target, key);
      },
    });
    let caught: unknown;
    try {
      try {
        signReceipt(hostileCore, { kid: pair.kid, privateKey: pair.privateKey });
      } catch (error) {
        caught = error;
      }
    } finally {
      restore();
    }

    assert.ok(proxyCalls > 0, `${attack}: hostile receipt did not reach its descriptor path`);
    assert.equal(leaked, undefined, `${attack}: the signing path exposed the private DER seed`);
    assert.match(
      String(caught),
      /Ed25519 runtime intrinsic integrity check failed: %TypedArray%\.prototype/,
      `${attack}: signing continued after an untrusted receipt installed a private-byte hook`,
    );
  }

  const signed = signReceipt(unsignedReceipt(pair.kid), { kid: pair.kid, privateKey: pair.privateKey });
  assert.notEqual(signed.sig.value, "", "hardening private DER decoding broke ordinary signing");
});

test("Ed25519 secret multiplication cannot reuse retained multiplier or window-map state", () => {
  const seed = new Uint8Array(32);
  for (let i = 0; i < seed.length; i++) seed[i] = i + 1;
  const pair = generateKeyPair("kid-ed25519-retained-state", seed);
  const core = unsignedReceipt(pair.kid);

  const multiplierPrototype = ScalarMultiplier.prototype;
  const isolatedDescriptor = Object.getOwnPropertyDescriptor(multiplierPrototype, "mulSecretIsolated");
  const sharedDescriptor = Object.getOwnPropertyDescriptor(multiplierPrototype, "mulSecret");
  const runDescriptor = Object.getOwnPropertyDescriptor(multiplierPrototype, "runCT");
  assert.ok(isolatedDescriptor && typeof isolatedDescriptor.value === "function");
  assert.ok(sharedDescriptor && typeof sharedDescriptor.value === "function");
  assert.ok(runDescriptor && typeof runDescriptor.value === "function");

  let retained: Record<PropertyKey, unknown> | undefined;
  const capture = (descriptor: PropertyDescriptor & { value: (...args: never[]) => unknown }) =>
    function captureMultiplier(this: object, ...args: unknown[]) {
      retained = this as Record<PropertyKey, unknown>;
      return Reflect.apply(descriptor.value, this, args);
    };
  Object.defineProperty(multiplierPrototype, "mulSecretIsolated", {
    ...isolatedDescriptor,
    value: capture(isolatedDescriptor as PropertyDescriptor & { value: (...args: never[]) => unknown }),
  });
  Object.defineProperty(multiplierPrototype, "mulSecret", {
    ...sharedDescriptor,
    value: capture(sharedDescriptor as PropertyDescriptor & { value: (...args: never[]) => unknown }),
  });
  try {
    ed25519.getPublicKey(new Uint8Array(32).fill(9));
  } finally {
    Object.defineProperty(multiplierPrototype, "mulSecretIsolated", isolatedDescriptor);
    Object.defineProperty(multiplierPrototype, "mulSecret", sharedDescriptor);
  }
  assert.ok(retained, "the direct Ed25519 witness did not expose a multiplier to the hook");

  const randomDescriptor = Object.getOwnPropertyDescriptor(retained, "randomBytes");
  const zeroDescriptor = Object.getOwnPropertyDescriptor(retained, "ZERO");
  const baseDescriptor = Object.getOwnPropertyDescriptor(retained, "BASE");
  assert.ok(randomDescriptor && "value" in randomDescriptor, "retained multiplier had no randomBytes state");
  assert.ok(zeroDescriptor && "value" in zeroDescriptor, "retained multiplier had no ZERO state");
  assert.ok(baseDescriptor && "value" in baseDescriptor, "retained multiplier had no BASE state");

  const weakMapGetDescriptor = Object.getOwnPropertyDescriptor(WeakMap.prototype, "get");
  const weakMapSetDescriptor = Object.getOwnPropertyDescriptor(WeakMap.prototype, "set");
  assert.ok(weakMapGetDescriptor && typeof weakMapGetDescriptor.value === "function");
  assert.ok(weakMapSetDescriptor && typeof weakMapSetDescriptor.value === "function");
  const realWeakMapGet = weakMapGetDescriptor.value as (...args: never[]) => unknown;
  const realWeakMapSet = weakMapSetDescriptor.value as (...args: never[]) => unknown;
  let retainedWindowMap: WeakMap<object, unknown> | undefined;
  Object.defineProperty(WeakMap.prototype, "get", {
    ...weakMapGetDescriptor,
    value: function capturePointWindowMap(this: WeakMap<object, unknown>, key: object) {
      const value = Reflect.apply(realWeakMapGet, this, [key]);
      if (key === ed25519.Point.BASE && typeof value === "number") {
        retainedWindowMap = this;
      }
      return value;
    },
  });
  try {
    ed25519.Point.BASE.multiplyUnsafe(2n);
  } finally {
    Object.defineProperty(WeakMap.prototype, "get", weakMapGetDescriptor);
  }
  assert.ok(retainedWindowMap, "the direct public-scalar witness did not expose the point window map");
  const originalWindow = Reflect.apply(realWeakMapGet, retainedWindowMap, [ed25519.Point.BASE]);
  assert.equal(typeof originalWindow, "number", "the retained point window was not numeric before mutation");

  let maliciousRandomCalls = 0;
  let capturedBlindedScalars = 0;
  let windowCoercions = 0;
  const maliciousWindow = {
    valueOf() {
      windowCoercions++;
      return originalWindow;
    },
  };
  Object.defineProperty(retained, "randomBytes", {
    ...randomDescriptor,
    value(length: number) {
      maliciousRandomCalls++;
      Object.defineProperty(retained, "runCT", {
        configurable: true,
        value(point: unknown, scalar: bigint, bits: number, transform: unknown) {
          capturedBlindedScalars++;
          delete retained?.runCT;
          return Reflect.apply(runDescriptor.value as (...args: never[]) => unknown, retained, [
            point,
            scalar,
            bits,
            transform,
          ]);
        },
      });
      return new Uint8Array(length);
    },
  });
  Object.defineProperty(retained, "ZERO", { ...zeroDescriptor, value: baseDescriptor.value });
  Reflect.apply(realWeakMapSet, retainedWindowMap, [ed25519.Point.BASE, maliciousWindow]);
  assert.equal(retained.ZERO, retained.BASE, "the retained ZERO mutation did not stick");
  assert.equal(
    Reflect.apply(realWeakMapGet, retainedWindowMap, [ed25519.Point.BASE]),
    maliciousWindow,
    "the retained window-map mutation did not stick",
  );

  let signed: Receipt;
  try {
    signed = signReceipt(core, { kid: pair.kid, privateKey: pair.privateKey });
  } finally {
    Object.defineProperty(retained, "randomBytes", randomDescriptor);
    Object.defineProperty(retained, "ZERO", zeroDescriptor);
    delete retained.runCT;
    Reflect.apply(realWeakMapSet, retainedWindowMap, [ed25519.Point.BASE, originalWindow]);
    Object.defineProperty(multiplierPrototype, "mulSecretIsolated", isolatedDescriptor);
    Object.defineProperty(multiplierPrototype, "mulSecret", sharedDescriptor);
    Object.defineProperty(multiplierPrototype, "runCT", runDescriptor);
    Object.defineProperty(WeakMap.prototype, "get", weakMapGetDescriptor);
    Object.defineProperty(WeakMap.prototype, "set", weakMapSetDescriptor);
  }

  assert.equal(maliciousRandomCalls, 0, "product signing reused an attacker-retained multiplier RNG");
  assert.equal(capturedBlindedScalars, 0, "product signing dispatched through attacker-retained multiplier state");
  assert.equal(windowCoercions, 0, "product signing consulted an attacker-retained point window policy");
  assert.deepEqual(seed, Uint8Array.from({ length: 32 }, (_, i) => i + 1), "the caller seed was mutated");

  const message = signingMessageBytes(RECEIPT_SIG_DOMAIN, receiptHashInput(signed));
  const publicKey = createPublicKey({
    key: Buffer.from(pair.publicKey, "base64"),
    format: "der",
    type: "spki",
  });
  assert.equal(
    verify(null, Buffer.from(message), publicKey, Buffer.from(base64ToBytes(signed.sig.value))),
    true,
    "the isolated secret path did not produce a standard Node-verifiable Ed25519 signature",
  );
});
