/** Secret-bearing Ed25519 entry points behind one shared post-load integrity fence. */

import { ScalarMultiplier } from "@noble/curves/abstract/curve.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { SHA512_IV } from "@noble/hashes/_md.js";
import { _SHA512, sha512 } from "@noble/hashes/sha2.js";
import {
  capturedCryptoRandomBytes,
  copyUnsharedUint8Array,
  createCryptoRuntimeIntegrityFence,
  cryptoByteLength,
  invokeCaptured,
  prototypeChainTargets,
  zeroCryptoBytes,
  type RuntimeIntegrityTarget,
} from "./runtime-integrity.js";

const ed25519Sign = ed25519.sign;
const ed25519GetPublicKey = ed25519.getPublicKey;

const ed25519IntegrityTargets: ReadonlyArray<RuntimeIntegrityTarget> = [
  ["@noble/curves.ed25519", ed25519],
  ["@noble/curves.ed25519.utils", ed25519.utils],
  ["@noble/curves.ed25519.lengths", ed25519.lengths],
  ["@noble/curves.ed25519.Point.Fp", ed25519.Point.Fp],
  ["@noble/curves.ed25519.Point.Fn", ed25519.Point.Fn],
  ["@noble/curves.ed25519.Point.BASE", ed25519.Point.BASE],
  ["@noble/curves.ed25519.Point.ZERO", ed25519.Point.ZERO],
  ...prototypeChainTargets("@noble/curves.ed25519.Point.constructor-chain", ed25519.Point),
  ...prototypeChainTargets("@noble/curves.ed25519.Point.prototype-chain", ed25519.Point.prototype),
  ...prototypeChainTargets("@noble/curves.ScalarMultiplier.constructor-chain", ScalarMultiplier),
  ...prototypeChainTargets("@noble/curves.ScalarMultiplier.prototype-chain", ScalarMultiplier.prototype),
  ["@noble/hashes.sha512", sha512],
  ...prototypeChainTargets("@noble/hashes._SHA512.constructor-chain", _SHA512),
  ...prototypeChainTargets("@noble/hashes._SHA512.prototype-chain", _SHA512.prototype),
  ["@noble/hashes.SHA512_IV", SHA512_IV],
];

export const assertEd25519RuntimeIntegrity = createCryptoRuntimeIntegrityFence(
  "Ed25519",
  ed25519IntegrityTargets,
);

function runSecretOperation(
  label: string,
  secretValue: unknown,
  operation: (secret: Uint8Array) => unknown,
): Uint8Array {
  const secret = copyUnsharedUint8Array(secretValue, `${label}.secretKey`);
  try {
    if (cryptoByteLength(secret) !== 32) {
      throw new Error(`${label}: secret key must be 32 bytes, got ${cryptoByteLength(secret)}`);
    }
    // LOAD-BEARING: no secret byte may enter mutable dependency dispatch before this final fence.
    assertEd25519RuntimeIntegrity();
    const output = operation(secret);
    assertEd25519RuntimeIntegrity();
    return copyUnsharedUint8Array(output, `${label}.result`);
  } finally {
    zeroCryptoBytes(secret);
  }
}

export function signEd25519(messageValue: unknown, secretValue: unknown): Uint8Array {
  const message = copyUnsharedUint8Array(messageValue, "signEd25519.message");
  return runSecretOperation("signEd25519", secretValue, (secret) => invokeCaptured(
    ed25519Sign as unknown as (...args: never[]) => unknown,
    ed25519,
    [message, secret],
  ));
}

export function deriveEd25519PublicKey(secretValue: unknown): Uint8Array {
  return runSecretOperation("deriveEd25519PublicKey", secretValue, (secret) => invokeCaptured(
    ed25519GetPublicKey as unknown as (...args: never[]) => unknown,
    ed25519,
    [secret],
  ));
}

export function randomEd25519SecretKey(): Uint8Array {
  assertEd25519RuntimeIntegrity();
  const secret = capturedCryptoRandomBytes(32, "randomEd25519SecretKey");
  assertEd25519RuntimeIntegrity();
  return secret;
}
