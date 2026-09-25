/**
 * The older (alpha) trust setup builds its keyrings on null-prototype maps, like the pinned setup.
 *
 * A keyring is looked up by kid. On a plain object a kid that is not enrolled — `constructor`,
 * `toString`, `__proto__` — resolves to an inherited member instead of to nothing, and a kid spelled
 * like one of them is at the mercy of the literal that built the map.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { intrinsics } from "noa-receipt";
import { createAlphaTrust } from "../src/trust.js";

const { hasOwn } = intrinsics;

function x25519Public(): string {
  return (generateKeyPairSync("x25519").publicKey.export({ type: "spki", format: "der" }) as Buffer).toString("base64");
}

function ed25519Public(): string {
  return (generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "der" }) as Buffer).toString("base64");
}

test("GATE-TRUST-PROTO — in the older trust setup a kid that is not enrolled resolves to nothing, in both keyrings", () => {
  const trust = createAlphaTrust({ tenant: "tenant-example-1" });
  const keyring = trust.keyring as Record<string, unknown>;
  const receiptKeys = trust.receiptKeyring.keys as Record<string, unknown>;
  for (const kid of ["constructor", "toString", "hasOwnProperty", "__proto__"]) {
    assert.equal(keyring[kid], undefined, `consequence: the unenrolled kid ${kid} resolves to no key entry`);
    assert.equal(receiptKeys[kid], undefined, `consequence: the unenrolled kid ${kid} resolves to no receipt key`);
  }
  assert.equal(Object.getPrototypeOf(keyring), null);
  assert.equal(Object.getPrototypeOf(receiptKeys), null);
});

test("GATE-TRUST-PROTO — an approver enrolled under the kid __proto__ or constructor is an ordinary own entry", () => {
  for (const kid of ["__proto__", "constructor"]) {
    const publicKey = ed25519Public();
    const trust = createAlphaTrust({ tenant: "tenant-example-1", approverPublicKey: { kid, publicKey, hpkePublicKey: x25519Public() } });
    const keyring = trust.keyring as Record<string, { publicKey: string; type: string }>;
    const receiptKeys = trust.receiptKeyring.keys as Record<string, { publicKey: string }>;
    assert.equal(hasOwn(keyring, kid), true, `${kid} is an own keyring entry`);
    assert.equal(keyring[kid]?.type, "APPROVER");
    assert.equal(keyring[kid]?.publicKey, publicKey);
    assert.equal(hasOwn(receiptKeys, kid), true, `${kid} is an own receipt key`);
    assert.equal(receiptKeys[kid]?.publicKey, publicKey);
    // What a verifier receives is the serialized map: the entry survives it.
    const wire = JSON.parse(JSON.stringify(keyring)) as Record<string, { publicKey: string }>;
    assert.equal(hasOwn(wire, kid), true);
  }
});
