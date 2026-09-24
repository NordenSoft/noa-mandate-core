/**
 * The two rules this package publishes for components that decide IN ADVANCE what a later verification
 * will accept: the strict Ed25519 public-key rule (`isStrictEd25519PublicKey`) and the F15 approver
 * lattice (`requiredApproverRole`). Each must be the verifier's own rule, not a copy of it.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import {
  generateKeyPair,
  isStrictEd25519PublicKey,
  requiredApproverRole,
  signEd25519,
  signingMessage,
  verifyEd25519,
} from "../src/index.js";

const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const spki = (raw: Buffer): string => Buffer.concat([SPKI_ED25519_PREFIX, raw]).toString("base64");

test("isStrictEd25519PublicKey accepts exactly the keys verifyEd25519 accepts", () => {
  const kp = generateKeyPair("k-1");
  const msg = signingMessage("NOA-Test-v0.1-sig", "{}");
  const goodSig = signEd25519(kp.privateKey, msg);
  const x25519 = (generateKeyPairSync("x25519").publicKey.export({ type: "spki", format: "der" }) as Buffer).toString("base64");
  const nonCanonicalY = Buffer.alloc(32, 0xff);
  nonCanonicalY[31] = 0x7f; // y = 2^255 - 1 >= p
  const candidates: Array<[string, unknown]> = [
    ["a generated key", kp.publicKey],
    ["the identity point (small order)", spki(Buffer.from("01" + "00".repeat(31), "hex"))],
    // RFC 8032 §5.1.3: x = 0 with the sign bit set fails decoding. These are the two x = 0 points
    // (y = 1 and y = p - 1) under a second spelling the small-order set did not list.
    ["y = 1 with the sign bit set (x = 0)", spki(Buffer.from("01" + "00".repeat(30) + "80", "hex"))],
    ["y = p - 1 with the sign bit set (x = 0)", spki(Buffer.from("ec" + "ff".repeat(31), "hex"))],
    // RFC 8032 §5.1.3 step 3: these y have no x on the curve, so the encoding names no point at all.
    ["off-curve y = 2", spki(Buffer.from("02" + "00".repeat(31), "hex"))],
    ["off-curve y = 7", spki(Buffer.from("07" + "00".repeat(31), "hex"))],
    ["off-curve y = 8 with the sign bit", spki(Buffer.from("08" + "00".repeat(30) + "80", "hex"))],
    ["a non-canonical y coordinate", spki(nonCanonicalY)],
    ["trailing garbage after the SPKI", Buffer.concat([Buffer.from(kp.publicKey, "base64"), Buffer.from([0])]).toString("base64")],
    ["non-canonical base64 padding", kp.publicKey.replace(/=$/, "")],
    ["an X25519 key", x25519],
    ["not a string", 42],
  ];
  let accepted = 0;
  for (const [name, key] of candidates) {
    const strict = isStrictEd25519PublicKey(key);
    // A key the verifier would refuse can never verify even a genuine signature; the published rule
    // must say the same thing. For the one genuine key the signature does verify.
    const verifies = typeof key === "string" && verifyEd25519(key, msg, goodSig);
    if (key === kp.publicKey) assert.equal(verifies, true, "control: the genuine key verifies its own signature");
    assert.equal(strict, key === kp.publicKey, `consequence: ${name} — the published key rule must accept exactly the genuine key; isStrictEd25519PublicKey returned ${strict}`);
    if (!strict) assert.equal(verifies, false, `${name}: a key the rule refuses must not verify`);
    if (strict) accepted++;
  }
  assert.equal(accepted, 1);
});

test("requiredApproverRole is the F15 lattice: CRITICAL/IRREVERSIBLE need approve-critical, HIGH accepts either, arrays are fresh", () => {
  assert.deepEqual(requiredApproverRole("CRITICAL"), ["approve-critical"]);
  assert.deepEqual(requiredApproverRole("IRREVERSIBLE"), ["approve-critical"]);
  assert.deepEqual(requiredApproverRole("HIGH"), ["approve-high", "approve-critical"]);
  const a = requiredApproverRole("HIGH");
  a.length = 0;
  assert.deepEqual(requiredApproverRole("HIGH"), ["approve-high", "approve-critical"], "a caller mutating the result changes nothing");
});
