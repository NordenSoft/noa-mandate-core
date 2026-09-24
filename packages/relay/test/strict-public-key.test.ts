import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519.js";
import { generateKeyPair, receiptHashInput, signingMessageBytes, RECEIPT_SIG_DOMAIN } from "noa-signer";
import { isStrictEd25519PublicKeyHex, verifyReceiptSignature } from "../src/crypto.js";
import { makeHarness, signDecisionReceipt, PARAMS_HASH } from "./helpers.js";

// Strict public-key validation at registration: the relay refuses non-canonical, off-curve,
// small-order and mixed-order Ed25519 key encodings (the same rule as noa-receipt/src/keys.ts).
const REFUSED: Array<[string, string]> = [
  ["small-order: identity", "0100000000000000000000000000000000000000000000000000000000000000"],
  ["small-order: order 2", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"],
  ["small-order: order 4 (even x)", "0000000000000000000000000000000000000000000000000000000000000000"],
  ["small-order: order 4 (odd x)", "0000000000000000000000000000000000000000000000000000000000000080"],
  ["small-order: order 8 (a)", "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"],
  ["small-order: order 8 (b)", "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"],
  ["small-order: order 8 (c)", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"],
  ["small-order: order 8 (d)", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"],
  ["x = 0 with sign bit: y = 1", "0100000000000000000000000000000000000000000000000000000000000080"],
  ["x = 0 with sign bit: y = p - 1", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"],
  ["non-canonical y: y = p, sign bit set", "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"],
  ["non-canonical y: y = p + 1", "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"],
  ["not a curve point: y = 2", "0200000000000000000000000000000000000000000000000000000000000000"],
  // The generated key 8a88…6f5c plus the order-2 point, (x, y) -> (-x, -y): a mixed-order key.
  ["mixed order", "63771c228bf60e6a02ad24d2c345a28d3598f640e26bede40c8b77fe4bf090a3"],
];
const VALID = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c";

test("isStrictEd25519PublicKeyHex refuses every non-canonical, off-curve, small-order and mixed-order key", () => {
  for (const [label, hex] of REFUSED) assert.equal(isStrictEd25519PublicKeyHex(hex), false, label);
  assert.equal(isStrictEd25519PublicKeyHex(VALID), true);
});

test("registerDevice refuses a key that fails strict public-key validation, and accepts a generated key", () => {
  const h = makeHarness();
  REFUSED.forEach(([label, hex], i) => {
    const r = h.engine.registerDevice({ kid: `strict-${i}`, publicKeyHex: hex });
    assert.equal(r.status, 422, `${label}: expected 422, got ${r.status}`);
    assert.equal((r.body as { error: string }).error, "BAD_PUBLIC_KEY", label);
  });
  const ok = h.engine.registerDevice({ kid: "strict-valid", publicKeyHex: VALID });
  assert.equal(ok.status, 201, JSON.stringify(ok.body));
});

test("knockout proof (signature-R rule): verifyReceiptSignature refuses key-holder signatures whose R is the identity, the identity with the sign bit, or rB + a small-order point", () => {
  // A fresh key and signatures made WITH its private scalar at test time; nothing is committed as bytes.
  const L = (1n << 252n) + 27742317777372353535851937790883648493n;
  const le = (b: Uint8Array): bigint => b.reduceRight((v, x) => (v << 8n) | BigInt(x), 0n);
  const le32 = (v: bigint): Uint8Array => Uint8Array.from({ length: 32 }, (_, i) => Number((v >> BigInt(8 * i)) & 0xffn));
  const seed = ed25519.utils.randomSecretKey();
  const { scalar, pointBytes } = ed25519.utils.getExtendedPublicKey(seed);
  const pubHex = Buffer.from(pointBytes).toString("hex");
  const kp = generateKeyPair("r-rule", new Uint8Array(32).fill(9));
  const receipt = signDecisionReceipt({ kid: "r-rule", privateKey: kp.privateKey, canonical: "wire.transfer", paramsHash: PARAMS_HASH, verdict: "ALLOWED" });
  const message = signingMessageBytes(RECEIPT_SIG_DOMAIN, receiptHashInput(receipt));
  const sign = (rBytes: Uint8Array, r: bigint): string => {
    const k = le(createHash("sha512").update(rBytes).update(pointBytes).update(message).digest()) % L;
    return Buffer.concat([rBytes, le32((r + k * scalar) % L)]).toString("base64");
  };
  const withSig = (value: string) => ({ ...receipt, sig: { ...receipt.sig, value } });
  const r = le(createHash("sha512").update(seed).update("r").digest()) % L;
  const rPoint = ed25519.Point.BASE.multiply(r);
  assert.equal(verifyReceiptSignature(withSig(sign(rPoint.toBytes(), r)), pubHex), true, "the control signature must verify");
  const identity = ed25519.Point.ZERO.toBytes();
  const identitySigned = Uint8Array.from(identity, (v, i) => (i === 31 ? v | 0x80 : v));
  const order8 = ed25519.Point.fromHex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05");
  const refused: Array<[string, string]> = [
    ["R = identity", sign(identity, 0n)],
    ["R = identity spelled with the sign bit", sign(identitySigned, 0n)],
    ["R = rB + small-order point", sign(rPoint.add(order8).toBytes(), r)],
  ];
  for (const [label, sig] of refused) assert.equal(verifyReceiptSignature(withSig(sig), pubHex), false, `${label} must be refused`);
});
