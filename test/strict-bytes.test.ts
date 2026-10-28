/**
 * The opt-in strict-bytes verifier profile, through the API (`verifyChain(bytes, { profile })`).
 *
 * The corpus is conformance/vectors/strict-bytes/ (scripts/gen-vectors.ts section 12) and its
 * manifest carries AUTHORED expectations. Every case is asserted against those constants — native
 * and strict — so a profile that changed a native verdict, or a gate that stopped refusing, fails
 * here. The file bytes are handed over unparsed: nothing in this suite re-serializes a chain file.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyChain, verifyChainText, type VerifyOptions } from "../src/verify.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const SB = join(__dirname, "..", "..", "conformance", "vectors", "strict-bytes");

interface Outcome { status: string; exit: number }
interface StrictOutcome extends Outcome { discriminator: string | null }
interface ManifestCase { name: string; file: string; sha256: string; native: Outcome | null; strict: StrictOutcome }
interface Manifest { spec: string; keyring: string; cases: ManifestCase[] }

const manifest = JSON.parse(readFileSync(join(SB, "manifest.json"), "utf8")) as Manifest;
const keyring = readFileSync(join(SB, manifest.keyring));
const bytesOf = (file: string): Uint8Array => readFileSync(join(SB, file));

/** Authored here, independently of the manifest: a case missing from the corpus fails the suite. */
const EXPECTED_CASES = [
  "canonical", "extra-space", "member-order", "escaped-string", "trailing-lf", "pretty",
  "leading-space", "trailing-crlf", "bom", "invalid-utf8", "reversed-order",
  "wrong-signature-canonical", "wrong-signature-noncanonical",
];

test("strict-bytes manifest: exactly the authored case set, every file present with its pinned SHA-256", () => {
  assert.equal(manifest.spec, "noa.strict-bytes-vectors/0.1");
  assert.deepEqual(manifest.cases.map((c) => c.name).sort(), [...EXPECTED_CASES].sort());
  for (const c of manifest.cases) {
    const digest = createHash("sha256").update(bytesOf(c.file)).digest("hex");
    assert.equal(digest, c.sha256, `${c.file}: bytes differ from the manifest digest`);
  }
});

for (const c of manifest.cases) {
  test(`strict-bytes/${c.name}: strict profile -> ${c.strict.status}${c.strict.discriminator ? ` (${c.strict.discriminator})` : ""}`, () => {
    const r = verifyChain(bytesOf(c.file), { keyring, profile: "strict-bytes" });
    assert.equal(r.status, c.strict.status, r.reason ?? "");
    if (c.strict.discriminator !== null) {
      assert.ok((r.reason ?? "").startsWith(c.strict.discriminator), `reason must lead with ${c.strict.discriminator}: ${r.reason}`);
      assert.equal(r.signaturesVerified, false);
      assert.equal(r.count, 0, "the gate refuses before any receipt is processed");
    }
  });

  test(`strict-bytes/${c.name}: native profile unchanged (omitted == "native"${c.native ? ` == ${c.native.status}` : ", outcome not asserted"})`, () => {
    const omitted = verifyChain(bytesOf(c.file), { keyring });
    const explicit = verifyChain(bytesOf(c.file), { keyring, profile: "native" });
    assert.deepEqual(explicit, omitted, "an explicit native profile must be the default run, byte for byte");
    if (c.native !== null) assert.equal(omitted.status, c.native.status, omitted.reason ?? "");
    assert.ok(!(omitted.reason ?? "").startsWith("NON_CANONICAL_BYTES"), "native never judges the received encoding");
  });
}

test("strict-bytes: canonical input yields the ordinary native result, warnings included", () => {
  const strict = verifyChain(bytesOf("canonical.json"), { keyring, profile: "strict-bytes" });
  const native = verifyChain(bytesOf("canonical.json"), { keyring });
  assert.deepEqual(strict, native);
});

test("strict-bytes: a byte mismatch outranks a missing keyring; canonical input without a keyring stays UNVERIFIED", () => {
  const mismatch = verifyChain(bytesOf("extra-space.json"), { profile: "strict-bytes" });
  assert.equal(mismatch.status, "MALFORMED");
  assert.ok((mismatch.reason ?? "").startsWith("NON_CANONICAL_BYTES"), mismatch.reason ?? "no reason");
  assert.equal(verifyChain(bytesOf("canonical.json"), { profile: "strict-bytes" }).status, "UNVERIFIED");
});

test("strict-bytes: text input is refused (the profile compares original bytes), native text input is unchanged", () => {
  const text = readFileSync(join(SB, "canonical.json"), "utf8");
  const viaText = verifyChain(text, { keyring, profile: "strict-bytes" });
  assert.equal(viaText.status, "MALFORMED");
  assert.ok(!(viaText.reason ?? "").startsWith("NON_CANONICAL_BYTES"), "a refused input type is not a byte mismatch");
  assert.equal(verifyChainText(text, { keyring, profile: "strict-bytes" }).status, "MALFORMED");
  assert.equal(verifyChainText(text, { keyring }).status, "VALID");
});

test("strict-bytes: the profile option is a closed set — any other value is MALFORMED, never a default", () => {
  const input = bytesOf("canonical.json");
  for (const bad of ["STRICT-BYTES", "strict", "", " native", 1, true, null, {}, ["strict-bytes"]]) {
    const r = verifyChain(input, { keyring, profile: bad } as unknown as VerifyOptions);
    assert.equal(r.status, "MALFORMED", `profile ${JSON.stringify(bad)} must be refused`);
    assert.match(r.reason ?? "", /option "profile" must be one of native, strict-bytes/);
  }
  // An explicitly undefined member means "not supplied", exactly like every other option.
  assert.equal(verifyChain(input, { keyring, profile: undefined }).status, "VALID");
});
