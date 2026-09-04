/**
 * Invocation-owned secret buffers must die with the invocation — on the success path AND on every
 * throw path.
 *
 * ── WHY A SOURCE-SCOPE ASSERTION AND NOT A HEAP PROBE ──────────────────────────────────────────
 * The buffers this file governs (the raw DH result, the HKDF extract PRK, the key-schedule secret,
 * the derived AEAD key and base nonce, the content-encryption key, the canonical display bytes, and
 * each private snapshot of a caller's secret) are function locals. JavaScript hands no observer a
 * reference to a local, so "was this local zeroed?" is not answerable from outside the function.
 * What IS answerable, mechanically and without inference, is whether each one is bound to a
 * `finally` that clears it — the same shape `dependency-hardening.test.mjs` already pins for the
 * private seed in `sign.ts`. That is stated here as a structural claim, not dressed up as a
 * measurement of memory.
 *
 * The behavioural half below is the ANTI-VACUITY control, and it is the half that would catch the
 * cheap wrong fix: clearing a buffer the CALLER still owns. A cleanup scope that zeroes the caller's
 * device key, the caller's plaintext, or its own return value would satisfy every structural
 * assertion here and destroy the API. Both halves have to hold.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { x25519 } from "@noble/curves/ed25519.js";
import {
  hpkeSealBase,
  hpkeOpenBase,
  sealEncryptedDisplay,
  openEncryptedDisplay,
} from "../src/index.js";
import { bytesToHex, hexToBytes } from "../src/bytes.js";
import { RFC9180_A2_1 as A21 } from "./fixtures/rfc9180-a2-1.js";

/** The package root, found by walking up to the manifest: this file executes from `dist/test/`. */
function packageRoot(): string {
  let dir = path.dirname(fileURLToPath(import.meta.url));
  for (let depth = 0; depth < 6; depth++) {
    const manifest = path.join(dir, "package.json");
    if (fs.existsSync(manifest) && JSON.parse(fs.readFileSync(manifest, "utf8")).name === "noa-signer") return dir;
    dir = path.dirname(dir);
  }
  throw new Error("secret-buffer-lifecycle: could not locate the noa-signer package root");
}

const SRC = path.join(packageRoot(), "src");
const read = (file: string): string => fs.readFileSync(path.join(SRC, file), "utf8");

/** The full body of a top-level function, located by its exact signature and brace-matched. */
function functionBody(source: string, signature: string): string {
  // The signature must run all the way to the body's own `{`. Stopping at the return-type colon
  // makes brace matching latch onto an object return type such as `{ key: ...; baseNonce: ... }`
  // and hand back a "body" that is really a type literal — which reads as "no cleanup scope here".
  assert.ok(signature.trimEnd().endsWith("{"), `signature must end at the body brace: ${signature}`);
  const start = source.indexOf(signature);
  assert.notEqual(start, -1, `source no longer contains: ${signature}`);
  let depth = 0;
  // The body brace is the LAST character of the signature. Searching forward from the signature's
  // start would find an object return type's brace instead.
  let cursor = start + signature.length - 1;
  assert.equal(source[cursor], "{", `signature did not land on the body brace: ${signature}`);
  const open = cursor;
  for (; cursor < source.length; cursor++) {
    const ch = source[cursor];
    if (ch === "{") depth++;
    else if (ch === "}") {
      depth--;
      if (depth === 0) break;
    }
  }
  return source.slice(open + 1, cursor);
}

/**
 * Offset of the cleanup scope: the first `try {` at the function body's own indentation, i.e. the
 * `try` whose `finally` clears this invocation's secrets.
 */
function cleanupScopeStart(body: string): number {
  const index = body.indexOf("\n  try {");
  assert.notEqual(index, -1, "the function has no top-level cleanup scope at all");
  return index;
}

/**
 * The body of THIS function's cleanup `finally` — brace-matched from its own top-level `try`.
 *
 * A whole-file `source.includes("zeroCryptoBytes(key)")` cannot tell which function did the
 * clearing, and the owned names are deliberately repetitive across this module: `key`, `baseNonce`,
 * `dh`, `cek` and `plaintext` each appear in more than one scope. Deleting one function's cleanup
 * therefore left a file-wide check green. Everything below reads one function's own finally.
 */
function cleanupFinallyBlock(body: string): string {
  let cursor = cleanupScopeStart(body);
  cursor = body.indexOf("{", cursor);
  let depth = 0;
  for (; cursor < body.length; cursor++) {
    const ch = body[cursor];
    if (ch === "{") depth++;
    else if (ch === "}") {
      depth--;
      if (depth === 0) break;
    }
  }
  const finallyAt = body.indexOf("finally {", cursor);
  assert.notEqual(finallyAt, -1, "the cleanup scope has no finally block");
  assert.ok(finallyAt - cursor < 12, "the first top-level try is not the cleanup scope");
  let open = body.indexOf("{", finallyAt);
  const start = open;
  depth = 0;
  for (; open < body.length; open++) {
    const ch = body[open];
    if (ch === "{") depth++;
    else if (ch === "}") {
      depth--;
      if (depth === 0) break;
    }
  }
  return body.slice(start + 1, open);
}

/** Each name must be cleared in THIS function's own finally, not merely somewhere in the file. */
function assertClearedInOwnFinally(label: string, body: string, owned: readonly string[]): void {
  const cleanup = cleanupFinallyBlock(body);
  for (const name of owned) {
    assert.ok(cleanup.includes(`zeroCryptoBytes(${name})`),
      `${label}: its own cleanup finally does not clear ${name} — a file-wide search would still find the name in a sibling function`);
  }
}

/**
 * REACHABILITY, not mere presence.
 *
 * The earlier revision of this file asked only "does some `finally` in this file mention this
 * name?". That question is answered `true` by a cleanup scope that opens too LATE, which is exactly
 * the defect it was written to catch: `hpkeSealBase` copied the plaintext and the injected ephemeral
 * scalar, then ran the integrity fence and two length checks — three statements that can each throw
 * — and only afterwards entered the scope that clears them. Same shape in `hpkeOpenBase` (the device
 * secret was snapshotted first, the fence and both length checks came next) and in
 * `sealEncryptedDisplay` (deterministic secrets copied, then canonicalization, the fence and the
 * CEK/nonce draw, all outside). Every one of those throw sites returned holding secrets that nothing
 * cleared, and a presence-only assertion reported green.
 *
 * So the assertion is POSITIONAL: each sensitive creation site must appear AFTER the `try` that owns
 * the cleanup. A scope that opens after any of them fails here, however complete its `finally` is.
 */
function assertInsideCleanupScope(
  label: string,
  body: string,
  sensitiveSites: readonly string[],
): void {
  const scope = cleanupScopeStart(body);
  for (const site of sensitiveSites) {
    const at = body.indexOf(site);
    assert.notEqual(at, -1, `${label}: the sensitive site ${JSON.stringify(site)} is gone — this assertion is now vacuous`);
    assert.ok(at > scope,
      `${label}: ${JSON.stringify(site)} happens BEFORE the cleanup scope opens, so a throw between them clears nothing`);
  }
}

/** The LAST integrity fence in a body — the one immediately guarding secret use — and every
 *  argument-shape throw, must also sit inside the scope: each of them can end the call. */
function assertThrowSitesInsideCleanupScope(label: string, body: string): void {
  const scope = cleanupScopeStart(body);
  const lastFence = body.lastIndexOf("assertHpkeRuntimeIntegrity()");
  assert.notEqual(lastFence, -1, `${label}: no integrity fence remains — this assertion is now vacuous`);
  assert.ok(lastFence > scope,
    `${label}: the final integrity fence can throw before the cleanup scope opens`);
  let index = body.indexOf("throw new Error(", scope === -1 ? 0 : 0);
  let checked = 0;
  while (index !== -1) {
    assert.ok(index > scope || !/must be \$\{|must be \d|must be exactly/.test(body.slice(index, index + 160)),
      `${label}: an argument-shape throw at offset ${index} sits outside the cleanup scope`);
    if (index > scope) checked++;
    index = body.indexOf("throw new Error(", index + 1);
  }
  assert.ok(checked > 0, `${label}: no throw site inside the cleanup scope — this assertion is now vacuous`);
}

test("hpkeSealBase opens its cleanup scope before the first secret exists", () => {
  const body = functionBody(read("hpke.ts"), "export function hpkeSealBase(input: HpkeSealInput): HpkeSealOutput {");
  assertInsideCleanupScope("hpkeSealBase", body, [
    '"hpkeSealBase.plaintext"',
    '"hpkeSealBase.ephemeralSecretKey"',
  ]);
  assertThrowSitesInsideCleanupScope("hpkeSealBase", body);
});

test("hpkeOpenBase opens its cleanup scope before the device-secret snapshot exists", () => {
  const body = functionBody(read("hpke.ts"), "export function hpkeOpenBase(input: HpkeOpenInput): Uint8Array {");
  assertInsideCleanupScope("hpkeOpenBase", body, ['"hpkeOpenBase.recipientSecretKey"']);
  assertThrowSitesInsideCleanupScope("hpkeOpenBase", body);
});

test("sealEncryptedDisplay opens its cleanup scope before any secret or canonical display exists", () => {
  const body = functionBody(
    read("encrypted-display.ts"),
    "export function sealEncryptedDisplay(input: SealDisplayInput): EncryptedDisplay {",
  );
  assertInsideCleanupScope("sealEncryptedDisplay", body, [
    '"sealEncryptedDisplay.deterministic.cek"',
    '"sealEncryptedDisplay.deterministic.payloadNonce"',
    '"sealEncryptedDisplay.deterministic.ephemeralSecretKey"',
    "canonicalize(display)",
    "hpkeRandomBytes(CEK_LEN)",
  ]);
  assertThrowSitesInsideCleanupScope("sealEncryptedDisplay", body);
});

test("openEncryptedDisplay opens its cleanup scope before the device-secret snapshot exists", () => {
  const body = functionBody(
    read("encrypted-display.ts"),
    "export function openEncryptedDisplay(ed: unknown, recipient: OpenRecipient): Record<string, unknown> {",
  );
  assertInsideCleanupScope("openEncryptedDisplay", body, ['"openEncryptedDisplay.recipient.secretKey"']);
});

/**
 * The same reachability rule applies BELOW the exported surface, and that is where it was still
 * broken after the first repair pass. Measured on those bytes: `decap` produced raw DH, then ran a
 * second scalar multiplication and a concat before entering the scope that cleared it;
 * `extractAndExpand` derived the PRK before its scope; `encap` drew the ephemeral scalar before its
 * scope; and `labeledExtract` built a buffer CONTAINING raw DH that no scope cleared at all. A
 * caller-level assertion cannot see any of that, so each helper is pinned here by name.
 */
test("every HPKE helper opens its cleanup scope before the secret it owns exists", () => {
  const source = read("hpke.ts");
  const cases: ReadonlyArray<readonly [string, string, readonly string[]]> = [
    ["labeledExtract",
      "function labeledExtract(suiteId: Uint8Array, salt: Uint8Array, label: string, ikm: Uint8Array): Uint8Array {",
      ["concatBytes(capturedTextEncode(HPKE_VERSION)"]],
    ["extractAndExpand",
      "function extractAndExpand(dh: Uint8Array, kemContext: Uint8Array): Uint8Array {",
      ['labeledExtract(KEM_SUITE_ID, EMPTY, "eae_prk", dh)']],
    ["encap",
      "function encap(recipientPublicKey: Uint8Array, ephemeralSecretKey?: Uint8Array): { sharedSecret: Uint8Array; enc: Uint8Array } {",
      ["hpkeRandomBytes(32)", "x25519ScalarMult(skE, recipientPublicKey)"]],
    ["decap",
      "function decap(enc: Uint8Array, recipientSecretKey: Uint8Array): Uint8Array {",
      ["x25519ScalarMult(recipientSecretKey, enc)"]],
    ["keyScheduleBase",
      "function keyScheduleBase(sharedSecret: Uint8Array, info: Uint8Array): { key: Uint8Array; baseNonce: Uint8Array } {",
      ['labeledExtract(HPKE_SUITE_ID, sharedSecret, "secret", EMPTY)',
       'labeledExpand(HPKE_SUITE_ID, secret, "key"']],
  ];
  for (const [label, signature, sites] of cases) {
    assertInsideCleanupScope(label, functionBody(source, signature), sites);
  }
});

test("keyScheduleBase clears a PARTIAL derivation and never clears a transferred one", () => {
  // The AEAD key is derived before the base nonce, so a failure between them leaves a complete
  // content key with no owner. Clearing unconditionally would be worse than the bug: the caller
  // would receive 32 zero bytes as a key. The flag is what separates those two cases, so its
  // position is the assertion — it must be set only after BOTH outputs exist.
  const body = functionBody(
    read("hpke.ts"),
    "function keyScheduleBase(sharedSecret: Uint8Array, info: Uint8Array): { key: Uint8Array; baseNonce: Uint8Array } {",
  );
  const transferred = body.indexOf("transferred = true;");
  const keyDerived = body.indexOf('labeledExpand(HPKE_SUITE_ID, secret, "key"');
  const nonceDerived = body.indexOf('labeledExpand(HPKE_SUITE_ID, secret, "base_nonce"');
  assert.notEqual(transferred, -1, "the ownership-transfer flag is gone — partial derivations are unclearable again");
  assert.ok(transferred > keyDerived && transferred > nonceDerived,
    "ownership is transferred before both outputs exist, so a failed derivation leaves a live AEAD key behind");
  assert.ok(body.includes("if (!transferred) {"),
    "the cleanup no longer distinguishes a partial derivation from a transferred one");
  for (const guarded of ["key", "baseNonce", "secret"]) {
    assert.ok(body.includes(`if (${guarded} !== undefined) zeroCryptoBytes(${guarded})`),
      `keyScheduleBase: ${guarded} is not cleared with a partial-initialization guard`);
  }
});

test("ANTI-VACUITY: transferred key material is NOT cleared — the RFC vector still reproduces", () => {
  // If the ownership-transfer flag were wrong in the other direction, the key schedule would hand
  // back zeroed buffers and this byte-exact vector would fail. That is the whole anti-vacuity claim.
  const sealed = hpkeSealBase({
    recipientPublicKey: hexToBytes(A21.pkRm),
    info: hexToBytes(A21.info),
    aad: hexToBytes(A21.aad),
    plaintext: hexToBytes(A21.plaintext),
    ephemeralSecretKey: hexToBytes(A21.skEm),
  });
  assert.equal(bytesToHex(sealed.enc), A21.pkEm);
  assert.equal(bytesToHex(sealed.ciphertext), A21.ciphertext);
  const opened = hpkeOpenBase({
    recipientSecretKey: hexToBytes(A21.skRm),
    enc: hexToBytes(A21.pkEm),
    info: hexToBytes(A21.info),
    aad: hexToBytes(A21.aad),
    ciphertext: hexToBytes(A21.ciphertext),
  });
  assert.equal(bytesToHex(opened), A21.plaintext);
});

/** file, signature, and the buffers THAT function owns and must clear in its OWN finally. */
const OWNED_BY_FUNCTION: ReadonlyArray<readonly [string, string, string, readonly string[]]> = [
  ["labeledExtract", "hpke.ts",
    "function labeledExtract(suiteId: Uint8Array, salt: Uint8Array, label: string, ikm: Uint8Array): Uint8Array {",
    ["labeledIkm"]],
  ["extractAndExpand", "hpke.ts",
    "function extractAndExpand(dh: Uint8Array, kemContext: Uint8Array): Uint8Array {",
    ["eaePrk"]],
  ["encap", "hpke.ts",
    "function encap(recipientPublicKey: Uint8Array, ephemeralSecretKey?: Uint8Array): { sharedSecret: Uint8Array; enc: Uint8Array } {",
    ["skE", "dh"]],
  ["decap", "hpke.ts",
    "function decap(enc: Uint8Array, recipientSecretKey: Uint8Array): Uint8Array {",
    ["dh"]],
  ["keyScheduleBase", "hpke.ts",
    "function keyScheduleBase(sharedSecret: Uint8Array, info: Uint8Array): { key: Uint8Array; baseNonce: Uint8Array } {",
    ["secret", "key", "baseNonce"]],
  ["hpkeSealBase", "hpke.ts",
    "export function hpkeSealBase(input: HpkeSealInput): HpkeSealOutput {",
    ["plaintext", "ephemeralSecretKey", "sharedSecret", "key", "baseNonce"]],
  ["hpkeOpenBase", "hpke.ts",
    "export function hpkeOpenBase(input: HpkeOpenInput): Uint8Array {",
    ["recipientSecretKey", "sharedSecret", "key", "baseNonce"]],
  ["sealEncryptedDisplay", "encrypted-display.ts",
    "export function sealEncryptedDisplay(input: SealDisplayInput): EncryptedDisplay {",
    ["cek", "displayBytes", "deterministicCek", "deterministicScalar"]],
  ["openEncryptedDisplay", "encrypted-display.ts",
    "export function openEncryptedDisplay(ed: unknown, recipient: OpenRecipient): Record<string, unknown> {",
    ["recipientSecretKey", "cek", "plaintext"]],
];

test("each function clears the buffers IT owns in its OWN cleanup finally", () => {
  for (const [label, file, signature, owned] of OWNED_BY_FUNCTION) {
    assertClearedInOwnFinally(label, functionBody(read(file), signature), owned);
  }
});

test("every cleared buffer carries a partial-initialization guard", () => {
  // `copyHpkeBytes` and every derivation can throw, so a cleanup that dereferences a name which was
  // never assigned would replace a leak with a TypeError inside a finally — which SWALLOWS the real
  // error. Each owned buffer is therefore cleared through an `if (x !== undefined)` guard.
  for (const [label, file, signature, owned] of OWNED_BY_FUNCTION) {
    const cleanup = cleanupFinallyBlock(functionBody(read(file), signature));
    for (const name of owned) {
      assert.ok(cleanup.includes(`if (${name} !== undefined) zeroCryptoBytes(${name})`),
        `${label}: ${name} is cleared without a partial-initialization guard`);
    }
  }
});

// ── ANTI-VACUITY: the cleanup scopes never reach anything the caller still owns ─────────────────

test("ANTI-VACUITY: hpkeSealBase leaves the caller's plaintext and keys untouched", () => {
  const plaintext = hexToBytes(A21.plaintext);
  const recipientPublicKey = hexToBytes(A21.pkRm);
  const ephemeralSecretKey = hexToBytes(A21.skEm);
  const sealed = hpkeSealBase({
    recipientPublicKey,
    info: hexToBytes(A21.info),
    aad: hexToBytes(A21.aad),
    plaintext,
    ephemeralSecretKey,
  });
  assert.equal(bytesToHex(sealed.ciphertext), A21.ciphertext, "the RFC vector stopped reproducing");
  assert.equal(bytesToHex(plaintext), A21.plaintext, "the caller's plaintext was cleared by the sealer");
  assert.equal(bytesToHex(ephemeralSecretKey), A21.skEm, "the caller's ephemeral scalar was cleared by the sealer");
  assert.equal(bytesToHex(recipientPublicKey), A21.pkRm, "the caller's recipient key was cleared by the sealer");
});

test("ANTI-VACUITY: hpkeOpenBase returns live plaintext and leaves the caller's device key intact", () => {
  const recipientSecretKey = hexToBytes(A21.skRm);
  const opened = hpkeOpenBase({
    recipientSecretKey,
    enc: hexToBytes(A21.pkEm),
    info: hexToBytes(A21.info),
    aad: hexToBytes(A21.aad),
    ciphertext: hexToBytes(A21.ciphertext),
  });
  assert.equal(bytesToHex(opened), A21.plaintext, "the returned plaintext was cleared before the caller could read it");
  assert.equal(bytesToHex(recipientSecretKey), A21.skRm, "the caller's device secret key was cleared by the opener");
});

test("ANTI-VACUITY: a failed open still leaves the caller's device key readable", () => {
  const secretKey = x25519.utils.randomSecretKey();
  const publicKey = x25519.getPublicKey(secretKey);
  const before = bytesToHex(secretKey);
  const display = sealEncryptedDisplay({
    tenant: "t", holdId: "h", deferredReceiptHash: "sha256:00", expiresAt: "2026-01-01T00:00:00Z",
    display: { amount: "1.00" },
    recipients: [{ kid: "device-1", hpkePublicKey: bytesToHex(publicKey) }],
  });
  // A tampered payload must fail closed — and the cleanup scope must not eat the caller's key.
  const tampered = {
    ...display,
    payload: { ...display.payload, ciphertext: `${display.payload.ciphertext.slice(0, -4)}AAAA` },
  };
  assert.throws(() => openEncryptedDisplay(tampered, { kid: "device-1", secretKey }));
  assert.equal(bytesToHex(secretKey), before, "a failed open cleared the caller's device secret key");
  // The same key still opens the untampered display: the throw path left nothing behind.
  const opened = openEncryptedDisplay(display, { kid: "device-1", secretKey });
  assert.deepEqual(opened, { amount: "1.00" });
  assert.equal(bytesToHex(secretKey), before, "a successful open cleared the caller's device secret key");
});

test("ANTI-VACUITY: the caller's deterministic material survives a seal", () => {
  const secretKey = x25519.utils.randomSecretKey();
  const publicKey = x25519.getPublicKey(secretKey);
  const deterministic = {
    cek: new Uint8Array(32).fill(3),
    payloadNonce: new Uint8Array(12).fill(4),
    ephemeralSecretKey: hexToBytes(A21.skEm),
  };
  sealEncryptedDisplay({
    tenant: "t", holdId: "h", deferredReceiptHash: "sha256:00", expiresAt: "2026-01-01T00:00:00Z",
    display: { amount: "2.00" },
    recipients: [{ kid: "device-1", hpkePublicKey: bytesToHex(publicKey) }],
    deterministic,
  });
  assert.equal(bytesToHex(deterministic.cek), "03".repeat(32), "the caller's deterministic CEK was cleared");
  assert.equal(bytesToHex(deterministic.payloadNonce), "04".repeat(12), "the caller's deterministic nonce was cleared");
  assert.equal(bytesToHex(deterministic.ephemeralSecretKey), A21.skEm, "the caller's deterministic scalar was cleared");
});
