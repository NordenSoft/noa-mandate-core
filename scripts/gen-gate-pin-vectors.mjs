#!/usr/bin/env node
/**
 * Generates conformance/gate-pin/vectors.json, the `noa.gate-pin/1` corpus (docs/gate-pin-spec.md).
 *
 *   node scripts/gen-gate-pin-vectors.mjs           write the corpus
 *   node scripts/gen-gate-pin-vectors.mjs --check   exit 1 when the committed corpus differs
 *
 * Needs the gate package built (`npm --prefix packages/gate run build`): every vector is checked
 * against the reference implementation, and every ACCEPT value is ALSO derived independently here
 * (SHA-256 from node:crypto over a JCS text built by hand — the members are ASCII strings, whose JCS
 * form is their JSON string form). The file is written only when both agree for every vector.
 *
 * The fixture is synthetic by construction: `tenant-example-N`, `gate-example-N`, an all-zero example
 * UUID for the console-style tenant, Ed25519 public keys generated once for this corpus and fixed
 * below, and the refused keys of conformance/vectors/strict-ed25519.
 */
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const OUT = join(ROOT, "conformance", "gate-pin", "vectors.json");
const { gatePinFingerprint, gatePinFingerprintFromRaw, gatePinPublicKeyFromRaw } = await import(
  pathToFileURL(join(ROOT, "packages", "gate", "dist", "src", "gate-pin.js")).href
);

// ── the fixture ────────────────────────────────────────────────────────────────────────────────
const T = "tenant-example-1";
const KID = "gate-example-1";
/** Ed25519 public keys generated once for this corpus; they have no use outside it. */
const K1 = "MCowBQYDK2VwAyEAEbt4AjTMouGHdJqL/XyuTmiHpHkJ1Gh5eGqaBnwIPqw=";
const K2 = "MCowBQYDK2VwAyEAA16p81ty4/ZpW8KOlrti05kpuaM0Wb8YVIAMi+MCCq4=";
/** An X25519 public key in SPKI form: the right length, the wrong curve. */
const X25519 = "MCowBQYDK2VuAyEAAbdG2n5Lurl54jKMPGuyJc36icRcyjEz++UdsDqxU1s=";
/** A console-style tenant identifier: `org_` and the all-zero example UUID. */
const CONSOLE_TENANT = "org_00000000-0000-0000-0000-000000000000";

const strict = (name) =>
  JSON.parse(readFileSync(join(ROOT, "conformance", "vectors", "strict-ed25519", name), "utf8"))["noa-test-key-2026"];
const rawOf = (spki) => Buffer.from(spki, "base64").subarray(12).toString("base64url");
const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
/** The same bytes with the last character's lowest (unused) bit flipped: a non-canonical spelling. */
const flipUnusedBit = (text, alphabet, suffix = "") => {
  const body = suffix === "" ? text : text.slice(0, -suffix.length);
  const last = body[body.length - 1];
  return body.slice(0, -1) + alphabet[alphabet.indexOf(last) ^ 1] + suffix;
};

function independent(t, k, p) {
  const canonical = `{"gateKid":${JSON.stringify(k)},"publicKey":${JSON.stringify(p)},"spec":"noa.gate-pin/1","tenant":${JSON.stringify(t)}}`;
  const hex = createHash("sha256").update(Buffer.from(canonical, "utf8")).digest("hex");
  const groups = [0, 4, 8, 12, 16].map((i) => hex.slice(i, i + 4));
  return { canonical, digest: `sha256:${hex}`, fingerprint: `NOAGP1-${groups.join("-")}` };
}

const vectors = [];
const fail = (msg) => {
  throw new Error(`gen-gate-pin-vectors: ${msg}`);
};

function accept(id, input, note) {
  const r = gatePinFingerprint(input);
  const ind = independent(input.tenant, input.gateKid, input.publicKey);
  if (!r.ok || r.fingerprint !== ind.fingerprint || r.digest !== ind.digest) fail(`${id}: the implementation and the independent derivation disagree`);
  vectors.push({ id, kind: "fingerprint", expect: "ACCEPT", input, canonical: ind.canonical, digest: ind.digest, fingerprint: ind.fingerprint, ...(note ? { note } : {}) });
}
function reject(id, input, code, extra = {}) {
  const r = gatePinFingerprint(input);
  if (r.ok || r.code !== code) fail(`${id}: expected ${code}, got ${JSON.stringify(r)}`);
  vectors.push({ id, kind: "fingerprint", expect: "REJECT", input, reasonCode: code, ...extra });
}
function acceptRaw(id, raw, equivalentTo) {
  const input = { tenant: T, gateKid: KID, publicKeyRaw: raw };
  const spki = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(raw, "base64url")]).toString("base64");
  const k = gatePinPublicKeyFromRaw(raw);
  const ind = independent(T, KID, spki);
  const r = gatePinFingerprintFromRaw(input);
  if (!k.ok || k.publicKey !== spki || !r.ok || r.fingerprint !== ind.fingerprint) fail(`${id}: the raw conversion disagrees`);
  vectors.push({ id, kind: "raw-key", expect: "ACCEPT", input, publicKey: spki, canonical: ind.canonical, digest: ind.digest, fingerprint: ind.fingerprint, equivalentTo });
}
function rejectRaw(id, input, code, extra = {}) {
  const r = gatePinFingerprintFromRaw(input);
  if (r.ok || r.code !== code) fail(`${id}: expected ${code}, got ${JSON.stringify(r)}`);
  vectors.push({ id, kind: "raw-key", expect: "REJECT", input, reasonCode: code, ...extra });
}

// ── ACCEPT ──────────────────────────────────────────────────────────────────────────────────────
accept("accept-basic", { tenant: T, gateKid: KID, publicKey: K1 });
accept("accept-kid-binds", { tenant: T, gateKid: "gate-example-2", publicKey: K1 }, "differs from accept-basic only in gateKid");
accept("accept-tenant-binds", { tenant: "tenant-example-2", gateKid: KID, publicKey: K1 }, "differs from accept-basic only in tenant");
accept("accept-key-binds", { tenant: T, gateKid: KID, publicKey: K2 }, "differs from accept-basic only in publicKey");
accept("accept-console-tenant", { tenant: CONSOLE_TENANT, gateKid: KID, publicKey: K1 }, "a console-style tenant identifier");
accept("accept-tenant-json-escapes", { tenant: 't"en\\ant', gateKid: KID, publicKey: K1 }, "JCS escapes the quotation mark and the reverse solidus in the tenant");
accept("accept-tenant-one-char", { tenant: "x", gateKid: KID, publicKey: K1 }, "the shortest tenant: one character");
accept("accept-tenant-edges", { tenant: "!~", gateKid: "g", publicKey: K1 }, "the first and last printable ASCII characters; a one-character kid");
accept("accept-lengths-max", { tenant: "t".repeat(256), gateKid: "g" + "a".repeat(62) + "1", publicKey: K2 }, "the longest tenant (256) and kid (64)");
accept("accept-extra-member-ignored", { tenant: T, gateKid: KID, publicKey: K1, environment: "production" }, "members other than the three are ignored: the fingerprint equals accept-basic");
acceptRaw("accept-raw-key", rawOf(K1), "accept-basic");
acceptRaw("accept-raw-key-2", rawOf(K2), "accept-key-binds");

// ── REJECT: one member at a time ────────────────────────────────────────────────────────────────
reject("reject-input-null", null, "GATE_PIN_INPUT_INVALID");
reject("reject-input-string", "tenant-example-1", "GATE_PIN_INPUT_INVALID");
const badTenants = [["absent", undefined], ["null", null], ["number", 1], ["empty", ""], ["space", "tenant example"], ["too-long", "t".repeat(257)], ["non-ascii", "tenánt"], ["control", "ten\tant"], ["del", "ten\u007fant"]];
for (const [n, v] of badTenants) {
  const input = { gateKid: KID, publicKey: K1 };
  if (v !== undefined) input.tenant = v;
  reject(`reject-tenant-${n}`, input, "GATE_PIN_TENANT_INVALID");
}
const badKids = [["absent", undefined], ["null", null], ["number", 1], ["empty", ""], ["upper", "Gate-example-1"], ["digit-first", "1gate"], ["hyphen-last", "gate-"], ["underscore", "gate_example"], ["too-long", "g" + "a".repeat(63) + "1"]];
for (const [n, v] of badKids) {
  const input = { tenant: T, publicKey: K1 };
  if (v !== undefined) input.gateKid = v;
  reject(`reject-kid-${n}`, input, "GATE_PIN_KID_INVALID");
}
const badKeys = [
  ["absent", undefined], ["null", null], ["number", 1], ["empty", ""],
  ["unpadded-base64", K1.replace(/=+$/, "")],
  ["base64url-spelling", Buffer.from(K1, "base64").toString("base64url")],
  ["raw-not-spki", rawOf(K1)],
  ["trailing-bytes", Buffer.concat([Buffer.from(K1, "base64"), Buffer.from([0])]).toString("base64")],
  ["non-canonical-bits", flipUnusedBit(K1, B64, "=")],
  ["extra-padding", K1 + "="],
  ["inner-space", K1.slice(0, 20) + " " + K1.slice(20)],
  ["inner-newline", K1.slice(0, 20) + "\n" + K1.slice(20)],
  ["x25519-spki", X25519],
  ["low-order", strict("keyring-low-order-0.json")],
  ["mixed-order", strict("keyring-mixed-order.json")],
  ["off-curve", strict("keyring-off-curve-y-2.json")],
  ["non-canonical-y", strict("keyring-y-p-plus-1.json")],
];
for (const [n, v] of badKeys) {
  const input = { tenant: T, gateKid: KID };
  if (v !== undefined) input.publicKey = v;
  reject(`reject-key-${n}`, input, "GATE_PIN_KEY_INVALID");
}

// ── REJECT: precedence, every adjacent pair of the fingerprint order, every category of the earlier
//    member against a malformed later one and a malformed earlier member against each category ──────
const cats = [["absent", undefined], ["null", null], ["number", 1], ["malformed", null]];
const malformed = { tenant: "tenant example", gateKid: "Gate-example-1", publicKey: rawOf(K1) };
const codes = { tenant: "GATE_PIN_TENANT_INVALID", gateKid: "GATE_PIN_KID_INVALID", publicKey: "GATE_PIN_KEY_INVALID" };
const valid = { tenant: T, gateKid: KID, publicKey: K1 };
for (const [first, second] of [["tenant", "gateKid"], ["gateKid", "publicKey"]]) {
  for (const [n, v] of cats) {
    const a = { ...valid };
    delete a[first];
    if (n === "malformed") a[first] = malformed[first];
    else if (v !== undefined) a[first] = v;
    a[second] = malformed[second];
    reject(`order-${first}-${n}-beats-${second}-malformed`, a, codes[first], { beats: codes[second] });
    if (n === "malformed") continue;
    const b = { ...valid };
    b[first] = malformed[first];
    delete b[second];
    if (v !== undefined) b[second] = v;
    reject(`order-${first}-malformed-beats-${second}-${n}`, b, codes[first], { beats: codes[second] });
  }
}
reject("order-input-array-beats-tenant-absent", [], "GATE_PIN_INPUT_INVALID", {
  beats: "GATE_PIN_TENANT_INVALID",
  note: "an array is not an object (RFC 8259): the input step refuses it before the tenant step, which would refuse its absent tenant",
});

// ── the raw-key order: input, tenant, kid, the raw spelling, the key ────────────────────────────────
const r1 = rawOf(K1);
const lowOrderRaw = rawOf(strict("keyring-low-order-0.json"));
const raw = (publicKeyRaw) => ({ tenant: T, gateKid: KID, publicKeyRaw });
rejectRaw("reject-raw-absent", raw(null), "GATE_PIN_RAW_KEY_INVALID");
rejectRaw("reject-raw-42", raw(r1.slice(0, 42)), "GATE_PIN_RAW_KEY_INVALID");
rejectRaw("reject-raw-44", raw(r1 + "A"), "GATE_PIN_RAW_KEY_INVALID");
rejectRaw("reject-raw-padded", raw(r1 + "="), "GATE_PIN_RAW_KEY_INVALID");
rejectRaw("reject-raw-plus", raw("+" + r1.slice(1)), "GATE_PIN_RAW_KEY_INVALID");
rejectRaw("reject-raw-slash", raw("/" + r1.slice(1)), "GATE_PIN_RAW_KEY_INVALID");
rejectRaw("reject-raw-non-canonical", raw(flipUnusedBit(r1, B64URL)), "GATE_PIN_RAW_KEY_INVALID");
rejectRaw("reject-raw-low-order", raw(lowOrderRaw), "GATE_PIN_KEY_INVALID");
rejectRaw("reject-raw-mixed-order", raw(rawOf(strict("keyring-mixed-order.json"))), "GATE_PIN_KEY_INVALID");
rejectRaw("order-raw-spelling-beats-key", raw(flipUnusedBit(lowOrderRaw, B64URL)), "GATE_PIN_RAW_KEY_INVALID", { beats: "GATE_PIN_KEY_INVALID" });
rejectRaw("order-raw-kid-malformed-beats-raw-malformed", { tenant: T, gateKid: "Gate-example-1", publicKeyRaw: r1.slice(0, 42) }, "GATE_PIN_KID_INVALID", { beats: "GATE_PIN_RAW_KEY_INVALID" });
rejectRaw("order-raw-kid-absent-beats-raw-malformed", { tenant: T, publicKeyRaw: r1.slice(0, 42) }, "GATE_PIN_KID_INVALID", { beats: "GATE_PIN_RAW_KEY_INVALID" });
rejectRaw("order-raw-kid-malformed-beats-raw-absent", { tenant: T, gateKid: "Gate-example-1" }, "GATE_PIN_KID_INVALID", { beats: "GATE_PIN_RAW_KEY_INVALID" });
rejectRaw("order-raw-tenant-malformed-beats-raw-malformed", { tenant: "tenant example", gateKid: KID, publicKeyRaw: r1.slice(0, 42) }, "GATE_PIN_TENANT_INVALID");

const doc = {
  spec: "noa.gate-pin/1",
  generatedFrom: "scripts/gen-gate-pin-vectors.mjs; every ACCEPT value is also recomputed independently (node:crypto SHA-256 over a hand-built JCS) by packages/gate/test/gate-pin.test.ts",
  refusalCodes: ["GATE_PIN_INPUT_INVALID", "GATE_PIN_TENANT_INVALID", "GATE_PIN_KID_INVALID", "GATE_PIN_KEY_INVALID", "GATE_PIN_RAW_KEY_INVALID"],
  note: "Synthetic identifiers only (tenant-example-N, gate-example-N, and an all-zero example UUID in the console-style tenant); the Ed25519 keys are freshly generated public keys with no use outside this corpus, and the refused keys come from conformance/vectors/strict-ed25519. A fingerprint vector's input is the object passed to the fingerprint function (an absent member is omitted); a raw-key vector's input carries publicKeyRaw instead of publicKey and is checked in the same order, its key step being the raw conversion (docs/gate-pin-spec.md §3.1, §5). ACCEPT vectors pin canonical (the JCS text), digest and fingerprint; REJECT vectors pin reasonCode; `beats` names the second rule a precedence vector's input violates, which reasonCode must win over; `equivalentTo` names the vector whose fingerprint a raw-key vector must equal. The fingerprint is a display string, never an authority input (docs/gate-pin-spec.md).",
  vectors,
};
const text = JSON.stringify(doc, null, 2) + "\n";
if (process.argv.includes("--check")) {
  const committed = readFileSync(OUT, "utf8");
  if (committed !== text) {
    process.stderr.write("gen-gate-pin-vectors: conformance/gate-pin/vectors.json differs from the generator's output; run the generator\n");
    process.exit(1);
  }
  process.stdout.write(`gen-gate-pin-vectors: OK — ${vectors.length} vectors match the generator\n`);
} else {
  writeFileSync(OUT, text);
  process.stdout.write(`gen-gate-pin-vectors: wrote ${vectors.length} vectors (${vectors.filter((v) => v.expect === "ACCEPT").length} ACCEPT, ${vectors.filter((v) => v.expect === "REJECT").length} REJECT)\n`);
}
