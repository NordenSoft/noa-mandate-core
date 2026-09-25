/**
 * `noa.gate-pin/1` (docs/gate-pin-spec.md) against its conformance corpus, conformance/gate-pin/vectors.json.
 *
 * Every ACCEPT value is recomputed here WITHOUT the implementation: SHA-256 from node:crypto over a JCS
 * text built by hand (the three members are ASCII strings, whose JCS form is their JSON string form),
 * and the SPKI from the fixed RFC 8410 prefix and the raw bytes. The implementation must then agree
 * with both the pinned value and that independent derivation.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import * as gatePin from "../src/gate-pin.js";
import { GATE_PIN_PREFIX, GATE_PIN_SPEC, gatePinFingerprint, gatePinPublicKeyFromRaw, type GatePinResult } from "../src/gate-pin.js";

/** The fingerprint of an identity whose key is a raw base64url key (docs/gate-pin-spec.md §3.1, §5). */
const fromRaw = (input: unknown): GatePinResult => (gatePin as unknown as Record<string, (i: unknown) => GatePinResult>)["gatePinFingerprintFromRaw"]!(input);

interface Vector {
  id: string;
  kind: "fingerprint" | "raw-key";
  expect: "ACCEPT" | "REJECT";
  input: unknown;
  canonical?: string;
  digest?: string;
  fingerprint?: string;
  publicKey?: string;
  reasonCode?: string;
  beats?: string;
  equivalentTo?: string;
}

// dist/test/gate-pin.test.js → the repository root is four levels up.
const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");
const corpus = JSON.parse(readFileSync(join(ROOT, "conformance", "gate-pin", "vectors.json"), "utf8")) as {
  spec: string;
  refusalCodes: string[];
  vectors: Vector[];
};

function independent(t: string, k: string, p: string): { canonical: string; digest: string; fingerprint: string } {
  const canonical = `{"gateKid":${JSON.stringify(k)},"publicKey":${JSON.stringify(p)},"spec":"noa.gate-pin/1","tenant":${JSON.stringify(t)}}`;
  const hex = createHash("sha256").update(Buffer.from(canonical, "utf8")).digest("hex");
  const groups = [0, 4, 8, 12, 16].map((i) => hex.slice(i, i + 4));
  return { canonical, digest: `sha256:${hex}`, fingerprint: `NOAGP1-${groups.join("-")}` };
}

function rawToSpki(raw: string): string {
  return Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(raw, "base64url")]).toString("base64");
}

function members(input: unknown): { tenant: string; gateKid: string; publicKey?: string; publicKeyRaw?: string } {
  return input as { tenant: string; gateKid: string; publicKey?: string; publicKeyRaw?: string };
}

test("GATE-PIN-VECTORS — every ACCEPT vector reproduces from an independent derivation and from the implementation; every REJECT vector refuses with its code", () => {
  assert.equal(corpus.spec, GATE_PIN_SPEC);
  assert.equal(GATE_PIN_PREFIX, "NOAGP1-");
  for (const v of corpus.vectors) {
    if (v.kind === "fingerprint") {
      const r = gatePinFingerprint(v.input);
      if (v.expect === "ACCEPT") {
        const m = members(v.input);
        const ind = independent(m.tenant, m.gateKid, m.publicKey as string);
        assert.deepEqual([ind.canonical, ind.digest, ind.fingerprint], [v.canonical, v.digest, v.fingerprint], `${v.id}: the pinned values are the independent derivation`);
        assert.ok(r.ok, `${v.id}: ${JSON.stringify(r)}`);
        assert.deepEqual([r.digest, r.fingerprint], [v.digest, v.fingerprint], `${v.id}: the implementation agrees`);
      } else {
        assert.equal(r.ok, false, `${v.id}: must be refused`);
        assert.equal(r.ok ? null : r.code, v.reasonCode, v.id);
      }
    } else {
      const m = members(v.input);
      const r = fromRaw(v.input);
      if (v.expect === "ACCEPT") {
        assert.equal(rawToSpki(m.publicKeyRaw as string), v.publicKey, `${v.id}: the pinned SPKI is the prefix and the raw bytes`);
        const k = gatePinPublicKeyFromRaw(m.publicKeyRaw);
        assert.ok(k.ok, `${v.id}: ${JSON.stringify(k)}`);
        assert.equal(k.publicKey, v.publicKey);
        const ind = independent(m.tenant, m.gateKid, k.publicKey);
        assert.ok(r.ok, `${v.id}: ${JSON.stringify(r)}`);
        assert.deepEqual([ind.canonical, ind.digest, ind.fingerprint, r.fingerprint], [v.canonical, v.digest, v.fingerprint, v.fingerprint], v.id);
      } else {
        assert.equal(r.ok, false, `${v.id}: must be refused`);
        assert.equal(r.ok ? null : r.code, v.reasonCode, v.id);
      }
    }
  }
});

test("GATE-PIN-CORPUS — every refusal code occurs, each precedence input really violates both rules, and every equivalent spelling pins one fingerprint", () => {
  const byId = new Map(corpus.vectors.map((v) => [v.id, v]));
  const seen = new Set(corpus.vectors.filter((v) => v.expect === "REJECT").map((v) => v.reasonCode));
  assert.deepEqual([...seen].sort(), [...corpus.refusalCodes].sort(), "every refusal code has a vector");
  const pairs = new Set<string>();
  for (const v of corpus.vectors.filter((x) => x.beats !== undefined)) {
    pairs.add(`${v.kind}:${v.reasonCode}>${v.beats}`);
    // Repair what the winning code names: the second rule must then refuse the same input.
    let repaired: unknown;
    if (v.reasonCode === "GATE_PIN_INPUT_INVALID") {
      repaired = Object.fromEntries(Object.entries(v.input as object).filter(([k]) => Number.isNaN(Number(k))));
    } else {
      const r = { ...(v.input as Record<string, unknown>) };
      if (v.reasonCode === "GATE_PIN_TENANT_INVALID") r["tenant"] = "tenant-example-1";
      else if (v.reasonCode === "GATE_PIN_KID_INVALID") r["gateKid"] = "gate-example-1";
      else if (v.reasonCode === "GATE_PIN_RAW_KEY_INVALID") r["publicKeyRaw"] = Buffer.from(r["publicKeyRaw"] as string, "base64url").toString("base64url");
      repaired = r;
    }
    const again = v.kind === "fingerprint" ? gatePinFingerprint(repaired) : fromRaw(repaired);
    assert.equal(again.ok ? null : again.code, v.beats, `${v.id}: the input also violates ${v.beats}`);
  }
  assert.deepEqual([...pairs].sort(), [
    "fingerprint:GATE_PIN_INPUT_INVALID>GATE_PIN_TENANT_INVALID",
    "fingerprint:GATE_PIN_KID_INVALID>GATE_PIN_KEY_INVALID",
    "fingerprint:GATE_PIN_TENANT_INVALID>GATE_PIN_KID_INVALID",
    "raw-key:GATE_PIN_KID_INVALID>GATE_PIN_RAW_KEY_INVALID",
    "raw-key:GATE_PIN_RAW_KEY_INVALID>GATE_PIN_KEY_INVALID",
  ], "every adjacent pair of both refusal orders is pinned");
  for (const v of corpus.vectors.filter((x) => x.equivalentTo !== undefined)) {
    assert.equal(v.fingerprint, byId.get(v.equivalentTo as string)?.fingerprint, `${v.id} equals ${v.equivalentTo}`);
  }
  // The shortest tenant the rule admits is pinned by an accepting vector.
  assert.ok(corpus.vectors.some((v) => v.expect === "ACCEPT" && members(v.input).tenant.length === 1), "a one-character tenant is accepted");
  const accepts = corpus.vectors.filter((v) => v.expect === "ACCEPT" && v.equivalentTo === undefined && v.id !== "accept-extra-member-ignored");
  assert.equal(new Set(accepts.map((v) => v.fingerprint)).size, accepts.length, "distinct identities, distinct fingerprints");
});

test("GATE-PIN-DISPLAY-ONLY — the function reads own members only and never throws on hostile input", () => {
  const inherited = Object.create({ tenant: "tenant-example-1", gateKid: "gate-example-1" }) as Record<string, unknown>;
  const r = gatePinFingerprint(inherited);
  assert.equal(r.ok ? null : r.code, "GATE_PIN_TENANT_INVALID", "inherited members are absent members");
  const throwing = { get tenant(): string { throw new Error("test: an unreadable member"); } };
  const t = gatePinFingerprint(throwing);
  assert.equal(t.ok ? null : t.code, "GATE_PIN_INPUT_INVALID", "an unreadable member is a refusal, not an exception");
  assert.equal(gatePinPublicKeyFromRaw(undefined).ok, false);
});
