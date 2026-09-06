import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import { test } from "node:test";

import { verifyEvidence } from "../src/verify-evidence.js";
import { buildReceiptKeyring, type ManifestDoc } from "../src/trust.js";
import { b } from "./helpers/bytes.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const CONF = join(HERE, "..", "..", "conformance");

interface Fixture {
  readonly now: string;
  readonly maxAgeHours: number;
  readonly purpose: "audit" | "authorize";
  readonly bundle: Record<string, unknown>;
  readonly tenantRoot: Record<string, unknown>;
  readonly checkpointKeyring: Record<string, unknown>;
}

function load(path: string): Fixture {
  return JSON.parse(readFileSync(join(CONF, path), "utf8")) as Fixture;
}

function run(fx: Fixture) {
  return verifyEvidence(b(fx.bundle), {
    tenantRoot: b(fx.tenantRoot),
    checkpointKeyring: b(fx.checkpointKeyring),
    purpose: fx.purpose,
    now: fx.now,
    maxAgeMs: fx.maxAgeHours * 60 * 60 * 1000,
  });
}

function receiptChain(bundle: Record<string, unknown>): unknown[] {
  return [bundle.deferredReceipt, bundle.allowedReceipt, bundle.executedReceipt];
}

test("G2 E -> E+: truthful later retirement preserves intact authenticated history", () => {
  const e = load("control/g2-history-e-current.json");
  const ePlus = load("control/g2-history-eplus-retired-audit.json");

  // Anti-vacuity: E and E+ present the exact same receipt bytes and checkpoint. Only the separately
  // signed lifecycle-bearing evidence world differs.
  assert.deepEqual(receiptChain(ePlus.bundle), receiptChain(e.bundle));
  assert.deepEqual(ePlus.bundle.checkpoint, e.bundle.checkpoint);

  const before = run(e);
  const after = run(ePlus);
  assert.equal(before.verdict, "VALID_FULL_CHAIN");
  assert.equal(before.dimensions.integrity, "INTACT");
  assert.equal(before.dimensions.historical, undefined, "active-key compatibility path unexpectedly changed");

  assert.equal(after.verdict, "VALID_FULL_CHAIN");
  assert.equal(after.dimensions.integrity, "INTACT");
  assert.equal(after.policy.verifierVersion, "noa.verify-evidence/2026-09-06");
  const historical = after.dimensions.historical;
  assert.ok(historical, "audit did not expose the canonical historical result");
  assert.equal(historical.spec, "noa.historical-verification/0.1");
  assert.equal(historical.classification, "VERIFIED");
  assert.equal(historical.code, "HEAD_ANCHORED");
  assert.equal(historical.dimensions.integrity, "INTACT");
  assert.equal(historical.dimensions.completeness, "HEAD_ANCHORED");
  assert.equal(historical.dimensions.attribution, "ATTRIBUTABLE_AS_OF");
  assert.equal(historical.dimensions.evidence.retirement, "PROVIDED");
  assert.equal(historical.dimensions.evidence.witness, "PROVIDED");
  assert.equal(historical.dimensions.evidence.availability, "AVAILABLE");
  assert.equal(historical.dimensions.organizationalIndependence, "UNVERIFIED");
  assert.notEqual(historical.dimensions.evidence.availability, "PROVEN_SUPPRESSED");

  const manifest = ePlus.bundle.keyManifest as { keys: Array<{ kid: string; validFrom: string; revokedAt: string | null }> };
  const receiptKey = manifest.keys.find((key) => key.kid === "receipt-history-1");
  const retiredAt = receiptKey?.revokedAt;
  assert.equal(retiredAt, "2026-07-14T11:59:30.000Z", "fixture did not carry actual lifecycle retirement");
  assert.equal(receiptKey?.validFrom, "2026-07-14T10:00:00.000Z", "fixture did not carry actual lifecycle activation");
  assert.ok(Date.parse(historical.asOf!) >= Date.parse(receiptKey!.validFrom), "checkpoint must be at/after activation");
  assert.ok(Date.parse(historical.asOf!) < Date.parse(retiredAt!), "checkpoint must strictly predate retirement");
  assert.ok(Date.parse(retiredAt!) < Date.parse(ePlus.now), "verification must occur after retirement");
});

test("G2 evidence audit binds projection to the checkpoint's full explicit lifecycle interval", () => {
  const before = load("reject/g2-history-checkpoint-before-activation.json");
  const at = load("control/g2-history-checkpoint-at-activation-lowercase.json");

  const beforeResult = run(before);
  assert.equal(beforeResult.verdict, "INVALID");
  assert.equal(beforeResult.failedStep, "STEP_18_TEMPORAL_AUTHORIZATION");
  assert.equal(beforeResult.code, "E_TEMPORAL_AUTH");
  assert.equal(beforeResult.dimensions.integrity, "INTACT");
  assert.equal(beforeResult.dimensions.historical?.code, "CHECKPOINT_BEFORE_ACTIVATION");
  assert.equal(beforeResult.dimensions.historical?.dimensions.completeness, "HEAD_ANCHORED");
  assert.equal(beforeResult.dimensions.historical?.dimensions.attribution, "UNATTRIBUTABLE");

  const atResult = run(at);
  assert.equal(atResult.verdict, "VALID_FULL_CHAIN");
  assert.equal(atResult.dimensions.historical?.classification, "VERIFIED");
  assert.equal(atResult.dimensions.historical?.dimensions.attribution, "ATTRIBUTABLE_AS_OF");
  const manifest = at.bundle.keyManifest as { keys: Array<{ kid: string; validFrom: string }> };
  const validFrom = manifest.keys.find((key) => key.kid === "receipt-history-1")?.validFrom;
  assert.equal(validFrom, "2026-07-14t11:59:00.000z");
  assert.equal(Date.parse(atResult.dimensions.historical!.asOf!), Date.parse(validFrom!), "activation boundary must be inclusive");
});

test("[PROOF:RES-PAR-G2-LIFECYCLE] G2 receipt lifecycle projection preserves explicit validFrom and legacy absence", () => {
  const ePlus = load("control/g2-history-eplus-retired-audit.json");
  const projected = buildReceiptKeyring(ePlus.bundle.keyManifest as ManifestDoc);
  const explicit = projected.keys["receipt-history-1"]!;
  assert.equal(explicit.validFrom, "2026-07-14T10:00:00.000Z");

  const publicKey = explicit.publicKey;
  const legacyManifest = {
    keys: [{ kid: "legacy-receipt", type: "GATE", roles: [], publicKey, revokedAt: "2026-07-14T11:59:30.000Z" }],
  } as unknown as ManifestDoc;
  const legacy = buildReceiptKeyring(legacyManifest).keys["legacy-receipt"]!;
  assert.deepEqual(Object.keys(legacy).sort(), ["publicKey", "retiredAt"], "an absent source validFrom was fabricated");
});

test("G2 current authorization remains fail-closed on the exact retired-key history", () => {
  const audit = load("control/g2-history-eplus-retired-audit.json");
  const authorize = load("reject/g2-history-eplus-retired-authorize.json");
  assert.deepEqual(authorize.bundle, audit.bundle, "purpose control does not use the same evidence bytes");
  assert.deepEqual(authorize.checkpointKeyring, audit.checkpointKeyring);

  const res = run(authorize);
  assert.equal(res.verdict, "INVALID");
  assert.equal(res.failedStep, "STEP_17_CHECKPOINT_RECONCILE");
  assert.equal(res.code, "E_CHECKPOINT_RECONCILE");
  assert.equal(res.dimensions.historical, undefined, "authorize must not enter historical verification");
});

test("G2 untrusted witness stays UNANSWERED and is never relabelled broken", () => {
  const fx = load("control/g2-history-eplus-retired-audit.json");
  const witnessPublicKey = Object.values(fx.checkpointKeyring)[0];
  assert.equal(typeof witnessPublicKey, "string", "fixture checkpoint root is empty");
  const result = verifyEvidence(b(fx.bundle), {
    tenantRoot: b(fx.tenantRoot),
    checkpointKeyring: b({ "unrelated-witness-id": witnessPublicKey }),
    purpose: "audit",
    now: fx.now,
    maxAgeMs: fx.maxAgeHours * 60 * 60 * 1000,
  });

  assert.equal(result.verdict, "INVALID");
  assert.equal(result.failedStep, "STEP_18_TEMPORAL_AUTHORIZATION");
  assert.equal(result.dimensions.integrity, "UNANSWERED");
  assert.equal(result.dimensions.historical?.code, "WITNESS_KEY_NOT_TRUSTED");
  assert.equal(result.dimensions.historical?.dimensions.integrity, "UNANSWERED");
});

test("G2 lifecycle projection uses captured collections and a null-prototype key map", () => {
  // This is a mechanical security invariant over the exact private helper. The evidence corpus's
  // intrinsic-poison suite exercises the same E+ fixture under Set/Object prototype mutation; this
  // pin prevents a future refactor from reintroducing the native constructor, Array.from iterator,
  // or object-spread projection that those poisons target.
  const source = readFileSync(join(HERE, "..", "..", "src", "verify-evidence.ts"), "utf8");
  const start = source.indexOf("function historicalTemporalAuthorization(");
  const end = source.indexOf("\n}\n\n/**\n * Verify an Approval Evidence Bundle", start);
  assert.ok(start >= 0 && end > start, "could not isolate historicalTemporalAuthorization source");
  const body = source.slice(start, end);
  assert.match(body, /newSet<unknown>\(\)/);
  assert.match(body, /newSet<string>\(\)/);
  assert.match(body, /setToArray\(receiptKids\)/);
  assert.match(body, /objectCreateNull<Record<string, KeyEntry>>\(\)/);
  assert.match(body, /objectCreateNull<KeyEntry>\(\)/);
  assert.doesNotMatch(body, /new Set/);
  assert.doesNotMatch(body, /Array\.from/);
  assert.doesNotMatch(body, /\.\.\.original|\.\.\.entry/);
});
