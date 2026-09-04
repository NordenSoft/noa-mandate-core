#!/usr/bin/env node

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync, chmodSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { pathToFileURL } from "node:url";

import {
  appendBoundaryLedgerRecord,
  boundaryEvidenceSpoolDirectory,
  boundarySpoolTestDependencies,
  HISTORICAL_BOUNDARY_EVIDENCE_NON_CLAIM,
  inspectBoundaryEvidenceSpool,
  prepareBoundaryEvidenceRecord,
} from "./boundary-ledger.mjs";
import {
  BOUNDARY_AUTHORITY_CLASS_CANDIDATE_TIER_A,
  CANDIDATE_TIER_A_NON_AUTHORITY_NON_CLAIM,
} from "./boundary-bootstrap.mjs";
import { unverifiedGateProvenance } from "./gate-event-contract.mjs";

const scratch = mkdtempSync(join(tmpdir(), "noa-boundary-ledger-v3-selftest-"));
chmodSync(scratch, 0o700);
let passed = 0;

function test(name, body) {
  body();
  passed++;
  process.stderr.write(`  PASS ${name}\n`);
}

function spool(name, version = 3) {
  const parent = join(scratch, name);
  mkdirSync(parent, { mode: 0o700 });
  chmodSync(parent, 0o700);
  return join(parent, ".noa-boundary", `evidence-spool-v${version}`, "prepush");
}

const provenance = Object.freeze({
  authorityClass: BOUNDARY_AUTHORITY_CLASS_CANDIDATE_TIER_A,
  authorityNonClaim: CANDIDATE_TIER_A_NON_AUTHORITY_NON_CLAIM,
  bootstrapMode: "candidate-tier-a-non-authority",
  controlManifestDigest: "1".repeat(64),
  controlManifestVersion: 2,
  externalAuthorizationSha256: null,
  schemaVersion: 1,
  subject: Object.freeze({
    archiveSha256: "2".repeat(64),
    commit: "3".repeat(40),
    repository: "example/public",
    tree: "4".repeat(40),
  }),
  tier: "a",
  verification: "VERIFIED_BOOTSTRAP",
  visibilitySource: "snapshot",
});

const metrics = Object.freeze({
  greenSteps: 1,
  overrideReasonSha256: null,
  overrideReasonUtf8Bytes: 0,
  redSteps: 0,
  setupFailedSteps: 0,
  skippedSteps: 0,
  stepCount: 1,
});

function input(spoolDirectoryPath, overrides = {}) {
  return {
    spoolDirectoryPath,
    event: "PREPUSH_GATE_VERDICT",
    repositoryHead: "5".repeat(40),
    verdict: "GREEN",
    metrics,
    provenance,
    at: "2026-09-01T00:00:00.000Z",
    ...overrides,
  };
}

function dependencies(seed, extra = {}) {
  const hex = seed.toString(16).padStart(2, "0").slice(-2);
  return boundarySpoolTestDependencies({
    pendingNonceHex: hex.repeat(16),
    recordNonceHex: hex.repeat(32),
    statfs: { bavail: "1000000", blocks: "2000000", bsize: "4096" },
    ...extra,
  });
}

try {
  test("schema-v3 green requires and preserves exact candidate provenance", () => {
    const target = spool("v3");
    const result = appendBoundaryLedgerRecord(input(target), dependencies(1));
    assert.equal(result.ok, true);
    assert.match(result.filename, /^record-v3-/);
    const census = inspectBoundaryEvidenceSpool({ spoolDirectoryPath: target, event: "PREPUSH_GATE_VERDICT" });
    assert.equal(census.validCount, 1);
    assert.equal(census.provenanceBoundCount, 1);
    assert.equal(census.historicalCount, 0);
  });

  test("production writer refuses missing provenance before creating a spool", () => {
    const target = spool("missing");
    const { provenance: omitted, ...withoutProvenance } = input(target);
    assert.equal(omitted, provenance);
    const result = appendBoundaryLedgerRecord(withoutProvenance);
    assert.equal(result.ok, false);
    assert.equal(result.code, "RECORD_PROVENANCE_REQUIRED");
    assert.equal(result.filename, null);
  });

  test("malformed and unverified green provenance are rejected", () => {
    const malformed = appendBoundaryLedgerRecord(
      input(spool("malformed"), { provenance: { ...provenance, authorityNonClaim: "WRONG_NONCLAIM" } }),
      dependencies(2),
    );
    assert.equal(malformed.ok, false);
    assert.equal(malformed.code, "RECORD_SCHEMA_REJECTED");
    const unverified = appendBoundaryLedgerRecord(
      input(spool("unverified"), {
        provenance: unverifiedGateProvenance({ tier: "a", visibilitySource: "snapshot" }),
      }),
      dependencies(3),
    );
    assert.equal(unverified.ok, false);
    assert.equal(unverified.code, "RECORD_SCHEMA_REJECTED");
    const setupTarget = spool("unverified-setup");
    const setupFailed = appendBoundaryLedgerRecord(
      input(setupTarget, {
        verdict: "SETUP_FAILED",
        provenance: unverifiedGateProvenance(),
      }),
      dependencies(8),
    );
    assert.equal(setupFailed.ok, true);
    const setupRecord = JSON.parse(readFileSync(join(setupTarget, setupFailed.filename), "utf8"));
    assert.equal(setupRecord.provenance.verification, "UNVERIFIED_BOOTSTRAP");
    assert.equal(setupRecord.provenance.tier, null);
    assert.equal(setupRecord.provenance.visibilitySource, null);
  });

  test("schema-v2 remains readable only as historical non-authority", () => {
    assert.match(HISTORICAL_BOUNDARY_EVIDENCE_NON_CLAIM, /HISTORICAL_NON_AUTHORITY/);
    const target = spool("historical", 2);
    const { provenance: omitted, ...legacyInput } = input(target);
    assert.equal(omitted, provenance);
    const result = appendBoundaryLedgerRecord(legacyInput, dependencies(4));
    assert.equal(result.ok, true);
    assert.match(result.filename, /^record-v2-/);
    const census = inspectBoundaryEvidenceSpool({ spoolDirectoryPath: target, event: "PREPUSH_GATE_VERDICT" });
    assert.equal(census.validCount, 1);
    assert.equal(census.historicalCount, 1);
    assert.equal(census.provenanceBoundCount, 0);
  });

  test("a schema-v2 body under a schema-v3 filename is malformed, never upgraded", () => {
    const target = spool("wrong-version", 2);
    mkdirSync(target, { recursive: true, mode: 0o700 });
    chmodSync(join(scratch, "wrong-version", ".noa-boundary"), 0o700);
    chmodSync(join(scratch, "wrong-version", ".noa-boundary", "evidence-spool-v2"), 0o700);
    chmodSync(target, 0o700);
    const { provenance: omitted, ...legacyInput } = input(target);
    assert.equal(omitted, provenance);
    const prepared = prepareBoundaryEvidenceRecord(legacyInput, dependencies(5));
    const wrongName = prepared.filename.replace("record-v2-", "record-v3-");
    writeFileSync(join(target, wrongName), prepared.bytes, { flag: "wx", mode: 0o400 });
    chmodSync(join(target, wrongName), 0o400);
    const census = inspectBoundaryEvidenceSpool({ spoolDirectoryPath: target, event: "PREPUSH_GATE_VERDICT" });
    assert.equal(census.validCount, 0);
    assert.equal(census.malformedCount, 1);
  });

  test("schema-v3 crash after durable directory sync is readable and idempotently recoverable", () => {
    const target = spool("crash");
    const payload = input(target, { at: "2026-09-01T00:00:01.000Z" });
    const options = {
      pendingNonceHex: "66".repeat(16),
      recordNonceHex: "77".repeat(32),
      statfs: { bavail: "1000000", blocks: "2000000", bsize: "4096" },
      faultAction: "crash",
      faultCode: "EIO",
      faultPoint: "publish-dir-fsync-after",
    };
    const moduleUrl = pathToFileURL(join(process.cwd(), "scripts", "lib", "boundary-ledger.mjs")).href;
    const source = [
      "const [moduleUrl, payloadText, optionsText] = process.argv.slice(1);",
      "const api = await import(moduleUrl);",
      "api.appendBoundaryLedgerRecord(JSON.parse(Buffer.from(payloadText, 'base64url').toString('utf8')), api.boundarySpoolTestDependencies(JSON.parse(Buffer.from(optionsText, 'base64url').toString('utf8'))));",
    ].join("\n");
    const child = spawnSync(process.execPath, [
      "--input-type=module", "--eval", source,
      moduleUrl,
      Buffer.from(JSON.stringify(payload), "utf8").toString("base64url"),
      Buffer.from(JSON.stringify(options), "utf8").toString("base64url"),
    ], { cwd: process.cwd(), encoding: "utf8", shell: false, timeout: 30_000 });
    assert.equal(child.status, null);
    assert.equal(child.signal, "SIGKILL");
    const afterCrash = inspectBoundaryEvidenceSpool({ spoolDirectoryPath: target, event: "PREPUSH_GATE_VERDICT" });
    assert.equal(afterCrash.provenanceBoundCount, 1);
    assert.equal(afterCrash.historicalCount, 0);
    const recovered = appendBoundaryLedgerRecord(payload, boundarySpoolTestDependencies({
      pendingNonceHex: options.pendingNonceHex,
      recordNonceHex: options.recordNonceHex,
      statfs: options.statfs,
    }));
    assert.equal(recovered.ok, true);
    assert.equal(recovered.idempotent, true);
    assert.equal(recovered.recordId, JSON.parse(readFileSync(join(target, recovered.filename), "utf8")).recordId);
  });

  process.stderr.write(`boundary ledger provenance selftest: PASS ${passed}/6\n`);
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
