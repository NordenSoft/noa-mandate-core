#!/usr/bin/env node

import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import { test } from "node:test";
import {
  BOUNDARY_CUSTODY_ADAPTER_VERSION,
  BOUNDARY_EXTERNAL_TRANSACTION_NAMES,
  createBoundaryV3PolicyBytes,
  deriveBoundaryAuthorityBundleIdentity,
  executeBoundaryFreshV3RotationTransaction,
  executeBoundaryV2RecoveryTransaction,
} from "./boundary-external-authority.mjs";
import {
  canonicalBoundaryJson,
  PREVIOUS_REVIEWED_CONTROL_PATHS,
  REVIEWED_CONTROL_PATHS,
} from "./boundary-bootstrap.mjs";

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const canonicalBytes = (value) => Buffer.from(`${canonicalBoundaryJson(value)}\n`, "utf8");
const transactionIdFromBody = (body) => sha256(Buffer.from(canonicalBoundaryJson({
  stage: body.stage,
  predecessor: body.predecessor,
  observedActive: body.observedActive,
  successor: body.successor,
  legacy: body.legacy,
}), "utf8"));
const resignTransaction = (kind, body) => canonicalBytes({
  body,
  [`${kind}Mac`]: createHmac("sha256", key)
    .update(`noa-boundary/exclusion-policy-transaction-${kind}/v1\0`, "utf8")
    .update(canonicalBoundaryJson(body), "utf8")
    .digest("hex"),
});
const key = Buffer.alloc(32, 0x61);
const keyId = sha256(key);
const legacyBytes = Buffer.from("synthetic-token # reviewed collision\n", "utf8");
const legacySha256 = sha256(legacyBytes);
const entries = [{ token: "synthetic-token", reason: "reviewed collision" }];
const nowMs = Date.now();
const observedAt = new Date(nowMs).toISOString();
const syntheticReviewSession = (suffix) => [
  "00000000", "0000", "4000", "8000", String(suffix).padStart(12, "0"),
].join("-");
const OLD_REVIEW_SESSION = syntheticReviewSession(1);
const FRESH_REVIEW_SESSION = syntheticReviewSession(2);
assert.equal(
  OLD_REVIEW_SESSION,
  Buffer.from("30303030303030302d303030302d343030302d383030302d303030303030303030303031", "hex").toString("utf8"),
);
assert.equal(
  FRESH_REVIEW_SESSION,
  Buffer.from("30303030303030302d303030302d343030302d383030302d303030303030303030303032", "hex").toString("utf8"),
);
const oldReview = Object.freeze({
  reviewer: "synthetic external supervisor fixture",
  reviewedAt: new Date(nowMs - 86_400_000).toISOString(),
  expiresAt: new Date(nowMs + 5 * 86_400_000).toISOString(),
  reviewSession: OLD_REVIEW_SESSION,
  classification: "PUBLIC_DERIVED_COLLISION",
  publicArtifact: "synthetic-authority@0.0.1",
  publicArtifactSRI: `sha512-${Buffer.alloc(64, 0x11).toString("base64")}`,
});
const freshReview = Object.freeze({
  ...oldReview,
  reviewedAt: new Date(nowMs - 1_000).toISOString(),
  expiresAt: new Date(nowMs + 10 * 86_400_000).toISOString(),
  reviewSession: FRESH_REVIEW_SESSION,
  publicArtifact: "synthetic-authority@0.0.2",
  publicArtifactSRI: `sha512-${Buffer.alloc(64, 0x22).toString("base64")}`,
});
const historicalDigest = sha256("historical exact seven controls");
const expandedManifest = Object.freeze({
  digest: sha256("expanded exact current controls"),
  paths: REVIEWED_CONTROL_PATHS,
  version: 2,
});
const bundleIdentity = deriveBoundaryAuthorityBundleIdentity({
  version: "synthetic-pinned-bundle-v1",
  files: [
    { byteLength: 17, path: "scripts/lib/boundary-bootstrap.mjs", sha256: sha256("bootstrap fixture") },
    { byteLength: 16, path: "scripts/lib/boundary-external-authority.mjs", sha256: sha256("authority fixture") },
  ],
});

function v2PolicyBytes() {
  const body = {
    schemaVersion: 2,
    keyId,
    reviewer: oldReview.reviewer,
    reviewedAt: oldReview.reviewedAt,
    expiresAt: oldReview.expiresAt,
    reviewSession: oldReview.reviewSession,
    repositoryHead: "1".repeat(40),
    classification: oldReview.classification,
    publicArtifact: oldReview.publicArtifact,
    publicArtifactSRI: oldReview.publicArtifactSRI,
    legacyByteLength: legacyBytes.length,
    legacySha256,
    entries,
  };
  return Buffer.from(`${JSON.stringify({
    ...body,
    mac: createHmac("sha256", key)
      .update("noa-boundary/exclusion-policy/v2\0", "utf8")
      .update(JSON.stringify(body), "utf8")
      .digest("hex"),
  }, null, 2)}\n`, "utf8");
}

function historicalV3PolicyBytes() {
  const body = {
    schemaVersion: 3,
    keyId,
    reviewer: oldReview.reviewer,
    reviewedAt: oldReview.reviewedAt,
    expiresAt: oldReview.expiresAt,
    reviewSession: oldReview.reviewSession,
    classification: oldReview.classification,
    publicArtifact: oldReview.publicArtifact,
    publicArtifactSRI: oldReview.publicArtifactSRI,
    controlManifestVersion: 1,
    controlManifestFiles: PREVIOUS_REVIEWED_CONTROL_PATHS,
    controlManifestDigest: historicalDigest,
    legacyByteLength: legacyBytes.length,
    legacySha256,
    entries,
  };
  return canonicalBytes({
    ...body,
    mac: createHmac("sha256", key)
      .update("noa-boundary/exclusion-policy/v3\0", "utf8")
      .update(canonicalBoundaryJson(body), "utf8")
      .digest("hex"),
  });
}

class MemoryCustody {
  constructor(records, crashAfter = null) {
    this.schemaVersion = BOUNDARY_CUSTODY_ADAPTER_VERSION;
    this.records = records;
    this.crashAfter = crashAfter;
    this.log = [];
  }

  checkpoint(label) {
    this.log.push(label);
    if (this.crashAfter === label) {
      this.crashAfter = null;
      throw new Error(`SYNTHETIC_PROCESS_CRASH_AFTER:${label}`);
    }
  }

  readExact(name) {
    const bytes = this.records.get(name);
    return bytes === undefined ? null : Buffer.from(bytes);
  }

  createDurableExclusive({ name, bytes }) {
    if (this.records.has(name)) throw new Error(`SYNTHETIC_EXCLUSIVE_CONFLICT:${name}`);
    this.records.set(name, Buffer.from(bytes));
    this.checkpoint(`create:${name}`);
  }

  replaceDurableExact({ name, expectedBytes, nextBytes }) {
    assert.deepEqual(this.records.get(name), expectedBytes);
    this.records.set(name, Buffer.from(nextBytes));
    this.checkpoint(`replace:${name}`);
  }

  removeDurableExact({ name, expectedBytes }) {
    assert.deepEqual(this.records.get(name), expectedBytes);
    this.records.delete(name);
    this.checkpoint(`remove:${name}`);
  }
}

const recoveryArgs = (custody, rawV2Name) => ({
  activeName: "exclusions.json",
  bundleIdentity,
  custody,
  keyBytes: key,
  legacyBytes,
  observedAt,
  rawV2Name,
});

test("recovery authenticates raw v2 and active v3/7, preserves active bytes, and records receipt before deletion", () => {
  const rawV2Name = `exclusions.superseded-v2-${sha256(v2PolicyBytes())}.json`;
  const active = historicalV3PolicyBytes();
  const records = new Map([[rawV2Name, v2PolicyBytes()], ["exclusions.json", active]]);
  const custody = new MemoryCustody(records);
  const result = executeBoundaryV2RecoveryTransaction(recoveryArgs(custody, rawV2Name));
  assert.equal(result.transaction.stage, "RECOVER_RAW_V2_TO_EXACT_ACTIVE_V3");
  assert.deepEqual(records.get("exclusions.json"), active);
  assert.equal(records.has(rawV2Name), false);
  assert.equal(records.has(BOUNDARY_EXTERNAL_TRANSACTION_NAMES.recoveryReceipt), true);
  assert.equal(records.has(BOUNDARY_EXTERNAL_TRANSACTION_NAMES.recoveryIntent), true);
  assert.ok(
    custody.log.indexOf(`create:${BOUNDARY_EXTERNAL_TRANSACTION_NAMES.recoveryAuthorization}`)
      < custody.log.indexOf(`remove:${rawV2Name}`),
    "raw v2 deletion must occur only after the durable pre-effect receipt",
  );
  const resumed = executeBoundaryV2RecoveryTransaction(recoveryArgs(new MemoryCustody(records), rawV2Name));
  assert.equal(resumed.transaction.receiptSha256, result.transaction.receiptSha256);
});

test("recovery and fresh rotation survive post-write crashes and produce two distinct receipts", () => {
  const rawBytes = v2PolicyBytes();
  const rawV2Name = `exclusions.superseded-v2-${sha256(rawBytes)}.json`;
  const active = historicalV3PolicyBytes();
  const records = new Map([[rawV2Name, rawBytes], ["exclusions.json", active]]);
  const crashingRecovery = new MemoryCustody(
    records,
    `create:${BOUNDARY_EXTERNAL_TRANSACTION_NAMES.recoveryAuthorization}`,
  );
  assert.throws(
    () => executeBoundaryV2RecoveryTransaction(recoveryArgs(crashingRecovery, rawV2Name)),
    /SYNTHETIC_PROCESS_CRASH_AFTER/,
  );
  assert.equal(records.has(rawV2Name), true, "raw predecessor survives a crash immediately after receipt write");
  const recovery = executeBoundaryV2RecoveryTransaction(recoveryArgs(new MemoryCustody(records), rawV2Name));
  assert.deepEqual(records.get("exclusions.json"), active, "recovery-only cannot rewrite active bytes or metadata");

  const successor = createBoundaryV3PolicyBytes({
    candidateManifest: expandedManifest,
    keyBytes: key,
    legacyBytes,
    nowMs,
    review: freshReview,
  });
  const staleExpanded = createBoundaryV3PolicyBytes({
    candidateManifest: expandedManifest,
    keyBytes: key,
    legacyBytes,
    nowMs,
    review: oldReview,
  });
  assert.throws(() => executeBoundaryFreshV3RotationTransaction({
    activeName: "exclusions.json",
    bundleIdentity,
    candidateManifest: expandedManifest,
    custody: new MemoryCustody(new Map(records)),
    keyBytes: key,
    legacyBytes,
    observedAt,
    successorPolicyBytes: staleExpanded,
  }), /EXTERNAL_FRESH_ROTATION_METADATA_NOT_FRESH/);

  const beforeEffectRecords = new Map([...records].map(([name, bytes]) => [name, Buffer.from(bytes)]));
  const beforeEffectCrash = new MemoryCustody(
    beforeEffectRecords,
    `create:${BOUNDARY_EXTERNAL_TRANSACTION_NAMES.rotationAuthorization}`,
  );
  assert.throws(() => executeBoundaryFreshV3RotationTransaction({
    activeName: "exclusions.json",
    bundleIdentity,
    candidateManifest: expandedManifest,
    custody: beforeEffectCrash,
    keyBytes: key,
    legacyBytes,
    observedAt,
    successorPolicyBytes: successor,
  }), /SYNTHETIC_PROCESS_CRASH_AFTER/);
  assert.deepEqual(beforeEffectRecords.get("exclusions.json"), active, "durable pre-effect receipt precedes replacement");
  assert.equal(beforeEffectRecords.has(BOUNDARY_EXTERNAL_TRANSACTION_NAMES.rotationAuthorization), true);
  assert.equal(beforeEffectRecords.has(BOUNDARY_EXTERNAL_TRANSACTION_NAMES.rotationReceipt), false);

  const crashingRotation = new MemoryCustody(records, "replace:exclusions.json");
  assert.throws(() => executeBoundaryFreshV3RotationTransaction({
    activeName: "exclusions.json",
    bundleIdentity,
    candidateManifest: expandedManifest,
    custody: crashingRotation,
    keyBytes: key,
    legacyBytes,
    observedAt,
    successorPolicyBytes: successor,
  }), /SYNTHETIC_PROCESS_CRASH_AFTER/);
  assert.deepEqual(records.get("exclusions.json"), successor);
  assert.equal(records.has(BOUNDARY_EXTERNAL_TRANSACTION_NAMES.rotationAuthorization), true);
  assert.equal(records.has(BOUNDARY_EXTERNAL_TRANSACTION_NAMES.rotationPredecessor), true);
  assert.equal(records.has(BOUNDARY_EXTERNAL_TRANSACTION_NAMES.rotationReceipt), false);

  const rotationCustody = new MemoryCustody(records);
  const rotation = executeBoundaryFreshV3RotationTransaction({
    activeName: "exclusions.json",
    bundleIdentity,
    candidateManifest: expandedManifest,
    custody: rotationCustody,
    keyBytes: key,
    legacyBytes,
    observedAt,
    successorPolicyBytes: successor,
  });
  assert.notEqual(rotation.transaction.receiptSha256, recovery.transaction.receiptSha256);
  assert.equal(records.has(BOUNDARY_EXTERNAL_TRANSACTION_NAMES.recoveryReceipt), true);
  assert.equal(records.has(BOUNDARY_EXTERNAL_TRANSACTION_NAMES.rotationReceipt), true);
  assert.equal(records.has(BOUNDARY_EXTERNAL_TRANSACTION_NAMES.rotationPredecessor), false);
  assert.equal(records.has(BOUNDARY_EXTERNAL_TRANSACTION_NAMES.rotationIntent), true);
  assert.ok(
    rotationCustody.log.indexOf(`create:${BOUNDARY_EXTERNAL_TRANSACTION_NAMES.rotationReceipt}`)
      < rotationCustody.log.indexOf(`remove:${BOUNDARY_EXTERNAL_TRANSACTION_NAMES.rotationPredecessor}`),
    "fresh predecessor cleanup follows exact completion receipt read-back",
  );
  const successorDoc = JSON.parse(successor.toString("utf8"));
  assert.equal(successorDoc.reviewSession, freshReview.reviewSession);
  assert.equal(successorDoc.controlManifestVersion, expandedManifest.version);
  assert.deepEqual(successorDoc.controlManifestFiles, [...expandedManifest.paths]);

  const resumed = executeBoundaryFreshV3RotationTransaction({
    activeName: "exclusions.json",
    bundleIdentity,
    candidateManifest: expandedManifest,
    custody: new MemoryCustody(records),
    keyBytes: key,
    legacyBytes,
    observedAt,
    successorPolicyBytes: successor,
  });
  assert.equal(resumed.transaction.receiptSha256, rotation.transaction.receiptSha256);
});

test("HMAC-valid retained transaction records cannot cross stage, state, legacy, id, or time", () => {
  const rawBytes = v2PolicyBytes();
  const rawV2Name = `exclusions.superseded-v2-${sha256(rawBytes)}.json`;
  const seed = () => {
    const records = new Map([[rawV2Name, rawBytes], ["exclusions.json", historicalV3PolicyBytes()]]);
    const custody = new MemoryCustody(records, `create:${BOUNDARY_EXTERNAL_TRANSACTION_NAMES.recoveryIntent}`);
    assert.throws(() => executeBoundaryV2RecoveryTransaction(recoveryArgs(custody, rawV2Name)), /SYNTHETIC_PROCESS_CRASH_AFTER/);
    return records;
  };
  const mutations = [
    {
      name: "stale stage",
      mutate: (body) => ({ ...body, stage: "ROTATE_ACTIVE_V3_TO_EXPANDED_V3" }),
    },
    {
      name: "wrong predecessor from another transaction",
      mutate: (body) => {
        const changed = {
          ...body,
          predecessor: { ...body.predecessor, sha256: "a".repeat(64) },
        };
        return { ...changed, transactionId: transactionIdFromBody(changed) };
      },
    },
    {
      name: "wrong legacy evidence",
      mutate: (body) => {
        const changed = { ...body, legacy: { ...body.legacy, sha256: "b".repeat(64) } };
        return { ...changed, transactionId: transactionIdFromBody(changed) };
      },
    },
    {
      name: "wrong transaction id",
      mutate: (body) => ({ ...body, transactionId: "c".repeat(64) }),
    },
    {
      name: "future transaction time",
      mutate: (body) => ({ ...body, recordedAt: new Date(nowMs + 60_000).toISOString() }),
    },
  ];
  for (const fixture of mutations) {
    const records = seed();
    const original = JSON.parse(records.get(BOUNDARY_EXTERNAL_TRANSACTION_NAMES.recoveryIntent).toString("utf8"));
    records.set(
      BOUNDARY_EXTERNAL_TRANSACTION_NAMES.recoveryIntent,
      resignTransaction("intent", fixture.mutate(original.body)),
    );
    assert.throws(
      () => executeBoundaryV2RecoveryTransaction(recoveryArgs(new MemoryCustody(records), rawV2Name)),
      /EXTERNAL_TRANSACTION_(?:RECORD_INVALID|ID_MISMATCH|EVIDENCE_MISMATCH)/,
      fixture.name,
    );
    assert.equal(records.has(rawV2Name), true, `${fixture.name}: hostile intent cannot delete raw predecessor`);
  }

  const completed = seed();
  executeBoundaryV2RecoveryTransaction(recoveryArgs(new MemoryCustody(completed), rawV2Name));
  const receiptName = BOUNDARY_EXTERNAL_TRANSACTION_NAMES.recoveryReceipt;
  const receipt = JSON.parse(completed.get(receiptName).toString("utf8"));
  const foreignBody = {
    ...receipt.body,
    successor: { ...receipt.body.successor, sha256: "d".repeat(64) },
  };
  completed.set(receiptName, resignTransaction("completion", foreignBody));
  assert.throws(
    () => executeBoundaryV2RecoveryTransaction(recoveryArgs(new MemoryCustody(completed), rawV2Name)),
    /EXTERNAL_CUSTODY_RECORD_CONFLICT|EXTERNAL_TRANSACTION_EVIDENCE_MISMATCH/,
  );
});

test("pre-effect receipt and post-effect completion evidence cannot be confused", () => {
  const rawBytes = v2PolicyBytes();
  const rawV2Name = `exclusions.superseded-v2-${sha256(rawBytes)}.json`;
  const records = new Map([[rawV2Name, rawBytes], ["exclusions.json", historicalV3PolicyBytes()]]);
  executeBoundaryV2RecoveryTransaction(recoveryArgs(new MemoryCustody(records), rawV2Name));
  const authorization = JSON.parse(records.get(BOUNDARY_EXTERNAL_TRANSACTION_NAMES.recoveryAuthorization).toString("utf8"));
  const completion = JSON.parse(records.get(BOUNDARY_EXTERNAL_TRANSACTION_NAMES.recoveryReceipt).toString("utf8"));
  assert.equal(authorization.body.event, "EXCLUSION_POLICY_EFFECT_AUTHORIZED_PRE_COMPLETION");
  assert.equal(authorization.body.evidenceStatus, "PRE_EFFECT_COMPLETION_NOT_CLAIMED");
  assert.equal(completion.body.event, "EXCLUSION_POLICY_COMPLETED_AFTER_EXACT_EFFECT_READBACK");
  assert.equal(completion.body.evidenceStatus, "POST_EFFECT_EXACT_STATE_READ_BACK");
  assert.equal(Object.hasOwn(authorization.body, "verifiedAt"), false);
  assert.equal(Object.hasOwn(completion.body, "completedAt"), false);
  assert.equal(authorization.body.timeAuthority, "OUTER_CONTROLLER_REQUIRED");
  assert.equal(completion.body.timeAuthority, "OUTER_CONTROLLER_REQUIRED");
  assert.equal(completion.body.recordedAt, authorization.body.recordedAt, "intent time is carried only as intent identity");
  assert.notEqual(sha256(records.get(BOUNDARY_EXTERNAL_TRANSACTION_NAMES.recoveryAuthorization)), sha256(records.get(BOUNDARY_EXTERNAL_TRANSACTION_NAMES.recoveryReceipt)));
});
