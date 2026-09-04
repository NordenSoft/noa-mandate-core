/**
 * Canonical N-1 external-supervisor boundary authority library.
 *
 * The installed supervisor pins this bundle by content hash, injects key/custody/source inputs, and
 * signs its own controller receipt around the returned observation. This module never discovers a
 * home directory, opens a key path, exposes a general HMAC oracle, or gives candidate code a private
 * policy value. Its observation is deliberately non-authoritative until bound by that outer receipt.
 */

import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import {
  BOUNDARY_AUTHORITY_NON_CLAIMS,
  BOUNDARY_RUNTIME_AUTHORIZATION_SCHEMA_VERSION,
  canonicalBoundaryJson,
  PREVIOUS_REVIEWED_CONTROL_PATHS,
  REVIEWED_CONTROL_PATHS,
} from "./boundary-bootstrap.mjs";
import { reachableTokenForms } from "./boundary-token.mjs";

export const BOUNDARY_EXTERNAL_AUTHORITY_SCHEMA_VERSION = 1;
export const BOUNDARY_EXTERNAL_CONTROLLER_ID = "noa-boundary-external-supervisor/v1";
export const BOUNDARY_AUTHORIZATION_CHANNEL = "PUBLIC_SANITIZED_AUTHORIZATION_V1";
export const BOUNDARY_CUSTODY_ADAPTER_VERSION = 1;

const POLICY_V2_KEYS = Object.freeze([
  "schemaVersion", "keyId", "reviewer", "reviewedAt", "expiresAt", "reviewSession",
  "repositoryHead", "classification", "publicArtifact", "publicArtifactSRI",
  "legacyByteLength", "legacySha256", "entries", "mac",
]);
const POLICY_V3_KEYS = Object.freeze([
  "schemaVersion", "keyId", "reviewer", "reviewedAt", "expiresAt", "reviewSession",
  "classification", "publicArtifact", "publicArtifactSRI", "controlManifestVersion",
  "controlManifestFiles", "controlManifestDigest", "legacyByteLength", "legacySha256",
  "entries", "mac",
]);
const BUNDLE_KEYS = Object.freeze(["digest", "files", "schemaVersion", "version"]);
const BUNDLE_FILE_KEYS = Object.freeze(["byteLength", "path", "sha256"]);
const TIER_B_KEYS = Object.freeze([
  "archiveSha256", "candidateFormCount", "controlManifestDigest", "findingCount",
  "inputDigest", "policySha256", "resultDigest", "scannedUnitCount", "scannerId",
  "schemaVersion", "verdict",
]);
const TRANSACTION_EVIDENCE_KEYS = Object.freeze([
  "authorizationName", "authorizationSha256", "intentName", "intentSha256", "receiptName",
  "receiptSha256", "stage", "transactionId",
]);
const HEX_64_RE = /^[0-9a-f]{64}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const PUBLIC_ARTIFACT_RE = /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*@[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$/;
const SHA512_SRI_RE = /^sha512-[A-Za-z0-9+/]{86}==$/;
const MAX_POLICY_BYTES = 1024 * 1024;
const MAX_VALIDITY_MS = 30 * 86_400_000;
const MAX_CLOCK_SKEW_MS = 5 * 60_000;
const TRANSACTION_SCHEMA_VERSION = 1;
const TRANSACTION_DURABILITY_PROFILE = "INJECTED_EXACT_FSYNC_CUSTODY_V1";
const RECOVERY_STAGE = "RECOVER_RAW_V2_TO_EXACT_ACTIVE_V3";
const ROTATION_STAGE = "ROTATE_ACTIVE_V3_TO_EXPANDED_V3";
const RECOVERY_INTENT_NAME = "exclusion-policy-recovery-v2-to-active-v3.intent.json";
const RECOVERY_AUTHORIZATION_NAME = "exclusion-policy-recovery-v2-to-active-v3.pre-effect-receipt.json";
const RECOVERY_RECEIPT_NAME = "exclusion-policy-recovery-v2-to-active-v3.completion.json";
const ROTATION_INTENT_NAME = "exclusion-policy-fresh-v3-rotation.intent.json";
const ROTATION_AUTHORIZATION_NAME = "exclusion-policy-fresh-v3-rotation.pre-effect-receipt.json";
const ROTATION_RECEIPT_NAME = "exclusion-policy-fresh-v3-rotation.completion.json";
const ROTATION_PREDECESSOR_NAME = "exclusions.fresh-rotation-predecessor-v3.json";

export const BOUNDARY_EXTERNAL_TRANSACTION_NAMES = Object.freeze({
  recoveryAuthorization: RECOVERY_AUTHORIZATION_NAME,
  recoveryIntent: RECOVERY_INTENT_NAME,
  recoveryReceipt: RECOVERY_RECEIPT_NAME,
  rotationAuthorization: ROTATION_AUTHORIZATION_NAME,
  rotationIntent: ROTATION_INTENT_NAME,
  rotationPredecessor: ROTATION_PREDECESSOR_NAME,
  rotationReceipt: ROTATION_RECEIPT_NAME,
});

export class BoundaryExternalAuthorityError extends Error {
  constructor(code) {
    super(code);
    this.name = "BoundaryExternalAuthorityError";
    this.code = code;
  }
}

const refuse = (code) => { throw new BoundaryExternalAuthorityError(code); };
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const exactHex = (left, right) => HEX_64_RE.test(String(left)) && HEX_64_RE.test(String(right))
  && timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
const canonicalBytes = (value) => Buffer.from(`${canonicalBoundaryJson(value)}\n`, "utf8");
const compareText = (left, right) => (left === right ? 0 : (left < right ? -1 : 1));
const hmac = (key, domain, value, { canonical = true } = {}) => createHmac("sha256", key)
  .update(`noa-boundary/${domain}\0`, "utf8")
  .update(canonical ? canonicalBoundaryJson(value) : JSON.stringify(value), "utf8")
  .digest("hex");

function exactKeys(value, expected, code) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) refuse(code);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) refuse(code);
}

function canonicalRegistry(paths, expected = null) {
  if (!Array.isArray(paths) || paths.length === 0 || paths.some((path) =>
    typeof path !== "string" || path.length === 0 || path.length > 512 || path.includes("\\")
      || path.startsWith("/") || path.split("/").some((part) => part === "" || part === "." || part === ".."))) {
    refuse("EXTERNAL_CONTROL_MANIFEST_FILES_INVALID");
  }
  const sorted = [...paths].sort();
  if (new Set(paths).size !== paths.length || paths.some((path, index) => path !== sorted[index])) {
    refuse("EXTERNAL_CONTROL_MANIFEST_FILES_INVALID");
  }
  if (expected !== null && (paths.length !== expected.length
      || paths.some((path, index) => path !== expected[index]))) {
    refuse("EXTERNAL_CONTROL_MANIFEST_FILES_MISMATCH");
  }
}

function exactTimestamp(value, code) {
  const raw = String(value ?? "");
  const parsed = Date.parse(raw);
  const canonical = raw.includes(".") ? raw : raw.replace(/Z$/, ".000Z");
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(raw)
      || !Number.isFinite(parsed) || new Date(parsed).toISOString() !== canonical) refuse(code);
  return parsed;
}

function reviewedLine(value, maxLength, code) {
  if (typeof value !== "string" || value.trim() !== value || value.length === 0
      || value.length > maxLength || /[\u0000-\u001f\u007f]/.test(value)
      || /^(?:unknown|todo|tbd|n\/a)$/i.test(value)) refuse(code);
  return value;
}

function parseLegacy(legacyBytes) {
  const bytes = Buffer.from(legacyBytes ?? Buffer.alloc(0));
  if (bytes.length === 0 || bytes.length > MAX_POLICY_BYTES) refuse("EXTERNAL_LEGACY_BYTES_INVALID");
  let text;
  try { text = new TextDecoder("utf-8", { fatal: true }).decode(bytes); } catch {
    refuse("EXTERNAL_LEGACY_BYTES_INVALID");
  }
  if (text.includes("\0")) refuse("EXTERNAL_LEGACY_BYTES_INVALID");
  const entries = [];
  const seen = new Set();
  for (const line of text.split(/\r?\n/)) {
    if (line.trim().length === 0 || line.trimStart().startsWith("#")) continue;
    const match = /^(.+?) # (.+)$/.exec(line);
    if (match === null) refuse("EXTERNAL_LEGACY_ENTRY_INVALID");
    const token = match[1].trimEnd();
    const reason = reviewedLine(match[2], 500, "EXTERNAL_LEGACY_ENTRY_INVALID");
    let forms;
    try { forms = reachableTokenForms(token); } catch { refuse("EXTERNAL_LEGACY_ENTRY_INVALID"); }
    if (forms.length !== 1 || token !== forms[0] || /[*?\[\]{}]/.test(token) || seen.has(token)) {
      refuse("EXTERNAL_LEGACY_ENTRY_INVALID");
    }
    seen.add(token);
    entries.push({ token, reason });
  }
  entries.sort((left, right) => compareText(left.token, right.token));
  if (entries.length === 0) refuse("EXTERNAL_LEGACY_ENTRY_INVALID");
  return Object.freeze({ byteLength: bytes.length, bytes, entries, sha256: sha256(bytes) });
}

function parsePolicyBytes(policyBytes, schemaVersion) {
  const bytes = Buffer.from(policyBytes ?? Buffer.alloc(0));
  if (bytes.length === 0 || bytes.length > MAX_POLICY_BYTES) refuse("EXTERNAL_POLICY_SIZE_INVALID");
  let text;
  let doc;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    doc = JSON.parse(text);
  } catch {
    refuse("EXTERNAL_POLICY_JSON_INVALID");
  }
  if (doc?.schemaVersion !== schemaVersion) refuse("EXTERNAL_POLICY_SCHEMA_INVALID");
  if (schemaVersion === 3 && text !== canonicalBytes(doc).toString("utf8")) {
    refuse("EXTERNAL_POLICY_NONCANONICAL");
  }
  exactKeys(doc, schemaVersion === 2 ? POLICY_V2_KEYS : POLICY_V3_KEYS, "EXTERNAL_POLICY_SCHEMA_INVALID");
  return { bytes, doc };
}

function validatePolicyEntries(doc, legacy) {
  if (!Array.isArray(doc.entries) || doc.entries.length !== legacy.entries.length) {
    refuse("EXTERNAL_POLICY_LEGACY_MISMATCH");
  }
  const entries = doc.entries.map((entry) => {
    exactKeys(entry, ["reason", "token"], "EXTERNAL_POLICY_ENTRY_INVALID");
    return {
      token: entry.token,
      reason: reviewedLine(entry.reason, 500, "EXTERNAL_POLICY_ENTRY_INVALID"),
    };
  });
  if (canonicalBoundaryJson(entries) !== canonicalBoundaryJson(legacy.entries)) {
    refuse("EXTERNAL_POLICY_LEGACY_MISMATCH");
  }
  return entries;
}

function validatePolicyMetadata(doc, { allowExpired, nowMs }) {
  reviewedLine(doc.reviewer, 240, "EXTERNAL_POLICY_METADATA_INVALID");
  reviewedLine(doc.reviewSession, 80, "EXTERNAL_POLICY_METADATA_INVALID");
  reviewedLine(doc.classification, 80, "EXTERNAL_POLICY_METADATA_INVALID");
  reviewedLine(doc.publicArtifact, 214, "EXTERNAL_POLICY_METADATA_INVALID");
  reviewedLine(doc.publicArtifactSRI, 160, "EXTERNAL_POLICY_METADATA_INVALID");
  if (!UUID_RE.test(doc.reviewSession) || doc.classification !== "PUBLIC_DERIVED_COLLISION"
      || !PUBLIC_ARTIFACT_RE.test(doc.publicArtifact) || !SHA512_SRI_RE.test(doc.publicArtifactSRI)) {
    refuse("EXTERNAL_POLICY_METADATA_INVALID");
  }
  const reviewedAt = exactTimestamp(doc.reviewedAt, "EXTERNAL_POLICY_METADATA_INVALID");
  const expiresAt = exactTimestamp(doc.expiresAt, "EXTERNAL_POLICY_METADATA_INVALID");
  if (reviewedAt > nowMs || expiresAt <= reviewedAt || expiresAt - reviewedAt > MAX_VALIDITY_MS
      || (!allowExpired && expiresAt <= nowMs)) refuse("EXTERNAL_POLICY_TIME_INVALID");
  return { expiresAt, reviewedAt };
}

function authenticatePolicy({
  allowExpired = false,
  expectedManifest = null,
  keyBytes,
  legacy,
  nowMs,
  policyBytes,
  schemaVersion,
}) {
  const key = Buffer.from(keyBytes ?? Buffer.alloc(0));
  try {
    if (key.length !== 32) refuse("EXTERNAL_POLICY_KEY_INVALID");
    const { bytes, doc } = parsePolicyBytes(policyBytes, schemaVersion);
    const keyId = sha256(key);
    if (!exactHex(doc.keyId, keyId) || !HEX_64_RE.test(String(doc.mac))) {
      refuse("EXTERNAL_POLICY_KEY_ID_MISMATCH");
    }
    validatePolicyMetadata(doc, { allowExpired, nowMs });
    if (doc.legacyByteLength !== legacy.byteLength || !exactHex(doc.legacySha256, legacy.sha256)) {
      refuse("EXTERNAL_POLICY_LEGACY_MISMATCH");
    }
    const entries = validatePolicyEntries(doc, legacy);
    if (schemaVersion === 2) {
      if (!/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(String(doc.repositoryHead))
          || /^0+$/.test(doc.repositoryHead)) refuse("EXTERNAL_POLICY_METADATA_INVALID");
    } else {
      if (!Number.isSafeInteger(doc.controlManifestVersion) || doc.controlManifestVersion <= 0
          || !HEX_64_RE.test(String(doc.controlManifestDigest))) {
        refuse("EXTERNAL_POLICY_MANIFEST_INVALID");
      }
      canonicalRegistry(doc.controlManifestFiles, expectedManifest?.files ?? null);
      if (expectedManifest !== null && (doc.controlManifestVersion !== expectedManifest.version
          || !exactHex(doc.controlManifestDigest, expectedManifest.digest))) {
        refuse("EXTERNAL_POLICY_MANIFEST_MISMATCH");
      }
    }
    const bodyKeys = (schemaVersion === 2 ? POLICY_V2_KEYS : POLICY_V3_KEYS).filter((keyName) => keyName !== "mac");
    const body = Object.fromEntries(bodyKeys.map((keyName) => [keyName, doc[keyName]]));
    const expectedMac = hmac(key, `exclusion-policy/v${schemaVersion}`, body, { canonical: schemaVersion === 3 });
    if (!exactHex(doc.mac, expectedMac)) refuse("EXTERNAL_POLICY_AUTHENTICATION_FAILED");
    return Object.freeze({ bytes, doc, entries, keyId, sha256: sha256(bytes) });
  } finally {
    key.fill(0);
  }
}

function manifestFromPolicy(policy) {
  return Object.freeze({
    digest: policy.doc.controlManifestDigest,
    files: Object.freeze([...policy.doc.controlManifestFiles]),
    version: policy.doc.controlManifestVersion,
  });
}

function validateCandidateManifest(manifest) {
  if (manifest === null || typeof manifest !== "object" || Array.isArray(manifest)
      || !Number.isSafeInteger(manifest.version) || manifest.version <= 0
      || !HEX_64_RE.test(String(manifest.digest))) refuse("EXTERNAL_CANDIDATE_MANIFEST_INVALID");
  canonicalRegistry(manifest.paths, REVIEWED_CONTROL_PATHS);
  return Object.freeze({ digest: manifest.digest, files: Object.freeze([...manifest.paths]), version: manifest.version });
}

function validateSubject(subject) {
  exactKeys(subject, ["archiveSha256", "commit", "repository", "tree"], "EXTERNAL_CANDIDATE_SUBJECT_INVALID");
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(String(subject.repository))
      || !/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(String(subject.commit))
      || !/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(String(subject.tree))
      || !HEX_64_RE.test(String(subject.archiveSha256))) refuse("EXTERNAL_CANDIDATE_SUBJECT_INVALID");
  return Object.freeze({ ...subject });
}

export function deriveBoundaryAuthorityBundleIdentity({ files, version }) {
  if (typeof version !== "string" || version.length === 0 || version.length > 80
      || !Array.isArray(files) || files.length === 0) refuse("EXTERNAL_BUNDLE_IDENTITY_INVALID");
  const copied = files.map((file) => {
    exactKeys(file, BUNDLE_FILE_KEYS, "EXTERNAL_BUNDLE_IDENTITY_INVALID");
    if (!Number.isSafeInteger(file.byteLength) || file.byteLength <= 0
        || !HEX_64_RE.test(String(file.sha256))) refuse("EXTERNAL_BUNDLE_IDENTITY_INVALID");
    canonicalRegistry([file.path]);
    return { byteLength: file.byteLength, path: file.path, sha256: file.sha256 };
  }).sort((left, right) => compareText(left.path, right.path));
  if (new Set(copied.map((file) => file.path)).size !== copied.length) refuse("EXTERNAL_BUNDLE_IDENTITY_INVALID");
  const body = { files: copied, schemaVersion: 1, version };
  return Object.freeze({ ...body, digest: sha256(Buffer.from(canonicalBoundaryJson(body), "utf8")) });
}

function validateBundleIdentity(bundle) {
  exactKeys(bundle, BUNDLE_KEYS, "EXTERNAL_BUNDLE_IDENTITY_INVALID");
  const derived = deriveBoundaryAuthorityBundleIdentity({ files: bundle.files, version: bundle.version });
  if (bundle.schemaVersion !== 1 || !exactHex(bundle.digest, derived.digest)) {
    refuse("EXTERNAL_BUNDLE_IDENTITY_INVALID");
  }
  return derived;
}

function validateTierBResult(result, { manifest, policySha256, subject }) {
  exactKeys(result, TIER_B_KEYS, "EXTERNAL_TIER_B_RESULT_INVALID");
  if (result.schemaVersion !== 1 || result.scannerId !== "noa-boundary-tier-b/v1"
      || result.verdict !== "PASS" || result.findingCount !== 0
      || !Number.isSafeInteger(result.scannedUnitCount) || result.scannedUnitCount <= 0
      || !Number.isSafeInteger(result.candidateFormCount) || result.candidateFormCount < 0
      || !HEX_64_RE.test(String(result.inputDigest)) || !HEX_64_RE.test(String(result.resultDigest))
      || !exactHex(result.archiveSha256, subject.archiveSha256)
      || !exactHex(result.controlManifestDigest, manifest.digest)
      || !exactHex(result.policySha256, policySha256)) refuse("EXTERNAL_TIER_B_RESULT_INVALID");
  return Object.freeze({ ...result });
}

function policyObservation(policy) {
  return Object.freeze({
    controlManifestDigest: policy.doc.controlManifestDigest,
    controlManifestFiles: Object.freeze([...policy.doc.controlManifestFiles]),
    controlManifestVersion: policy.doc.controlManifestVersion,
    keyId: policy.keyId,
    schemaVersion: policy.doc.schemaVersion,
    sha256: policy.sha256,
  });
}

function transactionSlots({ recovery = null, freshRotation = null } = {}) {
  for (const value of [recovery, freshRotation]) {
    if (value === null) continue;
    exactKeys(value, TRANSACTION_EVIDENCE_KEYS, "EXTERNAL_TRANSACTION_EVIDENCE_INVALID");
  }
  return Object.freeze({ recovery, freshRotation });
}

function privateObservation({
  authorizationSha256 = null,
  bundle,
  controlManifest,
  observedAt,
  operation,
  policy,
  subject = null,
  tierB = null,
  transactions = {},
}) {
  return Object.freeze({
    authority: "NON_AUTHORITATIVE_EXTERNAL_LIBRARY_OBSERVATION_V1",
    authorizationSha256,
    bundle,
    controllerId: BOUNDARY_EXTERNAL_CONTROLLER_ID,
    controlManifest,
    nonClaims: Object.freeze([...BOUNDARY_AUTHORITY_NON_CLAIMS]),
    observedAt,
    operation,
    policy: policyObservation(policy),
    schemaVersion: BOUNDARY_EXTERNAL_AUTHORITY_SCHEMA_VERSION,
    subject,
    tierB,
    transactions: transactionSlots(transactions),
  });
}

export function createBoundaryRuntimeAuthorization({
  bundleIdentity,
  candidateManifest,
  expiresAt,
  issuedAt,
  nonce,
  operation = "RUNTIME",
  policyBytes,
  subject,
  keyBytes,
  legacyBytes,
  tierBResult,
  transactionEvidence = {},
}) {
  if (operation !== "RUNTIME" && operation !== "RECOVERY_ONLY") refuse("EXTERNAL_OPERATION_INVALID");
  if (!HEX_64_RE.test(String(nonce))) refuse("EXTERNAL_NONCE_INVALID");
  const issuedMs = exactTimestamp(issuedAt, "EXTERNAL_ISSUED_AT_INVALID");
  const expiresMs = exactTimestamp(expiresAt, "EXTERNAL_EXPIRES_AT_INVALID");
  if (expiresMs <= issuedMs || expiresMs - issuedMs > MAX_CLOCK_SKEW_MS) {
    refuse("EXTERNAL_AUTHORIZATION_WINDOW_INVALID");
  }
  const manifest = validateCandidateManifest(candidateManifest);
  const publicSubject = validateSubject(subject);
  const bundle = validateBundleIdentity(bundleIdentity);
  const legacy = parseLegacy(legacyBytes);
  const policy = authenticatePolicy({
    expectedManifest: operation === "RUNTIME" ? manifest : null,
    keyBytes,
    legacy,
    nowMs: issuedMs,
    policyBytes,
    schemaVersion: 3,
  });
  if (operation === "RECOVERY_ONLY"
      && (policy.doc.controlManifestVersion !== 1
        || policy.doc.controlManifestFiles.length !== PREVIOUS_REVIEWED_CONTROL_PATHS.length
        || policy.doc.controlManifestFiles.some((path, index) => path !== PREVIOUS_REVIEWED_CONTROL_PATHS[index]))) {
    refuse("EXTERNAL_RECOVERY_PREDECESSOR_IDENTITY_INVALID");
  }
  const tierB = validateTierBResult(tierBResult, { manifest, policySha256: policy.sha256, subject: publicSubject });
  const authorization = Object.freeze({
    channel: BOUNDARY_AUTHORIZATION_CHANNEL,
    controlManifest: manifest,
    controllerId: BOUNDARY_EXTERNAL_CONTROLLER_ID,
    expiresAt,
    issuedAt,
    nonce,
    nonClaims: Object.freeze([...BOUNDARY_AUTHORITY_NON_CLAIMS]),
    operation,
    schemaVersion: BOUNDARY_RUNTIME_AUTHORIZATION_SCHEMA_VERSION,
    subject: publicSubject,
  });
  const authorizationBytes = canonicalBytes(authorization);
  const observation = privateObservation({
    authorizationSha256: sha256(authorizationBytes),
    bundle,
    controlManifest: manifest,
    observedAt: issuedAt,
    operation,
    policy,
    subject: publicSubject,
    tierB,
    transactions: transactionEvidence,
  });
  return Object.freeze({ authorization, authorizationBytes, observation });
}

export function createBoundaryV3PolicyBytes({ candidateManifest, keyBytes, legacyBytes, review, nowMs = Date.now() }) {
  const manifest = validateCandidateManifest(candidateManifest);
  const legacy = parseLegacy(legacyBytes);
  const key = Buffer.from(keyBytes ?? Buffer.alloc(0));
  try {
    if (key.length !== 32) refuse("EXTERNAL_POLICY_KEY_INVALID");
    exactKeys(review, [
      "classification", "expiresAt", "publicArtifact", "publicArtifactSRI", "reviewedAt",
      "reviewer", "reviewSession",
    ], "EXTERNAL_POLICY_METADATA_INVALID");
    const body = {
      schemaVersion: 3,
      keyId: sha256(key),
      reviewer: review.reviewer,
      reviewedAt: review.reviewedAt,
      expiresAt: review.expiresAt,
      reviewSession: review.reviewSession,
      classification: review.classification,
      publicArtifact: review.publicArtifact,
      publicArtifactSRI: review.publicArtifactSRI,
      controlManifestVersion: manifest.version,
      controlManifestFiles: manifest.files,
      controlManifestDigest: manifest.digest,
      legacyByteLength: legacy.byteLength,
      legacySha256: legacy.sha256,
      entries: legacy.entries,
    };
    validatePolicyMetadata(body, { allowExpired: false, nowMs });
    const policy = { ...body, mac: hmac(key, "exclusion-policy/v3", body) };
    const bytes = canonicalBytes(policy);
    authenticatePolicy({ expectedManifest: manifest, keyBytes: key, legacy, nowMs, policyBytes: bytes, schemaVersion: 3 });
    return bytes;
  } finally {
    key.fill(0);
  }
}

function reviewedDecision(policy) {
  const doc = policy.doc;
  return {
    reviewer: doc.reviewer,
    reviewedAt: doc.reviewedAt,
    expiresAt: doc.expiresAt,
    reviewSession: doc.reviewSession,
    classification: doc.classification,
    publicArtifact: doc.publicArtifact,
    publicArtifactSRI: doc.publicArtifactSRI,
    legacyByteLength: doc.legacyByteLength,
    legacySha256: doc.legacySha256,
    entries: doc.entries,
  };
}

function policyEvidence(policy, { successor = false } = {}) {
  const evidence = {
    schemaVersion: policy.doc.schemaVersion,
    byteLength: policy.bytes.length,
    sha256: policy.sha256,
    policyMac: policy.doc.mac,
  };
  if (successor) {
    evidence.controlManifestVersion = policy.doc.controlManifestVersion;
    evidence.controlManifestDigest = policy.doc.controlManifestDigest;
  }
  return evidence;
}

function transactionId(stage, predecessor, observedActive, successor, legacy) {
  return sha256(Buffer.from(canonicalBoundaryJson({
    stage,
    predecessor,
    observedActive,
    successor,
    legacy: { byteLength: legacy.byteLength, sha256: legacy.sha256 },
  }), "utf8"));
}

function transactionDocument(key, kind, body) {
  const macField = `${kind}Mac`;
  return { body, [macField]: hmac(key, `exclusion-policy-transaction-${kind}/v1`, body) };
}

function parseTransaction(bytes, kind, key) {
  if (bytes === null) return null;
  let doc;
  try { doc = JSON.parse(Buffer.from(bytes).toString("utf8")); } catch { refuse("EXTERNAL_TRANSACTION_RECORD_INVALID"); }
  if (!Buffer.from(bytes).equals(canonicalBytes(doc))) refuse("EXTERNAL_TRANSACTION_RECORD_INVALID");
  const macField = `${kind}Mac`;
  exactKeys(doc, ["body", macField], "EXTERNAL_TRANSACTION_RECORD_INVALID");
  if (!HEX_64_RE.test(String(doc[macField]))
      || !exactHex(doc[macField], hmac(key, `exclusion-policy-transaction-${kind}/v1`, doc.body))) {
    refuse("EXTERNAL_TRANSACTION_AUTHENTICATION_FAILED");
  }
  return doc;
}

const POLICY_EVIDENCE_KEYS = Object.freeze(["byteLength", "policyMac", "schemaVersion", "sha256"]);
const SUCCESSOR_EVIDENCE_KEYS = Object.freeze([
  "byteLength", "controlManifestDigest", "controlManifestVersion", "policyMac", "schemaVersion", "sha256",
]);
const INTENT_BODY_KEYS = Object.freeze([
  "durabilityProfile", "event", "keyId", "legacy", "observedActive", "predecessor",
  "recordedAt", "schemaVersion", "stage", "successor", "transactionId",
]);

function validatePolicyEvidence(value, { successor = false } = {}) {
  exactKeys(value, successor ? SUCCESSOR_EVIDENCE_KEYS : POLICY_EVIDENCE_KEYS, "EXTERNAL_TRANSACTION_RECORD_INVALID");
  if (![2, 3].includes(value.schemaVersion) || !Number.isSafeInteger(value.byteLength)
      || value.byteLength <= 0 || !HEX_64_RE.test(String(value.sha256))
      || !HEX_64_RE.test(String(value.policyMac))
      || (successor && (value.schemaVersion !== 3
        || !Number.isSafeInteger(value.controlManifestVersion) || value.controlManifestVersion <= 0
        || !HEX_64_RE.test(String(value.controlManifestDigest))))) {
    refuse("EXTERNAL_TRANSACTION_RECORD_INVALID");
  }
}

function validateIntentBody(body, { expectedStage, expectedKeyId, nowMs }) {
  exactKeys(body, INTENT_BODY_KEYS, "EXTERNAL_TRANSACTION_RECORD_INVALID");
  exactKeys(body.legacy, ["byteLength", "sha256"], "EXTERNAL_TRANSACTION_RECORD_INVALID");
  validatePolicyEvidence(body.predecessor);
  validatePolicyEvidence(body.observedActive);
  validatePolicyEvidence(body.successor, { successor: true });
  const recordedAt = exactTimestamp(body.recordedAt, "EXTERNAL_TRANSACTION_RECORD_INVALID");
  if (body.schemaVersion !== TRANSACTION_SCHEMA_VERSION
      || body.event !== "EXCLUSION_POLICY_EFFECT_INTENT"
      || body.stage !== expectedStage || body.keyId !== expectedKeyId
      || body.durabilityProfile !== TRANSACTION_DURABILITY_PROFILE
      || !HEX_64_RE.test(String(body.transactionId))
      || !Number.isSafeInteger(body.legacy.byteLength) || body.legacy.byteLength <= 0
      || !HEX_64_RE.test(String(body.legacy.sha256)) || recordedAt > nowMs + 5_000) {
    refuse("EXTERNAL_TRANSACTION_RECORD_INVALID");
  }
  const recomputed = transactionId(
    body.stage,
    body.predecessor,
    body.observedActive,
    body.successor,
    body.legacy,
  );
  if (!exactHex(body.transactionId, recomputed)) refuse("EXTERNAL_TRANSACTION_ID_MISMATCH");
  return body;
}

function effectAuthorizationBody(intentBody, intentBytes) {
  return {
    ...intentBody,
    event: "EXCLUSION_POLICY_EFFECT_AUTHORIZED_PRE_COMPLETION",
    evidenceStatus: "PRE_EFFECT_COMPLETION_NOT_CLAIMED",
    intentSha256: sha256(intentBytes),
    timeAuthority: "OUTER_CONTROLLER_REQUIRED",
  };
}

function completionBody(intentBody, intentBytes, authorizationBytes) {
  return {
    ...intentBody,
    authorizationSha256: sha256(authorizationBytes),
    event: "EXCLUSION_POLICY_COMPLETED_AFTER_EXACT_EFFECT_READBACK",
    evidenceStatus: "POST_EFFECT_EXACT_STATE_READ_BACK",
    intentSha256: sha256(intentBytes),
    timeAuthority: "OUTER_CONTROLLER_REQUIRED",
  };
}

function validateEffectAuthorization(bytes, key, intentBody, intentBytes) {
  const expected = effectAuthorizationBody(intentBody, intentBytes);
  const doc = parseTransaction(bytes, "authorization", key);
  if (doc === null || canonicalBoundaryJson(doc.body) !== canonicalBoundaryJson(expected)) {
    refuse("EXTERNAL_TRANSACTION_EVIDENCE_MISMATCH");
  }
  return doc;
}

function validateCompletion(bytes, key, intentBody, intentBytes, authorizationBytes) {
  const expected = completionBody(intentBody, intentBytes, authorizationBytes);
  const doc = parseTransaction(bytes, "completion", key);
  if (doc === null || canonicalBoundaryJson(doc.body) !== canonicalBoundaryJson(expected)) {
    refuse("EXTERNAL_TRANSACTION_EVIDENCE_MISMATCH");
  }
  return doc;
}

function resolveIntent({
  existingBytes,
  expectedBody,
  expectedKeyId,
  expectedStage,
  key,
  nowMs,
}) {
  let body = expectedBody;
  if (existingBytes !== null) {
    const existing = parseTransaction(existingBytes, "intent", key);
    validateIntentBody(existing.body, { expectedKeyId, expectedStage, nowMs });
    body = { ...expectedBody, recordedAt: existing.body.recordedAt };
    if (canonicalBoundaryJson(existing.body) !== canonicalBoundaryJson(body)) {
      refuse("EXTERNAL_TRANSACTION_EVIDENCE_MISMATCH");
    }
  }
  validateIntentBody(body, { expectedKeyId, expectedStage, nowMs });
  const bytes = canonicalBytes(transactionDocument(key, "intent", body));
  if (existingBytes !== null && !existingBytes.equals(bytes)) refuse("EXTERNAL_TRANSACTION_EVIDENCE_MISMATCH");
  return Object.freeze({ body, bytes });
}

function validateCustody(custody) {
  if (custody === null || typeof custody !== "object" || custody.schemaVersion !== BOUNDARY_CUSTODY_ADAPTER_VERSION
      || typeof custody.readExact !== "function" || typeof custody.createDurableExclusive !== "function"
      || typeof custody.replaceDurableExact !== "function" || typeof custody.removeDurableExact !== "function") {
    refuse("EXTERNAL_CUSTODY_ADAPTER_INVALID");
  }
  return custody;
}

function custodyRead(custody, name) {
  const value = custody.readExact(name);
  if (value === null) return null;
  if (!(value instanceof Uint8Array)) refuse("EXTERNAL_CUSTODY_ADAPTER_INVALID");
  return Buffer.from(value);
}

function ensureDurable(custody, name, bytes) {
  const current = custodyRead(custody, name);
  if (current !== null) {
    if (!current.equals(bytes)) refuse("EXTERNAL_CUSTODY_RECORD_CONFLICT");
    return;
  }
  custody.createDurableExclusive({ bytes: Buffer.from(bytes), name });
  const readBack = custodyRead(custody, name);
  if (readBack === null || !readBack.equals(bytes)) refuse("EXTERNAL_CUSTODY_DURABLE_READBACK_FAILED");
}

function replaceDurable(custody, name, expectedBytes, nextBytes) {
  const current = custodyRead(custody, name);
  if (current !== null && current.equals(nextBytes)) return;
  if (current === null || !current.equals(expectedBytes)) refuse("EXTERNAL_CUSTODY_ACTIVE_STATE_MISMATCH");
  custody.replaceDurableExact({ expectedBytes: Buffer.from(expectedBytes), name, nextBytes: Buffer.from(nextBytes) });
  const readBack = custodyRead(custody, name);
  if (readBack === null || !readBack.equals(nextBytes)) refuse("EXTERNAL_CUSTODY_DURABLE_READBACK_FAILED");
}

function removeDurable(custody, name, expectedBytes) {
  const current = custodyRead(custody, name);
  if (current === null) return;
  if (!current.equals(expectedBytes)) refuse("EXTERNAL_CUSTODY_RECORD_CONFLICT");
  custody.removeDurableExact({ expectedBytes: Buffer.from(expectedBytes), name });
  if (custodyRead(custody, name) !== null) refuse("EXTERNAL_CUSTODY_DURABLE_READBACK_FAILED");
}

function transactionEvidence(
  stage,
  intentName,
  intentBytes,
  authorizationName,
  authorizationBytes,
  receiptName,
  receiptBytes,
  id,
) {
  return Object.freeze({
    authorizationName,
    authorizationSha256: sha256(authorizationBytes),
    intentName,
    intentSha256: sha256(intentBytes),
    receiptName,
    receiptSha256: sha256(receiptBytes),
    stage,
    transactionId: id,
  });
}

function transactionBody({ recordedAt, stage, predecessor, observedActive, successor, legacy, id }) {
  return {
    schemaVersion: TRANSACTION_SCHEMA_VERSION,
    event: "EXCLUSION_POLICY_EFFECT_INTENT",
    stage,
    recordedAt,
    transactionId: id,
    keyId: predecessor.keyId,
    predecessor: policyEvidence(predecessor),
    observedActive: policyEvidence(observedActive),
    successor: policyEvidence(successor, { successor: true }),
    legacy: { byteLength: legacy.byteLength, sha256: legacy.sha256 },
    durabilityProfile: TRANSACTION_DURABILITY_PROFILE,
  };
}

export function executeBoundaryV2RecoveryTransaction({
  activeName = "exclusions.json",
  bundleIdentity,
  custody: suppliedCustody,
  keyBytes,
  legacyBytes,
  observedAt,
  rawV2Name,
}) {
  const custody = validateCustody(suppliedCustody);
  const bundle = validateBundleIdentity(bundleIdentity);
  const nowMs = exactTimestamp(observedAt, "EXTERNAL_TRANSACTION_TIME_INVALID");
  if (typeof rawV2Name !== "string" || rawV2Name.length === 0 || rawV2Name === activeName) {
    refuse("EXTERNAL_TRANSACTION_LOCATION_INVALID");
  }
  const key = Buffer.from(keyBytes ?? Buffer.alloc(0));
  try {
    if (key.length !== 32) refuse("EXTERNAL_POLICY_KEY_INVALID");
    const legacy = parseLegacy(legacyBytes);
    const activeBytes = custodyRead(custody, activeName);
    if (activeBytes === null) refuse("EXTERNAL_CUSTODY_ACTIVE_STATE_MISMATCH");
    const activeDoc = parsePolicyBytes(activeBytes, 3).doc;
    const previousManifest = {
      digest: activeDoc.controlManifestDigest,
      files: PREVIOUS_REVIEWED_CONTROL_PATHS,
      version: 1,
    };
    const active = authenticatePolicy({ expectedManifest: previousManifest, keyBytes: key, legacy, nowMs, policyBytes: activeBytes, schemaVersion: 3 });
    const rawBytes = custodyRead(custody, rawV2Name);
    const retainedIntent = custodyRead(custody, RECOVERY_INTENT_NAME);
    const retainedAuthorization = custodyRead(custody, RECOVERY_AUTHORIZATION_NAME);
    const retainedReceipt = custodyRead(custody, RECOVERY_RECEIPT_NAME);
    let intent;
    if (rawBytes === null) {
      if (retainedIntent === null || retainedAuthorization === null) {
        refuse("EXTERNAL_RECOVERY_PREDECESSOR_MISSING");
      }
      const parsed = parseTransaction(retainedIntent, "intent", key);
      validateIntentBody(parsed.body, { expectedKeyId: active.keyId, expectedStage: RECOVERY_STAGE, nowMs });
      if (parsed.body.predecessor.schemaVersion !== 2
          || canonicalBoundaryJson(parsed.body.observedActive) !== canonicalBoundaryJson(policyEvidence(active))
          || canonicalBoundaryJson(parsed.body.successor) !== canonicalBoundaryJson(policyEvidence(active, { successor: true }))
          || canonicalBoundaryJson(parsed.body.legacy) !== canonicalBoundaryJson({ byteLength: legacy.byteLength, sha256: legacy.sha256 })) {
        refuse("EXTERNAL_TRANSACTION_EVIDENCE_MISMATCH");
      }
      intent = Object.freeze({ body: parsed.body, bytes: retainedIntent });
    } else {
      const raw = authenticatePolicy({ allowExpired: true, keyBytes: key, legacy, nowMs, policyBytes: rawBytes, schemaVersion: 2 });
      if (canonicalBoundaryJson(reviewedDecision(raw)) !== canonicalBoundaryJson(reviewedDecision(active))) {
        refuse("EXTERNAL_RECOVERY_REVIEW_DECISION_MISMATCH");
      }
      const id = transactionId(RECOVERY_STAGE, policyEvidence(raw), policyEvidence(active), policyEvidence(active, { successor: true }), legacy);
      intent = resolveIntent({
        existingBytes: retainedIntent,
        expectedBody: transactionBody({
          id,
          legacy,
          observedActive: active,
          predecessor: raw,
          recordedAt: observedAt,
          stage: RECOVERY_STAGE,
          successor: active,
        }),
        expectedKeyId: raw.keyId,
        expectedStage: RECOVERY_STAGE,
        key,
        nowMs,
      });
      ensureDurable(custody, RECOVERY_INTENT_NAME, intent.bytes);
    }
    const authorizationBytes = canonicalBytes(transactionDocument(
      key,
      "authorization",
      effectAuthorizationBody(intent.body, intent.bytes),
    ));
    ensureDurable(custody, RECOVERY_AUTHORIZATION_NAME, authorizationBytes);
    validateEffectAuthorization(custodyRead(custody, RECOVERY_AUTHORIZATION_NAME), key, intent.body, intent.bytes);
    if (rawBytes !== null) removeDurable(custody, rawV2Name, rawBytes);
    if (custodyRead(custody, rawV2Name) !== null
        || !custodyRead(custody, activeName)?.equals(activeBytes)) {
      refuse("EXTERNAL_TRANSACTION_POST_EFFECT_STATE_INVALID");
    }
    const receiptBytes = canonicalBytes(transactionDocument(
      key,
      "completion",
      completionBody(intent.body, intent.bytes, authorizationBytes),
    ));
    ensureDurable(custody, RECOVERY_RECEIPT_NAME, receiptBytes);
    validateCompletion(
      custodyRead(custody, RECOVERY_RECEIPT_NAME),
      key,
      intent.body,
      intent.bytes,
      authorizationBytes,
    );
    if (retainedReceipt !== null && !retainedReceipt.equals(receiptBytes)) {
      refuse("EXTERNAL_TRANSACTION_EVIDENCE_MISMATCH");
    }
    const evidence = transactionEvidence(
      RECOVERY_STAGE,
      RECOVERY_INTENT_NAME,
      intent.bytes,
      RECOVERY_AUTHORIZATION_NAME,
      authorizationBytes,
      RECOVERY_RECEIPT_NAME,
      receiptBytes,
      intent.body.transactionId,
    );
    return Object.freeze({
      authorization: null,
      authorizationBytes: null,
      observation: privateObservation({
        bundle,
        controlManifest: manifestFromPolicy(active),
        observedAt,
        operation: RECOVERY_STAGE,
        policy: active,
        transactions: { recovery: evidence },
      }),
      transaction: evidence,
    });
  } finally {
    key.fill(0);
  }
}

function validateRecoveryCompletionChain(custody, key, keyId, legacy, nowMs) {
  const intentBytes = custodyRead(custody, RECOVERY_INTENT_NAME);
  const authorizationBytes = custodyRead(custody, RECOVERY_AUTHORIZATION_NAME);
  const completionBytes = custodyRead(custody, RECOVERY_RECEIPT_NAME);
  if (intentBytes === null || authorizationBytes === null || completionBytes === null) {
    refuse("EXTERNAL_FRESH_ROTATION_REQUIRES_RECOVERY_RECEIPT");
  }
  const intent = parseTransaction(intentBytes, "intent", key);
  validateIntentBody(intent.body, { expectedKeyId: keyId, expectedStage: RECOVERY_STAGE, nowMs });
  if (intent.body.predecessor.schemaVersion !== 2
      || intent.body.observedActive.schemaVersion !== 3
      || canonicalBoundaryJson(intent.body.legacy) !== canonicalBoundaryJson({
        byteLength: legacy.byteLength,
        sha256: legacy.sha256,
      })) {
    refuse("EXTERNAL_TRANSACTION_EVIDENCE_MISMATCH");
  }
  validateEffectAuthorization(authorizationBytes, key, intent.body, intentBytes);
  validateCompletion(completionBytes, key, intent.body, intentBytes, authorizationBytes);
  return Object.freeze({ authorizationBytes, completionBytes, intentBytes, intentBody: intent.body });
}

export function executeBoundaryFreshV3RotationTransaction({
  activeName = "exclusions.json",
  bundleIdentity,
  candidateManifest,
  custody: suppliedCustody,
  keyBytes,
  legacyBytes,
  observedAt,
  successorPolicyBytes,
}) {
  const custody = validateCustody(suppliedCustody);
  const bundle = validateBundleIdentity(bundleIdentity);
  const manifest = validateCandidateManifest(candidateManifest);
  const nowMs = exactTimestamp(observedAt, "EXTERNAL_TRANSACTION_TIME_INVALID");
  const key = Buffer.from(keyBytes ?? Buffer.alloc(0));
  try {
    if (key.length !== 32) refuse("EXTERNAL_POLICY_KEY_INVALID");
    const legacy = parseLegacy(legacyBytes);
    const keyId = sha256(key);
    validateRecoveryCompletionChain(custody, key, keyId, legacy, nowMs);
    const retainedPredecessor = custodyRead(custody, ROTATION_PREDECESSOR_NAME);
    const retainedIntent = custodyRead(custody, ROTATION_INTENT_NAME);
    const retainedAuthorization = custodyRead(custody, ROTATION_AUTHORIZATION_NAME);
    const retainedReceipt = custodyRead(custody, ROTATION_RECEIPT_NAME);
    const activeBytes = custodyRead(custody, activeName);
    if (activeBytes === null) refuse("EXTERNAL_CUSTODY_ACTIVE_STATE_MISMATCH");
    const successor = authenticatePolicy({ expectedManifest: manifest, keyBytes: key, legacy, nowMs, policyBytes: successorPolicyBytes, schemaVersion: 3 });
    let predecessorBytes = retainedPredecessor;
    if (predecessorBytes === null && !activeBytes.equals(successor.bytes)) predecessorBytes = activeBytes;
    let intent;
    if (predecessorBytes === null) {
      if (!activeBytes.equals(successor.bytes) || retainedIntent === null || retainedAuthorization === null) {
        refuse("EXTERNAL_ROTATION_PREDECESSOR_MISSING");
      }
      const parsed = parseTransaction(retainedIntent, "intent", key);
      validateIntentBody(parsed.body, { expectedKeyId: keyId, expectedStage: ROTATION_STAGE, nowMs });
      if (parsed.body.predecessor.schemaVersion !== 3
          || canonicalBoundaryJson(parsed.body.observedActive) !== canonicalBoundaryJson(parsed.body.predecessor)
          || canonicalBoundaryJson(parsed.body.successor) !== canonicalBoundaryJson(policyEvidence(successor, { successor: true }))
          || canonicalBoundaryJson(parsed.body.legacy) !== canonicalBoundaryJson({ byteLength: legacy.byteLength, sha256: legacy.sha256 })) {
        refuse("EXTERNAL_TRANSACTION_EVIDENCE_MISMATCH");
      }
      intent = Object.freeze({ body: parsed.body, bytes: retainedIntent });
    } else {
      const predecessorDoc = parsePolicyBytes(predecessorBytes, 3).doc;
      const historicalManifest = {
        digest: predecessorDoc.controlManifestDigest,
        files: PREVIOUS_REVIEWED_CONTROL_PATHS,
        version: 1,
      };
      const predecessor = authenticatePolicy({ allowExpired: true, expectedManifest: historicalManifest, keyBytes: key, legacy, nowMs, policyBytes: predecessorBytes, schemaVersion: 3 });
      if (successor.doc.reviewSession === predecessor.doc.reviewSession
          || Date.parse(successor.doc.reviewedAt) <= Date.parse(predecessor.doc.reviewedAt)
          || canonicalBoundaryJson(reviewedDecision(successor)) === canonicalBoundaryJson(reviewedDecision(predecessor))) {
        refuse("EXTERNAL_FRESH_ROTATION_METADATA_NOT_FRESH");
      }
      const id = transactionId(ROTATION_STAGE, policyEvidence(predecessor), policyEvidence(predecessor), policyEvidence(successor, { successor: true }), legacy);
      intent = resolveIntent({
        existingBytes: retainedIntent,
        expectedBody: transactionBody({
          id,
          legacy,
          observedActive: predecessor,
          predecessor,
          recordedAt: observedAt,
          stage: ROTATION_STAGE,
          successor,
        }),
        expectedKeyId: keyId,
        expectedStage: ROTATION_STAGE,
        key,
        nowMs,
      });
      ensureDurable(custody, ROTATION_INTENT_NAME, intent.bytes);
      ensureDurable(custody, ROTATION_PREDECESSOR_NAME, predecessorBytes);
    }
    const authorizationBytes = canonicalBytes(transactionDocument(
      key,
      "authorization",
      effectAuthorizationBody(intent.body, intent.bytes),
    ));
    ensureDurable(custody, ROTATION_AUTHORIZATION_NAME, authorizationBytes);
    validateEffectAuthorization(custodyRead(custody, ROTATION_AUTHORIZATION_NAME), key, intent.body, intent.bytes);
    if (predecessorBytes !== null) {
      replaceDurable(custody, activeName, predecessorBytes, successor.bytes);
    }
    if (!custodyRead(custody, activeName)?.equals(successor.bytes)) {
      refuse("EXTERNAL_TRANSACTION_POST_EFFECT_STATE_INVALID");
    }
    const receiptBytes = canonicalBytes(transactionDocument(
      key,
      "completion",
      completionBody(intent.body, intent.bytes, authorizationBytes),
    ));
    ensureDurable(custody, ROTATION_RECEIPT_NAME, receiptBytes);
    validateCompletion(
      custodyRead(custody, ROTATION_RECEIPT_NAME),
      key,
      intent.body,
      intent.bytes,
      authorizationBytes,
    );
    if (retainedReceipt !== null && !retainedReceipt.equals(receiptBytes)) {
      refuse("EXTERNAL_TRANSACTION_EVIDENCE_MISMATCH");
    }
    if (retainedAuthorization !== null && !retainedAuthorization.equals(authorizationBytes)) {
      refuse("EXTERNAL_TRANSACTION_EVIDENCE_MISMATCH");
    }
    // The staged predecessor remains until the exact post-replacement completion receipt has been
    // durably authenticated/read back. It is cleanup evidence, never replacement authority.
    if (predecessorBytes !== null) removeDurable(custody, ROTATION_PREDECESSOR_NAME, predecessorBytes);
    if (custodyRead(custody, ROTATION_PREDECESSOR_NAME) !== null
        || !custodyRead(custody, activeName)?.equals(successor.bytes)) {
      refuse("EXTERNAL_TRANSACTION_POST_EFFECT_STATE_INVALID");
    }
    const evidence = transactionEvidence(
      ROTATION_STAGE,
      ROTATION_INTENT_NAME,
      intent.bytes,
      ROTATION_AUTHORIZATION_NAME,
      authorizationBytes,
      ROTATION_RECEIPT_NAME,
      receiptBytes,
      intent.body.transactionId,
    );
    return Object.freeze({
      authorization: null,
      authorizationBytes: null,
      observation: privateObservation({ bundle, controlManifest: manifest, observedAt, operation: ROTATION_STAGE, policy: successor, transactions: { freshRotation: evidence } }),
      transaction: evidence,
    });
  } finally {
    key.fill(0);
  }
}
