/**
 * Immutable per-record custody for local NOA boundary evidence.
 *
 * Both production writers use disjoint provenance-bound schema-v3 spool directories. Schema-v2
 * records remain parseable only as historical non-authority and can never satisfy a v3 claim. There is no shared append
 * pathname, writer lock, stale-owner inference, or recovery delete. A writer publishes one exact
 * record from its own O_EXCL pending name with a no-clobber hard link. The verified pending name is
 * retained as an explicit quarantine alias: Node has no inode-conditional unlink, so pathname
 * revalidation cannot authorize deletion in a same-UID concurrent-agent environment. Pre-existing
 * pending, malformed, mismatched, and unknown artifacts are evidence for review and are never
 * deleted here.
 *
 * The historical `~/.noa-boundary/ledger.jsonl` and `prepush-ledger.jsonl` files are
 * LEGACY_MIXED_VERSION_SOURCE. This module never opens, imports, copies, renames, repairs, appends,
 * or deletes either legacy source and makes no claim that another process cannot still mutate it.
 *
 * NON-CLAIMS: these local records are not globally ordered, WORM, authenticated, or exactly-once
 * events. The bounded claim is one immutable final pathname per stable recordId on a local
 * filesystem while the same-UID account, kernel, and storage stack remain in the TCB. Strict
 * long-term total retention and export are unresolved; writers enforce a free-space reserve and
 * never silently discard old evidence.
 */

import {
  lstatSync,
  readdirSync,
  statfsSync,
} from "node:fs";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { basename, dirname, join, resolve } from "node:path";
import {
  BoundaryCustodyError,
  durablePublishImmutableByLink,
  durablePublishImmutableByLinkCountsForSelftest,
  durablePublishImmutableByLinkTestDependencies,
  ensureOwnerOnlyDirectory,
  ownerOnlyFileCustodyProblem,
  readStableOwnerOnlyFile,
} from "./boundary-custody.mjs";
import {
  BOUNDARY_AUTHORITY_CLASS_CANDIDATE_TIER_A,
  BOUNDARY_AUTHORITY_CLASS_EXTERNAL,
  CANDIDATE_TIER_A_NON_AUTHORITY_NON_CLAIM,
  EXTERNAL_SANITIZED_AUTHORIZATION_NON_CLAIM,
} from "./boundary-bootstrap.mjs";
import { normalizeGateProvenance } from "./gate-event-contract.mjs";

const DIRECTORY_MODE = 0o700;
const PENDING_FILE_MODE = 0o600;
const FINAL_FILE_MODE = 0o400;
const MAX_RECORD_BYTES = 4096;
const MIN_FREE_SPACE_RESERVE_BYTES = 64n * 1024n * 1024n;
const RECORD_ID_DOMAIN = Buffer.from("noa-boundary/evidence-spool-record-id/v2\0", "utf8");
const HEX_32_RE = /^[0-9a-f]{32}$/;
const HEX_40_OR_64_RE = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const HEX_64_RE = /^[0-9a-f]{64}$/;
const RFC3339_UTC_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;
const SAFE_LANE_ID_RE = /^L-[A-Z][A-Z0-9-]{0,15}$/;
const FINAL_NAME_RE = /^record-v(?:2|3)-([0-9a-f]{64})-([1-9][0-9]{0,15})\.json$/;
const PENDING_NAME_RE = /^\.pending-v(?:2|3)-([0-9a-f]{64})-([1-9][0-9]{0,15})-p([1-9][0-9]{0,15})-([0-9a-f]{32})\.json$/;
const VERDICTS = new Set(["GREEN", "RED", "SETUP_FAILED", "BYPASSED"]);
const LANE_STATUSES = new Set(["scanned", "skipped", "empty", "empty-ok"]);
const VISIBILITY_EVIDENCE = new Set(["SNAPSHOT_NON_CLAIM", "LIVE_PROVIDER_VERIFIED"]);
const PRIVATE_INPUT_EVIDENCE = new Set(["SNAPSHOT_NON_CLAIM", "LIVE_COMMITMENT_MATCH", "TIER_B_UNMEASURED"]);
const STREAM_BY_EVENT = Object.freeze({
  BOUNDARY_GATE_VERDICT: "boundary",
  PREPUSH_GATE_VERDICT: "prepush",
});
const TEST_DEPENDENCY_BRAND = Symbol("boundary-spool-test-dependencies");
const TEST_OPTION_KEYS = Object.freeze([
  "faultAction", "faultCode", "faultPoint", "pendingNonceHex", "recordNonceHex", "statfs",
  "trace", "writeChunkBytes",
]);
const FAULT_ACTIONS = new Set(["crash", "throw", "zero-write"]);
const FAULT_CODES = new Set(["EIO", "ENOSPC", "EINVAL"]);
const FINAL_SETTLEMENT_RACE_CODES = new Set([
  "FILE_LINK_COUNT_REJECTED",
  "FILE_MISSING",
  "FILE_READ_CHANGED",
  "FILE_READ_FAILED",
  "SPOOL_FINAL_LINK_CONTRACT_REJECTED",
]);
const FINAL_SETTLEMENT_WAIT = new Int32Array(new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT));

export const BOUNDARY_EVIDENCE_SPOOL_VERSION = 3;
export const HISTORICAL_BOUNDARY_EVIDENCE_SPOOL_VERSION = 2;
export const HISTORICAL_BOUNDARY_EVIDENCE_NON_CLAIM =
  "SCHEMA_V2_RECORD_IS_HISTORICAL_NON_AUTHORITY_AND_CANNOT_SATISFY_PROVENANCE_BOUND_EVIDENCE";
export const BOUNDARY_EVIDENCE_RETENTION_NON_CLAIM =
  "STRICT_LONG_TERM_TOTAL_RETENTION_AND_EXPORT_UNRESOLVED_WRITER_NON_CLAIM";
export const LEGACY_BOUNDARY_EVIDENCE_PROVENANCE = "LEGACY_MIXED_VERSION_SOURCE";

const currentUid = () => (typeof process.geteuid === "function"
  ? process.geteuid()
  : (typeof process.getuid === "function" ? process.getuid() : null));
const permissionBits = (stat) => stat.mode & 0o7777;
const sameIdentity = (left, right) => left.dev === right.dev && left.ino === right.ino;

class SpoolFailure extends Error {
  constructor(code, cause = null) {
    super(code, cause === null ? undefined : { cause });
    this.name = "SpoolFailure";
    this.code = code;
  }
}

const refuse = (code, cause = null) => { throw new SpoolFailure(code, cause); };

function optionalStat(path) {
  try { return lstatSync(path); } catch (error) {
    if (error?.code === "ENOENT") return null;
    refuse("PATH_INSPECTION_FAILED", error);
  }
  return null;
}

function exactKeys(value, expected) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function exactOptionalKeys(value, allowed) {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    && Object.keys(value).every((key) => allowed.includes(key));
}

function safeCount(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function canonicalTimestamp(value) {
  if (typeof value !== "string" || !RFC3339_UTC_RE.test(value) || !Number.isFinite(Date.parse(value))) return false;
  const canonical = value.includes(".") ? value : value.replace(/Z$/, ".000Z");
  return new Date(Date.parse(value)).toISOString() === canonical;
}

/** Deterministic JSON for record identities and final bytes. */
export function canonicalJson(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number" && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  if (typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  throw new TypeError("unsupported canonical JSON value");
}

function validateBoundaryMetrics(metrics) {
  if (!exactKeys(metrics, [
    "blocking", "carried", "keyId", "lanes", "ledgerEntries", "privateInputsEvidence",
    "repositoryVisibilityEvidence", "repositoryVisibilityObservedAt", "scannedUnits", "suppressed", "tier",
  ])) return false;
  if (![metrics.blocking, metrics.carried, metrics.ledgerEntries, metrics.scannedUnits, metrics.suppressed].every(safeCount)) return false;
  if (metrics.keyId !== null && !HEX_64_RE.test(String(metrics.keyId))) return false;
  if (metrics.tier !== "a" && metrics.tier !== "ab") return false;
  if (!VISIBILITY_EVIDENCE.has(metrics.repositoryVisibilityEvidence)
      || !PRIVATE_INPUT_EVIDENCE.has(metrics.privateInputsEvidence)
      || !canonicalTimestamp(metrics.repositoryVisibilityObservedAt)) return false;
  if (!Array.isArray(metrics.lanes) || metrics.lanes.length === 0 || metrics.lanes.length > 16) return false;
  const seen = new Set();
  for (const lane of metrics.lanes) {
    if (!exactKeys(lane, ["id", "status", "units"]) || !SAFE_LANE_ID_RE.test(String(lane.id))
        || !LANE_STATUSES.has(lane.status) || !safeCount(lane.units) || seen.has(lane.id)) return false;
    seen.add(lane.id);
  }
  return true;
}

function validatePrepushMetrics(metrics) {
  if (!exactKeys(metrics, [
    "greenSteps", "overrideReasonSha256", "overrideReasonUtf8Bytes", "redSteps", "setupFailedSteps",
    "skippedSteps", "stepCount",
  ])) return false;
  if (![metrics.greenSteps, metrics.overrideReasonUtf8Bytes, metrics.redSteps,
    metrics.setupFailedSteps, metrics.skippedSteps, metrics.stepCount].every(safeCount)) return false;
  if (metrics.overrideReasonSha256 !== null && !HEX_64_RE.test(String(metrics.overrideReasonSha256))) return false;
  return metrics.greenSteps + metrics.redSteps + metrics.setupFailedSteps + metrics.skippedSteps === metrics.stepCount;
}

function normalizedProvenanceOrNull(provenance) {
  try { return normalizeGateProvenance(provenance); } catch { return null; }
}

function validateProvenanceForRecord(body) {
  const provenance = normalizedProvenanceOrNull(body.provenance);
  if (provenance === null) return false;
  const wantedVisibility = body.event === "BOUNDARY_GATE_VERDICT"
    ? (body.metrics.repositoryVisibilityEvidence === "LIVE_PROVIDER_VERIFIED" ? "live" : "snapshot")
    : "snapshot";
  const wantedTier = body.event === "BOUNDARY_GATE_VERDICT" ? body.metrics.tier : "a";
  if (provenance.verification === "UNVERIFIED_BOOTSTRAP") {
    return body.verdict !== "GREEN"
      && (provenance.tier === null || provenance.tier === wantedTier)
      && (provenance.visibilitySource === null || provenance.visibilitySource === wantedVisibility);
  }
  if (provenance.tier !== wantedTier || provenance.visibilitySource !== wantedVisibility) return false;
  if (provenance.verification !== "VERIFIED_BOOTSTRAP") return false;
  if (body.event === "PREPUSH_GATE_VERDICT" && provenance.verification === "VERIFIED_BOOTSTRAP") {
    return provenance.authorityClass === BOUNDARY_AUTHORITY_CLASS_CANDIDATE_TIER_A
      && provenance.authorityNonClaim === CANDIDATE_TIER_A_NON_AUTHORITY_NON_CLAIM
      && provenance.bootstrapMode === "candidate-tier-a-non-authority"
      && provenance.externalAuthorizationSha256 === null;
  }
  if (body.event === "BOUNDARY_GATE_VERDICT" && provenance.verification === "VERIFIED_BOOTSTRAP") {
    return provenance.authorityClass === BOUNDARY_AUTHORITY_CLASS_EXTERNAL
      && provenance.authorityNonClaim === EXTERNAL_SANITIZED_AUTHORIZATION_NON_CLAIM
      && provenance.bootstrapMode === "runtime"
      && HEX_64_RE.test(String(provenance.externalAuthorizationSha256));
  }
  return body.verdict !== "GREEN";
}

function validateRecordBody(body) {
  const historical = body?.schemaVersion === HISTORICAL_BOUNDARY_EVIDENCE_SPOOL_VERSION;
  const expectedKeys = historical
    ? ["schemaVersion", "event", "at", "repositoryHead", "verdict", "metrics", "recordNonce"]
    : ["schemaVersion", "event", "at", "repositoryHead", "verdict", "metrics", "provenance", "recordNonce"];
  if (!exactKeys(body, expectedKeys)
      || (!historical && body.schemaVersion !== BOUNDARY_EVIDENCE_SPOOL_VERSION)
      || STREAM_BY_EVENT[body.event] === undefined
      || !HEX_40_OR_64_RE.test(String(body.repositoryHead))
      || !VERDICTS.has(body.verdict)
      || !canonicalTimestamp(body.at)
      || !HEX_64_RE.test(String(body.recordNonce))) return false;
  const metricsValid = body.event === "BOUNDARY_GATE_VERDICT"
    ? validateBoundaryMetrics(body.metrics)
    : validatePrepushMetrics(body.metrics);
  return metricsValid && (historical || validateProvenanceForRecord(body));
}

function recordIdForBody(body) {
  return createHash("sha256")
    .update(RECORD_ID_DOMAIN)
    .update(Buffer.from(canonicalJson(body), "utf8"))
    .digest("hex");
}

function normalizeBigInt(value, what) {
  try {
    const normalized = typeof value === "bigint" ? value : BigInt(value);
    if (normalized < 0n) refuse("SPOOL_CAPACITY_INVALID");
    return normalized;
  } catch (error) {
    if (error instanceof SpoolFailure) throw error;
    refuse("SPOOL_CAPACITY_INVALID", new Error(what));
  }
  return 0n;
}

/** Exact, branded test-only seam. Production callers pass no second argument. */
export function boundarySpoolTestDependencies(options = {}) {
  if (!exactOptionalKeys(options, TEST_OPTION_KEYS)) refuse("TEST_DEPENDENCY_SCHEMA_REJECTED");
  const recordNonceHex = options.recordNonceHex ?? "11".repeat(32);
  const pendingNonceHex = options.pendingNonceHex ?? "22".repeat(16);
  if (!HEX_64_RE.test(recordNonceHex) || !HEX_32_RE.test(pendingNonceHex)) {
    refuse("TEST_DEPENDENCY_NONCE_REJECTED");
  }
  const faultPoint = options.faultPoint ?? null;
  const faultAction = options.faultAction ?? null;
  const faultCode = options.faultCode ?? "EIO";
  if ((faultPoint === null) !== (faultAction === null)
      || (faultPoint !== null && (typeof faultPoint !== "string" || !/^[a-z0-9-]{1,48}$/.test(faultPoint)))
      || (faultAction !== null && !FAULT_ACTIONS.has(faultAction))
      || !FAULT_CODES.has(faultCode)) refuse("TEST_DEPENDENCY_FAULT_REJECTED");
  const writeChunkBytes = options.writeChunkBytes ?? null;
  if (writeChunkBytes !== null && (!Number.isSafeInteger(writeChunkBytes) || writeChunkBytes <= 0)) {
    refuse("TEST_DEPENDENCY_WRITE_CHUNK_REJECTED");
  }
  const trace = options.trace ?? false;
  if (typeof trace !== "boolean") refuse("TEST_DEPENDENCY_TRACE_REJECTED");
  let statfs = null;
  if (options.statfs !== undefined) {
    if (!exactKeys(options.statfs, ["bavail", "blocks", "bsize"])) refuse("TEST_DEPENDENCY_STATFS_REJECTED");
    statfs = Object.freeze({
      bavail: normalizeBigInt(options.statfs.bavail, "bavail"),
      blocks: normalizeBigInt(options.statfs.blocks, "blocks"),
      bsize: normalizeBigInt(options.statfs.bsize, "bsize"),
    });
  }
  return Object.freeze({
    [TEST_DEPENDENCY_BRAND]: true,
    faultAction, faultCode, faultPoint, pendingNonceHex, recordNonceHex, statfs, testOnly: true, trace,
    writeChunkBytes,
  });
}

function dependenciesOrProduction(testDependencies) {
  if (testDependencies === undefined || testDependencies === null) {
    return Object.freeze({
      faultAction: null,
      faultCode: null,
      faultPoint: null,
      pendingNonceHex: randomBytes(16).toString("hex"),
      recordNonceHex: randomBytes(32).toString("hex"),
      statfs: null, testOnly: false,
      trace: false,
      writeChunkBytes: null,
    });
  }
  if (testDependencies?.[TEST_DEPENDENCY_BRAND] !== true) refuse("TEST_DEPENDENCY_SEAM_REJECTED");
  return testDependencies;
}

function injectedFault(dependencies, point) {
  if (dependencies.faultPoint !== point) return;
  if (dependencies.faultAction === "crash") process.kill(process.pid, "SIGKILL");
  if (dependencies.faultAction === "throw") refuse(`INJECTED_${dependencies.faultCode}`);
}

function custodyDependenciesForSpool(dependencies) {
  return durablePublishImmutableByLinkTestDependencies({
    faultAction: dependencies.faultAction,
    faultCode: dependencies.faultCode ?? "EIO",
    faultPoint: dependencies.faultPoint,
    trace: dependencies.trace,
    writeChunkBytes: dependencies.writeChunkBytes === null
      ? null
      : Math.min(dependencies.writeChunkBytes, MAX_RECORD_BYTES),
  });
}

export function boundarySpoolPrimitiveCountsForSelftest() {
  return durablePublishImmutableByLinkCountsForSelftest();
}

export function boundaryEvidenceSpoolDirectory(boundaryDirectoryPath, event) {
  const stream = STREAM_BY_EVENT[event];
  if (stream === undefined) refuse("RECORD_SCHEMA_REJECTED");
  return join(boundaryDirectoryPath, "evidence-spool-v3", stream);
}

function validateSpoolPath(spoolDirectoryPath, event) {
  if (typeof spoolDirectoryPath !== "string" || spoolDirectoryPath.length === 0
      || resolve(spoolDirectoryPath) !== spoolDirectoryPath) refuse("SPOOL_PATH_REJECTED");
  const expectedStream = STREAM_BY_EVENT[event];
  const versionRoot = dirname(spoolDirectoryPath);
  const boundaryRoot = dirname(versionRoot);
  if (basename(spoolDirectoryPath) !== expectedStream
      || !["evidence-spool-v2", "evidence-spool-v3"].includes(basename(versionRoot))
      || basename(boundaryRoot) !== ".noa-boundary") refuse("SPOOL_PATH_REJECTED");
  return { boundaryRoot, versionRoot };
}

function ensureSpoolDirectory(spoolDirectoryPath, event) {
  const { boundaryRoot, versionRoot } = validateSpoolPath(spoolDirectoryPath, event);
  const uid = currentUid();
  try {
    ensureOwnerOnlyDirectory({ directoryPath: boundaryRoot, mode: DIRECTORY_MODE, expectedUid: uid });
    ensureOwnerOnlyDirectory({ directoryPath: versionRoot, mode: DIRECTORY_MODE, expectedUid: uid });
    ensureOwnerOnlyDirectory({ directoryPath: spoolDirectoryPath, mode: DIRECTORY_MODE, expectedUid: uid });
  } catch (error) {
    if (error instanceof BoundaryCustodyError) refuse(error.code, error);
    throw error;
  }
}

function prepareRecord(input, dependencies) {
  if (input === null || typeof input !== "object" || Array.isArray(input)) refuse("RECORD_SCHEMA_REJECTED");
  const required = ["spoolDirectoryPath", "event", "repositoryHead", "verdict", "metrics"];
  const provenanceBound = Object.hasOwn(input, "provenance");
  if (!provenanceBound && dependencies.testOnly !== true) refuse("RECORD_PROVENANCE_REQUIRED");
  const version = provenanceBound
    ? BOUNDARY_EVIDENCE_SPOOL_VERSION
    : HISTORICAL_BOUNDARY_EVIDENCE_SPOOL_VERSION;
  const expected = [
    ...required,
    ...(provenanceBound ? ["provenance"] : []),
    ...(Object.hasOwn(input, "at") ? ["at"] : []),
  ];
  if (!exactKeys(input, expected)) refuse("RECORD_SCHEMA_REJECTED");
  const body = {
    schemaVersion: version,
    event: input.event,
    at: input.at ?? new Date().toISOString(),
    repositoryHead: input.repositoryHead,
    verdict: input.verdict,
    metrics: input.metrics,
    ...(provenanceBound ? { provenance: input.provenance } : {}),
    recordNonce: dependencies.recordNonceHex,
  };
  if (!validateRecordBody(body)) refuse("RECORD_SCHEMA_REJECTED");
  const spool = validateSpoolPath(input.spoolDirectoryPath, input.event);
  if (version === BOUNDARY_EVIDENCE_SPOOL_VERSION && basename(spool.versionRoot) !== "evidence-spool-v3") {
    refuse("SPOOL_PATH_REJECTED");
  }
  const recordId = recordIdForBody(body);
  const record = { ...body, recordId };
  const bytes = Buffer.from(canonicalJson(record), "utf8");
  if (bytes.length === 0 || bytes.length > MAX_RECORD_BYTES) refuse("RECORD_SIZE_REJECTED");
  const filename = `record-v${version}-${recordId}-${bytes.length}.json`;
  return Object.freeze({
    body, bytes, filename, record, recordId, schemaVersion: version,
    spoolDirectoryPath: input.spoolDirectoryPath,
  });
}

export function prepareBoundaryEvidenceRecord(input, testDependencies = null) {
  const dependencies = dependenciesOrProduction(testDependencies);
  return prepareRecord(input, dependencies);
}

function parseRecordBytes(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length === 0 || bytes.length > MAX_RECORD_BYTES) refuse("SPOOL_RECORD_MALFORMED");
  let text;
  let record;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    record = JSON.parse(text);
  } catch (error) {
    refuse("SPOOL_RECORD_MALFORMED", error);
  }
  const historical = record?.schemaVersion === HISTORICAL_BOUNDARY_EVIDENCE_SPOOL_VERSION;
  const expectedKeys = historical
    ? ["schemaVersion", "event", "at", "repositoryHead", "verdict", "metrics", "recordNonce", "recordId"]
    : ["schemaVersion", "event", "at", "repositoryHead", "verdict", "metrics", "provenance", "recordNonce", "recordId"];
  if (!exactKeys(record, expectedKeys)) {
    refuse("SPOOL_RECORD_MALFORMED");
  }
  const { recordId, ...body } = record;
  if (!validateRecordBody(body) || !HEX_64_RE.test(String(recordId))
      || recordIdForBody(body) !== recordId || text !== canonicalJson(record)) refuse("SPOOL_RECORD_MALFORMED");
  return record;
}

export function boundarySpoolArtifactCustodyProblem(
  stat,
  { allowLinks = [1], allowedModes = [FINAL_FILE_MODE], expectedUid = currentUid() } = {},
) {
  return ownerOnlyFileCustodyProblem(stat, { allowedLinks: allowLinks, allowedModes, expectedUid });
}

function readPathExact(path, {
  allowLinks = [1],
  allowedModes = [FINAL_FILE_MODE],
  expectedBytes = null,
  expectedUid = currentUid(),
} = {}) {
  try {
    const expected = expectedBytes === null ? null : Buffer.from(expectedBytes);
    return readStableOwnerOnlyFile({
      path,
      expectedBytes: expected,
      exactBytes: expected === null ? null : expected.length,
      maxBytes: MAX_RECORD_BYTES,
      allowedModes,
      allowedLinks: allowLinks,
      expectedUid,
    });
  } catch (error) {
    if (error instanceof SpoolFailure) throw error;
    if (error instanceof BoundaryCustodyError) refuse(error.code, error);
    refuse("FILE_READ_FAILED", error);
  }
  return null;
}

function validatedStatfs(path, dependencies) {
  injectedFault(dependencies, "statfs");
  let measured;
  try { measured = dependencies.statfs ?? statfsSync(path, { bigint: true }); } catch (error) {
    if (error instanceof SpoolFailure) throw error;
    refuse("SPOOL_CAPACITY_UNAVAILABLE", error);
  }
  if (measured === null || typeof measured !== "object") refuse("SPOOL_CAPACITY_INVALID");
  const bsize = normalizeBigInt(measured.bsize, "bsize");
  const bavail = normalizeBigInt(measured.bavail, "bavail");
  const blocks = normalizeBigInt(measured.blocks, "blocks");
  if (bsize <= 0n || blocks <= 0n || bavail > blocks) refuse("SPOOL_CAPACITY_INVALID");
  return { bavail, blocks, bsize, freeBytes: bavail * bsize };
}

function assertCapacity(path, byteLength, dependencies) {
  const measured = validatedStatfs(path, dependencies);
  const length = BigInt(byteLength);
  const fileAllocation = ((length + measured.bsize - 1n) / measured.bsize) * measured.bsize;
  const projectedAllocation = fileAllocation + measured.bsize;
  if (measured.freeBytes < MIN_FREE_SPACE_RESERVE_BYTES + projectedAllocation) {
    refuse("SPOOL_CAPACITY_REACHED");
  }
  return { freeBytes: measured.freeBytes, projectedAllocation, reserveBytes: MIN_FREE_SPACE_RESERVE_BYTES };
}

function pendingPathFor(prepared, dependencies) {
  const name = `.pending-v${prepared.schemaVersion}-${prepared.recordId}-${prepared.bytes.length}`
    + `-p${process.pid}-${dependencies.pendingNonceHex}.json`;
  return join(prepared.spoolDirectoryPath, name);
}

function matchingPendingAlias(spoolDirectoryPath, prepared, final) {
  let names;
  try { names = readdirSync(spoolDirectoryPath).sort(); } catch (error) { refuse("SPOOL_DIRECTORY_READ_FAILED", error); }
  const matches = [];
  for (const name of names) {
    const parsed = PENDING_NAME_RE.exec(name);
    if (parsed === null || parsed[1] !== prepared.recordId || Number(parsed[2]) !== prepared.bytes.length) continue;
    if (!name.startsWith(`.pending-v${prepared.schemaVersion}-`)) continue;
    const path = join(spoolDirectoryPath, name);
    const stat = optionalStat(path);
    if (stat !== null && sameIdentity(stat, final.stat)) matches.push(path);
  }
  if (matches.length !== 1) refuse("SPOOL_FINAL_LINK_CONTRACT_REJECTED");
  const alias = readPathExact(matches[0], {
    allowLinks: [2],
    allowedModes: [FINAL_FILE_MODE],
    expectedBytes: prepared.bytes,
  });
  if (!sameIdentity(alias.stat, final.stat)) refuse("SPOOL_FINAL_LINK_CONTRACT_REJECTED");
  return matches[0];
}

function verifyFinalOnce(prepared, { allowCleanupResidue = true } = {}) {
  const finalPath = join(prepared.spoolDirectoryPath, prepared.filename);
  let measured;
  try {
    measured = readPathExact(finalPath, {
      allowLinks: allowCleanupResidue ? [1, 2] : [1],
      allowedModes: [FINAL_FILE_MODE],
    });
  } catch (error) {
    if (error instanceof SpoolFailure && error.code === "FILE_BYTES_CHANGED") refuse("SPOOL_RECORD_CONFLICT");
    throw error;
  }
  if (measured.bytes.length !== prepared.bytes.length || !timingSafeEqual(measured.bytes, prepared.bytes)) {
    refuse("SPOOL_RECORD_CONFLICT");
  }
  const record = parseRecordBytes(measured.bytes);
  if (record.recordId !== prepared.recordId) refuse("SPOOL_RECORD_CONFLICT");
  const parsedName = FINAL_NAME_RE.exec(prepared.filename);
  if (parsedName === null || parsedName[1] !== record.recordId || Number(parsedName[2]) !== measured.bytes.length) {
    refuse("SPOOL_RECORD_CONFLICT");
  }
  if (!prepared.filename.startsWith(`record-v${record.schemaVersion}-`)) refuse("SPOOL_RECORD_CONFLICT");
  let aliasPath = null;
  if (measured.stat.nlink === 2) {
    if (!allowCleanupResidue) refuse("SPOOL_FINAL_LINK_CONTRACT_REJECTED");
    try {
      aliasPath = matchingPendingAlias(prepared.spoolDirectoryPath, prepared, measured);
    } catch (error) {
      // A same-UID actor may move or remove the quarantine alias after our first final read. This
      // writer has no cleanup authority; it only restarts under the one-link read contract.
      if (!(error instanceof SpoolFailure) || error.code !== "SPOOL_FINAL_LINK_CONTRACT_REJECTED") throw error;
      measured = readPathExact(finalPath, {
        allowLinks: [1], allowedModes: [FINAL_FILE_MODE], expectedBytes: prepared.bytes,
      });
      parseRecordBytes(measured.bytes);
    }
  }
  return { aliasPath, finalPath, measured, cleanupResidue: aliasPath !== null };
}

function verifyFinal(prepared, options = {}) {
  let lastError = null;
  for (let attempt = 0; attempt < 16; attempt++) {
    try { return verifyFinalOnce(prepared, options); } catch (error) {
      if (!(error instanceof SpoolFailure) || !FINAL_SETTLEMENT_RACE_CODES.has(error.code)) throw error;
      lastError = error;
      // Namespace state can settle while a read is in flight. This bounded wait never confers
      // stale-owner or delete authority; it only lets a read restart from the final pathname.
      Atomics.wait(FINAL_SETTLEMENT_WAIT, 0, 0, 1);
    }
  }
  throw lastError;
}

function warningFor(event, code, evidenceState, cleanupResidue = false) {
  const stream = event === "PREPUSH_GATE_VERDICT" ? "PREPUSH" : "BOUNDARY";
  const safeCode = /^[A-Z0-9_]{1,64}$/.test(String(code)) ? code : "UNEXPECTED";
  const state = evidenceState === "PERSISTED"
    ? "evidence_persisted"
    : (evidenceState === "INDETERMINATE" ? "evidence_indeterminate" : "evidence_not_persisted");
  return `NOA_EVIDENCE_WRITE_WARNING stream=${stream} spool=v3 code=${safeCode} ${state}`
    + `${cleanupResidue ? " cleanup_residue" : ""}`;
}

function failureCode(error) {
  if (error instanceof SpoolFailure || error instanceof BoundaryCustodyError) return error.code;
  return "UNEXPECTED";
}

function allocatedBytesForStat(stat) {
  if (!Number.isSafeInteger(stat.blocks) || stat.blocks < 0) refuse("SPOOL_ALLOCATION_UNAVAILABLE");
  return BigInt(stat.blocks) * 512n;
}

export function inspectBoundaryEvidenceSpool({ spoolDirectoryPath, event }) {
  validateSpoolPath(spoolDirectoryPath, event);
  const directory = optionalStat(spoolDirectoryPath);
  if (directory === null) {
    return Object.freeze({
      allocatedBytes: "0", cleanupResidueCount: 0, exists: false, logicalBytes: "0",
      historicalCount: 0, malformedCount: 0, pendingCount: 0, provenanceBoundCount: 0,
      validCount: 0,
    });
  }
  if (directory.isSymbolicLink() || !directory.isDirectory()
      || permissionBits(directory) !== DIRECTORY_MODE
      || (currentUid() !== null && directory.uid !== currentUid())) refuse("DIRECTORY_CUSTODY_REJECTED");
  let names;
  try { names = readdirSync(spoolDirectoryPath).sort(); } catch (error) { refuse("SPOOL_DIRECTORY_READ_FAILED", error); }
  const entries = new Map();
  let logicalBytes = 0n;
  let allocatedBytes = 0n;
  for (const name of names) {
    const path = join(spoolDirectoryPath, name);
    const stat = optionalStat(path);
    if (stat === null) continue;
    entries.set(name, { path, stat });
    logicalBytes += BigInt(stat.size);
    allocatedBytes += allocatedBytesForStat(stat);
  }
  let validCount = 0;
  let historicalCount = 0;
  let provenanceBoundCount = 0;
  let pendingCount = 0;
  let malformedCount = 0;
  let cleanupResidueCount = 0;
  const pendingByIdentity = new Map();
  for (const [name, entry] of entries) {
    const parsed = PENDING_NAME_RE.exec(name);
    if (parsed === null) continue;
    const declaredLength = Number(parsed[2]);
    const problem = boundarySpoolArtifactCustodyProblem(entry.stat, {
      allowLinks: [1, 2], allowedModes: [PENDING_FILE_MODE, FINAL_FILE_MODE],
    });
    if (problem !== null || !Number.isSafeInteger(declaredLength) || declaredLength > MAX_RECORD_BYTES
        || entry.stat.size > declaredLength) {
      malformedCount++;
      continue;
    }
    pendingCount++;
    const key = `${entry.stat.dev}:${entry.stat.ino}`;
    const aliases = pendingByIdentity.get(key) ?? [];
    aliases.push({ ...entry, name, parsed });
    pendingByIdentity.set(key, aliases);
  }
  for (const [name, entry] of entries) {
    const parsed = FINAL_NAME_RE.exec(name);
    if (parsed === null) {
      if (!PENDING_NAME_RE.test(name)) malformedCount++;
      continue;
    }
    try {
      const measured = readPathExact(entry.path, {
        allowLinks: [1, 2], allowedModes: [FINAL_FILE_MODE],
      });
      const record = parseRecordBytes(measured.bytes);
      if (record.recordId !== parsed[1] || measured.bytes.length !== Number(parsed[2])) {
        refuse("SPOOL_RECORD_MALFORMED");
      }
      if (!name.startsWith(`record-v${record.schemaVersion}-`)) refuse("SPOOL_RECORD_MALFORMED");
      if (measured.stat.nlink === 2) {
        const aliases = pendingByIdentity.get(`${measured.stat.dev}:${measured.stat.ino}`) ?? [];
        if (aliases.length !== 1 || aliases[0].parsed[1] !== record.recordId
            || Number(aliases[0].parsed[2]) !== measured.bytes.length
            || permissionBits(aliases[0].stat) !== FINAL_FILE_MODE) refuse("SPOOL_FINAL_LINK_CONTRACT_REJECTED");
        const alias = readPathExact(aliases[0].path, {
          allowLinks: [2], allowedModes: [FINAL_FILE_MODE], expectedBytes: measured.bytes,
        });
        if (!sameIdentity(alias.stat, measured.stat)) refuse("SPOOL_FINAL_LINK_CONTRACT_REJECTED");
        cleanupResidueCount++;
      }
      validCount++;
      if (record.schemaVersion === HISTORICAL_BOUNDARY_EVIDENCE_SPOOL_VERSION) historicalCount++;
      else provenanceBoundCount++;
    } catch {
      malformedCount++;
    }
  }
  return Object.freeze({
    allocatedBytes: allocatedBytes.toString(), cleanupResidueCount, exists: true,
    historicalCount, logicalBytes: logicalBytes.toString(), malformedCount, pendingCount,
    provenanceBoundCount, validCount,
  });
}

const SPOOL_CUSTODY_CODE_MAP = Object.freeze({
  CANDIDATE_CREATE_ENOSPC: "PENDING_CREATE_ENOSPC",
  CANDIDATE_CREATE_FAILED: "PENDING_CREATE_FAILED",
  CANDIDATE_IDENTITY_CHANGED: "PENDING_IDENTITY_CHANGED",
  CANDIDATE_NAME_COLLISION: "PENDING_NAME_COLLISION",
  CANDIDATE_READBACK_FAILED: "PENDING_READBACK_FAILED",
  CANDIDATE_WRITE_ENOSPC: "PENDING_WRITE_ENOSPC",
  CANDIDATE_WRITE_FAILED: "PENDING_WRITE_FAILED",
  FILE_ALREADY_EXISTS: "SPOOL_RECORD_CONFLICT",
  FILE_BYTES_CHANGED: "SPOOL_RECORD_CONFLICT",
});

function spoolCodeForCustody(code) {
  return SPOOL_CUSTODY_CODE_MAP[code] ?? code ?? "UNEXPECTED";
}

/** Publish one exact immutable aggregate record; failures are bounded data, never gate verdicts. */
export function appendBoundaryLedgerRecord(input, testDependencies = null) {
  let dependencies;
  let prepared;
  let pendingPath = null;
  let publication = null;
  let cleanupResidue = false;
  let operationError = null;
  try {
    dependencies = dependenciesOrProduction(testDependencies);
    prepared = prepareRecord(input, dependencies);
    ensureSpoolDirectory(prepared.spoolDirectoryPath, input.event);
    const finalPath = join(prepared.spoolDirectoryPath, prepared.filename);
    if (optionalStat(finalPath) !== null) {
      cleanupResidue = verifyFinal(prepared).cleanupResidue;
    } else {
      assertCapacity(prepared.spoolDirectoryPath, prepared.bytes.length, dependencies);
    }
    pendingPath = pendingPathFor(prepared, dependencies);
    publication = durablePublishImmutableByLink({
      candidatePath: pendingPath,
      destinationPath: finalPath,
      bytes: prepared.bytes,
      candidateMode: PENDING_FILE_MODE,
      immutableMode: FINAL_FILE_MODE,
      directoryMode: DIRECTORY_MODE,
      expectedUid: currentUid(),
      maxBytes: MAX_RECORD_BYTES,
      existingFinalLinks: [1, 2],
      retainCandidateOnConflict: true,
      syncCandidateDirectoryBeforeLink: false,
    }, custodyDependenciesForSpool(dependencies));
    cleanupResidue = cleanupResidue || publication.cleanupResidue;
    if (publication.status === "INDETERMINATE") refuse(spoolCodeForCustody(publication.code));
    if (publication.status !== "CREATED" && publication.status !== "EXISTING") {
      refuse("IMMUTABLE_PUBLISH_RESULT_REJECTED");
    }
    const verified = verifyFinal(prepared, { allowCleanupResidue: true });
    // A same-UID peer can change the non-authoritative pending pathname between the publication
    // result and this final reread. Once either observation reports residue, never erase that
    // uncertainty merely because the authoritative final later settles to a one-link state.
    cleanupResidue = cleanupResidue || verified.cleanupResidue;
    const created = publication.status === "CREATED";
    return {
      bytesPublished: prepared.bytes.length,
      cleanupResidue,
      created,
      evidencePersisted: true,
      evidenceState: "PERSISTED",
      filename: prepared.filename,
      idempotent: !created,
      ok: true,
      recordId: prepared.recordId,
      warning: cleanupResidue
        ? warningFor(input.event, "SPOOL_CLEANUP_RESIDUE", "PERSISTED", true)
        : null,
    };
  } catch (error) {
    operationError = error;
  }

  const code = failureCode(operationError);
  let pendingResidue = publication === null ? false : publication.candidateResidue !== false;
  if (publication === null && pendingPath !== null) {
    try { pendingResidue = optionalStat(pendingPath) !== null; } catch { pendingResidue = true; }
  }
  cleanupResidue = cleanupResidue || pendingResidue || publication?.cleanupResidue === true;
  const evidenceState = publication?.persistence ?? "NOT_PERSISTED";
  return {
    cleanupResidue,
    closeCode: null,
    code,
    evidencePersisted: evidenceState === "PERSISTED",
    evidenceState,
    filename: prepared?.filename ?? null,
    ok: false,
    pendingResidue,
    recordId: prepared?.recordId ?? null,
    warning: warningFor(input?.event, code, evidenceState, cleanupResidue),
  };
}
