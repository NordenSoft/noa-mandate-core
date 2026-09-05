#!/usr/bin/env node
/**
 * lint-boundary.mjs — L12, the open-core publish boundary gate.
 *
 * Apache-2.0, part of noa-receipt. Node >=20 stdlib only, no third-party dependencies.
 *
 * ─── WHY THIS EXISTS, MEASURED RATHER THAN ASSERTED ──────────────────────────────────────────────
 *
 * A multi-surface audit established that package-only inspection cannot cover repository history,
 * refs, documentation, and publish-artifact metadata. `npm pack` cannot see a commit message, a ref
 * name, a tag, `conformance/**`, or most of `docs/**`, so this gate derives and inspects those
 * independently enumerated surfaces as well.
 *
 * A control that prints GREEN over exactly the class that leaked is this product's own founding
 * principle failing on us. So this gate is built to be structurally incapable of that:
 *
 *   1. SCOPE IS DERIVED, NEVER LISTED. Eight lanes, each naming an external enumerator — git and
 *      npm answer "what is in scope", not this file. A lane that derives zero units where zero is
 *      impossible exits 2; it never reports a smaller success.
 *   2. THE BASELINE COMES FROM OUTSIDE. What counts as confidential is (a) shapes, which are public
 *      knowledge, (b) the forge's own answer about which repositories are PUBLIC — inverted, so this
 *      repository never carries a list of what is private — and (c) HMAC digests under a key that
 *      lives outside the repository. The gate chooses none of the three.
 *   3. IT CANNOT FAIL OPEN. Every "could not run" path exits 2 with a distinguishable message.
 *      "The check could not run" and "the check passed" never share an exit code.
 *
 * ─── EXIT CODES ──────────────────────────────────────────────────────────────────────────────────
 *
 *     0   scanned, no unratcheted findings
 *     1   findings
 *     2   SETUP_FAILED or usage — the gate could not do its job
 *
 * Both 1 and 2 block. The difference is where to look.
 *
 * ─── WHAT IT CANNOT DO ───────────────────────────────────────────────────────────────────────────
 *
 * Tier A is shapes and Tier B is exact tokens. Prose that DESCRIBES a confidential programme without
 * naming it passes both. After a push, a finding is an INCIDENT, not a gate — which is why the
 * pre-push step is primary and the pre-push escape hatch does not reach it. A `--no-verify` push
 * defeats every local hook in existence; CI on `push: '**'` is the record, the required check blocks
 * the merge, and only a server-side ruleset could refuse the bytes.
 *
 * ─── COMMANDS ────────────────────────────────────────────────────────────────────────────────────
 *
 *     node scripts/lint-boundary.mjs --repo-visibility-source snapshot
 *                                                          default lanes; loud NON-CLAIM snapshot
 *     node scripts/lint-boundary.mjs --repo-visibility-source live
 *                                                          live provider proof; refuses snapshot drift
 *     node scripts/lint-boundary.mjs --explain             + the rule, the enumerator, and the fix
 *     node scripts/lint-boundary.mjs --lane L-PACK,L-MAP   named lanes only
 *     node scripts/lint-boundary.mjs --range a..b          also the commit/tag lanes over a range
 *     node scripts/lint-boundary.mjs --refs-from-stdin --pre-push-remote <name>
 *       --pre-push-url <location> --repo-visibility-source live
 *                                                          exact pre-push object/ref mode
 *     node scripts/lint-boundary.mjs --publish-path        + the local publish-credential check
 *     node scripts/lint-boundary.mjs --tier a              shapes only; prints TIER-B UNMEASURED
 *     node scripts/lint-boundary.mjs --selftest            the arm
 *     node scripts/lint-boundary.mjs --spool-selftest      focused schema-v2 evidence-spool arm
 *     node scripts/lint-boundary.mjs --custody-contract-selftest
 *                                                          scanner-independent custody contracts
 *     node scripts/lint-boundary.mjs --repo-visibility-source live --refresh-public-repos
 *     # review and freeze the public snapshot/control manifest, then separately:
 *     node scripts/lint-boundary.mjs --repo-visibility-source live --refresh-tokens
 *     node scripts/lint-boundary.mjs --migrate-exclusions|--rotate-exclusions
 *       --reviewer <reviewer> --reviewed-at <instant> --expires-at <instant>
 *       --review-session <uuid>
 *       --classification PUBLIC_DERIVED_COLLISION
 *       --public-artifact <package@version> --public-artifact-sri <sha512-SRI>
 *     node scripts/lint-boundary.mjs --tighten-known-exposure
 *     node scripts/lint-boundary.mjs --print-exposure-candidates   review-only; writes nothing, exits 2
 */

import { spawn, spawnSync } from "node:child_process";
import {
  constants as fsConstants,
  existsSync,
  chmodSync,
  readFileSync,
  writeFileSync,
  mkdirSync,
  mkdtempSync,
  lstatSync,
  fstatSync,
  openSync,
  closeSync,
  readSync,
  readlinkSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
} from "node:fs";
import { basename, dirname, join, resolve, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { homedir, tmpdir } from "node:os";
import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";

import {
  commitToken,
  reachableTokenForms,
  tokenForms,
  tokenNgramSize,
} from "./lib/boundary-token.mjs";
import {
  armCandidateTierANonAuthorityBootstrap,
  BOUNDARY_AUTHORITY_CLASS_CANDIDATE_TIER_A,
  BOUNDARY_AUTHORITY_CLASS_EXTERNAL,
  BOUNDARY_CONTROL_MANIFEST_VERSION,
  BOUNDARY_KNOCKOUT_BOOTSTRAP_ENV,
  boundaryBootstrapFailure,
  CANDIDATE_TIER_A_NON_AUTHORITY_NON_CLAIM,
  clearUntrustedBoundaryBootstrapModeMarker,
  deriveBoundaryControlManifest,
  PREVIOUS_REVIEWED_CONTROL_PATHS,
  REVIEWED_CONTROL_PATHS,
  verifyBoundaryBootstrap,
  verifyBoundaryHookActivation,
} from "./lib/boundary-bootstrap.mjs";
import { APPROVED_BOUNDARY_LANES, assertLaneRegistry, laneById, DEFAULT_LANES } from "./lib/boundary-lanes.mjs";
import { boundaryGateProvenance } from "./lib/boundary-gate-provenance.mjs";
import { emitProvenanceBoundGateEvidence } from "./lib/gate-event-contract.mjs";
import {
  appendBoundaryLedgerRecord,
  boundaryEvidenceSpoolDirectory,
  boundarySpoolTestDependencies,
  canonicalJson as strictCanonicalJson,
  inspectBoundaryEvidenceSpool,
  prepareBoundaryEvidenceRecord,
} from "./lib/boundary-ledger.mjs";
import {
  BoundaryCustodyError,
  durableClaimExactByLink,
  durableCreateStageTargets,
  durableCreateExclusive,
  durablePublishImmutableByLink,
  durablePublishImmutableByLinkTestDependencies,
  durableReplaceFromCandidate,
  durableSyncExact,
  durableUnlinkClaimedSource,
  durableUnlinkExact,
  ensureOwnerOnlyDirectory,
  readStableOwnerOnlyFile,
  recoverDurableCreateForPath,
} from "./lib/boundary-custody.mjs";
import {
  packFrozenPackageArtifact,
  validateRepositoryPath,
} from "./lib/publish-artifact-staging.mjs";

let scanShapes;
let scanRepoRefs;
let scanPrivacyAdjacency;
let scanTokens;
let scanSourceMap;
let contentKey;
let pathContentKey;
let SEVERITY;
let boundaryBootstrapAuthority = null;
let parsedGateOptions = null;

const isDeclarationArtifactPath = (file) => /\.d\.(?:ts|mts|cts)$/i.test(String(file));
const isBoundaryStaticSourcePath = (file) => /\.(?:[cm]?[jt]s|[jt]sx)$/i.test(String(file));

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// Roots and paths. ROOT is resolved from this file's own location, never from the caller's cwd, and
// then RECONCILED with git's answer — a gate run from the wrong directory must refuse, not measure
// a different tree.
// ─────────────────────────────────────────────────────────────────────────────────────────────────
const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(SCRIPT_DIR, "..");
const KEY_DIR = join(homedir(), ".noa-boundary");
const KEY_FILE = join(KEY_DIR, "key");
const CANARY_FILE = join(KEY_DIR, "canary.txt");
const LEGACY_TOKENS_FILE = join(KEY_DIR, "tokens.txt");
const EXTRA_TOKENS_FILE = join(KEY_DIR, "extra-tokens.txt");
const EXCLUSION_POLICY_FILE = join(KEY_DIR, "exclusions.json");
const LEGACY_EXCLUDE_TOKENS_FILE = join(KEY_DIR, "exclude-tokens.txt");
const BOUNDARY_EVIDENCE_SPOOL = boundaryEvidenceSpoolDirectory(KEY_DIR, "BOUNDARY_GATE_VERDICT");
const ROTATION_RECEIPT_SCHEMA_VERSION = 2;
const LEGACY_ROTATION_RECEIPT_SCHEMA_VERSION = 1;
const ROTATION_RECEIPT_EVENT = "EXCLUSION_POLICY_ROTATED";
const ROTATION_RECEIPT_DOMAIN = "exclusion-policy-rotation-receipt/v2";
const LEGACY_ROTATION_RECEIPT_DOMAIN = "exclusion-policy-rotation-receipt/v1";
const ROTATION_INTENT_SCHEMA_VERSION = 2;
const ROTATION_INTENT_EVENT = "EXCLUSION_POLICY_ROTATION_INTENT";
const ROTATION_INTENT_DOMAIN = "exclusion-policy-rotation-intent/v2";
const ROTATION_DURABILITY_PROFILE = "NODE_FSYNC_PROCESS_RESTART_V1";
const ROTATION_LOCK_FILE = join(KEY_DIR, "exclusion-policy-rotation.lock");
const ROTATION_LOCK_CLAIM_NAME_RE = /^exclusion-policy-rotation-lock-claim-([0-9a-f]{64})\.lock$/;
const FULL_SUPERSEDED_POLICY_NAME_RE = /^exclusions\.superseded-v([23])-([0-9a-f]{64})\.json$/;
const LEGACY_SUPERSEDED_POLICY_NAME_RE = /^exclusions\.superseded-v([23])-([0-9a-f]{16})\.json$/;
const PENDING_SUCCESSOR_NAME_RE = /^exclusions\.pending-successor-v3-([0-9a-f]{64})\.json$/;
const DELETING_POLICY_NAME_RE = /^exclusions\.deleting-v([23])-([0-9a-f]{64})\.json$/;
const ROTATION_INTENT_NAME_RE = /^exclusion-policy-rotation-intent-([0-9a-f]{64})\.json$/;
const ROTATION_RECEIPT_NAME_RE = /^exclusion-policy-rotation-v([23])-([0-9a-f]{64})-to-v3-([0-9a-f]{64})\.json$/;
const LEGACY_ROTATION_RECEIPT_NAME_RE = /^exclusion-policy-rotation-v([23])-([0-9a-f]{16})-to-v3-([0-9a-f]{16})\.json$/;
const LEGACY_RANDOM_DELETE_NAME_RE = /^\.exclusion-policy-delete-[0-9]+-[0-9a-f]{16}\.tmp$/;

const COMMITMENTS_PATH = join(ROOT, "scripts", "boundary-commitments.json");
const PUBLIC_REPOS_PATH = join(ROOT, "scripts", "boundary-public-repos.json");
const KNOWN_EXPOSURE_PATH = join(ROOT, "scripts", "boundary-known-exposure.json");

const MAX_BASELINE_AGE_DAYS = 30;
const MAX_FUTURE_SKEW_MS = 5 * 60 * 1000;
const LIVE_REPO_LIMIT = 10_000;
const PROVIDER_QUERY_TIMEOUT_MS = 30_000;
const GATE_ID = "boundary";
export const CANARY_PREFIX = "noaboundarycanary";
const KEY_BYTES = 32;
const KEY_MODE = 0o600;
const KEY_DIR_MODE = 0o700;
const MAX_CONFIDENTIAL_TEXT_BYTES = 1024 * 1024;
const COMMITMENT_SCHEMA_VERSION = 3;
const PREVIOUS_COMMITMENT_SCHEMA_VERSION = 2;
const EXCLUSION_POLICY_SCHEMA_VERSION = 3;
const PREVIOUS_EXCLUSION_POLICY_SCHEMA_VERSION = 2;
const MAX_EXCLUSION_VALIDITY_MS = 30 * 86_400_000;
const HEX_64_RE = /^[0-9a-f]{64}$/;
const URL_USERINFO_RE = /^[A-Za-z][A-Za-z0-9+.-]*:\/\/[^/]*@/;
const CANARY_RE = /^noaboundarycanary[0-9a-f]{24}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const PUBLIC_ARTIFACT_RE = /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*@[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$/;
// Compatibility exists only so the one authenticated, receipt-bound predecessor can recover
// forward. The canonical old/new registries live in the stdlib bootstrap consumed before parser
// import; duplicating either list here would let the two authority views drift.

const bold = (s) => `[1m${s}[0m`;
const red = (s) => `[31m${s}[0m`;
const green = (s) => `[32m${s}[0m`;
const yellow = (s) => `[33m${s}[0m`;

const QUIET = process.argv.includes("--knockout-json");
const say = (line) => { if (!QUIET) process.stderr.write(`${line}\n`); };
const compareText = (left, right) => (left === right ? 0 : (left < right ? -1 : 1));

function currentBoundaryGateProvenance() {
  const selftestOnly = parsedGateOptions?.selftest === true
    || parsedGateOptions?.outputContractSelftest === true
    || parsedGateOptions?.spoolSelftest === true
    || parsedGateOptions?.custodyContractSelftest === true;
  const tier = selftestOnly ? null : (parsedGateOptions?.tier ?? null);
  const visibilitySource = selftestOnly ? null : (parsedGateOptions?.repoVisibilitySource ?? null);
  return boundaryGateProvenance(boundaryBootstrapAuthority, { tier, visibilitySource });
}

function emitBoundaryGateEvidence(findings) {
  return emitProvenanceBoundGateEvidence(GATE_ID, findings, currentBoundaryGateProvenance());
}

// Every successful mutating/terminal operation uses this one exit path. In machine mode success is
// not an empty stdout plus OS status 0: it is exactly one provenance-bound empty finding terminal.
// Failure paths retain their own findings and exit semantics.
function exitSuccessfulBoundaryOperation(opts) {
  if (opts.knockoutJson) emitBoundaryGateEvidence([]);
  process.exit(0);
}

/**
 * SETUP_FAILED. Every one of these is a real, reachable branch with its own message — a gate that
 * cannot say WHY it could not run sends a human to the wrong place, and a gate that exits 0 when it
 * could not do its job is worse than no gate at all.
 */
function setupFailed(what, detail, fix) {
  if (process.argv.includes("--knockout-json")) {
    emitBoundaryGateEvidence([{ rule: "SETUP_FAILED", subject: what, detail: String(detail) }]);
    process.exit(2);
  }
  process.stderr.write(red(bold(`\n  lint-boundary: SETUP_FAILED — ${what}\n`)));
  process.stderr.write(`  ${detail}\n`);
  if (fix) process.stderr.write(yellow(`  fix: ${fix}\n`));
  process.stderr.write(
    `\n  This is exit 2, not exit 0. "The check could not run" and "the check passed" must never\n` +
    `  share an exit code, so this blocks exactly as a finding would.\n\n`,
  );
  process.exit(2);
}

async function loadParserBackedBoundaryScanner() {
  let scanner;
  try {
    scanner = await import("./lib/boundary-scan.mjs");
  } catch (error) {
    const failure = boundaryBootstrapFailure(error);
    setupFailed(
      failure.subject,
      `${failure.bootstrapCode}: ${failure.detail}`,
      failure.fix,
    );
  }
  ({
    scanShapes,
    scanRepoRefs,
    scanPrivacyAdjacency,
    scanTokens,
    scanSourceMap,
    contentKey,
    pathContentKey,
    SEVERITY,
  } = scanner);
  boundaryBootstrapAuthority = scanner.boundaryScannerAuthority;
}

function verifyRecoveryOnlyBootstrap() {
  try {
    boundaryBootstrapAuthority = verifyBoundaryBootstrap({ root: ROOT, mode: "recovery" });
    return boundaryBootstrapAuthority;
  } catch (error) {
    const failure = boundaryBootstrapFailure(error);
    setupFailed(
      failure.subject,
      `${failure.bootstrapCode}: ${failure.detail}`,
      failure.fix,
    );
  }
  return null;
}

function syntheticSupervisorFixtureAuthorized() {
  const requested = process.env.NOA_BOUNDARY_SYNTHETIC_SUPERVISOR_FIXTURE === "1";
  delete process.env.NOA_BOUNDARY_SYNTHETIC_SUPERVISOR_FIXTURE;
  if (!requested || boundaryBootstrapAuthority?.authorization?.controllerId
      !== "noa-boundary-external-supervisor/v1"
      || boundaryBootstrapAuthority?.subject?.repository !== "ExampleArmOrg/public-arm") return false;
  let manifest;
  try { manifest = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")); } catch { return false; }
  return manifest?.name === "synthetic-arm-package" && manifest?.version === "0.0.0";
}

function supervisorOnlyOperation(opts) {
  return opts.tier === "ab"
    || opts.repoVisibilitySource === "live"
    || opts.publishPath
    || opts.migrateExclusions
    || opts.recoverExclusionRotation
    || opts.rotateExclusions
    || opts.refreshPublicRepos
    || opts.refreshTokens
    || opts.tightenKnownExposure;
}

function requireExternalBoundarySupervisor(opts, syntheticSupervisorFixture, { missingChannel = false } = {}) {
  if (syntheticSupervisorFixture) return;
  if (!missingChannel && !supervisorOnlyOperation(opts)) return;
  const governanceMutation = opts.migrateExclusions || opts.recoverExclusionRotation
    || opts.rotateExclusions || opts.refreshPublicRepos || opts.refreshTokens
    || opts.tightenKnownExposure;
  const detail = governanceMutation
    ? "candidate CLI never receives exclusion-policy HMAC custody and cannot mutate governed boundary state"
    : opts.tier === "ab"
      ? "Tier B needs isolated HMAC custody and an exact-archive trusted scan; no general keyed lookup oracle is exposed to candidate code"
      : "this invocation is outside the closed keyless snapshot Tier-A non-authority class";
  setupFailed(
    "EXTERNAL_BOUNDARY_SUPERVISOR_REQUIRED",
    detail,
    "run only explicit --tier a plus snapshot for candidate non-authority evidence, or invoke the isolated N-1 supervisor",
  );
}

function hasExternalAuthorizationTransport() {
  return process.env.NOA_BOUNDARY_AUTHORIZATION_FD !== undefined
    || process.env.NOA_BOUNDARY_AUTHORIZATION_FILE !== undefined;
}

function exactCandidateSelftest(argv, flag) {
  const material = argv.filter((arg) => arg !== "--knockout-json");
  return material.length === 1 && material[0] === flag;
}

function candidateTierANonAuthorityEligible(opts, argv) {
  if (exactCandidateSelftest(argv, "--selftest")) return true;
  if (exactCandidateSelftest(argv, "--output-contract-selftest")) return true;
  return opts.candidateTierAScanGrammar === true
    && opts.tier === "a"
    && opts.repoVisibilitySource === "snapshot"
    && !opts.publishPath
    && !opts.refreshPublicRepos
    && !opts.refreshTokens
    && !opts.migrateExclusions
    && !opts.recoverExclusionRotation
    && !opts.rotateExclusions
    && !opts.tightenKnownExposure
    && !opts.printExposureCandidates
    && !opts.spoolSelftest
    && !opts.custodyContractSelftest;
}

function assertLoadedBootstrapAuthority(expectedClass) {
  const observed = boundaryBootstrapAuthority;
  if (observed?.authorityClass !== expectedClass
      || typeof observed.authorityNonClaim !== "string"
      || observed.authorityNonClaim.length === 0) {
    setupFailed(
      "the boundary bootstrap authority class is missing or mislabeled",
      "every parser-backed result must freeze its exact authority class and non-claim",
      "restore the reviewed bootstrap result contract",
    );
  }
  if (expectedClass === BOUNDARY_AUTHORITY_CLASS_CANDIDATE_TIER_A
      && (observed.authorization !== null
        || observed.authorityNonClaim !== CANDIDATE_TIER_A_NON_AUTHORITY_NON_CLAIM
        || observed.mode !== "candidate-tier-a-non-authority")) {
    setupFailed(
      "the candidate Tier-A bootstrap result acquired an authority claim",
      "candidate evidence must carry null external authorization and the exact non-authority label",
      "restore CANDIDATE_TIER_A_NON_AUTHORITY result semantics",
    );
  }
  say(`  BOUNDARY_BOOTSTRAP_AUTHORITY_CLASS=${observed.authorityClass}`);
  say(`  BOUNDARY_BOOTSTRAP_NON_CLAIM=${observed.authorityNonClaim}`);
}

const permissionBits = (stat) => stat.mode & 0o7777;
const octal = (mode) => `0${mode.toString(8).padStart(3, "0")}`;
const currentUid = () => (typeof process.geteuid === "function"
  ? process.geteuid()
  : (typeof process.getuid === "function" ? process.getuid() : null));

function requiredFsFlag(name, unsafeWithoutIt) {
  const flag = fsConstants[name];
  if (typeof flag !== "number" || flag === 0) {
    setupFailed(
      `this platform cannot safely open confidential boundary inputs without ${name}`,
      unsafeWithoutIt,
      "run Tier B on Linux or macOS with the required filesystem-open controls",
    );
  }
  return flag;
}

function inspectPath(path, what, { optional = false } = {}) {
  try {
    return lstatSync(path);
  } catch (e) {
    if (e?.code === "ENOENT" && optional) return null;
    if (e?.code === "ENOENT") setupFailed(`${what} is missing`, `expected ${opaquePathId(path)}`, "restore the outside-repository confidential input before running Tier B");
    setupFailed(`${what} cannot be inspected`, `${opaquePathId(path)}: ${e?.code ?? "I/O error"}`, "repair the outside-repository boundary-key custody");
  }
  return null;
}

function assertBoundaryDirectory(stat) {
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    setupFailed(
      "the boundary key directory is not a real directory",
      `${opaquePathId(KEY_DIR)} must be a non-symlink directory; got ${stat.isSymbolicLink() ? "a symbolic link" : "another file type"}`,
      "replace it with an owner-controlled directory",
    );
  }
  const mode = permissionBits(stat);
  if (mode !== KEY_DIR_MODE) {
    setupFailed(
      "the boundary key directory permissions are unsafe",
      `${opaquePathId(KEY_DIR)} must have exact mode ${octal(KEY_DIR_MODE)}; got ${octal(mode)}`,
      `set the boundary key directory to owner-only mode ${octal(KEY_DIR_MODE)}`,
    );
  }
  const uid = currentUid();
  if (uid !== null && stat.uid !== uid) {
    setupFailed(
      "the boundary key directory has the wrong owner",
      `${opaquePathId(KEY_DIR)} is owned by uid ${stat.uid}; this process runs as uid ${uid}`,
      "restore ownership to the account running the boundary gate",
    );
  }
}

function boundaryKeyDirectory({ create = false } = {}) {
  let stat;
  try {
    stat = lstatSync(KEY_DIR);
  } catch (e) {
    if (e?.code !== "ENOENT" || !create) {
      if (e?.code === "ENOENT") {
        setupFailed(
          "the boundary key directory is missing",
          `expected ${opaquePathId(KEY_DIR)}`,
          "restore the outside-repository boundary-key custody before running Tier B",
        );
      }
      setupFailed("the boundary key directory cannot be inspected", `${opaquePathId(KEY_DIR)}: ${e?.code ?? "I/O error"}`, "repair the outside-repository boundary-key custody");
    }
    try {
      stat = ensureOwnerOnlyDirectory({
        directoryPath: KEY_DIR,
        mode: KEY_DIR_MODE,
        repairMode: false,
      }).stat;
    } catch (createError) {
      setupFailed(
        "the boundary key directory could not be created safely",
        `${opaquePathId(KEY_DIR)}: ${createError instanceof BoundaryCustodyError ? createError.code : "create failed"}`,
        "create an owner-controlled non-symlink directory with mode 0700",
      );
    }
  }
  assertBoundaryDirectory(stat);
  return stat;
}

const sameFileIdentity = (left, right) => left.dev === right.dev && left.ino === right.ino;
const sameFileState = (left, right) => sameFileIdentity(left, right)
  && left.size === right.size
  && left.mtimeMs === right.mtimeMs
  && left.ctimeMs === right.ctimeMs
  && left.mode === right.mode
  && left.uid === right.uid
  && left.nlink === right.nlink;
const STABLE_READ_SETTLE_MS = 2;

function readFdExact(fd, size, what) {
  const bytes = Buffer.alloc(size);
  let offset = 0;
  while (offset < size) {
    const count = readSync(fd, bytes, offset, size - offset, offset);
    if (count === 0) {
      setupFailed(`the ${what} became shorter during the read`, "the opened descriptor reached EOF before its inspected size", "stop concurrent writers and retry");
    }
    offset += count;
  }
  return bytes;
}

/**
 * Read a Tier-B confidential input only after its custody is established. The path and open
 * descriptor are checked by the shared custody authority so a symlink, hard link, permission
 * regression, path swap, or in-place write cannot be mistaken for the committed key merely because
 * one sampled read happened to have the expected fingerprint.
 */
function readConfidentialFile(path, what, options = {}) {
  try {
    const exactBytes = options.exactBytes ?? null;
    const measured = readStableOwnerOnlyFile({
      path,
      exactBytes,
      maxBytes: options.maxBytes ?? exactBytes ?? MAX_CONFIDENTIAL_TEXT_BYTES,
      allowedModes: [KEY_MODE],
      allowedLinks: [options.allowLinks ?? 1],
      expectedUid: currentUid(),
      directoryPath: KEY_DIR,
      directoryMode: KEY_DIR_MODE,
      optional: options.optional === true,
      settleMs: STABLE_READ_SETTLE_MS,
    });
    return measured?.bytes ?? null;
  } catch (error) {
    if (!(error instanceof BoundaryCustodyError)) {
      setupFailed(`the ${what} could not be read safely`, `${opaquePathId(path)}: read failed`, "restore stable input custody");
    }
    const detail = `${opaquePathId(path)}: ${error.code}`;
    if (error.code === "FILE_MISSING") {
      setupFailed(`${what} is missing`, detail, "restore the outside-repository confidential input before running Tier B");
    }
    if (error.code === "FILE_TYPE_REJECTED") {
      setupFailed(`the ${what} is not a regular non-symlink file`, detail, "replace it with a single owner-controlled regular file");
    }
    if (error.code === "FILE_EXACT_SIZE_REJECTED") {
      setupFailed(`the ${what} has the wrong length`, detail, "restore the exact reviewed confidential input");
    }
    if (error.code === "FILE_SIZE_LIMIT_REJECTED") {
      setupFailed(`the ${what} exceeds its size bound`, detail, "review and reduce the confidential input before retrying");
    }
    if (error.code === "FILE_MODE_REJECTED") {
      setupFailed(`the ${what} permissions are unsafe`, detail, `set the confidential file to owner-only mode ${octal(KEY_MODE)}`);
    }
    if (error.code === "FILE_OWNER_REJECTED") {
      setupFailed(`the ${what} has the wrong owner`, detail, "restore ownership to the account running the boundary gate");
    }
    if (error.code === "FILE_LINK_COUNT_REJECTED") {
      const allowLinks = options.allowLinks ?? 1;
      setupFailed(
        allowLinks === 1 ? `the ${what} has multiple hard links` : `the ${what} has an unexpected hard-link count`,
        detail,
        "restore the exact owner-controlled custody state without alternate aliases",
      );
    }
    if (error.code === "DIRECTORY_TYPE_REJECTED") {
      setupFailed("the boundary key directory is not a real directory", detail, "replace it with an owner-controlled directory");
    }
    if (error.code === "DIRECTORY_MODE_REJECTED") {
      setupFailed("the boundary key directory permissions are unsafe", detail, `set the boundary key directory to owner-only mode ${octal(KEY_DIR_MODE)}`);
    }
    if (error.code === "DIRECTORY_OWNER_REJECTED") {
      setupFailed("the boundary key directory has the wrong owner", detail, "restore ownership to the account running the boundary gate");
    }
    if (["DIRECTORY_IDENTITY_CHANGED", "DIRECTORY_MISSING", "FILE_IDENTITY_CHANGED"].includes(error.code)) {
      setupFailed(`the ${what} custody changed during the read`, detail, "stop concurrent key replacement and retry with stable custody");
    }
    if (["FILE_READ_CHANGED", "SHORT_READ"].includes(error.code)) {
      setupFailed(`the opened ${what} changed during the stable double-read`, detail, "stop concurrent or in-place writers and retry with stable custody");
    }
    setupFailed(`the ${what} could not be read safely`, detail, "restore stable input custody");
  }
  return null;
}

function readConfidentialText(path, what, options = {}) {
  const bytes = readConfidentialFile(path, what, options);
  if (bytes === null) return null;
  return decodeConfidentialUtf8(bytes, what);
}

function writeConfidentialExclusive(path, what, bytes) {
  boundaryKeyDirectory({ create: true });
  try {
    durableCreateExclusive({ path, bytes, mode: KEY_MODE });
  } catch (error) {
    setupFailed(
      `the ${what} could not be created durably and exclusively`,
      `${opaquePathId(path)}: ${error instanceof BoundaryCustodyError ? error.code : "create failed"}`,
      "resolve the custody conflict; never overwrite an unknown confidential file",
    );
  }
  const measured = readConfidentialFile(path, what, { exactBytes: bytes.length });
  if (!measured.equals(Buffer.from(bytes))) setupFailed(`the ${what} changed immediately after creation`, "the bytes read back differ from the create-exclusive input", "stop concurrent writers and retry");
}

const readBoundaryKey = () => readConfidentialFile(KEY_FILE, "boundary key", { exactBytes: KEY_BYTES });

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// Process helpers. `shell: false` always; explicit cwd always; a non-zero exit from an enumerator is
// SETUP_FAILED with only bounded structural status, never raw argv/cwd/stderr and never `|| true`.
// ─────────────────────────────────────────────────────────────────────────────────────────────────
const gitProcessEnvironment = () => ({ ...process.env, GIT_NO_REPLACE_OBJECTS: "1" });

function capture(cmd, args, opts = {}) {
  const env = cmd === "git"
    ? gitProcessEnvironment()
    : process.env;
  const r = spawnSync(cmd, args, {
    cwd: opts.cwd ?? ROOT,
    shell: false,
    encoding: opts.encoding ?? "utf8",
    maxBuffer: 256 * 1024 * 1024,
    timeout: opts.timeoutMs,
    env,
  });
  if (r.error && r.error.code === "ENOENT") {
    setupFailed(
      `the external tool "${cmd}" is not on PATH`,
      "the enumerator could not start; arguments and paths are withheld because they may themselves be publication-boundary data",
      `install ${cmd}, or run this gate where ${cmd} exists`,
    );
  }
  if (r.error && r.error.code === "ETIMEDOUT") {
    setupFailed(
      `the external tool "${cmd}" timed out`,
      `the bounded ${opts.timeoutMs}ms operation window elapsed; arguments, paths, and incomplete output are withheld`,
      "repair provider connectivity and retry",
    );
  }
  if (r.error) setupFailed(`"${cmd}" could not be started`, "the process error is withheld because it may reproduce untrusted arguments or paths", null);
  if (r.status !== 0 && opts.tolerate !== true) {
    setupFailed(
      `"${cmd}" exited ${r.status}`,
      "the enumerator failed; its argv, cwd, and stderr are withheld because any of them may contain the sensitive publication bytes being rejected",
      null,
    );
  }
  return { code: r.status ?? 1, out: r.stdout ?? "" };
}

const nulList = (s) => String(s).split("\0").filter((x) => x.length > 0);

const opaqueContentKey = (text) => createHash("sha256").update(String(text), "utf8").digest("hex");
const opaquePathId = (path) => `path:sha256:${opaqueContentKey(`noa-boundary:path:v1\0${String(path)}`)}`;
const opaqueValueId = (domain, value) => `${domain}:sha256:${opaqueContentKey(`noa-boundary:${domain}:v1\0${String(value)}`)}`;

/** Refuse ambiguous external paths rather than normalising them into different bytes. */
function canonicalSurfacePath(value, source) {
  const path = String(value);
  const parts = path.split("/");
  if (
    path.length === 0 || path.includes("\0") || path.startsWith("/")
    || parts.some((part) => part.length === 0 || part === "." || part === "..")
  ) {
    setupFailed(
      `${source} derived a non-canonical external path`,
      `${opaquePathId(path)} is empty, absolute, escaping, or contains a non-canonical component`,
      "repair the external enumerator; do not normalise an ambiguous publication path inside the gate",
    );
  }
  return path;
}

function fileUnit(label, text, {
  scopePath,
  pathText = scopePath,
  pathIdentity = scopePath,
  structuredSource = true,
}) {
  const canonicalScope = canonicalSurfacePath(scopePath, "the file enumerator");
  const canonicalText = canonicalSurfacePath(pathText, "the publication enumerator");
  const canonicalIdentity = canonicalSurfacePath(pathIdentity, "the repository enumerator");
  return {
    path: label,
    text,
    scopePath: canonicalScope,
    pathText: canonicalText,
    pathIdentity: canonicalIdentity,
    structuredSource,
  };
}

function scopedTextUnit(label, text, scopePath) {
  return {
    path: label,
    text,
    scopePath: canonicalSurfacePath(scopePath, "the scoped-text enumerator"),
    structuredSource: true,
  };
}

function externalMetadataUnit(scopePath, field, index, value) {
  const canonicalScope = canonicalSurfacePath(scopePath, "the metadata enumerator");
  const identity = `${canonicalScope}\0${field}\0${index}\0${String(value)}`;
  const unitKey = contentKey(`noa-boundary:sourcemap-path:v1\0${identity}`);
  return {
    path: `map:${opaquePathId(canonicalScope)}:${field}[${index}]`,
    text: "",
    scopePath: canonicalScope,
    pathText: String(value),
    pathIdentity: identity,
    pathUnitKey: unitKey,
    pathReportId: `metadata:sha256:${unitKey}`,
    structuredSource: false,
  };
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// Argument parsing
// ─────────────────────────────────────────────────────────────────────────────────────────────────
const CANDIDATE_TIER_A_SCAN_FLAGS = new Set([
  "--explain",
  "--knockout-json",
  "--lane",
  "--pre-push-remote",
  "--pre-push-remote-git-dir",
  "--pre-push-url",
  "--range",
  "--refs-from-stdin",
  "--repo-visibility-source",
  "--require-lane",
  "--tier",
]);

function parseArgs(argv) {
  const opts = {
    lanes: null, range: null, refsFromStdin: false, tier: "ab", explain: false,
    packedDir: null, publishPath: false, selftest: false, spoolSelftest: false,
    custodyContractSelftest: false, outputContractSelftest: false, knockoutJson: false,
    refreshPublicRepos: false, refreshTokens: false, tightenKnownExposure: false, printExposureCandidates: false,
    migrateExclusions: false, recoverExclusionRotation: false, rotateExclusions: false,
    reviewer: null, reviewedAt: null, expiresAt: null,
    reviewSession: null, classification: null,
    publicArtifact: null, publicArtifactSri: null,
    repoVisibilitySource: null, prePushRemote: null, prePushRemoteGitDir: null, prePushUrl: null,
    // DELIBERATELY NOT A FLAG. The arm redirects the gate by COPYING it into a scratch repository,
    // which moves the root and all three baseline files at once. A --root flag would have been the
    // same capability handed to anyone who wanted a friendlier answer.
    root: ROOT, requireLanes: [], candidateTierAScanGrammar: false,
  };
  const seenFlags = new Set();
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (typeof a !== "string" || !a.startsWith("--")) {
      setupFailed(
        "an unexpected positional argument was supplied",
        "the closed boundary CLI accepts named options only; rejected positional bytes are omitted",
        "remove the positional argument and use one documented flag",
      );
    }
    if (seenFlags.has(a)) {
      setupFailed(
        `the flag ${opaqueValueId("argument", a)} was supplied more than once`,
        "duplicate options make last-value-wins classification ambiguous",
        "supply every option at most once",
      );
    }
    seenFlags.add(a);
    const next = () => {
      const v = argv[++i];
      if (v === undefined || v.startsWith("--")) setupFailed(`the flag ${opaqueValueId("argument", a)} needs a value`, "usage is documented in the script header; rejected argument bytes are omitted", null);
      return v;
    };
    const migrationNext = (key) => {
      if (opts[key] !== null) setupFailed(`the migration flag ${opaqueValueId("argument", a)} was supplied more than once`, "duplicate review metadata makes command intent ambiguous", "supply every reviewed field exactly once");
      return next();
    };
    switch (a) {
      case "--lane": opts.lanes = next().split(",").map((s) => s.trim()).filter(Boolean); break;
      case "--require-lane": opts.requireLanes.push(...next().split(",").map((s) => s.trim()).filter(Boolean)); break;
      case "--range": opts.range = next(); break;
      case "--refs-from-stdin": opts.refsFromStdin = true; break;
      case "--pre-push-remote": opts.prePushRemote = next(); break;
      case "--pre-push-remote-git-dir": opts.prePushRemoteGitDir = next(); break;
      case "--pre-push-url": opts.prePushUrl = next(); break;
      case "--repo-visibility-source": opts.repoVisibilitySource = next().toLowerCase(); break;
      case "--tier": opts.tier = next().toLowerCase(); break;
      case "--explain": opts.explain = true; break;
      case "--packed": opts.lanes = ["L-PACK", "L-MAP"]; break;
      case "--dir": opts.packedDir = next(); break;
      case "--publish-path": opts.publishPath = true; break;
      case "--selftest": opts.selftest = true; break;
      case "--spool-selftest": opts.spoolSelftest = true; break;
      case "--custody-contract-selftest": opts.custodyContractSelftest = true; break;
      case "--output-contract-selftest": opts.outputContractSelftest = true; break;
      case "--knockout-json": opts.knockoutJson = true; break;
      case "--refresh-public-repos": opts.refreshPublicRepos = true; break;
      case "--refresh-tokens": opts.refreshTokens = true; break;
      case "--migrate-exclusions":
        if (opts.migrateExclusions || opts.recoverExclusionRotation || opts.rotateExclusions) setupFailed("an exclusion migration mode was supplied more than once", "exactly one create, recovery-only, or fresh rotate operation is allowed", null);
        opts.migrateExclusions = true;
        break;
      case "--recover-exclusion-rotation":
        if (opts.migrateExclusions || opts.recoverExclusionRotation || opts.rotateExclusions) setupFailed("an exclusion migration mode was supplied more than once", "exactly one create, recovery-only, or fresh rotate operation is allowed", null);
        opts.recoverExclusionRotation = true;
        break;
      case "--rotate-exclusions":
        if (opts.migrateExclusions || opts.recoverExclusionRotation || opts.rotateExclusions) setupFailed("an exclusion migration mode was supplied more than once", "exactly one create, recovery-only, or fresh rotate operation is allowed", null);
        opts.rotateExclusions = true;
        break;
      case "--reviewer": opts.reviewer = migrationNext("reviewer"); break;
      case "--reviewed-at": opts.reviewedAt = migrationNext("reviewedAt"); break;
      case "--expires-at": opts.expiresAt = migrationNext("expiresAt"); break;
      case "--review-session": opts.reviewSession = migrationNext("reviewSession"); break;
      case "--classification": opts.classification = migrationNext("classification"); break;
      case "--public-artifact": opts.publicArtifact = migrationNext("publicArtifact"); break;
      case "--public-artifact-sri": opts.publicArtifactSri = migrationNext("publicArtifactSri"); break;
      case "--tighten-known-exposure": opts.tightenKnownExposure = true; break;
      case "--print-exposure-candidates": opts.printExposureCandidates = true; break;
      default:
        setupFailed(`unknown flag ${opaqueValueId("argument", a)}`, "an unrecognised flag is a typo, and a typo must not silently narrow the scan", "see the header for the flag list");
    }
  }
  opts.candidateTierAScanGrammar = [...seenFlags].every((flag) => CANDIDATE_TIER_A_SCAN_FLAGS.has(flag));
  if (seenFlags.has("--lane") && seenFlags.has("--packed")) {
    setupFailed("both explicit lanes and packed shorthand were supplied", "two lane selectors make scan intent ambiguous", "use exactly one lane selector");
  }
  if (seenFlags.has("--dir") && !seenFlags.has("--packed")) {
    setupFailed("a packed directory was supplied without packed mode", "--dir has meaning only with --packed", "supply --packed or remove --dir");
  }
  if (opts.custodyContractSelftest && (argv.length !== 1 || argv[0] !== "--custody-contract-selftest")) {
    setupFailed(
      "the custody contract self-test was combined with another operation",
      "scanner-independent custody evidence must run as one exact local operation",
      "run --custody-contract-selftest alone",
    );
  }
  if (opts.outputContractSelftest
      && argv.some((value) => value !== "--output-contract-selftest" && value !== "--knockout-json")) {
    setupFailed(
      "the output-boundary contract self-test was combined with another operation",
      "the terminal, candidate-JSON and gate-evidence renderer proof must run as one exact local operation",
      "run --output-contract-selftest alone, optionally with --knockout-json",
    );
  }
  if (opts.tier !== "a" && opts.tier !== "ab") {
    setupFailed(`unknown tier ${opaqueValueId("argument", opts.tier)}`, "tier must be 'a' (shapes only) or 'ab' (shapes and token commitments)", null);
  }
  if (opts.repoVisibilitySource !== null && opts.repoVisibilitySource !== "snapshot" && opts.repoVisibilitySource !== "live") {
    setupFailed(
      `unknown repository-visibility source ${opaqueValueId("argument", opts.repoVisibilitySource)}`,
      "the source must be exactly 'snapshot' or 'live'; silently falling back would turn stale evidence into provider truth",
      null,
    );
  }
  if (opts.refsFromStdin && opts.range !== null) {
    setupFailed(
      "both a literal range and pre-push refs were supplied",
      "two independent scope sources cannot be merged without proving which remote each object is new to",
      "use exactly one of --range or --refs-from-stdin",
    );
  }
  if (opts.refreshPublicRepos && opts.refreshTokens) {
    setupFailed(
      "public-repository and token refresh were combined",
      "the public snapshot is itself part of the reviewed token-control manifest, so one process cannot mutate it and then authenticate tokens against the pre-review bytes",
      "refresh and review the public snapshot first, freeze the reviewed controls, then refresh tokens in a separate invocation",
    );
  }
  if (opts.refsFromStdin && opts.prePushRemote === null) {
    setupFailed(
      "pre-push ref mode is missing the hook's remote arguments",
      "--refs-from-stdin requires --pre-push-remote so a new ref is compared with the actual destination instead of local --all",
      "invoke this through scripts/hooks/pre-push, or supply one exact configured remote",
    );
  }
  if (!opts.refsFromStdin && (opts.prePushRemote !== null || opts.prePushRemoteGitDir !== null
      || opts.prePushUrl !== null)) {
    setupFailed("pre-push remote arguments were supplied outside ref mode", "remote argv have meaning only with --refs-from-stdin", null);
  }
  const migrationMetadata = [
    ["--reviewer", opts.reviewer],
    ["--reviewed-at", opts.reviewedAt],
    ["--expires-at", opts.expiresAt],
    ["--review-session", opts.reviewSession],
    ["--classification", opts.classification],
    ["--public-artifact", opts.publicArtifact],
    ["--public-artifact-sri", opts.publicArtifactSri],
  ];
  const suppliedMigrationMetadata = migrationMetadata.filter(([, value]) => value !== null);
  const exclusionMigration = opts.migrateExclusions || opts.rotateExclusions;
  if (opts.recoverExclusionRotation && suppliedMigrationMetadata.length > 0) {
    setupFailed(
      "fresh review metadata was supplied to recovery-only exclusion rotation",
      "historical recovery must preserve the exact active schema-v3 bytes and metadata; it never issues a fresh policy",
      "run --recover-exclusion-rotation alone, then use a separate --rotate-exclusions invocation with fresh review metadata",
    );
  }
  if (!exclusionMigration && !opts.recoverExclusionRotation && suppliedMigrationMetadata.length > 0) {
    setupFailed(
      "exclusion-review metadata was supplied outside migration mode",
      `${suppliedMigrationMetadata.map(([flag]) => flag).join(", ")} only have meaning with one exclusion migration mode`,
      "use the reviewed one-time migration command, or remove the metadata flags",
    );
  }
  if (exclusionMigration) {
    const missing = migrationMetadata.filter(([, value]) => value === null).map(([flag]) => flag);
    if (missing.length > 0) {
      setupFailed(
        "the exclusion migration is missing reviewed metadata",
        `required flags: ${missing.join(", ")}`,
        "supply every exact reviewed field; the migration never fabricates defaults",
      );
    }
    const incompatible = opts.selftest || opts.spoolSelftest || opts.custodyContractSelftest || opts.outputContractSelftest
      || opts.refreshPublicRepos || opts.refreshTokens || opts.tightenKnownExposure
      || opts.printExposureCandidates || opts.refsFromStdin || opts.range !== null || opts.lanes !== null
      || opts.requireLanes.length > 0 || opts.publishPath || opts.packedDir !== null || opts.explain
      || opts.repoVisibilitySource !== null;
    if (incompatible) {
      setupFailed(
        "the exclusion migration was combined with another operation",
        "the exclusive governance migration is one local operation and cannot also scan, refresh, publish, or select provider evidence",
        "run one exclusion migration mode alone with its exact reviewed metadata, then run live refresh separately",
      );
    }
  }
  if (opts.recoverExclusionRotation) {
    const incompatible = opts.selftest || opts.spoolSelftest || opts.custodyContractSelftest || opts.outputContractSelftest
      || opts.refreshPublicRepos || opts.refreshTokens || opts.tightenKnownExposure
      || opts.printExposureCandidates || opts.refsFromStdin || opts.range !== null || opts.lanes !== null
      || opts.requireLanes.length > 0 || opts.publishPath || opts.packedDir !== null || opts.explain
      || opts.repoVisibilitySource !== null;
    if (incompatible) {
      setupFailed(
        "recovery-only exclusion rotation was combined with another operation",
        "historical recovery is one exact local transaction and cannot scan, refresh, publish, or accept fresh metadata",
        "run --recover-exclusion-rotation alone",
      );
    }
  }
  for (const [label, value] of [["remote name", opts.prePushRemote], ["remote URL", opts.prePushUrl]]) {
    if (value !== null && (value.length === 0 || value !== value.trim()
        || Buffer.byteLength(value, "utf8") > 8192 || /[\u0000-\u001f\u007f]/.test(value))) {
      setupFailed(`the pre-push ${label} is malformed`, "hook arguments must be nonempty, trimmed, and free of control characters", null);
    }
    if (value !== null && URL_USERINFO_RE.test(value)) {
      setupFailed(
        `the pre-push ${label} contains URL userinfo`,
        "credential-bearing destinations must be transported through the isolated hook config, never process argv",
        "invoke the committed pre-push hook instead of supplying a credential URL to the scanner CLI",
      );
    }
  }
  if (opts.prePushRemote !== null && opts.prePushRemote.startsWith("-")) {
    setupFailed("the pre-push remote name is option-like", "remote selectors must be non-option data", null);
  }
  if (opts.prePushRemoteGitDir !== null) {
    const scratchHome = resolve(homedir());
    const gitDir = resolve(opts.prePushRemoteGitDir);
    let realGitDir;
    let realConfig;
    let stat;
    let configStat;
    try {
      realGitDir = realpathSync(gitDir);
      realConfig = realpathSync(join(gitDir, "config"));
      stat = lstatSync(gitDir);
      configStat = lstatSync(join(gitDir, "config"));
    } catch {
      setupFailed("the pre-push remote Git directory is unavailable", "the isolated destination binding must exist before scanning", null);
    }
    if (opts.prePushRemoteGitDir !== gitDir || realGitDir !== gitDir
        || !gitDir.startsWith(`${scratchHome}${sep}`)
        || !stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o7777) !== 0o700
        || !configStat.isFile() || configStat.isSymbolicLink() || (configStat.mode & 0o7777) !== 0o600
        || realConfig !== join(gitDir, "config")
        || (currentUid() !== null && (stat.uid !== currentUid() || configStat.uid !== currentUid()))
        || opts.prePushUrl === null) {
      setupFailed(
        "the pre-push remote Git directory failed isolated custody",
        "it must be one absolute, real, owner-only directory below the child HOME with one owner-only config and a sanitized coordinate",
        "invoke the committed pre-push hook",
      );
    }
  }
  if (opts.lanes !== null) {
    const unknown = opts.lanes.filter((id) => laneById(id) === null);
    if (unknown.length > 0) {
      setupFailed(
        `unknown lane id(s): ${unknown.map((id) => opaqueValueId("argument", id)).join(", ")}`,
        `a mistyped lane silently scans less than the caller asked for. Known lanes: ${APPROVED_BOUNDARY_LANES.join(", ")}`,
        null,
      );
    }
  }
  return opts;
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// Baselines, all of them fail-closed
// ─────────────────────────────────────────────────────────────────────────────────────────────────
function readJson(path, what) {
  if (!existsSync(path)) {
    setupFailed(`${what} is missing`, `expected document ${opaquePathId(relative(ROOT, path))}`, "refresh the public snapshot, review/freeze controls, and refresh tokens in separate live-evidence invocations");
  }
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch {
    setupFailed(`${what} is unparsable`, `${opaquePathId(relative(ROOT, path))}: parser detail withheld because it may reproduce untrusted document bytes`, "restore it from version control, then refresh");
  }
  return null;
}

const RFC3339_UTC_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;

function canonicalTimestamp(what, value, fix) {
  const raw = String(value ?? "");
  const t = Date.parse(raw);
  const canonical = raw.includes(".") ? raw : raw.replace(/Z$/, ".000Z");
  if (!RFC3339_UTC_RE.test(raw) || !Number.isFinite(t) || new Date(t).toISOString() !== canonical) {
    setupFailed(`${what} has no usable timestamp`, "the value must be a real canonical UTC RFC3339 instant", fix);
  }
  return t;
}

function boundedTimestamp(what, value, fix) {
  const t = canonicalTimestamp(what, value, fix);
  const futureMs = t - Date.now();
  if (futureMs > MAX_FUTURE_SKEW_MS) {
    setupFailed(
      `${what} is in the future beyond the clock-skew bound`,
      `the timestamp is ${Math.ceil(futureMs / 1000)} second(s) ahead; the maximum tolerated skew is ${MAX_FUTURE_SKEW_MS / 1000} seconds`,
      fix,
    );
  }
  return t;
}

function assertFresh(what, refreshedAt, fix) {
  const t = boundedTimestamp(`${what}.refreshedAt`, refreshedAt, fix);
  const ageDays = (Date.now() - t) / 86_400_000;
  if (ageDays > MAX_BASELINE_AGE_DAYS) {
    setupFailed(
      `${what} is ${Math.floor(ageDays)} days old`,
      `the limit is ${MAX_BASELINE_AGE_DAYS} days. A list that has not been re-derived since a repository changed visibility is a WRONG baseline, not an old one.`,
      fix,
    );
  }
  return ageDays;
}

function loadPublicRepoSnapshot() {
  const doc = readJson(PUBLIC_REPOS_PATH, "the public-repository allowlist");
  if (doc === null || typeof doc.orgs !== "object" || doc.orgs === null || Object.keys(doc.orgs).length === 0) {
    setupFailed(
      "the public-repository allowlist derived zero organisations",
      "the inversion rule cannot run without the forge's answer about what is PUBLIC, and an empty allowlist would flag nothing rather than everything",
      "node scripts/lint-boundary.mjs --refresh-public-repos",
    );
  }
  for (const [org, repos] of Object.entries(doc.orgs)) {
    if (!Array.isArray(repos) || repos.length === 0) {
      setupFailed(`the public-repository allowlist has no repositories for ${opaqueValueId("org", org)}`, "an empty org list means the derivation failed, not that the org is empty", "node scripts/lint-boundary.mjs --refresh-public-repos");
    }
    if (new Set(repos.map((name) => String(name).toLowerCase())).size !== repos.length
        || repos.some((name) => typeof name !== "string" || name.trim() !== name || name.length === 0)) {
      setupFailed(
        `the public-repository allowlist for ${opaqueValueId("org", org)} is malformed or duplicated`,
        "every PUBLIC repository name must be one nonempty exact string, unique case-insensitively",
        "node scripts/lint-boundary.mjs --repo-visibility-source live --refresh-public-repos",
      );
    }
  }
  assertFresh("the public-repository allowlist", doc.refreshedAt, "node scripts/lint-boundary.mjs --refresh-public-repos");
  return doc;
}

function publicTokenCompounds(doc) {
  const out = new Set();
  const add = (value) => {
    for (const form of tokenForms(String(value))) {
      out.add(form);
      out.add(`${form}.git`);
    }
  };
  for (const [org, repos] of Object.entries(doc.orgs)) {
    add(org);
    for (const repo of repos) add(repo);
  }
  return out;
}

function exactObjectKeys(value, expected, what) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    setupFailed(`${what} is not an object`, "the authenticated structure cannot be interpreted", null);
  }
  const allowed = new Set(expected);
  const unknown = Object.keys(value).filter((key) => !allowed.has(key));
  const missing = expected.filter((key) => !Object.prototype.hasOwnProperty.call(value, key));
  if (unknown.length > 0) setupFailed(`${what} has unknown fields`, `${unknown.length} unrecognised field(s); names withheld because the authenticated input is untrusted`, "remove ambiguous fields and regenerate the authenticated document");
  if (missing.length > 0) setupFailed(`${what} is missing required fields`, missing.join(", "), "restore the complete authenticated document");
}

function keyedRecord(key, domain, value) {
  return createHmac("sha256", key)
    .update(`noa-boundary/${domain}\0`, "utf8")
    .update(JSON.stringify(value), "utf8")
    .digest("hex");
}

function canonicalJson(value) {
  try { return strictCanonicalJson(value); } catch {
    setupFailed("canonical JSON received an unsupported value", "undefined, non-finite numbers, functions, and symbols are forbidden", null);
  }
  return "";
}

function keyedCanonicalRecord(key, domain, value) {
  return createHmac("sha256", key)
    .update(`noa-boundary/${domain}\0`, "utf8")
    .update(canonicalJson(value), "utf8")
    .digest("hex");
}

function stableControlBytes(root, relativePath) {
  const path = join(root, relativePath);
  const label = `reviewed control file ${opaquePathId(relativePath)}`;
  const before = inspectPath(path, label);
  if (before.isSymbolicLink() || !before.isFile()) {
    setupFailed(`${label} is not a regular file`, "symlinked and special control inputs cannot be review evidence", null);
  }
  let fd;
  try {
    const noFollow = requiredFsFlag("O_NOFOLLOW", "without it, the reviewed control manifest could follow a path substitution");
    fd = openSync(path, fsConstants.O_RDONLY | noFollow);
    const opened = fstatSync(fd);
    if (!sameFileIdentity(before, opened) || !opened.isFile()) {
      setupFailed(`${label} changed during open`, "the inspected path and opened descriptor disagree", "stop concurrent writers and retry review binding");
    }
    const first = readFdExact(fd, opened.size, label);
    const middle = fstatSync(fd);
    const second = readFdExact(fd, middle.size, label);
    const afterDescriptor = fstatSync(fd);
    if (!sameFileState(opened, middle) || !sameFileState(middle, afterDescriptor)
        || first.length !== second.length || !timingSafeEqual(first, second)) {
      setupFailed(`${label} changed during stable read`, "identity, metadata, or bytes changed between two reads", "stop concurrent writers and retry review binding");
    }
    const afterPath = inspectPath(path, label);
    if (!sameFileState(before, afterPath)) {
      setupFailed(`${label} changed during manifest derivation`, "path metadata changed while its review digest was measured", "stop concurrent writers and retry review binding");
    }
    return first;
  } finally {
    if (fd !== undefined) {
      try { closeSync(fd); } catch { /* descriptor cleanup cannot change the already failed-closed evidence */ }
    }
  }
}

function reviewedControlManifest(root) {
  try {
    const manifest = deriveBoundaryControlManifest(root);
    return { version: manifest.version, paths: [...manifest.paths], digest: manifest.digest };
  } catch (error) {
    const failure = boundaryBootstrapFailure(error);
    setupFailed(failure.subject, `${failure.bootstrapCode}: ${failure.detail}`, failure.fix);
  }
  return null;
}

function equalHex64(actual, expected) {
  if (!HEX_64_RE.test(String(actual)) || !HEX_64_RE.test(String(expected))) return false;
  return timingSafeEqual(Buffer.from(actual, "hex"), Buffer.from(expected, "hex"));
}

const equalBytes = (actual, expected) => actual.length === expected.length && timingSafeEqual(actual, expected);

function tokenInputForms(text, what) {
  const forms = new Set();
  for (const [index, line] of String(text ?? "").split(/\r?\n/).entries()) {
    if (line.trim().length === 0 || line.trim().startsWith("#")) continue;
    let lineForms;
    try { lineForms = reachableTokenForms(line); } catch {
      setupFailed(
        `${what} line ${index + 1} is outside the scanner-reachable token grammar`,
        "only canonical ASCII inputs of 3..64 characters and at most six components are supported; the value is deliberately not printed",
        "review the input; future Unicode support requires a versioned tokenizer contract",
      );
    }
    if (lineForms.length !== 1) setupFailed(`${what} line ${index + 1} has no exact token form`, "empty, ambiguous, and pattern-only inputs are refused", null);
    const form = lineForms[0];
    if (forms.has(form)) setupFailed(`${what} contains a duplicate token form`, `duplicate at line ${index + 1}; the value is deliberately not printed`, null);
    forms.add(form);
  }
  return [...forms].sort();
}

function canaryFromCustody({ migrate = false } = {}) {
  recoverKnownBoundaryCreateStages({ onlyTarget: basename(CANARY_FILE) });
  const current = readConfidentialText(CANARY_FILE, "boundary canary", { optional: true, maxBytes: 256 });
  if (current !== null) {
    const value = current.trim();
    if (!CANARY_RE.test(value) || current.split(/\r?\n/).filter((line) => line.length > 0).length !== 1) {
      setupFailed("the boundary canary is malformed", "expected exactly one synthetic noaboundarycanary value", "restore or rotate the synthetic canary and refresh commitments");
    }
    return value;
  }

  if (!migrate) {
    setupFailed(
      "the dedicated boundary canary is missing",
      `authenticated commitments require the owner-only, no-follow file at ${CANARY_FILE}; a canary embedded in a legacy inventory is not active custody`,
      "restore the exact dedicated canary or use the reviewed migration and live refresh path",
    );
  }

  const legacy = readConfidentialText(LEGACY_TOKENS_FILE, "legacy token inventory", { optional: true, maxBytes: MAX_CONFIDENTIAL_TEXT_BYTES });
  const candidates = legacy === null
    ? []
    : legacy.split(/\r?\n/).map((line) => line.trim()).filter((line) => CANARY_RE.test(line));
  if (candidates.length > 1) setupFailed("the legacy token inventory has multiple canaries", "canary authority is ambiguous; no value was selected", "review the external inventory without deleting it");
  const canary = candidates[0] ?? `${CANARY_PREFIX}${randomBytes(12).toString("hex")}`;
  if (migrate) {
    writeConfidentialExclusive(CANARY_FILE, "boundary canary", Buffer.from(`${canary}\n`, "utf8"));
    if (legacy !== null) {
      say(yellow("  migrated only the synthetic canary into dedicated custody; the legacy token inventory was retained unchanged and is no longer written."));
    }
  }
  return canary;
}

function loadExtraInputs(key) {
  const text = readConfidentialText(EXTRA_TOKENS_FILE, "extra token inputs", { optional: true, maxBytes: MAX_CONFIDENTIAL_TEXT_BYTES });
  const forms = tokenInputForms(text ?? "", "extra token inputs");
  return { forms, commitment: keyedRecord(key, "extra-inputs/v1", forms) };
}

function reviewedLine(value, what, maxLength) {
  if (typeof value !== "string" || value.trim() !== value || value.length === 0 || value.length > maxLength
      || /[\u0000-\u001f\u007f]/.test(value) || /^(?:unknown|todo|tbd|n\/a)$/i.test(value)) {
    setupFailed(`${what} is invalid`, "the field must be one real reviewed line; empty values and placeholders are refused", "supply the actual reviewed value without fabricating it");
  }
  return value;
}

function exactExclusionToken(value, what) {
  if (typeof value !== "string") setupFailed(`${what} is not a string`, "each exclusion must bind one canonical exact token", null);
  let forms;
  try { forms = reachableTokenForms(value); } catch {
    setupFailed(
      `${what} is outside the scanner-reachable token grammar`,
      "Unicode, overlong values, unsupported punctuation, and forms the scanner cannot emit are refused without printing the value",
      "use only an exact reviewed version-1 ASCII token form",
    );
  }
  if (forms.length !== 1 || value !== forms[0] || /[*?\[\]{}]/.test(value)) {
    setupFailed(`${what} is not one canonical exact token`, "wildcards, prefixes, comments, and normalisation-dependent spellings are refused", null);
  }
  return value;
}

function decodeConfidentialUtf8(bytes, what) {
  let text;
  try { text = new TextDecoder("utf-8", { fatal: true }).decode(bytes); } catch {
    setupFailed(`the ${what} is not valid UTF-8`, "confidential text inputs must have one deterministic encoding", "rewrite it as UTF-8 without changing its reviewed meaning");
  }
  if (text.includes("\0")) setupFailed(`the ${what} contains a NUL byte`, "NUL-delimited ambiguity is forbidden in confidential text inputs", null);
  return text;
}

function loadLegacyExclusionSource({ required = false } = {}) {
  const bytes = readConfidentialFile(
    LEGACY_EXCLUDE_TOKENS_FILE,
    "legacy exclusion inputs",
    { optional: !required, maxBytes: MAX_CONFIDENTIAL_TEXT_BYTES },
  );
  if (bytes === null) return { present: false, bytes: null, byteLength: 0, sha256: null, entries: [], forms: [] };

  const entries = [];
  const seen = new Set();
  const text = decodeConfidentialUtf8(bytes, "legacy exclusion inputs");
  for (const [index, line] of text.split(/\r?\n/).entries()) {
    if (line.trim().length === 0 || line.trimStart().startsWith("#")) continue;
    const match = /^(.+?) # (.+)$/.exec(line);
    if (match === null) {
      setupFailed(
        `legacy exclusion input line ${index + 1} has no inline reason`,
        "every migrated token must retain its existing exact `token # reason` review context; no value was printed",
        "review the legacy file outside the repository; do not invent a reason in the migration command",
      );
    }
    // The retained file is a hand-aligned table: spaces immediately before `#` are layout, not
    // token bytes. Only trailing layout is removed; leading or internal ambiguity still fails the
    // canonical exact-token check. The legacy file itself is never rewritten.
    const token = exactExclusionToken(match[1].trimEnd(), `legacy exclusion input line ${index + 1}`);
    const reason = reviewedLine(match[2], `legacy exclusion input line ${index + 1} reason`, 500);
    if (seen.has(token)) setupFailed("the legacy exclusion inputs contain a duplicate token", `duplicate at line ${index + 1}; the value is deliberately not printed`, null);
    seen.add(token);
    entries.push({ token, reason });
  }
  entries.sort((a, b) => compareText(a.token, b.token));
  return {
    present: true,
    bytes,
    byteLength: bytes.length,
    sha256: createHash("sha256").update(bytes).digest("hex"),
    entries,
    forms: entries.map((entry) => entry.token),
  };
}

function canonicalSha512Sri(value) {
  if (typeof value !== "string" || !value.startsWith("sha512-")) return false;
  const encoded = value.slice("sha512-".length);
  try {
    const decoded = Buffer.from(encoded, "base64");
    return decoded.length === 64 && decoded.toString("base64") === encoded;
  } catch {
    return false;
  }
}

const EMPTY_EXCLUSION_POLICY_BODY = (keyId) => ({
  schemaVersion: EXCLUSION_POLICY_SCHEMA_VERSION,
  keyId,
  entries: [],
});

const PREVIOUS_EXCLUSION_POLICY_KEYS = [
  "schemaVersion", "keyId", "reviewer", "reviewedAt", "expiresAt", "reviewSession",
  "repositoryHead", "classification", "publicArtifact", "publicArtifactSRI",
  "legacyByteLength", "legacySha256", "entries", "mac",
];

function validatePreviousExclusionPolicyDocument(doc, key, legacy) {
  const keyId = createHash("sha256").update(key).digest("hex");
  exactObjectKeys(doc, PREVIOUS_EXCLUSION_POLICY_KEYS, "the predecessor governed exclusion policy");
  if (doc.schemaVersion !== PREVIOUS_EXCLUSION_POLICY_SCHEMA_VERSION || doc.keyId !== keyId
      || !Array.isArray(doc.entries) || !HEX_64_RE.test(String(doc.mac))) {
    setupFailed("the predecessor governed exclusion policy header is invalid", "schemaVersion 2, full keyId, entries, and 64-hex mac must all be exact", "restore the reviewed schema-v2 document under the current external key");
  }

  const reviewer = reviewedLine(doc.reviewer, "the exclusion policy reviewer", 240);
  const reviewedAtText = reviewedLine(doc.reviewedAt, "the exclusion policy review time", 40);
  const expiresAtText = reviewedLine(doc.expiresAt, "the exclusion policy expiry", 40);
  const reviewSession = reviewedLine(doc.reviewSession, "the exclusion policy review session", 80);
  const repositoryHead = reviewedLine(doc.repositoryHead, "the exclusion policy candidate HEAD", 64);
  const classification = reviewedLine(doc.classification, "the exclusion policy classification", 80);
  const publicArtifact = reviewedLine(doc.publicArtifact, "the exclusion policy public artifact", 214);
  const publicArtifactSRI = reviewedLine(doc.publicArtifactSRI, "the exclusion policy public artifact SRI", 160);
  if (!UUID_RE.test(reviewSession)) setupFailed("the exclusion policy review session is malformed", "a canonical lower-case UUID is required", null);
  if (!/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(repositoryHead) || /^0+$/.test(repositoryHead)) setupFailed("the exclusion policy candidate HEAD is malformed", "a nonzero full lower-case SHA-1 or SHA-256 Git object id is required", null);
  if (classification !== "PUBLIC_DERIVED_COLLISION") setupFailed("the exclusion policy classification is unsupported", "only the independently reviewed PUBLIC_DERIVED_COLLISION class is defined", null);
  if (!PUBLIC_ARTIFACT_RE.test(publicArtifact)) setupFailed("the exclusion policy public artifact is malformed", "an exact package@version coordinate is required", null);
  if (!canonicalSha512Sri(publicArtifactSRI)) setupFailed("the exclusion policy public artifact SRI is malformed", "a canonical SHA-512 Subresource Integrity value is required", null);
  if (!Number.isSafeInteger(doc.legacyByteLength) || doc.legacyByteLength <= 0 || !HEX_64_RE.test(String(doc.legacySha256))) {
    setupFailed("the exclusion policy legacy-byte evidence is malformed", "a positive safe byte length and full SHA-256 are required", null);
  }

  const entries = [];
  const seen = new Set();
  for (const [index, entry] of doc.entries.entries()) {
    exactObjectKeys(entry, ["token", "reason"], `exclusion policy entry ${index}`);
    const token = exactExclusionToken(entry.token, `exclusion policy entry ${index}`);
    const reason = reviewedLine(entry.reason, `exclusion policy entry ${index} reason`, 500);
    if (seen.has(token)) setupFailed(`exclusion policy entry ${index} duplicates a token`, "duplicate exclusions make removal arithmetic ambiguous", null);
    seen.add(token);
    entries.push({ token, reason });
  }
  const sortedEntries = [...entries].sort((a, b) => compareText(a.token, b.token));
  if (entries.some((entry, index) => entry.token !== sortedEntries[index].token)) {
    setupFailed("the governed exclusion policy entries are not canonically ordered", "entry order is part of the authenticated document and must be lexical by exact token", null);
  }

  const body = {
    schemaVersion: PREVIOUS_EXCLUSION_POLICY_SCHEMA_VERSION,
    keyId,
    reviewer,
    reviewedAt: reviewedAtText,
    expiresAt: expiresAtText,
    reviewSession,
    repositoryHead,
    classification,
    publicArtifact,
    publicArtifactSRI,
    legacyByteLength: doc.legacyByteLength,
    legacySha256: doc.legacySha256,
    entries,
  };
  const expectedMac = keyedRecord(key, "exclusion-policy/v2", body);
  // This MAC proves byte-level integrity under the local custody key. It does not authenticate the
  // reviewer as a person; the exact reviewer/session/evidence fields are recorded review evidence.
  if (!equalHex64(doc.mac, expectedMac)) {
    setupFailed("the governed exclusion policy authentication failed", "the HMAC does not bind these exact metadata and entries under the current key", "restore the reviewed file; do not regenerate it merely to make the gate pass");
  }

  const reviewedAt = canonicalTimestamp("the exclusion policy reviewedAt", reviewedAtText, null);
  const expiresAt = canonicalTimestamp("the exclusion policy expiresAt", expiresAtText, null);
  const now = Date.now();
  if (reviewedAt > now) setupFailed("the exclusion policy review time is in the future", "reviewedAt must describe a completed review, with no future-skew allowance", "record the actual completed review time");
  if (expiresAt <= reviewedAt || expiresAt <= now) {
    setupFailed("the exclusion policy is expired or has an invalid window", "expiresAt must be later than reviewedAt and still current", "renew it through a real review or remove the exclusion");
  }
  if (expiresAt - reviewedAt > MAX_EXCLUSION_VALIDITY_MS) {
    setupFailed("the exclusion policy validity exceeds 30 days", "temporary collision exclusions require review at least every 30 days", "use an expiry no more than 30 days after the completed review");
  }
  if (!legacy.present || legacy.byteLength !== doc.legacyByteLength || legacy.sha256 !== doc.legacySha256) {
    setupFailed("the retained legacy exclusion bytes changed after review", "the current file length or SHA-256 does not match the authenticated migration evidence; no values were printed", "restore the reviewed legacy bytes or perform a new independent review");
  }
  if (legacy.entries.length !== entries.length || legacy.entries.some((entry, index) =>
    entry.token !== entries[index]?.token || entry.reason !== entries[index]?.reason)) {
    setupFailed("the governed exclusion migration changes legacy semantics", "the authenticated exact tokens and inline reasons do not equal the retained legacy source; neither file was changed", "review the mismatch and migrate without silently adding, dropping, or rewriting exclusions");
  }
  return { forms: entries.map((entry) => entry.token), entries, commitment: expectedMac };
}

const EXCLUSION_POLICY_KEYS = [
  "schemaVersion", "keyId", "reviewer", "reviewedAt", "expiresAt", "reviewSession",
  "classification", "publicArtifact", "publicArtifactSRI", "controlManifestVersion",
  "controlManifestFiles", "controlManifestDigest", "legacyByteLength", "legacySha256",
  "entries", "mac",
];

function validateExclusionPolicyDocument(doc, key, legacy, root, {
  verifyControlManifest = true,
  allowPreviousControlManifest = false,
} = {}) {
  const keyId = createHash("sha256").update(key).digest("hex");
  exactObjectKeys(doc, EXCLUSION_POLICY_KEYS, "the governed exclusion policy");
  if (doc.schemaVersion !== EXCLUSION_POLICY_SCHEMA_VERSION || !equalHex64(doc.keyId, keyId)
      || !Array.isArray(doc.entries) || !HEX_64_RE.test(String(doc.mac))) {
    setupFailed("the governed exclusion policy header is invalid", "schemaVersion 3, full keyId, entries, and 64-hex mac must all be exact", "restore the reviewed canonical schema-v3 document under the current external key");
  }

  const reviewer = reviewedLine(doc.reviewer, "the exclusion policy reviewer", 240);
  const reviewedAtText = reviewedLine(doc.reviewedAt, "the exclusion policy review time", 40);
  const expiresAtText = reviewedLine(doc.expiresAt, "the exclusion policy expiry", 40);
  const reviewSession = reviewedLine(doc.reviewSession, "the exclusion policy review session", 80);
  const classification = reviewedLine(doc.classification, "the exclusion policy classification", 80);
  const publicArtifact = reviewedLine(doc.publicArtifact, "the exclusion policy public artifact", 214);
  const publicArtifactSRI = reviewedLine(doc.publicArtifactSRI, "the exclusion policy public artifact SRI", 160);
  if (!UUID_RE.test(reviewSession)) setupFailed("the exclusion policy review session is malformed", "a canonical lower-case UUID is required", null);
  if (classification !== "PUBLIC_DERIVED_COLLISION") setupFailed("the exclusion policy classification is unsupported", "only the independently reviewed PUBLIC_DERIVED_COLLISION class is defined", null);
  if (!PUBLIC_ARTIFACT_RE.test(publicArtifact)) setupFailed("the exclusion policy public artifact is malformed", "an exact package@version coordinate is required", null);
  if (!canonicalSha512Sri(publicArtifactSRI)) setupFailed("the exclusion policy public artifact SRI is malformed", "a canonical SHA-512 Subresource Integrity value is required", null);
  const matchesCurrentControlManifest = doc.controlManifestVersion === BOUNDARY_CONTROL_MANIFEST_VERSION
    && Array.isArray(doc.controlManifestFiles)
    && doc.controlManifestFiles.length === REVIEWED_CONTROL_PATHS.length
    && doc.controlManifestFiles.every((path, index) => path === REVIEWED_CONTROL_PATHS[index]);
  const matchesPreviousControlManifest = allowPreviousControlManifest
    && doc.controlManifestVersion === 1
    && Array.isArray(doc.controlManifestFiles)
    && doc.controlManifestFiles.length === PREVIOUS_REVIEWED_CONTROL_PATHS.length
    && doc.controlManifestFiles.every((path, index) => path === PREVIOUS_REVIEWED_CONTROL_PATHS[index]);
  if ((!matchesCurrentControlManifest && !matchesPreviousControlManifest)
      || !HEX_64_RE.test(String(doc.controlManifestDigest))) {
    setupFailed(
      "the exclusion policy reviewed-control manifest is malformed or narrowed",
      "version, complete exact path registry, order, and full digest must match the code-defined review surface",
      "regenerate only through the reviewed exclusive migration command",
    );
  }
  if (!Number.isSafeInteger(doc.legacyByteLength) || doc.legacyByteLength <= 0 || !HEX_64_RE.test(String(doc.legacySha256))) {
    setupFailed("the exclusion policy legacy-byte evidence is malformed", "a positive safe byte length and full SHA-256 are required", null);
  }

  const entries = [];
  const seen = new Set();
  for (const [index, entry] of doc.entries.entries()) {
    exactObjectKeys(entry, ["token", "reason"], `exclusion policy entry ${index}`);
    const token = exactExclusionToken(entry.token, `exclusion policy entry ${index}`);
    const reason = reviewedLine(entry.reason, `exclusion policy entry ${index} reason`, 500);
    if (seen.has(token)) setupFailed(`exclusion policy entry ${index} duplicates a token`, "duplicate exclusions make removal arithmetic ambiguous", null);
    seen.add(token);
    entries.push({ token, reason });
  }
  const sortedEntries = [...entries].sort((a, b) => compareText(a.token, b.token));
  if (entries.some((entry, index) => entry.token !== sortedEntries[index].token)) {
    setupFailed("the governed exclusion policy entries are not canonically ordered", "entry order is lexical by exact token", null);
  }

  const body = {
    schemaVersion: EXCLUSION_POLICY_SCHEMA_VERSION,
    keyId,
    reviewer,
    reviewedAt: reviewedAtText,
    expiresAt: expiresAtText,
    reviewSession,
    classification,
    publicArtifact,
    publicArtifactSRI,
    controlManifestVersion: doc.controlManifestVersion,
    controlManifestFiles: doc.controlManifestFiles,
    controlManifestDigest: doc.controlManifestDigest,
    legacyByteLength: doc.legacyByteLength,
    legacySha256: doc.legacySha256,
    entries,
  };
  const expectedMac = keyedCanonicalRecord(key, "exclusion-policy/v3", body);
  // The HMAC proves local integrity only. Reviewer provenance remains an evidence claim and is not
  // upgraded into a human signature or independent identity assertion by possession of this key.
  if (!equalHex64(doc.mac, expectedMac)) {
    setupFailed("the governed exclusion policy authentication failed", "the HMAC does not bind the canonical metadata, control manifest, and exact entries", "restore the reviewed file; do not regenerate it merely to make the gate pass");
  }

  const reviewedAt = canonicalTimestamp("the exclusion policy reviewedAt", reviewedAtText, null);
  const expiresAt = canonicalTimestamp("the exclusion policy expiresAt", expiresAtText, null);
  const now = Date.now();
  if (reviewedAt > now) setupFailed("the exclusion policy review time is in the future", "reviewedAt must describe a completed review, with no future-skew allowance", "record the actual completed review time");
  if (expiresAt <= reviewedAt || expiresAt <= now || expiresAt - reviewedAt > MAX_EXCLUSION_VALIDITY_MS) {
    setupFailed("the exclusion policy is expired or has an invalid window", "temporary collision exclusions require a positive current validity of no more than 30 days", "renew it through a real review or remove the exclusion");
  }
  if (!legacy.present || legacy.byteLength !== doc.legacyByteLength || legacy.sha256 !== doc.legacySha256) {
    setupFailed("the retained legacy exclusion bytes changed after review", "the current file length or SHA-256 does not match authenticated evidence; no values were printed", "restore the reviewed legacy bytes or perform a new independent review");
  }
  if (legacy.entries.length !== entries.length || legacy.entries.some((entry, index) =>
    entry.token !== entries[index]?.token || entry.reason !== entries[index]?.reason)) {
    setupFailed("the governed exclusion migration changes legacy semantics", "authenticated exact tokens and inline reasons do not equal the retained source", "review the mismatch without silently adding, dropping, or rewriting exclusions");
  }
  if (verifyControlManifest) {
    const measured = reviewedControlManifest(root);
    if (measured.version !== doc.controlManifestVersion || !equalHex64(measured.digest, doc.controlManifestDigest)) {
      setupFailed(
        "the reviewed exclusion control manifest is stale",
        "one or more explicitly governed source/control files changed after the external policy was issued; no confidential values were printed",
        "complete review on the exact current controls and rotate the policy through the exclusive migration command",
      );
    }
  }
  return { forms: entries.map((entry) => entry.token), entries, commitment: expectedMac };
}

function parseCanonicalExclusionPolicy(text) {
  let doc;
  try { doc = JSON.parse(text); } catch {
    setupFailed("the governed exclusion policy is not JSON", "parser detail is withheld because the policy bytes are confidential and untrusted", "restore the authenticated external file; the legacy file remains untouched");
  }
  const expected = `${canonicalJson(doc)}\n`;
  if (text !== expected) {
    setupFailed(
      "the governed exclusion policy is not in exact canonical JSON form",
      "duplicate keys, alternate key order, whitespace, escape variants, and missing or extra final newlines are refused before HMAC validation",
      "restore the exact bytes created by the exclusive migration command",
    );
  }
  return doc;
}

function loadExclusionPolicy(key) {
  const legacy = loadLegacyExclusionSource();
  const text = readConfidentialText(EXCLUSION_POLICY_FILE, "governed exclusion policy", { optional: true, maxBytes: MAX_CONFIDENTIAL_TEXT_BYTES });
  const keyId = createHash("sha256").update(key).digest("hex");

  if (text === null) {
    if (legacy.forms.length > 0) {
      setupFailed(
        "legacy exclusions have no authenticated governance record",
        `${legacy.forms.length} exclusion(s) remain in the untouched legacy file, but reviewer, reason, review time, expiry, evidence, and HMAC authority are absent. No values were printed or deleted.`,
        "create the external governed policy through the reviewed --migrate-exclusions command; do not invent metadata",
      );
    }
    const body = EMPTY_EXCLUSION_POLICY_BODY(keyId);
    return { forms: [], entries: [], commitment: keyedCanonicalRecord(key, "exclusion-policy/v3-empty", body) };
  }
  const doc = parseCanonicalExclusionPolicy(text);
  return validateExclusionPolicyDocument(doc, key, legacy, ROOT);
}

const LEGACY_ROTATION_RECEIPT_BODY_KEYS = [
  "schemaVersion", "event", "recordedAt", "verifiedAt", "predecessor", "successor",
  "legacy", "entryCount", "keyId",
];
const ROTATION_RECEIPT_BODY_KEYS = [
  "schemaVersion", "event", "recordedAt", "verifiedAt", "intentSha256", "predecessor",
  "observedActive", "successor", "legacy", "entryCount", "keyId", "durabilityProfile",
];

function parseCanonicalRotationReceipt(text) {
  let doc;
  try { doc = JSON.parse(text); } catch {
    setupFailed("the exclusion rotation receipt is not JSON", "the authenticated receipt cannot be interpreted; no policy values were printed", "restore the exact canonical receipt bytes");
  }
  if (text !== `${canonicalJson(doc)}\n`) {
    setupFailed(
      "the exclusion rotation receipt is not in exact canonical JSON form",
      "duplicate keys, whitespace variants, alternate escapes, and newline variants are refused before HMAC",
      "restore the create-exclusive canonical receipt",
    );
  }
  return doc;
}

function policyByteEvidence(bytes, doc) {
  return {
    schemaVersion: doc.schemaVersion,
    byteLength: bytes.length,
    sha256: createHash("sha256").update(bytes).digest("hex"),
    policyMac: doc.mac,
  };
}

function validateReceiptIntentAuthority(doc, envelope, intentRecord) {
  if (intentRecord === null) return;
  if (envelope.schemaVersion === LEGACY_ROTATION_RECEIPT_SCHEMA_VERSION
      && !sameEvidence(intentRecord.doc.body.observedActive, intentRecord.doc.body.predecessor)) {
    setupFailed(
      "the legacy exclusion rotation receipt cannot authorize deletion across an unrecorded active state",
      "receipt v1 does not bind the distinct observed-active policy preserved by the authenticated v2 intent; raw/deleting predecessor bytes and intent remain",
      "retain the evidence and complete only through a receipt v2 that reconstructs the exact intent digest",
    );
  }
  if (envelope.schemaVersion === ROTATION_RECEIPT_SCHEMA_VERSION
      && (!sameEvidence(doc.body.observedActive, intentRecord.doc.body.observedActive)
        || doc.body.intentSha256 !== intentRecord.digest
        || doc.body.durabilityProfile !== intentRecord.doc.body.durabilityProfile)) {
    setupFailed(
      "the exclusion rotation receipt does not bind the active intent",
      "the receipt's observed-active state, full intent SHA-256, or durability profile differs from the authenticated transaction; nothing was deleted",
      "restore the exact intent and receipt pair",
    );
  }
}

function validateRotationReceiptDocument(doc, key, {
  predecessorBytes,
  predecessorDoc,
  successorBytes,
  successorDoc,
  legacy,
  intentRecord = null,
}) {
  const envelope = validateRotationReceiptEnvelope(doc, key);

  const predecessor = policyByteEvidence(predecessorBytes, predecessorDoc);
  const successor = {
    ...policyByteEvidence(successorBytes, successorDoc),
    controlManifestVersion: successorDoc.controlManifestVersion,
    controlManifestDigest: successorDoc.controlManifestDigest,
  };
  const measuredLegacy = { byteLength: legacy.byteLength, sha256: legacy.sha256 };
  if (canonicalJson(doc.body.predecessor) !== canonicalJson(predecessor)
      || canonicalJson(doc.body.successor) !== canonicalJson(successor)
      || canonicalJson(doc.body.legacy) !== canonicalJson(measuredLegacy)
      || doc.body.entryCount !== successorDoc.entries.length) {
    setupFailed(
      "the exclusion rotation receipt does not bind the exact current evidence",
      "policy schema, byte length, SHA-256, policy MAC, control manifest, legacy evidence, or entry count differs; values are not printed",
      "restore the exact predecessor/successor evidence or perform a new forward rotation",
    );
  }
  validateReceiptIntentAuthority(doc, envelope, intentRecord);
  return { commitment: doc.receiptMac };
}

function validateRotationReceiptEnvelope(doc, key) {
  exactObjectKeys(doc, ["body", "receiptMac"], "the exclusion rotation receipt envelope");
  exactObjectKeys(doc.body, [
    ...(doc.body?.schemaVersion === ROTATION_RECEIPT_SCHEMA_VERSION
      ? ROTATION_RECEIPT_BODY_KEYS : LEGACY_ROTATION_RECEIPT_BODY_KEYS),
  ], "the exclusion rotation receipt body");
  exactObjectKeys(doc.body.predecessor, ["schemaVersion", "byteLength", "sha256", "policyMac"], "the exclusion rotation receipt predecessor");
  if (doc.body.schemaVersion === ROTATION_RECEIPT_SCHEMA_VERSION) {
    exactObjectKeys(doc.body.observedActive, ["schemaVersion", "byteLength", "sha256", "policyMac"], "the exclusion rotation receipt observed-active state");
  }
  exactObjectKeys(doc.body.successor, [
    "schemaVersion", "byteLength", "sha256", "policyMac", "controlManifestVersion", "controlManifestDigest",
  ], "the exclusion rotation receipt successor");
  exactObjectKeys(doc.body.legacy, ["byteLength", "sha256"], "the exclusion rotation receipt legacy evidence");

  const keyId = createHash("sha256").update(key).digest("hex");
  if (![LEGACY_ROTATION_RECEIPT_SCHEMA_VERSION, ROTATION_RECEIPT_SCHEMA_VERSION].includes(doc.body.schemaVersion)
      || doc.body.event !== ROTATION_RECEIPT_EVENT
      || !equalHex64(doc.body.keyId, keyId)
      || !Number.isSafeInteger(doc.body.entryCount) || doc.body.entryCount < 0
      || !HEX_64_RE.test(String(doc.receiptMac))) {
    setupFailed("the exclusion rotation receipt header is malformed", "schema, event, count, full keyId, and receipt HMAC must be exact", null);
  }
  const recordedAt = canonicalTimestamp("the exclusion rotation receipt recordedAt", doc.body.recordedAt, null);
  const verifiedAt = canonicalTimestamp("the exclusion rotation receipt verifiedAt", doc.body.verifiedAt, null);
  const now = Date.now();
  if (recordedAt > verifiedAt || verifiedAt > now || verifiedAt - recordedAt > MAX_FUTURE_SKEW_MS) {
    setupFailed(
      "the exclusion rotation receipt timestamps are inconsistent",
      "recordedAt must be no later than verifiedAt, verification cannot be in the future, and the evidence window is at most five minutes",
      "create a fresh receipt only after exact predecessor and successor read-back",
    );
  }
  const predecessor = doc.body.predecessor;
  const observedActive = doc.body.observedActive;
  const successor = doc.body.successor;
  const legacy = doc.body.legacy;
  if (![PREVIOUS_EXCLUSION_POLICY_SCHEMA_VERSION, EXCLUSION_POLICY_SCHEMA_VERSION].includes(predecessor.schemaVersion)
      || !Number.isSafeInteger(predecessor.byteLength) || predecessor.byteLength <= 0
      || !HEX_64_RE.test(String(predecessor.sha256)) || !HEX_64_RE.test(String(predecessor.policyMac))
      || successor.schemaVersion !== EXCLUSION_POLICY_SCHEMA_VERSION
      || !Number.isSafeInteger(successor.byteLength) || successor.byteLength <= 0
      || !HEX_64_RE.test(String(successor.sha256)) || !HEX_64_RE.test(String(successor.policyMac))
      || !Number.isSafeInteger(successor.controlManifestVersion) || successor.controlManifestVersion <= 0
      || !HEX_64_RE.test(String(successor.controlManifestDigest))
      || !Number.isSafeInteger(legacy.byteLength) || legacy.byteLength <= 0
      || !HEX_64_RE.test(String(legacy.sha256))
      || (doc.body.schemaVersion === ROTATION_RECEIPT_SCHEMA_VERSION
        && (![PREVIOUS_EXCLUSION_POLICY_SCHEMA_VERSION, EXCLUSION_POLICY_SCHEMA_VERSION].includes(observedActive.schemaVersion)
          || !Number.isSafeInteger(observedActive.byteLength) || observedActive.byteLength <= 0
          || !HEX_64_RE.test(String(observedActive.sha256)) || !HEX_64_RE.test(String(observedActive.policyMac))
          || !HEX_64_RE.test(String(doc.body.intentSha256))
          || doc.body.durabilityProfile !== ROTATION_DURABILITY_PROFILE))) {
    setupFailed("the exclusion rotation receipt evidence is malformed", "full byte evidence and control-manifest identity are required", null);
  }
  const receiptDomain = doc.body.schemaVersion === ROTATION_RECEIPT_SCHEMA_VERSION
    ? ROTATION_RECEIPT_DOMAIN : LEGACY_ROTATION_RECEIPT_DOMAIN;
  const expectedMac = keyedCanonicalRecord(key, receiptDomain, doc.body);
  if (!equalHex64(doc.receiptMac, expectedMac)) {
    setupFailed("the exclusion rotation receipt authentication failed", "the domain-separated HMAC does not bind this exact canonical body", "restore the authenticated receipt; never regenerate it merely to pass");
  }
  if (doc.body.schemaVersion === ROTATION_RECEIPT_SCHEMA_VERSION) {
    const reconstructedIntent = rotationIntentDocumentFromEvidence(key, {
      predecessor: doc.body.predecessor,
      observedActive: doc.body.observedActive,
      successor: doc.body.successor,
      legacy: doc.body.legacy,
      entryCount: doc.body.entryCount,
      durabilityProfile: doc.body.durabilityProfile,
    });
    const reconstructedBytes = Buffer.from(`${canonicalJson(reconstructedIntent)}\n`, "utf8");
    const reconstructedDigest = createHash("sha256").update(reconstructedBytes).digest("hex");
    if (!equalHex64(doc.body.intentSha256, reconstructedDigest)) {
      setupFailed("the exclusion rotation receipt intent digest is invalid", "the receipt cannot reconstruct the exact HMAC-bound forward intent; nothing was deleted", "restore the exact authenticated receipt");
    }
  }
  return { commitment: expectedMac, schemaVersion: doc.body.schemaVersion };
}

function readAndValidatePolicyAt(path, what, key, legacy, root, {
  verifyControlManifest = false,
  allowPreviousControlManifest = false,
} = {}) {
  const bytes = readConfidentialFile(path, what, { maxBytes: MAX_CONFIDENTIAL_TEXT_BYTES });
  const text = decodeConfidentialUtf8(bytes, what);
  let doc;
  try { doc = JSON.parse(text); } catch {
    setupFailed(`the ${what} is not JSON`, "the authenticated policy cannot be interpreted; no entry value was printed", "restore the exact reviewed policy bytes");
  }
  let validated;
  if (doc.schemaVersion === PREVIOUS_EXCLUSION_POLICY_SCHEMA_VERSION) {
    validated = validatePreviousExclusionPolicyDocument(doc, key, legacy);
  } else if (doc.schemaVersion === EXCLUSION_POLICY_SCHEMA_VERSION) {
    if (text !== `${canonicalJson(doc)}\n`) {
      setupFailed(`the ${what} is not canonical JSON`, "schema-v3 policy bytes must be exact canonical JSON with one final newline", null);
    }
    validated = validateExclusionPolicyDocument(doc, key, legacy, root, {
      verifyControlManifest,
      allowPreviousControlManifest,
    });
  } else {
    setupFailed(`the ${what} schema is unsupported`, "only authenticated schema v2 or v3 policy evidence can participate in a rotation", null);
  }
  return { bytes, text, doc, validated };
}

function reviewedDecisionMatches(left, right) {
  const fields = [
    "reviewer", "reviewedAt", "expiresAt", "reviewSession", "classification",
    "publicArtifact", "publicArtifactSRI", "legacyByteLength", "legacySha256",
  ];
  return fields.every((field) => left[field] === right[field])
    && canonicalJson(left.entries) === canonicalJson(right.entries);
}

const ROTATION_INTENT_BODY_KEYS = [
  "schemaVersion", "event", "predecessor", "observedActive", "successor", "legacy",
  "entryCount", "keyId", "durabilityProfile",
];
const ROTATION_TEST_WAIT = new Int32Array(new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT));

function rotationCheckpoint(name) {
  if (process.env.NOA_BOUNDARY_ROTATION_TEST_MODE !== "1") return;
  if (process.env.NOA_BOUNDARY_ROTATION_TRACE_CHECKPOINTS === "1") {
    process.stderr.write(`NOA_ROTATION_CHECKPOINT ${name}\n`);
  }
  if (process.env.NOA_BOUNDARY_ROTATION_PAUSE_AT === name) {
    const requested = Number(process.env.NOA_BOUNDARY_ROTATION_PAUSE_MS ?? "10000");
    const pauseMs = Number.isSafeInteger(requested) && requested >= 10 && requested <= 10_000
      ? requested : 10_000;
    const releaseFile = process.env.NOA_BOUNDARY_ROTATION_RELEASE_FILE;
    if (typeof releaseFile === "string" && releaseFile.length > 0) {
      const deadline = Date.now() + pauseMs;
      while (!existsSync(releaseFile) && Date.now() < deadline) {
        Atomics.wait(ROTATION_TEST_WAIT, 0, 0, Math.min(10, Math.max(1, deadline - Date.now())));
      }
      if (!existsSync(releaseFile)) {
        setupFailed(
          "the test-only rotation checkpoint release timed out",
          "the bounded child-process synchronization file was not observed",
          "fix the deterministic self-test schedule; do not weaken the rotation lock",
        );
      }
    } else {
      Atomics.wait(ROTATION_TEST_WAIT, 0, 0, pauseMs);
    }
  }
  if (process.env.NOA_BOUNDARY_ROTATION_CRASH_AFTER === name) {
    process.kill(process.pid, "SIGKILL");
  }
}

function custodyFailure(what, error, fix) {
  setupFailed(
    what,
    error instanceof BoundaryCustodyError ? error.code : "custody operation failed; detail withheld",
    fix,
  );
}

function durableRemoveExact(path, bytes, what, { allowLinks = 1 } = {}) {
  try { durableUnlinkExact({ path, expectedBytes: bytes, mode: KEY_MODE, allowLinks }); } catch (error) {
    custodyFailure(`the ${what} could not be removed durably`, error, "retain the exact evidence and resume the same forward operation");
  }
}

function parseCanonicalRotationIntent(text) {
  let doc;
  try { doc = JSON.parse(text); } catch {
    setupFailed("the exclusion rotation intent is not JSON", "the authenticated transaction cannot be interpreted", "restore the exact canonical intent bytes");
  }
  if (text !== `${canonicalJson(doc)}\n`) {
    setupFailed("the exclusion rotation intent is not canonical JSON", "alternate key order, whitespace, escapes, or newline variants are refused", "restore the exact create-exclusive intent");
  }
  return doc;
}

function validatePolicyByteEvidence(evidence, what, { successor = false } = {}) {
  const expectedKeys = successor
    ? ["schemaVersion", "byteLength", "sha256", "policyMac", "controlManifestVersion", "controlManifestDigest"]
    : ["schemaVersion", "byteLength", "sha256", "policyMac"];
  exactObjectKeys(evidence, expectedKeys, what);
  if ((successor ? evidence.schemaVersion !== EXCLUSION_POLICY_SCHEMA_VERSION
    : ![PREVIOUS_EXCLUSION_POLICY_SCHEMA_VERSION, EXCLUSION_POLICY_SCHEMA_VERSION].includes(evidence.schemaVersion))
      || !Number.isSafeInteger(evidence.byteLength) || evidence.byteLength <= 0
      || !HEX_64_RE.test(String(evidence.sha256)) || !HEX_64_RE.test(String(evidence.policyMac))
      || (successor && (!Number.isSafeInteger(evidence.controlManifestVersion)
        || evidence.controlManifestVersion <= 0 || !HEX_64_RE.test(String(evidence.controlManifestDigest))))) {
    setupFailed(`the ${what} is malformed`, "full schema, byte-length, SHA-256, policy-MAC, and required manifest evidence must be exact", null);
  }
}

function validateRotationIntentDocument(doc, key) {
  exactObjectKeys(doc, ["body", "intentMac"], "the exclusion rotation intent envelope");
  exactObjectKeys(doc.body, ROTATION_INTENT_BODY_KEYS, "the exclusion rotation intent body");
  validatePolicyByteEvidence(doc.body.predecessor, "exclusion rotation intent predecessor evidence");
  validatePolicyByteEvidence(doc.body.observedActive, "exclusion rotation intent observed-active evidence");
  validatePolicyByteEvidence(doc.body.successor, "exclusion rotation intent successor evidence", { successor: true });
  exactObjectKeys(doc.body.legacy, ["byteLength", "sha256"], "the exclusion rotation intent legacy evidence");
  const keyId = createHash("sha256").update(key).digest("hex");
  if (doc.body.schemaVersion !== ROTATION_INTENT_SCHEMA_VERSION
      || doc.body.event !== ROTATION_INTENT_EVENT || !equalHex64(doc.body.keyId, keyId)
      || !Number.isSafeInteger(doc.body.entryCount) || doc.body.entryCount < 0
      || !Number.isSafeInteger(doc.body.legacy.byteLength) || doc.body.legacy.byteLength <= 0
      || !HEX_64_RE.test(String(doc.body.legacy.sha256)) || !HEX_64_RE.test(String(doc.intentMac))
      || doc.body.durabilityProfile !== ROTATION_DURABILITY_PROFILE) {
    setupFailed("the exclusion rotation intent header is malformed", "schema, event, counts, key identity, legacy evidence, and HMAC must be exact", null);
  }
  const expectedMac = keyedCanonicalRecord(key, ROTATION_INTENT_DOMAIN, doc.body);
  if (!equalHex64(doc.intentMac, expectedMac)) {
    setupFailed("the exclusion rotation intent authentication failed", "the domain-separated HMAC does not bind this exact forward transaction", "restore the exact intent; never regenerate it merely to pass");
  }
  return doc;
}

function rotationIntentDocumentFromEvidence(key, {
  predecessor,
  observedActive,
  successor,
  legacy,
  entryCount,
  durabilityProfile = ROTATION_DURABILITY_PROFILE,
}) {
  const body = {
    schemaVersion: ROTATION_INTENT_SCHEMA_VERSION,
    event: ROTATION_INTENT_EVENT,
    predecessor,
    observedActive,
    successor,
    legacy,
    entryCount,
    keyId: createHash("sha256").update(key).digest("hex"),
    durabilityProfile,
  };
  return { body, intentMac: keyedCanonicalRecord(key, ROTATION_INTENT_DOMAIN, body) };
}

function rotationIntentDocument(key, predecessor, observedActive, successor, legacy) {
  return rotationIntentDocumentFromEvidence(key, {
    predecessor: policyByteEvidence(predecessor.bytes, predecessor.doc),
    observedActive: policyByteEvidence(observedActive.bytes, observedActive.doc),
    successor: {
      ...policyByteEvidence(successor.bytes, successor.doc),
      controlManifestVersion: successor.doc.controlManifestVersion,
      controlManifestDigest: successor.doc.controlManifestDigest,
    },
    legacy: { byteLength: legacy.byteLength, sha256: legacy.sha256 },
    entryCount: successor.doc.entries.length,
  });
}

function discoverRotationArtifacts() {
  let names;
  try { names = readdirSync(KEY_DIR); } catch {
    setupFailed("the boundary policy directory cannot be enumerated", "rotation recovery state is unknown", "restore the owner-only boundary directory before rotation");
  }
  const groups = {
    predecessors: [], pending: [], deleting: [], intents: [], receipts: [], legacyDeleting: [],
  };
  const unknown = [];
  for (const name of names.sort()) {
    if (name.startsWith("exclusions.superseded-")) {
      if (FULL_SUPERSEDED_POLICY_NAME_RE.test(name) || LEGACY_SUPERSEDED_POLICY_NAME_RE.test(name)) groups.predecessors.push(name);
      else unknown.push(name);
    } else if (name.startsWith("exclusions.pending-successor-")) {
      if (PENDING_SUCCESSOR_NAME_RE.test(name)) groups.pending.push(name); else unknown.push(name);
    } else if (name.startsWith("exclusions.deleting-")) {
      if (DELETING_POLICY_NAME_RE.test(name)) groups.deleting.push(name); else unknown.push(name);
    } else if (name.startsWith("exclusion-policy-rotation-intent-")) {
      if (ROTATION_INTENT_NAME_RE.test(name)) groups.intents.push(name); else unknown.push(name);
    } else if (name.startsWith("exclusion-policy-rotation-v")) {
      if (ROTATION_RECEIPT_NAME_RE.test(name) || LEGACY_ROTATION_RECEIPT_NAME_RE.test(name)) groups.receipts.push(name);
      else unknown.push(name);
    } else if (name.startsWith(".exclusion-policy-delete-")) {
      if (LEGACY_RANDOM_DELETE_NAME_RE.test(name)) groups.legacyDeleting.push(name); else unknown.push(name);
    }
  }
  if (unknown.length > 0) {
    setupFailed(
      "unknown exclusion rotation artifacts are present",
      `${unknown.length} transaction-like path(s) do not have a recognized, full-content-bound state name; names and values are omitted`,
      "inspect without deleting; restore one exact authenticated transaction state",
    );
  }
  if (groups.pending.length > 1 || groups.deleting.length > 1 || groups.intents.length > 1
      || groups.legacyDeleting.length > 1 || groups.predecessors.length > 2) {
    setupFailed("multiple exclusion rotation artifacts are present", "the forward transaction state is ambiguous; nothing was deleted", "retain one exact authenticated state chain through reviewed recovery");
  }
  for (const key of Object.keys(groups)) groups[key] = groups[key].map((name) => join(KEY_DIR, name));
  return groups;
}

function parseRotationLock(text) {
  let doc;
  try { doc = JSON.parse(text); } catch {
    setupFailed("the exclusion rotation lock is corrupt", "its owner cannot be established; nothing was deleted", "inspect the live process and exact lock bytes");
  }
  if (text !== `${canonicalJson(doc)}\n`) setupFailed("the exclusion rotation lock is noncanonical", "its owner cannot be established safely", null);
  exactObjectKeys(doc, ["schemaVersion", "event", "pid", "startedAt", "nonce"], "the exclusion rotation lock");
  canonicalTimestamp("the exclusion rotation lock startedAt", doc.startedAt, null);
  if (doc.schemaVersion !== 1 || doc.event !== "EXCLUSION_POLICY_ROTATION_LOCK"
      || !Number.isSafeInteger(doc.pid) || doc.pid <= 0 || !HEX_64_RE.test(String(doc.nonce))) {
    setupFailed("the exclusion rotation lock is malformed", "exact schema, event, positive pid, timestamp, and nonce are required", null);
  }
  return doc;
}

function processAppearsAlive(pid) {
  try { process.kill(pid, 0); return true; } catch (error) {
    if (error?.code === "ESRCH") return false;
    return true;
  }
}

function discoverRotationLockClaim() {
  let names;
  try { names = readdirSync(KEY_DIR).sort(); } catch {
    setupFailed("the boundary policy directory cannot be enumerated", "lock recovery state is unknown", "restore owner-only boundary custody");
  }
  const claimLike = names.filter((name) => name.startsWith("exclusion-policy-rotation-lock-claim-"));
  const claims = claimLike.filter((name) => ROTATION_LOCK_CLAIM_NAME_RE.test(name));
  if (claims.length !== claimLike.length || claims.length > 1) {
    setupFailed(
      "the exclusion rotation lock claim state is ambiguous",
      "unknown or multiple immutable claim names are present; no lock was removed",
      "retain the exact files and review the single full-SHA claim chain",
    );
  }
  return claims.length === 0 ? null : join(KEY_DIR, claims[0]);
}

function readRotationLockRecord(path, what, { allowLinks = 1 } = {}) {
  const bytes = readConfidentialFile(path, what, { maxBytes: 4096, allowLinks });
  const doc = parseRotationLock(decodeConfidentialUtf8(bytes, what));
  const digest = createHash("sha256").update(bytes).digest("hex");
  return { path, bytes, doc, digest };
}

function knownBoundaryCreateStageTarget(name) {
  return name === basename(CANARY_FILE)
    || name === basename(EXCLUSION_POLICY_FILE)
    || name === basename(ROTATION_LOCK_FILE)
    || FULL_SUPERSEDED_POLICY_NAME_RE.test(name)
    || LEGACY_SUPERSEDED_POLICY_NAME_RE.test(name)
    || PENDING_SUCCESSOR_NAME_RE.test(name)
    || DELETING_POLICY_NAME_RE.test(name)
    || ROTATION_INTENT_NAME_RE.test(name)
    || ROTATION_RECEIPT_NAME_RE.test(name)
    || LEGACY_ROTATION_RECEIPT_NAME_RE.test(name);
}

function boundaryCreateStageTargets() {
  try { return durableCreateStageTargets({ directoryPath: KEY_DIR }); } catch (error) {
    custodyFailure(
      "the boundary create staging namespace is unsafe",
      error,
      "retain unknown staging paths and restore exact owner-only directory custody",
    );
  }
  return [];
}

function rejectUnknownBoundaryCreateStageTargets(targets) {
  const unknownStageTargets = targets.filter((name) => !knownBoundaryCreateStageTarget(name));
  if (unknownStageTargets.length > 0) {
    setupFailed(
      "unknown boundary create stages are present",
      `${unknownStageTargets.length} staged destination name(s) are outside the closed canary/policy/rotation grammar; names are omitted`,
      "inspect without publishing or deleting the unknown stages",
    );
  }
}

function recoverStagedRotationLock() {
  const targets = boundaryCreateStageTargets();
  rejectUnknownBoundaryCreateStageTargets(targets);
  try {
    recoverDurableCreateForPath({
      path: ROTATION_LOCK_FILE,
      mode: KEY_MODE,
    });
  } catch (error) {
    custodyFailure(
      "the retired exclusion rotation lock staging state requires manual recovery",
      error,
      "retain every stage; do not publish or delete it automatically in a same-UID namespace",
    );
  }
}

function recoverKnownBoundaryCreateStages({ onlyTarget = null } = {}) {
  const targets = boundaryCreateStageTargets();
  rejectUnknownBoundaryCreateStageTargets(targets);
  for (const name of targets) {
    if (onlyTarget !== null && name !== onlyTarget) continue;
    const path = join(KEY_DIR, name);
    try {
      recoverDurableCreateForPath({
        path,
        mode: KEY_MODE,
      });
    } catch (error) {
      custodyFailure(
        `the retired staged boundary file ${opaqueValueId("stage", name)} requires manual recovery`,
        error,
        "retain every stage; do not publish or delete it automatically in a same-UID namespace",
      );
    }
  }
}

function acquireRotationLock() {
  let recoveredStale = false;
  boundaryKeyDirectory({ create: true });
  for (let attempt = 0; attempt < 8; attempt++) {
    recoverStagedRotationLock();
    let claimPath = discoverRotationLockClaim();
    let claimRecord = null;
    const lockStat = inspectPath(ROTATION_LOCK_FILE, "exclusion rotation lock", { optional: true });

    if (claimPath !== null) {
      const claimStat = inspectPath(claimPath, "exclusion rotation lock claim");
      if (claimStat.nlink !== 1 && claimStat.nlink !== 2) {
        setupFailed("the exclusion rotation lock claim has an unsafe link count", "only the exact one-link or claimed-source two-link state is accepted", null);
      }
      claimRecord = readRotationLockRecord(claimPath, "exclusion rotation lock claim", { allowLinks: claimStat.nlink });
      const claimName = ROTATION_LOCK_CLAIM_NAME_RE.exec(basename(claimPath));
      if (claimName === null || claimName[1] !== claimRecord.digest) {
        if (claimStat.nlink === 2 && lockStat !== null && sameFileIdentity(lockStat, claimStat)) {
          const delayedFixed = readRotationLockRecord(
            ROTATION_LOCK_FILE,
            "live lock carrying a delayed stale-claim alias",
            { allowLinks: 2 },
          );
          if (!equalBytes(delayedFixed.bytes, claimRecord.bytes)) {
            setupFailed("the delayed exclusion rotation claim differs from its fixed inode", "no path was removed", null);
          }
          durableRemoveExact(claimPath, claimRecord.bytes, "content-mismatched delayed stale-lock claim", { allowLinks: 2 });
          if (processAppearsAlive(delayedFixed.doc.pid)) {
            setupFailed("another exclusion rotation writer is active", "a crash-left delayed claim alias was removed from the exact live fixed lock", "wait for that writer");
          }
          recoveredStale = true;
          continue;
        }
        setupFailed("the exclusion rotation lock claim filename is not content-bound", "the full SHA-256 differs from its exact canonical lock bytes; no path was removed", null);
      }

      if (claimStat.nlink === 2) {
        if (lockStat === null || !sameFileIdentity(lockStat, claimStat)) {
          setupFailed("the exclusion rotation lock claim has an unknown second link", "the fixed lock is not the claimed inode; no path was removed", null);
        }
        const fixed = readRotationLockRecord(ROTATION_LOCK_FILE, "claimed stale exclusion rotation lock", { allowLinks: 2 });
        if (!equalBytes(fixed.bytes, claimRecord.bytes)) {
          setupFailed("the exclusion rotation lock claim differs from its source", "the claim cannot authorize unlinking a different inode", null);
        }
        if (processAppearsAlive(claimRecord.doc.pid)) {
          durableRemoveExact(claimPath, claimRecord.bytes, "invalid live-process exclusion rotation claim", { allowLinks: 2 });
          setupFailed("another exclusion rotation writer is active", "a delayed contender claimed a lock whose owner is live; the claim alias was removed, not the lock", "wait for that writer");
        }
        try {
          durableUnlinkClaimedSource({
            sourcePath: ROTATION_LOCK_FILE,
            claimPath,
            expectedBytes: claimRecord.bytes,
            mode: KEY_MODE,
          });
        } catch (error) {
          custodyFailure("the claimed stale exclusion rotation lock could not be detached", error, "retain the exact claim and retry forward recovery");
        }
        rotationCheckpoint("stale-lock-unlinked");
        recoveredStale = true;
      } else if (lockStat !== null) {
        if (sameFileIdentity(lockStat, claimStat)) {
          setupFailed("the exclusion rotation lock claim link count contradicts its fixed alias", "two names report a one-link inode; no path was removed", null);
        }
        const fixed = readRotationLockRecord(ROTATION_LOCK_FILE, "replacement exclusion rotation lock");
        if (processAppearsAlive(fixed.doc.pid)) {
          setupFailed(
            "another exclusion rotation writer is active",
            "the durable replacement lock names a live local process; its retained stale claim was not changed",
            "wait for that exact writer to consume its claim",
          );
        }
        durableRemoveExact(claimPath, claimRecord.bytes, "superseded stale exclusion rotation claim");
        recoveredStale = true;
        continue;
      }

      if (processAppearsAlive(claimRecord.doc.pid)) {
        setupFailed("the exclusion rotation claim owner identity is no longer safely stale", "the claimed PID is live; no fixed lock was created", "wait for the process or review PID reuse before recovery");
      }
    } else if (lockStat !== null) {
      const stale = readRotationLockRecord(ROTATION_LOCK_FILE, "exclusion rotation lock");
      if (processAppearsAlive(stale.doc.pid)) {
        setupFailed("another exclusion rotation writer is active", "the owner-only lock names a live local process", "wait for that writer; do not remove its lock");
      }
      rotationCheckpoint("stale-lock-observed");
      claimPath = join(KEY_DIR, `exclusion-policy-rotation-lock-claim-${stale.digest}.lock`);
      let claim;
      try {
        claim = durableClaimExactByLink({
          sourcePath: ROTATION_LOCK_FILE,
          claimPath,
          expectedBytes: stale.bytes,
          mode: KEY_MODE,
          beforeLink: () => rotationCheckpoint("stale-lock-source-opened"),
        });
      } catch (error) {
        custodyFailure("the stale exclusion rotation lock could not be atomically claimed", error, "retain the current fixed lock and retry from exact bytes");
      }
      if (!claim.claimed) {
        setupFailed("another stale-lock recoverer won the exclusion rotation claim", "the fixed lock was not removed by this contender", "let the elected recoverer finish, then retry");
      }
      rotationCheckpoint("stale-lock-claimed");
      if (processAppearsAlive(stale.doc.pid)) {
        durableRemoveExact(claimPath, stale.bytes, "late live-process exclusion rotation claim", { allowLinks: 2 });
        setupFailed("the exclusion rotation lock owner became live during stale recovery", "only the claim alias was removed", "wait for the live owner");
      }
      try {
        durableUnlinkClaimedSource({
          sourcePath: ROTATION_LOCK_FILE,
          claimPath,
          expectedBytes: stale.bytes,
          mode: KEY_MODE,
        });
      } catch (error) {
        custodyFailure("the claimed stale exclusion rotation lock could not be detached", error, "retain the exact claim and retry forward recovery");
      }
      rotationCheckpoint("stale-lock-unlinked");
      claimRecord = stale;
      recoveredStale = true;
    }

    const doc = {
      schemaVersion: 1,
      event: "EXCLUSION_POLICY_ROTATION_LOCK",
      pid: process.pid,
      startedAt: new Date().toISOString(),
      nonce: randomBytes(32).toString("hex"),
    };
    const bytes = Buffer.from(`${canonicalJson(doc)}\n`, "utf8");
    writeConfidentialExclusive(ROTATION_LOCK_FILE, "exclusion rotation lock", bytes);
    const exact = readRotationLockRecord(ROTATION_LOCK_FILE, "new exclusion rotation lock");
    if (!equalBytes(exact.bytes, bytes)) setupFailed("the new exclusion rotation lock changed after staged publication", "the current writer does not own the final exact bytes", null);
    rotationCheckpoint("replacement-lock-published-before-claim-cleanup");
    if (claimPath !== null && claimRecord !== null) {
      const retainedClaim = readRotationLockRecord(claimPath, "completed stale exclusion rotation claim");
      if (!equalBytes(retainedClaim.bytes, claimRecord.bytes)) setupFailed("the stale exclusion rotation claim changed before cleanup", "the replacement lock was retained", null);
      durableRemoveExact(claimPath, claimRecord.bytes, "completed stale exclusion rotation claim");
    }
    rotationCheckpoint("lock-acquired");
    return { bytes, recoveredStale };
  }
  setupFailed("the exclusion rotation lock recovery did not converge", "eight exact state transitions were insufficient; no unknown path was removed", "inspect the retained claim and lock bytes");
  return null;
}

function releaseRotationLock(bytes) {
  const measured = readConfidentialFile(ROTATION_LOCK_FILE, "exclusion rotation lock", { exactBytes: bytes.length });
  if (!equalBytes(measured, bytes)) setupFailed("the exclusion rotation lock owner changed", "the current process no longer holds the exact lock bytes", null);
  durableRemoveExact(ROTATION_LOCK_FILE, bytes, "exclusion rotation lock");
}

function ensureExactConfidentialFile(path, what, bytes) {
  let present = false;
  try { lstatSync(path); present = true; } catch (error) {
    if (error?.code !== "ENOENT") setupFailed(`the ${what} cannot be inspected`, "exclusive custody state is unknown", null);
  }
  if (!present) writeConfidentialExclusive(path, what, bytes);
  try { durableSyncExact({ path, expectedBytes: bytes, mode: KEY_MODE }); } catch (error) {
    custodyFailure(`the ${what} could not establish durable exact custody`, error, "retain the exact evidence and retry without replacing it");
  }
  const measured = readConfidentialFile(path, what, { exactBytes: bytes.length });
  if (!equalBytes(measured, bytes)) {
    setupFailed(`the ${what} does not contain the exact expected bytes`, "the create-exclusive recovery file differs; no values were printed", "stop and inspect the authenticated rotation state");
  }
}

function normalizeAuthenticatedAlias({
  legacyRecord,
  canonicalRecord,
  canonicalPath,
  canonicalWhat,
  legacyWhat,
  checkpoint,
  loadCanonical,
  validatePair,
}) {
  if (legacyRecord === null) return canonicalRecord;
  if (legacyRecord.path === canonicalPath) {
    setupFailed(`the ${legacyWhat} aliases its canonical path`, "normalization requires two distinct deterministic names", null);
  }
  if (canonicalRecord === null) {
    ensureExactConfidentialFile(canonicalPath, canonicalWhat, legacyRecord.bytes);
    canonicalRecord = loadCanonical();
  }
  if (!equalBytes(legacyRecord.bytes, canonicalRecord.bytes)) {
    setupFailed(
      `the ${legacyWhat} and ${canonicalWhat} differ`,
      "old and new names do not form one byte-identical authenticated normalization pair; nothing was deleted",
      null,
    );
  }
  validatePair(legacyRecord, canonicalRecord);
  try {
    durableSyncExact({ path: canonicalPath, expectedBytes: canonicalRecord.bytes, mode: KEY_MODE });
  } catch (error) {
    custodyFailure(`the ${canonicalWhat} could not be made durable`, error, "retain both exact aliases and retry forward normalization");
  }
  rotationCheckpoint(checkpoint);
  const legacyReadBack = readConfidentialFile(legacyRecord.path, legacyWhat, { exactBytes: legacyRecord.bytes.length });
  const canonicalReadBack = readConfidentialFile(canonicalPath, canonicalWhat, { exactBytes: canonicalRecord.bytes.length });
  if (!equalBytes(legacyReadBack, legacyRecord.bytes) || !equalBytes(canonicalReadBack, canonicalRecord.bytes)
      || !equalBytes(legacyReadBack, canonicalReadBack)) {
    setupFailed("the authenticated alias pair changed before normalization cleanup", "both names were retained", null);
  }
  durableRemoveExact(legacyRecord.path, legacyRecord.bytes, legacyWhat);
  return loadCanonical();
}

function successorByteEvidence(bytes, doc) {
  return {
    ...policyByteEvidence(bytes, doc),
    controlManifestVersion: doc.controlManifestVersion,
    controlManifestDigest: doc.controlManifestDigest,
  };
}

const sameEvidence = (left, right) => canonicalJson(left) === canonicalJson(right);

function loadRotationReceipts(paths, key) {
  return paths.map((path) => {
    const text = readConfidentialText(path, "exclusion rotation receipt", { maxBytes: MAX_CONFIDENTIAL_TEXT_BYTES });
    const doc = parseCanonicalRotationReceipt(text);
    validateRotationReceiptEnvelope(doc, key);
    const name = basename(path);
    const full = ROTATION_RECEIPT_NAME_RE.exec(name);
    const legacy = LEGACY_ROTATION_RECEIPT_NAME_RE.exec(name);
    const match = full ?? legacy;
    if (match === null || Number(match[1]) !== doc.body.predecessor.schemaVersion
        || (full !== null
          ? (match[2] !== doc.body.predecessor.sha256 || match[3] !== doc.body.successor.sha256)
          : (match[2] !== doc.body.predecessor.sha256.slice(0, 16)
            || match[3] !== doc.body.successor.sha256.slice(0, 16)))) {
      setupFailed("an exclusion rotation receipt filename is not content-bound", "schema and predecessor/successor SHA-256 identity must match its authenticated body", "restore the exact authenticated receipt name without changing bytes");
    }
    return { path, text, bytes: Buffer.from(text, "utf8"), doc, legacyName: legacy !== null };
  });
}

function normalizeReceiptAliases(matches, key) {
  if (matches.length === 0) return matches;
  const first = matches[0];
  const canonicalPath = join(
    KEY_DIR,
    `exclusion-policy-rotation-v${first.doc.body.predecessor.schemaVersion}-${first.doc.body.predecessor.sha256}`
      + `-to-v3-${first.doc.body.successor.sha256}.json`,
  );
  const legacy = matches.filter((receipt) => receipt.legacyName);
  const canonical = matches.filter((receipt) => !receipt.legacyName && receipt.path === canonicalPath);
  if (matches.length > 2 || legacy.length > 1 || canonical.length > 1
      || matches.some((receipt) => !receipt.legacyName && receipt.path !== canonicalPath)) {
    setupFailed("multiple receipts do not form one exact authenticated alias pair", "cleanup authority is ambiguous; nothing was deleted", null);
  }
  if (legacy.length === 0) return matches;
  const normalized = normalizeAuthenticatedAlias({
    legacyRecord: legacy[0],
    canonicalRecord: canonical[0] ?? null,
    canonicalPath,
    canonicalWhat: "full-SHA exclusion rotation receipt",
    legacyWhat: "legacy-prefix exclusion rotation receipt",
    checkpoint: "legacy-receipt-full-durable",
    loadCanonical: () => loadRotationReceipts([canonicalPath], key)[0],
    validatePair: (oldRecord, newRecord) => {
      validateRotationReceiptEnvelope(oldRecord.doc, key);
      validateRotationReceiptEnvelope(newRecord.doc, key);
      if (canonicalJson(oldRecord.doc) !== canonicalJson(newRecord.doc)) {
        setupFailed("the receipt aliases are not the same authenticated record", "both names were retained", null);
      }
    },
  });
  return [normalized];
}

function intentRecordFromReceipt(receipt, key) {
  if (receipt.doc.body.schemaVersion !== ROTATION_RECEIPT_SCHEMA_VERSION) return null;
  const intentDoc = rotationIntentDocumentFromEvidence(key, {
    predecessor: receipt.doc.body.predecessor,
    observedActive: receipt.doc.body.observedActive,
    successor: receipt.doc.body.successor,
    legacy: receipt.doc.body.legacy,
    entryCount: receipt.doc.body.entryCount,
    durabilityProfile: receipt.doc.body.durabilityProfile,
  });
  const bytes = Buffer.from(`${canonicalJson(intentDoc)}\n`, "utf8");
  const digest = createHash("sha256").update(bytes).digest("hex");
  if (!equalHex64(digest, receipt.doc.body.intentSha256)) {
    setupFailed("the exclusion rotation receipt cannot recover its intent", "the reconstructed intent digest differs; nothing was deleted", "restore the exact authenticated receipt");
  }
  return {
    path: join(KEY_DIR, `exclusion-policy-rotation-intent-${digest}.json`),
    text: bytes.toString("utf8"),
    bytes,
    doc: intentDoc,
    digest,
  };
}

function readNamedPolicy(path, what, key, legacy, root, options = {}) {
  const record = readAndValidatePolicyAt(path, what, key, legacy, root, options);
  const digest = createHash("sha256").update(record.bytes).digest("hex");
  return { ...record, path, digest };
}

function assertNamedPolicyDigest(record, match, what, { legacyPrefix = false } = {}) {
  if (match === null || Number(match[1] ?? EXCLUSION_POLICY_SCHEMA_VERSION) !== record.doc.schemaVersion
      || (legacyPrefix ? match[2] !== record.digest.slice(0, 16) : match.at(-1) !== record.digest)) {
    setupFailed(`the ${what} filename is not content-bound`, "schema or full SHA-256 differs from the authenticated exact bytes", "restore the exact deterministic state name without changing bytes");
  }
}

function migrateExclusions(opts, root) {
  const recoveryOnly = opts.recoverExclusionRotation === true;
  const rotationLock = acquireRotationLock();
  recoverKnownBoundaryCreateStages();
  let existingStat = null;
  try {
    existingStat = lstatSync(EXCLUSION_POLICY_FILE);
  } catch (error) {
    if (error?.code !== "ENOENT") setupFailed("the governed exclusion policy destination cannot be inspected", `${opaquePathId(EXCLUSION_POLICY_FILE)}: ${error?.code ?? "I/O error"}`, "restore stable owner-only custody before migration");
  }
  if (opts.migrateExclusions && existingStat !== null && !rotationLock.recoveredStale) {
    setupFailed("the governed exclusion policy destination already exists", "create mode never overwrites, follows, repairs, or deletes an existing destination", "use reviewed rotate mode only after authenticating the predecessor");
  }
  if ((opts.rotateExclusions || recoveryOnly) && existingStat === null) {
    setupFailed("the governed exclusion policy predecessor is missing", "rotate mode cannot prove or preserve a nonexistent predecessor", "use create mode only for a genuinely new destination");
  }

  const key = readBoundaryKey();
  const legacy = loadLegacyExclusionSource({ required: true });
  if (legacy.entries.length === 0) setupFailed("the legacy exclusion source has no active entries", "there is nothing reviewed to migrate", "do not create an empty governance document");
  let existingBytes = null;
  let existingDoc = null;
  if (existingStat !== null) {
    const existing = readAndValidatePolicyAt(
      EXCLUSION_POLICY_FILE,
      "governed exclusion policy predecessor",
      key,
      legacy,
      root,
      { verifyControlManifest: false, allowPreviousControlManifest: true },
    );
    ({ bytes: existingBytes, doc: existingDoc } = existing);
  }
  const keyId = createHash("sha256").update(key).digest("hex");
  let doc;
  let validated;
  if (recoveryOnly) {
    if (existingDoc?.schemaVersion !== EXCLUSION_POLICY_SCHEMA_VERSION
        || existingDoc.controlManifestVersion !== 1
        || existingDoc.controlManifestFiles.length !== PREVIOUS_REVIEWED_CONTROL_PATHS.length
        || existingDoc.controlManifestFiles.some((path, index) => path !== PREVIOUS_REVIEWED_CONTROL_PATHS[index])) {
      setupFailed(
        "recovery-only exclusion rotation has no exact historical schema-v3/7 active policy",
        "recovery never rewrites metadata or upgrades a current policy; it only closes the authenticated v2-to-v3 predecessor transaction",
        "retain all bytes and run fresh rotation only after the historical recovery receipt is durable",
      );
    }
    doc = existingDoc;
    validated = validateExclusionPolicyDocument(doc, key, legacy, root, {
      verifyControlManifest: false,
      allowPreviousControlManifest: true,
    });
  } else {
    const controlManifest = reviewedControlManifest(root);
    const body = {
      schemaVersion: EXCLUSION_POLICY_SCHEMA_VERSION,
      keyId,
      reviewer: opts.reviewer,
      reviewedAt: opts.reviewedAt,
      expiresAt: opts.expiresAt,
      reviewSession: opts.reviewSession,
      classification: opts.classification,
      publicArtifact: opts.publicArtifact,
      publicArtifactSRI: opts.publicArtifactSri,
      controlManifestVersion: controlManifest.version,
      controlManifestFiles: controlManifest.paths,
      controlManifestDigest: controlManifest.digest,
      legacyByteLength: legacy.byteLength,
      legacySha256: legacy.sha256,
      entries: legacy.entries,
    };
    doc = { ...body, mac: keyedCanonicalRecord(key, "exclusion-policy/v3", body) };
    validated = validateExclusionPolicyDocument(doc, key, legacy, root);
  }

  const legacyImmediatelyBefore = readConfidentialFile(LEGACY_EXCLUDE_TOKENS_FILE, "legacy exclusion inputs", { maxBytes: MAX_CONFIDENTIAL_TEXT_BYTES });
  if (!legacy.bytes.equals(legacyImmediatelyBefore)) setupFailed("the legacy exclusion source changed during migration", "the reviewed bytes changed before create-exclusive output; no destination was written", "stop concurrent writers and repeat the review");
  const serialized = recoveryOnly ? existingBytes : Buffer.from(`${canonicalJson(doc)}\n`, "utf8");
  if (opts.migrateExclusions) {
    if (existingBytes === null) {
      writeConfidentialExclusive(EXCLUSION_POLICY_FILE, "governed exclusion policy", serialized);
    } else if (!equalBytes(existingBytes, serialized)) {
      setupFailed("the recovered exclusion migration destination differs", "a stale writer lock cannot authorize replacing existing policy bytes", "inspect both exact states without overwriting either");
    }
    rotationCheckpoint("policy-created");
  } else {
    const proposedSuccessor = { bytes: serialized, doc, validated };
    let artifacts = discoverRotationArtifacts();
    let receipts = loadRotationReceipts(artifacts.receipts, key);
    let active = readNamedPolicy(
      EXCLUSION_POLICY_FILE,
      "active governed exclusion policy",
      key,
      legacy,
      root,
      { verifyControlManifest: false, allowPreviousControlManifest: true },
    );

    const rawSchemaV2 = artifacts.predecessors.some((path) => {
      const name = basename(path);
      return (FULL_SUPERSEDED_POLICY_NAME_RE.exec(name) ?? LEGACY_SUPERSEDED_POLICY_NAME_RE.exec(name))?.[1] === "2";
    }) || artifacts.deleting.some((path) => DELETING_POLICY_NAME_RE.exec(basename(path))?.[1] === "2");
    const intentSchemaV2 = artifacts.intents.some((path) => {
      const text = readConfidentialText(path, "exclusion rotation intent", { maxBytes: MAX_CONFIDENTIAL_TEXT_BYTES });
      return validateRotationIntentDocument(parseCanonicalRotationIntent(text), key).body.predecessor.schemaVersion
        === PREVIOUS_EXCLUSION_POLICY_SCHEMA_VERSION;
    });
    const legacyDeletingSchemaV2 = artifacts.legacyDeleting.some((path) =>
      readNamedPolicy(
        path,
        "legacy random exclusion deletion tombstone",
        key,
        legacy,
        root,
        { verifyControlManifest: false, allowPreviousControlManifest: true },
      ).doc.schemaVersion === PREVIOUS_EXCLUSION_POLICY_SCHEMA_VERSION);
    const receiptSchemaV2 = receipts.some((receipt) =>
      receipt.doc.body.predecessor.schemaVersion === PREVIOUS_EXCLUSION_POLICY_SCHEMA_VERSION);
    const historicalV2State = rawSchemaV2 || intentSchemaV2 || legacyDeletingSchemaV2 || receiptSchemaV2;
    if (opts.rotateExclusions && !recoveryOnly && (rawSchemaV2 || intentSchemaV2 || legacyDeletingSchemaV2)) {
      setupFailed(
        "fresh exclusion rotation encountered unfinished schema-v2 recovery state",
        "old metadata cannot authorize an expanded manifest, and fresh metadata cannot be written into historical cleanup",
        "run --recover-exclusion-rotation first; require its durable v2-to-exact-current-v3 receipt, then run a separate fresh rotation",
      );
    }
    if (recoveryOnly && !historicalV2State) {
      setupFailed(
        "recovery-only exclusion rotation found no schema-v2 predecessor transaction",
        "recovery mode cannot create a fresh policy or receipt without exact historical evidence",
        "use fresh --rotate-exclusions only when no unfinished v2 state remains",
      );
    }

    // Recover the one random tombstone shape emitted by the superseded implementation. It is never
    // deleted in place. A valid exact receipt advances it to deterministic deleting custody; without
    // a receipt its exact authenticated bytes return to deterministic predecessor custody.
    if (artifacts.legacyDeleting.length === 1) {
      const legacyTombstone = readNamedPolicy(
        artifacts.legacyDeleting[0],
        "legacy random exclusion deletion tombstone",
        key,
        legacy,
        root,
        { verifyControlManifest: false, allowPreviousControlManifest: true },
      );
      const activeSuccessorEvidence = active.doc.schemaVersion === EXCLUSION_POLICY_SCHEMA_VERSION
        ? successorByteEvidence(active.bytes, active.doc) : null;
      let matching = activeSuccessorEvidence === null ? [] : receipts.filter((receipt) =>
        sameEvidence(receipt.doc.body.predecessor, policyByteEvidence(legacyTombstone.bytes, legacyTombstone.doc))
          && sameEvidence(receipt.doc.body.successor, activeSuccessorEvidence));
      matching = normalizeReceiptAliases(matching, key);
      if (matching.length > 1) setupFailed("multiple receipts bind the legacy deletion tombstone", "cleanup authority is ambiguous; nothing was deleted", null);
      const recoveryPath = matching.length === 1
        ? join(KEY_DIR, `exclusions.deleting-v${legacyTombstone.doc.schemaVersion}-${legacyTombstone.digest}.json`)
        : join(KEY_DIR, `exclusions.superseded-v${legacyTombstone.doc.schemaVersion}-${legacyTombstone.digest}.json`);
      const expectedGroup = matching.length === 1 ? artifacts.deleting : artifacts.predecessors;
      const conflictingGroup = matching.length === 1 ? artifacts.predecessors : artifacts.deleting;
      if (artifacts.pending.length > 0 || artifacts.intents.length > 0 || conflictingGroup.length > 0
          || expectedGroup.length > 1 || (expectedGroup.length === 1 && expectedGroup[0] !== recoveryPath)) {
        setupFailed("a legacy random deletion tombstone conflicts with newer rotation state", "the files do not form the one exact authenticated old/new normalization pair; nothing was deleted", null);
      }
      if (matching.length === 1) {
        validateRotationReceiptDocument(matching[0].doc, key, {
          predecessorBytes: legacyTombstone.bytes,
          predecessorDoc: legacyTombstone.doc,
          successorBytes: active.bytes,
          successorDoc: active.doc,
          legacy,
        });
      }
      const loadRecovery = () => {
        const record = readNamedPolicy(
          recoveryPath,
          "deterministic legacy deletion recovery",
          key,
          legacy,
          root,
          { verifyControlManifest: false, allowPreviousControlManifest: true },
        );
        const nameMatch = matching.length === 1
          ? DELETING_POLICY_NAME_RE.exec(basename(record.path))
          : FULL_SUPERSEDED_POLICY_NAME_RE.exec(basename(record.path));
        assertNamedPolicyDigest(record, nameMatch, "deterministic legacy deletion recovery");
        return record;
      };
      normalizeAuthenticatedAlias({
        legacyRecord: legacyTombstone,
        canonicalRecord: expectedGroup.length === 1 ? loadRecovery() : null,
        canonicalPath: recoveryPath,
        canonicalWhat: "deterministic legacy deletion recovery",
        legacyWhat: "legacy random deletion tombstone",
        checkpoint: "legacy-tombstone-deterministic-durable",
        loadCanonical: loadRecovery,
        validatePair: (oldRecord, newRecord) => {
          if (!sameEvidence(policyByteEvidence(oldRecord.bytes, oldRecord.doc), policyByteEvidence(newRecord.bytes, newRecord.doc))) {
            setupFailed("the legacy tombstone aliases are not the same authenticated policy", "both names were retained", null);
          }
        },
      });
      rotationCheckpoint("legacy-tombstone-recovered");
      artifacts = discoverRotationArtifacts();
      receipts = loadRotationReceipts(artifacts.receipts, key);
    }

    const predecessorRecords = artifacts.predecessors.map((path) => {
      const record = readNamedPolicy(path, "raw superseded governed exclusion policy", key, legacy, root, {
        verifyControlManifest: false, allowPreviousControlManifest: true,
      });
      const name = basename(path);
      const full = FULL_SUPERSEDED_POLICY_NAME_RE.exec(name);
      const old = LEGACY_SUPERSEDED_POLICY_NAME_RE.exec(name);
      assertNamedPolicyDigest(record, full ?? old, "raw superseded exclusion policy", { legacyPrefix: old !== null });
      return { ...record, legacyName: old !== null };
    });
    if (predecessorRecords.length === 2) {
      const full = predecessorRecords.find((record) => !record.legacyName);
      const old = predecessorRecords.find((record) => record.legacyName);
      if (full === undefined || old === undefined || !equalBytes(full.bytes, old.bytes)) {
        setupFailed("multiple raw predecessor files do not form one exact name-normalization state", "nothing was deleted", null);
      }
    }
    let predecessor = predecessorRecords.find((record) => !record.legacyName) ?? predecessorRecords[0] ?? null;

    let deleting = null;
    if (artifacts.deleting.length === 1) {
      deleting = readNamedPolicy(artifacts.deleting[0], "deterministic deleting exclusion policy", key, legacy, root, {
        verifyControlManifest: false, allowPreviousControlManifest: true,
      });
      assertNamedPolicyDigest(deleting, DELETING_POLICY_NAME_RE.exec(basename(deleting.path)), "deterministic deleting exclusion policy");
    }
    if (predecessor !== null && deleting !== null && !equalBytes(predecessor.bytes, deleting.bytes)) {
      setupFailed("raw and deleting predecessor states differ", "the cleanup transaction is ambiguous; nothing was deleted", null);
    }
    if (predecessor === null) predecessor = deleting;

    let intentRecord = null;
    if (artifacts.intents.length === 1) {
      const intentText = readConfidentialText(artifacts.intents[0], "exclusion rotation intent", { maxBytes: MAX_CONFIDENTIAL_TEXT_BYTES });
      const intentDoc = validateRotationIntentDocument(parseCanonicalRotationIntent(intentText), key);
      const intentBytes = Buffer.from(intentText, "utf8");
      const intentDigest = createHash("sha256").update(intentBytes).digest("hex");
      const nameMatch = ROTATION_INTENT_NAME_RE.exec(basename(artifacts.intents[0]));
      if (nameMatch === null || nameMatch[1] !== intentDigest) {
        setupFailed("the exclusion rotation intent filename is not content-bound", "the full SHA-256 does not equal the exact authenticated intent bytes", null);
      }
      intentRecord = { path: artifacts.intents[0], text: intentText, bytes: intentBytes, doc: intentDoc, digest: intentDigest };
    }

    const proposedEvidence = successorByteEvidence(serialized, doc);
    let predecessorEvidence = predecessor === null ? null : policyByteEvidence(predecessor.bytes, predecessor.doc);
    if (intentRecord === null && predecessor !== null && equalBytes(active.bytes, serialized)) {
      const completed = normalizeReceiptAliases(receipts.filter((receipt) => sameEvidence(receipt.doc.body.predecessor, predecessorEvidence)
        && sameEvidence(receipt.doc.body.successor, proposedEvidence)
        && sameEvidence(receipt.doc.body.legacy, { byteLength: legacy.byteLength, sha256: legacy.sha256 })
        && receipt.doc.body.entryCount === doc.entries.length), key);
      if (completed.length > 1) setupFailed("multiple receipts could recover the exclusion rotation intent", "cleanup authority is ambiguous; nothing was deleted", null);
      if (completed.length === 1) {
        const recoveredIntent = intentRecordFromReceipt(completed[0], key);
        if (recoveredIntent !== null) {
          validateRotationReceiptDocument(completed[0].doc, key, {
            predecessorBytes: predecessor.bytes,
            predecessorDoc: predecessor.doc,
            successorBytes: active.bytes,
            successorDoc: active.doc,
            legacy,
            intentRecord: recoveredIntent,
          });
          ensureExactConfidentialFile(recoveredIntent.path, "receipt-recovered exclusion rotation intent", recoveredIntent.bytes);
          intentRecord = recoveredIntent;
        }
      }
    }
    if (intentRecord === null && predecessor === null && equalBytes(active.bytes, serialized)) {
      const completed = normalizeReceiptAliases(receipts.filter((receipt) => sameEvidence(receipt.doc.body.successor, proposedEvidence)
        && sameEvidence(receipt.doc.body.legacy, { byteLength: legacy.byteLength, sha256: legacy.sha256 })
        && receipt.doc.body.entryCount === doc.entries.length), key);
      if (completed.length > 1) setupFailed("multiple receipts could complete the recovered rotation", "terminal state is ambiguous; nothing was deleted", null);
      if (completed.length === 1) {
        const retained = readConfidentialText(completed[0].path, "completed exclusion rotation receipt", { maxBytes: MAX_CONFIDENTIAL_TEXT_BYTES });
        validateRotationReceiptEnvelope(parseCanonicalRotationReceipt(retained), key);
        releaseRotationLock(rotationLock.bytes);
        say(green("  resumed a completed exclusion rotation after intent cleanup; authenticated receipt and active successor remain exact."));
        return;
      }
    }
    if (intentRecord === null) {
      if (predecessor === null) predecessor = active;
      predecessorEvidence = policyByteEvidence(predecessor.bytes, predecessor.doc);
      if (predecessorRecords.length === 0 && deleting === null && equalBytes(active.bytes, serialized)) {
        setupFailed("the exclusion rotation has no material successor", "no pending predecessor exists and current policy already matches the proposed bytes", "rotate only for a reviewed control or decision change");
      }
      const intentDoc = rotationIntentDocument(key, predecessor, active, proposedSuccessor, legacy);
      const intentBytes = Buffer.from(`${canonicalJson(intentDoc)}\n`, "utf8");
      const intentDigest = createHash("sha256").update(intentBytes).digest("hex");
      const intentPath = join(KEY_DIR, `exclusion-policy-rotation-intent-${intentDigest}.json`);
      writeConfidentialExclusive(intentPath, "exclusion rotation intent", intentBytes);
      intentRecord = { path: intentPath, bytes: intentBytes, text: intentBytes.toString("utf8"), doc: intentDoc, digest: intentDigest };
      rotationCheckpoint("intent-durable");
    } else {
      const body = intentRecord.doc.body;
      if (!sameEvidence(body.successor, proposedEvidence)
          || !sameEvidence(body.legacy, { byteLength: legacy.byteLength, sha256: legacy.sha256 })
          || body.entryCount !== doc.entries.length) {
        setupFailed("the existing exclusion rotation intent differs from the requested successor", "restart may only resume the exact authenticated transaction; nothing was deleted", null);
      }
      if (predecessorEvidence !== null && !sameEvidence(body.predecessor, predecessorEvidence)) {
        setupFailed("the exclusion rotation predecessor differs from its authenticated intent", "nothing was deleted", null);
      }
      const activeEvidence = policyByteEvidence(active.bytes, active.doc);
      if (!sameEvidence(activeEvidence, body.observedActive)
          && !sameEvidence(active.doc.schemaVersion === EXCLUSION_POLICY_SCHEMA_VERSION
            ? successorByteEvidence(active.bytes, active.doc) : activeEvidence, body.successor)) {
        setupFailed("the active exclusion policy is outside the authenticated rotation state", "it matches neither observed pre-state nor reviewed successor", null);
      }
      if (predecessor === null && sameEvidence(activeEvidence, body.predecessor)) predecessor = active;
      predecessorEvidence = body.predecessor;
    }

    // A pre-existing schema-v2 raw predecessor may only bridge one unchanged reviewed decision.
    if (predecessor !== null && predecessor.doc.schemaVersion === PREVIOUS_EXCLUSION_POLICY_SCHEMA_VERSION
        && (!reviewedDecisionMatches(predecessor.doc, existingDoc) || !reviewedDecisionMatches(predecessor.doc, doc))) {
      setupFailed(
        "the schema-v2 predecessor, active policy, and proposed successor do not carry one review decision",
        "pending v2 cleanup cannot authorize changed reviewer, evidence, expiry, or exclusions; values are omitted",
        "complete the exact reviewed rotation or obtain a new independent review",
      );
    }

    // Normalize the historical 16-hex predecessor name only after the durable intent exists.
    const legacyPredecessor = predecessorRecords.find((record) => record.legacyName);
    if (legacyPredecessor !== undefined) {
      const fullPath = join(KEY_DIR, `exclusions.superseded-v${legacyPredecessor.doc.schemaVersion}-${legacyPredecessor.digest}.json`);
      const loadFullPredecessor = () => {
        const record = readNamedPolicy(fullPath, "raw superseded governed exclusion policy", key, legacy, root, {
          verifyControlManifest: false, allowPreviousControlManifest: true,
        });
        assertNamedPolicyDigest(record, FULL_SUPERSEDED_POLICY_NAME_RE.exec(basename(record.path)), "full-SHA raw predecessor");
        return record;
      };
      predecessor = normalizeAuthenticatedAlias({
        legacyRecord: legacyPredecessor,
        canonicalRecord: predecessorRecords.find((record) => !record.legacyName) ?? null,
        canonicalPath: fullPath,
        canonicalWhat: "full-SHA raw superseded exclusion policy",
        legacyWhat: "legacy-prefix raw predecessor",
        checkpoint: "full-predecessor-durable",
        loadCanonical: loadFullPredecessor,
        validatePair: (oldRecord, newRecord) => {
          if (!sameEvidence(policyByteEvidence(oldRecord.bytes, oldRecord.doc), policyByteEvidence(newRecord.bytes, newRecord.doc))) {
            setupFailed("the predecessor aliases are not the same authenticated policy", "both names were retained", null);
          }
        },
      });
    } else if (predecessorRecords.length === 0 && deleting === null) {
      // If a receipt proves deletion already completed, never recreate the predecessor merely to
      // replay cleanup. Otherwise the exact observed active bytes become the durable predecessor.
      const alreadyDeleted = receipts.some((receipt) => sameEvidence(receipt.doc.body.predecessor, predecessorEvidence)
        && sameEvidence(receipt.doc.body.successor, proposedEvidence))
        && equalBytes(active.bytes, serialized);
      if (!alreadyDeleted) {
        const predecessorPath = join(
          KEY_DIR,
          `exclusions.superseded-v${predecessor.doc.schemaVersion}-${createHash("sha256").update(predecessor.bytes).digest("hex")}.json`,
        );
        ensureExactConfidentialFile(predecessorPath, "raw superseded governed exclusion policy", predecessor.bytes);
        predecessor = readNamedPolicy(predecessorPath, "raw superseded governed exclusion policy", key, legacy, root, {
          verifyControlManifest: false, allowPreviousControlManifest: true,
        });
        rotationCheckpoint("predecessor-durable");
      }
    }

    artifacts = discoverRotationArtifacts();
    if (artifacts.pending.length > 0) {
      const pending = readNamedPolicy(artifacts.pending[0], "governed exclusion policy rotation candidate", key, legacy, root, recoveryOnly
        ? { verifyControlManifest: false, allowPreviousControlManifest: true }
        : { verifyControlManifest: true });
      const pendingMatch = PENDING_SUCCESSOR_NAME_RE.exec(basename(pending.path));
      if (pendingMatch === null || pendingMatch[1] !== pending.digest || !equalBytes(pending.bytes, serialized)) {
        setupFailed("the pending exclusion successor differs from the authenticated intent", "nothing was activated", null);
      }
    }

    active = readNamedPolicy(EXCLUSION_POLICY_FILE, "active governed exclusion policy", key, legacy, root, {
      verifyControlManifest: false, allowPreviousControlManifest: true,
    });
    if (!equalBytes(active.bytes, serialized)) {
      if (!sameEvidence(policyByteEvidence(active.bytes, active.doc), intentRecord.doc.body.observedActive)) {
        setupFailed("the active exclusion predecessor changed after intent", "the reviewed successor was not activated", null);
      }
      const successorDigest = createHash("sha256").update(serialized).digest("hex");
      const pendingPath = join(KEY_DIR, `exclusions.pending-successor-v3-${successorDigest}.json`);
      ensureExactConfidentialFile(pendingPath, "governed exclusion policy rotation candidate", serialized);
      const pending = readAndValidatePolicyAt(pendingPath, "governed exclusion policy rotation candidate", key, legacy, root, recoveryOnly
        ? { verifyControlManifest: false, allowPreviousControlManifest: true }
        : { verifyControlManifest: true });
      if (!equalHex64(pending.validated.commitment, validated.commitment)) {
        setupFailed("the exclusion rotation candidate commitment changed", "durable read-back differs from the reviewed document", null);
      }
      rotationCheckpoint("successor-durable");
      try {
        durableReplaceFromCandidate({
          candidatePath: pendingPath,
          destinationPath: EXCLUSION_POLICY_FILE,
          candidateBytes: serialized,
          expectedDestinationBytes: active.bytes,
          mode: KEY_MODE,
        });
      } catch (error) {
        custodyFailure("the exclusion policy successor could not be activated durably", error, "retain the predecessor and resume the same intent");
      }
      rotationCheckpoint("successor-activated");
    } else if (artifacts.pending.length > 0) {
      setupFailed("an active successor and pending successor both exist", "this is not a valid atomic-rename state; nothing was deleted", null);
    }

    const successor = readNamedPolicy(EXCLUSION_POLICY_FILE, "active governed exclusion policy successor", key, legacy, root, recoveryOnly
      ? { verifyControlManifest: false, allowPreviousControlManifest: true }
      : { verifyControlManifest: true });
    if (!equalBytes(successor.bytes, serialized) || !equalHex64(successor.validated.commitment, validated.commitment)) {
      setupFailed("the active exclusion policy successor differs after activation", "the receipt was not created and predecessor evidence was retained", null);
    }
    rotationCheckpoint("successor-readback");

    const predecessorDigest = predecessorEvidence.sha256;
    const successorDigest = createHash("sha256").update(successor.bytes).digest("hex");
    const receiptPath = join(KEY_DIR, `exclusion-policy-rotation-v${predecessorEvidence.schemaVersion}-${predecessorDigest}-to-v3-${successorDigest}.json`);
    receipts = loadRotationReceipts(discoverRotationArtifacts().receipts, key);
    let matchingReceipts = receipts.filter((receipt) => sameEvidence(receipt.doc.body.predecessor, predecessorEvidence)
      && sameEvidence(receipt.doc.body.successor, successorByteEvidence(successor.bytes, successor.doc)));
    matchingReceipts = normalizeReceiptAliases(matchingReceipts, key);
    if (matchingReceipts.length > 1) setupFailed("multiple receipts bind the same exclusion rotation", "cleanup authority is ambiguous; nothing was deleted", null);
    if (matchingReceipts.length === 0) {
      const conflictingExactPath = receipts.find((receipt) => receipt.path === receiptPath);
      const receiptPredecessor = predecessor ?? deleting;
      if (conflictingExactPath !== undefined && receiptPredecessor !== null) {
        validateRotationReceiptDocument(conflictingExactPath.doc, key, {
          predecessorBytes: receiptPredecessor.bytes,
          predecessorDoc: receiptPredecessor.doc,
          successorBytes: successor.bytes,
          successorDoc: successor.doc,
          legacy,
          intentRecord,
        });
      }
    }
    if (matchingReceipts.length === 0) {
      const recordedAt = new Date().toISOString();
      const receiptBody = {
        schemaVersion: ROTATION_RECEIPT_SCHEMA_VERSION,
        event: ROTATION_RECEIPT_EVENT,
        recordedAt,
        verifiedAt: new Date().toISOString(),
        intentSha256: intentRecord.digest,
        predecessor: predecessorEvidence,
        observedActive: intentRecord.doc.body.observedActive,
        successor: successorByteEvidence(successor.bytes, successor.doc),
        legacy: { byteLength: legacy.byteLength, sha256: legacy.sha256 },
        entryCount: successor.doc.entries.length,
        keyId,
        durabilityProfile: ROTATION_DURABILITY_PROFILE,
      };
      const receiptDoc = { body: receiptBody, receiptMac: keyedCanonicalRecord(key, ROTATION_RECEIPT_DOMAIN, receiptBody) };
      const receiptBytes = Buffer.from(`${canonicalJson(receiptDoc)}\n`, "utf8");
      writeConfidentialExclusive(receiptPath, "exclusion rotation receipt", receiptBytes);
      matchingReceipts = [{ path: receiptPath, bytes: receiptBytes, text: receiptBytes.toString("utf8"), doc: receiptDoc, legacyName: false }];
      rotationCheckpoint("receipt-durable");
    }
    const receipt = matchingReceipts[0];
    try { durableSyncExact({ path: receipt.path, expectedBytes: receipt.bytes, mode: KEY_MODE }); } catch (error) {
      custodyFailure("the exclusion rotation receipt could not re-establish durable custody", error, "retain predecessor evidence and retry the same transaction");
    }
    const currentPredecessor = predecessor ?? deleting;
    if (currentPredecessor !== null) {
      validateRotationReceiptDocument(receipt.doc, key, {
        predecessorBytes: currentPredecessor.bytes,
        predecessorDoc: currentPredecessor.doc,
        successorBytes: successor.bytes,
        successorDoc: successor.doc,
        legacy,
        intentRecord,
      });
    } else {
      const receiptEnvelope = validateRotationReceiptEnvelope(receipt.doc, key);
      validateReceiptIntentAuthority(receipt.doc, receiptEnvelope, intentRecord);
      if (!sameEvidence(receipt.doc.body.predecessor, intentRecord.doc.body.predecessor)
          || !sameEvidence(receipt.doc.body.successor, intentRecord.doc.body.successor)) {
        setupFailed("the retained receipt differs from the completed intent", "nothing was deleted", null);
      }
    }
    const receiptReadBack = readConfidentialText(receipt.path, "exclusion rotation receipt", { maxBytes: MAX_CONFIDENTIAL_TEXT_BYTES });
    if (receiptReadBack !== receipt.text) setupFailed("the exclusion rotation receipt changed during durable read-back", "predecessor cleanup was not started", null);
    rotationCheckpoint("receipt-readback");

    artifacts = discoverRotationArtifacts();
    let rawRecords = artifacts.predecessors.map((path) => readNamedPolicy(path, "raw superseded governed exclusion policy", key, legacy, root, {
      verifyControlManifest: false, allowPreviousControlManifest: true,
    }));
    let deletingRecord = artifacts.deleting.length === 1
      ? readNamedPolicy(artifacts.deleting[0], "deterministic deleting exclusion policy", key, legacy, root, { verifyControlManifest: false, allowPreviousControlManifest: true })
      : null;
    if (rawRecords.length > 1) {
      setupFailed("multiple raw predecessors remain after name normalization", "nothing was deleted", null);
    }
    if (rawRecords.length === 1) {
      const raw = rawRecords[0];
      if (!sameEvidence(policyByteEvidence(raw.bytes, raw.doc), predecessorEvidence)) setupFailed("the raw predecessor differs before deletion custody", "nothing was deleted", null);
      const deletingPath = join(KEY_DIR, `exclusions.deleting-v${raw.doc.schemaVersion}-${raw.digest}.json`);
      ensureExactConfidentialFile(deletingPath, "deterministic deleting exclusion policy", raw.bytes);
      deletingRecord = readNamedPolicy(deletingPath, "deterministic deleting exclusion policy", key, legacy, root, { verifyControlManifest: false, allowPreviousControlManifest: true });
      rotationCheckpoint("deleting-durable");
      const receiptBeforeRawRemoval = readConfidentialText(receipt.path, "exclusion rotation receipt", { maxBytes: MAX_CONFIDENTIAL_TEXT_BYTES });
      validateRotationReceiptDocument(parseCanonicalRotationReceipt(receiptBeforeRawRemoval), key, {
        predecessorBytes: raw.bytes,
        predecessorDoc: raw.doc,
        successorBytes: successor.bytes,
        successorDoc: successor.doc,
        legacy,
        intentRecord,
      });
      durableRemoveExact(raw.path, raw.bytes, "raw superseded exclusion policy");
      rotationCheckpoint("predecessor-in-deleting-custody");
    }

    if (deletingRecord !== null) {
      if (!sameEvidence(policyByteEvidence(deletingRecord.bytes, deletingRecord.doc), predecessorEvidence)) {
        setupFailed("the deleting predecessor differs from authenticated intent", "nothing was deleted", null);
      }
      const receiptImmediatelyBeforeDeletion = readConfidentialText(receipt.path, "exclusion rotation receipt", { maxBytes: MAX_CONFIDENTIAL_TEXT_BYTES });
      validateRotationReceiptDocument(parseCanonicalRotationReceipt(receiptImmediatelyBeforeDeletion), key, {
        predecessorBytes: deletingRecord.bytes,
        predecessorDoc: deletingRecord.doc,
        successorBytes: successor.bytes,
        successorDoc: successor.doc,
        legacy,
        intentRecord,
      });
      durableRemoveExact(deletingRecord.path, deletingRecord.bytes, "receipt-bound deleting predecessor");
      rotationCheckpoint("predecessor-deleted");
    }

    const receiptAfterDeletion = readConfidentialText(receipt.path, "exclusion rotation receipt", { maxBytes: MAX_CONFIDENTIAL_TEXT_BYTES });
    const retainedReceipt = validateRotationReceiptEnvelope(parseCanonicalRotationReceipt(receiptAfterDeletion), key);
    if (!equalHex64(retainedReceipt.commitment, receipt.doc.receiptMac)) setupFailed("the retained rotation receipt changed after predecessor deletion", "intent cleanup was not started", null);
    durableRemoveExact(intentRecord.path, intentRecord.bytes, "completed exclusion rotation intent");
    rotationCheckpoint("intent-removed");
  }

  const readBack = recoveryOnly
    ? readAndValidatePolicyAt(
      EXCLUSION_POLICY_FILE,
      "recovery-preserved active governed exclusion policy",
      key,
      legacy,
      root,
      { verifyControlManifest: false, allowPreviousControlManifest: true },
    ).validated
    : loadExclusionPolicy(key);
  if (!equalHex64(readBack.commitment, validated.commitment)
      || (recoveryOnly && !equalBytes(readConfidentialFile(
        EXCLUSION_POLICY_FILE,
        "recovery-preserved active governed exclusion policy",
        { maxBytes: MAX_CONFIDENTIAL_TEXT_BYTES },
      ), existingBytes))) {
    setupFailed("the governed exclusion policy read-back commitment changed", "the create-exclusive file did not validate to the in-memory reviewed document", "stop; do not overwrite or delete the created evidence");
  }
  const legacyAfter = readConfidentialFile(LEGACY_EXCLUDE_TOKENS_FILE, "legacy exclusion inputs", { maxBytes: MAX_CONFIDENTIAL_TEXT_BYTES });
  if (!legacy.bytes.equals(legacyAfter)) {
    setupFailed("the legacy exclusion source changed after migration", "the retained source no longer equals the independently reviewed bytes; the new policy will fail closed", "stop; do not overwrite or delete either evidence file");
  }
  releaseRotationLock(rotationLock.bytes);
  rotationCheckpoint("lock-removed");
  say(green(
    `  ${recoveryOnly ? "recovered historical v2-to-exact-current-v3 transaction for" : opts.rotateExclusions ? "rotated" : "created"} governed exclusion policy schema v3 with ` +
      `${validated.entries.length} reviewed exact entries; retained legacy bytes unchanged` +
      `${opts.rotateExclusions || recoveryOnly ? ", authenticated receipt retained, raw predecessor removed" : ""}.`,
  ));
}

const commitmentPayloadV2 = (doc) => ({
  schemaVersion: doc.schemaVersion,
  note: doc.note,
  alg: doc.alg,
  keyId: doc.keyId,
  refreshedAt: doc.refreshedAt,
  governanceStatus: doc.governanceStatus,
  count: doc.count,
  excludedCount: doc.excludedCount,
  ngramSizes: doc.ngramSizes,
  canaryDigest: doc.canaryDigest,
  extraInputsCommitment: doc.extraInputsCommitment,
  exclusionPolicyCommitment: doc.exclusionPolicyCommitment,
  digests: doc.digests,
});

const commitmentPayloadV3 = (doc) => ({
  ...commitmentPayloadV2(doc),
  privateInputCount: doc.privateInputCount,
  privateInputsCommitment: doc.privateInputsCommitment,
});

const commitmentPayload = (doc) => doc.schemaVersion === PREVIOUS_COMMITMENT_SCHEMA_VERSION
  ? commitmentPayloadV2(doc)
  : commitmentPayloadV3(doc);

function validateCommitmentDocument(doc, { allowPrevious = false, requireFresh = true } = {}) {
  const version = doc?.schemaVersion;
  if (version !== COMMITMENT_SCHEMA_VERSION && !(allowPrevious && version === PREVIOUS_COMMITMENT_SCHEMA_VERSION)) {
    setupFailed(
      "the token commitments schema is unsupported",
      `expected authenticated schema v${COMMITMENT_SCHEMA_VERSION}${allowPrevious ? ` or predecessor v${PREVIOUS_COMMITMENT_SCHEMA_VERSION}` : ""}`,
      "run the reviewed live refresh path without weakening the authenticated predecessor check",
    );
  }
  const fields = [
    "schemaVersion", "note", "alg", "keyId", "refreshedAt", "governanceStatus", "count",
    "excludedCount", "ngramSizes", "canaryDigest", "extraInputsCommitment",
    "exclusionPolicyCommitment", "digests", "commitmentMac",
  ];
  if (version === COMMITMENT_SCHEMA_VERSION) fields.splice(fields.length - 3, 0, "privateInputCount", "privateInputsCommitment");
  exactObjectKeys(doc, fields, "the token commitments file");
  if (doc.alg !== "HMAC-SHA256" || !HEX_64_RE.test(String(doc.keyId))) {
    setupFailed("the token commitments header is invalid", "HMAC-SHA256 and a full 64-hex keyId are mandatory", "run the reviewed refresh path");
  }
  if (!Array.isArray(doc.digests) || doc.digests.length === 0 || doc.count !== doc.digests.length
      || doc.digests.some((digest) => !HEX_64_RE.test(String(digest)))
      || new Set(doc.digests).size !== doc.digests.length
      || doc.digests.some((digest, index) => index > 0 && compareText(doc.digests[index - 1], digest) >= 0)) {
    setupFailed("token tier unmeasured — the commitments are malformed, duplicated, unsorted, or empty", "every digest must be one unique sorted lowercase SHA-256 HMAC and count must match exactly", "run the reviewed refresh path");
  }
  if (!Number.isInteger(doc.excludedCount) || doc.excludedCount < 0
      || !Array.isArray(doc.ngramSizes) || doc.ngramSizes.length === 0
      || doc.ngramSizes.some((size) => !Number.isInteger(size) || size < 1 || size > 6)
      || new Set(doc.ngramSizes).size !== doc.ngramSizes.length
      || doc.ngramSizes.some((size, index) => index > 0 && doc.ngramSizes[index - 1] >= size)) {
    setupFailed("the token commitments metadata is malformed", "excludedCount and the unique sorted 1..6 ngramSizes must be exact", "run the reviewed refresh path");
  }
  if (!HEX_64_RE.test(String(doc.canaryDigest)) || !doc.digests.includes(doc.canaryDigest)) {
    setupFailed("the synthetic canary is not bound into the commitment set", "canaryDigest must be one exact member of digests", "rotate the canary only through the reviewed refresh path");
  }
  if (doc.governanceStatus !== "AUTHENTICATED") {
    setupFailed("the token commitments governance status is not authenticated", "only AUTHENTICATED documents may be loaded or used as a monotonic predecessor", null);
  }
  if (!HEX_64_RE.test(String(doc.extraInputsCommitment)) || !HEX_64_RE.test(String(doc.exclusionPolicyCommitment))) {
    setupFailed("the token commitments omit authenticated input bindings", "extra inputs and governed exclusions require full HMAC commitments", "run the reviewed refresh path");
  }
  if (version === COMMITMENT_SCHEMA_VERSION
      && (!Number.isInteger(doc.privateInputCount) || doc.privateInputCount <= 0
        || !HEX_64_RE.test(String(doc.privateInputsCommitment)))) {
    setupFailed(
      "the token commitments omit the current PRIVATE-input binding",
      "schema v3 requires a positive normalized input count and full keyed commitment",
      "run the reviewed live refresh path",
    );
  }
  if (!HEX_64_RE.test(String(doc.commitmentMac))) setupFailed("the token commitments have no full authentication code", "commitmentMac must be a 64-hex HMAC", "run the reviewed refresh path");
  if (requireFresh) assertFresh("the token commitments", doc.refreshedAt, "run the reviewed refresh path");
  else boundedTimestamp("the token commitments.refreshedAt", doc.refreshedAt, "restore the exact authenticated predecessor timestamp");
  return version;
}

function authenticateCommitmentDocument(doc, key, options = {}) {
  const version = validateCommitmentDocument(doc, options);
  const keyId = createHash("sha256").update(key).digest("hex");
  if (!equalHex64(doc.keyId, keyId)) {
    setupFailed(
      "the boundary key does not match the committed digests",
      "the full SHA-256 keyId differs; prefix compatibility and implicit rotation are forbidden",
      "restore the exact external key; do not rewrite commitments around an unknown key",
    );
  }
  const expectedMac = keyedRecord(key, `commitments/v${version}`, commitmentPayload(doc));
  if (!equalHex64(doc.commitmentMac, expectedMac)) {
    setupFailed(
      "the token commitments authentication failed",
      "the HMAC does not bind this exact full-schema digest set and metadata; shrink or substitution is refused",
      "restore the reviewed committed document, then use the reviewed refresh path",
    );
  }
  return { version, keyId };
}

/**
 * Tier B. Missing key, missing commitments, a zero count, or a key that does not match the committed
 * keyId are ALL exit 2. A silent Tier-A-only pass would be the exact failure this gate was built
 * after: a green printed over an unmeasured class.
 */
function loadTierB(tier, visibility) {
  if (tier === "a") {
    if (visibility.evidence === "LIVE_PROVIDER_VERIFIED") {
      setupFailed(
        "live visibility was requested with Tier B disabled",
        "a live/release claim must authenticate and compare the current PRIVATE-input set; --tier a cannot do that",
        "use --tier ab for live evidence, or snapshot for the explicitly unmeasured local shape-only lane",
      );
    }
    return { enabled: false, reason: "TIER-B UNMEASURED — explicitly requested with --tier a" };
  }
  const doc = readJson(COMMITMENTS_PATH, "the token commitments file");
  const key = readBoundaryKey();
  const { keyId } = authenticateCommitmentDocument(doc, key);

  if (visibility.evidence === "LIVE_PROVIDER_VERIFIED") {
    if (!Array.isArray(visibility.privateForms) || visibility.privateForms.length === 0) {
      setupFailed("live PRIVATE inputs were not measured", "provider evidence returned no normalized private-input set", "stop the live/release lane");
    }
    const measuredPrivateInputsCommitment = keyedRecord(key, "private-inputs/v1", visibility.privateForms);
    if (doc.privateInputCount !== visibility.privateForms.length
        || !equalHex64(doc.privateInputsCommitment, measuredPrivateInputsCommitment)) {
      setupFailed(
        "live PRIVATE inputs differ from the authenticated commitment",
        "a visibility downgrade, new private repository, deletion, rename, or normalization change occurred; names are deliberately omitted",
        "review live provider state and run the coupled authenticated refresh before release",
      );
    }
  }

  const canary = canaryFromCustody();
  const canaryForms = tokenForms(canary);
  const measuredCanaryDigest = canaryForms.length === 1 ? commitToken(key, canaryForms[0]) : "";
  if (!equalHex64(doc.canaryDigest, measuredCanaryDigest)) {
    setupFailed("the boundary canary does not match its committed digest", "the exact synthetic canary file is not bound to canaryDigest", "restore the reviewed canary or refresh through the authenticated path");
  }
  const extra = loadExtraInputs(key);
  if (!equalHex64(doc.extraInputsCommitment, extra.commitment)) {
    setupFailed("the extra token inputs do not match their commitment", "the securely-read external inputs changed after the committed digest set was derived", "review the change and run the authenticated refresh path");
  }
  const exclusions = loadExclusionPolicy(key);
  if (!equalHex64(doc.exclusionPolicyCommitment, exclusions.commitment) || doc.excludedCount !== exclusions.entries.length) {
    setupFailed("the governed exclusions do not match the token commitments", "the authenticated policy binding or exact exclusion count differs", "restore the reviewed policy and refresh commitments");
  }
  const set = new Set(doc.digests);
  const ngramSizes = Array.isArray(doc.ngramSizes) && doc.ngramSizes.length > 0 ? doc.ngramSizes : [1];
  const memo = new Map();
  const lookup = (candidate) => {
    let hit = memo.get(candidate);
    if (hit === undefined) {
      hit = set.has(commitToken(key, candidate));
      memo.set(candidate, hit);
    }
    return hit;
  };
  return {
    enabled: true,
    lookup,
    ngramSizes,
    count: doc.count,
    keyId,
    canaryDigest: doc.canaryDigest,
    privateInputsEvidence: visibility.evidence === "LIVE_PROVIDER_VERIFIED" ? "LIVE_COMMITMENT_MATCH" : "SNAPSHOT_NON_CLAIM",
  };
}

function loadKnownExposure() {
  if (!existsSync(KNOWN_EXPOSURE_PATH)) {
    setupFailed("the known-exposure ledger is missing", `expected document ${opaquePathId(relative(ROOT, KNOWN_EXPOSURE_PATH))}`, "restore it from version control — an absent ledger is not an empty ledger");
  }
  const doc = readJson(KNOWN_EXPOSURE_PATH, "the known-exposure ledger");
  if (!Array.isArray(doc.entries)) setupFailed("the known-exposure ledger has no entries array", "a ledger that cannot be read cannot be ratcheted", null);
  const byKey = new Map();
  for (const [i, e] of doc.entries.entries()) {
    for (const field of ["key", "why", "remediation", "reviewedAt"]) {
      if (typeof e[field] !== "string" || e[field].trim().length === 0) {
        setupFailed(
          `known-exposure entry ${i} is missing ${field}`,
          "every carried exposure states WHY it is carried and WHAT closes it. An entry without both is an allowlist wearing a ledger's clothes.",
          "edit the reviewed known-exposure document",
        );
      }
    }
    if (!Number.isInteger(e.count) || e.count < 1) {
      setupFailed(`known-exposure entry ${i} has a non-positive count`, "the rejected count is withheld because the document is untrusted", "edit the reviewed known-exposure document");
    }
    if (byKey.has(e.key)) setupFailed(`known-exposure entry ${i} duplicates an existing key`, "the key is withheld because the document is untrusted; two entries for one key make the ratchet ambiguous", null);
    byKey.set(e.key, e);
  }
  return { doc, byKey };
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// Lane enumerators. Each returns { units, status, note }. `units` are { path, text }.
// ─────────────────────────────────────────────────────────────────────────────────────────────────

/** Read bytes without letting a NUL inside valid UTF-8 source corrupt its parser input. Recognized
 *  JavaScript/TypeScript source keeps every decoded character, including U+0000 and exact source
 *  positions. Invalid UTF-8 and true binary inputs retain the bounded printable-run detector path
 *  and are marked non-structured so extracted fragments never enter an AST/JSON parser. */
function printableText(buf) {
  const printable = [];
  let run = [];
  for (const b of buf) {
    if (b === 9 || b === 10 || b === 13 || (b >= 32 && b < 127)) run.push(b);
    else {
      if (run.length >= 4) printable.push(Buffer.from(run).toString("latin1"));
      run = [];
    }
  }
  if (run.length >= 4) printable.push(Buffer.from(run).toString("latin1"));
  return printable.join("\n");
}

const STRICT_UTF8_DECODER = new TextDecoder("utf-8", { fatal: true });

function toText(buf, sourcePath) {
  let text;
  try { text = STRICT_UTF8_DECODER.decode(buf); }
  catch { return { structuredSource: false, text: printableText(buf) }; }
  if (buf.includes(0) && !isBoundaryStaticSourcePath(sourcePath)) {
    return { structuredSource: false, text: printableText(buf) };
  }
  return { structuredSource: true, text };
}

function readUnit(root, relPath, unscanned, meta = {}) {
  const label = meta.label ?? opaqueValueId("file", relPath);
  const scopePath = meta.scopePath ?? relPath;
  const pathText = meta.pathText ?? scopePath;
  const pathIdentity = meta.pathIdentity ?? scopePath;
  canonicalSurfacePath(relPath, "the file reader");
  canonicalSurfacePath(scopePath, "the file enumerator");
  try {
    const fullPath = join(root, relPath);
    const bytes = meta.readPublishedSymlink === true && lstatSync(fullPath).isSymbolicLink()
      ? readlinkSync(fullPath, { encoding: "buffer" })
      : readFileSync(fullPath);
    const decoded = toText(bytes, scopePath);
    return fileUnit(label, decoded.text, {
      scopePath,
      pathText,
      pathIdentity,
      structuredSource: decoded.structuredSource,
    });
  } catch (e) {
    unscanned.push(`${opaquePathId(pathIdentity)}: ${e?.code ?? "I/O error"}`);
    return null;
  }
}

function laneWT(ctx) {
  const tracked = nulList(capture("git", ["ls-files", "-z"], { cwd: ctx.root }).out);
  const untracked = nulList(capture("git", ["ls-files", "-z", "--others", "--exclude-standard"], { cwd: ctx.root }).out);
  const paths = [...new Set([...tracked, ...untracked])].sort();
  const units = [];
  for (const p of paths) {
    const u = readUnit(ctx.root, p, ctx.unscanned, { readPublishedSymlink: true });
    if (u !== null) units.push(u);
  }
  return { units, note: `${tracked.length} tracked + ${untracked.length} untracked` };
}

function laneIDX(ctx) {
  const paths = nulList(capture("git", ["diff", "--cached", "--name-only", "-z", "--diff-filter=ACMR"], { cwd: ctx.root }).out);
  if (paths.length === 0) return { units: [], status: "skipped", note: "nothing staged" };
  const units = [];
  for (const p of paths) {
    canonicalSurfacePath(p, "git index");
    // FROM THE INDEX, not from disk. A secret staged and then reverted on disk is still going out.
    const r = capture("git", ["show", `:${p}`], { cwd: ctx.root, encoding: "buffer", tolerate: true });
    if (r.code !== 0) { ctx.unscanned.push(`${opaquePathId(p)}: not readable from the index`); continue; }
    const decoded = toText(r.out, p);
    units.push(fileUnit(opaqueValueId("index", p), decoded.text, {
      scopePath: p,
      pathText: p,
      pathIdentity: p,
      structuredSource: decoded.structuredSource,
    }));
  }
  return { units, note: `${paths.length} staged path(s), read from the index` };
}

/**
 * How much history a range covers. ONE place decides this for all three git lanes, so there is
 * exactly one place a knockout can prove it reads the WHOLE range rather than the tip. A tip-only
 * reading can score multi-commit history as one commit and allow earlier boundary-relevant commit
 * messages in the range to escape inspection.
 */
const zeroObjectId = (value) => /^0+$/.test(value);
const privatePathLabel = (kind, value) => `${kind}:${contentKey(String(value)).slice(0, 16)}`;

function objectIdLength(root) {
  const format = capture("git", ["rev-parse", "--show-object-format"], { cwd: root }).out.trim();
  if (format === "sha1") return 40;
  if (format === "sha256") return 64;
  setupFailed("git reported an unsupported object format", "only exact sha1 and sha256 object IDs are understood", null);
  return 0;
}

function validObjectId(value, length, { allowZero = false } = {}) {
  return new RegExp(`^[0-9a-f]{${length}}$`).test(value) && (allowZero || !zeroObjectId(value));
}

function exactGitRef(root, ref, what) {
  const r = spawnSync("git", ["check-ref-format", ref], {
    cwd: root, encoding: "utf8", shell: false, env: gitProcessEnvironment(),
  });
  if (r.status !== 0) setupFailed(`${what} is not an exact git ref`, "the malformed value is deliberately omitted from diagnostics", null);
}

const PRE_PUSH_LOCAL_SELECTOR_MAX_BYTES = 4096;

/**
 * Git's pre-push protocol does not promise that the local field is a full ref. A named branch is
 * expanded to `refs/heads/...`, while selectors such as `HEAD`, `HEAD~`, or a literal object name
 * are passed through exactly as supplied. Treating this field as a ref rejects valid Git output;
 * treating it as authority without resolving it would let the display name disagree with the exact
 * object set. Keep it inert, bounded data, resolve it behind an option boundary, and bind the result
 * byte-for-byte to the separately validated local object ID supplied by Git.
 */
function verifyPrePushLocalSelector(ctx, selector, localSha) {
  const byteLength = Buffer.byteLength(selector, "utf8");
  if (byteLength === 0 || byteLength > PRE_PUSH_LOCAL_SELECTOR_MAX_BYTES
      || selector.startsWith("-") || /\s/u.test(selector)
      || /[\u0000-\u001f\u007f]/u.test(selector) || selector.includes("\ufffd")) {
    setupFailed(
      "a pre-push local selector is malformed",
      "the rejected selector is omitted; it must be bounded, control-free, non-option data",
      null,
    );
  }
  const resolved = spawnSync(
    "git",
    ["rev-parse", "--verify", "--end-of-options", `${selector}^{object}`],
    { cwd: ctx.root, encoding: "utf8", shell: false, env: gitProcessEnvironment() },
  );
  if (resolved.status !== 0) {
    setupFailed(
      "a pre-push local selector cannot be resolved",
      "the selector is omitted; Git must resolve it to the exact local object supplied by the hook",
      null,
    );
  }
  const match = new RegExp(`^([0-9a-f]{${ctx.objectIdLength}})\\n$`).exec(String(resolved.stdout ?? ""));
  if (match === null) {
    setupFailed("git returned a malformed local-selector object ID", "the pre-push object binding is unavailable", null);
  }
  if (match[1] !== localSha) {
    setupFailed(
      "a pre-push local selector does not resolve to its supplied object ID",
      "the hook's selector and exact object identity disagree",
      null,
    );
  }
}

function verifyPrePushDestination(ctx) {
  if (ctx.prePushDestinationVerified) return;
  const { prePushRemote, prePushRemoteGitDir, prePushUrl } = ctx.opts;
  if (prePushRemoteGitDir !== null) {
    const observed = spawnSync(
      "git",
      ["--git-dir", prePushRemoteGitDir, "remote", "get-url", "--push", "--all", prePushRemote],
      { cwd: ctx.root, encoding: "utf8", shell: false, env: gitProcessEnvironment() },
    );
    const urls = observed.status === 0
      ? String(observed.stdout ?? "").split(/\r?\n/).filter(Boolean)
      : [];
    if (observed.status !== 0 || urls.length !== 1 || urls[0] !== prePushUrl
        || URL_USERINFO_RE.test(prePushUrl)) {
      setupFailed(
        "the isolated pre-push destination binding does not match its sanitized coordinate",
        "local config plumbing must return exactly one credential-free coordinate; values are omitted",
        "invoke the committed pre-push hook",
      );
    }
    ctx.prePushDestinationVerified = true;
    return;
  }
  const configured = spawnSync(
    "git", ["remote", "get-url", "--push", "--all", prePushRemote],
    { cwd: ctx.root, encoding: "utf8", shell: false, env: gitProcessEnvironment() },
  );
  if (configured.status === 0) {
    const urls = String(configured.stdout ?? "").split(/\r?\n/).filter(Boolean);
    if (urls.length === 0 || (prePushUrl !== null && !urls.includes(prePushUrl))) {
      setupFailed(
        "the pre-push remote name and destination do not agree",
        "the hook argv do not bind to the same configured push destination; values are omitted to avoid credential disclosure",
        "invoke the committed hook through git instead of constructing ref input manually",
      );
    }
  } else if (prePushUrl === null || prePushRemote !== prePushUrl) {
    setupFailed(
      "the pre-push destination cannot be bound to its remote argument",
      "the remote name is not configured and is not the exact destination supplied by git",
      "invoke the committed hook through git",
    );
  }
  ctx.prePushDestinationVerified = true;
}

function destinationRefs(ctx) {
  if (ctx.destinationRefs !== null) return ctx.destinationRefs;
  verifyPrePushDestination(ctx);
  // The destination may contain credentials. Keep this invocation local and expose only structural
  // status; neither destination argv nor stderr may enter terminal or machine evidence.
  const destinationArgs = ctx.opts.prePushRemoteGitDir === null
    ? ["ls-remote", "--refs", ctx.opts.prePushUrl ?? ctx.opts.prePushRemote]
    : ["--git-dir", ctx.opts.prePushRemoteGitDir, "ls-remote", "--refs", ctx.opts.prePushRemote];
  const r = spawnSync(
    "git", destinationArgs,
    {
      cwd: ctx.root, encoding: "utf8", shell: false, maxBuffer: 256 * 1024 * 1024,
      timeout: PROVIDER_QUERY_TIMEOUT_MS, env: gitProcessEnvironment(),
    },
  );
  if (r.error || r.status !== 0) {
    setupFailed(
      "the destination refs could not be enumerated",
      `git ls-remote failed with exit ${r.status ?? "unknown"}; destination and stderr are omitted because they may contain credentials`,
      "repair remote connectivity/authentication and retry the same push",
    );
  }
  const byRef = new Map();
  for (const [index, line] of String(r.stdout ?? "").split(/\r?\n/).filter(Boolean).entries()) {
    const match = /^([0-9a-f]+)\t([^\s]+)$/.exec(line);
    if (match === null || !validObjectId(match[1], ctx.objectIdLength)) {
      setupFailed("the destination ref enumeration is malformed", `entry ${index} is not an exact object-id/ref pair`, null);
    }
    exactGitRef(ctx.root, match[2], "a destination ref");
    if (byRef.has(match[2])) setupFailed("the destination ref enumeration contains a duplicate", "a destination ref appeared more than once", null);
    byRef.set(match[2], match[1]);
  }
  ctx.destinationRefs = byRef;
  return byRef;
}

/** Resolve the exact object sets this run is responsible for. */
function resolveRanges(ctx) {
  if (ctx.opts.range !== null) {
    if (ctx.opts.range.length === 0 || ctx.opts.range !== ctx.opts.range.trim()) {
      setupFailed("the literal git range is malformed", "--range must be one nonempty trimmed revision expression", null);
    }
    return [{ mode: "range", localRef: "HEAD", remoteRef: null, range: ctx.opts.range }];
  }
  if (!ctx.opts.refsFromStdin) return [];
  if (ctx.stdin.trim().length === 0) {
    setupFailed("pre-push ref input is empty", "the hook supplied no ref lines, so no pushed object set can be proven", "retry through git with the committed pre-push hook");
  }

  const length = ctx.objectIdLength;
  const ranges = [];
  const destinations = new Set();
  const lines = ctx.stdin.split(/\r?\n/);
  if (lines.at(-1) === "") lines.pop(); // the hook's conventional final newline, and only that
  if (lines.some((line) => line.length === 0)) {
    setupFailed("pre-push ref input contains an empty record", "blank records inside the hook stream are malformed, not ignorable", null);
  }
  ctx.refLineCount = lines.length;
  for (const [index, line] of lines.entries()) {
    if (line !== line.trim()) setupFailed("a pre-push ref line has surrounding whitespace", `line ${index + 1} is not canonical`, null);
    const parts = line.split(/\s+/);
    if (parts.length !== 4) setupFailed("a pre-push ref line is malformed", `line ${index + 1} must contain exactly four fields`, null);
    const [localRef, localSha, remoteRef, remoteSha] = parts;
    if (!validObjectId(localSha, length, { allowZero: true }) || !validObjectId(remoteSha, length, { allowZero: true })) {
      setupFailed("a pre-push ref line has a malformed object ID", `line ${index + 1} must use full lowercase ${length}-hex object IDs`, null);
    }
    exactGitRef(ctx.root, remoteRef, "a pre-push remote ref");
    if (destinations.has(remoteRef)) setupFailed("pre-push input updates one destination ref more than once", `duplicate at line ${index + 1}`, null);
    destinations.add(remoteRef);
    if (zeroObjectId(localSha)) {
      if (localRef !== "(delete)") {
        setupFailed(
          "a pre-push deletion does not use the exact deletion marker",
          "an all-zero local object ID is valid only with Git's exact (delete) local selector",
          null,
        );
      }
      continue; // explicit deletion: no new bytes leave the machine
    }
    if (localRef === "(delete)") {
      setupFailed(
        "a pre-push non-deletion uses the deletion marker",
        "Git's exact (delete) selector is valid only with an all-zero local object ID",
        null,
      );
    }
    verifyPrePushLocalSelector(ctx, localRef, localSha);
    const exists = spawnSync("git", ["cat-file", "-e", `${localSha}^{object}`], {
      cwd: ctx.root, encoding: "utf8", shell: false, env: gitProcessEnvironment(),
    });
    if (exists.status !== 0) setupFailed("a pushed local object is unavailable", `line ${index + 1} names an object this repository cannot read`, null);
    ranges.push({ mode: "push", localRef, localSha, remoteRef, remoteSha });
  }
  return ranges;
}

function commitsFor(ctx, descriptor) {
  const cacheKey = descriptor.mode === "range"
    ? `range:${descriptor.range}`
    : `push:${descriptor.localSha}:${descriptor.remoteRef}:${descriptor.remoteSha}`;
  const cached = ctx.commitSets.get(cacheKey);
  if (cached !== undefined) return cached;

  let args;
  if (descriptor.mode === "range") {
    args = ["rev-list", descriptor.range];
  } else {
    // A clean-history publication deliberately has no copy of the destination's old object graph.
    // `rev-list --not <missing-tip>` aborts before scanning anything. Exclude only tips whose commit
    // ancestry this local object store can actually prove; omitting an unavailable/non-commit tip
    // can only BROADEN the set scanned, never hide an outgoing commit.
    const candidateExclusions = !zeroObjectId(descriptor.remoteSha)
      ? [descriptor.remoteSha]
      : [...destinationRefs(ctx).entries()]
        .filter(([ref]) => ref !== descriptor.remoteRef)
        .map(([, sha]) => sha);
    const exclusions = [...new Set(candidateExclusions)].filter((sha) =>
      capture("git", ["cat-file", "-e", `${sha}^{commit}`], { cwd: ctx.root, tolerate: true }).code === 0);
    args = ["rev-list", descriptor.localSha, ...(exclusions.length > 0 ? ["--not", ...exclusions] : [])];
  }
  const shas = capture("git", args, { cwd: ctx.root }).out.trim().split("\n").filter(Boolean);
  if (shas.some((sha) => !validObjectId(sha, ctx.objectIdLength))) {
    setupFailed("git rev-list returned a malformed commit ID", "the pushed commit set cannot be trusted", null);
  }
  const distinct = [...new Set(shas)];
  ctx.commitSets.set(cacheKey, distinct);
  return distinct;
}

function laneCommits(ctx) {
  if (ctx.ranges.length === 0) {
    if (ctx.opts.refsFromStdin && ctx.refLineCount > 0) return { units: [], status: "empty-ok", note: "the push contains deletions only; no commit messages leave the machine" };
    return { units: [], status: "skipped", note: "no push refs or --range supplied" };
  }
  const units = [];
  let commits = 0;
  for (const descriptor of ctx.ranges) {
    for (const ref of [descriptor.localRef, descriptor.remoteRef].filter(Boolean)) {
      units.push({ path: privatePathLabel("ref-name", ref), text: ref });
    }
    const shas = commitsFor(ctx, descriptor);
    commits += shas.length;
    for (const sha of shas) {
      const body = capture("git", ["log", "-1", "--format=%B%x00", sha], { cwd: ctx.root }).out.replace(/\0$/, "");
      units.push({ path: `commit:${sha.slice(0, 12)}:message`, text: body });
    }
  }
  return { units, note: `${ctx.ranges.length} ref(s), ${commits} commit(s) — the FULL range, not the tip` };
}

function laneBlobs(ctx) {
  if (ctx.ranges.length === 0) {
    if (ctx.opts.refsFromStdin && ctx.refLineCount > 0) return { units: [], status: "empty-ok", note: "the push contains deletions only; no blobs leave the machine" };
    return { units: [], status: "skipped", note: "no push refs or --range supplied" };
  }
  const units = [];
  const versions = new Set();
  for (const descriptor of ctx.ranges) {
    for (const sha of commitsFor(ctx, descriptor)) {
      const names = capture(
        "git", ["diff-tree", "--root", "-m", "-r", "--no-commit-id", "--name-only", "-z", "--diff-filter=AM", sha],
        { cwd: ctx.root },
      ).out;
      for (const p of nulList(names)) {
        canonicalSurfacePath(p, "git diff-tree");
        const version = `${sha}:${p}`;
        if (versions.has(version)) continue;
        versions.add(version);
        const r = capture("git", ["show", `${sha}:${p}`], { cwd: ctx.root, encoding: "buffer", tolerate: true });
        if (r.code !== 0) {
          ctx.unscanned.push(`${opaquePathId(p)}: not readable from ${opaqueValueId("commit", sha)}`);
          continue;
        }
        const decoded = toText(r.out, p);
        units.push(fileUnit(privatePathLabel(`push-blob:${sha.slice(0, 12)}`, p), decoded.text, {
          scopePath: p,
          pathText: p,
          pathIdentity: p,
          structuredSource: decoded.structuredSource,
        }));
      }
    }
  }
  if (units.length === 0) return { units: [], status: "empty-ok", note: "the push set adds or modifies no blobs" };
  return { units, note: `${versions.size} path version(s) about to leave the machine; every historical version was read` };
}

function laneTags(ctx) {
  if (ctx.ranges.length === 0) {
    if (ctx.opts.refsFromStdin && ctx.refLineCount > 0) return { units: [], status: "empty-ok", note: "the push contains deletions only; no tag bytes leave the machine" };
    return { units: [], status: "skipped", note: "no push refs or --range supplied" };
  }
  const units = [];
  const seen = new Set();
  const addName = (name, kind = "tag-name") => {
    const key = `${kind}:${name}`;
    if (seen.has(key)) return;
    seen.add(key);
    units.push({ path: privatePathLabel(kind, name), text: name });
  };
  const addTagObjects = (startSha) => {
    let sha = startSha;
    const objects = new Set();
    for (let depth = 0; depth < 32; depth++) {
      if (objects.has(sha)) setupFailed("an annotated-tag object cycle was encountered", "the tag chain cannot be interpreted safely", null);
      objects.add(sha);
      const type = capture("git", ["cat-file", "-t", sha], { cwd: ctx.root }).out.trim();
      if (type === "commit") return;
      if (type !== "tag") {
        setupFailed(
          "a pushed tag terminates at a non-commit object",
          "tag targets must resolve to a commit; blob and tree targets are refused because commit-history lanes cannot enumerate them",
          null,
        );
      }
      const raw = capture("git", ["cat-file", "tag", sha], { cwd: ctx.root }).out;
      units.push({ path: `tag-object:${sha.slice(0, 16)}`, text: raw });
      const target = /^object ([0-9a-f]+)$/m.exec(raw)?.[1] ?? "";
      if (!validObjectId(target, ctx.objectIdLength)) setupFailed("an annotated-tag object has no exact target", "the tag object cannot be traversed safely", null);
      sha = target;
    }
    setupFailed("an annotated-tag chain exceeds the safety bound", "more than 32 nested tag objects were encountered", null);
  };

  for (const descriptor of ctx.ranges) {
    if (descriptor.mode === "push") {
      if (descriptor.localRef.startsWith("refs/tags/")) addName(descriptor.localRef.slice("refs/tags/".length), "local-tag-name");
      if (descriptor.remoteRef.startsWith("refs/tags/")) addName(descriptor.remoteRef.slice("refs/tags/".length), "remote-tag-name");
      if (descriptor.localRef.startsWith("refs/tags/") || descriptor.remoteRef.startsWith("refs/tags/")) addTagObjects(descriptor.localSha);
      continue;
    }
    for (const sha of commitsFor(ctx, descriptor)) {
      for (const name of capture("git", ["tag", "--points-at", sha], { cwd: ctx.root }).out.trim().split("\n").filter(Boolean)) {
        addName(name);
        const exactTagRef = `refs/tags/${name}`;
        const objectSha = capture("git", ["rev-parse", `${exactTagRef}^{object}`], { cwd: ctx.root }).out.trim();
        addTagObjects(objectSha);
      }
    }
  }
  if (units.length === 0) return { units: [], status: "empty-ok", note: "no tags in the push set" };
  return { units, note: `${seen.size} exact tag identity unit(s), including every annotated tag object` };
}

/** The publishable workspaces, DERIVED from the manifests — the same reasoning the workflow uses,
 *  and for the same reason: a hand-written list is how this class of check rots. */
function publishableDirs(root) {
  const dirs = ["."];
  const pkgRoot = join(root, "packages");
  if (!existsSync(pkgRoot)) return dirs;
  for (const name of nulList(capture(
    "git",
    ["ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", "packages/*/package.json"],
    { cwd: root },
  ).out)) {
    try {
      const m = JSON.parse(stableControlBytes(root, name).toString("utf8"));
      if (m.private !== true && typeof m.name === "string") dirs.push(dirname(name));
    } catch (error) {
      setupFailed(
        `publishable package manifest ${opaquePathId(name)} cannot be derived safely`,
        "the parser or stable-read detail is withheld because the manifest and path are untrusted",
        "repair the manifest; an unreadable package cannot be treated as absent",
      );
    }
  }
  return [...new Set(dirs)].sort(compareText);
}

const PACK_SNAPSHOT_MAX_FILES = 50_000;
const PACK_SNAPSHOT_MAX_BYTES = 512 * 1024 * 1024;
const PACKAGE_FILES_PATTERN_RE = /[*?[\]{}!]/u;

function canonicalSnapshotPath(path, what) {
  try { validateRepositoryPath(path); } catch {
    setupFailed(`${what} is not a canonical repository path`, `${opaquePathId(path)} was rejected; parser detail is withheld`, "use one relative UTF-8 path with no traversal");
  }
  return path;
}

function relativePackagePath(value, what) {
  const path = canonicalSnapshotPath(value, what);
  if (PACKAGE_FILES_PATTERN_RE.test(path)) {
    setupFailed(
      `${what} uses a glob or negation`,
      "the boundary snapshot accepts explicit manifest paths only, so its superset cannot silently omit a match",
      "replace the pattern with explicit files/directories or extend this fail-closed derivation with its own arm",
    );
  }
  return path;
}

function inspectSnapshotSource(root, relPath, what, { optional = false } = {}) {
  canonicalSnapshotPath(relPath, what);
  const absolute = join(root, ...relPath.split("/"));
  const escaped = relative(root, resolve(absolute));
  if (escaped === ".." || escaped.startsWith(`..${sep}`)) {
    setupFailed(`${what} escaped the repository`, opaquePathId(relPath), null);
  }
  try { return lstatSync(absolute); } catch (error) {
    if (optional && error?.code === "ENOENT") return null;
    setupFailed(`${what} cannot be inspected`, `${opaquePathId(relPath)}: ${error?.code ?? "I/O error"}`, "stop concurrent writers and retry");
  }
  return null;
}

function addSnapshotTree(root, relPath, paths, what, { optional = false } = {}) {
  const stat = inspectSnapshotSource(root, relPath, what, { optional });
  if (stat === null) return false;
  if (stat.isSymbolicLink()) {
    setupFailed(`${what} is a symbolic link`, `${opaquePathId(relPath)} cannot enter a publish snapshot by indirection`, "replace it with reviewed regular bytes");
  }
  if (stat.isFile()) {
    paths.add(relPath);
    if (paths.size > PACK_SNAPSHOT_MAX_FILES) {
      setupFailed("the publish snapshot exceeds its file-count bound", `more than ${PACK_SNAPSHOT_MAX_FILES} files`, "remove generated debris or narrow the manifest explicitly");
    }
    return true;
  }
  if (!stat.isDirectory()) {
    setupFailed(`${what} is a special filesystem object`, opaquePathId(relPath), "publishable input must be regular files and directories only");
  }
  const absolute = join(root, ...relPath.split("/"));
  for (const name of readdirSync(absolute).sort(compareText)) {
    if (name === ".git" || name === "node_modules") continue;
    addSnapshotTree(root, `${relPath}/${name}`, paths, what);
  }
  return true;
}

function stablePackageManifest(root, dir) {
  const relPath = dir === "." ? "package.json" : `${dir}/package.json`;
  let manifest;
  try { manifest = JSON.parse(stableControlBytes(root, relPath).toString("utf8")); } catch {
    setupFailed(`package manifest ${opaquePathId(relPath)} is not stable JSON`, "parser and path detail are withheld because the manifest is untrusted", "repair it before deriving publish bytes");
  }
  if (!Array.isArray(manifest.files) || manifest.files.length === 0
      || manifest.files.some((entry) => typeof entry !== "string")) {
    setupFailed(
      `package manifest ${opaquePathId(relPath)} has no explicit files inventory`,
      "a boundary snapshot may not guess an unbounded package surface",
      "declare a nonempty files array with explicit relative paths",
    );
  }
  return { manifest, relPath };
}

function packageScopedPath(dir, path) {
  return dir === "." ? path : `${dir}/${path}`;
}

function derivePackSnapshotPaths(root, dirs) {
  const paths = new Set();
  const gitPaths = nulList(capture(
    "git",
    ["ls-files", "-z", "--cached", "--others", "--exclude-standard"],
    { cwd: root },
  ).out);
  for (const path of gitPaths) {
    addSnapshotTree(root, path, paths, "a Git-enumerated snapshot input", { optional: true });
  }

  for (const dir of dirs) {
    const { manifest, relPath } = stablePackageManifest(root, dir);
    addSnapshotTree(root, relPath, paths, "a package manifest");
    for (const [index, entry] of manifest.files.entries()) {
      const path = relativePackagePath(entry, `package files[${index}]`);
      // npm-packlist treats a declared-but-absent path as absent. The snapshot mirrors that scope;
      // package-completeness policy belongs to the artifact verifier, while this lane scans every
      // byte that actually enters the tarball. A file appearing between the two censuses changes the
      // derived path set and is refused below.
      addSnapshotTree(
        root,
        packageScopedPath(dir, path),
        paths,
        `package files[${index}]`,
        { optional: true },
      );
    }

    const scalarEntrypoints = [manifest.main, manifest.module, manifest.types, manifest.typings];
    if (typeof manifest.browser === "string") scalarEntrypoints.push(manifest.browser);
    if (typeof manifest.bin === "string") scalarEntrypoints.push(manifest.bin);
    else if (manifest.bin && typeof manifest.bin === "object" && !Array.isArray(manifest.bin)) {
      scalarEntrypoints.push(...Object.values(manifest.bin));
    }
    if (typeof manifest.man === "string") scalarEntrypoints.push(manifest.man);
    else if (Array.isArray(manifest.man)) scalarEntrypoints.push(...manifest.man);
    for (const [index, value] of scalarEntrypoints.entries()) {
      if (value === undefined) continue;
      if (typeof value !== "string") {
        setupFailed(`package entrypoint ${index} is not a string`, "package entrypoint metadata is malformed", "repair the package manifest");
      }
      const path = relativePackagePath(value, `package entrypoint ${index}`);
      addSnapshotTree(
        root,
        packageScopedPath(dir, path),
        paths,
        `package entrypoint ${index}`,
        { optional: true },
      );
    }

    const absoluteDir = dir === "." ? root : join(root, ...dir.split("/"));
    for (const name of readdirSync(absoluteDir).sort(compareText)) {
      if (name === ".git" || name === "node_modules") continue;
      const relPathAtRoot = packageScopedPath(dir, name);
      const stat = inspectSnapshotSource(root, relPathAtRoot, "a top-level package input");
      if (stat.isSymbolicLink()) {
        setupFailed("a top-level package input is a symbolic link", opaquePathId(relPathAtRoot), "replace it with reviewed regular bytes");
      }
      if (stat.isFile()) paths.add(relPathAtRoot);
      else if (!stat.isDirectory()) {
        setupFailed("a top-level package input is a special filesystem object", opaquePathId(relPathAtRoot), null);
      }
    }
  }

  if (paths.size > PACK_SNAPSHOT_MAX_FILES) {
    setupFailed(
      "the publish snapshot exceeds its file-count bound",
      `more than ${PACK_SNAPSHOT_MAX_FILES} files`,
      "remove generated debris or narrow the manifest explicitly",
    );
  }
  return [...paths].sort(compareText);
}

function snapshotEvidence(root, paths, { retainBytes = false } = {}) {
  const blobs = new Map();
  const rows = [];
  let totalBytes = 0;
  for (const path of paths) {
    const absolute = join(root, ...path.split("/"));
    const before = inspectSnapshotSource(root, path, "a publish snapshot file");
    if (before.isSymbolicLink() || !before.isFile()) {
      setupFailed("a publish snapshot path stopped being a regular file", opaquePathId(path), "stop concurrent writers and retry");
    }
    if (before.size < 0 || before.size > PACK_SNAPSHOT_MAX_BYTES
        || totalBytes + before.size > PACK_SNAPSHOT_MAX_BYTES) {
      setupFailed(
        "the publish snapshot exceeds its byte bound",
        `more than ${PACK_SNAPSHOT_MAX_BYTES} bytes`,
        "remove generated debris or narrow the manifest explicitly",
      );
    }
    const bytes = stableControlBytes(root, path);
    const after = inspectSnapshotSource(root, path, "a publish snapshot file");
    if (!sameFileState(before, after) || bytes.length !== after.size) {
      setupFailed("a publish snapshot file changed while it was captured", opaquePathId(path), "stop concurrent writers and retry");
    }
    totalBytes += bytes.length;
    if (totalBytes > PACK_SNAPSHOT_MAX_BYTES) {
      setupFailed(
        "the publish snapshot exceeds its byte bound",
        `more than ${PACK_SNAPSHOT_MAX_BYTES} bytes`,
        "remove generated debris or narrow the manifest explicitly",
      );
    }
    rows.push({
      ctimeMs: after.ctimeMs,
      dev: after.dev,
      executable: (after.mode & 0o111) !== 0,
      ino: after.ino,
      mode: after.mode,
      mtimeMs: after.mtimeMs,
      nlink: after.nlink,
      path,
      sha256: createHash("sha256").update(bytes).digest("hex"),
      size: bytes.length,
      uid: after.uid,
    });
    if (retainBytes) blobs.set(path, bytes);
  }
  return { blobs, rows, totalBytes };
}

function materializeFrozenSnapshot(destination, evidence) {
  mkdirSync(destination, { mode: 0o700 });
  const directories = new Set([destination]);
  for (const row of evidence.rows) {
    const output = join(destination, ...row.path.split("/"));
    mkdirSync(dirname(output), { recursive: true, mode: 0o700 });
    let cursor = dirname(output);
    while (cursor !== destination && cursor.startsWith(`${destination}${sep}`)) {
      directories.add(cursor);
      cursor = dirname(cursor);
    }
    writeFileSync(output, evidence.blobs.get(row.path), {
      flag: "wx",
      mode: row.executable ? 0o555 : 0o444,
    });
  }
  for (const row of evidence.rows) {
    const copied = stableControlBytes(destination, row.path);
    const copiedStat = inspectSnapshotSource(destination, row.path, "a materialized publish snapshot file");
    if (copied.length !== row.size
        || createHash("sha256").update(copied).digest("hex") !== row.sha256
        || ((copiedStat.mode & 0o111) !== 0) !== row.executable
        || (copiedStat.mode & 0o222) !== 0) {
      setupFailed(
        "a materialized publish snapshot file differs from its captured source",
        opaquePathId(row.path),
        "stop concurrent scratch writers and retry",
      );
    }
  }
  for (const directory of [...directories].sort((left, right) => right.length - left.length)) {
    chmodSync(directory, 0o555);
  }
}

function removePackScratch(work) {
  const requiredPrefix = join(tmpdir(), "noa-boundary-pack-");
  if (!work.startsWith(requiredPrefix) || work === requiredPrefix) {
    throw new Error("refusing to remove an unexpected boundary scratch path");
  }
  const makeDirectoriesWritable = (path) => {
    if (!existsSync(path)) return;
    const stat = lstatSync(path);
    if (!stat.isDirectory() || stat.isSymbolicLink()) return;
    chmodSync(path, 0o700);
    for (const name of readdirSync(path)) makeDirectoriesWritable(join(path, name));
  };
  makeDirectoriesWritable(work);
  rmSync(work, { recursive: true, force: true });
  if (existsSync(work)) throw new Error("boundary pack scratch still exists after removal");
}

function packedSets(ctx) {
  const dirs = ctx.opts.packedDir !== null ? [ctx.opts.packedDir] : publishableDirs(ctx.root);
  for (const dir of dirs) {
    if (dir !== ".") canonicalSnapshotPath(dir, "publishable package directory");
    const absolute = resolve(ctx.root, dir);
    const escaped = relative(ctx.root, absolute);
    if (escaped === ".." || escaped.startsWith(`..${sep}`)) {
      setupFailed("a publishable package directory escaped the repository", opaquePathId(dir), null);
    }
  }

  const work = mkdtempSync(join(tmpdir(), "noa-boundary-pack-"));
  let operationError = null;
  let sets = null;
  try {
    const beforePaths = derivePackSnapshotPaths(ctx.root, dirs);
    if (beforePaths.length === 0) {
      setupFailed("the lifecycle-free publish snapshot derived zero files", "the source derivation is broken, not clean", null);
    }
    const before = snapshotEvidence(ctx.root, beforePaths, { retainBytes: true });
    const source = join(work, "source");
    materializeFrozenSnapshot(source, before);

    const afterPaths = derivePackSnapshotPaths(ctx.root, dirs);
    const after = snapshotEvidence(ctx.root, afterPaths);
    if (JSON.stringify(beforePaths) !== JSON.stringify(afterPaths)
        || JSON.stringify(before.rows) !== JSON.stringify(after.rows)) {
      setupFailed(
        "the publish source changed while its frozen snapshot was created",
        "path inventory, identity, metadata, or bytes differ across the capture window",
        "stop concurrent writers and retry",
      );
    }

    sets = [];
    for (const [index, dir] of dirs.entries()) {
      const output = join(work, `output-${index}`);
      let packed;
      try {
        packed = packFrozenPackageArtifact({ commitTime: 0, output, packagePath: dir, source });
      } catch {
        setupFailed(
          `the lifecycle-free exact tarball for ${opaquePathId(dir)} could not be produced`,
          "packer detail is withheld because it may contain untrusted paths or package bytes",
          "repair the package or the pinned packer; never fall back to npm lifecycle execution",
        );
      }
      if (packed.releaseAuthorized !== false || packed.status !== "CANDIDATE / NON-RELEASE"
          || !Array.isArray(packed.entries) || packed.entries.length !== packed.tarball.packlistCount) {
        setupFailed(
          `the lifecycle-free packer returned an invalid NON-RELEASE contract for ${opaquePathId(dir)}`,
          "the exact entry bytes and packlist count are required",
          null,
        );
      }
      sets.push({
        dir,
        entries: packed.entries.map(({ content, mode, path, sha256, size }) => ({
          content: Buffer.from(content), mode, path, sha256, size,
        })),
      });
    }
  } catch (error) {
    operationError = error;
  }

  try { removePackScratch(work); } catch (cleanupError) {
    setupFailed(
      "the lifecycle-free publish scratch could not be removed",
      operationError === null
        ? "cleanup failed; the scratch path and error are withheld"
        : "publication derivation and cleanup both failed; paths and errors are withheld",
      "remove only the named scratch directory after verifying its prefix and retry",
    );
  }
  if (operationError !== null) throw operationError;
  return sets;
}

function lanePACK(ctx) {
  const units = [];
  for (const set of ctx.packed) {
    for (const entry of set.entries) {
      const rel = set.dir === "." ? entry.path : `${set.dir}/${entry.path}`;
      const decoded = toText(entry.content, rel);
      units.push(fileUnit(opaqueValueId("pack", rel), decoded.text, {
        scopePath: rel,
        pathText: entry.path,
        pathIdentity: rel,
        structuredSource: decoded.structuredSource,
      }));
    }
  }
  return {
    units,
    note: `${ctx.packed.length} publishable package(s), ${units.length} file(s) from lifecycle-free exact tarball bytes`,
  };
}

function laneMAP(ctx) {
  const units = [];
  let maps = 0, dts = 0;
  for (const set of ctx.packed) {
    for (const entry of set.entries) {
      const isMap = entry.path.endsWith(".map");
      const isDts = isDeclarationArtifactPath(entry.path);
      if (!isMap && !isDts) continue;
      const rel = set.dir === "." ? entry.path : `${set.dir}/${entry.path}`;
      const decoded = toText(entry.content, rel);
      const label = isMap ? `map:${opaquePathId(rel)}` : `dts:${opaquePathId(rel)}`;
      const unit = fileUnit(label, decoded.text, {
        scopePath: rel,
        pathText: entry.path,
        pathIdentity: rel,
        structuredSource: decoded.structuredSource,
      });
      if (isMap) {
        maps++;
        const { findings, contents, paths } = scanSourceMap(label, decoded.text, { mapPath: entry.path });
        ctx.structuralFindings.push(...findings.map((finding) => ({
          ...finding,
          unitKey: contentKey(unit.text),
          pathIdentity: rel,
        })));
        units.push(unit);
        for (const metadata of paths) {
          units.push(externalMetadataUnit(rel, metadata.field, metadata.index, metadata.value));
        }
        for (const [i, content] of contents.entries()) {
          units.push(scopedTextUnit(`${label}:sourcesContent[${i}]`, content, rel));
        }
      } else {
        dts++;
        units.push(unit);
      }
    }
  }
  if (maps === 0 && dts === 0) {
    setupFailed(
      "the sourcemap lane found neither a .map nor a .d.ts/.d.mts/.d.cts in the packed set",
      "a published package with no declarations and no maps means the packed set is not build output — the derivation is broken, not the tree",
      "npm run build, then retry",
    );
  }
  return { units, note: `${maps} sourcemap(s), ${dts} declaration file(s)` };
}

function laneFIX(ctx) {
  const paths = nulList(capture("git", ["ls-files", "-z", "--", "conformance"], { cwd: ctx.root }).out);
  const units = [];
  for (const p of paths) {
    const u = readUnit(ctx.root, p, ctx.unscanned, { readPublishedSymlink: true });
    if (u !== null) units.push(u);
  }
  return { units, note: `${paths.length} tracked conformance file(s)` };
}

const ENUMERATORS = {
  "L-WT": laneWT, "L-IDX": laneIDX, "L-PUSH": laneBlobs, "L-MSG": laneCommits,
  "L-TAG": laneTags, "L-PACK": lanePACK, "L-MAP": laneMAP, "L-FIX": laneFIX,
};

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// Scanning
// ─────────────────────────────────────────────────────────────────────────────────────────────────
function externalPathViews(path) {
  const parts = String(path).split("/");
  return [...new Set(parts.map((_, index) => parts.slice(index).join("/")))];
}

function redactPathFinding(finding, reportId, unitKey) {
  return {
    ...finding,
    file: reportId,
    line: 0,
    matched: "<redacted>",
    shown: "<redacted>",
    snippet: "<redacted>",
    unitKey,
  };
}

function scanExternalPath(unit, ctx) {
  if (unit.pathText === undefined) return { findings: [], reportId: null };
  const unitKey = unit.pathUnitKey ?? pathContentKey(unit.pathIdentity);
  const reportId = unit.pathReportId ?? opaquePathId(unit.pathIdentity);
  const raw = [];
  const pathScanOptions = { structuredSource: false };
  for (const view of externalPathViews(unit.pathText)) {
    const push = (result) => raw.push(...result.findings, ...result.suppressed);
    push(scanShapes(unit.scopePath, view, pathScanOptions));
    push(scanRepoRefs(unit.scopePath, view, ctx.publicRepos, pathScanOptions));
    push(scanPrivacyAdjacency(unit.scopePath, view, ctx.publicRepos, pathScanOptions));
    if (ctx.tierB.enabled) {
      push(scanTokens(unit.scopePath, view, ctx.tierB.lookup, ctx.tierB.ngramSizes, {
        ...pathScanOptions,
        safeCompounds: ctx.publicTokenCompounds,
      }));
    }
  }
  return {
    findings: raw.map((finding) => redactPathFinding(finding, reportId, unitKey)),
    reportId,
  };
}

function redactContentFinding(finding, file) {
  return {
    ...finding,
    file,
    matched: "<redacted>",
    shown: "<redacted>",
    snippet: "<redacted>",
  };
}

function scanUnit(unit, ctx) {
  const pathResult = scanExternalPath(unit, ctx);
  const findings = [];
  const suppressed = [];
  const push = (r) => { findings.push(...r.findings); suppressed.push(...r.suppressed); };
  const scanOptions = { structuredSource: unit.structuredSource !== false };
  const scanPath = unit.scopePath ?? unit.path;
  push(scanShapes(scanPath, unit.text, scanOptions));
  push(scanRepoRefs(scanPath, unit.text, ctx.publicRepos, scanOptions));
  push(scanPrivacyAdjacency(scanPath, unit.text, ctx.publicRepos, scanOptions));
  if (ctx.tierB.enabled) {
    push(scanTokens(scanPath, unit.text, ctx.tierB.lookup, ctx.tierB.ngramSizes, {
      ...scanOptions,
      safeCompounds: ctx.publicTokenCompounds,
    }));
  }
  const unitKey = contentKey(unit.text);
  for (const finding of findings) finding.unitKey = unitKey;
  for (const finding of suppressed) finding.unitKey = unitKey;
  const reportFile = pathResult.reportId ?? unit.path;
  const redactedFindings = findings.map((finding) => redactContentFinding(finding, reportFile));
  const redactedSuppressed = suppressed.map((finding) => redactContentFinding(finding, reportFile));
  if (pathResult.findings.length > 0 && unit.pathIdentity !== undefined) {
    ctx.sensitivePathReports.set(unit.pathIdentity, pathResult.reportId);
  }
  return {
    findings: [...redactedFindings, ...pathResult.findings],
    suppressed: redactedSuppressed,
  };
}

function makeSafeLabeler({ publicRepos, tierB }) {
  const cache = new Map();
  const safeCompounds = publicTokenCompounds(publicRepos);
  return (label) => {
    const cached = cache.get(label);
    if (cached !== undefined) return cached;
    const text = String(label);
    const measured = [
      scanShapes("label", text),
      scanRepoRefs("label", text, publicRepos),
      scanPrivacyAdjacency("label", text, publicRepos),
    ];
    if (tierB.enabled) {
      measured.push(scanTokens("label", text, tierB.lookup, tierB.ngramSizes, {
        safeCompounds,
      }));
    }
    const unsafe = measured.some((result) => result.findings.length > 0 || result.suppressed.length > 0);
    const safe = unsafe ? "<redacted>" : text;
    cache.set(label, safe);
    return safe;
  };
}

function renderExposureCandidates(groups, safeLabel) {
  return [...groups].map(([key, group]) => ({
    key,
    count: group.length,
    rule: group[0].rule,
    severity: group[0].severity,
    files: [...new Set(group.map((finding) => safeLabel(finding.file)))],
    lines: group.map((finding) => finding.line),
    why: "",
    remediation: "",
    reviewedAt: "",
  })).sort((left, right) => (
    left.rule === right.rule ? compareText(left.files[0], right.files[0]) : compareText(left.rule, right.rule)
  ));
}

function renderTerminalFinding(finding, safeLabel) {
  return [
    `  ${red(finding.severity.toUpperCase().padEnd(8))} ${safeLabel(finding.file)}:${finding.line}  [${finding.rule}]  ${finding.shown}`,
    `           ${finding.snippet}`,
  ];
}

function renderGateFindings(findings, safeLabel) {
  return findings.map((finding) => ({
    rule: finding.rule,
    subject: safeLabel(finding.file),
    detail: `${finding.line}: ${finding.shown}`,
  }));
}

function outputContractFailures() {
  const confidentialLabel = ["PRIVATE https://10.20.", "30.40/resource"].join("");
  const safeLabel = makeSafeLabeler({
    publicRepos: { orgs: { examplearmorg: ["synthetic-public-repo"] } },
    tierB: { enabled: false, lookup: null, ngramSizes: [1] },
  });
  const finding = {
    file: confidentialLabel,
    line: 7,
    rule: "privacy-adjacency",
    severity: SEVERITY.HIGH,
    shown: "<redacted>",
    snippet: "<redacted>",
  };
  const groups = new Map([["synthetic-unit:privacy-adjacency", [finding]]]);
  const rendered = [
    JSON.stringify(renderExposureCandidates(groups, safeLabel)),
    renderTerminalFinding(finding, safeLabel).join("\n"),
    JSON.stringify(renderGateFindings([finding], safeLabel)),
  ];
  const failures = [];
  const unsafe = rendered.some((value) => value.includes(confidentialLabel))
    || rendered.some((value) => !value.includes("<redacted>"));
  if (unsafe) {
    failures.push({
      rule: "SELFTEST",
      subject: "boundary output routes keep confidential labels redacted",
      detail: "terminal, candidate JSON, or gate evidence violated the constant-safe label contract",
    });
  }

  const source = readFileSync(fileURLToPath(import.meta.url), "utf8");
  const successHelper = /function exitSuccessfulBoundaryOperation\(opts\) \{\n  if \(opts\.knockoutJson\) emitBoundaryGateEvidence\(\[\]\);\n  process\.exit\(0\);\n\}/g;
  const literalSuccessfulExits = source.match(/\bprocess\.exit\(0\);/g) ?? [];
  const successfulOperationCalls = source.match(/^\s*exitSuccessfulBoundaryOperation\(opts\);$/gm) ?? [];
  if ((source.match(successHelper) ?? []).length !== 1
      || literalSuccessfulExits.length !== 1
      || successfulOperationCalls.length !== 5) {
    failures.push({
      rule: "SELFTEST",
      subject: "boundary successful operation paths emit one provenance-bound machine terminal",
      detail: "a successful early-exit path bypassed the one closed machine-terminal helper",
    });
  }
  return failures;
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// The local publish-credential check.
//
// `npm publish --ignore-scripts` runs no lifecycle script, so NO local script can block it. The
// published workflow documents OIDC trusted publishing with no registry token, which is only true
// while no registry token exists on the machine. This check measures that claim instead of asserting
// it. It BLOCKS on the publish path — where it matters — and is a standing warning elsewhere, because
// a gate that refuses every unrelated push over a machine-wide condition is a gate people switch off.
// ─────────────────────────────────────────────────────────────────────────────────────────────────
function publishCredentialFindings(root) {
  const out = [];
  for (const p of [join(homedir(), ".npmrc"), join(root, ".npmrc")]) {
    if (!existsSync(p)) continue;
    let n = 0;
    try {
      for (const line of readFileSync(p, "utf8").split(/\r?\n/)) if (/(^|:)_auth(Token)?\s*=/.test(line)) n++;
    } catch { continue; }
    if (n > 0) {
      out.push({
        file: p.startsWith(homedir()) ? `~${p.slice(homedir().length)}` : relative(root, p),
        line: 0,
        rule: "local-publish-credential",
        severity: SEVERITY.HIGH,
        matched: "_authToken",
        shown: "_authToken",
        digest: "00000000",
        why: `${n} registry authentication line(s) present — a direct "npm publish --ignore-scripts" from this machine would authenticate, and no local script can intercept it`,
        fix: "npm logout   (publishing then happens only through the workflow that runs this gate)",
        snippet: "(value not read)",
        unitKey: "local-publish-credential",
      });
    }
  }
  return out;
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// Refreshers
// ─────────────────────────────────────────────────────────────────────────────────────────────────
function ghRepoNames(org, visibility) {
  const r = capture("gh", [
    "repo", "list", org, "--visibility", visibility,
    "--json", "name,nameWithOwner,visibility", "--limit", String(LIVE_REPO_LIMIT),
  ], { timeoutMs: PROVIDER_QUERY_TIMEOUT_MS });
  let parsed;
  try { parsed = JSON.parse(r.out); } catch { setupFailed(`the forge listing for ${opaqueValueId("org", org)} (${visibility}) is not JSON`, "parser detail is withheld because provider output is untrusted", "gh auth login"); }
  if (!Array.isArray(parsed) || parsed.length === 0) {
    setupFailed(`the forge returned zero ${visibility} repositories for ${opaqueValueId("org", org)}`, "an empty answer is a broken query, not an empty organisation", "gh auth status");
  }
  if (parsed.length >= LIVE_REPO_LIMIT) {
    setupFailed(
      `the forge listing for ${opaqueValueId("org", org)} reached its ${LIVE_REPO_LIMIT}-repository safety bound`,
      "the answer may be truncated, and an incomplete PUBLIC list would turn unknown repositories into false findings or false exceptions",
      "replace the bounded listing with a reviewed paginated provider query before continuing",
    );
  }
  const expectedVisibility = visibility.toUpperCase();
  const names = [];
  const seen = new Set();
  for (const [index, repo] of parsed.entries()) {
    if (repo === null || typeof repo !== "object" || typeof repo.name !== "string"
        || repo.name.trim() !== repo.name || repo.name.length === 0
        || repo.nameWithOwner !== `${org}/${repo.name}` || repo.visibility !== expectedVisibility) {
      setupFailed(
        `the forge listing for ${opaqueValueId("org", org)} (${visibility}) returned malformed repository metadata`,
        `entry ${index} did not bind exact nameWithOwner and visibility to the requested organisation`,
        "re-run with a current authenticated gh client",
      );
    }
    const key = repo.name.toLowerCase();
    if (seen.has(key)) setupFailed(`the forge listing for ${opaqueValueId("org", org)} (${visibility}) returned a duplicate`, "duplicate names make visibility comparison ambiguous", null);
    seen.add(key);
    names.push(repo.name);
  }
  return names;
}

function repoVisibilityFingerprint(doc) {
  const canonical = Object.entries(doc.orgs)
    .map(([org, repos]) => [org.toLowerCase(), [...repos].map((name) => name.toLowerCase()).sort()])
    .sort(([left], [right]) => compareText(left, right));
  return {
    digest: createHash("sha256").update(JSON.stringify(canonical), "utf8").digest("hex"),
    organisations: canonical.length,
    repositories: canonical.reduce((count, [, repos]) => count + repos.length, 0),
  };
}

function queryLiveRepoTruth(root) {
  const snapshot = loadPublicRepoSnapshot();
  const owners = Object.keys(snapshot.orgs).sort(compareText);
  if (owners.length !== 1) {
    setupFailed("the committed PUBLIC snapshot has an ambiguous organisation scope", "live refresh needs exactly one reviewed organisation without deriving a private repository identity", "split the boundary invocation by reviewed organisation");
  }
  const [owner] = owners;
  const orgs = {};
  orgs[owner] = ghRepoNames(owner, "public").sort(compareText);
  const privateRepoNames = ghRepoNames(owner, "private").sort(compareText);
  const privateForms = [];
  const seenPrivateForms = new Set();
  for (const name of privateRepoNames) {
    let forms;
    try { forms = reachableTokenForms(name); } catch {
      setupFailed(
        "a live PRIVATE repository name is outside the scanner-reachable grammar",
        "the confidential value is deliberately not printed; Unicode, unsupported punctuation, and overlong forms require a versioned tokenizer",
        "extend the scanner contract under review before claiming coverage",
      );
    }
    if (forms.length !== 1 || seenPrivateForms.has(forms[0])) {
      setupFailed(
        "the live PRIVATE repository inventory does not map one-to-one onto scanner forms",
        "a missing or colliding normalized form would make the authenticated input count ambiguous; values are not printed",
        "review the tokenizer and provider identities before release",
      );
    }
    seenPrivateForms.add(forms[0]);
    privateForms.push(forms[0]);
  }
  privateForms.sort(compareText);
  const publicRepos = {
    note: "PUBLIC repositories, per organisation, as the forge itself reports them. This file is safe " +
      "to publish because every name in it is already public. It exists so the boundary gate can " +
      "ALLOWLIST the public instead of denylisting the private: a denylist would itself be the " +
      "disclosure, and would always be one repository behind reality.",
    source: "live gh repo list <org> --visibility public --json name,nameWithOwner,visibility",
    refreshedAt: new Date().toISOString(),
    orgs,
  };
  return { publicRepos, privateForms };
}

function loadRepoVisibility(root, source) {
  const snapshot = loadPublicRepoSnapshot();
  if (source === "snapshot") {
    return {
      publicRepos: snapshot,
      evidence: "SNAPSHOT_NON_CLAIM",
      observedAt: snapshot.refreshedAt,
      privateForms: null,
    };
  }

  const live = queryLiveRepoTruth(root);
  const snapshotIdentity = repoVisibilityFingerprint(snapshot);
  const liveIdentity = repoVisibilityFingerprint(live.publicRepos);
  if (snapshotIdentity.digest !== liveIdentity.digest) {
    setupFailed(
      "the committed PUBLIC-repository snapshot has drifted from live provider truth",
      `snapshot=${snapshotIdentity.organisations} org/${snapshotIdentity.repositories} repo digest ${snapshotIdentity.digest}; ` +
        `live=${liveIdentity.organisations} org/${liveIdentity.repositories} repo digest ${liveIdentity.digest}. ` +
        "Names are deliberately omitted because a repository removed from PUBLIC may now be confidential.",
      "node scripts/lint-boundary.mjs --repo-visibility-source live --refresh-public-repos, then review the exact public-only diff",
    );
  }
  return {
    publicRepos: live.publicRepos,
    evidence: "LIVE_PROVIDER_VERIFIED",
    observedAt: live.publicRepos.refreshedAt,
    privateForms: live.privateForms,
  };
}

function refreshPublicRepos(root, live = queryLiveRepoTruth(root)) {
  const doc = live.publicRepos;
  doc.source = "gh repo list <org> --visibility public --json name,nameWithOwner,visibility";
  writeFileSync(PUBLIC_REPOS_PATH, `${JSON.stringify(doc, null, 2)}\n`);
  const written = loadPublicRepoSnapshot();
  if (repoVisibilityFingerprint(written).digest !== repoVisibilityFingerprint(doc).digest) {
    setupFailed("the refreshed PUBLIC snapshot failed exact read-back", "the committed snapshot does not equal the live in-memory visibility set", "stop concurrent writers and retry");
  }
  say(green(`  refreshed the public-repository snapshot — ${Object.keys(doc.orgs).length} organisation(s), ${Object.values(doc.orgs).reduce((sum, repos) => sum + repos.length, 0)} repository name(s)`));
}

function refreshTokens(root, privateForms) {
  boundaryKeyDirectory({ create: true });
  let keyExists = true;
  try {
    lstatSync(KEY_FILE);
  } catch (e) {
    if (e?.code === "ENOENT") keyExists = false;
    else setupFailed("the boundary key cannot be inspected before refresh", `${opaquePathId(KEY_FILE)}: ${e?.code ?? "I/O error"}`, "repair the outside-repository key custody");
  }
  if (!keyExists) {
    try {
      writeFileSync(KEY_FILE, randomBytes(KEY_BYTES), { mode: KEY_MODE, flag: "wx" });
    } catch {
      setupFailed(
        "a new boundary key could not be created exclusively",
        `${opaquePathId(KEY_FILE)}: create failed; detail withheld`,
        "remove the custody conflict and retry; never overwrite an unknown key",
      );
    }
    say(yellow("  generated a new external boundary key with mode 0600. It never enters the repository."));
  }
  const key = readBoundaryKey();
  const keyId = createHash("sha256").update(key).digest("hex");
  const extra = loadExtraInputs(key);
  // This is intentionally before provider enumeration and before canary migration. The current
  // legacy file has reasons but no honest reviewer/time authority; inventing either would turn an
  // old allowlist into an authenticated one. The failure leaves every operator byte untouched.
  const exclusions = loadExclusionPolicy(key);
  const canary = canaryFromCustody({ migrate: true });

  const previous = existsSync(COMMITMENTS_PATH) ? readJson(COMMITMENTS_PATH, "the previous token commitments") : null;
  const previousDigests = new Set();
  const previousNgramSizes = new Set();
  if (previous !== null) {
    authenticateCommitmentDocument(previous, key, { allowPrevious: true, requireFresh: false });
    for (const digest of previous.digests) previousDigests.add(digest);
    for (const size of previous.ngramSizes) previousNgramSizes.add(size);
  }

  if (!Array.isArray(privateForms) || privateForms.length === 0
      || new Set(privateForms).size !== privateForms.length
      || privateForms.some((form, index) => typeof form !== "string"
        || (index > 0 && compareText(privateForms[index - 1], form) >= 0))) {
    setupFailed("the live PRIVATE-input set is malformed or empty", "refresh requires one unique sorted scanner-reachable form per current live private repository", "rerun the coupled live provider query");
  }
  for (const form of privateForms) {
    let validated;
    try { validated = reachableTokenForms(form); } catch {
      setupFailed("a live PRIVATE input cannot round-trip through the scanner", "the value is deliberately not printed", "extend the versioned tokenizer before refreshing");
    }
    if (validated.length !== 1 || validated[0] !== form) setupFailed("a live PRIVATE input is not canonical", "normalization-dependent provider inputs are refused", null);
  }
  const sourceForms = new Set(extra.forms);
  for (const form of privateForms) sourceForms.add(form);
  const drop = new Set(exclusions.forms);
  let excluded = 0;
  for (const form of drop) if (sourceForms.delete(form)) excluded++;
  if (excluded !== exclusions.entries.length) {
    setupFailed("a governed exclusion did not match exactly one current derived token", `${exclusions.entries.length - excluded} authenticated exclusion(s) are stale or unrelated; values are not printed`, "review and remove stale policy entries instead of carrying invisible authority");
  }
  const before = sourceForms.size + excluded;
  if (excluded * 3 > before) {
    setupFailed("the governed exclusions remove more than a third of derived tokens", `${excluded} of ${before}; an exclusion policy cannot be allowed to empty the tier`, "reduce the reviewed exclusions");
  }
  const canaryForm = reachableTokenForms(canary)[0];
  sourceForms.add(canaryForm);
  if (sourceForms.size === 0) setupFailed("the token derivation produced nothing", "no confidential labels and no canary", "repair provider access and canary custody");

  const digests = new Set(previousDigests);
  for (const form of sourceForms) digests.add(commitToken(key, form));
  if (digests.size < previousDigests.size) setupFailed("the commitment refresh would shrink coverage", "a monotonic union must never remove an old HMAC digest", null);
  const ngramSizes = new Set(previousNgramSizes);
  for (const form of sourceForms) ngramSizes.add(tokenNgramSize(form));
  const sortedDigests = [...digests].sort();
  const doc = {
    schemaVersion: COMMITMENT_SCHEMA_VERSION,
    note: "HMAC-SHA256 commitments over the confidential label list. DIGESTS ONLY — the plaintext " +
      "labels are derived in memory and are never persisted; the key and reviewed inputs live outside " +
      "this repository. `ngramSizes` " +
      "is the set of WORD COUNTS present in the list, which is what lets a spaced phrase normalise " +
      "onto a hyphenated label without generating every n-gram in the tree; it discloses word " +
      "counts and nothing else. A `#` inside a committed form matches any digit run, so a numbered " +
      "family is one commitment rather than an unbounded list. Old digests are unioned forward, so " +
      "refresh cannot shrink coverage. External extra inputs and exact governed exclusions are bound " +
      "by HMAC; only counts and commitments are published.",
    alg: "HMAC-SHA256",
    keyId,
    refreshedAt: new Date().toISOString(),
    governanceStatus: "AUTHENTICATED",
    count: sortedDigests.length,
    excludedCount: excluded,
    ngramSizes: [...ngramSizes].sort((a, b) => a - b),
    canaryDigest: commitToken(key, canaryForm),
    extraInputsCommitment: extra.commitment,
    exclusionPolicyCommitment: exclusions.commitment,
    privateInputCount: privateForms.length,
    privateInputsCommitment: keyedRecord(key, "private-inputs/v1", privateForms),
    digests: sortedDigests,
  };
  doc.commitmentMac = keyedRecord(key, "commitments/v3", commitmentPayload(doc));
  writeFileSync(COMMITMENTS_PATH, `${JSON.stringify(doc, null, 2)}\n`);
  say(green(`  refreshed ${relative(root, COMMITMENTS_PATH)} — ${doc.count} monotonic commitment(s), full keyId bound, ngramSizes [${doc.ngramSizes}]`));
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// Ledger — evidence, never a gate. A machine that cannot write it still gets its verdict.
// ─────────────────────────────────────────────────────────────────────────────────────────────────
function writeLedger(record) {
  const result = appendBoundaryLedgerRecord({
    spoolDirectoryPath: BOUNDARY_EVIDENCE_SPOOL,
    event: "BOUNDARY_GATE_VERDICT",
    repositoryHead: record.repositoryHead,
    verdict: record.verdict,
    provenance: currentBoundaryGateProvenance(),
    metrics: {
      blocking: record.blocking,
      carried: record.carried,
      keyId: record.keyId,
      lanes: record.lanes.map(({ id, status, units }) => ({ id, status, units })),
      ledgerEntries: record.ledgerEntries,
      privateInputsEvidence: record.privateInputsEvidence,
      repositoryVisibilityEvidence: record.repositoryVisibilityEvidence,
      repositoryVisibilityObservedAt: record.repositoryVisibilityObservedAt,
      scannedUnits: record.scannedUnits,
      suppressed: record.suppressed,
      tier: record.tier,
    },
  });
  if (result.warning !== null) process.stderr.write(`${yellow(result.warning)}\n`);
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────────────────────────────────────────────
function proveImmutablePublicationResultContract() {
  const scratch = mkdtempSync(join(tmpdir(), "noa-boundary-custody-result-"));
  let problem = null;
  try {
    chmodSync(scratch, KEY_DIR_MODE);
    const bytes = Buffer.from("bounded immutable custody result proof\n", "utf8");
    const options = (candidate) => ({
      candidatePath: join(scratch, candidate),
      destinationPath: join(scratch, "final"),
      bytes,
      candidateMode: KEY_MODE,
      immutableMode: 0o400,
      directoryMode: KEY_DIR_MODE,
      maxBytes: 4096,
    });
    const created = durablePublishImmutableByLink(
      options(".candidate-created"),
      durablePublishImmutableByLinkTestDependencies({ trace: true }),
    );
    const existing = durablePublishImmutableByLink(
      options(".candidate-existing"),
      durablePublishImmutableByLinkTestDependencies({ trace: true }),
    );
    const finalPath = join(scratch, "final");
    const retainedPath = join(scratch, ".candidate-created");
    const finalStat = lstatSync(finalPath);
    const retainedStat = lstatSync(retainedPath);
    if (created.status !== "CREATED" || created.persistence !== "PERSISTED"
        || created.candidateResidue !== true || created.cleanupResidue !== true
        || !Object.isFrozen(created) || !Object.isFrozen(created.phaseTrace)
        || !created.phaseTrace.includes("final-link-after")
        || !created.phaseTrace.includes("candidate-retained-before-return")
        || existing.status !== "EXISTING" || existing.persistence !== "PERSISTED"
        || existing.candidateResidue !== false || existing.cleanupResidue !== true
        || !readFileSync(finalPath).equals(bytes) || !readFileSync(retainedPath).equals(bytes)
        || permissionBits(finalStat) !== 0o400 || finalStat.nlink !== 2
        || retainedStat.dev !== finalStat.dev || retainedStat.ino !== finalStat.ino) {
      problem = "CREATED/EXISTING persistence, residue, frozen trace, bytes, or mode diverged";
    }
  } catch (error) {
    problem = error instanceof BoundaryCustodyError ? error.code : "UNEXPECTED";
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
  if (problem !== null) {
    setupFailed(
      "the shared immutable publication result contract regressed",
      problem,
      "restore truthful CREATED/EXISTING residue and frozen phase-trace semantics in boundary custody",
    );
  }
}

function proveDurableCreateFailureContracts() {
  const cases = [
    ["candidate-create-operation", "EIO", "FILE_CREATE_FAILED"],
    ["candidate-write-operation", "ENOSPC", "FILE_CREATE_FAILED"],
  ];
  for (const [faultPoint, faultCode, expectedCode] of cases) {
    const scratch = mkdtempSync(join(tmpdir(), "noa-boundary-create-contract-"));
    let observed = "NO_ERROR";
    try {
      chmodSync(scratch, KEY_DIR_MODE);
      durableCreateExclusive({
        path: join(scratch, "final"),
        bytes: Buffer.from("bounded durable-create compatibility proof\n", "utf8"),
        mode: KEY_MODE,
      }, durablePublishImmutableByLinkTestDependencies({
        faultAction: "system-error",
        faultCode,
        faultPoint,
      }));
    } catch (error) {
      observed = error instanceof BoundaryCustodyError ? error.code : "UNEXPECTED";
    } finally {
      rmSync(scratch, { recursive: true, force: true });
    }
    if (observed !== expectedCode) {
      setupFailed(
        "the durable-create compatibility error contract regressed",
        `${faultPoint} returned ${observed}; expected ${expectedCode}`,
        "preserve the established rotation error taxonomy while sharing custody mechanics",
      );
    }
  }

  const expectedBytes = Buffer.from("bounded pre-existing durable-create proof\n", "utf8");
  for (const [id, existingBytes] of [
    ["shorter", expectedBytes.subarray(0, expectedBytes.length - 1)],
    ["longer", Buffer.concat([expectedBytes, Buffer.from("x")])],
  ]) {
    const scratch = mkdtempSync(join(tmpdir(), `noa-boundary-create-${id}-`));
    const finalPath = join(scratch, "final");
    let observed = "NO_ERROR";
    try {
      chmodSync(scratch, KEY_DIR_MODE);
      createSelftestFile(finalPath, existingBytes, KEY_MODE);
      durableCreateExclusive({ path: finalPath, bytes: expectedBytes, mode: KEY_MODE });
    } catch (error) {
      observed = error instanceof BoundaryCustodyError ? error.code : "UNEXPECTED";
    } finally {
      rmSync(scratch, { recursive: true, force: true });
    }
    if (observed !== "FILE_BYTES_CHANGED") {
      setupFailed(
        "the pre-existing durable-create byte mismatch contract regressed",
        `${id} winner returned ${observed}; expected FILE_BYTES_CHANGED`,
        "translate stable-reader size bounds only at the durable-create compatibility boundary",
      );
    }
  }

  const retryScratch = mkdtempSync(join(tmpdir(), "noa-boundary-create-retry-sync-"));
  const retryFinalPath = join(retryScratch, "final");
  const retryEnvironment = new Map([
    ["NOA_BOUNDARY_ROTATION_TEST_MODE", process.env.NOA_BOUNDARY_ROTATION_TEST_MODE],
    ["NOA_BOUNDARY_CUSTODY_FAIL_AT", process.env.NOA_BOUNDARY_CUSTODY_FAIL_AT],
    ["NOA_BOUNDARY_CUSTODY_FAIL_CODE", process.env.NOA_BOUNDARY_CUSTODY_FAIL_CODE],
  ]);
  let retryObserved = "NO_ERROR";
  let retryRetained = false;
  try {
    chmodSync(retryScratch, KEY_DIR_MODE);
    createSelftestFile(retryFinalPath, expectedBytes, KEY_MODE);
    process.env.NOA_BOUNDARY_ROTATION_TEST_MODE = "1";
    process.env.NOA_BOUNDARY_CUSTODY_FAIL_AT = "existing-file-sync:final";
    process.env.NOA_BOUNDARY_CUSTODY_FAIL_CODE = "EIO";
    durableCreateExclusive({ path: retryFinalPath, bytes: expectedBytes, mode: KEY_MODE });
  } catch (error) {
    retryObserved = error instanceof BoundaryCustodyError ? error.code : "UNEXPECTED";
  } finally {
    retryRetained = existsSync(retryFinalPath) && readFileSync(retryFinalPath).equals(expectedBytes);
    for (const [key, value] of retryEnvironment) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    rmSync(retryScratch, { recursive: true, force: true });
  }
  if (retryObserved !== "INJECTED_EIO" || !retryRetained) {
    setupFailed(
      "an exact pre-existing durable-create final bypassed the retry durability barrier",
      `code=${retryObserved}; retained=${retryRetained}`,
      "fsync the exact file and its directory, then reread it before accepting retry success",
    );
  }

  for (const faultPoint of [
    "existing-final-open-operation",
    "existing-final-fstat-operation",
    "existing-final-fsync-operation",
    "existing-final-close-operation",
  ]) {
    const scratch = mkdtempSync(join(tmpdir(), "noa-boundary-existing-sync-contract-"));
    const finalPath = join(scratch, "final");
    let result = null;
    try {
      chmodSync(scratch, KEY_DIR_MODE);
      createSelftestFile(finalPath, expectedBytes, 0o400);
      result = durablePublishImmutableByLink({
        candidatePath: join(scratch, ".candidate"),
        destinationPath: finalPath,
        bytes: expectedBytes,
        candidateMode: KEY_MODE,
        immutableMode: 0o400,
        directoryMode: KEY_DIR_MODE,
        maxBytes: 4096,
        existingFinalMaxBytes: 4096,
        existingFinalLinks: [1],
      }, durablePublishImmutableByLinkTestDependencies({
        faultAction: "system-error",
        faultCode: "EIO",
        faultPoint,
      }));
    } finally {
      rmSync(scratch, { recursive: true, force: true });
    }
    if (result?.status !== "INDETERMINATE" || result.code !== "FILE_SYNC_FAILED"
        || result.persistence !== "INDETERMINATE" || result.candidateResidue !== false) {
      setupFailed(
        "an existing-final synchronization fault escaped the custody taxonomy",
        `${faultPoint} returned ${result?.code ?? "NO_RESULT"}`,
        "normalize raw open/fstat/fsync/close failures to FILE_SYNC_FAILED without deleting evidence",
      );
    }
  }

  const legacyScratch = mkdtempSync(join(tmpdir(), "noa-boundary-retired-stage-"));
  const legacyFinalPath = join(legacyScratch, "final");
  const legacyStageRoot = join(legacyScratch, ".noa-boundary-create-v1");
  const legacyStageTarget = join(legacyStageRoot, "final");
  const legacyBytes = Buffer.from("retained retired-stage proof\n", "utf8");
  const legacyTargetDigest = createHash("sha256")
    .update(Buffer.from("noa-boundary-create-destination/v1\0final", "utf8"))
    .digest("hex");
  const legacyContentDigest = createHash("sha256").update(legacyBytes).digest("hex");
  const legacyStagePath = join(
    legacyStageTarget,
    `create-v1-${legacyTargetDigest}-${legacyContentDigest}-${legacyBytes.length}`
      + `-p${process.pid}-${"ab".repeat(16)}.stage`,
  );
  let legacyObserved = "NO_ERROR";
  try {
    chmodSync(legacyScratch, KEY_DIR_MODE);
    mkdirSync(legacyStageRoot, { mode: KEY_DIR_MODE });
    mkdirSync(legacyStageTarget, { mode: KEY_DIR_MODE });
    createSelftestFile(legacyStagePath, legacyBytes, KEY_MODE);
    durableCreateExclusive({ path: legacyFinalPath, bytes: legacyBytes, mode: KEY_MODE });
  } catch (error) {
    legacyObserved = error instanceof BoundaryCustodyError ? error.code : "UNEXPECTED";
  }
  const legacyRetained = existsSync(legacyStagePath)
    && readFileSync(legacyStagePath).equals(legacyBytes)
    && !existsSync(legacyFinalPath);
  rmSync(legacyScratch, { recursive: true, force: true });
  if (legacyObserved !== "CREATE_STAGE_MANUAL_RECOVERY_REQUIRED" || !legacyRetained) {
    setupFailed(
      "retired staged-create recovery mutated same-UID-swappable pathname state",
      `code=${legacyObserved}; retained=${legacyRetained}`,
      "retain every legacy stage and require bounded operator recovery without pathname deletion",
    );
  }

}

function checkpointedSelftestWorker({ source, args, environment, checkpoint, onCheckpoint }) {
  return new Promise((resolveWorker, rejectWorker) => {
    const childEnvironment = { ...process.env };
    for (const key of [
      "NOA_BOUNDARY_CUSTODY_CRASH_AFTER",
      "NOA_BOUNDARY_CUSTODY_FAIL_AT",
      "NOA_BOUNDARY_CUSTODY_FAIL_CODE",
      "NOA_BOUNDARY_IMMUTABLE_PAUSE_AT",
      "NOA_BOUNDARY_IMMUTABLE_PAUSE_MS",
      "NOA_BOUNDARY_IMMUTABLE_RELEASE_FILE",
      "NOA_BOUNDARY_IMMUTABLE_TRACE_CHECKPOINTS",
      "NOA_BOUNDARY_ROTATION_PAUSE_AT",
      "NOA_BOUNDARY_ROTATION_PAUSE_MS",
      "NOA_BOUNDARY_ROTATION_RELEASE_FILE",
      "NOA_BOUNDARY_ROTATION_TEST_MODE",
      "NOA_BOUNDARY_ROTATION_TRACE_CHECKPOINTS",
    ]) delete childEnvironment[key];
    Object.assign(childEnvironment, environment);
    const child = spawn(process.execPath, ["--input-type=module", "-e", source, ...args], {
      env: childEnvironment,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    let checkpointHandled = false;
    let actionError = null;
    let settled = false;
    const finish = (error, value = null) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error === null) resolveWorker(value);
      else rejectWorker(error);
    };
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      finish(new Error("checkpoint worker timeout"));
    }, 10_000);
    child.stdout.on("data", (chunk) => { stdout = `${stdout}${String(chunk)}`.slice(-32_768); });
    child.stderr.on("data", (chunk) => {
      stderr = `${stderr}${String(chunk)}`.slice(-32_768);
      if (!checkpointHandled && stderr.includes(checkpoint)) {
        checkpointHandled = true;
        try { onCheckpoint(); } catch (error) {
          actionError = error;
          child.kill("SIGKILL");
        }
      }
    });
    child.once("error", (error) => finish(error));
    child.once("close", (code, signal) => {
      if (actionError !== null) return finish(actionError);
      if (!checkpointHandled) return finish(new Error("required checkpoint was not observed"));
      return finish(null, { code, signal, stderr, stdout });
    });
  });
}

function parseCheckpointWorkerResult(result) {
  if (result.code !== 0 || result.signal !== null) throw new Error("checkpoint worker failed");
  try { return JSON.parse(result.stdout.trim()); } catch { throw new Error("checkpoint worker result malformed"); }
}

function createSelftestFile(path, bytes, mode) {
  writeFileSync(path, bytes, { flag: "wx", mode });
  chmodSync(path, mode);
}

async function proveSameUidCandidateSwapRetention() {
  const custodyModuleUrl = new URL("./lib/boundary-custody.mjs", import.meta.url).href;
  const scratch = mkdtempSync(join(tmpdir(), "noa-boundary-same-uid-swap-"));
  const candidatePath = join(scratch, ".candidate");
  const movedPath = join(scratch, ".candidate-moved-by-peer");
  const destinationPath = join(scratch, "final");
  const releasePath = join(scratch, ".release");
  const originalBytes = Buffer.from("same-uid retained candidate proof\n", "utf8");
  const replacementBytes = Buffer.from("peer replacement must survive\n", "utf8");
  const workerSource = String.raw`
    const [moduleUrl, candidatePath, destinationPath, encoded] = process.argv.slice(1);
    const { durablePublishImmutableByLink, durablePublishImmutableByLinkTestDependencies } = await import(moduleUrl);
    const result = durablePublishImmutableByLink({
      candidatePath,
      destinationPath,
      bytes: Buffer.from(encoded, "base64"),
      candidateMode: 0o600,
      immutableMode: 0o400,
      directoryMode: 0o700,
      maxBytes: 4096,
      existingFinalMaxBytes: 4096,
      existingFinalLinks: [1, 2],
      retainCandidateOnConflict: true,
    }, durablePublishImmutableByLinkTestDependencies({ trace: true }));
    process.stdout.write(JSON.stringify(result));
  `;
  let problem = null;
  try {
    chmodSync(scratch, KEY_DIR_MODE);
    const worker = await checkpointedSelftestWorker({
      source: workerSource,
      args: [
        custodyModuleUrl,
        candidatePath,
        destinationPath,
        originalBytes.toString("base64"),
      ],
      environment: {
        NOA_BOUNDARY_IMMUTABLE_PAUSE_AT: "candidate-retained-before-return",
        NOA_BOUNDARY_IMMUTABLE_PAUSE_MS: "5000",
        NOA_BOUNDARY_IMMUTABLE_RELEASE_FILE: releasePath,
        NOA_BOUNDARY_IMMUTABLE_TRACE_CHECKPOINTS: "1",
      },
      checkpoint: "NOA_IMMUTABLE_PUBLISH_CHECKPOINT candidate-retained-before-return",
      onCheckpoint: () => {
        renameSync(candidatePath, movedPath);
        createSelftestFile(candidatePath, replacementBytes, 0o400);
        createSelftestFile(releasePath, Buffer.from("ready\n", "utf8"), KEY_MODE);
      },
    });
    const result = parseCheckpointWorkerResult(worker);
    const finalStat = lstatSync(destinationPath);
    const movedStat = lstatSync(movedPath);
    const replacementStat = lstatSync(candidatePath);
    if (result.status !== "CREATED" || result.persistence !== "PERSISTED"
        || result.candidateResidue !== true || result.cleanupResidue !== true
        || !readFileSync(destinationPath).equals(originalBytes)
        || !readFileSync(movedPath).equals(originalBytes)
        || !readFileSync(candidatePath).equals(replacementBytes)
        || finalStat.nlink !== 2 || movedStat.nlink !== 2 || replacementStat.nlink !== 1
        || finalStat.dev !== movedStat.dev || finalStat.ino !== movedStat.ino) {
      problem = `status=${result.status}; persistence=${result.persistence}; cleanup=${result.cleanupResidue}`;
    }
  } catch {
    problem = "self-test operation failed; paths and error detail withheld";
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
  if (problem !== null) {
    setupFailed(
      "same-UID candidate replacement was deleted or hidden by a false cleanup claim",
      problem,
      "retain the verified quarantine alias and report cleanup residue without pathname unlink",
    );
  }
}

async function proveConcurrentWinnerContracts() {
  const custodyModuleUrl = new URL("./lib/boundary-custody.mjs", import.meta.url).href;
  const rotationWorkerSource = String.raw`
    const [moduleUrl, destinationPath, encoded, faultPoint] = process.argv.slice(1);
    const {
      BoundaryCustodyError,
      durableCreateExclusive,
      durablePublishImmutableByLinkTestDependencies,
    } = await import(moduleUrl);
    let code = "NO_ERROR";
    try {
      durableCreateExclusive({
        path: destinationPath,
        bytes: Buffer.from(encoded, "base64"),
        mode: 0o600,
      }, faultPoint === "none" ? null : durablePublishImmutableByLinkTestDependencies({
        faultAction: "system-error",
        faultCode: "EIO",
        faultPoint,
      }));
    } catch (error) {
      code = error instanceof BoundaryCustodyError ? error.code : "UNEXPECTED";
    }
    process.stdout.write(JSON.stringify({ code }));
  `;
  const candidateBytes = Buffer.from("bounded rotation candidate winner proof\n", "utf8");
  const rotationCases = [
    { id: "raw-open-failure", winner: candidateBytes, expected: "FILE_SYNC_FAILED", systemFaultPoint: "existing-final-open-operation", syncFailure: false },
    { id: "same-fsync-failure", winner: candidateBytes, expected: "INJECTED_EIO", syncFailure: true },
    { id: "shorter-fsync-failure", winner: candidateBytes.subarray(0, candidateBytes.length - 1), expected: "INJECTED_EIO", syncFailure: true },
    { id: "longer-fsync-failure", winner: Buffer.concat([candidateBytes, Buffer.from("x")]), expected: "INJECTED_EIO", syncFailure: true },
    { id: "shorter-mismatch", winner: candidateBytes.subarray(0, candidateBytes.length - 1), expected: "FILE_ALREADY_EXISTS", syncFailure: false },
    { id: "longer-mismatch", winner: Buffer.concat([candidateBytes, Buffer.from("x")]), expected: "FILE_ALREADY_EXISTS", syncFailure: false },
  ];
  for (const testCase of rotationCases) {
    const scratch = mkdtempSync(join(tmpdir(), `noa-boundary-${testCase.id}-`));
    const destinationPath = join(scratch, "winner");
    const releasePath = join(scratch, ".release");
    let problem = null;
    try {
      chmodSync(scratch, KEY_DIR_MODE);
      const environment = {
        NOA_BOUNDARY_ROTATION_PAUSE_AT: "create-link:winner",
        NOA_BOUNDARY_ROTATION_PAUSE_MS: "5000",
        NOA_BOUNDARY_ROTATION_RELEASE_FILE: releasePath,
        NOA_BOUNDARY_ROTATION_TEST_MODE: "1",
        NOA_BOUNDARY_ROTATION_TRACE_CHECKPOINTS: "1",
      };
      if (testCase.syncFailure) {
        environment.NOA_BOUNDARY_CUSTODY_FAIL_AT = "existing-file-sync:winner";
        environment.NOA_BOUNDARY_CUSTODY_FAIL_CODE = "EIO";
      }
      const worker = await checkpointedSelftestWorker({
        source: rotationWorkerSource,
        args: [
          custodyModuleUrl,
          destinationPath,
          candidateBytes.toString("base64"),
          testCase.systemFaultPoint ?? "none",
        ],
        environment,
        checkpoint: "NOA_ROTATION_CHECKPOINT create-link:winner",
        onCheckpoint: () => {
          createSelftestFile(destinationPath, testCase.winner, KEY_MODE);
          createSelftestFile(releasePath, Buffer.from("ready\n", "utf8"), KEY_MODE);
        },
      });
      const observed = parseCheckpointWorkerResult(worker);
      const targets = durableCreateStageTargets({ directoryPath: scratch });
      if (observed.code !== testCase.expected || targets.length !== 0
          || !readFileSync(destinationPath).equals(testCase.winner)) {
        problem = `${testCase.id}: code=${observed.code}; targets=${targets.length}`;
      }
    } catch {
      problem = `${testCase.id}: self-test operation failed; detail withheld`;
    } finally {
      rmSync(scratch, { recursive: true, force: true });
    }
    if (problem !== null) {
      setupFailed(
        "the durable-create competing-winner contract regressed",
        problem,
        "sync every pre-existing O_EXCL winner before comparison and preserve bounded legacy conflict behavior",
      );
    }
  }

  const ledgerInputFor = (spoolDirectoryPath, event) => ({
    spoolDirectoryPath,
    event,
    repositoryHead: "a".repeat(40),
    verdict: "GREEN",
    metrics: {
      blocking: 0, carried: 0, keyId: null,
      lanes: [{ id: "L-WT", status: "scanned", units: 1 }],
      ledgerEntries: 0,
      privateInputsEvidence: "TIER_B_UNMEASURED",
      repositoryVisibilityEvidence: "SNAPSHOT_NON_CLAIM",
      repositoryVisibilityObservedAt: "2026-08-30T00:00:00.000Z",
      scannedUnits: 1, suppressed: 0, tier: "a",
    },
    at: "2026-08-30T00:00:01.000Z",
  });
  const normalLedgerScratch = mkdtempSync(join(tmpdir(), "noa-boundary-ledger-retained-alias-"));
  const normalBoundaryDirectory = join(normalLedgerScratch, ".noa-boundary");
  const normalSpool = boundaryEvidenceSpoolDirectory(normalBoundaryDirectory, "BOUNDARY_GATE_VERDICT");
  const normalInput = ledgerInputFor(normalSpool, "BOUNDARY_GATE_VERDICT");
  const normalDependencies = boundarySpoolTestDependencies({
    pendingNonceHex: "11".repeat(16),
    recordNonceHex: "22".repeat(32),
    statfs: { bavail: "1000000", blocks: "2000000", bsize: "4096" },
    trace: true,
  });
  let normalLedgerProblem = null;
  try {
    const created = appendBoundaryLedgerRecord(normalInput, normalDependencies);
    const existing = appendBoundaryLedgerRecord(normalInput, normalDependencies);
    const census = inspectBoundaryEvidenceSpool({
      spoolDirectoryPath: normalSpool,
      event: "BOUNDARY_GATE_VERDICT",
    });
    if (!created.ok || !created.created || created.evidenceState !== "PERSISTED"
        || !created.cleanupResidue || !created.warning?.includes("cleanup_residue")
        || !existing.ok || !existing.idempotent || existing.created
        || !existing.cleanupResidue || census.validCount !== 1 || census.pendingCount !== 1
        || census.cleanupResidueCount !== 1 || census.malformedCount !== 0) {
      normalLedgerProblem = "retained quarantine alias did not preserve created/idempotent liveness";
    }
  } catch {
    normalLedgerProblem = "self-test operation failed; detail withheld";
  } finally {
    rmSync(normalLedgerScratch, { recursive: true, force: true });
  }
  if (normalLedgerProblem !== null) {
    setupFailed(
      "the non-deleting evidence spool contract regressed",
      normalLedgerProblem,
      "retain one exact quarantine alias while keeping final evidence idempotently readable",
    );
  }

  const ledgerModuleUrl = new URL("./lib/boundary-ledger.mjs", import.meta.url).href;
  const ledgerScratch = mkdtempSync(join(tmpdir(), "noa-boundary-ledger-wrong-winner-"));
  const boundaryDirectory = join(ledgerScratch, ".noa-boundary");
  const spoolDirectoryPath = boundaryEvidenceSpoolDirectory(boundaryDirectory, "BOUNDARY_GATE_VERDICT");
  const ledgerInput = ledgerInputFor(spoolDirectoryPath, "BOUNDARY_GATE_VERDICT");
  const ledgerOptions = {
    pendingNonceHex: "33".repeat(16),
    recordNonceHex: "44".repeat(32),
    statfs: { bavail: "1000000", blocks: "2000000", bsize: "4096" },
    trace: true,
  };
  const prepared = prepareBoundaryEvidenceRecord(
    ledgerInput,
    boundarySpoolTestDependencies(ledgerOptions),
  );
  const ledgerFinalPath = join(spoolDirectoryPath, prepared.filename);
  const ledgerReleasePath = join(ledgerScratch, ".release");
  const wrongLedgerBytes = Buffer.from("wrong durable ledger winner\n", "utf8");
  const ledgerWorkerSource = String.raw`
    const [moduleUrl, inputJson, optionsJson] = process.argv.slice(1);
    const { appendBoundaryLedgerRecord, boundarySpoolTestDependencies } = await import(moduleUrl);
    const result = appendBoundaryLedgerRecord(
      JSON.parse(inputJson),
      boundarySpoolTestDependencies(JSON.parse(optionsJson)),
    );
    process.stdout.write(JSON.stringify(result));
  `;
  let ledgerProblem = null;
  try {
    const worker = await checkpointedSelftestWorker({
      source: ledgerWorkerSource,
      args: [ledgerModuleUrl, JSON.stringify(ledgerInput), JSON.stringify(ledgerOptions)],
      environment: {
        NOA_BOUNDARY_IMMUTABLE_PAUSE_AT: "final-link-before",
        NOA_BOUNDARY_IMMUTABLE_PAUSE_MS: "5000",
        NOA_BOUNDARY_IMMUTABLE_RELEASE_FILE: ledgerReleasePath,
        NOA_BOUNDARY_IMMUTABLE_TRACE_CHECKPOINTS: "1",
      },
      checkpoint: "NOA_IMMUTABLE_PUBLISH_CHECKPOINT final-link-before",
      onCheckpoint: () => {
        createSelftestFile(ledgerFinalPath, wrongLedgerBytes, 0o400);
        createSelftestFile(ledgerReleasePath, Buffer.from("ready\n", "utf8"), KEY_MODE);
      },
    });
    const result = parseCheckpointWorkerResult(worker);
    const pending = readdirSync(spoolDirectoryPath).filter((name) =>
      name.startsWith(`.pending-v${prepared.schemaVersion}-`));
    const pendingPath = pending.length === 1 ? join(spoolDirectoryPath, pending[0]) : null;
    if (result.ok !== false || result.code !== "SPOOL_RECORD_CONFLICT"
        || result.evidenceState !== "NOT_PERSISTED" || result.evidencePersisted !== false
        || result.pendingResidue !== true || result.cleanupResidue !== true || pendingPath === null
        || !readFileSync(pendingPath).equals(prepared.bytes)
        || permissionBits(lstatSync(pendingPath)) !== 0o400 || lstatSync(pendingPath).nlink !== 1
        || !readFileSync(ledgerFinalPath).equals(wrongLedgerBytes)) {
      ledgerProblem = "wrong-byte EEXIST did not retain pending with NOT_PERSISTED evidence";
    }
  } catch {
    ledgerProblem = "self-test operation failed; detail withheld";
  } finally {
    rmSync(ledgerScratch, { recursive: true, force: true });
  }
  if (ledgerProblem !== null) {
    setupFailed(
      "a wrong-byte ledger winner was reported as persisted evidence",
      ledgerProblem,
      "bind persistence only to exact requested bytes at the authoritative final pathname",
    );
  }

  const rereadScratch = mkdtempSync(join(tmpdir(), "noa-boundary-existing-reread-"));
  const rereadFinalPath = join(rereadScratch, "final");
  const rereadReleasePath = join(rereadScratch, ".release");
  const rereadBytes = Buffer.from("exact final before closing reread\n", "utf8");
  const changedBytes = Buffer.alloc(rereadBytes.length, 0x5a);
  const rereadWorkerSource = String.raw`
    const [moduleUrl, candidatePath, destinationPath, encoded] = process.argv.slice(1);
    const { durablePublishImmutableByLink, durablePublishImmutableByLinkTestDependencies } = await import(moduleUrl);
    const result = durablePublishImmutableByLink({
      candidatePath,
      destinationPath,
      bytes: Buffer.from(encoded, "base64"),
      candidateMode: 0o600,
      immutableMode: 0o400,
      directoryMode: 0o700,
      maxBytes: 4096,
      existingFinalMaxBytes: 4096,
    }, durablePublishImmutableByLinkTestDependencies({ trace: true }));
    process.stdout.write(JSON.stringify(result));
  `;
  let rereadProblem = null;
  try {
    chmodSync(rereadScratch, KEY_DIR_MODE);
    createSelftestFile(rereadFinalPath, rereadBytes, 0o400);
    const worker = await checkpointedSelftestWorker({
      source: rereadWorkerSource,
      args: [
        custodyModuleUrl,
        join(rereadScratch, ".candidate"),
        rereadFinalPath,
        rereadBytes.toString("base64"),
      ],
      environment: {
        NOA_BOUNDARY_IMMUTABLE_PAUSE_AT: "existing-final-closing-read-before",
        NOA_BOUNDARY_IMMUTABLE_PAUSE_MS: "5000",
        NOA_BOUNDARY_IMMUTABLE_RELEASE_FILE: rereadReleasePath,
        NOA_BOUNDARY_IMMUTABLE_TRACE_CHECKPOINTS: "1",
      },
      checkpoint: "NOA_IMMUTABLE_PUBLISH_CHECKPOINT existing-final-closing-read-before",
      onCheckpoint: () => {
        chmodSync(rereadFinalPath, KEY_MODE);
        writeFileSync(rereadFinalPath, changedBytes, { flag: "w" });
        chmodSync(rereadFinalPath, 0o400);
        createSelftestFile(rereadReleasePath, Buffer.from("ready\n", "utf8"), KEY_MODE);
      },
    });
    const result = parseCheckpointWorkerResult(worker);
    if (result.status !== "INDETERMINATE" || result.code !== "FILE_READ_CHANGED"
        || result.persistence !== "INDETERMINATE" || result.candidateResidue !== false
        || !readFileSync(rereadFinalPath).equals(changedBytes)) {
      rereadProblem = `status=${result.status}; code=${result.code}; persistence=${result.persistence}`;
    }
  } catch {
    rereadProblem = "self-test operation failed; detail withheld";
  } finally {
    rmSync(rereadScratch, { recursive: true, force: true });
  }
  if (rereadProblem !== null) {
    setupFailed(
      "closing existing-final verification claimed unverified bytes durable",
      rereadProblem,
      "set exact durability only after the post-fsync stable reread matches the requested bytes",
    );
  }
}

async function main() {
  const argv = process.argv.slice(2);
  // Caller-controlled environment never selects the internal route. Classification is derived only
  // from the closed CLI grammar below, and the bootstrap clears the marker again at parser load.
  clearUntrustedBoundaryBootstrapModeMarker();
  const opts = parseArgs(argv);
  parsedGateOptions = opts;

  // An ordinary candidate invocation is refused before it can enter even the keyless parser
  // bootstrap. The one exception is an explicitly requested synthetic arm: that request is not
  // capability, so it is checked again below only after exact authorized subject + package identity
  // prove this is the disposable arm repository rather than a release candidate.
  const syntheticSupervisorFixtureRequested =
    process.env.NOA_BOUNDARY_SYNTHETIC_SUPERVISOR_FIXTURE === "1";
  const externalAuthorizationTransport = hasExternalAuthorizationTransport();
  const isolatedKnockoutTransport =
    process.env[BOUNDARY_KNOCKOUT_BOOTSTRAP_ENV] !== undefined;
  const candidateEligible = candidateTierANonAuthorityEligible(opts, argv);
  if (isolatedKnockoutTransport && (
    syntheticSupervisorFixtureRequested || externalAuthorizationTransport || !candidateEligible
  )) {
    setupFailed(
      "isolated knockout bootstrap scope",
      "the dedicated direct-child channel cannot combine with external authority, synthetic authority, or a privileged/non-Tier-A route",
      "use the channel only through the retained-arm knockout worker",
    );
  }
  const candidateTierANonAuthority = !syntheticSupervisorFixtureRequested
    && !externalAuthorizationTransport
    && candidateEligible;
  // A sanitized public authorization is parser defense-in-depth, not an N-1 supervisor capability.
  // Refuse every privileged candidate route before parser bootstrap even when that transport exists.
  // The exact synthetic arm remains a test-only exception and is re-bound to its disposable package
  // and subject immediately after bootstrap; it is never release or merge evidence.
  if (supervisorOnlyOperation(opts) && !syntheticSupervisorFixtureRequested
      && !candidateTierANonAuthority) {
    requireExternalBoundarySupervisor(opts, false);
  }
  if (candidateTierANonAuthority) {
    armCandidateTierANonAuthorityBootstrap({ root: ROOT });
  } else if (!syntheticSupervisorFixtureRequested && !externalAuthorizationTransport) {
    requireExternalBoundarySupervisor(opts, false, { missingChannel: true });
  }

  if (opts.recoverExclusionRotation) verifyRecoveryOnlyBootstrap();
  else await loadParserBackedBoundaryScanner();
  const syntheticSupervisorFixture = syntheticSupervisorFixtureAuthorized();
  if (syntheticSupervisorFixtureRequested && !syntheticSupervisorFixture) {
    requireExternalBoundarySupervisor(opts, false, { missingChannel: true });
  }
  assertLoadedBootstrapAuthority(candidateTierANonAuthority
    ? BOUNDARY_AUTHORITY_CLASS_CANDIDATE_TIER_A
    : BOUNDARY_AUTHORITY_CLASS_EXTERNAL);
  if (!candidateTierANonAuthority) {
    requireExternalBoundarySupervisor(opts, syntheticSupervisorFixture);
  }

  assertLaneRegistry();

  if (opts.custodyContractSelftest) {
    proveImmutablePublicationResultContract();
    proveDurableCreateFailureContracts();
    await proveSameUidCandidateSwapRetention();
    await proveConcurrentWinnerContracts();
    process.stdout.write("boundary custody contracts: PASS\n");
    return;
  }

  if (opts.outputContractSelftest) {
    const failures = outputContractFailures();
    if (!opts.knockoutJson) process.stdout.write(failures.length === 0
      ? "boundary output contracts: PASS\n"
      : "boundary output contracts: FAIL\n");
    if (failures.length === 0) {
      exitSuccessfulBoundaryOperation(opts);
    }
    if (opts.knockoutJson) emitBoundaryGateEvidence(failures);
    process.exit(1);
  }

  if (opts.selftest || opts.spoolSelftest) {
    if (opts.spoolSelftest) {
      proveImmutablePublicationResultContract();
      proveDurableCreateFailureContracts();
      await proveSameUidCandidateSwapRetention();
      await proveConcurrentWinnerContracts();
    }
    const { runArm } = await import("./lib/boundary-arm.mjs");
    process.exit(await runArm({
      root: ROOT,
      knockoutJson: opts.knockoutJson,
      spoolOnly: opts.spoolSelftest,
    }));
  }

  // The gate must be measuring the tree it thinks it is measuring.
  const toplevel = capture("git", ["rev-parse", "--show-toplevel"], { cwd: opts.root }).out.trim();
  if (resolve(toplevel) !== resolve(opts.root)) {
    setupFailed(
      "the gate is not at the root of the repository it is scanning",
      `script root ${opaquePathId(opts.root)}\n  git toplevel ${opaquePathId(toplevel)}\n  Scanning a different tree than the one being pushed is how a green describes the wrong bytes.`,
      "run the gate from inside its own repository",
    );
  }

  // Replacement refs are disabled for every Git child. Legacy grafts are a separate physical
  // history alias, so any non-empty or unreadable graft file makes the pushed object view unknown.
  const graftPath = capture(
    "git",
    ["rev-parse", "--path-format=absolute", "--git-path", "info/grafts"],
    { cwd: opts.root },
  ).out.trim();
  if (graftPath.length === 0) {
    setupFailed("Git did not resolve its legacy graft path", "an unknown object view cannot be compared with publication bytes", null);
  }
  if (existsSync(graftPath)) {
    let graftBytes;
    try { graftBytes = readFileSync(graftPath); } catch {
      setupFailed("the legacy Git graft file cannot be inspected", "an unreadable history override makes the physical push view unknown", "remove the legacy graft configuration");
    }
    if (graftBytes.length > 0) {
      setupFailed(
        "a non-empty legacy Git graft file changes commit reachability",
        "legacy grafts are not disabled by GIT_NO_REPLACE_OBJECTS; remove the graft before trusting a publication-boundary scan",
        "remove or migrate info/grafts, then rerun the gate",
      );
    }
  }
  const repositoryHead = capture("git", ["rev-parse", "HEAD"], { cwd: opts.root }).out.trim();
  if (!/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(repositoryHead)) {
    setupFailed("the repository HEAD identity is malformed", "the evidence ledger requires one exact full Git object id", "repair repository custody before scanning");
  }

  if (opts.refsFromStdin || opts.publishPath) {
    try {
      const hook = verifyBoundaryHookActivation(opts.root);
      say(yellow(
        `  ${hook.status}: effective hooks path ${opaquePathId(hook.hooksPath)}; ` +
        "--no-verify and independent malicious-candidate enforcement remain NON-CLAIM.",
      ));
    } catch (error) {
      const failure = boundaryBootstrapFailure(error);
      setupFailed(failure.subject, `${failure.bootstrapCode}: ${failure.detail}`, failure.fix);
    }
  }

  if (opts.migrateExclusions || opts.recoverExclusionRotation || opts.rotateExclusions) {
    migrateExclusions(opts, opts.root);
    exitSuccessfulBoundaryOperation(opts);
  }

  if (opts.repoVisibilitySource === null) {
    setupFailed(
      "the repository-visibility evidence source was not selected",
      "snapshot and live provider truth are different claims; choosing silently would let a stale snapshot masquerade as current visibility",
      "supply exactly --repo-visibility-source snapshot or --repo-visibility-source live",
    );
  }

  if (opts.refreshPublicRepos || opts.refreshTokens) {
    if (opts.repoVisibilitySource !== "live") {
      setupFailed("a boundary refresh was requested without live visibility evidence", "refresh operations require --repo-visibility-source live", null);
    }
    const live = queryLiveRepoTruth(opts.root);
    if (opts.refreshPublicRepos) refreshPublicRepos(opts.root, live);
    const snapshot = loadPublicRepoSnapshot();
    if (repoVisibilityFingerprint(snapshot).digest !== repoVisibilityFingerprint(live.publicRepos).digest) {
      setupFailed(
        "the committed PUBLIC snapshot differs from the coupled live refresh observation",
        "token refresh cannot authenticate private inputs beside a stale public visibility baseline",
        "refresh public repositories first, review and freeze that public-only diff, then rerun token refresh separately",
      );
    }
    if (opts.refreshTokens) refreshTokens(opts.root, live.privateForms);
    exitSuccessfulBoundaryOperation(opts);
  }

  const stdin = opts.refsFromStdin ? readFileSync(0, "utf8") : "";
  const visibility = loadRepoVisibility(opts.root, opts.repoVisibilitySource);
  const safeCompounds = publicTokenCompounds(visibility.publicRepos);
  const tierB = loadTierB(opts.tier, visibility);
  const { doc: knownDoc, byKey: known } = loadKnownExposure();

  const ctx = {
    opts, root: opts.root, stdin, publicRepos: visibility.publicRepos,
    publicTokenCompounds: safeCompounds,
    visibilityEvidence: visibility.evidence,
    visibilityObservedAt: visibility.observedAt, tierB,
    unscanned: [], structuralFindings: [], sensitivePathReports: new Map(), unitKeys: new Map(), packed: null, ranges: null,
    objectIdLength: objectIdLength(opts.root), refLineCount: 0, destinationRefs: null,
    prePushDestinationVerified: false, commitSets: new Map(),
  };
  ctx.ranges = resolveRanges(ctx);

  // `--require-lane X` means "run X and refuse if it had no input". The first version only checked
  // the requirement for lanes that happened to be selected, so `--lane L-WT --require-lane L-IDX`
  // exited 0 with L-IDX never run — a requirement that silently requires nothing. The arm caught it.
  const mandatoryPushLanes = opts.refsFromStdin ? ["L-PUSH", "L-MSG", "L-TAG"] : [];
  const selected = [...new Set([
    ...(opts.lanes ?? (ctx.ranges.length > 0 || opts.refsFromStdin ? APPROVED_BOUNDARY_LANES : DEFAULT_LANES)),
    ...opts.requireLanes,
    ...mandatoryPushLanes,
  ])];
  const needPacked = selected.includes("L-PACK") || selected.includes("L-MAP");
  ctx.packed = needPacked ? packedSets(ctx) : [];

  say(bold("\n  L12 boundary gate"));
  say(visibility.evidence === "LIVE_PROVIDER_VERIFIED"
    ? `  repository visibility ${green("LIVE PROVIDER VERIFIED")}`
    : `  repository visibility ${yellow("SNAPSHOT — NON-CLAIM; not current provider proof")}`);
  say(`  tier ${opts.tier === "a" ? yellow("A only — TIER-B UNMEASURED") : `A+B (${tierB.count} commitments, key ${tierB.keyId})`}`);

  const laneReports = [];
  const findings = [];
  const suppressed = [];
  let scannedUnits = 0;

  for (const id of selected) {
    const lane = laneById(id);
    const result = ENUMERATORS[id](ctx);
    const status = result.status ?? (result.units.length === 0 ? "empty" : "scanned");

    if (status === "empty" && lane.mustNotBeEmpty) {
      setupFailed(
        `lane ${id} derived zero units`,
        `enumerator: ${lane.enumerator}\n  ${lane.covers}\n  Zero here means the DERIVATION is broken, not that the tree is clean.`,
        null,
      );
    }
    if (status === "skipped" && opts.requireLanes.includes(id)) {
      setupFailed(`lane ${id} was required but had no input`, `enumerator: ${lane.enumerator}`, "supply --range or --refs-from-stdin");
    }

    for (const u of result.units) if (!ctx.unitKeys.has(u.path)) ctx.unitKeys.set(u.path, contentKey(u.text));
    for (const u of result.units) {
      const r = scanUnit(u, ctx);
      for (const f of [...r.findings, ...r.suppressed]) f.lane = id;
      findings.push(...r.findings);
      suppressed.push(...r.suppressed);
    }
    scannedUnits += result.units.length;
    laneReports.push({ id, status, units: result.units.length, note: result.note ?? "" });
  }

  for (const f of ctx.structuralFindings) {
    f.lane = "L-MAP";
    const reportId = ctx.sensitivePathReports.get(f.pathIdentity);
    Object.assign(f, redactContentFinding(f, reportId ?? f.file));
    delete f.pathIdentity;
    findings.push(f);
  }

  const credentialFindings = publishCredentialFindings(ctx.root);
  if (opts.publishPath) for (const f of credentialFindings) { f.lane = "L-PACK"; findings.push(f); }

  // ── refusals that are not findings ─────────────────────────────────────────────────────────────
  if (laneReports.every((l) => l.status === "skipped")) {
    setupFailed("every selected lane skipped", `selected: ${selected.join(", ")}`, "select a lane with input, or drop --lane");
  }
  if (ctx.unscanned.length > 0) {
    setupFailed(
      `${ctx.unscanned.length} unit(s) could not be read`,
      `A skipped file is not a clean file.\n  ${ctx.unscanned.slice(0, 10).join("\n  ")}`,
      null,
    );
  }

  // ── the ratchet ────────────────────────────────────────────────────────────────────────────────
  //
  // DEDUPED FIRST. `CHANGELOG.md` is enumerated by the working-tree lane AND by the packed lane, and
  // the ratchet key is the CONTENT digest, so the same exposure would otherwise be counted twice —
  // and then a run over one lane would look like it had "beaten" a ledger written from two. An
  // exposure is one piece of content, one rule, one line, one matched text; how many enumerators
  // reached it is a property of the run, not of the exposure.
  const seen = new Set();
  const distinct = [];
  for (const f of findings) {
    const identity = `${f.unitKey}:${f.rule}:${f.line}:${f.digest}`;
    if (seen.has(identity)) continue;
    seen.add(identity);
    distinct.push(f);
  }
  const groups = new Map();
  for (const f of distinct) {
    const key = `${f.unitKey}:${f.rule}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(f);
  }

  // A path can itself be the confidential label. Apply the same scanners to every operator/evidence
  // label before rendering it, not only to review-candidate output. The cache keeps this bounded when
  // many findings share one unit.
  const safeLabel = makeSafeLabeler({ publicRepos: ctx.publicRepos, tierB: ctx.tierB });

  // ── review-only candidate printer ──────────────────────────────────────────────────────────────
  //
  // Prints the SHAPE of a ledger entry and refuses to write one: `why` and `remediation` are left
  // empty, and an empty one is rejected at load with exit 2. Seeding this ledger is a reviewed human
  // act by construction — the tool can say WHAT is exposed and never WHY it is acceptable to carry.
  // Exits 2 because this run produced no verdict, and a reporting mode must not be wireable into CI
  // as if it had.
  if (opts.printExposureCandidates) {
    // A PATH CAN ITSELF BE THE SECRET, and the first seeding of this ledger proved it: an entry
    // listed a filename that is a committed label, and the gate refused its own ledger on the very
    // next run. Correct refusal. So the printer redacts by CONSTRUCTION rather than by the care of
    // whoever runs it — every emitted label is passed through the same scanners the gate uses, and
    // anything that fires comes out masked. The ledger must never become a map of where to look.
    const out = renderExposureCandidates(groups, safeLabel);
    process.stdout.write(`${JSON.stringify(out, null, 2)}\n`);
    say(yellow(`\n  ${out.length} candidate group(s) printed. NOTHING was written.`));
    say(`  Fill in why and remediation by hand; an entry without both is refused at load.`);
    process.exit(2);
  }
  const blocking = [];
  const carried = [];
  const beatsLedger = [];
  for (const [key, group] of groups) {
    const entry = known.get(key);
    if (entry === undefined) { blocking.push(...group); continue; }
    if (group.length > entry.count) { blocking.push(...group); continue; }
    if (group.length < entry.count) beatsLedger.push({ key, was: entry.count, now: group.length });
    carried.push({ key, entry, group });
  }

  // ── the ratchet WRITER — it can only tighten ───────────────────────────────────────────────────
  //
  // The writer NEVER adds a key and never raises a count. This repository has already paid for a
  // baseline writer that wrote the new number without reading the old one: a forbidden construct went
  // RED on an authorisation path, and the repository's own command then wrote the higher number and
  // turned it GREEN. A ratchet that can raise its own floor has no floor. Adding an entry stays a
  // hand edit with a stated why and remediation, which is what makes it a reviewed act.
  if (opts.tightenKnownExposure) {
    const next = [];
    let lowered = 0, dropped = 0;
    for (const e of knownDoc.entries) {
      const now = groups.get(e.key)?.length ?? 0;
      if (now === 0) { dropped++; continue; }
      if (now < e.count) { lowered++; next.push({ ...e, count: now, tightenedAt: new Date().toISOString() }); continue; }
      next.push(e);
    }
    writeFileSync(KNOWN_EXPOSURE_PATH, `${JSON.stringify({ ...knownDoc, entries: next }, null, 2)}\n`);
    say(green(`  tightened ${relative(ROOT, KNOWN_EXPOSURE_PATH)} — ${lowered} lowered, ${dropped} discharged, ${next.length} remaining.`));
    say(`  Nothing was added and no count was raised: this writer can only tighten.`);
    exitSuccessfulBoundaryOperation(opts);
  }

  // ── report ─────────────────────────────────────────────────────────────────────────────────────
  say("");
  for (const l of laneReports) {
    const lane = laneById(l.id);
    const mark = l.status === "scanned" ? green("scanned") : l.status === "skipped" ? yellow("SKIPPED") : yellow(l.status);
    say(`  ${l.id.padEnd(7)} ${mark.padEnd(18)} ${String(l.units).padStart(5)} unit(s)   ${lane.title} — ${l.note}`);
  }
  say(`\n  ${scannedUnits} unit(s) scanned across ${laneReports.filter((l) => l.status === "scanned").length} active lane(s); 0 unreadable.`);
  if (suppressed.length > 0) say(yellow(`  ${suppressed.length} inline suppression(s) in force — counted, never invisible.`));
  if (carried.length > 0) {
    // LOUD, and grouped by rule so it stays readable. A carried exposure that scrolls past unread is
    // an allowlist; a carried exposure named on every run, with its remediation, is a debt.
    const byRule = new Map();
    for (const c of carried) {
      const rule = c.group[0].rule;
      const agg = byRule.get(rule) ?? { findings: 0, files: new Set(), remediation: c.entry.remediation, severity: c.group[0].severity };
      agg.findings += c.group.length;
      for (const f of c.group) agg.files.add(f.file);
      byRule.set(rule, agg);
    }
    say(yellow(`  CARRIED — ${carried.reduce((n, c) => n + c.group.length, 0)} already-published finding(s) held by the known-exposure ledger.`));
    say(yellow(`  These are NOT clean. They are exposures the next push cannot un-publish:`));
    for (const [rule, agg] of [...byRule].sort()) {
      say(yellow(`    ${agg.severity.toUpperCase().padEnd(8)} ${rule.padEnd(20)} ${String(agg.findings).padStart(3)} finding(s) in ${agg.files.size} file(s)`));
      say(`             ${agg.remediation}`);
    }
  }
  for (const b of beatsLedger) say(bold(yellow(`  the ledger allows ${b.was} for ${b.key.slice(0, 12)}… and reality is now ${b.now}. Lower it in this commit: --tighten-known-exposure`)));
  if (!opts.publishPath && credentialFindings.length > 0) {
    say(yellow(`\n  UNCLOSED LAYER: ${credentialFindings.length} local registry credential(s) present. A direct`));
    say(yellow(`  "npm publish --ignore-scripts" from this machine would authenticate, and no local script`));
    say(yellow(`  can intercept that. One command closes it: npm logout`));
  }

  if (blocking.length > 0) {
    say(red(bold(`\n  ${blocking.length} boundary finding(s):\n`)));
    blocking.sort((a, b) => (a.file === b.file ? a.line - b.line : a.file < b.file ? -1 : 1));
    for (const f of blocking.slice(0, 200)) {
      for (const line of renderTerminalFinding(f, safeLabel)) say(line);
      if (opts.explain) {
        const lane = laneById(f.lane);
        say(`           why:  ${f.why}`);
        say(`           lane: ${f.lane} — in scope because: ${lane?.enumerator ?? "structural"}`);
        say(`           fix:  ${f.fix}`);
        say(
          INLINE_SUPPRESSIBLE_NOTE(f),
        );
      }
    }
    if (blocking.length > 200) say(`  … and ${blocking.length - 200} more`);
    if (!opts.explain) say(yellow(`\n  Re-run with --explain for the rule, the enumerator that put each file in scope, and the fix.`));
  }

  const verdict = blocking.length === 0 ? "GREEN" : "RED";
  if (boundaryBootstrapAuthority.authorityClass === BOUNDARY_AUTHORITY_CLASS_CANDIDATE_TIER_A) {
    say(`  ${CANDIDATE_TIER_A_NON_AUTHORITY_NON_CLAIM}; external evidence ledger NOT_WRITTEN.`);
  } else {
    writeLedger({
      repositoryHead,
      verdict, lanes: laneReports, scannedUnits, blocking: blocking.length,
      carried: carried.reduce((n, c) => n + c.group.length, 0), suppressed: suppressed.length,
      tier: opts.tier, keyId: tierB.enabled ? tierB.keyId : null,
      repositoryVisibilityEvidence: ctx.visibilityEvidence,
      repositoryVisibilityObservedAt: ctx.visibilityObservedAt,
      privateInputsEvidence: tierB.enabled ? tierB.privateInputsEvidence : "TIER_B_UNMEASURED",
      ledgerEntries: knownDoc.entries.length,
    });
  }

  if (blocking.length === 0) {
    if (!opts.knockoutJson) {
      say(green(bold(`\n  GREEN — ${scannedUnits} unit(s), 0 unratcheted findings.\n`)));
    }
    exitSuccessfulBoundaryOperation(opts);
  }
  if (opts.knockoutJson) {
    emitBoundaryGateEvidence(renderGateFindings(blocking, safeLabel));
    process.exit(1);
  }
  say(red(bold(`\n  RED — the boundary refuses ${blocking.length} finding(s).\n`)));
  process.exit(1);
}

function INLINE_SUPPRESSIBLE_NOTE(f) {
  if (f.severity === SEVERITY.CRITICAL) {
    return `           note: CRITICAL findings have no inline override. Fix the text, or record it in\n` +
      `                 ${relative(ROOT, KNOWN_EXPOSURE_PATH)} with a why and a remediation — which prints on every run.`;
  }
  return `           or:   noa-boundary-ok:${f.digest}:<one-word-reason>   (pinned to this exact text; edit the line and it stops applying)`;
}

main().catch(() => {
  if (process.argv.includes("--knockout-json")) {
    emitBoundaryGateEvidence([{
      rule: "SETUP_FAILED",
      subject: "the gate itself threw",
      detail: "the exception is withheld because it may contain untrusted publication bytes",
    }]);
    process.exit(2);
  }
  process.stderr.write(red(bold(`\n  lint-boundary: SETUP_FAILED — the gate itself threw\n`)));
  process.stderr.write("  the exception is withheld because it may contain untrusted publication bytes\n\n");
  process.exit(2);
});
