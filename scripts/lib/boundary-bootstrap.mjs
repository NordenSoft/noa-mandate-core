/**
 * Stdlib-only bootstrap for the public-boundary parser and its release-call closure.
 *
 * This is defense in depth, not an independent release authority. These bytes live in the same
 * candidate they inspect. An independently pinned supervisor must verify the external policy's
 * full file list/digest/HMAC before it executes any candidate byte. The deterministic manifest
 * schema exported here exists so that supervisor can consume the same exact contract.
 */

import { spawnSync } from "node:child_process";
import { createHash, timingSafeEqual } from "node:crypto";
import {
  closeSync,
  constants as fsConstants,
  fstatSync,
  lstatSync,
  openSync,
  readdirSync,
  readSync,
  realpathSync,
} from "node:fs";
import { dirname, isAbsolute, join, normalize, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

export const BOUNDARY_CONTROL_MANIFEST_VERSION = 2;
export const BOUNDARY_RUNTIME_ATTESTATION_SCHEMA_VERSION = 1;
export const BOUNDARY_RUNTIME_AUTHORIZATION_SCHEMA_VERSION = 1;
export const BOUNDARY_TYPESCRIPT_VERSION = "5.9.3";
export const BOUNDARY_NODE_VERSION = "22.22.2";
export const BOUNDARY_HOOKS_PATH = "scripts/hooks";
export const BOUNDARY_AUTHORITY_CLASS_EXTERNAL =
  "EXTERNAL_SANITIZED_AUTHORIZATION_DEFENSE_IN_DEPTH_NON_AUTHORITY";
export const BOUNDARY_AUTHORITY_CLASS_CANDIDATE_TIER_A = "CANDIDATE_TIER_A_NON_AUTHORITY";
export const BOUNDARY_BOOTSTRAP_MODE_CANDIDATE_TIER_A_NON_AUTHORITY =
  "candidate-tier-a-non-authority";
export const BOUNDARY_KNOCKOUT_BOOTSTRAP_ENV = "NOA_BOUNDARY_KNOCKOUT_CAPABILITY_FD";
const BOUNDARY_KNOCKOUT_BOOTSTRAP_PROTOCOL = "noa-boundary-knockout-bootstrap/1";
const BOUNDARY_SCANNER_SELFTEST_BOOTSTRAP_PROTOCOL =
  "noa-boundary-scanner-selftest-bootstrap/1";
export const EXTERNAL_SANITIZED_AUTHORIZATION_NON_CLAIM =
  "CANDIDATE_SANITIZED_AUTHORIZATION_IS_NOT_MERGE_EVIDENCE";
export const CANDIDATE_TIER_A_NON_AUTHORITY_NON_CLAIM =
  "CANDIDATE_TIER_A_RESULT_IS_NOT_N_MINUS_1_TIER_B_OR_RELEASE_AUTHORITY";

export const BOUNDARY_AUTHORITY_NON_CLAIMS = Object.freeze([
  "CANDIDATE_BOOTSTRAP_IS_NOT_AN_INDEPENDENT_RELEASE_AUTHORITY",
  "LOCAL_HOOK_CONFIGURATION_DOES_NOT_PREVENT_NO_VERIFY_OR_OTHER_BYPASS",
  "AUTHORITATIVE_TIER_B_AND_ROTATION_REQUIRE_EXTERNAL_N_MINUS_1_SUPERVISOR",
  EXTERNAL_SANITIZED_AUTHORIZATION_NON_CLAIM,
]);

// This is the exact historical seven-path surface carried by the active schema-v3 predecessor.
// It is accepted only as authenticated recovery evidence. It never authorizes parser execution or
// a fresh expanded-manifest policy.
export const PREVIOUS_REVIEWED_CONTROL_PATHS = Object.freeze([
  "package.json",
  "scripts/boundary-repo-reference-policy.json",
  "scripts/lib/boundary-arm.mjs",
  "scripts/lib/boundary-scan.mjs",
  "scripts/lib/boundary-scan.selftest.mjs",
  "scripts/lint-boundary.mjs",
  "scripts/pre-push-gate.mjs",
]);

export const REVIEWED_CONTROL_PATHS = Object.freeze([
  ".github/workflows/boundary.yml",
  ".github/workflows/publish-surface-lint.yml",
  ".node-version",
  "package-lock.json",
  "package.json",
  "scripts/boundary-known-exposure.json",
  "scripts/boundary-public-repos.json",
  "scripts/boundary-runtime-attestation.json",
  "scripts/hooks/pre-push",
  "scripts/install-hooks.mjs",
  "scripts/lib/boundary-arm.mjs",
  "scripts/lib/boundary-bootstrap.mjs",
  "scripts/lib/boundary-bootstrap.selftest.mjs",
  "scripts/lib/boundary-custody.mjs",
  "scripts/lib/boundary-external-authority.mjs",
  "scripts/lib/boundary-external-authority.selftest.mjs",
  "scripts/lib/boundary-gate-provenance.mjs",
  "scripts/lib/boundary-lanes.mjs",
  "scripts/lib/boundary-ledger.mjs",
  "scripts/lib/boundary-ledger.selftest.mjs",
  "scripts/lib/boundary-scan.mjs",
  "scripts/lib/boundary-scan.selftest.mjs",
  "scripts/lib/boundary-spool-arm.selftest.mjs",
  "scripts/lib/boundary-token.mjs",
  "scripts/lib/gate-event-contract.mjs",
  "scripts/lib/knockout-runner.mjs",
  "scripts/lib/knockout-test-observer.mjs",
  "scripts/lib/knockout-workspace-worker.mjs",
  "scripts/lib/knockout-workspace.mjs",
  "scripts/lib/npm-homedir-override.cjs",
  "scripts/lib/proof-event-contract.mjs",
  "scripts/lib/proof-event-reporter.mjs",
  "scripts/lib/proof-resolve.mjs",
  "scripts/lib/publish-artifact-executor.mjs",
  "scripts/lib/publish-artifact-policy.json",
  "scripts/lib/publish-artifact-staging.mjs",
  "scripts/lib/publish-container-driver.mjs",
  "scripts/lib/safe-npm-tarball.mjs",
  "scripts/lib/stage-publish-artifacts.mjs",
  "scripts/lib/typescript-test-hooks.mjs",
  "scripts/lib/typescript-test-register.mjs",
  "scripts/lint-boundary.mjs",
  "scripts/lint-control-knockout.mjs",
  "scripts/lint-published-surface.mjs",
  "scripts/pre-push-gate.mjs",
  "scripts/prepush-baseline.json",
  "scripts/stage-publish-artifacts.selftest.mjs",
]);

const ATTESTATION_KEYS = Object.freeze([
  "files", "lock", "moduleFormat", "node", "nonClaims", "package", "runtime", "schemaVersion",
]);
const AUTHORIZATION_KEYS = Object.freeze([
  "channel", "controlManifest", "controllerId", "expiresAt", "issuedAt", "nonce",
  "nonClaims", "operation", "schemaVersion", "subject",
]);
const HEX_64_RE = /^[0-9a-f]{64}$/;
const SHA512_SRI_RE = /^sha512-[A-Za-z0-9+/]+={0,2}$/;
const MAX_AUTHORIZATION_BYTES = 1024 * 1024;
const MAX_KNOCKOUT_BOOTSTRAP_BYTES = 16 * 1024;
const MAX_CONTROL_BYTES = 32 * 1024 * 1024;
const RUNTIME_ATTESTATION_PATH = "scripts/boundary-runtime-attestation.json";
const UNTRUSTED_INTERNAL_MODE_ENV = "NOA_BOUNDARY_INTERNAL_BOOTSTRAP_MODE";
let candidateTierANonAuthorityRoot = null;
const isolatedScannerSelftestBootstrapStates = new WeakMap();

const GIT_OBJECT_ID_RE = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const CLOSED_GIT_HOME = "/var/empty/noa-boundary-git-home";
const READ_ONLY_GIT_TIMEOUT_MS = 30_000;
const MAX_GIT_OUTPUT_BYTES = 512 * 1024 * 1024;
const MAX_GIT_STORAGE_ENTRIES = 1_000_000;

/**
 * One closed environment for every Git observation over provenance source bytes.
 *
 * Ambient Git variables can redirect the index, object store, work tree, common directory, config,
 * hooks, pager, SSH transport, or credential helper. Copying `process.env` and merely adding
 * `GIT_OPTIONAL_LOCKS=0` therefore does not make an observation read-only. This helper removes the
 * whole override/credential class and then adds only fixed non-interactive read controls.
 */
export function scrubbedReadOnlyGitEnvironment(_source = process.env) {
  return {
    GCM_INTERACTIVE: "Never",
    GIT_ATTR_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_SYSTEM: "/dev/null",
    GIT_NO_REPLACE_OBJECTS: "1",
    GIT_OPTIONAL_LOCKS: "0",
    GIT_PAGER: "cat",
    GIT_TERMINAL_PROMPT: "0",
    HOME: CLOSED_GIT_HOME,
    LANG: "C",
    LC_ALL: "C",
    PAGER: "cat",
    PATH: "/usr/bin:/bin",
    XDG_CONFIG_HOME: CLOSED_GIT_HOME,
  };
}

function assertReadOnlyGitArguments(args) {
  if (!Array.isArray(args) || args.length === 0 || args.some((arg) => typeof arg !== "string")) {
    fail("BOUNDARY_BOOTSTRAP_GIT_ARGUMENT_REJECTED", "read-only Git observation", "arguments must be a non-empty string array");
  }
  const [command, ...rest] = args;
  const exact = JSON.stringify(args);
  const allowed = (command === "archive"
      && rest.length === 2 && rest[0] === "--format=tar" && GIT_OBJECT_ID_RE.test(rest[1]))
    || (command === "config" && [
      JSON.stringify(["config", "--local", "--no-includes", "--null", "--list"]),
      JSON.stringify(["config", "--local", "--no-includes", "--get", "remote.origin.url"]),
      JSON.stringify(["config", "--no-includes", "--get", "core.hooksPath"]),
    ].includes(exact))
    || (command === "rev-parse" && rest.length === 1 && [
      "HEAD", "--absolute-git-dir", "--git-common-dir",
      "--show-toplevel",
    ].includes(rest[0]))
    || (command === "rev-parse" && exact === JSON.stringify(["rev-parse", "--git-path", "objects"]))
    || (command === "rev-parse" && rest.length === 1
      && /^(?:[0-9a-f]{40}|[0-9a-f]{64})\^\{tree\}$/.test(rest[0]));
  if (!allowed) {
    fail(
      "BOUNDARY_BOOTSTRAP_GIT_ARGUMENT_REJECTED",
      "read-only Git observation",
      `arguments ${exact} are outside the closed observation grammar`,
    );
  }
}

/** Run one allow-listed Git observation with no ambient redirection and no optional index lock. */
export function readOnlyGitOutput(root, args, { binary = false, maxBuffer = 512 * 1024 * 1024 } = {}) {
  assertReadOnlyGitArguments(args);
  if (!Number.isSafeInteger(maxBuffer) || maxBuffer <= 0 || maxBuffer > MAX_GIT_OUTPUT_BYTES) {
    fail("BOUNDARY_BOOTSTRAP_GIT_ARGUMENT_REJECTED", "read-only Git observation", "output bound is invalid");
  }
  const result = spawnSync("/usr/bin/git", args, {
    cwd: resolve(root),
    encoding: binary ? null : "utf8",
    env: scrubbedReadOnlyGitEnvironment(),
    maxBuffer,
    shell: false,
    timeout: READ_ONLY_GIT_TIMEOUT_MS,
  });
  const stderr = binary
    ? Buffer.from(result.stderr ?? Buffer.alloc(0))
    : String(result.stderr ?? "");
  if (result.status !== 0 || result.error !== undefined || stderr.length !== 0) {
    const error = new Error("read-only Git observation failed");
    error.code = "READ_ONLY_GIT_FAILED";
    error.status = result.status;
    error.stderr = stderr;
    throw error;
  }
  if (binary) return Buffer.from(result.stdout ?? Buffer.alloc(0));
  const stdout = String(result.stdout ?? "");
  if (!stdout.endsWith("\n") || stdout.slice(0, -1).includes("\n")
      || /[\u0000\r\u0085\u2028\u2029]/u.test(stdout)) {
    const error = new Error("read-only Git observation returned a malformed text record");
    error.code = "READ_ONLY_GIT_FAILED";
    error.status = result.status;
    error.stderr = stderr;
    throw error;
  }
  return stdout.slice(0, -1);
}

export class BoundaryBootstrapError extends Error {
  constructor(code, subject, detail, fix = null) {
    super(`${code}: ${subject}`);
    this.name = "BoundaryBootstrapError";
    this.code = code;
    this.subject = subject;
    this.detail = detail;
    this.fix = fix;
  }
}

const fail = (code, subject, detail, fix = null) => {
  throw new BoundaryBootstrapError(code, subject, detail, fix);
};

/**
 * A caller-controlled environment value can never select an internal bootstrap route. Clear the
 * reserved name both in the entry point before option classification and again at parser load, so
 * direct imports fail closed even when a caller attempts to inject the implementation marker.
 */
export function clearUntrustedBoundaryBootstrapModeMarker() {
  const present = process.env[UNTRUSTED_INTERNAL_MODE_ENV] !== undefined;
  delete process.env[UNTRUSTED_INTERNAL_MODE_ENV];
  return present;
}

/**
 * Arm one in-process, one-shot Tier-A parser load. This grants no external-policy authority and is
 * deliberately not an environment transport. The CLI calls it only after closed option parsing has
 * classified one snapshot, non-mutating Tier-A invocation. Supplying an external authorization at
 * the same time is ambiguous and therefore refused instead of silently downgrading that transport.
 */
export function armCandidateTierANonAuthorityBootstrap({ root } = {}) {
  clearUntrustedBoundaryBootstrapModeMarker();
  if (process.env.NOA_BOUNDARY_AUTHORIZATION_FD !== undefined
      || process.env.NOA_BOUNDARY_AUTHORIZATION_FILE !== undefined) {
    fail(
      "BOUNDARY_BOOTSTRAP_AUTHORIZATION_CHANNEL_AMBIGUOUS",
      "boundary bootstrap authority class",
      "candidate Tier-A non-authority mode and an external sanitized authorization cannot be combined",
    );
  }
  if (candidateTierANonAuthorityRoot !== null) {
    fail(
      "BOUNDARY_BOOTSTRAP_MODE_INVALID",
      "candidate Tier-A bootstrap mode",
      "the one-shot in-process candidate route was armed more than once",
    );
  }
  const isolatedKnockout = process.env[BOUNDARY_KNOCKOUT_BOOTSTRAP_ENV] !== undefined;
  if (isolatedKnockout && process.env[BOUNDARY_KNOCKOUT_BOOTSTRAP_ENV] !== "0") {
    delete process.env[BOUNDARY_KNOCKOUT_BOOTSTRAP_ENV];
    fail(
      "BOUNDARY_BOOTSTRAP_AUTHORIZATION_FD_MISSING",
      "isolated knockout bootstrap channel",
      "the dedicated direct-child descriptor must be exact stdin FD 0",
    );
  }
  candidateTierANonAuthorityRoot = Object.freeze({
    isolatedKnockout,
    root: resolve(root ?? join(dirname(fileURLToPath(import.meta.url)), "..", "..")),
  });
  return Object.freeze({
    authorityClass: BOUNDARY_AUTHORITY_CLASS_CANDIDATE_TIER_A,
    nonClaim: CANDIDATE_TIER_A_NON_AUTHORITY_NON_CLAIM,
  });
}

export function canonicalBoundaryJson(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number" && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((item) => canonicalBoundaryJson(item)).join(",")}]`;
  if (typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) =>
      `${JSON.stringify(key)}:${canonicalBoundaryJson(value[key])}`).join(",")}}`;
  }
  throw new TypeError("unsupported canonical JSON value");
}

function exactKeys(value, expected, subject) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail("BOUNDARY_BOOTSTRAP_SCHEMA_INVALID", subject, "expected one exact JSON object");
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    fail("BOUNDARY_BOOTSTRAP_SCHEMA_INVALID", subject, "required and observed object keys differ");
  }
}

function exactHex(left, right) {
  return HEX_64_RE.test(String(left)) && HEX_64_RE.test(String(right))
    && timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function sameIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function sameState(left, right) {
  return sameIdentity(left, right) && left.mode === right.mode && left.nlink === right.nlink
    && left.uid === right.uid && left.gid === right.gid && left.size === right.size
    && left.mtimeMs === right.mtimeMs && left.ctimeMs === right.ctimeMs;
}

function safeRelativePath(value, subject) {
  if (typeof value !== "string" || value.length === 0 || value.length > 512
      || isAbsolute(value) || value.includes("\\") || value.includes("\0")
      || normalize(value) !== value || value.split("/").some((part) => part.length === 0 || part === "." || part === "..")) {
    fail("BOUNDARY_BOOTSTRAP_PATH_INVALID", subject, "path must be one canonical repository-relative POSIX path");
  }
  return value;
}

function inspectDirectory(path, subject, { ownerOnly = false } = {}) {
  let stat;
  try { stat = lstatSync(path); } catch {
    fail("BOUNDARY_BOOTSTRAP_PATH_MISSING", subject, "required directory is absent or cannot be inspected");
  }
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    fail("BOUNDARY_BOOTSTRAP_PATH_IDENTITY_INVALID", subject, "directory must be a real non-symlink directory");
  }
  if (ownerOnly) {
    const uid = typeof process.geteuid === "function" ? process.geteuid() : null;
    if ((stat.mode & 0o7777) !== 0o700 || (uid !== null && stat.uid !== uid)) {
      fail("BOUNDARY_BOOTSTRAP_CUSTODY_INVALID", subject, "external authority directory must be owner-owned mode 0700");
    }
  }
  return stat;
}

function assertPathChain(root, relativePath, subject) {
  const rel = safeRelativePath(relativePath, subject);
  inspectDirectory(root, "boundary repository root");
  const parts = rel.split("/").slice(0, -1);
  let current = root;
  for (const part of parts) {
    current = join(current, part);
    inspectDirectory(current, subject);
  }
  return join(root, ...rel.split("/"));
}

function readDescriptorExact(fd, size, subject) {
  if (!Number.isSafeInteger(size) || size < 0 || size > MAX_CONTROL_BYTES) {
    fail("BOUNDARY_BOOTSTRAP_FILE_SIZE_INVALID", subject, "file size is outside the bounded bootstrap contract");
  }
  const bytes = Buffer.alloc(size);
  let offset = 0;
  while (offset < size) {
    let count;
    try { count = readSync(fd, bytes, offset, size - offset, offset); } catch {
      fail("BOUNDARY_BOOTSTRAP_FILE_READ_FAILED", subject, "stable descriptor read failed");
    }
    if (count <= 0) fail("BOUNDARY_BOOTSTRAP_FILE_READ_FAILED", subject, "stable descriptor read ended early");
    offset += count;
  }
  return bytes;
}

function closeDescriptorOnce(fd, subject) {
  try {
    closeSync(fd);
  } catch {
    fail(
      "BOUNDARY_BOOTSTRAP_DESCRIPTOR_CLOSE_FAILED",
      subject,
      "descriptor close outcome is indeterminate; the descriptor is never retried or reused",
    );
  }
}

function stableReadFile(path, subject, {
  maxBytes = MAX_CONTROL_BYTES,
  mode = null,
  readOnly = false,
  owner = false,
  links = null,
} = {}) {
  let before;
  try { before = lstatSync(path); } catch {
    fail("BOUNDARY_BOOTSTRAP_PATH_MISSING", subject, "required file is absent or cannot be inspected");
  }
  if (!before.isFile() || before.isSymbolicLink()) {
    fail("BOUNDARY_BOOTSTRAP_PATH_IDENTITY_INVALID", subject, "file must be one regular non-symlink inode");
  }
  if (before.size > maxBytes) fail("BOUNDARY_BOOTSTRAP_FILE_SIZE_INVALID", subject, "file exceeds its bounded byte limit");
  if (mode !== null && (before.mode & 0o7777) !== mode) {
    fail("BOUNDARY_BOOTSTRAP_CUSTODY_INVALID", subject, `file mode must be ${mode.toString(8)}`);
  }
  if (readOnly && (before.mode & 0o222) !== 0) {
    fail("BOUNDARY_BOOTSTRAP_CUSTODY_INVALID", subject, "file transport must not have any write bit set");
  }
  const uid = typeof process.geteuid === "function" ? process.geteuid() : null;
  if (owner && uid !== null && before.uid !== uid) {
    fail("BOUNDARY_BOOTSTRAP_CUSTODY_INVALID", subject, "file must be owned by the current effective user");
  }
  if (links !== null && before.nlink !== links) {
    fail("BOUNDARY_BOOTSTRAP_PATH_IDENTITY_INVALID", subject, `file link count must be exactly ${links}`);
  }
  if (typeof fsConstants.O_NOFOLLOW !== "number") {
    fail("BOUNDARY_BOOTSTRAP_PLATFORM_UNSUPPORTED", subject, "O_NOFOLLOW is required for trusted runtime reads");
  }
  let fd;
  try {
    fd = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    const opened = fstatSync(fd);
    if (!opened.isFile() || !sameIdentity(before, opened)) {
      fail("BOUNDARY_BOOTSTRAP_PATH_IDENTITY_INVALID", subject, "path and opened descriptor identify different files");
    }
    const first = readDescriptorExact(fd, opened.size, subject);
    const middle = fstatSync(fd);
    const second = readDescriptorExact(fd, middle.size, subject);
    const afterDescriptor = fstatSync(fd);
    let afterPath;
    try { afterPath = lstatSync(path); } catch {
      fail("BOUNDARY_BOOTSTRAP_FILE_CHANGED", subject, "file disappeared during stable read");
    }
    if (!sameState(opened, middle) || !sameState(middle, afterDescriptor)
        || !sameState(before, afterPath) || first.length !== second.length
        || !timingSafeEqual(first, second)) {
      fail("BOUNDARY_BOOTSTRAP_FILE_CHANGED", subject, "identity, metadata, or bytes changed during stable read");
    }
    return first;
  } catch (error) {
    if (error instanceof BoundaryBootstrapError) throw error;
    fail("BOUNDARY_BOOTSTRAP_FILE_READ_FAILED", subject, "no-follow open or descriptor verification failed");
  } finally {
    if (fd !== undefined) closeDescriptorOnce(fd, subject);
  }
  return Buffer.alloc(0);
}

function readRepositoryFile(root, relativePath, subject = `reviewed control ${relativePath}`) {
  const path = assertPathChain(root, relativePath, subject);
  return stableReadFile(path, subject);
}

function canonicalDocument(bytes, subject) {
  let text;
  let doc;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    doc = JSON.parse(text);
  } catch {
    fail("BOUNDARY_BOOTSTRAP_JSON_INVALID", subject, "document is not valid UTF-8 JSON");
  }
  if (text !== `${canonicalBoundaryJson(doc)}\n`) {
    fail("BOUNDARY_BOOTSTRAP_JSON_NONCANONICAL", subject, "document bytes are not exact canonical JSON plus one newline");
  }
  return { doc, text };
}

function assertCanonicalRegistry(paths, subject) {
  if (!Array.isArray(paths) || paths.length === 0
      || paths.some((path) => typeof path !== "string")) {
    fail("BOUNDARY_BOOTSTRAP_MANIFEST_INVALID", subject, "manifest paths must be one nonempty array of strings");
  }
  paths.forEach((path) => safeRelativePath(path, subject));
  const sorted = [...paths].sort();
  if (new Set(paths).size !== paths.length || paths.some((path, index) => path !== sorted[index])) {
    fail("BOUNDARY_BOOTSTRAP_MANIFEST_INVALID", subject, "manifest paths must be unique and lexically sorted");
  }
}

export function deriveBoundaryControlManifest(root) {
  const resolvedRoot = resolve(root);
  if (PREVIOUS_REVIEWED_CONTROL_PATHS.length !== 7) {
    fail(
      "BOUNDARY_BOOTSTRAP_PREDECESSOR_REGISTRY_DRIFT",
      "historical reviewed control registry",
      "the authenticated predecessor identity must remain exactly seven paths",
    );
  }
  assertCanonicalRegistry(PREVIOUS_REVIEWED_CONTROL_PATHS, "historical reviewed control registry");
  assertCanonicalRegistry(REVIEWED_CONTROL_PATHS, "reviewed control registry");
  const files = REVIEWED_CONTROL_PATHS.map((path) => {
    const bytes = readRepositoryFile(resolvedRoot, path);
    return { byteLength: bytes.length, path, sha256: sha256(bytes) };
  });
  const body = { files, schemaVersion: BOUNDARY_CONTROL_MANIFEST_VERSION };
  return Object.freeze({
    digest: sha256(Buffer.from(canonicalBoundaryJson(body), "utf8")),
    files: Object.freeze(files.map((file) => Object.freeze(file))),
    paths: REVIEWED_CONTROL_PATHS,
    version: BOUNDARY_CONTROL_MANIFEST_VERSION,
  });
}

function readBoundedAuthorizationStream(fd, subject, maxBytes = MAX_AUTHORIZATION_BYTES) {
  const chunks = [];
  let length = 0;
  for (;;) {
    const remaining = maxBytes + 1 - length;
    const chunk = Buffer.alloc(Math.min(64 * 1024, remaining));
    let count;
    try { count = readSync(fd, chunk, 0, chunk.length, null); } catch {
      fail("BOUNDARY_BOOTSTRAP_AUTHORIZATION_CHANNEL_INVALID", subject, "stream transport could not be read");
    }
    if (count === 0) break;
    length += count;
    if (length > maxBytes) {
      fail("BOUNDARY_BOOTSTRAP_AUTHORIZATION_CHANNEL_INVALID", subject, "stream transport exceeds its public byte bound");
    }
    chunks.push(chunk.subarray(0, count));
  }
  if (length === 0) {
    fail("BOUNDARY_BOOTSTRAP_AUTHORIZATION_CHANNEL_INVALID", subject, "stream transport is empty");
  }
  return Buffer.concat(chunks, length);
}

function readIsolatedKnockoutBootstrapContext() {
  const rawFd = process.env[BOUNDARY_KNOCKOUT_BOOTSTRAP_ENV];
  delete process.env[BOUNDARY_KNOCKOUT_BOOTSTRAP_ENV];
  if (rawFd !== "0") {
    fail(
      "BOUNDARY_BOOTSTRAP_AUTHORIZATION_FD_MISSING",
      "isolated knockout bootstrap channel",
      "the dedicated direct-child descriptor must be exact stdin FD 0",
    );
  }
  let descriptorObserved = false;
  let bytes;
  try {
    const before = fstatSync(0);
    descriptorObserved = true;
    if (!before.isFIFO() && !before.isSocket()) {
      fail(
        "BOUNDARY_BOOTSTRAP_AUTHORIZATION_FD_INVALID",
        "isolated knockout bootstrap channel",
        "the context must arrive through an anonymous direct-child pipe",
      );
    }
    bytes = readBoundedAuthorizationStream(
      0,
      "isolated knockout bootstrap pipe",
      MAX_KNOCKOUT_BOOTSTRAP_BYTES,
    );
  } catch (error) {
    if (error instanceof BoundaryBootstrapError) throw error;
    fail(
      "BOUNDARY_BOOTSTRAP_AUTHORIZATION_FD_INVALID",
      "isolated knockout bootstrap channel",
      "the direct-child pipe could not be inspected or read",
    );
  } finally {
    if (descriptorObserved) closeDescriptorOnce(0, "isolated knockout bootstrap channel");
  }
  const { doc } = canonicalDocument(bytes, "isolated knockout bootstrap context");
  const nestedScannerSelftest = doc !== null && typeof doc === "object" && !Array.isArray(doc)
    && doc.protocol === BOUNDARY_SCANNER_SELFTEST_BOOTSTRAP_PROTOCOL;
  exactKeys(doc, nestedScannerSelftest
    ? ["audiencePid", "candidateSubject", "protocol", "workerCapabilitySha256", "workerPid"]
    : ["candidateSubject", "protocol", "workerCapabilitySha256", "workerPid"],
  "isolated knockout bootstrap context");
  exactKeys(doc.candidateSubject, [
    "archiveSha256", "commit", "repository", "tree",
  ], "isolated knockout candidate subject");
  const subject = doc.candidateSubject;
  if (![BOUNDARY_KNOCKOUT_BOOTSTRAP_PROTOCOL, BOUNDARY_SCANNER_SELFTEST_BOOTSTRAP_PROTOCOL]
    .includes(doc.protocol)
      || !HEX_64_RE.test(String(doc.workerCapabilitySha256))
      || !Number.isSafeInteger(doc.workerPid) || doc.workerPid !== process.ppid
      || (nestedScannerSelftest && (!Number.isSafeInteger(doc.audiencePid)
        || doc.audiencePid <= 0 || doc.audiencePid !== process.pid))
      || !HEX_64_RE.test(String(subject.archiveSha256))
      || !GIT_OBJECT_ID_RE.test(String(subject.commit))
      || !GIT_OBJECT_ID_RE.test(String(subject.tree))
      || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(String(subject.repository))) {
    fail(
      "BOUNDARY_BOOTSTRAP_SCHEMA_INVALID",
      "isolated knockout bootstrap context",
      "protocol, parent/child audience binding, capability digest, or public subject is malformed",
    );
  }
  return Object.freeze({ ...doc, candidateSubject: Object.freeze({ ...subject }) });
}

function readSanitizedAuthorizationFd() {
  const rawFd = process.env.NOA_BOUNDARY_AUTHORIZATION_FD;
  delete process.env.NOA_BOUNDARY_AUTHORIZATION_FD;
  if (!/^[3-9][0-9]{0,2}$/.test(String(rawFd ?? ""))) {
    fail(
      "BOUNDARY_BOOTSTRAP_AUTHORIZATION_FD_MISSING",
      "sanitized boundary authorization channel",
      "an inherited descriptor number from 3 through 999 is required",
    );
  }
  const fd = Number(rawFd);
  let descriptorObserved = false;
  let before;
  let first;
  try {
    before = fstatSync(fd);
    descriptorObserved = true;
    if (before.isFIFO() || before.isSocket()) {
      return readBoundedAuthorizationStream(fd, "sanitized boundary authorization pipe");
    }
    const uid = typeof process.geteuid === "function" ? process.geteuid() : null;
    if (!before.isFile() || before.nlink !== 0 || (before.mode & 0o7777) !== 0o600
        || (uid !== null && before.uid !== uid) || before.size <= 0
        || before.size > MAX_AUTHORIZATION_BYTES) {
      fail(
        "BOUNDARY_BOOTSTRAP_AUTHORIZATION_FD_INVALID",
        "sanitized boundary authorization channel",
        "descriptor must be one owner-only unlinked regular file with bounded bytes",
      );
    }
    first = readDescriptorExact(fd, before.size, "sanitized boundary authorization");
    const middle = fstatSync(fd);
    const second = readDescriptorExact(fd, middle.size, "sanitized boundary authorization");
    const after = fstatSync(fd);
    if (!sameState(before, middle) || !sameState(middle, after)
        || first.length !== second.length || !timingSafeEqual(first, second)) {
      fail(
        "BOUNDARY_BOOTSTRAP_AUTHORIZATION_CHANGED",
        "sanitized boundary authorization channel",
        "descriptor identity, metadata, or bytes changed during stable read",
      );
    }
  } catch (error) {
    if (error instanceof BoundaryBootstrapError) throw error;
    fail(
      "BOUNDARY_BOOTSTRAP_AUTHORIZATION_FD_INVALID",
      "sanitized boundary authorization channel",
      "descriptor could not be inspected or read",
    );
  } finally {
    if (descriptorObserved) closeDescriptorOnce(fd, "sanitized boundary authorization channel");
  }
  return first;
}

function readSanitizedAuthorizationFile() {
  const rawPath = process.env.NOA_BOUNDARY_AUTHORIZATION_FILE;
  delete process.env.NOA_BOUNDARY_AUTHORIZATION_FILE;
  if (typeof rawPath !== "string" || rawPath.length === 0 || rawPath.includes("\0")
      || !isAbsolute(rawPath) || normalize(rawPath) !== rawPath) {
    fail(
      "BOUNDARY_BOOTSTRAP_AUTHORIZATION_FILE_INVALID",
      "sanitized boundary authorization file transport",
      "an exact absolute path to a read-only public authorization file is required",
    );
  }
  return stableReadFile(rawPath, "sanitized boundary authorization file transport", {
    links: 1,
    maxBytes: MAX_AUTHORIZATION_BYTES,
    readOnly: true,
  });
}

export function readSanitizedAuthorizationBytesFromEnvironment() {
  const hasFd = process.env.NOA_BOUNDARY_AUTHORIZATION_FD !== undefined;
  const hasFile = process.env.NOA_BOUNDARY_AUTHORIZATION_FILE !== undefined;
  if (hasFd === hasFile) {
    delete process.env.NOA_BOUNDARY_AUTHORIZATION_FD;
    delete process.env.NOA_BOUNDARY_AUTHORIZATION_FILE;
    fail(
      "BOUNDARY_BOOTSTRAP_AUTHORIZATION_CHANNEL_AMBIGUOUS",
      "sanitized boundary authorization channel",
      "supply exactly one inherited descriptor/pipe or read-only mounted public file",
    );
  }
  return hasFd ? readSanitizedAuthorizationFd() : readSanitizedAuthorizationFile();
}

function canonicalUtcTimestamp(value, subject) {
  const raw = String(value ?? "");
  const parsed = Date.parse(raw);
  const canonical = raw.includes(".") ? raw : raw.replace(/Z$/, ".000Z");
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(raw)
      || !Number.isFinite(parsed) || new Date(parsed).toISOString() !== canonical) {
    fail("BOUNDARY_BOOTSTRAP_AUTHORIZATION_INVALID", subject, "timestamp must be canonical UTC RFC3339");
  }
  return parsed;
}

function validateSanitizedAuthorization(doc, nowMs) {
  exactKeys(doc, AUTHORIZATION_KEYS, "sanitized boundary authorization");
  exactKeys(doc.controlManifest, ["digest", "files", "version"], "authorized public control manifest");
  exactKeys(doc.subject, ["archiveSha256", "commit", "repository", "tree"], "authorized public candidate subject");
  if (doc.schemaVersion !== BOUNDARY_RUNTIME_AUTHORIZATION_SCHEMA_VERSION
      || doc.channel !== "PUBLIC_SANITIZED_AUTHORIZATION_V1"
      || doc.controllerId !== "noa-boundary-external-supervisor/v1"
      || !["RECOVERY_ONLY", "RUNTIME"].includes(doc.operation)
      || !HEX_64_RE.test(String(doc.nonce))
      || !Array.isArray(doc.nonClaims)
      || doc.nonClaims.length !== BOUNDARY_AUTHORITY_NON_CLAIMS.length
      || doc.nonClaims.some((claim, index) => claim !== BOUNDARY_AUTHORITY_NON_CLAIMS[index])) {
    fail("BOUNDARY_BOOTSTRAP_AUTHORIZATION_INVALID", "sanitized boundary authorization", "schema, channel, controller, operation, nonce, or non-claims drifted");
  }
  if (!Number.isSafeInteger(doc.controlManifest.version) || doc.controlManifest.version <= 0
      || !HEX_64_RE.test(String(doc.controlManifest.digest))) {
    fail("BOUNDARY_BOOTSTRAP_AUTHORIZATION_INVALID", "authorized public control manifest", "version and digest must be exact");
  }
  assertCanonicalRegistry(doc.controlManifest.files, "authorized public control manifest");
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(String(doc.subject.repository))
      || !/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(String(doc.subject.commit))
      || !/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(String(doc.subject.tree))
      || !HEX_64_RE.test(String(doc.subject.archiveSha256))) {
    fail("BOUNDARY_BOOTSTRAP_AUTHORIZATION_INVALID", "authorized public candidate subject", "repository, commit, tree, and archive identities must be exact");
  }
  const issuedAt = canonicalUtcTimestamp(doc.issuedAt, "authorization issuedAt");
  const expiresAt = canonicalUtcTimestamp(doc.expiresAt, "authorization expiresAt");
  const now = nowMs;
  if (issuedAt > now + 5_000 || expiresAt <= now || expiresAt <= issuedAt || expiresAt - issuedAt > 5 * 60_000) {
    fail("BOUNDARY_BOOTSTRAP_AUTHORIZATION_EXPIRED", "sanitized boundary authorization", "authorization must be current and bounded to at most five minutes");
  }
  return Object.freeze(doc);
}

export function validateSanitizedAuthorizationBytes(bytes, { nowMs = Date.now() } = {}) {
  const copied = Buffer.from(bytes ?? Buffer.alloc(0));
  if (copied.length === 0 || copied.length > MAX_AUTHORIZATION_BYTES || !Number.isFinite(nowMs)) {
    fail(
      "BOUNDARY_BOOTSTRAP_AUTHORIZATION_INVALID",
      "sanitized boundary authorization",
      "authorization bytes and validation time must be bounded and exact",
    );
  }
  return validateSanitizedAuthorization(
    canonicalDocument(copied, "sanitized boundary authorization").doc,
    nowMs,
  );
}

function validateRuntimeAttestation(root) {
  const bytes = readRepositoryFile(root, RUNTIME_ATTESTATION_PATH, "reviewed boundary runtime attestation");
  const { doc } = canonicalDocument(bytes, "reviewed boundary runtime attestation");
  exactKeys(doc, ATTESTATION_KEYS, "reviewed boundary runtime attestation");
  exactKeys(doc.lock, ["integrity", "lockfileVersion", "packageKey", "path", "sha256", "version"], "runtime lock attestation");
  exactKeys(doc.node, ["byteLength", "path", "sha256", "version"], "Node runtime attestation");
  exactKeys(doc.package, ["main", "name", "path", "version"], "TypeScript package attestation");
  if (doc.schemaVersion !== BOUNDARY_RUNTIME_ATTESTATION_SCHEMA_VERSION
      || doc.runtime !== "typescript" || doc.moduleFormat !== "commonjs"
      || doc.package.name !== "typescript" || doc.package.version !== BOUNDARY_TYPESCRIPT_VERSION
      || doc.package.main !== "./lib/typescript.js" || doc.lock.version !== BOUNDARY_TYPESCRIPT_VERSION
      || doc.lock.lockfileVersion !== 3 || doc.lock.packageKey !== "node_modules/typescript"
      || doc.lock.path !== "package-lock.json" || !HEX_64_RE.test(String(doc.lock.sha256))
      || !SHA512_SRI_RE.test(String(doc.lock.integrity))
      || doc.node.version !== BOUNDARY_NODE_VERSION || doc.node.path !== ".node-version"
      || !HEX_64_RE.test(String(doc.node.sha256)) || !Number.isSafeInteger(doc.node.byteLength)
      || !Array.isArray(doc.files) || doc.files.length !== 2
      || !Array.isArray(doc.nonClaims)
      || doc.nonClaims.length !== BOUNDARY_AUTHORITY_NON_CLAIMS.length
      || doc.nonClaims.some((claim, index) => claim !== BOUNDARY_AUTHORITY_NON_CLAIMS[index])) {
    fail("BOUNDARY_BOOTSTRAP_RUNTIME_ATTESTATION_INVALID", "reviewed boundary runtime attestation", "schema, exact versions, runtime files, and non-claims must match the closed bootstrap contract");
  }
  const wantedPaths = ["node_modules/typescript/package.json", "node_modules/typescript/lib/typescript.js"];
  doc.files.forEach((file, index) => {
    exactKeys(file, ["byteLength", "path", "sha256"], `runtime file attestation ${index}`);
    if (file.path !== wantedPaths[index] || !Number.isSafeInteger(file.byteLength) || file.byteLength <= 0
        || !HEX_64_RE.test(String(file.sha256))) {
      fail("BOUNDARY_BOOTSTRAP_RUNTIME_ATTESTATION_INVALID", `runtime file attestation ${index}`, "path, byte length, and full SHA-256 must be exact");
    }
  });
  if (doc.package.path !== wantedPaths[0]) {
    fail("BOUNDARY_BOOTSTRAP_RUNTIME_ATTESTATION_INVALID", "TypeScript package attestation", "package manifest path differs from runtime file registry");
  }
  return doc;
}

function verifyRuntimeBytes(root, attestation) {
  if (process.versions.node !== BOUNDARY_NODE_VERSION) {
    fail("BOUNDARY_BOOTSTRAP_NODE_VERSION_MISMATCH", "Node runtime version", `expected exact ${BOUNDARY_NODE_VERSION}`);
  }
  const nodeVersionBytes = readRepositoryFile(root, attestation.node.path, "pinned Node version file");
  if (nodeVersionBytes.length !== attestation.node.byteLength
      || !exactHex(sha256(nodeVersionBytes), attestation.node.sha256)
      || nodeVersionBytes.toString("utf8") !== `${BOUNDARY_NODE_VERSION}\n`) {
    fail("BOUNDARY_BOOTSTRAP_NODE_ATTESTATION_MISMATCH", "pinned Node version file", "exact version bytes or SHA-256 drifted");
  }

  const lockBytes = readRepositoryFile(root, attestation.lock.path, "exact package lock");
  if (!exactHex(sha256(lockBytes), attestation.lock.sha256)) {
    fail("BOUNDARY_BOOTSTRAP_LOCK_DIGEST_MISMATCH", "exact package lock", "package-lock.json bytes differ from reviewed runtime attestation");
  }
  let lock;
  try { lock = JSON.parse(lockBytes.toString("utf8")); } catch {
    fail("BOUNDARY_BOOTSTRAP_LOCK_INVALID", "exact package lock", "package-lock.json is not JSON");
  }
  const locked = lock?.packages?.[attestation.lock.packageKey];
  const rootTypescript = lock?.packages?.[""]?.devDependencies?.typescript;
  if (lock?.lockfileVersion !== attestation.lock.lockfileVersion
      || rootTypescript !== BOUNDARY_TYPESCRIPT_VERSION
      || locked?.version !== BOUNDARY_TYPESCRIPT_VERSION
      || locked?.integrity !== attestation.lock.integrity) {
    fail("BOUNDARY_BOOTSTRAP_LOCK_RESOLUTION_MISMATCH", "exact package lock", "root pin, resolved TypeScript version, integrity, or lockfile version drifted");
  }
  const rootManifestBytes = readRepositoryFile(root, "package.json", "root package manifest");
  let rootManifest;
  try { rootManifest = JSON.parse(rootManifestBytes.toString("utf8")); } catch {
    fail("BOUNDARY_BOOTSTRAP_PACKAGE_INVALID", "root package manifest", "package.json is not JSON");
  }
  if (rootManifest?.devDependencies?.typescript !== BOUNDARY_TYPESCRIPT_VERSION) {
    fail("BOUNDARY_BOOTSTRAP_PACKAGE_PIN_MISMATCH", "root package manifest", "TypeScript dependency must be an exact 5.9.3 pin");
  }

  const runtime = new Map();
  for (const file of attestation.files) {
    const bytes = readRepositoryFile(root, file.path, `attested TypeScript runtime ${file.path}`);
    if (bytes.length !== file.byteLength || !exactHex(sha256(bytes), file.sha256)) {
      fail("BOUNDARY_BOOTSTRAP_RUNTIME_DIGEST_MISMATCH", `attested TypeScript runtime ${file.path}`, "byte length or SHA-256 differs from reviewed runtime attestation");
    }
    runtime.set(file.path, bytes);
  }
  let packageManifest;
  try { packageManifest = JSON.parse(runtime.get(attestation.package.path).toString("utf8")); } catch {
    fail("BOUNDARY_BOOTSTRAP_RUNTIME_PACKAGE_INVALID", "attested TypeScript package manifest", "runtime package.json is not JSON");
  }
  if (packageManifest?.name !== attestation.package.name
      || packageManifest?.version !== attestation.package.version
      || packageManifest?.main !== attestation.package.main) {
    fail("BOUNDARY_BOOTSTRAP_RUNTIME_PACKAGE_MISMATCH", "attested TypeScript package manifest", "name, exact version, or entry point drifted");
  }
  return Object.freeze({
    attestation,
    entryBytes: runtime.get("node_modules/typescript/lib/typescript.js"),
    entryPath: join(root, "node_modules", "typescript", "lib", "typescript.js"),
  });
}

function gitOutput(root, args, { binary = false } = {}) {
  try {
    return readOnlyGitOutput(root, args, { binary });
  } catch {
    fail("BOUNDARY_BOOTSTRAP_SUBJECT_UNAVAILABLE", "authorized public candidate subject", "git could not derive an exact local subject identity");
  }
}

function absentRepositoryControl(path, subject) {
  try {
    lstatSync(path);
  } catch (error) {
    if (error?.code === "ENOENT" || error?.code === "ENOTDIR") return;
    fail("BOUNDARY_BOOTSTRAP_GIT_LAYOUT_INVALID", subject, "repository control path could not be inspected");
  }
  fail("BOUNDARY_BOOTSTRAP_GIT_LAYOUT_INVALID", subject, "external or linked Git storage is not permitted");
}

function assertClosedGitStorageTree(gitDirectory) {
  const pending = [gitDirectory];
  const uid = typeof process.geteuid === "function" ? process.geteuid() : null;
  let storageDevice = null;
  let observed = 0;
  while (pending.length > 0) {
    const current = pending.pop();
    let stat;
    try { stat = lstatSync(current); } catch {
      fail("BOUNDARY_BOOTSTRAP_GIT_LAYOUT_INVALID", "standalone Git storage", "a Git storage path disappeared or could not be inspected");
    }
    observed += 1;
    if (observed > MAX_GIT_STORAGE_ENTRIES) {
      fail("BOUNDARY_BOOTSTRAP_GIT_LAYOUT_INVALID", "standalone Git storage", "Git storage exceeds the bounded entry count");
    }
    if (stat.isSymbolicLink() || (!stat.isDirectory() && !stat.isFile())) {
      fail("BOUNDARY_BOOTSTRAP_GIT_LAYOUT_INVALID", "standalone Git storage", "every Git storage entry must be a real directory or regular file");
    }
    if (storageDevice === null) storageDevice = stat.dev;
    if (stat.dev !== storageDevice || (uid !== null && stat.uid !== uid) || (stat.mode & 0o022) !== 0
        || (stat.isFile() && stat.nlink !== 1)) {
      fail("BOUNDARY_BOOTSTRAP_GIT_LAYOUT_INVALID", "standalone Git storage", "Git storage must stay on one device, be owner-held and non-group/world-writable, and contain no hard-linked files");
    }
    if (stat.isDirectory()) {
      let entries;
      try { entries = readdirSync(current); } catch {
        fail("BOUNDARY_BOOTSTRAP_GIT_LAYOUT_INVALID", "standalone Git storage", "a Git storage directory could not be enumerated");
      }
      for (const entry of entries) pending.push(join(current, entry));
    }
  }
}

function assertStandaloneGitLayout(root) {
  const resolvedRoot = resolve(root);
  let physicalRoot;
  try { physicalRoot = realpathSync(resolvedRoot); } catch {
    fail("BOUNDARY_BOOTSTRAP_GIT_LAYOUT_INVALID", "authorized public candidate subject", "repository root cannot be resolved physically");
  }
  if (physicalRoot !== resolvedRoot) {
    fail("BOUNDARY_BOOTSTRAP_GIT_LAYOUT_INVALID", "authorized public candidate subject", "repository root must be one physical non-symlink path");
  }
  const gitDirectory = join(resolvedRoot, ".git");
  inspectDirectory(gitDirectory, "standalone Git directory");
  inspectDirectory(join(gitDirectory, "objects"), "standalone Git object directory");
  assertClosedGitStorageTree(gitDirectory);
  stableReadFile(join(gitDirectory, "HEAD"), "standalone Git HEAD", { maxBytes: 1024 * 1024 });
  stableReadFile(join(gitDirectory, "config"), "standalone Git configuration", { maxBytes: 1024 * 1024 });
  absentRepositoryControl(join(gitDirectory, "commondir"), "Git common-directory indirection");
  absentRepositoryControl(join(gitDirectory, "info", "attributes"), "Git info attributes override");
  absentRepositoryControl(join(gitDirectory, "info", "grafts"), "Git graft history override");
  absentRepositoryControl(join(gitDirectory, "objects", "info", "alternates"), "Git object alternates");
  absentRepositoryControl(join(gitDirectory, "objects", "info", "http-alternates"), "Git HTTP object alternates");
  absentRepositoryControl(join(gitDirectory, "refs", "replace"), "Git replacement refs");
  absentRepositoryControl(join(gitDirectory, "shallow"), "shallow Git history");
  absentRepositoryControl(join(gitDirectory, "worktrees"), "linked Git worktree metadata");

  const absoluteGitDirectory = gitOutput(resolvedRoot, ["rev-parse", "--absolute-git-dir"]);
  const commonDirectory = gitOutput(resolvedRoot, ["rev-parse", "--git-common-dir"]);
  const objectDirectory = gitOutput(resolvedRoot, ["rev-parse", "--git-path", "objects"]);
  const topLevel = gitOutput(resolvedRoot, ["rev-parse", "--show-toplevel"]);
  if (resolve(absoluteGitDirectory) !== gitDirectory
      || resolve(resolvedRoot, commonDirectory) !== gitDirectory
      || resolve(resolvedRoot, objectDirectory) !== join(gitDirectory, "objects")
      || resolve(topLevel) !== resolvedRoot) {
    fail(
      "BOUNDARY_BOOTSTRAP_GIT_LAYOUT_INVALID",
      "authorized public candidate subject",
      "Git top-level, common directory, object directory, and standalone storage must be exact",
    );
  }
}

function readValidatedLocalGitConfig(root) {
  const bytes = readOnlyGitOutput(
    root,
    ["config", "--local", "--no-includes", "--null", "--list"],
    { binary: true, maxBuffer: 1024 * 1024 },
  );
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    fail("BOUNDARY_BOOTSTRAP_GIT_CONFIG_INVALID", "local Git configuration", "configuration is not valid UTF-8");
  }
  const records = text.endsWith("\0") ? text.slice(0, -1).split("\0") : [];
  if (records.length === 0 || records.some((record) => !record.includes("\n"))) {
    fail("BOUNDARY_BOOTSTRAP_GIT_CONFIG_INVALID", "local Git configuration", "configuration is empty or malformed");
  }
  const entries = new Map();
  for (const record of records) {
    const separator = record.indexOf("\n");
    const key = record.slice(0, separator);
    const value = record.slice(separator + 1);
    if (entries.has(key) || !/^[a-z0-9.-]{1,160}$/.test(key)
        || value.length > 1024 || /[\u0000\r\n\u0085\u2028\u2029]/u.test(value)) {
      fail("BOUNDARY_BOOTSTRAP_GIT_CONFIG_INVALID", "local Git configuration", "configuration contains duplicate, malformed, or unbounded entries");
    }
    entries.set(key, value);
  }

  const simpleValues = new Map([
    ["core.repositoryformatversion", /^(?:0|1)$/],
    ["core.filemode", /^(?:true|false)$/],
    ["core.bare", /^false$/],
    ["core.logallrefupdates", /^true$/],
    ["core.ignorecase", /^(?:true|false)$/],
    ["core.precomposeunicode", /^(?:true|false)$/],
    ["core.symlinks", /^(?:true|false)$/],
    ["core.hookspath", /^scripts\/hooks$/],
    ["extensions.objectformat", /^(?:sha1|sha256)$/],
    ["remote.origin.url", /^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:\.git)?$/],
    ["remote.origin.fetch", /^\+?refs\/heads\/[A-Za-z0-9_.*\/-]+:refs\/remotes\/origin\/[A-Za-z0-9_.*\/-]+$/],
    ["remote.origin.tagopt", /^--no-tags$/],
    ["user.email", /^[^\s@]+@[^\s@]+$/],
    ["user.name", /^[\x20-\x7e]{1,160}$/],
    ["commit.gpgsign", /^(?:true|false)$/],
    ["tag.gpgsign", /^false$/],
  ]);
  for (const [key, value] of entries) {
    const simple = simpleValues.get(key);
    const branch = /^branch\.([A-Za-z0-9_.\/-]{1,160})\.(remote|merge)$/.exec(key);
    const branchValid = branch !== null && (branch[2] === "remote"
      ? value === "origin"
      : value === `refs/heads/${branch[1]}`);
    if (!(simple?.test(value) || branchValid)) {
      fail(
        "BOUNDARY_BOOTSTRAP_GIT_CONFIG_INVALID",
        "local Git configuration",
        `unsupported or unsafe local key ${JSON.stringify(key)}`,
      );
    }
  }
  for (const required of [
    "core.repositoryformatversion", "core.filemode", "core.bare", "core.logallrefupdates",
    "core.hookspath", "remote.origin.url",
  ]) {
    if (!entries.has(required)) {
      fail("BOUNDARY_BOOTSTRAP_GIT_CONFIG_INVALID", "local Git configuration", `required local key ${JSON.stringify(required)} is absent`);
    }
  }
  return Object.freeze({
    bytes,
    digest: sha256(bytes),
    origin: entries.get("remote.origin.url"),
  });
}

function publicRepositoryCoordinate(remote) {
  const value = String(remote).trim();
  const patterns = [
    /^https:\/\/github\.com\/([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+?)(?:\.git)?$/,
    /^git@github\.com:([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+?)(?:\.git)?$/,
    /^ssh:\/\/git@github\.com\/([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+?)(?:\.git)?$/,
  ];
  for (const pattern of patterns) {
    const match = pattern.exec(value);
    if (match !== null) return match[1];
  }
  fail("BOUNDARY_BOOTSTRAP_SUBJECT_INVALID", "authorized public candidate subject", "origin is not one canonical public GitHub repository coordinate");
}

export function deriveBoundaryCandidateSubject(root) {
  const resolvedRoot = resolve(root);
  assertStandaloneGitLayout(resolvedRoot);
  const configBefore = readValidatedLocalGitConfig(resolvedRoot);
  const commit = gitOutput(resolvedRoot, ["rev-parse", "HEAD"]);
  const tree = gitOutput(resolvedRoot, ["rev-parse", `${commit}^{tree}`]);
  const archive = gitOutput(resolvedRoot, ["archive", "--format=tar", commit], { binary: true });
  const commitAfter = gitOutput(resolvedRoot, ["rev-parse", "HEAD"]);
  const configAfter = readValidatedLocalGitConfig(resolvedRoot);
  assertStandaloneGitLayout(resolvedRoot);
  if (commitAfter !== commit || !exactHex(configBefore.digest, configAfter.digest)) {
    fail("BOUNDARY_BOOTSTRAP_SUBJECT_CHANGED", "authorized public candidate subject", "HEAD or local Git configuration changed during subject capture");
  }
  if (!/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(commit)
      || !/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(tree) || archive.length === 0) {
    fail("BOUNDARY_BOOTSTRAP_SUBJECT_INVALID", "authorized public candidate subject", "commit, tree, or archive identity is malformed");
  }
  return Object.freeze({
    archiveSha256: sha256(archive),
    commit,
    repository: publicRepositoryCoordinate(configBefore.origin),
    tree,
  });
}

/**
 * Derive the public subject carried into a disposable knockout arm. Unlike the release bootstrap,
 * this non-authority observation does not require a locally installed pre-push hook: hosted CI
 * checkouts intentionally have no active hook. The later isolated capture independently closes and
 * binds the complete local Git configuration before any worker can receive this subject.
 */
export function deriveBoundaryKnockoutCandidateSubject(root) {
  const resolvedRoot = resolve(root);
  assertStandaloneGitLayout(resolvedRoot);
  const originBefore = readOnlyGitOutput(
    resolvedRoot,
    ["config", "--local", "--no-includes", "--get", "remote.origin.url"],
  );
  const commit = gitOutput(resolvedRoot, ["rev-parse", "HEAD"]);
  const tree = gitOutput(resolvedRoot, ["rev-parse", `${commit}^{tree}`]);
  const archive = gitOutput(resolvedRoot, ["archive", "--format=tar", commit], { binary: true });
  const commitAfter = gitOutput(resolvedRoot, ["rev-parse", "HEAD"]);
  const originAfter = readOnlyGitOutput(
    resolvedRoot,
    ["config", "--local", "--no-includes", "--get", "remote.origin.url"],
  );
  assertStandaloneGitLayout(resolvedRoot);
  if (commitAfter !== commit || originAfter !== originBefore) {
    fail(
      "BOUNDARY_BOOTSTRAP_SUBJECT_CHANGED",
      "isolated knockout candidate subject",
      "HEAD or the canonical public origin changed during subject capture",
    );
  }
  if (!GIT_OBJECT_ID_RE.test(commit) || !GIT_OBJECT_ID_RE.test(tree) || archive.length === 0) {
    fail(
      "BOUNDARY_BOOTSTRAP_SUBJECT_INVALID",
      "isolated knockout candidate subject",
      "commit, tree, or archive identity is malformed",
    );
  }
  return Object.freeze({
    archiveSha256: sha256(archive),
    commit,
    repository: publicRepositoryCoordinate(originBefore),
    tree,
  });
}

export function verifyBoundaryBootstrap({ root, mode = "runtime", authorizationBytes = null } = {}) {
  const resolvedRoot = resolve(root ?? join(dirname(fileURLToPath(import.meta.url)), "..", ".."));
  if (mode !== "runtime" && mode !== "recovery") {
    fail("BOUNDARY_BOOTSTRAP_MODE_INVALID", "boundary bootstrap mode", "only runtime or recovery mode is defined");
  }
  if (authorizationBytes !== null
      && (process.env.NOA_BOUNDARY_AUTHORIZATION_FD !== undefined
        || process.env.NOA_BOUNDARY_AUTHORIZATION_FILE !== undefined)) {
    fail(
      "BOUNDARY_BOOTSTRAP_AUTHORIZATION_CHANNEL_AMBIGUOUS",
      "sanitized boundary authorization channel",
      "explicit public bytes and environment transport cannot be combined",
    );
  }
  const authorization = validateSanitizedAuthorizationBytes(
    authorizationBytes === null ? readSanitizedAuthorizationBytesFromEnvironment() : authorizationBytes,
  );
  const expectedOperation = mode === "runtime" ? "RUNTIME" : "RECOVERY_ONLY";
  if (authorization.operation !== expectedOperation) {
    fail("BOUNDARY_BOOTSTRAP_OPERATION_MISMATCH", "sanitized boundary authorization", "authorized operation differs from the requested bootstrap mode");
  }
  const manifest = deriveBoundaryControlManifest(resolvedRoot);
  if (authorization.controlManifest.version !== manifest.version
      || authorization.controlManifest.files.length !== manifest.paths.length
      || authorization.controlManifest.files.some((path, index) => path !== manifest.paths[index])
      || !exactHex(authorization.controlManifest.digest, manifest.digest)) {
    fail("BOUNDARY_BOOTSTRAP_CONTROL_MANIFEST_MISMATCH", "authorized public control manifest", "version, exact sorted file list, or digest differs from current candidate bytes");
  }
  const subject = deriveBoundaryCandidateSubject(resolvedRoot);
  if (canonicalBoundaryJson(subject) !== canonicalBoundaryJson(authorization.subject)) {
    fail("BOUNDARY_BOOTSTRAP_SUBJECT_MISMATCH", "authorized public candidate subject", "repository, commit, tree, or archive identity differs from controller authorization");
  }
  if (mode === "recovery") {
    return Object.freeze({
      authorization,
      authorityClass: BOUNDARY_AUTHORITY_CLASS_EXTERNAL,
      authorityNonClaim: EXTERNAL_SANITIZED_AUTHORIZATION_NON_CLAIM,
      manifest,
      mode,
      nonClaims: BOUNDARY_AUTHORITY_NON_CLAIMS,
      root: resolvedRoot,
      runtime: null,
      subject,
    });
  }
  const attestation = validateRuntimeAttestation(resolvedRoot);
  const runtime = verifyRuntimeBytes(resolvedRoot, attestation);
  return Object.freeze({
    authorization,
    authorityClass: BOUNDARY_AUTHORITY_CLASS_EXTERNAL,
    authorityNonClaim: EXTERNAL_SANITIZED_AUTHORIZATION_NON_CLAIM,
    manifest,
    mode,
    nonClaims: BOUNDARY_AUTHORITY_NON_CLAIMS,
    root: resolvedRoot,
    runtime,
    subject,
  });
}

function verifyCandidateTierANonAuthorityBootstrap(root) {
  const resolvedRoot = resolve(root);
  const manifest = deriveBoundaryControlManifest(resolvedRoot);
  const subject = deriveBoundaryCandidateSubject(resolvedRoot);
  const attestation = validateRuntimeAttestation(resolvedRoot);
  const runtime = verifyRuntimeBytes(resolvedRoot, attestation);
  return Object.freeze({
    authorization: null,
    authorityClass: BOUNDARY_AUTHORITY_CLASS_CANDIDATE_TIER_A,
    authorityNonClaim: CANDIDATE_TIER_A_NON_AUTHORITY_NON_CLAIM,
    manifest,
    mode: BOUNDARY_BOOTSTRAP_MODE_CANDIDATE_TIER_A_NON_AUTHORITY,
    nonClaims: Object.freeze([
      ...BOUNDARY_AUTHORITY_NON_CLAIMS,
      CANDIDATE_TIER_A_NON_AUTHORITY_NON_CLAIM,
    ]),
    root: resolvedRoot,
    runtime,
    subject,
  });
}

function readValidatedIsolatedKnockoutGitConfig(root) {
  const bytes = readOnlyGitOutput(
    root,
    ["config", "--local", "--no-includes", "--null", "--list"],
    { binary: true, maxBuffer: 1024 * 1024 },
  );
  let text;
  try { text = new TextDecoder("utf-8", { fatal: true }).decode(bytes); }
  catch {
    fail(
      "BOUNDARY_BOOTSTRAP_GIT_CONFIG_INVALID",
      "isolated knockout Git configuration",
      "configuration is not valid UTF-8",
    );
  }
  const records = text.endsWith("\0") ? text.slice(0, -1).split("\0") : [];
  const allowed = new Map([
    ["core.repositoryformatversion", /^(?:0|1)$/],
    ["core.filemode", /^(?:true|false)$/],
    ["core.bare", /^false$/],
    ["core.logallrefupdates", /^true$/],
    ["core.ignorecase", /^(?:true|false)$/],
    ["core.precomposeunicode", /^(?:true|false)$/],
    ["core.symlinks", /^(?:true|false)$/],
    ["core.fsmonitor", /^false$/],
    ["core.splitindex", /^false$/],
    ["core.untrackedcache", /^false$/],
    ["core.hookspath", /^\/dev\/null$/],
    ["extensions.objectformat", /^(?:sha1|sha256)$/],
    ["gc.auto", /^0$/],
    ["maintenance.auto", /^false$/],
  ]);
  const entries = new Map();
  if (records.length === 0 || records.some((record) => !record.includes("\n"))) {
    fail(
      "BOUNDARY_BOOTSTRAP_GIT_CONFIG_INVALID",
      "isolated knockout Git configuration",
      "configuration is empty or malformed",
    );
  }
  for (const record of records) {
    const separator = record.indexOf("\n");
    const key = record.slice(0, separator);
    const value = record.slice(separator + 1);
    if (entries.has(key) || !allowed.get(key)?.test(value)) {
      fail(
        "BOUNDARY_BOOTSTRAP_GIT_CONFIG_INVALID",
        "isolated knockout Git configuration",
        "configuration contains a duplicate, remote, hook-enabling, or unsupported entry",
      );
    }
    entries.set(key, value);
  }
  for (const required of [
    "core.repositoryformatversion", "core.filemode", "core.bare", "core.logallrefupdates",
    "core.ignorecase", "core.precomposeunicode", "core.symlinks", "core.fsmonitor",
    "core.splitindex", "core.untrackedcache", "core.hookspath", "gc.auto",
    "maintenance.auto",
  ]) {
    if (!entries.has(required)) {
      fail(
        "BOUNDARY_BOOTSTRAP_GIT_CONFIG_INVALID",
        "isolated knockout Git configuration",
        `required sealed-arm key ${JSON.stringify(required)} is absent`,
      );
    }
  }
  return Object.freeze({ bytes, digest: sha256(bytes) });
}

function verifyIsolatedKnockoutTierANonAuthorityBootstrap(root) {
  const context = readIsolatedKnockoutBootstrapContext();
  const resolvedRoot = resolve(root);
  if (context.protocol === BOUNDARY_SCANNER_SELFTEST_BOOTSTRAP_PROTOCOL) {
    let invokedPath;
    let expectedPath;
    try {
      invokedPath = realpathSync(resolve(String(process.argv[1] ?? "")));
      expectedPath = realpathSync(join(
        resolvedRoot,
        "scripts",
        "lib",
        "boundary-scan.selftest.mjs",
      ));
    } catch {
      invokedPath = null;
      expectedPath = null;
    }
    if (invokedPath === null || invokedPath !== expectedPath) {
      fail(
        "BOUNDARY_BOOTSTRAP_NESTED_AUDIENCE_MISMATCH",
        "isolated scanner selftest bootstrap",
        "the nested capability audience is not the exact reviewed scanner selftest entry point",
      );
    }
  }
  assertStandaloneGitLayout(resolvedRoot);
  const configBefore = readValidatedIsolatedKnockoutGitConfig(resolvedRoot);
  const commit = gitOutput(resolvedRoot, ["rev-parse", "HEAD"]);
  const tree = gitOutput(resolvedRoot, ["rev-parse", `${commit}^{tree}`]);
  const archive = gitOutput(resolvedRoot, ["archive", "--format=tar", commit], { binary: true });
  const commitAfter = gitOutput(resolvedRoot, ["rev-parse", "HEAD"]);
  const configAfter = readValidatedIsolatedKnockoutGitConfig(resolvedRoot);
  assertStandaloneGitLayout(resolvedRoot);
  const observedSubject = {
    archiveSha256: sha256(archive),
    commit,
    repository: context.candidateSubject.repository,
    tree,
  };
  if (commitAfter !== commit || !exactHex(configBefore.digest, configAfter.digest)) {
    fail(
      "BOUNDARY_BOOTSTRAP_SUBJECT_CHANGED",
      "isolated knockout candidate subject",
      "HEAD or sealed-arm Git configuration changed during subject capture",
    );
  }
  if (canonicalBoundaryJson(observedSubject) !== canonicalBoundaryJson(context.candidateSubject)) {
    fail(
      "BOUNDARY_BOOTSTRAP_SUBJECT_MISMATCH",
      "isolated knockout candidate subject",
      "sealed-arm commit, tree, archive, or public repository differs from the supervisor-bound subject",
    );
  }
  const manifest = deriveBoundaryControlManifest(resolvedRoot);
  const attestation = validateRuntimeAttestation(resolvedRoot);
  const runtime = verifyRuntimeBytes(resolvedRoot, attestation);
  const authority = Object.freeze({
    authorization: null,
    authorityClass: BOUNDARY_AUTHORITY_CLASS_CANDIDATE_TIER_A,
    authorityNonClaim: CANDIDATE_TIER_A_NON_AUTHORITY_NON_CLAIM,
    manifest,
    mode: BOUNDARY_BOOTSTRAP_MODE_CANDIDATE_TIER_A_NON_AUTHORITY,
    nonClaims: Object.freeze([
      ...BOUNDARY_AUTHORITY_NON_CLAIMS,
      CANDIDATE_TIER_A_NON_AUTHORITY_NON_CLAIM,
    ]),
    root: resolvedRoot,
    runtime,
    subject: Object.freeze(observedSubject),
  });
  if (context.protocol === BOUNDARY_KNOCKOUT_BOOTSTRAP_PROTOCOL) {
    isolatedScannerSelftestBootstrapStates.set(authority, {
      consumed: false,
      workerCapabilitySha256: context.workerCapabilitySha256,
    });
  }
  return authority;
}

/**
 * Prepare one exact-child bootstrap issuer for the pure scanner selftest in a sealed knockout arm.
 *
 * Only the exact frozen authority object returned by the outer isolated verifier is eligible. The
 * process-private issuer emits once after spawn, binds its bytes to that exact child PID and fixed
 * entry point, and retains the supervisor-bound subject. A nested verifier is a non-delegable leaf.
 * Unknown authorities return null so the ordinary externally-authorized route remains unchanged.
 */
export function prepareNestedBoundaryScannerSelftestBootstrap(authority) {
  const state = authority !== null && typeof authority === "object"
    ? isolatedScannerSelftestBootstrapStates.get(authority)
    : undefined;
  if (state === undefined) return null;
  if (state.consumed) {
    fail(
      "BOUNDARY_BOOTSTRAP_NESTED_CAPABILITY_REUSED",
      "isolated scanner selftest bootstrap",
      "the one-shot nested direct-child capability was already consumed",
    );
  }
  state.consumed = true;
  let issued = false;
  return Object.freeze({
    issueForChild(audiencePid) {
      if (issued) {
        fail(
          "BOUNDARY_BOOTSTRAP_NESTED_CAPABILITY_REUSED",
          "isolated scanner selftest bootstrap",
          "the one-shot exact-child bootstrap issuer was already consumed",
        );
      }
      issued = true;
      if (!Number.isSafeInteger(audiencePid) || audiencePid <= 0) {
        fail(
          "BOUNDARY_BOOTSTRAP_NESTED_AUDIENCE_MISMATCH",
          "isolated scanner selftest bootstrap",
          "the nested capability requires one exact positive child PID",
        );
      }
      return Buffer.from(`${canonicalBoundaryJson({
        audiencePid,
        candidateSubject: authority.subject,
        protocol: BOUNDARY_SCANNER_SELFTEST_BOOTSTRAP_PROTOCOL,
        workerCapabilitySha256: state.workerCapabilitySha256,
        workerPid: process.pid,
      })}\n`, "utf8");
    },
  });
}

export function verifyBoundaryHookActivation(root) {
  const resolvedRoot = resolve(root);
  let top;
  try { top = readOnlyGitOutput(resolvedRoot, ["rev-parse", "--show-toplevel"]); }
  catch { top = null; }
  if (top === null || resolve(top) !== resolvedRoot) {
    fail("BOUNDARY_BOOTSTRAP_GIT_ROOT_MISMATCH", "local hook activation", "git toplevel does not equal the exact boundary repository root");
  }
  let configured;
  try {
    configured = readOnlyGitOutput(
      resolvedRoot,
      ["config", "--no-includes", "--get", "core.hooksPath"],
    );
  }
  catch { configured = null; }
  if (configured !== BOUNDARY_HOOKS_PATH) {
    fail("BOUNDARY_BOOTSTRAP_HOOKS_PATH_MISMATCH", "local hook activation", `effective core.hooksPath must be exact ${BOUNDARY_HOOKS_PATH}`);
  }
  const hookPath = resolve(resolvedRoot, BOUNDARY_HOOKS_PATH, "pre-push");
  const rel = relative(resolvedRoot, hookPath);
  if (rel.startsWith(`..${sep}`) || rel === ".." || isAbsolute(rel)) {
    fail("BOUNDARY_BOOTSTRAP_HOOKS_PATH_MISMATCH", "local hook activation", "resolved hook path escapes the repository root");
  }
  stableReadFile(hookPath, "committed pre-push hook");
  return Object.freeze({
    hooksPath: BOUNDARY_HOOKS_PATH,
    nonClaims: BOUNDARY_AUTHORITY_NON_CLAIMS,
    status: "LOCAL_HOOK_ROUTE_OBSERVED_NON_CLAIM",
  });
}

async function executeVerifiedTypeScriptRuntime(verified) {
  const entryBytes = verified.runtime.entryBytes;
  const entryPath = verified.runtime.entryPath;
  // Execute the already-attested bytes from memory. Importing the mutable filesystem path after
  // hashing it would re-open a same-UID swap window between verification and parser top level.
  const wrapper = [
    "import { createRequire } from 'node:module';",
    `const __filename = ${JSON.stringify(entryPath)};`,
    `const __dirname = ${JSON.stringify(dirname(entryPath))};`,
    "const require = createRequire(__filename);",
    "const module = { exports: {} };",
    "const exports = module.exports;",
    entryBytes.toString("utf8"),
    "export default module.exports;",
  ].join("\n");
  const source = `data:text/javascript;base64,${Buffer.from(wrapper, "utf8").toString("base64")}`;
  const namespace = await import(source);
  const typescript = namespace.default;
  if (typescript === null || typeof typescript !== "object"
      || typescript.version !== BOUNDARY_TYPESCRIPT_VERSION
      || typeof typescript.createSourceFile !== "function") {
    fail("BOUNDARY_BOOTSTRAP_RUNTIME_EXPORT_INVALID", "attested TypeScript runtime", "executed exact bytes did not expose the pinned parser contract");
  }
  return typescript;
}

/**
 * Load only the byte-attested parser for local knockout recurrence analysis. This deliberately
 * returns no candidate, merge, release, or boundary authority; the disposable-workspace supervisor
 * separately binds the experiment subject and retained evidence.
 */
export async function loadAttestedTypeScriptForKnockout({ root } = {}) {
  clearUntrustedBoundaryBootstrapModeMarker();
  const resolvedRoot = resolve(root ?? join(dirname(fileURLToPath(import.meta.url)), "..", ".."));
  const attestation = validateRuntimeAttestation(resolvedRoot);
  const runtime = verifyRuntimeBytes(resolvedRoot, attestation);
  const typescript = await executeVerifiedTypeScriptRuntime({ runtime });
  return Object.freeze({
    nonClaim: "ATTESTED_KNOCKOUT_PARSER_IS_NOT_BOUNDARY_OR_RELEASE_AUTHORITY",
    typescript,
  });
}

export async function loadTrustedTypeScript({ root } = {}) {
  clearUntrustedBoundaryBootstrapModeMarker();
  const resolvedRoot = resolve(root ?? join(dirname(fileURLToPath(import.meta.url)), "..", ".."));
  const armed = candidateTierANonAuthorityRoot;
  candidateTierANonAuthorityRoot = null;
  const candidateTierANonAuthority = armed !== null && armed.root === resolvedRoot;
  if (armed !== null && armed.root !== resolvedRoot) {
    fail(
      "BOUNDARY_BOOTSTRAP_MODE_INVALID",
      "candidate Tier-A bootstrap mode",
      "the armed repository root differs from the parser load root",
    );
  }
  if (candidateTierANonAuthority
      && (process.env.NOA_BOUNDARY_AUTHORIZATION_FD !== undefined
        || process.env.NOA_BOUNDARY_AUTHORIZATION_FILE !== undefined)) {
    fail(
      "BOUNDARY_BOOTSTRAP_AUTHORIZATION_CHANNEL_AMBIGUOUS",
      "boundary bootstrap authority class",
      "candidate Tier-A non-authority mode and an external sanitized authorization cannot be combined",
    );
  }
  const verified = candidateTierANonAuthority
    ? armed.isolatedKnockout
      ? verifyIsolatedKnockoutTierANonAuthorityBootstrap(resolvedRoot)
      : verifyCandidateTierANonAuthorityBootstrap(resolvedRoot)
    : verifyBoundaryBootstrap({ root: resolvedRoot, mode: "runtime" });
  const typescript = await executeVerifiedTypeScriptRuntime(verified);
  return Object.freeze({
    authority: verified,
    typescript,
  });
}

export function boundaryBootstrapFailure(error) {
  if (error instanceof BoundaryBootstrapError) {
    return Object.freeze({
      detail: error.detail,
      fix: error.fix,
      rule: "SETUP_FAILED",
      subject: error.subject,
      bootstrapCode: error.code,
    });
  }
  return Object.freeze({
    detail: "unexpected stdlib bootstrap failure; no parser byte was imported",
    fix: "restore exact reviewed bootstrap inputs and rerun",
    rule: "SETUP_FAILED",
    subject: "boundary runtime bootstrap failed unexpectedly",
    bootstrapCode: "BOUNDARY_BOOTSTRAP_UNEXPECTED",
  });
}
