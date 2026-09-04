import { randomBytes, createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  closeSync,
  chmodSync,
  copyFileSync,
  existsSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readSync,
  readdirSync,
  realpathSync,
  rmSync,
  statfsSync,
  writeSync,
  writeFileSync,
} from "node:fs";
import { constants as fsConstants } from "node:fs";
import { dirname, join, posix, relative, resolve, sep } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import {
  TarballValidationError,
  bytewiseCompare,
  canonicalJson,
  readSafeNpmTarball,
  sha256Hex,
} from "./safe-npm-tarball.mjs";
export const CANDIDATE_STATUS = "CANDIDATE / NON-RELEASE";
export const MANIFEST_SCHEMA = "noa.publish-artifact-set/2";
export const PUBLISH_TOOLCHAIN_CONTRACT = Object.freeze({
  image:
    "docker.io/library/node@sha256:62e4daa6819762bbd3072af77cc282ab72c631c4aed30dd7980192babaf385b3",
  node: "22.22.2",
  npm: "10.9.7",
  packStack: Object.freeze({
    arborist: "8.0.4",
    npmPacklist: "9.0.0",
    tar: "7.5.11",
  }),
});
export const NODE_IMAGE = PUBLISH_TOOLCHAIN_CONTRACT.image;
export const EXPECTED_HOST_NODE = PUBLISH_TOOLCHAIN_CONTRACT.node;
export const EXPECTED_NODE = PUBLISH_TOOLCHAIN_CONTRACT.node;
export const EXPECTED_NPM = PUBLISH_TOOLCHAIN_CONTRACT.npm;
export const EXPECTED_PACK_STACK = PUBLISH_TOOLCHAIN_CONTRACT.packStack;

const THIS_DIR = dirname(fileURLToPath(import.meta.url));
const { COPYFILE_EXCL } = fsConstants;
// The stdlib-only bootstrap sets this only while it executes this exact Git blob. It prevents the
// copied executor from treating its temporary controller directory as the repository to inspect.
const DEFAULT_REPO_ROOT = resolve(process.env.NOA_PUBLISH_ARTIFACT_REPO_ROOT ?? resolve(THIS_DIR, "../.."));
const DRIVER = join(THIS_DIR, "publish-container-driver.mjs");
const NPM_HOMEDIR_OVERRIDE = join(THIS_DIR, "npm-homedir-override.cjs");
const SURFACE_LINTER = resolve(THIS_DIR, "../lint-published-surface.mjs");
const POLICY = join(THIS_DIR, "publish-artifact-policy.json");
const PUBLIC_REPOS = join(THIS_DIR, "../boundary-public-repos.json");
const POLICY_REPO_PATH = "scripts/lib/publish-artifact-policy.json";
const POLICY_SCHEMA = "noa.publish-artifact-policy/2";
const CONTROLLER_REPO_PATHS = Object.freeze([
  "scripts/boundary-public-repos.json",
  "scripts/lib/npm-homedir-override.cjs",
  "scripts/lib/publish-artifact-executor.mjs",
  "scripts/lib/publish-artifact-policy.json",
  "scripts/lib/publish-artifact-staging.mjs",
  "scripts/lib/publish-container-driver.mjs",
  "scripts/lib/safe-npm-tarball.mjs",
  "scripts/lib/stage-publish-artifacts.mjs",
  "scripts/lint-published-surface.mjs",
]);
const STRICT_UTF8 = new TextDecoder("utf-8", { fatal: true });
const FORBIDDEN_PATH_CHARS_RE = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/u;
const PACKAGE_NAME_RE = /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/u;
const VERSION_RE = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/u;
const DEPENDENCY_FIELDS = Object.freeze(["dependencies", "optionalDependencies", "peerDependencies"]);
const REQUIRED_PUBLIC_CARRIER_PATHS = Object.freeze(["LICENSE", "NOTICE", "README.md", "package.json"]);
const BUILD_TSCONFIGS = Object.freeze(["tsconfig.json", "packages/approval-artifacts/tsconfig.json"]);
const BUILD_OUTPUT_ROOTS = Object.freeze(["dist/src", "packages/approval-artifacts/dist/src"]);
const DOCKER_CANDIDATES = Object.freeze([
  "/Applications/Docker.app/Contents/Resources/bin/docker",
  "/usr/local/bin/docker",
  "/usr/bin/docker",
]);
const DOCKER_OWNERSHIP_LABEL = "io.noa.publish-artifact-staging.owner";
const DOCKER_CLEANUP_QUIET_OBSERVATIONS = 2;
const DOCKER_CLEANUP_QUIET_INTERVAL_MS = 250;
const DOCKER_CLEANUP_MAX_QUERIES = 8;
const DOCKER_CLEANUP_COMMAND_TIMEOUT_MS = 3_000;
const DOCKER_CLEANUP_TIME_BUDGET_MS = 60_000;
const GIT_CANDIDATES = Object.freeze(["/usr/bin/git", "/opt/homebrew/bin/git"]);
const MIB = 1024 * 1024;

/**
 * The offline cache is copied into a 2 GiB container tmpfs before `npm ci` consumes it. These are
 * resource controls, not npm-content policy: 512 MiB leaves 75% of that tmpfs for npm metadata,
 * temporary extraction and logs; 192 MiB prevents one entry consuming most of the cache allowance;
 * 4,096 files plus derived 16,384-directory / 32-component-depth ceilings bound inode, recursion
 * and traversal work. As a disconfirming host measurement on 2026-08-31,
 * the populated npm content cache held 488 files / 168,099,779 bytes / 120,938,684-byte maximum, so
 * the fixed controls retain >8x count, >3x total-byte and >1.5x per-file headroom.
 */
export const OFFLINE_CACHE_LIMITS = Object.freeze({
  fileCount: 4_096,
  perFileBytes: 192 * MIB,
  totalBytes: 512 * MIB,
});
const CACHE_COPY_BUFFER_BYTES = MIB;
const CACHE_DESTINATION_FREE_RESERVE_BYTES = 64 * MIB;
const CACHE_MAX_PATH_DEPTH = 32;
const CACHE_MAX_DIRECTORIES = 16_384;

export class SetupFailure extends Error {
  constructor(message) {
    super(message);
    this.name = "SetupFailure";
  }
}

export class ValidationFailure extends Error {
  constructor(message) {
    super(message);
    this.name = "ValidationFailure";
  }
}

function fail(message) {
  throw new ValidationFailure(message);
}

function setupFail(message) {
  throw new SetupFailure(message);
}

function safeOneLine(value, limit = 8_000) {
  const text = String(value ?? "");
  return JSON.stringify(text.length > limit ? `${text.slice(0, limit)}…[truncated]` : text);
}

function requireExactKeys(value, expected, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(`${label} is not an object`);
  const actual = Object.keys(value).sort(bytewiseCompare);
  const wanted = [...expected].sort(bytewiseCompare);
  if (JSON.stringify(actual) !== JSON.stringify(wanted)) {
    fail(`${label} keys are not exact: ${JSON.stringify(actual)}`);
  }
}

function assertRealFile(path, label) {
  let stat;
  try {
    stat = lstatSync(path);
  } catch (error) {
    fail(`${label} is unavailable at ${JSON.stringify(path)}: ${String(error && error.message)}`);
  }
  if (stat.isSymbolicLink() || !stat.isFile()) {
    fail(`${label} must be a real regular file: ${JSON.stringify(path)}`);
  }
  return stat;
}

function assertRealDirectory(path, label) {
  let stat;
  try {
    stat = lstatSync(path);
  } catch (error) {
    fail(`${label} is unavailable at ${JSON.stringify(path)}: ${String(error && error.message)}`);
  }
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    fail(`${label} must be a real directory: ${JSON.stringify(path)}`);
  }
  return stat;
}

function resolveExecutable(candidates, label) {
  for (const candidate of candidates) {
    try {
      const resolved = realpathSync(candidate);
      const stat = lstatSync(resolved);
      if (stat.isFile() && (stat.mode & 0o111) !== 0) return resolved;
    } catch {}
  }
  setupFail(`${label} executable is unavailable in the fixed candidate set`);
}

function closedGitEnv() {
  return {
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_NO_REPLACE_OBJECTS: "1",
    LANG: "C",
    LC_ALL: "C",
    PATH: "/usr/bin:/bin",
  };
}

export function closedGitEnvForSelftest() {
  return { ...closedGitEnv() };
}

function runCommand(executable, args, options = {}) {
  const result = spawnSync(executable, args, {
    cwd: options.cwd,
    encoding: options.encoding,
    env: options.env,
    input: options.input,
    maxBuffer: options.maxBuffer ?? 512 * 1024 * 1024,
    timeout: options.timeout ?? 10 * 60 * 1000,
  });
  if (result.error) {
    const problem = `${options.label ?? executable} could not start: ${result.error.message}`;
    if (options.setup) setupFail(problem);
    fail(problem);
  }
  if (result.signal) {
    fail(`${options.label ?? executable} terminated by signal ${result.signal}`);
  }
  if (result.status !== 0 && !options.allowFailure) {
    const message =
      `${options.label ?? executable} exited ${String(result.status)}; stdout=${safeOneLine(result.stdout)}; ` +
      `stderr=${safeOneLine(result.stderr)}`;
    if (options.setup) setupFail(message);
    fail(message);
  }
  return result;
}

function gitText(git, repoRoot, args, label) {
  return runCommand(git, args, {
    cwd: repoRoot,
    encoding: "utf8",
    env: closedGitEnv(),
    label,
  }).stdout.trim();
}

export function validateRepositoryPath(path) {
  if (typeof path !== "string" || path === "" || path.startsWith("/") || path.includes("\\") ||
      FORBIDDEN_PATH_CHARS_RE.test(path) || path.normalize("NFC") !== path) {
    fail(`unsafe or non-canonical repository path ${JSON.stringify(path)}`);
  }
  const components = path.split("/");
  if (components.some((component) => component === "" || component === "." || component === "..")) {
    fail(`unsafe repository path component in ${JSON.stringify(path)}`);
  }
  return path;
}

function decodeStrict(bytes, label) {
  try {
    const text = STRICT_UTF8.decode(bytes);
    if (!Buffer.from(text, "utf8").equals(bytes)) fail(`${label} is not canonical UTF-8`);
    return text;
  } catch (error) {
    if (error instanceof ValidationFailure) throw error;
    fail(`${label} is not strict UTF-8`);
  }
}

export function parseGitLsTree(buffer, objectFormat) {
  const expectedOidLength = objectFormat === "sha1" ? 40 : objectFormat === "sha256" ? 64 : 0;
  if (expectedOidLength === 0) fail(`unsupported Git object format ${JSON.stringify(objectFormat)}`);
  const records = [];
  const seenPaths = new Set();
  let offset = 0;
  while (offset < buffer.length) {
    const nul = buffer.indexOf(0, offset);
    if (nul === -1) fail("git ls-tree output lacks a NUL terminator");
    const record = buffer.subarray(offset, nul);
    offset = nul + 1;
    if (record.length === 0) fail("git ls-tree emitted an empty record");
    const tab = record.indexOf(0x09);
    if (tab === -1) fail("git ls-tree record lacks a path separator");
    const metadata = record.subarray(0, tab).toString("ascii");
    const match = /^(100644|100755|120000|160000) (blob|commit) ([0-9a-f]+) +([0-9-]+)$/u.exec(metadata);
    if (!match) fail(`unrecognized git ls-tree metadata ${JSON.stringify(metadata)}`);
    const [, mode, type, oid, sizeRaw] = match;
    if (oid.length !== expectedOidLength) fail(`Git object id has wrong length in ${metadata}`);
    const path = validateRepositoryPath(decodeStrict(record.subarray(tab + 1), "Git path"));
    if (seenPaths.has(path)) fail(`duplicate Git path ${JSON.stringify(path)}`);
    seenPaths.add(path);
    if ((mode !== "100644" && mode !== "100755") || type !== "blob") {
      fail(`Git source contains forbidden non-regular entry ${JSON.stringify(path)} (${mode} ${type})`);
    }
    if (!/^(?:0|[1-9][0-9]*)$/u.test(sizeRaw)) fail(`invalid Git blob size for ${path}`);
    const size = Number(sizeRaw);
    if (!Number.isSafeInteger(size)) fail(`Git blob is too large for safe staging: ${path}`);
    records.push({ mode, oid, path, size });
  }
  if (records.length === 0) fail("Git source tree contains zero regular files");
  records.sort((left, right) => bytewiseCompare(left.path, right.path));
  return records;
}

function gitBlobOid(bytes, objectFormat) {
  const algorithm = objectFormat === "sha1" ? "sha1" : objectFormat === "sha256" ? "sha256" : null;
  if (!algorithm) fail(`unsupported Git object format ${objectFormat}`);
  return createHash(algorithm).update(`blob ${bytes.length}\0`).update(bytes).digest("hex");
}

function readGitBlobBatch(git, repoRoot, records) {
  const input = Buffer.from(`${records.map((record) => record.oid).join("\n")}\n`, "ascii");
  const result = runCommand(git, ["cat-file", "--batch"], {
    cwd: repoRoot,
    env: closedGitEnv(),
    input,
    label: "git cat-file --batch",
  });
  const output = result.stdout;
  const blobs = new Map();
  let offset = 0;
  for (const record of records) {
    const newline = output.indexOf(0x0a, offset);
    if (newline === -1) fail(`git cat-file omitted a header for ${record.path}`);
    const header = output.subarray(offset, newline).toString("ascii");
    const match = /^([0-9a-f]+) blob ([0-9]+)$/u.exec(header);
    if (!match || match[1] !== record.oid || Number(match[2]) !== record.size) {
      fail(`git cat-file header disagrees with inventory for ${record.path}`);
    }
    const start = newline + 1;
    const end = start + record.size;
    if (end >= output.length || output[end] !== 0x0a) fail(`git cat-file truncated ${record.path}`);
    blobs.set(record.path, Buffer.from(output.subarray(start, end)));
    offset = end + 1;
  }
  if (offset !== output.length) fail("git cat-file emitted unrequested trailing bytes");
  return blobs;
}

export function loadGitSource(repoRoot = DEFAULT_REPO_ROOT, requestedRef = "HEAD") {
  const realRoot = realpathSync(repoRoot);
  assertRealDirectory(realRoot, "repository root");
  const git = resolveExecutable(GIT_CANDIDATES, "Git");
  const commit = gitText(git, realRoot, ["rev-parse", "--verify", `${requestedRef}^{commit}`], "resolve Git commit");
  const objectFormat = gitText(git, realRoot, ["rev-parse", "--show-object-format"], "read Git object format");
  const expectedLength = objectFormat === "sha1" ? 40 : objectFormat === "sha256" ? 64 : 0;
  if (!new RegExp(`^[0-9a-f]{${expectedLength}}$`, "u").test(commit)) fail("resolved Git commit is malformed");
  const tree = gitText(git, realRoot, ["rev-parse", `${commit}^{tree}`], "resolve Git tree");
  const commitTimeRaw = gitText(git, realRoot, ["show", "-s", "--format=%ct", commit], "read commit time");
  if (!/^[0-9]+$/u.test(commitTimeRaw)) fail("Git commit time is malformed");
  const listed = runCommand(git, ["ls-tree", "-rz", "-r", "-l", "--full-tree", commit], {
    cwd: realRoot,
    env: closedGitEnv(),
    label: "inventory immutable Git tree",
  }).stdout;
  const records = parseGitLsTree(listed, objectFormat);
  const blobs = readGitBlobBatch(git, realRoot, records);
  for (const record of records) {
    const bytes = blobs.get(record.path);
    if (!bytes || bytes.length !== record.size || gitBlobOid(bytes, objectFormat) !== record.oid) {
      fail(`Git blob proof failed for ${record.path}`);
    }
  }
  const inventoryRows = records.map(({ mode, oid, path, size }) => ({ mode, oid, path, size }));
  return {
    blobs,
    commit,
    commitTime: Number(commitTimeRaw),
    git,
    inventoryDigest: sha256Hex(Buffer.from(canonicalJson(inventoryRows), "utf8")),
    objectFormat,
    records,
    repoRoot: realRoot,
    tree,
  };
}

function parseManifest(bytes, path) {
  let manifest;
  try {
    manifest = JSON.parse(decodeStrict(bytes, path));
  } catch (error) {
    if (error instanceof ValidationFailure) throw error;
    fail(`invalid JSON manifest ${path}: ${String(error && error.message)}`);
  }
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) {
    fail(`package manifest is not an object: ${path}`);
  }
  return manifest;
}

function validatePackageIdentity(manifest, packagePath) {
  const { name, version } = manifest;
  if (typeof name !== "string" || name.length > 214 || !PACKAGE_NAME_RE.test(name)) {
    fail(`invalid public package name at ${packagePath}: ${JSON.stringify(name)}`);
  }
  if (typeof version !== "string" || !VERSION_RE.test(version)) {
    fail(`invalid public package version at ${packagePath}: ${JSON.stringify(version)}`);
  }
  const filename = `${name}-${version}.tgz`.replace(/^@/u, "").replace("/", "-");
  return { filename, name, version };
}

export function derivePackageInventory(gitSource) {
  const byPath = new Map(gitSource.records.map((record) => [record.path, record]));
  const packageChildren = new Set();
  for (const record of gitSource.records) {
    if (!record.path.startsWith("packages/")) continue;
    const parts = record.path.split("/");
    if (parts.length < 3) {
      fail(`packages inventory contains a non-directory root entry: ${JSON.stringify(record.path)}`);
    }
    packageChildren.add(parts[1]);
  }
  const manifestPaths = ["package.json"];
  for (const child of [...packageChildren].sort(bytewiseCompare)) {
    const manifestPath = `packages/${child}/package.json`;
    if (byPath.has(manifestPath)) manifestPaths.push(manifestPath);
  }
  const packages = [];
  const seenNames = new Set();
  const seenFilenames = new Set();
  const seenPaths = new Set();
  for (const manifestPath of manifestPaths) {
    const record = byPath.get(manifestPath);
    if (!record) fail(`required root manifest is absent: ${manifestPath}`);
    const sourceBytes = gitSource.blobs.get(manifestPath);
    const manifest = parseManifest(sourceBytes, manifestPath);
    if (manifest.private === true) {
      if (manifest.publishConfig?.access === "public") {
        fail(`private package declares contradictory public publish access: ${manifestPath}`);
      }
      if (manifestPath === "package.json") fail("the root package unexpectedly became private");
      continue;
    }
    const packagePath = manifestPath === "package.json" ? "." : posix.dirname(manifestPath);
    const identity = validatePackageIdentity(manifest, packagePath);
    if (seenPaths.has(packagePath)) fail(`duplicate public package path ${packagePath}`);
    if (seenNames.has(identity.name)) fail(`duplicate public package name ${identity.name}`);
    if (seenFilenames.has(identity.filename)) fail(`duplicate public tarball filename ${identity.filename}`);
    seenPaths.add(packagePath);
    seenNames.add(identity.name);
    seenFilenames.add(identity.filename);
    packages.push({
      ...identity,
      manifest,
      manifestPath,
      packagePath,
      sourceManifestGitOid: record.oid,
      sourceManifestSha256: sha256Hex(sourceBytes),
      sourceManifestBytes: sourceBytes,
    });
  }
  if (packages.length === 0) fail("derived zero publishable packages");
  packages.sort((left, right) => bytewiseCompare(left.packagePath, right.packagePath));
  return packages;
}

export function isLocalDependencySpecifier(specifier) {
  if (typeof specifier !== "string") return false;
  return specifier.startsWith("file:") || specifier.startsWith("link:") ||
    specifier.startsWith("portal:") || specifier.startsWith("./") ||
    specifier.startsWith("../") || specifier.startsWith("/") || specifier.startsWith("~/");
}

function resolveLocalDependency(packagePath, specifier) {
  let raw = specifier;
  for (const prefix of ["file:", "link:", "portal:"]) {
    if (raw.startsWith(prefix)) raw = raw.slice(prefix.length);
  }
  if (raw === "" || raw.startsWith("/") || raw.startsWith("~/") || raw.includes("\\") ||
      FORBIDDEN_PATH_CHARS_RE.test(raw)) {
    fail(`unsupported local dependency target ${JSON.stringify(specifier)} from ${packagePath}`);
  }
  const base = packagePath === "." ? "." : packagePath;
  const target = posix.normalize(posix.join(base, raw));
  if (target === ".." || target.startsWith("../") || target === "" || target.startsWith("/")) {
    fail(`local dependency escapes repository: ${JSON.stringify(specifier)} from ${packagePath}`);
  }
  return target === "" ? "." : target;
}

export function planReleaseManifests(packages) {
  const byPath = new Map(packages.map((entry) => [entry.packagePath, entry]));
  const planned = [];
  for (const entry of packages) {
    const releaseManifest = structuredClone(entry.manifest);
    const transformations = [];
    if (Object.prototype.hasOwnProperty.call(releaseManifest, "repository")) {
      delete releaseManifest.repository;
      transformations.push({
        field: "repository",
        from: "SOURCE_OMITTED_FROM_PUBLIC_ARTIFACT",
        name: "repository",
        targetPath: entry.packagePath,
        to: "SOURCE_ABSENT",
      });
    }
    for (const field of DEPENDENCY_FIELDS) {
      const dependencies = releaseManifest[field];
      if (dependencies === undefined) continue;
      if (!dependencies || typeof dependencies !== "object" || Array.isArray(dependencies)) {
        fail(`${entry.packagePath} ${field} is not an object`);
      }
      for (const name of Object.keys(dependencies).sort(bytewiseCompare)) {
        const specifier = dependencies[name];
        if (!isLocalDependencySpecifier(specifier)) continue;
        const targetPath = resolveLocalDependency(entry.packagePath, specifier);
        const target = byPath.get(targetPath);
        if (!target) {
          fail(`${entry.packagePath} ${field}.${name} targets non-publishable ${targetPath}`);
        }
        if (target.name !== name) {
          fail(
            `${entry.packagePath} ${field}.${name} resolves to ${targetPath} named ${target.name}`,
          );
        }
        const replacement = `^${target.version}`;
        dependencies[name] = replacement;
        transformations.push({ field, from: specifier, name, targetPath, to: replacement });
      }
    }
    for (const field of DEPENDENCY_FIELDS) {
      for (const [name, specifier] of Object.entries(releaseManifest[field] ?? {})) {
        if (isLocalDependencySpecifier(specifier)) {
          fail(`release manifest retains local dependency ${entry.packagePath} ${field}.${name}`);
        }
      }
    }
    const releaseManifestBytes = transformations.length === 0
      ? Buffer.from(entry.sourceManifestBytes)
      : Buffer.from(`${JSON.stringify(releaseManifest, null, 2)}\n`, "utf8");
    planned.push({
      ...entry,
      releaseManifest,
      releaseManifestBytes,
      releaseManifestSha256: sha256Hex(releaseManifestBytes),
      transformations,
    });
  }
  return planned;
}

export function loadPublishArtifactPolicy(policyPath = POLICY) {
  assertRealFile(policyPath, "publish-artifact policy");
  let policy;
  try {
    policy = JSON.parse(decodeStrict(readFileSync(policyPath), "publish-artifact policy"));
  } catch (error) {
    if (error instanceof ValidationFailure) throw error;
    fail(`publish-artifact policy is invalid JSON: ${String(error && error.message)}`);
  }
  requireExactKeys(
    policy,
    ["allowedBuildOutputPrefixes", "manifestPolicy", "packages", "schema"],
    "publish-artifact policy",
  );
  if (policy.schema !== POLICY_SCHEMA || !Array.isArray(policy.allowedBuildOutputPrefixes) ||
      !policy.manifestPolicy || typeof policy.manifestPolicy !== "object" ||
      Array.isArray(policy.manifestPolicy) || !Array.isArray(policy.packages) ||
      policy.packages.length === 0) {
    fail("publish-artifact policy schema or arrays are invalid");
  }
  requireExactKeys(
    policy.manifestPolicy,
    ["enginesNode", "homepage", "license", "provenanceRequired"],
    "publish-artifact manifest policy",
  );
  if (policy.manifestPolicy.enginesNode !== ">=20" ||
      policy.manifestPolicy.homepage !== "https://noatrust.com" ||
      policy.manifestPolicy.license !== "Apache-2.0" ||
      policy.manifestPolicy.provenanceRequired !== true) {
    fail("publish-artifact manifest policy does not match the canonical public-package contract");
  }
  const prefixes = new Set();
  for (const prefix of policy.allowedBuildOutputPrefixes) {
    if (typeof prefix !== "string" || prefix === "" || !prefix.endsWith("/")) {
      fail(`publish-artifact policy has an invalid build-output prefix ${JSON.stringify(prefix)}`);
    }
    validateRepositoryPath(prefix.slice(0, -1));
    if (prefixes.has(prefix)) fail(`publish-artifact policy repeats build-output prefix ${prefix}`);
    prefixes.add(prefix);
  }
  const controllerOutputPrefixes = BUILD_OUTPUT_ROOTS.map((path) => `${path}/`);
  if (canonicalJson(policy.allowedBuildOutputPrefixes) !== canonicalJson(controllerOutputPrefixes)) {
    fail("publish-artifact policy build-output roots do not match the trusted controller copy roots");
  }
  const paths = new Set();
  const names = new Set();
  for (const entry of policy.packages) {
    requireExactKeys(
      entry,
      ["name", "noticeTitle", "packagePath", "pathCount", "pathSetSha256"],
      "policy package",
    );
    validatePackageIdentity({ name: entry.name, version: "0.0.0" }, entry.packagePath);
    if (entry.packagePath !== ".") validateRepositoryPath(entry.packagePath);
    requireSafeInteger(entry.pathCount, `policy ${entry.name} path count`, 1);
    if (typeof entry.noticeTitle !== "string" || entry.noticeTitle === "" ||
        entry.noticeTitle.includes("\n") || entry.noticeTitle.includes("\r")) {
      fail(`policy ${entry.name} notice title is invalid`);
    }
    if (!/^[0-9a-f]{64}$/u.test(entry.pathSetSha256 ?? "")) {
      fail(`policy ${entry.name} path-set digest is malformed`);
    }
    if (paths.has(entry.packagePath) || names.has(entry.name)) {
      fail("publish-artifact policy contains a duplicate package path or name");
    }
    paths.add(entry.packagePath);
    names.add(entry.name);
  }
  return {
    ...policy,
    sha256: sha256Hex(readFileSync(policyPath)),
  };
}

export function validatePublicPackageMetadata(packages, policy, gitSource) {
  if (!gitSource || !(gitSource.blobs instanceof Map)) {
    fail("public-package metadata validation lacks immutable Git bytes");
  }
  const byPath = new Map(policy.packages.map((entry) => [entry.packagePath, entry]));
  for (const entry of packages) {
    const manifest = entry.releaseManifest;
    if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) {
      fail(`${entry.name} public-package metadata validation requires a derived release manifest`);
    }
    const packagePolicy = byPath.get(entry.packagePath);
    if (!packagePolicy) fail(`public-package policy is absent for ${entry.packagePath}`);
    const expectedPublishConfig = {
      access: "public",
      provenance: policy.manifestPolicy.provenanceRequired,
    };
    if (manifest.license !== policy.manifestPolicy.license) {
      fail(`${entry.name} license is not the public-package policy value`);
    }
    if (manifest.homepage !== policy.manifestPolicy.homepage) {
      fail(`${entry.name} homepage is not the public-package policy value`);
    }
    if (Object.prototype.hasOwnProperty.call(manifest, "repository")) {
      fail(`${entry.name} public manifest must omit repository metadata until an approved public source exists`);
    }
    if (canonicalJson(manifest.publishConfig) !== canonicalJson(expectedPublishConfig)) {
      fail(`${entry.name} publishConfig does not require public access and provenance`);
    }
    if (manifest.engines?.node !== policy.manifestPolicy.enginesNode) {
      fail(`${entry.name} Node engine does not match the public-package policy`);
    }
    if (!Array.isArray(manifest.keywords) || manifest.keywords.length < 3 ||
        manifest.keywords.some((keyword) => typeof keyword !== "string" || keyword === "") ||
        new Set(manifest.keywords).size !== manifest.keywords.length) {
      fail(`${entry.name} keywords are absent, malformed, or duplicated`);
    }
    if (!Array.isArray(manifest.files) ||
        ["LICENSE", "NOTICE", "README.md"].some((path) => !manifest.files.includes(path)) ||
        new Set(manifest.files).size !== manifest.files.length) {
      fail(`${entry.name} files inventory lacks a unique required public carrier path`);
    }
    if (typeof manifest.main === "string") {
      const hasRootExport = typeof manifest.exports === "string" ||
        (manifest.exports && typeof manifest.exports === "object" &&
          !Array.isArray(manifest.exports) && manifest.exports["."] !== undefined);
      if (!hasRootExport) fail(`${entry.name} importable main has no explicit root export`);
    }
    const noticePath = entry.packagePath === "." ? "NOTICE" : `${entry.packagePath}/NOTICE`;
    const noticeBytes = gitSource.blobs.get(noticePath);
    if (!noticeBytes) fail(`${entry.name} NOTICE is absent from immutable Git source`);
    const noticeText = decodeStrict(noticeBytes, noticePath);
    const newline = noticeText.indexOf("\n");
    const firstLine = newline === -1 ? noticeText : noticeText.slice(0, newline);
    if (firstLine !== packagePolicy.noticeTitle) {
      fail(`${entry.name} NOTICE title does not match the independent package policy`);
    }
  }
}

function enforcePolicyPackageSet(packages, policy, gitSource) {
  const actual = packages.map(({ name, packagePath }) => ({ name, packagePath }));
  const expected = policy.packages.map(({ name, packagePath }) => ({ name, packagePath }));
  if (canonicalJson(actual) !== canonicalJson(expected)) {
    fail("publishable package set does not equal the independent publish-artifact policy");
  }
  validatePublicPackageMetadata(packages, policy, gitSource);
}

function isAllowedBuildOutput(path, policy) {
  return policy.allowedBuildOutputPrefixes.some((prefix) => path.startsWith(prefix));
}

function deriveBuildOutputCensus(gitSource, frozenEvidence, policy) {
  const gitPaths = new Set(gitSource.records.map((record) => record.path));
  const outputs = frozenEvidence.rows.filter((row) => !gitPaths.has(row.path));
  if (outputs.length === 0) fail("frozen snapshot contains zero build-output files");
  for (const row of outputs) {
    if (!isAllowedBuildOutput(row.path, policy)) {
      fail(`frozen snapshot contains an unapproved build-output path ${JSON.stringify(row.path)}`);
    }
  }
  for (const prefix of policy.allowedBuildOutputPrefixes) {
    if (!outputs.some((row) => row.path.startsWith(prefix))) {
      fail(`frozen snapshot has no output below required policy prefix ${prefix}`);
    }
  }
  return outputs;
}

function deriveCarriedBuildOutputCensus(gitSource, buildRoot, policy) {
  const tracked = new Set(gitSource.records.map((record) => record.path));
  const carriedRows = digestRealTree(buildRoot).rows.filter((row) =>
    tracked.has(row.path) || isAllowedBuildOutput(row.path, policy));
  return deriveBuildOutputCensus(gitSource, { rows: carriedRows }, policy);
}

function materializeGitSource(gitSource, destination) {
  mkdirSync(destination, { recursive: false, mode: 0o700 });
  for (const record of gitSource.records) {
    const absolute = join(destination, ...record.path.split("/"));
    mkdirSync(dirname(absolute), { recursive: true, mode: 0o755 });
    writeFileSync(absolute, gitSource.blobs.get(record.path), {
      flag: "wx",
      mode: record.mode === "100755" ? 0o755 : 0o644,
    });
  }
  verifyMaterializedGitSource(gitSource, destination);
}

function materializeExactController(gitSource, workRoot) {
  const controllerRoot = join(workRoot, "exact-controller");
  mkdirSync(controllerRoot, { recursive: false, mode: 0o700 });
  const records = new Map(gitSource.records.map((record) => [record.path, record]));
  for (const path of CONTROLLER_REPO_PATHS) {
    const record = records.get(path);
    const bytes = gitSource.blobs.get(path);
    if (!record || !bytes || record.mode !== "100644") fail(`exact Git controller lacks regular file ${path}`);
    const target = join(controllerRoot, ...path.split("/"));
    mkdirSync(dirname(target), { recursive: true, mode: 0o755 });
    writeFileSync(target, bytes, { flag: "wx", mode: 0o644 });
    if (!readFileSync(target).equals(bytes)) fail(`exact Git controller materialization drifted for ${path}`);
  }
  return {
    driver: join(controllerRoot, "scripts", "lib", "publish-container-driver.mjs"),
    executor: join(controllerRoot, "scripts", "lib", "publish-artifact-executor.mjs"),
    linter: join(controllerRoot, "scripts", "lint-published-surface.mjs"),
    policy: join(controllerRoot, "scripts", "lib", "publish-artifact-policy.json"),
    publicRepos: join(controllerRoot, "scripts", "boundary-public-repos.json"),
    safeTarballParser: join(controllerRoot, "scripts", "lib", "safe-npm-tarball.mjs"),
    bootstrap: join(controllerRoot, "scripts", "lib", "stage-publish-artifacts.mjs"),
    staging: join(controllerRoot, "scripts", "lib", "publish-artifact-staging.mjs"),
    npmHomedirOverride: join(controllerRoot, "scripts", "lib", "npm-homedir-override.cjs"),
  };
}

export function materializeExactControllerForSelftest(gitSource, workRoot) {
  return materializeExactController(gitSource, workRoot);
}

function walkRealFiles(root, relativeRoot = "") {
  const absoluteRoot = relativeRoot === "" ? root : join(root, ...relativeRoot.split("/"));
  const stat = lstatSync(absoluteRoot);
  if (stat.isSymbolicLink() || !stat.isDirectory()) fail(`tree root is not a real directory: ${absoluteRoot}`);
  const rows = [];
  const visit = (absolute, relativePath) => {
    const entries = readdirSync(absolute, { withFileTypes: true }).sort((left, right) =>
      bytewiseCompare(left.name, right.name));
    for (const entry of entries) {
      const nextRelative = relativePath === "" ? entry.name : `${relativePath}/${entry.name}`;
      validateRepositoryPath(nextRelative);
      const nextAbsolute = join(absolute, entry.name);
      const nextStat = lstatSync(nextAbsolute);
      if (nextStat.isSymbolicLink()) fail(`tree contains a symbolic link: ${nextRelative}`);
      if (nextStat.isDirectory()) visit(nextAbsolute, nextRelative);
      else if (nextStat.isFile()) {
        const bytes = readFileSync(nextAbsolute);
        rows.push({
          mode: (nextStat.mode & 0o111) !== 0 ? "100755" : "100644",
          path: nextRelative,
          sha256: sha256Hex(bytes),
          size: bytes.length,
        });
      } else fail(`tree contains a special filesystem entry: ${nextRelative}`);
    }
  };
  visit(absoluteRoot, "");
  rows.sort((left, right) => bytewiseCompare(left.path, right.path));
  return rows;
}

export function verifyMaterializedGitSource(gitSource, destination) {
  const actual = walkRealFiles(destination);
  if (actual.length !== gitSource.records.length) {
    fail(`materialized Git file count mismatch: ${actual.length} != ${gitSource.records.length}`);
  }
  for (let index = 0; index < actual.length; index++) {
    const row = actual[index];
    const expected = gitSource.records[index];
    if (row.path !== expected.path || row.mode !== expected.mode || row.size !== expected.size) {
      fail(`materialized Git inventory mismatch at ${JSON.stringify(row.path)}`);
    }
    const bytes = readFileSync(join(destination, ...row.path.split("/")));
    if (gitBlobOid(bytes, gitSource.objectFormat) !== expected.oid) {
      fail(`materialized Git bytes mismatch at ${row.path}`);
    }
  }
}

export function digestRealTree(root) {
  const rows = walkRealFiles(root);
  return {
    count: rows.length,
    digest: sha256Hex(Buffer.from(canonicalJson(rows), "utf8")),
    rows,
    size: rows.reduce((sum, row) => sum + row.size, 0),
  };
}

function dependencyInputFromCache(evidence) {
  return {
    count: evidence.count,
    sha256: evidence.digest,
    size: evidence.size,
  };
}

function sameFilesystemState(left, right) {
  return ["dev", "ino", "mode", "nlink", "uid", "gid", "size", "mtimeNs", "ctimeNs"]
    .every((field) => left[field] === right[field]);
}

function normalizeOfflineCacheLimits(limits = OFFLINE_CACHE_LIMITS) {
  requireExactKeys(limits, ["fileCount", "perFileBytes", "totalBytes"], "offline cache limits");
  for (const [name, value] of Object.entries(limits)) {
    requireSafeInteger(value, `offline cache ${name} limit`, 1);
  }
  if (limits.perFileBytes > limits.totalBytes) {
    fail("offline cache per-file limit exceeds its total-byte limit");
  }
  return Object.freeze({ ...limits });
}

function inventoryOfflineCache(root, label, limits) {
  const files = [];
  const directories = [];
  let totalBytes = 0;
  let visitedDirectories = 0;
  const directoryLimit = Math.min(CACHE_MAX_DIRECTORIES, Math.max(64, limits.fileCount * 4));
  const visit = (path, relativePath, depth) => {
    if (depth > CACHE_MAX_PATH_DEPTH) {
      fail(`${label} exceeds the ${CACHE_MAX_PATH_DEPTH}-component path-depth limit`);
    }
    visitedDirectories++;
    if (visitedDirectories > directoryLimit) {
      fail(`${label} exceeds the ${directoryLimit}-directory traversal limit`);
    }
    const before = lstatSync(path, { bigint: true });
    if (before.isSymbolicLink() || !before.isDirectory()) {
      fail(`${label} contains a non-directory tree node: ${JSON.stringify(relativePath || ".")}`);
    }
    const names = readdirSync(path).sort(bytewiseCompare);
    for (const name of names) {
      const childRelative = relativePath === "" ? name : `${relativePath}/${name}`;
      validateRepositoryPath(childRelative);
      const childPath = join(path, name);
      const child = lstatSync(childPath, { bigint: true });
      if (child.isSymbolicLink()) {
        fail(`${label} contains a symbolic link: ${JSON.stringify(childRelative)}`);
      }
      if (child.isDirectory()) {
        visit(childPath, childRelative, depth + 1);
        continue;
      }
      if (!child.isFile()) {
        fail(`${label} contains a special filesystem entry: ${JSON.stringify(childRelative)}`);
      }
      if (child.size < 0n || child.size > BigInt(Number.MAX_SAFE_INTEGER)) {
        fail(`${label} entry is too large for exact accounting: ${JSON.stringify(childRelative)}`);
      }
      const size = Number(child.size);
      if (size > limits.perFileBytes) {
        fail(
          `${label} entry exceeds the ${limits.perFileBytes}-byte per-file limit: ` +
          JSON.stringify(childRelative),
        );
      }
      if (files.length + 1 > limits.fileCount) {
        fail(`${label} exceeds the ${limits.fileCount}-file limit`);
      }
      totalBytes += size;
      if (!Number.isSafeInteger(totalBytes) || totalBytes > limits.totalBytes) {
        fail(`${label} exceeds the ${limits.totalBytes}-byte total limit`);
      }
      files.push({ path: childPath, relativePath: childRelative, size, state: child });
    }
    const afterNames = readdirSync(path).sort(bytewiseCompare);
    const after = lstatSync(path, { bigint: true });
    if (!after.isDirectory() || canonicalJson(afterNames) !== canonicalJson(names) ||
        !sameFilesystemState(before, after)) {
      fail(`${label} directory changed while inventorying: ${JSON.stringify(relativePath || ".")}`);
    }
    directories.push({ names, path, relativePath, state: after });
  };
  visit(root, "", 0);
  files.sort((left, right) => bytewiseCompare(left.relativePath, right.relativePath));
  directories.sort((left, right) => bytewiseCompare(left.relativePath, right.relativePath));
  return { directories, files, totalBytes };
}

function verifyOfflineCacheInventoryStates(inventory, label) {
  for (const entry of inventory.files) {
    const current = lstatSync(entry.path, { bigint: true });
    if (!current.isFile() || !sameFilesystemState(entry.state, current)) {
      fail(`${label} changed before its snapshot was sealed: ${JSON.stringify(entry.relativePath)}`);
    }
  }
  for (const entry of inventory.directories) {
    const current = lstatSync(entry.path, { bigint: true });
    if (!current.isDirectory() || !sameFilesystemState(entry.state, current) ||
        canonicalJson(readdirSync(entry.path).sort(bytewiseCompare)) !== canonicalJson(entry.names)) {
      fail(`${label} changed before its snapshot was sealed: ${JSON.stringify(entry.relativePath || ".")}`);
    }
  }
}

function streamDigestFile(path, relativePath, { requireReadOnly = false, requireSingleLink = false } = {}) {
  if (!Number.isInteger(fsConstants.O_NOFOLLOW)) {
    setupFail("offline cache streaming requires O_NOFOLLOW support");
  }
  const before = lstatSync(path, { bigint: true });
  if (before.isSymbolicLink() || !before.isFile()) {
    fail(`offline cache snapshot entry is not a real regular file: ${JSON.stringify(relativePath)}`);
  }
  if (before.size < 0n || before.size > BigInt(Number.MAX_SAFE_INTEGER)) {
    fail(`offline cache snapshot entry is too large to digest exactly: ${JSON.stringify(relativePath)}`);
  }
  if (requireReadOnly && (before.mode & 0o222n) !== 0n) {
    fail(`offline cache snapshot entry remains writable: ${JSON.stringify(relativePath)}`);
  }
  if (requireSingleLink && before.nlink !== 1n) {
    fail(`offline cache snapshot entry retained a hard link: ${JSON.stringify(relativePath)}`);
  }
  let fd;
  try {
    fd = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    const opened = fstatSync(fd, { bigint: true });
    if (!opened.isFile() || opened.dev !== before.dev || opened.ino !== before.ino ||
        !sameFilesystemState(before, opened)) {
      fail(`offline cache snapshot entry changed while opening: ${JSON.stringify(relativePath)}`);
    }
    const buffer = Buffer.allocUnsafe(CACHE_COPY_BUFFER_BYTES);
    const hash = createHash("sha256");
    const size = Number(opened.size);
    let offset = 0;
    while (offset < size) {
      const count = readSync(fd, buffer, 0, Math.min(buffer.length, size - offset), offset);
      if (count === 0) fail(`offline cache snapshot entry became shorter: ${JSON.stringify(relativePath)}`);
      hash.update(buffer.subarray(0, count));
      offset += count;
    }
    if (readSync(fd, buffer, 0, 1, offset) !== 0) {
      fail(`offline cache snapshot entry grew while digesting: ${JSON.stringify(relativePath)}`);
    }
    const afterDescriptor = fstatSync(fd, { bigint: true });
    const afterPath = lstatSync(path, { bigint: true });
    if (!afterPath.isFile() || !sameFilesystemState(opened, afterDescriptor) ||
        !sameFilesystemState(before, afterPath)) {
      fail(`offline cache snapshot entry changed while digesting: ${JSON.stringify(relativePath)}`);
    }
    return { sha256: hash.digest("hex"), size };
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

function streamStableCacheFile(sourcePath, destinationPath, entry, afterRead) {
  if (!Number.isInteger(fsConstants.O_NOFOLLOW)) {
    setupFail("offline cache snapshot requires O_NOFOLLOW support");
  }
  const before = lstatSync(sourcePath, { bigint: true });
  if (!before.isFile() || !sameFilesystemState(entry.state, before)) {
    fail(`offline cache entry changed before opening: ${JSON.stringify(entry.relativePath)}`);
  }
  let sourceFd;
  let destinationFd;
  try {
    sourceFd = openSync(sourcePath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    const opened = fstatSync(sourceFd, { bigint: true });
    if (!opened.isFile() || !sameFilesystemState(before, opened)) {
      fail(`offline cache entry changed while opening: ${JSON.stringify(entry.relativePath)}`);
    }
    destinationFd = openSync(
      destinationPath,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW,
      0o600,
    );
    const buffer = Buffer.allocUnsafe(CACHE_COPY_BUFFER_BYTES);
    const sourceHash = createHash("sha256");
    let offset = 0;
    while (offset < entry.size) {
      const count = readSync(
        sourceFd,
        buffer,
        0,
        Math.min(buffer.length, entry.size - offset),
        offset,
      );
      if (count === 0) fail(`offline cache entry became shorter: ${JSON.stringify(entry.relativePath)}`);
      sourceHash.update(buffer.subarray(0, count));
      let written = 0;
      while (written < count) {
        const amount = writeSync(destinationFd, buffer, written, count - written, offset + written);
        if (amount === 0) fail(`offline cache snapshot write made no progress: ${JSON.stringify(entry.relativePath)}`);
        written += amount;
      }
      offset += count;
    }
    if (readSync(sourceFd, buffer, 0, 1, offset) !== 0) {
      fail(`offline cache entry grew while snapshotting: ${JSON.stringify(entry.relativePath)}`);
    }
    fsyncSync(destinationFd);
    if (afterRead) afterRead({ path: entry.relativePath, sourcePath });
    const afterDescriptor = fstatSync(sourceFd, { bigint: true });
    const afterPath = lstatSync(sourcePath, { bigint: true });
    if (!afterPath.isFile() || !sameFilesystemState(opened, afterDescriptor) ||
        !sameFilesystemState(before, afterPath)) {
      fail(`offline cache entry changed while snapshotting: ${JSON.stringify(entry.relativePath)}`);
    }
    const copiedDescriptor = fstatSync(destinationFd, { bigint: true });
    if (!copiedDescriptor.isFile() || copiedDescriptor.nlink !== 1n ||
        copiedDescriptor.size !== BigInt(entry.size)) {
      fail(`offline cache snapshot output is not an independent exact file: ${JSON.stringify(entry.relativePath)}`);
    }
    const sourceSha256 = sourceHash.digest("hex");
    closeSync(destinationFd);
    destinationFd = undefined;
    chmodSync(destinationPath, (entry.state.mode & 0o111n) !== 0n ? 0o755 : 0o644);
    const copied = streamDigestFile(destinationPath, entry.relativePath, { requireSingleLink: true });
    if (copied.size !== entry.size || copied.sha256 !== sourceSha256) {
      fail(`offline cache snapshot bytes differ from consumed source: ${JSON.stringify(entry.relativePath)}`);
    }
  } finally {
    if (destinationFd !== undefined) closeSync(destinationFd);
    if (sourceFd !== undefined) closeSync(sourceFd);
  }
}

function filesystemAvailableBytes(path, label) {
  let state;
  try {
    state = statfsSync(path, { bigint: true });
  } catch (error) {
    setupFail(`${label} capacity could not be measured: ${String(error && error.message)}`);
  }
  if (state.bsize <= 0n || state.bavail < 0n) setupFail(`${label} capacity report is malformed`);
  return state.bsize * state.bavail;
}

function preflightCacheDestinationCapacity(parent, totalBytes, label) {
  const required = BigInt(totalBytes + CACHE_DESTINATION_FREE_RESERVE_BYTES);
  if (filesystemAvailableBytes(parent, label) < required) {
    fail(
      `${label} lacks capacity for ${totalBytes} cache bytes plus ` +
      `${CACHE_DESTINATION_FREE_RESERVE_BYTES} bytes of free-space reserve`,
    );
  }
}

function verifyCacheDestinationCapacity(parent, label) {
  if (filesystemAvailableBytes(parent, label) < BigInt(CACHE_DESTINATION_FREE_RESERVE_BYTES)) {
    fail(`${label} consumed the required destination free-space reserve`);
  }
}

function digestOfflineCacheTree(root, label, limits, { requireReadOnly = false } = {}) {
  const inventory = inventoryOfflineCache(root, label, limits);
  const rows = inventory.files.map((entry) => {
    const stat = lstatSync(entry.path, { bigint: true });
    if (requireReadOnly && (stat.mode & 0o222n) !== 0n) {
      fail(`${label} remains writable: ${JSON.stringify(entry.relativePath)}`);
    }
    const digest = streamDigestFile(entry.path, entry.relativePath, {
      requireReadOnly,
      requireSingleLink: true,
    });
    return {
      mode: (stat.mode & 0o111n) !== 0n ? "100755" : "100644",
      path: entry.relativePath,
      sha256: digest.sha256,
      size: digest.size,
    };
  });
  if (requireReadOnly) {
    for (const directory of inventory.directories) {
      if ((lstatSync(directory.path, { bigint: true }).mode & 0o222n) !== 0n) {
        fail(`${label} directory remains writable: ${JSON.stringify(directory.relativePath || ".")}`);
      }
    }
  }
  verifyOfflineCacheInventoryStates(inventory, label);
  return {
    count: rows.length,
    digest: sha256Hex(Buffer.from(canonicalJson(rows), "utf8")),
    rows,
    size: inventory.totalBytes,
  };
}

function snapshotOfflineCache(offlineCache, destination, label, { afterRead, limits } = {}) {
  if (typeof offlineCache !== "string" || offlineCache === "") fail(`${label} path is required`);
  const activeLimits = normalizeOfflineCacheLimits(limits);
  const requested = resolve(offlineCache);
  assertRealDirectory(requested, label);
  const source = realpathSync(requested);
  const snapshot = resolve(destination);
  assertRealDirectory(dirname(snapshot), `${label} snapshot parent`);
  const fromSource = relative(source, snapshot);
  const fromSnapshot = relative(snapshot, source);
  if (fromSource === "" || (!fromSource.startsWith(`..${sep}`) && fromSource !== "..") ||
      (!fromSnapshot.startsWith(`..${sep}`) && fromSnapshot !== "..")) {
    fail(`${label} snapshot source and destination overlap`);
  }

  const sourceInventory = inventoryOfflineCache(source, label, activeLimits);
  if (sourceInventory.files.length === 0) fail(`${label} contains zero files`);
  preflightCacheDestinationCapacity(dirname(snapshot), sourceInventory.totalBytes, `${label} snapshot destination`);
  let snapshotOwnership;
  let completed = false;
  try {
    try {
      mkdirSync(snapshot, { recursive: false, mode: 0o700 });
    } catch (error) {
      if (error && error.code === "EEXIST") fail(`${label} snapshot destination already exists`);
      throw error;
    }
    snapshotOwnership = captureOwnedDirectory(snapshot, `${label} snapshot`);
    for (const directory of sourceInventory.directories
      .filter((entry) => entry.relativePath !== "")
      .sort((left, right) => left.relativePath.split("/").length - right.relativePath.split("/").length ||
        bytewiseCompare(left.relativePath, right.relativePath))) {
      mkdirSync(join(snapshot, ...directory.relativePath.split("/")), { recursive: false, mode: 0o700 });
    }
    for (const entry of sourceInventory.files) {
      streamStableCacheFile(
        entry.path,
        join(snapshot, ...entry.relativePath.split("/")),
        entry,
        afterRead,
      );
    }
    verifyOfflineCacheInventoryStates(sourceInventory, label);
    makeReadOnly(snapshot);
    const evidence = digestOfflineCacheTree(snapshot, `${label} owned snapshot`, activeLimits, {
      requireReadOnly: true,
    });
    verifyCacheDestinationCapacity(dirname(snapshot), `${label} snapshot destination`);
    completed = true;
    return { evidence, limits: activeLimits, path: snapshot };
  } finally {
    if (!completed) removeOwnedDirectory(snapshotOwnership, `${label} snapshot`);
  }
}

function verifyOwnedOfflineCache(cache, label) {
  const after = digestOfflineCacheTree(cache.path, label, cache.limits, { requireReadOnly: true });
  if (canonicalJson(after.rows) !== canonicalJson(cache.evidence.rows)) {
    fail(`${label} owned snapshot changed while the pinned build was running`);
  }
}

// Deterministic test seam. Release paths never expose the mutation hook and always create their
// snapshot below a fresh owner-only work root.
export function snapshotOfflineCacheForSelftest(options) {
  return snapshotOfflineCache(options.source, options.destination, "offline cache selftest", {
    afterRead: options.afterRead,
    limits: options.limits,
  });
}

function copyRealTree(source, destination) {
  const stat = lstatSync(source);
  if (stat.isSymbolicLink() || !stat.isDirectory()) fail(`copy source is not a real directory: ${source}`);
  mkdirSync(destination, { recursive: true, mode: 0o755 });
  for (const entry of readdirSync(source, { withFileTypes: true })) {
    const from = join(source, entry.name);
    const to = join(destination, entry.name);
    const entryStat = lstatSync(from);
    if (entryStat.isSymbolicLink()) fail(`build output contains a symbolic link: ${from}`);
    if (entryStat.isDirectory()) copyRealTree(from, to);
    else if (entryStat.isFile()) {
      copyFileSync(from, to, COPYFILE_EXCL);
      chmodSync(to, (entryStat.mode & 0o111) !== 0 ? 0o755 : 0o644);
    } else fail(`build output contains a special filesystem entry: ${from}`);
  }
}

function verifyBuildAndRemoveDependencies(gitSource, buildRoot) {
  const dependencies = join(buildRoot, "node_modules");
  if (existsSync(dependencies)) rmSync(dependencies, { recursive: true, force: true });
  const tracked = new Set(gitSource.records.map((record) => record.path));
  const all = walkRealFiles(buildRoot);
  for (const row of all) {
    if (tracked.has(row.path)) continue;
    if (!row.path.startsWith("dist/") && !row.path.startsWith("packages/approval-artifacts/dist/")) {
      fail(`build created unexpected path ${JSON.stringify(row.path)}`);
    }
  }
  for (const record of gitSource.records) {
    const absolute = join(buildRoot, ...record.path.split("/"));
    const stat = assertRealFile(absolute, `tracked file ${record.path}`);
    const mode = (stat.mode & 0o111) !== 0 ? "100755" : "100644";
    const bytes = readFileSync(absolute);
    if (mode !== record.mode || bytes.length !== record.size ||
        gitBlobOid(bytes, gitSource.objectFormat) !== record.oid) {
      fail(`build mutated tracked Git bytes at ${record.path}`);
    }
  }
  for (const output of BUILD_OUTPUT_ROOTS) {
    const outputPath = join(buildRoot, ...output.split("/"));
    assertRealDirectory(outputPath, `required build output ${output}`);
    if (walkRealFiles(outputPath).length === 0) fail(`required build output is empty: ${output}`);
  }
}

function makeReadOnly(root) {
  const visit = (path) => {
    const stat = lstatSync(path);
    if (stat.isSymbolicLink()) fail(`cannot freeze symbolic link ${path}`);
    if (stat.isDirectory()) {
      for (const entry of readdirSync(path)) visit(join(path, entry));
      chmodSync(path, 0o555);
    } else if (stat.isFile()) chmodSync(path, (stat.mode & 0o111) !== 0 ? 0o555 : 0o444);
    else fail(`cannot freeze special filesystem entry ${path}`);
  };
  visit(root);
}

function makeGeneratedTreeRemovable(root) {
  if (!existsSync(root)) return;
  const visit = (path) => {
    const stat = lstatSync(path);
    // Cleanup never follows a link or opens a special entry. `rmSync(..., {recursive:true})`
    // unlinks the directory entry itself; this is required for a failed npm install whose generated
    // `.bin` links must not strand the owner-only scratch tree or touch their external targets.
    if (stat.isSymbolicLink()) return;
    if (stat.isDirectory()) {
      chmodSync(path, 0o700);
      for (const entry of readdirSync(path)) visit(join(path, entry));
    } else if (stat.isFile()) chmodSync(path, 0o600);
    // FIFO/socket/device entries are unlinked as entries and never read, opened or followed.
  };
  visit(root);
}

function dockerPlatform() {
  if (process.arch === "arm64") return "linux/arm64";
  if (process.arch === "x64") return "linux/amd64";
  setupFail(`unsupported host architecture ${process.arch}`);
}

function containerEnvironment(commitTime, buildNetwork) {
  const offline = buildNetwork === "offline" || buildNetwork === "none";
  return [
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "TMPDIR=/noa-tmp",
    "TMP=/noa-tmp",
    "TEMP=/noa-tmp",
    "LANG=C.UTF-8",
    "LC_ALL=C.UTF-8",
    "TZ=UTC",
    "CI=1",
    "NO_COLOR=1",
    `SOURCE_DATE_EPOCH=${commitTime}`,
    `NOA_BUILD_NETWORK=${buildNetwork}`,
    "NOA_NPM_HOMEDIR=/noa-tmp/npm-home",
    "npm_config_cache=/noa-tmp/npm-cache",
    "npm_config_ignore_scripts=true",
    `npm_config_offline=${offline ? "true" : "false"}`,
    "npm_config_audit=false",
    "npm_config_fund=false",
    "npm_config_update_notifier=false",
    "npm_config_progress=false",
    "npm_config_color=false",
    "npm_config_script_shell=/bin/false",
    "npm_config_userconfig=/noa-tmp/user.npmrc",
    "npm_config_globalconfig=/noa-tmp/global.npmrc",
  ];
}

function mountArg(source, target, readonly = false) {
  if (source.includes(",") || target.includes(",")) fail("Docker bind mount path contains a comma");
  return `type=bind,src=${source},dst=${target}${readonly ? ",readonly" : ""}`;
}

export function createDockerRunArgs({
  buildNetwork,
  cacheInput,
  commitTime,
  containerName,
  driver,
  homedirOverride = NPM_HOMEDIR_OVERRIDE,
  mode,
  output,
  packagePath,
  platform,
  source,
  tsconfigs = BUILD_TSCONFIGS,
  uid,
  gid,
}) {
  if (mode !== "build" && mode !== "pack") fail(`unknown Docker mode ${mode}`);
  if (mode === "pack" && buildNetwork !== "none") fail("pack Docker plan must have no network");
  if (mode === "build" && buildNetwork !== "online" && buildNetwork !== "offline") {
    fail("build Docker plan network must be online or offline");
  }
  const network = buildNetwork === "online" ? "bridge" : "none";
  const args = [
    "run",
    "--rm",
    "--init",
    "--name", containerName,
    "--label", `${DOCKER_OWNERSHIP_LABEL}=${containerName}`,
    "--pull=never",
    `--platform=${platform}`,
    `--network=${network}`,
    "--cap-drop=ALL",
    "--security-opt=no-new-privileges",
    "--security-opt=seccomp=builtin",
    "--read-only",
    "--pids-limit=512",
    "--memory=2g",
    "--memory-swap=2g",
    "--cpus=2",
    "--user", `${uid}:${gid}`,
    "--workdir=/workspace",
    "--tmpfs", `/noa-tmp:rw,nosuid,nodev,size=2g,mode=0700,uid=${uid},gid=${gid}`,
    "--mount", mountArg(source, "/workspace", mode === "pack"),
    "--mount", mountArg(driver, "/noa-driver.mjs", true),
    "--mount", mountArg(homedirOverride, "/noa-npm-homedir-override.cjs", true),
  ];
  if (mode === "pack") args.push("--mount", mountArg(output, "/out", false));
  if (mode === "build" && buildNetwork === "offline") {
    args.push("--mount", mountArg(cacheInput, "/cache-input", true));
  }
  for (const env of containerEnvironment(commitTime, buildNetwork)) args.push("--env", env);
  // The base image supplies HOME by default. Remove it before the driver begins rather than
  // rebinding it to a scratch path: npm is fully directed by its explicit config/cache paths.
  args.push(
    "--entrypoint=/usr/bin/env",
    NODE_IMAGE,
    "-u",
    "HOME",
    "node",
    "--require",
    "/noa-npm-homedir-override.cjs",
    "/noa-driver.mjs",
    mode,
  );
  if (mode === "build") {
    for (const tsconfig of tsconfigs) args.push("--tsconfig", tsconfig);
  } else args.push("--package", packagePath);
  validateDockerRunArgs(args, mode, buildNetwork);
  return args;
}

export function validateDockerRunArgs(args, mode, buildNetwork) {
  const serialized = `\0${args.join("\0")}\0`;
  const required = [
    "\0--rm\0",
    "\0--init\0",
    "\0--pull=never\0",
    "\0--cap-drop=ALL\0",
    "\0--security-opt=no-new-privileges\0",
    "\0--security-opt=seccomp=builtin\0",
    "\0--read-only\0",
    "\0--entrypoint=/usr/bin/env\0",
    `\0${NODE_IMAGE}\0`,
  ];
  for (const token of required) if (!serialized.includes(token)) fail(`Docker plan omitted ${token}`);
  if (!serialized.includes("\0-u\0HOME\0node\0--require\0/noa-npm-homedir-override.cjs\0/noa-driver.mjs\0")) {
    fail("Docker plan does not remove the image HOME before the staging driver starts");
  }
  if (!args.some((arg) => arg.includes("dst=/noa-npm-homedir-override.cjs,readonly"))) {
    fail("Docker plan omitted the exact npm homedir preload");
  }
  if (!serialized.includes("\0NOA_NPM_HOMEDIR=/noa-tmp/npm-home\0")) {
    fail("Docker plan omitted the closed task-local npm homedir path");
  }
  if (args.some((arg, index) => args[index - 1] === "--env" && arg.startsWith("HOME="))) {
    fail("Docker plan passes HOME into the staging driver");
  }
  const nameIndexes = args.flatMap((arg, index) => arg === "--name" ? [index] : []);
  if (nameIndexes.length !== 1 || nameIndexes[0] + 1 >= args.length) {
    fail("Docker plan must contain exactly one staging container name");
  }
  const containerName = args[nameIndexes[0] + 1];
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/u.test(containerName)) {
    fail("Docker plan staging container name is malformed");
  }
  const ownershipLabel = `${DOCKER_OWNERSHIP_LABEL}=${containerName}`;
  const labelIndexes = args.flatMap((arg, index) => arg === "--label" ? [index] : []);
  if (
    labelIndexes.length !== 1 ||
    labelIndexes[0] + 1 >= args.length ||
    args[labelIndexes[0] + 1] !== ownershipLabel
  ) {
    fail("Docker plan must bind exactly one ownership label to its staging container name");
  }
  const networkToken = `\0--network=${buildNetwork === "online" ? "bridge" : "none"}\0`;
  if (!serialized.includes(networkToken)) fail("Docker plan network does not match the staging mode");
  if (mode === "pack" && !args.some((arg) => arg.includes("dst=/workspace,readonly"))) {
    fail("pack Docker plan lost its read-only frozen snapshot mount");
  }
  if (mode === "pack" && !args.some((arg) => arg.includes("dst=/out") && !arg.endsWith(",readonly"))) {
    fail("pack Docker plan lost its isolated writable output mount");
  }
  const forbiddenFragments = ["GITHUB_TOKEN", "NODE_AUTH_TOKEN", "NPM_TOKEN", "ACTIONS_ID_TOKEN", "--privileged"];
  for (const fragment of forbiddenFragments) {
    if (serialized.includes(fragment)) fail(`Docker plan contains forbidden authority ${fragment}`);
  }
}

function inspectDocker(docker, platform) {
  const version = runCommand(docker, ["version", "--format", "{{json .Server.Version}}"], {
    encoding: "utf8",
    label: "Docker daemon probe",
    setup: true,
  }).stdout.trim();
  if (!/^"[0-9]+\.[0-9]+\.[0-9]+"$/u.test(version)) setupFail("Docker server version is malformed");
  const inspected = runCommand(
    docker,
    ["image", "inspect", NODE_IMAGE, "--format", "{{json .}}"],
    { encoding: "utf8", label: "pinned Node image probe", setup: true },
  ).stdout.trim();
  let image;
  try { image = JSON.parse(inspected); } catch { setupFail("Docker image inspection was not JSON"); }
  const expectedArch = platform.endsWith("/arm64") ? "arm64" : "amd64";
  if (image.Os !== "linux" || image.Architecture !== expectedArch) {
    setupFail(`pinned Node image is ${image.Os}/${image.Architecture}, expected linux/${expectedArch}`);
  }
}

function cleanupExactDockerContainer(containerName, execute, options = {}) {
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/u.test(containerName)) {
    fail(`invalid staging container name ${JSON.stringify(containerName)}`);
  }
  const maxQueries = options.maxQueries ?? DOCKER_CLEANUP_MAX_QUERIES;
  const quietObservations = options.quietObservations ?? DOCKER_CLEANUP_QUIET_OBSERVATIONS;
  const quietIntervalMs = options.quietIntervalMs ?? DOCKER_CLEANUP_QUIET_INTERVAL_MS;
  const timeBudgetMs = options.timeBudgetMs ?? DOCKER_CLEANUP_TIME_BUDGET_MS;
  const now = options.now ?? Date.now;
  const wait = options.wait ?? ((milliseconds) => {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, milliseconds);
  });
  if (!Number.isSafeInteger(maxQueries) || maxQueries < quietObservations) {
    fail("Docker cleanup query budget is invalid");
  }
  if (!Number.isSafeInteger(quietObservations) || quietObservations < 2) {
    fail("Docker cleanup quiet-observation requirement is invalid");
  }
  if (
    !Number.isSafeInteger(quietIntervalMs) || quietIntervalMs < 1 ||
    !Number.isSafeInteger(timeBudgetMs) || timeBudgetMs < quietIntervalMs ||
    typeof now !== "function" || typeof wait !== "function"
  ) {
    fail("Docker cleanup time budget is invalid");
  }
  const startedAt = now();
  if (!Number.isFinite(startedAt)) fail("Docker cleanup clock is invalid");
  const remainingTime = (phase) => {
    const observedAt = now();
    if (!Number.isFinite(observedAt) || observedAt < startedAt) {
      setupFail("Docker cleanup clock became invalid");
    }
    const remaining = timeBudgetMs - (observedAt - startedAt);
    if (remaining < 1) {
      setupFail(
        `Docker cleanup did not stabilize within its ${timeBudgetMs}ms time budget during ${phase}`,
      );
    }
    return Math.min(remaining, DOCKER_CLEANUP_COMMAND_TIMEOUT_MS);
  };
  const query = (phase) => {
    const result = execute(
      [
        "container", "ls", "--all", "--no-trunc",
        "--filter", `name=^/${containerName}$`,
        "--filter", `label=${DOCKER_OWNERSHIP_LABEL}=${containerName}`,
        "--format", "{{.ID}}",
      ],
      `${phase} exact-container query`,
      remainingTime(`${phase} query`),
    );
    if (!result || result.status !== 0) {
      setupFail(
        `${phase} exact-container query failed with status ${String(result && result.status)}; ` +
        `stderr=${safeOneLine(result && result.stderr)}`,
      );
    }
    const lines = String(result.stdout ?? "").split(/\r?\n/u).filter((line) => line !== "");
    if (lines.length > 1 || lines.some((line) => !/^[0-9a-f]{64}$/u.test(line))) {
      setupFail(`${phase} exact-container query returned ambiguous identifiers: ${safeOneLine(result.stdout)}`);
    }
    return lines;
  };

  let quietCount = 0;
  let residueObserved = false;
  for (let queryCount = 1; queryCount <= maxQueries; queryCount++) {
    const ids = query(`cleanup observation ${queryCount}/${maxQueries}`);
    if (ids.length === 0) {
      quietCount++;
      if (quietCount < quietObservations) {
        const remaining = remainingTime("quiet-observation stabilization");
        if (remaining < quietIntervalMs) {
          setupFail("Docker cleanup lacks time for the required quiet-observation interval");
        }
        wait(quietIntervalMs);
        continue;
      }
      if (residueObserved) {
        fail(`staging container residue was found and removed; refusing success: ${containerName}`);
      }
      return;
    }

    residueObserved = true;
    quietCount = 0;
    const id = ids[0];
    const removal = execute(
      ["rm", "-f", id],
      "remove exact staging container",
      remainingTime("exact-container removal"),
    );
    if (!removal || removal.status !== 0) {
      setupFail(
        `exact staging-container removal failed with status ${String(removal && removal.status)}; ` +
        `stderr=${safeOneLine(removal && removal.stderr)}`,
      );
    }
  }
  setupFail(
    `Docker cleanup did not reach ${quietObservations} consecutive quiet observations ` +
    `within ${maxQueries} exact-name query attempts`,
  );
}

export function ensureNoContainerResidue(docker, containerName) {
  return cleanupExactDockerContainer(containerName, (args, label, timeout) => runCommand(docker, args, {
    allowFailure: true,
    encoding: "utf8",
    label,
    setup: true,
    timeout,
  }));
}

// Deterministic seam: tests inject status/stdout/stderr but drive the exact production state machine.
export function cleanupExactDockerContainerForSelftest(containerName, execute, options) {
  return cleanupExactDockerContainer(containerName, execute, options);
}

function runDockerStage(docker, args, containerName, mode, buildNetwork) {
  let result;
  try {
    result = runCommand(docker, args, {
      allowFailure: true,
      encoding: "utf8",
      label: `${mode} container`,
      timeout: 20 * 60 * 1000,
    });
  } finally {
    ensureNoContainerResidue(docker, containerName);
  }
  if (result.status === 125 || result.status === 126 || result.status === 127) {
    setupFail(`Docker ${mode} setup failed: ${safeOneLine(result.stderr)}`);
  }
  if (result.status !== 0) {
    const message = `Docker ${mode} failed; stdout=${safeOneLine(result.stdout)}; stderr=${safeOneLine(result.stderr)}`;
    if (mode === "build") setupFail(message);
    fail(message);
  }
  const marker = mode === "build" ? "NOA_BUILD_RESULT " : "NOA_PACK_RESULT ";
  const lines = result.stdout.split(/\r?\n/u).filter((line) => line.startsWith(marker));
  if (lines.length !== 1) fail(`Docker ${mode} emitted ${lines.length} result markers`);
  try { return JSON.parse(lines[0].slice(marker.length)); } catch { fail(`Docker ${mode} result marker is invalid JSON`); }
}

function buildImmutableGitSource({
  buildNetwork,
  cacheInput,
  docker,
  gitSource,
  platform,
  policy,
  controller = { driver: DRIVER, npmHomedirOverride: NPM_HOMEDIR_OVERRIDE },
  workRoot,
}) {
  const buildRoot = join(workRoot, "build-source");
  materializeGitSource(gitSource, buildRoot);
  const buildName = `noa-publish-build-${process.pid}-${randomBytes(6).toString("hex")}`;
  const buildArgs = createDockerRunArgs({
    buildNetwork,
    cacheInput,
    commitTime: gitSource.commitTime,
    containerName: buildName,
    driver: controller.driver,
    homedirOverride: controller.npmHomedirOverride,
    mode: "build",
    platform,
    source: buildRoot,
    uid: process.getuid(),
    gid: process.getgid(),
  });
  runDockerStage(docker, buildArgs, buildName, "build", buildNetwork);
  verifyBuildAndRemoveDependencies(gitSource, buildRoot);
  return {
    buildOutputs: deriveCarriedBuildOutputCensus(gitSource, buildRoot, policy),
    buildRoot,
  };
}

function applyReleaseManifests(frozenRoot, plannedPackages) {
  for (const entry of plannedPackages) {
    const path = join(frozenRoot, ...entry.manifestPath.split("/"));
    assertRealFile(path, `frozen manifest ${entry.manifestPath}`);
    writeFileSync(path, entry.releaseManifestBytes, { flag: "w" });
    if (sha256Hex(readFileSync(path)) !== entry.releaseManifestSha256) {
      fail(`release manifest write did not persist exact bytes at ${entry.manifestPath}`);
    }
  }
}

function verifyPackedManifest(parsed, expected) {
  const paths = new Set(parsed.entries.map((candidate) => candidate.path));
  for (const path of REQUIRED_PUBLIC_CARRIER_PATHS) {
    if (!paths.has(path)) {
      fail(`tarball ${expected.filename} lacks required public carrier file ${path}`);
    }
  }
  const entry = parsed.entries.find((candidate) => candidate.path === "package.json");
  if (!entry) fail(`tarball ${expected.filename} has no package.json entry`);
  if (sha256Hex(entry.content) !== expected.releaseManifestSha256) {
    fail(`tarball ${expected.filename} does not contain the planned release manifest bytes`);
  }
  const manifest = parseManifest(entry.content, `${expected.filename}:package.json`);
  if (manifest.name !== expected.name || manifest.version !== expected.version) {
    fail(`tarball identity mismatch for ${expected.filename}`);
  }
  if (Object.prototype.hasOwnProperty.call(manifest, "repository")) {
    fail(`tarball ${expected.filename} retains source repository metadata`);
  }
  for (const field of DEPENDENCY_FIELDS) {
    for (const [name, specifier] of Object.entries(manifest[field] ?? {})) {
      if (isLocalDependencySpecifier(specifier)) {
        fail(`tarball retains local dependency ${field}.${name}=${JSON.stringify(specifier)}`);
      }
    }
  }
}

function runSurfaceLinter(tarballPath, linter = SURFACE_LINTER, publicRepos) {
  assertRealFile(linter, "published-surface linter");
  assertRealFile(publicRepos, "published-artifact public repository policy");
  const result = runCommand(process.execPath, [linter, "--tarball", tarballPath, "--public-repos", publicRepos], {
    allowFailure: true,
    encoding: "utf8",
    env: {
      LANG: "C.UTF-8",
      LC_ALL: "C.UTF-8",
      NO_COLOR: "1",
      PATH: "/usr/bin:/bin",
      TZ: "UTC",
    },
    label: "published-surface tarball linter",
  });
  if (result.status === 2) setupFail(`tarball linter setup failed: ${safeOneLine(result.stderr)}`);
  if (result.status !== 0) fail(`tarball linter rejected candidate: ${safeOneLine(result.stderr)}`);
  return sha256Hex(readFileSync(linter));
}

function assertOutputParent(output) {
  const parent = dirname(output);
  assertRealDirectory(parent, "output parent");
  return parent;
}

function captureOwnedDirectory(path, label) {
  const state = lstatSync(path, { bigint: true });
  if (state.isSymbolicLink() || !state.isDirectory()) {
    fail(`${label} is not a real owned directory: ${JSON.stringify(path)}`);
  }
  return { path, state };
}

function assertOwnedDirectory(ownership, label) {
  let current;
  try {
    current = lstatSync(ownership.path, { bigint: true });
  } catch (error) {
    fail(`${label} disappeared or became unreadable: ${String(error && error.message)}`);
  }
  if (!current.isDirectory() || current.isSymbolicLink() ||
      current.dev !== ownership.state.dev || current.ino !== ownership.state.ino) {
    fail(`${label} identity changed; refusing to touch replacement path ${JSON.stringify(ownership.path)}`);
  }
  return current;
}

function assertOwnedFlatCleanupContents(ownership, label, { cleanupPrepared = false } = {}) {
  if (!ownership.allowedFlatRows) return;
  const expected = new Map(ownership.allowedFlatRows.map((row) => [row.path, row]));
  for (const name of readdirSync(ownership.path)) {
    const row = expected.get(name);
    if (!row) fail(`${label} gained unknown data; refusing recursive cleanup: ${JSON.stringify(name)}`);
    const path = join(ownership.path, name);
    const stat = assertRealFile(path, `${label} cleanup entry ${name}`);
    const mode = (stat.mode & 0o111) !== 0 ? "100755" : "100644";
    if (stat.size !== row.size || (!cleanupPrepared && mode !== row.mode) ||
        sha256Hex(readFileSync(path)) !== row.sha256) {
      fail(`${label} generated entry changed; refusing recursive cleanup: ${JSON.stringify(name)}`);
    }
  }
}

function removeOwnedDirectory(ownership, label) {
  if (!ownership) return;
  try {
    lstatSync(ownership.path);
  } catch (error) {
    if (error && error.code === "ENOENT") return;
    fail(`${label} could not be checked before cleanup: ${String(error && error.message)}`);
  }
  assertOwnedDirectory(ownership, label);
  assertOwnedFlatCleanupContents(ownership, label);
  makeGeneratedTreeRemovable(ownership.path);
  assertOwnedDirectory(ownership, label);
  assertOwnedFlatCleanupContents(ownership, label, { cleanupPrepared: true });
  rmSync(ownership.path, { recursive: true, force: false });
  if (existsSync(ownership.path)) fail(`${label} cleanup did not remove its exact generated directory`);
}

function withOwnedScratch(prefix, label, operation, makeScratch = mkdtempSync) {
  let ownership;
  try {
    const path = makeScratch(prefix);
    ownership = captureOwnedDirectory(path, label);
    return operation(path);
  } finally {
    removeOwnedDirectory(ownership, label);
  }
}

function withOwnedScratchPair(outputParent, operation, makeScratch = mkdtempSync) {
  return withOwnedScratch(
    join(tmpdir(), "noa-publish-artifact-stage-"),
    "publish-artifact work scratch",
    (workRoot) => withOwnedScratch(
      join(outputParent, ".noa-publish-artifact-set-"),
      "publish-artifact final scratch",
      (finalScratch) => operation({ finalScratch, workRoot }),
      makeScratch,
    ),
    makeScratch,
  );
}

export function withOwnedScratchPairForSelftest(outputParent, operation, makeScratch) {
  return withOwnedScratchPair(outputParent, operation, makeScratch);
}

function materializeCandidateOutput(source, output, verify, { afterMaterialize, beforeReserve } = {}) {
  const resolvedSource = realpathSync(source);
  assertRealDirectory(resolvedSource, "candidate materialization source");
  const sourceRows = walkRealFiles(resolvedSource);
  if (sourceRows.length === 0) fail("candidate materialization source is empty");
  if (sourceRows.some((row) => row.path.includes("/"))) {
    fail("candidate materialization source must contain only flat regular files");
  }
  assertOutputParent(output);
  if (beforeReserve) beforeReserve();
  let ownership;
  let completed = false;
  try {
    try {
      mkdirSync(output, { recursive: false, mode: 0o700 });
    } catch (error) {
      if (error && error.code === "EEXIST") {
        fail(`output path already exists; refusing overwrite: ${JSON.stringify(output)}`);
      }
      throw error;
    }
    ownership = captureOwnedDirectory(output, "candidate output");
    ownership.allowedFlatRows = sourceRows;
    for (const sourceRow of sourceRows) {
      const name = sourceRow.path;
      assertOwnedDirectory(ownership, "candidate output");
      const from = join(resolvedSource, name);
      const sourceStat = assertRealFile(from, `candidate materialization source ${name}`);
      const to = join(output, name);
      copyFileSync(from, to, COPYFILE_EXCL);
      chmodSync(to, (sourceStat.mode & 0o111) !== 0 ? 0o755 : 0o644);
      const copied = assertRealFile(to, `materialized candidate ${name}`);
      const copiedMode = (copied.mode & 0o111) !== 0 ? "100755" : "100644";
      if (copied.nlink !== 1 || copied.size !== sourceRow.size || copiedMode !== sourceRow.mode ||
          sha256Hex(readFileSync(to)) !== sourceRow.sha256) {
        fail(`materialized candidate bytes are not exact for ${JSON.stringify(name)}`);
      }
    }
    assertOwnedDirectory(ownership, "candidate output");
    if (canonicalJson(walkRealFiles(resolvedSource)) !== canonicalJson(sourceRows)) {
      fail("candidate materialization source changed while it was copied");
    }
    if (afterMaterialize) afterMaterialize({ output, ownership });
    verify(output);
    assertOwnedDirectory(ownership, "candidate output");
    completed = true;
  } finally {
    if (!completed) removeOwnedDirectory(ownership, "candidate output");
  }
}

export function materializeCandidateOutputForSelftest(options) {
  return materializeCandidateOutput(
    options.source,
    options.output,
    options.verify,
    { afterMaterialize: options.afterMaterialize, beforeReserve: options.beforeReserve },
  );
}

function requireSafeInteger(value, label, minimum = 0) {
  if (!Number.isSafeInteger(value) || value < minimum) fail(`${label} is not a safe integer >= ${minimum}`);
}

function validateBuildOutputCensus(outputs, gitSource, policy) {
  if (!Array.isArray(outputs) || outputs.length === 0) fail("candidate build-output census is empty");
  const gitPaths = new Set(gitSource.records.map((record) => record.path));
  const seen = new Set();
  for (const row of outputs) {
    requireExactKeys(row, ["mode", "path", "sha256", "size"], "candidate build-output row");
    validateRepositoryPath(row.path);
    if ((row.mode !== "100644" && row.mode !== "100755") ||
        !/^[0-9a-f]{64}$/u.test(row.sha256 ?? "")) {
      fail(`candidate build-output row is malformed at ${JSON.stringify(row.path)}`);
    }
    requireSafeInteger(row.size, `candidate build-output size ${row.path}`);
    if (gitPaths.has(row.path) || seen.has(row.path) || !isAllowedBuildOutput(row.path, policy)) {
      fail(`candidate build-output census has a duplicate, tracked, or unapproved path ${JSON.stringify(row.path)}`);
    }
    seen.add(row.path);
  }
  const sorted = [...outputs].sort((left, right) => bytewiseCompare(left.path, right.path));
  if (canonicalJson(sorted) !== canonicalJson(outputs)) fail("candidate build-output census is not bytewise sorted");
  for (const prefix of policy.allowedBuildOutputPrefixes) {
    if (!outputs.some((row) => row.path.startsWith(prefix))) {
      fail(`candidate build-output census omits required policy prefix ${prefix}`);
    }
  }
  return new Map(outputs.map((row) => [row.path, row]));
}

function expectedFrozenSnapshot(gitSource, plannedPackages, buildOutputs) {
  const releaseByPath = new Map(plannedPackages.map((entry) => [entry.manifestPath, entry]));
  const rows = gitSource.records.map((record) => {
    const release = releaseByPath.get(record.path);
    const bytes = release ? release.releaseManifestBytes : gitSource.blobs.get(record.path);
    return {
      mode: record.mode,
      path: record.path,
      sha256: sha256Hex(bytes),
      size: bytes.length,
    };
  });
  rows.push(...buildOutputs);
  rows.sort((left, right) => bytewiseCompare(left.path, right.path));
  return {
    fileCount: rows.length,
    sha256: sha256Hex(Buffer.from(canonicalJson(rows), "utf8")),
    size: rows.reduce((sum, row) => sum + row.size, 0),
  };
}

function verifyManifestShape(manifest, policy) {
  requireExactKeys(
    manifest,
    ["build", "controller", "frozenSnapshot", "packages", "policy", "releaseAuthorized", "schema", "source", "status"],
    "candidate manifest",
  );
  if (!manifest || manifest.schema !== MANIFEST_SCHEMA || manifest.status !== CANDIDATE_STATUS ||
      manifest.releaseAuthorized !== false) {
    fail("candidate manifest lost its NON-RELEASE status contract");
  }
  const source = manifest.source;
  requireExactKeys(source, ["commit", "commitTime", "fileCount", "inventorySha256", "objectFormat", "tree"], "candidate source");
  if (!source || (source.objectFormat !== "sha1" && source.objectFormat !== "sha256")) {
    fail("candidate source object format is missing or unsupported");
  }
  const oidLength = source.objectFormat === "sha1" ? 40 : 64;
  if (!new RegExp(`^[0-9a-f]{${oidLength}}$`, "u").test(source.commit ?? "") ||
      !new RegExp(`^[0-9a-f]{${oidLength}}$`, "u").test(source.tree ?? "") ||
      !/^[0-9a-f]{64}$/u.test(source.inventorySha256 ?? "")) {
    fail("candidate Git commit/tree/inventory digest is malformed");
  }
  requireSafeInteger(source.commitTime, "candidate commit time");
  requireSafeInteger(source.fileCount, "candidate source file count", 1);
  if (!manifest.frozenSnapshot || !/^[0-9a-f]{64}$/u.test(manifest.frozenSnapshot.sha256 ?? "")) {
    fail("candidate frozen snapshot digest is malformed");
  }
  requireSafeInteger(manifest.frozenSnapshot.fileCount, "candidate frozen file count", 1);
  requireSafeInteger(manifest.frozenSnapshot.size, "candidate frozen size", 1);
  requireExactKeys(manifest.frozenSnapshot, ["fileCount", "sha256", "size"], "candidate frozen snapshot");
  requireExactKeys(
    manifest.controller,
    ["driverSha256", "image", "node", "npm", "packStack", "platform"],
    "candidate controller",
  );
  requireExactKeys(manifest.controller.packStack, ["arborist", "npmPacklist", "tar"], "candidate pack stack");
  if (!manifest.controller || manifest.controller.image !== NODE_IMAGE ||
      manifest.controller.node !== EXPECTED_NODE || manifest.controller.npm !== EXPECTED_NPM ||
      !/^[0-9a-f]{64}$/u.test(manifest.controller.driverSha256 ?? "") ||
      !/^linux\/(?:amd64|arm64)$/u.test(manifest.controller.platform ?? "") ||
      !manifest.controller.packStack || typeof manifest.controller.packStack !== "object" ||
      manifest.controller.packStack.arborist !== EXPECTED_PACK_STACK.arborist ||
      manifest.controller.packStack.npmPacklist !== EXPECTED_PACK_STACK.npmPacklist ||
      manifest.controller.packStack.tar !== EXPECTED_PACK_STACK.tar) {
    fail("candidate controller identity is malformed or unpinned");
  }
  if (!manifest.build || (manifest.build.network !== "online" && manifest.build.network !== "offline")) {
    fail("candidate build-network claim is missing or unsupported");
  }
  requireExactKeys(manifest.build, ["dependencyInput", "network", "outputs", "tsconfigs"], "candidate build");
  if (canonicalJson(manifest.build.tsconfigs) !== canonicalJson([...BUILD_TSCONFIGS])) {
    fail("candidate TypeScript build targets do not match the trusted controller");
  }
  if (manifest.build.network === "offline") {
    requireExactKeys(manifest.build.dependencyInput, ["count", "sha256", "size"], "offline dependency input");
    requireSafeInteger(manifest.build.dependencyInput.count, "offline dependency input count", 1);
    requireSafeInteger(manifest.build.dependencyInput.size, "offline dependency input size", 1);
    if (!/^[0-9a-f]{64}$/u.test(manifest.build.dependencyInput.sha256 ?? "")) {
      fail("offline dependency-input digest is malformed");
    }
  } else {
    requireExactKeys(manifest.build.dependencyInput, ["source"], "online dependency input");
    if (manifest.build.dependencyInput.source !== "networked npm ci from exact package-lock.json; no cache retained") {
      fail("online dependency-input statement is not exact");
    }
  }
  requireExactKeys(manifest.policy, ["path", "schema", "sha256"], "candidate policy binding");
  if (manifest.policy.path !== POLICY_REPO_PATH || manifest.policy.schema !== POLICY_SCHEMA ||
      manifest.policy.sha256 !== policy.sha256) {
    fail("candidate policy binding does not match the trusted publish-artifact policy");
  }
}

function verifyGitBinding(manifest, gitSource, policy) {
  const expectedSource = {
    commit: gitSource.commit,
    commitTime: gitSource.commitTime,
    fileCount: gitSource.records.length,
    inventorySha256: gitSource.inventoryDigest,
    objectFormat: gitSource.objectFormat,
    tree: gitSource.tree,
  };
  if (canonicalJson(manifest.source) !== canonicalJson(expectedSource)) {
    fail("candidate manifest source identity does not match the requested immutable Git tree");
  }
  const planned = planReleaseManifests(derivePackageInventory(gitSource));
  enforcePolicyPackageSet(planned, policy, gitSource);
  if (planned.length !== manifest.packages.length) {
    fail("candidate artifact count does not match the immutable Git package inventory");
  }
  const expectedByPath = new Map(planned.map((entry) => [entry.packagePath, entry]));
  for (const artifact of manifest.packages) {
    const expected = expectedByPath.get(artifact.packagePath);
    if (!expected || artifact.name !== expected.name || artifact.version !== expected.version ||
        artifact.filename !== expected.filename ||
        artifact.sourceManifestGitOid !== expected.sourceManifestGitOid ||
        artifact.sourceManifestSha256 !== expected.sourceManifestSha256 ||
        artifact.releaseManifestSha256 !== expected.releaseManifestSha256 ||
        canonicalJson(artifact.transformations) !== canonicalJson(expected.transformations)) {
      fail(`candidate artifact metadata is not derived from Git for ${JSON.stringify(artifact.packagePath)}`);
    }
  }
  return planned;
}

function assertOfflineDependencyInput(manifest, cache, label) {
  const observedInput = dependencyInputFromCache(cache.evidence);
  if (canonicalJson(observedInput) !== canonicalJson(manifest.build.dependencyInput)) {
    fail(`${label} does not match the candidate dependency-input digest`);
  }
}

function independentlyReproduceBuildOutputs(manifest, gitSource, policy, offlineCache, controller) {
  return withOwnedScratch(join(tmpdir(), "noa-publish-artifact-rebuild-"), "independent rebuild scratch", (workRoot) => {
    let cache;
    if (manifest.build.network === "offline") {
      if (offlineCache === undefined) {
        fail("offline candidate verification requires the exact --offline-cache dependency input");
      }
      cache = snapshotOfflineCache(
        offlineCache,
        join(workRoot, "offline-cache-snapshot"),
        "offline verification npm content cache",
      );
      assertOfflineDependencyInput(manifest, cache, "offline verification cache snapshot");
    } else if (offlineCache !== undefined) {
      fail("online candidate verification cannot accept an offline dependency cache");
    }
    const platform = manifest.controller.platform;
    const docker = resolveExecutable(DOCKER_CANDIDATES, "Docker");
    inspectDocker(docker, platform);
    const { buildOutputs } = buildImmutableGitSource({
      buildNetwork: manifest.build.network,
      cacheInput: cache?.path,
      docker,
      gitSource,
      platform,
      policy,
      controller,
      workRoot,
    });
    if (cache) verifyOwnedOfflineCache(cache, "offline verification npm content cache");
    return buildOutputs;
  });
}

function verifyDependencyInputForSuppliedOutputs(manifest, offlineCache, ownedOfflineCache) {
  if (manifest.build.network === "online") {
    if (offlineCache !== undefined || ownedOfflineCache !== undefined) {
      fail("online candidate verification cannot accept an offline dependency cache");
    }
    return;
  }
  if (ownedOfflineCache !== undefined) {
    if (offlineCache !== undefined) fail("offline candidate verification received two cache inputs");
    verifyOwnedOfflineCache(ownedOfflineCache, "owned offline verification cache");
    assertOfflineDependencyInput(manifest, ownedOfflineCache, "owned offline verification cache");
    return;
  }
  if (offlineCache === undefined) {
    fail("offline candidate verification requires the exact --offline-cache dependency input");
  }
  return withOwnedScratch(join(tmpdir(), "noa-publish-artifact-cache-check-"), "cache verification scratch", (workRoot) => {
    const cache = snapshotOfflineCache(
      offlineCache,
      join(workRoot, "offline-cache-snapshot"),
      "offline verification npm content cache",
    );
    assertOfflineDependencyInput(manifest, cache, "offline verification cache snapshot");
  });
}

function verifyCandidateSetBound(
  output,
  {
    gitRef,
    gitSource,
    independentBuildOutputs,
    offlineCache,
    ownedOfflineCache,
    repoRoot = DEFAULT_REPO_ROOT,
  } = {},
  policy,
  controller = {
    driver: DRIVER,
    linter: SURFACE_LINTER,
    publicRepos: PUBLIC_REPOS,
    npmHomedirOverride: NPM_HOMEDIR_OVERRIDE,
  },
) {
  if (gitSource === undefined && gitRef === undefined) {
    fail("candidate verification requires an immutable --git-ref or Git source binding");
  }
  assertRealDirectory(resolve(output), "candidate artifact set");
  const root = realpathSync(output);
  const allowed = new Set([
    "CANDIDATE-NON-RELEASE.txt",
    "publish-artifacts.manifest.json",
    "publish-artifacts.manifest.sha256",
  ]);
  const manifestPath = join(root, "publish-artifacts.manifest.json");
  assertRealFile(manifestPath, "candidate manifest");
  const manifestBytes = readFileSync(manifestPath);
  let manifest;
  try { manifest = JSON.parse(decodeStrict(manifestBytes, "candidate manifest")); }
  catch (error) {
    if (error instanceof ValidationFailure) throw error;
    fail(`candidate manifest is invalid JSON: ${String(error && error.message)}`);
  }
  verifyManifestShape(manifest, policy);
  if (!Buffer.from(canonicalJson(manifest), "utf8").equals(manifestBytes)) {
    fail("candidate manifest is not canonical JSON");
  }
  const expectedManifestDigest = `${sha256Hex(manifestBytes)}\n`;
  const sidecarPath = join(root, "publish-artifacts.manifest.sha256");
  assertRealFile(sidecarPath, "candidate manifest digest sidecar");
  if (readFileSync(sidecarPath, "utf8") !== expectedManifestDigest) {
    fail("candidate manifest digest sidecar is wrong");
  }
  if (!Array.isArray(manifest.packages) || manifest.packages.length === 0) {
    fail("candidate manifest contains zero packages");
  }
  const bindingSource = gitSource ?? loadGitSource(repoRoot, gitRef);
  const planned = verifyGitBinding(manifest, bindingSource, policy);
  const plannedByPath = new Map(planned.map((entry) => [entry.packagePath, entry]));
  const policyByPath = new Map(policy.packages.map((entry) => [entry.packagePath, entry]));
  if (manifest.controller.driverSha256 !== sha256Hex(readFileSync(controller.driver))) {
    fail("candidate controller driver digest does not match the executing trusted driver");
  }
  validateBuildOutputCensus(manifest.build.outputs, bindingSource, policy);
  let reproducedBuildOutputs;
  if (independentBuildOutputs === undefined) {
    reproducedBuildOutputs = independentlyReproduceBuildOutputs(
      manifest,
      bindingSource,
      policy,
      offlineCache,
      controller,
    );
  } else {
    verifyDependencyInputForSuppliedOutputs(manifest, offlineCache, ownedOfflineCache);
    reproducedBuildOutputs = independentBuildOutputs;
  }
  const buildOutputs = validateBuildOutputCensus(reproducedBuildOutputs, bindingSource, policy);
  if (canonicalJson(reproducedBuildOutputs) !== canonicalJson(manifest.build.outputs)) {
    fail("candidate build-output census does not match independently reproduced build output");
  }
  const frozen = expectedFrozenSnapshot(bindingSource, planned, reproducedBuildOutputs);
  if (canonicalJson(frozen) !== canonicalJson(manifest.frozenSnapshot)) {
    fail("candidate frozen snapshot is not the complete Git + release-manifest + build-output census");
  }
  const gitByPath = new Map(bindingSource.records.map((record) => [record.path, record]));
  const linterSha256 = sha256Hex(readFileSync(controller.linter));
  const seenFiles = new Set();
  const seenNames = new Set();
  const seenPackages = new Set();
  const seenPaths = new Set();
  for (const entry of manifest.packages) {
    requireExactKeys(
      entry,
      ["compressedSize", "filename", "name", "packlistCount", "packlistDigest", "packlistSize", "packagePath", "pathSetSha256", "releaseManifestSha256", "sourceManifestGitOid", "sourceManifestSha256", "surfaceLinterSha256", "tarballSha256", "transformations", "uncompressedSize", "version"],
      "candidate package entry",
    );
    if (!entry || typeof entry !== "object" || typeof entry.filename !== "string" ||
        typeof entry.name !== "string" || typeof entry.version !== "string" ||
        typeof entry.packagePath !== "string" || typeof entry.releaseManifestSha256 !== "string" ||
        !Array.isArray(entry.transformations)) {
      fail("candidate package manifest entry is malformed");
    }
    const identity = validatePackageIdentity(entry, entry.packagePath);
    if (identity.filename !== entry.filename ||
        (entry.packagePath !== "." && !entry.packagePath.startsWith("packages/"))) {
      fail("candidate package path/name/version/filename contract is malformed");
    }
    if (entry.packagePath !== ".") validateRepositoryPath(entry.packagePath);
    for (const field of ["packlistDigest", "pathSetSha256", "releaseManifestSha256", "sourceManifestSha256", "surfaceLinterSha256", "tarballSha256"]) {
      if (!/^[0-9a-f]{64}$/u.test(entry[field] ?? "")) fail(`candidate ${field} is malformed`);
    }
    if (!/^[0-9a-f]+$/u.test(entry.sourceManifestGitOid ?? "")) fail("candidate source manifest Git OID is malformed");
    for (const field of ["compressedSize", "packlistCount", "packlistSize", "uncompressedSize"]) {
      requireSafeInteger(entry[field], `candidate ${entry.filename} ${field}`, 1);
    }
    for (const transformation of entry.transformations) {
      requireExactKeys(transformation, ["field", "from", "name", "targetPath", "to"], "dependency transformation");
    }
    if (seenFiles.has(entry.filename) || seenNames.has(entry.name) ||
        seenPackages.has(`${entry.name}@${entry.version}`) || seenPaths.has(entry.packagePath)) {
      fail("candidate manifest contains a duplicate artifact identity");
    }
    seenFiles.add(entry.filename);
    seenNames.add(entry.name);
    seenPackages.add(`${entry.name}@${entry.version}`);
    seenPaths.add(entry.packagePath);
    allowed.add(entry.filename);
    const tarballPath = join(root, entry.filename);
    let parsed;
    try { parsed = readSafeNpmTarball(tarballPath); }
    catch (error) {
      if (error instanceof TarballValidationError) fail(error.message);
      throw error;
    }
    const carrierPaths = new Set(parsed.entries.map((item) => item.path));
    for (const path of REQUIRED_PUBLIC_CARRIER_PATHS) {
      if (!carrierPaths.has(path)) {
        fail(`candidate ${entry.filename} lacks required public carrier file ${path}`);
      }
    }
    const observed = {
      compressedSize: parsed.compressedSize,
      packlistCount: parsed.packlistCount,
      packlistDigest: parsed.packlistDigest,
      packlistSize: parsed.packlistSize,
      tarballSha256: parsed.tarballSha256,
      uncompressedSize: parsed.uncompressedSize,
    };
    for (const [field, value] of Object.entries(observed)) {
      if (entry[field] !== value) fail(`candidate ${entry.filename} ${field} does not match bytes`);
    }
    const paths = parsed.entries.map((item) => item.path);
    const pathSetSha256 = sha256Hex(Buffer.from(canonicalJson(paths), "utf8"));
    const policyEntry = policyByPath.get(entry.packagePath);
    if (!policyEntry || policyEntry.name !== entry.name || policyEntry.pathCount !== paths.length ||
        policyEntry.pathSetSha256 !== pathSetSha256 || entry.pathSetSha256 !== pathSetSha256) {
      fail(`candidate ${entry.filename} published path set does not match the trusted policy`);
    }
    const plannedEntry = plannedByPath.get(entry.packagePath);
    for (const item of parsed.entries) {
      const repositoryPath = entry.packagePath === "." ? item.path : `${entry.packagePath}/${item.path}`;
      if (item.path === "package.json") {
        if (!plannedEntry || !item.content.equals(plannedEntry.releaseManifestBytes)) {
          fail(`candidate ${entry.filename} package.json is not the planned Git-derived release manifest`);
        }
        continue;
      }
      const source = gitByPath.get(repositoryPath);
      const build = buildOutputs.get(repositoryPath);
      const expected = source
        ? { mode: source.mode, sha256: sha256Hex(bindingSource.blobs.get(repositoryPath)), size: source.size }
        : build;
      const observedMode = item.mode === 0o755 ? "100755" : item.mode === 0o644 ? "100644" : "invalid";
      if (!expected || observedMode !== expected.mode || item.sha256 !== expected.sha256 || item.size !== expected.size) {
        fail(`candidate ${entry.filename} file is not bound to Git or the complete build census: ${item.path}`);
      }
    }
    const observedLinterSha256 = runSurfaceLinter(tarballPath, controller.linter, controller.publicRepos);
    if (entry.surfaceLinterSha256 !== linterSha256 || observedLinterSha256 !== linterSha256) {
      fail(`candidate ${entry.filename} linter binding does not match the executing linter`);
    }
    const packageJson = parsed.entries.find((item) => item.path === "package.json");
    const packageManifest = parseManifest(packageJson.content, `${entry.filename}:package.json`);
    if (packageManifest.name !== entry.name || packageManifest.version !== entry.version ||
        sha256Hex(packageJson.content) !== entry.releaseManifestSha256) {
      fail(`candidate ${entry.filename} manifest identity/digest mismatch`);
    }
  }
  const actual = readdirSync(root).sort(bytewiseCompare);
  const expected = [...allowed].sort(bytewiseCompare);
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    fail(`candidate output has missing or extra files: ${JSON.stringify(actual)}`);
  }
  const labelPath = join(root, "CANDIDATE-NON-RELEASE.txt");
  assertRealFile(labelPath, "candidate NON-RELEASE label");
  const label = readFileSync(labelPath, "utf8");
  if (!label.includes(CANDIDATE_STATUS) || !label.includes("not authorized")) {
    fail("candidate output label is ambiguous");
  }
  return manifest;
}

export function verifyCandidateSet(output, options = {}) {
  requireExactKeys(
    options,
    ["gitRef", "offlineCache", "repoRoot"].filter((key) => options[key] !== undefined),
    "candidate verification options",
  );
  const { gitRef, offlineCache, repoRoot } = options;
  const gitSource = loadGitSource(repoRoot, gitRef);
  return withOwnedScratch(join(tmpdir(), "noa-publish-artifact-controller-"), "exact Git controller scratch", (workRoot) => {
    const controller = materializeExactController(gitSource, workRoot);
    return verifyCandidateSetBound(output, { gitSource, offlineCache, repoRoot }, loadPublishArtifactPolicy(controller.policy), controller);
  });
}

// Test-only seam for deterministic fixtures. The authoritative verifier accepts neither a caller-
// supplied Git source nor caller-supplied output rows and always rebuilds from the requested ref.
export function verifyCandidateSetForSelftest(output, options, policy) {
  if (!Array.isArray(options?.independentBuildOutputs)) {
    fail("selftest candidate verification requires independently supplied build-output rows");
  }
  return verifyCandidateSetBound(output, options, policy);
}

function assertFrozenRealTree(root) {
  const visit = (path) => {
    const stat = lstatSync(path);
    if (stat.isSymbolicLink()) fail(`frozen input contains a symbolic link: ${path}`);
    if ((stat.mode & 0o222) !== 0) fail(`frozen input remains writable: ${path}`);
    if (stat.isDirectory()) {
      for (const entry of readdirSync(path)) visit(join(path, entry));
    } else if (!stat.isFile()) fail(`frozen input contains a special filesystem entry: ${path}`);
  };
  visit(root);
  const evidence = digestRealTree(root);
  if (evidence.count === 0) fail("frozen input contains zero files");
  return evidence;
}

/**
 * Lifecycle-free NON-RELEASE pack primitive for another trusted local gate.
 *
 * The caller owns snapshot creation and must pass a no-follow, already-read-only scratch tree.
 * This function never mutates that tree: it binds it read-only into a fresh non-root, no-network
 * container, emits one real tgz into a previously absent output directory, re-proves source
 * stability, parses the exact bytes, and returns their full packlist. It is not release authority.
 */
export function packFrozenPackageArtifact({ commitTime = 0, output, packagePath = ".", source } = {}) {
  if (process.version !== `v${EXPECTED_HOST_NODE}`) {
    setupFail(`host controller requires Node ${EXPECTED_HOST_NODE}, got ${process.version}`);
  }
  if (typeof source !== "string" || source === "" || typeof output !== "string" || output === "") {
    fail("frozen pack requires source and output paths");
  }
  requireSafeInteger(commitTime, "frozen pack commit time");
  const resolvedSource = realpathSync(source);
  assertRealDirectory(resolvedSource, "frozen pack source");
  const before = assertFrozenRealTree(resolvedSource);
  if (packagePath !== ".") validateRepositoryPath(packagePath);
  const packageRoot = packagePath === "."
    ? resolvedSource
    : join(resolvedSource, ...packagePath.split("/"));
  assertRealDirectory(packageRoot, "frozen package root");
  const sourceRelative = relative(resolvedSource, realpathSync(packageRoot));
  if (sourceRelative === ".." || sourceRelative.startsWith(`..${sep}`)) fail("frozen package root escaped source");
  const resolvedOutput = resolve(output);
  assertOutputParent(resolvedOutput);
  return withOwnedScratch(join(tmpdir(), "noa-frozen-pack-"), "frozen-pack scratch", (workRoot) => {
    const generatedOutput = join(workRoot, "candidate");
    mkdirSync(generatedOutput, { mode: 0o700 });
    const platform = dockerPlatform();
    const docker = resolveExecutable(DOCKER_CANDIDATES, "Docker");
    inspectDocker(docker, platform);
    const containerName = `noa-frozen-pack-${process.pid}-${randomBytes(6).toString("hex")}`;
    const args = createDockerRunArgs({
      buildNetwork: "none",
      commitTime,
      containerName,
      driver: DRIVER,
      homedirOverride: NPM_HOMEDIR_OVERRIDE,
      mode: "pack",
      output: generatedOutput,
      packagePath,
      platform,
      source: resolvedSource,
      uid: process.getuid(),
      gid: process.getgid(),
    });
    const marker = runDockerStage(docker, args, containerName, "pack", "none");
    const after = assertFrozenRealTree(resolvedSource);
    if (canonicalJson(after.rows) !== canonicalJson(before.rows)) fail("frozen source changed while packing");
    const files = readdirSync(generatedOutput);
    if (files.length !== 1 || files[0] !== marker.filename) {
      fail(`frozen pack produced an unexpected output set: ${JSON.stringify(files)}`);
    }
    let parsed;
    try { parsed = readSafeNpmTarball(join(generatedOutput, marker.filename)); }
    catch (error) {
      if (error instanceof TarballValidationError) fail(error.message);
      throw error;
    }
    if (marker.package !== packagePath || marker.packlistCount !== parsed.packlistCount) {
      fail("frozen pack result marker does not match the actual tarball");
    }
    const result = {
      entries: parsed.entries.map(({ content, mode, path, sha256, size }) => ({
        content: Buffer.from(content),
        mode,
        path,
        sha256,
        size,
      })),
      filename: marker.filename,
      output: resolvedOutput,
      packagePath,
      packlist: parsed.entries.map(({ mode, path, sha256, size }) => ({ mode, path, sha256, size })),
      releaseAuthorized: false,
      source: { fileCount: before.count, sha256: before.digest, size: before.size },
      status: CANDIDATE_STATUS,
      tarball: {
        compressedSize: parsed.compressedSize,
        packlistCount: parsed.packlistCount,
        packlistDigest: parsed.packlistDigest,
        packlistSize: parsed.packlistSize,
        sha256: parsed.tarballSha256,
        uncompressedSize: parsed.uncompressedSize,
      },
    };
    materializeCandidateOutput(generatedOutput, resolvedOutput, (materializedOutput) => {
      const materializedFiles = readdirSync(materializedOutput);
      if (materializedFiles.length !== 1 || materializedFiles[0] !== marker.filename) {
        fail(`materialized frozen pack has an unexpected output set: ${JSON.stringify(materializedFiles)}`);
      }
      let materialized;
      try { materialized = readSafeNpmTarball(join(materializedOutput, marker.filename)); }
      catch (error) {
        if (error instanceof TarballValidationError) fail(error.message);
        throw error;
      }
      if (materialized.tarballSha256 !== parsed.tarballSha256 ||
          materialized.packlistDigest !== parsed.packlistDigest) {
        fail("materialized frozen pack bytes differ from the verified scratch artifact");
      }
    });
    return result;
  });
}

export function stagePublishArtifacts({
  gitRef = "HEAD",
  offlineCache,
  output,
  repoRoot = DEFAULT_REPO_ROOT,
} = {}) {
  if (typeof output !== "string" || output === "") fail("stage output path is required");
  if (process.version !== `v${EXPECTED_HOST_NODE}`) {
    setupFail(`host controller requires Node ${EXPECTED_HOST_NODE}, got ${process.version}`);
  }
  const resolvedOutput = resolve(output);
  const outputParent = assertOutputParent(resolvedOutput);
  const gitSource = loadGitSource(repoRoot, gitRef);
  const platform = dockerPlatform();
  const docker = resolveExecutable(DOCKER_CANDIDATES, "Docker");
  inspectDocker(docker, platform);
  const buildNetwork = offlineCache === undefined ? "online" : "offline";
  try {
    return withOwnedScratchPair(outputParent, ({ finalScratch, workRoot }) => {
    const controller = materializeExactController(gitSource, workRoot);
    const policy = loadPublishArtifactPolicy(controller.policy);
    const driverDigest = sha256Hex(readFileSync(controller.driver));
    const inventory = derivePackageInventory(gitSource);
    const plannedPackages = planReleaseManifests(inventory);
    enforcePolicyPackageSet(plannedPackages, policy, gitSource);
    const finalCandidate = join(finalScratch, "candidate");
    const offlineCacheState = offlineCache === undefined
      ? undefined
      : snapshotOfflineCache(
        offlineCache,
        join(workRoot, "offline-cache-snapshot"),
        "offline npm content cache",
      );
    const { buildOutputs, buildRoot } = buildImmutableGitSource({
      buildNetwork,
      cacheInput: offlineCacheState?.path,
      docker,
      gitSource,
      platform,
      policy,
      controller,
      workRoot,
    });
    if (offlineCacheState) verifyOwnedOfflineCache(offlineCacheState, "offline npm content cache");

    const frozenRoot = join(workRoot, "frozen-source");
    materializeGitSource(gitSource, frozenRoot);
    for (const outputRoot of BUILD_OUTPUT_ROOTS) {
      copyRealTree(
        join(buildRoot, ...outputRoot.split("/")),
        join(frozenRoot, ...outputRoot.split("/")),
      );
    }
    applyReleaseManifests(frozenRoot, plannedPackages);
    const frozenEvidence = digestRealTree(frozenRoot);
    const copiedBuildOutputs = deriveBuildOutputCensus(gitSource, frozenEvidence, policy);
    if (canonicalJson(copiedBuildOutputs) !== canonicalJson(buildOutputs)) {
      fail("frozen snapshot build output does not equal the pinned-container build census");
    }
    makeReadOnly(frozenRoot);

    mkdirSync(finalCandidate, { mode: 0o700 });
    const artifactRows = [];
    for (const entry of plannedPackages) {
      const perPackageOutput = join(workRoot, `pack-${artifactRows.length}`);
      mkdirSync(perPackageOutput, { mode: 0o700 });
      const packName = `noa-publish-pack-${process.pid}-${artifactRows.length}-${randomBytes(5).toString("hex")}`;
      const packArgs = createDockerRunArgs({
        buildNetwork: "none",
        commitTime: gitSource.commitTime,
        containerName: packName,
        driver: controller.driver,
        homedirOverride: controller.npmHomedirOverride,
        mode: "pack",
        output: perPackageOutput,
        packagePath: entry.packagePath,
        platform,
        source: frozenRoot,
        uid: process.getuid(),
        gid: process.getgid(),
      });
      const packed = runDockerStage(docker, packArgs, packName, "pack", "none");
      if (packed.filename !== entry.filename || packed.package !== entry.packagePath) {
        fail(`packer result marker disagrees with planned package ${entry.name}`);
      }
      const produced = readdirSync(perPackageOutput);
      if (produced.length !== 1 || produced[0] !== entry.filename) {
        fail(`packer output set disagrees for ${entry.name}`);
      }
      const sourceTarball = join(perPackageOutput, entry.filename);
      assertRealFile(sourceTarball, `tarball ${entry.filename}`);
      const parsed = readSafeNpmTarball(sourceTarball);
      verifyPackedManifest(parsed, entry);
      const paths = parsed.entries.map((item) => item.path);
      const pathSetSha256 = sha256Hex(Buffer.from(canonicalJson(paths), "utf8"));
      const policyEntry = policy.packages.find((candidate) => candidate.packagePath === entry.packagePath);
      if (!policyEntry || policyEntry.name !== entry.name || policyEntry.pathCount !== paths.length ||
          policyEntry.pathSetSha256 !== pathSetSha256) {
        fail(`packer path set disagrees with policy for ${entry.name}`);
      }
      const surfaceLinterSha256 = runSurfaceLinter(sourceTarball, controller.linter, controller.publicRepos);
      const destinationTarball = join(finalCandidate, entry.filename);
      copyFileSync(sourceTarball, destinationTarball, COPYFILE_EXCL);
      const copied = readSafeNpmTarball(destinationTarball);
      if (copied.tarballSha256 !== parsed.tarballSha256) fail(`tarball copy drifted: ${entry.filename}`);
      artifactRows.push({
        compressedSize: parsed.compressedSize,
        filename: entry.filename,
        name: entry.name,
        packlistCount: parsed.packlistCount,
        packlistDigest: parsed.packlistDigest,
        packlistSize: parsed.packlistSize,
        packagePath: entry.packagePath,
        pathSetSha256,
        releaseManifestSha256: entry.releaseManifestSha256,
        sourceManifestGitOid: entry.sourceManifestGitOid,
        sourceManifestSha256: entry.sourceManifestSha256,
        surfaceLinterSha256,
        tarballSha256: parsed.tarballSha256,
        transformations: entry.transformations,
        uncompressedSize: parsed.uncompressedSize,
        version: entry.version,
      });
      const afterPackage = digestRealTree(frozenRoot);
      if (afterPackage.digest !== frozenEvidence.digest) fail(`frozen snapshot changed while packing ${entry.name}`);
    }
    const manifest = {
      build: {
        dependencyInput: offlineCacheState
          ? dependencyInputFromCache(offlineCacheState.evidence)
          : { source: "networked npm ci from exact package-lock.json; no cache retained" },
        network: buildNetwork,
        outputs: buildOutputs.map((row) => ({ ...row })),
        tsconfigs: [...BUILD_TSCONFIGS],
      },
      controller: {
        driverSha256: driverDigest,
        image: NODE_IMAGE,
        node: EXPECTED_NODE,
        npm: EXPECTED_NPM,
        packStack: EXPECTED_PACK_STACK,
        platform,
      },
      frozenSnapshot: {
        fileCount: frozenEvidence.count,
        sha256: frozenEvidence.digest,
        size: frozenEvidence.size,
      },
      packages: artifactRows,
      policy: {
        path: POLICY_REPO_PATH,
        schema: POLICY_SCHEMA,
        sha256: policy.sha256,
      },
      releaseAuthorized: false,
      schema: MANIFEST_SCHEMA,
      source: {
        commit: gitSource.commit,
        commitTime: gitSource.commitTime,
        fileCount: gitSource.records.length,
        inventorySha256: gitSource.inventoryDigest,
        objectFormat: gitSource.objectFormat,
        tree: gitSource.tree,
      },
      status: CANDIDATE_STATUS,
    };
    const manifestBytes = Buffer.from(canonicalJson(manifest), "utf8");
    writeFileSync(join(finalCandidate, "publish-artifacts.manifest.json"), manifestBytes, { flag: "wx" });
    writeFileSync(
      join(finalCandidate, "publish-artifacts.manifest.sha256"),
      `${sha256Hex(manifestBytes)}\n`,
      { flag: "wx" },
    );
    writeFileSync(
      join(finalCandidate, "CANDIDATE-NON-RELEASE.txt"),
      `${CANDIDATE_STATUS}\nThese tarballs are staging evidence only and are not authorized for publication or release.\n`,
      { flag: "wx" },
    );
    verifyCandidateSetBound(
      finalCandidate,
      { gitSource, independentBuildOutputs: buildOutputs, ownedOfflineCache: offlineCacheState },
      policy,
      controller,
    );
    materializeCandidateOutput(finalCandidate, resolvedOutput, (materializedOutput) => {
      verifyCandidateSetBound(
        materializedOutput,
        { gitSource, independentBuildOutputs: buildOutputs, ownedOfflineCache: offlineCacheState },
        policy,
        controller,
      );
    });
    return { manifest, output: resolvedOutput };
    }, mkdtempSync);
  } catch (error) {
    normalizeStageTarballFailure(error);
  }
}

// Keep tarball-parser failures in the public staging error vocabulary even when they arise inside
// the no-clobber materialization callback.
function normalizeStageTarballFailure(error) {
  if (error instanceof TarballValidationError) fail(error.message);
  throw error;
}
