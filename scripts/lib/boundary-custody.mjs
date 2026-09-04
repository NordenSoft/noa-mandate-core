/**
 * Crash-ordered owner-only filesystem custody for NOA boundary evidence.
 *
 * The public contract is deliberately small: make an owner-only directory durable, create one
 * file without replacement, replace an already-authenticated destination from an exact candidate,
 * and remove one exact file through a deterministic deleting path. Every completed operation does
 * a full-write check, file fsync, parent-directory fsync, and exact read-back as applicable.
 *
 * NON-CLAIM: ordinary Node.js fsyncSync supports process-crash/restart sequencing while the OS and
 * storage stack remain intact. On macOS it does not guarantee write ordering across an OS crash or
 * sudden physical power loss; that stronger claim requires facilities Node's stdlib does not expose.
 * Node also exposes no descriptor-relative conditional rename/unlink. The legacy replace, claim,
 * and delete exports below therefore require an externally isolated pathname namespace; they are
 * not safe against a hostile same-UID process swapping a validated name immediately before the
 * pathname mutation. Immutable publication and retired staged-create recovery do not use them.
 */

import {
  constants as fsConstants,
  closeSync,
  fchmodSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  linkSync,
  mkdirSync,
  openSync,
  readdirSync,
  readSync,
  renameSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { createHash, timingSafeEqual } from "node:crypto";
import { basename, dirname, join, resolve } from "node:path";

const DEFAULT_DIRECTORY_MODE = 0o700;
const DEFAULT_FILE_MODE = 0o600;
const DEFAULT_MAX_STABLE_READ_BYTES = 64 * 1024 * 1024;
const CREATE_STAGE_DIRECTORY = ".noa-boundary-create-v1";
const CREATE_STAGE_NAME_RE = /^create-v1-([0-9a-f]{64})-([0-9a-f]{64})-([1-9][0-9]{0,15})-p([1-9][0-9]{0,15})-([0-9a-f]{32})\.stage$/;
const IMMUTABLE_PUBLISH_TEST_BRAND = Symbol("boundary-immutable-publish-test-dependencies");
const IMMUTABLE_PUBLISH_TEST_KEYS = Object.freeze([
  "faultAction", "faultCode", "faultPoint", "trace", "writeChunkBytes",
]);
const IMMUTABLE_PUBLISH_FAULT_ACTIONS = new Set(["crash", "system-error", "throw", "zero-write"]);
const IMMUTABLE_PUBLISH_FAULT_CODES = new Set(["EIO", "ENOSPC", "EINVAL"]);
const IMMUTABLE_PUBLISH_SYSTEM_FAULT_POINTS = new Set([
  "candidate-create-operation",
  "candidate-write-operation",
  "existing-final-close-operation",
  "existing-final-fstat-operation",
  "existing-final-fsync-operation",
  "existing-final-open-operation",
  "final-link-operation",
]);
const IMMUTABLE_PUBLISH_MAX_PHASES = 64;
let FILE_SYNC_BARRIERS = 0;
let DIRECTORY_SYNC_BARRIERS = 0;
let IMMUTABLE_PUBLISH_PENDING_READBACKS = 0;
let IMMUTABLE_PUBLISH_FILE_SYNCS = 0;
let IMMUTABLE_PUBLISH_DIRECTORY_SYNCS = 0;
const CUSTODY_TEST_WAIT = new Int32Array(new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT));

const currentUid = () => (typeof process.geteuid === "function"
  ? process.geteuid()
  : (typeof process.getuid === "function" ? process.getuid() : null));
const permissionBits = (stat) => stat.mode & 0o7777;
const sameIdentity = (left, right) => left.dev === right.dev && left.ino === right.ino;
const sameState = (left, right) => sameIdentity(left, right)
  && left.size === right.size && left.mtimeMs === right.mtimeMs && left.ctimeMs === right.ctimeMs;
const sameCustodyState = (left, right) => sameState(left, right)
  && left.mode === right.mode && left.uid === right.uid && left.nlink === right.nlink;
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const targetDigest = (name) => sha256(Buffer.from(`noa-boundary-create-destination/v1\0${name}`, "utf8"));

export class BoundaryCustodyError extends Error {
  constructor(code, cause = null) {
    super(code, cause === null ? undefined : { cause });
    this.name = "BoundaryCustodyError";
    this.code = code;
  }
}

const refuse = (code, cause = null) => { throw new BoundaryCustodyError(code, cause); };

function injectedFault(point, path) {
  if (process.env.NOA_BOUNDARY_ROTATION_TEST_MODE !== "1") return;
  const observed = `${point}:${basename(path)}`;
  if (process.env.NOA_BOUNDARY_ROTATION_TRACE_CHECKPOINTS === "1") {
    process.stderr.write(`NOA_ROTATION_CHECKPOINT ${observed}\n`);
  }
  if (process.env.NOA_BOUNDARY_ROTATION_PAUSE_AT === observed) {
    const requested = Number(process.env.NOA_BOUNDARY_ROTATION_PAUSE_MS ?? "10000");
    const pauseMs = Number.isSafeInteger(requested) && requested >= 10 && requested <= 10_000
      ? requested : 10_000;
    const releaseFile = process.env.NOA_BOUNDARY_ROTATION_RELEASE_FILE;
    if (typeof releaseFile === "string" && releaseFile.length > 0) {
      const deadline = Date.now() + pauseMs;
      while (optionalStat(releaseFile) === null && Date.now() < deadline) {
        Atomics.wait(CUSTODY_TEST_WAIT, 0, 0, Math.min(10, Math.max(1, deadline - Date.now())));
      }
      if (optionalStat(releaseFile) === null) refuse("TEST_CHECKPOINT_TIMEOUT");
    } else {
      Atomics.wait(CUSTODY_TEST_WAIT, 0, 0, pauseMs);
    }
  }
  const crashAfter = process.env.NOA_BOUNDARY_CUSTODY_CRASH_AFTER;
  if (typeof crashAfter === "string" && observed.startsWith(crashAfter)) {
    process.kill(process.pid, "SIGKILL");
  }
  const requested = process.env.NOA_BOUNDARY_CUSTODY_FAIL_AT;
  if (typeof requested !== "string" || !observed.startsWith(requested)) return;
  const requestedCode = process.env.NOA_BOUNDARY_CUSTODY_FAIL_CODE;
  const code = ["EIO", "ENOSPC", "EINVAL"].includes(requestedCode) ? requestedCode : "EIO";
  refuse(`INJECTED_${code}`);
}

function injectedPartialWrite(fd, bytes, path) {
  if (process.env.NOA_BOUNDARY_ROTATION_TEST_MODE !== "1") return;
  const observed = `create-partial-write:${basename(path)}`;
  const crashAfter = process.env.NOA_BOUNDARY_CUSTODY_CRASH_AFTER;
  const requested = process.env.NOA_BOUNDARY_CUSTODY_FAIL_AT;
  if ((typeof crashAfter !== "string" || !observed.startsWith(crashAfter))
      && (typeof requested !== "string" || !observed.startsWith(requested))) return;
  const count = Math.max(1, Math.floor(bytes.length / 2));
  fullWrite(fd, bytes.subarray(0, count));
  if (typeof crashAfter === "string" && observed.startsWith(crashAfter)) {
    process.kill(process.pid, "SIGKILL");
  }
  const requestedCode = process.env.NOA_BOUNDARY_CUSTODY_FAIL_CODE;
  const code = ["EIO", "ENOSPC", "EINVAL"].includes(requestedCode) ? requestedCode : "ENOSPC";
  refuse(`INJECTED_${code}`);
}

function requiredFlag(name) {
  const value = fsConstants[name];
  if (typeof value !== "number" || value === 0) refuse(`MISSING_${name}`);
  return value;
}

function optionalStat(path) {
  try { return lstatSync(path); } catch (error) {
    if (error?.code === "ENOENT") return null;
    refuse("PATH_INSPECTION_FAILED", error);
  }
  return null;
}

function assertDirectory(stat, { mode, uid }) {
  if (stat.isSymbolicLink() || !stat.isDirectory()) refuse("DIRECTORY_TYPE_REJECTED");
  if (uid !== null && stat.uid !== uid) refuse("DIRECTORY_OWNER_REJECTED");
  if (permissionBits(stat) !== mode) refuse("DIRECTORY_MODE_REJECTED");
}

function assertRegular(stat, { mode, uid, allowLinks = 1 }) {
  if (stat.isSymbolicLink() || !stat.isFile()) refuse("FILE_TYPE_REJECTED");
  if (uid !== null && stat.uid !== uid) refuse("FILE_OWNER_REJECTED");
  if (permissionBits(stat) !== mode) refuse("FILE_MODE_REJECTED");
  if (stat.nlink !== allowLinks) refuse("FILE_LINK_COUNT_REJECTED");
}

function exactPositiveIntegerArray(values, maximum, code) {
  if (!Array.isArray(values) || values.length === 0 || values.length > 8
      || values.some((value) => !Number.isSafeInteger(value) || value <= 0 || value > maximum)
      || new Set(values).size !== values.length) refuse(code);
  return Object.freeze([...values]);
}

/** Pure custody classification shared by evidence census and stable readers. */
export function ownerOnlyFileCustodyProblem(
  stat,
  { allowedLinks = [1], allowedModes = [DEFAULT_FILE_MODE], expectedUid = currentUid() } = {},
) {
  if (stat === null || typeof stat !== "object") return "FILE_STAT_MISSING";
  if (typeof stat.isSymbolicLink !== "function" || typeof stat.isFile !== "function"
      || stat.isSymbolicLink() || !stat.isFile()) return "FILE_TYPE_REJECTED";
  if (expectedUid !== null && stat.uid !== expectedUid) return "FILE_OWNER_REJECTED";
  if (!allowedModes.includes(permissionBits(stat))) return "FILE_MODE_REJECTED";
  if (!allowedLinks.includes(stat.nlink)) return "FILE_LINK_COUNT_REJECTED";
  return null;
}

function assertOwnerOnlyRegular(stat, options) {
  const problem = ownerOnlyFileCustodyProblem(stat, options);
  if (problem !== null) refuse(problem);
}

function openDirectory(path) {
  try {
    return openSync(path, fsConstants.O_RDONLY | requiredFlag("O_DIRECTORY") | requiredFlag("O_NOFOLLOW"));
  } catch (error) {
    if (error instanceof BoundaryCustodyError) throw error;
    refuse("DIRECTORY_OPEN_FAILED", error);
  }
  return undefined;
}

/** Shared file barrier used by boundary policy and ledger writes. */
export function syncFileDescriptor(fd) {
  try { fsyncSync(fd); } catch (error) { refuse("FILE_SYNC_FAILED", error); }
  FILE_SYNC_BARRIERS++;
}

function syncDirectoryDescriptor(fd) {
  try { fsyncSync(fd); } catch (error) { refuse("DIRECTORY_SYNC_FAILED", error); }
  DIRECTORY_SYNC_BARRIERS++;
}

/** Monotonic process-local counters used only by the arm's remove/restore knockout experiment. */
export function custodyBarrierCountsForSelftest() {
  return Object.freeze({ file: FILE_SYNC_BARRIERS, directory: DIRECTORY_SYNC_BARRIERS });
}

/** Synchronize one already-existing, non-symlink directory entry. */
export function syncDirectory(path) {
  let fd;
  try {
    const before = lstatSync(path);
    if (before.isSymbolicLink() || !before.isDirectory()) refuse("DIRECTORY_TYPE_REJECTED");
    fd = openDirectory(path);
    const opened = fstatSync(fd);
    if (!sameIdentity(before, opened) || !opened.isDirectory()) refuse("DIRECTORY_IDENTITY_CHANGED");
    syncDirectoryDescriptor(fd);
    const after = lstatSync(path);
    if (!sameIdentity(opened, after) || after.isSymbolicLink() || !after.isDirectory()) {
      refuse("DIRECTORY_IDENTITY_CHANGED");
    }
  } catch (error) {
    if (error instanceof BoundaryCustodyError) throw error;
    refuse("DIRECTORY_SYNC_FAILED", error);
  } finally {
    if (fd !== undefined) try { closeSync(fd); } catch { /* operation has already been synchronized */ }
  }
}

/**
 * Establish exact owner-only directory custody. A newly created directory is synchronized itself
 * and then made discoverable by synchronizing its parent directory.
 */
export function ensureOwnerOnlyDirectory({
  directoryPath,
  mode = DEFAULT_DIRECTORY_MODE,
  repairMode = false,
  expectedUid = currentUid(),
}) {
  let created = false;
  let before = optionalStat(directoryPath);
  if (before === null) {
    try {
      mkdirSync(directoryPath, { mode });
      created = true;
    } catch (error) {
      if (error?.code !== "EEXIST") refuse("DIRECTORY_CREATE_FAILED", error);
    }
    before = optionalStat(directoryPath);
    if (before === null) refuse("DIRECTORY_CREATE_FAILED");
  }
  if (before.isSymbolicLink() || !before.isDirectory()) refuse("DIRECTORY_TYPE_REJECTED");
  if (expectedUid !== null && before.uid !== expectedUid) refuse("DIRECTORY_OWNER_REJECTED");

  let fd;
  try {
    fd = openDirectory(directoryPath);
    const opened = fstatSync(fd);
    if (!sameIdentity(before, opened) || !opened.isDirectory()) refuse("DIRECTORY_IDENTITY_CHANGED");
    if (permissionBits(opened) !== mode) {
      if (!repairMode) refuse("DIRECTORY_MODE_REJECTED");
      fchmodSync(fd, mode);
    }
    syncDirectoryDescriptor(fd);
    const repaired = fstatSync(fd);
    assertDirectory(repaired, { mode, uid: expectedUid });
    const after = lstatSync(directoryPath);
    assertDirectory(after, { mode, uid: expectedUid });
    if (!sameIdentity(repaired, after)) refuse("DIRECTORY_IDENTITY_CHANGED");
    if (created) syncDirectory(dirname(directoryPath));
    return { created, stat: after };
  } catch (error) {
    if (error instanceof BoundaryCustodyError) throw error;
    refuse("DIRECTORY_CUSTODY_FAILED", error);
  } finally {
    if (fd !== undefined) try { closeSync(fd); } catch { /* custody verdict already decided */ }
  }
  return null;
}

function fullWrite(fd, bytes) {
  let offset = 0;
  while (offset < bytes.length) {
    const written = writeSync(fd, bytes, offset, bytes.length - offset, offset);
    if (!Number.isSafeInteger(written) || written <= 0) refuse("SHORT_WRITE");
    offset += written;
  }
  if (offset !== bytes.length) refuse("SHORT_WRITE");
}

function readDescriptorExact(fd, size) {
  const bytes = Buffer.alloc(size);
  let offset = 0;
  while (offset < size) {
    const count = readSync(fd, bytes, offset, size - offset, offset);
    if (!Number.isSafeInteger(count) || count <= 0) refuse("SHORT_READ");
    offset += count;
  }
  return bytes;
}

function pathBytesFromDescriptor(fd, opened, path, { mode, expectedUid, allowLinks }) {
  const bytes = readDescriptorExact(fd, opened.size);
  const afterDescriptor = fstatSync(fd);
  const afterPath = lstatSync(path);
  assertRegular(afterDescriptor, { mode, uid: expectedUid, allowLinks });
  assertRegular(afterPath, { mode, uid: expectedUid, allowLinks });
  if (!sameState(opened, afterDescriptor) || !sameIdentity(afterDescriptor, afterPath)) {
    refuse("FILE_READ_CHANGED");
  }
  return { bytes, stat: afterPath, sha256: sha256(bytes) };
}

/**
 * Stable owner-only read authority. The descriptor is no-follow/non-blocking, bytes are read twice
 * from exact positions, full custody metadata is stable, and an optional owner-only parent
 * directory must retain its identity for the entire read. No caller supplies raw fs primitives.
 */
export function readStableOwnerOnlyFile({
  path,
  expectedBytes = null,
  exactBytes = null,
  maxBytes = DEFAULT_MAX_STABLE_READ_BYTES,
  allowedModes = [DEFAULT_FILE_MODE],
  allowedLinks = [1],
  expectedUid = currentUid(),
  directoryPath = null,
  directoryMode = DEFAULT_DIRECTORY_MODE,
  optional = false,
  settleMs = 0,
}) {
  const modes = exactPositiveIntegerArray(allowedModes, 0o7777, "FILE_MODE_POLICY_REJECTED");
  const links = exactPositiveIntegerArray(allowedLinks, 1_000_000, "FILE_LINK_POLICY_REJECTED");
  if (modes.some((mode) => (mode & 0o077) !== 0 || (mode & 0o400) === 0)
      || (expectedUid !== null && (!Number.isSafeInteger(expectedUid) || expectedUid < 0))
      || !Number.isSafeInteger(maxBytes) || maxBytes < 0 || maxBytes > DEFAULT_MAX_STABLE_READ_BYTES
      || (exactBytes !== null && (!Number.isSafeInteger(exactBytes) || exactBytes < 0 || exactBytes > maxBytes))
      || !Number.isSafeInteger(settleMs) || settleMs < 0 || settleMs > 1_000
      || typeof path !== "string" || path.length === 0
      || (directoryPath !== null && (typeof directoryPath !== "string"
        || dirname(path) !== directoryPath || !Number.isSafeInteger(directoryMode)
        || directoryMode <= 0 || directoryMode > 0o7777 || (directoryMode & 0o077) !== 0))) {
    refuse("STABLE_READ_POLICY_REJECTED");
  }
  let expected = null;
  try { expected = expectedBytes === null ? null : Buffer.from(expectedBytes); } catch (error) {
    refuse("STABLE_READ_POLICY_REJECTED", error);
  }
  if (expected !== null && expected.length > maxBytes) refuse("FILE_SIZE_LIMIT_REJECTED");
  if (exactBytes !== null && expected !== null && exactBytes !== expected.length) {
    refuse("FILE_EXACT_SIZE_REJECTED");
  }

  let directoryBefore = null;
  if (directoryPath !== null) {
    directoryBefore = optionalStat(directoryPath);
    if (directoryBefore === null) refuse("DIRECTORY_MISSING");
    assertDirectory(directoryBefore, { mode: directoryMode, uid: expectedUid });
  }
  const before = optionalStat(path);
  if (before === null) {
    if (optional) return null;
    refuse("FILE_MISSING");
  }
  assertOwnerOnlyRegular(before, { allowedLinks: links, allowedModes: modes, expectedUid });
  if (before.size < 0 || before.size > maxBytes) refuse("FILE_SIZE_LIMIT_REJECTED");
  if (exactBytes !== null && before.size !== exactBytes) refuse("FILE_EXACT_SIZE_REJECTED");

  let fd;
  try {
    fd = openSync(
      path,
      fsConstants.O_RDONLY | requiredFlag("O_NOFOLLOW") | requiredFlag("O_NONBLOCK"),
    );
    const opened = fstatSync(fd);
    assertOwnerOnlyRegular(opened, { allowedLinks: links, allowedModes: modes, expectedUid });
    if (!sameIdentity(before, opened)) refuse("FILE_IDENTITY_CHANGED");
    if (opened.size < 0 || opened.size > maxBytes) refuse("FILE_SIZE_LIMIT_REJECTED");
    if (exactBytes !== null && opened.size !== exactBytes) refuse("FILE_EXACT_SIZE_REJECTED");
    if (directoryBefore !== null) {
      const directoryAtOpen = optionalStat(directoryPath);
      if (directoryAtOpen === null) refuse("DIRECTORY_MISSING");
      assertDirectory(directoryAtOpen, { mode: directoryMode, uid: expectedUid });
      if (!sameIdentity(directoryBefore, directoryAtOpen)) refuse("DIRECTORY_IDENTITY_CHANGED");
    }

    const first = readDescriptorExact(fd, opened.size);
    if (settleMs > 0) Atomics.wait(CUSTODY_TEST_WAIT, 0, 0, settleMs);
    const between = fstatSync(fd);
    assertOwnerOnlyRegular(between, { allowedLinks: links, allowedModes: modes, expectedUid });
    if (between.size < 0 || between.size > maxBytes) refuse("FILE_SIZE_LIMIT_REJECTED");
    const second = readDescriptorExact(fd, between.size);
    const afterDescriptor = fstatSync(fd);
    const afterPath = lstatSync(path);
    assertOwnerOnlyRegular(afterDescriptor, { allowedLinks: links, allowedModes: modes, expectedUid });
    assertOwnerOnlyRegular(afterPath, { allowedLinks: links, allowedModes: modes, expectedUid });
    if (!sameCustodyState(opened, between) || !sameCustodyState(between, afterDescriptor)
        || !sameCustodyState(afterDescriptor, afterPath)
        || first.length !== second.length || !timingSafeEqual(first, second)) {
      refuse("FILE_READ_CHANGED");
    }
    if (expected !== null
        && (first.length !== expected.length || !timingSafeEqual(first, expected))) {
      refuse("FILE_BYTES_CHANGED");
    }
    if (directoryBefore !== null) {
      const directoryAfter = lstatSync(directoryPath);
      assertDirectory(directoryAfter, { mode: directoryMode, uid: expectedUid });
      if (!sameCustodyState(directoryBefore, directoryAfter)) refuse("DIRECTORY_IDENTITY_CHANGED");
    }
    return { bytes: first, stat: afterPath, sha256: sha256(first) };
  } catch (error) {
    if (error instanceof BoundaryCustodyError) throw error;
    refuse("FILE_READ_FAILED", error);
  } finally {
    if (fd !== undefined) try { closeSync(fd); } catch { /* stable read verdict already decided */ }
  }
  return null;
}

/** Compatibility wrapper over the sole stable owner-only reader. */
export function readOwnerOnlyFile({
  path,
  expectedBytes = null,
  mode = DEFAULT_FILE_MODE,
  expectedUid = currentUid(),
  allowLinks = 1,
}) {
  const expected = expectedBytes === null ? null : Buffer.from(expectedBytes);
  return readStableOwnerOnlyFile({
    path,
    expectedBytes: expected,
    exactBytes: expected === null ? null : expected.length,
    maxBytes: expected === null ? DEFAULT_MAX_STABLE_READ_BYTES : expected.length,
    allowedModes: [mode],
    allowedLinks: [allowLinks],
    expectedUid,
  });
}

function stagePaths(path) {
  const parent = dirname(path);
  const name = basename(path);
  if (name.length === 0 || name === "." || name === ".." || resolve(parent, name) !== resolve(path)) {
    refuse("STAGE_DESTINATION_REJECTED");
  }
  const root = join(parent, CREATE_STAGE_DIRECTORY);
  return { parent, name, root, target: join(root, name) };
}

function stageEntriesForPath(path, { mode, expectedUid }) {
  const paths = stagePaths(path);
  const rootStat = optionalStat(paths.root);
  if (rootStat === null) return { paths, entries: [] };
  assertDirectory(rootStat, { mode: DEFAULT_DIRECTORY_MODE, uid: expectedUid });
  const targetStat = optionalStat(paths.target);
  if (targetStat === null) return { paths, entries: [] };
  assertDirectory(targetStat, { mode: DEFAULT_DIRECTORY_MODE, uid: expectedUid });
  let names;
  try { names = readdirSync(paths.target).sort(); } catch (error) { refuse("STAGE_DIRECTORY_READ_FAILED", error); }
  const entries = names.map((name) => {
    const match = CREATE_STAGE_NAME_RE.exec(name);
    if (match === null || match[1] !== targetDigest(paths.name)) refuse("UNKNOWN_CREATE_STAGE");
    const length = Number(match[3]);
    const pid = Number(match[4]);
    if (!Number.isSafeInteger(length) || length <= 0 || !Number.isSafeInteger(pid) || pid <= 0) {
      refuse("UNKNOWN_CREATE_STAGE");
    }
    const stagePath = join(paths.target, name);
    const stat = optionalStat(stagePath);
    if (stat === null) refuse("STAGE_CHANGED");
    assertRegular(stat, { mode, uid: expectedUid, allowLinks: stat.nlink });
    if (stat.nlink !== 1 && stat.nlink !== 2) refuse("FILE_LINK_COUNT_REJECTED");
    return {
      path: stagePath,
      payloadSha256: match[2],
      length,
      pid,
      nonce: match[5],
      stat,
    };
  });
  return { paths, entries };
}

/** Enumerate only the destination names inside the reserved owner-only create namespace. */
export function durableCreateStageTargets({
  directoryPath,
  expectedUid = currentUid(),
}) {
  const root = join(directoryPath, CREATE_STAGE_DIRECTORY);
  const rootStat = optionalStat(root);
  if (rootStat === null) return [];
  assertDirectory(rootStat, { mode: DEFAULT_DIRECTORY_MODE, uid: expectedUid });
  let names;
  try { names = readdirSync(root).sort(); } catch (error) { refuse("STAGE_DIRECTORY_READ_FAILED", error); }
  for (const name of names) {
    if (name.length === 0 || name === "." || name === ".." || basename(name) !== name) {
      refuse("UNKNOWN_CREATE_STAGE_TARGET");
    }
    const targetStat = optionalStat(join(root, name));
    if (targetStat === null) refuse("STAGE_CHANGED");
    assertDirectory(targetStat, { mode: DEFAULT_DIRECTORY_MODE, uid: expectedUid });
  }
  return names;
}

/**
 * Detect the retired staged-create format without mutating it. Node exposes no inode-conditional
 * unlink, so a same-UID process can replace a validated pathname before deletion. Automatic legacy
 * stage publication or cleanup is forbidden; every observed stage is retained and fails closed.
 */
export function recoverDurableCreateForPath({
  path,
  mode = DEFAULT_FILE_MODE,
  expectedUid = currentUid(),
}) {
  const { entries } = stageEntriesForPath(path, { mode, expectedUid });
  if (entries.length === 0) return { recovered: false, removedPartial: false };
  refuse("CREATE_STAGE_MANUAL_RECOVERY_REQUIRED");
}

/**
 * Create one uniquely named, non-authoritative candidate with exact durable readback. The caller
 * must content-bind the unique name and recover partial crash residue before using the candidate in
 * an atomic publication election. Unlike durableCreateExclusive, this primitive never creates a
 * shared staging directory and therefore remains safe when many independent candidates race.
 */
export function durableCreatePrivateCandidate({
  path,
  bytes,
  mode = DEFAULT_FILE_MODE,
  expectedUid = currentUid(),
}) {
  const input = Buffer.from(bytes);
  if (input.length === 0) refuse("EMPTY_FILE_REJECTED");
  let fd;
  try {
    fd = openSync(
      path,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | requiredFlag("O_NOFOLLOW"),
      mode,
    );
    const opened = fstatSync(fd);
    assertRegular(opened, { mode, uid: expectedUid });
    fullWrite(fd, input);
    syncFileDescriptor(fd);
    syncDirectory(dirname(path));
    const written = fstatSync(fd);
    assertRegular(written, { mode, uid: expectedUid });
    if (!sameIdentity(opened, written) || written.size !== input.length) refuse("FILE_WRITE_CHANGED");
    const measured = readOwnerOnlyFile({ path, expectedBytes: input, mode, expectedUid });
    if (!sameIdentity(written, measured.stat)) refuse("FILE_IDENTITY_CHANGED");
    return measured;
  } catch (error) {
    if (error instanceof BoundaryCustodyError) throw error;
    refuse("FILE_CANDIDATE_CREATE_FAILED", error);
  } finally {
    if (fd !== undefined) try { closeSync(fd); } catch { /* exact readback verdict already selected */ }
  }
  return null;
}

function exactOptionalKeys(value, allowed) {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    && Object.keys(value).every((key) => allowed.includes(key));
}

/** Exact branded seam for bounded fault injection and structural phase tracing. */
export function durablePublishImmutableByLinkTestDependencies(options = {}) {
  if (!exactOptionalKeys(options, IMMUTABLE_PUBLISH_TEST_KEYS)) {
    refuse("IMMUTABLE_PUBLISH_TEST_SCHEMA_REJECTED");
  }
  const faultAction = options.faultAction ?? null;
  const faultCode = options.faultCode ?? "EIO";
  const faultPoint = options.faultPoint ?? null;
  const writeChunkBytes = options.writeChunkBytes ?? null;
  const trace = options.trace ?? false;
  if ((faultPoint === null) !== (faultAction === null)
      || (faultPoint !== null && (typeof faultPoint !== "string" || !/^[a-z0-9-]{1,48}$/.test(faultPoint)))
      || (faultAction !== null && !IMMUTABLE_PUBLISH_FAULT_ACTIONS.has(faultAction))
      || (faultAction === "system-error" && !IMMUTABLE_PUBLISH_SYSTEM_FAULT_POINTS.has(faultPoint))
      || (faultAction !== "system-error" && IMMUTABLE_PUBLISH_SYSTEM_FAULT_POINTS.has(faultPoint))
      || !IMMUTABLE_PUBLISH_FAULT_CODES.has(faultCode)
      || (writeChunkBytes !== null
        && (!Number.isSafeInteger(writeChunkBytes) || writeChunkBytes <= 0 || writeChunkBytes > 1024 * 1024))
      || typeof trace !== "boolean") refuse("IMMUTABLE_PUBLISH_TEST_OPTIONS_REJECTED");
  return Object.freeze({
    [IMMUTABLE_PUBLISH_TEST_BRAND]: true,
    faultAction,
    faultCode,
    faultPoint,
    trace,
    writeChunkBytes,
  });
}

function immutablePublishDependencies(testDependencies) {
  if (testDependencies === undefined || testDependencies === null) {
    return Object.freeze({
      faultAction: null, faultCode: "EIO", faultPoint: null, trace: false, writeChunkBytes: null,
    });
  }
  if (testDependencies?.[IMMUTABLE_PUBLISH_TEST_BRAND] !== true) {
    refuse("IMMUTABLE_PUBLISH_TEST_SEAM_REJECTED");
  }
  return testDependencies;
}

/** Monotonic structural counters; callers compare deltas and receive no path or payload data. */
export function durablePublishImmutableByLinkCountsForSelftest() {
  return Object.freeze({
    directorySync: IMMUTABLE_PUBLISH_DIRECTORY_SYNCS,
    fileSync: IMMUTABLE_PUBLISH_FILE_SYNCS,
    pendingReadback: IMMUTABLE_PUBLISH_PENDING_READBACKS,
  });
}

function immutablePublishPhase(context, point) {
  if (context.dependencies.trace) {
    if (context.phases.length >= IMMUTABLE_PUBLISH_MAX_PHASES) refuse("IMMUTABLE_PUBLISH_TRACE_BOUNDS_REJECTED");
    context.phases.push(point);
    if (process.env.NOA_BOUNDARY_IMMUTABLE_TRACE_CHECKPOINTS === "1") {
      process.stderr.write(`NOA_IMMUTABLE_PUBLISH_CHECKPOINT ${point}\n`);
    }
    if (process.env.NOA_BOUNDARY_IMMUTABLE_PAUSE_AT === point) {
      const requested = Number(process.env.NOA_BOUNDARY_IMMUTABLE_PAUSE_MS ?? "10000");
      const pauseMs = Number.isSafeInteger(requested) && requested >= 10 && requested <= 10_000
        ? requested : 10_000;
      const releaseFile = process.env.NOA_BOUNDARY_IMMUTABLE_RELEASE_FILE;
      if (typeof releaseFile !== "string" || releaseFile.length === 0) {
        refuse("TEST_CHECKPOINT_RELEASE_REJECTED");
      }
      const deadline = Date.now() + pauseMs;
      while (optionalStat(releaseFile) === null && Date.now() < deadline) {
        Atomics.wait(CUSTODY_TEST_WAIT, 0, 0, Math.min(10, Math.max(1, deadline - Date.now())));
      }
      if (optionalStat(releaseFile) === null) refuse("TEST_CHECKPOINT_TIMEOUT");
    }
  }
  if (context.legacyFaultPath !== null) {
    const legacyPoint = {
      "existing-final-dir-fsync-before": "existing-directory-sync",
      "existing-final-file-fsync-before": "existing-file-sync",
      "pending-write-before": "create-write",
      "pending-write-after": "create-stage-written",
      "content-file-fsync-before": "create-file-sync",
      "candidate-dir-fsync-before": "create-stage-directory-sync",
      "candidate-dir-fsync-after": "create-stage-synced",
      "final-link-before": "create-link",
      "final-link-after": "create-final-linked",
      "publish-dir-fsync-before": "create-directory-sync",
      "publish-dir-fsync-after": "create-final-synced",
    }[point];
    if (legacyPoint !== undefined) injectedFault(legacyPoint, context.legacyFaultPath);
  }
  if (context.dependencies.faultPoint !== point) return;
  if (context.dependencies.faultAction === "crash") process.kill(process.pid, "SIGKILL");
  if (context.dependencies.faultAction === "throw") {
    refuse(`INJECTED_${context.dependencies.faultCode}`);
  }
}

function immutablePublishSystemFault(context, point) {
  if (context.dependencies.faultAction !== "system-error"
      || context.dependencies.faultPoint !== point) return;
  const error = new Error("bounded immutable publication system fault");
  error.code = context.dependencies.faultCode;
  throw error;
}

function immutablePublishRefuse(context, code, legacyCode, cause = null) {
  refuse(context.legacyFaultPath === null ? code : legacyCode, cause);
}

function immutablePublishFileSync(fd, context, phase) {
  immutablePublishPhase(context, `${phase}-file-fsync-before`);
  syncFileDescriptor(fd);
  IMMUTABLE_PUBLISH_FILE_SYNCS++;
  immutablePublishPhase(context, `${phase}-file-fsync-after`);
}

function assertImmutableDirectoryIdentity(path, expected, context) {
  const observed = optionalStat(path);
  if (observed === null) refuse("DIRECTORY_MISSING");
  assertDirectory(observed, { mode: context.directoryMode, uid: context.expectedUid });
  if (!sameIdentity(expected, observed)) refuse("DIRECTORY_IDENTITY_CHANGED");
  return observed;
}

function immutablePublishDirectorySync(path, context, phase) {
  const expected = path === context.candidateDirectory
    ? context.candidateDirectoryStat
    : context.destinationDirectoryStat;
  assertImmutableDirectoryIdentity(path, expected, context);
  immutablePublishPhase(context, `${phase}-dir-fsync-before`);
  syncDirectory(path);
  IMMUTABLE_PUBLISH_DIRECTORY_SYNCS++;
  immutablePublishPhase(context, `${phase}-dir-fsync-after`);
  assertImmutableDirectoryIdentity(path, expected, context);
}

function immutablePublishFullWrite(fd, bytes, context) {
  let offset = 0;
  let iterations = 0;
  while (offset < bytes.length) {
    if (++iterations > bytes.length) refuse("SHORT_WRITE");
    const remaining = bytes.length - offset;
    const requested = context.dependencies.writeChunkBytes === null
      ? remaining
      : Math.min(remaining, context.dependencies.writeChunkBytes);
    let written;
    try {
      immutablePublishSystemFault(context, "candidate-write-operation");
      written = context.dependencies.faultPoint === "pending-write"
          && context.dependencies.faultAction === "zero-write"
        ? 0
        : writeSync(fd, bytes, offset, requested, offset);
    } catch (error) {
      if (error?.code === "ENOSPC") refuse("CANDIDATE_WRITE_ENOSPC", error);
      refuse("CANDIDATE_WRITE_FAILED", error);
    }
    if (!Number.isSafeInteger(written) || written <= 0 || written > requested) refuse("SHORT_WRITE");
    offset += written;
    immutablePublishPhase(context, "partial-write");
  }
  if (offset !== bytes.length) refuse("SHORT_WRITE");
}

function immutablePublishReadCandidate(context, fd, opened, path, bytes, mode, expectedUid) {
  const held = pathBytesFromDescriptor(fd, opened, path, {
    mode,
    expectedUid,
    allowLinks: 1,
  });
  if (held.bytes.length !== bytes.length || !timingSafeEqual(held.bytes, bytes)) {
    immutablePublishRefuse(context, "CANDIDATE_READBACK_FAILED", "FILE_BYTES_CHANGED");
  }
  IMMUTABLE_PUBLISH_PENDING_READBACKS++;
  return held;
}

function immutablePublishResult(context, status, code = null) {
  let candidateResidue = null;
  let destinationExists = null;
  let inspectionCode = null;
  if (context.publishDirectToFinal) {
    candidateResidue = false;
  } else {
    try { candidateResidue = optionalStat(context.candidatePath) !== null; } catch (error) {
      inspectionCode = error instanceof BoundaryCustodyError ? error.code : "PATH_INSPECTION_FAILED";
    }
  }
  try { destinationExists = optionalStat(context.destinationPath) !== null; } catch (error) {
    inspectionCode ??= error instanceof BoundaryCustodyError ? error.code : "PATH_INSPECTION_FAILED";
  }
  const persistence = context.finalDurable && context.finalVerified
    ? "PERSISTED"
    : (context.finalLinked || context.finalVerified ? "INDETERMINATE" : "NOT_PERSISTED");
  // A direct-final failure can leave the authoritative O_EXCL name partially written. It is not a
  // candidate alias, but it is still manual-cleanup residue; this primitive never deletes it.
  const cleanupResidue = context.publishDirectToFinal
    ? status === "INDETERMINATE" && (context.finalLinked || destinationExists !== false)
    : candidateResidue !== false || context.existingFinalHasAliases;
  return Object.freeze({
    candidateResidue,
    cleanupResidue,
    code: inspectionCode ?? code,
    destinationExists,
    persistence,
    phaseTrace: context.dependencies.trace ? Object.freeze([...context.phases]) : null,
    status: inspectionCode === null ? status : "INDETERMINATE",
  });
}

function readImmutableFinalWithSettlement(reader) {
  let lastError = null;
  for (let attempt = 0; attempt < 16; attempt++) {
    try {
      return reader();
    } catch (error) {
      if (!(error instanceof BoundaryCustodyError)
          || !["FILE_IDENTITY_CHANGED", "FILE_LINK_COUNT_REJECTED", "FILE_MISSING", "FILE_READ_CHANGED"].includes(error.code)) {
        throw error;
      }
      lastError = error;
      Atomics.wait(CUSTODY_TEST_WAIT, 0, 0, 1);
    }
  }
  throw lastError;
}

function readImmutableFinal(context, allowedLinks) {
  return readImmutableFinalWithSettlement(() => readStableOwnerOnlyFile({
    path: context.destinationPath,
    expectedBytes: context.bytes,
    exactBytes: context.bytes.length,
    maxBytes: context.maxBytes,
    allowedModes: [context.immutableMode],
    allowedLinks,
    expectedUid: context.expectedUid,
  }));
}

function readImmutableExistingFinal(context) {
  return readImmutableFinalWithSettlement(() => readStableOwnerOnlyFile({
    path: context.destinationPath,
    maxBytes: context.existingFinalMaxBytes,
    allowedModes: [context.immutableMode],
    allowedLinks: context.existingFinalLinks,
    expectedUid: context.expectedUid,
  }));
}

function syncImmutableExistingFinal(context) {
  const before = readImmutableExistingFinal(context);
  if (before.stat.nlink > 1) context.existingFinalHasAliases = true;
  const exactBefore = before.bytes.length === context.bytes.length
    && timingSafeEqual(before.bytes, context.bytes);
  if (exactBefore) context.finalVerified = true;
  let fd;
  try {
    immutablePublishSystemFault(context, "existing-final-open-operation");
    fd = openSync(
      context.destinationPath,
      fsConstants.O_RDONLY | requiredFlag("O_NOFOLLOW") | requiredFlag("O_NONBLOCK"),
    );
    immutablePublishSystemFault(context, "existing-final-fstat-operation");
    const opened = fstatSync(fd);
    assertOwnerOnlyRegular(opened, {
      allowedLinks: context.existingFinalLinks,
      allowedModes: [context.immutableMode],
      expectedUid: context.expectedUid,
    });
    if (!sameIdentity(before.stat, opened)) refuse("FILE_IDENTITY_CHANGED");
    immutablePublishSystemFault(context, "existing-final-fsync-operation");
    immutablePublishFileSync(fd, context, "existing-final");
    immutablePublishSystemFault(context, "existing-final-close-operation");
    closeSync(fd);
    fd = undefined;
    immutablePublishPhase(context, "close");
    immutablePublishDirectorySync(context.destinationDirectory, context, "existing-final");
    immutablePublishPhase(context, "existing-final-closing-read-before");
    const after = readImmutableExistingFinal(context);
    if (!sameIdentity(before.stat, after.stat)
        || before.bytes.length !== after.bytes.length
        || !timingSafeEqual(before.bytes, after.bytes)) refuse("FILE_READ_CHANGED");
    if (exactBefore) context.finalDurable = true;
    immutablePublishPhase(context, "existing-final-closing-read-after");
    return after;
  } catch (error) {
    if (error instanceof BoundaryCustodyError) throw error;
    refuse("FILE_SYNC_FAILED", error);
  } finally {
    if (fd !== undefined) try { closeSync(fd); } catch { /* bounded result reports the earlier failure */ }
  }
}

function publishImmutableByLinkInternal({
  candidatePath,
  destinationPath,
  bytes,
  candidateMode = DEFAULT_FILE_MODE,
  immutableMode = DEFAULT_FILE_MODE,
  directoryMode = DEFAULT_DIRECTORY_MODE,
  expectedUid = currentUid(),
  maxBytes = DEFAULT_MAX_STABLE_READ_BYTES,
  existingFinalMaxBytes = maxBytes,
  existingFinalLinks = [1, 2],
  retainCandidateOnConflict = true,
  syncCandidateDirectoryBeforeLink = false,
}, testDependencies, legacyFaultPath = null, publishDirectToFinal = false) {
  let input;
  try { input = Buffer.from(bytes); } catch (error) { refuse("IMMUTABLE_PUBLISH_POLICY_REJECTED", error); }
  const finalLinks = exactPositiveIntegerArray(
    existingFinalLinks,
    8,
    "IMMUTABLE_PUBLISH_POLICY_REJECTED",
  );
  if (typeof candidatePath !== "string" || candidatePath.length === 0
      || typeof destinationPath !== "string" || destinationPath.length === 0
      || (!publishDirectToFinal && resolve(candidatePath) === resolve(destinationPath))
      || input.length === 0 || !Number.isSafeInteger(maxBytes) || maxBytes <= 0
      || maxBytes > DEFAULT_MAX_STABLE_READ_BYTES || input.length > maxBytes
      || !Number.isSafeInteger(existingFinalMaxBytes) || existingFinalMaxBytes < input.length
      || existingFinalMaxBytes > DEFAULT_MAX_STABLE_READ_BYTES
      || !Number.isSafeInteger(candidateMode) || !Number.isSafeInteger(immutableMode)
      || !Number.isSafeInteger(directoryMode)
      || candidateMode <= 0 || immutableMode <= 0 || directoryMode <= 0
      || candidateMode > 0o7777 || immutableMode > 0o7777 || directoryMode > 0o7777
      || (candidateMode & 0o077) !== 0 || (immutableMode & 0o077) !== 0
      || (directoryMode & 0o077) !== 0 || (immutableMode & 0o400) === 0
      || (expectedUid !== null && (!Number.isSafeInteger(expectedUid) || expectedUid < 0))
      || typeof retainCandidateOnConflict !== "boolean"
      || typeof syncCandidateDirectoryBeforeLink !== "boolean"
      || (!publishDirectToFinal && !retainCandidateOnConflict)) {
    refuse("IMMUTABLE_PUBLISH_POLICY_REJECTED");
  }
  const dependencies = immutablePublishDependencies(testDependencies);
  const context = {
    bytes: input,
    candidateDirectory: dirname(candidatePath),
    candidateDirectoryStat: null,
    candidatePath,
    dependencies,
    destinationDirectory: dirname(destinationPath),
    destinationDirectoryStat: null,
    destinationPath,
    directoryMode,
    existingFinalMaxBytes,
    existingFinalHasAliases: false,
    existingFinalLinks: finalLinks,
    expectedUid,
    finalDurable: false,
    finalLinked: false,
    finalVerified: false,
    immutableMode,
    legacyFaultPath,
    maxBytes,
    phases: [],
    publishDirectToFinal,
    syncCandidateDirectoryBeforeLink,
  };
  const candidateDirectoryStat = optionalStat(context.candidateDirectory);
  const destinationDirectoryStat = optionalStat(context.destinationDirectory);
  if (candidateDirectoryStat === null || destinationDirectoryStat === null) refuse("DIRECTORY_MISSING");
  assertDirectory(candidateDirectoryStat, { mode: directoryMode, uid: expectedUid });
  assertDirectory(destinationDirectoryStat, { mode: directoryMode, uid: expectedUid });
  context.candidateDirectoryStat = candidateDirectoryStat;
  context.destinationDirectoryStat = destinationDirectoryStat;

  let fd;
  try {
    if (optionalStat(destinationPath) !== null) {
      const existing = syncImmutableExistingFinal(context);
      if (existing.bytes.length !== input.length || !timingSafeEqual(existing.bytes, input)) {
        refuse("FILE_ALREADY_EXISTS");
      }
      return immutablePublishResult(context, "EXISTING");
    }
    immutablePublishPhase(context, "pending-create-before");
    if (publishDirectToFinal) immutablePublishPhase(context, "final-link-before");
    const creationPath = publishDirectToFinal ? destinationPath : candidatePath;
    try {
      immutablePublishSystemFault(context, "candidate-create-operation");
      fd = openSync(
        creationPath,
        fsConstants.O_RDWR | fsConstants.O_CREAT | fsConstants.O_EXCL | requiredFlag("O_NOFOLLOW"),
        candidateMode,
      );
      if (publishDirectToFinal) {
        context.finalLinked = true;
        immutablePublishPhase(context, "final-link-after");
      }
    } catch (error) {
      if (error?.code === "EEXIST" && publishDirectToFinal) {
        const existing = syncImmutableExistingFinal(context);
        if (existing.bytes.length !== input.length || !timingSafeEqual(existing.bytes, input)) {
          refuse("FILE_ALREADY_EXISTS");
        }
        return immutablePublishResult(context, "EXISTING");
      }
      if (error?.code === "EEXIST") refuse("CANDIDATE_NAME_COLLISION", error);
      if (error?.code === "ENOSPC") refuse("CANDIDATE_CREATE_ENOSPC", error);
      refuse("CANDIDATE_CREATE_FAILED", error);
    }
    const opened = fstatSync(fd);
    assertRegular(opened, { mode: candidateMode, uid: expectedUid });
    immutablePublishPhase(context, "pending-create-after");
    immutablePublishPhase(context, "pending-write-before");
    if (legacyFaultPath !== null) injectedPartialWrite(fd, input, legacyFaultPath);
    immutablePublishFullWrite(fd, input, context);
    immutablePublishPhase(context, "pending-write-after");
    immutablePublishFileSync(fd, context, "content");
    if (syncCandidateDirectoryBeforeLink) {
      immutablePublishDirectorySync(context.candidateDirectory, context, "candidate");
    }
    immutablePublishPhase(context, "pending-readback-before");
    immutablePublishReadCandidate(
      context, fd, fstatSync(fd), creationPath, input, candidateMode, expectedUid,
    );
    immutablePublishPhase(context, "pending-readback-after");
    if (candidateMode !== immutableMode) {
      immutablePublishPhase(context, "readonly-chmod-before");
      try { fchmodSync(fd, immutableMode); } catch (error) { refuse("FILE_MODE_CHANGE_FAILED", error); }
      immutablePublishPhase(context, "readonly-chmod-after");
      immutablePublishFileSync(fd, context, "readonly");
    }
    const immutableCandidate = fstatSync(fd);
    assertRegular(immutableCandidate, { mode: immutableMode, uid: expectedUid });
    if (!sameIdentity(opened, immutableCandidate) || immutableCandidate.size !== input.length) {
      immutablePublishRefuse(context, "CANDIDATE_IDENTITY_CHANGED", "FILE_WRITE_CHANGED");
    }
    const exactCandidate = readStableOwnerOnlyFile({
      path: creationPath,
      expectedBytes: input,
      exactBytes: input.length,
      maxBytes,
      allowedModes: [immutableMode],
      allowedLinks: [1],
      expectedUid,
    });
    if (!sameIdentity(immutableCandidate, exactCandidate.stat)) {
      immutablePublishRefuse(context, "CANDIDATE_IDENTITY_CHANGED", "STAGE_CHANGED");
    }

    if (!publishDirectToFinal) {
      immutablePublishPhase(context, "final-link-before");
      assertImmutableDirectoryIdentity(context.candidateDirectory, context.candidateDirectoryStat, context);
      assertImmutableDirectoryIdentity(context.destinationDirectory, context.destinationDirectoryStat, context);
      try {
        immutablePublishSystemFault(context, "final-link-operation");
        linkSync(candidatePath, destinationPath);
        context.finalLinked = true;
      } catch (error) {
        if (error?.code !== "EEXIST") refuse("FINAL_LINK_FAILED", error);
        let winner;
        try {
          winner = syncImmutableExistingFinal(context);
        } catch (winnerError) {
          // The candidate crossed both its content and namespace barriers. Until the competing final
          // is proven exact and durable, losing that known-durable copy would make recovery weaker.
          throw winnerError;
        }
        if (winner.bytes.length !== input.length || !timingSafeEqual(winner.bytes, input)) {
          refuse("FILE_ALREADY_EXISTS");
        }
        closeSync(fd);
        fd = undefined;
        immutablePublishPhase(context, "close");
        return immutablePublishResult(context, "EXISTING");
      }
      immutablePublishPhase(context, "final-link-after");
    }
    immutablePublishDirectorySync(context.destinationDirectory, context, "publish");
    context.finalDurable = true;
    if (publishDirectToFinal) {
      closeSync(fd);
      fd = undefined;
      immutablePublishPhase(context, "close");
      const final = readImmutableFinal(context, [1]);
      if (!sameIdentity(immutableCandidate, final.stat)) refuse("FILE_IDENTITY_CHANGED");
      context.finalVerified = true;
      return immutablePublishResult(context, "CREATED");
    }
    const candidateLinked = readStableOwnerOnlyFile({
      path: candidatePath,
      expectedBytes: input,
      exactBytes: input.length,
      maxBytes,
      allowedModes: [immutableMode],
      allowedLinks: [2],
      expectedUid,
    });
    const finalLinked = readImmutableFinal(context, [2]);
    if (!sameIdentity(immutableCandidate, candidateLinked.stat)
        || !sameIdentity(candidateLinked.stat, finalLinked.stat)) refuse("FILE_LINK_IDENTITY_CHANGED");
    context.finalVerified = true;
    // Node exposes no inode-conditional unlink. The verified hard-link candidate therefore remains
    // as an explicit quarantine alias; later pathname revalidation cannot make deletion safe from
    // a same-UID replacement between validation and unlink.
    immutablePublishPhase(context, "candidate-retained-before-return");
    const final = readImmutableFinal(context, [2]);
    if (!sameIdentity(immutableCandidate, final.stat)) refuse("FILE_IDENTITY_CHANGED");
    closeSync(fd);
    fd = undefined;
    immutablePublishPhase(context, "close");
    return immutablePublishResult(context, "CREATED");
  } catch (error) {
    const code = error instanceof BoundaryCustodyError ? error.code : "UNEXPECTED";
    return immutablePublishResult(context, "INDETERMINATE", code);
  } finally {
    if (fd !== undefined) try { closeSync(fd); } catch { /* returned state remains conservative */ }
  }
}

/**
 * Sole O_EXCL/full-write/readback/fsync publication transaction for immutable local evidence.
 * Link publication retains its verified candidate as a quarantine alias; direct-final publication
 * creates no candidate. Operational failures are conservative structural state; invalid policy throws.
 */
export function durablePublishImmutableByLink(options, testDependencies = null) {
  return publishImmutableByLinkInternal(options, testDependencies, null);
}

/** Create, synchronize, and verify one final O_EXCL name without automatic pathname deletion. */
export function durableCreateExclusive({
  path,
  bytes,
  mode = DEFAULT_FILE_MODE,
  expectedUid = currentUid(),
}, testDependencies = null) {
  const input = Buffer.from(bytes);
  if (input.length === 0) refuse("EMPTY_FILE_REJECTED");
  recoverDurableCreateForPath({
    path,
    mode,
    expectedUid,
  });
  if (optionalStat(path) !== null) {
    try {
      readOwnerOnlyFile({ path, expectedBytes: input, mode, expectedUid });
    } catch (error) {
      if (error instanceof BoundaryCustodyError
          && ["FILE_EXACT_SIZE_REJECTED", "FILE_SIZE_LIMIT_REJECTED"].includes(error.code)) {
        refuse("FILE_BYTES_CHANGED", error);
      }
      throw error;
    }
    // A direct-final writer can stop after the last byte but before either durability barrier.
    // Exact visible bytes therefore become reusable only after this retry establishes both barriers.
    durableSyncExact({ path, expectedBytes: input, mode, expectedUid });
    return readOwnerOnlyFile({ path, expectedBytes: input, mode, expectedUid });
  }
  const result = publishImmutableByLinkInternal({
    candidatePath: path,
    destinationPath: path,
    bytes: input,
    candidateMode: mode,
    immutableMode: mode,
    directoryMode: DEFAULT_DIRECTORY_MODE,
    expectedUid,
    maxBytes: input.length,
    existingFinalMaxBytes: DEFAULT_MAX_STABLE_READ_BYTES,
    existingFinalLinks: [1],
    retainCandidateOnConflict: false,
    syncCandidateDirectoryBeforeLink: false,
  }, testDependencies, path, true);
  if (result.status === "INDETERMINATE") {
    const compatibilityCode = {
      CANDIDATE_CREATE_ENOSPC: "FILE_CREATE_FAILED",
      CANDIDATE_CREATE_FAILED: "FILE_CREATE_FAILED",
      CANDIDATE_IDENTITY_CHANGED: "STAGE_CHANGED",
      CANDIDATE_READBACK_FAILED: "FILE_BYTES_CHANGED",
      CANDIDATE_WRITE_ENOSPC: "FILE_CREATE_FAILED",
      CANDIDATE_WRITE_FAILED: "FILE_CREATE_FAILED",
      UNEXPECTED: "FILE_CREATE_FAILED",
    }[result.code] ?? result.code ?? "FILE_CREATE_FAILED";
    refuse(compatibilityCode);
  }
  durableSyncExact({ path, expectedBytes: input, mode, expectedUid });
  return readOwnerOnlyFile({ path, expectedBytes: input, mode, expectedUid });
}

/** Re-establish file and namespace barriers for exact existing evidence before it authorizes delete. */
export function durableSyncExact({
  path,
  expectedBytes,
  mode = DEFAULT_FILE_MODE,
  expectedUid = currentUid(),
  allowLinks = 1,
}) {
  const expected = Buffer.from(expectedBytes);
  const before = readOwnerOnlyFile({ path, expectedBytes: expected, mode, expectedUid, allowLinks });
  let fd;
  try {
    fd = openSync(path, fsConstants.O_RDWR | requiredFlag("O_NOFOLLOW"));
    const opened = fstatSync(fd);
    assertRegular(opened, { mode, uid: expectedUid, allowLinks });
    if (!sameIdentity(before.stat, opened) || opened.size !== expected.length) refuse("FILE_IDENTITY_CHANGED");
    injectedFault("existing-file-sync", path);
    syncFileDescriptor(fd);
    closeSync(fd);
    fd = undefined;
    injectedFault("existing-directory-sync", path);
    syncDirectory(dirname(path));
    return readOwnerOnlyFile({ path, expectedBytes: expected, mode, expectedUid, allowLinks });
  } catch (error) {
    if (error instanceof BoundaryCustodyError) throw error;
    refuse("FILE_SYNC_FAILED", error);
  } finally {
    if (fd !== undefined) try { closeSync(fd); } catch { /* one bounded failure reaches caller */ }
  }
  return null;
}

/**
 * Atomically replace one already-authenticated destination from an exact, durable candidate in an
 * externally isolated pathname namespace. The caller must retain a durable predecessor; Node
 * stdlib cannot make the final pathname rename conditional on the held candidate/destination fds.
 */
export function durableReplaceFromCandidate({
  candidatePath,
  destinationPath,
  candidateBytes,
  expectedDestinationBytes,
  mode = DEFAULT_FILE_MODE,
  expectedUid = currentUid(),
}) {
  const candidate = Buffer.from(candidateBytes);
  const destination = Buffer.from(expectedDestinationBytes);
  let candidateFd;
  let destinationFd;
  try {
    const candidateBefore = readOwnerOnlyFile({ path: candidatePath, expectedBytes: candidate, mode, expectedUid });
    const destinationBefore = readOwnerOnlyFile({ path: destinationPath, expectedBytes: destination, mode, expectedUid });
    candidateFd = openSync(candidatePath, fsConstants.O_RDWR | requiredFlag("O_NOFOLLOW"));
    destinationFd = openSync(destinationPath, fsConstants.O_RDONLY | requiredFlag("O_NOFOLLOW"));
    const candidateOpened = fstatSync(candidateFd);
    const destinationOpened = fstatSync(destinationFd);
    assertRegular(candidateOpened, { mode, uid: expectedUid });
    assertRegular(destinationOpened, { mode, uid: expectedUid });
    if (!sameIdentity(candidateBefore.stat, candidateOpened)
        || !sameIdentity(destinationBefore.stat, destinationOpened)) refuse("FILE_IDENTITY_CHANGED");
    syncFileDescriptor(candidateFd);
    const candidateAtRename = lstatSync(candidatePath);
    const destinationAtRename = lstatSync(destinationPath);
    if (!sameIdentity(candidateOpened, candidateAtRename)
        || !sameIdentity(destinationOpened, destinationAtRename)) refuse("FILE_IDENTITY_CHANGED");
    injectedFault("replace-rename", candidatePath);
    try { renameSync(candidatePath, destinationPath); } catch (error) { refuse("FILE_RENAME_FAILED", error); }
    injectedFault("replace-directory-sync", destinationPath);
    syncDirectory(dirname(destinationPath));
    if (dirname(candidatePath) !== dirname(destinationPath)) syncDirectory(dirname(candidatePath));
    if (optionalStat(candidatePath) !== null) refuse("RENAME_SOURCE_REMAINS");
    const destinationAfter = lstatSync(destinationPath);
    const candidateAfter = fstatSync(candidateFd);
    if (!sameIdentity(candidateOpened, candidateAfter) || !sameIdentity(candidateAfter, destinationAfter)) {
      refuse("FILE_IDENTITY_CHANGED");
    }
    return readOwnerOnlyFile({ path: destinationPath, expectedBytes: candidate, mode, expectedUid });
  } catch (error) {
    if (error instanceof BoundaryCustodyError) throw error;
    refuse("FILE_RENAME_FAILED", error);
  } finally {
    if (candidateFd !== undefined) try { closeSync(candidateFd); } catch { /* bounded verdict already selected */ }
    if (destinationFd !== undefined) try { closeSync(destinationFd); } catch { /* old destination inode */ }
  }
  return null;
}

/** Atomically elect one stale-file claimant by hard-linking the exact source inode. */
export function durableClaimExactByLink({
  sourcePath,
  claimPath,
  expectedBytes,
  mode = DEFAULT_FILE_MODE,
  expectedUid = currentUid(),
  beforeLink = null,
}) {
  const expected = Buffer.from(expectedBytes);
  let fd;
  let linked = false;
  try {
    const before = optionalStat(sourcePath);
    if (before === null) refuse("FILE_MISSING");
    assertRegular(before, { mode, uid: expectedUid, allowLinks: 1 });
    fd = openSync(sourcePath, fsConstants.O_RDONLY | requiredFlag("O_NOFOLLOW"));
    const opened = fstatSync(fd);
    assertRegular(opened, { mode, uid: expectedUid, allowLinks: 1 });
    if (!sameIdentity(before, opened)) refuse("FILE_IDENTITY_CHANGED");
    const measured = pathBytesFromDescriptor(fd, opened, sourcePath, {
      mode,
      expectedUid,
      allowLinks: 1,
    });
    if (measured.bytes.length !== expected.length || !timingSafeEqual(measured.bytes, expected)) {
      refuse("FILE_BYTES_CHANGED");
    }
    if (beforeLink !== null) {
      if (typeof beforeLink !== "function") refuse("FILE_CLAIM_CALLBACK_REJECTED");
      beforeLink();
    }
    try { linkSync(sourcePath, claimPath); } catch (error) {
      if (error?.code === "EEXIST") return { claimed: false };
      refuse("FILE_CLAIM_LINK_FAILED", error);
    }
    linked = true;
    syncDirectory(dirname(sourcePath));
    const openedAfterLink = fstatSync(fd);
    const sourceClaimed = readOwnerOnlyFile({ path: sourcePath, mode, expectedUid, allowLinks: 2 });
    const claim = readOwnerOnlyFile({ path: claimPath, mode, expectedUid, allowLinks: 2 });
    const exact = sameIdentity(opened, openedAfterLink)
      && sameIdentity(openedAfterLink, sourceClaimed.stat)
      && sameIdentity(sourceClaimed.stat, claim.stat)
      && sourceClaimed.bytes.length === expected.length
      && timingSafeEqual(sourceClaimed.bytes, expected)
      && claim.bytes.length === expected.length
      && timingSafeEqual(claim.bytes, expected);
    if (!exact) {
      durableUnlinkExact({
        path: claimPath,
        expectedBytes: claim.bytes,
        mode,
        expectedUid,
        allowLinks: 2,
      });
      linked = false;
      refuse("FILE_CLAIM_SOURCE_CHANGED");
    }
    return { claimed: true, source: sourceClaimed, claim };
  } catch (error) {
    if (linked) {
      try {
        const claimStat = optionalStat(claimPath);
        if (claimStat !== null && (claimStat.nlink === 1 || claimStat.nlink === 2)) {
          const claim = readOwnerOnlyFile({ path: claimPath, mode, expectedUid, allowLinks: claimStat.nlink });
          durableUnlinkExact({
            path: claimPath,
            expectedBytes: claim.bytes,
            mode,
            expectedUid,
            allowLinks: claimStat.nlink,
          });
        }
      } catch (cleanupError) {
        refuse("FILE_CLAIM_ROLLBACK_FAILED", cleanupError);
      }
    }
    if (error instanceof BoundaryCustodyError) throw error;
    refuse("FILE_CLAIM_LINK_FAILED", error);
  } finally {
    if (fd !== undefined) try { closeSync(fd); } catch { /* claim identity verdict already selected */ }
  }
  return null;
}

/**
 * Remove a claimed source under an externally isolated pathname namespace. This cannot provide an
 * inode-conditional-unlink guarantee against hostile same-UID replacement through Node stdlib.
 */
export function durableUnlinkClaimedSource({
  sourcePath,
  claimPath,
  expectedBytes,
  mode = DEFAULT_FILE_MODE,
  expectedUid = currentUid(),
}) {
  const expected = Buffer.from(expectedBytes);
  let claimFd;
  try {
    const source = readOwnerOnlyFile({
      path: sourcePath,
      expectedBytes: expected,
      mode,
      expectedUid,
      allowLinks: 2,
    });
    const claimBefore = optionalStat(claimPath);
    if (claimBefore === null) refuse("FILE_CLAIM_MISSING");
    assertRegular(claimBefore, { mode, uid: expectedUid, allowLinks: 2 });
    claimFd = openSync(claimPath, fsConstants.O_RDONLY | requiredFlag("O_NOFOLLOW"));
    const claimOpened = fstatSync(claimFd);
    assertRegular(claimOpened, { mode, uid: expectedUid, allowLinks: 2 });
    if (!sameIdentity(source.stat, claimBefore) || !sameIdentity(claimBefore, claimOpened)) {
      refuse("FILE_CLAIM_IDENTITY_CHANGED");
    }
    const heldClaim = pathBytesFromDescriptor(claimFd, claimOpened, claimPath, {
      mode,
      expectedUid,
      allowLinks: 2,
    });
    if (heldClaim.bytes.length !== expected.length || !timingSafeEqual(heldClaim.bytes, expected)) {
      refuse("FILE_BYTES_CHANGED");
    }
    const sourceImmediatelyBefore = readOwnerOnlyFile({
      path: sourcePath,
      expectedBytes: expected,
      mode,
      expectedUid,
      allowLinks: 2,
    });
    if (!sameIdentity(claimOpened, sourceImmediatelyBefore.stat)) refuse("FILE_CLAIM_IDENTITY_CHANGED");
    durableUnlinkExact({ path: sourcePath, expectedBytes: expected, mode, expectedUid, allowLinks: 2 });
    const retainedOpened = fstatSync(claimFd);
    assertRegular(retainedOpened, { mode, uid: expectedUid, allowLinks: 1 });
    if (!sameIdentity(claimOpened, retainedOpened)) refuse("FILE_CLAIM_IDENTITY_CHANGED");
    const retained = pathBytesFromDescriptor(claimFd, retainedOpened, claimPath, {
      mode,
      expectedUid,
      allowLinks: 1,
    });
    if (retained.bytes.length !== expected.length || !timingSafeEqual(retained.bytes, expected)) {
      refuse("FILE_BYTES_CHANGED");
    }
    return retained;
  } catch (error) {
    if (error instanceof BoundaryCustodyError) throw error;
    refuse("FILE_CLAIM_UNLINK_FAILED", error);
  } finally {
    if (claimFd !== undefined) try { closeSync(claimFd); } catch { /* retained claim verdict already decided */ }
  }
}

/**
 * Remove one exact file and synchronize the namespace change when the pathname namespace is
 * externally isolated. Validation followed by pathname unlink is not hostile-same-UID inode safe.
 */
export function durableUnlinkExact({
  path,
  expectedBytes,
  expectedIdentity = null,
  mode = DEFAULT_FILE_MODE,
  expectedUid = currentUid(),
  allowLinks = 1,
}) {
  const expected = Buffer.from(expectedBytes);
  let fd;
  try {
    const before = optionalStat(path);
    if (before === null) refuse("FILE_MISSING");
    assertRegular(before, { mode, uid: expectedUid, allowLinks });
    if (expectedIdentity !== null && !sameIdentity(before, expectedIdentity)) {
      refuse("FILE_IDENTITY_CHANGED");
    }
    fd = openSync(path, fsConstants.O_RDONLY | requiredFlag("O_NOFOLLOW"));
    const opened = fstatSync(fd);
    assertRegular(opened, { mode, uid: expectedUid, allowLinks });
    if (!sameIdentity(before, opened)) refuse("FILE_IDENTITY_CHANGED");
    const measured = pathBytesFromDescriptor(fd, opened, path, { mode, expectedUid, allowLinks });
    if (measured.bytes.length !== expected.length || !timingSafeEqual(measured.bytes, expected)) {
      refuse("FILE_BYTES_CHANGED");
    }
    const immediatelyBefore = lstatSync(path);
    assertRegular(immediatelyBefore, { mode, uid: expectedUid, allowLinks });
    if (!sameIdentity(opened, immediatelyBefore)) refuse("FILE_IDENTITY_CHANGED");
    injectedFault("unlink", path);
    try { unlinkSync(path); } catch (error) { refuse("FILE_UNLINK_FAILED", error); }
    const retained = fstatSync(fd);
    assertRegular(retained, { mode, uid: expectedUid, allowLinks: allowLinks - 1 });
    if (!sameIdentity(opened, retained) || retained.size !== expected.length) refuse("FILE_IDENTITY_CHANGED");
    injectedFault("unlink-directory-sync", path);
    syncDirectory(dirname(path));
    if (optionalStat(path) !== null) refuse("FILE_REMAINS_AFTER_UNLINK");
  } catch (error) {
    if (error instanceof BoundaryCustodyError) throw error;
    refuse("FILE_UNLINK_FAILED", error);
  } finally {
    if (fd !== undefined) try { closeSync(fd); } catch { /* unlinked inode custody already decided */ }
  }
}
