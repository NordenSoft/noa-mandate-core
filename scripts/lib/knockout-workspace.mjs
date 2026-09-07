import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync, spawn, spawnSync } from "node:child_process";
import { TextDecoder, types as utilTypes } from "node:util";
import {
  canonicalJson as canonicalJsonString,
  sha256Hex,
} from "./safe-npm-tarball.mjs";

/**
 * Isolated knockout-workspace materialization.
 *
 * This module is deliberately independent of the legacy in-place knockout runner. It observes a
 * live source without Git locks, seals the exact dirty state into a standalone private seed, and
 * materializes disposable arms. Importing this module has no side effects.
 */

export const KNOCKOUT_WORKSPACE_PROTOCOLS = Object.freeze({
  arm: "noa-knockout-workspace/arm/1",
  armPlan: "noa-knockout-workspace/arm-plan/1",
  cooperativeSourceLease: "noa-knockout-workspace/cooperative-source-lease/1",
  workerCapability: "noa-knockout-workspace/worker-capability/1",
  workerResult: "noa-knockout-workspace/worker-result/1",
  workerSubject: "noa-knockout-workspace/worker-subject/1",
  candidateManifest: "noa-knockout-workspace/candidate-manifest/14",
  state: "noa-knockout-workspace/state/6",
  capability: "noa-knockout-workspace/capability/6",
  retainedTargets: "noa-knockout-workspace/retained-targets/1",
  terminal: "noa-knockout-workspace/terminal/6",
});

export const LEGACY_TOMBSTONE_PROTOCOL = "noa-knockout-legacy-tombstone/1";
const LEGACY_TOMBSTONE_KEYS = Object.freeze([
  "migratedAt", "protocol", "root", "rootIdentity",
]);
const LEGACY_TOMBSTONE_KEYSET = JSON.stringify(LEGACY_TOMBSTONE_KEYS);
const ROOT_LOCAL_STATE_PATH = "node_modules/.cache/noa-knockout/lock.json";
const ROOT_LOCAL_STATE_DIRECTORY = path.posix.dirname(ROOT_LOCAL_STATE_PATH);
const ROOT_LOCAL_STATE_RUNS_DIRECTORY = `${ROOT_LOCAL_STATE_DIRECTORY}/runs`;
const ROOT_LOCAL_STATE_STAGING = /^\.lock\.json\.[0-9a-f]{32}\.tombstone-tmp$/;
const ROOT_LOCAL_STATE_PROJECTION_POLICY = "noa-knockout-root-local-state-projection/1";
const ROOT_LOCAL_STATE_PROJECTION_ACTION = "OMIT_FROM_PORTABLE_SEED";

/** Shared closed parser for the one permanent v3-to-v4 migration barrier record. */
export function isKnockoutLegacyTombstoneForRoot(record, expectedIdentity) {
  if (record === null || typeof record !== "object" || Array.isArray(record)) return false;
  if (JSON.stringify(Object.keys(record).sort()) !== LEGACY_TOMBSTONE_KEYSET) return false;
  if (
    record.protocol !== LEGACY_TOMBSTONE_PROTOCOL ||
    typeof record.root !== "string" || !path.isAbsolute(record.root) ||
    record.rootIdentity !== expectedIdentity ||
    typeof record.migratedAt !== "string"
  ) return false;
  try { return new Date(record.migratedAt).toISOString() === record.migratedAt; }
  catch { return false; }
}

function knockoutGuardRootIdentity(workspaceIdentity) {
  if (typeof workspaceIdentity !== "string" || !/^[0-9]+:[0-9]+$/.test(workspaceIdentity)) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.ROOT_LOCAL_STATE_UNSUPPORTED,
      "workspace identity cannot be projected into the knockout guard identity protocol",
    );
  }
  return `noa-directory/2:${workspaceIdentity}`;
}

/**
 * Persisted capture state is evidence, never authority. On a same-UID mutable filesystem no file
 * can outlive an attacker's replacement or a crash between durability and validation, so state.json
 * records that a capture was produced (status CAPTURED) and binds the bytes it certifies, while the
 * only authority is the same-process capability registered after full post-publication validation.
 * There is deliberately no API that reconstructs a capability from state, manifest or pathname.
 */
export const KNOCKOUT_WORKSPACE_CAPTURE_STATUS = "CAPTURED";
export const KNOCKOUT_WORKSPACE_STATE_EVIDENCE_ROLE = "NON_AUTHORITATIVE_CAPTURE_EVIDENCE";

/** Closed, stable machine error taxonomy. Callers must branch on `code`, never message text. */
export const KNOCKOUT_WORKSPACE_ERROR_CODES = Object.freeze({
  ACL_UNSUPPORTED: "ACL_UNSUPPORTED",
  // Reserved for Phase 2 arm/capability orchestration; Phase 1 has no producer for either code.
  ARM_IDENTITY_MISMATCH: "ARM_IDENTITY_MISMATCH",
  CAPABILITY_INVALID: "CAPABILITY_INVALID",
  COPY_INCOMPLETE: "COPY_INCOMPLETE",
  DESTINATION_EXISTS: "DESTINATION_EXISTS",
  DURABILITY_FAILED: "DURABILITY_FAILED",
  EXTERNAL_HARDLINK_UNSUPPORTED: "EXTERNAL_HARDLINK_UNSUPPORTED",
  GITLINK_UNSUPPORTED: "GITLINK_UNSUPPORTED",
  INVALID_ARGUMENT: "INVALID_ARGUMENT",
  MANIFEST_MISMATCH: "MANIFEST_MISMATCH",
  NESTED_GIT_REPOSITORY: "NESTED_GIT_REPOSITORY",
  PRIVATE_ROOT_UNSAFE: "PRIVATE_ROOT_UNSAFE",
  ROOT_LOCAL_STATE_UNSUPPORTED: "ROOT_LOCAL_STATE_UNSUPPORTED",
  OPERATION_DEADLINE_EXCEEDED: "OPERATION_DEADLINE_EXCEEDED",
  RESOURCE_LIMIT_EXCEEDED: "RESOURCE_LIMIT_EXCEEDED",
  SNAPSHOT_UNSTABLE: "SNAPSHOT_UNSTABLE",
  SOURCE_CHANGED: "SOURCE_CHANGED",
  SOURCE_GIT_LAYOUT_UNSUPPORTED: "SOURCE_GIT_LAYOUT_UNSUPPORTED",
  SOURCE_GIT_OBSERVATION_FAILED: "SOURCE_GIT_OBSERVATION_FAILED",
  SOURCE_INDEX_UNSUPPORTED: "SOURCE_INDEX_UNSUPPORTED",
  SOURCE_LEASE_HELD: "SOURCE_LEASE_HELD",
  SOURCE_LEASE_INDETERMINATE: "SOURCE_LEASE_INDETERMINATE",
  SOURCE_NOT_GIT_WORKTREE: "SOURCE_NOT_GIT_WORKTREE",
  SOURCE_OBJECT_MISSING: "SOURCE_OBJECT_MISSING",
  SPECIAL_NODE_UNSUPPORTED: "SPECIAL_NODE_UNSUPPORTED",
  STANDALONE_GIT_INVALID: "STANDALONE_GIT_INVALID",
  TERMINAL_EXISTS: "TERMINAL_EXISTS",
  TERMINAL_COMMIT_INDETERMINATE: "TERMINAL_COMMIT_INDETERMINATE",
  TERMINAL_HASH_MISMATCH: "TERMINAL_HASH_MISMATCH",
  TERMINAL_IDENTITY_MISMATCH: "TERMINAL_IDENTITY_MISMATCH",
  TERMINAL_INCOMPLETE: "TERMINAL_INCOMPLETE",
  UNSAFE_SYMLINK: "UNSAFE_SYMLINK",
  XATTR_UNSUPPORTED: "XATTR_UNSUPPORTED",
});

const ERROR_CODE_SET = new Set(Object.values(KNOCKOUT_WORKSPACE_ERROR_CODES));

export class KnockoutWorkspaceError extends Error {
  constructor(code, message, details = null, options = undefined) {
    if (!ERROR_CODE_SET.has(code)) throw new TypeError(`unknown knockout-workspace error code: ${code}`);
    super(message, options);
    this.name = "KnockoutWorkspaceError";
    this.code = code;
    this.details = details === null ? null : Object.freeze({ ...details });
  }
}

const MAX_CAPTURE_ATTEMPTS = 2;
const MAX_CHILD_PROCESS_DURATION_MS = 5 * 60 * 1000;
const MAX_ARM_WORKER_DURATION_MS = 20 * 60 * 1000;
const MAX_CAPTURE_OPERATION_DURATION_MS = 20 * 60 * 1000;
export const KNOCKOUT_WORKSPACE_COMMAND_TIMEOUT_LIMIT_MS =
  MAX_CHILD_PROCESS_DURATION_MS;
export const KNOCKOUT_WORKSPACE_ARM_WORKER_TIMEOUT_LIMIT_MS =
  MAX_ARM_WORKER_DURATION_MS;
export const KNOCKOUT_WORKSPACE_CAPTURE_TIMEOUT_LIMIT_MS =
  MAX_CAPTURE_OPERATION_DURATION_MS;
const MAX_GIT_DIRECTORY_ENTRIES = 4096;
const MAX_SHARED_INDEX_CANDIDATES = 128;
// Keep descriptor inheritance well below ordinary per-process limits. Metadata subprocess count
// is therefore bounded by the admitted node count divided by this fixed chunk size, while every
// node still receives its own descriptor-pinned xattr observation.
const MAC_METADATA_BATCH_NODE_LIMIT = 64;
// `--template=` makes the observation repository shape fixed apart from admitted split indexes.
// Every witnessed node consumes one simultaneously held descriptor, so keep that FD surface
// substantially below ordinary process limits instead of inheriting the generic 4096-node cap.
const GIT_OBSERVATION_SCRATCH_FIXED_FD_RESERVE = 32;
const MAX_TOOL_OUTPUT_BYTES = 64 * 1024 * 1024;
const MIB = 1024 * 1024;
const MAX_CANDIDATE_MANIFEST_BYTES = 64 * MIB;
const MAX_STATE_BYTES = 64 * 1024;
const MAX_TERMINAL_EVIDENCE_BYTES = MIB;
const WORKSPACE_COPY_BUFFER_BYTES = MIB;
const GIT_CONTROL_LOGICAL_RESERVE_BYTES = MIB;
const GIT_CONTROL_ALLOCATED_RESERVE_BYTES = 4 * MIB;
// One node for each possible loose-object fanout directory plus fixed refs/logs/config structure.
const GIT_CONTROL_NODE_RESERVE = 320;
const GIT_CONTROL_MAX_DEPTH = 8;
export const KNOCKOUT_WORKSPACE_CAPTURE_LIMITS = Object.freeze({
  maxAllocatedBytes: 512 * MIB,
  maxDepth: 64,
  maxFileBytes: 64 * MIB,
  maxNodes: 50_000,
  maxTotalBytes: 512 * MIB,
  minFreeBytes: 64 * MIB,
});
export const KNOCKOUT_WORKSPACE_ARM_ROLES = Object.freeze([
  "SELFTEST",
  "PLANNING",
  "BASELINE",
  "MUTANT",
  "POSTCHECK",
]);
export const KNOCKOUT_WORKSPACE_ARM_LIMITS = Object.freeze({
  maxRetainedArms: 512,
  maxRetainedBytes: 16 * 1024 * MIB,
});
const ARM_ID = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;
const ARM_EVIDENCE_RESERVE_BYTES = 4 * MIB;
const COOPERATIVE_SOURCE_LEASE_DEFAULT_HANDSHAKE_MS = 5_000;
const COOPERATIVE_SOURCE_LEASE_MAX_CONTROL_BYTES = 64 * 1024;
const MAX_WORKER_SUBJECT_METADATA_BYTES = 32 * 1024;
const MAX_WORKER_CAPABILITY_METADATA_BYTES = 64 * 1024;
const MAX_WORKER_RESULT_BYTES = 512 * 1024;
// POSTCHECK carries both previously admitted result wires. Their transport allowance must not
// consume the original metadata budgets or relax either individual result's fixed ceiling.
const MAX_WORKER_SUBJECT_BYTES = MAX_WORKER_SUBJECT_METADATA_BYTES + 2 * MAX_WORKER_RESULT_BYTES;
const MAX_WORKER_CAPABILITY_BYTES = MAX_WORKER_CAPABILITY_METADATA_BYTES + 2 * MAX_WORKER_RESULT_BYTES;
const MAX_WORKER_DIAGNOSTIC_BYTES = 512 * 1024;
export const KNOCKOUT_WORKER_RELATIVE_PATH = "scripts/lib/knockout-workspace-worker.mjs";
const ARM_WORKER_RELATIVE_PATH = KNOCKOUT_WORKER_RELATIVE_PATH;
export const KNOCKOUT_WORKER_OPERATIONS = Object.freeze({
  ATTEST_ARM: "ATTEST_ARM",
  OBSERVE_KNOCKOUT_BASELINE: "OBSERVE_KNOCKOUT_BASELINE",
  OBSERVE_KNOCKOUT_POSTCHECK: "OBSERVE_KNOCKOUT_POSTCHECK",
  RUN_KNOCKOUT: "RUN_KNOCKOUT",
  RUN_KNOCKOUT_SELFTEST: "RUN_KNOCKOUT_SELFTEST",
});
const KNOCKOUT_WORKER_OPERATION_ROLES = Object.freeze({
  [KNOCKOUT_WORKER_OPERATIONS.OBSERVE_KNOCKOUT_BASELINE]: "BASELINE",
  [KNOCKOUT_WORKER_OPERATIONS.OBSERVE_KNOCKOUT_POSTCHECK]: "POSTCHECK",
  [KNOCKOUT_WORKER_OPERATIONS.RUN_KNOCKOUT]: "MUTANT",
  [KNOCKOUT_WORKER_OPERATIONS.RUN_KNOCKOUT_SELFTEST]: "SELFTEST",
});
export const KNOCKOUT_SELFTEST_GATE = "knockout-selftest";
export const KNOCKOUT_SELFTEST_SUITE = Object.freeze([
  ".",
  "node",
  Object.freeze(["scripts/lint-control-knockout.selftest.mjs", "--knockout-json"]),
]);
const NOFOLLOW = fs.constants.O_NOFOLLOW ?? 0;
const DIRECTORY = fs.constants.O_DIRECTORY ?? 0;
const SYMLINK = fs.constants.O_SYMLINK ?? 0;
const METADATA_FCHDIR_LAUNCHER = "/usr/bin/perl";
const MAC_METADATA_HELPER = "/usr/bin/python3";
const METADATA_FCHDIR_SCRIPT = [
  "open(my $directory, q{<&=3}) or die q{metadata directory descriptor unavailable};",
  "chdir($directory) or die q{metadata directory cannot be entered};",
  "close($directory) or die q{metadata directory descriptor cannot be closed};",
  "exec {$ARGV[0]} @ARGV;",
  "die q{metadata tool exec failed};",
].join(" ");
// Darwin's ls(1) deliberately converts some listxattr(2) and ACL read failures into an empty
// display, while xattr(1)'s line-oriented output cannot frame arbitrary attribute names. Use the
// native descriptor APIs directly and return one bounded JSON value only after the whole batch is
// observed. `-I -S` at invocation ignores user configuration and skips site initialization.
const MAC_METADATA_HELPER_SCRIPT = String.raw`
import base64
import ctypes
import errno
import json
import os
import stat
import sys

EXIT_REFUSED = 70
ACL_TYPE_EXTENDED = 0x00000100
ACL_FIRST_ENTRY = 0
PROVENANCE = b"com.apple.provenance"

def refuse(stage, error_number=0):
    sys.stderr.write("mac metadata helper refused " + stage + " errno=" + str(error_number) + "\n")
    raise SystemExit(EXIT_REFUSED)

if sys.platform != "darwin" or len(sys.argv) != 5:
    refuse("arguments")

mode = sys.argv[1]
try:
    output_limit = int(sys.argv[2])
    raw_limit = int(sys.argv[3])
    descriptor_count = int(sys.argv[4])
except ValueError:
    refuse("arguments")
if mode not in ("acl", "xattr") or output_limit < 1 or raw_limit < 1 or not 1 <= descriptor_count <= 64:
    refuse("arguments")

libc = ctypes.CDLL(None, use_errno=True)
libc.flistxattr.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
libc.flistxattr.restype = ctypes.c_ssize_t
libc.fgetxattr.argtypes = [
    ctypes.c_int, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t,
    ctypes.c_uint32, ctypes.c_int,
]
libc.fgetxattr.restype = ctypes.c_ssize_t
libc.acl_get_fd_np.argtypes = [ctypes.c_int, ctypes.c_int]
libc.acl_get_fd_np.restype = ctypes.c_void_p
libc.acl_get_entry.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)]
libc.acl_get_entry.restype = ctypes.c_int
libc.acl_free.argtypes = [ctypes.c_void_p]
libc.acl_free.restype = ctypes.c_int

def stat_record(fd):
    try:
        observed = os.fstat(fd)
    except OSError as error:
        refuse("fstat", error.errno or 0)
    if stat.S_ISLNK(observed.st_mode):
        node_type = "symlink"
    elif stat.S_ISDIR(observed.st_mode):
        node_type = "directory"
    elif stat.S_ISREG(observed.st_mode):
        node_type = "file"
    else:
        node_type = "other"
    return {
        "ctimeNs": str(observed.st_ctime_ns),
        "identity": str(observed.st_dev) + ":" + str(observed.st_ino),
        "mode": observed.st_mode & 0o7777,
        "mtimeNs": str(observed.st_mtime_ns),
        "nlink": observed.st_nlink,
        "size": observed.st_size,
        "type": node_type,
        "uid": observed.st_uid,
    }

raw_used = 0
def reserve_raw(size):
    global raw_used
    if size < 0 or size > raw_limit - raw_used:
        refuse("resource_limit")
    raw_used += size

def list_xattrs(fd, reserve):
    ctypes.set_errno(0)
    needed = libc.flistxattr(fd, None, 0, 0)
    if needed < 0:
        refuse("flistxattr_size", ctypes.get_errno())
    if needed > raw_limit:
        refuse("resource_limit")
    if reserve:
        reserve_raw(needed)
    if needed == 0:
        ctypes.set_errno(0)
        confirmed = libc.flistxattr(fd, None, 0, 0)
        if confirmed != 0:
            refuse("flistxattr_empty", ctypes.get_errno())
        return b""
    value = ctypes.create_string_buffer(needed)
    ctypes.set_errno(0)
    observed = libc.flistxattr(fd, value, needed, 0)
    if observed != needed:
        refuse("flistxattr_value", ctypes.get_errno())
    return bytes(value.raw[:observed])

def split_xattr_names(raw):
    if raw == b"":
        return []
    if not raw.endswith(b"\0"):
        refuse("xattr_name_framing")
    names = raw[:-1].split(b"\0")
    if any(name == b"" for name in names):
        refuse("xattr_name_framing")
    return names

def read_xattr(fd, name, reserve):
    ctypes.set_errno(0)
    needed = libc.fgetxattr(fd, name, None, 0, 0, 0)
    if needed < 0:
        refuse("fgetxattr_size", ctypes.get_errno())
    if needed > raw_limit:
        refuse("resource_limit")
    if reserve:
        reserve_raw(needed)
    if needed == 0:
        ctypes.set_errno(0)
        confirmed = libc.fgetxattr(fd, name, None, 0, 0, 0)
        if confirmed != 0:
            refuse("fgetxattr_empty", ctypes.get_errno())
        return b""
    value = ctypes.create_string_buffer(needed)
    ctypes.set_errno(0)
    observed = libc.fgetxattr(fd, name, value, needed, 0, 0)
    if observed != needed:
        refuse("fgetxattr_value", ctypes.get_errno())
    return bytes(value.raw[:observed])

def acl_present(fd):
    ctypes.set_errno(0)
    acl = libc.acl_get_fd_np(fd, ACL_TYPE_EXTENDED)
    if not acl:
        error_number = ctypes.get_errno()
        if error_number == errno.ENOENT:
            return False
        refuse("acl_get_fd_np", error_number)
    result = None
    try:
        entry = ctypes.c_void_p()
        ctypes.set_errno(0)
        status = libc.acl_get_entry(acl, ACL_FIRST_ENTRY, ctypes.byref(entry))
        if status != 0 or not entry.value:
            refuse("acl_get_entry", ctypes.get_errno())
        result = True
    finally:
        ctypes.set_errno(0)
        if libc.acl_free(acl) != 0:
            refuse("acl_free", ctypes.get_errno())
    return result

records = []
for ordinal in range(descriptor_count):
    fd = 4 + ordinal
    before = stat_record(fd)
    if mode == "acl":
        first = acl_present(fd)
        second = acl_present(fd)
        if first != second:
            refuse("acl_changed")
        record = {"fd": fd, "present": first, "stat": before}
    else:
        names_raw = list_xattrs(fd, True)
        names = split_xattr_names(names_raw)
        provenance = None
        if PROVENANCE in names:
            provenance = read_xattr(fd, PROVENANCE, True)
        names_confirmed = list_xattrs(fd, False)
        if names_confirmed != names_raw:
            refuse("xattr_names_changed")
        if provenance is not None:
            provenance_confirmed = read_xattr(fd, PROVENANCE, False)
            if provenance_confirmed != provenance:
                refuse("provenance_changed")
        record = {
            "fd": fd,
            "namesBase64": [base64.b64encode(name).decode("ascii") for name in names],
            "provenanceBase64": None if provenance is None else base64.b64encode(provenance).decode("ascii"),
            "stat": before,
        }
    after = stat_record(fd)
    if after != before:
        refuse("descriptor_changed")
    records.append(record)

encoded = json.dumps(records, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
if len(encoded) > output_limit:
    refuse("output_limit")
sys.stdout.buffer.write(encoded)
`;
const WORKER_FCHDIR_SCRIPT = [
  "open(my $directory, q{<&=7}) or die q{worker directory descriptor unavailable};",
  "chdir($directory) or die q{worker directory cannot be entered};",
  "close($directory) or die q{worker directory descriptor cannot be closed};",
  "exec {$ARGV[0]} @ARGV;",
  "die q{worker exec failed};",
].join(" ");
const SOURCE_DIRECTORY_FLOCK_SCRIPT = [
  "use Fcntl qw(:flock);",
  "use Errno qw(EAGAIN EWOULDBLOCK);",
  "open(my $source, q{<&=3}) or exit 70;",
  "if (!flock($source, LOCK_EX | LOCK_NB)) {",
  "  my $error = 0 + $!;",
  "  exit 73 if $error == EAGAIN || $error == EWOULDBLOCK;",
  "  exit 75;",
  "}",
  "syswrite(STDOUT, qq{LOCKED\\n}) == 7 or exit 71;",
  "my $command;",
  "while (sysread(STDIN, $command, 1)) {",
  "  if ($command eq q{P}) {",
  "    syswrite(STDOUT, qq{ALIVE\\n}) == 6 or exit 71;",
  "    next;",
  "  }",
  "  exit 74;",
  "}",
  "exit 0;",
].join(" ");
const PRIVATE_TREE_CENSUS_SCRIPT = [
  'const crypto = require("node:crypto");',
  'const fs = require("node:fs");',
  'const path = require("node:path");',
  'const { TextDecoder } = require("node:util");',
  'const decoder = new TextDecoder("utf-8", { fatal: true });',
  'const limit = Number(process.argv[1]);',
  'if (!Number.isSafeInteger(limit) || limit < 1) throw new Error("invalid node limit");',
  'const records = [];',
  'const observe = (relative, stat, type, sha256) => ({',
  '  path: relative,',
  '  observation: {',
  '    ctimeNs: String(stat.ctimeNs),',
  '    identity: `${stat.dev}:${stat.ino}`,',
  '    mode: Number(stat.mode & 0o7777n),',
  '    mtimeNs: String(stat.mtimeNs),',
  '    nlink: Number(stat.nlink),',
  '    size: String(stat.size),',
  '    type,',
  '  },',
  '  sha256,',
  '});',
  'const walk = (relative) => {',
  '  if (records.length >= limit) throw new Error("private tree exceeds node limit");',
  '  const stat = fs.lstatSync(relative, { bigint: true });',
  '  if (stat.isSymbolicLink()) throw new Error("private tree contains symlink");',
  '  if (stat.isFile()) {',
  '    const digest = crypto.createHash("sha256").update(fs.readFileSync(relative)).digest("hex");',
  '    records.push(observe(relative, stat, "file", digest));',
  '    return;',
  '  }',
  '  if (!stat.isDirectory()) throw new Error("private tree contains special node");',
  '  records.push(observe(relative, stat, "directory", null));',
  '  const directory = fs.opendirSync(relative, { bufferSize: 32, encoding: "buffer" });',
  '  const names = [];',
  '  try {',
  '    for (let entry = directory.readSync(); entry !== null; entry = directory.readSync()) {',
  '      names.push(Buffer.from(entry.name));',
  '    }',
  '  } finally { directory.closeSync(); }',
  '  names.sort(Buffer.compare);',
  '  for (const name of names) {',
  '    const text = decoder.decode(name);',
  '    if (text.length === 0 || text === "." || text === ".." || text.includes("/") || text.includes("\\0")) {',
  '      throw new Error("private tree contains malformed name");',
  '    }',
  '    walk(relative === "." ? text : path.join(relative, text));',
  '  }',
  '};',
  'walk(".");',
  'records.sort((left, right) => Buffer.compare(Buffer.from(left.path), Buffer.from(right.path)));',
  'process.stdout.write(JSON.stringify(records));',
].join("\n");
const PROVENANCE_XATTR = "com.apple.provenance";
const PROVENANCE_CLASSIFICATION = "NON_SEMANTIC_OS_MANAGED_PATH_LOCAL";
const HASH_40 = /^[0-9a-f]{40}$/;
const HASH_64 = /^[0-9a-f]{64}$/;
const HASH_40_OR_64 = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const SHARED_INDEX_BASENAME = /^sharedindex\.(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const REF_NAME = /^refs\/[\x21-\x7e]+$/;
const utf8Decoder = new TextDecoder("utf-8", { fatal: true });
const operationBudgets = new WeakSet();
const metadataObservationCacheStates = new WeakMap();
const sealedCaptureCapabilities = new WeakMap();
const boundDirectoryLeaseStates = new WeakMap();
const knockoutCustodyStates = new WeakMap();
const captureCustodyOwners = new WeakMap();
const sourceLeaseStates = new WeakMap();
const armPlanStates = new WeakMap();
const armCapabilityStates = new WeakMap();
const cooperativeSourceLeaseStates = new WeakMap();
const workerTransferStates = new WeakMap();
const claimedWorkerCapabilityStates = new WeakMap();
const boundaryKnockoutBootstrapTokenStates = new WeakMap();
const claimedWorkerCapabilityDigests = new Set();
const activeModuleSourceLeases = new Map();

const sha256 = (bytes) => sha256Hex(bytes);
const modeOf = (stat) => Number(stat.mode & 0o7777n);
const identityOf = (stat) => `${stat.dev}:${stat.ino}`;

function workspaceError(code, message, details = null, cause = undefined) {
  return new KnockoutWorkspaceError(
    code,
    message,
    details,
    cause === undefined ? undefined : { cause },
  );
}

function fail(code, message, details = null, cause = undefined) {
  throw workspaceError(code, message, details, cause);
}

function combineWorkspaceFailures(
  primaryError,
  secondaryErrors,
  fallbackCode,
  fallbackMessage,
  details = null,
) {
  if (!Array.isArray(secondaryErrors) || secondaryErrors.length === 0) return primaryError;
  const aggregate = new AggregateError(
    primaryError === null ? secondaryErrors : [primaryError, ...secondaryErrors],
    fallbackMessage,
  );
  if (primaryError instanceof KnockoutWorkspaceError) {
    return workspaceError(
      primaryError.code,
      primaryError.message,
      {
        ...(primaryError.details ?? {}),
        secondaryFailureCount: secondaryErrors.length,
      },
      aggregate,
    );
  }
  return workspaceError(
    fallbackCode,
    fallbackMessage,
    {
      ...(details ?? {}),
      secondaryFailureCount: secondaryErrors.length,
    },
    aggregate,
  );
}

function createReleaseLease({ fallbackCode, message }) {
  if (!ERROR_CODE_SET.has(fallbackCode) || typeof message !== "string" || message.length === 0) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "release lease options are malformed");
  }
  let pending = [];
  const add = (closer) => {
    if (pending === null || typeof closer !== "function") {
      fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, `${message} lease is unavailable`);
    }
    pending.push(closer);
  };
  const ownBound = (bound, label, code = fallbackCode) => {
    add(() => closeBoundDirectory(bound, label, code));
    return bound;
  };
  const release = (primaryError = null) => {
    if (pending === null) return;
    const closers = pending.reverse();
    pending = null;
    const failures = [];
    for (const closer of closers) {
      try {
        const nested = closer();
        if (Array.isArray(nested)) failures.push(...nested);
      } catch (error) {
        failures.push(error);
      }
    }
    if (failures.length !== 0) {
      throw combineWorkspaceFailures(
        primaryError,
        failures,
        fallbackCode,
        message,
      );
    }
  };
  const assertActive = (code = fallbackCode) => {
    if (pending === null) fail(code, `${message} was already released`);
  };
  return Object.freeze({ add, assertActive, ownBound, release });
}

function releaseLeaseError(releaseLease, primaryError) {
  try {
    releaseLease.release(primaryError);
    return primaryError;
  } catch (error) {
    return error;
  }
}

function createDescriptorCloser(fd, code, message, details = null) {
  if (!Number.isInteger(fd) || fd < 0 || !ERROR_CODE_SET.has(code)) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "descriptor closer is malformed");
  }
  let activeFd = fd;
  return () => {
    if (activeFd === null) return;
    const closingFd = activeFd;
    activeFd = null;
    try { fs.closeSync(closingFd); }
    catch (error) { fail(code, message, details, error); }
  };
}

function createBoundedLineReader(stream, maxBytes, label) {
  let buffered = Buffer.alloc(0);
  let ended = false;
  let failure = null;
  let observedBytes = 0;
  const lines = [];
  const waiters = [];

  const settle = () => {
    if (failure !== null) {
      while (waiters.length > 0) {
        const waiter = waiters.shift();
        clearTimeout(waiter.timer);
        waiter.reject(failure);
      }
      return;
    }
    while (lines.length > 0 && waiters.length > 0) {
      const waiter = waiters.shift();
      clearTimeout(waiter.timer);
      waiter.resolve(lines.shift());
    }
    if (ended && lines.length === 0) {
      while (waiters.length > 0) {
        const waiter = waiters.shift();
        clearTimeout(waiter.timer);
        waiter.reject(new Error(`${label} ended before a complete control line`));
      }
    }
  };
  const rejectReader = (error) => {
    if (failure === null) failure = error instanceof Error ? error : new Error(String(error));
    settle();
  };

  stream.on("data", (chunk) => {
    if (failure !== null) return;
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    observedBytes += bytes.length;
    if (observedBytes > maxBytes) {
      rejectReader(new Error(`${label} exceeded ${maxBytes} control bytes`));
      return;
    }
    buffered = Buffer.concat([buffered, bytes]);
    for (let newline = buffered.indexOf(0x0a); newline !== -1; newline = buffered.indexOf(0x0a)) {
      const lineBytes = buffered.subarray(0, newline);
      buffered = buffered.subarray(newline + 1);
      if (
        lineBytes.length === 0 || lineBytes.length > 128 ||
        [...lineBytes].some((byte) => byte < 0x20 || byte > 0x7e)
      ) {
        rejectReader(new Error(`${label} emitted a malformed control line`));
        return;
      }
      lines.push(lineBytes.toString("ascii"));
    }
    settle();
  });
  stream.on("error", rejectReader);
  stream.on("end", () => {
    ended = true;
    if (buffered.length !== 0 && failure === null) {
      failure = new Error(`${label} ended with an incomplete control line`);
    }
    settle();
  });

  const readLine = (timeoutMs, operation) => {
    if (lines.length > 0) return Promise.resolve(lines.shift());
    if (failure !== null) return Promise.reject(failure);
    if (ended) return Promise.reject(new Error(`${label} ended before ${operation}`));
    return new Promise((resolve, reject) => {
      const waiter = { resolve, reject, timer: null };
      waiter.timer = setTimeout(() => {
        const index = waiters.indexOf(waiter);
        if (index !== -1) waiters.splice(index, 1);
        reject(new Error(`${label} timed out during ${operation}`));
      }, timeoutMs);
      waiters.push(waiter);
    });
  };
  return Object.freeze({
    hasQueuedLine: () => lines.length > 0 || buffered.length > 0,
    readLine,
  });
}

function createBoundedByteCollector(stream, maxBytes, label) {
  const chunks = [];
  let failure = null;
  let observedBytes = 0;
  stream.on("data", (chunk) => {
    if (failure !== null) return;
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    observedBytes += bytes.length;
    if (observedBytes > maxBytes) {
      failure = new Error(`${label} exceeded ${maxBytes} bytes`);
      return;
    }
    chunks.push(Buffer.from(bytes));
  });
  stream.on("error", (error) => { if (failure === null) failure = error; });
  return Object.freeze({
    assertEmpty: () => {
      if (failure !== null) throw failure;
      if (observedBytes !== 0) throw new Error(`${label} emitted unexpected diagnostics`);
    },
    bytes: () => Buffer.concat(chunks),
  });
}

function createChildCloseObservation(child) {
  let outcome = null;
  const promise = new Promise((resolve) => {
    child.once("close", (code, signal) => {
      outcome = Object.freeze({ code, signal });
      resolve(outcome);
    });
  });
  return Object.freeze({ current: () => outcome, promise });
}

async function waitWithTimeout(promise, timeoutMs, label) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(`${label} timed out`)), timeoutMs);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

function decodeUtf8(
  bytes,
  label,
  code = KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_LAYOUT_UNSUPPORTED,
) {
  try { return utf8Decoder.decode(bytes); }
  catch (error) {
    fail(
      code,
      `${label} is not valid UTF-8`,
      null,
      error,
    );
  }
}

export function canonicalJsonBytes(value) {
  try { return Buffer.from(canonicalJsonString(value), "utf8"); }
  catch (error) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
      "value is outside the shared canonical JSON contract",
      null,
      error,
    );
  }
}

function deepFreezeJson(value) {
  if (value !== null && typeof value === "object") {
    for (const child of Object.values(value)) deepFreezeJson(child);
    Object.freeze(value);
  }
  return value;
}

function canonicalJsonSnapshot(value) {
  const bytes = canonicalJsonBytes(value);
  let snapshot;
  try { snapshot = JSON.parse(bytes.toString("utf8")); }
  catch (error) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
      "canonical JSON snapshot could not be materialized",
      null,
      error,
    );
  }
  return Object.freeze({ bytes, value: deepFreezeJson(snapshot) });
}

function hasExactObjectKeys(value, expectedKeys) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  return actual.length === expected.length &&
    actual.every((key, index) => key === expected[index]);
}

const KNOCKOUT_BASELINE_OBSERVATION_KEYS = Object.freeze([
  "armTerminalProtocolComplete", "armTerminalProtocolError", "armTerminalSummary", "exit",
  "failing", "failureEvents", "fileFailureCount", "findings", "gate", "gateFindings",
  "gateProtocol", "gateProtocolComplete", "gateProtocolError", "gateProvenance",
  "protocolComplete", "protocolError", "signal", "testCount", "timedOut",
]);
const KNOCKOUT_RESULT_EVIDENCE_KEYS = Object.freeze([
  "andAlso", "baselineArmTerminal", "baselineExit", "baselineFailing",
  "baselineFailureEvents", "baselineFindings", "baselineGate", "baselineGateFindings",
  "baselineGateProtocol", "baselineGateProvenance", "buildState", "control", "detail", "file",
  "hashAfter", "hashBefore", "hashMutated", "hashMutatedByFile", "id",
  "mutatedArmTerminal", "mutatedExit", "mutatedFailing", "mutatedFailureEvents",
  "mutatedFindings", "mutatedGate", "mutatedGateFindings", "mutatedGateProtocol",
  "mutatedGateProvenance", "mutatedMs", "mutatedSignal", "newFailureEvents", "newFailures",
  "newGateFindings", "postRestoreArmTerminal", "postRestoreBaselineExit",
  "postRestoreBaselineVerified", "postRestoreGateProtocol", "postRestoreGateProvenance",
  "postRestoreHashAfter", "postRestoreState", "restored", "stderrTail", "suite", "verdict",
  "workspaceDisposition",
]);
const KNOCKOUT_WORKER_REFUSAL_REASONS = new Set([
  "ATTEST_REQUEST_NOT_EMPTY",
  "BASELINE_RESTORE_FAILED",
  "DEPENDENCY_REFUSED",
  "GUARD_REFUSED",
  "MUTANT_RETENTION_FAILED",
  "OPERATION_UNSUPPORTED",
  "POSTCHECK_RESTORE_FAILED",
  "REGISTRY_REFUSED",
  "ROLE_MISMATCH",
]);

function requireSha256(value, label) {
  if (typeof value !== "string" || !HASH_64.test(value)) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID, `${label} must be a sha256 digest`);
  }
  return value;
}

function requireKnockoutCandidateSubject(value, label) {
  if (!hasExactObjectKeys(value, ["archiveSha256", "commit", "repository", "tree"])) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID, `${label} has an open schema`);
  }
  requireSha256(value.archiveSha256, `${label} archive`);
  if (!/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(String(value.commit))
      || !/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(String(value.tree))
      || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(String(value.repository))) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID, `${label} is malformed`);
  }
  return value;
}

export function knockoutCandidateSubject(value) {
  return canonicalJsonSnapshot(requireKnockoutCandidateSubject(value, "knockout candidate subject")).value;
}

function requireWorkerSuite(value, label) {
  if (
    !Array.isArray(value) || value.length !== 3 ||
    typeof value[0] !== "string" || value[0].length < 1 ||
    typeof value[1] !== "string" || value[1].length < 1 ||
    !Array.isArray(value[2]) || value[2].some((argument) => typeof argument !== "string")
  ) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID, `${label} is malformed`);
  }
  return value;
}

function requireRawWorkerDependencies(value, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID, `${label} must be an object`);
  }
  for (const [name, descriptor] of Object.entries(value)) {
    if (
      !/^[a-z][a-z0-9-]{0,63}$/.test(name) || descriptor === null ||
      typeof descriptor !== "object" || Array.isArray(descriptor)
    ) {
      fail(KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID, `${label} is malformed`);
    }
  }
  return value;
}

function requireWorkerTimeout(value, label) {
  if (!Number.isSafeInteger(value) || value < 1 || value > MAX_ARM_WORKER_DURATION_MS) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID, `${label} is outside the worker bound`);
  }
  return value;
}

function requireArmWorkerTimeoutMs(value) {
  if (!Number.isSafeInteger(value) || value < 1 || value > MAX_ARM_WORKER_DURATION_MS) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
      `arm worker timeoutMs must be between 1 and ${MAX_ARM_WORKER_DURATION_MS}`,
    );
  }
  return value;
}

function validateWorkerOperationRequest(operation, request) {
  if (request === null || typeof request !== "object" || Array.isArray(request)) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID, "worker request must be an object");
  }
  if (operation === KNOCKOUT_WORKER_OPERATIONS.RUN_KNOCKOUT_SELFTEST) {
    if (!hasExactObjectKeys(request, ["selftestKeySha256", "suiteTimeoutMs"])) {
      fail(KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID, "selftest worker request has an open schema");
    }
    requireSha256(request.selftestKeySha256, "selftest key");
    requireWorkerTimeout(request.suiteTimeoutMs, "selftest timeout");
    if (request.selftestKeySha256 !== knockoutSelftestKeySha256()) {
      fail(KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID, "selftest key does not bind the fixed suite");
    }
  } else if (operation === KNOCKOUT_WORKER_OPERATIONS.OBSERVE_KNOCKOUT_BASELINE) {
    const candidateSubjectKeys = Object.hasOwn(request, "candidateSubject")
      ? ["candidateSubject"]
      : [];
    if (!hasExactObjectKeys(request, [
      "baselineKeySha256", "dependencies", "entryId", "kind", "registrySha256", "suite",
      "suiteTimeoutMs", ...candidateSubjectKeys,
    ])) {
      fail(KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID, "baseline worker request has an open schema");
    }
    requireSha256(request.baselineKeySha256, "baseline key");
    requireSha256(request.registrySha256, "baseline registry");
    requireRawWorkerDependencies(request.dependencies, "baseline dependencies");
    if (typeof request.entryId !== "string" || request.entryId.length < 1) {
      fail(KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID, "baseline entry id is malformed");
    }
    if (!['gate', 'tests'].includes(request.kind)) {
      fail(KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID, "baseline kind is malformed");
    }
    requireWorkerSuite(request.suite, "baseline suite");
    requireWorkerTimeout(request.suiteTimeoutMs, "baseline timeout");
    if (candidateSubjectKeys.length === 1) {
      requireKnockoutCandidateSubject(request.candidateSubject, "baseline candidate subject");
    }
    const observedBaselineKey = sha256(canonicalJsonBytes({
      dependencies: request.dependencies,
      kind: request.kind,
      suite: request.suite,
    }));
    if (observedBaselineKey !== request.baselineKeySha256) {
      fail(KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID, "baseline key does not bind its request");
    }
  } else if (
    operation === KNOCKOUT_WORKER_OPERATIONS.RUN_KNOCKOUT ||
    operation === KNOCKOUT_WORKER_OPERATIONS.OBSERVE_KNOCKOUT_POSTCHECK
  ) {
    const postcheck = operation === KNOCKOUT_WORKER_OPERATIONS.OBSERVE_KNOCKOUT_POSTCHECK;
    const expectedKeys = [
      "baseline", "baselineResultSha256", "baselineTerminalSha256", "dependencies", "entry",
      "pairedEntry", "registrySha256", "suiteTimeoutMs",
      ...(Object.hasOwn(request, "candidateSubject") ? ["candidateSubject"] : []),
      ...(postcheck ? ["mutant", "mutantResultSha256", "mutantTerminalSha256"] : []),
    ];
    if (!hasExactObjectKeys(request, [
      ...expectedKeys,
    ])) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
        `${postcheck ? "postcheck" : "mutant"} worker request has an open schema`,
      );
    }
    validateKnockoutBaselineWire(request.baseline);
    requireSha256(request.baselineResultSha256, "baseline result");
    requireSha256(request.baselineTerminalSha256, "baseline terminal");
    requireSha256(request.registrySha256, "mutant registry");
    requireRawWorkerDependencies(request.dependencies, "mutant dependencies");
    if (request.entry === null || typeof request.entry !== "object" || Array.isArray(request.entry)) {
      fail(KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID, "mutant entry is malformed");
    }
    if (!(request.pairedEntry === null || (
      typeof request.pairedEntry === "object" && !Array.isArray(request.pairedEntry)
    ))) {
      fail(KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID, "paired mutant entry is malformed");
    }
    canonicalKnockoutTargetSet(
      request,
      KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
      postcheck ? "postcheck" : "mutant",
    );
    requireWorkerTimeout(request.suiteTimeoutMs, "mutant timeout");
    if (Object.hasOwn(request, "candidateSubject")) {
      requireKnockoutCandidateSubject(
        request.candidateSubject,
        `${postcheck ? "postcheck" : "mutant"} candidate subject`,
      );
    }
    if (
      !["gate", "tests"].includes(request.entry.kind) ||
      knockoutBaselineKeySha256({
        dependencies: request.dependencies,
        kind: request.entry.kind,
        suite: request.entry.suite,
      }) !== request.baseline.baselineKeySha256
    ) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
        `${postcheck ? "postcheck" : "mutant"} baseline does not bind the captured entry and dependencies`,
      );
    }
    if (postcheck) {
      requireSha256(request.mutantResultSha256, "mutant result");
      requireSha256(request.mutantTerminalSha256, "mutant terminal");
      validateKnockoutResultWire(request.mutant, request);
    }
  }
  return request;
}

function requireNullableString(value, label) {
  if (!(value === null || typeof value === "string")) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID, `${label} must be a string or null`);
  }
}

function requireNonnegativeInteger(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID, `${label} must be a nonnegative integer`);
  }
}

function validateFailureEvents(value, label) {
  if (!Array.isArray(value) || value.some((event) =>
    !hasExactObjectKeys(event, ["column", "file", "line", "name"]) ||
    typeof event.name !== "string" || typeof event.file !== "string" ||
    !Number.isSafeInteger(event.line) || event.line < 1 ||
    !Number.isSafeInteger(event.column) || event.column < 1
  )) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID, `${label} is malformed`);
  }
}

function validateGateFindings(value, label) {
  if (!Array.isArray(value) || value.some((finding) =>
    !hasExactObjectKeys(finding, ["detail", "rule", "subject"]) ||
    typeof finding.detail !== "string" || typeof finding.rule !== "string" ||
    finding.rule.length < 1 || typeof finding.subject !== "string" || finding.subject.length < 1
  )) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID, `${label} is malformed`);
  }
}

function validateKnockoutBaselineObservation(value) {
  if (!hasExactObjectKeys(value, KNOCKOUT_BASELINE_OBSERVATION_KEYS)) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID, "baseline observation has an open schema");
  }
  if (
    typeof value.armTerminalProtocolComplete !== "boolean" ||
    typeof value.gateProtocolComplete !== "boolean" ||
    typeof value.protocolComplete !== "boolean" || typeof value.timedOut !== "boolean" ||
    !(value.exit === null || Number.isSafeInteger(value.exit)) ||
    !Array.isArray(value.failing) || value.failing.some((name) => typeof name !== "string") ||
    [...value.failing].sort().some((name, index) => name !== value.failing[index]) ||
    new Set(value.failing).size !== value.failing.length ||
    !(value.armTerminalSummary === null || (
      typeof value.armTerminalSummary === "object" && !Array.isArray(value.armTerminalSummary)
    )) ||
    !(value.gateProvenance === null || (
      typeof value.gateProvenance === "object" && !Array.isArray(value.gateProvenance)
    ))
  ) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID, "baseline observation fields are malformed");
  }
  requireNullableString(value.armTerminalProtocolError, "baseline arm terminal error");
  requireNullableString(value.gate, "baseline gate");
  requireNullableString(value.gateProtocol, "baseline gate protocol");
  requireNullableString(value.gateProtocolError, "baseline gate protocol error");
  requireNullableString(value.protocolError, "baseline test protocol error");
  requireNullableString(value.signal, "baseline signal");
  requireNonnegativeInteger(value.fileFailureCount, "baseline file-failure count");
  requireNonnegativeInteger(value.findings, "baseline finding count");
  requireNonnegativeInteger(value.testCount, "baseline test count");
  validateFailureEvents(value.failureEvents, "baseline failure events");
  if (value.failureEvents.some((event) =>
    path.isAbsolute(event.file) || event.file.includes("\\") ||
    event.file.split("/").some((segment) => segment === "" || segment === "." || segment === "..")
  )) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
      "baseline failure-event paths are not canonical workspace-relative paths",
    );
  }
  validateGateFindings(value.gateFindings, "baseline gate findings");
  if (value.findings !== value.gateFindings.length) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID, "baseline finding count is inconsistent");
  }
  return value;
}

function validateKnockoutBaselineWire(wire) {
  if (!hasExactObjectKeys(wire, ["baselineKeySha256", "observation", "observationSha256"])) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID, "baseline wire value has an open schema");
  }
  requireSha256(wire.baselineKeySha256, "baseline wire key");
  requireSha256(wire.observationSha256, "baseline observation");
  validateKnockoutBaselineObservation(wire.observation);
  const observed = sha256(canonicalJsonBytes(wire.observation));
  if (observed !== wire.observationSha256) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
      "baseline observation digest is invalid",
      { expected: wire.observationSha256, observed },
    );
  }
  return wire;
}

function relativeWorkerFailureEvents(workspaceRoot, events) {
  const root = requireAbsolutePath(workspaceRoot, "baseline workspace root");
  return events.map((event) => {
    const absolute = requireAbsolutePath(event.file, "baseline failure-event file");
    const relative = path.relative(root, absolute);
    if (
      relative === "" || path.isAbsolute(relative) || relative === ".." ||
      relative.startsWith(`..${path.sep}`)
    ) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
        "baseline failure event is outside its disposable workspace",
      );
    }
    return { ...event, file: relative.split(path.sep).join("/") };
  });
}

export function knockoutBaselineWireFromObservation(
  baselineKeySha256,
  observation,
  { workspaceRoot } = {},
) {
  requireSha256(baselineKeySha256, "baseline key");
  if (!(observation?.failing instanceof Set)) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID, "baseline observation requires a failing Set");
  }
  const projected = canonicalJsonSnapshot({
    armTerminalProtocolComplete: observation.armTerminalProtocolComplete,
    armTerminalProtocolError: observation.armTerminalProtocolError,
    armTerminalSummary: observation.armTerminalSummary,
    exit: observation.exit,
    failing: [...observation.failing].sort(),
    failureEvents: relativeWorkerFailureEvents(workspaceRoot, observation.failureEvents),
    fileFailureCount: observation.fileFailureCount,
    findings: observation.findings,
    gate: observation.gate,
    gateFindings: observation.gateFindings,
    gateProtocol: observation.gateProtocol,
    gateProtocolComplete: observation.gateProtocolComplete,
    gateProtocolError: observation.gateProtocolError,
    gateProvenance: observation.gateProvenance,
    protocolComplete: observation.protocolComplete,
    protocolError: observation.protocolError,
    signal: observation.signal,
    testCount: observation.testCount,
    timedOut: observation.timedOut,
  }).value;
  validateKnockoutBaselineObservation(projected);
  return deepFreezeJson({
    baselineKeySha256,
    observation: projected,
    observationSha256: sha256(canonicalJsonBytes(projected)),
  });
}

export function knockoutBaselineObservationFromWire(wire, { workspaceRoot } = {}) {
  const validated = validateKnockoutBaselineWire(canonicalJsonSnapshot(wire).value);
  const root = requireAbsolutePath(workspaceRoot, "mutant workspace root");
  return Object.freeze({
    ...validated.observation,
    failureEvents: Object.freeze(validated.observation.failureEvents.map((event) => Object.freeze({
      ...event,
      file: path.join(root, ...event.file.split("/")),
    }))),
    failing: new Set(validated.observation.failing),
  });
}

function nullableJsonValue(value, fallback = null) {
  return value === undefined ? fallback : canonicalJsonSnapshot(value).value;
}

export function knockoutResultWireFromEvidence({ baselineKeySha256, entryId, result }) {
  requireSha256(baselineKeySha256, "result baseline key");
  if (typeof entryId !== "string" || entryId.length < 1 || result?.id !== entryId) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID, "knockout result entry binding is invalid");
  }
  const evidence = canonicalJsonSnapshot({
    andAlso: result.andAlso ?? null,
    baselineArmTerminal: nullableJsonValue(result.baselineArmTerminal),
    baselineExit: result.baselineExit ?? null,
    baselineFailing: nullableJsonValue(result.baselineFailing, []),
    baselineFailureEvents: nullableJsonValue(result.baselineFailureEvents, []),
    baselineFindings: result.baselineFindings ?? null,
    baselineGate: result.baselineGate ?? null,
    baselineGateFindings: nullableJsonValue(result.baselineGateFindings, []),
    baselineGateProtocol: result.baselineGateProtocol ?? null,
    baselineGateProvenance: nullableJsonValue(result.baselineGateProvenance),
    buildState: nullableJsonValue(result.buildState),
    control: result.control,
    detail: result.detail ?? null,
    file: result.file,
    hashAfter: nullableJsonValue(result.hashAfter),
    hashBefore: nullableJsonValue(result.hashBefore),
    hashMutated: result.hashMutated ?? null,
    hashMutatedByFile: nullableJsonValue(result.hashMutatedByFile),
    id: result.id,
    mutatedArmTerminal: nullableJsonValue(result.mutatedArmTerminal),
    mutatedExit: result.mutatedExit ?? null,
    mutatedFailing: nullableJsonValue(result.mutatedFailing, []),
    mutatedFailureEvents: nullableJsonValue(result.mutatedFailureEvents, []),
    mutatedFindings: result.mutatedFindings ?? null,
    mutatedGate: result.mutatedGate ?? null,
    mutatedGateFindings: nullableJsonValue(result.mutatedGateFindings, []),
    mutatedGateProtocol: result.mutatedGateProtocol ?? null,
    mutatedGateProvenance: nullableJsonValue(result.mutatedGateProvenance),
    mutatedMs: result.mutatedMs ?? null,
    mutatedSignal: result.mutatedSignal ?? null,
    newFailureEvents: nullableJsonValue(result.newFailureEvents, []),
    newFailures: nullableJsonValue(result.newFailures, []),
    newGateFindings: nullableJsonValue(result.newGateFindings, []),
    postRestoreArmTerminal: nullableJsonValue(result.postRestoreArmTerminal),
    postRestoreBaselineExit: result.postRestoreBaselineExit ?? null,
    postRestoreBaselineVerified: result.postRestoreBaselineVerified ?? null,
    postRestoreGateProtocol: result.postRestoreGateProtocol ?? null,
    postRestoreGateProvenance: nullableJsonValue(result.postRestoreGateProvenance),
    postRestoreHashAfter: nullableJsonValue(result.postRestoreHashAfter),
    postRestoreState: nullableJsonValue(result.postRestoreState),
    restored: result.restored,
    stderrTail: result.stderrTail ?? null,
    suite: result.suite,
    verdict: result.verdict,
    workspaceDisposition: result.workspaceDisposition,
  }).value;
  if (
    !hasExactObjectKeys(evidence, KNOCKOUT_RESULT_EVIDENCE_KEYS) ||
    typeof evidence.id !== "string" || typeof evidence.control !== "string" ||
    typeof evidence.file !== "string" || typeof evidence.suite !== "string" ||
    typeof evidence.verdict !== "string" || !/^[A-Z][A-Z0-9_]*$/.test(evidence.verdict) ||
    typeof evidence.restored !== "boolean" ||
    ![
      "RESTORED_IN_PLACE", "RESTORATION_FAILED", "RETAINED_DISPOSABLE_ARM_DRIFTED",
      "RETAINED_DISPOSABLE_MUTANT", "RETAINED_UNMODIFIED_ARM",
    ].includes(evidence.workspaceDisposition) ||
    !(evidence.detail === null || typeof evidence.detail === "string")
  ) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID, "knockout result evidence is malformed");
  }
  validateFailureEvents(evidence.baselineFailureEvents, "result baseline failures");
  validateFailureEvents(evidence.mutatedFailureEvents, "result mutant failures");
  validateFailureEvents(evidence.newFailureEvents, "result new failures");
  const evidenceSha256 = sha256(canonicalJsonBytes(evidence));
  return deepFreezeJson({ baselineKeySha256, entryId, evidence, evidenceSha256 });
}

function validateKnockoutResultWire(wire, request) {
  if (!hasExactObjectKeys(wire, ["baselineKeySha256", "entryId", "evidence", "evidenceSha256"])) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_INCOMPLETE, "knockout result wire value has an open schema");
  }
  requireSha256(wire.baselineKeySha256, "knockout result baseline key");
  requireSha256(wire.evidenceSha256, "knockout result evidence");
  if (
    wire.baselineKeySha256 !== request.baseline.baselineKeySha256 ||
    wire.entryId !== request.entry.id || !hasExactObjectKeys(wire.evidence, KNOCKOUT_RESULT_EVIDENCE_KEYS) ||
    wire.evidence.id !== request.entry.id || wire.evidence.control !== request.entry.control ||
    wire.evidence.file !== request.entry.file || wire.evidence.suite !== request.entry.suite?.[0] ||
    typeof wire.evidence.verdict !== "string" || !/^[A-Z][A-Z0-9_]*$/.test(wire.evidence.verdict) ||
    typeof wire.evidence.restored !== "boolean" ||
    ![
      "RESTORED_IN_PLACE", "RESTORATION_FAILED", "RETAINED_DISPOSABLE_ARM_DRIFTED",
      "RETAINED_DISPOSABLE_MUTANT", "RETAINED_UNMODIFIED_ARM",
    ].includes(wire.evidence.workspaceDisposition) ||
    sha256(canonicalJsonBytes(wire.evidence)) !== wire.evidenceSha256
  ) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_INCOMPLETE, "knockout result evidence binding is invalid");
  }
  validateFailureEvents(wire.evidence.baselineFailureEvents, "result baseline failures");
  validateFailureEvents(wire.evidence.mutatedFailureEvents, "result mutant failures");
  validateFailureEvents(wire.evidence.newFailureEvents, "result new failures");
  return wire;
}

export function createKnockoutWorkerSubject({ operation, request, workerSha256 }) {
  const subject = {
    operation,
    protocol: KNOCKOUT_WORKSPACE_PROTOCOLS.workerSubject,
    request,
    worker: { path: KNOCKOUT_WORKER_RELATIVE_PATH, sha256: workerSha256 },
  };
  return validateWorkerSubjectValue(subject).subject;
}

export function knockoutBaselineKeySha256({ dependencies, kind, suite }) {
  requireRawWorkerDependencies(dependencies, "baseline-key dependencies");
  if (!["gate", "tests"].includes(kind)) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID, "baseline-key kind is malformed");
  }
  requireWorkerSuite(suite, "baseline-key suite");
  return sha256(canonicalJsonBytes({ dependencies, kind, suite }));
}

export function knockoutSelftestKeySha256() {
  return sha256(canonicalJsonBytes({
    gate: KNOCKOUT_SELFTEST_GATE,
    kind: "gate",
    suite: KNOCKOUT_SELFTEST_SUITE,
  }));
}

export function knockoutResultEvidenceFromWire(wire, { baseline, entry }) {
  const snapshot = canonicalJsonSnapshot(wire).value;
  validateKnockoutResultWire(snapshot, { baseline, entry });
  return snapshot.evidence;
}

export function knockoutWorkerSubjectSha256(subject) {
  return validateWorkerSubjectValue(subject).subjectSha256;
}

/**
 * Return the single role authorized for an evidence-bearing runner operation. ATTEST_ARM is
 * deliberately excluded because it attests whichever admitted arm role carries it. A new or
 * unknown operation must therefore fail closed instead of inheriting a MUTANT fallback.
 */
export function knockoutWorkerOperationRole(operation) {
  const role = KNOCKOUT_WORKER_OPERATION_ROLES[operation];
  if (typeof role !== "string") {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
      `worker operation ${JSON.stringify(operation)} has no closed role mapping`,
    );
  }
  return role;
}

export function validateKnockoutWorkerOperationResult({
  observation, operation, request, role, status,
}) {
  if (!["COMPLETE", "REFUSED"].includes(status)) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_INCOMPLETE, "worker operation status is invalid");
  }
  validateWorkerOperationRequest(operation, request);
  const requestKeys = Object.keys(request).sort();
  if (operation === KNOCKOUT_WORKER_OPERATIONS.ATTEST_ARM) {
    const expectedStatus = requestKeys.length === 0 ? "COMPLETE" : "REFUSED";
    const expectedObservation = requestKeys.length === 0
      ? { operation, role, workspaceBound: true }
      : { operation, reasonCode: "ATTEST_REQUEST_NOT_EMPTY" };
    if (
      status !== expectedStatus ||
      !canonicalJsonBytes(observation).equals(canonicalJsonBytes(expectedObservation))
    ) {
      fail(KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_INCOMPLETE, "ATTEST_ARM result contract is invalid");
    }
    return observation;
  }
  if (!Object.values(KNOCKOUT_WORKER_OPERATIONS).includes(operation)) {
    if (
      status !== "REFUSED" ||
      !canonicalJsonBytes(observation).equals(canonicalJsonBytes({
        operation,
        reasonCode: "OPERATION_UNSUPPORTED",
      }))
    ) {
      fail(KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_INCOMPLETE, "unsupported worker operation was not refused");
    }
    return observation;
  }
  const expectedRole = knockoutWorkerOperationRole(operation);
  if (role !== expectedRole) {
    if (
      status !== "REFUSED" ||
      !canonicalJsonBytes(observation).equals(canonicalJsonBytes({ operation, reasonCode: "ROLE_MISMATCH" }))
    ) {
      fail(KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_INCOMPLETE, "worker role mismatch was not refused");
    }
    return observation;
  }
  if (status === "REFUSED") {
    if (
      !hasExactObjectKeys(observation, ["operation", "reasonCode"]) ||
      observation.operation !== operation || !KNOCKOUT_WORKER_REFUSAL_REASONS.has(observation.reasonCode)
    ) {
      fail(KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_INCOMPLETE, "worker refusal result is malformed");
    }
    return observation;
  }
  if (operation === KNOCKOUT_WORKER_OPERATIONS.RUN_KNOCKOUT_SELFTEST) {
    if (!hasExactObjectKeys(observation, ["operation", "selftest"]) || observation.operation !== operation) {
      fail(KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_INCOMPLETE, "selftest worker result has an open schema");
    }
    const selftest = validateKnockoutBaselineWire(observation.selftest);
    if (selftest.baselineKeySha256 !== request.selftestKeySha256) {
      fail(KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_INCOMPLETE, "selftest worker result names a different suite");
    }
    return observation;
  }
  if (operation === KNOCKOUT_WORKER_OPERATIONS.OBSERVE_KNOCKOUT_BASELINE) {
    if (!hasExactObjectKeys(observation, ["baseline", "operation"]) || observation.operation !== operation) {
      fail(KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_INCOMPLETE, "baseline worker result has an open schema");
    }
    const baseline = validateKnockoutBaselineWire(observation.baseline);
    if (baseline.baselineKeySha256 !== request.baselineKeySha256) {
      fail(KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_INCOMPLETE, "baseline worker result names a different suite");
    }
    return observation;
  }
  if (!hasExactObjectKeys(observation, ["knockout", "operation"]) || observation.operation !== operation) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_INCOMPLETE,
      `${operation === KNOCKOUT_WORKER_OPERATIONS.OBSERVE_KNOCKOUT_POSTCHECK ? "postcheck" : "mutant"} worker result has an open schema`,
    );
  }
  validateKnockoutResultWire(observation.knockout, request);
  return observation;
}

function parseCanonicalJsonBytes(bytes, label, maxBytes) {
  if (
    !Buffer.isBuffer(bytes) || bytes.length < 1 ||
    !Number.isSafeInteger(maxBytes) || maxBytes < 1
  ) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, `${label} bytes are malformed`);
  }
  if (bytes.length > maxBytes) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.RESOURCE_LIMIT_EXCEEDED,
      `${label} exceeds its fixed byte limit`,
      { limitBytes: maxBytes, observedBytes: bytes.length },
    );
  }
  let value;
  try { value = deepFreezeJson(JSON.parse(decodeUtf8(bytes, label, KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID))); }
  catch (error) {
    if (error instanceof KnockoutWorkspaceError) throw error;
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID, `${label} is not complete JSON`, null, error);
  }
  if (!canonicalJsonBytes(value).equals(bytes)) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID, `${label} is not canonical JSON`);
  }
  return value;
}

function requireAnonymousPipeDescriptor(fd, label) {
  if (!Number.isInteger(fd) || fd < 3) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID, `${label} must be an inherited descriptor`);
  }
  let stat;
  try { stat = fs.fstatSync(fd, { bigint: true }); }
  catch (error) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID, `${label} is unavailable`, null, error);
  }
  if (!stat.isFIFO() && !stat.isSocket()) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
      `${label} must be an anonymous pipe or socket, never a pathname-backed file`,
    );
  }
  return stat;
}

function readAnonymousPipeExactly(fd, maxBytes, label) {
  requireAnonymousPipeDescriptor(fd, label);
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const chunk = Buffer.alloc(Math.min(64 * 1024, maxBytes - total + 1));
      const read = fs.readSync(fd, chunk, 0, chunk.length, null);
      if (read === 0) break;
      total += read;
      if (total > maxBytes) {
        fail(
          KNOCKOUT_WORKSPACE_ERROR_CODES.RESOURCE_LIMIT_EXCEEDED,
          `${label} exceeds its fixed byte limit`,
          { limitBytes: maxBytes, observedBytes: total },
        );
      }
      chunks.push(chunk.subarray(0, read));
    }
  } finally {
    try { fs.closeSync(fd); }
    catch {}
  }
  if (total === 0) fail(KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID, `${label} is empty`);
  return Buffer.concat(chunks, total);
}

function writeAnonymousPipeExactly(fd, bytes, maxBytes, label) {
  requireAnonymousPipeDescriptor(fd, label);
  if (!Buffer.isBuffer(bytes) || bytes.length < 1 || bytes.length > maxBytes) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.RESOURCE_LIMIT_EXCEEDED,
      `${label} bytes exceed their fixed bound`,
      { limitBytes: maxBytes, observedBytes: Buffer.isBuffer(bytes) ? bytes.length : null },
    );
  }
  let offset = 0;
  try {
    while (offset < bytes.length) {
      const written = fs.writeSync(fd, bytes, offset, bytes.length - offset, null);
      if (!Number.isInteger(written) || written <= 0 || written > bytes.length - offset) {
        fail(KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_INCOMPLETE, `${label} made no write progress`);
      }
      offset += written;
    }
  } finally {
    try { fs.closeSync(fd); }
    catch {}
  }
  return offset;
}

function validateWorkerSubjectValue(value, expectedSha256 = null) {
  const subject = canonicalJsonSnapshot(value).value;
  if (!hasExactObjectKeys(subject, ["operation", "protocol", "request", "worker"])) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID, "worker subject has an open or incomplete schema");
  }
  if (
    subject.protocol !== KNOCKOUT_WORKSPACE_PROTOCOLS.workerSubject ||
    typeof subject.operation !== "string" ||
    !/^[A-Z][A-Z0-9_]{0,63}$/.test(subject.operation) ||
    subject.request === null || typeof subject.request !== "object" || Array.isArray(subject.request) ||
    !hasExactObjectKeys(subject.worker, ["path", "sha256"]) ||
    subject.worker.path !== ARM_WORKER_RELATIVE_PATH ||
    typeof subject.worker.sha256 !== "string" || !HASH_64.test(subject.worker.sha256)
  ) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID, "worker subject fields are malformed");
  }
  validateWorkerOperationRequest(subject.operation, subject.request);
  const relativePath = decodeCanonicalIndexPath(
    Buffer.from(subject.worker.path, "utf8"),
    "worker subject executable path",
    KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
  );
  if (relativePath !== subject.worker.path) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID, "worker subject executable path is not canonical");
  }
  const evidenceFields = subject.operation === KNOCKOUT_WORKER_OPERATIONS.RUN_KNOCKOUT
    ? ["baseline"]
    : subject.operation === KNOCKOUT_WORKER_OPERATIONS.OBSERVE_KNOCKOUT_POSTCHECK
      ? ["baseline", "mutant"]
      : [];
  const metadataRequest = { ...subject.request };
  for (const field of evidenceFields) {
    const wireBytes = canonicalJsonBytes(subject.request[field]);
    if (wireBytes.length > MAX_WORKER_RESULT_BYTES) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.RESOURCE_LIMIT_EXCEEDED,
        `worker subject ${field} wire exceeds the fixed result byte limit`,
        { limitBytes: MAX_WORKER_RESULT_BYTES, observedBytes: wireBytes.length },
      );
    }
    metadataRequest[field] = null;
  }
  // This projection is for size accounting only. Authority and evidence still bind the complete
  // unprojected subject below, including every byte of both retained result wires.
  const metadataSubject = Object.freeze({ ...subject, request: Object.freeze(metadataRequest) });
  const metadataBytes = canonicalJsonBytes(metadataSubject);
  if (metadataBytes.length > MAX_WORKER_SUBJECT_METADATA_BYTES) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.RESOURCE_LIMIT_EXCEEDED,
      "worker subject metadata exceeds its fixed byte limit",
      { limitBytes: MAX_WORKER_SUBJECT_METADATA_BYTES, observedBytes: metadataBytes.length },
    );
  }
  const bytes = canonicalJsonBytes(subject);
  if (bytes.length > MAX_WORKER_SUBJECT_BYTES) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.RESOURCE_LIMIT_EXCEEDED,
      "worker subject exceeds its fixed byte limit",
      { limitBytes: MAX_WORKER_SUBJECT_BYTES, observedBytes: bytes.length },
    );
  }
  const subjectSha256 = sha256(bytes);
  if (expectedSha256 !== null && subjectSha256 !== expectedSha256) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
      "worker subject does not match the admitted arm subject",
      { expected: expectedSha256, observed: subjectSha256 },
    );
  }
  return Object.freeze({ bytes, metadataSubject, subject, subjectSha256, workerRelativePath: relativePath });
}

function workerInitialWorkspaceSummary(census) {
  return Object.freeze({
    allocatedBytes: census.allocatedBytes,
    logicalBytes: census.logicalBytes,
    materialSha256: census.materialSha256,
    maxDepth: census.maxDepth,
    nodeCount: census.nodeCount,
    observationSha256: census.observationSha256,
  });
}

function validateWorkerCapabilityBytes(bytes) {
  const capability = parseCanonicalJsonBytes(
    bytes,
    "worker capability",
    MAX_WORKER_CAPABILITY_BYTES,
  );
  const expectedKeys = [
    "armId", "armPlanSha256", "armRoot", "armRootIdentity",
    "candidateManifestSha256", "evidenceIdentity", "evidenceRoot", "initialWorkspace", "limits",
    "nonce", "predecessorTerminalSha256", "protocol", "role", "seedObservationSha256",
    "sourceLeaseSha256", "sourceSnapshotSha256", "subject", "subjectSha256",
    "supervisorPid", "workerCapabilitySha256", "workerPid", "workspaceIdentity",
    "workspaceRoot",
  ];
  if (!hasExactObjectKeys(capability, expectedKeys)) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID, "worker capability has an open or incomplete schema");
  }
  const initial = capability.initialWorkspace;
  if (
    capability.protocol !== KNOCKOUT_WORKSPACE_PROTOCOLS.workerCapability ||
    typeof capability.armId !== "string" || !ARM_ID.test(capability.armId) ||
    !KNOCKOUT_WORKSPACE_ARM_ROLES.includes(capability.role) ||
    !HASH_64.test(capability.armPlanSha256 ?? "") ||
    !HASH_64.test(capability.candidateManifestSha256 ?? "") ||
    !HASH_64.test(capability.nonce ?? "") ||
    !HASH_64.test(capability.seedObservationSha256 ?? "") ||
    !HASH_64.test(capability.sourceLeaseSha256 ?? "") ||
    !HASH_64.test(capability.sourceSnapshotSha256 ?? "") ||
    !HASH_64.test(capability.subjectSha256 ?? "") ||
    !HASH_64.test(capability.workerCapabilitySha256 ?? "") ||
    !(capability.predecessorTerminalSha256 === null ||
      HASH_64.test(capability.predecessorTerminalSha256 ?? "")) ||
    !Number.isSafeInteger(capability.supervisorPid) || capability.supervisorPid < 1 ||
    !Number.isSafeInteger(capability.workerPid) || capability.workerPid < 1 ||
    typeof capability.armRootIdentity !== "string" || capability.armRootIdentity.length < 1 ||
    typeof capability.evidenceIdentity !== "string" || capability.evidenceIdentity.length < 1 ||
    typeof capability.workspaceIdentity !== "string" || capability.workspaceIdentity.length < 1 ||
    !hasExactObjectKeys(initial, [
      "allocatedBytes", "logicalBytes", "materialSha256", "maxDepth", "nodeCount",
      "observationSha256",
    ]) ||
    !Number.isSafeInteger(initial.allocatedBytes) || initial.allocatedBytes < 0 ||
    !Number.isSafeInteger(initial.logicalBytes) || initial.logicalBytes < 0 ||
    !Number.isSafeInteger(initial.maxDepth) || initial.maxDepth < 0 ||
    !Number.isSafeInteger(initial.nodeCount) || initial.nodeCount < 1 ||
    !HASH_64.test(initial.materialSha256 ?? "") ||
    !HASH_64.test(initial.observationSha256 ?? "")
  ) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID, "worker capability fields are malformed");
  }
  const armRoot = requireAbsolutePath(capability.armRoot, "worker capability arm root");
  const evidenceRoot = requireAbsolutePath(capability.evidenceRoot, "worker capability evidence root");
  const workspaceRoot = requireAbsolutePath(capability.workspaceRoot, "worker capability workspace root");
  if (
    path.dirname(workspaceRoot) !== armRoot || path.basename(workspaceRoot) !== "workspace" ||
    path.dirname(evidenceRoot) !== armRoot || path.basename(evidenceRoot) !== "evidence"
  ) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID, "worker capability arm topology is malformed");
  }
  const subject = validateWorkerSubjectValue(capability.subject, capability.subjectSha256);
  const metadataBytes = canonicalJsonBytes({ ...capability, subject: subject.metadataSubject });
  if (metadataBytes.length > MAX_WORKER_CAPABILITY_METADATA_BYTES) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.RESOURCE_LIMIT_EXCEEDED,
      "worker capability metadata exceeds its fixed byte limit",
      { limitBytes: MAX_WORKER_CAPABILITY_METADATA_BYTES, observedBytes: metadataBytes.length },
    );
  }
  const limits = normalizeCaptureLimits(capability.limits);
  const unsigned = { ...capability };
  delete unsigned.workerCapabilitySha256;
  const observedCapabilitySha256 = sha256(canonicalJsonBytes(unsigned));
  if (observedCapabilitySha256 !== capability.workerCapabilitySha256) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
      "worker capability digest is invalid",
      { expected: capability.workerCapabilitySha256, observed: observedCapabilitySha256 },
    );
  }
  return Object.freeze({ capability, limits, subject });
}

function validateWorkerResultBytes(bytes, expectedCapability) {
  let result;
  try {
    result = parseCanonicalJsonBytes(bytes, "worker result", MAX_WORKER_RESULT_BYTES);
  } catch (error) {
    if (
      error instanceof KnockoutWorkspaceError &&
      error.code === KNOCKOUT_WORKSPACE_ERROR_CODES.RESOURCE_LIMIT_EXCEEDED
    ) throw error;
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_INCOMPLETE,
      "worker result is not one complete canonical JSON document",
      { sourceCode: error?.code ?? null },
      error,
    );
  }
  if (!hasExactObjectKeys(result, [
    "armId", "armPlanSha256", "candidateManifestSha256", "observation", "protocol", "role",
    "sourceLeaseSha256", "status", "subjectSha256", "workerCapabilitySha256", "workerPid",
  ])) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_INCOMPLETE, "worker result has an open or incomplete schema");
  }
  if (
    result.protocol !== KNOCKOUT_WORKSPACE_PROTOCOLS.workerResult ||
    !["COMPLETE", "REFUSED"].includes(result.status) ||
    result.observation === null || typeof result.observation !== "object" ||
    Array.isArray(result.observation) ||
    result.armId !== expectedCapability.armId ||
    result.armPlanSha256 !== expectedCapability.armPlanSha256 ||
    result.candidateManifestSha256 !== expectedCapability.candidateManifestSha256 ||
    result.role !== expectedCapability.role ||
    result.sourceLeaseSha256 !== expectedCapability.sourceLeaseSha256 ||
    result.subjectSha256 !== expectedCapability.subjectSha256 ||
    result.workerCapabilitySha256 !== expectedCapability.workerCapabilitySha256 ||
    result.workerPid !== expectedCapability.workerPid
  ) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_INCOMPLETE, "worker result binding or status is invalid");
  }
  validateKnockoutWorkerOperationResult({
    observation: result.observation,
    operation: expectedCapability.subject.operation,
    request: expectedCapability.subject.request,
    role: expectedCapability.role,
    status: result.status,
  });
  return result;
}

function createBoundedProcessStreamCollector(stream, maxBytes, label, onFailure) {
  const chunks = [];
  let capturedBytes = 0;
  let complete = false;
  let eof = false;
  let failure = null;
  let observedBytes = 0;
  let settled = false;
  let resolveFinished;
  const finished = new Promise((resolve) => { resolveFinished = resolve; });
  const settle = (ended) => {
    if (settled) return;
    settled = true;
    eof = ended;
    complete = ended && failure === null;
    resolveFinished();
  };
  const recordFailure = (error) => {
    if (failure === null) {
      failure = error instanceof Error ? error : new Error(String(error));
      try { onFailure(failure); }
      catch {}
    }
  };
  stream.on("data", (chunk) => {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    observedBytes += bytes.length;
    const remaining = Math.max(0, maxBytes - capturedBytes);
    if (remaining > 0) {
      const kept = bytes.subarray(0, remaining);
      chunks.push(Buffer.from(kept));
      capturedBytes += kept.length;
    }
    if (observedBytes > maxBytes) {
      recordFailure(new Error(`${label} exceeded ${maxBytes} bytes`));
    }
  });
  stream.on("error", (error) => { recordFailure(error); settle(false); });
  stream.on("end", () => settle(true));
  stream.on("close", () => settle(stream.readableEnded === true));
  return Object.freeze({
    finished,
    snapshot: () => Object.freeze({
      bytes: Buffer.concat(chunks, capturedBytes),
      capturedBytes,
      complete,
      eof,
      failure,
      observedBytes,
    }),
  });
}

function writeChildPipeExactly(stream, bytes, label) {
  return new Promise((resolve, reject) => {
    if (stream === null || typeof stream?.end !== "function") {
      reject(new Error(`${label} is unavailable`));
      return;
    }
    let settled = false;
    const finish = (error = null) => {
      if (settled) return;
      settled = true;
      stream.off("error", onError);
      if (error === null) resolve();
      else reject(error);
    };
    const onError = (error) => finish(error);
    stream.once("error", onError);
    stream.end(bytes, (error) => finish(error ?? null));
  });
}

const workerDelay = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

function signalWorkerProcessGroup(child, signal) {
  if (!Number.isSafeInteger(child.pid) || child.pid < 1) return false;
  try { process.kill(-child.pid, signal); return true; }
  catch (error) {
    if (error?.code === "ESRCH") return false;
    try { return child.kill(signal); }
    catch { return false; }
  }
}

function workerProcessGroupExists(pid) {
  if (!Number.isSafeInteger(pid) || pid < 1 || process.platform === "win32") return false;
  try { process.kill(-pid, 0); return true; }
  catch (error) { return error?.code !== "ESRCH"; }
}

async function waitForWorkerProcessGroupExit(pid, timeoutMs = 2_000) {
  if (process.platform === "win32") return false;
  const deadline = Date.now() + timeoutMs;
  while (workerProcessGroupExists(pid) && Date.now() < deadline) await workerDelay(25);
  return !workerProcessGroupExists(pid);
}

/**
 * Claim the one canonical capability delivered on inherited FD 3. The capability is bound to this
 * exact PID, parent PID, executable byte hash, cwd inode and pristine arm census. A process-local
 * digest set additionally prevents a second claim in the same worker; it is not a global replay
 * database and no such cross-process claim is made.
 */
export function claimArmWorkerCapabilityFromFd() {
  const bytes = readAnonymousPipeExactly(3, MAX_WORKER_CAPABILITY_BYTES, "worker capability FD 3");
  const validated = validateWorkerCapabilityBytes(bytes);
  const capability = validated.capability;
  if (
    capability.workerPid !== process.pid || capability.supervisorPid !== process.ppid ||
    process.execArgv.length !== 0 || process.argv.length !== 2
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
      "worker capability is not bound to this exact direct child invocation",
      {
        expectedSupervisorPid: capability.supervisorPid,
        expectedWorkerPid: capability.workerPid,
        observedSupervisorPid: process.ppid,
        observedWorkerPid: process.pid,
      },
    );
  }
  const expectedEnvironment = Object.freeze({ LANG: "C", LC_ALL: "C", PATH: "/usr/bin:/bin" });
  const environmentKeys = Object.keys(process.env).sort();
  const macTextEncoding = process.env.__CF_USER_TEXT_ENCODING;
  const expectedKeys = process.platform === "darwin"
    ? ["LANG", "LC_ALL", "PATH", "__CF_USER_TEXT_ENCODING"].sort()
    : ["LANG", "LC_ALL", "PATH"];
  const macEncodingValid = process.platform !== "darwin" || (
    typeof macTextEncoding === "string" &&
    /^0x[0-9A-Fa-f]+:0x[0-9A-Fa-f]+:0x[0-9A-Fa-f]+$/.test(macTextEncoding) &&
    (typeof process.getuid !== "function" ||
      Number.parseInt(macTextEncoding.split(":", 1)[0], 16) === process.getuid())
  );
  if (
    environmentKeys.length !== expectedKeys.length ||
    environmentKeys.some((key, index) => key !== expectedKeys[index]) ||
    Object.entries(expectedEnvironment).some(([key, value]) => process.env[key] !== value) ||
    !macEncodingValid
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
      "worker inherited an open environment instead of the fixed execution environment",
    );
  }
  if (claimedWorkerCapabilityDigests.has(capability.workerCapabilitySha256)) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID, "worker capability was already claimed in this process");
  }

  const armRoot = requireRealDirectory(capability.armRoot, "worker arm root", {
    expectedIdentity: capability.armRootIdentity,
    expectedIdentityCode: KNOCKOUT_WORKSPACE_ERROR_CODES.ARM_IDENTITY_MISMATCH,
    privateMode: true,
  });
  const workspaceRoot = requireRealDirectory(capability.workspaceRoot, "worker workspace root", {
    expectedIdentity: capability.workspaceIdentity,
    expectedIdentityCode: KNOCKOUT_WORKSPACE_ERROR_CODES.ARM_IDENTITY_MISMATCH,
    privateMode: true,
  });
  requireRealDirectory(capability.evidenceRoot, "worker evidence root", {
    expectedIdentity: capability.evidenceIdentity,
    expectedIdentityCode: KNOCKOUT_WORKSPACE_ERROR_CODES.ARM_IDENTITY_MISMATCH,
    privateMode: true,
  });
  if (
    path.dirname(workspaceRoot.path) !== armRoot.path ||
    fs.realpathSync(process.cwd()) !== workspaceRoot.path ||
    identityOf(fs.statSync(process.cwd(), { bigint: true })) !== workspaceRoot.identity
  ) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.ARM_IDENTITY_MISMATCH, "worker cwd is not the admitted arm workspace");
  }
  const expectedWorkerPath = path.join(
    workspaceRoot.path,
    ...validated.subject.workerRelativePath.split("/"),
  );
  let invokedWorkerPath;
  try { invokedWorkerPath = fs.realpathSync(path.resolve(process.argv[1])); }
  catch (error) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID, "worker executable path cannot be reopened", null, error);
  }
  if (invokedWorkerPath !== expectedWorkerPath) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID, "a different worker executable claimed the capability");
  }

  const census = censusWorkspace(workspaceRoot.path, {
    expectedRoot: Object.freeze({ identity: workspaceRoot.identity, path: workspaceRoot.path }),
    expectedRootCode: KNOCKOUT_WORKSPACE_ERROR_CODES.ARM_IDENTITY_MISMATCH,
    limits: validated.limits,
    rootGitPolicy: "include",
  });
  const observedInitial = workerInitialWorkspaceSummary(census);
  if (!canonicalJsonBytes(observedInitial).equals(canonicalJsonBytes(capability.initialWorkspace))) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.ARM_IDENTITY_MISMATCH,
      "worker arm changed before its capability was claimed",
      {
        expected: capability.initialWorkspace.observationSha256,
        observed: observedInitial.observationSha256,
      },
    );
  }
  const workerNode = census.nodes.find((node) => node.path === validated.subject.workerRelativePath);
  if (
    workerNode?.type !== "file" ||
    workerNode.sha256 !== validated.subject.subject.worker.sha256
  ) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID, "worker executable bytes do not match the admitted subject");
  }

  claimedWorkerCapabilityDigests.add(capability.workerCapabilitySha256);
  const claimedCapability = Object.freeze({
    armId: capability.armId,
    armPlanSha256: capability.armPlanSha256,
    candidateManifestSha256: capability.candidateManifestSha256,
    evidenceRoot: capability.evidenceRoot,
    kind: "CLAIMED_ARM_WORKER_CAPABILITY",
    operation: validated.subject.subject.operation,
    protocol: KNOCKOUT_WORKSPACE_PROTOCOLS.workerCapability,
    request: validated.subject.subject.request,
    role: capability.role,
    sourceLeaseSha256: capability.sourceLeaseSha256,
    subjectSha256: capability.subjectSha256,
    workerCapabilitySha256: capability.workerCapabilitySha256,
    workspaceRoot: capability.workspaceRoot,
  });
  claimedWorkerCapabilityStates.set(claimedCapability, {
    capability,
    status: "CLAIMED",
  });
  return claimedCapability;
}

/**
 * Re-attest the exact live worker claim to a trusted in-process consumer. This exports no pathname-
 * reconstructed authority: only the unforgeable object returned by the FD claim is accepted, and
 * the result contains the already-validated arm roots needed to keep dependency binding local.
 */
export function attestClaimedArmWorkerCapability(claimedCapability) {
  const claimState = claimedWorkerCapabilityStates.get(claimedCapability);
  if (claimState === undefined || claimState.status !== "CLAIMED") {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
      "worker operation requires the exact currently claimed arm capability",
    );
  }
  return Object.freeze({
    evidenceRoot: claimedCapability.evidenceRoot,
    role: claimedCapability.role,
    workspaceRoot: claimedCapability.workspaceRoot,
  });
}

/**
 * Mint one process-local, one-shot transport token for an isolated boundary-gate observation. The
 * exact claimed worker capability is a WeakMap key and its request already binds the public source
 * subject into the PID/PPID/cwd/census-bound capability bytes. No caller-supplied path or authority
 * is accepted here.
 */
export function createBoundaryKnockoutBootstrapToken(claimedCapability) {
  const claimState = claimedWorkerCapabilityStates.get(claimedCapability);
  if (claimState === undefined || claimState.status !== "CLAIMED") {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
      "boundary knockout bootstrap requires the exact currently claimed worker capability",
    );
  }
  const request = claimedCapability.request;
  if (!Object.hasOwn(request, "candidateSubject")) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
      "boundary knockout bootstrap request has no supervisor-bound candidate subject",
    );
  }
  const candidateSubject = knockoutCandidateSubject(request.candidateSubject);
  const token = Object.freeze({});
  boundaryKnockoutBootstrapTokenStates.set(token, {
    context: Object.freeze({
      candidateSubject,
      protocol: "noa-boundary-knockout-bootstrap/1",
      workerCapabilitySha256: claimedCapability.workerCapabilitySha256,
      workerPid: process.pid,
    }),
    status: "ISSUED",
  });
  return token;
}

export function consumeBoundaryKnockoutBootstrapToken(token) {
  const state = boundaryKnockoutBootstrapTokenStates.get(token);
  if (state === undefined || state.status !== "ISSUED") {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
      "boundary knockout bootstrap token is absent, cloned, or already consumed",
    );
  }
  state.status = "CONSUMED";
  // `canonicalJsonBytes` already terminates every document with exactly one LF. Appending another
  // one makes the direct-child receiver reject its own supervisor-issued context as non-canonical.
  return canonicalJsonBytes(state.context);
}

/** Write one closed worker result on inherited FD 4, then burn the claim whether writing succeeds. */
export function writeArmWorkerResultToFd(claimedCapability, result) {
  const claimState = claimedWorkerCapabilityStates.get(claimedCapability);
  if (claimState === undefined || claimState.status !== "CLAIMED") {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID, "worker result requires the exact unused claim");
  }
  claimState.status = "CONSUMING";
  try {
    const snapshot = strictDataObjectSnapshot(
      result,
      "worker result",
      ["observation", "status"],
    );
    if (!["COMPLETE", "REFUSED"].includes(snapshot.status)) {
      fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "worker result status must be COMPLETE or REFUSED");
    }
    if (
      snapshot.observation === null || typeof snapshot.observation !== "object" ||
      Array.isArray(snapshot.observation)
    ) {
      fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "worker result observation must be a JSON object");
    }
    const capability = claimState.capability;
    const envelope = Object.freeze({
      armId: capability.armId,
      armPlanSha256: capability.armPlanSha256,
      candidateManifestSha256: capability.candidateManifestSha256,
      observation: snapshot.observation,
      protocol: KNOCKOUT_WORKSPACE_PROTOCOLS.workerResult,
      role: capability.role,
      sourceLeaseSha256: capability.sourceLeaseSha256,
      status: snapshot.status,
      subjectSha256: capability.subjectSha256,
      workerCapabilitySha256: capability.workerCapabilitySha256,
      workerPid: process.pid,
    });
    const bytes = canonicalJsonBytes(envelope);
    if (bytes.length > MAX_WORKER_RESULT_BYTES) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.RESOURCE_LIMIT_EXCEEDED,
        "worker result exceeds its fixed byte limit",
        { limitBytes: MAX_WORKER_RESULT_BYTES, observedBytes: bytes.length },
      );
    }
    claimState.status = "WRITING";
    writeAnonymousPipeExactly(4, bytes, MAX_WORKER_RESULT_BYTES, "worker result FD 4");
    claimState.status = "WRITTEN";
    return Object.freeze({ bytes: bytes.length, sha256: sha256(bytes), status: envelope.status });
  } catch (error) {
    claimState.status = "FAILED";
    throw error;
  }
}

function candidateManifestSha256FromSnapshot(manifest) {
  const unsigned = { ...manifest };
  delete unsigned.candidateManifestSha256;
  return sha256(canonicalJsonBytes(unsigned));
}

export function candidateManifestSha256(manifest) {
  const snapshot = canonicalJsonSnapshot(manifest).value;
  if (snapshot === null || typeof snapshot !== "object" || Array.isArray(snapshot)) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "candidate manifest must be an object");
  }
  return candidateManifestSha256FromSnapshot(snapshot);
}

function requireCommandTimeoutMs(value) {
  if (
    !Number.isSafeInteger(value) || value < 1 ||
    value > MAX_CHILD_PROCESS_DURATION_MS
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
      `commandTimeoutMs must be between 1 and ${MAX_CHILD_PROCESS_DURATION_MS}`,
    );
  }
  return value;
}

function requireCaptureOperationTimeoutMs(value) {
  if (
    !Number.isSafeInteger(value) || value < 1 ||
    value > MAX_CAPTURE_OPERATION_DURATION_MS
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
      `operationTimeoutMs must be between 1 and ${MAX_CAPTURE_OPERATION_DURATION_MS}`,
    );
  }
  return value;
}

function normalizeCaptureLimits(value = KNOCKOUT_WORKSPACE_CAPTURE_LIMITS) {
  if (value === KNOCKOUT_WORKSPACE_CAPTURE_LIMITS) return value;
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "capture limits must be an object");
  }
  // Materialize one data-descriptor snapshot before validation. Reading caller-owned properties
  // more than once lets accessors return a permitted value during validation and a larger value
  // when the normalized object is built. Accessors are rejected without invoking them.
  let prototype;
  let descriptors;
  try {
    prototype = Object.getPrototypeOf(value);
    descriptors = Object.getOwnPropertyDescriptors(value);
  } catch (error) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
      "capture limits could not be snapshotted safely",
      null,
      error,
    );
  }
  if (prototype !== Object.prototype && prototype !== null) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "capture limits must be a plain object");
  }
  const descriptorKeys = Reflect.ownKeys(descriptors);
  if (descriptorKeys.some((key) => typeof key !== "string")) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "capture limits cannot use symbol keys");
  }
  const snapshotInput = Object.create(null);
  for (const key of descriptorKeys) {
    const descriptor = descriptors[key];
    if (descriptor.enumerable !== true || !("value" in descriptor)) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
        "capture limits must use enumerable data properties",
      );
    }
    Object.defineProperty(snapshotInput, key, {
      enumerable: true,
      value: descriptor.value,
    });
  }
  const snapshot = canonicalJsonSnapshot(snapshotInput).value;
  const expected = Object.keys(KNOCKOUT_WORKSPACE_CAPTURE_LIMITS).sort();
  const actual = Object.keys(snapshot).sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "capture limits have unknown or missing fields");
  }
  for (const key of [
    "maxAllocatedBytes",
    "maxDepth",
    "maxFileBytes",
    "maxNodes",
    "maxTotalBytes",
  ]) {
    if (
      !Number.isSafeInteger(snapshot[key]) || snapshot[key] < 1 ||
      snapshot[key] > KNOCKOUT_WORKSPACE_CAPTURE_LIMITS[key]
    ) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
        `${key} must be a positive safe integer no greater than the fixed maximum`,
      );
    }
  }
  if (
    !Number.isSafeInteger(snapshot.minFreeBytes) ||
    snapshot.minFreeBytes < KNOCKOUT_WORKSPACE_CAPTURE_LIMITS.minFreeBytes
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
      "minFreeBytes cannot weaken the fixed free-space reserve",
    );
  }
  if (snapshot.maxFileBytes > snapshot.maxTotalBytes) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "maxFileBytes exceeds maxTotalBytes");
  }
  return Object.freeze({
    maxAllocatedBytes: snapshot.maxAllocatedBytes,
    maxDepth: snapshot.maxDepth,
    maxFileBytes: snapshot.maxFileBytes,
    maxNodes: snapshot.maxNodes,
    maxTotalBytes: snapshot.maxTotalBytes,
    minFreeBytes: snapshot.minFreeBytes,
  });
}

function strictDataObjectSnapshot(value, label, allowedKeys, requiredKeys = allowedKeys) {
  if (
    value === null || typeof value !== "object" || Array.isArray(value) ||
    !Array.isArray(allowedKeys) || !Array.isArray(requiredKeys)
  ) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, `${label} must be a plain data object`);
  }
  if (utilTypes.isProxy(value)) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, `${label} cannot be a Proxy`);
  }
  let prototype;
  let descriptors;
  try {
    prototype = Object.getPrototypeOf(value);
    descriptors = Object.getOwnPropertyDescriptors(value);
  } catch (error) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
      `${label} could not be snapshotted safely`,
      null,
      error,
    );
  }
  if (prototype !== Object.prototype && prototype !== null) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, `${label} must be a plain data object`);
  }
  const allowed = new Set(allowedKeys);
  const keys = Reflect.ownKeys(descriptors);
  if (keys.some((key) => typeof key !== "string" || !allowed.has(key))) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, `${label} has unknown or symbol fields`);
  }
  for (const key of requiredKeys) {
    if (!Object.prototype.hasOwnProperty.call(descriptors, key)) {
      fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, `${label} is missing ${key}`);
    }
  }
  const input = Object.create(null);
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (descriptor.enumerable !== true || !("value" in descriptor)) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
        `${label} must use enumerable data properties`,
      );
    }
    Object.defineProperty(input, key, { enumerable: true, value: descriptor.value });
  }
  const ancestors = new WeakSet();
  const state = { nodes: 0, stringBytes: 0 };
  const clone = (candidate, depth) => {
    state.nodes += 1;
    if (state.nodes > 4096 || depth > 16) {
      fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, `${label} exceeds its data-shape bound`);
    }
    if (candidate === null || typeof candidate === "boolean") return candidate;
    if (typeof candidate === "string") {
      state.stringBytes += Buffer.byteLength(candidate, "utf8");
      if (state.stringBytes > MIB) {
        fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, `${label} exceeds its string-byte bound`);
      }
      return candidate;
    }
    if (typeof candidate === "number") {
      if (!Number.isSafeInteger(candidate)) {
        fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, `${label} contains a non-integer number`);
      }
      return candidate;
    }
    if (typeof candidate !== "object" || utilTypes.isProxy(candidate)) {
      fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, `${label} contains unsupported authority data`);
    }
    if (ancestors.has(candidate)) {
      fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, `${label} contains a cycle`);
    }
    ancestors.add(candidate);
    try {
      const candidatePrototype = Object.getPrototypeOf(candidate);
      const candidateIsArray = Array.isArray(candidate);
      if (
        candidateIsArray &&
        (!Number.isSafeInteger(candidate.length) || candidate.length < 0 ||
          candidate.length > KNOCKOUT_WORKSPACE_ARM_LIMITS.maxRetainedArms)
      ) {
        fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, `${label} contains an unbounded array`);
      }
      const candidateDescriptors = Object.getOwnPropertyDescriptors(candidate);
      const candidateKeys = Reflect.ownKeys(candidateDescriptors);
      if (candidateKeys.some((key) => typeof key !== "string")) {
        fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, `${label} contains symbol fields`);
      }
      if (candidateIsArray) {
        if (candidatePrototype !== Array.prototype) {
          fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, `${label} contains a non-plain array`);
        }
        const lengthDescriptor = candidateDescriptors.length;
        const length = lengthDescriptor?.value;
        if (
          !Number.isSafeInteger(length) || length < 0 ||
          candidateKeys.length !== length + 1
        ) {
          fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, `${label} contains an unbounded or sparse array`);
        }
        const result = new Array(length);
        for (let index = 0; index < length; index++) {
          const descriptor = candidateDescriptors[String(index)];
          if (descriptor?.enumerable !== true || !("value" in descriptor)) {
            fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, `${label} contains an accessor or sparse array`);
          }
          result[index] = clone(descriptor.value, depth + 1);
        }
        return Object.freeze(result);
      }
      if (candidatePrototype !== Object.prototype && candidatePrototype !== null) {
        fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, `${label} contains a non-plain object`);
      }
      const result = Object.create(null);
      for (const key of candidateKeys) {
        const descriptor = candidateDescriptors[key];
        if (descriptor.enumerable !== true || !("value" in descriptor)) {
          fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, `${label} contains an accessor field`);
        }
        Object.defineProperty(result, key, {
          enumerable: true,
          value: clone(descriptor.value, depth + 1),
        });
      }
      return Object.freeze(result);
    } catch (error) {
      if (error instanceof KnockoutWorkspaceError) throw error;
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
        `${label} could not be snapshotted safely`,
        null,
        error,
      );
    } finally {
      ancestors.delete(candidate);
    }
  };
  return canonicalJsonSnapshot(clone(input, 0)).value;
}

function normalizeArmRetentionLimits(maxRetainedArms, maxRetainedBytes) {
  if (
    !Number.isSafeInteger(maxRetainedArms) || maxRetainedArms < 1 ||
    maxRetainedArms > KNOCKOUT_WORKSPACE_ARM_LIMITS.maxRetainedArms
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
      `maxRetainedArms must be between 1 and ${KNOCKOUT_WORKSPACE_ARM_LIMITS.maxRetainedArms}`,
    );
  }
  if (
    !Number.isSafeInteger(maxRetainedBytes) || maxRetainedBytes < 1 ||
    maxRetainedBytes > KNOCKOUT_WORKSPACE_ARM_LIMITS.maxRetainedBytes
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
      `maxRetainedBytes must be between 1 and ${KNOCKOUT_WORKSPACE_ARM_LIMITS.maxRetainedBytes}`,
    );
  }
  return Object.freeze({ maxRetainedArms, maxRetainedBytes });
}

function currentEffectiveUid() {
  if (typeof process.geteuid !== "function") return null;
  let uid;
  try { uid = process.geteuid(); }
  catch (error) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
      "the effective filesystem principal cannot be observed",
      null,
      error,
    );
  }
  if (!Number.isSafeInteger(uid) || uid < 0) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
      "the effective filesystem principal is malformed",
      { observedEffectiveUid: uid },
    );
  }
  return uid;
}

function registerOperationBudget(operationTimeoutMs, commandTimeoutMs) {
  const effectiveUid = currentEffectiveUid();
  if (effectiveUid === null) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
      "the platform cannot report the effective filesystem principal",
    );
  }
  const budget = Object.freeze({
    commandTimeoutMs: Math.min(commandTimeoutMs, operationTimeoutMs),
    deadlineNs: process.hrtime.bigint() + BigInt(operationTimeoutMs) * 1_000_000n,
    effectiveUid,
    operationTimeoutMs,
  });
  operationBudgets.add(budget);
  return budget;
}

function createOperationBudget(timeoutMs) {
  const bounded = requireCommandTimeoutMs(timeoutMs);
  return registerOperationBudget(bounded, bounded);
}

function createCaptureOperationBudget(operationTimeoutMs, commandTimeoutMs) {
  return registerOperationBudget(
    requireCaptureOperationTimeoutMs(operationTimeoutMs),
    requireCommandTimeoutMs(commandTimeoutMs),
  );
}

function remainingOperationMs(budget, label = "workspace operation") {
  if (
    budget === null || typeof budget !== "object" ||
    !operationBudgets.has(budget) || typeof budget.deadlineNs !== "bigint" ||
    !Number.isSafeInteger(budget.commandTimeoutMs) ||
    !Number.isSafeInteger(budget.operationTimeoutMs) ||
    (budget.effectiveUid !== null && !Number.isSafeInteger(budget.effectiveUid))
  ) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "operation budget is malformed");
  }
  const observedEffectiveUid = currentEffectiveUid();
  if (observedEffectiveUid !== budget.effectiveUid) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
      `${label} changed effective filesystem principal`,
      { expectedEffectiveUid: budget.effectiveUid, observedEffectiveUid },
    );
  }
  const remainingNs = budget.deadlineNs - process.hrtime.bigint();
  if (remainingNs <= 0n) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.OPERATION_DEADLINE_EXCEEDED,
      `${label} exceeded its ${budget.operationTimeoutMs}ms deadline`,
      { timeoutMs: budget.operationTimeoutMs },
    );
  }
  const roundedUpMs = (remainingNs + 999_999n) / 1_000_000n;
  return Number(roundedUpMs > BigInt(budget.commandTimeoutMs)
    ? BigInt(budget.commandTimeoutMs)
    : roundedUpMs);
}

function createMetadataObservationCache(maxEntries) {
  if (!Number.isSafeInteger(maxEntries) || maxEntries < 1) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
      "metadata observation cache bound is malformed",
    );
  }
  const cache = Object.freeze({});
  metadataObservationCacheStates.set(cache, {
    entries: new Map(),
    maxEntries,
  });
  return cache;
}

function operationEffectiveUid(operationBudget, label) {
  if (operationBudget === null) return currentEffectiveUid();
  remainingOperationMs(operationBudget, label);
  return operationBudget.effectiveUid;
}

function childProcessFailureCode(error, fallback) {
  if (error?.code === "ETIMEDOUT") {
    return KNOCKOUT_WORKSPACE_ERROR_CODES.OPERATION_DEADLINE_EXCEEDED;
  }
  if (["ENOBUFS", "ERR_CHILD_PROCESS_STDIO_MAXBUFFER"].includes(error?.code)) {
    return KNOCKOUT_WORKSPACE_ERROR_CODES.RESOURCE_LIMIT_EXCEEDED;
  }
  return fallback;
}

function descriptorFailureCode(error, fallback) {
  if (["EMFILE", "ENFILE"].includes(error?.code)) {
    return KNOCKOUT_WORKSPACE_ERROR_CODES.RESOURCE_LIMIT_EXCEEDED;
  }
  return fallback;
}

function filesystemCapacity(abs, label, operationBudget = null) {
  if (operationBudget !== null) remainingOperationMs(operationBudget, `capacity check for ${label}`);
  let state;
  try { state = fs.statfsSync(abs, { bigint: true }); }
  catch (error) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.RESOURCE_LIMIT_EXCEEDED,
      `cannot measure capacity for ${label}`,
      null,
      error,
    );
  }
  if (
    state.bsize <= 0n || state.bsize > BigInt(Number.MAX_SAFE_INTEGER) ||
    state.bavail < 0n
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.RESOURCE_LIMIT_EXCEEDED,
      `capacity report is malformed for ${label}`,
    );
  }
  if (operationBudget !== null) remainingOperationMs(operationBudget, `capacity check for ${label}`);
  return Object.freeze({
    allocationUnitBytes: Number(state.bsize),
    availableBytes: state.bsize * state.bavail,
  });
}

function requireDestinationCapacity(parent, copyBytes, limits, label, operationBudget = null) {
  if (!Number.isSafeInteger(copyBytes) || copyBytes < 0) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "copy-byte projection is malformed");
  }
  const required = BigInt(copyBytes) + BigInt(limits.minFreeBytes);
  const capacity = filesystemCapacity(parent, label, operationBudget);
  if (capacity.availableBytes < required) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.RESOURCE_LIMIT_EXCEEDED,
      `${label} lacks projected copy capacity plus the fixed reserve`,
      { availableBytes: String(capacity.availableBytes), requiredBytes: String(required) },
    );
  }
  return capacity;
}

function createCaptureResourceLedger(limits, initial) {
  const normalizedLimits = normalizeCaptureLimits(limits);
  if (
    initial === null || typeof initial !== "object" ||
    !Number.isSafeInteger(initial.allocatedBytes) || initial.allocatedBytes < 0 ||
    !Number.isSafeInteger(initial.logicalBytes) || initial.logicalBytes < 0 ||
    !Number.isSafeInteger(initial.maxDepth) || initial.maxDepth < 0 ||
    !Number.isSafeInteger(initial.nodeCount) || initial.nodeCount < 1
  ) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "initial resource admission is malformed");
  }
  let allocatedBytes = initial.allocatedBytes;
  let logicalBytes = initial.logicalBytes;
  let maxDepth = initial.maxDepth;
  let nodeCount = initial.nodeCount;

  const snapshot = () => Object.freeze({ allocatedBytes, logicalBytes, maxDepth, nodeCount });
  const charge = ({
    allocatedBytes: allocated = 0,
    label,
    logicalBytes: logical = 0,
    maxDepth: depth = 0,
    nodeCount: nodes = 0,
  }) => {
    if (
      typeof label !== "string" || label.length === 0 ||
      !Number.isSafeInteger(allocated) || allocated < 0 ||
      !Number.isSafeInteger(logical) || logical < 0 ||
      !Number.isSafeInteger(depth) || depth < 0 ||
      !Number.isSafeInteger(nodes) || nodes < 0
    ) {
      fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "resource charge is malformed");
    }
    const next = {
      allocatedBytes: allocatedBytes + allocated,
      logicalBytes: logicalBytes + logical,
      maxDepth: Math.max(maxDepth, depth),
      nodeCount: nodeCount + nodes,
    };
    if (
      !Number.isSafeInteger(next.allocatedBytes) ||
      !Number.isSafeInteger(next.logicalBytes) ||
      !Number.isSafeInteger(next.nodeCount) ||
      next.allocatedBytes > normalizedLimits.maxAllocatedBytes ||
      next.logicalBytes > normalizedLimits.maxTotalBytes ||
      next.maxDepth > normalizedLimits.maxDepth ||
      next.nodeCount > normalizedLimits.maxNodes
    ) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.RESOURCE_LIMIT_EXCEEDED,
        `${label} exceeds the shared pre-write capture budget`,
        { limits: normalizedLimits, projected: next },
      );
    }
    ({ allocatedBytes, logicalBytes, maxDepth, nodeCount } = next);
    return snapshot();
  };

  // Validate the starting state against the same fixed ceilings before exposing the ledger.
  charge({ label: "initial workspace admission" });
  return Object.freeze({ charge, snapshot });
}

function createObservationByteBudget(limits, label) {
  const normalizedLimits = normalizeCaptureLimits(limits);
  if (typeof label !== "string" || label.length === 0) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "observation budget label is malformed");
  }
  let observedBytes = 0;
  const remainingLimit = (itemLabel) => {
    const remaining = normalizedLimits.maxTotalBytes - observedBytes;
    if (remaining < 1) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.RESOURCE_LIMIT_EXCEEDED,
        `${label} exhausted before ${itemLabel}`,
        { limitBytes: normalizedLimits.maxTotalBytes, observedBytes },
      );
    }
    return Math.min(normalizedLimits.maxFileBytes, remaining, MAX_TOOL_OUTPUT_BYTES);
  };
  const charge = (bytes, itemLabel) => {
    if (!Number.isSafeInteger(bytes) || bytes < 0) {
      fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, `${label} charge is malformed`);
    }
    const next = observedBytes + bytes;
    if (!Number.isSafeInteger(next) || next > normalizedLimits.maxTotalBytes) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.RESOURCE_LIMIT_EXCEEDED,
        `${label} exceeds its cumulative byte limit at ${itemLabel}`,
        { limitBytes: normalizedLimits.maxTotalBytes, projectedBytes: next },
      );
    }
    observedBytes = next;
    return observedBytes;
  };
  return Object.freeze({ charge, remainingLimit, snapshot: () => observedBytes });
}

function projectedAllocatedWriteBytes(byteLength, allocationUnitBytes) {
  if (
    !Number.isSafeInteger(byteLength) || byteLength < 0 ||
    !Number.isSafeInteger(allocationUnitBytes) || allocationUnitBytes < 1
  ) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "projected write geometry is malformed");
  }
  if (byteLength === 0) return 0;
  const projected = Math.ceil(byteLength / allocationUnitBytes) * allocationUnitBytes;
  if (!Number.isSafeInteger(projected)) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.RESOURCE_LIMIT_EXCEEDED, "projected write is too large");
  }
  return projected;
}

function gitLooseObjectUpperBound(byteLength) {
  if (!Number.isSafeInteger(byteLength) || byteLength < 0) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "Git object length is malformed");
  }
  const headerBytes = Buffer.byteLength(`blob ${byteLength}\0`, "ascii");
  const inputBytes = byteLength + headerBytes;
  // zlib's documented compressBound formula, applied to Git's header-plus-blob input.
  const bound = inputBytes + Math.floor(inputBytes / 4096) +
    Math.floor(inputBytes / 16384) + Math.floor(inputBytes / 33554432) + 13;
  if (!Number.isSafeInteger(bound)) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.RESOURCE_LIMIT_EXCEEDED, "Git object projection is too large");
  }
  return bound;
}

function gitPackArtifactUpperBounds(pack, objectFormat) {
  if (
    !Buffer.isBuffer(pack) || pack.length < 12 || pack.subarray(0, 4).toString("ascii") !== "PACK"
  ) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_OBJECT_MISSING, "Git produced a malformed pack header");
  }
  const version = pack.readUInt32BE(4);
  if (version !== 2 && version !== 3) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_OBJECT_MISSING,
      `Git produced unsupported pack version ${version}`,
    );
  }
  const objectCount = pack.readUInt32BE(8);
  const hashBytes = objectFormat === "sha256" ? 32 : objectFormat === "sha1" ? 20 : 0;
  if (hashBytes === 0) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_OBJECT_MISSING, "Git object format is unsupported");
  }
  // Pack index v2: header, 256-entry fanout, object IDs, CRCs, 32-bit offsets, the maximum
  // possible 64-bit offset table, and the pack/index checksums.
  const indexUpperBound = 8 + (256 * 4) +
    objectCount * (hashBytes + 4 + 4 + 8) + (2 * hashBytes);
  // Reverse index v1 (RIDX): magic, version, hash id, one uint32 per object, pack checksum,
  // and reverse-index checksum. Git may write this sidecar even when the caller did not request it.
  const reverseIndexUpperBound = 12 + (objectCount * 4) + (2 * hashBytes);
  const logicalBytes = pack.length + indexUpperBound + reverseIndexUpperBound;
  if (!Number.isSafeInteger(logicalBytes)) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.RESOURCE_LIMIT_EXCEEDED, "Git pack projection is too large");
  }
  return Object.freeze({
    indexBytes: indexUpperBound,
    logicalBytes,
    packBytes: pack.length,
    reverseIndexBytes: reverseIndexUpperBound,
  });
}

export function scrubGitEnvironment(environment = process.env) {
  if (environment === null || typeof environment !== "object" || Array.isArray(environment)) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "Git environment must be an object");
  }
  // Deliberately do not inherit HOME, XDG_CONFIG_HOME, SSH/GH helpers, credential agents, or PATH.
  // The argument is validated only so a caller cannot mistake this for an environment-merging API.
  return Object.freeze({
    GIT_ATTR_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_NO_LAZY_FETCH: "1",
    GIT_NO_REPLACE_OBJECTS: "1",
    GIT_OPTIONAL_LOCKS: "0",
    GIT_TERMINAL_PROMPT: "0",
    LANG: "C",
    LC_ALL: "C",
    PATH: "/usr/bin:/bin",
  });
}

export function resolveGitExecutable(candidate = null) {
  const candidates = candidate === null ? ["/usr/bin/git", "/bin/git"] : [candidate];
  for (const executable of candidates) {
    if (typeof executable !== "string" || !path.isAbsolute(executable)) continue;
    try {
      const stat = fs.statSync(executable);
      if (stat.isFile() && (stat.mode & 0o111) !== 0) return executable;
    } catch {}
  }
  fail(
    KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_OBSERVATION_FAILED,
    "no fixed absolute Git executable is available",
  );
}

const GIT_FIXED_ARGUMENTS = Object.freeze([
  "-c", "color.ui=false",
  "-c", "core.quotePath=false",
  "-c", "core.fsmonitor=false",
  "-c", "core.hooksPath=/dev/null",
]);

function requireDirectoryDescriptor(value, label) {
  if (value !== null && (!Number.isInteger(value) || value < 0)) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
      `${label} requires one bound directory descriptor or null`,
    );
  }
  return value;
}

/**
 * Git is launched either at a pathname (private custody scratch and seed directories) or, for
 * every command that touches the live source, through the fixed fchdir launcher with an already
 * bound directory descriptor. In the descriptor form the child never resolves the admitted
 * directory by pathname: its working tree and every relative GIT_* path are resolved from the
 * bound inode, so renaming the source or any of its ancestors between or during commands cannot
 * redirect the command to a look-alike root.
 */
function gitInvocation(resolvedGit, args, directoryFd) {
  const gitArguments = [...GIT_FIXED_ARGUMENTS, ...args];
  if (directoryFd === null) return { arguments: gitArguments, executable: resolvedGit };
  return {
    arguments: ["-e", METADATA_FCHDIR_SCRIPT, "--", resolvedGit, ...gitArguments],
    executable: METADATA_FCHDIR_LAUNCHER,
  };
}

function runGit(root, args, {
  code = null,
  directoryFd = null,
  environment = null,
  gitExecutable = null,
  input = undefined,
  maxBuffer = MAX_TOOL_OUTPUT_BYTES,
  timeoutMs = MAX_CHILD_PROCESS_DURATION_MS,
} = {}) {
  const boundedTimeoutMs = requireCommandTimeoutMs(timeoutMs);
  if (!Number.isSafeInteger(maxBuffer) || maxBuffer < 1 || maxBuffer > MAX_TOOL_OUTPUT_BYTES) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
      "Git output limit must be a positive safe integer within the fixed maximum",
    );
  }
  const boundFd = requireDirectoryDescriptor(directoryFd, "descriptor-bound Git execution");
  const resolvedGit = resolveGitExecutable(gitExecutable);
  const invocation = gitInvocation(resolvedGit, args, boundFd);
  try {
    return execFileSync(
      invocation.executable,
      invocation.arguments,
      {
        cwd: boundFd === null ? root : undefined,
        encoding: null,
        env: environment ?? scrubGitEnvironment(),
        input,
        killSignal: "SIGKILL",
        maxBuffer,
        stdio: [
          input === undefined ? "ignore" : "pipe",
          "pipe",
          "pipe",
          ...(boundFd === null ? [] : [boundFd]),
        ],
        timeout: boundedTimeoutMs,
      },
    );
  } catch (error) {
    const stableCode = childProcessFailureCode(
      error,
      code ?? KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_OBSERVATION_FAILED,
    );
    const stderr = Buffer.isBuffer(error?.stderr)
      ? error.stderr.subarray(0, 4096).toString("utf8")
      : String(error?.stderr ?? "").slice(0, 4096);
    fail(
      stableCode,
      `Git observation failed for ${JSON.stringify(args[0] ?? "command")}`,
      {
        args: args.map(String),
        outputLimitExceeded: ["ENOBUFS", "ERR_CHILD_PROCESS_STDIO_MAXBUFFER"]
          .includes(error?.code),
        stderr,
        timedOut: error?.code === "ETIMEDOUT",
        timeoutMs: boundedTimeoutMs,
      },
      error,
    );
  }
}

function runGitAllowStatus(
  root,
  args,
  allowedStatuses,
  gitExecutable = null,
  timeoutMs = MAX_CHILD_PROCESS_DURATION_MS,
  maxBuffer = MAX_TOOL_OUTPUT_BYTES,
  {
    code = KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_OBSERVATION_FAILED,
    directoryFd = null,
    environment = null,
  } = {},
) {
  const boundedTimeoutMs = requireCommandTimeoutMs(timeoutMs);
  if (!Number.isSafeInteger(maxBuffer) || maxBuffer < 1 || maxBuffer > MAX_TOOL_OUTPUT_BYTES) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
      "Git output limit must be a positive safe integer within the fixed maximum",
    );
  }
  const boundFd = requireDirectoryDescriptor(directoryFd, "descriptor-bound Git execution");
  const resolvedGit = resolveGitExecutable(gitExecutable);
  const invocation = gitInvocation(resolvedGit, args, boundFd);
  const result = spawnSync(
    invocation.executable,
    invocation.arguments,
    {
      cwd: boundFd === null ? root : undefined,
      encoding: null,
      env: environment ?? scrubGitEnvironment(),
      killSignal: "SIGKILL",
      maxBuffer,
      stdio: ["ignore", "pipe", "pipe", ...(boundFd === null ? [] : [boundFd])],
      timeout: boundedTimeoutMs,
    },
  );
  if (result.error !== undefined || !allowedStatuses.has(result.status)) {
    const stableCode = childProcessFailureCode(result.error, code);
    fail(
      stableCode,
      `Git observation returned an unsupported result for ${JSON.stringify(args[0] ?? "command")}`,
      {
        args: args.map(String),
        outputLimitExceeded: ["ENOBUFS", "ERR_CHILD_PROCESS_STDIO_MAXBUFFER"]
          .includes(result.error?.code),
        status: result.status,
        stderr: Buffer.isBuffer(result.stderr)
          ? result.stderr.subarray(0, 4096).toString("utf8")
          : "",
        timedOut: result.error?.code === "ETIMEDOUT",
        timeoutMs: boundedTimeoutMs,
      },
      result.error,
    );
  }
  return result;
}

function runObservedGit(root, args, label, byteBudget, options = {}) {
  const maxBuffer = byteBudget.remainingLimit(label);
  const bytes = runGit(root, args, { ...options, maxBuffer });
  byteBudget.charge(bytes.length, label);
  return bytes;
}

function oneLine(bytes, label, { allowEmpty = false } = {}) {
  const withoutLf = bytes.length > 0 && bytes[bytes.length - 1] === 0x0a
    ? bytes.subarray(0, -1)
    : bytes;
  if ((!allowEmpty && withoutLf.length === 0) || withoutLf.includes(0x00) || withoutLf.includes(0x0a)) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_OBSERVATION_FAILED,
      `Git returned a malformed ${label}`,
    );
  }
  return decodeUtf8(withoutLf, label);
}

function requireAbsolutePath(value, label) {
  if (typeof value !== "string" || !path.isAbsolute(value) || value.includes("\0")) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
      `${label} must be an absolute pathname`,
    );
  }
  return path.resolve(value);
}

function realpathOrFail(value, code, label) {
  try { return fs.realpathSync(value); }
  catch (error) {
    fail(code, `cannot resolve ${label}`, { path: value }, error);
  }
}

function requireRealDirectory(
  value,
  label,
  {
    expectedIdentity = null,
    expectedIdentityCode = null,
    operationBudget = null,
    privateMode = false,
  } = {},
) {
  if (
    expectedIdentity !== null &&
    (typeof expectedIdentity !== "string" || expectedIdentity.length === 0)
  ) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, `${label} expected identity is malformed`);
  }
  if (
    expectedIdentityCode !== null &&
    (expectedIdentity === null || !ERROR_CODE_SET.has(expectedIdentityCode))
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
      `${label} expected-identity refusal code is malformed`,
    );
  }
  // Confirming a caller-bound identity is a check on a directory the caller already admitted, so
  // every refusal on that path carries the caller's classification (for example SOURCE_CHANGED for
  // the live source root). An unbound inspection keeps the argument/private-root taxonomy.
  const refusalCode = expectedIdentityCode ?? (
    privateMode
      ? KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE
      : KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT
  );
  if (operationBudget !== null) remainingOperationMs(operationBudget, `directory observation for ${label}`);
  const absolute = requireAbsolutePath(value, label);
  let stat;
  try { stat = fs.lstatSync(absolute, { bigint: true }); }
  catch (error) {
    fail(refusalCode, `cannot inspect ${label} ${absolute}`, null, error);
  }
  if (operationBudget !== null) remainingOperationMs(operationBudget, `directory observation for ${label}`);
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    fail(refusalCode, `${label} must be a real directory`, { path: absolute });
  }
  if (expectedIdentity !== null && identityOf(stat) !== expectedIdentity) {
    fail(
      refusalCode,
      `${label} identity changed before inspection`,
      { expectedIdentity, path: absolute, pathIdentity: identityOf(stat) },
    );
  }
  let physical;
  try { physical = fs.realpathSync(absolute); }
  catch (error) {
    fail(refusalCode, `cannot resolve ${label}`, null, error);
  }
  if (operationBudget !== null) remainingOperationMs(operationBudget, `directory observation for ${label}`);
  if (privateMode) {
    const uid = operationEffectiveUid(operationBudget, `private-directory owner check for ${label}`);
    if ((uid !== null && Number(stat.uid) !== uid) || modeOf(stat) !== 0o700) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
        `${label} must be owned by the current account and mode 0700`,
        { mode: modeOf(stat), path: physical, uid: Number(stat.uid) },
      );
    }
    try {
      observeMetadata(
        physical,
        false,
        operationBudget,
        stat,
        Object.freeze({ identity: identityOf(stat), path: physical }),
      );
    } catch (error) {
      if (
        error instanceof KnockoutWorkspaceError &&
        error.code === KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE
      ) {
        fail(
          KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
          `${label} changed during private-metadata inspection`,
          { path: physical },
          error,
        );
      }
      throw error;
    }
    let confirmed;
    try { confirmed = fs.lstatSync(absolute, { bigint: true }); }
    catch (error) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
        `${label} changed during private-metadata inspection`,
        { path: physical },
        error,
      );
    }
    if (
      confirmed.isSymbolicLink() || !confirmed.isDirectory() ||
      identityOf(confirmed) !== identityOf(stat) || modeOf(confirmed) !== 0o700 ||
      (uid !== null && Number(confirmed.uid) !== uid) ||
      String(confirmed.ctimeNs) !== String(stat.ctimeNs)
    ) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
        `${label} changed during private-metadata inspection`,
        { path: physical },
      );
    }
  }
  if (operationBudget !== null) remainingOperationMs(operationBudget, `directory observation for ${label}`);
  return Object.freeze({
    identity: identityOf(stat),
    observation: directoryObservation(stat),
    path: physical,
  });
}

function validDirectoryObservation(value) {
  return (
    value !== null && typeof value === "object" && !Array.isArray(value) &&
    typeof value.identity === "string" && typeof value.dev === "string" &&
    typeof value.ino === "string" && value.identity === `${value.dev}:${value.ino}` &&
    typeof value.ctimeNs === "string" && typeof value.mtimeNs === "string" &&
    Number.isInteger(value.mode) && Number.isInteger(value.nlink)
  );
}

function sameDirectoryObservation(left, right) {
  return canonicalJsonBytes(left).equals(canonicalJsonBytes(right));
}

function validBoundDirectory(value) {
  return (
    value !== null && typeof value === "object" && !Array.isArray(value) &&
    typeof value.identity === "string" && value.identity.length > 0 &&
    typeof value.path === "string" && path.isAbsolute(value.path)
  );
}

/**
 * Source-root reopen audit. The live source is named by pathname only at the moments listed
 * here; everything in between runs on bound directory descriptors (bindDirectoryDescriptor,
 * boundEntryStat, readBoundGitFile, descriptor-bound Git). One physical identity and the full
 * directory observation captured at entry (ctime changes when the directory itself is renamed
 * away and back; mtime/ctime/nlink when its entries change) are confirmed at every reopen through
 * success:
 *   1. capture entry                     requireRealDirectory binds identity + observation + path
 *   2. Git observation start / end       observeSourceGit binds the root descriptor, confirms it
 *   3. workspace census root             censusWorkspace expectedRoot (identity + pathname)
 *   4. snapshot composition              Git-observation root observation == census "." node
 *   5. worktree copy start / end         copyLiveWorktree expectedSourceRoot
 *   6. standalone Git ingestion          initializeStandaloneGit binds root + common descriptors
 *   7. final closeout                    closeoutSourceGit re-binds root, Git and common dirs and
 *                                        re-reads index, companion, HEAD and ref
 *   8. state commit and publication      every witness confirms identity + observation
 * Every refusal classifies as SOURCE_CHANGED so capture retry and exhaustion semantics stay stable.
 */
function requireSourceRoot(
  value,
  expected,
  operationBudget = null,
  {
    label = "source root",
    mismatchCode = KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED,
    observation = null,
  } = {},
) {
  if (expected !== null && !validBoundDirectory(expected)) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, `${label} binding is malformed`);
  }
  if (observation !== null && !validDirectoryObservation(observation)) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, `${label} bound observation is malformed`);
  }
  if (!ERROR_CODE_SET.has(mismatchCode)) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, `${label} mismatch code is malformed`);
  }
  const directory = requireRealDirectory(value, label, {
    expectedIdentity: expected === null ? null : expected.identity,
    expectedIdentityCode: expected === null ? null : mismatchCode,
    operationBudget,
  });
  if (expected !== null && directory.path !== expected.path) {
    fail(
      mismatchCode,
      `${label} no longer resolves to its bound physical pathname`,
      { expectedPath: expected.path, path: directory.path },
    );
  }
  if (observation !== null && !sameDirectoryObservation(directory.observation, observation)) {
    fail(
      mismatchCode,
      `${label} changed during the observed interval`,
      { expected: observation, observed: directory.observation, path: directory.path },
    );
  }
  return directory;
}

/**
 * A bound directory is an admitted `{ identity, observation, path }` plus an open O_DIRECTORY
 * descriptor on that very inode. Descriptor-relative tools (see boundEntryStat) and descriptor-
 * bound Git commands resolve names from the inode, never from the pathname, so the only pathname
 * interval left is the one open() below, which is closed by the fstat identity comparison.
 */
function bindDirectoryDescriptor(directory, label, code, operationBudget = null) {
  if (!validBoundDirectory(directory) || !validDirectoryObservation(directory.observation)) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, `${label} binding is malformed`);
  }
  if (operationBudget !== null) remainingOperationMs(operationBudget, `descriptor bind for ${label}`);
  let fd;
  try { fd = fs.openSync(directory.path, fs.constants.O_RDONLY | DIRECTORY | NOFOLLOW); }
  catch (error) {
    fail(code, `cannot bind ${label} ${directory.path}`, { path: directory.path }, error);
  }
  const closeProvisional = createDescriptorCloser(
    fd,
    code,
    `cannot release the provisional descriptor for ${label}`,
    { path: directory.path },
  );
  try {
    let opened;
    try { opened = fs.fstatSync(fd, { bigint: true }); }
    catch (error) {
      fail(code, `cannot observe bound ${label}`, { path: directory.path }, error);
    }
    if (
      !opened.isDirectory() || identityOf(opened) !== directory.identity ||
      !sameDirectoryObservation(directoryObservation(opened), directory.observation)
    ) {
      fail(
        code,
        `${label} changed while binding its directory descriptor`,
        {
          expectedIdentity: directory.identity,
          observedIdentity: identityOf(opened),
          path: directory.path,
        },
      );
    }
    if (operationBudget !== null) remainingOperationMs(operationBudget, `descriptor bind for ${label}`);
    const bound = Object.freeze({
      fd,
      identity: directory.identity,
      observation: directory.observation,
      path: directory.path,
    });
    boundDirectoryLeaseStates.set(bound, { fd });
    return bound;
  } catch (primary) {
    const failures = [];
    try { closeProvisional(); }
    catch (cleanupError) { failures.push(cleanupError); }
    throw combineWorkspaceFailures(
      primary,
      failures,
      code,
      `cannot release ${label} after descriptor binding refusal`,
    );
  }
}

function confirmBoundDirectory(bound, label, code, operationBudget = null) {
  if (operationBudget !== null) remainingOperationMs(operationBudget, `descriptor confirmation for ${label}`);
  const leaseState = boundDirectoryLeaseStates.get(bound);
  if (leaseState === undefined || leaseState.fd === null) {
    fail(code, `${label} descriptor was already released`, { path: bound?.path ?? null });
  }
  let opened;
  let atPath;
  try {
    opened = fs.fstatSync(leaseState.fd, { bigint: true });
    atPath = fs.lstatSync(bound.path, { bigint: true });
  } catch (error) {
    fail(code, `${label} can no longer be observed`, { path: bound.path }, error);
  }
  if (
    !opened.isDirectory() || atPath.isSymbolicLink() || !atPath.isDirectory() ||
    identityOf(opened) !== bound.identity || identityOf(atPath) !== bound.identity ||
    !sameDirectoryObservation(directoryObservation(opened), bound.observation) ||
    !sameDirectoryObservation(directoryObservation(atPath), bound.observation)
  ) {
    fail(
      code,
      `${label} changed after it was bound`,
      {
        expected: bound.observation,
        observedDescriptor: directoryObservation(opened),
        observedPath: directoryObservation(atPath),
        path: bound.path,
      },
    );
  }
  return bound;
}

function confirmBoundDirectoryIdentity(
  bound,
  label,
  code,
  operationBudget = null,
  { privateMode = false } = {},
) {
  if (operationBudget !== null) remainingOperationMs(operationBudget, `identity confirmation for ${label}`);
  const leaseState = boundDirectoryLeaseStates.get(bound);
  if (leaseState === undefined || leaseState.fd === null) {
    fail(code, `${label} descriptor was already released`, { path: bound?.path ?? null });
  }
  let opened;
  let atPath;
  let physical;
  try {
    opened = fs.fstatSync(leaseState.fd, { bigint: true });
    atPath = fs.lstatSync(bound.path, { bigint: true });
    physical = fs.realpathSync(bound.path);
  } catch (error) {
    fail(code, `${label} can no longer be observed`, { path: bound.path }, error);
  }
  const uid = operationEffectiveUid(operationBudget, `owner confirmation for ${label}`);
  if (
    !opened.isDirectory() || atPath.isSymbolicLink() || !atPath.isDirectory() ||
    physical !== bound.path || identityOf(opened) !== bound.identity ||
    identityOf(atPath) !== bound.identity ||
    (privateMode && (modeOf(opened) !== 0o700 || modeOf(atPath) !== 0o700)) ||
    (privateMode && uid !== null &&
      (Number(opened.uid) !== uid || Number(atPath.uid) !== uid))
  ) {
    fail(
      code,
      `${label} no longer names its bound directory identity`,
      {
        expectedIdentity: bound.identity,
        observedDescriptorIdentity: identityOf(opened),
        observedPathIdentity: identityOf(atPath),
        path: bound.path,
      },
    );
  }
  return bound;
}

function closeBoundDirectory(bound, label, code) {
  if (bound === null || bound === undefined) return;
  const leaseState = boundDirectoryLeaseStates.get(bound);
  if (leaseState === undefined || leaseState.fd === null) return;
  const closingFd = leaseState.fd;
  leaseState.fd = null;
  try { fs.closeSync(closingFd); }
  catch (error) {
    fail(code, `cannot release the bound descriptor for ${label}`, { path: bound.path }, error);
  }
}

function requireBoundEntryName(name, label) {
  if (
    typeof name !== "string" || name.length === 0 || name.includes("\0") ||
    path.isAbsolute(name) ||
    name.split("/").some((component) => component === "" || component === "." || component === "..")
  ) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, `${label} entry name is malformed`);
  }
  return name;
}

function boundEntryType(text) {
  switch (text) {
    case "Directory":
    case "directory":
      return "directory";
    case "Regular File":
    case "regular file":
    case "regular empty file":
      return "file";
    case "Symbolic Link":
    case "symbolic link":
      return "symlink";
    default:
      return "other";
  }
}

/**
 * Descriptor-relative identity of one entry below a bound directory. The fixed launcher performs
 * fchdir(descriptor) and the stat tool names the entry relatively, so the answer is the entry of
 * the bound inode itself; no ancestor pathname can redirect it. Returns null when the entry is
 * absent and refuses every other tool failure with the caller's classification.
 */
function boundEntryStat(bound, name, label, { code, operationBudget = null } = {}) {
  const relative = requireBoundEntryName(name, label);
  if (operationBudget !== null) remainingOperationMs(operationBudget, `bound entry stat for ${label}`);
  let executable;
  let args;
  if (process.platform === "darwin") {
    executable = "/usr/bin/stat";
    args = ["-f", "%d:%i:%HT", "--", relative];
  } else if (process.platform === "linux") {
    executable = findExecutable(["/usr/bin/stat", "/bin/stat"]);
    if (executable === null) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_OBSERVATION_FAILED,
        `no fixed stat tool is available for ${label}`,
        { launcherUnavailable: false },
      );
    }
    args = ["-c", "%d:%i:%F", "--", relative];
  } else {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_LAYOUT_UNSUPPORTED,
      `descriptor-relative observation is unsupported on ${process.platform}`,
    );
  }
  const result = spawnSync(
    METADATA_FCHDIR_LAUNCHER,
    ["-e", METADATA_FCHDIR_SCRIPT, "--", executable, ...args],
    {
      encoding: null,
      env: { LANG: "C", LC_ALL: "C", PATH: "/usr/bin:/bin" },
      killSignal: "SIGKILL",
      maxBuffer: 64 * 1024,
      stdio: ["ignore", "pipe", "pipe", bound.fd],
      timeout: metadataTimeout(operationBudget, `bound entry stat for ${label}`),
    },
  );
  const stderr = Buffer.isBuffer(result.stderr) ? result.stderr.toString("utf8") : "";
  if (result.error !== undefined) {
    const failureCode = result.error?.code === "ENOENT"
      ? KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_OBSERVATION_FAILED
      : childProcessFailureCode(result.error, code);
    fail(
      failureCode,
      `cannot observe ${label} relative to its bound directory`,
      {
        launcher: METADATA_FCHDIR_LAUNCHER,
        launcherUnavailable: result.error?.code === "ENOENT",
        name: relative,
        timedOut: result.error?.code === "ETIMEDOUT",
      },
      result.error,
    );
  }
  if (result.status !== 0) {
    if (result.status === 1 && /No such file or directory/u.test(stderr)) return null;
    fail(
      code,
      `cannot observe ${label} relative to its bound directory`,
      { name: relative, status: result.status, stderr: stderr.slice(0, 4096) },
    );
  }
  const match = /^(\d+):(\d+):([^\n]+)\n?$/u.exec(
    Buffer.isBuffer(result.stdout) ? result.stdout.toString("utf8") : "",
  );
  if (match === null || stderr.length !== 0) {
    fail(code, `unrecognized bound observation for ${label}`, { name: relative });
  }
  return Object.freeze({
    identity: `${match[1]}:${match[2]}`,
    name: relative,
    type: boundEntryType(match[3]),
  });
}

/**
 * Read one regular file below a bound directory. The bytes are descriptor-read at the pathname
 * (observeGitFile), and the inode that was read must be the very entry the bound directory holds
 * both before and after the read, so the read cannot have been redirected through a substituted
 * ancestor. Returns null for an absent entry only when `optional` is set.
 */
function readBoundGitFile(bound, name, label, options = {}) {
  const {
    byteBudget = null,
    code = KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED,
    limits = KNOCKOUT_WORKSPACE_CAPTURE_LIMITS,
    maxBytes = null,
    operationBudget = null,
    optional = false,
    retainBytes = false,
    typeCode = KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_LAYOUT_UNSUPPORTED,
  } = options;
  const before = boundEntryStat(bound, name, label, { code, operationBudget });
  if (before === null) {
    if (optional) return null;
    fail(code, `${label} is absent from its bound directory`, { name, path: bound.path });
  }
  if (before.type !== "file") {
    fail(typeCode, `${label} is not a regular file`, { name, path: bound.path, type: before.type });
  }
  const observed = observeGitFile(path.join(bound.path, ...name.split("/")), label, {
    byteBudget,
    limits,
    maxBytes,
    metadataAnchor: bound,
    operationBudget,
    retainBytes,
  });
  if (observed.observation.identity !== before.identity) {
    fail(
      code,
      `${label} was not read from its bound directory`,
      { boundIdentity: before.identity, name, readIdentity: observed.observation.identity },
    );
  }
  const after = boundEntryStat(bound, name, label, { code, operationBudget });
  if (after === null || after.identity !== before.identity || after.type !== "file") {
    fail(
      code,
      `${label} changed in its bound directory during the read`,
      { after: after?.identity ?? null, before: before.identity, name },
    );
  }
  return observed;
}

/**
 * Hold a bounded set of Git control files, their direct parent directories, and optional absence
 * witnesses until one terminal confirmation. No descriptor enters canonical evidence.
 */
function createBoundControlCustody({ byteBudget, code, limits, operationBudget }) {
  const heldFiles = [];
  const absences = [];
  const ownedBounds = [];
  const parentBounds = new Map();
  const releaseLease = createReleaseLease({
    fallbackCode: code,
    message: "Git control custody release failed",
  });
  const statObservation = (stat) => Object.freeze({
    ctimeNs: String(stat.ctimeNs),
    identity: identityOf(stat),
    mode: modeOf(stat),
    mtimeNs: String(stat.mtimeNs),
    nlink: Number(stat.nlink),
    size: Number(stat.size),
  });
  const resolveParent = (baseBound, name, label, optional, entryCode) => {
    const relative = requireBoundEntryName(name, label);
    const components = relative.split("/");
    const basename = components.pop();
    let parent = baseBound;
    let prefix = "";
    for (let index = 0; index < components.length; index++) {
      const component = components[index];
      prefix = prefix === "" ? component : `${prefix}/${component}`;
      const key = `${baseBound.identity}\0${prefix}`;
      const cached = parentBounds.get(key);
      if (cached !== undefined) {
        parent = cached;
        continue;
      }
      const entry = boundEntryStat(parent, component, `${label} parent ${prefix}`, {
        code: entryCode,
        operationBudget,
      });
      if (entry === null) {
        if (!optional) fail(entryCode, `${label} parent is absent`, { name, prefix });
        return Object.freeze({
          absentName: components.slice(index).concat(basename).join("/"),
          basename: null,
          parent,
        });
      }
      if (entry.type !== "directory") {
        fail(entryCode, `${label} parent is not a directory`, { name, prefix, type: entry.type });
      }
      const directory = requireRealDirectory(path.join(parent.path, component), `${label} parent`, {
        expectedIdentity: entry.identity,
        expectedIdentityCode: entryCode,
        operationBudget,
      });
      const bound = bindDirectoryDescriptor(directory, `${label} parent`, entryCode, operationBudget);
      releaseLease.ownBound(bound, `${label} parent`, entryCode);
      const after = boundEntryStat(parent, component, `${label} parent ${prefix}`, {
        code: entryCode,
        operationBudget,
      });
      if (after === null || after.type !== "directory" || after.identity !== bound.identity) {
        fail(entryCode, `${label} parent changed while it was bound`, { name, prefix });
      }
      ownedBounds.push(Object.freeze({ bound, code: entryCode, label: `${label} parent` }));
      parentBounds.set(key, bound);
      parent = bound;
    }
    return Object.freeze({ absentName: null, basename, parent });
  };
  const acquire = (baseBound, name, label, options = {}) => {
    releaseLease.assertActive(code);
    const optional = options.optional ?? false;
    const entryCode = options.code ?? code;
    if (!ERROR_CODE_SET.has(entryCode)) {
      fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, `${label} refusal code is malformed`);
    }
    const resolved = resolveParent(baseBound, name, label, optional, entryCode);
    if (resolved.absentName !== null) {
      absences.push(Object.freeze({
        code: entryCode,
        label,
        name: resolved.absentName,
        parent: resolved.parent,
      }));
      return null;
    }
    const observed = readBoundGitFile(resolved.parent, resolved.basename, label, {
      byteBudget,
      code: entryCode,
      limits,
      maxBytes: options.maxBytes ?? null,
      operationBudget,
      optional,
      retainBytes: options.retainBytes ?? false,
      typeCode: KNOCKOUT_WORKSPACE_ERROR_CODES.SPECIAL_NODE_UNSUPPORTED,
    });
    if (observed === null) {
      absences.push(Object.freeze({
        code: entryCode,
        label,
        name: resolved.basename,
        parent: resolved.parent,
      }));
      return null;
    }
    let fd;
    try {
      fd = fs.openSync(observed.path, fs.constants.O_RDONLY | NOFOLLOW);
    } catch (error) {
      fail(entryCode, `${label} cannot be held through final closeout`, { path: observed.path }, error);
    }
    releaseLease.add(createDescriptorCloser(
      fd,
      entryCode,
      `${label} cannot be released after final custody`,
      { path: observed.path },
    ));
    let stat;
    try { stat = fs.fstatSync(fd, { bigint: true }); }
    catch (error) {
      fail(entryCode, `${label} cannot be observed after it was held`, { path: observed.path }, error);
    }
    if (!stat.isFile() || !sameFileObservation(statObservation(stat), observed.observation)) {
      fail(entryCode, `${label} changed while entering final custody`, { path: observed.path });
    }
    const atParent = boundEntryStat(resolved.parent, resolved.basename, label, {
      code: entryCode,
      operationBudget,
    });
    if (atParent === null || atParent.type !== "file" || atParent.identity !== observed.observation.identity) {
      fail(entryCode, `${label} is no longer held by its bound parent`, { path: observed.path });
    }
    heldFiles.push(Object.freeze({
      basename: resolved.basename,
      code: entryCode,
      fd,
      label,
      observation: observed.observation,
      parent: resolved.parent,
      path: observed.path,
    }));
    return observed;
  };
  const confirm = (phase) => {
    releaseLease.assertActive(code);
    for (const file of heldFiles) {
      let stat;
      try { stat = fs.fstatSync(file.fd, { bigint: true }); }
      catch (error) {
        fail(file.code, `${file.label} cannot be re-observed`, { path: file.path, phase }, error);
      }
      const atParent = boundEntryStat(file.parent, file.basename, file.label, {
        code: file.code,
        operationBudget,
      });
      if (
        !stat.isFile() || !sameFileObservation(statObservation(stat), file.observation) ||
        atParent === null || atParent.type !== "file" ||
        atParent.identity !== file.observation.identity
      ) {
        fail(file.code, `${file.label} changed during final custody`, { path: file.path, phase });
      }
    }
    for (const absence of absences) {
      if (boundEntryStat(absence.parent, absence.name, absence.label, {
        code: absence.code,
        operationBudget,
      }) !== null) {
        fail(absence.code, `${absence.label} appeared during final custody`, {
          name: absence.name,
          phase,
        });
      }
    }
    for (const owned of ownedBounds) {
      confirmBoundDirectory(owned.bound, owned.label, owned.code, operationBudget);
    }
  };
  const release = (primaryError = null) => releaseLease.release(primaryError);
  return Object.freeze({ acquire, confirm, release });
}

function bindBoundChildDirectory(parentBound, name, label, code, operationBudget) {
  const relative = requireBoundEntryName(name, label);
  if (relative.includes("/")) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, `${label} must be one direct entry`);
  }
  const before = boundEntryStat(parentBound, relative, label, { code, operationBudget });
  if (before === null || before.type !== "directory") {
    fail(code, `${label} is not a directory below its bound parent`, {
      name: relative,
      type: before?.type ?? null,
    });
  }
  const directory = requireRealDirectory(path.join(parentBound.path, relative), label, {
    expectedIdentity: before.identity,
    expectedIdentityCode: code,
    operationBudget,
  });
  const bound = bindDirectoryDescriptor(directory, label, code, operationBudget);
  const after = boundEntryStat(parentBound, relative, label, { code, operationBudget });
  if (after === null || after.type !== "directory" || after.identity !== bound.identity) {
    const primary = workspaceError(
      code,
      `${label} changed while its descriptor was bound`,
      { name: relative },
    );
    const failures = [];
    try { closeBoundDirectory(bound, label, code); }
    catch (error) { failures.push(error); }
    throw combineWorkspaceFailures(
      primary,
      failures,
      code,
      `${label} release failed after binding refusal`,
    );
  }
  return bound;
}

/**
 * Descriptor-rooted read authority for the live object store. Git receives only `.` and `..`:
 * its cwd and object directory are the held `objects` inode, while its Git directory is that
 * inode's currently witnessed bound common-directory parent. Local alternate stores are refused
 * and their absence stays in custody around every object command.
 */
function createBoundObjectAuthority(
  commonBound,
  objectFormat,
  {
    byteBudget,
    configFile,
    limits,
    nestedCommondir,
    operationBudget,
    worktreeConfigFile,
  },
) {
  if (!["sha1", "sha256"].includes(objectFormat)) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "object authority format is malformed");
  }
  if (
    !validGitFileEvidence(configFile) ||
    (worktreeConfigFile !== null && !validGitFileEvidence(worktreeConfigFile)) ||
    nestedCommondir !== null
  ) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "object authority controls are malformed");
  }
  const code = KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED;
  const releaseLease = createReleaseLease({
    fallbackCode: code,
    message: "source object authority release failed",
  });
  let objectsBound;
  let custody;
  try {
    objectsBound = releaseLease.ownBound(
      bindBoundChildDirectory(
        commonBound,
        "objects",
        "source object directory",
        code,
        operationBudget,
      ),
      "source object directory",
      code,
    );
    custody = createBoundControlCustody({ byteBudget, code, limits, operationBudget });
    releaseLease.add(() => custody.release());
    const heldConfig = custody.acquire(commonBound, "config", "source object-child Git config", {
      code,
      maxBytes: MAX_GIT_CONTROL_TEXT_BYTES,
    });
    if (!sameGitFileEvidence(heldConfig, configFile)) {
      fail(code, "source object-child Git config changed before custody");
    }
    const heldWorktreeConfig = custody.acquire(
      commonBound,
      "config.worktree",
      "source object-child Git worktree config",
      {
        code,
        maxBytes: MAX_GIT_CONTROL_TEXT_BYTES,
        optional: true,
      },
    );
    if (!sameOptionalGitFileEvidence(heldWorktreeConfig, worktreeConfigFile)) {
      fail(code, "source object-child Git worktree config changed before custody");
    }
    const heldNestedCommondir = custody.acquire(
      commonBound,
      "commondir",
      "source object-child nested commondir",
      {
        code,
        maxBytes: MAX_GIT_CONTROL_TEXT_BYTES,
        optional: true,
      },
    );
    if (heldNestedCommondir !== null) {
      fail(code, "source object-child nested commondir appeared before custody");
    }
    for (const name of ["info/alternates", "info/http-alternates"]) {
      const alternate = custody.acquire(
        objectsBound,
        name,
        `source object-store ${name}`,
        {
          code,
          maxBytes: MAX_GIT_CONTROL_TEXT_BYTES,
          optional: true,
        },
      );
      if (alternate !== null) {
        fail(
          KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_LAYOUT_UNSUPPORTED,
          `source object-store ${name} is unsupported for isolated capture`,
        );
      }
    }
  } catch (error) {
    throw releaseLeaseError(releaseLease, error);
  }
  const release = (primaryError = null) => releaseLease.release(primaryError);
  const confirm = (phase) => {
    releaseLease.assertActive(code);
    confirmBoundDirectory(
      commonBound,
      `Git common directory ${phase}`,
      code,
      operationBudget,
    );
    const entry = boundEntryStat(
      commonBound,
      "objects",
      `source object directory ${phase}`,
      { code, operationBudget },
    );
    if (entry === null || entry.type !== "directory" || entry.identity !== objectsBound.identity) {
      fail(code, `source object directory changed ${phase}`, {
        expectedIdentity: objectsBound.identity,
        observed: entry,
      });
    }
    confirmBoundDirectory(
      objectsBound,
      `source object directory ${phase}`,
      code,
      operationBudget,
    );
    custody.confirm(phase);
  };
  const run = (label, callback) => {
    releaseLease.assertActive(code);
    if (typeof callback !== "function") {
      fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "object authority callback is malformed");
    }
    confirm(`before ${label}`);
    let result;
    let primaryError = null;
    try { result = callback(objectsBound.fd, environment); }
    catch (error) { primaryError = error; }
    const secondaryErrors = [];
    try { confirm(`after ${label}`); }
    catch (error) { secondaryErrors.push(error); }
    const combined = combineWorkspaceFailures(
      primaryError,
      secondaryErrors,
      code,
      `source object authority changed during ${label}`,
      { label },
    );
    if (combined !== null) throw combined;
    return result;
  };
  const environment = Object.freeze({
    ...scrubGitEnvironment(),
    GIT_COMMON_DIR: "..",
    GIT_DIR: "..",
    GIT_OBJECT_DIRECTORY: ".",
  });
  return Object.freeze({ confirm, environment, objectsBound, release, run });
}

function pathInside(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative === "" || (!relative.startsWith(`..${path.sep}`) && relative !== "..");
}

function allocatedBytesOf(stat, label) {
  const allocated = typeof stat.blocks === "bigint" && stat.blocks >= 0n
    ? stat.blocks * 512n
    : stat.size;
  if (allocated < 0n || allocated > BigInt(Number.MAX_SAFE_INTEGER)) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.RESOURCE_LIMIT_EXCEEDED,
      `${label} exceeds safe allocated-size bounds`,
    );
  }
  return Number(allocated);
}

function observeRegularFile(abs, expected = null, options = {}) {
  const {
    maxAllocatedBytes = KNOCKOUT_WORKSPACE_CAPTURE_LIMITS.maxAllocatedBytes,
    maxBytes = KNOCKOUT_WORKSPACE_CAPTURE_LIMITS.maxFileBytes,
    operationBudget = null,
  } = options;
  if (
    !Number.isSafeInteger(maxBytes) || maxBytes < 1 ||
    maxBytes > KNOCKOUT_WORKSPACE_CAPTURE_LIMITS.maxFileBytes
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
      "maxBytes must be a positive safe integer no greater than the fixed maximum",
    );
  }
  if (
    !Number.isSafeInteger(maxAllocatedBytes) || maxAllocatedBytes < 0 ||
    maxAllocatedBytes > KNOCKOUT_WORKSPACE_CAPTURE_LIMITS.maxAllocatedBytes
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
      "maxAllocatedBytes must be a non-negative safe integer within the fixed maximum",
    );
  }
  if (operationBudget !== null) remainingOperationMs(operationBudget, `regular-file read for ${abs}`);
  if (NOFOLLOW === 0) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.SPECIAL_NODE_UNSUPPORTED,
      "this platform has no O_NOFOLLOW",
    );
  }
  let first;
  try { first = fs.lstatSync(abs, { bigint: true }); }
  catch (error) { fail(KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE, `${abs} disappeared`, null, error); }
  if (operationBudget !== null) remainingOperationMs(operationBudget, `regular-file read for ${abs}`);
  if (first.isSymbolicLink() || !first.isFile()) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.SPECIAL_NODE_UNSUPPORTED, `${abs} is not a regular file`);
  }
  let fd;
  try { fd = fs.openSync(abs, fs.constants.O_RDONLY | NOFOLLOW); }
  catch (error) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE, `${abs} could not be opened safely`, null, error);
  }
  let result = null;
  let pendingError = null;
  try {
    if (operationBudget !== null) remainingOperationMs(operationBudget, `regular-file read for ${abs}`);
    const opened = fs.fstatSync(fd, { bigint: true });
    if (operationBudget !== null) remainingOperationMs(operationBudget, `regular-file read for ${abs}`);
    if (!opened.isFile() || identityOf(opened) !== identityOf(first)) {
      fail(KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE, `${abs} changed while opening`);
    }
    if (opened.size < 0n || opened.size > BigInt(maxBytes)) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.RESOURCE_LIMIT_EXCEEDED,
        `${abs} exceeds the admitted per-file byte limit`,
        { limitBytes: maxBytes, observedBytes: String(opened.size) },
      );
    }
    const byteLength = Number(opened.size);
    if (!Number.isSafeInteger(byteLength)) {
      fail(KNOCKOUT_WORKSPACE_ERROR_CODES.RESOURCE_LIMIT_EXCEEDED, `${abs} exceeds safe size bounds`);
    }
    const openedAllocatedBytes = allocatedBytesOf(opened, abs);
    if (openedAllocatedBytes > maxAllocatedBytes) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.RESOURCE_LIMIT_EXCEEDED,
        `${abs} exceeds the admitted allocated-byte limit`,
        { limitBytes: maxAllocatedBytes, observedBytes: openedAllocatedBytes },
      );
    }
    const bytes = Buffer.allocUnsafe(byteLength);
    let offset = 0;
    while (offset < byteLength) {
      if (operationBudget !== null) remainingOperationMs(operationBudget, `regular-file read for ${abs}`);
      const length = Math.min(WORKSPACE_COPY_BUFFER_BYTES, byteLength - offset);
      const read = fs.readSync(fd, bytes, offset, length, null);
      if (operationBudget !== null) remainingOperationMs(operationBudget, `regular-file read for ${abs}`);
      if (read === 0) {
        fail(KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE, `${abs} shortened while reading`);
      }
      offset += read;
    }
    const after = fs.fstatSync(fd, { bigint: true });
    const atPath = fs.lstatSync(abs, { bigint: true });
    if (operationBudget !== null) remainingOperationMs(operationBudget, `regular-file read for ${abs}`);
    const stable =
      after.isFile() && atPath.isFile() &&
      identityOf(opened) === identityOf(after) && identityOf(opened) === identityOf(atPath) &&
      opened.mode === after.mode && opened.mode === atPath.mode &&
      opened.nlink === after.nlink && opened.nlink === atPath.nlink &&
      opened.size === after.size && opened.size === atPath.size &&
      opened.blocks === after.blocks && opened.blocks === atPath.blocks &&
      opened.mtimeNs === after.mtimeNs && opened.mtimeNs === atPath.mtimeNs &&
      opened.ctimeNs === after.ctimeNs && opened.ctimeNs === atPath.ctimeNs;
    if (!stable) fail(KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE, `${abs} changed while reading`);
    const observation = Object.freeze({
      allocatedBytes: openedAllocatedBytes,
      ctimeNs: String(opened.ctimeNs),
      dev: String(opened.dev),
      identity: identityOf(opened),
      ino: String(opened.ino),
      mode: modeOf(opened),
      mtimeNs: String(opened.mtimeNs),
      nlink: Number(opened.nlink),
      size: Number(opened.size),
    });
    const digest = sha256(bytes);
    if (
      expected !== null &&
      (expected.sha256 !== digest || expected.observation.identity !== observation.identity ||
        expected.observation.ctimeNs !== observation.ctimeNs ||
        expected.observation.mtimeNs !== observation.mtimeNs ||
        expected.observation.size !== observation.size ||
        expected.observation.allocatedBytes !== observation.allocatedBytes ||
        expected.observation.mode !== observation.mode ||
        expected.observation.nlink !== observation.nlink)
    ) {
      fail(KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE, `${abs} differs from its census`);
    }
    result = Object.freeze({ bytes, observation, sha256: digest });
  } catch (error) {
    pendingError = error instanceof KnockoutWorkspaceError
      ? error
      : workspaceError(
          KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE,
          `${abs} could not be read as one stable regular file`,
          null,
          error,
        );
  } finally {
    try { fs.closeSync(fd); }
    catch (error) {
      if (pendingError === null) {
        pendingError = workspaceError(
          KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE,
          `${abs} could not be closed after observation`,
          null,
          error,
        );
      }
    }
  }
  if (pendingError !== null) throw pendingError;
  if (operationBudget !== null) remainingOperationMs(operationBudget, `regular-file read for ${abs}`);
  return result;
}

function toolResult(
  executable,
  args,
  code,
  label,
  timeoutMs = MAX_CHILD_PROCESS_DURATION_MS,
  directoryFd,
  inheritedDescriptors = [],
) {
  const boundedTimeoutMs = requireCommandTimeoutMs(timeoutMs);
  if (!Number.isInteger(directoryFd) || directoryFd < 0) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
      "metadata tool requires one bound directory descriptor",
    );
  }
  if (
    !Array.isArray(inheritedDescriptors) ||
    inheritedDescriptors.length > MAC_METADATA_BATCH_NODE_LIMIT ||
    inheritedDescriptors.some((fd) => !Number.isInteger(fd) || fd < 0)
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
      "metadata tool inherited-descriptor batch is malformed",
    );
  }
  // Node exposes no fchdir operation and Darwin's /dev/fd/<n> cannot be traversed. This fixed,
  // argument-only launcher performs exactly fchdir(descriptor) + exec(target, argv): no pathname
  // lookup of the admitted anchor and no shell interpolation can occur in the metadata child.
  const result = spawnSync(
    METADATA_FCHDIR_LAUNCHER,
    ["-e", METADATA_FCHDIR_SCRIPT, "--", executable, ...args],
    {
      encoding: null,
      env: { LANG: "C", LC_ALL: "C", PATH: "/usr/bin:/bin" },
      killSignal: "SIGKILL",
      maxBuffer: MAX_TOOL_OUTPUT_BYTES,
      stdio: ["ignore", "pipe", "pipe", directoryFd, ...inheritedDescriptors],
      timeout: boundedTimeoutMs,
    },
  );
  if (
    result.error !== undefined || result.status !== 0 ||
    !Buffer.isBuffer(result.stdout) || !Buffer.isBuffer(result.stderr) || result.stderr.length !== 0
  ) {
    const stableCode = childProcessFailureCode(result.error, code);
    fail(
      stableCode,
      `cannot inspect ${label}`,
      {
        executable,
        launcher: METADATA_FCHDIR_LAUNCHER,
        launcherUnavailable: result.error?.code === "ENOENT",
        outputLimitExceeded: ["ENOBUFS", "ERR_CHILD_PROCESS_STDIO_MAXBUFFER"]
          .includes(result.error?.code),
        status: result.status,
        stderr: Buffer.isBuffer(result.stderr)
          ? result.stderr.subarray(0, 4096).toString("utf8")
          : "",
        timedOut: result.error?.code === "ETIMEDOUT",
        timeoutMs: boundedTimeoutMs,
      },
      result.error,
    );
  }
  return result.stdout;
}

function metadataTimeout(operationBudget, label) {
  return operationBudget === null
    ? MAX_CHILD_PROCESS_DURATION_MS
    : remainingOperationMs(operationBudget, label);
}

function parseMacMetadataHelperJson(output, observations, code, label) {
  const text = decodeUtf8(
    output,
    label,
    code,
  );
  let parsed;
  try { parsed = JSON.parse(text); }
  catch (error) {
    fail(
      code,
      `${label} is not one complete JSON value`,
      null,
      error,
    );
  }
  if (!Array.isArray(parsed) || parsed.length !== observations.length) {
    fail(
      code,
      `${label} does not cover the complete descriptor batch`,
    );
  }
  let canonical;
  try { canonical = canonicalJsonBytes(parsed); }
  catch (error) {
    fail(code, `${label} is not bounded canonical data`, null, error);
  }
  if (!canonical.equals(Buffer.concat([output, Buffer.from("\n")]))) {
    fail(code, `${label} is not canonically and unambiguously framed`);
  }
  return parsed;
}

function requireMacMetadataHelperStat(value, observation, label) {
  const expected = {
    ctimeNs: observation.opened.ctimeNs,
    identity: observation.opened.identity,
    mode: observation.opened.mode,
    mtimeNs: observation.opened.mtimeNs,
    nlink: observation.opened.nlink,
    size: observation.opened.size,
    type: observation.opened.type,
    uid: observation.opened.uid,
  };
  if (
    !hasExactObjectKeys(value, [
      "ctimeNs", "identity", "mode", "mtimeNs", "nlink", "size", "type", "uid",
    ]) ||
    !canonicalJsonBytes(value).equals(canonicalJsonBytes(expected))
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE,
      `${label} was returned for the wrong or changed descriptor`,
      { expected, observed: value },
    );
  }
}

function parseMacAclObservations(output, observations) {
  const parsed = parseMacMetadataHelperJson(
    output,
    observations,
    KNOCKOUT_WORKSPACE_ERROR_CODES.ACL_UNSUPPORTED,
    "macOS ACL descriptor batch",
  );
  for (let index = 0; index < observations.length; index++) {
    const value = parsed[index];
    const observation = observations[index];
    if (
      !hasExactObjectKeys(value, ["fd", "present", "stat"]) ||
      value.fd !== index + 4 || typeof value.present !== "boolean"
    ) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.ACL_UNSUPPORTED,
        `macOS ACL output is not bound to ${observation.context.absolute}`,
      );
    }
    requireMacMetadataHelperStat(value.stat, observation, "macOS ACL observation");
    if (value.present) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.ACL_UNSUPPORTED,
        `${observation.context.absolute} carries an ACL`,
      );
    }
  }
}

function decodeMacMetadataBase64(value, label) {
  if (typeof value !== "string" || value.length > MAX_TOOL_OUTPUT_BYTES) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.XATTR_UNSUPPORTED, `${label} is malformed`);
  }
  const decoded = Buffer.from(value, "base64");
  if (decoded.toString("base64") !== value) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.XATTR_UNSUPPORTED, `${label} is not canonical base64`);
  }
  return decoded;
}

function parseMacXattrObservations(output, observations) {
  const parsed = parseMacMetadataHelperJson(
    output,
    observations,
    KNOCKOUT_WORKSPACE_ERROR_CODES.XATTR_UNSUPPORTED,
    "macOS extended-attribute descriptor batch",
  );
  for (let index = 0; index < observations.length; index++) {
    const value = parsed[index];
    const observation = observations[index];
    if (
      !hasExactObjectKeys(value, ["fd", "namesBase64", "provenanceBase64", "stat"]) ||
      value.fd !== index + 4 || !Array.isArray(value.namesBase64) ||
      (value.provenanceBase64 !== null && typeof value.provenanceBase64 !== "string")
    ) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.XATTR_UNSUPPORTED,
        `macOS extended-attribute output is not bound to ${observation.context.absolute}`,
      );
    }
    requireMacMetadataHelperStat(
      value.stat,
      observation,
      "macOS extended-attribute observation",
    );
    const names = value.namesBase64.map((encodedName) => decodeUtf8(
      decodeMacMetadataBase64(encodedName, "macOS extended-attribute name"),
      "macOS extended-attribute name",
      KNOCKOUT_WORKSPACE_ERROR_CODES.XATTR_UNSUPPORTED,
    ));
    if (
      names.some((name) => name.length === 0 || name !== PROVENANCE_XATTR) ||
      new Set(names).size !== names.length
    ) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.XATTR_UNSUPPORTED,
        `${observation.context.absolute} carries an unsupported or duplicate extended attribute`,
        { names },
      );
    }
    if ((names.length === 1) !== (value.provenanceBase64 !== null)) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.XATTR_UNSUPPORTED,
        `macOS provenance presence is inconsistent for ${observation.context.absolute}`,
      );
    }
    const provenance = value.provenanceBase64 === null
      ? null
      : decodeMacMetadataBase64(value.provenanceBase64, "macOS provenance value");
    observation.metadata = Object.freeze({
      classification: PROVENANCE_CLASSIFICATION,
      length: provenance?.length ?? 0,
      present: provenance !== null,
      sha256: provenance === null ? null : sha256(provenance),
    });
  }
}

function findExecutable(candidates) {
  for (const candidate of candidates) {
    try {
      const stat = fs.statSync(candidate);
      if (stat.isFile() && (stat.mode & 0o111) !== 0) return candidate;
    } catch {}
  }
  return null;
}

function observeLinuxMetadata(abs, operand, isSymlink, operationBudget, directoryFd) {
  const getfacl = findExecutable(["/usr/bin/getfacl", "/bin/getfacl"]);
  const getfattr = findExecutable(["/usr/bin/getfattr", "/bin/getfattr"]);
  if (getfacl === null) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.ACL_UNSUPPORTED, "getfacl is unavailable");
  }
  if (getfattr === null) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.XATTR_UNSUPPORTED, "getfattr is unavailable");
  }
  const acl = toolResult(
    getfacl,
    ["--absolute-names", "--omit-header", ...(isSymlink ? ["--physical"] : []), operand],
    KNOCKOUT_WORKSPACE_ERROR_CODES.ACL_UNSUPPORTED,
    `ACLs for ${abs}`,
    metadataTimeout(operationBudget, `metadata inspection for ${abs}`),
    directoryFd,
  ).toString("utf8");
  const aclEntries = acl.split("\n").filter((line) => line.length > 0 && !line.startsWith("#"));
  if (
    aclEntries.some((line) =>
      line.startsWith("default:") ||
      (!/^user::[rwx-]{3}$/.test(line) && !/^group::[rwx-]{3}$/.test(line) &&
        !/^other::[rwx-]{3}$/.test(line)))
  ) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.ACL_UNSUPPORTED, `${abs} carries an ACL`);
  }
  const xattrs = toolResult(
    getfattr,
    ["--absolute-names", "--dump", "--match=-", ...(isSymlink ? ["--no-dereference"] : []), operand],
    KNOCKOUT_WORKSPACE_ERROR_CODES.XATTR_UNSUPPORTED,
    `extended attributes for ${abs}`,
    metadataTimeout(operationBudget, `metadata inspection for ${abs}`),
    directoryFd,
  ).toString("utf8");
  const names = xattrs
    .split("\n")
    .filter((line) => line.length > 0 && !line.startsWith("#"))
    .map((line) => line.split("=", 1)[0]);
  if (names.length > 0) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.XATTR_UNSUPPORTED,
      `${abs} carries unsupported extended attributes`,
      { names },
    );
  }
  if (operationBudget !== null) remainingOperationMs(operationBudget, `metadata inspection for ${abs}`);
  return Object.freeze({
    classification: PROVENANCE_CLASSIFICATION,
    length: 0,
    present: false,
    sha256: null,
  });
}

function metadataPathContext(abs, anchorRoot) {
  const absolute = requireAbsolutePath(abs, "metadata path");
  if (
    anchorRoot === null || typeof anchorRoot !== "object" || Array.isArray(anchorRoot) ||
    typeof anchorRoot.identity !== "string" || typeof anchorRoot.path !== "string"
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
      "metadata anchor must be one bound directory identity",
    );
  }
  const anchor = requireAbsolutePath(anchorRoot.path, "metadata anchor");
  if (!pathInside(anchor, absolute)) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
      "metadata anchor must contain the observed path",
      { anchor, path: absolute },
    );
  }
  const relative = path.relative(anchor, absolute);
  const components = relative === "" ? [] : relative.split(path.sep);
  return Object.freeze({
    absolute,
    anchor,
    components: Object.freeze(components),
    operand: relative === "" ? "." : `.${path.sep}${relative}`,
  });
}

function metadataPathEntry(stat, current) {
  return Object.freeze({
    ctimeNs: String(stat.ctimeNs),
    identity: identityOf(stat),
    mode: modeOf(stat),
    mtimeNs: String(stat.mtimeNs),
    nlink: Number(stat.nlink),
    path: current,
    size: Number(stat.size),
    type: stat.isSymbolicLink() ? "symlink" : stat.isDirectory() ? "directory" :
      stat.isFile() ? "file" : "other",
    uid: Number(stat.uid),
  });
}

function metadataPathChain(context, isSymlink, operationBudget = null, anchorRoot) {
  const { absolute, anchor, components } = context;
  const chain = [];
  let current = anchor;
  for (let index = -1; index < components.length; index++) {
    if (operationBudget !== null) {
      remainingOperationMs(operationBudget, `metadata pathname bind for ${absolute}`);
    }
    if (index >= 0) current = path.join(current, components[index]);
    let stat;
    try { stat = fs.lstatSync(current, { bigint: true }); }
    catch (error) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE,
        `cannot bind metadata pathname ${current}`,
        { path: absolute },
        error,
      );
    }
    const leaf = index === components.length - 1;
    if ((!leaf || !isSymlink) && stat.isSymbolicLink()) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE,
        `metadata pathname acquired a symbolic-link component at ${current}`,
        { path: absolute },
      );
    }
    if (!leaf && !stat.isDirectory()) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE,
        `metadata pathname acquired a non-directory component at ${current}`,
        { path: absolute },
      );
    }
    if (index === -1 && (!stat.isDirectory() || identityOf(stat) !== anchorRoot.identity)) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE,
        `metadata anchor identity changed at ${current}`,
        {
          expectedIdentity: anchorRoot.identity,
          observedIdentity: identityOf(stat),
          path: absolute,
        },
      );
    }
    chain.push(metadataPathEntry(stat, current));
  }
  return Object.freeze(chain);
}

function expectedMetadataLeafMatches(leaf, expected) {
  if (expected === null) return true;
  const expectedIdentity = typeof expected.identity === "string"
    ? expected.identity
    : typeof expected.dev === "bigint" && typeof expected.ino === "bigint"
      ? identityOf(expected)
      : null;
  const expectedCtime = typeof expected.ctimeNs === "bigint"
    ? String(expected.ctimeNs)
    : expected.ctimeNs;
  const expectedMtime = typeof expected.mtimeNs === "bigint"
    ? String(expected.mtimeNs)
    : expected.mtimeNs;
  const expectedMode = typeof expected.mode === "bigint" ? modeOf(expected) : expected.mode;
  const expectedNlink = typeof expected.nlink === "bigint"
    ? Number(expected.nlink)
    : expected.nlink;
  return (
    expectedIdentity !== null && leaf.identity === expectedIdentity &&
    leaf.ctimeNs === expectedCtime && leaf.mtimeNs === expectedMtime &&
    leaf.mode === expectedMode && leaf.nlink === expectedNlink
  );
}

function observeMacMetadataBatch(
  requests,
  operationBudget = null,
  anchorRoot,
  metadataCache = null,
  descriptorCode = KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE,
) {
  if (!Array.isArray(requests)) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "metadata batch is malformed");
  }
  if (!ERROR_CODE_SET.has(descriptorCode)) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
      "metadata batch descriptor refusal code is malformed",
    );
  }
  const cacheState = metadataCache === null
    ? null
    : metadataObservationCacheStates.get(metadataCache);
  if (metadataCache !== null && cacheState === undefined) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
      "metadata observation cache is malformed",
    );
  }
  if (NOFOLLOW === 0 || DIRECTORY === 0 || SYMLINK === 0) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.XATTR_UNSUPPORTED,
      "macOS metadata batching requires O_NOFOLLOW, O_DIRECTORY, and O_SYMLINK",
    );
  }
  const results = new Array(requests.length);
  for (let offset = 0; offset < requests.length; offset += MAC_METADATA_BATCH_NODE_LIMIT) {
    const requestedChunk = requests.slice(offset, offset + MAC_METADATA_BATCH_NODE_LIMIT);
    let directoryFd;
    let openedAnchorObservation;
    const openedNodeFds = [];
    let records = [];
    const cacheUpdates = [];
    let primaryError = null;
    try {
      const firstContext = metadataPathContext(requestedChunk[0].abs, anchorRoot);
      try {
        directoryFd = fs.openSync(
          firstContext.anchor,
          fs.constants.O_RDONLY | DIRECTORY | NOFOLLOW,
        );
        const openedAnchor = fs.fstatSync(directoryFd, { bigint: true });
        if (!openedAnchor.isDirectory() || identityOf(openedAnchor) !== anchorRoot.identity) {
          fail(
            KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE,
            "metadata anchor changed while binding its batch descriptor",
            {
              expectedIdentity: anchorRoot.identity,
              observedIdentity: identityOf(openedAnchor),
              path: firstContext.absolute,
            },
          );
        }
        openedAnchorObservation = directoryObservation(openedAnchor);
      } catch (error) {
        if (error instanceof KnockoutWorkspaceError) throw error;
        fail(
          descriptorFailureCode(error, descriptorCode),
          "metadata anchor could not be bound to a batch directory descriptor",
          { path: firstContext.absolute },
          error,
        );
      }

      records = requestedChunk.map((request, index) => {
        if (request === null || typeof request !== "object" || Array.isArray(request) ||
            typeof request.isSymlink !== "boolean") {
          fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "metadata batch entry is malformed");
        }
        const context = metadataPathContext(request.abs, anchorRoot);
        if (context.anchor !== firstContext.anchor) {
          fail(
            KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
            "metadata batch crosses anchor directories",
          );
        }
        const before = metadataPathChain(
          context,
          request.isSymlink,
          operationBudget,
          anchorRoot,
        );
        const beforeLeaf = before.at(-1);
        if (beforeLeaf === undefined || !expectedMetadataLeafMatches(beforeLeaf, request.expected)) {
          fail(
            KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE,
            `${context.absolute} changed before metadata inspection`,
          );
        }
        if ((beforeLeaf.type === "symlink") !== request.isSymlink) {
          fail(
            KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE,
            `${context.absolute} changed node type before metadata inspection`,
          );
        }
        const pathChainSha256 = sha256(canonicalJsonBytes(before));
        const cacheKey = cacheState === null
          ? null
          : `${anchorRoot.identity}\0${request.isSymlink ? "symlink" : "node"}\0${context.operand}`;
        const cached = cacheKey === null ? undefined : cacheState.entries.get(cacheKey);
        return {
          before,
          beforeLeaf,
          cacheHit: cached !== undefined && cached.pathChainSha256 === pathChainSha256,
          cacheKey,
          context,
          index,
          isSymlink: request.isSymlink,
          metadata: cached?.pathChainSha256 === pathChainSha256 ? cached.metadata : null,
          pathChainSha256,
        };
      });

      const misses = records.filter((record) => !record.cacheHit);
      for (const record of misses) {
        const flags = record.isSymlink
          ? fs.constants.O_RDONLY | SYMLINK
          : fs.constants.O_RDONLY | NOFOLLOW |
            (record.beforeLeaf.type === "directory" ? DIRECTORY : 0);
        let fd;
        try { fd = fs.openSync(record.context.absolute, flags); }
        catch (error) {
          fail(
            descriptorFailureCode(error, descriptorCode),
            `${record.context.absolute} could not be descriptor-bound for metadata inspection`,
            null,
            error,
          );
        }
        openedNodeFds.push(fd);
        let opened;
        try { opened = metadataPathEntry(fs.fstatSync(fd, { bigint: true }), record.context.absolute); }
        catch (error) {
          fail(
            KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE,
            `${record.context.absolute} metadata descriptor could not be observed`,
            null,
            error,
          );
        }
        if (!canonicalJsonBytes(opened).equals(canonicalJsonBytes(record.beforeLeaf))) {
          fail(
            KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE,
            `${record.context.absolute} changed while binding its metadata descriptor`,
            { before: record.beforeLeaf, opened },
          );
        }
        record.fd = fd;
        record.opened = opened;
      }

      if (misses.length > 0) {
        const helperPrefix = [
          "-I",
          "-S",
          "-c",
          MAC_METADATA_HELPER_SCRIPT,
        ];
        const helperLimits = [
          String(MAX_TOOL_OUTPUT_BYTES),
          String(Math.floor(MAX_TOOL_OUTPUT_BYTES / 2)),
          String(misses.length),
        ];
        const aclOutput = toolResult(
          MAC_METADATA_HELPER,
          [
            ...helperPrefix,
            "acl",
            ...helperLimits,
          ],
          KNOCKOUT_WORKSPACE_ERROR_CODES.ACL_UNSUPPORTED,
          "batched macOS ACLs",
          metadataTimeout(operationBudget, "batched macOS ACL inspection"),
          directoryFd,
          openedNodeFds,
        );
        parseMacAclObservations(aclOutput, misses);
        const xattrOutput = toolResult(
          MAC_METADATA_HELPER,
          [
            ...helperPrefix,
            "xattr",
            ...helperLimits,
          ],
          KNOCKOUT_WORKSPACE_ERROR_CODES.XATTR_UNSUPPORTED,
          "batched macOS extended attributes",
          metadataTimeout(operationBudget, "batched macOS extended-attribute inspection"),
          directoryFd,
          openedNodeFds,
        );
        parseMacXattrObservations(xattrOutput, misses);
      }

      for (const record of records) {
        if (!record.cacheHit) {
          const confirmed = metadataPathEntry(
            fs.fstatSync(record.fd, { bigint: true }),
            record.context.absolute,
          );
          if (!canonicalJsonBytes(confirmed).equals(canonicalJsonBytes(record.opened))) {
            fail(
              KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE,
              `${record.context.absolute} changed through its metadata descriptor`,
              { after: confirmed, before: record.opened },
            );
          }
        }
        const after = metadataPathChain(
          record.context,
          record.isSymlink,
          operationBudget,
          anchorRoot,
        );
        if (!canonicalJsonBytes(record.before).equals(canonicalJsonBytes(after))) {
          const changedIndex = record.before.findIndex((entry, index) =>
            !canonicalJsonBytes(entry).equals(canonicalJsonBytes(after[index])));
          fail(
            KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE,
            `${record.context.absolute} or one of its pathname ancestors changed during metadata inspection`,
            {
              after: changedIndex < 0 ? null : after[changedIndex],
              before: changedIndex < 0 ? null : record.before[changedIndex],
            },
          );
        }
      }
      const confirmedAnchor = fs.fstatSync(directoryFd, { bigint: true });
      if (
        !confirmedAnchor.isDirectory() ||
        !canonicalJsonBytes(directoryObservation(confirmedAnchor))
          .equals(canonicalJsonBytes(openedAnchorObservation))
      ) {
        fail(
          KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE,
          "metadata anchor descriptor changed during batch inspection",
          { path: firstContext.anchor },
        );
      }
      for (const record of records) {
        if (!record.cacheHit && record.cacheKey !== null) {
          cacheUpdates.push(Object.freeze({
            key: record.cacheKey,
            metadata: record.metadata,
            pathChainSha256: record.pathChainSha256,
          }));
        }
        results[offset + record.index] = record.metadata;
      }
    } catch (error) {
      primaryError = error instanceof KnockoutWorkspaceError
        ? error
        : workspaceError(
            KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE,
            "batched metadata inspection failed without stable taxonomy",
            null,
            error,
          );
    } finally {
      const closeErrors = [];
      for (const fd of [...openedNodeFds].reverse()) {
        try { fs.closeSync(fd); }
        catch (error) {
          closeErrors.push(workspaceError(
            descriptorFailureCode(error, descriptorCode),
            "metadata node descriptor could not be closed",
            null,
            error,
          ));
        }
      }
      if (directoryFd !== undefined) {
        try { fs.closeSync(directoryFd); }
        catch (error) {
          closeErrors.push(workspaceError(
            descriptorFailureCode(error, descriptorCode),
            "metadata anchor descriptor could not be closed",
            { path: anchorRoot.path },
            error,
          ));
        }
      }
      primaryError = combineWorkspaceFailures(
        primaryError,
        closeErrors,
        descriptorCode,
        "metadata batch descriptors could not be closed",
      );
    }
    if (primaryError !== null) throw primaryError;
    for (const update of cacheUpdates) {
      if (
        cacheState.entries.has(update.key) ||
        cacheState.entries.size < cacheState.maxEntries
      ) {
        cacheState.entries.set(update.key, Object.freeze({
          metadata: update.metadata,
          pathChainSha256: update.pathChainSha256,
        }));
      }
    }
  }
  return Object.freeze(results);
}

function observeMetadataBatch(requests, operationBudget, anchorRoot, metadataCache) {
  if (process.platform === "darwin") {
    return observeMacMetadataBatch(requests, operationBudget, anchorRoot, metadataCache);
  }
  return Object.freeze(requests.map((request) => observeMetadata(
    request.abs,
    request.isSymlink,
    operationBudget,
    request.expected,
    anchorRoot,
    metadataCache,
  )));
}

function observeMetadata(
  abs,
  isSymlink,
  operationBudget = null,
  expected = null,
  anchorRoot,
  metadataCache = null,
  descriptorCode = KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE,
) {
  if (process.platform === "darwin") {
    return observeMacMetadataBatch(
      [{ abs, expected, isSymlink }],
      operationBudget,
      anchorRoot,
      metadataCache,
      descriptorCode,
    )[0];
  }
  const context = metadataPathContext(abs, anchorRoot);
  const cacheState = metadataCache === null
    ? null
    : metadataObservationCacheStates.get(metadataCache);
  if (metadataCache !== null && cacheState === undefined) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
      "metadata observation cache is malformed",
    );
  }
  if (NOFOLLOW === 0 || DIRECTORY === 0) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE,
      "metadata inspection requires O_NOFOLLOW and O_DIRECTORY",
    );
  }
  let directoryFd;
  let openedAnchorObservation;
  let metadata;
  let cacheUpdate = null;
  let pendingError = null;
  try {
    try {
      directoryFd = fs.openSync(
        context.anchor,
        fs.constants.O_RDONLY | DIRECTORY | NOFOLLOW,
      );
      const openedAnchor = fs.fstatSync(directoryFd, { bigint: true });
      if (!openedAnchor.isDirectory() || identityOf(openedAnchor) !== anchorRoot.identity) {
        fail(
          KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE,
          "metadata anchor changed while binding its directory descriptor",
          {
            expectedIdentity: anchorRoot.identity,
            observedIdentity: identityOf(openedAnchor),
            path: context.absolute,
          },
        );
      }
      openedAnchorObservation = directoryObservation(openedAnchor);
    } catch (error) {
      if (error instanceof KnockoutWorkspaceError) throw error;
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE,
        "metadata anchor could not be bound to a directory descriptor",
        { path: context.absolute },
        error,
      );
    }

    const before = metadataPathChain(context, isSymlink, operationBudget, anchorRoot);
    const beforeLeaf = before.at(-1);
    if (beforeLeaf === undefined || !expectedMetadataLeafMatches(beforeLeaf, expected)) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE,
        `${abs} changed before metadata inspection`,
      );
    }
    const beforeSha256 = sha256(canonicalJsonBytes(before));
    if (operationBudget !== null) {
      remainingOperationMs(operationBudget, `metadata pathname bind for ${context.absolute}`);
    }
    const cacheKey = cacheState === null
      ? null
      : `${anchorRoot.identity}\0${isSymlink ? "symlink" : "node"}\0${context.operand}`;
    const cached = cacheKey === null ? undefined : cacheState.entries.get(cacheKey);
    const cacheHit = cached !== undefined && cached.pathChainSha256 === beforeSha256;
    if (cacheHit) {
      metadata = cached.metadata;
    } else if (process.platform === "linux") {
      metadata = observeLinuxMetadata(
        context.absolute,
        context.operand,
        isSymlink,
        operationBudget,
        directoryFd,
      );
    } else {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.XATTR_UNSUPPORTED,
        `metadata inspection is unsupported on ${process.platform}`,
      );
    }
    const after = metadataPathChain(context, isSymlink, operationBudget, anchorRoot);
    if (!canonicalJsonBytes(before).equals(canonicalJsonBytes(after))) {
      const changedIndex = before.findIndex((entry, index) =>
        !canonicalJsonBytes(entry).equals(canonicalJsonBytes(after[index])));
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE,
        `${abs} or one of its pathname ancestors changed during metadata inspection`,
        {
          after: changedIndex < 0 ? null : after[changedIndex],
          before: changedIndex < 0 ? null : before[changedIndex],
        },
      );
    }
    const confirmedAnchor = fs.fstatSync(directoryFd, { bigint: true });
    if (
      !confirmedAnchor.isDirectory() ||
      !canonicalJsonBytes(directoryObservation(confirmedAnchor))
        .equals(canonicalJsonBytes(openedAnchorObservation))
    ) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE,
        "metadata anchor descriptor changed during inspection",
        { path: context.absolute },
      );
    }
    if (
      !cacheHit && cacheKey !== null &&
      (cacheState.entries.has(cacheKey) || cacheState.entries.size < cacheState.maxEntries)
    ) {
      cacheUpdate = Object.freeze({
        key: cacheKey,
        metadata,
        pathChainSha256: beforeSha256,
      });
    }
  } catch (error) {
    pendingError = error instanceof KnockoutWorkspaceError
      ? error
      : workspaceError(
          KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE,
          "metadata inspection failed without stable taxonomy",
          { path: context.absolute },
          error,
        );
  } finally {
    if (directoryFd !== undefined) {
      try { fs.closeSync(directoryFd); }
      catch (error) {
        if (pendingError === null) {
          pendingError = workspaceError(
            KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE,
            "metadata anchor descriptor could not be closed",
            { path: context.absolute },
            error,
          );
        }
      }
    }
  }
  if (pendingError !== null) throw pendingError;
  if (cacheUpdate !== null) {
    cacheState.entries.set(cacheUpdate.key, Object.freeze({
      metadata: cacheUpdate.metadata,
      pathChainSha256: cacheUpdate.pathChainSha256,
    }));
  }
  return metadata;
}

function directoryObservation(stat) {
  return Object.freeze({
    ctimeNs: String(stat.ctimeNs),
    dev: String(stat.dev),
    identity: identityOf(stat),
    ino: String(stat.ino),
    mode: modeOf(stat),
    mtimeNs: String(stat.mtimeNs),
    nlink: Number(stat.nlink),
  });
}

function materialNode(node) {
  const base = {
    executable: node.executable,
    hardlinkCount: node.hardlinkCount,
    hardlinkGroup: node.hardlinkGroup,
    mode: node.mode,
    path: node.path,
    type: node.type,
  };
  if (node.type === "file") return { ...base, sha256: node.sha256, size: node.size };
  if (node.type === "symlink") return { ...base, target: node.target };
  return base;
}

function resolveCensusTarget(
  nodesByPath,
  target,
  { forbidRootGit = false, operationBudget = null } = {},
) {
  if (operationBudget !== null) remainingOperationMs(operationBudget, "workspace symlink resolution");
  let pending = target === "." ? [] : target.split("/");
  let resolved = [];
  let symlinkHops = 0;
  while (pending.length > 0) {
    if (operationBudget !== null) remainingOperationMs(operationBudget, "workspace symlink resolution");
    const component = pending.shift();
    const candidateParts = [...resolved, component];
    const candidate = candidateParts.join("/");
    if (forbidRootGit && (candidate === ".git" || candidate.startsWith(".git/"))) {
      return Object.freeze({ kind: "forbidden-root-git", path: candidate });
    }
    const node = nodesByPath.get(candidate);
    if (node === undefined) return Object.freeze({ kind: "missing", path: candidate });
    if (node.type === "symlink") {
      symlinkHops += 1;
      if (symlinkHops > nodesByPath.size) {
        return Object.freeze({ kind: "cycle", path: candidate });
      }
      const parent = resolved.length === 0 ? "." : resolved.join("/");
      const next = path.posix.normalize(path.posix.join(parent, node.target));
      if (next === ".." || next.startsWith("../") || path.posix.isAbsolute(next)) {
        return Object.freeze({ kind: "escape", path: next });
      }
      pending = [...(next === "." ? [] : next.split("/")), ...pending];
      resolved = [];
      continue;
    }
    if (pending.length > 0 && node.type !== "directory") {
      return Object.freeze({ kind: "non-directory-prefix", path: candidate });
    }
    resolved = candidateParts;
  }
  const resolvedPath = resolved.length === 0 ? "." : resolved.join("/");
  if (forbidRootGit && (resolvedPath === ".git" || resolvedPath.startsWith(".git/"))) {
    return Object.freeze({ kind: "forbidden-root-git", path: resolvedPath });
  }
  return nodesByPath.has(resolvedPath)
    ? Object.freeze({ kind: "resolved", path: resolvedPath })
    : Object.freeze({ kind: "missing", path: resolvedPath });
}

function workspaceEvidenceFromNodes(
  nodes,
  limits = null,
  { forbidRootGit = false, operationBudget = null } = {},
) {
  if (operationBudget !== null) remainingOperationMs(operationBudget, "workspace evidence admission");
  if (!Array.isArray(nodes) || nodes.length < 1) return null;
  const admittedLimits = limits === null ? null : normalizeCaptureLimits(limits);
  const chargedFiles = new Map();
  const nodesByPath = new Map();
  const symlinkTargets = [];
  const seenPaths = new Set();
  let allocatedBytes = 0;
  let logicalBytes = 0;
  let maxDepth = 0;
  let rootCount = 0;
  let previousPath = null;
  for (const node of nodes) {
    if (operationBudget !== null) remainingOperationMs(operationBudget, "workspace evidence nodes");
    if (
      node === null || typeof node !== "object" || Array.isArray(node) ||
      typeof node.path !== "string" || !["directory", "file", "symlink"].includes(node.type) ||
      typeof node.executable !== "boolean" ||
      !Number.isSafeInteger(node.mode) || node.mode < 0 || node.mode > 0o7777 ||
      node.observation === null || typeof node.observation !== "object" ||
      Array.isArray(node.observation) || node.provenance === null ||
      typeof node.provenance !== "object" || Array.isArray(node.provenance)
    ) return null;
    if (seenPaths.has(node.path)) return null;
    seenPaths.add(node.path);
    if (
      previousPath !== null &&
      Buffer.compare(Buffer.from(previousPath), Buffer.from(node.path)) >= 0
    ) return null;
    previousPath = node.path;
    const components = node.path === "." ? [] : node.path.split("/");
    if (
      (node.path === "." && node.type !== "directory") ||
      components.some((component) => component === "" || component === "." || component === ".." ||
        component.includes("\0"))
    ) return null;
    if (node.path === ".") rootCount += 1;
    maxDepth = Math.max(maxDepth, components.length);
    const observation = node.observation;
    if (
      !/^[0-9]+$/.test(observation.dev) || !/^[0-9]+$/.test(observation.ino) ||
      observation.identity !== `${observation.dev}:${observation.ino}` ||
      !/^[0-9]+$/.test(observation.ctimeNs) || !/^[0-9]+$/.test(observation.mtimeNs) ||
      !Number.isSafeInteger(observation.mode) || observation.mode !== node.mode ||
      !Number.isSafeInteger(observation.nlink) || observation.nlink < 1 ||
      node.provenance.classification !== PROVENANCE_CLASSIFICATION ||
      typeof node.provenance.present !== "boolean" ||
      !Number.isSafeInteger(node.provenance.length) || node.provenance.length < 0 ||
      (node.provenance.present
        ? !HASH_64.test(node.provenance.sha256)
        : node.provenance.sha256 !== null || node.provenance.length !== 0)
    ) return null;
    if (node.type !== "file") {
      if (
        node.hardlinkCount !== null || node.hardlinkGroup !== null ||
        (node.type === "directory" && node.executable !== true) ||
        (node.type === "symlink" && (
          node.executable !== false || typeof node.target !== "string" ||
          node.target.length === 0 || node.target.includes("\0") ||
          path.posix.isAbsolute(node.target)
        ))
      ) return null;
      if (node.type === "symlink") {
        const parent = components.length <= 1 ? "." : components.slice(0, -1).join("/");
        const target = path.posix.normalize(path.posix.join(parent, node.target));
        if (target === ".." || target.startsWith("../")) return null;
        symlinkTargets.push(Object.freeze({ path: node.path, target }));
      }
      nodesByPath.set(node.path, node);
      continue;
    }
    if (
      !Number.isSafeInteger(node.size) || node.size < 0 ||
      observation.size !== node.size || !HASH_64.test(node.sha256) ||
      !Number.isSafeInteger(observation.allocatedBytes) || observation.allocatedBytes < 0 ||
      node.executable !== ((node.mode & 0o111) !== 0) ||
      (admittedLimits !== null && (
        node.size > admittedLimits.maxFileBytes ||
        observation.allocatedBytes > admittedLimits.maxAllocatedBytes
      )) ||
      (node.hardlinkGroup !== null && !HASH_64.test(node.hardlinkGroup))
    ) return null;
    const chargeKey = node.hardlinkGroup ?? `identity:${observation.identity}`;
    const prior = chargedFiles.get(chargeKey);
    if (prior !== undefined) {
      if (node.hardlinkGroup === null) return null;
      if (
        prior.identity !== observation.identity || prior.size !== node.size ||
        prior.allocatedBytes !== observation.allocatedBytes
      ) return null;
      prior.members += 1;
      prior.paths.push(node.path);
      if (node.hardlinkCount !== prior.hardlinkCount) return null;
      // Every admitted pathname remains part of the workspace topology even when its inode has
      // already been charged. A relative symlink may legitimately name this non-primary hardlink
      // (npm's esbuild install does exactly that); omitting the alias makes an internally resolved
      // link look missing and causes the census to contradict its own node list.
      nodesByPath.set(node.path, node);
      continue;
    }
    if (
      node.hardlinkGroup !== null &&
      (!Number.isSafeInteger(node.hardlinkCount) || node.hardlinkCount < 2 ||
        observation.nlink !== node.hardlinkCount)
    ) return null;
    if (
      node.hardlinkGroup === null &&
      (node.hardlinkCount !== null || observation.nlink !== 1)
    ) return null;
    chargedFiles.set(chargeKey, {
      allocatedBytes: observation.allocatedBytes,
      group: node.hardlinkGroup,
      hardlinkCount: node.hardlinkGroup === null ? 1 : node.hardlinkCount,
      identity: observation.identity,
      members: 1,
      paths: [node.path],
      size: node.size,
    });
    allocatedBytes += observation.allocatedBytes;
    logicalBytes += node.size;
    if (!Number.isSafeInteger(allocatedBytes) || !Number.isSafeInteger(logicalBytes)) return null;
    nodesByPath.set(node.path, node);
  }
  if ([...chargedFiles.values()].some((entry) => {
    if (operationBudget !== null) remainingOperationMs(operationBudget, "workspace hardlink evidence");
    if (entry.members !== entry.hardlinkCount) return true;
    if (entry.group === null) return false;
    entry.paths.sort((left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right)));
    return entry.group !== sha256(
      Buffer.from(`noa-knockout-hardlink/1\0${entry.paths.join("\0")}`),
    );
  })) return null;
  if (rootCount !== 1) return null;
  for (const node of nodes) {
    if (operationBudget !== null) remainingOperationMs(operationBudget, "workspace parent evidence");
    if (node.path === ".") continue;
    const components = node.path.split("/");
    const parent = components.length === 1 ? "." : components.slice(0, -1).join("/");
    if (nodesByPath.get(parent)?.type !== "directory") return null;
  }
  for (const { target } of symlinkTargets) {
    if (operationBudget !== null) remainingOperationMs(operationBudget, "workspace symlink evidence");
    if (resolveCensusTarget(
      nodesByPath,
      target,
      { forbidRootGit, operationBudget },
    ).kind !== "resolved") return null;
  }
  if (
    admittedLimits !== null &&
    (allocatedBytes > admittedLimits.maxAllocatedBytes ||
      logicalBytes > admittedLimits.maxTotalBytes ||
      maxDepth > admittedLimits.maxDepth || nodes.length > admittedLimits.maxNodes)
  ) return null;
  const materialSha256 = sha256(canonicalJsonBytes(nodes.map(materialNode)));
  if (operationBudget !== null) remainingOperationMs(operationBudget, "workspace material evidence hash");
  const observationSha256 = sha256(canonicalJsonBytes(nodes));
  if (operationBudget !== null) remainingOperationMs(operationBudget, "workspace observation evidence hash");
  return Object.freeze({
    allocatedBytes,
    logicalBytes,
    materialSha256,
    maxDepth,
    nodeCount: nodes.length,
    observationSha256,
  });
}

function resourceMetricsFromNodes(nodes, operationBudget = null) {
  const evidence = workspaceEvidenceFromNodes(nodes, null, { operationBudget });
  if (evidence === null) return null;
  return Object.freeze({
    allocatedBytes: evidence.allocatedBytes,
    logicalBytes: evidence.logicalBytes,
    maxDepth: evidence.maxDepth,
    nodeCount: evidence.nodeCount,
  });
}

function rootLocalStateNodeSet(nodes) {
  const byPath = new Map(nodes.map((node) => [node.path, node]));
  for (const directoryPath of [
    "node_modules",
    "node_modules/.cache",
    ROOT_LOCAL_STATE_DIRECTORY,
  ]) {
    const node = byPath.get(directoryPath);
    if (node !== undefined && node.type !== "directory") {
      return Object.freeze({ byPath, problem: `${directoryPath} is not a real directory` });
    }
  }
  for (const node of nodes) {
    if (node.path === ROOT_LOCAL_STATE_DIRECTORY || node.path === ROOT_LOCAL_STATE_PATH) continue;
    if (node.path === ROOT_LOCAL_STATE_RUNS_DIRECTORY) {
      if (node.type === "directory") continue;
      return Object.freeze({ byPath, problem: `${ROOT_LOCAL_STATE_RUNS_DIRECTORY} is not a directory` });
    }
    if (node.path.startsWith(`${ROOT_LOCAL_STATE_RUNS_DIRECTORY}/`)) {
      return Object.freeze({ byPath, problem: `legacy recovery material remains at ${node.path}` });
    }
    if (!node.path.startsWith(`${ROOT_LOCAL_STATE_DIRECTORY}/`)) continue;
    const relative = node.path.slice(ROOT_LOCAL_STATE_DIRECTORY.length + 1);
    if (
      !relative.includes("/") && node.type === "file" &&
      ROOT_LOCAL_STATE_STAGING.test(relative)
    ) continue;
    return Object.freeze({ byPath, problem: `unsupported legacy recovery state remains at ${node.path}` });
  }
  return Object.freeze({ byPath, problem: null });
}

function portableSourceCensus(sourceCensus, projection, operationBudget = null) {
  const omitted = projection.status === "VALID_SOURCE_BOUND"
    ? ROOT_LOCAL_STATE_PATH
    : null;
  const nodes = Object.freeze(sourceCensus.nodes.filter((node) => node.path !== omitted));
  const evidence = workspaceEvidenceFromNodes(nodes, sourceCensus.limits, {
    forbidRootGit: true,
    operationBudget,
  });
  if (evidence === null) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.ROOT_LOCAL_STATE_UNSUPPORTED,
      "root-local state projection does not produce a valid portable workspace census",
    );
  }
  return Object.freeze({
    allocatedBytes: evidence.allocatedBytes,
    limits: sourceCensus.limits,
    logicalBytes: evidence.logicalBytes,
    materialSha256: evidence.materialSha256,
    maxDepth: evidence.maxDepth,
    nodeCount: evidence.nodeCount,
    nodes,
    observationSha256: evidence.observationSha256,
    provenancePolicy: sourceCensus.provenancePolicy,
    root: sourceCensus.root,
  });
}

function validateRootLocalStateProjection(projection, sourceCensus, sourceRootIdentity) {
  if (!hasExactObjectKeys(projection, [
    "action", "path", "policy", "record", "sourceBytesBase64", "sourceFileSha256",
    "sourceNodeSha256", "status",
  ])) return "root-local state projection has an open or incomplete schema";
  if (
    projection.action !== ROOT_LOCAL_STATE_PROJECTION_ACTION ||
    projection.path !== ROOT_LOCAL_STATE_PATH ||
    projection.policy !== ROOT_LOCAL_STATE_PROJECTION_POLICY ||
    !["ABSENT", "VALID_SOURCE_BOUND"].includes(projection.status)
  ) return "root-local state projection policy is malformed";
  const state = rootLocalStateNodeSet(sourceCensus.nodes);
  if (state.problem !== null) return state.problem;
  const node = state.byPath.get(ROOT_LOCAL_STATE_PATH);
  if (projection.status === "ABSENT") {
    if (
      node !== undefined || projection.record !== null ||
      projection.sourceBytesBase64 !== null || projection.sourceFileSha256 !== null ||
      projection.sourceNodeSha256 !== null
    ) return "ABSENT root-local state projection contradicts the full source census";
    return null;
  }
  let sourceBytes;
  let decodedRecord;
  try {
    if (typeof projection.sourceBytesBase64 !== "string") throw new Error("not a string");
    sourceBytes = Buffer.from(projection.sourceBytesBase64, "base64");
    if (
      sourceBytes.length < 1 || sourceBytes.length > 4096 ||
      sourceBytes.toString("base64") !== projection.sourceBytesBase64
    ) throw new Error("not canonical bounded base64");
    decodedRecord = JSON.parse(sourceBytes.toString("utf8"));
  } catch {
    return "VALID_SOURCE_BOUND root-local state projection does not carry its exact tombstone bytes";
  }
  if (
    node?.type !== "file" || node.executable !== false || node.mode !== 0o600 ||
    node.hardlinkCount !== null || node.hardlinkGroup !== null ||
    node.observation?.nlink !== 1 || !HASH_64.test(node.sha256 ?? "") ||
    projection.sourceFileSha256 !== node.sha256 ||
    sha256(sourceBytes) !== projection.sourceFileSha256 ||
    projection.sourceNodeSha256 !== sha256(canonicalJsonBytes(node)) ||
    !canonicalJsonBytes(decodedRecord).equals(canonicalJsonBytes(projection.record)) ||
    !isKnockoutLegacyTombstoneForRoot(
      projection.record,
      knockoutGuardRootIdentity(sourceRootIdentity),
    )
  ) return "VALID_SOURCE_BOUND root-local state projection is not bound to one safe source tombstone";
  return null;
}

function observeRootLocalStateProjection(sourceCensus, sourceBinding, operationBudget) {
  const state = rootLocalStateNodeSet(sourceCensus.nodes);
  if (state.problem !== null) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.ROOT_LOCAL_STATE_UNSUPPORTED, state.problem);
  }
  const node = state.byPath.get(ROOT_LOCAL_STATE_PATH);
  if (node === undefined) {
    const projection = Object.freeze({
      action: ROOT_LOCAL_STATE_PROJECTION_ACTION,
      path: ROOT_LOCAL_STATE_PATH,
      policy: ROOT_LOCAL_STATE_PROJECTION_POLICY,
      record: null,
      sourceBytesBase64: null,
      sourceFileSha256: null,
      sourceNodeSha256: null,
      status: "ABSENT",
    });
    return Object.freeze({
      portable: portableSourceCensus(sourceCensus, projection, operationBudget),
      projection,
    });
  }
  if (
    node.type !== "file" || node.executable !== false || node.mode !== 0o600 ||
    node.hardlinkCount !== null || node.hardlinkGroup !== null || node.observation?.nlink !== 1
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.ROOT_LOCAL_STATE_UNSUPPORTED,
      `${ROOT_LOCAL_STATE_PATH} is not one private single-link regular file`,
    );
  }
  requireSourceRoot(sourceCensus.root, sourceBinding, operationBudget, {
    label: "source root before root-local state observation",
    observation: sourceBinding.observation,
  });
  const observed = observeRegularFile(
    path.join(sourceCensus.root, ...ROOT_LOCAL_STATE_PATH.split("/")),
    node,
    {
      maxAllocatedBytes: sourceCensus.limits.maxAllocatedBytes,
      maxBytes: 4096,
      operationBudget,
    },
  );
  let record;
  try { record = deepFreezeJson(JSON.parse(observed.bytes.toString("utf8"))); }
  catch (error) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.ROOT_LOCAL_STATE_UNSUPPORTED,
      `${ROOT_LOCAL_STATE_PATH} is not a JSON migration tombstone`,
      null,
      error,
    );
  }
  if (!isKnockoutLegacyTombstoneForRoot(
    record,
    knockoutGuardRootIdentity(sourceBinding.identity),
  )) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.ROOT_LOCAL_STATE_UNSUPPORTED,
      `${ROOT_LOCAL_STATE_PATH} is not the migration tombstone for this physical source root`,
    );
  }
  requireSourceRoot(sourceCensus.root, sourceBinding, operationBudget, {
    label: "source root after root-local state observation",
    observation: sourceBinding.observation,
  });
  const projection = Object.freeze({
    action: ROOT_LOCAL_STATE_PROJECTION_ACTION,
    path: ROOT_LOCAL_STATE_PATH,
    policy: ROOT_LOCAL_STATE_PROJECTION_POLICY,
    record,
    sourceBytesBase64: observed.bytes.toString("base64"),
    sourceFileSha256: observed.sha256,
    sourceNodeSha256: sha256(canonicalJsonBytes(node)),
    status: "VALID_SOURCE_BOUND",
  });
  const problem = validateRootLocalStateProjection(
    projection,
    sourceCensus,
    sourceBinding.identity,
  );
  if (problem !== null) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.ROOT_LOCAL_STATE_UNSUPPORTED, problem);
  }
  return Object.freeze({
    portable: portableSourceCensus(sourceCensus, projection, operationBudget),
    projection,
  });
}

/**
 * Exact worktree-node census. The root `.git` node is excluded for source captures; every other
 * directory (including empty ones), regular file, and internal relative symlink is material.
 */
export function censusWorkspace(root, options = {}) {
  if (options === null || typeof options !== "object" || Array.isArray(options)) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "workspace census options are malformed");
  }
  const {
    allowRootGit = false,
    commandTimeoutMs = MAX_CHILD_PROCESS_DURATION_MS,
    expectedRoot = null,
    expectedRootCode = KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
    limits: requestedLimits = KNOCKOUT_WORKSPACE_CAPTURE_LIMITS,
    metadataCache = null,
    operationBudget: suppliedBudget = null,
    rootGitPolicy: requestedRootGitPolicy = null,
  } = options;
  if (typeof allowRootGit !== "boolean") {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "allowRootGit must be boolean");
  }
  if (expectedRoot !== null && !validBoundDirectory(expectedRoot)) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "expected census root binding is malformed");
  }
  if (!ERROR_CODE_SET.has(expectedRootCode)) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "expected census root code is malformed");
  }
  if (metadataCache !== null && !metadataObservationCacheStates.has(metadataCache)) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "metadata observation cache is malformed");
  }
  const compatibilityPolicy = allowRootGit ? "include" : "exclude";
  const rootGitPolicy = requestedRootGitPolicy ?? compatibilityPolicy;
  if (!["absent", "exclude", "include"].includes(rootGitPolicy)) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
      "rootGitPolicy must be absent, exclude, or include",
    );
  }
  if (
    requestedRootGitPolicy !== null &&
    Object.prototype.hasOwnProperty.call(options, "allowRootGit") &&
    allowRootGit !== (rootGitPolicy === "include")
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
      "allowRootGit conflicts with rootGitPolicy",
    );
  }
  const limits = normalizeCaptureLimits(requestedLimits);
  const operationBudget = suppliedBudget ?? createOperationBudget(commandTimeoutMs);
  remainingOperationMs(operationBudget, "workspace census");
  // The census root is the anchor for every node observation below it. When the caller already
  // holds a bound identity for that root, the census confirms it here so a pathname that now names
  // a substituted root is refused before any node is observed under the wrong anchor.
  const workspaceDirectory = requireRealDirectory(root, "workspace root", {
    expectedIdentity: expectedRoot === null ? null : expectedRoot.identity,
    expectedIdentityCode: expectedRoot === null ? null : expectedRootCode,
    operationBudget,
  });
  const physical = workspaceDirectory.path;
  if (expectedRoot !== null && physical !== expectedRoot.path) {
    fail(
      expectedRootCode,
      "workspace root no longer resolves to its bound physical pathname",
      { expectedPath: expectedRoot.path, path: physical },
    );
  }
  const provisional = [];
  const metadataRequests = [];
  const regularByIdentity = new Map();
  let pendingNodeReservations = 0;
  let allocatedBytes = 0;
  let logicalBytes = 0;
  let observedMaxDepth = 0;

  const assertNodeAdmission = (nodePath, depth) => {
    if (depth > limits.maxDepth) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.RESOURCE_LIMIT_EXCEEDED,
        "workspace exceeds the admitted node-depth limit",
        { depth, limit: limits.maxDepth, path: nodePath },
      );
    }
    if (provisional.length + pendingNodeReservations >= limits.maxNodes) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.RESOURCE_LIMIT_EXCEEDED,
        "workspace exceeds the admitted node-count limit",
        { limit: limits.maxNodes, nextPath: nodePath },
      );
    }
  };

  const addNode = (node, depth, metadataRequest) => {
    assertNodeAdmission(node.path, depth);
    observedMaxDepth = Math.max(observedMaxDepth, depth);
    provisional.push(node);
    metadataRequests.push(metadataRequest);
  };

  const addDirectory = (abs, rel, stat, depth) => {
    remainingOperationMs(operationBudget, `workspace census at ${rel}`);
    assertNodeAdmission(rel, depth);
    addNode({
      executable: true,
      hardlinkCount: null,
      hardlinkGroup: null,
      mode: modeOf(stat),
      observation: directoryObservation(stat),
      path: rel,
      provenance: null,
      type: "directory",
    }, depth, { abs, expected: stat, isSymlink: false });
  };

  const readBoundedDirectoryEntries = (absDir, relDir) => {
    const entries = [];
    let directory;
    let pendingError = null;
    try {
      directory = fs.opendirSync(absDir, { bufferSize: 32, encoding: "buffer" });
      while (true) {
        remainingOperationMs(operationBudget, `workspace enumeration at ${relDir}`);
        const entry = directory.readSync();
        remainingOperationMs(operationBudget, `workspace enumeration at ${relDir}`);
        if (entry === null) break;
        const name = decodeUtf8(entry.name, `filesystem entry below ${relDir}`);
        if (relDir === "." && name === ".git" && rootGitPolicy === "exclude") continue;
        if (provisional.length + pendingNodeReservations >= limits.maxNodes) {
          fail(
            KNOCKOUT_WORKSPACE_ERROR_CODES.RESOURCE_LIMIT_EXCEEDED,
            "workspace directory exceeds the remaining admitted node count",
            {
              limit: limits.maxNodes,
              nextPath: relDir === "." ? name : `${relDir}/${name}`,
            },
          );
        }
        entries.push(entry);
        pendingNodeReservations += 1;
      }
    } catch (error) {
      pendingError = error instanceof KnockoutWorkspaceError
        ? error
        : workspaceError(
            KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE,
            `cannot enumerate ${absDir}`,
            null,
            error,
          );
    }
    if (directory !== undefined) {
      try { directory.closeSync(); }
      catch (error) {
        if (pendingError === null) {
          pendingError = workspaceError(
            KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE,
            `cannot close enumeration for ${absDir}`,
            null,
            error,
          );
        }
      }
    }
    if (pendingError !== null) throw pendingError;
    remainingOperationMs(operationBudget, `workspace enumeration at ${relDir}`);
    entries.sort((left, right) => Buffer.compare(left.name, right.name));
    return entries;
  };

  const walk = (absDir, relDir, depth) => {
    remainingOperationMs(operationBudget, `workspace census at ${relDir}`);
    let before;
    try { before = fs.lstatSync(absDir, { bigint: true }); }
    catch (error) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE,
        `${absDir} disappeared during enumeration`,
        null,
        error,
      );
    }
    if (!before.isDirectory() || before.isSymbolicLink()) {
      fail(KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE, `${absDir} is no longer a directory`);
    }
    addDirectory(absDir, relDir, before, depth);
    const entries = readBoundedDirectoryEntries(absDir, relDir);
    for (const entry of entries) {
      pendingNodeReservations -= 1;
      const name = decodeUtf8(entry.name, `filesystem entry below ${relDir}`);
      const rel = relDir === "." ? name : `${relDir}/${name}`;
      if (name === ".git") {
        if (relDir === "." && rootGitPolicy === "exclude") continue;
        if (relDir === "." && rootGitPolicy === "absent") {
          fail(
            KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
            "private worktree already contains root Git metadata before initialization",
            { path: rel },
          );
        }
        if (relDir === "." && rootGitPolicy === "include") {
          // The one standalone Git directory is copied as ordinary private state.
        } else {
          fail(
            KNOCKOUT_WORKSPACE_ERROR_CODES.NESTED_GIT_REPOSITORY,
            `nested Git metadata is unsupported at ${rel}`,
          );
        }
      }
      remainingOperationMs(operationBudget, `workspace census at ${rel}`);
      const abs = path.join(absDir, name);
      let stat;
      try { stat = fs.lstatSync(abs, { bigint: true }); }
      catch (error) {
        fail(KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE, `${rel} disappeared`, null, error);
      }
      if (relDir === "." && name === ".git" && !stat.isDirectory()) {
        fail(
          KNOCKOUT_WORKSPACE_ERROR_CODES.STANDALONE_GIT_INVALID,
          "standalone root Git metadata is not a real directory",
          { path: rel },
        );
      }
      if (stat.isDirectory()) {
        walk(abs, rel, depth + 1);
        continue;
      }
      assertNodeAdmission(rel, depth + 1);
      if (stat.isFile()) {
        if (stat.size < 0n || stat.size > BigInt(limits.maxFileBytes)) {
          fail(
            KNOCKOUT_WORKSPACE_ERROR_CODES.RESOURCE_LIMIT_EXCEEDED,
            `${rel} exceeds the admitted per-file byte limit`,
            { limitBytes: limits.maxFileBytes, observedBytes: String(stat.size) },
          );
        }
        const statSize = Number(stat.size);
        const statAllocatedBytes = allocatedBytesOf(stat, rel);
        const existingAliases = regularByIdentity.get(identityOf(stat));
        if (existingAliases === undefined && logicalBytes + statSize > limits.maxTotalBytes) {
          fail(
            KNOCKOUT_WORKSPACE_ERROR_CODES.RESOURCE_LIMIT_EXCEEDED,
            "workspace exceeds the admitted total regular-file byte limit",
            {
              limitBytes: limits.maxTotalBytes,
              nextPath: rel,
              projectedBytes: logicalBytes + statSize,
            },
          );
        }
        if (
          existingAliases === undefined &&
          allocatedBytes + statAllocatedBytes > limits.maxAllocatedBytes
        ) {
          fail(
            KNOCKOUT_WORKSPACE_ERROR_CODES.RESOURCE_LIMIT_EXCEEDED,
            "workspace exceeds the admitted allocated-byte limit",
            {
              limitBytes: limits.maxAllocatedBytes,
              nextPath: rel,
              projectedBytes: allocatedBytes + statAllocatedBytes,
            },
          );
        }
        const remainingLogicalBytes = existingAliases === undefined
          ? limits.maxTotalBytes - logicalBytes
          : existingAliases[0].size;
        const remainingAllocatedBytes = existingAliases === undefined
          ? limits.maxAllocatedBytes - allocatedBytes
          : existingAliases[0].observation.allocatedBytes;
        const observed = observeRegularFile(abs, null, {
          maxAllocatedBytes: Math.max(0, remainingAllocatedBytes),
          maxBytes: Math.max(1, Math.min(limits.maxFileBytes, remainingLogicalBytes)),
          operationBudget,
        });
        const node = {
          executable: (observed.observation.mode & 0o111) !== 0,
          hardlinkCount: null,
          hardlinkGroup: null,
          mode: observed.observation.mode,
          observation: observed.observation,
          path: rel,
          provenance: null,
          sha256: observed.sha256,
          size: observed.observation.size,
          type: "file",
        };
        addNode(
          node,
          depth + 1,
          { abs, expected: observed.observation, isSymlink: false },
        );
        const aliases = regularByIdentity.get(observed.observation.identity) ?? [];
        if (aliases.length === 0) {
          logicalBytes += observed.observation.size;
          allocatedBytes += observed.observation.allocatedBytes;
          if (logicalBytes > limits.maxTotalBytes) {
            fail(
              KNOCKOUT_WORKSPACE_ERROR_CODES.RESOURCE_LIMIT_EXCEEDED,
              "workspace exceeds the admitted total regular-file byte limit",
              { limitBytes: limits.maxTotalBytes, observedBytes: logicalBytes },
            );
          }
          if (allocatedBytes > limits.maxAllocatedBytes) {
            fail(
              KNOCKOUT_WORKSPACE_ERROR_CODES.RESOURCE_LIMIT_EXCEEDED,
              "workspace exceeds the admitted allocated-byte limit",
              { limitBytes: limits.maxAllocatedBytes, observedBytes: allocatedBytes },
            );
          }
        }
        aliases.push(node);
        regularByIdentity.set(observed.observation.identity, aliases);
        continue;
      }
      if (stat.isSymbolicLink()) {
        let target;
        try { target = fs.readlinkSync(abs, "utf8"); }
        catch (error) {
          fail(KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE, `${rel} changed while reading`, null, error);
        }
        if (path.isAbsolute(target)) {
          fail(KNOCKOUT_WORKSPACE_ERROR_CODES.UNSAFE_SYMLINK, `${rel} has an absolute target`);
        }
        const lexical = path.resolve(path.dirname(abs), target);
        if (!pathInside(physical, lexical)) {
          fail(KNOCKOUT_WORKSPACE_ERROR_CODES.UNSAFE_SYMLINK, `${rel} escapes the workspace`);
        }
        let resolved;
        try { resolved = fs.realpathSync(abs); }
        catch (error) {
          fail(
            KNOCKOUT_WORKSPACE_ERROR_CODES.UNSAFE_SYMLINK,
            `${rel} is dangling or cannot be resolved safely`,
            null,
            error,
          );
        }
        if (!pathInside(physical, resolved)) {
          fail(KNOCKOUT_WORKSPACE_ERROR_CODES.UNSAFE_SYMLINK, `${rel} resolves outside the workspace`);
        }
        let after;
        let targetAfter;
        try {
          after = fs.lstatSync(abs, { bigint: true });
          targetAfter = fs.readlinkSync(abs, "utf8");
        } catch (error) {
          fail(
            KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE,
            `${rel} changed during final symbolic-link observation`,
            null,
            error,
          );
        }
        if (
          !after.isSymbolicLink() || identityOf(stat) !== identityOf(after) ||
          stat.ctimeNs !== after.ctimeNs || targetAfter !== target
        ) {
          fail(KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE, `${rel} changed while reading`);
        }
        addNode({
          executable: false,
          hardlinkCount: null,
          hardlinkGroup: null,
          mode: modeOf(stat),
          observation: Object.freeze({
            ctimeNs: String(stat.ctimeNs),
            dev: String(stat.dev),
            identity: identityOf(stat),
            ino: String(stat.ino),
            mode: modeOf(stat),
            mtimeNs: String(stat.mtimeNs),
            nlink: Number(stat.nlink),
          }),
          path: rel,
          provenance: null,
          target,
          type: "symlink",
        }, depth + 1, { abs, expected: stat, isSymlink: true });
        continue;
      }
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.SPECIAL_NODE_UNSUPPORTED,
        `${rel} has an unsupported filesystem node type`,
      );
    }
    let after;
    try { after = fs.lstatSync(absDir, { bigint: true }); }
    catch (error) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE,
        `${relDir} disappeared after enumeration`,
        null,
        error,
      );
    }
    if (
      !after.isDirectory() || identityOf(before) !== identityOf(after) ||
      before.mode !== after.mode || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs
    ) {
      fail(KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE, `${relDir} changed while enumerating`);
    }
    remainingOperationMs(operationBudget, `workspace census at ${relDir}`);
  };

  walk(physical, ".", 0);
  if (pendingNodeReservations !== 0) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE, "workspace node reservations leaked");
  }
  const metadata = observeMetadataBatch(
    metadataRequests,
    operationBudget,
    workspaceDirectory,
    metadataCache,
  );
  if (metadata.length !== provisional.length) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE,
      "workspace metadata batch returned an incomplete observation",
    );
  }
  for (let index = 0; index < provisional.length; index++) {
    provisional[index].provenance = metadata[index];
  }
  for (const aliases of regularByIdentity.values()) {
    aliases.sort((left, right) => Buffer.compare(Buffer.from(left.path), Buffer.from(right.path)));
    const observedLinks = aliases[0].observation.nlink;
    if (aliases.some((node) => node.observation.nlink !== observedLinks) || observedLinks !== aliases.length) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.EXTERNAL_HARDLINK_UNSUPPORTED,
        `hardlink topology escapes the workspace at ${aliases[0].path}`,
        { internalNames: aliases.length, observedLinks },
      );
    }
    if (aliases.length > 1) {
      const group = sha256(Buffer.from(`noa-knockout-hardlink/1\0${aliases.map((n) => n.path).join("\0")}`));
      for (const node of aliases) {
        node.hardlinkCount = aliases.length;
        node.hardlinkGroup = group;
      }
    }
  }
  provisional.sort((left, right) => Buffer.compare(Buffer.from(left.path), Buffer.from(right.path)));
  const nodes = provisional.map((node) => Object.freeze({ ...node }));
  const nodesByPath = new Map(nodes.map((node) => [node.path, node]));
  for (const node of nodes) {
    if (node.type !== "symlink") continue;
    const components = node.path.split("/");
    const parent = components.length === 1 ? "." : components.slice(0, -1).join("/");
    const target = path.posix.normalize(path.posix.join(parent, node.target));
    const resolved = resolveCensusTarget(nodesByPath, target, {
      forbidRootGit: rootGitPolicy === "exclude",
      operationBudget,
    });
    if (resolved.kind === "forbidden-root-git") {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.UNSAFE_SYMLINK,
        `${node.path} resolves into excluded root Git metadata`,
        { resolvedPath: resolved.path },
      );
    }
    if (resolved.kind !== "resolved") {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.UNSAFE_SYMLINK,
        `${node.path} has an unsupported symbolic-link chain`,
        { resolution: resolved.kind, resolvedPath: resolved.path },
      );
    }
  }
  const resourceMetrics = resourceMetricsFromNodes(nodes, operationBudget);
  if (
    resourceMetrics === null || resourceMetrics.allocatedBytes !== allocatedBytes ||
    resourceMetrics.logicalBytes !== logicalBytes ||
    resourceMetrics.maxDepth !== observedMaxDepth || resourceMetrics.nodeCount !== nodes.length
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE,
      "workspace resource metrics diverged from its node census",
    );
  }
  const materialNodes = nodes.map(materialNode);
  remainingOperationMs(operationBudget, "workspace material hash");
  const materialSha256 = sha256(canonicalJsonBytes(materialNodes));
  remainingOperationMs(operationBudget, "workspace observation hash");
  const observationSha256 = sha256(canonicalJsonBytes(nodes));
  remainingOperationMs(operationBudget, "workspace census completion");
  return Object.freeze({
    allocatedBytes: resourceMetrics.allocatedBytes,
    limits,
    logicalBytes: resourceMetrics.logicalBytes,
    materialSha256,
    maxDepth: resourceMetrics.maxDepth,
    nodeCount: resourceMetrics.nodeCount,
    nodes: Object.freeze(nodes),
    observationSha256,
    provenancePolicy: Object.freeze({
      allowedName: PROVENANCE_XATTR,
      classification: PROVENANCE_CLASSIFICATION,
      copiedOrMutatedByWorkspace: false,
    }),
    root: physical,
  });
}

function nulFields(bytes) {
  if (bytes.length === 0) return [];
  if (bytes[bytes.length - 1] !== 0) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_OBSERVATION_FAILED,
      "Git pathname output is not NUL terminated",
    );
  }
  const fields = [];
  let start = 0;
  for (let index = 0; index < bytes.length; index++) {
    if (bytes[index] !== 0) continue;
    fields.push(bytes.subarray(start, index));
    start = index + 1;
  }
  return fields;
}

function isGitMetadataPathComponent(component) {
  const folded = component
    .normalize("NFKD")
    .replace(/\p{Default_Ignorable_Code_Point}/gu, "")
    .toLowerCase()
    .replace(/[ .]+$/u, "");
  return folded === ".git" || folded === ".git~1";
}

function decodeCanonicalIndexPath(
  pathnameBytes,
  label,
  code = KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_INDEX_UNSUPPORTED,
) {
  const pathname = decodeUtf8(pathnameBytes, label, code);
  const components = pathname.split("/");
  if (
    pathnameBytes.length === 0 || pathname.startsWith("/") ||
    /^[A-Za-z]:[\\/]/u.test(pathname) ||
    components.some((component) =>
      component === "" || component === "." || component === ".." ||
      isGitMetadataPathComponent(component))
  ) {
    fail(code, `${label} is not a canonical relative worktree path`, { pathname });
  }
  return pathname;
}

function parseIndexEntries(bytes, objectFormat, label) {
  const objectPattern = objectFormat === "sha256" ? /^[0-9a-f]{64}$/ : /^[0-9a-f]{40}$/;
  const result = [];
  for (const field of nulFields(bytes)) {
    const tab = field.indexOf(0x09);
    if (tab < 0) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_INDEX_UNSUPPORTED,
        `${label} has no pathname delimiter`,
      );
    }
    const header = field.subarray(0, tab).toString("ascii");
    const match = /^([0-7]{6}) ([0-9a-f]+) ([0-3])$/.exec(header);
    if (match === null || !objectPattern.test(match[2])) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_INDEX_UNSUPPORTED,
        `${label} has a malformed index entry`,
        { header },
      );
    }
    const mode = match[1];
    if (mode === "160000") {
      fail(KNOCKOUT_WORKSPACE_ERROR_CODES.GITLINK_UNSUPPORTED, `${label} contains a gitlink`);
    }
    if (mode === "040000") {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_INDEX_UNSUPPORTED,
        `${label} contains a sparse-index directory`,
      );
    }
    if (!["100644", "100755", "120000"].includes(mode)) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_INDEX_UNSUPPORTED,
        `${label} contains unsupported mode ${mode}`,
      );
    }
    const pathname = decodeCanonicalIndexPath(
      field.subarray(tab + 1),
      `${label} pathname`,
    );
    result.push(Object.freeze({
      mode,
      objectId: match[2],
      path: pathname,
      stage: Number(match[3]),
    }));
  }
  return Object.freeze(result);
}

const SUPPORTED_SOURCE_INDEX_EXTENSIONS = new Set([
  "EOIE",
  "IEOT",
  "REUC",
  "TREE",
  "UNTR",
  "link",
]);
const SUPPORTED_STANDALONE_INDEX_EXTENSIONS = new Set(["REUC"]);
const SEMANTIC_INDEX_EXTENSIONS = new Set(["REUC"]);

function parseRawGitIndex(bytes, objectFormat, label, options = {}) {
  const code = options.code ?? KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_INDEX_UNSUPPORTED;
  const maxEntries = options.maxEntries ?? KNOCKOUT_WORKSPACE_CAPTURE_LIMITS.maxNodes;
  const allowEmptyPaths = options.allowEmptyPaths ?? false;
  const invalid = (message, details = null) => fail(code, `${label} ${message}`, details);
  const hashAlgorithm = objectFormat === "sha256" ? "sha256" : "sha1";
  const hashLength = objectFormat === "sha256" ? 32 : 20;
  if (!Buffer.isBuffer(bytes) || bytes.length < 12 + hashLength) invalid("is truncated");
  if (!bytes.subarray(0, 4).equals(Buffer.from("DIRC", "ascii"))) {
    invalid("has a malformed signature");
  }
  const version = bytes.readUInt32BE(4);
  if (![2, 3, 4].includes(version)) invalid("uses an unsupported version", { version });
  const entryCount = bytes.readUInt32BE(8);
  if (!Number.isSafeInteger(maxEntries) || maxEntries < 0 || entryCount > maxEntries) {
    invalid("exceeds the admitted entry count", { entryCount, maxEntries });
  }
  const contentEnd = bytes.length - hashLength;
  const expectedChecksum = bytes.subarray(contentEnd);
  const observedChecksum = crypto.createHash(hashAlgorithm).update(bytes.subarray(0, contentEnd)).digest();
  if (!observedChecksum.equals(expectedChecksum)) invalid("has an invalid checksum");
  const requireBytes = (offset, length, phase) => {
    if (
      !Number.isSafeInteger(offset) || !Number.isSafeInteger(length) || offset < 0 || length < 0 ||
      offset + length > contentEnd
    ) invalid(`is truncated during ${phase}`, { length, offset });
  };
  const entries = [];
  let offset = 12;
  let previousPath = Buffer.alloc(0);
  for (let ordinal = 0; ordinal < entryCount; ordinal++) {
    const entryStart = offset;
    requireBytes(offset, 40 + hashLength + 2, `entry ${ordinal}`);
    const statBytes = bytes.subarray(offset, offset + 40);
    const mode = bytes.readUInt32BE(offset + 24);
    if (![0o100644, 0o100755, 0o120000].includes(mode)) {
      invalid(`entry ${ordinal} has unsupported mode`, { mode: mode.toString(8) });
    }
    offset += 40;
    const objectId = bytes.subarray(offset, offset + hashLength).toString("hex");
    offset += hashLength;
    const flags = bytes.readUInt16BE(offset);
    offset += 2;
    let extendedFlags = 0;
    if ((flags & 0x4000) !== 0) {
      if (version === 2) invalid(`entry ${ordinal} sets extended flags in version 2`);
      requireBytes(offset, 2, `entry ${ordinal} extended flags`);
      extendedFlags = bytes.readUInt16BE(offset);
      offset += 2;
      if ((extendedFlags & ~0x6000) !== 0) {
        invalid(`entry ${ordinal} sets unknown extended flags`, { extendedFlags });
      }
    }
    let pathname;
    if (version === 4) {
      requireBytes(offset, 1, `entry ${ordinal} path prefix`);
      let byte = bytes[offset++];
      let strip = byte & 0x7f;
      while ((byte & 0x80) !== 0) {
        requireBytes(offset, 1, `entry ${ordinal} path prefix`);
        byte = bytes[offset++];
        strip = ((strip + 1) * 128) + (byte & 0x7f);
        if (!Number.isSafeInteger(strip) || strip > previousPath.length) {
          invalid(`entry ${ordinal} has an invalid compressed path prefix`, { strip });
        }
      }
      if (strip > previousPath.length) {
        invalid(`entry ${ordinal} has an invalid compressed path prefix`, { strip });
      }
      const terminator = bytes.indexOf(0, offset);
      if (terminator < 0 || terminator >= contentEnd) invalid(`entry ${ordinal} has no path terminator`);
      pathname = Buffer.concat([
        previousPath.subarray(0, previousPath.length - strip),
        bytes.subarray(offset, terminator),
      ]);
      offset = terminator + 1;
    } else {
      const terminator = bytes.indexOf(0, offset);
      if (terminator < 0 || terminator >= contentEnd) invalid(`entry ${ordinal} has no path terminator`);
      pathname = bytes.subarray(offset, terminator);
      const encodedLength = flags & 0x0fff;
      if (encodedLength !== 0x0fff && encodedLength !== pathname.length) {
        invalid(`entry ${ordinal} path length differs`, {
          encodedLength,
          observedLength: pathname.length,
        });
      }
      offset = terminator + 1;
      const paddedEnd = entryStart + Math.ceil((offset - entryStart) / 8) * 8;
      requireBytes(offset, paddedEnd - offset, `entry ${ordinal} padding`);
      for (let cursor = offset; cursor < paddedEnd; cursor++) {
        if (bytes[cursor] !== 0) invalid(`entry ${ordinal} has non-zero padding`);
      }
      offset = paddedEnd;
    }
    if (pathname.length === 0 && !allowEmptyPaths) invalid(`entry ${ordinal} has an empty path`);
    if (pathname.length !== 0) {
      decodeCanonicalIndexPath(pathname, `${label} entry ${ordinal} pathname`, code);
    }
    previousPath = Buffer.from(pathname);
    entries.push(Object.freeze({
      assumeValid: (flags & 0x8000) !== 0,
      intentToAdd: (extendedFlags & 0x2000) !== 0,
      mode,
      objectId,
      path: pathname.toString("hex"),
      statOffset: entryStart,
      skipWorktree: (extendedFlags & 0x4000) !== 0,
      stage: (flags >>> 12) & 0x3,
      stat: statBytes.toString("hex"),
    }));
  }
  const entriesEnd = offset;
  const extensions = [];
  while (offset < contentEnd) {
    requireBytes(offset, 8, "extension header");
    const signatureBytes = bytes.subarray(offset, offset + 4);
    const signature = signatureBytes.toString("latin1");
    const size = bytes.readUInt32BE(offset + 4);
    offset += 8;
    requireBytes(offset, size, `extension ${signatureBytes.toString("hex")}`);
    extensions.push(Object.freeze({
      bytes: Buffer.from(bytes.subarray(offset, offset + size)),
      sha256: sha256(bytes.subarray(offset, offset + size)),
      signature,
      size,
    }));
    offset += size;
  }
  if (offset !== contentEnd) invalid("has trailing bytes before its checksum");
  return Object.freeze({
    checksum: expectedChecksum.toString("hex"),
    entries: Object.freeze(entries),
    entriesEnd,
    extensions: Object.freeze(extensions),
    version,
  });
}

function rawIndexExtensionProjection(parsed, signatures) {
  return Object.freeze(parsed.extensions
    .filter((extension) => signatures.has(extension.signature))
    .map((extension) => Object.freeze({
      sha256: extension.sha256,
      signature: extension.signature,
      size: extension.size,
    })));
}

function canonicalStandaloneIndexBytes(bytes, parsed, objectFormat) {
  const hashAlgorithm = objectFormat === "sha256" ? "sha256" : "sha1";
  const retained = parsed.extensions.filter((extension) => extension.signature === "REUC");
  const canonicalEntries = Buffer.from(bytes.subarray(0, parsed.entriesEnd));
  for (const entry of parsed.entries) {
    // A copied worktree must never inherit a source stat-cache claim. Preserve only the semantic
    // mode field; zero ctime, mtime, dev, ino, uid, gid, and size so Git must inspect the seed.
    canonicalEntries.fill(0, entry.statOffset, entry.statOffset + 24);
    canonicalEntries.fill(0, entry.statOffset + 28, entry.statOffset + 40);
  }
  const chunks = [canonicalEntries];
  for (const extension of retained) {
    const header = Buffer.alloc(8);
    header.write(extension.signature, 0, 4, "latin1");
    header.writeUInt32BE(extension.bytes.length, 4);
    chunks.push(header, Buffer.from(extension.bytes));
  }
  const content = Buffer.concat(chunks);
  return Buffer.concat([
    content,
    crypto.createHash(hashAlgorithm).update(content).digest(),
  ]);
}

function requireSupportedRawIndexExtensions(parsed, label, { standalone = false } = {}) {
  const allowed = standalone
    ? SUPPORTED_STANDALONE_INDEX_EXTENSIONS
    : SUPPORTED_SOURCE_INDEX_EXTENSIONS;
  const code = standalone
    ? KNOCKOUT_WORKSPACE_ERROR_CODES.STANDALONE_GIT_INVALID
    : KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_INDEX_UNSUPPORTED;
  const seen = new Set();
  for (const extension of parsed.extensions) {
    if (seen.has(extension.signature)) {
      fail(
        code,
        `${label} repeats index extension ${extension.signature}`,
      );
    }
    seen.add(extension.signature);
    if (extension.signature === "FSMN") {
      fail(
        code,
        `${label} contains unsupported fsmonitor index state`,
      );
    }
    if (extension.signature === "sdir") {
      fail(
        code,
        `${label} contains an unsupported sparse index`,
      );
    }
    if (!allowed.has(extension.signature)) {
      fail(
        code,
        `${label} contains unsupported index extension ${extension.signature}`,
        { signatureHex: Buffer.from(extension.signature, "latin1").toString("hex") },
      );
    }
  }
  return seen;
}

function decodeEwahSetBits(bytes, offset, maxBits, label) {
  const invalid = (message, details = null) => fail(
    KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_INDEX_UNSUPPORTED,
    `${label} ${message}`,
    details,
  );
  if (offset + 8 > bytes.length) invalid("is truncated");
  const bitSize = bytes.readUInt32BE(offset);
  const wordCount = bytes.readUInt32BE(offset + 4);
  if (bitSize > maxBits) invalid("exceeds the shared-index entry count", { bitSize, maxBits });
  const serializedBytes = 12 + wordCount * 8;
  if (!Number.isSafeInteger(serializedBytes) || offset + serializedBytes > bytes.length) {
    invalid("has an invalid compressed-word count", { wordCount });
  }
  const words = [];
  let cursor = offset + 8;
  for (let index = 0; index < wordCount; index++, cursor += 8) {
    words.push(bytes.readBigUInt64BE(cursor));
  }
  const rlwPosition = bytes.readUInt32BE(cursor);
  if (wordCount === 0 || rlwPosition >= wordCount) {
    invalid("has an invalid running-length-word position", { rlwPosition, wordCount });
  }
  const positions = [];
  let pointer = 0;
  let expandedWord = 0;
  const expectedWords = Math.ceil(bitSize / 64);
  const appendWord = (word) => {
    if (expandedWord >= expectedWords) invalid("expands beyond its declared bit size");
    for (let bit = 0; bit < 64; bit++) {
      const position = expandedWord * 64 + bit;
      if ((word & (1n << BigInt(bit))) === 0n) continue;
      if (position >= bitSize) invalid("sets a bit beyond its declared bit size", { position });
      positions.push(position);
    }
    expandedWord += 1;
  };
  while (pointer < words.length) {
    const rlw = words[pointer++];
    const runBit = (rlw & 1n) !== 0n;
    const runLength = Number((rlw >> 1n) & 0xffffffffn);
    const literalCount = Number(rlw >> 33n);
    if (pointer + literalCount > words.length) invalid("has truncated literal words");
    for (let index = 0; index < runLength; index++) appendWord(runBit ? 0xffffffffffffffffn : 0n);
    for (let index = 0; index < literalCount; index++) appendWord(words[pointer++]);
  }
  if (expandedWord !== expectedWords) {
    invalid("does not expand to its declared bit size", { expandedWord, expectedWords });
  }
  return Object.freeze({
    bytesConsumed: serializedBytes,
    positions: Object.freeze(positions),
  });
}

function validateLogicalRawIndexEntries(entries, limits, label) {
  if (entries.length > limits.maxNodes) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.RESOURCE_LIMIT_EXCEEDED,
      `${label} exceeds the admitted node count`,
    );
  }
  const stagesByPath = new Map();
  let previous = null;
  for (const entry of entries) {
    const pathBytes = Buffer.from(entry.path, "hex");
    if (previous !== null) {
      const pathOrder = Buffer.compare(Buffer.from(previous.path, "hex"), pathBytes);
      if (pathOrder > 0 || (pathOrder === 0 && previous.stage >= entry.stage)) {
        fail(
          KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_INDEX_UNSUPPORTED,
          `${label} is not strictly ordered by pathname and stage`,
        );
      }
    }
    previous = entry;
    const pathname = pathBytes.toString("utf8");
    const stages = stagesByPath.get(pathname) ?? new Set();
    stages.add(entry.stage);
    stagesByPath.set(pathname, stages);
  }
  for (const [pathname, stages] of stagesByPath) {
    if (stages.has(0) && stages.size !== 1) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_INDEX_UNSUPPORTED,
        `${label} mixes stage zero with unmerged stages`,
        { pathname },
      );
    }
    const components = pathname.split("/");
    for (let length = 1; length < components.length; length++) {
      const ancestor = components.slice(0, length).join("/");
      const ancestorStages = stagesByPath.get(ancestor);
      if (ancestorStages !== undefined && (stages.has(0) || ancestorStages.has(0))) {
        fail(
          KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_INDEX_UNSUPPORTED,
          `${label} contains a stage-zero directory/file conflict`,
          { ancestor, pathname },
        );
      }
    }
  }
  return entries;
}

function logicalEntriesFromRawIndex(indexBytes, sharedBytes, objectFormat, limits) {
  const main = parseRawGitIndex(indexBytes, objectFormat, "source Git index", {
    allowEmptyPaths: sharedBytes !== null,
    maxEntries: limits.maxNodes,
  });
  const mainExtensions = requireSupportedRawIndexExtensions(main, "source Git index");
  const linkExtensions = main.extensions.filter((extension) => extension.signature === "link");
  if (sharedBytes === null) {
    if (linkExtensions.length !== 0) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_INDEX_UNSUPPORTED,
        "source Git index requires a missing split-index companion",
      );
    }
    validateLogicalRawIndexEntries(main.entries, limits, "source Git index");
    return Object.freeze({ entries: main.entries, main, shared: null });
  }
  if (!mainExtensions.has("link") || linkExtensions.length !== 1) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_INDEX_UNSUPPORTED,
      "source split index does not contain exactly one link extension",
    );
  }
  const shared = parseRawGitIndex(sharedBytes, objectFormat, "source shared index", {
    maxEntries: limits.maxNodes,
  });
  const sharedExtensions = requireSupportedRawIndexExtensions(shared, "source shared index");
  if (sharedExtensions.has("link")) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_INDEX_UNSUPPORTED,
      "source shared index recursively uses split-index state",
    );
  }
  if (shared.extensions.length !== 0) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_INDEX_UNSUPPORTED,
      "source shared index contains unsupported extension state",
      { extensions: shared.extensions.map((extension) => extension.signature) },
    );
  }
  validateLogicalRawIndexEntries(shared.entries, limits, "source shared index");
  const link = linkExtensions[0].bytes;
  const hashLength = objectFormat === "sha256" ? 32 : 20;
  if (link.length < hashLength || link.subarray(0, hashLength).toString("hex") !== shared.checksum) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_INDEX_UNSUPPORTED,
      "source split-index link does not identify the selected shared index",
    );
  }
  let linkOffset = hashLength;
  let deleted = Object.freeze([]);
  let replaced = Object.freeze([]);
  if (linkOffset !== link.length) {
    const deleteBitmap = decodeEwahSetBits(
      link,
      linkOffset,
      shared.entries.length,
      "source split-index delete bitmap",
    );
    linkOffset += deleteBitmap.bytesConsumed;
    const replaceBitmap = decodeEwahSetBits(
      link,
      linkOffset,
      shared.entries.length,
      "source split-index replace bitmap",
    );
    linkOffset += replaceBitmap.bytesConsumed;
    deleted = deleteBitmap.positions;
    replaced = replaceBitmap.positions;
  }
  if (linkOffset !== link.length) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_INDEX_UNSUPPORTED,
      "source split-index link has trailing data",
    );
  }
  const deletedSet = new Set(deleted);
  for (const position of replaced) {
    if (deletedSet.has(position)) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_INDEX_UNSUPPORTED,
        "source split index replaces and deletes the same shared entry",
        { position },
      );
    }
  }
  if (replaced.length > main.entries.length) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_INDEX_UNSUPPORTED,
      "source split index has too few replacement entries",
    );
  }
  const merged = [...shared.entries];
  for (let ordinal = 0; ordinal < replaced.length; ordinal++) {
    const replacement = main.entries[ordinal];
    if (replacement.path !== "") {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_INDEX_UNSUPPORTED,
        "source split-index replacement entry has a non-empty path",
        { ordinal },
      );
    }
    merged[replaced[ordinal]] = Object.freeze({
      ...replacement,
      path: shared.entries[replaced[ordinal]].path,
    });
  }
  const survivors = merged.filter((_, position) => !deletedSet.has(position));
  for (const added of main.entries.slice(replaced.length)) {
    if (added.path === "") {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_INDEX_UNSUPPORTED,
        "source split-index added entry has an empty path",
      );
    }
    survivors.push(added);
  }
  survivors.sort((left, right) => {
    const pathOrder = Buffer.compare(Buffer.from(left.path, "hex"), Buffer.from(right.path, "hex"));
    return pathOrder === 0 ? left.stage - right.stage : pathOrder;
  });
  validateLogicalRawIndexEntries(survivors, limits, "merged source index");
  return Object.freeze({ entries: Object.freeze(survivors), main, shared });
}

function parseIntentToAdd(statusBytes) {
  const intent = [];
  const fields = nulFields(statusBytes);
  for (let index = 0; index < fields.length; index++) {
    const field = fields[index];
    if (field.length < 3) continue;
    const kind = field[0];
    if (kind === 0x32) index++; // rename/copy records carry one following original pathname
    if (kind !== 0x31) continue;
    let spaces = 0;
    let pathnameOffset = -1;
    for (let offset = 0; offset < field.length; offset++) {
      if (field[offset] !== 0x20) continue;
      spaces++;
      if (spaces === 8) {
        pathnameOffset = offset + 1;
        break;
      }
    }
    if (pathnameOffset < 0 || field.length < 4) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_INDEX_UNSUPPORTED,
        "Git status emitted a malformed ordinary record",
      );
    }
    const xy = field.subarray(2, 4).toString("ascii");
    if (xy === ".A") {
      intent.push(decodeUtf8(field.subarray(pathnameOffset), "intent-to-add pathname"));
    }
  }
  intent.sort((left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right)));
  return Object.freeze(intent);
}

function rejectHeadGitlinks(treeBytes) {
  for (const field of nulFields(treeBytes)) {
    const tab = field.indexOf(0x09);
    if (tab < 0) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_OBSERVATION_FAILED,
        "Git tree output has no pathname delimiter",
      );
    }
    const header = field.subarray(0, tab).toString("ascii");
    if (header.startsWith("160000 commit ")) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.GITLINK_UNSUPPORTED,
        `HEAD contains gitlink ${decodeUtf8(field.subarray(tab + 1), "gitlink pathname")}`,
      );
    }
  }
}

function observeGitFile(abs, label, options = {}) {
  const {
    byteBudget = null,
    limits: requestedLimits = KNOCKOUT_WORKSPACE_CAPTURE_LIMITS,
    maxBytes: requestedMaxBytes = null,
    metadataAnchor,
    operationBudget = null,
    retainBytes = false,
  } = options;
  const limits = normalizeCaptureLimits(requestedLimits);
  if (
    requestedMaxBytes !== null &&
    (!Number.isSafeInteger(requestedMaxBytes) || requestedMaxBytes < 1)
  ) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, `${label} byte cap is malformed`);
  }
  if (typeof retainBytes !== "boolean") {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, `${label} retainBytes must be boolean`);
  }
  const budgetedMaxBytes = byteBudget === null
    ? limits.maxFileBytes
    : byteBudget.remainingLimit(label);
  const maxBytes = requestedMaxBytes === null
    ? budgetedMaxBytes
    : Math.max(1, Math.min(requestedMaxBytes, budgetedMaxBytes));
  const observed = observeRegularFile(abs, null, {
    maxAllocatedBytes: limits.maxAllocatedBytes,
    maxBytes,
    operationBudget,
  });
  byteBudget?.charge(observed.bytes.length, label);
  const metadata = observeMetadata(
    abs,
    false,
    operationBudget,
    observed.observation,
    metadataAnchor,
  );
  if (operationBudget !== null) remainingOperationMs(operationBudget, `Git-file observation for ${label}`);
  const result = {
    metadata,
    mode: observed.observation.mode,
    observation: observed.observation,
    path: abs,
    sha256: observed.sha256,
    size: observed.observation.size,
  };
  if (retainBytes) {
    // The bytes are process-local input for raw parsing; they never enter canonical evidence.
    Object.defineProperty(result, "bytes", {
      configurable: false,
      enumerable: false,
      value: observed.bytes,
      writable: false,
    });
  }
  return Object.freeze(result);
}

function sameGitFile(left, right) {
  return canonicalJsonBytes(left).equals(canonicalJsonBytes(right));
}

const MAX_GIT_CONTROL_TEXT_BYTES = 64 * 1024;
const PER_WORKTREE_REF_PREFIXES = Object.freeze(["refs/bisect/", "refs/rewritten/", "refs/worktree/"]);

function gitFileEvidence(file) {
  return file === null
    ? null
    : Object.freeze({ observation: file.observation, sha256: file.sha256 });
}

function validGitFileEvidence(value) {
  return (
    value !== null && typeof value === "object" && !Array.isArray(value) &&
    HASH_64.test(value.sha256 ?? "") && validFileObservation(value.observation)
  );
}

function sameGitFileEvidence(file, evidence) {
  return (
    file !== null && validGitFileEvidence(evidence) &&
    file.sha256 === evidence.sha256 &&
    sameFileObservation(file.observation, evidence.observation)
  );
}

function sameOptionalGitFileEvidence(file, evidence) {
  return (
    (file === null) === (evidence === null) &&
    (file === null || sameGitFileEvidence(file, evidence))
  );
}

function gitFileDescriptor(file) {
  return Object.freeze({
    metadata: file.metadata,
    mode: file.mode,
    observation: file.observation,
    path: file.path,
    sha256: file.sha256,
    size: file.size,
  });
}

function parseGitfileTarget(bytes, sourceRoot) {
  const text = decodeUtf8(bytes, "root gitfile");
  const match = /^gitdir: ([^\r\n\0]+)\r?\n?$/u.exec(text);
  if (match === null) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_LAYOUT_UNSUPPORTED, "root gitfile is malformed");
  }
  return path.resolve(sourceRoot, match[1]);
}

function parseGitTextPath(bytes, label, base) {
  const text = decodeUtf8(bytes, label).replace(/\r?\n$/u, "");
  if (text.length === 0 || /[\r\n\0]/u.test(text)) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_LAYOUT_UNSUPPORTED, `${label} is malformed`);
  }
  return path.resolve(base, text);
}

function parseHeadReference(bytes, objectPattern) {
  const text = decodeUtf8(bytes, "Git HEAD").replace(/\r?\n$/u, "");
  if (text.startsWith("ref: ")) {
    const headRef = text.slice("ref: ".length);
    if (!REF_NAME.test(headRef)) {
      fail(KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_LAYOUT_UNSUPPORTED, "HEAD symbolic ref is malformed");
    }
    return Object.freeze({ headRef, oid: null });
  }
  if (!objectPattern.test(text)) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_OBSERVATION_FAILED, "HEAD identity is malformed");
  }
  return Object.freeze({ headRef: null, oid: text });
}

function parseLooseReference(bytes, refName, objectPattern) {
  const text = decodeUtf8(bytes, `Git ref ${refName}`).replace(/\r?\n$/u, "");
  if (text.startsWith("ref: ")) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_LAYOUT_UNSUPPORTED,
      `nested symbolic ref ${refName} is unsupported for isolated capture`,
    );
  }
  if (!objectPattern.test(text)) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_OBSERVATION_FAILED, `Git ref ${refName} is malformed`);
  }
  return text;
}

function parsePackedReference(bytes, refName, objectPattern) {
  const text = decodeUtf8(bytes, "packed-refs");
  let found = null;
  for (const line of text.split("\n")) {
    if (line.length === 0 || line.startsWith("#") || line.startsWith("^")) continue;
    const separator = line.indexOf(" ");
    if (separator < 1) {
      fail(KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_LAYOUT_UNSUPPORTED, "packed-refs is malformed");
    }
    if (line.slice(separator + 1) !== refName) continue;
    if (found !== null) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_LAYOUT_UNSUPPORTED,
        `packed-refs names ${refName} more than once`,
      );
    }
    const oid = line.slice(0, separator);
    if (!objectPattern.test(oid)) {
      fail(KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_OBSERVATION_FAILED, `packed ref ${refName} is malformed`);
    }
    found = oid;
  }
  return found;
}

function parseGitConfigList(bytes) {
  const entries = [];
  for (const record of decodeUtf8(bytes, "Git config listing").split("\0")) {
    if (record.length === 0) continue;
    const newline = record.indexOf("\n");
    entries.push(Object.freeze(
      newline === -1
        ? { key: record, value: null }
        : { key: record.slice(0, newline), value: record.slice(newline + 1) },
    ));
  }
  return Object.freeze(entries);
}

/**
 * Git parses the configuration bytes we already descriptor-read: they are piped to `git config
 * --file -`, Git's portable stdin sentinel, so no pathname of the live repository is consulted and
 * no private copy is written. Opening `/dev/stdin` is not equivalent on every supported host: a
 * Linux child whose fd 0 is a pipe can receive ENXIO when Git reopens that path. Include directives
 * are not followed by `--file` and are refused explicitly.
 */
function listBoundGitConfig(bytes, label, gitExecutable, operationBudget, byteBudget) {
  const listing = runObservedGit(
    "/",
    ["config", "--file", "-", "--null", "--list"],
    `${label} listing`,
    byteBudget,
    {
      code: KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_LAYOUT_UNSUPPORTED,
      gitExecutable,
      input: bytes,
      timeoutMs: remainingOperationMs(operationBudget, `${label} listing`),
    },
  );
  remainingOperationMs(operationBudget, `${label} listing`);
  return parseGitConfigList(listing);
}

const GIT_STATUS_CONFIG_DEFAULTS = Object.freeze({
  "core.filemode": true,
  "core.ignorecase": false,
  "core.precomposeunicode": false,
  "core.symlinks": true,
});
const GIT_STATUS_CONFIG_KEYS = Object.freeze(Object.keys(GIT_STATUS_CONFIG_DEFAULTS));
const GIT_STATUS_CONFIG_KEY_SET = new Set(GIT_STATUS_CONFIG_KEYS);
const GIT_LOCAL_CONFIG_NON_STATUS_KEYS = new Set([
  "core.bare",
  "core.fsmonitor",
  "core.hookspath",
  "core.logallrefupdates",
  "core.repositoryformatversion",
  "core.splitindex",
  "core.untrackedcache",
  // Candidate bootstrap requires the canonical origin pair so it can bind the public repository
  // identity. Neither value changes the local status/index semantics captured below, and the
  // sealed workspace deliberately reconstructs only statusConfig, so admit-and-drop them exactly.
  "remote.origin.fetch",
  "remote.origin.url",
  "user.email",
  "user.name",
]);

function parseGitBoolean(value, label, key) {
  if (value === null) return true;
  const normalized = value.toLowerCase();
  if (["1", "on", "true", "yes"].includes(normalized)) return true;
  if (["0", "off", "false", "no"].includes(normalized)) return false;
  fail(
    KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_LAYOUT_UNSUPPORTED,
    `${label} config has a non-boolean ${key}`,
    { key, value },
  );
}

function gitStatusConfig(overrides = {}) {
  return Object.freeze(Object.fromEntries(GIT_STATUS_CONFIG_KEYS.map((key) => [
    key,
    Object.hasOwn(overrides, key) ? overrides[key] : GIT_STATUS_CONFIG_DEFAULTS[key],
  ])));
}

function validGitStatusConfig(value) {
  return (
    value !== null && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).length === GIT_STATUS_CONFIG_KEYS.length &&
    GIT_STATUS_CONFIG_KEYS.every((key) => typeof value[key] === "boolean")
  );
}

function evaluateSourceGitConfig(entries, label, options = {}) {
  const worktree = options.worktree ?? false;
  const headRef = options.headRef ?? null;
  const values = new Map();
  const keySpellings = new Map();
  for (const entry of entries) {
    const key = entry.key.toLowerCase();
    const list = values.get(key) ?? [];
    list.push(entry.value);
    values.set(key, list);
    keySpellings.set(key, entry.key);
  }
  for (const [key, list] of values) {
    if (list.length !== 1) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_LAYOUT_UNSUPPORTED,
        `${label} config sets ${key} more than once`,
      );
    }
  }
  const single = (key) => {
    const list = values.get(key);
    if (list === undefined) return undefined;
    return list[0];
  };
  const branchName = !worktree && typeof headRef === "string" && headRef.startsWith("refs/heads/")
    ? headRef.slice("refs/heads/".length)
    : null;
  const upstreamKeys = branchName === null || branchName.length === 0
    ? null
    : Object.freeze({
        merge: `branch.${branchName}.merge`,
        remote: `branch.${branchName}.remote`,
      });
  const admittedUpstreamKeys = upstreamKeys === null
    ? new Set()
    : new Set([upstreamKeys.merge.toLowerCase(), upstreamKeys.remote.toLowerCase()]);
  for (const key of values.keys()) {
    if (key.startsWith("include.") || key.startsWith("includeif.")) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_LAYOUT_UNSUPPORTED,
        `${label} config include directives are unsupported for isolated capture`,
        { key },
      );
    }
    if (
      !GIT_STATUS_CONFIG_KEY_SET.has(key) &&
      !GIT_LOCAL_CONFIG_NON_STATUS_KEYS.has(key) &&
      !admittedUpstreamKeys.has(key) &&
      !key.startsWith("extensions.") &&
      !["core.attributesfile", "core.excludesfile"].includes(key)
    ) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_LAYOUT_UNSUPPORTED,
        `${label} config key ${key} is outside the closed isolated-capture policy`,
        { key },
      );
    }
  }
  if (upstreamKeys !== null) {
    const mergeKey = upstreamKeys.merge.toLowerCase();
    const remoteKey = upstreamKeys.remote.toLowerCase();
    const hasMerge = values.has(mergeKey);
    const hasRemote = values.has(remoteKey);
    if (hasMerge !== hasRemote) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_LAYOUT_UNSUPPORTED,
        `${label} config must set the current branch upstream remote and merge together`,
        { headRef },
      );
    }
    if (hasMerge) {
      if (
        keySpellings.get(mergeKey) !== upstreamKeys.merge ||
        keySpellings.get(remoteKey) !== upstreamKeys.remote
      ) {
        fail(
          KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_LAYOUT_UNSUPPORTED,
          `${label} config current branch upstream keys are not canonical`,
          { headRef },
        );
      }
      if (single(remoteKey) !== "origin") {
        fail(
          KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_LAYOUT_UNSUPPORTED,
          `${label} config current branch upstream remote must be origin`,
          { headRef },
        );
      }
      if (single(mergeKey) !== headRef) {
        fail(
          KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_LAYOUT_UNSUPPORTED,
          `${label} config current branch upstream merge must match HEAD`,
          { headRef },
        );
      }
    }
  }
  for (const key of ["core.excludesfile", "core.attributesfile"]) {
    if (values.has(key)) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_LAYOUT_UNSUPPORTED,
        `effective ${key} semantics are unsupported for isolated capture`,
      );
    }
  }
  const formatVersion = single("core.repositoryformatversion") ?? "0";
  if (worktree && values.has("core.repositoryformatversion")) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_LAYOUT_UNSUPPORTED,
      "worktree config cannot redefine the repository format",
    );
  }
  if (formatVersion !== "0" && formatVersion !== "1") {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_LAYOUT_UNSUPPORTED,
      `unsupported Git repository format version ${JSON.stringify(formatVersion)}`,
    );
  }
  let objectFormat = "sha1";
  let worktreeConfig = false;
  for (const key of values.keys()) {
    if (!key.startsWith("extensions.")) continue;
    if (worktree) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_LAYOUT_UNSUPPORTED,
        `Git worktree extension ${key} is unsupported for isolated capture`,
      );
    }
    if (key === "extensions.objectformat") {
      const value = single(key);
      if (value !== "sha1" && value !== "sha256") {
        fail(
          KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_LAYOUT_UNSUPPORTED,
          `unsupported Git object format ${JSON.stringify(value)}`,
        );
      }
      objectFormat = value;
      continue;
    }
    if (key === "extensions.refstorage") {
      const value = single(key);
      if (value !== "files") {
        fail(
          KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_LAYOUT_UNSUPPORTED,
          `unsupported Git ref storage ${JSON.stringify(value)}`,
        );
      }
      continue;
    }
    if (key === "extensions.worktreeconfig") {
      worktreeConfig = parseGitBoolean(single(key), label, key);
      continue;
    }
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_LAYOUT_UNSUPPORTED,
      `Git repository extension ${key} is unsupported for isolated capture`,
    );
  }
  if (values.has("core.bare") && parseGitBoolean(single("core.bare"), label, "core.bare")) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_LAYOUT_UNSUPPORTED,
      `${label} config describes a bare repository`,
    );
  }
  for (const key of ["core.logallrefupdates", "core.splitindex", "core.untrackedcache"]) {
    if (values.has(key)) parseGitBoolean(single(key), label, key);
  }
  const statusOverrides = {};
  for (const key of GIT_STATUS_CONFIG_KEYS) {
    if (values.has(key)) statusOverrides[key] = parseGitBoolean(single(key), label, key);
  }
  return Object.freeze({
    objectFormat,
    statusOverrides: Object.freeze(statusOverrides),
    worktreeConfig,
  });
}

/**
 * Repository-local semantics are admitted only under a closed policy. Four status booleans are
 * captured and replayed exactly; every other status-affecting or executable setting is refused.
 * Every input is descriptor-bound: the repository config (and the worktree config when its
 * extension is enabled) is read below the bound common and Git directories and parsed by Git from
 * a pipe; info/exclude and info/attributes are read the same way.
 */
function rejectUnsupportedLocalGitSemantics(
  commonBound,
  gitBound,
  gitExecutable,
  operationBudget,
  limits,
  byteBudget,
  options = {},
) {
  const configFile = readBoundGitFile(commonBound, "config", "Git config", {
    byteBudget,
    limits,
    operationBudget,
    optional: true,
    retainBytes: true,
  });
  if (configFile === null) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_LAYOUT_UNSUPPORTED,
      "Git repository has no configuration file",
      { path: commonBound.path },
    );
  }
  const policy = evaluateSourceGitConfig(
    listBoundGitConfig(configFile.bytes, "Git config", gitExecutable, operationBudget, byteBudget),
    "repository",
    { headRef: options.headRef ?? null },
  );
  let statusConfig = gitStatusConfig(policy.statusOverrides);
  const worktreeConfigFile = readBoundGitFile(
    gitBound,
    "config.worktree",
    "Git worktree config",
    {
      byteBudget,
      limits,
      operationBudget,
      optional: true,
      retainBytes: true,
    },
  );
  const commonWorktreeConfigFile = commonBound === gitBound
    ? null
    : readBoundGitFile(
        commonBound,
        "config.worktree",
        "Git common-directory worktree config",
        {
          byteBudget,
          limits,
          operationBudget,
          optional: true,
          retainBytes: true,
        },
      );
  if (policy.worktreeConfig) {
    if (worktreeConfigFile !== null) {
      const worktreePolicy = evaluateSourceGitConfig(
        listBoundGitConfig(
          worktreeConfigFile.bytes,
          "Git worktree config",
          gitExecutable,
          operationBudget,
          byteBudget,
        ),
        "worktree",
        { worktree: true },
      );
      statusConfig = gitStatusConfig({
        ...statusConfig,
        ...worktreePolicy.statusOverrides,
      });
    }
    if (commonWorktreeConfigFile !== null) {
      // A descriptor-rooted object child uses the common directory as GIT_DIR. Its main-worktree
      // config is therefore an input even though it must not override the selected linked
      // worktree's status semantics. Admit that child-only input under the same closed policy.
      evaluateSourceGitConfig(
        listBoundGitConfig(
          commonWorktreeConfigFile.bytes,
          "Git common-directory worktree config",
          gitExecutable,
          operationBudget,
          byteBudget,
        ),
        "common-directory worktree",
        { worktree: true },
      );
    }
  }
  const infoFiles = {};
  for (const basename of ["exclude", "attributes"]) {
    const observed = readBoundGitFile(commonBound, `info/${basename}`, `repository-local Git ${basename} rules`, {
      byteBudget,
      limits,
      operationBudget,
      optional: true,
      retainBytes: true,
    });
    infoFiles[basename] = gitFileEvidence(observed);
    if (observed === null) continue;
    const text = decodeUtf8(observed.bytes, `repository-local Git ${basename} rules`);
    const hasEffectiveRule = text.split(/\r?\n/u).some((line) => {
      const trimmed = line.trim();
      return trimmed.length > 0 && !trimmed.startsWith("#");
    });
    if (hasEffectiveRule) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_LAYOUT_UNSUPPORTED,
        `repository-local Git info/${basename} semantics are unsupported for isolated capture`,
        { path: observed.path },
      );
    }
  }
  return Object.freeze({
    commonWorktreeConfigFile: gitFileEvidence(commonWorktreeConfigFile),
    configFile: gitFileEvidence(configFile),
    infoAttributes: infoFiles.attributes,
    infoExclude: infoFiles.exclude,
    localSemanticsPolicy: "REPOSITORY_LOCAL_STATUS_SEMANTICS_CLOSED_AND_REPLAYED_V2",
    objectFormat: policy.objectFormat,
    statusConfig,
    worktreeConfigFile: gitFileEvidence(worktreeConfigFile),
  });
}

function observeSharedIndexCandidates(commonDirectory, options = {}) {
  const {
    bound = null,
    byteBudget = null,
    limits = KNOCKOUT_WORKSPACE_CAPTURE_LIMITS,
    metadataAnchor,
    operationBudget = null,
  } = options;
  let directory;
  try {
    directory = fs.opendirSync(commonDirectory, { bufferSize: 32, encoding: "buffer" });
  } catch (error) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_LAYOUT_UNSUPPORTED,
      "cannot enumerate the common Git directory",
      null,
      error,
    );
  }
  const candidates = [];
  let entries = 0;
  let pendingError = null;
  try {
    for (let entry = directory.readSync(); entry !== null; entry = directory.readSync()) {
      if (operationBudget !== null) {
        remainingOperationMs(operationBudget, "split-index candidate observation");
      }
      entries++;
      if (entries > MAX_GIT_DIRECTORY_ENTRIES) {
        fail(
          KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_LAYOUT_UNSUPPORTED,
          "common Git directory exceeds the bounded observation limit",
          { limit: MAX_GIT_DIRECTORY_ENTRIES },
        );
      }
      const nameBytes = Buffer.isBuffer(entry.name) ? entry.name : Buffer.from(entry.name);
      if (
        nameBytes.length !== 52 && nameBytes.length !== 76 ||
        !nameBytes.subarray(0, 12).equals(Buffer.from("sharedindex.", "ascii")) ||
        nameBytes.subarray(12).some((byte) =>
          !((byte >= 0x30 && byte <= 0x39) || (byte >= 0x61 && byte <= 0x66)))
      ) continue;
      if (candidates.length >= MAX_SHARED_INDEX_CANDIDATES) {
        fail(
          KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_LAYOUT_UNSUPPORTED,
          "split-index candidate count exceeds the bounded observation limit",
          { limit: MAX_SHARED_INDEX_CANDIDATES },
        );
      }
      const basename = nameBytes.toString("ascii");
      if (!entry.isFile()) {
        fail(
          KNOCKOUT_WORKSPACE_ERROR_CODES.SPECIAL_NODE_UNSUPPORTED,
          `split-index candidate ${basename} is not a regular file`,
        );
      }
      const candidate = observeGitFile(
        path.join(commonDirectory, basename),
        `split-index candidate ${basename}`,
        { byteBudget, limits, metadataAnchor, operationBudget },
      );
      if (bound !== null) {
        // The enumeration above is a pathname hint; the candidate is admitted only if the bound
        // index directory itself holds that very inode under that name.
        const entry = boundEntryStat(bound, basename, `split-index candidate ${basename}`, {
          code: KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED,
          operationBudget,
        });
        if (
          entry === null || entry.type !== "file" ||
          entry.identity !== candidate.observation.identity
        ) {
          fail(
            KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED,
            `split-index candidate ${basename} was not observed below its bound directory`,
            { boundIdentity: entry?.identity ?? null, readIdentity: candidate.observation.identity },
          );
        }
      }
      candidates.push(candidate);
    }
  } catch (error) {
    pendingError = error instanceof KnockoutWorkspaceError
      ? error
      : workspaceError(
          KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_LAYOUT_UNSUPPORTED,
          "cannot enumerate split-index candidates",
          { directory: commonDirectory },
          error,
        );
  }
  try { directory.closeSync(); }
  catch (error) {
    if (pendingError === null) {
      pendingError = workspaceError(
        KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_LAYOUT_UNSUPPORTED,
        "cannot close split-index candidate enumeration",
        { directory: commonDirectory },
        error,
      );
    }
  }
  if (pendingError !== null) throw pendingError;
  if (operationBudget !== null) {
    remainingOperationMs(operationBudget, "split-index candidate observation");
  }
  candidates.sort((left, right) => Buffer.compare(
    Buffer.from(path.basename(left.path), "ascii"),
    Buffer.from(path.basename(right.path), "ascii"),
  ));
  return Object.freeze(candidates);
}

function resolveScratchSharedIndex(
  sharedPathText,
  scratchRoot,
  scratchGit,
  scratchIndexDirectory,
  candidatesByBasename,
) {
  const interpretations = path.isAbsolute(sharedPathText)
    ? [path.resolve(sharedPathText)]
    : [path.resolve(scratchRoot, sharedPathText), path.resolve(scratchGit, sharedPathText)];
  const matches = [...new Set(interpretations)].filter((candidatePath) => {
    const basename = path.basename(candidatePath);
    return (
      path.dirname(candidatePath) === scratchGit &&
      SHARED_INDEX_BASENAME.test(basename) &&
      candidatesByBasename.has(basename)
    );
  });
  if (matches.length !== 1) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_LAYOUT_UNSUPPORTED,
      "private split-index discovery did not resolve exactly one copied candidate",
      { matches: matches.length },
    );
  }
  // Git reports the conventional $GIT_DIR/sharedindex.<oid> name even when read_index_from()
  // loaded its fallback companion beside GIT_INDEX_FILE. The conventional pathname is
  // deliberately absent: otherwise Git freshens its mtime on every read. The returned path is
  // the descriptor-witnessed fallback copy that Git actually consumed.
  return path.join(scratchIndexDirectory, path.basename(matches[0]));
}

function descriptorPrivateTreeCensus(
  rootBound,
  label,
  code,
  maxNodes,
  operationBudget,
) {
  if (operationBudget !== null) {
    remainingOperationMs(operationBudget, `${label} descriptor census`);
  }
  const result = spawnSync(
    METADATA_FCHDIR_LAUNCHER,
    [
      "-e",
      METADATA_FCHDIR_SCRIPT,
      "--",
      process.execPath,
      "-e",
      PRIVATE_TREE_CENSUS_SCRIPT,
      String(maxNodes),
    ],
    {
      encoding: null,
      env: { LANG: "C", LC_ALL: "C", PATH: "/usr/bin:/bin" },
      killSignal: "SIGKILL",
      maxBuffer: Math.min(MAX_TOOL_OUTPUT_BYTES, Math.max(64 * 1024, maxNodes * 1024)),
      stdio: ["ignore", "pipe", "pipe", rootBound.fd],
      timeout: metadataTimeout(operationBudget, `${label} descriptor census`),
    },
  );
  if (result.error !== undefined) {
    fail(
      childProcessFailureCode(result.error, code),
      `cannot execute ${label} descriptor census`,
      {
        launcher: METADATA_FCHDIR_LAUNCHER,
        launcherUnavailable: result.error?.code === "ENOENT",
        timedOut: result.error?.code === "ETIMEDOUT",
      },
      result.error,
    );
  }
  const stderr = Buffer.isBuffer(result.stderr) ? result.stderr.toString("utf8") : "";
  if (result.status !== 0 || stderr.length !== 0) {
    fail(
      code,
      `${label} descriptor census failed`,
      { status: result.status, stderr: stderr.slice(0, 4096) },
    );
  }
  let parsed;
  try {
    parsed = JSON.parse(Buffer.isBuffer(result.stdout) ? result.stdout.toString("utf8") : "");
  } catch (error) {
    fail(code, `${label} descriptor census emitted malformed JSON`, null, error);
  }
  if (!Array.isArray(parsed) || parsed.length < 1 || parsed.length > maxNodes) {
    fail(code, `${label} descriptor census exceeds its node contract`);
  }
  let prior = null;
  const records = parsed.map((record) => {
    const observation = record?.observation;
    if (
      record === null || typeof record !== "object" || Array.isArray(record) ||
      typeof record.path !== "string" ||
      (record.path !== "." && (
        path.isAbsolute(record.path) || record.path.split("/").some((part) =>
          part === "" || part === "." || part === "..")
      )) ||
      observation === null || typeof observation !== "object" || Array.isArray(observation) ||
      typeof observation.ctimeNs !== "string" ||
      typeof observation.identity !== "string" ||
      !Number.isInteger(observation.mode) ||
      typeof observation.mtimeNs !== "string" ||
      !Number.isInteger(observation.nlink) ||
      typeof observation.size !== "string" ||
      !["directory", "file"].includes(observation.type) ||
      (observation.type === "directory" ? record.sha256 !== null : !HASH_64.test(record.sha256 ?? ""))
    ) {
      fail(code, `${label} descriptor census emitted a malformed record`);
    }
    if (
      prior !== null &&
      Buffer.compare(Buffer.from(prior), Buffer.from(record.path)) >= 0
    ) {
      fail(code, `${label} descriptor census order is non-canonical`);
    }
    prior = record.path;
    return Object.freeze({
      observation: Object.freeze({ ...observation }),
      path: record.path,
      sha256: record.sha256,
    });
  });
  if (records[0].path !== "." || records[0].observation.type !== "directory") {
    fail(code, `${label} descriptor census has no directory root`);
  }
  if (operationBudget !== null) {
    remainingOperationMs(operationBudget, `${label} descriptor census`);
  }
  return Object.freeze(records);
}

/**
 * Hold every node of a small private tree open and witness it around a genuine Git child. The
 * descriptors pin the inodes; fstat before and after the child must return the identical
 * observation (identity, type, mode, size, nlink, mtime, ctime). A same-UID replacement of an
 * entry changes its directory's ctime, an in-place write changes the file's ctime, and neither
 * can be reset from user space, so any substitution while the child runs is refused.
 */
function holdPrivateTree(
  root,
  {
    code,
    expectedRootIdentity = null,
    label,
    maxNodes = MAX_GIT_DIRECTORY_ENTRIES,
    operationBudget = null,
  } = {},
) {
  if (!ERROR_CODE_SET.has(code) || typeof label !== "string" || label.length === 0) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "private tree witness options are malformed");
  }
  if (
    expectedRootIdentity !== null &&
    (typeof expectedRootIdentity !== "string" || expectedRootIdentity.length === 0)
  ) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "private tree root identity is malformed");
  }
  const held = [];
  const releaseLease = createReleaseLease({
    fallbackCode: code,
    message: `${label} witness release failed`,
  });
  const release = (primaryError = null) => releaseLease.release(primaryError);
  const observe = (stat) => Object.freeze({
    ctimeNs: String(stat.ctimeNs),
    identity: identityOf(stat),
    mode: modeOf(stat),
    mtimeNs: String(stat.mtimeNs),
    nlink: Number(stat.nlink),
    size: String(stat.size),
    type: stat.isDirectory() ? "directory" : stat.isFile() ? "file" : "other",
  });
  const hashHeldFile = (fd, sizeText, abs) => {
    const size = Number(sizeText);
    if (!Number.isSafeInteger(size) || size < 0) {
      fail(code, `${label} file has an unsafe size at ${abs}`, { size: sizeText });
    }
    const digest = crypto.createHash("sha256");
    const buffer = Buffer.allocUnsafe(Math.max(1, Math.min(WORKSPACE_COPY_BUFFER_BYTES, size)));
    let offset = 0;
    while (offset < size) {
      if (operationBudget !== null) remainingOperationMs(operationBudget, `${label} hash at ${abs}`);
      let read;
      try { read = fs.readSync(fd, buffer, 0, Math.min(buffer.length, size - offset), offset); }
      catch (error) { fail(code, `${label} file cannot be hashed at ${abs}`, null, error); }
      if (read < 1) fail(code, `${label} file ended during hashing at ${abs}`);
      digest.update(buffer.subarray(0, read));
      offset += read;
    }
    return digest.digest("hex");
  };
  const hold = (abs, relativePath, type) => {
    if (held.length >= maxNodes) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.RESOURCE_LIMIT_EXCEEDED,
        `${label} exceeds its witness node limit`,
        { limit: maxNodes, path: abs },
      );
    }
    if (operationBudget !== null) remainingOperationMs(operationBudget, `${label} witness at ${abs}`);
    let fd;
    try {
      fd = fs.openSync(
        abs,
        fs.constants.O_RDONLY | NOFOLLOW | (type === "directory" ? DIRECTORY : 0),
      );
    } catch (error) {
      fail(
        descriptorFailureCode(error, code),
        `${label} node cannot be held at ${abs}`,
        { path: abs },
        error,
      );
    }
    releaseLease.add(createDescriptorCloser(
      fd,
      code,
      `${label} node cannot be released at ${abs}`,
      { path: abs },
    ));
    let stat;
    try { stat = fs.fstatSync(fd, { bigint: true }); }
    catch (error) {
      fail(code, `${label} node cannot be observed at ${abs}`, { path: abs }, error);
    }
    const observation = observe(stat);
    if (observation.type !== type) {
      fail(code, `${label} node changed type at ${abs}`, { expected: type, observed: observation.type });
    }
    const fileSha256 = type === "file" ? hashHeldFile(fd, observation.size, abs) : null;
    held.push(Object.freeze({
      fd,
      observation,
      path: abs,
      relativePath,
      sha256: fileSha256,
    }));
  };
  const walkChildren = (directory, relativeDirectory) => {
    const entries = [];
    const enumerationLease = createReleaseLease({
      fallbackCode: code,
      message: `${label} enumeration release failed at ${directory}`,
    });
    try {
      const enumeration = fs.opendirSync(directory, { bufferSize: 32, encoding: "buffer" });
      enumerationLease.add(() => {
        try { enumeration.closeSync(); }
        catch (error) {
          fail(
            code,
            `cannot close ${label} enumeration at ${directory}`,
            { path: directory },
            error,
          );
        }
      });
      for (let entry = enumeration.readSync(); entry !== null; entry = enumeration.readSync()) {
        if (operationBudget !== null) remainingOperationMs(operationBudget, `${label} witness at ${directory}`);
        if (entries.length >= maxNodes) {
          fail(
            KNOCKOUT_WORKSPACE_ERROR_CODES.RESOURCE_LIMIT_EXCEEDED,
            `${label} exceeds its witness node limit`,
            { limit: maxNodes, path: directory },
          );
        }
        entries.push(Object.freeze({
          directory: entry.isDirectory(),
          file: entry.isFile(),
          name: decodeUtf8(entry.name, `${label} entry below ${directory}`),
          symlink: entry.isSymbolicLink(),
        }));
      }
    } catch (error) {
      const primary = error instanceof KnockoutWorkspaceError
        ? error
        : workspaceError(
            descriptorFailureCode(error, code),
            `cannot enumerate ${label} at ${directory}`,
            { path: directory },
            error,
          );
      throw releaseLeaseError(enumerationLease, primary);
    }
    enumerationLease.release();
    entries.sort((left, right) => Buffer.compare(Buffer.from(left.name), Buffer.from(right.name)));
    for (const entry of entries) {
      const abs = path.join(directory, entry.name);
      const relativePath = relativeDirectory === "."
        ? entry.name
        : `${relativeDirectory}/${entry.name}`;
      if (entry.symlink || (!entry.directory && !entry.file)) {
        fail(code, `${label} contains an unsupported node at ${abs}`, { path: abs });
      }
      if (entry.directory) {
        hold(abs, relativePath, "directory");
        walkChildren(abs, relativePath);
      } else {
        hold(abs, relativePath, "file");
      }
    }
  };
  const absoluteRoot = requireAbsolutePath(root, label);
  let baselineCensus;
  try {
    hold(absoluteRoot, ".", "directory");
    if (expectedRootIdentity !== null && held[0]?.observation.identity !== expectedRootIdentity) {
      fail(
        code,
        `${label} witness did not bind the expected root`,
        { expected: expectedRootIdentity, observed: held[0]?.observation.identity ?? null },
      );
    }
    baselineCensus = descriptorPrivateTreeCensus(
      held[0],
      label,
      code,
      maxNodes,
      operationBudget,
    );
    walkChildren(absoluteRoot, ".");
    const afterWalkCensus = descriptorPrivateTreeCensus(
      held[0],
      label,
      code,
      maxNodes,
      operationBudget,
    );
    const heldProjection = held
      .map((node) => Object.freeze({
        observation: node.observation,
        path: node.relativePath,
        sha256: node.sha256,
      }))
      .sort((left, right) => Buffer.compare(Buffer.from(left.path), Buffer.from(right.path)));
    if (
      !canonicalJsonBytes(baselineCensus).equals(canonicalJsonBytes(afterWalkCensus)) ||
      !canonicalJsonBytes(baselineCensus).equals(canonicalJsonBytes(heldProjection))
    ) {
      fail(code, `${label} changed while its descriptor-rooted witness was constructed`);
    }
  }
  catch (error) {
    throw releaseLeaseError(releaseLease, error);
  }
  const confirm = (phase) => {
    releaseLease.assertActive(code);
    for (const node of held) {
      let stat;
      try { stat = fs.fstatSync(node.fd, { bigint: true }); }
      catch (error) {
        fail(code, `${label} node cannot be re-observed at ${node.path}`, { phase }, error);
      }
      const current = observe(stat);
      if (!canonicalJsonBytes(current).equals(canonicalJsonBytes(node.observation))) {
        fail(
          code,
          `${label} changed ${phase} at ${node.path}`,
          { expected: node.observation, observed: current, phase },
        );
      }
      if (current.type === "file" && hashHeldFile(node.fd, current.size, node.path) !== node.sha256) {
        fail(code, `${label} file bytes changed ${phase} at ${node.path}`, { phase });
      }
    }
    const currentCensus = descriptorPrivateTreeCensus(
      held[0],
      label,
      code,
      maxNodes,
      operationBudget,
    );
    if (!canonicalJsonBytes(currentCensus).equals(canonicalJsonBytes(baselineCensus))) {
      fail(code, `${label} descriptor-rooted tree changed ${phase}`, { phase });
    }
  };
  return Object.freeze({ confirm, nodeCount: held.length, release });
}

/**
 * Private Git-observation scratch for the live source. Git never receives an absolute private
 * pathname: every semantic command runs on the bound scratch descriptor with GIT_DIR,
 * GIT_INDEX_FILE and GIT_WORK_TREE relative to it, and the whole scratch tree is held open and
 * witnessed around each child (holdPrivateTree). Index and split-index companion copies live
 * together below `.git/index-observation/`; the conventional `.git/sharedindex.<oid>` pathname is
 * absent. Git therefore reads the companion beside GIT_INDEX_FILE but cannot freshen the held
 * file's timestamps as it normally does for a split index. This scratch is index-only: it has no
 * live object-store authority and no synthetic HEAD.
 */
function createGitObservationScratch(
  sourceRoot,
  commonDirectory,
  gitObservation,
  indexMetadataAnchor,
  gitExecutable,
  operationBudget,
  limits,
  byteBudget,
  scratchRoot,
  scratchParentPrivate,
  binding,
) {
  if (
    binding === null || binding === undefined || typeof binding !== "object" ||
    binding.indexBound === null || typeof binding.indexBound !== "object"
  ) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "Git observation binding is malformed");
  }
  const commandTimeout = () => remainingOperationMs(
    operationBudget,
    "private Git-observation scratch",
  );
  const observeScratchGit = (root, args, label, extra = {}) => {
    const bytes = runObservedGit(
      root,
      args,
      label,
      byteBudget,
      { gitExecutable, timeoutMs: commandTimeout(), ...extra },
    );
    remainingOperationMs(operationBudget, label);
    return bytes;
  };
  const indexDirectory = path.dirname(gitObservation.index.path);
  const sourceCandidates = observeSharedIndexCandidates(indexDirectory, {
    bound: binding.indexBound,
    byteBudget,
    limits,
    metadataAnchor: indexMetadataAnchor,
    operationBudget,
  });
  const created = createUniquePrivateDirectory(
    scratchRoot,
    "noa-kws-git-observe-",
    {
      label: "private Git-observation scratch",
      operationBudget,
      privateParent: scratchParentPrivate,
    },
  );
  const releaseLease = createReleaseLease({
    fallbackCode: KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
    message: "private Git-observation scratch release failed",
  });
  let scratchBound = null;
  let scratchParentBound = null;
  let witness = null;
  try {
    observeScratchGit(
      created.path,
      ["init", "-q", `--object-format=${gitObservation.objectFormat}`, "--template="],
      "private observation Git init",
    );
    const scratchGit = path.join(created.path, ".git");
    observeScratchGit(
      created.path,
      ["config", "--local", "core.filemode", "true"],
      "private observation Git filemode config",
    );
    observeScratchGit(
      created.path,
      ["config", "--local", "core.symlinks", "true"],
      "private observation Git symlink config",
    );
    clampPrivateGitTree(scratchGit, { limits, operationBudget });
    const scratchGitRoot = requireRealDirectory(
      scratchGit,
      "private Git-observation directory",
      { operationBudget, privateMode: true },
    );
    const scratchIndexDirectory = createPrivateDirectory(
      path.join(scratchGit, "index-observation"),
      { operationBudget },
    );
    copyObservedGitFile(gitObservation.index, path.join(scratchIndexDirectory.path, "index"), {
      byteBudget,
      destinationMetadataAnchor: scratchIndexDirectory,
      limits,
      operationBudget,
    });
    const candidatesByBasename = new Map();
    for (const sourceCandidate of sourceCandidates) {
      const basename = path.basename(sourceCandidate.path);
      if (candidatesByBasename.has(basename)) {
        fail(
          KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_LAYOUT_UNSUPPORTED,
          `split-index candidate ${basename} is ambiguous`,
        );
      }
      const scratchCandidatePath = path.join(scratchIndexDirectory.path, basename);
      copyObservedGitFile(sourceCandidate, scratchCandidatePath, {
        byteBudget,
        destinationMetadataAnchor: scratchIndexDirectory,
        limits,
        operationBudget,
      });
      const scratchCandidate = assertPrivateFile(
        scratchCandidatePath,
        sourceCandidate.sha256,
        null,
        {
          metadataAnchor: scratchIndexDirectory,
          mismatchCode: KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
          operationBudget,
        },
      );
      if (scratchCandidate.observation.identity === sourceCandidate.observation.identity) {
        fail(
          KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
          `split-index candidate ${basename} was not byte-copied to a new inode`,
        );
      }
      const sourceCandidateAfter = readBoundGitFile(
        binding.indexBound,
        basename,
        `split-index candidate ${basename}`,
        {
          byteBudget,
          limits,
          operationBudget,
          typeCode: KNOCKOUT_WORKSPACE_ERROR_CODES.SPECIAL_NODE_UNSUPPORTED,
        },
      );
      if (!sameGitFile(sourceCandidate, sourceCandidateAfter)) {
        fail(
          KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED,
          `split-index candidate ${basename} changed while it was copied`,
        );
      }
      candidatesByBasename.set(basename, sourceCandidateAfter);
    }
    const environment = Object.freeze({
      ...scrubGitEnvironment(),
      GIT_DIR: ".git",
      GIT_INDEX_FILE: ".git/index-observation/index",
      GIT_NO_LAZY_FETCH: "1",
      GIT_WORK_TREE: ".",
    });
    const scratchDirectory = requireRealDirectory(
      created.path,
      "private Git-observation scratch",
      { expectedIdentity: created.identity, operationBudget, privateMode: true },
    );
    scratchBound = releaseLease.ownBound(
      bindDirectoryDescriptor(
        scratchDirectory,
        "private Git-observation scratch",
        KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
        operationBudget,
      ),
      "private Git-observation scratch",
      KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
    );
    if (scratchParentPrivate) {
      scratchParentBound = releaseLease.ownBound(
        bindDirectoryDescriptor(
          requireRealDirectory(
            scratchRoot,
            "private Git-observation scratch parent",
            { operationBudget, privateMode: true },
          ),
          "private Git-observation scratch parent",
          KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
          operationBudget,
        ),
        "private Git-observation scratch parent",
        KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
      );
    }
    const conventionalSharedIndexes = [...candidatesByBasename.keys()].filter((name) => {
      try {
        fs.lstatSync(path.join(scratchGit, name));
        return true;
      } catch (error) {
        if (error !== null && typeof error === "object" && error.code === "ENOENT") return false;
        fail(
          KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
          "cannot inspect the conventional private shared-index pathname",
          { name },
          error,
        );
      }
    });
    if (conventionalSharedIndexes.length !== 0) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
        "private Git-observation scratch exposes a timestamp-mutable shared-index pathname",
        { entries: conventionalSharedIndexes.sort() },
      );
    }
    witness = holdPrivateTree(created.path, {
      code: KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
      expectedRootIdentity: scratchBound.identity,
      label: "private Git-observation scratch",
      maxNodes: MAX_SHARED_INDEX_CANDIDATES + GIT_OBSERVATION_SCRATCH_FIXED_FD_RESERVE,
      operationBudget,
    });
    releaseLease.add(() => witness.release());
    const boundWitness = witness;
    const boundScratch = scratchBound;
    const boundScratchParent = scratchParentBound;
    const run = (args, label, extra = {}) => {
      if (boundScratchParent !== null) {
        confirmBoundDirectory(
          boundScratchParent,
          "private Git-observation scratch parent",
          KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
          operationBudget,
        );
      }
      confirmBoundDirectory(
        boundScratch,
        "private Git-observation scratch",
        KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
        operationBudget,
      );
      boundWitness.confirm(`before ${label}`);
      const bytes = observeScratchGit(created.path, args, label, {
        directoryFd: boundScratch.fd,
        environment,
        ...extra,
      });
      boundWitness.confirm(`after ${label}`);
      confirmBoundDirectory(
        boundScratch,
        "private Git-observation scratch",
        KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
        operationBudget,
      );
      if (boundScratchParent !== null) {
        confirmBoundDirectory(
          boundScratchParent,
          "private Git-observation scratch parent",
          KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
          operationBudget,
        );
      }
      return bytes;
    };
    const release = (primaryError = null) => releaseLease.release(primaryError);
    const sharedPathText = oneLine(
      run(
        ["rev-parse", "--shared-index-path"],
        "private shared-index path",
        { code: KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_INDEX_UNSUPPORTED },
      ),
      "private shared-index path",
      { allowEmpty: true },
    );
    let sharedIndex = null;
    if (sharedPathText !== "") {
      const scratchSharedPath = resolveScratchSharedIndex(
        sharedPathText,
        created.path,
        scratchGit,
        scratchIndexDirectory.path,
        candidatesByBasename,
      );
      const basename = path.basename(scratchSharedPath);
      const objectPattern = gitObservation.objectFormat === "sha256" ? HASH_64 : HASH_40;
      if (!objectPattern.test(basename.slice("sharedindex.".length))) {
        fail(
          KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_LAYOUT_UNSUPPORTED,
          "private split-index discovery selected the wrong object-format identity",
          { basename, objectFormat: gitObservation.objectFormat },
        );
      }
      const sourceCandidate = candidatesByBasename.get(basename);
      const livePath = path.join(indexDirectory, basename);
      if (sourceCandidate === undefined || sourceCandidate.path !== livePath) {
        fail(
          KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_LAYOUT_UNSUPPORTED,
          "private split-index discovery did not map to exactly one live candidate",
          { basename },
        );
      }
      sharedIndex = readBoundGitFile(binding.indexBound, basename, "selected split-index companion", {
        byteBudget,
        limits,
        operationBudget,
        typeCode: KNOCKOUT_WORKSPACE_ERROR_CODES.SPECIAL_NODE_UNSUPPORTED,
      });
      if (!sameGitFile(sourceCandidate, sharedIndex)) {
        fail(
          KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED,
          "selected split-index companion changed during private discovery",
          { basename },
        );
      }
    }
    return Object.freeze({ created, environment, release, run, sharedIndex });
  } catch (error) {
    throw reportRetainedPrivateRoots(
      releaseLeaseError(releaseLease, error),
      [retainCreatedPrivateTree(created)],
    );
  }
}

function validGitTopologyExpectation(value) {
  return (
    value !== null && typeof value === "object" && !Array.isArray(value) &&
    ["direct", "linked"].includes(value.topology) &&
    typeof value.gitDirectory === "string" && path.isAbsolute(value.gitDirectory) &&
    typeof value.gitDirectoryIdentity === "string" && value.gitDirectoryIdentity.length > 0 &&
    validDirectoryObservation(value.gitDirectoryObservation) &&
    typeof value.commonDirectory === "string" && path.isAbsolute(value.commonDirectory) &&
    typeof value.commonDirectoryIdentity === "string" && value.commonDirectoryIdentity.length > 0 &&
    validDirectoryObservation(value.commonDirectoryObservation) &&
    validGitFileEvidence(value.configFile) &&
    (value.worktreeConfigFile === null || validGitFileEvidence(value.worktreeConfigFile)) &&
    (value.commonWorktreeConfigFile === null ||
      validGitFileEvidence(value.commonWorktreeConfigFile)) &&
    value.nestedCommondir === null &&
    (value.commonDirectory !== value.gitDirectory || value.commonWorktreeConfigFile === null)
  );
}

/**
 * Observe every Git value used to materialize the seed from ONE admitted physical topology.
 *
 * Nothing about the live repository is taken from a pathname-resolved Git command. The source root,
 * the Git directory and the common directory are bound directory descriptors; the root `.git`
 * entry, the linked-worktree gitfile and back-reference, `commondir`, the repository and worktree
 * configuration, `info/exclude`, `info/attributes`, `HEAD`, the HEAD ref (loose or packed), the raw
 * index and the selected split-index companion are all descriptor-relative reads confirmed against
 * the entry the bound directory holds. Every Git command runs through the fchdir launcher on the
 * bound source root with `GIT_WORK_TREE=.`, a private scratch `GIT_DIR`, and an object directory
 * that is relative to the bound root when it lies inside it. Object bytes are bound by object
 * identity: `index-pack` and `hash-object` re-hash every ingested object, so a pathname-substituted
 * object store can only fail, never forge. Git's own discovery output (top level, Git directory,
 * common directory, index path, object format, HEAD, symbolic ref) is retained as a cross-check
 * that must agree with the bound reads; any disagreement is refused as SOURCE_CHANGED.
 */
export function observeSourceGit(sourceRoot, options = {}) {
  if (options === null || typeof options !== "object" || Array.isArray(options)) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "source Git options are malformed");
  }
  const {
    commandTimeoutMs = MAX_CHILD_PROCESS_DURATION_MS,
    expectedRoot = null,
    expectedTopology = null,
    gitExecutable = null,
    limits: requestedLimits = KNOCKOUT_WORKSPACE_CAPTURE_LIMITS,
    operationBudget: suppliedBudget = null,
    scratchRoot: requestedScratchRoot = null,
  } = options;
  const boundedTimeoutMs = requireCommandTimeoutMs(commandTimeoutMs);
  const limits = normalizeCaptureLimits(requestedLimits);
  const operationBudget = suppliedBudget ?? createOperationBudget(boundedTimeoutMs);
  const byteBudget = createObservationByteBudget(limits, "source Git observation");
  const commandTimeout = () => remainingOperationMs(operationBudget, "source Git observation");
  if (gitExecutable !== null && (typeof gitExecutable !== "string" || !path.isAbsolute(gitExecutable))) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "gitExecutable must be absolute or null");
  }
  if (expectedRoot !== null && !validBoundDirectory(expectedRoot)) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "expected source root binding is malformed");
  }
  if (expectedTopology !== null && !validGitTopologyExpectation(expectedTopology)) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "expected Git topology binding is malformed");
  }
  const changed = (message, details = null) => fail(
    KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED,
    message,
    details,
  );
  const sourceDirectory = requireSourceRoot(sourceRoot, expectedRoot, operationBudget, {
    observation: expectedRoot?.observation ?? null,
  });
  const source = sourceDirectory.path;
  const releaseLease = createReleaseLease({
    fallbackCode: KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED,
    message: "source Git observation release failed",
  });
  let primaryError = null;
  try {
    const sourceBound = releaseLease.ownBound(
      bindDirectoryDescriptor(
        sourceDirectory,
        "source root",
        KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED,
        operationBudget,
      ),
      "source root",
      KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED,
    );
    const observeGit = (args, label, extra = {}) => {
      const bytes = runObservedGit(
        source,
        args,
        label,
        byteBudget,
        { directoryFd: sourceBound.fd, gitExecutable, timeoutMs: commandTimeout(), ...extra },
      );
      remainingOperationMs(operationBudget, label);
      return bytes;
    };
    const controlFile = (bound, name, label, extra = {}) => readBoundGitFile(bound, name, label, {
      byteBudget,
      limits,
      maxBytes: MAX_GIT_CONTROL_TEXT_BYTES,
      operationBudget,
      retainBytes: true,
      ...extra,
    });

    // 1. The root `.git` entry, observed relative to the bound source root.
    const rootEntry = boundEntryStat(sourceBound, ".git", "root Git entry", {
      code: KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED,
      operationBudget,
    });
    if (rootEntry === null) {
      fail(KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_NOT_GIT_WORKTREE, `${source} is not a Git worktree`);
    }
    let gitDirectoryPath;
    let rootGitEntry;
    if (rootEntry.type === "directory") {
      gitDirectoryPath = path.join(source, ".git");
      rootGitEntry = Object.freeze({
        gitfile: null,
        identity: rootEntry.identity,
        target: null,
        type: "directory",
      });
    } else if (rootEntry.type === "file") {
      const gitfile = controlFile(sourceBound, ".git", "root gitfile");
      gitDirectoryPath = parseGitfileTarget(gitfile.bytes, source);
      rootGitEntry = Object.freeze({
        gitfile: gitFileEvidence(gitfile),
        identity: rootEntry.identity,
        target: gitDirectoryPath,
        type: "gitfile",
      });
    } else {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_LAYOUT_UNSUPPORTED,
        "root .git entry must be a directory or a gitfile",
        { type: rootEntry.type },
      );
    }
    const topology = rootGitEntry.type === "directory" ? "direct" : "linked";
    if (expectedTopology !== null && expectedTopology.topology !== topology) {
      changed("source Git topology kind changed", {
        expected: expectedTopology.topology,
        observed: topology,
      });
    }

    // 2. The Git directory: for a direct layout its identity is the bound root's own `.git` entry;
    //    for a linked layout it is bound once and confirmed by pathname on every later reopen.
    const expectedGitDirectoryIdentity = expectedTopology?.gitDirectoryIdentity ??
      (topology === "direct" ? rootEntry.identity : null);
    if (topology === "direct" && expectedTopology !== null &&
      expectedTopology.gitDirectoryIdentity !== rootEntry.identity) {
      changed("root .git entry identity changed", {
        expected: expectedTopology.gitDirectoryIdentity,
        observed: rootEntry.identity,
      });
    }
    const gitDirectory = requireRealDirectory(gitDirectoryPath, "Git directory", {
      expectedIdentity: expectedGitDirectoryIdentity,
      expectedIdentityCode: expectedGitDirectoryIdentity === null
        ? null
        : KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED,
      operationBudget,
    });
    if (
      expectedTopology !== null &&
      (gitDirectory.path !== expectedTopology.gitDirectory ||
        !sameDirectoryObservation(gitDirectory.observation, expectedTopology.gitDirectoryObservation))
    ) {
      changed("Git directory changed during the observed interval", {
        expected: expectedTopology.gitDirectoryObservation,
        expectedPath: expectedTopology.gitDirectory,
        observed: gitDirectory.observation,
        path: gitDirectory.path,
      });
    }
    const gitBound = releaseLease.ownBound(
      bindDirectoryDescriptor(
        gitDirectory,
        "Git directory",
        KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED,
        operationBudget,
      ),
      "Git directory",
      KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED,
    );

    // 3. A linked worktree's Git directory must name this very worktree back.
    let worktreeBackReference = null;
    if (topology === "linked") {
      const backReference = controlFile(gitBound, "gitdir", "linked worktree back-reference", {
        optional: true,
      });
      if (backReference === null) {
        fail(
          KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_LAYOUT_UNSUPPORTED,
          "linked worktree Git directory has no back-reference",
          { path: gitDirectory.path },
        );
      }
      const backTarget = parseGitTextPath(
        backReference.bytes,
        "linked worktree back-reference",
        gitDirectory.path,
      );
      let backWorktree = null;
      try { backWorktree = fs.realpathSync(path.dirname(backTarget)); }
      catch {}
      if (path.basename(backTarget) !== ".git" || backWorktree !== source) {
        fail(
          KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_LAYOUT_UNSUPPORTED,
          "linked worktree back-reference does not name this worktree",
          { backTarget, source },
        );
      }
      worktreeBackReference = Object.freeze({
        ...gitFileEvidence(backReference),
        target: backTarget,
      });
    }

    // 4. The common directory through the bound `commondir` indirection.
    const commondirFile = controlFile(gitBound, "commondir", "Git commondir", { optional: true });
    let commonDirectory = gitDirectory;
    let commonBound = gitBound;
    if (commondirFile !== null) {
      const commonPath = parseGitTextPath(commondirFile.bytes, "Git commondir", gitDirectory.path);
      commonDirectory = requireRealDirectory(commonPath, "Git common directory", {
        expectedIdentity: expectedTopology?.commonDirectoryIdentity ?? null,
        expectedIdentityCode: expectedTopology === null
          ? null
          : KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED,
        operationBudget,
      });
      commonBound = releaseLease.ownBound(
        bindDirectoryDescriptor(
          commonDirectory,
          "Git common directory",
          KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED,
          operationBudget,
        ),
        "Git common directory",
        KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED,
      );
    }
    if (
      expectedTopology !== null &&
      (commonDirectory.path !== expectedTopology.commonDirectory ||
        commonDirectory.identity !== expectedTopology.commonDirectoryIdentity ||
        !sameDirectoryObservation(
          commonDirectory.observation,
          expectedTopology.commonDirectoryObservation,
        ))
    ) {
      changed("Git common directory changed during the observed interval", {
        expected: expectedTopology.commonDirectoryObservation,
        expectedPath: expectedTopology.commonDirectory,
        observed: commonDirectory.observation,
        path: commonDirectory.path,
      });
    }
    // The first `commondir` is the only admitted indirection. A second one below the selected
    // common directory would let descriptor-rooted object children discover another control root.
    const nestedCommondirFile = controlFile(
      commonBound,
      "commondir",
      "Git common-directory nested commondir",
      { optional: true },
    );
    if (nestedCommondirFile !== null) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_LAYOUT_UNSUPPORTED,
        "Git common directory contains an unsupported second commondir indirection",
        { path: nestedCommondirFile.path },
      );
    }
    const nestedCommondir = null;
    const scratchParentPrivate = requestedScratchRoot !== null;
    const scratchDirectory = requireRealDirectory(
      requestedScratchRoot ?? os.tmpdir(),
      "Git scratch root",
      { operationBudget, privateMode: scratchParentPrivate },
    ).path;
    if (
      pathInside(source, scratchDirectory) || pathInside(gitDirectory.path, scratchDirectory) ||
      pathInside(commonDirectory.path, scratchDirectory)
    ) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
        "Git scratch root must not be inside the source or its Git control directories",
        {
          commonDirectory: commonDirectory.path,
          gitDirectory: gitDirectory.path,
          scratchRoot: scratchDirectory,
          source,
        },
      );
    }

    // 5. Git's own discovery, executed on the bound root, must agree with the bound topology.
    const inside = oneLine(
      observeGit(["rev-parse", "--is-inside-work-tree"], "worktree result"),
      "worktree result",
    );
    if (inside !== "true") {
      fail(KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_NOT_GIT_WORKTREE, `${source} is not a Git worktree`);
    }
    const top = realpathOrFail(
      oneLine(
        observeGit(["rev-parse", "--path-format=absolute", "--show-toplevel"], "worktree root"),
        "worktree root",
      ),
      KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_LAYOUT_UNSUPPORTED,
      "Git worktree root",
    );
    if (top !== source) {
      // Git ran on the bound root descriptor, so its top level is either an ancestor of the
      // requested pathname (the caller named a subdirectory of the worktree) or the bound inode
      // reached under another name (the source or one of its ancestors was renamed while the
      // command ran). Only the first is a caller error.
      if (pathInside(top, source)) {
        fail(
          KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_NOT_GIT_WORKTREE,
          "sourceRoot must name the complete Git worktree",
          { observed: top, requested: source },
        );
      }
      changed("source root was renamed during Git observation", { observed: top, requested: source });
    }
    const reportedGitDirectory = realpathOrFail(
      oneLine(observeGit(["rev-parse", "--absolute-git-dir"], "Git directory"), "Git directory"),
      KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_LAYOUT_UNSUPPORTED,
      "Git directory",
    );
    const reportedCommonDirectory = realpathOrFail(
      oneLine(
        observeGit(
          ["rev-parse", "--path-format=absolute", "--git-common-dir"],
          "Git common directory",
        ),
        "Git common directory",
      ),
      KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_LAYOUT_UNSUPPORTED,
      "Git common directory",
    );
    if (reportedGitDirectory !== gitDirectory.path || reportedCommonDirectory !== commonDirectory.path) {
      changed("live Git discovery disagrees with the bound source topology", {
        boundCommonDirectory: commonDirectory.path,
        boundGitDirectory: gitDirectory.path,
        reportedCommonDirectory,
        reportedGitDirectory,
      });
    }
    const indexPath = oneLine(
      observeGit(
        ["rev-parse", "--path-format=absolute", "--git-path", "index"],
        "Git index path",
      ),
      "Git index path",
    );
    if (
      !path.isAbsolute(indexPath) || path.basename(indexPath) !== "index" ||
      realpathOrFail(
        path.dirname(indexPath),
        KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_LAYOUT_UNSUPPORTED,
        "Git index directory",
      ) !== gitDirectory.path
    ) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_LAYOUT_UNSUPPORTED,
        "Git index is not the bound Git directory's index",
        { gitDirectory: gitDirectory.path, indexPath },
      );
    }

    // 6. Bind HEAD before admitting its exact current-branch upstream pair from configuration.
    const headFile = controlFile(gitBound, "HEAD", "Git HEAD");
    const configHeadRef = parseHeadReference(headFile.bytes, HASH_40_OR_64).headRef;

    // Repository-local semantics and the object format, from bound configuration bytes.
    const localSemantics = rejectUnsupportedLocalGitSemantics(
      commonBound,
      gitBound,
      gitExecutable,
      operationBudget,
      limits,
      byteBudget,
      { headRef: configHeadRef },
    );
    if (
      expectedTopology !== null &&
      (!sameGitFileEvidence(
        Object.freeze({
          observation: localSemantics.configFile.observation,
          sha256: localSemantics.configFile.sha256,
        }),
        expectedTopology.configFile,
      ) ||
        !sameOptionalGitFileEvidence(
          localSemantics.worktreeConfigFile,
          expectedTopology.worktreeConfigFile,
        ) ||
        !sameOptionalGitFileEvidence(
          localSemantics.commonWorktreeConfigFile,
          expectedTopology.commonWorktreeConfigFile,
        ))
    ) {
      changed("source Git configuration changed during the observed interval");
    }
    const objectFormat = localSemantics.objectFormat;
    const reportedObjectFormat = oneLine(
      observeGit(["rev-parse", "--show-object-format"], "object format"),
      "object format",
    );
    if (reportedObjectFormat !== objectFormat) {
      changed("live Git object format disagrees with the bound repository configuration", {
        bound: objectFormat,
        reported: reportedObjectFormat,
      });
    }
    const objectPattern = objectFormat === "sha256" ? HASH_64 : HASH_40;
    const objectAuthority = createBoundObjectAuthority(
      commonBound,
      objectFormat,
      {
        byteBudget,
        configFile: localSemantics.configFile,
        limits,
        nestedCommondir,
        operationBudget,
        worktreeConfigFile: commonBound === gitBound
          ? localSemantics.worktreeConfigFile
          : localSemantics.commonWorktreeConfigFile,
      },
    );
    releaseLease.add(() => objectAuthority.release());
    const objectGit = (args, label, extra = {}) => objectAuthority.run(label, (directoryFd, environment) => {
      const bytes = runObservedGit(
        objectAuthority.objectsBound.path,
        args,
        label,
        byteBudget,
        {
          directoryFd,
          environment,
          gitExecutable,
          timeoutMs: commandTimeout(),
          ...extra,
        },
      );
      remainingOperationMs(operationBudget, label);
      return bytes;
    });

    // 7. HEAD and its ref from the bound read; Git's answer must agree.
    const parsedHead = parseHeadReference(headFile.bytes, objectPattern);
    const headRef = parsedHead.headRef;
    let head = parsedHead.oid;
    let headReference = null;
    let packedRefs = null;
    const readHeadReference = () => {
      if (headRef === null) return null;
      const referenceBound = PER_WORKTREE_REF_PREFIXES.some((prefix) => headRef.startsWith(prefix))
        ? gitBound
        : commonBound;
      const loose = controlFile(referenceBound, headRef, `Git ref ${headRef}`, { optional: true });
      if (loose !== null) {
        return Object.freeze({
          file: loose,
          oid: parseLooseReference(loose.bytes, headRef, objectPattern),
          packed: null,
          reference: Object.freeze({
            name: headRef,
            observation: loose.observation,
            sha256: loose.sha256,
            storage: "loose",
          }),
        });
      }
      const packed = readBoundGitFile(commonBound, "packed-refs", "Git packed-refs", {
        byteBudget,
        limits,
        operationBudget,
        optional: true,
        retainBytes: true,
      });
      const packedOid = packed === null
        ? null
        : parsePackedReference(packed.bytes, headRef, objectPattern);
      if (packedOid === null) {
        fail(
          KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_OBSERVATION_FAILED,
          `HEAD ref ${headRef} is unborn or unresolvable`,
        );
      }
      return Object.freeze({
        file: null,
        oid: packedOid,
        packed,
        reference: Object.freeze({ name: headRef, observation: null, sha256: null, storage: "packed" }),
      });
    };
    const resolvedHead = readHeadReference();
    if (resolvedHead !== null) {
      head = resolvedHead.oid;
      headReference = resolvedHead.reference;
      packedRefs = gitFileEvidence(resolvedHead.packed);
    }
    const reportedHead = oneLine(observeGit(["rev-parse", "HEAD"], "HEAD"), "HEAD");
    const symbolic = runGitAllowStatus(
      source,
      ["symbolic-ref", "-q", "HEAD"],
      new Set([0, 1]),
      gitExecutable,
      commandTimeout(),
      byteBudget.remainingLimit("HEAD symbolic ref"),
      { directoryFd: sourceBound.fd },
    );
    byteBudget.charge(
      (Buffer.isBuffer(symbolic.stdout) ? symbolic.stdout.length : 0) +
        (Buffer.isBuffer(symbolic.stderr) ? symbolic.stderr.length : 0),
      "HEAD symbolic ref",
    );
    remainingOperationMs(operationBudget, "HEAD symbolic ref");
    const reportedHeadRef = symbolic.status === 0 ? oneLine(symbolic.stdout, "HEAD symbolic ref") : null;
    if (reportedHead !== head || reportedHeadRef !== headRef) {
      changed("live Git HEAD disagrees with the bound HEAD and ref files", {
        boundHead: head,
        boundHeadRef: headRef,
        reportedHead,
        reportedHeadRef,
      });
    }

    // 8. The raw index from the bound Git directory.
    const indexRead = readBoundGitFile(gitBound, "index", "Git index", {
      byteBudget,
      code: KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_LAYOUT_UNSUPPORTED,
      limits,
      operationBudget,
      retainBytes: true,
      typeCode: KNOCKOUT_WORKSPACE_ERROR_CODES.SPECIAL_NODE_UNSUPPORTED,
    });
    const preliminaryRawIndex = parseRawGitIndex(
      indexRead.bytes,
      objectFormat,
      "source Git index",
      { allowEmptyPaths: true, maxEntries: limits.maxNodes },
    );
    requireSupportedRawIndexExtensions(preliminaryRawIndex, "source Git index");
    const indexBefore = gitFileDescriptor(indexRead);

    // 9. Index-derived semantics from a witnessed private scratch whose descriptor is Git's
    //    working directory; nothing about the scratch reaches Git as an absolute pathname. Status
    //    semantics are not observed live at all: they are produced on the descriptor-bound seed by
    //    validateStandaloneGit from the very inputs bound here.
    const objectsPath = path.join(commonDirectory.path, "objects");
    const scratch = createGitObservationScratch(
      source,
      commonDirectory.path,
      { head, index: indexBefore, objectFormat },
      gitBound,
      gitExecutable,
      operationBudget,
      limits,
      byteBudget,
      scratchDirectory,
      scratchParentPrivate,
      Object.freeze({ indexBound: gitBound }),
    );
    releaseLease.add(() => scratch.release());
    const sharedBefore = scratch.sharedIndex;
    const scratchResidue = retainCreatedPrivateTree(scratch.created);
    try {
      const scratchGit = (args, label) => scratch.run(args, label);
      const headTree = oneLine(
        objectGit(["rev-parse", `${head}^{tree}`], "HEAD tree"),
        "HEAD tree",
      );
      if (!objectPattern.test(headTree)) {
        fail(KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_GIT_OBSERVATION_FAILED, "HEAD tree identity is malformed");
      }
      rejectHeadGitlinks(objectGit(
        ["ls-tree", "-r", "--full-tree", "-z", head],
        "HEAD tree listing",
      ));
      const stageBytes = scratchGit(["ls-files", "--stage", "--full-name", "-z"], "Git stage listing");
      const resolveUndoBytes = scratchGit(
        ["ls-files", "--resolve-undo", "--full-name", "-z"],
        "Git resolve-undo listing",
      );
      const stages = parseIndexEntries(stageBytes, objectFormat, "Git index");
      const resolveUndo = parseIndexEntries(
        resolveUndoBytes,
        objectFormat,
        "resolve-undo index extension",
      );

      // 10. The observed interval is closed: every bound control file must be exactly as first
      //     read, and every bound directory must still be the one that was bound.
      const indexAfter = readBoundGitFile(gitBound, "index", "Git index", {
        byteBudget,
        limits,
        operationBudget,
        typeCode: KNOCKOUT_WORKSPACE_ERROR_CODES.SPECIAL_NODE_UNSUPPORTED,
      });
      const sharedAfter = sharedBefore === null
        ? null
        : readBoundGitFile(
            gitBound,
            path.basename(sharedBefore.path),
            "selected split-index companion",
            {
              byteBudget,
              limits,
              operationBudget,
              typeCode: KNOCKOUT_WORKSPACE_ERROR_CODES.SPECIAL_NODE_UNSUPPORTED,
            },
          );
      const sharedStable = sharedBefore === null
        ? sharedAfter === null
        : sharedAfter !== null && sameGitFile(sharedBefore, sharedAfter);
      if (!sameGitFile(indexBefore, indexAfter) || !sharedStable) {
        changed("source Git index changed during read-only observation", {
          indexAfter,
          indexBefore,
          sharedAfter,
          sharedBefore,
        });
      }
      const headFileAfter = controlFile(gitBound, "HEAD", "Git HEAD");
      const resolvedHeadAfter = readHeadReference();
      if (
        !canonicalJsonBytes(gitFileEvidence(headFile))
          .equals(canonicalJsonBytes(gitFileEvidence(headFileAfter))) ||
        (resolvedHead === null) !== (resolvedHeadAfter === null) ||
        (resolvedHead !== null &&
          (resolvedHeadAfter.oid !== resolvedHead.oid ||
            !canonicalJsonBytes(resolvedHeadAfter.reference).equals(canonicalJsonBytes(resolvedHead.reference)) ||
            !canonicalJsonBytes(gitFileEvidence(resolvedHeadAfter.packed))
              .equals(canonicalJsonBytes(gitFileEvidence(resolvedHead.packed)))))
      ) {
        changed("source Git HEAD changed during read-only observation");
      }
      confirmBoundDirectory(sourceBound, "source root", KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED, operationBudget);
      confirmBoundDirectory(gitBound, "Git directory", KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED, operationBudget);
      if (commonBound !== gitBound) {
        confirmBoundDirectory(commonBound, "Git common directory", KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED, operationBudget);
      }
      const objectIds = [...new Set([...stages, ...resolveUndo].map((entry) => entry.objectId))].sort();
      return freezeWithRetainedPrivateRoots({
        commonWorktreeConfigFile: localSemantics.commonWorktreeConfigFile,
        commonDirectory: commonDirectory.path,
        commonDirectoryIdentity: commonDirectory.identity,
        commonDirectoryObservation: commonDirectory.observation,
        commondir: commondirFile === null
          ? null
          : Object.freeze({
              ...gitFileEvidence(commondirFile),
              target: parseGitTextPath(
                commondirFile.bytes,
                "Git commondir",
                gitDirectory.path,
              ),
            }),
        configFile: localSemantics.configFile,
        gitDirectory: gitDirectory.path,
        gitDirectoryIdentity: gitDirectory.identity,
        gitDirectoryObservation: gitDirectory.observation,
        head,
        headFile: gitFileEvidence(headFile),
        headRef,
        headReference,
        headTree,
        index: indexAfter,
        indexStageBytes: stageBytes.length,
        indexStageSha256: sha256(stageBytes),
        infoAttributes: localSemantics.infoAttributes,
        infoExclude: localSemantics.infoExclude,
        localSemanticsPolicy: localSemantics.localSemanticsPolicy,
        nestedCommondir,
        objectDirectory: objectsPath,
        objectFormat,
        objectIds: Object.freeze(objectIds),
        packedRefs,
        resolveUndo: Object.freeze(resolveUndo),
        rootGitEntry,
        sharedIndex: sharedAfter,
        stages: Object.freeze(stages),
        statusConfig: localSemantics.statusConfig,
        topology,
        worktreeBackReference,
        worktreeConfigFile: localSemantics.worktreeConfigFile,
        worktreeRoot: source,
        worktreeRootIdentity: sourceDirectory.identity,
        worktreeRootObservation: sourceDirectory.observation,
      }, [scratchResidue]);
    } catch (error) {
      throw reportRetainedPrivateRoots(error, [scratchResidue]);
    }
  } catch (error) {
    primaryError = error;
    throw error;
  } finally {
    releaseLease.release(primaryError);
  }
}

export function observeSourceSnapshot(sourceRoot, options = {}) {
  if (options === null || typeof options !== "object" || Array.isArray(options)) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "source snapshot options are malformed");
  }
  const commandTimeoutMs = requireCommandTimeoutMs(
    options.commandTimeoutMs ?? MAX_CHILD_PROCESS_DURATION_MS,
  );
  const operationBudget = options.operationBudget ?? createOperationBudget(commandTimeoutMs);
  const expectedRoot = options.expectedRoot ?? null;
  if (expectedRoot !== null && !validBoundDirectory(expectedRoot)) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "expected source root binding is malformed");
  }
  const expectedTopology = options.expectedTopology ?? null;
  if (expectedTopology !== null && !validGitTopologyExpectation(expectedTopology)) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "expected Git topology binding is malformed");
  }
  const sharedOptions = {
    ...options,
    commandTimeoutMs,
    expectedRoot,
    expectedTopology,
    operationBudget,
  };
  const git = observeSourceGit(sourceRoot, sharedOptions);
  try {
    // The census reopens the same pathname independently of the Git commands. It is bound to the
    // identity the Git observation admitted, and its root node must carry the very directory
    // observation the Git observation saw: one snapshot never composes two physical roots.
    const workspace = censusWorkspace(git.worktreeRoot, {
      commandTimeoutMs,
      expectedRoot: Object.freeze({ identity: git.worktreeRootIdentity, path: git.worktreeRoot }),
      expectedRootCode: KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED,
      limits: options.limits ?? KNOCKOUT_WORKSPACE_CAPTURE_LIMITS,
      metadataCache: options.metadataCache ?? null,
      operationBudget,
      rootGitPolicy: "exclude",
    });
    const censusRoot = workspace.nodes.find((node) => node.path === ".");
    if (
      censusRoot === undefined || censusRoot.type !== "directory" ||
      !sameDirectoryObservation(censusRoot.observation, git.worktreeRootObservation)
    ) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED,
        "source root changed between Git observation and workspace census",
        {
          censusRoot: censusRoot?.observation ?? null,
          gitRoot: git.worktreeRootObservation,
          path: git.worktreeRoot,
        },
      );
    }
    // Retained scratch custody is deliberately attached as non-enumerable process metadata.
    // Project only the observed Git fields before entering the strict canonical JSON contract.
    const canonicalGit = Object.freeze({ ...git });
    const descriptor = Object.freeze({ git: canonicalGit, workspace });
    return freezeWithRetainedPrivateRoots({
      ...descriptor,
      snapshotSha256: sha256(canonicalJsonBytes(descriptor)),
    }, retainedPrivateRoots(git));
  } catch (error) {
    throw reportRetainedPrivateRoots(error, retainedPrivateRoots(git));
  }
}

export function verifySourceUnchanged(expectedSnapshot, options = {}) {
  if (
    expectedSnapshot === null || typeof expectedSnapshot !== "object" ||
    typeof expectedSnapshot.snapshotSha256 !== "string" ||
    typeof expectedSnapshot.workspace?.root !== "string" ||
    typeof expectedSnapshot.git?.worktreeRootIdentity !== "string" ||
    expectedSnapshot.git.worktreeRootIdentity.length === 0 ||
    !validDirectoryObservation(expectedSnapshot.git.worktreeRootObservation) ||
    !validGitTopologyExpectation(expectedSnapshot.git)
  ) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "expected snapshot is malformed");
  }
  if (options === null || typeof options !== "object" || Array.isArray(options)) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "source snapshot options are malformed");
  }
  // Re-verification binds the recorded physical root, its observation, and the recorded Git
  // topology; the pathname alone is never sufficient.
  const observed = observeSourceSnapshot(expectedSnapshot.workspace.root, {
    ...options,
    expectedRoot: Object.freeze({
      identity: expectedSnapshot.git.worktreeRootIdentity,
      observation: expectedSnapshot.git.worktreeRootObservation,
      path: expectedSnapshot.workspace.root,
    }),
    expectedTopology: expectedSnapshot.git,
  });
  if (observed.snapshotSha256 !== expectedSnapshot.snapshotSha256) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED,
      "source changed after candidate capture",
      { expected: expectedSnapshot.snapshotSha256, observed: observed.snapshotSha256 },
    );
  }
  return observed;
}

function fsyncDirectory(directory, operationBudget = null) {
  if (operationBudget !== null) remainingOperationMs(operationBudget, `directory fsync for ${directory}`);
  let fd;
  let pendingError = null;
  try {
    fd = fs.openSync(directory, fs.constants.O_RDONLY | DIRECTORY | NOFOLLOW);
    const stat = fs.fstatSync(fd);
    if (!stat.isDirectory()) {
      fail(KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE, `${directory} is not a directory`);
    }
    fs.fsyncSync(fd);
    if (operationBudget !== null) remainingOperationMs(operationBudget, `directory fsync for ${directory}`);
  } catch (error) {
    pendingError = error instanceof KnockoutWorkspaceError
      ? error
      : workspaceError(
          KNOCKOUT_WORKSPACE_ERROR_CODES.DURABILITY_FAILED,
          `cannot durably synchronize directory ${directory}`,
          null,
          error,
        );
  } finally {
    if (fd !== undefined) {
      try { fs.closeSync(fd); }
      catch (error) {
        if (pendingError === null) {
          pendingError = workspaceError(
            KNOCKOUT_WORKSPACE_ERROR_CODES.DURABILITY_FAILED,
            `cannot close synchronized directory ${directory}`,
            null,
            error,
          );
        }
      }
    }
  }
  if (pendingError !== null) throw pendingError;
  if (operationBudget !== null) remainingOperationMs(operationBudget, `directory fsync for ${directory}`);
}

function validFileObservation(value) {
  return (
    value !== null && typeof value === "object" && !Array.isArray(value) &&
    typeof value.identity === "string" && typeof value.ctimeNs === "string" &&
    typeof value.mtimeNs === "string" && Number.isSafeInteger(value.size) &&
    Number.isInteger(value.mode) && Number.isInteger(value.nlink)
  );
}

function sameFileObservation(left, right) {
  return (
    left.identity === right.identity && left.ctimeNs === right.ctimeNs &&
    left.mtimeNs === right.mtimeNs && left.size === right.size &&
    left.mode === right.mode && left.nlink === right.nlink
  );
}

function assertPrivateFile(abs, expectedSha256 = null, expectedObservation = null, options = {}) {
  const metadataAnchor = options.metadataAnchor;
  const operationBudget = options.operationBudget ?? null;
  const maxBytes = options.maxBytes ?? KNOCKOUT_WORKSPACE_CAPTURE_LIMITS.maxFileBytes;
  const mismatchCode = options.mismatchCode ?? null;
  if (mismatchCode !== null && !ERROR_CODE_SET.has(mismatchCode)) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "private-file mismatch code is malformed");
  }
  const identityMismatchCode = mismatchCode ??
    KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_IDENTITY_MISMATCH;
  const hashMismatchCode = mismatchCode ?? KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_HASH_MISMATCH;
  if (operationBudget !== null) remainingOperationMs(operationBudget, `private-file check for ${abs}`);
  if (expectedObservation !== null && !validFileObservation(expectedObservation)) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
      "expected private-file observation is malformed",
    );
  }
  const uid = operationEffectiveUid(operationBudget, `private-file owner check for ${abs}`);
  let initial;
  try { initial = fs.lstatSync(abs, { bigint: true }); }
  catch (error) {
    if (
      expectedObservation !== null && error !== null && typeof error === "object" &&
      error.code === "ENOENT"
    ) {
      fail(
        identityMismatchCode,
        `${abs} no longer names the expected private file identity`,
        { expected: expectedObservation.identity, observed: null },
        error,
      );
    }
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
      `cannot inspect private file ${abs}`,
      null,
      error,
    );
  }
  if (
    initial.isSymbolicLink() || !initial.isFile() || modeOf(initial) !== 0o600 ||
    (uid !== null && Number(initial.uid) !== uid) || Number(initial.nlink) !== 1
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
      `${abs} is not a private single-link mode-0600 file`,
    );
  }
  if (
    expectedObservation !== null &&
    identityOf(initial) !== expectedObservation.identity
  ) {
    fail(
      identityMismatchCode,
      `${abs} does not name the expected private file identity`,
      { expected: expectedObservation.identity, observed: identityOf(initial) },
    );
  }
  const observed = observeRegularFile(abs, null, { maxBytes, operationBudget });
  const stable = observed.observation;
  observeMetadata(abs, false, operationBudget, stable, metadataAnchor);
  let stat;
  try { stat = fs.lstatSync(abs, { bigint: true }); }
  catch (error) {
    if (
      mismatchCode !== null && expectedObservation !== null &&
      error !== null && typeof error === "object" && error.code === "ENOENT"
    ) {
      fail(
        mismatchCode,
        `${abs} no longer names the expected private file identity`,
        { expected: expectedObservation.identity, observed: null },
        error,
      );
    }
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
      `cannot re-inspect private file ${abs}`,
      null,
      error,
    );
  }
  if (
    identityOf(initial) !== stable.identity ||
    identityOf(stat) !== stable.identity ||
    modeOf(stat) !== stable.mode || Number(stat.nlink) !== stable.nlink ||
    Number(stat.size) !== stable.size || String(stat.ctimeNs) !== stable.ctimeNs ||
    String(stat.mtimeNs) !== stable.mtimeNs ||
    modeOf(stat) !== 0o600 || (uid !== null && Number(stat.uid) !== uid) ||
    Number(stat.nlink) !== 1
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
      `${abs} is not a private single-link mode-0600 file`,
    );
  }
  if (expectedSha256 !== null && observed.sha256 !== expectedSha256) {
    fail(
      hashMismatchCode,
      `${abs} does not match its expected hash`,
      { expected: expectedSha256, observed: observed.sha256 },
    );
  }
  if (
    expectedObservation !== null &&
    !sameFileObservation(observed.observation, expectedObservation)
  ) {
    fail(
      identityMismatchCode,
      `${abs} does not match its expected private file observation`,
      { expected: expectedObservation, observed: observed.observation },
    );
  }
  if (operationBudget !== null) remainingOperationMs(operationBudget, `private-file check for ${abs}`);
  return observed;
}

function writeAll(
  fd,
  bytes,
  simulateShortWriteAfterBytes = null,
  operationBudget = null,
  label = "file write",
) {
  let offset = 0;
  while (offset < bytes.length) {
    if (operationBudget !== null) remainingOperationMs(operationBudget, label);
    const remaining = simulateShortWriteAfterBytes === null
      ? bytes.length - offset
      : Math.min(bytes.length - offset, Math.max(0, simulateShortWriteAfterBytes - offset));
    if (remaining === 0) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_INCOMPLETE,
        "simulated short publication write",
        { writtenBytes: offset },
      );
    }
    const written = fs.writeSync(fd, bytes, offset, remaining, offset);
    if (operationBudget !== null) remainingOperationMs(operationBudget, label);
    if (!Number.isInteger(written) || written <= 0 || written > remaining) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_INCOMPLETE,
        "publication write made no valid progress",
        { requestedBytes: remaining, writtenBytes: written },
      );
    }
    offset += written;
  }
  return offset;
}

function readBoundFileExactly(fd, expectedBytes, operationBudget = null, label = "file read-back") {
  const bytes = Buffer.alloc(expectedBytes);
  let offset = 0;
  while (offset < bytes.length) {
    if (operationBudget !== null) remainingOperationMs(operationBudget, label);
    const read = fs.readSync(fd, bytes, offset, bytes.length - offset, offset);
    if (operationBudget !== null) remainingOperationMs(operationBudget, label);
    if (!Number.isInteger(read) || read <= 0 || read > bytes.length - offset) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_INCOMPLETE,
        "publication read-back made no valid progress",
        { expectedBytes, readBytes: offset },
      );
    }
    offset += read;
  }
  const extra = Buffer.alloc(1);
  if (operationBudget !== null) remainingOperationMs(operationBudget, label);
  if (fs.readSync(fd, extra, 0, 1, expectedBytes) !== 0) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_INCOMPLETE,
      "publication read-back exceeded its expected size",
      { expectedBytes },
    );
  }
  return bytes;
}

function observePublicationPath(abs) {
  try {
    const stat = fs.lstatSync(abs, { bigint: true });
    return Object.freeze({
      identity: identityOf(stat),
      mode: modeOf(stat),
      nlink: Number(stat.nlink),
      type: stat.isSymbolicLink() ? "symlink" : stat.isFile() ? "file" : "other",
    });
  } catch (error) {
    if (error && error.code === "ENOENT") return null;
    return Object.freeze({ identity: null, mode: null, nlink: null, type: "unobservable" });
  }
}

function publicationFailure(error, {
  committed,
  createdIdentity,
  createdObservation,
  directoryIdentity,
  expectedBytes,
  expectedSha256,
  path: terminalPath,
  phase,
}) {
  const current = observePublicationPath(terminalPath);
  const details = Object.freeze({
    ...(error instanceof KnockoutWorkspaceError && error.details !== null ? error.details : {}),
    retainedTerminalPublication: Object.freeze({
      createdIdentity,
      createdObservation,
      currentIdentity: current?.identity ?? null,
      currentMode: current?.mode ?? null,
      currentNlink: current?.nlink ?? null,
      currentType: current?.type ?? "absent",
      directoryIdentity,
      expectedBytes,
      expectedSha256,
      path: terminalPath,
      phase,
    }),
  });
  if (committed) {
    return workspaceError(
      KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_COMMIT_INDETERMINATE,
      `terminal commit is indeterminate at ${terminalPath}`,
      details,
      error,
    );
  }
  if (error instanceof KnockoutWorkspaceError) {
    return workspaceError(error.code, error.message, details, error);
  }
  return workspaceError(
    KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_INCOMPLETE,
    `terminal publication failed before commit at ${terminalPath}`,
    details,
    error,
  );
}

function assertBoundPublicationDirectory(fd, absolute, expectedIdentity, expectedUid) {
  let opened;
  let atPath;
  try {
    opened = fs.fstatSync(fd, { bigint: true });
    atPath = fs.lstatSync(absolute, { bigint: true });
  } catch (error) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
      `publication directory cannot be observed safely at ${absolute}`,
      { expectedIdentity },
      error,
    );
  }
  if (
    !opened.isDirectory() || atPath.isSymbolicLink() || !atPath.isDirectory() ||
    identityOf(opened) !== expectedIdentity || identityOf(atPath) !== expectedIdentity ||
    modeOf(opened) !== 0o700 || modeOf(atPath) !== 0o700 ||
    (expectedUid !== null &&
      (Number(opened.uid) !== expectedUid || Number(atPath.uid) !== expectedUid))
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
      `publication directory identity changed at ${absolute}`,
      {
        expectedIdentity,
        openedIdentity: identityOf(opened),
        pathIdentity: identityOf(atPath),
      },
    );
  }
  return opened;
}

function durablePublishNoClobber(directory, filename, bytes, options = {}) {
  // Storage contract: ABSENT -> CREATED_UNBOUND -> PREPARED(mode 000) -> COMMITTED(mode 0600).
  // A created inode is not PREPARED until both its pathname and its already-opened directory are
  // identity-bound. Failed residue is retained and can never pass assertPrivateFile. This explicit
  // state machine replaces hardlink-then-unlink publication because Node has no
  // inode-conditional unlink and a same-UID pathname replacement must never be deleted as cleanup.
  const {
    afterCommitWitness = null,
    beforeCommitWitness = null,
    expectedDirectoryIdentity = null,
    limits: requestedLimits = KNOCKOUT_WORKSPACE_CAPTURE_LIMITS,
    maxBytes = MAX_TERMINAL_EVIDENCE_BYTES,
    operationBudget = null,
    simulateShortWriteAfterBytes = null,
  } = options;
  const limits = normalizeCaptureLimits(requestedLimits);
  if (
    (beforeCommitWitness !== null && typeof beforeCommitWitness !== "function") ||
    (afterCommitWitness !== null && typeof afterCommitWitness !== "function")
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
      "publication commit witnesses must be functions or null",
    );
  }
  const checkBudget = (phase) => {
    if (operationBudget !== null) remainingOperationMs(operationBudget, `terminal publication ${phase}`);
  };
  if (
    expectedDirectoryIdentity !== null &&
    (typeof expectedDirectoryIdentity !== "string" || expectedDirectoryIdentity.length === 0)
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
      "expected publication-directory identity is malformed",
    );
  }
  const publicationDirectory = requireRealDirectory(
    directory,
    "publication directory",
    { expectedIdentity: expectedDirectoryIdentity, operationBudget, privateMode: true },
  );
  const privateDirectory = publicationDirectory.path;
  if (
    expectedDirectoryIdentity !== null &&
    publicationDirectory.identity !== expectedDirectoryIdentity
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
      `publication directory identity changed at ${privateDirectory}`,
      {
        expectedIdentity: expectedDirectoryIdentity,
        pathIdentity: publicationDirectory.identity,
      },
    );
  }
  if (
    typeof filename !== "string" || filename.length < 1 || filename.length > 200 ||
    Buffer.byteLength(filename, "utf8") > 200 || filename.includes("\0") ||
    path.basename(filename) !== filename || filename === "." || filename === ".."
  ) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "publication filename is unsafe");
  }
  if (!Buffer.isBuffer(bytes) || bytes.length === 0) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "publication bytes must be non-empty");
  }
  if (
    !Number.isSafeInteger(maxBytes) || maxBytes < 1 ||
    maxBytes > MAX_CANDIDATE_MANIFEST_BYTES
  ) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "publication byte limit is malformed");
  }
  if (bytes.length > maxBytes) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.RESOURCE_LIMIT_EXCEEDED,
      "terminal publication exceeds its fixed byte limit",
      { limitBytes: maxBytes, observedBytes: bytes.length },
    );
  }
  if (
    simulateShortWriteAfterBytes !== null &&
    (!Number.isSafeInteger(simulateShortWriteAfterBytes) || simulateShortWriteAfterBytes < 0)
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
      "simulateShortWriteAfterBytes must be a non-negative safe integer or null",
    );
  }
  if (NOFOLLOW === 0) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.SPECIAL_NODE_UNSUPPORTED,
      "this platform has no O_NOFOLLOW for terminal publication",
    );
  }
  const terminalPath = path.join(privateDirectory, filename);
  const expected = sha256(bytes);
  const expectedUid = operationEffectiveUid(
    operationBudget,
    `publication owner check for ${terminalPath}`,
  );
  requireDestinationCapacity(
    privateDirectory,
    bytes.length,
    limits,
    `terminal publication ${filename}`,
    operationBudget,
  );
  let fd;
  let directoryFd;
  let createdIdentity = null;
  let createdObservation = null;
  let committed = false;
  let commitAttempted = false;
  let phase = "ABSENT";
  try {
    checkBudget("before directory bind");
    try {
      directoryFd = fs.openSync(privateDirectory, fs.constants.O_RDONLY | DIRECTORY | NOFOLLOW);
      assertBoundPublicationDirectory(
        directoryFd,
        privateDirectory,
        publicationDirectory.identity,
        expectedUid,
      );
    } catch (error) {
      if (
        error instanceof KnockoutWorkspaceError &&
        error.code === KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE
      ) throw error;
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
        `cannot bind publication directory ${privateDirectory}`,
        { expectedIdentity: publicationDirectory.identity },
        error,
      );
    }
    checkBudget("before inode creation");
    try {
      fd = fs.openSync(
        terminalPath,
        fs.constants.O_RDWR | fs.constants.O_CREAT | fs.constants.O_EXCL | NOFOLLOW,
        0o000,
      );
    } catch (error) {
      if (error && ["EEXIST", "EISDIR", "ELOOP"].includes(error.code)) {
        fail(
          KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_EXISTS,
          `${terminalPath} already exists or is unsafe`,
          null,
          error,
        );
      }
      if (error && ["ENOENT", "ENOTDIR"].includes(error.code)) {
        fail(
          KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
          `publication directory changed before creating ${terminalPath}`,
          { expectedIdentity: publicationDirectory.identity },
          error,
        );
      }
      try {
        assertBoundPublicationDirectory(
          directoryFd,
          privateDirectory,
          publicationDirectory.identity,
          expectedUid,
        );
      } catch (directoryError) {
        throw directoryError;
      }
      throw error;
    }
    phase = "CREATED_UNBOUND";
    const prepared = fs.fstatSync(fd, { bigint: true });
    createdIdentity = identityOf(prepared);
    assertBoundPublicationDirectory(
      directoryFd,
      privateDirectory,
      publicationDirectory.identity,
      expectedUid,
    );
    const preparedAtPath = fs.lstatSync(terminalPath, { bigint: true });
    if (
      !prepared.isFile() || preparedAtPath.isSymbolicLink() || !preparedAtPath.isFile() ||
      identityOf(preparedAtPath) !== createdIdentity || modeOf(prepared) !== 0o000 ||
      modeOf(preparedAtPath) !== 0o000 || Number(prepared.nlink) !== 1 ||
      Number(preparedAtPath.nlink) !== 1 ||
      (expectedUid !== null && Number(prepared.uid) !== expectedUid)
    ) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_INCOMPLETE,
        `terminal PREPARED state is unsafe at ${terminalPath}`,
      );
    }
    phase = "PREPARED";
    checkBudget("before prepared write");
    writeAll(
      fd,
      bytes,
      simulateShortWriteAfterBytes,
      operationBudget,
      `terminal publication write for ${terminalPath}`,
    );
    fs.fsyncSync(fd);
    const readBack = readBoundFileExactly(
      fd,
      bytes.length,
      operationBudget,
      `terminal publication read-back for ${terminalPath}`,
    );
    if (!readBack.equals(bytes) || sha256(readBack) !== expected) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_HASH_MISMATCH,
        `terminal PREPARED bytes do not match at ${terminalPath}`,
      );
    }
    const verified = fs.fstatSync(fd, { bigint: true });
    const verifiedAtPath = fs.lstatSync(terminalPath, { bigint: true });
    if (
      identityOf(verified) !== createdIdentity || identityOf(verifiedAtPath) !== createdIdentity ||
      modeOf(verified) !== 0o000 || modeOf(verifiedAtPath) !== 0o000 ||
      Number(verified.nlink) !== 1 || Number(verifiedAtPath.nlink) !== 1 ||
      Number(verified.size) !== bytes.length || Number(verifiedAtPath.size) !== bytes.length
    ) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_INCOMPLETE,
        `terminal PREPARED identity changed at ${terminalPath}`,
      );
    }
    assertBoundPublicationDirectory(
      directoryFd,
      privateDirectory,
      publicationDirectory.identity,
      expectedUid,
    );
    fs.fsyncSync(directoryFd);
    assertBoundPublicationDirectory(
      directoryFd,
      privateDirectory,
      publicationDirectory.identity,
      expectedUid,
    );
    phase = "PREPARED_DURABLE";
    checkBudget("before commit transition");
    if (beforeCommitWitness !== null) {
      // The marker is durable but still PREPARED (mode 000), so nothing can accept it as terminal.
      // The caller's witness re-verifies the bytes the marker certifies before the commit
      // transition is attempted; a witness refusal leaves PREPARED residue and no committed state.
      beforeCommitWitness();
      checkBudget("after pre-commit witness");
      assertBoundPublicationDirectory(
        directoryFd,
        privateDirectory,
        publicationDirectory.identity,
        expectedUid,
      );
      const witnessed = fs.fstatSync(fd, { bigint: true });
      const witnessedAtPath = fs.lstatSync(terminalPath, { bigint: true });
      if (
        identityOf(witnessed) !== createdIdentity || identityOf(witnessedAtPath) !== createdIdentity ||
        modeOf(witnessed) !== 0o000 || modeOf(witnessedAtPath) !== 0o000 ||
        Number(witnessed.nlink) !== 1 || Number(witnessedAtPath.nlink) !== 1 ||
        Number(witnessed.size) !== bytes.length || Number(witnessedAtPath.size) !== bytes.length
      ) {
        fail(
          KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_INCOMPLETE,
          `terminal PREPARED identity changed after the pre-commit witness at ${terminalPath}`,
        );
      }
    }
    operationEffectiveUid(operationBudget, `terminal commit principal check for ${terminalPath}`);
    commitAttempted = true;
    phase = "COMMIT_TRANSITION_ATTEMPTED";
    fs.fchmodSync(fd, 0o600);
    committed = true;
    phase = "COMMIT_TRANSITION";
    fs.fsyncSync(fd);
    phase = "COMMITTED_FILE_DURABLE";
    const committedStat = fs.fstatSync(fd, { bigint: true });
    const committedAtPath = fs.lstatSync(terminalPath, { bigint: true });
    if (
      identityOf(committedStat) !== createdIdentity || identityOf(committedAtPath) !== createdIdentity ||
      modeOf(committedStat) !== 0o600 || modeOf(committedAtPath) !== 0o600 ||
      Number(committedStat.nlink) !== 1 || Number(committedAtPath.nlink) !== 1 ||
      Number(committedStat.size) !== bytes.length || Number(committedAtPath.size) !== bytes.length
    ) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_COMMIT_INDETERMINATE,
        `terminal identity changed after commit at ${terminalPath}`,
      );
    }
    // Preserve the exact first committed pathname observation before any later verification or
    // descriptor-close can fail. A TERMINAL_COMMIT_INDETERMINATE result must give its caller the
    // identity evidence needed to reopen the retained marker without blessing whatever happens to
    // occupy the pathname after this point. The full private-file verification below replaces this
    // checkpoint on success with its independently re-read observation.
    createdObservation = Object.freeze({
      ctimeNs: String(committedAtPath.ctimeNs),
      identity: identityOf(committedAtPath),
      mode: modeOf(committedAtPath),
      mtimeNs: String(committedAtPath.mtimeNs),
      nlink: Number(committedAtPath.nlink),
      size: Number(committedAtPath.size),
    });
    assertBoundPublicationDirectory(
      directoryFd,
      privateDirectory,
      publicationDirectory.identity,
      expectedUid,
    );
    fs.fsyncSync(directoryFd);
    assertBoundPublicationDirectory(
      directoryFd,
      privateDirectory,
      publicationDirectory.identity,
      expectedUid,
    );
    phase = "COMMITTED_NAMESPACE_DURABLE";
    const reopened = assertPrivateFile(
      terminalPath,
      expected,
      null,
      { metadataAnchor: publicationDirectory, operationBudget },
    );
    if (reopened.observation.identity !== createdIdentity || !reopened.bytes.equals(bytes)) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_HASH_MISMATCH,
        `${terminalPath} changed after publication`,
      );
    }
    createdObservation = reopened.observation;
    if (afterCommitWitness !== null) {
      let witnessFailure = null;
      try { afterCommitWitness(); }
      catch (error) { witnessFailure = error; }
      if (witnessFailure !== null) {
        // The committed marker must not outlive the bytes it certifies. Revocation acts on the
        // descriptor created above (never on a pathname), returns the inode to PREPARED (mode 000)
        // and makes that durable before the witness refusal is reported. A revocation that cannot
        // be confirmed keeps `committed` set and is reported as TERMINAL_COMMIT_INDETERMINATE.
        phase = "COMMIT_REVOCATION_ATTEMPTED";
        fs.fchmodSync(fd, 0o000);
        fs.fsyncSync(fd);
        const revoked = fs.fstatSync(fd, { bigint: true });
        const revokedAtPath = fs.lstatSync(terminalPath, { bigint: true });
        if (
          identityOf(revoked) !== createdIdentity || identityOf(revokedAtPath) !== createdIdentity ||
          modeOf(revoked) !== 0o000 || modeOf(revokedAtPath) !== 0o000 ||
          Number(revoked.nlink) !== 1 || Number(revokedAtPath.nlink) !== 1
        ) {
          fail(
            KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_COMMIT_INDETERMINATE,
            `terminal commit revocation could not be confirmed at ${terminalPath}`,
          );
        }
        fs.fsyncSync(directoryFd);
        committed = false;
        createdObservation = null;
        phase = "COMMIT_REVOKED";
        throw witnessFailure;
      }
    }
    assertBoundPublicationDirectory(
      directoryFd,
      privateDirectory,
      publicationDirectory.identity,
      expectedUid,
    );
    const closingFd = fd;
    fd = undefined;
    fs.closeSync(closingFd);
    const closingDirectoryFd = directoryFd;
    directoryFd = undefined;
    fs.closeSync(closingDirectoryFd);
    return Object.freeze({
      bytes: bytes.length,
      createdIdentity,
      createdObservation,
      directoryIdentity: publicationDirectory.identity,
      path: terminalPath,
      sha256: expected,
    });
  } catch (error) {
    if (error instanceof KnockoutWorkspaceError && createdIdentity === null) throw error;
    let commitMayHaveOccurred = committed;
    if (!commitMayHaveOccurred && commitAttempted) {
      try { commitMayHaveOccurred = modeOf(fs.fstatSync(fd, { bigint: true })) !== 0o000; }
      catch { commitMayHaveOccurred = true; }
    }
    throw publicationFailure(error, {
      committed: commitMayHaveOccurred,
      createdIdentity,
      createdObservation,
      directoryIdentity: publicationDirectory.identity,
      expectedBytes: bytes.length,
      expectedSha256: expected,
      path: terminalPath,
      phase,
    });
  } finally {
    if (fd !== undefined) {
      try { fs.closeSync(fd); }
      catch {}
    }
    if (directoryFd !== undefined) {
      try { fs.closeSync(directoryFd); }
      catch {}
    }
  }
}

function terminalStatusPolicy(allowedTerminalStatuses) {
  const snapshot = canonicalJsonSnapshot(allowedTerminalStatuses).value;
  if (
    !Array.isArray(snapshot) || snapshot.length < 1 || snapshot.length > 64 ||
    snapshot.some((status) =>
      typeof status !== "string" || status.length < 1 || status.length > 64 ||
      !/^[A-Z][A-Z0-9_]*$/.test(status) || status === "RUNNING") ||
    new Set(snapshot).size !== snapshot.length
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
      "allowedTerminalStatuses must be one non-empty closed set that excludes RUNNING",
    );
  }
  return Object.freeze(new Set(snapshot));
}

function validateTerminalBytes(
  terminalBytes,
  expectedCandidateManifestSha256,
  allowedTerminalStatuses,
  errorCode,
) {
  if (!Buffer.isBuffer(terminalBytes) || terminalBytes.length < 1) {
    fail(errorCode, "terminal evidence must be non-empty bytes");
  }
  if (terminalBytes.length > MAX_TERMINAL_EVIDENCE_BYTES) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.RESOURCE_LIMIT_EXCEEDED,
      "terminal evidence exceeds its fixed byte limit",
      { limitBytes: MAX_TERMINAL_EVIDENCE_BYTES, observedBytes: terminalBytes.length },
    );
  }
  if (!HASH_64.test(expectedCandidateManifestSha256 ?? "")) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
      "expected candidate-manifest SHA-256 is required for terminal evidence",
    );
  }
  const statuses = terminalStatusPolicy(allowedTerminalStatuses);
  const bytes = Buffer.from(terminalBytes);
  let terminal;
  try { terminal = deepFreezeJson(JSON.parse(bytes.toString("utf8"))); }
  catch (error) { fail(errorCode, "terminal JSON is incomplete", null, error); }
  if (
    terminal === null || typeof terminal !== "object" || Array.isArray(terminal) ||
    terminal.protocol !== KNOCKOUT_WORKSPACE_PROTOCOLS.terminal ||
    terminal.candidateManifestSha256 !== expectedCandidateManifestSha256 ||
    typeof terminal.status !== "string" || terminal.status === "RUNNING" ||
    !statuses.has(terminal.status)
  ) {
    fail(errorCode, "terminal candidate binding or terminal status is invalid");
  }
  if (!canonicalJsonBytes(terminal).equals(bytes)) {
    fail(errorCode, "terminal JSON is not canonical");
  }
  return Object.freeze({ bytes, terminal });
}

export function reopenTerminalEvidence(options) {
  if (options === null || typeof options !== "object" || Array.isArray(options)) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "terminal reopen options are malformed");
  }
  const {
    allowedTerminalStatuses,
    commandTimeoutMs = MAX_CHILD_PROCESS_DURATION_MS,
    expectedCandidateManifestSha256,
    expectedDirectoryIdentity,
    expectedObservation = null,
    expectedSha256 = null,
    terminalPath,
  } = options;
  const operationBudget = createOperationBudget(commandTimeoutMs);
  const absolute = requireAbsolutePath(terminalPath, "terminal path");
  if (!HASH_64.test(expectedSha256 ?? "")) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
      "expected terminal SHA-256 is required and must be lowercase hexadecimal",
    );
  }
  if (!validFileObservation(expectedObservation)) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
      "expected terminal file observation is required and must be well formed",
    );
  }
  if (typeof expectedDirectoryIdentity !== "string" || expectedDirectoryIdentity.length === 0) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
      "expected terminal-directory identity is required",
    );
  }
  const terminalDirectory = requireRealDirectory(
    path.dirname(absolute),
    "terminal evidence directory",
    { expectedIdentity: expectedDirectoryIdentity, operationBudget, privateMode: true },
  );
  if (terminalDirectory.identity !== expectedDirectoryIdentity) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
      `terminal evidence directory identity changed at ${terminalDirectory.path}`,
      {
        expectedIdentity: expectedDirectoryIdentity,
        pathIdentity: terminalDirectory.identity,
      },
    );
  }
  let observed;
  try {
    observed = assertPrivateFile(absolute, expectedSha256, expectedObservation, {
      maxBytes: MAX_TERMINAL_EVIDENCE_BYTES,
      metadataAnchor: terminalDirectory,
      operationBudget,
    });
  } catch (error) {
    if (error instanceof KnockoutWorkspaceError) throw error;
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_INCOMPLETE,
      `terminal evidence could not be reopened at ${absolute}`,
      null,
      error,
    );
  }
  const validated = validateTerminalBytes(
    observed.bytes,
    expectedCandidateManifestSha256,
    allowedTerminalStatuses,
    KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_INCOMPLETE,
  );
  return Object.freeze({
    bytes: observed.bytes.length,
    identity: observed.observation.identity,
    identityVerified: true,
    observation: observed.observation,
    path: absolute,
    sha256: observed.sha256,
    terminal: validated.terminal,
  });
}

export function publishTerminalEvidence(options) {
  if (options === null || typeof options !== "object" || Array.isArray(options)) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "terminal publication options are malformed");
  }
  const {
    allowedTerminalStatuses,
    commandTimeoutMs = MAX_CHILD_PROCESS_DURATION_MS,
    directory,
    expectedCandidateManifestSha256,
    expectedDirectoryIdentity = null,
    filename = "terminal.json",
    simulateShortWriteAfterBytes = null,
    terminalBytes,
  } = options;
  const operationBudget = createOperationBudget(commandTimeoutMs);
  const validated = validateTerminalBytes(
    terminalBytes,
    expectedCandidateManifestSha256,
    allowedTerminalStatuses,
    KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
  );
  const published = durablePublishNoClobber(
    directory,
    filename,
    validated.bytes,
    {
      expectedDirectoryIdentity,
      maxBytes: MAX_TERMINAL_EVIDENCE_BYTES,
      operationBudget,
      simulateShortWriteAfterBytes,
    },
  );
  return Object.freeze({
    ...published,
    identityVerified: true,
    terminal: validated.terminal,
  });
}

function bindCreatedPrivateDirectoryIdentity(abs, fd, operationBudget = null) {
  if (operationBudget !== null) remainingOperationMs(operationBudget, `private-directory bind for ${abs}`);
  fs.fchmodSync(fd, 0o700);
  fs.fsyncSync(fd);
  if (operationBudget !== null) remainingOperationMs(operationBudget, `private-directory bind for ${abs}`);
  const opened = fs.fstatSync(fd, { bigint: true });
  const atPath = fs.lstatSync(abs, { bigint: true });
  const uid = operationEffectiveUid(operationBudget, `private-directory owner bind for ${abs}`);
  if (
    !opened.isDirectory() || atPath.isSymbolicLink() || !atPath.isDirectory() ||
    identityOf(opened) !== identityOf(atPath) || modeOf(opened) !== 0o700 ||
    modeOf(atPath) !== 0o700 ||
    (uid !== null && (Number(opened.uid) !== uid || Number(atPath.uid) !== uid))
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
      `created private directory identity changed at ${abs}`,
    );
  }
  const identity = identityOf(opened);
  return Object.freeze({
    identity,
    observation: directoryObservation(opened),
    path: path.resolve(abs),
  });
}

function bindCreatedPrivateDirectory(abs, fd, operationBudget = null, metadataAnchor = null) {
  const createdDirectory = bindCreatedPrivateDirectoryIdentity(abs, fd, operationBudget);
  observeMetadata(
    abs,
    false,
    operationBudget,
    createdDirectory.observation,
    metadataAnchor ?? createdDirectory,
    null,
    KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
  );
  const confirmedOpened = fs.fstatSync(fd, { bigint: true });
  const confirmedAtPath = fs.lstatSync(abs, { bigint: true });
  const uid = operationEffectiveUid(operationBudget, `private-directory owner bind for ${abs}`);
  if (
    !confirmedOpened.isDirectory() || confirmedAtPath.isSymbolicLink() ||
    !confirmedAtPath.isDirectory() ||
    identityOf(confirmedOpened) !== createdDirectory.identity ||
    identityOf(confirmedAtPath) !== createdDirectory.identity ||
    modeOf(confirmedOpened) !== 0o700 ||
    modeOf(confirmedAtPath) !== 0o700 ||
    !sameDirectoryObservation(directoryObservation(confirmedOpened), createdDirectory.observation) ||
    !sameDirectoryObservation(directoryObservation(confirmedAtPath), createdDirectory.observation) ||
    (uid !== null &&
      (Number(confirmedOpened.uid) !== uid || Number(confirmedAtPath.uid) !== uid))
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
      `created private directory changed during metadata inspection at ${abs}`,
    );
  }
  if (operationBudget !== null) remainingOperationMs(operationBudget, `private-directory bind for ${abs}`);
  return Object.freeze({
    ...createdDirectory,
    observation: directoryObservation(confirmedOpened),
  });
}

function observeProvisionalPrivateDirectory(abs, operationBudget = null) {
  let stat;
  try { stat = fs.lstatSync(abs, { bigint: true }); }
  catch (error) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
      `cannot observe newly-created private directory ${abs}`,
      null,
      error,
    );
  }
  const uid = operationEffectiveUid(operationBudget, `private-directory owner observation for ${abs}`);
  if (
    stat.isSymbolicLink() || !stat.isDirectory() ||
    (uid !== null && Number(stat.uid) !== uid)
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
      `newly-created private directory is unsafe at ${abs}`,
    );
  }
  return Object.freeze({ identity: identityOf(stat), path: path.resolve(abs) });
}

function assertPrivateDirectoryIdentity(expected, label, operationBudget = null) {
  if (
    expected === null || typeof expected !== "object" ||
    typeof expected.identity !== "string" || typeof expected.path !== "string"
  ) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, `${label} identity is malformed`);
  }
  const uid = operationEffectiveUid(operationBudget, `private-directory identity check for ${expected.path}`);
  let fd;
  try {
    if (operationBudget !== null) remainingOperationMs(operationBudget, `identity check for ${label}`);
    if (fs.realpathSync(expected.path) !== expected.path) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
        `${label} acquired a symbolic-link ancestor at ${expected.path}`,
        { expectedIdentity: expected.identity },
      );
    }
    fd = fs.openSync(expected.path, fs.constants.O_RDONLY | DIRECTORY | NOFOLLOW);
    assertBoundPublicationDirectory(fd, expected.path, expected.identity, uid);
    observeMetadata(
      expected.path,
      false,
      operationBudget,
      fs.fstatSync(fd, { bigint: true }),
      expected,
    );
    assertBoundPublicationDirectory(fd, expected.path, expected.identity, uid);
    if (fs.realpathSync(expected.path) !== expected.path) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
        `${label} acquired a symbolic-link ancestor at ${expected.path}`,
        { expectedIdentity: expected.identity },
      );
    }
    const closingFd = fd;
    fd = undefined;
    fs.closeSync(closingFd);
    if (operationBudget !== null) remainingOperationMs(operationBudget, `identity check for ${label}`);
  } catch (error) {
    if (error instanceof KnockoutWorkspaceError) throw error;
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
      `${label} identity could not be revalidated at ${expected.path}`,
      { expectedIdentity: expected.identity },
      error,
    );
  } finally {
    if (fd !== undefined) {
      try { fs.closeSync(fd); }
      catch {}
    }
  }
  return expected;
}

function assertEmptyPrivateDirectory(expected, label, operationBudget = null) {
  if (
    !validBoundDirectory(expected) ||
    !validDirectoryObservation(expected.observation)
  ) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, `${label} binding is malformed`);
  }
  // Re-observe ACL/xattr policy first, then bind the exact creation-time directory observation.
  // Reading at most one entry proves emptiness without allocating an attacker-sized list.
  assertPrivateDirectoryIdentity(expected, label, operationBudget);
  const bound = bindDirectoryDescriptor(
    expected,
    label,
    KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
    operationBudget,
  );
  let directory;
  let primaryError = null;
  const cleanupFailures = [];
  try {
    if (operationBudget !== null) {
      remainingOperationMs(operationBudget, `empty-directory check for ${label}`);
    }
    directory = fs.opendirSync(bound.path, { bufferSize: 1, encoding: "buffer" });
    const firstEntry = directory.readSync();
    if (operationBudget !== null) {
      remainingOperationMs(operationBudget, `empty-directory check for ${label}`);
    }
    const closingDirectory = directory;
    closingDirectory.closeSync();
    directory = undefined;
    confirmBoundDirectory(
      bound,
      label,
      KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
      operationBudget,
    );
    if (firstEntry !== null) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
        `${label} is not empty before standalone Git initialization`,
        { path: bound.path },
      );
    }
  } catch (error) {
    primaryError = error instanceof KnockoutWorkspaceError
      ? error
      : workspaceError(
          KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
          `cannot prove ${label} is empty`,
          { path: bound.path },
          error,
        );
  } finally {
    if (directory !== undefined) {
      try { directory.closeSync(); }
      catch (error) { cleanupFailures.push(error); }
    }
    try {
      closeBoundDirectory(
        bound,
        label,
        KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
      );
    } catch (error) {
      cleanupFailures.push(error);
    }
  }
  if (cleanupFailures.length !== 0) {
    throw combineWorkspaceFailures(
      primaryError,
      cleanupFailures,
      KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
      `cannot release ${label} after its empty-directory check`,
      { path: bound.path },
    );
  }
  if (primaryError !== null) throw primaryError;
  return expected;
}

function createPrivateDirectory(abs, options = {}) {
  const operationBudget = options.operationBudget ?? null;
  const expectedParent = options.expectedParent ?? null;
  const parentMismatchCode = options.parentMismatchCode ??
    KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE;
  if (expectedParent !== null && !validBoundDirectory(expectedParent)) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "private-directory parent binding is malformed");
  }
  if (!ERROR_CODE_SET.has(parentMismatchCode)) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "private-directory parent code is malformed");
  }
  const parentDirectory = requireRealDirectory(
    path.dirname(requireAbsolutePath(abs, "private-directory path")),
    "private-directory parent",
    {
      expectedIdentity: expectedParent?.identity ?? null,
      expectedIdentityCode: expectedParent === null ? null : parentMismatchCode,
      operationBudget,
      privateMode: true,
    },
  );
  if (expectedParent !== null && parentDirectory.path !== expectedParent.path) {
    fail(
      parentMismatchCode,
      "private-directory parent no longer resolves to its bound physical pathname",
      { expectedPath: expectedParent.path, path: parentDirectory.path },
    );
  }
  if (operationBudget !== null) remainingOperationMs(operationBudget, `private-directory creation for ${abs}`);
  try { fs.mkdirSync(abs, { mode: 0o700 }); }
  catch (error) {
    if (error && error.code === "EEXIST") {
      fail(KNOCKOUT_WORKSPACE_ERROR_CODES.DESTINATION_EXISTS, `${abs} already exists`, null, error);
    }
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE, `cannot create ${abs}`, null, error);
  }
  if (operationBudget !== null) remainingOperationMs(operationBudget, `private-directory creation for ${abs}`);
  let fd;
  let created = null;
  try {
    fd = fs.openSync(abs, fs.constants.O_RDONLY | DIRECTORY | NOFOLLOW);
    created = bindCreatedPrivateDirectory(abs, fd, operationBudget, parentDirectory);
    const closingFd = fd;
    fd = undefined;
    fs.closeSync(closingFd);
  } catch (error) {
    if (error instanceof KnockoutWorkspaceError) throw error;
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
      `cannot bind created private directory ${abs}`,
      null,
      error,
    );
  } finally {
    if (fd !== undefined) {
      const closingFd = fd;
      fd = undefined;
      try { fs.closeSync(closingFd); }
      catch {}
    }
  }
  fsyncDirectory(path.dirname(abs), operationBudget);
  if (operationBudget !== null) remainingOperationMs(operationBudget, `private-directory creation for ${abs}`);
  return created;
}

function inspectPrivateDirectoryForCohort(
  value,
  expected,
  operationBudget,
  label,
) {
  if (expected !== null && !validBoundDirectory(expected)) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, `${label} expected binding is malformed`);
  }
  if (
    expected?.observation !== undefined &&
    !validDirectoryObservation(expected.observation)
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
      `${label} expected observation is malformed`,
    );
  }
  if (operationBudget !== null) remainingOperationMs(operationBudget, `cohort inspection for ${label}`);
  const absolute = requireAbsolutePath(value, `${label} path`);
  let stat;
  let physical;
  try {
    stat = fs.lstatSync(absolute, { bigint: true });
    physical = fs.realpathSync(absolute);
  } catch (error) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
      `cannot inspect ${label} ${absolute}`,
      { path: absolute },
      error,
    );
  }
  const uid = operationEffectiveUid(operationBudget, `cohort owner inspection for ${label}`);
  const observed = Object.freeze({
    identity: identityOf(stat),
    observation: directoryObservation(stat),
    path: physical,
  });
  if (
    stat.isSymbolicLink() || !stat.isDirectory() || physical !== absolute ||
    modeOf(stat) !== 0o700 || (uid !== null && Number(stat.uid) !== uid) ||
    (expected !== null &&
      (observed.identity !== expected.identity || observed.path !== expected.path)) ||
    (expected?.observation !== undefined &&
      !sameDirectoryObservation(observed.observation, expected.observation))
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
      `${label} no longer names the expected private directory`,
      {
        expectedIdentity: expected?.identity ?? null,
        observedIdentity: observed.identity,
        path: absolute,
      },
    );
  }
  if (operationBudget !== null) remainingOperationMs(operationBudget, `cohort inspection for ${label}`);
  return observed;
}

function observePrivateDirectoryCohort(entries, anchorRoot, operationBudget, label) {
  if (!Array.isArray(entries) || entries.length === 0 || !validBoundDirectory(anchorRoot)) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, `${label} metadata cohort is malformed`);
  }
  const before = entries.map((entry, index) => {
    if (
      entry === null || typeof entry !== "object" || Array.isArray(entry) ||
      typeof entry.path !== "string"
    ) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
        `${label} metadata cohort entry ${index} is malformed`,
      );
    }
    return inspectPrivateDirectoryForCohort(
      entry.path,
      entry.expected ?? null,
      operationBudget,
      `${label} entry ${index}`,
    );
  });
  try {
    observeMetadataBatch(
      before.map((directory) => Object.freeze({
        abs: directory.path,
        expected: directory.observation,
        isSymlink: false,
      })),
      operationBudget,
      anchorRoot,
      null,
    );
  } catch (error) {
    if (
      error instanceof KnockoutWorkspaceError &&
      error.code === KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE
    ) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
        `${label} changed during batched private-metadata inspection`,
        null,
        error,
      );
    }
    throw error;
  }
  return Object.freeze(before.map((directory, index) =>
    inspectPrivateDirectoryForCohort(
      directory.path,
      directory,
      operationBudget,
      `${label} confirmed entry ${index}`,
    )));
}

function observeBoundPrivateDirectoryCurrent(
  bound,
  expectedObservation,
  operationBudget,
  label,
) {
  confirmBoundDirectoryIdentity(
    bound,
    label,
    KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
    operationBudget,
    { privateMode: true },
  );
  const leaseState = boundDirectoryLeaseStates.get(bound);
  let opened;
  let atPath;
  try {
    opened = fs.fstatSync(leaseState.fd, { bigint: true });
    atPath = fs.lstatSync(bound.path, { bigint: true });
  } catch (error) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
      `cannot inspect ${label}`,
      { path: bound.path },
      error,
    );
  }
  const openedObservation = directoryObservation(opened);
  const pathObservation = directoryObservation(atPath);
  if (
    !sameDirectoryObservation(openedObservation, pathObservation) ||
    (expectedObservation !== null &&
      !sameDirectoryObservation(openedObservation, expectedObservation))
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
      `${label} changed outside its authorized child insertion`,
      {
        expected: expectedObservation,
        observedDescriptor: openedObservation,
        observedPath: pathObservation,
        path: bound.path,
      },
    );
  }
  return openedObservation;
}

function fsyncBoundPrivateDirectory(bound, expectedObservation, operationBudget, label) {
  const before = observeBoundPrivateDirectoryCurrent(
    bound,
    expectedObservation,
    operationBudget,
    label,
  );
  const leaseState = boundDirectoryLeaseStates.get(bound);
  try {
    fs.fsyncSync(leaseState.fd);
  } catch (error) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.DURABILITY_FAILED,
      `cannot durably synchronize ${label}`,
      { path: bound.path },
      error,
    );
  }
  if (operationBudget !== null) remainingOperationMs(operationBudget, `directory fsync for ${label}`);
  return observeBoundPrivateDirectoryCurrent(bound, before, operationBudget, label);
}

function createPrivateDirectoryWithinCohort(abs, parentState, operationBudget) {
  let primaryError = null;
  const cleanupFailures = [];
  let fd;
  let created = null;
  try {
    parentState.observation = observeBoundPrivateDirectoryCurrent(
      parentState.bound,
      parentState.observation,
      operationBudget,
      `private-directory cohort parent ${parentState.bound.path}`,
    );
    if (operationBudget !== null) remainingOperationMs(operationBudget, `private-directory creation for ${abs}`);
    try { fs.mkdirSync(abs, { mode: 0o700 }); }
    catch (error) {
      if (error && error.code === "EEXIST") {
        fail(KNOCKOUT_WORKSPACE_ERROR_CODES.DESTINATION_EXISTS, `${abs} already exists`, null, error);
      }
      fail(KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE, `cannot create ${abs}`, null, error);
    }
    parentState.observation = observeBoundPrivateDirectoryCurrent(
      parentState.bound,
      null,
      operationBudget,
      `private-directory cohort parent ${parentState.bound.path}`,
    );
    fd = fs.openSync(abs, fs.constants.O_RDONLY | DIRECTORY | NOFOLLOW);
    created = bindCreatedPrivateDirectoryIdentity(abs, fd, operationBudget);
    const closingFd = fd;
    fd = undefined;
    fs.closeSync(closingFd);
    parentState.observation = fsyncBoundPrivateDirectory(
      parentState.bound,
      parentState.observation,
      operationBudget,
      `private-directory cohort parent ${parentState.bound.path}`,
    );
  } catch (error) {
    primaryError = error instanceof KnockoutWorkspaceError
      ? error
      : workspaceError(
          KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
          `cannot bind created private directory ${abs}`,
          null,
          error,
        );
  } finally {
    if (fd !== undefined) {
      const closingFd = fd;
      fd = undefined;
      try { fs.closeSync(closingFd); }
      catch (error) {
        cleanupFailures.push(workspaceError(
          KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
          `cannot release created private directory ${abs}`,
          { path: abs },
          error,
        ));
      }
    }
  }
  primaryError = combineWorkspaceFailures(
    primaryError,
    cleanupFailures,
    KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
    `cannot release created private directory ${abs}`,
    { path: abs },
  );
  if (primaryError !== null) throw primaryError;
  return created;
}

function createPrivateDirectoryCohort(paths, options) {
  const operationBudget = options.operationBudget ?? null;
  const anchorRoot = options.expectedDestinationRoot ?? null;
  if (
    !Array.isArray(paths) || paths.length === 0 ||
    paths.length > MAC_METADATA_BATCH_NODE_LIMIT ||
    !validBoundDirectory(anchorRoot)
  ) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "private-directory cohort is malformed");
  }
  const absolutePaths = paths.map((value, index) =>
    requireAbsolutePath(value, `private-directory cohort path ${index}`));
  if (new Set(absolutePaths).size !== absolutePaths.length) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "private-directory cohort paths repeat");
  }
  const relativeDepths = new Set(absolutePaths.map((absolute) => {
    const relative = path.relative(anchorRoot.path, absolute);
    if (
      relative.length === 0 || relative === ".." || relative.startsWith(`..${path.sep}`) ||
      path.isAbsolute(relative)
    ) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
        "private-directory cohort path escapes its destination root",
      );
    }
    return relative.split(path.sep).length;
  }));
  if (relativeDepths.size !== 1) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
      "private-directory cohort must contain one directory depth",
    );
  }
  const parentPaths = [...new Set(absolutePaths.map((absolute) => path.dirname(absolute)))];
  const expectedAnchorIdentity = Object.freeze({
    identity: anchorRoot.identity,
    path: anchorRoot.path,
  });
  let primaryError = null;
  const cleanupFailures = [];
  const parentStates = [];
  const createdDirectories = [];
  try {
    const admittedParents = observePrivateDirectoryCohort(
      parentPaths.map((parentPath) => Object.freeze({
        expected: parentPath === anchorRoot.path ? expectedAnchorIdentity : null,
        path: parentPath,
      })),
      anchorRoot,
      operationBudget,
      "private-directory cohort parents before creation",
    );
    for (const parent of admittedParents) {
      const bound = bindDirectoryDescriptor(
        parent,
        `private-directory cohort parent ${parent.path}`,
        KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
        operationBudget,
      );
      parentStates.push({ bound, observation: parent.observation });
    }
    const parentsByPath = new Map(parentStates.map((state) => [state.bound.path, state]));
    for (const absolute of absolutePaths) {
      const parentState = parentsByPath.get(path.dirname(absolute));
      if (parentState === undefined) {
        fail(
          KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
          `private-directory cohort lost its parent for ${absolute}`,
        );
      }
      createdDirectories.push(
        createPrivateDirectoryWithinCohort(absolute, parentState, operationBudget),
      );
    }
    observePrivateDirectoryCohort(
      [
        ...parentStates.map((state) => Object.freeze({
          expected: Object.freeze({
            identity: state.bound.identity,
            observation: state.observation,
            path: state.bound.path,
          }),
          path: state.bound.path,
        })),
        ...createdDirectories.map((directory) => Object.freeze({
          expected: directory,
          path: directory.path,
        })),
      ],
      anchorRoot,
      operationBudget,
      "private-directory cohort after creation",
    );
  } catch (error) {
    primaryError = error instanceof KnockoutWorkspaceError
      ? error
      : workspaceError(
          KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
          "private-directory cohort could not be created",
          null,
          error,
        );
  } finally {
    for (const state of [...parentStates].reverse()) {
      try {
        closeBoundDirectory(
          state.bound,
          `private-directory cohort parent ${state.bound.path}`,
          KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
        );
      } catch (error) {
        cleanupFailures.push(error);
      }
    }
  }
  primaryError = combineWorkspaceFailures(
    primaryError,
    cleanupFailures,
    KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
    "private-directory cohort descriptors could not be closed",
  );
  if (primaryError !== null) throw primaryError;
  return Object.freeze(createdDirectories);
}

function createUniquePrivateDirectory(
  parentRoot,
  prefix,
  {
    expectedParent = null,
    label = "private workspace",
    operationBudget = null,
    parentMismatchCode = KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
    privateParent = true,
  } = {},
) {
  if (expectedParent !== null && !validBoundDirectory(expectedParent)) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, `${label} parent binding is malformed`);
  }
  if (!ERROR_CODE_SET.has(parentMismatchCode)) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, `${label} parent code is malformed`);
  }
  const parentDirectory = requireRealDirectory(
    parentRoot,
    `${label} parent`,
    {
      expectedIdentity: expectedParent?.identity ?? null,
      expectedIdentityCode: expectedParent === null ? null : parentMismatchCode,
      operationBudget,
      privateMode: privateParent,
    },
  );
  const parent = parentDirectory.path;
  if (expectedParent !== null && parent !== expectedParent.path) {
    fail(
      parentMismatchCode,
      `${label} parent no longer resolves to its bound physical pathname`,
      { expectedPath: expectedParent.path, path: parent },
    );
  }
  if (operationBudget !== null) remainingOperationMs(operationBudget, `${label} creation`);
  let createdPath;
  try { createdPath = fs.mkdtempSync(path.join(parent, prefix), "utf8"); }
  catch (error) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
      `cannot create ${label}`,
      null,
      error,
    );
  }
  if (operationBudget !== null) remainingOperationMs(operationBudget, `${label} creation`);
  const provisional = observeProvisionalPrivateDirectory(createdPath, operationBudget);
  let fd;
  let descriptor = null;
  try {
    fd = fs.openSync(createdPath, fs.constants.O_RDONLY | DIRECTORY | NOFOLLOW);
    descriptor = bindCreatedPrivateDirectory(
      createdPath,
      fd,
      operationBudget,
      privateParent ? parentDirectory : null,
    );
    const closingFd = fd;
    fd = undefined;
    fs.closeSync(closingFd);
    fsyncDirectory(parent, operationBudget);
  } catch (error) {
    const failure = error instanceof KnockoutWorkspaceError
      ? error
      : workspaceError(
          KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
          `cannot bind created ${label} ${createdPath}`,
          null,
          error,
        );
    throw reportRetainedPrivateRoots(failure, [
      retainCreatedPrivateTree(descriptor ?? provisional),
    ]);
  } finally {
    if (fd !== undefined) {
      const closingFd = fd;
      fd = undefined;
      try { fs.closeSync(closingFd); }
      catch {}
    }
  }
  if (operationBudget !== null) remainingOperationMs(operationBudget, `${label} creation`);
  return descriptor;
}

function retainCreatedPrivateTree(created) {
  if (
    created === null || typeof created !== "object" ||
    typeof created.identity !== "string" || typeof created.path !== "string"
  ) return null;
  // This is a custody record, not deletion authority. Preserve the exact identity observed at
  // creation even if its pathname is later absent or names a replacement; re-observing the path
  // here would either lose that evidence or bless the replacement. Node exposes no descriptor-
  // relative recursive removal primitive, so automatic pathname deletion remains forbidden.
  return Object.freeze({ identity: created.identity, path: created.path });
}

function retainedPrivateRoots(value) {
  return Array.isArray(value?.retainedPrivateRoots) ? value.retainedPrivateRoots : [];
}

function uniqueRetainedPrivateRoots(roots) {
  const unique = new Map();
  for (const root of roots) {
    if (
      root === null || typeof root !== "object" ||
      typeof root.identity !== "string" || typeof root.path !== "string"
    ) continue;
    unique.set(`${root.identity}\0${root.path}`, Object.freeze({
      identity: root.identity,
      path: root.path,
    }));
  }
  return Object.freeze([...unique.values()]);
}

function freezeWithRetainedPrivateRoots(value, roots) {
  Object.defineProperty(value, "retainedPrivateRoots", {
    configurable: false,
    enumerable: false,
    value: uniqueRetainedPrivateRoots(roots),
    writable: false,
  });
  return Object.freeze(value);
}

function reportRetainedPrivateRoots(error, roots) {
  const combined = uniqueRetainedPrivateRoots([
    ...retainedPrivateRoots(error?.details),
    ...roots,
  ]);
  if (combined.length === 0) return error;
  if (error instanceof KnockoutWorkspaceError) {
    return workspaceError(
      error.code,
      error.message,
      { ...(error.details ?? {}), retainedPrivateRoots: combined },
      error,
    );
  }
  return workspaceError(
    KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
    "operation failed with retained private roots",
    { retainedPrivateRoots: combined },
    error,
  );
}

function writeExclusivePrivateFile(abs, bytes, mode = 0o600, operationBudget = null) {
  let fd;
  let pendingError = null;
  try {
    if (operationBudget !== null) remainingOperationMs(operationBudget, `private-file write for ${abs}`);
    fd = fs.openSync(
      abs,
      fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | NOFOLLOW,
      mode,
    );
    fs.fchmodSync(fd, mode);
    writeAll(fd, bytes, null, operationBudget, `private-file write for ${abs}`);
    fs.fsyncSync(fd);
    if (operationBudget !== null) remainingOperationMs(operationBudget, `private-file write for ${abs}`);
  } catch (error) {
    pendingError = error instanceof KnockoutWorkspaceError
      ? error
      : error && error.code === "EEXIST"
        ? workspaceError(
            KNOCKOUT_WORKSPACE_ERROR_CODES.DESTINATION_EXISTS,
            `${abs} already exists`,
            null,
            error,
          )
        : workspaceError(
            KNOCKOUT_WORKSPACE_ERROR_CODES.COPY_INCOMPLETE,
            `cannot create ${abs}`,
            null,
            error,
          );
  }
  if (fd !== undefined) {
    try { fs.closeSync(fd); }
    catch (error) {
      if (pendingError === null) {
        pendingError = workspaceError(
          KNOCKOUT_WORKSPACE_ERROR_CODES.COPY_INCOMPLETE,
          `cannot close created private file ${abs}`,
          null,
          error,
        );
      }
    }
  }
  if (pendingError !== null) throw pendingError;
  if (operationBudget !== null) remainingOperationMs(operationBudget, `private-file write for ${abs}`);
}

function copyLiveFile(sourceRoot, destinationRoot, node, options = {}) {
  const limits = normalizeCaptureLimits(options.limits ?? KNOCKOUT_WORKSPACE_CAPTURE_LIMITS);
  const operationBudget = options.operationBudget ?? null;
  const sourceMismatchCode = options.sourceMismatchCode ??
    KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE;
  if (!ERROR_CODE_SET.has(sourceMismatchCode)) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "source-file mismatch code is malformed");
  }
  const source = path.join(sourceRoot, ...node.path.split("/"));
  const destination = path.join(destinationRoot, ...node.path.split("/"));
  let observed;
  try {
    observed = observeRegularFile(source, node, {
      maxAllocatedBytes: limits.maxAllocatedBytes,
      maxBytes: limits.maxFileBytes,
      operationBudget,
    });
  } catch (error) {
    if (
      sourceMismatchCode !== KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE &&
      error instanceof KnockoutWorkspaceError &&
      [
        KNOCKOUT_WORKSPACE_ERROR_CODES.RESOURCE_LIMIT_EXCEEDED,
        KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE,
        KNOCKOUT_WORKSPACE_ERROR_CODES.SPECIAL_NODE_UNSUPPORTED,
      ].includes(error.code)
    ) {
      fail(
        sourceMismatchCode,
        `${node.path} no longer matches the admitted copy source`,
        { path: node.path, sourceCode: error.code },
        error,
      );
    }
    throw error;
  }
  writeExclusivePrivateFile(
    destination,
    observed.bytes,
    node.executable ? 0o700 : 0o600,
    operationBudget,
  );
  const copied = observeRegularFile(destination, null, {
    maxAllocatedBytes: limits.maxAllocatedBytes,
    maxBytes: limits.maxFileBytes,
    operationBudget,
  });
  if (
    copied.sha256 !== node.sha256 || copied.observation.size !== node.size ||
    ((copied.observation.mode & 0o111) !== 0) !== node.executable
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.COPY_INCOMPLETE,
      `${node.path} did not copy exactly`,
    );
  }
}

function copiedWorktreeEquivalent(sourceCensus, destinationCensus) {
  if (sourceCensus.nodes.length !== destinationCensus.nodes.length) return false;
  for (let index = 0; index < sourceCensus.nodes.length; index++) {
    const source = sourceCensus.nodes[index];
    const destination = destinationCensus.nodes[index];
    if (
      source.path !== destination.path || source.type !== destination.type ||
      source.executable !== destination.executable || source.hardlinkCount !== destination.hardlinkCount ||
      source.hardlinkGroup !== destination.hardlinkGroup
    ) return false;
    if (destination.type === "directory" && destination.mode !== 0o700) return false;
    if (
      destination.type === "file" &&
      destination.mode !== (source.executable ? 0o700 : 0o600)
    ) return false;
    if (source.type === "file" && (source.sha256 !== destination.sha256 || source.size !== destination.size)) {
      return false;
    }
    if (source.type === "symlink" && source.target !== destination.target) return false;
  }
  return true;
}

function copyLiveWorktree(sourceCensus, destinationRoot, options = {}) {
  const limits = normalizeCaptureLimits(options.limits ?? sourceCensus.limits);
  const metadataCache = options.metadataCache ?? null;
  const operationBudget = options.operationBudget ?? null;
  const expectedSourceRoot = options.expectedSourceRoot ?? null;
  const expectedDestinationRoot = options.expectedDestinationRoot ?? null;
  const rootGitPolicy = options.rootGitPolicy ?? "absent";
  const sourceMismatchCode = options.sourceMismatchCode ?? null;
  if (expectedSourceRoot !== null && !validBoundDirectory(expectedSourceRoot)) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "expected source root binding is malformed");
  }
  if (expectedDestinationRoot !== null && !validBoundDirectory(expectedDestinationRoot)) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
      "expected destination root binding is malformed",
    );
  }
  if (!["absent", "exclude", "include"].includes(rootGitPolicy)) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
      "copied-worktree root Git policy must be absent, exclude, or include",
    );
  }
  if (sourceMismatchCode !== null && !ERROR_CODE_SET.has(sourceMismatchCode)) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "copy-source mismatch code is malformed");
  }
  const sourceRoot = sourceCensus.root;
  // Each file read is already bound to the inode its census node observed; the root check closes
  // the pathname interval around the whole copy so a substituted root is refused as SOURCE_CHANGED
  // rather than surfacing only as per-file instability.
  const confirmSourceRoot = (label) => {
    if (expectedSourceRoot === null) return;
    requireSourceRoot(sourceRoot, expectedSourceRoot, operationBudget, {
      label,
      mismatchCode: sourceMismatchCode ?? KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED,
      observation: expectedSourceRoot.observation ?? null,
    });
  };
  confirmSourceRoot("source root before worktree copy");
  const directoryNodes = sourceCensus.nodes
    .filter((node) => node.type === "directory" && node.path !== ".")
    .sort((left, right) => left.path.split("/").length - right.path.split("/").length);
  if (process.platform === "darwin" && expectedDestinationRoot !== null) {
    for (let offset = 0; offset < directoryNodes.length;) {
      const depth = directoryNodes[offset].path.split("/").length;
      let depthEnd = offset + 1;
      while (
        depthEnd < directoryNodes.length &&
        directoryNodes[depthEnd].path.split("/").length === depth
      ) depthEnd += 1;
      for (
        let cohortOffset = offset;
        cohortOffset < depthEnd;
        cohortOffset += MAC_METADATA_BATCH_NODE_LIMIT
      ) {
        createPrivateDirectoryCohort(
          directoryNodes
            .slice(cohortOffset, Math.min(depthEnd, cohortOffset + MAC_METADATA_BATCH_NODE_LIMIT))
            .map((node) => path.join(destinationRoot, ...node.path.split("/"))),
          { expectedDestinationRoot, operationBudget },
        );
      }
      offset = depthEnd;
    }
  } else {
    for (const node of directoryNodes) {
      createPrivateDirectory(
        path.join(destinationRoot, ...node.path.split("/")),
        { operationBudget },
      );
    }
  }
  const hardlinkPrimary = new Map();
  for (const node of sourceCensus.nodes) {
    if (node.type !== "file") continue;
    if (operationBudget !== null) remainingOperationMs(operationBudget, `worktree copy at ${node.path}`);
    const destination = path.join(destinationRoot, ...node.path.split("/"));
    if (node.hardlinkGroup !== null && hardlinkPrimary.has(node.hardlinkGroup)) {
      try { fs.linkSync(hardlinkPrimary.get(node.hardlinkGroup), destination); }
      catch (error) {
        fail(
          KNOCKOUT_WORKSPACE_ERROR_CODES.COPY_INCOMPLETE,
          `cannot recreate hardlink ${node.path}`,
          null,
          error,
        );
      }
      if (operationBudget !== null) remainingOperationMs(operationBudget, `worktree copy at ${node.path}`);
      continue;
    }
    copyLiveFile(sourceRoot, destinationRoot, node, {
      limits,
      operationBudget,
      sourceMismatchCode: sourceMismatchCode ?? KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE,
    });
    if (node.hardlinkGroup !== null) hardlinkPrimary.set(node.hardlinkGroup, destination);
  }
  for (const node of sourceCensus.nodes) {
    if (node.type !== "symlink") continue;
    if (operationBudget !== null) remainingOperationMs(operationBudget, `worktree copy at ${node.path}`);
    const destination = path.join(destinationRoot, ...node.path.split("/"));
    try { fs.symlinkSync(node.target, destination); }
    catch (error) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.COPY_INCOMPLETE,
        `cannot recreate symlink ${node.path}`,
        null,
        error,
      );
    }
    if (operationBudget !== null) remainingOperationMs(operationBudget, `worktree copy at ${node.path}`);
  }
  const directories = [
    ...directoryNodes.map((node) => path.join(destinationRoot, ...node.path.split("/"))),
    destinationRoot,
  ].sort((left, right) => right.split(path.sep).length - left.split(path.sep).length);
  for (const directory of directories) fsyncDirectory(directory, operationBudget);
  if (operationBudget !== null) remainingOperationMs(operationBudget, "worktree copy completion");
  confirmSourceRoot("source root after worktree copy");
  const copied = censusWorkspace(destinationRoot, {
    expectedRoot: expectedDestinationRoot,
    limits,
    metadataCache,
    operationBudget,
    rootGitPolicy,
  });
  if (!copiedWorktreeEquivalent(sourceCensus, copied)) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.COPY_INCOMPLETE,
      "private worktree does not match the source census",
    );
  }
  return copied;
}

function copyObservedGitFile(sourceDescriptor, destination, options = {}) {
  const byteBudget = options.byteBudget ?? null;
  const destinationMetadataAnchor = options.destinationMetadataAnchor;
  const limits = normalizeCaptureLimits(options.limits ?? KNOCKOUT_WORKSPACE_CAPTURE_LIMITS);
  const operationBudget = options.operationBudget ?? null;
  const resourceLedger = options.resourceLedger ?? null;
  const observed = observeRegularFile(sourceDescriptor.path, null, {
    maxAllocatedBytes: limits.maxAllocatedBytes,
    maxBytes: byteBudget === null
      ? limits.maxFileBytes
      : byteBudget.remainingLimit(`Git-state copy for ${path.basename(destination)}`),
    operationBudget,
  });
  byteBudget?.charge(
    observed.bytes.length,
    `Git-state copy for ${path.basename(destination)}`,
  );
  if (observed.sha256 !== sourceDescriptor.sha256 || observed.observation.mode !== sourceDescriptor.mode) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE,
      `${sourceDescriptor.path} changed before Git-state copy`,
    );
  }
  const capacity = requireDestinationCapacity(
    path.dirname(destination),
    observed.bytes.length,
    limits,
    `Git-state copy for ${path.basename(destination)}`,
    operationBudget,
  );
  resourceLedger?.charge({
    allocatedBytes: Math.max(
      observed.observation.allocatedBytes,
      projectedAllocatedWriteBytes(observed.bytes.length, capacity.allocationUnitBytes),
    ),
    label: `Git-state copy for ${path.basename(destination)}`,
    logicalBytes: observed.bytes.length,
    maxDepth: 3,
    nodeCount: 1,
  });
  writeExclusivePrivateFile(destination, observed.bytes, 0o600, operationBudget);
  return assertPrivateFile(
    destination,
    sourceDescriptor.sha256,
    null,
    {
      metadataAnchor: destinationMetadataAnchor,
      mismatchCode: KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
      operationBudget,
    },
  );
}

function rawIndexSemanticProjection(entries) {
  return Object.freeze(entries.map((entry) => Object.freeze({
    assumeValid: entry.assumeValid,
    intentToAdd: entry.intentToAdd,
    mode: entry.mode,
    objectId: entry.objectId,
    path: entry.path,
    skipWorktree: entry.skipWorktree,
    stage: entry.stage,
  })));
}

function rawIndexStageProjection(entries) {
  return Object.freeze(entries.map((entry) => Object.freeze({
    mode: entry.mode.toString(8).padStart(6, "0"),
    objectId: entry.objectId,
    path: Buffer.from(entry.path, "hex").toString("utf8"),
    stage: entry.stage,
  })));
}

/**
 * Convert a copied Git index into one ordinary, full index without ever rewriting the live source
 * or the final seed. The split input pair lives below an alternate GIT_INDEX_FILE inside a retained
 * private scratch. Raw parsing independently derives the merged source entry set (including all
 * on-disk entry flags) and rejects extension state that Git could silently drop. Git performs the
 * portable conversion; the independently parsed output plus exact Git semantic outputs must match
 * before the normalized file may be copied into the seed.
 */
function normalizeIndexForStandalone(gitObservation, options = {}) {
  const gitExecutable = options.gitExecutable ?? null;
  const destinationIndex = requireAbsolutePath(
    options.destinationIndex,
    "normalized standalone index destination",
  );
  const destinationMetadataAnchor = options.destinationMetadataAnchor;
  const resourceLedger = options.resourceLedger;
  if (
    !validBoundDirectory(destinationMetadataAnchor) ||
    resourceLedger === null || typeof resourceLedger !== "object" ||
    typeof resourceLedger.charge !== "function"
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
      "normalization destination anchor and resource ledger are required",
    );
  }
  const commandTimeoutMs = requireCommandTimeoutMs(
    options.commandTimeoutMs ?? MAX_CHILD_PROCESS_DURATION_MS,
  );
  const operationBudget = options.operationBudget ?? createOperationBudget(commandTimeoutMs);
  const commandTimeout = () => remainingOperationMs(operationBudget, "standalone index normalization");
  const limits = normalizeCaptureLimits(options.limits ?? KNOCKOUT_WORKSPACE_CAPTURE_LIMITS);
  const scratchParentPrivate = options.scratchParentPrivate ?? false;
  if (typeof scratchParentPrivate !== "boolean") {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
      "scratchParentPrivate must be a boolean",
    );
  }
  const scratchDirectory = requireRealDirectory(
    options.scratchRoot ?? os.tmpdir(),
    "standalone index-normalization scratch root",
    { operationBudget, privateMode: scratchParentPrivate },
  );
  const created = createUniquePrivateDirectory(
    scratchDirectory.path,
    "noa-kws-index-normalize-",
    {
      label: "private index-normalization scratch",
      operationBudget,
      privateParent: scratchParentPrivate,
    },
  );
  const residue = retainCreatedPrivateTree(created);
  const releaseLease = createReleaseLease({
    fallbackCode: KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
    message: "private index-normalization release failed",
  });
  let primaryError = null;
  try {
    const scratchGit = createPrivateDirectory(path.join(created.path, ".git"), { operationBudget });
    runGit(
      created.path,
      ["init", "-q", `--object-format=${gitObservation.objectFormat}`, "--template="],
      {
        code: KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_INDEX_UNSUPPORTED,
        gitExecutable,
        timeoutMs: commandTimeout(),
      },
    );
    for (const [key, value] of [
      ["core.filemode", "true"],
      ["core.fsmonitor", "false"],
      ["core.symlinks", "true"],
      ["core.untrackedCache", "false"],
      ["core.hooksPath", "/dev/null"],
      ["gc.auto", "0"],
      ["maintenance.auto", "false"],
    ]) {
      runGit(created.path, ["config", "--local", key, value], {
        code: KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_INDEX_UNSUPPORTED,
        gitExecutable,
        timeoutMs: commandTimeout(),
      });
    }
    const indexDirectory = createPrivateDirectory(
      path.join(scratchGit.path, "index-normalize"),
      { operationBudget },
    );
    const canonicalIndexDirectory = createPrivateDirectory(
      path.join(scratchGit.path, "index-canonical"),
      { operationBudget },
    );
    const indexPath = path.join(indexDirectory.path, "index");
    const canonicalIndexPath = path.join(canonicalIndexDirectory.path, "index");
    copyObservedGitFile(gitObservation.index, indexPath, {
      destinationMetadataAnchor: indexDirectory,
      limits,
      operationBudget,
    });
    let sharedPath = null;
    if (gitObservation.sharedIndex !== null) {
      sharedPath = path.join(
        indexDirectory.path,
        path.basename(gitObservation.sharedIndex.path),
      );
      copyObservedGitFile(gitObservation.sharedIndex, sharedPath, {
        destinationMetadataAnchor: indexDirectory,
        limits,
        operationBudget,
      });
    }
    clampPrivateGitTree(scratchGit.path, { expectedRoot: scratchGit, limits, operationBudget });
    const scratchConfigPath = path.join(scratchGit.path, "config");
    const scratchConfigBefore = assertPrivateFile(scratchConfigPath, null, null, {
      metadataAnchor: scratchGit,
      mismatchCode: KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
      operationBudget,
    });

    const scratchRoot = requireRealDirectory(
      created.path,
      "private index-normalization scratch",
      { expectedIdentity: created.identity, operationBudget, privateMode: true },
    );
    const scratchBound = releaseLease.ownBound(
      bindDirectoryDescriptor(
        scratchRoot,
        "private index-normalization scratch",
        KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
        operationBudget,
      ),
      "private index-normalization scratch",
      KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
    );
    const scratchParentBound = releaseLease.ownBound(
      bindDirectoryDescriptor(
        requireRealDirectory(
          scratchDirectory.path,
          "private index-normalization scratch parent",
          { operationBudget, privateMode: scratchParentPrivate },
        ),
        "private index-normalization scratch parent",
        KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
        operationBudget,
      ),
      "private index-normalization scratch parent",
      KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
    );
    const scratchGitBound = releaseLease.ownBound(
      bindDirectoryDescriptor(
        requireRealDirectory(
          scratchGit.path,
          "private index-normalization Git directory",
          { expectedIdentity: scratchGit.identity, operationBudget, privateMode: true },
        ),
        "private index-normalization Git directory",
        KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
        operationBudget,
      ),
      "private index-normalization Git directory",
      KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
    );
    const environment = Object.freeze({
      ...scrubGitEnvironment(),
      GIT_DIR: ".git",
      GIT_INDEX_FILE: ".git/index-normalize/index",
      GIT_NO_LAZY_FETCH: "1",
      GIT_OBJECT_DIRECTORY: ".git/objects",
      GIT_WORK_TREE: ".",
    });
    const byteBudget = createObservationByteBudget(limits, "standalone index normalization");
    const observedIndexBefore = observeRegularFile(indexPath, null, {
      maxAllocatedBytes: limits.maxAllocatedBytes,
      maxBytes: limits.maxFileBytes,
      operationBudget,
    });
    if (observedIndexBefore.sha256 !== gitObservation.index.sha256) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE,
        "copied normalization index differs from the captured source index",
      );
    }
    const observedSharedBefore = sharedPath === null
      ? null
      : observeRegularFile(sharedPath, null, {
          maxAllocatedBytes: limits.maxAllocatedBytes,
          maxBytes: limits.maxFileBytes,
          operationBudget,
        });
    if (
      (gitObservation.sharedIndex === null) !== (observedSharedBefore === null) ||
      (gitObservation.sharedIndex !== null &&
        observedSharedBefore.sha256 !== gitObservation.sharedIndex.sha256)
    ) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE,
        "copied normalization companion differs from the captured shared index",
      );
    }
    const sourceLogical = logicalEntriesFromRawIndex(
      observedIndexBefore.bytes,
      observedSharedBefore?.bytes ?? null,
      gitObservation.objectFormat,
      limits,
    );
    const sourceSemanticExtensions = rawIndexExtensionProjection(
      sourceLogical.main,
      SEMANTIC_INDEX_EXTENSIONS,
    );
    const runSemantic = (args, label) => runObservedGit(created.path, args, label, byteBudget, {
      code: KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_INDEX_UNSUPPORTED,
      directoryFd: scratchBound.fd,
      environment,
      gitExecutable,
      timeoutMs: commandTimeout(),
    });
    const beforeStage = runSemantic(
      ["ls-files", "--stage", "--full-name", "-z"],
      "normalization input stage listing",
    );
    const beforeResolveUndo = runSemantic(
      ["ls-files", "--resolve-undo", "--full-name", "-z"],
      "normalization input resolve-undo listing",
    );
    const beforeFlags = runSemantic(
      ["ls-files", "-v", "--full-name", "-z"],
      "normalization input flag listing",
    );
    const activeSharedBefore = oneLine(
      runSemantic(["rev-parse", "--shared-index-path"], "normalization input shared-index path"),
      "normalization input shared-index path",
      { allowEmpty: true },
    );
    if (
      gitObservation.sharedIndex === null
        ? activeSharedBefore !== ""
        : activeSharedBefore === "" ||
          path.basename(activeSharedBefore) !== path.basename(gitObservation.sharedIndex.path)
    ) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_INDEX_UNSUPPORTED,
        "normalization input does not use the captured split-index state",
        { activeSharedBefore },
      );
    }

    const normalized = runGitAllowStatus(
      created.path,
      [
        "-c",
        "core.splitIndex=false",
        "-c",
        "index.threads=1",
        "-c",
        "index.recordOffsetTable=false",
        "-c",
        "index.recordEndOfIndexEntries=false",
        "update-index",
        "--index-version",
        "3",
        "--no-split-index",
        "--no-untracked-cache",
        "--no-fsmonitor",
      ],
      new Set([0]),
      gitExecutable,
      commandTimeout(),
      byteBudget.remainingLimit("standalone index normalization command"),
      {
        code: KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_INDEX_UNSUPPORTED,
        directoryFd: scratchBound.fd,
        environment,
      },
    );
    const normalizedOutputBytes =
      (Buffer.isBuffer(normalized.stdout) ? normalized.stdout.length : 0) +
      (Buffer.isBuffer(normalized.stderr) ? normalized.stderr.length : 0);
    byteBudget.charge(normalizedOutputBytes, "standalone index normalization command");
    if (normalizedOutputBytes !== 0) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_INDEX_UNSUPPORTED,
        "standalone index normalization emitted output",
        {
          stderr: Buffer.isBuffer(normalized.stderr)
            ? normalized.stderr.subarray(0, 4096).toString("utf8")
            : "",
        },
      );
    }
    confirmBoundDirectory(
      scratchParentBound,
      "private index-normalization scratch parent",
      KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
      operationBudget,
    );
    confirmBoundDirectory(
      scratchBound,
      "private index-normalization scratch",
      KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
      operationBudget,
    );
    confirmBoundDirectory(
      scratchGitBound,
      "private index-normalization Git directory",
      KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
      operationBudget,
    );
    const indexDirectoryAfter = requireRealDirectory(
      indexDirectory.path,
      "private normalized-index directory",
      { expectedIdentity: indexDirectory.identity, operationBudget, privateMode: true },
    );
    const activeSharedAfter = oneLine(
      runSemantic(["rev-parse", "--shared-index-path"], "normalized shared-index path"),
      "normalized shared-index path",
      { allowEmpty: true },
    );
    if (activeSharedAfter !== "") {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_INDEX_UNSUPPORTED,
        "standalone index normalization retained active split-index state",
        { activeSharedAfter },
      );
    }
    const afterStage = runSemantic(
      ["ls-files", "--stage", "--full-name", "-z"],
      "normalized stage listing",
    );
    const afterResolveUndo = runSemantic(
      ["ls-files", "--resolve-undo", "--full-name", "-z"],
      "normalized resolve-undo listing",
    );
    const afterFlags = runSemantic(
      ["ls-files", "-v", "--full-name", "-z"],
      "normalized flag listing",
    );
    if (
      !beforeStage.equals(afterStage) ||
      !beforeResolveUndo.equals(afterResolveUndo) ||
      !beforeFlags.equals(afterFlags)
    ) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_INDEX_UNSUPPORTED,
        "standalone index normalization changed Git-visible index semantics",
        {
          flagsChanged: !beforeFlags.equals(afterFlags),
          resolveUndoChanged: !beforeResolveUndo.equals(afterResolveUndo),
          stageChanged: !beforeStage.equals(afterStage),
        },
      );
    }
    const observedIndexAfter = observeRegularFile(indexPath, null, {
      maxAllocatedBytes: limits.maxAllocatedBytes,
      maxBytes: limits.maxFileBytes,
      operationBudget,
    });
    const output = parseRawGitIndex(
      observedIndexAfter.bytes,
      gitObservation.objectFormat,
      "normalized standalone index",
      {
        code: KNOCKOUT_WORKSPACE_ERROR_CODES.STANDALONE_GIT_INVALID,
        maxEntries: limits.maxNodes,
      },
    );
    const outputExtensions = requireSupportedRawIndexExtensions(
      output,
      "normalized standalone index before cache canonicalization",
    );
    if (outputExtensions.has("link") || outputExtensions.has("UNTR")) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.STANDALONE_GIT_INVALID,
        "normalized standalone index retains non-standalone cache state",
      );
    }
    if (
      !canonicalJsonBytes(rawIndexSemanticProjection(sourceLogical.entries)).equals(
        canonicalJsonBytes(rawIndexSemanticProjection(output.entries)),
      )
    ) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.STANDALONE_GIT_INVALID,
        "normalized standalone index differs from the independently parsed source index",
      );
    }
    if (
      !canonicalJsonBytes(rawIndexExtensionProjection(output, SEMANTIC_INDEX_EXTENSIONS)).equals(
        canonicalJsonBytes(sourceSemanticExtensions),
      )
    ) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.STANDALONE_GIT_INVALID,
        "standalone index normalization changed resolve-undo extension bytes",
      );
    }
    const parsedBeforeStage = parseIndexEntries(
      beforeStage,
      gitObservation.objectFormat,
      "normalization input stage listing",
    );
    if (
      !canonicalJsonBytes(rawIndexStageProjection(sourceLogical.entries)).equals(
        canonicalJsonBytes(parsedBeforeStage),
      )
    ) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_INDEX_UNSUPPORTED,
        "independent split-index reconstruction differs from Git's stage listing",
      );
    }

    const canonicalIndexBytes = canonicalStandaloneIndexBytes(
      observedIndexAfter.bytes,
      output,
      gitObservation.objectFormat,
    );
    if (canonicalIndexBytes.length > limits.maxFileBytes) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.RESOURCE_LIMIT_EXCEEDED,
        "canonical standalone index exceeds the admitted per-file byte limit",
      );
    }
    writeExclusivePrivateFile(canonicalIndexPath, canonicalIndexBytes, 0o600, operationBudget);
    fsyncDirectory(canonicalIndexDirectory.path, operationBudget);
    const canonicalIndexDirectoryAfter = requireRealDirectory(
      canonicalIndexDirectory.path,
      "private canonical-index directory",
      {
        expectedIdentity: canonicalIndexDirectory.identity,
        operationBudget,
        privateMode: true,
      },
    );
    const canonicalIndexDirectoryBound = releaseLease.ownBound(
      bindDirectoryDescriptor(
        canonicalIndexDirectoryAfter,
        "private canonical-index directory",
        KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
        operationBudget,
      ),
      "private canonical-index directory",
      KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
    );
    const mutableIndexDirectoryBound = releaseLease.ownBound(
      bindDirectoryDescriptor(
        requireRealDirectory(
          indexDirectoryAfter.path,
          "private normalized-index directory",
          {
            expectedIdentity: indexDirectoryAfter.identity,
            operationBudget,
            privateMode: true,
          },
        ),
        "private normalized-index directory",
        KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
        operationBudget,
      ),
      "private normalized-index directory",
      KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
    );
    for (const [bound, lockName, label] of [
      [mutableIndexDirectoryBound, "index.lock", "normalization lock residue"],
      [canonicalIndexDirectoryBound, "index.lock", "canonical index lock residue"],
    ]) {
      if (boundEntryStat(bound, lockName, label, {
        code: KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_INDEX_UNSUPPORTED,
        operationBudget,
      }) !== null) {
        fail(
          KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_INDEX_UNSUPPORTED,
          `${label} remains after standalone index normalization`,
        );
      }
    }
    const requireExactEntries = (directory, expectedNames, label) => {
      let entries;
      try {
        entries = fs.readdirSync(directory, { encoding: "utf8", withFileTypes: true });
      } catch (error) {
        fail(
          KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
          `cannot enumerate ${label}`,
          null,
          error,
        );
      }
      const observedNames = entries.map((entry) => entry.name).sort();
      const unexpected = entries
        .filter((entry) => !entry.isFile() || !expectedNames.has(entry.name))
        .map((entry) => entry.name)
        .sort();
      if (unexpected.length !== 0 || entries.length !== expectedNames.size) {
        fail(
          KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_INDEX_UNSUPPORTED,
          `${label} contains unexpected state`,
          { entries: observedNames, unexpected },
        );
      }
    };
    requireExactEntries(
      indexDirectory.path,
      new Set([
        "index",
        ...(gitObservation.sharedIndex === null
          ? []
          : [path.basename(gitObservation.sharedIndex.path)]),
      ]),
      "normalized-index directory",
    );
    requireExactEntries(
      canonicalIndexDirectory.path,
      new Set(["index"]),
      "canonical-index directory",
    );
    const canonicalIndexSha256 = sha256(canonicalIndexBytes);
    const canonicalIndexBefore = assertPrivateFile(
      canonicalIndexPath,
      canonicalIndexSha256,
      null,
      {
        metadataAnchor: canonicalIndexDirectoryAfter,
        mismatchCode: KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
        operationBudget,
      },
    );
    const canonicalParsed = parseRawGitIndex(
      canonicalIndexBefore.bytes,
      gitObservation.objectFormat,
      "canonical standalone index",
      {
        code: KNOCKOUT_WORKSPACE_ERROR_CODES.STANDALONE_GIT_INVALID,
        maxEntries: limits.maxNodes,
      },
    );
    requireSupportedRawIndexExtensions(canonicalParsed, "canonical standalone index", {
      standalone: true,
    });
    if (
      !canonicalJsonBytes(rawIndexSemanticProjection(sourceLogical.entries)).equals(
        canonicalJsonBytes(rawIndexSemanticProjection(canonicalParsed.entries)),
      ) ||
      !canonicalJsonBytes(rawIndexExtensionProjection(canonicalParsed, SEMANTIC_INDEX_EXTENSIONS))
        .equals(canonicalJsonBytes(sourceSemanticExtensions))
    ) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.STANDALONE_GIT_INVALID,
        "canonical standalone index differs from independently parsed source semantics",
      );
    }
    if (canonicalParsed.entries.some((entry) => !/^0{48}[0-9a-f]{8}0{24}$/u.test(entry.stat))) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.STANDALONE_GIT_INVALID,
        "canonical standalone index retains trusted source stat-cache bytes",
      );
    }

    const canonicalEnvironment = Object.freeze({
      ...environment,
      GIT_INDEX_FILE: ".git/index-canonical/index",
    });
    const runCanonicalSemantic = (args, label) => runObservedGit(
      created.path,
      args,
      label,
      byteBudget,
      {
        code: KNOCKOUT_WORKSPACE_ERROR_CODES.STANDALONE_GIT_INVALID,
        directoryFd: scratchBound.fd,
        environment: canonicalEnvironment,
        gitExecutable,
        timeoutMs: commandTimeout(),
      },
    );
    const canonicalShared = oneLine(
      runCanonicalSemantic(
        ["rev-parse", "--shared-index-path"],
        "canonical standalone shared-index path",
      ),
      "canonical standalone shared-index path",
      { allowEmpty: true },
    );
    const finalStage = runCanonicalSemantic(
      ["ls-files", "--stage", "--full-name", "-z"],
      "canonical standalone stage listing",
    );
    const finalResolveUndo = runCanonicalSemantic(
      ["ls-files", "--resolve-undo", "--full-name", "-z"],
      "canonical standalone resolve-undo listing",
    );
    const finalFlags = runCanonicalSemantic(
      ["ls-files", "-v", "--full-name", "-z"],
      "canonical standalone flag listing",
    );
    if (
      canonicalShared !== "" || !beforeStage.equals(finalStage) ||
      !beforeResolveUndo.equals(finalResolveUndo) || !beforeFlags.equals(finalFlags)
    ) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.STANDALONE_GIT_INVALID,
        "canonical standalone index changed Git-visible index semantics",
        {
          flagsChanged: !beforeFlags.equals(finalFlags),
          resolveUndoChanged: !beforeResolveUndo.equals(finalResolveUndo),
          sharedIndexPath: canonicalShared,
          stageChanged: !beforeStage.equals(finalStage),
        },
      );
    }
    if (
      !canonicalJsonBytes(rawIndexStageProjection(canonicalParsed.entries)).equals(
        canonicalJsonBytes(parseIndexEntries(
          finalStage,
          gitObservation.objectFormat,
          "canonical standalone stage listing",
        )),
      )
    ) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.STANDALONE_GIT_INVALID,
        "canonical raw index differs from Git's final stage listing",
      );
    }
    assertPrivateFile(
      canonicalIndexPath,
      canonicalIndexSha256,
      canonicalIndexBefore.observation,
      {
        metadataAnchor: canonicalIndexDirectoryAfter,
        mismatchCode: KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
        operationBudget,
      },
    );
    confirmBoundDirectory(
      canonicalIndexDirectoryBound,
      "private canonical-index directory",
      KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
      operationBudget,
    );
    confirmBoundDirectory(
      mutableIndexDirectoryBound,
      "private normalized-index directory",
      KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
      operationBudget,
    );
    if (observedSharedBefore !== null) {
      const observedSharedAfter = observeRegularFile(sharedPath, null, {
        maxAllocatedBytes: limits.maxAllocatedBytes,
        maxBytes: limits.maxFileBytes,
        operationBudget,
      });
      if (
        observedSharedAfter.sha256 !== observedSharedBefore.sha256 ||
        !sameFileObservation(observedSharedAfter.observation, observedSharedBefore.observation)
      ) {
        fail(
          KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
          "normalization shared-index companion changed unexpectedly",
        );
      }
    }
    assertPrivateFile(
      scratchConfigPath,
      scratchConfigBefore.sha256,
      scratchConfigBefore.observation,
      {
        metadataAnchor: scratchGit,
        mismatchCode: KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
        operationBudget,
      },
    );
    confirmBoundDirectory(
      scratchGitBound,
      "private index-normalization Git directory",
      KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
      operationBudget,
    );
    const capacity = requireDestinationCapacity(
      path.dirname(destinationIndex),
      canonicalIndexBytes.length,
      limits,
      "canonical standalone index publication",
      operationBudget,
    );
    resourceLedger.charge({
      allocatedBytes: Math.max(
        canonicalIndexBefore.observation.allocatedBytes,
        projectedAllocatedWriteBytes(
          canonicalIndexBytes.length,
          capacity.allocationUnitBytes,
        ),
      ),
      label: "canonical standalone index publication",
      logicalBytes: canonicalIndexBytes.length,
      maxDepth: 3,
      nodeCount: 1,
    });
    writeExclusivePrivateFile(destinationIndex, canonicalIndexBytes, 0o600, operationBudget);
    const publishedIndex = assertPrivateFile(
      destinationIndex,
      canonicalIndexSha256,
      null,
      {
        metadataAnchor: destinationMetadataAnchor,
        mismatchCode: KNOCKOUT_WORKSPACE_ERROR_CODES.STANDALONE_GIT_INVALID,
        operationBudget,
      },
    );
    confirmBoundDirectory(
      canonicalIndexDirectoryBound,
      "private canonical-index directory after seed publication",
      KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
      operationBudget,
    );
    return freezeWithRetainedPrivateRoots({
      index: Object.freeze({
        mode: publishedIndex.observation.mode,
        observation: publishedIndex.observation,
        path: destinationIndex,
        sha256: publishedIndex.sha256,
        size: publishedIndex.observation.size,
      }),
      indexStageBytes: finalStage.length,
      indexStageSha256: sha256(finalStage),
      resolveUndo: Object.freeze(parseIndexEntries(
        finalResolveUndo,
        gitObservation.objectFormat,
        "normalized resolve-undo index extension",
      )),
    }, [residue]);
  } catch (error) {
    primaryError = reportRetainedPrivateRoots(error, [residue]);
    throw primaryError;
  } finally {
    releaseLease.release(primaryError);
  }
}

function clampPrivateGitTree(gitDirectory, options = {}) {
  const {
    expectedRoot = null,
    limits: requestedLimits = KNOCKOUT_WORKSPACE_CAPTURE_LIMITS,
    operationBudget = null,
  } = options;
  const limits = normalizeCaptureLimits(requestedLimits);
  const absoluteRoot = requireAbsolutePath(gitDirectory, "standalone Git directory");
  const root = expectedRoot ?? requireRealDirectory(absoluteRoot, "standalone Git directory");
  if (
    root === null || typeof root !== "object" ||
    typeof root.identity !== "string" || root.path !== absoluteRoot
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.STANDALONE_GIT_INVALID,
      "standalone Git root identity is malformed",
    );
  }
  const expectedUid = operationEffectiveUid(
    operationBudget,
    `standalone Git owner check for ${gitDirectory}`,
  );
  let visitedNodes = 0;

  const chargeNode = (abs, depth) => {
    if (operationBudget !== null) {
      remainingOperationMs(operationBudget, `standalone Git durability at ${abs}`);
    }
    if (depth > limits.maxDepth || visitedNodes >= limits.maxNodes) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.RESOURCE_LIMIT_EXCEEDED,
        "standalone Git tree exceeds its admitted traversal limits",
        { depth, maxDepth: limits.maxDepth, maxNodes: limits.maxNodes, path: abs },
      );
    }
    visitedNodes += 1;
  };

  const assertBoundNode = (fd, abs, expectedIdentity, type, requiredMode = null) => {
    let opened;
    let atPath;
    try {
      opened = fs.fstatSync(fd, { bigint: true });
      atPath = fs.lstatSync(abs, { bigint: true });
    } catch (error) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.STANDALONE_GIT_INVALID,
        `standalone Git node cannot be rebound at ${abs}`,
        { expectedIdentity, type },
        error,
      );
    }
    const expectedType = type === "directory"
      ? opened.isDirectory() && atPath.isDirectory()
      : opened.isFile() && atPath.isFile();
    if (
      atPath.isSymbolicLink() || !expectedType ||
      identityOf(opened) !== expectedIdentity || identityOf(atPath) !== expectedIdentity ||
      (type === "file" && (Number(opened.nlink) !== 1 || Number(atPath.nlink) !== 1)) ||
      (requiredMode !== null && (modeOf(opened) !== requiredMode || modeOf(atPath) !== requiredMode)) ||
      (expectedUid !== null &&
        (Number(opened.uid) !== expectedUid || Number(atPath.uid) !== expectedUid))
    ) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.STANDALONE_GIT_INVALID,
        `standalone Git ${type} identity changed at ${abs}`,
        {
          expectedIdentity,
          openedIdentity: identityOf(opened),
          pathIdentity: identityOf(atPath),
        },
      );
    }
    return opened;
  };

  const sealFile = (abs, expectedIdentity, depth) => {
    chargeNode(abs, depth);
    let fd;
    let pendingError = null;
    try {
      fd = fs.openSync(abs, fs.constants.O_RDONLY | NOFOLLOW);
      assertBoundNode(fd, abs, expectedIdentity, "file");
      try {
        fs.fchmodSync(fd, 0o600);
        fs.fsyncSync(fd);
        if (operationBudget !== null) {
          remainingOperationMs(operationBudget, `standalone Git durability at ${abs}`);
        }
      } catch (error) {
        fail(
          KNOCKOUT_WORKSPACE_ERROR_CODES.DURABILITY_FAILED,
          `cannot durably seal standalone Git file ${abs}`,
          null,
          error,
        );
      }
      assertBoundNode(fd, abs, expectedIdentity, "file", 0o600);
    } catch (error) {
      pendingError = error instanceof KnockoutWorkspaceError
        ? error
        : workspaceError(
            KNOCKOUT_WORKSPACE_ERROR_CODES.STANDALONE_GIT_INVALID,
            `cannot inspect standalone Git file ${abs}`,
            null,
            error,
          );
    }
    if (fd !== undefined) {
      try { fs.closeSync(fd); }
      catch (error) {
        if (pendingError === null) {
          pendingError = workspaceError(
            KNOCKOUT_WORKSPACE_ERROR_CODES.DURABILITY_FAILED,
            `cannot close sealed standalone Git file ${abs}`,
            null,
            error,
          );
        }
      }
    }
    if (pendingError !== null) throw pendingError;
    if (operationBudget !== null) {
      remainingOperationMs(operationBudget, `standalone Git durability at ${abs}`);
    }
  };

  const walk = (directory, expectedIdentity, depth) => {
    chargeNode(directory, depth);
    let fd;
    let pendingError = null;
    try {
      fd = fs.openSync(directory, fs.constants.O_RDONLY | DIRECTORY | NOFOLLOW);
      assertBoundNode(fd, directory, expectedIdentity, "directory");
      let enumeration;
      let enumerationError = null;
      try {
        enumeration = fs.opendirSync(directory, { bufferSize: 32, encoding: "buffer" });
        while (true) {
          if (operationBudget !== null) {
            remainingOperationMs(operationBudget, `standalone Git durability at ${directory}`);
          }
          const entry = enumeration.readSync();
          if (operationBudget !== null) {
            remainingOperationMs(operationBudget, `standalone Git durability at ${directory}`);
          }
          if (entry === null) break;
          let name;
          try { name = utf8Decoder.decode(entry.name); }
          catch (error) {
            fail(
              KNOCKOUT_WORKSPACE_ERROR_CODES.STANDALONE_GIT_INVALID,
              "standalone Git pathname is not valid UTF-8",
              null,
              error,
            );
          }
          const abs = path.join(directory, name);
          let stat;
          try { stat = fs.lstatSync(abs, { bigint: true }); }
          catch (error) {
            fail(
              KNOCKOUT_WORKSPACE_ERROR_CODES.STANDALONE_GIT_INVALID,
              `standalone Git node disappeared at ${abs}`,
              null,
              error,
            );
          }
          if (operationBudget !== null) {
            remainingOperationMs(operationBudget, `standalone Git durability at ${abs}`);
          }
          if (stat.isSymbolicLink()) {
            fail(
              KNOCKOUT_WORKSPACE_ERROR_CODES.STANDALONE_GIT_INVALID,
              `standalone Git metadata contains symlink ${abs}`,
            );
          }
          if (stat.isDirectory()) {
            walk(abs, identityOf(stat), depth + 1);
          } else if (stat.isFile()) {
            sealFile(abs, identityOf(stat), depth + 1);
          } else {
            fail(
              KNOCKOUT_WORKSPACE_ERROR_CODES.STANDALONE_GIT_INVALID,
              `standalone Git metadata contains a special node at ${abs}`,
            );
          }
          assertBoundNode(fd, directory, expectedIdentity, "directory");
        }
      } catch (error) {
        enumerationError = error instanceof KnockoutWorkspaceError
          ? error
          : workspaceError(
              KNOCKOUT_WORKSPACE_ERROR_CODES.STANDALONE_GIT_INVALID,
              `cannot enumerate standalone Git directory ${directory}`,
              null,
              error,
            );
      }
      if (enumeration !== undefined) {
        try { enumeration.closeSync(); }
        catch (error) {
          if (enumerationError === null) {
            enumerationError = workspaceError(
              KNOCKOUT_WORKSPACE_ERROR_CODES.DURABILITY_FAILED,
              `cannot close standalone Git enumeration at ${directory}`,
              null,
              error,
            );
          }
        }
      }
      if (enumerationError !== null) throw enumerationError;
      if (operationBudget !== null) {
        remainingOperationMs(operationBudget, `standalone Git durability at ${directory}`);
      }
      try {
        fs.fchmodSync(fd, 0o700);
        fs.fsyncSync(fd);
        if (operationBudget !== null) {
          remainingOperationMs(operationBudget, `standalone Git durability at ${directory}`);
        }
      } catch (error) {
        fail(
          KNOCKOUT_WORKSPACE_ERROR_CODES.DURABILITY_FAILED,
          `cannot durably seal standalone Git directory ${directory}`,
          null,
          error,
        );
      }
      assertBoundNode(fd, directory, expectedIdentity, "directory", 0o700);
    } catch (error) {
      pendingError = error instanceof KnockoutWorkspaceError
        ? error
        : workspaceError(
            KNOCKOUT_WORKSPACE_ERROR_CODES.STANDALONE_GIT_INVALID,
            `cannot inspect standalone Git directory ${directory}`,
            null,
            error,
          );
    }
    if (fd !== undefined) {
      try { fs.closeSync(fd); }
      catch (error) {
        if (pendingError === null) {
          pendingError = workspaceError(
            KNOCKOUT_WORKSPACE_ERROR_CODES.DURABILITY_FAILED,
            `cannot close sealed standalone Git directory ${directory}`,
            null,
            error,
          );
        }
      }
    }
    if (pendingError !== null) throw pendingError;
    if (operationBudget !== null) {
      remainingOperationMs(operationBudget, `standalone Git durability at ${directory}`);
    }
  };

  walk(absoluteRoot, root.identity, 0);
  if (operationBudget !== null) {
    remainingOperationMs(operationBudget, "standalone Git durability completion");
  }
  return Object.freeze({ identity: root.identity, nodeCount: visitedNodes, path: absoluteRoot });
}

function importIndexObjects(
  destinationRoot,
  gitObservation,
  gitExecutable,
  operationBudget,
  limits,
  resourceLedger,
  readSourceObject,
) {
  if (typeof readSourceObject !== "function") {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "source object reader is required");
  }
  const commandTimeout = () => remainingOperationMs(operationBudget, "standalone index-object import");
  for (const objectId of gitObservation.objectIds) {
    const type = oneLine(
      readSourceObject(["cat-file", "-t", objectId], `index object ${objectId} type`, {
        code: KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_OBJECT_MISSING,
        timeoutMs: commandTimeout(),
      }),
      "index object type",
    );
    if (type !== "blob") {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_INDEX_UNSUPPORTED,
        `index object ${objectId} is ${type}, not blob`,
      );
    }
    const bytes = readSourceObject(["cat-file", "blob", objectId], `index object ${objectId}`, {
      code: KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_OBJECT_MISSING,
      maxBuffer: limits.maxFileBytes,
      timeoutMs: commandTimeout(),
    });
    const projectedObjectBytes = gitLooseObjectUpperBound(bytes.length);
    const capacity = requireDestinationCapacity(
      destinationRoot,
      projectedObjectBytes,
      limits,
      "standalone index-object import",
      operationBudget,
    );
    resourceLedger.charge({
      allocatedBytes: projectedAllocatedWriteBytes(
        projectedObjectBytes,
        capacity.allocationUnitBytes,
      ),
      label: `standalone index object ${objectId}`,
      logicalBytes: projectedObjectBytes,
      maxDepth: 4,
      nodeCount: 1,
    });
    const imported = oneLine(
      runGit(destinationRoot, ["hash-object", "-w", "--stdin"], {
        code: KNOCKOUT_WORKSPACE_ERROR_CODES.STANDALONE_GIT_INVALID,
        gitExecutable,
        input: bytes,
        timeoutMs: commandTimeout(),
      }),
      "imported object identity",
    );
    if (imported !== objectId) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.STANDALONE_GIT_INVALID,
        `index object ${objectId} changed during import`,
        { imported },
      );
    }
  }
}

function initializeStandaloneGit(sourceRoot, destinationRoot, gitObservation, options = {}) {
  const gitExecutable = options.gitExecutable ?? null;
  const commandTimeoutMs = requireCommandTimeoutMs(
    options.commandTimeoutMs ?? MAX_CHILD_PROCESS_DURATION_MS,
  );
  const operationBudget = options.operationBudget ?? createOperationBudget(commandTimeoutMs);
  const commandTimeout = () => remainingOperationMs(operationBudget, "standalone Git initialization");
  const limits = normalizeCaptureLimits(
    options.limits ?? KNOCKOUT_WORKSPACE_CAPTURE_LIMITS,
  );
  const resourceLedger = options.resourceLedger;
  if (
    resourceLedger === null || typeof resourceLedger !== "object" ||
    typeof resourceLedger.charge !== "function" || typeof resourceLedger.snapshot !== "function"
  ) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "shared capture resource ledger is required");
  }
  if (!validGitStatusConfig(gitObservation?.statusConfig)) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
      "source Git status configuration is malformed",
    );
  }
  const expectedGitRoot = options.expectedGitRoot;
  const destination = requireRealDirectory(
    destinationRoot,
    "standalone destination workspace",
    { operationBudget, privateMode: true },
  ).path;
  const expectedGitPath = path.join(destination, ".git");
  if (
    expectedGitRoot === null || typeof expectedGitRoot !== "object" ||
    typeof expectedGitRoot.identity !== "string" || expectedGitRoot.path !== expectedGitPath
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
      "pre-created standalone Git root identity is required",
    );
  }
  const gitRootBefore = requireRealDirectory(
    expectedGitPath,
    "pre-created standalone Git directory",
    { operationBudget, privateMode: true },
  );
  if (gitRootBefore.identity !== expectedGitRoot.identity) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.STANDALONE_GIT_INVALID,
      "pre-created standalone Git root identity changed before initialization",
    );
  }
  const expectedSourceRoot = options.expectedSourceRoot ?? null;
  if (expectedSourceRoot === null || !validBoundDirectory(expectedSourceRoot)) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "expected source root binding is required");
  }
  // Object ingestion reads the live object store only from a descriptor bound to the exact
  // `objects` entry of the bound common directory. Git receives relative `.` / `..` authority;
  // no source or linked-common absolute pathname is passed to an object-reading child.
  let sourceBound = null;
  let commonBound = null;
  let objectAuthority = null;
  const releaseLease = createReleaseLease({
    fallbackCode: KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED,
    message: "standalone Git initialization release failed",
  });
  let primaryError = null;
  sourceBound = releaseLease.ownBound(
    bindDirectoryDescriptor(
      requireSourceRoot(sourceRoot, expectedSourceRoot, operationBudget, {
        label: "source root before standalone Git ingestion",
        observation: expectedSourceRoot.observation ?? null,
      }),
      "source root",
      KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED,
      operationBudget,
    ),
    "source root",
    KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED,
  );
  try {
    const commonDirectory = requireRealDirectory(
      gitObservation.commonDirectory,
      "Git common directory",
      {
        expectedIdentity: gitObservation.commonDirectoryIdentity,
        expectedIdentityCode: KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED,
        operationBudget,
      },
    );
    if (
      !validDirectoryObservation(gitObservation.commonDirectoryObservation) ||
      !sameDirectoryObservation(commonDirectory.observation, gitObservation.commonDirectoryObservation)
    ) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED,
        "Git common directory changed before standalone Git ingestion",
        {
          expected: gitObservation.commonDirectoryObservation ?? null,
          observed: commonDirectory.observation,
          path: commonDirectory.path,
        },
      );
    }
    commonBound = releaseLease.ownBound(
      bindDirectoryDescriptor(
        commonDirectory,
        "Git common directory",
        KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED,
        operationBudget,
      ),
      "Git common directory",
      KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED,
    );
    objectAuthority = createBoundObjectAuthority(
      commonBound,
      gitObservation.objectFormat,
      {
        byteBudget: null,
        configFile: gitObservation.configFile,
        limits,
        nestedCommondir: gitObservation.nestedCommondir,
        operationBudget,
        worktreeConfigFile: gitObservation.commonDirectory === gitObservation.gitDirectory
          ? gitObservation.worktreeConfigFile
          : gitObservation.commonWorktreeConfigFile,
      },
    );
    releaseLease.add(() => objectAuthority.release());
  } catch (error) {
    throw releaseLeaseError(releaseLease, error);
  }
  const ingest = () => {
  runGit(
    destination,
    ["init", "-q", `--object-format=${gitObservation.objectFormat}`, "--template="],
    {
      code: KNOCKOUT_WORKSPACE_ERROR_CODES.STANDALONE_GIT_INVALID,
      gitExecutable,
      timeoutMs: commandTimeout(),
    },
  );
  const initializedGitPath = realpathOrFail(
    oneLine(
      runGit(destination, ["rev-parse", "--absolute-git-dir"], {
        code: KNOCKOUT_WORKSPACE_ERROR_CODES.STANDALONE_GIT_INVALID,
        gitExecutable,
        timeoutMs: commandTimeout(),
      }),
      "initialized standalone Git directory",
    ),
    KNOCKOUT_WORKSPACE_ERROR_CODES.STANDALONE_GIT_INVALID,
    "initialized standalone Git directory",
  );
  const gitRootAfterInit = requireRealDirectory(
    expectedGitPath,
    "initialized standalone Git directory",
    { operationBudget, privateMode: true },
  );
  if (
    initializedGitPath !== expectedGitPath ||
    gitRootAfterInit.identity !== expectedGitRoot.identity
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.STANDALONE_GIT_INVALID,
      "Git initialized outside the pre-created identity-bound root",
      { expectedGitPath, initializedGitPath },
    );
  }
  for (const [key, value] of [
    ...Object.entries(gitObservation.statusConfig).map(([key, enabled]) => [key, String(enabled)]),
    ["core.fsmonitor", "false"],
    ["core.splitIndex", "false"],
    ["core.untrackedCache", "false"],
    ["core.hooksPath", "/dev/null"],
    ["gc.auto", "0"],
    ["maintenance.auto", "false"],
  ]) {
    runGit(destination, ["config", "--local", key, value], {
      code: KNOCKOUT_WORKSPACE_ERROR_CODES.STANDALONE_GIT_INVALID,
      gitExecutable,
      timeoutMs: commandTimeout(),
    });
  }
  const readSourceObject = (args, label, extra = {}) => objectAuthority.run(
    label,
    (directoryFd, environment) => runGit(
      objectAuthority.objectsBound.path,
      args,
      {
        directoryFd,
        environment,
        gitExecutable,
        timeoutMs: commandTimeout(),
        ...extra,
      },
    ),
  );
  const pack = readSourceObject(
    ["pack-objects", "--stdout", "--revs"],
    "standalone HEAD pack",
    {
      code: KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_OBJECT_MISSING,
      input: Buffer.from(`${gitObservation.head}\n`, "ascii"),
      maxBuffer: limits.maxFileBytes,
      timeoutMs: commandTimeout(),
    },
  );
  const projectedPack = gitPackArtifactUpperBounds(pack, gitObservation.objectFormat);
  const packCapacity = requireDestinationCapacity(
    destination,
    projectedPack.logicalBytes,
    limits,
    "standalone Git pack import",
    operationBudget,
  );
  resourceLedger.charge({
    allocatedBytes:
      projectedAllocatedWriteBytes(projectedPack.packBytes, packCapacity.allocationUnitBytes) +
      projectedAllocatedWriteBytes(projectedPack.indexBytes, packCapacity.allocationUnitBytes) +
      projectedAllocatedWriteBytes(
        projectedPack.reverseIndexBytes,
        packCapacity.allocationUnitBytes,
      ),
    label: "standalone Git pack, index, and reverse index",
    logicalBytes: projectedPack.logicalBytes,
    maxDepth: 4,
    nodeCount: 3,
  });
  runGit(destination, ["index-pack", "--stdin"], {
    code: KNOCKOUT_WORKSPACE_ERROR_CODES.STANDALONE_GIT_INVALID,
    gitExecutable,
    input: pack,
    timeoutMs: commandTimeout(),
  });
  importIndexObjects(
    destination,
    gitObservation,
    gitExecutable,
    operationBudget,
    limits,
    resourceLedger,
    readSourceObject,
  );
  requireDestinationCapacity(
    destination,
    0,
    limits,
    "standalone Git import reserve",
    operationBudget,
  );
  let normalizationResidues = [];
  try {
    const normalized = normalizeIndexForStandalone(gitObservation, {
      commandTimeoutMs,
      destinationIndex: path.join(expectedGitPath, "index"),
      destinationMetadataAnchor: expectedGitRoot,
      gitExecutable,
      limits,
      operationBudget,
      resourceLedger,
      scratchParentPrivate: options.scratchParentPrivate ?? false,
      scratchRoot: options.scratchRoot ?? os.tmpdir(),
    });
    normalizationResidues = retainedPrivateRoots(normalized);
    if (sourceBound !== null) {
      confirmBoundDirectory(
        sourceBound,
        "source root after standalone Git ingestion",
        KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED,
        operationBudget,
      );
      confirmBoundDirectory(
        commonBound,
        "Git common directory after standalone Git ingestion",
        KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED,
        operationBudget,
      );
    }
    if (gitObservation.headRef === null) {
      runGit(destination, ["update-ref", "--no-deref", "HEAD", gitObservation.head], {
        code: KNOCKOUT_WORKSPACE_ERROR_CODES.STANDALONE_GIT_INVALID,
        gitExecutable,
        timeoutMs: commandTimeout(),
      });
    } else {
      runGit(destination, ["update-ref", gitObservation.headRef, gitObservation.head], {
        code: KNOCKOUT_WORKSPACE_ERROR_CODES.STANDALONE_GIT_INVALID,
        gitExecutable,
        timeoutMs: commandTimeout(),
      });
      runGit(destination, ["symbolic-ref", "HEAD", gitObservation.headRef], {
        code: KNOCKOUT_WORKSPACE_ERROR_CODES.STANDALONE_GIT_INVALID,
        gitExecutable,
        timeoutMs: commandTimeout(),
      });
    }
    const destinationGitDirectory = oneLine(
      runGit(destination, ["rev-parse", "--absolute-git-dir"], {
        code: KNOCKOUT_WORKSPACE_ERROR_CODES.STANDALONE_GIT_INVALID,
        gitExecutable,
        timeoutMs: commandTimeout(),
      }),
      "standalone Git directory",
    );
    if (destinationGitDirectory !== expectedGitPath) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.STANDALONE_GIT_INVALID,
        "standalone Git directory moved after initialization",
      );
    }
    const destinationIndex = path.join(destinationGitDirectory, "index");
    if (normalized.index.path !== destinationIndex) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.STANDALONE_GIT_INVALID,
        "canonical standalone index was published outside the destination Git directory",
      );
    }
    const copiedIndex = assertPrivateFile(
      destinationIndex,
      normalized.index.sha256,
      normalized.index.observation,
      {
        metadataAnchor: expectedGitRoot,
        mismatchCode: KNOCKOUT_WORKSPACE_ERROR_CODES.STANDALONE_GIT_INVALID,
        operationBudget,
      },
    );
    clampPrivateGitTree(destinationGitDirectory, {
      expectedRoot: expectedGitRoot,
      limits,
      operationBudget,
    });
    fsyncDirectory(destination, operationBudget);
    objectAuthority.confirm("at standalone ingestion completion");
    return Object.freeze({
      admissionProjection: resourceLedger.snapshot(),
      gitDirectory: destinationGitDirectory,
      index: Object.freeze({
        mode: copiedIndex.observation.mode,
        observation: copiedIndex.observation,
        path: destinationIndex,
        sha256: copiedIndex.sha256,
        size: copiedIndex.observation.size,
      }),
      retainedPrivateRoots: uniqueRetainedPrivateRoots(normalizationResidues),
    });
  } catch (error) {
    throw reportRetainedPrivateRoots(error, normalizationResidues);
  }
  };
  try { return ingest(); }
  catch (error) {
    primaryError = error;
    throw error;
  }
  finally {
    releaseLease.release(primaryError);
  }
}

/**
 * Validate the published standalone repository itself. Its primary index is a normalized full
 * index, so ordinary controlled read-only Git commands need no split companion and cannot freshen
 * sealed index metadata. Workspace, parent and `.git` descriptors remain bound around every Git
 * child; exact index observations and the caller's full pre/post seed census close file mutation.
 */
export function validateStandaloneGit(workspaceRoot, expectedGit, options = {}) {
  if (expectedGit === null || typeof expectedGit !== "object" || Array.isArray(expectedGit)) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "expected Git observation is malformed");
  }
  if (options === null || typeof options !== "object" || Array.isArray(options)) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "standalone Git options are malformed");
  }
  const expectedIndex = options.expectedIndex ?? null;
  if (
    expectedIndex === null || typeof expectedIndex !== "object" ||
    !HASH_64.test(expectedIndex.sha256 ?? "")
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
      "normalized standalone index evidence is required",
    );
  }
  const gitExecutable = options.gitExecutable ?? null;
  const limits = normalizeCaptureLimits(options.limits ?? KNOCKOUT_WORKSPACE_CAPTURE_LIMITS);
  const commandTimeoutMs = requireCommandTimeoutMs(
    options.commandTimeoutMs ?? MAX_CHILD_PROCESS_DURATION_MS,
  );
  const operationBudget = options.operationBudget ?? createOperationBudget(commandTimeoutMs);
  const byteBudget = createObservationByteBudget(limits, "standalone Git validation");
  const commandTimeout = () => remainingOperationMs(operationBudget, "standalone Git validation");
  if (
    typeof expectedGit.objectFormat !== "string" || !Array.isArray(expectedGit.objectIds) ||
    !Array.isArray(expectedGit.resolveUndo) || typeof expectedGit.indexStageSha256 !== "string" ||
    !validGitStatusConfig(expectedGit.statusConfig)
  ) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "expected Git observation is malformed");
  }
  const invalid = (message, details = null) => fail(
    KNOCKOUT_WORKSPACE_ERROR_CODES.STANDALONE_GIT_INVALID,
    message,
    details,
  );
  const workspaceDirectory = requireRealDirectory(
    workspaceRoot,
    "standalone workspace",
    { operationBudget, privateMode: true },
  );
  const workspace = workspaceDirectory.path;
  const expectedGitDirectory = path.join(workspace, ".git");
  const releaseLease = createReleaseLease({
    fallbackCode: KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
    message: "standalone Git validation release failed",
  });
  let primaryError = null;
  try {
    const workspaceBound = releaseLease.ownBound(
      bindDirectoryDescriptor(
        workspaceDirectory,
        "standalone workspace",
        KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
        operationBudget,
      ),
      "standalone workspace",
      KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
    );
    const workspaceParentBound = releaseLease.ownBound(
      bindDirectoryDescriptor(
        requireRealDirectory(
          path.dirname(workspace),
          "standalone workspace parent",
          { operationBudget, privateMode: true },
        ),
        "standalone workspace parent",
        KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
        operationBudget,
      ),
      "standalone workspace parent",
      KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
    );
    const gitEntry = boundEntryStat(workspaceBound, ".git", "standalone Git directory", {
      code: KNOCKOUT_WORKSPACE_ERROR_CODES.STANDALONE_GIT_INVALID,
      operationBudget,
    });
    if (gitEntry === null || gitEntry.type !== "directory") {
      invalid("candidate does not own one standalone .git directory", {
        entry: gitEntry === null ? null : gitEntry.type,
      });
    }
    const gitRoot = requireRealDirectory(
      expectedGitDirectory,
      "standalone Git directory",
      { expectedIdentity: gitEntry.identity, operationBudget, privateMode: true },
    );
    const gitBound = releaseLease.ownBound(
      bindDirectoryDescriptor(
        gitRoot,
        "standalone Git directory",
        KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
        operationBudget,
      ),
      "standalone Git directory",
      KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
    );
    const confirmBindings = (phase) => {
      confirmBoundDirectory(
        workspaceParentBound,
        `standalone workspace parent ${phase}`,
        KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
        operationBudget,
      );
      confirmBoundDirectory(
        workspaceBound,
        `standalone workspace ${phase}`,
        KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
        operationBudget,
      );
      confirmBoundDirectory(
        gitBound,
        `standalone Git directory ${phase}`,
        KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
        operationBudget,
      );
    };
    const seedGit = (args, label, extra = {}) => {
      confirmBindings(`before ${label}`);
      const bytes = runObservedGit(workspace, args, label, byteBudget, {
        code: KNOCKOUT_WORKSPACE_ERROR_CODES.STANDALONE_GIT_INVALID,
        directoryFd: workspaceBound.fd,
        gitExecutable,
        timeoutMs: commandTimeout(),
        ...extra,
      });
      remainingOperationMs(operationBudget, label);
      confirmBindings(`after ${label}`);
      return bytes;
    };
    const gitDirectory = realpathOrFail(
      oneLine(
        seedGit(["rev-parse", "--absolute-git-dir"], "standalone Git directory"),
        "standalone Git directory",
      ),
      KNOCKOUT_WORKSPACE_ERROR_CODES.STANDALONE_GIT_INVALID,
      "standalone Git directory",
    );
    const commonDirectory = realpathOrFail(
      oneLine(
        seedGit(
          ["rev-parse", "--path-format=absolute", "--git-common-dir"],
          "standalone common Git directory",
        ),
        "standalone common Git directory",
      ),
      KNOCKOUT_WORKSPACE_ERROR_CODES.STANDALONE_GIT_INVALID,
      "standalone common Git directory",
    );
    if (gitDirectory !== expectedGitDirectory || commonDirectory !== expectedGitDirectory) {
      invalid("candidate does not own one standalone .git directory", { commonDirectory, gitDirectory });
    }
    for (const forbidden of [
      "commondir",
      "objects/info/alternates",
      "objects/info/http-alternates",
      "index.lock",
      "noa-validation",
    ]) {
      const entry = boundEntryStat(gitBound, forbidden, `standalone Git indirection ${forbidden}`, {
        code: KNOCKOUT_WORKSPACE_ERROR_CODES.STANDALONE_GIT_INVALID,
        operationBudget,
      });
      if (entry !== null) invalid(`standalone Git contains forbidden state ${forbidden}`);
    }
    const sharedCandidates = observeSharedIndexCandidates(gitDirectory, {
      bound: gitBound,
      byteBudget,
      limits,
      metadataAnchor: gitRoot,
      operationBudget,
    });
    if (sharedCandidates.length !== 0) {
      invalid("standalone Git publishes split-index companions", {
        entries: sharedCandidates.map((candidate) => path.basename(candidate.path)),
      });
    }
    const remotes = seedGit(["remote"], "standalone remotes");
    if (remotes.length !== 0) invalid("standalone Git retains a remote");
    const objectFormat = oneLine(
      seedGit(["rev-parse", "--show-object-format"], "standalone object format"),
      "standalone object format",
    );
    const head = oneLine(seedGit(["rev-parse", "HEAD"], "standalone HEAD"), "standalone HEAD");
    const headTree = oneLine(
      seedGit(["rev-parse", "HEAD^{tree}"], "standalone HEAD tree"),
      "standalone HEAD tree",
    );
    const symbolic = runGitAllowStatus(
      workspace,
      ["symbolic-ref", "-q", "HEAD"],
      new Set([0, 1]),
      gitExecutable,
      commandTimeout(),
      byteBudget.remainingLimit("standalone HEAD ref"),
      {
        code: KNOCKOUT_WORKSPACE_ERROR_CODES.STANDALONE_GIT_INVALID,
        directoryFd: workspaceBound.fd,
      },
    );
    byteBudget.charge(
      (Buffer.isBuffer(symbolic.stdout) ? symbolic.stdout.length : 0) +
        (Buffer.isBuffer(symbolic.stderr) ? symbolic.stderr.length : 0),
      "standalone HEAD ref",
    );
    remainingOperationMs(operationBudget, "standalone HEAD ref");
    confirmBindings("after standalone HEAD ref");
    const headRef = symbolic.status === 0 ? oneLine(symbolic.stdout, "standalone HEAD ref") : null;
    if (
      objectFormat !== expectedGit.objectFormat || head !== expectedGit.head ||
      headTree !== expectedGit.headTree || headRef !== expectedGit.headRef
    ) {
      invalid("standalone Git identity differs from the source observation", {
        head,
        headRef,
        headTree,
        objectFormat,
      });
    }
    rejectHeadGitlinks(
      seedGit(["ls-tree", "-r", "--full-tree", "-z", "HEAD"], "standalone HEAD tree listing"),
    );
    const indexPath = oneLine(
      seedGit(
        ["rev-parse", "--path-format=absolute", "--git-path", "index"],
        "standalone index path",
      ),
      "standalone index path",
    );
    if (indexPath !== path.join(gitDirectory, "index")) {
      invalid("standalone index is not the .git/index of the candidate", { indexPath });
    }
    const observeIndex = (expectedObservation = null) => {
      const entry = boundEntryStat(gitBound, "index", "standalone index", {
        code: KNOCKOUT_WORKSPACE_ERROR_CODES.STANDALONE_GIT_INVALID,
        operationBudget,
      });
      const observed = assertPrivateFile(
        indexPath,
        expectedIndex.sha256,
        expectedObservation,
        {
          metadataAnchor: gitRoot,
          mismatchCode: KNOCKOUT_WORKSPACE_ERROR_CODES.STANDALONE_GIT_INVALID,
          operationBudget,
        },
      );
      if (
        entry === null || entry.type !== "file" ||
        entry.identity !== observed.observation.identity
      ) invalid("standalone index is not the entry held by the Git directory");
      return observed;
    };
    const indexBefore = observeIndex();
    const parsedIndex = parseRawGitIndex(
      indexBefore.bytes,
      objectFormat,
      "standalone index",
      {
        code: KNOCKOUT_WORKSPACE_ERROR_CODES.STANDALONE_GIT_INVALID,
        maxEntries: limits.maxNodes,
      },
    );
    requireSupportedRawIndexExtensions(parsedIndex, "standalone index", { standalone: true });
    const sharedPathText = oneLine(
      seedGit(["rev-parse", "--shared-index-path"], "standalone shared-index path"),
      "standalone shared-index path",
      { allowEmpty: true },
    );
    if (sharedPathText !== "") {
      invalid("standalone index unexpectedly uses split-index state", { sharedPathText });
    }
    const assertLiveIndex = (phase) => {
      try {
        const observed = observeIndex(indexBefore.observation);
        confirmBindings(`during ${phase}`);
        return observed;
      } catch (error) {
        if (
          error instanceof KnockoutWorkspaceError &&
          [
            KNOCKOUT_WORKSPACE_ERROR_CODES.OPERATION_DEADLINE_EXCEEDED,
            KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
            KNOCKOUT_WORKSPACE_ERROR_CODES.RESOURCE_LIMIT_EXCEEDED,
          ].includes(error.code)
        ) throw error;
        fail(
          KNOCKOUT_WORKSPACE_ERROR_CODES.STANDALONE_GIT_INVALID,
          `standalone Git index changed during ${phase}`,
          { phase },
          error,
        );
      }
    };
    const stageBytes = seedGit(
      ["ls-files", "--stage", "--full-name", "-z"],
      "standalone Git stage listing",
    );
    const resolveUndoBytes = seedGit(
      ["ls-files", "--resolve-undo", "--full-name", "-z"],
      "standalone Git resolve-undo listing",
    );
    const observedStatusConfig = gitStatusConfig(Object.fromEntries(
      GIT_STATUS_CONFIG_KEYS.map((key) => {
        const value = oneLine(
          seedGit(
            ["config", "--local", "--type=bool", "--get", key],
            `standalone Git ${key} config`,
          ),
          `standalone Git ${key} config`,
        );
        if (value !== "true" && value !== "false") {
          invalid(`standalone Git ${key} config is not canonical`, { key, value });
        }
        return [key, value === "true"];
      }),
    ));
    if (!canonicalJsonBytes(observedStatusConfig).equals(canonicalJsonBytes(expectedGit.statusConfig))) {
      invalid("standalone Git status configuration differs from the source observation", {
        expected: expectedGit.statusConfig,
        observed: observedStatusConfig,
      });
    }
    const statusBytes = seedGit(
      ["status", "--porcelain=v2", "-z", "--untracked-files=all", "--ignored=matching"],
      "standalone Git status listing",
    );
    assertLiveIndex("standalone semantic validation");
    const stages = parseIndexEntries(stageBytes, expectedGit.objectFormat, "standalone index");
    const resolveUndo = parseIndexEntries(
      resolveUndoBytes,
      expectedGit.objectFormat,
      "standalone resolve-undo",
    );
    const objectIds = [...new Set([...stages, ...resolveUndo].map((entry) => entry.objectId))].sort();
    if (
      sha256(stageBytes) !== expectedGit.indexStageSha256 ||
      !canonicalJsonBytes(resolveUndo).equals(canonicalJsonBytes(expectedGit.resolveUndo)) ||
      !canonicalJsonBytes(objectIds).equals(canonicalJsonBytes(expectedGit.objectIds))
    ) {
      invalid("standalone index semantics differ from the source observation", {
        expectedStage: expectedGit.indexStageSha256,
        observedStage: sha256(stageBytes),
      });
    }
    for (const objectId of expectedGit.objectIds) {
      seedGit(["cat-file", "-e", `${objectId}^{blob}`], `standalone Git object ${objectId}`);
    }
    assertLiveIndex("standalone object validation");
    seedGit(["fsck", "--full", "--strict", "--no-reflogs"], "standalone Git fsck validation");
    const indexAfter = assertLiveIndex("standalone fsck validation");
    if (boundEntryStat(gitBound, "index.lock", "standalone index lock", {
      code: KNOCKOUT_WORKSPACE_ERROR_CODES.STANDALONE_GIT_INVALID,
      operationBudget,
    }) !== null) invalid("standalone Git validation left an index lock");
    return freezeWithRetainedPrivateRoots({
      commonDirectory,
      gitDirectory,
      head,
      headRef,
      headTree,
      indexMode: indexAfter.observation.mode,
      indexSha256: indexAfter.sha256,
      indexStageBytes: stageBytes.length,
      indexStageSha256: sha256(stageBytes),
      intentToAddPaths: parseIntentToAdd(statusBytes),
      objectFormat,
      sharedIndexSha256: null,
      statusBytes: statusBytes.length,
      statusConfig: observedStatusConfig,
      statusFieldCount: nulFields(statusBytes).length,
      statusSha256: sha256(statusBytes),
    }, []);
  } catch (error) {
    primaryError = error;
    throw error;
  } finally {
    releaseLease.release(primaryError);
  }
}
function worktreeProjectionOfSeed(seedCensus) {
  return Object.freeze({
    nodes: Object.freeze(seedCensus.nodes.filter((node) =>
      node.path !== ".git" && !node.path.startsWith(".git/"))),
  });
}

function verifySealedSeedDescriptor(descriptor, options = {}) {
  const commandTimeoutMs = requireCommandTimeoutMs(
    options.commandTimeoutMs ?? MAX_CHILD_PROCESS_DURATION_MS,
  );
  const operationBudget = options.operationBudget ?? createOperationBudget(commandTimeoutMs);
  remainingOperationMs(operationBudget, "sealed-seed verifier admission");
  if (
    descriptor === null || typeof descriptor !== "object" ||
    !HASH_64.test(descriptor.candidateManifestSha256 ?? "") ||
    !HASH_64.test(descriptor.manifestFileSha256 ?? "") ||
    !HASH_64.test(descriptor.sourceSnapshotSha256 ?? "") ||
    descriptor.seedObservation === null || typeof descriptor.seedObservation !== "object" ||
    !Array.isArray(descriptor.seedObservation.nodes) ||
    !HASH_64.test(descriptor.seedObservation.observationSha256 ?? "") ||
    typeof descriptor.custodyIdentity !== "string" ||
    typeof descriptor.seedIdentity !== "string" ||
    typeof descriptor.workspaceIdentity !== "string" ||
    typeof descriptor.evidenceIdentity !== "string" ||
    !validDirectoryObservation(descriptor.seedRootObservation) ||
    !validFileObservation(descriptor.manifestObservation) ||
    (descriptor.metadataCache !== undefined &&
      !metadataObservationCacheStates.has(descriptor.metadataCache))
  ) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "sealed capture capability is malformed");
  }
  // State evidence is absent only for the producer's own pre-publication verification passes.
  // A registered capability always carries it (verifySealedSeed refuses one that does not), and
  // when present all three fields must be present and well formed.
  const stateEvidencePresent = descriptor.statePath !== undefined ||
    descriptor.stateFileSha256 !== undefined || descriptor.stateObservation !== undefined;
  if (
    stateEvidencePresent &&
    (typeof descriptor.statePath !== "string" ||
      !HASH_64.test(descriptor.stateFileSha256 ?? "") ||
      !validFileObservation(descriptor.stateObservation))
  ) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "sealed capture capability is malformed");
  }
  const workspaceRoot = requireAbsolutePath(descriptor.workspaceRoot, "sealed seed workspace");
  const custodyRoot = requireAbsolutePath(descriptor.custodyRoot, "sealed custody root");
  const seedRoot = requireAbsolutePath(descriptor.seedRoot, "sealed seed root");
  const evidenceRoot = requireAbsolutePath(descriptor.evidenceRoot, "sealed evidence root");
  const manifestPath = requireAbsolutePath(descriptor.manifestPath, "candidate-manifest path");
  const statePath = stateEvidencePresent
    ? requireAbsolutePath(descriptor.statePath, "capture state path")
    : null;
  if (manifestPath !== path.join(evidenceRoot, "candidate-manifest.json")) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
      "candidate-manifest path is no longer the exact evidence child",
    );
  }
  if (statePath !== null && statePath !== path.join(evidenceRoot, "state.json")) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
      "capture state path is no longer the exact evidence child",
    );
  }
  if (
    path.dirname(seedRoot) !== custodyRoot ||
    workspaceRoot !== path.join(seedRoot, "workspace") ||
    evidenceRoot !== path.join(seedRoot, "evidence")
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
      "sealed capture directory topology no longer matches its capability",
    );
  }
  const workspaceDirectory = requireRealDirectory(
    workspaceRoot,
    "sealed seed workspace",
    { expectedIdentity: descriptor.workspaceIdentity, operationBudget, privateMode: true },
  );
  const custodyDirectory = requireRealDirectory(
    custodyRoot,
    "sealed custody root",
    { expectedIdentity: descriptor.custodyIdentity, operationBudget, privateMode: true },
  );
  const seedDirectory = requireRealDirectory(
    seedRoot,
    "sealed seed root",
    { expectedIdentity: descriptor.seedIdentity, operationBudget, privateMode: true },
  );
  const evidenceDirectory = requireRealDirectory(
    evidenceRoot,
    "sealed evidence root",
    { expectedIdentity: descriptor.evidenceIdentity, operationBudget, privateMode: true },
  );
  if (
    custodyDirectory.path !== custodyRoot || seedDirectory.path !== seedRoot ||
    workspaceDirectory.path !== workspaceRoot ||
    evidenceDirectory.path !== evidenceRoot ||
    custodyDirectory.identity !== descriptor.custodyIdentity ||
    seedDirectory.identity !== descriptor.seedIdentity ||
    workspaceDirectory.identity !== descriptor.workspaceIdentity ||
    evidenceDirectory.identity !== descriptor.evidenceIdentity
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
      "sealed capture directory identity changed before verification",
    );
  }
  if (!sameDirectoryObservation(seedDirectory.observation, descriptor.seedRootObservation)) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.MANIFEST_MISMATCH,
      "sealed seed-root observation changed before verification",
      {
        expected: descriptor.seedRootObservation,
        observed: seedDirectory.observation,
        path: seedDirectory.path,
      },
    );
  }
  // Persisted state is required integrity evidence for this use, never sufficient authority: it
  // must be the exact inode and bytes the capture published, and it must bind this very capture.
  if (statePath !== null) {
    reopenCaptureStateEvidence(statePath, descriptor, evidenceDirectory, operationBudget);
  }
  let manifestFile;
  try {
    manifestFile = assertPrivateFile(
      manifestPath,
      descriptor.manifestFileSha256,
      descriptor.manifestObservation,
      {
        maxBytes: MAX_CANDIDATE_MANIFEST_BYTES,
        metadataAnchor: evidenceDirectory,
        mismatchCode: KNOCKOUT_WORKSPACE_ERROR_CODES.MANIFEST_MISMATCH,
        operationBudget,
      },
    );
  } catch (error) {
    if (
      error instanceof KnockoutWorkspaceError &&
      [
        KNOCKOUT_WORKSPACE_ERROR_CODES.OPERATION_DEADLINE_EXCEEDED,
        KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
        KNOCKOUT_WORKSPACE_ERROR_CODES.RESOURCE_LIMIT_EXCEEDED,
      ].includes(error.code)
    ) throw error;
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.MANIFEST_MISMATCH,
      "candidate manifest file does not match its sealed capture capability",
      null,
      error,
    );
  }
  let manifestSnapshot;
  try {
    manifestSnapshot = deepFreezeJson(JSON.parse(manifestFile.bytes.toString("utf8")));
  } catch (error) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.MANIFEST_MISMATCH,
      "candidate manifest is not JSON",
      null,
      error,
    );
  }
  if (
    manifestSnapshot === null || typeof manifestSnapshot !== "object" ||
    Array.isArray(manifestSnapshot) ||
    manifestSnapshot.protocol !== KNOCKOUT_WORKSPACE_PROTOCOLS.candidateManifest ||
    !HASH_64.test(manifestSnapshot.candidateManifestSha256 ?? "") ||
    manifestSnapshot.candidateManifestSha256 !== descriptor.candidateManifestSha256 ||
    candidateManifestSha256FromSnapshot(manifestSnapshot) !==
      manifestSnapshot.candidateManifestSha256 ||
    !canonicalJsonBytes(manifestSnapshot).equals(manifestFile.bytes) ||
    !hasExactObjectKeys(manifestSnapshot.copy, [
      "privateDirectoryMode", "privateExecutableFileMode", "privateFileMode", "strategy",
    ]) ||
    manifestSnapshot.copy.privateDirectoryMode !== 0o700 ||
    manifestSnapshot.copy.privateExecutableFileMode !== 0o700 ||
    manifestSnapshot.copy.privateFileMode !== 0o600 ||
    manifestSnapshot.copy.strategy !==
      "descriptor-byte-copy-with-attested-root-local-omission" ||
    manifestSnapshot.seed === null || typeof manifestSnapshot.seed !== "object" ||
    manifestSnapshot.seed.includesStandaloneGit !== true ||
    manifestSnapshot.seed.git === null || typeof manifestSnapshot.seed.git !== "object" ||
    !Number.isSafeInteger(manifestSnapshot.seed.nodeCount) ||
      manifestSnapshot.seed.nodeCount < 1 ||
    !HASH_64.test(manifestSnapshot.seed.observationSha256 ?? "") ||
    !HASH_64.test(manifestSnapshot.seed.workspaceMaterialSha256 ?? "") ||
    manifestSnapshot.resourceAdmission === null ||
    typeof manifestSnapshot.resourceAdmission !== "object" ||
    Array.isArray(manifestSnapshot.resourceAdmission) ||
    manifestSnapshot.resourceAdmission.policy !==
      "shared-prewrite-projection-plus-postwrite-exact-census-plus-fixed-reserve" ||
    !Number.isSafeInteger(manifestSnapshot.resourceAdmission.operationDeadlineMs) ||
    manifestSnapshot.resourceAdmission.operationDeadlineMs < 1 ||
    manifestSnapshot.resourceAdmission.operationDeadlineMs >
      MAX_CAPTURE_OPERATION_DURATION_MS ||
    !Number.isSafeInteger(manifestSnapshot.resourceAdmission.childCommandTimeoutMs) ||
    manifestSnapshot.resourceAdmission.childCommandTimeoutMs < 1 ||
    manifestSnapshot.resourceAdmission.childCommandTimeoutMs > MAX_CHILD_PROCESS_DURATION_MS ||
    manifestSnapshot.resourceAdmission.childCommandTimeoutMs >
      manifestSnapshot.resourceAdmission.operationDeadlineMs
  ) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.MANIFEST_MISMATCH, "candidate manifest is malformed");
  }
  let limits;
  try { limits = normalizeCaptureLimits(manifestSnapshot.resourceAdmission.limits); }
  catch (error) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.MANIFEST_MISMATCH,
      "candidate manifest carries malformed resource limits",
      null,
      error,
    );
  }
  const metadataCache = options.metadataCache ?? descriptor.metadataCache ??
    createMetadataObservationCache(limits.maxNodes);
  if (!metadataObservationCacheStates.has(metadataCache)) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "metadata observation cache is malformed");
  }
  const validAdmission = (value) => (
    value !== null && typeof value === "object" && !Array.isArray(value) &&
    Number.isSafeInteger(value.allocatedBytes) && value.allocatedBytes >= 0 &&
      value.allocatedBytes <= limits.maxAllocatedBytes &&
    Number.isSafeInteger(value.logicalBytes) && value.logicalBytes >= 0 &&
      value.logicalBytes <= limits.maxTotalBytes &&
    Number.isSafeInteger(value.maxDepth) && value.maxDepth >= 0 && value.maxDepth <= limits.maxDepth &&
    Number.isSafeInteger(value.nodeCount) && value.nodeCount >= 1 && value.nodeCount <= limits.maxNodes
  );
  const admittedSeed = manifestSnapshot.resourceAdmission.seed;
  const admittedSource = manifestSnapshot.resourceAdmission.source;
  const admittedProjection = manifestSnapshot.resourceAdmission.prewriteProjection;
  const sourceEvidence = workspaceEvidenceFromNodes(
    manifestSnapshot.source?.nodes,
    limits,
    { forbidRootGit: true, operationBudget },
  );
  if (
    !validAdmission(admittedSeed) || !validAdmission(admittedSource) ||
    !validAdmission(admittedProjection) ||
    sourceEvidence === null ||
    manifestSnapshot.source === null || typeof manifestSnapshot.source !== "object" ||
    Array.isArray(manifestSnapshot.source) ||
    manifestSnapshot.source.git === null || typeof manifestSnapshot.source.git !== "object" ||
    Array.isArray(manifestSnapshot.source.git) ||
    !Number.isSafeInteger(manifestSnapshot.source.nodeCount) ||
    manifestSnapshot.source.nodeCount < 1 ||
    !HASH_64.test(manifestSnapshot.source.snapshotSha256 ?? "") ||
    !HASH_64.test(manifestSnapshot.source.workspaceMaterialSha256 ?? "") ||
    !HASH_64.test(manifestSnapshot.source.workspaceObservationSha256 ?? "") ||
    admittedSeed.nodeCount !== manifestSnapshot.seed.nodeCount ||
    admittedSource.nodeCount !== manifestSnapshot.source.nodeCount ||
    admittedSource.allocatedBytes !== sourceEvidence.allocatedBytes ||
    admittedSource.logicalBytes !== sourceEvidence.logicalBytes ||
    admittedSource.maxDepth !== sourceEvidence.maxDepth ||
    admittedSource.nodeCount !== sourceEvidence.nodeCount ||
    manifestSnapshot.source.workspaceMaterialSha256 !== sourceEvidence.materialSha256 ||
    manifestSnapshot.source.workspaceObservationSha256 !== sourceEvidence.observationSha256 ||
    admittedProjection.allocatedBytes < admittedSeed.allocatedBytes ||
    admittedProjection.logicalBytes < admittedSeed.logicalBytes ||
    admittedProjection.maxDepth < admittedSeed.maxDepth ||
    admittedProjection.nodeCount < admittedSeed.nodeCount ||
    admittedProjection.allocatedBytes < admittedSource.allocatedBytes ||
    admittedProjection.logicalBytes < admittedSource.logicalBytes ||
    admittedProjection.maxDepth < admittedSource.maxDepth ||
    admittedProjection.nodeCount < admittedSource.nodeCount
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.MANIFEST_MISMATCH,
      "candidate manifest carries inconsistent resource admission evidence",
    );
  }
  // The manifest must name exactly one physical source root: the Git observation's bound identity
  // and observation, and the census root node it was composed with, must agree.
  const manifestSourceGit = manifestSnapshot.source.git;
  const manifestSourceRoot = manifestSnapshot.source.nodes.find((node) => node.path === ".");
  if (
    typeof manifestSourceGit.worktreeRoot !== "string" ||
    !path.isAbsolute(manifestSourceGit.worktreeRoot) ||
    typeof manifestSourceGit.worktreeRootIdentity !== "string" ||
    typeof manifestSourceGit.gitDirectoryIdentity !== "string" ||
    manifestSourceGit.gitDirectoryIdentity.length === 0 ||
    typeof manifestSourceGit.commonDirectoryIdentity !== "string" ||
    manifestSourceGit.commonDirectoryIdentity.length === 0 ||
    !validDirectoryObservation(manifestSourceGit.worktreeRootObservation) ||
    manifestSourceGit.worktreeRootObservation.identity !== manifestSourceGit.worktreeRootIdentity ||
    manifestSourceRoot === undefined || manifestSourceRoot.type !== "directory" ||
    !sameDirectoryObservation(
      manifestSourceRoot.observation,
      manifestSourceGit.worktreeRootObservation,
    )
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.MANIFEST_MISMATCH,
      "candidate manifest does not bind one physical source root",
    );
  }
  const sourceWorkspace = Object.freeze({
    allocatedBytes: admittedSource.allocatedBytes,
    limits,
    logicalBytes: admittedSource.logicalBytes,
    materialSha256: sourceEvidence.materialSha256,
    maxDepth: admittedSource.maxDepth,
    nodeCount: sourceEvidence.nodeCount,
    nodes: manifestSnapshot.source.nodes,
    observationSha256: sourceEvidence.observationSha256,
    provenancePolicy: Object.freeze({
      allowedName: PROVENANCE_XATTR,
      classification: PROVENANCE_CLASSIFICATION,
      copiedOrMutatedByWorkspace: false,
    }),
    root: manifestSnapshot.source.git.worktreeRoot,
  });
  let portableSourceWorkspace;
  try {
    const projectionProblem = validateRootLocalStateProjection(
      manifestSnapshot.rootLocalStateProjection,
      sourceWorkspace,
      manifestSourceGit.worktreeRootIdentity,
    );
    if (projectionProblem !== null) {
      fail(KNOCKOUT_WORKSPACE_ERROR_CODES.MANIFEST_MISMATCH, projectionProblem);
    }
    portableSourceWorkspace = portableSourceCensus(
      sourceWorkspace,
      manifestSnapshot.rootLocalStateProjection,
      operationBudget,
    );
  } catch (error) {
    if (
      error instanceof KnockoutWorkspaceError &&
      error.code === KNOCKOUT_WORKSPACE_ERROR_CODES.OPERATION_DEADLINE_EXCEEDED
    ) throw error;
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.MANIFEST_MISMATCH,
      "candidate manifest carries an invalid root-local state projection",
      null,
      error,
    );
  }
  const reconstructedSourceSnapshotSha256 = sha256(canonicalJsonBytes(Object.freeze({
    git: manifestSnapshot.source.git,
    workspace: sourceWorkspace,
  })));
  if (
    reconstructedSourceSnapshotSha256 !== manifestSnapshot.source.snapshotSha256 ||
    reconstructedSourceSnapshotSha256 !== descriptor.sourceSnapshotSha256
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.MANIFEST_MISMATCH,
      "candidate manifest source provenance does not match the captured source snapshot",
      {
        captured: descriptor.sourceSnapshotSha256,
        manifest: manifestSnapshot.source.snapshotSha256,
        reconstructed: reconstructedSourceSnapshotSha256,
      },
    );
  }
  const observed = censusWorkspace(workspaceDirectory.path, {
    expectedRoot: Object.freeze({
      identity: workspaceDirectory.identity,
      path: workspaceDirectory.path,
    }),
    limits,
    metadataCache,
    operationBudget,
    rootGitPolicy: "include",
  });
  const expectedNodes = descriptor.seedObservation.nodes;
  const changedNodeIndex = expectedNodes.findIndex((node, index) =>
    index >= observed.nodes.length ||
    !canonicalJsonBytes(node).equals(canonicalJsonBytes(observed.nodes[index])));
  if (
    observed.nodeCount !== manifestSnapshot.seed.nodeCount ||
    observed.materialSha256 !== manifestSnapshot.seed.workspaceMaterialSha256 ||
    observed.observationSha256 !== manifestSnapshot.seed.observationSha256 ||
    admittedSeed.allocatedBytes !== observed.allocatedBytes ||
    admittedSeed.logicalBytes !== observed.logicalBytes ||
    admittedSeed.maxDepth !== observed.maxDepth ||
    admittedSeed.nodeCount !== observed.nodeCount
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.MANIFEST_MISMATCH,
      "sealed seed differs from its candidate manifest",
      {
        expectedMaterial: manifestSnapshot.seed.workspaceMaterialSha256,
        expectedNodes: manifestSnapshot.seed.nodeCount,
        expectedObservation: manifestSnapshot.seed.observationSha256,
        observedMaterial: observed.materialSha256,
        observedNodes: observed.nodeCount,
        observedObservation: observed.observationSha256,
        changedNode: changedNodeIndex < 0 ? null : Object.freeze({
          after: observed.nodes[changedNodeIndex] ?? null,
          before: expectedNodes[changedNodeIndex],
        }),
      },
    );
  }
  if (!copiedWorktreeEquivalent(
    portableSourceWorkspace,
    worktreeProjectionOfSeed(observed),
  )) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.MANIFEST_MISMATCH,
      "sealed seed worktree projection differs from captured source material",
    );
  }
  let validatedGit;
  try {
    validatedGit = validateStandaloneGit(
      workspaceDirectory.path,
      manifestSnapshot.source.git,
      {
        commandTimeoutMs,
        expectedIndex: Object.freeze({ sha256: manifestSnapshot.seed.git.indexSha256 }),
        gitExecutable: options.gitExecutable ?? null,
        limits,
        operationBudget,
      },
    );
  } catch (error) {
    if (
      error instanceof KnockoutWorkspaceError &&
      [
        KNOCKOUT_WORKSPACE_ERROR_CODES.OPERATION_DEADLINE_EXCEEDED,
        KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
        KNOCKOUT_WORKSPACE_ERROR_CODES.RESOURCE_LIMIT_EXCEEDED,
      ].includes(error.code)
    ) throw error;
    throw reportRetainedPrivateRoots(
      workspaceError(
        KNOCKOUT_WORKSPACE_ERROR_CODES.MANIFEST_MISMATCH,
        "sealed seed Git does not match captured source Git semantics",
        null,
        error,
      ),
      retainedPrivateRoots(error?.details),
    );
  }
  // Witness for the Git validation: Git read the seed relative to its bound descriptor, and no
  // seed node may have changed while it did. The census taken before validation and this one
  // must be identical; a same-UID substitution around any child changes a ctime the census holds.
  const observedAfterValidation = censusWorkspace(workspaceDirectory.path, {
    expectedRoot: Object.freeze({
      identity: workspaceDirectory.identity,
      path: workspaceDirectory.path,
    }),
    limits,
    metadataCache,
    operationBudget,
    rootGitPolicy: "include",
  });
  if (
    observedAfterValidation.nodeCount !== observed.nodeCount ||
    observedAfterValidation.materialSha256 !== observed.materialSha256 ||
    observedAfterValidation.observationSha256 !== observed.observationSha256
  ) {
    const changedNodeIndex = observed.nodes.findIndex((node, index) =>
      index >= observedAfterValidation.nodes.length ||
      !canonicalJsonBytes(node).equals(canonicalJsonBytes(observedAfterValidation.nodes[index])));
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.MANIFEST_MISMATCH,
      "sealed seed changed during standalone Git validation",
      {
        changedNode: changedNodeIndex < 0 ? null : Object.freeze({
          after: observedAfterValidation.nodes[changedNodeIndex] ?? null,
          before: observed.nodes[changedNodeIndex],
        }),
        expectedObservation: observed.observationSha256,
        observedObservation: observedAfterValidation.observationSha256,
      },
    );
  }
  const validationRoots = retainedPrivateRoots(validatedGit);
  try {
    if (!canonicalJsonBytes({ ...validatedGit }).equals(canonicalJsonBytes(manifestSnapshot.seed.git))) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.MANIFEST_MISMATCH,
        "sealed seed Git evidence differs from independently validated Git state",
      );
    }
    assertPrivateDirectoryIdentity(
      Object.freeze({ identity: descriptor.custodyIdentity, path: custodyDirectory.path }),
      "sealed custody root",
      operationBudget,
    );
    assertPrivateDirectoryIdentity(
      Object.freeze({ identity: descriptor.seedIdentity, path: seedDirectory.path }),
      "sealed seed root",
      operationBudget,
    );
    assertPrivateDirectoryIdentity(
      Object.freeze({ identity: descriptor.workspaceIdentity, path: workspaceDirectory.path }),
      "sealed seed workspace",
      operationBudget,
    );
    assertPrivateDirectoryIdentity(
      Object.freeze({ identity: descriptor.evidenceIdentity, path: evidenceDirectory.path }),
      "sealed evidence root",
      operationBudget,
    );
    assertPrivateFile(
      manifestPath,
      descriptor.manifestFileSha256,
      descriptor.manifestObservation,
      {
        maxBytes: MAX_CANDIDATE_MANIFEST_BYTES,
        metadataAnchor: evidenceDirectory,
        mismatchCode: KNOCKOUT_WORKSPACE_ERROR_CODES.MANIFEST_MISMATCH,
        operationBudget,
      },
    );
    if (statePath !== null) {
      reopenCaptureStateEvidence(statePath, descriptor, evidenceDirectory, operationBudget);
    }
    return freezeWithRetainedPrivateRoots(
      { ...observed },
      validationRoots,
    );
  } catch (error) {
    throw reportRetainedPrivateRoots(error, validationRoots);
  }
}

function reopenCaptureStateEvidence(statePath, descriptor, evidenceDirectory, operationBudget) {
  let stateFile;
  try {
    stateFile = assertPrivateFile(
      statePath,
      descriptor.stateFileSha256,
      descriptor.stateObservation,
      {
        maxBytes: MAX_STATE_BYTES,
        metadataAnchor: evidenceDirectory,
        mismatchCode: KNOCKOUT_WORKSPACE_ERROR_CODES.MANIFEST_MISMATCH,
        operationBudget,
      },
    );
  } catch (error) {
    if (
      error instanceof KnockoutWorkspaceError &&
      [
        KNOCKOUT_WORKSPACE_ERROR_CODES.OPERATION_DEADLINE_EXCEEDED,
        KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
        KNOCKOUT_WORKSPACE_ERROR_CODES.RESOURCE_LIMIT_EXCEEDED,
      ].includes(error.code)
    ) throw error;
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.MANIFEST_MISMATCH,
      "capture state evidence does not match its capture capability",
      null,
      error,
    );
  }
  let state;
  try { state = deepFreezeJson(JSON.parse(stateFile.bytes.toString("utf8"))); }
  catch (error) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.MANIFEST_MISMATCH, "capture state evidence is not JSON", null, error);
  }
  if (
    state === null || typeof state !== "object" || Array.isArray(state) ||
    state.protocol !== KNOCKOUT_WORKSPACE_PROTOCOLS.state ||
    state.status !== KNOCKOUT_WORKSPACE_CAPTURE_STATUS ||
    state.evidenceRole !== KNOCKOUT_WORKSPACE_STATE_EVIDENCE_ROLE ||
    state.candidateManifestSha256 !== descriptor.candidateManifestSha256 ||
    state.candidateManifestFileSha256 !== descriptor.manifestFileSha256 ||
    state.seedObservationSha256 !== descriptor.seedObservation.observationSha256 ||
    state.sourceSnapshotSha256 !== descriptor.sourceSnapshotSha256 ||
    state.workspace !== "../workspace" ||
    !canonicalJsonBytes(state).equals(stateFile.bytes)
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.MANIFEST_MISMATCH,
      "capture state evidence is malformed or does not bind this capture",
    );
  }
  return stateFile;
}

export function verifySealedSeed(captureCapability, options = {}) {
  const descriptor = sealedCaptureCapabilities.get(captureCapability);
  if (descriptor === undefined) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
      "verifySealedSeed requires the exact same-process capture capability",
    );
  }
  // A registered capability always binds its persisted state evidence; every use revalidates
  // state, manifest and seed against this same-process descriptor, never against disk alone.
  if (typeof descriptor.statePath !== "string") {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
      "registered capture capability lacks its state evidence binding",
    );
  }
  return verifySealedSeedDescriptor(descriptor, options);
}

function sameWorkspaceCensus(left, right) {
  return (
    left !== null && right !== null &&
    left.nodeCount === right.nodeCount &&
    left.allocatedBytes === right.allocatedBytes &&
    left.logicalBytes === right.logicalBytes &&
    left.maxDepth === right.maxDepth &&
    left.materialSha256 === right.materialSha256 &&
    left.observationSha256 === right.observationSha256 &&
    canonicalJsonBytes(left.nodes).equals(canonicalJsonBytes(right.nodes))
  );
}

function observeExactLeaseSeed(leaseState, operationBudget, label) {
  let observed;
  try {
    observed = censusWorkspace(leaseState.workspaceBound.path, {
      expectedRoot: Object.freeze({
        identity: leaseState.workspaceBound.identity,
        path: leaseState.workspaceBound.path,
      }),
      expectedRootCode: KNOCKOUT_WORKSPACE_ERROR_CODES.ARM_IDENTITY_MISMATCH,
      limits: leaseState.custodyState.limits,
      metadataCache: leaseState.custodyState.metadataCache,
      operationBudget,
      rootGitPolicy: "include",
    });
  } catch (error) {
    if (
      error instanceof KnockoutWorkspaceError &&
      error.code === KNOCKOUT_WORKSPACE_ERROR_CODES.OPERATION_DEADLINE_EXCEEDED
    ) throw error;
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.ARM_IDENTITY_MISMATCH,
      `sealed seed could not be re-observed ${label}`,
      { sourceCode: error?.code ?? null },
      error,
    );
  }
  if (!sameWorkspaceCensus(observed, leaseState.custodyState.seedCensus)) {
    const expectedNodes = leaseState.custodyState.seedCensus.nodes;
    const changedNodeIndex = expectedNodes.findIndex((node, index) =>
      index >= observed.nodes.length ||
      !canonicalJsonBytes(node).equals(canonicalJsonBytes(observed.nodes[index])));
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.ARM_IDENTITY_MISMATCH,
      `sealed seed changed ${label}`,
      {
        changedNode: changedNodeIndex < 0 ? null : Object.freeze({
          after: observed.nodes[changedNodeIndex] ?? null,
          before: expectedNodes[changedNodeIndex],
        }),
        expectedObservation: leaseState.custodyState.seedCensus.observationSha256,
        observedObservation: observed.observationSha256,
      },
    );
  }
  return observed;
}

function armMaterializationCharge(seedCensus, allocationUnitBytes) {
  if (
    seedCensus === null || typeof seedCensus !== "object" || !Array.isArray(seedCensus.nodes) ||
    !Number.isSafeInteger(allocationUnitBytes) || allocationUnitBytes < 1
  ) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "arm materialization geometry is malformed");
  }
  const unit = BigInt(allocationUnitBytes);
  const rounded = (bytes) => {
    const value = BigInt(bytes);
    return value === 0n ? 0n : ((value + unit - 1n) / unit) * unit;
  };
  // One allocation unit per copied node covers directory-entry/metadata growth. Three additional
  // units cover the retained run, arm and evidence directories. File payloads are then charged as
  // dense copies, never at the possibly-sparse source allocation, and hardlinked payloads once.
  let projected = BigInt(seedCensus.nodes.length + 3) * unit +
    rounded(ARM_EVIDENCE_RESERVE_BYTES);
  const chargedFiles = new Set();
  for (const node of seedCensus.nodes) {
    if (node.type === "file") {
      const key = node.hardlinkGroup ?? `identity:${node.observation.identity}`;
      if (chargedFiles.has(key)) continue;
      chargedFiles.add(key);
      projected += rounded(Math.max(node.size, node.observation.allocatedBytes));
    } else if (node.type === "symlink") {
      projected += rounded(Buffer.byteLength(node.target, "utf8"));
    }
    if (projected > BigInt(Number.MAX_SAFE_INTEGER)) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.RESOURCE_LIMIT_EXCEEDED,
        "arm materialization reservation exceeds safe integer bounds",
      );
    }
  }
  return Number(projected);
}

function armCapacityProjection(custodyState, additionalArms, operationBudget) {
  if (!Number.isSafeInteger(additionalArms) || additionalArms < 1) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "arm reservation count is malformed");
  }
  const capacity = filesystemCapacity(
    custodyState.captureDescriptor.custodyRoot,
    "knockout arm custody",
    operationBudget,
  );
  const perArmBytes = armMaterializationCharge(
    custodyState.seedCensus,
    capacity.allocationUnitBytes,
  );
  const addedBytesBig = BigInt(perArmBytes) * BigInt(additionalArms);
  const projectedBytesBig = BigInt(custodyState.reservedBytes) + addedBytesBig;
  const projectedArms = custodyState.reservedArms + additionalArms;
  if (
    projectedBytesBig > BigInt(Number.MAX_SAFE_INTEGER) ||
    !Number.isSafeInteger(projectedArms) ||
    projectedArms > custodyState.retentionLimits.maxRetainedArms ||
    projectedBytesBig > BigInt(custodyState.retentionLimits.maxRetainedBytes)
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.RESOURCE_LIMIT_EXCEEDED,
      "arm plan exceeds the cumulative retained-arm admission",
      {
        maxRetainedArms: custodyState.retentionLimits.maxRetainedArms,
        maxRetainedBytes: custodyState.retentionLimits.maxRetainedBytes,
        projectedArms,
        projectedBytes: String(projectedBytesBig),
      },
    );
  }
  const projectedBytes = Number(projectedBytesBig);
  const outstandingBytes = projectedBytes - custodyState.consumedReservationBytes;
  if (!Number.isSafeInteger(outstandingBytes) || outstandingBytes < 0) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID, "arm reservation ledger is inconsistent");
  }
  const requiredBytes = BigInt(outstandingBytes) + BigInt(custodyState.limits.minFreeBytes);
  if (capacity.availableBytes < requiredBytes) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.RESOURCE_LIMIT_EXCEEDED,
      "knockout custody lacks capacity for all outstanding admitted arms plus the fixed reserve",
      {
        availableBytes: String(capacity.availableBytes),
        outstandingBytes,
        requiredBytes: String(requiredBytes),
      },
    );
  }
  return Object.freeze({
    allocationUnitBytes: capacity.allocationUnitBytes,
    perArmBytes,
    projectedArms,
    projectedBytes,
  });
}

function requireActiveSourceLease(sourceLease) {
  const leaseState = sourceLeaseStates.get(sourceLease);
  if (leaseState === undefined || leaseState.status !== "ACTIVE") {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
      "operation requires the exact active same-process source lease capability",
    );
  }
  return leaseState;
}

function confirmLeaseBoundaries(leaseState, operationBudget) {
  confirmBoundDirectoryIdentity(
    leaseState.custodyBound,
    "knockout custody root",
    KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
    operationBudget,
    { privateMode: true },
  );
  confirmBoundDirectory(
    leaseState.sourceBound,
    "leased source root",
    KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED,
    operationBudget,
  );
  confirmBoundDirectory(
    leaseState.seedRootBound,
    "leased seed root",
    KNOCKOUT_WORKSPACE_ERROR_CODES.ARM_IDENTITY_MISMATCH,
    operationBudget,
  );
  confirmBoundDirectory(
    leaseState.workspaceBound,
    "leased seed workspace",
    KNOCKOUT_WORKSPACE_ERROR_CODES.ARM_IDENTITY_MISMATCH,
    operationBudget,
  );
  confirmBoundDirectory(
    leaseState.evidenceBound,
    "leased seed evidence",
    KNOCKOUT_WORKSPACE_ERROR_CODES.ARM_IDENTITY_MISMATCH,
    operationBudget,
  );
  const captureDescriptor = leaseState.custodyState.captureDescriptor;
  const evidenceDirectory = Object.freeze({
    identity: leaseState.evidenceBound.identity,
    observation: leaseState.evidenceBound.observation,
    path: leaseState.evidenceBound.path,
  });
  sealedManifest(
    evidenceDirectory.path,
    captureDescriptor.candidateManifestSha256,
    captureDescriptor.manifestFileSha256,
    captureDescriptor.manifestObservation,
    evidenceDirectory.identity,
    operationBudget,
  );
  reopenCaptureStateEvidence(
    captureDescriptor.statePath,
    captureDescriptor,
    evidenceDirectory,
    operationBudget,
  );
  if (leaseState.runBound !== null) {
    confirmBoundDirectoryIdentity(
      leaseState.runBound,
      "knockout run root",
      KNOCKOUT_WORKSPACE_ERROR_CODES.ARM_IDENTITY_MISMATCH,
      operationBudget,
      { privateMode: true },
    );
  }
}

/** Open one non-reconstructible, one-shot arm lifecycle from an exact capture capability. */
export function openKnockoutCustody(captureCapability, options = {}) {
  const captureDescriptor = sealedCaptureCapabilities.get(captureCapability);
  if (captureDescriptor === undefined) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
      "openKnockoutCustody requires the exact same-process capture capability",
    );
  }
  if (captureCustodyOwners.has(captureCapability)) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
      "the capture capability already owns a knockout custody lifecycle",
    );
  }
  const snapshot = strictDataObjectSnapshot(
    options,
    "knockout custody options",
    ["commandTimeoutMs", "gitExecutable", "limits", "maxRetainedArms", "maxRetainedBytes"],
    ["maxRetainedArms", "maxRetainedBytes"],
  );
  const commandTimeoutMs = requireCommandTimeoutMs(
    snapshot.commandTimeoutMs ?? MAX_CHILD_PROCESS_DURATION_MS,
  );
  if (snapshot.gitExecutable !== undefined && snapshot.gitExecutable !== null &&
      typeof snapshot.gitExecutable !== "string") {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "gitExecutable must be a pathname or null");
  }
  const gitExecutable = resolveGitExecutable(snapshot.gitExecutable ?? null);
  const retentionLimits = normalizeArmRetentionLimits(
    snapshot.maxRetainedArms,
    snapshot.maxRetainedBytes,
  );
  const operationBudget = createOperationBudget(commandTimeoutMs);
  const metadataCache = captureDescriptor.metadataCache;
  if (!metadataObservationCacheStates.has(metadataCache)) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
      "registered capture capability lacks its metadata observation cache",
    );
  }
  const seedCensus = verifySealedSeedDescriptor(captureDescriptor, {
    commandTimeoutMs,
    gitExecutable,
    metadataCache,
    operationBudget,
  });
  const limits = normalizeCaptureLimits(snapshot.limits ?? seedCensus.limits);
  const metadataCacheState = metadataObservationCacheStates.get(metadataCache);
  metadataCacheState.maxEntries = Math.max(
    metadataCacheState.maxEntries,
    limits.maxNodes * 4,
  );
  const admittedSeed = workspaceEvidenceFromNodes(seedCensus.nodes, limits, {
    operationBudget,
  });
  if (admittedSeed === null) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.RESOURCE_LIMIT_EXCEEDED,
      "sealed seed exceeds the requested arm limits",
    );
  }
  if (
    captureCapability.sourceSnapshot === null ||
    typeof captureCapability.sourceSnapshot !== "object" ||
    captureCapability.sourceSnapshot.snapshotSha256 !== captureDescriptor.sourceSnapshotSha256 ||
    captureCapability.sourceRootIdentity !==
      captureCapability.sourceSnapshot.git?.worktreeRootIdentity
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
      "capture capability does not expose its bound source provenance",
    );
  }
  const custodyCapability = Object.freeze({
    candidateManifestSha256: captureDescriptor.candidateManifestSha256,
    kind: "KNOCKOUT_CUSTODY",
    maxRetainedArms: retentionLimits.maxRetainedArms,
    maxRetainedBytes: retentionLimits.maxRetainedBytes,
    protocol: KNOCKOUT_WORKSPACE_PROTOCOLS.capability,
    retentionAccountingScope:
      "DETERMINISTIC_INITIAL_ARM_MATERIALIZATION_NOT_PORTABLE_PHYSICAL_USAGE_PROOF",
  });
  const custodyState = {
    activeSourceLease: null,
    activeWorkerTransfer: null,
    allArmRecords: new Map(),
    armCapabilities: new Set(),
    captureCapability,
    captureDescriptor,
    commandTimeoutMs,
    consumedReservationBytes: 0,
    gitExecutable,
    lastPlanSha256: null,
    lastTerminalSha256: null,
    limits,
    metadataCache,
    nextBatch: 1,
    reservedArms: 0,
    reservedBytes: 0,
    retainedRoots: [...retainedPrivateRoots(captureCapability)],
    retentionLimits,
    seedCensus,
    status: "OPEN",
    workerExecutionBlock: null,
  };
  knockoutCustodyStates.set(custodyCapability, custodyState);
  captureCustodyOwners.set(captureCapability, custodyCapability);
  return custodyCapability;
}

/**
 * Bind source/custody/seed descriptors and exclude a second lease in this ESM module instance.
 * This is deliberately not a cross-process advisory-lock claim; the later supervisor/worker slice
 * must close that boundary before any broader exclusivity claim.
 */
export function acquireSourceLease(custodyCapability) {
  const custodyState = knockoutCustodyStates.get(custodyCapability);
  if (
    custodyState === undefined || custodyState.status !== "OPEN" ||
    custodyState.activeSourceLease !== null
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
      "acquireSourceLease requires an unused open knockout custody capability",
    );
  }
  const expectedSource = custodyState.captureCapability.sourceSnapshot;
  const expectedSourceLeaseKey =
    `${expectedSource.git.worktreeRootIdentity}\0${expectedSource.workspace.root}`;
  // Refuse a known collision before a second expensive source observation can create retained
  // scratch. This refusal leaves the second custody unused so it may be acquired after the active
  // lifecycle releases; every acquisition that actually starts verification is otherwise one-shot.
  if (activeModuleSourceLeases.has(expectedSourceLeaseKey)) {
    throw reportRetainedPrivateRoots(
      workspaceError(
        KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
        "the physical source already has an active lease in this module instance",
        { sourceRootIdentity: expectedSource.git.worktreeRootIdentity },
      ),
      custodyState.retainedRoots,
    );
  }
  const operationBudget = createOperationBudget(custodyState.commandTimeoutMs);
  custodyState.status = "ACQUIRING";
  let observedSource;
  try {
    observedSource = verifySourceUnchanged(custodyState.captureCapability.sourceSnapshot, {
      commandTimeoutMs: custodyState.commandTimeoutMs,
      gitExecutable: custodyState.gitExecutable,
      limits: custodyState.limits,
      metadataCache: custodyState.metadataCache,
      operationBudget,
      scratchRoot: custodyState.captureDescriptor.custodyRoot,
    });
    custodyState.retainedRoots.push(...retainedPrivateRoots(observedSource));
  } catch (error) {
    custodyState.status = "FAILED_RETAINED";
    custodyState.retainedRoots.push(...retainedPrivateRoots(error?.details));
    throw reportRetainedPrivateRoots(error, custodyState.retainedRoots);
  }
  const sourceLeaseKey = `${observedSource.git.worktreeRootIdentity}\0${observedSource.workspace.root}`;
  if (activeModuleSourceLeases.has(sourceLeaseKey)) {
    custodyState.status = "FAILED_RETAINED";
    throw reportRetainedPrivateRoots(
      workspaceError(
        KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
        "the physical source already has an active lease in this module instance",
        { sourceRootIdentity: observedSource.git.worktreeRootIdentity },
      ),
      custodyState.retainedRoots,
    );
  }
  let observedSeed;
  try {
    observedSeed = censusWorkspace(custodyState.captureDescriptor.workspaceRoot, {
      expectedRoot: Object.freeze({
        identity: custodyState.captureDescriptor.workspaceIdentity,
        path: custodyState.captureDescriptor.workspaceRoot,
      }),
      expectedRootCode: KNOCKOUT_WORKSPACE_ERROR_CODES.ARM_IDENTITY_MISMATCH,
      limits: custodyState.limits,
      metadataCache: custodyState.metadataCache,
      operationBudget,
      rootGitPolicy: "include",
    });
  } catch (error) {
    custodyState.status = "FAILED_RETAINED";
    if (
      error instanceof KnockoutWorkspaceError &&
      error.code === KNOCKOUT_WORKSPACE_ERROR_CODES.OPERATION_DEADLINE_EXCEEDED
    ) throw reportRetainedPrivateRoots(error, custodyState.retainedRoots);
    throw reportRetainedPrivateRoots(
      workspaceError(
        KNOCKOUT_WORKSPACE_ERROR_CODES.ARM_IDENTITY_MISMATCH,
        "sealed seed could not be re-observed at source-lease acquisition",
        { sourceCode: error?.code ?? null },
        error,
      ),
      custodyState.retainedRoots,
    );
  }
  if (!sameWorkspaceCensus(observedSeed, custodyState.seedCensus)) {
    custodyState.status = "FAILED_RETAINED";
    throw reportRetainedPrivateRoots(
      workspaceError(
        KNOCKOUT_WORKSPACE_ERROR_CODES.ARM_IDENTITY_MISMATCH,
        "sealed seed changed before source-lease acquisition",
        {
          expectedObservation: custodyState.seedCensus.observationSha256,
          observedObservation: observedSeed.observationSha256,
        },
      ),
      custodyState.retainedRoots,
    );
  }

  const releaseLease = createReleaseLease({
    fallbackCode: KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
    message: "source-lease descriptor release",
  });
  let activeRegistered = false;
  try {
    const sourceDirectory = requireRealDirectory(
      observedSource.workspace.root,
      "source-lease source root",
      {
        expectedIdentity: observedSource.git.worktreeRootIdentity,
        expectedIdentityCode: KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED,
        operationBudget,
      },
    );
    if (!sameDirectoryObservation(
      sourceDirectory.observation,
      observedSource.git.worktreeRootObservation,
    )) {
      fail(KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED, "source changed while its lease was acquired");
    }
    const custodyDirectory = requireRealDirectory(
      custodyState.captureDescriptor.custodyRoot,
      "source-lease custody root",
      {
        expectedIdentity: custodyState.captureDescriptor.custodyIdentity,
        expectedIdentityCode: KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
        operationBudget,
        privateMode: true,
      },
    );
    const seedDirectory = requireRealDirectory(
      custodyState.captureDescriptor.seedRoot,
      "source-lease seed root",
      {
        expectedIdentity: custodyState.captureDescriptor.seedIdentity,
        expectedIdentityCode: KNOCKOUT_WORKSPACE_ERROR_CODES.ARM_IDENTITY_MISMATCH,
        operationBudget,
        privateMode: true,
      },
    );
    if (!sameDirectoryObservation(
      seedDirectory.observation,
      custodyState.captureDescriptor.seedRootObservation,
    )) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.ARM_IDENTITY_MISMATCH,
        "seed root changed while its source lease was acquired",
      );
    }
    const workspaceRootNode = observedSeed.nodes.find((node) => node.path === ".");
    if (workspaceRootNode?.type !== "directory") {
      fail(KNOCKOUT_WORKSPACE_ERROR_CODES.ARM_IDENTITY_MISMATCH, "sealed seed has no root witness");
    }
    const workspaceDirectory = requireRealDirectory(
      custodyState.captureDescriptor.workspaceRoot,
      "source-lease seed workspace",
      {
        expectedIdentity: custodyState.captureDescriptor.workspaceIdentity,
        expectedIdentityCode: KNOCKOUT_WORKSPACE_ERROR_CODES.ARM_IDENTITY_MISMATCH,
        operationBudget,
        privateMode: true,
      },
    );
    if (!sameDirectoryObservation(workspaceDirectory.observation, workspaceRootNode.observation)) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.ARM_IDENTITY_MISMATCH,
        "seed workspace changed while its source lease was acquired",
      );
    }
    const evidenceDirectory = requireRealDirectory(
      custodyState.captureDescriptor.evidenceRoot,
      "source-lease seed evidence",
      {
        expectedIdentity: custodyState.captureDescriptor.evidenceIdentity,
        expectedIdentityCode: KNOCKOUT_WORKSPACE_ERROR_CODES.ARM_IDENTITY_MISMATCH,
        operationBudget,
        privateMode: true,
      },
    );
    const sourceBound = releaseLease.ownBound(bindDirectoryDescriptor(
      sourceDirectory,
      "source-lease source root",
      KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED,
      operationBudget,
    ), "source-lease source root", KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED);
    const custodyBound = releaseLease.ownBound(bindDirectoryDescriptor(
      custodyDirectory,
      "source-lease custody root",
      KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
      operationBudget,
    ), "source-lease custody root", KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID);
    const seedRootBound = releaseLease.ownBound(bindDirectoryDescriptor(
      seedDirectory,
      "source-lease seed root",
      KNOCKOUT_WORKSPACE_ERROR_CODES.ARM_IDENTITY_MISMATCH,
      operationBudget,
    ), "source-lease seed root", KNOCKOUT_WORKSPACE_ERROR_CODES.ARM_IDENTITY_MISMATCH);
    const workspaceBound = releaseLease.ownBound(bindDirectoryDescriptor(
      workspaceDirectory,
      "source-lease seed workspace",
      KNOCKOUT_WORKSPACE_ERROR_CODES.ARM_IDENTITY_MISMATCH,
      operationBudget,
    ), "source-lease seed workspace", KNOCKOUT_WORKSPACE_ERROR_CODES.ARM_IDENTITY_MISMATCH);
    const evidenceBound = releaseLease.ownBound(bindDirectoryDescriptor(
      evidenceDirectory,
      "source-lease seed evidence",
      KNOCKOUT_WORKSPACE_ERROR_CODES.ARM_IDENTITY_MISMATCH,
      operationBudget,
    ), "source-lease seed evidence", KNOCKOUT_WORKSPACE_ERROR_CODES.ARM_IDENTITY_MISMATCH);
    const sourceLeaseSha256 = sha256(crypto.randomBytes(32));
    const sourceLease = Object.freeze({
      candidateManifestSha256: custodyState.captureDescriptor.candidateManifestSha256,
      exclusivityScope: "THIS_ESM_MODULE_INSTANCE_ONLY",
      kind: "SOURCE_LEASE",
      protocol: KNOCKOUT_WORKSPACE_PROTOCOLS.capability,
      sourceLeaseSha256,
      sourceRootIdentity: sourceDirectory.identity,
    });
    const leaseState = {
      cooperativeLeaseState: null,
      custodyBound,
      custodyState,
      descriptorLease: releaseLease,
      evidenceBound,
      planStates: new Set(),
      runBound: null,
      seedRootBound,
      sourceBound,
      sourceLease,
      sourceLeaseKey,
      sourceLeaseSha256,
      sourceSnapshot: observedSource,
      status: "ACTIVE",
      workspaceBound,
    };
    sourceLeaseStates.set(sourceLease, leaseState);
    activeModuleSourceLeases.set(sourceLeaseKey, sourceLease);
    activeRegistered = true;
    custodyState.activeSourceLease = sourceLease;
    custodyState.status = "LEASED";
    return sourceLease;
  } catch (error) {
    if (activeRegistered) activeModuleSourceLeases.delete(sourceLeaseKey);
    custodyState.status = "FAILED_RETAINED";
    throw reportRetainedPrivateRoots(
      releaseLeaseError(releaseLease, error),
      custodyState.retainedRoots,
    );
  }
}

function cooperativeLeaseFailure(
  message,
  state,
  cause = undefined,
  details = {},
  code = KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_LEASE_INDETERMINATE,
) {
  const closeOutcome = state?.closeObservation?.current() ?? null;
  const stderr = state?.stderrCollector?.bytes().subarray(0, 4096).toString("utf8") ?? "";
  return workspaceError(
    code,
    message,
    {
      ...details,
      helperExitCode: closeOutcome?.code ?? null,
      helperSignal: closeOutcome?.signal ?? null,
      helperStderr: stderr,
      lockScope: "COOPERATING_LOCAL_PROCESSES_SAME_PHYSICAL_SOURCE_DIRECTORY",
    },
    cause,
  );
}

async function stopCooperativeLeaseHolder(state) {
  let outcome = state.closeObservation.current();
  if (outcome !== null) return outcome;
  try { state.child.stdin.end(); }
  catch {}
  try {
    outcome = await waitWithTimeout(
      state.closeObservation.promise,
      state.handshakeTimeoutMs,
      "cooperative source-lease helper graceful reap",
    );
    return outcome;
  } catch {}
  try { state.child.kill("SIGKILL"); }
  catch {}
  try {
    return await waitWithTimeout(
      state.closeObservation.promise,
      state.handshakeTimeoutMs,
      "cooperative source-lease helper forced reap",
    );
  } catch {
    return null;
  }
}

function requireCooperativeSourceLease(cooperativeLease) {
  const state = cooperativeSourceLeaseStates.get(cooperativeLease);
  if (state === undefined || !["HELD", "LOST"].includes(state.status)) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
      "operation requires the exact active cooperative source-lease capability",
    );
  }
  return state;
}

function requireHeldCooperativeSourceLease(cooperativeLease) {
  const state = cooperativeSourceLeaseStates.get(cooperativeLease);
  if (
    state === undefined || state.status !== "HELD" ||
    state.commandInFlight ||
    state.cooperativeLease !== cooperativeLease ||
    state.leaseState.status !== "ACTIVE" ||
    state.leaseState.cooperativeLeaseState !== state
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
      "operation requires the exact HELD cooperative source-lease capability",
    );
  }
  return state;
}

function requireCancellableCooperativeSourceLease(cooperativeLease) {
  const state = cooperativeSourceLeaseStates.get(cooperativeLease);
  if (
    state === undefined || !["HELD", "LOST"].includes(state.status) ||
    state.commandInFlight ||
    state.cooperativeLease !== cooperativeLease ||
    state.leaseState.status !== "ACTIVE" ||
    state.leaseState.cooperativeLeaseState !== state
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
      "cancellation requires the exact quiescent HELD or LOST cooperative source-lease capability",
    );
  }
  return state;
}

async function writeCooperativeLeaseControl(state, byte, operation) {
  if (state.stdinError !== null) throw state.stdinError;
  if (state.child.stdin.destroyed || !state.child.stdin.writable) {
    throw new Error(`cooperative source-lease helper stdin is unavailable during ${operation}`);
  }
  await new Promise((resolve, reject) => {
    state.child.stdin.write(byte, (error) => {
      if (error !== null && error !== undefined) reject(error);
      else resolve();
    });
  });
}

async function confirmCooperativeSourceLeaseState(
  state,
  { expectedStatus = "HELD", failureStatus = "LOST" } = {},
) {
  if (state.status !== expectedStatus || state.commandInFlight) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
      "cooperative source lease is unavailable or already processing a control command",
    );
  }
  state.commandInFlight = true;
  try {
    if (
      state.spawnError !== null || state.stdinError !== null ||
      state.closeObservation.current() !== null || state.lineReader.hasQueuedLine()
    ) {
      throw cooperativeLeaseFailure(
        "cooperative source-lease helper lost its exact control state",
        state,
        state.spawnError ?? state.stdinError ?? undefined,
      );
    }
    state.stderrCollector.assertEmpty();
    const operationBudget = createOperationBudget(state.leaseState.custodyState.commandTimeoutMs);
    confirmLeaseBoundaries(state.leaseState, operationBudget);
    await writeCooperativeLeaseControl(state, "P", "liveness challenge");
    const line = await state.lineReader.readLine(
      state.handshakeTimeoutMs,
      "cooperative source-lease liveness challenge",
    );
    if (line !== "ALIVE") {
      throw cooperativeLeaseFailure(
        "cooperative source-lease helper returned an invalid liveness response",
        state,
        undefined,
        { response: line },
      );
    }
    state.stderrCollector.assertEmpty();
    if (state.closeObservation.current() !== null) {
      throw cooperativeLeaseFailure(
        "cooperative source-lease helper exited after its liveness response",
        state,
      );
    }
    confirmLeaseBoundaries(state.leaseState, operationBudget);
    return Object.freeze({
      lockScope: "COOPERATING_LOCAL_PROCESSES_SAME_PHYSICAL_SOURCE_DIRECTORY",
      sourceLeaseSha256: state.leaseState.sourceLeaseSha256,
      status: "HELD",
    });
  } catch (error) {
    state.status = failureStatus;
    if (error instanceof KnockoutWorkspaceError) throw error;
    throw cooperativeLeaseFailure(
      "cooperative source-lease liveness could not be proven",
      state,
      error,
    );
  } finally {
    state.commandInFlight = false;
  }
}

function verifyIndependentCooperativeContention(
  leaseState,
  sourceDirectory,
  handshakeTimeoutMs,
  operationBudget,
) {
  const probeDescriptorLease = createReleaseLease({
    fallbackCode: KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_LEASE_INDETERMINATE,
    message: "cooperative source-lease contention-probe descriptor release",
  });
  let result;
  let primaryError = null;
  try {
    const probeBound = probeDescriptorLease.ownBound(bindDirectoryDescriptor(
      sourceDirectory,
      "cooperative source-lease independent contention probe",
      KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED,
      operationBudget,
    ), "cooperative source-lease independent contention probe",
    KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED);
    result = spawnSync(
      METADATA_FCHDIR_LAUNCHER,
      ["-e", SOURCE_DIRECTORY_FLOCK_SCRIPT],
      {
        encoding: null,
        env: { LANG: "C", LC_ALL: "C", PATH: "/usr/bin:/bin" },
        killSignal: "SIGKILL",
        maxBuffer: 4096,
        shell: false,
        stdio: ["ignore", "pipe", "pipe", probeBound.fd],
        timeout: handshakeTimeoutMs,
        windowsHide: true,
      },
    );
    const stdout = Buffer.isBuffer(result.stdout) ? result.stdout : Buffer.alloc(0);
    const stderr = Buffer.isBuffer(result.stderr) ? result.stderr : Buffer.alloc(0);
    if (
      result.error !== undefined || result.signal !== null || result.status !== 73 ||
      stdout.length !== 0 || stderr.length !== 0
    ) {
      primaryError = workspaceError(
        KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_LEASE_INDETERMINATE,
        "an independent descriptor did not prove nonblocking contention on the held source lease",
        {
          outputLimitExceeded: ["ENOBUFS", "ERR_CHILD_PROCESS_STDIO_MAXBUFFER"]
            .includes(result.error?.code),
          probeExitCode: result.status,
          probeSignal: result.signal,
          probeStderr: stderr.subarray(0, 4096).toString("utf8"),
          probeStdout: stdout.subarray(0, 4096).toString("utf8"),
          timedOut: result.error?.code === "ETIMEDOUT",
        },
        result.error,
      );
    }
  } catch (error) {
    primaryError = error instanceof KnockoutWorkspaceError
      ? error
      : workspaceError(
          KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_LEASE_INDETERMINATE,
          "the independent cooperative source-lease contention probe failed",
          null,
          error,
        );
  }
  try { probeDescriptorLease.release(primaryError); }
  catch (error) { primaryError = error; }
  if (primaryError !== null) throw primaryError;
  confirmLeaseBoundaries(leaseState, operationBudget);
  return Object.freeze({
    expectedExitCode: 73,
    method: "INDEPENDENT_OPEN_DESCRIPTOR_NONBLOCKING_FLOCK",
    observedExitCode: result.status,
    status: "CONTENTION_PROVEN",
  });
}

/**
 * Add cooperative cross-process exclusion over the exact source-directory inode. The lock is
 * advisory: only supervisors using this protocol participate. The parent deliberately retains the
 * shared locked open-file description; helper death is still fail-closed, while the lock remains
 * held until the parent reaps the helper and closes that descriptor.
 */
export async function acquireCooperativeSourceLease(sourceLease, options = {}) {
  const leaseState = requireActiveSourceLease(sourceLease);
  if (leaseState.cooperativeLeaseState !== null) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
      "the source lease already owns a cooperative cross-process lifecycle",
    );
  }
  const snapshot = strictDataObjectSnapshot(
    options,
    "cooperative source-lease options",
    ["handshakeTimeoutMs"],
    [],
  );
  const handshakeTimeoutMs = requireCommandTimeoutMs(
    snapshot.handshakeTimeoutMs ?? COOPERATIVE_SOURCE_LEASE_DEFAULT_HANDSHAKE_MS,
  );
  const operationBudget = createOperationBudget(leaseState.custodyState.commandTimeoutMs);
  confirmLeaseBoundaries(leaseState, operationBudget);
  const sourceDirectory = requireRealDirectory(
    leaseState.sourceBound.path,
    "cooperative source-lease root",
    {
      expectedIdentity: leaseState.sourceBound.identity,
      expectedIdentityCode: KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED,
      operationBudget,
    },
  );
  const holderDescriptorLease = createReleaseLease({
    fallbackCode: KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
    message: "cooperative source-lease holder descriptor release",
  });
  const holderBound = holderDescriptorLease.ownBound(bindDirectoryDescriptor(
    sourceDirectory,
    "cooperative source-lease root",
    KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED,
    operationBudget,
  ), "cooperative source-lease root", KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED);

  let child;
  try {
    child = spawn(
      METADATA_FCHDIR_LAUNCHER,
      ["-e", SOURCE_DIRECTORY_FLOCK_SCRIPT],
      {
        env: { LANG: "C", LC_ALL: "C", PATH: "/usr/bin:/bin" },
        shell: false,
        stdio: ["pipe", "pipe", "pipe", holderBound.fd],
        windowsHide: true,
      },
    );
  } catch (error) {
    throw releaseLeaseError(
      holderDescriptorLease,
      workspaceError(
        KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
        "cooperative source-lease helper could not be spawned",
        null,
        error,
      ),
    );
  }
  const state = {
    child,
    closeObservation: createChildCloseObservation(child),
    commandInFlight: false,
    cooperativeLease: null,
    handshakeTimeoutMs,
    holderBound,
    holderDescriptorLease,
    leaseState,
    lineReader: createBoundedLineReader(
      child.stdout,
      COOPERATIVE_SOURCE_LEASE_MAX_CONTROL_BYTES,
      "cooperative source-lease helper stdout",
    ),
    spawnError: null,
    status: "ACQUIRING",
    stderrCollector: createBoundedByteCollector(
      child.stderr,
      4096,
      "cooperative source-lease helper stderr",
    ),
    stdinError: null,
  };
  child.once("error", (error) => { if (state.spawnError === null) state.spawnError = error; });
  child.stdin.on("error", (error) => { if (state.stdinError === null) state.stdinError = error; });
  leaseState.cooperativeLeaseState = state;

  try {
    const line = await state.lineReader.readLine(
      handshakeTimeoutMs,
      "cooperative source-lease acquisition",
    );
    if (line !== "LOCKED") {
      throw cooperativeLeaseFailure(
        "cooperative source-lease helper returned an invalid acquisition response",
        state,
        undefined,
        { response: line },
      );
    }
    state.stderrCollector.assertEmpty();
    if (state.spawnError !== null || state.closeObservation.current() !== null) {
      throw cooperativeLeaseFailure(
        "cooperative source-lease helper exited during acquisition",
        state,
        state.spawnError ?? undefined,
      );
    }
    confirmLeaseBoundaries(leaseState, operationBudget);
    const contentionProbe = verifyIndependentCooperativeContention(
      leaseState,
      sourceDirectory,
      handshakeTimeoutMs,
      operationBudget,
    );
    // `spawnSync` above blocks delivery of the helper's close event. Challenge the original helper
    // after that independent probe and before registering any authority, so a helper that died in
    // the probe window cannot briefly produce a HELD capability.
    state.status = "HELD";
    await confirmCooperativeSourceLeaseState(state);
    const cooperativeLease = Object.freeze({
      contentionProbe,
      kind: "COOPERATIVE_SOURCE_LEASE",
      lockScope: "COOPERATING_LOCAL_PROCESSES_SAME_PHYSICAL_SOURCE_DIRECTORY",
      protocol: KNOCKOUT_WORKSPACE_PROTOCOLS.cooperativeSourceLease,
      sourceLeaseSha256: leaseState.sourceLeaseSha256,
      sourceRootIdentity: leaseState.sourceBound.identity,
    });
    state.cooperativeLease = cooperativeLease;
    state.status = "HELD";
    cooperativeSourceLeaseStates.set(cooperativeLease, state);
    return cooperativeLease;
  } catch (error) {
    state.status = "FAILED";
    const outcome = await stopCooperativeLeaseHolder(state);
    let primary;
    if (outcome?.code === 73 && outcome.signal === null) {
      try { state.stderrCollector.assertEmpty(); }
      catch (diagnosticError) {
        primary = cooperativeLeaseFailure(
          "cooperative source-lease contention response carried unexpected diagnostics",
          state,
          diagnosticError,
          { holderReaped: true },
        );
      }
      primary ??= cooperativeLeaseFailure(
        "the physical source directory is held by another cooperating supervisor",
        state,
        undefined,
        { holderReaped: true },
        KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_LEASE_HELD,
      );
    } else {
      primary = error instanceof KnockoutWorkspaceError
        ? error
        : cooperativeLeaseFailure(
            "cooperative source lease could not be acquired",
            state,
            error,
            { holderReaped: outcome !== null },
          );
    }
    if (outcome === null) {
      state.status = "REAP_UNKNOWN";
      throw cooperativeLeaseFailure(
        "cooperative source-lease acquisition failed and its helper could not be proven reaped; the parent lock descriptor is retained",
        state,
        primary,
        { holderReaped: false },
      );
    }
    leaseState.cooperativeLeaseState = null;
    throw releaseLeaseError(holderDescriptorLease, primary);
  }
}

/** Challenge the fixed helper and revalidate every local lease boundary around its response. */
export async function confirmCooperativeSourceLease(cooperativeLease) {
  return confirmCooperativeSourceLeaseState(requireCooperativeSourceLease(cooperativeLease));
}

/** Snapshot and cumulatively reserve one append-only batch before any run/arm inode is created. */
export function admitArmPlan(cooperativeLease, options) {
  const cooperativeState = requireHeldCooperativeSourceLease(cooperativeLease);
  const leaseState = cooperativeState.leaseState;
  if (leaseState.custodyState.workerExecutionBlock !== null) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
      "arm-plan admission is blocked by an earlier indeterminate or refused worker",
      { block: leaseState.custodyState.workerExecutionBlock },
    );
  }
  confirmLeaseBoundaries(leaseState, createOperationBudget(leaseState.custodyState.commandTimeoutMs));
  const snapshot = strictDataObjectSnapshot(
    options,
    "arm-plan options",
    ["arms"],
  );
  if (!Array.isArray(snapshot.arms) || snapshot.arms.length < 1) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "arm plan must contain at least one arm");
  }
  const operationBudget = createOperationBudget(leaseState.custodyState.commandTimeoutMs);
  confirmLeaseBoundaries(leaseState, operationBudget);
  observeExactLeaseSeed(leaseState, operationBudget, "before arm-plan admission");
  const seenBatchIds = new Set();
  const entries = snapshot.arms.map((entry, index) => {
    if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
      fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, `arm plan entry ${index} is malformed`);
    }
    const keys = Object.keys(entry).sort();
    const expectedKeys = ["armId", "role", "subjectSha256"];
    if (keys.length !== expectedKeys.length || keys.some((key, keyIndex) => key !== expectedKeys[keyIndex])) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
        `arm plan entry ${index} has unknown or missing fields`,
      );
    }
    if (typeof entry.armId !== "string" || !ARM_ID.test(entry.armId)) {
      fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, `arm plan entry ${index} has an invalid armId`);
    }
    if (!KNOCKOUT_WORKSPACE_ARM_ROLES.includes(entry.role)) {
      fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, `arm plan entry ${index} has an invalid role`);
    }
    if (typeof entry.subjectSha256 !== "string" || !HASH_64.test(entry.subjectSha256)) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
        `arm plan entry ${index} has an invalid subjectSha256`,
      );
    }
    if (
      seenBatchIds.has(entry.armId) ||
      leaseState.custodyState.allArmRecords.has(entry.armId)
    ) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
        `armId ${entry.armId} was already admitted in this custody lifecycle`,
      );
    }
    seenBatchIds.add(entry.armId);
    return Object.freeze({
      armId: entry.armId,
      role: entry.role,
      subjectSha256: entry.subjectSha256,
    });
  });
  const projection = armCapacityProjection(
    leaseState.custodyState,
    entries.length,
    operationBudget,
  );
  const planWithoutHash = Object.freeze({
    batch: leaseState.custodyState.nextBatch,
    candidateManifestSha256: leaseState.custodyState.captureDescriptor.candidateManifestSha256,
    entries: Object.freeze(entries),
    predecessorPlanSha256: leaseState.custodyState.lastPlanSha256,
    protocol: KNOCKOUT_WORKSPACE_PROTOCOLS.armPlan,
    sourceLeaseSha256: leaseState.sourceLeaseSha256,
  });
  const armPlanSha256 = sha256(canonicalJsonBytes(planWithoutHash));
  const planCapability = Object.freeze({ ...planWithoutHash, armPlanSha256 });
  requireHeldCooperativeSourceLease(cooperativeLease);
  const armById = new Map();
  for (const entry of entries) {
    const record = {
      armId: entry.armId,
      armPlanSha256,
      capability: null,
      retainedTargets: null,
      reservationBytes: projection.perArmBytes,
      role: entry.role,
      status: "ADMITTED",
      subjectSha256: entry.subjectSha256,
      workerResult: null,
    };
    armById.set(entry.armId, record);
  }
  const planState = {
    armById,
    armPlanSha256,
    cooperativeState,
    leaseState,
    planCapability,
    valid: true,
  };
  armPlanStates.set(planCapability, planState);
  leaseState.planStates.add(planState);
  for (const [armId, record] of armById) {
    leaseState.custodyState.allArmRecords.set(armId, record);
  }
  leaseState.custodyState.reservedArms = projection.projectedArms;
  leaseState.custodyState.reservedBytes = projection.projectedBytes;
  leaseState.custodyState.lastPlanSha256 = armPlanSha256;
  leaseState.custodyState.nextBatch += 1;
  return planCapability;
}

/** Materialize one admitted ID exactly once into a random retained physical arm. */
export function materializeArm(planCapability, armId) {
  const planState = armPlanStates.get(planCapability);
  if (
    planState === undefined || planState.valid !== true ||
    planState.leaseState.status !== "ACTIVE" ||
    planState.cooperativeState.status !== "HELD"
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
      "materializeArm requires the exact active same-process arm-plan capability",
    );
  }
  if (typeof armId !== "string" || !ARM_ID.test(armId)) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "materializeArm armId is malformed");
  }
  const record = planState.armById.get(armId);
  if (record === undefined) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
      "armId is not authorized by this exact arm-plan capability",
    );
  }
  if (record.status !== "ADMITTED") {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
      `armId ${armId} cannot be materialized from state ${record.status}`,
    );
  }

  const leaseState = planState.leaseState;
  const custodyState = leaseState.custodyState;
  if (custodyState.workerExecutionBlock !== null) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
      "arm materialization is blocked by an earlier indeterminate or refused worker",
      { block: custodyState.workerExecutionBlock },
    );
  }
  const operationBudget = createOperationBudget(custodyState.commandTimeoutMs);
  let armRoot = null;
  let reservationConsumed = false;
  record.status = "MATERIALIZING";
  try {
    requireHeldCooperativeSourceLease(planState.cooperativeState.cooperativeLease);
    confirmLeaseBoundaries(leaseState, operationBudget);
    observeExactLeaseSeed(leaseState, operationBudget, `before arm ${armId} materialization`);
    const outstandingBytes = custodyState.reservedBytes - custodyState.consumedReservationBytes;
    if (!Number.isSafeInteger(outstandingBytes) || outstandingBytes < record.reservationBytes) {
      fail(KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID, "arm reservation ledger is inconsistent");
    }
    const capacity = filesystemCapacity(
      custodyState.captureDescriptor.custodyRoot,
      `arm ${armId} materialization`,
      operationBudget,
    );
    const requiredBytes = BigInt(outstandingBytes) + BigInt(custodyState.limits.minFreeBytes);
    if (capacity.availableBytes < requiredBytes) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.RESOURCE_LIMIT_EXCEEDED,
        `arm ${armId} cannot start without capacity for all outstanding reservations`,
        {
          availableBytes: String(capacity.availableBytes),
          outstandingBytes,
          requiredBytes: String(requiredBytes),
        },
      );
    }
    custodyState.consumedReservationBytes += record.reservationBytes;
    reservationConsumed = true;

    if (leaseState.runBound === null) {
      const runRoot = createUniquePrivateDirectory(
        custodyState.captureDescriptor.custodyRoot,
        "run-",
        {
          expectedParent: leaseState.custodyBound,
          label: "knockout run root",
          operationBudget,
          parentMismatchCode: KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
          privateParent: true,
        },
      );
      custodyState.retainedRoots.push(retainCreatedPrivateTree(runRoot));
      leaseState.runBound = leaseState.descriptorLease.ownBound(bindDirectoryDescriptor(
        runRoot,
        "knockout run root",
        KNOCKOUT_WORKSPACE_ERROR_CODES.ARM_IDENTITY_MISMATCH,
        operationBudget,
      ), "knockout run root", KNOCKOUT_WORKSPACE_ERROR_CODES.ARM_IDENTITY_MISMATCH);
    } else {
      confirmBoundDirectoryIdentity(
        leaseState.runBound,
        "knockout run root",
        KNOCKOUT_WORKSPACE_ERROR_CODES.ARM_IDENTITY_MISMATCH,
        operationBudget,
        { privateMode: true },
      );
    }

    armRoot = createUniquePrivateDirectory(
      leaseState.runBound.path,
      "arm-",
      {
        expectedParent: leaseState.runBound,
        label: `arm ${armId} root`,
        operationBudget,
        parentMismatchCode: KNOCKOUT_WORKSPACE_ERROR_CODES.ARM_IDENTITY_MISMATCH,
        privateParent: true,
      },
    );
    custodyState.retainedRoots.push(retainCreatedPrivateTree(armRoot));
    const workspaceRoot = createPrivateDirectory(
      path.join(armRoot.path, "workspace"),
      {
        expectedParent: armRoot,
        operationBudget,
        parentMismatchCode: KNOCKOUT_WORKSPACE_ERROR_CODES.ARM_IDENTITY_MISMATCH,
      },
    );
    const evidenceRoot = createPrivateDirectory(
      path.join(armRoot.path, "evidence"),
      {
        expectedParent: armRoot,
        operationBudget,
        parentMismatchCode: KNOCKOUT_WORKSPACE_ERROR_CODES.ARM_IDENTITY_MISMATCH,
      },
    );
    const copied = copyLiveWorktree(custodyState.seedCensus, workspaceRoot.path, {
      expectedDestinationRoot: workspaceRoot,
      expectedSourceRoot: leaseState.workspaceBound,
      limits: custodyState.limits,
      metadataCache: custodyState.metadataCache,
      operationBudget,
      rootGitPolicy: "include",
      sourceMismatchCode: KNOCKOUT_WORKSPACE_ERROR_CODES.ARM_IDENTITY_MISMATCH,
    });
    observeExactLeaseSeed(leaseState, operationBudget, `after arm ${armId} materialization`);
    const sourceIdentities = new Set(custodyState.seedCensus.nodes.map((node) =>
      node.observation.identity));
    const aliasedNode = copied.nodes.find((node) => sourceIdentities.has(node.observation.identity));
    if (aliasedNode !== undefined) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.COPY_INCOMPLETE,
        `arm ${armId} is not physically disjoint from its sealed seed`,
        { path: aliasedNode.path },
      );
    }
    confirmLeaseBoundaries(leaseState, operationBudget);
    const observedArmRoot = requireRealDirectory(
      armRoot.path,
      `arm ${armId} root`,
      {
        expectedIdentity: armRoot.identity,
        expectedIdentityCode: KNOCKOUT_WORKSPACE_ERROR_CODES.ARM_IDENTITY_MISMATCH,
        operationBudget,
        privateMode: true,
      },
    );
    const observedWorkspace = requireRealDirectory(
      workspaceRoot.path,
      `arm ${armId} workspace`,
      {
        expectedIdentity: workspaceRoot.identity,
        expectedIdentityCode: KNOCKOUT_WORKSPACE_ERROR_CODES.ARM_IDENTITY_MISMATCH,
        operationBudget,
        privateMode: true,
      },
    );
    const observedEvidence = requireRealDirectory(
      evidenceRoot.path,
      `arm ${armId} evidence`,
      {
        expectedIdentity: evidenceRoot.identity,
        expectedIdentityCode: KNOCKOUT_WORKSPACE_ERROR_CODES.ARM_IDENTITY_MISMATCH,
        operationBudget,
        privateMode: true,
      },
    );
    const armBound = leaseState.descriptorLease.ownBound(bindDirectoryDescriptor(
      observedArmRoot,
      `arm ${armId} root`,
      KNOCKOUT_WORKSPACE_ERROR_CODES.ARM_IDENTITY_MISMATCH,
      operationBudget,
    ), `arm ${armId} root`, KNOCKOUT_WORKSPACE_ERROR_CODES.ARM_IDENTITY_MISMATCH);
    const armWorkspaceBound = leaseState.descriptorLease.ownBound(bindDirectoryDescriptor(
      observedWorkspace,
      `arm ${armId} workspace`,
      KNOCKOUT_WORKSPACE_ERROR_CODES.ARM_IDENTITY_MISMATCH,
      operationBudget,
    ), `arm ${armId} workspace`, KNOCKOUT_WORKSPACE_ERROR_CODES.ARM_IDENTITY_MISMATCH);
    const armEvidenceBound = leaseState.descriptorLease.ownBound(bindDirectoryDescriptor(
      observedEvidence,
      `arm ${armId} evidence`,
      KNOCKOUT_WORKSPACE_ERROR_CODES.ARM_IDENTITY_MISMATCH,
      operationBudget,
    ), `arm ${armId} evidence`, KNOCKOUT_WORKSPACE_ERROR_CODES.ARM_IDENTITY_MISMATCH);
    const armDescriptor = Object.freeze({
      armId: record.armId,
      armPlanSha256: record.armPlanSha256,
      armBound,
      armEvidenceBound,
      armRoot: observedArmRoot.path,
      armRootIdentity: observedArmRoot.identity,
      armRootObservation: observedArmRoot.observation,
      candidateManifestSha256: custodyState.captureDescriptor.candidateManifestSha256,
      evidenceIdentity: observedEvidence.identity,
      evidenceObservation: observedEvidence.observation,
      evidenceRoot: observedEvidence.path,
      initialObservation: copied,
      role: record.role,
      runRoot: leaseState.runBound.path,
      runRootIdentity: leaseState.runBound.identity,
      seedObservationSha256: custodyState.seedCensus.observationSha256,
      seedWorkspaceIdentity: leaseState.workspaceBound.identity,
      sourceLeaseSha256: leaseState.sourceLeaseSha256,
      sourceSnapshotSha256: leaseState.sourceSnapshot.snapshotSha256,
      subjectSha256: record.subjectSha256,
      workspaceIdentity: observedWorkspace.identity,
      workspaceObservation: observedWorkspace.observation,
      armWorkspaceBound,
      workspaceRoot: observedWorkspace.path,
    });
    const armCapability = Object.freeze({
      armId: record.armId,
      armPlanSha256: record.armPlanSha256,
      armRoot: armDescriptor.armRoot,
      candidateManifestSha256: armDescriptor.candidateManifestSha256,
      evidenceRoot: armDescriptor.evidenceRoot,
      initialObservationSha256: copied.observationSha256,
      kind: "DISPOSABLE_ARM",
      protocol: KNOCKOUT_WORKSPACE_PROTOCOLS.arm,
      retainedPrivateRoots: uniqueRetainedPrivateRoots(custodyState.retainedRoots),
      role: record.role,
      seedObservationSha256: armDescriptor.seedObservationSha256,
      sourceLeaseSha256: leaseState.sourceLeaseSha256,
      sourceSnapshotSha256: armDescriptor.sourceSnapshotSha256,
      subjectSha256: record.subjectSha256,
      workspaceRoot: armDescriptor.workspaceRoot,
    });
    requireHeldCooperativeSourceLease(planState.cooperativeState.cooperativeLease);
    armCapabilityStates.set(armCapability, {
      descriptor: armDescriptor,
      leaseState,
      record,
      valid: true,
    });
    custodyState.armCapabilities.add(armCapability);
    record.capability = armCapability;
    record.status = "MATERIALIZED";
    return armCapability;
  } catch (caught) {
    if (!reservationConsumed) {
      custodyState.consumedReservationBytes += record.reservationBytes;
      reservationConsumed = true;
    }
    record.status = "FAILED_RETAINED";
    custodyState.retainedRoots.push(...retainedPrivateRoots(caught?.details));
    if (armRoot !== null) custodyState.retainedRoots.push(retainCreatedPrivateTree(armRoot));
    throw reportRetainedPrivateRoots(caught, custodyState.retainedRoots);
  }
}

/** Explicitly burn one admitted-but-unmaterialized arm so cooperative release cannot cancel it. */
export function cancelAdmittedArm(planCapability, armId, reasonCode) {
  const planState = armPlanStates.get(planCapability);
  if (
    planState === undefined || planState.valid !== true ||
    planState.leaseState.status !== "ACTIVE"
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
      "cancelAdmittedArm requires the exact active arm-plan capability",
    );
  }
  const cooperativeState = requireCancellableCooperativeSourceLease(
    planState.cooperativeState.cooperativeLease,
  );
  if (cooperativeState !== planState.cooperativeState) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
      "cancelAdmittedArm plan is not bound to the active cooperative lifecycle",
    );
  }
  if (typeof armId !== "string" || !ARM_ID.test(armId)) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "cancelAdmittedArm armId is malformed");
  }
  if (
    typeof reasonCode !== "string" || reasonCode.length < 1 || reasonCode.length > 64 ||
    !/^[A-Z][A-Z0-9_]*$/.test(reasonCode)
  ) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "arm cancellation reasonCode is malformed");
  }
  const record = planState.armById.get(armId);
  if (record === undefined || record.status !== "ADMITTED") {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
      `armId ${armId} cannot be cancelled from state ${record?.status ?? "UNAUTHORIZED"}`,
    );
  }
  const custodyState = planState.leaseState.custodyState;
  const nextConsumed = custodyState.consumedReservationBytes + record.reservationBytes;
  if (!Number.isSafeInteger(nextConsumed) || nextConsumed > custodyState.reservedBytes) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID, "arm reservation ledger is inconsistent");
  }
  custodyState.consumedReservationBytes = nextConsumed;
  record.cancellationReasonCode = reasonCode;
  record.status = "CANCELLED";
  return Object.freeze({
    armId,
    armPlanSha256: record.armPlanSha256,
    candidateManifestSha256: custodyState.captureDescriptor.candidateManifestSha256,
    reasonCode,
    sourceLeaseSha256: planState.leaseState.sourceLeaseSha256,
    status: "CANCELLED",
  });
}

/** Explicitly burn one materialized arm without running it; retained bytes are never deleted. */
export function cancelMaterializedArm(cooperativeLease, armCapability, reasonCode) {
  const cooperativeState = requireCancellableCooperativeSourceLease(cooperativeLease);
  const armState = armCapabilityStates.get(armCapability);
  if (
    armState === undefined || armState.valid !== true ||
    armState.leaseState !== cooperativeState.leaseState ||
    armState.record.capability !== armCapability || armState.record.status !== "MATERIALIZED"
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
      "cancelMaterializedArm requires the exact unused materialized-arm capability",
    );
  }
  if (
    typeof reasonCode !== "string" || reasonCode.length < 1 || reasonCode.length > 64 ||
    !/^[A-Z][A-Z0-9_]*$/.test(reasonCode)
  ) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "arm cancellation reasonCode is malformed");
  }
  const operationBudget = createOperationBudget(cooperativeState.leaseState.custodyState.commandTimeoutMs);
  confirmLeaseBoundaries(cooperativeState.leaseState, operationBudget);
  confirmArmDescriptorIdentities(armState.descriptor, operationBudget);
  armState.valid = false;
  armState.record.cancellationReasonCode = reasonCode;
  armState.record.status = "CANCELLED";
  return Object.freeze({
    armId: armState.record.armId,
    armPlanSha256: armState.record.armPlanSha256,
    candidateManifestSha256: armState.descriptor.candidateManifestSha256,
    reasonCode,
    sourceLeaseSha256: armState.descriptor.sourceLeaseSha256,
    status: "CANCELLED",
  });
}

function confirmArmDescriptorIdentities(armDescriptor, operationBudget) {
  confirmBoundDirectoryIdentity(
    armDescriptor.armBound,
    `arm ${armDescriptor.armId} root`,
    KNOCKOUT_WORKSPACE_ERROR_CODES.ARM_IDENTITY_MISMATCH,
    operationBudget,
    { privateMode: true },
  );
  confirmBoundDirectoryIdentity(
    armDescriptor.armWorkspaceBound,
    `arm ${armDescriptor.armId} workspace`,
    KNOCKOUT_WORKSPACE_ERROR_CODES.ARM_IDENTITY_MISMATCH,
    operationBudget,
    { privateMode: true },
  );
  confirmBoundDirectoryIdentity(
    armDescriptor.armEvidenceBound,
    `arm ${armDescriptor.armId} evidence`,
    KNOCKOUT_WORKSPACE_ERROR_CODES.ARM_IDENTITY_MISMATCH,
    operationBudget,
    { privateMode: true },
  );
}

function observeExactInitialArm(armState, operationBudget) {
  const descriptor = armState.descriptor;
  confirmArmDescriptorIdentities(descriptor, operationBudget);
  let observed;
  try {
    observed = censusWorkspace(descriptor.workspaceRoot, {
      expectedRoot: Object.freeze({
        identity: descriptor.workspaceIdentity,
        path: descriptor.workspaceRoot,
      }),
      expectedRootCode: KNOCKOUT_WORKSPACE_ERROR_CODES.ARM_IDENTITY_MISMATCH,
      limits: armState.leaseState.custodyState.limits,
      metadataCache: armState.leaseState.custodyState.metadataCache,
      operationBudget,
      rootGitPolicy: "include",
    });
  } catch (error) {
    if (error instanceof KnockoutWorkspaceError) throw error;
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.ARM_IDENTITY_MISMATCH,
      `arm ${descriptor.armId} could not be re-observed before worker launch`,
      null,
      error,
    );
  }
  if (!sameWorkspaceCensus(observed, descriptor.initialObservation)) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.ARM_IDENTITY_MISMATCH,
      `arm ${descriptor.armId} changed before worker launch`,
      {
        expected: descriptor.initialObservation.observationSha256,
        observed: observed.observationSha256,
      },
    );
  }
  confirmArmDescriptorIdentities(descriptor, operationBudget);
  return observed;
}

function workerStreamEvidence(snapshot) {
  return Object.freeze({
    bytes: snapshot.observedBytes,
    complete: snapshot.complete,
    sha256: snapshot.complete ? sha256(snapshot.bytes) : null,
  });
}

function validWorkerStreamEvidence(value) {
  return (
    hasExactObjectKeys(value, ["bytes", "complete", "sha256"]) &&
    Number.isSafeInteger(value.bytes) && value.bytes >= 0 &&
    typeof value.complete === "boolean" &&
    ((value.complete && HASH_64.test(value.sha256 ?? "")) ||
      (!value.complete && value.sha256 === null))
  );
}

function validWorkerResultPublication(value) {
  return (
    value === null ||
    (
      hasExactObjectKeys(value, ["filename", "identity", "observation", "sha256"]) &&
      value.filename === "worker-result.bin" &&
      typeof value.identity === "string" && value.identity.length > 0 &&
      validFileObservation(value.observation) &&
      value.observation.identity === value.identity &&
      HASH_64.test(value.sha256 ?? "")
    )
  );
}

const RETAINED_FILE_OBSERVATION_KEYS = Object.freeze([
  "allocatedBytes", "ctimeNs", "dev", "identity", "ino", "mode", "mtimeNs", "nlink", "size",
]);

function retainedFileObservation(value, label) {
  const decimal = /^(?:0|[1-9][0-9]*)$/u;
  if (
    !hasExactObjectKeys(value, RETAINED_FILE_OBSERVATION_KEYS) ||
    !Number.isSafeInteger(value.allocatedBytes) || value.allocatedBytes < 0 ||
    typeof value.ctimeNs !== "string" || !decimal.test(value.ctimeNs) ||
    typeof value.dev !== "string" || !decimal.test(value.dev) ||
    typeof value.identity !== "string" || value.identity !== `${value.dev}:${value.ino}` ||
    typeof value.ino !== "string" || !decimal.test(value.ino) ||
    !Number.isInteger(value.mode) || value.mode < 0 || value.mode > 0o7777 ||
    typeof value.mtimeNs !== "string" || !decimal.test(value.mtimeNs) ||
    !Number.isInteger(value.nlink) || value.nlink < 1 ||
    !Number.isSafeInteger(value.size) || value.size < 0
  ) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_INCOMPLETE, `${label} is malformed`);
  }
  return Object.freeze({
    allocatedBytes: value.allocatedBytes,
    ctimeNs: value.ctimeNs,
    dev: value.dev,
    identity: value.identity,
    ino: value.ino,
    mode: value.mode,
    mtimeNs: value.mtimeNs,
    nlink: value.nlink,
    size: value.size,
  });
}

function canonicalKnockoutTargetSet(request, code, label) {
  const entries = [request.entry, ...(request.pairedEntry === null ? [] : [request.pairedEntry])];
  const rawMutationTargets = entries.map((entry) => entry?.file);
  const rawTargets = [...new Set(entries.flatMap((entry) => [
    entry?.file,
    ...(entry?.companionFile === undefined ? [] : [entry.companionFile]),
  ]))].sort();
  if (rawTargets.length < 1 || rawTargets.length > 4) {
    fail(code, `${label} target count is outside the closed registry bound`);
  }
  const canonicalize = (target, index, targetLabel) => {
    if (typeof target !== "string") fail(code, `${label} ${targetLabel} ${index} is malformed`);
    const canonical = decodeCanonicalIndexPath(
      Buffer.from(target, "utf8"),
      `${label} ${targetLabel} ${index}`,
      code,
    );
    if (canonical !== target) fail(code, `${label} ${targetLabel} ${index} is not canonical`);
    return canonical;
  };
  const targets = rawTargets.map((target, index) => canonicalize(target, index, "target"));
  const mutationTargets = [...new Set(rawMutationTargets.map((target, index) =>
    canonicalize(target, index, "mutation target")))].sort();
  return Object.freeze({
    mutationTargets: Object.freeze(mutationTargets),
    targets: Object.freeze(targets),
  });
}

function retainedMutantTargetClaim(workerCapability, workerResult) {
  if (
    workerCapability?.subject?.operation !== KNOCKOUT_WORKER_OPERATIONS.RUN_KNOCKOUT ||
    workerResult?.status !== "COMPLETE" ||
    workerResult.observation?.operation !== KNOCKOUT_WORKER_OPERATIONS.RUN_KNOCKOUT ||
    workerResult.observation?.knockout?.evidence?.workspaceDisposition !==
      "RETAINED_DISPOSABLE_MUTANT"
  ) return null;
  const request = workerCapability.subject.request;
  const targetSet = canonicalKnockoutTargetSet(
    request,
    KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_INCOMPLETE,
    "retained mutant",
  );
  const canonicalTargets = targetSet.targets;
  const evidence = workerResult.observation.knockout.evidence;
  const hashBefore = evidence.hashBefore;
  const hashAfter = evidence.hashAfter;
  if (
    hashBefore === null || typeof hashBefore !== "object" || Array.isArray(hashBefore) ||
    hashAfter === null || typeof hashAfter !== "object" || Array.isArray(hashAfter) ||
    !hasExactObjectKeys(hashBefore, canonicalTargets) ||
    !hasExactObjectKeys(hashAfter, canonicalTargets)
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_INCOMPLETE,
      "retained mutant hashes do not name the exact closed target set",
    );
  }
  const targets = canonicalTargets.map((target) => {
    const beforeSha256 = hashBefore[target];
    const retainedSha256 = hashAfter[target];
    if (!HASH_64.test(beforeSha256 ?? "") || !HASH_64.test(retainedSha256 ?? "")) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_INCOMPLETE,
        `retained mutant hashes for ${target} are malformed`,
      );
    }
    return Object.freeze({ beforeSha256, path: target, retainedSha256 });
  });
  if (!targets.some((target) => target.beforeSha256 !== target.retainedSha256)) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_INCOMPLETE,
      "retained mutant claim has no byte-changing target",
    );
  }
  for (const mutationTarget of targetSet.mutationTargets) {
    const target = targets.find((candidate) => candidate.path === mutationTarget);
    if (target === undefined || target.beforeSha256 === target.retainedSha256) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_INCOMPLETE,
        `retained mutation target ${mutationTarget} did not retain changed bytes`,
      );
    }
  }
  return Object.freeze({ targets: Object.freeze(targets) });
}

function validateRetainedTargetEvidence(value, { armDescriptor, workerCapability, workerResult }) {
  const claim = retainedMutantTargetClaim(workerCapability, workerResult);
  if (claim === null) {
    if (value !== null) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_INCOMPLETE,
        "terminal carries retained-target evidence for an operation with no retained mutant claim",
      );
    }
    return null;
  }
  if (
    !hasExactObjectKeys(value, ["protocol", "targets", "verifiedAfterOriginalProcessGroupExit"]) ||
    value.protocol !== KNOCKOUT_WORKSPACE_PROTOCOLS.retainedTargets ||
    value.verifiedAfterOriginalProcessGroupExit !== true ||
    !Array.isArray(value.targets) || value.targets.length !== claim.targets.length
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_INCOMPLETE,
      "retained-target terminal evidence is malformed",
    );
  }
  const initialNodes = new Map(armDescriptor.initialObservation.nodes.map((node) => [node.path, node]));
  for (const [index, expected] of claim.targets.entries()) {
    const target = value.targets[index];
    if (!hasExactObjectKeys(target, [
      "beforeSha256", "initialObservation", "path", "retainedObservation", "retainedSha256",
    ])) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_INCOMPLETE,
        `retained-target terminal entry ${index} has an open schema`,
      );
    }
    const initialNode = initialNodes.get(expected.path);
    const initialObservation = retainedFileObservation(
      target.initialObservation,
      `retained target ${expected.path} initial observation`,
    );
    const retainedObservation = retainedFileObservation(
      target.retainedObservation,
      `retained target ${expected.path} terminal observation`,
    );
    if (
      target.path !== expected.path || target.beforeSha256 !== expected.beforeSha256 ||
      target.retainedSha256 !== expected.retainedSha256 ||
      initialNode?.type !== "file" || initialNode.sha256 !== expected.beforeSha256 ||
      !canonicalJsonBytes(initialObservation).equals(
        canonicalJsonBytes(retainedFileObservation(
          initialNode.observation,
          `retained target ${expected.path} captured observation`,
        )),
      ) ||
      initialObservation.identity !== retainedObservation.identity ||
      initialObservation.mode !== retainedObservation.mode ||
      initialObservation.nlink !== 1 || retainedObservation.nlink !== 1 ||
      retainedObservation.size < 0
    ) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_INCOMPLETE,
        `retained target ${expected.path} is not bound to its initial single-link inode and worker hashes`,
      );
    }
  }
  return value;
}

function acquireRetainedMutantTargetEvidence(
  armState,
  workerCapability,
  workerResult,
  operationBudget,
  expectedEvidence = null,
) {
  const claim = retainedMutantTargetClaim(workerCapability, workerResult);
  if (claim === null) return Object.freeze({ custody: null, evidence: null });
  const custodyState = armState.leaseState.custodyState;
  const custody = createBoundControlCustody({
    byteBudget: null,
    code: KNOCKOUT_WORKSPACE_ERROR_CODES.ARM_IDENTITY_MISMATCH,
    limits: custodyState.limits,
    operationBudget,
  });
  try {
    const initialNodes = new Map(
      armState.descriptor.initialObservation.nodes.map((node) => [node.path, node]),
    );
    const physicalIdentities = new Set();
    const targets = claim.targets.map((expected) => {
      const initialNode = initialNodes.get(expected.path);
      if (
        initialNode?.type !== "file" || initialNode.sha256 !== expected.beforeSha256 ||
        initialNode.observation?.nlink !== 1
      ) {
        fail(
          KNOCKOUT_WORKSPACE_ERROR_CODES.ARM_IDENTITY_MISMATCH,
          `retained target ${expected.path} does not match its captured initial file`,
        );
      }
      if (physicalIdentities.has(initialNode.observation.identity)) {
        fail(
          KNOCKOUT_WORKSPACE_ERROR_CODES.ARM_IDENTITY_MISMATCH,
          "two retained target names resolve to one physical inode",
          { identity: initialNode.observation.identity },
        );
      }
      physicalIdentities.add(initialNode.observation.identity);
      const observed = custody.acquire(
        armState.descriptor.armWorkspaceBound,
        expected.path,
        `arm ${armState.descriptor.armId} retained target ${expected.path}`,
        {
          code: KNOCKOUT_WORKSPACE_ERROR_CODES.ARM_IDENTITY_MISMATCH,
          maxBytes: custodyState.limits.maxFileBytes,
        },
      );
      if (
        observed.sha256 !== expected.retainedSha256 ||
        observed.observation.identity !== initialNode.observation.identity ||
        observed.observation.mode !== initialNode.observation.mode ||
        observed.observation.nlink !== 1
      ) {
        fail(
          KNOCKOUT_WORKSPACE_ERROR_CODES.ARM_IDENTITY_MISMATCH,
          `retained target ${expected.path} changed after worker retention`,
          {
            expectedIdentity: initialNode.observation.identity,
            expectedSha256: expected.retainedSha256,
            observedIdentity: observed.observation.identity,
            observedSha256: observed.sha256,
          },
        );
      }
      return Object.freeze({
        beforeSha256: expected.beforeSha256,
        initialObservation: retainedFileObservation(
          initialNode.observation,
          `retained target ${expected.path} captured observation`,
        ),
        path: expected.path,
        retainedObservation: retainedFileObservation(
          observed.observation,
          `retained target ${expected.path} supervisor observation`,
        ),
        retainedSha256: observed.sha256,
      });
    });
    const evidence = Object.freeze({
      protocol: KNOCKOUT_WORKSPACE_PROTOCOLS.retainedTargets,
      targets: Object.freeze(targets),
      verifiedAfterOriginalProcessGroupExit: true,
    });
    validateRetainedTargetEvidence(evidence, {
      armDescriptor: armState.descriptor,
      workerCapability,
      workerResult,
    });
    custody.confirm("after retained-target acquisition");
    if (
      expectedEvidence !== null &&
      !canonicalJsonBytes(evidence).equals(canonicalJsonBytes(expectedEvidence))
    ) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_HASH_MISMATCH,
        "retained target state differs from the terminal-bound observation",
      );
    }
    return Object.freeze({ custody, evidence });
  } catch (error) {
    try { custody.release(error); }
    catch (releaseError) { throw releaseError; }
    throw error;
  }
}

function confirmRetainedMutantTargetEvidence(
  armState,
  workerCapability,
  workerResult,
  expectedEvidence,
  operationBudget,
  phase,
) {
  if (expectedEvidence === null) return;
  const retained = acquireRetainedMutantTargetEvidence(
    armState,
    workerCapability,
    workerResult,
    operationBudget,
    expectedEvidence,
  );
  if (retained.custody === null || retained.evidence === null) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_HASH_MISMATCH,
      `retained target evidence disappeared ${phase}`,
    );
  }
  let primaryError = null;
  try { retained.custody.confirm(phase); }
  catch (error) { primaryError = error; }
  try { retained.custody.release(primaryError); }
  catch (error) { primaryError = error; }
  if (primaryError !== null) throw primaryError;
}

function retainedTargetFailureEvidence(error) {
  return Object.freeze({
    code: ERROR_CODE_SET.has(error?.code)
      ? error.code
      : KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_INCOMPLETE,
    phase: "POST_PROCESS_GROUP_REVALIDATION",
  });
}

function completedReferencedWorkerRecord(
  custodyState,
  { expectedOperation, expectedRole, operationBudget, resultSha256, terminalSha256, wire, wireField },
) {
  const matches = [...custodyState.allArmRecords.values()].filter((record) =>
    record.status === "TERMINAL" && record.terminalPublication?.sha256 === terminalSha256);
  if (matches.length !== 1) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
      `worker request references ${matches.length} retained terminals for ${expectedRole}`,
      { terminalSha256 },
    );
  }
  const record = matches[0];
  const reopened = reopenArmTerminalRecord(record, operationBudget);
  const terminal = reopened.terminal;
  const workerResult = reopened.workerResult;
  const observedWire = workerResult?.observation?.[wireField];
  if (
    record.role !== expectedRole || terminal.role !== expectedRole ||
    terminal.status !== "COMPLETE" || terminal.workerResult?.accepted !== true ||
    terminal.workerResult?.status !== "COMPLETE" ||
    record.workerResultPublication?.sha256 !== resultSha256 ||
    terminal.workerResult?.sha256 !== resultSha256 ||
    workerResult?.status !== "COMPLETE" ||
    workerResult?.observation?.operation !== expectedOperation ||
    observedWire === undefined ||
    !canonicalJsonBytes(observedWire).equals(canonicalJsonBytes(wire))
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
      `worker request does not bind the exact completed ${expectedRole} result and terminal`,
      { resultSha256, terminalSha256 },
    );
  }
  return record;
}

/** Bind every cross-arm request to an already terminal retained publication before worker spawn. */
function validateWorkerEvidenceReferences(
  custodyState,
  operation,
  request,
  predecessorTerminalSha256,
  operationBudget,
) {
  if (
    operation !== KNOCKOUT_WORKER_OPERATIONS.RUN_KNOCKOUT &&
    operation !== KNOCKOUT_WORKER_OPERATIONS.OBSERVE_KNOCKOUT_POSTCHECK
  ) return;
  const baselineRecord = completedReferencedWorkerRecord(custodyState, {
    expectedOperation: KNOCKOUT_WORKER_OPERATIONS.OBSERVE_KNOCKOUT_BASELINE,
    expectedRole: "BASELINE",
    operationBudget,
    resultSha256: request.baselineResultSha256,
    terminalSha256: request.baselineTerminalSha256,
    wire: request.baseline,
    wireField: "baseline",
  });
  const baselineRequest = baselineRecord.workerCapability?.subject?.request;
  const candidateSubjectKeys = Object.hasOwn(request, "candidateSubject")
    ? ["candidateSubject"] : [];
  if (
    baselineRequest === null || typeof baselineRequest !== "object" || Array.isArray(baselineRequest) ||
    Object.hasOwn(baselineRequest, "candidateSubject") !== Object.hasOwn(request, "candidateSubject") ||
    candidateSubjectKeys.some((key) =>
      !canonicalJsonBytes(baselineRequest[key]).equals(canonicalJsonBytes(request[key])))
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
      "worker request does not preserve the exact baseline candidate subject",
    );
  }
  if (operation !== KNOCKOUT_WORKER_OPERATIONS.OBSERVE_KNOCKOUT_POSTCHECK) return;
  if (request.mutantTerminalSha256 !== predecessorTerminalSha256) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
      "postcheck request mutant terminal is not its immediate retained predecessor",
      {
        expected: predecessorTerminalSha256,
        observed: request.mutantTerminalSha256,
      },
    );
  }
  const mutantRecord = completedReferencedWorkerRecord(custodyState, {
    expectedOperation: KNOCKOUT_WORKER_OPERATIONS.RUN_KNOCKOUT,
    expectedRole: "MUTANT",
    operationBudget,
    resultSha256: request.mutantResultSha256,
    terminalSha256: request.mutantTerminalSha256,
    wire: request.mutant,
    wireField: "knockout",
  });
  const mutantRequest = mutantRecord.workerCapability?.subject?.request;
  const sharedRequestKeys = [
    "baseline", "baselineResultSha256", "baselineTerminalSha256", "dependencies", "entry",
    "pairedEntry", "registrySha256", "suiteTimeoutMs", ...candidateSubjectKeys,
  ];
  if (
    mutantRequest === null || typeof mutantRequest !== "object" || Array.isArray(mutantRequest) ||
    Object.hasOwn(mutantRequest, "candidateSubject") !== Object.hasOwn(request, "candidateSubject") ||
    sharedRequestKeys.some((key) =>
      !canonicalJsonBytes(mutantRequest[key]).equals(canonicalJsonBytes(request[key])))
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
      "postcheck request does not preserve the exact mutant request subject",
    );
  }
}

function validateArmTerminalBytes(bytes, transferState) {
  const validated = validateTerminalBytes(
    bytes,
    transferState.armDescriptor.candidateManifestSha256,
    ["COMPLETE", "REFUSED", "INDETERMINATE"],
    KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_INCOMPLETE,
  );
  const terminal = validated.terminal;
  if (!hasExactObjectKeys(terminal, [
    "armId", "armPlanSha256", "candidateManifestSha256", "diagnostics", "evidenceRole",
    "initialObservationSha256", "lifecycle", "predecessorTerminalSha256",
    "processContainmentScope", "protocol", "reasonCode", "retainedTargetFailure",
    "retainedTargets", "role", "sourceLeaseSha256", "status", "subjectSha256",
    "workerCapabilitySha256", "workerResult",
  ])) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_INCOMPLETE, "arm terminal has an open or incomplete schema");
  }
  const lifecycle = terminal.lifecycle;
  const result = terminal.workerResult;
  const diagnostics = terminal.diagnostics;
  const descriptor = transferState.armDescriptor;
  const capability = transferState.workerCapability;
  const retainedTargets = validateRetainedTargetEvidence(terminal.retainedTargets, {
    armDescriptor: descriptor,
    workerCapability: capability,
    workerResult: terminal.workerResult?.accepted === true ? transferState.workerResult : null,
  });
  const retainedTargetFailure = terminal.retainedTargetFailure;
  const retainedTargetFailureValid = retainedTargetFailure === null || (
    hasExactObjectKeys(retainedTargetFailure, ["code", "phase"]) &&
    ERROR_CODE_SET.has(retainedTargetFailure.code) &&
    retainedTargetFailure.phase === "POST_PROCESS_GROUP_REVALIDATION"
  );
  if (
    terminal.evidenceRole !== "SUPERVISOR_ONLY_ARM_TERMINAL_EVIDENCE" ||
    terminal.processContainmentScope !== "ORIGINAL_POSIX_PROCESS_GROUP_ONLY_REGROUPING_ESCAPE_NOT_EXCLUDED" ||
    typeof terminal.reasonCode !== "string" || !/^[A-Z][A-Z0-9_]*$/.test(terminal.reasonCode) ||
    terminal.armId !== descriptor.armId ||
    terminal.armPlanSha256 !== descriptor.armPlanSha256 ||
    terminal.initialObservationSha256 !== descriptor.initialObservation.observationSha256 ||
    terminal.predecessorTerminalSha256 !== capability.predecessorTerminalSha256 ||
    terminal.role !== descriptor.role ||
    terminal.sourceLeaseSha256 !== descriptor.sourceLeaseSha256 ||
    terminal.subjectSha256 !== descriptor.subjectSha256 ||
    terminal.workerCapabilitySha256 !== capability.workerCapabilitySha256 ||
    !canonicalJsonBytes(retainedTargets).equals(canonicalJsonBytes(transferState.retainedTargets)) ||
    !retainedTargetFailureValid ||
    (terminal.reasonCode === "RETAINED_TARGET_REVALIDATION_FAILED"
      ? retainedTargetFailure === null || terminal.status !== "INDETERMINATE"
      : retainedTargetFailure !== null) ||
    !hasExactObjectKeys(diagnostics, ["stderr", "stdout"]) ||
    !validWorkerStreamEvidence(diagnostics.stderr) ||
    !validWorkerStreamEvidence(diagnostics.stdout) ||
    !hasExactObjectKeys(lifecycle, [
      "directChildClosed", "exitCode", "originalProcessGroupAbsent", "signal", "timedOut",
    ]) ||
    lifecycle.directChildClosed !== true || lifecycle.originalProcessGroupAbsent !== true ||
    !(lifecycle.exitCode === null || Number.isInteger(lifecycle.exitCode)) ||
    !(lifecycle.signal === null || typeof lifecycle.signal === "string") ||
    typeof lifecycle.timedOut !== "boolean" ||
    !hasExactObjectKeys(result, [
      "accepted", "bytes", "complete", "publication", "sha256", "status",
    ]) ||
    typeof result.accepted !== "boolean" ||
    !Number.isSafeInteger(result.bytes) || result.bytes < 0 ||
    typeof result.complete !== "boolean" ||
    !validWorkerResultPublication(result.publication) ||
    !((result.complete && HASH_64.test(result.sha256 ?? "")) ||
      (!result.complete && result.sha256 === null)) ||
    !(result.status === null || ["COMPLETE", "REFUSED"].includes(result.status)) ||
    (result.accepted &&
      (!result.complete || result.bytes < 1 || result.publication === null || result.status === null)) ||
    (result.publication !== null && (
      result.publication.sha256 !== result.sha256 ||
      result.publication.observation.size !== result.bytes
    )) ||
    (terminal.status === "COMPLETE" && !(
      result.accepted && result.status === "COMPLETE" && lifecycle.exitCode === 0 &&
      lifecycle.signal === null && lifecycle.timedOut === false &&
      diagnostics.stdout.complete && diagnostics.stderr.complete &&
      terminal.reasonCode === "WORKER_COMPLETE"
    )) ||
    (terminal.status === "REFUSED" && !(
      result.accepted && result.status === "REFUSED" && lifecycle.exitCode === 0 &&
      lifecycle.signal === null && lifecycle.timedOut === false &&
      diagnostics.stdout.complete && diagnostics.stderr.complete &&
      terminal.reasonCode === "WORKER_REFUSED"
    ))
  ) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_INCOMPLETE, "arm terminal binding or lifecycle is invalid");
  }
  return validated;
}

function publishWorkerResultEvidence(transferState, resultSnapshot, operationBudget) {
  if (!resultSnapshot.complete || resultSnapshot.bytes.length === 0) return null;
  confirmArmDescriptorIdentities(transferState.armDescriptor, operationBudget);
  const published = durablePublishNoClobber(
    transferState.armDescriptor.evidenceRoot,
    "worker-result.bin",
    resultSnapshot.bytes,
    {
      expectedDirectoryIdentity: transferState.armDescriptor.evidenceIdentity,
      maxBytes: MAX_WORKER_RESULT_BYTES,
      operationBudget,
    },
  );
  assertPrivateFile(
    published.path,
    published.sha256,
    published.createdObservation,
    {
      maxBytes: MAX_WORKER_RESULT_BYTES,
      metadataAnchor: Object.freeze({
        identity: transferState.armDescriptor.evidenceIdentity,
        path: transferState.armDescriptor.evidenceRoot,
      }),
      mismatchCode: KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_HASH_MISMATCH,
      operationBudget,
    },
  );
  return Object.freeze({
    filename: "worker-result.bin",
    identity: published.createdIdentity,
    observation: published.createdObservation,
    sha256: published.sha256,
  });
}

function publishArmTerminalEvidence(
  transferState,
  terminalBytes,
  resultPublication,
  operationBudget,
  retainedTargetCustody = null,
) {
  const initiallyValidated = validateArmTerminalBytes(terminalBytes, transferState);
  if (!canonicalJsonBytes(initiallyValidated.terminal.workerResult.publication)
    .equals(canonicalJsonBytes(resultPublication))) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_INCOMPLETE,
      "arm terminal does not bind the exact result publication supplied to its witness",
    );
  }
  const witness = () => {
    confirmArmDescriptorIdentities(transferState.armDescriptor, operationBudget);
    retainedTargetCustody?.confirm("during arm-terminal publication");
    if (resultPublication !== null) {
      assertPrivateFile(
        path.join(transferState.armDescriptor.evidenceRoot, resultPublication.filename),
        resultPublication.sha256,
        resultPublication.observation,
        {
          maxBytes: MAX_WORKER_RESULT_BYTES,
          metadataAnchor: Object.freeze({
            identity: transferState.armDescriptor.evidenceIdentity,
            path: transferState.armDescriptor.evidenceRoot,
          }),
          mismatchCode: KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_HASH_MISMATCH,
          operationBudget,
        },
      );
    }
  };
  const published = durablePublishNoClobber(
    transferState.armDescriptor.evidenceRoot,
    "arm-terminal.json",
    terminalBytes,
    {
      afterCommitWitness: witness,
      beforeCommitWitness: witness,
      expectedDirectoryIdentity: transferState.armDescriptor.evidenceIdentity,
      maxBytes: MAX_TERMINAL_EVIDENCE_BYTES,
      operationBudget,
    },
  );
  const reopened = assertPrivateFile(
    published.path,
    published.sha256,
    published.createdObservation,
    {
      maxBytes: MAX_TERMINAL_EVIDENCE_BYTES,
      metadataAnchor: Object.freeze({
        identity: transferState.armDescriptor.evidenceIdentity,
        path: transferState.armDescriptor.evidenceRoot,
      }),
      mismatchCode: KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_HASH_MISMATCH,
      operationBudget,
    },
  );
  const finallyValidated = validateArmTerminalBytes(reopened.bytes, transferState);
  return Object.freeze({
    bytes: reopened.bytes.length,
    identity: reopened.observation.identity,
    observation: reopened.observation,
    path: published.path,
    sha256: reopened.sha256,
    terminal: finallyValidated.terminal,
  });
}

async function containWorkerAfterSetupFailure(child, closeObservation) {
  for (const stream of [child.stdio?.[3], child.stdio?.[4], child.stdout, child.stderr]) {
    try { stream?.destroy(); }
    catch {}
  }
  signalWorkerProcessGroup(child, "SIGTERM");
  if (!await waitForWorkerProcessGroupExit(child.pid, 2_000)) {
    signalWorkerProcessGroup(child, "SIGKILL");
    await waitForWorkerProcessGroupExit(child.pid, 2_000);
  }
  let directChildClosed = closeObservation.current() !== null;
  if (!directChildClosed) {
    try {
      await waitWithTimeout(closeObservation.promise, 2_000, "worker setup-failure direct-child close");
      directChildClosed = true;
    } catch {}
  }
  return Object.freeze({
    directChildClosed,
    originalProcessGroupAbsent: await waitForWorkerProcessGroupExit(child.pid, 250),
  });
}

/**
 * Run one materialized arm through the fixed descriptor-bound worker transport. Authority enters on
 * FD 3 and the only accepted result leaves on FD 4. The worker never publishes its own terminal;
 * this supervisor does so only after direct-child close and absence of the original POSIX process
 * group. That process-group fact is deliberately not a claim that a hostile `setsid` escape is gone.
 */
export async function runArmWorker(cooperativeLease, armCapability, options) {
  if (process.platform === "win32") {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
      "arm worker supervision currently requires POSIX process-group semantics",
    );
  }
  const cooperativeState = requireHeldCooperativeSourceLease(cooperativeLease);
  const armState = armCapabilityStates.get(armCapability);
  if (
    armState === undefined || armState.valid !== true ||
    armState.leaseState !== cooperativeState.leaseState ||
    armState.record.capability !== armCapability || armState.record.status !== "MATERIALIZED"
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
      "runArmWorker requires the exact unused arm capability under this cooperative lease",
    );
  }
  const custodyState = cooperativeState.leaseState.custodyState;
  if (
    custodyState.activeWorkerTransfer !== null ||
    custodyState.workerExecutionBlock !== null
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
      "another worker is active or an earlier worker blocked execution",
      { block: custodyState.workerExecutionBlock },
    );
  }
  const snapshot = strictDataObjectSnapshot(
    options,
    "arm-worker options",
    ["subject", "timeoutMs"],
    ["subject"],
  );
  const timeoutMs = requireArmWorkerTimeoutMs(snapshot.timeoutMs ?? custodyState.commandTimeoutMs);
  const subject = validateWorkerSubjectValue(snapshot.subject, armState.record.subjectSha256);
  const record = armState.record;
  const predecessorTerminalSha256 = custodyState.lastTerminalSha256;
  const transferCapability = Object.freeze({
    armId: record.armId,
    kind: "ACTIVE_ARM_WORKER_TRANSFER",
    nonce: crypto.randomBytes(32).toString("hex"),
  });
  const transferState = {
    armDescriptor: armState.descriptor,
    cooperativeState,
    retainedTargets: null,
    status: "PREPARING",
    workerCapability: null,
    workerResult: null,
  };
  workerTransferStates.set(transferCapability, transferState);
  custodyState.activeWorkerTransfer = transferCapability;
  armState.valid = false;
  record.status = "PREPARING";

  const operationBudget = createOperationBudget(custodyState.commandTimeoutMs);
  let initialArm;
  try {
    validateWorkerEvidenceReferences(
      custodyState,
      subject.subject.operation,
      subject.subject.request,
      predecessorTerminalSha256,
      operationBudget,
    );
    await confirmCooperativeSourceLeaseState(cooperativeState);
    confirmLeaseBoundaries(cooperativeState.leaseState, operationBudget);
    initialArm = observeExactInitialArm(armState, operationBudget);
    const workerNode = initialArm.nodes.find((node) => node.path === subject.workerRelativePath);
    if (workerNode?.type !== "file" || workerNode.sha256 !== subject.subject.worker.sha256) {
      fail(
        KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
        "the admitted worker executable is absent or has different bytes in the arm",
      );
    }
    await confirmCooperativeSourceLeaseState(cooperativeState);
  } catch (error) {
    record.status = "FAILED_RETAINED";
    custodyState.workerExecutionBlock = cooperativeState.status === "LOST"
      ? "COOPERATIVE_SOURCE_LEASE_LOST"
      : "WORKER_PREPARATION_FAILED";
    transferState.status = "FAILED_RETAINED";
    custodyState.activeWorkerTransfer = null;
    const reported = error instanceof KnockoutWorkspaceError
      ? error
      : workspaceError(
          KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_INCOMPLETE,
          `arm ${record.armId} worker preparation failed before spawn`,
          null,
          error,
        );
    throw reportRetainedPrivateRoots(reported, custodyState.retainedRoots);
  }
  transferState.status = "ISSUING";
  record.status = "ISSUING";

  let child;
  try {
    child = spawn(
      METADATA_FCHDIR_LAUNCHER,
      ["-e", WORKER_FCHDIR_SCRIPT, process.execPath, subject.workerRelativePath],
      {
        detached: true,
        env: { LANG: "C", LC_ALL: "C", PATH: "/usr/bin:/bin" },
        shell: false,
        stdio: [
          "ignore", "pipe", "pipe", "pipe", "pipe", "ignore", "ignore",
          armState.descriptor.armWorkspaceBound.fd,
        ],
        windowsHide: true,
      },
    );
  } catch (error) {
    record.status = "FAILED_RETAINED";
    custodyState.workerExecutionBlock = "WORKER_SPAWN_FAILED";
    custodyState.activeWorkerTransfer = null;
    transferState.status = "FAILED_RETAINED";
    throw reportRetainedPrivateRoots(
      workspaceError(
        KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_INCOMPLETE,
        `arm ${record.armId} worker could not be spawned`,
        null,
        error,
      ),
      custodyState.retainedRoots,
    );
  }

  let spawnFailure = null;
  const closeObservation = createChildCloseObservation(child);
  child.once("error", (error) => {
    if (spawnFailure === null) spawnFailure = error;
  });

  if (!Number.isSafeInteger(child.pid) || child.pid < 1) {
    try { child.kill("SIGKILL"); }
    catch {}
    let closeProven = false;
    try {
      await waitWithTimeout(closeObservation.promise, 2_000, "worker spawn-failure close");
      closeProven = true;
    } catch {}
    record.status = closeProven ? "FAILED_RETAINED" : "PROCESS_UNCERTAIN";
    custodyState.workerExecutionBlock = "WORKER_PID_UNAVAILABLE";
    transferState.status = record.status;
    if (closeProven) custodyState.activeWorkerTransfer = null;
    throw reportRetainedPrivateRoots(
      workspaceError(
        KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_INCOMPLETE,
        `arm ${record.armId} worker has no verifiable process identity`,
      ),
      custodyState.retainedRoots,
    );
  }

  let workerCapability;
  let workerCapabilityBytes;
  let workerCapabilitySha256;
  try {
    if (
      child.stdout === null || child.stderr === null ||
      child.stdio[3] === null || child.stdio[4] === null
    ) throw new Error("worker authority or diagnostic pipe was not created");
    const capabilityWithoutHash = Object.freeze({
      armId: record.armId,
      armPlanSha256: record.armPlanSha256,
      armRoot: armState.descriptor.armRoot,
      armRootIdentity: armState.descriptor.armRootIdentity,
      candidateManifestSha256: armState.descriptor.candidateManifestSha256,
      evidenceIdentity: armState.descriptor.evidenceIdentity,
      evidenceRoot: armState.descriptor.evidenceRoot,
      initialWorkspace: workerInitialWorkspaceSummary(initialArm),
      limits: custodyState.limits,
      nonce: transferCapability.nonce,
      predecessorTerminalSha256,
      protocol: KNOCKOUT_WORKSPACE_PROTOCOLS.workerCapability,
      role: record.role,
      seedObservationSha256: armState.descriptor.seedObservationSha256,
      sourceLeaseSha256: armState.descriptor.sourceLeaseSha256,
      sourceSnapshotSha256: armState.descriptor.sourceSnapshotSha256,
      subject: subject.subject,
      subjectSha256: subject.subjectSha256,
      supervisorPid: process.pid,
      workerPid: child.pid,
      workspaceIdentity: armState.descriptor.workspaceIdentity,
      workspaceRoot: armState.descriptor.workspaceRoot,
    });
    workerCapabilitySha256 = sha256(canonicalJsonBytes(capabilityWithoutHash));
    workerCapability = Object.freeze({
      ...capabilityWithoutHash,
      workerCapabilitySha256,
    });
    workerCapabilityBytes = canonicalJsonBytes(workerCapability);
    workerCapability = validateWorkerCapabilityBytes(workerCapabilityBytes).capability;
    workerCapabilityBytes = canonicalJsonBytes(workerCapability);
  } catch (error) {
    const containment = await containWorkerAfterSetupFailure(child, closeObservation);
    const contained = containment.directChildClosed && containment.originalProcessGroupAbsent;
    record.status = contained ? "FAILED_RETAINED" : "PROCESS_UNCERTAIN";
    custodyState.workerExecutionBlock = "WORKER_SETUP_FAILED";
    transferState.status = record.status;
    if (contained) custodyState.activeWorkerTransfer = null;
    throw reportRetainedPrivateRoots(
      workspaceError(
        KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_INCOMPLETE,
        `arm ${record.armId} worker setup failed after spawn`,
        containment,
        error,
      ),
      custodyState.retainedRoots,
    );
  }
  transferState.workerCapability = workerCapability;
  transferState.status = "RUNNING";
  record.status = "RUNNING";

  let abnormalReason = null;
  let capabilityDeliveryFailure = null;
  let directChildClosed = false;
  let heartbeatStopped = false;
  let leaseFailure = null;
  let terminationPromise = null;
  let timedOut = false;
  const requestTermination = (reason) => {
    if (abnormalReason === null) abnormalReason = reason;
    if (terminationPromise === null) {
      terminationPromise = (async () => {
        signalWorkerProcessGroup(child, "SIGTERM");
        if (!await waitForWorkerProcessGroupExit(child.pid, 2_000)) {
          signalWorkerProcessGroup(child, "SIGKILL");
          await waitForWorkerProcessGroupExit(child.pid, 2_000);
        }
      })();
    }
    return terminationPromise;
  };
  const resultCollector = createBoundedProcessStreamCollector(
    child.stdio[4],
    MAX_WORKER_RESULT_BYTES,
    `arm ${record.armId} worker result`,
    () => requestTermination("WORKER_RESULT_STREAM_FAILED"),
  );
  const stdoutCollector = createBoundedProcessStreamCollector(
    child.stdout,
    MAX_WORKER_DIAGNOSTIC_BYTES,
    `arm ${record.armId} worker stdout`,
    () => requestTermination("WORKER_STDOUT_STREAM_FAILED"),
  );
  const stderrCollector = createBoundedProcessStreamCollector(
    child.stderr,
    MAX_WORKER_DIAGNOSTIC_BYTES,
    `arm ${record.armId} worker stderr`,
    () => requestTermination("WORKER_STDERR_STREAM_FAILED"),
  );
  const deliveryPromise = writeChildPipeExactly(
    child.stdio[3],
    workerCapabilityBytes,
    `arm ${record.armId} worker capability`,
  ).catch((error) => {
    capabilityDeliveryFailure = error;
    requestTermination("WORKER_CAPABILITY_DELIVERY_FAILED");
  });
  const timeout = setTimeout(() => {
    timedOut = true;
    requestTermination("WORKER_TIMEOUT");
  }, timeoutMs);
  const heartbeatMs = Math.min(5_000, Math.max(1_000, Math.floor(timeoutMs / 4)));
  const heartbeatPromise = (async () => {
    while (!directChildClosed && !heartbeatStopped) {
      await Promise.race([workerDelay(heartbeatMs), closeObservation.promise]);
      if (directChildClosed || heartbeatStopped || closeObservation.current() !== null) return;
      try { await confirmCooperativeSourceLeaseState(cooperativeState); }
      catch (error) {
        leaseFailure = error;
        requestTermination("COOPERATIVE_SOURCE_LEASE_LOST");
        return;
      }
    }
  })();

  let closeOutcome = null;
  try {
    closeOutcome = await waitWithTimeout(
      closeObservation.promise,
      timeoutMs + 4_500,
      `arm ${record.armId} direct-child close`,
    );
    directChildClosed = true;
  } catch (error) {
    requestTermination("DIRECT_CHILD_CLOSE_UNPROVEN");
    try {
      closeOutcome = await waitWithTimeout(
        closeObservation.promise,
        2_500,
        `arm ${record.armId} direct-child forced close`,
      );
      directChildClosed = true;
    } catch {
      if (abnormalReason === null) abnormalReason = "DIRECT_CHILD_CLOSE_UNPROVEN";
    }
  } finally {
    clearTimeout(timeout);
  }
  try { await waitWithTimeout(deliveryPromise, 1_000, `arm ${record.armId} capability delivery close`); }
  catch {
    capabilityDeliveryFailure ??= new Error("worker capability delivery did not close");
    try { child.stdio[3]?.destroy(); }
    catch {}
    await requestTermination("WORKER_CAPABILITY_DELIVERY_FAILED");
  }
  if (terminationPromise !== null) await terminationPromise;
  if (!directChildClosed && closeObservation.current() !== null) {
    closeOutcome = closeObservation.current();
    directChildClosed = true;
  }
  if (
    directChildClosed && workerProcessGroupExists(child.pid) &&
    abnormalReason === null
  ) {
    await requestTermination("ORIGINAL_PROCESS_GROUP_SURVIVED_LEADER");
  }
  const originalProcessGroupAbsent = directChildClosed &&
    await waitForWorkerProcessGroupExit(child.pid, 250);
  heartbeatStopped = true;
  try { await waitWithTimeout(heartbeatPromise, heartbeatMs + 250, `arm ${record.armId} lease heartbeat stop`); }
  catch (error) { leaseFailure ??= error; }
  const streamDrain = Promise.all([
    resultCollector.finished, stdoutCollector.finished, stderrCollector.finished,
  ]);
  try { await waitWithTimeout(streamDrain, 1_000, `arm ${record.armId} worker stream drain`); }
  catch {
    if (abnormalReason === null) abnormalReason = "WORKER_STREAM_EOF_UNPROVEN";
    for (const stream of [child.stdio[4], child.stdout, child.stderr]) {
      try { stream?.destroy(); }
      catch {}
    }
    try { await waitWithTimeout(streamDrain, 1_000, `arm ${record.armId} forced worker stream close`); }
    catch {}
  }

  if (!directChildClosed || !originalProcessGroupAbsent) {
    record.status = "PROCESS_UNCERTAIN";
    custodyState.workerExecutionBlock = "ORIGINAL_PROCESS_GROUP_ABSENCE_UNPROVEN";
    transferState.status = "PROCESS_UNCERTAIN";
    throw reportRetainedPrivateRoots(
      workspaceError(
        KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_INCOMPLETE,
        `arm ${record.armId} worker process closure is indeterminate`,
        {
          directChildClosed,
          originalProcessGroupAbsent,
          processContainmentScope: "ORIGINAL_POSIX_PROCESS_GROUP_ONLY_REGROUPING_ESCAPE_NOT_EXCLUDED",
        },
      ),
      custodyState.retainedRoots,
    );
  }

  const resultSnapshot = resultCollector.snapshot();
  const stdoutSnapshot = stdoutCollector.snapshot();
  const stderrSnapshot = stderrCollector.snapshot();
  if (!resultSnapshot.eof || !stdoutSnapshot.eof || !stderrSnapshot.eof) {
    record.status = "PROCESS_UNCERTAIN";
    custodyState.workerExecutionBlock = "WORKER_STREAM_EOF_UNPROVEN";
    transferState.status = "PROCESS_UNCERTAIN";
    throw reportRetainedPrivateRoots(
      workspaceError(
        KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_INCOMPLETE,
        `arm ${record.armId} worker left an authority or diagnostic stream without proven EOF`,
        {
          resultEof: resultSnapshot.eof,
          stderrEof: stderrSnapshot.eof,
          stdoutEof: stdoutSnapshot.eof,
        },
      ),
      custodyState.retainedRoots,
    );
  }

  if (leaseFailure !== null) {
    record.status = "FAILED_RETAINED";
    custodyState.workerExecutionBlock = "COOPERATIVE_SOURCE_LEASE_LOST";
    transferState.status = "FAILED_RETAINED";
    custodyState.activeWorkerTransfer = null;
    throw reportRetainedPrivateRoots(leaseFailure, custodyState.retainedRoots);
  }

  let acceptedWorkerResult = null;
  let resultValidationFailure = null;
  if (resultSnapshot.complete) {
    try { acceptedWorkerResult = validateWorkerResultBytes(resultSnapshot.bytes, workerCapability); }
    catch (error) { resultValidationFailure = error; }
  }
  if (resultSnapshot.failure !== null && abnormalReason === null) {
    abnormalReason = "WORKER_RESULT_STREAM_FAILED";
  }
  if (stdoutSnapshot.failure !== null && abnormalReason === null) {
    abnormalReason = "WORKER_STDOUT_STREAM_FAILED";
  }
  if (stderrSnapshot.failure !== null && abnormalReason === null) {
    abnormalReason = "WORKER_STDERR_STREAM_FAILED";
  }
  if (capabilityDeliveryFailure !== null && abnormalReason === null) {
    abnormalReason = "WORKER_CAPABILITY_DELIVERY_FAILED";
  }
  if (spawnFailure !== null && abnormalReason === null) abnormalReason = "WORKER_SPAWN_FAILED";
  if (timedOut && abnormalReason === null) abnormalReason = "WORKER_TIMEOUT";
  if (
    (closeOutcome?.code !== 0 || closeOutcome?.signal !== null) &&
    abnormalReason === null
  ) abnormalReason = "WORKER_EXIT_ABNORMAL";
  if (resultValidationFailure !== null && abnormalReason === null) {
    abnormalReason = "WORKER_RESULT_INVALID";
  }

  try { await confirmCooperativeSourceLeaseState(cooperativeState); }
  catch (error) {
    record.status = "FAILED_RETAINED";
    custodyState.workerExecutionBlock = "COOPERATIVE_SOURCE_LEASE_LOST";
    transferState.status = "FAILED_RETAINED";
    custodyState.activeWorkerTransfer = null;
    throw reportRetainedPrivateRoots(error, custodyState.retainedRoots);
  }
  const publicationBudget = createOperationBudget(custodyState.commandTimeoutMs);
  confirmLeaseBoundaries(cooperativeState.leaseState, publicationBudget);
  confirmArmDescriptorIdentities(armState.descriptor, publicationBudget);
  let retainedTargetCustody = null;
  let retainedTargetFailure = null;
  let retainedTargets = null;
  if (abnormalReason === null && acceptedWorkerResult !== null) {
    try {
      const retained = acquireRetainedMutantTargetEvidence(
        armState,
        workerCapability,
        acceptedWorkerResult,
        publicationBudget,
      );
      retainedTargetCustody = retained.custody;
      retainedTargets = retained.evidence;
    } catch (error) {
      retainedTargetFailure = retainedTargetFailureEvidence(error);
      abnormalReason = "RETAINED_TARGET_REVALIDATION_FAILED";
    }
  }
  transferState.retainedTargets = retainedTargets;
  transferState.workerResult = acceptedWorkerResult;
  let resultPublication;
  let terminalPublication;
  let publicationFailure = null;
  try {
    retainedTargetCustody?.confirm("before worker-result publication");
    resultPublication = publishWorkerResultEvidence(
      transferState,
      resultSnapshot,
      publicationBudget,
    );
    retainedTargetCustody?.confirm("after worker-result publication");
    const cleanAcceptedResult = abnormalReason === null && acceptedWorkerResult !== null;
    const terminalStatus = cleanAcceptedResult ? acceptedWorkerResult.status : "INDETERMINATE";
    const reasonCode = terminalStatus === "COMPLETE"
      ? "WORKER_COMPLETE"
      : terminalStatus === "REFUSED"
        ? "WORKER_REFUSED"
        : abnormalReason ?? "WORKER_RESULT_INVALID";
    const terminal = Object.freeze({
      armId: record.armId,
      armPlanSha256: record.armPlanSha256,
      candidateManifestSha256: armState.descriptor.candidateManifestSha256,
      diagnostics: Object.freeze({
        stderr: workerStreamEvidence(stderrSnapshot),
        stdout: workerStreamEvidence(stdoutSnapshot),
      }),
      evidenceRole: "SUPERVISOR_ONLY_ARM_TERMINAL_EVIDENCE",
      initialObservationSha256: armState.descriptor.initialObservation.observationSha256,
      lifecycle: Object.freeze({
        directChildClosed: true,
        exitCode: Number.isInteger(closeOutcome?.code) ? closeOutcome.code : null,
        originalProcessGroupAbsent: true,
        signal: closeOutcome?.signal ?? null,
        timedOut,
      }),
      predecessorTerminalSha256,
      processContainmentScope: "ORIGINAL_POSIX_PROCESS_GROUP_ONLY_REGROUPING_ESCAPE_NOT_EXCLUDED",
      protocol: KNOCKOUT_WORKSPACE_PROTOCOLS.terminal,
      reasonCode,
      retainedTargetFailure,
      retainedTargets,
      role: record.role,
      sourceLeaseSha256: armState.descriptor.sourceLeaseSha256,
      status: terminalStatus,
      subjectSha256: armState.descriptor.subjectSha256,
      workerCapabilitySha256,
      workerResult: Object.freeze({
        accepted: cleanAcceptedResult,
        bytes: resultSnapshot.observedBytes,
        complete: resultSnapshot.complete,
        publication: resultPublication,
        sha256: resultSnapshot.complete ? sha256(resultSnapshot.bytes) : null,
        status: acceptedWorkerResult?.status ?? null,
      }),
    });
    const terminalBytes = canonicalJsonBytes(terminal);
    terminalPublication = publishArmTerminalEvidence(
      transferState,
      terminalBytes,
      resultPublication,
      publicationBudget,
      retainedTargetCustody,
    );
    retainedTargetCustody?.confirm("after arm-terminal publication");
  } catch (error) {
    publicationFailure = error;
  }
  if (retainedTargetCustody !== null) {
    try { retainedTargetCustody.release(publicationFailure); }
    catch (error) { publicationFailure = error; }
  }
  if (publicationFailure !== null) {
    record.status = "TERMINAL_INDETERMINATE";
    custodyState.workerExecutionBlock = "TERMINAL_PUBLICATION_FAILED";
    transferState.status = "TERMINAL_INDETERMINATE";
    custodyState.activeWorkerTransfer = null;
    throw reportRetainedPrivateRoots(publicationFailure, custodyState.retainedRoots);
  }

  record.status = "TERMINAL";
  record.retainedTargets = retainedTargets;
  record.terminalPublication = terminalPublication;
  record.workerCapability = workerCapability;
  record.workerResult = acceptedWorkerResult;
  record.workerResultPublication = resultPublication;
  custodyState.lastTerminalSha256 = terminalPublication.sha256;
  transferState.status = "TERMINAL";
  custodyState.activeWorkerTransfer = null;
  if (terminalPublication.terminal.status !== "COMPLETE") {
    custodyState.workerExecutionBlock = `WORKER_${terminalPublication.terminal.status}`;
  }
  return Object.freeze({
    armId: record.armId,
    originalProcessGroupAbsent: true,
    processContainmentScope: "ORIGINAL_POSIX_PROCESS_GROUP_ONLY_REGROUPING_ESCAPE_NOT_EXCLUDED",
    resultPublication,
    status: terminalPublication.terminal.status,
    terminalPublication,
    workerResult: acceptedWorkerResult,
    workspaceRoot: armState.descriptor.workspaceRoot,
  });
}

function reopenArmTerminalRecord(
  record,
  operationBudget,
  { verifyRetainedTargets = true } = {},
) {
  const armState = armCapabilityStates.get(record.capability);
  if (
    armState === undefined || record.terminalPublication === undefined ||
    record.workerCapability === undefined
  ) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_INCOMPLETE, "terminal arm record is incomplete");
  }
  confirmArmDescriptorIdentities(armState.descriptor, operationBudget);
  let reopenedWorkerResult = null;
  if (record.workerResultPublication !== null) {
    const reopenedResult = assertPrivateFile(
      path.join(armState.descriptor.evidenceRoot, record.workerResultPublication.filename),
      record.workerResultPublication.sha256,
      record.workerResultPublication.observation,
      {
        maxBytes: MAX_WORKER_RESULT_BYTES,
        metadataAnchor: Object.freeze({
          identity: armState.descriptor.evidenceIdentity,
          path: armState.descriptor.evidenceRoot,
        }),
        mismatchCode: KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_HASH_MISMATCH,
        operationBudget,
      },
    );
    // A complete transport may still contain deliberately rejected bytes. The terminal binds their
    // exact publication/hash, but only bytes accepted during the live PID-bound transfer are parsed
    // again as a worker result. Reclassifying rejected bytes during close would upgrade them into a
    // second decision path and make a correctly INDETERMINATE terminal impossible to release.
    if (record.workerResult !== null) {
      reopenedWorkerResult = validateWorkerResultBytes(reopenedResult.bytes, record.workerCapability);
      if (!canonicalJsonBytes(reopenedWorkerResult).equals(canonicalJsonBytes(record.workerResult))) {
        fail(
          KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_HASH_MISMATCH,
          "reopened worker result differs from the accepted retained result",
        );
      }
    }
  }
  const reopened = assertPrivateFile(
    record.terminalPublication.path,
    record.terminalPublication.sha256,
    record.terminalPublication.observation,
    {
      maxBytes: MAX_TERMINAL_EVIDENCE_BYTES,
      metadataAnchor: Object.freeze({
        identity: armState.descriptor.evidenceIdentity,
        path: armState.descriptor.evidenceRoot,
      }),
      mismatchCode: KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_HASH_MISMATCH,
      operationBudget,
    },
  );
  const validatedTerminal = validateArmTerminalBytes(reopened.bytes, Object.freeze({
    armDescriptor: armState.descriptor,
    retainedTargets: record.retainedTargets,
    workerCapability: record.workerCapability,
    workerResult: reopenedWorkerResult,
  }));
  if (verifyRetainedTargets && validatedTerminal.terminal.retainedTargets !== null) {
    confirmRetainedMutantTargetEvidence(
      armState,
      record.workerCapability,
      reopenedWorkerResult,
      validatedTerminal.terminal.retainedTargets,
      operationBudget,
      "during terminal reopen",
    );
  }
  return Object.freeze({
    terminal: validatedTerminal.terminal,
    terminalSha256: reopened.sha256,
    workerResult: reopenedWorkerResult,
    workerResultSha256: record.workerResultPublication?.sha256 ?? null,
  });
}

/** Revalidate source and sealed seed, close every descriptor, invalidate authority, delete nothing. */
function releaseSourceLeaseInternal(sourceLease, cooperativeState = null) {
  const leaseState = sourceLeaseStates.get(sourceLease);
  if (leaseState === undefined || leaseState.status !== "ACTIVE") {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
      "releaseSourceLease requires the exact active same-process source lease capability",
    );
  }
  if (
    leaseState.cooperativeLeaseState !== null &&
    leaseState.cooperativeLeaseState !== cooperativeState
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
      "the same-process source lease cannot be released outside its active cooperative lifecycle",
    );
  }
  const custodyState = leaseState.custodyState;
  if (custodyState.activeWorkerTransfer !== null) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
      "source lease cannot release while a worker transfer is active or process closure is uncertain",
    );
  }
  const operationBudget = createOperationBudget(custodyState.commandTimeoutMs);
  leaseState.status = "RELEASING";
  let primaryError = null;
  let finalSource = null;
  let finalSeed = null;
  const addFailure = (error) => {
    if (primaryError === null) {
      primaryError = error;
      return;
    }
    primaryError = combineWorkspaceFailures(
      primaryError,
      [error],
      KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
      "source lease failed more than one final verification",
    );
  };
  try { confirmLeaseBoundaries(leaseState, operationBudget); }
  catch (error) { addFailure(error); }
  try {
    finalSource = verifySourceUnchanged(leaseState.sourceSnapshot, {
      commandTimeoutMs: custodyState.commandTimeoutMs,
      gitExecutable: custodyState.gitExecutable,
      limits: custodyState.limits,
      metadataCache: custodyState.metadataCache,
      operationBudget,
      scratchRoot: custodyState.captureDescriptor.custodyRoot,
    });
    custodyState.retainedRoots.push(...retainedPrivateRoots(finalSource));
  } catch (error) {
    custodyState.retainedRoots.push(...retainedPrivateRoots(error?.details));
    addFailure(error);
  }
  try {
    finalSeed = verifySealedSeedDescriptor(custodyState.captureDescriptor, {
      commandTimeoutMs: custodyState.commandTimeoutMs,
      gitExecutable: custodyState.gitExecutable,
      metadataCache: custodyState.metadataCache,
      operationBudget,
    });
    custodyState.retainedRoots.push(...retainedPrivateRoots(finalSeed));
  } catch (error) {
    custodyState.retainedRoots.push(...retainedPrivateRoots(error?.details));
    addFailure(error);
  }
  // Re-open retained mutant targets again at the final descriptor-release boundary. The terminal
  // proves a point-in-time post-process-group observation; this second observation narrows the close
  // window without claiming protection from a later non-cooperating same-UID writer.
  for (const record of custodyState.allArmRecords.values()) {
    if (record.status !== "TERMINAL" || record.retainedTargets === null) continue;
    try {
      const armState = armCapabilityStates.get(record.capability);
      if (armState === undefined || record.workerCapability === undefined) {
        fail(
          KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_INCOMPLETE,
          "retained-target arm record is incomplete at final source-lease release",
        );
      }
      confirmRetainedMutantTargetEvidence(
        armState,
        record.workerCapability,
        record.workerResult,
        record.retainedTargets,
        operationBudget,
        "immediately before source-lease descriptor release",
      );
    } catch (error) { addFailure(error); }
  }
  try { leaseState.descriptorLease.release(primaryError); }
  catch (error) { primaryError = error; }

  if (activeModuleSourceLeases.get(leaseState.sourceLeaseKey) === sourceLease) {
    activeModuleSourceLeases.delete(leaseState.sourceLeaseKey);
  }
  leaseState.status = "RELEASED";
  custodyState.activeSourceLease = null;
  custodyState.status = "RELEASED";
  for (const planState of leaseState.planStates) planState.valid = false;
  for (const armCapability of custodyState.armCapabilities) {
    const armState = armCapabilityStates.get(armCapability);
    if (armState !== undefined) armState.valid = false;
  }

  if (primaryError !== null) {
    throw reportRetainedPrivateRoots(primaryError, custodyState.retainedRoots);
  }
  return Object.freeze({
    candidateManifestSha256: custodyState.captureDescriptor.candidateManifestSha256,
    retainedPrivateRoots: uniqueRetainedPrivateRoots(custodyState.retainedRoots),
    seedObservationSha256: finalSeed.observationSha256,
    sourceSnapshotSha256: finalSource.snapshotSha256,
    status: "RELEASED",
  });
}

export function releaseSourceLease(sourceLease) {
  return releaseSourceLeaseInternal(sourceLease);
}

/**
 * Close the same-process lease while its cooperative lock is still held, reap the helper, and only
 * then close the parent's shared locked descriptor. Supervisors must publish all arm terminals
 * before calling this function; any nonterminal admitted arm makes release refuse without unlocking.
 */
export async function closeCooperativeSourceLease(cooperativeLease) {
  const state = requireCooperativeSourceLease(cooperativeLease);
  const initialStatus = state.status;
  if (state.commandInFlight) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
      "cooperative source lease cannot close during a control command",
    );
  }
  if (state.leaseState.custodyState.activeWorkerTransfer !== null) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
      "cooperative source lease cannot close while worker authority is active or process closure is uncertain",
    );
  }
  const outstanding = [...state.leaseState.custodyState.allArmRecords.values()]
    .filter((record) => !["CANCELLED", "FAILED_RETAINED", "TERMINAL"].includes(record.status))
    .map((record) => record.armId);
  if (outstanding.length !== 0) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
      "cooperative source lease cannot close before every admitted arm is terminal",
      { outstandingArmIds: Object.freeze(outstanding.sort()) },
    );
  }

  // Own the lifecycle before the first await. This is the close linearization point: no plan,
  // materialization, cancellation or worker launch may race past the pending helper challenge.
  state.status = initialStatus === "HELD" ? "CLOSING" : "CLOSING_LOST";

  let primaryError = null;
  let sourceRelease = null;
  const addFailure = (error) => {
    primaryError = primaryError === null
      ? error
      : combineWorkspaceFailures(
          primaryError,
          [error],
          KNOCKOUT_WORKSPACE_ERROR_CODES.CAPABILITY_INVALID,
          "cooperative source lease failed more than one close boundary",
        );
  };
  const terminalBudget = createOperationBudget(state.leaseState.custodyState.commandTimeoutMs);
  for (const record of state.leaseState.custodyState.allArmRecords.values()) {
    if (record.status !== "TERMINAL") continue;
    try { reopenArmTerminalRecord(record, terminalBudget, { verifyRetainedTargets: false }); }
    catch (error) { addFailure(error); }
  }
  if (initialStatus === "HELD") {
    try {
      await confirmCooperativeSourceLeaseState(state, {
        expectedStatus: "CLOSING",
        failureStatus: "CLOSING_LOST",
      });
    }
    catch (error) { addFailure(error); }
  }
  try { sourceRelease = releaseSourceLeaseInternal(state.leaseState.sourceLease, state); }
  catch (error) { addFailure(error); }

  const helperOutcome = await stopCooperativeLeaseHolder(state);
  if (helperOutcome === null) {
    state.status = "REAP_UNKNOWN";
    addFailure(cooperativeLeaseFailure(
      "cooperative source-lease helper could not be proven reaped; the parent lock descriptor is retained",
      state,
      undefined,
      { helperReaped: false },
    ));
  } else {
    if (helperOutcome.code !== 0 || helperOutcome.signal !== null) {
      addFailure(cooperativeLeaseFailure(
        "cooperative source-lease helper did not close normally",
        state,
        undefined,
        { helperReaped: true },
      ));
    }
    try { state.stderrCollector.assertEmpty(); }
    catch (error) {
      addFailure(cooperativeLeaseFailure(
        "cooperative source-lease helper emitted diagnostics",
        state,
        error,
        { helperReaped: true },
      ));
    }
    try { state.holderDescriptorLease.release(primaryError); }
    catch (error) { primaryError = error; }
    state.status = "RELEASED";
    state.leaseState.cooperativeLeaseState = null;
  }

  if (primaryError !== null) throw primaryError;
  return Object.freeze({
    helperExitCode: helperOutcome.code,
    helperReaped: true,
    helperSignal: helperOutcome.signal,
    lockScope: "COOPERATING_LOCAL_PROCESSES_SAME_PHYSICAL_SOURCE_DIRECTORY",
    sourceRelease,
    status: "RELEASED",
  });
}

function sealedManifest(
  directory,
  expectedCandidateSha256,
  expectedFileSha256,
  expectedObservation,
  expectedDirectoryIdentity,
  operationBudget = null,
) {
  const requestedDirectory = requireAbsolutePath(directory, "candidate-manifest directory");
  const publicationDirectory = requireRealDirectory(
    requestedDirectory,
    "candidate-manifest directory",
    { expectedIdentity: expectedDirectoryIdentity, operationBudget, privateMode: true },
  );
  if (
    publicationDirectory.path !== requestedDirectory ||
    publicationDirectory.identity !== expectedDirectoryIdentity
  ) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
      `candidate-manifest directory identity changed at ${publicationDirectory.path}`,
    );
  }
  const manifestPath = path.join(publicationDirectory.path, "candidate-manifest.json");
  let directoryFd;
  let observed;
  try {
    directoryFd = fs.openSync(
      publicationDirectory.path,
      fs.constants.O_RDONLY | DIRECTORY | NOFOLLOW,
    );
    assertBoundPublicationDirectory(
      directoryFd,
      publicationDirectory.path,
      expectedDirectoryIdentity,
      operationEffectiveUid(operationBudget, "candidate-manifest directory owner bind"),
    );
    observed = assertPrivateFile(
      manifestPath,
      expectedFileSha256,
      expectedObservation,
      {
        metadataAnchor: publicationDirectory,
        mismatchCode: KNOCKOUT_WORKSPACE_ERROR_CODES.MANIFEST_MISMATCH,
        operationBudget,
      },
    );
    assertBoundPublicationDirectory(
      directoryFd,
      publicationDirectory.path,
      expectedDirectoryIdentity,
      operationEffectiveUid(operationBudget, "candidate-manifest directory owner rebind"),
    );
    const closingFd = directoryFd;
    directoryFd = undefined;
    fs.closeSync(closingFd);
  } catch (error) {
    if (
      error instanceof KnockoutWorkspaceError &&
      [
        KNOCKOUT_WORKSPACE_ERROR_CODES.OPERATION_DEADLINE_EXCEEDED,
        KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
        KNOCKOUT_WORKSPACE_ERROR_CODES.RESOURCE_LIMIT_EXCEEDED,
      ].includes(error.code)
    ) throw error;
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.MANIFEST_MISMATCH,
      "candidate manifest could not be verified",
      null,
      error,
    );
  } finally {
    if (directoryFd !== undefined) {
      const closingFd = directoryFd;
      directoryFd = undefined;
      try { fs.closeSync(closingFd); }
      catch {}
    }
  }
  let manifest;
  try { manifest = deepFreezeJson(JSON.parse(observed.bytes.toString("utf8"))); }
  catch (error) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.MANIFEST_MISMATCH,
      "candidate manifest is not JSON",
      null,
      error,
    );
  }
  if (
    manifest === null || typeof manifest !== "object" || Array.isArray(manifest) ||
    manifest.protocol !== KNOCKOUT_WORKSPACE_PROTOCOLS.candidateManifest ||
    manifest.candidateManifestSha256 !== expectedCandidateSha256 ||
    candidateManifestSha256FromSnapshot(manifest) !== expectedCandidateSha256 ||
    !canonicalJsonBytes(manifest).equals(observed.bytes)
  ) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.MANIFEST_MISMATCH, "candidate manifest is malformed");
  }
  return Object.freeze({
    manifest,
    observation: observed.observation,
    path: manifestPath,
    sha256: observed.sha256,
  });
}

/**
 * Final source closeout after the post snapshot. The entry-bound source root (identity and
 * observation), the Git directory and the common directory are re-bound with the observations the
 * capture admitted, and the raw index, the selected split-index companion, HEAD and the HEAD ref
 * (loose file or packed-refs) are descriptor-relative re-read and must be exactly the files the
 * snapshot observed: identity, mode, size, timestamps and bytes.
 */
function closeoutSourceGit(gitObservation, sourceBinding, { byteBudget, limits, operationBudget }) {
  const releaseLease = createReleaseLease({
    fallbackCode: KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED,
    message: "final source Git closeout release failed",
  });
  let custody = null;
  let pendingError = null;
  const snapshotCode = KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE;
  const sourceCode = KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED;
  const changed = (code, message, details = null) => fail(code, message, details);
  try {
    const sourceBound = releaseLease.ownBound(
      bindDirectoryDescriptor(
        requireSourceRoot(sourceBinding.path, sourceBinding, operationBudget, {
          label: "source root at final closeout",
          observation: sourceBinding.observation,
        }),
        "source root",
        KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED,
        operationBudget,
      ),
      "source root",
      KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED,
    );
    const bindObserved = (directoryPath, identity, observation, label) => {
      const directory = requireRealDirectory(directoryPath, label, {
        expectedIdentity: identity,
        expectedIdentityCode: KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED,
        operationBudget,
      });
      if (!sameDirectoryObservation(directory.observation, observation)) {
        changed(
          KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED,
          `${label} changed before final closeout`,
          { expected: observation, observed: directory.observation, path: directory.path },
        );
      }
      return releaseLease.ownBound(
        bindDirectoryDescriptor(
          directory,
          label,
          KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED,
          operationBudget,
        ),
        label,
        KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED,
      );
    };
    const gitBound = bindObserved(
      gitObservation.gitDirectory,
      gitObservation.gitDirectoryIdentity,
      gitObservation.gitDirectoryObservation,
      "Git directory",
    );
    const commonBound = gitObservation.commonDirectory === gitObservation.gitDirectory
      ? gitBound
      : bindObserved(
          gitObservation.commonDirectory,
          gitObservation.commonDirectoryIdentity,
          gitObservation.commonDirectoryObservation,
          "Git common directory",
        );
    custody = createBoundControlCustody({
      byteBudget,
      code: KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED,
      limits,
      operationBudget,
    });
    releaseLease.add(() => custody.release());
    const reread = (bound, name, label, extra = {}) => custody.acquire(
      bound,
      name,
      label,
      extra,
    );
    const evidenceOnly = (evidence) => evidence === null
      ? null
      : Object.freeze({ observation: evidence.observation, sha256: evidence.sha256 });
    const sameEvidence = (file, evidence) =>
      file !== null && evidence !== null &&
      canonicalJsonBytes(gitFileEvidence(file)).equals(canonicalJsonBytes(evidenceOnly(evidence)));
    const sameOptionalEvidence = (file, evidence) =>
      (file === null) === (evidence === null) &&
      (file === null || sameEvidence(file, evidence));
    const terminalTopologyChecks = [];
    const requireCurrentTarget = (target, expectedBound, label) => {
      const observed = requireRealDirectory(target, label, {
        expectedIdentity: expectedBound.identity,
        expectedIdentityCode: sourceCode,
        operationBudget,
      });
      if (
        observed.path !== expectedBound.path ||
        !sameDirectoryObservation(observed.observation, expectedBound.observation)
      ) {
        changed(
          sourceCode,
          `${label} no longer resolves to the bound directory`,
          {
            expected: expectedBound.observation,
            expectedPath: expectedBound.path,
            observed: observed.observation,
            path: observed.path,
          },
        );
      }
    };

    // Acquire all mutable control inputs into one concurrent custody set. Files remain open and
    // optional absences remain witnessed until the terminal confirmation below.
    const indexFinal = reread(gitBound, "index", "final source Git index", {
      code: snapshotCode,
    });
    if (!sameGitFile(indexFinal, gitObservation.index)) {
      changed(
        snapshotCode,
        "source raw index changed after final Git read",
        { expected: gitObservation.index, observed: indexFinal },
      );
    }
    if (gitObservation.sharedIndex !== null) {
      const sharedFinal = reread(
        gitBound,
        path.basename(gitObservation.sharedIndex.path),
        "final selected split-index companion",
        { code: snapshotCode },
      );
      if (!sameGitFile(sharedFinal, gitObservation.sharedIndex)) {
        changed(
          snapshotCode,
          "selected split-index companion changed after final Git read",
          { expected: gitObservation.sharedIndex, observed: sharedFinal },
        );
      }
    }
    const headFinal = reread(gitBound, "HEAD", "final Git HEAD", {
      code: snapshotCode,
      maxBytes: MAX_GIT_CONTROL_TEXT_BYTES,
    });
    if (!sameEvidence(headFinal, gitObservation.headFile)) {
      changed(
        snapshotCode,
        "source Git HEAD changed after final Git read",
      );
    }
    const reference = gitObservation.headReference;
    if (reference !== null && reference.storage === "loose") {
      const referenceBound = PER_WORKTREE_REF_PREFIXES.some((prefix) => reference.name.startsWith(prefix))
        ? gitBound
        : commonBound;
      const referenceFinal = reread(referenceBound, reference.name, `final Git ref ${reference.name}`, {
        code: snapshotCode,
        maxBytes: MAX_GIT_CONTROL_TEXT_BYTES,
      });
      if (
        !sameEvidence(referenceFinal, { observation: reference.observation, sha256: reference.sha256 })
      ) {
        changed(
          snapshotCode,
          `source Git ref ${reference.name} changed after final Git read`,
        );
      }
    } else if (reference !== null && reference.storage === "packed") {
      const referenceBound = PER_WORKTREE_REF_PREFIXES.some((prefix) =>
        reference.name.startsWith(prefix))
        ? gitBound
        : commonBound;
      const looseFinal = reread(
        referenceBound,
        reference.name,
        `absent loose Git ref ${reference.name} at final closeout`,
        {
          code: snapshotCode,
          maxBytes: MAX_GIT_CONTROL_TEXT_BYTES,
          optional: true,
        },
      );
      if (looseFinal !== null) {
        changed(snapshotCode, `loose Git ref ${reference.name} appeared after final Git read`);
      }
      const packedFinal = reread(commonBound, "packed-refs", "final Git packed-refs", {
        code: snapshotCode,
      });
      if (!sameEvidence(packedFinal, gitObservation.packedRefs)) {
        changed(
          snapshotCode,
          "source Git packed-refs changed after final Git read",
        );
      }
    }
    // The topology linkage itself is re-read last: the root `.git` entry (directory identity or
    // gitfile bytes and target), the linked back-reference, and the commondir indirection must be
    // exactly what the snapshot observed, so a same-inode rewrite of the gitfile that points the
    // live worktree at another Git directory after the post snapshot is refused.
    const rootEntry = gitObservation.rootGitEntry;
    const rootEntryFinal = boundEntryStat(sourceBound, ".git", "root Git entry at final closeout", {
      code: KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED,
      operationBudget,
    });
    if (
      rootEntryFinal === null || rootEntryFinal.identity !== rootEntry.identity ||
      rootEntryFinal.type !== (rootEntry.type === "directory" ? "directory" : "file")
    ) {
      changed(
        KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED,
        "root .git entry changed after final Git read",
        { expected: rootEntry, observed: rootEntryFinal },
      );
    }
    if (rootEntry.type === "gitfile") {
      const gitfileFinal = reread(sourceBound, ".git", "final root gitfile", {
        code: sourceCode,
        maxBytes: MAX_GIT_CONTROL_TEXT_BYTES,
        retainBytes: true,
      });
      const gitfileTarget = parseGitfileTarget(gitfileFinal.bytes, sourceBinding.path);
      if (
        !sameEvidence(gitfileFinal, rootEntry.gitfile) ||
        gitfileTarget !== rootEntry.target
      ) {
        changed(
          sourceCode,
          "root gitfile changed after final Git read",
          { expected: rootEntry.gitfile, observed: gitFileEvidence(gitfileFinal) },
        );
      }
      requireCurrentTarget(gitfileTarget, gitBound, "root gitfile target");
      terminalTopologyChecks.push(() =>
        requireCurrentTarget(gitfileTarget, gitBound, "terminal root gitfile target"));
      const backReferenceFinal = reread(gitBound, "gitdir", "final linked worktree back-reference", {
        code: sourceCode,
        maxBytes: MAX_GIT_CONTROL_TEXT_BYTES,
        retainBytes: true,
      });
      if (!sameEvidence(backReferenceFinal, gitObservation.worktreeBackReference)) {
        changed(
          sourceCode,
          "linked worktree back-reference changed after final Git read",
        );
      }
      const backTarget = parseGitTextPath(
        backReferenceFinal.bytes,
        "linked worktree back-reference",
        gitBound.path,
      );
      if (
        backTarget !== gitObservation.worktreeBackReference.target ||
        path.basename(backTarget) !== ".git"
      ) {
        changed(sourceCode, "linked worktree back-reference target changed after final Git read");
      }
      requireCurrentTarget(
        path.dirname(backTarget),
        sourceBound,
        "linked worktree back-reference worktree",
      );
      terminalTopologyChecks.push(() =>
        requireCurrentTarget(
          path.dirname(backTarget),
          sourceBound,
          "terminal linked worktree back-reference worktree",
        ));
    }
    const commondirFile = reread(gitBound, "commondir", "final Git commondir", {
      code: sourceCode,
      maxBytes: MAX_GIT_CONTROL_TEXT_BYTES,
      optional: true,
      retainBytes: true,
    });
    if (gitObservation.commondir === null) {
      if (commondirFile !== null) {
        changed(sourceCode, "Git commondir appeared after final Git read");
      }
    } else {
      if (!sameEvidence(commondirFile, gitObservation.commondir)) {
        changed(sourceCode, "Git commondir changed after final Git read");
      }
      const commondirTarget = parseGitTextPath(
        commondirFile.bytes,
        "Git commondir",
        gitBound.path,
      );
      if (commondirTarget !== gitObservation.commondir.target) {
        changed(sourceCode, "Git commondir target changed after final Git read");
      }
      requireCurrentTarget(commondirTarget, commonBound, "Git commondir target");
      terminalTopologyChecks.push(() =>
        requireCurrentTarget(commondirTarget, commonBound, "terminal Git commondir target"));
    }
    if (commonBound !== gitBound) {
      const nestedCommondirFinal = reread(
        commonBound,
        "commondir",
        "final Git common-directory nested commondir",
        {
          code: sourceCode,
          maxBytes: MAX_GIT_CONTROL_TEXT_BYTES,
          optional: true,
        },
      );
      if (!sameOptionalEvidence(nestedCommondirFinal, gitObservation.nestedCommondir)) {
        changed(sourceCode, "Git common-directory nested commondir appeared after final Git read");
      }
    }

    const configFinal = reread(commonBound, "config", "final Git config", {
      code: sourceCode,
      maxBytes: MAX_GIT_CONTROL_TEXT_BYTES,
    });
    if (!sameEvidence(configFinal, gitObservation.configFile)) {
      changed(sourceCode, "Git repository config changed after final Git read");
    }
    const worktreeConfigFinal = reread(
      gitBound,
      "config.worktree",
      "final Git worktree config",
      {
        code: sourceCode,
        maxBytes: MAX_GIT_CONTROL_TEXT_BYTES,
        optional: true,
      },
    );
    if (!sameOptionalEvidence(worktreeConfigFinal, gitObservation.worktreeConfigFile)) {
      changed(sourceCode, "Git worktree config changed after final Git read");
    }
    if (commonBound !== gitBound) {
      const commonWorktreeConfigFinal = reread(
        commonBound,
        "config.worktree",
        "final Git common-directory worktree config",
        {
          code: sourceCode,
          maxBytes: MAX_GIT_CONTROL_TEXT_BYTES,
          optional: true,
        },
      );
      if (!sameOptionalEvidence(
        commonWorktreeConfigFinal,
        gitObservation.commonWorktreeConfigFile,
      )) {
        changed(sourceCode, "Git common-directory worktree config changed after final Git read");
      }
    }
    const infoExcludeFinal = reread(
      commonBound,
      "info/exclude",
      "final repository-local Git exclude rules",
      {
        code: sourceCode,
        maxBytes: MAX_GIT_CONTROL_TEXT_BYTES,
        optional: true,
      },
    );
    if (!sameOptionalEvidence(infoExcludeFinal, gitObservation.infoExclude)) {
      changed(sourceCode, "repository-local Git info/exclude changed after final Git read");
    }
    const infoAttributesFinal = reread(
      commonBound,
      "info/attributes",
      "final repository-local Git attributes rules",
      {
        code: sourceCode,
        maxBytes: MAX_GIT_CONTROL_TEXT_BYTES,
        optional: true,
      },
    );
    if (!sameOptionalEvidence(infoAttributesFinal, gitObservation.infoAttributes)) {
      changed(sourceCode, "repository-local Git info/attributes changed after final Git read");
    }
    confirmBoundDirectory(
      sourceBound,
      "source root at final closeout",
      KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED,
      operationBudget,
    );
    confirmBoundDirectory(
      gitBound,
      "Git directory at final closeout",
      KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED,
      operationBudget,
    );
    if (commonBound !== gitBound) {
      confirmBoundDirectory(
        commonBound,
        "Git common directory at final closeout",
        KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED,
        operationBudget,
      );
    }
    custody.confirm("before terminal topology resolution");
    for (const confirmTopology of terminalTopologyChecks) confirmTopology();
    custody.confirm("after terminal topology resolution");
    confirmBoundDirectory(
      sourceBound,
      "source root after terminal Git control custody",
      sourceCode,
      operationBudget,
    );
    confirmBoundDirectory(
      gitBound,
      "Git directory after terminal Git control custody",
      sourceCode,
      operationBudget,
    );
    if (commonBound !== gitBound) {
      confirmBoundDirectory(
        commonBound,
        "Git common directory after terminal Git control custody",
        sourceCode,
        operationBudget,
      );
    }
  } catch (error) {
    pendingError = error;
  }
  if (pendingError !== null) throw releaseLeaseError(releaseLease, pendingError);
  releaseLease.release();
}

/**
 * Capture one stable source interval into a private standalone seed. At most two pre/copy/post
 * attempts are permitted. An unstable attempt and every ephemeral scratch are retained and
 * reported by recorded private identity; the source is never restored or written.
 */
export function captureAndSealCandidate(options) {
  if (options === null || typeof options !== "object" || Array.isArray(options)) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "capture options are malformed");
  }
  const {
    commandTimeoutMs = MAX_CHILD_PROCESS_DURATION_MS,
    custodyRoot,
    gitExecutable = null,
    hooks = null,
    limits: requestedLimits = KNOCKOUT_WORKSPACE_CAPTURE_LIMITS,
    maxAttempts = MAX_CAPTURE_ATTEMPTS,
    operationTimeoutMs = commandTimeoutMs,
    sourceRoot,
  } = options;
  const boundedTimeoutMs = requireCommandTimeoutMs(commandTimeoutMs);
  const boundedOperationTimeoutMs = requireCaptureOperationTimeoutMs(operationTimeoutMs);
  const limits = normalizeCaptureLimits(requestedLimits);
  const operationBudget = createCaptureOperationBudget(
    boundedOperationTimeoutMs,
    boundedTimeoutMs,
  );
  const metadataCache = createMetadataObservationCache(
    limits.maxNodes * (MAX_CAPTURE_ATTEMPTS + 1),
  );
  if (!Number.isInteger(maxAttempts) || maxAttempts < 1 || maxAttempts > MAX_CAPTURE_ATTEMPTS) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT,
      `maxAttempts must be between 1 and ${MAX_CAPTURE_ATTEMPTS}`,
    );
  }
  if (
    hooks !== null &&
    (typeof hooks !== "object" || Array.isArray(hooks) ||
      Object.entries(hooks).some(([name, callback]) =>
        ![
          "afterManifestPublication",
          "afterPreObservation",
          "afterPreSealObservation",
          "afterWorktreeCopy",
          "beforeStatePublication",
        ].includes(name) || typeof callback !== "function"))
  ) {
    fail(KNOCKOUT_WORKSPACE_ERROR_CODES.INVALID_ARGUMENT, "capture hooks are malformed");
  }
  // The one physical source-root identity for this capture. Every later reopen of the source
  // pathname (see requireSourceRoot) confirms this binding, and the identity travels into the Git
  // observation, the source snapshot, the candidate manifest and the returned capability.
  const sourceDirectory = requireSourceRoot(sourceRoot, null, operationBudget);
  const source = sourceDirectory.path;
  const sourceBinding = Object.freeze({
    identity: sourceDirectory.identity,
    observation: sourceDirectory.observation,
    path: source,
  });
  const custodyDirectory = requireRealDirectory(
    custodyRoot,
    "custody root",
    { operationBudget, privateMode: true },
  );
  const custody = custodyDirectory.path;
  if (pathInside(source, custody) || pathInside(custody, source)) {
    fail(
      KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
      "custody root and live source must be disjoint",
    );
  }
  let lastUnstable = null;
  const retainedRoots = [];
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    const attemptStartedNs = process.hrtime.bigint();
    let created = null;
    let retryableSourceFailure = true;
    try {
      const before = observeSourceSnapshot(source, {
        commandTimeoutMs: boundedTimeoutMs,
        expectedRoot: sourceBinding,
        gitExecutable,
        limits,
        metadataCache,
        operationBudget,
        scratchRoot: custody,
      });
      retainedRoots.push(...retainedPrivateRoots(before));
      // The permanent v3-to-v4 migration barrier is deliberately bound to one physical root. It
      // remains fully observed in `before` but is the only source node omitted from the portable
      // seed. Every disposable arm must establish its own barrier through the guard's existing
      // atomic no-clobber migration path; copying a source-bound marker would make that arm look
      // like foreign recovery state.
      const rootLocalState = observeRootLocalStateProjection(
        before.workspace,
        sourceBinding,
        operationBudget,
      );
      const portableBefore = rootLocalState.portable;
      hooks?.afterPreObservation?.(Object.freeze({ attempt, sourceRoot: source }));
      remainingOperationMs(operationBudget, "candidate capture after source observation");
      requireDestinationCapacity(
        custody,
        before.workspace.logicalBytes + limits.maxTotalBytes,
        limits,
        "candidate custody root",
        operationBudget,
      );
      created = createUniquePrivateDirectory(
        custody,
        `seed-attempt-${attempt}-`,
        { label: "private candidate seed", operationBudget, privateParent: true },
      );
      const workspace = createPrivateDirectory(
        path.join(created.path, "workspace"),
        { operationBudget },
      );
      const evidence = createPrivateDirectory(
        path.join(created.path, "evidence"),
        { operationBudget },
      );
      // Create the identity-bound Git root before copying. This makes the workspace-root pathname
      // chain stable at the first destination census, so later censuses can reuse the exact ACL/
      // xattr evidence for unchanged worktree nodes. The directory remains excluded from the
      // copied-worktree witness and must still match its creation observation and be empty after
      // the copy hook, immediately before Git is allowed to initialize it.
      const gitRoot = createPrivateDirectory(
        path.join(workspace.path, ".git"),
        { operationBudget },
      );
      const copied = copyLiveWorktree(portableBefore, workspace.path, {
        expectedDestinationRoot: workspace,
        expectedSourceRoot: sourceBinding,
        limits,
        metadataCache,
        operationBudget,
        rootGitPolicy: "exclude",
      });
      requireDestinationCapacity(
        workspace.path,
        0,
        limits,
        "candidate worktree reserve",
        operationBudget,
      );
      retryableSourceFailure = false;
      hooks?.afterWorktreeCopy?.(Object.freeze({
        attempt,
        evidenceRoot: evidence.path,
        workspaceRoot: workspace.path,
      }));
      remainingOperationMs(operationBudget, "candidate capture after worktree-copy hook");
      assertEmptyPrivateDirectory(
        gitRoot,
        "pre-created standalone Git directory",
        operationBudget,
      );
      const copiedAfterHook = censusWorkspace(workspace.path, {
        expectedRoot: workspace,
        limits,
        metadataCache,
        operationBudget,
        rootGitPolicy: "exclude",
      });
      if (
        copiedAfterHook.nodeCount !== copied.nodeCount ||
        copiedAfterHook.materialSha256 !== copied.materialSha256 ||
        copiedAfterHook.observationSha256 !== copied.observationSha256
      ) {
        fail(
          KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
          "private worktree changed after its copy witness",
          {
            copiedMaterial: copied.materialSha256,
            copiedObservation: copied.observationSha256,
            observedMaterial: copiedAfterHook.materialSha256,
            observedObservation: copiedAfterHook.observationSha256,
          },
        );
      }
      retryableSourceFailure = true;
      const resourceLedger = createCaptureResourceLedger(limits, copiedAfterHook);
      const evidenceCapacity = requireDestinationCapacity(
        evidence.path,
        MAX_CANDIDATE_MANIFEST_BYTES + MAX_STATE_BYTES,
        limits,
        "candidate evidence reserve",
        operationBudget,
      );
      resourceLedger.charge({
        allocatedBytes:
          projectedAllocatedWriteBytes(
            MAX_CANDIDATE_MANIFEST_BYTES,
            evidenceCapacity.allocationUnitBytes,
          ) +
          projectedAllocatedWriteBytes(MAX_STATE_BYTES, evidenceCapacity.allocationUnitBytes),
        label: "candidate manifest and sealed-state evidence reserve",
        logicalBytes: MAX_CANDIDATE_MANIFEST_BYTES + MAX_STATE_BYTES,
        maxDepth: 2,
        nodeCount: 2,
      });
      resourceLedger.charge({
        allocatedBytes: GIT_CONTROL_ALLOCATED_RESERVE_BYTES,
        label: "standalone Git control metadata",
        logicalBytes: GIT_CONTROL_LOGICAL_RESERVE_BYTES,
        maxDepth: GIT_CONTROL_MAX_DEPTH,
        nodeCount: GIT_CONTROL_NODE_RESERVE,
      });
      const initialized = initializeStandaloneGit(
        source,
        workspace.path,
        before.git,
        {
          commandTimeoutMs: boundedTimeoutMs,
          expectedGitRoot: gitRoot,
          expectedSourceRoot: sourceBinding,
          gitExecutable,
          limits,
          operationBudget,
          resourceLedger,
          scratchParentPrivate: true,
          scratchRoot: custody,
        },
      );
      retainedRoots.push(...retainedPrivateRoots(initialized));
      retryableSourceFailure = false;
      const standaloneValidation = validateStandaloneGit(workspace.path, before.git, {
        commandTimeoutMs: boundedTimeoutMs,
        expectedIndex: initialized.index,
        gitExecutable,
        limits,
        operationBudget,
      });
      retainedRoots.push(...retainedPrivateRoots(standaloneValidation));
      const standalone = Object.freeze({ ...standaloneValidation });
      retryableSourceFailure = true;
      const after = observeSourceSnapshot(source, {
        commandTimeoutMs: boundedTimeoutMs,
        expectedRoot: sourceBinding,
        expectedTopology: before.git,
        gitExecutable,
        limits,
        metadataCache,
        operationBudget,
        scratchRoot: custody,
      });
      retainedRoots.push(...retainedPrivateRoots(after));
      if (after.snapshotSha256 !== before.snapshotSha256) {
        fail(
          KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE,
          "source pre/post censuses differ",
          {
            after: after.snapshotSha256,
            afterGit: sha256(canonicalJsonBytes(after.git)),
            afterWorkspace: after.workspace.observationSha256,
            attempt,
            before: before.snapshotSha256,
            beforeGit: sha256(canonicalJsonBytes(before.git)),
            beforeWorkspace: before.workspace.observationSha256,
            changedGitFields: Object.keys(before.git).filter((key) =>
              !canonicalJsonBytes(before.git[key]).equals(canonicalJsonBytes(after.git[key]))),
            changedSharedIndex: canonicalJsonBytes(before.git.sharedIndex)
              .equals(canonicalJsonBytes(after.git.sharedIndex))
              ? null
              : Object.freeze({ after: after.git.sharedIndex, before: before.git.sharedIndex }),
          },
        );
      }
      closeoutSourceGit(before.git, sourceBinding, {
        byteBudget: createObservationByteBudget(limits, "final source closeout"),
        limits,
        operationBudget,
      });
      retryableSourceFailure = false;
      const preSeal = censusWorkspace(workspace.path, {
        expectedRoot: workspace,
        limits,
        metadataCache,
        operationBudget,
        rootGitPolicy: "include",
      });
      const prewriteProjection = resourceLedger.snapshot();
      if (
        preSeal.allocatedBytes > prewriteProjection.allocatedBytes ||
        preSeal.logicalBytes > prewriteProjection.logicalBytes ||
        preSeal.maxDepth > prewriteProjection.maxDepth ||
        preSeal.nodeCount > prewriteProjection.nodeCount
      ) {
        fail(
          KNOCKOUT_WORKSPACE_ERROR_CODES.RESOURCE_LIMIT_EXCEEDED,
          "standalone seed exceeded its pre-write resource projection",
          {
            observed: resourceMetricsFromNodes(preSeal.nodes, operationBudget),
            projected: prewriteProjection,
          },
        );
      }
      if (!copiedWorktreeEquivalent(portableBefore, worktreeProjectionOfSeed(preSeal))) {
        fail(
          KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
          "seed worktree changed after its copy witness",
          {
            copiedMaterial: copied.materialSha256,
            sealedMaterial: preSeal.materialSha256,
          },
        );
      }
      hooks?.afterPreSealObservation?.(Object.freeze({
        attempt,
        evidenceRoot: evidence.path,
        workspaceRoot: workspace.path,
      }));
      remainingOperationMs(operationBudget, "candidate capture after pre-seal hook");
      const manifestWithoutHash = {
        attempt,
        copy: {
          privateDirectoryMode: 0o700,
          privateExecutableFileMode: 0o700,
          privateFileMode: 0o600,
          strategy: "descriptor-byte-copy-with-attested-root-local-omission",
        },
        protocol: KNOCKOUT_WORKSPACE_PROTOCOLS.candidateManifest,
        rootLocalStateProjection: rootLocalState.projection,
        resourceAdmission: {
          childCommandTimeoutMs: operationBudget.commandTimeoutMs,
          limits,
          operationDeadlineMs: boundedOperationTimeoutMs,
          policy: "shared-prewrite-projection-plus-postwrite-exact-census-plus-fixed-reserve",
          prewriteProjection,
          seed: {
            allocatedBytes: preSeal.allocatedBytes,
            logicalBytes: preSeal.logicalBytes,
            maxDepth: preSeal.maxDepth,
            nodeCount: preSeal.nodeCount,
          },
          source: {
            allocatedBytes: before.workspace.allocatedBytes,
            logicalBytes: before.workspace.logicalBytes,
            maxDepth: before.workspace.maxDepth,
            nodeCount: before.workspace.nodeCount,
          },
        },
        seed: {
          git: standalone,
          includesStandaloneGit: true,
          nodeCount: preSeal.nodeCount,
          observationSha256: preSeal.observationSha256,
          workspaceMaterialSha256: preSeal.materialSha256,
        },
        source: {
          git: before.git,
          nodeCount: before.workspace.nodeCount,
          nodes: before.workspace.nodes,
          snapshotSha256: before.snapshotSha256,
          workspaceMaterialSha256: before.workspace.materialSha256,
          workspaceObservationSha256: before.workspace.observationSha256,
        },
      };
      const candidateHash = candidateManifestSha256(manifestWithoutHash);
      const manifest = Object.freeze({
        ...manifestWithoutHash,
        candidateManifestSha256: candidateHash,
      });
      const manifestBytes = canonicalJsonBytes(manifest);
      remainingOperationMs(operationBudget, "candidate capture before manifest publication");
      const manifestPublication = durablePublishNoClobber(
        evidence.path,
        "candidate-manifest.json",
        manifestBytes,
        {
          expectedDirectoryIdentity: evidence.identity,
          limits,
          maxBytes: MAX_CANDIDATE_MANIFEST_BYTES,
          operationBudget,
        },
      );
      hooks?.afterManifestPublication?.(Object.freeze({
        attempt,
        evidenceRoot: evidence.path,
        manifestPath: manifestPublication.path,
        workspaceRoot: workspace.path,
      }));
      remainingOperationMs(operationBudget, "candidate capture after manifest-publication hook");
      const verifiedManifest = sealedManifest(
        evidence.path,
        candidateHash,
        manifestPublication.sha256,
        manifestPublication.createdObservation,
        evidence.identity,
        operationBudget,
      );
      const seedRootDirectory = requireRealDirectory(
        created.path,
        "candidate seed root",
        { expectedIdentity: created.identity, operationBudget, privateMode: true },
      );
      const verificationDescriptor = Object.freeze({
        candidateManifestSha256: candidateHash,
        custodyIdentity: custodyDirectory.identity,
        custodyRoot: custody,
        evidenceIdentity: evidence.identity,
        evidenceRoot: evidence.path,
        manifestFileSha256: manifestPublication.sha256,
        manifestObservation: verifiedManifest.observation,
        manifestPath: verifiedManifest.path,
        seedIdentity: seedRootDirectory.identity,
        seedObservation: preSeal,
        seedRoot: seedRootDirectory.path,
        seedRootObservation: seedRootDirectory.observation,
        sourceSnapshotSha256: before.snapshotSha256,
        workspaceIdentity: workspace.identity,
        workspaceRoot: workspace.path,
      });
      const initiallyVerifiedSeed = verifySealedSeedDescriptor(
        verificationDescriptor,
        { commandTimeoutMs: boundedTimeoutMs, metadataCache, operationBudget },
      );
      retainedRoots.push(...retainedPrivateRoots(initiallyVerifiedSeed));
      const plannedStatePath = path.join(evidence.path, "state.json");
      hooks?.beforeStatePublication?.(Object.freeze({
        attempt,
        evidenceRoot: evidence.path,
        statePath: plannedStatePath,
        workspaceRoot: workspace.path,
      }));
      remainingOperationMs(operationBudget, "candidate capture after pre-state hook");
      const finalManifest = sealedManifest(
        evidence.path,
        candidateHash,
        manifestPublication.sha256,
        manifestPublication.createdObservation,
        evidence.identity,
        operationBudget,
      );
      const finalVerificationDescriptor = Object.freeze({
        ...verificationDescriptor,
        manifestObservation: finalManifest.observation,
        manifestPath: finalManifest.path,
      });
      const finalSeed = verifySealedSeedDescriptor(
        finalVerificationDescriptor,
        { commandTimeoutMs: boundedTimeoutMs, metadataCache, operationBudget },
      );
      retainedRoots.push(...retainedPrivateRoots(finalSeed));
      remainingOperationMs(operationBudget, "candidate capture before final identity checks");
      assertPrivateDirectoryIdentity(custodyDirectory, "custody root", operationBudget);
      assertPrivateDirectoryIdentity(created, "candidate seed root", operationBudget);
      assertPrivateDirectoryIdentity(workspace, "candidate workspace root", operationBudget);
      assertPrivateDirectoryIdentity(evidence, "candidate evidence root", operationBudget);
      remainingOperationMs(operationBudget, "candidate capture before terminal state commit");
      // Capture witness. The exact bytes the state file certifies are re-observed under the bound
      // workspace identity, together with the entry-bound source root (identity and observation),
      // the custody, seed, workspace and evidence identities, and the exact published manifest:
      // once while the state file is PREPARED, once after it is committed and durable, and once
      // more after publication returns, before the capability is registered. A refusal before the
      // commit leaves PREPARED residue; a refusal after it revokes the commit on its descriptor as
      // fault detection. Neither is the security claim: only the registered capability is.
      const witnessSealedSeed = (label) => {
        remainingOperationMs(operationBudget, `candidate capture ${label}`);
        requireSourceRoot(source, sourceBinding, operationBudget, {
          label: `source root ${label}`,
          observation: sourceBinding.observation,
        });
        assertPrivateDirectoryIdentity(custodyDirectory, "custody root", operationBudget);
        assertPrivateDirectoryIdentity(created, "candidate seed root", operationBudget);
        assertPrivateDirectoryIdentity(workspace, "candidate workspace root", operationBudget);
        assertPrivateDirectoryIdentity(evidence, "candidate evidence root", operationBudget);
        sealedManifest(
          evidence.path,
          candidateHash,
          manifestPublication.sha256,
          manifestPublication.createdObservation,
          evidence.identity,
          operationBudget,
        );
        const witness = censusWorkspace(workspace.path, {
          expectedRoot: workspace,
          limits,
          metadataCache,
          operationBudget,
          rootGitPolicy: "include",
        });
        if (
          witness.nodeCount !== finalSeed.nodeCount ||
          witness.materialSha256 !== finalSeed.materialSha256 ||
          witness.observationSha256 !== finalSeed.observationSha256
        ) {
          const changedNodeIndex = finalSeed.nodes.findIndex((node, index) =>
            index >= witness.nodes.length ||
            !canonicalJsonBytes(node).equals(canonicalJsonBytes(witness.nodes[index])));
          fail(
            KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
            `sealed seed changed ${label}`,
            {
              changedNode: changedNodeIndex < 0 ? null : Object.freeze({
                after: witness.nodes[changedNodeIndex] ?? null,
                before: finalSeed.nodes[changedNodeIndex],
              }),
              expectedMaterial: finalSeed.materialSha256,
              expectedNodes: finalSeed.nodeCount,
              expectedObservation: finalSeed.observationSha256,
              observedMaterial: witness.materialSha256,
              observedNodes: witness.nodeCount,
              observedObservation: witness.observationSha256,
            },
          );
        }
      };
      // Persisted state is non-authoritative capture evidence (status CAPTURED). It binds the
      // manifest, the seed observation and the source snapshot so every later use can confirm the
      // exact published inode and bytes, but no reader may derive authority from it.
      const state = Object.freeze({
        candidateManifestFileSha256: manifestPublication.sha256,
        candidateManifestSha256: candidateHash,
        evidenceRole: KNOCKOUT_WORKSPACE_STATE_EVIDENCE_ROLE,
        protocol: KNOCKOUT_WORKSPACE_PROTOCOLS.state,
        seedObservationSha256: finalSeed.observationSha256,
        sourceSnapshotSha256: before.snapshotSha256,
        status: KNOCKOUT_WORKSPACE_CAPTURE_STATUS,
        workspace: "../workspace",
      });
      const stateBytes = canonicalJsonBytes(state);
      const statePublication = durablePublishNoClobber(
        evidence.path,
        "state.json",
        stateBytes,
        {
          afterCommitWitness: () => witnessSealedSeed("after capture state commit"),
          beforeCommitWitness: () => witnessSealedSeed("before capture state commit"),
          expectedDirectoryIdentity: evidence.identity,
          limits,
          maxBytes: MAX_STATE_BYTES,
          operationBudget,
        },
      );
      // Authority contract. The capability below is the only authority for this capture and it is
      // registered only after post-publication validation of the exact state inode and bytes, the
      // exact manifest inode and bytes, every bound directory, the entry-bound source root, and
      // the exact seed census. A crash or substitution before this point leaves retained,
      // non-authoritative residue and no capability; one after it is caught at use time because
      // verifySealedSeed revalidates the same evidence against this descriptor.
      const capabilityDescriptor = Object.freeze({
        ...finalVerificationDescriptor,
        metadataCache,
        stateFileSha256: statePublication.sha256,
        stateObservation: statePublication.createdObservation,
        statePath: statePublication.path,
      });
      witnessSealedSeed("after capture state publication");
      reopenCaptureStateEvidence(
        statePublication.path,
        capabilityDescriptor,
        requireRealDirectory(evidence.path, "candidate evidence root", {
          expectedIdentity: evidence.identity,
          operationBudget,
          privateMode: true,
        }),
        operationBudget,
      );
      // This is the source-provenance linearization point. All publication hooks and durable
      // evidence writes have completed; re-observe the complete worktree and every admitted Git
      // control from the original bound topology immediately before constructing and registering
      // the sole authority capability. Source changes after this exact observation are ordinary
      // post-capture changes and cannot alter the sealed seed or its candidate-bound evidence.
      const finalSource = verifySourceUnchanged(before, {
        commandTimeoutMs: boundedTimeoutMs,
        gitExecutable,
        limits,
        metadataCache,
        operationBudget,
        scratchRoot: custody,
      });
      retainedRoots.push(...retainedPrivateRoots(finalSource));
      const retainedForCapability = uniqueRetainedPrivateRoots(retainedRoots);
      const captureCapability = Object.freeze({
        attempt,
        candidateManifestSha256: candidateHash,
        custodyIdentity: custodyDirectory.identity,
        evidenceIdentity: evidence.identity,
        evidenceRoot: evidence.path,
        manifest: finalManifest.manifest,
        manifestObservation: finalManifest.observation,
        manifestPath: finalManifest.path,
        retainedPrivateRoots: retainedForCapability,
        seedIdentity: created.identity,
        seedRoot: created.path,
        seedRootObservation: seedRootDirectory.observation,
        sourceRootIdentity: sourceDirectory.identity,
        sourceSnapshot: before,
        stateObservation: statePublication.createdObservation,
        statePath: statePublication.path,
        stateSha256: statePublication.sha256,
        workspaceObservation: finalSeed,
        workspaceIdentity: workspace.identity,
        workspaceRoot: workspace.path,
      });
      remainingOperationMs(operationBudget, "candidate capture before capability registration");
      sealedCaptureCapabilities.set(captureCapability, capabilityDescriptor);
      return captureCapability;
    } catch (caught) {
      let error = caught;
      retainedRoots.push(...retainedPrivateRoots(error?.details));
      if (created !== null) retainedRoots.push(retainCreatedPrivateTree(created));
      error = reportRetainedPrivateRoots(error, retainedRoots);
      if (
        lastUnstable !== null &&
        error instanceof KnockoutWorkspaceError &&
        error.code === KNOCKOUT_WORKSPACE_ERROR_CODES.OPERATION_DEADLINE_EXCEEDED
      ) {
        // The retry existed only because a prior attempt proved source instability. Preserve both
        // facts when that admitted retry consumes the shared deadline: callers still receive the
        // controlling source-stability taxonomy, while the exact deadline failure remains in the
        // error tree and structured details for diagnosis.
        const retryFailures = new AggregateError(
          [lastUnstable, error],
          "source instability was followed by a retry deadline failure",
        );
        fail(
          KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE,
          "source did not stabilize before the admitted retry exhausted the shared deadline",
          {
            attempts: attempt,
            lastCode: lastUnstable.code,
            maxAttempts,
            retainedPrivateRoots: uniqueRetainedPrivateRoots(retainedRoots),
            retryDeadlineCode: error.code,
            retrySkipped: "ADMITTED_RETRY_DEADLINE_EXCEEDED",
          },
          retryFailures,
        );
      }
      if (
        retryableSourceFailure &&
        error instanceof KnockoutWorkspaceError &&
        [
          KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE,
          KNOCKOUT_WORKSPACE_ERROR_CODES.SOURCE_CHANGED,
        ].includes(error.code)
      ) {
        lastUnstable = error;
        const retryDecisionNs = process.hrtime.bigint();
        const attemptElapsedNs = retryDecisionNs - attemptStartedNs;
        const remainingNs = operationBudget.deadlineNs - retryDecisionNs;
        // A retry is admitted only when the remaining whole-operation budget can cover at least
        // the just-observed attempt cost. This is deliberately conservative: a cache-warmed retry
        // may be faster, but starting one without even that evidence merely burns the remaining
        // deadline and hides the source-instability taxonomy behind a later timeout.
        if (
          attempt < maxAttempts && attemptElapsedNs > 0n &&
          remainingNs > attemptElapsedNs
        ) continue;
        const boundedDurationMs = (durationNs) => {
          if (durationNs <= 0n) return 0;
          const roundedUpMs = (durationNs + 999_999n) / 1_000_000n;
          return Number(
            roundedUpMs > BigInt(operationBudget.operationTimeoutMs)
              ? BigInt(operationBudget.operationTimeoutMs)
              : roundedUpMs,
          );
        };
        const retrySkipped = attempt < maxAttempts
          ? "INSUFFICIENT_REMAINING_DEADLINE"
          : null;
        fail(
          KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE,
          retrySkipped === null
            ? `source did not stabilize in ${attempt} attempts`
            : "source did not stabilize before another bounded capture attempt",
          {
            attemptElapsedMs: boundedDurationMs(attemptElapsedNs),
            attempts: attempt,
            lastCode: error.code,
            maxAttempts,
            remainingRetryBudgetMs: boundedDurationMs(remainingNs),
            retainedPrivateRoots: uniqueRetainedPrivateRoots(retainedRoots),
            retrySkipped,
          },
          error,
        );
      }
      throw error;
    }
  }
  fail(
    KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE,
    "source capture exhausted without a stable candidate",
    { lastCode: lastUnstable?.code ?? null },
    lastUnstable ?? undefined,
  );
}
