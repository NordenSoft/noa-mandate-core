import assert from "node:assert/strict";
import childProcess, { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import ts from "typescript";
import { fileURLToPath, pathToFileURL } from "node:url";

type RetainedPrivateRoot = { identity: string; path: string };
type CaptureLimits = {
  maxAllocatedBytes: number;
  maxDepth: number;
  maxFileBytes: number;
  maxNodes: number;
  maxTotalBytes: number;
  minFreeBytes: number;
};
type FileObservation = {
  allocatedBytes?: number;
  ctimeNs: string;
  identity: string;
  mode: number;
  mtimeNs: string;
  nlink: number;
  size: number;
};
type RetainedTerminalPublication = {
  createdIdentity: string | null;
  createdObservation: FileObservation | null;
  currentIdentity: string | null;
  currentMode: number | null;
  currentNlink: number | null;
  currentType: string;
  directoryIdentity: string;
  expectedBytes: number;
  expectedSha256: string;
  path: string;
  phase: string;
};
type WorkspaceError = Error & {
  code?: string;
  details?: {
    attempts?: number;
    changedNode?: {
      after?: { path?: string } | null;
      before?: { path?: string } | null;
    } | null;
    expectedEffectiveUid?: number;
    expectedIdentity?: string;
    lastCode?: string;
    launcher?: string;
    launcherUnavailable?: boolean;
    maxAttempts?: number;
    names?: string[];
    observedEffectiveUid?: number;
    outstandingArmIds?: string[];
    pathIdentity?: string;
    retainedPrivateRoots?: RetainedPrivateRoot[];
    retainedTerminalPublication?: RetainedTerminalPublication;
    retryDeadlineCode?: string;
    retrySkipped?: string | null;
    status?: number | null;
    stderr?: string;
  } | null;
};
type DirectoryObservation = {
  ctimeNs: string;
  dev: string;
  identity: string;
  ino: string;
  mode: number;
  mtimeNs: string;
  nlink: number;
};
type GitFileEvidence = {
  observation: FileObservation;
  sha256: string;
};
type SourceSnapshot = {
  git: {
    commonWorktreeConfigFile?: GitFileEvidence | null;
    commonDirectoryIdentity?: string;
    configFile?: GitFileEvidence;
    gitDirectoryIdentity?: string;
    head?: string;
    headRef?: string | null;
    index: { path: string; sha256: string };
    topology?: string;
    sharedIndex: { path: string; sha256: string } | null;
    indexStageSha256?: string;
    statusConfig?: {
      "core.filemode": boolean;
      "core.ignorecase": boolean;
      "core.precomposeunicode": boolean;
      "core.symlinks": boolean;
    };
    statusSha256?: string;
    worktreeConfigFile?: GitFileEvidence | null;
    worktreeRoot?: string;
    worktreeRootIdentity?: string;
    worktreeRootObservation?: DirectoryObservation;
  };
  snapshotSha256: string;
  workspace: {
    allocatedBytes: number;
    logicalBytes: number;
    maxDepth: number;
    nodeCount: number;
  };
};
type Capture = {
  attempt: number;
  candidateManifestSha256: string;
  custodyIdentity?: string;
  evidenceIdentity: string;
  evidenceRoot: string;
  manifest: {
    candidateManifestSha256: string;
    protocol: string;
    rootLocalStateProjection: {
      action: string;
      path: string;
      policy: string;
      record: null | { migratedAt: string; protocol: string; root: string; rootIdentity: string };
      sourceBytesBase64: string | null;
      sourceFileSha256: string | null;
      sourceNodeSha256: string | null;
      status: string;
    };
    resourceAdmission: {
      childCommandTimeoutMs: number;
      limits: CaptureLimits;
      operationDeadlineMs: number;
      policy: string;
      prewriteProjection: {
        allocatedBytes: number; logicalBytes: number; maxDepth: number; nodeCount: number;
      };
      seed: { allocatedBytes: number; logicalBytes: number; maxDepth: number; nodeCount: number };
      source: { allocatedBytes: number; logicalBytes: number; maxDepth: number; nodeCount: number };
    };
    seed: {
      git: {
        indexSha256: string;
        indexStageSha256: string;
        sharedIndexSha256: string | null;
        statusConfig: {
          "core.filemode": boolean;
          "core.ignorecase": boolean;
          "core.precomposeunicode": boolean;
          "core.symlinks": boolean;
        };
        statusSha256: string;
      };
      includesStandaloneGit: boolean;
      nodeCount: number;
      observationSha256: string;
      workspaceMaterialSha256: string;
    };
    source: {
      git?: SourceSnapshot["git"];
      nodes: Array<{
        executable: boolean;
        hardlinkCount: number | null;
        hardlinkGroup: string | null;
        mode: number;
        observation: FileObservation;
        path: string;
        provenance: { classification: string; present: boolean; sha256: string | null };
        sha256?: string;
        size?: number;
        target?: string;
        type: string;
      }>;
      nodeCount: number;
      workspaceMaterialSha256: string;
      workspaceObservationSha256: string;
    };
  };
  retainedPrivateRoots: RetainedPrivateRoot[];
  manifestObservation: FileObservation;
  manifestPath: string;
  seedRoot: string;
  seedIdentity?: string;
  seedRootObservation?: DirectoryObservation;
  sourceRootIdentity?: string;
  sourceSnapshot: SourceSnapshot;
  stateObservation: FileObservation;
  statePath: string;
  stateSha256?: string;
  workspaceObservation: {
    allocatedBytes: number;
    logicalBytes: number;
    materialSha256: string;
    maxDepth: number;
    nodeCount: number;
    observationSha256: string;
  };
  workspaceRoot: string;
  workspaceIdentity?: string;
};
type KnockoutCustody = {
  candidateManifestSha256: string;
  kind: string;
  maxRetainedArms: number;
  maxRetainedBytes: number;
  protocol: string;
  retentionAccountingScope: string;
};
type SourceLease = {
  candidateManifestSha256: string;
  exclusivityScope: string;
  kind: string;
  protocol: string;
  sourceLeaseSha256: string;
  sourceRootIdentity: string;
};
type SourceRelease = {
  candidateManifestSha256: string;
  retainedPrivateRoots: RetainedPrivateRoot[];
  seedObservationSha256: string;
  sourceSnapshotSha256: string;
  status: string;
};
type CooperativeSourceLease = {
  contentionProbe: {
    expectedExitCode: number;
    method: string;
    observedExitCode: number;
    status: string;
  };
  kind: string;
  lockScope: string;
  protocol: string;
  sourceLeaseSha256: string;
  sourceRootIdentity: string;
};
type ArmPlan = {
  armPlanSha256: string;
  batch: number;
  candidateManifestSha256: string;
  entries: Array<{ armId: string; role: string; subjectSha256: string }>;
  predecessorPlanSha256: string | null;
  protocol: string;
  sourceLeaseSha256: string;
};
type DisposableArm = {
  armId: string;
  armPlanSha256: string;
  armRoot: string;
  candidateManifestSha256: string;
  evidenceRoot: string;
  initialObservationSha256: string;
  kind: string;
  protocol: string;
  retainedPrivateRoots: RetainedPrivateRoot[];
  role: string;
  seedObservationSha256: string;
  sourceLeaseSha256: string;
  sourceSnapshotSha256: string;
  subjectSha256: string;
  workspaceRoot: string;
};
type WorkerSubject = {
  operation: string;
  protocol: string;
  request: Record<string, unknown>;
  worker: { path: string; sha256: string };
};

const directRepositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repositoryRoot = process.env.NOA_KWS_REPOSITORY_ROOT ??
  (fs.existsSync(path.join(directRepositoryRoot, "scripts", "lib", "knockout-workspace.mjs"))
    ? directRepositoryRoot
    : path.resolve(directRepositoryRoot, ".."));
const workspace = await import(
  pathToFileURL(path.join(repositoryRoot, "scripts/lib/knockout-workspace.mjs")).href
) as {
  KNOCKOUT_WORKSPACE_ERROR_CODES: Record<string, string>;
  KNOCKOUT_WORKSPACE_ARM_LIMITS: { maxRetainedArms: number; maxRetainedBytes: number };
  KNOCKOUT_WORKSPACE_ARM_ROLES: string[];
  KNOCKOUT_WORKSPACE_ARM_WORKER_TIMEOUT_LIMIT_MS: number;
  KNOCKOUT_WORKSPACE_CAPTURE_LIMITS: CaptureLimits;
  KNOCKOUT_WORKSPACE_CAPTURE_TIMEOUT_LIMIT_MS: number;
  KNOCKOUT_WORKSPACE_COMMAND_TIMEOUT_LIMIT_MS: number;
  KNOCKOUT_WORKSPACE_CAPTURE_STATUS?: string;
  KNOCKOUT_WORKSPACE_PROTOCOLS: Record<string, string> & { workerSubject: string };
  KNOCKOUT_WORKSPACE_STATE_EVIDENCE_ROLE?: string;
  KNOCKOUT_WORKER_OPERATIONS: Record<string, string> & {
    ATTEST_ARM: string;
    OBSERVE_KNOCKOUT_BASELINE: string;
    OBSERVE_KNOCKOUT_POSTCHECK: string;
    RUN_KNOCKOUT: string;
    RUN_KNOCKOUT_SELFTEST: string;
  };
  canonicalJsonBytes: (value: unknown) => Buffer;
  candidateManifestSha256: (manifest: object) => string;
  createKnockoutWorkerSubject: (options: {
    operation: string;
    request: Record<string, unknown>;
    workerSha256: string;
  }) => WorkerSubject;
  knockoutBaselineKeySha256: (options: {
    dependencies: Record<string, unknown>;
    kind: string;
    suite: unknown[];
  }) => string;
  knockoutBaselineWireFromObservation: (
    baselineKeySha256: string,
    observation: Record<string, unknown>,
    options: { workspaceRoot: string },
  ) => Record<string, unknown>;
  knockoutResultWireFromEvidence: (options: {
    baselineKeySha256: string;
    entryId: string;
    result: Record<string, unknown>;
  }) => Record<string, unknown>;
  knockoutWorkerSubjectSha256: (subject: WorkerSubject) => string;
  captureAndSealCandidate: (options: {
    commandTimeoutMs?: number;
    custodyRoot: string;
    gitExecutable?: string;
    hooks?: {
      afterManifestPublication?: (value: {
        attempt: number; evidenceRoot: string; manifestPath: string; workspaceRoot: string;
      }) => void;
      afterPreObservation?: (value: { attempt: number; sourceRoot: string }) => void;
      afterPreSealObservation?: (value: {
        attempt: number; evidenceRoot: string; workspaceRoot: string;
      }) => void;
      beforeStatePublication?: (value: {
        attempt: number; evidenceRoot: string; statePath: string; workspaceRoot: string;
      }) => void;
      afterWorktreeCopy?: (value: {
        attempt: number; evidenceRoot: string; workspaceRoot: string;
      }) => void;
    };
    limits?: CaptureLimits;
    maxAttempts?: number;
    operationTimeoutMs?: number;
    sourceRoot: string;
  }) => Capture;
  openKnockoutCustody: (captureCapability: Capture, options: {
    commandTimeoutMs?: number;
    gitExecutable?: string | null;
    limits?: CaptureLimits;
    maxRetainedArms: number;
    maxRetainedBytes: number;
  }) => KnockoutCustody;
  acquireSourceLease: (custodyCapability: KnockoutCustody) => SourceLease;
  acquireCooperativeSourceLease: (
    sourceLease: SourceLease,
    options?: { handshakeTimeoutMs?: number },
  ) => Promise<CooperativeSourceLease>;
  confirmCooperativeSourceLease: (
    cooperativeLease: CooperativeSourceLease,
  ) => Promise<{ lockScope: string; sourceLeaseSha256: string; status: string }>;
  closeCooperativeSourceLease: (
    cooperativeLease: CooperativeSourceLease,
  ) => Promise<{
    helperExitCode: number | null;
    helperReaped: boolean;
    helperSignal: string | null;
    lockScope: string;
    sourceRelease: SourceRelease;
    status: string;
  }>;
  admitArmPlan: (cooperativeLease: CooperativeSourceLease, options: {
    arms: Array<{ armId: string; role: string; subjectSha256: string }>;
  }) => ArmPlan;
  materializeArm: (planCapability: ArmPlan, armId: string) => DisposableArm;
  knockoutWorkerOperationRole: (operation: string) => string;
  cancelAdmittedArm: (planCapability: ArmPlan, armId: string, reasonCode: string) => {
    status: string;
  };
  cancelMaterializedArm: (
    cooperativeLease: CooperativeSourceLease,
    armCapability: DisposableArm,
    reasonCode: string,
  ) => { status: string };
  runArmWorker: (
    cooperativeLease: CooperativeSourceLease,
    armCapability: DisposableArm,
    options: { subject: WorkerSubject; timeoutMs?: number },
  ) => Promise<{
    originalProcessGroupAbsent: boolean;
    processContainmentScope: string;
    resultPublication: { sha256: string };
    status: string;
    terminalPublication: {
      path: string;
      sha256: string;
      terminal: Record<string, unknown>;
    };
    workerResult: {
      observation: Record<string, unknown>;
      status: string;
    };
    workspaceRoot: string;
  }>;
  releaseSourceLease: (sourceLease: SourceLease) => SourceRelease;
  publishTerminalEvidence: (options: {
    allowedTerminalStatuses: string[];
    commandTimeoutMs?: number;
    directory: string;
    expectedCandidateManifestSha256: string;
    expectedDirectoryIdentity?: string;
    filename?: string;
    simulateShortWriteAfterBytes?: number;
    terminalBytes: Buffer;
  }) => {
    createdIdentity: string;
    createdObservation: FileObservation;
    directoryIdentity: string;
    identityVerified: boolean;
    path: string;
    sha256: string;
    terminal: Record<string, unknown>;
  };
  reopenTerminalEvidence: (options: {
    allowedTerminalStatuses: string[];
    commandTimeoutMs?: number;
    expectedCandidateManifestSha256: string;
    expectedDirectoryIdentity: string;
    expectedObservation: FileObservation | null;
    expectedSha256: string | null;
    terminalPath: string;
  }) => {
    identity: string;
    identityVerified: boolean;
    observation: FileObservation;
    path: string;
    sha256: string;
    terminal: Record<string, unknown>;
  };
  censusWorkspace: (root: string, options?: {
    allowRootGit?: boolean;
    commandTimeoutMs?: number;
    limits?: CaptureLimits;
    rootGitPolicy?: "absent" | "exclude" | "include";
  }) => {
    allocatedBytes: number;
    limits: CaptureLimits;
    logicalBytes: number;
    materialSha256: string;
    maxDepth: number;
    nodeCount: number;
    nodes: Array<{
      path: string;
      provenance: {
        classification: string;
        length: number;
        present: boolean;
        sha256: string | null;
      };
      sha256?: string;
      type: string;
    }>;
    observationSha256: string;
  };
  resolveGitExecutable: () => string;
  observeSourceGit: (sourceRoot: string, options?: {
    commandTimeoutMs?: number;
    gitExecutable?: string;
    scratchRoot?: string;
  }) => SourceSnapshot["git"];
  scrubGitEnvironment: (environment?: Record<string, string>) => Readonly<Record<string, string>>;
  verifySealedSeed: (
    captureCapability: Capture,
  ) => {
    materialSha256: string;
    nodeCount: number;
    observationSha256: string;
  };
  verifySourceUnchanged: (
    expectedSnapshot: SourceSnapshot,
    options?: { commandTimeoutMs?: number; gitExecutable?: string },
  ) => SourceSnapshot;
};
const knockoutRunner = await import(
  pathToFileURL(path.join(repositoryRoot, "scripts/lib/knockout-runner.mjs")).href
) as {
  BOUNDARY_CANDIDATE_TIER_A_KNOCKOUT_PROVENANCE_EXPECTATION: Record<string, unknown>;
  assertKnockoutMigrationBarrier: (root: string) => true;
  createBuildStateGuard: (options: {
    cacheDir?: string;
    protectedRoots?: string[];
    root: string;
  }) => {
    cacheDir: string;
    release: () => boolean;
    start: () => { ok: boolean; kind?: string; detail?: string };
  };
  ISOLATED_KNOCKOUT_SWEEP_TIMEOUTS: {
    captureTimeoutMs: number;
    minimumWorkerEnvelopeMs: number;
    suiteTimeoutMs: number;
    workerTimeoutMs: number;
  };
  createIsolatedCustodyRoot: (cacheHome?: string) => string;
  finalizeIsolatedSetupIntegrityPostcheck: (options: Record<string, unknown>) => {
    detail?: string;
    postRestoreBaselineVerified?: boolean;
    verdict: string;
  };
  runIsolatedKnockoutSweep: (options: Record<string, unknown>) => Promise<{
    baselines: Array<{ observation: { timedOut: boolean }; workspaceRoot: string }>;
    closeEvidence: { sourceRelease: { status: string } };
    mutants: Array<{ entryId: string; workspaceRoot: string }>;
    results: Array<{
      detail?: string | null;
      id: string;
      restored: boolean;
      verdict: string;
      workspaceDisposition: string;
    }>;
    status: string;
  }>;
};

const TEST_TERMINAL_STATUSES = ["PASS", "FAIL", "REFUSED", "INDETERMINATE"];

function publishTerminalEvidence(options: {
  directory: string;
  expectedDirectoryIdentity?: string;
  filename?: string;
  simulateShortWriteAfterBytes?: number;
  terminal: object;
}) {
  const terminalBytes = workspace.canonicalJsonBytes(options.terminal);
  const terminal = JSON.parse(terminalBytes.toString("utf8")) as {
    candidateManifestSha256?: unknown;
  };
  const expectedCandidateManifestSha256 =
    typeof terminal.candidateManifestSha256 === "string"
      ? terminal.candidateManifestSha256
      : "0".repeat(64);
  return workspace.publishTerminalEvidence({
    allowedTerminalStatuses: TEST_TERMINAL_STATUSES,
    directory: options.directory,
    expectedCandidateManifestSha256,
    expectedDirectoryIdentity: options.expectedDirectoryIdentity,
    filename: options.filename,
    simulateShortWriteAfterBytes: options.simulateShortWriteAfterBytes,
    terminalBytes,
  });
}

function reopenTerminalEvidence(
  terminalPath: string,
  expectedSha256: string,
  expectedObservation: FileObservation,
  expectedCandidateManifestSha256: string | null = null,
) {
  let candidate = expectedCandidateManifestSha256;
  if (candidate === null) {
    try {
      const terminal = JSON.parse(fs.readFileSync(terminalPath, "utf8")) as {
        candidateManifestSha256?: unknown;
      };
      if (typeof terminal.candidateManifestSha256 === "string") {
        candidate = terminal.candidateManifestSha256;
      }
    } catch {}
  }
  const directoryStat = fs.lstatSync(path.dirname(terminalPath), { bigint: true });
  const expectedDirectoryIdentity = `${directoryStat.dev}:${directoryStat.ino}`;
  return workspace.reopenTerminalEvidence({
    allowedTerminalStatuses: TEST_TERMINAL_STATUSES,
    expectedCandidateManifestSha256: candidate ?? "0".repeat(64),
    expectedDirectoryIdentity,
    expectedObservation,
    expectedSha256,
    terminalPath,
  });
}

const gitExecutable = workspace.resolveGitExecutable();
const gitEnvironment = workspace.scrubGitEnvironment();

function workspaceErrorCode(name: string): string {
  const code = workspace.KNOCKOUT_WORKSPACE_ERROR_CODES[name];
  if (typeof code !== "string" || code.length === 0) {
    throw new Error(`knockout-workspace error code is unavailable: ${name}`);
  }
  return code;
}

function git(root: string, args: string[], encoding?: BufferEncoding): string;
function git(root: string, args: string[], encoding: null): Buffer;
function git(root: string, args: string[], encoding: BufferEncoding | null = "utf8"): string | Buffer {
  return execFileSync(gitExecutable, args, {
    cwd: root,
    encoding,
    env: gitEnvironment,
    maxBuffer: 64 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function privateTemp(prefix: string): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  fs.chmodSync(root, 0o700);
  return root;
}

function pathExistsNoFollow(candidate: string): boolean {
  try { fs.lstatSync(candidate); return true; }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
}

function removeFixturePath(candidate: string): void {
  if (!pathExistsNoFollow(candidate)) return;
  if (fs.lstatSync(candidate).isSymbolicLink()) fs.unlinkSync(candidate);
  else fs.rmSync(candidate, { recursive: true, force: true });
}

function requiredExecutable(candidates: string[], label: string): string {
  for (const candidate of candidates) {
    try {
      const stat = fs.statSync(candidate);
      if (stat.isFile() && (stat.mode & 0o111) !== 0) return candidate;
    } catch {}
  }
  throw new Error(`${label} is required for this platform regression`);
}

function initRepository(root: string): void {
  git(root, ["init", "-q", "--object-format=sha1", "--template="]);
  git(root, ["config", "--local", "user.name", "NOA Workspace Test"]);
  git(root, ["config", "--local", "user.email", "workspace-test@noa.invalid"]);
  git(root, ["config", "--local", "core.filemode", "true"]);
}

function statusBytes(root: string): Buffer {
  return git(
    root,
    ["status", "--porcelain=v2", "-z", "--untracked-files=all", "--ignored=matching"],
    null,
  ) as Buffer;
}

function sha256File(file: string): string {
  const digest = execFileSync("/usr/bin/shasum", ["-a", "256", file], {
    encoding: "utf8",
  }).split(" ")[0];
  if (typeof digest !== "string" || !/^[0-9a-f]{64}$/.test(digest)) {
    throw new Error("shasum did not return one lowercase SHA-256 digest");
  }
  return digest;
}

function fileObservationForTest(file: string): FileObservation {
  const stat = fs.lstatSync(file, { bigint: true });
  return {
    ctimeNs: String(stat.ctimeNs),
    identity: `${stat.dev}:${stat.ino}`,
    mode: Number(stat.mode & 0o7777n),
    mtimeNs: String(stat.mtimeNs),
    nlink: Number(stat.nlink),
    size: Number(stat.size),
  };
}

function sha256Bytes(bytes: Buffer): string {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function sourceMaterialSha256(nodes: Capture["manifest"]["source"]["nodes"]): string {
  const materialNodes = nodes.map((node) => {
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
  });
  return sha256Bytes(workspace.canonicalJsonBytes(materialNodes));
}

function gitFileStableObservation(file: string): Record<string, number | string> {
  const stat = fs.lstatSync(file, { bigint: true });
  assert.equal(stat.isFile(), true, `${file} is not a regular file`);
  assert.equal(stat.isSymbolicLink(), false, `${file} is a symlink`);
  return {
    ctimeNs: String(stat.ctimeNs),
    dev: String(stat.dev),
    ino: String(stat.ino),
    mode: Number(stat.mode & 0o7777n),
    mtimeNs: String(stat.mtimeNs),
    nlink: Number(stat.nlink),
    size: Number(stat.size),
  };
}

type RawIndexEntrySummary = {
  assumeValid: boolean;
  intentToAdd: boolean;
  path: string;
  skipWorktree: boolean;
  stage: number;
  stat: string;
};

function rawIndexSummary(
  indexPath: string,
  objectFormat: "sha1" | "sha256" = "sha1",
): {
  entries: RawIndexEntrySummary[];
  extensionSizes: Record<string, number>;
  extensions: string[];
  version: number;
} {
  const bytes = fs.readFileSync(indexPath);
  const hashLength = objectFormat === "sha256" ? 32 : 20;
  const hashAlgorithm = objectFormat;
  assert.equal(bytes.subarray(0, 4).toString("ascii"), "DIRC");
  const version = bytes.readUInt32BE(4);
  assert.ok(version === 2 || version === 3, `test parser does not support index v${version}`);
  const count = bytes.readUInt32BE(8);
  const contentEnd = bytes.length - hashLength;
  assert.deepEqual(
    crypto.createHash(hashAlgorithm).update(bytes.subarray(0, contentEnd)).digest(),
    bytes.subarray(contentEnd),
  );
  const entries: RawIndexEntrySummary[] = [];
  let offset = 12;
  for (let ordinal = 0; ordinal < count; ordinal++) {
    const entryStart = offset;
    const stat = bytes.subarray(offset, offset + 40).toString("hex");
    offset += 40 + hashLength;
    const flags = bytes.readUInt16BE(offset);
    offset += 2;
    let extendedFlags = 0;
    if ((flags & 0x4000) !== 0) {
      extendedFlags = bytes.readUInt16BE(offset);
      offset += 2;
    }
    const terminator = bytes.indexOf(0, offset);
    assert.ok(terminator >= offset && terminator < contentEnd, `entry ${ordinal} has no terminator`);
    entries.push({
      assumeValid: (flags & 0x8000) !== 0,
      intentToAdd: (extendedFlags & 0x2000) !== 0,
      path: bytes.subarray(offset, terminator).toString("utf8"),
      skipWorktree: (extendedFlags & 0x4000) !== 0,
      stage: (flags >>> 12) & 0x3,
      stat,
    });
    offset = entryStart + Math.ceil((terminator + 1 - entryStart) / 8) * 8;
  }
  const extensions: string[] = [];
  const extensionSizes: Record<string, number> = {};
  while (offset < contentEnd) {
    const signature = bytes.subarray(offset, offset + 4).toString("latin1");
    const size = bytes.readUInt32BE(offset + 4);
    extensions.push(signature);
    extensionSizes[signature] = size;
    offset += 8 + size;
    assert.ok(offset <= contentEnd, `extension ${signature} exceeds the index`);
  }
  assert.equal(offset, contentEnd);
  return { entries, extensionSizes, extensions, version };
}

function appendRawIndexExtension(
  root: string,
  signature: string,
  payload: Buffer,
): void {
  assert.equal(Buffer.byteLength(signature, "latin1"), 4);
  const indexPath = path.join(root, ".git", "index");
  const objectFormat = (git(root, ["rev-parse", "--show-object-format"]) as string).trim();
  assert.ok(objectFormat === "sha1" || objectFormat === "sha256");
  const hashLength = objectFormat === "sha256" ? 32 : 20;
  const bytes = fs.readFileSync(indexPath);
  const header = Buffer.alloc(8);
  header.write(signature, 0, 4, "latin1");
  header.writeUInt32BE(payload.length, 4);
  const content = Buffer.concat([bytes.subarray(0, -hashLength), header, payload]);
  fs.writeFileSync(indexPath, Buffer.concat([
    content,
    crypto.createHash(objectFormat).update(content).digest(),
  ]));
}

function replaceRawIndexPath(root: string, original: string, replacement: string): void {
  const originalBytes = Buffer.from(original, "utf8");
  const replacementBytes = Buffer.from(replacement, "utf8");
  assert.equal(replacementBytes.length, originalBytes.length, "replacement path length changed");
  const indexPath = path.join(root, ".git", "index");
  const objectFormat = (git(root, ["rev-parse", "--show-object-format"]) as string).trim();
  assert.ok(objectFormat === "sha1" || objectFormat === "sha256");
  const hashLength = objectFormat === "sha256" ? 32 : 20;
  const bytes = fs.readFileSync(indexPath);
  const content = Buffer.from(bytes.subarray(0, -hashLength));
  const needle = Buffer.concat([originalBytes, Buffer.from([0])]);
  const offset = content.indexOf(needle);
  assert.ok(offset >= 0, `index does not contain ${original}`);
  assert.equal(content.indexOf(needle, offset + 1), -1, `index repeats ${original}`);
  replacementBytes.copy(content, offset);
  fs.writeFileSync(indexPath, Buffer.concat([
    content,
    crypto.createHash(objectFormat).update(content).digest(),
  ]));
}

function pathStableObservation(file: string): Record<string, boolean | number | string> {
  const stat = fs.lstatSync(file, { bigint: true });
  return {
    ctimeNs: String(stat.ctimeNs),
    dev: String(stat.dev),
    ino: String(stat.ino),
    isDirectory: stat.isDirectory(),
    isFile: stat.isFile(),
    isSymbolicLink: stat.isSymbolicLink(),
    mode: Number(stat.mode & 0o7777n),
    mtimeNs: String(stat.mtimeNs),
    nlink: Number(stat.nlink),
    size: Number(stat.size),
  };
}

function errorChain(error: unknown): string {
  const chain: Array<{
    code: unknown;
    details: unknown;
    errno: unknown;
    message: unknown;
    name: unknown;
    pid: unknown;
    signal: unknown;
    status: unknown;
    syscall: unknown;
  }> = [];
  let current: unknown = error;
  while (current instanceof Error && chain.length < 8) {
    const typed = current as WorkspaceError & {
      cause?: unknown;
      details?: unknown;
      errno?: unknown;
      pid?: unknown;
      signal?: unknown;
      status?: unknown;
      syscall?: unknown;
    };
    chain.push({
      code: typed.code,
      details: typed.details,
      errno: typed.errno,
      message: typed.message,
      name: typed.name,
      pid: typed.pid,
      signal: typed.signal,
      status: typed.status,
      syscall: typed.syscall,
    });
    current = typed.cause;
  }
  return JSON.stringify(chain);
}

function causeWithCode(error: unknown, code: string): WorkspaceError | null {
  let current: unknown = error;
  for (let depth = 0; current instanceof Error && depth < 8; depth++) {
    const typed = current as WorkspaceError & { cause?: unknown };
    if (typed.code === code) return typed;
    current = typed.cause;
  }
  return null;
}

function errorTreeHasCode(error: unknown, code: string, seen = new Set<unknown>()): boolean {
  if (!(error instanceof Error) || seen.has(error)) return false;
  seen.add(error);
  const typed = error as WorkspaceError & { cause?: unknown; errors?: unknown[] };
  if (typed.code === code) return true;
  if (errorTreeHasCode(typed.cause, code, seen)) return true;
  return Array.isArray(typed.errors) && typed.errors.some((nested) =>
    errorTreeHasCode(nested, code, seen));
}

function reportedPrivateRoots(value: unknown): RetainedPrivateRoot[] {
  const roots = (value as { retainedPrivateRoots?: unknown } | null)?.retainedPrivateRoots;
  if (!Array.isArray(roots)) return [];
  return roots.map((root: unknown) => {
    assert.equal(typeof (root as { identity?: unknown })?.identity, "string");
    assert.equal(typeof (root as { path?: unknown })?.path, "string");
    return {
      identity: (root as { identity: string }).identity,
      path: (root as { path: string }).path,
    };
  });
}

function errorPrivateRoots(error: WorkspaceError | null): RetainedPrivateRoot[] {
  return error === null ? [] : reportedPrivateRoots(error.details);
}

function assertCustodyMatchesReportedRoots(
  custodyRoot: string,
  roots: RetainedPrivateRoot[],
): string[] {
  const custodyPhysical = fs.realpathSync(custodyRoot);
  const directRoots = roots.filter((root) => path.dirname(root.path) === custodyPhysical);
  assert.equal(directRoots.length, roots.length, "retained root escaped capture custody");
  for (const root of directRoots) {
    const stat = fs.lstatSync(root.path, { bigint: true });
    assert.equal(`${stat.dev}:${stat.ino}`, root.identity, "reported custody identity changed");
  }
  const directEntries = [...new Set(directRoots.map((root) => path.basename(root.path)))].sort();
  assert.deepEqual(fs.readdirSync(custodyPhysical).sort(), directEntries);
  return directEntries;
}

function errorTerminalPublication(error: WorkspaceError | null): RetainedTerminalPublication | null {
  const retained = error?.details?.retainedTerminalPublication;
  return retained === undefined ? null : retained;
}

function requiredString(value: unknown, message: string): string {
  assert.equal(typeof value, "string", message);
  return value as string;
}

function cleanupReportedScratchRoots(roots: RetainedPrivateRoot[]): void {
  const tempRoot = fs.realpathSync(os.tmpdir());
  for (const root of roots) {
    if (
      path.dirname(root.path) !== tempRoot ||
      !/^(?:noa-kws-git-observe-|noa-kws-index-normalize-|noa-kws-object-read-)/.test(
        path.basename(root.path),
      )
    ) continue;
    const stat = fs.lstatSync(root.path, { bigint: true });
    assert.equal(`${stat.dev}:${stat.ino}`, root.identity, "reported scratch identity changed");
    fs.rmSync(root.path, { recursive: true, force: false });
  }
}

function splitIndexFixture(prefix: string): {
  custody: string;
  indexPath: string;
  sharedBasename: string;
  sharedPath: string;
  source: string;
  tools: string;
} {
  const source = privateTemp(`noa-kws-${prefix}-source-`);
  const custody = privateTemp(`noa-kws-${prefix}-custody-`);
  const tools = privateTemp(`noa-kws-${prefix}-tools-`);
  initRepository(source);
  fs.writeFileSync(path.join(source, "tracked.txt"), "base\n");
  git(source, ["add", "--all"]);
  git(source, ["commit", "-q", "-m", `${prefix} base`]);
  git(source, ["update-index", "--split-index"]);
  const sharedPathText = (git(source, ["rev-parse", "--shared-index-path"]) as string).trim();
  assert.notEqual(sharedPathText, "", `${prefix} fixture did not retain a split index`);
  const reported = path.resolve(source, sharedPathText);
  const sharedPath = path.join(fs.realpathSync(path.dirname(reported)), path.basename(reported));
  const sharedBasename = path.basename(sharedPath);
  assert.match(sharedBasename, /^sharedindex\.[0-9a-f]{40}$/);
  return {
    custody,
    indexPath: path.join(source, ".git", "index"),
    sharedBasename,
    sharedPath,
    source,
    tools,
  };
}

function minimalCaptureFixture(prefix: string): {
  custody: string;
  source: string;
  trackedPath: string;
} {
  const source = privateTemp(`noa-kws-${prefix}-source-`);
  const custody = privateTemp(`noa-kws-${prefix}-custody-`);
  const trackedPath = path.join(source, "tracked.txt");
  initRepository(source);
  fs.writeFileSync(trackedPath, "stable source bytes\n", { mode: 0o600 });
  fs.mkdirSync(path.join(source, "nested"), { mode: 0o700 });
  fs.writeFileSync(path.join(source, "nested", "child.txt"), "nested bytes\n", { mode: 0o600 });
  git(source, ["add", "--all"]);
  git(source, ["commit", "-q", "-m", `${prefix} base`]);
  return { custody, source, trackedPath };
}

function withSyntheticMacMetadata<T>(operation: () => T): {
  helperCalls: number;
  result: T;
} {
  // These consumer-capability tests need a genuine registered capture, while the
  // native ACL/xattr backend and its exact bytes are covered by dedicated tests.
  // Keep this unrelated setup bounded by synthesizing descriptor-bound empty metadata.
  if (process.platform !== "darwin") return { helperCalls: 0, result: operation() };
  const descriptor = Object.getOwnPropertyDescriptor(childProcess, "spawnSync");
  assert.ok(descriptor !== undefined);
  const originalSpawnSync = childProcess.spawnSync;
  let helperCalls = 0;
  let result: T;
  try {
    Object.defineProperty(childProcess, "spawnSync", {
      ...descriptor,
      value: ((...args: Parameters<typeof childProcess.spawnSync>) => {
        const childArgs = args[1];
        if (
          args[0] === "/usr/bin/perl" && Array.isArray(childArgs) &&
          childArgs.includes("/usr/bin/python3") &&
          (childArgs.includes("acl") || childArgs.includes("xattr"))
        ) {
          const stdio = (args[2] as { stdio?: unknown[] } | undefined)?.stdio;
          assert.ok(Array.isArray(stdio));
          const nodeFds = stdio.slice(4);
          const declaredCount = Number(childArgs.at(-1));
          assert.equal(declaredCount, nodeFds.length);
          const mode = childArgs.includes("acl") ? "acl" : "xattr";
          const records = nodeFds.map((fd, index) => {
            assert.equal(typeof fd, "number");
            const observed = fs.fstatSync(fd as number, { bigint: true });
            const stat = {
              ctimeNs: String(observed.ctimeNs),
              identity: `${observed.dev}:${observed.ino}`,
              mode: Number(observed.mode & 0o7777n),
              mtimeNs: String(observed.mtimeNs),
              nlink: Number(observed.nlink),
              size: Number(observed.size),
              type: observed.isSymbolicLink() ? "symlink" : observed.isDirectory()
                ? "directory" : observed.isFile() ? "file" : "other",
              uid: Number(observed.uid),
            };
            return mode === "acl"
              ? { fd: index + 4, present: false, stat }
              : { fd: index + 4, namesBase64: [], provenanceBase64: null, stat };
          });
          const stdout = Buffer.from(JSON.stringify(records));
          const stderr = Buffer.alloc(0);
          helperCalls += 1;
          return {
            output: [null, stdout, stderr],
            pid: process.pid,
            signal: null,
            status: 0,
            stderr,
            stdout,
          } as unknown as ReturnType<typeof childProcess.spawnSync>;
        }
        return Reflect.apply(originalSpawnSync, childProcess, args);
      }) as typeof childProcess.spawnSync,
    });
    syncBuiltinESMExports();
    result = operation();
  } finally {
    Object.defineProperty(childProcess, "spawnSync", descriptor);
    syncBuiltinESMExports();
  }
  return { helperCalls, result };
}

function installArmWorkerFixture(
  source: string,
  commitMessage: string,
  workerSource: string | null = null,
): string {
  const destination = path.join(source, "scripts", "lib");
  fs.mkdirSync(destination, { recursive: true, mode: 0o700 });
  for (const filename of [
    "knockout-workspace.mjs",
    "knockout-workspace-worker.mjs",
    "safe-npm-tarball.mjs",
  ]) {
    fs.copyFileSync(
      path.join(repositoryRoot, "scripts", "lib", filename),
      path.join(destination, filename),
    );
    fs.chmodSync(path.join(destination, filename), 0o600);
  }
  if (workerSource !== null) {
    fs.writeFileSync(
      path.join(destination, "knockout-workspace-worker.mjs"),
      workerSource,
      { mode: 0o600 },
    );
  }
  git(source, ["add", "--all"]);
  git(source, ["commit", "-q", "-m", commitMessage]);
  return sha256File(path.join(destination, "knockout-workspace-worker.mjs"));
}

function installPhase2RunnerFixture(source: string, commitMessage: string): void {
  const scripts = path.join(source, "scripts");
  const library = path.join(scripts, "lib");
  fs.mkdirSync(library, { recursive: true, mode: 0o700 });
  for (const filename of [
    "boundary-bootstrap.mjs",
    "boundary-gate-provenance.mjs",
    "gate-event-contract.mjs",
    "knockout-runner.mjs",
    "knockout-test-observer.mjs",
    "knockout-workspace.mjs",
    "knockout-workspace-worker.mjs",
    "proof-event-contract.mjs",
    "proof-event-reporter.mjs",
    "proof-resolve.mjs",
    "safe-npm-tarball.mjs",
    "typescript-test-hooks.mjs",
    "typescript-test-register.mjs",
  ]) {
    fs.copyFileSync(
      path.join(repositoryRoot, "scripts", "lib", filename),
      path.join(library, filename),
    );
    fs.chmodSync(path.join(library, filename), 0o600);
  }
  fs.writeFileSync(
    path.join(scripts, "resolver-inventory.json"),
    `${JSON.stringify({ proofs: {} }, null, 2)}\n`,
    { mode: 0o600 },
  );
  fs.writeFileSync(
    path.join(scripts, "lint-control-knockout.selftest.mjs"),
    [
      "import { emitGateEvidence } from './lib/gate-event-contract.mjs';",
      "if (!process.argv.includes('--knockout-json')) process.exit(2);",
      "emitGateEvidence('knockout-selftest', []);",
      "",
    ].join("\n"),
    { mode: 0o600 },
  );
  const typescriptPackage = path.join(source, "node_modules", "typescript");
  fs.mkdirSync(typescriptPackage, { recursive: true, mode: 0o700 });
  fs.writeFileSync(
    path.join(typescriptPackage, "package.json"),
    `${JSON.stringify({
      name: "typescript",
      private: true,
      type: "module",
      exports: "./index.mjs",
    }, null, 2)}\n`,
    { mode: 0o600 },
  );
  fs.writeFileSync(
    path.join(typescriptPackage, "index.mjs"),
    [
      "// These direct-gate fixtures do not resolve TypeScript proofs.",
      "// Fail closed if a fixture unexpectedly starts using the compiler API.",
      "export default new Proxy(Object.freeze({}), {",
      "  get() { throw new Error('TypeScript proof resolution is unavailable in this direct-gate fixture'); },",
      "});",
      "",
    ].join("\n"),
    { mode: 0o600 },
  );
  fs.writeFileSync(path.join(source, ".gitignore"), "node_modules/\n", { mode: 0o600 });
  git(source, ["add", "--all"]);
  git(source, ["commit", "-q", "-m", commitMessage]);
}

function installFixtureKnockoutRegistry(
  source: string,
  registry: Array<Record<string, unknown>>,
  proofInventory: Record<string, unknown> = {},
): void {
  fs.writeFileSync(
    path.join(source, "scripts", "lint-control-knockout.mjs"),
    [
      `const registry = ${JSON.stringify(registry)};`,
      `const proofInventory = ${JSON.stringify(proofInventory)};`,
      "export function knockoutRegistrySnapshot() {",
      "  return Object.freeze({ proofInventory, registry });",
      "}",
      "",
    ].join("\n"),
    { mode: 0o600 },
  );
}

function armWorkerSubject(
  workerSha256: string,
  operation = "ATTEST_ARM",
  request: Record<string, unknown> = {},
): WorkerSubject {
  return {
    operation,
    protocol: workspace.KNOCKOUT_WORKSPACE_PROTOCOLS.workerSubject,
    request,
    worker: {
      path: "scripts/lib/knockout-workspace-worker.mjs",
      sha256: workerSha256,
    },
  };
}

function armWorkerSubjectSha256(subject: WorkerSubject): string {
  return crypto.createHash("sha256")
    .update(workspace.canonicalJsonBytes(subject))
    .digest("hex");
}

function linkedWorktreeFixture(prefix: string): {
  custody: string;
  fixtureRoot: string;
  linked: string;
  main: string;
} {
  const fixtureRoot = privateTemp(`noa-kws-${prefix}-root-`);
  const custody = privateTemp(`noa-kws-${prefix}-custody-`);
  const main = path.join(fixtureRoot, "main");
  const linked = path.join(fixtureRoot, "linked");
  fs.mkdirSync(main, { mode: 0o700 });
  initRepository(main);
  fs.writeFileSync(path.join(main, "tracked.txt"), `${prefix} base\n`, { mode: 0o600 });
  git(main, ["add", "--all"]);
  git(main, ["commit", "-q", "-m", `${prefix} base`]);
  git(main, ["worktree", "add", "-q", "-b", `${prefix}-linked`, linked]);
  return { custody, fixtureRoot, linked, main };
}

function configureCanonicalOriginUpstream(fixture: ReturnType<typeof linkedWorktreeFixture>): {
  branchName: string;
  headRef: string;
} {
  const branchName = (git(fixture.linked, ["branch", "--show-current"]) as string).trim();
  assert.notEqual(branchName, "", "linked worktree fixture unexpectedly has a detached HEAD");
  const head = (git(fixture.linked, ["rev-parse", "HEAD"]) as string).trim();
  git(fixture.main, ["remote", "add", "origin", fixture.main]);
  git(fixture.main, ["update-ref", `refs/remotes/origin/${branchName}`, head]);
  git(fixture.linked, ["branch", "--set-upstream-to", `origin/${branchName}`]);
  assert.equal(
    (git(fixture.linked, ["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}"]) as string).trim(),
    `origin/${branchName}`,
  );
  return { branchName, headRef: `refs/heads/${branchName}` };
}

function captureLimits(overrides: Partial<CaptureLimits> = {}): CaptureLimits {
  return { ...workspace.KNOCKOUT_WORKSPACE_CAPTURE_LIMITS, ...overrides };
}

function regularFilesBelow(root: string): string[] {
  const files: string[] = [];
  const pending = [root];
  while (pending.length > 0) {
    const directory = pending.pop();
    assert.notEqual(directory, undefined);
    for (const entry of fs.readdirSync(directory!, { withFileTypes: true })) {
      const absolute = path.join(directory!, entry.name);
      const stat = fs.lstatSync(absolute);
      assert.equal(stat.isSymbolicLink(), false, `unexpected symlink below ${root}`);
      if (stat.isDirectory()) pending.push(absolute);
      else if (stat.isFile()) files.push(absolute);
      else assert.fail(`unexpected special node below ${root}: ${absolute}`);
    }
  }
  return files.sort();
}

test("canonical candidate binding preserves reserved keys and refuses ambiguous or active input", () => {
  const first = JSON.parse('{"__proto__":{"tag":"A"},"safe":1}') as Record<string, unknown>;
  const second = JSON.parse('{"__proto__":{"tag":"B"},"safe":1}') as Record<string, unknown>;
  assert.equal(Object.prototype.hasOwnProperty.call(first, "__proto__"), true);
  assert.notEqual(
    workspace.candidateManifestSha256(first),
    workspace.candidateManifestSha256(second),
    "different own __proto__ values collapsed to one candidate identity",
  );
  assert.deepEqual(first.__proto__, { tag: "A" });
  assert.deepEqual(second.__proto__, { tag: "B" });

  const sparse = new Array(1);
  const named = [null] as Array<null> & { label?: string };
  named.label = "not-json";
  for (const ambiguous of [{ value: sparse }, { value: named }]) {
    assert.throws(
      () => workspace.canonicalJsonBytes(ambiguous),
      (error: WorkspaceError) => error.code === workspaceErrorCode("INVALID_ARGUMENT"),
    );
  }
  let getterReads = 0;
  const objectAccessor = Object.defineProperty({}, "value", {
    enumerable: true,
    get() {
      getterReads += 1;
      return "active object";
    },
  });
  const arrayAccessor = [null];
  Object.defineProperty(arrayAccessor, "0", {
    enumerable: true,
    get() {
      getterReads += 1;
      return "active array";
    },
  });
  let proxyTraps = 0;
  const proxy = new Proxy({}, {
    getOwnPropertyDescriptor() {
      proxyTraps += 1;
      return undefined;
    },
    getPrototypeOf() {
      proxyTraps += 1;
      return Object.prototype;
    },
    ownKeys() {
      proxyTraps += 1;
      return [];
    },
  });
  for (const active of [objectAccessor, arrayAccessor, proxy]) {
    assert.throws(
      () => workspace.canonicalJsonBytes(active),
      (error: WorkspaceError) => error.code === workspaceErrorCode("INVALID_ARGUMENT"),
    );
  }
  assert.equal(getterReads, 0, "canonicalization invoked an accessor");
  assert.equal(proxyTraps, 0, "canonicalization invoked a Proxy trap");
  assert.deepEqual(JSON.parse(workspace.canonicalJsonBytes({ value: [null] }).toString("utf8")), {
    value: [null],
  });
  assert.equal(0 in sparse, false, "canonicalization changed the caller's sparse array");
  assert.equal(named.label, "not-json", "canonicalization changed the caller's named property");
});

test("isolated custody keeps candidate bytes private below an ordinary owned cache home", () => {
  const cacheHome = privateTemp("noa-kws-owned-cache-home-");
  fs.chmodSync(cacheHome, 0o755);
  try {
    const custodyRoot = knockoutRunner.createIsolatedCustodyRoot(cacheHome);
    const privateParent = path.join(cacheHome, "noa-knockout-isolated");
    assert.equal(fs.realpathSync(path.dirname(custodyRoot)), fs.realpathSync(privateParent));
    assert.equal(fs.lstatSync(cacheHome).mode & 0o777, 0o755);
    assert.equal(fs.lstatSync(privateParent).mode & 0o777, 0o700);
    assert.equal(fs.lstatSync(custodyRoot).mode & 0o777, 0o700);
  } finally {
    removeFixturePath(cacheHome);
  }
});

test("capture seals exact dirty state into a standalone private Git seed without source writes", () => {
  const source = privateTemp("noa-kws-source-");
  const custody = privateTemp("noa-kws-custody-");
  const reportedRoots: RetainedPrivateRoot[] = [];
  try {
    initRepository(source);
    fs.writeFileSync(path.join(source, ".gitignore"), "ignored.log\n");
    fs.writeFileSync(path.join(source, "dual.txt"), "base\n");
    fs.writeFileSync(path.join(source, "delete.txt"), "delete me\n");
    fs.writeFileSync(path.join(source, "rename-me.txt"), "rename me\n");
    fs.writeFileSync(path.join(source, "target.txt"), "target\n");
    fs.writeFileSync(path.join(source, "exec.sh"), "#!/bin/sh\nexit 0\n", { mode: 0o755 });
    fs.writeFileSync(path.join(source, "hard-a.txt"), "hardlink bytes\n");
    fs.linkSync(path.join(source, "hard-a.txt"), path.join(source, "hard-b.txt"));
    fs.symlinkSync("hard-b.txt", path.join(source, "hard-tool"));
    const oddPath = "odd-å-\n-name.txt";
    fs.writeFileSync(path.join(source, oddPath), "odd path\n");
    git(source, ["add", "--all"]);
    git(source, ["commit", "-q", "-m", "fixture base"]);
    git(source, ["update-index", "--split-index"]);

    fs.writeFileSync(path.join(source, "dual.txt"), "staged\n");
    git(source, ["add", "--", "dual.txt"]);
    fs.writeFileSync(path.join(source, "dual.txt"), "staged plus unstaged\n");
    fs.unlinkSync(path.join(source, "delete.txt"));
    fs.renameSync(path.join(source, "rename-me.txt"), path.join(source, "renamed.txt"));
    git(source, ["add", "--all", "--", "delete.txt", "rename-me.txt", "renamed.txt"]);
    fs.writeFileSync(path.join(source, "staged-only.txt"), "object only in index\n");
    git(source, ["add", "--", "staged-only.txt"]);
    const stagedOnlyObject = (git(source, ["rev-parse", ":staged-only.txt"]) as string).trim();
    fs.unlinkSync(path.join(source, "staged-only.txt"));
    fs.writeFileSync(path.join(source, "intent.txt"), "intent to add\n");
    git(source, ["add", "--intent-to-add", "--", "intent.txt"]);
    fs.writeFileSync(path.join(source, "untracked.txt"), "untracked\n");
    fs.writeFileSync(path.join(source, "ignored.log"), "ignored\n");
    fs.mkdirSync(path.join(source, "empty", "nested"), { recursive: true });
    fs.symlinkSync("target.txt", path.join(source, "internal-link"));

    const indexPath = path.join(source, ".git", "index");
    const sharedPathText = (git(source, ["rev-parse", "--shared-index-path"]) as string).trim();
    assert.notEqual(sharedPathText, "", "fixture did not retain a split index");
    const reportedSharedPath = path.resolve(source, sharedPathText);
    const sharedPath = path.join(
      fs.realpathSync(path.dirname(reportedSharedPath)),
      path.basename(reportedSharedPath),
    );
    const sharedBasename = path.basename(sharedPath);
    assert.match(sharedBasename, /^sharedindex\.[0-9a-f]{40}$/);
    assert.equal(path.dirname(sharedPath), fs.realpathSync(path.join(source, ".git")));
    const decoyIdentity = sharedBasename === `sharedindex.${"a".repeat(40)}`
      ? "b".repeat(40)
      : "a".repeat(40);
    const decoyBasename = `sharedindex.${decoyIdentity}`;
    const decoyPath = path.join(source, ".git", decoyBasename);
    fs.writeFileSync(decoyPath, "valid-name decoy; not a Git index\n", { mode: 0o644 });
    const indexBefore = fs.readFileSync(indexPath);
    const indexObservationBefore = gitFileStableObservation(indexPath);
    const indexModeBefore = fs.statSync(indexPath).mode & 0o777;
    const statusBefore = statusBytes(source);
    const sourceBytesBefore = fs.readFileSync(path.join(source, "dual.txt"));
    const sharedSha256Before = sha256File(sharedPath);
    const sharedObservationBefore = gitFileStableObservation(sharedPath);

    let captured: Capture;
    try { captured = workspace.captureAndSealCandidate({ sourceRoot: source, custodyRoot: custody }); }
    catch (error) {
      throw new Error(`stable capture failed: ${errorChain(error)}`, { cause: error });
    }
    reportedRoots.push(...captured.retainedPrivateRoots);
    // Three source-observation scratches and one retained normalization scratch; the third source
    // observation is the capability-registration linearization check.
    assert.equal(captured.retainedPrivateRoots.length, 4);
    assert.equal(captured.attempt, 1);
    assert.match(captured.candidateManifestSha256, /^[0-9a-f]{64}$/);
    assert.equal(
      workspace.candidateManifestSha256(captured.manifest),
      captured.candidateManifestSha256,
    );
    assert.equal(
      captured.manifest.protocol,
      workspace.KNOCKOUT_WORKSPACE_PROTOCOLS.candidateManifest,
    );
    assert.deepEqual(captured.manifest.rootLocalStateProjection, {
      action: "OMIT_FROM_PORTABLE_SEED",
      path: "node_modules/.cache/noa-knockout/lock.json",
      policy: "noa-knockout-root-local-state-projection/1",
      record: null,
      sourceBytesBase64: null,
      sourceFileSha256: null,
      sourceNodeSha256: null,
      status: "ABSENT",
    });
    assert.deepEqual(
      captured.manifest.resourceAdmission.limits,
      workspace.KNOCKOUT_WORKSPACE_CAPTURE_LIMITS,
    );
    assert.equal(captured.manifest.resourceAdmission.operationDeadlineMs, 5 * 60 * 1000);
    assert.equal(captured.manifest.resourceAdmission.childCommandTimeoutMs, 5 * 60 * 1000);
    assert.equal(
      captured.manifest.resourceAdmission.source.logicalBytes,
      captured.sourceSnapshot.workspace.logicalBytes,
    );
    assert.equal(
      captured.manifest.resourceAdmission.seed.logicalBytes,
      captured.workspaceObservation.logicalBytes,
    );
    assert.equal(captured.manifest.seed.includesStandaloneGit, true);
    assert.deepEqual(
      gitFileStableObservation(indexPath),
      indexObservationBefore,
      "capture changed source index identity or timestamps",
    );
    assert.deepEqual(
      gitFileStableObservation(sharedPath),
      sharedObservationBefore,
      "capture changed selected source split-index identity or timestamps",
    );
    const seedIndexPath = path.join(captured.workspaceRoot, ".git", "index");
    const seedSharedPath = path.join(captured.workspaceRoot, ".git", sharedBasename);
    const seedIndexObservationBeforeVerify = gitFileStableObservation(seedIndexPath);
    assert.equal(fs.existsSync(seedSharedPath), false);
    assert.equal(fs.existsSync(path.join(captured.workspaceRoot, ".git", "noa-validation")), false);
    assert.notEqual(sha256File(seedIndexPath), sha256Bytes(indexBefore));
    assert.notEqual(
      `${seedIndexObservationBeforeVerify.dev}:${seedIndexObservationBeforeVerify.ino}`,
      `${indexObservationBefore.dev}:${indexObservationBefore.ino}`,
    );
    assert.equal(
      (git(captured.workspaceRoot, ["rev-parse", "--shared-index-path"]) as string).trim(),
      "",
      "sealed seed retained active split-index state",
    );
    const verifiedSeed = workspace.verifySealedSeed(captured);
    const verificationRoots = reportedPrivateRoots(verifiedSeed);
    assert.equal(verificationRoots.length, 0);
    reportedRoots.push(...verificationRoots);
    assert.equal(verifiedSeed.nodeCount, captured.manifest.seed.nodeCount);
    assert.equal(
      verifiedSeed.materialSha256,
      captured.manifest.seed.workspaceMaterialSha256,
    );
    assert.equal(
      verifiedSeed.observationSha256,
      captured.manifest.seed.observationSha256,
    );
    assert.deepEqual(
      gitFileStableObservation(seedIndexPath),
      seedIndexObservationBeforeVerify,
      "sealed-seed verification changed seed index identity or timestamps",
    );
    assert.equal(fs.existsSync(seedSharedPath), false);

    assert.equal(sha256File(sharedPath), sharedSha256Before);
    assert.equal(path.basename(captured.sourceSnapshot.git.sharedIndex?.path ?? ""), sharedBasename);
    assert.equal(captured.sourceSnapshot.git.sharedIndex?.sha256, sharedSha256Before);
    assert.deepEqual(fs.readFileSync(indexPath), indexBefore, "capture changed the raw source index");
    assert.equal(fs.statSync(indexPath).mode & 0o777, indexModeBefore);
    assert.deepEqual(statusBytes(source), statusBefore, "capture changed source Git status bytes");
    assert.deepEqual(fs.readFileSync(path.join(source, "dual.txt")), sourceBytesBefore);

    assert.equal(fs.statSync(captured.seedRoot).mode & 0o777, 0o700);
    assert.equal(fs.statSync(captured.workspaceRoot).mode & 0o777, 0o700);
    assert.ok(fs.statSync(path.join(captured.workspaceRoot, ".git")).isDirectory());
    assert.equal((git(captured.workspaceRoot, ["rev-parse", "--absolute-git-dir"]) as string).trim(), path.join(captured.workspaceRoot, ".git"));
    assert.equal((git(captured.workspaceRoot, ["rev-parse", "--path-format=absolute", "--git-common-dir"]) as string).trim(), path.join(captured.workspaceRoot, ".git"));
    assert.equal(git(captured.workspaceRoot, ["remote"], null).length, 0);
    assert.equal(fs.existsSync(path.join(captured.workspaceRoot, ".git", "commondir")), false);
    assert.equal(fs.existsSync(path.join(captured.workspaceRoot, ".git", "objects", "info", "alternates")), false);
    assert.notEqual(sha256File(seedIndexPath), sha256File(indexPath));
    assert.equal(captured.manifest.seed.git.sharedIndexSha256, null);
    assert.equal(
      captured.manifest.seed.git.indexStageSha256,
      captured.sourceSnapshot.git.indexStageSha256,
      "sealed seed index does not preserve the observed source stage semantics",
    );
    assert.equal(fs.existsSync(path.join(captured.workspaceRoot, ".git", decoyBasename)), false);
    assert.notEqual(sha256File(decoyPath), sharedSha256Before);
    assert.deepEqual(statusBytes(captured.workspaceRoot), statusBefore);
    git(captured.workspaceRoot, ["cat-file", "-e", `${stagedOnlyObject}^{blob}`]);

    assert.equal(fs.readFileSync(path.join(captured.workspaceRoot, "dual.txt"), "utf8"), "staged plus unstaged\n");
    assert.equal(fs.existsSync(path.join(captured.workspaceRoot, "delete.txt")), false);
    assert.equal(fs.readFileSync(path.join(captured.workspaceRoot, "renamed.txt"), "utf8"), "rename me\n");
    assert.equal(fs.readFileSync(path.join(captured.workspaceRoot, "untracked.txt"), "utf8"), "untracked\n");
    assert.equal(fs.readFileSync(path.join(captured.workspaceRoot, "ignored.log"), "utf8"), "ignored\n");
    assert.ok(fs.statSync(path.join(captured.workspaceRoot, "empty", "nested")).isDirectory());
    assert.equal(fs.readlinkSync(path.join(captured.workspaceRoot, "internal-link")), "target.txt");
    assert.equal(fs.readlinkSync(path.join(captured.workspaceRoot, "hard-tool")), "hard-b.txt");
    assert.equal(fs.readFileSync(path.join(captured.workspaceRoot, "hard-tool"), "utf8"), "hardlink bytes\n");
    assert.equal(fs.readFileSync(path.join(captured.workspaceRoot, oddPath), "utf8"), "odd path\n");
    assert.equal(fs.statSync(path.join(captured.workspaceRoot, "exec.sh")).mode & 0o777, 0o700);
    assert.equal(fs.statSync(path.join(captured.workspaceRoot, "dual.txt")).mode & 0o777, 0o600);
    const hardA = fs.statSync(path.join(captured.workspaceRoot, "hard-a.txt"));
    const hardB = fs.statSync(path.join(captured.workspaceRoot, "hard-b.txt"));
    assert.equal(hardA.ino, hardB.ino);
    assert.equal(hardA.nlink, 2);

    const nodes = new Map(captured.manifest.source.nodes.map((node) => [node.path, node]));
    assert.equal(nodes.get("empty")?.type, "directory");
    assert.equal(nodes.get("empty/nested")?.type, "directory");
    assert.equal(nodes.get("exec.sh")?.executable, true);
    assert.equal(nodes.get("internal-link")?.target, "target.txt");
    assert.equal(nodes.get("hard-tool")?.target, "hard-b.txt");
    assert.equal(nodes.get("hard-a.txt")?.hardlinkGroup, nodes.get("hard-b.txt")?.hardlinkGroup);
    assert.ok(nodes.get("hard-a.txt")?.hardlinkGroup);
    assert.equal(nodes.get(oddPath)?.type, "file");
    for (const node of nodes.values()) {
      assert.equal(node.provenance.classification, "NON_SEMANTIC_OS_MANAGED_PATH_LOCAL");
      if (!node.provenance.present) assert.equal(node.provenance.sha256, null);
    }
    assert.equal(fs.statSync(captured.statePath).mode & 0o777, 0o600);

    const custodyEntriesBeforeRefusal = fs.readdirSync(custody).sort();
    let unstableRefusal: WorkspaceError | null = null;
    assert.throws(
      () => workspace.captureAndSealCandidate({
        sourceRoot: source,
        custodyRoot: custody,
        maxAttempts: 1,
        hooks: {
          afterPreObservation() {
            fs.unlinkSync(sharedPath);
          },
        },
      }),
      (error: WorkspaceError) => {
        unstableRefusal = error;
        return error.code === workspace.KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE;
      },
    );
    const refusalRoots = errorPrivateRoots(unstableRefusal);
    reportedRoots.push(...refusalRoots);
    const custodyPhysical = fs.realpathSync(custody);
    const directRefusalEntries = [...new Set(refusalRoots
      .filter((root) => path.dirname(root.path) === custodyPhysical)
      .map((root) => path.basename(root.path)))].sort();
    assert.ok(directRefusalEntries.length > 0);
    assert.equal(fs.existsSync(sharedPath), false, "capture restored a removed source companion");
    const priorEntries = new Set(custodyEntriesBeforeRefusal);
    assert.deepEqual(
      fs.readdirSync(custody).filter((entry) => !priorEntries.has(entry)).sort(),
      directRefusalEntries,
    );
  } finally {
    cleanupReportedScratchRoots(reportedRoots);
    fs.rmSync(source, { recursive: true, force: true });
    fs.rmSync(custody, { recursive: true, force: true });
  }
});

test("canonical full index preserves entry flags and REUC while discarding cache authority", () => {
  const source = privateTemp("noa-kws-index-canonical-source-");
  const custody = privateTemp("noa-kws-index-canonical-custody-");
  let captured: Capture | null = null;
  try {
    initRepository(source);
    for (const [name, bytes] of [
      ["assume.txt", "assume base\n"],
      ["conflict.txt", "conflict base\n"],
      ["skip.txt", "skip base\n"],
    ] as Array<[string, string]>) fs.writeFileSync(path.join(source, name), bytes, { mode: 0o600 });
    git(source, ["add", "--all"]);
    git(source, ["commit", "-q", "-m", "canonical index base"]);
    const primaryBranch = (git(source, ["branch", "--show-current"]) as string).trim();
    git(source, ["checkout", "-q", "-b", "canonical-side"]);
    fs.writeFileSync(path.join(source, "conflict.txt"), "side bytes\n", { mode: 0o600 });
    git(source, ["add", "--", "conflict.txt"]);
    git(source, ["commit", "-q", "-m", "canonical side"]);
    git(source, ["checkout", "-q", primaryBranch]);
    fs.writeFileSync(path.join(source, "conflict.txt"), "primary bytes\n", { mode: 0o600 });
    git(source, ["add", "--", "conflict.txt"]);
    git(source, ["commit", "-q", "-m", "canonical primary"]);
    const merge = childProcess.spawnSync(gitExecutable, ["merge", "--no-edit", "canonical-side"], {
      cwd: source,
      encoding: "utf8",
      env: gitEnvironment,
      maxBuffer: 64 * 1024 * 1024,
      stdio: ["ignore", "pipe", "pipe"],
    });
    assert.equal(merge.status, 1, `fixture merge did not conflict: ${merge.stderr}`);
    fs.writeFileSync(path.join(source, "conflict.txt"), "resolved bytes\n", { mode: 0o600 });
    git(source, ["add", "--", "conflict.txt"]);
    const resolveUndoBefore = git(
      source,
      ["ls-files", "--resolve-undo", "--full-name", "-z"],
      null,
    ) as Buffer;
    assert.ok(resolveUndoBefore.length > 0, "fixture did not create REUC state");
    fs.writeFileSync(path.join(source, "intent.txt"), "intent bytes\n", { mode: 0o600 });
    git(source, ["add", "--intent-to-add", "--", "intent.txt"]);
    git(source, ["update-index", "--assume-unchanged", "--", "assume.txt"]);
    git(source, ["update-index", "--skip-worktree", "--", "skip.txt"]);
    git(source, ["write-tree"]);
    git(source, ["update-index", "--split-index"]);

    const indexPath = path.join(source, ".git", "index");
    const sharedPathText = (git(source, ["rev-parse", "--shared-index-path"]) as string).trim();
    assert.notEqual(sharedPathText, "");
    const sharedPath = path.resolve(source, sharedPathText);
    const stageBefore = git(source, ["ls-files", "--stage", "--full-name", "-z"], null) as Buffer;
    const flagsBefore = git(source, ["ls-files", "-v", "--full-name", "-z"], null) as Buffer;
    const statusBefore = statusBytes(source);
    const sourceRaw = rawIndexSummary(indexPath);
    assert.ok(sourceRaw.extensions.includes("link"));
    assert.ok(sourceRaw.extensions.includes("REUC"));
    const indexBefore = fs.readFileSync(indexPath);
    const indexObservationBefore = gitFileStableObservation(indexPath);
    const sharedBefore = fs.readFileSync(sharedPath);
    const sharedObservationBefore = gitFileStableObservation(sharedPath);

    captured = workspace.captureAndSealCandidate({ sourceRoot: source, custodyRoot: custody });
    const seedIndexPath = path.join(captured.workspaceRoot, ".git", "index");
    const seedRaw = rawIndexSummary(seedIndexPath);
    assert.equal(seedRaw.version, 3);
    assert.deepEqual(seedRaw.extensions, ["REUC"]);
    assert.ok(
      seedRaw.entries.every((entry) => /^0{48}[0-9a-f]{8}0{24}$/u.test(entry.stat)),
      "canonical seed retained source stat-cache authority",
    );
    const entries = new Map(seedRaw.entries.map((entry) => [entry.path, entry]));
    assert.equal(entries.get("assume.txt")?.assumeValid, true);
    assert.equal(entries.get("skip.txt")?.skipWorktree, true);
    assert.equal(entries.get("intent.txt")?.intentToAdd, true);
    assert.deepEqual(
      git(captured.workspaceRoot, ["ls-files", "--stage", "--full-name", "-z"], null),
      stageBefore,
    );
    assert.deepEqual(
      git(captured.workspaceRoot, ["ls-files", "--resolve-undo", "--full-name", "-z"], null),
      resolveUndoBefore,
    );
    assert.deepEqual(
      git(captured.workspaceRoot, ["ls-files", "-v", "--full-name", "-z"], null),
      flagsBefore,
    );
    assert.deepEqual(statusBytes(captured.workspaceRoot), statusBefore);
    assert.doesNotThrow(() => workspace.verifySealedSeed(captured!));
    assert.deepEqual(fs.readFileSync(indexPath), indexBefore);
    assert.deepEqual(gitFileStableObservation(indexPath), indexObservationBefore);
    assert.deepEqual(fs.readFileSync(sharedPath), sharedBefore);
    assert.deepEqual(gitFileStableObservation(sharedPath), sharedObservationBefore);
  } finally {
    cleanupReportedScratchRoots(reportedPrivateRoots(captured));
    removeFixturePath(source);
    removeFixturePath(custody);
  }
});

test("unsupported source index extensions fail closed before normalization", async (t) => {
  const cases = [
    { signature: "ABCD", label: "unknown optional" },
    { signature: "abcd", label: "unknown required" },
    { signature: "FSMN", label: "fsmonitor" },
    { signature: "sdir", label: "sparse" },
  ];
  for (const fixtureCase of cases) {
    await t.test(fixtureCase.label, () => {
      const fixture = minimalCaptureFixture(`index-extension-${fixtureCase.label.replace(" ", "-")}`);
      let refusal: WorkspaceError | null = null;
      try {
        appendRawIndexExtension(
          fixture.source,
          fixtureCase.signature,
          Buffer.from("untrusted extension payload", "utf8"),
        );
        const indexPath = path.join(fixture.source, ".git", "index");
        const indexBefore = fs.readFileSync(indexPath);
        assert.throws(
          () => workspace.captureAndSealCandidate({
            custodyRoot: fixture.custody,
            maxAttempts: 1,
            sourceRoot: fixture.source,
          }),
          (error: WorkspaceError) => {
            refusal = error;
            return error.code === workspaceErrorCode("SOURCE_INDEX_UNSUPPORTED");
          },
        );
        assert.deepEqual(fs.readFileSync(indexPath), indexBefore);
        assert.deepEqual(
          regularFilesBelow(fixture.custody)
            .filter((file) => path.basename(file) === "candidate-manifest.json"),
          [],
        );
      } finally {
        cleanupReportedScratchRoots(errorPrivateRoots(refusal));
        removeFixturePath(fixture.source);
        removeFixturePath(fixture.custody);
      }
    });
  }
});

test("non-canonical raw index paths are refused before Git can authorize a seed", async (t) => {
  const cases = [
    { label: "parent traversal", original: "safe.txt", replacement: "../x.txt" },
    { label: "absolute", original: "safe.txt", replacement: "/bad.txt" },
    { label: "Git metadata alias", original: "safe/config", replacement: ".GiT/config" },
  ];
  for (const fixtureCase of cases) {
    await t.test(fixtureCase.label, () => {
      const source = privateTemp(`noa-kws-index-path-${fixtureCase.label.replaceAll(" ", "-")}-`);
      const custody = privateTemp("noa-kws-index-path-custody-");
      let refusal: WorkspaceError | null = null;
      try {
        initRepository(source);
        const tracked = path.join(source, ...fixtureCase.original.split("/"));
        fs.mkdirSync(path.dirname(tracked), { recursive: true });
        fs.writeFileSync(tracked, "tracked bytes\n", { mode: 0o600 });
        git(source, ["add", "--all"]);
        git(source, ["commit", "-q", "-m", "raw path base"]);
        replaceRawIndexPath(source, fixtureCase.original, fixtureCase.replacement);
        const indexPath = path.join(source, ".git", "index");
        const indexBefore = fs.readFileSync(indexPath);
        assert.throws(
          () => workspace.captureAndSealCandidate({
            custodyRoot: custody,
            maxAttempts: 1,
            sourceRoot: source,
          }),
          (error: WorkspaceError) => {
            refusal = error;
            return error.code === workspaceErrorCode("SOURCE_INDEX_UNSUPPORTED");
          },
        );
        assert.deepEqual(fs.readFileSync(indexPath), indexBefore);
        assert.deepEqual(
          regularFilesBelow(custody)
            .filter((file) => path.basename(file) === "candidate-manifest.json"),
          [],
        );
      } finally {
        cleanupReportedScratchRoots(errorPrivateRoots(refusal));
        removeFixturePath(source);
        removeFixturePath(custody);
      }
    });
  }
});

test("full index v4 capture canonicalizes SHA-1 and SHA-256 repositories", async (t) => {
  for (const objectFormat of ["sha1", "sha256"] as const) {
    await t.test(objectFormat, () => {
      const source = privateTemp(`noa-kws-index-v4-${objectFormat}-source-`);
      const custody = privateTemp(`noa-kws-index-v4-${objectFormat}-custody-`);
      let captured: Capture | null = null;
      try {
        git(source, ["init", "-q", `--object-format=${objectFormat}`, "--template="]);
        git(source, ["config", "--local", "user.name", "NOA Workspace Test"]);
        git(source, ["config", "--local", "user.email", "workspace-test@noa.invalid"]);
        git(source, ["config", "--local", "core.filemode", "true"]);
        fs.writeFileSync(path.join(source, "tracked.txt"), "base\n", { mode: 0o600 });
        fs.writeFileSync(path.join(source, "other.txt"), "other\n", { mode: 0o600 });
        git(source, ["add", "--all"]);
        git(source, ["commit", "-q", "-m", `${objectFormat} v4 base`]);
        fs.writeFileSync(path.join(source, "tracked.txt"), "staged\n", { mode: 0o600 });
        git(source, ["add", "--", "tracked.txt"]);
        fs.writeFileSync(path.join(source, "tracked.txt"), "staged and dirty\n", { mode: 0o600 });
        fs.writeFileSync(path.join(source, "intent.txt"), "intent\n", { mode: 0o600 });
        git(source, ["add", "--intent-to-add", "--", "intent.txt"]);
        git(source, ["update-index", "--index-version", "4"]);
        const indexPath = path.join(source, ".git", "index");
        assert.equal(fs.readFileSync(indexPath).readUInt32BE(4), 4);
        const stageBefore = git(
          source,
          ["ls-files", "--stage", "--full-name", "-z"],
          null,
        ) as Buffer;
        const statusBefore = statusBytes(source);
        // Git reads can refresh the source index stat cache, so bind the final source observation.
        const stableIndexBefore = fs.readFileSync(indexPath);
        const stableObservationBefore = gitFileStableObservation(indexPath);

        captured = workspace.captureAndSealCandidate({ sourceRoot: source, custodyRoot: custody });
        const seedIndexPath = path.join(captured.workspaceRoot, ".git", "index");
        const seedRaw = rawIndexSummary(seedIndexPath, objectFormat);
        assert.equal(seedRaw.version, 3);
        assert.ok(seedRaw.extensions.every((extension) => extension === "REUC"));
        assert.deepEqual(
          git(captured.workspaceRoot, ["ls-files", "--stage", "--full-name", "-z"], null),
          stageBefore,
        );
        assert.deepEqual(statusBytes(captured.workspaceRoot), statusBefore);
        assert.doesNotThrow(() => workspace.verifySealedSeed(captured!));
        assert.deepEqual(fs.readFileSync(indexPath), stableIndexBefore);
        assert.deepEqual(gitFileStableObservation(indexPath), stableObservationBefore);
      } finally {
        cleanupReportedScratchRoots(reportedPrivateRoots(captured));
        removeFixturePath(source);
        removeFixturePath(custody);
      }
    });
  }
});

test("modified split-index EWAH boundaries preserve deleted, replaced, added, and flagged entries", () => {
  const source = privateTemp("noa-kws-ewah-source-");
  const custody = privateTemp("noa-kws-ewah-custody-");
  let captured: Capture | null = null;
  try {
    initRepository(source);
    for (let index = 0; index < 130; index++) {
      const name = `f${String(index).padStart(3, "0")}.txt`;
      fs.writeFileSync(path.join(source, name), `base-${index}\n`, { mode: 0o600 });
    }
    git(source, ["add", "--all"]);
    git(source, ["commit", "-q", "-m", "EWAH boundary base"]);
    git(source, ["update-index", "--assume-unchanged", "--", "f000.txt"]);
    git(source, ["update-index", "--split-index"]);
    git(source, ["update-index", "--no-assume-unchanged", "--", "f000.txt"]);
    fs.writeFileSync(path.join(source, "f063.txt"), "replacement-63\n", { mode: 0o600 });
    git(source, ["add", "--", "f063.txt"]);
    git(source, ["rm", "-q", "--", "f064.txt"]);
    git(source, ["update-index", "--skip-worktree", "--", "f129.txt"]);
    fs.writeFileSync(path.join(source, "z-added.txt"), "added\n", { mode: 0o600 });
    git(source, ["add", "--", "z-added.txt"]);

    const indexPath = path.join(source, ".git", "index");
    const sourceRaw = rawIndexSummary(indexPath);
    assert.ok(sourceRaw.extensions.includes("link"));
    assert.ok((sourceRaw.extensionSizes.link ?? 0) > 20, "split link has no EWAH payload");
    const stageBefore = git(source, ["ls-files", "--stage", "--full-name", "-z"], null) as Buffer;
    const flagsBefore = git(source, ["ls-files", "-v", "--full-name", "-z"], null) as Buffer;
    const statusBefore = statusBytes(source);
    const indexBefore = fs.readFileSync(indexPath);
    const indexObservationBefore = gitFileStableObservation(indexPath);
    const sharedPath = path.resolve(
      source,
      (git(source, ["rev-parse", "--shared-index-path"]) as string).trim(),
    );
    const sharedBefore = fs.readFileSync(sharedPath);
    const sharedObservationBefore = gitFileStableObservation(sharedPath);

    captured = workspace.captureAndSealCandidate({ sourceRoot: source, custodyRoot: custody });
    const seedIndexPath = path.join(captured.workspaceRoot, ".git", "index");
    const seedRaw = rawIndexSummary(seedIndexPath);
    assert.equal(seedRaw.version, 3);
    assert.equal(seedRaw.extensions.includes("link"), false);
    assert.equal(seedRaw.entries.some((entry) => entry.path === "f064.txt"), false);
    assert.equal(seedRaw.entries.some((entry) => entry.path === "z-added.txt"), true);
    assert.equal(
      seedRaw.entries.find((entry) => entry.path === "f129.txt")?.skipWorktree,
      true,
    );
    assert.deepEqual(
      git(captured.workspaceRoot, ["ls-files", "--stage", "--full-name", "-z"], null),
      stageBefore,
    );
    assert.deepEqual(
      git(captured.workspaceRoot, ["ls-files", "-v", "--full-name", "-z"], null),
      flagsBefore,
    );
    assert.deepEqual(statusBytes(captured.workspaceRoot), statusBefore);
    assert.doesNotThrow(() => workspace.verifySealedSeed(captured!));
    assert.deepEqual(fs.readFileSync(indexPath), indexBefore);
    assert.deepEqual(gitFileStableObservation(indexPath), indexObservationBefore);
    assert.deepEqual(fs.readFileSync(sharedPath), sharedBefore);
    assert.deepEqual(gitFileStableObservation(sharedPath), sharedObservationBefore);
  } finally {
    cleanupReportedScratchRoots(reportedPrivateRoots(captured));
    removeFixturePath(source);
    removeFixturePath(custody);
  }
});

test("capture binds one physical source root across Git observation and worktree copy", () => {
  const fixtureRoot = privateTemp("noa-kws-source-root-aba-");
  const source = path.join(fixtureRoot, "source");
  const alternate = path.join(fixtureRoot, "alternate");
  const custody = path.join(fixtureRoot, "custody");
  const tools = path.join(fixtureRoot, "tools");
  const heldOriginal = path.join(fixtureRoot, "held-original");
  const displacedAlternate = path.join(fixtureRoot, "displaced-alternate");
  fs.mkdirSync(source, { mode: 0o700 });
  fs.mkdirSync(custody, { mode: 0o700 });
  fs.mkdirSync(tools, { mode: 0o700 });
  initRepository(source);
  fs.writeFileSync(path.join(source, "tracked.txt"), "BASE\n", { mode: 0o600 });
  fs.mkdirSync(path.join(source, "nested"), { mode: 0o700 });
  fs.writeFileSync(path.join(source, "nested", "child.txt"), "nested\n", { mode: 0o600 });
  git(source, ["add", "--all"]);
  git(source, ["commit", "-q", "-m", "source-root ABA base"]);
  fs.cpSync(source, alternate, { preserveTimestamps: true, recursive: true });
  fs.unlinkSync(path.join(alternate, ".git", "index"));
  fs.linkSync(path.join(source, ".git", "index"), path.join(alternate, ".git", "index"));
  fs.writeFileSync(path.join(source, "tracked.txt"), "AAAA-DIRTY\n");
  fs.writeFileSync(path.join(alternate, "tracked.txt"), "BBBB-DIRTY\n");
  assert.deepEqual(
    statusBytes(source),
    statusBytes(alternate),
    "fixture roots do not have the same observable Git status",
  );

  const physicalSource = fs.realpathSync(source);
  const marker = path.join(tools, "source-git-observed");
  const shim = path.join(tools, "git-shim");
  // Live status is intentionally never consulted: exact status semantics are derived later from
  // the isolated seed. Trigger instead on Git's first source-root discovery command so this
  // regression continues to attack the boundary between Git observation and the workspace census.
  fs.writeFileSync(shim, [
    "#!/bin/sh",
    "for argument in \"$@\"; do",
    "  if [ \"$argument\" = \"--is-inside-work-tree\" ]; then",
    `    if [ \"\${GIT_WORK_TREE:-}\" = ${JSON.stringify(physicalSource)} ] || [ \"$(pwd -P)\" = ${JSON.stringify(physicalSource)} ]; then`,
    `      /usr/bin/printf 'x\\n' >> ${JSON.stringify(marker)}`,
    "    fi",
    "  fi",
    "done",
    `exec ${JSON.stringify(gitExecutable)} \"$@\"`,
    "",
  ].join("\n"), { mode: 0o700 });

  const lstatDescriptor = Object.getOwnPropertyDescriptor(fs, "lstatSync");
  assert.ok(lstatDescriptor !== undefined);
  const originalLstat = fs.lstatSync;
  let swapped = false;
  let restored = false;
  let workspaceRoot: string | null = null;
  let captured: Capture | null = null;
  let refusal: WorkspaceError | null = null;
  const gitObservationCount = (): number => {
    try { return (fs.readFileSync(marker, "utf8").match(/x/g) ?? []).length; }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return 0;
      throw error;
    }
  };
  try {
    Object.defineProperty(fs, "lstatSync", {
      ...lstatDescriptor,
      value: (...args: Parameters<typeof fs.lstatSync>) => {
        const candidate = typeof args[0] === "string" ? path.resolve(args[0]) : null;
        if (!swapped && candidate === physicalSource && gitObservationCount() >= 1) {
          fs.renameSync(source, heldOriginal);
          fs.renameSync(alternate, source);
          swapped = true;
        } else if (
          swapped && !restored && workspaceRoot !== null && gitObservationCount() >= 2 &&
          candidate !== null &&
          (candidate === workspaceRoot || candidate.startsWith(`${workspaceRoot}${path.sep}`))
        ) {
          fs.renameSync(source, displacedAlternate);
          fs.renameSync(heldOriginal, source);
          restored = true;
        }
        return Reflect.apply(originalLstat, fs, args) as ReturnType<typeof fs.lstatSync>;
      },
    });
    try {
      captured = workspace.captureAndSealCandidate({
        commandTimeoutMs: 60_000,
        custodyRoot: custody,
        gitExecutable: shim,
        hooks: {
          afterWorktreeCopy(value) { workspaceRoot = value.workspaceRoot; },
        },
        maxAttempts: 1,
        sourceRoot: source,
      });
    } catch (error) {
      refusal = error as WorkspaceError;
    }
    // Acceptance is deliberately independent of how far the unsafe path was allowed to run: a
    // fail-early repair may refuse on the first census reopen, so the original root is restored
    // here (and again in `finally`) before anything is asserted about it.
    if (swapped && !restored) {
      if (pathExistsNoFollow(source)) fs.renameSync(source, displacedAlternate);
      fs.renameSync(heldOriginal, source);
      restored = true;
    }
    assert.equal(swapped, true, "source-root ABA substitution was not reached");
    assert.ok(gitObservationCount() >= 1, "capture never ran Git discovery on the original source root");
    assert.equal(
      fs.readFileSync(path.join(source, "tracked.txt"), "utf8"),
      "AAAA-DIRTY\n",
      "the original source was not preserved after cleanup",
    );
    assert.equal(
      fs.readFileSync(path.join(displacedAlternate, "tracked.txt"), "utf8"),
      "BBBB-DIRTY\n",
    );
    if (captured !== null) {
      assert.equal(
        fs.readFileSync(path.join(captured.workspaceRoot, "tracked.txt"), "utf8"),
        "AAAA-DIRTY\n",
        "capture accepted bytes from a substituted physical source root",
      );
    }
    assert.equal(captured, null, "capture accepted a source-root ABA substitution");
    assert.equal(refusal?.code, workspaceErrorCode("SNAPSHOT_UNSTABLE"), errorChain(refusal));
    assert.equal(refusal?.details?.lastCode, workspaceErrorCode("SOURCE_CHANGED"));
    const sourceChanged = causeWithCode(refusal, workspaceErrorCode("SOURCE_CHANGED"));
    assert.notEqual(sourceChanged, null, "refusal does not carry its SOURCE_CHANGED cause");
    assert.deepEqual(
      regularFilesBelow(custody).filter((file) => path.basename(file) === "state.json"),
      [],
      "a SEALED state was published for a substituted source root",
    );
  } finally {
    Object.defineProperty(fs, "lstatSync", lstatDescriptor);
    if (!restored && pathExistsNoFollow(heldOriginal)) {
      if (pathExistsNoFollow(source)) fs.renameSync(source, displacedAlternate);
      fs.renameSync(heldOriginal, source);
    }
    removeFixturePath(fixtureRoot);
  }
});

test("capture ignores ambient TMPDIR inside the source and keeps every scratch in custody", () => {
  const fixture = minimalCaptureFixture("ambient-tmpdir");
  const ambientTmp = path.join(fixture.source, "ambient-tmp");
  fs.mkdirSync(ambientTmp, { mode: 0o700 });
  const priorTmpdir = process.env.TMPDIR;
  let captured: Capture | null = null;
  try {
    process.env.TMPDIR = ambientTmp;
    captured = workspace.captureAndSealCandidate({
      custodyRoot: fixture.custody,
      sourceRoot: fixture.source,
    });
    assert.deepEqual(fs.readdirSync(ambientTmp), []);
    const custodyPhysical = fs.realpathSync(fixture.custody);
    // Three source-observation scratches and one index-normalization scratch; the third source
    // observation is the capability-registration linearization check.
    assert.equal(captured.retainedPrivateRoots.length, 4);
    for (const root of captured.retainedPrivateRoots) {
      assert.equal(path.relative(custodyPhysical, root.path).startsWith(".."), false);
    }
  } finally {
    if (priorTmpdir === undefined) delete process.env.TMPDIR;
    else process.env.TMPDIR = priorTmpdir;
    cleanupReportedScratchRoots(captured?.retainedPrivateRoots ?? []);
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
  }
});

test("repository-local ignore and attribute semantics are refused before isolated capture", async (t) => {
  const cases = [
    {
      configure(source: string) {
        fs.mkdirSync(path.join(source, ".git", "info"), { recursive: true });
        fs.writeFileSync(path.join(source, ".git", "info", "exclude"), "local-only.log\n");
      },
      label: "info/exclude",
    },
    {
      configure(source: string) {
        fs.mkdirSync(path.join(source, ".git", "info"), { recursive: true });
        fs.writeFileSync(path.join(source, ".git", "info", "attributes"), "*.txt ident\n");
      },
      label: "info/attributes",
    },
    {
      configure(source: string) {
        const rules = path.join(source, "local-excludes");
        fs.writeFileSync(rules, "local-only.log\n");
        git(source, ["config", "--local", "core.excludesFile", rules]);
      },
      label: "core.excludesFile",
    },
    {
      configure(source: string) {
        const rules = path.join(source, "local-attributes");
        fs.writeFileSync(rules, "*.txt ident\n");
        git(source, ["config", "--local", "core.attributesFile", rules]);
      },
      label: "core.attributesFile",
    },
    {
      configure(source: string) {
        git(source, ["config", "--local", "status.renames", "false"]);
      },
      label: "status.renames outside the closed policy",
    },
  ];
  for (const fixtureCase of cases) {
    await t.test(fixtureCase.label, () => {
      const fixture = minimalCaptureFixture(`local-git-${fixtureCase.label.replaceAll("/", "-")}`);
      try {
        fixtureCase.configure(fixture.source);
        assert.throws(
          () => workspace.captureAndSealCandidate({
            custodyRoot: fixture.custody,
            sourceRoot: fixture.source,
          }),
          (error: WorkspaceError) =>
            error.code === workspaceErrorCode("SOURCE_GIT_LAYOUT_UNSUPPORTED"),
        );
        assert.deepEqual(fs.readdirSync(fixture.custody), []);
      } finally {
        removeFixturePath(fixture.source);
        removeFixturePath(fixture.custody);
      }
    });
  }
});

test("descriptor-bound Git config bytes use Git's portable stdin sentinel", () => {
  const fixture = minimalCaptureFixture("portable-config-stdin");
  const tools = privateTemp("noa-kws-portable-config-stdin-tools-");
  const marker = path.join(tools, "portable-stdin-observed");
  const shim = path.join(tools, "git-shim");
  let observed: SourceSnapshot["git"] | null = null;
  try {
    fs.writeFileSync(shim, [
      "#!/bin/sh",
      "expect_file=0",
      "for argument in \"$@\"; do",
      "  if [ \"$expect_file\" = 1 ]; then",
      "    if [ \"$argument\" != \"-\" ]; then",
      "      /usr/bin/printf '%s\\n' 'Git config did not use the portable stdin sentinel' >&2",
      "      exit 97",
      "    fi",
      `    /usr/bin/printf observed > ${JSON.stringify(marker)}`,
      "    expect_file=0",
      "  elif [ \"$argument\" = \"--file\" ]; then",
      "    expect_file=1",
      "  fi",
      "done",
      `exec ${JSON.stringify(gitExecutable)} \"$@\"`,
      "",
    ].join("\n"), { mode: 0o700 });
    observed = workspace.observeSourceGit(fixture.source, {
      gitExecutable: shim,
      scratchRoot: fixture.custody,
    });
    assert.equal(fs.readFileSync(marker, "utf8"), "observed");
    assert.equal(observed.worktreeRoot, fs.realpathSync(fixture.source));
  } finally {
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
    removeFixturePath(tools);
  }
});

test("descriptor-bound config admits an exact current linked-worktree origin upstream pair", () => {
  const fixture = linkedWorktreeFixture("current-origin-upstream");
  try {
    const { branchName, headRef } = configureCanonicalOriginUpstream(fixture);
    assert.equal(
      (git(fixture.linked, ["config", "--local", "--get", `branch.${branchName}.remote`]) as string).trim(),
      "origin",
    );
    assert.equal(
      (git(fixture.linked, ["config", "--local", "--get", `branch.${branchName}.merge`]) as string).trim(),
      headRef,
    );
    const observed = workspace.observeSourceGit(fixture.linked, { scratchRoot: fixture.custody });
    assert.equal(observed.headRef, headRef);
    assert.equal(observed.worktreeRoot, fs.realpathSync(fixture.linked));
  } finally {
    removeFixturePath(fixture.fixtureRoot);
    removeFixturePath(fixture.custody);
  }
});

test("branch upstream config remains closed and refuses before any object command", async (t) => {
  const cases: Array<{
    label: string;
    mutate: (
      fixture: ReturnType<typeof linkedWorktreeFixture>,
      branchName: string,
      headRef: string,
    ) => void;
  }> = [
    {
      label: "detached HEAD",
      mutate(fixture) {
        git(fixture.linked, ["checkout", "--detach", "-q"]);
      },
    },
    {
      label: "missing merge",
      mutate(fixture, branchName) {
        git(fixture.linked, ["config", "--local", "--unset", `branch.${branchName}.merge`]);
      },
    },
    {
      label: "missing remote",
      mutate(fixture, branchName) {
        git(fixture.linked, ["config", "--local", "--unset", `branch.${branchName}.remote`]);
      },
    },
    {
      label: "other branch pair",
      mutate(fixture) {
        git(fixture.linked, ["config", "--local", "branch.other-branch.remote", "origin"]);
        git(fixture.linked, ["config", "--local", "branch.other-branch.merge", "refs/heads/other-branch"]);
      },
    },
    {
      label: "duplicate remote",
      mutate(fixture, branchName) {
        fs.appendFileSync(
          path.join(fixture.main, ".git", "config"),
          `\n[branch ${JSON.stringify(branchName)}]\n\tremote = origin\n`,
        );
      },
    },
    {
      label: "pushRemote",
      mutate(fixture, branchName) {
        git(fixture.linked, ["config", "--local", `branch.${branchName}.pushRemote`, "origin"]);
      },
    },
    {
      label: "rebase",
      mutate(fixture, branchName) {
        git(fixture.linked, ["config", "--local", `branch.${branchName}.rebase`, "true"]);
      },
    },
    {
      label: "non-origin remote",
      mutate(fixture, branchName) {
        git(fixture.linked, ["config", "--local", `branch.${branchName}.remote`, "."]);
      },
    },
    {
      label: "merge mismatch",
      mutate(fixture, branchName) {
        git(fixture.linked, [
          "config", "--local", `branch.${branchName}.merge`, `refs/heads/${branchName}-other`,
        ]);
      },
    },
    {
      label: "case-variant branch subsection",
      mutate(fixture, branchName, headRef) {
        git(fixture.linked, ["config", "--local", "--unset", `branch.${branchName}.remote`]);
        git(fixture.linked, ["config", "--local", "--unset", `branch.${branchName}.merge`]);
        const variant = `${branchName[0]!.toUpperCase()}${branchName.slice(1)}`;
        git(fixture.linked, ["config", "--local", `branch.${variant}.remote`, "origin"]);
        git(fixture.linked, ["config", "--local", `branch.${variant}.merge`, headRef]);
      },
    },
  ];

  for (const fixtureCase of cases) {
    await t.test(fixtureCase.label, () => {
      const fixture = linkedWorktreeFixture(`upstream-${fixtureCase.label.replaceAll(" ", "-")}`);
      const tools = privateTemp(`noa-kws-upstream-${fixtureCase.label.replaceAll(" ", "-")}-tools-`);
      const marker = path.join(tools, "object-command-reached");
      const observingGit = path.join(tools, "git-object-marker");
      try {
        const { branchName, headRef } = configureCanonicalOriginUpstream(fixture);
        fixtureCase.mutate(fixture, branchName, headRef);
        fs.writeFileSync(observingGit, [
          "#!/bin/sh",
          "if [ \"${GIT_DIR-}\" = \"..\" ]; then",
          `  /usr/bin/printf reached > ${JSON.stringify(marker)}`,
          "fi",
          `exec ${JSON.stringify(gitExecutable)} \"$@\"`,
          "",
        ].join("\n"), { mode: 0o700 });
        assert.throws(
          () => workspace.captureAndSealCandidate({
            custodyRoot: fixture.custody,
            gitExecutable: observingGit,
            maxAttempts: 1,
            sourceRoot: fixture.linked,
          }),
          (error: WorkspaceError) =>
            error.code === workspaceErrorCode("SOURCE_GIT_LAYOUT_UNSUPPORTED"),
        );
        assert.equal(pathExistsNoFollow(marker), false, "an object command ran before config refusal");
        assert.deepEqual(fs.readdirSync(fixture.custody), []);
      } finally {
        removeFixturePath(fixture.fixtureRoot);
        removeFixturePath(fixture.custody);
        removeFixturePath(tools);
      }
    });
  }
});

test("unsupported repository filter configuration is refused without executing the filter", () => {
  const fixture = minimalCaptureFixture("local-filter-refusal");
  const tools = privateTemp("noa-kws-local-filter-tools-");
  const marker = path.join(tools, "filter-invoked");
  const filter = path.join(tools, "filter-command");
  try {
    fs.writeFileSync(path.join(fixture.source, ".gitattributes"), "tracked.txt filter=noa\n");
    git(fixture.source, ["add", ".gitattributes"]);
    git(fixture.source, ["commit", "-q", "-m", "add filter attribute"]);
    fs.writeFileSync(filter, [
      "#!/bin/sh",
      `/usr/bin/printf invoked > ${JSON.stringify(marker)}`,
      "/bin/cat",
      "",
    ].join("\n"), { mode: 0o700 });
    git(fixture.source, ["config", "--local", "filter.noa.clean", filter]);

    assert.throws(
      () => workspace.captureAndSealCandidate({
        custodyRoot: fixture.custody,
        sourceRoot: fixture.source,
      }),
      (error: WorkspaceError) =>
        error.code === workspaceErrorCode("SOURCE_GIT_LAYOUT_UNSUPPORTED"),
    );
    assert.equal(pathExistsNoFollow(marker), false, "unsupported filter command was executed");
    assert.deepEqual(fs.readdirSync(fixture.custody), []);
  } finally {
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
    removeFixturePath(tools);
  }
});

test("source Git status configuration is replayed into equivalent seed semantics", () => {
  const fixture = minimalCaptureFixture("status-config-replay");
  let captured: Capture | null = null;
  try {
    git(fixture.source, ["config", "--local", "core.filemode", "false"]);
    fs.chmodSync(fixture.trackedPath, 0o700);
    const sourceStatus = statusBytes(fixture.source);
    assert.equal(sourceStatus.length, 0, "core.filemode=false fixture still reported a mode change");
    const counterfactualStatus = git(fixture.source, [
      "-c", "core.filemode=true",
      "status", "--porcelain=v2", "-z", "--untracked-files=all", "--ignored=matching",
    ], null) as Buffer;
    assert.ok(counterfactualStatus.length > 0, "fixture does not distinguish filemode semantics");

    captured = workspace.captureAndSealCandidate({
      custodyRoot: fixture.custody,
      sourceRoot: fixture.source,
    });
    const sourceStatusConfig = captured.sourceSnapshot.git.statusConfig;
    assert.notEqual(sourceStatusConfig, undefined);
    assert.equal(sourceStatusConfig?.["core.filemode"], false);
    const seedStatus = statusBytes(captured.workspaceRoot);
    assert.deepEqual(seedStatus, sourceStatus);
    assert.equal(captured.manifest.seed.git.statusSha256, sha256Bytes(sourceStatus));
    assert.deepEqual(captured.manifest.seed.git.statusConfig, sourceStatusConfig);
    assert.deepEqual(captured.manifest.source.git?.statusConfig, sourceStatusConfig);
    assert.doesNotThrow(() => workspace.verifySealedSeed(captured!));
  } finally {
    cleanupReportedScratchRoots(captured?.retainedPrivateRoots ?? []);
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
  }
});

test("worktree-local status configuration overrides repository configuration in the seed", () => {
  const fixtureRoot = privateTemp("noa-kws-status-worktree-root-");
  const custody = privateTemp("noa-kws-status-worktree-custody-");
  const main = path.join(fixtureRoot, "main");
  const linked = path.join(fixtureRoot, "linked");
  const tools = privateTemp("noa-kws-status-worktree-tools-");
  const objectMarker = path.join(tools, "object-child-env");
  const enforcingGit = path.join(tools, "git-enforce-common-dir");
  fs.mkdirSync(main, { mode: 0o700 });
  let captured: Capture | null = null;
  try {
    initRepository(main);
    fs.writeFileSync(path.join(main, "tracked.txt"), "worktree status config\n", { mode: 0o600 });
    git(main, ["add", "--all"]);
    git(main, ["commit", "-q", "-m", "status worktree base"]);
    git(main, ["worktree", "add", "-q", "-b", "status-worktree", linked]);
    git(main, ["config", "extensions.worktreeConfig", "true"]);
    git(main, ["config", "--local", "core.ignorecase", "true"]);
    git(main, ["config", "--worktree", "core.ignorecase", "false"]);
    git(linked, ["config", "--worktree", "core.filemode", "false"]);
    fs.writeFileSync(enforcingGit, [
      "#!/bin/sh",
      "if [ \"${GIT_DIR-}\" = \"..\" ] && [ \"${GIT_OBJECT_DIRECTORY-}\" = \".\" ]; then",
      "  [ \"${GIT_COMMON_DIR-}\" = \"..\" ] || exit 91",
      `  /usr/bin/printf reached >> ${JSON.stringify(objectMarker)}`,
      "fi",
      `exec ${JSON.stringify(gitExecutable)} \"$@\"`,
      "",
    ].join("\n"), { mode: 0o700 });
    const linkedTracked = path.join(linked, "tracked.txt");
    fs.chmodSync(linkedTracked, 0o700);
    const sourceStatus = statusBytes(linked);
    assert.equal(sourceStatus.length, 0, "worktree filemode override was not effective");
    const counterfactualStatus = git(linked, [
      "-c", "core.filemode=true",
      "status", "--porcelain=v2", "-z", "--untracked-files=all", "--ignored=matching",
    ], null) as Buffer;
    assert.ok(counterfactualStatus.length > 0, "worktree fixture does not distinguish filemode semantics");

    captured = workspace.captureAndSealCandidate({
      custodyRoot: custody,
      gitExecutable: enforcingGit,
      sourceRoot: linked,
    });
    assert.equal(captured.sourceSnapshot.git.statusConfig?.["core.filemode"], false);
    assert.equal(captured.sourceSnapshot.git.statusConfig?.["core.ignorecase"], true);
    assert.equal(captured.manifest.source.git?.statusConfig?.["core.filemode"], false);
    assert.equal(captured.manifest.seed.git.statusConfig["core.filemode"], false);
    assert.deepEqual(statusBytes(captured.workspaceRoot), sourceStatus);
    assert.equal(captured.manifest.seed.git.statusSha256, sha256Bytes(sourceStatus));
    const linkedGitDirectory = fs.realpathSync(
      (git(linked, ["rev-parse", "--absolute-git-dir"]) as string).trim(),
    );
    const commonDirectory = fs.realpathSync(path.join(main, ".git"));
    assert.equal(
      captured.sourceSnapshot.git.worktreeConfigFile?.sha256,
      sha256File(path.join(linkedGitDirectory, "config.worktree")),
    );
    assert.equal(
      captured.sourceSnapshot.git.commonWorktreeConfigFile?.sha256,
      sha256File(path.join(commonDirectory, "config.worktree")),
    );
    assert.notEqual(
      captured.sourceSnapshot.git.worktreeConfigFile?.sha256,
      captured.sourceSnapshot.git.commonWorktreeConfigFile?.sha256,
    );
    assert.equal(
      captured.manifest.protocol,
      "noa-knockout-workspace/candidate-manifest/14",
    );
    assert.equal(pathExistsNoFollow(objectMarker), true, "bound object-child path was not exercised");
    assert.doesNotThrow(() => workspace.verifySealedSeed(captured!));
  } finally {
    cleanupReportedScratchRoots(captured?.retainedPrivateRoots ?? []);
    removeFixturePath(fixtureRoot);
    removeFixturePath(custody);
    removeFixturePath(tools);
  }
});

test("linked-worktree split indexes are captured without touching their live index files", () => {
  const fixtureRoot = privateTemp("noa-kws-linked-worktree-root-");
  const custody = privateTemp("noa-kws-linked-worktree-custody-");
  const main = path.join(fixtureRoot, "main");
  const linked = path.join(fixtureRoot, "linked");
  fs.mkdirSync(main, { mode: 0o700 });
  let captured: Capture | null = null;
  try {
    initRepository(main);
    fs.writeFileSync(path.join(main, "tracked.txt"), "linked worktree base\n");
    git(main, ["add", "--all"]);
    git(main, ["commit", "-q", "-m", "linked worktree base"]);
    git(main, ["worktree", "add", "-q", "-b", "linked-candidate", linked]);
    git(linked, ["update-index", "--split-index"]);
    fs.writeFileSync(path.join(linked, "tracked.txt"), "linked worktree dirty\n");
    const indexPath = (git(
      linked,
      ["rev-parse", "--path-format=absolute", "--git-path", "index"],
    ) as string).trim();
    const sharedText = (git(linked, ["rev-parse", "--shared-index-path"]) as string).trim();
    const reportedSharedPath = path.resolve(linked, sharedText);
    const sharedPath = path.join(
      fs.realpathSync(path.dirname(reportedSharedPath)),
      path.basename(reportedSharedPath),
    );
    assert.equal(path.dirname(indexPath), path.dirname(sharedPath));
    const indexBefore = gitFileStableObservation(indexPath);
    const sharedBefore = gitFileStableObservation(sharedPath);
    captured = workspace.captureAndSealCandidate({ custodyRoot: custody, sourceRoot: linked });
    assert.equal(captured.attempt, 1);
    assert.deepEqual(gitFileStableObservation(indexPath), indexBefore);
    assert.deepEqual(gitFileStableObservation(sharedPath), sharedBefore);
    assert.equal(
      path.basename(captured.sourceSnapshot.git.sharedIndex?.path ?? ""),
      path.basename(sharedPath),
    );
  } finally {
    cleanupReportedScratchRoots(captured?.retainedPrivateRoots ?? []);
    removeFixturePath(fixtureRoot);
    removeFixturePath(custody);
  }
});

test("symlink-prefix resolution accepts safe chains and classifies excluded Git targets", async (t) => {
  await t.test("safe internal prefix chain", () => {
    const fixture = minimalCaptureFixture("safe-symlink-prefix");
    let captured: Capture | null = null;
    try {
      fs.mkdirSync(path.join(fixture.source, "dir"), { mode: 0o700 });
      fs.writeFileSync(path.join(fixture.source, "dir", "x"), "safe target\n", { mode: 0o600 });
      fs.symlinkSync("dir", path.join(fixture.source, "dirlink"));
      fs.symlinkSync("dirlink/x", path.join(fixture.source, "link"));
      captured = workspace.captureAndSealCandidate({
        custodyRoot: fixture.custody,
        sourceRoot: fixture.source,
      });
      assert.equal(fs.readlinkSync(path.join(captured.workspaceRoot, "link")), "dirlink/x");
    } finally {
      cleanupReportedScratchRoots(captured?.retainedPrivateRoots ?? []);
      removeFixturePath(fixture.source);
      removeFixturePath(fixture.custody);
    }
  });

  for (const fixtureCase of [
    {
      configure(source: string) {
        fs.symlinkSync(".git/HEAD", path.join(source, "leak"));
      },
      label: "direct .git target",
    },
    {
      configure(source: string) {
        fs.symlinkSync(".git", path.join(source, "gitlink"));
        fs.symlinkSync("gitlink/HEAD", path.join(source, "leak"));
      },
      label: "indirect .git target",
    },
  ]) {
    await t.test(fixtureCase.label, () => {
      const fixture = minimalCaptureFixture(`unsafe-${fixtureCase.label.replaceAll(" ", "-")}`);
      try {
        fixtureCase.configure(fixture.source);
        assert.throws(
          () => workspace.captureAndSealCandidate({
            custodyRoot: fixture.custody,
            maxAttempts: 2,
            sourceRoot: fixture.source,
          }),
          (error: WorkspaceError) => error.code === workspaceErrorCode("UNSAFE_SYMLINK"),
        );
      } finally {
        removeFixturePath(fixture.source);
        removeFixturePath(fixture.custody);
      }
    });
  }
});

test("metadata census excludes shared temp ancestors above its bound workspace", () => {
  const root = fs.realpathSync(privateTemp("noa-kws-metadata-boundary-"));
  const leaf = path.join(root, "leaf.txt");
  fs.writeFileSync(leaf, "stable\n", { mode: 0o600 });
  const sharedTemp = fs.realpathSync(os.tmpdir());
  const lstatDescriptor = Object.getOwnPropertyDescriptor(fs, "lstatSync");
  assert.ok(lstatDescriptor !== undefined);
  const originalLstat = fs.lstatSync;
  let sharedAncestorObservations = 0;
  try {
    Object.defineProperty(fs, "lstatSync", {
      ...lstatDescriptor,
      value: (...args: Parameters<typeof fs.lstatSync>) => {
        if (path.resolve(String(args[0])) === sharedTemp) sharedAncestorObservations += 1;
        return Reflect.apply(originalLstat, fs, args) as ReturnType<typeof fs.lstatSync>;
      },
    });
    const observed = workspace.censusWorkspace(root, { rootGitPolicy: "absent" });
    assert.equal(observed.nodeCount, 2);
    assert.equal(sharedAncestorObservations, 0);
  } finally {
    Object.defineProperty(fs, "lstatSync", lstatDescriptor);
    removeFixturePath(root);
  }
});

test("metadata census rejects a forged admitted-root identity", () => {
  const root = fs.realpathSync(privateTemp("noa-kws-metadata-anchor-"));
  const leaf = path.join(root, "a", "b", "leaf.txt");
  fs.mkdirSync(path.dirname(leaf), { recursive: true, mode: 0o700 });
  fs.chmodSync(path.join(root, "a"), 0o700);
  fs.chmodSync(path.join(root, "a", "b"), 0o700);
  fs.writeFileSync(leaf, "stable\n", { mode: 0o600 });

  const openDescriptor = Object.getOwnPropertyDescriptor(fs, "openSync");
  const lstatDescriptor = Object.getOwnPropertyDescriptor(fs, "lstatSync");
  assert.ok(openDescriptor !== undefined);
  assert.ok(lstatDescriptor !== undefined);
  const originalOpen = fs.openSync;
  const originalLstat = fs.lstatSync;
  let leafOpened = false;
  let rootLstatsAfterLeaf = 0;
  let forgedRootLstats = 0;
  try {
    Object.defineProperty(fs, "openSync", {
      ...openDescriptor,
      value: (...args: Parameters<typeof fs.openSync>) => {
        const fd = Reflect.apply(originalOpen, fs, args) as number;
        if (args[0] === leaf) leafOpened = true;
        return fd;
      },
    });
    Object.defineProperty(fs, "lstatSync", {
      ...lstatDescriptor,
      value: (...args: Parameters<typeof fs.lstatSync>) => {
        const stat = Reflect.apply(originalLstat, fs, args) as ReturnType<typeof fs.lstatSync>;
        if (args[0] === root && leafOpened) {
          rootLstatsAfterLeaf += 1;
          if (rootLstatsAfterLeaf <= 2) {
            assert.notEqual(stat, undefined);
            const bigStat = stat as fs.BigIntStats;
            assert.equal(typeof bigStat.ino, "bigint");
            const inoDescriptor = Object.getOwnPropertyDescriptor(bigStat, "ino");
            assert.ok(inoDescriptor !== undefined);
            Object.defineProperty(bigStat, "ino", {
              ...inoDescriptor,
              value: bigStat.ino + 1_000_000n,
            });
            forgedRootLstats += 1;
          }
        }
        return stat;
      },
    });
    assert.throws(
      () => workspace.censusWorkspace(root, { rootGitPolicy: "absent" }),
      (error: WorkspaceError) => error.code === workspaceErrorCode("SNAPSHOT_UNSTABLE"),
    );
    assert.equal(leafOpened, true);
    assert.equal(rootLstatsAfterLeaf, 1);
    assert.equal(forgedRootLstats, 1);
  } finally {
    Object.defineProperty(fs, "openSync", openDescriptor);
    Object.defineProperty(fs, "lstatSync", lstatDescriptor);
    removeFixturePath(root);
  }
});

test("descriptor-pinned metadata prevents parent-subtree ABA laundering", {
  skip: !["darwin", "linux"].includes(process.platform),
}, () => {
  const container = fs.realpathSync(privateTemp("noa-kws-metadata-parent-aba-"));
  const decoyContainer = fs.realpathSync(privateTemp("noa-kws-metadata-parent-decoy-"));
  const root = path.join(container, "workspace");
  const decoy = path.join(decoyContainer, "workspace");
  const retainedContainer = `${container}.created-parent.retained`;
  fs.mkdirSync(root, { mode: 0o700 });
  fs.mkdirSync(decoy, { mode: 0o700 });
  const prepare = (base: string) => {
    const leaf = path.join(base, "a", "b", "leaf.txt");
    fs.mkdirSync(path.dirname(leaf), { recursive: true, mode: 0o700 });
    fs.chmodSync(path.join(base, "a"), 0o700);
    fs.chmodSync(path.join(base, "a", "b"), 0o700);
    fs.writeFileSync(leaf, "stable\n", { mode: 0o600 });
    return leaf;
  };
  const leaf = prepare(root);
  prepare(decoy);

  const openDescriptor = Object.getOwnPropertyDescriptor(fs, "openSync");
  const lstatDescriptor = Object.getOwnPropertyDescriptor(fs, "lstatSync");
  assert.ok(openDescriptor !== undefined);
  assert.ok(lstatDescriptor !== undefined);
  const originalOpen = fs.openSync;
  const originalLstat = fs.lstatSync;
  let leafOpened = false;
  let leafLstatsAfterOpen = 0;
  let swapped = false;
  let restored = false;
  try {
    // The Darwin batch binds every pathname chain before opening its node descriptors. This
    // fixture swaps the admitted root during that bind, so the earliest deterministic refusal is
    // the root descriptor disagreeing with its already witnessed identity.
    const expectedCode = process.platform === "linux" ? "ACL_UNSUPPORTED" : "SNAPSHOT_UNSTABLE";
    if (process.platform === "linux") {
      const setfacl = requiredExecutable(["/usr/bin/setfacl", "/bin/setfacl"], "setfacl");
      requiredExecutable(["/usr/bin/getfacl", "/bin/getfacl"], "getfacl");
      requiredExecutable(["/usr/bin/getfattr", "/bin/getfattr"], "getfattr");
      execFileSync(setfacl, ["-m", "u:12345:r--", leaf]);
    } else {
      execFileSync("/usr/bin/xattr", ["-w", "user.noa_anchor_aba", "must-be-observed", leaf]);
    }
    Object.defineProperty(fs, "openSync", {
      ...openDescriptor,
      value: (...args: Parameters<typeof fs.openSync>) => {
        const fd = Reflect.apply(originalOpen, fs, args) as number;
        if (args[0] === leaf) leafOpened = true;
        return fd;
      },
    });
    Object.defineProperty(fs, "lstatSync", {
      ...lstatDescriptor,
      value: (...args: Parameters<typeof fs.lstatSync>) => {
        if (args[0] === root && swapped && !restored) {
          fs.renameSync(container, decoyContainer);
          fs.renameSync(retainedContainer, container);
          restored = true;
        }
        const stat = Reflect.apply(originalLstat, fs, args) as ReturnType<typeof fs.lstatSync>;
        if (args[0] === leaf && leafOpened && !swapped) {
          leafLstatsAfterOpen += 1;
          if (leafLstatsAfterOpen === 2) {
            fs.renameSync(container, retainedContainer);
            fs.renameSync(decoyContainer, container);
            swapped = true;
          }
        }
        return stat;
      },
    });
    assert.throws(
      () => workspace.censusWorkspace(root, { rootGitPolicy: "absent" }),
      (error: WorkspaceError) =>
        error.code === workspaceErrorCode(expectedCode) &&
        (process.platform === "linux" || error.message.includes(
          "changed while binding its metadata descriptor",
        )),
    );
    assert.equal(swapped, true, "parent-subtree substitution was not exercised");
  } finally {
    Object.defineProperty(fs, "openSync", openDescriptor);
    Object.defineProperty(fs, "lstatSync", lstatDescriptor);
    if (swapped && !restored) {
      fs.renameSync(container, decoyContainer);
      fs.renameSync(retainedContainer, container);
    }
    removeFixturePath(container);
    removeFixturePath(decoyContainer);
    removeFixturePath(retainedContainer);
  }
});

test("metadata launcher diagnostics and absence fail closed", {
  skip: !["darwin", "linux"].includes(process.platform),
}, () => {
  const root = fs.realpathSync(privateTemp("noa-kws-metadata-launcher-"));
  fs.writeFileSync(path.join(root, "leaf.txt"), "stable\n", { mode: 0o600 });
  const descriptor = Object.getOwnPropertyDescriptor(childProcess, "spawnSync");
  assert.ok(descriptor !== undefined);
  const originalSpawnSync = childProcess.spawnSync;
  const launcher = "/usr/bin/perl";
  let calls = 0;
  let mode: "enoent" | "stderr" = "stderr";
  const stub = ((...args: Parameters<typeof childProcess.spawnSync>) => {
    if (args[0] !== launcher) {
      return Reflect.apply(originalSpawnSync, childProcess, args);
    }
    calls += 1;
    if (mode === "stderr") {
      const stdout = Buffer.alloc(0);
      const stderr = Buffer.from("unexpected diagnostic\n");
      return {
        pid: 123,
        output: [null, stdout, stderr],
        signal: null,
        status: 0,
        stderr,
        stdout,
      };
    }
    const error = Object.assign(new Error("injected missing launcher"), { code: "ENOENT" });
    return {
      error,
      pid: 0,
      output: [null, null, null],
      signal: null,
      status: null,
      stderr: null,
      stdout: null,
    };
  }) as typeof childProcess.spawnSync;
  try {
    Object.defineProperty(childProcess, "spawnSync", { ...descriptor, value: stub });
    syncBuiltinESMExports();
    let refusal: WorkspaceError | null = null;
    assert.throws(
      () => workspace.censusWorkspace(root, { rootGitPolicy: "absent" }),
      (error: WorkspaceError) => {
        refusal = error;
        return error.code === workspaceErrorCode("ACL_UNSUPPORTED") &&
          error.details?.status === 0 &&
          error.details.stderr === "unexpected diagnostic\n" &&
          error.details.launcherUnavailable === false;
      },
    );
    assert.equal(calls, 1);

    mode = "enoent";
    calls = 0;
    refusal = null;
    assert.throws(
      () => workspace.censusWorkspace(root, { rootGitPolicy: "absent" }),
      (error: WorkspaceError) => {
        refusal = error;
        return error.code === workspaceErrorCode("ACL_UNSUPPORTED") &&
          error.details?.launcher === launcher &&
          error.details.launcherUnavailable === true &&
          (error.cause as NodeJS.ErrnoException | undefined)?.code === "ENOENT";
      },
    );
    assert.equal(calls, 1);
    assert.ok(refusal !== null);
  } finally {
    Object.defineProperty(childProcess, "spawnSync", descriptor);
    syncBuiltinESMExports();
    removeFixturePath(root);
  }
});

test("macOS descriptor metadata batches preserve exact bytes and fixed chunk bounds", (t) => {
  if (process.platform !== "darwin") {
    t.skip("requires Darwin descriptor metadata APIs");
    return;
  }
  for (const executable of ["/usr/bin/perl", "/usr/bin/python3", "/usr/bin/xattr"]) {
    try { fs.accessSync(executable, fs.constants.X_OK); }
    catch {
      t.skip(`required metadata tool is unavailable: ${executable}`);
      return;
    }
  }

  const root = fs.realpathSync(privateTemp("noa-kws-metadata-batch-"));
  const directory = path.join(root, "directory");
  const unusual = path.join(directory, "line\nname\tfile");
  const link = path.join(root, "link");
  const symlinkFlag = fs.constants.O_SYMLINK;
  assert.ok(Number.isSafeInteger(symlinkFlag) && symlinkFlag > 0);
  const requestedProvenance = Buffer.from([
    0x00, 0x01, 0x02, 0x03, 0x0a, 0x0d, 0xff, 0x80, 0x41, 0x42, 0x43,
  ]);
  const exactXattrFixture = String.raw`
import base64
import ctypes
import os
import stat
import sys
value = base64.b64decode(sys.argv[2], validate=True)
link_flags = int(sys.argv[3])
fd = os.open(sys.argv[1], os.O_RDONLY | link_flags)
try:
    if stat.S_ISLNK(os.fstat(fd).st_mode) != (link_flags != 0):
        raise ValueError("fixture descriptor has the wrong node type")
    libc = ctypes.CDLL(None, use_errno=True)
    libc.fsetxattr.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_int]
    libc.fsetxattr.restype = ctypes.c_int
    libc.fgetxattr.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_int]
    libc.fgetxattr.restype = ctypes.c_ssize_t
    name = b"com.apple.provenance"
    source = ctypes.create_string_buffer(value, len(value))
    if libc.fsetxattr(fd, name, source, len(value), 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "fsetxattr")
    size = libc.fgetxattr(fd, name, None, 0, 0, 0)
    if size < 0:
        raise OSError(ctypes.get_errno(), "fgetxattr size")
    observed = ctypes.create_string_buffer(size)
    if libc.fgetxattr(fd, name, observed, size, 0, 0) != size:
        raise OSError(ctypes.get_errno(), "fgetxattr value")
    sys.stdout.write(base64.b64encode(bytes(observed.raw[:size])).decode("ascii"))
finally:
    os.close(fd)
`;
  const directXattrOracle = String.raw`
import base64
import ctypes
import errno
import json
import os
import stat
import sys
request = json.loads(sys.stdin.buffer.read())
symlink_flag = int(sys.argv[1])
if symlink_flag <= 0:
    raise ValueError("a nonzero Darwin symlink flag is required")
libc = ctypes.CDLL(None, use_errno=True)
libc.fgetxattr.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_int]
libc.fgetxattr.restype = ctypes.c_ssize_t
name = sys.argv[2].encode("ascii")
absent_errnos = {getattr(errno, "ENOATTR", -1), getattr(errno, "ENODATA", -1)}
result = []
for item in request:
    flags = os.O_RDONLY | (symlink_flag if item["symlink"] else 0)
    fd = os.open(item["operand"], flags)
    try:
        if stat.S_ISLNK(os.fstat(fd).st_mode) != item["symlink"]:
            raise ValueError("oracle descriptor has the wrong node type")
        ctypes.set_errno(0)
        size = libc.fgetxattr(fd, name, None, 0, 0, 0)
        if size < 0:
            observed_errno = ctypes.get_errno()
            if observed_errno not in absent_errnos:
                raise OSError(observed_errno, "fgetxattr size")
            value = None
        else:
            observed = ctypes.create_string_buffer(size)
            ctypes.set_errno(0)
            read = libc.fgetxattr(fd, name, observed, size, 0, 0)
            if read != size:
                observed_errno = ctypes.get_errno()
                raise OSError(observed_errno, "fgetxattr value")
            value = base64.b64encode(bytes(observed.raw[:size])).decode("ascii")
        result.append({"path": item["path"], "valueBase64": value})
    finally:
        os.close(fd)
sys.stdout.write(json.dumps(result, ensure_ascii=True, separators=(",", ":"), sort_keys=True))
`;
  const spawnDescriptor = Object.getOwnPropertyDescriptor(childProcess, "spawnSync");
  assert.ok(spawnDescriptor !== undefined);
  const originalSpawnSync = childProcess.spawnSync;
  const helperCalls = { acl: 0, xattr: 0 };
  try {
    fs.mkdirSync(directory, { mode: 0o700 });
    for (let index = 0; index < 126; index++) {
      fs.writeFileSync(path.join(directory, `file-${index.toString().padStart(3, "0")}`), "x", {
        mode: 0o600,
      });
    }
    fs.writeFileSync(unusual, "unusual\n", { mode: 0o600 });
    fs.symlinkSync(path.join("directory", "file-000"), link);
    const oracleAttribute = "com.noa.metadata-oracle";
    const distinctNodes = [
      { operand: path.join(directory, "file-000"), path: "directory/file-000", symlink: false,
        value: Buffer.from("TARGET\0\xff", "latin1") },
      { operand: link, path: "link", symlink: true, value: Buffer.from("LINK\0\x80", "latin1") },
    ];
    for (const node of distinctNodes) {
      execFileSync("/usr/bin/xattr", [
        "-w", "-x", ...(node.symlink ? ["-s"] : []),
        oracleAttribute, node.value.toString("hex"), node.operand,
      ]);
    }
    const distinctReadback = execFileSync("/usr/bin/python3", [
      "-I", "-S", "-c", directXattrOracle, String(symlinkFlag), oracleAttribute,
    ], { encoding: "utf8", input: JSON.stringify(distinctNodes) });
    assert.deepEqual(JSON.parse(distinctReadback), distinctNodes.map((node) => ({
      path: node.path, valueBase64: node.value.toString("base64"),
    })), "the independent oracle must distinguish the link object from its target");
    for (const node of distinctNodes) {
      execFileSync("/usr/bin/xattr", [
        "-d", ...(node.symlink ? ["-s"] : []), oracleAttribute, node.operand,
      ]);
    }
    const readBackValues = [];
    for (const [target, symlink] of [
      [root, false], [directory, false], [unusual, false], [link, true],
    ] as const) {
      const readBack = execFileSync("/usr/bin/python3", [
        "-I", "-S", "-c", exactXattrFixture, target, requestedProvenance.toString("base64"),
        String(symlink ? symlinkFlag : 0),
      ], { encoding: "utf8" });
      const readBackValue = Buffer.from(readBack, "base64");
      assert.equal(readBackValue.toString("base64"), readBack);
      readBackValues.push(readBackValue);
    }
    const provenance = readBackValues[0];
    assert.ok(provenance !== undefined && provenance.includes(0x00));
    for (const readBack of readBackValues) assert.deepEqual(readBack, provenance);

    const oracleRequest = [
      { operand: root, path: ".", symlink: false },
      { operand: directory, path: "directory", symlink: false },
      ...Array.from({ length: 126 }, (_, index) => {
        const name = `file-${index.toString().padStart(3, "0")}`;
        return { operand: path.join(directory, name), path: `directory/${name}`, symlink: false };
      }),
      { operand: unusual, path: "directory/line\nname\tfile", symlink: false },
      { operand: link, path: "link", symlink: true },
    ];
    const oracleOutput = execFileSync(
      "/usr/bin/python3",
      ["-I", "-S", "-c", directXattrOracle, String(symlinkFlag), "com.apple.provenance"],
      { encoding: "utf8", input: JSON.stringify(oracleRequest), maxBuffer: 1024 * 1024 },
    );
    const oracleRecords = JSON.parse(oracleOutput) as Array<{
      path: string;
      valueBase64: string | null;
    }>;
    assert.equal(oracleRecords.length, oracleRequest.length);
    const expectedProvenance = new Map<string, {
      classification: string;
      length: number;
      present: boolean;
      sha256: string | null;
    }>();
    for (const record of oracleRecords) {
      assert.equal(expectedProvenance.has(record.path), false, `duplicate oracle path ${record.path}`);
      if (record.valueBase64 === null) {
        expectedProvenance.set(record.path, {
          classification: "NON_SEMANTIC_OS_MANAGED_PATH_LOCAL",
          length: 0,
          present: false,
          sha256: null,
        });
        continue;
      }
      const value = Buffer.from(record.valueBase64, "base64");
      assert.equal(value.toString("base64"), record.valueBase64);
      expectedProvenance.set(record.path, {
        classification: "NON_SEMANTIC_OS_MANAGED_PATH_LOCAL",
        length: value.length,
        present: true,
        sha256: crypto.createHash("sha256").update(value).digest("hex"),
      });
    }
    assert.deepEqual(
      [".", "directory", "directory/line\nname\tfile", "link"].map((operand) =>
        expectedProvenance.get(operand)),
      Array.from({ length: 4 }, () => ({
        classification: "NON_SEMANTIC_OS_MANAGED_PATH_LOCAL",
        length: provenance.length,
        present: true,
        sha256: crypto.createHash("sha256").update(provenance).digest("hex"),
      })),
    );

    Object.defineProperty(childProcess, "spawnSync", {
      ...spawnDescriptor,
      value: ((...args: Parameters<typeof childProcess.spawnSync>) => {
        const childArgs = args[1];
        if (
          args[0] === "/usr/bin/perl" && Array.isArray(childArgs) &&
          childArgs.includes("/usr/bin/python3")
        ) {
          if (childArgs.includes("acl")) helperCalls.acl += 1;
          if (childArgs.includes("xattr")) helperCalls.xattr += 1;
        }
        return Reflect.apply(originalSpawnSync, childProcess, args);
      }) as typeof childProcess.spawnSync,
    });
    syncBuiltinESMExports();

    const census = workspace.censusWorkspace(root, {
      commandTimeoutMs: 10_000,
      rootGitPolicy: "absent",
    });
    assert.equal(census.nodeCount, 130);
    const expectedChunks = Math.ceil(census.nodeCount / 64);
    assert.deepEqual(helperCalls, { acl: expectedChunks, xattr: expectedChunks });
    for (const node of census.nodes) {
      const expected = expectedProvenance.get(node.path);
      assert.ok(expected !== undefined, `oracle omitted ${JSON.stringify(node.path)}`);
      assert.deepEqual(
        node.provenance,
        expected,
        `unexpected metadata for ${JSON.stringify(node.path)}`,
      );
    }
    assert.equal(census.nodes.find((node) => node.path === "link")?.type, "symlink");
  } finally {
    Object.defineProperty(childProcess, "spawnSync", spawnDescriptor);
    syncBuiltinESMExports();
    removeFixturePath(root);
  }
});

test("macOS descriptor metadata helper errors and partial output fail closed", async (t) => {
  if (process.platform !== "darwin") {
    t.skip("requires Darwin descriptor metadata APIs");
    return;
  }
  const cases: Array<{
    expectedCode: string;
    label: string;
    mode: "acl" | "xattr";
    response: "api-error" | "duplicate" | "noncanonical" | "partial" | "wrong-fd";
  }> = [
    { expectedCode: "ACL_UNSUPPORTED", label: "ACL API error", mode: "acl", response: "api-error" },
    {
      expectedCode: "XATTR_UNSUPPORTED",
      label: "xattr API error",
      mode: "xattr",
      response: "api-error",
    },
    {
      expectedCode: "XATTR_UNSUPPORTED",
      label: "partial successful batch",
      mode: "xattr",
      response: "partial",
    },
    {
      expectedCode: "XATTR_UNSUPPORTED",
      label: "duplicate attribute record",
      mode: "xattr",
      response: "duplicate",
    },
    {
      expectedCode: "XATTR_UNSUPPORTED",
      label: "noncanonical output framing",
      mode: "xattr",
      response: "noncanonical",
    },
    {
      expectedCode: "XATTR_UNSUPPORTED",
      label: "wrong descriptor ordinal",
      mode: "xattr",
      response: "wrong-fd",
    },
  ];
  for (const fixtureCase of cases) {
    await t.test(fixtureCase.label, () => {
      const root = fs.realpathSync(privateTemp("noa-kws-metadata-helper-refusal-"));
      fs.writeFileSync(path.join(root, "leaf"), "stable\n", { mode: 0o600 });
      const spawnDescriptor = Object.getOwnPropertyDescriptor(childProcess, "spawnSync");
      assert.ok(spawnDescriptor !== undefined);
      const originalSpawnSync = childProcess.spawnSync;
      let injected = 0;
      try {
        Object.defineProperty(childProcess, "spawnSync", {
          ...spawnDescriptor,
          value: ((...args: Parameters<typeof childProcess.spawnSync>) => {
            const childArgs = args[1];
            if (
              injected === 0 && args[0] === "/usr/bin/perl" && Array.isArray(childArgs) &&
              childArgs.includes("/usr/bin/python3") && childArgs.includes(fixtureCase.mode)
            ) {
              injected += 1;
              let stdout = Buffer.alloc(0);
              if (fixtureCase.response === "partial") stdout = Buffer.from("[]");
              if (["duplicate", "noncanonical", "wrong-fd"].includes(fixtureCase.response)) {
                const stdio = (args[2] as { stdio?: unknown[] } | undefined)?.stdio;
                assert.ok(Array.isArray(stdio));
                const records = stdio.slice(4).map((fd, index) => {
                  assert.equal(typeof fd, "number");
                  const observed = fs.fstatSync(fd as number, { bigint: true });
                  return {
                    fd: fixtureCase.response === "wrong-fd" && index === 0 ? 99 : index + 4,
                    namesBase64: fixtureCase.response === "duplicate"
                      ? [
                          Buffer.from("com.apple.provenance").toString("base64"),
                          Buffer.from("com.apple.provenance").toString("base64"),
                        ]
                      : [],
                    provenanceBase64: fixtureCase.response === "duplicate" ? "" : null,
                    stat: {
                      ctimeNs: String(observed.ctimeNs),
                      identity: `${observed.dev}:${observed.ino}`,
                      mode: Number(observed.mode & 0o7777n),
                      mtimeNs: String(observed.mtimeNs),
                      nlink: Number(observed.nlink),
                      size: Number(observed.size),
                      type: observed.isSymbolicLink() ? "symlink" : observed.isDirectory()
                        ? "directory" : observed.isFile() ? "file" : "other",
                      uid: Number(observed.uid),
                    },
                  };
                });
                stdout = Buffer.from(
                  `${fixtureCase.response === "noncanonical" ? " " : ""}${JSON.stringify(records)}`,
                );
              }
              const stderr = Buffer.from(
                fixtureCase.response === "api-error"
                  ? "mac metadata helper refused injected errno=5\n"
                  : "",
              );
              return {
                pid: 123,
                output: [null, stdout, stderr],
                signal: null,
                status: fixtureCase.response === "api-error" ? 70 : 0,
                stderr,
                stdout,
              };
            }
            return Reflect.apply(originalSpawnSync, childProcess, args);
          }) as typeof childProcess.spawnSync,
        });
        syncBuiltinESMExports();
        assert.throws(
          () => workspace.censusWorkspace(root, {
            commandTimeoutMs: 10_000,
            rootGitPolicy: "absent",
          }),
          (error: WorkspaceError) => error.code === workspaceErrorCode(fixtureCase.expectedCode),
        );
        assert.equal(injected, 1);
      } finally {
        Object.defineProperty(childProcess, "spawnSync", spawnDescriptor);
        syncBuiltinESMExports();
        removeFixturePath(root);
      }
    });
  }
});

test("macOS descriptor xattr framing refuses newline-bearing attribute names", (t) => {
  if (process.platform !== "darwin") {
    t.skip("requires Darwin descriptor metadata APIs");
    return;
  }
  const root = fs.realpathSync(privateTemp("noa-kws-metadata-xattr-name-"));
  const leaf = path.join(root, "line\nname\tfile");
  const unsupportedName = "user.noa\nambiguous";
  try {
    fs.writeFileSync(leaf, "stable\n", { mode: 0o600 });
    try { execFileSync("/usr/bin/xattr", ["-w", unsupportedName, "value", leaf]); }
    catch {
      t.skip("the local filesystem cannot create a newline-bearing xattr name");
      return;
    }
    assert.throws(
      () => workspace.censusWorkspace(root, {
        commandTimeoutMs: 10_000,
        rootGitPolicy: "absent",
      }),
      (error: WorkspaceError) =>
        error.code === workspaceErrorCode("XATTR_UNSUPPORTED") &&
        Array.isArray(error.details?.names) && error.details.names.includes(unsupportedName),
    );
  } finally {
    removeFixturePath(root);
  }
});

test("bound Git-entry launcher absence is a terminal platform refusal", {
  skip: !["darwin", "linux"].includes(process.platform),
}, () => {
  const fixture = minimalCaptureFixture("bound-entry-launcher");
  const descriptor = Object.getOwnPropertyDescriptor(childProcess, "spawnSync");
  assert.ok(descriptor !== undefined);
  const originalSpawnSync = childProcess.spawnSync;
  const launcher = "/usr/bin/perl";
  let injected = 0;
  let refusal: WorkspaceError | null = null;
  try {
    Object.defineProperty(childProcess, "spawnSync", {
      ...descriptor,
      value: ((...args: Parameters<typeof childProcess.spawnSync>) => {
        if (
          args[0] === launcher && Array.isArray(args[1]) &&
          args[1].includes(process.platform === "darwin" ? "/usr/bin/stat" :
            (["/usr/bin/stat", "/bin/stat"].find((value) => fs.existsSync(value)) ?? "/usr/bin/stat"))
        ) {
          injected += 1;
          const error = Object.assign(new Error("injected missing metadata launcher"), {
            code: "ENOENT",
          });
          return {
            error,
            pid: 0,
            output: [null, null, null],
            signal: null,
            status: null,
            stderr: null,
            stdout: null,
          };
        }
        return Reflect.apply(originalSpawnSync, childProcess, args);
      }) as typeof childProcess.spawnSync,
    });
    syncBuiltinESMExports();
    assert.throws(
      () => workspace.observeSourceGit(fixture.source),
      (error: WorkspaceError) => {
        refusal = error;
        return error.code === workspaceErrorCode("SOURCE_GIT_OBSERVATION_FAILED") &&
          error.details?.launcher === launcher &&
          error.details.launcherUnavailable === true &&
          (error.cause as NodeJS.ErrnoException | undefined)?.code === "ENOENT";
      },
    );
    assert.equal(injected, 1, "bound-entry launcher failure was not injected");
    assert.ok(refusal !== null);
  } finally {
    Object.defineProperty(childProcess, "spawnSync", descriptor);
    syncBuiltinESMExports();
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
  }
});

test("metadata census detects in-anchor ancestor ctime ABA", () => {
  const root = fs.realpathSync(privateTemp("noa-kws-metadata-ctime-aba-"));
  const parent = path.join(root, "a");
  const originalDirectory = path.join(parent, "b");
  const decoyDirectory = path.join(parent, "decoy-b");
  const retainedDirectory = path.join(parent, "created-b.retained");
  fs.mkdirSync(originalDirectory, { recursive: true, mode: 0o700 });
  fs.mkdirSync(decoyDirectory, { mode: 0o700 });
  fs.chmodSync(parent, 0o700);
  const leaf = path.join(originalDirectory, "leaf.txt");
  fs.writeFileSync(leaf, "stable\n", { mode: 0o600 });
  fs.writeFileSync(path.join(decoyDirectory, "leaf.txt"), "stable\n", { mode: 0o600 });

  const openDescriptor = Object.getOwnPropertyDescriptor(fs, "openSync");
  const lstatDescriptor = Object.getOwnPropertyDescriptor(fs, "lstatSync");
  assert.ok(openDescriptor !== undefined);
  assert.ok(lstatDescriptor !== undefined);
  const originalOpen = fs.openSync;
  const originalLstat = fs.lstatSync;
  let leafOpened = false;
  let leafLstatsAfterOpen = 0;
  let swapped = false;
  let restored = false;
  try {
    Object.defineProperty(fs, "openSync", {
      ...openDescriptor,
      value: (...args: Parameters<typeof fs.openSync>) => {
        const fd = Reflect.apply(originalOpen, fs, args) as number;
        if (args[0] === leaf) leafOpened = true;
        return fd;
      },
    });
    Object.defineProperty(fs, "lstatSync", {
      ...lstatDescriptor,
      value: (...args: Parameters<typeof fs.lstatSync>) => {
        if (args[0] === root && swapped && !restored) {
          fs.renameSync(originalDirectory, decoyDirectory);
          fs.renameSync(retainedDirectory, originalDirectory);
          restored = true;
        }
        const stat = Reflect.apply(originalLstat, fs, args) as ReturnType<typeof fs.lstatSync>;
        if (args[0] === leaf && leafOpened && !swapped) {
          leafLstatsAfterOpen += 1;
          if (leafLstatsAfterOpen === 2) {
            fs.renameSync(originalDirectory, retainedDirectory);
            fs.renameSync(decoyDirectory, originalDirectory);
            swapped = true;
          }
        }
        return stat;
      },
    });
    assert.throws(
      () => workspace.censusWorkspace(root, { rootGitPolicy: "absent" }),
      (error: WorkspaceError) => error.code === workspaceErrorCode("SNAPSHOT_UNSTABLE"),
    );
    assert.equal(swapped, true, "in-anchor substitution was not exercised");
    assert.equal(restored, true, "the in-anchor original was not restored");
  } finally {
    Object.defineProperty(fs, "openSync", openDescriptor);
    Object.defineProperty(fs, "lstatSync", lstatDescriptor);
    if (swapped && !restored) {
      fs.renameSync(originalDirectory, decoyDirectory);
      fs.renameSync(retainedDirectory, originalDirectory);
    }
    removeFixturePath(root);
  }
});

test("an effective-UID change invalidates the operation before filesystem work continues", () => {
  const root = privateTemp("noa-kws-effective-uid-");
  fs.writeFileSync(path.join(root, "leaf.txt"), "stable\n", { mode: 0o600 });
  const descriptor = Object.getOwnPropertyDescriptor(process, "geteuid");
  assert.ok(descriptor !== undefined);
  const originalGeteuid = process.geteuid;
  assert.equal(typeof originalGeteuid, "function");
  const initialUid = originalGeteuid!();
  let calls = 0;
  try {
    Object.defineProperty(process, "geteuid", {
      ...descriptor,
      value: () => {
        calls += 1;
        return calls === 1 ? initialUid : initialUid + 1;
      },
    });
    assert.throws(
      () => workspace.censusWorkspace(root, { rootGitPolicy: "absent" }),
      (error: WorkspaceError) => {
        assert.equal(error.details?.expectedEffectiveUid, initialUid);
        assert.equal(error.details?.observedEffectiveUid, initialUid + 1);
        return error.code === workspaceErrorCode("PRIVATE_ROOT_UNSAFE");
      },
    );
    assert.equal(calls, 2);
  } finally {
    Object.defineProperty(process, "geteuid", descriptor);
    removeFixturePath(root);
  }
});

test("effective-UID preflight refuses unavailable, throwing, and malformed principals", async (t) => {
  const cases: Array<{ label: string; value: unknown }> = [
    { label: "unavailable", value: undefined },
    { label: "throws", value: () => { throw new Error("simulated geteuid failure"); } },
    { label: "negative", value: () => -1 },
    { label: "non-integer", value: () => 1.5 },
    { label: "unsafe integer", value: () => Number.MAX_SAFE_INTEGER + 1 },
  ];
  for (const fixtureCase of cases) {
    await t.test(fixtureCase.label, () => {
      const root = privateTemp(`noa-kws-effective-uid-${fixtureCase.label.replaceAll(" ", "-")}-`);
      const geteuidDescriptor = Object.getOwnPropertyDescriptor(process, "geteuid");
      const lstatDescriptor = Object.getOwnPropertyDescriptor(fs, "lstatSync");
      assert.ok(geteuidDescriptor !== undefined);
      assert.ok(lstatDescriptor !== undefined);
      const originalLstat = fs.lstatSync;
      let lstatCalls = 0;
      try {
        Object.defineProperty(process, "geteuid", {
          ...geteuidDescriptor,
          value: fixtureCase.value,
        });
        Object.defineProperty(fs, "lstatSync", {
          ...lstatDescriptor,
          value: (...args: Parameters<typeof fs.lstatSync>) => {
            lstatCalls += 1;
            return Reflect.apply(originalLstat, fs, args) as ReturnType<typeof fs.lstatSync>;
          },
        });
        assert.throws(
          () => workspace.censusWorkspace(root, { rootGitPolicy: "absent" }),
          (error: WorkspaceError) => error.code === workspaceErrorCode("PRIVATE_ROOT_UNSAFE"),
        );
        assert.equal(lstatCalls, 0, "filesystem work began before effective-UID admission");
      } finally {
        Object.defineProperty(process, "geteuid", geteuidDescriptor);
        Object.defineProperty(fs, "lstatSync", lstatDescriptor);
        removeFixturePath(root);
      }
    });
  }
});

test("raw private-file and split-index I/O failures use stable workspace taxonomy", async (t) => {
  await t.test("private terminal lstat EIO", () => {
    const directory = privateTemp("noa-kws-private-file-eio-");
    const terminal = {
      candidateManifestSha256: "6".repeat(64),
      protocol: workspace.KNOCKOUT_WORKSPACE_PROTOCOLS.terminal,
      status: "PASS",
    };
    const published = publishTerminalEvidence({ directory, terminal });
    const descriptor = Object.getOwnPropertyDescriptor(fs, "lstatSync");
    assert.ok(descriptor !== undefined);
    const original = fs.lstatSync;
    try {
      Object.defineProperty(fs, "lstatSync", {
        ...descriptor,
        value: (...args: Parameters<typeof fs.lstatSync>) => {
          if (args[0] === published.path) {
            throw Object.assign(new Error("simulated private-file lstat EIO"), { code: "EIO" });
          }
          return Reflect.apply(original, fs, args) as ReturnType<typeof fs.lstatSync>;
        },
      });
      assert.throws(
        () => workspace.reopenTerminalEvidence({
          allowedTerminalStatuses: TEST_TERMINAL_STATUSES,
          expectedCandidateManifestSha256: terminal.candidateManifestSha256,
          expectedDirectoryIdentity: published.directoryIdentity,
          expectedObservation: published.createdObservation,
          expectedSha256: published.sha256,
          terminalPath: published.path,
        }),
        (error: WorkspaceError) => error.code === workspaceErrorCode("PRIVATE_ROOT_UNSAFE"),
      );
    } finally {
      Object.defineProperty(fs, "lstatSync", descriptor);
      removeFixturePath(directory);
    }
  });

  for (const failurePoint of ["open", "read", "close"] as const) {
    await t.test(`split-index directory ${failurePoint} EIO`, () => {
      const fixture = splitIndexFixture(`split-enumeration-${failurePoint}`);
      const indexDirectory = fs.realpathSync(path.dirname(fixture.indexPath));
      const descriptor = Object.getOwnPropertyDescriptor(fs, "opendirSync");
      assert.ok(descriptor !== undefined);
      const original = fs.opendirSync;
      try {
        Object.defineProperty(fs, "opendirSync", {
          ...descriptor,
          value: (...args: Parameters<typeof fs.opendirSync>) => {
            if (path.resolve(String(args[0])) !== indexDirectory) {
              return Reflect.apply(original, fs, args) as ReturnType<typeof fs.opendirSync>;
            }
            if (failurePoint === "open") {
              throw Object.assign(new Error("simulated split-index opendir EIO"), { code: "EIO" });
            }
            const directory = Reflect.apply(original, fs, args) as fs.Dir;
            return new Proxy(directory, {
              get(target, property, receiver) {
                if (property === "readSync" && failurePoint === "read") {
                  return () => {
                    throw Object.assign(new Error("simulated split-index read EIO"), { code: "EIO" });
                  };
                }
                if (property === "closeSync" && failurePoint === "close") {
                  return () => {
                    target.closeSync();
                    throw Object.assign(new Error("simulated split-index close EIO"), { code: "EIO" });
                  };
                }
                const value = Reflect.get(target, property, receiver) as unknown;
                return typeof value === "function"
                  ? (value as (...values: unknown[]) => unknown).bind(target)
                  : value;
              },
            });
          },
        });
        assert.throws(
          () => workspace.captureAndSealCandidate({
            custodyRoot: fixture.custody,
            sourceRoot: fixture.source,
          }),
          (error: WorkspaceError) =>
            error.code === workspaceErrorCode("SOURCE_GIT_LAYOUT_UNSUPPORTED"),
        );
      } finally {
        Object.defineProperty(fs, "opendirSync", descriptor);
        removeFixturePath(fixture.source);
        removeFixturePath(fixture.custody);
        removeFixturePath(fixture.tools);
      }
    });
  }
});

test("capture fails closed when the seed changes in any sealing window", async (t) => {
  const cases = [
    {
      expectedCode: workspaceErrorCode("PRIVATE_ROOT_UNSAFE"),
      expectManifest: false,
      label: "after worktree copy",
      window: "afterWorktreeCopy",
    },
    {
      expectedCode: workspaceErrorCode("MANIFEST_MISMATCH"),
      expectManifest: true,
      label: "after pre-seal observation",
      window: "afterPreSealObservation",
    },
    {
      expectedCode: workspaceErrorCode("MANIFEST_MISMATCH"),
      expectManifest: true,
      label: "after manifest publication",
      window: "afterManifestPublication",
    },
  ] as const;

  for (const fixtureCase of cases) {
    await t.test(fixtureCase.label, () => {
      const fixture = minimalCaptureFixture(fixtureCase.window);
      const attempts: number[] = [];
      let evidenceRoot: string | null = null;
      let refusal: WorkspaceError | null = null;
      const mutate = (value: { attempt: number; evidenceRoot: string; workspaceRoot: string }) => {
        attempts.push(value.attempt);
        evidenceRoot = value.evidenceRoot;
        fs.writeFileSync(
          path.join(value.workspaceRoot, `intruder-${fixtureCase.window}.txt`),
          "must never be sealed\n",
          { flag: "wx", mode: 0o600 },
        );
      };
      try {
        assert.throws(
          () => workspace.captureAndSealCandidate({
            sourceRoot: fixture.source,
            custodyRoot: fixture.custody,
            hooks: {
              afterManifestPublication(value) {
                if (fixtureCase.window === "afterManifestPublication") mutate(value);
              },
              afterPreSealObservation(value) {
                if (fixtureCase.window === "afterPreSealObservation") mutate(value);
              },
              afterWorktreeCopy(value) {
                if (fixtureCase.window === "afterWorktreeCopy") mutate(value);
              },
            },
          }),
          (error: WorkspaceError) => {
            refusal = error;
            return error.code === fixtureCase.expectedCode;
          },
        );
        assert.deepEqual(attempts, [1]);
        const evidence = requiredString(evidenceRoot, "mutation hook did not receive evidence root");
        assert.equal(
          pathExistsNoFollow(path.join(evidence, "candidate-manifest.json")),
          fixtureCase.expectManifest,
        );
        assert.equal(pathExistsNoFollow(path.join(evidence, "state.json")), false);
        assert.equal(fs.readFileSync(fixture.trackedPath, "utf8"), "stable source bytes\n");
      } finally {
        cleanupReportedScratchRoots(errorPrivateRoots(refusal));
        removeFixturePath(fixture.source);
        removeFixturePath(fixture.custody);
      }
    });
  }
});

test("a replacement root Git link is refused before Git initialization touches its target", () => {
  const fixture = minimalCaptureFixture("pre-init-root-git");
  const external = privateTemp("noa-kws-pre-init-root-git-target-");
  const marker = path.join(external, "marker.txt");
  fs.writeFileSync(marker, "external bytes stay unchanged\n", { mode: 0o600 });
  const markerBefore = pathStableObservation(marker);
  const bytesBefore = fs.readFileSync(marker);
  let evidenceRoot: string | null = null;
  let refusal: WorkspaceError | null = null;
  try {
    assert.throws(
      () => workspace.captureAndSealCandidate({
        custodyRoot: fixture.custody,
        hooks: {
          afterWorktreeCopy(value) {
            evidenceRoot = value.evidenceRoot;
            const gitRoot = path.join(value.workspaceRoot, ".git");
            fs.renameSync(gitRoot, `${gitRoot}.held`);
            fs.symlinkSync(external, gitRoot, "dir");
          },
        },
        maxAttempts: 1,
        sourceRoot: fixture.source,
      }),
      (error: WorkspaceError) => {
        refusal = error;
        return error.code === workspaceErrorCode("PRIVATE_ROOT_UNSAFE");
      },
    );
    assert.deepEqual(pathStableObservation(marker), markerBefore);
    assert.deepEqual(fs.readFileSync(marker), bytesBefore);
    const evidence = requiredString(evidenceRoot, "copy hook did not receive evidence root");
    assert.equal(pathExistsNoFollow(path.join(evidence, "candidate-manifest.json")), false);
    assert.equal(pathExistsNoFollow(path.join(evidence, "state.json")), false);
  } finally {
    cleanupReportedScratchRoots(errorPrivateRoots(refusal));
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
    removeFixturePath(external);
  }
});

test("a pre-initialization root Git entry is refused before Git can consume it", () => {
  const fixture = minimalCaptureFixture("pre-init-root-git-entry");
  let evidenceRoot: string | null = null;
  let refusal: WorkspaceError | null = null;
  try {
    assert.throws(
      () => workspace.captureAndSealCandidate({
        custodyRoot: fixture.custody,
        hooks: {
          afterWorktreeCopy(value) {
            evidenceRoot = value.evidenceRoot;
            fs.writeFileSync(
              path.join(value.workspaceRoot, ".git", "config"),
              "[core]\n\tbare = true\n",
              { flag: "wx", mode: 0o600 },
            );
          },
        },
        maxAttempts: 1,
        sourceRoot: fixture.source,
      }),
      (error: WorkspaceError) => {
        refusal = error;
        return error.code === workspaceErrorCode("PRIVATE_ROOT_UNSAFE");
      },
    );
    const evidence = requiredString(evidenceRoot, "copy hook did not receive evidence root");
    assert.equal(pathExistsNoFollow(path.join(evidence, "candidate-manifest.json")), false);
    assert.equal(pathExistsNoFollow(path.join(evidence, "state.json")), false);
  } finally {
    cleanupReportedScratchRoots(errorPrivateRoots(refusal));
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
  }
});

test("capture refuses non-private copied file and directory modes before evidence publication", async (t) => {
  const cases = [
    {
      label: "regular file mode 0644",
      mutate(workspaceRoot: string) {
        fs.chmodSync(path.join(workspaceRoot, "tracked.txt"), 0o644);
      },
    },
    {
      label: "nested directory mode 0755",
      mutate(workspaceRoot: string) {
        fs.chmodSync(path.join(workspaceRoot, "nested"), 0o755);
      },
    },
  ];
  for (const fixtureCase of cases) {
    await t.test(fixtureCase.label, () => {
      const fixture = minimalCaptureFixture(fixtureCase.label.replaceAll(" ", "-"));
      const attempts: number[] = [];
      let evidenceRoot: string | null = null;
      let refusal: WorkspaceError | null = null;
      try {
        assert.throws(
          () => workspace.captureAndSealCandidate({
            sourceRoot: fixture.source,
            custodyRoot: fixture.custody,
            hooks: {
              afterWorktreeCopy(value) {
                attempts.push(value.attempt);
                evidenceRoot = value.evidenceRoot;
                fixtureCase.mutate(value.workspaceRoot);
              },
            },
          }),
          (error: WorkspaceError) => {
            refusal = error;
            return error.code === workspaceErrorCode("PRIVATE_ROOT_UNSAFE");
          },
        );
        assert.deepEqual(attempts, [1]);
        const evidence = requiredString(evidenceRoot, "mode hook did not receive evidence root");
        assert.equal(pathExistsNoFollow(path.join(evidence, "candidate-manifest.json")), false);
        assert.equal(pathExistsNoFollow(path.join(evidence, "state.json")), false);
      } finally {
        cleanupReportedScratchRoots(errorPrivateRoots(refusal));
        removeFixturePath(fixture.source);
        removeFixturePath(fixture.custody);
      }
    });
  }
});

test("capture revalidates the complete evidence pair after every publication boundary", async (t) => {
  for (const mutation of ["remove", "replace"] as const) {
    await t.test(`manifest ${mutation} after publication`, () => {
      const fixture = minimalCaptureFixture(`manifest-${mutation}`);
      const attempts: number[] = [];
      let evidenceRoot: string | null = null;
      let manifestPath: string | null = null;
      let retainedManifest: string | null = null;
      let refusal: WorkspaceError | null = null;
      try {
        assert.throws(
          () => workspace.captureAndSealCandidate({
            sourceRoot: fixture.source,
            custodyRoot: fixture.custody,
            hooks: {
              afterManifestPublication(value) {
                attempts.push(value.attempt);
                evidenceRoot = value.evidenceRoot;
                manifestPath = value.manifestPath;
                if (mutation === "remove") {
                  fs.unlinkSync(value.manifestPath);
                  return;
                }
                const bytes = fs.readFileSync(value.manifestPath);
                retainedManifest = `${value.manifestPath}.created-inode.retained`;
                fs.renameSync(value.manifestPath, retainedManifest);
                fs.writeFileSync(value.manifestPath, bytes, { flag: "wx", mode: 0o600 });
              },
            },
          }),
          (error: WorkspaceError) => {
            refusal = error;
            return error.code === workspaceErrorCode("MANIFEST_MISMATCH");
          },
        );
        assert.deepEqual(attempts, [1]);
        const evidence = requiredString(evidenceRoot, "manifest hook did not receive evidence root");
        const manifest = requiredString(manifestPath, "manifest hook did not receive manifest path");
        assert.equal(pathExistsNoFollow(manifest), mutation === "replace");
        if (mutation === "replace") {
          const retained = requiredString(retainedManifest, "manifest inode was not retained");
          assert.deepEqual(fs.readFileSync(manifest), fs.readFileSync(retained));
          assert.notEqual(
            `${fs.lstatSync(manifest, { bigint: true }).dev}:${fs.lstatSync(manifest, { bigint: true }).ino}`,
            `${fs.lstatSync(retained, { bigint: true }).dev}:${fs.lstatSync(retained, { bigint: true }).ino}`,
          );
        }
        assert.equal(pathExistsNoFollow(path.join(evidence, "state.json")), false);
      } finally {
        cleanupReportedScratchRoots(errorPrivateRoots(refusal));
        removeFixturePath(fixture.source);
        removeFixturePath(fixture.custody);
      }
    });
  }

  await t.test("evidence directory replacement after manifest publication", () => {
    const fixture = minimalCaptureFixture("evidence-swap-after-manifest");
    const attempts: number[] = [];
    let evidenceRoot: string | null = null;
    let movedEvidence: string | null = null;
    let refusal: WorkspaceError | null = null;
    try {
      assert.throws(
        () => workspace.captureAndSealCandidate({
          sourceRoot: fixture.source,
          custodyRoot: fixture.custody,
          hooks: {
            afterManifestPublication(value) {
              attempts.push(value.attempt);
              evidenceRoot = value.evidenceRoot;
              movedEvidence = `${value.evidenceRoot}.created-directory.retained`;
              fs.renameSync(value.evidenceRoot, movedEvidence);
              fs.mkdirSync(value.evidenceRoot, { mode: 0o700 });
            },
          },
        }),
        (error: WorkspaceError) => {
          refusal = error;
          return error.code === workspaceErrorCode("PRIVATE_ROOT_UNSAFE");
        },
      );
      assert.deepEqual(attempts, [1]);
      const replacement = requiredString(evidenceRoot, "evidence hook did not receive its root");
      const retained = requiredString(movedEvidence, "evidence directory was not retained");
      assert.equal(pathExistsNoFollow(path.join(retained, "candidate-manifest.json")), true);
      assert.equal(pathExistsNoFollow(path.join(retained, "state.json")), false);
      assert.deepEqual(fs.readdirSync(replacement), []);
    } finally {
      cleanupReportedScratchRoots(errorPrivateRoots(refusal));
      removeFixturePath(fixture.source);
      removeFixturePath(fixture.custody);
    }
  });

  await t.test("workspace mutation immediately before state publication never creates SEALED state", () => {
    const fixture = minimalCaptureFixture("workspace-mutation-before-state");
    const attempts: number[] = [];
    let evidenceRoot: string | null = null;
    let workspaceRoot: string | null = null;
    let refusal: WorkspaceError | null = null;
    try {
      assert.throws(
        () => workspace.captureAndSealCandidate({
          sourceRoot: fixture.source,
          custodyRoot: fixture.custody,
          hooks: {
            beforeStatePublication(value) {
              attempts.push(value.attempt);
              evidenceRoot = value.evidenceRoot;
              workspaceRoot = value.workspaceRoot;
              assert.equal(pathExistsNoFollow(value.statePath), false);
              fs.writeFileSync(
                path.join(value.workspaceRoot, "pre-state-intruder.txt"),
                "must invalidate the state\n",
                { flag: "wx", mode: 0o600 },
              );
            },
          },
        }),
        (error: WorkspaceError) => {
          refusal = error;
          return error.code === workspaceErrorCode("MANIFEST_MISMATCH");
        },
      );
      assert.deepEqual(attempts, [1]);
      const evidence = requiredString(evidenceRoot, "pre-state hook did not receive evidence root");
      const seed = requiredString(workspaceRoot, "pre-state hook did not receive workspace root");
      const manifest = JSON.parse(
        fs.readFileSync(path.join(evidence, "candidate-manifest.json"), "utf8"),
      ) as { candidateManifestSha256: string };
      assert.equal(pathExistsNoFollow(path.join(evidence, "state.json")), false);
      assert.throws(
        () => workspace.verifySealedSeed({
          workspaceRoot: seed,
          manifest,
          candidateManifestSha256: manifest.candidateManifestSha256,
        } as unknown as Capture),
        (error: WorkspaceError) => error.code === workspaceErrorCode("INVALID_ARGUMENT"),
      );
    } finally {
      cleanupReportedScratchRoots(errorPrivateRoots(refusal));
      removeFixturePath(fixture.source);
      removeFixturePath(fixture.custody);
    }
  });

  await t.test("manifest same-content inode replacement before state commit cannot create SEALED state", () => {
    const fixture = minimalCaptureFixture("manifest-replacement-before-state");
    const attempts: number[] = [];
    let evidenceRoot: string | null = null;
    let manifestPath: string | null = null;
    let retainedManifest: string | null = null;
    let refusal: WorkspaceError | null = null;
    try {
      assert.throws(
        () => workspace.captureAndSealCandidate({
          sourceRoot: fixture.source,
          custodyRoot: fixture.custody,
          hooks: {
            beforeStatePublication(value) {
              attempts.push(value.attempt);
              evidenceRoot = value.evidenceRoot;
              assert.equal(pathExistsNoFollow(value.statePath), false);
              manifestPath = path.join(value.evidenceRoot, "candidate-manifest.json");
              const bytes = fs.readFileSync(manifestPath);
              retainedManifest = `${manifestPath}.created-inode.retained`;
              fs.renameSync(manifestPath, retainedManifest);
              fs.writeFileSync(manifestPath, bytes, { flag: "wx", mode: 0o600 });
            },
          },
        }),
        (error: WorkspaceError) => {
          refusal = error;
          return error.code === workspaceErrorCode("MANIFEST_MISMATCH");
        },
      );
      assert.deepEqual(attempts, [1]);
      const evidence = requiredString(evidenceRoot, "pre-state hook did not receive evidence root");
      const replacement = requiredString(manifestPath, "manifest path was not recorded");
      const retained = requiredString(retainedManifest, "manifest inode was not retained");
      assert.equal(pathExistsNoFollow(path.join(evidence, "candidate-manifest.json")), true);
      assert.equal(pathExistsNoFollow(path.join(evidence, "state.json")), false);
      assert.deepEqual(fs.readFileSync(replacement), fs.readFileSync(retained));
      assert.notEqual(
        `${fs.lstatSync(replacement, { bigint: true }).dev}:${fs.lstatSync(replacement, { bigint: true }).ino}`,
        `${fs.lstatSync(retained, { bigint: true }).dev}:${fs.lstatSync(retained, { bigint: true }).ino}`,
      );
    } finally {
      cleanupReportedScratchRoots(errorPrivateRoots(refusal));
      removeFixturePath(fixture.source);
      removeFixturePath(fixture.custody);
    }
  });

  await t.test("evidence directory replacement before state publication cannot create SEALED state", () => {
    const fixture = minimalCaptureFixture("evidence-swap-before-state");
    const attempts: number[] = [];
    let evidenceRoot: string | null = null;
    let movedEvidence: string | null = null;
    let refusal: WorkspaceError | null = null;
    try {
      assert.throws(
        () => workspace.captureAndSealCandidate({
          sourceRoot: fixture.source,
          custodyRoot: fixture.custody,
          hooks: {
            beforeStatePublication(value) {
              attempts.push(value.attempt);
              evidenceRoot = value.evidenceRoot;
              assert.equal(pathExistsNoFollow(value.statePath), false);
              movedEvidence = `${value.evidenceRoot}.created-directory.retained`;
              fs.renameSync(value.evidenceRoot, movedEvidence);
              fs.mkdirSync(value.evidenceRoot, { mode: 0o700 });
            },
          },
        }),
        (error: WorkspaceError) => {
          refusal = error;
          return error.code === workspaceErrorCode("PRIVATE_ROOT_UNSAFE");
        },
      );
      assert.deepEqual(attempts, [1]);
      const replacement = requiredString(evidenceRoot, "pre-state hook did not receive evidence root");
      const retained = requiredString(movedEvidence, "evidence directory was not retained");
      assert.equal(pathExistsNoFollow(path.join(retained, "candidate-manifest.json")), true);
      assert.equal(pathExistsNoFollow(path.join(retained, "state.json")), false);
      assert.deepEqual(fs.readdirSync(replacement), []);
    } finally {
      cleanupReportedScratchRoots(errorPrivateRoots(refusal));
      removeFixturePath(fixture.source);
      removeFixturePath(fixture.custody);
    }
  });
});

test("consumer seed verification requires a trusted digest and rejects every material mutation", async (t) => {
  const cases: Array<{
    expectedCode: string;
    label: string;
    mutate: (captured: Capture) => void;
  }> = [
    {
      expectedCode: workspaceErrorCode("MANIFEST_MISMATCH"),
      label: "added file",
      mutate(captured) {
        fs.writeFileSync(
          path.join(captured.workspaceRoot, "added-after-seal.txt"),
          "added\n",
          { flag: "wx", mode: 0o600 },
        );
      },
    },
    {
      expectedCode: workspaceErrorCode("MANIFEST_MISMATCH"),
      label: "same-content new inode",
      mutate(captured) {
        const target = path.join(captured.workspaceRoot, "tracked.txt");
        const retained = `${captured.workspaceRoot}.tracked-created-inode.retained`;
        const bytes = fs.readFileSync(target);
        fs.renameSync(target, retained);
        fs.writeFileSync(target, bytes, { flag: "wx", mode: 0o600 });
      },
    },
    {
      expectedCode: workspaceErrorCode("MANIFEST_MISMATCH"),
      label: "mtime change",
      mutate(captured) {
        const target = path.join(captured.workspaceRoot, "tracked.txt");
        const stat = fs.statSync(target);
        fs.utimesSync(target, stat.atime, new Date(stat.mtimeMs + 5_000));
      },
    },
    {
      expectedCode: workspaceErrorCode("MANIFEST_MISMATCH"),
      label: "file mode change",
      mutate(captured) {
        fs.chmodSync(path.join(captured.workspaceRoot, "nested", "child.txt"), 0o644);
      },
    },
    {
      expectedCode: workspaceErrorCode("MANIFEST_MISMATCH"),
      label: "standalone Git index byte change",
      mutate(captured) {
        const indexPath = path.join(captured.workspaceRoot, ".git", "index");
        const bytes = fs.readFileSync(indexPath);
        assert.ok(bytes.length > 0);
        bytes[0] = (bytes[0] ?? 0) ^ 0x01;
        fs.writeFileSync(indexPath, bytes);
      },
    },
    {
      expectedCode: workspaceErrorCode("MANIFEST_MISMATCH"),
      label: "standalone Git status config change",
      mutate(captured) {
        fs.appendFileSync(
          path.join(captured.workspaceRoot, ".git", "config"),
          "\n[core]\n\tfilemode = true\n",
        );
      },
    },
    {
      expectedCode: workspaceErrorCode("MANIFEST_MISMATCH"),
      label: "removed trailing file",
      mutate(captured) {
        fs.unlinkSync(path.join(captured.workspaceRoot, "tracked.txt"));
      },
    },
    {
      expectedCode: workspaceErrorCode("PRIVATE_ROOT_UNSAFE"),
      label: "workspace root mode 0755",
      mutate(captured) {
        fs.chmodSync(captured.workspaceRoot, 0o755);
      },
    },
  ];

  for (const fixtureCase of cases) {
    await t.test(fixtureCase.label, () => {
      const fixture = minimalCaptureFixture(`consumer-${fixtureCase.label.replaceAll(" ", "-")}`);
      let captured: Capture | null = null;
      try {
        captured = workspace.captureAndSealCandidate({
          sourceRoot: fixture.source,
          custodyRoot: fixture.custody,
        });
        fixtureCase.mutate(captured);
        assert.throws(
          () => workspace.verifySealedSeed(captured!),
          (error: WorkspaceError) => error.code === fixtureCase.expectedCode,
        );
      } finally {
        cleanupReportedScratchRoots(captured?.retainedPrivateRoots ?? []);
        removeFixturePath(fixture.source);
        removeFixturePath(fixture.custody);
      }
    });
  }

  await t.test("shorter census reports the absent node through the stable taxonomy", () => {
    const fixture = minimalCaptureFixture("consumer-shorter-census");
    const descriptor = Object.getOwnPropertyDescriptor(fs, "opendirSync");
    assert.ok(descriptor !== undefined);
    const originalOpendir = fs.opendirSync;
    let captured: Capture | null = null;
    let hidden = 0;
    try {
      captured = workspace.captureAndSealCandidate({
        sourceRoot: fixture.source,
        custodyRoot: fixture.custody,
      });
      const workspaceRoot = fs.realpathSync(captured.workspaceRoot);
      Object.defineProperty(fs, "opendirSync", {
        ...descriptor,
        value: ((...args: Parameters<typeof fs.opendirSync>) => {
          const directory = Reflect.apply(originalOpendir, fs, args) as fs.Dir;
          if (
            hidden !== 0 || typeof args[0] !== "string" ||
            path.resolve(args[0]) !== workspaceRoot
          ) return directory;
          return new Proxy(directory, {
            get(target, property) {
              if (property === "readSync") {
                return () => {
                  for (;;) {
                    const entry = target.readSync();
                    if (entry === null) return null;
                    const name = Buffer.isBuffer(entry.name)
                      ? entry.name.toString("utf8")
                      : entry.name;
                    if (name === "tracked.txt") {
                      hidden += 1;
                      continue;
                    }
                    return entry;
                  }
                };
              }
              const value = Reflect.get(target, property, target) as unknown;
              return typeof value === "function"
                ? (value as (...values: unknown[]) => unknown).bind(target)
                : value;
            },
          });
        }) as typeof fs.opendirSync,
      });
      assert.throws(
        () => workspace.verifySealedSeed(captured!),
        (error: WorkspaceError) =>
          error.code === workspaceErrorCode("MANIFEST_MISMATCH") &&
          error.details?.changedNode?.before?.path === "tracked.txt" &&
          error.details.changedNode.after === null,
      );
      assert.equal(hidden, 1, "the shorter-census path was not exercised");
    } finally {
      Object.defineProperty(fs, "opendirSync", descriptor);
      cleanupReportedScratchRoots(captured?.retainedPrivateRoots ?? []);
      removeFixturePath(fixture.source);
      removeFixturePath(fixture.custody);
    }
  });

  await t.test("self-consistent untrusted capture-shaped input cannot replace the capability", () => {
    const fixture = minimalCaptureFixture("consumer-trust-anchor");
    let captured: Capture | null = null;
    try {
      captured = workspace.captureAndSealCandidate({
        sourceRoot: fixture.source,
        custodyRoot: fixture.custody,
      });
      const tampered = JSON.parse(JSON.stringify(captured.manifest)) as Capture["manifest"];
      tampered.seed.includesStandaloneGit = false;
      tampered.candidateManifestSha256 = workspace.candidateManifestSha256(tampered);
      assert.notEqual(tampered.candidateManifestSha256, captured.candidateManifestSha256);
      const forged = Object.freeze({
        ...captured,
        candidateManifestSha256: tampered.candidateManifestSha256,
        manifest: tampered,
      }) as Capture;
      assert.throws(
        () => workspace.verifySealedSeed(forged),
        (error: WorkspaceError) => error.code === workspaceErrorCode("INVALID_ARGUMENT"),
      );
      assert.throws(
        () => workspace.verifySealedSeed(Object.freeze({ ...captured }) as Capture),
        (error: WorkspaceError) => error.code === workspaceErrorCode("INVALID_ARGUMENT"),
      );
      assert.equal(
        workspace.verifySealedSeed(captured).observationSha256,
        captured.workspaceObservation.observationSha256,
      );
    } finally {
      cleanupReportedScratchRoots(captured?.retainedPrivateRoots ?? []);
      removeFixturePath(fixture.source);
      removeFixturePath(fixture.custody);
    }
  });
});

test("pre-terminal-commit seed instability is never retried or recorded as SEALED", () => {
  const fixture = minimalCaptureFixture("pre-terminal-commit-instability");
  const openDescriptor = Object.getOwnPropertyDescriptor(fs, "openSync");
  const readDescriptor = Object.getOwnPropertyDescriptor(fs, "readSync");
  assert.ok(openDescriptor !== undefined);
  assert.ok(readDescriptor !== undefined);
  const originalOpen = fs.openSync;
  const originalRead = fs.readSync;
  const attempts: number[] = [];
  let armed = false;
  let evidenceRoot: string | null = null;
  let mutated = false;
  let targetFd: number | null = null;
  let targetPath: string | null = null;
  let refusal: WorkspaceError | null = null;
  try {
    Object.defineProperty(fs, "openSync", {
      ...openDescriptor,
      value: (...args: Parameters<typeof fs.openSync>) => {
        const fd = Reflect.apply(originalOpen, fs, args) as number;
        const flags = typeof args[1] === "number" ? args[1] : 0;
        if (
          armed && targetFd === null && args[0] === targetPath &&
          (flags & (fs.constants.O_WRONLY | fs.constants.O_RDWR)) === 0
        ) targetFd = fd;
        return fd;
      },
    });
    Object.defineProperty(fs, "readSync", {
      ...readDescriptor,
      value: (...args: Parameters<typeof fs.readSync>) => {
        const read = Reflect.apply(originalRead, fs, args) as number;
        if (!mutated && args[0] === targetFd) {
          mutated = true;
          fs.appendFileSync(requiredString(targetPath, "target path was not armed"), "race\n");
        }
        return read;
      },
    });
    assert.throws(
      () => workspace.captureAndSealCandidate({
        sourceRoot: fixture.source,
        custodyRoot: fixture.custody,
        hooks: {
          beforeStatePublication(value) {
            attempts.push(value.attempt);
            evidenceRoot = value.evidenceRoot;
            assert.equal(pathExistsNoFollow(value.statePath), false);
            targetPath = path.join(value.workspaceRoot, "tracked.txt");
            armed = true;
          },
        },
      }),
      (error: WorkspaceError) => {
        refusal = error;
        return error.code === workspaceErrorCode("SNAPSHOT_UNSTABLE");
      },
    );
    assert.equal(mutated, true);
    assert.deepEqual(attempts, [1]);
    const evidence = requiredString(evidenceRoot, "pre-state hook did not receive evidence root");
    assert.equal(pathExistsNoFollow(path.join(evidence, "candidate-manifest.json")), true);
    assert.equal(pathExistsNoFollow(path.join(evidence, "state.json")), false);
  } finally {
    Object.defineProperty(fs, "openSync", openDescriptor);
    Object.defineProperty(fs, "readSync", readDescriptor);
    cleanupReportedScratchRoots(errorPrivateRoots(refusal));
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
  }
});

function countCaptureStateCloses(prefix: string): number {
  // Calibration: how many descriptors opened on state.json a clean capture closes. The last of
  // them is closed after every producer-side witness, so a mutation at that close lands after the
  // final witness and before the capability is returned.
  const fixture = minimalCaptureFixture(prefix);
  const openDescriptor = Object.getOwnPropertyDescriptor(fs, "openSync");
  const closeDescriptor = Object.getOwnPropertyDescriptor(fs, "closeSync");
  assert.ok(openDescriptor !== undefined);
  assert.ok(closeDescriptor !== undefined);
  const originalOpen = fs.openSync;
  const originalClose = fs.closeSync;
  const stateFds = new Set<number>();
  let statePath: string | null = null;
  let closes = 0;
  let captured: Capture | null = null;
  try {
    Object.defineProperty(fs, "openSync", {
      ...openDescriptor,
      value: (...args: Parameters<typeof fs.openSync>) => {
        const fd = Reflect.apply(originalOpen, fs, args) as number;
        if (statePath !== null && args[0] === statePath) stateFds.add(fd);
        return fd;
      },
    });
    Object.defineProperty(fs, "closeSync", {
      ...closeDescriptor,
      value: (...args: Parameters<typeof fs.closeSync>) => {
        if (stateFds.has(args[0])) {
          stateFds.delete(args[0]);
          closes += 1;
        }
        return Reflect.apply(originalClose, fs, args) as ReturnType<typeof fs.closeSync>;
      },
    });
    captured = workspace.captureAndSealCandidate({
      custodyRoot: fixture.custody,
      hooks: { beforeStatePublication(value) { statePath = value.statePath; } },
      maxAttempts: 1,
      sourceRoot: fixture.source,
    });
  } finally {
    Object.defineProperty(fs, "openSync", openDescriptor);
    Object.defineProperty(fs, "closeSync", closeDescriptor);
    cleanupReportedScratchRoots(reportedPrivateRoots(captured));
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
  }
  assert.ok(closes >= 2, "calibration capture did not reopen its state file");
  return closes;
}

test("terminal SEALED commit is witnessed against the verified seed in its exact late window", async (t) => {
  // The window under attack starts after the final seed verification (and after every existing
  // beforeStatePublication regression has already run) and ends when the capability is
  // registered. Three attacks land inside it; the fourth lands after the last producer-side
  // witness and pins the honest boundary: a mutation after the last witness is caught by
  // consumer verification, exactly like a mutation after the capability is returned.
  const openDescriptor = Object.getOwnPropertyDescriptor(fs, "openSync");
  const fchmodDescriptor = Object.getOwnPropertyDescriptor(fs, "fchmodSync");
  const closeDescriptor = Object.getOwnPropertyDescriptor(fs, "closeSync");
  assert.ok(openDescriptor !== undefined);
  assert.ok(fchmodDescriptor !== undefined);
  assert.ok(closeDescriptor !== undefined);
  const originalOpen = fs.openSync;
  const originalFchmod = fs.fchmodSync;
  const originalClose = fs.closeSync;
  const stateCloseTarget = countCaptureStateCloses("late-window-calibration");
  const cases = [
    {
      expectedPhase: "PREPARED_DURABLE",
      label: "content mutation before the state inode exists",
      mutation: "content",
      window: "before-state-inode",
    },
    {
      expectedPhase: "COMMIT_REVOKED",
      label: "content mutation at the commit transition",
      mutation: "content",
      window: "at-commit-transition",
    },
    {
      expectedPhase: "COMMIT_REVOKED",
      label: "workspace root replacement at the commit transition",
      mutation: "root-replacement",
      window: "at-commit-transition",
    },
    {
      expectedPhase: null,
      label: "content mutation after the last producer witness is caught by consumer verification",
      mutation: "content",
      window: "after-post-commit-witness",
    },
  ] as const;

  for (const fixtureCase of cases) {
    await t.test(fixtureCase.label, () => {
      const fixture = minimalCaptureFixture(
        `late-window-${fixtureCase.window}-${fixtureCase.mutation}`,
      );
      const stateFds = new Set<number>();
      let stateCloses = 0;
      let statePath: string | null = null;
      let workspaceRoot: string | null = null;
      let stateFd: number | null = null;
      let mutated = false;
      let retainedWorkspace: string | null = null;
      let captured: Capture | null = null;
      let refusal: WorkspaceError | null = null;
      const mutate = () => {
        if (mutated) return;
        mutated = true;
        const root = requiredString(workspaceRoot, "pre-state hook did not receive workspace root");
        if (fixtureCase.mutation === "content") {
          fs.appendFileSync(path.join(root, "tracked.txt"), "LATE-MUTATION\n");
          return;
        }
        retainedWorkspace = `${root}.verified-original.retained`;
        fs.renameSync(root, retainedWorkspace);
        fs.mkdirSync(root, { mode: 0o700 });
        fs.writeFileSync(path.join(root, "tracked.txt"), "REPLACEMENT-ROOT\n", { mode: 0o600 });
      };
      try {
        Object.defineProperty(fs, "openSync", {
          ...openDescriptor,
          value: (...args: Parameters<typeof fs.openSync>) => {
            const flags = typeof args[1] === "number" ? args[1] : 0;
            const createsState = statePath !== null && args[0] === statePath &&
              (flags & fs.constants.O_CREAT) !== 0;
            if (createsState && fixtureCase.window === "before-state-inode") mutate();
            const fd = Reflect.apply(originalOpen, fs, args) as number;
            if (statePath !== null && args[0] === statePath) stateFds.add(fd);
            if (createsState && stateFd === null) stateFd = fd;
            return fd;
          },
        });
        Object.defineProperty(fs, "fchmodSync", {
          ...fchmodDescriptor,
          value: (...args: Parameters<typeof fs.fchmodSync>) => {
            if (
              stateFd !== null && args[0] === stateFd && args[1] === 0o600 &&
              fixtureCase.window === "at-commit-transition"
            ) mutate();
            return Reflect.apply(originalFchmod, fs, args) as ReturnType<typeof fs.fchmodSync>;
          },
        });
        Object.defineProperty(fs, "closeSync", {
          ...closeDescriptor,
          value: (...args: Parameters<typeof fs.closeSync>) => {
            if (stateFds.has(args[0])) {
              stateFds.delete(args[0]);
              stateCloses += 1;
              if (
                fixtureCase.window === "after-post-commit-witness" &&
                stateCloses === stateCloseTarget
              ) mutate();
            }
            return Reflect.apply(originalClose, fs, args) as ReturnType<typeof fs.closeSync>;
          },
        });
        try {
          captured = workspace.captureAndSealCandidate({
            commandTimeoutMs: 60_000,
            custodyRoot: fixture.custody,
            hooks: {
              beforeStatePublication(value) {
                assert.equal(pathExistsNoFollow(value.statePath), false);
                statePath = value.statePath;
                workspaceRoot = value.workspaceRoot;
              },
            },
            maxAttempts: 1,
            operationTimeoutMs: 5 * 60_000,
            sourceRoot: fixture.source,
          });
        } catch (error) {
          refusal = error as WorkspaceError;
        }
      } finally {
        Object.defineProperty(fs, "openSync", openDescriptor);
        Object.defineProperty(fs, "fchmodSync", fchmodDescriptor);
        Object.defineProperty(fs, "closeSync", closeDescriptor);
      }
      try {
        assert.equal(mutated, true, "the late-window mutation was not reached");
        assert.notEqual(stateFd, null, "the state inode was never created");
        const state = requiredString(statePath, "pre-state hook did not receive the state path");
        const root = requiredString(workspaceRoot, "pre-state hook did not receive workspace root");
        assert.equal(fs.readFileSync(fixture.trackedPath, "utf8"), "stable source bytes\n");
        const manifestPath = path.join(path.dirname(state), "candidate-manifest.json");
        assert.equal(fs.lstatSync(manifestPath).mode & 0o777, 0o600);
        if (fixtureCase.expectedPhase === null) {
          const sealed = captured;
          assert.ok(sealed !== null, `post-witness mutation was refused: ${errorChain(refusal)}`);
          assert.equal(fs.lstatSync(state).mode & 0o777, 0o600);
          const stateJson = JSON.parse(fs.readFileSync(state, "utf8")) as {
            evidenceRole?: unknown; status?: unknown;
          };
          // Persisted state is capture evidence, never authority: it must not claim SEALED.
          assert.equal(stateJson.status, "CAPTURED");
          assert.equal(stateJson.evidenceRole, "NON_AUTHORITATIVE_CAPTURE_EVIDENCE");
          assert.equal(
            fs.readFileSync(path.join(root, "tracked.txt"), "utf8"),
            "stable source bytes\nLATE-MUTATION\n",
          );
          assert.throws(
            () => workspace.verifySealedSeed(sealed),
            (error: WorkspaceError) => error.code === workspaceErrorCode("MANIFEST_MISMATCH"),
          );
          return;
        }
        assert.equal(
          captured,
          null,
          "capture returned success for bytes mutated before the terminal commit witness",
        );
        assert.equal(refusal?.code, workspaceErrorCode("PRIVATE_ROOT_UNSAFE"), errorChain(refusal));
        const publication = errorTerminalPublication(refusal);
        assert.notEqual(publication, null, "refusal does not report the state publication residue");
        assert.equal(publication?.path, state);
        assert.equal(publication?.phase, fixtureCase.expectedPhase);
        assert.equal(publication?.currentMode, 0);
        const stateStat = fs.lstatSync(state);
        assert.equal(stateStat.isFile(), true);
        assert.equal(stateStat.mode & 0o777, 0, "a committed SEALED marker survived the refusal");
        if (fixtureCase.mutation === "content") {
          assert.equal(
            fs.readFileSync(path.join(root, "tracked.txt"), "utf8"),
            "stable source bytes\nLATE-MUTATION\n",
          );
        } else {
          const retained = requiredString(retainedWorkspace, "verified workspace was not retained");
          assert.equal(fs.readFileSync(path.join(root, "tracked.txt"), "utf8"), "REPLACEMENT-ROOT\n");
          assert.equal(
            fs.readFileSync(path.join(retained, "tracked.txt"), "utf8"),
            "stable source bytes\n",
          );
        }
      } finally {
        cleanupReportedScratchRoots(reportedPrivateRoots(captured));
        cleanupReportedScratchRoots(errorPrivateRoots(refusal));
        removeFixturePath(fixture.source);
        removeFixturePath(fixture.custody);
      }
    });
  }
});

test("capture binds one physical source-root identity into its snapshot, manifest, and capability", () => {
  const fixture = minimalCaptureFixture("source-root-identity-binding");
  const displaced = `${fixture.source}.displaced-original`;
  const reportedRoots: RetainedPrivateRoot[] = [];
  let captured: Capture | null = null;
  let refusal: WorkspaceError | null = null;
  try {
    captured = workspace.captureAndSealCandidate({
      custodyRoot: fixture.custody,
      sourceRoot: fixture.source,
    });
    reportedRoots.push(...captured.retainedPrivateRoots);
    const sourceStat = fs.lstatSync(fixture.source, { bigint: true });
    const identity = `${sourceStat.dev}:${sourceStat.ino}`;
    assert.equal(captured.sourceRootIdentity, identity);
    assert.equal(captured.sourceSnapshot.git.worktreeRootIdentity, identity);
    assert.equal(captured.sourceSnapshot.git.worktreeRoot, fs.realpathSync(fixture.source));
    assert.equal(captured.manifest.source.git?.worktreeRootIdentity, identity);
    assert.match(captured.manifest.source.git?.gitDirectoryIdentity ?? "", /^\d+:\d+$/);
    assert.match(captured.manifest.source.git?.commonDirectoryIdentity ?? "", /^\d+:\d+$/);
    const rootNode = captured.manifest.source.nodes.find((node) => node.path === ".");
    assert.equal(rootNode?.type, "directory");
    assert.equal(rootNode?.observation.identity, identity);
    assert.deepEqual(captured.manifest.source.git?.worktreeRootObservation, rootNode?.observation);
    const unchanged = workspace.verifySourceUnchanged(captured.sourceSnapshot);
    reportedRoots.push(...reportedPrivateRoots(unchanged));
    assert.equal(unchanged.snapshotSha256, captured.sourceSnapshot.snapshotSha256);
    assert.equal(unchanged.git.worktreeRootIdentity, identity);

    // Same pathname, same bytes, different physical root: refused by identity before any Git
    // command or census can be fooled by the look-alike.
    fs.renameSync(fixture.source, displaced);
    fs.cpSync(displaced, fixture.source, { preserveTimestamps: true, recursive: true });
    const snapshot = captured.sourceSnapshot;
    assert.throws(
      () => workspace.verifySourceUnchanged(snapshot),
      (error: WorkspaceError) => {
        refusal = error;
        return error.code === workspaceErrorCode("SOURCE_CHANGED") &&
          error.details?.expectedIdentity === identity &&
          typeof error.details?.pathIdentity === "string" &&
          error.details.pathIdentity !== identity;
      },
    );
  } finally {
    cleanupReportedScratchRoots(reportedRoots);
    cleanupReportedScratchRoots(errorPrivateRoots(refusal));
    removeFixturePath(fixture.source);
    removeFixturePath(displaced);
    removeFixturePath(fixture.custody);
  }
});

type AncestorAbaFixture = {
  custody: string;
  fixtureRoot: string;
  headA: string;
  headB: string;
  held: string;
  indexPath: string;
  live: string;
  sharedPath: string | null;
  source: string;
};

/**
 * Two complete Git topologies, A below `live/` and B below `held/`, with identical trees,
 * worktrees, indexes and status but distinct HEADs. B's extra commit object is copied into A's
 * object store so that any genuine Git validation of a B HEAD can complete. Swapping the `live`
 * and `held` ancestors makes the very same source pathname resolve to the other topology.
 */
function ancestorAbaFixture(
  prefix: string,
  topology: "direct" | "linked",
  splitIndex: boolean,
): AncestorAbaFixture {
  const fixtureRoot = privateTemp(`noa-kws-${prefix}-`);
  const live = path.join(fixtureRoot, "live");
  const held = path.join(fixtureRoot, "held");
  const custody = path.join(fixtureRoot, "custody");
  fs.mkdirSync(live, { mode: 0o700 });
  fs.mkdirSync(custody, { mode: 0o700 });
  const main = path.join(live, "main");
  fs.mkdirSync(main, { mode: 0o700 });
  initRepository(main);
  fs.writeFileSync(path.join(main, "tracked.txt"), "base\n", { mode: 0o600 });
  git(main, ["add", "--all"]);
  git(main, ["commit", "-q", "-m", "ancestor ABA base"]);
  const relativeSource = topology === "linked" ? "linked" : "main";
  const source = path.join(live, relativeSource);
  if (topology === "linked") git(main, ["worktree", "add", "-q", "-b", "linked-candidate", source]);
  if (splitIndex) git(source, ["update-index", "--split-index"]);
  fs.writeFileSync(path.join(source, "tracked.txt"), "dirty\n");
  const headA = (git(source, ["rev-parse", "HEAD"]) as string).trim();
  const indexPath = (git(
    source,
    ["rev-parse", "--path-format=absolute", "--git-path", "index"],
  ) as string).trim();
  let sharedPath: string | null = null;
  if (splitIndex) {
    const sharedText = (git(source, ["rev-parse", "--shared-index-path"]) as string).trim();
    assert.notEqual(sharedText, "", "fixture did not retain a split index");
    sharedPath = path.resolve(source, sharedText);
  }
  fs.cpSync(live, held, { preserveTimestamps: true, recursive: true });
  // B's HEAD advances on an identical tree. For a linked topology B's gitfile names the same
  // absolute pathname as A's, so B is only reachable while it is swapped into place.
  swapAncestors(fixtureRoot);
  let headB: string;
  try {
    git(source, ["commit", "-q", "--allow-empty", "-m", "ancestor ABA alternate"]);
    headB = (git(source, ["rev-parse", "HEAD"]) as string).trim();
    fs.writeFileSync(path.join(source, "tracked.txt"), "dirty\n");
  } finally {
    swapAncestors(fixtureRoot);
  }
  assert.notEqual(headB, headA);
  assert.equal((git(source, ["rev-parse", "HEAD"]) as string).trim(), headA);
  const objectRelative = path.join("objects", headB.slice(0, 2), headB.slice(2));
  const objectSource = path.join(held, "main", ".git", objectRelative);
  const objectTarget = path.join(main, ".git", objectRelative);
  fs.mkdirSync(path.dirname(objectTarget), { recursive: true, mode: 0o700 });
  fs.copyFileSync(objectSource, objectTarget);
  git(main, ["cat-file", "-e", `${headB}^{commit}`]);
  assert.deepEqual(statusBytes(source), statusBytes(path.join(held, relativeSource)));
  return { custody, fixtureRoot, headA, headB, held, indexPath, live, sharedPath, source };
}

function swapAncestors(fixtureRoot: string): void {
  const live = path.join(fixtureRoot, "live");
  const held = path.join(fixtureRoot, "held");
  const parking = path.join(fixtureRoot, "parking");
  fs.renameSync(live, parking);
  fs.renameSync(held, live);
  fs.renameSync(parking, held);
}

test("descriptor-rooted private-tree census rejects ancestor A-B-A during witness construction", async () => {
  const fixtureRoot = privateTemp("noa-kws-private-tree-ancestor-aba-");
  const live = path.join(fixtureRoot, "live");
  const held = path.join(fixtureRoot, "held");
  const scratch = path.join(live, "scratch");
  const heldScratch = path.join(held, "scratch");
  fs.mkdirSync(scratch, { mode: 0o700, recursive: true });
  fs.mkdirSync(heldScratch, { mode: 0o700, recursive: true });
  fs.writeFileSync(path.join(scratch, "payload"), "AAAA\n", { mode: 0o600 });
  fs.writeFileSync(path.join(heldScratch, "payload"), "BBBB\n", { mode: 0o600 });
  const moduleRoot = privateTemp("noa-kws-private-tree-module-");
  const modulePath = path.join(moduleRoot, "knockout-workspace.mjs");
  fs.copyFileSync(
    path.join(repositoryRoot, "scripts", "lib", "knockout-workspace.mjs"),
    modulePath,
  );
  fs.copyFileSync(
    path.join(repositoryRoot, "scripts", "lib", "safe-npm-tarball.mjs"),
    path.join(moduleRoot, "safe-npm-tarball.mjs"),
  );
  fs.appendFileSync(modulePath, "\nexport { holdPrivateTree as __testHoldPrivateTree };\n");
  const internal = await import(`${pathToFileURL(modulePath).href}?case=ancestor-aba`) as {
    __testHoldPrivateTree: (root: string, options: {
      code: string;
      label: string;
    }) => { release: () => void };
  };
  const openDescriptor = Object.getOwnPropertyDescriptor(fs, "openSync");
  const opendirDescriptor = Object.getOwnPropertyDescriptor(fs, "opendirSync");
  assert.ok(openDescriptor !== undefined);
  assert.ok(opendirDescriptor !== undefined);
  const originalOpen = fs.openSync;
  const originalOpendir = fs.opendirSync;
  let swapped = false;
  let restored = false;
  let witness: { release: () => void } | null = null;
  let refusal: WorkspaceError | null = null;
  try {
    Object.defineProperty(fs, "opendirSync", {
      ...opendirDescriptor,
      value: (...args: Parameters<typeof fs.opendirSync>) => {
        if (!swapped && typeof args[0] === "string" && path.resolve(args[0]) === scratch) {
          swapAncestors(fixtureRoot);
          swapped = true;
        }
        return Reflect.apply(originalOpendir, fs, args);
      },
    });
    Object.defineProperty(fs, "openSync", {
      ...openDescriptor,
      value: (...args: Parameters<typeof fs.openSync>) => {
        const restoreAfterOpen = swapped && typeof args[0] === "string" &&
          path.resolve(args[0]) === path.join(scratch, "payload");
        const fd = Reflect.apply(originalOpen, fs, args) as number;
        if (restoreAfterOpen) {
          swapAncestors(fixtureRoot);
          swapped = false;
          restored = true;
        }
        return fd;
      },
    });
    try {
      witness = internal.__testHoldPrivateTree(scratch, {
        code: workspaceErrorCode("PRIVATE_ROOT_UNSAFE"),
        label: "test private tree",
      });
    } catch (error) {
      refusal = error as WorkspaceError;
    }
    assert.equal(restored, true, "the descendant walk did not traverse B and restore A");
    assert.equal(witness, null, "a mixed A-root/B-descendant witness was admitted");
    assert.equal(refusal?.code, workspaceErrorCode("PRIVATE_ROOT_UNSAFE"), errorChain(refusal));
    assert.equal(fs.readFileSync(path.join(scratch, "payload"), "utf8"), "AAAA\n");
    assert.equal(fs.readFileSync(path.join(heldScratch, "payload"), "utf8"), "BBBB\n");
  } finally {
    Object.defineProperty(fs, "openSync", openDescriptor);
    Object.defineProperty(fs, "opendirSync", opendirDescriptor);
    if (swapped) swapAncestors(fixtureRoot);
    const releasableWitness = witness as { release: () => void } | null;
    if (releasableWitness !== null) releasableWitness.release();
    removeFixturePath(fixtureRoot);
    removeFixturePath(moduleRoot);
  }
});

function isGenuineGitLaunch(file: unknown, args: unknown): boolean {
  if (file === gitExecutable) return true;
  return typeof file === "string" && file.endsWith("/perl") && Array.isArray(args) &&
    args.includes(gitExecutable);
}

test("ancestor A-B-A around every genuine Git launch never composes a foreign Git topology", async (t) => {
  const cases = [
    { splitIndex: false, topology: "direct" },
    { splitIndex: true, topology: "direct" },
    { splitIndex: false, topology: "linked" },
    { splitIndex: true, topology: "linked" },
  ] as const;
  for (const fixtureCase of cases) {
    await t.test(`${fixtureCase.topology} ${fixtureCase.splitIndex ? "split" : "no-split"} index`, () => {
      const fixture = ancestorAbaFixture(
        `ancestor-aba-${fixtureCase.topology}-${fixtureCase.splitIndex ? "split" : "plain"}`,
        fixtureCase.topology,
        fixtureCase.splitIndex,
      );
      const originalExecFileSync = childProcess.execFileSync;
      const originalSpawnSync = childProcess.spawnSync;
      const indexBefore = gitFileStableObservation(fixture.indexPath);
      const sharedBefore = fixture.sharedPath === null
        ? null
        : gitFileStableObservation(fixture.sharedPath);
      let armed = false;
      let swapped = false;
      let swaps = 0;
      let captured: Capture | null = null;
      let refusal: WorkspaceError | null = null;
      const wrap = <T extends (...args: never[]) => unknown>(original: T): T =>
        ((...args: Parameters<T>) => {
          if (!armed || swapped || !isGenuineGitLaunch(args[0], args[1])) {
            return Reflect.apply(original, childProcess, args);
          }
          // Immediately before the genuine launch the same pathname resolves to B; immediately
          // after the child returns, A is back. No JavaScript-side check runs in between.
          swapAncestors(fixture.fixtureRoot);
          swapped = true;
          swaps += 1;
          try {
            return Reflect.apply(original, childProcess, args);
          } finally {
            swapAncestors(fixture.fixtureRoot);
            swapped = false;
          }
        }) as unknown as T;
      try {
        childProcess.execFileSync = wrap(originalExecFileSync);
        childProcess.spawnSync = wrap(originalSpawnSync);
        syncBuiltinESMExports();
        armed = true;
        try {
          captured = workspace.captureAndSealCandidate({
            commandTimeoutMs: 120_000,
            custodyRoot: fixture.custody,
            maxAttempts: 1,
            sourceRoot: fixture.source,
          });
        } catch (error) {
          refusal = error as WorkspaceError;
        } finally {
          armed = false;
        }
      } finally {
        childProcess.execFileSync = originalExecFileSync;
        childProcess.spawnSync = originalSpawnSync;
        syncBuiltinESMExports();
      }
      try {
        assert.ok(swaps >= 1, "no genuine Git launch was wrapped by an ancestor swap");
        assert.equal(swapped, false);
        assert.equal((git(fixture.source, ["rev-parse", "HEAD"]) as string).trim(), fixture.headA);
        assert.equal(fs.readFileSync(path.join(fixture.source, "tracked.txt"), "utf8"), "dirty\n");
        assert.deepEqual(gitFileStableObservation(fixture.indexPath), indexBefore);
        if (fixture.sharedPath !== null) {
          assert.deepEqual(gitFileStableObservation(fixture.sharedPath), sharedBefore);
        }
        for (const manifestPath of regularFilesBelow(fixture.custody)
          .filter((file) => path.basename(file) === "candidate-manifest.json")) {
          const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8")) as {
            source?: { git?: { head?: unknown } };
          };
          assert.notEqual(manifest.source?.git?.head, fixture.headB, "a manifest sealed B's HEAD");
        }
        if (captured !== null) {
          // Descriptor-pinned success is acceptable only as exact A.
          assert.equal(captured.sourceSnapshot.git.head, fixture.headA);
          assert.equal(captured.manifest.source.git?.head, fixture.headA);
          assert.equal(
            (git(captured.workspaceRoot, ["rev-parse", "HEAD"]) as string).trim(),
            fixture.headA,
          );
          assert.doesNotThrow(() => workspace.verifySealedSeed(captured!));
          return;
        }
        assert.equal(refusal?.code, workspaceErrorCode("SNAPSHOT_UNSTABLE"), errorChain(refusal));
        assert.equal(refusal?.details?.lastCode, workspaceErrorCode("SOURCE_CHANGED"));
        assert.notEqual(causeWithCode(refusal, workspaceErrorCode("SOURCE_CHANGED")), null);
      } finally {
        cleanupReportedScratchRoots(reportedPrivateRoots(captured));
        cleanupReportedScratchRoots(errorPrivateRoots(refusal));
        removeFixturePath(fixture.fixtureRoot);
      }
    });
  }

  await t.test("linked no-split positive control seals exact A without any swap", () => {
    const fixture = ancestorAbaFixture("ancestor-aba-linked-control", "linked", false);
    const indexBefore = gitFileStableObservation(fixture.indexPath);
    let captured: Capture | null = null;
    try {
      captured = workspace.captureAndSealCandidate({
        custodyRoot: fixture.custody,
        sourceRoot: fixture.source,
      });
      assert.equal(captured.sourceSnapshot.git.head, fixture.headA);
      assert.equal(captured.sourceSnapshot.git.topology, "linked");
      assert.equal(
        (git(captured.workspaceRoot, ["rev-parse", "HEAD"]) as string).trim(),
        fixture.headA,
      );
      assert.deepEqual(gitFileStableObservation(fixture.indexPath), indexBefore);
      assert.doesNotThrow(() => workspace.verifySealedSeed(captured!));
    } finally {
      cleanupReportedScratchRoots(reportedPrivateRoots(captured));
      removeFixturePath(fixture.fixtureRoot);
    }
  });
});

test("final closeout re-reads the selected split-index companion", () => {
  // Run 1 records the read-only main-index count at the pre-seal boundary; run 2 changes only the
  // companion timestamp immediately before that last pre-seal open, which is the closeout read.
  const fixture = splitIndexFixture("companion-closeout");
  const secondCustody = privateTemp("noa-kws-companion-closeout-custody-2-");
  const openDescriptor = Object.getOwnPropertyDescriptor(fs, "openSync");
  assert.ok(openDescriptor !== undefined);
  const originalOpen = fs.openSync;
  const indexPhysical = fs.realpathSync(fixture.indexPath);
  let indexOpens = 0;
  let closeoutIndexOpens: number | null = null;
  let mutateAt: number | null = null;
  let mutated = false;
  let first: Capture | null = null;
  let second: Capture | null = null;
  let refusal: WorkspaceError | null = null;
  try {
    Object.defineProperty(fs, "openSync", {
      ...openDescriptor,
      value: (...args: Parameters<typeof fs.openSync>) => {
        const flags = typeof args[1] === "number" ? args[1] : 0;
        if (
          typeof args[0] === "string" && path.resolve(args[0]) === indexPhysical &&
          (flags & (fs.constants.O_WRONLY | fs.constants.O_RDWR | fs.constants.O_CREAT)) === 0
        ) {
          indexOpens += 1;
          if (mutateAt !== null && indexOpens === mutateAt && !mutated) {
            mutated = true;
            const stat = fs.statSync(fixture.sharedPath);
            fs.utimesSync(fixture.sharedPath, stat.atime, new Date(stat.mtimeMs + 5_000));
          }
        }
        return Reflect.apply(originalOpen, fs, args) as number;
      },
    });
    first = workspace.captureAndSealCandidate({
      custodyRoot: fixture.custody,
      hooks: {
        afterPreSealObservation() { closeoutIndexOpens = indexOpens; },
      },
      maxAttempts: 1,
      sourceRoot: fixture.source,
    });
    assert.ok(
      closeoutIndexOpens !== null && closeoutIndexOpens >= 2,
      "the first capture did not reach the pre-seal closeout boundary",
    );
    assert.ok(
      indexOpens > closeoutIndexOpens,
      "calibration did not reach the later capability-time source verification",
    );
    mutateAt = closeoutIndexOpens;
    indexOpens = 0;
    const indexBytes = fs.readFileSync(fixture.indexPath);
    const sharedBytes = fs.readFileSync(fixture.sharedPath);
    try {
      second = workspace.captureAndSealCandidate({
        custodyRoot: secondCustody,
        maxAttempts: 1,
        sourceRoot: fixture.source,
      });
    } catch (error) {
      refusal = error as WorkspaceError;
    }
    assert.equal(mutated, true, "the companion mutation was not reached at the final pre-seal index open");
    assert.deepEqual(fs.readFileSync(fixture.indexPath), indexBytes);
    assert.deepEqual(fs.readFileSync(fixture.sharedPath), sharedBytes);
    assert.equal(second, null, "capture sealed a stale split-index companion observation");
    assert.equal(refusal?.code, workspaceErrorCode("SNAPSHOT_UNSTABLE"), errorChain(refusal));
    assert.deepEqual(
      regularFilesBelow(secondCustody).filter((file) =>
        ["candidate-manifest.json", "state.json"].includes(path.basename(file))),
      [],
      "evidence was published for a stale companion observation",
    );
  } finally {
    Object.defineProperty(fs, "openSync", openDescriptor);
    cleanupReportedScratchRoots(reportedPrivateRoots(first));
    cleanupReportedScratchRoots(reportedPrivateRoots(second));
    cleanupReportedScratchRoots(errorPrivateRoots(refusal));
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
    removeFixturePath(fixture.tools);
    removeFixturePath(secondCustody);
  }
});

function runCalibratedFinalReadMutation(options: {
  assertAfterMutation: () => void;
  attackedCustody: string;
  boundaryPath: string;
  calibrationCustody: string;
  expectedLastCode: string;
  mutate: () => void;
  source: string;
}): void {
  const openDescriptor = Object.getOwnPropertyDescriptor(fs, "openSync");
  assert.ok(openDescriptor !== undefined);
  const originalOpen = fs.openSync;
  const boundaryPhysical = fs.realpathSync(options.boundaryPath);
  let boundaryOpens = 0;
  let closeoutBoundaryOpens: number | null = null;
  let mutateAt: number | null = null;
  let mutated = false;
  let first: Capture | null = null;
  let second: Capture | null = null;
  let refusal: WorkspaceError | null = null;
  try {
    Object.defineProperty(fs, "openSync", {
      ...openDescriptor,
      value: (...args: Parameters<typeof fs.openSync>) => {
        const flags = typeof args[1] === "number" ? args[1] : 0;
        if (
          typeof args[0] === "string" && path.resolve(args[0]) === boundaryPhysical &&
          (flags & (fs.constants.O_WRONLY | fs.constants.O_RDWR | fs.constants.O_CREAT)) === 0
        ) {
          boundaryOpens += 1;
          if (mutateAt !== null && boundaryOpens === mutateAt && !mutated) {
            mutated = true;
            options.mutate();
          }
        }
        return Reflect.apply(originalOpen, fs, args) as number;
      },
    });
    first = workspace.captureAndSealCandidate({
      custodyRoot: options.calibrationCustody,
      hooks: {
        afterPreSealObservation() { closeoutBoundaryOpens = boundaryOpens; },
      },
      maxAttempts: 1,
      sourceRoot: options.source,
    });
    assert.ok(
      closeoutBoundaryOpens !== null && closeoutBoundaryOpens >= 1,
      "calibration did not reach the selected pre-seal final-read boundary",
    );
    assert.ok(
      boundaryOpens > closeoutBoundaryOpens,
      "calibration did not reach the later capability-time source verification",
    );
    const calibratedBoundaryOpens = closeoutBoundaryOpens;
    mutateAt = calibratedBoundaryOpens;
    boundaryOpens = 0;
    try {
      second = workspace.captureAndSealCandidate({
        custodyRoot: options.attackedCustody,
        maxAttempts: 1,
        sourceRoot: options.source,
      });
    } catch (error) {
      refusal = error as WorkspaceError;
    }
    assert.equal(mutated, true, "the calibrated final-read mutation was not reached");
    assert.equal(
      boundaryOpens,
      calibratedBoundaryOpens,
      "the attacked run diverged before the calibrated terminal boundary",
    );
    assert.equal(second, null, "capture accepted a control mutation after its individual read");
    assert.equal(refusal?.code, workspaceErrorCode("SNAPSHOT_UNSTABLE"), errorChain(refusal));
    assert.equal(refusal?.details?.lastCode, options.expectedLastCode, errorChain(refusal));
    assert.notEqual(causeWithCode(refusal, options.expectedLastCode), null, errorChain(refusal));
    options.assertAfterMutation();
    assert.deepEqual(
      regularFilesBelow(options.attackedCustody).filter((file) =>
        ["candidate-manifest.json", "state.json"].includes(path.basename(file))),
      [],
      "capture evidence was published for a mutated final control set",
    );
  } finally {
    Object.defineProperty(fs, "openSync", openDescriptor);
    cleanupReportedScratchRoots(reportedPrivateRoots(first));
    cleanupReportedScratchRoots(reportedPrivateRoots(second));
    cleanupReportedScratchRoots(errorPrivateRoots(refusal));
  }
}

test("final control custody detects mutations and appearances after earlier reads", async (t) => {
  await t.test("repository config changes after its final read", () => {
    const fixture = minimalCaptureFixture("final-config-custody");
    const attackedCustody = privateTemp("noa-kws-final-config-custody-2-");
    const configPath = path.join(fixture.source, ".git", "config");
    const attributesPath = path.join(fixture.source, ".git", "info", "attributes");
    fs.mkdirSync(path.dirname(attributesPath), { mode: 0o700, recursive: true });
    fs.writeFileSync(attributesPath, "# terminal boundary\n", { mode: 0o600 });
    try {
      runCalibratedFinalReadMutation({
        assertAfterMutation: () => {
          assert.match(fs.readFileSync(configPath, "utf8"), /excludesFile/u);
        },
        attackedCustody,
        boundaryPath: attributesPath,
        calibrationCustody: fixture.custody,
        expectedLastCode: workspaceErrorCode("SOURCE_CHANGED"),
        mutate: () => {
          fs.appendFileSync(configPath, "\n[core]\n\texcludesFile = /dev/null\n");
        },
        source: fixture.source,
      });
    } finally {
      removeFixturePath(fixture.source);
      removeFixturePath(fixture.custody);
      removeFixturePath(attackedCustody);
    }
  });

  await t.test("nested info/exclude appears after its final absence read", () => {
    const fixture = minimalCaptureFixture("final-info-absence");
    const attackedCustody = privateTemp("noa-kws-final-info-absence-2-");
    const excludePath = path.join(fixture.source, ".git", "info", "exclude");
    const attributesPath = path.join(fixture.source, ".git", "info", "attributes");
    fs.mkdirSync(path.dirname(attributesPath), { mode: 0o700, recursive: true });
    fs.writeFileSync(attributesPath, "# terminal boundary\n", { mode: 0o600 });
    assert.equal(pathExistsNoFollow(excludePath), false);
    try {
      runCalibratedFinalReadMutation({
        assertAfterMutation: () => {
          assert.equal(fs.readFileSync(excludePath, "utf8"), "# appeared late\n");
        },
        attackedCustody,
        boundaryPath: attributesPath,
        calibrationCustody: fixture.custody,
        expectedLastCode: workspaceErrorCode("SOURCE_CHANGED"),
        mutate: () => fs.writeFileSync(excludePath, "# appeared late\n", { flag: "wx", mode: 0o600 }),
        source: fixture.source,
      });
    } finally {
      removeFixturePath(fixture.source);
      removeFixturePath(fixture.custody);
      removeFixturePath(attackedCustody);
    }
  });

  await t.test("loose HEAD ref appears after the packed-ref absence read", () => {
    const fixture = minimalCaptureFixture("final-packed-ref-absence");
    const attackedCustody = privateTemp("noa-kws-final-packed-ref-absence-2-");
    const headA = (git(fixture.source, ["rev-parse", "HEAD"]) as string).trim();
    git(fixture.source, ["commit", "-q", "--allow-empty", "-m", "alternate packed-ref head"]);
    const headB = (git(fixture.source, ["rev-parse", "HEAD"]) as string).trim();
    assert.notEqual(headA, headB);
    git(fixture.source, ["reset", "-q", "--hard", headA]);
    git(fixture.source, ["pack-refs", "--all", "--prune"]);
    const headRef = (git(fixture.source, ["symbolic-ref", "HEAD"]) as string).trim();
    const loosePath = path.join(fixture.source, ".git", ...headRef.split("/"));
    const packedPath = path.join(fixture.source, ".git", "packed-refs");
    assert.equal(pathExistsNoFollow(loosePath), false);
    try {
      runCalibratedFinalReadMutation({
        assertAfterMutation: () => {
          assert.equal((git(fixture.source, ["rev-parse", "HEAD"]) as string).trim(), headB);
        },
        attackedCustody,
        boundaryPath: packedPath,
        calibrationCustody: fixture.custody,
        expectedLastCode: workspaceErrorCode("SNAPSHOT_UNSTABLE"),
        mutate: () => fs.writeFileSync(loosePath, `${headB}\n`, { flag: "wx", mode: 0o600 }),
        source: fixture.source,
      });
    } finally {
      removeFixturePath(fixture.source);
      removeFixturePath(fixture.custody);
      removeFixturePath(attackedCustody);
    }
  });

  await t.test("main split index changes after its final read but before companion custody", () => {
    const fixture = splitIndexFixture("final-split-reverse-custody");
    const attackedCustody = privateTemp("noa-kws-final-split-reverse-custody-2-");
    const indexBytes = fs.readFileSync(fixture.indexPath);
    try {
      runCalibratedFinalReadMutation({
        assertAfterMutation: () => {
          assert.deepEqual(fs.readFileSync(fixture.indexPath), indexBytes);
        },
        attackedCustody,
        boundaryPath: fixture.sharedPath,
        calibrationCustody: fixture.custody,
        expectedLastCode: workspaceErrorCode("SNAPSHOT_UNSTABLE"),
        mutate: () => {
          const stat = fs.statSync(fixture.indexPath);
          fs.utimesSync(fixture.indexPath, stat.atime, new Date(stat.mtimeMs + 5_000));
        },
        source: fixture.source,
      });
    } finally {
      removeFixturePath(fixture.source);
      removeFixturePath(fixture.custody);
      removeFixturePath(fixture.tools);
      removeFixturePath(attackedCustody);
    }
  });
});

function forgedStateBytes(statePath: string, forge: boolean): Buffer {
  const state = JSON.parse(fs.readFileSync(statePath, "utf8")) as Record<string, unknown>;
  if (forge) state.workspace = "../forged-workspace";
  return workspace.canonicalJsonBytes(state);
}

function replaceEvidenceInode(target: string, bytes: Buffer): string {
  const retained = `${target}.created-inode.retained`;
  fs.renameSync(target, retained);
  fs.writeFileSync(target, bytes, { flag: "wx", mode: 0o600 });
  return retained;
}

test("persisted capture state is evidence, never authority", async (t) => {
  const substitutions = [
    { forge: true, label: "forged different-byte state" },
    { forge: false, label: "same-content new-inode state" },
  ] as const;

  for (const substitution of substitutions) {
    await t.test(`${substitution.label} before capability issuance refuses`, () => {
      const fixture = minimalCaptureFixture(`state-pre-issuance-${substitution.forge ? "forged" : "same"}`);
      const openDescriptor = Object.getOwnPropertyDescriptor(fs, "openSync");
      const closeDescriptor = Object.getOwnPropertyDescriptor(fs, "closeSync");
      assert.ok(openDescriptor !== undefined);
      assert.ok(closeDescriptor !== undefined);
      const originalOpen = fs.openSync;
      const originalClose = fs.closeSync;
      let statePath: string | null = null;
      let stateFd: number | null = null;
      let retained: string | null = null;
      let captured: Capture | null = null;
      let refusal: WorkspaceError | null = null;
      try {
        Object.defineProperty(fs, "openSync", {
          ...openDescriptor,
          value: (...args: Parameters<typeof fs.openSync>) => {
            const flags = typeof args[1] === "number" ? args[1] : 0;
            const fd = Reflect.apply(originalOpen, fs, args) as number;
            if (
              statePath !== null && args[0] === statePath && stateFd === null &&
              (flags & fs.constants.O_CREAT) !== 0
            ) stateFd = fd;
            return fd;
          },
        });
        Object.defineProperty(fs, "closeSync", {
          ...closeDescriptor,
          value: (...args: Parameters<typeof fs.closeSync>) => {
            const result = Reflect.apply(originalClose, fs, args) as ReturnType<typeof fs.closeSync>;
            if (stateFd !== null && args[0] === stateFd && retained === null) {
              // The state file is committed, durable, and just released: replace its inode
              // before the producer can register any capability. The descriptor number is
              // disarmed first because the replacement write may reuse it.
              stateFd = null;
              const state = requiredString(statePath, "state path was not armed");
              retained = replaceEvidenceInode(state, forgedStateBytes(state, substitution.forge));
            }
            return result;
          },
        });
        try {
          captured = workspace.captureAndSealCandidate({
            custodyRoot: fixture.custody,
            hooks: { beforeStatePublication(value) { statePath = value.statePath; } },
            maxAttempts: 1,
            sourceRoot: fixture.source,
          });
        } catch (error) {
          refusal = error as WorkspaceError;
        }
      } finally {
        Object.defineProperty(fs, "openSync", openDescriptor);
        Object.defineProperty(fs, "closeSync", closeDescriptor);
      }
      try {
        const state = requiredString(statePath, "pre-state hook did not receive the state path");
        const retainedPath = requiredString(retained, "the state substitution was not reached");
        assert.equal(captured, null, "a capability was issued over a substituted state inode");
        assert.equal(refusal?.code, workspaceErrorCode("MANIFEST_MISMATCH"), errorChain(refusal));
        assert.equal(pathExistsNoFollow(retainedPath), true, "the original state inode was deleted");
        assert.equal(pathExistsNoFollow(state), true, "the replacement inode was deleted");
      } finally {
        cleanupReportedScratchRoots(errorPrivateRoots(refusal));
        removeFixturePath(fixture.source);
        removeFixturePath(fixture.custody);
      }
    });

    await t.test(`${substitution.label} after capability issuance refuses at use time`, () => {
      const fixture = minimalCaptureFixture(`state-post-issuance-${substitution.forge ? "forged" : "same"}`);
      let captured: Capture | null = null;
      try {
        captured = workspace.captureAndSealCandidate({
          custodyRoot: fixture.custody,
          sourceRoot: fixture.source,
        });
        assert.doesNotThrow(() => workspace.verifySealedSeed(captured!));
        const retained = replaceEvidenceInode(
          captured.statePath,
          forgedStateBytes(captured.statePath, substitution.forge),
        );
        assert.throws(
          () => workspace.verifySealedSeed(captured!),
          (error: WorkspaceError) => error.code === workspaceErrorCode("MANIFEST_MISMATCH"),
        );
        assert.equal(pathExistsNoFollow(retained), true);
      } finally {
        cleanupReportedScratchRoots(reportedPrivateRoots(captured));
        removeFixturePath(fixture.source);
        removeFixturePath(fixture.custody);
      }
    });
  }

  await t.test("a crash after the durable state commit leaves no SEALED claim and no capability", () => {
    const fixture = minimalCaptureFixture("state-crash");
    const moduleUrl = pathToFileURL(
      path.join(repositoryRoot, "scripts/lib/knockout-workspace.mjs"),
    ).href;
    const script = [
      "import fs from 'node:fs';",
      "import path from 'node:path';",
      "const workspace = await import(process.env.KWS_MODULE_URL);",
      "let statePath = null;",
      "let workspaceRoot = null;",
      "let stateFd = null;",
      "const originalOpen = fs.openSync;",
      "const originalFchmod = fs.fchmodSync;",
      "fs.openSync = (...args) => {",
      "  const fd = originalOpen(...args);",
      "  if (statePath !== null && args[0] === statePath && stateFd === null &&",
      "    typeof args[1] === 'number' && (args[1] & fs.constants.O_CREAT) !== 0) stateFd = fd;",
      "  return fd;",
      "};",
      "fs.fchmodSync = (...args) => {",
      "  const result = originalFchmod(...args);",
      "  if (stateFd !== null && args[0] === stateFd && args[1] === 0o600) {",
      "    // The commit transition is durable; the seed is mutated and the process dies before",
      "    // any post-commit witness can run.",
      "    fs.fsyncSync(stateFd);",
      "    fs.appendFileSync(path.join(workspaceRoot, 'tracked.txt'), 'CRASH-MUTATION\\n');",
      "    process.kill(process.pid, 'SIGKILL');",
      "  }",
      "  return result;",
      "};",
      "workspace.captureAndSealCandidate({",
      "  custodyRoot: process.env.KWS_CUSTODY,",
      "  hooks: {",
      "    beforeStatePublication(value) {",
      "      statePath = value.statePath;",
      "      workspaceRoot = value.workspaceRoot;",
      "    },",
      "  },",
      "  maxAttempts: 1,",
      "  sourceRoot: process.env.KWS_SOURCE,",
      "});",
      "process.stdout.write('RETURNED\\n');",
    ].join("\n");
    let stateFile: string | null = null;
    try {
      const child = childProcess.spawnSync(process.execPath, ["--input-type=module", "--eval", script], {
        encoding: "utf8",
        env: {
          ...process.env,
          KWS_CUSTODY: fixture.custody,
          KWS_MODULE_URL: moduleUrl,
          KWS_SOURCE: fixture.source,
        },
        timeout: 120_000,
      });
      assert.equal(child.signal, "SIGKILL", `child did not crash: ${child.stdout}${child.stderr}`);
      assert.equal(child.stdout.includes("RETURNED"), false);
      const seedsAfterCrash = fs.readdirSync(fixture.custody)
        .filter((entry) => entry.startsWith("seed-attempt-1-"));
      assert.equal(seedsAfterCrash.length, 1);
      assert.equal(
        fs.readFileSync(path.join(fixture.custody, seedsAfterCrash[0]!, "workspace", "tracked.txt"), "utf8"),
        "stable source bytes\nCRASH-MUTATION\n",
        "the crash did not land after the durable commit",
      );
      const seeds = fs.readdirSync(fixture.custody).filter((entry) => entry.startsWith("seed-attempt-1-"));
      assert.equal(seeds.length, 1, "crash residue seed was not retained");
      const seedRoot = path.join(fixture.custody, seeds[0]!);
      stateFile = path.join(seedRoot, "evidence", "state.json");
      assert.equal(pathExistsNoFollow(stateFile), true, "the durable state residue is absent");
      assert.equal(fs.lstatSync(stateFile).mode & 0o777, 0o600);
      const state = JSON.parse(fs.readFileSync(stateFile, "utf8")) as Record<string, unknown>;
      assert.notEqual(state.status, "SEALED", "crash residue persists a SEALED claim");
      assert.equal(state.status, "CAPTURED");
      assert.equal(state.evidenceRole, "NON_AUTHORITATIVE_CAPTURE_EVIDENCE");
      assert.equal(state.protocol, workspace.KNOCKOUT_WORKSPACE_PROTOCOLS.state);
      const manifestPath = path.join(seedRoot, "evidence", "candidate-manifest.json");
      const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8")) as Capture["manifest"];
      const residueShaped = {
        attempt: 1,
        candidateManifestSha256: manifest.candidateManifestSha256,
        evidenceIdentity: "0:0",
        evidenceRoot: path.join(seedRoot, "evidence"),
        manifest,
        manifestObservation: gitFileStableObservation(manifestPath) as unknown as FileObservation,
        manifestPath,
        retainedPrivateRoots: [],
        seedRoot,
        sourceSnapshot: { git: manifest.source.git, workspace: manifest.resourceAdmission.source },
        stateObservation: gitFileStableObservation(stateFile) as unknown as FileObservation,
        statePath: stateFile,
        workspaceObservation: manifest.seed,
        workspaceRoot: path.join(seedRoot, "workspace"),
      } as unknown as Capture;
      assert.throws(
        () => workspace.verifySealedSeed(residueShaped),
        (error: WorkspaceError) => error.code === workspaceErrorCode("INVALID_ARGUMENT"),
        "crash residue was adopted as a capability",
      );
    } finally {
      removeFixturePath(fixture.source);
      removeFixturePath(fixture.custody);
    }
  });

  await t.test("copied, spread, serialized, and prototype-linked capture shapes are rejected", () => {
    const fixture = minimalCaptureFixture("capability-shapes");
    let captured: Capture | null = null;
    try {
      captured = workspace.captureAndSealCandidate({
        custodyRoot: fixture.custody,
        sourceRoot: fixture.source,
      });
      const shapes: Array<[string, unknown]> = [
        ["spread copy", { ...captured }],
        ["JSON round trip", JSON.parse(JSON.stringify(captured))],
        ["structured clone", structuredClone(captured)],
        ["prototype-linked", Object.create(captured)],
        ["null-prototype copy", Object.assign(Object.create(null), captured)],
      ];
      for (const [label, shape] of shapes) {
        assert.throws(
          () => workspace.verifySealedSeed(shape as Capture),
          (error: WorkspaceError) => error.code === workspaceErrorCode("INVALID_ARGUMENT"),
          `${label} entered as a capability`,
        );
      }
      assert.doesNotThrow(() => workspace.verifySealedSeed(captured!));
      assert.doesNotThrow(() => workspace.verifySealedSeed(captured!));
    } finally {
      cleanupReportedScratchRoots(reportedPrivateRoots(captured));
      removeFixturePath(fixture.source);
      removeFixturePath(fixture.custody);
    }
  });
});

test("manifest replacement at the state commit transition cannot issue a capability", async (t) => {
  const cases = [
    { forge: true, label: "forged different-byte manifest" },
    { forge: false, label: "same-content new-inode manifest" },
  ] as const;
  for (const fixtureCase of cases) {
    await t.test(fixtureCase.label, () => {
      const fixture = minimalCaptureFixture(`manifest-commit-${fixtureCase.forge ? "forged" : "same"}`);
      const openDescriptor = Object.getOwnPropertyDescriptor(fs, "openSync");
      const fchmodDescriptor = Object.getOwnPropertyDescriptor(fs, "fchmodSync");
      assert.ok(openDescriptor !== undefined);
      assert.ok(fchmodDescriptor !== undefined);
      const originalOpen = fs.openSync;
      const originalFchmod = fs.fchmodSync;
      let statePath: string | null = null;
      let manifestPath: string | null = null;
      let stateFd: number | null = null;
      let retained: string | null = null;
      let captured: Capture | null = null;
      let refusal: WorkspaceError | null = null;
      try {
        Object.defineProperty(fs, "openSync", {
          ...openDescriptor,
          value: (...args: Parameters<typeof fs.openSync>) => {
            const flags = typeof args[1] === "number" ? args[1] : 0;
            const fd = Reflect.apply(originalOpen, fs, args) as number;
            if (
              statePath !== null && args[0] === statePath && stateFd === null &&
              (flags & fs.constants.O_CREAT) !== 0
            ) stateFd = fd;
            return fd;
          },
        });
        Object.defineProperty(fs, "fchmodSync", {
          ...fchmodDescriptor,
          value: (...args: Parameters<typeof fs.fchmodSync>) => {
            if (stateFd !== null && args[0] === stateFd && args[1] === 0o600 && retained === null) {
              const target = requiredString(manifestPath, "manifest path was not armed");
              const manifest = JSON.parse(fs.readFileSync(target, "utf8")) as Record<string, unknown>;
              if (fixtureCase.forge) manifest.attempt = 99;
              retained = replaceEvidenceInode(target, workspace.canonicalJsonBytes(manifest));
            }
            return Reflect.apply(originalFchmod, fs, args) as ReturnType<typeof fs.fchmodSync>;
          },
        });
        try {
          captured = workspace.captureAndSealCandidate({
            custodyRoot: fixture.custody,
            hooks: {
              beforeStatePublication(value) {
                statePath = value.statePath;
                manifestPath = path.join(value.evidenceRoot, "candidate-manifest.json");
              },
            },
            maxAttempts: 1,
            sourceRoot: fixture.source,
          });
        } catch (error) {
          refusal = error as WorkspaceError;
        }
      } finally {
        Object.defineProperty(fs, "openSync", openDescriptor);
        Object.defineProperty(fs, "fchmodSync", fchmodDescriptor);
      }
      try {
        const state = requiredString(statePath, "pre-state hook did not receive the state path");
        const retainedPath = requiredString(retained, "the manifest substitution was not reached");
        assert.equal(captured, null, "a capability was issued over a substituted manifest inode");
        assert.equal(refusal?.code, workspaceErrorCode("MANIFEST_MISMATCH"), errorChain(refusal));
        const publication = errorTerminalPublication(refusal);
        assert.equal(publication?.path, state);
        assert.equal(publication?.phase, "COMMIT_REVOKED");
        assert.equal(fs.lstatSync(state).mode & 0o777, 0, "a committed state marker survived");
        assert.equal(pathExistsNoFollow(retainedPath), true, "the original manifest inode was deleted");
      } finally {
        cleanupReportedScratchRoots(errorPrivateRoots(refusal));
        removeFixturePath(fixture.source);
        removeFixturePath(fixture.custody);
      }
    });
  }
});

test("the entry source observation is enforced on every reopen through success", async (t) => {
  const renameAwayAndBack = (source: string): void => {
    const parked = `${source}.parked`;
    fs.renameSync(source, parked);
    fs.renameSync(parked, source);
  };

  await t.test("same-inode rename before the first observation refuses", () => {
    const fixture = minimalCaptureFixture("entry-same-inode-aba");
    const originalSpawnSync = childProcess.spawnSync;
    const entryStat = fs.lstatSync(fixture.source, { bigint: true });
    let renamed = false;
    let armed = false;
    let captured: Capture | null = null;
    let refusal: WorkspaceError | null = null;
    try {
      childProcess.spawnSync = ((...args: Parameters<typeof childProcess.spawnSync>) => {
        if (armed && !renamed) {
          // The first child launched after capture entry precedes every source observation.
          renamed = true;
          renameAwayAndBack(fixture.source);
        }
        return Reflect.apply(originalSpawnSync, childProcess, args);
      }) as typeof childProcess.spawnSync;
      syncBuiltinESMExports();
      armed = true;
      try {
        captured = workspace.captureAndSealCandidate({
          custodyRoot: fixture.custody,
          maxAttempts: 1,
          sourceRoot: fixture.source,
        });
      } catch (error) {
        refusal = error as WorkspaceError;
      } finally {
        armed = false;
      }
    } finally {
      childProcess.spawnSync = originalSpawnSync;
      syncBuiltinESMExports();
    }
    try {
      assert.equal(renamed, true, "the entry rename was not reached");
      const afterStat = fs.lstatSync(fixture.source, { bigint: true });
      assert.equal(`${afterStat.dev}:${afterStat.ino}`, `${entryStat.dev}:${entryStat.ino}`);
      assert.notEqual(afterStat.ctimeNs, entryStat.ctimeNs, "rename did not alter the root ctime");
      assert.equal(captured, null, "capture accepted a source root renamed after entry");
      assert.equal(refusal?.code, workspaceErrorCode("SNAPSHOT_UNSTABLE"), errorChain(refusal));
      assert.equal(refusal?.details?.lastCode, workspaceErrorCode("SOURCE_CHANGED"));
    } finally {
      cleanupReportedScratchRoots(reportedPrivateRoots(captured));
      cleanupReportedScratchRoots(errorPrivateRoots(refusal));
      removeFixturePath(fixture.source);
      removeFixturePath(fixture.custody);
    }
  });

  await t.test("same-inode rename before the state commit refuses without a committed marker", () => {
    const fixture = minimalCaptureFixture("late-same-inode-aba");
    let statePath: string | null = null;
    let renamed = false;
    let captured: Capture | null = null;
    let refusal: WorkspaceError | null = null;
    try {
      try {
        captured = workspace.captureAndSealCandidate({
          custodyRoot: fixture.custody,
          hooks: {
            beforeStatePublication(value) {
              statePath = value.statePath;
              renamed = true;
              renameAwayAndBack(fixture.source);
            },
          },
          maxAttempts: 1,
          sourceRoot: fixture.source,
        });
      } catch (error) {
        refusal = error as WorkspaceError;
      }
      assert.equal(renamed, true);
      assert.equal(captured, null, "capture accepted a source root renamed before the commit");
      assert.equal(refusal?.code, workspaceErrorCode("SOURCE_CHANGED"), errorChain(refusal));
      const state = requiredString(statePath, "pre-state hook did not receive the state path");
      if (pathExistsNoFollow(state)) {
        assert.equal(fs.lstatSync(state).mode & 0o777, 0, "a committed state marker survived");
      }
      assert.equal(fs.readFileSync(fixture.trackedPath, "utf8"), "stable source bytes\n");
    } finally {
      cleanupReportedScratchRoots(reportedPrivateRoots(captured));
      cleanupReportedScratchRoots(errorPrivateRoots(refusal));
      removeFixturePath(fixture.source);
      removeFixturePath(fixture.custody);
    }
  });
});

type ScratchIndexAttackFixture = {
  aStageSha256: string;
  bIndexBytes: Buffer;
  bStageSha256: string;
  custody: string;
  indexPath: string;
  source: string;
  trackedPath: string;
};

/**
 * A live source A and a decoy index B with distinct staged content and status. B's staged blob
 * is copied into A's object store so that any genuine Git validation of B semantics can complete.
 */
function scratchIndexAttackFixture(prefix: string): ScratchIndexAttackFixture {
  const fixture = minimalCaptureFixture(prefix);
  const decoy = privateTemp(`noa-kws-${prefix}-decoy-`);
  try {
    fs.cpSync(fixture.source, decoy, { preserveTimestamps: true, recursive: true });
    fs.writeFileSync(path.join(decoy, "b-only.txt"), "decoy staged bytes\n", { mode: 0o600 });
    git(decoy, ["add", "--", "b-only.txt"]);
    const bIndexBytes = fs.readFileSync(path.join(decoy, ".git", "index"));
    const blob = (git(decoy, ["rev-parse", ":b-only.txt"]) as string).trim();
    const objectRelative = path.join("objects", blob.slice(0, 2), blob.slice(2));
    const target = path.join(fixture.source, ".git", objectRelative);
    fs.mkdirSync(path.dirname(target), { mode: 0o700, recursive: true });
    fs.copyFileSync(path.join(decoy, ".git", objectRelative), target);
    git(fixture.source, ["cat-file", "-e", `${blob}^{blob}`]);
    const stageOf = (root: string): string =>
      sha256Bytes(git(root, ["ls-files", "--stage", "--full-name", "-z"], null) as Buffer);
    const aStageSha256 = stageOf(fixture.source);
    const bStageSha256 = stageOf(decoy);
    assert.notEqual(aStageSha256, bStageSha256, "decoy index does not carry distinct semantics");
    assert.notDeepEqual(statusBytes(fixture.source), statusBytes(decoy));
    return {
      aStageSha256,
      bIndexBytes,
      bStageSha256,
      custody: fixture.custody,
      indexPath: path.join(fixture.source, ".git", "index"),
      source: fixture.source,
      trackedPath: fixture.trackedPath,
    };
  } finally {
    removeFixturePath(decoy);
  }
}

function observationScratchIndexTargets(roots: string[]): string[] {
  const targets: string[] = [];
  for (const root of roots) {
    if (!pathExistsNoFollow(root)) continue;
    for (const entry of fs.readdirSync(root)) {
      if (!entry.startsWith("noa-kws-git-observe-")) continue;
      const candidates = [
        path.join(root, entry, ".git", "index-observation", "index"),
        path.join(root, entry, ".git", "index"),
      ];
      const candidate = candidates.find((value) => pathExistsNoFollow(value));
      if (candidate !== undefined) targets.push(candidate);
    }
  }
  return targets;
}

function seedIndexTargets(roots: string[]): string[] {
  const targets: string[] = [];
  for (const root of roots) {
    if (!pathExistsNoFollow(root)) continue;
    for (const entry of fs.readdirSync(root)) {
      if (!entry.startsWith("seed-attempt-")) continue;
      const candidate = path.join(root, entry, "workspace", ".git", "index");
      if (pathExistsNoFollow(candidate)) targets.push(candidate);
    }
  }
  return targets;
}

/**
 * Around every genuine Git launch, replace each selected private index with the decoy B and
 * restore A when the child returns: the exact window in which Git reads its inputs.
 */
function armPrivateIndexAttack(
  roots: string[],
  bIndexBytes: Buffer,
  resolveTargets: (roots: string[]) => string[],
): { disarm: () => void; substitutions: () => number; wrappedCommands: () => string[] } {
  const originalExecFileSync = childProcess.execFileSync;
  const originalSpawnSync = childProcess.spawnSync;
  let substitutions = 0;
  let active = false;
  const wrappedCommands: string[] = [];
  const wrap = <T extends (...args: never[]) => unknown>(original: T): T =>
    ((...args: Parameters<T>) => {
      if (active || !isGenuineGitLaunch(args[0], args[1])) {
        return Reflect.apply(original, childProcess, args);
      }
      const targets = resolveTargets(roots);
      if (targets.length === 0) return Reflect.apply(original, childProcess, args);
      active = true;
      const held: Array<[string, string]> = [];
      try {
        for (const target of targets) {
          const parked = `${target}.a-held`;
          fs.renameSync(target, parked);
          fs.writeFileSync(target, bIndexBytes, { flag: "wx", mode: 0o600 });
          held.push([target, parked]);
        }
        substitutions += held.length;
        const gitArgs = Array.isArray(args[1]) ? (args[1] as unknown[]).map(String) : [];
        wrappedCommands.push(gitArgs.filter((argument) => !argument.startsWith("-")).join(" "));
        return Reflect.apply(original, childProcess, args);
      } finally {
        for (const [target, parked] of held.reverse()) {
          fs.unlinkSync(target);
          fs.renameSync(parked, target);
        }
        active = false;
      }
    }) as unknown as T;
  childProcess.execFileSync = wrap(originalExecFileSync);
  childProcess.spawnSync = wrap(originalSpawnSync);
  syncBuiltinESMExports();
  return {
    disarm() {
      childProcess.execFileSync = originalExecFileSync;
      childProcess.spawnSync = originalSpawnSync;
      syncBuiltinESMExports();
    },
    substitutions: () => substitutions,
    wrappedCommands: () => wrappedCommands,
  };
}

test("private scratch index substitution around genuine Git launches never blesses decoy semantics", async (t) => {
  await t.test("capture and same-process verification under the active substitution", () => {
    const fixture = scratchIndexAttackFixture("scratch-index-capture");
    const indexBefore = fs.readFileSync(fixture.indexPath);
    const attack = armPrivateIndexAttack(
      [fixture.custody],
      fixture.bIndexBytes,
      observationScratchIndexTargets,
    );
    let captured: Capture | null = null;
    let refusal: WorkspaceError | null = null;
    let activeVerification: "passed" | "refused" | null = null;
    try {
      try {
        captured = workspace.captureAndSealCandidate({
          commandTimeoutMs: 120_000,
          custodyRoot: fixture.custody,
          maxAttempts: 1,
          sourceRoot: fixture.source,
        });
      } catch (error) {
        refusal = error as WorkspaceError;
      }
      if (captured !== null) {
        try {
          workspace.verifySealedSeed(captured);
          activeVerification = "passed";
        } catch {
          activeVerification = "refused";
        }
      }
    } finally {
      attack.disarm();
    }
    try {
      assert.ok(attack.substitutions() >= 1, "no private index was substituted around a Git launch");
      assert.deepEqual(fs.readFileSync(fixture.indexPath), indexBefore, "live raw index is not A");
      for (const manifestPath of regularFilesBelow(fixture.custody)
        .filter((file) => path.basename(file) === "candidate-manifest.json")) {
        const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8")) as {
          source?: { git?: { indexStageSha256?: unknown } };
        };
        assert.notEqual(
          manifest.source?.git?.indexStageSha256,
          fixture.bStageSha256,
          "a manifest blessed the decoy stage semantics",
        );
      }
      if (captured !== null) {
        assert.equal(captured.sourceSnapshot.git.indexStageSha256, fixture.aStageSha256);
        assert.notEqual(captured.sourceSnapshot.git.indexStageSha256, fixture.bStageSha256);
        const sealedStageSha256 = sha256Bytes(
          git(captured.workspaceRoot, ["ls-files", "--stage", "--full-name", "-z"], null) as Buffer,
        );
        assert.equal(sealedStageSha256, fixture.aStageSha256);
        assert.notEqual(sealedStageSha256, fixture.bStageSha256);
        assert.equal(activeVerification, "passed");
        return;
      }
      assert.equal(refusal?.code, workspaceErrorCode("PRIVATE_ROOT_UNSAFE"), errorChain(refusal));
    } finally {
      cleanupReportedScratchRoots(reportedPrivateRoots(captured));
      cleanupReportedScratchRoots(errorPrivateRoots(refusal));
      removeFixturePath(fixture.source);
      removeFixturePath(fixture.custody);
    }
  });

  await t.test("use-time verification under the active substitution refuses and leaves the seed exact", () => {
    const fixture = scratchIndexAttackFixture("scratch-index-use");
    let captured: Capture | null = null;
    try {
      captured = workspace.captureAndSealCandidate({
        custodyRoot: fixture.custody,
        sourceRoot: fixture.source,
      });
      assert.equal(captured.sourceSnapshot.git.indexStageSha256, fixture.aStageSha256);
      const seedIndexPath = path.join(captured.workspaceRoot, ".git", "index");
      const seedGitDirectory = path.dirname(seedIndexPath);
      const seedIndexBefore = fs.readFileSync(seedIndexPath);
      const seedObservationBefore = gitFileStableObservation(seedIndexPath);
      const seedDirectoryObservationBefore = pathStableObservation(seedGitDirectory);
      assert.doesNotThrow(() => workspace.verifySealedSeed(captured!));
      const attack = armPrivateIndexAttack(
        [fixture.custody],
        fixture.bIndexBytes,
        seedIndexTargets,
      );
      let refusal: WorkspaceError | null = null;
      try {
        assert.throws(
          () => workspace.verifySealedSeed(captured!),
          (error: WorkspaceError) => {
            refusal = error;
            return error.code === workspaceErrorCode("MANIFEST_MISMATCH") ||
              error.code === workspaceErrorCode("PRIVATE_ROOT_UNSAFE");
          },
        );
      } finally {
        attack.disarm();
      }
      assert.ok(attack.substitutions() >= 1, "no private index was substituted around a Git launch");
      assert.notEqual(refusal, null);
      assert.deepEqual(fs.readFileSync(seedIndexPath), seedIndexBefore, "seed raw index is not A");
      const seedObservationAfter = gitFileStableObservation(seedIndexPath);
      assert.equal(seedObservationAfter.size, seedObservationBefore.size);
      assert.equal(seedObservationAfter.dev, seedObservationBefore.dev);
      assert.equal(seedObservationAfter.ino, seedObservationBefore.ino);
      assert.notDeepEqual(
        pathStableObservation(seedGitDirectory),
        seedDirectoryObservationBefore,
        "the seed directory observation did not record the transient substitution",
      );
      assert.throws(
        () => workspace.verifySealedSeed(captured!),
        (error: WorkspaceError) =>
          error.code === workspaceErrorCode("MANIFEST_MISMATCH") ||
          error.code === workspaceErrorCode("PRIVATE_ROOT_UNSAFE"),
        "verification recovered after a transient seed substitution changed sealed observation",
      );
    } finally {
      cleanupReportedScratchRoots(reportedPrivateRoots(captured));
      removeFixturePath(fixture.source);
      removeFixturePath(fixture.custody);
    }
  });
});

function runGitfileCloseoutRewriteCase(splitIndex: boolean): void {
  // Run 1 records linked-index opens at the pre-seal boundary; run 2 rewrites the root gitfile in
  // place, keeping its inode, immediately before that last pre-seal open (the closeout read). The
  // alternate Git directory B is a valid same-tree topology whose HEAD differs, so a capture that
  // ignores the rewrite seals a HEAD the live worktree no longer has.
  const mode = splitIndex ? "split" : "full";
  const fixtureRoot = privateTemp(`noa-kws-gitfile-closeout-${mode}-`);
  const custodyOne = privateTemp(`noa-kws-gitfile-closeout-${mode}-custody-1-`);
  const custodyTwo = privateTemp(`noa-kws-gitfile-closeout-${mode}-custody-2-`);
  const main = path.join(fixtureRoot, "main");
  const linked = path.join(fixtureRoot, "linked");
  fs.mkdirSync(main, { mode: 0o700 });
  initRepository(main);
  fs.writeFileSync(path.join(main, "tracked.txt"), "base\n", { mode: 0o600 });
  git(main, ["add", "--all"]);
  git(main, ["commit", "-q", "-m", "gitfile closeout base"]);
  git(main, ["worktree", "add", "-q", "-b", "linked-candidate", linked]);
  fs.writeFileSync(path.join(linked, "tracked.txt"), "dirty\n");
  git(linked, ["update-index", splitIndex ? "--split-index" : "--no-split-index"]);
  assert.equal(
    ((git(linked, ["rev-parse", "--shared-index-path"]) as string).trim() !== ""),
    splitIndex,
    `fixture did not enter ${mode} index mode`,
  );
  const headA = (git(linked, ["rev-parse", "HEAD"]) as string).trim();
  git(main, ["commit", "-q", "--allow-empty", "-m", "alternate same-tree head"]);
  const headB = (git(main, ["rev-parse", "HEAD"]) as string).trim();
  assert.notEqual(headA, headB);
  const gitDirectoryA = fs.realpathSync(
    (git(linked, ["rev-parse", "--absolute-git-dir"]) as string).trim(),
  );
  const gitDirectoryB = `${gitDirectoryA}-b`;
  fs.cpSync(gitDirectoryA, gitDirectoryB, { preserveTimestamps: true, recursive: true });
  fs.writeFileSync(path.join(gitDirectoryB, "HEAD"), `${headB}\n`);
  const gitfilePath = path.join(linked, ".git");
  const gitfileBefore = fs.readFileSync(gitfilePath, "utf8");
  const gitfileInode = fs.lstatSync(gitfilePath, { bigint: true }).ino;
  const indexPath = fs.realpathSync(path.join(gitDirectoryA, "index"));
  const openDescriptor = Object.getOwnPropertyDescriptor(fs, "openSync");
  assert.ok(openDescriptor !== undefined);
  const originalOpen = fs.openSync;
  let indexOpens = 0;
  let closeoutIndexOpens: number | null = null;
  let rewriteAt: number | null = null;
  let rewritten = false;
  let first: Capture | null = null;
  let second: Capture | null = null;
  let refusal: WorkspaceError | null = null;
  try {
    Object.defineProperty(fs, "openSync", {
      ...openDescriptor,
      value: (...args: Parameters<typeof fs.openSync>) => {
        const flags = typeof args[1] === "number" ? args[1] : 0;
        if (
          typeof args[0] === "string" && path.resolve(args[0]) === indexPath &&
          (flags & (fs.constants.O_WRONLY | fs.constants.O_RDWR | fs.constants.O_CREAT)) === 0
        ) {
          indexOpens += 1;
          if (rewriteAt !== null && indexOpens === rewriteAt && !rewritten) {
            rewritten = true;
            fs.writeFileSync(gitfilePath, `gitdir: ${gitDirectoryB}\n`);
          }
        }
        return Reflect.apply(originalOpen, fs, args) as number;
      },
    });
    first = workspace.captureAndSealCandidate({
      custodyRoot: custodyOne,
      hooks: {
        afterPreSealObservation() { closeoutIndexOpens = indexOpens; },
      },
      maxAttempts: 1,
      sourceRoot: linked,
    });
    assert.equal(first.sourceSnapshot.git.head, headA);
    assert.ok(
      closeoutIndexOpens !== null && closeoutIndexOpens >= 2,
      "the first capture did not reach the linked pre-seal closeout boundary",
    );
    assert.ok(
      indexOpens > closeoutIndexOpens,
      "calibration did not reach the linked capability-time source verification",
    );
    const calibratedIndexOpens = closeoutIndexOpens;
    rewriteAt = calibratedIndexOpens;
    indexOpens = 0;
    try {
      second = workspace.captureAndSealCandidate({
        custodyRoot: custodyTwo,
        maxAttempts: 1,
        sourceRoot: linked,
      });
    } catch (error) {
      refusal = error as WorkspaceError;
    }
    assert.equal(rewritten, true, "the gitfile rewrite was not reached at the final pre-seal index open");
    assert.equal(
      indexOpens,
      calibratedIndexOpens,
      "the attacked run did not reach the same terminal index-open boundary as calibration",
    );
    assert.equal(fs.lstatSync(gitfilePath, { bigint: true }).ino, gitfileInode, "gitfile inode changed");
    assert.equal(fs.readFileSync(gitfilePath, "utf8"), `gitdir: ${gitDirectoryB}\n`);
    assert.equal((git(linked, ["rev-parse", "HEAD"]) as string).trim(), headB);
    if (second !== null) {
      assert.equal(
        second.sourceSnapshot.git.head,
        headB,
        "capture sealed a HEAD the live worktree no longer has",
      );
    }
    assert.equal(second, null, "capture accepted a rewritten root gitfile after its final read");
    assert.equal(refusal?.code, workspaceErrorCode("SNAPSHOT_UNSTABLE"), errorChain(refusal));
    assert.equal(refusal?.details?.lastCode, workspaceErrorCode("SOURCE_CHANGED"));
    assert.deepEqual(
      regularFilesBelow(custodyTwo).filter((file) =>
        ["candidate-manifest.json", "state.json"].includes(path.basename(file))),
      [],
    );
  } finally {
    Object.defineProperty(fs, "openSync", openDescriptor);
    if (pathExistsNoFollow(gitfilePath)) fs.writeFileSync(gitfilePath, gitfileBefore);
    cleanupReportedScratchRoots(reportedPrivateRoots(first));
    cleanupReportedScratchRoots(reportedPrivateRoots(second));
    cleanupReportedScratchRoots(errorPrivateRoots(refusal));
    removeFixturePath(fixtureRoot);
    removeFixturePath(custodyOne);
    removeFixturePath(custodyTwo);
  }
}

test("a same-inode gitfile rewrite at the final closeout cannot seal a stale linked topology", async (t) => {
  await t.test("full index", () => runGitfileCloseoutRewriteCase(false));
  await t.test("split index", () => runGitfileCloseoutRewriteCase(true));
});

test("terminal topology resolution rejects an unchanged gitfile whose symlink ancestor retargets", () => {
  const fixtureRoot = privateTemp("noa-kws-gitfile-alias-retarget-");
  const calibrationCustody = privateTemp("noa-kws-gitfile-alias-retarget-custody-1-");
  const attackedCustody = privateTemp("noa-kws-gitfile-alias-retarget-custody-2-");
  const main = path.join(fixtureRoot, "main");
  const linked = path.join(fixtureRoot, "linked");
  fs.mkdirSync(main, { mode: 0o700 });
  initRepository(main);
  fs.writeFileSync(path.join(main, "tracked.txt"), "base\n", { mode: 0o600 });
  git(main, ["add", "--all"]);
  git(main, ["commit", "-q", "-m", "gitfile alias base"]);
  git(main, ["worktree", "add", "-q", "-b", "linked-candidate", linked]);
  fs.writeFileSync(path.join(linked, "tracked.txt"), "dirty\n", { mode: 0o600 });
  const headA = (git(linked, ["rev-parse", "HEAD"]) as string).trim();
  git(main, ["commit", "-q", "--allow-empty", "-m", "gitfile alias alternate"]);
  const headB = (git(main, ["rev-parse", "HEAD"]) as string).trim();
  assert.notEqual(headA, headB);
  const gitDirectoryA = fs.realpathSync(
    (git(linked, ["rev-parse", "--absolute-git-dir"]) as string).trim(),
  );
  const alternateParent = path.join(fixtureRoot, "alternate-worktrees");
  const gitDirectoryB = path.join(alternateParent, path.basename(gitDirectoryA));
  fs.mkdirSync(alternateParent, { mode: 0o700 });
  fs.cpSync(gitDirectoryA, gitDirectoryB, { preserveTimestamps: true, recursive: true });
  fs.writeFileSync(path.join(gitDirectoryB, "HEAD"), `${headB}\n`, { mode: 0o600 });
  fs.writeFileSync(path.join(gitDirectoryB, "commondir"), `${path.join(main, ".git")}\n`, {
    mode: 0o600,
  });
  const alias = path.join(fixtureRoot, "gitdir-parent-alias");
  fs.symlinkSync(path.dirname(gitDirectoryA), alias, "dir");
  const gitfilePath = path.join(linked, ".git");
  fs.writeFileSync(gitfilePath, `gitdir: ${path.join(alias, path.basename(gitDirectoryA))}\n`);
  const gitfileBefore = fs.readFileSync(gitfilePath);
  const gitfileInode = fs.lstatSync(gitfilePath, { bigint: true }).ino;
  const attributesPath = path.join(main, ".git", "info", "attributes");
  fs.mkdirSync(path.dirname(attributesPath), { mode: 0o700, recursive: true });
  fs.writeFileSync(attributesPath, "# terminal topology boundary\n", { mode: 0o600 });
  assert.equal((git(linked, ["rev-parse", "HEAD"]) as string).trim(), headA);
  try {
    runCalibratedFinalReadMutation({
      assertAfterMutation: () => {
        assert.deepEqual(fs.readFileSync(gitfilePath), gitfileBefore, "root gitfile bytes changed");
        assert.equal(fs.lstatSync(gitfilePath, { bigint: true }).ino, gitfileInode);
        assert.equal((git(linked, ["rev-parse", "HEAD"]) as string).trim(), headB);
      },
      attackedCustody,
      boundaryPath: attributesPath,
      calibrationCustody,
      expectedLastCode: workspaceErrorCode("SOURCE_CHANGED"),
      mutate: () => {
        fs.unlinkSync(alias);
        fs.symlinkSync(alternateParent, alias, "dir");
      },
      source: linked,
    });
  } finally {
    removeFixturePath(fixtureRoot);
    removeFixturePath(calibrationCustody);
    removeFixturePath(attackedCustody);
  }
});

test("private-tree release is one-shot, attempts every close, and cannot close a reused fd", () => {
  const fixture = minimalCaptureFixture("private-release-one-shot");
  const sentinelPath = path.join(fixture.source, "sentinel.txt");
  fs.writeFileSync(sentinelPath, "sentinel\n", { mode: 0o600 });
  const openDescriptor = Object.getOwnPropertyDescriptor(fs, "openSync");
  const closeDescriptor = Object.getOwnPropertyDescriptor(fs, "closeSync");
  assert.ok(openDescriptor !== undefined);
  assert.ok(closeDescriptor !== undefined);
  const originalOpen = fs.openSync;
  const originalClose = fs.closeSync;
  type DescriptorRecord = { closeCount: number; fd: number; generation: number; path: string };
  const records: DescriptorRecord[] = [];
  const liveByFd = new Map<number, DescriptorRecord>();
  let generation = 0;
  let target: DescriptorRecord | null = null;
  let injected = false;
  let sentinelFd: number | null = null;
  let sentinelCloseAttempts = 0;
  let refusal: WorkspaceError | null = null;
  try {
    Object.defineProperty(fs, "openSync", {
      ...openDescriptor,
      value: (...args: Parameters<typeof fs.openSync>) => {
        const fd = Reflect.apply(originalOpen, fs, args) as number;
        if (
          typeof args[0] === "string" &&
          path.basename(path.resolve(args[0])).startsWith("noa-kws-git-observe-")
        ) {
          const openedPath = path.resolve(args[0]);
          const record: DescriptorRecord = { closeCount: 0, fd, generation: generation++, path: openedPath };
          const samePathAlreadyHeld = [...liveByFd.values()].some((candidate) =>
            candidate.path === openedPath);
          records.push(record);
          liveByFd.set(fd, record);
          if (target === null && samePathAlreadyHeld) target = record;
        }
        return fd;
      },
    });
    Object.defineProperty(fs, "closeSync", {
      ...closeDescriptor,
      value: (fd: number) => {
        if (injected && fd === sentinelFd) sentinelCloseAttempts += 1;
        const record = liveByFd.get(fd);
        const result = originalClose(fd);
        if (record !== undefined) {
          record.closeCount += 1;
          liveByFd.delete(fd);
        }
        if (!injected && record !== undefined && record === target) {
          injected = true;
          sentinelFd = originalOpen(sentinelPath, fs.constants.O_RDONLY);
          assert.equal(sentinelFd, fd, "the injected close did not reuse the released fd generation");
          throw Object.assign(new Error("simulated private witness close failure"), { code: "EIO" });
        }
        return result;
      },
    });
    try {
      workspace.captureAndSealCandidate({
        custodyRoot: fixture.custody,
        maxAttempts: 1,
        sourceRoot: fixture.source,
      });
      assert.fail("capture returned after a private witness close failure");
    } catch (error) {
      refusal = error as WorkspaceError;
    }
    assert.notEqual(target, null, "the concurrently held private-tree root was not identified");
    assert.equal(injected, true, "the private-tree close failure was not injected");
    assert.equal(sentinelCloseAttempts, 0, "a stale closer acted on the reused fd generation");
    assert.doesNotThrow(() => fs.fstatSync(sentinelFd!));
    assert.equal(target!.closeCount, 1);
    assert.equal(records.some((record) => record.closeCount > 1), false);
    assert.equal(liveByFd.size, 0, "a private-tree descriptor leaked after aggregate cleanup");
    assert.equal(errorTreeHasCode(refusal, workspaceErrorCode("PRIVATE_ROOT_UNSAFE")), true, errorChain(refusal));
    assert.deepEqual(
      regularFilesBelow(fixture.custody).filter((file) =>
        ["candidate-manifest.json", "state.json"].includes(path.basename(file))),
      [],
    );
  } finally {
    Object.defineProperty(fs, "openSync", openDescriptor);
    Object.defineProperty(fs, "closeSync", closeDescriptor);
    if (sentinelFd !== null) {
      try { originalClose(sentinelFd); }
      catch {}
    }
    cleanupReportedScratchRoots(errorPrivateRoots(refusal));
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
  }
});

test("private observation FD exhaustion is a bounded resource refusal", () => {
  const fixture = minimalCaptureFixture("private-witness-emfile");
  const openDescriptor = Object.getOwnPropertyDescriptor(fs, "openSync");
  const closeDescriptor = Object.getOwnPropertyDescriptor(fs, "closeSync");
  assert.ok(openDescriptor !== undefined);
  assert.ok(closeDescriptor !== undefined);
  const originalOpen = fs.openSync;
  const originalClose = fs.closeSync;
  const liveDirectoryByFd = new Map<number, string>();
  let injected = false;
  let refusal: WorkspaceError | null = null;
  try {
    Object.defineProperty(fs, "openSync", {
      ...openDescriptor,
      value: (...args: Parameters<typeof fs.openSync>) => {
        const flags = typeof args[1] === "number" ? args[1] : 0;
        if (typeof args[0] === "string" && (flags & fs.constants.O_DIRECTORY) !== 0) {
          const absolute = path.resolve(args[0]);
          if (
            !injected &&
            path.basename(absolute).startsWith("noa-kws-git-observe-") &&
            [...liveDirectoryByFd.values()].includes(absolute)
          ) {
            injected = true;
            throw Object.assign(new Error("simulated private witness descriptor exhaustion"), {
              code: "EMFILE",
            });
          }
          const fd = Reflect.apply(originalOpen, fs, args) as number;
          if (path.basename(absolute).startsWith("noa-kws-git-observe-")) {
            liveDirectoryByFd.set(fd, absolute);
          }
          return fd;
        }
        return Reflect.apply(originalOpen, fs, args) as number;
      },
    });
    Object.defineProperty(fs, "closeSync", {
      ...closeDescriptor,
      value: (fd: number) => {
        const result = originalClose(fd);
        liveDirectoryByFd.delete(fd);
        return result;
      },
    });
    assert.throws(
      () => workspace.captureAndSealCandidate({
        custodyRoot: fixture.custody,
        maxAttempts: 1,
        sourceRoot: fixture.source,
      }),
      (error: WorkspaceError) => {
        refusal = error;
        return error.code === workspaceErrorCode("RESOURCE_LIMIT_EXCEEDED") &&
          causeWithCode(error, "EMFILE") !== null;
      },
    );
    assert.equal(injected, true, "private witness descriptor exhaustion was not injected");
    assert.deepEqual(
      regularFilesBelow(fixture.custody).filter((file) =>
        ["candidate-manifest.json", "state.json"].includes(path.basename(file))),
      [],
    );
  } finally {
    Object.defineProperty(fs, "openSync", openDescriptor);
    Object.defineProperty(fs, "closeSync", closeDescriptor);
    cleanupReportedScratchRoots(errorPrivateRoots(refusal));
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
  }
});

test("cleanup failure preserves the primary Git-layout refusal and releases later bounds", () => {
  const fixture = minimalCaptureFixture("primary-plus-release-failure");
  const excluded = path.join(fixture.source, "unsupported-global-ignore");
  fs.writeFileSync(excluded, "ignored\n", { mode: 0o600 });
  git(fixture.source, ["config", "--local", "core.excludesFile", excluded]);
  const gitDirectory = fs.realpathSync(path.join(fixture.source, ".git"));
  const sentinelPath = path.join(fixture.source, "tracked.txt");
  const openDescriptor = Object.getOwnPropertyDescriptor(fs, "openSync");
  const closeDescriptor = Object.getOwnPropertyDescriptor(fs, "closeSync");
  assert.ok(openDescriptor !== undefined);
  assert.ok(closeDescriptor !== undefined);
  const originalOpen = fs.openSync;
  const originalClose = fs.closeSync;
  type BoundRecord = { closeCount: number; fd: number };
  let target: BoundRecord | null = null;
  let injected = false;
  let sentinelFd: number | null = null;
  let sentinelCloseAttempts = 0;
  let refusal: WorkspaceError | null = null;
  try {
    Object.defineProperty(fs, "openSync", {
      ...openDescriptor,
      value: (...args: Parameters<typeof fs.openSync>) => {
        const fd = Reflect.apply(originalOpen, fs, args) as number;
        const flags = typeof args[1] === "number" ? args[1] : 0;
        if (
          target === null && typeof args[0] === "string" &&
          path.resolve(args[0]) === gitDirectory &&
          (flags & fs.constants.O_DIRECTORY) !== 0
        ) target = { closeCount: 0, fd };
        return fd;
      },
    });
    Object.defineProperty(fs, "closeSync", {
      ...closeDescriptor,
      value: (fd: number) => {
        if (injected && fd === sentinelFd) sentinelCloseAttempts += 1;
        const result = originalClose(fd);
        if (target !== null && fd === target.fd) {
          target.closeCount += 1;
          if (!injected) {
            injected = true;
            sentinelFd = originalOpen(sentinelPath, fs.constants.O_RDONLY);
            assert.equal(sentinelFd, fd, "the injected bound close did not reuse its fd generation");
            throw Object.assign(new Error("simulated Git-directory close failure"), { code: "EIO" });
          }
        }
        return result;
      },
    });
    try {
      workspace.captureAndSealCandidate({
        custodyRoot: fixture.custody,
        maxAttempts: 1,
        sourceRoot: fixture.source,
      });
      assert.fail("capture returned despite unsupported config and close failure");
    } catch (error) {
      refusal = error as WorkspaceError;
    }
    assert.equal(refusal?.code, workspaceErrorCode("SOURCE_GIT_LAYOUT_UNSUPPORTED"), errorChain(refusal));
    assert.equal(injected, true, "the Git-directory close failure was not injected");
    const targetRecord = target as BoundRecord | null;
    assert.notEqual(targetRecord, null, "the Git-directory bound descriptor was not identified");
    assert.equal(targetRecord!.closeCount, 1);
    assert.equal(sentinelCloseAttempts, 0, "a stale bound closer acted on the reused fd generation");
    assert.doesNotThrow(() => fs.fstatSync(sentinelFd!));
    assert.equal(
      (refusal?.details as { secondaryFailureCount?: number } | null)?.secondaryFailureCount,
      1,
      errorChain(refusal),
    );
    assert.equal(errorTreeHasCode(refusal, workspaceErrorCode("SOURCE_GIT_LAYOUT_UNSUPPORTED")), true);
    assert.deepEqual(
      regularFilesBelow(fixture.custody).filter((file) =>
        ["candidate-manifest.json", "state.json"].includes(path.basename(file))),
      [],
    );
  } finally {
    Object.defineProperty(fs, "openSync", openDescriptor);
    Object.defineProperty(fs, "closeSync", closeDescriptor);
    if (sentinelFd !== null) {
      try { originalClose(sentinelFd); }
      catch {}
    }
    cleanupReportedScratchRoots(errorPrivateRoots(refusal));
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
  }
});

test("two unstable source attempts refuse with SNAPSHOT_UNSTABLE and never restore source", () => {
  const source = privateTemp("noa-kws-drift-source-");
  const custody = privateTemp("noa-kws-drift-custody-");
  let refusal: WorkspaceError | null = null;
  try {
    initRepository(source);
    fs.writeFileSync(path.join(source, "drift.txt"), "base\n");
    git(source, ["add", "--all"]);
    git(source, ["commit", "-q", "-m", "drift base"]);
    const indexBefore = fs.readFileSync(path.join(source, ".git", "index"));
    const attempts: number[] = [];
    assert.throws(
      () => workspace.captureAndSealCandidate({
        sourceRoot: source,
        custodyRoot: custody,
        hooks: {
          afterPreObservation({ attempt }) {
            attempts.push(attempt);
            fs.writeFileSync(path.join(source, "drift.txt"), `drift-${attempt}\n`);
          },
        },
      }),
      (error: WorkspaceError) => {
        refusal = error;
        return error.code === workspace.KNOCKOUT_WORKSPACE_ERROR_CODES.SNAPSHOT_UNSTABLE;
      },
    );
    assert.deepEqual(attempts, [1, 2]);
    assert.equal(fs.readFileSync(path.join(source, "drift.txt"), "utf8"), "drift-2\n");
    assert.deepEqual(fs.readFileSync(path.join(source, ".git", "index")), indexBefore);
    const roots = errorPrivateRoots(refusal);
    const custodyPhysical = fs.realpathSync(custody);
    const directEntries = [...new Set(roots
      .filter((root) => path.dirname(root.path) === custodyPhysical)
      .map((root) => path.basename(root.path)))].sort();
    assert.equal(directEntries.length, 4);
    assert.deepEqual(fs.readdirSync(custody).sort(), directEntries);
  } finally {
    cleanupReportedScratchRoots(errorPrivateRoots(refusal));
    fs.rmSync(source, { recursive: true, force: true });
    fs.rmSync(custody, { recursive: true, force: true });
  }
});

test("retry admission preserves instability taxonomy when the deadline cannot fund another attempt", () => {
  const fixture = minimalCaptureFixture("retry-deadline-admission");
  const clockDescriptor = Object.getOwnPropertyDescriptor(process.hrtime, "bigint");
  assert.ok(clockDescriptor !== undefined);
  const originalClock = process.hrtime.bigint;
  const attempts: number[] = [];
  let virtualOffsetNs = 0n;
  let refusal: WorkspaceError | null = null;
  try {
    try {
      Object.defineProperty(process.hrtime, "bigint", {
        ...clockDescriptor,
        value: () => originalClock() + virtualOffsetNs,
      });
      assert.throws(
        () => workspace.captureAndSealCandidate({
          commandTimeoutMs: 60_000,
          custodyRoot: fixture.custody,
          hooks: {
            afterPreObservation({ attempt }) {
              attempts.push(attempt);
              if (attempt === 1) {
                fs.writeFileSync(fixture.trackedPath, "first attempt drift\n", { mode: 0o600 });
                virtualOffsetNs = 45_000_000_000n;
              } else {
                virtualOffsetNs = 61_000_000_000n;
              }
            },
          },
          sourceRoot: fixture.source,
        }),
        (error: WorkspaceError) => {
          refusal = error;
          return error.code === workspaceErrorCode("SNAPSHOT_UNSTABLE");
        },
      );
    } finally {
      Object.defineProperty(process.hrtime, "bigint", clockDescriptor);
    }
    assert.deepEqual(attempts, [1], "capture started a retry its remaining deadline could not fund");
    const observedRefusal = refusal as WorkspaceError | null;
    assert.equal(observedRefusal?.details?.attempts, 1);
    assert.equal(observedRefusal?.details?.maxAttempts, 2);
    assert.equal(observedRefusal?.details?.lastCode, workspaceErrorCode("SNAPSHOT_UNSTABLE"));
    assert.equal(observedRefusal?.details?.retrySkipped, "INSUFFICIENT_REMAINING_DEADLINE");
  } finally {
    cleanupReportedScratchRoots(errorPrivateRoots(refusal));
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
  }
});

test("an admitted retry preserves prior instability when the shared deadline expires", () => {
  const fixture = minimalCaptureFixture("retry-deadline-overrun");
  const clockDescriptor = Object.getOwnPropertyDescriptor(process.hrtime, "bigint");
  assert.ok(clockDescriptor !== undefined);
  const operationTimeoutMs = 60_000;
  const attempts: number[] = [];
  let virtualNowNs = 0n;
  let refusal: WorkspaceError | null = null;
  try {
    try {
      Object.defineProperty(process.hrtime, "bigint", {
        ...clockDescriptor,
        value: () => virtualNowNs,
      });
      assert.throws(
        () => workspace.captureAndSealCandidate({
          commandTimeoutMs: 60_000,
          custodyRoot: fixture.custody,
          hooks: {
            afterPreObservation({ attempt }) {
              attempts.push(attempt);
              if (attempt === 1) {
                fs.writeFileSync(fixture.trackedPath, "first attempt drift\n", { mode: 0o600 });
                virtualNowNs = 20_000_000_000n;
              } else {
                virtualNowNs = 61_000_000_000n;
              }
            },
          },
          operationTimeoutMs,
          sourceRoot: fixture.source,
        }),
        (error: WorkspaceError) => {
          refusal = error;
          return error.code === workspaceErrorCode("SNAPSHOT_UNSTABLE");
        },
      );
    } finally {
      Object.defineProperty(process.hrtime, "bigint", clockDescriptor);
    }
    assert.deepEqual(attempts, [1, 2]);
    const observedRefusal = refusal as WorkspaceError | null;
    assert.equal(observedRefusal?.details?.attempts, 2);
    assert.equal(observedRefusal?.details?.lastCode, workspaceErrorCode("SNAPSHOT_UNSTABLE"));
    assert.equal(
      observedRefusal?.details?.retryDeadlineCode,
      workspaceErrorCode("OPERATION_DEADLINE_EXCEEDED"),
    );
    assert.equal(observedRefusal?.details?.retrySkipped, "ADMITTED_RETRY_DEADLINE_EXCEEDED");
    assert.equal(
      errorTreeHasCode(refusal, workspaceErrorCode("OPERATION_DEADLINE_EXCEEDED")),
      true,
    );
  } finally {
    cleanupReportedScratchRoots(errorPrivateRoots(refusal));
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
  }
});

test("source census failure reports the already-created private Git observation scratch", () => {
  const fixture = minimalCaptureFixture("source-census-retention");
  let refusal: WorkspaceError | null = null;
  try {
    fs.mkdirSync(path.join(fixture.source, "nested", ".git"), { mode: 0o700 });
    assert.throws(
      () => workspace.captureAndSealCandidate({
        custodyRoot: fixture.custody,
        maxAttempts: 1,
        sourceRoot: fixture.source,
      }),
      (error: WorkspaceError) => {
        refusal = error;
        return error.code === workspaceErrorCode("NESTED_GIT_REPOSITORY");
      },
    );
    const scratch = errorPrivateRoots(refusal).filter((entry) =>
      path.basename(entry.path).startsWith("noa-kws-git-observe-"));
    assert.equal(scratch.length, 1, "Git observation scratch custody was lost");
    const stat = fs.lstatSync(scratch[0]!.path, { bigint: true });
    assert.equal(`${stat.dev}:${stat.ino}`, scratch[0]!.identity);
    assert.equal(Number(stat.mode & 0o7777n), 0o700);
    assert.deepEqual(fs.readdirSync(fixture.custody), [path.basename(scratch[0]!.path)]);
  } finally {
    cleanupReportedScratchRoots(errorPrivateRoots(refusal));
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
  }
});

test("split-index special, missing, and unresolved companions fail closed without source repair", async (t) => {
  const cases: Array<{
    expectedCode: string;
    mutate: (fixture: ReturnType<typeof splitIndexFixture>) => string | null;
    name: string;
  }> = [
    {
      name: "selected companion symlink",
      expectedCode: workspaceErrorCode("SPECIAL_NODE_UNSUPPORTED"),
      mutate(fixture) {
        fs.unlinkSync(fixture.sharedPath);
        fs.symlinkSync("index", fixture.sharedPath);
        assert.equal(fs.lstatSync(fixture.sharedPath).isSymbolicLink(), true);
        return null;
      },
    },
    {
      name: "selected companion FIFO",
      expectedCode: workspaceErrorCode("SPECIAL_NODE_UNSUPPORTED"),
      mutate(fixture) {
        fs.unlinkSync(fixture.sharedPath);
        execFileSync("/usr/bin/mkfifo", [fixture.sharedPath]);
        assert.equal(fs.lstatSync(fixture.sharedPath).isFIFO(), true);
        return null;
      },
    },
    {
      name: "selected companion missing before discovery",
      expectedCode: workspaceErrorCode("SOURCE_INDEX_UNSUPPORTED"),
      mutate(fixture) {
        fs.unlinkSync(fixture.sharedPath);
        assert.equal(fs.existsSync(fixture.sharedPath), false);
        return null;
      },
    },
    {
      name: "private discovery resolves no copied candidate",
      expectedCode: workspaceErrorCode("SOURCE_GIT_LAYOUT_UNSUPPORTED"),
      mutate(fixture) {
        const actualIdentity = fixture.sharedBasename.slice("sharedindex.".length);
        const fakeIdentity = actualIdentity === "a".repeat(40) ? "b".repeat(40) : "a".repeat(40);
        const marker = path.join(fixture.tools, "shared-path-intercepted");
        const shim = path.join(fixture.tools, "git-shim");
        fs.writeFileSync(shim, [
          "#!/bin/sh",
          "for argument in \"$@\"; do",
          "  if [ \"$argument\" = \"--shared-index-path\" ]; then",
          `    /usr/bin/printf x >> ${JSON.stringify(marker)}`,
          `    /usr/bin/printf '%s\\n' ${JSON.stringify(`sharedindex.${fakeIdentity}`)}`,
          "    exit 0",
          "  fi",
          "done",
          `exec ${JSON.stringify(gitExecutable)} \"$@\"`,
          "",
        ].join("\n"), { mode: 0o700 });
        return shim;
      },
    },
  ];

  for (const fixtureCase of cases) {
    await t.test(fixtureCase.name, () => {
      const fixture = splitIndexFixture(fixtureCase.name.replaceAll(" ", "-"));
      let refusal: WorkspaceError | null = null;
      try {
        const indexBefore = fs.readFileSync(fixture.indexPath);
        const gitOverride = fixtureCase.mutate(fixture);
        assert.throws(
          () => workspace.captureAndSealCandidate({
            sourceRoot: fixture.source,
            custodyRoot: fixture.custody,
            gitExecutable: gitOverride ?? undefined,
            maxAttempts: 1,
          }),
          (error: WorkspaceError) => {
            refusal = error;
            return error.code === fixtureCase.expectedCode;
          },
        );
        assert.deepEqual(
          fs.readFileSync(fixture.indexPath),
          indexBefore,
          `${fixtureCase.name} changed the source raw index`,
        );
        const custodyPhysical = fs.realpathSync(fixture.custody);
        const directEntries = [...new Set(errorPrivateRoots(refusal)
          .filter((root) => path.dirname(root.path) === custodyPhysical)
          .map((root) => path.basename(root.path)))].sort();
        assert.deepEqual(fs.readdirSync(fixture.custody).sort(), directEntries);
        if (gitOverride !== null) {
          assert.equal(
            fs.readFileSync(path.join(fixture.tools, "shared-path-intercepted"), "utf8"),
            "x",
            "the exact-cardinality interception did not execute",
          );
        }
      } finally {
        cleanupReportedScratchRoots(errorPrivateRoots(refusal));
        fs.rmSync(fixture.source, { recursive: true, force: true });
        fs.rmSync(fixture.custody, { recursive: true, force: true });
        fs.rmSync(fixture.tools, { recursive: true, force: true });
      }
    });
  }
});

test("failure custody retains a pre-state replacement without publishing SEALED state", () => {
  const source = privateTemp("noa-kws-cleanup-race-source-");
  const custody = privateTemp("noa-kws-cleanup-race-custody-");
  const replacement = privateTemp("noa-kws-cleanup-race-replacement-");
  const markerName = "must-survive.txt";
  fs.writeFileSync(path.join(replacement, markerName), "replacement marker\n", { mode: 0o600 });
  const rmDescriptor = Object.getOwnPropertyDescriptor(fs, "rmSync");
  assert.ok(rmDescriptor !== undefined);
  const originalRm = fs.rmSync;
  let deleteAttempted = false;
  let originalTree: string | null = null;
  let refusal: WorkspaceError | null = null;
  let replacementTarget: string | null = null;
  let replacedIdentity: string | null = null;
  try {
    initRepository(source);
    const tracked = path.join(source, "tracked.txt");
    fs.writeFileSync(tracked, "base\n");
    git(source, ["add", "--all"]);
    git(source, ["commit", "-q", "-m", "cleanup race base"]);

    Object.defineProperty(fs, "rmSync", {
      ...rmDescriptor,
      value(...args: unknown[]) {
        if (replacementTarget !== null && String(args[0]) === replacementTarget) {
          deleteAttempted = true;
        }
        return Reflect.apply(originalRm, fs, args);
      },
    });

    assert.throws(
      () => workspace.captureAndSealCandidate({
        sourceRoot: source,
        custodyRoot: custody,
        maxAttempts: 1,
        hooks: {
          beforeStatePublication({ statePath, workspaceRoot }) {
            assert.equal(pathExistsNoFollow(statePath), false);
            const target = path.dirname(workspaceRoot);
            const stat = fs.lstatSync(target, { bigint: true });
            replacedIdentity = `${stat.dev}:${stat.ino}`;
            replacementTarget = target;
            originalTree = `${target}.identity-checked-original`;
            fs.renameSync(target, originalTree);
            fs.renameSync(replacement, target);
          },
        },
      }),
      (error: WorkspaceError) => {
        refusal = error;
        return error.code === workspace.KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE;
      },
    );
  } finally {
    Object.defineProperty(fs, "rmSync", rmDescriptor);
  }
  try {
    const observedTarget = requiredString(
      replacementTarget,
      "pre-state replacement did not execute",
    );
    const observedOriginal = requiredString(
      originalTree,
      "the checked generated tree was not preserved",
    );
    const observedIdentity = requiredString(
      replacedIdentity,
      "the checked generated-tree identity was not recorded",
    );
    assert.equal(deleteAttempted, false, "module attempted pathname-recursive failure cleanup");
    assert.equal(fs.existsSync(path.join(observedTarget, markerName)), true);
    assert.equal(fs.existsSync(observedOriginal), true);
    assert.equal(
      pathExistsNoFollow(path.join(observedOriginal, "evidence", "state.json")),
      false,
      "failed pre-state replacement retained a SEALED state",
    );
    const retained = errorPrivateRoots(refusal).find((root) => root.path === observedTarget);
    assert.ok(retained !== undefined, "failure did not report the identity-bound retained root");
    assert.equal(retained.identity, observedIdentity);
    const current = fs.lstatSync(observedTarget, { bigint: true });
    assert.notEqual(`${current.dev}:${current.ino}`, retained.identity);
  } finally {
    cleanupReportedScratchRoots(errorPrivateRoots(refusal));
    fs.rmSync(source, { recursive: true, force: true });
    fs.rmSync(custody, { recursive: true, force: true });
    if (fs.existsSync(replacement)) fs.rmSync(replacement, { recursive: true, force: true });
  }
});

test("terminal publication retains PREPARED residue but never accepts partial evidence or clobbers", () => {
  const partialDirectory = privateTemp("noa-kws-terminal-partial-");
  const successDirectory = privateTemp("noa-kws-terminal-success-");
  const terminal = {
    candidateManifestSha256: "a".repeat(64),
    protocol: workspace.KNOCKOUT_WORKSPACE_PROTOCOLS.terminal,
    status: "PASS",
  };
  try {
    let partialError: WorkspaceError | null = null;
    assert.throws(
      () => publishTerminalEvidence({
        directory: partialDirectory,
        terminal,
        simulateShortWriteAfterBytes: 5,
      }),
      (error: WorkspaceError) => {
        partialError = error;
        return error.code === workspace.KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_INCOMPLETE;
      },
    );
    const partialPath = path.join(fs.realpathSync(partialDirectory), "terminal.json");
    const partialStat = fs.lstatSync(partialPath, { bigint: true });
    assert.equal(Number(partialStat.mode & 0o7777n), 0o000);
    assert.equal(Number(partialStat.nlink), 1);
    const retained = errorTerminalPublication(partialError);
    assert.ok(retained !== null, "PREPARED residue was not reported");
    assert.equal(retained.path, partialPath);
    assert.equal(retained.createdIdentity, `${partialStat.dev}:${partialStat.ino}`);
    assert.equal(retained.currentIdentity, retained.createdIdentity);
    assert.equal(retained.phase, "PREPARED");
    assert.throws(
      () => reopenTerminalEvidence(
        partialPath,
        retained.expectedSha256,
        fileObservationForTest(partialPath),
      ),
      (error: WorkspaceError) =>
        error.code === workspace.KNOCKOUT_WORKSPACE_ERROR_CODES.PRIVATE_ROOT_UNSAFE,
    );

    const published = publishTerminalEvidence({ directory: successDirectory, terminal });
    assert.equal(published.terminal.status, "PASS");
    assert.equal(published.identityVerified, true);
    assert.match(published.sha256, /^[0-9a-f]{64}$/);
    const publishedStat = fs.statSync(published.path, { bigint: true });
    assert.equal(Number(publishedStat.mode & 0o7777n), 0o600);
    assert.equal(Number(publishedStat.nlink), 1);
    assert.equal(published.createdIdentity, `${publishedStat.dev}:${publishedStat.ino}`);
    assert.equal(published.createdObservation.identity, published.createdIdentity);
    const reopened = reopenTerminalEvidence(
      published.path,
      published.sha256,
      published.createdObservation,
    );
    assert.equal(reopened.identityVerified, true);
    assert.equal(reopened.identity, published.createdIdentity);
    assert.deepEqual(reopened.terminal, published.terminal);
    assert.throws(
      () => publishTerminalEvidence({ directory: successDirectory, terminal }),
      (error: WorkspaceError) => error.code === workspace.KNOCKOUT_WORKSPACE_ERROR_CODES.TERMINAL_EXISTS,
    );
  } finally {
    fs.rmSync(partialDirectory, { recursive: true, force: true });
    fs.rmSync(successDirectory, { recursive: true, force: true });
  }
});

test("terminal publication binds the private directory before creating any inode", async (t) => {
  const terminal = {
    candidateManifestSha256: "d".repeat(64),
    protocol: workspace.KNOCKOUT_WORKSPACE_PROTOCOLS.terminal,
    status: "PASS",
  };

  const preOpenCases: Array<{
    label: string;
    replace: (physicalDirectory: string, movedOriginal: string) => string[];
  }> = [
    {
      label: "symlink to directory",
      replace: (physicalDirectory, movedOriginal) => {
        fs.symlinkSync(movedOriginal, physicalDirectory);
        return [];
      },
    },
    {
      label: "symlink to file",
      replace: (physicalDirectory, _movedOriginal) => {
        const target = `${physicalDirectory}.symlink-target`;
        fs.writeFileSync(target, "target\n", { mode: 0o600 });
        fs.symlinkSync(target, physicalDirectory);
        return [target];
      },
    },
    { label: "removed", replace: () => [] },
    {
      label: "mode 0755 directory",
      replace: (physicalDirectory) => {
        fs.mkdirSync(physicalDirectory, { mode: 0o755 });
        fs.chmodSync(physicalDirectory, 0o755);
        return [];
      },
    },
    {
      label: "different mode 0700 directory",
      replace: (physicalDirectory) => {
        fs.mkdirSync(physicalDirectory, { mode: 0o700 });
        return [];
      },
    },
  ];

  for (const fixture of preOpenCases) {
    await t.test(`before directory open: ${fixture.label}`, () => {
      const directory = privateTemp("noa-kws-terminal-directory-preopen-");
      const physicalDirectory = fs.realpathSync(directory);
      const movedOriginal = `${physicalDirectory}.retained-original`;
      const descriptor = Object.getOwnPropertyDescriptor(fs, "openSync");
      assert.ok(descriptor !== undefined);
      const originalOpen = fs.openSync;
      let extraPaths: string[] = [];
      let swapped = false;
      try {
        Object.defineProperty(fs, "openSync", {
          ...descriptor,
          value: (...args: Parameters<typeof fs.openSync>) => {
            if (!swapped && args[0] === physicalDirectory) {
              swapped = true;
              fs.renameSync(physicalDirectory, movedOriginal);
              extraPaths = fixture.replace(physicalDirectory, movedOriginal);
            }
            return Reflect.apply(originalOpen, fs, args) as number;
          },
        });
        let refusal: WorkspaceError | null = null;
        assert.throws(
          () => publishTerminalEvidence({ directory: physicalDirectory, terminal }),
          (error: WorkspaceError) => {
            refusal = error;
            return error.code === workspaceErrorCode("PRIVATE_ROOT_UNSAFE");
          },
        );
        assert.equal(swapped, true);
        assert.equal(pathExistsNoFollow(path.join(movedOriginal, "terminal.json")), false);
        if (pathExistsNoFollow(physicalDirectory) && fs.lstatSync(physicalDirectory).isDirectory()) {
          assert.equal(pathExistsNoFollow(path.join(physicalDirectory, "terminal.json")), false);
        }
        assert.equal(errorTerminalPublication(refusal), null);
      } finally {
        Object.defineProperty(fs, "openSync", descriptor);
        removeFixturePath(physicalDirectory);
        removeFixturePath(movedOriginal);
        for (const extra of extraPaths) removeFixturePath(extra);
      }
    });
  }

  await t.test("wrong expected directory identity is rejected before opening it", () => {
    const directory = privateTemp("noa-kws-terminal-directory-wrong-identity-");
    const physicalDirectory = fs.realpathSync(directory);
    const terminalPath = path.join(physicalDirectory, "terminal.json");
    const descriptor = Object.getOwnPropertyDescriptor(fs, "openSync");
    assert.ok(descriptor !== undefined);
    const originalOpen = fs.openSync;
    let directoryOpenCount = 0;
    try {
      Object.defineProperty(fs, "openSync", {
        ...descriptor,
        value: (...args: Parameters<typeof fs.openSync>) => {
          if (args[0] === physicalDirectory) directoryOpenCount++;
          return Reflect.apply(originalOpen, fs, args) as number;
        },
      });
      assert.throws(
        () => publishTerminalEvidence({
          directory: physicalDirectory,
          expectedDirectoryIdentity: "0:0",
          terminal,
        }),
        (error: WorkspaceError) => error.code === workspaceErrorCode("PRIVATE_ROOT_UNSAFE"),
      );
      assert.equal(directoryOpenCount, 0);
      assert.equal(pathExistsNoFollow(terminalPath), false);
    } finally {
      Object.defineProperty(fs, "openSync", descriptor);
      removeFixturePath(physicalDirectory);
    }
  });

  await t.test("between directory bind and terminal create", () => {
    const directory = privateTemp("noa-kws-terminal-directory-postbind-");
    const physicalDirectory = fs.realpathSync(directory);
    const movedOriginal = `${physicalDirectory}.retained-original`;
    const terminalPath = path.join(physicalDirectory, "terminal.json");
    const descriptor = Object.getOwnPropertyDescriptor(fs, "openSync");
    assert.ok(descriptor !== undefined);
    const originalOpen = fs.openSync;
    let directoryBound = false;
    let swapped = false;
    let refusal: WorkspaceError | null = null;
    try {
      Object.defineProperty(fs, "openSync", {
        ...descriptor,
        value: (...args: Parameters<typeof fs.openSync>) => {
          if (directoryBound && !swapped && args[0] === terminalPath) {
            swapped = true;
            fs.renameSync(physicalDirectory, movedOriginal);
            fs.mkdirSync(physicalDirectory, { mode: 0o700 });
          }
          const fd = Reflect.apply(originalOpen, fs, args) as number;
          if (!directoryBound && args[0] === physicalDirectory) directoryBound = true;
          return fd;
        },
      });
      assert.throws(
        () => publishTerminalEvidence({ directory: physicalDirectory, terminal }),
        (error: WorkspaceError) => {
          refusal = error;
          return error.code === workspaceErrorCode("PRIVATE_ROOT_UNSAFE");
        },
      );
      assert.equal(swapped, true);
      assert.equal(pathExistsNoFollow(path.join(movedOriginal, "terminal.json")), false);
      const residue = fs.lstatSync(terminalPath, { bigint: true });
      assert.equal(Number(residue.mode & 0o7777n), 0o000);
      assert.equal(Number(residue.nlink), 1);
      const retained = errorTerminalPublication(refusal);
      assert.ok(retained !== null);
      assert.equal(retained.createdIdentity, `${residue.dev}:${residue.ino}`);
      assert.equal(retained.phase, "CREATED_UNBOUND");
    } finally {
      Object.defineProperty(fs, "openSync", descriptor);
      removeFixturePath(physicalDirectory);
      removeFixturePath(movedOriginal);
    }
  });
});

test("publication-directory observation races fail with one stable boundary code", async (t) => {
  const terminal = {
    candidateManifestSha256: "1".repeat(64),
    protocol: workspace.KNOCKOUT_WORKSPACE_PROTOCOLS.terminal,
    status: "PASS",
  };

  await t.test("directory disappears between private lstat and realpath", () => {
    const directory = privateTemp("noa-kws-terminal-realpath-race-");
    const physicalDirectory = fs.realpathSync(directory);
    const movedOriginal = `${physicalDirectory}.retained-original`;
    const descriptor = Object.getOwnPropertyDescriptor(fs, "realpathSync");
    assert.ok(descriptor !== undefined);
    const originalRealpath = fs.realpathSync;
    let swapped = false;
    try {
      Object.defineProperty(fs, "realpathSync", {
        ...descriptor,
        value: (...args: Parameters<typeof fs.realpathSync>) => {
          if (!swapped && args[0] === physicalDirectory) {
            swapped = true;
            fs.renameSync(physicalDirectory, movedOriginal);
          }
          return Reflect.apply(originalRealpath, fs, args) as ReturnType<typeof fs.realpathSync>;
        },
      });
      assert.throws(
        () => publishTerminalEvidence({ directory: physicalDirectory, terminal }),
        (error: WorkspaceError) => error.code === workspaceErrorCode("PRIVATE_ROOT_UNSAFE"),
      );
      assert.equal(swapped, true);
      assert.equal(pathExistsNoFollow(path.join(movedOriginal, "terminal.json")), false);
    } finally {
      Object.defineProperty(fs, "realpathSync", descriptor);
      removeFixturePath(physicalDirectory);
      removeFixturePath(movedOriginal);
    }
  });

  await t.test("directory disappears after O_EXCL creates the unbound inode", () => {
    const directory = privateTemp("noa-kws-terminal-post-create-race-");
    const physicalDirectory = fs.realpathSync(directory);
    const movedOriginal = `${physicalDirectory}.retained-original`;
    const terminalPath = path.join(physicalDirectory, "terminal.json");
    const openDescriptor = Object.getOwnPropertyDescriptor(fs, "openSync");
    const lstatDescriptor = Object.getOwnPropertyDescriptor(fs, "lstatSync");
    assert.ok(openDescriptor !== undefined);
    assert.ok(lstatDescriptor !== undefined);
    const originalOpen = fs.openSync;
    const originalLstat = fs.lstatSync;
    let created = false;
    let swapped = false;
    let refusal: WorkspaceError | null = null;
    try {
      Object.defineProperty(fs, "openSync", {
        ...openDescriptor,
        value: (...args: Parameters<typeof fs.openSync>) => {
          const fd = Reflect.apply(originalOpen, fs, args) as number;
          const flags = typeof args[1] === "number" ? args[1] : 0;
          if (args[0] === terminalPath && (flags & fs.constants.O_CREAT) !== 0) created = true;
          return fd;
        },
      });
      Object.defineProperty(fs, "lstatSync", {
        ...lstatDescriptor,
        value: (...args: Parameters<typeof fs.lstatSync>) => {
          if (created && !swapped && args[0] === physicalDirectory) {
            swapped = true;
            fs.renameSync(physicalDirectory, movedOriginal);
          }
          return Reflect.apply(originalLstat, fs, args) as ReturnType<typeof fs.lstatSync>;
        },
      });
      assert.throws(
        () => publishTerminalEvidence({ directory: physicalDirectory, terminal }),
        (error: WorkspaceError) => {
          refusal = error;
          return error.code === workspaceErrorCode("PRIVATE_ROOT_UNSAFE");
        },
      );
      assert.equal(swapped, true);
      const retainedPath = path.join(movedOriginal, "terminal.json");
      const retainedStat = fs.lstatSync(retainedPath, { bigint: true });
      assert.equal(Number(retainedStat.mode & 0o7777n), 0o000);
      assert.equal(Number(retainedStat.nlink), 1);
      const retained = errorTerminalPublication(refusal);
      assert.ok(retained !== null);
      assert.equal(retained.createdIdentity, `${retainedStat.dev}:${retainedStat.ino}`);
      assert.equal(retained.currentType, "absent");
      assert.equal(retained.phase, "CREATED_UNBOUND");
    } finally {
      Object.defineProperty(fs, "openSync", openDescriptor);
      Object.defineProperty(fs, "lstatSync", lstatDescriptor);
      removeFixturePath(physicalDirectory);
      removeFixturePath(movedOriginal);
    }
  });
});

test("terminal filenames are bounded as filesystem bytes before publication", async (t) => {
  const terminal = {
    candidateManifestSha256: "2".repeat(64),
    protocol: workspace.KNOCKOUT_WORKSPACE_PROTOCOLS.terminal,
    status: "PASS",
  };
  const cases = [
    { filename: "invalid\0name.json", label: "NUL" },
    { filename: `${"å".repeat(101)}.json`, label: "over 200 UTF-8 bytes" },
  ];
  for (const fixture of cases) {
    await t.test(fixture.label, () => {
      const directory = privateTemp("noa-kws-terminal-invalid-name-");
      try {
        assert.throws(
          () => publishTerminalEvidence({
            directory,
            filename: fixture.filename,
            terminal,
          }),
          (error: WorkspaceError) => error.code === workspaceErrorCode("INVALID_ARGUMENT"),
        );
        assert.deepEqual(fs.readdirSync(directory), []);
      } finally {
        removeFixturePath(directory);
      }
    });
  }
});

test("terminal bytes and destination capacity are admitted before inode creation", async (t) => {
  const terminal = {
    candidateManifestSha256: "2".repeat(64),
    protocol: workspace.KNOCKOUT_WORKSPACE_PROTOCOLS.terminal,
    status: "PASS",
  };
  const assertPreflightRefusal = (
    directory: string,
    publish: () => unknown,
  ) => {
    const descriptor = Object.getOwnPropertyDescriptor(fs, "openSync");
    assert.ok(descriptor !== undefined);
    const original = fs.openSync;
    const physicalDirectory = fs.realpathSync(directory);
    let createAttempts = 0;
    try {
      Object.defineProperty(fs, "openSync", {
        ...descriptor,
        value: (...args: Parameters<typeof fs.openSync>) => {
          const flags = typeof args[1] === "number" ? args[1] : 0;
          if (
            typeof args[0] === "string" && path.dirname(path.resolve(args[0])) === physicalDirectory &&
            (flags & fs.constants.O_CREAT) !== 0
          ) createAttempts += 1;
          return Reflect.apply(original, fs, args) as number;
        },
      });
      assert.throws(
        publish,
        (error: WorkspaceError) => error.code === workspaceErrorCode("RESOURCE_LIMIT_EXCEEDED"),
      );
    } finally {
      Object.defineProperty(fs, "openSync", descriptor);
    }
    assert.equal(createAttempts, 0, "terminal preflight reached inode creation");
    assert.deepEqual(fs.readdirSync(directory), []);
  };

  await t.test("canonical terminal exceeds the fixed one-MiB cap", () => {
    const directory = privateTemp("noa-kws-terminal-byte-cap-");
    try {
      assertPreflightRefusal(directory, () => publishTerminalEvidence({
        directory,
        terminal: { ...terminal, payload: "x".repeat(1024 * 1024) },
      }));
    } finally {
      removeFixturePath(directory);
    }
  });

  await t.test("publication directory lacks the fixed free-space reserve", () => {
    const directory = privateTemp("noa-kws-terminal-capacity-");
    const descriptor = Object.getOwnPropertyDescriptor(fs, "statfsSync");
    assert.ok(descriptor !== undefined);
    const original = fs.statfsSync;
    const physicalDirectory = fs.realpathSync(directory);
    try {
      try {
        Object.defineProperty(fs, "statfsSync", {
          ...descriptor,
          value: (...args: Parameters<typeof fs.statfsSync>) => {
            const result = Reflect.apply(original, fs, args) as unknown as
              Record<string, number | bigint>;
            if (path.resolve(String(args[0])) !== physicalDirectory) return result;
            return { ...result, bavail: typeof result.bavail === "bigint" ? 0n : 0 };
          },
        });
        assertPreflightRefusal(directory, () => publishTerminalEvidence({
          directory,
          terminal,
        }));
      } finally {
        Object.defineProperty(fs, "statfsSync", descriptor);
      }
    } finally {
      removeFixturePath(directory);
    }
  });
});

test("terminal publication never deletes a replacement on success or failure", async (t) => {
  const terminal = {
    candidateManifestSha256: "b".repeat(64),
    protocol: workspace.KNOCKOUT_WORKSPACE_PROTOCOLS.terminal,
    status: "PASS",
  };

  await t.test("commit interleaving retains the replacement and reports indeterminate", () => {
    const directory = privateTemp("noa-kws-terminal-commit-race-");
    const physicalDirectory = fs.realpathSync(directory);
    const terminalPath = path.join(physicalDirectory, "terminal.json");
    const movedOriginal = path.join(physicalDirectory, "created-inode.retained");
    const marker = "replacement-survives-commit\n";
    const descriptor = Object.getOwnPropertyDescriptor(fs, "fchmodSync");
    assert.ok(descriptor !== undefined);
    const originalFchmod = fs.fchmodSync;
    let swapped = false;
    let refusal: WorkspaceError | null = null;
    try {
      Object.defineProperty(fs, "fchmodSync", {
        ...descriptor,
        value: (fd: number, mode: number) => {
          if (!swapped && mode === 0o600 && fs.existsSync(terminalPath)) {
            fs.renameSync(terminalPath, movedOriginal);
            fs.writeFileSync(terminalPath, marker, { encoding: "utf8", flag: "wx", mode: 0o600 });
            swapped = true;
          }
          return originalFchmod(fd, mode);
        },
      });
      assert.throws(
        () => publishTerminalEvidence({ directory, terminal }),
        (error: WorkspaceError) => {
          refusal = error;
          return error.code === workspaceErrorCode("TERMINAL_COMMIT_INDETERMINATE");
        },
      );
      assert.equal(swapped, true);
      assert.equal(fs.readFileSync(terminalPath, "utf8"), marker);
      assert.equal(fs.existsSync(movedOriginal), true);
      const retained = errorTerminalPublication(refusal);
      assert.ok(retained !== null);
      assert.equal(retained.path, terminalPath);
      assert.notEqual(retained.createdIdentity, retained.currentIdentity);
      assert.equal(retained.currentIdentity, `${fs.statSync(terminalPath, { bigint: true }).dev}:${fs.statSync(terminalPath, { bigint: true }).ino}`);
    } finally {
      Object.defineProperty(fs, "fchmodSync", descriptor);
      fs.rmSync(directory, { recursive: true, force: true });
    }
  });

  await t.test("post-effect commit error with uncertain fstat is indeterminate", () => {
    const directory = privateTemp("noa-kws-terminal-post-effect-commit-");
    const terminalPath = path.join(fs.realpathSync(directory), "terminal.json");
    const fchmodDescriptor = Object.getOwnPropertyDescriptor(fs, "fchmodSync");
    const fstatDescriptor = Object.getOwnPropertyDescriptor(fs, "fstatSync");
    assert.ok(fchmodDescriptor !== undefined);
    assert.ok(fstatDescriptor !== undefined);
    const originalFchmod = fs.fchmodSync;
    const originalFstat = fs.fstatSync;
    let commitFd: number | null = null;
    let injectedFstatFailures = 0;
    let refusal: WorkspaceError | null = null;
    try {
      Object.defineProperty(fs, "fchmodSync", {
        ...fchmodDescriptor,
        value: (fd: number, mode: number) => {
          const result = originalFchmod(fd, mode);
          if (mode === 0o600 && commitFd === null) {
            commitFd = fd;
            throw Object.assign(new Error("simulated post-effect fchmod failure"), { code: "EIO" });
          }
          return result;
        },
      });
      Object.defineProperty(fs, "fstatSync", {
        ...fstatDescriptor,
        value: (...args: Parameters<typeof fs.fstatSync>) => {
          if (args[0] === commitFd && injectedFstatFailures === 0) {
            injectedFstatFailures += 1;
            throw Object.assign(new Error("simulated uncertain post-effect fstat"), { code: "EIO" });
          }
          return Reflect.apply(originalFstat, fs, args) as ReturnType<typeof fs.fstatSync>;
        },
      });
      assert.throws(
        () => publishTerminalEvidence({ directory, terminal }),
        (error: WorkspaceError) => {
          refusal = error;
          return error.code === workspaceErrorCode("TERMINAL_COMMIT_INDETERMINATE");
        },
      );
      assert.notEqual(commitFd, null);
      assert.equal(injectedFstatFailures, 1);
      assert.equal(fs.statSync(terminalPath).mode & 0o777, 0o600);
      const retained = errorTerminalPublication(refusal);
      assert.ok(retained !== null);
      assert.equal(retained.phase, "COMMIT_TRANSITION_ATTEMPTED");
    } finally {
      Object.defineProperty(fs, "fchmodSync", fchmodDescriptor);
      Object.defineProperty(fs, "fstatSync", fstatDescriptor);
      removeFixturePath(directory);
    }
  });

  await t.test("pre-commit failure retains a replacement and the original PREPARED inode", () => {
    const directory = privateTemp("noa-kws-terminal-failure-race-");
    const physicalDirectory = fs.realpathSync(directory);
    const terminalPath = path.join(physicalDirectory, "terminal.json");
    const movedOriginal = path.join(physicalDirectory, "prepared-inode.retained");
    const marker = "replacement-survives-failure\n";
    const descriptor = Object.getOwnPropertyDescriptor(fs, "writeSync");
    assert.ok(descriptor !== undefined);
    const originalWrite = fs.writeSync;
    let swapped = false;
    let refusal: WorkspaceError | null = null;
    try {
      Object.defineProperty(fs, "writeSync", {
        ...descriptor,
        value: (...args: Parameters<typeof fs.writeSync>) => {
          const written = Reflect.apply(originalWrite, fs, args) as number;
          if (!swapped && fs.existsSync(terminalPath)) {
            fs.renameSync(terminalPath, movedOriginal);
            fs.writeFileSync(terminalPath, marker, { encoding: "utf8", flag: "wx", mode: 0o600 });
            swapped = true;
          }
          return written;
        },
      });
      assert.throws(
        () => publishTerminalEvidence({
          directory,
          simulateShortWriteAfterBytes: 5,
          terminal,
        }),
        (error: WorkspaceError) => {
          refusal = error;
          return error.code === workspaceErrorCode("TERMINAL_INCOMPLETE");
        },
      );
      assert.equal(swapped, true);
      assert.equal(fs.readFileSync(terminalPath, "utf8"), marker);
      assert.equal(Number(fs.statSync(movedOriginal).mode & 0o777), 0o000);
      const retained = errorTerminalPublication(refusal);
      assert.ok(retained !== null);
      assert.equal(retained.phase, "PREPARED");
      assert.notEqual(retained.createdIdentity, retained.currentIdentity);
    } finally {
      Object.defineProperty(fs, "writeSync", descriptor);
      fs.rmSync(directory, { recursive: true, force: true });
    }
  });

  const moduleSource = fs.readFileSync(
    path.join(repositoryRoot, "scripts/lib/knockout-workspace.mjs"),
    "utf8",
  );
  assert.doesNotMatch(moduleSource, /\bfs\.(?:rename|unlink|rm|rmdir)(?:Sync)?\s*\(/);
});

test("identity-bound reopen rejects a same-content inode substituted after publication close", () => {
  const directory = privateTemp("noa-kws-terminal-post-close-swap-");
  const physicalDirectory = fs.realpathSync(directory);
  const terminalPath = path.join(physicalDirectory, "terminal.json");
  const retainedOriginal = path.join(physicalDirectory, "terminal.created-inode.retained");
  const terminal = {
    candidateManifestSha256: "e".repeat(64),
    protocol: workspace.KNOCKOUT_WORKSPACE_PROTOCOLS.terminal,
    status: "PASS",
  };
  const openDescriptor = Object.getOwnPropertyDescriptor(fs, "openSync");
  const closeDescriptor = Object.getOwnPropertyDescriptor(fs, "closeSync");
  assert.ok(openDescriptor !== undefined);
  assert.ok(closeDescriptor !== undefined);
  const originalOpen = fs.openSync;
  const originalClose = fs.closeSync;
  let createdFd: number | null = null;
  let swapped = false;
  try {
    Object.defineProperty(fs, "openSync", {
      ...openDescriptor,
      value: (...args: Parameters<typeof fs.openSync>) => {
        const fd = Reflect.apply(originalOpen, fs, args) as number;
        const flags = typeof args[1] === "number" ? args[1] : 0;
        if (
          createdFd === null && args[0] === terminalPath &&
          (flags & fs.constants.O_CREAT) !== 0
        ) createdFd = fd;
        return fd;
      },
    });
    Object.defineProperty(fs, "closeSync", {
      ...closeDescriptor,
      value: (fd: number) => {
        const result = originalClose(fd);
        if (!swapped && fd === createdFd) {
          swapped = true;
          const canonicalBytes = fs.readFileSync(terminalPath);
          fs.renameSync(terminalPath, retainedOriginal);
          fs.writeFileSync(terminalPath, canonicalBytes, { flag: "wx", mode: 0o600 });
        }
        return result;
      },
    });
    const published = publishTerminalEvidence({ directory: physicalDirectory, terminal });
    assert.equal(swapped, true);
    const retainedStat = fs.lstatSync(retainedOriginal, { bigint: true });
    const replacementStat = fs.lstatSync(terminalPath, { bigint: true });
    assert.equal(published.createdIdentity, `${retainedStat.dev}:${retainedStat.ino}`);
    assert.notEqual(published.createdIdentity, `${replacementStat.dev}:${replacementStat.ino}`);
    assert.deepEqual(fs.readFileSync(retainedOriginal), fs.readFileSync(terminalPath));
    assert.throws(
      () => reopenTerminalEvidence(
        terminalPath,
        published.sha256,
        published.createdObservation,
      ),
      (error: WorkspaceError) =>
        error.code === workspaceErrorCode("TERMINAL_IDENTITY_MISMATCH"),
    );
    assert.throws(
      () => workspace.reopenTerminalEvidence({
        allowedTerminalStatuses: TEST_TERMINAL_STATUSES,
        expectedCandidateManifestSha256: terminal.candidateManifestSha256,
        expectedDirectoryIdentity: published.directoryIdentity,
        expectedObservation: null,
        expectedSha256: published.sha256,
        terminalPath,
      }),
      (error: WorkspaceError) => error.code === workspaceErrorCode("INVALID_ARGUMENT"),
    );
    assert.throws(
      () => workspace.reopenTerminalEvidence({
        allowedTerminalStatuses: TEST_TERMINAL_STATUSES,
        expectedCandidateManifestSha256: terminal.candidateManifestSha256,
        expectedDirectoryIdentity: published.directoryIdentity,
        expectedObservation: published.createdObservation,
        expectedSha256: null,
        terminalPath,
      }),
      (error: WorkspaceError) => error.code === workspaceErrorCode("INVALID_ARGUMENT"),
    );
  } finally {
    Object.defineProperty(fs, "openSync", openDescriptor);
    Object.defineProperty(fs, "closeSync", closeDescriptor);
    removeFixturePath(physicalDirectory);
  }
});

test("every post-commit close failure is classified and no descriptor is double-closed", async (t) => {
  const cases = ["verification", "metadata", "created", "directory"] as const;
  for (const target of cases) {
    await t.test(target, () => {
      const directory = privateTemp(`noa-kws-terminal-close-${target}-`);
      const physicalDirectory = fs.realpathSync(directory);
      const terminalPath = path.join(physicalDirectory, "terminal.json");
      const terminal = {
        candidateManifestSha256: "f".repeat(64),
        protocol: workspace.KNOCKOUT_WORKSPACE_PROTOCOLS.terminal,
        status: "PASS",
      };
      const openDescriptor = Object.getOwnPropertyDescriptor(fs, "openSync");
      const closeDescriptor = Object.getOwnPropertyDescriptor(fs, "closeSync");
      assert.ok(openDescriptor !== undefined);
      assert.ok(closeDescriptor !== undefined);
      const originalOpen = fs.openSync;
      const originalClose = fs.closeSync;
      type CloseTarget = (typeof cases)[number];
      type DescriptorRecord = {
        closeCount: number;
        fd: number;
        generation: number;
        kind: CloseTarget | "directory-candidate" | "preflight-metadata";
      };
      const descriptors: Partial<Record<CloseTarget, DescriptorRecord>> = {};
      const records: DescriptorRecord[] = [];
      const liveByFd = new Map<number, DescriptorRecord>();
      let generation = 0;
      let injected = false;
      let refusal: WorkspaceError | null = null;
      try {
        Object.defineProperty(fs, "openSync", {
          ...openDescriptor,
          value: (...args: Parameters<typeof fs.openSync>) => {
            const fd = Reflect.apply(originalOpen, fs, args) as number;
            const flags = typeof args[1] === "number" ? args[1] : 0;
            if (args[0] === physicalDirectory) {
              const record: DescriptorRecord = {
                closeCount: 0,
                fd,
                generation: generation++,
                kind: descriptors.created === undefined ? "directory-candidate" : "metadata",
              };
              assert.equal(liveByFd.has(fd), false, "numeric fd was reused while still live");
              records.push(record);
              liveByFd.set(fd, record);
              if (record.kind === "metadata" && descriptors.metadata === undefined) {
                descriptors.metadata = record;
              }
            } else if (
              args[0] === terminalPath && (flags & fs.constants.O_CREAT) !== 0 &&
              descriptors.created === undefined
            ) {
              const record: DescriptorRecord = {
                closeCount: 0,
                fd,
                generation: generation++,
                kind: "created",
              };
              assert.equal(liveByFd.has(fd), false, "numeric fd was reused while still live");
              records.push(record);
              liveByFd.set(fd, record);
              descriptors.created = record;
              const directoryRecords = [...liveByFd.values()].filter((candidate) =>
                candidate.kind === "directory-candidate"
              );
              assert.equal(directoryRecords.length, 1, "publication directory descriptor was ambiguous");
              const publicationDirectory = directoryRecords[0]!;
              publicationDirectory.kind = "directory";
              descriptors.directory = publicationDirectory;
            } else if (
              args[0] === terminalPath && (flags & fs.constants.O_CREAT) === 0
            ) {
              const record: DescriptorRecord = {
                closeCount: 0,
                fd,
                generation: generation++,
                kind: "verification",
              };
              assert.equal(liveByFd.has(fd), false, "numeric fd was reused while still live");
              records.push(record);
              liveByFd.set(fd, record);
              if (descriptors.verification === undefined) descriptors.verification = record;
            }
            return fd;
          },
        });
        Object.defineProperty(fs, "closeSync", {
          ...closeDescriptor,
          value: (fd: number) => {
            const record = liveByFd.get(fd);
            const result = originalClose(fd);
            if (record !== undefined) {
              record.closeCount += 1;
              liveByFd.delete(fd);
              if (
                record.kind === "directory-candidate" &&
                descriptors.created === undefined
              ) {
                record.kind = "preflight-metadata";
              }
            }
            if (!injected && descriptors[target] === record) {
              injected = true;
              throw Object.assign(new Error(`simulated ${target} close failure`), { code: "EIO" });
            }
            return result;
          },
        });
        assert.throws(
          () => publishTerminalEvidence({ directory: physicalDirectory, terminal }),
          (error: WorkspaceError) => {
            refusal = error;
            return error.code === workspaceErrorCode("TERMINAL_COMMIT_INDETERMINATE");
          },
        );
        assert.equal(injected, true);
        const targetRecord = descriptors[target];
        assert.ok(targetRecord !== undefined);
        assert.equal(targetRecord.closeCount, 1);
        assert.equal(records.some((record) => record.closeCount > 1), false);
        const retained = errorTerminalPublication(refusal);
        assert.ok(retained !== null);
        assert.equal(retained.path, terminalPath);
        assert.equal(retained.currentMode, 0o600);
        assert.equal(retained.currentNlink, 1);
        assert.equal(retained.currentType, "file");
        const retainedObservation = retained.createdObservation;
        assert.ok(retainedObservation !== null);
        assert.deepEqual(
          reopenTerminalEvidence(
            terminalPath,
            retained.expectedSha256,
            retainedObservation,
          ).terminal,
          terminal,
        );
      } finally {
        Object.defineProperty(fs, "openSync", openDescriptor);
        Object.defineProperty(fs, "closeSync", closeDescriptor);
        removeFixturePath(physicalDirectory);
      }
    });
  }
});

test("terminal publication leaves every pre-existing pathname untouched", async (t) => {
  const terminal = {
    candidateManifestSha256: "c".repeat(64),
    protocol: workspace.KNOCKOUT_WORKSPACE_PROTOCOLS.terminal,
    status: "PASS",
  };
  const cases: Array<{
    label: string;
    setup: (directory: string, terminalPath: string) => string[];
  }> = [
    {
      label: "regular file",
      setup: (_directory, terminalPath) => {
        fs.writeFileSync(terminalPath, "existing-regular\n", { mode: 0o600 });
        return [terminalPath];
      },
    },
    {
      label: "symlink",
      setup: (directory, terminalPath) => {
        const target = path.join(directory, "symlink-target");
        fs.writeFileSync(target, "target\n", { mode: 0o600 });
        fs.symlinkSync(target, terminalPath);
        return [terminalPath, target];
      },
    },
    {
      label: "directory",
      setup: (_directory, terminalPath) => {
        fs.mkdirSync(terminalPath, { mode: 0o700 });
        return [terminalPath];
      },
    },
    {
      label: "hardlink",
      setup: (directory, terminalPath) => {
        const external = path.join(directory, "external-hardlink-target");
        fs.writeFileSync(external, "external\n", { mode: 0o600 });
        fs.linkSync(external, terminalPath);
        return [terminalPath, external];
      },
    },
    {
      label: "mode-000 PREPARED residue",
      setup: (_directory, terminalPath) => {
        const fd = fs.openSync(
          terminalPath,
          fs.constants.O_RDWR | fs.constants.O_CREAT | fs.constants.O_EXCL,
          0o000,
        );
        try { fs.writeSync(fd, Buffer.from("prepared\n"), 0, 9, 0); }
        finally { fs.closeSync(fd); }
        return [terminalPath];
      },
    },
  ];

  for (const fixture of cases) {
    await t.test(fixture.label, () => {
      const directory = privateTemp("noa-kws-terminal-existing-");
      const physicalDirectory = fs.realpathSync(directory);
      const terminalPath = path.join(physicalDirectory, "terminal.json");
      try {
        const observedPaths = fixture.setup(physicalDirectory, terminalPath);
        const before = observedPaths.map(pathStableObservation);
        assert.throws(
          () => publishTerminalEvidence({ directory, terminal }),
          (error: WorkspaceError) => error.code === workspaceErrorCode("TERMINAL_EXISTS"),
        );
        assert.deepEqual(observedPaths.map(pathStableObservation), before);
      } finally {
        fs.rmSync(directory, { recursive: true, force: true });
      }
    });
  }
});

test("macOS @-marked inherited ACLs are refused before capture evidence exists", (t) => {
  if (process.platform !== "darwin") {
    t.skip("requires the macOS ACL and extended-attribute representation");
    return;
  }
  for (const executable of ["/bin/chmod", "/bin/ls", "/usr/bin/xattr"]) {
    try { fs.accessSync(executable, fs.constants.X_OK); }
    catch {
      t.skip(`required metadata tool is unavailable: ${executable}`);
      return;
    }
  }

  const source = privateTemp("noa-kws-acl-source-");
  const custodyParent = privateTemp("noa-kws-acl-parent-");
  const custody = path.join(custodyParent, "custody");
  const inheritedAcl =
    "everyone allow list,search,readattr,readextattr,readsecurity,file_inherit,directory_inherit";
  let captured: Capture | null = null;
  let refusal: WorkspaceError | null = null;
  try {
    initRepository(source);
    fs.writeFileSync(path.join(source, "tracked.txt"), "acl fixture\n", { mode: 0o600 });
    git(source, ["add", "--all"]);
    git(source, ["commit", "-q", "-m", "acl fixture"]);
    try { execFileSync("/bin/chmod", ["+a", inheritedAcl, custodyParent]); }
    catch {
      t.skip("the local filesystem cannot create the required inheritable ACL fixture");
      return;
    }
    fs.mkdirSync(custody, { mode: 0o700 });
    fs.chmodSync(custody, 0o700);
    const aclObservation = execFileSync("/bin/ls", ["-lde", custody], {
      encoding: "utf8",
    });
    const firstLine = aclObservation.split("\n", 1)[0] ?? "";
    const modeToken = firstLine.split(/\s+/, 1)[0] ?? "";
    if (!modeToken.endsWith("@") || !aclObservation.includes(" inherited ")) {
      t.skip("the local filesystem did not expose the @-marked inherited ACL representation");
      return;
    }

    try {
      captured = workspace.captureAndSealCandidate({ sourceRoot: source, custodyRoot: custody });
    } catch (error) {
      refusal = error as WorkspaceError;
      assert.equal(refusal.code, workspaceErrorCode("ACL_UNSUPPORTED"));
    }
    assert.ok(captured === null, "capture accepted an @-marked inherited ACL");
    assert.deepEqual(fs.readdirSync(custody), [], "capture created evidence below an ACL-bearing root");
  } finally {
    cleanupReportedScratchRoots(reportedPrivateRoots(captured));
    cleanupReportedScratchRoots(errorPrivateRoots(refusal));
    removeFixturePath(source);
    removeFixturePath(custodyParent);
  }
});

test("terminal validation and publication consume one canonical input snapshot", () => {
  const directory = privateTemp("noa-kws-terminal-snapshot-");
  const expectedCandidateManifestSha256 = "9".repeat(64);
  const terminal = {
    candidateManifestSha256: expectedCandidateManifestSha256,
    protocol: workspace.KNOCKOUT_WORKSPACE_PROTOCOLS.terminal,
    status: "PASS",
  };
  const terminalBytes = workspace.canonicalJsonBytes(terminal);
  terminal.protocol = "noa-knockout-workspace/terminal/unvalidated";
  try {
    const published = workspace.publishTerminalEvidence({
      allowedTerminalStatuses: TEST_TERMINAL_STATUSES,
      directory,
      expectedCandidateManifestSha256,
      terminalBytes,
    });
    assert.equal(terminal.protocol, "noa-knockout-workspace/terminal/unvalidated");
    assert.equal(
      published.terminal.protocol,
      workspace.KNOCKOUT_WORKSPACE_PROTOCOLS.terminal,
    );
    const reopened = reopenTerminalEvidence(
      published.path,
      published.sha256,
      published.createdObservation,
    );
    assert.deepEqual(reopened.terminal, published.terminal);
  } finally {
    removeFixturePath(directory);
  }
});

test("terminal evidence binds raw bytes, candidate, closed status, size, and directory identity", async (t) => {
  const expectedCandidate = "7".repeat(64);
  const validTerminal = {
    candidateManifestSha256: expectedCandidate,
    protocol: workspace.KNOCKOUT_WORKSPACE_PROTOCOLS.terminal,
    status: "PASS",
  };
  const invalidCases: Array<{ label: string; terminal: object }> = [
    {
      label: "missing candidate",
      terminal: { protocol: workspace.KNOCKOUT_WORKSPACE_PROTOCOLS.terminal, status: "PASS" },
    },
    {
      label: "malformed candidate",
      terminal: { ...validTerminal, candidateManifestSha256: "not-a-hash" },
    },
    {
      label: "mismatched candidate",
      terminal: { ...validTerminal, candidateManifestSha256: "8".repeat(64) },
    },
    { label: "RUNNING", terminal: { ...validTerminal, status: "RUNNING" } },
    { label: "missing status", terminal: {
      candidateManifestSha256: expectedCandidate,
      protocol: workspace.KNOCKOUT_WORKSPACE_PROTOCOLS.terminal,
    } },
    { label: "null status", terminal: { ...validTerminal, status: null } },
    { label: "unknown status", terminal: { ...validTerminal, status: "UNKNOWN_RESULT" } },
  ];
  for (const fixtureCase of invalidCases) {
    await t.test(fixtureCase.label, () => {
      const directory = privateTemp(`noa-kws-terminal-contract-${fixtureCase.label.replaceAll(" ", "-")}-`);
      try {
        const directoryStat = fs.lstatSync(directory, { bigint: true });
        assert.throws(
          () => workspace.publishTerminalEvidence({
            allowedTerminalStatuses: TEST_TERMINAL_STATUSES,
            directory,
            expectedCandidateManifestSha256: expectedCandidate,
            expectedDirectoryIdentity: `${directoryStat.dev}:${directoryStat.ino}`,
            terminalBytes: workspace.canonicalJsonBytes(fixtureCase.terminal),
          }),
          (error: WorkspaceError) => error.code === workspaceErrorCode("INVALID_ARGUMENT"),
        );
        assert.deepEqual(fs.readdirSync(directory), []);
      } finally {
        removeFixturePath(directory);
      }
    });
  }

  await t.test("closed-status policy rejects empty, open, duplicate, and malformed sets", async (policyTest) => {
    const invalidPolicies: Array<{ label: string; statuses: string[] }> = [
      { label: "empty", statuses: [] },
      { label: "contains RUNNING", statuses: ["PASS", "RUNNING"] },
      { label: "duplicate", statuses: ["PASS", "PASS"] },
      { label: "malformed", statuses: ["pass"] },
    ];
    for (const fixtureCase of invalidPolicies) {
      await policyTest.test(fixtureCase.label, () => {
        const directory = privateTemp(
          `noa-kws-terminal-policy-${fixtureCase.label.replaceAll(" ", "-")}-`,
        );
        try {
          const directoryStat = fs.lstatSync(directory, { bigint: true });
          assert.throws(
            () => workspace.publishTerminalEvidence({
              allowedTerminalStatuses: fixtureCase.statuses,
              directory,
              expectedCandidateManifestSha256: expectedCandidate,
              expectedDirectoryIdentity: `${directoryStat.dev}:${directoryStat.ino}`,
              terminalBytes: workspace.canonicalJsonBytes(validTerminal),
            }),
            (error: WorkspaceError) => error.code === workspaceErrorCode("INVALID_ARGUMENT"),
          );
          assert.deepEqual(fs.readdirSync(directory), []);
        } finally {
          removeFixturePath(directory);
        }
      });
    }
  });

  await t.test("consumer refuses a canonical RUNNING terminal", () => {
    const directory = privateTemp("noa-kws-terminal-running-reopen-");
    const terminalPath = path.join(fs.realpathSync(directory), "terminal.json");
    try {
      fs.writeFileSync(
        terminalPath,
        workspace.canonicalJsonBytes({ ...validTerminal, status: "RUNNING" }),
        { flag: "wx", mode: 0o600 },
      );
      const directoryStat = fs.lstatSync(directory, { bigint: true });
      assert.throws(
        () => workspace.reopenTerminalEvidence({
          allowedTerminalStatuses: TEST_TERMINAL_STATUSES,
          expectedCandidateManifestSha256: expectedCandidate,
          expectedDirectoryIdentity: `${directoryStat.dev}:${directoryStat.ino}`,
          expectedObservation: fileObservationForTest(terminalPath),
          expectedSha256: sha256File(terminalPath),
          terminalPath,
        }),
        (error: WorkspaceError) => error.code === workspaceErrorCode("TERMINAL_INCOMPLETE"),
      );
    } finally {
      removeFixturePath(directory);
    }
  });

  await t.test("oversized raw publication bytes", () => {
    const directory = privateTemp("noa-kws-terminal-contract-publish-cap-");
    try {
      const directoryStat = fs.lstatSync(directory, { bigint: true });
      assert.throws(
        () => workspace.publishTerminalEvidence({
          allowedTerminalStatuses: TEST_TERMINAL_STATUSES,
          directory,
          expectedCandidateManifestSha256: expectedCandidate,
          expectedDirectoryIdentity: `${directoryStat.dev}:${directoryStat.ino}`,
          terminalBytes: Buffer.alloc((1024 * 1024) + 1, 0x20),
        }),
        (error: WorkspaceError) => error.code === workspaceErrorCode("RESOURCE_LIMIT_EXCEEDED"),
      );
      assert.deepEqual(fs.readdirSync(directory), []);
    } finally {
      removeFixturePath(directory);
    }
  });

  await t.test("reopen policy and bounded read", () => {
    const directory = privateTemp("noa-kws-terminal-contract-reopen-");
    const oversizedDirectory = privateTemp("noa-kws-terminal-contract-reopen-cap-");
    try {
      const published = publishTerminalEvidence({ directory, terminal: validTerminal });
      assert.throws(
        () => workspace.reopenTerminalEvidence({
          allowedTerminalStatuses: TEST_TERMINAL_STATUSES,
          expectedCandidateManifestSha256: expectedCandidate,
          expectedDirectoryIdentity: "0:0",
          expectedObservation: published.createdObservation,
          expectedSha256: published.sha256,
          terminalPath: published.path,
        }),
        (error: WorkspaceError) => error.code === workspaceErrorCode("PRIVATE_ROOT_UNSAFE"),
      );
      assert.throws(
        () => workspace.reopenTerminalEvidence({
          allowedTerminalStatuses: TEST_TERMINAL_STATUSES,
          expectedCandidateManifestSha256: "8".repeat(64),
          expectedDirectoryIdentity: published.directoryIdentity,
          expectedObservation: published.createdObservation,
          expectedSha256: published.sha256,
          terminalPath: published.path,
        }),
        (error: WorkspaceError) => error.code === workspaceErrorCode("TERMINAL_INCOMPLETE"),
      );
      assert.throws(
        () => workspace.reopenTerminalEvidence({
          allowedTerminalStatuses: ["FAIL"],
          expectedCandidateManifestSha256: expectedCandidate,
          expectedDirectoryIdentity: published.directoryIdentity,
          expectedObservation: published.createdObservation,
          expectedSha256: published.sha256,
          terminalPath: published.path,
        }),
        (error: WorkspaceError) => error.code === workspaceErrorCode("TERMINAL_INCOMPLETE"),
      );
      const reopened = workspace.reopenTerminalEvidence({
        allowedTerminalStatuses: TEST_TERMINAL_STATUSES,
        expectedCandidateManifestSha256: expectedCandidate,
        expectedDirectoryIdentity: published.directoryIdentity,
        expectedObservation: published.createdObservation,
        expectedSha256: published.sha256,
        terminalPath: published.path,
      });
      assert.deepEqual(reopened.terminal, published.terminal);

      const oversizedPath = path.join(oversizedDirectory, "terminal.json");
      fs.writeFileSync(oversizedPath, Buffer.alloc((1024 * 1024) + 1, 0x20), { mode: 0o600 });
      const oversizedDirectoryStat = fs.lstatSync(oversizedDirectory, { bigint: true });
      assert.throws(
        () => workspace.reopenTerminalEvidence({
          allowedTerminalStatuses: TEST_TERMINAL_STATUSES,
          expectedCandidateManifestSha256: expectedCandidate,
          expectedDirectoryIdentity:
            `${oversizedDirectoryStat.dev}:${oversizedDirectoryStat.ino}`,
          expectedObservation: fileObservationForTest(oversizedPath),
          expectedSha256: sha256File(oversizedPath),
          terminalPath: oversizedPath,
        }),
        (error: WorkspaceError) => error.code === workspaceErrorCode("RESOURCE_LIMIT_EXCEEDED"),
      );
    } finally {
      removeFixturePath(directory);
      removeFixturePath(oversizedDirectory);
    }
  });
});

test("consumer verification rejects proxy-wrapped capabilities without observing properties", () => {
  const fixture = minimalCaptureFixture("consumer-capability-proxy");
  let captured: Capture | null = null;
  let propertyReads = 0;
  try {
    const bounded = withSyntheticMacMetadata(() => {
      const sealed = workspace.captureAndSealCandidate({
        sourceRoot: fixture.source,
        custodyRoot: fixture.custody,
      });
      captured = sealed;
      const proxied = new Proxy(sealed, {
        get(target, property, receiver) {
          propertyReads += 1;
          return Reflect.get(target, property, receiver);
        },
      });
      assert.throws(
        () => workspace.verifySealedSeed(proxied),
        (error: WorkspaceError) => error.code === workspaceErrorCode("INVALID_ARGUMENT"),
      );
      assert.equal(propertyReads, 0, "unregistered capability properties were observed");
      assert.doesNotThrow(() => workspace.verifySealedSeed(sealed));
      return sealed;
    });
    captured = bounded.result;
    if (process.platform === "darwin") {
      assert.ok(bounded.helperCalls > 0, "the consumer-only test used bounded macOS metadata");
    }
  } finally {
    cleanupReportedScratchRoots(captured?.retainedPrivateRoots ?? []);
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
  }
});

test("consumer capability rejects producer-rehashed source resource summaries", () => {
  const fixture = minimalCaptureFixture("consumer-source-resource-summary");
  let captured: Capture | null = null;
  try {
    const bounded = withSyntheticMacMetadata(() => {
      const sealed = workspace.captureAndSealCandidate({
        sourceRoot: fixture.source,
        custodyRoot: fixture.custody,
      });
      captured = sealed;
      for (const field of ["allocatedBytes", "logicalBytes", "maxDepth", "nodeCount"] as const) {
        const tampered = JSON.parse(JSON.stringify(sealed.manifest)) as Capture["manifest"];
        tampered.resourceAdmission.source[field] += 1;
        tampered.candidateManifestSha256 = workspace.candidateManifestSha256(tampered);
        const forged = Object.freeze({
          ...sealed,
          candidateManifestSha256: tampered.candidateManifestSha256,
          manifest: tampered,
        }) as Capture;
        assert.throws(
          () => workspace.verifySealedSeed(forged),
          (error: WorkspaceError) => error.code === workspaceErrorCode("INVALID_ARGUMENT"),
          `source ${field} entered through an unregistered capture capability`,
        );
      }
      return sealed;
    });
    captured = bounded.result;
    if (process.platform === "darwin") {
      assert.ok(bounded.helperCalls > 0, "the consumer-only test used bounded macOS metadata");
    }
  } finally {
    cleanupReportedScratchRoots(captured?.retainedPrivateRoots ?? []);
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
  }
});

test("consumer capability refuses rehashed source limits, commitments, and topology", async (t) => {
  const fixture = minimalCaptureFixture("consumer-source-contract");
  let captured: Capture | null = null;
  try {
    captured = workspace.captureAndSealCandidate({
      sourceRoot: fixture.source,
      custodyRoot: fixture.custody,
    });
    const verifyRefusal = (tampered: Capture["manifest"], label: string) => {
      tampered.candidateManifestSha256 = workspace.candidateManifestSha256(tampered);
      const forged = Object.freeze({
        ...captured!,
        candidateManifestSha256: tampered.candidateManifestSha256,
        manifest: tampered,
      }) as Capture;
      assert.throws(
        () => workspace.verifySealedSeed(forged),
        (error: WorkspaceError) => error.code === workspaceErrorCode("INVALID_ARGUMENT"),
        label,
      );
    };
    const cloneManifest = () => JSON.parse(JSON.stringify(captured!.manifest)) as Capture["manifest"];
    const firstFile = (
      manifest: Capture["manifest"],
    ): Capture["manifest"]["source"]["nodes"][number] & { size: number } => {
      const node = manifest.source.nodes.find((candidate) => candidate.type === "file");
      assert.ok(node !== undefined && node.size !== undefined, "fixture has no source file node");
      return node as Capture["manifest"]["source"]["nodes"][number] & { size: number };
    };

    await t.test("source file exceeds declared maxFileBytes", () => {
      const tampered = cloneManifest();
      const file = firstFile(tampered);
      assert.ok(file.size > 1, "fixture file is too small for a strict maxFile regression");
      tampered.resourceAdmission.limits.maxFileBytes = file.size - 1;
      verifyRefusal(tampered, "source per-file limit was not enforced from manifest evidence");
    });

    await t.test("source file size diverges from its stable observation", () => {
      const tampered = cloneManifest();
      const file = firstFile(tampered);
      file.size += 1;
      tampered.resourceAdmission.source.logicalBytes += 1;
      verifyRefusal(tampered, "source file size was not bound to observation.size");
    });

    for (const field of ["workspaceMaterialSha256", "workspaceObservationSha256"] as const) {
      await t.test(`source ${field} is recomputed from source nodes`, () => {
        const tampered = cloneManifest();
        tampered.source[field] = tampered.source[field] === "0".repeat(64)
          ? "1".repeat(64)
          : "0".repeat(64);
        verifyRefusal(tampered, `source ${field} was trusted instead of recomputed`);
      });
    }

    await t.test("self-consistent source hashes cannot bless a node whose parent is absent", () => {
      const tampered = cloneManifest();
      const child = tampered.source.nodes.find((node) => node.path === "nested/child.txt");
      assert.ok(child !== undefined, "fixture nested source node is missing");
      child.path = "missing-parent/child.txt";
      tampered.source.workspaceMaterialSha256 = sourceMaterialSha256(tampered.source.nodes);
      tampered.source.workspaceObservationSha256 = sha256Bytes(
        workspace.canonicalJsonBytes(tampered.source.nodes),
      );
      verifyRefusal(tampered, "source topology accepted a node below an absent parent");
    });
  } finally {
    cleanupReportedScratchRoots(captured?.retainedPrivateRoots ?? []);
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
  }
});

test("pre-state seed-root ancestor substitution cannot return success or publish SEALED state", () => {
  const fixture = minimalCaptureFixture("pre-state-seed-root-swap");
  let movedSeedRoot: string | null = null;
  let refusal: WorkspaceError | null = null;
  let seedRoot: string | null = null;
  let unexpectedCapture: Capture | null = null;
  try {
    try {
      unexpectedCapture = workspace.captureAndSealCandidate({
        sourceRoot: fixture.source,
        custodyRoot: fixture.custody,
        hooks: {
          beforeStatePublication(value) {
            assert.equal(pathExistsNoFollow(value.statePath), false);
            seedRoot = path.dirname(value.workspaceRoot);
            movedSeedRoot = `${seedRoot}.created-directory.retained`;
            fs.renameSync(seedRoot, movedSeedRoot);
            fs.symlinkSync(movedSeedRoot, seedRoot, "dir");
          },
        },
      });
    } catch (error) {
      refusal = error as WorkspaceError;
      assert.equal(refusal.code, workspaceErrorCode("PRIVATE_ROOT_UNSAFE"), errorChain(refusal));
    }
    assert.ok(
      unexpectedCapture === null,
      "capture returned success through a substituted seed root",
    );
    const substituted = requiredString(seedRoot, "pre-state hook did not receive the seed root");
    const retained = requiredString(movedSeedRoot, "pre-state hook did not retain the seed root");
    assert.equal(fs.lstatSync(substituted).isSymbolicLink(), true);
    assert.equal(fs.lstatSync(retained).isDirectory(), true);
    assert.equal(pathExistsNoFollow(path.join(retained, "evidence", "state.json")), false);
    assert.notEqual(refusal, null);
  } finally {
    cleanupReportedScratchRoots(reportedPrivateRoots(unexpectedCapture));
    cleanupReportedScratchRoots(errorPrivateRoots(refusal));
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
  }
});

test("capture durably records child-directory insertions in their parents", () => {
  const fixture = minimalCaptureFixture("directory-fsync-order");
  const openDescriptor = Object.getOwnPropertyDescriptor(fs, "openSync");
  const fchmodDescriptor = Object.getOwnPropertyDescriptor(fs, "fchmodSync");
  const fsyncDescriptor = Object.getOwnPropertyDescriptor(fs, "fsyncSync");
  assert.ok(openDescriptor !== undefined);
  assert.ok(fchmodDescriptor !== undefined);
  assert.ok(fsyncDescriptor !== undefined);
  const originalOpen = fs.openSync;
  const originalFchmod = fs.fchmodSync;
  const originalFsync = fs.fsyncSync;
  const descriptorPaths = new Map<number, string>();
  const durabilityEvents: Array<{ kind: "fchmod" | "fsync"; mode?: number; path: string }> = [];
  const fsyncEvents: string[] = [];
  let captured: Capture | null = null;
  try {
    try {
      Object.defineProperty(fs, "openSync", {
        ...openDescriptor,
        value: (...args: Parameters<typeof fs.openSync>) => {
          const fd = Reflect.apply(originalOpen, fs, args) as number;
          if (typeof args[0] === "string") descriptorPaths.set(fd, path.resolve(args[0]));
          return fd;
        },
      });
      Object.defineProperty(fs, "fchmodSync", {
        ...fchmodDescriptor,
        value: (fd: number, mode: number) => {
          const descriptorPath = descriptorPaths.get(fd);
          if (descriptorPath !== undefined) {
            durabilityEvents.push({ kind: "fchmod", mode, path: descriptorPath });
          }
          return Reflect.apply(originalFchmod, fs, [fd, mode]) as void;
        },
      });
      Object.defineProperty(fs, "fsyncSync", {
        ...fsyncDescriptor,
        value: (fd: number) => {
          const descriptorPath = descriptorPaths.get(fd);
          if (descriptorPath !== undefined) {
            fsyncEvents.push(descriptorPath);
            durabilityEvents.push({ kind: "fsync", path: descriptorPath });
          }
          return Reflect.apply(originalFsync, fs, [fd]) as void;
        },
      });
      captured = workspace.captureAndSealCandidate({
        sourceRoot: fixture.source,
        custodyRoot: fixture.custody,
      });
    } finally {
      Object.defineProperty(fs, "openSync", openDescriptor);
      Object.defineProperty(fs, "fchmodSync", fchmodDescriptor);
      Object.defineProperty(fs, "fsyncSync", fsyncDescriptor);
    }

    const workspaceReady = fsyncEvents.indexOf(captured.workspaceRoot);
    const evidenceReady = fsyncEvents.indexOf(captured.evidenceRoot);
    const seedParentDurable = fsyncEvents.findIndex(
      (event, index) => event === captured!.seedRoot &&
        index > Math.max(workspaceReady, evidenceReady),
    );
    assert.ok(workspaceReady >= 0 && evidenceReady >= 0, "child-directory binds were not observed");
    assert.ok(seedParentDurable >= 0, "seed parent was not fsynced after workspace/evidence creation");

    const gitRoot = path.join(captured.workspaceRoot, ".git");
    const lastGitFsync = fsyncEvents.reduce(
      (last, event, index) => event === gitRoot || event.startsWith(`${gitRoot}${path.sep}`)
        ? index
        : last,
      -1,
    );
    const workspaceAfterGit = fsyncEvents.findIndex(
      (event, index) => event === captured!.workspaceRoot && index > lastGitFsync,
    );
    assert.ok(lastGitFsync >= 0, "standalone .git durability was not observed");
    assert.ok(workspaceAfterGit >= 0, "workspace was not fsynced after final .git durability");
    const gitFiles = regularFilesBelow(gitRoot);
    assert.ok(gitFiles.length > 0, "standalone .git contains no regular files");
    for (const file of gitFiles) {
      const finalMode = durabilityEvents.findLastIndex((event) =>
        event.kind === "fchmod" && event.path === file && event.mode === 0o600);
      const durableAfterMode = durabilityEvents.findIndex((event, index) =>
        index > finalMode && event.kind === "fsync" && event.path === file);
      assert.ok(finalMode >= 0, `${file} had no final descriptor-bound mode clamp`);
      assert.ok(durableAfterMode > finalMode, `${file} had no fsync after its final mode clamp`);
    }
  } finally {
    cleanupReportedScratchRoots(captured?.retainedPrivateRoots ?? []);
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
  }
});

test("a standalone Git file fsync failure prevents manifest publication", () => {
  const fixture = minimalCaptureFixture("git-file-fsync-failure");
  const openDescriptor = Object.getOwnPropertyDescriptor(fs, "openSync");
  const fchmodDescriptor = Object.getOwnPropertyDescriptor(fs, "fchmodSync");
  const fsyncDescriptor = Object.getOwnPropertyDescriptor(fs, "fsyncSync");
  assert.ok(openDescriptor !== undefined);
  assert.ok(fchmodDescriptor !== undefined);
  assert.ok(fsyncDescriptor !== undefined);
  const originalOpen = fs.openSync;
  const originalFchmod = fs.fchmodSync;
  const originalFsync = fs.fsyncSync;
  const descriptorPaths = new Map<number, string>();
  let candidateConfig: string | null = null;
  let evidenceRoot: string | null = null;
  let injected = false;
  let targetFd: number | null = null;
  let refusal: WorkspaceError | null = null;
  try {
    try {
      Object.defineProperty(fs, "openSync", {
        ...openDescriptor,
        value: (...args: Parameters<typeof fs.openSync>) => {
          const fd = Reflect.apply(originalOpen, fs, args) as number;
          if (typeof args[0] === "string") descriptorPaths.set(fd, path.resolve(args[0]));
          return fd;
        },
      });
      Object.defineProperty(fs, "fchmodSync", {
        ...fchmodDescriptor,
        value: (fd: number, mode: number) => {
          if (candidateConfig !== null && descriptorPaths.get(fd) === candidateConfig && mode === 0o600) {
            targetFd = fd;
          }
          return Reflect.apply(originalFchmod, fs, [fd, mode]) as void;
        },
      });
      Object.defineProperty(fs, "fsyncSync", {
        ...fsyncDescriptor,
        value: (fd: number) => {
          if (!injected && targetFd === fd) {
            injected = true;
            throw Object.assign(new Error("injected standalone Git file fsync failure"), {
              code: "EIO",
            });
          }
          return Reflect.apply(originalFsync, fs, [fd]) as void;
        },
      });
      assert.throws(
        () => workspace.captureAndSealCandidate({
          custodyRoot: fixture.custody,
          hooks: {
            afterWorktreeCopy(value) {
              evidenceRoot = value.evidenceRoot;
              candidateConfig = path.join(value.workspaceRoot, ".git", "config");
            },
          },
          maxAttempts: 1,
          sourceRoot: fixture.source,
        }),
        (error: WorkspaceError) => {
          refusal = error;
          return error.code === workspaceErrorCode("DURABILITY_FAILED");
        },
      );
    } finally {
      Object.defineProperty(fs, "openSync", openDescriptor);
      Object.defineProperty(fs, "fchmodSync", fchmodDescriptor);
      Object.defineProperty(fs, "fsyncSync", fsyncDescriptor);
    }
    assert.equal(injected, true, "standalone Git file durability failure was not injected");
    const evidence = requiredString(evidenceRoot, "copy hook did not receive evidence root");
    assert.equal(pathExistsNoFollow(path.join(evidence, "candidate-manifest.json")), false);
    assert.equal(pathExistsNoFollow(path.join(evidence, "state.json")), false);
  } finally {
    cleanupReportedScratchRoots(errorPrivateRoots(refusal));
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
  }
});

test("workspace census enforces file, total-byte, node, and depth admission before copying", async (t) => {
  const cases: Array<{
    label: string;
    limits: Partial<CaptureLimits>;
    prepare: (root: string) => void;
  }> = [
    {
      label: "per-file bytes",
      limits: { maxFileBytes: 4, maxTotalBytes: 8 },
      prepare(root) { fs.writeFileSync(path.join(root, "five.txt"), "12345"); },
    },
    {
      label: "unique total bytes",
      limits: { maxFileBytes: 4, maxTotalBytes: 7 },
      prepare(root) {
        fs.writeFileSync(path.join(root, "first.txt"), "1234");
        fs.writeFileSync(path.join(root, "second.txt"), "5678");
      },
    },
    {
      label: "allocated bytes",
      limits: { maxAllocatedBytes: 1, maxFileBytes: 8, maxTotalBytes: 8 },
      prepare(root) { fs.writeFileSync(path.join(root, "allocated.txt"), "x"); },
    },
    {
      label: "node count",
      limits: { maxFileBytes: 8, maxNodes: 1, maxTotalBytes: 8 },
      prepare(root) { fs.writeFileSync(path.join(root, "node.txt"), "node"); },
    },
    {
      label: "directory depth",
      limits: { maxDepth: 1 },
      prepare(root) { fs.mkdirSync(path.join(root, "one", "two"), { recursive: true }); },
    },
  ];
  for (const fixtureCase of cases) {
    await t.test(fixtureCase.label, () => {
      const root = privateTemp(`noa-kws-limit-${fixtureCase.label.replaceAll(" ", "-")}-`);
      try {
        fixtureCase.prepare(root);
        assert.throws(
          () => workspace.censusWorkspace(root, {
            limits: captureLimits(fixtureCase.limits),
            rootGitPolicy: "absent",
          }),
          (error: WorkspaceError) => error.code === workspaceErrorCode("RESOURCE_LIMIT_EXCEEDED"),
        );
      } finally {
        removeFixturePath(root);
      }
    });
  }
});

test("node and depth admission fail before regular-file content reads", async (t) => {
  const cases = [
    {
      label: "node count",
      limits: captureLimits({ maxNodes: 1 }),
      prepare(root: string) { fs.writeFileSync(path.join(root, "blocked.txt"), "blocked"); },
    },
    {
      label: "node depth",
      limits: captureLimits({ maxDepth: 1 }),
      prepare(root: string) {
        fs.mkdirSync(path.join(root, "one"));
        fs.writeFileSync(path.join(root, "one", "blocked.txt"), "blocked");
      },
    },
  ];
  for (const fixtureCase of cases) {
    await t.test(fixtureCase.label, () => {
      const root = privateTemp(`noa-kws-pre-read-${fixtureCase.label.replaceAll(" ", "-")}-`);
      const descriptor = Object.getOwnPropertyDescriptor(fs, "readSync");
      assert.ok(descriptor !== undefined);
      const original = fs.readSync;
      let contentReads = 0;
      try {
        fixtureCase.prepare(root);
        try {
          Object.defineProperty(fs, "readSync", {
            ...descriptor,
            value: (...args: Parameters<typeof fs.readSync>) => {
              contentReads += 1;
              return Reflect.apply(original, fs, args) as number;
            },
          });
          assert.throws(
            () => workspace.censusWorkspace(root, {
              limits: fixtureCase.limits,
              rootGitPolicy: "absent",
            }),
            (error: WorkspaceError) => error.code === workspaceErrorCode("RESOURCE_LIMIT_EXCEEDED"),
          );
        } finally {
          Object.defineProperty(fs, "readSync", descriptor);
        }
        assert.equal(contentReads, 0, "file content was read before node admission");
      } finally {
        removeFixturePath(root);
      }
    });
  }
});

test("capture limits reject accessors without invoking them", () => {
  const root = privateTemp("noa-kws-limit-accessor-");
  let getterReads = 0;
  const limits = { ...workspace.KNOCKOUT_WORKSPACE_CAPTURE_LIMITS } as Record<string, unknown>;
  Object.defineProperty(limits, "maxTotalBytes", {
    enumerable: true,
    get() {
      getterReads += 1;
      return workspace.KNOCKOUT_WORKSPACE_CAPTURE_LIMITS.maxTotalBytes + getterReads - 1;
    },
  });
  try {
    assert.throws(
      () => workspace.censusWorkspace(root, {
        limits: limits as CaptureLimits,
        rootGitPolicy: "absent",
      }),
      (error: WorkspaceError) => error.code === workspaceErrorCode("INVALID_ARGUMENT"),
    );
    assert.equal(getterReads, 0, "limit accessor executed during validation");
  } finally {
    removeFixturePath(root);
  }
});

test("workspace census refuses a deadline that expires on the final file read or close", async (t) => {
  for (const phase of ["read", "close"] as const) {
    await t.test(`after final ${phase}`, () => {
      const root = privateTemp(`noa-kws-final-${phase}-deadline-`);
      const target = path.join(fs.realpathSync(root), "only.txt");
      fs.writeFileSync(target, "one bounded observation\n", { mode: 0o600 });
      const openDescriptor = Object.getOwnPropertyDescriptor(fs, "openSync");
      const readDescriptor = Object.getOwnPropertyDescriptor(fs, "readSync");
      const closeDescriptor = Object.getOwnPropertyDescriptor(fs, "closeSync");
      const clockDescriptor = Object.getOwnPropertyDescriptor(process.hrtime, "bigint");
      assert.ok(openDescriptor !== undefined);
      assert.ok(readDescriptor !== undefined);
      assert.ok(closeDescriptor !== undefined);
      assert.ok(clockDescriptor !== undefined);
      const originalOpen = fs.openSync;
      const originalRead = fs.readSync;
      const originalClose = fs.closeSync;
      const originalClock = process.hrtime.bigint;
      let expired = false;
      let targetFd: number | null = null;
      let triggered = false;
      try {
        try {
          Object.defineProperty(fs, "openSync", {
            ...openDescriptor,
            value: (...args: Parameters<typeof fs.openSync>) => {
              const fd = Reflect.apply(originalOpen, fs, args) as number;
              if (typeof args[0] === "string" && path.resolve(args[0]) === target) targetFd = fd;
              return fd;
            },
          });
          Object.defineProperty(fs, "readSync", {
            ...readDescriptor,
            value: (...args: Parameters<typeof fs.readSync>) => {
              const bytes = Reflect.apply(originalRead, fs, args) as number;
              if (phase === "read" && args[0] === targetFd && bytes > 0) {
                triggered = true;
                expired = true;
              }
              return bytes;
            },
          });
          Object.defineProperty(fs, "closeSync", {
            ...closeDescriptor,
            value: (fd: number) => {
              const result = Reflect.apply(originalClose, fs, [fd]) as void;
              if (phase === "close" && fd === targetFd) {
                triggered = true;
                expired = true;
              }
              return result;
            },
          });
          Object.defineProperty(process.hrtime, "bigint", {
            ...clockDescriptor,
            value: () => originalClock() + (expired ? 600_000_000_000n : 0n),
          });
          assert.throws(
            () => workspace.censusWorkspace(root, {
              commandTimeoutMs: 5_000,
              rootGitPolicy: "absent",
            }),
            (error: WorkspaceError) =>
              error.code === workspaceErrorCode("OPERATION_DEADLINE_EXCEEDED"),
          );
        } finally {
          Object.defineProperty(fs, "openSync", openDescriptor);
          Object.defineProperty(fs, "readSync", readDescriptor);
          Object.defineProperty(fs, "closeSync", closeDescriptor);
          Object.defineProperty(process.hrtime, "bigint", clockDescriptor);
        }
        assert.equal(triggered, true, `final ${phase} deadline trigger was not reached`);
      } finally {
        removeFixturePath(root);
      }
    });
  }
});

test("custom capture limits govern raw Git files and bounded Git command output", async (t) => {
  await t.test("raw source index", () => {
    const fixture = minimalCaptureFixture("custom-limit-git-index");
    const indexPath = path.join(fixture.source, ".git", "index");
    const indexBytes = fs.statSync(indexPath).size;
    assert.ok(indexBytes > fs.statSync(fixture.trackedPath).size + 1);
    let copied = false;
    let refusal: WorkspaceError | null = null;
    try {
      assert.throws(
        () => workspace.captureAndSealCandidate({
          custodyRoot: fixture.custody,
          hooks: { afterWorktreeCopy() { copied = true; } },
          limits: captureLimits({ maxFileBytes: indexBytes - 1 }),
          maxAttempts: 1,
          sourceRoot: fixture.source,
        }),
        (error: WorkspaceError) => {
          refusal = error;
          return error.code === workspaceErrorCode("RESOURCE_LIMIT_EXCEEDED");
        },
      );
      assert.equal(copied, false, "capture copied the worktree before admitting its Git index");
      assert.deepEqual(fs.readdirSync(fixture.custody), []);
    } finally {
      cleanupReportedScratchRoots(errorPrivateRoots(refusal));
      removeFixturePath(fixture.source);
      removeFixturePath(fixture.custody);
    }
  });

  await t.test("standalone status output", () => {
    const fixture = minimalCaptureFixture("custom-limit-git-output");
    const tools = privateTemp("noa-kws-custom-limit-git-output-tools-");
    const statusRootsPath = path.join(tools, "status-roots");
    const shim = path.join(tools, "git-shim");
    fs.writeFileSync(shim, [
      "#!/bin/sh",
      "for argument in \"$@\"; do",
      "  if [ \"$argument\" = \"status\" ]; then",
      `    pwd -P >> ${JSON.stringify(statusRootsPath)}`,
      "  fi",
      "done",
      `exec ${JSON.stringify(gitExecutable)} \"$@\"`,
      "",
    ].join("\n"), { mode: 0o700 });
    const indexBytes = fs.statSync(path.join(fixture.source, ".git", "index")).size;
    const outputLimit = Math.max(1024, indexBytes + 64);
    for (let index = 0; index < 64; index++) {
      const filename = `untracked-${String(index).padStart(3, "0")}-${"x".repeat(96)}.txt`;
      fs.writeFileSync(path.join(fixture.source, filename), "", { mode: 0o600 });
    }
    assert.ok(statusBytes(fixture.source).length > outputLimit * 2);
    let copied = false;
    let workspaceRoot: string | null = null;
    let refusal: WorkspaceError | null = null;
    try {
      assert.throws(
        () => workspace.captureAndSealCandidate({
          custodyRoot: fixture.custody,
          gitExecutable: shim,
          hooks: {
            afterWorktreeCopy(value) {
              copied = true;
              workspaceRoot = value.workspaceRoot;
            },
          },
          limits: captureLimits({ maxFileBytes: outputLimit }),
          maxAttempts: 1,
          sourceRoot: fixture.source,
        }),
        (error: WorkspaceError) => {
          refusal = error;
          return error.code === workspaceErrorCode("RESOURCE_LIMIT_EXCEEDED");
        },
      );
      assert.equal(copied, true, "capture did not reach isolated-seed status validation");
      const isolatedWorkspace = requiredString(
        workspaceRoot,
        "copy hook did not report the isolated workspace",
      );
      const statusRoots = fs.readFileSync(statusRootsPath, "utf8").trim().split("\n");
      assert.deepEqual(
        statusRoots,
        [fs.realpathSync(isolatedWorkspace)],
        "status must run exactly once on the isolated seed and never on the live source",
      );
      const retained = assertCustodyMatchesReportedRoots(
        fixture.custody,
        errorPrivateRoots(refusal),
      );
      assert.equal(retained.length, 3);
      assert.equal(retained.filter((entry) => /^noa-kws-git-observe-/u.test(entry)).length, 1);
      assert.equal(retained.filter((entry) => /^noa-kws-index-normalize-/u.test(entry)).length, 1);
      const seedRoots = retained.filter((entry) => /^seed-attempt-1-/u.test(entry));
      assert.equal(seedRoots.length, 1);
      assert.equal(
        fs.realpathSync(path.dirname(isolatedWorkspace)),
        fs.realpathSync(path.join(fixture.custody, seedRoots[0]!)),
      );
      assert.deepEqual(
        regularFilesBelow(fixture.custody).filter((file) => path.basename(file) === "state.json"),
        [],
        "an oversized isolated status output published capture state",
      );
    } finally {
      cleanupReportedScratchRoots(errorPrivateRoots(refusal));
      removeFixturePath(fixture.source);
      removeFixturePath(fixture.custody);
      removeFixturePath(tools);
    }
  });
});

test("cumulative staged-only Git objects are refused before evidence publication", () => {
  const fixture = minimalCaptureFixture("cumulative-index-objects");
  let evidenceRoot: string | null = null;
  let refusal: WorkspaceError | null = null;
  try {
    for (let index = 0; index < 3; index++) {
      fs.writeFileSync(
        path.join(fixture.source, `staged-${index}.bin`),
        Buffer.alloc(1024 * 1024, 0x41 + index),
        { mode: 0o600 },
      );
    }
    git(fixture.source, ["add", "--all"]);
    assert.throws(
      () => workspace.captureAndSealCandidate({
        custodyRoot: fixture.custody,
        hooks: {
          afterWorktreeCopy(value) { evidenceRoot = value.evidenceRoot; },
        },
        limits: captureLimits({
          maxFileBytes: 2 * 1024 * 1024,
          maxTotalBytes: 70 * 1024 * 1024,
        }),
        maxAttempts: 1,
        sourceRoot: fixture.source,
      }),
      (error: WorkspaceError) => {
        refusal = error;
        return error.code === workspaceErrorCode("RESOURCE_LIMIT_EXCEEDED");
      },
    );
    const evidence = requiredString(evidenceRoot, "copy hook did not receive evidence root");
    assert.equal(pathExistsNoFollow(path.join(evidence, "candidate-manifest.json")), false);
    assert.equal(pathExistsNoFollow(path.join(evidence, "state.json")), false);
  } finally {
    cleanupReportedScratchRoots(errorPrivateRoots(refusal));
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
  }
});

test("capture reserves bounded manifest and state evidence before publishing either inode", () => {
  const fixture = minimalCaptureFixture("evidence-reserve");
  let evidenceRoot: string | null = null;
  let refusal: WorkspaceError | null = null;
  try {
    assert.throws(
      () => workspace.captureAndSealCandidate({
        custodyRoot: fixture.custody,
        hooks: { afterWorktreeCopy(value) { evidenceRoot = value.evidenceRoot; } },
        limits: captureLimits({
          maxFileBytes: workspace.KNOCKOUT_WORKSPACE_CAPTURE_LIMITS.maxFileBytes,
          maxTotalBytes: workspace.KNOCKOUT_WORKSPACE_CAPTURE_LIMITS.maxFileBytes,
        }),
        maxAttempts: 1,
        sourceRoot: fixture.source,
      }),
      (error: WorkspaceError) => {
        refusal = error;
        return error.code === workspaceErrorCode("RESOURCE_LIMIT_EXCEEDED");
      },
    );
    const evidence = requiredString(evidenceRoot, "evidence reserve failed before worktree copy");
    assert.equal(pathExistsNoFollow(path.join(evidence, "candidate-manifest.json")), false);
    assert.equal(pathExistsNoFollow(path.join(evidence, "state.json")), false);
  } finally {
    cleanupReportedScratchRoots(errorPrivateRoots(refusal));
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
  }
});

test("Git pack projection includes reverse-index bytes and per-file allocation rounding", () => {
  const fixture = minimalCaptureFixture("pack-reverse-index-projection");
  const logicalCustody = privateTemp("noa-kws-pack-logical-limit-");
  const allocatedCustody = privateTemp("noa-kws-pack-allocated-limit-");
  let captured: Capture | null = null;
  const refusals: WorkspaceError[] = [];
  try {
    captured = workspace.captureAndSealCandidate({
      custodyRoot: fixture.custody,
      sourceRoot: fixture.source,
    });
    const packRoot = path.join(captured.workspaceRoot, ".git", "objects", "pack");
    const packFiles = regularFilesBelow(packRoot);
    const reverseIndexes = packFiles.filter((file) => file.endsWith(".rev"));
    assert.equal(reverseIndexes.length, 1, "standalone Git pack has no reverse index");
    const packLogicalBytes = packFiles.reduce((sum, file) => sum + fs.statSync(file).size, 0);
    const packAllocatedBytes = packFiles.reduce(
      (sum, file) => sum + fs.statSync(file).blocks * 512,
      0,
    );
    const filesystemBlockBytes = fs.statfsSync(packRoot).bsize;
    const aggregateRoundedBytes = Math.ceil(packLogicalBytes / filesystemBlockBytes) *
      filesystemBlockBytes;
    const separateRoundingDelta = packAllocatedBytes - aggregateRoundedBytes;
    assert.ok(
      separateRoundingDelta > 0,
      "fixture does not expose the separate pack/index/reverse-index allocation boundary",
    );

    const cases = [
      {
        custody: logicalCustody,
        label: "reverse-index logical bytes",
        limits: captureLimits({
          maxTotalBytes: captured.manifest.resourceAdmission.prewriteProjection.logicalBytes -
            fs.statSync(reverseIndexes[0]!).size,
        }),
      },
      {
        custody: allocatedCustody,
        label: "separate file allocation rounding",
        limits: captureLimits({
          maxAllocatedBytes:
            captured.manifest.resourceAdmission.prewriteProjection.allocatedBytes -
            separateRoundingDelta,
        }),
      },
    ];
    for (const fixtureCase of cases) {
      let evidenceRoot: string | null = null;
      let refusal: WorkspaceError | null = null;
      assert.throws(
        () => workspace.captureAndSealCandidate({
          custodyRoot: fixtureCase.custody,
          hooks: { afterWorktreeCopy(value) { evidenceRoot = value.evidenceRoot; } },
          limits: fixtureCase.limits,
          maxAttempts: 1,
          sourceRoot: fixture.source,
        }),
        (error: WorkspaceError) => {
          refusal = error;
          return error.code === workspaceErrorCode("RESOURCE_LIMIT_EXCEEDED");
        },
        `${fixtureCase.label} was omitted from prewrite admission`,
      );
      assert.notEqual(refusal, null);
      refusals.push(refusal!);
      const evidence = requiredString(evidenceRoot, `${fixtureCase.label} failed before worktree copy`);
      assert.equal(pathExistsNoFollow(path.join(evidence, "candidate-manifest.json")), false);
      assert.equal(pathExistsNoFollow(path.join(evidence, "state.json")), false);
    }
  } finally {
    cleanupReportedScratchRoots(captured?.retainedPrivateRoots ?? []);
    for (const refusal of refusals) cleanupReportedScratchRoots(errorPrivateRoots(refusal));
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
    removeFixturePath(logicalCustody);
    removeFixturePath(allocatedCustody);
  }
});

test("standalone Git traversal never uses unbounded readdirSync", () => {
  const fixture = minimalCaptureFixture("bounded-standalone-git-enumeration");
  const descriptor = Object.getOwnPropertyDescriptor(fs, "readdirSync");
  assert.ok(descriptor !== undefined);
  const original = fs.readdirSync;
  let captured: Capture | null = null;
  let generatedGitRoot: string | null = null;
  let unboundedRead = false;
  try {
    try {
      Object.defineProperty(fs, "readdirSync", {
        ...descriptor,
        value: (...args: Parameters<typeof fs.readdirSync>) => {
          const requested = typeof args[0] === "string" ? path.resolve(args[0]) : null;
          if (
            requested !== null && generatedGitRoot !== null &&
            (requested === generatedGitRoot || requested.startsWith(`${generatedGitRoot}${path.sep}`))
          ) {
            unboundedRead = true;
            throw new Error(`unbounded standalone Git enumeration at ${requested}`);
          }
          return Reflect.apply(original, fs, args) as ReturnType<typeof fs.readdirSync>;
        },
      });
      captured = workspace.captureAndSealCandidate({
        custodyRoot: fixture.custody,
        hooks: {
          afterWorktreeCopy(value) {
            generatedGitRoot = path.join(value.workspaceRoot, ".git");
          },
        },
        sourceRoot: fixture.source,
      });
    } finally {
      Object.defineProperty(fs, "readdirSync", descriptor);
    }
    assert.equal(unboundedRead, false);
    assert.notEqual(captured, null);
  } finally {
    cleanupReportedScratchRoots(captured?.retainedPrivateRoots ?? []);
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
  }
});

test("late live-source changes are refused before capture capability registration", async (t) => {
  const cases = [
    { hook: "afterPreSealObservation", label: "worktree bytes" },
    { hook: "beforeStatePublication", label: "Git config bytes" },
  ] as const;
  for (const fixtureCase of cases) {
    await t.test(fixtureCase.label, () => {
      const fixture = minimalCaptureFixture(`late-source-${fixtureCase.label.replaceAll(" ", "-")}`);
      let evidenceRoot: string | null = null;
      let mutated = false;
      let refusal: WorkspaceError | null = null;
      const attempts: number[] = [];
      const mutate = (value: { evidenceRoot: string }) => {
        evidenceRoot = value.evidenceRoot;
        if (fixtureCase.hook === "afterPreSealObservation") {
          fs.writeFileSync(fixture.trackedPath, "late live-source mutation\n", { mode: 0o600 });
        } else {
          fs.appendFileSync(path.join(fixture.source, ".git", "config"), "\n# late config mutation\n");
        }
        mutated = true;
      };
      const hooks: NonNullable<
        Parameters<typeof workspace.captureAndSealCandidate>[0]["hooks"]
      > = {
        afterPreObservation(value) { attempts.push(value.attempt); },
        ...(fixtureCase.hook === "afterPreSealObservation"
          ? { afterPreSealObservation: mutate }
          : { beforeStatePublication: mutate }),
      };
      try {
        assert.throws(
          () => workspace.captureAndSealCandidate({
            custodyRoot: fixture.custody,
            hooks,
            maxAttempts: 2,
            sourceRoot: fixture.source,
          }),
          (error: WorkspaceError) => {
            refusal = error;
            return error.code === workspaceErrorCode("SOURCE_CHANGED");
          },
        );
        assert.equal(mutated, true, "late source mutation hook was not reached");
        assert.deepEqual(attempts, [1], "post-closeout source failure was retried");
        if (fixtureCase.hook === "afterPreSealObservation") {
          assert.equal(
            fs.readFileSync(fixture.trackedPath, "utf8"),
            "late live-source mutation\n",
            "capture altered or concealed the live worktree mutation",
          );
        } else {
          assert.equal(
            fs.readFileSync(path.join(fixture.source, ".git", "config"), "utf8")
              .endsWith("# late config mutation\n"),
            true,
            "capture altered or concealed the live Git-config mutation",
          );
        }
        const evidence = requiredString(evidenceRoot, "late source hook did not expose evidence root");
        const statePath = path.join(evidence, "state.json");
        const manifestPath = path.join(evidence, "candidate-manifest.json");
        assert.equal(pathExistsNoFollow(manifestPath), true);
        assert.equal(pathExistsNoFollow(statePath), true);
        const state = JSON.parse(fs.readFileSync(statePath, "utf8")) as {
          evidenceRole?: string; status?: string;
        };
        assert.equal(state.status, workspace.KNOCKOUT_WORKSPACE_CAPTURE_STATUS);
        assert.equal(state.evidenceRole, workspace.KNOCKOUT_WORKSPACE_STATE_EVIDENCE_ROLE);
        assert.notEqual(state.status, "SEALED", "non-authoritative residue claimed sealed authority");
      } finally {
        cleanupReportedScratchRoots(errorPrivateRoots(refusal));
        removeFixturePath(fixture.source);
        removeFixturePath(fixture.custody);
      }
    });
  }
});

test("deadline expiry after each late hook cannot return capture success", async (t) => {
  const cases = [
    { hook: "afterPreSealObservation", manifest: false, state: false },
    { hook: "afterManifestPublication", manifest: true, state: false },
    { hook: "beforeStatePublication", manifest: true, state: false },
  ] as const;
  for (const fixtureCase of cases) {
    await t.test(fixtureCase.hook, () => {
      const fixture = minimalCaptureFixture(`deadline-${fixtureCase.hook}`);
      const descriptor = Object.getOwnPropertyDescriptor(process.hrtime, "bigint");
      assert.ok(descriptor !== undefined);
      const original = process.hrtime.bigint;
      const hooks: NonNullable<
        Parameters<typeof workspace.captureAndSealCandidate>[0]["hooks"]
      > = {};
      let evidenceRoot: string | null = null;
      let expire = false;
      let refusal: WorkspaceError | null = null;
      hooks[fixtureCase.hook] = (value) => {
        evidenceRoot = "evidenceRoot" in value ? value.evidenceRoot : null;
        if ("statePath" in value) assert.equal(pathExistsNoFollow(value.statePath), false);
        expire = true;
      };
      try {
        try {
          Object.defineProperty(process.hrtime, "bigint", {
            ...descriptor,
            value: () => original() + (expire ? 600_000_000_000n : 0n),
          });
          assert.throws(
            () => workspace.captureAndSealCandidate({
              commandTimeoutMs: 60_000,
              custodyRoot: fixture.custody,
              hooks,
              maxAttempts: 1,
              sourceRoot: fixture.source,
            }),
            (error: WorkspaceError) => {
              refusal = error;
              return error.code === workspaceErrorCode("OPERATION_DEADLINE_EXCEEDED");
            },
          );
        } finally {
          Object.defineProperty(process.hrtime, "bigint", descriptor);
        }
        assert.equal(expire, true);
        const evidence = requiredString(evidenceRoot, "deadline hook did not receive evidence root");
        assert.equal(
          pathExistsNoFollow(path.join(evidence, "candidate-manifest.json")),
          fixtureCase.manifest,
        );
        assert.equal(pathExistsNoFollow(path.join(evidence, "state.json")), fixtureCase.state);
        assert.ok(errorPrivateRoots(refusal).length > 0, "failed capture did not report retained custody");
      } finally {
        cleanupReportedScratchRoots(errorPrivateRoots(refusal));
        removeFixturePath(fixture.source);
        removeFixturePath(fixture.custody);
      }
    });
  }
});

test("standalone index rechecks preserve operation-deadline taxonomy", () => {
  const fixture = minimalCaptureFixture("standalone-index-deadline");
  const tools = privateTemp("noa-kws-standalone-index-deadline-tools-");
  const marker = path.join(tools, "standalone-status-observed");
  const shim = path.join(tools, "git-shim");
  const physicalSource = fs.realpathSync(fixture.source);
  // The marker fires on the standalone-seed status command: a status whose working tree is not
  // the live source, whether Git names it through GIT_WORK_TREE or runs inside the bound seed.
  fs.writeFileSync(shim, [
    "#!/bin/sh",
    "for argument in \"$@\"; do",
    "  if [ \"$argument\" = \"status\" ]; then",
    `    if [ \"\${GIT_WORK_TREE:-}\" != ${JSON.stringify(physicalSource)} ] && [ \"$(pwd -P)\" != ${JSON.stringify(physicalSource)} ]; then`,
    `      /usr/bin/printf observed > ${JSON.stringify(marker)}`,
    "    fi",
    "  fi",
    "done",
    `exec ${JSON.stringify(gitExecutable)} \"$@\"`,
    "",
  ].join("\n"), { mode: 0o700 });

  const lstatDescriptor = Object.getOwnPropertyDescriptor(fs, "lstatSync");
  const clockDescriptor = Object.getOwnPropertyDescriptor(process.hrtime, "bigint");
  assert.ok(lstatDescriptor !== undefined);
  assert.ok(clockDescriptor !== undefined);
  const originalLstat = fs.lstatSync;
  const originalClock = process.hrtime.bigint;
  let generatedIndex: string | null = null;
  let expired = false;
  let triggered = false;
  let refusal: WorkspaceError | null = null;
  try {
    try {
      Object.defineProperty(fs, "lstatSync", {
        ...lstatDescriptor,
        value: (...args: Parameters<typeof fs.lstatSync>) => {
          const stat = Reflect.apply(originalLstat, fs, args) as ReturnType<typeof fs.lstatSync>;
          let markerExists = false;
          try {
            Reflect.apply(originalLstat, fs, [marker]);
            markerExists = true;
          } catch (error) {
            if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
          }
          if (!triggered && generatedIndex !== null && args[0] === generatedIndex && markerExists) {
            triggered = true;
            expired = true;
          }
          return stat;
        },
      });
      Object.defineProperty(process.hrtime, "bigint", {
        ...clockDescriptor,
        value: () => originalClock() + (expired ? 600_000_000_000n : 0n),
      });
      assert.throws(
        () => workspace.captureAndSealCandidate({
          commandTimeoutMs: 60_000,
          custodyRoot: fixture.custody,
          gitExecutable: shim,
          hooks: {
            afterWorktreeCopy(value) {
              generatedIndex = path.join(value.workspaceRoot, ".git", "index");
            },
          },
          maxAttempts: 1,
          sourceRoot: fixture.source,
        }),
        (error: WorkspaceError) => {
          refusal = error;
          return error.code === workspaceErrorCode("OPERATION_DEADLINE_EXCEEDED");
        },
      );
    } finally {
      Object.defineProperty(fs, "lstatSync", lstatDescriptor);
      Object.defineProperty(process.hrtime, "bigint", clockDescriptor);
    }
    assert.equal(triggered, true, "standalone index deadline trigger was not reached");
    assert.equal(pathExistsNoFollow(marker), true);
  } finally {
    cleanupReportedScratchRoots(errorPrivateRoots(refusal));
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
    removeFixturePath(tools);
  }
});

test("capture refuses insufficient destination reserve before creating a candidate seed", () => {
  const fixture = minimalCaptureFixture("capacity-reserve");
  const descriptor = Object.getOwnPropertyDescriptor(fs, "statfsSync");
  assert.ok(descriptor !== undefined);
  const original = fs.statfsSync;
  const custody = fs.realpathSync(fixture.custody);
  let refusal: WorkspaceError | null = null;
  try {
    try {
      Object.defineProperty(fs, "statfsSync", {
        ...descriptor,
        value: (...args: Parameters<typeof fs.statfsSync>) => {
          const result = Reflect.apply(original, fs, args) as unknown as Record<string, bigint>;
          if (path.resolve(String(args[0])) === custody) return { ...result, bavail: 0n };
          return result;
        },
      });
      assert.throws(
        () => workspace.captureAndSealCandidate({
          custodyRoot: fixture.custody,
          maxAttempts: 1,
          sourceRoot: fixture.source,
        }),
        (error: WorkspaceError) => {
          refusal = error;
          return error.code === workspaceErrorCode("RESOURCE_LIMIT_EXCEEDED");
        },
      );
    } finally {
      Object.defineProperty(fs, "statfsSync", descriptor);
    }
    const retained = assertCustodyMatchesReportedRoots(
      fixture.custody,
      errorPrivateRoots(refusal),
    );
    assert.equal(retained.length, 1);
    assert.match(retained[0]!, /^noa-kws-git-observe-/u);
  } finally {
    cleanupReportedScratchRoots(errorPrivateRoots(refusal));
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
  }
});

test("one operation deadline includes time spent in capture hooks", () => {
  const fixture = minimalCaptureFixture("operation-deadline");
  const descriptor = Object.getOwnPropertyDescriptor(process.hrtime, "bigint");
  assert.ok(descriptor !== undefined);
  const original = process.hrtime.bigint;
  const operationTimeoutMs = workspace.KNOCKOUT_WORKSPACE_CAPTURE_TIMEOUT_LIMIT_MS;
  const expiredClockOffsetNs = BigInt(operationTimeoutMs + 1) * 1_000_000n;
  let expire = false;
  let refusal: WorkspaceError | null = null;
  try {
    for (const operationTimeoutMs of [
      0,
      workspace.KNOCKOUT_WORKSPACE_CAPTURE_TIMEOUT_LIMIT_MS + 1,
    ]) {
      assert.throws(
        () => workspace.captureAndSealCandidate({
          custodyRoot: fixture.custody,
          maxAttempts: 1,
          operationTimeoutMs,
          sourceRoot: fixture.source,
        }),
        (error: WorkspaceError) => error.code === workspaceErrorCode("INVALID_ARGUMENT"),
      );
      assert.deepEqual(fs.readdirSync(fixture.custody), []);
    }
    try {
      Object.defineProperty(process.hrtime, "bigint", {
        ...descriptor,
        value: () => original() + (expire ? expiredClockOffsetNs : 0n),
      });
      assert.throws(
        () => workspace.captureAndSealCandidate({
          commandTimeoutMs: 60_000,
          custodyRoot: fixture.custody,
          hooks: { afterPreObservation() { expire = true; } },
          maxAttempts: 1,
          operationTimeoutMs,
          sourceRoot: fixture.source,
        }),
        (error: WorkspaceError) => {
          refusal = error;
          return error.code === workspaceErrorCode("OPERATION_DEADLINE_EXCEEDED");
        },
      );
    } finally {
      Object.defineProperty(process.hrtime, "bigint", descriptor);
    }
    assert.equal(expire, true);
    const retained = assertCustodyMatchesReportedRoots(
      fixture.custody,
      errorPrivateRoots(refusal),
    );
    assert.equal(retained.length, 1);
    assert.match(retained[0]!, /^noa-kws-git-observe-/u);
  } finally {
    cleanupReportedScratchRoots(errorPrivateRoots(refusal));
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
  }
});

test("Git and metadata child processes have finite fail-closed time budgets", () => {
  const fixture = minimalCaptureFixture("command-timeout");
  const tools = privateTemp("noa-kws-command-timeout-tools-");
  const sleepingGit = path.join(tools, "git-sleep");
  fs.writeFileSync(sleepingGit, "#!/bin/sh\nexec /bin/sleep 5\n", { mode: 0o700 });
  let refusal: WorkspaceError | null = null;
  const started = Date.now();
  try {
    assert.throws(
      () => workspace.captureAndSealCandidate({
        commandTimeoutMs: 100,
        custodyRoot: fixture.custody,
        gitExecutable: sleepingGit,
        maxAttempts: 1,
        operationTimeoutMs: 60_000,
        sourceRoot: fixture.source,
      }),
      (error: WorkspaceError) => {
        refusal = error;
        return error.code === workspaceErrorCode("OPERATION_DEADLINE_EXCEEDED");
      },
    );
    assert.ok(Date.now() - started < 2_000, "hung Git exceeded its finite command budget");

    const moduleSource = fs.readFileSync(
      path.join(repositoryRoot, "scripts/lib/knockout-workspace.mjs"),
      "utf8",
    );
    const toolStart = moduleSource.indexOf("function toolResult(");
    const toolEnd = moduleSource.indexOf("\nfunction observeMacMetadata", toolStart);
    assert.ok(toolStart >= 0 && toolEnd > toolStart, "metadata tool wrapper was not found");
    assert.match(
      moduleSource.slice(toolStart, toolEnd),
      /\btimeout\s*:/,
      "metadata tool wrapper has no finite timeout option",
    );
  } finally {
    cleanupReportedScratchRoots(errorPrivateRoots(refusal));
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
    removeFixturePath(tools);
  }
});

test("early seed bind failure reports the already-created private root", () => {
  const fixture = minimalCaptureFixture("early-seed-bind-failure");
  const mkdtempDescriptor = Object.getOwnPropertyDescriptor(fs, "mkdtempSync");
  const openDescriptor = Object.getOwnPropertyDescriptor(fs, "openSync");
  const fsyncDescriptor = Object.getOwnPropertyDescriptor(fs, "fsyncSync");
  assert.ok(mkdtempDescriptor !== undefined);
  assert.ok(openDescriptor !== undefined);
  assert.ok(fsyncDescriptor !== undefined);
  const originalMkdtemp = fs.mkdtempSync;
  const originalOpen = fs.openSync;
  const originalFsync = fs.fsyncSync;
  const custodyPhysical = fs.realpathSync(fixture.custody);
  const descriptorPaths = new Map<number, string>();
  let createdRoot: string | null = null;
  let injected = false;
  let refusal: WorkspaceError | null = null;
  try {
    try {
      Object.defineProperty(fs, "mkdtempSync", {
        ...mkdtempDescriptor,
        value: (...args: Parameters<typeof fs.mkdtempSync>) => {
          const created = Reflect.apply(originalMkdtemp, fs, args) as string;
          if (created.startsWith(`${custodyPhysical}${path.sep}seed-attempt-`)) {
            createdRoot = created;
          }
          return created;
        },
      });
      Object.defineProperty(fs, "openSync", {
        ...openDescriptor,
        value: (...args: Parameters<typeof fs.openSync>) => {
          const fd = Reflect.apply(originalOpen, fs, args) as number;
          if (typeof args[0] === "string") descriptorPaths.set(fd, path.resolve(args[0]));
          return fd;
        },
      });
      Object.defineProperty(fs, "fsyncSync", {
        ...fsyncDescriptor,
        value: (fd: number) => {
          if (!injected && createdRoot !== null && descriptorPaths.get(fd) === createdRoot) {
            injected = true;
            throw Object.assign(new Error("injected seed-directory fsync failure"), { code: "EIO" });
          }
          return Reflect.apply(originalFsync, fs, [fd]) as void;
        },
      });
      assert.throws(
        () => workspace.captureAndSealCandidate({
          sourceRoot: fixture.source,
          custodyRoot: fixture.custody,
        }),
        (error: WorkspaceError) => {
          refusal = error;
          return error.code === workspaceErrorCode("PRIVATE_ROOT_UNSAFE");
        },
      );
    } finally {
      Object.defineProperty(fs, "mkdtempSync", mkdtempDescriptor);
      Object.defineProperty(fs, "openSync", openDescriptor);
      Object.defineProperty(fs, "fsyncSync", fsyncDescriptor);
    }

    assert.equal(injected, true, "seed-directory bind failure was not injected");
    const root = requiredString(createdRoot, "seed root was not created");
    const stat = fs.lstatSync(root, { bigint: true });
    const retained = errorPrivateRoots(refusal).find((entry) => entry.path === root);
    assert.ok(retained !== undefined, "created seed root was omitted from retainedPrivateRoots");
    assert.equal(retained.identity, `${stat.dev}:${stat.ino}`);
  } finally {
    cleanupReportedScratchRoots(errorPrivateRoots(refusal));
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
  }
});

test("Git environment is fixed and contains no ambient custody or credential variables", () => {
  const scrubbed = workspace.scrubGitEnvironment({
    GIT_DIR: "/attacker/git",
    GIT_INDEX_FILE: "/attacker/index",
    HOME: "/attacker/home",
    PATH: "/attacker/bin",
    SSH_AUTH_SOCK: "/attacker/agent",
  });
  assert.deepEqual(Object.keys(scrubbed).sort(), [
    "GIT_ATTR_NOSYSTEM",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_NOSYSTEM",
    "GIT_NO_LAZY_FETCH",
    "GIT_NO_REPLACE_OBJECTS",
    "GIT_OPTIONAL_LOCKS",
    "GIT_TERMINAL_PROMPT",
    "LANG",
    "LC_ALL",
    "PATH",
  ]);
  assert.equal(scrubbed.GIT_OPTIONAL_LOCKS, "0");
  assert.equal(scrubbed.GIT_NO_LAZY_FETCH, "1");
  assert.equal(scrubbed.GIT_ATTR_NOSYSTEM, "1");
  assert.equal(scrubbed.GIT_CONFIG_GLOBAL, "/dev/null");
  assert.equal(scrubbed.PATH, "/usr/bin:/bin");
  assert.equal("HOME" in scrubbed, false);
  assert.equal("GIT_DIR" in scrubbed, false);
});

test("capture disables repository-local fsmonitor execution", () => {
  const fixture = minimalCaptureFixture("fsmonitor-disabled");
  const marker = path.join(fixture.custody, "fsmonitor-invoked");
  const monitor = path.join(fixture.custody, "fsmonitor-hook");
  let captured: Capture | null = null;
  try {
    fs.writeFileSync(monitor, [
      "#!/bin/sh",
      `/usr/bin/printf invoked > ${JSON.stringify(marker)}`,
      "/usr/bin/printf 'token\\n'",
      "exit 0",
      "",
    ].join("\n"), { mode: 0o700 });
    git(fixture.source, ["config", "--local", "core.fsmonitor", monitor]);
    statusBytes(fixture.source);
    assert.equal(fs.readFileSync(marker, "utf8"), "invoked");
    fs.unlinkSync(marker);

    captured = workspace.captureAndSealCandidate({
      sourceRoot: fixture.source,
      custodyRoot: fixture.custody,
    });
    assert.equal(pathExistsNoFollow(marker), false);
  } finally {
    cleanupReportedScratchRoots(captured?.retainedPrivateRoots ?? []);
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
  }
});

test("workspace census enforces its deadline after the final evidence hash", () => {
  const root = privateTemp("noa-kws-post-hash-deadline-");
  fs.writeFileSync(path.join(root, "tracked.txt"), "hash boundary\n", { mode: 0o600 });
  const createHashDescriptor = Object.getOwnPropertyDescriptor(crypto, "createHash");
  const hrtimeDescriptor = Object.getOwnPropertyDescriptor(process.hrtime, "bigint");
  assert.ok(createHashDescriptor !== undefined);
  assert.ok(hrtimeDescriptor !== undefined);
  const originalCreateHash = crypto.createHash;
  const originalHrtime = process.hrtime.bigint;
  let hashCalls = 0;
  let expireOnHash: number | null = null;
  let expired = false;
  try {
    Object.defineProperty(crypto, "createHash", {
      ...createHashDescriptor,
      value: ((...args: Parameters<typeof crypto.createHash>) => {
        const hash = Reflect.apply(originalCreateHash, crypto, args) as ReturnType<
          typeof crypto.createHash
        >;
        const ordinal = ++hashCalls;
        const originalDigest = hash.digest.bind(hash) as (...digestArgs: unknown[]) => unknown;
        Object.defineProperty(hash, "digest", {
          configurable: true,
          value: (...digestArgs: unknown[]) => {
            const result = originalDigest(...digestArgs);
            if (expireOnHash === ordinal) expired = true;
            return result;
          },
          writable: true,
        });
        return hash;
      }) as typeof crypto.createHash,
    });
    syncBuiltinESMExports();
    Object.defineProperty(process.hrtime, "bigint", {
      ...hrtimeDescriptor,
      value: () => originalHrtime() + (expired ? 600_000_000_000n : 0n),
    });

    workspace.censusWorkspace(root, { commandTimeoutMs: 5_000 });
    const calibratedHashCount = hashCalls;
    assert.ok(calibratedHashCount > 0);
    hashCalls = 0;
    expireOnHash = calibratedHashCount;
    assert.throws(
      () => workspace.censusWorkspace(root, { commandTimeoutMs: 5_000 }),
      (error: WorkspaceError) =>
        error.code === workspaceErrorCode("OPERATION_DEADLINE_EXCEEDED"),
    );
    assert.equal(expired, true, "the calibrated final hash boundary was not reached");
    assert.equal(hashCalls, calibratedHashCount);
  } finally {
    Object.defineProperty(crypto, "createHash", createHashDescriptor);
    syncBuiltinESMExports();
    Object.defineProperty(process.hrtime, "bigint", hrtimeDescriptor);
    removeFixturePath(root);
  }
});

test("capture does not register a capability after its final freeze exceeds the deadline", () => {
  const fixture = minimalCaptureFixture("pre-registration-deadline");
  const freezeDescriptor = Object.getOwnPropertyDescriptor(Object, "freeze");
  const hrtimeDescriptor = Object.getOwnPropertyDescriptor(process.hrtime, "bigint");
  assert.ok(freezeDescriptor !== undefined);
  assert.ok(hrtimeDescriptor !== undefined);
  const originalFreeze = Object.freeze;
  const originalHrtime = process.hrtime.bigint;
  let expired = false;
  let frozenCapability: object | null = null;
  let refusal: WorkspaceError | null = null;
  try {
    try {
      Object.defineProperty(Object, "freeze", {
        ...freezeDescriptor,
        value: ((value: object) => {
          const frozen = originalFreeze(value);
          const candidate = value as Record<string, unknown>;
          if (
            frozenCapability === null && typeof candidate.seedRoot === "string" &&
            typeof candidate.statePath === "string" &&
            typeof candidate.workspaceRoot === "string" && candidate.sourceSnapshot !== undefined &&
            candidate.workspaceObservation !== undefined
          ) {
            frozenCapability = frozen;
            expired = true;
          }
          return frozen;
        }) as typeof Object.freeze,
      });
      Object.defineProperty(process.hrtime, "bigint", {
        ...hrtimeDescriptor,
        value: () => originalHrtime() + (expired ? 600_000_000_000n : 0n),
      });
      assert.throws(
        () => workspace.captureAndSealCandidate({
          commandTimeoutMs: 60_000,
          custodyRoot: fixture.custody,
          maxAttempts: 1,
          sourceRoot: fixture.source,
        }),
        (error: WorkspaceError) => {
          refusal = error;
          return error.code === workspaceErrorCode("OPERATION_DEADLINE_EXCEEDED");
        },
      );
    } finally {
      Object.defineProperty(Object, "freeze", freezeDescriptor);
      Object.defineProperty(process.hrtime, "bigint", hrtimeDescriptor);
    }
    assert.equal(expired, true, "the final public capability freeze was not reached");
    assert.notEqual(frozenCapability, null);
    assert.throws(
      () => workspace.verifySealedSeed(frozenCapability as Capture),
      (error: WorkspaceError) => error.code === workspaceErrorCode("INVALID_ARGUMENT"),
    );
  } finally {
    cleanupReportedScratchRoots(errorPrivateRoots(refusal));
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
  }
});

test("Linux metadata is observed again after an anchor close failure", (t) => {
  if (process.platform !== "linux") {
    t.skip("requires the Linux metadata backend");
    return;
  }
  const fixture = minimalCaptureFixture("metadata-close-failure");
  const spawnDescriptor = Object.getOwnPropertyDescriptor(childProcess, "spawnSync");
  const closeDescriptor = Object.getOwnPropertyDescriptor(fs, "closeSync");
  assert.ok(spawnDescriptor !== undefined);
  assert.ok(closeDescriptor !== undefined);
  const originalSpawn = childProcess.spawnSync;
  const originalClose = fs.closeSync;
  let captured: Capture | null = null;
  let metadataCalls = 0;
  let failCloseFd: number | null = null;
  let closeFailed = false;
  try {
    captured = workspace.captureAndSealCandidate({
      custodyRoot: fixture.custody,
      maxAttempts: 1,
      sourceRoot: fixture.source,
    });
    const sealedCapture = captured;
    const tracked = path.join(sealedCapture.workspaceRoot, "tracked.txt");
    const before = fs.lstatSync(tracked, { bigint: true });
    // A real stat change requires a fresh observation. This seed must remain refused on retry.
    fs.chmodSync(tracked, Number(before.mode & 0o777n));
    assert.notEqual(fs.lstatSync(tracked, { bigint: true }).ctimeNs, before.ctimeNs);
    Object.defineProperty(childProcess, "spawnSync", {
      ...spawnDescriptor,
      value: ((...args: Parameters<typeof childProcess.spawnSync>) => {
        const childArgs = args[1];
        if (
          Array.isArray(childArgs) &&
          childArgs.some((argument) =>
            typeof argument === "string" && path.basename(argument) === "getfacl") &&
          childArgs.includes(`.${path.sep}tracked.txt`)
        ) {
          const stdio = (args[2] as { stdio?: unknown[] } | undefined)?.stdio;
          const fd = Array.isArray(stdio) ? stdio[3] : null;
          assert.equal(typeof fd, "number");
          const anchor = fs.fstatSync(fd as number, { bigint: true });
          assert.equal(`${anchor.dev}:${anchor.ino}`, sealedCapture.workspaceIdentity);
          metadataCalls += 1;
          if (!closeFailed) failCloseFd = fd as number;
        }
        return Reflect.apply(originalSpawn, childProcess, args);
      }) as typeof childProcess.spawnSync,
    });
    Object.defineProperty(fs, "closeSync", {
      ...closeDescriptor,
      value: (...args: Parameters<typeof fs.closeSync>) => {
        const failThisClose = args[0] === failCloseFd;
        if (failThisClose) failCloseFd = null;
        const result = Reflect.apply(originalClose, fs, args);
        if (failThisClose) {
          closeFailed = true;
          throw Object.assign(new Error("one-shot metadata anchor close failure"), { code: "EIO" });
        }
        return result;
      },
    });
    syncBuiltinESMExports();
    const openCustody = () => workspace.openKnockoutCustody(sealedCapture, {
      maxRetainedArms: 1,
      maxRetainedBytes: 16 * 1024 * 1024,
    });
    assert.throws(openCustody, (error: WorkspaceError) =>
      error.code === workspaceErrorCode("SNAPSHOT_UNSTABLE"));
    assert.equal(closeFailed, true, "the metadata anchor close failure was not reached");
    assert.equal(metadataCalls, 1);
    assert.throws(openCustody, (error: WorkspaceError) =>
      error.code === workspaceErrorCode("MANIFEST_MISMATCH"));
    assert.equal(metadataCalls, 2, "failed cleanup left reusable metadata evidence");
    assert.equal(fs.readFileSync(fixture.trackedPath, "utf8"), "stable source bytes\n");
  } finally {
    Object.defineProperty(childProcess, "spawnSync", spawnDescriptor);
    Object.defineProperty(fs, "closeSync", closeDescriptor);
    syncBuiltinESMExports();
    cleanupReportedScratchRoots(captured?.retainedPrivateRoots ?? []);
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
  }
});

test("capture reuses metadata evidence while each fresh arm is observed in fixed chunks", async () => {
  const fixture = minimalCaptureFixture("metadata-cache");
  const spawnDescriptor = Object.getOwnPropertyDescriptor(childProcess, "spawnSync");
  assert.ok(spawnDescriptor !== undefined);
  const originalSpawnSync = childProcess.spawnSync;
  const metadataBatches: Array<{ anchor: string; mode: "acl" | "xattr"; nodes: string[] }> = [];
  const legacyTrackedAclAnchors: string[] = [];
  let captured: Capture | null = null;
  let cooperativeLease: CooperativeSourceLease | null = null;
  let arm: DisposableArm | null = null;
  let released: SourceRelease | null = null;
  try {
    try {
      Object.defineProperty(childProcess, "spawnSync", {
        ...spawnDescriptor,
        value: ((...args: Parameters<typeof childProcess.spawnSync>) => {
          const childArgs = args[1];
          if (Array.isArray(childArgs) && childArgs.includes("/usr/bin/python3")) {
            const stdio = (args[2] as { stdio?: unknown[] } | undefined)?.stdio;
            const directoryFd = Array.isArray(stdio) ? stdio[3] : null;
            if (typeof directoryFd === "number") {
              const stat = fs.fstatSync(directoryFd, { bigint: true });
              const mode = childArgs.includes("acl") ? "acl" : "xattr";
              metadataBatches.push({
                anchor: `${stat.dev}:${stat.ino}`,
                mode,
                nodes: stdio!.slice(4).map((fd) => {
                  assert.equal(typeof fd, "number");
                  const node = fs.fstatSync(fd as number, { bigint: true });
                  return `${node.dev}:${node.ino}`;
                }),
              });
            }
          } else if (
            Array.isArray(childArgs) &&
            childArgs.some((argument) =>
              argument === "/bin/ls" ||
              (typeof argument === "string" && path.basename(argument) === "getfacl")) &&
            childArgs.some((argument) => argument === `.${path.sep}tracked.txt`)
          ) {
            const stdio = (args[2] as { stdio?: unknown[] } | undefined)?.stdio;
            const directoryFd = Array.isArray(stdio) ? stdio[3] : null;
            if (typeof directoryFd === "number") {
              const stat = fs.fstatSync(directoryFd, { bigint: true });
              legacyTrackedAclAnchors.push(`${stat.dev}:${stat.ino}`);
            }
          }
          return Reflect.apply(originalSpawnSync, childProcess, args);
        }) as typeof childProcess.spawnSync,
      });
      syncBuiltinESMExports();
      captured = workspace.captureAndSealCandidate({
        custodyRoot: fixture.custody,
        maxAttempts: 1,
        sourceRoot: fixture.source,
      });
      const sealedCapture = captured;
      const sourceStat = fs.lstatSync(fixture.source, { bigint: true });
      const sourceTracked = fs.lstatSync(path.join(fixture.source, "tracked.txt"), { bigint: true });
      const destinationTracked = fs.lstatSync(
        path.join(sealedCapture.workspaceRoot, "tracked.txt"),
        { bigint: true },
      );
      const trackedIdentities = new Set([
        `${sourceTracked.dev}:${sourceTracked.ino}`,
        `${destinationTracked.dev}:${destinationTracked.ino}`,
      ]);
      const trackedAclAnchors = process.platform === "darwin"
        ? metadataBatches
            .filter((batch) =>
              batch.mode === "acl" && batch.nodes.some((identity) => trackedIdentities.has(identity)))
            .map((batch) => batch.anchor)
        : legacyTrackedAclAnchors;
      assert.deepEqual(
        trackedAclAnchors.sort(),
        [`${sourceStat.dev}:${sourceStat.ino}`, sealedCapture.workspaceIdentity].sort(),
        "source/destination ACL metadata must each be externally observed exactly once",
      );
      const destinationTrackedIdentity = `${destinationTracked.dev}:${destinationTracked.ino}`;
      const trackedObservationCount = () => process.platform === "darwin"
        ? metadataBatches.filter((batch) => batch.nodes.includes(destinationTrackedIdentity)).length
        : legacyTrackedAclAnchors.length;
      const destinationTrackedCallsAfterCapture = trackedObservationCount();
      assert.equal(destinationTrackedCallsAfterCapture, 2);
      assert.doesNotThrow(() => workspace.verifySealedSeed(sealedCapture));
      assert.equal(
        trackedObservationCount(),
        destinationTrackedCallsAfterCapture,
        "unchanged seed verification re-observed cached tracked-file metadata",
      );
      if (process.platform === "darwin") {
        const custody = workspace.openKnockoutCustody(sealedCapture, {
          maxRetainedArms: 1,
          maxRetainedBytes: 64 * 1024 * 1024,
        });
        const sourceLease = workspace.acquireSourceLease(custody);
        cooperativeLease = await workspace.acquireCooperativeSourceLease(sourceLease);
        const plan = workspace.admitArmPlan(cooperativeLease, {
          arms: [{ armId: "metadata-batch", role: "SELFTEST", subjectSha256: "1".repeat(64) }],
        });
        assert.equal(
          metadataBatches.filter((batch) => batch.nodes.includes(destinationTrackedIdentity)).length,
          destinationTrackedCallsAfterCapture,
          "opening custody or leasing an unchanged seed re-observed cached tracked metadata",
        );
        arm = workspace.materializeArm(plan, "metadata-batch");
        const armStat = fs.lstatSync(arm.workspaceRoot, { bigint: true });
        const armIdentity = `${armStat.dev}:${armStat.ino}`;
        const completeArmCensusBatches = metadataBatches.filter((batch) =>
          batch.anchor === armIdentity &&
          batch.nodes.length === sealedCapture.workspaceObservation.nodeCount);
        assert.deepEqual(
          completeArmCensusBatches.map((batch) => batch.mode).sort(),
          ["acl", "xattr"],
          "the fresh arm census did not batch all fixture nodes once per native API",
        );
        const armTracked = fs.lstatSync(path.join(arm.workspaceRoot, "tracked.txt"), {
          bigint: true,
        });
        const armTrackedBatches = metadataBatches.filter((batch) =>
          batch.nodes.includes(`${armTracked.dev}:${armTracked.ino}`));
        assert.deepEqual(
          armTrackedBatches.map((batch) => batch.mode).sort(),
          ["acl", "xattr"],
          "the fresh arm tracked file was not observed exactly once by each native API batch",
        );
        assert.equal(
          arm.seedObservationSha256,
          sealedCapture.workspaceObservation.observationSha256,
        );
        workspace.cancelMaterializedArm(cooperativeLease, arm, "TEST_COMPLETE");
        arm = null;
        const closed = await workspace.closeCooperativeSourceLease(cooperativeLease);
        cooperativeLease = null;
        released = closed.sourceRelease;
        assert.equal(released.status, "RELEASED");
      }
    } finally {
      Object.defineProperty(childProcess, "spawnSync", spawnDescriptor);
      syncBuiltinESMExports();
    }
  } finally {
    if (cooperativeLease !== null) {
      if (arm !== null) {
        try { workspace.cancelMaterializedArm(cooperativeLease, arm, "TEST_CLEANUP"); }
        catch {}
      }
      try {
        const closed = await workspace.closeCooperativeSourceLease(cooperativeLease);
        released = closed.sourceRelease;
      } catch {}
    }
    cleanupReportedScratchRoots(released?.retainedPrivateRoots ?? captured?.retainedPrivateRoots ?? []);
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
  }
});

test("Darwin directory cohorts batch more than 64 siblings across distinct depths", (t) => {
  if (process.platform !== "darwin") {
    t.skip("requires the Darwin metadata backend");
    return;
  }
  const fixture = minimalCaptureFixture("directory-cohort-depths");
  const originalMkdir = fs.mkdirSync;
  const originalSpawn = childProcess.spawnSync;
  const copiedIdentities = new Set<string>();
  const observedModes = new Map<string, Set<string>>();
  let copiedMetadataCalls = 0;
  let widestBatch = 0;
  let captured: Capture | null = null;
  try {
    for (let index = 0; index < 70; index += 1) {
      const directory = path.join(fixture.source, `cohort-${index}`, "nested");
      fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
      fs.writeFileSync(path.join(directory, "leaf.txt"), `cohort ${index}\n`, { mode: 0o600 });
    }
    fs.mkdirSync = ((...args: Parameters<typeof fs.mkdirSync>) => {
      const result = Reflect.apply(originalMkdir, fs, args);
      if (String(args[0]).includes(`${path.sep}workspace${path.sep}cohort-`)) {
        const stat = fs.lstatSync(args[0], { bigint: true });
        copiedIdentities.add(`${stat.dev}:${stat.ino}`);
      }
      return result;
    }) as typeof fs.mkdirSync;
    childProcess.spawnSync = ((...args: Parameters<typeof childProcess.spawnSync>) => {
      const childArgs = args[1];
      if (Array.isArray(childArgs) && childArgs.includes("/usr/bin/python3")) {
        const stdio = (args[2] as { stdio?: unknown[] } | undefined)?.stdio;
        if (Array.isArray(stdio) && stdio.length > 4) {
          const mode = childArgs.includes("acl") ? "acl" : "xattr";
          const identities = stdio.slice(4).map((fd) => {
            assert.equal(typeof fd, "number");
            const stat = fs.fstatSync(fd as number, { bigint: true });
            return `${stat.dev}:${stat.ino}`;
          });
          assert.ok(identities.length <= 64, "native metadata descriptor bound exceeded");
          const matching = identities.filter((identity) => copiedIdentities.has(identity));
          if (matching.length > 0) {
            copiedMetadataCalls += 1;
            widestBatch = Math.max(widestBatch, matching.length);
            for (const identity of matching) {
              const modes = observedModes.get(identity) ?? new Set<string>();
              modes.add(mode);
              observedModes.set(identity, modes);
            }
          }
        }
      }
      return Reflect.apply(originalSpawn, childProcess, args);
    }) as typeof childProcess.spawnSync;
    syncBuiltinESMExports();
    captured = workspace.captureAndSealCandidate({
      custodyRoot: fixture.custody,
      maxAttempts: 1,
      sourceRoot: fixture.source,
    });
    assert.equal(copiedIdentities.size, 140);
    assert.ok(widestBatch > 1, "directory metadata was never batched");
    assert.ok(copiedMetadataCalls < copiedIdentities.size, "per-directory helper amplification remains");
    for (const identity of copiedIdentities) {
      assert.deepEqual([...(observedModes.get(identity) ?? [])].sort(), ["acl", "xattr"]);
    }
    for (let index = 0; index < 70; index += 1) {
      assert.equal(
        fs.readFileSync(path.join(captured.workspaceRoot, `cohort-${index}`, "nested/leaf.txt"), "utf8"),
        `cohort ${index}\n`,
      );
    }
    assert.doesNotThrow(() => workspace.verifySealedSeed(captured!));
    t.diagnostic(JSON.stringify({ directories: copiedIdentities.size, copiedMetadataCalls, widestBatch }));
  } finally {
    fs.mkdirSync = originalMkdir;
    childProcess.spawnSync = originalSpawn;
    syncBuiltinESMExports();
    cleanupReportedScratchRoots(captured?.retainedPrivateRoots ?? []);
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
  }
});

for (const fault of ["parent-replacement", "child-replacement", "child-xattr", "child-fsync", "child-close", "parent-close"] as const) {
  test(`Darwin directory cohort refuses ${fault} before copied file use`, (t) => {
    if (process.platform !== "darwin") {
      t.skip("requires the Darwin directory cohort path");
      return;
    }
    const fixture = minimalCaptureFixture(`directory-cohort-${fault}`);
    const originalMkdir = fs.mkdirSync;
    const originalOpen = fs.openSync;
    const originalClose = fs.closeSync;
    const originalFsync = fs.fsyncSync;
    const descriptors = new Map<number, string>();
    let createdPath: string | null = null;
    let heldParentDescriptor: number | null = null;
    let injected = false;
    let copiedLeafOpened = false;
    let refusal: WorkspaceError | null = null;
    let captured: Capture | null = null;
    const injectionMessage = `injected directory cohort ${fault}`;
    try {
      fs.mkdirSync(path.join(fixture.source, "cohort-parent", "nested"), { recursive: true, mode: 0o700 });
      fs.writeFileSync(path.join(fixture.source, "cohort-parent", "nested", "leaf.txt"), "protected bytes\n");
      fs.mkdirSync = ((...args: Parameters<typeof fs.mkdirSync>) => {
        const result = Reflect.apply(originalMkdir, fs, args);
        const absolute = String(args[0]);
        if (absolute.includes(`${path.sep}workspace${path.sep}cohort-parent`)) {
          createdPath = absolute;
          if (fault === "parent-close" && heldParentDescriptor === null) {
            const held = [...descriptors].find(([, directory]) => directory === path.dirname(absolute));
            assert.notEqual(held, undefined, "the cohort parent descriptor is not held across mkdir");
            heldParentDescriptor = held![0];
          }
          if (!injected && fault === "parent-replacement" && path.basename(absolute) === "nested") {
            injected = true;
            const parent = path.dirname(absolute);
            fs.renameSync(parent, `${parent}-retained`);
            originalMkdir(parent, { mode: 0o700 });
          }
        }
        return result;
      }) as typeof fs.mkdirSync;
      fs.openSync = ((...args: Parameters<typeof fs.openSync>) => {
        const absolute = String(args[0]);
        if (absolute.includes(`${path.sep}workspace${path.sep}cohort-parent${path.sep}nested${path.sep}leaf.txt`)) {
          copiedLeafOpened = true;
        }
        const fd = Reflect.apply(originalOpen, fs, args);
        descriptors.set(fd, absolute);
        return fd;
      }) as typeof fs.openSync;
      fs.fsyncSync = (fd: number) => {
        originalFsync(fd);
        const absolute = descriptors.get(fd);
        if (injected || createdPath === null) return;
        if (fault === "child-fsync" && absolute === createdPath) {
          injected = true;
          throw Object.assign(new Error(injectionMessage), { code: "EIO" });
        }
        if (absolute !== path.dirname(createdPath) || !["child-replacement", "child-xattr"].includes(fault)) return;
        injected = true;
        if (fault === "child-replacement") {
          fs.renameSync(createdPath, `${createdPath}-retained`);
          originalMkdir(createdPath, { mode: 0o700 });
        } else {
          execFileSync("/usr/bin/xattr", ["-w", "com.noa.cohort-test", "changed", createdPath]);
        }
      };
      fs.closeSync = (fd: number) => {
        const absolute = descriptors.get(fd);
        descriptors.delete(fd);
        originalClose(fd);
        if (injected || createdPath === null) return;
        if ((fault === "child-close" && absolute === createdPath)
          || (fault === "parent-close" && fd === heldParentDescriptor)) {
          injected = true;
          throw Object.assign(new Error(injectionMessage), { code: "EIO" });
        }
      };
      syncBuiltinESMExports();
      assert.throws(() => {
        captured = workspace.captureAndSealCandidate({
          custodyRoot: fixture.custody,
          maxAttempts: 1,
          sourceRoot: fixture.source,
        });
      }, (error: WorkspaceError) => {
        refusal = error;
        return error instanceof Error;
      });
      assert.equal(injected, true, "the directory cohort fault window was not reached");
      assert.equal(copiedLeafOpened, false, "an unvalidated cohort reached copied file use");
      assert.equal(captured, null, "a failed cohort published a capture capability");
      if (fault.endsWith("close") || fault === "child-fsync") {
        assert.ok(errorTreeHasCode(refusal, "EIO"), `the injected durability/close failure was lost: ${errorChain(refusal)}`);
      }
      assert.equal(fs.readFileSync(path.join(fixture.source, "cohort-parent", "nested", "leaf.txt"), "utf8"), "protected bytes\n");
    } finally {
      fs.mkdirSync = originalMkdir;
      fs.openSync = originalOpen;
      fs.closeSync = originalClose;
      fs.fsyncSync = originalFsync;
      syncBuiltinESMExports();
      cleanupReportedScratchRoots(errorPrivateRoots(refusal));
      cleanupReportedScratchRoots((captured as Capture | null)?.retainedPrivateRoots ?? []);
      removeFixturePath(fixture.source);
      removeFixturePath(fixture.custody);
    }
  });
}

for (const refusalKind of ["deadline", "principal"] as const) {
  for (const closeFails of [false, true]) {
    test(`Darwin cohort provisional parent closes on ${refusalKind} refusal with close failure ${closeFails}`, (t) => {
      if (process.platform !== "darwin") {
        t.skip("requires the Darwin directory cohort path");
        return;
      }
      const fixture = minimalCaptureFixture(`cohort-bind-${refusalKind}-${closeFails}`);
      const originalOpen = fs.openSync;
      const originalFstat = fs.fstatSync;
      const originalClose = fs.closeSync;
      const originalMkdir = fs.mkdirSync;
      const clockDescriptor = Object.getOwnPropertyDescriptor(process.hrtime, "bigint");
      const uidDescriptor = Object.getOwnPropertyDescriptor(process, "geteuid");
      assert.ok(clockDescriptor !== undefined);
      assert.ok(uidDescriptor !== undefined);
      const originalClock = process.hrtime.bigint;
      const originalUid = process.geteuid!;
      let provisionalFd: number | null = null;
      let injected = false;
      let closeCalls = 0;
      let childCreated = false;
      let copiedLeafOpened = false;
      let refusal: WorkspaceError | null = null;
      let captured: Capture | null = null;
      const expectedCode = workspaceErrorCode(
        refusalKind === "deadline" ? "OPERATION_DEADLINE_EXCEEDED" : "PRIVATE_ROOT_UNSAFE",
      );
      try {
        fs.mkdirSync(path.join(fixture.source, "cohort-child"), { mode: 0o700 });
        fs.writeFileSync(path.join(fixture.source, "cohort-child", "leaf.txt"), "preserved bytes\n");
        fs.openSync = ((...args: Parameters<typeof fs.openSync>) => {
          if (String(args[0]).includes(`${path.sep}workspace${path.sep}cohort-child${path.sep}leaf.txt`)) {
            copiedLeafOpened = true;
          }
          const fd = Reflect.apply(originalOpen, fs, args);
          // Select the actual held-parent admission, rather than an earlier metadata anchor.
          const stack = new Error().stack ?? "";
          if (provisionalFd === null && stack.includes("bindDirectoryDescriptor")
            && stack.includes("createPrivateDirectoryCohort")) provisionalFd = fd;
          return fd;
        }) as typeof fs.openSync;
        fs.fstatSync = ((...args: Parameters<typeof fs.fstatSync>) => {
          const result = Reflect.apply(originalFstat, fs, args);
          if (args[0] === provisionalFd) injected = true;
          return result;
        }) as typeof fs.fstatSync;
        fs.mkdirSync = ((...args: Parameters<typeof fs.mkdirSync>) => {
          if (String(args[0]).includes(`${path.sep}workspace${path.sep}cohort-child`)) childCreated = true;
          return Reflect.apply(originalMkdir, fs, args);
        }) as typeof fs.mkdirSync;
        fs.closeSync = (fd: number) => {
          if (fd === provisionalFd) closeCalls += 1;
          originalClose(fd);
          if (fd === provisionalFd && closeFails) {
            throw Object.assign(new Error("injected provisional parent close failure"), { code: "EIO" });
          }
        };
        Object.defineProperty(process.hrtime, "bigint", {
          ...clockDescriptor,
          value: () => originalClock() + (injected && refusalKind === "deadline" ? 86_400_000_000_000n : 0n),
        });
        Object.defineProperty(process, "geteuid", {
          ...uidDescriptor,
          value: () => originalUid() + (injected && refusalKind === "principal" ? 1 : 0),
        });
        syncBuiltinESMExports();
        assert.throws(() => {
          captured = workspace.captureAndSealCandidate({
            custodyRoot: fixture.custody,
            maxAttempts: 1,
            sourceRoot: fixture.source,
          });
        }, (error: WorkspaceError) => {
          refusal = error;
          return error.code === expectedCode;
        });
        assert.equal(injected, true, "the provisional parent admission window was not reached");
        assert.match(errorChain(refusal), /descriptor bind for private-directory cohort parent/);
        assert.equal(childCreated, false, "refused parent custody reached child creation");
        assert.equal(copiedLeafOpened, false, "refused parent custody reached copied file use");
        assert.equal(captured, null, "refused parent custody published a capture capability");
        t.diagnostic(JSON.stringify({ refusalKind, closeFails, closeCalls }));
        assert.equal(closeCalls, 1, "the provisional parent descriptor must be closed exactly once");
        assert.throws(() => originalFstat(provisionalFd!), (error: NodeJS.ErrnoException) => error.code === "EBADF");
        assert.equal(errorTreeHasCode(refusal, "EIO"), closeFails, "the close failure must remain visible");
        assert.equal(fs.readFileSync(path.join(fixture.source, "cohort-child", "leaf.txt"), "utf8"), "preserved bytes\n");
      } finally {
        fs.openSync = originalOpen;
        fs.fstatSync = originalFstat;
        fs.closeSync = originalClose;
        fs.mkdirSync = originalMkdir;
        Object.defineProperty(process.hrtime, "bigint", clockDescriptor);
        Object.defineProperty(process, "geteuid", uidDescriptor);
        syncBuiltinESMExports();
        if (provisionalFd !== null && closeCalls === 0) originalClose(provisionalFd);
        cleanupReportedScratchRoots(errorPrivateRoots(refusal));
        cleanupReportedScratchRoots((captured as Capture | null)?.retainedPrivateRoots ?? []);
        removeFixturePath(fixture.source);
        removeFixturePath(fixture.custody);
      }
    });
  }
}

test("linked main-worktree child configuration is closed before any object command", () => {
  const fixture = linkedWorktreeFixture("common-worktree-refusal");
  const tools = privateTemp("noa-kws-common-worktree-refusal-tools-");
  const marker = path.join(tools, "object-child-reached");
  const observingGit = path.join(tools, "git-object-marker");
  try {
    git(fixture.main, ["config", "extensions.worktreeConfig", "true"]);
    git(fixture.main, ["config", "--worktree", "pack.threads", "64"]);
    const counterfactual = execFileSync(
      gitExecutable,
      ["config", "--get", "pack.threads"],
      {
        cwd: path.join(fixture.main, ".git", "objects"),
        encoding: "utf8",
        env: {
          ...gitEnvironment,
          GIT_DIR: "..",
          GIT_OBJECT_DIRECTORY: ".",
        },
      },
    ).trim();
    assert.equal(counterfactual, "64", "the old object-child environment did not read the unsafe input");
    fs.writeFileSync(observingGit, [
      "#!/bin/sh",
      "if [ \"${GIT_DIR-}\" = \"..\" ]; then",
      `  /usr/bin/printf reached > ${JSON.stringify(marker)}`,
      "fi",
      `exec ${JSON.stringify(gitExecutable)} \"$@\"`,
      "",
    ].join("\n"), { mode: 0o700 });
    assert.throws(
      () => workspace.captureAndSealCandidate({
        custodyRoot: fixture.custody,
        gitExecutable: observingGit,
        maxAttempts: 1,
        sourceRoot: fixture.linked,
      }),
      (error: WorkspaceError) =>
        error.code === workspaceErrorCode("SOURCE_GIT_LAYOUT_UNSUPPORTED"),
    );
    assert.equal(pathExistsNoFollow(marker), false, "an object command ran before config refusal");
    assert.deepEqual(fs.readdirSync(fixture.custody), []);
  } finally {
    removeFixturePath(fixture.fixtureRoot);
    removeFixturePath(fixture.custody);
    removeFixturePath(tools);
  }
});

test("a second common-directory commondir indirection is refused before object authority", () => {
  const fixture = linkedWorktreeFixture("nested-commondir");
  const commonDirectory = path.join(fixture.main, ".git");
  const thirdCommon = path.join(fixture.fixtureRoot, "third-common");
  try {
    fs.cpSync(commonDirectory, thirdCommon, { preserveTimestamps: true, recursive: true });
    fs.writeFileSync(
      path.join(commonDirectory, "commondir"),
      `${path.relative(commonDirectory, thirdCommon)}\n`,
      { mode: 0o600 },
    );
    const counterfactual = execFileSync(
      gitExecutable,
      ["rev-parse", "--path-format=absolute", "--git-common-dir"],
      {
        cwd: path.join(commonDirectory, "objects"),
        encoding: "utf8",
        env: {
          ...gitEnvironment,
          GIT_DIR: "..",
          GIT_OBJECT_DIRECTORY: ".",
        },
      },
    ).trim();
    assert.equal(fs.realpathSync(counterfactual), fs.realpathSync(thirdCommon));
    assert.throws(
      () => workspace.captureAndSealCandidate({
        custodyRoot: fixture.custody,
        maxAttempts: 1,
        sourceRoot: fixture.linked,
      }),
      (error: WorkspaceError) =>
        error.code === workspaceErrorCode("SOURCE_GIT_LAYOUT_UNSUPPORTED"),
    );
    assert.deepEqual(fs.readdirSync(fixture.custody), []);
  } finally {
    removeFixturePath(fixture.fixtureRoot);
    removeFixturePath(fixture.custody);
  }
});

test("object authority detects same-inode config rewrites restored by the Git child", () => {
  const fixture = linkedWorktreeFixture("object-config-custody");
  const tools = privateTemp("noa-kws-object-config-custody-tools-");
  const marker = path.join(tools, "object-child-reached");
  const backup = path.join(tools, "config.backup");
  const attackingGit = path.join(tools, "git-rewrite-config");
  const configPath = path.join(fixture.main, ".git", "config");
  let refusal: WorkspaceError | null = null;
  try {
    git(fixture.main, ["config", "extensions.worktreeConfig", "true"]);
    git(fixture.main, ["config", "--worktree", "core.ignorecase", "false"]);
    git(fixture.linked, ["config", "--worktree", "core.filemode", "false"]);
    const configBefore = fs.readFileSync(configPath);
    const inodeBefore = fs.lstatSync(configPath, { bigint: true }).ino;
    fs.writeFileSync(attackingGit, [
      "#!/bin/sh",
      "if [ \"${GIT_DIR-}\" = \"..\" ] && [ \"${GIT_COMMON_DIR-}\" = \"..\" ] && " +
        `[ ! -e ${JSON.stringify(marker)} ]; then`,
      `  /bin/cp ../config ${JSON.stringify(backup)} || exit 92`,
      "  /usr/bin/printf '\\n[pack]\\n\\tthreads = 64\\n' >> ../config || exit 93",
      `  ${JSON.stringify(gitExecutable)} \"$@\"`,
      "  status=$?",
      `  /bin/cat ${JSON.stringify(backup)} > ../config || exit 94`,
      `  /usr/bin/printf reached > ${JSON.stringify(marker)}`,
      "  exit $status",
      "fi",
      `exec ${JSON.stringify(gitExecutable)} \"$@\"`,
      "",
    ].join("\n"), { mode: 0o700 });
    assert.throws(
      () => workspace.observeSourceGit(fixture.linked, {
        gitExecutable: attackingGit,
        scratchRoot: fixture.custody,
      }),
      (error: WorkspaceError) => {
        refusal = error;
        return error.code === workspaceErrorCode("SOURCE_CHANGED");
      },
    );
    assert.equal(pathExistsNoFollow(marker), true, "the object-child rewrite was not exercised");
    assert.deepEqual(fs.readFileSync(configPath), configBefore);
    assert.equal(fs.lstatSync(configPath, { bigint: true }).ino, inodeBefore);
  } finally {
    cleanupReportedScratchRoots(errorPrivateRoots(refusal));
    removeFixturePath(fixture.fixtureRoot);
    removeFixturePath(fixture.custody);
    removeFixturePath(tools);
  }
});

test("standalone validation parses the already bounded index bytes without a pathname reread", () => {
  const fixture = minimalCaptureFixture("bounded-index-bytes");
  const readDescriptor = Object.getOwnPropertyDescriptor(fs, "readFileSync");
  assert.ok(readDescriptor !== undefined);
  const originalReadFile = fs.readFileSync;
  let generatedIndex: string | null = null;
  let forbiddenReads = 0;
  let captured: Capture | null = null;
  try {
    try {
      Object.defineProperty(fs, "readFileSync", {
        ...readDescriptor,
        value: ((...args: Parameters<typeof fs.readFileSync>) => {
          if (
            generatedIndex !== null && typeof args[0] === "string" &&
            path.resolve(args[0]) === generatedIndex
          ) {
            forbiddenReads += 1;
            throw new Error("standalone index pathname reread");
          }
          return Reflect.apply(originalReadFile, fs, args);
        }) as typeof fs.readFileSync,
      });
      captured = workspace.captureAndSealCandidate({
        custodyRoot: fixture.custody,
        hooks: {
          afterWorktreeCopy({ workspaceRoot }) {
            generatedIndex = path.join(workspaceRoot, ".git", "index");
          },
        },
        maxAttempts: 1,
        sourceRoot: fixture.source,
      });
    } finally {
      Object.defineProperty(fs, "readFileSync", readDescriptor);
    }
    assert.notEqual(generatedIndex, null);
    assert.equal(forbiddenReads, 0);
    assert.doesNotThrow(() => workspace.verifySealedSeed(captured!));
  } finally {
    cleanupReportedScratchRoots(captured?.retainedPrivateRoots ?? []);
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
  }
});

test("seed-index drift uses standalone Git taxonomy and never terminal taxonomy", () => {
  const fixture = minimalCaptureFixture("seed-index-taxonomy");
  const execDescriptor = Object.getOwnPropertyDescriptor(childProcess, "execFileSync");
  assert.ok(execDescriptor !== undefined);
  const originalExecFileSync = childProcess.execFileSync;
  let mutated = false;
  let refusal: WorkspaceError | null = null;
  try {
    try {
      Object.defineProperty(childProcess, "execFileSync", {
        ...execDescriptor,
        value: ((...args: Parameters<typeof childProcess.execFileSync>) => {
          const result = Reflect.apply(originalExecFileSync, childProcess, args);
          const childArgs = Array.isArray(args[1]) ? args[1].map(String) : [];
          if (
            !mutated && childArgs.includes("rev-parse") &&
            childArgs.includes("--git-path") && childArgs.includes("index")
          ) {
            const indexPath = Buffer.isBuffer(result)
              ? result.toString("utf8").trim()
              : String(result).trim();
            if (
              path.isAbsolute(indexPath) &&
              indexPath.startsWith(`${fs.realpathSync(fixture.custody)}${path.sep}seed-attempt-`) &&
              indexPath.endsWith(`${path.sep}workspace${path.sep}.git${path.sep}index`)
            ) {
              fs.appendFileSync(indexPath, "X");
              mutated = true;
            }
          }
          return result;
        }) as typeof childProcess.execFileSync,
      });
      syncBuiltinESMExports();
      assert.throws(
        () => workspace.captureAndSealCandidate({
          custodyRoot: fixture.custody,
          maxAttempts: 1,
          sourceRoot: fixture.source,
        }),
        (error: WorkspaceError) => {
          refusal = error;
          return error.code === workspaceErrorCode("STANDALONE_GIT_INVALID");
        },
      );
    } finally {
      Object.defineProperty(childProcess, "execFileSync", execDescriptor);
      syncBuiltinESMExports();
    }
    assert.equal(mutated, true, "the generated seed index was not mutated");
    assert.equal(
      errorTreeHasCode(refusal, workspaceErrorCode("TERMINAL_HASH_MISMATCH")),
      false,
      errorChain(refusal),
    );
    assert.equal(
      errorTreeHasCode(refusal, workspaceErrorCode("TERMINAL_IDENTITY_MISMATCH")),
      false,
      errorChain(refusal),
    );
  } finally {
    cleanupReportedScratchRoots(errorPrivateRoots(refusal));
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
  }
});

test("manifest drift uses manifest taxonomy and never terminal taxonomy", () => {
  const fixture = minimalCaptureFixture("manifest-taxonomy");
  const execDescriptor = Object.getOwnPropertyDescriptor(childProcess, "execFileSync");
  assert.ok(execDescriptor !== undefined);
  const originalExecFileSync = childProcess.execFileSync;
  let captured: Capture | null = null;
  let refusal: WorkspaceError | null = null;
  let mutated = false;
  try {
    captured = workspace.captureAndSealCandidate({
      custodyRoot: fixture.custody,
      maxAttempts: 1,
      sourceRoot: fixture.source,
    });
    const originalManifest = fs.readFileSync(captured.manifestPath);
    const changedManifest = Buffer.from(originalManifest);
    const attempt = changedManifest.indexOf(Buffer.from('"attempt":1'));
    assert.ok(attempt >= 0);
    changedManifest[attempt + '"attempt":'.length] = "2".charCodeAt(0);
    try {
      Object.defineProperty(childProcess, "execFileSync", {
        ...execDescriptor,
        value: ((...args: Parameters<typeof childProcess.execFileSync>) => {
          const result = Reflect.apply(originalExecFileSync, childProcess, args);
          const childArgs = args[1];
          if (
            !mutated && Array.isArray(childArgs) && childArgs.includes("fsck") &&
            childArgs.includes("--no-reflogs")
          ) {
            const fd = fs.openSync(captured!.manifestPath, fs.constants.O_WRONLY | fs.constants.O_NOFOLLOW);
            try {
              fs.writeSync(fd, changedManifest, 0, changedManifest.length, 0);
              fs.fsyncSync(fd);
            } finally {
              fs.closeSync(fd);
            }
            mutated = true;
          }
          return result;
        }) as typeof childProcess.execFileSync,
      });
      syncBuiltinESMExports();
      assert.throws(
        () => workspace.verifySealedSeed(captured!),
        (error: WorkspaceError) => {
          refusal = error;
          return error.code === workspaceErrorCode("MANIFEST_MISMATCH");
        },
      );
    } finally {
      Object.defineProperty(childProcess, "execFileSync", execDescriptor);
      syncBuiltinESMExports();
    }
    assert.equal(mutated, true, "the post-validation manifest mutation was not reached");
    assert.equal(
      errorTreeHasCode(refusal, workspaceErrorCode("TERMINAL_HASH_MISMATCH")),
      false,
      errorChain(refusal),
    );
    assert.equal(
      errorTreeHasCode(refusal, workspaceErrorCode("TERMINAL_IDENTITY_MISMATCH")),
      false,
      errorChain(refusal),
    );
  } finally {
    cleanupReportedScratchRoots(captured?.retainedPrivateRoots ?? []);
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
  }
});

test("Phase 2 projects a valid source-bound migration tombstone out of portable seeds and arms", async () => {
  const fixture = minimalCaptureFixture("phase2-root-local-tombstone");
  const tombstonePath = path.join(
    fixture.source,
    "node_modules", ".cache", "noa-knockout", "lock.json",
  );
  let captured: Capture | null = null;
  let cooperativeLease: CooperativeSourceLease | null = null;
  let released: SourceRelease | null = null;
  let selftestArm: DisposableArm | null = null;
  let baselineArm: DisposableArm | null = null;
  let armGuard: ReturnType<typeof knockoutRunner.createBuildStateGuard> | null = null;
  let armGuardCache: string | null = null;
  try {
    fs.writeFileSync(path.join(fixture.source, ".gitignore"), "node_modules/\n", { mode: 0o600 });
    git(fixture.source, ["add", ".gitignore"]);
    git(fixture.source, ["commit", "-q", "-m", "ignore installed runtime state"]);
    fs.mkdirSync(path.dirname(tombstonePath), { recursive: true });
    const sourceRootStat = fs.lstatSync(fixture.source, { bigint: true });
    const sourceRootIdentity = `${sourceRootStat.dev}:${sourceRootStat.ino}`;
    const sourceRecord = {
      protocol: "noa-knockout-legacy-tombstone/1",
      root: fs.realpathSync(fixture.source),
      rootIdentity: `noa-directory/2:${sourceRootIdentity}`,
      migratedAt: "2026-09-03T00:00:00.000Z",
    };
    fs.writeFileSync(tombstonePath, JSON.stringify(sourceRecord), { mode: 0o600 });
    fs.chmodSync(tombstonePath, 0o600);
    const sourceBytesBefore = fs.readFileSync(tombstonePath);
    const sourceObservationBefore = pathStableObservation(tombstonePath);

    captured = workspace.captureAndSealCandidate({
      custodyRoot: fixture.custody,
      maxAttempts: 1,
      sourceRoot: fixture.source,
    });
    const projection = captured.manifest.rootLocalStateProjection;
    assert.deepEqual(projection, {
      action: "OMIT_FROM_PORTABLE_SEED",
      path: "node_modules/.cache/noa-knockout/lock.json",
      policy: "noa-knockout-root-local-state-projection/1",
      record: sourceRecord,
      sourceBytesBase64: sourceBytesBefore.toString("base64"),
      sourceFileSha256: sha256Bytes(sourceBytesBefore),
      sourceNodeSha256: projection.sourceNodeSha256,
      status: "VALID_SOURCE_BOUND",
    });
    assert.match(projection.sourceNodeSha256 ?? "", /^[0-9a-f]{64}$/);
    assert.equal(
      captured.manifest.source.nodes.some((node) =>
        node.path === "node_modules/.cache/noa-knockout/lock.json" &&
        node.sha256 === projection.sourceFileSha256),
      true,
      "full source evidence omitted the source-bound tombstone",
    );
    assert.equal(
      pathExistsNoFollow(path.join(captured.workspaceRoot, projection.path)),
      false,
      "portable seed copied a physical-root-bound tombstone",
    );
    assert.deepEqual(fs.readFileSync(tombstonePath), sourceBytesBefore);
    assert.deepEqual(pathStableObservation(tombstonePath), sourceObservationBefore);
    assert.doesNotThrow(() => workspace.verifySealedSeed(captured!));

    const custody = workspace.openKnockoutCustody(captured, {
      maxRetainedArms: 2,
      maxRetainedBytes: 64 * 1024 * 1024,
    });
    const sourceLease = workspace.acquireSourceLease(custody);
    cooperativeLease = await workspace.acquireCooperativeSourceLease(sourceLease);
    const plan = workspace.admitArmPlan(cooperativeLease, {
      arms: [
        { armId: "selftest-tombstone", role: "SELFTEST", subjectSha256: "1".repeat(64) },
        { armId: "baseline-tombstone", role: "BASELINE", subjectSha256: "2".repeat(64) },
      ],
    });
    selftestArm = workspace.materializeArm(plan, "selftest-tombstone");
    baselineArm = workspace.materializeArm(plan, "baseline-tombstone");
    for (const arm of [selftestArm, baselineArm]) {
      const armTombstone = path.join(arm.workspaceRoot, ...projection.path.split("/"));
      assert.equal(pathExistsNoFollow(armTombstone), false);
      assert.equal(
        workspace.censusWorkspace(arm.workspaceRoot, { rootGitPolicy: "include" }).observationSha256,
        arm.initialObservationSha256,
        "arm initial observation did not bind the projected tombstone absence",
      );
    }

    armGuard = knockoutRunner.createBuildStateGuard({ root: selftestArm.workspaceRoot });
    armGuardCache = armGuard.cacheDir;
    const started = armGuard.start();
    assert.equal(started.ok, true, JSON.stringify(started));
    assert.equal(knockoutRunner.assertKnockoutMigrationBarrier(selftestArm.workspaceRoot), true);
    assert.equal(armGuard.release(), true);
    armGuard = null;
    const armRecord = JSON.parse(fs.readFileSync(
      path.join(selftestArm.workspaceRoot, ...projection.path.split("/")),
      "utf8",
    )) as { root: string; rootIdentity: string };
    const armRootStat = fs.lstatSync(selftestArm.workspaceRoot, { bigint: true });
    assert.equal(armRecord.root, fs.realpathSync(selftestArm.workspaceRoot));
    assert.equal(armRecord.rootIdentity, `noa-directory/2:${armRootStat.dev}:${armRootStat.ino}`);
    assert.deepEqual(fs.readFileSync(tombstonePath), sourceBytesBefore);
    assert.deepEqual(pathStableObservation(tombstonePath), sourceObservationBefore);

    assert.equal(
      workspace.cancelMaterializedArm(cooperativeLease, selftestArm, "TEST_COMPLETE").status,
      "CANCELLED",
    );
    assert.equal(
      workspace.cancelMaterializedArm(cooperativeLease, baselineArm, "TEST_COMPLETE").status,
      "CANCELLED",
    );
    const closed = await workspace.closeCooperativeSourceLease(cooperativeLease);
    cooperativeLease = null;
    released = closed.sourceRelease;
    assert.equal(released.status, "RELEASED");
  } finally {
    if (armGuard !== null) {
      try { armGuard.release(); }
      catch {}
    }
    if (cooperativeLease !== null) {
      if (selftestArm !== null) {
        try { workspace.cancelMaterializedArm(cooperativeLease, selftestArm, "TEST_CLEANUP"); }
        catch {}
      }
      if (baselineArm !== null) {
        try { workspace.cancelMaterializedArm(cooperativeLease, baselineArm, "TEST_CLEANUP"); }
        catch {}
      }
      try { await workspace.closeCooperativeSourceLease(cooperativeLease); }
      catch {}
    }
    cleanupReportedScratchRoots(released?.retainedPrivateRoots ?? captured?.retainedPrivateRoots ?? []);
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
    if (armGuardCache !== null) removeFixturePath(armGuardCache);
  }
});

test("capture refuses malformed, foreign, and live legacy root-local recovery state", () => {
  const cases: Array<{
    name: string;
    mutate: (record: Record<string, unknown>, stateDirectory: string) => void;
  }> = [
    {
      name: "hybrid tombstone",
      mutate(record) { record.pid = 42; },
    },
    {
      name: "foreign tombstone",
      mutate(record) { record.rootIdentity = "noa-directory/2:0:0"; },
    },
    {
      name: "live recovery material",
      mutate(_record, stateDirectory) {
        const runDirectory = path.join(stateDirectory, "runs", "retained-run");
        fs.mkdirSync(runDirectory, { recursive: true });
        fs.writeFileSync(path.join(runDirectory, "inflight.json"), "{}", { mode: 0o600 });
      },
    },
  ];
  for (const fixtureCase of cases) {
    const fixture = minimalCaptureFixture(`root-local-refuse-${fixtureCase.name.replaceAll(" ", "-")}`);
    let refusal: WorkspaceError | null = null;
    try {
      fs.writeFileSync(path.join(fixture.source, ".gitignore"), "node_modules/\n", { mode: 0o600 });
      git(fixture.source, ["add", ".gitignore"]);
      git(fixture.source, ["commit", "-q", "-m", "ignore installed runtime state"]);
      const stateDirectory = path.join(fixture.source, "node_modules", ".cache", "noa-knockout");
      fs.mkdirSync(stateDirectory, { recursive: true });
      const rootStat = fs.lstatSync(fixture.source, { bigint: true });
      const record: Record<string, unknown> = {
        protocol: "noa-knockout-legacy-tombstone/1",
        root: fs.realpathSync(fixture.source),
        rootIdentity: `noa-directory/2:${rootStat.dev}:${rootStat.ino}`,
        migratedAt: "2026-09-03T00:00:00.000Z",
      };
      fixtureCase.mutate(record, stateDirectory);
      fs.writeFileSync(path.join(stateDirectory, "lock.json"), JSON.stringify(record), { mode: 0o600 });
      fs.chmodSync(path.join(stateDirectory, "lock.json"), 0o600);
      assert.throws(
        () => workspace.captureAndSealCandidate({
          custodyRoot: fixture.custody,
          maxAttempts: 1,
          sourceRoot: fixture.source,
        }),
        (error: WorkspaceError) => {
          refusal = error;
          return error.code === workspaceErrorCode("ROOT_LOCAL_STATE_UNSUPPORTED");
        },
        fixtureCase.name,
      );
      assert.equal(
        fs.readdirSync(fixture.custody).some((name) => name.startsWith("seed-attempt-")),
        false,
        `${fixtureCase.name} reached portable seed creation`,
      );
    } finally {
      cleanupReportedScratchRoots(errorPrivateRoots(refusal));
      removeFixturePath(fixture.source);
      removeFixturePath(fixture.custody);
    }
  }
});

test("capture detects a projected tombstone change inside the sealed source interval", () => {
  const fixture = minimalCaptureFixture("root-local-drift");
  const stateDirectory = path.join(fixture.source, "node_modules", ".cache", "noa-knockout");
  const tombstonePath = path.join(stateDirectory, "lock.json");
  let refusal: WorkspaceError | null = null;
  let mutated = false;
  try {
    fs.writeFileSync(path.join(fixture.source, ".gitignore"), "node_modules/\n", { mode: 0o600 });
    git(fixture.source, ["add", ".gitignore"]);
    git(fixture.source, ["commit", "-q", "-m", "ignore installed runtime state"]);
    fs.mkdirSync(stateDirectory, { recursive: true });
    const rootStat = fs.lstatSync(fixture.source, { bigint: true });
    fs.writeFileSync(tombstonePath, JSON.stringify({
      protocol: "noa-knockout-legacy-tombstone/1",
      root: fs.realpathSync(fixture.source),
      rootIdentity: `noa-directory/2:${rootStat.dev}:${rootStat.ino}`,
      migratedAt: "2026-09-03T00:00:00.000Z",
    }), { mode: 0o600 });
    fs.chmodSync(tombstonePath, 0o600);
    assert.throws(
      () => workspace.captureAndSealCandidate({
        custodyRoot: fixture.custody,
        hooks: {
          afterPreObservation() {
            fs.appendFileSync(tombstonePath, " ");
            mutated = true;
          },
        },
        maxAttempts: 1,
        sourceRoot: fixture.source,
      }),
      (error: WorkspaceError) => {
        refusal = error;
        return error.code === workspaceErrorCode("SNAPSHOT_UNSTABLE");
      },
    );
    assert.equal(mutated, true, "the tombstone-drift window was not exercised");
  } finally {
    cleanupReportedScratchRoots(errorPrivateRoots(refusal));
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
  }
});

test("Phase 2 custody admits two bounded batches and materializes fresh noninterfering arms", async () => {
  const fixture = minimalCaptureFixture("phase2-two-batch");
  let captured: Capture | null = null;
  let released: {
    retainedPrivateRoots: RetainedPrivateRoot[];
    seedObservationSha256: string;
    sourceSnapshotSha256: string;
    status: string;
  } | null = null;
  let cooperativeLease: CooperativeSourceLease | null = null;
  try {
    captured = workspace.captureAndSealCandidate({
      custodyRoot: fixture.custody,
      maxAttempts: 1,
      sourceRoot: fixture.source,
    });
    assert.throws(
      () => workspace.openKnockoutCustody(Object.freeze({ ...captured! }) as Capture, {
        maxRetainedArms: 5,
        maxRetainedBytes: 128 * 1024 * 1024,
      }),
      (error: WorkspaceError) => error.code === workspaceErrorCode("CAPABILITY_INVALID"),
    );
    assert.throws(
      () => workspace.openKnockoutCustody(captured!, {
        maxRetainedArms: workspace.KNOCKOUT_WORKSPACE_ARM_LIMITS.maxRetainedArms + 1,
        maxRetainedBytes: 128 * 1024 * 1024,
      }),
      (error: WorkspaceError) => error.code === workspaceErrorCode("INVALID_ARGUMENT"),
    );
    const custody = workspace.openKnockoutCustody(captured, {
      maxRetainedArms: 5,
      maxRetainedBytes: 128 * 1024 * 1024,
    });
    assert.equal(custody.kind, "KNOCKOUT_CUSTODY");
    assert.match(custody.retentionAccountingScope, /^DETERMINISTIC_INITIAL_ARM_MATERIALIZATION_/);
    assert.throws(
      () => workspace.openKnockoutCustody(captured!, {
        maxRetainedArms: 5,
        maxRetainedBytes: 128 * 1024 * 1024,
      }),
      (error: WorkspaceError) => error.code === workspaceErrorCode("CAPABILITY_INVALID"),
    );
    assert.throws(
      () => workspace.acquireSourceLease(Object.freeze({ ...custody }) as KnockoutCustody),
      (error: WorkspaceError) => error.code === workspaceErrorCode("CAPABILITY_INVALID"),
    );
    const lease = workspace.acquireSourceLease(custody);
    cooperativeLease = await workspace.acquireCooperativeSourceLease(lease);
    assert.equal(lease.sourceRootIdentity, captured.sourceRootIdentity);
    assert.equal(lease.exclusivityScope, "THIS_ESM_MODULE_INSTANCE_ONLY");
    assert.throws(
      () => workspace.admitArmPlan(
        Object.freeze({ ...cooperativeLease! }) as CooperativeSourceLease,
        {
        arms: [{ armId: "forged", role: "SELFTEST", subjectSha256: "0".repeat(64) }],
        },
      ),
      (error: WorkspaceError) => error.code === workspaceErrorCode("CAPABILITY_INVALID"),
    );
    const entriesBeforeAdmission = fs.readdirSync(fixture.custody).sort();

    let getterCalls = 0;
    const accessorOptions = Object.defineProperty({}, "arms", {
      enumerable: true,
      get() {
        getterCalls += 1;
        return [];
      },
    });
    assert.throws(
      () => workspace.admitArmPlan(
        cooperativeLease!,
        accessorOptions as { arms: Array<{ armId: string; role: string; subjectSha256: string }> },
      ),
      (error: WorkspaceError) => error.code === workspaceErrorCode("INVALID_ARGUMENT"),
    );
    assert.equal(getterCalls, 0, "arm-plan accessor was invoked");
    let nestedGetterCalls = 0;
    const accessorEntry = Object.defineProperties({}, {
      armId: { enumerable: true, value: "accessor-entry" },
      role: {
        enumerable: true,
        get() {
          nestedGetterCalls += 1;
          return "SELFTEST";
        },
      },
      subjectSha256: { enumerable: true, value: "0".repeat(64) },
    });
    assert.throws(
      () => workspace.admitArmPlan(cooperativeLease!, {
        arms: [accessorEntry as { armId: string; role: string; subjectSha256: string }],
      }),
      (error: WorkspaceError) => error.code === workspaceErrorCode("INVALID_ARGUMENT"),
    );
    assert.equal(nestedGetterCalls, 0, "nested arm-plan accessor was invoked");
    let proxyReads = 0;
    const proxyEntry = new Proxy({
      armId: "proxy-entry",
      role: "SELFTEST",
      subjectSha256: "0".repeat(64),
    }, {
      get(target, property, receiver) {
        proxyReads += 1;
        return Reflect.get(target, property, receiver);
      },
    });
    assert.throws(
      () => workspace.admitArmPlan(cooperativeLease!, { arms: [proxyEntry] }),
      (error: WorkspaceError) => error.code === workspaceErrorCode("INVALID_ARGUMENT"),
    );
    assert.equal(proxyReads, 0, "arm-plan Proxy was read");
    const sparseArms = new Array(1) as Array<{
      armId: string; role: string; subjectSha256: string;
    }>;
    assert.throws(
      () => workspace.admitArmPlan(cooperativeLease!, { arms: sparseArms }),
      (error: WorkspaceError) => error.code === workspaceErrorCode("INVALID_ARGUMENT"),
    );
    const namedArms = [
      { armId: "named-array", role: "SELFTEST", subjectSha256: "0".repeat(64) },
    ];
    Object.defineProperty(namedArms, "authority", { enumerable: true, value: true });
    assert.throws(
      () => workspace.admitArmPlan(cooperativeLease!, { arms: namedArms }),
      (error: WorkspaceError) => error.code === workspaceErrorCode("INVALID_ARGUMENT"),
    );
    assert.throws(
      () => workspace.admitArmPlan(cooperativeLease!, {
        arms: [{
          armId: "unknown-field",
          role: "SELFTEST",
          subjectSha256: "1".repeat(64),
          unexpected: true,
        } as unknown as { armId: string; role: string; subjectSha256: string }],
      }),
      (error: WorkspaceError) => error.code === workspaceErrorCode("INVALID_ARGUMENT"),
    );
    for (const malformed of [
      { armId: "../escape", role: "SELFTEST", subjectSha256: "0".repeat(64) },
      { armId: "bad-role", role: "EXECUTE", subjectSha256: "0".repeat(64) },
      { armId: "bad-hash", role: "SELFTEST", subjectSha256: "A".repeat(64) },
    ]) {
      assert.throws(
        () => workspace.admitArmPlan(cooperativeLease!, { arms: [malformed] }),
        (error: WorkspaceError) => error.code === workspaceErrorCode("INVALID_ARGUMENT"),
      );
    }
    const symbolEntry = {
      armId: "symbol-entry",
      role: "SELFTEST",
      subjectSha256: "0".repeat(64),
      [Symbol("authority")]: true,
    };
    assert.throws(
      () => workspace.admitArmPlan(cooperativeLease!, { arms: [symbolEntry] }),
      (error: WorkspaceError) => error.code === workspaceErrorCode("INVALID_ARGUMENT"),
    );
    assert.deepEqual(
      fs.readdirSync(fixture.custody).sort(),
      entriesBeforeAdmission,
      "refused arm plans created filesystem state",
    );

    const first = workspace.admitArmPlan(cooperativeLease, {
      arms: [
        { armId: "selftest-1", role: "SELFTEST", subjectSha256: "1".repeat(64) },
        { armId: "planning-1", role: "PLANNING", subjectSha256: "2".repeat(64) },
      ],
    });
    assert.throws(
      () => workspace.admitArmPlan(cooperativeLease!, {
        arms: [{ armId: "selftest-1", role: "SELFTEST", subjectSha256: "a".repeat(64) }],
      }),
      (error: WorkspaceError) => error.code === workspaceErrorCode("CAPABILITY_INVALID"),
    );
    const second = workspace.admitArmPlan(cooperativeLease, {
      arms: [
        { armId: "baseline-1", role: "BASELINE", subjectSha256: "3".repeat(64) },
        { armId: "mutant-1", role: "MUTANT", subjectSha256: "4".repeat(64) },
        { armId: "postcheck-1", role: "POSTCHECK", subjectSha256: "5".repeat(64) },
      ],
    });
    assert.equal(first.batch, 1);
    assert.equal(first.predecessorPlanSha256, null);
    assert.equal(second.batch, 2);
    assert.equal(second.predecessorPlanSha256, first.armPlanSha256);
    assert.match(first.armPlanSha256, /^[0-9a-f]{64}$/);
    assert.equal(second.sourceLeaseSha256, lease.sourceLeaseSha256);
    assert.deepEqual(
      fs.readdirSync(fixture.custody).sort(),
      entriesBeforeAdmission,
      "successful admission created an arm before materialization",
    );
    assert.throws(
      () => workspace.admitArmPlan(cooperativeLease!, {
        arms: [{ armId: "overflow-1", role: "MUTANT", subjectSha256: "6".repeat(64) }],
      }),
      (error: WorkspaceError) => error.code === workspaceErrorCode("RESOURCE_LIMIT_EXCEEDED"),
    );
    assert.deepEqual(
      fs.readdirSync(fixture.custody).sort(),
      entriesBeforeAdmission,
      "over-cap admission created an arm directory",
    );
    assert.throws(
      () => workspace.materializeArm(Object.freeze({ ...first }) as ArmPlan, "selftest-1"),
      (error: WorkspaceError) => error.code === workspaceErrorCode("CAPABILITY_INVALID"),
    );
    assert.throws(
      () => workspace.materializeArm(first, "baseline-1"),
      (error: WorkspaceError) => error.code === workspaceErrorCode("CAPABILITY_INVALID"),
    );

    const selftest = workspace.materializeArm(first, "selftest-1");
    const baseline = workspace.materializeArm(second, "baseline-1");
    assert.equal(path.basename(selftest.armRoot).startsWith("arm-"), true);
    assert.equal(selftest.armRoot.includes(selftest.armId), false, "logical armId entered a pathname");
    assert.notEqual(selftest.armRoot, baseline.armRoot);
    assert.notEqual(selftest.workspaceRoot, baseline.workspaceRoot);
    assert.equal(fs.realpathSync(selftest.workspaceRoot).startsWith(fs.realpathSync(fixture.custody)), true);
    assert.equal(selftest.seedObservationSha256, captured.workspaceObservation.observationSha256);
    assert.equal(selftest.sourceSnapshotSha256, captured.sourceSnapshot.snapshotSha256);
    assert.equal(
      fs.readFileSync(path.join(selftest.workspaceRoot, "tracked.txt"), "utf8"),
      "stable source bytes\n",
    );
    assert.equal(
      fs.readFileSync(path.join(baseline.workspaceRoot, "tracked.txt"), "utf8"),
      "stable source bytes\n",
    );
    fs.writeFileSync(path.join(selftest.workspaceRoot, "tracked.txt"), "mutated arm only\n");
    assert.equal(
      fs.readFileSync(path.join(baseline.workspaceRoot, "tracked.txt"), "utf8"),
      "stable source bytes\n",
      "one arm modified its sibling",
    );
    assert.equal(fs.readFileSync(fixture.trackedPath, "utf8"), "stable source bytes\n");
    assert.equal(
      fs.readFileSync(path.join(captured.workspaceRoot, "tracked.txt"), "utf8"),
      "stable source bytes\n",
      "one arm modified the sealed seed",
    );
    assert.throws(
      () => workspace.materializeArm(first, "selftest-1"),
      (error: WorkspaceError) => error.code === workspaceErrorCode("CAPABILITY_INVALID"),
    );
    await assert.rejects(
      () => workspace.closeCooperativeSourceLease(cooperativeLease!),
      (error: WorkspaceError) => {
        assert.deepEqual(error.details?.outstandingArmIds, [
          "baseline-1", "mutant-1", "planning-1", "postcheck-1", "selftest-1",
        ]);
        return error.code === workspaceErrorCode("CAPABILITY_INVALID");
      },
    );
    assert.equal(workspace.cancelMaterializedArm(cooperativeLease, selftest, "TEST_COMPLETE").status, "CANCELLED");
    assert.equal(workspace.cancelMaterializedArm(cooperativeLease, baseline, "TEST_COMPLETE").status, "CANCELLED");
    assert.equal(workspace.cancelAdmittedArm(first, "planning-1", "TEST_COMPLETE").status, "CANCELLED");
    assert.equal(workspace.cancelAdmittedArm(second, "mutant-1", "TEST_COMPLETE").status, "CANCELLED");
    assert.equal(workspace.cancelAdmittedArm(second, "postcheck-1", "TEST_COMPLETE").status, "CANCELLED");
    assert.throws(
      () => workspace.cancelMaterializedArm(cooperativeLease!, selftest, "SECOND_CANCEL"),
      (error: WorkspaceError) => error.code === workspaceErrorCode("CAPABILITY_INVALID"),
    );
    assert.throws(
      () => workspace.cancelAdmittedArm(first, "planning-1", "SECOND_CANCEL"),
      (error: WorkspaceError) => error.code === workspaceErrorCode("CAPABILITY_INVALID"),
    );
    const cooperativeRelease = await workspace.closeCooperativeSourceLease(cooperativeLease);
    cooperativeLease = null;
    released = cooperativeRelease.sourceRelease;
    assert.equal(released.status, "RELEASED");
    assert.equal(released.sourceSnapshotSha256, captured.sourceSnapshot.snapshotSha256);
    assert.equal(released.seedObservationSha256, captured.workspaceObservation.observationSha256);
    assert.throws(
      () => workspace.materializeArm(second, "mutant-1"),
      (error: WorkspaceError) => error.code === workspaceErrorCode("CAPABILITY_INVALID"),
    );
    assert.throws(
      () => workspace.admitArmPlan(
        Object.freeze({ kind: "released" }) as unknown as CooperativeSourceLease,
        {
        arms: [{ armId: "late-1", role: "MUTANT", subjectSha256: "7".repeat(64) }],
        },
      ),
      (error: WorkspaceError) => error.code === workspaceErrorCode("CAPABILITY_INVALID"),
    );
    assert.throws(
      () => workspace.releaseSourceLease(lease),
      (error: WorkspaceError) => error.code === workspaceErrorCode("CAPABILITY_INVALID"),
    );
  } finally {
    if (cooperativeLease !== null) {
      try { await workspace.closeCooperativeSourceLease(cooperativeLease); }
      catch {}
    }
    cleanupReportedScratchRoots(released?.retainedPrivateRoots ?? captured?.retainedPrivateRoots ?? []);
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
  }
});

test("Phase 2 release detects source drift, invalidates authority, and never restores source", async () => {
  const fixture = minimalCaptureFixture("phase2-source-drift");
  let captured: Capture | null = null;
  let refusal: WorkspaceError | null = null;
  try {
    captured = workspace.captureAndSealCandidate({
      custodyRoot: fixture.custody,
      maxAttempts: 1,
      sourceRoot: fixture.source,
    });
    const custody = workspace.openKnockoutCustody(captured, {
      maxRetainedArms: 1,
      maxRetainedBytes: 32 * 1024 * 1024,
    });
    const lease = workspace.acquireSourceLease(custody);
    const cooperativeLease = await workspace.acquireCooperativeSourceLease(lease);
    fs.writeFileSync(fixture.trackedPath, "owner change remains\n", { mode: 0o600 });
    await assert.rejects(
      () => workspace.closeCooperativeSourceLease(cooperativeLease),
      (error: WorkspaceError) => {
        refusal = error;
        return error.code === workspaceErrorCode("SOURCE_CHANGED");
      },
    );
    assert.equal(fs.readFileSync(fixture.trackedPath, "utf8"), "owner change remains\n");
    assert.throws(
      () => workspace.admitArmPlan(cooperativeLease, {
        arms: [{ armId: "late", role: "SELFTEST", subjectSha256: "8".repeat(64) }],
      }),
      (error: WorkspaceError) => error.code === workspaceErrorCode("CAPABILITY_INVALID"),
    );
    assert.throws(
      () => workspace.releaseSourceLease(lease),
      (error: WorkspaceError) => error.code === workspaceErrorCode("CAPABILITY_INVALID"),
    );
  } finally {
    cleanupReportedScratchRoots(errorPrivateRoots(refusal));
    cleanupReportedScratchRoots(captured?.retainedPrivateRoots ?? []);
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
  }
});

test("Phase 2 seed drift burns the admitted arm and fails closed before creating it", async () => {
  const fixture = minimalCaptureFixture("phase2-seed-drift");
  let captured: Capture | null = null;
  let materializationRefusal: WorkspaceError | null = null;
  let releaseRefusal: WorkspaceError | null = null;
  try {
    captured = workspace.captureAndSealCandidate({
      custodyRoot: fixture.custody,
      maxAttempts: 1,
      sourceRoot: fixture.source,
    });
    const custody = workspace.openKnockoutCustody(captured, {
      maxRetainedArms: 1,
      maxRetainedBytes: 32 * 1024 * 1024,
    });
    const lease = workspace.acquireSourceLease(custody);
    const cooperativeLease = await workspace.acquireCooperativeSourceLease(lease);
    const plan = workspace.admitArmPlan(cooperativeLease, {
      arms: [{ armId: "drifted", role: "SELFTEST", subjectSha256: "9".repeat(64) }],
    });
    const entriesBefore = fs.readdirSync(fixture.custody).sort();
    fs.writeFileSync(path.join(captured.workspaceRoot, "tracked.txt"), "hostile seed bytes\n");
    assert.throws(
      () => workspace.materializeArm(plan, "drifted"),
      (error: WorkspaceError) => {
        materializationRefusal = error;
        return error.code === workspaceErrorCode("ARM_IDENTITY_MISMATCH");
      },
    );
    assert.deepEqual(
      fs.readdirSync(fixture.custody).sort(),
      entriesBefore,
      "seed preflight failure created a run or arm root",
    );
    assert.throws(
      () => workspace.materializeArm(plan, "drifted"),
      (error: WorkspaceError) => error.code === workspaceErrorCode("CAPABILITY_INVALID"),
    );
    await assert.rejects(
      () => workspace.closeCooperativeSourceLease(cooperativeLease),
      (error: WorkspaceError) => {
        releaseRefusal = error;
        return error.code === workspaceErrorCode("ARM_IDENTITY_MISMATCH") ||
          error.code === workspaceErrorCode("MANIFEST_MISMATCH");
      },
    );
    assert.throws(
      () => workspace.releaseSourceLease(lease),
      (error: WorkspaceError) => error.code === workspaceErrorCode("CAPABILITY_INVALID"),
    );
  } finally {
    cleanupReportedScratchRoots(errorPrivateRoots(materializationRefusal));
    cleanupReportedScratchRoots(errorPrivateRoots(releaseRefusal));
    cleanupReportedScratchRoots(captured?.retainedPrivateRoots ?? []);
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
  }
});

test("Phase 2 partial copy failure retains exact custody evidence and forbids arm retry", async () => {
  const fixture = minimalCaptureFixture("phase2-partial-copy");
  const openDescriptor = Object.getOwnPropertyDescriptor(fs, "openSync");
  const writeDescriptor = Object.getOwnPropertyDescriptor(fs, "writeSync");
  assert.ok(openDescriptor !== undefined);
  assert.ok(writeDescriptor !== undefined);
  const originalOpen = fs.openSync;
  const originalWrite = fs.writeSync;
  let captured: Capture | null = null;
  let refusal: WorkspaceError | null = null;
  let released: SourceRelease | null = null;
  let destinationFd: number | null = null;
  let injected = false;
  try {
    captured = workspace.captureAndSealCandidate({
      custodyRoot: fixture.custody,
      maxAttempts: 1,
      sourceRoot: fixture.source,
    });
    const custody = workspace.openKnockoutCustody(captured, {
      maxRetainedArms: 1,
      maxRetainedBytes: 32 * 1024 * 1024,
    });
    const lease = workspace.acquireSourceLease(custody);
    const cooperativeLease = await workspace.acquireCooperativeSourceLease(lease);
    const plan = workspace.admitArmPlan(cooperativeLease, {
      arms: [{ armId: "copy-failure", role: "SELFTEST", subjectSha256: "a".repeat(64) }],
    });
    Object.defineProperty(fs, "openSync", {
      ...openDescriptor,
      value: ((...args: Parameters<typeof fs.openSync>) => {
        const fd = Reflect.apply(originalOpen, fs, args) as number;
        const requested = args[0];
        const flags = typeof args[1] === "number" ? args[1] : 0;
        if (
          typeof requested === "string" && requested.endsWith(`${path.sep}workspace${path.sep}tracked.txt`) &&
          requested !== path.join(captured!.workspaceRoot, "tracked.txt") &&
          (flags & fs.constants.O_WRONLY) !== 0
        ) destinationFd = fd;
        return fd;
      }) as typeof fs.openSync,
    });
    Object.defineProperty(fs, "writeSync", {
      ...writeDescriptor,
      value: ((...args: Parameters<typeof fs.writeSync>) => {
        if (!injected && destinationFd !== null && args[0] === destinationFd) {
          injected = true;
          throw Object.assign(new Error("injected arm-copy write failure"), { code: "EIO" });
        }
        return Reflect.apply(originalWrite, fs, args);
      }) as typeof fs.writeSync,
    });
    assert.throws(
      () => workspace.materializeArm(plan, "copy-failure"),
      (error: WorkspaceError) => {
        refusal = error;
        return error.code === workspaceErrorCode("COPY_INCOMPLETE");
      },
    );
    assert.equal(injected, true, "arm-copy failure injection was not reached");
    const armRoots = errorPrivateRoots(refusal).filter((root) =>
      path.basename(root.path).startsWith("arm-"));
    assert.equal(armRoots.length, 1, errorChain(refusal));
    const retainedArm = armRoots[0];
    assert.notEqual(retainedArm, undefined);
    const retainedStat = fs.lstatSync(retainedArm!.path, { bigint: true });
    assert.equal(`${retainedStat.dev}:${retainedStat.ino}`, retainedArm!.identity);
    assert.throws(
      () => workspace.materializeArm(plan, "copy-failure"),
      (error: WorkspaceError) => error.code === workspaceErrorCode("CAPABILITY_INVALID"),
    );
    Object.defineProperty(fs, "openSync", openDescriptor);
    Object.defineProperty(fs, "writeSync", writeDescriptor);
    released = (await workspace.closeCooperativeSourceLease(cooperativeLease)).sourceRelease;
  } finally {
    Object.defineProperty(fs, "openSync", openDescriptor);
    Object.defineProperty(fs, "writeSync", writeDescriptor);
    cleanupReportedScratchRoots(released?.retainedPrivateRoots ?? errorPrivateRoots(refusal));
    cleanupReportedScratchRoots(captured?.retainedPrivateRoots ?? []);
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
  }
});

test("Phase 2 permits only one active module-instance lease for one physical source", () => {
  const fixture = minimalCaptureFixture("phase2-exclusive-lease");
  const secondCustodyRoot = privateTemp("noa-kws-phase2-exclusive-lease-custody-2-");
  let firstCapture: Capture | null = null;
  let secondCapture: Capture | null = null;
  let firstRelease: { retainedPrivateRoots: RetainedPrivateRoot[] } | null = null;
  let secondRelease: { retainedPrivateRoots: RetainedPrivateRoot[] } | null = null;
  try {
    firstCapture = workspace.captureAndSealCandidate({
      custodyRoot: fixture.custody,
      maxAttempts: 1,
      sourceRoot: fixture.source,
    });
    secondCapture = workspace.captureAndSealCandidate({
      custodyRoot: secondCustodyRoot,
      maxAttempts: 1,
      sourceRoot: fixture.source,
    });
    const firstCustody = workspace.openKnockoutCustody(firstCapture, {
      maxRetainedArms: 1,
      maxRetainedBytes: 32 * 1024 * 1024,
    });
    const secondCustody = workspace.openKnockoutCustody(secondCapture, {
      maxRetainedArms: 1,
      maxRetainedBytes: 32 * 1024 * 1024,
    });
    const firstLease = workspace.acquireSourceLease(firstCustody);
    assert.throws(
      () => workspace.acquireSourceLease(secondCustody),
      (error: WorkspaceError) => error.code === workspaceErrorCode("CAPABILITY_INVALID"),
    );
    firstRelease = workspace.releaseSourceLease(firstLease);
    const secondLease = workspace.acquireSourceLease(secondCustody);
    secondRelease = workspace.releaseSourceLease(secondLease);
  } finally {
    cleanupReportedScratchRoots(firstRelease?.retainedPrivateRoots ?? firstCapture?.retainedPrivateRoots ?? []);
    cleanupReportedScratchRoots(secondRelease?.retainedPrivateRoots ?? secondCapture?.retainedPrivateRoots ?? []);
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
    removeFixturePath(secondCustodyRoot);
  }
});

test("Phase 2 byte admission refuses before creating run or arm directories", async () => {
  const fixture = minimalCaptureFixture("phase2-byte-admission");
  let captured: Capture | null = null;
  let released: { retainedPrivateRoots: RetainedPrivateRoot[] } | null = null;
  try {
    captured = workspace.captureAndSealCandidate({
      custodyRoot: fixture.custody,
      maxAttempts: 1,
      sourceRoot: fixture.source,
    });
    const custody = workspace.openKnockoutCustody(captured, {
      maxRetainedArms: 1,
      maxRetainedBytes: 1,
    });
    const lease = workspace.acquireSourceLease(custody);
    const cooperativeLease = await workspace.acquireCooperativeSourceLease(lease);
    const entriesBefore = fs.readdirSync(fixture.custody).sort();
    assert.throws(
      () => workspace.admitArmPlan(cooperativeLease, {
        arms: [{ armId: "too-large", role: "SELFTEST", subjectSha256: "b".repeat(64) }],
      }),
      (error: WorkspaceError) => error.code === workspaceErrorCode("RESOURCE_LIMIT_EXCEEDED"),
    );
    assert.deepEqual(fs.readdirSync(fixture.custody).sort(), entriesBefore);
    released = (await workspace.closeCooperativeSourceLease(cooperativeLease)).sourceRelease;
  } finally {
    cleanupReportedScratchRoots(released?.retainedPrivateRoots ?? captured?.retainedPrivateRoots ?? []);
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
  }
});

test("Phase 2 run-root substitution burns the next arm and is never restored or deleted", async () => {
  const fixture = minimalCaptureFixture("phase2-run-substitution");
  let captured: Capture | null = null;
  let materializationRefusal: WorkspaceError | null = null;
  let releaseRefusal: WorkspaceError | null = null;
  try {
    captured = workspace.captureAndSealCandidate({
      custodyRoot: fixture.custody,
      maxAttempts: 1,
      sourceRoot: fixture.source,
    });
    const custody = workspace.openKnockoutCustody(captured, {
      maxRetainedArms: 2,
      maxRetainedBytes: 64 * 1024 * 1024,
    });
    const lease = workspace.acquireSourceLease(custody);
    const cooperativeLease = await workspace.acquireCooperativeSourceLease(lease);
    const plan = workspace.admitArmPlan(cooperativeLease, {
      arms: [
        { armId: "first", role: "SELFTEST", subjectSha256: "c".repeat(64) },
        { armId: "second", role: "PLANNING", subjectSha256: "d".repeat(64) },
      ],
    });
    const first = workspace.materializeArm(plan, "first");
    assert.equal(
      workspace.cancelMaterializedArm(cooperativeLease, first, "TEST_COMPLETE").status,
      "CANCELLED",
    );
    const runRoot = path.dirname(first.armRoot);
    const runEvidence = first.retainedPrivateRoots.find((root) => root.path === runRoot);
    assert.notEqual(runEvidence, undefined);
    const retainedRunPath = `${runRoot}-attacker-retained`;
    fs.renameSync(runRoot, retainedRunPath);
    fs.mkdirSync(runRoot, { mode: 0o700 });
    assert.throws(
      () => workspace.materializeArm(plan, "second"),
      (error: WorkspaceError) => {
        materializationRefusal = error;
        return error.code === workspaceErrorCode("ARM_IDENTITY_MISMATCH");
      },
    );
    const originalRunStat = fs.lstatSync(retainedRunPath, { bigint: true });
    assert.equal(`${originalRunStat.dev}:${originalRunStat.ino}`, runEvidence!.identity);
    const replacementStat = fs.lstatSync(runRoot, { bigint: true });
    assert.notEqual(`${replacementStat.dev}:${replacementStat.ino}`, runEvidence!.identity);
    assert.throws(
      () => workspace.materializeArm(plan, "second"),
      (error: WorkspaceError) => error.code === workspaceErrorCode("CAPABILITY_INVALID"),
    );
    await assert.rejects(
      () => workspace.closeCooperativeSourceLease(cooperativeLease),
      (error: WorkspaceError) => {
        releaseRefusal = error;
        return error.code === workspaceErrorCode("ARM_IDENTITY_MISMATCH");
      },
    );
    assert.equal(fs.existsSync(retainedRunPath), true, "release deleted the displaced original run root");
    assert.equal(fs.existsSync(runRoot), true, "release deleted the attacker replacement");
  } finally {
    cleanupReportedScratchRoots(errorPrivateRoots(materializationRefusal));
    cleanupReportedScratchRoots(errorPrivateRoots(releaseRefusal));
    cleanupReportedScratchRoots(captured?.retainedPrivateRoots ?? []);
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
  }
});

test("Phase 2 revalidates candidate evidence before materializing an admitted arm", async () => {
  const fixture = minimalCaptureFixture("phase2-evidence-drift");
  let captured: Capture | null = null;
  let materializationRefusal: WorkspaceError | null = null;
  let releaseRefusal: WorkspaceError | null = null;
  try {
    captured = workspace.captureAndSealCandidate({
      custodyRoot: fixture.custody,
      maxAttempts: 1,
      sourceRoot: fixture.source,
    });
    const custody = workspace.openKnockoutCustody(captured, {
      maxRetainedArms: 1,
      maxRetainedBytes: 32 * 1024 * 1024,
    });
    const lease = workspace.acquireSourceLease(custody);
    const cooperativeLease = await workspace.acquireCooperativeSourceLease(lease);
    const plan = workspace.admitArmPlan(cooperativeLease, {
      arms: [{ armId: "evidence-drift", role: "SELFTEST", subjectSha256: "e".repeat(64) }],
    });
    const entriesBefore = fs.readdirSync(fixture.custody).sort();
    fs.appendFileSync(captured.statePath, "\n");
    assert.throws(
      () => workspace.materializeArm(plan, "evidence-drift"),
      (error: WorkspaceError) => {
        materializationRefusal = error;
        return error.code === workspaceErrorCode("MANIFEST_MISMATCH");
      },
    );
    assert.deepEqual(fs.readdirSync(fixture.custody).sort(), entriesBefore);
    assert.throws(
      () => workspace.materializeArm(plan, "evidence-drift"),
      (error: WorkspaceError) => error.code === workspaceErrorCode("CAPABILITY_INVALID"),
    );
    await assert.rejects(
      () => workspace.closeCooperativeSourceLease(cooperativeLease),
      (error: WorkspaceError) => {
        releaseRefusal = error;
        return error.code === workspaceErrorCode("MANIFEST_MISMATCH");
      },
    );
  } finally {
    cleanupReportedScratchRoots(errorPrivateRoots(materializationRefusal));
    cleanupReportedScratchRoots(errorPrivateRoots(releaseRefusal));
    cleanupReportedScratchRoots(captured?.retainedPrivateRoots ?? []);
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
  }
});

test("Phase 2 burns a custody after a started lease acquisition fails", () => {
  const fixture = minimalCaptureFixture("phase2-acquire-failure");
  let captured: Capture | null = null;
  let refusal: WorkspaceError | null = null;
  try {
    captured = workspace.captureAndSealCandidate({
      custodyRoot: fixture.custody,
      maxAttempts: 1,
      sourceRoot: fixture.source,
    });
    const custody = workspace.openKnockoutCustody(captured, {
      maxRetainedArms: 1,
      maxRetainedBytes: 32 * 1024 * 1024,
    });
    fs.writeFileSync(fixture.trackedPath, "changed before lease\n", { mode: 0o600 });
    assert.throws(
      () => workspace.acquireSourceLease(custody),
      (error: WorkspaceError) => {
        refusal = error;
        return error.code === workspaceErrorCode("SOURCE_CHANGED");
      },
    );
    assert.equal(fs.readFileSync(fixture.trackedPath, "utf8"), "changed before lease\n");
    assert.throws(
      () => workspace.acquireSourceLease(custody),
      (error: WorkspaceError) => error.code === workspaceErrorCode("CAPABILITY_INVALID"),
    );
  } finally {
    cleanupReportedScratchRoots(errorPrivateRoots(refusal));
    cleanupReportedScratchRoots(captured?.retainedPrivateRoots ?? []);
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
  }
});

test("Phase 2 worker atomically reserves one PID-bound FD capability before cancellation and only the supervisor publishes terminal evidence", async () => {
  const fixture = minimalCaptureFixture("phase2-worker-terminal");
  let captured: Capture | null = null;
  let cooperativeLease: CooperativeSourceLease | null = null;
  let plan: ArmPlan | null = null;
  let arm: DisposableArm | null = null;
  let terminal = false;
  let released: { retainedPrivateRoots: RetainedPrivateRoot[] } | null = null;
  try {
    const workerSha256 = installArmWorkerFixture(fixture.source, "install bound arm worker");
    const subject = armWorkerSubject(workerSha256);
    const subjectSha256 = armWorkerSubjectSha256(subject);
    captured = workspace.captureAndSealCandidate({
      custodyRoot: fixture.custody,
      maxAttempts: 1,
      sourceRoot: fixture.source,
    });
    const sourceLease = workspace.acquireSourceLease(workspace.openKnockoutCustody(captured, {
      maxRetainedArms: 1,
      maxRetainedBytes: 64 * 1024 * 1024,
    }));
    cooperativeLease = await workspace.acquireCooperativeSourceLease(sourceLease);
    plan = workspace.admitArmPlan(cooperativeLease, {
      arms: [{ armId: "attest-1", role: "SELFTEST", subjectSha256 }],
    });
    arm = workspace.materializeArm(plan, "attest-1");
    assert.deepEqual(fs.readdirSync(arm.evidenceRoot), []);

    const running = workspace.runArmWorker(cooperativeLease, arm, {
      subject,
      timeoutMs: 30_000,
    });
    let concurrentCancellationStatus: string | null = null;
    let concurrentCancellationError: WorkspaceError | null = null;
    try {
      concurrentCancellationStatus = workspace.cancelMaterializedArm(
        cooperativeLease,
        arm,
        "RACING_CANCEL",
      ).status;
    } catch (error) {
      concurrentCancellationError = error as WorkspaceError;
    }
    const result = await running;
    terminal = true;
    assert.equal(concurrentCancellationStatus, null, "a racing cancellation consumed active worker authority");
    assert.equal(concurrentCancellationError?.code, workspaceErrorCode("CAPABILITY_INVALID"));
    assert.equal(
      result.status,
      "COMPLETE",
      JSON.stringify(result.terminalPublication.terminal),
    );
    assert.equal(result.originalProcessGroupAbsent, true);
    assert.equal(
      result.processContainmentScope,
      "ORIGINAL_POSIX_PROCESS_GROUP_ONLY_REGROUPING_ESCAPE_NOT_EXCLUDED",
    );
    assert.deepEqual(fs.readdirSync(arm.evidenceRoot).sort(), [
      "arm-terminal.json",
      "worker-result.bin",
    ]);
    assert.equal(result.terminalPublication.terminal.status, "COMPLETE");
    assert.equal(result.terminalPublication.terminal.reasonCode, "WORKER_COMPLETE");
    assert.equal(result.terminalPublication.terminal.predecessorTerminalSha256, null);
    assert.equal(
      (result.terminalPublication.terminal.workerResult as { accepted?: unknown }).accepted,
      true,
    );
    assert.equal(fs.lstatSync(result.terminalPublication.path).mode & 0o777, 0o600);
    await assert.rejects(
      () => workspace.runArmWorker(cooperativeLease!, arm!, { subject, timeoutMs: 30_000 }),
      (error: WorkspaceError) => error.code === workspaceErrorCode("CAPABILITY_INVALID"),
    );
    released = (await workspace.closeCooperativeSourceLease(cooperativeLease)).sourceRelease;
    cooperativeLease = null;
  } finally {
    if (cooperativeLease !== null) {
      if (!terminal && arm !== null) {
        try { workspace.cancelMaterializedArm(cooperativeLease, arm, "TEST_ABORT"); }
        catch {}
      } else if (plan !== null && arm === null) {
        try { workspace.cancelAdmittedArm(plan, "attest-1", "TEST_ABORT"); }
        catch {}
      }
      try { released = (await workspace.closeCooperativeSourceLease(cooperativeLease)).sourceRelease; }
      catch {}
    }
    cleanupReportedScratchRoots(released?.retainedPrivateRoots ?? captured?.retainedPrivateRoots ?? []);
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
  }
});

test("Phase 2 CLI registry accessor is import-safe and leaves the source and index unchanged", () => {
  const cliUrl = pathToFileURL(
    path.join(repositoryRoot, "scripts", "lint-control-knockout.mjs"),
  ).href;
  const statusBefore = git(repositoryRoot, ["status", "--porcelain=v1", "-z"]);
  const indexPath = git(repositoryRoot, ["rev-parse", "--git-path", "index"]).trim();
  const absoluteIndexPath = path.isAbsolute(indexPath)
    ? indexPath
    : path.join(repositoryRoot, indexPath);
  const indexBefore = sha256File(absoluteIndexPath);
  const imported = childProcess.spawnSync(
    process.execPath,
    [
      "--input-type=module",
      "-e",
      [
        `const module = await import(${JSON.stringify(cliUrl)});`,
        "const snapshot = module.knockoutRegistrySnapshot();",
        "process.stdout.write(JSON.stringify({ proofs: Object.keys(snapshot.proofInventory).length, registry: snapshot.registry.length }));",
      ].join("\n"),
    ],
    { cwd: repositoryRoot, encoding: "utf8", timeout: 30_000 },
  );
  assert.equal(imported.status, 0, imported.stderr);
  const summary = JSON.parse(imported.stdout) as { proofs: number; registry: number };
  assert.ok(summary.registry > 0);
  assert.ok(summary.proofs >= 0);
  assert.equal(sha256File(absoluteIndexPath), indexBefore);
  assert.equal(git(repositoryRoot, ["status", "--porcelain=v1", "-z"]), statusBefore);
});

test("Phase 2 worker operations have one closed execution-role mapping", () => {
  assert.deepEqual(
    Object.fromEntries([
      "OBSERVE_KNOCKOUT_BASELINE",
      "OBSERVE_KNOCKOUT_POSTCHECK",
      "RUN_KNOCKOUT",
      "RUN_KNOCKOUT_SELFTEST",
    ].map((name) => [name, workspace.knockoutWorkerOperationRole(
      workspace.KNOCKOUT_WORKER_OPERATIONS[name]!,
    )])),
    {
      OBSERVE_KNOCKOUT_BASELINE: "BASELINE",
      OBSERVE_KNOCKOUT_POSTCHECK: "POSTCHECK",
      RUN_KNOCKOUT: "MUTANT",
      RUN_KNOCKOUT_SELFTEST: "SELFTEST",
    },
  );
  assert.throws(
    () => workspace.knockoutWorkerOperationRole(workspace.KNOCKOUT_WORKER_OPERATIONS.ATTEST_ARM),
    (error: WorkspaceError) => error.code === "CAPABILITY_INVALID",
  );
  assert.throws(
    () => workspace.knockoutWorkerOperationRole("FUTURE_UNMAPPED_OPERATION"),
    (error: WorkspaceError) => error.code === "CAPABILITY_INVALID",
  );
});

test("Phase 2 invalid timeout or retention preflight creates no custody directory", async () => {
  const fixture = minimalCaptureFixture("phase2-runner-preflight");
  const custodyRoot = path.join(fixture.custody, "must-not-exist");
  const entry = {
    id: "isolated-preflight-control",
    control: "fixture preflight control",
    file: "control.mjs",
    find: "export const controlEnabled = true;",
    replace: "export const controlEnabled = false;",
    kind: "gate",
    gateId: "fixture-gate",
    expectedGateFindings: [{ rule: "CONTROL_DISABLED", subject: "control" }],
    suite: [".", "node", ["fixture-gate.mjs"]],
  };
  try {
    const suiteTimeoutLimitMs = workspace.KNOCKOUT_WORKSPACE_ARM_WORKER_TIMEOUT_LIMIT_MS -
      workspace.KNOCKOUT_WORKSPACE_COMMAND_TIMEOUT_LIMIT_MS;
    const invalidTimeoutOptions = [
      { timeoutMs: 0 },
      { timeoutMs: suiteTimeoutLimitMs + 1 },
      { captureTimeoutMs: 0 },
      { captureTimeoutMs: workspace.KNOCKOUT_WORKSPACE_CAPTURE_TIMEOUT_LIMIT_MS + 1 },
      { suiteTimeoutMs: 0 },
      { suiteTimeoutMs: suiteTimeoutLimitMs + 1 },
      { workerTimeoutMs: 0 },
      { workerTimeoutMs: workspace.KNOCKOUT_WORKSPACE_ARM_WORKER_TIMEOUT_LIMIT_MS + 1 },
      {
        suiteTimeoutMs: 60_000,
        workerTimeoutMs: 60_000 + workspace.KNOCKOUT_WORKSPACE_COMMAND_TIMEOUT_LIMIT_MS - 1,
      },
      { suiteTimeoutMs: 60_001, timeoutMs: 60_000 },
    ];
    for (const timeoutOptions of invalidTimeoutOptions) {
      await assert.rejects(
        () => knockoutRunner.runIsolatedKnockoutSweep({
          custodyRoot,
          maxRetainedArms: 3,
          maxRetainedBytes: 512 * 1024 * 1024,
          rawDependenciesByEntry: new Map([[entry.id, {}]]),
          registry: [entry],
          root: fixture.source,
          selected: [entry],
          ...timeoutOptions,
        }),
        (error: WorkspaceError) => error.code === "SWEEP_TIMEOUT_INVALID",
      );
      assert.equal(fs.existsSync(custodyRoot), false);
    }
    await assert.rejects(
      () => knockoutRunner.runIsolatedKnockoutSweep({
        custodyRoot,
        maxRetainedArms: 2,
        maxRetainedBytes: 512 * 1024 * 1024,
        rawDependenciesByEntry: new Map([[entry.id, {}]]),
        registry: [entry],
        root: fixture.source,
        selected: [entry],
        captureTimeoutMs: workspace.KNOCKOUT_WORKSPACE_CAPTURE_TIMEOUT_LIMIT_MS,
        suiteTimeoutMs: 60_000,
        timeoutMs: 60_000,
        workerTimeoutMs: workspace.KNOCKOUT_WORKSPACE_ARM_WORKER_TIMEOUT_LIMIT_MS,
      }),
      (error: WorkspaceError) => error.code === "RETENTION_BUDGET_INSUFFICIENT",
    );
    assert.equal(fs.existsSync(custodyRoot), false);
  } finally {
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
  }
});

test("Phase 2 bad fresh POSTCHECK can only downgrade setup-integrity credit", () => {
  const entry = {
    id: "isolated-postcheck-downgrade",
    expectedSetupIntegrity: {},
    gateId: "fixture-setup-gate",
  };
  const finalized = knockoutRunner.finalizeIsolatedSetupIntegrityPostcheck({
    baseline: { gateProvenance: null },
    entry,
    postcheck: {
      armTerminalSummary: null,
      exit: null,
      gate: entry.gateId,
      gateProtocol: null,
      gateProvenance: null,
      signal: null,
      timedOut: true,
    },
    postcheckState: {
      artifactsRemoved: [],
      artifactsRestored: [],
      exactCustodyAdditions: [],
      exactCustodyRestored: [],
      exactGitIndexObservationChanged: false,
      exactGitIndexSemanticChanged: false,
      freshArm: true,
      trackedReverted: [],
      untrackedAdditions: [],
    },
    result: {
      id: entry.id,
      verdict: "DETECTOR_TRIGGERED",
      workspaceDisposition: "RETAINED_DISPOSABLE_MUTANT",
    },
  });
  assert.equal(finalized.verdict, "INVALID_TEST");
  assert.equal(finalized.postRestoreBaselineVerified, false);
  assert.match(finalized.detail ?? "", /fresh postcheck failed/);
});

test("Phase 2 CLI has one isolated supervisor seam and no live-root execution fallback", () => {
  const cliPath = path.join(repositoryRoot, "scripts", "lint-control-knockout.mjs");
  const source = fs.readFileSync(cliPath, "utf8");
  const ast = ts.createSourceFile(cliPath, source, ts.ScriptTarget.ES2022, true, ts.ScriptKind.JS);
  assert.equal(
    (ast as ts.SourceFile & { parseDiagnostics: readonly ts.Diagnostic[] }).parseDiagnostics.length,
    0,
  );
  const directEntries = ast.statements.filter((statement): statement is ts.IfStatement =>
    ts.isIfStatement(statement) && ts.isIdentifier(statement.expression) &&
    statement.expression.text === "DIRECT_ENTRY");
  assert.ok(directEntries.length > 0, "CLI has no DIRECT_ENTRY guard");
  const calls = new Map<string, number>();
  const visit = (node: ts.Node | undefined) => {
    if (node === undefined) return;
    if (ts.isCallExpression(node)) {
      const name = ts.isIdentifier(node.expression)
        ? node.expression.text
        : ts.isPropertyAccessExpression(node.expression)
          ? node.expression.name.text
          : null;
      if (name !== null) calls.set(name, (calls.get(name) ?? 0) + 1);
    }
    ts.forEachChild(node, visit);
  };
  for (const directEntry of directEntries) visit(directEntry.thenStatement);
  assert.equal(calls.get("runIsolatedKnockoutSweep"), 1);
  for (const retired of [
    "bindObserverDependency", "buildStateGuardFor", "execFileSync", "observeSuite", "runKnockout",
  ]) {
    assert.equal(calls.get(retired) ?? 0, 0, `${retired} remains reachable from DIRECT_ENTRY`);
  }
  const manifest = JSON.parse(fs.readFileSync(path.join(repositoryRoot, "package.json"), "utf8"));
  assert.equal(manifest.scripts["lint:knockout"], "node scripts/lint-control-knockout.mjs");
});

test("Phase 2 CLI invalid selection and argument grammar stay hard and start no sweep", async () => {
  const { BOUNDARY_NODE_VERSION } = await import(
    pathToFileURL(path.join(repositoryRoot, "scripts/lib/boundary-bootstrap.mjs")).href
  ) as { BOUNDARY_NODE_VERSION: string };
  const statusBefore = git(repositoryRoot, ["status", "--porcelain=v1", "-z"]);
  const indexPath = git(repositoryRoot, ["rev-parse", "--git-path", "index"]).trim();
  const absoluteIndexPath = path.isAbsolute(indexPath)
    ? indexPath
    : path.join(repositoryRoot, indexPath);
  const indexBefore = sha256File(absoluteIndexPath);
  const environment: NodeJS.ProcessEnv = { ...process.env };
  const run = childProcess.spawnSync(
    process.execPath,
    ["scripts/lint-control-knockout.mjs", "--only", "__absent__", "--warn"],
    { cwd: repositoryRoot, encoding: "utf8", env: environment, timeout: 30_000 },
  );
  assert.equal(run.status, 1, run.stderr);
  if (process.versions.node === BOUNDARY_NODE_VERSION) {
    assert.match(run.stderr, /NOTHING_SELECTED: --only __absent__ does not name a registered knockout/);
  } else {
    assert.match(run.stderr, /BOUNDARY_BOOTSTRAP_NODE_VERSION_MISMATCH/);
    assert.ok(run.stderr.includes(`expected exact ${BOUNDARY_NODE_VERSION}`), run.stderr);
  }
  assert.doesNotMatch(run.stdout, /L4 control knockout|proven load-bearing|retained custody/);
  for (const args of [
    ["--war"],
    ["--warn", "--warn"],
    ["--print-suite-packages", "--warn"],
    ["unconsumed-positional"],
  ]) {
    const refused = childProcess.spawnSync(
      process.execPath,
      ["scripts/lint-control-knockout.mjs", ...args],
      { cwd: repositoryRoot, encoding: "utf8", env: environment, timeout: 30_000 },
    );
    assert.equal(refused.status, 1, `${args.join(" ")}: ${refused.stderr}`);
    assert.match(refused.stderr, /CLI_ARGUMENT_REFUSED:/);
    assert.doesNotMatch(
      refused.stdout,
      /L4 control knockout|proven load-bearing|retained custody|progress/,
    );
  }
  assert.equal(sha256File(absoluteIndexPath), indexBefore);
  assert.equal(git(repositoryRoot, ["status", "--porcelain=v1", "-z"]), statusBefore);
});

test("Phase 2 layered subject budget preserves full wires and the original metadata ceiling", async (t) => {
  const entry = {
    id: "subject-budget-fixture",
    control: "test-only result transport accounting",
    file: "control.mjs",
    find: "enabled = true",
    replace: "enabled = false",
    kind: "tests",
    suite: [".", "npm", ["test"]],
  };
  const baselineKeySha256 = workspace.knockoutBaselineKeySha256({
    dependencies: {}, kind: entry.kind, suite: entry.suite,
  });
  const baselineWire = (count: number, nameLength = 100, prefix = "fixture") => {
    const names = Array.from({ length: count }, (_, i) => `${prefix}-${i}-${"x".repeat(nameLength)}`);
    return workspace.knockoutBaselineWireFromObservation(baselineKeySha256, {
      armTerminalProtocolComplete: false, armTerminalProtocolError: null, armTerminalSummary: null,
      exit: 1, failing: new Set(names),
      failureEvents: names.map((name, i) => ({
        name, file: path.join(repositoryRoot, "test", `budget-fixture-${i}.ts`), line: i + 1, column: 1,
      })),
      fileFailureCount: 0, findings: 0, gate: null, gateFindings: [], gateProtocol: null,
      gateProtocolComplete: false, gateProtocolError: null, gateProvenance: null,
      protocolComplete: true, protocolError: null, signal: null, testCount: count, timedOut: false,
    }, { workspaceRoot: repositoryRoot });
  };
  const mutantWire = (detailLength: number) => workspace.knockoutResultWireFromEvidence({
    baselineKeySha256,
    entryId: entry.id,
    result: {
      ...entry, suite: ".", verdict: "INVALID_TEST", restored: true,
      workspaceDisposition: "RETAINED_UNMODIFIED_ARM", detail: "x".repeat(detailLength),
    },
  });
  const largeBaseline = baselineWire(200);
  assert.ok(workspace.canonicalJsonBytes(largeBaseline).length > 32 * 1024);
  assert.ok(workspace.canonicalJsonBytes(largeBaseline).length < 512 * 1024);
  const request = {
    baseline: largeBaseline, baselineResultSha256: "1".repeat(64),
    baselineTerminalSha256: "2".repeat(64), dependencies: {}, entry, pairedEntry: null,
    registrySha256: "3".repeat(64), suiteTimeoutMs: 60_000,
  };
  const subject = (value: Record<string, unknown>, postcheck = false) => workspace.createKnockoutWorkerSubject({
    operation: postcheck
      ? workspace.KNOCKOUT_WORKER_OPERATIONS.OBSERVE_KNOCKOUT_POSTCHECK
      : workspace.KNOCKOUT_WORKER_OPERATIONS.RUN_KNOCKOUT,
    request: value,
    workerSha256: "4".repeat(64),
  });
  const exceeds = (limitBytes: number) => (error: WorkspaceError) => {
    const details = (error as unknown as { details?: { limitBytes: number; observedBytes: number } }).details;
    return error.code === workspaceErrorCode("RESOURCE_LIMIT_EXCEEDED")
      && details?.limitBytes === limitBytes && details.observedBytes > limitBytes;
  };

  await t.test("a large baseline remains complete and changes the full subject digest", () => {
    const accepted = subject(request);
    assert.deepEqual(accepted.request.baseline, largeBaseline);
    assert.equal(workspace.knockoutWorkerSubjectSha256(accepted), armWorkerSubjectSha256(accepted));
    const different = subject({ ...request, baseline: baselineWire(200, 100, "another") });
    assert.notEqual(workspace.knockoutWorkerSubjectSha256(accepted), workspace.knockoutWorkerSubjectSha256(different));
  });
  await t.test("metadata is admitted exactly at 32 KiB and refused one byte above", () => {
    const projected = armWorkerSubject("4".repeat(64), workspace.KNOCKOUT_WORKER_OPERATIONS.RUN_KNOCKOUT, {
      ...request, baseline: null, entry: { ...entry, control: "" },
    });
    const padding = 32 * 1024 - workspace.canonicalJsonBytes(projected).length;
    assert.ok(padding > 0);
    subject({ ...request, entry: { ...entry, control: "x".repeat(padding) } });
    assert.throws(() => subject({ ...request, entry: { ...entry, control: "x".repeat(padding + 1) } }), exceeds(32 * 1024));
  });
  await t.test("POSTCHECK carries both independently bounded wires above 64 KiB", () => {
    const mutant = mutantWire(40 * 1024);
    const accepted = subject({
      ...request, mutant, mutantResultSha256: "5".repeat(64), mutantTerminalSha256: "6".repeat(64),
    }, true);
    assert.ok(workspace.canonicalJsonBytes(accepted).length > 64 * 1024);
    assert.deepEqual(accepted.request.baseline, largeBaseline);
    assert.deepEqual(accepted.request.mutant, mutant);
    assert.equal(workspace.knockoutWorkerSubjectSha256(accepted), armWorkerSubjectSha256(accepted));
  });
  await t.test("an individual baseline above the unchanged 512 KiB result ceiling is refused", () => {
    const oversized = baselineWire(1, 270_000);
    assert.ok(workspace.canonicalJsonBytes(oversized).length > 512 * 1024);
    assert.throws(() => subject({ ...request, baseline: oversized }), exceeds(512 * 1024));
  });
  await t.test("an individual mutant above the unchanged 512 KiB result ceiling is refused", () => {
    const oversized = mutantWire(512 * 1024);
    assert.ok(workspace.canonicalJsonBytes(oversized).length > 512 * 1024);
    assert.throws(() => subject({
      ...request, mutant: oversized, mutantResultSha256: "5".repeat(64), mutantTerminalSha256: "6".repeat(64),
    }, true), exceeds(512 * 1024));
  });
});

test("Phase 2 large baseline wire crosses FD 3 intact and keeps an invalid gate fail-closed", async () => {
  const fixture = minimalCaptureFixture("phase2-large-baseline");
  const detail = "test-only baseline diagnostic ".repeat(3000);
  const entry = {
    id: "large-baseline-control", control: "large evidence must not erase baseline refusal",
    file: "control.mjs", find: "export const controlEnabled = true;",
    replace: "export const controlEnabled = false;", kind: "gate", gateId: "large-baseline-gate",
    expectedGateFindings: [{ rule: "CONTROL_DISABLED", subject: "control" }],
    suite: [".", "node", ["large-baseline-gate.mjs"]],
  };
  try {
    installPhase2RunnerFixture(fixture.source, "install large-baseline runner closure");
    fs.writeFileSync(path.join(fixture.source, "control.mjs"), "export const controlEnabled = true;\n", { mode: 0o600 });
    fs.writeFileSync(path.join(fixture.source, "large-baseline-gate.mjs"), [
      "import { emitGateEvidence } from './scripts/lib/gate-event-contract.mjs';",
      `emitGateEvidence('large-baseline-gate', [{ rule: 'BASELINE_INVALID', subject: 'test fixture', detail: ${JSON.stringify(detail)} }]);`,
      "process.exitCode = 1;",
      "",
    ].join("\n"), { mode: 0o600 });
    installFixtureKnockoutRegistry(fixture.source, [entry]);
    git(fixture.source, ["add", "--all"]);
    git(fixture.source, ["commit", "-q", "-m", "add test-only large baseline diagnostic"]);
    const controlBefore = sha256File(path.join(fixture.source, "control.mjs"));
    const indexBefore = sha256File(path.join(fixture.source, ".git", "index"));
    const progress: Array<Record<string, unknown>> = [];
    const sweep = await knockoutRunner.runIsolatedKnockoutSweep({
      captureTimeoutMs: workspace.KNOCKOUT_WORKSPACE_CAPTURE_TIMEOUT_LIMIT_MS,
      custodyRoot: fixture.custody, maxRetainedArms: 3, maxRetainedBytes: 512 * 1024 * 1024,
      onProgress: (event: Record<string, unknown>) => progress.push(event),
      rawDependenciesByEntry: new Map([[entry.id, {}]]), registry: [entry], root: fixture.source,
      selected: [entry], suiteTimeoutMs: 60_000,
      workerTimeoutMs: workspace.KNOCKOUT_WORKSPACE_ARM_WORKER_TIMEOUT_LIMIT_MS,
    });
    assert.equal(sweep.status, "COMPLETE");
    assert.equal(sweep.closeEvidence.sourceRelease.status, "RELEASED");
    assert.equal(sweep.baselines.length, 1);
    assert.equal(sweep.mutants.length, 1);
    assert.equal(sweep.results[0]?.verdict, "INVALID_TEST");
    assert.equal(sweep.results[0]?.workspaceDisposition, "RETAINED_UNMODIFIED_ARM");
    assert.deepEqual(progress, [{
      completed: 1, detail: sweep.results[0]?.detail ?? null,
      id: entry.id, suite: entry.suite, total: 1, verdict: "INVALID_TEST",
    }]);
    assert.match(String(progress[0]?.detail), /baseline/i);
    const baseline = sweep.baselines[0]!;
    const published = JSON.parse(fs.readFileSync(path.join(baseline.workspaceRoot, "..", "evidence", "worker-result.bin"), "utf8"));
    assert.ok(workspace.canonicalJsonBytes(published.observation.baseline).length > 64 * 1024);
    assert.equal(published.observation.baseline.observation.gateFindings[0].detail, detail);
    const terminals = regularFilesBelow(fixture.custody)
      .filter((file) => path.basename(file) === "arm-terminal.json")
      .map((file) => ({ hash: sha256File(file), terminal: JSON.parse(fs.readFileSync(file, "utf8")) }));
    assert.equal(terminals.length, 3);
    const selftest = terminals.find(({ terminal }) => terminal.role === "SELFTEST")!;
    const baselineTerminal = terminals.find(({ terminal }) => terminal.role === "BASELINE")!;
    const mutantTerminal = terminals.find(({ terminal }) => terminal.role === "MUTANT")!;
    assert.equal(selftest.terminal.predecessorTerminalSha256, null);
    assert.equal(baselineTerminal.terminal.predecessorTerminalSha256, selftest.hash);
    assert.equal(mutantTerminal.terminal.predecessorTerminalSha256, baselineTerminal.hash);
    assert.ok(terminals.every(({ terminal }) => terminal.status === "COMPLETE" && terminal.workerResult.accepted === true));
    assert.equal(sha256File(path.join(fixture.source, "control.mjs")), controlBefore);
    assert.equal(sha256File(path.join(fixture.source, ".git", "index")), indexBefore);
    assert.equal(git(fixture.source, ["status", "--porcelain=v1", "-z"]), "");
  } finally {
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
  }
});

test("Phase 2 isolated runner executes one real baseline and mutant in separate retained arms without source writes", async () => {
  const fixture = minimalCaptureFixture("phase2-runner-integration");
  const entry = {
    id: "isolated-runner-control",
    control: "fixture control must be load-bearing",
    file: "control.mjs",
    find: "export const controlEnabled = true;",
    replace: "export const controlEnabled = false;",
    kind: "gate",
    gateId: "fixture-gate",
    expectedGateFindings: [{ rule: "CONTROL_DISABLED", subject: "control" }],
    suite: [".", "node", ["fixture-gate.mjs"]],
  };
  try {
    installPhase2RunnerFixture(fixture.source, "install isolated runner closure");
    fs.writeFileSync(
      path.join(fixture.source, "control.mjs"),
      "export const controlEnabled = true;\n",
      { mode: 0o600 },
    );
    fs.writeFileSync(
      path.join(fixture.source, "fixture-gate.mjs"),
      [
        "import { controlEnabled } from './control.mjs';",
        "const findings = controlEnabled ? [] : [{ rule: 'CONTROL_DISABLED', subject: 'control', detail: 'disabled' }];",
        "console.log(JSON.stringify({ protocol: 'noa-gate-runner/1', event: 'complete', gate: 'fixture-gate', findings }));",
        "process.exitCode = findings.length === 0 ? 0 : 1;",
        "",
      ].join("\n"),
      { mode: 0o600 },
    );
    installFixtureKnockoutRegistry(fixture.source, [entry]);
    git(fixture.source, ["add", "--all"]);
    git(fixture.source, ["commit", "-q", "-m", "add isolated runner integration fixture"]);

    const statusBefore = git(fixture.source, ["status", "--porcelain=v1", "-z"]);
    const indexBefore = sha256File(path.join(fixture.source, ".git", "index"));
    const controlBefore = sha256File(path.join(fixture.source, "control.mjs"));
    const captureTimeoutMs = workspace.KNOCKOUT_WORKSPACE_CAPTURE_TIMEOUT_LIMIT_MS;
    const suiteTimeoutMs = 600_000;
    const workerTimeoutMs = workspace.KNOCKOUT_WORKSPACE_ARM_WORKER_TIMEOUT_LIMIT_MS;
    const sweep = await knockoutRunner.runIsolatedKnockoutSweep({
      captureTimeoutMs,
      custodyRoot: fixture.custody,
      maxRetainedArms: 3,
      maxRetainedBytes: 512 * 1024 * 1024,
      rawDependenciesByEntry: new Map([[entry.id, {}]]),
      registry: [entry],
      root: fixture.source,
      selected: [entry],
      suiteTimeoutMs,
      workerTimeoutMs,
    });

    assert.equal(sweep.status, "COMPLETE");
    const candidateManifestFiles = regularFilesBelow(fixture.custody)
      .filter((file) => path.basename(file) === "candidate-manifest.json");
    assert.equal(candidateManifestFiles.length, 1);
    const candidateManifest = JSON.parse(
      fs.readFileSync(candidateManifestFiles[0]!, "utf8"),
    ) as Capture["manifest"];
    assert.equal(candidateManifest.resourceAdmission.operationDeadlineMs, captureTimeoutMs);
    assert.equal(candidateManifest.resourceAdmission.childCommandTimeoutMs, 300_000);
    assert.equal(sweep.closeEvidence.sourceRelease.status, "RELEASED");
    assert.equal(sweep.baselines.length, 1);
    const baselineArm = sweep.baselines[0];
    const mutantArm = sweep.mutants[0];
    const result = sweep.results[0];
    assert.ok(baselineArm !== undefined);
    assert.ok(mutantArm !== undefined);
    assert.ok(result !== undefined);
    assert.equal(baselineArm.observation.timedOut, false);
    assert.deepEqual(
      sweep.results.map((result) => ({
        id: result.id,
        restored: result.restored,
        verdict: result.verdict,
      })),
      [{ id: entry.id, restored: false, verdict: "DETECTOR_TRIGGERED" }],
    );
    assert.equal(result.workspaceDisposition, "RETAINED_DISPOSABLE_MUTANT");
    assert.equal(
      fs.readFileSync(path.join(mutantArm.workspaceRoot, "control.mjs"), "utf8"),
      "export const controlEnabled = false;\n",
    );
    assert.equal(
      fs.readFileSync(path.join(baselineArm.workspaceRoot, "control.mjs"), "utf8"),
      "export const controlEnabled = true;\n",
    );
    assert.equal(sha256File(path.join(fixture.source, "control.mjs")), controlBefore);
    assert.equal(sha256File(path.join(fixture.source, ".git", "index")), indexBefore);
    assert.equal(git(fixture.source, ["status", "--porcelain=v1", "-z"]), statusBefore);
    const armTerminals = regularFilesBelow(fixture.custody)
      .filter((file) => path.basename(file) === "arm-terminal.json")
      .map((file) => ({
        sha256: sha256File(file),
        terminal: JSON.parse(fs.readFileSync(file, "utf8")) as {
        predecessorTerminalSha256: string | null;
        retainedTargets: null | {
          protocol: string;
          targets: Array<{
            beforeSha256: string;
            initialObservation: { identity: string; mode: number; nlink: number };
            path: string;
            retainedObservation: { identity: string; mode: number; nlink: number };
            retainedSha256: string;
          }>;
          verifiedAfterOriginalProcessGroupExit: boolean;
        };
        role: string;
      },
      }));
    assert.equal(armTerminals.length, 3);
    const orderedRoles = [];
    let next = armTerminals.find(({ terminal }) => terminal.predecessorTerminalSha256 === null);
    while (next !== undefined) {
      orderedRoles.push(next.terminal.role);
      const predecessor = next.sha256;
      next = armTerminals.find(({ terminal }) => terminal.predecessorTerminalSha256 === predecessor);
    }
    assert.deepEqual(orderedRoles, ["SELFTEST", "BASELINE", "MUTANT"]);
    const retainedTerminal = armTerminals.find(({ terminal }) => terminal.role === "MUTANT")?.terminal;
    assert.ok(retainedTerminal !== undefined);
    assert.ok(retainedTerminal.retainedTargets !== null);
    assert.equal(
      retainedTerminal.retainedTargets.protocol,
      workspace.KNOCKOUT_WORKSPACE_PROTOCOLS.retainedTargets,
    );
    assert.equal(retainedTerminal.retainedTargets.verifiedAfterOriginalProcessGroupExit, true);
    assert.equal(retainedTerminal.retainedTargets.targets.length, 1);
    const retainedTarget = retainedTerminal.retainedTargets.targets[0];
    assert.ok(retainedTarget !== undefined);
    assert.equal(retainedTarget.path, "control.mjs");
    assert.equal(retainedTarget.beforeSha256, controlBefore);
    assert.equal(retainedTarget.retainedSha256, sha256File(path.join(mutantArm.workspaceRoot, "control.mjs")));
    assert.equal(retainedTarget.initialObservation.identity, retainedTarget.retainedObservation.identity);
    assert.equal(retainedTarget.initialObservation.mode, retainedTarget.retainedObservation.mode);
    assert.equal(retainedTarget.initialObservation.nlink, 1);
    assert.equal(retainedTarget.retainedObservation.nlink, 1);
    assert.equal(
      armTerminals.filter(({ terminal }) => terminal.role !== "MUTANT")
        .every(({ terminal }) => terminal.retainedTargets === null),
      true,
    );
  } finally {
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
  }
});

test("Phase 2 supervisor refuses a retained mutant changed by a delayed same-group child after worker commit", async () => {
  const fixture = minimalCaptureFixture("phase2-delayed-retained-target");
  const entry = {
    id: "delayed-retained-target-control",
    control: "terminal evidence must bind the retained mutant after its original process group exits",
    file: "control.mjs",
    find: "export const controlEnabled = true;",
    replace: "export const controlEnabled = false;",
    kind: "gate",
    gateId: "delayed-retained-target-gate",
    expectedGateFindings: [{ rule: "CONTROL_DISABLED", subject: "control" }],
    suite: [".", "node", ["delayed-retained-target-gate.mjs"]],
  };
  try {
    installPhase2RunnerFixture(fixture.source, "install delayed-child runner closure");
    fs.writeFileSync(
      path.join(fixture.source, "control.mjs"),
      "export const controlEnabled = true;\n",
      { mode: 0o600 },
    );
    fs.writeFileSync(
      path.join(fixture.source, "late-retained-mutator.cjs"),
      [
        "const fs = require('node:fs');",
        "const path = require('node:path');",
        "const wait = new Int32Array(new SharedArrayBuffer(4));",
        "const runsRoot = path.resolve(process.cwd(), '..', 'evidence', 'runner-state', 'runs');",
        "const ready = path.join(process.cwd(), 'late-retained-mutator.ready');",
        "const target = path.join(process.cwd(), 'control.mjs');",
        "let marker = null;",
        "const markerDeadline = Date.now() + 5000;",
        "while (marker === null && Date.now() < markerDeadline) {",
        "  try {",
        "    for (const name of fs.readdirSync(runsRoot)) {",
        "      const candidate = path.join(runsRoot, name, 'inflight.json');",
        "      if (fs.existsSync(candidate)) { marker = candidate; break; }",
        "    }",
        "  } catch {}",
        "  if (marker === null) Atomics.wait(wait, 0, 0, 1);",
        "}",
        "if (marker === null) process.exit(74);",
        "fs.writeFileSync(ready, marker, { mode: 0o600 });",
        "const commitDeadline = Date.now() + 20000;",
        "while (fs.existsSync(marker) && Date.now() < commitDeadline) Atomics.wait(wait, 0, 0, 1);",
        "if (fs.existsSync(marker)) process.exit(75);",
        "const replacement = `${target}.late-${process.pid}`;",
        "fs.writeFileSync(replacement, 'export const controlEnabled = true;\\n', { flag: 'wx', mode: 0o600 });",
        "fs.renameSync(replacement, target);",
        "",
      ].join("\n"),
      { mode: 0o600 },
    );
    fs.writeFileSync(
      path.join(fixture.source, "delayed-retained-target-gate.mjs"),
      [
        "import { spawn } from 'node:child_process';",
        "import fs from 'node:fs';",
        "import path from 'node:path';",
        "import { controlEnabled } from './control.mjs';",
        "if (!controlEnabled) {",
        "  const child = spawn(process.execPath, ['late-retained-mutator.cjs'], { detached: false, stdio: 'ignore' });",
        "  child.unref();",
        "  const ready = path.join(process.cwd(), 'late-retained-mutator.ready');",
        "  const wait = new Int32Array(new SharedArrayBuffer(4));",
        "  const deadline = Date.now() + 5000;",
        "  while (!fs.existsSync(ready) && Date.now() < deadline) Atomics.wait(wait, 0, 0, 1);",
        "  if (!fs.existsSync(ready)) throw new Error('delayed child did not bind the live recovery marker');",
        "}",
        "const findings = controlEnabled ? [] : [{ rule: 'CONTROL_DISABLED', subject: 'control', detail: 'disabled' }];",
        "console.log(JSON.stringify({ protocol: 'noa-gate-runner/1', event: 'complete', gate: 'delayed-retained-target-gate', findings }));",
        "process.exitCode = findings.length === 0 ? 0 : 1;",
        "",
      ].join("\n"),
      { mode: 0o600 },
    );
    installFixtureKnockoutRegistry(fixture.source, [entry]);
    git(fixture.source, ["add", "--all"]);
    git(fixture.source, ["commit", "-q", "-m", "add delayed retained-target attack fixture"]);

    const statusBefore = git(fixture.source, ["status", "--porcelain=v1", "-z"]);
    const indexBefore = sha256File(path.join(fixture.source, ".git", "index"));
    const controlBefore = sha256File(path.join(fixture.source, "control.mjs"));
    await assert.rejects(
      () => knockoutRunner.runIsolatedKnockoutSweep({
        captureTimeoutMs: workspace.KNOCKOUT_WORKSPACE_CAPTURE_TIMEOUT_LIMIT_MS,
        custodyRoot: fixture.custody,
        maxRetainedArms: 3,
        maxRetainedBytes: 512 * 1024 * 1024,
        rawDependenciesByEntry: new Map([[entry.id, {}]]),
        registry: [entry],
        root: fixture.source,
        selected: [entry],
        suiteTimeoutMs: 60_000,
        workerTimeoutMs: workspace.KNOCKOUT_WORKSPACE_ARM_WORKER_TIMEOUT_LIMIT_MS,
      }),
      (error: WorkspaceError) => {
        const details = (error as unknown as { details?: { status?: unknown } }).details;
        return error.code === "ARM_REFUSED" && details?.status === "INDETERMINATE";
      },
    );

    const terminals = regularFilesBelow(fixture.custody)
      .filter((file) => path.basename(file) === "arm-terminal.json")
      .map((file) => JSON.parse(fs.readFileSync(file, "utf8")) as {
        reasonCode: string;
        retainedTargetFailure: null | { code: string; phase: string };
        retainedTargets: unknown;
        role: string;
        status: string;
        workerResult: { accepted: boolean; status: string | null };
      });
    assert.equal(terminals.length, 3);
    const mutantTerminal = terminals.find((terminal) => terminal.role === "MUTANT");
    assert.ok(mutantTerminal !== undefined);
    assert.equal(mutantTerminal.status, "INDETERMINATE");
    assert.equal(mutantTerminal.reasonCode, "RETAINED_TARGET_REVALIDATION_FAILED");
    assert.deepEqual(mutantTerminal.retainedTargetFailure, {
      code: workspaceErrorCode("ARM_IDENTITY_MISMATCH"),
      phase: "POST_PROCESS_GROUP_REVALIDATION",
    });
    assert.equal(mutantTerminal.retainedTargets, null);
    assert.equal(mutantTerminal.workerResult.accepted, false);
    assert.equal(mutantTerminal.workerResult.status, "COMPLETE");
    const retainedControl = regularFilesBelow(fixture.custody)
      .filter((file) => path.basename(file) === "control.mjs")
      .find((file) => fs.existsSync(path.join(path.dirname(file), "late-retained-mutator.ready")));
    assert.ok(retainedControl !== undefined);
    assert.equal(fs.readFileSync(retainedControl, "utf8"), "export const controlEnabled = true;\n");
    assert.equal(sha256File(path.join(fixture.source, "control.mjs")), controlBefore);
    assert.equal(sha256File(path.join(fixture.source, ".git", "index")), indexBefore);
    assert.equal(git(fixture.source, ["status", "--porcelain=v1", "-z"]), statusBefore);
  } finally {
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
  }
});

function fixtureBoundaryGatePrelude({ optional = false } = {}): string[] {
  if (optional) return [
    "// TEST ONLY: support both ordinary gate runs and the real worker's one-shot bootstrap transport.",
    "import crypto from 'node:crypto';",
    "import { BOUNDARY_KNOCKOUT_BOOTSTRAP_ENV } from './lib/boundary-bootstrap.mjs';",
    "import { BOUNDARY_CANDIDATE_TIER_A_GATE_EXPECTATION } from './lib/boundary-gate-provenance.mjs';",
    "import { emitGateEvidence, emitProvenanceBoundGateEvidence } from './lib/gate-event-contract.mjs';",
    "const bootstrapDescriptor = process.env[BOUNDARY_KNOCKOUT_BOOTSTRAP_ENV];",
    "if (bootstrapDescriptor !== undefined && bootstrapDescriptor !== '0') throw new Error('invalid fixture bootstrap descriptor');",
    "const bootstrap = bootstrapDescriptor === undefined ? null : JSON.parse(fs.readFileSync(0, 'utf8'));",
    "if (bootstrap !== null && bootstrap.protocol !== 'noa-boundary-knockout-bootstrap/1') throw new Error('invalid fixture bootstrap');",
    "const { protocol, ...provenance } = BOUNDARY_CANDIDATE_TIER_A_GATE_EXPECTATION;",
  ];
  return [
    "// TEST ONLY: exercise the real worker's one-shot bootstrap transport in a disposable gate.",
    "import crypto from 'node:crypto';",
    "import { BOUNDARY_KNOCKOUT_BOOTSTRAP_ENV } from './lib/boundary-bootstrap.mjs';",
    "import { BOUNDARY_CANDIDATE_TIER_A_GATE_EXPECTATION } from './lib/boundary-gate-provenance.mjs';",
    "import { emitProvenanceBoundGateEvidence } from './lib/gate-event-contract.mjs';",
    "if (process.env[BOUNDARY_KNOCKOUT_BOOTSTRAP_ENV] !== '0') throw new Error('missing fixture bootstrap');",
    "const bootstrap = JSON.parse(fs.readFileSync(0, 'utf8'));",
    "if (bootstrap.protocol !== 'noa-boundary-knockout-bootstrap/1') throw new Error('invalid fixture bootstrap');",
    "const { protocol, ...provenance } = BOUNDARY_CANDIDATE_TIER_A_GATE_EXPECTATION;",
  ];
}

type MixedGateSweepCase = {
  expectedPlainFinding?: { rule: string; subject: string };
  forceInvalidProvenanceProtocol?: boolean;
  order: readonly ["plain", "provenance"] | readonly ["provenance", "plain"];
};

async function runMixedGateSweepCase({
  expectedPlainFinding = { rule: "PLAIN_CONTROL_DISABLED", subject: "plain control" },
  forceInvalidProvenanceProtocol = false,
  order,
}: MixedGateSweepCase): Promise<void> {
  const fixture = minimalCaptureFixture(`phase2-mixed-provenance-${order.join("-")}`);
  const plainEntry = {
    id: "mixed-plain-control",
    control: "plain fixture control must be load-bearing",
    file: "plain-control.mjs",
    find: "export const plainControlEnabled = true;",
    replace: "export const plainControlEnabled = false;",
    kind: "gate",
    gateId: "mixed-provenance-gate",
    expectedGateFindings: [expectedPlainFinding],
    suite: [".", "node", ["scripts/lint-boundary.mjs"]],
  };
  const provenanceEntry = {
    id: "mixed-provenance-control",
    control: "provenance fixture control must be load-bearing",
    file: "provenance-control.mjs",
    find: "export const provenanceControlEnabled = true;",
    replace: "export const provenanceControlEnabled = false;",
    kind: "gate",
    gateId: "mixed-provenance-gate",
    expectedGateFindings: [{ rule: "PROVENANCE_CONTROL_DISABLED", subject: "provenance control" }],
    expectedGateProvenance: knockoutRunner.BOUNDARY_CANDIDATE_TIER_A_KNOCKOUT_PROVENANCE_EXPECTATION,
    suite: [".", "node", ["scripts/lint-boundary.mjs"]],
  };
  const entries = { plain: plainEntry, provenance: provenanceEntry };
  const selected = order.map((name) => entries[name]);
  try {
    installPhase2RunnerFixture(fixture.source, "install mixed-provenance runner closure");
    fs.writeFileSync(
      path.join(fixture.source, "plain-control.mjs"),
      "export const plainControlEnabled = true;\n",
      { mode: 0o600 },
    );
    fs.writeFileSync(
      path.join(fixture.source, "provenance-control.mjs"),
      "export const provenanceControlEnabled = true;\n",
      { mode: 0o600 },
    );
    fs.writeFileSync(
      path.join(fixture.source, "scripts", "lint-boundary.mjs"),
      [
        "import fs from 'node:fs';",
        "import { plainControlEnabled } from '../plain-control.mjs';",
        "import { provenanceControlEnabled } from '../provenance-control.mjs';",
        ...fixtureBoundaryGatePrelude({ optional: true }),
        "const findings = [];",
        "if (!plainControlEnabled) findings.push({ rule: 'PLAIN_CONTROL_DISABLED', subject: 'plain control', detail: 'plain control disabled' });",
        "if (!provenanceControlEnabled) findings.push({ rule: 'PROVENANCE_CONTROL_DISABLED', subject: 'provenance control', detail: 'provenance control disabled' });",
        "const manifestDigest = crypto.createHash('sha256')",
        "  .update(fs.readFileSync('plain-control.mjs')).update('\\0')",
        "  .update(fs.readFileSync('provenance-control.mjs')).digest('hex');",
        `if (bootstrap === null || ${JSON.stringify(forceInvalidProvenanceProtocol)}) {`,
        "  emitGateEvidence('mixed-provenance-gate', findings);",
        "} else {",
        "  emitProvenanceBoundGateEvidence('mixed-provenance-gate', findings, {",
        "    ...provenance, subject: bootstrap.candidateSubject, controlManifestDigest: manifestDigest,",
        "  });",
        "}",
        "process.exitCode = findings.length === 0 ? 0 : 1;",
        "",
      ].join("\n"),
      { mode: 0o600 },
    );
    installFixtureKnockoutRegistry(fixture.source, [plainEntry, provenanceEntry]);
    git(fixture.source, ["add", "--all"]);
    git(fixture.source, ["commit", "-q", "-m", "add mixed-provenance gate fixture"]);

    const candidateSubject = {
      archiveSha256: sha256File(path.join(fixture.source, "scripts", "lint-boundary.mjs")),
      commit: git(fixture.source, ["rev-parse", "HEAD"]).trim(),
      repository: "fixture/mixed-provenance-candidate",
      tree: git(fixture.source, ["rev-parse", "HEAD^{tree}"]).trim(),
    };
    const statusBefore = git(fixture.source, ["status", "--porcelain=v1", "-z"]);
    const indexBefore = sha256File(path.join(fixture.source, ".git", "index"));
    const controlsBefore = new Map([
      [plainEntry.file, sha256File(path.join(fixture.source, plainEntry.file))],
      [provenanceEntry.file, sha256File(path.join(fixture.source, provenanceEntry.file))],
    ]);
    let sweep: Awaited<ReturnType<typeof knockoutRunner.runIsolatedKnockoutSweep>>;
    try {
      sweep = await knockoutRunner.runIsolatedKnockoutSweep({
        candidateSubject,
        captureTimeoutMs: workspace.KNOCKOUT_WORKSPACE_CAPTURE_TIMEOUT_LIMIT_MS,
        custodyRoot: fixture.custody,
        maxRetainedArms: 4,
        maxRetainedBytes: 768 * 1024 * 1024,
        rawDependenciesByEntry: new Map(selected.map((entry) => [entry.id, {}])),
        registry: [plainEntry, provenanceEntry],
        root: fixture.source,
        selected,
        suiteTimeoutMs: 60_000,
        workerTimeoutMs: workspace.KNOCKOUT_WORKSPACE_ARM_WORKER_TIMEOUT_LIMIT_MS,
      });
    } catch (error) {
      for (const [file, digest] of controlsBefore) {
        assert.equal(sha256File(path.join(fixture.source, file)), digest);
      }
      assert.equal(sha256File(path.join(fixture.source, ".git", "index")), indexBefore);
      assert.equal(git(fixture.source, ["status", "--porcelain=v1", "-z"]), statusBefore);
      const terminals = regularFilesBelow(fixture.custody)
        .filter((file) => path.basename(file) === "arm-terminal.json")
        .map((file) => JSON.parse(fs.readFileSync(file, "utf8")) as {
          role: string;
          status: string;
          workerResult: { accepted: boolean };
        });
      assert.equal(terminals.length, 3);
      assert.equal(terminals.filter((terminal) => terminal.status === "REFUSED").length, 0);
      assert.equal(terminals.filter((terminal) => terminal.status === "COMPLETE").length, 3);
      assert.ok(terminals.every((terminal) => terminal.workerResult.accepted === true));
      if (error instanceof Error) {
        error.message = `${error.message}; fixture source/index and pre-spawn three-terminal lifecycle remained preserved`;
      }
      throw error;
    }

    assert.equal(sweep.status, "COMPLETE");
    assert.equal(sweep.closeEvidence.sourceRelease.status, "RELEASED");
    assert.equal(sweep.baselines.length, 1);
    assert.equal(sweep.mutants.length, 2);
    assert.deepEqual(sweep.results.map((result) => result.id), selected.map((entry) => entry.id));
    const plainResult = sweep.results.find((result) => result.id === plainEntry.id)! as
      (typeof sweep.results)[number] & {
        newGateFindings: Array<{ detail: string; rule: string; subject: string }>;
      };
    const provenanceResult = sweep.results.find((result) => result.id === provenanceEntry.id)! as
      (typeof sweep.results)[number] & {
        newGateFindings: Array<{ detail: string; rule: string; subject: string }>;
      };
    assert.equal(
      plainResult.verdict,
      expectedPlainFinding.rule === "PLAIN_CONTROL_DISABLED"
        ? "DETECTOR_TRIGGERED"
        : "DETECTOR_DID_NOT_TRIGGER",
    );
    assert.equal(
      provenanceResult.verdict,
      forceInvalidProvenanceProtocol ? "INVALID_TEST" : "DETECTOR_TRIGGERED",
    );
    assert.deepEqual(plainResult.newGateFindings, [{
      detail: "plain control disabled",
      rule: "PLAIN_CONTROL_DISABLED",
      subject: "plain control",
    }]);
    assert.deepEqual(provenanceResult.newGateFindings, forceInvalidProvenanceProtocol ? [] : [{
      detail: "provenance control disabled",
      rule: "PROVENANCE_CONTROL_DISABLED",
      subject: "provenance control",
    }]);
    if (!forceInvalidProvenanceProtocol) {
      const provenanceEvidence = provenanceResult as typeof provenanceResult & {
        baselineGateProvenance: { subject: unknown };
        mutatedGateProvenance: { subject: unknown };
      };
      assert.deepEqual(provenanceEvidence.baselineGateProvenance.subject, candidateSubject);
      assert.deepEqual(provenanceEvidence.mutatedGateProvenance.subject, candidateSubject);
    }
    for (const [file, digest] of controlsBefore) {
      assert.equal(sha256File(path.join(fixture.source, file)), digest);
    }
    assert.equal(sha256File(path.join(fixture.source, ".git", "index")), indexBefore);
    assert.equal(git(fixture.source, ["status", "--porcelain=v1", "-z"]), statusBefore);
    const terminals = regularFilesBelow(fixture.custody)
      .filter((file) => path.basename(file) === "arm-terminal.json")
      .map((file) => ({
        sha256: sha256File(file),
        terminal: JSON.parse(fs.readFileSync(file, "utf8")) as {
          predecessorTerminalSha256: string | null;
          role: string;
          status: string;
          workerResult: { accepted: boolean };
        },
      }));
    assert.equal(terminals.length, 4);
    const orderedRoles = [];
    let next = terminals.find(({ terminal }) => terminal.predecessorTerminalSha256 === null);
    while (next !== undefined) {
      orderedRoles.push(next.terminal.role);
      const predecessor = next.sha256;
      next = terminals.find(({ terminal }) => terminal.predecessorTerminalSha256 === predecessor);
    }
    assert.deepEqual(orderedRoles, ["SELFTEST", "BASELINE", "MUTANT", "MUTANT"]);
    assert.ok(terminals.every(({ terminal }) =>
      terminal.status === "COMPLETE" && terminal.workerResult.accepted === true));
  } finally {
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
  }
}

for (const order of [
  ["plain", "provenance"],
  ["provenance", "plain"],
] as const) {
  test(`Phase 2 reuses one mixed legacy/provenance baseline (${order.join(" first, ")} second)`, async () => {
    await runMixedGateSweepCase({ order });
  });
}

test("Phase 2 mixed baseline gives no detection credit for a mismatched authored finding", async () => {
  await runMixedGateSweepCase({
    expectedPlainFinding: { rule: "PLAIN_CONTROL_BLOCKED", subject: "plain control" },
    order: ["plain", "provenance"],
  });
});

test("Phase 2 mixed baseline gives no provenance-bound detection credit for a legacy protocol", async () => {
  await runMixedGateSweepCase({
    forceInvalidProvenanceProtocol: true,
    order: ["plain", "provenance"],
  });
});

const crossPhaseScenarios = [
  { id: "baseline-result", phase: "mutant" },
  { id: "mutant-wire", phase: "postcheck" },
  { id: "mutant-predecessor", phase: "postcheck" },
  { id: "candidate-mutant-value", phase: "mutant" },
  { id: "candidate-mutant-absent", phase: "mutant" },
  { id: "candidate-postcheck-value", phase: "postcheck" },
  { id: "candidate-postcheck-absent", phase: "postcheck" },
] as const;

for (const scenario of crossPhaseScenarios) {
  test(`Phase 2 refuses forged cross-phase references before worker spawn (${scenario.id})`, async () => {
    const fixture = minimalCaptureFixture(`phase2-cross-phase-${scenario.id}`);
    const bindsCandidate = scenario.id.startsWith("candidate-");
    const gateScript = bindsCandidate ? "scripts/lint-boundary.mjs" : "cross-phase-gate.mjs";
    const entry = {
      id: `cross-phase-${scenario.id}`,
      control: "cross-phase evidence must come from the immediate retained predecessor",
      file: "control.mjs",
      find: "export const controlEnabled = true;",
      replace: "export const controlEnabled = false;",
      kind: "gate",
      gateId: "cross-phase-gate",
      expectedGateFindings: [{ rule: "CONTROL_DISABLED", subject: "control" }],
      ...(bindsCandidate ? {
        expectedGateProvenance: knockoutRunner.BOUNDARY_CANDIDATE_TIER_A_KNOCKOUT_PROVENANCE_EXPECTATION,
      } : {}),
      suite: [".", "node", [gateScript]],
    };
    let captured: Capture | null = null;
    let cooperativeLease: CooperativeSourceLease | null = null;
    let released: { retainedPrivateRoots?: RetainedPrivateRoot[] } | null = null;
    try {
      installPhase2RunnerFixture(fixture.source, `install ${scenario.id} runner closure`);
      fs.writeFileSync(
        path.join(fixture.source, "control.mjs"),
        "export const controlEnabled = true;\n",
        { mode: 0o600 },
      );
      fs.writeFileSync(
        path.join(fixture.source, gateScript),
        [
          "import fs from 'node:fs';",
          `import { controlEnabled } from '${bindsCandidate ? ".." : "."}/control.mjs';`,
          ...(bindsCandidate ? fixtureBoundaryGatePrelude() : []),
          "if (!controlEnabled) fs.writeFileSync('mutant-ran.txt', 'spawned\\n');",
          "const findings = controlEnabled ? [] : [{ rule: 'CONTROL_DISABLED', subject: 'control', detail: 'disabled' }];",
          ...(bindsCandidate ? [
            "emitProvenanceBoundGateEvidence('cross-phase-gate', findings, {",
            "  ...provenance, subject: bootstrap.candidateSubject,",
            "  controlManifestDigest: crypto.createHash('sha256').update(fs.readFileSync('control.mjs')).digest('hex'),",
            "});",
          ] : [
            "console.log(JSON.stringify({ protocol: 'noa-gate-runner/1', event: 'complete', gate: 'cross-phase-gate', findings }));",
          ]),
          "process.exitCode = findings.length === 0 ? 0 : 1;",
          "",
        ].join("\n"),
        { mode: 0o600 },
      );
      installFixtureKnockoutRegistry(fixture.source, [entry]);
      git(fixture.source, ["add", "--all"]);
      git(fixture.source, ["commit", "-q", "-m", `add ${scenario.id} cross-phase fixture`]);

      const workerSha256 = sha256File(
        path.join(fixture.source, "scripts", "lib", "knockout-workspace-worker.mjs"),
      );
      const registrySha256 = crypto.createHash("sha256")
        .update(workspace.canonicalJsonBytes([entry]))
        .digest("hex");
      const dependencies = {};
      const candidateSubject = {
        archiveSha256: workerSha256,
        commit: git(fixture.source, ["rev-parse", "HEAD"]).trim(),
        repository: "fixture/cross-phase-candidate",
        tree: git(fixture.source, ["rev-parse", "HEAD^{tree}"]).trim(),
      };
      const otherCandidateSubject = { ...candidateSubject, archiveSha256: "f".repeat(64) };
      const baselineKeySha256 = workspace.knockoutBaselineKeySha256({
        dependencies,
        kind: entry.kind,
        suite: entry.suite,
      });
      captured = workspace.captureAndSealCandidate({
        custodyRoot: fixture.custody,
        maxAttempts: 1,
        sourceRoot: fixture.source,
      });
      const sourceLease = workspace.acquireSourceLease(workspace.openKnockoutCustody(captured, {
        maxRetainedArms: 3,
        maxRetainedBytes: 512 * 1024 * 1024,
      }));
      cooperativeLease = await workspace.acquireCooperativeSourceLease(sourceLease);

      const startArm = (armId: string, role: string, subject: WorkerSubject) => {
        const plan = workspace.admitArmPlan(cooperativeLease!, {
          arms: [{
            armId,
            role,
            subjectSha256: workspace.knockoutWorkerSubjectSha256(subject),
          }],
        });
        const arm = workspace.materializeArm(plan, armId);
        return {
          arm,
          completed: workspace.runArmWorker(cooperativeLease!, arm, { subject, timeoutMs: 60_000 }),
        };
      };

      const baselineSubject = workspace.createKnockoutWorkerSubject({
        operation: workspace.KNOCKOUT_WORKER_OPERATIONS.OBSERVE_KNOCKOUT_BASELINE,
        request: {
          baselineKeySha256,
          ...(bindsCandidate ? { candidateSubject } : {}),
          dependencies,
          entryId: entry.id,
          kind: entry.kind,
          registrySha256,
          suite: entry.suite,
          suiteTimeoutMs: 60_000,
        },
        workerSha256,
      });
      const baselineRun = startArm(`${scenario.id}-baseline`, "BASELINE", baselineSubject);
      const baselineCompleted = await baselineRun.completed;
      assert.equal(baselineCompleted.status, "COMPLETE");
      const baselineWire = (baselineCompleted.workerResult.observation as {
        baseline: Record<string, unknown>;
      }).baseline;

      const mutantRequest = {
        baseline: baselineWire,
        ...(bindsCandidate && scenario.id !== "candidate-mutant-absent"
          ? { candidateSubject: scenario.id === "candidate-mutant-value"
            ? otherCandidateSubject : candidateSubject }
          : {}),
        baselineResultSha256: scenario.id === "baseline-result"
          ? "f".repeat(64)
          : baselineCompleted.resultPublication.sha256,
        baselineTerminalSha256: baselineCompleted.terminalPublication.sha256,
        dependencies,
        entry,
        pairedEntry: null,
        registrySha256,
        suiteTimeoutMs: 60_000,
      };
      const mutantSubject = workspace.createKnockoutWorkerSubject({
        operation: workspace.KNOCKOUT_WORKER_OPERATIONS.RUN_KNOCKOUT,
        request: mutantRequest,
        workerSha256,
      });

      if (scenario.phase === "mutant") {
        const refused = startArm(`${scenario.id}-mutant`, "MUTANT", mutantSubject);
        await assert.rejects(
          refused.completed,
          (error: WorkspaceError) => error.code === workspaceErrorCode("CAPABILITY_INVALID"),
        );
        assert.deepEqual(fs.readdirSync(refused.arm.evidenceRoot), []);
        assert.equal(fs.existsSync(path.join(refused.arm.workspaceRoot, "mutant-ran.txt")), false);
      } else {
        const mutantRun = startArm(`${scenario.id}-mutant`, "MUTANT", mutantSubject);
        const mutantCompleted = await mutantRun.completed;
        assert.equal(mutantCompleted.status, "COMPLETE");
        const mutantWire = (mutantCompleted.workerResult.observation as {
          knockout: Record<string, unknown>;
        }).knockout;
        let requestedMutant = mutantWire;
        if (scenario.id === "mutant-wire") {
          requestedMutant = JSON.parse(JSON.stringify(mutantWire)) as Record<string, unknown>;
          const evidence = requestedMutant.evidence as Record<string, unknown>;
          evidence.detail = `${String(evidence.detail)} forged`;
          requestedMutant.evidenceSha256 = crypto.createHash("sha256")
            .update(workspace.canonicalJsonBytes(evidence))
            .digest("hex");
        }
        const postcheckRequest: Record<string, unknown> = {
          ...mutantRequest,
          baselineResultSha256: baselineCompleted.resultPublication.sha256,
          mutant: requestedMutant,
          mutantResultSha256: mutantCompleted.resultPublication.sha256,
          mutantTerminalSha256: scenario.id === "mutant-predecessor"
            ? baselineCompleted.terminalPublication.sha256
            : mutantCompleted.terminalPublication.sha256,
        };
        if (scenario.id === "candidate-postcheck-value") {
          postcheckRequest.candidateSubject = otherCandidateSubject;
        } else if (scenario.id === "candidate-postcheck-absent") {
          delete postcheckRequest.candidateSubject;
        }
        const postcheckSubject = workspace.createKnockoutWorkerSubject({
          operation: workspace.KNOCKOUT_WORKER_OPERATIONS.OBSERVE_KNOCKOUT_POSTCHECK,
          request: postcheckRequest,
          workerSha256,
        });
        const refused = startArm(`${scenario.id}-postcheck`, "POSTCHECK", postcheckSubject);
        await assert.rejects(
          refused.completed,
          (error: WorkspaceError) => error.code === workspaceErrorCode("CAPABILITY_INVALID"),
        );
        assert.deepEqual(fs.readdirSync(refused.arm.evidenceRoot), []);
      }

      const close = await workspace.closeCooperativeSourceLease(cooperativeLease);
      cooperativeLease = null;
      released = close.sourceRelease as { retainedPrivateRoots?: RetainedPrivateRoot[] };
      assert.equal(close.status, "RELEASED");
    } finally {
      if (cooperativeLease !== null) {
        try {
          const close = await workspace.closeCooperativeSourceLease(cooperativeLease);
          released = close.sourceRelease as { retainedPrivateRoots?: RetainedPrivateRoot[] };
        } catch {}
      }
      cleanupReportedScratchRoots(
        released?.retainedPrivateRoots ?? captured?.retainedPrivateRoots ?? [],
      );
      removeFixturePath(fixture.source);
      removeFixturePath(fixture.custody);
    }
  });
}

test("Phase 2 setup-integrity credit waits for a fresh pristine POSTCHECK arm with one exact candidate", async () => {
  const fixture = minimalCaptureFixture("phase2-runner-postcheck");
  const baselineCasePlanSha256 = "a".repeat(64);
  const mutatedCasePlanSha256 = "b".repeat(64);
  const from = "case.fixture-setup-plan-a";
  const to = "case.fixture-setup-plan-b";
  const entry = {
    id: "isolated-runner-setup-integrity",
    control: "fixture setup-integrity control must be load-bearing",
    file: "control.mjs",
    find: from,
    replace: to,
    kind: "gate",
    gateId: "fixture-setup-gate",
    expectedGateFindings: [{ rule: "SELFTEST", subject: "fixture setup plan" }],
    expectedGateProvenance: knockoutRunner.BOUNDARY_CANDIDATE_TIER_A_KNOCKOUT_PROVENANCE_EXPECTATION,
    expectedSetupIntegrity: {
      baselineCaseCount: 1,
      baselineCasePlanSha256,
      exitCode: 2,
      idSubstitution: { from, to },
      mutatedCaseCount: 1,
      mutatedCasePlanSha256,
      stableError: "ARM_CASE_PLAN_DIGEST_MISMATCH",
      terminalProtocol: "noa-boundary-arm-terminal/1",
      terminalStatus: "SETUP_FAILED",
    },
    suite: [".", "node", ["scripts/lint-boundary.mjs"]],
  };
  try {
    installPhase2RunnerFixture(fixture.source, "install setup-integrity runner closure");
    fs.writeFileSync(
      path.join(fixture.source, "control.mjs"),
      `export const caseId = ${JSON.stringify(from)};\n`,
      { mode: 0o600 },
    );
    fs.writeFileSync(
      path.join(fixture.source, "scripts", "lint-boundary.mjs"),
      [
        "import fs from 'node:fs';",
        "import { caseId } from '../control.mjs';",
        ...fixtureBoundaryGatePrelude(),
        `const baseline = ${JSON.stringify(from)};`,
        `const baselineDigest = ${JSON.stringify(baselineCasePlanSha256)};`,
        `const mutantDigest = ${JSON.stringify(mutatedCasePlanSha256)};`,
        "const mutated = caseId !== baseline;",
        "const terminal = {",
        "  casePlanSha256: mutated ? mutantDigest : baselineDigest,",
        "  duplicateCaseCount: 0, event: 'complete', failureCount: mutated ? 1 : 0,",
        "  missingCaseCount: 0, observedCaseCount: 1, plannedCaseCount: 1,",
        "  protocol: 'noa-boundary-arm-terminal/1', status: mutated ? 'SETUP_FAILED' : 'PASS',",
        "  unexpectedCaseCount: 0,",
        "};",
        "process.stderr.write(`NOA_BOUNDARY_ARM_TERMINAL ${JSON.stringify(terminal)}\\n`);",
        "const detail = JSON.stringify({",
        "  actualCasePlanSha256: mutantDigest, diagnosticExpectedCaseCount: 1,",
        "  diagnosticPlannedCaseCount: 1, duplicateCaseCount: 0, missingCaseIds: [],",
        "  reviewedCasePlanSha256: baselineDigest, unexpectedCaseCount: 0,",
        "});",
        "emitProvenanceBoundGateEvidence('fixture-setup-gate', mutated ? [{ rule: 'SELFTEST', subject: 'fixture setup plan', detail }] : [], {",
        "  ...provenance, subject: bootstrap.candidateSubject,",
        "  controlManifestDigest: crypto.createHash('sha256').update(fs.readFileSync('control.mjs')).digest('hex'),",
        "});",
        "process.exitCode = mutated ? 2 : 0;",
        "",
      ].join("\n"),
      { mode: 0o600 },
    );
    installFixtureKnockoutRegistry(fixture.source, [entry]);
    git(fixture.source, ["add", "--all"]);
    git(fixture.source, ["commit", "-q", "-m", "add isolated setup-integrity fixture"]);

    const candidateSubject = {
      archiveSha256: sha256File(path.join(fixture.source, "control.mjs")),
      commit: git(fixture.source, ["rev-parse", "HEAD"]).trim(),
      repository: "fixture/setup-integrity-candidate",
      tree: git(fixture.source, ["rev-parse", "HEAD^{tree}"]).trim(),
    };
    const statusBefore = git(fixture.source, ["status", "--porcelain=v1", "-z"]);
    const indexBefore = sha256File(path.join(fixture.source, ".git", "index"));
    const controlBefore = sha256File(path.join(fixture.source, "control.mjs"));
    const sweep = await knockoutRunner.runIsolatedKnockoutSweep({
      candidateSubject,
      captureTimeoutMs: workspace.KNOCKOUT_WORKSPACE_CAPTURE_TIMEOUT_LIMIT_MS,
      custodyRoot: fixture.custody,
      maxRetainedArms: 4,
      maxRetainedBytes: 768 * 1024 * 1024,
      rawDependenciesByEntry: new Map([[entry.id, {}]]),
      registry: [entry],
      root: fixture.source,
      selected: [entry],
      suiteTimeoutMs: 60_000,
      workerTimeoutMs: workspace.KNOCKOUT_WORKSPACE_ARM_WORKER_TIMEOUT_LIMIT_MS,
    });

    const result = sweep.results[0];
    const mutant = sweep.mutants[0];
    assert.ok(result !== undefined);
    assert.ok(mutant !== undefined);
    assert.equal(result.verdict, "DETECTOR_TRIGGERED");
    const evidence = result as unknown as {
      baselineGateProvenance: { subject: unknown };
      mutatedGateProvenance: { subject: unknown };
      postRestoreGateProvenance: { subject: unknown };
    };
    for (const observed of [
      evidence.baselineGateProvenance, evidence.mutatedGateProvenance, evidence.postRestoreGateProvenance,
    ]) assert.deepEqual(observed.subject, candidateSubject);
    assert.equal(result.restored, false);
    assert.equal(result.workspaceDisposition, "RETAINED_DISPOSABLE_MUTANT");
    assert.equal((result as { postRestoreBaselineVerified?: unknown }).postRestoreBaselineVerified, true);
    assert.equal(sweep.mutants.length, 1);
    const postchecks = (sweep as unknown as {
      postchecks: Array<{ entryId: string; workspaceRoot: string }>;
    }).postchecks;
    assert.equal(postchecks.length, 1);
    const postcheck = postchecks[0];
    assert.ok(postcheck !== undefined);
    assert.equal(postcheck.entryId, entry.id);
    assert.match(fs.readFileSync(path.join(mutant.workspaceRoot, "control.mjs"), "utf8"), new RegExp(to));
    assert.match(fs.readFileSync(path.join(postcheck.workspaceRoot, "control.mjs"), "utf8"), new RegExp(from));
    assert.equal(sha256File(path.join(fixture.source, "control.mjs")), controlBefore);
    assert.equal(sha256File(path.join(fixture.source, ".git", "index")), indexBefore);
    assert.equal(git(fixture.source, ["status", "--porcelain=v1", "-z"]), statusBefore);

    const terminals = regularFilesBelow(fixture.custody)
      .filter((file) => path.basename(file) === "arm-terminal.json")
      .map((file) => ({
        sha256: sha256File(file),
        terminal: JSON.parse(fs.readFileSync(file, "utf8")) as {
          predecessorTerminalSha256: string | null;
          role: string;
        },
      }));
    const orderedRoles = [];
    let next = terminals.find(({ terminal }) => terminal.predecessorTerminalSha256 === null);
    while (next !== undefined) {
      orderedRoles.push(next.terminal.role);
      const predecessor = next.sha256;
      next = terminals.find(({ terminal }) => terminal.predecessorTerminalSha256 === predecessor);
    }
    assert.deepEqual(orderedRoles, ["SELFTEST", "BASELINE", "MUTANT", "POSTCHECK"]);
  } finally {
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
  }
});

test("Phase 2 isolated selftest failure stops before every baseline and cannot produce a verdict", async () => {
  const fixture = minimalCaptureFixture("phase2-runner-selftest-failure");
  const entry = {
    id: "isolated-selftest-failure-control",
    control: "fixture control must never run after a failed framework selftest",
    file: "control.mjs",
    find: "export const controlEnabled = true;",
    replace: "export const controlEnabled = false;",
    kind: "gate",
    gateId: "fixture-never-runs",
    expectedGateFindings: [{ rule: "CONTROL_DISABLED", subject: "control" }],
    suite: [".", "node", ["fixture-never-runs.mjs"]],
  };
  try {
    installPhase2RunnerFixture(fixture.source, "install selftest-refusal runner closure");
    fs.writeFileSync(
      path.join(fixture.source, "scripts", "lint-control-knockout.selftest.mjs"),
      [
        "import { emitGateEvidence } from './lib/gate-event-contract.mjs';",
        "emitGateEvidence('knockout-selftest', [{ rule: 'SELFTEST', subject: 'fixture framework failure', detail: 'deliberate' }]);",
        "process.exitCode = 1;",
        "",
      ].join("\n"),
      { mode: 0o600 },
    );
    fs.writeFileSync(path.join(fixture.source, "control.mjs"), "export const controlEnabled = true;\n");
    fs.writeFileSync(
      path.join(fixture.source, "fixture-never-runs.mjs"),
      [
        "import fs from 'node:fs';",
        "import { emitGateEvidence } from './scripts/lib/gate-event-contract.mjs';",
        "fs.writeFileSync('baseline-ran.txt', 'unexpected');",
        "emitGateEvidence('fixture-never-runs', []);",
        "",
      ].join("\n"),
      { mode: 0o600 },
    );
    installFixtureKnockoutRegistry(fixture.source, [entry]);
    git(fixture.source, ["add", "--all"]);
    git(fixture.source, ["commit", "-q", "-m", "add failed selftest fixture"]);

    const statusBefore = git(fixture.source, ["status", "--porcelain=v1", "-z"]);
    const indexBefore = sha256File(path.join(fixture.source, ".git", "index"));
    await assert.rejects(
      () => knockoutRunner.runIsolatedKnockoutSweep({
        captureTimeoutMs: workspace.KNOCKOUT_WORKSPACE_CAPTURE_TIMEOUT_LIMIT_MS,
        custodyRoot: fixture.custody,
        maxRetainedArms: 3,
        maxRetainedBytes: 512 * 1024 * 1024,
        rawDependenciesByEntry: new Map([[entry.id, {}]]),
        registry: [entry],
        root: fixture.source,
        selected: [entry],
        suiteTimeoutMs: 60_000,
        workerTimeoutMs: workspace.KNOCKOUT_WORKSPACE_ARM_WORKER_TIMEOUT_LIMIT_MS,
      }),
      (error: WorkspaceError & { details?: { gateFindings?: unknown[] } }) =>
        error.code === "SELFTEST_FAILED" && error.details?.gateFindings?.length === 1,
    );
    assert.equal(fs.existsSync(path.join(fixture.source, "baseline-ran.txt")), false);
    assert.equal(
      regularFilesBelow(fixture.custody).some((file) => path.basename(file) === "baseline-ran.txt"),
      false,
    );
    assert.equal(sha256File(path.join(fixture.source, ".git", "index")), indexBefore);
    assert.equal(git(fixture.source, ["status", "--porcelain=v1", "-z"]), statusBefore);
    const terminals = regularFilesBelow(fixture.custody)
      .filter((file) => path.basename(file) === "arm-terminal.json")
      .map((file) => JSON.parse(fs.readFileSync(file, "utf8")) as { role: string; status: string });
    assert.equal(terminals.length, 1);
    const terminal = terminals[0];
    assert.ok(terminal !== undefined);
    assert.equal(terminal.role, "SELFTEST");
    assert.equal(terminal.status, "COMPLETE");
  } finally {
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
  }
});

test("Phase 2 isolated runner refuses a captured registry mismatch before suite execution and never falls back in place", async () => {
  const fixture = minimalCaptureFixture("phase2-runner-registry-mismatch");
  const capturedEntry = {
    id: "isolated-registry-bound-control",
    control: "captured registry control",
    file: "control.mjs",
    find: "export const controlEnabled = true;",
    replace: "export const controlEnabled = false;",
    kind: "gate",
    gateId: "fixture-gate",
    expectedGateFindings: [{ rule: "CONTROL_DISABLED", subject: "control" }],
    suite: [".", "node", ["fixture-gate.mjs"]],
  };
  const supervisorEntry = { ...capturedEntry, control: "supervisor substituted control" };
  try {
    installPhase2RunnerFixture(fixture.source, "install isolated mismatch runner closure");
    fs.writeFileSync(
      path.join(fixture.source, "control.mjs"),
      "export const controlEnabled = true;\n",
      { mode: 0o600 },
    );
    fs.writeFileSync(
      path.join(fixture.source, "fixture-gate.mjs"),
      [
        "import fs from 'node:fs';",
        "import { controlEnabled } from './control.mjs';",
        "fs.writeFileSync('suite-ran.txt', 'suite executed\\n');",
        "const findings = controlEnabled ? [] : [{ rule: 'CONTROL_DISABLED', subject: 'control', detail: 'disabled' }];",
        "console.log(JSON.stringify({ protocol: 'noa-gate-runner/1', event: 'complete', gate: 'fixture-gate', findings }));",
        "process.exitCode = findings.length === 0 ? 0 : 1;",
        "",
      ].join("\n"),
      { mode: 0o600 },
    );
    installFixtureKnockoutRegistry(fixture.source, [capturedEntry]);
    git(fixture.source, ["add", "--all"]);
    git(fixture.source, ["commit", "-q", "-m", "add captured registry mismatch fixture"]);

    const statusBefore = git(fixture.source, ["status", "--porcelain=v1", "-z"]);
    const indexBefore = sha256File(path.join(fixture.source, ".git", "index"));
    const controlBefore = sha256File(path.join(fixture.source, "control.mjs"));
    await assert.rejects(
      () => knockoutRunner.runIsolatedKnockoutSweep({
        captureTimeoutMs: workspace.KNOCKOUT_WORKSPACE_CAPTURE_TIMEOUT_LIMIT_MS,
        custodyRoot: fixture.custody,
        maxRetainedArms: 3,
        maxRetainedBytes: 512 * 1024 * 1024,
        rawDependenciesByEntry: new Map([[supervisorEntry.id, {}]]),
        registry: [supervisorEntry],
        root: fixture.source,
        selected: [supervisorEntry],
        suiteTimeoutMs: 60_000,
        workerTimeoutMs: workspace.KNOCKOUT_WORKSPACE_ARM_WORKER_TIMEOUT_LIMIT_MS,
      }),
      (error: WorkspaceError) => {
        assert.equal(error.code, "ARM_REFUSED", errorChain(error));
        return true;
      },
    );

    assert.equal(fs.existsSync(path.join(fixture.source, "suite-ran.txt")), false);
    assert.equal(
      regularFilesBelow(fixture.custody).some((file) => path.basename(file) === "suite-ran.txt"),
      false,
    );
    assert.equal(sha256File(path.join(fixture.source, "control.mjs")), controlBefore);
    assert.equal(sha256File(path.join(fixture.source, ".git", "index")), indexBefore);
    assert.equal(git(fixture.source, ["status", "--porcelain=v1", "-z"]), statusBefore);
    const terminalFiles = regularFilesBelow(fixture.custody)
      .filter((file) => path.basename(file) === "arm-terminal.json");
    assert.equal(terminalFiles.length, 2);
    const terminal = terminalFiles.map((file) => JSON.parse(fs.readFileSync(file, "utf8")) as {
      reasonCode: string;
      status: string;
    }).find((candidate) => candidate.status === "REFUSED");
    assert.equal(terminal?.status, "REFUSED");
    assert.equal(terminal?.reasonCode, "WORKER_REFUSED");
  } finally {
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
  }
});

const forgedCompleteWorkerSource = [
  "import { claimArmWorkerCapabilityFromFd, writeArmWorkerResultToFd } from './knockout-workspace.mjs';",
  "const capability = claimArmWorkerCapabilityFromFd();",
  "writeArmWorkerResultToFd(capability, {",
  "  observation: { operation: 'ATTEST_ARM', role: capability.role, workspaceBound: false },",
  "  status: 'COMPLETE',",
  "});",
].join("\n");

const malformedResultWorkerSource = [
  "import fs from 'node:fs';",
  "import { claimArmWorkerCapabilityFromFd } from './knockout-workspace.mjs';",
  "claimArmWorkerCapabilityFromFd();",
  "fs.writeSync(4, Buffer.from('{'));",
  "fs.closeSync(4);",
].join("\n");

const oversizedResultWorkerSource = [
  "import fs from 'node:fs';",
  "import { claimArmWorkerCapabilityFromFd } from './knockout-workspace.mjs';",
  "claimArmWorkerCapabilityFromFd();",
  "const bytes = Buffer.alloc(512 * 1024 + 1, 0x78);",
  "let offset = 0;",
  "while (offset < bytes.length) offset += fs.writeSync(4, bytes, offset, bytes.length - offset);",
  "fs.closeSync(4);",
].join("\n");

for (const scenario of [
  {
    accepted: true,
    complete: true,
    expectedEvidenceFiles: ["arm-terminal.json", "worker-result.bin"],
    expectedReason: "WORKER_REFUSED",
    expectedResultStatus: "REFUSED",
    expectedStatus: "REFUSED",
    id: "deterministic-refusal",
    operation: "UNSUPPORTED_TEST",
    rawResult: null,
    workerSource: null,
  },
  {
    accepted: false,
    complete: true,
    expectedEvidenceFiles: ["arm-terminal.json", "worker-result.bin"],
    expectedReason: "WORKER_RESULT_INVALID",
    expectedResultStatus: null,
    expectedStatus: "INDETERMINATE",
    id: "forged-complete",
    operation: "ATTEST_ARM",
    rawResult: null,
    workerSource: forgedCompleteWorkerSource,
  },
  {
    accepted: false,
    complete: true,
    expectedEvidenceFiles: ["arm-terminal.json", "worker-result.bin"],
    expectedReason: "WORKER_RESULT_INVALID",
    expectedResultStatus: null,
    expectedStatus: "INDETERMINATE",
    id: "malformed-result",
    operation: "ATTEST_ARM",
    rawResult: "{",
    workerSource: malformedResultWorkerSource,
  },
  {
    accepted: false,
    complete: false,
    expectedEvidenceFiles: ["arm-terminal.json"],
    expectedReason: "WORKER_RESULT_STREAM_FAILED",
    expectedResultStatus: null,
    expectedStatus: "INDETERMINATE",
    id: "oversized-result",
    operation: "ATTEST_ARM",
    rawResult: null,
    workerSource: oversizedResultWorkerSource,
  },
] as const) {
  test(`Phase 2 worker supervisor closes ${scenario.id} without upgrading its outcome`, async () => {
    const fixture = minimalCaptureFixture(`phase2-worker-${scenario.id}`);
    let captured: Capture | null = null;
    let cooperativeLease: CooperativeSourceLease | null = null;
    let plan: ArmPlan | null = null;
    let arm: DisposableArm | null = null;
    let terminal = false;
    let released: { retainedPrivateRoots: RetainedPrivateRoot[] } | null = null;
    try {
      const workerSha256 = installArmWorkerFixture(
        fixture.source,
        `install ${scenario.id} worker`,
        scenario.workerSource,
      );
      const subject = armWorkerSubject(workerSha256, scenario.operation);
      captured = workspace.captureAndSealCandidate({
        custodyRoot: fixture.custody,
        maxAttempts: 1,
        sourceRoot: fixture.source,
      });
      const sourceLease = workspace.acquireSourceLease(workspace.openKnockoutCustody(captured, {
        maxRetainedArms: 1,
        maxRetainedBytes: 64 * 1024 * 1024,
      }));
      cooperativeLease = await workspace.acquireCooperativeSourceLease(sourceLease);
      plan = workspace.admitArmPlan(cooperativeLease, {
        arms: [{
          armId: scenario.id,
          role: "SELFTEST",
          subjectSha256: armWorkerSubjectSha256(subject),
        }],
      });
      arm = workspace.materializeArm(plan, scenario.id);

      const result = await workspace.runArmWorker(cooperativeLease, arm, {
        subject,
        timeoutMs: 30_000,
      });
      terminal = true;
      const workerResult = result.terminalPublication.terminal.workerResult as {
        accepted: boolean;
        bytes: number;
        complete: boolean;
        publication: unknown;
        sha256: string | null;
        status: string | null;
      };
      assert.equal(result.status, scenario.expectedStatus);
      assert.equal(result.originalProcessGroupAbsent, true);
      assert.equal(result.terminalPublication.terminal.reasonCode, scenario.expectedReason);
      assert.equal(workerResult.accepted, scenario.accepted);
      assert.equal(workerResult.complete, scenario.complete);
      assert.equal(workerResult.status, scenario.expectedResultStatus);
      assert.deepEqual(fs.readdirSync(arm.evidenceRoot).sort(), scenario.expectedEvidenceFiles);
      if (scenario.complete) {
        assert.match(workerResult.sha256 ?? "", /^[0-9a-f]{64}$/);
        assert.notEqual(workerResult.publication, null);
      } else {
        assert.equal(workerResult.bytes > 512 * 1024, true);
        assert.equal(workerResult.sha256, null);
        assert.equal(workerResult.publication, null);
      }
      if (scenario.rawResult !== null) {
        assert.equal(
          fs.readFileSync(path.join(arm.evidenceRoot, "worker-result.bin"), "utf8"),
          scenario.rawResult,
        );
      }
      released = (await workspace.closeCooperativeSourceLease(cooperativeLease)).sourceRelease;
      cooperativeLease = null;
    } finally {
      if (cooperativeLease !== null) {
        if (!terminal && arm !== null) {
          try { workspace.cancelMaterializedArm(cooperativeLease, arm, "TEST_ABORT"); }
          catch {}
        } else if (plan !== null && arm === null) {
          try { workspace.cancelAdmittedArm(plan, scenario.id, "TEST_ABORT"); }
          catch {}
        }
        try { released = (await workspace.closeCooperativeSourceLease(cooperativeLease)).sourceRelease; }
        catch {}
      }
      cleanupReportedScratchRoots(released?.retainedPrivateRoots ?? captured?.retainedPrivateRoots ?? []);
      removeFixturePath(fixture.source);
      removeFixturePath(fixture.custody);
    }
  });
}

const stubbornProcessGroupWorkerSource = [
  "import { spawn } from 'node:child_process';",
  "import fs from 'node:fs';",
  "import { claimArmWorkerCapabilityFromFd, writeArmWorkerResultToFd } from './knockout-workspace.mjs';",
  "const capability = claimArmWorkerCapabilityFromFd();",
  "let secondClaimCode = 'NO_ERROR';",
  "try { claimArmWorkerCapabilityFromFd(); } catch (error) { secondClaimCode = error?.code ?? 'UNKNOWN'; }",
  "process.on('SIGTERM', () => {});",
  "const descendant = spawn(process.execPath, ['-e', \"process.on('SIGTERM',()=>{});setInterval(()=>{},1000)\"], {",
  "  detached: false,",
  "  stdio: 'ignore',",
  "});",
  "fs.writeFileSync('worker-processes.json', JSON.stringify({ descendantPid: descendant.pid, workerPid: process.pid }));",
  "fs.writeFileSync('second-claim-code.txt', secondClaimCode);",
  "writeArmWorkerResultToFd(capability, {",
  "  observation: { operation: 'ATTEST_ARM', role: capability.role, workspaceBound: true },",
  "  status: 'COMPLETE',",
  "});",
  "setInterval(() => {}, 1000);",
].join("\n");

test("Phase 2 worker timeout rejects active close and reaps a stubborn original process group", async () => {
  const fixture = minimalCaptureFixture("phase2-worker-timeout-group");
  let captured: Capture | null = null;
  let cooperativeLease: CooperativeSourceLease | null = null;
  let plan: ArmPlan | null = null;
  let arm: DisposableArm | null = null;
  let terminal = false;
  let workerPid: number | null = null;
  let descendantPid: number | null = null;
  let released: { retainedPrivateRoots: RetainedPrivateRoot[] } | null = null;
  try {
    const workerSha256 = installArmWorkerFixture(
      fixture.source,
      "install stubborn process-group worker",
      stubbornProcessGroupWorkerSource,
    );
    const subject = armWorkerSubject(workerSha256);
    captured = workspace.captureAndSealCandidate({
      custodyRoot: fixture.custody,
      maxAttempts: 1,
      sourceRoot: fixture.source,
    });
    const sourceLease = workspace.acquireSourceLease(workspace.openKnockoutCustody(captured, {
      maxRetainedArms: 1,
      maxRetainedBytes: 64 * 1024 * 1024,
    }));
    cooperativeLease = await workspace.acquireCooperativeSourceLease(sourceLease);
    plan = workspace.admitArmPlan(cooperativeLease, {
      arms: [{
        armId: "timeout-group",
        role: "SELFTEST",
        subjectSha256: armWorkerSubjectSha256(subject),
      }],
    });
    arm = workspace.materializeArm(plan, "timeout-group");

    const running = workspace.runArmWorker(cooperativeLease, arm, { subject, timeoutMs: 30_000 });
    await assert.rejects(
      () => workspace.closeCooperativeSourceLease(cooperativeLease!),
      (error: WorkspaceError) => error.code === workspaceErrorCode("CAPABILITY_INVALID"),
    );
    const result = await running;
    terminal = true;
    const processMarker = path.join(arm.workspaceRoot, "worker-processes.json");
    assert.equal(fs.existsSync(processMarker), true, "stubborn worker never published its PID marker");
    const processIds = JSON.parse(fs.readFileSync(processMarker, "utf8")) as {
      descendantPid: number;
      workerPid: number;
    };
    workerPid = processIds.workerPid;
    descendantPid = processIds.descendantPid;
    assert.equal(Number.isSafeInteger(workerPid) && workerPid > 1, true);
    assert.equal(Number.isSafeInteger(descendantPid) && descendantPid > 1, true);
    assert.equal(
      fs.readFileSync(path.join(arm.workspaceRoot, "second-claim-code.txt"), "utf8"),
      workspaceErrorCode("CAPABILITY_INVALID"),
      "a consumed FD3 transport was claimed twice",
    );

    const terminalRecord = result.terminalPublication.terminal as {
      lifecycle: {
        directChildClosed: boolean;
        originalProcessGroupAbsent: boolean;
        signal: string | null;
        timedOut: boolean;
      };
      reasonCode: string;
      workerResult: {
        accepted: boolean;
        publication: unknown;
        status: string | null;
      };
    };
    assert.equal(result.status, "INDETERMINATE");
    assert.equal(result.originalProcessGroupAbsent, true);
    assert.equal(terminalRecord.reasonCode, "WORKER_TIMEOUT");
    assert.equal(terminalRecord.lifecycle.directChildClosed, true);
    assert.equal(terminalRecord.lifecycle.originalProcessGroupAbsent, true);
    assert.equal(terminalRecord.lifecycle.signal, "SIGKILL");
    assert.equal(terminalRecord.lifecycle.timedOut, true);
    assert.equal(terminalRecord.workerResult.accepted, false);
    assert.equal(terminalRecord.workerResult.status, "COMPLETE");
    assert.notEqual(terminalRecord.workerResult.publication, null);

    const processExitDeadline = Date.now() + 2_000;
    let descendantAbsent = false;
    while (!descendantAbsent && Date.now() < processExitDeadline) {
      try { process.kill(descendantPid, 0); }
      catch (error) { descendantAbsent = (error as NodeJS.ErrnoException).code === "ESRCH"; }
      if (!descendantAbsent) await new Promise((resolve) => setTimeout(resolve, 25));
    }
    assert.equal(descendantAbsent, true, "stubborn same-group descendant remained alive after terminal");
    released = (await workspace.closeCooperativeSourceLease(cooperativeLease)).sourceRelease;
    cooperativeLease = null;
  } finally {
    if (!terminal && workerPid !== null && workerPid > 1) {
      try { process.kill(-workerPid, "SIGKILL"); }
      catch {}
    }
    if (!terminal && descendantPid !== null && descendantPid > 1) {
      try { process.kill(descendantPid, "SIGKILL"); }
      catch {}
    }
    if (cooperativeLease !== null) {
      if (!terminal && arm !== null) {
        try { workspace.cancelMaterializedArm(cooperativeLease, arm, "TEST_ABORT"); }
        catch {}
      } else if (plan !== null && arm === null) {
        try { workspace.cancelAdmittedArm(plan, "timeout-group", "TEST_ABORT"); }
        catch {}
      }
      try { released = (await workspace.closeCooperativeSourceLease(cooperativeLease)).sourceRelease; }
      catch {}
    }
    cleanupReportedScratchRoots(released?.retainedPrivateRoots ?? captured?.retainedPrivateRoots ?? []);
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
  }
});

test("Phase 2 cooperative close reopens every worker result and terminal before releasing authority", async () => {
  const fixture = minimalCaptureFixture("phase2-worker-terminal-tamper");
  const openDescriptor = Object.getOwnPropertyDescriptor(fs, "openSync");
  assert.ok(openDescriptor);
  const originalOpen = fs.openSync;
  let captured: Capture | null = null;
  let cooperativeLease: CooperativeSourceLease | null = null;
  let closeAttempted = false;
  let openPatched = false;
  let refusal: WorkspaceError | null = null;
  try {
    const workerSha256 = installArmWorkerFixture(fixture.source, "install terminal-tamper worker");
    const subject = armWorkerSubject(workerSha256);
    captured = workspace.captureAndSealCandidate({
      custodyRoot: fixture.custody,
      maxAttempts: 1,
      sourceRoot: fixture.source,
    });
    const sourceLease = workspace.acquireSourceLease(workspace.openKnockoutCustody(captured, {
      maxRetainedArms: 2,
      maxRetainedBytes: 128 * 1024 * 1024,
    }));
    cooperativeLease = await workspace.acquireCooperativeSourceLease(sourceLease);
    const plan = workspace.admitArmPlan(cooperativeLease, {
      arms: [
        { armId: "tamper-result", role: "SELFTEST", subjectSha256: armWorkerSubjectSha256(subject) },
        { armId: "tamper-terminal", role: "POSTCHECK", subjectSha256: armWorkerSubjectSha256(subject) },
      ],
    });
    const resultArm = workspace.materializeArm(plan, "tamper-result");
    const terminalArm = workspace.materializeArm(plan, "tamper-terminal");
    const first = await workspace.runArmWorker(cooperativeLease, resultArm, { subject, timeoutMs: 30_000 });
    const second = await workspace.runArmWorker(cooperativeLease, terminalArm, { subject, timeoutMs: 30_000 });
    assert.equal(first.status, "COMPLETE");
    assert.equal(second.status, "COMPLETE");
    assert.equal(
      second.terminalPublication.terminal.predecessorTerminalSha256,
      first.terminalPublication.sha256,
    );

    const tamperedResultPath = path.join(resultArm.evidenceRoot, "worker-result.bin");
    const tamperedTerminalPath = second.terminalPublication.path;
    for (const target of [tamperedResultPath, tamperedTerminalPath]) {
      const bytes = fs.readFileSync(target);
      assert.equal(bytes.length > 0, true);
      bytes[0] = (bytes[0] ?? 0) ^ 1;
      const fd = fs.openSync(target, fs.constants.O_WRONLY | fs.constants.O_NOFOLLOW);
      try {
        assert.equal(fs.writeSync(fd, bytes, 0, bytes.length, 0), bytes.length);
        fs.fsyncSync(fd);
      } finally {
        fs.closeSync(fd);
      }
    }
    const reopenedTargets = new Set<string>();
    Object.defineProperty(fs, "openSync", {
      ...openDescriptor,
      value: ((...args: Parameters<typeof fs.openSync>) => {
        if (typeof args[0] === "string") {
          const requested = path.resolve(args[0]);
          if (requested === tamperedResultPath || requested === tamperedTerminalPath) {
            reopenedTargets.add(requested);
          }
        }
        return Reflect.apply(originalOpen, fs, args) as number;
      }) as typeof fs.openSync,
    });
    openPatched = true;
    closeAttempted = true;
    await assert.rejects(
      () => workspace.closeCooperativeSourceLease(cooperativeLease!),
      (error: WorkspaceError) => {
        refusal = error;
        return errorTreeHasCode(error, workspaceErrorCode("TERMINAL_HASH_MISMATCH"));
      },
    );
    cooperativeLease = null;
    Object.defineProperty(fs, "openSync", openDescriptor);
    openPatched = false;
    assert.deepEqual([...reopenedTargets].sort(), [tamperedResultPath, tamperedTerminalPath].sort());
    assert.equal(fs.existsSync(tamperedResultPath), true, "close deleted tampered result evidence");
    assert.equal(fs.existsSync(tamperedTerminalPath), true, "close deleted tampered terminal evidence");
    assert.throws(
      () => workspace.releaseSourceLease(sourceLease),
      (error: WorkspaceError) => error.code === workspaceErrorCode("CAPABILITY_INVALID"),
    );
  } finally {
    if (openPatched) Object.defineProperty(fs, "openSync", openDescriptor);
    if (cooperativeLease !== null && !closeAttempted) {
      try { await workspace.closeCooperativeSourceLease(cooperativeLease); }
      catch {}
    }
    cleanupReportedScratchRoots(errorPrivateRoots(refusal));
    cleanupReportedScratchRoots(captured?.retainedPrivateRoots ?? []);
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
  }
});

test("Phase 2 cooperative source lease excludes an independent module instance and reaps before unlock", async () => {
  const fixture = minimalCaptureFixture("phase2-cooperative-lease");
  const moduleUrl = pathToFileURL(
    path.join(repositoryRoot, "scripts/lib/knockout-workspace.mjs"),
  );
  moduleUrl.searchParams.set("cooperative-instance", crypto.randomUUID());
  const independentWorkspace = await import(moduleUrl.href) as typeof workspace;
  let capturedA: Capture | null = null;
  let capturedB: Capture | null = null;
  let sourceLeaseA: SourceLease | null = null;
  let sourceLeaseB: SourceLease | null = null;
  let cooperativeA: CooperativeSourceLease | null = null;
  let cooperativeB: CooperativeSourceLease | null = null;
  let closedA = false;
  let closedB = false;
  try {
    capturedA = workspace.captureAndSealCandidate({
      custodyRoot: fixture.custody,
      maxAttempts: 1,
      sourceRoot: fixture.source,
    });
    capturedB = independentWorkspace.captureAndSealCandidate({
      custodyRoot: fixture.custody,
      maxAttempts: 1,
      sourceRoot: fixture.source,
    });
    sourceLeaseA = workspace.acquireSourceLease(workspace.openKnockoutCustody(capturedA, {
      maxRetainedArms: 1,
      maxRetainedBytes: 32 * 1024 * 1024,
    }));
    sourceLeaseB = independentWorkspace.acquireSourceLease(
      independentWorkspace.openKnockoutCustody(capturedB, {
        maxRetainedArms: 1,
        maxRetainedBytes: 32 * 1024 * 1024,
      }),
    );
    cooperativeA = await workspace.acquireCooperativeSourceLease(sourceLeaseA);
    assert.equal(cooperativeA.protocol, workspace.KNOCKOUT_WORKSPACE_PROTOCOLS.cooperativeSourceLease);
    assert.equal(
      cooperativeA.lockScope,
      "COOPERATING_LOCAL_PROCESSES_SAME_PHYSICAL_SOURCE_DIRECTORY",
    );
    assert.deepEqual(cooperativeA.contentionProbe, {
      expectedExitCode: 73,
      method: "INDEPENDENT_OPEN_DESCRIPTOR_NONBLOCKING_FLOCK",
      observedExitCode: 73,
      status: "CONTENTION_PROVEN",
    });
    assert.deepEqual(
      await workspace.confirmCooperativeSourceLease(cooperativeA),
      {
        lockScope: "COOPERATING_LOCAL_PROCESSES_SAME_PHYSICAL_SOURCE_DIRECTORY",
        sourceLeaseSha256: sourceLeaseA.sourceLeaseSha256,
        status: "HELD",
      },
    );
    await assert.rejects(
      () => workspace.confirmCooperativeSourceLease(
        Object.freeze({ ...cooperativeA! }) as CooperativeSourceLease,
      ),
      (error: WorkspaceError) => error.code === workspaceErrorCode("CAPABILITY_INVALID"),
    );
    assert.throws(
      () => workspace.releaseSourceLease(sourceLeaseA!),
      (error: WorkspaceError) => error.code === workspaceErrorCode("CAPABILITY_INVALID"),
    );
    await assert.rejects(
      () => independentWorkspace.acquireCooperativeSourceLease(sourceLeaseB!),
      (error: WorkspaceError) => error.code === workspaceErrorCode("SOURCE_LEASE_HELD"),
    );

    const firstRelease = await workspace.closeCooperativeSourceLease(cooperativeA);
    closedA = true;
    assert.equal(firstRelease.helperReaped, true);
    assert.equal(firstRelease.helperExitCode, 0);
    assert.equal(firstRelease.helperSignal, null);
    assert.equal(firstRelease.sourceRelease.status, "RELEASED");
    await assert.rejects(
      () => workspace.closeCooperativeSourceLease(cooperativeA!),
      (error: WorkspaceError) => error.code === workspaceErrorCode("CAPABILITY_INVALID"),
    );

    cooperativeB = await independentWorkspace.acquireCooperativeSourceLease(sourceLeaseB);
    assert.equal((await independentWorkspace.confirmCooperativeSourceLease(cooperativeB)).status, "HELD");
    const secondRelease = await independentWorkspace.closeCooperativeSourceLease(cooperativeB);
    closedB = true;
    assert.equal(secondRelease.helperReaped, true);
    assert.equal(secondRelease.helperExitCode, 0);
    assert.equal(secondRelease.helperSignal, null);
    assert.equal(secondRelease.sourceRelease.status, "RELEASED");
    assert.equal(fs.readFileSync(fixture.trackedPath, "utf8"), "stable source bytes\n");
  } finally {
    if (cooperativeA !== null && !closedA) {
      try { await workspace.closeCooperativeSourceLease(cooperativeA); }
      catch {}
    } else if (sourceLeaseA !== null && cooperativeA === null) {
      try { workspace.releaseSourceLease(sourceLeaseA); }
      catch {}
    }
    if (cooperativeB !== null && !closedB) {
      try { await independentWorkspace.closeCooperativeSourceLease(cooperativeB); }
      catch {}
    } else if (sourceLeaseB !== null && cooperativeB === null) {
      try { independentWorkspace.releaseSourceLease(sourceLeaseB); }
      catch {}
    }
    cleanupReportedScratchRoots(capturedA?.retainedPrivateRoots ?? []);
    cleanupReportedScratchRoots(capturedB?.retainedPrivateRoots ?? []);
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
  }
});

test("Phase 2 cooperative close atomically blocks new arm admission before its first await", async () => {
  const fixture = minimalCaptureFixture("phase2-cooperative-close-race");
  let captured: Capture | null = null;
  let cooperativeLease: CooperativeSourceLease | null = null;
  let released: SourceRelease | null = null;
  try {
    captured = workspace.captureAndSealCandidate({
      custodyRoot: fixture.custody,
      maxAttempts: 1,
      sourceRoot: fixture.source,
    });
    const sourceLease = workspace.acquireSourceLease(workspace.openKnockoutCustody(captured, {
      maxRetainedArms: 1,
      maxRetainedBytes: 32 * 1024 * 1024,
    }));
    cooperativeLease = await workspace.acquireCooperativeSourceLease(sourceLease);

    const closing = workspace.closeCooperativeSourceLease(cooperativeLease);
    let admission: ArmPlan | null = null;
    let admissionError: WorkspaceError | null = null;
    try {
      admission = workspace.admitArmPlan(cooperativeLease, {
        arms: [{ armId: "too-late", role: "SELFTEST", subjectSha256: "f".repeat(64) }],
      });
    } catch (error) {
      admissionError = error as WorkspaceError;
    }
    released = (await closing).sourceRelease;
    cooperativeLease = null;

    assert.equal(admission, null, "close admitted new authority while its liveness check was pending");
    assert.equal(admissionError?.code, workspaceErrorCode("CAPABILITY_INVALID"));
    assert.equal(released.status, "RELEASED");
  } finally {
    if (cooperativeLease !== null) {
      try { released = (await workspace.closeCooperativeSourceLease(cooperativeLease)).sourceRelease; }
      catch {}
    }
    cleanupReportedScratchRoots(released?.retainedPrivateRoots ?? captured?.retainedPrivateRoots ?? []);
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
  }
});

test("Phase 2 LOST lease permits explicit unused-arm cancellation before fail-closed reap", async () => {
  const fixture = minimalCaptureFixture("phase2-cooperative-lost-cancel");
  const spawnDescriptor = Object.getOwnPropertyDescriptor(childProcess, "spawn");
  assert.ok(spawnDescriptor);
  const originalSpawn = childProcess.spawn;
  let captured: Capture | null = null;
  let cooperativeLease: CooperativeSourceLease | null = null;
  let plan: ArmPlan | null = null;
  let arm: DisposableArm | null = null;
  let holder: ReturnType<typeof childProcess.spawn> | null = null;
  let spawnPatched = false;
  let closeAttempted = false;
  try {
    captured = workspace.captureAndSealCandidate({
      custodyRoot: fixture.custody,
      maxAttempts: 1,
      sourceRoot: fixture.source,
    });
    const sourceLease = workspace.acquireSourceLease(workspace.openKnockoutCustody(captured, {
      maxRetainedArms: 2,
      maxRetainedBytes: 64 * 1024 * 1024,
    }));
    Object.defineProperty(childProcess, "spawn", {
      ...spawnDescriptor,
      value: ((...args: Parameters<typeof childProcess.spawn>) => {
        const child = originalSpawn(...args);
        if (
          args[0] === "/usr/bin/perl" && Array.isArray(args[1]) &&
          typeof args[1][1] === "string" && args[1][1].includes("flock($source")
        ) holder = child;
        return child;
      }) as typeof childProcess.spawn,
    });
    syncBuiltinESMExports();
    spawnPatched = true;
    cooperativeLease = await workspace.acquireCooperativeSourceLease(sourceLease);
    Object.defineProperty(childProcess, "spawn", spawnDescriptor);
    syncBuiltinESMExports();
    spawnPatched = false;
    const observedHolder = holder as ReturnType<typeof childProcess.spawn> | null;
    assert.ok(observedHolder, "cooperative source-lease holder was not observed");

    plan = workspace.admitArmPlan(cooperativeLease, {
      arms: [
        { armId: "lost-materialized", role: "SELFTEST", subjectSha256: "1".repeat(64) },
        { armId: "lost-admitted", role: "PLANNING", subjectSha256: "2".repeat(64) },
      ],
    });
    arm = workspace.materializeArm(plan, "lost-materialized");
    const holderClosed = new Promise<void>((resolve) => observedHolder.once("close", () => resolve()));
    assert.equal(observedHolder.kill("SIGKILL"), true);
    await holderClosed;
    await assert.rejects(
      () => workspace.confirmCooperativeSourceLease(cooperativeLease!),
      (error: WorkspaceError) => error.code === workspaceErrorCode("SOURCE_LEASE_INDETERMINATE"),
    );

    assert.equal(
      workspace.cancelMaterializedArm(cooperativeLease, arm, "LEASE_LOST").status,
      "CANCELLED",
    );
    arm = null;
    assert.equal(workspace.cancelAdmittedArm(plan, "lost-admitted", "LEASE_LOST").status, "CANCELLED");
    plan = null;
    closeAttempted = true;
    await assert.rejects(
      () => workspace.closeCooperativeSourceLease(cooperativeLease!),
      (error: WorkspaceError) => error.code === workspaceErrorCode("SOURCE_LEASE_INDETERMINATE"),
    );
    await assert.rejects(
      () => workspace.confirmCooperativeSourceLease(cooperativeLease!),
      (error: WorkspaceError) => error.code === workspaceErrorCode("CAPABILITY_INVALID"),
    );
    assert.throws(
      () => workspace.releaseSourceLease(sourceLease),
      (error: WorkspaceError) => error.code === workspaceErrorCode("CAPABILITY_INVALID"),
    );
    cooperativeLease = null;
  } finally {
    if (spawnPatched) {
      Object.defineProperty(childProcess, "spawn", spawnDescriptor);
      syncBuiltinESMExports();
    }
    if (cooperativeLease !== null && !closeAttempted) {
      if (arm !== null) {
        try { workspace.cancelMaterializedArm(cooperativeLease, arm, "TEST_ABORT"); }
        catch {}
      }
      if (plan !== null) {
        try { workspace.cancelAdmittedArm(plan, "lost-admitted", "TEST_ABORT"); }
        catch {}
      }
      try { await workspace.closeCooperativeSourceLease(cooperativeLease); }
      catch {}
    }
    const remainingHolder = holder as ReturnType<typeof childProcess.spawn> | null;
    if (remainingHolder !== null && remainingHolder.exitCode === null && remainingHolder.signalCode === null) {
      try { remainingHolder.kill("SIGKILL"); }
      catch {}
    }
    cleanupReportedScratchRoots(captured?.retainedPrivateRoots ?? []);
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
  }
});

test("Phase 2 never registers a cooperative lease when its holder dies during the independent probe", async () => {
  const fixture = minimalCaptureFixture("phase2-cooperative-probe-race");
  const spawnDescriptor = Object.getOwnPropertyDescriptor(childProcess, "spawn");
  const spawnSyncDescriptor = Object.getOwnPropertyDescriptor(childProcess, "spawnSync");
  assert.ok(spawnDescriptor);
  assert.ok(spawnSyncDescriptor);
  const originalSpawn = childProcess.spawn;
  const originalSpawnSync = childProcess.spawnSync;
  let captured: Capture | null = null;
  let sourceLease: SourceLease | null = null;
  let holder: ReturnType<typeof childProcess.spawn> | null = null;
  let killedDuringProbe = false;
  try {
    captured = workspace.captureAndSealCandidate({
      custodyRoot: fixture.custody,
      maxAttempts: 1,
      sourceRoot: fixture.source,
    });
    sourceLease = workspace.acquireSourceLease(workspace.openKnockoutCustody(captured, {
      maxRetainedArms: 1,
      maxRetainedBytes: 32 * 1024 * 1024,
    }));
    Object.defineProperty(childProcess, "spawn", {
      ...spawnDescriptor,
      value: ((...args: Parameters<typeof childProcess.spawn>) => {
        const child = originalSpawn(...args);
        if (args[0] === "/usr/bin/perl") holder = child;
        return child;
      }) as typeof childProcess.spawn,
    });
    Object.defineProperty(childProcess, "spawnSync", {
      ...spawnSyncDescriptor,
      value: ((...args: Parameters<typeof childProcess.spawnSync>) => {
        const options = args[2] as { stdio?: unknown[] } | undefined;
        if (
          !killedDuringProbe && args[0] === "/usr/bin/perl" &&
          typeof args[1]?.[1] === "string" &&
          args[1][1].includes("flock($source, LOCK_EX | LOCK_NB)") &&
          Array.isArray(options?.stdio) && options.stdio[0] === "ignore"
        ) {
          assert.ok(holder, "cooperative holder was not spawned before its contention probe");
          killedDuringProbe = holder.kill("SIGKILL");
        }
        return originalSpawnSync(...args);
      }) as typeof childProcess.spawnSync,
    });
    syncBuiltinESMExports();
    await assert.rejects(
      () => workspace.acquireCooperativeSourceLease(sourceLease!, { handshakeTimeoutMs: 2_000 }),
      (error: WorkspaceError) =>
        error.code === workspaceErrorCode("SOURCE_LEASE_INDETERMINATE"),
    );
    assert.equal(killedDuringProbe, true, "the post-readiness helper-loss window was not reached");
    const released = workspace.releaseSourceLease(sourceLease);
    sourceLease = null;
    assert.equal(released.status, "RELEASED");
  } finally {
    Object.defineProperty(childProcess, "spawn", spawnDescriptor);
    Object.defineProperty(childProcess, "spawnSync", spawnSyncDescriptor);
    syncBuiltinESMExports();
    if (sourceLease !== null) {
      try { workspace.releaseSourceLease(sourceLease); }
      catch {}
    }
    cleanupReportedScratchRoots(captured?.retainedPrivateRoots ?? []);
    removeFixturePath(fixture.source);
    removeFixturePath(fixture.custody);
  }
});
