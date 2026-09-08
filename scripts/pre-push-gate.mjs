#!/usr/bin/env node
/**
 * NOA — the pre-push gate. Runs the mechanical gates BEFORE a push, so local and CI cannot disagree
 * silently.
 *
 * The committed hook makes the fast local checks deterministic and visible before bytes leave the
 * workstation. CI remains the authoritative merge gate; local success is never release authority.
 *
 * ⚠ WHAT THIS GATE DOES **NOT** DO, stated first so it is not mistaken for the whole answer:
 *
 *   • L12 measures the exact pushed refs before any override. The remaining correctness steps still
 *     measure the WORKING TREE. Every verdict line below prints `worktree: clean|DIRTY` for exactly
 *     this reason: their GREEN on a dirty tree does not describe the commits about to leave.
 *   • It runs the FAST subset. `lint:knockout` mutates source and re-runs many suites; it
 *     belongs in the daemon layer, not in a hook a human waits on.
 *   • It does not replace the complete knockout matrix. It catches the narrower class of pushing
 *     something that already fails a required fast gate.
 *
 * ─── THE FIVE DESIGN REFUSALS, each learned by getting it wrong first ─────────────────
 *
 *   1. Dependencies missing ⇒ SETUP_FAILED, never RED. A RED that measures your own broken install
 *      sends a human to the wrong place. SETUP_FAILED still blocks — "the check could not run" and
 *      "the check passed" must never share an exit code — but it prints the one command that fixes
 *      it, so it is a signpost rather than a wall.
 *   2. SKIPPED ≠ FAILED. Distinct verdicts, distinct exit meanings.
 *   3. A gate that always blocks gets switched off, and then there is no gate. This repository has a
 *      documented red baseline (`scripts/prepush-baseline.json`), so the gate blocks on NEW failures
 *      only — and DEMANDS the baseline be lowered the moment reality beats it.
 *   4. The immutable per-record evidence spool lives OUTSIDE the repository. Writing evidence
 *      inside would dirty the tree and invalidate the next run: the gate would corrupt its own
 *      measurement.
 *   5. No branch exemptions. The one bug that hid the last broken gate for weeks was a hook that
 *      exited early on the very branch it was tested on — testing a gate on the branch it skips is
 *      not testing it.
 *
 * ESCAPE HATCH, and it is recorded in the active spool when persistence succeeds:
 *                                      NOA_SKIP_PREPUSH="the reason" git push
 * ROLLBACK, one command:           git config --unset core.hooksPath
 *
 * ⚠ ONE STEP THE ESCAPE HATCH DOES NOT REACH, and the ordering in this file is the mechanism.
 * Step 0 is the L12 publish-boundary gate, and it runs ABOVE the NOA_SKIP_PREPUSH branch. Every
 * other step here protects correctness, which a later push repairs; that one protects
 * irreversibility, which nothing repairs. See the block comment at step 0 for the measurement.
 */

import { spawnSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { isAbsolute, join, relative, resolve, sep } from "node:path";
import { homedir, tmpdir } from "node:os";
import { createHash, randomBytes } from "node:crypto";
import {
  appendBoundaryLedgerRecord,
  BOUNDARY_EVIDENCE_RETENTION_NON_CLAIM,
  boundaryEvidenceSpoolDirectory,
  LEGACY_BOUNDARY_EVIDENCE_PROVENANCE,
} from "./lib/boundary-ledger.mjs";
import {
  BOUNDARY_AUTHORITY_CLASS_CANDIDATE_TIER_A,
  CANDIDATE_TIER_A_NON_AUTHORITY_NON_CLAIM,
} from "./lib/boundary-bootstrap.mjs";
import {
  parseGateEvidence,
  PROVENANCE_BOUND_GATE_EVENT_PROTOCOL,
  unverifiedGateProvenance,
} from "./lib/gate-event-contract.mjs";

/** Render untrusted diagnostic bytes only as bounded metadata. */
export function opaqueDiagnostic(value) {
  let text;
  try { text = typeof value === "string" ? value : String(value ?? ""); }
  catch { text = "[unrenderable diagnostic]"; }
  const bytes = Buffer.from(text, "utf8");
  return `diagnostic withheld (utf8Bytes=${bytes.length}, sha256=${createHash("sha256").update(bytes).digest("hex")})`;
}

const TIER_A_ARGV_SELFTEST_COMMAND = "--selftest-tier-a-argv";
const TIER_A_ARGV_SELFTEST_ROOT = "/noa-prepush-selftest-root";
const TIER_A_ARGV_SELFTEST_SCRATCH = "/noa-prepush-selftest-scratch";

// This checks only the frozen local command contract.  It deliberately takes
// synthetic paths so the targeted test can run before scratch/Git/bootstrap
// setup; the full selftest below calls the same assertion with its real paths.
function runTierAArgvSelftest({ root, scratchRoot }) {
  const commandArgs = buildBoundaryPrePushArgs({
    destination: "https://example.invalid/synthetic.git",
    remoteGitDir: join(scratchRoot, "synthetic-destination.git"),
    root,
    remote: "synthetic-origin",
  });
  const exactCommandArgs = Object.freeze([
    join(root, "scripts", "lint-boundary.mjs"),
    "--explain",
    "--knockout-json",
    "--tier", "a",
    "--lane", "L-PUSH,L-MSG,L-TAG",
    "--refs-from-stdin",
    "--pre-push-remote", "synthetic-origin",
    "--pre-push-remote-git-dir", join(scratchRoot, "synthetic-destination.git"),
    "--pre-push-url", "https://example.invalid/synthetic.git",
    "--repo-visibility-source", "snapshot",
    "--require-lane", "L-PUSH,L-MSG,L-TAG",
  ]);
  return Object.freeze({
    ok: JSON.stringify(commandArgs) === JSON.stringify(exactCommandArgs)
      && Object.isFrozen(commandArgs),
  });
}

// A Git pre-push hook always supplies two arguments.  Dispatching only this
// exact one-argument command prevents a real hook invocation from exiting via
// the portable selftest path.
if (process.argv.length === 3 && process.argv[2] === TIER_A_ARGV_SELFTEST_COMMAND) {
  const { ok } = runTierAArgvSelftest({
    root: TIER_A_ARGV_SELFTEST_ROOT,
    scratchRoot: TIER_A_ARGV_SELFTEST_SCRATCH,
  });
  console.error(`${ok ? "SELFTEST PASS" : "SELFTEST FAIL"}: boundary pre-push exact Tier-A argv`);
  process.exit(ok ? 0 : 1);
}

function createPrepushScratch() {
  try {
    const parent = realpathSync(tmpdir());
    const scratch = realpathSync(mkdtempSync(join(parent, "noa-prepush-child-")));
    return Object.freeze({ parent, scratch });
  } catch (error) {
    console.error(`SETUP_FAILED: pre-push scratch custody unavailable; ${opaqueDiagnostic(error?.message)}`);
    process.exit(1);
  }
}

const PREPUSH_PATHS = createPrepushScratch();
const PREPUSH_TEMP_ROOT = PREPUSH_PATHS.parent;
const PREPUSH_SCRATCH = PREPUSH_PATHS.scratch;
chmodSync(PREPUSH_SCRATCH, 0o700);
let scratchRemoved = false;
function cleanupPrepushScratch() {
  if (scratchRemoved) return;
  const resolved = resolve(PREPUSH_SCRATCH);
  const parent = PREPUSH_TEMP_ROOT;
  if (!isAbsolute(resolved) || !resolved.startsWith(`${parent}${sep}`)
      || !relative(parent, resolved).startsWith("noa-prepush-child-")) return;
  scratchRemoved = true;
  rmSync(resolved, { recursive: true, force: true });
}
process.once("exit", cleanupPrepushScratch);

/** Retain failed child output locally; console rendering remains opaque. */
function retainedFailureDiagnostic(value, parentDirectory = PREPUSH_TEMP_ROOT, writeDiagnostic = writeFileSync) {
  const withheld = opaqueDiagnostic(value);
  let directory;
  try {
    const parent = realpathSync(parentDirectory);
    for (const forbidden of [ROOT, PREPUSH_SCRATCH]) {
      if (parent === forbidden || parent.startsWith(`${forbidden}${sep}`)) {
        throw new Error("diagnostic parent must be outside repository and child scratch");
      }
    }
    directory = mkdtempSync(join(parent, "noa-prepush-diagnostic-"));
    chmodSync(directory, 0o700);
    const path = join(directory, "diagnostic.log");
    const bytes = Buffer.from(value, "utf8");
    writeDiagnostic(path, bytes, { flag: "wx", mode: 0o600 });
    return {
      directory,
      path,
      message: `${withheld}; retained locally at ${JSON.stringify(path)}`,
    };
  } catch (error) {
    // Preserve any partial bytes for diagnosis, but never report them as a complete retained output.
    const partialLocation = directory === undefined
      ? ""
      : `; incomplete diagnostic may remain in ${JSON.stringify(directory)}`;
    return {
      directory,
      message: `${withheld}; LOCAL_DIAGNOSTIC_RETENTION_FAILED; ${opaqueDiagnostic(error?.message)}${partialLocation}`,
    };
  }
}

export function buildPrepushChildEnvironment({ scratchRoot, source = process.env } = {}) {
  const root = resolve(String(scratchRoot ?? ""));
  if (!isAbsolute(root) || root.length < 8) throw new TypeError("prepush child scratch root must be absolute");
  const environment = {};
  for (const name of ["PATH", "LANG", "LC_ALL", "LC_CTYPE", "TERM", "TZ"]) {
    if (typeof source[name] === "string" && source[name].length > 0) environment[name] = source[name];
  }
  return Object.freeze({
    ...environment,
    HOME: root,
    TMP: join(root, "tmp"),
    TEMP: join(root, "tmp"),
    TMPDIR: join(root, "tmp"),
    XDG_CACHE_HOME: join(root, ".cache"),
    XDG_CONFIG_HOME: join(root, ".config"),
    XDG_DATA_HOME: join(root, ".local", "share"),
    XDG_STATE_HOME: join(root, ".local", "state"),
    GIT_CONFIG_GLOBAL: join(root, "gitconfig"),
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_NO_REPLACE_OBJECTS: "1",
    NPM_CONFIG_CACHE: join(root, ".npm-cache"),
    NPM_CONFIG_USERCONFIG: join(root, ".npmrc"),
    npm_config_cache: join(root, ".npm-cache"),
    npm_config_userconfig: join(root, ".npmrc"),
  });
}

const PREPUSH_CHILD_ENV = buildPrepushChildEnvironment({ scratchRoot: PREPUSH_SCRATCH });
// The selftest starts another gate process, which realpaths TMPDIR before it can initialize anything.
// Materialize the shared private temp root before any command receives the isolated environment.
mkdirSync(PREPUSH_CHILD_ENV.TMPDIR, { recursive: true, mode: 0o700 });
chmodSync(PREPUSH_CHILD_ENV.TMPDIR, 0o700);
function discoverRepositoryRoot() {
  const observed = spawnSync("git", ["rev-parse", "--show-toplevel"], {
    encoding: "utf8",
    env: PREPUSH_CHILD_ENV,
    maxBuffer: 1024 * 1024,
    shell: false,
    timeout: 30_000,
  });
  const value = String(observed.stdout ?? "").trim();
  if (observed.error !== undefined || observed.status !== 0 || !isAbsolute(value)
      || value.length === 0 || value.includes("\n") || value.includes("\r")) {
    const diagnostic = `${observed.error?.message ?? ""}\n${observed.stdout ?? ""}\n${observed.stderr ?? ""}`;
    console.error(`SETUP_FAILED: repository root unavailable; ${opaqueDiagnostic(diagnostic)}`);
    process.exit(1);
  }
  try { return realpathSync(value); }
  catch (error) {
    console.error(`SETUP_FAILED: repository root custody unavailable; ${opaqueDiagnostic(error?.message)}`);
    process.exit(1);
  }
}

const ROOT = discoverRepositoryRoot();
const BOUNDARY_DIRECTORY = join(homedir(), ".noa-boundary");
const EVIDENCE_SPOOL = boundaryEvidenceSpoolDirectory(BOUNDARY_DIRECTORY, "PREPUSH_GATE_VERDICT");

/** Verdicts. Only RED and SETUP_FAILED block; the distinction between them is WHERE to look. */
const GREEN = "GREEN", RED = "RED", SETUP_FAILED = "SETUP_FAILED", SKIPPED = "SKIPPED";

const bold = (s) => `[1m${s}[0m`;
const red = (s) => `[31m${s}[0m`;
const green = (s) => `[32m${s}[0m`;
const yellow = (s) => `[33m${s}[0m`;

// Keep the existing bounded capture budget; an overflow is incomplete evidence, never a full log.
const PREPUSH_CAPTURE_MAX_BUFFER_BYTES = 1024 * 1024;
function run(cmd, args, cwd) {
  const r = spawnSync(cmd, args, {
    cwd,
    encoding: "utf8",
    env: PREPUSH_CHILD_ENV,
    shell: false,
    maxBuffer: PREPUSH_CAPTURE_MAX_BUFFER_BYTES,
  });
  const captureComplete = r.error === undefined && r.signal === null;
  return {
    code: captureComplete ? r.status ?? 1 : 1,
    out: `${r.stdout ?? ""}${r.stderr ?? ""}`,
    captureComplete,
    captureProblem: captureComplete ? null
      : `error=${opaqueDiagnostic(r.error?.message)}; signal=${JSON.stringify(r.signal ?? null)}`,
  };
}

function retainedRunFailureDiagnostic(observed) {
  const retained = retainedFailureDiagnostic(observed.out);
  return {
    ...retained,
    message: observed.captureComplete === false
      ? `CAPTURE_INCOMPLETE (${observed.captureProblem}); ${retained.message}`
      : retained.message,
  };
}

/** node:test prints `# fail N` / `ℹ fail N` (and the same for `cancelled`). Parsed rather than
 *  inferred from the exit code, because the count is what the baseline ratchets against — an exit
 *  code cannot say "one fewer than before". */
function summaryCount(output, key) {
  const m = new RegExp(`^[ℹ#]\\s*${key}\\s+(\\d+)`, "m").exec(output);
  return m ? Number(m[1]) : null;
}

/**
 * Classify a baselined suite run. PURE, so `--selftest` can drive it with the exact outputs that
 * matter. Failure and cancellation counts are both required because an allowed failure may explain
 * a non-zero exit while cancelled tests still mean the suite did not complete.
 */
export function classifySuite(run, allowedFailures) {
  if (run.captureComplete === false) {
    return { verdict: SETUP_FAILED, detail: "child output capture was incomplete; retained bytes are partial evidence" };
  }
  const fails = summaryCount(run.out, "fail");
  const cancelled = summaryCount(run.out, "cancelled");

  if (fails === null || cancelled === null) {
    return { verdict: SETUP_FAILED, detail: "could not parse the suite's fail/cancelled summary" };
  }
  if (cancelled > 0) {
    return {
      verdict: RED,
      detail: `${cancelled} test(s) CANCELLED — tests not run are not tests passed. ` +
        `A cancellation takes every sibling after it down as \`cancelledByParent\`, and the summary ` +
        `still reads \`fail ${fails}\`.`,
    };
  }
  if (fails > allowedFailures) {
    return { verdict: RED, detail: `${fails} failing, baseline allows ${allowedFailures}` };
  }
  // `fails === 0` is load-bearing and I dropped it on the first attempt; the selftest caught it.
  // With `allowedFailures > 0` a non-zero exit is the EXPECTED state — the allowed failures explain
  // it — so `code !== 0` alone would refuse every push while the baseline is above zero, which is the
  // "gate that always blocks" this file spends a paragraph warning about. Only an exit code that
  // NOTHING in the summary accounts for is a finding.
  if (run.code !== 0 && fails === 0) {
    return {
      verdict: RED,
      detail: `exit ${run.code} that the summary cannot explain (fail 0, cancelled 0) — ` +
        `a crashed reporter or a post-suite failure. An unexplained non-zero exit is not a pass.`,
    };
  }
  return {
    verdict: GREEN,
    detail: fails < allowedFailures
      ? bold(yellow(`${fails} failing — BEATS the baseline of ${allowedFailures}. Lower it in this commit.`))
      : `${fails} failing, 0 cancelled`,
  };
}

/** Validate an escape-hatch reason without ever rendering or persisting its raw value. */
export function classifySkipReason(value) {
  if (value === undefined || value === null || value === "") {
    return { present: false, valid: true, evidence: null, digest: null, utf8Bytes: 0 };
  }
  const bytes = Buffer.byteLength(String(value), "utf8");
  const digest = createHash("sha256").update(String(value), "utf8").digest("hex");
  if (typeof value !== "string" || value.trim() !== value || bytes > 256 || /[\u0000-\u001f\u007f]/.test(value)) {
    return {
      present: true,
      valid: false,
      evidence: "reason rejected: must be one trimmed control-free line of at most 256 UTF-8 bytes",
      digest,
      utf8Bytes: bytes,
    };
  }
  return {
    present: true,
    valid: true,
    evidence: `reason accepted (utf8Bytes=${bytes}, sha256=${digest.slice(0, 12)})`,
    digest,
    utf8Bytes: bytes,
  };
}

export function buildBoundaryPrePushArgs({ destination, remoteGitDir, root, remote }) {
  return Object.freeze([
    join(root, "scripts", "lint-boundary.mjs"),
    "--explain",
    "--knockout-json",
    "--tier", "a",
    "--lane", "L-PUSH,L-MSG,L-TAG",
    "--refs-from-stdin",
    "--pre-push-remote", remote,
    "--pre-push-remote-git-dir", remoteGitDir,
    "--pre-push-url", destination,
    "--repo-visibility-source", "snapshot",
    "--require-lane", "L-PUSH,L-MSG,L-TAG",
  ]);
}

function gitConfigQuoted(value) {
  return `"${value.replace(/\\/g, "\\\\").replace(/"/g, "\\\"")}"`;
}

function validHookArgument(value, { remote = false } = {}) {
  return typeof value === "string" && value.length > 0 && value === value.trim()
    && Buffer.byteLength(value, "utf8") <= 8192
    && !/[\u0000-\u001f\u007f]/.test(value)
    && (!remote || !value.startsWith("-"));
}

function carriesUrlUserinfo(value) {
  return /^[A-Za-z][A-Za-z0-9+.-]*:\/\/[^/]*@/.test(String(value));
}

function sanitizePrepushDestination(url) {
  if (!validHookArgument(url)) throw new TypeError("pre-push destination is malformed");
  if (/^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(url)) {
    let parsed;
    try { parsed = new URL(url); } catch { throw new TypeError("pre-push destination URL is malformed"); }
    if (parsed.search !== "" || parsed.hash !== "") {
      throw new TypeError("pre-push destination URL query or fragment is not an identity coordinate");
    }
    parsed.username = "";
    parsed.password = "";
    const sanitized = parsed.toString();
    if (/^[A-Za-z][A-Za-z0-9+.-]*:\/\/[^/]*@/.test(sanitized)) {
      throw new TypeError("pre-push destination credentials could not be removed");
    }
    return sanitized;
  }
  return url;
}

export function preparePrepushDestination({ root, remote, scratchRoot, url }) {
  if (!validHookArgument(remote, { remote: true }) || !validHookArgument(url)) {
    throw new TypeError("pre-push remote argv are missing or malformed");
  }
  if (remote !== url && carriesUrlUserinfo(remote)) {
    throw new TypeError("credential-bearing remote selectors cannot be passed to Git child argv");
  }
  const sanitizedCoordinate = sanitizePrepushDestination(url);
  const environment = buildPrepushChildEnvironment({ scratchRoot });
  if (remote !== url) {
    const configured = spawnSync(
      "git",
      ["remote", "get-url", "--push", "--all", remote],
      { cwd: root, encoding: "utf8", env: environment, shell: false },
    );
    const urls = configured.status === 0
      ? String(configured.stdout ?? "").split(/\r?\n/).filter(Boolean)
      : [];
    if (configured.status !== 0 || !urls.includes(url)) {
      throw new TypeError("pre-push remote name and destination do not agree");
    }
  }
  const alias = `noa-prepush-${randomBytes(16).toString("hex")}`;
  const remoteGitDir = join(resolve(scratchRoot), "destination.git");
  mkdirSync(remoteGitDir, { mode: 0o700 });
  const initialized = spawnSync(
    "git",
    ["init", "--bare", "--quiet", remoteGitDir],
    { cwd: root, encoding: "utf8", env: environment, shell: false },
  );
  if (initialized.status !== 0) throw new TypeError("isolated pre-push Git directory initialization failed");
  const configPath = join(remoteGitDir, "config");
  const configBytes = `${readFileSync(configPath, "utf8")}\n`
    + `[remote ${gitConfigQuoted(alias)}]\n\turl = ${gitConfigQuoted(sanitizedCoordinate)}\n`;
  writeFileSync(configPath, configBytes, { flag: "w", mode: 0o600 });
  chmodSync(configPath, 0o600);
  const observed = spawnSync(
    "git",
    ["--git-dir", remoteGitDir, "remote", "get-url", "--push", "--all", alias],
    { cwd: root, encoding: "utf8", env: environment, shell: false },
  );
  const observedUrls = observed.status === 0
    ? String(observed.stdout ?? "").split(/\r?\n/).filter(Boolean)
    : [];
  if (observed.status !== 0 || observedUrls.length !== 1 || observedUrls[0] !== sanitizedCoordinate) {
    throw new TypeError("isolated pre-push destination binding could not be reread exactly");
  }
  return Object.freeze({ alias, environment, configPath, remoteGitDir, sanitizedCoordinate });
}

export function spawnIsolatedBoundaryProcess(args, {
  environment,
  input = "",
  root = ROOT,
} = {}) {
  return spawnSync(process.execPath, args, {
    cwd: root,
    encoding: "utf8",
    env: environment,
    input,
    maxBuffer: 256 * 1024 * 1024,
    shell: false,
    timeout: 300_000,
  });
}

export function classifyBoundaryGateRun(run) {
  const parsed = parseGateEvidence(run?.stdout ?? "", { requireProvenance: true, strictOutput: true });
  if (!parsed.protocolComplete || parsed.protocol !== PROVENANCE_BOUND_GATE_EVENT_PROTOCOL
      || parsed.gate !== "boundary" || run?.error !== undefined || !Number.isInteger(run?.status)) {
    return Object.freeze({
      accepted: false,
      detail: parsed.error ?? "boundary child status or protocol is malformed",
      provenance: unverifiedGateProvenance({ tier: "a", visibilitySource: "snapshot" }),
      verdict: SETUP_FAILED,
    });
  }
  const candidate = parsed.provenance.verification === "VERIFIED_BOOTSTRAP"
    && parsed.provenance.authorityClass === BOUNDARY_AUTHORITY_CLASS_CANDIDATE_TIER_A
    && parsed.provenance.authorityNonClaim === CANDIDATE_TIER_A_NON_AUTHORITY_NON_CLAIM
    && parsed.provenance.bootstrapMode === "candidate-tier-a-non-authority"
    && parsed.provenance.externalAuthorizationSha256 === null
    && parsed.provenance.tier === "a"
    && parsed.provenance.visibilitySource === "snapshot";
  if (run.status === 0 && candidate && parsed.findings.length === 0) {
    return Object.freeze({ accepted: true, detail: null, provenance: parsed.provenance, verdict: GREEN });
  }
  if (run.status === 1 && candidate && parsed.findings.length > 0
      && parsed.findings.every((finding) => finding.rule !== "SETUP_FAILED")) {
    return Object.freeze({ accepted: true, detail: null, provenance: parsed.provenance, verdict: RED });
  }
  if (run.status === 2 && parsed.findings.length === 1 && parsed.findings[0].rule === "SETUP_FAILED") {
    return Object.freeze({ accepted: true, detail: null, provenance: parsed.provenance, verdict: SETUP_FAILED });
  }
  return Object.freeze({
    accepted: false,
    detail: "boundary exit, findings, authority class, tier, visibility, or non-claim disagree",
    provenance: parsed.provenance,
    verdict: SETUP_FAILED,
  });
}

// ── SELFTEST ─────────────────────────────────────────────────────────────────────────────────────
// Drives the classifier with the discriminating terminal shapes. A gate whose own verdict logic is
// untested is a gate on trust.
if (process.argv.includes("--selftest")) {
  const CASES = [
    { name: "cancelled tests with a zero failure count", allowed: 0,
      run: { out: "# tests 132\n# pass 125\n# fail 0\n# cancelled 7\n", code: 1 }, want: RED },
    // The allowed failure explains the non-zero exit, leaving cancellation as the only blocking
    // signal. This makes the cancellation branch independently observable.
    { name: "cancellations HIDDEN behind an allowed failure", allowed: 1,
      run: { out: "# tests 20\n# pass 16\n# fail 1\n# cancelled 3\n", code: 1 }, want: RED },
    { name: "clean run", allowed: 0,
      run: { out: "# tests 134\n# pass 134\n# fail 0\n# cancelled 0\n", code: 0 }, want: GREEN },
    { name: "failures over the baseline", allowed: 1,
      run: { out: "# tests 10\n# pass 7\n# fail 3\n# cancelled 0\n", code: 1 }, want: RED },
    { name: "allowed failure, exit 1 expected", allowed: 2,
      run: { out: "# tests 10\n# pass 8\n# fail 2\n# cancelled 0\n", code: 1 }, want: GREEN },
    { name: "unexplained non-zero exit", allowed: 0,
      run: { out: "# tests 10\n# pass 10\n# fail 0\n# cancelled 0\n", code: 7 }, want: RED },
    { name: "unreadable summary", allowed: 0,
      run: { out: "the reporter crashed\n", code: 1 }, want: SETUP_FAILED },
  ];
  let bad = 0;
  const { ok: commandOk } = runTierAArgvSelftest({
    root: ROOT,
    scratchRoot: PREPUSH_SCRATCH,
  });
  if (!commandOk) bad++;
  console.error(`  ${commandOk ? green("✔") : red("✖")} ${"boundary pre-push exact Tier-A argv".padEnd(46)} closed builder contract`);

  const taintedSource = {
    ...process.env,
    HOME: "/Users/ambient-home-canary",
    XDG_CONFIG_HOME: "/Users/ambient-xdg-canary",
    GIT_CONFIG_GLOBAL: "/Users/ambient-git-canary",
    npm_config_userconfig: "/Users/ambient-npm-canary",
    NOA_BOUNDARY_AUTHORIZATION_FD: "9",
    NOA_BOUNDARY_AUTHORIZATION_FILE: "/Users/ambient-auth-canary",
    NOA_BOUNDARY_INTERNAL_BOOTSTRAP_MODE: "ambient-mode-canary",
    NOA_BOUNDARY_SYNTHETIC_SUPERVISOR_FIXTURE: "1",
    NODE_OPTIONS: "--require=/Users/ambient-loader-canary.cjs",
  };
  const isolatedEnvironment = buildPrepushChildEnvironment({
    scratchRoot: PREPUSH_SCRATCH,
    source: taintedSource,
  });
  const ambientNames = [
    "NOA_BOUNDARY_AUTHORIZATION_FD",
    "NOA_BOUNDARY_AUTHORIZATION_FILE",
    "NOA_BOUNDARY_INTERNAL_BOOTSTRAP_MODE",
    "NOA_BOUNDARY_SYNTHETIC_SUPERVISOR_FIXTURE",
    "NODE_OPTIONS",
  ];
  const pathNames = [
    "HOME", "TMP", "TEMP", "TMPDIR", "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME",
    "XDG_STATE_HOME", "GIT_CONFIG_GLOBAL", "NPM_CONFIG_CACHE", "NPM_CONFIG_USERCONFIG",
    "npm_config_cache", "npm_config_userconfig",
  ];
  const environmentOk = ambientNames.every((name) => isolatedEnvironment[name] === undefined)
    && isolatedEnvironment.GIT_NO_REPLACE_OBJECTS === "1"
    && existsSync(isolatedEnvironment.TMPDIR)
    && realpathSync(isolatedEnvironment.TMPDIR) === resolve(isolatedEnvironment.TMPDIR)
    && pathNames.every((name) => {
      const target = resolve(isolatedEnvironment[name]);
      return target === resolve(PREPUSH_SCRATCH) || target.startsWith(`${resolve(PREPUSH_SCRATCH)}${sep}`);
    })
    && !JSON.stringify(isolatedEnvironment).includes("ambient-");
  if (!environmentOk) bad++;
  console.error(`  ${environmentOk ? green("✔") : red("✖")} ${"isolated child environment".padEnd(46)} no ambient HOME/XDG/Git/npm/NOA/loader state`);

  const credentialUrl = "https://credential-canary:secret-canary@example.invalid/example/noa.git";
  let transportOk = false;
  try {
    let mismatchedCredentialRemoteRejected = false;
    try {
      preparePrepushDestination({
        root: ROOT,
        remote: credentialUrl,
        scratchRoot: PREPUSH_SCRATCH,
        url: "https://example.invalid/different.git",
      });
    } catch (error) {
      mismatchedCredentialRemoteRejected = /cannot be passed to Git child argv/.test(String(error?.message));
    }
    const destination = preparePrepushDestination({
      root: ROOT,
      remote: credentialUrl,
      scratchRoot: PREPUSH_SCRATCH,
      url: credentialUrl,
    });
    const transportedArgs = buildBoundaryPrePushArgs({
      destination: destination.sanitizedCoordinate,
      remoteGitDir: destination.remoteGitDir,
      root: ROOT,
      remote: destination.alias,
    });
    const probeSource = [
      'const { readFileSync } = require("node:fs");',
      'const { join } = require("node:path");',
      'const argvText = JSON.stringify(process.argv.slice(1));',
      'const envText = JSON.stringify(process.env);',
      'const at = process.argv.indexOf("--pre-push-remote-git-dir");',
      'const config = readFileSync(join(process.argv[at + 1], "config"), "utf8");',
      'process.stdout.write(JSON.stringify({',
      '  argvHasCredential: argvText.includes("secret-canary"),',
      '  envHasCredential: envText.includes("secret-canary"),',
      '  configHasCredential: config.includes("secret-canary"),',
      '  configHasSanitized: config.includes("https://example.invalid/example/noa.git"),',
      '  aliasPresent: argvText.includes("noa-prepush-")',
      '}));',
    ].join("\n");
    const probe = spawnIsolatedBoundaryProcess(
      ["--eval", probeSource, "--", ...transportedArgs],
      { environment: destination.environment, root: ROOT },
    );
    const observation = probe.status === 0 ? JSON.parse(String(probe.stdout ?? "")) : null;
    transportOk = observation?.argvHasCredential === false
      && observation?.envHasCredential === false
      && observation?.configHasCredential === false
      && observation?.configHasSanitized === true
      && observation?.aliasPresent === true
      && destination.sanitizedCoordinate === "https://example.invalid/example/noa.git"
      && mismatchedCredentialRemoteRejected
      && !JSON.stringify(transportedArgs).includes(credentialUrl)
      && !JSON.stringify(destination.environment).includes(credentialUrl);
  } catch { transportOk = false; }
  if (!transportOk) bad++;
  console.error(`  ${transportOk ? green("✔") : red("✖")} ${"credential-free child argv/env wrapper".padEnd(46)} opaque isolated Git config transport`);

  let actualWrapperOk = false;
  try {
    // This scratch intentionally is not re-canonicalized here. PREPUSH_SCRATCH is the production
    // parent handed to every wrapper child; on macOS a regression from /private/var back to the
    // /var alias must make the real custody check fail instead of being hidden by this self-test.
    const wrapperScratch = mkdtempSync(join(PREPUSH_SCRATCH, "actual-wrapper-"));
    chmodSync(wrapperScratch, 0o700);
    const localRemote = join(wrapperScratch, "remote.git");
    const cloned = spawnSync(
      "git",
      ["clone", "--bare", "--no-hardlinks", "--quiet", ROOT, localRemote],
      { cwd: wrapperScratch, encoding: "utf8", env: PREPUSH_CHILD_ENV, shell: false, timeout: 120_000 },
    );
    if (cloned.status !== 0) throw new TypeError("local bare wrapper fixture could not be cloned");
    const head = spawnSync("git", ["rev-parse", "HEAD"], {
      cwd: ROOT, encoding: "utf8", env: PREPUSH_CHILD_ENV, shell: false,
    });
    const remoteOid = String(head.stdout ?? "").trim();
    const remoteRef = "refs/heads/noa-prepush-wrapper-selftest";
    const installedRef = spawnSync("git", ["--git-dir", localRemote, "update-ref", remoteRef, remoteOid], {
      cwd: ROOT, encoding: "utf8", env: PREPUSH_CHILD_ENV, shell: false,
    });
    if (head.status !== 0 || installedRef.status !== 0 || !/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(remoteOid)) {
      throw new TypeError("local bare wrapper fixture identity is unavailable");
    }
    const destination = preparePrepushDestination({
      root: ROOT,
      remote: localRemote,
      scratchRoot: wrapperScratch,
      url: localRemote,
    });
    const actualEnvironment = buildPrepushChildEnvironment({
      scratchRoot: wrapperScratch,
      source: taintedSource,
    });
    const actual = spawnIsolatedBoundaryProcess(buildBoundaryPrePushArgs({
      destination: destination.sanitizedCoordinate,
      remoteGitDir: destination.remoteGitDir,
      root: ROOT,
      remote: destination.alias,
    }), {
      environment: actualEnvironment,
      input: `(delete) ${"0".repeat(remoteOid.length)} ${remoteRef} ${remoteOid}\n`,
      root: ROOT,
    });
    const classified = classifyBoundaryGateRun({
      error: actual.error,
      status: actual.status,
      stdout: actual.stdout,
    });
    actualWrapperOk = actual.status === 0
      && classified.accepted === true
      && classified.verdict === GREEN
      && classified.provenance.authorityClass === BOUNDARY_AUTHORITY_CLASS_CANDIDATE_TIER_A
      && classified.provenance.authorityNonClaim === CANDIDATE_TIER_A_NON_AUTHORITY_NON_CLAIM
      && classified.provenance.bootstrapMode === "candidate-tier-a-non-authority"
      && classified.provenance.externalAuthorizationSha256 === null
      && classified.provenance.tier === "a"
      && classified.provenance.visibilitySource === "snapshot"
      && realpathSync(destination.remoteGitDir) === destination.remoteGitDir
      && !JSON.stringify(actualEnvironment).includes("ambient-")
      && !existsSync(join(wrapperScratch, ".noa-boundary"));
  } catch { actualWrapperOk = false; }
  if (!actualWrapperOk) bad++;
  console.error(`  ${actualWrapperOk ? green("✔") : red("✖")} ${"actual isolated boundary child".padEnd(46)} local-only deletion, exact candidate provenance`);

  const candidateProvenance = {
    authorityClass: BOUNDARY_AUTHORITY_CLASS_CANDIDATE_TIER_A,
    authorityNonClaim: CANDIDATE_TIER_A_NON_AUTHORITY_NON_CLAIM,
    bootstrapMode: "candidate-tier-a-non-authority",
    controlManifestDigest: "1".repeat(64),
    controlManifestVersion: 2,
    externalAuthorizationSha256: null,
    schemaVersion: 1,
    subject: {
      archiveSha256: "2".repeat(64),
      commit: "3".repeat(40),
      repository: "example/public",
      tree: "4".repeat(40),
    },
    tier: "a",
    verification: "VERIFIED_BOOTSTRAP",
    visibilitySource: "snapshot",
  };
  const machine = (provenance, findings = []) => `${JSON.stringify({
    protocol: PROVENANCE_BOUND_GATE_EVENT_PROTOCOL,
    event: "complete",
    gate: "boundary",
    findings,
    provenance,
  })}\n`;
  const classifierCases = [
    {
      name: "candidate provenance green",
      run: { status: 0, stdout: machine(candidateProvenance) },
      accepted: true,
    },
    {
      name: "legacy v1 cannot satisfy provenance",
      run: { status: 0, stdout: `${JSON.stringify({ protocol: "noa-gate-runner/1", event: "complete", gate: "boundary", findings: [] })}\n` },
      accepted: false,
    },
    {
      name: "external class cannot masquerade as candidate",
      run: { status: 0, stdout: machine({ ...candidateProvenance, authorityClass: "EXTERNAL_SANITIZED_AUTHORIZATION_DEFENSE_IN_DEPTH_NON_AUTHORITY" }) },
      accepted: false,
    },
    {
      name: "candidate nonclaim mislabel refused",
      run: { status: 0, stdout: machine({ ...candidateProvenance, authorityNonClaim: "CANDIDATE_TIER_A_RESULT_IS_RELEASE_AUTHORITY" }) },
      accepted: false,
    },
    {
      name: "duplicate machine records refused",
      run: { status: 0, stdout: `${machine(candidateProvenance)}${machine(candidateProvenance)}` },
      accepted: false,
    },
    {
      name: "discarded stdout before machine record refused",
      run: { status: 0, stdout: `discarded authority text\n${machine(candidateProvenance)}` },
      accepted: false,
    },
    {
      name: "nonzero without finding refused",
      run: { status: 1, stdout: machine(candidateProvenance) },
      accepted: false,
    },
  ];
  for (const testCase of classifierCases) {
    const observed = classifyBoundaryGateRun(testCase.run);
    const ok = observed.accepted === testCase.accepted;
    if (!ok) bad++;
    console.error(`  ${ok ? green("✔") : red("✖")} ${testCase.name.padEnd(46)} accepted ${testCase.accepted}`);
  }
  for (const c of CASES) {
    const got = classifySuite(c.run, c.allowed).verdict;
    const ok = got === c.want;
    if (!ok) bad++;
    console.error(`  ${ok ? green("✔") : red("✖")} ${c.name.padEnd(46)} want ${c.want}, got ${got}`);
  }
  for (const c of [
    { name: "bounded skip reason", value: "documented emergency", valid: true },
    { name: "multiline skip reason", value: "first\nsecond", valid: false },
    { name: "overlong skip reason", value: "x".repeat(257), valid: false },
  ]) {
    const measured = classifySkipReason(c.value);
    const ok = measured.present && measured.valid === c.valid && !measured.evidence.includes(c.value)
      && /^[0-9a-f]{64}$/.test(measured.digest) && measured.utf8Bytes === Buffer.byteLength(c.value, "utf8");
    if (!ok) bad++;
    console.error(`  ${ok ? green("✔") : red("✖")} ${c.name.padEnd(46)} raw value not logged, valid ${c.valid}`);
  }
  const diagnosticCanary = "credential-canary diagnostic body";
  const withheldDiagnostic = opaqueDiagnostic(diagnosticCanary);
  const diagnosticOk = !withheldDiagnostic.includes(diagnosticCanary)
    && /utf8Bytes=\d+, sha256=[0-9a-f]{64}/.test(withheldDiagnostic);
  if (!diagnosticOk) bad++;
  console.error(`  ${diagnosticOk ? green("✔") : red("✖")} ${"opaque failure diagnostics".padEnd(46)} byte count and digest only`);
  const retainedDiagnostics = [];
  try {
    const outputCanary = `${diagnosticCanary}\n\u001b[31mUTF-8: \u00e9\u0000\n`;
    const first = retainedFailureDiagnostic(outputCanary);
    const second = retainedFailureDiagnostic("second diagnostic");
    retainedDiagnostics.push(first, second);
    const privateBytesOk = typeof first.path === "string" && typeof second.path === "string"
      && first.directory !== second.directory
      && readFileSync(first.path).equals(Buffer.from(outputCanary, "utf8"))
      && readFileSync(second.path, "utf8") === "second diagnostic"
      && (lstatSync(first.directory).mode & 0o777) === 0o700
      && (lstatSync(first.path).mode & 0o777) === 0o600
      && !first.message.includes(diagnosticCanary)
      && first.message.startsWith(opaqueDiagnostic(outputCanary));
    if (!privateBytesOk) bad++;
    console.error(`  ${privateBytesOk ? green("✔") : red("✖")} ${"private failure output retained without overwrite".padEnd(46)} exact UTF-8 bytes, owner-only modes, opaque console`);

    const failedRetention = retainedFailureDiagnostic(outputCanary, first.path);
    const failureOk = failedRetention.path === undefined
      && failedRetention.message.includes("LOCAL_DIAGNOSTIC_RETENTION_FAILED")
      && !failedRetention.message.includes(diagnosticCanary);
    if (!failureOk) bad++;
    console.error(`  ${failureOk ? green("✔") : red("✖")} ${"diagnostic write failure remains visible".padEnd(46)} raw diagnostic is not printed`);

    const partial = retainedFailureDiagnostic(outputCanary, PREPUSH_TEMP_ROOT, (path, bytes, options) => {
      writeFileSync(path, bytes.subarray(0, 7), options);
      throw new Error("synthetic write failure after partial output");
    });
    retainedDiagnostics.push(partial);
    const partialPath = join(partial.directory, "diagnostic.log");
    const partialOk = partial.path === undefined
      && partial.message.includes("LOCAL_DIAGNOSTIC_RETENTION_FAILED")
      && partial.message.includes(`incomplete diagnostic may remain in ${JSON.stringify(partial.directory)}`)
      && !partial.message.includes(diagnosticCanary)
      && readFileSync(partialPath).equals(Buffer.from(outputCanary, "utf8").subarray(0, 7))
      && (lstatSync(partial.directory).mode & 0o777) === 0o700
      && (lstatSync(partialPath).mode & 0o777) === 0o600;
    if (!partialOk) bad++;
    console.error(`  ${partialOk ? green("✔") : red("✖")} ${"partial failed write has explicit private custody".padEnd(46)} incomplete bytes preserved without a success claim`);

    const completeCapture = run(process.execPath, ["-e", "process.stdout.write('bounded failure'); process.exitCode = 1"], ROOT);
    const completeDiagnostic = retainedRunFailureDiagnostic(completeCapture);
    retainedDiagnostics.push(completeDiagnostic);
    const completeCaptureOk = completeCapture.captureComplete === true && completeCapture.code === 1
      && readFileSync(completeDiagnostic.path, "utf8") === "bounded failure"
      && !completeDiagnostic.message.includes("CAPTURE_INCOMPLETE");
    if (!completeCaptureOk) bad++;
    console.error(`  ${completeCaptureOk ? green("✔") : red("✖")} ${"complete failed child capture retains exact output".padEnd(46)} real child exit and bytes observed`);

    const overflowCapture = run(process.execPath, ["-e",
      "process.stdout.write('# fail 1\\n# cancelled 0\\n' + 'x'.repeat(2 * 1024 * 1024)); process.exitCode = 1"], ROOT);
    const overflowDiagnostic = retainedRunFailureDiagnostic(overflowCapture);
    retainedDiagnostics.push(overflowDiagnostic);
    const overflowOk = overflowCapture.captureComplete === false && overflowCapture.code !== 0
      && classifySuite(overflowCapture, 1).verdict === SETUP_FAILED
      && overflowDiagnostic.message.includes("CAPTURE_INCOMPLETE")
      && readFileSync(overflowDiagnostic.path).equals(Buffer.from(overflowCapture.out, "utf8"));
    if (!overflowOk) bad++;
    console.error(`  ${overflowOk ? green("✔") : red("✖")} ${"capture overflow cannot pass an allowed failure baseline".padEnd(46)} partial captured bytes are explicitly labelled`);

    const forbiddenParentsOk = [ROOT, PREPUSH_SCRATCH].every(parent => {
      const refused = retainedFailureDiagnostic(outputCanary, parent);
      return refused.path === undefined && refused.directory === undefined
        && refused.message.includes("LOCAL_DIAGNOSTIC_RETENTION_FAILED");
    });
    if (!forbiddenParentsOk) bad++;
    console.error(`  ${forbiddenParentsOk ? green("✔") : red("✖")} ${"repository and child scratch diagnostic parents refused".padEnd(46)} evidence remains outside measured source`);

    cleanupPrepushScratch();
    const survivesCleanup = !existsSync(PREPUSH_SCRATCH)
      && readFileSync(first.path).equals(Buffer.from(outputCanary, "utf8"));
    if (!survivesCleanup) bad++;
    console.error(`  ${survivesCleanup ? green("✔") : red("✖")} ${"failure output survives child scratch cleanup".padEnd(46)} retained bytes remain readable`);
  } catch (error) {
    bad++;
    console.error(`  ${red("✖")} diagnostic retention selftest ${opaqueDiagnostic(error?.message)}`);
  } finally {
    for (const retained of retainedDiagnostics) {
      if (retained.directory) rmSync(retained.directory, { recursive: true, force: true });
    }
  }
  console.error(bad === 0 ? green(bold("\n  SELFTEST PASS\n")) : red(bold(`\n  SELFTEST FAIL — ${bad} case(s)\n`)));
  process.exit(bad === 0 ? 0 : 1);
}

const hookArgs = process.argv.slice(2);
if (hookArgs.length !== 2 || !validHookArgument(hookArgs[0], { remote: true })
    || !validHookArgument(hookArgs[1])) {
  console.error(red(bold("\n  SETUP_FAILED — pre-push remote argv are missing or malformed.")));
  console.error("  Invoke this gate through the committed git pre-push hook; do not synthesize scope.\n");
  process.exit(1);
}
const [PRE_PUSH_REMOTE, PRE_PUSH_URL] = hookArgs;
let prepushDestination;
try {
  prepushDestination = preparePrepushDestination({
    root: ROOT,
    remote: PRE_PUSH_REMOTE,
    scratchRoot: PREPUSH_SCRATCH,
    url: PRE_PUSH_URL,
  });
} catch (error) {
  console.error(red(bold("\n  SETUP_FAILED — pre-push destination could not be bound in isolated custody.")));
  console.error(`  ${opaqueDiagnostic(error?.message)}\n`);
  process.exit(1);
}

console.error(bold("\n  NOA pre-push gate\n"));

const steps = [];
let boundaryEvidenceProvenance = unverifiedGateProvenance({ tier: "a", visibilitySource: "snapshot" });
function record(name, verdict, detail) {
  steps.push({ name, verdict, detail });
  const mark = verdict === GREEN ? green("✔") : verdict === SKIPPED ? yellow("○") : red("✖");
  console.error(`  ${mark} ${name.padEnd(34)} ${verdict}${detail ? `  ${detail}` : ""}`);
}

// ── 0. THE BOUNDARY GATE (L12) — DELIBERATELY ABOVE THE ESCAPE HATCH ─────────────────────────────
//
// Every other step in this file protects correctness, and a later push can repair a correctness
// mistake. This one protects irreversibility. Once bytes reach a public remote, later branch or file
// deletion does not guarantee that every other ref, cache, or object route stops serving them.
//
// So NOA_SKIP_PREPUSH does not reach this step, and the ordering is the mechanism rather than a
// comment asking nicely. What it is NOT: a `--no-verify` push skips every local hook there has ever
// been. CI on every branch is the record and the required check blocks the merge; after the bytes
// leave, a finding is an INCIDENT, not a gate. That is precisely why this runs first.
//
// This local hook intentionally uses the checked-in snapshot and labels it NON-CLAIM, so ordinary
// pushes remain usable without provider credentials. Trusted release/publish lanes use explicit
// `live` mode; this hook's green is never credited as current visibility evidence.
//
// The push refs arrive on stdin as `<localref> <localsha> <remoteref> <remotesha>`, which is what
// lets the boundary gate measure the EXACT commits, messages, tags and blobs about to leave —
// rather than the working tree, which is all the rest of this file can see.
{
  let refs = "";
  try { if (process.stdin.isTTY !== true) refs = readFileSync(0, "utf8"); } catch { refs = ""; }
  const args = buildBoundaryPrePushArgs({
    destination: prepushDestination.sanitizedCoordinate,
    remoteGitDir: prepushDestination.remoteGitDir,
    root: ROOT,
    remote: prepushDestination.alias,
  });
  const r = spawnIsolatedBoundaryProcess(args, {
    environment: prepushDestination.environment,
    input: refs,
    root: ROOT,
  });
  const classified = classifyBoundaryGateRun({
    error: r.error,
    status: r.status,
    stdout: r.stdout,
  });
  boundaryEvidenceProvenance = classified.provenance;
  const code = r.status ?? 2;
  if (!classified.accepted) {
    record("boundary L12", SETUP_FAILED, "provenance-bound machine evidence missing or malformed");
    console.error(`\n  boundary machine evidence refused; ${opaqueDiagnostic(classified.detail)}\n`);
    writeLedger(SETUP_FAILED, steps);
    process.exit(1);
  }
  if (code !== 0) {
    const verdict = classified.verdict;
    record("boundary L12", verdict, `exit ${code}`);
    console.error(`\n  boundary child ${opaqueDiagnostic(r.stderr)}\n`);
    console.error(red(bold("  This step has NO override. NOA_SKIP_PREPUSH does not reach it.")));
    console.error("  reproduce:  retry the same git push through scripts/hooks/pre-push\n");
    writeLedger(verdict, [{ name: "boundary L12", verdict, detail: `exit ${code}` }]);
    process.exit(1);
  }
  record(
    "boundary L12",
    GREEN,
    `exact push set scanned; authorityClass=${boundaryEvidenceProvenance.authorityClass}; `
      + `nonClaim=${boundaryEvidenceProvenance.authorityNonClaim}`,
  );
}

// ── 0b. escape hatch — reaches everything BELOW it, and nothing above ────────────────────────────
const skipReason = classifySkipReason(process.env["NOA_SKIP_PREPUSH"]);
if (skipReason.present && !skipReason.valid) {
  record("pre-push override", SETUP_FAILED, skipReason.evidence);
  console.error(red(bold("\n  Invalid NOA_SKIP_PREPUSH reason refused; raw text was not logged.\n")));
  writeLedger(SETUP_FAILED, steps, skipReason);
  process.exit(1);
}
if (skipReason.present) {
  console.error(yellow(`\n  pre-push gate BYPASSED — ${skipReason.evidence}; raw text not logged\n`));
  writeLedger("BYPASSED", [{ name: "bypass", verdict: SKIPPED, detail: skipReason.evidence }], skipReason);
  process.exit(0);
}

// ── 1. can the gate run at all? ──────────────────────────────────────────────────────────────────
const needed = [join(ROOT, "node_modules"), join(ROOT, "packages", "gate", "node_modules")];
const missing = needed.filter((p) => !existsSync(p));
if (missing.length > 0) {
  record("dependencies", SETUP_FAILED, missing.map((p) => p.replace(`${ROOT}/`, "")).join(" "));
  finish(SETUP_FAILED, "npm ci && (cd packages/gate && npm ci)");
}
record("dependencies", GREEN);

// ── 2. what is actually being measured ───────────────────────────────────────────────────────────
const dirty = run("git", ["status", "--porcelain"], ROOT).out.trim().length > 0;
record("worktree", GREEN, dirty ? yellow("DIRTY — this verdict describes the tree, not the pushed commits") : "clean");

// ── 3. the fast subset, in CI's own order ────────────────────────────────────────────────────────
for (const [name, cmd, args, cwd] of [
  // First and cheapest: validate both workflow structure and this gate's own verdict logic. A
  // structurally invalid workflow can prevent required jobs from being created at all, and an
  // untested verdict classifier can mislabel an incomplete run.
  ["gate selftest", "node", ["scripts/pre-push-gate.mjs", "--selftest"], ROOT],
  ["workflow files", "node", ["scripts/lint-workflows.mjs"], ROOT],
  ["kernel build", "npm", ["run", "build"], ROOT],
  // AFTER the build, so it inspects the artifacts a run would actually execute. Catches a compiled
  // test with no source — a file that runs locally, counts toward every local green, and that no
  // reviewer or diff can ever see. Two were sitting in this repo when it was written.
  ["test extent", "node", ["scripts/lint-test-extent.mjs"], ROOT],
  ["kernel tests", "npm", ["test"], ROOT],
  ["typecheck (all packages)", "npm", ["run", "typecheck:all"], ROOT],
  ["security gates L1-L7", "npm", ["run", "lint:security-gates"], ROOT],
  // ── ADDED AFTER CI CAUGHT WHAT THIS GATE DID NOT ────────────────────────────────────────────────
  // `test (20)` went red on `lint:dispatch-surfaces` and this gate had said GREEN, because it ran a
  // "fast subset" chosen by what I happened to think of rather than by what CI actually runs. These
  // four are all sub-second, they are in CI's `test` job, and their absence here reproduced the very
  // local-vs-CI divergence the gate exists to prevent.
  //
  // `lint:knockout` stays out deliberately: it creates isolated mutants and re-runs many suites, so
  // it belongs in the separately governed broad gate rather than a latency-sensitive local hook.
  ["dispatch surfaces", "npm", ["run", "lint:dispatch-surfaces"], ROOT],
  ["entry points", "npm", ["run", "check:entry-points"], ROOT],
  ["thrown-value boundary", "npm", ["run", "lint:thrown"], ROOT],
  ["trusted roots L9", "node", ["scripts/lint-trusted-roots.mjs"], ROOT],
  ["trusted roots L9 selftest", "node", ["scripts/lint-trusted-roots.mjs", "--selftest"], ROOT],
  // L11. The `lint:inert-containers` script is selftest-then-gate, for the reason the L8 evasion
  // matrix is ordered the same way: a defanged analyser's count of 0 must never be printed before
  // the proof that it still bites. Sub-second, and in CI's `test` job — the two properties this
  // list's own note above says an entry here needs.
  ["inert containers L11", "npm", ["run", "lint:inert-containers"], ROOT],
  ["gate build", "npm", ["run", "build"], join(ROOT, "packages", "gate")],
]) {
  const r = run(cmd, args, cwd);
  if (r.code !== 0) {
    record(name, RED, `exit ${r.code}`);
    console.error(`\n  failed command ${retainedRunFailureDiagnostic(r).message}\n`);
    finish(RED, `cd ${cwd.replace(`${ROOT}/`, "") || "."} && ${cmd} ${args.join(" ")}`);
  }
  record(name, GREEN);
}

// ── 4. the baselined suite — blocks on NEW failures, demands the ratchet when it beats the base ───
const baseline = JSON.parse(readFileSync(join(ROOT, "scripts", "prepush-baseline.json"), "utf8"));
const gateBase = baseline.suites["packages/gate"];
const gateRun = run("npm", ["test"], join(ROOT, "packages", "gate"));
const verdict = classifySuite(gateRun, gateBase.allowedFailures);

record("gate tests", verdict.verdict, verdict.detail);
if (verdict.verdict !== GREEN) {
  console.error(`\n  baselined suite ${retainedRunFailureDiagnostic(gateRun).message}\n`);
  finish(verdict.verdict, "cd packages/gate && npm test");
}

finish(GREEN, null);

// ── ────────────────────────────────────────────────────────────────────────────────────────────────
function writeLedger(verdict, entries, overrideReason = null) {
  printEvidenceProvenance();
  const head = run("git", ["rev-parse", "HEAD"], ROOT);
  const repositoryHead = head.code === 0 ? head.out.trim() : "";
  if (!/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(repositoryHead)) {
    console.error(yellow("NOA_EVIDENCE_WRITE_WARNING stream=PREPUSH code=HEAD_UNAVAILABLE evidence_not_persisted"));
    return;
  }
  const count = (wanted) => entries.filter((entry) => entry.verdict === wanted).length;
  const result = appendBoundaryLedgerRecord({
    spoolDirectoryPath: EVIDENCE_SPOOL,
    event: "PREPUSH_GATE_VERDICT",
    repositoryHead,
    verdict,
    provenance: boundaryEvidenceProvenance,
    metrics: {
      greenSteps: count(GREEN),
      overrideReasonSha256: overrideReason?.digest ?? null,
      overrideReasonUtf8Bytes: overrideReason?.utf8Bytes ?? 0,
      redSteps: count(RED),
      setupFailedSteps: count(SETUP_FAILED),
      skippedSteps: count(SKIPPED),
      stepCount: entries.length,
    },
  });
  if (result.warning !== null) console.error(yellow(result.warning));
}

function printEvidenceProvenance() {
  console.error("  evidence:   ~/.noa-boundary/evidence-spool/ (active provenance-bound schema-v3 immutable-record spool)");
  console.error(`  authority:  ${boundaryEvidenceProvenance.authorityClass}; ${boundaryEvidenceProvenance.authorityNonClaim}`);
  console.error(`  legacy:     ~/.noa-boundary/prepush-ledger.jsonl (${LEGACY_BOUNDARY_EVIDENCE_PROVENANCE}; not imported or mutated)`);
  console.error(`  retention:  ${BOUNDARY_EVIDENCE_RETENTION_NON_CLAIM}`);
}

function finish(verdict, howToReproduce) {
  writeLedger(verdict, steps);
  if (verdict === GREEN) {
    console.error(green(bold("\n  GREEN — pushing.\n")));
    process.exit(0);
  }
  console.error(red(bold(`\n  ${verdict} — push refused.`)));
  if (howToReproduce) console.error(`  reproduce:  ${howToReproduce}`);
  console.error(yellow(`  override:   NOA_SKIP_PREPUSH="why" git push    (recorded in the active spool when persistence succeeds)\n`));
  process.exit(1);
}
