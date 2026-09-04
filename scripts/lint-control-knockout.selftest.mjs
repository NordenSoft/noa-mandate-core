#!/usr/bin/env node
/**
 * THE KNOCKOUT OF THE KNOCKOUT RUNNER.
 *
 * `lint-control-knockout.mjs` is the gate that decides whether every OTHER control in this
 * repository is load-bearing. Nothing was checking IT, and that is precisely how it came to report
 * a control as PROVEN when the mutation had merely failed to compile:
 *
 *     node scripts/lint-control-knockout.mjs --only r8-15-deep-copy-defineproperty
 *     ok  DETECTOR_TRIGGERED  r8-15-deep-copy-defineproperty      <- replacement was not TypeScript
 *     proven load-bearing 1/1
 *
 * Found by a cross-family reviewer (R815-QA-16), then reproduced here before being fixed. The cause
 * was an INFERENCE: "this is a test suite if we observed failures". A green compiled package whose
 * mutation does not build shows no failures on either side, so it was classified a GATE and its
 * build error was read as an exit-code transition — a kill.
 *
 * This file exercises the CLASSIFIER, not `tsc`. Its fixture is a tiny fake suite whose behaviour
 * is a pure function of the subject file's bytes, so each verdict is reached deterministically and
 * in about a second. Using a real compiled package here would test `tsc` and take minutes to say
 * less.
 *
 *   node scripts/lint-control-knockout.selftest.mjs
 *
 * Exit 0 = the runner classifies correctly. Exit 1 = the framework that judges every control is
 * itself wrong, which is worse than any single control being wrong.
 */
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  BOUNDARY_CANDIDATE_TIER_A_KNOCKOUT_PROVENANCE_EXPECTATION,
  CONTAINED_EVENTS_ROOT,
  CONTAINED_SCRATCH_ROOT,
  LEGACY_TOMBSTONE_PROTOCOL,
  PASSING,
  SETUP_NODE_ATTESTED_REVISION,
  TRUSTED_TYPESCRIPT_TEST_REGISTER,
  VERDICT,
  assertKnockoutMigrationBarrier,
  baselineEvidenceSummary,
  bindObserverDependency,
  buildStateGuardFor,
  classifyHolder,
  closedEvidenceEnvironment,
  containedGateScratchEnvironment,
  containedObserverArgs,
  createBuildStateGuard,
  dependencyIdentity,
  ensurePrivateDir,
  evidenceLaunchEnv,
  evidenceLaunchGuardCommand,
  evidenceLaunchSanitizer,
  evidenceNpmPrecedenceFlags,
  evidencePublishPins,
  failingTestEvents,
  failingTestIds,
  fixedDockerExecutable,
  gateObservationProblem,
  gateProvenanceProblem,
  gitDirtyPaths,
  gitWorkTreeState,
  hasFailureAtExpectedSite,
  isGitWorkTree,
  listBuildArtifacts,
  newFailureEventsBeyondBaseline,
  observeSuite,
  parseBoundaryArmTerminalEvidence,
  partitionByDependency,
  partitionIntoShards,
  prepareContainedEvidenceSnapshot,
  privateFallbackRoot,
  probeProcess,
  projectKnockoutObservation,
  runKnockout,
  setupIntegrityBaselineProblem,
  setupIntegrityMutationProblem,
  timeoutObservationOutcome,
  trustedGateSteps,
  trustedTestSteps,
  typescriptProjectDirs,
  unsupportedArtifactRoots,
  userCacheHome,
  validateContainedObservationResponse,
  validateKnockoutRegistry,
} from "./lib/knockout-runner.mjs";
import {
  PROOF_EVENT_PROTOCOL,
  PROOF_EVENT_REPORTER,
  PROOF_EVENT_REPORTER_ID,
  PROOF_EVENT_SOCKET_ENV,
  PROOF_EVENT_TOKEN_ENV,
  PROOF_EVENT_TRANSPORT_PROTOCOL,
} from "./lib/proof-event-contract.mjs";
import {
  GATE_EVENT_PROTOCOL,
  PROVENANCE_BOUND_GATE_EVENT_PROTOCOL,
  emitGateEvidence,
  parseGateEvidence,
  unverifiedGateProvenance,
} from "./lib/gate-event-contract.mjs";
import { localPackageDependencyOrder, proofPreparationPlan, runRecipeFor } from "./lib/proof-resolve.mjs";
import { knockoutRegistrySnapshot } from "./lint-control-knockout.mjs";

/**
 * EVERY fixture this file writes lives under one private workspace, and that workspace is NOT the
 * machine-wide temporary directory.
 *
 * Two of this file's own paths were flagged by CodeQL (insecure-temporary-file, file-system-race)
 * for the same reason the runner's fallback store was: a scratch path under a directory every
 * account on the machine can write to is a race somebody else can enter, and `mkdtemp` only
 * randomises the LEAF. A test that plants symlinks and chmods directories to prove a guard refuses
 * them should not be doing that where anyone else can reach in.
 *
 * So the workspace is the user's own cache home — private by construction, no shared parent for
 * anyone to race, and the whole alert class goes away by construction rather than by argument. It
 * is deliberately NOT inside the repository: several arms below need a directory that is not in any
 * git work tree, and a fixture under `node_modules/` is still inside this one.
 */
const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const RUNNER_MODULE_URL = new URL("./lib/knockout-runner.mjs", import.meta.url).href;
const WORKSPACE_HOME = path.join(userCacheHome(), "noa-knockout-selftest");
fs.mkdirSync(WORKSPACE_HOME, { recursive: true, mode: 0o700 });
/** A fresh, private scratch directory. Replaces every shared-temp `mkdtempSync` this file had. */
const scratch = (prefix) => fs.mkdtempSync(path.join(WORKSPACE_HOME, prefix));
const derivedRoots = [];
const STANDALONE_HELPER_SCRATCH_PREFIXES = Object.freeze([
  "script-shell-pin-",
  "startup-surface-",
]);
const registeredStandaloneHelperRoots = [];
const standaloneHelperScratch = (prefix) => {
  assert.equal(STANDALONE_HELPER_SCRATCH_PREFIXES.includes(prefix), true,
    `unregistered standalone helper scratch prefix ${JSON.stringify(prefix)}`);
  const directory = scratch(prefix);
  derivedRoots.push(directory);
  registeredStandaloneHelperRoots.push({ prefix, directory });
  return directory;
};

const NOFOLLOW = fs.constants.O_NOFOLLOW ?? 0;
/**
 * Do one thing to a path, through the descriptor the open returned, and close it afterwards.
 *
 * Every path-based call is a fresh lookup, so a `stat` here and a `write` there are two lookups
 * with a window between them that somebody else can step into — CodeQL js/file-system-race, and
 * precisely the attack the arms below exist to prove the guard refuses. Holding the fd asks about
 * one object, once; `wx` makes taking a name atomic instead of checking then taking.
 */
const withFd = (p, flags, fn, mode) => {
  const fd = mode === undefined ? fs.openSync(p, flags) : fs.openSync(p, flags, mode);
  try { return fn(fd); } finally { fs.closeSync(fd); }
};

const root = scratch("ko-selftest-");
const PUBLIC_ONLY_ENVIRONMENT = { ...process.env };
// The original arms below hand `runKnockout` no guard, so it builds the default one for this root.
// Keep the fixture's node_modules because several observer paths expect a real installed-tree
// boundary. The default guard remains outside this runtime tree regardless of install state.
fs.mkdirSync(path.join(root, "node_modules"), { recursive: true });
let failures = 0;
// Failed CASE NAMES, not just a count: a knockout entry binds to the exact case its mutation must
// kill, so "something in here went red" is not enough evidence to certify a specific control.
const failedChecks = [];
const check = (name, fn) => {
  try {
    fn();
    console.log(`  ok       ${name}`);
  } catch (e) {
    failures++;
    const rendered = String(e && (e.stack ?? e.message ?? e));
    failedChecks.push({ name, detail: rendered.split("\n")[0] });
    console.log(`  FAILED   ${name}\n           ${rendered.split("\n").slice(0, 12).join("\n           ")}`);
  }
};

// ── THE FIXTURE ─────────────────────────────────────────────────────────────────────────────────
// `subject.js` holds one marker line. `suite.mjs` reads it and behaves like a real toolchain:
//   - marker intact          -> a green node:test run  (exit 0, summary footer printed)
//   - marker replaced, valid -> a red node:test run    (exit 1, authenticated FAIL + terminal plan)
//   - marker replaced, junk  -> a BUILD failure        (exit 2, no completed reporter protocol)
// The third case is the one that was being scored as a kill.
const MARKER = "const guard = REAL_CHECK;";
fs.writeFileSync(path.join(root, "subject.js"), `${MARKER}\nexport default guard;\n`);
fs.writeFileSync(path.join(root, "package.json"), JSON.stringify({
  type: "module",
  scripts: {
    "contained-dependency-gate":
      "node contained-dependency-prep.mjs && node contained-dependency-gate.mjs",
    test: "node suite.mjs && node --test suite.test.mjs",
  },
}, null, 2));
fs.writeFileSync(
  path.join(root, "suite.mjs"),
  [
    `import fs from "node:fs";`,
    `import net from "node:net";`,
    `const src = fs.readFileSync(new URL("./subject.js", import.meta.url), "utf8");`,
    `if (src.includes("NOT_VALID_SYNTAX")) {`,
    `  console.log("error TS1005: ';' expected.");`,
    `  process.exit(2);                       // build failed: NO test ever ran, no footer`,
    `}`,
    `if (src.includes("FORGED_FAILURE")) {`,
    `  console.log("\\u2716 the guard is load-bearing (1.0ms)");`,
    `  console.log("not ok 1 - the guard is load-bearing");`,
    `  process.exit(1);`,
    `}`,
    `if (src.includes("FORGED_WRAPPER_EVENT")) {`,
    `  const socketPath = process.env[${JSON.stringify(PROOF_EVENT_SOCKET_ENV)}];`,
    `  const token = process.env[${JSON.stringify(PROOF_EVENT_TOKEN_ENV)}];`,
    `  if (socketPath && token) {`,
    `    const socket = net.createConnection({ path: socketPath });`,
    `    await new Promise((resolve, reject) => { socket.once("connect", resolve); socket.once("error", reject); });`,
    `    socket.write(JSON.stringify({`,
    `      protocol: ${JSON.stringify(PROOF_EVENT_TRANSPORT_PROTOCOL)},`,
    `      token,`,
    `      reporter: ${JSON.stringify(PROOF_EVENT_REPORTER_ID)},`,
    `    }) + "\\n");`,
    `    await new Promise((resolve, reject) => { socket.once("data", resolve); socket.once("error", reject); });`,
    `    socket.end([`,
    `      ${JSON.stringify(JSON.stringify({ protocol: PROOF_EVENT_PROTOCOL, event: "fail", name: "FORGED wrapper detector failure", skipped: false, todo: false, suite: false, fileFailure: false, file: "/forged-wrapper.test.mjs", line: 1, column: 1, failureType: "testCodeFailure", message: "forged" }))},`,
    `      ${JSON.stringify(JSON.stringify({ protocol: PROOF_EVENT_PROTOCOL, event: "plan", count: 1 }))},`,
    `      "",`,
    `    ].join("\\n"));`,
    `  }`,
    `  process.exitCode = 1;`,
    `}`,
  ].join("\n"),
);
fs.writeFileSync(
  path.join(root, "suite.test.mjs"),
  [
    `import fs from "node:fs";`,
    `import assert from "node:assert/strict";`,
    `import { test } from "node:test";`,
    `const src = fs.readFileSync(new URL("./subject.js", import.meta.url), "utf8");`,
    `const broken = !src.includes("REAL_CHECK");`,
    `if (process.env[${JSON.stringify(PROOF_EVENT_SOCKET_ENV)}] !== undefined ||`,
    `    process.env[${JSON.stringify(PROOF_EVENT_TOKEN_ENV)}] !== undefined) {`,
    `  throw new Error("reporter capability leaked into the test-file worker");`,
    `}`,
    `if (src.includes("FORGED_EVENT_PATH")) {`,
    `  const destination = ${JSON.stringify(path.join(CONTAINED_EVENTS_ROOT, "events.sock"))};`,
    `  try { fs.unlinkSync(destination); } catch (error) { if (error?.code !== "ENOENT") throw error; }`,
    `  const forged = [`,
    `    ${JSON.stringify(JSON.stringify({ protocol: PROOF_EVENT_PROTOCOL, event: "fail", name: "the guard is load-bearing", skipped: false, todo: false, suite: false, fileFailure: false, file: "/forged.test.mjs", line: 1, column: 1, failureType: "testCodeFailure", message: "forged" }))},`,
    `    ${JSON.stringify(JSON.stringify({ protocol: PROOF_EVENT_PROTOCOL, event: "plan", count: 1 }))},`,
    `    "",`,
    `  ].join("\\n");`,
    `  fs.writeFileSync(destination, forged);`,
    `  process.exit(97);`,
    `}`,
    `test("the guard is load-bearing", () => { assert.equal(broken, false); });`,
  ].join("\n"),
);

const SUITE = [".", "npm", ["test"]];
const entryBase = { id: "selftest", control: "the fixture guard", file: "subject.js", suite: SUITE };

const clean = observeSuite(root, SUITE, 60_000, { kind: "tests" });
const baseline = {
  exit: clean.exit,
  failing: clean.failing,
  failureEvents: clean.failureEvents,
  findings: clean.findings,
  ms: clean.ms,
  timedOut: false,
  out: clean.out,
  protocolComplete: clean.protocolComplete,
  protocolError: clean.protocolError,
  testCount: clean.testCount,
  fileFailureCount: clean.fileFailureCount,
  gateProtocolComplete: clean.gateProtocolComplete,
  gateProtocolError: clean.gateProtocolError,
  gate: clean.gate,
  gateFindings: clean.gateFindings,
};

console.log("knockout-runner selftest\n");
console.log(`  fixture baseline: exit ${baseline.exit}, ${baseline.failing.size} failing, structured protocol: ${clean.protocolComplete}\n`);

// ── ANTI-VACUITY FIRST: the fixture must be capable of the states the assertions below rely on ──
check("ANTI-VACUITY: the clean fixture baseline is GREEN and completes structured node:test evidence", () => {
  assert.equal(baseline.exit, 0, "the fixture is not green when untouched — every verdict below would be about that instead");
  assert.ok(clean.protocolComplete, `the fixture reporter protocol did not complete: ${clean.protocolError}`);
  assert.equal(clean.testCount, 1, "the fixture did not execute exactly one test");
  assert.equal(baseline.failing.size, 0);
});

check("ANTI-VACUITY: MUTATION_DID_NOT_BUILD can never be counted as a pass", () => {
  assert.ok(!PASSING.has(VERDICT.MUTATION_DID_NOT_BUILD), "a non-building mutation would still be scored as a proven control");
  assert.ok(PASSING.has(VERDICT.DETECTOR_TRIGGERED), "the passing set is empty of the one verdict that should pass — the test is inverted");
});

check("the trusted npm-test grammar refuses shell composition and reporter substitution", () => {
  const manifestPath = path.join(root, "package.json");
  const original = fs.readFileSync(manifestPath, "utf8");
  const refuse = (script, expected) => {
    fs.writeFileSync(manifestPath, JSON.stringify({
      type: "module",
      scripts: { test: script },
    }, null, 2));
    assert.throws(() => trustedTestSteps(root, SUITE), expected);
  };
  try {
    refuse("node suite.mjs | node --test suite.test.mjs", /shell syntax/);
    refuse(
      "node --test suite.test.mjs && node --test suite.test.mjs",
      /exactly one direct node --test evidence step/,
    );
    refuse("node --test --test-reporter=tap suite.test.mjs", /may not select or redirect/);
  } finally {
    fs.writeFileSync(manifestPath, original);
  }
});

check("contained TypeScript tests use the platform-neutral attested loader", () => {
  const manifestPath = path.join(root, "package.json");
  const original = fs.readFileSync(manifestPath, "utf8");
  try {
    fs.writeFileSync(manifestPath, JSON.stringify({
      type: "module",
      scripts: { test: "node --import tsx --test suite.test.mjs" },
    }, null, 2));
    const [step] = trustedTestSteps(root, SUITE);
    assert.deepEqual(
      step.args.slice(0, 4),
      ["--enable-source-maps", "--import", TRUSTED_TYPESCRIPT_TEST_REGISTER, "--test"],
      "contained evidence still imports the host-native tsx/esbuild toolchain",
    );
    const probeEnvironment = { ...PUBLIC_ONLY_ENVIRONMENT, NODE_OPTIONS: "" };
    const probe = spawnSync(process.execPath, [
      "--import", TRUSTED_TYPESCRIPT_TEST_REGISTER,
      "--input-type=module",
      "--eval", "const m = await import('./packages/gate/src/projections.ts'); if (typeof m.getProjection !== 'function') process.exit(9);",
    ], {
      cwd: REPO,
      encoding: "utf8",
      env: probeEnvironment,
      timeout: 60_000,
    });
    assert.equal(
      probe.status,
      0,
      `the platform-neutral loader could not execute public TypeScript source: ${probe.stderr}`,
    );
    const outsideSource = path.join(scratch("typescript-outside-root-"), "escape.ts");
    fs.writeFileSync(outsideSource, "export const escaped = true;\n");
    const escaped = spawnSync(process.execPath, [
      "--import", TRUSTED_TYPESCRIPT_TEST_REGISTER,
      "--input-type=module",
      "--eval", `await import(${JSON.stringify(pathToFileURL(outsideSource).href)});`,
    ], {
      cwd: REPO,
      encoding: "utf8",
      env: probeEnvironment,
      timeout: 60_000,
    });
    assert.notEqual(escaped.status, 0, "the TypeScript loader accepted source outside the public repository");
    assert.match(escaped.stderr, /outside the public repository/);
  } finally {
    fs.writeFileSync(manifestPath, original);
  }
});

check("the observer refuses inherited Node startup hooks before opening an evidence channel", () => {
  const hadNodeOptions = Object.prototype.hasOwnProperty.call(process.env, "NODE_OPTIONS");
  const priorNodeOptions = process.env.NODE_OPTIONS;
  try {
    process.env.NODE_OPTIONS = "--trace-warnings";
    const observation = observeSuite(root, SUITE, 60_000, { kind: "tests" });
    assert.equal(observation.protocolComplete, false,
      "an inherited Node startup hook entered a proof-bearing test process");
    assert.equal(observation.testCount, 0, "the refused observer reported executed tests");
    assert.match(observation.protocolError ?? "", /closed Node startup surface/);
  } finally {
    if (hadNodeOptions) process.env.NODE_OPTIONS = priorNodeOptions;
    else delete process.env.NODE_OPTIONS;
  }
});

check("a GATE observation refuses an inherited Node startup hook instead of reading its output", () => {
  // ── WHY THIS EXISTS (reproduced 2026-08-24, then fixed) ───────────────────────────────────────
  // The closed-startup-surface refusal above was scoped to `kind: "tests"`. The gate lane runs its
  // suite directly on the host with the inherited environment, so an inherited
  // `NODE_OPTIONS=--import <module>` loaded a module into the gate child that printed a well-formed
  // `noa-gate-runner/1` terminal record at exit. MEASURED: a gate that emitted NO evidence of its
  // own and exited 1 was read back as `gateProtocolComplete: true`, gate identity "security-gates",
  // and the exact rule/subject pair a registry entry requires — DETECTOR_TRIGGERED manufactured for
  // every gate-kind knockout out of the environment alone, with no repository change at all.
  //
  // Both halves are asserted here: the forged record must NOT be believed, and a real gate under a
  // clean environment must still be observed, or this check would pass by refusing everything.
  const workspace = scratch("gate-startup-surface-");
  const guardCache = scratch("gate-startup-surface-guard-");
  const workspaceGuard = createBuildStateGuard({ root: workspace, cacheDir: guardCache });
  const hadNodeOptions = Object.prototype.hasOwnProperty.call(process.env, "NODE_OPTIONS");
  const priorNodeOptions = process.env.NODE_OPTIONS;
  try {
    const forgedFinding = { rule: "L8-selftest", subject: "scripts/lib/dispatch-ast.mjs", detail: "forged" };
    fs.writeFileSync(path.join(workspace, "forge.mjs"), [
      'process.on("exit", () => {',
      `  process.stdout.write(JSON.stringify(${JSON.stringify({
        protocol: GATE_EVENT_PROTOCOL,
        event: "complete",
        gate: "security-gates",
        findings: [forgedFinding],
      })}) + "\n");`,
      "});",
      "",
    ].join("\n"));
    // A gate that produces no evidence of its own and fails: the only honest reading is a refusal.
    fs.writeFileSync(path.join(workspace, "silent-gate.mjs"), "process.exitCode = 1;\n");
    // A gate that speaks the real protocol: proof that the refusal is not simply refusing everything.
    fs.writeFileSync(path.join(workspace, "honest-gate.mjs"), [
      'import { emitGateEvidence } from ' + JSON.stringify(path.join(REPO, "scripts/lib/gate-event-contract.mjs")) + ";",
      'emitGateEvidence("selftest-gate", []);',
      "",
    ].join("\n"));

    const silent = [".", process.execPath, [path.join(workspace, "silent-gate.mjs")]];
    const honest = [".", process.execPath, [path.join(workspace, "honest-gate.mjs")]];

    delete process.env.NODE_OPTIONS;
    const clean = observeSuite(workspace, honest, 60_000, { kind: "gate" });
    assert.equal(clean.gateProtocolComplete, true,
      `ANTI-VACUITY: a real gate under a clean environment was not observed: ${clean.gateProtocolError}`);
    assert.equal(clean.gate, "selftest-gate", "the clean gate identity did not survive the observation");

    process.env.NODE_OPTIONS = `--import ${JSON.stringify(path.join(workspace, "forge.mjs"))}`;
    const forged = observeSuite(workspace, silent, 60_000, { kind: "gate" });
    assert.equal(forged.gateProtocolComplete, false,
      "an inherited Node startup hook forged a complete gate protocol");
    assert.equal(forged.gate, null, "a forged gate identity was accepted as evidence");
    assert.deepEqual(forged.gateFindings, [], "forged gate findings were carried into the verdict");
    assert.match(forged.gateProtocolError ?? "", /closed Node startup surface/);

    // And the forgery must not be rescued by the entry it was aimed at.
    const ev = runKnockout({
      root: workspace,
      entry: {
        id: "forged-gate", control: "forged gate", file: "silent-gate.mjs",
        find: "process.exitCode = 1;", replace: "process.exitCode = 1; // mutated",
        kind: "gate", gateId: "security-gates", expectedGateFindings: [{
          rule: forgedFinding.rule, subject: forgedFinding.subject,
        }],
        suite: silent,
      },
      baseline: forged,
      timeoutMs: 60_000,
      guard: workspaceGuard,
    });
    assert.notEqual(ev.verdict, VERDICT.DETECTOR_TRIGGERED,
      `a forged gate record scored a kill: ${ev.detail}`);
    assert.equal(ev.verdict, VERDICT.INVALID_TEST, `got ${ev.verdict}: ${ev.detail}`);
  } finally {
    if (hadNodeOptions) process.env.NODE_OPTIONS = priorNodeOptions;
    else delete process.env.NODE_OPTIONS;
    const released = workspaceGuard.ownerNonce === null || workspaceGuard.release();
    const retained = fs.existsSync(workspaceGuard.lockPath);
    if (!retained) {
      fs.rmSync(workspace, { recursive: true, force: true });
      fs.rmSync(guardCache, { recursive: true, force: true });
    }
    assert.equal(released, true, "the startup-surface fixture did not release its owned guard");
    assert.equal(retained, false,
      `startup-surface recovery state was retained at ${workspaceGuard.lockPath}`);
  }
});

check("the fixed SPOOL driver refuses every argument except one gate machine-output selector", () => {
  const driver = path.join(REPO, "scripts/lib/boundary-spool-arm.selftest.mjs");
  const refuse = (args) => {
    const result = spawnSync(process.execPath, [driver, ...args], {
      cwd: REPO,
      encoding: "utf8",
      env: closedEvidenceEnvironment(process.env),
      stdio: "pipe",
      timeout: 60_000,
    });
    assert.equal(result.status, 1, `unexpected exit for ${JSON.stringify(args)}: ${result.stdout}${result.stderr}`);
    assert.match(`${result.stdout}${result.stderr}`, /SPOOL_ONLY_SELFTEST_ARGUMENTS_REFUSED/);
  };
  refuse([]);
  refuse(["--unknown"]);
  refuse(["positional"]);
  refuse(["--knockout-json", "--knockout-json"]);
});

check("a GATE observation refuses an npm config alias that maps into the child's NODE_OPTIONS", () => {
  // ── WHY THIS EXISTS (reproduced 2026-08-24, after the first fix) ──────────────────────────────
  // The first repair checked `NODE_OPTIONS` and nothing else. MEASURED with NODE_OPTIONS UNSET and
  // only `npm_config_node_options=--import=<percent-encoded data: URL>` set: `npm run` maps that
  // config straight into the child's NODE_OPTIONS (verified directly — the child printed the value
  // back), the data URL's exit handler emitted a well-formed `noa-gate-runner/1` record, and a gate
  // that produced NO evidence and exited 1 came back as gateProtocolComplete:true, identity
  // "security-gates", findings [FORGED/ambient], protocolError null. A `.npmrc` `node-options` line
  // reaches the same place with no environment variable at all.
  const workspace = scratch("gate-npm-alias-");
  const saved = process.env.npm_config_node_options;
  const hadSaved = Object.prototype.hasOwnProperty.call(process.env, "npm_config_node_options");
  try {
    fs.writeFileSync(path.join(workspace, "silent-gate.mjs"), "process.exitCode = 1;\n");
    fs.writeFileSync(path.join(workspace, "honest-gate.mjs"), [
      'import { emitGateEvidence } from ' + JSON.stringify(path.join(REPO, "scripts/lib/gate-event-contract.mjs")) + ";",
      'emitGateEvidence("selftest-npm-gate", []);',
      "",
    ].join("\n"));
    fs.writeFileSync(path.join(workspace, "package.json"), JSON.stringify({
      name: "noa-gate-alias-fixture", version: "1.0.0", private: true,
      scripts: { "silent-gate": "node silent-gate.mjs", "honest-gate": "node honest-gate.mjs" },
    }) + "\n");

    const forge = "data:text/javascript," + encodeURIComponent(
      'process.on("exit",()=>process.stdout.write(JSON.stringify(' +
      JSON.stringify({
        protocol: GATE_EVENT_PROTOCOL, event: "complete", gate: "security-gates",
        findings: [{ rule: "FORGED", subject: "ambient" }],
      }) + ')+String.fromCharCode(10)));',
    );

    delete process.env.npm_config_node_options;
    const clean = observeSuite(workspace, [".", "npm", ["run", "honest-gate"]], 120_000, { kind: "gate" });
    assert.equal(clean.gateProtocolComplete, true,
      `ANTI-VACUITY: an npm-scripted gate under a clean environment was not observed: ${clean.gateProtocolError}`);
    assert.equal(clean.gate, "selftest-npm-gate", "the clean npm-scripted gate identity did not survive");

    process.env.npm_config_node_options = `--import=${forge}`;
    const aliased = observeSuite(workspace, [".", "npm", ["run", "silent-gate"]], 120_000, { kind: "gate" });
    assert.equal(aliased.gateProtocolComplete, false,
      "an npm config alias forged a complete gate protocol through the child's NODE_OPTIONS");
    assert.equal(aliased.gate, null, "a forged gate identity arrived through an npm config alias");
    assert.deepEqual(aliased.gateFindings, [], "forged findings arrived through an npm config alias");
    assert.match(aliased.gateProtocolError ?? "", /closed Node startup surface/);
  } finally {
    if (hadSaved) process.env.npm_config_node_options = saved;
    else delete process.env.npm_config_node_options;
    fs.rmSync(workspace, { recursive: true, force: true });
  }
});

check("a project .npmrc cannot reach an evidence step, because no npm runs there", () => {
  // ── WHY THIS EXISTS (reproduced 2026-08-24) ───────────────────────────────────────────────────
  // The environment neutralizers disarm the USER and GLOBAL rc files. They do NOT disarm a PROJECT
  // `.npmrc`: MEASURED, a project rc carrying `script-shell=/tmp/attacker-shell` and
  // `node-options=--import=/tmp/attacker.mjs` was returned verbatim by `npm config get` while
  // `npm_config_node_options` was set empty in the environment. No environment variable turns a
  // project rc off, so the proof recipe's build step no longer starts npm at all.
  //
  // Both directions are measured here: the rc must be genuinely hostile (or this proves nothing),
  // and the direct Node step must be untouched by it.
  const workspace = scratch("project-npmrc-");
  try {
    const marker = "PROJECT_RC_REACHED_THE_CHILD";
    const forge = "data:text/javascript," + encodeURIComponent(
      `process.stdout.write(${JSON.stringify(marker)} + String.fromCharCode(10));`,
    );
    fs.writeFileSync(path.join(workspace, ".npmrc"), `node-options=--import=${forge}\n`);
    fs.writeFileSync(path.join(workspace, "print.mjs"), 'process.stdout.write("child ran" + String.fromCharCode(10));\n');
    fs.writeFileSync(path.join(workspace, "package.json"), JSON.stringify({
      name: "noa-project-rc-fixture", version: "1.0.0", private: true,
      scripts: { show: "node print.mjs" },
    }) + "\n");
    const environment = closedEvidenceEnvironment(process.env);

    // ANTI-VACUITY: through npm, the project rc DOES reach the child. If this stops being true the
    // assertion below is measuring nothing, and the check says so instead of passing quietly.
    let viaNpm = "";
    try {
      viaNpm = execFileSync("npm", ["run", "--silent", "show"],
        { cwd: workspace, encoding: "utf8", stdio: "pipe", env: environment });
    } catch (e) { viaNpm = `${e.stdout ?? ""}${e.stderr ?? ""}`; }
    assert.ok(viaNpm.includes(marker),
      "the fixture project .npmrc no longer injects through npm — this check has become vacuous");

    // THE CONTROL: the same rc, the same directory, an exact Node step. npm is not involved, so the
    // rc is never read and nothing of the attacker's runs.
    const viaNode = execFileSync(process.execPath, ["print.mjs"],
      { cwd: workspace, encoding: "utf8", stdio: "pipe", env: environment });
    assert.ok(!viaNode.includes(marker),
      "a project .npmrc reached a direct Node evidence step");
    assert.ok(viaNode.includes("child ran"), "the direct Node step did not actually run");

    // And the compiled proof recipe must contain no npm step for the rc to act on.
    const recipe = runRecipeFor("packages/gate/test/example.test.ts");
    for (const [command] of recipe.steps) {
      assert.equal(command, "node", `a proof recipe step still starts ${command}, which reads the project rc`);
    }
  } finally {
    fs.rmSync(workspace, { recursive: true, force: true });
  }
});

check("an inherited LD_LIBRARY_PATH is REFUSED, and removing it at the launch point restores the run", () => {
  // ── WHY THIS EXISTS, AND WHY AN EARLIER REVISION OF IT WAS WRONG ──────────────────────────────
  // A previous revision asserted the OPPOSITE — that a library search path is benign — because
  // GitHub's runner sets LD_LIBRARY_PATH and the required checks went red. That reasoning was false
  // at an evidence-trust boundary: the dynamic loader searches LD_LIBRARY_PATH directories BEFORE
  // the default ones, so a writable entry selects which shared object loads at process start. glibc's
  // own hardening guidance says not to use LD_PRELOAD or LD_LIBRARY_PATH to change loader behaviour.
  //
  // So the refusal stays, and the environment is cleaned before the evidence-bearing process starts.
  // Both halves are asserted: inheriting it REFUSES, and removing it lets the very same gate run.
  const workspace = scratch("gate-ld-library-path-");
  const had = Object.prototype.hasOwnProperty.call(process.env, "LD_LIBRARY_PATH");
  const saved = process.env.LD_LIBRARY_PATH;
  try {
    fs.writeFileSync(path.join(workspace, "honest-gate.mjs"), [
      'import { emitGateEvidence } from ' + JSON.stringify(path.join(REPO, "scripts/lib/gate-event-contract.mjs")) + ";",
      'emitGateEvidence("selftest-ld-path", []);',
      "",
    ].join("\n"));
    const suite = [".", process.execPath, [path.join(workspace, "honest-gate.mjs")]];

    process.env.LD_LIBRARY_PATH = "/tmp/attacker-libs:/usr/lib";
    const inherited = observeSuite(workspace, suite, 60_000, { kind: "gate" });
    assert.equal(inherited.gateProtocolComplete, false,
      "an inherited LD_LIBRARY_PATH did not refuse: the loader searches it before the default paths, so it selects which shared object starts the process");
    assert.equal(inherited.gate, null);
    assert.match(inherited.gateProtocolError ?? "", /LD_LIBRARY_PATH/);

    delete process.env.LD_LIBRARY_PATH;
    const sanitized = observeSuite(workspace, suite, 60_000, { kind: "gate" });
    assert.equal(sanitized.gateProtocolComplete, true,
      `removing the variable at the launch point did not restore the run: ${sanitized.gateProtocolError}`);
    assert.equal(sanitized.gate, "selftest-ld-path");
  } finally {
    if (had) process.env.LD_LIBRARY_PATH = saved;
    else delete process.env.LD_LIBRARY_PATH;
    fs.rmSync(workspace, { recursive: true, force: true });
  }
});

/**
 * Steps of a workflow, line-structurally — the same choice `lint-workflows.mjs` makes and for the
 * same reason: this repository ships no YAML parser, and the association being checked here is
 * between a step's OWN `env:` and that step's OWN `run:`, which is exactly what a flat scan loses.
 */
function workflowSteps(file) {
  const lines = fs.readFileSync(file, "utf8").split("\n");
  const steps = [];
  let current = null;
  for (let index = 0; index < lines.length; index++) {
    const line = lines[index];
    if (/^ {6}- /.test(line)) {
      if (current !== null) steps.push(current);
      current = { line: index + 1, run: null, runLines: [], env: null };
    } else if (/^ {0,4}\S/.test(line) && current !== null) {
      steps.push(current);
      current = null;
    }
    if (current === null) continue;
    const run = /^ {8}run: (.*)$/.exec(line);
    if (run !== null) {
      current.run = run[1];
      current.runLines = [run[1]];
      if (/^[|>][+-]?$/.test(run[1])) {
        current.runLines = [];
        for (let cursor = index + 1; cursor < lines.length; cursor++) {
          if (/^\s*$/.test(lines[cursor])) {
            current.runLines.push("");
            continue;
          }
          const bodyLine = /^ {10}(.*)$/.exec(lines[cursor]);
          if (bodyLine === null) break;
          current.runLines.push(bodyLine[1]);
        }
      }
    }
    if (/^ {8}env:\s*$/.test(line)) {
      current.env = {};
      for (let cursor = index + 1; cursor < lines.length; cursor++) {
        if (/^\s*$/.test(lines[cursor]) || /^ {10}#/.test(lines[cursor])) continue;
        const entry = /^ {10}([A-Za-z_][A-Za-z0-9_]*):(?:[ \t]*(.*))?$/.exec(lines[cursor]);
        if (entry === null) break;
        const rawValue = entry[2] ?? "";
        const quotedValue = /^"(.*)"$/.exec(rawValue);
        current.env[entry[1]] = quotedValue === null ? rawValue : quotedValue[1];
      }
    }
  }
  if (current !== null) steps.push(current);
  return steps;
}

/**
 * A non-evidence step may need its own environment (for example, a boundary key), but it must not
 * carry even one key from the evidence launch's neutralization block. A partial block is still a
 * place the protection can be parked while an evidence shell starts without it.
 */
function misplacedNeutralizationKeys(steps, evidence, declaredEnv) {
  const evidenceSteps = new Set(evidence);
  const neutralizationKeys = new Set(Object.keys(declaredEnv));
  const findings = [];
  for (const step of steps) {
    if (step.env === null || evidenceSteps.has(step)) continue;
    for (const key of Object.keys(step.env)) {
      if (neutralizationKeys.has(key)) findings.push({ line: step.line, key });
    }
  }
  return findings;
}

check("non-evidence workflow env allows unrelated keys and refuses partial or exact neutralization", () => {
  const declaredEnv = evidenceLaunchEnv();
  const keys = Object.keys(declaredEnv);
  assert.ok(keys.length > 1, "the neutralization set is too small to prove partial-block handling");

  const evidenceStep = { line: 1, run: "evidence", env: declaredEnv };
  const unrelatedStep = {
    line: 2,
    run: "unrelated",
    env: {
      UNRELATED_KEY: "fixture-value",
      UNRELATED_CANARY: "fixture-value",
    },
  };
  assert.deepEqual(
    misplacedNeutralizationKeys([evidenceStep, unrelatedStep], [evidenceStep], declaredEnv),
    [],
    "an unrelated non-evidence environment was misclassified as evidence neutralization",
  );

  const partialStep = {
    line: 3,
    run: "unrelated",
    env: { UNRELATED_KEY: "fixture-value", [keys[0]]: declaredEnv[keys[0]] },
  };
  assert.deepEqual(
    misplacedNeutralizationKeys([evidenceStep, partialStep], [evidenceStep], declaredEnv),
    [{ line: 3, key: keys[0] }],
    "one parked neutralization key was not refused",
  );

  const exactStep = { line: 4, run: "unrelated", env: { ...declaredEnv } };
  assert.deepEqual(
    misplacedNeutralizationKeys([evidenceStep, exactStep], [evidenceStep], declaredEnv),
    keys.map((key) => ({ line: 4, key })),
    "an exact parked neutralization block was not refused",
  );

  const fixture = scratch("workflow-env-parser-");
  try {
    const workflow = path.join(fixture, "workflow.yml");
    fs.writeFileSync(workflow, [
      "jobs:",
      "  fixture:",
      "    steps:",
      "      - name: Unrelated",
      "        env:",
      "          UNRELATED_KEY: fixture-value",
      "          # A comment inside the mapping must not hide the following key.",
      "          UNRELATED_CANARY: fixture-value",
      "        run: echo unrelated",
      "",
    ].join("\n"));
    const parsed = workflowSteps(workflow);
    assert.deepEqual(parsed.map((step) => step.env), [
      {
        UNRELATED_KEY: "fixture-value",
        UNRELATED_CANARY: "fixture-value",
      },
    ], "an unquoted GitHub expression env value was not parsed as its step's own key");
  } finally {
    fs.rmSync(fixture, { recursive: true, force: true });
  }
});

const LEGACY_PUBLISHER_WORKFLOWS = ["publish.yml", "publish-mcp.yml", "publish-tsa.yml"];

// These are SHA-256 digests of the complete production bytes, including comments, blank lines and
// every block-scalar byte. There is deliberately no YAML-comment stripper here: inside `run: |`, a
// hash-prefixed line is shell input and GitHub expands `${{ ... }}` before the shell sees the hash.
// A partial lexer cannot safely decide which hash begins YAML prose, so this quarantine ignores
// nothing. Any material or prose change requires explicit re-review of the whole tiny workflow.
const CLOSED_WORKFLOW_SHA256 = Object.freeze({
  "boundary.yml": "7b0bd804e92afa0d98770e2c022a08671a264de02be2afbf60385348b0ca4796",
  "publish.yml": "95a5c267c674326e90ca97b1abe8c9b5b1628b7ca05a820851bbdb852795d5c3",
  "publish-mcp.yml": "7a38cf1cd331d2a61a2890f1430b422996e7c85d7aa892a18c2a8760bbcbc0e7",
  "publish-tsa.yml": "91745dac92651660718868884d203af96f7bcc42f5986ce9f319087c4b38716e",
});

// Only LF is a line separator in the canonical production representation. Reject every other
// control/format separator before decoding workflow meaning. In particular, YAML recognises CR,
// NEL, LS and PS as line boundaries while the old `/\r?\n/` splitter did not recognise three of
// them; a physical line beginning `#` could therefore conceal a trigger or job from the comparator.
const NONCANONICAL_WORKFLOW_CODE_POINT =
  /[\u0000-\u0009\u000b-\u001f\u007f-\u009f\u2028\u2029\ufeff]/u;

function exactReplacement(source, find, replace, label) {
  assert.equal(source.includes(find), true, `${label}: mutation subject is absent`);
  return source.replace(find, replace);
}

function closedWorkflowByteProblems(file, source) {
  const expected = CLOSED_WORKFLOW_SHA256[file];
  assert.equal(typeof expected, "string", `${file}: no closed workflow digest is registered`);
  const bytes = Buffer.isBuffer(source) ? source : Buffer.from(source, "utf8");
  const decoded = bytes.toString("utf8");
  if (!Buffer.from(decoded, "utf8").equals(bytes)) {
    return [`${file} is not canonical UTF-8`];
  }
  const forbidden = NONCANONICAL_WORKFLOW_CODE_POINT.exec(decoded);
  if (forbidden !== null) {
    const codePoint = forbidden[0].codePointAt(0).toString(16).toUpperCase().padStart(4, "0");
    return [`${file} contains noncanonical workflow code point U+${codePoint}`];
  }
  const actual = crypto.createHash("sha256").update(bytes).digest("hex");
  return actual === expected
    ? []
    : [`${file} complete production bytes differ from the closed canonical digest`];
}

function legacyPublisherProblems(file, source) {
  return closedWorkflowByteProblems(file, source);
}

function boundaryWorkflowProblems(source) {
  return closedWorkflowByteProblems("boundary.yml", source);
}

check("legacy publisher workflow IDs are inert fail-closed quarantine", () => {
  for (const file of LEGACY_PUBLISHER_WORKFLOWS) {
    const source = fs.readFileSync(path.join(REPO, ".github/workflows", file));
    const problems = legacyPublisherProblems(file, source);
    assert.deepEqual(problems, [], `${file}: ${problems.join("; ")}`);
  }

  const file = "publish.yml";
  const base = fs.readFileSync(path.join(REPO, ".github/workflows", file), "utf8");
  const mutations = [
    ["tag authority", "on:\n  workflow_dispatch: {}", "on:\n  push:\n    tags: ['v*']\n  workflow_dispatch: {}"],
    ["checkout", "    steps:\n", "    steps:\n      - uses: actions/checkout@v7\n"],
    ["secret", "        shell: bash\n", "        shell: bash\n        env:\n          RELEASE_TOKEN: ${{ secrets.RELEASE_TOKEN }}\n"],
    ["GITHUB_TOKEN permission", "permissions: {}\n", "permissions:\n  contents: read\n"],
    ["OIDC", "permissions: {}\n", "permissions:\n  id-token: write\n"],
    ["dispatch success", "          exit 1\n", "          exit 0\n"],
    ["npm publish", "          exit 1\n", "          npm publish\n          exit 1\n"],
    ["npm stage", "          exit 1\n", "          npm stage\n          exit 1\n"],
    ["npm exec", "          exit 1\n", "          npm exec -- fixture\n          exit 1\n"],
    ["CRLF is not the canonical separator", "name: publish (RELEASE_FROZEN)\n", "name: publish (RELEASE_FROZEN)\r\n", /U\+000D/u],
    ["LS-hidden workflow_call", "  workflow_dispatch: {}\n", "  workflow_dispatch: {}\n# comparator-visible comment\u2028  workflow_call:\n", /U\+2028/u],
    ["PS-hidden tag publication", "  workflow_dispatch: {}\n", "  workflow_dispatch: {}\n# comparator-visible comment\u2029  push:\u2029    tags: [\"v*\"]\n", /U\+2029/u],
    ["NUL control byte", "name: publish (RELEASE_FROZEN)", "name: publish (RELEASE_FROZEN)\u0000", /U\+0000/u],
    ["second document with duplicate authority keys", "          exit 1\n", "          exit 1\n---\nname: hidden\npermissions: {}\npermissions:\n  id-token: write\non: workflow_dispatch\njobs: {}\n", /complete production bytes/u],
  ];
  for (const [label, find, replace, expectedProblem] of mutations) {
    const mutant = exactReplacement(base, find, replace, label);
    const mutantProblems = legacyPublisherProblems(file, mutant);
    assert.notDeepEqual(mutantProblems, [], `${label} was not detected`);
    if (expectedProblem !== undefined) assert.match(mutantProblems.join("; "), expectedProblem);
  }
});

check("boundary workflow is keyless Tier-A CI with least privilege", () => {
  const raw = fs.readFileSync(path.join(REPO, ".github/workflows/boundary.yml"));
  const base = raw.toString("utf8");
  const problems = boundaryWorkflowProblems(raw);
  assert.deepEqual(problems, [], problems.join("; "));

  const mutations = [
    ["arbitrary ref trigger", "    branches: [main]\n", "    branches: ['**']\n    tags: ['**']\n"],
    ["secret access", "        shell: bash\n", "        shell: bash\n        env:\n          NOA_BOUNDARY_KEY: ${{ secrets['NOA_BOUNDARY_KEY'] }}\n"],
    ["whole secrets context", "        shell: bash\n", "        shell: bash\n        env:\n          OBSERVED: ${{ toJSON(secrets) }}\n"],
    ["OIDC", "  contents: read\n", "  contents: read\n  id-token: write\n"],
    ["permissions drift", "  contents: read\n", "  contents: write\n"],
    ["persisted checkout credential", "          persist-credentials: false\n", "          persist-credentials: true\n"],
    ["injected GitHub job token", "        shell: bash\n", "        shell: bash\n        env:\n          GH_TOKEN: ${{ github.token }}\n"],
    ["bracketed GitHub job token", "        shell: bash\n", "        shell: bash\n        env:\n          GH_TOKEN: ${{ github['token'] }}\n"],
    ["hash-prefixed scalar whole-secrets expression", "          set -euo pipefail\n          if [ -n \"${{ steps.range.outputs.range }}\" ]; then", "          set -euo pipefail\n          # ${{ toJSON(secrets) }}\n          if [ -n \"${{ steps.range.outputs.range }}\" ]; then", /complete production bytes/u],
    ["hash-prefixed scalar GitHub-token expression", "          set -euo pipefail\n          if [ -n \"${{ steps.range.outputs.range }}\" ]; then", "          set -euo pipefail\n          # ${{ github['token'] }}\n          if [ -n \"${{ steps.range.outputs.range }}\" ]; then", /complete production bytes/u],
    ["second observer job", "          else\n            node scripts/lint-boundary.mjs --repo-visibility-source snapshot --tier a --explain\n          fi\n", "          else\n            node scripts/lint-boundary.mjs --repo-visibility-source snapshot --tier a --explain\n          fi\n  _observer:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo observer\n"],
    ["dynamically unreachable step", "          else\n            node scripts/lint-boundary.mjs --repo-visibility-source snapshot --tier a --explain\n          fi\n", "          else\n            node scripts/lint-boundary.mjs --repo-visibility-source snapshot --tier a --explain\n          fi\n      - name: Dynamically unreachable observer\n        if: ${{ github.event_name == 'never' }}\n        env:\n          OBSERVED: ${{ toJSON(secrets) }}\n        run: echo unreachable\n"],
    ["lone-CR-hidden second job", "          else\n            node scripts/lint-boundary.mjs --repo-visibility-source snapshot --tier a --explain\n          fi\n", "          else\n            node scripts/lint-boundary.mjs --repo-visibility-source snapshot --tier a --explain\n          fi\n# comparator-visible comment\r  _observer:\r    runs-on: ubuntu-latest\r    steps:\r      - run: echo observer\n", /U\+000D/u],
    ["NEL-hidden second job", "          else\n            node scripts/lint-boundary.mjs --repo-visibility-source snapshot --tier a --explain\n          fi\n", "          else\n            node scripts/lint-boundary.mjs --repo-visibility-source snapshot --tier a --explain\n          fi\n# comparator-visible comment\u0085  _observer:\u0085    runs-on: ubuntu-latest\u0085    steps:\u0085      - run: echo observer\n", /U\+0085/u],
    ["live-provider substitution", "--repo-visibility-source snapshot --tier a --explain\n", "--repo-visibility-source live --tier a --explain\n"],
    ["implicit scanner tier", "node scripts/lint-boundary.mjs --repo-visibility-source snapshot --tier a --explain\n", "node scripts/lint-boundary.mjs --repo-visibility-source snapshot --explain\n"],
  ];
  for (const [label, find, replace, expectedProblem] of mutations) {
    const mutant = exactReplacement(base, find, replace, label);
    const mutantProblems = boundaryWorkflowProblems(mutant);
    assert.notDeepEqual(mutantProblems, [], `${label} was not detected`);
    if (expectedProblem !== undefined) assert.match(mutantProblems.join("; "), expectedProblem);
  }

  let anchorMutant = exactReplacement(
    base,
    "  shapes:\n    runs-on: ubuntu-latest\n",
    "  shapes:\n    env: &observer_env\n      GH_TOKEN: ${{ github['token'] }}\n    runs-on: ubuntu-latest\n",
    "YAML-anchor token injection",
  );
  anchorMutant = exactReplacement(
    anchorMutant,
    "      - name: Boundary shapes and the public-repository inversion (TIER A)\n        shell: bash\n",
    "      - name: Boundary shapes and the public-repository inversion (TIER A)\n        shell: bash\n        env: *observer_env\n",
    "YAML-anchor token alias",
  );
  assert.notDeepEqual(
    boundaryWorkflowProblems(anchorMutant),
    [],
    "YAML-anchor token injection was not detected",
  );

  const invalidUtf8 = Buffer.concat([raw, Buffer.from([0xc3, 0x28])]);
  assert.match(
    boundaryWorkflowProblems(invalidUtf8).join("; "),
    /not canonical UTF-8/u,
    "invalid UTF-8 reached the workflow digest as decoded replacement text",
  );
});

check("branch-hygiene workflow retains least-privilege pull-request measurement", () => {
  // Keep the permission parser and its negative fixtures in their authoritative selftest. This
  // wrapper supplies only the structured knockout finding identity, so the registry can mutate the
  // checked-in workflow without duplicating the permission semantics here.
  const result = spawnSync(
    process.execPath,
    ["scripts/lint-stranded-branches.mjs", "--selftest"],
    { cwd: REPO, encoding: "utf8", maxBuffer: 1024 * 1024 },
  );
  if (result.error !== undefined) throw result.error;
  assert.equal(
    result.status,
    0,
    `branch-hygiene selftest did not pass:\n${result.stdout ?? ""}${result.stderr ?? ""}`,
  );
});

check("every evidence-bearing CI launch point sanitizes the exact refusal list", () => {
  // The refusal is only survivable in CI because the workflow removes those variables BEFORE Node
  // starts. That coupling is the control, so the expected prefix is DERIVED from the observer's own
  // list: adding a variable to the refusal without adding it to the workflows fails here.
  //
  // The EXACT COUNTS matter as much as the prefix. Without them a launch point could disappear while
  // the check stayed green on its siblings. Release workflows are intentionally absent from this
  // census: all three legacy IDs are quarantined above and contain no candidate-controlled evidence.
  const sanitizer = `${evidenceLaunchSanitizer()} ${evidenceLaunchGuardCommand()}`;
  const flags = evidenceNpmPrecedenceFlags();
  const quote = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const EXPECTED = [
    [".github/workflows/ci.yml", "npm test", 2],
    [".github/workflows/ci.yml", "npm run lint:knockout", 1],
  ];
  // The sharded sweep appends its slice AFTER npm's `--`, so the launch line carries one more
  // suffix. It is written out here rather than derived because it is a GitHub expression, not
  // anything the runner exports: `strategy.job-index` / `strategy.job-total` are values only the
  // workflow engine can produce, which is the whole reason no id list is maintained by hand.
  const shardSuffix = "-- --shard ${{ strategy.job-index }}/${{ strategy.job-total }}";
  // PHASE 1 is a step-level `env:`, applied by the runner when it CREATES the shell process. It is
  // bound to EACH evidence step structurally, not counted across the file: counting alone let a
  // mutant move one exact block onto an unrelated step, leaving every count intact, every `run:`
  // line still carrying the inner sanitizer, and an unprotected shell greenlit.
  const declaredEnv = evidenceLaunchEnv();
  for (const [file, expectedSteps] of [[".github/workflows/ci.yml", 3]]) {
    const steps = workflowSteps(path.join(REPO, file));
    const evidence = steps.filter((step) => typeof step.run === "string" && step.run.startsWith(`${sanitizer} `));
    assert.equal(evidence.length, expectedSteps,
      `${file}: expected exactly ${expectedSteps} evidence step(s), found ${evidence.length}`);
    for (const step of evidence) {
      assert.deepEqual(step.env, declaredEnv,
        `${file}:${step.line}: this evidence step does not declare the exact derived neutralization as its OWN env`);
    }
    // …and no exact OR partial neutralization block may be parked somewhere harmless. Unrelated
    // step environment is valid and outside this control's scope.
    const misplaced = misplacedNeutralizationKeys(steps, evidence, declaredEnv);
    assert.deepEqual(misplaced, [],
      `${file}: evidence neutralization key(s) are declared on a step that launches no evidence`);
  }

  for (const [file, command, expected] of EXPECTED) {
    const lines = fs.readFileSync(path.join(REPO, file), "utf8").split("\n");
    const pattern = new RegExp(`^\\s*run: (?:${quote(sanitizer)} )?${quote(command)}(?: ${quote(flags)})?(?: ${quote(shardSuffix)})?\\s*$`);
    const launches = lines.filter((line) => pattern.test(line));
    assert.equal(launches.length, expected,
      `${file}: expected exactly ${expected} \`${command}\` launch(es), found ${launches.length} — a launch point moved, vanished, or was added without coverage`);
    for (const line of launches) {
      assert.ok(line.includes(sanitizer),
        `${file}: a \`${command}\` launch does not go through the exact sanitizer AND pre-npm guard:\n  ${line.trim()}`);
      // PHASE 3, bound to the SAME matched launches rather than counted across the file. `env -u`
      // removes a NAME; npm resolves a SETTING under any casing of that name, so the settings are
      // pinned in argv where casing has nothing to attack. A launch that keeps the sanitizer and
      // drops the flags is exactly the shape the reproduction walked through.
      const tail = line.trimEnd();
      assert.ok(tail.endsWith(flags) || tail.endsWith(`${flags} ${shardSuffix}`),
        `${file}: a \`${command}\` launch does not pin npm configuration on the command line, so a mixed-case npm_config_* spelling decides it:\n  ${line.trim()}`);
    }
  }
});

/**
 * One live npm fixture, shared by the three proofs below.
 *
 * Its `prepublishOnly` is `npm test` — the shape the REAL package has — because a fixture whose
 * `prepublishOnly` calls node directly proves nothing about the publish lane: the whole question
 * there is what a SECOND npm does with the environment the first one hands it.
 */
const npmCasingFixture = () => {
  const npm = path.join(path.dirname(process.execPath), "npm");
  assert.ok(fs.existsSync(npm),
    `no npm beside this Node at ${npm}; these proofs need the npm the runtime under measurement ships`);
  // HOME AND THE CACHE LIVE OUTSIDE THE PACKAGE, and that is not a style choice. Pointing HOME at
  // the package directory put npm's cache INSIDE the tree `npm publish --dry-run` packs, so each
  // dry-run packed the previous run's cache: measured at 7.2G and CPU-bound before it was stopped.
  const root = scratch("npm-casing-");
  const dir = path.join(root, "package");
  const home = path.join(root, "home");
  for (const made of [dir, home]) fs.mkdirSync(made, { recursive: true });
  fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({
    name: "npm-casing-fixture", version: "1.0.0",
    scripts: { test: "node ./ran.mjs", "lint:knockout": "node ./ran.mjs", prepublishOnly: "npm test" },
  }));
  // The marker records what the EVIDENCE CHILD actually received, not what npm was asked for.
  fs.writeFileSync(path.join(dir, "ran.mjs"),
    'import{writeFileSync}from"node:fs";' +
    'writeFileSync("RAN.marker",JSON.stringify({NODE_OPTIONS:process.env.NODE_OPTIONS??null,title:process.title,' +
    'userconfig:process.env.npm_config_userconfig??null,authToken:process.env.NODE_AUTH_TOKEN??null}));\n');
  // Harmless: it records that npm SELECTED it and exits, so a hijack is observable without the
  // fixture ever running anything a real attacker would.
  const standIn = path.join(dir, "stand-in-shell.sh");
  fs.writeFileSync(standIn, '#!/bin/sh\ntouch "$(dirname "$0")/HIJACKED.marker"\nexit 0\n', { mode: 0o700 });
  // Two DISTINCT empty rc files: npm refuses to start when userconfig and globalconfig name the same
  // file, and without them these proofs would read whichever `.npmrc` the developer happens to have.
  // The runner's own npm configuration, in the shape `actions/setup-node` actually produces: it
  // writes `$RUNNER_TEMP/.npmrc` and exports NPM_CONFIG_USERCONFIG naming it.
  const runnerTemp = path.join(root, "runner-temp");
  fs.mkdirSync(runnerTemp, { recursive: true });
  // BYTE FOR BYTE what setup-node writes at the pinned SHA: `authString + os.EOL + registryString`,
  // and nothing else. Read from the action's own source — no always-auth, no comments, no blanks.
  fs.writeFileSync(path.join(runnerTemp, ".npmrc"),
    ['//registry.npmjs.org/:_authToken=${NODE_AUTH_TOKEN}',
     "registry=https://registry.npmjs.org/"].join("\n"));
  const baseEnv = {
    PATH: [path.dirname(process.execPath), "/usr/bin", "/bin"].join(path.delimiter),
    RUNNER_TEMP: runnerTemp,
    // HOME alone, and deliberately no `npm_config_*` of any kind: the guard closes that whole
    // namespace, so a fixture that set `npm_config_cache` to place the cache would be refused by the
    // very control it is testing — measured, every guarded row refused on `npm_config_cache` before
    // this was removed. HOME lives outside the package, so npm's default `$HOME/.npm` is already out
    // of the tree `npm publish --dry-run` packs.
    HOME: home,
  };
  const launch = (argv, extra) => {
    for (const marker of ["RAN.marker", "HIJACKED.marker"]) fs.rmSync(path.join(dir, marker), { force: true });
    let status = 0;
    try {
      execFileSync(npm, argv, { cwd: dir, env: { ...baseEnv, ...extra }, stdio: "pipe", timeout: 300_000 });
    } catch (e) { status = typeof e.status === "number" ? e.status : -1; }
    const marker = path.join(dir, "RAN.marker");
    return {
      status,
      ran: fs.existsSync(marker) ? JSON.parse(fs.readFileSync(marker, "utf8")) : null,
      hijacked: fs.existsSync(path.join(dir, "HIJACKED.marker")),
    };
  };
  // The guarded launch is the shipped one: the workflow's own guard command, then npm.
  const launchGuarded = (argv, extra) => {
    for (const m of ["RAN.marker", "HIJACKED.marker"]) fs.rmSync(path.join(dir, m), { force: true });
    const guard = evidenceLaunchGuardCommand().split(" ").slice(1);
    let status = 0, stderr = "";
    try {
      execFileSync(process.execPath, [path.join(REPO, guard[0]), guard[1], npm, ...argv],
        { cwd: dir, env: { ...baseEnv, ...extra }, stdio: "pipe", timeout: 300_000 });
    } catch (e) {
      status = typeof e.status === "number" ? e.status : -1;
      stderr = String(e.stderr ?? "");
    }
    const marker = path.join(dir, "RAN.marker");
    return { status, stderr,
      ran: fs.existsSync(marker) ? JSON.parse(fs.readFileSync(marker, "utf8")) : null,
      hijacked: fs.existsSync(path.join(dir, "HIJACKED.marker")) };
  };
  return { standIn, dir, home, runnerTemp, launch, launchGuarded,
    dispose: () => fs.rmSync(root, { recursive: true, force: true }) };
};

check("npm resolves a config name case-INSENSITIVELY, so the pinned flags are the control", () => {
  // ── THE REPRODUCTION THIS PINS ────────────────────────────────────────────────────────────────
  // npm strips `npm_config_` and lowercases the rest, so `NpM_CoNfIg_ScRiPt_ShElL` and
  // `npm_config_script_shell` are ONE setting to npm and TWO names to `env -u`. MEASURED on npm
  // 10.9.7 and on 11.18.0 — the two supported npm lines under measurement — with a harmless stand-in shell
  // that records that it was chosen and exits 0 without running what npm handed it:
  //     npm test               → exit 0, shell hijacked, THE TEST NEVER RAN
  //     npm run lint:knockout  → exit 0, shell hijacked, THE WORK NEVER RAN
  //     npm publish --dry-run  → exit 0, prepublishOnly SKIPPED  (NpM_CoNfIg_Ignore_Scripts=true)
  // A green step that measured nothing is the worst output this repository can produce, and the
  // `env -u` prefix could not see any of it.
  //
  // The fix is not a longer list of names — a 23-character name has 2^18 casings. npm's documented
  // precedence puts command-line flags above every environment spelling and every rc file, so the
  // settings are pinned in argv, which has no casing to attack.
  //
  // SCOPE OF THIS CASE: script-shell and ignore-scripts ONLY. node-options is proven separately with
  // a DISJOINT hostile set, so that neither pin can stand in for the other's proof.
  const fixture = npmCasingFixture();
  try {
    const HOSTILE = { NpM_CoNfIg_ScRiPt_ShElL: fixture.standIn, NpM_CoNfIg_Ignore_Scripts: "true" };
    const flags = evidenceNpmPrecedenceFlags().split(" ");
    for (const [label, argv] of [
      ["npm test", ["test"]],
      ["npm run lint:knockout", ["run", "lint:knockout"]],
      ["npm publish --dry-run", ["publish", "--dry-run"]],
    ]) {
      // ANTI-VACUITY: without the flags this environment really does produce a green launch that
      // measured nothing. If this stops being true the proof below is proving nothing.
      const undefended = fixture.launch(argv, HOSTILE);
      assert.equal(undefended.status, 0, `${label}: the reproduction no longer exits 0 — this proof has gone vacuous`);
      assert.equal(undefended.ran, null,
        `${label}: the mixed-case spelling no longer suppresses the real work — this proof has gone vacuous`);

      // THE CONTROL: the same environment, with the settings pinned in argv.
      const defended = fixture.launch([...argv, ...flags], HOSTILE);
      assert.equal(defended.status, 0, `${label}: the pinned launch did not succeed`);
      assert.notEqual(defended.ran, null,
        `${label}: a mixed-case npm_config_* spelling still decides the setting despite the pinned flags`);
      assert.equal(defended.hijacked, false, `${label}: the script shell was still replaced from the environment`);

      // …and the pin is npm's OWN default, so a clean runner is unchanged. A "fix" that only worked
      // by altering ordinary behaviour would be paid for on every honest run.
      const clean = fixture.launch([...argv, ...flags], {});
      assert.equal(clean.status, 0, `${label}: the pinned flags made an ordinary launch fail`);
      assert.notEqual(clean.ran, null, `${label}: the pinned flags changed behaviour on a CLEAN runner`);
      assert.equal(clean.hijacked, false, `${label}: a clean launch reported a hijack`);
    }
  } finally { fixture.dispose(); }
});

check("the node-options pin is the only thing keeping a mixed-case spelling out of NODE_OPTIONS", () => {
  // ── THE REPRODUCTION THIS PINS ────────────────────────────────────────────────────────────────
  // `npm_config_node_options` is the one npm setting that becomes a NODE flag: npm hands it to the
  // script child as NODE_OPTIONS, which is how a config name reaches the evidence process itself.
  // MEASURED with `NpM_CoNfIg_NoDe_OpTiOnS=--title=pwned`, a harmless payload the child can observe:
  //     no pin  → the child ran with NODE_OPTIONS="--title=pwned" and process.title "pwned"
  //     pinned  → the child ran with NODE_OPTIONS absent and process.title "node"
  //
  // The hostile set here is DISJOINT from the case above: no script-shell, no ignore-scripts. Those
  // two would suppress the child entirely, and a proof that dies because the child never ran cannot
  // tell anyone whether the node-options pin does anything at all.
  const fixture = npmCasingFixture();
  try {
    const HOSTILE = { NpM_CoNfIg_NoDe_OpTiOnS: "--title=pwned" };
    const flags = evidenceNpmPrecedenceFlags().split(" ");
    for (const [label, argv] of [["npm test", ["test"]], ["npm run lint:knockout", ["run", "lint:knockout"]]]) {
      // ANTI-VACUITY: the payload really does reach the child when nothing pins the setting.
      const undefended = fixture.launch(argv, HOSTILE);
      assert.equal(undefended.status, 0, `${label}: the reproduction no longer exits 0 — this proof has gone vacuous`);
      assert.equal(undefended.ran?.NODE_OPTIONS, "--title=pwned",
        `${label}: a mixed-case npm_config_node_options no longer reaches the child — this proof has gone vacuous`);
      assert.equal(undefended.ran?.title, "pwned",
        `${label}: the payload no longer takes effect in the child — this proof has gone vacuous`);

      // THE CONTROL.
      const defended = fixture.launch([...argv, ...flags], HOSTILE);
      assert.equal(defended.status, 0, `${label}: the pinned launch did not succeed`);
      assert.equal(defended.ran?.NODE_OPTIONS, null,
        `${label}: the evidence child still inherited NODE_OPTIONS from a mixed-case npm config spelling`);
      assert.equal(defended.ran?.title, "node", `${label}: the injected payload still took effect in the child`);

      const clean = fixture.launch([...argv, ...flags], {});
      assert.equal(clean.status, 0, `${label}: the pinned flags made an ordinary launch fail`);
      assert.equal(clean.ran?.NODE_OPTIONS, null, `${label}: a CLEAN launch handed the child a NODE_OPTIONS`);
    }
  } finally { fixture.dispose(); }
});

check("the sole knockout launch is sharded by GitHub's own job index, and nothing else is", () => {
  // ── WHY THIS IS SEPARATE FROM THE GENERIC LAUNCH CHECK ────────────────────────────────────────
  // The generic check above admits the shard suffix OPTIONALLY, because four of the five evidence
  // launches must not carry it. That optionality means removing `-- --shard …` from the sweep would
  // still satisfy it — so on its own it does not make the matrix selector load-bearing. This case
  // does: it requires the EXACT strategy-derived suffix on the one launch that sweeps the registry,
  // and requires that no second, unsharded sweep launch exists anywhere.
  //
  // A serial sweep is the failure this whole repair is about: run 32853985529 job 97821365624 was
  // cancelled at its ceiling with the registry unmeasured.
  const SUFFIX = "-- --shard ${{ strategy.job-index }}/${{ strategy.job-total }}";
  const files = [".github/workflows/ci.yml"];
  const sweepLaunches = [];
  for (const file of files) {
    fs.readFileSync(path.join(REPO, file), "utf8").split("\n").forEach((line, index) => {
      if (line.trimStart().startsWith("run: ") && line.includes("npm run lint:knockout")) {
        sweepLaunches.push({ file, line: index + 1, text: line.trimEnd() });
      }
    });
  }
  assert.equal(sweepLaunches.length, 1,
    `expected exactly one knockout sweep launch, found ${sweepLaunches.length}: ${JSON.stringify(sweepLaunches.map((l) => `${l.file}:${l.line}`))}`);

  const [sweep] = sweepLaunches;
  assert.ok(sweep.text.endsWith(SUFFIX),
    `the sweep launch does not end with the exact strategy-derived shard suffix, so the matrix selector is not load-bearing:\n  ${sweep.text}`);
  // The coordinate must come from GitHub. A literal index/total here would be a second registry of
  // shard numbers to keep in step with the matrix, which is the class of hand-kept list this file
  // keeps deleting.
  assert.match(sweep.text, /--shard \$\{\{ strategy\.job-index \}\}\/\$\{\{ strategy\.job-total \}\}/,
    `the shard coordinate is not derived from GitHub's strategy context:\n  ${sweep.text}`);
  assert.doesNotMatch(sweep.text, /--shard \d/, "the shard coordinate is hard-coded");

  // The job that carries it must be a real parallel matrix whose siblings survive a finding.
  const ci = fs.readFileSync(path.join(REPO, ".github/workflows/ci.yml"), "utf8");
  const job = ci.slice(ci.indexOf("\n  knockout-shards:"));
  assert.notEqual(job.length, 0, "the sharded sweep job is gone");
  assert.match(job, /\n      fail-fast: false\n/,
    "fail-fast defaults to TRUE, which cancels queued and in-progress siblings after one finding — " +
    "turning one red control into however many the cancelled shards never measured");
  // The KEY, not the word: the comment above it explains why it is absent, and matching prose would
  // make this assertion impossible to document.
  assert.doesNotMatch(job, /^\s*continue-on-error:/m,
    "continue-on-error would let a finding stop making the workflow red; evidence must survive, failures must not");

  // ── ANTI-VACUITY ──────────────────────────────────────────────────────────────────────────────
  // The two ways this control is removed — deleting the suffix, or replacing GitHub's coordinate
  // with a hand-written one — must both be visible to the assertions above. Applied to a copy of the
  // real line, so this proves the checks and not a hypothetical.
  const withoutSuffix = sweep.text.slice(0, sweep.text.length - SUFFIX.length).trimEnd();
  assert.equal(withoutSuffix.endsWith(SUFFIX), false,
    "removing the suffix still satisfies the endsWith check — this case is vacuous");
  const handWritten = `${withoutSuffix} -- --shard 0/8`;
  assert.equal(handWritten.endsWith(SUFFIX), false,
    "a hand-written shard coordinate still satisfies the endsWith check — this case is vacuous");
  assert.match(handWritten, /--shard \d/,
    "a hand-written shard coordinate is not detectable by the hard-coding check — this case is vacuous");
});

check("the registry shards deterministically: exact union, no overlap, and every bad shard refuses", () => {
  // ── WHY THIS EXISTS ───────────────────────────────────────────────────────────────────────────
  // Run 32853985529 job 97821365624 was CANCELLED at the 120-minute ceiling: the 78/78 runner
  // selftest finished at 13:37:45Z and the real sweep then ran silently until the timeout. A
  // cancelled gate reports nothing, so every control in it went unmeasured. ci.yml's own instruction
  // for that situation is to SHARD the registry across jobs and never drop controls — which makes
  // the partition itself a control: if it silently dropped or duplicated an entry, the sweep would
  // still look green while measuring less than it claims.
  const mk = (id, suite, kind = "tests") => ({ id, kind, suite });
  const registry = [];
  for (let index = 0; index < 208; index += 1) {
    registry.push(mk(`entry-${index}`, [`packages/p${index % 18}`, "npm", ["test"]]));
  }

  // EXACT PARTITION at several totals, including 1 and a total that does not divide evenly.
  for (const total of [1, 2, 4, 7, 8, 13, 16]) {
    const shards = [];
    for (let index = 0; index < total; index += 1) shards.push(partitionIntoShards(registry, index, total));
    const ids = shards.flat().map((entry) => entry.id);
    assert.equal(ids.length, registry.length,
      `total=${total}: the shards cover ${ids.length} entries, the registry has ${registry.length}`);
    assert.equal(new Set(ids).size, registry.length,
      `total=${total}: an entry appears in more than one shard`);
    assert.deepEqual([...ids].sort(), registry.map((e) => e.id).sort(),
      `total=${total}: the union is not the registry`);
    // Balanced to within one entry — a shard carrying the long tail alone is the timeout again.
    const sizes = shards.map((shard) => shard.length);
    assert.ok(Math.max(...sizes) - Math.min(...sizes) <= 1,
      `total=${total}: shard sizes are unbalanced: ${JSON.stringify(sizes)}`);
    // SUITE AFFINITY, which is why this is not round-robin: a baseline is measured once per distinct
    // suite in a run, so a partition that scattered suites would multiply baseline cost by N.
    const suiteCounts = shards.map((shard) => new Set(shard.map((e) => JSON.stringify(e.suite))).size);
    assert.ok(Math.max(...suiteCounts) <= Math.ceil(18 / total) + 1,
      `total=${total}: a shard touches ${Math.max(...suiteCounts)} suites; the partition lost suite affinity`);
  }

  // DETERMINISTIC: the same inputs give the same slice, every time.
  assert.deepEqual(partitionIntoShards(registry, 2, 8).map((e) => e.id),
    partitionIntoShards(registry, 2, 8).map((e) => e.id),
    "the partition is not deterministic");

  // ANTI-VACUITY: the coverage assertions above must be able to FAIL. A partitioner that drops one
  // entry and one that duplicates an entry are both caught by the same two checks.
  const dropsOne = (entries, index, total) => partitionIntoShards(entries, index, total).slice(index === 0 ? 1 : 0);
  const duplicates = (entries, index, total) => {
    const slice = partitionIntoShards(entries, index, total);
    return index === 0 ? [...slice, entries[entries.length - 1]] : slice;
  };
  for (const [label, broken] of [["a dropped entry", dropsOne], ["a duplicated entry", duplicates]]) {
    const ids = [];
    for (let index = 0; index < 8; index += 1) ids.push(...broken(registry, index, 8).map((e) => e.id));
    const complete = ids.length === registry.length && new Set(ids).size === registry.length;
    assert.equal(complete, false, `${label} was not detected by the coverage checks above`);
  }

  // MALFORMED AND OUT-OF-RANGE refuse in the pure function, before any caller can act on them.
  for (const [index, total] of [[0, 0], [0, -1], [1, 1], [4, 4], [-1, 4], [1.5, 4], ["0", 4], [0, "4"], [NaN, 4]]) {
    assert.throws(() => partitionIntoShards(registry, index, total),
      `shard ${JSON.stringify(index)}/${JSON.stringify(total)} was accepted instead of refused`);
  }

  // AN EMPTY SLICE IS RETURNED AS EMPTY, so the caller can refuse rather than report a green job.
  assert.deepEqual(partitionIntoShards(registry, 900, 999), [],
    "a shard beyond the registry did not come back empty");

  // ── THE CLI REFUSES, END TO END, BEFORE MEASURING ANYTHING ────────────────────────────────────
  // Each of these exits non-zero without running an arm, which is the property that stops a
  // misconfigured matrix from reporting green while measuring zero controls.
  const cli = (args) => spawnSync(process.execPath, ["scripts/lint-control-knockout.mjs", ...args],
    { cwd: REPO, encoding: "utf8", timeout: 300_000, env: PUBLIC_ONLY_ENVIRONMENT });
  for (const [label, args, expected] of [
    ["unknown option", ["--not-a-knockout-option"], /unknown or unconsumed argument/],
    ["orphan value", ["orphan-value"], /unknown or unconsumed argument/],
    ["no value", ["--shard"], /--shard requires one non-option value/],
    ["not a pair", ["--shard", "3"], /--shard must be <index>\/<total>/],
    ["not numeric", ["--shard", "abc"], /--shard must be <index>\/<total>/],
    ["negative index", ["--shard", "-1/4"], /--shard must be <index>\/<total>/],
    ["fractional index", ["--shard", "1.5/4"], /--shard must be <index>\/<total>/],
    ["zero total", ["--shard", "1/0"], /index must be an integer in \[0, total\)/],
    ["index equals total", ["--shard", "8/8"], /index must be an integer in \[0, total\)/],
    ["empty slice", ["--shard", "900/999"], /0 runnable entries in this slice/],
    ["duplicate selector", ["--shard", "0/4", "--shard", "1/4"], /supplied exactly once/],
    ["duplicate only", ["--only", "one", "--only", "two"], /supplied exactly once/],
    ["with --only", ["--shard", "0/4", "--only", "any-id"], /cannot be combined with --only/],
    ["mixed print mode", ["--print-suite-packages", "--warn"], /must be used alone/],
    ["unsupported dependency selector", ["--requires", "external-source"], /--requires is not supported/],
  ]) {
    const result = cli(args);
    assert.notEqual(result.status, 0, `${label}: the CLI accepted ${JSON.stringify(args)}`);
    assert.match(`${result.stdout ?? ""}${result.stderr ?? ""}`, expected,
      `${label}: unexpected refusal text for ${JSON.stringify(args)}`);
  }
});

check("the exported public registry snapshot is source-only and closed", () => {
  const snapshot = knockoutRegistrySnapshot();
  assert.deepEqual(Object.keys(snapshot).sort(), ["proofInventory", "registry"]);
  assert.equal(Object.isFrozen(snapshot), true);
  assert.ok(Array.isArray(snapshot.registry) && snapshot.registry.length > 0,
    "the exported public registry is empty");
  assert.equal(snapshot.registry.some((entry) => Object.hasOwn(entry, "requires")), false,
    "the public registry exports an external source dependency selector");
  assert.doesNotThrow(() => validateKnockoutRegistry(snapshot.registry));

  const boundaryGates = snapshot.registry.filter((entry) =>
    entry.gateId === "boundary-selftest" ||
    entry.id === "boundary-successful-operations-emit-provenance-terminal");
  assert.equal(boundaryGates.length, 15,
    "the reviewed Task3 plus Task4 boundary provenance frontier changed");
  assert.equal(boundaryGates.every((entry) => entry.expectedGateProvenance !== undefined), true,
    "a reviewed boundary gate can receive credit without candidate-bound provenance");

  const setupIntegrity = snapshot.registry.filter((entry) => entry.expectedSetupIntegrity !== undefined);
  assert.deepEqual(setupIntegrity.map((entry) => entry.id).sort(), [
    "boundary-arm-case-plan-digest-rejects-equal-count-substitution",
    "boundary-spool-arm-case-plan-digest-rejects-equal-count-substitution",
  ]);
  for (const entry of setupIntegrity) {
    assert.equal(entry.expectedSetupIntegrity.idSubstitution.from, entry.find,
      `${entry.id}: setup-integrity source binding differs from the knockout mutation`);
    assert.equal(entry.expectedSetupIntegrity.idSubstitution.to, entry.replace,
      `${entry.id}: setup-integrity target binding differs from the knockout mutation`);
  }
});

check("sharding partitions the DEPENDENCY-RUNNABLE registry, never the declared one", () => {
  // A shard slices what `partitionByDependency` already decided is runnable. An entry whose declared
  // dependency is absent must stay SETUP_FAILED and appear in NO shard — being handed to a shard
  // would turn "not measured because a dependency is missing" into "measured and passed", which is
  // the exact substitution the dependency partition exists to prevent.
  const withDep = (id, requires) => ({ id, kind: "tests", suite: ["packages/p", "npm", ["test"]], requires });
  const registry = [
    withDep("public-1", undefined), withDep("dependent-1", ["external-source"]),
    withDep("public-2", undefined), withDep("dependent-2", ["external-source"]),
    withDep("public-3", undefined),
  ];
  const absent = { "external-source": () => null };
  const { runnable, setupFailed } = partitionByDependency(registry, REPO, absent);
  assert.deepEqual(runnable.map((e) => e.id), ["public-1", "public-2", "public-3"]);
  assert.deepEqual(setupFailed.map((e) => e.id), ["dependent-1", "dependent-2"]);

  const sharded = [];
  for (let index = 0; index < 3; index += 1) sharded.push(...partitionIntoShards(runnable, index, 3).map((e) => e.id));
  assert.deepEqual(sharded.sort(), ["public-1", "public-2", "public-3"],
    "the shards do not cover exactly the dependency-runnable entries");
  for (const missing of setupFailed) {
    assert.equal(sharded.includes(missing.id), false,
      `${missing.id} is SETUP_FAILED yet was assigned to a shard, which would score it as measured`);
  }
});

check("the preparation planner orders a synthetic file: chain, and fails closed on every bad plan", () => {
  // INDEPENDENT OF THE LIVE REPOSITORY, on purpose. Read against this repo alone the planner largely
  // proves itself: the answer it gives is the answer the assertions are written from. These fixtures
  // are built here, so the expected order is known before the planner is asked, and each negative
  // case is a shape the planner must refuse rather than a shape that happens not to occur today.
  const workspace = scratch("plan-fixture-");
  const write = (root, rel, value) => {
    const file = path.join(root, rel);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, typeof value === "string" ? value : JSON.stringify(value));
  };
  const pkg = (name, extra = {}) => ({ name, version: "1.0.0", ...extra });
  const link = (deps) => ({ dependencies: Object.fromEntries(deps.map((d) => [d.replace("packages/", "noa-"), `file:../${d.replace("packages/", "")}`])) });

  // a  <- b  <- c, where c is SOURCE-ONLY (no build script) and holds the proof file.
  const root = path.join(workspace, "chain");
  write(root, "packages/a/package.json", pkg("noa-a", { scripts: { build: "tsc -p tsconfig.json" } }));
  write(root, "packages/b/package.json", pkg("noa-b", { scripts: { build: "tsc -p tsconfig.json" }, ...link(["packages/a"]) }));
  write(root, "packages/c/package.json", pkg("noa-c", link(["packages/b"])));
  const plan = proofPreparationPlan(root, ["packages/c/test/only.test.ts"]);

  // ORDER: a dependency is prepared before whatever links it, transitively — c pulls b, b pulls a.
  assert.deepEqual(plan.map((entry) => entry.cwd), ["packages/a", "packages/b", "packages/c"],
    `the planner did not order the file: chain dependency-first: ${JSON.stringify(plan)}`);
  // SOURCE-ONLY: c is installed with no build action of its own; its siblings' entries do that work.
  assert.deepEqual(plan.map((entry) => entry.actions), [["build"], ["build"], []],
    `a source-only package must carry no build action: ${JSON.stringify(plan)}`);

  // NEGATIVE, and the reason the order assertion above is not self-fulfilling: reverse the link and
  // the expected order reverses with it. A planner that emitted a fixed or alphabetical order would
  // pass the case above and fail this one.
  const reversed = path.join(workspace, "reversed");
  write(reversed, "packages/a/package.json", pkg("noa-a", { scripts: { build: "tsc -p tsconfig.json" }, ...link(["packages/b"]) }));
  write(reversed, "packages/b/package.json", pkg("noa-b", { scripts: { build: "tsc -p tsconfig.json" } }));
  write(reversed, "packages/c/package.json", pkg("noa-c", link(["packages/a"])));
  assert.deepEqual(proofPreparationPlan(reversed, ["packages/c/test/only.test.ts"]).map((e) => e.cwd),
    ["packages/b", "packages/a", "packages/c"],
    "the planner's order does not follow the links; it is producing a fixed order");

  // THE CLEAN-CHECKOUT REGRESSION: a suite package can start source from an OPTIONAL local package,
  // whose own local dependency must be installed too. Preparing only the direct suite directory made
  // mcp-proxy's signer scenario die before node:test completed, while a populated developer tree hid
  // the omission. This fixture uses all three hops and the same dependency fields as that incident.
  const suiteClosure = path.join(workspace, "suite-closure");
  write(suiteClosure, "packages/adapter/package.json", pkg("noa-adapter"));
  write(suiteClosure, "packages/sidecar/package.json", pkg("noa-sidecar", {
    dependencies: { "noa-adapter": "file:../adapter" },
  }));
  write(suiteClosure, "packages/proxy/package.json", pkg("noa-proxy", {
    dependencies: { "noa-adapter": "file:../adapter" },
    optionalDependencies: { "noa-sidecar": "file:../sidecar" },
  }));
  assert.deepEqual(localPackageDependencyOrder(suiteClosure, ["packages/proxy"]),
    ["packages/adapter", "packages/sidecar", "packages/proxy"],
    "a suite package's transitive optional local dependency closure was not ordered for preparation");

  // `build:deps` is never emitted, even when a package declares one.
  const withDeps = path.join(workspace, "withdeps");
  write(withDeps, "packages/a/package.json", pkg("noa-a", { scripts: { build: "tsc -p tsconfig.json", "build:deps": "npm --prefix ../b run build" } }));
  assert.deepEqual(proofPreparationPlan(withDeps, ["packages/a/test/x.test.ts"])[0].actions, ["build"],
    "the planner emitted build:deps, which rebuilds siblings this plan already builds itself");

  // FAIL CLOSED, one shape per case.
  const cycle = path.join(workspace, "cycle");
  write(cycle, "packages/a/package.json", pkg("noa-a", link(["packages/b"])));
  write(cycle, "packages/b/package.json", pkg("noa-b", link(["packages/a"])));
  assert.throws(() => proofPreparationPlan(cycle, ["packages/a/test/x.test.ts"]), /cycle/,
    "a local package dependency cycle was planned instead of refused");

  const unsafe = path.join(workspace, "unsafe");
  write(unsafe, "packages/a/package.json", pkg("noa-a", { dependencies: { "noa-bad": "file:../bad.name" } }));
  write(unsafe, "packages/bad.name/package.json", pkg("noa-bad"));
  assert.throws(() => proofPreparationPlan(unsafe, ["packages/a/test/x.test.ts"]), /exact packages\/<name>/,
    "a package path that is not an exact packages/<name> was planned instead of refused");

  const empty = path.join(workspace, "empty");
  write(empty, "packages/a/package.json", pkg("noa-a"));
  assert.throws(() => proofPreparationPlan(empty, []), /empty/,
    "an empty plan was returned instead of refused");
  assert.throws(() => proofPreparationPlan(empty, ["not-a-package-path.test.ts"]), /empty/,
    "a file list that resolves to no package produced a plan instead of a refusal");

  const malformed = path.join(workspace, "malformed");
  write(malformed, "packages/a/package.json", "{ this is not json");
  assert.throws(() => proofPreparationPlan(malformed, ["packages/a/test/x.test.ts"]),
    "a manifest that is not JSON was planned instead of refused");

  // ── LOCAL-LINK CLOSURE: exactly one omission is allowed ───────────────────────────────────────
  // The repository root is separately authoritative, so `file:../..` is the ONE link a plan may pass
  // over. Everything else must be traversed or refused; an earlier shape kept only links whose
  // lexical target began `packages/` and dropped the rest in silence, which hid an outside-root
  // target and a self-link alike.
  const rootLink = path.join(workspace, "rootlink");
  write(rootLink, "package.json", pkg("noa-root"));
  write(rootLink, "packages/a/package.json", pkg("noa-a", { dependencies: { "noa-receipt": "file:../.." } }));
  assert.deepEqual(proofPreparationPlan(rootLink, ["packages/a/test/x.test.ts"]).map((e) => e.cwd), ["packages/a"],
    "the exact repository-root link is no longer accepted as the one allowed omission");

  const outsideRoot = path.join(workspace, "outside");
  write(outsideRoot, "packages/a/package.json", pkg("noa-a", { dependencies: { "noa-elsewhere": "file:../../../elsewhere" } }));
  assert.throws(() => proofPreparationPlan(outsideRoot, ["packages/a/test/x.test.ts"]), /outside this repository/,
    "a file: target outside the repository was ignored instead of refused");

  // Inside this root but not a package directory: a different refusal, and the message says which.
  // A non-exact path UNDER packages/ is already covered by the `bad.name` case above, so it is not
  // repeated here.
  const insideNonPackages = path.join(workspace, "insidenonpackages");
  write(insideNonPackages, "packages/a/package.json", pkg("noa-a", { dependencies: { "noa-vendor": "file:../../vendor" } }));
  write(insideNonPackages, "vendor/package.json", pkg("noa-vendor"));
  assert.throws(() => proofPreparationPlan(insideNonPackages, ["packages/a/test/x.test.ts"]),
    /neither the repository root nor an exact packages\/<name>/,
    "an in-repo file: target outside packages/ was ignored instead of refused");

  const selfLink = path.join(workspace, "selflink");
  write(selfLink, "packages/a/package.json", pkg("noa-a", { dependencies: { "noa-a": "file:../a" } }));
  assert.throws(() => proofPreparationPlan(selfLink, ["packages/a/test/x.test.ts"]), /links noa-a to itself/,
    "a package linking itself disappeared instead of failing");

  fs.rmSync(workspace, { recursive: true, force: true });
});

check("the preparation runner validates the WHOLE plan before it installs anything, and refuses bad plans", () => {
  // THE REAL RUNNER, not a copy of it. `scripts/prepare-proof-packages.mjs` is executed against
  // crafted derivations with `npm` and the two derivers stubbed, so nothing is installed and no proof
  // is run. A second validator written here would be a second opinion about what the runner accepts,
  // which is the duplication this repair exists to remove.
  const workspace = scratch("prep-runner-");
  const bin = path.join(workspace, "bin");
  const scripts = path.join(workspace, "scripts");
  fs.mkdirSync(bin, { recursive: true });
  fs.mkdirSync(scripts, { recursive: true });
  fs.copyFileSync(path.join(REPO, "scripts/prepare-proof-packages.mjs"), path.join(scripts, "prepare-proof-packages.mjs"));
  // The derivers are replaced by fixtures the case controls; the runner shells out to them by path.
  fs.writeFileSync(path.join(scripts, "lint-resolver-parity.mjs"),
    'import fs from "node:fs";process.stdout.write(fs.readFileSync(process.env.PLAN_FIXTURE,"utf8"));\n');
  fs.writeFileSync(path.join(scripts, "lint-control-knockout.mjs"),
    'import fs from "node:fs";process.stdout.write(fs.readFileSync(process.env.SUITE_FIXTURE,"utf8"));\n');
  fs.writeFileSync(path.join(bin, "npm"), '#!/bin/sh\necho "$@" >> "$NPM_LOG"\nexit 0\n', { mode: 0o755 });
  for (const name of ["gate", "evidence", "relay"]) {
    fs.mkdirSync(path.join(workspace, "packages", name), { recursive: true });
    fs.writeFileSync(path.join(workspace, "packages", name, "package.json"), "{}");
  }

  const run = (planText, suiteText = "packages/relay\n") => {
    const planFixture = path.join(workspace, "plan.tsv");
    const suiteFixture = path.join(workspace, "suites.txt");
    const npmLog = path.join(workspace, "npm.log");
    fs.writeFileSync(planFixture, planText);
    fs.writeFileSync(suiteFixture, suiteText);
    fs.writeFileSync(npmLog, "");
    const result = spawnSync(process.execPath, [path.join(scripts, "prepare-proof-packages.mjs")], {
      cwd: workspace, encoding: "utf8", timeout: 120_000,
      env: { PATH: `${bin}:/usr/bin:/bin`, HOME: workspace, PLAN_FIXTURE: planFixture,
             SUITE_FIXTURE: suiteFixture, NPM_LOG: npmLog },
    });
    return { status: result.status, output: `${result.stdout ?? ""}${result.stderr ?? ""}`,
             npm: fs.readFileSync(npmLog, "utf8").split("\n").filter(Boolean) };
  };

  // ANTI-VACUITY: a well-formed plan is ACCEPTED, and its npm calls arrive in the required order —
  // every install first, then the builds. Without this every refusal below could be the harness.
  const good = run("packages/evidence\tbuild\npackages/gate\tbuild\n");
  assert.equal(good.status, 0, `a well-formed plan was refused, so the refusals below prove nothing:\n${good.output}`);
  const lastInstall = good.npm.map((c) => / ci$/.test(c)).lastIndexOf(true);
  const firstBuild = good.npm.findIndex((c) => /run build$/.test(c));
  assert.ok(lastInstall !== -1 && firstBuild !== -1 && lastInstall < firstBuild,
    `installs and builds interleave: ${JSON.stringify(good.npm)}`);
  // The suite package is prepared too, and never built — nothing asks for its compiled output.
  assert.ok(good.npm.some((c) => c.includes("packages/relay ci")), `the suite package was not installed: ${JSON.stringify(good.npm)}`);
  assert.equal(good.npm.some((c) => c.includes("packages/relay run")), false, "a suite package was built without the plan asking");

  for (const [label, plan, expected] of [
    ["an empty plan", "", /empty preparation plan/],
    ["a duplicated package", "packages/gate\tbuild\npackages/gate\tbuild\n", /names packages\/gate more than once/],
    ["a traversal path", "packages/../etc\tbuild\n", /not an exact packages\/<name>/],
    ["an absolute path", "/etc\tbuild\n", /not an exact packages\/<name>/],
    ["a nested path", "packages/gate/sub\tbuild\n", /not an exact packages\/<name>/],
    ["an unknown action", "packages/gate\tpublish\n", /unknown action/],
    ["a build:deps action", "packages/gate\tbuild:deps\n", /unknown action/],
    ["a repeated build action", "packages/gate\tbuild\tbuild\n", /repeats an action/],
    ["a path that is not a package", "packages/absent\tbuild\n", /not an exact packages\/<name>|is not a package/],
  ]) {
    const result = run(plan);
    assert.notEqual(result.status, 0, `${label} was accepted`);
    assert.match(result.output, expected, `${label}: unexpected refusal:\n${result.output}`);
    assert.deepEqual(result.npm, [], `${label} still reached npm: ${JSON.stringify(result.npm)}`);
  }

  // A late bad line stops everything: validation is whole-plan, before any install.
  const lateBad = run("packages/gate\tbuild\npackages/evidence\tbuild\npackages/../etc\tbuild\n");
  assert.notEqual(lateBad.status, 0, "a plan whose last line is unsafe was accepted");
  assert.deepEqual(lateBad.npm, [], `a late unsafe line was refused only after installing earlier ones: ${JSON.stringify(lateBad.npm)}`);

  // An unsafe SUITE package refuses too, and before any install.
  const badSuite = run("packages/gate\tbuild\n", "packages/../etc\n");
  assert.notEqual(badSuite.status, 0, "an unsafe suite package was accepted");
  assert.deepEqual(badSuite.npm, [], "an unsafe suite package still reached npm");

  fs.rmSync(workspace, { recursive: true, force: true });
});

check("the proof and knockout consumers prepare through the ONE runner before they execute", () => {
  // ── THE DEFECT THIS PINS ──────────────────────────────────────────────────────────────────────
  // Packages were once installed inside the R7 exploit step, several steps BELOW the proof steps that
  // resolve through them; then a hand-kept list omitted `packages/evidence` and CI died on
  // `ENOENT ... packages/evidence/node_modules/typescript/bin/tsc`; then it omitted
  // `packages/e2e-demo`, whose constructed surface proof runs on the public lane. The preparation is
  // now ONE runner that derives both sets, and this case holds the workflow to calling it — once per
  // job, before anything that needs a prepared tree.
  const lines = fs.readFileSync(path.join(REPO, ".github/workflows/ci.yml"), "utf8").split("\n");
  const RUNNER = "node scripts/prepare-proof-packages.mjs";

  // Parse RUN VALUES, including block bodies. The previous shallow parser saw only scalar `run:`
  // values; a copied installer inside `run: |` was therefore invisible and could satisfy this test.
  const runs = [];
  let job = null;
  let block = null;
  lines.forEach((raw, index) => {
    const indent = /^(\s*)/.exec(raw)[1].length;
    const header = /^ {2}([a-z0-9-]+):$/.exec(raw);
    if (header !== null) {
      job = header[1];
      block = null;
    }
    if (block !== null && raw.trim() !== "" && indent <= block.keyIndent) block = null;
    const key = /^(\s*)(?:- )?run:\s*(.*)$/.exec(raw);
    if (key !== null) {
      const value = key[2].trim();
      if (["", "|", ">", "|-", ">-"].includes(value)) {
        block = { job, line: index + 1, keyIndent: key[1].length, commands: [] };
        runs.push(block);
      } else {
        block = null;
        runs.push({ job, line: index + 1, keyIndent: key[1].length, commands: [value] });
      }
      return;
    }
    if (block !== null && raw.trim() !== "" && indent > block.keyIndent && !raw.trimStart().startsWith("#")) {
      block.commands.push(raw.trim());
    }
  });

  const commands = runs.flatMap((run) => run.commands.map((text) => ({ job: run.job, line: run.line, text })));
  const calls = commands.filter(({ text }) => text.includes(RUNNER));
  const consumers = commands.filter(({ text }) =>
    /node scripts\/lib\/proof-resolve\.selftest\.mjs|node scripts\/lint-resolver-parity\.mjs|npm run lint:knockout/.test(text));

  // ONE CALL PER JOB THAT NEEDS A PREPARED TREE, and both of them call the same line.
  const byJob = new Map();
  for (const call of calls) byJob.set(call.job, [...(byJob.get(call.job) ?? []), call.line]);
  assert.deepEqual([...byJob.keys()].sort(), ["knockout-shards", "test"],
    `expected the preparation runner in exactly the test and knockout-shards jobs, found ${JSON.stringify([...byJob.keys()])}`);
  for (const [name, at] of byJob) {
    assert.equal(at.length, 1, `${name} calls the preparation runner ${at.length} times: ${JSON.stringify(at)}`);
  }

  // ORDER: preparation precedes both public proof consumers and the sharded knockout launch.
  assert.equal(consumers.length, 3,
    `expected two proof consumers and one knockout consumer, found ${JSON.stringify(consumers)}`);
  for (const consumer of consumers) {
    const prepared = byJob.get(consumer.job);
    assert.ok(prepared !== undefined && prepared[0] < consumer.line,
      `ci.yml:${consumer.line}: a consumer in job ${consumer.job} runs before its tree is prepared`);
  }

  // NO SECOND INSTALLER FOR A DERIVED PACKAGE in either consumer job. Derive the set from the same
  // two authorities the runner uses; tsa-anchor remains a job-owned dependency and is not a false
  // positive merely because its tests also live in this workflow.
  const proofPlan = execFileSync(process.execPath,
    ["scripts/lint-resolver-parity.mjs", "--print-proof-packages"],
    { cwd: REPO, encoding: "utf8", timeout: 300_000 }).trim().split("\n").filter(Boolean)
    .map((line) => line.split("\t")[0]);
  const suitePackages = execFileSync(process.execPath,
    ["scripts/lint-control-knockout.mjs", "--print-suite-packages"],
    { cwd: REPO, encoding: "utf8", timeout: 300_000, env: PUBLIC_ONLY_ENVIRONMENT })
    .trim().split("\n").filter(Boolean);
  assert.equal(suitePackages.includes("packages/signer-sidecar"), true,
    "the mcp-proxy suite's local signer-sidecar dependency is absent from clean-tree preparation");
  assert.ok(suitePackages.indexOf("packages/signer-sidecar") < suitePackages.indexOf("packages/mcp-proxy"),
    "the signer-sidecar dependency is not prepared before the mcp-proxy suite that starts it");
  const preparedPackages = new Set([...proofPlan, ...suitePackages]);
  assert.notEqual(preparedPackages.size, 0, "the derived package set is empty, so duplicate detection is vacuous");

  const installsFromRuns = (subjectRuns) => {
    const found = [];
    for (const run of subjectRuns) {
      let cwd = ".";
      for (const raw of run.commands) {
        for (const segment of raw.split(/&&|\|\||;/).map((part) => part.trim()).filter(Boolean)) {
          const cd = /^cd\s+(?:"([^"]+)"|'([^']+)'|(\S+))$/.exec(segment);
          if (cd !== null) {
            cwd = cd[1] ?? cd[2] ?? cd[3];
            continue;
          }
          const prefixed = /npm\s+--prefix\s+(?:"([^"]+)"|'([^']+)'|(\S+))\s+ci(?:\s|$)/.exec(segment);
          if (prefixed !== null) found.push({ job: run.job, line: run.line, cwd: prefixed[1] ?? prefixed[2] ?? prefixed[3] });
          else if (/^npm\s+ci(?:\s|$)/.test(segment)) found.push({ job: run.job, line: run.line, cwd });
        }
      }
    }
    return found;
  };
  const consumerRuns = runs.filter((run) => run.job === "test" || run.job === "knockout-shards");
  const installs = installsFromRuns(consumerRuns);
  const strays = installs.filter((install) => preparedPackages.has(install.cwd));
  assert.deepEqual(strays, [],
    `a derived package is installed outside the preparation runner: ${JSON.stringify(strays)}`);

  // ANTI-VACUITY: the parser sees scalar and block bodies, and the same detector rejects a synthetic
  // copied installer for a package derived above.
  assert.ok(calls.length >= 2, "the parser found fewer runner calls than the workflow contains");
  assert.equal(installs.some((i) => i.cwd === "packages/tsa-anchor"), true,
    "the parser is not seeing npm ci inside block run bodies");
  const samplePrepared = [...preparedPackages][0];
  const synthetic = installsFromRuns([{ job: "test", line: 1, commands: [`npm --prefix ${samplePrepared} ci`] }]);
  assert.equal(synthetic.some((install) => preparedPackages.has(install.cwd)), true,
    "a copied installer for a derived package is not detectable — the duplicate check is vacuous");
});

check("the pre-npm guard closes npm's whole config namespace before npm exists", () => {
  // ── THE REPRODUCTIONS THIS PINS, AND WHY THE SHAPE CHANGED TWICE ──────────────────────────────
  // The real publish lane is `npm publish` -> `prepublishOnly` -> `npm test` -> the evidence Node
  // process, so the argv we control sits ONE npm level above the evidence, and an EMPTY pin loses to
  // a non-empty hostile value at the second npm. MEASURED on npm 10.9.7 and on 11.18.0 with every
  // argv pin in place:
  //
  //   NpM_CoNfIg_NoDe_OpTiOnS=--import=<module>   exit 0, ATTACKER RAN, EVIDENCE DID NOT
  //   NpM_CoNfIg_UsErCoNfIg -> rc with node-options   exit 0, ATTACKER RAN, EVIDENCE DID NOT
  //   NpM_CoNfIg_GlObAlCoNfIg -> the same rc           exit 0, ATTACKER RAN, EVIDENCE DID NOT
  //   a project .npmrc beside package.json             exit 0, ATTACKER RAN, EVIDENCE DID NOT
  //   NpM_CoNfIg_DrY_RuN=true                          `npm publish` reported "(dry-run)" and exited
  //                                                    0 against a registry that was not listening —
  //                                                    a lane that reports success having published
  //                                                    nothing at all.
  //
  // Two lessons, both paid for. First, a refusal made INSIDE the evidence process is worthless here:
  // `--import` runs before any application code, so the attacker owns that process before a line of
  // this repository executes, and a control that then reports on itself is forbidden. Second, a
  // denylist of SETTINGS fails for the same reason a list of casings did — npm has hundreds, and
  // dry-run was not on anybody's list. So the boundary stands in the first Node process on the
  // launch line, before any npm, and closes the whole `npm_config_*` namespace rather than naming
  // members of it. Node is the right place to stand because it reads NODE_OPTIONS and nothing else,
  // which makes every one of those spellings inert to it.
  const fixture = npmCasingFixture();
  try {
    const attacker = path.join(fixture.home, "attacker.mjs");
    const marker = path.join(fixture.home, "ATTACKER-RAN.marker");
    // Harmless: it records that it won the race and exits 0, which is exactly how a real one would
    // manufacture a green run without ever letting the evidence execute.
    fs.writeFileSync(attacker,
      `import{writeFileSync}from"node:fs";writeFileSync(${JSON.stringify(marker)},"first\\n");process.exit(0);\n`);
    const hostileRc = path.join(fixture.home, "hostile.npmrc");
    fs.writeFileSync(hostileRc, `node-options=--import=${attacker}\n`);
    const contract = { NPM_CONFIG_USERCONFIG: path.join(fixture.runnerTemp, ".npmrc") };
    const flags = evidenceNpmPrecedenceFlags().split(" ");
    const attackerRan = () => fs.existsSync(marker);
    const reset = () => fs.rmSync(marker, { force: true });
    const projectRc = path.join(fixture.dir, ".npmrc");

    // ANTI-VACUITY, measured WITHOUT the argv pins on purpose. On the flat lane a pin already
    // defeats the payload, so including it would let that pin stand in for the guard's proof.
    reset();
    const undefended = fixture.launch(["publish", "--dry-run"], { NpM_CoNfIg_NoDe_OpTiOnS: `--import=${attacker}` });
    assert.equal(undefended.status, 0, "the unguarded reproduction no longer exits 0 — this proof has gone vacuous");
    assert.equal(attackerRan(), true, "the --import payload no longer reaches the evidence process — this proof has gone vacuous");
    assert.equal(undefended.ran, null, "the attacker module no longer displaces the evidence — this proof has gone vacuous");

    // THE CONTROL: every door, refused before npm starts. Each is its own case so that a repair
    // which closes one and reopens another cannot pass.
    for (const [door, extra, expected] of [
      ["mixed-case node-options", { NpM_CoNfIg_NoDe_OpTiOnS: `--import=${attacker}` }, /NpM_CoNfIg_NoDe_OpTiOnS/],
      ["mixed-case dry-run", { NpM_CoNfIg_DrY_RuN: "true" }, /NpM_CoNfIg_DrY_RuN/],
      ["mixed-case prefix", { NpM_CoNfIg_PrEfIx: fixture.home }, /NpM_CoNfIg_PrEfIx/],
      ["mixed-case userconfig", { NpM_CoNfIg_UsErCoNfIg: hostileRc }, /NpM_CoNfIg_UsErCoNfIg/],
      ["mixed-case globalconfig", { NpM_CoNfIg_GlObAlCoNfIg: hostileRc }, /NpM_CoNfIg_GlObAlCoNfIg/],
      // The contract spelling is admitted only for the contract PATH; anywhere else it is just
      // another member of the namespace.
      ["contract spelling, wrong path", { NPM_CONFIG_USERCONFIG: hostileRc }, /NPM_CONFIG_USERCONFIG/],
    ]) {
      reset();
      const guarded = fixture.launchGuarded(["publish", "--dry-run", ...flags], { ...contract, ...extra });
      assert.notEqual(guarded.status, 0, `${door}: the guard let it through`);
      assert.equal(attackerRan(), false, `${door}: attacker code ran even through the guard`);
      assert.equal(guarded.ran, null, `${door}: an evidence process started despite the refusal`);
      assert.match(guarded.stderr, /evidence launch refused:/, `${door}: refused without saying so`);
      assert.match(guarded.stderr, expected, `${door}: the refusal does not name what it found:\n  ${guarded.stderr}`);
      // Neither the attacker's rc content nor a credential-shaped value is ever echoed.
      assert.doesNotMatch(guarded.stderr, /--import=/, `${door}: the refusal echoed attacker-controlled file content`);
    }

    // The contract file is admitted on CONTENT, and the content test is EQUALITY, not a parse. An
    // earlier version matched registry-ish and auth-ish patterns and was vacuous: it would have
    // admitted an attacker's registry, a second placeholder variable, comments, blanks and
    // duplicates. setup-node writes `authString + EOL + registryString` and nothing else, so every
    // shape below is a refusal.
    const contractRc = path.join(fixture.runnerTemp, ".npmrc");
    const pristine = fs.readFileSync(contractRc, "utf8");
    const EOL = "\n";
    for (const [shape, body, forbidden] of [
      ["an execution setting", `registry=https://registry.npmjs.org/${EOL}node-options=--import=${attacker}`, "--import="],
      ["a literal credential", `//registry.npmjs.org/:_authToken=npm_ThisIsNotARealTokenValue${EOL}registry=https://registry.npmjs.org/`, "npm_ThisIsNotARealTokenValue"],
      ["an extra always-auth line", `${pristine}${EOL}always-auth=false`, "always-auth"],
      ["a comment line", `#anything${EOL}${pristine}`, "#anything"],
      ["a blank line", pristine.replace(EOL, EOL + EOL), null],
      ["a duplicate registry line", `${pristine}${EOL}registry=https://registry.npmjs.org/`, null],
      ["somebody else's registry", `//evil.example/:_authToken=\${NODE_AUTH_TOKEN}${EOL}registry=https://evil.example/`, "evil.example"],
      ["a different placeholder variable", `//registry.npmjs.org/:_authToken=\${OTHER_TOKEN}${EOL}registry=https://registry.npmjs.org/`, "OTHER_TOKEN"],
      // The four shapes a line-wise parse would have waved through. The attestation is whole-string
      // equality precisely so "nearly right" is still wrong.
      ["nothing at all", "", null],
      ["the two lines in the wrong order", `registry=https://registry.npmjs.org/${EOL}//registry.npmjs.org/:_authToken=\${NODE_AUTH_TOKEN}`, null],
      ["one trailing newline", `${pristine}${EOL}`, null],
      ["one trailing extra line", `${pristine}${EOL}cache=/tmp`, "cache=/tmp"],
    ]) {
      reset();
      fs.writeFileSync(contractRc, body);
      try {
        const guarded = fixture.launchGuarded(["publish", "--dry-run", ...flags], contract);
        assert.notEqual(guarded.status, 0, `contract rc holding ${shape}: the guard admitted it`);
        assert.equal(attackerRan(), false, `contract rc holding ${shape}: attacker code ran`);
        assert.match(guarded.stderr, /is not byte-for-byte the two-line registry configuration setup-node writes/,
          `contract rc holding ${shape}: unexpected refusal reason:${EOL}  ${guarded.stderr}`);
        // The FILE is named, never a line of it. An rc can hold a real credential and this guard
        // must not be the thing that prints one.
        if (forbidden !== null) {
          assert.ok(!guarded.stderr.includes(forbidden),
            `contract rc holding ${shape}: the refusal echoed the file's own contents`);
        }
      } finally { fs.writeFileSync(contractRc, pristine); }
    }
    // …and the pristine file really is the exact thing setup-node writes, so the cases above are
    // rejections of DIFFERENCE rather than of a fixture that was never admissible.
    assert.equal(pristine, ['//registry.npmjs.org/:_authToken=${NODE_AUTH_TOKEN}', 'registry=https://registry.npmjs.org/'].join("\n"),
      "the fixture's contract rc is not byte-for-byte what setup-node writes — every case above proves nothing");
    // …and that claim is about somebody ELSE'S program, so it is tied to the revision of that program
    // it was read at. The CI workflow pins one setup-node SHA; if it moves, the contract must be
    // re-read from the new source rather than assumed to have survived the bump. Quarantined legacy
    // publisher workflows contain no setup action and therefore cannot stand in for this evidence.
    for (const file of ["ci.yml"]) {
      const pins = fs.readFileSync(path.join(REPO, ".github/workflows", file), "utf8")
        .split("\n").filter((line) => line.includes("actions/setup-node@"));
      assert.notEqual(pins.length, 0, `${file}: no setup-node pin found, so the rc contract is bound to nothing`);
      for (const pin of pins) {
        assert.ok(pin.includes(`actions/setup-node@${SETUP_NODE_ATTESTED_REVISION}`),
          `${file}: setup-node moved off the revision the rc contract was read from; re-read it before trusting the bytes:\n  ${pin.trim()}`);
      }
    }

    // A token contradicts the lane's own OIDC claim, and never reaches npm either way.
    reset();
    const withToken = fixture.launchGuarded(["publish", "--dry-run", ...flags], { ...contract, NODE_AUTH_TOKEN: "npm_ThisIsNotARealTokenValue" });
    assert.notEqual(withToken.status, 0, "a NODE_AUTH_TOKEN was accepted on a lane that claims to publish without one");
    assert.match(withToken.stderr, /publishes through OIDC with no token/, `unexpected refusal:${EOL}  ${withToken.stderr}`);
    assert.ok(!withToken.stderr.includes("npm_ThisIsNotARealTokenValue"), "the refusal echoed the token it refused");

    // A project rc is refused for EXISTING, not for what it says — deciding which of its lines are
    // safe is the losing game this replaced.
    reset();
    fs.writeFileSync(projectRc, `node-options=--import=${attacker}\n`);
    try {
      const guarded = fixture.launchGuarded(["publish", "--dry-run", ...flags], contract);
      assert.notEqual(guarded.status, 0, "project .npmrc: the guard let it through");
      assert.equal(attackerRan(), false, "project .npmrc: attacker code ran even through the guard");
      assert.match(guarded.stderr, /a project rc is refused outright rather than parsed/,
        `project .npmrc: unexpected refusal reason:\n  ${guarded.stderr}`);
    } finally { fs.rmSync(projectRc, { force: true }); }

    // …and the guard is transparent on the runner it is meant to run on: setup-node's own
    // configuration, in its own spelling, at its own path, passes and the work happens.
    for (const [lane, argv] of [["nested publish", ["publish", "--dry-run"]], ["flat test", ["test"]]]) {
      reset();
      const clean = fixture.launchGuarded([...argv, ...flags], contract);
      assert.equal(clean.status, 0, `${lane}: the guard made an ordinary setup-node launch fail:\n  ${clean.stderr}`);
      assert.notEqual(clean.ran, null, `${lane}: the guard suppressed an ordinary launch`);
      assert.equal(attackerRan(), false, `${lane}: a clean guarded launch ran attacker code`);
      assert.equal(clean.ran?.NODE_OPTIONS, null, `${lane}: a clean guarded launch handed the child a NODE_OPTIONS`);
      assert.equal(clean.ran?.authToken, null, `${lane}: NODE_AUTH_TOKEN reached the evidence process`);
      // npm read a file this guard OWNS, holding bytes it verified — never the path the environment
      // named. Between attesting that path and npm opening it, whoever chose it could swap it.
      assert.notEqual(clean.ran?.userconfig, path.join(fixture.runnerTemp, ".npmrc"),
        `${lane}: npm was pointed at the path the environment named instead of an owned copy`);
      assert.equal(fs.readFileSync(clean.ran.userconfig, "utf8"), fs.readFileSync(path.join(fixture.runnerTemp, ".npmrc"), "utf8"),
        `${lane}: the owned copy does not hold the bytes that were attested`);
    }

    // Exit status is the child's, and a signalled child is never mistaken for a passing one.
    const guardOnly = (args) => spawnSync(process.execPath,
      [path.join(REPO, "scripts/lib/knockout-runner.mjs"), "--launch-evidence", ...args],
      { cwd: fixture.dir, env: { PATH: process.env.PATH, HOME: fixture.home }, encoding: "utf8", timeout: 120_000 });
    assert.equal(guardOnly([process.execPath, "-e", "process.exit(0)"]).status, 0, "a passing child was not reported as passing");
    assert.equal(guardOnly([process.execPath, "-e", "process.exit(7)"]).status, 7, "the child's exit status was not propagated");
    assert.notEqual(guardOnly([process.execPath, "-e", "process.kill(process.pid,'SIGKILL')"]).status, 0,
      "a child killed by a signal was reported as passing");
    assert.notEqual(guardOnly(["/nonexistent/not-a-command"]).status, 0, "a command that never started was reported as passing");
  } finally { fixture.dispose(); }
});

check("the observer admits the script shell THIS repository pins, and nothing else that resembles it", () => {
  // ── THE REPRODUCTION THIS PINS ────────────────────────────────────────────────────────────────
  // The launch pins `--script-shell` in npm's argv; npm then exports that choice to every script
  // child as `npm_config_script_shell`, where the observer meets it again. With the pin and the
  // refusal written as two separate literals, the observer refused the value the launch had itself
  // just chosen. MEASURED on the exact shipped launch, Node 22: 617 tests, 4 FAILED, every one of
  // them "knockout observer inherited npm_config_script_shell". With the exemption: 617/617.
  //
  // The exemption is one PAIR, both halves compared by equality: the canonical spelling npm itself
  // produces, and the shared constant the argv pin is composed from. Provenance is what that
  // narrowness protects — a value that merely looks safe is not the value this repository emitted,
  // so every near miss below is still refused.
  const probe = path.join(standaloneHelperScratch("script-shell-pin-"), "probe.mjs");
  fs.writeFileSync(probe, [
    // A CHILD, so a hostile process.env never touches this selftest.
    'const [key, value] = process.argv.slice(2);',
    'if (key !== "-") process.env[key] = value;',
    `const { observeSuite } = await import(${JSON.stringify(path.join(REPO, "scripts/lib/knockout-runner.mjs"))});`,
    'const r = observeSuite(process.cwd(), [".", process.execPath, ["-e", "0"]], 20000, { kind: "tests" });',
    'console.log(JSON.stringify({ protocolError: r.protocolError ?? null }));',
  ].join("\n"));
  const refusedFor = (key, value) => {
    const out = execFileSync(process.execPath, [probe, key, value],
      { encoding: "utf8", timeout: 120_000, stdio: ["ignore", "pipe", "ignore"] });
    const error = JSON.parse(out.trim().split("\n").pop()).protocolError ?? "";
    return /knockout observer inherited/.test(error);
  };

  // The pin is read from the SAME expression the launch is built from, so this cannot drift.
  const pinned = /--script-shell=(\S+)/.exec(evidenceNpmPrecedenceFlags());
  assert.notEqual(pinned, null, "the launch no longer pins a script shell, so this exemption has no subject");
  const shell = pinned[1];

  // ANTI-VACUITY: the exemption is real — the exact pair npm hands down survives.
  assert.equal(refusedFor("npm_config_script_shell", shell), false,
    `the observer refuses ${shell}, which is the very value this repository's own launch pins`);

  // …and it is the ONLY pair admitted. Every near miss is a different pair.
  for (const [label, key, value] of [
    ["another shell entirely", "npm_config_script_shell", "/tmp/attacker-shell"],
    ["the same shell with an argument", "npm_config_script_shell", `${shell} -x`],
    ["the same name at another path", "npm_config_script_shell", "/usr/bin/sh"],
    ["the pinned value with trailing space", "npm_config_script_shell", `${shell} `],
    ["a mixed-case spelling of the safe pair", "NpM_CoNfIg_ScRiPt_ShElL", shell],
    ["an upper-case spelling of the safe pair", "NPM_CONFIG_SCRIPT_SHELL", shell],
    ["a different npm setting entirely", "npm_config_node_options", "--import=/tmp/attacker.mjs"],
  ]) {
    assert.equal(refusedFor(key, value), true,
      `${label} (${key}=${JSON.stringify(value)}) was admitted; only the exact pinned pair may be`);
  }

  // The exemption is expressed ONCE. Two literals are two opinions, and the drift between them is
  // exactly what cost 4 tests before it was one constant.
  const source = fs.readFileSync(path.join(REPO, "scripts/lib/knockout-runner.mjs"), "utf8");
  const code = source.replace(/\/\*[\s\S]*?\*\//g, "")
    .split("\n").filter((line) => !line.trim().startsWith("//")).join("\n");
  const literals = (code.match(/"\/bin\/sh"/g) ?? []).length;
  assert.equal(literals, 1,
    `the pinned script shell is written as ${literals} literal(s) in code; it must come from the one shared constant`);
});

check("the observer refuses the spelling npm would have honoured, and stays quiet on an inert one", () => {
  // The launch flags decide the SETTING; this is the fail-closed backstop that decides the RUN.
  // Both are needed: the flags stop a hijack that would prevent the observer from ever executing,
  // and the refusal stops a run whose environment is dirty in some way the flags do not cover.
  //
  // Each set is matched the way ITS OWN consumer matches, and both halves are proven here, because
  // getting either one wrong is a defect: matching npm's names exactly was BLIND (the mixed-case
  // spelling walked past), and matching the loader's names loosely would be NOISY (`LD_pReLoAd` is
  // inert to the dynamic loader, so refusing on it is a false alarm on an honest run).
  const probe = path.join(standaloneHelperScratch("startup-surface-"), "probe.mjs");
  fs.writeFileSync(probe, [
    // A CHILD, so a hostile process.env never touches this selftest.
    'const spelling = process.argv[2];',
    'if (spelling !== "-") process.env[spelling] = "/nonexistent/stand-in";',
    `const { observeSuite } = await import(${JSON.stringify(path.join(REPO, "scripts/lib/knockout-runner.mjs"))});`,
    'const r = observeSuite(process.cwd(), [".", process.execPath, ["-e", "0"]], 20000, { kind: "tests" });',
    'console.log(JSON.stringify({ protocolError: r.protocolError ?? null }));',
  ].join("\n"));
  const refusalFor = (spelling) => {
    const out = execFileSync(process.execPath, [probe, spelling], { encoding: "utf8", timeout: 120_000, stdio: ["ignore", "pipe", "ignore"] });
    return JSON.parse(out.trim().split("\n").pop()).protocolError ?? "";
  };
  const REFUSAL = /knockout observer inherited/;

  // ANTI-VACUITY: a clean environment reaches a DIFFERENT error entirely (the probe's fixture is not
  // a real suite), so the refusals below are caused by the spelling and not by the fixture.
  assert.doesNotMatch(refusalFor("-"), REFUSAL, "a clean environment now refuses on startup surface — this proof has gone vacuous");

  for (const spelling of ["npm_config_script_shell", "NpM_CoNfIg_ScRiPt_ShElL", "NPM_CONFIG_SHELL"]) {
    const refusal = refusalFor(spelling);
    assert.match(refusal, REFUSAL, `the observer ran with ${spelling} in its environment; npm would have honoured it`);
    // The ACTUAL spelling, not the canonical one: a refusal that renames what it found sends the
    // reader looking for a variable that is not there.
    assert.ok(refusal.includes(spelling), `the refusal does not name the spelling actually present:\n  ${refusal}`);
  }
  assert.match(refusalFor("LD_PRELOAD"), REFUSAL, "an exact loader variable is no longer refused");
  assert.doesNotMatch(refusalFor("LD_pReLoAd"), REFUSAL,
    "a casing the dynamic loader never reads is refused as if it were live — that is a false refusal on an honest run");
});

check("the npm refusal is a RULE, with exactly one spelling admitted by contract", () => {
  // The defect that produced this check was a list that could not be completed — first a list of
  // casings, then a list of settings. Any attempt to rescue either shape by writing more spellings
  // into the runner is itself the bug, so it fails here rather than being reviewed by eye.
  //
  // ONE non-canonical spelling is allowed, and only as the contract constant: `NPM_CONFIG_USERCONFIG`
  // is what `actions/setup-node` exports, so admitting it by name is an allowlist of size one, which
  // is the opposite of an enumeration. Prose is not scanned — the comments must stay free to record
  // the exact spellings the reproductions used, which is where that evidence belongs.
  const source = fs.readFileSync(path.join(REPO, "scripts/lib/knockout-runner.mjs"), "utf8");
  const code = source
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .split("\n").filter((line) => !line.trim().startsWith("//")).join("\n");
  const CONTRACT = 'const SETUP_NODE_USERCONFIG_SPELLING = "NPM_CONFIG_USERCONFIG";';
  assert.equal(code.split(CONTRACT).length - 1, 1,
    "the setup-node contract spelling is no longer declared exactly once as a constant");
  const spellings = (code.replace(CONTRACT, "").match(/["'`][A-Za-z_]*[Nn][Pp][Mm]_?[Cc][Oo][Nn][Ff][Ii][Gg][A-Za-z_]*["'`]/g) ?? [])
    .map((quoted) => quoted.slice(1, -1))
    .filter((name) => name !== name.toLowerCase());
  assert.deepEqual(spellings, [],
    `the runner's CODE names ${spellings.length} non-canonical npm config spelling(s) beyond the one contract constant — enumerating spellings is the defect, not the fix`);
});

check("the runner's step env neutralizes a hostile launch that the shell would otherwise obey", () => {
  // ── WHY NEITHER EARLIER ATTEMPT WAS THE BOUNDARY ──────────────────────────────────────────────
  // An `env -u` inside `run:` is handed to a Bash the runner has ALREADY started, so it is too late
  // for anything acting at shell startup. A custom `shell: /usr/bin/env -u … bash` fixes BASH_ENV but
  // cannot support a clean-start claim for the loader, because `/usr/bin/env` is itself the first
  // user process and the dynamic loader consumes LD_PRELOAD / LD_LIBRARY_PATH / LD_AUDIT while
  // loading it. Only a step-level `env:`, applied by the runner as it CREATES the process, is before
  // every user process — so the runner is modelled the way it actually behaves, by INJECTING the
  // environment at process creation rather than by `export`ing inside a shell.
  //
  // `SHLVL` is pinned because the fixture must not depend on how this test was itself launched:
  // MEASURED, of the 81 variables two environments differed by, `SHLVL` alone decided whether a
  // hostile BASH_ENV fired at all. A fixture that quietly stops biting is worse than no fixture.
  const workspace = scratch("launch-boundary-");
  try {
    const marker = "BASH_ENV_EXECUTED_FIRST";
    const startupFile = path.join(workspace, "startup.sh");
    fs.writeFileSync(startupFile, `echo ${marker}\n`);
    const quote = (value) => `'${String(value).replaceAll("'", `'\\''`)}'`;
    const absolute = evidenceLaunchSanitizer();
    const probe =
      'const k=["BASH_ENV","LD_PRELOAD","LD_LIBRARY_PATH","LD_AUDIT","NODE_OPTIONS"];' +
      'console.log("CHILD:" + (k.filter((x) => x in process.env).join(",") || "<none>"));';
    const innerFor = (launcher) => [
      'echo "SHELL:BASH_ENV=[${BASH_ENV-<unset>}]:LD_PRELOAD=[${LD_PRELOAD-<unset>}]:LD_LIBRARY_PATH=[${LD_LIBRARY_PATH-<unset>}]"',
      `${launcher} ${quote(process.execPath)} -e ${quote(probe)}`,
    ].join("\n");
    // A hostile fixture may legitimately end non-zero, so output is captured either way and the
    // ASSERTIONS decide, never the exit status.
    const capture = (argv, environment) => {
      try {
        return execFileSync(argv[0], argv.slice(1), { encoding: "utf8", stdio: "pipe", env: environment });
      } catch (error) {
        return `${error.stdout ?? ""}${error.stderr ?? ""}`;
      }
    };

    // ── PROOF 1: the two-phase boundary, modelled by injection at process creation ──────────────
    const hostile = {
      ...process.env,
      SHLVL: "1",
      BASH_ENV: startupFile,
      LD_PRELOAD: "/attacker/evil.so",
      LD_LIBRARY_PATH: "/attacker/libs",
      LD_AUDIT: "/attacker/audit.so",
      NODE_OPTIONS: "--import=/attacker/x.mjs",
    };
    const step = (environment) => capture(["bash", "-e", "-c", innerFor(absolute)], environment);

    // ANTI-VACUITY: with no runner override the hostile launch really does execute attacker code.
    const attacked = step(hostile);
    assert.ok(attacked.includes(marker),
      "a hostile BASH_ENV no longer executes at shell startup — this regression has gone vacuous");
    assert.ok(attacked.includes("LD_PRELOAD=[/attacker/evil.so]"),
      "the hostile loader value no longer reaches the shell — this regression has gone vacuous");

    // PHASE 1: the runner creates the shell with the neutralized values, so nothing is sourced.
    const defended = step({ ...hostile, ...evidenceLaunchEnv() });
    assert.ok(!defended.includes(marker),
      "the step env did not stop BASH_ENV from executing at shell startup");
    assert.ok(defended.includes("BASH_ENV=[]"), "BASH_ENV was not neutralized for the shell");
    assert.ok(defended.includes("LD_PRELOAD=[]"), "LD_PRELOAD was not neutralized for the shell");
    assert.ok(defended.includes("LD_LIBRARY_PATH=[/nonexistent]"),
      "the loader search path was left empty, which denotes the CURRENT DIRECTORY to the glibc loader");

    // PHASE 2: the evidence child sees the names absent, not merely neutral.
    assert.ok(defended.includes("CHILD:<none>"),
      "the evidence child still inherited one of the hostile names");

    // ── PROOF 2: the launcher is a NAME unless it is a path ─────────────────────────────────────
    // Bash resolves a bare command name against exported shell functions before it looks at PATH, so
    // a launcher written as `env` can be replaced wholesale by the environment it was meant to clean.
    // The function is exported BY the selected Bash, so every version emits its own native encoding
    // rather than a hard-coded `BASH_FUNC_env%%`, which bash 3.2 ignores. Only MUTABLE keys are
    // exported here: `SHELLOPTS` is readonly, and exporting it aborts a `bash -e` shell outright.
    const bare = absolute.replace(/^\/usr\/bin\//, "");
    assert.notEqual(bare, absolute,
      "the declared launcher is not an absolute path, so an exported function can replace it");
    const mutable = { ...evidenceLaunchEnv() };
    delete mutable.SHELLOPTS;
    const hijack = [
      ...Object.entries(mutable).map(([key, value]) => `export ${key}=${quote(value)}`),
      "env() { echo INTERCEPTED; return 0; }",
      "export -f env",
    ].join("\n");
    const throughBash = (launcher) =>
      capture(["bash", "-e", "-c", `${hijack}\nexec bash -e -c ${quote(innerFor(launcher))}`], hostile);

    // ANTI-VACUITY: the bare name really is intercepted, and the child really does not run.
    const intercepted = throughBash(bare);
    assert.ok(intercepted.includes("INTERCEPTED"),
      "an exported `env` function no longer intercepts a bare launcher — this regression has gone vacuous");
    assert.ok(!intercepted.includes("CHILD:"),
      "the bare launcher still reached the evidence child, so the interception being measured is not real");

    // The declared launcher contains a slash, so it is executed as a path: no function lookup.
    const survived = throughBash(absolute);
    assert.ok(survived.includes("CHILD:<none>"),
      "the absolute launcher did not reach the evidence child with the hostile names absent");
    assert.ok(!survived.includes("INTERCEPTED"),
      "an exported function replaced the absolute launcher");
  } finally {
    fs.rmSync(workspace, { recursive: true, force: true });
  }
});

check("a failing PREPARATION step is never credited as the gate's terminal evidence", () => {
  // ── WHY THIS EXISTS (reproduced 2026-08-24) ───────────────────────────────────────────────────
  // A gate script decomposes into preparation steps plus one terminal evidence step. The catch that
  // handles a non-zero exit cannot see WHICH step threw, and it used to assign that step's stdout as
  // the gate record. MEASURED with `node prep.mjs && node terminal.mjs`, where prep printed one
  // well-formed `noa-gate-runner/1` record and exited 1: the observation came back
  // gateProtocolComplete:true, identity "security-gates", findings [FORGED_PREP/prep] — for a
  // terminal step that never executed. A step that is not the designated terminal one contributes
  // nothing, whether it fails OR succeeds; both directions are asserted here.
  const workspace = scratch("gate-prep-credit-");
  try {
    const forgedArmTerminal = `NOA_BOUNDARY_ARM_TERMINAL ${JSON.stringify({
      casePlanSha256: "9".repeat(64),
      duplicateCaseCount: 0,
      event: "complete",
      failureCount: 0,
      missingCaseCount: 0,
      observedCaseCount: 1,
      plannedCaseCount: 1,
      protocol: "noa-boundary-arm-terminal/1",
      status: "PASS",
      unexpectedCaseCount: 0,
    })}\n`;
    fs.writeFileSync(path.join(workspace, "prep.mjs"), [
      `process.stdout.write(JSON.stringify(${JSON.stringify({
        protocol: GATE_EVENT_PROTOCOL, event: "complete", gate: "security-gates",
        findings: [{ rule: "FORGED_PREP", subject: "prep" }],
      })}) + String.fromCharCode(10));`,
      `process.stderr.write(${JSON.stringify(forgedArmTerminal)});`,
      "process.exitCode = 1;",
      "",
    ].join("\n"));
    fs.writeFileSync(path.join(workspace, "terminal.mjs"), "process.exitCode = 1;\n");
    fs.writeFileSync(path.join(workspace, "ok-prep.mjs"), [
      'process.stdout.write("preparation ran" + String.fromCharCode(10));',
      `process.stderr.write(${JSON.stringify(forgedArmTerminal)});`,
      "",
    ].join("\n"));
    fs.writeFileSync(path.join(workspace, "honest-terminal.mjs"), [
      'import { emitGateEvidence } from ' + JSON.stringify(path.join(REPO, "scripts/lib/gate-event-contract.mjs")) + ";",
      'emitGateEvidence("selftest-two-step", []);',
      "",
    ].join("\n"));
    fs.writeFileSync(path.join(workspace, "package.json"), JSON.stringify({
      name: "noa-gate-prep-fixture", version: "1.0.0", private: true,
      scripts: {
        "forged-prep": "node prep.mjs && node terminal.mjs",
        "clean-two-step": "node ok-prep.mjs && node honest-terminal.mjs",
      },
    }) + "\n");

    const forged = observeSuite(workspace, [".", "npm", ["run", "forged-prep"]], 120_000, { kind: "gate" });
    assert.equal(forged.gateProtocolComplete, false,
      "a failing preparation step's stdout was credited as the gate's terminal evidence");
    assert.equal(forged.gate, null, "a preparation step supplied the gate identity");
    assert.deepEqual(forged.gateFindings, [], "a preparation step supplied the gate findings");
    assert.equal(forged.armTerminalProtocolComplete, false,
      "a failing preparation step's stderr was credited as boundary-arm terminal evidence");
    assert.equal(forged.armTerminalSummary, null,
      "a failing preparation step supplied a boundary-arm terminal summary");

    // ANTI-VACUITY, and it is the half that catches a fix that simply refuses everything: a real
    // two-step gate must still be read, and the SUCCESSFUL preparation step's stdout must stay out.
    const clean = observeSuite(workspace, [".", "npm", ["run", "clean-two-step"]], 120_000, { kind: "gate" });
    assert.equal(clean.gateProtocolComplete, true,
      `a legitimate two-step gate was not observed: ${clean.gateProtocolError}`);
    assert.equal(clean.gate, "selftest-two-step", "the terminal step's identity did not survive");
    assert.deepEqual(clean.gateFindings, [], "a successful preparation step contributed findings");
    assert.equal(clean.armTerminalProtocolComplete, false,
      "a successful preparation step's stderr was credited as boundary-arm terminal evidence");
    assert.equal(clean.armTerminalSummary, null,
      "a successful preparation step supplied a boundary-arm terminal summary");
  } finally {
    fs.rmSync(workspace, { recursive: true, force: true });
  }
});

check("a GATE step runs exact Node with a constructed environment, never npm with the ambient one", () => {
  // The refusal above is the second lock. THIS is the first: the ambient environment never reaches a
  // gate child at all, and npm — the component that turns config into NODE_OPTIONS and script-shell
  // into an interpreter — is not on the evidence path any more. package.json remains the command
  // source; it is decomposed into exact Node steps.
  for (const suite of [
    [".", "npm", ["run", "lint:inert-containers"]],
    [".", "npm", ["run", "lint:security-gates"]],
    [".", "npm", ["run", "lint:resolver-parity"]],
  ]) {
    const steps = trustedGateSteps(REPO, suite);
    assert.ok(steps.length >= 1, `${suite[2].join(" ")} decomposed to no steps`);
    for (const step of steps) {
      assert.equal(step.cmd, process.execPath,
        `${suite[2].join(" ")} still starts ${step.cmd} instead of the exact Node executable`);
      assert.ok(!step.args.includes("npm"), "an npm invocation survived the gate decomposition");
    }
  }

  const constructed = closedEvidenceEnvironment({
    ...process.env,
    NODE_OPTIONS: "--import=evil",
    npm_config_node_options: "--import=evil",
    npm_config_script_shell: "/evil/sh",
    BASH_ENV: "/evil.sh",
    DYLD_INSERT_LIBRARIES: "/evil.dylib",
    LD_PRELOAD: "/evil.so",
    PATH: "/attacker/bin",
  });
  for (const key of ["NODE_OPTIONS", "npm_config_script_shell", "BASH_ENV", "DYLD_INSERT_LIBRARIES", "LD_PRELOAD"]) {
    assert.ok(!(key in constructed), `${key} survived into a gate step's environment`);
  }
  assert.equal(constructed.npm_config_node_options, "",
    "npm_config_node_options is not neutralized for a nested npm a proof recipe may start");
  assert.notEqual(constructed.npm_config_userconfig, constructed.npm_config_globalconfig,
    "npm refuses to start when userconfig and globalconfig name the same file");
  assert.ok(constructed.PATH.startsWith(path.dirname(process.execPath)),
    "a gate step inherited an attacker-controlled PATH instead of one built from this Node");
  assert.throws(
    () => closedEvidenceEnvironment({}, { rcRoot: privateFallbackRoot(), typo: true }),
    /unknown options/,
    "a misspelled closed-environment option was accepted as inert configuration",
  );
  assert.throws(
    () => closedEvidenceEnvironment({}, { rcRoot: REPO }),
    /overlaps evidence root/,
    "the neutral rc store accepted a path inside the public evidence repository",
  );
});

check("Docker evidence resolves a fixed absolute executable without consulting PATH", () => {
  const fixture = scratch("fixed-docker-cli-");
  const executable = path.join(fixture, "docker-fixture");
  const attackerBin = path.join(fixture, "attacker-bin");
  const attackerDocker = path.join(attackerBin, "docker");
  const savedPath = process.env.PATH;
  try {
    fs.mkdirSync(attackerBin);
    fs.writeFileSync(executable, "#!/bin/sh\nexit 0\n", { mode: 0o755 });
    fs.writeFileSync(attackerDocker, "#!/bin/sh\nexit 99\n", { mode: 0o755 });
    process.env.PATH = attackerBin;

    const selected = fixedDockerExecutable([path.join(fixture, "absent"), executable]);
    assert.equal(selected, fs.realpathSync(executable),
      "the fixed candidate resolver selected a PATH entry instead of the declared executable");
    assert.ok(path.isAbsolute(selected), "the Docker capability is not an absolute executable path");
    assert.throws(() => fixedDockerExecutable(["docker"]), /must be absolute/,
      "a bare Docker command name re-entered the evidence TCB");

    const installed = fixedDockerExecutable();
    assert.ok(path.isAbsolute(installed), "the installed Docker evidence executable is not absolute");
    assert.ok(fs.statSync(installed).isFile(), "the installed Docker evidence executable is not regular");

    const runnerSource = fs.readFileSync(path.join(REPO, "scripts/lib/knockout-runner.mjs"), "utf8");
    assert.doesNotMatch(runnerSource, /execFileSync\(\s*["']docker["']/u,
      "a Docker evidence call bypasses the fixed absolute resolver");
  } finally {
    if (savedPath === undefined) delete process.env.PATH;
    else process.env.PATH = savedPath;
    fs.rmSync(fixture, { recursive: true, force: true });
  }
});

// ── THE REGRESSION ITSELF ───────────────────────────────────────────────────────────────────────
check("QA-16: a replacement that does NOT BUILD is MUTATION_DID_NOT_BUILD, never a kill", () => {
  const ev = runKnockout({
    root,
    entry: { ...entryBase, kind: "tests", find: MARKER, replace: "const guard = NOT_VALID_SYNTAX((( ;" },
    baseline,
    timeoutMs: 60_000,
  });
  assert.notEqual(ev.verdict, VERDICT.DETECTOR_TRIGGERED,
    "a build failure was scored as a proven control — this is the exact defect QA-16 reported");
  assert.equal(ev.verdict, VERDICT.MUTATION_DID_NOT_BUILD, `got ${ev.verdict}: ${ev.detail}`);
});

check("presentation-text failure names without completed runner events cannot score a kill", () => {
  const ev = runKnockout({
    root,
    entry: { ...entryBase, kind: "tests", find: MARKER, replace: "const guard = FORGED_FAILURE;" },
    baseline,
    timeoutMs: 60_000,
  });
  assert.notEqual(ev.verdict, VERDICT.DETECTOR_TRIGGERED, `forged text scored a kill: ${ev.detail}`);
  assert.equal(ev.verdict, VERDICT.MUTATION_DID_NOT_BUILD, `got ${ev.verdict}: ${ev.detail}`);
});

check("a suite wrapper or pretest step never receives the reporter capability", () => {
  const ev = runKnockout({
    root,
    entry: { ...entryBase, kind: "tests", find: MARKER, replace: "const guard = FORGED_WRAPPER_EVENT;" },
    baseline,
    timeoutMs: 60_000,
  });
  assert.notEqual(ev.verdict, VERDICT.DETECTOR_TRIGGERED,
    `credential-bearing wrapper forged a proven control: ${ev.detail}`);
  assert.equal(ev.verdict, VERDICT.MUTATION_DID_NOT_BUILD, `got ${ev.verdict}: ${ev.detail}`);
  assert.deepEqual(ev.newFailures ?? [], [], "a wrapper-authored FAIL entered the evidence set");
});

check("a test cannot replace the disclosed rendezvous path with forged FAIL+plan evidence", () => {
  const ev = runKnockout({
    root,
    entry: { ...entryBase, kind: "tests", find: MARKER, replace: "const guard = FORGED_EVENT_PATH;" },
    baseline,
    timeoutMs: 60_000,
  });
  assert.notEqual(ev.verdict, VERDICT.DETECTOR_TRIGGERED,
    `path-replacement forgery scored a proven control: ${ev.detail}`);
  assert.equal(ev.verdict, VERDICT.MUTATION_DID_NOT_BUILD, `got ${ev.verdict}: ${ev.detail}`);
  assert.match(ev.detail, /file-wrapper failure/,
    "the real setup crash was not distinguished from the forged authored failure");
  assert.match(ev.detail, /unlinked proof socket pathname was replaced after the reporter handshake/,
    "the fixture passed without reaching the path-replacement attack");
});

check("a replacement that BUILDS and breaks the guard is a real kill", () => {
  const ev = runKnockout({
    root,
    entry: { ...entryBase, kind: "tests", find: MARKER, replace: "const guard = true;" },
    baseline,
    timeoutMs: 60_000,
  });
  assert.equal(ev.verdict, VERDICT.DETECTOR_TRIGGERED, `got ${ev.verdict}: ${ev.detail}`);
  assert.match(ev.detail, /NEW authenticated authored-site failure/);
});

// A FACT, NOT A HANDLE. This fixture runs as a descendant of PID 1 inside a disposable Linux
// namespace, so any pid it sees is namespace-local and means nothing on the host. An earlier version
// wrote that number out and the check `process.kill`-ed it: on a developer machine the number was
// usually free, so the probe raised ESRCH and the case passed having measured nothing, and in CI the
// number belonged to an unrelated host process, so the probe raised `kill EPERM` — and the cleanup
// path would have sent SIGKILL to whatever host process happened to hold it. Nothing host-usable
// leaves the namespace now; what is recorded is what the descendant DID, in three ordered markers.
const resistantReadyPath = path.join(root, "sigterm-resistant.ready");
const resistantSeenPath = path.join(root, "sigterm-resistant.sigterm-seen");
const resistantSurvivedPath = path.join(root, "sigterm-resistant.survived-sigterm");
const resistantMarkers = [resistantReadyPath, resistantSeenPath, resistantSurvivedPath];
fs.writeFileSync(
  path.join(root, "timeout.test.mjs"),
  [
    `import fs from "node:fs";`,
    `import { spawn } from "node:child_process";`,
    `import { test } from "node:test";`,
    `test("timeout descendant fixture", async () => {`,
    // The child announces READY only AFTER its SIGTERM handler is installed, and the parent waits for
    // that file before hanging. Without the handshake the deadline could arrive first and the whole
    // case would be about a race rather than about escalation.
    `  const childCode = ${JSON.stringify([
      `const fs = require("node:fs");`,
      `process.on("SIGTERM", () => {`,
      `  fs.writeFileSync(${JSON.stringify(resistantSeenPath)}, "SIGTERM_SEEN");`,
      `  setTimeout(() => fs.writeFileSync(${JSON.stringify(resistantSurvivedPath)}, "SURVIVED_SIGTERM"), 250);`,
      `});`,
      `process.on("SIGINT", () => {});`,
      `setInterval(() => {}, 1000);`,
      `fs.writeFileSync(${JSON.stringify(resistantReadyPath)}, "READY");`,
    ].join(""))};`,
    `  spawn(process.execPath, ["-e", childCode], { stdio: "ignore" });`,
    `  const deadline = Date.now() + 10000;`,
    `  while (!fs.existsSync(${JSON.stringify(resistantReadyPath)})) {`,
    `    if (Date.now() > deadline) throw new Error("the resistant descendant never reported READY");`,
    `    await new Promise((r) => setTimeout(r, 25));`,
    `  }`,
    `  await new Promise(() => {});`,
    `});`,
  ].join("\n"),
);

check("a timeout tears down the evidence namespace, so a SIGTERM-resistant descendant cannot outlive it", () => {
  // Renamed from "timeout escalation kills the whole process group after its leader exits". The
  // runner says in its own words why that name was wrong: "A process group is not a containment
  // boundary: setsid(2), including Node's `detached: true`, creates a new group that a negative-PGID
  // kill cannot reach." The boundary is the disposable namespace, and the inner observer escalates
  // SIGTERM to SIGKILL inside it. This case is about that escalation actually happening.
  //
  // It is deliberately not the adjacent detached-writer case. That one lets a suite COMPLETE and
  // proves a late write cannot land afterwards. This one never completes: the descendant installs a
  // SIGTERM handler, announces READY, and the suite then hangs until the deadline. The three markers
  // below prove the descendant reached each stage, so the escalation is measured against a process
  // that demonstrably ignored the polite signal rather than one that simply exited.
  for (const marker of resistantMarkers) fs.rmSync(marker, { force: true });
  const observation = observeSuite(
    root,
    [".", process.execPath, ["--test", path.join(root, "timeout.test.mjs")]],
    1500,
    { kind: "tests" },
  );

  // ANTI-VACUITY, in order: the descendant existed, was signalled, and outlived the polite signal.
  // Without all three this case could hold for a fixture that spawned nothing and merely hung.
  assert.equal(fs.existsSync(resistantReadyPath), true,
    "the descendant never installed its SIGTERM handler, so nothing here measures escalation");
  assert.equal(fs.existsSync(resistantSeenPath), true,
    "the descendant never received SIGTERM, so the escalation path was never entered");
  assert.equal(fs.existsSync(resistantSurvivedPath), true,
    "the descendant did not outlive SIGTERM, so SIGKILL escalation was never the thing being tested");

  // THE CONTROL: the deadline was reached and reported, and the inner observer did not come back
  // reporting a survivor. Those two error strings are the observer's own words for the failure this
  // case exists to catch, so this reads its report rather than probing a namespace-local pid.
  assert.equal(observation.timedOut, true,
    `the resistant-descendant fixture did not report a timeout: exit=${observation.exit} error=${observation.protocolError}`);
  assert.doesNotMatch(String(observation.protocolError ?? "") + String(observation.out ?? ""),
    /left a descendant process alive after its leader closed|survived SIGKILL escalation/,
    `a descendant outlived the escalation: ${observation.protocolError ?? observation.out}`);
});

const detachedLateTarget = path.join(root, "detached-late-write-target.js");
const detachedLatePidPath = path.join(root, "detached-late-write.pid");
fs.writeFileSync(detachedLateTarget, "const state = PRISTINE;\n");
fs.writeFileSync(
  path.join(root, "detached-late-write.test.mjs"),
  [
    `import fs from "node:fs";`,
    `import { spawn } from "node:child_process";`,
    `import { test } from "node:test";`,
    `test("detached delayed writer fixture", () => {`,
    `  const childCode = ${JSON.stringify([
      `const fs = require("node:fs");`,
      `process.on("SIGTERM", () => {});`,
      `setTimeout(() => fs.writeFileSync(${JSON.stringify(detachedLateTarget)}, "LATE DETACHED WRITE\\n"), 3000);`,
      `setInterval(() => {}, 1000);`,
    ].join(""))};`,
    `  const descendant = spawn(process.execPath, ["-e", childCode], {`,
    `    detached: true,`,
    `    stdio: "ignore",`,
    `  });`,
    `  descendant.unref();`,
    `  fs.writeFileSync(${JSON.stringify(detachedLatePidPath)}, String(descendant.pid));`,
    `});`,
  ].join("\n"),
);

check("a detached delayed writer is destroyed before observeSuite returns", () => {
  const observation = observeSuite(
    root,
    [".", process.execPath, ["--test", path.join(root, "detached-late-write.test.mjs")]],
    60_000,
    { kind: "tests" },
  );
  assert.equal(observation.protocolComplete, true, observation.protocolError ?? observation.out);
  assert.equal(observation.exit, 0, observation.out);
  assert.match(fs.readFileSync(detachedLatePidPath, "utf8"), /^\d+$/);
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 3500);
  assert.equal(
    fs.readFileSync(detachedLateTarget, "utf8"),
    "const state = PRISTINE;\n",
    "a detached descendant wrote into the subject after the observer reported completion",
  );
});

check("the CLI refuses an unknown knockout kind before baselines, mutation, or reporting", () => {
  // The in-memory malformed entry is copied from this first real registry target. If validation
  // ever moves after mutation, this exact byte comparison catches it without assuming a clean tree.
  const target = path.join(REPO, "packages/signer-core/src/der.ts");
  const before = fs.readFileSync(target);
  const result = spawnSync(
    process.execPath,
    ["scripts/lint-control-knockout.mjs", "--selftest-unknown-kind"],
    { cwd: REPO, encoding: "utf8", timeout: 60_000, env: PUBLIC_ONLY_ENVIRONMENT },
  );
  if (result.error !== undefined) throw result.error;
  const output = `${result.stdout ?? ""}${result.stderr ?? ""}`;
  assert.equal(result.status, 1, `unknown-kind CLI fixture exited ${result.status}: ${output}`);
  assert.equal(
    output.trim(),
    'knockout registry refused before measurement: invalid knockout entry "__selftest_unknown_kind__": ' +
      'kind must be exactly "tests" or "gate", got "future-kind"',
    "the CLI did not return its deterministic closed registry diagnostic",
  );
  assert.doesNotMatch(
    output,
    /L4 control knockout|suite baselines|unknown baseline evidence kind|baselineEvidenceSummary/,
    "the malformed entry escaped into baseline measurement or the report path",
  );
  assert.deepEqual(fs.readFileSync(target), before,
    "the CLI changed its malformed entry's source target before rejecting the registry");
});

check("a 'tests' declaration whose baseline printed no footer is INVALID_TEST, not a result", () => {
  const ev = runKnockout({
    root,
    entry: { ...entryBase, kind: "tests", find: MARKER, replace: "const guard = NOT_VALID_SYNTAX((( ;" },
    baseline: { ...baseline, protocolComplete: false, protocolError: "no event stream", testCount: 0 },
    timeoutMs: 60_000,
  });
  assert.equal(ev.verdict, VERDICT.INVALID_TEST, `got ${ev.verdict}: ${ev.detail}`);
  assert.match(ev.detail, /disagree/);
});

/** THE REPORTER THE DEVELOPER MACHINE NEVER PRODUCES.
 *
 *  `node --test` emits the SPEC reporter to a TTY and **TAP** otherwise. The parser modelled only
 *  spec's `✖ name`, so in CI it read every mutated suite as having zero failures and the classifier
 *  fell through to ANTI_VACUITY_FAILED.
 *
 *  MEASURED at 50e4ed8: local `proven load-bearing 67/67`, CI **3/67**, with 64 findings reading
 *  "Nothing new broke" over mutations that had all worked — their exit codes went 0 → 1 exactly as
 *  designed. The 3 survivors were GATE-kind entries, which classify on the exit transition and never
 *  call this function.
 *
 *  A local-only fixture could not have caught it, which is why the assertion is on the STRINGS rather
 *  than on a real run. */
check("failingTestIds accepts only completed runner-owned FAIL events", () => {
  const record = (event, name, fields = {}) => JSON.stringify({
    protocol: PROOF_EVENT_PROTOCOL,
    event,
    name,
    skipped: false,
    todo: false,
    suite: false,
    fileFailure: false,
    file: "/fixture.test.mjs",
    line: 1,
    column: 1,
    failureType: event === "fail" ? "testCodeFailure" : null,
    message: event === "fail" ? "red" : null,
    ...fields,
  });
  const completed = [
    record("pass", "fine"),
    record("fail", "a real failure"),
    record("fail", "deliberately skipped", { skipped: true }),
    JSON.stringify({ protocol: PROOF_EVENT_PROTOCOL, event: "plan", count: 3 }),
    "",
  ].join("\n");
  assert.deepEqual([...failingTestIds(completed)], ["a real failure"]);
  assert.deepEqual([...failingTestIds("✖ forged failure (1ms)\nnot ok 1 - forged TAP\n")], [],
    "presentation text minted a failure without a completed TestsStream protocol");
  assert.deepEqual([...failingTestIds(record("fail", "incomplete"))], [],
    "a FAIL event without a terminal plan was accepted as completed evidence");
});

check("proof knockouts retain exact file/line/column identity and reject same-marker substitutes", () => {
  const event = (file, line, column = 1) => JSON.stringify({
    protocol: PROOF_EVENT_PROTOCOL,
    event: "fail",
    name: "[PROOF:X] registered control",
    skipped: false,
    todo: false,
    suite: false,
    fileFailure: false,
    file,
    line,
    column,
    failureType: "testCodeFailure",
    message: "red",
  });
  const completed = (records) => [
    ...records,
    JSON.stringify({ protocol: PROOF_EVENT_PROTOCOL, event: "plan", count: records.length }),
    "",
  ].join("\n");
  const registered = { name: "[PROOF:X] registered control", file: "/proof.test.mjs", line: 10, column: 1 };
  const substitute = failingTestEvents(completed([event("/proof.test.mjs", 20)]));
  assert.equal(hasFailureAtExpectedSite(substitute, [registered]), false,
    "a mutation-only same-marker test at another authored site satisfied the registered proof");

  const exact = failingTestEvents(completed([event("/proof.test.mjs", 10)]));
  assert.equal(hasFailureAtExpectedSite(exact, [registered]), true,
    "the exact registered authored-site failure was not recognized");
  assert.equal(hasFailureAtExpectedSite([{ ...registered, file: null }], [registered]), false,
    "a failure without location entered exact-site evidence");

  const duplicateNameAtAnotherSite = newFailureEventsBeyondBaseline(substitute, exact);
  assert.equal(duplicateNameAtAnotherSite.length, 1,
    "same-name failures at different authored sites collapsed into one identity");
  assert.equal(duplicateNameAtAnotherSite[0].line, 20);
});

fs.writeFileSync(path.join(root, "gate.mjs"), [
  `import fs from "node:fs";`,
  `const source = fs.readFileSync(new URL("./subject.js", import.meta.url), "utf8");`,
  `if (source.includes("FORGED_GATE_TEXT")) {`,
  `  console.log("  RED [FORGED] subject.js — presentation text only");`,
  `  process.exit(1);`,
  `}`,
  `const findings = source.includes("REAL_CHECK") ? [] : [{ rule: "FIXTURE", subject: "subject.js", detail: "guard removed" }];`,
  `console.log(JSON.stringify({ protocol: ${JSON.stringify(GATE_EVENT_PROTOCOL)}, event: "complete", gate: "fixture-gate", findings }));`,
  `process.exit(findings.length === 0 ? 0 : 1);`,
].join("\n"));
const GATE_SUITE = [".", process.execPath, [path.join(root, "gate.mjs")]];
const GATE_ENTRY_BINDING = {
  gateId: "fixture-gate",
  expectedGateFindings: [{ rule: "FIXTURE", subject: "subject.js" }],
};
const gateBaseline = observeSuite(root, GATE_SUITE, 60_000, { kind: "gate" });

const SETUP_FROM_ID = "case.fixture-reviewed-plan-id-aaaaaaaa";
const SETUP_TO_ID = "case.fixture-reviewed-plan-id-bbbbbbbb";
const SETUP_BASELINE_DIGEST = "1".repeat(64);
const SETUP_MUTATED_DIGEST = "2".repeat(64);
const SETUP_CASE_COUNT = 3;
const SETUP_BASELINE_MANIFEST_DIGEST = "3".repeat(64);
const SETUP_MUTATED_MANIFEST_DIGEST = "4".repeat(64);
const SETUP_CANDIDATE_SUBJECT = Object.freeze({
  archiveSha256: "5".repeat(64),
  commit: "6".repeat(40),
  repository: "fixture/public-candidate",
  tree: "7".repeat(40),
});
const SETUP_GATE_PROVENANCE_EXPECTATION =
  BOUNDARY_CANDIDATE_TIER_A_KNOCKOUT_PROVENANCE_EXPECTATION;
const setupGateProvenance = ({ mutated = false, ...overrides } = {}) => ({
  authorityClass: SETUP_GATE_PROVENANCE_EXPECTATION.authorityClass,
  authorityNonClaim: SETUP_GATE_PROVENANCE_EXPECTATION.authorityNonClaim,
  bootstrapMode: SETUP_GATE_PROVENANCE_EXPECTATION.bootstrapMode,
  controlManifestDigest: mutated
    ? SETUP_MUTATED_MANIFEST_DIGEST : SETUP_BASELINE_MANIFEST_DIGEST,
  controlManifestVersion: SETUP_GATE_PROVENANCE_EXPECTATION.controlManifestVersion,
  externalAuthorizationSha256: SETUP_GATE_PROVENANCE_EXPECTATION.externalAuthorizationSha256,
  schemaVersion: SETUP_GATE_PROVENANCE_EXPECTATION.schemaVersion,
  subject: SETUP_CANDIDATE_SUBJECT,
  tier: SETUP_GATE_PROVENANCE_EXPECTATION.tier,
  verification: SETUP_GATE_PROVENANCE_EXPECTATION.verification,
  visibilitySource: SETUP_GATE_PROVENANCE_EXPECTATION.visibilitySource,
  ...overrides,
});
const SETUP_FINDING = {
  rule: "SELFTEST",
  subject: "the arm executed its exact reviewed case plan once",
};
const SETUP_EXPECTATION = Object.freeze({
  baselineCaseCount: SETUP_CASE_COUNT,
  baselineCasePlanSha256: SETUP_BASELINE_DIGEST,
  exitCode: 2,
  idSubstitution: Object.freeze({ from: SETUP_FROM_ID, to: SETUP_TO_ID }),
  mutatedCaseCount: SETUP_CASE_COUNT,
  mutatedCasePlanSha256: SETUP_MUTATED_DIGEST,
  stableError: "ARM_CASE_PLAN_DIGEST_MISMATCH",
  terminalProtocol: "noa-boundary-arm-terminal/1",
  terminalStatus: "SETUP_FAILED",
});
const setupFindingDetail = (overrides = {}) => JSON.stringify({
  actualCasePlanSha256: SETUP_MUTATED_DIGEST,
  diagnosticExpectedCaseCount: SETUP_CASE_COUNT,
  diagnosticPlannedCaseCount: SETUP_CASE_COUNT,
  duplicateCaseCount: 0,
  missingCaseIds: [],
  reviewedCasePlanSha256: SETUP_BASELINE_DIGEST,
  unexpectedCaseCount: 0,
  ...overrides,
});
const setupTerminal = ({ mutated = false, ...overrides } = {}) => ({
  casePlanSha256: mutated ? SETUP_MUTATED_DIGEST : SETUP_BASELINE_DIGEST,
  duplicateCaseCount: 0,
  event: "complete",
  failureCount: mutated ? 1 : 0,
  missingCaseCount: 0,
  observedCaseCount: SETUP_CASE_COUNT,
  plannedCaseCount: SETUP_CASE_COUNT,
  protocol: "noa-boundary-arm-terminal/1",
  status: mutated ? "SETUP_FAILED" : "PASS",
  unexpectedCaseCount: 0,
  ...overrides,
});
const terminalLine = (summary) => `NOA_BOUNDARY_ARM_TERMINAL ${JSON.stringify(summary)}\n`;

fs.writeFileSync(path.join(root, "setup-plan.txt"), `${SETUP_FROM_ID}\n`);
fs.writeFileSync(path.join(root, "setup-integrity-gate.mjs"), [
  'import fs from "node:fs";',
  'const source = fs.readFileSync(new URL("./setup-plan.txt", import.meta.url), "utf8");',
  `const mutated = source.includes(${JSON.stringify(SETUP_TO_ID)});`,
  `const summary = mutated ? ${JSON.stringify(setupTerminal({ mutated: true }))} : ${JSON.stringify(setupTerminal())};`,
  `const detail = ${JSON.stringify(setupFindingDetail())};`,
  `const findings = mutated ? [{ ...${JSON.stringify(SETUP_FINDING)}, detail }] : [];`,
  'process.stderr.write("NOA_BOUNDARY_ARM_TERMINAL " + JSON.stringify(summary) + "\\n");',
  `const provenance = mutated ? ${JSON.stringify(setupGateProvenance({ mutated: true }))} : ${JSON.stringify(setupGateProvenance())};`,
  `process.stdout.write(JSON.stringify({ protocol: ${JSON.stringify(PROVENANCE_BOUND_GATE_EVENT_PROTOCOL)}, event: "complete", gate: "setup-integrity-gate", findings, provenance }) + "\\n");`,
  "process.exit(mutated ? 2 : 0);",
].join("\n"));
const SETUP_SUITE = [".", process.execPath, [path.join(root, "setup-integrity-gate.mjs")]];
const SETUP_ENTRY = Object.freeze({
  id: "setup-integrity-fixture",
  control: "the reviewed arm plan digest is an authorization/setup integrity boundary",
  file: "setup-plan.txt",
  find: SETUP_FROM_ID,
  replace: SETUP_TO_ID,
  kind: "gate",
  gateId: "setup-integrity-gate",
  expectedGateFindings: [SETUP_FINDING],
  expectedGateProvenance: SETUP_GATE_PROVENANCE_EXPECTATION,
  expectedSetupIntegrity: SETUP_EXPECTATION,
  suite: SETUP_SUITE,
});
const setupGateBaseline = projectKnockoutObservation(
  observeSuite(root, SETUP_SUITE, 60_000, { kind: "gate" }),
);

const REGULAR_PROVENANCE_FINDING = Object.freeze({ rule: "FIXTURE", subject: "subject.js" });
fs.writeFileSync(path.join(root, "regular-provenance-gate.mjs"), [
  'import fs from "node:fs";',
  'const source = fs.readFileSync(new URL("./subject.js", import.meta.url), "utf8");',
  `const mutated = !source.includes(${JSON.stringify(MARKER)});`,
  'const stale = source.includes("STALE_PROVENANCE");',
  `const findings = mutated ? [{ ...${JSON.stringify(REGULAR_PROVENANCE_FINDING)}, detail: "guard removed" }] : [];`,
  `const baselineProvenance = ${JSON.stringify(setupGateProvenance())};`,
  `const mutatedProvenance = ${JSON.stringify(setupGateProvenance({ mutated: true }))};`,
  'const provenance = mutated && !stale ? mutatedProvenance : baselineProvenance;',
  `process.stdout.write(JSON.stringify({ protocol: ${JSON.stringify(PROVENANCE_BOUND_GATE_EVENT_PROTOCOL)}, event: "complete", gate: "regular-provenance-gate", findings, provenance }) + "\\n");`,
  'process.exit(findings.length === 0 ? 0 : 1);',
].join("\n"));
const REGULAR_PROVENANCE_SUITE = [
  ".", process.execPath, [path.join(root, "regular-provenance-gate.mjs")],
];
const REGULAR_PROVENANCE_ENTRY = Object.freeze({
  ...entryBase,
  control: "ordinary boundary gate credit requires provenance for the mutated reviewed bytes",
  expectedGateFindings: [REGULAR_PROVENANCE_FINDING],
  expectedGateProvenance: SETUP_GATE_PROVENANCE_EXPECTATION,
  find: MARKER,
  gateId: "regular-provenance-gate",
  kind: "gate",
  replace: "const guard = true;",
  suite: REGULAR_PROVENANCE_SUITE,
});
const regularProvenanceBaseline = projectKnockoutObservation(
  observeSuite(root, REGULAR_PROVENANCE_SUITE, 60_000, { kind: "gate" }),
);

check("gate baseline reporting uses structured gate findings, not node:test failures", () => {
  const gateFindings = Array.from({ length: 20 }, (_, index) => ({
    rule: "BASELINE",
    subject: `finding-${index + 1}`,
    detail: "already red",
  }));
  const gateSummary = baselineEvidenceSummary("gate", {
    ...gateBaseline,
    failing: new Set(),
    gateFindings,
  });
  assert.equal(gateSummary.count, 20,
    "a red gate was reported through the empty node:test failure set");
  assert.equal(gateSummary.label, "pre-existing gate finding(s)");
  assert.equal(gateSummary.details.length, 20);

  const testSummary = baselineEvidenceSummary("tests", {
    failing: new Set(["first test", "second test"]),
    gateFindings: [],
  });
  assert.equal(testSummary.count, 2, "a node:test baseline stopped using its authored failure set");
  assert.equal(testSummary.label, "pre-existing test failure(s)");
});

check("gate outcomes bind exact exit codes to structured finding cardinality", () => {
  const finding = { rule: "FIXTURE", subject: "subject.js", detail: "guard removed" };
  const observation = (exit, gateFindings, overrides = {}) => ({
    ...gateBaseline,
    exit,
    timedOut: false,
    signal: null,
    gateProtocolComplete: true,
    gateProtocolError: null,
    gate: "fixture-gate",
    gateFindings,
    findings: gateFindings.length,
    ...overrides,
  });

  assert.equal(gateObservationProblem(observation(0, []), "baseline"), null,
    "a real clean gate baseline was refused");
  assert.equal(gateObservationProblem(observation(0, []), "mutated"), null,
    "a coherent green mutated gate was refused");
  assert.equal(gateObservationProblem(observation(1, [finding]), "mutated"), null,
    "a coherent finding-bearing mutated gate was refused");

  for (const [label, candidate, phase] of [
    ["red baseline", observation(1, [finding]), "baseline"],
    ["exit 1 without a finding", observation(1, []), "mutated"],
    ["exit 0 with a finding", observation(0, [finding]), "mutated"],
    ["setup exit 2 with an expected finding", observation(2, [finding]), "mutated"],
    ["arbitrary non-zero exit with an expected finding", observation(97, [finding]), "mutated"],
    ["signal with an otherwise clean record", observation(0, [], { signal: "SIGTERM" }), "mutated"],
    ["timeout with an otherwise clean record", observation(null, [], { timedOut: true }), "mutated"],
    ["counter/record disagreement", observation(1, [finding], { findings: 0 }), "mutated"],
  ]) {
    assert.notEqual(gateObservationProblem(candidate, phase), null, `${label} was accepted as evidence`);
  }
});

const setupMutationObservation = ({
  summary = setupTerminal({ mutated: true }),
  detail = setupFindingDetail(),
  findings = [{ ...SETUP_FINDING, detail }],
  provenance = setupGateProvenance({ mutated: true }),
  protocol = PROVENANCE_BOUND_GATE_EVENT_PROTOCOL,
  terminalOutput = null,
  ...overrides
} = {}) => {
  const terminal = parseBoundaryArmTerminalEvidence(
    terminalOutput ?? terminalLine(summary),
  );
  return projectKnockoutObservation({
    armTerminalProtocolComplete: terminal.protocolComplete,
    armTerminalProtocolError: terminal.error,
    armTerminalSummary: terminal.summary,
    exit: 2,
    failing: new Set(),
    failureEvents: [],
    fileFailureCount: 0,
    findings: findings.length,
    gate: "setup-integrity-gate",
    gateFindings: findings,
    gateProtocol: protocol,
    gateProtocolComplete: true,
    gateProtocolError: null,
    gateProvenance: provenance,
    ms: 0,
    out: "",
    protocolComplete: false,
    protocolError: null,
    signal: null,
    testCount: 0,
    testEvents: "",
    timedOut: false,
    ...overrides,
  });
};

check("setup-integrity evidence binds one exact arm terminal record and exact clean baseline", () => {
  assert.equal(setupGateBaseline.exit, 0, setupGateBaseline.out);
  assert.equal(setupIntegrityBaselineProblem(setupGateBaseline, SETUP_EXPECTATION), null);
  assert.equal(
    setupIntegrityMutationProblem(
      setupMutationObservation(),
      SETUP_EXPECTATION,
      [SETUP_FINDING],
    ),
    null,
  );
  assert.equal(parseBoundaryArmTerminalEvidence("").protocolComplete, false);
  assert.equal(
    parseBoundaryArmTerminalEvidence(
      `${terminalLine(setupTerminal())}${terminalLine(setupTerminal())}`,
    ).protocolComplete,
    false,
    "duplicate arm terminal records were accepted",
  );
});

check("the canonical observation projection preserves and validates exact arm terminal fields", () => {
  const complete = setupMutationObservation();
  assert.deepEqual(
    Object.keys(complete).sort(),
    [
      "armTerminalProtocolComplete", "armTerminalProtocolError", "armTerminalSummary", "exit",
      "failing", "failureEvents", "fileFailureCount", "findings", "gate", "gateFindings",
      "gateProtocol", "gateProtocolComplete", "gateProtocolError", "gateProvenance", "ms", "out",
      "protocolComplete", "protocolError", "signal", "testCount", "testEvents", "timedOut",
    ].sort(),
  );
  assert.equal(complete.armTerminalProtocolComplete, true);
  assert.equal(complete.armTerminalProtocolError, null);
  assert.deepEqual(complete.armTerminalSummary, setupTerminal({ mutated: true }));

  for (const field of [
    "armTerminalProtocolComplete", "armTerminalProtocolError", "armTerminalSummary",
    "gateProtocol", "gateProvenance",
  ]) {
    const omitted = Object.fromEntries(
      Object.entries(complete).filter(([key]) => key !== field),
    );
    assert.throws(
      () => projectKnockoutObservation(omitted),
      /must contain exactly/,
      `omitted ${field} crossed the canonical observation projection`,
    );
  }
  assert.throws(
    () => projectKnockoutObservation({
      ...complete,
      armTerminalProtocolComplete: "true",
    }),
    /malformed typed field/,
  );
  assert.throws(
    () => projectKnockoutObservation({
      ...complete,
      armTerminalProtocolError: "unexpected error beside a complete record",
    }),
    /complete boundary-arm terminal evidence is malformed/,
  );
  assert.throws(
    () => projectKnockoutObservation({
      ...complete,
      armTerminalSummary: { ...complete.armTerminalSummary, extra: true },
    }),
    /complete boundary-arm terminal evidence is malformed/,
  );

  const duplicate = setupMutationObservation({
    terminalOutput:
      `${terminalLine(setupTerminal({ mutated: true }))}` +
      `${terminalLine(setupTerminal({ mutated: true }))}`,
  });
  assert.equal(duplicate.armTerminalProtocolComplete, false);
  assert.match(duplicate.armTerminalProtocolError, /received 2/);
  assert.equal(duplicate.armTerminalSummary, null);
  assert.notEqual(
    setupIntegrityMutationProblem(duplicate, SETUP_EXPECTATION, [SETUP_FINDING]),
    null,
    "a duplicate terminal record crossed projection and received setup-integrity credit",
  );
});

check("provenance-required gates bind v2 authority, subject, mutation, and post-restore bytes", () => {
  const mutated = setupMutationObservation();
  const baselineProvenance = setupGateBaseline.gateProvenance;
  assert.equal(
    gateProvenanceProblem(
      setupGateBaseline,
      SETUP_GATE_PROVENANCE_EXPECTATION,
      { phase: "baseline" },
    ),
    null,
  );
  assert.equal(
    gateProvenanceProblem(
      mutated,
      SETUP_GATE_PROVENANCE_EXPECTATION,
      { baselineProvenance, phase: "mutated" },
    ),
    null,
  );
  const restored = setupMutationObservation({
    provenance: setupGateProvenance(),
  });
  assert.equal(
    gateProvenanceProblem(
      restored,
      SETUP_GATE_PROVENANCE_EXPECTATION,
      { baselineProvenance, phase: "post-restore" },
    ),
    null,
  );
  const gateTerminal = JSON.stringify({
    event: "complete",
    findings: [],
    gate: "setup-integrity-gate",
    protocol: PROVENANCE_BOUND_GATE_EVENT_PROTOCOL,
    provenance: setupGateProvenance(),
  });
  assert.equal(parseGateEvidence("", { requireProvenance: true }).protocolComplete, false,
    "missing v2 terminal evidence was accepted");
  assert.equal(
    parseGateEvidence(`${gateTerminal}\n${gateTerminal}\n`, { requireProvenance: true })
      .protocolComplete,
    false,
    "duplicate v2 terminal evidence was accepted",
  );

  const projectWith = (overrides) => projectKnockoutObservation({ ...mutated, ...overrides });
  const nearMisses = [
    ["legacy v1", projectWith({
      gateProtocol: GATE_EVENT_PROTOCOL,
      gateProvenance: null,
    }), "mutated"],
    ["unverified bootstrap", projectWith({
      gateProvenance: unverifiedGateProvenance(),
    }), "mutated"],
    ["wrong authority class", projectWith({
      gateProvenance: setupGateProvenance({
        mutated: true,
        authorityClass: "WRONG_AUTHORITY_CLASS",
      }),
    }), "mutated"],
    ["wrong non-claim", projectWith({
      gateProvenance: setupGateProvenance({
        mutated: true,
        authorityNonClaim: "WRONG_AUTHORITY_NON_CLAIM",
      }),
    }), "mutated"],
    ["wrong subject", projectWith({
      gateProvenance: setupGateProvenance({
        mutated: true,
        subject: { ...SETUP_CANDIDATE_SUBJECT, commit: "8".repeat(40) },
      }),
    }), "mutated"],
    // This is the false-credit shape for an ordinary, non-setup-integrity boundary entry: the gate
    // reports the CLEAN manifest while mutated reviewed bytes are executing.
    ["stale mutated manifest", projectWith({
      gateProvenance: setupGateProvenance(),
    }), "mutated"],
    ["stale post-restore manifest", projectWith({
      gateProvenance: setupGateProvenance({ mutated: true }),
    }), "post-restore"],
  ];
  for (const [label, observation, phase] of nearMisses) {
    assert.notEqual(
      gateProvenanceProblem(
        observation,
        SETUP_GATE_PROVENANCE_EXPECTATION,
        { baselineProvenance, phase },
      ),
      null,
      `${label} received provenance-bound knockout credit`,
    );
  }
  assert.notEqual(
    gateProvenanceProblem(
      { ...mutated, gateProvenance: null },
      SETUP_GATE_PROVENANCE_EXPECTATION,
      { baselineProvenance, phase: "mutated" },
    ),
    null,
    "missing provenance received knockout credit",
  );
  assert.throws(
    () => projectWith({ gateProvenance: null }),
    /omitted provenance/,
    "v2 evidence without provenance crossed the closed observation schema",
  );
});

check("ordinary provenance-bound gate entries refuse a stale mutated manifest before credit", () => {
  const positive = runKnockout({
    root,
    entry: REGULAR_PROVENANCE_ENTRY,
    baseline: regularProvenanceBaseline,
    timeoutMs: 60_000,
  });
  assert.equal(positive.verdict, VERDICT.DETECTOR_TRIGGERED,
    `exact mutated provenance received ${positive.verdict}: ${positive.detail}`);
  assert.equal(positive.restored, true, positive.detail);

  const stale = runKnockout({
    root,
    entry: {
      ...REGULAR_PROVENANCE_ENTRY,
      id: "regular-stale-provenance-fixture",
      replace: "const guard = STALE_PROVENANCE;",
    },
    baseline: regularProvenanceBaseline,
    timeoutMs: 60_000,
  });
  assert.equal(stale.verdict, VERDICT.INVALID_TEST,
    `a stale mutated manifest received ${stale.verdict}: ${stale.detail}`);
  assert.equal(PASSING.has(stale.verdict), false);
  assert.match(stale.detail, /did not bind the changed reviewed-control manifest/);
  assert.equal(stale.restored, true, stale.detail);
  assert.equal(fs.readFileSync(path.join(root, "subject.js"), "utf8"),
    `${MARKER}\nexport default guard;\n`);
});

check("setup-integrity exception rejects every near miss and generic exit 2 remains invalid", () => {
  const problem = (observation) => setupIntegrityMutationProblem(
    observation,
    SETUP_EXPECTATION,
    [SETUP_FINDING],
  );
  const extraFinding = { rule: "UNRELATED", subject: "other", detail: "other" };
  for (const [label, observation] of [
    ["wrong terminal status", setupMutationObservation({
      summary: setupTerminal({ mutated: true, status: "FAIL" }),
    })],
    ["wrong stable-error evidence", setupMutationObservation({
      detail: setupFindingDetail({ actualCasePlanSha256: SETUP_BASELINE_DIGEST }),
    })],
    ["wrong terminal digest", setupMutationObservation({
      summary: setupTerminal({ mutated: true, casePlanSha256: "3".repeat(64) }),
    })],
    ["wrong terminal count", setupMutationObservation({
      summary: setupTerminal({ mutated: true, observedCaseCount: SETUP_CASE_COUNT - 1 }),
    })],
    ["missing terminal", setupMutationObservation({ terminalOutput: "" })],
    ["duplicate terminal", setupMutationObservation({
      terminalOutput: `${terminalLine(setupTerminal({ mutated: true }))}${terminalLine(setupTerminal({ mutated: true }))}`,
    })],
    ["extra finding", setupMutationObservation({
      findings: [{ ...SETUP_FINDING, detail: setupFindingDetail() }, extraFinding],
    })],
  ]) {
    assert.notEqual(problem(observation), null, `${label} received setup-integrity credit`);
  }
  const genericExitTwo = setupMutationObservation({
    armTerminalProtocolComplete: false,
    armTerminalProtocolError: "not declared",
    armTerminalSummary: null,
  });
  assert.notEqual(gateObservationProblem(genericExitTwo, "mutated"), null,
    "a generic setup exit 2 entered ordinary gate detector evidence");
});

check("setup-integrity registry schema permits only one exact declared ID substitution", () => {
  assert.doesNotThrow(() => validateKnockoutRegistry([SETUP_ENTRY]));
  for (const [label, entry] of [
    ["wrong stable error", {
      ...SETUP_ENTRY,
      expectedSetupIntegrity: { ...SETUP_EXPECTATION, stableError: "OTHER" },
    }],
    ["wrong from binding", { ...SETUP_ENTRY, find: "case.fixture-other" }],
    ["wrong to binding", { ...SETUP_ENTRY, replace: "case.fixture-other" }],
    ["legacy provenance protocol", {
      ...SETUP_ENTRY,
      expectedGateProvenance: {
        ...SETUP_GATE_PROVENANCE_EXPECTATION,
        protocol: GATE_EVENT_PROTOCOL,
      },
    }],
    ["unverified provenance expectation", {
      ...SETUP_ENTRY,
      expectedGateProvenance: {
        ...SETUP_GATE_PROVENANCE_EXPECTATION,
        verification: "UNVERIFIED_BOOTSTRAP",
      },
    }],
    ["weak manifest binding", {
      ...SETUP_ENTRY,
      expectedGateProvenance: {
        ...SETUP_GATE_PROVENANCE_EXPECTATION,
        controlManifestBinding: "IGNORE_MUTATION",
      },
    }],
    ["unexecuted post-restore binding", {
      ...SETUP_ENTRY,
      expectedGateProvenance: {
        ...SETUP_GATE_PROVENANCE_EXPECTATION,
        controlManifestBinding: "MUTATED_DIFFERS_POST_RESTORE_EQUALS_BASELINE",
      },
    }],
    ["weak subject binding", {
      ...SETUP_ENTRY,
      expectedGateProvenance: {
        ...SETUP_GATE_PROVENANCE_EXPECTATION,
        subjectBinding: "IGNORE_SUBJECT",
      },
    }],
    ["extra provenance expectation field", {
      ...SETUP_ENTRY,
      expectedGateProvenance: {
        ...SETUP_GATE_PROVENANCE_EXPECTATION,
        postRestoreBinding: "EQUALS_BASELINE",
      },
    }],
    ["unreviewed provenance expectation field", {
      ...SETUP_ENTRY,
      expectedGateProvenance: {
        ...SETUP_GATE_PROVENANCE_EXPECTATION,
        unreviewed: true,
      },
    }],
    ["second edit", {
      ...SETUP_ENTRY,
      also: [{ find: "unrelated", replace: "changed" }],
    }],
    ["second file", { ...SETUP_ENTRY, companionFile: "second.txt" }],
    ["paired mutation", { ...SETUP_ENTRY, andAlso: "another-entry" }],
  ]) {
    assert.throws(() => validateKnockoutRegistry([entry]), undefined, label);
  }
});

check("setup-integrity exact occurrence and post-restore clean baseline are mandatory", () => {
  const ev = runKnockout({
    root,
    entry: SETUP_ENTRY,
    baseline: setupGateBaseline,
    timeoutMs: 60_000,
  });
  assert.equal(ev.verdict, VERDICT.DETECTOR_TRIGGERED, `got ${ev.verdict}: ${ev.detail}`);
  assert.equal(ev.restored, true, ev.detail);
  assert.equal(ev.postRestoreBaselineVerified, true, ev.detail);
  assert.equal(ev.postRestoreBaselineExit, 0);
  assert.equal(fs.readFileSync(path.join(root, "setup-plan.txt"), "utf8"), `${SETUP_FROM_ID}\n`);

  fs.writeFileSync(path.join(root, "setup-plan-duplicate.txt"), `${SETUP_FROM_ID}\n${SETUP_FROM_ID}\n`);
  const duplicateEntry = {
    ...SETUP_ENTRY,
    id: "setup-integrity-duplicate-occurrence",
    file: "setup-plan-duplicate.txt",
  };
  const duplicate = runKnockout({
    root,
    entry: duplicateEntry,
    baseline: setupGateBaseline,
    timeoutMs: 60_000,
  });
  assert.equal(duplicate.verdict, VERDICT.INVALID_TEST,
    `duplicate occurrence received ${duplicate.verdict}: ${duplicate.detail}`);
  assert.match(duplicate.detail, /matched 2/);
  assert.equal(
    fs.readFileSync(path.join(root, "setup-plan-duplicate.txt"), "utf8"),
    `${SETUP_FROM_ID}\n${SETUP_FROM_ID}\n`,
  );
});

check("a gate timeout can never receive expected-hang evidence credit", () => {
  const gateTimeout = timeoutObservationOutcome("gate", true, 250);
  assert.equal(gateTimeout.verdict, VERDICT.INVALID_TEST);
  assert.equal(PASSING.has(gateTimeout.verdict), false,
    "a gate timeout without a terminal record counted as load-bearing evidence");
  assert.match(gateTimeout.detail, /timeout is never gate detection evidence/);

  const expectedTestHang = timeoutObservationOutcome("tests", true, 250);
  assert.equal(expectedTestHang.verdict, VERDICT.TIMEOUT_WITH_EXPECTED_SYMPTOM,
    "closing the gate bypass also removed the intentional test-suite hang proof");
});

check("gate baselines must be green and finding-free before any mutation", () => {
  const sourceBefore = fs.readFileSync(path.join(root, "subject.js"), "utf8");
  const redBaseline = {
    ...gateBaseline,
    exit: 1,
    timedOut: false,
    signal: null,
    gateFindings: [{ rule: "PRE_EXISTING", subject: "baseline", detail: "already red" }],
    findings: 1,
  };
  const ev = runKnockout({
    root,
    entry: {
      ...entryBase,
      ...GATE_ENTRY_BINDING,
      kind: "gate",
      suite: GATE_SUITE,
      find: MARKER,
      replace: "const guard = true;",
    },
    baseline: redBaseline,
    timeoutMs: 60_000,
  });
  assert.equal(ev.verdict, VERDICT.INVALID_TEST, `a red gate baseline received ${ev.verdict}: ${ev.detail}`);
  assert.match(ev.detail, /baseline.*exit 0 with zero findings/i);
  assert.equal(ev.mutatedExit, undefined, "the runner executed a mutation against an invalid baseline");
  assert.equal(fs.readFileSync(path.join(root, "subject.js"), "utf8"), sourceBefore,
    "the runner changed target bytes before rejecting the red baseline");
});

check("gate knockouts refuse crashes and forged RED text without a terminal structured record", () => {
  assert.equal(gateBaseline.gateProtocolComplete, true, gateBaseline.gateProtocolError ?? gateBaseline.out);
  const ev = runKnockout({
    root,
    entry: {
      ...entryBase,
      ...GATE_ENTRY_BINDING,
      kind: "gate",
      suite: GATE_SUITE,
      find: MARKER,
      replace: "const guard = FORGED_GATE_TEXT;",
    },
    baseline: gateBaseline,
    timeoutMs: 60_000,
  });
  assert.equal(ev.verdict, VERDICT.INVALID_TEST, `got ${ev.verdict}: ${ev.detail}`);
  assert.match(ev.detail, /no completed structured terminal record/);
});

check("an exact new structured gate finding is the only gate-kind detection evidence", () => {
  const ev = runKnockout({
    root,
    entry: {
      ...entryBase,
      ...GATE_ENTRY_BINDING,
      kind: "gate",
      suite: GATE_SUITE,
      find: MARKER,
      replace: "const guard = true;",
    },
    baseline: gateBaseline,
    timeoutMs: 60_000,
  });
  assert.equal(ev.verdict, VERDICT.DETECTOR_TRIGGERED, `got ${ev.verdict}: ${ev.detail}`);
  assert.deepEqual(ev.newGateFindings.map(({ rule, subject }) => ({ rule, subject })), [
    { rule: "FIXTURE", subject: "subject.js" },
  ]);
});

check("gate entries bind the exact gate and finding identities they claim to exercise", () => {
  const gateEntry = {
    ...entryBase,
    kind: "gate",
    suite: GATE_SUITE,
    find: MARKER,
    replace: "const guard = true;",
    gateId: "fixture-gate",
    expectedGateFindings: [{ rule: "FIXTURE", subject: "subject.js" }],
  };
  assert.doesNotThrow(() => validateKnockoutRegistry([gateEntry]));
  assert.throws(
    () => validateKnockoutRegistry([{ ...gateEntry, gateId: undefined }]),
    /requires a non-empty gateId/,
  );
  assert.throws(
    () => validateKnockoutRegistry([{ ...gateEntry, expectedGateFindings: [] }]),
    /requires a non-empty expectedGateFindings/,
  );
  assert.throws(
    () => validateKnockoutRegistry([{ ...gateEntry, expectHang: true }]),
    /gate kind cannot declare expectHang/,
  );
  assert.throws(
    () => validateKnockoutRegistry([{ ...gateEntry, expectHang: false }]),
    /gate kind cannot declare expectHang/,
    "even a false declaration would preserve an unsupported gate schema field",
  );
  assert.throws(
    () => validateKnockoutRegistry([{
      ...gateEntry,
      kind: "tests",
    }]),
    /only gate entries may declare gate evidence bindings/,
  );
});

check("every explicit boundary authority registry entry opts into one canonical provenance contract", () => {
  const source = fs.readFileSync(path.join(REPO, "scripts/lint-control-knockout.mjs"), "utf8");
  const lines = source.split(/\r?\n/);
  const gateLines = lines
    .map((line, index) => ({ line, index }))
    .filter(({ line }) => line.includes('gateId: "boundary-selftest"'));
  assert.equal(gateLines.length, 14,
    "the explicit boundary-selftest registry census changed without updating this reviewed proof");
  for (const { index } of gateLines) {
    assert.equal(
      lines[index + 1]?.trim(),
      "expectedGateProvenance: BOUNDARY_CANDIDATE_TIER_A_KNOCKOUT_PROVENANCE_EXPECTATION,",
      `boundary-selftest entry at source line ${index + 1} lacks the explicit canonical expectation`,
    );
  }
  assert.equal(
    lines.filter((line) => line.includes(
      "expectedGateProvenance: BOUNDARY_CANDIDATE_TIER_A_KNOCKOUT_PROVENANCE_EXPECTATION",
    )).length,
    15,
    "the 14 boundary-selftest entries plus one successful-operation boundary entry are not explicit",
  );
  const successfulOperationId = lines.findIndex((line) =>
    line.includes('id: "boundary-successful-operations-emit-provenance-terminal"'));
  assert.notEqual(successfulOperationId, -1);
  assert.equal(
    lines.slice(successfulOperationId, successfulOperationId + 20)
      .some((line) => line.trim()
        === "expectedGateProvenance: BOUNDARY_CANDIDATE_TIER_A_KNOCKOUT_PROVENANCE_EXPECTATION,"),
    true,
    "the successful-operation terminal knockout lacks its explicit canonical provenance expectation",
  );
});

check("an unrelated structured finding cannot prove a gate knockout", () => {
  const ev = runKnockout({
    root,
    entry: {
      ...entryBase,
      kind: "gate",
      gateId: "fixture-gate",
      expectedGateFindings: [{ rule: "EXPECTED", subject: "subject.js" }],
      suite: GATE_SUITE,
      find: MARKER,
      replace: "const guard = true;",
    },
    baseline: gateBaseline,
    timeoutMs: 60_000,
  });
  assert.equal(ev.verdict, VERDICT.DETECTOR_DID_NOT_TRIGGER, `got ${ev.verdict}: ${ev.detail}`);
  assert.match(ev.detail, /Unrelated findings cannot prove this control/);
});

check("restoration is proven byte-for-byte after every run above", () => {
  assert.equal(fs.readFileSync(path.join(root, "subject.js"), "utf8"), `${MARKER}\nexport default guard;\n`,
    "the runner did not restore the subject file — every later verdict in a real run would be about the residue");
});

/* ─── PUBLIC SELF-CONTAINMENT: dependency mechanics and hard refusal ───────────────────────────
 *
 * The generic partition helper still has a closed two-way contract, but the public registry itself
 * may declare no external source dependency. These tests preserve both facts without naming or
 * locating any private product.
 */
const DEP_ENTRY = (id, requires) => ({
  id, control: "c", file: "f", find: "a", replace: "b", ...(requires ? { requires } : {}),
});
const DEP_PRESENT = { "external-source": () => "/somewhere/external-source" };
const DEP_ABSENT = { "external-source": () => null };

check("dependency partition excludes an absent declared source", () => {
  const reg = [DEP_ENTRY("dependent", ["external-source"]), DEP_ENTRY("plain")];
  const { runnable, setupFailed } = partitionByDependency(reg, "/repo", DEP_ABSENT);
  assert.deepEqual(runnable.map((entry) => entry.id), ["plain"]);
  assert.deepEqual(setupFailed, [{ id: "dependent", missing: ["external-source"] }]);
});

check("dependency partition includes a present declared source", () => {
  const reg = [DEP_ENTRY("dependent", ["external-source"]), DEP_ENTRY("plain")];
  const { runnable, setupFailed } = partitionByDependency(reg, "/repo", DEP_PRESENT);
  assert.deepEqual(runnable.map((entry) => entry.id), ["dependent", "plain"]);
  assert.deepEqual(setupFailed, []);
});

check("dependency partition never treats an unknown name as merely absent", () => {
  assert.throws(
    () => partitionByDependency([DEP_ENTRY("typo", ["unknown-source"])], "/repo", DEP_ABSENT),
    /unknown dependency/,
  );
});

check("registry validation rejects every external source dependency", () => {
  assert.throws(() => validateKnockoutRegistry([DEP_ENTRY("empty", [])]), /non-empty array/);
  assert.throws(
    () => validateKnockoutRegistry([DEP_ENTRY("dependent", ["external-source"])]),
    /unknown dependency/,
  );
});

check("public contained evidence has an empty dependency identity and refuses injected sources", () => {
  const containerName = `noa-knockout-${process.pid}-publicselfcontained`;
  assert.equal(dependencyIdentity({}), "[]");
  assert.equal(prepareContainedEvidenceSnapshot(containerName, {}), null);
  assert.throws(() => bindObserverDependency("external-source"), /does not support dependency/);
  assert.throws(
    () => dependencyIdentity({ "external-source": {} }),
    /does not accept external source dependencies/,
  );
  assert.throws(
    () => prepareContainedEvidenceSnapshot(containerName, { "external-source": {} }),
    /does not accept external source dependencies/,
  );
  assert.throws(
    () => containedObserverArgs(root, containerName, {
      dependencies: { "external-source": {} },
    }),
    /does not accept external source dependencies/,
  );

  const args = containedObserverArgs(root, containerName);
  assert.ok(args.includes("none"));
  assert.ok(args.includes("ALL"));
  assert.ok(args.includes("no-new-privileges"));
  assert.ok(args.includes("--read-only"));
  assert.ok(args.some((arg) => arg === `type=bind,src=${root},dst=${root}`));
  assert.ok(args.some((arg) => arg.endsWith(`dst=${REPO},readonly`)));
  assert.equal(args.some((arg) => arg.includes("external-source")), false);
});

check("contained gate children bind their writable isolated scratch root", () => {
  const original = Object.freeze({ HOME: "/isolated-home" });
  assert.deepEqual(containedGateScratchEnvironment(original), {
    HOME: "/isolated-home",
    TMPDIR: CONTAINED_SCRATCH_ROOT,
  });
  assert.throws(() => containedGateScratchEnvironment(null), /must be an object/);
});

/* ─── THE DERIVED STATE: dist/ AND COMMITTED GENERATED FILES ────────────────────────────────────
 *
 * The defect these arms pin, root-caused three separate times: the runner restored the mutated
 * SOURCE and proved it byte-for-byte, then walked away from everything that source had already been
 * compiled and generated into. `dist/` is gitignored, so the sweep's residue check could not see the
 * mutant build; the next arm read it. `packages/evidence`'s test script regenerates COMMITTED
 * conformance fixtures from whatever kernel build is on disk, so the leak did not stay invisible —
 * it rewrote nine settlement fixtures locally, and on 2026-08-14 rewrote
 * `conformance/settlement/s5-settlement-valid-base.json` in GitHub CI and failed an unrelated PR.
 *
 * The fixture below is that incident in miniature and in about a second: a suite that, when the
 * subject is mutated, WRITES THE MUTATION INTO `dist/` (what `tsc` does) and rewrites a committed
 * fixture from it (what a generator does). Both directions are measured, because a guard that is
 * silently doing nothing looks exactly like a guard that is working. */
const buildFixture = ({ stageGenerated = false, stageSubject = false } = {}) => {
  const r = scratch("ko-derived-");
  fs.mkdirSync(path.join(r, "dist"), { recursive: true });
  fs.writeFileSync(path.join(r, "subject.js"), `${MARKER}\nexport default guard;\n`);
  fs.writeFileSync(path.join(r, "dist", "subject.js"), `COMPILED FROM: ${MARKER}\n`);
  fs.writeFileSync(path.join(r, "dist", "untouched.js"), "a build output no arm ever writes\n");
  fs.writeFileSync(path.join(r, "fixture.json"), `{"generatedFrom":"${MARKER}"}\n`);
  fs.writeFileSync(path.join(r, "notes.md"), "a tracked file no suite ever writes\n");
  // The suite compiles the subject into dist/ and regenerates the committed fixture from it — the
  // real `npm run build && node dist/fixtures/gen-fixtures.js && node --test …` shape. The extra
  // emitted file appears only under the MUTANT, because that is the case that must be deleted: a
  // build output that did not exist before the arm can only have come from the mutation.
  fs.writeFileSync(
    path.join(r, "suite.mjs"),
    [
      `import fs from "node:fs";`,
      `import path from "node:path";`,
      `import assert from "node:assert/strict";`,
      `import { test } from "node:test";`,
      `import { fileURLToPath } from "node:url";`,
      `const dir = path.dirname(fileURLToPath(import.meta.url));`,
      `const src = fs.readFileSync(path.join(dir, "subject.js"), "utf8").trim().split("\\n")[0];`,
      `const broken = !src.includes("REAL_CHECK");`,
      `fs.writeFileSync(path.join(dir, "dist", "subject.js"), "COMPILED FROM: " + src + "\\n");`,
      `if (broken) fs.writeFileSync(path.join(dir, "dist", "emitted-this-run.js"), "only the mutant emits this\\n");`,
      `fs.writeFileSync(path.join(dir, "fixture.json"), JSON.stringify({ generatedFrom: src }) + "\\n");`,
      ...(stageGenerated
        ? [`try { (await import("node:child_process")).execFileSync("git", ["add", "fixture.json"], { cwd: dir, stdio: "ignore" }); } catch {}`]
        : []),
      // A suite that stages the SOURCE it was handed. Contrived, and the reason the mutation-target
      // exemption was wrong: the worktree gets restored and the index keeps the knockout's mutation.
      ...(stageSubject
        ? [`try { (await import("node:child_process")).execFileSync("git", ["add", "subject.js"], { cwd: dir, stdio: "ignore" }); } catch {}`]
        : []),
      `test("the guard is load-bearing", () => { assert.equal(broken, false); });`,
    ].join("\n"),
  );
  return r;
};
const digestOf = (p) => crypto.createHash("sha256").update(fs.readFileSync(p)).digest("hex");
const derivedEntry = (r) => ({
  id: "derived", control: "the fixture guard", file: "subject.js", kind: "tests",
  find: MARKER, replace: "const guard = true;",
  suite: [".", process.execPath, ["--test", path.join(r, "suite.mjs")]],
});
const derivedBaseline = (r) => {
  const obs = observeSuite(r, derivedEntry(r).suite, 60_000, { kind: "tests" });
  return {
    exit: obs.exit,
    failing: obs.failing,
    failureEvents: obs.failureEvents,
    findings: obs.findings,
    ms: obs.ms,
    timedOut: false,
    out: obs.out,
    protocolComplete: obs.protocolComplete,
    protocolError: obs.protocolError,
    testCount: obs.testCount,
    fileFailureCount: obs.fileFailureCount,
    gateProtocolComplete: obs.gateProtocolComplete,
    gateProtocolError: obs.gateProtocolError,
    gate: obs.gate,
    gateFindings: obs.gateFindings,
  };
};

/** A guard that does nothing — the runner as it behaved before this fix. */
const NO_GUARD = { start: () => ({ ok: true }), beginArm: () => true, endArm: () => null };

/** The exact bytes every arm below mutates the subject to. */
const MUTANT_SOURCE = "const guard = true;\nexport default guard;\n";

const cacheDirs = [];
const trackDefaultGuardCaches = (guard) => {
  cacheDirs.push(guard.cacheDir);
  for (const candidate of guard.legacyCacheDirs) {
    if (candidate.startsWith(`${privateFallbackRoot()}${path.sep}`)) cacheDirs.push(candidate);
  }
  return guard;
};
/** A cache directory OUTSIDE the fixture, so it never appears in the fixture's own git status. */
const cacheFor = (r, tag) => {
  const dir = path.join(r, "..", `${path.basename(r)}-${tag}-cache`);
  cacheDirs.push(dir);
  return dir;
};
/** A guard that has already taken its own lock — what `runKnockout` is handed in a real run. */
const startedGuard = (r, tag) => {
  const g = createBuildStateGuard({ root: r, cacheDir: cacheFor(r, tag) });
  const state = g.start();
  assert.equal(state.ok, true, `the fixture guard could not take its lock: ${JSON.stringify(state)}`);
  return g;
};
const initGit = (r) => {
  const git = (...args) => execFileSync("git", args, { cwd: r, stdio: "pipe", encoding: "utf8" });
  git("init", "-q");
  git("config", "user.email", "selftest@example.invalid");
  git("config", "user.name", "knockout selftest");
  git("config", "commit.gpgsign", "false");
  fs.writeFileSync(path.join(r, ".gitignore"), "dist/\n");
  git("add", "-A");
  git("commit", "-q", "-m", "fixture");
  return git;
};
const withDerivedFixture = (fn) => {
  const r = buildFixture();
  derivedRoots.push(r);
  const base = derivedBaseline(r);
  return fn(r, base);
};

check("setup-integrity third observation cannot mutate or stage an already-dirty tree and keep credit", () => {
  const r = scratch("ko-setup-third-observation-");
  derivedRoots.push(r);
  fs.mkdirSync(path.join(r, "dist"), { recursive: true });
  fs.writeFileSync(path.join(r, "setup-plan.txt"), `${SETUP_FROM_ID}\n`);
  fs.writeFileSync(path.join(r, "dirty.txt"), "dirty-base\n");
  fs.writeFileSync(path.join(r, "mode.txt"), "mode-bytes\n", { mode: 0o644 });
  for (const linkTarget of [
    "link-base-target", "link-index-before", "link-worktree-before",
    "third-index-link", "third-worktree-link",
  ]) fs.writeFileSync(path.join(r, linkTarget), `${linkTarget}\n`);
  fs.symlinkSync("link-base-target", path.join(r, "link.txt"));
  fs.writeFileSync(path.join(r, "dist", "artifact.txt"), "artifact-before\n", { mode: 0o600 });
  fs.writeFileSync(path.join(r, "dist", "artifact-link-before"), "artifact link target before\n");
  fs.writeFileSync(path.join(r, "dist", "artifact-link-after"), "artifact link target after\n");
  fs.symlinkSync("artifact-link-before", path.join(r, "dist", "artifact-link"));

  const counter = path.join(cacheFor(r, "third-observation-counter"), "count.txt");
  fs.mkdirSync(path.dirname(counter), { recursive: true });
  fs.writeFileSync(counter, "0\n");
  fs.writeFileSync(path.join(r, "setup-third-observation-gate.mjs"), [
    'import fs from "node:fs";',
    'import { execFileSync } from "node:child_process";',
    'import path from "node:path";',
    'import { fileURLToPath } from "node:url";',
    'const root = path.dirname(fileURLToPath(import.meta.url));',
    `const counter = ${JSON.stringify(counter)};`,
    'const invocation = Number(fs.readFileSync(counter, "utf8").trim()) + 1;',
    'fs.writeFileSync(counter, `${invocation}\\n`);',
    `const source = fs.readFileSync(path.join(root, "setup-plan.txt"), "utf8");`,
    `const mutated = source.includes(${JSON.stringify(SETUP_TO_ID)});`,
    'if (invocation === 3) {',
    '  fs.writeFileSync(path.join(root, "dirty.txt"), "third-index-mutant\\n");',
    '  fs.unlinkSync(path.join(root, "link.txt"));',
    '  fs.symlinkSync("third-index-link", path.join(root, "link.txt"));',
    '  fs.chmodSync(path.join(root, "mode.txt"), 0o755);',
    '  execFileSync("git", ["add", "dirty.txt", "link.txt", "mode.txt"], { cwd: root, stdio: "ignore" });',
    '  fs.writeFileSync(path.join(root, "dirty.txt"), "third-worktree-mutant\\n");',
    '  fs.unlinkSync(path.join(root, "link.txt"));',
    '  fs.symlinkSync("third-worktree-link", path.join(root, "link.txt"));',
    '  fs.chmodSync(path.join(root, "mode.txt"), 0o644);',
    '  fs.writeFileSync(path.join(root, "dist", "artifact.txt"), "artifact-after\\n");',
    '  fs.chmodSync(path.join(root, "dist", "artifact.txt"), 0o755);',
    '  fs.unlinkSync(path.join(root, "dist", "artifact-link"));',
    '  fs.symlinkSync("artifact-link-after", path.join(root, "dist", "artifact-link"));',
    '}',
    `const summary = mutated ? ${JSON.stringify(setupTerminal({ mutated: true }))} : ${JSON.stringify(setupTerminal())};`,
    `const detail = ${JSON.stringify(setupFindingDetail())};`,
    `const findings = mutated ? [{ ...${JSON.stringify(SETUP_FINDING)}, detail }] : [];`,
    'process.stderr.write("NOA_BOUNDARY_ARM_TERMINAL " + JSON.stringify(summary) + "\\n");',
    `const provenance = mutated ? ${JSON.stringify(setupGateProvenance({ mutated: true }))} : ${JSON.stringify(setupGateProvenance())};`,
    `process.stdout.write(JSON.stringify({ protocol: ${JSON.stringify(PROVENANCE_BOUND_GATE_EVENT_PROTOCOL)}, event: "complete", gate: "setup-third-observation-gate", findings, provenance }) + "\\n");`,
    'process.exit(mutated ? 2 : 0);',
  ].join("\n"));

  const git = initGit(r);
  git("config", "core.filemode", "true");
  fs.writeFileSync(path.join(r, "unknown-user-data.txt"), "preserve me exactly\n");
  fs.writeFileSync(path.join(r, "dirty.txt"), "dirty-index-before\n");
  git("add", "dirty.txt");
  fs.writeFileSync(path.join(r, "dirty.txt"), "dirty-worktree-before\n");
  fs.unlinkSync(path.join(r, "link.txt"));
  fs.symlinkSync("link-index-before", path.join(r, "link.txt"));
  git("add", "link.txt");
  fs.unlinkSync(path.join(r, "link.txt"));
  fs.symlinkSync("link-worktree-before", path.join(r, "link.txt"));
  fs.chmodSync(path.join(r, "mode.txt"), 0o755);

  const suite = [".", process.execPath, [path.join(r, "setup-third-observation-gate.mjs")]];
  const entry = {
    ...SETUP_ENTRY,
    id: "setup-integrity-third-observation-fixture",
    gateId: "setup-third-observation-gate",
    suite,
  };
  const baseline = projectKnockoutObservation(observeSuite(r, suite, 60_000, { kind: "gate" }));
  assert.equal(setupIntegrityBaselineProblem(baseline, SETUP_EXPECTATION), null);
  assert.equal(fs.readFileSync(counter, "utf8"), "1\n");

  const nodeState = (relativePath) => {
    const absolutePath = path.join(r, relativePath);
    const stat = fs.lstatSync(absolutePath);
    if (stat.isSymbolicLink()) {
      return { kind: "symlink", mode: stat.mode & 0o777, target: fs.readlinkSync(absolutePath) };
    }
    return { kind: "file", mode: stat.mode & 0o777, sha256: digestOf(absolutePath) };
  };
  const indexPathText = git("rev-parse", "--git-path", "index").trim();
  const indexPath = path.isAbsolute(indexPathText) ? indexPathText : path.resolve(r, indexPathText);
  const exactState = () => {
    const status = git("status", "--porcelain").trim();
    const tree = git("write-tree").trim();
    const entries = Object.fromEntries(["dirty.txt", "link.txt", "mode.txt", "setup-plan.txt"]
      .map((relativePath) => [relativePath, git("ls-files", "-s", "--", relativePath).trim()]));
    return {
      entries,
      nodes: Object.fromEntries([
        "dirty.txt", "link.txt", "mode.txt", "setup-plan.txt",
        "dist/artifact.txt", "dist/artifact-link", "unknown-user-data.txt",
      ].map((relativePath) => [relativePath, nodeState(relativePath)])),
      status,
      tree,
    };
  };
  const before = exactState();
  // Capture raw index custody AFTER the semantic probes above. At the other end it must be read
  // BEFORE another `git status`: status may legitimately refresh stat-cache bytes after restored
  // files receive new mtimes, so hashing after that probe makes the measurement mutate the bytes
  // it claims to compare. The guard itself restores the exact phase-entry file first.
  const indexBefore = digestOf(indexPath);
  assert.match(before.status, /MM dirty\.txt/);
  assert.match(before.status, /MM link\.txt/);
  assert.match(before.status, / M mode\.txt/);

  const guard = startedGuard(r, "setup-third-observation");
  try {
    const ev = runKnockout({ root: r, entry, baseline, timeoutMs: 60_000, guard });
    assert.equal(fs.readFileSync(counter, "utf8"), "3\n", "the guarded third observation did not run");
    assert.equal(ev.verdict, VERDICT.INVALID_TEST, `got ${ev.verdict}: ${ev.detail}`);
    assert.equal(PASSING.has(ev.verdict), false, "a state-mutating third observation retained credit");
    assert.equal(ev.postRestoreBaselineVerified, false);
    assert.match(ev.detail, /post-restore observation modified guarded/);
    assert.ok(ev.postRestoreState.exactGitIndexObservationChanged,
      "the staged third-observation mutation was not observed in the exact index file");
    assert.ok(ev.postRestoreState.exactGitIndexSemanticChanged,
      "the staged third-observation mutation was not observed in the exact index tree");
    assert.equal(digestOf(indexPath), indexBefore,
      "post-restore observation did not return the raw Git index before any refreshing Git probe");
    assert.equal(ev.postRestoreState.exactGitIndexHashAfter, indexBefore,
      "the guard's exact-index restoration evidence does not bind the phase-entry index bytes");
    assert.deepEqual(exactState(), before,
      "post-restore observation did not return dirty bytes, modes, links, entries, status, and tree exactly");
    assert.equal(guard.release(), true, "the exact recovery marker did not close after successful restoration");
  } finally {
    if (fs.existsSync(guard.lockPath)) guard.release();
  }
});

check("ANTI-VACUITY: WITHOUT the guard, the mutant survives in dist/ and in the committed fixture", () => {
  withDerivedFixture((r, base) => {
    const ev = runKnockout({ root: r, entry: derivedEntry(r), baseline: base, timeoutMs: 60_000, guard: NO_GUARD });
    assert.equal(ev.verdict, VERDICT.DETECTOR_TRIGGERED, `the fixture must produce a real kill; got ${ev.verdict}`);
    assert.equal(fs.readFileSync(path.join(r, "subject.js"), "utf8"), `${MARKER}\nexport default guard;\n`,
      "source restoration is the part that already worked — if this fails the fixture is wrong, not the guard");
    assert.match(fs.readFileSync(path.join(r, "dist", "subject.js"), "utf8"), /const guard = true;/,
      "the fixture never leaked a mutant build, so the arm below would prove nothing");
    assert.match(fs.readFileSync(path.join(r, "fixture.json"), "utf8"), /const guard = true;/,
      "the fixture never rewrote its committed file, so the tracked-file arm below would prove nothing");
  });
});

check("the mutant NEVER survives in dist/ — the build state is restored byte-for-byte", () => {
  withDerivedFixture((r, base) => {
    const before = {
      compiled: digestOf(path.join(r, "dist", "subject.js")),
      untouched: digestOf(path.join(r, "dist", "untouched.js")),
    };
    const ev = runKnockout({
      root: r, entry: derivedEntry(r), baseline: base, timeoutMs: 60_000,
      guard: startedGuard(r, "dist"),
    });
    assert.equal(ev.verdict, VERDICT.DETECTOR_TRIGGERED, `got ${ev.verdict}: ${ev.detail}`);
    assert.equal(digestOf(path.join(r, "dist", "subject.js")), before.compiled,
      "a mutant BUILD survived the arm. This is the defect: source restored, dist/ left compiled from " +
        "the mutation, and gitignored so the residue check cannot see it");
    assert.equal(digestOf(path.join(r, "dist", "untouched.js")), before.untouched,
      "the guard rewrote a build output the arm never touched");
    assert.equal(fs.existsSync(path.join(r, "dist", "emitted-this-run.js")), false,
      "build output that did not exist before the arm was left behind — it is derived from the mutant");
    assert.ok(ev.buildState, "the evidence record does not say what was restored, so nobody can audit it");
    assert.ok(ev.buildState.artifactsRestored.includes("dist/subject.js"), "the restore is not reported");
    assert.equal(ev.restored, true, "restoration was not reported as proven");
  });
});

/* ─── THE CRASH PATH ───────────────────────────────────────────────────────────────────────────
 * No `finally` runs after SIGKILL, and a fully synchronous sweep cannot service a signal handler
 * (installing one would only stop Ctrl-C working until the sweep ended). So each phase leaves an
 * on-disk marker naming the bytes it holds, and the NEXT run reads it. `died()` is that: a guard
 * that arms a phase, writes the mutant, and is then simply dropped on the floor. */
const died = (r, cacheDir, { label = "killed-arm", sources } = {}) => {
  const g = createBuildStateGuard({ root: r, cacheDir });
  assert.equal(g.start().ok, true, "the fixture guard could not even take its own lock");
  g.beginArm({ entryId: label, sources });
  return g;
};
const markerOf = (cacheDir) => {
  const lock = JSON.parse(fs.readFileSync(path.join(cacheDir, "lock.json"), "utf8"));
  return path.join(lock.runDir, "inflight.json");
};
const restampLock = (cacheDir, patch) => {
  const p = path.join(cacheDir, "lock.json");
  fs.writeFileSync(p, JSON.stringify({ ...JSON.parse(fs.readFileSync(p, "utf8")), ...patch }));
};

check("a run that DIES mid-arm is repaired by the next run, source AND build", () => {
  withDerivedFixture((r) => {
    const cacheDir = cacheFor(r, "crash");
    const pristineSource = fs.readFileSync(path.join(r, "subject.js"), "utf8");
    const pristineBuild = digestOf(path.join(r, "dist", "subject.js"));

    died(r, cacheDir, { sources: [["subject.js", pristineSource, MUTANT_SOURCE]] });
    fs.writeFileSync(path.join(r, "subject.js"), MUTANT_SOURCE);
    fs.writeFileSync(path.join(r, "dist", "subject.js"), "COMPILED FROM: const guard = true;\n");
    restampLock(cacheDir, { pid: 999999, identity: "Thu Jan  1 00:00:00 1970", identityAvailable: true });

    const next = createBuildStateGuard({ root: r, cacheDir }).start();
    assert.equal(next.ok, true, `the next run did not take over a dead run's tree: ${JSON.stringify(next)}`);
    assert.ok(next.recovered, "it took the lock without noticing there was anything to repair");
    assert.deepEqual(next.recovered.sources, ["subject.js"]);
    assert.deepEqual(next.recovered.failures, []);
    assert.deepEqual(next.recovered.unresolved, []);
    assert.equal(fs.readFileSync(path.join(r, "subject.js"), "utf8"), pristineSource,
      "the mutant SOURCE survived the crash — this happened twice for real, found by hand with git status");
    assert.equal(digestOf(path.join(r, "dist", "subject.js")), pristineBuild,
      "the mutant BUILD survived the crash, and git status cannot see it at all");
  });
});

/* ─── ROUND 1 #5 ───────────────────────────────────────────────────────────────────────────────
 * Recovery used to overwrite any source whose hash differed from the recorded PRISTINE hash. A
 * human who fixed that file after the crash — the most likely next thing to happen — would have had
 * their work silently reverted. The marker records the exact MUTANT hash, and recovery may touch a
 * file only while it still holds those bytes. */
check("recovery touches a crashed file ONLY while it still holds the recorded mutant", () => {
  withDerivedFixture((r) => {
    const cacheDir = cacheFor(r, "unprovable");
    const pristineSource = fs.readFileSync(path.join(r, "subject.js"), "utf8");
    died(r, cacheDir, { sources: [["subject.js", pristineSource, MUTANT_SOURCE]] });
    fs.writeFileSync(path.join(r, "subject.js"), MUTANT_SOURCE);
    const theirs = "const guard = REAL_CHECK; // and a human note\nexport default guard;\n";
    fs.writeFileSync(path.join(r, "subject.js"), theirs);
    restampLock(cacheDir, { pid: 999999, identity: "Thu Jan  1 00:00:00 1970", identityAvailable: true });

    const next = createBuildStateGuard({ root: r, cacheDir }).start();
    assert.equal(next.ok, false, "the run started over a tree it could not account for");
    assert.equal(next.kind, "unrepaired");
    assert.equal(next.recovered.unresolved.length, 1, "the unprovable file was not reported at all");
    assert.match(next.recovered.unresolved[0], /changed after the crash/);
    assert.equal(fs.readFileSync(path.join(r, "subject.js"), "utf8"), theirs,
      "recovery overwrote a legitimate post-crash edit — it reverted a human, not a mutation");
    assert.ok(fs.existsSync(markerOf(cacheDir)),
      "the marker was cleared over a tree that is not provably clean, so the next run starts blind");
  });
});

/* ─── ROUND 2 #1 ───────────────────────────────────────────────────────────────────────────────
 * An untracked file the crashed phase created is a leftover nobody has accounted for, and it used
 * to be filtered out of the clean predicate — so recovery declared success and cleared the marker
 * with the file still sitting there. */
check("an untracked file a crashed phase created BLOCKS the marker from clearing", () => {
  withDerivedFixture((r) => {
    initGit(r);
    const cacheDir = cacheFor(r, "leftover");
    died(r, cacheDir, { sources: [] });
    fs.writeFileSync(path.join(r, "left-behind.txt"), "something the crashed phase wrote\n");
    restampLock(cacheDir, { pid: 999999, identity: "Thu Jan  1 00:00:00 1970", identityAvailable: true });

    const next = createBuildStateGuard({ root: r, cacheDir }).start();
    assert.equal(next.ok, false, "recovery declared success over a file nobody accounted for");
    assert.equal(next.kind, "unrepaired");
    assert.deepEqual(next.recovered.suspect, ["left-behind.txt"]);
    assert.ok(fs.existsSync(path.join(r, "left-behind.txt")),
      "the runner deleted a file it cannot prove it created");
  });
});

/* ─── ROUND 2 #1, the marker itself ────────────────────────────────────────────────────────────
 * A marker that cannot be PARSED is not "no marker". Only ENOENT is. The same for the artifact
 * index: an "empty snapshot" would make recovery treat every real build output as something the
 * crashed arm created — and DELETE it. */
check("a CORRUPT marker refuses the run; it never reads as 'nothing in flight'", () => {
  withDerivedFixture((r) => {
    const cacheDir = cacheFor(r, "corrupt-marker");
    died(r, cacheDir, { sources: [] });
    fs.writeFileSync(markerOf(cacheDir), "{ this is not json");
    restampLock(cacheDir, { pid: 999999, identity: "Thu Jan  1 00:00:00 1970", identityAvailable: true });
    const next = createBuildStateGuard({ root: r, cacheDir }).start();
    assert.equal(next.ok, false, "an unparseable marker was treated as no marker at all");
    assert.equal(next.kind, "corrupt");
    assert.match(next.detail, /not valid JSON/);
  });
});

check("a CORRUPT artifact index refuses the run — an empty one would DELETE real build output", () => {
  withDerivedFixture((r) => {
    const cacheDir = cacheFor(r, "corrupt-index");
    died(r, cacheDir, { sources: [] });
    const lock = JSON.parse(fs.readFileSync(path.join(cacheDir, "lock.json"), "utf8"));
    fs.rmSync(path.join(lock.runDir, "index.json"), { force: true });
    restampLock(cacheDir, { pid: 999999, identity: "Thu Jan  1 00:00:00 1970", identityAvailable: true });
    const before = digestOf(path.join(r, "dist", "subject.js"));
    const next = createBuildStateGuard({ root: r, cacheDir }).start();
    assert.equal(next.ok, false, "a missing index was treated as an empty snapshot");
    assert.equal(next.kind, "corrupt");
    assert.match(next.detail, /artifact index is missing/);
    assert.equal(digestOf(path.join(r, "dist", "subject.js")), before,
      "recovery deleted a real build output as though the crashed arm had created it");
  });
});

check("a CORRUPT lock refuses the run", () => {
  withDerivedFixture((r) => {
    const cacheDir = cacheFor(r, "corrupt-lock");
    fs.mkdirSync(cacheDir, { recursive: true });
    fs.writeFileSync(path.join(cacheDir, "lock.json"), "not json either");
    const next = createBuildStateGuard({ root: r, cacheDir }).start();
    assert.equal(next.ok, false);
    assert.equal(next.kind, "corrupt");
  });
});

check("null and malformed recovery records return corrupt without losing evidence", () => {
  withDerivedFixture((r) => {
    const nullLockCache = cacheFor(r, "null-lock");
    fs.mkdirSync(nullLockCache, { recursive: true });
    const nullLockPath = path.join(nullLockCache, "lock.json");
    fs.writeFileSync(nullLockPath, "null");
    const nullLockGuard = createBuildStateGuard({ root: r, cacheDir: nullLockCache });
    const nullLock = nullLockGuard.start();
    assert.equal(nullLock.kind, "corrupt",
      "JSON null escaped the corrupt-lock result as an uncaught TypeError");
    assert.ok(Array.isArray(nullLock.warnings),
      "the corrupt result bypassed finishStart and lost its warning channel");
    assert.equal(nullLockGuard.start(), nullLock,
      "the corrupt result was not memoized after strict record validation");
    assert.equal(fs.readFileSync(nullLockPath, "utf8"), "null",
      "strict validation deleted the corrupt lock bytes instead of preserving evidence");

    const assertMarkerRefuses = (tag, rewrite, expected) => {
      const cacheDir = cacheFor(r, tag);
      died(r, cacheDir, { sources: [] });
      const markerPath = markerOf(cacheDir);
      const marker = JSON.parse(fs.readFileSync(markerPath, "utf8"));
      fs.writeFileSync(markerPath, JSON.stringify(rewrite(marker)));
      restampLock(cacheDir, {
        pid: 999999,
        identity: "Thu Jan  1 00:00:00 1970",
        identityAvailable: true,
      });
      const lockPath = path.join(cacheDir, "lock.json");
      const lockBefore = fs.readFileSync(lockPath, "utf8");
      const state = createBuildStateGuard({ root: r, cacheDir }).start();
      assert.equal(state.kind, "corrupt", `${tag} escaped strict marker refusal`);
      assert.match(state.detail, expected);
      assert.equal(fs.readFileSync(lockPath, "utf8"), lockBefore,
        `${tag} removed the recovery lock instead of preserving it`);
      assert.equal(fs.existsSync(markerPath), true,
        `${tag} removed the malformed marker instead of preserving it`);
    };

    assertMarkerRefuses("null-marker", () => null, /marker is not an object/);
    assertMarkerRefuses("null-sources", (marker) => ({ ...marker, sources: null }),
      /marker sources are not an array/);
    assertMarkerRefuses("bad-dirty-before", (marker) => ({ ...marker, dirtyBefore: 5 }),
      /marker dirtyBefore is not an array/);
    assertMarkerRefuses("wrong-marker-nonce", (marker) => ({ ...marker, nonce: "another-owner" }),
      /marker belongs to nonce/);
  });
});

/** THE INCIDENT ITSELF: a suite that regenerates a COMMITTED file while the mutant is live. */
check("a committed file the mutated suite regenerated is put back from HEAD", () => {
  withDerivedFixture((r) => {
    const git = initGit(r);
    const committed = fs.readFileSync(path.join(r, "fixture.json"), "utf8");

    const ev = runKnockout({
      root: r, entry: derivedEntry(r), baseline: derivedBaseline(r), timeoutMs: 60_000,
      guard: startedGuard(r, "git"),
    });
    assert.equal(ev.verdict, VERDICT.DETECTOR_TRIGGERED, `got ${ev.verdict}: ${ev.detail}`);
    assert.equal(fs.readFileSync(path.join(r, "fixture.json"), "utf8"), committed,
      "the mutated suite's generator rewrote a COMMITTED file and the runner left it rewritten — " +
        "this is byte-for-byte the CI failure of 2026-08-14");
    assert.deepEqual(ev.buildState.trackedReverted, ["fixture.json"]);
    assert.equal(git("status", "--porcelain").trim(), "", "the arm left the worktree dirty");
  });
});

/* ─── ROUND 1 #2 ───────────────────────────────────────────────────────────────────────────────
 * The guard skipped every already-dirty path so as not to destroy a developer's work, and by
 * skipping destroyed exactly that: the arm's generator OVERWRITES the file, so their edit was gone
 * and the MUTANT's content stayed — invisibly, because the residue check compares status strings
 * and ` M fixture.json` is ` M fixture.json` either way. Both directions are measured. */
const MINE = `{"generatedFrom":"MY OWN UNCOMMITTED EDIT"}\n`;
check("uncommitted work in a file the arm DOES rewrite survives, and the mutant does not", () => {
  withDerivedFixture((r, base) => {
    initGit(r);
    fs.writeFileSync(path.join(r, "fixture.json"), MINE);

    const ev = runKnockout({
      root: r, entry: derivedEntry(r), baseline: base, timeoutMs: 60_000, guard: startedGuard(r, "dirty"),
    });
    const after = fs.readFileSync(path.join(r, "fixture.json"), "utf8");
    assert.equal(after, MINE,
      "a developer's uncommitted fixture was overwritten by the arm and never put back");
    assert.ok(!after.includes("const guard = true;"),
      "the MUTANT's generated content survived behind an unchanged ` M` status — the residue check " +
        "compares status strings and cannot see this");
    assert.ok(ev.buildState.trackedReverted.includes("fixture.json"));
  });
});

check("ANTI-VACUITY: without the guard, that same dirty file keeps the mutant's content", () => {
  withDerivedFixture((r, base) => {
    initGit(r);
    fs.writeFileSync(path.join(r, "fixture.json"), MINE);
    runKnockout({ root: r, entry: derivedEntry(r), baseline: base, timeoutMs: 60_000, guard: NO_GUARD });
    const after = fs.readFileSync(path.join(r, "fixture.json"), "utf8");
    assert.match(after, /const guard = true;/,
      "the fixture cannot reproduce the defect, so the arm above proves nothing");
    assert.notEqual(after, MINE, "the developer's work was not destroyed, so there was nothing to save");
  });
});

/* ─── ROUND 2 #2, the half that has nothing to do with arms ────────────────────────────────────
 * Protection used to begin at the first MUTATION. The damage does not: `packages/evidence`'s CLEAN
 * baseline runs the fixture generator too, so a developer's uncommitted fixture was destroyed
 * before any arm existed to protect it. Here the edit is made BEFORE the baseline measurement,
 * which is the case the previous selftest carefully stepped around. */
check("a dirty file is protected across the BASELINE phase, before any arm exists", () => {
  const r = buildFixture();
  derivedRoots.push(r);
  initGit(r);
  fs.writeFileSync(path.join(r, "fixture.json"), MINE);

  const guard = startedGuard(r, "baseline");
  guard.beginPhase({ label: "<suite baselines>", artifacts: false, tracked: "dirty-only" });
  const base = derivedBaseline(r);                     // the generator runs here, over MINE
  assert.notEqual(fs.readFileSync(path.join(r, "fixture.json"), "utf8"), MINE,
    "the baseline suite did not overwrite the dirty file, so this arm measures nothing");
  const report = guard.endPhase();

  assert.deepEqual(report.failures, []);
  assert.deepEqual(report.trackedReverted, ["fixture.json"]);
  assert.equal(fs.readFileSync(path.join(r, "fixture.json"), "utf8"), MINE,
    "uncommitted work was destroyed by a BASELINE run, before the first mutation existed");
  assert.equal(base.exit, 0, "the baseline itself must still have been measured normally");
});

check("the baseline phase does NOT revert a clean file the baseline changed — that is real drift", () => {
  const r = buildFixture();
  derivedRoots.push(r);
  const git = initGit(r);
  // A committed fixture that disagrees with its own generator: the baseline regenerates it, and
  // that is a fact about the repository, not this runner's mess to tidy away.
  fs.writeFileSync(path.join(r, "fixture.json"), `{"generatedFrom":"STALE COMMITTED CONTENT"}\n`);
  git("add", "-A");
  git("commit", "-q", "-m", "stale fixture");

  const guard = startedGuard(r, "drift");
  guard.beginPhase({ label: "<suite baselines>", artifacts: false, tracked: "dirty-only" });
  derivedBaseline(r);
  const report = guard.endPhase();
  assert.deepEqual(report.failures, []);
  assert.deepEqual(report.trackedReverted, [], "the baseline phase reverted a genuine drift out of sight");
  assert.notEqual(git("status", "--porcelain").trim(), "",
    "the drift was hidden from the residue check, which is the one thing meant to report it");
});

check("uncommitted work the arm never touched is NEVER reverted by the guard", () => {
  withDerivedFixture((r) => {
    initGit(r);
    const mine = "MY OWN UNCOMMITTED EDIT\n";
    fs.writeFileSync(path.join(r, "notes.md"), mine);

    const ev = runKnockout({
      root: r, entry: derivedEntry(r), baseline: derivedBaseline(r), timeoutMs: 60_000,
      guard: startedGuard(r, "mine"),
    });
    assert.equal(fs.readFileSync(path.join(r, "notes.md"), "utf8"), mine,
      "the guard reverted a file the arm never touched — it just deleted a developer's work");
    assert.deepEqual(ev.buildState.trackedReverted, ["fixture.json"],
      "the guard reverted more (or less) than the one file this arm's generator rewrote");
  });
});

/* ─── ROUND 1 #2 / ROUND 2 #2, the INDEX ───────────────────────────────────────────────────────
 * `git checkout -- <path>` restores the worktree FROM THE INDEX, so a suite that staged its output
 * had the mutation copied back over itself. Reading HEAD fixes the clean-before case; a path that
 * was ALREADY dirty needs its recorded index entry putting back, and so does a mutated SOURCE that
 * the suite staged — which the old mutation-target exemption made worse rather than better. */
check("a generated file the suite STAGED is reset in the index as well as the worktree", () => {
  const r = buildFixture({ stageGenerated: true });
  derivedRoots.push(r);
  const git = initGit(r);
  const base = derivedBaseline(r);
  git("reset", "-q");
  assert.equal(git("status", "--porcelain").trim(), "", "the fixture did not start clean");
  const committed = fs.readFileSync(path.join(r, "fixture.json"), "utf8");

  runKnockout({ root: r, entry: derivedEntry(r), baseline: base, timeoutMs: 60_000, guard: startedGuard(r, "staged") });
  assert.equal(fs.readFileSync(path.join(r, "fixture.json"), "utf8"), committed,
    "the worktree kept the mutant's generated bytes");
  assert.equal(git("diff", "--cached", "--name-only").trim(), "",
    "the INDEX still holds the mutation — `git checkout --` restores FROM the index, so it would " +
      "have put the mutant back rather than removed it");
  assert.equal(git("status", "--porcelain").trim(), "", "the arm left the worktree dirty");
});

check("ANTI-VACUITY: the staging fixture really does stage a mutant", () => {
  const r = buildFixture({ stageGenerated: true });
  derivedRoots.push(r);
  const git = initGit(r);
  const base = derivedBaseline(r);
  git("reset", "-q");
  runKnockout({ root: r, entry: derivedEntry(r), baseline: base, timeoutMs: 60_000, guard: NO_GUARD });
  assert.equal(git("diff", "--cached", "--name-only").trim(), "fixture.json",
    "the fixture never staged anything, so the arm above proves nothing about the index");
});

check("an ALREADY-DIRTY file the suite stages gets BOTH its bytes and its index entry back", () => {
  const r = buildFixture({ stageGenerated: true });
  derivedRoots.push(r);
  const git = initGit(r);
  const base = derivedBaseline(r);
  git("reset", "-q");
  // worktree != index != HEAD, the case a byte-only snapshot cannot express.
  fs.writeFileSync(path.join(r, "fixture.json"), `{"generatedFrom":"STAGED WORK IN PROGRESS"}\n`);
  git("add", "fixture.json");
  const stagedEntry = git("ls-files", "-s", "--", "fixture.json").trim();
  fs.writeFileSync(path.join(r, "fixture.json"), MINE);
  const statusBefore = git("status", "--porcelain").trim();
  assert.equal(statusBefore, "MM fixture.json", `the fixture is not in the intended state: ${statusBefore}`);

  runKnockout({ root: r, entry: derivedEntry(r), baseline: base, timeoutMs: 60_000, guard: startedGuard(r, "dirty-staged") });
  assert.equal(fs.readFileSync(path.join(r, "fixture.json"), "utf8"), MINE,
    "the developer's unstaged work was lost");
  assert.equal(git("ls-files", "-s", "--", "fixture.json").trim(), stagedEntry,
    "the INDEX kept the mutant's content — the next `git commit` would have shipped it");
  assert.equal(git("status", "--porcelain").trim(), statusBefore,
    "the arm did not leave the tree in the state it found it");
});

check("a mutated SOURCE the suite stages is unstaged again", () => {
  const r = buildFixture({ stageSubject: true });
  derivedRoots.push(r);
  const git = initGit(r);
  const base = derivedBaseline(r);
  git("reset", "-q");
  const entryBefore = git("ls-files", "-s", "--", "subject.js").trim();

  const ev = runKnockout({ root: r, entry: derivedEntry(r), baseline: base, timeoutMs: 60_000, guard: startedGuard(r, "staged-src") });
  assert.equal(ev.restored, true, `the arm did not report a proven restore: ${ev.detail}`);
  assert.equal(git("ls-files", "-s", "--", "subject.js").trim(), entryBefore,
    "a MUTATED SOURCE stayed staged in the index; the worktree looked clean and the commit would " +
      "have carried the knockout's own mutation");
  assert.equal(git("status", "--porcelain").trim(), "", "the arm left the tree dirty");
});

/* ─── ROUND 1 #3 / ROUND 2 #3 ──────────────────────────────────────────────────────────────────
 * Declining to CORRUPT another live run is not declining to RACE it. The marker was never a lock:
 * two runners could both see no marker, both snapshot, and both overwrite. The lock is an O_EXCL
 * create, and two attempts in one process are enough to prove exclusivity. */
check("the lock is EXCLUSIVE: a second guard on the same cache cannot start", () => {
  withDerivedFixture((r) => {
    const cacheDir = cacheFor(r, "exclusive");
    const first = createBuildStateGuard({ root: r, cacheDir });
    const second = createBuildStateGuard({ root: r, cacheDir });
    assert.equal(first.start().ok, true, "the first run could not take a free lock");
    const blocked = second.start();
    assert.equal(blocked.ok, false, "two runs took the same lock — nothing here is exclusive");
    assert.equal(blocked.kind, "held");
    assert.notEqual(first.ownerNonce, null);
    assert.deepEqual(fs.readdirSync(path.join(cacheDir, "runs")), [first.ownerNonce],
      "the lock loser published an ownerless run directory before it won exclusivity");
    assert.throws(() => second.beginPhase({ label: "second", sources: [] }), /another knockout run holds this tree/,
      "the blocked run went on to snapshot and mutate anyway");
    // ...and the loser must not have been able to touch the winner's record.
    assert.equal(JSON.parse(fs.readFileSync(path.join(cacheDir, "lock.json"), "utf8")).nonce, first.ownerNonce);
    assert.equal(second.release(), false, "a run that never held the lock released it");
    assert.equal(first.release(), true, "the owner could not release its own lock");
  });
});

check("a LIVE lock refuses a whole arm, and mutates nothing", () => {
  withDerivedFixture((r) => {
    const cacheDir = cacheFor(r, "lock");
    const pristineSource = fs.readFileSync(path.join(r, "subject.js"), "utf8");
    const pristineBuild = digestOf(path.join(r, "dist", "subject.js"));
    died(r, cacheDir, { label: "an-arm-in-flight-elsewhere", sources: [["subject.js", pristineSource, MUTANT_SOURCE]] });
    // Re-stamp as a process that is certainly alive and certainly not this one, identity and all.
    const probe = probeProcess(1);
    restampLock(cacheDir, { pid: 1, identity: probe.identity, identityAvailable: probe.identity !== null });
    const lockBefore = fs.readFileSync(path.join(cacheDir, "lock.json"), "utf8");

    const second = createBuildStateGuard({ root: r, cacheDir });
    const held = second.start();
    assert.equal(held.ok, false, "a live run's lock was taken over");
    assert.equal(held.kind, "held");
    assert.match(held.detail, /pid 1|may still be alive/, "the refusal does not name the process to wait on");

    const ev = runKnockout({
      root: r, entry: derivedEntry(r), baseline: derivedBaseline(r), timeoutMs: 60_000, guard: second,
    });
    assert.equal(ev.verdict, VERDICT.RESTORATION_FAILED, `got ${ev.verdict}: ${ev.detail}`);
    assert.match(ev.detail, /NOTHING was mutated/);
    assert.equal(fs.readFileSync(path.join(r, "subject.js"), "utf8"), pristineSource,
      "the second run mutated a tree another run is holding");
    assert.equal(digestOf(path.join(r, "dist", "subject.js")), pristineBuild);
    assert.equal(fs.readFileSync(path.join(cacheDir, "lock.json"), "utf8"), lockBefore,
      "the second run overwrote the live run's lock, so the holder lost its own recovery record");
  });
});

/* ─── ROUND 2 #5 ───────────────────────────────────────────────────────────────────────────────
 * `ps` returning nothing because a process is gone, and `ps` refusing to run at all, were the same
 * `null` — and the second was read as "dead", so a run would start recovering a tree another run
 * might still be holding. The reviewer's own runtime returned EPERM from `/bin/ps`, so this is a
 * measured environment. The classifier is pure precisely so all three states are testable. */
check("holder liveness is THREE-valued: unknown is treated exactly like live", () => {
  const rec = { pid: 4242, identity: "Mon Jan  1 00:00:00 2020", identityAvailable: true };
  assert.equal(classifyHolder(rec, { exists: "no", identity: null }), "DEAD",
    "a pid that provably does not exist must be recoverable, or a crash locks the repo forever");
  assert.equal(classifyHolder(rec, { exists: "yes", identity: rec.identity }), "LIVE");
  assert.equal(classifyHolder(rec, { exists: "yes", identity: "Tue Feb  2 11:11:11 2021" }), "DEAD",
    "a REUSED pid was read as the original process; the tree would never be repaired");
  assert.equal(classifyHolder(rec, { exists: "unknown", identity: null }), "UNKNOWN",
    "a process this machine will not answer about was declared dead");
  assert.equal(classifyHolder(rec, { exists: "yes", identity: null }), "UNKNOWN",
    "`ps` refused (EPERM is real: the reviewer's runtime did exactly this) and the holder was " +
      "declared dead anyway");
  assert.equal(classifyHolder({ pid: 4242, identity: null, identityAvailable: false }, { exists: "yes", identity: "x" }),
    "UNKNOWN", "a lock written where `ps` was unavailable cannot later prove identity, so it is held");
  assert.equal(classifyHolder({ pid: process.pid }, { exists: "yes", identity: null }), "SELF");
});

check("an UNKNOWN holder refuses the run rather than recovering it", () => {
  withDerivedFixture((r) => {
    const cacheDir = cacheFor(r, "unknown-holder");
    const pristineSource = fs.readFileSync(path.join(r, "subject.js"), "utf8");
    died(r, cacheDir, { sources: [["subject.js", pristineSource, MUTANT_SOURCE]] });
    fs.writeFileSync(path.join(r, "subject.js"), MUTANT_SOURCE);
    // pid 1 exists; the recorded lock says `ps` could not be consulted when it was written, so
    // identity can never be compared — indeterminate, and indeterminate is held.
    restampLock(cacheDir, { pid: 1, identity: null, identityAvailable: false });

    const next = createBuildStateGuard({ root: r, cacheDir }).start();
    assert.equal(next.ok, false, "an indeterminate holder was recovered over");
    assert.equal(next.kind, "held");
    assert.equal(next.certainty, "indeterminate");
    assert.equal(fs.readFileSync(path.join(r, "subject.js"), "utf8"), MUTANT_SOURCE,
      "it restored a file that may belong to a run still using it");
  });
});

check("probeProcess reports THIS process as existing, and pid 0 as absent", () => {
  const self = probeProcess(process.pid);
  assert.equal(self.exists, "yes");
  assert.deepEqual(probeProcess(0), { exists: "no", identity: null });
  assert.deepEqual(probeProcess(-1), { exists: "no", identity: null });
});

check("a guard that cannot snapshot means NO experiment happens — not a weaker one", () => {
  withDerivedFixture((r) => {
    const pristineSource = fs.readFileSync(path.join(r, "subject.js"), "utf8");
    const pristineBuild = digestOf(path.join(r, "dist", "subject.js"));
    const ev = runKnockout({
      root: r, entry: derivedEntry(r), baseline: derivedBaseline(r), timeoutMs: 60_000,
      guard: { start: () => ({ ok: true }), endArm: () => null, beginArm() { throw new Error("no room on device"); } },
    });
    assert.equal(ev.verdict, VERDICT.RESTORATION_FAILED, `got ${ev.verdict}: ${ev.detail}`);
    assert.match(ev.detail, /NOTHING was mutated/);
    assert.equal(fs.readFileSync(path.join(r, "subject.js"), "utf8"), pristineSource,
      "the runner mutated the tree after its promise to give it back had already failed");
    assert.equal(digestOf(path.join(r, "dist", "subject.js")), pristineBuild);
  });
});

/* ─── ROUND 1 #4 ───────────────────────────────────────────────────────────────────────────────
 * The arm above injects a throw, which only proves the wiring. The REAL incomplete-snapshot paths
 * were the silent ones: a directory that cannot be read used to `catch { return; }` and produce a
 * SHORTER list, and a short list is not a smaller snapshot — it is a snapshot with holes that
 * restoration will never fill. */
check("an UNREADABLE build directory refuses the arm — a short list is not a snapshot", () => {
  withDerivedFixture((r) => {
    const locked = path.join(r, "dist", "locked");
    fs.mkdirSync(locked, { recursive: true });
    fs.writeFileSync(path.join(locked, "out.js"), "build output nobody can read\n");
    fs.chmodSync(locked, 0o000);
    let readable = true;
    try { fs.readdirSync(locked); } catch { readable = false; }
    try {
      assert.equal(readable, false,
        "the unreadable directory is readable here — running as root? this arm cannot measure anything");
      assert.throws(() => listBuildArtifacts(r), /cannot read/,
        "an unreadable directory was silently skipped, leaving a hole in the snapshot");

      const pristineSource = fs.readFileSync(path.join(r, "subject.js"), "utf8");
      const ev = runKnockout({
        root: r, entry: derivedEntry(r), baseline: derivedBaseline(r), timeoutMs: 60_000,
        guard: startedGuard(r, "unreadable"),
      });
      assert.equal(ev.verdict, VERDICT.RESTORATION_FAILED, `got ${ev.verdict}: ${ev.detail}`);
      assert.equal(fs.readFileSync(path.join(r, "subject.js"), "utf8"), pristineSource,
        "the arm mutated the tree over an incomplete snapshot");
    } finally {
      fs.chmodSync(locked, 0o755);
    }
  });
});

/* ─── ROUND 2 #4 ───────────────────────────────────────────────────────────────────────────────
 * Enumeration and hashing are two moments. A file that disappears between them used to be skipped;
 * if it came back, restoration would delete it as "created by the arm". And a regular file swapped
 * for a SYMLINK in that window would have been read — and later WRITTEN THROUGH — pointing this
 * guard's restore at a path outside the repository. */
check("a build file that VANISHES mid-snapshot refuses the arm", () => {
  withDerivedFixture((r) => {
    const guard = startedGuard(r, "vanish");
    const real = fs.readdirSync;
    let armed = false;
    fs.readdirSync = (...args) => {
      const out = real.apply(fs, args);
      if (!armed && String(args[0]).endsWith(path.join(r, "dist"))) {
        armed = true;
        fs.rmSync(path.join(r, "dist", "untouched.js"), { force: true });   // gone before it is hashed
      }
      return out;
    };
    try {
      assert.throws(() => guard.beginPhase({ label: "vanishing", sources: [] }), /vanished between enumeration and hashing/,
        "a file that disappeared mid-snapshot left a hole the restore can never fill");
    } finally { fs.readdirSync = real; }
  });
});

check("a build file REPLACED BY A SYMLINK is never read or written through", () => {
  withDerivedFixture((r) => {
    const outside = path.join(r, "..", `${path.basename(r)}-outside.txt`);
    cacheDirs.push(outside);
    fs.writeFileSync(outside, "a file outside the repository\n");
    const victim = path.join(r, "dist", "untouched.js");
    fs.rmSync(victim, { force: true });
    fs.symlinkSync(outside, victim);
    // The walker rejects it by dirent type, so it is simply not in the snapshot...
    assert.ok(!listBuildArtifacts(r).includes("dist/untouched.js"),
      "a symlink was taken into the build snapshot; restoring it would write outside the repository");
    // ...and a direct read of that path refuses rather than following it.
    assert.throws(() => listBuildArtifacts(path.join(r, "dist", "untouched.js")), /cannot read/);
    assert.equal(fs.readFileSync(outside, "utf8"), "a file outside the repository\n",
      "the guard wrote through a symlink to a path outside the repository");
  });
});

/* ─── ROUND 1 #6 / ROUND 2 #7 ──────────────────────────────────────────────────────────────────
 * The walker knows one artifact root: `dist`. That is complete today because every tsconfig here
 * emits there — a convention, checked by nothing. And the CHECK was itself fail-open: an extends
 * chain that could not be resolved left the effective outDir unknown, and unknown was accepted. */
check("an artifact root this guard cannot see REFUSES the arm, by name", () => {
  withDerivedFixture((r) => {
    const odd = path.join(r, "packages", "odd");
    fs.mkdirSync(odd, { recursive: true });
    const write = (body) => fs.writeFileSync(path.join(odd, "tsconfig.json"), body);

    write(`{ // a package that emits somewhere this guard does not look\n  "compilerOptions": { "outDir": "build" } }\n`);
    assert.deepEqual(unsupportedArtifactRoots(r, []), [], "an empty project list invented a problem");
    assert.match(unsupportedArtifactRoots(r, ["packages/odd"])[0], /outDir is "build"/);

    write(`{ "compilerOptions": { } }\n`);
    assert.match(unsupportedArtifactRoots(r, ["packages/odd"])[0], /BESIDE its sources/,
      "a tsconfig with no outDir emits next to the sources and must not be treated as supported");

    write(`{ "compilerOptions": { "noEmit": true } }\n`);
    assert.deepEqual(unsupportedArtifactRoots(r, ["packages/odd"]), [],
      "a package that emits NOTHING has no artifact root to miss");

    write(`{ "compilerOptions": { "outDir": "./dist/" } }\n`);
    assert.deepEqual(unsupportedArtifactRoots(r, ["packages/odd"]), [],
      "the supported convention was rejected over a trailing slash");

    // ── the resolution paths, every one of which used to be accepted silently ──
    write(`{ "extends": "./missing-base" }\n`);
    assert.match(unsupportedArtifactRoots(r, ["packages/odd"])[0], /does not exist/);
    write(`{ "extends": "@some/tsconfig-base" }\n`);
    assert.match(unsupportedArtifactRoots(r, ["packages/odd"])[0], /package-style base/);
    write(`{ "extends": "./tsconfig.json" }\n`);
    assert.match(unsupportedArtifactRoots(r, ["packages/odd"])[0], /cycle/);
    write(`{ "compilerOptions": { "outDir": "dist" `);
    assert.match(unsupportedArtifactRoots(r, ["packages/odd"])[0], /cannot be read or parsed/);

    // ── and a resolvable chain still resolves ──
    fs.writeFileSync(path.join(odd, "base.json"), `{ "compilerOptions": { "outDir": "dist" } }\n`);
    write(`{ "extends": "./base" }\n`);
    assert.deepEqual(unsupportedArtifactRoots(r, ["packages/odd"]), [],
      "an extensionless but perfectly resolvable base was rejected");

    // ── end to end: the arm is refused before anything is written ──
    write(`{ "compilerOptions": { "outDir": "build" } }\n`);
    const pristineSource = fs.readFileSync(path.join(r, "subject.js"), "utf8");
    const ev = runKnockout({
      root: r, entry: derivedEntry(r), baseline: derivedBaseline(r), timeoutMs: 60_000,
      guard: startedGuard(r, "outdir"),
    });
    assert.equal(ev.verdict, VERDICT.RESTORATION_FAILED, `got ${ev.verdict}: ${ev.detail}`);
    assert.match(ev.detail, /unsupported artifact root/);
    assert.equal(fs.readFileSync(path.join(r, "subject.js"), "utf8"), pristineSource,
      "the arm mutated a tree holding a package whose build output it cannot restore");
  });
});

check("EVERY TypeScript project is checked, not only the arm's own package", () => {
  const r = scratch("ko-projects-");
  derivedRoots.push(r);
  for (const d of ["", "packages/a", "packages/b", "packages/b/node_modules/dep", "dist/nested"]) {
    fs.mkdirSync(path.join(r, d), { recursive: true });
    fs.writeFileSync(path.join(r, d, "tsconfig.json"), `{ "compilerOptions": { "outDir": "dist" } }\n`);
  }
  assert.deepEqual(typescriptProjectDirs(r), ["", "packages/a", "packages/b"],
    "a sibling an arbitrary suite command could build was left unchecked, or a dependency's own " +
      "config was dragged in");
});

check("the real repository's own TypeScript projects all satisfy the artifact-root invariant", () => {
  const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const dirs = typescriptProjectDirs(repo);
  assert.ok(dirs.length >= 7, `only ${dirs.length} TypeScript projects found; the walk is not seeing this repository`);
  assert.deepEqual(unsupportedArtifactRoots(repo, dirs), [],
    "a package in this repository emits where the guard cannot see it, so its knockouts would " +
      "report a clean restore over a leaked build");
});

/* ─── CodeQL js/insecure-temporary-file + file-system-race ─────────────────────────────────────
 * The recovery store holds this run's
 * pristine sources, the mutant hashes recovery compares against, and the lock that decides whether
 * another run may touch the tree. It lived under the machine-wide temporary directory at a path
 * derived from the repository path alone: deterministic on purpose, because crash recovery has to
 * FIND it, and therefore predictable to every other account.
 *
 * Making that directory 0700 closed the hole and the scanner kept flagging it, which was the right
 * instinct: "a shared directory is safe THIS time" is the kind of argument this file exists to
 * distrust. The store now lives under the user's own cache home, private by construction, with no
 * shared parent for anyone to race — and the refusals below are kept anyway, because the surface
 * shrank and the standard did not. */
check("the fallback store is under the USER'S CACHE HOME, never a shared directory", () => {
  const base = scratch("ko-fallback-");
  derivedRoots.push(base);
  const root = privateFallbackRoot(base);

  assert.equal(privateFallbackRoot(), path.join(userCacheHome(), "noa-knockout"),
    "the default fallback root is not the user's own cache home");
  assert.ok(!privateFallbackRoot().startsWith(`${os.tmpdir()}${path.sep}`),
    "the fallback store is still inside the machine-wide temporary directory — this is the finding");
  assert.equal(userCacheHome(), path.join(fs.realpathSync(os.userInfo().homedir), ".cache"),
    "the cache home came from mutable HOME/XDG launch input instead of the operating-system account");
  assert.equal(root, path.join(base, "noa-knockout"),
    "the base parameter the selftest relies on stopped being honoured");

  ensurePrivateDir(root);
  // Inspected through a descriptor this arm HOLDS, not by a second path lookup: opening
  // no-follow-and-must-be-a-directory and then `fstat`-ing that fd asks about one object, once.
  // A `lstat` here and an act on the same path later is a check-then-act pair, and a test that
  // plants symlinks to prove a guard refuses them should not leave one of its own lying around.
  const made = withFd(root, fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY ?? 0) | NOFOLLOW,
    (fd) => fs.fstatSync(fd));
  assert.ok(made.isDirectory());
  assert.equal(made.mode & 0o777, 0o700,
    "the store other accounts must not read was created world-readable");
  assert.doesNotThrow(() => ensurePrivateDir(root), "a directory this guard itself created was then rejected");

  // A directory somebody else left loose is refused, not quietly repaired.
  fs.chmodSync(root, 0o777);
  assert.throws(() => ensurePrivateDir(root), /not 700/,
    "a world-writable store was accepted; another account could have replaced the pristine sources " +
      "this run restores from");
  fs.chmodSync(root, 0o700);
  assert.doesNotThrow(() => ensurePrivateDir(root));

  // THE PLANTED SYMLINK: the attack the CodeQL rule is about.
  const elsewhere = path.join(base, "somewhere-else");
  fs.mkdirSync(elsewhere, { mode: 0o700 });
  fs.rmSync(root, { recursive: true, force: true });
  fs.symlinkSync(elsewhere, root);
  assert.throws(() => ensurePrivateDir(root), /not a real directory/,
    "a symlink planted at the predictable fallback path was followed — this run's pristine sources " +
      "and its lock would have been written wherever it pointed");
  assert.deepEqual(fs.readdirSync(elsewhere), [], "something was written through the planted symlink");

  // ...and a plain file at that path is refused for the same reason. Created with an ATOMIC
  // exclusive open — `wx` either takes the name or fails with EEXIST — rather than deciding the
  // path is free and then writing to it. The second shape is the race itself, and it would also
  // follow a symlink somebody slipped in between the two steps.
  fs.unlinkSync(root);            // unlink, not rm: the symlink itself goes, never what it points at
  withFd(root, "wx", (fd) => fs.writeSync(fd, "not a directory at all\n"), 0o600);
  assert.throws(() => ensurePrivateDir(root), /not a real directory/);
  fs.rmSync(root, { force: true });
});

check("hostile HOME and XDG_CACHE_HOME cannot redirect private state into an evidence root", () => {
  const hostileRoot = scratch("ko-hostile-env-");
  derivedRoots.push(hostileRoot);
  const result = spawnSync(process.execPath, [
    "--input-type=module",
    "-e",
    [
      `const m = await import(${JSON.stringify(RUNNER_MODULE_URL)});`,
      "const guard = m.createBuildStateGuard({ root: process.env.TEST_ROOT });",
      "const state = guard.start();",
      "process.stdout.write(JSON.stringify({ home: m.userCacheHome(), cache: guard.cacheDir, state }));",
    ].join("\n"),
  ], {
    encoding: "utf8",
    env: {
      ...process.env,
      HOME: REPO,
      XDG_CACHE_HOME: path.join(REPO, "node_modules", ".cache"),
      TEST_ROOT: hostileRoot,
    },
  });
  assert.equal(result.status, 0, result.stderr);
  const observed = JSON.parse(result.stdout);
  assert.equal(observed.home, path.join(fs.realpathSync(os.userInfo().homedir), ".cache"));
  assert.ok(observed.cache.startsWith(`${privateFallbackRoot()}${path.sep}`));
  assert.ok(!observed.cache.startsWith(`${REPO}${path.sep}`),
    `hostile launch input redirected the guard into the public evidence root: ${observed.cache}`);
  assert.ok(!observed.cache.startsWith(`${hostileRoot}${path.sep}`),
    `hostile launch input redirected the guard into its protected root: ${observed.cache}`);
  assert.equal(observed.state.kind, "legacy",
    "a fixture guard accepted an environment-selected v3 cache inside the public evidence root");
  assert.match(observed.state.detail, /overlaps evidence root/);
});

/**
 * The structural claim, kept structural. Everything else in this section tests BEHAVIOUR, and
 * behaviour can be re-introduced by one convenient `mkdtempSync` in a future patch. This reads the
 * runner's own source: no product path may name the machine-wide temporary directory. The one
 * admitted TMPDIR spelling binds a child to the private per-container tmpfs constant and is checked
 * by the contained-gate behavioural proof above.
 */
check("the runner never reaches for the machine-wide temporary directory, in any line", () => {
  const src = fs.readFileSync(path.join(REPO, "scripts", "lib", "knockout-runner.mjs"), "utf8");
  const hits = src.split("\n")
    .map((line, i) => [i + 1, line])
    .filter(([, line]) =>
      /\bos\s*\.\s*tmpdir\b|\bTMPDIR\b|(^|[^\w/])\/tmp\//.test(line) &&
      line.trim() !== "return { ...environment, TMPDIR: CONTAINED_SCRATCH_ROOT };"
    );
  assert.deepEqual(hits, [],
    `the runner is back in the shared temporary directory at ${hits.map(([n]) => n).join(", ")} — ` +
      "its store holds this run's pristine sources and its lock, and a directory every account can " +
      "write to is a race somebody else can enter");
});

check("runtime evidence cannot bind before the default guard establishes its migration barrier", () => {
  const r = scratch("ko-bind-order-");
  derivedRoots.push(r);
  assert.throws(() => assertKnockoutMigrationBarrier(r), /start the default build-state guard before binding/,
    "a first-run caller could freeze node_modules before the v3 tombstone exists");
  const guard = trackDefaultGuardCaches(createBuildStateGuard({ root: r }));
  assert.equal(guard.start().ok, true);
  assert.equal(assertKnockoutMigrationBarrier(r), true);
  assert.equal(guard.release(), true);
});

check("install state cannot split one physical repository into two default locks", () => {
  const r = scratch("ko-install-state-");
  derivedRoots.push(r);
  const beforeInstall = trackDefaultGuardCaches(createBuildStateGuard({ root: r }));
  fs.mkdirSync(path.join(r, "node_modules"), { recursive: true });
  const afterInstall = trackDefaultGuardCaches(createBuildStateGuard({ root: r }));
  assert.equal(beforeInstall.rootIdentity, afterInstall.rootIdentity);
  assert.equal(beforeInstall.cacheDir, afterInstall.cacheDir,
    "creating node_modules changed the recovery store and stranded the first lock");
  assert.equal(beforeInstall.lockPath, afterInstall.lockPath);
  assert.ok(beforeInstall.cacheDir.startsWith(`${privateFallbackRoot()}${path.sep}`));
  assert.ok(!beforeInstall.cacheDir.startsWith(`${r}${path.sep}`),
    `the active v4 lock is inside the tree it protects: ${beforeInstall.cacheDir}`);

  assert.equal(beforeInstall.start().ok, true);
  assert.equal(afterInstall.start().kind, "held",
    "a second guard for the same physical tree did not contend on the same lock");
  assert.equal(fs.lstatSync(beforeInstall.cacheDir).mode & 0o777, 0o700);
  assert.equal(fs.lstatSync(beforeInstall.lockPath).mode & 0o777, 0o600);

  const installedLegacy = path.join(r, "node_modules", ".cache", "noa-knockout");
  const tombstone = JSON.parse(fs.readFileSync(path.join(installedLegacy, "lock.json"), "utf8"));
  assert.equal(tombstone.protocol, LEGACY_TOMBSTONE_PROTOCOL);
  assert.equal(tombstone.rootIdentity, beforeInstall.rootIdentity);
  const oldStyle = createBuildStateGuard({ root: r, cacheDir: installedLegacy }).start();
  assert.equal(oldStyle.kind, "corrupt",
    "an old runner accepted the migration tombstone and could take a duplicate v3 lock");
  assert.equal(beforeInstall.release(), true);
  assert.equal(fs.existsSync(beforeInstall.lockPath), false);
  assert.ok(fs.existsSync(beforeInstall.cacheDir),
    "release removed the deterministic directory and reopened the ensure/open contender race");
});

check("an already-migrated contender creates no transient tombstone staging file", () => {
  const r = scratch("ko-steady-tombstone-");
  derivedRoots.push(r);
  const owner = trackDefaultGuardCaches(createBuildStateGuard({ root: r }));
  assert.equal(owner.start().ok, true);
  const contender = createBuildStateGuard({ root: r });
  cacheDirs.push(contender.cacheDir);

  const originalOpenSync = fs.openSync;
  const stagingOpens = [];
  let contenderState;
  fs.openSync = (candidate, ...args) => {
    if (typeof candidate === "string" && /\.lock\.json\.[0-9a-f]{32}\.tombstone-tmp$/.test(candidate)) {
      stagingOpens.push(candidate);
    }
    return originalOpenSync(candidate, ...args);
  };
  try {
    contenderState = contender.start();
  } finally {
    fs.openSync = originalOpenSync;
  }
  try {
    assert.equal(contenderState.kind, "held",
      "the already-migrated contender did not reach the existing v4 lock");
    assert.deepEqual(stagingOpens, [],
      "an already-present tombstone still caused a transient write inside the runtime closure");
  } finally {
    assert.equal(owner.release(), true);
  }
});

check("a generationless record at the v4 lock path is never accepted for recovery", () => {
  const r = scratch("ko-generationless-v4-");
  derivedRoots.push(r);
  const guard = trackDefaultGuardCaches(createBuildStateGuard({ root: r }));
  ensurePrivateDir(privateFallbackRoot());
  ensurePrivateDir(guard.cacheDir);
  fs.writeFileSync(guard.lockPath, JSON.stringify({
    version: 3,
    root: r,
    rootIdentity: guard.rootIdentity,
    nonce: "generationless-owner",
    pid: 0,
    identity: null,
    identityAvailable: false,
    startedAt: "1970-01-01T00:00:00.000Z",
    runDir: path.join(guard.cacheDir, "runs", "generationless-owner"),
  }), { mode: 0o600 });
  try {
    const state = guard.start();
    assert.equal(state.kind, "corrupt",
      "a generationless v3-shaped record was accepted at the v4 recovery lock path");
    assert.match(state.detail, /protocol version 3 cannot bind v4 recovery bytes/);
    assert.equal(fs.existsSync(guard.lockPath), true,
      "the unsafe generationless recovery record was deleted rather than preserved for inspection");
  } finally {
    fs.unlinkSync(guard.lockPath);
  }
});

check("recovery metadata cannot escape repository, artifact, or cache boundaries", () => {
  const base = scratch("ko-recovery-confinement-");
  derivedRoots.push(base);
  const digest = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
  const mutant = Buffer.from("MUTANT");
  const pristine = Buffer.from("PRISTINE");

  const plant = ({ root: fixtureRoot, cache, nonce, runDir, marker, index = {} }) => {
    const guard = createBuildStateGuard({ root: fixtureRoot, cacheDir: cache });
    fs.mkdirSync(path.join(runDir, "sources"), { recursive: true });
    fs.writeFileSync(path.join(runDir, "sources", "s0"), pristine);
    fs.writeFileSync(path.join(runDir, "index.json"), JSON.stringify(index));
    fs.writeFileSync(path.join(runDir, "inflight.json"), JSON.stringify({
      version: 4,
      root: fixtureRoot,
      rootIdentity: guard.rootIdentity,
      rootGeneration: guard.rootGeneration,
      nonce,
      entry: "recovery-confinement",
      artifacts: marker.artifacts,
      dirtyBefore: null,
      sources: marker.sources,
    }));
    fs.mkdirSync(cache, { recursive: true });
    fs.writeFileSync(guard.lockPath, JSON.stringify({
      version: 4,
      root: fixtureRoot,
      rootIdentity: guard.rootIdentity,
      rootGeneration: guard.rootGeneration,
      nonce,
      pid: 99999999,
      identity: null,
      identityAvailable: false,
      startedAt: "1970-01-01T00:00:00.000Z",
      runDir,
    }));
    return guard;
  };

  const lexicalRoot = path.join(base, "lexical-repo");
  const lexicalCache = path.join(base, "lexical-cache");
  const lexicalNonce = "lexical-owner";
  const lexicalRun = path.join(lexicalCache, "runs", lexicalNonce);
  fs.mkdirSync(lexicalRoot);
  const lexicalOutside = path.join(base, "lexical-outside.txt");
  fs.writeFileSync(lexicalOutside, mutant);
  const lexicalGuard = plant({
    root: lexicalRoot,
    cache: lexicalCache,
    nonce: lexicalNonce,
    runDir: lexicalRun,
    marker: {
      artifacts: false,
      sources: [{
        rel: "../lexical-outside.txt",
        store: "s0",
        pristineSha: digest(pristine),
        mutantSha: digest(mutant),
      }],
    },
  });
  const lexicalState = lexicalGuard.start();
  assert.equal(lexicalState.kind, "corrupt");
  assert.match(lexicalState.detail, /non-canonical path segment|escapes repository root/);
  assert.equal(fs.readFileSync(lexicalOutside, "utf8"), "MUTANT",
    "a persisted ../ source path was restored outside the repository");
  assert.equal(fs.existsSync(lexicalGuard.lockPath), true,
    "the unsafe recovery record was removed instead of preserved");

  const physicalRoot = path.join(base, "physical-repo");
  const physicalCache = path.join(base, "physical-cache");
  const physicalNonce = "physical-owner";
  const physicalRun = path.join(physicalCache, "runs", physicalNonce);
  const physicalOutside = path.join(base, "physical-outside");
  fs.mkdirSync(physicalRoot);
  fs.mkdirSync(physicalOutside);
  fs.writeFileSync(path.join(physicalOutside, "escaped.txt"), mutant);
  fs.symlinkSync(physicalOutside, path.join(physicalRoot, "linked-parent"));
  const physicalGuard = plant({
    root: physicalRoot,
    cache: physicalCache,
    nonce: physicalNonce,
    runDir: physicalRun,
    marker: {
      artifacts: false,
      sources: [{
        rel: "linked-parent/escaped.txt",
        store: "s0",
        pristineSha: digest(pristine),
        mutantSha: digest(mutant),
      }],
    },
  });
  const physicalState = physicalGuard.start();
  assert.equal(physicalState.kind, "corrupt");
  assert.match(physicalState.detail, /projects outside physical repository root/);
  assert.equal(fs.readFileSync(path.join(physicalOutside, "escaped.txt"), "utf8"), "MUTANT",
    "a persisted source path wrote through an in-repository parent symlink");

  const artifactRoot = path.join(base, "artifact-repo");
  const artifactCache = path.join(base, "artifact-cache");
  const artifactNonce = "artifact-owner";
  const artifactRun = path.join(artifactCache, "runs", artifactNonce);
  fs.mkdirSync(artifactRoot);
  const artifactOutside = path.join(base, "artifact-outside.txt");
  fs.writeFileSync(artifactOutside, mutant);
  const artifactGuard = plant({
    root: artifactRoot,
    cache: artifactCache,
    nonce: artifactNonce,
    runDir: artifactRun,
    marker: { artifacts: true, sources: [] },
    index: { "../artifact-outside.txt": digest(pristine) },
  });
  const artifactState = artifactGuard.start();
  assert.equal(artifactState.kind, "corrupt");
  assert.match(artifactState.detail, /artifact index is corrupt/);
  assert.equal(fs.readFileSync(artifactOutside, "utf8"), "MUTANT",
    "a persisted artifact path escaped the repository during recovery");

  const runRoot = path.join(base, "run-repo");
  const runCache = path.join(base, "run-cache");
  const runNonce = "outside-run-owner";
  const outsideRun = path.join(base, "outside-run");
  fs.mkdirSync(runRoot);
  fs.mkdirSync(outsideRun);
  const outsideSentinel = path.join(outsideRun, "must-remain.txt");
  fs.writeFileSync(outsideSentinel, "PRESERVE");
  const runGuard = plant({
    root: runRoot,
    cache: runCache,
    nonce: runNonce,
    runDir: outsideRun,
    marker: { artifacts: false, sources: [] },
  });
  const runState = runGuard.start();
  assert.equal(runState.kind, "corrupt");
  assert.match(runState.detail, /names run directory .* not/);
  assert.equal(fs.readFileSync(outsideSentinel, "utf8"), "PRESERVE",
    "an out-of-cache run directory was treated as owned recovery state");
});

check("birth-time drift cannot split one physical repository into two locks", () => {
  const r = scratch("ko-birthtime-drift-");
  derivedRoots.push(r);
  const first = trackDefaultGuardCaches(createBuildStateGuard({ root: r }));
  const firstState = first.start();
  assert.equal(firstState.ok, true, `the first identity guard did not start: ${JSON.stringify(firstState)}`);

  const physical = fs.statSync(r, { bigint: true });
  const originalFstatSync = fs.fstatSync;
  let drifted;
  fs.fstatSync = (fd, options) => {
    const stat = originalFstatSync(fd, options);
    if (
      options?.bigint === true && stat.dev === physical.dev && stat.ino === physical.ino &&
      stat.isDirectory()
    ) {
      return new Proxy(stat, {
        get(target, property) {
          if (property === "birthtimeNs") return target.birthtimeNs + 1n;
          const value = Reflect.get(target, property, target);
          return typeof value === "function" ? value.bind(target) : value;
        },
      });
    }
    return stat;
  };
  try {
    drifted = createBuildStateGuard({ root: r });
  } finally {
    fs.fstatSync = originalFstatSync;
  }
  cacheDirs.push(drifted.cacheDir);

  try {
    assert.equal(drifted.rootIdentity, first.rootIdentity,
      "a changed birth-time fallback selected a different coordination identity");
    assert.equal(drifted.cacheDir, first.cacheDir,
      "a changed birth-time fallback selected a second external lock path");
    assert.notEqual(drifted.rootGeneration, first.rootGeneration,
      "the fixture did not alter the recovery generation and is vacuous");
    const driftedState = drifted.start();
    assert.equal(driftedState.kind, "held",
      "a live holder with a stale generation was misclassified as removable corruption");
    assert.equal(driftedState.certainty, "live");
    assert.match(driftedState.recoveryUnsafe, /lock generation .* does not match current/);
    assert.notEqual(first.ownerNonce, null,
      "the original owner disappeared while the drifted contender was evaluated");
  } finally {
    assert.equal(first.release(), true, "the original identity guard did not release");
  }
});

check("a hybrid tombstone and v3 lock cannot create two simultaneous owners", () => {
  const r = scratch("ko-hybrid-tombstone-");
  derivedRoots.push(r);
  fs.mkdirSync(path.join(r, "node_modules"), { recursive: true });

  const externalGuard = trackDefaultGuardCaches(createBuildStateGuard({ root: r }));
  const installedLegacy = path.join(r, "node_modules", ".cache", "noa-knockout");
  const legacyRunDir = path.join(installedLegacy, "runs", "hybrid-owner");
  fs.mkdirSync(installedLegacy, { recursive: true });
  fs.writeFileSync(path.join(installedLegacy, "lock.json"), JSON.stringify({
    version: 3,
    protocol: LEGACY_TOMBSTONE_PROTOCOL,
    root: r,
    rootIdentity: externalGuard.rootIdentity,
    nonce: "hybrid-owner",
    pid: 999999,
    identity: "Thu Jan  1 00:00:00 1970",
    identityAvailable: true,
    startedAt: "1970-01-01T00:00:00.000Z",
    migratedAt: "1970-01-01T00:00:00.000Z",
    runDir: legacyRunDir,
  }), { mode: 0o600 });

  const installedGuard = createBuildStateGuard({ root: r, cacheDir: installedLegacy });
  let externalState = null;
  let installedState = null;
  try {
    assert.throws(() => assertKnockoutMigrationBarrier(r), /does not describe this physical repository/,
      "runtime evidence accepted a live-lock/tombstone hybrid as its migration barrier");
    externalState = externalGuard.start();
    installedState = installedGuard.start();
    assert.equal(externalState.kind, "legacy",
      "the v4 guard accepted a record carrying the complete v3 ownership shape as a tombstone");
    assert.equal(installedState.ok, true,
      "the fixture's v3-compatible guard did not demonstrate that the hybrid remains live state");
    assert.equal(Boolean(externalState.ok && installedState.ok), false,
      "the external v4 and installed legacy guards both claimed ownership of one physical tree");
    assert.equal(fs.existsSync(externalGuard.lockPath), false,
      "the v4 lock was written even though the legacy ownership state was unresolved");
  } finally {
    if (externalState?.ok) externalGuard.release();
    if (installedState?.ok) installedGuard.release();
  }
});

check("an environment-relocated v3 fallback lock blocks the v4 owner", () => {
  const r = scratch("ko-env-legacy-root-");
  const relocated = scratch("ko-env-legacy-cache-");
  derivedRoots.push(r, relocated);
  const shared = path.join(relocated, "noa-knockout");
  const oldStore = path.join(
    shared,
    crypto.createHash("sha256").update(path.resolve(r)).digest("hex").slice(0, 16),
  );
  ensurePrivateDir(shared);
  ensurePrivateDir(oldStore);
  fs.writeFileSync(path.join(oldStore, "lock.json"), JSON.stringify({
    version: 3,
    root: r,
    nonce: "environment-v3-owner",
    pid: 999999,
    identity: "Thu Jan  1 00:00:00 1970",
    identityAvailable: true,
    startedAt: "1970-01-01T00:00:00.000Z",
    runDir: path.join(oldStore, "runs", "environment-v3-owner"),
  }), { mode: 0o600 });

  const previousXdg = process.env.XDG_CACHE_HOME;
  process.env.XDG_CACHE_HOME = relocated;
  let guard;
  try {
    guard = trackDefaultGuardCaches(createBuildStateGuard({ root: r }));
    assert.ok(guard.legacyCacheDirs.includes(oldStore),
      "the exact fallback store selected by the v3 launch environment was not scanned");
    const state = guard.start();
    assert.equal(state.kind, "legacy");
    assert.match(state.detail, /pre-migration recovery state/);
    assert.equal(fs.existsSync(guard.lockPath), false,
      "v4 took its physical-identity lock beside an environment-relocated v3 owner");
  } finally {
    if (previousXdg === undefined) delete process.env.XDG_CACHE_HOME;
    else process.env.XDG_CACHE_HOME = previousXdg;
  }
});

check("a remount-stale identity cannot silently orphan recovery state", () => {
  const r = scratch("ko-remount-root-");
  const relocated = scratch("ko-remount-cache-");
  derivedRoots.push(r, relocated);
  const guard = createBuildStateGuard({ root: r });
  cacheDirs.push(guard.cacheDir);
  const [, currentDevice, currentInode] = guard.rootIdentity.split(":");
  const staleIdentity = `noa-directory/2:${BigInt(currentDevice) + 1n}:${currentInode}`;
  const shared = path.join(relocated, "noa-knockout");
  const staleStore = path.join(shared, crypto.randomBytes(8).toString("hex"));
  const staleRun = path.join(staleStore, "runs", "remount-owner");
  ensurePrivateDir(shared);
  ensurePrivateDir(staleStore);
  fs.mkdirSync(staleRun, { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(staleStore, "lock.json"), JSON.stringify({
    version: 4,
    root: r,
    rootIdentity: staleIdentity,
    rootGeneration: `noa-directory-generation/1:${BigInt(currentDevice) + 1n}:${currentInode}:1`,
    nonce: "remount-owner",
    pid: 0,
    identity: null,
    identityAvailable: false,
    startedAt: "1970-01-01T00:00:00.000Z",
    runDir: staleRun,
  }), { mode: 0o600 });
  const staleMarker = path.join(staleRun, "inflight.json");
  fs.writeFileSync(staleMarker, JSON.stringify({
    version: 4,
    root: r,
    rootIdentity: staleIdentity,
    rootGeneration: `noa-directory-generation/1:${BigInt(currentDevice) + 1n}:${currentInode}:1`,
    nonce: "remount-owner",
    entry: "remount-recovery",
    sources: [],
  }), { mode: 0o600 });

  const previousXdg = process.env.XDG_CACHE_HOME;
  process.env.XDG_CACHE_HOME = relocated;
  try {
    assert.ok(guard.legacyCacheDirs.includes(staleStore),
      "the stale physical identity was not rediscovered through its still-current lexical root");
    const state = guard.start();
    assert.equal(state.kind, "legacy",
      "a stale-device recovery store was silently orphaned after the physical cache key changed");
    assert.ok(state.detail.includes(staleStore),
      "the refusal did not name the orphaned recovery store for operator resolution");
    assert.match(state.detail, /pre-migration recovery state/);
    assert.equal(fs.existsSync(staleMarker), true,
      "discovery erased the orphaned recovery marker instead of preserving it for inspection");
    assert.equal(fs.existsSync(guard.lockPath), false,
      "v4 took a new lock while remount-stale recovery state remained unresolved");
  } finally {
    if (previousXdg === undefined) delete process.env.XDG_CACHE_HOME;
    else process.env.XDG_CACHE_HOME = previousXdg;
  }
});

check("a symlinked v3 launch cache cannot project missing descendants inside the evidence root", () => {
  const r = scratch("ko-env-symlink-root-");
  const holder = scratch("ko-env-symlink-holder-");
  const protectedSubdirectory = path.join(r, "protected-subdirectory");
  derivedRoots.push(r, holder);
  fs.mkdirSync(protectedSubdirectory);
  fs.symlinkSync(protectedSubdirectory, path.join(holder, "cache-link"));
  const projectedCacheHome = path.join(holder, "cache-link", "not-created-yet");

  const previousXdg = process.env.XDG_CACHE_HOME;
  process.env.XDG_CACHE_HOME = projectedCacheHome;
  const guard = createBuildStateGuard({ root: r });
  cacheDirs.push(guard.cacheDir);
  try {
    const state = guard.start();
    assert.equal(state.kind, "legacy");
    assert.match(state.detail, /projects to .* and overlaps evidence root/,
      "a missing descendant hid the physical symlink projection from the overlap guard");
    assert.equal(fs.existsSync(path.join(protectedSubdirectory, "not-created-yet")), false,
      "the environment-selected migration path wrote inside the protected repository");
    assert.equal(fs.existsSync(path.join(r, "node_modules")), false,
      "migration mutated the protected tree before rejecting its hostile cache projection");
    assert.equal(fs.existsSync(guard.lockPath), false,
      "v4 took its external lock after the migration boundary was rejected");
  } finally {
    if (previousXdg === undefined) delete process.env.XDG_CACHE_HOME;
    else process.env.XDG_CACHE_HOME = previousXdg;
  }
});

check("a v3 launch cache cannot project missing descendants inside a protected dependency root", () => {
  const publicRoot = scratch("ko-public-protected-root-");
  const dependencyRoot = scratch("ko-private-protected-root-");
  const holder = scratch("ko-private-protected-holder-");
  const protectedSubdirectory = path.join(dependencyRoot, "protected-subdirectory");
  derivedRoots.push(publicRoot, dependencyRoot, holder);
  fs.mkdirSync(protectedSubdirectory);
  fs.symlinkSync(protectedSubdirectory, path.join(holder, "cache-link"));
  const projectedCacheHome = path.join(holder, "cache-link", "not-created-yet");

  const previousXdg = process.env.XDG_CACHE_HOME;
  process.env.XDG_CACHE_HOME = projectedCacheHome;
  const guard = createBuildStateGuard({ root: publicRoot, protectedRoots: [dependencyRoot] });
  cacheDirs.push(guard.cacheDir);
  try {
    const state = guard.start();
    assert.equal(state.kind, "legacy");
    assert.match(state.detail, /projects to .* and overlaps evidence root/,
      "a missing descendant hid the private dependency from the overlap guard");
    assert.equal(fs.existsSync(path.join(protectedSubdirectory, "not-created-yet")), false,
      "the environment-selected migration path wrote inside the private dependency root");
    assert.equal(fs.existsSync(path.join(publicRoot, "node_modules")), false,
      "migration mutated the public tree before rejecting the hostile dependency projection");
    assert.equal(fs.existsSync(guard.lockPath), false,
      "v4 took its lock after the private dependency boundary was rejected");
  } finally {
    if (previousXdg === undefined) delete process.env.XDG_CACHE_HOME;
    else process.env.XDG_CACHE_HOME = previousXdg;
  }
});

check("an existing singleton guard cannot silently acquire a missing protected root", () => {
  const weakRoot = scratch("ko-weak-singleton-root-");
  const strongRoot = scratch("ko-strong-singleton-root-");
  const dependencyRoot = scratch("ko-singleton-dependency-root-");
  derivedRoots.push(weakRoot, strongRoot, dependencyRoot);

  const weak = buildStateGuardFor(weakRoot);
  assert.throws(
    () => buildStateGuardFor(weakRoot, { protectedRoots: [dependencyRoot] }),
    /does not protect requested evidence root/,
    "a previously cached weak guard was returned for a stronger evidence-root request",
  );

  const strong = buildStateGuardFor(strongRoot, { protectedRoots: [dependencyRoot] });
  assert.equal(buildStateGuardFor(strongRoot), strong,
    "a later subset request did not reuse the already-strong singleton guard");
  assert.throws(
    () => buildStateGuardFor(strongRoot, { protectedRoot: dependencyRoot }),
    /unknown buildStateGuardFor option/,
    "a misspelled protected-root authority option was accepted as inert configuration",
  );
  assert.throws(
    () => createBuildStateGuard({ root: strongRoot, protectedRoot: dependencyRoot }),
    /unknown build-state guard option/,
    "the guard constructor accepted a misspelled protected-root authority option",
  );
});

check("migration publishes only complete tombstones at the legacy lock name", () => {
  const r = scratch("ko-atomic-tombstone-");
  derivedRoots.push(r);
  const guard = trackDefaultGuardCaches(createBuildStateGuard({ root: r }));
  const originalLinkSync = fs.linkSync;
  const publications = [];
  let state = null;
  fs.linkSync = (source, destination) => {
    if (path.basename(destination) === "lock.json" && /\.tombstone-tmp$/.test(source)) {
      // Perform the real no-clobber publication first. A successful hard-link operation itself
      // proves the destination was absent at its atomic linearization point; a pre-existing name
      // makes linkSync throw EEXIST and the fixture fail. Inspect the PUBLISHED inode afterwards
      // through one no-follow descriptor so mode and bytes cannot come from two path resolutions.
      const linked = originalLinkSync(source, destination);
      publications.push(withFd(
        destination,
        fs.constants.O_RDONLY | NOFOLLOW,
        (fd) => {
          const stat = fs.fstatSync(fd);
          let record = null;
          try { record = JSON.parse(fs.readFileSync(fd, "utf8")); } catch {}
          return { mode: stat.mode & 0o777, record };
        },
      ));
      return linked;
    }
    return originalLinkSync(source, destination);
  };
  try {
    state = guard.start();
  } finally {
    fs.linkSync = originalLinkSync;
  }
  try {
    assert.equal(state?.ok, true, `the atomic migration fixture did not start: ${JSON.stringify(state)}`);
    assert.ok(publications.length >= 2, "the fixture observed no installed plus fallback publication");
    for (const publication of publications) {
      assert.equal(publication.mode, 0o600);
      assert.deepEqual(Object.keys(publication.record ?? {}).sort(),
        ["migratedAt", "protocol", "root", "rootIdentity"]);
      assert.equal(publication.record.protocol, LEGACY_TOMBSTONE_PROTOCOL);
      assert.equal(publication.record.rootIdentity, guard.rootIdentity);
    }
    for (const candidate of guard.legacyCacheDirs) {
      if (!fs.existsSync(candidate)) continue;
      assert.deepEqual(fs.readdirSync(candidate).filter((name) => /\.tombstone-tmp$/.test(name)), [],
        `a completed migration left staging bytes in ${candidate}`);
    }
  } finally {
    if (state?.ok) guard.release();
  }
});

check("physical path aliases converge on one in-process guard and one external lock", () => {
  const r = scratch("ko-physical-root-");
  const aliasHolder = scratch("ko-alias-holder-");
  derivedRoots.push(r, aliasHolder);
  const parentAlias = path.join(aliasHolder, "parent-link");
  fs.symlinkSync(path.dirname(r), parentAlias);
  const aliasRoot = path.join(parentAlias, path.basename(r));

  const direct = trackDefaultGuardCaches(createBuildStateGuard({ root: r }));
  const aliased = trackDefaultGuardCaches(createBuildStateGuard({ root: aliasRoot }));
  assert.equal(direct.rootIdentity, aliased.rootIdentity);
  assert.equal(direct.cacheDir, aliased.cacheDir,
    "physical aliases produced different external recovery stores");
  assert.equal(buildStateGuardFor(r), buildStateGuardFor(aliasRoot),
    "the in-process guard map is keyed by lexical path instead of physical identity");
  assert.equal(direct.start().ok, true);
  assert.equal(aliased.start().kind, "held");
  for (const candidate of aliased.legacyCacheDirs) {
    assert.ok(fs.existsSync(path.join(candidate, "lock.json")),
      `the aliased v3 lock location was not tombstoned: ${candidate}`);
  }
  assert.equal(direct.release(), true);

  const dataAlias = `/System/Volumes/Data${REPO}`;
  if (fs.existsSync(dataAlias) && fs.statSync(dataAlias).ino === fs.statSync(REPO).ino) {
    assert.equal(buildStateGuardFor(REPO), buildStateGuardFor(dataAlias),
      "the macOS Data-volume alias produced a second in-process guard");
  }
});

check("cached in-process guards revalidate their physical root before reuse", () => {
  // A directory identity is reusable after unlink. The map may coordinate by device+inode, but it
  // must not return an object whose lexical root and recovery generation belong to the previous
  // occupant. This fixture makes the reuse deterministic by projecting a replacement directory's
  // descriptor onto the deleted root's identity; the cached root itself remains genuinely absent.
  const staleRoot = scratch("ko-cached-stale-root-");
  const replacementRoot = scratch("ko-cached-replacement-root-");
  derivedRoots.push(staleRoot, replacementRoot);
  const stalePhysical = fs.statSync(staleRoot, { bigint: true });
  const replacementPhysical = fs.statSync(replacementRoot, { bigint: true });
  const stale = trackDefaultGuardCaches(buildStateGuardFor(staleRoot));
  assert.equal(stale.start().ok, true, "the stale-root fixture did not own its guard");
  fs.rmSync(staleRoot, { recursive: true, force: true });

  const originalFstatSync = fs.fstatSync;
  fs.fstatSync = (fd, options) => {
    const stat = originalFstatSync(fd, options);
    if (
      options?.bigint === true && stat.dev === replacementPhysical.dev &&
      stat.ino === replacementPhysical.ino && stat.isDirectory()
    ) {
      return new Proxy(stat, {
        get(target, property) {
          if (property === "dev") return stalePhysical.dev;
          if (property === "ino") return stalePhysical.ino;
          if (property === "birthtimeNs") return stalePhysical.birthtimeNs;
          const value = Reflect.get(target, property, target);
          return typeof value === "function" ? value.bind(target) : value;
        },
      });
    }
    return stat;
  };
  try {
    assert.throws(
      () => buildStateGuardFor(replacementRoot),
      /active knockout guard .* no longer describes the requested repository root/,
      "an inode-reused replacement received the deleted root's active cached guard",
    );
  } finally {
    fs.fstatSync = originalFstatSync;
    assert.equal(stale.release(), true, "the stale-root fixture did not release its owned guard");
  }

  // An ownerless cached guard has no live coordination state to preserve. Generation drift must
  // rebuild it, binding future recovery bytes to the descriptor observed by this call.
  const generationRoot = scratch("ko-cached-generation-root-");
  derivedRoots.push(generationRoot);
  const generationPhysical = fs.statSync(generationRoot, { bigint: true });
  const before = trackDefaultGuardCaches(buildStateGuardFor(generationRoot));
  fs.fstatSync = (fd, options) => {
    const stat = originalFstatSync(fd, options);
    if (
      options?.bigint === true && stat.dev === generationPhysical.dev &&
      stat.ino === generationPhysical.ino && stat.isDirectory()
    ) {
      return new Proxy(stat, {
        get(target, property) {
          if (property === "birthtimeNs") return target.birthtimeNs + 1n;
          const value = Reflect.get(target, property, target);
          return typeof value === "function" ? value.bind(target) : value;
        },
      });
    }
    return stat;
  };
  let after;
  try {
    after = buildStateGuardFor(generationRoot);
  } finally {
    fs.fstatSync = originalFstatSync;
  }
  trackDefaultGuardCaches(after);
  assert.notEqual(after, before, "an ownerless generation-stale guard was returned from the cache");
  assert.notEqual(after.rootGeneration, before.rootGeneration,
    "the replacement guard did not bind the newly observed directory generation");
});

check("default cache child symlinks and permissive modes are refused before a lock write", () => {
  ensurePrivateDir(privateFallbackRoot());

  const symlinkRoot = scratch("ko-cache-symlink-root-");
  const symlinkTarget = scratch("ko-cache-symlink-target-");
  derivedRoots.push(symlinkRoot, symlinkTarget);
  const symlinkGuard = trackDefaultGuardCaches(createBuildStateGuard({ root: symlinkRoot }));
  fs.symlinkSync(symlinkTarget, symlinkGuard.cacheDir);
  const symlinkStart = symlinkGuard.start();
  assert.equal(symlinkStart.kind, "corrupt");
  assert.match(symlinkStart.detail, /not a real directory/);
  assert.deepEqual(fs.readdirSync(symlinkTarget), [], "the lock was written through a planted cache symlink");
  fs.unlinkSync(symlinkGuard.cacheDir);

  const modeRoot = scratch("ko-cache-mode-root-");
  derivedRoots.push(modeRoot);
  const modeGuard = trackDefaultGuardCaches(createBuildStateGuard({ root: modeRoot }));
  fs.mkdirSync(modeGuard.cacheDir, { mode: 0o755 });
  const modeStart = modeGuard.start();
  assert.equal(modeStart.kind, "corrupt");
  assert.match(modeStart.detail, /not 700/);
  assert.equal(fs.existsSync(modeGuard.lockPath), false);

  const normalRoot = scratch("ko-cache-normal-root-");
  derivedRoots.push(normalRoot);
  const normalGuard = trackDefaultGuardCaches(createBuildStateGuard({ root: normalRoot }));
  assert.equal(normalGuard.start().ok, true);
  assert.equal(fs.lstatSync(normalGuard.cacheDir).mode & 0o777, 0o700);
  assert.equal(fs.lstatSync(normalGuard.lockPath).mode & 0o777, 0o600);
  assert.equal(normalGuard.release(), true);
});

check("material v3 recovery state blocks migration before the v4 lock is written", () => {
  const r = scratch("ko-legacy-material-");
  derivedRoots.push(r);
  fs.mkdirSync(path.join(r, "node_modules"), { recursive: true });
  const guard = trackDefaultGuardCaches(createBuildStateGuard({ root: r }));
  const legacy = path.join(r, "node_modules", ".cache", "noa-knockout");
  fs.mkdirSync(legacy, { recursive: true });
  fs.writeFileSync(path.join(legacy, "lock.json"), JSON.stringify({
    version: 3,
    root: r,
    nonce: "legacy-owner",
    pid: 999999,
    identity: "Thu Jan  1 00:00:00 1970",
    identityAvailable: true,
    startedAt: "1970-01-01T00:00:00.000Z",
    runDir: path.join(legacy, "runs", "legacy-owner"),
  }));
  const state = guard.start();
  assert.equal(state.kind, "legacy");
  assert.match(state.detail, /pre-migration recovery state/);
  assert.equal(fs.existsSync(guard.lockPath), false,
    "the v4 lock was taken despite unresolved v3 recovery state");
});

check("an alias-only legacy lock stays authoritative when its runs directory is unreadable", () => {
  const r = scratch("ko-legacy-alias-root-");
  const aliasHolder = scratch("ko-legacy-alias-holder-");
  derivedRoots.push(r, aliasHolder);
  const parentAlias = path.join(aliasHolder, "parent-link");
  fs.symlinkSync(path.dirname(r), parentAlias);
  const aliasRoot = path.join(parentAlias, path.basename(r));
  const realGuard = trackDefaultGuardCaches(createBuildStateGuard({ root: r }));
  const aliasGuard = trackDefaultGuardCaches(createBuildStateGuard({ root: aliasRoot }));
  const realLegacy = new Set(realGuard.legacyCacheDirs);
  const aliasOnly = aliasGuard.legacyCacheDirs.find((candidate) =>
    candidate.startsWith(`${privateFallbackRoot()}${path.sep}`) && !realLegacy.has(candidate));
  assert.ok(aliasOnly, "the fixture did not produce a lexical-alias v3 store");
  ensurePrivateDir(aliasOnly);
  const runs = path.join(aliasOnly, "runs");
  fs.mkdirSync(runs, { mode: 0o700 });
  const lock = path.join(aliasOnly, "lock.json");
  fs.writeFileSync(lock, JSON.stringify({
    version: 3,
    root: aliasRoot,
    nonce: "alias-v3-owner",
    pid: 999999,
    identity: "Thu Jan  1 00:00:00 1970",
    identityAvailable: true,
    startedAt: "1970-01-01T00:00:00.000Z",
    runDir: path.join(runs, "alias-v3-owner"),
  }), { mode: 0o600 });
  fs.chmodSync(runs, 0o000);
  try {
    assert.throws(() => fs.readdirSync(runs), /EACCES|permission denied/i,
      "the fixture can still enumerate its mode-000 runs directory and measures no refusal");
    const oldState = realGuard.start();
    assert.equal(oldState.kind, "legacy");
    assert.match(oldState.detail, /pre-migration recovery state/,
      "an unreadable runs directory made discovery skip the matching v3 lock");

    fs.chmodSync(runs, 0o700);
    fs.chmodSync(lock, 0o600);
    fs.unlinkSync(lock);
    fs.writeFileSync(lock, JSON.stringify({
      protocol: LEGACY_TOMBSTONE_PROTOCOL,
      root: aliasRoot,
      rootIdentity: realGuard.rootIdentity,
      migratedAt: "1970-01-01T00:00:00.000Z",
    }), { mode: 0o600 });
    fs.chmodSync(runs, 0o000);
    const unreadableState = trackDefaultGuardCaches(createBuildStateGuard({ root: r })).start();
    assert.equal(unreadableState.kind, "legacy");
    assert.match(unreadableState.detail, /runs\(unreadable:/,
      "material validation did not report the unreadable alias store after matching its lock");
  } finally {
    try { fs.chmodSync(runs, 0o700); } catch {}
    try { fs.chmodSync(lock, 0o600); } catch {}
  }
});

check("legacy scan warnings survive a later shared-root refusal", () => {
  const r = scratch("ko-warning-before-refusal-root-");
  const foreignRoot = scratch("ko-warning-before-refusal-foreign-");
  const relocated = scratch("ko-warning-before-refusal-cache-");
  derivedRoots.push(r, foreignRoot, relocated);

  ensurePrivateDir(privateFallbackRoot());
  const foreignStore = path.join(privateFallbackRoot(), crypto.randomBytes(8).toString("hex"));
  cacheDirs.push(foreignStore);
  ensurePrivateDir(foreignStore);
  const foreignLock = path.join(foreignStore, "lock.json");
  fs.writeFileSync(foreignLock, JSON.stringify({ version: 3, root: foreignRoot }), { mode: 0o600 });
  fs.chmodSync(foreignLock, 0o000);

  const relocatedShared = path.join(relocated, "noa-knockout");
  ensurePrivateDir(relocatedShared);
  const previousXdg = process.env.XDG_CACHE_HOME;
  const originalReaddirSync = fs.readdirSync;
  let forcedRefusals = 0;
  process.env.XDG_CACHE_HOME = relocated;
  fs.readdirSync = (candidate, ...args) => {
    if (typeof candidate === "string" && path.resolve(candidate) === path.resolve(relocatedShared)) {
      forcedRefusals++;
      const error = new Error("forced later shared-root refusal");
      error.code = "EACCES";
      throw error;
    }
    return originalReaddirSync(candidate, ...args);
  };
  let state;
  try {
    assert.throws(() => fs.readFileSync(foreignLock), /EACCES|permission denied/i,
      "the first shared root did not produce the warning this case must preserve");
    const guard = createBuildStateGuard({ root: r });
    cacheDirs.push(guard.cacheDir);
    state = guard.start();
  } finally {
    fs.readdirSync = originalReaddirSync;
    try { fs.chmodSync(foreignLock, 0o600); } catch {}
    if (previousXdg === undefined) delete process.env.XDG_CACHE_HOME;
    else process.env.XDG_CACHE_HOME = previousXdg;
  }
  assert.ok(forcedRefusals > 0, "the fixture never reached the later failing shared root");
  assert.equal(state.kind, "legacy");
  assert.match(state.detail, /cannot inspect legacy knockout stores under/);
  assert.ok(state.warnings.some((warning) => warning.includes(foreignLock)),
    "a hard refusal in a later shared root erased an earlier scan warning");
});

check("an unassociated lock-absent unreadable runs directory is never skipped silently", () => {
  const r = scratch("ko-unreadable-runs-root-");
  const relocated = scratch("ko-unreadable-runs-cache-");
  derivedRoots.push(r, relocated);
  const shared = path.join(relocated, "noa-knockout");
  const candidate = path.join(shared, crypto.randomBytes(8).toString("hex"));
  const runs = path.join(candidate, "runs");
  ensurePrivateDir(shared);
  ensurePrivateDir(candidate);
  fs.mkdirSync(runs, { mode: 0o700 });

  const previousXdg = process.env.XDG_CACHE_HOME;
  process.env.XDG_CACHE_HOME = relocated;
  fs.chmodSync(runs, 0o000);
  let state;
  try {
    assert.throws(() => fs.readdirSync(runs), /EACCES|permission denied/i,
      "the runs directory remained readable and the fixture measures no skipped state");
    const guard = createBuildStateGuard({ root: r });
    cacheDirs.push(guard.cacheDir);
    state = guard.start();
    assert.equal(state.ok, true,
      "an unassociated unreadable store blocked every repository instead of being scoped");
    assert.ok(state.warnings.some((warning) => warning.includes(runs)),
      "a lock-absent unreadable runs directory disappeared without an operator warning");
    assert.equal(guard.release(), true);
  } finally {
    try { fs.chmodSync(runs, 0o700); } catch {}
    if (previousXdg === undefined) delete process.env.XDG_CACHE_HOME;
    else process.env.XDG_CACHE_HOME = previousXdg;
  }
});

check("a foreign unreadable scanned v3 store warns without wedging this repository", () => {
  const r = scratch("ko-unreadable-foreign-root-");
  const foreignRoot = scratch("ko-unreadable-foreign-owner-");
  const relocated = scratch("ko-unreadable-foreign-cache-");
  derivedRoots.push(r, foreignRoot, relocated);
  const shared = path.join(relocated, "noa-knockout");
  const foreignStore = path.join(shared, crypto.randomBytes(8).toString("hex"));
  ensurePrivateDir(shared);
  ensurePrivateDir(foreignStore);
  const foreignLock = path.join(foreignStore, "lock.json");
  fs.writeFileSync(foreignLock, JSON.stringify({ version: 3, root: foreignRoot }), { mode: 0o600 });

  const previousXdg = process.env.XDG_CACHE_HOME;
  process.env.XDG_CACHE_HOME = relocated;
  fs.chmodSync(foreignLock, 0o000);
  let guard;
  try {
    assert.throws(() => fs.readFileSync(foreignLock), /EACCES|permission denied/i,
      "the foreign fixture lock remained readable and did not exercise scoped scan failure");
    guard = trackDefaultGuardCaches(createBuildStateGuard({ root: r }));
    const state = guard.start();
    assert.equal(state.ok, true,
      "an unreadable record for a different repository blocked this root's migration");
    assert.ok(state.warnings.some((warning) => warning.includes(foreignLock)),
      "the skipped unreadable foreign record was not surfaced to the operator");

    const contender = createBuildStateGuard({ root: r });
    cacheDirs.push(contender.cacheDir);
    const held = contender.start();
    assert.equal(held.kind, "held");
    assert.ok(held.warnings.some((warning) => warning.includes(foreignLock)),
      "the skipped unreadable foreign record warning disappeared on a held refusal");
    assert.equal(guard.release(), true);

    const corruptRoot = scratch("ko-warning-corrupt-root-");
    derivedRoots.push(corruptRoot);
    const corruptGuard = createBuildStateGuard({ root: corruptRoot });
    cacheDirs.push(corruptGuard.cacheDir);
    ensurePrivateDir(corruptGuard.cacheDir);
    fs.writeFileSync(corruptGuard.lockPath, "{not-json", { mode: 0o600 });
    const corrupt = corruptGuard.start();
    assert.equal(corrupt.kind, "corrupt");
    assert.ok(corrupt.warnings.some((warning) => warning.includes(foreignLock)),
      "the skipped unreadable foreign record warning disappeared on a corrupt refusal");
    fs.unlinkSync(corruptGuard.lockPath);

    const unrepairedRoot = scratch("ko-warning-unrepaired-root-");
    derivedRoots.push(unrepairedRoot);
    const unrepairedGuard = createBuildStateGuard({ root: unrepairedRoot });
    cacheDirs.push(unrepairedGuard.cacheDir);
    ensurePrivateDir(unrepairedGuard.cacheDir);
    const nonce = "unrepaired-warning-owner";
    const runDir = path.join(unrepairedGuard.cacheDir, "runs", nonce);
    const sourceDir = path.join(runDir, "sources");
    fs.mkdirSync(sourceDir, { recursive: true, mode: 0o700 });
    const sourcePath = path.join(unrepairedRoot, "source.txt");
    const pristine = Buffer.from("PRISTINE");
    const mutant = Buffer.from("MUTANT");
    const digest = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
    fs.writeFileSync(sourcePath, "CONCURRENT");
    fs.writeFileSync(path.join(sourceDir, "s0"), pristine);
    fs.writeFileSync(path.join(runDir, "index.json"), "{}");
    fs.writeFileSync(path.join(runDir, "inflight.json"), JSON.stringify({
      version: 4,
      root: unrepairedRoot,
      rootIdentity: unrepairedGuard.rootIdentity,
      rootGeneration: unrepairedGuard.rootGeneration,
      nonce,
      entry: "warning-unrepaired",
      artifacts: false,
      dirtyBefore: null,
      sources: [{
        rel: "source.txt",
        store: "s0",
        pristineSha: digest(pristine),
        mutantSha: digest(mutant),
      }],
    }));
    fs.writeFileSync(unrepairedGuard.lockPath, JSON.stringify({
      version: 4,
      root: unrepairedRoot,
      rootIdentity: unrepairedGuard.rootIdentity,
      rootGeneration: unrepairedGuard.rootGeneration,
      nonce,
      pid: 99999999,
      identity: null,
      identityAvailable: false,
      startedAt: "1970-01-01T00:00:00.000Z",
      runDir,
    }), { mode: 0o600 });
    const unrepaired = unrepairedGuard.start();
    assert.equal(unrepaired.kind, "unrepaired");
    assert.ok(unrepaired.warnings.some((warning) => warning.includes(foreignLock)),
      "the skipped unreadable foreign record warning disappeared on an unrepaired refusal");
  } finally {
    try { fs.chmodSync(foreignLock, 0o600); } catch {}
    if (previousXdg === undefined) delete process.env.XDG_CACHE_HOME;
    else process.env.XDG_CACHE_HOME = previousXdg;
  }
});

check("an unreadable deterministic v3 store for this root still refuses migration", () => {
  const r = scratch("ko-unreadable-own-root-");
  const relocated = scratch("ko-unreadable-own-cache-");
  derivedRoots.push(r, relocated);
  const shared = path.join(relocated, "noa-knockout");
  const ownStore = path.join(
    shared,
    crypto.createHash("sha256").update(path.resolve(r)).digest("hex").slice(0, 16),
  );
  ensurePrivateDir(shared);
  ensurePrivateDir(ownStore);
  const ownLock = path.join(ownStore, "lock.json");
  fs.writeFileSync(ownLock, JSON.stringify({ version: 3, root: r }), { mode: 0o600 });

  const previousXdg = process.env.XDG_CACHE_HOME;
  process.env.XDG_CACHE_HOME = relocated;
  fs.chmodSync(ownLock, 0o000);
  let guard;
  try {
    assert.throws(() => fs.readFileSync(ownLock), /EACCES|permission denied/i,
      "the deterministic fixture lock remained readable and did not exercise fail-closed handling");
    guard = trackDefaultGuardCaches(createBuildStateGuard({ root: r }));
    const state = guard.start();
    assert.equal(state.kind, "legacy",
      "an unreadable deterministic v3 lock was treated as a foreign scanned store");
    assert.match(state.detail, /cannot be read as a migration tombstone/);
    assert.equal(fs.existsSync(state.lockPath), false,
      "v4 took its lock while this root's deterministic v3 record was unreadable");
  } finally {
    try { fs.chmodSync(ownLock, 0o600); } catch {}
    if (previousXdg === undefined) delete process.env.XDG_CACHE_HOME;
    else process.env.XDG_CACHE_HOME = previousXdg;
  }
});

check("listBuildArtifacts takes every dist/ tree and never enters node_modules", () => {
  const r = scratch("ko-walk-");
  derivedRoots.push(r);
  fs.mkdirSync(path.join(r, "dist", "src"), { recursive: true });
  fs.mkdirSync(path.join(r, "packages", "a", "dist"), { recursive: true });
  fs.mkdirSync(path.join(r, "packages", "a", "node_modules", "dep", "dist"), { recursive: true });
  fs.mkdirSync(path.join(r, "src"), { recursive: true });
  fs.writeFileSync(path.join(r, "dist", "src", "i.js"), "1");
  fs.writeFileSync(path.join(r, "dist", "tsconfig.tsbuildinfo"), "2");
  fs.writeFileSync(path.join(r, "packages", "a", "dist", "i.js"), "3");
  fs.writeFileSync(path.join(r, "packages", "a", "node_modules", "dep", "dist", "i.js"), "4");
  fs.writeFileSync(path.join(r, "src", "i.ts"), "5");
  assert.deepEqual(listBuildArtifacts(r), [
    "dist/src/i.js", "dist/tsconfig.tsbuildinfo", "packages/a/dist/i.js",
  ], "a dependency's dist/ was snapshotted (thousands of files per arm) or a real one was missed");
});

/* ─── ROUND 2 #6 ───────────────────────────────────────────────────────────────────────────────
 * "There is no work tree here" and "the probe would not answer" are opposite facts, and both were
 * returning `false` — so a git that failed for any other reason read as "nothing is tracked", and
 * every generated file an arm rewrote was then left alone. */
check("gitWorkTreeState is THREE-valued; only a probe that RAN may answer 'no'", () => {
  const r = scratch("ko-nogit-");
  derivedRoots.push(r);
  assert.equal(gitWorkTreeState(r), "no",
    `${r} reports as a git work tree — is the selftest workspace inside a repository? ` +
      "(a repository initialised over your home directory would do it.) This arm measures nothing from in there.");
  assert.equal(isGitWorkTree(r), false);
  assert.equal(gitDirtyPaths(r), null,
    "a proven non-work-tree is the one place where 'nothing is tracked' is a complete answer");

  const gone = path.join(r, "a-directory-that-does-not-exist");
  assert.equal(gitWorkTreeState(gone), "unknown",
    "git could not even be launched there, and that was reported as a definite 'no'");
  assert.throws(() => isGitWorkTree(gone), /cannot determine/);
  assert.throws(() => gitDirtyPaths(gone), /IncompleteSnapshot|git status failed|cannot determine/);

  const g = scratch("ko-git-");
  derivedRoots.push(g);
  fs.writeFileSync(path.join(g, "a.txt"), "a\n");
  const cfg = ["-c", "user.email=s@e.invalid", "-c", "user.name=s", "-c", "commit.gpgsign=false"];
  execFileSync("git", ["init", "-q"], { cwd: g, stdio: "pipe" });
  execFileSync("git", [...cfg, "add", "-A"], { cwd: g, stdio: "pipe" });
  execFileSync("git", [...cfg, "commit", "-q", "-m", "x"], { cwd: g, stdio: "pipe" });
  assert.equal(gitWorkTreeState(g), "yes");
  assert.ok(gitDirtyPaths(g) instanceof Map, "a real work tree must answer with a map, not null");

  // git is present, the tree IS a work tree, and `status` cannot run — it needs the index and
  // `rev-parse --is-inside-work-tree` does not.
  const indexPath = path.join(g, ".git", "index");
  fs.chmodSync(indexPath, 0o000);
  let statusRuns = true;
  try { execFileSync("git", ["status", "--porcelain"], { cwd: g, stdio: "pipe" }); } catch { statusRuns = false; }
  try {
    assert.equal(statusRuns, false,
      "git status still works with an unreadable index — running as root? this arm measures nothing");
    assert.equal(gitWorkTreeState(g), "yes", "the tree stopped identifying as a work tree; the arm is not measuring the intended case");
    assert.throws(() => gitDirtyPaths(g), /git status failed inside a git work tree/,
      "git failed inside a work tree and the guard reported it as 'nothing was dirty'");
  } finally {
    fs.chmodSync(indexPath, 0o644);
  }
});

const selftestGuard = trackDefaultGuardCaches(buildStateGuardFor(root));
check("the selftest releases its own default guard before deleting any fixture state", () => {
  if (fs.existsSync(selftestGuard.lockPath)) {
    assert.equal(selftestGuard.release(), true,
      "the selftest guard retained an in-flight recovery marker; its fixture must be preserved");
  }
  assert.equal(fs.existsSync(selftestGuard.lockPath), false,
    "the selftest default lock survived its explicit release");
});
const preserveSelftestRecovery = fs.existsSync(selftestGuard.lockPath);
const preservedCaches = preserveSelftestRecovery
  ? new Set([selftestGuard.cacheDir, ...selftestGuard.legacyCacheDirs])
  : new Set();
for (const r of derivedRoots) fs.rmSync(r, { recursive: true, force: true });
check("every registered standalone helper scratch root is removed", () => {
  assert.equal(registeredStandaloneHelperRoots.length, STANDALONE_HELPER_SCRATCH_PREFIXES.length,
    "not every standalone helper scratch root was registered for cleanup");
  assert.deepEqual(
    registeredStandaloneHelperRoots.map(({ prefix }) => prefix).sort(),
    [...STANDALONE_HELPER_SCRATCH_PREFIXES].sort(),
    "the registered standalone helper scratch roots do not match the closed helper set",
  );
  assert.equal(
    new Set(registeredStandaloneHelperRoots.map(({ directory }) => directory)).size,
    registeredStandaloneHelperRoots.length,
    "two standalone helper fixtures unexpectedly reused one scratch directory",
  );
  for (const { prefix, directory } of registeredStandaloneHelperRoots) {
    assert.equal(fs.existsSync(directory), false,
      `${prefix} generated scratch survived cleanup at ${directory}`);
  }
});
for (const d of cacheDirs) {
  if (!preservedCaches.has(d)) fs.rmSync(d, { recursive: true, force: true });
}
if (!preserveSelftestRecovery) fs.rmSync(root, { recursive: true, force: true });
else console.error(`selftest recovery fixture retained at ${root}`);
if (process.argv.includes("--knockout-json")) {
  // Machine evidence for the knockout registry: the exact case names that went red, so an entry
  // targeting this file certifies on the case it named and never on an unrelated failure.
  emitGateEvidence("knockout-selftest", failedChecks.map(({ name, detail }) => ({
    rule: "SELFTEST", subject: name, detail,
  })));
  process.exit(failures === 0 ? 0 : 1);
}
console.log(`\n${failures === 0 ? "knockout runner classifies correctly" : `${failures} FAILURE(S) — the framework that judges every control is wrong`}`);
process.exit(failures === 0 ? 0 : 1);
