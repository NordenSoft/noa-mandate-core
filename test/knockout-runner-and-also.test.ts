import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

type Suite = [string, string, string[]];
type Entry = {
  id: string;
  control: string;
  file: string;
  find: string;
  replace: string;
  also?: Array<{ find: string; replace: string }>;
  andAlso?: string;
  kind: "gate" | "tests";
  gateId?: string;
  expectedGateFindings?: Array<{ rule: string; subject: string }>;
  suite: Suite;
};
type Observation = {
  exit: number | null;
  failing: Set<string>;
  failureEvents: Array<{ name: string; file: string; line: number; column: number }>;
  findings: number;
  ms: number;
  timedOut: boolean;
  out: string;
  protocolComplete: boolean;
  protocolError: string | null;
  testEvents: string;
  testCount: number;
  fileFailureCount: number;
  gateProtocolComplete: boolean;
  gateProtocolError: string | null;
  gate: string | null;
  gateFindings: Array<{ rule: string; subject: string; detail: string }>;
};
type Evidence = {
  verdict: string;
  detail?: string;
  andAlso?: string;
  hashBefore: Record<string, string>;
  hashAfter: Record<string, string>;
  restored: boolean;
  workspaceDisposition?: string;
};
type Guard = {
  beginArm: (options: {
    entryId: string;
    sources: Array<[string, string | Buffer, string | Buffer]>;
  }) => boolean;
  cacheDir: string;
  commitRetainedArm: () => boolean;
  ownerNonce: string | null;
  release: () => boolean;
  start: () => {
    ok: boolean;
    kind?: string;
    detail?: string;
    recovered?: { clean: boolean } | null;
  };
};
type Fixture = {
  cacheDir: string;
  root: string;
  guard: Guard;
  cleanup: () => void;
};

// This test is compiled to dist/test. Resolve back to the source runner so `npm test` exercises the
// exact instrument used by lint-control-knockout, not a copied fixture or stale build artefact.
const testFileDirectory = path.dirname(fileURLToPath(import.meta.url));
const directSourceRoot = path.resolve(testFileDirectory, "..");
const repoRoot = fs.existsSync(path.join(directSourceRoot, "scripts/lib/knockout-runner.mjs"))
  ? directSourceRoot
  : path.resolve(testFileDirectory, "..", "..");
const runner = await import(pathToFileURL(path.join(repoRoot, "scripts/lib/knockout-runner.mjs")).href) as {
  runKnockout: (options: {
    root: string;
    entry: Entry;
    registry: Entry[];
    baseline: Observation;
    timeoutMs: number;
    guard: Guard;
    workspaceMode?: "disposable" | "restoring";
  }) => Evidence;
  createBuildStateGuard: (options: { root: string; cacheDir: string }) => Guard;
  observeSuite: (
    root: string,
    suite: Suite,
    timeoutMs?: number,
    options?: { kind?: "gate" | "tests" },
  ) => Observation;
  validateKnockoutRegistry: (registry: object[]) => Map<string, object>;
  VERDICT: Record<string, string>;
};
const { createBuildStateGuard, runKnockout, observeSuite, validateKnockoutRegistry, VERDICT } = runner;

const PRIMARY = "const primary = REAL_PRIMARY;";
const COMPANION = "const companion = REAL_COMPANION;";
const EXTRA = "const extra = REAL_EXTRA;";
const runnerModuleUrl = pathToFileURL(
  path.join(repoRoot, "scripts/lib/knockout-runner.mjs"),
).href;

function leaveCrashedArm(root: string, cacheDir: string, mode: "mutant" | "hardlink-user"): void {
  const child = [
    'import fs from "node:fs";',
    'import path from "node:path";',
    'const { createBuildStateGuard } = await import(process.env.NOA_KO_RUNNER_URL);',
    'const root = process.env.NOA_KO_FIXTURE_ROOT;',
    'const cacheDir = process.env.NOA_KO_FIXTURE_CACHE;',
    'const mode = process.env.NOA_KO_CRASH_MODE;',
    'const source = path.join(root, "primary.js");',
    'const pristine = fs.readFileSync(source, "utf8");',
    'const mutant = pristine.replace("const primary = REAL_PRIMARY;", "const primary = false;");',
    'const guard = createBuildStateGuard({ root, cacheDir });',
    'const started = guard.start();',
    'if (!started.ok) throw new Error(`child guard refused: ${JSON.stringify(started)}`);',
    'guard.beginArm({ entryId: `crash-${mode}`, sources: [["primary.js", pristine, mutant]] });',
    'fs.writeFileSync(source, mutant);',
    'if (mode === "hardlink-user") {',
    '  const derived = path.join(root, "dist", "derived.js");',
    '  fs.unlinkSync(derived);',
    '  fs.linkSync(source, derived);',
    '  fs.writeFileSync(source, "post-crash user bytes must survive\\n");',
    '}',
  ].join("\n");
  execFileSync(process.execPath, ["--input-type=module", "-e", child], {
    env: {
      ...process.env,
      NOA_KO_CRASH_MODE: mode,
      NOA_KO_FIXTURE_CACHE: cacheDir,
      NOA_KO_FIXTURE_ROOT: root,
      NOA_KO_RUNNER_URL: runnerModuleUrl,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function fixture({ git = false } = {}): Fixture {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "ko-and-also-"));
  const cacheDir = fs.mkdtempSync(path.join(os.tmpdir(), "ko-and-also-cache-"));
  try {
    fs.writeFileSync(path.join(root, "primary.js"), `${PRIMARY}\n`);
    fs.writeFileSync(path.join(root, "companion.js"), `${COMPANION}\n${EXTRA}\n`);
    fs.writeFileSync(path.join(root, "suite.mjs"), [
      'import assert from "node:assert/strict";',
      'import fs from "node:fs";',
      'import test from "node:test";',
      'test("paired guard is load-bearing", () => {',
      '  const primary = fs.readFileSync(new URL("./primary.js", import.meta.url), "utf8");',
      '  const companion = fs.readFileSync(new URL("./companion.js", import.meta.url), "utf8");',
      '  const broken = !primary.includes("REAL_PRIMARY") && !companion.includes("REAL_COMPANION") && !companion.includes("REAL_EXTRA");',
      '  assert.equal(broken, false);',
      '});',
    ].join("\n"));
    if (git) {
      execFileSync("git", ["init", "-q"], { cwd: root });
      execFileSync("git", ["config", "user.name", "NOA Knockout Selftest"], { cwd: root });
      execFileSync("git", ["config", "user.email", "selftest@noa.invalid"], { cwd: root });
      execFileSync("git", ["add", "--", "primary.js", "companion.js", "suite.mjs"], { cwd: root });
      execFileSync("git", ["commit", "-q", "-m", "fixture"], { cwd: root });
    }
    const guard = createBuildStateGuard({ root, cacheDir });
    return {
      cacheDir,
      root,
      guard,
      cleanup() {
        try { guard.release(); }
        finally {
          fs.rmSync(root, { recursive: true, force: true });
          fs.rmSync(cacheDir, { recursive: true, force: true });
        }
      },
    };
  } catch (error) {
    fs.rmSync(root, { recursive: true, force: true });
    fs.rmSync(cacheDir, { recursive: true, force: true });
    throw error;
  }
}

function registry(): [Entry, Entry] {
  const suite: Suite = [".", process.execPath, ["--test", "suite.mjs"]];
  return [
    {
      id: "primary",
      control: "primary half",
      file: "primary.js",
      find: PRIMARY,
      replace: "const primary = false;",
      andAlso: "companion",
      kind: "tests",
      suite,
    },
    {
      id: "companion",
      control: "companion half",
      file: "companion.js",
      find: COMPANION,
      replace: "const companion = false;",
      also: [{ find: EXTRA, replace: "const extra = false;" }],
      kind: "tests",
      suite,
    },
  ];
}

function baseline(root: string, suite: Suite): Observation {
  const observed = observeSuite(root, suite, 60_000, { kind: "tests" });
  assert.equal(
    observed.protocolComplete,
    true,
    `${observed.protocolError ?? "no protocol error"}\n${observed.out}\n${observed.testEvents}`,
  );
  return observed;
}

test("an unknown registry key errors loudly with the entry id and key", () => {
  const [entry] = registry();
  assert.throws(
    () => validateKnockoutRegistry([{ ...entry, andAlso: undefined, silentlyIgnored: true }]),
    /invalid knockout entry "primary": unknown key "silentlyIgnored"/,
  );
});

test("a missing andAlso id errors loudly before a suite can run", () => {
  const [entry] = registry();
  assert.throws(
    () => validateKnockoutRegistry([{ ...entry, andAlso: "does-not-exist" }]),
    /invalid knockout entry "primary": andAlso references missing entry id "does-not-exist"/,
  );
});

test("direct node test entries reject invalid evidence commands at registry load", () => {
  const [entry] = registry();
  for (const command of ["node", process.execPath]) {
    for (const args of [
      ["suite.mjs", "--selftest"],
      ["--test", "--test", "suite.mjs"],
      ["--test", "--test-reporter=tap", "suite.mjs"],
    ]) {
      assert.throws(
        () => validateKnockoutRegistry([{
          ...entry, andAlso: undefined, suite: [".", command, args],
        }]),
        /invalid knockout entry "primary": direct test command:/,
        JSON.stringify({ command, args }),
      );
    }
  }
});

test("direct node test registry admission preserves supported source-map and TypeScript arguments", () => {
  const [entry] = registry();
  for (const command of ["node", process.execPath]) {
    for (const args of [
      ["--test", "suite.mjs"],
      ["--enable-source-maps", "--test", "suite.mjs"],
      ["--import", "tsx", "--test", "suite.ts"],
      ["--enable-source-maps", "--import", "tsx", "--test", "suite.ts"],
    ]) {
      assert.equal(validateKnockoutRegistry([{
        ...entry, andAlso: undefined, suite: [".", command, args],
      }]).size, 1);
    }
  }
});

test("required values and nested also edits use closed schemas too", () => {
  const [entry, companion] = registry();
  assert.throws(
    () => validateKnockoutRegistry([{ ...entry, replace: undefined }]),
    /invalid knockout entry "primary": replace must be a string/,
  );
  assert.throws(
    () => validateKnockoutRegistry([
      { ...entry, andAlso: undefined },
      { ...companion, also: [{ find: EXTRA, replace: "const extra = false;", typo: true }] },
    ]),
    /invalid knockout entry "companion": unknown also\[0\] key "typo"/,
  );
});

test("andAlso applies both mutations and hash-verifies restoration of both files", () => {
  const fixtureState = fixture();
  const { root, guard } = fixtureState;
  try {
    const entries = registry();
    const ev = runKnockout({
      root,
      entry: entries[0],
      registry: entries,
      baseline: baseline(root, entries[0].suite),
      timeoutMs: 60_000,
      guard,
    });

    assert.equal(ev.verdict, VERDICT.DETECTOR_TRIGGERED, ev.detail ?? "");
    assert.equal(ev.andAlso, "companion");
    assert.deepEqual(Object.keys(ev.hashBefore).sort(), ["companion.js", "primary.js"]);
    assert.deepEqual(Object.keys(ev.hashAfter).sort(), ["companion.js", "primary.js"]);
    assert.equal(ev.restored, true);
    assert.equal(fs.readFileSync(path.join(root, "primary.js"), "utf8"), `${PRIMARY}\n`);
    assert.equal(
      fs.readFileSync(path.join(root, "companion.js"), "utf8"),
      `${COMPANION}\n${EXTRA}\n`,
    );
  } finally {
    fixtureState.cleanup();
  }
});

test("the primary mutation alone stays green in the same fixture", () => {
  const fixtureState = fixture();
  const { root, guard } = fixtureState;
  try {
    const [entry] = registry();
    const lone = { ...entry };
    delete lone.andAlso;
    const ev = runKnockout({
      root,
      entry: lone,
      registry: [lone],
      baseline: baseline(root, lone.suite),
      timeoutMs: 60_000,
      guard,
    });
    assert.equal(ev.verdict, VERDICT.DETECTOR_DID_NOT_TRIGGER, ev.detail ?? "");
    assert.equal(ev.restored, true);
  } finally {
    fixtureState.cleanup();
  }
});

test("same-file paired mutations that cancel to pristine never run as a mutant", () => {
  const fixtureState = fixture();
  const { root, guard } = fixtureState;
  try {
    const suite: Suite = [".", process.execPath, ["--test", "suite.mjs"]];
    const first: Entry = {
      id: "first",
      control: "first half",
      file: "primary.js",
      find: PRIMARY,
      replace: "const primary = INTERMEDIATE;",
      andAlso: "second",
      kind: "tests",
      suite,
    };
    const second: Entry = {
      id: "second",
      control: "second half",
      file: "primary.js",
      find: "const primary = INTERMEDIATE;",
      replace: PRIMARY,
      kind: "tests",
      suite,
    };
    const ev = runKnockout({
      root,
      entry: first,
      registry: [first, second],
      baseline: baseline(root, suite),
      timeoutMs: 60_000,
      guard,
    });
    assert.equal(ev.verdict, VERDICT.MUTATION_NOT_APPLIED, ev.detail ?? "");
    assert.match(ev.detail ?? "", /pair cancelled itself/);
    assert.equal(ev.restored, true);
  } finally {
    fixtureState.cleanup();
  }
});

for (const scenario of [
  {
    id: "self-restored-bytes",
    mutationAction: `fs.writeFileSync(target, ${JSON.stringify(`${PRIMARY}\n`)});`,
    expectedDetail: /does not retain the exact expected bytes/,
  },
  {
    id: "replacement-inode",
    mutationAction: "fs.unlinkSync(target); fs.writeFileSync(target, source);",
    expectedDetail: /replaced by a different inode/,
  },
  {
    id: "new-hardlink",
    mutationAction: "fs.linkSync(target, new URL('./primary-alias.js', import.meta.url));",
    expectedDetail: /not the exact retained single-link inode/,
  },
] as const) {
  test(`a disposable mutant cannot keep detector credit after ${scenario.id}`, () => {
    const fixtureState = fixture();
    const { root, guard } = fixtureState;
    try {
      fs.writeFileSync(path.join(root, "retained-mutant-gate.mjs"), [
        'import fs from "node:fs";',
        'const target = new URL("./primary.js", import.meta.url);',
        'const source = fs.readFileSync(target, "utf8");',
        'const mutated = source.includes("const primary = false;");',
        `if (mutated) { ${scenario.mutationAction} }`,
        'const findings = mutated ? [{ rule: "MUTANT_DETECTED", subject: "primary", detail: "detected" }] : [];',
        'console.log(JSON.stringify({ protocol: "noa-gate-runner/1", event: "complete", gate: "retained-mutant-gate", findings }));',
        'process.exitCode = findings.length === 0 ? 0 : 1;',
      ].join("\n"));
      const suite: Suite = [".", process.execPath, ["retained-mutant-gate.mjs"]];
      const entry: Entry = {
        id: `retained-${scenario.id}`,
        control: "detector credit requires exact retained mutant state",
        file: "primary.js",
        find: PRIMARY,
        replace: "const primary = false;",
        kind: "gate",
        gateId: "retained-mutant-gate",
        expectedGateFindings: [{ rule: "MUTANT_DETECTED", subject: "primary" }],
        suite,
      };
      const clean = observeSuite(root, suite, 60_000, { kind: "gate" });
      assert.equal(clean.gateProtocolComplete, true, clean.gateProtocolError ?? clean.out);
      const ev = runKnockout({
        root,
        entry,
        registry: [entry],
        baseline: clean,
        timeoutMs: 60_000,
        guard,
        workspaceMode: "disposable",
      });
      assert.equal(ev.verdict, VERDICT.INVALID_TEST, ev.detail ?? "");
      assert.equal(ev.restored, false);
      assert.equal(ev.workspaceDisposition, "RETAINED_DISPOSABLE_ARM_DRIFTED");
      assert.match(ev.detail ?? "", scenario.expectedDetail);
    } finally {
      fixtureState.cleanup();
    }
  });
}

test("a committed disposable mutant survives release and a later guard start", () => {
  const fixtureState = fixture();
  const { root, cacheDir, guard } = fixtureState;
  let successor: Guard | null = null;
  try {
    fs.writeFileSync(path.join(root, "retained-mutant-gate.mjs"), [
      'import fs from "node:fs";',
      'const source = fs.readFileSync(new URL("./primary.js", import.meta.url), "utf8");',
      'const mutated = source.includes("const primary = false;");',
      'const findings = mutated ? [{ rule: "MUTANT_DETECTED", subject: "primary", detail: "detected" }] : [];',
      'console.log(JSON.stringify({ protocol: "noa-gate-runner/1", event: "complete", gate: "retained-mutant-gate", findings }));',
      'process.exitCode = findings.length === 0 ? 0 : 1;',
    ].join("\n"));
    const suite: Suite = [".", process.execPath, ["retained-mutant-gate.mjs"]];
    const entry: Entry = {
      id: "retained-commit",
      control: "retained recovery authority is closed only for exact mutant bytes",
      file: "primary.js",
      find: PRIMARY,
      replace: "const primary = false;",
      kind: "gate",
      gateId: "retained-mutant-gate",
      expectedGateFindings: [{ rule: "MUTANT_DETECTED", subject: "primary" }],
      suite,
    };
    const clean = observeSuite(root, suite, 60_000, { kind: "gate" });
    assert.equal(clean.gateProtocolComplete, true, clean.gateProtocolError ?? clean.out);
    const ev = runKnockout({
      root,
      entry,
      registry: [entry],
      baseline: clean,
      timeoutMs: 60_000,
      guard,
      workspaceMode: "disposable",
    });
    assert.equal(ev.verdict, VERDICT.DETECTOR_TRIGGERED, ev.detail ?? "");
    assert.equal(ev.workspaceDisposition, "RETAINED_DISPOSABLE_MUTANT");
    assert.match(fs.readFileSync(path.join(root, "primary.js"), "utf8"), /const primary = false;/);
    assert.equal(guard.release(), true, "the committed retained arm must release its exact lock");

    successor = createBuildStateGuard({ root, cacheDir });
    const restarted = successor.start();
    assert.equal(restarted.ok, true, JSON.stringify(restarted));
    assert.equal(restarted.recovered ?? null, null, "no dead-run recovery may remain after commit");
    assert.match(fs.readFileSync(path.join(root, "primary.js"), "utf8"), /const primary = false;/);
    assert.equal(successor.release(), true);
  } finally {
    successor?.release();
    fixtureState.cleanup();
  }
});

for (const mode of ["early-refusal", "retained-mutant", "observation-failure"] as const) {
  test(`mutation target descriptor cleanup remains visible after ${mode}`, () => {
    const fixtureState = fixture();
    const { root, guard } = fixtureState;
    const entries = registry();
    const clean = baseline(root, entries[0].suite);
    const originalOpen = fs.openSync;
    const originalClose = fs.closeSync;
    const closeFailure = new Error("injected identity descriptor close failure");
    const observationFailure = new Error("injected companion observation failure");
    let pinnedDescriptor: number | null = null;
    let closeInjected = false;
    try {
      fs.openSync = ((...args: Parameters<typeof fs.openSync>) => {
        if (mode === "observation-failure" && args[0] === path.join(root, "companion.js")) {
          throw observationFailure;
        }
        const fd = originalOpen(...args);
        if (pinnedDescriptor === null && args[0] === path.join(root, "primary.js")) {
          pinnedDescriptor = fd;
        }
        return fd;
      }) as typeof fs.openSync;
      fs.closeSync = (fd: number) => {
        originalClose(fd);
        if (fd === pinnedDescriptor && !closeInjected) {
          closeInjected = true;
          throw closeFailure;
        }
      };
      const entry = mode === "early-refusal"
        ? { ...entries[0], find: "NO_MATCH_FOR_THIS_CONTROL" }
        : entries[0];
      assert.throws(
        () => runKnockout({
          root,
          entry,
          registry: [entry, entries[1]],
          baseline: clean,
          timeoutMs: 60_000,
          guard,
          workspaceMode: "disposable",
        }),
        (error: unknown) => error instanceof AggregateError
          && error.message === "mutation-target identity descriptor cleanup failed"
          && error.errors.includes(closeFailure)
          && (mode !== "observation-failure" || error.errors.includes(observationFailure)),
      );
      assert.equal(closeInjected, true, "the retained identity descriptor close was not reached");
      assert.notEqual(pinnedDescriptor, null);
      assert.throws(() => fs.fstatSync(pinnedDescriptor!), { code: "EBADF" });
    } finally {
      fs.openSync = originalOpen;
      fs.closeSync = originalClose;
      fixtureState.cleanup();
    }
  });
}

test("restoration refuses to erase an unexpected edit made while the suite runs", () => {
  const fixtureState = fixture();
  const { root, cacheDir, guard } = fixtureState;
  try {
    fs.mkdirSync(path.join(root, "dist"));
    fs.writeFileSync(path.join(root, "dist", "derived.js"), "clean derived state\n");
    fs.writeFileSync(path.join(root, "concurrent-suite.mjs"), [
      'import fs from "node:fs";',
      'import test from "node:test";',
      'test("concurrent edit fixture", () => {',
      '  const target = new URL("./primary.js", import.meta.url);',
      '  const source = fs.readFileSync(target, "utf8");',
      '  if (source.includes("const primary = false;")) {',
      '    fs.writeFileSync(target, "concurrent edit\\n");',
      '    fs.writeFileSync(new URL("./dist/derived.js", import.meta.url), "mutant derived state\\n");',
      '    fs.writeFileSync(new URL("./dist/transient.js", import.meta.url), "mutant-only output\\n");',
      '  }',
      '});',
    ].join("\n"));
    const suite: Suite = [".", process.execPath, ["--test", "concurrent-suite.mjs"]];
    const entry: Entry = {
      id: "concurrent",
      control: "concurrent edit preservation",
      file: "primary.js",
      find: PRIMARY,
      replace: "const primary = false;",
      kind: "tests",
      suite,
    };
    const ev = runKnockout({
      root,
      entry,
      registry: [entry],
      baseline: baseline(root, suite),
      timeoutMs: 60_000,
      guard,
    });
    assert.equal(ev.verdict, VERDICT.RESTORATION_FAILED, ev.detail ?? "");
    assert.equal(ev.restored, false);
    assert.match(ev.detail ?? "", /refusing to overwrite a concurrent edit/);
    assert.equal(fs.readFileSync(path.join(root, "primary.js"), "utf8"), "concurrent edit\n");
    assert.equal(
      fs.readFileSync(path.join(root, "dist", "derived.js"), "utf8"),
      "clean derived state\n",
      "derived output was not restored while the concurrent source edit was preserved",
    );
    assert.equal(
      fs.existsSync(path.join(root, "dist", "transient.js")),
      false,
      "mutant-only derived output survived orderly cleanup",
    );
    const completedNonce = guard.ownerNonce;
    assert.notEqual(completedNonce, null);
    assert.equal(
      fs.existsSync(path.join(cacheDir, "runs", completedNonce!, "inflight.json")),
      false,
      "orderly cleanup retained a crash marker after safely preserving the user edit",
    );
    assert.equal(guard.release(), true, "the completed arm left derived-state recovery residue");
    const restarted = createBuildStateGuard({ root, cacheDir });
    assert.equal(restarted.start().ok, true, "a preserved user edit blocked the next orderly run");
    assert.equal(
      fs.readFileSync(path.join(root, "primary.js"), "utf8"),
      "concurrent edit\n",
      "restart erased the user edit that orderly cleanup preserved",
    );
    assert.equal(restarted.release(), true);
  } finally {
    fixtureState.cleanup();
  }
});

test("paired restoration preserves independent concurrent edits to every mutation target", () => {
  const fixtureState = fixture({ git: true });
  const { root, guard } = fixtureState;
  try {
    fs.writeFileSync(path.join(root, "concurrent-pair-suite.mjs"), [
      'import fs from "node:fs";',
      'import test from "node:test";',
      'test("paired concurrent edit fixture", () => {',
      '  const primary = new URL("./primary.js", import.meta.url);',
      '  const companion = new URL("./companion.js", import.meta.url);',
      '  if (fs.readFileSync(primary, "utf8").includes("const primary = false;")) {',
      '    fs.writeFileSync(primary, "user primary edit\\n");',
      '  }',
      '  const companionSource = fs.readFileSync(companion, "utf8");',
      '  if (companionSource.includes("const companion = false;") && companionSource.includes("const extra = false;")) {',
      '    fs.writeFileSync(companion, "user companion edit\\n");',
      '  }',
      '});',
    ].join("\n"));
    const suite: Suite = [".", process.execPath, ["--test", "concurrent-pair-suite.mjs"]];
    const entries = registry().map((entry) => ({ ...entry, suite })) as [Entry, Entry];
    const indexBefore = fs.readFileSync(path.join(root, ".git", "index"));
    const ev = runKnockout({
      root,
      entry: entries[0],
      registry: entries,
      baseline: baseline(root, suite),
      timeoutMs: 60_000,
      guard,
    });

    assert.equal(ev.verdict, VERDICT.RESTORATION_FAILED, ev.detail ?? "");
    assert.equal(ev.restored, false);
    assert.match(ev.detail ?? "", /primary\.js changed unexpectedly.*concurrent edit/);
    assert.match(ev.detail ?? "", /companion\.js changed unexpectedly.*concurrent edit/);
    assert.equal(fs.readFileSync(path.join(root, "primary.js"), "utf8"), "user primary edit\n");
    assert.equal(
      fs.readFileSync(path.join(root, "companion.js"), "utf8"),
      "user companion edit\n",
    );
    assert.deepEqual(
      fs.readFileSync(path.join(root, ".git", "index")),
      indexBefore,
      "preserving concurrent worktree bytes changed the exact Git index",
    );
    assert.equal(guard.release(), true, "paired orderly cleanup left derived-state recovery residue");
    const restarted = createBuildStateGuard({ root, cacheDir: guard.cacheDir });
    assert.equal(restarted.start().ok, true, "paired preserved edits blocked the next orderly run");
    assert.equal(restarted.release(), true);
  } finally {
    fixtureState.cleanup();
  }
});

test("derived hardlink cleanup cannot erase user bytes observed on a mutation target", () => {
  const fixtureState = fixture({ git: true });
  const { root, cacheDir, guard } = fixtureState;
  try {
    fs.mkdirSync(path.join(root, "dist"));
    fs.writeFileSync(path.join(root, "dist", "derived.js"), "clean derived state\n");
    fs.writeFileSync(path.join(root, "hardlink-suite.mjs"), [
      'import fs from "node:fs";',
      'import test from "node:test";',
      'test("runtime hardlink alias", () => {',
      '  const source = new URL("./primary.js", import.meta.url);',
      '  const derived = new URL("./dist/derived.js", import.meta.url);',
      '  if (fs.readFileSync(source, "utf8").includes("const primary = false;")) {',
      '    fs.unlinkSync(derived);',
      '    fs.linkSync(source, derived);',
      '    fs.writeFileSync(source, "user bytes that must survive\\n");',
      '  }',
      '});',
    ].join("\n"));
    const suite: Suite = [".", process.execPath, ["--test", "hardlink-suite.mjs"]];
    const entry: Entry = {
      id: "runtime-hardlink",
      control: "derived aliases cannot erase concurrent source bytes",
      file: "primary.js",
      find: PRIMARY,
      replace: "const primary = false;",
      kind: "tests",
      suite,
    };
    const indexBefore = fs.readFileSync(path.join(root, ".git", "index"));
    const ev = runKnockout({
      root,
      entry,
      registry: [entry],
      baseline: baseline(root, suite),
      timeoutMs: 60_000,
      guard,
    });

    assert.equal(ev.verdict, VERDICT.RESTORATION_FAILED, ev.detail ?? "");
    assert.equal(ev.restored, false);
    assert.equal(
      fs.readFileSync(path.join(root, "primary.js"), "utf8"),
      "user bytes that must survive\n",
    );
    assert.equal(
      fs.readFileSync(path.join(root, "dist", "derived.js"), "utf8"),
      "user bytes that must survive\n",
      "unsafe derived cleanup ran after the alias was created",
    );
    assert.deepEqual(fs.readFileSync(path.join(root, ".git", "index")), indexBefore);
    const nonce = guard.ownerNonce;
    assert.notEqual(nonce, null);
    assert.equal(fs.existsSync(path.join(cacheDir, "runs", nonce!, "inflight.json")), true);
    assert.equal(guard.release(), false, "unsafe cleanup cleared its durable recovery marker");
  } finally {
    fixtureState.cleanup();
  }
});

test("a pre-existing hardlink refuses the arm before any source byte is mutated", () => {
  const fixtureState = fixture({ git: true });
  const { root, cacheDir, guard } = fixtureState;
  try {
    fs.mkdirSync(path.join(root, "dist"));
    fs.linkSync(path.join(root, "primary.js"), path.join(root, "dist", "derived.js"));
    const [pairedEntry] = registry();
    const entry = { ...pairedEntry };
    delete entry.andAlso;
    const indexBefore = fs.readFileSync(path.join(root, ".git", "index"));
    const sourceBefore = fs.readFileSync(path.join(root, "primary.js"));
    const ev = runKnockout({
      root,
      entry,
      registry: [entry],
      baseline: baseline(root, entry.suite),
      timeoutMs: 60_000,
      guard,
    });

    assert.equal(ev.verdict, VERDICT.RESTORATION_FAILED, ev.detail ?? "");
    assert.match(ev.detail ?? "", /not a single-link regular file/);
    assert.deepEqual(fs.readFileSync(path.join(root, "primary.js")), sourceBefore);
    assert.deepEqual(fs.readFileSync(path.join(root, "dist", "derived.js")), sourceBefore);
    assert.deepEqual(fs.readFileSync(path.join(root, ".git", "index")), indexBefore);
    const nonce = guard.ownerNonce;
    assert.notEqual(nonce, null);
    assert.equal(
      fs.existsSync(path.join(cacheDir, "runs", nonce!, "inflight.json")),
      false,
      "a refused pre-arm mutation wrote a recovery marker",
    );
    assert.equal(guard.release(), true);
  } finally {
    fixtureState.cleanup();
  }
});

test("runtime aliases across two mutation targets preserve every user byte and the marker", () => {
  const fixtureState = fixture({ git: true });
  const { root, cacheDir, guard } = fixtureState;
  try {
    fs.mkdirSync(path.join(root, "dist"));
    fs.writeFileSync(path.join(root, "dist", "primary.js"), "clean primary output\n");
    fs.writeFileSync(path.join(root, "dist", "companion.js"), "clean companion output\n");
    fs.writeFileSync(path.join(root, "multi-hardlink-suite.mjs"), [
      'import fs from "node:fs";',
      'import test from "node:test";',
      'test("two runtime aliases", () => {',
      '  const primary = new URL("./primary.js", import.meta.url);',
      '  const companion = new URL("./companion.js", import.meta.url);',
      '  const primaryOut = new URL("./dist/primary.js", import.meta.url);',
      '  const companionOut = new URL("./dist/companion.js", import.meta.url);',
      '  if (fs.readFileSync(primary, "utf8").includes("const primary = false;")) {',
      '    fs.unlinkSync(primaryOut);',
      '    fs.unlinkSync(companionOut);',
      '    fs.linkSync(primary, primaryOut);',
      '    fs.linkSync(companion, companionOut);',
      '    fs.writeFileSync(primary, "user primary alias bytes\\n");',
      '    fs.writeFileSync(companion, "user companion alias bytes\\n");',
      '  }',
      '});',
    ].join("\n"));
    const suite: Suite = [".", process.execPath, ["--test", "multi-hardlink-suite.mjs"]];
    const entries = registry().map((entry) => ({ ...entry, suite })) as [Entry, Entry];
    const indexBefore = fs.readFileSync(path.join(root, ".git", "index"));
    const ev = runKnockout({
      root,
      entry: entries[0],
      registry: entries,
      baseline: baseline(root, suite),
      timeoutMs: 60_000,
      guard,
    });

    assert.equal(ev.verdict, VERDICT.RESTORATION_FAILED, ev.detail ?? "");
    assert.match(ev.detail ?? "", /primary\.js has 2 hardlinks/);
    assert.match(ev.detail ?? "", /companion\.js has 2 hardlinks/);
    assert.equal(fs.readFileSync(path.join(root, "primary.js"), "utf8"), "user primary alias bytes\n");
    assert.equal(fs.readFileSync(path.join(root, "companion.js"), "utf8"), "user companion alias bytes\n");
    assert.equal(fs.readFileSync(path.join(root, "dist", "primary.js"), "utf8"), "user primary alias bytes\n");
    assert.equal(fs.readFileSync(path.join(root, "dist", "companion.js"), "utf8"), "user companion alias bytes\n");
    assert.deepEqual(fs.readFileSync(path.join(root, ".git", "index")), indexBefore);
    const nonce = guard.ownerNonce;
    assert.notEqual(nonce, null);
    assert.equal(fs.existsSync(path.join(cacheDir, "runs", nonce!, "inflight.json")), true);
    assert.equal(guard.release(), false);
  } finally {
    fixtureState.cleanup();
  }
});

test("a source replaced by a symlink cannot redirect cleanup outside the repository", () => {
  const fixtureState = fixture({ git: true });
  const { root, cacheDir, guard } = fixtureState;
  const outside = path.join(os.tmpdir(), `ko-outside-${process.pid}-${Date.now()}.txt`);
  try {
    fs.writeFileSync(outside, "outside user bytes\n");
    fs.mkdirSync(path.join(root, "dist"));
    fs.writeFileSync(path.join(root, "dist", "derived.js"), "clean derived state\n");
    fs.writeFileSync(path.join(root, "symlink-suite.mjs"), [
      'import fs from "node:fs";',
      'import test from "node:test";',
      'test("source symlink replacement", () => {',
      '  const source = new URL("./primary.js", import.meta.url);',
      '  if (fs.readFileSync(source, "utf8").includes("const primary = false;")) {',
      '    fs.unlinkSync(source);',
      `    fs.symlinkSync(${JSON.stringify(outside)}, source);`,
      '    fs.writeFileSync(new URL("./dist/derived.js", import.meta.url), "mutant derived state\\n");',
      '  }',
      '});',
    ].join("\n"));
    const suite: Suite = [
      ".",
      process.execPath,
      ["--test", "symlink-suite.mjs"],
    ];
    const entry: Entry = {
      id: "runtime-symlink",
      control: "source symlinks cannot redirect cleanup",
      file: "primary.js",
      find: PRIMARY,
      replace: "const primary = false;",
      kind: "tests",
      suite,
    };
    const ev = runKnockout({
      root,
      entry,
      registry: [entry],
      baseline: baseline(root, suite),
      timeoutMs: 60_000,
      guard,
    });
    assert.equal(ev.verdict, VERDICT.RESTORATION_FAILED, ev.detail ?? "");
    assert.equal(fs.readFileSync(outside, "utf8"), "outside user bytes\n");
    assert.equal(fs.lstatSync(path.join(root, "primary.js")).isSymbolicLink(), true);
    assert.equal(fs.readFileSync(path.join(root, "dist", "derived.js"), "utf8"), "mutant derived state\n");
    const nonce = guard.ownerNonce;
    assert.notEqual(nonce, null);
    assert.equal(fs.existsSync(path.join(cacheDir, "runs", nonce!, "inflight.json")), true);
    assert.equal(guard.release(), false);
  } finally {
    fs.rmSync(outside, { force: true });
    fixtureState.cleanup();
  }
});

test("dead-run recovery preserves a runtime source hardlink and post-crash user bytes", () => {
  const fixtureState = fixture({ git: true });
  const { root, cacheDir } = fixtureState;
  try {
    fs.mkdirSync(path.join(root, "dist"));
    fs.writeFileSync(path.join(root, "dist", "derived.js"), "clean derived state\n");
    const indexBefore = fs.readFileSync(path.join(root, ".git", "index"));
    leaveCrashedArm(root, cacheDir, "hardlink-user");

    const restarted = createBuildStateGuard({ root, cacheDir });
    const start = restarted.start();
    assert.equal(start.ok, false);
    assert.equal(start.kind, "unrepaired");
    assert.equal(fs.readFileSync(path.join(root, "primary.js"), "utf8"), "post-crash user bytes must survive\n");
    assert.equal(fs.readFileSync(path.join(root, "dist", "derived.js"), "utf8"), "post-crash user bytes must survive\n");
    assert.deepEqual(fs.readFileSync(path.join(root, ".git", "index")), indexBefore);
    const lock = JSON.parse(fs.readFileSync(path.join(cacheDir, "lock.json"), "utf8"));
    assert.equal(fs.existsSync(path.join(lock.runDir, "inflight.json")), true);
    assert.equal(restarted.release(), false);
  } finally {
    fixtureState.cleanup();
  }
});

test("clean dead-run recovery leaves the raw Git index byte-identical after its final status", () => {
  const fixtureState = fixture({ git: true });
  const { root, cacheDir } = fixtureState;
  try {
    const indexPath = path.join(root, ".git", "index");
    const indexBefore = fs.readFileSync(indexPath);
    leaveCrashedArm(root, cacheDir, "mutant");
    assert.deepEqual(fs.readFileSync(indexPath), indexBefore, "the crashed arm changed the live index");

    const restarted = createBuildStateGuard({ root, cacheDir });
    const start = restarted.start();
    assert.equal(start.ok, true, JSON.stringify(start));
    assert.equal(fs.readFileSync(path.join(root, "primary.js"), "utf8"), `${PRIMARY}\n`);
    assert.deepEqual(
      fs.readFileSync(indexPath),
      indexBefore,
      "a read-only recovery Git inspection refreshed raw index stat-cache bytes",
    );
    assert.equal(start.recovered?.clean, true);
    assert.equal(restarted.release(), true);
  } finally {
    fixtureState.cleanup();
  }
});
