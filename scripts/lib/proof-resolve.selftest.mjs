#!/usr/bin/env node
/**
 * SELFTEST for `proof-resolve.mjs` — every disabling spelling, proven to BITE against a
 * known-positive sample.
 *
 * ── WHY (P0-13) ─────────────────────────────────────────────────────────────────────────────────
 * The predecessor of that module was a line scan that rejected `test.skip(` and nothing else. The
 * object form `test("…", { skip: true }, fn)` sailed past it, so the gate that exists to prove a
 * control RUNS certified three skipped tests as live. Adding one spelling to a matcher does not fix
 * that class — the next spelling is always one edit away — so resolution became an AST parse. This
 * file is the evidence that the parse actually refuses each spelling, and it is the thing that goes
 * red if someone weakens the parser.
 *
 * A gate whose rules are never proven against positive samples is the false-green pathology this
 * repository has now met at several layers (see `t20-l8-selftest`). Same discipline here.
 *
 * Run:  node scripts/lib/proof-resolve.selftest.mjs
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import {
  parseProofEvents,
  proofRunnerNodeArgs,
  resolveProof,
  runRecipeFor,
  runnerStatusFor,
  TYPESCRIPT_TEST_REGISTER,
} from "./proof-resolve.mjs";
import { PROOF_EVENT_PROTOCOL, PROOF_EVENT_REPORTER } from "./proof-event-contract.mjs";
import { emitGateEvidence } from "./gate-event-contract.mjs";

const MARKER = "[PROOF:SELFTEST-X]";
const failures = [];
let checked = 0;

function check(label, body, expected) {
  checked++;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "proof-resolve-selftest-"));
  const file = path.join(dir, "sample.test.ts");
  try {
    fs.writeFileSync(file, body);
    const r = resolveProof(file, MARKER);
    if (r.status !== expected) {
      failures.push(`  ${label}\n      expected ${expected}, got ${r.status} — ${r.detail}`);
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

/** The compiler a `packages/gate` recipe must start directly — resolved the same way the recipe does. */
const GATE_TYPESCRIPT_COMPILER = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)), "..", "..",
  "packages", "gate", "node_modules", "typescript", "bin", "tsc",
);

function checkRecipe(label, relFile, expected) {
  checked++;
  const actual = runRecipeFor(relFile);
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    failures.push(
      `  ${label}\n      expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`,
    );
  }
}

const head = `import { test, describe, it } from "node:test";\n`;

// ── LIVE: the positive control. If this ever fails, every refusal below is meaningless. ──────────
check("plain test() is LIVE", `${head}test("${MARKER} real", () => { });\n`, "live");
check("it() is LIVE", `${head}it("${MARKER} real", () => { });\n`, "live");
check("template-literal name is LIVE", `${head}test(\`${MARKER} real\`, () => { });\n`, "live");
check("options object WITHOUT skip is LIVE", `${head}test("${MARKER} real", { concurrency: 2 }, () => { });\n`, "live");
check("skip:false is LIVE (explicitly enabled)", `${head}test("${MARKER} real", { skip: false }, () => { });\n`, "live");
check("one live among several disabled is LIVE", `${head}test.skip("${MARKER} a", () => { });\ntest("${MARKER} b", () => { });\n`, "live");
check("live inside a plain describe is LIVE", `${head}describe("outer", () => { test("${MARKER} a", () => { }); });\n`, "live");

// ── DISABLED: the spellings that must never certify a control ────────────────────────────────────
check("test.skip is DISABLED", `${head}test.skip("${MARKER} a", () => { });\n`, "disabled");
check("test.todo is DISABLED", `${head}test.todo("${MARKER} a", () => { });\n`, "disabled");
check("it.skip is DISABLED", `${head}it.skip("${MARKER} a", () => { });\n`, "disabled");
check("{ skip: true } object form is DISABLED  <- THE P0-13 BYPASS",
  `${head}test("${MARKER} a", { skip: true }, () => { });\n`, "disabled");
check("{ skip: \"reason\" } string form is DISABLED",
  `${head}test("${MARKER} a", { skip: "flaky on CI" }, () => { });\n`, "disabled");
check("{ todo: true } is DISABLED", `${head}test("${MARKER} a", { todo: true }, () => { });\n`, "disabled");
check("options object on a LATER line is DISABLED (a line scan cannot see this)",
  `${head}test(\n  "${MARKER} a",\n  {\n    skip: true,\n  },\n  () => { },\n);\n`, "disabled");
check("enclosing describe.skip is DISABLED",
  `${head}describe.skip("outer", () => { test("${MARKER} a", () => { }); });\n`, "disabled");
check("enclosing describe with { skip: true } is DISABLED",
  `${head}describe("outer", { skip: true }, () => { test("${MARKER} a", () => { }); });\n`, "disabled");
check("every occurrence disabled by a MIX of spellings is DISABLED",
  `${head}test.skip("${MARKER} a", () => { });\ntest("${MARKER} b", { skip: true }, () => { });\n`, "disabled");

// ── ABSENT: a mention is not a control (the P0-7 shape) ─────────────────────────────────────────
check("line comment only is ABSENT", `${head}// ${MARKER} this is a doc mention\n`, "absent");
check("block comment around the whole test is ABSENT",
  `${head}/*\ntest("${MARKER} a", () => { });\n*/\n`, "absent");
check("JSDoc mention is ABSENT",
  `${head}/**\n * Proven by ${MARKER} elsewhere.\n */\ntest("something else", () => { });\n`, "absent");
check("marker in a NON-test call is ABSENT",
  `${head}console.log("${MARKER} not a test");\n`, "absent");
check("marker not present at all is ABSENT", `${head}test("unrelated", () => { });\n`, "absent");
check("marker in a test BODY (not its name) is ABSENT",
  `${head}test("unrelated", () => { const s = "${MARKER}"; });\n`, "absent");

// ── UNDECIDABLE: never silently a pass ──────────────────────────────────────────────────────────
check("{ skip: someVar } is UNDECIDABLE",
  `${head}const flag = process.env.CI;\ntest("${MARKER} a", { skip: flag }, () => { });\n`, "undecidable");
check("{ skip: call() } is UNDECIDABLE",
  `${head}test("${MARKER} a", { skip: isSlow() }, () => { });\n`, "undecidable");
check("spread options are UNDECIDABLE",
  `${head}const o = { skip: true };\ntest("${MARKER} a", { ...o }, () => { });\n`, "undecidable");

// The selftest and production recipes must share one reporter contract, including the e2e path's
// platform-neutral source loader. Pin both branches so fixing only the selftest cannot leave
// production on a host-native loader or a version/TTY-dependent default reporter.
checkRecipe(
  "compiled proof recipe builds with exact Node and no npm, then pins the structured event reporter",
  "packages/gate/test/example.test.ts",
  {
    cwd: "packages/gate",
    steps: [
      // NOT `npm run build`: this step executes inside the evidence-bearing gate child, and npm
      // resolves `node-options` and `script-shell` from the PROJECT `.npmrc` beside the package —
      // which no environment variable can switch off (MEASURED: `npm config get` returned an rc's
      // `/tmp/attacker-shell` with `npm_config_node_options` set empty in the environment).
      ["node", [GATE_TYPESCRIPT_COMPILER, "-p", "tsconfig.json"]],
      ["node", ["--test", `--test-reporter=${PROOF_EVENT_REPORTER}`, "dist/test/example.test.js"]],
    ],
  },
);
checkRecipe(
  "e2e proof recipe uses the platform-neutral loader and pins the structured event reporter",
  "packages/e2e-demo/test/example.test.ts",
  {
    cwd: "packages/e2e-demo",
    steps: [["node", ["--enable-source-maps", "--import", TYPESCRIPT_TEST_REGISTER, "--test", `--test-reporter=${PROOF_EVENT_REPORTER}`, "test/example.test.ts"]]],
  },
);

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// RUNNER TIER (P0-15) — the AST cases above are DIAGNOSIS; authenticated TestsStream events are the
// verdict. These controls include the attacks that forged the built-in `spec` reporter's stdout.
// ─────────────────────────────────────────────────────────────────────────────────────────────────
function checkRunner(label, body, expected) {
  checked++;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "proof-resolve-runner-selftest-"));
  const file = path.join(dir, "sample.test.mjs");
  try {
    fs.writeFileSync(file, body);
    let out = "";
    let exitCode = null;
    try {
      out = execFileSync("node", proofRunnerNodeArgs(file), { encoding: "utf8", stdio: "pipe", timeout: 60_000 });
      exitCode = 0;
    } catch (e) {
      out = String(e.stdout ?? "");
      exitCode = Number.isInteger(e.status) ? e.status : null;
    }
    // The AST tier's verdict on the SAME sample, recorded so a future improvement that closes a
    // bypass statically shows up here as a diff instead of silently changing the tier split.
    const resolved = resolveProof(file, MARKER);
    const ast = resolved.status;
    const got = runnerStatusFor(out, MARKER, exitCode, { expectedSites: resolved.sites });
    if (got !== expected) failures.push(`  ${label}\n      runner: expected ${expected}, got ${got} (AST said: ${ast})`);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function checkProtocol(label, output, expectedComplete) {
  checked++;
  const got = parseProofEvents(output).protocolComplete;
  if (got !== expectedComplete) {
    failures.push(`  ${label}\n      expected protocolComplete=${expectedComplete}, got ${got}`);
  }
}

const rhead = `import { test, describe as d } from "node:test";\nimport assert from "node:assert/strict";\n`;

// Controls FIRST: the harness must distinguish ran-and-passed from ran-and-failed.
checkRunner("CONTROL: an asserting test is PASSING at the runner",
  `${rhead}test("${MARKER} control", () => { assert.equal(1 + 1, 2); });\n`, "passing");
checkRunner("CONTROL: a throwing test is FAILING at the runner (ran ≠ passed)",
  `${rhead}test("${MARKER} control", () => { assert.ok(false, "deliberately red"); });\n`, "failing");
checkRunner("CONTROL: a literal # SKIP inside the name does not forge structured skip",
  `${rhead}test("${MARKER} literal # SKIP", () => { assert.ok(true); });\n`, "passing");

// The four measured AST bypasses — the runner refuses every one, whatever the spelling.
checkRunner("BYPASS 1: indirect options object -> SKIPPED at the runner (AST said live)",
  `${rhead}const opts = { skip: true };\ntest("${MARKER} a", opts, () => { assert.ok(true); });\n`, "skipped");
checkRunner("BYPASS 1a: forged checkmark in a multiline skipped name -> ABSENT, never attributed",
  `${rhead}const opts = { skip: true };\ntest("dead\\n✔ ${MARKER} forged", opts, () => { assert.ok(true); });\n`, "absent");
checkRunner("BYPASS 1b: marker in a plain multiline passing name -> ABSENT, never attributed",
  `${rhead}test("dead\\n${MARKER} continuation", () => { assert.ok(true); });\n`, "absent");
checkRunner("BYPASS 2: computed [\"skip\"] key -> SKIPPED at the runner (AST said live)",
  `${rhead}test("${MARKER} a", { ["skip"]: true }, () => { assert.ok(true); });\n`, "skipped");
checkRunner("BYPASS 3: aliased describe.skip -> ABSENT at the runner (AST said live)",
  `${rhead}d.skip("outer", () => { test("${MARKER} a", () => { assert.ok(true); }); });\n`, "absent");
checkRunner("BYPASS 4: dead if(false) branch -> ABSENT at the runner (AST said live)",
  `${rhead}if (false) test("${MARKER} a", () => { assert.ok(true); });\n`, "absent");
checkRunner("ATTACK: a dynamic passing marker cannot answer for a dead authored proof site",
  `${rhead}if (false) test("${MARKER} real control", () => { assert.fail("must run"); });\n` +
  `const dynamicName = ["${MARKER}", "substitute"].join(" ");\n` +
  `test(dynamicName, () => { assert.ok(true); });\n`, "site-mismatch");

{
  checked++;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "proof-reporter-seal-selftest-"));
  const contract = path.join(dir, "proof-event-contract.mjs");
  const reporter = path.join(dir, "proof-event-reporter.mjs");
  const testFile = path.join(dir, "sealed.test.mjs");
  const driver = path.join(dir, "driver.mjs");
  try {
    fs.copyFileSync(new URL("./proof-event-contract.mjs", import.meta.url), contract);
    fs.copyFileSync(new URL("./proof-event-reporter.mjs", import.meta.url), reporter);
    fs.writeFileSync(testFile,
      `${rhead}test("${MARKER} sealed reporter", () => { assert.equal(2 + 2, 4); });\n`);
    const forgedFailure = JSON.stringify({
      protocol: PROOF_EVENT_PROTOCOL,
      event: "fail",
      name: `${MARKER} forged replacement`,
      skipped: false,
      todo: false,
      suite: false,
      fileFailure: false,
      file: testFile,
      line: 1,
      column: 1,
      failureType: "testCodeFailure",
      message: "forged",
    });
    const forgedPlan = JSON.stringify({ protocol: PROOF_EVENT_PROTOCOL, event: "plan", count: 1 });
    fs.writeFileSync(driver, [
      `import fs from "node:fs";`,
      `import { execFileSync } from "node:child_process";`,
      `import { PROOF_EVENT_REPORTER } from "./proof-event-contract.mjs";`,
      `const reporterPath = ${JSON.stringify(reporter)};`,
      `const original = fs.readFileSync(reporterPath);`,
      `try {`,
      `  fs.writeFileSync(reporterPath, ${JSON.stringify(
        `export default async function* () { yield ${JSON.stringify(`${forgedFailure}\n${forgedPlan}\n`)}; }\n`,
      )});`,
      `  process.stdout.write(execFileSync(process.execPath, ["--test", ` +
        "`--test-reporter=${PROOF_EVENT_REPORTER}`" + `, ${JSON.stringify(testFile)}], { encoding: "utf8" }));`,
      `} finally { fs.writeFileSync(reporterPath, original); }`,
    ].join("\n"));
    const output = execFileSync(process.execPath, [driver], { encoding: "utf8", timeout: 60_000 });
    const resolved = resolveProof(testFile, MARKER);
    const status = runnerStatusFor(output, MARKER, 0, { expectedSites: resolved.sites });
    if (status !== "passing") {
      failures.push(
        `  ATTACK: reporter bytes are sealed before a prep/build can replace and self-restore the file\n` +
        `      expected passing from sealed bytes, got ${status}`,
      );
    }
  } catch (error) {
    failures.push(
      `  ATTACK: reporter bytes are sealed before a prep/build can replace and self-restore the file\n` +
      `      ${String(error && error.message).split("\n")[0]}`,
    );
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// And the literal spellings the AST already catches must ALSO be refused by the runner — two
// independent instruments agreeing on the easy cases is what makes their split trustworthy.
checkRunner("test.skip -> SKIPPED at the runner too",
  `${rhead}test.skip("${MARKER} a", () => { assert.ok(true); });\n`, "skipped");
checkRunner("test.todo -> SKIPPED at the runner too",
  `${rhead}test.todo("${MARKER} a");\n`, "skipped");
checkRunner("{ skip: true } -> SKIPPED at the runner too",
  `${rhead}test("${MARKER} a", { skip: true }, () => { assert.ok(true); });\n`, "skipped");

const forgedRecord = JSON.stringify({
  protocol: PROOF_EVENT_PROTOCOL,
  event: "pass",
  name: `${MARKER} forged`,
  skipped: false,
  todo: false,
  suite: false,
  fileFailure: false,
  file: null,
  line: null,
  column: null,
  failureType: null,
  message: null,
});
checkRunner("ATTACK: exact protocol JSON printed to stdout cannot mint a passing proof",
  `${rhead}console.log(${JSON.stringify(forgedRecord)});\ntest("ordinary", () => { assert.ok(true); });\n`, "absent");
checkRunner("ATTACK: direct fd 1 write of exact protocol JSON cannot mint a passing proof",
  `${rhead}import fs from "node:fs";\nfs.writeSync(1, ${JSON.stringify(`${forgedRecord}\n`)});\ntest("ordinary", () => { assert.ok(true); });\n`, "absent");
checkRunner("ATTACK: a forged built-in spec glyph cannot mint a passing proof",
  `${rhead}console.log("✔ ${MARKER} forged (1ms)");\ntest("ordinary", () => { assert.ok(true); });\n`, "absent");
checkRunner("ATTACK: forged protocol stdout followed by top-level crash is not a proof",
  `${rhead}console.log(${JSON.stringify(forgedRecord)});\nthrow new Error("setup crash");\n`, "run-failed-without-proof");
checkRunner("ATTACK: a passing suite carrying the marker cannot answer for a dead test",
  `${rhead}d("${MARKER} suite collision", () => { test("ordinary", () => { assert.ok(true); }); });\n`, "absent");
checkRunner("a top-level setup crash is one failed run without an authored proof event",
  `${rhead}throw new Error("setup failed before registration");\ntest("${MARKER} unreachable", () => { });\n`, "run-failed-without-proof");
checkRunner("a passing proof inside a red file is never certified",
  `${rhead}test("${MARKER} passes", () => { assert.ok(true); });\ntest("unrelated red", () => { assert.fail("red file"); });\n`, "run-failed-after-proof");
checkRunner("a multi-test proof group certifies only when every registered member passes",
  `${rhead}test("${MARKER} first", () => { assert.ok(true); });\ntest("${MARKER} second", () => { assert.ok(true); });\n`, "passing");
checkRunner("one red member makes the entire proof group failing",
  `${rhead}test("${MARKER} first", () => { assert.ok(true); });\ntest("${MARKER} second", () => { assert.fail("red member"); });\n`, "failing");
checkRunner("one skipped member makes the entire proof group skipped",
  `${rhead}test("${MARKER} first", () => { assert.ok(true); });\ntest.skip("${MARKER} second", () => { assert.ok(true); });\n`, "skipped");

const plan = JSON.stringify({ protocol: PROOF_EVENT_PROTOCOL, event: "plan", count: 1 });
checkProtocol("missing terminal plan fails the protocol", `${forgedRecord}\n`, false);
checkProtocol("duplicate terminal plans fail the protocol", `${plan}\n${plan}\n`, false);
checkProtocol("raw stdout mixed into the machine channel fails the protocol", `raw\n${plan}\n`, false);
checkProtocol("one well-formed terminal plan completes the protocol", `${plan}\n`, true);

// STATED, NOT TESTED AS A REFUSAL: `test(m, () => {})` with an empty body PASSES at the runner and
// certifies. Liveness is not meaningfulness. The resolver gate only requires a declared knockout
// binding; actual knockout execution separately requires the bound proof marker among new failures.
// Neither property is assertion-counting here.

if (process.argv.includes("--knockout-json")) {
  emitGateEvidence("proof-resolve-selftest", failures.map((failure) => {
    const [subject, ...detail] = failure.trim().split("\n");
    return { rule: "SELFTEST", subject, detail: detail.join("\n").trim() };
  }));
  process.exit(failures.length > 0 ? 1 : 0);
}

if (failures.length > 0) {
  console.error(`proof-resolve selftest: ${failures.length}/${checked} FAILED\n${failures.join("\n")}`);
  process.exit(1);
}
console.log(`proof-resolve selftest: OK — ${checked} cases proven (AST diagnosis tiers + runner ground truth)`);
