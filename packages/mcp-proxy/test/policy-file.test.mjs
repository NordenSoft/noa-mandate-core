/**
 * policy-file.test.mjs — `noa-mcp-proxy --policy <file.json>`, through the REAL CLI (child process,
 * real stdio, the bundled demo downstream as "the user's own server").
 *
 *   - a valid file governs the user's own tool exactly as written, and a tool the file does not
 *     name is denied (the downstream handler never runs — counted through NOA_DEMO_COUNTS_FILE);
 *   - an unreadable, unparsable or invalid file refuses to start, with a stable code, a one-line
 *     message naming the file, and no downstream ever spawned;
 *   - with no --policy the built-in demo policy is used AND stderr says so.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import path from "node:path";
import fs from "node:fs";
import os from "node:os";
import { spawnSync } from "node:child_process";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { runInitCli } from "../src/init.mjs";
import { STARTER_TOOL_NAMES } from "../src/policy.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROXY_CLI = path.join(__dirname, "..", "src", "proxy.mjs");
const DEMO_DOWNSTREAM = path.join(__dirname, "..", "src", "demo-downstream.mjs");
const DEMO_WARNING = /WARNING — no --policy given; using the built-in DEMO policy/;

function tmpDir() {
  return fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "noa-mcp-proxy-policy-test-")));
}

// The user's own policy: allow their tool `get_time` (the demo server's 4th tool, which the BUILT-IN
// demo policy denies), explicitly block `echo` (which the demo policy allows), and say nothing about
// `read_data` or `transfer_funds`.
const USER_POLICY = {
  spec: "noa.policy/0.2",
  id: "user-tools-v1",
  requiredPaths: ["action"],
  rules: [
    { id: "allow-get-time", when: { op: "eq", path: "action", value: "get_time" }, then: "ALLOW" },
    { id: "block-echo", when: { op: "eq", path: "action", value: "echo" }, then: "DENY" },
  ],
};

// The proxy starts its downstream with the MCP SDK's filtered default environment, so the demo
// server's test switches are handed to it on its own command line, through /usr/bin/env.
function downstream(countsFile) {
  return ["/usr/bin/env", "NOA_DEMO_EXTRA_TOOL=1", `NOA_DEMO_COUNTS_FILE=${countsFile}`, process.execPath, DEMO_DOWNSTREAM];
}

function writeFile(dir, name, content, mode = 0o600) {
  const p = path.join(dir, name);
  fs.writeFileSync(p, content, { mode });
  return p;
}

async function startProxy(args, countsFile) {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [PROXY_CLI, ...args, "--", ...downstream(countsFile)],
    stderr: "pipe",
  });
  const stderrChunks = [];
  transport.stderr?.on("data", (c) => stderrChunks.push(c));
  const client = new Client({ name: "policy-test-host", version: "1.0.0" }, { capabilities: {} });
  await client.connect(transport);
  return { client, stderr: () => Buffer.concat(stderrChunks).toString("utf8") };
}

async function outcome(promise) {
  try {
    const r = await promise;
    return r.isError ? "denied" : "ran";
  } catch {
    return "denied";
  }
}

function counts(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

test("--policy <valid file>: the user's own tool runs, a tool the file blocks or never names is denied and never reaches the downstream", async () => {
  const dir = tmpDir();
  const policyPath = writeFile(dir, "policy.json", JSON.stringify(USER_POLICY));
  const countsFile = path.join(dir, "counts.json");
  const { client, stderr } = await startProxy(["--policy", policyPath], countsFile);
  // Closed in `finally`: a failed assertion must not leave the proxy child keeping the run alive.
  try {
    assert.equal(await outcome(client.callTool({ name: "get_time", arguments: {} })), "ran");
    assert.equal(await outcome(client.callTool({ name: "echo", arguments: { text: "hi" } })), "denied");
    assert.equal(await outcome(client.callTool({ name: "read_data", arguments: { key: "a" } })), "denied");
    assert.equal(await outcome(client.callTool({ name: "transfer_funds", arguments: { amountMinor: 1, to: "x" } })), "denied");
  } finally {
    await client.close();
  }

  const c = counts(countsFile);
  assert.deepEqual({ get_time: c.get_time, echo: c.echo, read_data: c.read_data, transfer_funds: c.transfer_funds }, { get_time: 1, echo: 0, read_data: 0, transfer_funds: 0 });
  assert.doesNotMatch(stderr(), DEMO_WARNING, "a user-supplied policy must not print the demo warning");
});

test("no --policy: the built-in demo policy is used and stderr says so in one line", async () => {
  const dir = tmpDir();
  const countsFile = path.join(dir, "counts.json");
  const { client, stderr } = await startProxy([], countsFile);
  try {
    assert.equal(await outcome(client.callTool({ name: "echo", arguments: { text: "hi" } })), "ran");
    assert.equal(await outcome(client.callTool({ name: "get_time", arguments: {} })), "denied");
  } finally {
    await client.close();
  }
  const c = counts(countsFile);
  assert.deepEqual({ echo: c.echo, get_time: c.get_time }, { echo: 1, get_time: 0 });

  const warnings = stderr().split("\n").filter((l) => DEMO_WARNING.test(l));
  assert.equal(warnings.length, 1, `expected exactly one demo-policy warning line, got:\n${stderr()}`);
  assert.match(warnings[0], /mcp-proxy-demo-guard-v1/);
  assert.match(warnings[0], /Pass --policy <file\.json>/);
});

// Each refusal: exit 1, the stable code, the file named, ONE stderr line, no downstream spawned.
const REFUSALS = [
  { name: "missing file", code: "POLICY_UNREADABLE", make: (dir) => path.join(dir, "does-not-exist.json") },
  { name: "symlinked file", code: "POLICY_UNREADABLE", make: (dir) => { const real = writeFile(dir, "real.json", JSON.stringify(USER_POLICY)); const link = path.join(dir, "policy.json"); fs.symlinkSync(real, link); return link; } },
  { name: "group/other-writable file", code: "POLICY_UNREADABLE", make: (dir) => { const p = writeFile(dir, "policy.json", JSON.stringify(USER_POLICY)); fs.chmodSync(p, 0o666); return p; } },
  { name: "not JSON", code: "POLICY_UNPARSABLE", make: (dir) => writeFile(dir, "policy.json", "{ spec: noa.policy/0.2 ") },
  { name: "empty file", code: "POLICY_UNPARSABLE", make: (dir) => writeFile(dir, "policy.json", "") },
  { name: "JSON that is not a policy", code: "POLICY_INVALID", field: /policy\.spec/, make: (dir) => writeFile(dir, "policy.json", "{}") },
  { name: "invalid verdict", code: "POLICY_INVALID", field: /policy\.rules\[0\]\.then: must be exactly "ALLOW" or "DENY"/, make: (dir) => writeFile(dir, "policy.json", JSON.stringify({ ...USER_POLICY, rules: [{ ...USER_POLICY.rules[0], then: "MAYBE" }] })) },
  { name: "unknown key (closed grammar)", code: "POLICY_INVALID", field: /unknown key "comment"/, make: (dir) => writeFile(dir, "policy.json", JSON.stringify({ ...USER_POLICY, comment: "x" })) },
  { name: "duplicate key", code: "POLICY_INVALID", field: /duplicate object key 'id'/, make: (dir) => writeFile(dir, "policy.json", '{"spec":"noa.policy/0.2","id":"a","id":"b","requiredPaths":["action"],"rules":[]}') },
];

for (const r of REFUSALS) {
  test(`--policy refuses to start on a ${r.name} (${r.code}), before any downstream is spawned`, () => {
    const dir = tmpDir();
    const policyPath = r.make(dir);
    const countsFile = path.join(dir, "counts.json");
    const run = spawnSync(process.execPath, [PROXY_CLI, "--policy", policyPath, "--", ...downstream(countsFile)], {
      encoding: "utf8",
      input: "",
      timeout: 30_000,
    });
    assert.equal(run.status, 1, `expected exit 1, got ${run.status}; stderr: ${run.stderr}`);
    const lines = run.stderr.split("\n").filter((l) => l.length > 0);
    assert.equal(lines.length, 1, `expected ONE stderr line, got:\n${run.stderr}`);
    assert.ok(lines[0].includes(`[${r.code}]`), `expected code ${r.code} in: ${lines[0]}`);
    assert.ok(lines[0].includes(policyPath), `the message must name the file: ${lines[0]}`);
    if (r.field) assert.match(lines[0], r.field);
    assert.doesNotMatch(run.stderr, DEMO_WARNING, "a refused --policy must never fall back to the demo policy");
    assert.equal(fs.existsSync(countsFile), false, "the downstream must never have been spawned");
  });
}

test("--policy with no value, or given twice, is refused instead of falling back to the demo policy", () => {
  const dir = tmpDir();
  const policyPath = writeFile(dir, "policy.json", JSON.stringify(USER_POLICY));
  const countsFile = path.join(dir, "counts.json");
  for (const args of [["--policy"], ["--policy", ""], ["--policy", policyPath, "--policy", policyPath]]) {
    const run = spawnSync(process.execPath, [PROXY_CLI, ...args, "--", ...downstream(countsFile)], { encoding: "utf8", input: "", timeout: 30_000 });
    assert.equal(run.status, 1, `args ${JSON.stringify(args)}: expected exit 1, got ${run.status}`);
    assert.match(run.stderr, /\[POLICY_UNREADABLE\]/);
    assert.doesNotMatch(run.stderr, DEMO_WARNING);
    assert.equal(fs.existsSync(countsFile), false, "the downstream must never have been spawned");
  }
});

// ---------------------------------------------------------------------------------------------
// Policy and approval rules are checked AGAINST EACH OTHER. The reproduced defect: run init, rename
// the approval tool in policy.json only, start the proxy exactly as the README says — the renamed
// tool EXECUTED with no human asked and nothing on stderr. Every start below uses the README's own
// start command (step 3), with only the server command replaced by the demo server.
// ---------------------------------------------------------------------------------------------
const README = fs.readFileSync(path.join(__dirname, "..", "README.md"), "utf8");
const USE_YOUR_OWN = README.slice(README.indexOf("## Use your own tools"), README.indexOf("### Policy file format"));
const README_START_ARGS = (() => {
  const line = USE_YOUR_OWN.split("\n").map((l) => l.trim()).find((l) => l.startsWith("noa-mcp-proxy --policy "));
  assert.ok(line, "the README must carry a one-line start command");
  const words = line.split(" ").slice(1);
  assert.deepEqual(words.slice(-3), ["--", "node", "your-server.js"]);
  return words.slice(0, -3);
})();

function initInto(cwd, extra = []) {
  const silence = process.stdout.write;
  process.stdout.write = () => true;
  try {
    assert.equal(runInitCli(["--dir", path.join(cwd, "noa"), ...extra]), 0);
  } finally {
    process.stdout.write = silence;
  }
}

function renameIn(file, from, to) {
  fs.writeFileSync(file, fs.readFileSync(file, "utf8").replaceAll(`"${from}"`, `"${to}"`));
}

async function startAsReadme(cwd, countsFile, args = README_START_ARGS) {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [PROXY_CLI, ...args, "--", ...downstream(countsFile)],
    cwd,
    stderr: "pipe",
  });
  const stderrChunks = [];
  transport.stderr?.on("data", (c) => stderrChunks.push(c));
  const client = new Client({ name: "policy-approval-test-host", version: "1.0.0" }, { capabilities: {} });
  await client.connect(transport);
  return { client, stderr: () => Buffer.concat(stderrChunks).toString("utf8") };
}

function refusedAsReadme(cwd, countsFile, args = README_START_ARGS) {
  return spawnSync(process.execPath, [PROXY_CLI, ...args, "--", ...downstream(countsFile)], { cwd, encoding: "utf8", input: "", timeout: 30_000 });
}

for (const [where, file] of [["policy.json only", "policy.json"], ["approval-rules.json only", "approval-rules.json"]]) {
  test(`renaming the approval tool in ${where} is refused at startup (POLICY_APPROVAL_MISMATCH), never a silent forward`, () => {
    const cwd = tmpDir();
    initInto(cwd);
    renameIn(path.join(cwd, "noa", file), STARTER_TOOL_NAMES.needsApproval, "transfer_funds");
    const countsFile = path.join(cwd, "counts.json");
    const run = refusedAsReadme(cwd, countsFile);
    assert.equal(run.status, 1, `expected exit 1, got ${run.status}; stderr: ${run.stderr}`);
    const lines = run.stderr.split("\n").filter((l) => l.length > 0);
    assert.equal(lines.length, 1, `expected ONE stderr line, got:\n${run.stderr}`);
    assert.match(lines[0], /\[POLICY_APPROVAL_MISMATCH\] --approval-rules "noa\/approval-rules\.json": approval rule "my_payment_tool-needs-human" holds "(my_payment_tool|transfer_funds)"/);
    assert.equal(fs.existsSync(countsFile), false, "the downstream must never have been spawned");
  });
}

test("the approval tool named in BOTH files (init --approval-tool, or a hand edit of both) is HELD for a human, never forwarded", async () => {
  for (const viaFlag of [true, false]) {
    const cwd = tmpDir();
    if (viaFlag) initInto(cwd, ["--allow-tool", "echo", "--approval-tool", "transfer_funds", "--block-tool", "read_data"]);
    else {
      initInto(cwd);
      renameIn(path.join(cwd, "noa", "policy.json"), STARTER_TOOL_NAMES.needsApproval, "transfer_funds");
      renameIn(path.join(cwd, "noa", "approval-rules.json"), STARTER_TOOL_NAMES.needsApproval, "transfer_funds");
    }
    const countsFile = path.join(cwd, "counts.json");
    const { client, stderr } = await startAsReadme(cwd, countsFile);
    let held;
    try {
      held = await client.callTool({ name: "transfer_funds", arguments: { amountMinor: 1, to: "x" } }).then(() => null, (e) => e);
    } finally {
      await client.close();
    }
    assert.ok(held, `${viaFlag ? "init --approval-tool" : "hand edit"}: transfer_funds must be held, not forwarded`);
    assert.match(held.message, /held for human approval/);
    assert.ok(typeof held.data?.receiptId === "string" && held.data.receiptId.length > 0);
    assert.equal(JSON.parse(fs.readFileSync(countsFile, "utf8")).transfer_funds, 0, "the held tool must never have run");
    assert.doesNotMatch(stderr(), /WARNING/);
  }
});

test("--policy without --approval-rules starts, and says in ONE stderr line that no call will be held for a human", async () => {
  const cwd = tmpDir();
  initInto(cwd);
  const countsFile = path.join(cwd, "counts.json");
  const { client, stderr } = await startAsReadme(cwd, countsFile, ["--policy", "noa/policy.json"]);
  await client.close();
  const warnings = stderr().split("\n").filter((l) => l.includes("WARNING"));
  assert.deepEqual(warnings, ["noa-mcp-proxy: WARNING — --policy given without --approval-rules; no call will be held for human approval."]);
});

test("a POLICY_INVALID refusal prints EXACTLY the line the README shows", () => {
  const cwd = tmpDir();
  fs.mkdirSync(path.join(cwd, "noa"));
  writeFile(path.join(cwd, "noa"), "policy.json", JSON.stringify({ ...USER_POLICY, rules: [{ ...USER_POLICY.rules[0], then: "MAYBE" }] }));
  const shown = README.split("\n").find((l) => l.startsWith("noa-mcp-proxy: fatal — Error: [POLICY_INVALID]"));
  assert.ok(shown, "the README must show a POLICY_INVALID example line");
  const run = refusedAsReadme(cwd, path.join(cwd, "counts.json"), ["--policy", "noa/policy.json"]);
  assert.equal(run.status, 1);
  assert.equal(run.stderr.trimEnd(), shown);
});
