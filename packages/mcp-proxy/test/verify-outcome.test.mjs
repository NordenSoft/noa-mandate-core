/**
 * verify-outcome.test.mjs — `noa-mcp-proxy verify-outcome <file> --keyring <file>`.
 *
 * The receipts are not hand-built: a REAL proxy run (child process, real stdio) writes them with
 * --outcome-log and its public key with --keyring-file, and the subcommand is run the way an npm
 * install runs it — through a `.bin` symlink. Tampered and malformed inputs are derived from that
 * genuine log. Exit codes: 0 VALID, 2 TAMPERED, 3 MALFORMED, 4 USAGE.
 */
import { test, before } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import path from "node:path";
import fs from "node:fs";
import os from "node:os";
import { spawnSync } from "node:child_process";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { generateKeyPair } from "noa-mcp-adapter-core";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROXY_CLI = path.join(__dirname, "..", "src", "proxy.mjs");
const DEMO_DOWNSTREAM = path.join(__dirname, "..", "src", "demo-downstream.mjs");

let dir;
let bin;
let outcomeLog;
let keyringFile;
let lines;

before(async () => {
  dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "noa-mcp-proxy-verify-outcome-")));
  // npm-style bin link: `node_modules/.bin/noa-mcp-proxy` -> the package's src/proxy.mjs.
  const binDir = path.join(dir, "node_modules", ".bin");
  fs.mkdirSync(binDir, { recursive: true });
  bin = path.join(binDir, "noa-mcp-proxy");
  fs.symlinkSync(PROXY_CLI, bin);

  outcomeLog = path.join(dir, "outcomes.jsonl");
  keyringFile = path.join(dir, "keyring.json");
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [PROXY_CLI, "--outcome-log", outcomeLog, "--keyring-file", keyringFile, "--", process.execPath, DEMO_DOWNSTREAM],
    stderr: "pipe",
  });
  const client = new Client({ name: "verify-outcome-test-host", version: "1.0.0" }, { capabilities: {} });
  await client.connect(transport);
  await client.callTool({ name: "echo", arguments: { text: "one" } });
  await client.callTool({ name: "read_data", arguments: { key: "a" } });
  await client.close();
  lines = fs.readFileSync(outcomeLog, "utf8").split("\n").filter((l) => l.length > 0);
  assert.equal(lines.length, 2, "the real proxy run must have written two outcome receipts");
});

function verify(args) {
  // Run through the symlink exactly as an installed CLI is run (node resolves the real file).
  return spawnSync(process.execPath, [bin, "verify-outcome", ...args], { encoding: "utf8", timeout: 30_000 });
}

function write(name, content) {
  const p = path.join(dir, name);
  fs.writeFileSync(p, content);
  return p;
}

test("verify-outcome: the genuine outcome log of a real proxy run is VALID (exit 0), one line per receipt", () => {
  const run = verify([outcomeLog, "--keyring", keyringFile]);
  assert.equal(run.status, 0, run.stdout + run.stderr);
  assert.match(run.stdout, /^VALID line 1 .*\(outcome success, decision /m);
  assert.match(run.stdout, /^VALID line 2 /m);
  assert.match(run.stdout, /^VALID: 2 valid, 0 tampered, 0 malformed$/m);
});

test("verify-outcome: a single receipt given as one JSON object is VALID too", () => {
  const p = write("one.json", JSON.stringify(JSON.parse(lines[0]), null, 2));
  assert.equal(verify([p, "--keyring", keyringFile]).status, 0);
});

test("verify-outcome: a receipt whose signed content was changed is TAMPERED (exit 2)", () => {
  const changed = JSON.parse(lines[1]);
  changed.outcome = { status: "error", error: "rewritten" };
  const p = write("tampered.jsonl", `${lines[0]}\n${JSON.stringify(changed)}\n`);
  const run = verify([p, "--keyring", keyringFile]);
  assert.equal(run.status, 2, run.stdout + run.stderr);
  assert.match(run.stdout, /^VALID line 1 /m);
  assert.match(run.stdout, /^TAMPERED line 2 .*signature mismatch/m);
});

test("verify-outcome: a genuine receipt checked against a keyring that does not hold its key is TAMPERED (exit 2), never VALID", () => {
  const other = generateKeyPair("verify-outcome-test:other");
  const k = write("other-keyring.json", JSON.stringify({ [other.kid]: other.publicKey }));
  const run = verify([outcomeLog, "--keyring", k]);
  assert.equal(run.status, 2, run.stdout + run.stderr);
  assert.match(run.stdout, /not in keyring/);
});

test("verify-outcome: a re-pointed decision binding is TAMPERED (exit 2)", () => {
  const changed = JSON.parse(lines[0]);
  changed.decision.hash = "sha256:" + "0".repeat(64);
  const p = write("repointed.jsonl", JSON.stringify(changed) + "\n");
  assert.equal(verify([p, "--keyring", keyringFile]).status, 2);
});

for (const [name, content] of [
  ["a line that is not JSON", () => `${lines[0]}\nnot json at all\n`],
  ["a decision receipt (wrong spec)", () => JSON.stringify({ ...JSON.parse(lines[0]), spec: "noa.receipt/0.1" }) + "\n"],
  ["a receipt with its signature removed", () => { const r = JSON.parse(lines[0]); delete r.sig; return JSON.stringify(r) + "\n"; }],
  ["an empty file (nothing verified is not VALID)", () => ""],
  ["blank lines only", () => "\n\n  \n"],
  ["a JSON array", () => `[${lines[0]}]`],
]) {
  test(`verify-outcome: ${name} is MALFORMED (exit 3)`, () => {
    const p = write(`malformed-${name.replace(/[^a-z]+/gi, "-")}.jsonl`, content());
    const run = verify([p, "--keyring", keyringFile]);
    assert.equal(run.status, 3, run.stdout + run.stderr);
    assert.match(run.stdout, /^MALFORMED: /m);
  });
}

test("verify-outcome: TAMPERED is reported ahead of MALFORMED when a file has both (exit 2)", () => {
  const changed = JSON.parse(lines[0]);
  changed.action.id = "transfer_funds";
  const p = write("both.jsonl", `${JSON.stringify(changed)}\nnot json\n`);
  assert.equal(verify([p, "--keyring", keyringFile]).status, 2);
});

test("verify-outcome: missing --keyring, an unreadable file or a keyring that is not an object is a USAGE error (exit 4)", () => {
  assert.equal(verify([outcomeLog]).status, 4);
  assert.equal(verify([path.join(dir, "nope.jsonl"), "--keyring", keyringFile]).status, 4);
  assert.equal(verify([outcomeLog, "--keyring", write("array-keyring.json", "[]")]).status, 4);
  assert.equal(verify([outcomeLog, "--keyring", write("bad-keyring.json", "{")]).status, 4);
  assert.equal(verify([outcomeLog, "--keyring", keyringFile, "--unknown"]).status, 4);
});

test("verify-outcome: a line with a DUPLICATE key is MALFORMED (exit 3) — the strict parser never picks the last one", () => {
  // Same genuine receipt, with a second "outcome" member a lenient JSON.parse would let win.
  const line = lines[0].replace(/\}$/, ',"outcome":{"status":"error","error":"second"}}');
  assert.notEqual(line, lines[0]);
  const p = write("duplicate-key.jsonl", line + "\n");
  const run = verify([p, "--keyring", keyringFile]);
  assert.equal(run.status, 3, run.stdout + run.stderr);
  assert.match(run.stdout, /^MALFORMED line 1: .*duplicate object key/m);
});

test("verify-outcome: the same decision's outcome twice (a replayed line) is TAMPERED (exit 2), not VALID", () => {
  const p = write("replayed.jsonl", `${lines[0]}\n${lines[1]}\n${lines[0]}\n`);
  const run = verify([p, "--keyring", keyringFile]);
  assert.equal(run.status, 2, run.stdout + run.stderr);
  assert.match(run.stdout, /^TAMPERED line 3 .*duplicate — the outcome of decision .* already appears on line 1$/m);
  assert.match(run.stdout, /^TAMPERED: 2 valid, 1 tampered, 0 malformed$/m);
});
