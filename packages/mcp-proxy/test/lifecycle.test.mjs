/**
 * lifecycle.test.mjs — the stdio proxy stops the downstream it started, through the REAL CLI (child
 * process, real stdio, a real SDK MCP server as the downstream: test/fixtures/lifecycle-downstream.mjs).
 *
 *   - the host closing stdin ends the proxy (exit 0) and its downstream;
 *   - SIGTERM, SIGINT and SIGHUP end the proxy (exit 128+n) and its downstream, including one that
 *     ignores stdin EOF and SIGTERM, so only SIGKILL stops it;
 *   - the downstream connection closing ends the proxy (exit 1);
 *   - a downstream that never answers MCP initialize ends the proxy at the documented 30 s bound
 *     (exit 1, one stderr line naming the bound), and the downstream is stopped.
 *
 * The downstream in the stop tests keeps running after its stdin closes (--stay-alive), so a test can
 * tell "the proxy stopped its child" from "the child left on its own". Every process these tests
 * signal is the proxy they spawned (through its ChildProcess handle) or that proxy's own child, whose
 * parent pid and per-test command-line tag are checked right before the signal.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { LATEST_PROTOCOL_VERSION } from "@modelcontextprotocol/sdk/types.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROXY_CLI = path.join(__dirname, "..", "src", "proxy.mjs");
const FIXTURE = path.join(__dirname, "fixtures", "lifecycle-downstream.mjs");
// The documented bound (README, and DOWNSTREAM_INITIALIZE_TIMEOUT_MS in src/proxy.mjs).
const INITIALIZE_TIMEOUT_MS = 30_000;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function waitUntil(predicate, ms) {
  const deadline = Date.now() + ms;
  for (;;) {
    if (predicate()) return true;
    if (Date.now() >= deadline) return false;
    await sleep(50);
  }
}

function ps(field, pid) {
  try {
    return execFileSync("ps", ["-o", `${field}=`, "-p", String(pid)], { encoding: "utf8" }).trim();
  } catch {
    return "";
  }
}

// Alive: the pid exists and is not a zombie waiting to be reaped.
function isAlive(pid) {
  try {
    process.kill(pid, 0);
  } catch (err) {
    if (err.code === "ESRCH") return false;
  }
  const stat = ps("stat", pid);
  return stat !== "" && !stat.startsWith("Z");
}

function startProxy(downstreamFlags) {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "noa-mcp-proxy-lifecycle-")));
  const pidFile = path.join(dir, "downstream.pid");
  const tag = `lifecycle-${randomUUID()}`;
  const proc = spawn(process.execPath, [PROXY_CLI, "--", process.execPath, FIXTURE, "--pid-file", pidFile, "--tag", tag, ...downstreamFlags], {
    stdio: ["pipe", "pipe", "pipe"],
  });
  const startedAt = Date.now();
  const pending = new Map();
  let stdoutBuffer = "";
  let stderr = "";
  proc.stdout.setEncoding("utf8");
  proc.stdout.on("data", (chunk) => {
    stdoutBuffer += chunk;
    for (let i = stdoutBuffer.indexOf("\n"); i !== -1; i = stdoutBuffer.indexOf("\n")) {
      const line = stdoutBuffer.slice(0, i);
      stdoutBuffer = stdoutBuffer.slice(i + 1);
      let message;
      try {
        message = JSON.parse(line);
      } catch {
        continue;
      }
      const settle = pending.get(message.id);
      if (settle) {
        pending.delete(message.id);
        settle(message);
      }
    }
  });
  proc.stderr.setEncoding("utf8");
  proc.stderr.on("data", (chunk) => {
    stderr += chunk;
  });
  proc.stdin.on("error", () => {}); // a write racing the proxy's exit (EPIPE) is not what these tests measure
  const exited = new Promise((resolve) => proc.once("exit", (code, signal) => resolve({ code, signal, at: Date.now() })));
  let nextId = 1;
  const request = (method, params) =>
    new Promise((resolve, reject) => {
      const id = nextId++;
      const timer = setTimeout(() => {
        pending.delete(id);
        reject(new Error(`no answer to ${method} within 15 s; proxy stderr:\n${stderr}`));
      }, 15_000);
      pending.set(id, (message) => {
        clearTimeout(timer);
        resolve(message);
      });
      proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
    });
  const notify = (method) => proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", method }) + "\n");
  return { proc, dir, pidFile, tag, startedAt, exited, request, notify, stderr: () => stderr };
}

// The pid of the downstream this proxy started, proved by its parent pid and this test's tag.
async function downstreamPid(p) {
  const written = await waitUntil(() => fs.existsSync(p.pidFile) && fs.readFileSync(p.pidFile, "utf8") !== "", 10_000);
  assert.ok(written, `the downstream never wrote its pid file; proxy stderr:\n${p.stderr()}`);
  const pid = Number(fs.readFileSync(p.pidFile, "utf8"));
  assert.equal(Number(ps("ppid", pid)), p.proc.pid, "the pid file must name the proxy's own child");
  assert.ok(ps("command", pid).includes(p.tag), "the pid file must name this test's downstream");
  return pid;
}

// A full MCP handshake through the proxy, ending with a live tools/list from the downstream.
async function handshake(p) {
  const init = await p.request("initialize", {
    protocolVersion: LATEST_PROTOCOL_VERSION,
    capabilities: {},
    clientInfo: { name: "lifecycle-test-host", version: "1.0.0" },
  });
  assert.ok(init.result, `initialize failed: ${JSON.stringify(init)}`);
  p.notify("notifications/initialized");
  const list = await p.request("tools/list", {});
  assert.deepEqual(list.result?.tools?.map((t) => t.name), ["echo"], "the downstream must be serving through the proxy");
  return downstreamPid(p);
}

function exitWithin(p, ms) {
  return Promise.race([p.exited, sleep(ms).then(() => null)]);
}

async function stopEverything(p, child) {
  if (p.proc.exitCode === null && p.proc.signalCode === null) p.proc.kill("SIGKILL");
  await p.exited;
  // Only this test's own downstream: its tag is checked right before the signal.
  if (child && isAlive(child) && ps("command", child).includes(p.tag)) process.kill(child, "SIGKILL");
  p.proc.stdin.destroy();
  p.proc.stdout.destroy();
  p.proc.stderr.destroy();
  fs.rmSync(p.dir, { recursive: true, force: true });
}

test("the host closing stdin stops the proxy (exit 0) and the downstream it started", async () => {
  const p = startProxy(["--stay-alive"]);
  let child;
  try {
    child = await handshake(p);
    p.proc.stdin.end();
    const result = await exitWithin(p, 10_000);
    assert.ok(result, `the proxy was still running 10 s after the host closed its stdin (downstream ${child} alive: ${isAlive(child)})`);
    assert.ok(await waitUntil(() => !isAlive(child), 3_000), `downstream ${child} was still alive after the proxy exited (parent pid now ${ps("ppid", child)})`);
    assert.equal(result.code, 0, `exit code ${result.code}, signal ${result.signal}; proxy stderr:\n${p.stderr()}`);
    assert.match(p.stderr(), /the host closed stdin; stopping the downstream and exiting/);
  } finally {
    await stopEverything(p, child);
  }
});

const SIGNAL_CASES = [
  ["SIGTERM", ["--stay-alive", "--ignore-sigterm"], ", including one that ignores stdin EOF and SIGTERM"],
  ["SIGINT", ["--stay-alive"], ""],
  ["SIGHUP", ["--stay-alive"], ""],
];
for (const [signal, flags, note] of SIGNAL_CASES) {
  const expectedCode = 128 + os.constants.signals[signal];
  test(`${signal} stops the proxy (exit ${expectedCode}) and the downstream it started${note}`, async () => {
    const p = startProxy(flags);
    let child;
    try {
      child = await handshake(p);
      p.proc.kill(signal);
      const result = await exitWithin(p, 12_000);
      assert.ok(result, `the proxy was still running 12 s after ${signal}`);
      assert.ok(await waitUntil(() => !isAlive(child), 3_000), `downstream ${child} was still alive after the proxy exited on ${signal} (parent pid now ${ps("ppid", child)})`);
      assert.equal(result.code, expectedCode, `exit code ${result.code}, signal ${result.signal}; proxy stderr:\n${p.stderr()}`);
      assert.match(p.stderr(), new RegExp(`received ${signal}; stopping the downstream and exiting`));
    } finally {
      await stopEverything(p, child);
    }
  });
}

test("the downstream connection closing stops the proxy (exit 1)", async () => {
  const p = startProxy(["--stay-alive"]);
  let child;
  try {
    child = await handshake(p);
    assert.ok(ps("command", child).includes(p.tag) && Number(ps("ppid", child)) === p.proc.pid, "about to signal a process that is not this test's downstream");
    process.kill(child, "SIGKILL");
    const result = await exitWithin(p, 10_000);
    assert.ok(result, "the proxy was still running 10 s after its downstream died");
    assert.equal(result.code, 1, `exit code ${result.code}, signal ${result.signal}; proxy stderr:\n${p.stderr()}`);
    assert.match(p.stderr(), /the downstream MCP connection closed; stopping \(fail closed\)/);
  } finally {
    await stopEverything(p, child);
  }
});

test(`a downstream that never answers MCP initialize: the proxy exits 1 at the ${INITIALIZE_TIMEOUT_MS / 1000} s bound and stops it`, async () => {
  const p = startProxy(["--never-answer"]);
  let child;
  try {
    child = await downstreamPid(p);
    const limit = INITIALIZE_TIMEOUT_MS + 10_000;
    const result = await exitWithin(p, p.startedAt + limit - Date.now());
    assert.ok(result, `the proxy was still running ${limit / 1000} s after it started a downstream that never answers initialize`);
    assert.ok(await waitUntil(() => !isAlive(child), 3_000), `downstream ${child} was still alive after the proxy gave up on it (parent pid now ${ps("ppid", child)})`);
    assert.equal(result.code, 1, `exit code ${result.code}, signal ${result.signal}; proxy stderr:\n${p.stderr()}`);
    assert.ok(result.at - p.startedAt >= INITIALIZE_TIMEOUT_MS - 1_000, `the proxy gave up after ${result.at - p.startedAt} ms, before the documented ${INITIALIZE_TIMEOUT_MS} ms`);
    const lines = p.stderr().split("\n").filter((l) => l.length > 0 && !l.includes("WARNING — no --policy given"));
    assert.deepEqual(lines, [`noa-mcp-proxy: fatal — the downstream did not answer MCP initialize within ${INITIALIZE_TIMEOUT_MS} ms; stopping it (fail closed, nothing was served)`]);
  } finally {
    await stopEverything(p, child);
  }
});
