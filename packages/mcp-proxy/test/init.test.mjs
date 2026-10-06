/**
 * init.test.mjs — `noa-mcp-proxy init` (src/init.mjs): the scaffolding command that generates the
 * starter --policy (policy.json) and the human-approval gate's inputs (approval-rules.json,
 * pending-store.jsonl, approver-key.json, approver-keyring.json).
 *
 * Three things this covers, matched to the task's evidence gate:
 *   1. generated-file shape — each of the five files is exactly what proxy.mjs/noa-approve expect.
 *   2. the refuse-to-overwrite path — a second `init` in the same directory writes NOTHING and
 *      exits non-zero unless --force is given, in which case it regenerates (including a genuinely
 *      NEW approver identity, not a silent no-op).
 *   3. the generated config actually starts the REAL proxy.mjs CLI with the gate ON — a real child
 *      process, real stdio, exactly the pattern test/smoke.mjs's "Bonus F" uses for the literal
 *      host-config path, not an in-process stand-in.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import path from "node:path";
import fs from "node:fs";
import os from "node:os";
import { execFileSync, spawnSync } from "node:child_process";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { runInitCli, mintApproverIdentityExclusive, createFileExclusive } from "../src/init.mjs";
import { starterPolicy, starterApprovalRules, STARTER_TOOL_NAMES } from "../src/policy.mjs";
import { generateKeyPair, assertValidPolicy } from "noa-mcp-adapter-core";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROXY_CLI = path.join(__dirname, "..", "src", "proxy.mjs");
const DEMO_DOWNSTREAM = path.join(__dirname, "..", "src", "demo-downstream.mjs");

function tmpDir() {
  // realpathSync: os.tmpdir() sits behind macOS's own /var -> /private/var symlink, which has
  // nothing to do with the ancestor-symlink VULNERABILITY (HIGH 4) init.mjs now refuses on — it is
  // the OS's own baseline layout, present for every process regardless of --dir. Resolving here
  // once keeps every OTHER test's tmpDir() free of that unrelated OS-level symlink, so only tests
  // that deliberately plant a symlink INSIDE the tree exercise the new guard.
  return fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "noa-mcp-proxy-init-test-")));
}

async function expectDeny(promise) {
  try {
    await promise;
    return { denied: false };
  } catch (err) {
    return { denied: true, code: err.code, data: err.data };
  }
}

test("init writes all five generated files with the shape proxy.mjs/noa-approve expect", () => {
  const dir = tmpDir();
  const exitCode = runInitCli(["--dir", dir]);
  assert.equal(exitCode, 0);

  const policyPath = path.join(dir, "policy.json");
  const rulesPath = path.join(dir, "approval-rules.json");
  const pendingStorePath = path.join(dir, "pending-store.jsonl");
  const approverKeyPath = path.join(dir, "approver-key.json");
  const approverKeyringPath = path.join(dir, "approver-keyring.json");
  for (const p of [policyPath, rulesPath, pendingStorePath, approverKeyPath, approverKeyringPath]) {
    assert.ok(fs.existsSync(p), `expected ${p} to exist`);
  }

  // policy.json — the starter --policy: a valid noa.policy/0.2 document under the kernel's own
  // validator, with one ALLOW, one ALLOW-held-for-approval and one DENY placeholder tool.
  const policyText = fs.readFileSync(policyPath, "utf8");
  assert.deepEqual(JSON.parse(policyText), starterPolicy());
  assert.doesNotThrow(() => assertValidPolicy(policyText));
  const verdicts = Object.fromEntries(starterPolicy().rules.map((r) => [r.when.value, r.then]));
  assert.deepEqual(verdicts, { [STARTER_TOOL_NAMES.allowed]: "ALLOW", [STARTER_TOOL_NAMES.needsApproval]: "ALLOW", [STARTER_TOOL_NAMES.blocked]: "DENY" });

  // approval-rules.json — the demo rule (Scenario R's own) plus a rule holding every call of the
  // starter policy's approval tool, as a JSON ARRAY (the shape matchApprovalRule/
  // validateApprovalRules expect for --approval-rules, not an object).
  const rules = JSON.parse(fs.readFileSync(rulesPath, "utf8"));
  assert.deepEqual(rules, starterApprovalRules());
  assert.ok(rules.some((r) => r.match.action === STARTER_TOOL_NAMES.needsApproval && r.threshold === undefined), "the approval tool must be held on every call");
  assert.ok(Array.isArray(rules));

  // pending-store.jsonl — empty (loadPendingIndex folds "missing" and "empty" identically; this is
  // a real, inspectable starting point rather than a dangling path).
  assert.equal(fs.readFileSync(pendingStorePath, "utf8"), "");

  // approver-key.json — mode 0600 (private key material), and the { kid, privateKey, publicKey }
  // shape loadOrCreateKeyFile's own loader requires.
  //
  // Read through ONE descriptor: `fstat` the handle and read from that same handle, never
  // `stat(path)` then `read(path)`. The mode and the bytes then provably describe the same file.
  // This test's whole subject is that `init` refuses check-then-use, so asserting it through a
  // check-then-use of its own would measure the property with an instrument that lacks it.
  const keyFd = fs.openSync(approverKeyPath, "r");
  let key;
  try {
    const keyStat = fs.fstatSync(keyFd);
    assert.equal(keyStat.mode & 0o777, 0o600, `expected approver-key.json mode 0600, got 0${(keyStat.mode & 0o777).toString(8)}`);
    key = JSON.parse(fs.readFileSync(keyFd, "utf8"));
  } finally {
    fs.closeSync(keyFd);
  }
  assert.equal(typeof key.kid, "string");
  assert.equal(typeof key.privateKey, "string");
  assert.equal(typeof key.publicKey, "string");

  // approver-keyring.json — the PUBLIC { [kid]: publicKey } derived from the SAME identity, world-
  // readable (it carries no secret), and containing EXACTLY that one key.
  const keyring = JSON.parse(fs.readFileSync(approverKeyringPath, "utf8"));
  assert.deepEqual(Object.keys(keyring), [key.kid]);
  assert.equal(keyring[key.kid], key.publicKey);
});

test("init refuses to overwrite an existing scaffold without --force, and touches nothing", () => {
  const dir = tmpDir();
  assert.equal(runInitCli(["--dir", dir]), 0);

  const rulesPath = path.join(dir, "approval-rules.json");
  const approverKeyPath = path.join(dir, "approver-key.json");
  // Snapshot and re-read the key through ONE descriptor each time, so "same bytes" and "same mtime"
  // are read off the same open file rather than off a path that could name a different file between
  // the two calls. Same reasoning as the mode assertion above: this test measures anti-TOCTOU
  // behaviour, so it must not itself be check-then-use.
  const readKeyOnce = () => {
    const fd = fs.openSync(approverKeyPath, "r");
    try {
      return { bytes: fs.readFileSync(fd, "utf8"), mtimeMs: fs.fstatSync(fd).mtimeMs };
    } finally {
      fs.closeSync(fd);
    }
  };

  const beforeRules = fs.readFileSync(rulesPath, "utf8");
  const before = readKeyOnce();

  const secondExitCode = runInitCli(["--dir", dir]);
  assert.equal(secondExitCode, 1, "a second init in the same directory must refuse (non-zero exit), not silently overwrite");

  const after = readKeyOnce();
  assert.equal(fs.readFileSync(rulesPath, "utf8"), beforeRules, "approval-rules.json must be byte-identical after a refused re-run");
  assert.equal(after.bytes, before.bytes, "approver-key.json (private key material) must be untouched after a refused re-run");
  assert.equal(after.mtimeMs, before.mtimeMs, "the private key file must not even be re-written with identical content");
});

test("init --force regenerates all five files, including a genuinely NEW approver identity", () => {
  const dir = tmpDir();
  assert.equal(runInitCli(["--dir", dir]), 0);
  const approverKeyringPath = path.join(dir, "approver-keyring.json");
  const firstKid = Object.keys(JSON.parse(fs.readFileSync(approverKeyringPath, "utf8")))[0];

  const forcedExitCode = runInitCli(["--dir", dir, "--force"]);
  assert.equal(forcedExitCode, 0, "--force must succeed where a bare re-run refused");

  const secondKid = Object.keys(JSON.parse(fs.readFileSync(approverKeyringPath, "utf8")))[0];
  assert.notEqual(secondKid, firstKid, "--force must mint a FRESH approver identity, not silently reuse the old one");
});

test("init refuses a directory with only SOME of the five files present (never a mixed partial scaffold)", () => {
  const dir = tmpDir();
  fs.writeFileSync(path.join(dir, "pending-store.jsonl"), "", "utf8");
  const exitCode = runInitCli(["--dir", dir]);
  assert.equal(exitCode, 1);
  assert.ok(!fs.existsSync(path.join(dir, "approval-rules.json")), "must not have written the other three files around the one pre-existing file");
});

test("the generated config actually starts the REAL proxy.mjs CLI with the human-approval gate ON (real child process, real stdio)", async () => {
  const dir = tmpDir();
  assert.equal(runInitCli(["--dir", dir, "--allow-tool", "echo", "--approval-tool", "transfer_funds", "--block-tool", "read_data"]), 0);
  const policyPath = path.join(dir, "policy.json");
  const rulesPath = path.join(dir, "approval-rules.json");
  const pendingStorePath = path.join(dir, "pending-store.jsonl");
  const approverKeyringPath = path.join(dir, "approver-keyring.json");

  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [
      PROXY_CLI, "--session-id", "init-test-session", "--policy", policyPath,
      "--approval-rules", rulesPath, "--pending-store", pendingStorePath, "--approver-keyring", approverKeyringPath,
      "--", process.execPath, DEMO_DOWNSTREAM,
    ],
  });
  const client = new Client({ name: "init-test-host", version: "1.0.0" }, { capabilities: {} });
  await client.connect(transport);
  try {
    // The gate is ON and SELECTIVE, not a blanket deny: the allowed tool is forwarded.
    const echoed = await client.callTool({ name: "echo", arguments: { text: "through" } });
    assert.match(echoed.content?.[0]?.text ?? "", /through/);

    // The approval tool is HELD on every call — an MCP error carrying the DEFERRED receipt id,
    // never a silent forward — because init wrote the SAME name into both files.
    const held = await expectDeny(client.callTool({ name: "transfer_funds", arguments: { amountMinor: 1, to: "vendor-9" } }));
    assert.ok(held.denied, "a call of the approval tool must be held, not forwarded");
    assert.equal(held.code, -32600);
    assert.ok(typeof held.data?.receiptId === "string" && held.data.receiptId.length > 0);
  } finally {
    await client.close();
  }
});

test("init --allow-tool/--approval-tool/--block-tool refuse a missing value, a repeat, or one tool in two roles", () => {
  for (const args of [["--approval-tool"], ["--approval-tool", "--force"], ["--approval-tool", "a", "--approval-tool", "b"], ["--allow-tool", "x", "--block-tool", "x"], ["--approval-tool", STARTER_TOOL_NAMES.allowed]]) {
    const dir = tmpDir();
    const errWrite = process.stderr.write;
    process.stderr.write = () => true;
    let code;
    try {
      code = runInitCli(["--dir", dir, ...args]);
    } finally {
      process.stderr.write = errWrite;
    }
    assert.equal(code, 1, `args ${JSON.stringify(args)} must be refused`);
    assert.deepEqual(fs.readdirSync(dir), [], "nothing may be written");
  }
});

test("the proxy fails closed at startup when --approver-keyring is missing (init's generated rules/pending-store alone are not enough)", async () => {
  const dir = tmpDir();
  assert.equal(runInitCli(["--dir", dir]), 0);
  const rulesPath = path.join(dir, "approval-rules.json");
  const pendingStorePath = path.join(dir, "pending-store.jsonl");

  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [PROXY_CLI, "--approval-rules", rulesPath, "--pending-store", pendingStorePath, "--", process.execPath, DEMO_DOWNSTREAM],
    stderr: "pipe",
  });
  await assert.rejects(() => new Client({ name: "init-test-host-no-keyring", version: "1.0.0" }, { capabilities: {} }).connect(transport));
  const stderrChunks = [];
  if (transport.stderr) {
    for await (const chunk of transport.stderr) stderrChunks.push(chunk);
  }
  const stderr = Buffer.concat(stderrChunks).toString("utf8");
  assert.match(stderr, /refusing to start without --approver-keyring/);
});

// ---------------------------------------------------------------------------------------------
// CVE-shaped regression: a DANGLING symlink planted at one of the five target paths, pointing at
// an attacker-chosen location OUTSIDE --dir. `fs.existsSync()` returns false for a dangling
// symlink, so a pre-flight check built on it never sees the path as "occupied" — and a plain
// `writeFileSync` then follows the link and writes THROUGH it to the attacker's path. Confirmed
// by direct reproduction against the pre-fix commit (7b8cc5b): approver-keyring.json — this
// package's own trust anchor for the human-approval seat — was written to an attacker path with
// exit 0 and a "wrote 4 files" success message that was itself false (one of the four never
// landed in --dir at all). One test per generated file: each must (a) refuse the whole run
// (non-zero exit), (b) never write anything at the attacker's target path, and (c) never write
// any of the OTHER generated files either (the batch pre-flight check must catch this BEFORE writing
// starts, not mid-way through).
// ---------------------------------------------------------------------------------------------
const GENERATED_FILE_NAMES = ["policy.json", "approval-rules.json", "pending-store.jsonl", "approver-key.json", "approver-keyring.json"];

for (const targetName of GENERATED_FILE_NAMES) {
  test(`init refuses when "${targetName}" is a DANGLING symlink to an attacker path — nothing lands at the target, nothing else is written`, () => {
    const dir = tmpDir();
    const attackerDir = tmpDir(); // a SEPARATE directory standing in for "outside --dir"
    const attackerTarget = path.join(attackerDir, "attacker-owned-file");
    fs.symlinkSync(attackerTarget, path.join(dir, targetName)); // dangling: attackerTarget does not exist yet

    const exitCode = runInitCli(["--dir", dir]);
    assert.notEqual(exitCode, 0, `init must refuse (non-zero exit) when "${targetName}" is a dangling symlink, got 0`);

    assert.equal(fs.existsSync(attackerTarget), false, `nothing may be written at the attacker's target path via the "${targetName}" symlink`);

    // The symlink itself must be untouched — still a symlink, still pointing at the same place.
    const linkStat = fs.lstatSync(path.join(dir, targetName));
    assert.ok(linkStat.isSymbolicLink(), `"${targetName}" must remain a symlink, not be replaced`);
    assert.equal(fs.readlinkSync(path.join(dir, targetName)), attackerTarget);

    // None of the OTHER generated files may have been written either — a symlink on ONE of
    // the five must refuse the WHOLE batch before any of the five writes begin.
    for (const other of GENERATED_FILE_NAMES) {
      if (other === targetName) continue;
      assert.equal(fs.existsSync(path.join(dir, other)), false, `"${other}" must not be written when "${targetName}" is a dangling symlink (whole run must refuse before any write)`);
    }
  });
}

test("init --force removes a dangling symlink at a target path and writes a REAL file there — never through the link", () => {
  const dir = tmpDir();
  const attackerDir = tmpDir();
  const attackerTarget = path.join(attackerDir, "attacker-owned-file");
  fs.symlinkSync(attackerTarget, path.join(dir, "approver-keyring.json"));

  const exitCode = runInitCli(["--dir", dir, "--force"]);
  assert.equal(exitCode, 0, "--force must succeed even when a target path starts out as a dangling symlink");

  assert.equal(fs.existsSync(attackerTarget), false, "the attacker's target must still have nothing written to it after --force");
  const finalStat = fs.lstatSync(path.join(dir, "approver-keyring.json"));
  assert.ok(finalStat.isFile() && !finalStat.isSymbolicLink(), "approver-keyring.json must end up a REAL regular file, not a surviving/re-created symlink");
  const keyring = JSON.parse(fs.readFileSync(path.join(dir, "approver-keyring.json"), "utf8"));
  assert.equal(Object.keys(keyring).length, 1);
});

// ---------------------------------------------------------------------------------------------
// ROUND 2 — an independent review (cross-family) reproduced three CRITICALs and four lower-severity findings
// end-to-end against the round-1 fix. Each test below reproduces the STATE the finding depends
// on (not necessarily the exact timing mechanism, where that would make the test flaky) and
// proves the code's response to that state, per the "verify by reproducing" instruction.
// ---------------------------------------------------------------------------------------------

// CRITICAL 1 — `loadOrCreateKeyFile` is LOAD-or-create, not create-only. If a valid 0600 key
// appears at the target path between init's preflight check and this call (a real TOCTOU window:
// two OTHER files are written synchronously in between), the LOAD branch silently returns the
// planted identity without ever calling `mintKeyPair`. Reproduced here by pre-planting a
// well-formed, correctly-permissioned key at the path BEFORE calling the extracted unit directly
// — the exact state the race produces, deterministically, with no timing dependency.
test("mintApproverIdentityExclusive refuses to adopt a pre-existing key instead of minting a fresh one (closes the load-or-create TOCTOU)", () => {
  const dir = tmpDir();
  const keyPath = path.join(dir, "approver-key.json");
  const attackerKp = generateKeyPair("attacker-planted-identity");
  fs.writeFileSync(keyPath, JSON.stringify({ kid: attackerKp.kid, privateKey: attackerKp.privateKey, publicKey: attackerKp.publicKey }), { mode: 0o600 });

  assert.throws(
    () => mintApproverIdentityExclusive(keyPath),
    /already exists|did not mint|refus/i,
    "must refuse rather than silently adopt a key it did not itself mint",
  );

  // The attacker's planted file must be left completely untouched — never adopted, never
  // overwritten, never reported as success.
  const stillThere = JSON.parse(fs.readFileSync(keyPath, "utf8"));
  assert.equal(stillThere.kid, attackerKp.kid, "the planted file must be untouched after the refusal");
});

test("mintApproverIdentityExclusive mints and persists a genuinely fresh identity when the path is free", () => {
  const dir = tmpDir();
  const keyPath = path.join(dir, "approver-key.json");
  const kp = mintApproverIdentityExclusive(keyPath);
  assert.equal(typeof kp.kid, "string");
  const onDisk = JSON.parse(fs.readFileSync(keyPath, "utf8"));
  assert.equal(onDisk.kid, kp.kid, "the persisted file must match what was actually minted and returned");
});

// CRITICAL 3 — 0600 (POSIX mode bits) does not prevent disclosure on macOS: a directory carrying
// an inheritable "everyone allow read" ACL propagates that ACL to files created inside it
// REGARDLESS of the requested mode, and `stat`/the mode bits alone never reveal it. Reproduced
// with the REAL macOS ACL mechanism (chmod +a ... file_inherit,directory_inherit on the parent),
// not a simulation.
test(
  "approver-key.json carries no inherited ACL after init, even under a directory with an inheritable everyone-read ACL (macOS)",
  { skip: process.platform !== "darwin" ? "ACL inheritance is a macOS-specific mechanism" : false },
  () => {
    const dir = tmpDir();
    execFileSync("/bin/chmod", ["+a", "everyone allow read,file_inherit,directory_inherit", dir]);

    const exitCode = runInitCli(["--dir", dir]);
    assert.equal(exitCode, 0);

    const keyPath = path.join(dir, "approver-key.json");
    const lsOut = execFileSync("/bin/ls", ["-le", keyPath], { encoding: "utf8" });
    const lines = lsOut.split("\n").filter((l) => l.trim().length > 0);
    assert.equal(lines.length, 1, `expected no ACL entries on approver-key.json (mode bits alone are not the real readability), got:\n${lsOut}`);
  },
);

// HIGH 4 — O_NOFOLLOW only protects the FINAL path component; a symlinked ANCESTOR directory in
// --dir's chain is followed by mkdirSync/openSync regardless, silently placing every artifact
// (including the private key) outside the requested tree while the tool reports the lexical path.
test("init refuses when --dir resolves through a symlinked ANCESTOR directory (escapes the requested tree)", () => {
  const root = tmpDir();
  const outside = tmpDir();
  fs.symlinkSync(outside, path.join(root, "parent-link"));
  const requestedDir = path.join(root, "parent-link", "child");

  const exitCode = runInitCli(["--dir", requestedDir]);
  assert.notEqual(exitCode, 0, "must refuse when the resolved directory chain escapes the requested lexical path");
  assert.equal(fs.existsSync(path.join(outside, "child", "approver-key.json")), false, "the private key must never land outside --dir via a symlinked ancestor");
});

test("init still succeeds for an ordinary nested --dir with no symlinks anywhere in the chain (no false positive)", () => {
  const root = tmpDir();
  const nested = path.join(root, "a", "b", "c");
  const exitCode = runInitCli(["--dir", nested]);
  assert.equal(exitCode, 0, "an ordinary nested --dir with no symlinks must still succeed");
  assert.ok(fs.existsSync(path.join(nested, "approver-key.json")));
});

// MEDIUM 6 — the --force unlink loop deleted all preexisting targets BEFORE any validation that
// they could actually be replaced. A target that cannot be replaced (e.g. a directory sitting
// where a file belongs) then stranded the operator with the OLD identity destroyed and no new one
// created.
test("init --force refuses upfront (destroying NOTHING) when a preexisting target cannot possibly be replaced", () => {
  const dir = tmpDir();
  assert.equal(runInitCli(["--dir", dir]), 0);
  const beforeRules = fs.readFileSync(path.join(dir, "approval-rules.json"), "utf8");
  const beforeKey = fs.readFileSync(path.join(dir, "approver-key.json"), "utf8");

  // approver-keyring.json becomes a DIRECTORY — --force can never turn a directory back into a file.
  fs.unlinkSync(path.join(dir, "approver-keyring.json"));
  fs.mkdirSync(path.join(dir, "approver-keyring.json"));

  const exitCode = runInitCli(["--dir", dir, "--force"]);
  assert.notEqual(exitCode, 0, "must refuse rather than destroy the other three targets for a run that could never succeed");

  assert.equal(fs.readFileSync(path.join(dir, "approval-rules.json"), "utf8"), beforeRules, "approval-rules.json must survive an upfront refusal");
  assert.equal(fs.readFileSync(path.join(dir, "approver-key.json"), "utf8"), beforeKey, "approver-key.json must survive an upfront refusal");
});

// MEDIUM 7 — `createFileExclusive` creates the file (openSync/O_CREAT) BEFORE writing its content;
// if the write itself fails, the empty/partial file it just created was left on disk while the
// caller's bookkeeping still says "0 files were written" — a false claim. The fix must make the
// on-disk reality match the claim: either the file has its full content, or it does not exist.
test("createFileExclusive removes the file it just created if writing the content fails, so nothing lands half-written", () => {
  const dir = tmpDir();
  const target = path.join(dir, "will-fail.json");
  assert.throws(() => createFileExclusive(target, undefined), /./, "a content type writeFileSync rejects must still propagate");
  assert.equal(fs.existsSync(target), false, "the half-created file must be removed on a write failure, not left as an empty stub");
});

// LOW 8 — the generic creator used mode 0644 unconditionally, so pending-store.jsonl (tenant/
// session/action metadata, approval tickets, free-text denial reasons) was world-readable.
test("pending-store.jsonl is created mode 0600, not world/group-readable", () => {
  const dir = tmpDir();
  assert.equal(runInitCli(["--dir", dir]), 0);
  const st = fs.statSync(path.join(dir, "pending-store.jsonl"));
  assert.equal(st.mode & 0o777, 0o600, `expected pending-store.jsonl mode 0600, got 0${(st.mode & 0o777).toString(8)}`);
});

// LOW 9 — generated paths were interpolated BARE into printed example shell commands. A --dir
// containing a space or shell metacharacter becomes a command-injection trap for anyone who
// copy-pastes the printed line.
test("the printed next-steps commands shell-quote generated paths (a --dir with shell metacharacters must not print an unsafe copy-paste command)", () => {
  const dir = tmpDir();
  const nasty = path.join(dir, "weird dir; $(touch pwned-if-run) 'q");
  let captured = "";
  const realWrite = process.stdout.write;
  process.stdout.write = (chunk) => {
    captured += chunk;
    return true;
  };
  let exitCode;
  try {
    exitCode = runInitCli(["--dir", nasty]);
  } finally {
    process.stdout.write = realWrite;
  }
  assert.equal(exitCode, 0);
  const rulesPath = path.join(nasty, "approval-rules.json");
  assert.ok(!captured.includes(`--approval-rules ${rulesPath} \\`), "the raw, unquoted path must not appear in the printed example command");
  assert.ok(captured.includes(`'${rulesPath.replace(/'/g, "'\\''")}'`), "the printed example command must shell-quote the generated path");
});

// ---------------------------------------------------------------------------------------------
// The starter policy is usable as written: init prints ONE command line and ONE MCP config that
// start the real proxy with it, and once a placeholder is renamed to a real tool, that tool is
// governed exactly as the starter says — while every tool the file does not name stays denied.
// ---------------------------------------------------------------------------------------------
function captureStdout(fn) {
  let captured = "";
  const realWrite = process.stdout.write;
  process.stdout.write = (chunk) => {
    captured += chunk;
    return true;
  };
  try {
    return { result: fn(), out: captured };
  } finally {
    process.stdout.write = realWrite;
  }
}

test("init prints a one-line start command and a pasteable MCP config, both pointing --policy at the generated policy.json", () => {
  const dir = tmpDir();
  const { result, out } = captureStdout(() => runInitCli(["--dir", dir]));
  assert.equal(result, 0);
  const policyPath = path.join(dir, "policy.json");
  const startLine = out.split("\n").find((l) => l.trim().startsWith("noa-mcp-proxy --policy "));
  assert.ok(startLine, `no one-line start command in:\n${out}`);
  assert.ok(startLine.includes(`--policy '${policyPath}'`), startLine);
  assert.ok(startLine.includes(" -- "), "the start command must show where the server's own command goes");
  const argsLine = out.split("\n").find((l) => l.includes('"command": "noa-mcp-proxy", "args": '));
  assert.ok(argsLine, `no MCP config in:\n${out}`);
  const args = JSON.parse(argsLine.slice(argsLine.indexOf("[")));
  assert.equal(args[args.indexOf("--policy") + 1], policyPath);
  assert.equal(args[args.indexOf("--approver-keyring") + 1], path.join(dir, "approver-keyring.json"));
});

test("the generated policy.json drives the REAL proxy: a renamed placeholder runs, the blocked one and every unnamed tool are denied", async () => {
  const dir = tmpDir();
  assert.equal(runInitCli(["--dir", dir]), 0);
  const policyPath = path.join(dir, "policy.json");
  // The user's one edit: rename the allowed placeholder to a tool their server really has.
  fs.writeFileSync(policyPath, fs.readFileSync(policyPath, "utf8").replaceAll(STARTER_TOOL_NAMES.allowed, "echo"));
  const countsFile = path.join(dir, "counts.json");
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [
      PROXY_CLI, "--policy", policyPath,
      "--approval-rules", path.join(dir, "approval-rules.json"), "--pending-store", path.join(dir, "pending-store.jsonl"),
      "--approver-keyring", path.join(dir, "approver-keyring.json"),
      "--", "/usr/bin/env", `NOA_DEMO_COUNTS_FILE=${countsFile}`, process.execPath, DEMO_DOWNSTREAM,
    ],
    stderr: "pipe",
  });
  const stderrChunks = [];
  transport.stderr?.on("data", (c) => stderrChunks.push(c));
  const client = new Client({ name: "init-starter-policy-host", version: "1.0.0" }, { capabilities: {} });
  await client.connect(transport);

  try {
    const echoed = await client.callTool({ name: "echo", arguments: { text: "renamed" } });
    assert.match(echoed.content?.[0]?.text ?? "", /renamed/);
    for (const name of ["read_data", "transfer_funds", STARTER_TOOL_NAMES.blocked]) {
      const r = await expectDeny(client.callTool({ name, arguments: { key: "a", amountMinor: 1, to: "x" } }));
      assert.ok(r.denied, `${name} is not allowed by the starter policy and must be denied`);
    }
  } finally {
    await client.close();
  }
  const counts = JSON.parse(fs.readFileSync(countsFile, "utf8"));
  assert.deepEqual({ echo: counts.echo, read_data: counts.read_data, transfer_funds: counts.transfer_funds }, { echo: 1, read_data: 0, transfer_funds: 0 });
  assert.doesNotMatch(Buffer.concat(stderrChunks).toString("utf8"), /built-in DEMO policy/);
});

test("init run through a SYMLINK to init.mjs actually writes its files (the entry check resolves symlinks)", () => {
  const dir = tmpDir();
  const binDir = path.join(dir, "bin");
  fs.mkdirSync(binDir);
  const link = path.join(binDir, "noa-mcp-proxy-init");
  fs.symlinkSync(path.join(__dirname, "..", "src", "init.mjs"), link);
  const target = path.join(dir, "out");
  const run = spawnSync(process.execPath, [link, "--dir", target], { encoding: "utf8", timeout: 30_000 });
  assert.equal(run.status, 0, run.stderr);
  for (const name of GENERATED_FILE_NAMES) assert.ok(fs.existsSync(path.join(target, name)), `${name} must have been written`);
});
