/**
 * Pinned trust — the `noa-gate` binary in pinned mode, spawned for real: the HPKE sealer is wired (and a human's
 * device can open what the gate sealed), every broken input refuses the boot with its code and never
 * falls back to a listening alpha gate, a restart keeps the gate identity, `keygen` is the only
 * minting path, `roster-check` agrees with `serve`, and an unknown subcommand starts nothing.
 *
 * The roster files here are written by this test's own uid, so a positive boot uses the documented
 * development escape (NOA_GATE_UNSAFE_ROSTER_SAME_UID=1). The owner rule itself is proven with an
 * injected gate uid in pinned-roster.test.ts; one arm below proves the escape is REQUIRED.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { closeSync, existsSync, fstatSync, openSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { openEncryptedDisplay } from "noa-signer";
import { refHash } from "noa-approval-artifacts";
import { getProjection } from "../src/projections.js";
import { sampleCommandParams } from "./helpers.js";
import { AUDIT_KID, freshDir, newWorld, rosterDoc, writeRoster, x25519Pair, type RosterWorld } from "./helpers/pinned.js";
import type { HoldEnvelope } from "../src/types.js";

const CLI = fileURLToPath(new URL("../src/cli.js", import.meta.url));

/** Mode and content through ONE descriptor, so the two observations are of the same file. */
function readPrivate(p: string): { mode: number; text: string } {
  const fd = openSync(p, "r");
  try {
    return { mode: fstatSync(fd).mode, text: readFileSync(fd, "utf8") };
  } finally {
    closeSync(fd);
  }
}
const HOUR = 60 * 60 * 1000;

/** A clean environment: nothing inherited from the test process can select a trust mode. */
function cleanEnv(extra: Record<string, string>): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { PATH: process.env["PATH"] ?? "/usr/bin:/bin" };
  if (process.env["HOME"]) env["HOME"] = process.env["HOME"];
  if (process.env["TMPDIR"]) env["TMPDIR"] = process.env["TMPDIR"];
  return { ...env, NOA_GATE_PORT: "0", ...extra };
}

interface Exit {
  code: number | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
}

function runToExit(args: string[], env: NodeJS.ProcessEnv, timeoutMs = 15_000): Promise<Exit> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI, ...args], { env, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    child.stdout!.setEncoding("utf8").on("data", (c: string) => { stdout += c; });
    child.stderr!.setEncoding("utf8").on("data", (c: string) => { stderr += c; });
    const t = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, timeoutMs);
    child.once("exit", (code) => {
      clearTimeout(t);
      resolve({ code, stdout, stderr, timedOut });
    });
  });
}

interface Running {
  child: ChildProcess;
  banner: Record<string, unknown>;
  base: string;
  stop(): Promise<void>;
}

function startGate(env: NodeJS.ProcessEnv): Promise<Running> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI, "serve"], { env, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    const stop = () => new Promise<void>((done) => {
      if (child.exitCode !== null || child.signalCode !== null) return done();
      child.once("exit", () => done());
      child.kill("SIGTERM");
    });
    const t = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error(`gate did not print its banner; stderr: ${stderr}`));
    }, 15_000);
    child.stderr!.setEncoding("utf8").on("data", (c: string) => { stderr += c; });
    child.stdout!.setEncoding("utf8").on("data", (c: string) => {
      stdout += c;
      try {
        const banner = JSON.parse(stdout) as Record<string, unknown>;
        clearTimeout(t);
        resolve({ child, banner, base: banner["listening"] as string, stop });
      } catch {
        // the banner is still arriving
      }
    });
    child.once("exit", (code) => {
      clearTimeout(t);
      reject(new Error(`gate exited (${String(code)}) before its banner; stderr: ${stderr}`));
    });
  });
}

async function post(base: string, apiKey: string, path: string, payload: unknown, headers: Record<string, string> = {}) {
  const res = await fetch(`${base}${path}`, {
    method: "POST",
    headers: { authorization: `Bearer ${apiKey}`, "content-type": "application/json", ...headers },
    body: JSON.stringify(payload),
  });
  return { status: res.status, body: (await res.json().catch(() => null)) as Record<string, unknown> | null };
}
async function get(base: string, apiKey: string, path: string) {
  const res = await fetch(`${base}${path}`, { headers: { authorization: `Bearer ${apiKey}` } });
  return { status: res.status, body: (await res.json().catch(() => null)) as Record<string, unknown> | null };
}

interface PinnedSetup {
  dir: string;
  keyFile: string;
  rosterFile: string;
  world: RosterWorld;
  env: NodeJS.ProcessEnv;
}

/** keygen through the binary, a roster naming the printed gate member, and a pinned serve environment. */
async function pinnedSetup(over: Record<string, unknown> = {}): Promise<PinnedSetup> {
  const dir = freshDir("cli");
  const keyFile = join(dir, "gate.key.json");
  const kg = await runToExit(["keygen", "--key-file", keyFile, "--kid", "gate-example-1"], cleanEnv({}));
  assert.equal(kg.code, 0, kg.stderr);
  const gate = (JSON.parse(kg.stdout) as { gate: { kid: string; publicKey: string } }).gate;
  const world = newWorld();
  const doc = rosterDoc(world, Date.now(), { gate, ...over });
  const rosterFile = writeRoster(dir, doc);
  const env = cleanEnv({
    NOA_GATE_ROSTER_FILE: rosterFile,
    NOA_GATE_KEY_FILE: keyFile,
    NOA_GATE_UNSAFE_ROSTER_SAME_UID: "1",
    NOA_GATE_UNSAFE_IN_PROCESS_GRANT_KEY: "1",
  });
  return { dir, keyFile, rosterFile, world, env };
}

const HOLD_BODY = {
  mode: "ENFORCED",
  action: { canonical: "noa.command.exec", riskClass: "HIGH", reversible: false },
  params: sampleCommandParams(),
  chain: "cli-chain",
};

test("K15 — pinned serve seals with real HPKE: the roster's approver AND audit keys open exactly the projection's display", async () => {
  const s = await pinnedSetup();
  const gate = await startGate(s.env);
  try {
    assert.equal(gate.banner["trustMode"], "PINNED");
    assert.equal(gate.banner["displaySealer"], "hpke");
    assert.equal(gate.banner["rosterCustody"], process.geteuid?.() === 0 ? "ROOT-GATE (unsafe)" : "SAME-UID (unsafe)");
    const apiKey = gate.banner["agentApiKey"] as string;
    const created = await post(gate.base, apiKey, "/v1/holds", HOLD_BODY, { "idempotency-key": "cli-k15" });
    assert.equal(created.status, 201, `consequence: a pinned gate must freeze the hold with a sealed display: ${JSON.stringify(created.body)}`);
    const ed = created.body!["encryptedDisplay"] as Record<string, unknown>;
    const envelope = created.body!["holdEnvelope"] as unknown as HoldEnvelope;
    assert.equal(envelope.displayCiphertextHash, refHash(ed), "the envelope binds exactly the sealed object handed out");
    const recipients = (ed["recipients"] as Array<{ kid: string }>).map((r) => r.kid);
    assert.deepEqual(recipients, [s.world.approver.kid, AUDIT_KID]);

    const run = getProjection("noa.command.exec")!.run(sampleCommandParams());
    assert.ok(run.ok);
    const byApprover = openEncryptedDisplay(ed, { kid: s.world.approver.kid, secretKey: s.world.approver.x.secretKey });
    const byAudit = openEncryptedDisplay(ed, { kid: AUDIT_KID, secretKey: s.world.audit.secretKey });
    assert.deepEqual(byApprover, run.display);
    assert.deepEqual(byAudit, run.display);
    assert.throws(() => openEncryptedDisplay(ed, { kid: s.world.approver.kid, secretKey: x25519Pair().secretKey }), "a stranger's key opens nothing");
  } finally {
    await gate.stop();
  }
});

test("alpha serve is unchanged: no display sealer, so a hold is refused 500 DISPLAY_SEALER_UNCONFIGURED", async () => {
  const gate = await startGate(cleanEnv({ NOA_GATE_UNSAFE_IN_PROCESS_GRANT_KEY: "1" }));
  try {
    assert.equal(gate.banner["trustMode"], "ALPHA-EPHEMERAL");
    assert.equal(gate.banner["displaySealer"], "none");
    const r = await post(gate.base, gate.banner["agentApiKey"] as string, "/v1/holds", HOLD_BODY, { "idempotency-key": "cli-alpha" });
    assert.equal(r.status, 500, JSON.stringify(r.body));
    assert.equal(r.body!["error"], "DISPLAY_SEALER_UNCONFIGURED");
  } finally {
    await gate.stop();
  }
});

test("K17 — every broken pinned input exits 1 with its code on stderr and never listens (no alpha fallback)", async () => {
  const s = await pinnedSetup();
  const expired = await pinnedSetup({ validFrom: new Date(Date.now() - 10 * HOUR).toISOString(), expiresAt: new Date(Date.now() - HOUR).toISOString() });
  const cases: Array<[string, NodeJS.ProcessEnv, string]> = [
    ["missing roster", { ...s.env, NOA_GATE_ROSTER_FILE: join(s.dir, "absent.json") }, "ROSTER_FILE_MISSING"],
    ["missing key file", { ...s.env, NOA_GATE_KEY_FILE: join(s.dir, "absent.key") }, "GATE_KEY_FILE_MISSING"],
    ["key file of another gate", { ...s.env, NOA_GATE_KEY_FILE: expired.keyFile }, "GATE_KEY_NOT_PINNED"],
    ["expired roster", expired.env, "ROSTER_EXPIRED"],
    ["wrong digest pin", { ...s.env, NOA_GATE_ROSTER_SHA256: "sha256:" + "0".repeat(64) }, "ROSTER_DIGEST_MISMATCH"],
    ["roster owned by the gate's own uid", { ...s.env, NOA_GATE_UNSAFE_ROSTER_SAME_UID: "0" }, "ROSTER_FILE_UNSAFE"],
    ["a second identity source", { ...s.env, NOA_GATE_APPROVER_KID: "approver-example-9" }, "CONFIG_SOURCE_CONFLICT"],
    ["half a configuration", cleanEnv({ NOA_GATE_ROSTER_FILE: s.rosterFile, NOA_GATE_UNSAFE_IN_PROCESS_GRANT_KEY: "1" }), "CONFIG_PINNED_INCOMPLETE"],
    ["a pin with no roster", cleanEnv({ NOA_GATE_ROSTER_SHA256: "sha256:" + "0".repeat(64), NOA_GATE_UNSAFE_IN_PROCESS_GRANT_KEY: "1" }), "CONFIG_PINNED_INCOMPLETE"],
    // An EMPTY pinned variable is present: the downgrade to the self-minting alpha root is refused.
    ["an empty roster variable", cleanEnv({ NOA_GATE_ROSTER_FILE: "", NOA_GATE_UNSAFE_IN_PROCESS_GRANT_KEY: "1" }), "CONFIG_PINNED_INCOMPLETE"],
    ["a relative roster path", { ...s.env, NOA_GATE_ROSTER_FILE: "roster.json" }, "ROSTER_FILE_UNSAFE"],
  ];
  if (process.geteuid?.() === 0) cases.splice(5, 1); // root owns every file: the same-uid arm needs a non-root gate
  for (const [name, env, want] of cases) {
    const r = await runToExit(["serve"], env);
    assert.equal(r.timedOut, false, `consequence: ${name} — the gate kept running (a fallback listened)`);
    assert.equal(r.code, 1, `${name}: exit ${String(r.code)}; stderr ${r.stderr}`);
    assert.match(r.stderr, new RegExp(`^noa-gate: ${want}: `), `${name}: stderr ${r.stderr}`);
    assert.equal(r.stdout, "", `${name}: nothing may be printed as if a gate were listening`);
  }
  assert.equal(existsSync(join(s.dir, "absent.key")), false, "serve never mints a key");
  assert.equal(existsSync(`${s.keyFile}.roster-state`), false, "a refused boot never advances the high-water mark");
});

test("restart — the same key file keeps the gate identity, bootId is new, the high-water mark holds, and pre-restart holds are gone", async () => {
  const s = await pinnedSetup();
  const first = await startGate(s.env);
  let holdId: string;
  let firstBanner: Record<string, unknown>;
  try {
    firstBanner = first.banner;
    assert.equal(firstBanner["rosterHighWater"], "INITIALIZED");
    const created = await post(first.base, first.banner["agentApiKey"] as string, "/v1/holds", HOLD_BODY, { "idempotency-key": "cli-restart" });
    assert.equal(created.status, 201, JSON.stringify(created.body));
    holdId = created.body!["holdId"] as string;
  } finally {
    await first.stop();
  }
  const statePath = `${s.keyFile}.roster-state`;
  assert.equal(readPrivate(statePath).mode & 0o777, 0o600);
  const second = await startGate(s.env);
  try {
    assert.equal(second.banner["gateKid"], firstBanner["gateKid"]);
    assert.equal(second.banner["gatePublicKey"], firstBanner["gatePublicKey"]);
    assert.equal(second.banner["rosterDigest"], firstBanner["rosterDigest"]);
    assert.notEqual(second.banner["bootId"], firstBanner["bootId"]);
    assert.equal(second.banner["rosterHighWater"], "UNCHANGED");
    const old = await get(second.base, second.banner["agentApiKey"] as string, `/v1/holds/${holdId}`);
    assert.equal(old.status, 404, JSON.stringify(old.body));
  } finally {
    await second.stop();
  }
});

test("keygen is the only minting path: 0600, idempotent, never overwrites, refuses another kid; roster-check matches serve and writes nothing", async () => {
  const s = await pinnedSetup();
  const before = readPrivate(s.keyFile);
  assert.equal(before.mode & 0o777, 0o600);
  const again = await runToExit(["keygen", "--key-file", s.keyFile, "--kid", "gate-example-1"], cleanEnv({}));
  assert.equal(readPrivate(s.keyFile).text, before.text, "consequence: an existing key file is read, never rewritten");
  assert.equal(again.code, 0, again.stderr);
  const other = await runToExit(["keygen", "--key-file", s.keyFile, "--kid", "gate-example-2"], cleanEnv({}));
  assert.equal(readPrivate(s.keyFile).text, before.text, "consequence: another kid never replaces the key");
  assert.equal(other.code, 1);
  assert.match(other.stderr, /GATE_KEY_KID_MISMATCH/);
  assert.ok(!again.stdout.includes("privateKey"), "keygen never prints the private key");
  const bad = await runToExit(["keygen", "--key-file", join(s.dir, "x.key"), "--kid", "Gate_1"], cleanEnv({}));
  assert.equal(bad.code, 2);

  const env = { ...s.env };
  const check = await runToExit(["roster-check", s.rosterFile, "--key-file", s.keyFile], env);
  assert.equal(check.code, 0, check.stderr);
  const report = JSON.parse(check.stdout) as Record<string, unknown>;
  assert.equal(existsSync(`${s.keyFile}.roster-state`), false, "roster-check never writes the state file");
  const gate = await startGate(s.env);
  try {
    assert.equal(report["rosterDigest"], gate.banner["rosterDigest"], "roster-check prints the digest serve prints");
  } finally {
    await gate.stop();
  }
  const refusedCheck = await runToExit(["roster-check", s.rosterFile], { ...env, NOA_GATE_ROSTER_SHA256: "sha256:" + "0".repeat(64) });
  assert.equal(refusedCheck.code, 1);
  assert.match(refusedCheck.stderr, /ROSTER_DIGEST_MISMATCH/);
});

test("an unknown subcommand exits 2 and starts nothing; so does a stray flag to keygen", async () => {
  const r = await runToExit(["roster-chek"], cleanEnv({ NOA_GATE_UNSAFE_IN_PROCESS_GRANT_KEY: "1" }));
  assert.equal(r.timedOut, false, "consequence: an unknown subcommand must not boot a gate");
  assert.equal(r.code, 2);
  assert.match(r.stderr, /UNKNOWN_SUBCOMMAND/);
  assert.equal(r.stdout, "");
  const flag = spawnSync(process.execPath, [CLI, "keygen", "--key-file", "/nonexistent/k", "--kid", "gate-a", "--force"], { env: cleanEnv({}), encoding: "utf8" });
  assert.equal(flag.status, 2, flag.stderr);
});

test("every subcommand refuses an argument it does not know (UNKNOWN_ARGUMENT, exit 2): `serve --roster-file X` boots nothing", async () => {
  const s = await pinnedSetup();
  const serve = await runToExit(["serve", "--roster-file", s.rosterFile], cleanEnv({ NOA_GATE_UNSAFE_IN_PROCESS_GRANT_KEY: "1" }));
  assert.equal(serve.timedOut, false, "consequence: a mistyped pinned configuration must not boot the alpha root");
  assert.equal(serve.stdout, "", "consequence: nothing listens");
  assert.equal(serve.code, 2, serve.stderr);
  assert.match(serve.stderr, /UNKNOWN_ARGUMENT/);
  const hold = await runToExit(["hold-and-run", "--frobnicate", "x", "--", "true"], cleanEnv({ NOA_GATE_KEY: "k" }));
  assert.equal(hold.code, 2, hold.stderr);
  assert.match(hold.stderr, /UNKNOWN_ARGUMENT/);
  const check = await runToExit(["roster-check", s.rosterFile, "extra"], s.env);
  assert.equal(check.code, 2, check.stderr);
  assert.match(check.stderr, /UNKNOWN_ARGUMENT/);
});

test("roster-check applies serve's environment rules: a second identity source is CONFIG_SOURCE_CONFLICT", async () => {
  const s = await pinnedSetup();
  const r = await runToExit(["roster-check", s.rosterFile], { ...s.env, NOA_GATE_APPROVER_KID: "approver-example-9" });
  assert.equal(r.stdout, "", "consequence: no digest is printed for an environment serve would refuse");
  assert.equal(r.code, 1, r.stderr);
  assert.match(r.stderr, /CONFIG_SOURCE_CONFLICT/);
});
