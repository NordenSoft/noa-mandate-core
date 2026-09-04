#!/usr/bin/env node
/**
 * Trusted asynchronous sidecar for the synchronous knockout runner.
 *
 * The suite gets ordinary stdout/stderr pipes. Structured test evidence arrives on one Unix-domain
 * socket accepted by this process. The rendezvous pathname is unlinked before the reporter is
 * acknowledged, so test-file workers can neither replace the evidence object nor open its held
 * descriptor. Only this sidecar serializes the final observation back to the runner.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { spawn } from "node:child_process";
import {
  PROOF_EVENT_REPORTER,
  PROOF_EVENT_REPORTER_ID,
  PROOF_EVENT_SOCKET_ENV,
  PROOF_EVENT_TOKEN_ENV,
  PROOF_EVENT_TRANSPORT_PROTOCOL,
  proofEventReporterNodeOption,
} from "./proof-event-contract.mjs";
import {
  closedEvidenceEnvironment,
  containedGateScratchEnvironment,
  CONTAINED_SCRATCH_ROOT,
} from "./knockout-runner.mjs";

const MAX_REQUEST_BYTES = 64 * 1024;
const MAX_CAPTURE_BYTES = 16 * 1024 * 1024;
const MAX_HANDSHAKE_BYTES = 4096;
const TOKEN_PATTERN = /^[0-9a-f]{64}$/;

const jsonReply = (value) => {
  process.stdout.write(`${JSON.stringify(value)}\n`);
};

async function readRequest() {
  const chunks = [];
  let bytes = 0;
  for await (const chunk of process.stdin) {
    bytes += chunk.length;
    if (bytes > MAX_REQUEST_BYTES) throw new Error("observer request exceeded its bound");
    chunks.push(chunk);
  }
  let value;
  try { value = JSON.parse(Buffer.concat(chunks).toString("utf8")); }
  catch { throw new Error("observer request is not JSON"); }
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("observer request must be an object");
  }
  const keys = Object.keys(value).sort();
  const expectedKeys = ["cwd", "kind", "socketPath", "steps", "timeoutMs"];
  if (JSON.stringify(keys) !== JSON.stringify(expectedKeys)) {
    throw new Error(`observer request keys must be exactly ${expectedKeys.join(", ")}`);
  }
  if (typeof value.cwd !== "string" || !path.isAbsolute(value.cwd)) {
    throw new Error("observer cwd must be absolute");
  }
  if (value.kind !== "tests" && value.kind !== "gate") {
    throw new Error("observer kind must be tests or gate");
  }
  if (!Array.isArray(value.steps) || value.steps.length < 1 || value.steps.length > 64) {
    throw new Error("observer steps must be a non-empty array of at most 64 entries");
  }
  let evidenceSteps = 0;
  for (const [index, step] of value.steps.entries()) {
    if (step === null || typeof step !== "object" || Array.isArray(step)) {
      throw new Error(`observer step ${index + 1} must be an object`);
    }
    const stepKeys = Object.keys(step).sort();
    const expectedStepKeys = ["args", "cmd", "evidence"];
    if (JSON.stringify(stepKeys) !== JSON.stringify(expectedStepKeys)) {
      throw new Error(`observer step ${index + 1} keys must be exactly ${expectedStepKeys.join(", ")}`);
    }
    if (typeof step.cmd !== "string" || step.cmd.length === 0) {
      throw new Error(`observer step ${index + 1} command must be non-empty`);
    }
    if (!Array.isArray(step.args) || step.args.some((arg) => typeof arg !== "string")) {
      throw new Error(`observer step ${index + 1} args must be an array of strings`);
    }
    if (typeof step.evidence !== "boolean") {
      throw new Error(`observer step ${index + 1} evidence must be boolean`);
    }
    if (step.evidence) {
      evidenceSteps++;
      if (step.cmd !== process.execPath) {
        throw new Error("the evidence step must use the exact current Node executable");
      }
      if (value.kind === "tests") {
        if (step.args.filter((arg) => arg === "--test").length !== 1) {
          throw new Error("the test evidence step must carry exactly one --test option");
        }
        if (step.args.some((arg) => arg.startsWith("--test-reporter"))) {
          throw new Error("the evidence step may not override or redirect its reporter");
        }
      } else if (
        index !== value.steps.length - 1 ||
        step.args.filter((arg) => arg === "--knockout-json").length !== 1
      ) {
        throw new Error("the gate evidence step must be terminal and carry one --knockout-json option");
      }
    }
  }
  if (evidenceSteps !== 1) {
    throw new Error("observer request must contain exactly one evidence step");
  }
  if (!Number.isInteger(value.timeoutMs) || value.timeoutMs < 1 || value.timeoutMs > 3_600_000) {
    throw new Error("observer timeout must be an integer from 1 through 3600000 milliseconds");
  }
  if (value.kind === "tests") {
    if (
      typeof value.socketPath !== "string" || !path.isAbsolute(value.socketPath) ||
      path.basename(value.socketPath) !== "events.sock"
    ) {
      throw new Error("test observer socketPath must be an absolute events.sock pathname");
    }
    const directory = path.dirname(value.socketPath);
    const directoryStat = fs.lstatSync(directory);
    if (!directoryStat.isDirectory() || directoryStat.isSymbolicLink()) {
      throw new Error("observer socket parent is not a real directory");
    }
    if ((directoryStat.mode & 0o077) !== 0) {
      throw new Error("observer socket parent is accessible outside its owner");
    }
    if (typeof process.getuid === "function" && directoryStat.uid !== process.getuid()) {
      throw new Error("observer socket parent is owned by another account");
    }
    if (fs.existsSync(value.socketPath)) throw new Error("observer socket pathname already exists");
  } else if (value.socketPath !== null) {
    throw new Error("gate observer socketPath must be null");
  }
  return value;
}

const sameToken = (actual, expected) => {
  if (typeof actual !== "string" || !TOKEN_PATTERN.test(actual)) return false;
  return crypto.timingSafeEqual(Buffer.from(actual, "hex"), Buffer.from(expected, "hex"));
};

function terminateTree(child, signal) {
  if (child.pid === undefined) return false;
  if (process.platform !== "win32") {
    try { process.kill(-child.pid, signal); return true; }
    catch { /* fall back to the direct child */ }
  }
  try { return child.kill(signal); } catch { return false; }
}

const delay = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

function processGroupExists(pid) {
  if (process.platform === "win32") return false;
  try {
    process.kill(-pid, 0);
    return true;
  } catch (error) {
    if (error?.code === "ESRCH") return false;
    return true;
  }
}

async function waitForProcessGroupExit(pid, timeoutMs = 2000) {
  if (process.platform === "win32") return true;
  const deadline = Date.now() + timeoutMs;
  while (processGroupExists(pid) && Date.now() < deadline) await delay(25);
  return !processGroupExists(pid);
}

async function observe(request) {
  const inherited = process.env.NODE_OPTIONS ?? "";
  if (inherited.trim().length !== 0) {
    throw new Error("observer inherited NODE_OPTIONS; evidence requires a closed Node startup surface");
  }
  if (
    process.env[PROOF_EVENT_SOCKET_ENV] !== undefined ||
    process.env[PROOF_EVENT_TOKEN_ENV] !== undefined
  ) {
    throw new Error("observer inherited a proof reporter capability");
  }

  const token = crypto.randomBytes(32).toString("hex");
  const reporterOption = proofEventReporterNodeOption();
  const baseEnvironment = request.kind === "gate"
    ? {
        ...containedGateScratchEnvironment(
          closedEvidenceEnvironment(process.env, {
            rcRoot: path.join(CONTAINED_SCRATCH_ROOT, "npm-rc"),
          }),
        ),
        // The namespace root is read-only and its only writable filesystem is this per-container
        // tmpfs. Gate preparations such as proof-resolve selftests legitimately need bounded
        // scratch files; leaving TMPDIR absent makes Node fall back to the read-only host `/tmp`
        // mount and kills the clean baseline before the terminal gate can speak.
      }
    : { ...process.env };
  delete baseEnvironment.NODE_TEST_CONTEXT;

  const stdout = [];
  const stderr = [];
  const events = [];
  let outputBytes = 0;
  let eventBytes = 0;
  let observationError = null;
  let acceptedSocket = null;
  let acceptedClosed = null;
  let acceptedDidClose = false;
  let listenerUnlinked = false;
  let terminateCurrent = () => undefined;

  const refuseRecreatedSocketPath = () => {
    if (!listenerUnlinked || request.kind !== "tests") return;
    try {
      fs.lstatSync(request.socketPath);
    } catch (error) {
      if (error?.code === "ENOENT") return;
      observationError ??=
        `could not verify the unlinked proof socket pathname stayed absent: ${String(error && error.message)}`;
      return;
    }
    const replacement = "unlinked proof socket pathname was replaced after the reporter handshake";
    observationError = observationError === null ? replacement : `${observationError}; ${replacement}`;
    try { fs.unlinkSync(request.socketPath); }
    catch (error) {
      observationError += `; replacement could not be removed: ${String(error && error.message)}`;
    }
  };

  const appendBounded = (bucket, chunk, kind) => {
    const copy = Buffer.from(chunk);
    if (kind === "events") eventBytes += copy.length;
    else outputBytes += copy.length;
    const total = kind === "events" ? eventBytes : outputBytes;
    if (total > MAX_CAPTURE_BYTES) {
      observationError ??= `${kind} exceeded the ${MAX_CAPTURE_BYTES}-byte evidence bound`;
      terminateCurrent();
      return;
    }
    bucket.push(copy);
  };

  const server = net.createServer((socket) => {
    if (acceptedSocket !== null) {
      socket.destroy();
      return;
    }
    let handshake = Buffer.alloc(0);
    const reject = () => socket.destroy();
    const onHandshake = (chunk) => {
      handshake = Buffer.concat([handshake, chunk]);
      if (handshake.length > MAX_HANDSHAKE_BYTES) { reject(); return; }
      const newline = handshake.indexOf(0x0a);
      if (newline < 0) return;
      if (newline !== handshake.length - 1) { reject(); return; }
      let hello;
      try { hello = JSON.parse(handshake.subarray(0, newline).toString("utf8")); }
      catch { reject(); return; }
      if (
        hello === null || typeof hello !== "object" || Array.isArray(hello) ||
        hello.protocol !== PROOF_EVENT_TRANSPORT_PROTOCOL ||
        hello.reporter !== PROOF_EVENT_REPORTER_ID || !sameToken(hello.token, token)
      ) {
        reject();
        return;
      }

      socket.off("data", onHandshake);
      acceptedSocket = socket;
      acceptedClosed = new Promise((resolve) => socket.once("close", () => {
        acceptedDidClose = true;
        resolve();
      }));
      try {
        fs.unlinkSync(request.socketPath);
        listenerUnlinked = true;
        server.close();
      } catch (error) {
        observationError = `could not unlink the accepted proof socket: ${String(error && error.message)}`;
        socket.destroy();
        terminateCurrent();
        return;
      }

      socket.on("data", (data) => appendBounded(events, data, "events"));
      socket.on("end", () => socket.destroy());
      socket.on("error", (error) => {
        observationError ??= `proof socket failed: ${String(error && error.message)}`;
      });
      socket.write(`${JSON.stringify({
        protocol: PROOF_EVENT_TRANSPORT_PROTOCOL,
        accepted: true,
      })}\n`);
    };
    socket.on("data", onHandshake);
    socket.on("error", () => { /* rejected or disconnected clients carry no evidence */ });
  });

  let timedOut = false;
  let exit = null;
  let signal = null;
  let machineOutput = "";
  let machineDiagnostics = "";
  const deadline = Date.now() + request.timeoutMs;

  const runStep = async (step, environment, remainingMs) => {
    let child;
    let stepExit = null;
    let stepSignal = null;
    let spawnError = null;
    let stepTimedOut = false;
    let terminationRequested = false;
    let hardKillPromise = null;

    try {
      child = spawn(step.cmd, step.args, {
        cwd: request.cwd,
        env: environment,
        detached: process.platform !== "win32",
        stdio: ["ignore", "pipe", "pipe"],
        windowsHide: true,
      });
    } catch (error) {
      return { exit: null, signal: null, timedOut: false, spawnError: error };
    }

    const terminateWithEscalation = () => {
      if (terminationRequested || child.pid === undefined) return;
      terminationRequested = true;
      terminateTree(child, "SIGTERM");
      // This promise is intentionally awaited even if the process-group leader closes first. A
      // SIGTERM-resistant descendant remains addressable by the original PGID and must receive the
      // hard kill before the observer may return or the build-state guard may restore sources.
      hardKillPromise = new Promise((resolve) => {
        setTimeout(() => {
          terminateTree(child, "SIGKILL");
          resolve();
        }, 2000);
      });
    };
    terminateCurrent = terminateWithEscalation;
    child.stdout.on("data", (chunk) => appendBounded(stdout, chunk, "stdout"));
    child.stderr.on("data", (chunk) => appendBounded(stderr, chunk, "stderr"));

    const timeout = setTimeout(() => {
      stepTimedOut = true;
      terminateWithEscalation();
    }, remainingMs);

    await new Promise((resolve) => {
      child.once("error", (error) => {
        spawnError = error;
        resolve();
      });
      child.once("close", (code, closeSignal) => {
        stepExit = Number.isInteger(code) ? code : null;
        stepSignal = closeSignal ?? null;
        resolve();
      });
    });
    clearTimeout(timeout);

    if (terminationRequested && hardKillPromise !== null) await hardKillPromise;
    // TWO DIFFERENT FACTS, AND THEY WERE BEING REPORTED AS ONE.
    //
    // `hardKillPromise` resolves as soon as SIGKILL has been SENT, not once the group has been
    // reaped, so the instant after it is precisely when a just-killed group still exists. Probing
    // existence there latched "left a descendant process alive" on the TIMEOUT path — against a
    // suite whose descendant ignored SIGTERM, which is the exact case this escalation exists for.
    // MEASURED before this change: a descendant that installed a SIGTERM handler, recorded that it
    // received the signal, outlived it, and was then SIGKILLed produced that error while
    // `waitForProcessGroupExit` on the next line confirmed the group HAD exited.
    //
    // So the conditions are separated. A live group after a leader closed with NO termination
    // requested is the suite's own doing and keeps that message. Everything else — every timeout
    // included — is judged only by whether the group actually exits within the bounded wait, and a
    // group that genuinely outlives SIGKILL is still reported, by the message that says exactly that.
    if (child.pid !== undefined && !terminationRequested && processGroupExists(child.pid)) {
      observationError ??= "suite step left a descendant process alive after its leader closed";
      terminateWithEscalation();
      if (hardKillPromise !== null) await hardKillPromise;
    }
    if (child.pid !== undefined && !await waitForProcessGroupExit(child.pid)) {
      observationError ??= `suite process group ${child.pid} survived SIGKILL escalation`;
    }
    terminateCurrent = () => undefined;
    return { exit: stepExit, signal: stepSignal, timedOut: stepTimedOut, spawnError };
  };

  const evidenceIndex = request.steps.findIndex((step) => step.evidence);
  for (const [index, step] of request.steps.entries()) {
    const remainingMs = deadline - Date.now();
    if (remainingMs < 1) {
      timedOut = true;
      observationError ??= "suite timeout elapsed before the next step could start";
      break;
    }

    let environment = baseEnvironment;
    if (request.kind === "tests" && index === evidenceIndex) {
      await new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen(request.socketPath, resolve);
      });
      environment = {
        ...baseEnvironment,
        NODE_OPTIONS: reporterOption,
        [PROOF_EVENT_SOCKET_ENV]: request.socketPath,
        [PROOF_EVENT_TOKEN_ENV]: token,
      };
    }

    const stdoutStart = stdout.length;
    const stderrStart = stderr.length;
    const result = await runStep(step, environment, remainingMs);
    exit = result.exit;
    signal = result.signal;
    timedOut = result.timedOut;
    if (result.spawnError !== null) {
      observationError ??= `suite step ${index + 1} could not start: ${String(result.spawnError && result.spawnError.message)}`;
    }

    if (request.kind === "gate" && index === evidenceIndex) {
      machineOutput = Buffer.concat(stdout.slice(stdoutStart)).toString("utf8");
      // Stdout is the machine gate-event channel; stderr is the separate arm-terminal channel.
      // Slice both at the evidence step so preparation output cannot impersonate either channel.
      machineDiagnostics = Buffer.concat(stderr.slice(stderrStart)).toString("utf8");
    }

    if (request.kind === "tests" && index === evidenceIndex) {
      // A closed test runner closes its reporter socket. Give pending frames a bounded opportunity
      // to arrive, then close the descriptor and pathname before any credential-free post-step.
      if (acceptedClosed !== null) {
        await Promise.race([acceptedClosed, delay(2000)]);
        if (!acceptedDidClose) {
          observationError ??= "proof reporter socket remained open after the test runner closed";
          acceptedSocket?.destroy();
        }
      }
      if (server.listening) server.close();
      if (!listenerUnlinked) {
        try { fs.unlinkSync(request.socketPath); }
        catch (error) {
          if (error?.code !== "ENOENT") {
            observationError ??= `could not remove the proof socket: ${String(error && error.message)}`;
          }
        }
      }
      // The held descriptor remains authoritative after unlink, but recreating its disclosed name
      // is still an attempted evidence substitution. Make that attack an explicit refusal instead
      // of silently relying on the descriptor to render the forged pathname inert.
      refuseRecreatedSocketPath();
    }

    if (
      result.spawnError !== null || result.timedOut || result.signal !== null ||
      result.exit !== 0 || observationError !== null
    ) {
      if (!step.evidence && observationError === null) {
        observationError = `credential-free suite step ${index + 1} failed before or after the test runner`;
      }
      break;
    }
  }

  if (server.listening) server.close();
  refuseRecreatedSocketPath();
  if (request.kind === "tests" && !listenerUnlinked && fs.existsSync(request.socketPath)) {
    try { fs.unlinkSync(request.socketPath); }
    catch (error) {
      observationError ??= `could not clean the proof socket: ${String(error && error.message)}`;
    }
  }

  return {
    ok: true,
    exit,
    signal,
    timedOut,
    out: Buffer.concat([...stdout, ...stderr]).toString("utf8"),
    testEvents: Buffer.concat(events).toString("utf8"),
    machineDiagnostics,
    machineOutput,
    observationError,
  };
}

try {
  jsonReply(await observe(await readRequest()));
} catch (error) {
  jsonReply({ ok: false, error: String(error && error.message) });
}
