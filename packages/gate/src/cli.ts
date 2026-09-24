#!/usr/bin/env node
/**
 * noa-gate CLI (spec §8). Subcommands:
 *
 *   noa-gate [serve]               boot the reference gate (loopback-by-default, D20) and print its
 *                                  banner. PINNED when NOA_GATE_ROSTER_FILE / NOA_GATE_KEY_FILE are
 *                                  set: a persistent gate key, identities only from the operator's
 *                                  roster, the HPKE display sealer wired (docs/gate-pinned-trust.md).
 *                                  Otherwise ALPHA-EPHEMERAL: a fresh self-minted trust root per boot
 *                                  and NO display sealer, so every hold is refused with
 *                                  DISPLAY_SEALER_UNCONFIGURED — alpha can sign nothing a human was shown.
 *   noa-gate hold-and-run ...      the exact-execution wrapper (D3/D14): freeze a command as a hold,
 *                                  wait for the human, reserve the grant, run the command, report.
 *                                  Exits 0 ONLY on EXECUTED; fail-closed non-zero on
 *                                  deny/expire/timeout/refusal/error (never runs an unapproved cmd).
 *   noa-gate keygen --key-file P --kid K
 *                                  create the persistent gate key (the ONLY minting path; an existing
 *                                  file is read, never overwritten) and print the roster `gate` member.
 *   noa-gate roster-check FILE [--key-file P]
 *                                  validate a roster exactly as `serve` would and print its digest.
 *                                  Never writes the state file and never listens. Run it as the gate's
 *                                  OS user: the owner rule is evaluated against the caller's uid.
 *
 * Any other subcommand exits 2 (UNKNOWN_SUBCOMMAND) without starting anything. Before pinned trust,
 * every unrecognized word booted `serve`, so a mistyped `roster-chek` would have started a gate.
 */

import { randomBytes } from "node:crypto";
import { describeThrown } from "noa-mcp-adapter-core/safe-throw";
import { loadOrCreateKeyFile } from "noa-mcp-adapter-core";
import { generateKeyPair } from "noa-approval-artifacts";
import { sealEncryptedDisplay } from "noa-signer";
import { spawnSync } from "node:child_process";
import { createGate } from "./server.js";
import {
  checkGateKey,
  createAlphaTrust,
  loadPinnedRoster,
  loadPinnedTrust,
  pinnedEnvironmentConflict,
  resolveTrustMode,
  type PinnedBoot,
  type PinnedBootCode,
} from "./trust.js";
import { isRosterId } from "./roster.js";
import { remoteExecutionSigner } from "./exec-signer.js";
import { hashSecret } from "./auth.js";
import { InMemoryStore } from "./store.js";
import type { DisplaySealer } from "./engine.js";
import { guard, HttpGateClient } from "./wrapper.js";

/** An operator-supplied value with no safe default: absent means refuse to start, never guess. */
function requireEnv(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`noa-gate serve: ${name} is required when NOA_GATE_GRANT_SIGNER_SOCKET is set`);
  return v;
}

/** A coded boot refusal: one line on stderr, exit 1, before anything listens. No fallback exists. */
function refuseBoot(code: PinnedBootCode, detail: string): never {
  process.stderr.write(`noa-gate: ${code}: ${detail}\n`);
  process.exit(1);
}

/**
 * The real HPKE display sealer (`noa-signer`), wired in PINNED mode only. Every field is copied
 * explicitly, so the sealer's TEST-ONLY `deterministic` member can never ride in from the engine's
 * argument object.
 *
 * NOT wired in alpha, deliberately: alpha's approver HPKE private half is discarded at
 * birth (`trust.ts`), so an alpha hold would carry a display no human can open while the environment's
 * approver key can still sign a decision for it — a blind approval path. Alpha's
 * DISPLAY_SEALER_UNCONFIGURED refusal is the fail-closed state and stays.
 */
const sealDisplayHpke: DisplaySealer = (a) => {
  const sealed = sealEncryptedDisplay({
    tenant: a.tenant,
    holdId: a.holdId,
    deferredReceiptHash: a.deferredReceiptHash,
    expiresAt: a.expiresAt,
    display: a.display,
    recipients: a.recipients.map((r) => ({ kid: r.kid, hpkePublicKey: r.hpkePublicKey })),
  });
  // The sealer's closed interface carries no index signature, the gate's wire type does; a spread is
  // the same members as a plain object. The engine re-verifies every member it relies on at egress.
  return { ...sealed };
};

interface ServeCommon {
  bindAddress: string;
  port: number;
  grantSignerSocket: string | undefined;
}

function newAgentKey(store: InMemoryStore): string {
  const apiKey = "noa_gateagent_" + randomBytes(24).toString("base64url");
  store.putAgent({ id: "agent-1", name: "dev-agent", apiKeyHash: hashSecret(apiKey), createdAt: Date.now() });
  return apiKey;
}

function onSignals(close: () => Promise<void>): void {
  const shutdown = (): void => void close().then(() => process.exit(0));
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

/** A usage refusal: one line on stderr and exit code 2. Nothing is started. */
function refuseUsage(command: string, detail: string): number {
  process.stderr.write(`noa-gate ${command}: UNKNOWN_ARGUMENT: ${detail}\n`);
  return 2;
}

async function serve(args: string[]): Promise<number | null> {
  // `serve` takes no arguments. One was once silently ignored, so `serve --roster-file X` booted the
  // self-minting alpha root for an operator who asked for a pinned one.
  if (args.length > 0) return refuseUsage("serve", `${JSON.stringify(args[0])}; serve takes no arguments (configuration is read from the environment)`);
  const bindAddress = process.env["NOA_GATE_BIND"] ?? "127.0.0.1";
  const port = Number.parseInt(process.env["NOA_GATE_PORT"] ?? "8899", 10);

  // ── THE AUTHORITY ROOT LEAVES THIS PROCESS ────────────────────────────────────────────────────
  // PROTECTED is the configuration you get by naming a running `noa-gate-grant-signer`; UNSAFE is
  // the one you have to type out. That order is deliberate and it is a correction: the first cut
  // shipped the in-process grant key as the silent default, which meant the posture NON-CLAIMS.md
  // calls the defect was what an operator got by saying nothing (adversarial review 2026-08-12).
  // It applies to BOTH trust modes: a pinned roster with a null executionSigner still has to say so.
  const grantSignerSocket = process.env["NOA_GATE_GRANT_SIGNER_SOCKET"];
  const unsafeInProcess = process.env["NOA_GATE_UNSAFE_IN_PROCESS_GRANT_KEY"] === "1";
  if (!grantSignerSocket && !unsafeInProcess) {
    throw new Error(
      "noa-gate serve: refusing to start with the grant-signing key on this process's heap. Either set " +
        "NOA_GATE_GRANT_SIGNER_SOCKET (plus, in alpha, NOA_GATE_GRANT_SIGNER_KID, NOA_GATE_GRANT_SIGNER_PUBLIC_KEY and the " +
        "NOA_GATE_APPROVER_* enrolment; in pinned mode, the roster's executionSigner), or state the development posture with " +
        "NOA_GATE_UNSAFE_IN_PROCESS_GRANT_KEY=1. See NON-CLAIMS.md, the authority-root corollary.",
    );
  }
  const common: ServeCommon = { bindAddress, port, grantSignerSocket: grantSignerSocket || undefined };

  // ── stages 0-1: which trust root. ANY pinned variable present means pinned, or refuse. ──────────
  const request = resolveTrustMode(process.env, typeof process.geteuid === "function");
  if ("code" in request) return refuseBoot(request.code, request.detail);
  if (request.mode === "alpha") {
    await serveAlpha(common);
    return null;
  }

  // ── stages 2-11: the pinned trust root. A refusal is final: there is no alpha fallback. ────────
  const boot = loadPinnedTrust({
    rosterFile: request.rosterFile,
    keyFile: request.keyFile,
    rosterSha256: request.rosterSha256,
    unsafeSameUid: request.unsafeSameUid,
    tenantEnv: process.env["NOA_GATE_TENANT"],
    grantSignerSocketSet: common.grantSignerSocket !== undefined,
    gateEuid: (process.geteuid as () => number)(),
    nowMs: Date.now(),
  });
  if (!boot.ok) return refuseBoot(boot.code, boot.detail);
  try {
    return await servePinned(boot, common);
  } catch (err) {
    // Anything that stops the boot after loading releases the high-water lock before the exit.
    boot.release();
    throw err;
  }
}

async function servePinned(boot: PinnedBoot, common: ServeCommon): Promise<number | null> {
  const { bindAddress, port } = common;
  // The signer's identity comes from the ROSTER (stage 10 already proved roster and socket agree), and
  // a signer we cannot reach, or that names itself differently, stops the boot here.
  // A configured socket without a pinned signer must never fall through to the in-process grant key.
  let executionSigner;
  if (common.grantSignerSocket !== undefined) {
    const pinnedSigner = boot.roster.executionSigner;
    if (pinnedSigner === null) {
      boot.release();
      return refuseBoot("ROSTER_EXEC_SIGNER_MISMATCH", "NOA_GATE_GRANT_SIGNER_SOCKET is set but the roster pins no executionSigner");
    }
    executionSigner = remoteExecutionSigner({
      socketPath: common.grantSignerSocket,
      expect: { kid: pinnedSigner.kid, publicKey: pinnedSigner.publicKey },
    });
  }
  const trust = boot.trust;
  const store = new InMemoryStore();
  const apiKey = newAgentKey(store);
  const gate = createGate({
    trust,
    store,
    config: { bindAddress, port },
    sealDisplay: sealDisplayHpke,
    ...(executionSigner ? { executionSigner } : { unsafeInProcessGrantKey: true as const }),
  });

  // ── stage 11 (write): the high-water mark advances only once everything else has passed. ──────
  const committed = boot.commitState();
  if (committed !== null) return refuseBoot(committed.code, committed.detail);

  const { address, port: boundPort } = await gate.listen();
  process.stdout.write(
    JSON.stringify(
      {
        service: "noa-gate",
        role: "trusted-signer",
        listening: `http://${address}:${boundPort}`,
        trustMode: "PINNED",
        tenant: trust.tenant,
        agentApiKey: apiKey,
        rosterDigest: boot.rosterDigest,
        rosterVersion: boot.roster.rosterVersion,
        rosterHighWater: boot.stateStatus,
        rosterExpiresAt: boot.roster.expiresAt,
        rosterCustody: boot.rosterCustody,
        epoch: { keyManifestVersion: trust.keyManifestVersion, keyManifestHash: trust.keyManifestHash },
        gateKid: trust.gate.kid,
        gatePublicKey: trust.gate.publicKey,
        executionSignerKid: trust.executionSigner?.kid ?? trust.gate.kid,
        grantKeyCustody: trust.executionSigner ? `out-of-process (${common.grantSignerSocket})` : "IN-PROCESS (see NON-CLAIMS.md)",
        activeApproverKid: boot.activeApproverKid,
        quorum: boot.roster.quorum,
        bootId: trust.bootId,
        displaySealer: "hpke",
      },
      null,
      2,
    ) + "\n",
  );
  onSignals(() => gate.close());
  return null;
}

/**
 * ALPHA-EPHEMERAL: a trust root minted for this process alone, approver enrolment from the
 * environment, and no display sealer (see `sealDisplayHpke`). Unchanged by pinned trust apart from the banner.
 */
async function serveAlpha(common: ServeCommon): Promise<void> {
  const tenant = process.env["NOA_GATE_TENANT"] ?? "alpha-tenant";
  // Three env vars, not one, and the two extra ones are the whole fix for two more findings:
  //   *_SIGNER_KID / *_SIGNER_PUBLIC_KEY — the signer's identity, from the OPERATOR. Asking the
  //     socket who it is and then minting a manifest naming that answer let anyone who could
  //     replace the listener publish themselves as the tenant's execution-signer.
  //   *_APPROVER_KID / *_APPROVER_PUBLIC_KEY / *_APPROVER_HPKE_PUBLIC_KEY — the phone's enrolled
  //     public half. Without it `createAlphaTrust` would GENERATE the approver key here, leaving
  //     the one signature the sidecar relies on inside the process it is defending against.
  let executionSigner;
  let approverPublicKey;
  if (common.grantSignerSocket) {
    const expectKid = requireEnv("NOA_GATE_GRANT_SIGNER_KID");
    const expectPublicKey = requireEnv("NOA_GATE_GRANT_SIGNER_PUBLIC_KEY");
    approverPublicKey = {
      kid: requireEnv("NOA_GATE_APPROVER_KID"),
      publicKey: requireEnv("NOA_GATE_APPROVER_PUBLIC_KEY"),
      hpkePublicKey: requireEnv("NOA_GATE_APPROVER_HPKE_PUBLIC_KEY"),
    };
    // Bound BEFORE the trust root is built: the manifest must name this kid as the tenant's only
    // execution-signer, and a signer we cannot reach must stop the boot rather than surface on the
    // first human approval.
    executionSigner = remoteExecutionSigner({
      socketPath: common.grantSignerSocket,
      expect: { kid: expectKid, publicKey: expectPublicKey },
    });
  }

  const trust = createAlphaTrust({
    tenant,
    ...(executionSigner ? { executionSigner: { kid: executionSigner.kid, publicKey: executionSigner.publicKey } } : {}),
    ...(approverPublicKey ? { approverPublicKey } : {}),
  });
  const store = new InMemoryStore();
  const apiKey = newAgentKey(store);

  const gate = createGate({
    trust,
    store,
    config: { bindAddress: common.bindAddress, port: common.port },
    ...(executionSigner ? { executionSigner } : { unsafeInProcessGrantKey: true as const }),
  });
  const { address, port: boundPort } = await gate.listen();
  process.stdout.write(
    JSON.stringify(
      {
        service: "noa-gate",
        role: "trusted-signer",
        listening: `http://${address}:${boundPort}`,
        trustMode: "ALPHA-EPHEMERAL",
        tenant,
        agentApiKey: apiKey,
        gateKid: trust.gate.kid,
        executionSignerKid: trust.executionSigner?.kid ?? trust.gate.kid,
        // Said out loud at boot, because "is the authority root in this process?" is the one
        // operational fact a reader of this output most needs and cannot otherwise see.
        grantKeyCustody: trust.executionSigner ? `out-of-process (${common.grantSignerSocket})` : "IN-PROCESS (alpha default; see NON-CLAIMS.md)",
        keyManifestVersion: trust.keyManifestVersion,
        bootId: trust.bootId,
        displaySealer: "none",
        note:
          "alpha: a fresh trust root is minted on every boot and no display sealer is wired, so every hold is refused " +
          "with DISPLAY_SEALER_UNCONFIGURED. Set NOA_GATE_ROSTER_FILE and NOA_GATE_KEY_FILE for a pinned gate " +
          "(docs/gate-pinned-trust.md).",
      },
      null,
      2,
    ) + "\n",
  );
  onSignals(() => gate.close());
}

/** Strict flag parsing for the operator subcommands: each flag once, with a value; nothing unknown. */
function parseFlags(args: string[], allowed: readonly string[]): { ok: true; flags: Record<string, string>; positional: string[] } | { ok: false; detail: string } {
  const flags: Record<string, string> = Object.create(null) as Record<string, string>;
  const positional: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i] as string;
    if (!a.startsWith("--")) {
      positional.push(a);
      continue;
    }
    const name = a.slice(2);
    if (!allowed.includes(name)) return { ok: false, detail: `UNKNOWN_ARGUMENT: unknown flag ${JSON.stringify(a)}` };
    if (Object.prototype.hasOwnProperty.call(flags, name)) return { ok: false, detail: `flag ${JSON.stringify(a)} given twice` };
    const v = args[i + 1];
    if (v === undefined || v.startsWith("--")) return { ok: false, detail: `flag ${JSON.stringify(a)} needs a value` };
    flags[name] = v;
    i++;
  }
  return { ok: true, flags, positional };
}

/**
 * `noa-gate keygen --key-file P --kid K` — the ONLY path that creates a gate key. Exclusive create
 * (O_EXCL, mode 0600) through the shared key-file loader; an existing file is read and printed, never
 * overwritten, and exits 1 when it holds a different kid. Prints the roster `gate` member; the private
 * key is never printed.
 */
function keygen(args: string[]): number {
  const usage = "usage: noa-gate keygen --key-file <path> --kid <kid>";
  const parsed = parseFlags(args, ["key-file", "kid"]);
  if (!parsed.ok || parsed.positional.length > 0) {
    process.stderr.write(`noa-gate keygen: ${parsed.ok ? `UNKNOWN_ARGUMENT: unexpected argument ${JSON.stringify(parsed.positional[0])}` : parsed.detail}; ${usage}\n`);
    return 2;
  }
  const keyFile = parsed.flags["key-file"];
  const kid = parsed.flags["kid"];
  if (keyFile === undefined || kid === undefined) {
    process.stderr.write(`noa-gate keygen: --key-file and --kid are both required; ${usage}\n`);
    return 2;
  }
  if (!isRosterId(kid)) {
    process.stderr.write("noa-gate keygen: --kid must be 1-64 characters of [a-z0-9-], first [a-z], last [a-z0-9]\n");
    return 2;
  }
  let key;
  try {
    key = loadOrCreateKeyFile({ keyFile, mintKeyPair: () => generateKeyPair(kid), callerLabel: "noa-gate keygen" });
  } catch (err) {
    process.stderr.write(`noa-gate keygen: GATE_KEY_FILE_UNSAFE: ${describeThrown(err)}\n`);
    return 1;
  }
  if (key.kid !== kid) {
    process.stderr.write(`noa-gate keygen: GATE_KEY_KID_MISMATCH: ${JSON.stringify(keyFile)} already holds kid ${JSON.stringify(key.kid)}, not ${JSON.stringify(kid)}; it was not changed\n`);
    return 1;
  }
  const problem = checkGateKey(key, { kid: key.kid, publicKey: key.publicKey });
  if (problem !== null) {
    process.stderr.write(`noa-gate keygen: ${problem.code}: ${problem.detail}\n`);
    return 1;
  }
  process.stdout.write(JSON.stringify({ gate: { kid: key.kid, publicKey: key.publicKey } }, null, 2) + "\n");
  return 0;
}

/**
 * `noa-gate roster-check FILE [--key-file P]` — stages 0-8 on the roster (and 9-11 with a key file,
 * read-only), under the same environment `serve` reads. Prints the digest `serve` prints.
 */
function rosterCheck(args: string[]): number {
  const usage = "usage: noa-gate roster-check <roster-file> [--key-file <path>]";
  const parsed = parseFlags(args, ["key-file"]);
  if (!parsed.ok || parsed.positional.length !== 1) {
    process.stderr.write(`noa-gate roster-check: ${parsed.ok ? (parsed.positional.length > 1 ? `UNKNOWN_ARGUMENT: unexpected argument ${JSON.stringify(parsed.positional[1])}` : "exactly one roster file is required") : parsed.detail}; ${usage}\n`);
    return 2;
  }
  const rosterFile = parsed.positional[0] as string;
  if (typeof process.geteuid !== "function") {
    process.stderr.write("noa-gate roster-check: PINNED_PLATFORM_UNSUPPORTED: this platform has no POSIX user ids\n");
    return 1;
  }
  // The same environment rules `serve` applies: a second identity source is refused here too, so a
  // roster that checks clean cannot then be refused by `serve` for an environment reason.
  const conflict = pinnedEnvironmentConflict(process.env);
  if (conflict !== null) {
    process.stderr.write(`noa-gate roster-check: ${conflict.code}: ${conflict.detail}\n`);
    return 1;
  }
  const common = {
    rosterFile,
    rosterSha256: process.env["NOA_GATE_ROSTER_SHA256"],
    unsafeSameUid: process.env["NOA_GATE_UNSAFE_ROSTER_SAME_UID"] === "1",
    tenantEnv: process.env["NOA_GATE_TENANT"],
    gateEuid: process.geteuid(),
    nowMs: Date.now(),
  };
  const keyFile = parsed.flags["key-file"];
  const result = keyFile === undefined
    ? loadPinnedRoster(common)
    : loadPinnedTrust({ ...common, keyFile, grantSignerSocketSet: Boolean(process.env["NOA_GATE_GRANT_SIGNER_SOCKET"]), lockState: false });
  if (!result.ok) {
    process.stderr.write(`noa-gate roster-check: ${result.code}: ${result.detail}\n`);
    return 1;
  }
  const r = result.roster;
  process.stdout.write(
    JSON.stringify(
      {
        rosterDigest: result.rosterDigest,
        rosterVersion: r.rosterVersion,
        tenant: r.tenant,
        rosterValidFrom: r.validFrom,
        rosterExpiresAt: r.expiresAt,
        epoch: r.epoch,
        gateKid: r.gate.kid,
        executionSignerKid: r.executionSigner?.kid ?? null,
        activeApproverKid: result.activeApproverKid,
        auditKid: r.audit.kid,
        quorum: r.quorum,
        rosterCustody: result.rosterCustody,
        checked: keyFile === undefined ? "roster" : "roster, key file and high-water state (read only)",
        ...("stateStatus" in result ? { rosterHighWater: result.stateStatus } : {}),
      },
      null,
      2,
    ) + "\n",
  );
  return 0;
}

function flag(args: string[], name: string): string | undefined {
  const i = args.indexOf(`--${name}`);
  return i >= 0 && i + 1 < args.length ? args[i + 1] : undefined;
}

/** The options `hold-and-run` accepts before `--`; each takes one value. */
const HOLD_AND_RUN_FLAGS = ["--url", "--key", "--canonical", "--risk", "--cwd", "--target-env"] as const;

async function holdAndRun(args: string[]): Promise<number> {
  const dashDash = args.indexOf("--");
  const options = dashDash < 0 ? args : args.slice(0, dashDash);
  for (let i = 0; i < options.length; i += 2) {
    const name = options[i] as string;
    if (!(HOLD_AND_RUN_FLAGS as readonly string[]).includes(name) || i + 1 >= options.length) {
      return refuseUsage("hold-and-run", `${JSON.stringify(name)} is not an option with a value (known: ${HOLD_AND_RUN_FLAGS.join(", ")}); the command goes after --`);
    }
  }
  const explicitUrl = flag(options, "url");
  const explicitKey = flag(options, "key");
  const environmentUrl = process.env["NOA_GATE_URL"];
  if ((options.includes("--url") && explicitKey === undefined) ||
    (explicitKey !== undefined && explicitUrl === undefined && environmentUrl !== undefined)) {
    process.stderr.write("hold-and-run: GATE_CREDENTIAL_SOURCE_MISMATCH; use NOA_GATE_URL with NOA_GATE_KEY, or provide both --url and --key\n");
    return 2;
  }
  const url = explicitUrl ?? environmentUrl ?? "http://127.0.0.1:8899";
  const key = explicitKey ?? process.env["NOA_GATE_KEY"];
  const canonical = flag(options, "canonical") ?? "noa.command.exec";
  const risk = flag(options, "risk") ?? "HIGH";
  const cwd = flag(options, "cwd") ?? process.cwd();
  const targetEnv = flag(options, "target-env") ?? "production";
  const cmd = dashDash >= 0 ? args.slice(dashDash + 1) : [];
  if (!key) {
    process.stderr.write("hold-and-run: --key (or NOA_GATE_KEY) is required\n");
    return 2;
  }
  if (cmd.length === 0) {
    process.stderr.write("hold-and-run: no command after `--`\n");
    return 2;
  }
  const [executable, ...argv] = cmd;

  const client = new HttpGateClient(url, key);
  const result = await guard({
    client,
    action: { canonical, riskClass: risk, reversible: false },
    params: { executable, argv, cwd, targetEnv, allowedEnvHash: null, stdinHash: null },
    idempotencyKey: randomBytes(12).toString("hex"),
    // ADR-0006-A part B — DISPATCH FROM WHAT WAS GRANTED, not from this closure's own locals.
    //
    // This executor used to run `executable`/`argv`/`cwd` captured from the enclosing scope: the same
    // values it PROPOSED, never the ones the gate derived, hashed, showed a human and bound into the
    // grant. Nothing forced the two to agree, and this is the flagship `noa hold-and-run` — the only
    // executor this project ships. An API whose sole shipped consumer ignores it is a display-only
    // surface (the shipped-surface rule), and it would have made the new command argument decorative on the very path
    // most likely to be copied by an integrator.
    //
    // The shape is CHECKED, not cast: `command.params` is typed `unknown` precisely so that a consumer
    // must look before it leaps. The values are deep-frozen by the wrapper, so reading them here is a
    // read of an immutable value rather than a second live read of a caller-owned object.
    execute: async (command) => {
      const p = command.params as { executable?: unknown; argv?: unknown; cwd?: unknown } | null;
      if (
        typeof p !== "object" || p === null ||
        typeof p.executable !== "string" || !Array.isArray(p.argv) || typeof p.cwd !== "string"
      ) {
        // `ok: false` is an UNVERIFIABLE self-report and the gate treats it as such — the outcome is
        // UNKNOWN_AFTER_DISPATCH, not a clean refusal. That is the documented cost of the executor
        // having no channel that says "I provably did nothing" (wrapper.ts, the dispatch invariant),
        // and it is correct: nobody but this closure observed that it refused.
        return { ok: false, detail: "granted command is not a shell-exec params object" };
      }
      const r = spawnSync(p.executable, p.argv as string[], { stdio: "inherit", cwd: p.cwd });
      return { ok: r.status === 0, detail: `exit ${r.status}` };
    },
  });

  process.stderr.write(`hold-and-run: ${result.outcome}${result.detail ? ` (${result.detail})` : ""}\n`);
  return result.outcome === "EXECUTED" ? 0 : 1;
}

/**
 * The subcommands this binary knows, as a closed table: a handler returns an exit code, or `null` when
 * the process keeps running (a listening gate). Nothing outside the table starts anything.
 */
type Subcommand = (rest: string[]) => Promise<number | null>;
const SUBCOMMANDS: Readonly<Record<string, Subcommand>> = Object.freeze(Object.assign(Object.create(null) as Record<string, Subcommand>, {
  serve: (rest: string[]) => serve(rest),
  "hold-and-run": (rest: string[]) => holdAndRun(rest),
  keygen: async (rest: string[]) => keygen(rest),
  "roster-check": async (rest: string[]) => rosterCheck(rest),
}));

async function main(): Promise<void> {
  const [, , sub = "serve", ...rest] = process.argv;
  const handler = Object.prototype.hasOwnProperty.call(SUBCOMMANDS, sub) ? SUBCOMMANDS[sub] : undefined;
  if (handler === undefined) {
    process.stderr.write(`noa-gate: UNKNOWN_SUBCOMMAND: ${JSON.stringify(sub)}; known: ${Object.keys(SUBCOMMANDS).join(", ")}\n`);
    process.exit(2);
  }
  const exitCode = await handler(rest);
  if (exitCode !== null) process.exit(exitCode);
}

main().catch((e) => {
  // BOUNDARY 2: `(e as Error).message` is a cast, not a check — the value decides what happens next,
  // and here "next" is the process's last act before exit(1). A throwing getter turned a clean
  // fail-closed exit into an unhandled rejection with a different exit code.
  process.stderr.write(`noa-gate: ${describeThrown(e)}\n`);
  process.exit(1);
});
