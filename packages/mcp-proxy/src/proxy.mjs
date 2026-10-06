#!/usr/bin/env node
/**
 * proxy.mjs — the CLI entrypoint an MCP host launches EXACTLY like it would launch the
 * downstream server directly, except wrapped:
 *
 *   Before:  { "command": "node", "args": ["demo-downstream.mjs"] }
 *   After:   { "command": "node", "args": ["proxy.mjs", "--", "node", "demo-downstream.mjs"] }
 *
 * Everything after the first bare `--` is the REAL downstream command, spawned exactly as the
 * host would have spawned it itself. The downstream file is never edited, never re-imported,
 * never made aware a proxy exists — the host's config line is the only thing that changes.
 *
 * `proxy.mjs init [--dir <path>] [--force]` is a SEPARATE subcommand (see src/init.mjs) that
 * scaffolds the human-approval gate's inputs (approval-rules.json, pending-store.jsonl, an
 * approver keypair) into a target directory. It is scaffolding, not activation — read init.mjs's
 * own doc comment before assuming a clean exit means anything is protected yet.
 *
 * `proxy.mjs verify-outcome <file> --keyring <file>` verifies OUTCOME receipts (the
 * `noa.mcp.outcome/0.1` lines --outcome-log writes) offline — see src/verify-outcome-cli.mjs.
 * DECISION receipts (--receipt-log) are verified with the `noa-receipt` CLI instead.
 *
 * Flags (all optional):
 *   --policy <file.json>       the `noa.policy/0.2` document that decides every tools/call (see
 *                              src/policy-file.mjs). Read and validated at startup, FAIL-CLOSED: an
 *                              unreadable, unparsable or invalid file stops the process with a stable
 *                              code (POLICY_UNREADABLE / POLICY_UNPARSABLE / POLICY_INVALID) before
 *                              any downstream is spawned. A tool the policy does not name is denied.
 *                              Without this flag the BUILT-IN DEMO policy (src/policy.mjs, written
 *                              for demo-downstream.mjs's three tools) is used, and the proxy says so
 *                              on stderr at startup.
 *   --session-id <id>          receipt-chain session id (default: a fresh randomUUID())
 *   --tenant <name>            receipt scope.tenant (default: "default-tenant")
 *   --agent-id <id>            STATIC receipt.agent.id for every call this process makes (default:
 *                              the session id, the prior behavior). Read ONLY from this flag/env —
 *                              never from a tool call's own arguments, so a host or downstream tool
 *                              can never spoof its own attribution.
 *   --receipt-log <path>       append each emitted DECISION receipt as one JSON line (JSONL), written
 *                              with a non-blocking fs.promises.appendFile so a slow disk never blocks
 *                              the event loop for other in-flight sessions.
 *   --outcome-log <path>       (R2) append each POST-execution OUTCOME receipt as one JSON line — the
 *                              signed attestation of what a tool call actually DID (success/error),
 *                              distinct from the pre-execution decision receipt in --receipt-log.
 *                              Written with the same non-blocking appender. Verify offline with
 *                              verifyOutcomeReceipt() against the --keyring-file.
 *   --http-port <n>            (R2) serve over HTTP+SSE (Streamable HTTP) on this port INSTEAD of
 *                              stdio — stdio stays the default when this is omitted. Each MCP session
 *                              gets its own downstream connection + receipt chain, fronted by the
 *                              exact same governed proxy as stdio (same fail-closed gate; the gate is
 *                              not forked per transport).
 *   --http-host <host>         (R2) bind address for --http-port (default 127.0.0.1 — loopback only;
 *                              set 0.0.0.0 deliberately to expose beyond localhost).
 *   --keyring-file <path>      write { [kid]: publicKey } once at startup, so an external verifier
 *                              can `verifyChain`/`verify` the receipt log independently of this
 *                              process.
 *   --key-file <path>          load a persisted signing identity from this path, or — if it
 *                              doesn't exist yet — generate one and write it here (mode 0600, since
 *                              it holds a private key). Without this flag, the prior behavior is
 *                              unchanged: a fresh Ed25519 keypair every process start (kid tied to
 *                              this run's session id). WITH it, restarting the proxy against the
 *                              SAME --key-file reuses the exact same kid — receipts emitted before
 *                              AND after a restart verify under that ONE signing identity/external
 *                              keyring. Honest limit: a restart still begins a NEW, distinct
 *                              receipt-chain SEGMENT (`scope.chain` differs — see
 *                              noa-mcp-adapter-core's createChainSessionStore, which mints a fresh
 *                              per-process-lifetime token specifically so a restarted process can
 *                              never collide with its pre-restart chain-id even when reusing the
 *                              same --session-id); it does NOT resume one continuous chain spanning
 *                              the restart. Each segment verifies independently on its own — group
 *                              receipts by `scope.chain` before calling `verifyChain()`, exactly as
 *                              noa-mcp-adapter-core's README documents. True cross-restart
 *                              continuity of ONE logical chain would additionally require
 *                              persisting the session's `{prev,seq}` state itself, which this
 *                              package does not do (see its "Honest limits" section). Alternative:
 *                              the NOA_MCP_PROXY_KEY_FILE env var (the flag wins if both are
 *                              given).
 *   --session-idle-ttl-ms <n>  override the session store's idle-TTL sweep (default: 1 hour;
 *                              see noa-mcp-adapter-core's createChainSessionStore).
 *   --max-sessions <n>         override the session store's max-sessions cap (default: 10,000).
 *   --session-dir <path>       opt-in file-backed session store (noa-mcp-adapter-core's
 *                              createFileSessionStore): persists each session's chain position to
 *                              disk under this directory, so a restart resumes the SAME chain
 *                              segment instead of starting a fresh one (unlike the default
 *                              in-memory store, which always mints a fresh segment on restart —
 *                              see this package's README "Honest limits"). Independent of
 *                              --key-file: --session-dir alone still generates a fresh signing
 *                              key every restart unless --key-file is ALSO given; combine both
 *                              for a fully restart-durable proxy. Only one live process may point
 *                              at a given --session-dir at a time (lockfile-enforced).
 *   --signer-socket <path>     use a remote signer (packages/signer-sidecar's client) reachable
 *                              at this Unix domain socket path instead of a local, in-process
 *                              private key — the private key never lives in THIS process when
 *                              this flag is given. Mutually exclusive with --key-file /
 *                              NOA_MCP_PROXY_KEY_FILE (the sidecar owns its own --key-file
 *                              independently). Fails closed at startup if the sidecar is
 *                              unreachable — see createRemoteSigner's own doc comment.
 *   --approval-rules <path>    JSON array of human-approval rules (adapter-core's approvalRules): a
 *                              matching tool call is HELD (DEFERRED), never forwarded, until a human
 *                              approves it out-of-band with `noa-approve`.
 *   --pending-store <path>     JSONL operational index of outstanding approvals the DEFERRED holds
 *                              are recorded into and `noa-approve` resolves against.
 *   --approver-keyring <path>  REQUIRED whenever --approval-rules/--pending-store is set: a
 *                              `{ [kid]: publicKey }` JSON of TRUSTED approver keys. An approval's
 *                              Ed25519 signature is verified against this before the held action is
 *                              adopted + forwarded — the proxy REFUSES TO START without it (a gate
 *                              that could adopt unverifiable approvals would be fail-open).
 *   --approver-identity <path> optional `{ [agentId]: kid[] }` identity manifest pinning which kid
 *                              may sign for the approval seat, so a co-trusted key cannot impersonate
 *                              the human approver.
 *
 * Fail-closed at startup: if the downstream command cannot be spawned or fails MCP
 * initialization, this process logs to stderr and exits non-zero WITHOUT ever starting to serve
 * the host — there is no partially-working proxy state. A downstream that has not answered MCP
 * initialize within DOWNSTREAM_INITIALIZE_TIMEOUT_MS (30 s) counts as failed.
 *
 * Lifecycle (stdio mode): the host closing stdin, SIGTERM/SIGINT/SIGHUP, the downstream connection
 * closing and every startup failure end in ONE shutdown path, which stops the downstream this
 * process started before exiting — see the stdio section of main().
 */
import { randomUUID } from "node:crypto";
import { promises as fsp } from "node:fs";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { generateKeyPair, createChainSessionStore, createFileSessionStore, loadOrCreateKeyFile, readConfigJson, writeConfigArtifact, requireValidApprovalRules, describeThrown, describeThrownDetailed } from "noa-mcp-adapter-core";
import { createProxyServer } from "./create-proxy-server.mjs";
import { TRANSFER_GUARD_POLICY } from "./policy.mjs";
import { runInitCli } from "./init.mjs";
import { loadPolicyFile, requireApprovalRulesCovered } from "./policy-file.mjs";
import { runVerifyOutcomeCli } from "./verify-outcome-cli.mjs";

import { intrinsics } from "noa-mcp-adapter-core";

// REDTEAM 2026-08-03 — bulk hardening of the published decision paths, same rationale as
// adapter-core: four CRITICALs in two days, every one a LIVE builtin an attacker replaces after
// module load. Auditing ~300 remaining flagged reads one at a time is a race against the next person
// who adds one, so the builtins come from the kernel's module-load capture whether or not each site
// is reachable today. Reachability is a property of the surrounding code, and that changes.
// `objectSetPrototypeOf` closes the WRITE half of the same argument (L11): `opts.keyFile = value`
// is a [[Set]] that walks the receiver's prototype chain, so an accessor on Object.prototype can
// swallow a parsed flag and answer the read with a path of its own choosing — with no builtin
// replaced at all. See scripts/lint-inert-containers.mjs.
const { isFiniteNumber, jsonParse, jsonStringify, arrayIndexOf, arraySlice, toNumber, strIncludes,
        objectSetPrototypeOf, objectDefineProperty } = intrinsics;

// Captured ONCE at module load, same reasoning as the intrinsics destructure just above: `process`,
// `Promise` and the timer functions have no wrapper in the shared intrinsics bundle (host objects /
// language builtins the kernel doesn't wrap), so they are captured locally here instead of read live
// from inside `main()` and its callbacks, which all run at CALL time, not load time.
const PROCESS = process;
const PROMISE = Promise;
const SET_TIMEOUT = setTimeout;
const CLEAR_TIMEOUT = clearTimeout;

// The downstream must answer MCP initialize within this bound, or the proxy fails closed: it stops
// the downstream and exits 1 without ever serving the host. Fixed and documented in the README.
// 30 s is half the MCP SDK client's own default request timeout (60 s), so a host built on that SDK
// gets this process's explicit refusal and exit rather than its own generic timeout, and it leaves
// room for a downstream launched through a package runner that fetches the server on first start.
const DOWNSTREAM_INITIALIZE_TIMEOUT_MS = 30_000;
// How long a shutdown waits, after the SDK transport's close() returns, for the child process to be
// reaped; and the bound on the whole shutdown, whatever happens beneath it.
const CHILD_REAP_WAIT_MS = 2_000;
const SHUTDOWN_BACKSTOP_MS = 10_000;

function parseArgs(argv) {
  const sepIndex = arrayIndexOf(argv, "--");
  if (sepIndex === -1) {
    throw new Error(
      "usage: proxy.mjs [--policy <file.json>] [--session-id <id>] [--tenant <name>] [--agent-id <id>] " +
        "[--receipt-log <path>] [--outcome-log <path>] [--keyring-file <path>] [--key-file <path>] [--signer-socket <path>] " +
        "[--session-idle-ttl-ms <n>] [--max-sessions <n>] [--session-dir <path>] " +
        "[--approval-rules <path>] [--pending-store <path>] [--approver-keyring <path>] [--approver-identity <path>] " +
        "[--http-port <n>] [--http-host <host>] " +
        "-- <downstream-command> [downstream-args...]\n" +
        "       proxy.mjs init [--dir <path>] [--force]   (scaffolds a starter policy and the approval-gate inputs — see init.mjs)\n" +
        "       proxy.mjs verify-outcome <outcome-receipts.jsonl> --keyring <keyring.json>",
    );
  }
  const own = arraySlice(argv, 0, sepIndex);
  const downstream = arraySlice(argv, sepIndex + 1);
  if (downstream.length === 0) throw new Error("proxy.mjs: no downstream command given after `--`");

  const opts = {
    policyFile: null,
    sessionId: null,
    tenant: "default-tenant",
    agentId: null,
    receiptLog: null,
    outcomeLog: null,
    keyringFile: null,
    keyFile: null,
    signerSocket: null,
    sessionIdleTtlMs: null,
    maxSessions: null,
    sessionDir: null,
    approvalRulesFile: null,
    pendingStore: null,
    approverKeyringFile: null,
    approverIdentityFile: null,
    httpPort: null,
    httpHost: "127.0.0.1",
  };
  // NULL-ROOTED BEFORE THE FIRST FLAG IS APPLIED (L11). Four of the fields below name the files that
  // decide who may approve (`--approver-keyring`, `--approver-identity`, `--approval-rules`) and
  // which key this proxy signs with (`--key-file`). Each assignment is a [[Set]] that walks the
  // prototype chain, so an accessor at e.g. `Object.prototype.approverKeyringFile` swallows the
  // operator's flag and answers every later read with a keyring the attacker chose — the flag looks
  // parsed, `--help` looks right, and no builtin was replaced. A null-prototype object has no chain.
  objectSetPrototypeOf(opts, null);
  for (let i = 0; i < own.length; i++) {
    const flag = own[i];
    const value = own[++i];
    if (flag === "--policy") {
      // Refused here rather than defaulted: `--policy` with no value (or given twice) must never
      // fall back to the demo policy — the operator asked for THEIR policy and would not get it.
      if (opts.policyFile !== null) throw new Error('proxy.mjs: [POLICY_UNREADABLE] "--policy" given more than once — pass exactly one policy file');
      if (value === undefined || value.length === 0) throw new Error('proxy.mjs: [POLICY_UNREADABLE] "--policy" needs a file path — pass --policy <file.json>');
      opts.policyFile = value;
    } else if (flag === "--session-id") opts.sessionId = value;
    else if (flag === "--tenant") opts.tenant = value;
    else if (flag === "--agent-id") opts.agentId = value;
    else if (flag === "--receipt-log") opts.receiptLog = value;
    else if (flag === "--outcome-log") opts.outcomeLog = value;
    else if (flag === "--http-port") opts.httpPort = toNumber(value);
    else if (flag === "--http-host") opts.httpHost = value;
    else if (flag === "--keyring-file") opts.keyringFile = value;
    else if (flag === "--key-file") opts.keyFile = value;
    else if (flag === "--signer-socket") opts.signerSocket = value;
    else if (flag === "--session-idle-ttl-ms") opts.sessionIdleTtlMs = toNumber(value);
    else if (flag === "--max-sessions") opts.maxSessions = toNumber(value);
    else if (flag === "--session-dir") opts.sessionDir = value;
    else if (flag === "--approval-rules") opts.approvalRulesFile = value;
    else if (flag === "--pending-store") opts.pendingStore = value;
    else if (flag === "--approver-keyring") opts.approverKeyringFile = value;
    else if (flag === "--approver-identity") opts.approverIdentityFile = value;
    else throw new Error(`proxy.mjs: unknown flag "${flag}"`);
  }
  return { opts, downstreamCommand: downstream[0], downstreamArgs: arraySlice(downstream, 1) };
}

/**
 * Loads a persisted `{ kid, privateKey, publicKey }` signing identity from `keyFile`, or generates
 * one and persists it if the file doesn't exist yet. Delegates the actual CWE-367/TOCTOU-hardened
 * load/create logic to noa-mcp-adapter-core's loadOrCreateKeyFile (moved there so
 * packages/signer-sidecar's sidecar.mjs can reuse the exact same hardening — see that module's
 * own docstring for the symlink/loose-permission guard detail). Without a `keyFile` at all, keeps
 * the prior behavior exactly: a fresh keypair every call, kid tied to this run's `sessionId`.
 */
function loadOrCreateSigner({ keyFile, sessionId }) {
  if (!keyFile) {
    const kp = generateKeyPair(`noa-mcp-proxy:${sessionId}`);
    return { kid: kp.kid, privateKey: kp.privateKey, publicKey: kp.publicKey };
  }
  return loadOrCreateKeyFile({
    keyFile,
    mintKeyPair: () => generateKeyPair(`noa-mcp-proxy:${randomUUID()}`),
    callerLabel: "proxy.mjs",
  });
}

/**
 * Serializes every append to ONE file path through a single promise chain, so concurrent sessions
 * writing to the SAME shared --receipt-log never interleave partial lines, while still using the
 * non-blocking fs.promises API (never fs.appendFileSync, which blocks the whole event loop for
 * every other in-flight session while the disk write completes).
 */
function createSequentialFileAppender(path) {
  let tail = PROMISE.resolve();
  return function append(line) {
    const next = tail.then(() => fsp.appendFile(path, line, "utf8"));
    // Decoupled always-settling continuation: one failed write must reject THIS call's own
    // promise (propagated back to create-proxy-server.mjs's onReceipt handling, which fails the
    // call closed) without poisoning the chain for the next queued append.
    tail = next.then(() => undefined, () => undefined);
    return next;
  };
}

async function main() {
  // `noa-mcp-proxy init [--dir <path>] [--force]` — a distinct subcommand, dispatched BEFORE
  // parseArgs (which requires the `--` downstream-command separator and would reject "init" as an
  // unknown flag). Scaffolds the human-approval gate's inputs; see src/init.mjs's own doc comment
  // for exactly what it does and does not do — it is NOT "one command and you're done". Statically
  // imported above (not a lazy `await import(...)`): init.mjs's only real dependencies
  // (noa-mcp-adapter-core's loadOrCreateKeyFile/generateKeyPair, ./policy.mjs) are ALREADY loaded
  // unconditionally by this file for the normal proxy path, so there is no lazy-load benefit to
  // defer for — unlike the genuinely optional noa-signer-sidecar/http-server.mjs imports below.
  //
  // `noa-mcp-proxy verify-outcome <file> --keyring <file>` is the other subcommand: offline
  // verification of outcome receipts; it never starts a proxy or spawns anything.
  const subcommand = PROCESS.argv[2];
  if (subcommand === "init" || subcommand === "verify-outcome") {
    const subArgs = arraySlice(PROCESS.argv, 3);
    PROCESS.exitCode = subcommand === "init" ? runInitCli(subArgs) : runVerifyOutcomeCli(subArgs);
    return;
  }

  const { opts, downstreamCommand, downstreamArgs } = parseArgs(arraySlice(PROCESS.argv, 2));

  // The policy is settled FIRST, before a key is loaded, a file written or a downstream spawned:
  // a policy file that cannot be used stops the process here (loadPolicyFile throws an error whose
  // message leads with its stable code, which main().catch below turns into exit 1).
  let policy;
  if (opts.policyFile !== null) {
    policy = loadPolicyFile(opts.policyFile);
  } else {
    policy = TRANSFER_GUARD_POLICY;
    // Never let a demo pass for production: one line, every start, on stderr (stdout is the MCP
    // channel in stdio mode).
    console.error(
      `noa-mcp-proxy: WARNING — no --policy given; using the built-in DEMO policy "${TRANSFER_GUARD_POLICY.id}" ` +
        "(written for the bundled demo tools only; every other tool is denied). Pass --policy <file.json> for your own tools.",
    );
  }
  // ── CONFIG ARTIFACTS ARE READ THROUGH A DESCRIPTOR, NEVER BY PATH (CWE-59/CWE-367) ────────────
  // MEASURED 2026-08-12 against the shipped CLI: with a path-based `readFileSync`, replacing
  // `approval-rules.json` with a SYMLINK to a file containing `[]` turned the human-approval gate
  // OFF and a `transfer_funds` of 7000 (above the configured 5000 threshold) was forwarded and
  // EXECUTED with no human approval; replacing `approver-keyring.json` with a symlink to an
  // attacker keyring let the attacker sign their own approval and the identical retry EXECUTED.
  // In most real deployments the agent process CAN WRITE ITS OWN WORKING DIRECTORY, so planting
  // that symlink is inside the threat model, not outside it. readConfigJson (adapter-core's
  // config-artifact.mjs) opens with O_NOFOLLOW, fstats the DESCRIPTOR (regular file, owned by this
  // process or root, not group/other-writable) and reads from that same descriptor — the pathname
  // never gets a second chance to decide which bytes this process trusts.
  //
  // ── AND THE BYTES ARE THEN STRUCTURALLY VALIDATED, BEFORE ANY DOWNSTREAM IS SPAWNED ───────────
  // MEASURED 2026-08-12 against the shipped CLI, with the symlink guard above already in place: a
  // REGULAR, mode-0600, correctly-owned `approval-rules.json` containing `{}` — valid JSON, not an
  // array — was accepted, and the same 7000 transfer was FORWARDED AND EXECUTED with no human
  // approval. `readConfigJson` decides WHICH BYTES are read; it has nothing to say about whether
  // those bytes are a rule set. `matchApprovalRule` answers `null` for a non-array, `null` means
  // "no rule matched", and "no rule matched" means forward — so a two-byte file switched the gate
  // off. This removes the need for the conspicuous `[]` payload the symlink attack needed: ANY
  // content-write primitive, including the same-uid rewrite NON-CLAIMS.md NC-6.9 names as an
  // accepted residual, was a full bypass. `requireValidApprovalRules` refuses a non-array AND every
  // malformed rule — in FULL, never partially — so the process exits non-zero here rather than
  // serving the host with the gate silently absent. createProxyServer/startHttpProxy apply the
  // identical check on their own inputs (a library consumer must not be able to skip it by not
  // using this CLI); this call is what gives the OPERATOR the flag-named error.
  // THE RETURN VALUE is what travels on: a frozen, inert snapshot compiled from own data properties
  // only. Keeping the parsed object instead would keep the bug — a rule set whose fields are
  // inherited or computed, or one mutated after this line, was measured executing the same
  // unapproved 7000-unit transfer (see `requireValidApprovalRules`' own note).
  let approvalRules;
  if (opts.approvalRulesFile) {
    approvalRules = requireValidApprovalRules(
      readConfigJson(opts.approvalRulesFile, { label: "--approval-rules" }),
      `--approval-rules "${opts.approvalRulesFile}"`,
    );
  }

  // A policy file and an approval rule set are checked AGAINST EACH OTHER before anything starts: an
  // exact-match approval rule for a tool the policy never names holds nothing (see
  // policy-file.mjs's requireApprovalRulesCovered). A policy with no approval rules at all is a
  // legitimate setup, but never a silent one.
  if (opts.policyFile !== null) {
    if (approvalRules !== undefined) {
      requireApprovalRulesCovered(policy, approvalRules, `--approval-rules "${opts.approvalRulesFile}"`);
    } else {
      console.error("noa-mcp-proxy: WARNING — --policy given without --approval-rules; no call will be held for human approval.");
    }
  }

  const sessionId = opts.sessionId ?? randomUUID();
  const keyFile = opts.keyFile ?? PROCESS.env.NOA_MCP_PROXY_KEY_FILE ?? null;

  if (opts.signerSocket && keyFile) {
    throw new Error(
      "proxy.mjs: --signer-socket and --key-file (or NOA_MCP_PROXY_KEY_FILE) are mutually exclusive — " +
        "the sidecar owns its OWN --key-file independently; pick exactly one signing mode.",
    );
  }

  let signer;
  let signerPublicKey;
  if (opts.signerSocket) {
    // noa-signer-sidecar is an OPTIONAL dependency, imported LAZILY here — ONLY on the opt-in
    // --signer-socket branch. The default (in-process key) path never touches it, so the common
    // install can omit the sidecar package entirely (e.g. before it is even published to the
    // registry). If --signer-socket is used but the package is absent, surface an actionable
    // install hint rather than a raw ERR_MODULE_NOT_FOUND. (client.mjs imports only node:net, so an
    // ERR_MODULE_NOT_FOUND naming this specifier can ONLY mean the package itself is missing; any
    // other resolution failure is genuinely unexpected and propagates unchanged.)
    let createRemoteSigner;
    try {
      ({ createRemoteSigner } = await import("noa-signer-sidecar/client.mjs"));
    } catch (err) {
      // BOUNDARY 2: this branch DECIDES control flow from the thrown value's own fields. A throwing
      // `code`/`message` getter here did not garble a message — it escaped the handler and skipped
      // the "the sidecar package is not installed" guidance entirely.
      const d = describeThrownDetailed(err);
      if (d.code === "ERR_MODULE_NOT_FOUND" && strIncludes(d.message, "noa-signer-sidecar")) {
        throw new Error(
          "proxy.mjs: --signer-socket requires the optional 'noa-signer-sidecar' package, which is not installed — " +
            "install it with: npm install noa-signer-sidecar",
        );
      }
      throw err;
    }
    // Fail-closed at startup: an unreachable/misconfigured sidecar must stop this process before
    // it ever starts serving the host — see createRemoteSigner's own "fail closed AT
    // CONSTRUCTION" doc comment. main().catch() below turns this rejection into the same
    // non-zero-exit fatal path every other startup failure already uses.
    const remoteSigner = await createRemoteSigner({ socketPath: opts.signerSocket });
    signer = { kid: remoteSigner.kid, sign: remoteSigner.sign };
    signerPublicKey = remoteSigner.publicKey;
  } else {
    const kp = loadOrCreateSigner({ keyFile, sessionId });
    signer = { kid: kp.kid, privateKey: kp.privateKey };
    signerPublicKey = kp.publicKey;
  }
  // Through a verified descriptor (adapter-core's config-artifact.mjs): a symlink planted at
  // --keyring-file would otherwise turn this routine startup write into "clobber any file this
  // process can write" — the same primitive loadOrCreateKeyFile already refuses for --key-file.
  if (opts.keyringFile) writeConfigArtifact(opts.keyringFile, jsonStringify({ [signer.kid]: signerPublicKey }), { label: "--keyring-file", mode: 0o644 });

  const sessionStoreOptions = {
    ...(opts.sessionIdleTtlMs != null && isFiniteNumber(opts.sessionIdleTtlMs) ? { idleTtlMs: opts.sessionIdleTtlMs } : {}),
    ...(opts.maxSessions != null && isFiniteNumber(opts.maxSessions) ? { maxSessions: opts.maxSessions } : {}),
  };
  const store = opts.sessionDir
    ? createFileSessionStore(opts.sessionDir, sessionStoreOptions)
    : createChainSessionStore(sessionStoreOptions);

  const appendReceiptLine = opts.receiptLog ? createSequentialFileAppender(opts.receiptLog) : null;
  const onReceipt = appendReceiptLine
    ? (_sessionId, receipt) => appendReceiptLine(jsonStringify(receipt) + "\n")
    : undefined;

  // R2 — outcome-receipt JSONL, same non-blocking serialized appender as --receipt-log.
  const appendOutcomeLine = opts.outcomeLog ? createSequentialFileAppender(opts.outcomeLog) : null;
  const onOutcome = appendOutcomeLine
    ? (_sessionId, outcomeReceipt) => appendOutcomeLine(jsonStringify(outcomeReceipt) + "\n")
    : undefined;

  // A FRESH downstream transport per call — a transport can only be connected once. Stdio serves a
  // single session (one factory call); HTTP calls it once per MCP session.
  const makeDownstreamTransport = () => new StdioClientTransport({ command: downstreamCommand, args: downstreamArgs });

  // FAIL-CLOSED at startup: the human-approval gate (--approval-rules and/or --pending-store) can
  // adopt an approver's ALLOWED receipt onto the live chain and forward the held action. Adopting
  // one requires authenticating the approver's signature, which needs a trusted approver keyring.
  // Refuse to start the gate without --approver-keyring rather than ever adopt an unverifiable
  // approval (createProxyServer enforces the same invariant; this gives a precise CLI-level error).
  if ((opts.approvalRulesFile || opts.pendingStore) && !opts.approverKeyringFile) {
    throw new Error(
      "proxy.mjs: --approval-rules/--pending-store enable the human-approval gate, which adopts an approver's signed ALLOWED receipt onto the live chain — refusing to start without --approver-keyring <path> (a { kid: publicKey } JSON of trusted approver keys) to verify approval signatures (fail-closed).",
    );
  }
  let approverKeyring;
  if (opts.approverKeyringFile) approverKeyring = readConfigJson(opts.approverKeyringFile, { label: "--approver-keyring" });
  let approverIdentityManifest;
  if (opts.approverIdentityFile) approverIdentityManifest = readConfigJson(opts.approverIdentityFile, { label: "--approver-identity" });

  // Everything except the transport wiring is identical for stdio and HTTP — the gate is NOT forked
  // per transport. This one config object feeds both paths.
  const gateConfig = {
    signer,
    policy,
    store,
    tenant: opts.tenant,
    agentId: opts.agentId ?? undefined,
    onReceipt,
    onOutcome,
    approvalRules,
    pendingStorePath: opts.pendingStore ?? undefined,
    approverKeyring,
    approverIdentityManifest,
  };

  // R2 — HTTP+SSE transport (opt-in via --http-port). Stdio stays the default. startHttpProxy is
  // imported LAZILY so the default stdio path never loads the HTTP server module (nor its transitive
  // @hono/node-server chain).
  if (opts.httpPort != null && isFiniteNumber(opts.httpPort)) {
    const { startHttpProxy } = await import("./http-server.mjs");
    const http = await startHttpProxy({
      host: opts.httpHost,
      port: opts.httpPort,
      makeDownstreamTransport,
      sessionIdGenerator: () => randomUUID(),
      ...gateConfig,
    });
    // stderr (never stdout — stdout is reserved for any future stdio use); an operator sees where it bound.
    console.error(`noa-mcp-proxy: HTTP+SSE (Streamable HTTP) listening on ${http.url}`);
    return; // stay alive serving HTTP — no stdio front transport is attached in this mode
  }

  // Default: stdio front transport, one session for this process.
  //
  // ── ONE SHUTDOWN PATH ──────────────────────────────────────────────────────────────────────────
  // MEASURED on 0.5.0 (Node 22, a healthy downstream after a full MCP handshake): the proxy was
  // still running 8 s after the host closed its stdin; after SIGTERM the proxy died and a downstream
  // that does not exit on stdin EOF lived on with parent pid 1; a downstream that never answered
  // initialize held the proxy for the SDK's implicit 60 s and was then left running the same way.
  //
  // The host closing stdin, SIGTERM/SIGINT/SIGHUP, the downstream connection closing, a downstream
  // that misses the initialize bound and a failed connect now all call shutdown(), which acts once.
  // It stops reading the host, then closes the downstream through the SDK transport. That close()
  // drops the transport's process handle before anything else, so every later send is refused
  // ("Not connected") and nothing is forwarded once shutdown has begun; it then ends the child's
  // stdin, sends SIGTERM after 2 s and SIGKILL after 2 s more. The child is signalled only through
  // that transport's own ChildProcess handle, which Node stops using once the child is reaped, and
  // never by a bare pid, so no other process can be hit. The proxy exits after the child has been
  // reaped (or the bound has passed): 0 after the host closed stdin, 128+n after signal n, 1 on
  // every other path. No session state is ended here, so a --session-dir store keeps its on-disk
  // position exactly as before and a restart still resumes the same chain segment.
  const downstreamTransport = makeDownstreamTransport();
  let shuttingDown = false;
  let connected = false;
  let initializeTimer;
  let markDownstreamClosed;
  const downstreamClosed = new PROMISE((resolve) => {
    markDownstreamClosed = resolve;
  });
  const shutdown = (line, exitCode) => {
    if (shuttingDown) return;
    shuttingDown = true;
    CLEAR_TIMEOUT(initializeTimer);
    console.error(line);
    PROCESS.stdin.pause();
    SET_TIMEOUT(() => PROCESS.exit(exitCode), SHUTDOWN_BACKSTOP_MS);
    // Read before close(), which clears it: null when no child was spawned or it has already closed.
    const childRunning = downstreamTransport.pid !== null;
    const exit = () => PROCESS.exit(exitCode);
    downstreamTransport
      .close()
      .then(() => (childRunning ? PROMISE.race([downstreamClosed, new PROMISE((resolve) => SET_TIMEOUT(resolve, CHILD_REAP_WAIT_MS))]) : undefined))
      .then(exit, exit);
  };
  // Defined BEFORE connect: the SDK's Protocol.connect keeps an onclose handler that is already on
  // the transport and calls it first whenever the child process closes, during connect or after it.
  // An own data property (no [[Set]], so no prototype-chain accessor can swallow it — L11), writable
  // because Protocol.connect then replaces it with its wrapper.
  objectDefineProperty(downstreamTransport, "onclose", {
    value: () => {
      markDownstreamClosed();
      shutdown(
        connected
          ? "noa-mcp-proxy: fatal — the downstream MCP connection closed; stopping (fail closed)"
          : "noa-mcp-proxy: fatal — could not establish the downstream MCP connection: the downstream process exited before MCP initialize completed",
        1,
      );
    },
    writable: true,
    enumerable: true,
    configurable: true,
  });
  // Exit 128 + the POSIX signal number (SIGHUP 1, SIGINT 2, SIGTERM 15).
  const onSignal = (signal, exitCode) => shutdown(`noa-mcp-proxy: received ${signal}; stopping the downstream and exiting`, exitCode);
  PROCESS.on("SIGTERM", () => onSignal("SIGTERM", 143));
  PROCESS.on("SIGINT", () => onSignal("SIGINT", 130));
  PROCESS.on("SIGHUP", () => onSignal("SIGHUP", 129));
  initializeTimer = SET_TIMEOUT(
    () => shutdown(`noa-mcp-proxy: fatal — the downstream did not answer MCP initialize within ${DOWNSTREAM_INITIALIZE_TIMEOUT_MS} ms; stopping it (fail closed, nothing was served)`, 1),
    DOWNSTREAM_INITIALIZE_TIMEOUT_MS,
  );

  let proxy;
  try {
    proxy = await createProxyServer({
      sessionId,
      downstreamTransport,
      ...gateConfig,
    });
  } catch (err) {
    // Fail-closed at startup: never expose a half-connected proxy to the host.
    shutdown(`noa-mcp-proxy: fatal — could not establish the downstream MCP connection: ${describeThrown(err)}`, 1);
    return;
  }
  CLEAR_TIMEOUT(initializeTimer);
  // A signal or the initialize bound may have started a shutdown while connect was finishing.
  if (shuttingDown) return;
  connected = true;

  // The SDK's StdioServerTransport reads stdin but never reacts to its end, so the host closing
  // stdin (the MCP stdio way to ask a server to stop) is handled here. Registered before the
  // transport starts reading, so an end that is already pending is not missed.
  PROCESS.stdin.once("end", () => shutdown("noa-mcp-proxy: the host closed stdin; stopping the downstream and exiting", 0));
  const frontTransport = new StdioServerTransport();
  await proxy.server.connect(frontTransport);
}

main().catch((err) => {
  console.error(`noa-mcp-proxy: fatal — ${describeThrown(err)}`);
  PROCESS.exit(1);
});
