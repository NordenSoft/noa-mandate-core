#!/usr/bin/env node
/**
 * init.mjs — `noa-mcp-proxy init`: scaffolds the artifacts the R4 human-approval gate needs to
 * START, into a target directory.
 *
 * THIS IS SCAFFOLDING, NOT ACTIVATION. Do not read a clean exit from this command as "the gate is
 * now protecting anything" — it is not, until every one of the following is also true:
 *   1. an MCP host's config actually launches `proxy.mjs` wrapping your real downstream, pointed at
 *      the files this command writes (see this package's README, "Human-approval gate (R4)" and
 *      "Run it yourself");
 *   2. the generated `policy.json` and `approval-rules.json` name YOUR tools — pass them with
 *      `--allow-tool`, `--approval-tool` and `--block-tool`; the default placeholders match nothing
 *      you own, so until then every one of your tools is denied; and
 *   3. a real HUMAN runs `noa-approve` out-of-band for every held call, from a separate terminal,
 *      holding the approver private key this command mints — that human's judgment is the control;
 *      this package only proves, cryptographically, what they decided, after the fact; and
 *   4. the agent RETRIES the identical held call once approved — approval does not itself re-execute
 *      anything.
 * "One command and you're done" is a claim this project's own review explicitly rejected; do not
 * reintroduce it in help text, a commit message, or documentation that wraps this command. Nothing
 * generated here is described as "unforgeable" or "cannot be bypassed" — see NON-CLAIMS.md and
 * THREAT-MODEL.md before relying on any of it.
 *
 * Generates, under --dir (default "."):
 *   policy.json             A STARTER `noa.policy/0.2` document for `--policy` (src/policy.mjs's
 *                            `starterPolicy()`): one tool allowed, one tool allowed only after a human
 *                            approves it (paired with the matching rule in approval-rules.json), one
 *                            tool blocked, every other tool denied. The three tool names come from
 *                            --allow-tool / --approval-tool / --block-tool; without them they are
 *                            PLACEHOLDERS that match nothing, so every real tool is denied.
 *                            JSON has no comments and the policy grammar is closed, so the
 *                            explanation lives in the rule ids and in the printed next steps.
 *   approval-rules.json     A starter rule set (src/policy.mjs's `starterApprovalRules()`): ONE rule
 *                            holding every call of policy.json's approval tool, built from the SAME
 *                            name, so the two files cannot disagree. (A hand edit that renames the
 *                            tool in only one file leaves a dead approval rule, which the proxy
 *                            refuses to start with — POLICY_APPROVAL_MISMATCH.)
 *   pending-store.jsonl      The empty JSONL operational index --pending-store points at. Empty and
 *                            "does not exist yet" fold to the identical state (see adapter-core's
 *                            pending-store.mjs) — creating it here is a real, inspectable starting
 *                            point, not a magic trick.
 *   approver-key.json        A FRESH Ed25519 signing identity for the human-approver seat, written
 *                            mode 0600 through noa-mcp-adapter-core's `loadOrCreateKeyFile` — the
 *                            SAME CWE-367/TOCTOU-hardened helper packages/signer-sidecar's sidecar
 *                            uses, never a hand-rolled `writeFileSync`. Hand this path to
 *                            `noa-approve --key-file` and NOWHERE else — whoever holds it IS the
 *                            approval seat, in full.
 *   approver-keyring.json    The PUBLIC `{ kid: publicKey }` derived from approver-key.json — what
 *                            `--approver-keyring` feeds the proxy so it can authenticate that seat's
 *                            signature. Sharing this file is fine; sharing approver-key.json is the
 *                            same as handing over the approval seat itself.
 *
 * Refuses to silently overwrite: the pre-flight check runs as ONE BATCH, over all five paths,
 * BEFORE any write begins — so a directory where NONE of the five is occupied gets all five
 * written, and a directory where ANY of the five is already occupied (a regular file, a
 * directory, or a symlink — dangling or not; see the CWE-367 note below) refuses the run before
 * touching anything, unless --force is given, in which case all five are regenerated fresh
 * (including a BRAND NEW approver identity — any approval-in-flight signed under the old one
 * stops verifying against the new keyring).
 *
 * Honest limit on that guarantee: the pre-flight check is atomic as a CHECK, not as a WRITE. Once
 * writing begins, the five files are still created one at a time; a failure partway through
 * (a disk error, or a file appearing at one of the five paths in the window between the
 * pre-flight check and that specific write — the same TOCTOU class CWE-367 names) can leave
 * earlier files in this run on disk and later ones missing. On any write failure this prints
 * exactly which of the five were confirmed written before the failure, rather than claiming
 * either "all five" or "none" by default.
 *
 * CWE-367 (symlink / TOCTOU): every one of the five writes below uses the SAME
 * `O_CREAT|O_EXCL|O_NOFOLLOW` guard, applied uniformly rather than only on the one file that
 * happens to hold key material. `O_EXCL` alone already makes the OS refuse to create through a
 * PRE-EXISTING symlink at the target path — dangling or not, per POSIX open(2) — independently of
 * where the link points; `O_NOFOLLOW` is belt-and-suspenders on platforms that support it. For
 * approver-key.json specifically, the actual write still goes through
 * noa-mcp-adapter-core's `loadOrCreateKeyFile` (mode 0600, the same helper packages/signer-sidecar
 * uses) rather than the local helper below — that helper carries its own, independently-audited
 * version of this exact guard; the local helper here exists because no equivalent is exported from
 * noa-mcp-adapter-core for non-key files (checked: index.mjs exports nothing narrower than the
 * key-file loader for a single-file exclusive create).
 */
import { mkdirSync, lstatSync, openSync, writeFileSync, closeSync, unlinkSync, realpathSync, constants as fsConstants } from "node:fs";
import { join, resolve as resolvePath } from "node:path";
import { randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";
import { loadOrCreateKeyFile, generateKeyPair, validateApprovalRules, assertValidPolicy, describeThrown, thrownCode, isEntryPoint, intrinsics } from "noa-mcp-adapter-core";
import { starterPolicy, starterApprovalRules, STARTER_TOOL_NAMES } from "./policy.mjs";

// Builtins taken from the kernel's module-load capture rather than read live, matching every other
// file in this TCB (see proxy.mjs's own REDTEAM 2026-08-03 note): a decision path — and refusing to
// write through a symlink onto the gate's own trust anchor IS one — must not resolve `.filter`,
// `.push`, `JSON.stringify` etc. through a prototype slot an attacker in this realm could replace.
// `objectSetPrototypeOf` + `INERT_ARRAY_PROTOTYPE` close the WRITE half of the same argument
// (L11): capturing `push` protects the METHOD, not the RECEIVER, and push is defined as
// Set(O, "0", v) — a [[Set]] that walks the receiver's chain to the mutable Object.prototype.
const { jsonStringify, arrayPush, objectSetPrototypeOf, objectFreeze, INERT_ARRAY_PROTOTYPE } = intrinsics;

// Captured ONCE at module load — every `process.std*.write` inside a function called later reads
// this local binding, never the live global. `process` itself has no wrapper in the shared
// intrinsics bundle (it is a host object, not a JS-spec builtin the kernel wraps), so it is
// captured locally here, the same way, for the same reason: a value read before this module
// finishes evaluating can no longer be repointed by anything that runs after.
const PROCESS = process;

const GENERATED = Object.freeze(["policy.json", "approval-rules.json", "pending-store.jsonl", "approver-key.json", "approver-keyring.json"]);

const HELP = `usage: noa-mcp-proxy init [--dir <path>] [--allow-tool <name>] [--approval-tool <name>]
                          [--block-tool <name>] [--force]

Scaffolds policy.json (a starter --policy: one allowed tool, one tool held for a human, one blocked
tool, every other tool denied), plus approval-rules.json, pending-store.jsonl, approver-key.json and
approver-keyring.json (the inputs the human-approval gate --approval-rules / --pending-store /
--approver-keyring needs) into --dir (default: the current directory), then prints the one-line
command that starts the proxy with them. This is scaffolding, not activation: it does not wire an
MCP host and does not run any approval — see this package's README, "Use your own tools".

  --dir <path>             target directory (created if missing; default ".")
  --allow-tool <name>      your tool the policy allows (default placeholder: ${STARTER_TOOL_NAMES.allowed})
  --approval-tool <name>   your tool that runs only after a human approves it, written into BOTH
                           policy.json and approval-rules.json (default placeholder: ${STARTER_TOOL_NAMES.needsApproval})
  --block-tool <name>      your tool the policy blocks (default placeholder: ${STARTER_TOOL_NAMES.blocked})
  --force        overwrite existing generated files instead of refusing (regenerates the approver
                 identity too — anything approved under the old one stops verifying)
  --help, -h     print this message
`;

/**
 * True if ANYTHING sits at `path` — a regular file, a directory, or a symlink (dangling or not).
 * Deliberately `lstatSync`, never `existsSync`/`statSync`: both of those FOLLOW a symlink and
 * report "nothing here" for a DANGLING one (the target doesn't exist, so the query about the
 * target says false) — which is exactly backwards for a pre-flight occupancy check: the pathname
 * itself is occupied by the link regardless of what, if anything, it points at. `lstatSync` looks
 * at the link itself and never follows it.
 */
function pathOccupied(path) {
  try {
    lstatSync(path);
    return true;
  } catch (err) {
    if (thrownCode(err) === "ENOENT") return false;
    throw err; // anything else (EACCES, ...) is a real problem, not "free to write here"
  }
}

/**
 * ROUND 2 / MEDIUM 6 FIX helper: removes `path` ONLY when `force` is true, and treats "already
 * gone" (ENOENT) as success rather than an error — the directory-check above already refused any
 * target `unlinkSync` could never succeed on (a directory), so by the time this runs, a real
 * failure here is a genuine, unexpected problem, not routine housekeeping. Called immediately
 * before recreating that SAME target (never as a separate batch pass) so a later target's failure
 * can never destroy an earlier target that was never actually touched.
 */
function removeIfForced(path, force) {
  if (!force) return;
  try {
    unlinkSync(path);
  } catch (err) {
    if (thrownCode(err) !== "ENOENT") throw err;
  }
}

/**
 * Creates a BRAND-NEW file at `path` and writes `content` to it, refusing outright if anything
 * already sits there (see the module doc-comment's CWE-367 note for why `O_CREAT|O_EXCL` is the
 * control, not just this function's own existence). Throws with a clear, greppable message on
 * EEXIST/ELOOP; any other open/write failure propagates as-is (converted to a description by the
 * caller via `describeThrown`, per this package's thrown-value-handling boundary).
 *
 * ROUND 2 / MEDIUM 7 FIX: `O_CREAT` makes the file exist the moment `openSync` succeeds — BEFORE
 * a single byte of `content` is written. An independent review measured that a write failure after that point
 * (reproduced with `EFBIG`; any `writeFileSync` failure is the same shape) left an EMPTY file on
 * disk while the caller's own bookkeeping said "0 files were written" — the on-disk reality and
 * the printed claim disagreed. The write is now wrapped so a failure `unlinkSync`s the just-created
 * file (best-effort — a failed cleanup does not hide the ORIGINAL error) before re-throwing, so the
 * invariant callers rely on stays true: after this function either returns (full content present)
 * or throws (path is exactly as it was before the call — nothing, not something half-written).
 *
 * ROUND 2 / LOW 8 FIX: `mode` is now a parameter, not a hardcoded `0o644`. The pending store holds
 * tenant/session/action metadata, approval tickets and free-text denial reasons — `init.mjs`'s
 * caller now asks for `0o600` for that file, not the public-document default.
 */
export function createFileExclusive(path, content, mode = 0o644) {
  const flags = fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | (fsConstants.O_NOFOLLOW ?? 0);
  let fd;
  try {
    fd = openSync(path, flags, mode);
  } catch (err) {
    const code = thrownCode(err);
    if (code === "EEXIST" || code === "ELOOP") {
      throw new Error(`"${path}" already exists or is a symlink -- refusing to write through it (CWE-367 symlink-attack guard)`);
    }
    throw err;
  }
  try {
    writeFileSync(fd, content, "utf8");
  } catch (err) {
    try {
      unlinkSync(path);
    } catch {
      // Best-effort: the ORIGINAL write failure is what the caller needs to see and act on: it is
      // re-thrown below regardless of whether cleanup itself succeeded.
    }
    throw err;
  } finally {
    closeSync(fd);
  }
}

/**
 * ROUND 2 / HIGH 4 FIX. `O_NOFOLLOW` on each of the five writes above protects only the FINAL path
 * component — `--dir root/parent-link/child` still resolves through `parent-link` if it is a
 * symlink, because `mkdirSync`/`openSync` follow every ANCESTOR component the same way a plain
 * shell `cd` would. An independent review measured this placing all five artifacts, including the private key,
 * outside the requested tree while every message still printed the harmless-looking lexical path.
 *
 * Fails closed if the REAL (symlink-resolved) location of `dir` differs from its LEXICAL
 * (unresolved) absolute path — i.e. if any component along the way, at the time this runs, was a
 * symlink. `dir` must already exist (call this AFTER `mkdirSync`) for `realpathSync` to resolve it.
 */
function assertNoAncestorSymlink(dir) {
  const lexical = resolvePath(dir);
  let real;
  try {
    real = realpathSync(dir);
  } catch (err) {
    throw new Error(`noa-mcp-proxy init: could not resolve "${dir}" to check for a symlinked ancestor (${describeThrown(err)})`);
  }
  if (real !== lexical) {
    throw new Error(
      `noa-mcp-proxy init: "${dir}" resolves through a symlink to "${real}" — refusing to write outside the ` +
        `requested directory. Point --dir directly at the real location, not through a symlinked ancestor.`,
    );
  }
}

/**
 * ROUND 2 / CRITICAL 3 FIX. POSIX mode bits (`0600`) are not the whole access-control picture on
 * macOS: a directory carrying an INHERITABLE ACL (`chmod +a "everyone allow read,file_inherit,...`)
 * propagates that ACL to a file created inside it REGARDLESS of the mode the creator requested, and
 * neither `stat`'s mode field nor a plain `ls -l` reveals it — `ls -le` (or an ACL-aware API) is the
 * only way to see it. An independent review measured a file reporting `-rw-------` that was still readable by
 * `everyone` via exactly this mechanism. Theft of the approver key is full approval authority, so
 * this strips any ACL unconditionally after creating the key and then VERIFIES none remains —
 * fail-closed (throws) rather than silently trusting that the strip worked.
 *
 * Scoped to `darwin`: this specific mode-bits-vs-ACL gap is a macOS (NFSv4-style ACL) mechanism.
 * Linux's separate, OPTIONAL POSIX ACL subsystem is not inherited onto new files by default and
 * requires an explicit `setfacl -d` the operator would have to have deliberately configured — a
 * materially different, unmeasured threat this fix does not claim to cover.
 */
function stripInheritedAclOrFail(path) {
  if (PROCESS.platform !== "darwin") return;
  try {
    execFileSync("/bin/chmod", ["-N", path], { stdio: "pipe" });
  } catch (err) {
    throw new Error(`noa-mcp-proxy init: could not strip a possible inherited ACL from "${path}" (${describeThrown(err)}) — refusing to leave a key whose real readability could not be confirmed`);
  }
  let lsOut;
  try {
    lsOut = execFileSync("/bin/ls", ["-le", path], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  } catch (err) {
    throw new Error(`noa-mcp-proxy init: could not verify "${path}" carries no ACL after stripping (${describeThrown(err)})`);
  }
  let nonEmptyLines = 0;
  let lineHasContent = false;
  for (let i = 0; i < lsOut.length; i++) {
    const c = lsOut[i];
    if (c === "\n") {
      if (lineHasContent) nonEmptyLines++;
      lineHasContent = false;
    } else if (c !== " " && c !== "\t" && c !== "\r") {
      lineHasContent = true;
    }
  }
  if (lineHasContent) nonEmptyLines++;
  // `ls -le` prints exactly ONE line (the ordinary long-format line) when there is no ACL, and one
  // ADDITIONAL line per ACL entry when there is. More than one line means the strip did not fully
  // work (or something re-added an entry) — fail closed rather than report success on a key that
  // may still be readable by more than its owner.
  if (nonEmptyLines > 1) {
    throw new Error(`noa-mcp-proxy init: "${path}" still carries an ACL after stripping — refusing to treat mode 0600 as private (real output:\n${lsOut})`);
  }
}

/**
 * ROUND 2 / CRITICAL 1 FIX. `noa-mcp-adapter-core`'s `loadOrCreateKeyFile` is LOAD-*or*-create, not
 * create-only: if a valid, correctly-permissioned key materializes at `keyFile` in the window
 * between this package's own preflight check and this call (two OTHER files are written
 * synchronously in between — a real window, not a theoretical one), the LOAD branch returns that
 * key WITHOUT ever invoking `mintKeyPair` — silently adopting whatever identity is sitting there.
 * An independent review reproduced this racing both a fresh `init` and `--force`: both exited 0 having adopted an
 * attacker-planted `kid`.
 *
 * This wraps the SAME hardened helper (never a hand-rolled key write — the file's own doc-comment
 * already explains why `loadOrCreateKeyFile` is preferred for the private key specifically) with a
 * verification: the caller-supplied `mintKeyPair` callback sets a local flag when — and only when —
 * IT actually ran. If it did not run, the LOAD branch was taken, meaning something this process did
 * not mint is sitting at `keyFile` — refuse rather than adopt it, regardless of how it got there.
 * Also strips/verifies any inherited ACL on the freshly-created key (CRITICAL 3, above) before
 * returning it as trustworthy.
 */
export function mintApproverIdentityExclusive(keyFile) {
  let minted = null;
  const kp = loadOrCreateKeyFile({
    keyFile,
    mintKeyPair: () => {
      minted = generateKeyPair(`noa-mcp-proxy-init:approver:${randomUUID()}`);
      return minted;
    },
    callerLabel: "noa-mcp-proxy init",
  });
  if (minted === null) {
    throw new Error(
      `"${keyFile}" already exists — this process did NOT mint the identity now sitting there (a race, or something else wrote it between this run's own preflight check and this step). Refusing to adopt an approver identity this process cannot vouch for.`,
    );
  }
  stripInheritedAclOrFail(keyFile);
  return kp;
}

/**
 * ROUND 2 / LOW 9 FIX. Wraps `s` in POSIX single-quotes for safe interpolation into the illustrative
 * shell commands this file prints, escaping any embedded single quote the standard `'\''` way. An
 * index loop (not `.replace`/`.split`) — both are prototype dispatches on this decision path, same
 * reasoning as `joinLines` below.
 */
function shellQuote(s) {
  let out = "'";
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    out += c === "'" ? "'\\''" : c;
  }
  return out + "'";
}

/**
 * Renders `items` as one indented line per entry — replaces the `.map(...).join("")` shape used
 * throughout this file's messages. `.map`/`.join` are BOTH prototype dispatches an attacker could
 * rewrite (L2/L8's own DISPATCH_METHODS list), and an index loop needs no wrapper import at all for
 * a use this small and local.
 */
function joinLines(items) {
  let out = "";
  for (let i = 0; i < items.length; i++) out += `  ${items[i]}\n`;
  return out;
}

function parseArgs(argv) {
  // NULL-ROOTED BEFORE THE FIRST FLAG IS APPLIED (L11). `--dir` decides where this command mints the
  // approver private key and writes the PUBLIC keyring the proxy calls its trust anchor. An accessor
  // at `Object.prototype.dir` swallows `opts.dir = value` and answers every later read with the
  // attacker's directory — the same class as the symlink-redirect this file already defends against,
  // reached through the option object instead of the filesystem.
  const opts = { dir: ".", force: false, help: false, allowed: null, needsApproval: null, blocked: null };
  objectSetPrototypeOf(opts, null);
  const TOOL_FLAGS = { "--allow-tool": "allowed", "--approval-tool": "needsApproval", "--block-tool": "blocked" };
  objectSetPrototypeOf(TOOL_FLAGS, null);
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    const toolField = TOOL_FLAGS[flag];
    if (toolField !== undefined) {
      const value = argv[++i];
      if (value === undefined || value.length === 0 || value[0] === "-") throw new Error(`noa-mcp-proxy init: "${flag}" requires a tool name`);
      if (opts[toolField] !== null) throw new Error(`noa-mcp-proxy init: "${flag}" given more than once`);
      opts[toolField] = value;
    } else if (flag === "--dir") {
      const value = argv[++i];
      if (value === undefined) throw new Error('noa-mcp-proxy init: "--dir" requires a value');
      opts.dir = value;
    } else if (flag === "--force") {
      opts.force = true;
    } else if (flag === "--help" || flag === "-h") {
      opts.help = true;
    } else {
      throw new Error(`noa-mcp-proxy init: unknown flag "${flag}" (see --help)`);
    }
  }
  // One name per role: the same tool both allowed and blocked (or both held and allowed) would make
  // the starter's meaning depend on rule order, which is not something a starter file should hide.
  const names = {
    allowed: opts.allowed ?? STARTER_TOOL_NAMES.allowed,
    needsApproval: opts.needsApproval ?? STARTER_TOOL_NAMES.needsApproval,
    blocked: opts.blocked ?? STARTER_TOOL_NAMES.blocked,
  };
  objectSetPrototypeOf(names, null);
  if (names.allowed === names.needsApproval || names.allowed === names.blocked || names.needsApproval === names.blocked) {
    throw new Error("noa-mcp-proxy init: --allow-tool, --approval-tool and --block-tool must name three different tools");
  }
  opts.names = objectFreeze(names);
  return opts;
}

function nextStepsMessage({ dir, names, policyPath, rulesPath, pendingStorePath, approverKeyPath, approverKeyringPath }) {
  // Absolute paths in everything meant to be copied: an MCP host starts the proxy from its OWN
  // working directory, not this one. The last four flags are not generated here: the proxy creates
  // them on first start (its own signing key, kept across restarts so keyring.json stays valid, and
  // the two receipt logs `verify-outcome` / `noa-receipt` check against that keyring).
  const abs = {
    policy: resolvePath(policyPath),
    rules: resolvePath(rulesPath),
    pending: resolvePath(pendingStorePath),
    key: resolvePath(approverKeyPath),
    keyring: resolvePath(approverKeyringPath),
  };
  const { allowed, needsApproval, blocked } = names;
  const placeholders = allowed === STARTER_TOOL_NAMES.allowed || needsApproval === STARTER_TOOL_NAMES.needsApproval || blocked === STARTER_TOOL_NAMES.blocked;
  // One list feeds both the shell line and the MCP config: flag/value pairs, then the downstream.
  const flagPairs = [
    "--policy", abs.policy,
    "--approval-rules", abs.rules,
    "--pending-store", abs.pending,
    "--approver-keyring", abs.keyring,
    "--key-file", resolvePath(join(dir, "proxy-key.json")),
    "--keyring-file", resolvePath(join(dir, "keyring.json")),
    "--receipt-log", resolvePath(join(dir, "decisions.jsonl")),
    "--outcome-log", resolvePath(join(dir, "outcomes.jsonl")),
  ];
  const downstream = ["--", "node", "/path/to/your-server.js"];
  let shellArgs = "";
  const proxyArgs = [];
  objectSetPrototypeOf(proxyArgs, INERT_ARRAY_PROTOTYPE);
  for (let i = 0; i < flagPairs.length; i++) {
    shellArgs += ` ${i % 2 === 1 ? shellQuote(flagPairs[i]) : flagPairs[i]}`;
    arrayPush(proxyArgs, flagPairs[i]);
  }
  for (let i = 0; i < downstream.length; i++) {
    shellArgs += ` ${downstream[i]}`;
    arrayPush(proxyArgs, downstream[i]);
  }
  const configArgs = jsonStringify(proxyArgs);
  return `noa-mcp-proxy init: wrote ${GENERATED.length} files to "${dir}":
  ${policyPath}
      starter policy: ${allowed} is allowed, ${needsApproval} needs a human's approval, ${blocked} is
      blocked, every other tool is denied.${placeholders ? " Placeholder names match none of your tools:\n      re-run with --allow-tool/--approval-tool/--block-tool <your tool> (and --force)." : ""}
  ${rulesPath}
      approval rule: hold every ${needsApproval} call for a human (the same name as in policy.json)
  ${pendingStorePath}
      empty operational index for outstanding approvals
  ${approverKeyPath}
      PRIVATE key (mode 0600) for the human-approver seat — pass to \`noa-approve --key-file\` ONLY
  ${approverKeyringPath}
      PUBLIC key derived from the file above — this is what --approver-keyring feeds the proxy

Start the proxy in front of your MCP server (put your server's own command after --):

  noa-mcp-proxy${shellArgs}

Or add it to your agent's MCP config ("mcpServers"):

  "my-tools": {
    "command": "noa-mcp-proxy", "args": ${configArgs}
  }

When a ${needsApproval} call is held, the agent gets an error carrying a receipt id. A human approves
it from a SEPARATE terminal, then the agent retries the IDENTICAL call (approving does not itself
run anything):

  noa-approve approve --id <receiptId> --by you@example.com --pending-store ${shellQuote(abs.pending)} --key-file ${shellQuote(abs.key)}

This is scaffolding, not activation: nothing is protected until your MCP host launches the proxy
with these files and the placeholder names are your real tool names. No claim here is "unforgeable"
or "cannot be bypassed". Read NON-CLAIMS.md and THREAT-MODEL.md
(https://github.com/NordenSoft/noa-mandate-core) before relying on this for anything that matters.
`;
}


/**
 * Runs one `init` invocation. Returns an exit code (0/1) — NEVER throws, NEVER calls
 * `process.exit` — mirroring adapter-core's `runApproveCli` so this is directly unit-testable
 * in-process (see test/init.test.mjs).
 */
export function runInitCli(argv) {
  let opts;
  try {
    opts = parseArgs(argv);
  } catch (err) {
    PROCESS.stderr.write(`${describeThrown(err)}\n`);
    return 1;
  }
  if (opts.help) {
    PROCESS.stdout.write(HELP);
    return 0;
  }

  const dir = opts.dir;
  const policyPath = join(dir, "policy.json");
  const rulesPath = join(dir, "approval-rules.json");
  const pendingStorePath = join(dir, "pending-store.jsonl");
  const approverKeyPath = join(dir, "approver-key.json");
  const approverKeyringPath = join(dir, "approver-keyring.json");
  const targets = { policyPath, rulesPath, pendingStorePath, approverKeyPath, approverKeyringPath };

  try {
    mkdirSync(dir, { recursive: true });
  } catch (err) {
    PROCESS.stderr.write(`noa-mcp-proxy init: could not create "${dir}" (${describeThrown(err)})\n`);
    return 1;
  }

  // ROUND 2 / HIGH 4 FIX: refuse if `dir` resolves through a symlinked ANCESTOR directory — see
  // assertNoAncestorSymlink's own doc-comment. Checked ONCE, right after the directory is known to
  // exist, rather than re-derived per target below (the five target paths are already computed
  // relative to this SAME `dir`, so one check here covers all five).
  try {
    assertNoAncestorSymlink(dir);
  } catch (err) {
    PROCESS.stderr.write(`${describeThrown(err)}\n`);
    return 1;
  }

  // Refuse the WHOLE run before writing anything if any target already exists, unless --force.
  // Checked as a batch (not "refuse the first one hit and leave the rest half-written") — a
  // partial scaffold silently mixed with pre-existing files is worse than a clean refusal.
  // `pathOccupied` (lstat-based) catches a symlink here too, dangling or not — see the module
  // doc-comment's CWE-367 note; `existsSync` would miss a dangling one. `pathOccupied` can itself
  // throw on a non-ENOENT lstat failure (e.g. EACCES on a parent directory) — caught HERE so that
  // failure reaches the caller as a normal exit-1 report, honoring this function's own "never
  // throws" contract, rather than escaping uncaught. An index loop (not `.filter`) over a plain
  // array (not `for…of`) — both are prototype/iterator dispatches on this decision path.
  const allTargets = [policyPath, rulesPath, pendingStorePath, approverKeyPath, approverKeyringPath];
  // Inert before the first write (L11): `preexisting.length > 0` is the refusal, and a swallowed
  // FIRST element leaves the count intact while `joinLines` reports the attacker's getter value —
  // the refusal message would then name a file that was never in the way.
  const preexisting = [];
  objectSetPrototypeOf(preexisting, INERT_ARRAY_PROTOTYPE);
  try {
    for (let i = 0; i < allTargets.length; i++) {
      if (pathOccupied(allTargets[i])) arrayPush(preexisting, allTargets[i]);
    }
  } catch (err) {
    PROCESS.stderr.write(`noa-mcp-proxy init: could not check "${dir}" for existing files (${describeThrown(err)})\n`);
    return 1;
  }
  if (preexisting.length > 0 && !opts.force) {
    PROCESS.stderr.write(
      `noa-mcp-proxy init: refusing to overwrite ${preexisting.length} existing file(s) in "${dir}":\n` +
        joinLines(preexisting) +
        `Pass --force to regenerate all ${GENERATED.length} files (this MINTS A NEW approver identity — anything\n` +
        `approved under the old one stops verifying against the new keyring), or move them aside first.\n`,
    );
    return 1;
  }
  // ROUND 2 / MEDIUM 6 FIX (part 1): refuse the WHOLE run, before touching ANYTHING, if any
  // preexisting target is something --force could never turn back into a generated file (a
  // directory sitting where a file belongs). An independent review measured the OLD code deleting the rules,
  // pending store and private key, in that order, before discovering the 4th target could not be
  // removed as a file — stranding the operator with the old identity destroyed and nothing new.
  if (opts.force) {
    for (let i = 0; i < preexisting.length; i++) {
      let st;
      try {
        st = lstatSync(preexisting[i]);
      } catch (err) {
        PROCESS.stderr.write(`noa-mcp-proxy init: could not check "${preexisting[i]}" before --force (${describeThrown(err)})\n`);
        return 1;
      }
      if (st.isDirectory()) {
        PROCESS.stderr.write(
          `noa-mcp-proxy init: --force cannot replace "${preexisting[i]}" — it is a DIRECTORY, not a file. ` +
            `Refusing the whole run before touching anything else; remove it by hand first, then re-run.\n`,
        );
        return 1;
      }
    }
  }

  // Self-check the starter files against the SAME validators the proxy runs at load time
  // (validateApprovalRules for --approval-rules, the kernel's assertValidPolicy for --policy) — a
  // generator that ships a file it has never validated is exactly the kind of "trust me" this
  // package exists to replace.
  const policyText = jsonStringify(starterPolicy(opts.names), null, 2) + "\n";
  try {
    assertValidPolicy(policyText);
  } catch (err) {
    PROCESS.stderr.write(`noa-mcp-proxy init: internal error — this package's own starter policy failed validation (${describeThrown(err)})\n`);
    return 1;
  }
  const validation = validateApprovalRules(starterApprovalRules(opts.names));
  if (!validation.ok) {
    PROCESS.stderr.write(
      `noa-mcp-proxy init: internal error — this package's own starter approval rules failed validation:\n${joinLines(validation.errors)}`,
    );
    return 1;
  }

  // Written one at a time (this is where the "checked as one batch, written sequentially" honest
  // limit from the module doc-comment applies) — `confirmed` tracks exactly which of the five
  // landed before any failure, so a partial-write report never has to guess or overclaim.
  //
  // ROUND 2 / MEDIUM 6 FIX (part 2): under --force, each target's OLD file is removed IMMEDIATELY
  // BEFORE that SAME target is recreated — never all five removed upfront. A failure at step N
  // therefore leaves steps 1..N-1 holding their NEW content and steps N..5 holding their OLD
  // (untouched, still-working) content — never "all five destroyed, nothing replaced".
  // Inert before the first write (L11): this list is the partial-progress report a failed scaffold
  // hands the operator. A swallowed element makes it name the wrong file, which is the one thing
  // this list exists to get right.
  const confirmed = [];
  objectSetPrototypeOf(confirmed, INERT_ARRAY_PROTOTYPE);
  try {
    removeIfForced(policyPath, opts.force);
    createFileExclusive(policyPath, policyText);
    arrayPush(confirmed, policyPath);

    removeIfForced(rulesPath, opts.force);
    createFileExclusive(rulesPath, jsonStringify(starterApprovalRules(opts.names), null, 2) + "\n");
    arrayPush(confirmed, rulesPath);

    removeIfForced(pendingStorePath, opts.force);
    // ROUND 2 / LOW 8 FIX: mode 0600, not the generic 0644 — this file holds tenant/session/action
    // metadata, approval tickets and free-text denial reasons, not public configuration.
    createFileExclusive(pendingStorePath, "", 0o600);
    arrayPush(confirmed, pendingStorePath);

    removeIfForced(approverKeyPath, opts.force);
    // ROUND 2 / CRITICAL 1 + CRITICAL 3 FIX: mintApproverIdentityExclusive (not a raw
    // loadOrCreateKeyFile call) refuses to adopt whatever is sitting at this path unless THIS call
    // is what minted it, and strips/verifies any inherited ACL before returning — see its own
    // doc-comment.
    const approverKp = mintApproverIdentityExclusive(approverKeyPath);
    arrayPush(confirmed, approverKeyPath);

    removeIfForced(approverKeyringPath, opts.force);
    createFileExclusive(approverKeyringPath, jsonStringify({ [approverKp.kid]: approverKp.publicKey }, null, 2) + "\n");
    arrayPush(confirmed, approverKeyringPath);
  } catch (err) {
    PROCESS.stderr.write(
      `noa-mcp-proxy init: could not write generated files (${describeThrown(err)})\n` +
        (confirmed.length > 0
          ? `${confirmed.length} of ${GENERATED.length} file(s) WERE written before this failure (not all-or-nothing once writing starts — see init.mjs's doc-comment):\n${joinLines(confirmed)}`
          : `0 of ${GENERATED.length} files were written.\n`),
    );
    return 1;
  }

  // Only reached once EVERY one of the five literal paths below was freshly created (never
  // followed through a symlink — createFileExclusive would have thrown first) — so this message
  // is never printed for a run that actually wrote somewhere else.
  PROCESS.stdout.write(nextStepsMessage({ dir, names: opts.names, ...targets }));
  return 0;
}

export const GENERATED_FILE_NAMES = GENERATED;

// Symlink-safe entry check (adapter-core's isEntryPoint): a raw `import.meta.url === file://argv[1]`
// comparison never matches when this file is reached through a symlink, and the body was skipped.
if (isEntryPoint(import.meta.url)) {
  process.exit(runInitCli(process.argv.slice(2)));
}
