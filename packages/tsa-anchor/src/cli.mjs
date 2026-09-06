#!/usr/bin/env node
/**
 * noa-tsa — independent anchoring for noa-receipt witness anchors (opt-in, offline).
 *
 *   noa-tsa stamp       --anchors <anchors.json> --tsa-url <url> [--out <path>] [--no-cert-req] [--no-nonce]
 *   noa-tsa verify      --anchors <anchors.json> --tsr <tsr.json> <TSA verification flags>
 *   noa-tsa fork-scan   --anchors <pool.json> --trust-set <trust-set.json> [--chain <receipts.json>] [--tsr <tsr.json>]
 *   noa-tsa corroborate --checkpoint <cp.json> --anchors <pool.json> --trust-set <trust-set.json>
 *                       [--now <rfc3339> --max-age-ms <n>] [--tsr <tsr.json> <TSA verification flags>]
 *
 * `stamp` requests ONE RFC 3161 timestamp per DISTINCT anchor in <anchors.json> (keyed by the
 * anchor's own hash — see anchor-hash.mjs — so two anchors over the same frontier from different
 * witnesses get separate stamps) and writes a {anchorHash -> stamp record} sidecar map; it NEVER
 * modifies <anchors.json>. `verify` authenticates every token against explicit caller trust,
 * revocation, policy, and clock inputs and exits non-zero if ANY anchor is unstamped or unverified.
 *
 * `fork-scan` is the MONITOR (equivocation.mjs): it reads a pool of PUBLISHED anchors and reports
 * signed contradictions — one identity, two histories. It needs no presented head and no private
 * state. `--chain` additionally compares the pool against the chain the prover presented, which is
 * what catches a retroactive edit that also extended the chain. `corroborate` asks whether a v0.1
 * checkpoint's endorsed head was independently observed by a quorum of pinned witnesses.
 *
 * Hostile-input hardened: input files are read with a size cap and parsed by noa-receipt's own
 * hardened safeParse.
 *
 * Exit codes: 0 OK · 1 MISMATCH (verify: >=1 anchor unstamped/mismatched; corroborate: quorum not
 * met) · 2 TRANSPORT (stamp: TSA request failed) · 3 MALFORMED (bad JSON/DER input) · 4 USAGE ·
 * 5 EQUIVOCATION (a signed contradiction was found) · 7 RESOURCE_LIMIT (authenticated verification
 * exceeded its declared unique-anchor, OpenSSL-process, or aggregate-deadline bound).
 */
import { readSync, writeFileSync, openSync, fstatSync, closeSync, constants as fsConstants } from "node:fs";
import { safeParse, frozenTable, verifyChain, intrinsics } from "noa-receipt";
import { stampAnchor } from "./client.mjs";
import {
  createVerificationResourceBudget,
  DEFAULT_VERIFICATION_COMMAND_TIMEOUT_MS,
  MAX_VERIFICATION_COMMAND_TIMEOUT_MS,
  MAX_VERIFICATION_UNIQUE_ANCHORS,
  MIN_VERIFICATION_COMMAND_TIMEOUT_MS,
  OPENSSL_PROCESS_BUDGET_PER_STAMP,
  verifyStamp,
} from "./verify.mjs";
import { anchorHash } from "./anchor-hash.mjs";
import { scanForEquivocation, checkpointCorroboration, historyFromReceipts, receiptCount, rfc3339ToMs } from "./equivocation.mjs";

const MAX_FILE_BYTES = 64 * 1024 * 1024;
// Captured at load, and the exit table frozen + null-rooted (ADR §5.6). The exit code IS the
// verdict as a pipeline consumes it, so a rewritable EXIT.EQUIVOCATION would turn a detected
// fork into a silent success for every caller at once.
const { setHas, setAdd, newSet, newMap, mapGet, mapHas, mapSet, arrayLength, arrayPush, arraySlice, isArray, isSafeInteger, strStartsWith, toNumber, isFiniteNumber, jsonStringify } = intrinsics;
const EXIT = frozenTable({ OK: 0, MISMATCH: 1, TRANSPORT: 2, MALFORMED: 3, USAGE: 4, EQUIVOCATION: 5, NO_CLEAN_RESULT: 6, RESOURCE_LIMIT: 7 });

// Authenticated verification is five synchronous OpenSSL processes per unique anchor. A fixed
// unique-input ceiling bounds process creation and makes an oversized request a refusal rather
// than a silently truncated verification. The deadline override deliberately reuses verifyStamp's
// existing, reviewed 100..30000 ms timeout range; the anchor ceiling has no CLI override.
function usage(msg) {
  if (msg) process.stderr.write(`error: ${msg}\n`);
  process.stderr.write(
    "usage: noa-tsa stamp --anchors <anchors.json> --tsa-url <url> [--out <path>] [--no-cert-req] [--no-nonce]\n" +
      "       noa-tsa verify --anchors <anchors.json> --tsr <tsr.json> <TSA verification flags>\n" +
      "       noa-tsa fork-scan --anchors <pool.json> --trust-set <trust-set.json> [--chain <receipts.json>] [--tsr <tsr.json> <TSA verification flags>]\n" +
      "       noa-tsa corroborate --checkpoint <cp.json> --anchors <pool.json> --trust-set <trust-set.json>\n" +
      "                           [--now <rfc3339> --max-age-ms <n>] [--tsr <tsr.json> <TSA verification flags>]\n" +
      "TSA verification flags: --openssl <absolute-path> --tsa-trust-roots <pem> --tsa-policy <oid>\n" +
      "                        --tsa-crls <pem> --tsa-now <rfc3339> --tsa-max-future-skew-ms <0..300000>\n" +
      "                        [--tsa-untrusted <intermediate-pem>]\n" +
      "verification resource flag (verify, or monitor with --tsr): [--tsa-command-timeout-ms <100..30000>]\n",
  );
  process.exit(EXIT.USAGE);
}

/**
 * ONE fatal-exit path, rather than a `process.stderr.write` + `process.exit` pair at each site.
 * Centralising it keeps the exit-code table honest (every fatal route goes through a single place
 * that takes the code as an argument) and keeps the number of raw `process.*` dispatch sites in
 * this decision-path file to the few that genuinely need them.
 */
function fail(code, msg) {
  process.stderr.write(`error: ${msg}\n`);
  process.exit(code);
}

function readBoundedFile(path) {
  const flags = fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0);
  let fd;
  try {
    fd = openSync(path, flags);
  } catch {
    usage(`cannot open file: ${path}`);
  }
  let bytes;
  try {
    let st;
    try {
      st = fstatSync(fd);
    } catch {
      usage(`cannot inspect file: ${path}`);
    }
    if (!st.isFile()) usage(`not a regular file: ${path}`);
    if (st.size > MAX_FILE_BYTES) usage(`file too large (>${MAX_FILE_BYTES} bytes): ${path}`);
    try {
      const chunks = [];
      const chunk = Buffer.allocUnsafe(64 * 1024);
      let total = 0;
      for (;;) {
        const remaining = MAX_FILE_BYTES + 1 - total;
        const n = readSync(fd, chunk, 0, Math.min(chunk.length, remaining), null);
        if (n === 0) break;
        total += n;
        if (total > MAX_FILE_BYTES) usage(`file too large (>${MAX_FILE_BYTES} bytes): ${path}`);
        chunks.push(Buffer.from(chunk.subarray(0, n)));
      }
      bytes = Buffer.concat(chunks, total);
    } catch {
      usage(`cannot read file: ${path}`);
    }
  } finally {
    closeSync(fd);
  }
  return bytes;
}

function readJsonFile(path) {
  const text = readBoundedFile(path).toString("utf8");
  try {
    return safeParse(text, { maxLength: MAX_FILE_BYTES });
  } catch (e) {
    // Malformed JSON is EXIT.MALFORMED (3) with a clean one-line message — never an uncaught
    // safeParse throw dumping a raw stack and exiting 1 (which contradicts the header's exit table).
    fail(EXIT.MALFORMED, `malformed JSON in ${path}: ${e.message}`);
  }
}

const TSA_VALUE_FLAGS = frozenTable([
  "--openssl",
  "--tsa-trust-roots",
  "--tsa-policy",
  "--tsa-crls",
  "--tsa-untrusted",
  "--tsa-now",
  "--tsa-max-future-skew-ms",
]);

function tsaFlagSet(extra = []) {
  const values = newSet(TSA_VALUE_FLAGS);
  for (let i = 0; i < arrayLength(extra); i++) setAdd(values, extra[i]);
  return values;
}

function loadTsaVerification(flags) {
  const required = ["--openssl", "--tsa-trust-roots", "--tsa-policy", "--tsa-crls", "--tsa-now", "--tsa-max-future-skew-ms"];
  for (let i = 0; i < arrayLength(required); i++) {
    if (flags[required[i]] === undefined) usage(`authenticated stamp verification requires ${required[i]} <value>`);
  }
  const maxFutureSkewMs = toNumber(flags["--tsa-max-future-skew-ms"]);
  if (!isSafeInteger(maxFutureSkewMs) || maxFutureSkewMs < 0 || maxFutureSkewMs > 300000) {
    usage("--tsa-max-future-skew-ms must be an integer from 0 through 300000");
  }
  return {
    opensslExecutable: flags["--openssl"],
    trustRoots: readBoundedFile(flags["--tsa-trust-roots"]),
    allowedPolicyOids: [flags["--tsa-policy"]],
    revocation: { mode: "crl-check-all", crls: readBoundedFile(flags["--tsa-crls"]) },
    untrustedCertificates: flags["--tsa-untrusted"] === undefined ? undefined : readBoundedFile(flags["--tsa-untrusted"]),
    clock: { now: flags["--tsa-now"], maxFutureSkewMs },
  };
}

function parseFlags(args, spec) {
  const out = {};
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (setHas(spec.valued, a)) {
      const v = args[++i];
      if (v === undefined || strStartsWith(v, "--")) usage(`${a} requires a value`);
      out[a] = v;
    } else if (setHas(spec.flags, a)) {
      out[a] = true;
    } else {
      usage(`unknown flag: ${a}`);
    }
  }
  return out;
}

function parseVerificationCommandTimeout(flags) {
  if (flags["--tsa-command-timeout-ms"] === undefined) return DEFAULT_VERIFICATION_COMMAND_TIMEOUT_MS;
  const value = toNumber(flags["--tsa-command-timeout-ms"]);
  if (
    !isSafeInteger(value) ||
    value < MIN_VERIFICATION_COMMAND_TIMEOUT_MS ||
    value > MAX_VERIFICATION_COMMAND_TIMEOUT_MS
  ) {
    usage("--tsa-command-timeout-ms must be an integer from 100 through 30000");
  }
  return value;
}

/** Hash every input before OpenSSL work, retaining input order while collecting unique content. */
function preflightVerifyAnchors(anchors) {
  const entries = [];
  const unique = [];
  const seen = newMap();
  for (let ai = 0; ai < arrayLength(anchors); ai++) {
    const anchor = anchors[ai];
    let key;
    try {
      key = anchorHash(anchor);
    } catch (e) {
      arrayPush(entries, { malformed: true, reason: `malformed anchor entry: ${e.message}` });
      continue;
    }
    arrayPush(entries, { anchor, key });
    if (!mapHas(seen, key)) {
      mapSet(seen, key, true);
      arrayPush(unique, { anchor, key });
    }
  }
  return { entries, unique };
}

function prepareVerificationResources(anchors, flags) {
  const commandTimeoutMs = parseVerificationCommandTimeout(flags);
  const preflight = preflightVerifyAnchors(anchors);
  const uniqueAnchors = arrayLength(preflight.unique);
  if (uniqueAnchors > MAX_VERIFICATION_UNIQUE_ANCHORS) {
    return { ok: false, preflight, uniqueAnchors, commandTimeoutMs };
  }
  let resourceBudget;
  if (uniqueAnchors > 0) {
    resourceBudget = createVerificationResourceBudget(
      commandTimeoutMs,
      uniqueAnchors * OPENSSL_PROCESS_BUDGET_PER_STAMP,
    );
    if (resourceBudget === null) return { ok: false, preflight, uniqueAnchors, commandTimeoutMs };
  }
  return { ok: true, preflight, uniqueAnchors, commandTimeoutMs, resourceBudget };
}

function resourceLimits(uniqueAnchors, commandTimeoutMs) {
  return {
    maxUniqueAnchors: MAX_VERIFICATION_UNIQUE_ANCHORS,
    maxOpenSslProcesses: uniqueAnchors * OPENSSL_PROCESS_BUDGET_PER_STAMP,
    commandTimeoutMs,
  };
}

function printPreflightResourceRefusal(uniqueAnchors, commandTimeoutMs, base) {
  const reason =
    `anchor set contains ${uniqueAnchors} unique anchors, exceeding the authenticated-verification limit ` +
    `of ${MAX_VERIFICATION_UNIQUE_ANCHORS}; refusing before OpenSSL work`;
  process.stdout.write(jsonStringify({
    ...base,
    resourceLimited: true,
    code: "VERIFICATION_RESOURCE_LIMIT",
    reason,
    uniqueAnchors,
    limits: resourceLimits(MAX_VERIFICATION_UNIQUE_ANCHORS, commandTimeoutMs),
  }) + "\n");
  return EXIT.RESOURCE_LIMIT;
}

async function cmdStamp(args) {
  const flags = parseFlags(args, { valued: newSet(["--anchors", "--tsa-url", "--out"]), flags: newSet(["--no-cert-req", "--no-nonce"]) });
  if (!flags["--anchors"]) usage("stamp requires --anchors <path>");
  if (!flags["--tsa-url"]) usage("stamp requires --tsa-url <url>");
  const anchors = readJsonFile(flags["--anchors"]);
  if (!isArray(anchors)) usage("--anchors file must contain a JSON array of anchors");
  // "Did nothing" is not "succeeded". Exiting 0 over an empty array reported success for a run that
  // did no work at all - reproduced for `stamp` against an UNREACHABLE TSA, where exit 0 said
  // nothing about whether the TSA had ever been contacted.
  if (arrayLength(anchors) === 0) usage("--anchors file contains an empty array - refusing to report success for stamping nothing");
  const out = flags["--out"] ?? `${flags["--anchors"]}.tsr.json`;

  const sidecar = {};
  // Index walk, not `for…of`: the iterator protocol is rewritable and a substituting iterator
  // could hand the stamper a different anchor from the one the caller supplied.
  for (let ai = 0; ai < arrayLength(anchors); ai++) {
    const a = anchors[ai];
    let key;
    try {
      key = anchorHash(a);
    } catch (e) {
      fail(EXIT.MALFORMED, `malformed anchor entry: ${e.message}`);
    }
    if (sidecar[key]) continue; // distinct-anchor dedup (same witness re-listed twice in the file)
    try {
      sidecar[key] = await stampAnchor(a, {
        tsaUrl: flags["--tsa-url"],
        certReq: !flags["--no-cert-req"],
        includeNonce: !flags["--no-nonce"],
      });
    } catch (e) {
      fail(EXIT.TRANSPORT, `stamping anchor ${key} (kid=${a?.sig?.kid}): ${e.message}`);
    }
  }
  writeFileSync(out, JSON.stringify(sidecar, null, 2) + "\n", "utf8");
  process.stdout.write(`wrote ${Object.keys(sidecar).length} stamp(s) to ${out}\n`);
  return EXIT.OK;
}

function cmdVerify(args) {
  const flags = parseFlags(args, { valued: tsaFlagSet(["--anchors", "--tsr", "--tsa-command-timeout-ms"]), flags: newSet() });
  if (!flags["--anchors"]) usage("verify requires --anchors <path>");
  if (!flags["--tsr"]) usage("verify requires --tsr <path>");
  const anchors = readJsonFile(flags["--anchors"]);
  const sidecar = readJsonFile(flags["--tsr"]);
  if (!isArray(anchors)) usage("--anchors file must contain a JSON array of anchors");
  if (arrayLength(anchors) === 0) usage("--anchors file contains an empty array - refusing to report success for verifying nothing");
  if (typeof sidecar !== "object" || sidecar === null || isArray(sidecar)) usage("--tsr file must contain a JSON object (anchorHash -> stamp record)");
  const tsaVerification = loadTsaVerification(flags);
  const resources = prepareVerificationResources(anchors, flags);
  if (!resources.ok) {
    return printPreflightResourceRefusal(resources.uniqueAnchors, resources.commandTimeoutMs, {
      results: [],
      mismatches: 0,
    });
  }
  const { commandTimeoutMs, preflight, resourceBudget } = resources;
  const uniqueCount = resources.uniqueAnchors;

  const verifiedByHash = newMap();
  let aggregateFailure;
  for (let ui = 0; ui < uniqueCount; ui++) {
    const entry = preflight.unique[ui];
    if (aggregateFailure !== undefined) {
      mapSet(verifiedByHash, entry.key, {
        ok: false,
        authenticated: false,
        code: "VERIFICATION_RESOURCE_LIMIT",
        reason: "not attempted because the command exhausted its aggregate OpenSSL resource budget",
      });
      continue;
    }
    const record = sidecar[entry.key];
    const result = record
      ? verifyStamp(entry.anchor, record, tsaVerification, resourceBudget)
      : { ok: false, authenticated: false, code: "STAMP_MISSING", reason: "no stamp for this anchor in the .tsr file" };
    mapSet(verifiedByHash, entry.key, result);
    if (result.code === "VERIFICATION_RESOURCE_LIMIT") {
      aggregateFailure = result;
    }
  }

  let mismatches = 0;
  let malformed = 0;
  const results = [];
  for (let ai = 0; ai < arrayLength(preflight.entries); ai++) {
    const entry = preflight.entries[ai];
    if (entry.malformed === true) {
      arrayPush(results, { ok: false, code: "MALFORMED", reason: entry.reason });
      mismatches++;
      malformed++;
      continue;
    }
    const res = mapGet(verifiedByHash, entry.key);
    arrayPush(results, { anchorHash: entry.key, chain: entry.anchor?.chain, highestSeq: entry.anchor?.highestSeq, ...res });
    if (!res.ok) {
      mismatches++;
      if (res.code === "MALFORMED") malformed++;
    }
  }
  const output = { results, mismatches };
  if (aggregateFailure !== undefined) {
    output.resourceLimited = true;
    output.code = "VERIFICATION_RESOURCE_LIMIT";
    output.reason = aggregateFailure.reason;
    output.uniqueAnchors = uniqueCount;
    output.limits = {
      ...resourceLimits(uniqueCount, commandTimeoutMs),
    };
  }
  process.stdout.write(JSON.stringify(output, null, 2) + "\n");
  // A bad-DER/bad-base64 (or malformed anchor) input is EXIT.MALFORMED (3) per the header table —
  // distinct from a well-formed-but-non-matching stamp, which is EXIT.MISMATCH (1).
  if (aggregateFailure !== undefined) return EXIT.RESOURCE_LIMIT;
  if (malformed > 0) return EXIT.MALFORMED;
  return mismatches === 0 ? EXIT.OK : EXIT.MISMATCH;
}

/** Shared loader for the monitor commands: the anchor pool, the pinned trust-set, optional stamps. */
function loadMonitorInputs(flags) {
  const anchors = readJsonFile(flags["--anchors"]);
  const trustSet = readJsonFile(flags["--trust-set"]);
  if (!isArray(anchors)) usage("--anchors file must contain a JSON array of anchors (the published pool)");
  if (arrayLength(anchors) === 0) usage("--anchors file contains an empty array - an empty pool is not a clean pool");
  const opts = {};
  if (flags["--tsa-command-timeout-ms"] !== undefined && flags["--tsr"] === undefined) {
    usage("--tsa-command-timeout-ms is valid for a monitor command only when --tsr is supplied");
  }
  if (flags["--chain"]) {
    const receipts = readJsonFile(flags["--chain"]);
    if (!isArray(receipts)) usage("--chain file must contain a JSON array of receipts");
    if (arrayLength(receipts) === 0) usage("--chain file contains an empty array - there is no presented history to compare against");
    // THE PRESENTED CHAIN IS VERIFIED, NOT TRUSTED. `historyFromReceipts` reads each receipt's OWN
    // `chain.hash` and skips whatever it cannot read; on its own that let `--chain '[{}]'` exit 0
    // while reporting `historyChecked:true` over a history containing nothing at all. Two checks
    // close it: the kernel's unchanged offline verifier must accept the document (no keyring needed
    // - this is the structural and hash-linkage check, so the hashes the history is built from are
    // the chain's own real ones), and the derivation must be TOTAL, not partial.
    const chainResult = verifyChain(jsonStringify(receipts));
    if (chainResult.status === "MALFORMED" || chainResult.status === "TAMPERED") {
      fail(EXIT.MALFORMED, `--chain does not verify (${chainResult.status}: ${chainResult.reason}) - refusing to compare anchors against a chain that is not internally consistent`);
    }
    const history = historyFromReceipts(receipts);
    if (arrayLength(history) !== receiptCount(receipts)) {
      fail(EXIT.MALFORMED, `--chain: only ${arrayLength(history)} of ${receiptCount(receipts)} receipt(s) yielded a usable (chain, seq, hash) entry - a partially-read history would silently narrow the comparison`);
    }
    opts.history = history;
  }
  if (flags["--tsr"]) {
    const sidecar = readJsonFile(flags["--tsr"]);
    if (typeof sidecar !== "object" || sidecar === null || isArray(sidecar)) {
      usage("--tsr file must contain a JSON object (anchorHash -> stamp record)");
    }
    opts.stamps = sidecar;
    opts.tsaVerification = loadTsaVerification(flags);
    const verificationResources = prepareVerificationResources(anchors, flags);
    if (!verificationResources.ok) return { anchors, trustSet, opts, verificationResources };
    // The opaque capability is deliberately separate from the public tsaVerification policy.
    // equivocation.mjs may forward it, but a caller-created lookalike fails closed in verify.mjs.
    opts.tsaResourceBudget = verificationResources.resourceBudget;
    return { anchors, trustSet, opts, verificationResources };
  }
  return { anchors, trustSet, opts, verificationResources: undefined };
}

function cmdForkScan(args) {
  const flags = parseFlags(args, {
    valued: tsaFlagSet(["--anchors", "--trust-set", "--chain", "--tsr", "--tsa-command-timeout-ms"]),
    flags: newSet(),
  });
  if (!flags["--anchors"]) usage("fork-scan requires --anchors <path>");
  if (!flags["--trust-set"]) usage("fork-scan requires --trust-set <path>");
  const { anchors, trustSet, opts, verificationResources } = loadMonitorInputs(flags);
  if (verificationResources !== undefined && !verificationResources.ok) {
    return printPreflightResourceRefusal(
      verificationResources.uniqueAnchors,
      verificationResources.commandTimeoutMs,
      { clean: false, verdict: "RESOURCE_LIMIT", equivocationFound: false, findings: [] },
    );
  }

  const res = scanForEquivocation(anchors, trustSet, opts);
  if (res.resourceLimited === true) {
    res.uniqueAnchors = verificationResources.uniqueAnchors;
    res.limits = resourceLimits(verificationResources.uniqueAnchors, verificationResources.commandTimeoutMs);
  }
  process.stdout.write(JSON.stringify(res, null, 2) + "\n");
  // EXIT 0 MEANS "CLEAN", AND NOTHING ELSE. It used to also cover "I admitted nothing" and "the
  // pool was full of forgeries", so a pipeline could not tell a clean bill from a scan that never
  // examined anything. `clean` is the single fail-closed field, and the exit code now follows it.
  if (res.verdict === "INVALID_INPUT") return EXIT.MALFORMED;
  if (res.resourceLimited === true) return EXIT.RESOURCE_LIMIT;
  if (res.equivocationFound) return EXIT.EQUIVOCATION;
  // 6, NOT 1. Exit 1 already means "this stamp does not match" for `verify` and "quorum not met"
  // for `corroborate`; folding "the scan examined nothing" into it left a pipeline unable to tell
  // a substantive negative from an empty one.
  return res.clean ? EXIT.OK : EXIT.NO_CLEAN_RESULT;
}

function cmdCorroborate(args) {
  const flags = parseFlags(args, {
    valued: tsaFlagSet([
      "--checkpoint", "--anchors", "--trust-set", "--chain", "--tsr", "--now", "--max-age-ms",
      "--tsa-command-timeout-ms",
    ]),
    flags: newSet(),
  });
  if (!flags["--checkpoint"]) usage("corroborate requires --checkpoint <path>");
  if (!flags["--anchors"]) usage("corroborate requires --anchors <path>");
  if (!flags["--trust-set"]) usage("corroborate requires --trust-set <path>");
  const checkpoint = readJsonFile(flags["--checkpoint"]);
  const { anchors, trustSet, opts, verificationResources } = loadMonitorInputs(flags);
  if (verificationResources !== undefined && !verificationResources.ok) {
    return printPreflightResourceRefusal(
      verificationResources.uniqueAnchors,
      verificationResources.commandTimeoutMs,
      { corroborated: false, verdict: "RESOURCE_LIMIT", equivocationFound: false, findings: [] },
    );
  }

  // Freshness is all-or-nothing: half a policy is an operator error, and silently treating it as "no
  // freshness" would re-open the replay gap the flag exists to close.
  const hasNow = flags["--now"] !== undefined;
  const hasAge = flags["--max-age-ms"] !== undefined;
  if (hasNow !== hasAge) usage("--now and --max-age-ms must be supplied together (a freshness policy is not half a policy)");
  if (hasNow) {
    // STRICT RFC 3339, because that is what the flag claims. `Date.parse` accepted "2026" and
    // silently anchored the whole freshness window to the first instant of that year. The strict
    // scanner already existed in equivocation.mjs and simply was not being used here.
    const now = rfc3339ToMs(flags["--now"]);
    const maxAgeMs = toNumber(flags["--max-age-ms"]);
    if (now === null) usage(`--now must be a full RFC 3339 timestamp such as 2026-06-23T10:30:00Z (got: ${flags["--now"]})`);
    if (!isFiniteNumber(maxAgeMs) || maxAgeMs < 0) usage(`--max-age-ms must be a non-negative number: ${flags["--max-age-ms"]}`);
    opts.freshness = { now, maxAgeMs };
  }

  const res = checkpointCorroboration(checkpoint, anchors, trustSet, opts);
  if (res.resourceLimited === true) {
    res.uniqueAnchors = verificationResources.uniqueAnchors;
    res.limits = resourceLimits(verificationResources.uniqueAnchors, verificationResources.commandTimeoutMs);
  }
  process.stdout.write(JSON.stringify(res, null, 2) + "\n");
  if (res.verdict === "INVALID_INPUT") return EXIT.MALFORMED;
  if (res.resourceLimited === true) return EXIT.RESOURCE_LIMIT;
  if (res.equivocationFound) return EXIT.EQUIVOCATION;
  return res.corroborated ? EXIT.OK : EXIT.MISMATCH;
}

async function main(argv) {
  // Captured slicing: the argv walk selects WHICH verdict runs, so it does not go through a
  // rewritable `Array.prototype.slice`.
  const args = arraySlice(argv, 2);
  if (arrayLength(args) === 0) usage();
  const cmd = args[0];
  const rest = arraySlice(args, 1);
  if (cmd === "stamp") return cmdStamp(rest);
  if (cmd === "verify") return cmdVerify(rest);
  if (cmd === "fork-scan") return cmdForkScan(rest);
  if (cmd === "corroborate") return cmdCorroborate(rest);
  usage(`unknown command: ${cmd}`);
}

main(process.argv).then((code) => {
  // Let buffered JSON reach a pipe before Node exits. Monitor findings can legitimately carry
  // several embedded TSRs and exceed a platform pipe's immediate-write capacity.
  process.exitCode = code;
});
