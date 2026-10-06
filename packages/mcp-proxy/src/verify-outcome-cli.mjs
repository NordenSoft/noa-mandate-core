/**
 * verify-outcome-cli.mjs — `noa-mcp-proxy verify-outcome <file> --keyring <file>`.
 *
 * Offline verification of OUTCOME receipts (`noa.mcp.outcome/0.1`, the lines `--outcome-log`
 * writes). The `noa-receipt` CLI verifies DECISION receipts (`noa.receipt/0.1`, `--receipt-log`)
 * and, correctly, does not know this second, domain-separated format; this subcommand is the
 * command-line front of the existing `verifyOutcomeReceipt` — it adds no verification logic of its
 * own and changes nothing about the receipt format.
 *
 * Input: one receipt as a JSON object, or a JSONL file with one receipt per line (blank lines are
 * ignored). The keyring is the `{ [kid]: publicKey }` JSON `--keyring-file` writes, or a rotatable
 * signer's verification lifecycle document.
 *
 * Exit codes (any non-zero is a failure; do not special-case one value):
 *   0  VALID      every receipt verified, and there was at least one
 *   2  TAMPERED   at least one well-formed receipt is NOT authenticated under the keyring
 *                 (signature mismatch, unknown or retired kid), or one decision's outcome appears
 *                 more than once (a replayed line) — reported ahead of MALFORMED
 *   3  MALFORMED  the file holds no receipt, or a line is not JSON / not an outcome receipt
 *   4  USAGE      bad arguments, an unreadable file (missing, a symlink, not owned by you, group/
 *                 other-writable, over 64 MiB), or a keyring that is not a JSON object
 * Same numbering as the `noa-receipt` CLI for the codes the two share.
 *
 * VALID means every line is a genuine, signed outcome receipt, each for a different decision. It
 * does NOT mean the log is complete: an outcome receipt is not chained, so a deleted line leaves no
 * trace here.
 *
 * Every document is parsed by the kernel's strict parser (`parseDocument`): a duplicate key is
 * refused, never resolved "last one wins" — two readers of one line must not see two receipts.
 */
import { readConfigArtifact, parseDocument, describeThrown, intrinsics } from "noa-mcp-adapter-core";
import { verifyOutcomeReceipt } from "./outcome-receipt.mjs";

const { strSplit, strTrim, isArray, arrayPush, objectSetPrototypeOf, objectCreateNull, hasOwn, INERT_ARRAY_PROTOTYPE } = intrinsics;

const PROCESS = process;

export const VERIFY_OUTCOME_EXIT = Object.freeze({ VALID: 0, TAMPERED: 2, MALFORMED: 3, USAGE: 4 });

const USAGE_TEXT =
  "usage: noa-mcp-proxy verify-outcome <outcome-receipts.jsonl> --keyring <keyring.json>\n" +
  "  verifies noa.mcp.outcome/0.1 receipts offline; exit 0 VALID, 2 TAMPERED, 3 MALFORMED, 4 USAGE\n" +
  "  (decision receipts from --receipt-log are verified with the noa-receipt CLI instead)\n";

class UsageError extends Error {}

function parseArgs(argv) {
  const opts = { file: null, keyring: null };
  objectSetPrototypeOf(opts, null);
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--keyring") {
      const v = argv[++i];
      if (v === undefined || v.length === 0) throw new UsageError("--keyring needs a file path");
      if (opts.keyring !== null) throw new UsageError("--keyring given more than once");
      opts.keyring = v;
    } else if (a.length > 0 && a[0] === "-") {
      throw new UsageError(`unknown flag "${a}"`);
    } else {
      if (opts.file !== null) throw new UsageError(`unexpected extra argument "${a}"`);
      opts.file = a;
    }
  }
  if (opts.file === null) throw new UsageError("missing <outcome-receipts file>");
  if (opts.keyring === null) throw new UsageError("missing --keyring <file> (an outcome receipt is only VALID against a key you trust)");
  return opts;
}

/**
 * Through adapter-core's descriptor-checked reader (the one every governance file goes through): a
 * regular file, not a symlink, owned by this user or root, not group/other-writable, under the size
 * cap. A verifier that follows a planted symlink to a different keyring would be checking against
 * keys someone else chose.
 */
function readRegularFile(pathname, label) {
  try {
    return readConfigArtifact(pathname, { label, required: true });
  } catch (err) {
    throw new UsageError(`cannot use ${label} "${pathname}" (${describeThrown(err)})`);
  }
}

/** Splits the input into receipt candidates: `{ line, value }` or `{ line, error }`. */
function receiptCandidates(text) {
  const out = [];
  objectSetPrototypeOf(out, INERT_ARRAY_PROTOTYPE);
  // A single (possibly pretty-printed) JSON object first; otherwise JSONL.
  const parsedWhole = parseDocument(text, "receipt");
  if (parsedWhole.ok) {
    const whole = parsedWhole.value;
    if (whole === null || typeof whole !== "object" || isArray(whole)) {
      arrayPush(out, { line: 1, error: "expected one outcome receipt object or JSONL (one receipt per line)" });
    } else {
      arrayPush(out, { line: 1, value: whole });
    }
    return out;
  }
  const lines = strSplit(text, "\n");
  for (let i = 0; i < lines.length; i++) {
    const raw = strTrim(lines[i]);
    if (raw.length === 0) continue;
    const parsed = parseDocument(raw, "receipt");
    if (parsed.ok) arrayPush(out, { line: i + 1, value: parsed.value });
    else arrayPush(out, { line: i + 1, error: `not a valid JSON document (${parsed.reason})` });
  }
  return out;
}

/**
 * Runs one invocation and returns its exit code. Never throws and never calls `process.exit`, so it
 * is testable in-process (same contract as `runInitCli`).
 */
export function runVerifyOutcomeCli(argv) {
  let opts;
  let text;
  let verification;
  try {
    if (argv.length === 1 && (argv[0] === "--help" || argv[0] === "-h")) {
      PROCESS.stdout.write(USAGE_TEXT);
      return VERIFY_OUTCOME_EXIT.VALID;
    }
    opts = parseArgs(argv);
    text = readRegularFile(opts.file, "receipts file");
    const keyringText = readRegularFile(opts.keyring, "keyring");
    const parsedKeyring = parseDocument(keyringText, "keyring");
    if (!parsedKeyring.ok) throw new UsageError(`keyring "${opts.keyring}" is not a valid JSON document (${parsedKeyring.reason})`);
    verification = parsedKeyring.value;
    if (verification === null || typeof verification !== "object" || isArray(verification)) {
      throw new UsageError(`keyring "${opts.keyring}" must be a JSON object ({ "<kid>": "<publicKey>" })`);
    }
  } catch (err) {
    PROCESS.stderr.write(`noa-mcp-proxy verify-outcome: ${describeThrown(err)}\n${USAGE_TEXT}`);
    return VERIFY_OUTCOME_EXIT.USAGE;
  }

  const candidates = receiptCandidates(text);
  let valid = 0;
  let tampered = 0;
  let malformed = 0;
  let report = "";
  // decision hash -> line of the first VALID outcome for it. The hash is inside the signed bytes and
  // unique per decision, so a second authentic outcome for the same decision is a replayed line.
  const seen = objectCreateNull();
  for (let i = 0; i < candidates.length; i++) {
    const c = candidates[i];
    if (c.error !== undefined) {
      malformed++;
      report += `MALFORMED line ${c.line}: ${c.error}\n`;
      continue;
    }
    const r = verifyOutcomeReceipt(c.value, { verification });
    const id = typeof c.value?.id === "string" ? ` ${c.value.id}` : "";
    if (r.ok === true && hasOwn(seen, c.value.decision.hash)) {
      tampered++;
      report += `TAMPERED line ${c.line}${id}: duplicate — the outcome of decision ${r.decisionId} already appears on line ${seen[c.value.decision.hash]}\n`;
    } else if (r.ok === true) {
      seen[c.value.decision.hash] = c.line;
      valid++;
      report += `VALID line ${c.line}${id} (outcome ${r.status}, decision ${r.decisionId})\n`;
    } else if (r.code === "TAMPERED") {
      tampered++;
      report += `TAMPERED line ${c.line}${id}: ${r.reason}\n`;
    } else {
      // MALFORMED, VERIFICATION_INPUT, or any code this CLI does not know: never a pass.
      malformed++;
      report += `MALFORMED line ${c.line}${id}: ${r.reason}\n`;
    }
  }

  let exit;
  let verdict;
  if (tampered > 0) {
    exit = VERIFY_OUTCOME_EXIT.TAMPERED;
    verdict = "TAMPERED";
  } else if (malformed > 0 || valid === 0) {
    exit = VERIFY_OUTCOME_EXIT.MALFORMED;
    verdict = "MALFORMED";
    if (candidates.length === 0) report += "MALFORMED: the file holds no outcome receipt\n";
  } else {
    exit = VERIFY_OUTCOME_EXIT.VALID;
    verdict = "VALID";
  }
  report += `${verdict}: ${valid} valid, ${tampered} tampered, ${malformed} malformed\n`;
  try {
    PROCESS.stdout.write(report);
  } catch {
    // The verdict is the exit code; a closed stdout does not change it.
  }
  return exit;
}
