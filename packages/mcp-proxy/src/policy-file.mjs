/**
 * policy-file.mjs — loads the operator's `--policy <file.json>` for the proxy CLI, FAIL-CLOSED.
 *
 * The file is a `noa.policy/0.2` document: the SAME shape `createProxyServer({ policy })` and
 * adapter-core's `preCheck` already take, checked by the SAME kernel grammar validator `evaluate`
 * runs on every call (`assertValidPolicy`). There is no second format and no second validator.
 *
 * Why validate at startup when `evaluate` already refuses an invalid policy per call: a policy the
 * kernel rejects makes EVERY call `DENY policy-invalid`. That is safe, but it is a proxy that looks
 * healthy, serves `tools/list`, and silently governs nothing the operator wrote. A typo in the file
 * must stop the process with a message that names the file and the field, not degrade at runtime.
 *
 * Three refusals, each with a stable code (the code is part of this CLI's contract; the prose after
 * it may improve):
 *   POLICY_UNREADABLE   the file is missing, a symlink, foreign-owned, group/other-writable,
 *                       not a regular file, or over the size cap (adapter-core's config-artifact
 *                       descriptor checks — the same ones every other governance file goes through)
 *   POLICY_UNPARSABLE   the bytes are not JSON
 *   POLICY_INVALID      JSON, but not a valid `noa.policy/0.2` document (closed grammar: an
 *                       unknown key, a duplicate key, a bad op or verdict, ...)
 *
 * Tools the policy does not name are not affected by loading it: the kernel's default is DENY.
 *
 * A fourth refusal checks the policy AGAINST the approval rules (requireApprovalRulesCovered):
 *   POLICY_APPROVAL_MISMATCH  an exact-match approval rule names a tool no policy rule mentions
 * Measured before this check existed: `init`, then rename the approval tool in policy.json only,
 * start the proxy — the renamed tool was ALLOWED by the policy, the approval rule still named the
 * old tool and matched nothing, and the call EXECUTED with no human asked and nothing on stderr. A
 * dead approval rule is a gate that is silently off, so it stops the process like the others.
 */
import { readConfigArtifact, assertValidPolicy, describeThrown, intrinsics } from "noa-mcp-adapter-core";

const { jsonParse, strStartsWith, strSlice, isArray, arrayIncludes } = intrinsics;

export const POLICY_FILE_ERROR_CODES = Object.freeze({
  UNREADABLE: "POLICY_UNREADABLE",
  UNPARSABLE: "POLICY_UNPARSABLE",
  INVALID: "POLICY_INVALID",
  APPROVAL_MISMATCH: "POLICY_APPROVAL_MISMATCH",
});

// The kernel throws `new Error("invalid policy: ...")`, and describeThrown renders it with its name
// ("Error: invalid policy: ..."); both prefixes go, so the message starts at the field.
const KERNEL_PREFIX = "invalid policy: ";
const DESCRIBED_KERNEL_PREFIX = `Error: ${KERNEL_PREFIX}`;
const FORMAT_HINT = 'the format is described in the noa-mcp-proxy README, "Use your own tools"';

/** The refusal. The stable code leads the message, so it survives every logging path unchanged. */
function policyFileError(code, message) {
  return new Error(`[${code}] ${message}`);
}

/** One line, always: a refusal is read in a terminal or a log, and a wrapped one gets cut in half.
 *  A character walk, not a regex (a regex dispatches `exec` through a replaceable prototype slot). */
function oneLine(text) {
  let out = "";
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    out += c === "\n" || c === "\r" ? " " : c;
  }
  return out;
}

/**
 * Reads, parses and validates `pathname`. Returns the kernel-parsed policy document (the value the
 * validator accepted, not a second parse of the same bytes). Throws an Error whose message starts
 * with `[<code>]` (one of POLICY_FILE_ERROR_CODES) otherwise.
 *
 * @param {string} pathname
 * @returns {object}
 */
export function loadPolicyFile(pathname) {
  if (typeof pathname !== "string" || pathname.length === 0) {
    throw policyFileError(POLICY_FILE_ERROR_CODES.UNREADABLE, "--policy needs a file path (got none) — pass --policy <file.json>");
  }
  const where = `--policy "${pathname}"`;

  let text;
  try {
    text = readConfigArtifact(pathname, { label: "--policy", required: true });
  } catch (err) {
    throw policyFileError(POLICY_FILE_ERROR_CODES.UNREADABLE, oneLine(`${where}: ${describeThrown(err)} — fix the path or the file's owner/permissions (regular file, owned by you, not group/other-writable)`));
  }

  try {
    jsonParse(text);
  } catch (err) {
    throw policyFileError(POLICY_FILE_ERROR_CODES.UNPARSABLE, oneLine(`${where} is not valid JSON (${describeThrown(err)}) — fix the JSON syntax; ${FORMAT_HINT}`));
  }

  try {
    return assertValidPolicy(text);
  } catch (err) {
    let detail = describeThrown(err);
    if (strStartsWith(detail, DESCRIBED_KERNEL_PREFIX)) detail = strSlice(detail, DESCRIBED_KERNEL_PREFIX.length);
    else if (strStartsWith(detail, KERNEL_PREFIX)) detail = strSlice(detail, KERNEL_PREFIX.length);
    throw policyFileError(POLICY_FILE_ERROR_CODES.INVALID, oneLine(`${where}: ${detail} — fix the named field(s); ${FORMAT_HINT}`));
  }
}

/** True if `cond` (a validated policy condition) compares the `action` path with `tool` anywhere. */
function conditionMentions(cond, tool) {
  if (cond === null || typeof cond !== "object") return false;
  if (cond.path === "action") {
    if (cond.op === "eq" && cond.value === tool) return true;
    if (cond.op === "in" && isArray(cond.values) && arrayIncludes(cond.values, tool)) return true;
  }
  if (isArray(cond.clauses)) {
    for (let i = 0; i < cond.clauses.length; i++) if (conditionMentions(cond.clauses[i], tool)) return true;
  }
  return cond.clause !== undefined && conditionMentions(cond.clause, tool);
}

/**
 * Refuses a DEAD approval rule: an exact-match rule whose tool no policy rule mentions (`action`
 * compared with `eq` or `in`, anywhere in a rule's condition). Such a rule holds nothing, while the
 * operator believes that tool needs a human. Prefix/suffix rules match families of names and cannot
 * be checked this way; they are left to the operator.
 *
 * Deliberately conservative: a policy that allows a tool only through a broad condition (`exists`,
 * `ne`) without naming it is refused too, and the message says how to fix it (name the tool).
 *
 * @param {object} policy          the document loadPolicyFile returned
 * @param {ReadonlyArray<{ id: string, match: { type: string, action: string } }>} approvalRules
 *                                 the snapshot requireValidApprovalRules returned
 * @param {string} rulesLabel      how the operator named the rules file, for the message
 */
export function requireApprovalRulesCovered(policy, approvalRules, rulesLabel) {
  for (let i = 0; i < approvalRules.length; i++) {
    const rule = approvalRules[i];
    if (rule.match.type !== "exact") continue;
    const tool = rule.match.action;
    let mentioned = false;
    for (let r = 0; r < policy.rules.length && !mentioned; r++) mentioned = conditionMentions(policy.rules[r].when, tool);
    if (!mentioned) {
      throw policyFileError(
        POLICY_FILE_ERROR_CODES.APPROVAL_MISMATCH,
        oneLine(`${rulesLabel}: approval rule "${rule.id}" holds "${tool}", but no rule in --policy names "${tool}", so this approval rule would never hold anything — use the same tool name in both files (noa-mcp-proxy init --approval-tool <name> writes both)`),
      );
    }
  }
}
