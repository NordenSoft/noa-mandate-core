/**
 * The demo governance policy for the 3 tools demo-downstream.mjs exposes: `echo` and
 * `read_data` are auto-allowed (read-only/benign); `transfer_funds` is gated on amount, mirroring
 * the refund-guard shape from examples/mcp-preflight/preflight.mjs but scoped to this package's
 * own downstream tool surface (a real integration always supplies its own policy — this one is
 * NOT a shared default, see noa-mcp-adapter-core's REFUND_GUARD_POLICY for that reference fixture).
 *
 * Any tool call this policy doesn't explicitly ALLOW falls through to L2's default-DENY
 * (fail-closed) — including a hypothetical 4th tool a downstream server might add later that this
 * policy has no rule for.
 */
export const TRANSFER_GUARD_POLICY = {
  spec: "noa.policy/0.2",
  id: "mcp-proxy-demo-guard-v1",
  requiredPaths: ["action"],
  rules: [
    { id: "allow-echo", when: { op: "eq", path: "action", value: "echo" }, then: "ALLOW" },
    { id: "allow-read-data", when: { op: "eq", path: "action", value: "read_data" }, then: "ALLOW" },
    {
      id: "deny-large-transfer",
      when: {
        op: "and",
        clauses: [
          { op: "eq", path: "action", value: "transfer_funds" },
          { op: "ge", path: "amountMinor", value: 100_000_000 }, // >= 1,000,000.00 minor units
        ],
      },
      then: "DENY",
    },
    {
      id: "allow-small-transfer",
      when: {
        op: "and",
        clauses: [
          { op: "eq", path: "action", value: "transfer_funds" },
          // Floor at 0: a negative amountMinor is numerically "< 100_000_000" too, and without
          // this clause it would fall straight into this ALLOW rule. Anything outside
          // [0, 100_000_000) — including negative amounts — falls through to L2's default-DENY.
          { op: "ge", path: "amountMinor", value: 0 },
          { op: "lt", path: "amountMinor", value: 100_000_000 },
        ],
      },
      then: "ALLOW",
    },
  ],
};

/**
 * R4 demo approval-gate fixture: any `transfer_funds` >= 5000 minor units is held for a human
 * (DEFERRED) even though TRANSFER_GUARD_POLICY's own L2 decision for that amount is ALLOW — a
 * SEPARATE, post-policy layer (adapter-core's approval-rules.mjs), never a replacement for L2.
 */
export const APPROVAL_RULES = [
  { id: "transfer-needs-human", match: { type: "exact", action: "transfer_funds" }, threshold: { path: "amountMinor", op: "ge", value: 5000 } },
];

/**
 * The placeholder tool names `noa-mcp-proxy init` writes into its starter files. They are
 * deliberately names no real server is likely to expose, so an un-renamed starter policy matches
 * nothing and every real tool stays denied (default-DENY) until the operator names their own.
 */
export const STARTER_TOOL_NAMES = Object.freeze({
  allowed: "my_read_tool",
  needsApproval: "my_payment_tool",
  blocked: "my_delete_tool",
});

/**
 * Builds a fresh starter `--policy` document, written by `init` as policy.json (a builder, not a
 * shared module-level table, so no caller can change what the next one gets). One tool allowed,
 * one allowed by the policy but held for a human by starterApprovalRules() (the policy decides IF a
 * call may run; the approval rule decides that a human must say yes first), one blocked by an
 * explicit DENY. Anything not named here is denied by the kernel's default. The rule ids carry the
 * explanation because JSON has no comments and the policy grammar is closed (an extra "comment"
 * key is refused).
 *
 * `names` defaults to the placeholders; `init --allow-tool/--approval-tool/--block-tool` passes the
 * operator's own names, and the SAME object feeds starterApprovalRules(), so the two files can never
 * disagree about which tool needs a human.
 *
 * @param {{ allowed: string, needsApproval: string, blocked: string }} [names]
 */
export function starterPolicy(names = STARTER_TOOL_NAMES) {
  const { allowed, needsApproval, blocked } = names;
  return {
    spec: "noa.policy/0.2",
    id: "my-tools-v1",
    requiredPaths: ["action"],
    rules: [
      { id: `allow-${allowed}`, when: { op: "eq", path: "action", value: allowed }, then: "ALLOW" },
      { id: `allow-${needsApproval}-after-human-approval`, when: { op: "eq", path: "action", value: needsApproval }, then: "ALLOW" },
      { id: `block-${blocked}`, when: { op: "eq", path: "action", value: blocked }, then: "DENY" },
    ],
  };
}

/**
 * Builds the starter approval-rules.json written by `init`: ONE rule that holds every call of the
 * starter policy's approval tool for a human. Nothing else: a rule for a tool the starter policy
 * does not name would be a dead rule, and the proxy refuses to start with one (see
 * policy-file.mjs's requireApprovalRulesCovered).
 *
 * @param {{ needsApproval: string }} [names]
 */
export function starterApprovalRules(names = STARTER_TOOL_NAMES) {
  return [{ id: `${names.needsApproval}-needs-human`, match: { type: "exact", action: names.needsApproval } }];
}
