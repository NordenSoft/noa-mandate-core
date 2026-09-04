/**
 * Fixed internal driver for the SPOOL_ONLY boundary arm.
 *
 * This is test instrumentation, never an authorization transport. It deliberately takes no
 * semantic options: the only parser route it can arm is the candidate Tier-A non-authority route,
 * and the resulting arm always executes the reviewed SPOOL_ONLY plan with knockout JSON evidence.
 * The gate observer appends its one machine-output selector, so this driver accepts that exact
 * spelling once while refusing every argument that could alter scope, authority, or execution.
 */
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import {
  armCandidateTierANonAuthorityBootstrap,
  BOUNDARY_AUTHORITY_CLASS_CANDIDATE_TIER_A,
  CANDIDATE_TIER_A_NON_AUTHORITY_NON_CLAIM,
} from "./boundary-bootstrap.mjs";

const args = process.argv.slice(2);
if (args.length !== 1 || args[0] !== "--knockout-json") {
  throw new Error("SPOOL_ONLY_SELFTEST_ARGUMENTS_REFUSED");
}

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const armed = armCandidateTierANonAuthorityBootstrap({ root });
if (armed.authorityClass !== BOUNDARY_AUTHORITY_CLASS_CANDIDATE_TIER_A
    || armed.nonClaim !== CANDIDATE_TIER_A_NON_AUTHORITY_NON_CLAIM) {
  throw new Error("SPOOL_ONLY_SELFTEST_BOOTSTRAP_ARM_MISMATCH");
}

// Loading the scanner consumes the one-shot bootstrap. Prove the loaded parser retained the exact
// non-authority classification before the arm is allowed to run.
const { boundaryScannerAuthority } = await import("./boundary-scan.mjs");
if (boundaryScannerAuthority.authorization !== null
    || boundaryScannerAuthority.authorityClass !== BOUNDARY_AUTHORITY_CLASS_CANDIDATE_TIER_A
    || boundaryScannerAuthority.authorityNonClaim !== CANDIDATE_TIER_A_NON_AUTHORITY_NON_CLAIM
    || boundaryScannerAuthority.mode !== "candidate-tier-a-non-authority"
    || boundaryScannerAuthority.root !== root) {
  throw new Error("SPOOL_ONLY_SELFTEST_NON_AUTHORITY_MISMATCH");
}

const { runArm } = await import("./boundary-arm.mjs");
const code = await runArm({ root, knockoutJson: true, spoolOnly: true });
if (!Number.isSafeInteger(code) || code < 0 || code > 2) {
  throw new Error("SPOOL_ONLY_SELFTEST_EXIT_INVALID");
}
process.exitCode = code;
