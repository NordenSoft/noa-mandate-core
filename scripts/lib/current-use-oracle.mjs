/**
 * The one comparator for the current-use half of the survivable-retirement corpus
 * (`conformance/survivable-retirement/cases.json` -> `currentUse`).
 *
 * Shared by the cross-port checker and by the ordering knockout, so "the corpus accepts this CLI
 * run" means exactly the same thing in both: the checker requires it for every IMPLEMENTED port,
 * and the knockout requires a mutated verifier to FAIL it.
 */

/**
 * Compare one CLI run with a case's `expected`. Returns null when every pinned property holds,
 * otherwise a short description of the first mismatch.
 *
 * @param {{ status: string, exit: number, badSeq: number | null,
 *           keyRetired: { seq: number, kid: string, subject: string } | null,
 *           historicalPointer: boolean }} expected
 * @param {{ stdout: string, stderr: string, exit: number | null }} run
 * @returns {string | null}
 */
export function currentUseMismatch(expected, run) {
  let result;
  try {
    result = JSON.parse(run.stdout);
  } catch {
    return "stdout is not JSON";
  }
  if (result.status !== expected.status) return `status ${result.status} (want ${expected.status})`;
  if (run.exit !== expected.exit) return `exit ${run.exit} (want ${expected.exit})`;
  const badSeq = result.badSeq ?? null;
  if (badSeq !== expected.badSeq) return `badSeq ${badSeq} (want ${expected.badSeq})`;
  if (result.status !== "VALID" && (result.signaturesVerified !== false || result.tailChecked !== false)) {
    return "a refusal carried a positive sub-claim";
  }
  const warnings = Array.isArray(result.warnings) ? result.warnings : [];
  const retired = warnings.filter((w) => typeof w === "string" && w.startsWith("key-retired:"));
  const k = expected.keyRetired;
  if (retired.length !== (k === null ? 0 : 1)) return `${retired.length} key-retired warning(s) (want ${k === null ? 0 : 1})`;
  if (k !== null) {
    const prefix = `key-retired: seq ${k.seq} kid "${k.kid}" (${k.subject})`;
    if (!retired[0].startsWith(prefix)) return `key-retired warning does not start with ${prefix}`;
  }
  const pointer = `${run.stdout}\n${run.stderr}`.includes("--purpose historical");
  if (pointer !== expected.historicalPointer) {
    return expected.historicalPointer ? "no pointer to --purpose historical" : "a non-KEY_RETIRED result points to --purpose historical";
  }
  return null;
}
