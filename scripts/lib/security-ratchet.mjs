/**
 * Pure helpers for the security-gate exact-count ratchet.
 *
 * Keeping comparison policy out of the CLI makes the two properties that matter directly
 * testable: a snapshot must be a real integer-valued object, and any difference from the exact
 * measured counts must be named rather than silently treated as budget slack.
 */

export function validCountSnapshot(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  for (const key of Object.keys(value)) {
    if (!Number.isSafeInteger(value[key]) || value[key] < 0) return false;
  }
  return true;
}

export function parseCountSnapshot(text) {
  const value = JSON.parse(text);
  if (!validCountSnapshot(value)) {
    throw new Error("expected a JSON object of non-negative safe integers");
  }
  return value;
}

export function exactRatchetProblems(measuredRows, recorded) {
  const problems = [];
  const measuredIds = new Set();

  for (const row of measuredRows) {
    measuredIds.add(row.id);
    const was = recorded[row.id];
    if (typeof was !== "number") {
      problems.push({ kind: "missing", id: row.id, current: row.count });
    } else if (row.count > was) {
      problems.push({ kind: "rise", id: row.id, was, current: row.count });
    } else if (row.count < was) {
      problems.push({ kind: "fall", id: row.id, was, current: row.count });
    }
  }

  for (const id of Object.keys(recorded)) {
    if (!measuredIds.has(id)) problems.push({ kind: "obsolete", id, was: recorded[id] });
  }
  return problems;
}

export function ratchetIncreases(measuredRows, recorded) {
  return exactRatchetProblems(measuredRows, recorded).filter((problem) => problem.kind === "rise");
}
