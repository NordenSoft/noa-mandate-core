/**
 * boundary-lanes.mjs — L12's lane registry and its owner-visible exact-ID ratchet.
 *
 * ─── WHY A REGISTRY AT ALL ───────────────────────────────────────────────────────────────────────
 *
 * The measurement that produced this gate: the existing publish-surface lint exits 0 over a set of
 * 74 files while 983 are tracked. It was never wrong about the 74 — it was wrong about believing the
 * 74 were the surface. So every lane here must NAME ITS ENUMERATOR, and the enumerator must be an
 * external authority (git, npm) rather than the gate's own idea of what exists.
 *
 * ─── THE RATCHET, AND WHY IT IS A SEPARATE LIST ──────────────────────────────────────────────────
 *
 * `APPROVED_BOUNDARY_LANES` is an independent ratchet: a lane must not be able to remove itself
 * from coverage by editing its own record.
 * The assertion runs BEFORE anything is scanned, so registry drift is a refusal, never a smaller
 * green. Adding or removing a lane requires editing this list in the same reviewed change.
 *
 * ─── ZERO UNITS IS NOT A PASS ────────────────────────────────────────────────────────────────────
 *
 * `mustNotBeEmpty` says the lane's derivation is broken if it finds nothing — a git repository
 * always has tracked files, a publishable package always packs something. Those lanes exit 2 on an
 * empty enumeration, following the workflow's own rule that "the check could not run" and "the check
 * passed" must never share an exit code.
 *
 * `needsInput` marks the lanes that legitimately have nothing to look at when no push refs or range
 * were supplied. Those report SKIPPED — by name, never folded into the OK line — and a run in which
 * EVERY lane skipped is itself exit 2.
 */

export const BOUNDARY_LANES = Object.freeze([
  Object.freeze({
    id: "L-WT",
    title: "working tree",
    enumerator: "git ls-files -z + git ls-files -z --others --exclude-standard",
    covers: "every tracked and every untracked-but-not-ignored repository-relative path and file body, read from disk",
    mustNotBeEmpty: true,
    needsInput: false,
  }),
  Object.freeze({
    id: "L-IDX",
    title: "staged content",
    enumerator: "git diff --cached --name-only -z, content via git show :<path>",
    covers: "the staged repository-relative path and bytes — read from the INDEX, not disk, so a staged secret reverted on disk is still seen",
    mustNotBeEmpty: false,
    needsInput: true,
  }),
  Object.freeze({
    id: "L-PUSH",
    title: "blobs leaving the machine",
    enumerator: "git rev-list <remote>..<local> then git diff-tree -r --no-commit-id --name-only",
    covers: "every repository-relative path and every blob version in the push set, including non-tip versions that remain fetchable",
    mustNotBeEmpty: false,
    needsInput: true,
  }),
  Object.freeze({
    id: "L-MSG",
    title: "commit messages and ref names",
    enumerator: "git log --format=%B%x00 <range>, plus the ref name itself",
    covers: "messages and branch names — unrewritable once pushed, and where a whole programme's labels leaked",
    mustNotBeEmpty: false,
    needsInput: true,
  }),
  Object.freeze({
    id: "L-TAG",
    title: "tag names and annotations",
    enumerator: "git tag --points-at over the push set, git cat-file tag for annotations",
    covers: "tags, which keep publishing a deleted file long after it leaves the branch",
    mustNotBeEmpty: false,
    needsInput: true,
  }),
  Object.freeze({
    id: "L-PACK",
    title: "the npm tarball surface",
    enumerator: "packFrozenPackageArtifact over a frozen read-only source snapshot, using the pinned no-network Arborist/npm-packlist/tar stack; root plus every workspace with private !== true",
    covers: "the exact parsed tar member paths and file bytes the lifecycle-free packer emits, not a dry-run or mutable-tree prediction",
    mustNotBeEmpty: true,
    needsInput: false,
  }),
  Object.freeze({
    id: "L-MAP",
    title: "sourcemaps and declaration files",
    enumerator: "the .map and .d.ts members of L-PACK's own set",
    covers: "packed map/declaration paths plus sources[]/sourcesContent[]/sourceRoot and absolute paths baked into declarations",
    mustNotBeEmpty: true,
    needsInput: false,
  }),
  Object.freeze({
    id: "L-FIX",
    title: "conformance fixtures",
    enumerator: "git ls-files -z -- conformance",
    covers: "the paths and bytes of vectors, which are tracked and never packed — reachable only through the git lanes",
    mustNotBeEmpty: true,
    needsInput: false,
  }),
]);

/**
 * The owner-visible ratchet. Independent of the records above ON PURPOSE: a lane cannot self-exclude
 * by editing `BOUNDARY_LANES`, because this list is compared against it before any scanning happens.
 */
export const APPROVED_BOUNDARY_LANES = Object.freeze([
  "L-FIX", "L-IDX", "L-MAP", "L-MSG", "L-PACK", "L-PUSH", "L-TAG", "L-WT",
]);

export function assertLaneRegistry(lanes = BOUNDARY_LANES) {
  const actual = lanes.map((l) => l.id).sort();
  const expected = [...APPROVED_BOUNDARY_LANES].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    const expectedSet = new Set(expected);
    const actualSet = new Set(actual);
    const added = actual.filter((id) => !expectedSet.has(id));
    const removed = expected.filter((id) => !actualSet.has(id));
    throw new Error(
      `boundary lane classification drift: added=[${added.join(", ")}], removed=[${removed.join(", ")}]. ` +
      "A lane cannot add or remove itself from coverage; update APPROVED_BOUNDARY_LANES in the same reviewed change.",
    );
  }
  for (const lane of lanes) {
    for (const field of ["id", "title", "enumerator", "covers"]) {
      if (typeof lane[field] !== "string" || lane[field].length === 0) {
        throw new Error(`boundary lane ${JSON.stringify(lane.id)} is missing a non-empty ${field}`);
      }
    }
    if (typeof lane.mustNotBeEmpty !== "boolean" || typeof lane.needsInput !== "boolean") {
      throw new Error(`boundary lane ${JSON.stringify(lane.id)} must declare mustNotBeEmpty and needsInput as booleans`);
    }
    if (lane.mustNotBeEmpty && lane.needsInput) {
      throw new Error(
        `boundary lane ${JSON.stringify(lane.id)} declares both mustNotBeEmpty and needsInput: a lane that ` +
        "legitimately has no input cannot also treat emptiness as a broken derivation. Pick one.",
      );
    }
  }
  return lanes;
}

export const laneById = (id) => BOUNDARY_LANES.find((l) => l.id === id) ?? null;

/** Lanes that run when no push refs or range were supplied — a plain local or CI check. */
export const DEFAULT_LANES = Object.freeze(BOUNDARY_LANES.filter((l) => !l.needsInput).map((l) => l.id));
