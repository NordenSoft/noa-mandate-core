/**
 * The published "atomic" sentences cite exactly the tagged blocks that make them so.
 *
 * `NON-CLAIMS.md` and `CHANGELOG.md` call two blocks of this package atomic: the effect owner's
 * in-process commit (`src/effect-owner.ts`, O9) and the in-memory store's `settleHold`
 * (`src/store.ts`). Each citation must name the lines from `ATOMIC-BLOCK: <id>` to
 * `ATOMIC-BLOCK-END: <id>` (the rule is `scripts/lib/atomic-citations.mjs`, run by
 * `scripts/lint-doc-truth.mjs` as rule 9). This test runs the same rule over the real tree, so an edit
 * that moves a tagged block, moves a tag, or shifts a line above one fails here as well as in the lint.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { lstatSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");

type Findings = { problems: string[]; checked: Array<{ doc: string; line: number; citation: string }> };
type Rule = (md: string, readSource: (path: string) => string | null, docName: string) => Findings;

function readRepoSource(path: string): string | null {
  const abs = join(ROOT, path);
  try {
    if (!lstatSync(abs).isFile()) return null;
  } catch {
    return null;
  }
  return readFileSync(abs, "utf8");
}

test("ATOMIC-CITATION — every line citation in an \"atomic\" sentence of NON-CLAIMS.md and CHANGELOG.md names exactly its tagged block", async () => {
  const mod = (await import(pathToFileURL(join(ROOT, "scripts", "lib", "atomic-citations.mjs")).href)) as { atomicCitationFindings: Rule };
  const problems: string[] = [];
  const checked: string[] = [];
  for (const doc of ["NON-CLAIMS.md", "CHANGELOG.md"]) {
    const r = mod.atomicCitationFindings(readFileSync(join(ROOT, doc), "utf8"), readRepoSource, doc);
    problems.push(...r.problems);
    checked.push(...r.checked.map((c) => c.citation));
  }
  assert.deepEqual(problems, [], "consequence: every published atomic citation names the lines of its tagged block");
  // Anti-vacuity: the two blocks this package ships are actually cited and checked.
  assert.ok(checked.some((c) => c.startsWith("packages/gate/src/effect-owner.ts:")), `the O9 citation was checked: ${JSON.stringify(checked)}`);
  assert.ok(checked.some((c) => c.startsWith("packages/gate/src/store.ts:")), `the settleHold citation was checked: ${JSON.stringify(checked)}`);
});
