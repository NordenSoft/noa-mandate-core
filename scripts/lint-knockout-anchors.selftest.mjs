#!/usr/bin/env node
/**
 * Proof that the knockout anchor lint is LOAD-BEARING.
 *
 * A lint that prints OK is indistinguishable from a lint that checks nothing, so each failure it
 * claims to catch is planted and the real script is executed on it: it must exit 1 and name exactly
 * the planted entries, each with the expected problem.
 *   - Live-registry copies: one defect planted in one real single-edit entry (rotted, ambiguous,
 *     no-op, missing file). Every other real entry must stay unnamed, so the copy fails only on the
 *     planted defect.
 *   - Fixture registries over a temporary root: the paths a single-edit entry never exercises
 *     (`also[]` staging, `andAlso` partner staging, a pair that cancels itself, symlinked and
 *     non-regular targets, `companionFile`, the setup-integrity single-target rule). Each fixture
 *     registry also carries one valid entry, which must stay unnamed.
 * The live registry itself is checked once, by the lint run that follows this selftest.
 *
 * Usage: node scripts/lint-knockout-anchors.selftest.mjs
 */
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { knockoutRegistrySnapshot } from "./lint-control-knockout.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const LINT = path.join(ROOT, "scripts", "lint-knockout-anchors.mjs");
const dir = fs.mkdtempSync(path.join(os.tmpdir(), "knockout-anchor-selftest-"));
const failures = [];
let cases = 0;

/** Run the lint on `registry`; require exit 1 and exactly `expected` ({id: problem substring}) named. */
function expectCaught(name, registry, expected, extraArgs = []) {
  cases++;
  const file = path.join(dir, "registry.json");
  fs.writeFileSync(file, JSON.stringify(registry));
  const r = spawnSync(process.execPath, [LINT, "--registry-json", file, ...extraArgs], { cwd: ROOT, encoding: "utf8" });
  const named = (r.stderr ?? "").split("\n").filter((l) => l.startsWith("knockout anchor FAIL ["));
  const ids = named.map((l) => /^knockout anchor FAIL \[([^\]]+)\]/.exec(l)[1]).sort();
  const ok = r.status === 1 && JSON.stringify(ids) === JSON.stringify(Object.keys(expected).sort()) &&
    Object.entries(expected).every(([id, text]) => named.some((l) => l.startsWith(`knockout anchor FAIL [${id}]`) && l.includes(text)));
  console.log(`${ok ? "CAUGHT" : "MISSED"} ${name}`);
  if (!ok) failures.push(`${name}: exit ${r.status}, reported ${JSON.stringify(named)}`);
}

try {
  // ── live-registry copies ─────────────────────────────────────────────────────────────────────
  const registry = JSON.parse(JSON.stringify(knockoutRegistrySnapshot().registry));
  const victimIndex = registry.findIndex((e) => e.andAlso === undefined && e.also === undefined &&
    e.companionFile === undefined && !registry.some((other) => other.andAlso === e.id));
  if (victimIndex < 0) throw new Error("no single-edit registry entry to plant a defect in");
  const victim = registry[victimIndex];
  const plant = (change) => registry.map((e, i) => (i === victimIndex ? change(e) : e));
  expectCaught("live copy: rotted anchor (find matches 0 times)",
    plant((e) => ({ ...e, find: `${e.find}\u0000knockout-anchor-selftest` })), { [victim.id]: "matched 0x" });
  expectCaught("live copy: ambiguous anchor (find matches more than once)",
    plant((e) => ({ ...e, find: "\n" })), { [victim.id]: "(must be exactly 1)" });
  expectCaught("live copy: no-op mutation (replace equals find)",
    plant((e) => ({ ...e, replace: e.find })), { [victim.id]: "byte-identical" });
  expectCaught("live copy: anchor in a missing file",
    plant((e) => ({ ...e, file: `${e.file}.knockout-anchor-selftest-missing` })), { [victim.id]: "does not exist" });

  // ── fixture registries over a temporary root ─────────────────────────────────────────────────
  const fx = path.join(dir, "root");
  fs.mkdirSync(path.join(fx, "a-directory"), { recursive: true });
  fs.writeFileSync(path.join(fx, "a.txt"), "cat dog\nalpha beta gamma\n");
  fs.writeFileSync(path.join(fx, "b.txt"), "one two\n");
  fs.symlinkSync("a.txt", path.join(fx, "link.txt"));
  const root = ["--root", fx];
  const valid = { id: "fx-valid", file: "b.txt", find: "one", replace: "uno" };
  expectCaught("fixture: rotted also[0].find", [valid,
    { id: "fx-also", file: "a.txt", find: "alpha", replace: "ALPHA", also: [{ find: "rotted-also-anchor", replace: "x" }] },
  ], { "fx-also": "also[0].find matched 0x" }, root);
  expectCaught("fixture: rotted andAlso partner", [valid,
    { id: "fx-pair", file: "a.txt", find: "alpha", replace: "ALPHA", andAlso: "fx-partner" },
    { id: "fx-partner", file: "a.txt", find: "rotted-partner-anchor", replace: "x" },
  ], { "fx-pair": "fx-partner: find matched 0x", "fx-partner": "find matched 0x" }, root);
  expectCaught("fixture: a pair whose edits cancel", [valid,
    { id: "fx-cancel", file: "a.txt", find: "cat dog", replace: "dog", andAlso: "fx-restore" },
    { id: "fx-restore", file: "a.txt", find: "dog", replace: "cat dog" },
  ], { "fx-cancel": "combined mutation sequence leaves a.txt byte-identical" }, root);
  expectCaught("fixture: symlinked target", [valid,
    { id: "fx-link", file: "link.txt", find: "alpha", replace: "x" },
  ], { "fx-link": "is a symlink" }, root);
  expectCaught("fixture: non-regular target", [valid,
    { id: "fx-dir", file: "a-directory", find: "a", replace: "b" },
  ], { "fx-dir": "is not a regular file" }, root);
  expectCaught("fixture: missing companionFile", [valid,
    { id: "fx-companion", file: "a.txt", find: "alpha", replace: "x", companionFile: "missing-companion.txt" },
  ], { "fx-companion": "missing-companion.txt does not exist" }, root);
  expectCaught("fixture: setup-integrity entry that changes a second file", [valid,
    { id: "fx-setup", file: "a.txt", find: "alpha", replace: "x", expectedSetupIntegrity: { from: "alpha", to: "x" }, andAlso: "fx-second" },
    { id: "fx-second", file: "b.txt", find: "two", replace: "dos" },
  ], { "fx-setup": "not exactly its one declared file a.txt" }, root);
} finally {
  fs.rmSync(dir, { recursive: true, force: true });
}

if (failures.length > 0) {
  console.error(`\nknockout anchor lint SELF-TEST FAILED:\n${failures.join("\n")}`);
  process.exit(1);
}
console.log(`\nknockout anchor lint self-test: ${cases}/${cases} planted defects caught, each naming exactly the planted entries`);
