#!/usr/bin/env node
/**
 * PREPARE EVERY PACKAGE THE PROOF LANES RESOLVE THROUGH — ONCE, FROM ONE DERIVATION.
 *
 * Two CI jobs need the same tree: `test`, whose proof-runner selftest and resolver-parity census run
 * proofs, and `knockout-shards`, whose sweep mutates those same packages and re-runs their suites.
 * A separate job is a separate machine, so each has to prepare its own checkout — but "each prepares
 * its own" must not become "each carries its own recipe". This file is that recipe, in one place,
 * and both jobs invoke it with no arguments.
 *
 * ── WHY THIS EXISTS AS A FILE AND NOT AS A COPIED YAML BLOCK ─────────────────────────────────────
 * The preparation used to be forty lines of shell inside one job. Moving the sweep into its own job
 * meant copying those lines, and a copy is how two jobs start disagreeing about what "prepared"
 * means. It also broke a knockout: `find` must match EXACTLY ONCE, and a duplicated block made the
 * registry's own anchor ambiguous — the tooling said plainly that the second copy was wrong.
 *
 * ── THE PLAN IS DERIVED, NEVER KEPT HERE ─────────────────────────────────────────────────────────
 * `lint-resolver-parity.mjs --print-proof-packages` prints the preparation plan from the SAME file
 * selection its tier-2 runner will execute: the registered runtime proofs plus the constructed
 * surface proofs and the closure of the local `file:` links those packages declare. Nothing in
 * this file names a package.
 * A hand-kept list is what failed twice — first omitting `packages/evidence` (CI died on
 * `ENOENT ... packages/evidence/node_modules/typescript/bin/tsc`), then omitting `packages/e2e-demo`,
 * whose constructed surface proof runs on the public lane.
 *
 * ── THREE PASSES, IN THIS ORDER ──────────────────────────────────────────────────────────────────
 * 1. VALIDATE the whole plan. Validating inside the install loop would let a malformed line on row
 *    nine be found only after eight packages were installed — a half-prepared tree nobody asked for.
 * 2. INSTALL everything. A `file:` sibling is a symlink, so a build that runs while a later sibling
 *    is still uninstalled compiles against a directory that is about to change.
 * 3. BUILD, dependency before consumer, in the plan's own order. Only a package's OWN `build` runs:
 *    `build:deps` is a package's private recipe for rebuilding its siblings, and the plan already
 *    builds each of them exactly once, in order.
 *
 * Every plan-validation refusal exits non-zero before anything is installed. A runtime install or
 * build failure can occur after earlier operations, but it also exits non-zero; a preparation step
 * that half-succeeds can never report success and let a later gate measure the partial tree.
 */
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

/** The one action a package's own manifest may contribute to this plan. */
const ALLOWED_ACTIONS = new Set(["build"]);

/** An exact, relative, single-segment package directory. Anything else is refused, never sanitized. */
const SAFE_PACKAGE = /^packages\/[A-Za-z0-9_-]+$/;

function refuse(message) {
  process.stderr.write(`prepare-proof-packages: ${message}\n`);
  process.exit(1);
}

function run(command, args) {
  const result = spawnSync(command, args, { cwd: ROOT, stdio: "inherit" });
  if (result.error) refuse(`could not start ${command}: ${result.error.message}`);
  if (result.status !== 0) refuse(`${command} ${args.join(" ")} exited ${result.status}`);
}

// ── DERIVE, FROM BOTH AUTHORITIES ────────────────────────────────────────────────────────────────
// Two sets, each printed by the tool that owns it, and neither written down here:
//   • the proof preparation plan, from the resolver's own union of registered and constructed-surface
//     proofs plus the closure of their local `file:` links — this one also says what to BUILD;
//   • the package directories the knockout registry's own suites live in, plus the closure of their
//     local `file:` links, from the registry and the shared dependency resolver. A control added in
//     a package nobody installed — or a suite that directly starts an unprepared local dependency —
//     turns into a baseline that cannot start and that no mutation can make worse.
// A package in the second set that the first does not build is installed and not built: nothing in
// the registry asks for its compiled output, and inventing a build for it here would be this file
// deciding something neither authority said.
function derive(what, args) {
  const result = spawnSync(process.execPath, args, { cwd: ROOT, encoding: "utf8" });
  if (result.error) refuse(`could not run the ${what} deriver: ${result.error.message}`);
  if (result.status !== 0) {
    process.stderr.write(String(result.stderr ?? ""));
    refuse(`the ${what} deriver exited ${result.status}; no plan was produced`);
  }
  return String(result.stdout ?? "").split("\n").filter((line) => line.length !== 0);
}

const lines = derive("proof-package", ["scripts/lint-resolver-parity.mjs", "--print-proof-packages"]);
if (lines.length === 0) refuse("the proof-package deriver produced an empty preparation plan");

const suiteDirs = derive("knockout-suite", ["scripts/lint-control-knockout.mjs", "--print-suite-packages"]);
if (suiteDirs.length === 0) refuse("the knockout-suite deriver produced no packages");

// ── PASS 1: VALIDATE THE WHOLE PLAN, TOUCHING NOTHING ────────────────────────────────────────────
const plan = [];
const seen = new Set();
for (const line of lines) {
  const [cwd, ...actions] = line.split("\t");
  if (!SAFE_PACKAGE.test(cwd)) refuse(`refusing a plan path that is not an exact packages/<name>: ${JSON.stringify(cwd)}`);
  if (seen.has(cwd)) refuse(`the plan names ${cwd} more than once`);
  seen.add(cwd);
  if (new Set(actions).size !== actions.length) {
    refuse(`the plan repeats an action for ${cwd}: ${JSON.stringify(actions)}`);
  }
  for (const action of actions) {
    if (!ALLOWED_ACTIONS.has(action)) refuse(`refusing an unknown action for ${cwd}: ${JSON.stringify(action)}`);
  }
  if (!fs.existsSync(path.join(ROOT, cwd, "package.json"))) refuse(`plan path is not a package: ${cwd}`);
  plan.push({ cwd, actions });
}

// The suite dependency closure is already dependency-first. It is appended AFTER the proof plan, so
// the proof plan's order is untouched: every entry here is one the plan did not already name, and
// none of them is built.
for (const cwd of suiteDirs) {
  if (!SAFE_PACKAGE.test(cwd)) refuse(`refusing a suite path that is not an exact packages/<name>: ${JSON.stringify(cwd)}`);
  if (seen.has(cwd)) continue;
  seen.add(cwd);
  if (!fs.existsSync(path.join(ROOT, cwd, "package.json"))) refuse(`suite path is not a package: ${cwd}`);
  plan.push({ cwd, actions: [] });
}

process.stdout.write("derived preparation plan (package, then its own build script if it has one):\n");
for (const { cwd, actions } of plan) process.stdout.write(`  ${cwd}${actions.length === 0 ? "" : `\t${actions.join("\t")}`}\n`);

// ── PASS 2: EVERY INSTALL ────────────────────────────────────────────────────────────────────────
for (const { cwd } of plan) {
  process.stdout.write(`::group::install ${cwd}\n`);
  run("npm", ["--prefix", cwd, "ci"]);
  process.stdout.write("::endgroup::\n");
}

// ── PASS 3: THEN BUILD, DEPENDENCY BEFORE CONSUMER ───────────────────────────────────────────────
for (const { cwd, actions } of plan) {
  for (const action of actions) {
    process.stdout.write(`::group::${action} ${cwd}\n`);
    run("npm", ["--prefix", cwd, "run", action]);
    process.stdout.write("::endgroup::\n");
  }
}
