#!/usr/bin/env node
/**
 * KNOCKOUT ANCHOR LINT — every registry mutation still applies to the source it names.
 *
 * WHY THIS EXISTS. A knockout entry removes a control with a literal `find` -> `replace` edit, and
 * the runner refuses an entry whose `find` does not match EXACTLY ONCE (MUTATION_NOT_APPLIED). That
 * refusal only surfaces inside a knockout shard, hours into CI. A refactor that splits or rewords an
 * anchored line passes every unit suite and every other lint and fails only there. Measured on
 * 2026-09-24: `grant-ownership-before-cas` matched 0 times after the report route's ownership check
 * was split into two statements, and nothing before the shards would have said so.
 *
 * WHAT IT CHECKS — the runner's mutation setup (`scripts/lib/knockout-runner.mjs`), mirrored:
 *   1. targets: every `file` and `companionFile` of the entry and its `andAlso` partner must be a
 *      regular file reached without following a symlink at the final path component;
 *   2. staging: the entry, then its partner; inside one mutation `find` first and then each
 *      `also[].find`, each edit applied to the bytes the previous edit produced (`String.replace`, the
 *      runner's own call). Every edit must match exactly once and every mutation must change its file;
 *   3. the combined sequence must leave every mutated file changed (a pair may not cancel itself);
 *   4. an entry with `expectedSetupIntegrity` must change exactly its one declared file.
 * It reads source files only: it builds, runs and writes nothing. It checks literal applicability, not
 * whether the anchored code still carries the control (semantic rot is the knockout run's job).
 *
 * Usage:  node scripts/lint-knockout-anchors.mjs [--registry-json <file> [--root <dir>]]
 *   --registry-json  check a JSON array of entries instead of the live registry (selftest input)
 *   --root           resolve entry files against <dir> instead of the repository (selftest fixtures)
 * Exit 0 every anchor applies · 1 at least one entry fails (each named on stderr) · 2 usage or input
 * error. Selftest: scripts/lint-knockout-anchors.selftest.mjs.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { knockoutRegistrySnapshot } from "./lint-control-knockout.mjs";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function usage(message) {
  console.error(`lint-knockout-anchors: ${message}`);
  console.error("usage: node scripts/lint-knockout-anchors.mjs [--registry-json <file> [--root <dir>]]");
  process.exit(2);
}

function parseArgs(argv) {
  const opts = {};
  for (let i = 0; i < argv.length; i += 2) {
    const [flag, value] = [argv[i], argv[i + 1]];
    if ((flag !== "--registry-json" && flag !== "--root") || value === undefined || flag.slice(2) in opts) {
      usage(`unexpected arguments: ${argv.join(" ")}`);
    }
    opts[flag.slice(2)] = value;
  }
  if (opts.root !== undefined && opts["registry-json"] === undefined) usage("--root needs --registry-json");
  return opts;
}

function loadRegistry(file) {
  if (file === undefined) return knockoutRegistrySnapshot().registry;
  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (error) {
    usage(`cannot read ${file}: ${String(error && error.message)}`);
  }
  if (!Array.isArray(parsed) || parsed.length === 0) usage("--registry-json must hold a non-empty array");
  return parsed;
}

/** A registry path must name something inside the root by a relative path. */
function underRoot(root, rel) {
  if (typeof rel !== "string" || rel.length === 0 || path.isAbsolute(rel)) return null;
  const abs = path.resolve(root, rel);
  return abs.startsWith(root + path.sep) ? abs : null;
}

/** The runner's observeFileNoFollow, reduced to its verdict: a regular file, never through a symlink. */
function observe(root, rel) {
  const abs = underRoot(root, rel);
  if (abs === null) return { error: `${JSON.stringify(rel)} is not a path inside the repository` };
  let st;
  try {
    st = fs.lstatSync(abs);
  } catch (error) {
    if (error && error.code === "ENOENT") return { error: `${rel} does not exist` };
    return { error: `${rel} cannot be observed (${String(error && error.code)})` };
  }
  if (st.isSymbolicLink()) return { error: `${rel} is a symlink; the runner refuses to follow it` };
  if (!st.isFile()) return { error: `${rel} is not a regular file` };
  return { text: fs.readFileSync(abs, "utf8") };
}

/** Non-overlapping occurrence count, computed exactly as the runner computes it. */
const hits = (src, find) => src.split(find).length - 1;

function stageEntry(root, entry, byId) {
  const paired = entry.andAlso === undefined ? null : byId.get(entry.andAlso);
  if (entry.andAlso !== undefined && !paired) return [`andAlso names missing entry ${JSON.stringify(entry.andAlso)}`];
  const mutations = [entry, ...(paired ? [paired] : [])];
  const pristine = new Map();
  for (const mutation of mutations) {
    for (const rel of [mutation.file, ...(mutation.companionFile === undefined ? [] : [mutation.companionFile])]) {
      if (pristine.has(rel)) continue;
      const seen = observe(root, rel);
      if (seen.error) return [`${mutation.id}: ${seen.error}`];
      pristine.set(rel, seen.text);
    }
  }
  const mutated = new Map(pristine);
  for (const mutation of mutations) {
    const edits = [{ find: mutation.find, replace: mutation.replace }, ...(mutation.also ?? [])];
    let src = mutated.get(mutation.file);
    const before = src;
    for (const [index, edit] of edits.entries()) {
      const label = index === 0 ? "find" : `also[${index - 1}].find`;
      if (typeof edit.find !== "string" || edit.find.length === 0) return [`${mutation.id}: ${label} must be a non-empty string`];
      if (typeof edit.replace !== "string") return [`${mutation.id}: the replace for ${label} must be a string`];
      const n = hits(src, edit.find);
      if (n !== 1) return [`${mutation.id}: ${label} matched ${n}x in ${mutation.file} (must be exactly 1)`];
      src = src.replace(edit.find, edit.replace); // the runner's own call, `$` patterns included
    }
    if (src === before) return [`${mutation.id}: the mutation leaves ${mutation.file} byte-identical`];
    mutated.set(mutation.file, src);
  }
  for (const mutation of mutations) {
    if (mutated.get(mutation.file) === pristine.get(mutation.file)) {
      return [`${mutation.id}: the combined mutation sequence leaves ${mutation.file} byte-identical`];
    }
  }
  if (entry.expectedSetupIntegrity !== undefined) {
    const changed = [...mutated].filter(([rel, src]) => src !== pristine.get(rel)).map(([rel]) => rel);
    if (changed.length !== 1 || changed[0] !== entry.file) {
      return [`setup-integrity mutation changes ${JSON.stringify(changed)}, not exactly its one declared file ${entry.file}`];
    }
  }
  return [];
}

const opts = parseArgs(process.argv.slice(2));
const root = opts.root === undefined ? REPO_ROOT : path.resolve(opts.root);
const registry = loadRegistry(opts["registry-json"]);
const byId = new Map(registry.map((entry) => [entry.id, entry]));
const failures = [];
let edits = 0;
for (const entry of registry) {
  edits += 1 + (Array.isArray(entry.also) ? entry.also.length : 0);
  for (const problem of stageEntry(root, entry, byId)) failures.push({ id: entry.id, problem });
}
if (failures.length > 0) {
  for (const { id, problem } of failures) console.error(`knockout anchor FAIL [${id}] ${problem}`);
  console.error(`lint-knockout-anchors: ${failures.length} of ${registry.length} entries do not apply`);
  process.exit(1);
}
console.log(
  `lint-knockout-anchors: OK — ${registry.length} entries, ${edits} edits; every target is a regular file, ` +
    "every find matches exactly once and every mutation changes its file",
);
