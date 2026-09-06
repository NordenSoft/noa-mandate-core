#!/usr/bin/env node
/**
 * G2 control-removal proof.
 *
 * Build a disposable copy of the shipped JavaScript verifier, remove one historical control at a
 * time, and require the canonical corpus oracle to turn red. The shared worktree is never mutated.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const CORPUS = join(ROOT, "conformance", "survivable-retirement");
const argv = process.argv.slice(2);
for (const arg of argv) {
  if (arg !== "--no-build") throw new Error(`unknown argument ${arg}`);
}
if (!argv.includes("--no-build")) {
  const built = spawnSync("npm", ["run", "build"], { cwd: ROOT, encoding: "utf8" });
  if (built.status !== 0 || built.error) {
    process.stderr.write(built.stdout ?? "");
    process.stderr.write(built.stderr ?? "");
    throw built.error ?? new Error(`npm run build exited ${built.status}`);
  }
}

const corpus = JSON.parse(readFileSync(join(CORPUS, "cases.json"), "utf8"));
assert.equal(corpus.spec, "noa.historical-verification-corpus/0.1");

function expectedExit(expected) {
  if (expected.classification === "VERIFIED") return 0;
  if (expected.classification === "PARTIAL" || expected.classification === "UNVERIFIED") return 1;
  if (expected.classification === "CONFLICT") return 7;
  return expected.code === "RECEIPT_INTEGRITY_FAILURE" || expected.code === "WITNESS_INTEGRITY_FAILURE" ? 8 : 3;
}

function runCase(cli, id) {
  const c = corpus.cases.find((candidate) => candidate.id === id);
  assert.ok(c, `missing corpus case ${id}`);
  const args = [
    cli,
    "verify",
    join(CORPUS, c.receipts),
    "--purpose",
    "historical",
    "--keyring",
    join(CORPUS, c.keyring),
  ];
  if (c.checkpoint !== undefined) args.push("--checkpoint", join(CORPUS, c.checkpoint));
  if (c.checkpointKeyring !== undefined) {
    args.push("--checkpoint-keyring", join(CORPUS, c.checkpointKeyring));
  }
  const completed = spawnSync(process.execPath, args, { cwd: ROOT, encoding: "utf8" });
  assert.equal(completed.error, undefined, `${id}: CLI did not start`);
  let actual;
  try {
    actual = JSON.parse(completed.stdout);
  } catch {
    assert.fail(`${id}: CLI returned non-JSON\n${completed.stdout}\n${completed.stderr}`);
  }
  return { c, actual, status: completed.status };
}

function assertOracle(cli, id) {
  const observed = runCase(cli, id);
  assert.deepEqual(observed.actual, observed.c.expected, `${id}: result mismatch`);
  assert.equal(observed.status, expectedExit(observed.c.expected), `${id}: exit mismatch`);
}

function replaceOnce(source, before, after, label) {
  const first = source.indexOf(before);
  assert.ok(first >= 0, `${label}: compiled control marker is absent`);
  assert.equal(source.indexOf(before, first + before.length), -1, `${label}: control marker is ambiguous`);
  return source.slice(0, first) + after + source.slice(first + before.length);
}

const shippedCli = join(ROOT, "dist", "src", "cli.js");
assertOracle(shippedCli, "checkpoint-after-retirement");
assertOracle(shippedCli, "checkpoint-one-nanosecond-before-activation");
assertOracle(shippedCli, "same-key-witness-alias");

const temp = mkdtempSync(join(ROOT, ".g2-knockout-"));
try {
  const sourceDir = join(ROOT, "dist", "src");
  const pristine = readFileSync(join(sourceDir, "verify.js"), "utf8");
  const mutants = [
    {
      name: "strict retirement boundary",
      caseId: "checkpoint-after-retirement",
      before: "if (checkpointTime === null || retirementTime === null || checkpointTime >= retirementTime) {",
      after: "if (false) {",
    },
    {
      name: "inclusive activation lower bound",
      caseId: "checkpoint-one-nanosecond-before-activation",
      before: "if (checkpointTime === null || activationTime === null || checkpointTime < activationTime) {",
      after: "if (false) {",
    },
    {
      name: "witness key-material separation",
      caseId: "same-key-witness-alias",
      before: "if (!witnessKeySeparated) {",
      after: "if (false) {",
    },
  ];

  for (let i = 0; i < mutants.length; i++) {
    const mutant = mutants[i];
    const mutantRoot = join(temp, `mutant-${i}`);
    const mutantSrc = join(mutantRoot, "src");
    cpSync(sourceDir, mutantSrc, { recursive: true });
    writeFileSync(
      join(mutantSrc, "verify.js"),
      replaceOnce(pristine, mutant.before, mutant.after, mutant.name),
    );
    const observed = runCase(join(mutantSrc, "cli.js"), mutant.caseId);
    assert.notDeepEqual(
      observed.actual,
      observed.c.expected,
      `${mutant.name}: removing the control did not make the canonical oracle fail`,
    );
    assert.equal(
      observed.actual.classification,
      "VERIFIED",
      `${mutant.name}: knockout did not reproduce the unsupported historical positive`,
    );
    process.stdout.write(`KILLED: ${mutant.name} (${mutant.caseId})\n`);
  }
} finally {
  rmSync(temp, { recursive: true, force: true });
}

process.stdout.write("survivable-retirement knockout: 3/3 controls load-bearing\n");
