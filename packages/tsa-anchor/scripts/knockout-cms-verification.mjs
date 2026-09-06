#!/usr/bin/env node
/**
 * Mutation proof for authenticated RFC 3161 and its CLI resource boundary.
 *
 * Each mutant is built in a fresh private package copy. The tests must turn red for the exact
 * removed control: CMS authentication, command/monitor/proof deduplication, the 16-unique
 * preflights, command-wide deadline propagation, and weak capability-state retention. The working
 * tree is never mutated.
 */
import { spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const mutants = [
  {
    name: "cms-authentication",
    file: "src/verify.mjs",
    needle: "    return authenticateWithOpenSsl(inspected, policy, resourceBudget);",
    replacement:
      '    return { ok: true, authenticated: true, code: "MUTANT_BYPASS", reason: "OpenSSL verification removed by knockout mutant" };',
    testFile: "verify.test.mjs",
    testPattern: "^verifyStamp: rejects bad CMS signature",
    expectedFailure: "bad CMS signature must fail closed",
  },
  {
    name: "content-deduplication",
    file: "src/cli.mjs",
    needle: "    if (!mapHas(seen, key)) {",
    replacement: "    if (true) {",
    testFile: "cli.test.mjs",
    testPattern: "^CLI verify resource bound: duplicates preserve result order",
    expectedFailure: "two unique anchors must invoke only two five-process verification sequences",
  },
  {
    name: "unique-anchor-preflight",
    file: "src/cli.mjs",
    needle: "  if (uniqueAnchors > MAX_VERIFICATION_UNIQUE_ANCHORS) {",
    replacement: "  if (false) {",
    testFile: "cli.test.mjs",
    testPattern: "^CLI verify resource bound: seventeen unique anchors are refused",
    expectedFailure: "seventeen unique anchors must be rejected with resource-limit exit 7",
  },
  {
    name: "aggregate-deadline-propagation",
    file: "src/verify.mjs",
    needle: "    result = runOpenSslSequence(paths, inspected, policy, resourceBudget);",
    replacement: "    result = runOpenSslSequence(paths, inspected, policy, undefined);",
    testFile: "cli.test.mjs",
    testPattern: "^CLI verify resource bound: aggregate deadline exhaustion",
    expectedFailure: "aggregate deadline exhaustion must use resource-limit exit 7",
  },
  {
    name: "monitor-command-budget-propagation",
    file: "src/cli.mjs",
    needle: "    opts.tsaResourceBudget = verificationResources.resourceBudget;",
    replacement: "    opts.tsaResourceBudget = undefined;",
    testFile: "cli.test.mjs",
    testPattern: "^CLI monitor resource bound: aggregate deadline stops later unique branches",
    expectedFailure: "aggregate deadline exhaustion must use resource-limit exit 7 for fork-scan",
  },
  {
    name: "monitor-verdict-deduplication",
    file: "src/equivocation.mjs",
    needle: "        mapSet(stampVerification.results, jobKey, res);",
    replacement: "        // knockout: do not retain the authenticated monitor verdict",
    testFile: "cli.test.mjs",
    testPattern: "^CLI monitor resource bound: twenty duplicate branches",
    expectedFailure: "duplicate monitor verification must preserve substantive exit 5 for fork-scan",
  },
  {
    name: "proof-branch-preflight",
    file: "src/equivocation.mjs",
    needle: "  if (nb > MAX_VERIFICATION_UNIQUE_ANCHORS) {",
    replacement: "  if (false) {",
    testFile: "equivocation.test.mjs",
    testPattern: "^STAMP RESOURCES",
    expectedFailure: "seventeen proof branches must be refused before OpenSSL",
  },
  {
    name: "proof-verdict-deduplication",
    file: "src/equivocation.mjs",
    needle: "      mapSet(proofStampResults, item.jobKey, res);",
    replacement: "      // knockout: do not retain the authenticated proof verdict",
    testFile: "equivocation.test.mjs",
    testPattern: "^STAMP RESOURCES",
    expectedFailure: "exact duplicate proof jobs must reuse one authenticated verdict without resource exhaustion",
  },
  {
    name: "budget-token-weak-retention",
    file: "src/verify.mjs",
    edits: [
      {
        needle: "const verificationResourceBudgets = newWeakMap();",
        replacement: "const verificationResourceBudgets = new Map();",
      },
      {
        needle: "  weakMapSet(verificationResourceBudgets, token, {",
        replacement: "  verificationResourceBudgets.set(token, {",
      },
      {
        needle: "function reserveOpenSslProcess(resourceBudget, timeoutMs) {\n  if (resourceBudget === undefined) return { valid: true, timeoutMs, deadlineLimited: false };\n  const state = weakMapGet(verificationResourceBudgets, resourceBudget);",
        replacement: "function reserveOpenSslProcess(resourceBudget, timeoutMs) {\n  if (resourceBudget === undefined) return { valid: true, timeoutMs, deadlineLimited: false };\n  const state = verificationResourceBudgets.get(resourceBudget);",
      },
      {
        needle: "function resourceDeadlineExpired(resourceBudget) {\n  if (resourceBudget === undefined) return false;\n  const state = weakMapGet(verificationResourceBudgets, resourceBudget);",
        replacement: "function resourceDeadlineExpired(resourceBudget) {\n  if (resourceBudget === undefined) return false;\n  const state = verificationResourceBudgets.get(resourceBudget);",
      },
    ],
    testFile: "verify.test.mjs",
    testPattern: "^resource budget registry: discarded capability tokens",
    expectedFailure: "discarded resource capabilities must not be strongly retained after GC",
  },
];

const exits = [];
for (let i = 0; i < mutants.length; i++) {
  const mutant = mutants[i];
  const tempRoot = mkdtempSync(join(packageRoot, ".verification-knockout-"));
  try {
    cpSync(join(packageRoot, "src"), join(tempRoot, "src"), { recursive: true });
    cpSync(join(packageRoot, "test"), join(tempRoot, "test"), { recursive: true });
    const mutantPath = join(tempRoot, mutant.file);
    let source = readFileSync(mutantPath, "utf8");
    const edits = mutant.edits ?? [{ needle: mutant.needle, replacement: mutant.replacement }];
    for (let editIndex = 0; editIndex < edits.length; editIndex++) {
      const edit = edits[editIndex];
      const first = source.indexOf(edit.needle);
      if (first < 0 || source.indexOf(edit.needle, first + edit.needle.length) !== -1) {
        throw new Error(`${mutant.name}: knockout target ${editIndex + 1} must occur exactly once in ${mutant.file}`);
      }
      source = source.replace(edit.needle, edit.replacement);
    }
    writeFileSync(mutantPath, source, "utf8");

    const run = spawnSync(
      process.execPath,
      ["--test", `--test-name-pattern=${mutant.testPattern}`, join(tempRoot, "test", mutant.testFile)],
      { cwd: tempRoot, encoding: "utf8", timeout: 60000, maxBuffer: 4 * 1024 * 1024, shell: false },
    );
    if (run.error) throw run.error;
    const output = `${run.stdout ?? ""}${run.stderr ?? ""}`;
    if (run.status === 0 || !output.includes(mutant.expectedFailure)) {
      process.stderr.write(output);
      throw new Error(`${mutant.name}: control-removal mutant survived or failed for an unrelated reason`);
    }
    exits.push(`${mutant.name}:${run.status}`);
  } finally {
    rmSync(tempRoot, { recursive: true, force: true });
  }
}

process.stdout.write(`KNOCKOUT_CMS_VERIFICATION=PASS mutant_exit=${exits[0].split(":")[1]}\n`);
process.stdout.write(`KNOCKOUT_VERIFICATION_RESOURCES=PASS ${exits.slice(1).join(" ")}\n`);
