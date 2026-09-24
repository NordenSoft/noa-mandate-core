#!/usr/bin/env node
/**
 * G2 control-removal proof.
 *
 * Build a disposable copy of the shipped JavaScript verifier, remove one historical control at a
 * time, and require the canonical corpus oracle to turn red. The shared worktree is never mutated.
 *
 * The same disposable-copy method proves that the current-use half of the corpus DEFINES the
 * KEY_RETIRED refusal order: each mutant swaps one adjacent pair of that order (or reports a
 * different retired signature), and every case named for the pair must stop matching the oracle.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { currentUseMismatch } from "./lib/current-use-oracle.mjs";

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
assertOracle(shippedCli, "witness-one-nanosecond-before-activation");
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
      name: "witness activation lower bound",
      caseId: "witness-one-nanosecond-before-activation",
      before: "const witnessValidFrom = witnessTrust.validFromByKid[checkpoint.sig.kid];",
      after: "const witnessValidFrom = undefined;",
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

  // ── CURRENT USE: every adjacent pair of the KEY_RETIRED refusal order, swapped one at a time ────
  const current = new Map(corpus.currentUse.cases.map((c) => [c.id, c]));
  const runCurrent = (cli, id) => {
    const c = current.get(id);
    assert.ok(c !== undefined, `unknown current-use case ${id}`);
    const args = [cli, "verify", join(CORPUS, c.receipts), "--keyring", join(CORPUS, c.keyring)];
    if (c.checkpoint !== undefined) args.push("--checkpoint", join(CORPUS, c.checkpoint));
    if (c.identity !== undefined) args.push("--identity", join(CORPUS, c.identity));
    const completed = spawnSync(process.execPath, args, { cwd: ROOT, encoding: "utf8" });
    return currentUseMismatch(c.expected, { stdout: completed.stdout, stderr: completed.stderr, exit: completed.status });
  };
  const early = (subject, kid, seq) =>
    `return keyRetired(${subject}, ${kid}, chainId, list.length, ${seq}, [keyRetiredWarning(${subject}, ${kid}, ${seq})]);`;
  // Cross-phase swaps in LABELED-BREAK form: once a receipt signature is found retired, skip the rest
  // of the checkpoint step from one phase onward, then finish normally, so every warning survives
  // and only the ordering differs. A later receipt's own phases are skipped the same way ("later").
  const LABEL = ["if (checkpointSnap !== undefined) {", "cpblock: if (checkpointSnap !== undefined) {"];
  const skipFrom = (marker) => [marker, `if (retiredSeq >= 0) break cpblock; ${marker}`];
  const later = "!(retiredSeq >= 0 && retiredSeq < seq)";
  const orderMutants = [
    {
      name: "KEY_RETIRED above receipt signature authentication",
      caseIds: ["current-retired-kid-forged-signature", "current-retired-then-altered"],
      edits: [["const pub = keyring[r.sig.kid];",
        `if (verification.retiredKids[r.sig.kid] === true) ${early('"receipt"', "r.sig.kid", "seq")} const pub = keyring[r.sig.kid];`]],
    },
    {
      name: "KEY_RETIRED above receipt identity binding (UNTRUSTED)",
      caseIds: ["current-retired-receipt-unauthorized-identity"],
      edits: [["if (retiredSeq < 0 && verification.retiredKids[r.sig.kid] === true) {",
        `if (verification.retiredKids[r.sig.kid] === true) ${early('"receipt"', "r.sig.kid", "seq")} if (false) {`]],
    },
    {
      name: "KEY_RETIRED above the checkpoint MALFORMED check",
      caseIds: ["current-retired-checkpoint-not-an-object"],
      edits: [["let tailChecked = false;",
        `if (retiredSeq >= 0) ${early("retiredSubject", "retiredKid", "retiredSeq")} let tailChecked = false;`]],
    },
    {
      name: "the LAST retired signature reported instead of the first",
      caseIds: ["current-first-retired-signature-mid-chain"],
      edits: [["if (retiredSeq < 0 && verification.retiredKids[r.sig.kid] === true) {",
        "if (verification.retiredKids[r.sig.kid] === true) {"]],
    },
    {
      name: "a checkpoint finding outranks a receipt finding",
      caseIds: ["current-receipt-finding-outranks-checkpoint"],
      edits: [["if (checkpointKeyRetired && retiredSeq < 0) {", "if (checkpointKeyRetired) {"]],
    },
    {
      name: "KEY_RETIRED above checkpoint signature authentication",
      caseIds: ["current-retired-checkpoint-forged"],
      edits: [["cpVerify = verifyCheckpointParsed(cp, retainedPublicMaterial(verification));", 'cpVerify = "ok";']],
    },
    {
      name: "KEY_RETIRED above the checkpoint head and opener checks",
      caseIds: ["current-retired-checkpoint-truncated-head", "current-retired-checkpoint-unauthorized-identity"],
      edits: [['checkpointKeyRetired = cpVerify === "ok";',
        `checkpointKeyRetired = cpVerify === "ok"; if (checkpointKeyRetired) ${early('"checkpoint"', "cp.sig.kid", "head.chain.seq")}`]],
    },
    {
      name: "B2: a retired receipt skips the checkpoint from AUTHENTICATION onward",
      caseIds: ["current-retired-receipts-forged-checkpoint"],
      edits: [LABEL, skipFrom("let cpVerify = verifyCheckpointParsed(cp, verification);")],
    },
    {
      name: "C2: a retired receipt skips the checkpoint from the HEAD match onward",
      caseIds: ["current-retired-receipts-truncated-head"],
      edits: [LABEL, skipFrom("if (cp.chain !== chainId)")],
    },
    {
      name: "D2: a retired receipt skips the checkpoint OPENER binding",
      caseIds: ["current-retired-receipts-checkpoint-unauthorized-opener"],
      edits: [LABEL, skipFrom("const genesis = ordered[0];")],
    },
    {
      name: "W: later receipts skip signature, identity and linkage after a retired signature",
      caseIds: ["current-retired-then-later-untrusted", "current-retired-then-later-forged-signature", "current-retired-then-later-broken-linkage"],
      edits: [["if (haveKeyring) {\n                const pub = keyring[r.sig.kid];",
        "if (retiredSeq >= 0 && retiredSeq < seq) { prev = r; continue; } if (haveKeyring) {\n                const pub = keyring[r.sig.kid];"]],
    },
    {
      name: "W-signature: later receipts skip only the signature check",
      caseIds: ["current-retired-then-later-forged-signature"],
      edits: [["if (haveKeyring) {\n                const pub = keyring[r.sig.kid];",
        `if (haveKeyring && ${later}) {\n                const pub = keyring[r.sig.kid];`]],
    },
    {
      name: "W-identity: later receipts skip only the identity binding",
      caseIds: ["current-retired-then-later-untrusted"],
      edits: [["if (haveKeyring && haveManifest) {\n                const allowed = mapGet(manifest, r.agent.id);",
        `if (haveKeyring && haveManifest && ${later}) {\n                const allowed = mapGet(manifest, r.agent.id);`]],
    },
    {
      name: "W-linkage: later receipts skip only the linkage check",
      caseIds: ["current-retired-then-later-broken-linkage"],
      edits: [["else if (r.chain.prevHash !== prev.chain.hash) {",
        `else if (${later} && r.chain.prevHash !== prev.chain.hash) {`]],
    },
  ];
  for (const c of corpus.currentUse.cases) {
    assert.equal(runCurrent(shippedCli, c.id), null, `${c.id}: the shipped verifier does not match the current-use oracle`);
  }
  for (let i = 0; i < orderMutants.length; i++) {
    const mutant = orderMutants[i];
    const mutantRoot = join(temp, `order-mutant-${i}`);
    const mutantSrc = join(mutantRoot, "src");
    cpSync(sourceDir, mutantSrc, { recursive: true });
    let mutated = pristine;
    for (const [before, after] of mutant.edits) mutated = replaceOnce(mutated, before, after, mutant.name);
    writeFileSync(join(mutantSrc, "verify.js"), mutated);
    for (const id of mutant.caseIds) {
      const mismatch = runCurrent(join(mutantSrc, "cli.js"), id);
      assert.notEqual(mismatch, null, `${mutant.name}: swapping the pair left ${id} matching the oracle`);
      process.stdout.write(`KILLED: ${mutant.name} (${id}: ${mismatch})\n`);
    }
  }
  process.stdout.write(`survivable-retirement current-use ordering: ${orderMutants.length}/${orderMutants.length} swaps detected\n`);
} finally {
  rmSync(temp, { recursive: true, force: true });
}

process.stdout.write("survivable-retirement knockout: 4/4 controls load-bearing\n");
