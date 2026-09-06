#!/usr/bin/env node
/** Build all five verifier ports and require exact result + exit-code parity on the canonical G2 corpus. */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const CORPUS = join(ROOT, "conformance", "survivable-retirement");
const argv = process.argv.slice(2);
for (const arg of argv) {
  if (arg !== "--no-build") throw new Error(`unknown argument ${arg}`);
}
const noBuild = argv.includes("--no-build");

function run(command, args, cwd = ROOT) {
  const result = spawnSync(command, args, { cwd, encoding: "utf8" });
  if (result.error || result.status !== 0) {
    process.stderr.write(result.stdout ?? "");
    process.stderr.write(result.stderr ?? "");
    throw result.error ?? new Error(`${command} ${args.join(" ")} exited ${result.status}`);
  }
  return result;
}

if (noBuild) {
  // CI's five-verifier job has already built each exact executable through its existing legacy
  // conformance step. Regenerate with the already-built TS generator, then reuse those artifacts;
  // the workflow's scoped git diff below makes any checked-in corpus drift fatal.
  run("node", [join(ROOT, "dist", "scripts", "gen-survivable-retirement-vectors.js")]);
} else {
  run("npm", ["run", "build"]);
  run("npm", ["run", "gen:survivable-retirement-vectors"]);
  run("go", ["test", "./..."], join(ROOT, "impl-go"));
  run("go", ["build", "-o", "noa-verify", "."], join(ROOT, "impl-go"));
  run("cargo", ["test"], join(ROOT, "impl-rust"));
  run("cargo", ["build"], join(ROOT, "impl-rust"));
  run("dotnet", ["build", "--nologo"], join(ROOT, "impl-csharp"));
}

const corpus = JSON.parse(readFileSync(join(CORPUS, "cases.json"), "utf8"));
assert.equal(corpus.spec, "noa.historical-verification-corpus/0.1");

const implementations = {
  typescript(c) {
    return ["node", [
      join(ROOT, "dist", "src", "cli.js"), "verify", join(CORPUS, c.receipts),
      "--purpose", "historical", "--keyring", join(CORPUS, c.keyring),
    ]];
  },
  python(c) {
    return ["python3", [
      join(ROOT, "impl-py", "noa_verify.py"), join(CORPUS, c.receipts), join(CORPUS, c.keyring),
      "--purpose", "historical",
    ]];
  },
  go(c) {
    return [join(ROOT, "impl-go", "noa-verify"), [
      join(CORPUS, c.receipts), join(CORPUS, c.keyring), "--purpose", "historical",
    ]];
  },
  rust(c) {
    return [join(ROOT, "impl-rust", "target", noBuild ? "release" : "debug", "noa-verify"), [
      join(CORPUS, c.receipts), join(CORPUS, c.keyring), "--purpose", "historical",
    ]];
  },
  csharp(c) {
    if (noBuild) {
      return ["dotnet", [
        join(ROOT, "impl-csharp", "bin", "Release", "net10.0", "noa-verify.dll"),
        join(CORPUS, c.receipts), join(CORPUS, c.keyring), "--purpose", "historical",
      ]];
    }
    return ["dotnet", [
      "run", "--project", join(ROOT, "impl-csharp"), "--no-build", "--",
      join(CORPUS, c.receipts), join(CORPUS, c.keyring), "--purpose", "historical",
    ]];
  },
};

function expectedExit(expected) {
  if (expected.classification === "VERIFIED") return 0;
  if (expected.classification === "PARTIAL" || expected.classification === "UNVERIFIED") return 1;
  if (expected.classification === "CONFLICT") return 7;
  return expected.code === "RECEIPT_INTEGRITY_FAILURE" || expected.code === "WITNESS_INTEGRITY_FAILURE" ? 8 : 3;
}

const allOutputs = new Map();
for (const [name, commandFor] of Object.entries(implementations)) {
  let passed = 0;
  for (const c of corpus.cases) {
    const [command, args] = commandFor(c);
    if (c.checkpoint !== undefined) args.push("--checkpoint", join(CORPUS, c.checkpoint));
    if (c.checkpointKeyring !== undefined) args.push("--checkpoint-keyring", join(CORPUS, c.checkpointKeyring));
    const invocation = spawnSync(command, args, { cwd: ROOT, encoding: "utf8" });
    assert.equal(invocation.error, undefined, `${name}/${c.id}: failed to start`);
    let actual;
    try {
      actual = JSON.parse(invocation.stdout);
    } catch {
      assert.fail(`${name}/${c.id}: non-JSON output\n${invocation.stdout}\n${invocation.stderr}`);
    }
    assert.deepEqual(actual, c.expected, `${name}/${c.id}: result mismatch`);
    assert.equal(invocation.status, expectedExit(c.expected), `${name}/${c.id}: exit mismatch`);
    assert.notEqual(actual.dimensions.evidence.availability, "PROVEN_SUPPRESSED", `${name}/${c.id}`);
    const prior = allOutputs.get(c.id);
    if (prior !== undefined) assert.deepEqual(actual, prior, `${name}/${c.id}: cross-port divergence`);
    else allOutputs.set(c.id, actual);
    passed++;
  }
  process.stdout.write(`${name}: ${passed}/${corpus.cases.length} PASS\n`);
}

const e = allOutputs.get("e-static-no-witness");
const retirement = allOutputs.get("e-plus-retirement-no-witness");
const witness = allOutputs.get("e-plus-witness-exact-head");
const both = allOutputs.get("e-plus-retirement-and-witness");
for (const item of [e, retirement, witness, both]) assert.equal(item.dimensions.integrity, "INTACT");
assert.equal(e.dimensions.attribution, "UNATTRIBUTABLE");
assert.equal(retirement.dimensions.attribution, "UNATTRIBUTABLE");
assert.equal(witness.dimensions.attribution, "ATTRIBUTABLE_AS_OF");
assert.equal(both.dimensions.attribution, "ATTRIBUTABLE_AS_OF");
assert.equal(allOutputs.get("honest-stale-prefix").classification, "PARTIAL");
assert.equal(allOutputs.get("honest-stale-prefix").dimensions.completeness, "PREFIX_ANCHORED");

process.stdout.write(`survivable-retirement: ${corpus.cases.length} cases x ${Object.keys(implementations).length} ports PASS\n`);
