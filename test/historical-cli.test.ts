import { spawnSync } from "node:child_process";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { test } from "node:test";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI = join(HERE, "..", "src", "cli.js");
const CONF = join(HERE, "..", "..", "conformance", "survivable-retirement");

function run(
  receipts: string,
  checkpoint?: string,
  checkpointKeyring = "checkpoint-keyring.json",
  keyring = "receipt-keyring-retired.json",
): { readonly status: number; readonly stdout: string; readonly stderr: string } {
  const args = [
    CLI,
    "verify",
    join(CONF, receipts),
    "--purpose",
    "historical",
    "--keyring",
    join(CONF, keyring),
  ];
  if (checkpoint !== undefined) {
    args.push("--checkpoint", join(CONF, checkpoint), "--checkpoint-keyring", join(CONF, checkpointKeyring));
  }
  const completed = spawnSync(process.execPath, args, { encoding: "utf8" });
  return { status: completed.status ?? -1, stdout: completed.stdout, stderr: completed.stderr };
}

test("historical CLI emits the versioned JSON classification and distinct process exits", () => {
  const exact = run("chain.json", "checkpoints/exact-before-retirement.json");
  assert.equal(exact.status, 0, exact.stderr);
  const exactJson = JSON.parse(exact.stdout) as {
    spec: string;
    classification: string;
    code: string;
    dimensions: { completeness: string };
  };
  assert.equal(exactJson.spec, "noa.historical-verification/0.1");
  assert.equal(exactJson.classification, "VERIFIED");
  assert.equal(exactJson.code, "HEAD_ANCHORED");
  assert.equal(exactJson.dimensions.completeness, "HEAD_ANCHORED");

  const prefix = run("chain.json", "checkpoints/prefix-before-retirement.json");
  const prefixJson = JSON.parse(prefix.stdout) as { classification: string; dimensions: { completeness: string } };
  assert.equal(prefix.status, 1);
  assert.equal(prefixJson.classification, "PARTIAL");
  assert.equal(prefixJson.dimensions.completeness, "PREFIX_ANCHORED");

  const conflict = run("chain.json", "checkpoints/conflict.json");
  const conflictJson = JSON.parse(conflict.stdout) as { classification: string; code: string; dimensions: { integrity: string; completeness: string } };
  assert.equal(conflict.status, 7, "authenticated contradiction collapsed into the legacy TAMPERED exit");
  assert.equal(conflictJson.classification, "CONFLICT");
  assert.equal(conflictJson.code, "CHECKPOINT_CONFLICT");
  assert.equal(conflictJson.dimensions.integrity, "INTACT");
  assert.equal(conflictJson.dimensions.completeness, "CONFLICT");

  const damaged = run("chain-damaged.json", "checkpoints/exact-before-retirement.json");
  const damagedJson = JSON.parse(damaged.stdout) as { classification: string; code: string; dimensions: { integrity: string } };
  assert.equal(damaged.status, 8, "cryptographic receipt damage collapsed into a malformed-input exit");
  assert.equal(damagedJson.classification, "INVALID");
  assert.equal(damagedJson.code, "RECEIPT_INTEGRITY_FAILURE");
  assert.equal(damagedJson.dimensions.integrity, "BROKEN");

  const malformedWitness = run("chain.json", "receipt-keyring-static.json");
  const malformedJson = JSON.parse(malformedWitness.stdout) as { classification: string; code: string };
  assert.equal(malformedWitness.status, 3, "malformed witness was mislabelled as cryptographic damage");
  assert.equal(malformedJson.classification, "INVALID");
  assert.equal(malformedJson.code, "WITNESS_MALFORMED");

  const beforeActivation = run(
    "chain.json",
    "checkpoints/exact-before-retirement.json",
    "checkpoint-keyring.json",
    "receipt-keyring-before-activation.json",
  );
  const beforeActivationJson = JSON.parse(beforeActivation.stdout) as { classification: string; code: string };
  assert.equal(beforeActivation.status, 1, "unattributable intact history must use the neutral unverified exit");
  assert.equal(beforeActivationJson.classification, "UNVERIFIED");
  assert.equal(beforeActivationJson.code, "CHECKPOINT_BEFORE_ACTIVATION");
});

test("historical CLI rejects an unused or current-purpose checkpoint keyring", () => {
  const unused = spawnSync(process.execPath, [
    CLI,
    "verify",
    join(CONF, "chain.json"),
    "--purpose",
    "historical",
    "--keyring",
    join(CONF, "receipt-keyring-retired.json"),
    "--checkpoint-keyring",
    join(CONF, "checkpoint-keyring.json"),
  ], { encoding: "utf8" });
  assert.equal(unused.status, 4);
  assert.match(unused.stderr, /--checkpoint-keyring requires --checkpoint/);

  const current = spawnSync(process.execPath, [
    CLI,
    "verify",
    join(CONF, "chain.json"),
    "--checkpoint",
    join(CONF, "checkpoints/exact-before-retirement.json"),
    "--checkpoint-keyring",
    join(CONF, "checkpoint-keyring.json"),
  ], { encoding: "utf8" });
  assert.equal(current.status, 4);
  assert.match(current.stderr, /--checkpoint-keyring requires --purpose historical/);
});

test("historical CLI ignores inherited checkpoint and identity option values", () => {
  const temp = mkdtempSync(join(tmpdir(), "noa-historical-cli-poison-"));
  const preload = join(temp, "poison.mjs");
  writeFileSync(preload, [
    'Object.defineProperty(Object.prototype, "checkpoint", { value: "{}", configurable: true });',
    'Object.defineProperty(Object.prototype, "identityManifest", { value: JSON.stringify({ "g2-historical-agent": ["attacker"] }), configurable: true });',
  ].join("\n"));
  try {
    const noWitness = spawnSync(process.execPath, [
      "--import", preload,
      CLI,
      "verify",
      join(CONF, "chain.json"),
      "--purpose", "historical",
      "--keyring", join(CONF, "receipt-keyring-retired.json"),
    ], { encoding: "utf8" });
    assert.equal(noWitness.status, 1, noWitness.stderr);
    assert.equal(JSON.parse(noWitness.stdout).code, "NO_WITNESS");

    const exact = spawnSync(process.execPath, [
      "--import", preload,
      CLI,
      "verify",
      join(CONF, "chain.json"),
      "--purpose", "historical",
      "--keyring", join(CONF, "receipt-keyring-retired.json"),
      "--checkpoint", join(CONF, "checkpoints", "exact-before-retirement.json"),
      "--checkpoint-keyring", join(CONF, "checkpoint-keyring.json"),
    ], { encoding: "utf8" });
    assert.equal(exact.status, 0, exact.stderr);
    assert.equal(JSON.parse(exact.stdout).classification, "VERIFIED");
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
});
