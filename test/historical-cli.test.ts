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

test("current-purpose CLI gives a retired-key signature its own exit and steer; tampering keeps exit 2 without one", () => {
  const current = (receipts: string) => {
    const completed = spawnSync(process.execPath, [
      CLI,
      "verify",
      join(CONF, receipts),
      "--keyring",
      join(CONF, "receipt-keyring-retired.json"),
    ], { encoding: "utf8" });
    return { status: completed.status ?? -1, stdout: completed.stdout, stderr: completed.stderr };
  };

  // Intact bytes, authentic signatures, key retired by the lifecycle root: exit 9, not the legacy 2.
  const retired = current("chain.json");
  assert.equal(retired.status, 9, retired.stderr);
  const retiredJson = JSON.parse(retired.stdout);
  assert.equal(retiredJson.status, "KEY_RETIRED");
  assert.equal(retiredJson.signaturesVerified, false);
  assert.equal(retiredJson.badSeq, 0);
  assert.match(retiredJson.reason, /--purpose historical/);
  const retiredWarnings = retiredJson.warnings.filter((w: string) => w.startsWith("key-retired:"));
  assert.equal(retiredWarnings.length, 1, JSON.stringify(retiredJson.warnings));
  assert.match(retiredWarnings[0], /^key-retired: seq 0 kid "g2-receipt-retired" \(receipt\)/);
  assert.match(retired.stderr, /--purpose historical/);

  // Same key, same lifecycle root, altered bytes at seq 1: TAMPERED, exit 2, and no historical steer.
  const damaged = current("chain-damaged.json");
  assert.equal(damaged.status, 2, damaged.stderr);
  const damagedJson = JSON.parse(damaged.stdout);
  assert.equal(damagedJson.status, "TAMPERED");
  assert.match(damagedJson.reason, /hash mismatch/);
  assert.equal(damagedJson.badSeq, 1);
  assert.doesNotMatch(damaged.stdout + damaged.stderr, /--purpose historical|key-retired/);
});

test("witnessed current-purpose CLI: a retired-key signature exits 9 with the note; later tampering exits 2 without it", () => {
  // The opt-in federation path (--anchors/--trust-set) stops at the chain verdict when the chain did
  // not verify. An empty snapshot is enough: the chain verdict is what decides the exit here.
  const temp = mkdtempSync(join(tmpdir(), "noa-witnessed-retired-"));
  try {
    const anchors = join(temp, "anchors.json");
    const trustSet = join(temp, "trust-set.json");
    writeFileSync(anchors, "[]");
    writeFileSync(trustSet, JSON.stringify({ witnesses: [], quorum: 0 }));
    const witnessed = (receipts: string) => {
      const completed = spawnSync(process.execPath, [
        CLI, "verify", join(CONF, receipts),
        "--keyring", join(CONF, "receipt-keyring-retired.json"),
        "--anchors", anchors, "--trust-set", trustSet,
      ], { encoding: "utf8" });
      return { status: completed.status ?? -1, stdout: completed.stdout, stderr: completed.stderr };
    };

    const retired = witnessed("chain.json");
    assert.equal(retired.status, 9, retired.stderr);
    assert.equal(JSON.parse(retired.stdout).chain.status, "KEY_RETIRED");
    assert.match(retired.stderr, /chain did not verify \(KEY_RETIRED\)/);
    assert.match(retired.stderr, /^note: .*--purpose historical/m);

    const damaged = witnessed("chain-damaged.json");
    assert.equal(damaged.status, 2, damaged.stderr);
    assert.equal(JSON.parse(damaged.stdout).chain.status, "TAMPERED");
    assert.match(damaged.stderr, /chain did not verify \(TAMPERED\)/);
    assert.doesNotMatch(damaged.stdout + damaged.stderr, /--purpose historical|key-retired|^note:/m);
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
});
