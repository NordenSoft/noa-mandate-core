import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { writeFileSync, mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { buildAnchor, buildCheckpoint, buildReceipt, generateKeyPair, sha256Prefixed } from "noa-receipt";
import { anchorHash } from "../src/anchor-hash.mjs";
import { createVerificationResourceBudget, verifyStamp } from "../src/verify.mjs";
import { startMockTsa } from "./mock-tsa-server.mjs";
import { createAuthenticatedTsaFixture, createCountingOpenSsl } from "./openssl-tsa-fixture.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const CLI = join(__dirname, "..", "src", "cli.mjs");

/**
 * Async spawn, NOT spawnSync: the mock TSA server (startMockTsa, below) runs its HTTP listener
 * in-process, on this same test-runner's event loop. spawnSync blocks that event loop for the
 * child's entire lifetime, so a child that calls back into our own in-process mock server would
 * deadlock (the server can never accept/respond while the parent is frozen inside spawnSync).
 * spawn() lets the event loop keep servicing the mock server's HTTP handler while we await exit.
 */
function run(args) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI, ...args]);
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    child.on("close", (status) => resolve({ status: status ?? -1, stdout, stderr }));
  });
}

function mkAnchor(kp = generateKeyPair("cli-test-witness")) {
  const frontier = {
    chain: "tenant-acme/orders",
    highestSeq: 5,
    headHash: "sha256:" + "a".repeat(64),
    ts: "2026-06-23T10:00:00Z",
  };
  return buildAnchor(frontier, { kid: kp.kid, privateKey: kp.privateKey });
}

function mkAnchorsFile(dir, anchor = mkAnchor()) {
  const path = join(dir, "anchors.json");
  writeFileSync(path, JSON.stringify([anchor]), "utf8");
  return path;
}

const AUTHENTICATED_WITNESS = generateKeyPair("cli-authenticated-witness");
const AUTHENTICATED_ANCHOR = mkAnchor(AUTHENTICATED_WITNESS);
let tsaFixture;
let boundedAuthenticatedSet;
let monitorAuthenticatedSet;

before(() => {
  tsaFixture = createAuthenticatedTsaFixture(AUTHENTICATED_ANCHOR);
});

after(() => tsaFixture?.cleanup());

function getBoundedAuthenticatedSet() {
  if (boundedAuthenticatedSet !== undefined) return boundedAuthenticatedSet;
  const anchors = [AUTHENTICATED_ANCHOR];
  const records = [tsaFixture.valid];
  for (let i = 1; i < 17; i++) {
    const anchor = mkAnchor();
    anchors.push(anchor);
    records.push(tsaFixture.stampFor(anchor));
  }
  boundedAuthenticatedSet = { anchors, records };
  return boundedAuthenticatedSet;
}

function getMonitorAuthenticatedSet() {
  if (monitorAuthenticatedSet !== undefined) return monitorAuthenticatedSet;
  const witnesses = [AUTHENTICATED_WITNESS];
  const anchors = [AUTHENTICATED_ANCHOR];
  const records = [tsaFixture.valid];
  for (let i = 1; i < 17; i++) {
    const witness = generateKeyPair(`cli-monitor-witness-${i}`);
    const anchor = mkAnchor(witness);
    witnesses.push(witness);
    anchors.push(anchor);
    if (i < 16) records.push(tsaFixture.stampFor(anchor));
  }

  const author = generateKeyPair("cli-monitor-checkpoint-author");
  const authorSigner = { kid: author.kid, privateKey: author.privateKey };
  const receipts = [];
  let previous = null;
  for (let i = 0; i < 6; i++) {
    previous = buildReceipt(
      {
        id: `cli-monitor-receipt-${i}`,
        ts: `2026-06-20T00:0${i}:00.000Z`,
        scope: { tenant: "t", chain: "tenant-acme/orders" },
        agent: { id: "a", model: null, principal: "SERVICE" },
        action: {
          id: "db.write",
          canonical: "db.write",
          riskClass: "LOW",
          paramsHash: sha256Prefixed(`monitor-${i}`),
          reversible: true,
          rollbackRef: null,
        },
        governance: { mode: "on", verdict: "EXECUTED", ruleId: "r", approval: null, sandboxed: false },
      },
      previous,
      authorSigner,
    );
    receipts.push(previous);
  }
  monitorAuthenticatedSet = {
    anchors,
    records,
    receipts,
    checkpoint: buildCheckpoint(receipts[5], "2026-06-23T10:00:00Z", authorSigner),
    trustSet: {
      witnesses: witnesses.map((witness) => ({ kid: witness.kid, pubkey: witness.publicKey })),
      quorum: 2,
    },
  };
  return monitorAuthenticatedSet;
}

function tsaVerificationFlags(dir, executable = tsaFixture.executable) {
  const rootsPath = join(dir, "tsa-roots.pem");
  const crlsPath = join(dir, "tsa-crls.pem");
  writeFileSync(rootsPath, tsaFixture.trustRoots, { mode: 0o600 });
  writeFileSync(crlsPath, tsaFixture.crls, { mode: 0o600 });
  return [
    "--openssl", executable,
    "--tsa-trust-roots", rootsPath,
    "--tsa-policy", tsaFixture.policyOid,
    "--tsa-crls", crlsPath,
    "--tsa-now", new Date().toISOString(),
    "--tsa-max-future-skew-ms", "300000",
  ];
}

function countingOpenSsl(dir, { stall = false } = {}) {
  return createCountingOpenSsl(dir, tsaFixture.executable, { stall });
}

function writeVerifyInputs(dir, anchors, records) {
  const anchorsPath = join(dir, "anchors.json");
  const tsrPath = join(dir, "anchors.tsr.json");
  const sidecar = {};
  for (let i = 0; i < anchors.length; i++) {
    if (records[i] !== undefined) sidecar[anchorHash(anchors[i])] = records[i];
  }
  writeFileSync(anchorsPath, JSON.stringify(anchors), "utf8");
  writeFileSync(tsrPath, JSON.stringify(sidecar), "utf8");
  return { anchorsPath, tsrPath };
}

function writeMonitorInputs(dir, anchors, records, monitorSet) {
  const inputs = writeVerifyInputs(dir, anchors, records);
  const trustSetPath = join(dir, "trust-set.json");
  const receiptsPath = join(dir, "receipts.json");
  const checkpointPath = join(dir, "checkpoint.json");
  writeFileSync(trustSetPath, JSON.stringify(monitorSet.trustSet), "utf8");
  writeFileSync(receiptsPath, JSON.stringify(monitorSet.receipts), "utf8");
  writeFileSync(checkpointPath, JSON.stringify(monitorSet.checkpoint), "utf8");
  return { ...inputs, trustSetPath, receiptsPath, checkpointPath };
}

test("CLI usage: no args / unknown command -> exit 4", async () => {
  assert.equal((await run([])).status, 4);
  assert.equal((await run(["bogus"])).status, 4);
  assert.equal((await run(["stamp"])).status, 4); // missing --anchors/--tsa-url
});

test("CLI verify: explicit OpenSSL, roots, policy, CRLs, and clock are mandatory", async () => {
  const dir = mkdtempSync(join(tmpdir(), "noa-tsa-cli-"));
  const anchorsPath = mkAnchorsFile(dir, AUTHENTICATED_ANCHOR);
  const tsrPath = join(dir, "anchors.tsr.json");
  writeFileSync(tsrPath, JSON.stringify({ [anchorHash(AUTHENTICATED_ANCHOR)]: tsaFixture.valid }), "utf8");
  const result = await run(["verify", "--anchors", anchorsPath, "--tsr", tsrPath]);
  assert.equal(result.status, 4, result.stdout + result.stderr);
  assert.match(result.stderr, /authenticated stamp verification requires --openssl/);
});

test("CLI verify: a cryptographically signed trusted RFC 3161 token exits 0", async () => {
  const dir = mkdtempSync(join(tmpdir(), "noa-tsa-cli-"));
  const anchorsPath = mkAnchorsFile(dir, AUTHENTICATED_ANCHOR);
  const tsrPath = join(dir, "anchors.tsr.json");
  writeFileSync(tsrPath, JSON.stringify({ [anchorHash(AUTHENTICATED_ANCHOR)]: tsaFixture.valid }), "utf8");

  const verifyResult = await run(["verify", "--anchors", anchorsPath, "--tsr", tsrPath, ...tsaVerificationFlags(dir)]);
  assert.equal(verifyResult.status, 0, verifyResult.stderr);
  const parsed = JSON.parse(verifyResult.stdout);
  assert.equal(parsed.mismatches, 0);
  assert.equal(parsed.results[0].ok, true);
  assert.equal(parsed.results[0].authenticated, true);
});

test("CLI verify resource bound: duplicates preserve result order but each unique anchor invokes OpenSSL once", async () => {
  const dir = mkdtempSync(join(tmpdir(), "noa-tsa-cli-dedup-"));
  try {
    const other = mkAnchor();
    const otherStamp = tsaFixture.stampFor(other);
    const anchors = [AUTHENTICATED_ANCHOR, other, AUTHENTICATED_ANCHOR, other, AUTHENTICATED_ANCHOR];
    const records = [tsaFixture.valid, otherStamp, tsaFixture.valid, otherStamp, tsaFixture.valid];
    const inputs = writeVerifyInputs(dir, anchors, records);
    const wrapper = countingOpenSsl(dir);
    const result = await run([
      "verify", "--anchors", inputs.anchorsPath, "--tsr", inputs.tsrPath,
      ...tsaVerificationFlags(dir, wrapper.executable),
    ]);

    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.equal(wrapper.count(), 2 * 6, "two unique anchors must invoke only two six-process verification sequences");
    const output = JSON.parse(result.stdout);
    assert.equal(output.results.length, anchors.length);
    assert.deepEqual(
      output.results.map((entry) => entry.anchorHash),
      anchors.map((anchor) => anchorHash(anchor)),
      "deduplication must not reorder or remove caller-visible result entries",
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("CLI verify resource bound: twenty identical anchors still invoke one six-process verification", async () => {
  const dir = mkdtempSync(join(tmpdir(), "noa-tsa-cli-dedup-one-"));
  try {
    const anchors = Array.from({ length: 20 }, () => AUTHENTICATED_ANCHOR);
    const inputs = writeVerifyInputs(dir, anchors, anchors.map(() => tsaFixture.valid));
    const wrapper = countingOpenSsl(dir);
    const result = await run([
      "verify", "--anchors", inputs.anchorsPath, "--tsr", inputs.tsrPath,
      ...tsaVerificationFlags(dir, wrapper.executable),
    ]);

    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.equal(wrapper.count(), 6);
    const output = JSON.parse(result.stdout);
    assert.equal(output.results.length, 20);
    assert.equal(output.mismatches, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("CLI verify resource bound: sixteen unique authenticated anchors pass within exactly ninety-six process credits", async () => {
  const dir = mkdtempSync(join(tmpdir(), "noa-tsa-cli-limit-pass-"));
  try {
    const set = getBoundedAuthenticatedSet();
    const anchors = set.anchors.slice(0, 16);
    const records = set.records.slice(0, 16);
    const inputs = writeVerifyInputs(dir, anchors, records);
    const wrapper = countingOpenSsl(dir);
    const result = await run([
      "verify", "--anchors", inputs.anchorsPath, "--tsr", inputs.tsrPath,
      ...tsaVerificationFlags(dir, wrapper.executable),
    ]);

    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.equal(wrapper.count(), 16 * 6);
    const output = JSON.parse(result.stdout);
    assert.equal(output.results.length, 16);
    assert.equal(output.mismatches, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("CLI verify resource bound: seventeen unique anchors are refused before any OpenSSL process", async () => {
  const dir = mkdtempSync(join(tmpdir(), "noa-tsa-cli-limit-refuse-"));
  try {
    const set = getBoundedAuthenticatedSet();
    const inputs = writeVerifyInputs(dir, set.anchors, set.records);
    const wrapper = countingOpenSsl(dir);
    const result = await run([
      "verify", "--anchors", inputs.anchorsPath, "--tsr", inputs.tsrPath,
      ...tsaVerificationFlags(dir, wrapper.executable),
    ]);

    assert.equal(result.status, 7, `seventeen unique anchors must be rejected with resource-limit exit 7: ${result.stdout}${result.stderr}`);
    assert.equal(wrapper.count(), 0, "the unique-anchor preflight must run before OpenSSL");
    const output = JSON.parse(result.stdout);
    assert.equal(output.code, "VERIFICATION_RESOURCE_LIMIT");
    assert.equal(output.uniqueAnchors, 17);
    assert.equal(output.limits.maxUniqueAnchors, 16);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("CLI verify resource bound: aggregate deadline exhaustion stops every remaining unique anchor", async () => {
  const dir = mkdtempSync(join(tmpdir(), "noa-tsa-cli-deadline-"));
  try {
    const other = mkAnchor();
    const inputs = writeVerifyInputs(dir, [AUTHENTICATED_ANCHOR, other], [tsaFixture.valid, tsaFixture.stampFor(other)]);
    const wrapper = countingOpenSsl(dir, { stall: true });
    const result = await run([
      "verify", "--anchors", inputs.anchorsPath, "--tsr", inputs.tsrPath,
      ...tsaVerificationFlags(dir, wrapper.executable),
      "--tsa-command-timeout-ms", "1000",
    ]);

    assert.equal(result.status, 7, `aggregate deadline exhaustion must use resource-limit exit 7: ${result.stdout}${result.stderr}`);
    // The aggregate budget includes stamp inspection and workspace preparation, so it may expire before
    // the first process starts. Once the first wrapper stalls, no further process may start.
    assert.ok(wrapper.count() <= 1, "deadline exhaustion in the first unique anchor must prevent every later process start");
    const output = JSON.parse(result.stdout);
    assert.equal(output.code, "VERIFICATION_RESOURCE_LIMIT");
    assert.equal(output.resourceLimited, true);
    assert.equal(output.results[0].code, "VERIFICATION_RESOURCE_LIMIT");
    assert.equal(output.results[1].code, "VERIFICATION_RESOURCE_LIMIT");
    assert.match(output.results[1].reason, /not attempted/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("verification resource bound: an already expired capability starts no OpenSSL process", async () => {
  const dir = mkdtempSync(join(tmpdir(), "noa-tsa-expired-capability-"));
  try {
    const wrapper = countingOpenSsl(dir);
    const policy = {
      opensslExecutable: wrapper.executable,
      trustRoots: tsaFixture.trustRoots,
      allowedPolicyOids: [tsaFixture.policyOid],
      revocation: { mode: "crl-check-all", crls: tsaFixture.crls },
      clock: { now: new Date().toISOString(), maxFutureSkewMs: 300000 },
    };
    const budget = createVerificationResourceBudget(100, 1);
    assert.notEqual(budget, null);
    await new Promise((resolve) => setTimeout(resolve, 150));

    const result = verifyStamp(AUTHENTICATED_ANCHOR, tsaFixture.valid, policy, budget);
    assert.equal(result.ok, false);
    assert.equal(result.authenticated, false);
    assert.equal(result.code, "VERIFICATION_RESOURCE_LIMIT", result.reason);
    assert.equal(wrapper.count(), 0, "an expired capability must refuse before the first process starts");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("CLI verify resource bound: command timeout override is strictly bounded", async () => {
  const dir = mkdtempSync(join(tmpdir(), "noa-tsa-cli-timeout-"));
  try {
    const inputs = writeVerifyInputs(dir, [AUTHENTICATED_ANCHOR], [tsaFixture.valid]);
    const base = [
      "verify", "--anchors", inputs.anchorsPath, "--tsr", inputs.tsrPath,
      ...tsaVerificationFlags(dir),
    ];
    for (const value of ["99", "30001", "100.5", "not-a-number"]) {
      const result = await run([...base, "--tsa-command-timeout-ms", value]);
      assert.equal(result.status, 4, `${value}: ${result.stdout}${result.stderr}`);
      assert.match(result.stderr, /--tsa-command-timeout-ms must be an integer from 100 through 30000/);
    }
    const missing = await run([...base, "--tsa-command-timeout-ms"]);
    assert.equal(missing.status, 4, missing.stdout + missing.stderr);
    assert.match(missing.stderr, /--tsa-command-timeout-ms requires a value/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("CLI monitor resource bound: twenty duplicate branches preserve output but invoke one OpenSSL sequence", async () => {
  const monitorSet = getMonitorAuthenticatedSet();
  const anchors = Array.from({ length: 20 }, () => monitorSet.anchors[0]);
  const records = anchors.map(() => monitorSet.records[0]);
  for (const command of ["fork-scan", "corroborate"]) {
    const dir = mkdtempSync(join(tmpdir(), `noa-tsa-cli-monitor-dedup-${command}-`));
    try {
      const inputs = writeMonitorInputs(dir, anchors, records, monitorSet);
      const wrapper = countingOpenSsl(dir);
      const commandArgs = command === "fork-scan"
        ? [command, "--anchors", inputs.anchorsPath, "--trust-set", inputs.trustSetPath, "--chain", inputs.receiptsPath]
        : [command, "--checkpoint", inputs.checkpointPath, "--anchors", inputs.anchorsPath, "--trust-set", inputs.trustSetPath];
      const result = await run([
        ...commandArgs,
        "--tsr", inputs.tsrPath,
        ...tsaVerificationFlags(dir, wrapper.executable),
      ]);

      assert.equal(
        result.status,
        5,
        `duplicate monitor verification must preserve substantive exit 5 for ${command}`,
      );
      assert.equal(wrapper.count(), 6, `${command}: duplicate branches must share one six-process verification`);
      const output = JSON.parse(result.stdout);
      assert.equal(output.findings[0].branches.length, 16, "the existing branch-output cap and order must be preserved");
      assert.deepEqual(
        output.findings[0].branches.map((branch) => branch.anchorHash),
        Array.from({ length: 16 }, () => anchorHash(monitorSet.anchors[0])),
      );
      assert.ok(output.findings[0].branches.every((branch) => branch.stamp.code === "OK"));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
});

test("CLI monitor resource bound: sixteen unique stamped anchors consume exactly ninety-six process credits", async () => {
  const dir = mkdtempSync(join(tmpdir(), "noa-tsa-cli-monitor-limit-pass-"));
  try {
    const monitorSet = getMonitorAuthenticatedSet();
    const inputs = writeMonitorInputs(
      dir,
      monitorSet.anchors.slice(0, 16),
      monitorSet.records.slice(0, 16),
      monitorSet,
    );
    const wrapper = countingOpenSsl(dir);
    const result = await run([
      "fork-scan", "--anchors", inputs.anchorsPath, "--trust-set", inputs.trustSetPath,
      "--chain", inputs.receiptsPath, "--tsr", inputs.tsrPath,
      ...tsaVerificationFlags(dir, wrapper.executable),
    ]);

    assert.equal(result.status, 5, result.stdout + result.stderr);
    assert.equal(wrapper.count(), 16 * 6);
    const output = JSON.parse(result.stdout);
    assert.equal(output.resourceLimited, false);
    assert.equal(output.findings[0].branches.length, 16);
    assert.ok(output.findings[0].branches.every((branch) => branch.stamp.code === "OK"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("CLI monitor resource bound: seventeen unique anchors are refused before OpenSSL on both paths", async () => {
  const monitorSet = getMonitorAuthenticatedSet();
  for (const command of ["fork-scan", "corroborate"]) {
    const dir = mkdtempSync(join(tmpdir(), `noa-tsa-cli-monitor-limit-refuse-${command}-`));
    try {
      const inputs = writeMonitorInputs(dir, monitorSet.anchors, [], monitorSet);
      const wrapper = countingOpenSsl(dir);
      const commandArgs = command === "fork-scan"
        ? [command, "--anchors", inputs.anchorsPath, "--trust-set", inputs.trustSetPath, "--chain", inputs.receiptsPath]
        : [command, "--checkpoint", inputs.checkpointPath, "--anchors", inputs.anchorsPath, "--trust-set", inputs.trustSetPath];
      const result = await run([
        ...commandArgs,
        "--tsr", inputs.tsrPath,
        ...tsaVerificationFlags(dir, wrapper.executable),
      ]);

      assert.equal(
        result.status,
        7,
        `seventeen unique monitor anchors must use preflight resource-limit exit 7 for ${command}: ${result.stdout}${result.stderr}`,
      );
      assert.equal(wrapper.count(), 0, `${command}: preflight refusal must precede OpenSSL`);
      const output = JSON.parse(result.stdout);
      assert.equal(output.code, "VERIFICATION_RESOURCE_LIMIT");
      assert.equal(output.resourceLimited, true);
      assert.equal(output.uniqueAnchors, 17);
      assert.equal(output.limits.maxOpenSslProcesses, 96);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
});

test("CLI monitor resource bound: aggregate deadline stops later unique branches and exits 7", async () => {
  const monitorSet = getMonitorAuthenticatedSet();
  for (const command of ["fork-scan", "corroborate"]) {
    const dir = mkdtempSync(join(tmpdir(), `noa-tsa-cli-monitor-deadline-${command}-`));
    try {
      const inputs = writeMonitorInputs(
        dir,
        monitorSet.anchors.slice(0, 2),
        monitorSet.records.slice(0, 2),
        monitorSet,
      );
      const wrapper = countingOpenSsl(dir, { stall: true });
      const commandArgs = command === "fork-scan"
        ? [command, "--anchors", inputs.anchorsPath, "--trust-set", inputs.trustSetPath, "--chain", inputs.receiptsPath]
        : [command, "--checkpoint", inputs.checkpointPath, "--anchors", inputs.anchorsPath, "--trust-set", inputs.trustSetPath];
      const result = await run([
        ...commandArgs,
        "--tsr", inputs.tsrPath,
        ...tsaVerificationFlags(dir, wrapper.executable),
        "--tsa-command-timeout-ms", "1000",
      ]);

      assert.equal(
        result.status,
        7,
        `aggregate deadline exhaustion must use resource-limit exit 7 for ${command}: ${result.stdout}${result.stderr}`,
      );
      assert.ok(wrapper.count() <= 1, `${command}: no later unique branch may start after deadline exhaustion`);
      const output = JSON.parse(result.stdout);
      assert.equal(output.code, "VERIFICATION_RESOURCE_LIMIT");
      assert.equal(output.resourceLimited, true);
      assert.equal(output.limits.commandTimeoutMs, 1000);
      assert.ok(output.findings[0].branches.every((branch) => branch.stamp.code === "VERIFICATION_RESOURCE_LIMIT"));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
});

test("CLI monitor resource bound: aggregate timeout flag is bounded and requires --tsr", async () => {
  const dir = mkdtempSync(join(tmpdir(), "noa-tsa-cli-monitor-timeout-"));
  try {
    const monitorSet = getMonitorAuthenticatedSet();
    const inputs = writeMonitorInputs(dir, [monitorSet.anchors[0]], [monitorSet.records[0]], monitorSet);
    const common = [
      "--anchors", inputs.anchorsPath,
      "--trust-set", inputs.trustSetPath,
      "--tsr", inputs.tsrPath,
      ...tsaVerificationFlags(dir),
    ];
    for (const command of ["fork-scan", "corroborate"]) {
      const prefix = command === "fork-scan"
        ? [command, ...common, "--chain", inputs.receiptsPath]
        : [command, "--checkpoint", inputs.checkpointPath, ...common];
      for (const value of ["99", "30001", "100.5", "not-a-number"]) {
        const result = await run([...prefix, "--tsa-command-timeout-ms", value]);
        assert.equal(result.status, 4, `${command} ${value}: ${result.stdout}${result.stderr}`);
        assert.match(result.stderr, /--tsa-command-timeout-ms must be an integer from 100 through 30000/);
      }
      const missing = await run([...prefix, "--tsa-command-timeout-ms"]);
      assert.equal(missing.status, 4, `${command}: ${missing.stdout}${missing.stderr}`);
      assert.match(missing.stderr, /--tsa-command-timeout-ms requires a value/);
    }
    const withoutTsr = await run([
      "fork-scan", "--anchors", inputs.anchorsPath, "--trust-set", inputs.trustSetPath,
      "--tsa-command-timeout-ms", "1000",
    ]);
    assert.equal(withoutTsr.status, 4, withoutTsr.stdout + withoutTsr.stderr);
    assert.match(withoutTsr.stderr, /only when --tsr is supplied/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("CLI stamp: an unsigned mock response cannot be upgraded to verify exit 0", async () => {
  const mock = await startMockTsa({ mode: "ok" });
  try {
    const dir = mkdtempSync(join(tmpdir(), "noa-tsa-cli-"));
    const anchorsPath = mkAnchorsFile(dir, AUTHENTICATED_ANCHOR);
    const tsrPath = join(dir, "anchors.tsr.json");

    const stampResult = await run(["stamp", "--anchors", anchorsPath, "--tsa-url", mock.url, "--out", tsrPath]);
    assert.equal(stampResult.status, 0, stampResult.stderr);

    const verifyResult = await run(["verify", "--anchors", anchorsPath, "--tsr", tsrPath, ...tsaVerificationFlags(dir)]);
    assert.equal(verifyResult.status, 1, verifyResult.stderr);
    const parsed = JSON.parse(verifyResult.stdout);
    assert.equal(parsed.mismatches, 1);
    assert.equal(parsed.results[0].ok, false);
    assert.equal(parsed.results[0].code, "CMS_SIGNER_COUNT_INVALID");
  } finally {
    await mock.close();
  }
});

test("CLI verify: exit 1 when the .tsr file has no stamp for the anchor", async () => {
  const dir = mkdtempSync(join(tmpdir(), "noa-tsa-cli-"));
  const anchorsPath = mkAnchorsFile(dir, AUTHENTICATED_ANCHOR);
  const tsrPath = join(dir, "empty.tsr.json");
  writeFileSync(tsrPath, "{}", "utf8");
  const result = await run(["verify", "--anchors", anchorsPath, "--tsr", tsrPath, ...tsaVerificationFlags(dir)]);
  assert.equal(result.status, 1);
});

test("CLI verify: a JSON-array .tsr (not an object map) -> exit 4 (USAGE), not a bogus mismatch", async () => {
  // typeof [] === "object", so the old `typeof sidecar !== "object" || sidecar === null` guard let a
  // JSON array through; every `sidecar[anchorHash]` lookup then read undefined and the run exited 1
  // (MISMATCH) instead of the documented 4 (USAGE) — symmetric with the --anchors Array.isArray guard.
  const dir = mkdtempSync(join(tmpdir(), "noa-tsa-cli-"));
  const anchorsPath = mkAnchorsFile(dir);
  const tsrPath = join(dir, "arr.tsr.json");
  writeFileSync(tsrPath, "[1,2,3]", "utf8");
  const result = await run(["verify", "--anchors", anchorsPath, "--tsr", tsrPath]);
  assert.equal(result.status, 4, result.stdout + result.stderr);
  assert.match(result.stderr, /--tsr file must contain a JSON object/);
});

test("CLI stamp: exit 2 when the TSA is unreachable", async () => {
  const dir = mkdtempSync(join(tmpdir(), "noa-tsa-cli-"));
  const anchorsPath = mkAnchorsFile(dir);
  const result = await run(["stamp", "--anchors", anchorsPath, "--tsa-url", "http://127.0.0.1:1"]);
  assert.equal(result.status, 2);
});

test("CLI verify: malformed JSON input -> exit 3 (MALFORMED), clean message, no raw stack", async () => {
  const dir = mkdtempSync(join(tmpdir(), "noa-tsa-cli-"));
  const bad = join(dir, "bad.json");
  writeFileSync(bad, "{bad", "utf8");
  const result = await run(["verify", "--anchors", bad, "--tsr", bad]);
  assert.equal(result.status, 3, result.stderr);
  assert.match(result.stderr, /malformed JSON/i);
  assert.doesNotMatch(result.stderr, /at (readJsonFile|safeParse|parseObject)/, "must not leak a raw stack trace");
});

test("CLI verify: a stamp record with undecodable DER -> exit 3 (MALFORMED, not a plain mismatch)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "noa-tsa-cli-"));
  const anchor = AUTHENTICATED_ANCHOR;
  const anchorsPath = join(dir, "anchors.json");
  writeFileSync(anchorsPath, JSON.stringify([anchor]), "utf8");
  const tsrPath = join(dir, "bad.tsr.json");
  // base64 that decodes fine but is not a decodable TimeStampResp (tag claims a 25-octet length).
  writeFileSync(tsrPath, JSON.stringify({ [anchorHash(anchor)]: { tsr: Buffer.from([0x30, 0x02, 0x99, 0x99]).toString("base64") } }), "utf8");
  const result = await run(["verify", "--anchors", anchorsPath, "--tsr", tsrPath, ...tsaVerificationFlags(dir)]);
  assert.equal(result.status, 3, result.stdout + result.stderr);
});

test("CLI stamp: a malformed anchor entry -> exit 3 (MALFORMED) before any network I/O", async () => {
  const dir = mkdtempSync(join(tmpdir(), "noa-tsa-cli-"));
  const anchorsPath = join(dir, "anchors.json");
  writeFileSync(anchorsPath, JSON.stringify([{ not: "an anchor" }]), "utf8");
  // unroutable TSA url — must NOT be reached; anchorHash rejects the entry first (exit 3, not 2).
  const result = await run(["stamp", "--anchors", anchorsPath, "--tsa-url", "http://127.0.0.1:1"]);
  assert.equal(result.status, 3, result.stderr);
  assert.match(result.stderr, /malformed anchor/i);
});

test("CLI refuses a symlinked JSON input instead of following a swapped path", { skip: process.platform === "win32" }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "noa-tsa-cli-nofollow-"));
  try {
    const target = mkAnchorsFile(dir);
    const link = join(dir, "anchors-link.json");
    const tsrPath = join(dir, "empty.tsr.json");
    symlinkSync(target, link);
    writeFileSync(tsrPath, "{}", "utf8");
    const result = await run(["verify", "--anchors", link, "--tsr", tsrPath]);
    assert.equal(result.status, 4, result.stdout + result.stderr);
    assert.match(result.stderr, /cannot open file/i);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
