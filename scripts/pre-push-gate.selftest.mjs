import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

// Keep the existing end-to-end selftest authoritative; this adapter gives the knockout observer
// an authored node:test terminal without copying the command or classifier contracts.
test("pre-push Tier-A argv selftest is portable and exact", () => {
  const options = {
    cwd: fileURLToPath(new URL("../", import.meta.url)),
    encoding: "utf8",
    maxBuffer: 1024 * 1024,
    shell: false,
    timeout: 30_000,
  };
  const observed = spawnSync(process.execPath, ["scripts/pre-push-gate.mjs", "--selftest-tier-a-argv"], options);
  assert.ifError(observed.error);
  assert.equal(observed.signal, null);
  assert.equal(observed.status, 0, observed.stderr);
  assert.match(observed.stderr, /SELFTEST PASS: boundary pre-push exact Tier-A argv/);
  assert.doesNotMatch(observed.stderr, /SELFTEST FAIL/);

  for (const hookArgs of [
    ["--selftest-tier-a-argv", "https://example.invalid/synthetic.git"],
    ["origin", "--selftest-tier-a-argv"],
  ]) {
    const hookCall = spawnSync(process.execPath, ["scripts/pre-push-gate.mjs", ...hookArgs], options);
    assert.ifError(hookCall.error);
    assert.equal(hookCall.signal, null);
    assert.equal(hookCall.status, 1, hookCall.stderr);
    assert.match(hookCall.stderr, /SETUP_FAILED/);
    assert.doesNotMatch(hookCall.stderr, /SELFTEST PASS/);
  }
});

test("pre-push selftest validates the exact Tier-A command and isolated wrapper", () => {
  const observed = spawnSync(process.execPath, ["scripts/pre-push-gate.mjs", "--selftest"], {
    cwd: fileURLToPath(new URL("../", import.meta.url)),
    encoding: "utf8",
    maxBuffer: 1024 * 1024,
    shell: false,
    timeout: 120_000,
  });
  assert.ifError(observed.error);
  assert.equal(observed.signal, null);
  assert.equal(observed.status, 0, observed.stderr);
  assert.match(observed.stderr, /SELFTEST PASS/);
  assert.doesNotMatch(observed.stderr, /SELFTEST FAIL/);
});
