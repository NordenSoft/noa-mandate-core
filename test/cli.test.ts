import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, symlinkSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const CLI = join(__dirname, "..", "src", "cli.js");
const VEC = join(__dirname, "..", "..", "conformance", "vectors");

function run(args: string[]): number {
  const r = spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8" });
  return r.status ?? -1;
}

test("CLI exit-code contract: 0 VALID / 1 UNVERIFIED / 2 TAMPERED / 3 MALFORMED / 4 USAGE", () => {
  // 0 — VALID (keyring + checkpoint)
  assert.equal(
    run(["verify", join(VEC, "valid-chain.json"), "--keyring", join(VEC, "keyring.json"), "--checkpoint", join(VEC, "checkpoint.json")]),
    0,
  );
  // 1 — UNVERIFIED (no keyring; signatures not authenticated)
  assert.equal(run(["verify", join(VEC, "valid-chain.json")]), 1);
  // 2 — TAMPERED
  assert.equal(run(["verify", join(VEC, "attack", "tampered-content.json"), "--keyring", join(VEC, "keyring.json")]), 2);
  // 2 — forged checkpoint must not fake a tail check
  assert.equal(
    run(["verify", join(VEC, "attack", "forged-checkpoint-chain.json"), "--keyring", join(VEC, "keyring.json"), "--checkpoint", join(VEC, "attack", "forged-checkpoint-cp.json")]),
    2,
  );
  // 3 — MALFORMED (duplicate key rejected by the strict parser)
  assert.equal(run(["verify", join(VEC, "malformed", "duplicate-key.json")]), 3);
  // 4 — USAGE
  assert.equal(run([]), 4);
  assert.equal(run(["verify"]), 4); // missing file
  assert.equal(run(["verify", join(VEC, "valid-chain.json"), "--keyring"]), 4); // trailing flag, no value
  assert.equal(run(["verify", join(VEC, "valid-chain.json"), "--checkpoint"]), 4);
  assert.equal(run(["bogus-command"]), 4);
});

// ── --profile native|strict-bytes (opt-in) ─────────────────────────────────────────────────────────
// Every case of conformance/vectors/strict-bytes/manifest.json, against its AUTHORED expectations:
// the default and `--profile native` must print the same result, and `--profile strict-bytes` must
// exit with the pinned code and lead its `reason` with the pinned discriminator.
const SB = join(VEC, "strict-bytes");

function runOut(args: string[]): { code: number; stdout: string } {
  const r = spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8" });
  return { code: r.status ?? -1, stdout: r.stdout };
}

test("CLI --profile strict-bytes: every manifest case exits as authored; native output is unchanged", () => {
  const manifest = JSON.parse(readFileSync(join(SB, "manifest.json"), "utf8")) as {
    keyring: string;
    cases: Array<{ file: string; native: { status: string; exit: number } | null; strict: { status: string; exit: number; discriminator: string | null } }>;
  };
  const statusOf = (stdout: string): string | undefined => {
    try {
      return (JSON.parse(stdout) as { status?: string }).status;
    } catch {
      return undefined;
    }
  };
  assert.equal(manifest.cases.length, 13, "the strict-bytes corpus has 13 authored cases");
  const kr = join(SB, manifest.keyring);
  for (const c of manifest.cases) {
    const file = join(SB, c.file);
    const strict = runOut(["verify", file, "--keyring", kr, "--profile", "strict-bytes"]);
    assert.equal(strict.code, c.strict.exit, `${c.file} strict: ${strict.stdout}`);
    assert.equal(statusOf(strict.stdout), c.strict.status, `${c.file} strict status`);
    if (c.strict.discriminator !== null) {
      const reason = (JSON.parse(strict.stdout) as { reason?: string }).reason ?? "";
      assert.ok(reason.startsWith(c.strict.discriminator), `${c.file} strict reason: ${reason}`);
    }
    const omitted = runOut(["verify", file, "--keyring", kr]);
    const explicit = runOut(["verify", file, "--keyring", kr, "--profile", "native"]);
    assert.equal(explicit.code, omitted.code, `${c.file}: --profile native must equal the default`);
    assert.equal(explicit.stdout, omitted.stdout, `${c.file}: --profile native must print the default output`);
    if (c.native !== null) {
      assert.equal(omitted.code, c.native.exit, `${c.file} native: ${omitted.stdout}`);
      assert.equal(statusOf(omitted.stdout), c.native.status, `${c.file} native status`);
    }
  }
});

test("CLI --profile: missing, unknown, repeated or unsupported combinations are usage errors (exit 4)", () => {
  const canonical = join(SB, "canonical.json");
  const kr = join(VEC, "keyring.json");
  assert.equal(run(["verify", canonical, "--profile"]), 4);
  assert.equal(run(["verify", canonical, "--profile", "strict"]), 4);
  assert.equal(run(["verify", canonical, "--profile", "STRICT-BYTES"]), 4);
  assert.equal(run(["verify", canonical, "--profile", "native", "--profile", "native"]), 4);
  assert.equal(run(["verify", canonical, "--profile", "strict-bytes", "--profile", "native"]), 4);
  assert.equal(run(["verify", canonical, "--keyring", kr, "--purpose", "historical", "--profile", "strict-bytes"]), 4);
  assert.equal(run(["verify", canonical, "--profile", "strict-bytes", "--anchors", kr, "--trust-set", kr]), 4);
  // native stays combinable with historical: the profile flag alone changes nothing there.
  assert.notEqual(run(["verify", canonical, "--keyring", kr, "--purpose", "historical", "--profile", "native"]), 4);
});

test("CLI refuses a symlinked JSON input instead of following a swapped path", { skip: process.platform === "win32" }, () => {
  const dir = mkdtempSync(join(tmpdir(), "noa-cli-nofollow-"));
  try {
    const link = join(dir, "receipts.json");
    symlinkSync(join(VEC, "valid-chain.json"), link);
    assert.equal(run(["verify", link]), 4);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
