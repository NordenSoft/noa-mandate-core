/**
 * A supervisor-supplied boot identifier (docs/gate-pinned-trust.md): every worker of one boot must
 * share one `bootId`, so a supervisor may supply it, together with the boot's start (test/pinned-boot-start.test.ts).
 * It is 32 lowercase hex characters (128 bits); anything else is refused before any file is read, and no
 * trust root is built on it.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseGateRoster } from "../src/roster.js";
import { createPinnedTrust, isBootId, loadPinnedTrust, type LoadPinnedTrustInput, type PinnedBoot, type PinnedRefusal } from "../src/trust.js";
import { freshDir, newWorld, rosterBytes, rosterDoc, writeKeyFile, writeRoster, type RosterWorld } from "./helpers/pinned.js";

const NOW = Date.parse("2026-09-01T12:00:00.000Z");
const OTHER_UID = 4242;
const SUPERVISOR_BOOT = "0123456789abcdef0123456789abcdef";
const MALFORMED = [
  "0123456789ABCDEF0123456789ABCDEF", // upper case
  "0123456789abcdef0123456789abcde", // 31
  "0123456789abcdef0123456789abcdef0", // 33
  "0123456789abcdef0123456789abcdeg", // not hex
  "01234567-89ab-cdef-0123-456789abcdef", // a UUID spelling
  "",
];

function onDisk(world: RosterWorld, over: Partial<LoadPinnedTrustInput> = {}): LoadPinnedTrustInput {
  const dir = freshDir("boot-id");
  return {
    rosterFile: writeRoster(dir, rosterDoc(world, NOW)),
    keyFile: writeKeyFile(dir, world.gate),
    rosterSha256: undefined,
    unsafeSameUid: false,
    tenantEnv: undefined,
    grantSignerSocketSet: false,
    gateEuid: OTHER_UID,
    nowMs: NOW,
    now: () => NOW,
    lockState: false,
    ...over,
  };
}

function booted(r: PinnedBoot | PinnedRefusal): asserts r is PinnedBoot {
  assert.equal(r.ok, true, `expected a boot, got ${JSON.stringify(r)}`);
}

test("BOOT-ID — a supervisor's bootId is the trust root's bootId (SUPERVISOR); without one the process mints its own (SELF)", () => {
  const world = newWorld();
  const supplied = loadPinnedTrust(onDisk(world, { bootId: SUPERVISOR_BOOT, bootStartedAt: new Date(NOW - 60 * 1000).toISOString() }));
  booted(supplied);
  assert.equal(supplied.trust.bootId, SUPERVISOR_BOOT);
  assert.equal(supplied.bootIdSource, "SUPERVISOR");
  const own = loadPinnedTrust(onDisk(world));
  booted(own);
  assert.notEqual(own.trust.bootId, SUPERVISOR_BOOT);
  assert.equal(own.bootIdSource, "SELF");
  assert.equal(isBootId(SUPERVISOR_BOOT), true);
});

test("BOOT-ID-INVALID — a malformed supervisor bootId builds no trust root, before any file is read", () => {
  const world = newWorld();
  for (const bootId of MALFORMED) {
    // With a well-formed boot start beside it, only the identifier's format can refuse it.
    const bootStartedAt = new Date(NOW - 60 * 1000).toISOString();
    const r = loadPinnedTrust(onDisk(world, { bootId, bootStartedAt }));
    assert.equal(r.ok, false, `consequence: no gate boots on the bootId ${JSON.stringify(bootId)}`);
    assert.equal((r as PinnedRefusal).code, "BOOT_ID_INVALID");
    // First: a missing roster file is not what refuses it.
    const early = loadPinnedTrust(onDisk(world, { bootId, bootStartedAt, rosterFile: "/nonexistent/roster.json" }));
    assert.equal((early as PinnedRefusal).code, "BOOT_ID_INVALID");
    const parsed = parseGateRoster(rosterBytes(rosterDoc(world, NOW)));
    if (!parsed.ok) throw new Error("fixture roster refused");
    let trust: unknown = null;
    let refusal: unknown = null;
    try {
      trust = createPinnedTrust({
        roster: parsed.roster,
        rosterDigest: parsed.digest,
        activeApproverKid: parsed.activeApproverKid,
        expiresAtMs: parsed.expiresAtMs,
        gateKey: { kid: world.gate.kid, publicKey: world.gate.publicKey, privateKey: world.gate.privateKey },
        stateStatus: "INITIALIZED",
        bootId,
        bootStartedAt,
        now: () => NOW,
      });
    } catch (e) {
      refusal = e;
    }
    assert.equal(trust, null, `consequence: no trust root is built on the bootId ${JSON.stringify(bootId)}`);
    assert.match(String(refusal), /^Error: BOOT_ID_INVALID/);
    assert.equal(isBootId(bootId), false);
  }
});
