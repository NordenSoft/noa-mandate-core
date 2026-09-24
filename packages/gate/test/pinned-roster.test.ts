/**
 * Pinned trust — the pinned roster (`noa.gate-roster/1`) and the boot stages that load it (`trust.ts`
 * `resolveTrustMode` / `loadPinnedRoster` / `loadPinnedTrust`).
 *
 * Every refusal is asserted by its CODE, and every refusal has a positive control: `CONTROL` below
 * boots the same fixture successfully, so a refusal further down is about the one thing the test
 * changed. The file-discipline tests inject the gate's effective uid (a loader PARAMETER, not an
 * environment variable) so "a roster owned by the gate's own uid" can be expressed without root.
 *
 * Knockout arms registered in scripts/lint-control-knockout.mjs name the test that detects them.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  chownSync,
  closeSync,
  existsSync,
  fstatSync,
  linkSync,
  mkdirSync,
  openSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPair, virtualHash } from "noa-approval-artifacts";
import { parseGateRoster, checkRosterClock } from "../src/roster.js";
import {
  loadPinnedTrust,
  resolveTrustMode,
  type LoadPinnedTrustInput,
  type PinnedBoot,
  type PinnedRefusal,
} from "../src/trust.js";
import {
  GATE_KID,
  TENANT,
  approverKeys,
  freshDir,
  grantsAfterBoot,
  newWorld,
  rosterBytes,
  rosterDoc,
  writeKeyFile,
  writeRoster,
  x25519Pair,
  type RosterWorld,
} from "./helpers/pinned.js";

const NOW = Date.parse("2026-09-01T12:00:00.000Z");
const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;

/** A uid that is not this process's: the gate "is someone else", so a roster this test wrote is admin-owned. */
const OTHER_UID = 4242;

function refused(r: { ok: boolean }): asserts r is PinnedRefusal {
  assert.equal(r.ok, false, `consequence: the input must not be accepted (no roster, no boot); got ${JSON.stringify(r)}`);
}
/**
 * REFUSED IS THE CONSEQUENCE, the code is the label: a knockout that removes a check must turn THIS
 * assertion red — the input going through — not merely change which code a later check prints.
 */
function refusedWith(r: { ok: boolean; code?: string }, want: string, label = ""): void {
  assert.equal(r.ok, false, `consequence: ${label || want} — the input must not be accepted (no roster, no boot); got ${JSON.stringify(r)}`);
  assert.equal(r.code, want, `${label || want}: ${JSON.stringify(r)}`);
}
function booted(r: PinnedBoot | PinnedRefusal): asserts r is PinnedBoot {
  assert.equal(r.ok, true, `expected a boot, got ${JSON.stringify(r)}`);
}
/** Mode and content through ONE descriptor, so the two observations are of the same file. */
function readPrivate(p: string): { mode: number; text: string } {
  const fd = openSync(p, "r");
  try {
    return { mode: fstatSync(fd).mode, text: readFileSync(fd, "utf8") };
  } finally {
    closeSync(fd);
  }
}

/** Files on disk for one gate: roster (0644), key file (0600), and the default load input. */
function onDisk(world: RosterWorld, doc: Record<string, unknown>, over: Partial<LoadPinnedTrustInput> = {}) {
  const dir = freshDir("roster");
  const rosterFile = writeRoster(dir, doc);
  const keyFile = writeKeyFile(dir, world.gate);
  const input: LoadPinnedTrustInput = {
    rosterFile,
    keyFile,
    rosterSha256: undefined,
    unsafeSameUid: false,
    tenantEnv: undefined,
    grantSignerSocketSet: false,
    gateEuid: OTHER_UID,
    nowMs: NOW,
    now: () => NOW,
    ...over,
  };
  return { dir, rosterFile, keyFile, input };
}

// ── CONTROL ─────────────────────────────────────────────────────────────────────────────────────

test("CONTROL — a valid admin-owned roster and a matching key file boot a pinned trust root", () => {
  const world = newWorld();
  const { input, keyFile } = onDisk(world, rosterDoc(world, NOW));
  const boot = loadPinnedTrust(input);
  booted(boot);
  assert.equal(boot.trust.tenant, TENANT);
  assert.equal(boot.trust.gate.kid, GATE_KID);
  assert.equal(boot.trust.gate.publicKey, world.gate.publicKey);
  assert.equal(boot.trust.approver.kid, world.approver.kid);
  assert.equal(boot.trust.approver.privateKey, undefined, "a pinned trust root never holds an approver private key");
  assert.equal(boot.trust.keyManifestVersion, 2);
  assert.equal(boot.trust.keyManifestHash, "sha256:" + "2".repeat(64));
  assert.equal(boot.trust.keyManifest, undefined, "a pinned gate signs no manifest");
  assert.equal(boot.stateStatus, "INITIALIZED");
  assert.equal(boot.rosterCustody, "ADMIN-OWNED");
  assert.ok(boot.trust.pinned, "pinned state is present");
  assert.ok(Object.isFrozen(boot.trust.pinned) && Object.getPrototypeOf(boot.trust.pinned) === null);
  assert.equal(existsSync(`${keyFile}.roster-state`), false, "loading never writes: only commitState does");
});

test("the roster digest is JCS over the parsed value: key order, whitespace and escapes do not move it", () => {
  const world = newWorld();
  const doc = rosterDoc(world, NOW);
  const a = parseGateRoster(rosterBytes(doc));
  assert.ok(a.ok, JSON.stringify(a));
  assert.equal(a.digest, virtualHash(doc));
  const reordered = Object.fromEntries(Object.entries(doc).reverse());
  const spaced = new TextEncoder().encode(JSON.stringify(reordered, null, 7).replace('"tenant-example-1"', '"tenant\\u002dexample-1"'));
  const b = parseGateRoster(spaced);
  assert.ok(b.ok, JSON.stringify(b));
  assert.equal(b.digest, a.digest);
});

// ── stage 5/6: the roster's own rules ───────────────────────────────────────────────────────────

test("K4 — a quorum of 2 is QUORUM_UNSUPPORTED, never read as 1; below 1 or an unknown class is ROSTER_QUORUM_INVALID", () => {
  const world = newWorld();
  refusedWith(parseGateRoster(rosterBytes(rosterDoc(world, NOW, { quorum: { HIGH: 2 } }))), "QUORUM_UNSUPPORTED");
  refusedWith(parseGateRoster(rosterBytes(rosterDoc(world, NOW, { quorum: { HIGH: 1, CRITICAL: 3 } }))), "QUORUM_UNSUPPORTED");
  refusedWith(parseGateRoster(rosterBytes(rosterDoc(world, NOW, { quorum: { HIGH: 0 } }))), "ROSTER_QUORUM_INVALID");
  refusedWith(parseGateRoster(rosterBytes(rosterDoc(world, NOW, { quorum: { URGENT: 1 } }))), "ROSTER_QUORUM_INVALID");
  refusedWith(parseGateRoster(rosterBytes(rosterDoc(world, NOW, { quorum: {} }))), "ROSTER_QUORUM_INVALID");
  refusedWith(parseGateRoster(rosterBytes(rosterDoc(world, NOW, { quorum: { HIGH: "1" } }))), "ROSTER_QUORUM_INVALID");
});

test("K8 — an approver key equal to the gate key is ROSTER_KEY_REUSE (the gate cannot approve itself); so is a shared X25519 key", () => {
  const world = newWorld();
  const selfApprover = rosterDoc(world, NOW);
  (selfApprover["approvers"] as Record<string, Record<string, unknown>>)[world.approver.kid]!["publicKey"] = world.gate.publicKey;
  const r = parseGateRoster(rosterBytes(selfApprover));
  refusedWith(r, "ROSTER_KEY_REUSE", JSON.stringify(r));

  // The consequence the rule exists for: booted, the gate's own private key would approve its own hold.
  const selfBoot = loadPinnedTrust(onDisk(world, selfApprover).input);
  assert.equal(grantsAfterBoot(selfBoot, { kid: world.approver.kid, ed: world.gate, x: world.approver.x }, NOW), 0, "consequence: the gate key must not approve its own hold");

  const sharedRecipient = rosterDoc(world, NOW, { audit: { kid: "audit-example-1", hpkePublicKey: world.approver.x.publicKey } });
  refusedWith(parseGateRoster(rosterBytes(sharedRecipient)), "ROSTER_KEY_REUSE");
  // The same key under a second spelling (bit 255 set: RFC 7748 masks it, so it is the same key) is
  // refused as a non-canonical key before the string comparison could miss it.
  const alias = Buffer.from(world.approver.x.publicKey, "base64");
  alias[43] = (alias[43] as number) | 0x80;
  const aliased = rosterDoc(world, NOW, { audit: { kid: "audit-example-1", hpkePublicKey: alias.toString("base64") } });
  refusedWith(parseGateRoster(rosterBytes(aliased)), "ROSTER_HPKE_KEY_INVALID");
});

test("K14 — an approver kid equal to the gate kid is ROSTER_DUPLICATE_KID (it would overwrite the GATE keyring entry)", () => {
  const world = newWorld();
  const doc = rosterDoc(world, NOW, {
    approvers: {
      [GATE_KID]: {
        role: "approve-critical",
        publicKey: world.approver.ed.publicKey,
        hpkePublicKey: world.approver.x.publicKey,
        validFrom: new Date(NOW - HOUR).toISOString(),
        revokedAt: null,
      },
    },
  });
  const r = parseGateRoster(rosterBytes(doc));
  refusedWith(r, "ROSTER_DUPLICATE_KID", JSON.stringify(r));
  refusedWith(parseGateRoster(rosterBytes(rosterDoc(world, NOW, { audit: { kid: world.approver.kid, hpkePublicKey: world.audit.publicKey } }))), "ROSTER_DUPLICATE_KID");
});

test("K18 — a small-order Ed25519 approver key is ROSTER_KEY_INVALID at load; a raw-hex or low-order X25519 key is ROSTER_HPKE_KEY_INVALID", () => {
  const world = newWorld();
  // The identity point (y = 1): canonical DER, accepted by OpenSSL, refused by the decision verifier.
  const smallOrder = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from("01" + "00".repeat(31), "hex")]).toString("base64");
  const bad = rosterDoc(world, NOW);
  (bad["approvers"] as Record<string, Record<string, unknown>>)[world.approver.kid]!["publicKey"] = smallOrder;
  refusedWith(parseGateRoster(rosterBytes(bad)), "ROSTER_KEY_INVALID");

  const rawHex = Buffer.from(world.approver.x.publicKey, "base64").subarray(12).toString("hex");
  const hex = rosterDoc(world, NOW);
  (hex["approvers"] as Record<string, Record<string, unknown>>)[world.approver.kid]!["hpkePublicKey"] = rawHex;
  refusedWith(parseGateRoster(rosterBytes(hex)), "ROSTER_HPKE_KEY_INVALID");

  // A low-order X25519 point (u = 1): canonical DER, but the sealer can never seal to it.
  const lowOrder = Buffer.concat([Buffer.from("302a300506032b656e032100", "hex"), Buffer.from("01" + "00".repeat(31), "hex")]).toString("base64");
  const low = rosterDoc(world, NOW, { audit: { kid: "audit-example-1", hpkePublicKey: lowOrder } });
  refusedWith(parseGateRoster(rosterBytes(low)), "ROSTER_HPKE_KEY_INVALID");

  // The two x = 0 points spelled with the sign bit set (RFC 8032 §5.1.3: decoding fails): the same
  // small-order points as the canonical entries, under a second spelling. Then an off-curve y, and the
  // mixed-order key of conformance/vectors/strict-ed25519/keyring-mixed-order.json: on the curve and
  // not small-order, but outside the prime-order subgroup ([L]A is not the identity).
  const mixedOrder = Buffer.from("MCowBQYDK2VwAyEAcdzclbjztOK/MhheQB8rJkjeSwsQ+BRXaX2Lb2yp3JE=", "base64").subarray(12).toString("hex");
  for (const hexKey of ["01" + "00".repeat(30) + "80", "ec" + "ff".repeat(31), "02" + "00".repeat(31), mixedOrder]) {
    const signed = rosterDoc(world, NOW);
    (signed["approvers"] as Record<string, Record<string, unknown>>)[world.approver.kid]!["publicKey"] =
      Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(hexKey, "hex")]).toString("base64");
    refusedWith(parseGateRoster(rosterBytes(signed)), "ROSTER_KEY_INVALID", `x = 0 with the sign bit, off-curve or mixed-order: ${hexKey}`);
  }
  // An X25519 u-coordinate at or above p is a second spelling of u - p. u = p + 9 is the base point
  // u = 9, a perfectly valid key under a second string: the canonical-field-element rule is its ONLY
  // barrier, so it runs first. u = p (u = 0) is refused by the low-order trial as well and stays a plain
  // negative test.
  for (const hexKey of ["f6" + "ff".repeat(30) + "7f", "ed" + "ff".repeat(30) + "7f"]) {
    const big = rosterDoc(world, NOW, {
      audit: { kid: "audit-example-1", hpkePublicKey: Buffer.concat([Buffer.from("302a300506032b656e032100", "hex"), Buffer.from(hexKey, "hex")]).toString("base64") },
    });
    refusedWith(parseGateRoster(rosterBytes(big)), "ROSTER_HPKE_KEY_INVALID", `u >= p: ${hexKey}`);
  }
});

test("K18 — a small-order Ed25519 executionSigner key is ROSTER_KEY_INVALID at load; a genuine one loads", () => {
  const world = newWorld();
  // The identity point (y = 1): canonical DER, accepted by OpenSSL, refused by the decision verifier.
  const smallOrder = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from("01" + "00".repeat(31), "hex")]).toString("base64");
  const bad = rosterDoc(world, NOW, { executionSigner: { kid: "exec-example-1", publicKey: smallOrder } });
  refusedWith(parseGateRoster(rosterBytes(bad)), "ROSTER_KEY_INVALID", "small-order executionSigner key");
  const exec = generateKeyPair("exec-example-1");
  const good = parseGateRoster(rosterBytes(rosterDoc(world, NOW, { executionSigner: { kid: exec.kid, publicKey: exec.publicKey } })));
  assert.equal(good.ok, true, `control: a genuine executionSigner key must load, got ${JSON.stringify(good)}`);
});

test("K19 — the closed world: a sig member, a requiredApprovals member and an unknown approver member are refused, not ignored", () => {
  const world = newWorld();
  refusedWith(parseGateRoster(rosterBytes(rosterDoc(world, NOW, { sig: { kid: "x", value: "y" } }))), "ROSTER_UNRECOGNIZED_MEMBER");
  refusedWith(parseGateRoster(rosterBytes(rosterDoc(world, NOW, { requiredApprovals: 2 }))), "ROSTER_UNRECOGNIZED_MEMBER");
  const extra = rosterDoc(world, NOW);
  (extra["approvers"] as Record<string, Record<string, unknown>>)[world.approver.kid]!["quorumWeight"] = 2;
  refusedWith(parseGateRoster(rosterBytes(extra)), "ROSTER_UNRECOGNIZED_MEMBER");
  refusedWith(parseGateRoster(rosterBytes(rosterDoc(world, NOW, { epoch: { keyManifestVersion: 2, keyManifestHash: "sha256:" + "2".repeat(64), note: "x" } }))), "ROSTER_UNRECOGNIZED_MEMBER");
  refusedWith(parseGateRoster(rosterBytes(rosterDoc(world, NOW, { spec: "noa.gate-roster/2" }))), "ROSTER_SPEC_UNSUPPORTED");
});

test("members are judged before the closed world (an unknown member AND a bad kid → the kid's code)", () => {
  const world = newWorld();
  const doc = rosterDoc(world, NOW, { extra: true, gate: { kid: "Gate-Upper", publicKey: world.gate.publicKey } });
  refusedWith(parseGateRoster(rosterBytes(doc)), "ROSTER_KID_INVALID");
});

test("member rules: kid, tenant, version, epoch, role, times, executionSigner, approver count, role sufficiency", () => {
  const world = newWorld();
  const approver = (over: Record<string, unknown>) => {
    const d = rosterDoc(world, NOW);
    Object.assign((d["approvers"] as Record<string, Record<string, unknown>>)[world.approver.kid]!, over);
    return d;
  };
  const cases: Array<[string, Record<string, unknown>]> = [
    ["ROSTER_KID_INVALID", rosterDoc(world, NOW, { gate: { kid: "gate_example", publicKey: world.gate.publicKey } })],
    ["ROSTER_KID_INVALID", rosterDoc(world, NOW, { audit: { kid: "a".repeat(65), hpkePublicKey: world.audit.publicKey } })],
    ["ROSTER_TENANT_INVALID", rosterDoc(world, NOW, { tenant: "tenant example" })],
    ["ROSTER_TENANT_INVALID", rosterDoc(world, NOW, { tenant: "" })],
    ["ROSTER_VERSION_INVALID", rosterDoc(world, NOW, { rosterVersion: 0 })],
    ["ROSTER_EPOCH_INVALID", rosterDoc(world, NOW, { epoch: { keyManifestVersion: 2, keyManifestHash: "sha256:" + "A".repeat(64) } })],
    ["ROSTER_EPOCH_INVALID", rosterDoc(world, NOW, { epoch: { keyManifestVersion: 0, keyManifestHash: "sha256:" + "2".repeat(64) } })],
    ["ROSTER_ROLE_INVALID", approver({ role: "approve-all" })],
    ["ROSTER_TIME_INVALID", approver({ validFrom: "2026-02-30T00:00:00Z" })],
    ["ROSTER_TIME_INVALID", approver({ revokedAt: "yesterday" })],
    ["ROSTER_TIME_INVALID", rosterDoc(world, NOW, { expiresAt: new Date(NOW - 2 * HOUR).toISOString() })],
    ["ROSTER_MEMBER_INVALID", (() => { const d = rosterDoc(world, NOW); delete d["executionSigner"]; return d; })()],
    ["ROSTER_MEMBER_INVALID", rosterDoc(world, NOW, { approvers: [] })],
    ["ROSTER_NO_ACTIVE_APPROVER", approver({ revokedAt: new Date(NOW - 60_000).toISOString() })],
    ["ROSTER_ROLE_INSUFFICIENT", approver({ role: "approve-high" })],
  ];
  for (const [want, doc] of cases) {
    const r = parseGateRoster(rosterBytes(doc));
    refusedWith(r, want, `${want}: ${JSON.stringify(r)}`);
  }
  const second = approverKeys(2);
  const twoActive = rosterDoc(world, NOW);
  (twoActive["approvers"] as Record<string, unknown>)[second.kid] = {
    role: "approve-critical",
    publicKey: second.ed.publicKey,
    hpkePublicKey: second.x.publicKey,
    validFrom: new Date(NOW - HOUR).toISOString(),
    revokedAt: null,
  };
  refusedWith(parseGateRoster(rosterBytes(twoActive)), "ROSTER_APPROVER_COUNT_UNSUPPORTED");
  // approve-high is sufficient when the quorum names only HIGH.
  assert.equal(parseGateRoster(rosterBytes(rosterDoc(world, NOW, { quorum: { HIGH: 1 } }))).ok, true);
});

test("K11 — a digest pin that does not match is ROSTER_DIGEST_MISMATCH, checked before any semantic rule", () => {
  const world = newWorld();
  const honest = parseGateRoster(rosterBytes(rosterDoc(world, NOW)));
  assert.ok(honest.ok);
  // An attacker edits an approver in; the operator's pin still names the honest roster.
  const attacker = approverKeys(9);
  const edited = rosterDoc(world, NOW, {
    approvers: {
      [attacker.kid]: {
        role: "approve-critical",
        publicKey: attacker.ed.publicKey,
        hpkePublicKey: attacker.x.publicKey,
        validFrom: new Date(NOW - HOUR).toISOString(),
        revokedAt: null,
      },
    },
  });
  const r = parseGateRoster(rosterBytes(edited), { expectedDigest: honest.digest });
  refusedWith(r, "ROSTER_DIGEST_MISMATCH", JSON.stringify(r));
  const booted2 = loadPinnedTrust({ ...onDisk(world, edited).input, rosterSha256: honest.digest });
  assert.equal(grantsAfterBoot(booted2, attacker, NOW), 0, "consequence: the edited-in approver gets no grant");
  assert.equal(parseGateRoster(rosterBytes(rosterDoc(world, NOW)), { expectedDigest: honest.digest }).ok, true);
});

test("stage 8 — not yet valid, expired, a window over 90 days, a future-activated approver, a future revocation", () => {
  const world = newWorld();
  const parse = (doc: Record<string, unknown>) => {
    const r = parseGateRoster(rosterBytes(doc));
    assert.ok(r.ok, JSON.stringify(r));
    return r;
  };
  const clock = (doc: Record<string, unknown>, at = NOW) => {
    const r = parse(doc);
    return checkRosterClock(r.roster, r.activeApproverKid, at);
  };
  assert.equal(clock(rosterDoc(world, NOW)).ok, true, "control: a roster inside its window loads");
  // The roster itself not yet valid while its approver already is: only the roster window refuses it.
  const early = rosterDoc(world, NOW);
  (early["approvers"] as Record<string, Record<string, unknown>>)[world.approver.kid]!["validFrom"] = new Date(NOW - 3 * HOUR).toISOString();
  refusedWith(clock(early, NOW - 2 * HOUR), "ROSTER_NOT_YET_VALID");
  refusedWith(clock(rosterDoc(world, NOW), NOW - 2 * HOUR), "ROSTER_NOT_YET_VALID");
  refusedWith(clock(rosterDoc(world, NOW), NOW + 31 * DAY), "ROSTER_EXPIRED");
  refusedWith(clock(rosterDoc(world, NOW, { expiresAt: new Date(NOW + 90 * DAY).toISOString() })), "ROSTER_VALIDITY_TOO_LONG");
  const later = rosterDoc(world, NOW);
  (later["approvers"] as Record<string, Record<string, unknown>>)[world.approver.kid]!["validFrom"] = new Date(NOW + HOUR).toISOString();
  refusedWith(clock(later), "ROSTER_APPROVER_NOT_YET_VALID");
  const old = approverKeys(2);
  const future = rosterDoc(world, NOW);
  (future["approvers"] as Record<string, unknown>)[old.kid] = {
    role: "approve-critical",
    publicKey: old.ed.publicKey,
    hpkePublicKey: old.x.publicKey,
    validFrom: new Date(NOW - DAY).toISOString(),
    revokedAt: new Date(NOW + HOUR).toISOString(),
  };
  refusedWith(clock(future), "ROSTER_TIME_INVALID");
});

// ── stage 2: file discipline ────────────────────────────────────────────────────────────────────

test("K12 — a roster owned by the gate's own uid is ROSTER_FILE_UNSAFE owner, even carrying a well-formed attacker approver", () => {
  const world = newWorld();
  const attacker = approverKeys(9);
  const doc = rosterDoc(world, NOW, {
    approvers: {
      [attacker.kid]: {
        role: "approve-critical",
        publicKey: attacker.ed.publicKey,
        hpkePublicKey: attacker.x.publicKey,
        validFrom: new Date(NOW - HOUR).toISOString(),
        revokedAt: null,
      },
    },
  });
  const { input, rosterFile } = onDisk(world, doc);
  // Root owns every file it creates; hand the roster to a non-root uid so "owner == gate" is expressible.
  if (process.geteuid?.() === 0) chownSync(rosterFile, OTHER_UID, OTHER_UID);
  const gateUid = statSync(rosterFile).uid;
  const r = loadPinnedTrust({ ...input, gateEuid: gateUid });
  assert.equal(grantsAfterBoot(r, attacker, NOW), 0, "consequence: an approver the gate's own uid wrote in gets no grant");
  refused(r);
  assert.equal(r.code, "ROSTER_FILE_UNSAFE");
  assert.match(r.detail, /^owner: /);
  // The development escape accepts it — and says so.
  const escaped = loadPinnedTrust({ ...input, gateEuid: gateUid, unsafeSameUid: true });
  booted(escaped);
  assert.equal(escaped.rosterCustody, "SAME-UID (unsafe)");
  escaped.release();
});

test("K12 — file arms: group-writable mode, symlink, FIFO (returns promptly), second hard link, group-writable parent, oversize, missing", () => {
  const world = newWorld();
  const doc = rosterDoc(world, NOW);

  const modeCase = onDisk(world, doc);
  chmodSync(modeCase.rosterFile, 0o664);
  const m = loadPinnedTrust(modeCase.input);
  refused(m);
  assert.equal(m.code, "ROSTER_FILE_UNSAFE");
  assert.match(m.detail, /^mode: /);

  const linkCase = onDisk(world, doc);
  const linkPath = join(linkCase.dir, "roster-link.json");
  symlinkSync(linkCase.rosterFile, linkPath);
  const l = loadPinnedTrust({ ...linkCase.input, rosterFile: linkPath });
  refused(l);
  assert.match(l.detail, /^symlink: /);

  const fifoCase = onDisk(world, doc);
  const fifo = join(fifoCase.dir, "roster-fifo.json");
  const mk = spawnSync("mkfifo", [fifo]);
  assert.equal(mk.status, 0, "mkfifo is available on the platforms this suite runs on");
  const t0 = Date.now();
  const f = loadPinnedTrust({ ...fifoCase.input, rosterFile: fifo });
  refused(f);
  assert.match(f.detail, /^not-regular: /);
  assert.ok(Date.now() - t0 < 5_000, "a FIFO at the roster path must not stall the boot");

  const hardCase = onDisk(world, doc);
  linkSync(hardCase.rosterFile, join(hardCase.dir, "second-name.json"));
  const h = loadPinnedTrust(hardCase.input);
  refused(h);
  assert.match(h.detail, /^nlink: /);

  const parentCase = onDisk(world, doc);
  const loose = join(parentCase.dir, "loose");
  mkdirSync(loose);
  chmodSync(loose, 0o775);
  const inLoose = writeRoster(loose, doc);
  const p = loadPinnedTrust({ ...parentCase.input, rosterFile: inLoose });
  refused(p);
  assert.match(p.detail, /^ancestor: /);

  const bigCase = onDisk(world, { ...doc, padding: "x".repeat(70 * 1024) });
  const b = loadPinnedTrust(bigCase.input);
  refused(b);
  assert.match(b.detail, /^size: /);

  const missing = onDisk(world, doc);
  const g = loadPinnedTrust({ ...missing.input, rosterFile: join(missing.dir, "absent.json") });
  refused(g);
  assert.equal(g.code, "ROSTER_FILE_MISSING");
});

// ── stage 9: the persistent gate key ────────────────────────────────────────────────────────────

test("K9 — a key file that is not the roster's gate member is GATE_KEY_NOT_PINNED", () => {
  const world = newWorld();
  const { input, dir } = onDisk(world, rosterDoc(world, NOW));
  const swapped = writeKeyFile(dir, generateKeyPair(GATE_KID), "swapped.key.json");
  const r = loadPinnedTrust({ ...input, keyFile: swapped });
  refused(r);
  assert.equal(r.code, "GATE_KEY_NOT_PINNED");
});

test("K10 — a key file whose publicKey is not its privateKey's public half is GATE_KEY_INCONSISTENT", () => {
  const world = newWorld();
  const { input, dir } = onDisk(world, rosterDoc(world, NOW));
  const other = generateKeyPair(GATE_KID);
  const mixed = writeKeyFile(dir, { kid: GATE_KID, publicKey: world.gate.publicKey, privateKey: other.privateKey }, "mixed.key.json");
  const r = loadPinnedTrust({ ...input, keyFile: mixed });
  refused(r);
  assert.equal(r.code, "GATE_KEY_INCONSISTENT");
});

test("a missing key file is GATE_KEY_FILE_MISSING and none is created; a loose key file is GATE_KEY_FILE_UNSAFE", () => {
  const world = newWorld();
  const { input, dir } = onDisk(world, rosterDoc(world, NOW));
  const absent = join(dir, "absent.key.json");
  const r = loadPinnedTrust({ ...input, keyFile: absent });
  refused(r);
  assert.equal(r.code, "GATE_KEY_FILE_MISSING");
  assert.equal(existsSync(absent), false, "serve never mints a key");
  const loose = writeKeyFile(dir, world.gate, "loose.key.json");
  chmodSync(loose, 0o644);
  const u = loadPinnedTrust({ ...input, keyFile: loose });
  refused(u);
  assert.equal(u.code, "GATE_KEY_FILE_UNSAFE");
});

// ── stage 10: signer posture ────────────────────────────────────────────────────────────────────

test("stage 10 — the roster's executionSigner and NOA_GATE_GRANT_SIGNER_SOCKET must agree, both ways", () => {
  const world = newWorld();
  const noSigner = onDisk(world, rosterDoc(world, NOW));
  refusedWith(loadPinnedTrust({ ...noSigner.input, grantSignerSocketSet: true }), "ROSTER_EXEC_SIGNER_MISMATCH");
  const exec = generateKeyPair("exec-example-1");
  const withSigner = onDisk(world, rosterDoc(world, NOW, { executionSigner: { kid: exec.kid, publicKey: exec.publicKey } }));
  refusedWith(loadPinnedTrust(withSigner.input), "ROSTER_EXEC_SIGNER_MISMATCH");
  const ok = loadPinnedTrust({ ...withSigner.input, grantSignerSocketSet: true });
  booted(ok);
  assert.deepEqual(ok.trust.keyring[GATE_KID]!.roles, ["hold-signer"], "an external signer takes execution-signer away from the gate key");
  assert.deepEqual(ok.trust.keyring[exec.kid]!.roles, ["execution-signer"]);
});

// ── stage 11: anti-rollback high-water ──────────────────────────────────────────────────────────

test("K13 — a lower roster version is ROSTER_ROLLBACK (it would re-admit a revoked approver); same version, new bytes is ROSTER_EQUIVOCATION", () => {
  const world = newWorld();
  const retired = approverKeys(7);
  // v3: the old approver is revoked, the current one active.
  const v3 = rosterDoc(world, NOW);
  (v3["approvers"] as Record<string, unknown>)[retired.kid] = {
    role: "approve-critical",
    publicKey: retired.ed.publicKey,
    hpkePublicKey: retired.x.publicKey,
    validFrom: new Date(NOW - 10 * DAY).toISOString(),
    revokedAt: new Date(NOW - 2 * HOUR).toISOString(),
  };
  const disk = onDisk(world, v3);
  const first = loadPinnedTrust(disk.input);
  booted(first);
  assert.equal(first.stateStatus, "INITIALIZED");
  assert.equal(first.commitState(), null);
  const statePath = `${disk.keyFile}.roster-state`;
  const written = readPrivate(statePath);
  assert.equal(written.mode & 0o777, 0o600, "the state file is private to the gate");
  assert.deepEqual(JSON.parse(written.text), { rosterDigest: first.rosterDigest, rosterVersion: 3, spec: "noa.gate-roster-state/1" });

  const again = loadPinnedTrust(disk.input);
  booted(again);
  assert.equal(again.stateStatus, "UNCHANGED");
  again.release();

  // v2: the retired approver is active again and the current one is gone — a restore of an old file.
  const v2 = rosterDoc(world, NOW, {
    rosterVersion: 2,
    approvers: {
      [retired.kid]: {
        role: "approve-critical",
        publicKey: retired.ed.publicKey,
        hpkePublicKey: retired.x.publicKey,
        validFrom: new Date(NOW - 10 * DAY).toISOString(),
        revokedAt: null,
      },
    },
  });
  writeFileSync(disk.rosterFile, JSON.stringify(v2));
  const rolled = loadPinnedTrust(disk.input);
  assert.equal(grantsAfterBoot(rolled, retired, NOW), 0, "consequence: the approver revoked in v3 gets no grant from a restored v2");
  refused(rolled);
  assert.equal(rolled.code, "ROSTER_ROLLBACK");

  writeFileSync(disk.rosterFile, JSON.stringify({ ...v3, quorum: { HIGH: 1 } }));
  const equivocated = loadPinnedTrust(disk.input);
  refused(equivocated);
  assert.equal(equivocated.code, "ROSTER_EQUIVOCATION");

  writeFileSync(disk.rosterFile, JSON.stringify({ ...v3, rosterVersion: 4 }));
  const advanced = loadPinnedTrust(disk.input);
  booted(advanced);
  assert.equal(advanced.stateStatus, "ADVANCED");
  assert.equal(advanced.commitState(), null);
  assert.equal(JSON.parse(readPrivate(statePath).text).rosterVersion, 4);
});

test("stage 11 — a loose state file is STATE_FILE_UNSAFE even when its content is valid", () => {
  const world = newWorld();
  const disk = onDisk(world, rosterDoc(world, NOW));
  const statePath = `${disk.keyFile}.roster-state`;
  writeFileSync(statePath, JSON.stringify({ rosterDigest: "sha256:" + "a".repeat(64), rosterVersion: 1, spec: "noa.gate-roster-state/1" }), { mode: 0o644 });
  chmodSync(statePath, 0o644);
  refusedWith(loadPinnedTrust(disk.input), "STATE_FILE_UNSAFE");
});

test("stage 11 — a corrupt state file is STATE_FILE_CORRUPT; a loose one is STATE_FILE_UNSAFE", () => {
  const world = newWorld();
  const disk = onDisk(world, rosterDoc(world, NOW));
  const statePath = `${disk.keyFile}.roster-state`;
  writeFileSync(statePath, JSON.stringify({ spec: "noa.gate-roster-state/1", rosterVersion: 1 }), { mode: 0o600 });
  refusedWith(loadPinnedTrust(disk.input), "STATE_FILE_CORRUPT");
  writeFileSync(statePath, JSON.stringify({ spec: "noa.gate-roster-state/1", rosterVersion: 1, rosterDigest: "sha256:" + "a".repeat(64), extra: 1 }));
  refusedWith(loadPinnedTrust(disk.input), "STATE_FILE_CORRUPT");
  chmodSync(statePath, 0o644);
  refusedWith(loadPinnedTrust(disk.input), "STATE_FILE_UNSAFE");
});

// ── stages 0, 1 and 7: the environment ──────────────────────────────────────────────────────────

test("stages 0-1 — any pinned variable selects pinned mode; half a configuration or a second identity source is refused", () => {
  assert.deepEqual(resolveTrustMode({}, true), { mode: "alpha" });
  assert.deepEqual(resolveTrustMode({ NOA_GATE_TENANT: "t" }, true), { mode: "alpha" });
  refusedWith(resolveTrustMode({ NOA_GATE_ROSTER_FILE: "/r" }, false) as { ok: boolean; code?: string }, "PINNED_PLATFORM_UNSUPPORTED");
  for (const env of [
    { NOA_GATE_ROSTER_FILE: "/r" },
    { NOA_GATE_KEY_FILE: "/k" },
    { NOA_GATE_ROSTER_FILE: "/r", NOA_GATE_KEY_FILE: "" },
    { NOA_GATE_ROSTER_SHA256: "sha256:" + "0".repeat(64) },
    { NOA_GATE_UNSAFE_ROSTER_SAME_UID: "1" },
    // "Present" includes EMPTY: an empty pinned variable is not "not pinned", it is half a configuration.
    { NOA_GATE_ROSTER_FILE: "" },
    { NOA_GATE_KEY_FILE: "", NOA_GATE_ROSTER_SHA256: "" },
  ]) {
    refusedWith(resolveTrustMode(env, true) as { ok: boolean; code?: string }, "CONFIG_PINNED_INCOMPLETE", JSON.stringify(env));
  }
  for (const extra of ["NOA_GATE_APPROVER_KID", "NOA_GATE_APPROVER_HPKE_PUBLIC_KEY", "NOA_GATE_GRANT_SIGNER_KID", "NOA_GATE_GRANT_SIGNER_PUBLIC_KEY"]) {
    const r = resolveTrustMode({ NOA_GATE_ROSTER_FILE: "/r", NOA_GATE_KEY_FILE: "/k", [extra]: "x" }, true);
    refusedWith(r as { ok: boolean; code?: string }, "CONFIG_SOURCE_CONFLICT", extra);
  }
  const ok = resolveTrustMode({ NOA_GATE_ROSTER_FILE: "/r", NOA_GATE_KEY_FILE: "/k", NOA_GATE_UNSAFE_ROSTER_SAME_UID: "1" }, true);
  assert.deepEqual(ok, { mode: "pinned", rosterFile: "/r", keyFile: "/k", rosterSha256: undefined, unsafeSameUid: true });
});

test("stage 7 — NOA_GATE_TENANT that differs from the roster is CONFIG_SOURCE_CONFLICT; the same value is accepted", () => {
  const world = newWorld();
  const disk = onDisk(world, rosterDoc(world, NOW));
  refusedWith(loadPinnedTrust({ ...disk.input, tenantEnv: "tenant-example-2" }), "CONFIG_SOURCE_CONFLICT");
  assert.equal(loadPinnedTrust({ ...disk.input, tenantEnv: TENANT }).ok, true);
});

// ── precedence: each adjacent pair of stages, the earlier stage wins ─────────────────────────────

/** The CLI's order: resolveTrustMode, then loadPinnedTrust. */
function bootFromEnv(env: Record<string, string>, platform: boolean, over: Partial<LoadPinnedTrustInput>): string {
  const mode = resolveTrustMode(env, platform);
  if ("code" in mode) return mode.code;
  if (mode.mode !== "pinned") return "ALPHA";
  const r = loadPinnedTrust({
    rosterFile: mode.rosterFile,
    keyFile: mode.keyFile,
    rosterSha256: mode.rosterSha256,
    unsafeSameUid: mode.unsafeSameUid,
    tenantEnv: env["NOA_GATE_TENANT"],
    grantSignerSocketSet: false,
    gateEuid: OTHER_UID,
    nowMs: NOW,
    ...over,
  });
  if (r.ok) {
    r.release();
    return "BOOTED";
  }
  return r.code;
}

test("precedence — stages 0|1, 1|2, 2|2, 2|3, 3|4, 4|5, 5|6, 6|7, 7|8, 8|9, 9|10, 10|11, 11|11: the earlier check's code wins", () => {
  const world = newWorld();
  const dir = freshDir("precedence");
  const keyFile = writeKeyFile(dir, world.gate);
  const put = (name: string, doc: unknown, mode = 0o644) => writeRoster(dir, doc, name, mode);
  const good = rosterDoc(world, NOW);
  const env = (rosterFile: string, extra: Record<string, string> = {}) => ({ NOA_GATE_ROSTER_FILE: rosterFile, NOA_GATE_KEY_FILE: keyFile, ...extra });

  // 0|1: no POSIX uids AND half a configuration.
  assert.equal(bootFromEnv({ NOA_GATE_ROSTER_FILE: "/absent" }, false, {}), "PINNED_PLATFORM_UNSUPPORTED");
  // 1|2: a second identity source AND a missing roster file.
  assert.equal(bootFromEnv(env(join(dir, "absent.json"), { NOA_GATE_APPROVER_KID: "x" }), true, {}), "CONFIG_SOURCE_CONFLICT");
  // 2 (prelude) | 2 (file): a root gate AND a missing roster file.
  assert.equal(bootFromEnv(env(join(dir, "absent.json")), true, { gateEuid: 0 }), "PINNED_ROOT_GATE");
  // 2|3: a group-writable file AND unparsable bytes.
  const loose = join(dir, "loose.json");
  writeFileSync(loose, "{not json", { mode: 0o664 });
  chmodSync(loose, 0o664);
  assert.equal(bootFromEnv(env(loose), true, {}), "ROSTER_FILE_UNSAFE");
  // 3|4: not an object AND a pin that cannot match.
  assert.equal(bootFromEnv(env(put("array.json", [good])), true, { rosterSha256: "sha256:" + "0".repeat(64) }), "ROSTER_NOT_OBJECT");
  // 4|5: a wrong pin AND an unsupported spec.
  assert.equal(bootFromEnv(env(put("spec.json", { ...good, spec: "noa.gate-roster/2" })), true, { rosterSha256: "sha256:" + "0".repeat(64) }), "ROSTER_DIGEST_MISMATCH");
  // 5|6: a bad tenant AND a duplicate kid.
  assert.equal(bootFromEnv(env(put("five.json", { ...good, tenant: "has space", audit: { kid: GATE_KID, hpkePublicKey: world.audit.publicKey } })), true, {}), "ROSTER_TENANT_INVALID");
  // 6|7: a duplicate kid AND a conflicting NOA_GATE_TENANT.
  assert.equal(bootFromEnv(env(put("six.json", { ...good, audit: { kid: GATE_KID, hpkePublicKey: world.audit.publicKey } })), true, { tenantEnv: "other-tenant" }), "ROSTER_DUPLICATE_KID");
  // 7|8: a conflicting NOA_GATE_TENANT AND an expired roster.
  assert.equal(bootFromEnv(env(put("seven.json", good)), true, { tenantEnv: "other-tenant", nowMs: NOW + 31 * DAY }), "CONFIG_SOURCE_CONFLICT");
  // 8|9: an expired roster AND a missing key file.
  assert.equal(bootFromEnv({ NOA_GATE_ROSTER_FILE: put("eight.json", good), NOA_GATE_KEY_FILE: join(dir, "absent.key") }, true, { nowMs: NOW + 31 * DAY }), "ROSTER_EXPIRED");
  // 9|10: a key file that is not pinned AND a signer posture mismatch.
  const otherKey = writeKeyFile(dir, generateKeyPair(GATE_KID), "other.key.json");
  assert.equal(bootFromEnv({ NOA_GATE_ROSTER_FILE: put("nine.json", good), NOA_GATE_KEY_FILE: otherKey }, true, { grantSignerSocketSet: true }), "GATE_KEY_NOT_PINNED");
  // 10|11: a signer posture mismatch AND a rollback.
  writeFileSync(`${keyFile}.roster-state`, JSON.stringify({ rosterDigest: "sha256:" + "a".repeat(64), rosterVersion: 99, spec: "noa.gate-roster-state/1" }), { mode: 0o600 });
  assert.equal(bootFromEnv(env(put("ten.json", good)), true, { grantSignerSocketSet: true }), "ROSTER_EXEC_SIGNER_MISMATCH");
  // 10|11 (lock): a signer posture mismatch AND a live lock; then the lock AND a rollback.
  const lockPath = `${keyFile}.roster-state.lock`;
  writeFileSync(lockPath, `${process.pid}\n`, { mode: 0o600 });
  assert.equal(bootFromEnv(env(put("ten-lock.json", good)), true, { grantSignerSocketSet: true }), "ROSTER_EXEC_SIGNER_MISMATCH");
  assert.equal(bootFromEnv(env(put("eleven-lock.json", good)), true, {}), "STATE_LOCKED");
  rmSync(lockPath);
  // …and with the posture fixed and the lock gone, the rollback is what refuses.
  assert.equal(bootFromEnv(env(put("eleven.json", good)), true, {}), "ROSTER_ROLLBACK");
});

test("a generated X25519 recipient key is accepted in its canonical base64 DER form", () => {
  const world = newWorld();
  const doc = rosterDoc(world, NOW, { audit: { kid: "audit-example-1", hpkePublicKey: x25519Pair().publicKey } });
  assert.equal(parseGateRoster(rosterBytes(doc)).ok, true);
});

// ── QA round 1: the configured path, a root gate, the high-water lock, the state owner ────────────

test("K12 symlink — a symlink on the configured roster path in a directory others can write is ROSTER_FILE_UNSAFE symlink-ancestor, and the archived roster it points at never grants", () => {
  const world = newWorld();
  const retired = approverKeys(9);
  const base = freshDir("symlink");
  const admin = join(base, "admin");
  const archive = join(base, "admin-archive");
  mkdirSync(admin);
  chmodSync(admin, 0o755);
  mkdirSync(archive);
  chmodSync(archive, 0o755);
  writeRoster(admin, rosterDoc(world, NOW));
  // The archived roster: the approver since retired is its active one.
  writeRoster(archive, rosterDoc(world, NOW, {
    rosterVersion: 2,
    approvers: { [retired.kid]: { role: "approve-critical", publicKey: retired.ed.publicKey, hpkePublicKey: retired.x.publicKey, validFrom: new Date(NOW - HOUR).toISOString(), revokedAt: null } },
  }));
  const keyFile = writeKeyFile(base, world.gate);
  // A directory the gate's uid (here: anyone) can write, holding a symlink re-pointed at the archive.
  const gatehome = join(base, "gatehome");
  mkdirSync(gatehome);
  chmodSync(gatehome, 0o777);
  symlinkSync(archive, join(gatehome, "cfg"));
  const input: LoadPinnedTrustInput = {
    rosterFile: join(gatehome, "cfg", "roster.json"), keyFile, rosterSha256: undefined, unsafeSameUid: false,
    tenantEnv: undefined, grantSignerSocketSet: false, gateEuid: OTHER_UID, nowMs: NOW, now: () => NOW,
  };
  const r = loadPinnedTrust(input);
  assert.equal(grantsAfterBoot(r, retired, NOW), 0, "consequence: the archived roster's approver gets no grant");
  refused(r);
  assert.equal(r.code, "ROSTER_FILE_UNSAFE");
  assert.match(r.detail, /^symlink-ancestor: /);

  // Control: the same kind of symlink, owned by the roster's owner in a directory only that owner can
  // write, is the administrator's own indirection and is accepted.
  const links = join(base, "admin-links");
  mkdirSync(links);
  chmodSync(links, 0o755);
  symlinkSync(admin, join(links, "cfg"));
  const ok = loadPinnedTrust({ ...input, rosterFile: join(links, "cfg", "roster.json") });
  booted(ok);
  assert.equal(ok.roster.rosterVersion, 3);
  ok.release();
});

test("the configured roster path: a platform symlink owned by root (macOS /var -> /private/var) is accepted; relative and dot-segment paths are refused", () => {
  const world = newWorld();
  const disk = onDisk(world, rosterDoc(world, NOW));
  // Rebuild the path through the platform's own temp-dir spelling: on macOS that goes through the
  // root-owned /var symlink; on Linux it is the same real path.
  const raw = tmpdir();
  const real = realpathSync(raw);
  const viaPlatform = disk.rosterFile.startsWith(real) ? join(raw, disk.rosterFile.slice(real.length)) : disk.rosterFile;
  const boot = loadPinnedTrust({ ...disk.input, rosterFile: viaPlatform });
  booted(boot);
  boot.release();
  // Built by concatenation on purpose: path.join would normalize the dot segments away.
  for (const bad of ["roster.json", `${disk.dir}/../${disk.dir.split("/").pop() as string}/roster.json`, `${disk.dir}/./roster.json`]) {
    const r = loadPinnedTrust({ ...disk.input, rosterFile: bad });
    refused(r);
    assert.equal(r.code, "ROSTER_FILE_UNSAFE", bad);
    assert.match(r.detail, /^path-form: /, bad);
  }
});

test("a gate running as root is PINNED_ROOT_GATE (root can rewrite any roster); the development escape says ROOT-GATE (unsafe)", () => {
  const world = newWorld();
  const disk = onDisk(world, rosterDoc(world, NOW));
  const r = loadPinnedTrust({ ...disk.input, gateEuid: 0 });
  assert.equal(grantsAfterBoot(r, world.approver, NOW), 0, "consequence: no gate boots as root under the protected posture");
  refusedWith(r, "PINNED_ROOT_GATE");
  const escaped = loadPinnedTrust({ ...disk.input, gateEuid: 0, unsafeSameUid: true });
  booted(escaped);
  assert.equal(escaped.rosterCustody, "ROOT-GATE (unsafe)");
  escaped.release();
});

test("K13 lock — overlapping boots on one key file are serialized: the second is STATE_LOCKED until the first commits, so the floor never goes down", () => {
  const world = newWorld();
  const disk = onDisk(world, rosterDoc(world, NOW, { rosterVersion: 4 }));
  const v5 = writeRoster(disk.dir, rosterDoc(world, NOW, { rosterVersion: 5 }), "roster-v5.json");
  const first = loadPinnedTrust(disk.input);
  booted(first);
  const second = loadPinnedTrust({ ...disk.input, rosterFile: v5 });
  assert.equal(second.ok, false, "consequence: a second boot must not proceed while the first holds the high-water state");
  assert.equal(second.ok ? "" : second.code, "STATE_LOCKED");
  assert.equal(first.commitState(), null);
  const statePath = `${disk.keyFile}.roster-state`;
  assert.equal(existsSync(`${statePath}.lock`), false, "commitState releases the lock");
  const later = loadPinnedTrust({ ...disk.input, rosterFile: v5 });
  booted(later);
  assert.equal(later.stateStatus, "ADVANCED");
  assert.equal(later.commitState(), null);
  assert.equal(JSON.parse(readPrivate(statePath).text).rosterVersion, 5);
  // A boot of the older roster now meets the floor.
  const stale = loadPinnedTrust(disk.input);
  refusedWith(stale, "ROSTER_ROLLBACK");
  assert.equal(existsSync(`${statePath}.lock`), false, "a refused load releases the lock");
});

test("K13 re-compare — a state file changed under the lock by something that ignores it is re-read at commit, and the floor is not lowered", () => {
  const world = newWorld();
  const disk = onDisk(world, rosterDoc(world, NOW, { rosterVersion: 4 }));
  const boot = loadPinnedTrust(disk.input);
  booted(boot);
  const statePath = `${disk.keyFile}.roster-state`;
  // An administrator's restore writes a higher floor while the boot is between its read and its write.
  writeFileSync(statePath, JSON.stringify({ rosterDigest: "sha256:" + "a".repeat(64), rosterVersion: 9, spec: "noa.gate-roster-state/1" }), { mode: 0o600 });
  const committed = boot.commitState();
  assert.equal(JSON.parse(readPrivate(statePath).text).rosterVersion, 9, "consequence: the recorded floor is never lowered");
  assert.equal(committed?.code, "ROSTER_ROLLBACK");
  assert.equal(existsSync(`${statePath}.lock`), false, "a refused commit releases the lock");
});

test("K13 lock — a lock left by a dead holder is replaced once; a live or unreadable holder is STATE_LOCKED", () => {
  const world = newWorld();
  const disk = onDisk(world, rosterDoc(world, NOW));
  const lockPath = `${disk.keyFile}.roster-state.lock`;
  writeFileSync(lockPath, "424242\n", { mode: 0o600 });
  refusedWith(loadPinnedTrust({ ...disk.input, isProcessAlive: () => true }), "STATE_LOCKED");
  const replaced = loadPinnedTrust({ ...disk.input, isProcessAlive: () => false });
  booted(replaced);
  assert.equal(replaced.commitState(), null);
  writeFileSync(lockPath, "not a pid\n", { mode: 0o600 });
  refusedWith(loadPinnedTrust({ ...disk.input, isProcessAlive: () => false }), "STATE_LOCKED");
  rmSync(lockPath);
});

test("stage 11 — a state file owned by another uid is STATE_FILE_UNSAFE owner (the key-file owner rule: the gate's uid or root)", () => {
  const world = newWorld();
  const disk = onDisk(world, rosterDoc(world, NOW));
  const first = loadPinnedTrust(disk.input);
  booted(first);
  assert.equal(first.commitState(), null);
  // The test process wrote the state; a gate running as another uid must refuse it.
  const r = loadPinnedTrust({ ...disk.input, stateOwnerEuid: OTHER_UID });
  refusedWith(r, "STATE_FILE_UNSAFE");
  assert.match(r.ok ? "" : r.detail, /^owner: /);
  const same = loadPinnedTrust(disk.input);
  booted(same);
  same.release();
});

test("K4 — a quorum of 2 refuses the boot itself (the engine's own re-check, K5, is a separate control)", () => {
  const world = newWorld();
  const r = loadPinnedTrust(onDisk(world, rosterDoc(world, NOW, { quorum: { HIGH: 2 } })).input);
  refusedWith(r, "QUORUM_UNSUPPORTED");
});

test("K13 lock takeover — two boots that both find the same dead holder: exactly one takes the lock (the other is STATE_LOCKED)", () => {
  const world = newWorld();
  const disk = onDisk(world, rosterDoc(world, NOW, { rosterVersion: 4 }));
  const v5 = writeRoster(disk.dir, rosterDoc(world, NOW, { rosterVersion: 5 }), "roster-v5.json");
  const lockPath = `${disk.keyFile}.roster-state.lock`;
  writeFileSync(lockPath, "424242\n", { mode: 0o600 });
  // B has read the dead holder; before B acts, A also finds it dead, takes it over and creates its own.
  let first: ReturnType<typeof loadPinnedTrust> | null = null;
  const second = loadPinnedTrust({
    ...disk.input,
    isProcessAlive: () => {
      first = loadPinnedTrust({ ...disk.input, rosterFile: v5, isProcessAlive: () => false });
      return false;
    },
  });
  const a = first as ReturnType<typeof loadPinnedTrust> | null;
  assert.ok(a !== null, "fixture: the interleaved boot ran");
  assert.equal(Boolean(a.ok && second.ok), false, "consequence: two boots must never both hold the high-water lock");
  booted(a);
  refusedWith(second, "STATE_LOCKED");
  assert.equal(a.commitState(), null);
  assert.equal(existsSync(lockPath), false, "the holder released its own lock");
});

test("K13 lock release — a boot releases only the lock file it created, never another boot's", () => {
  const world = newWorld();
  const disk = onDisk(world, rosterDoc(world, NOW));
  const lockPath = `${disk.keyFile}.roster-state.lock`;
  const boot = loadPinnedTrust(disk.input);
  booted(boot);
  // The path now names someone else's lock (an administrator replaced it, or a takeover race).
  rmSync(lockPath);
  writeFileSync(lockPath, "31337\n", { mode: 0o600 });
  boot.release();
  assert.equal(existsSync(lockPath), true, "consequence: another boot's lock must survive this boot's release");
  assert.equal(readPrivate(lockPath).text, "31337\n");
  rmSync(lockPath);
});

test("stage 11 — a key directory the gate cannot write is STATE_DIR_NOT_WRITABLE, not a lock someone must remove", { skip: process.geteuid?.() === 0 ? "root ignores directory permissions" : false }, () => {
  const world = newWorld();
  const disk = onDisk(world, rosterDoc(world, NOW));
  const keyDir = join(disk.dir, "keys");
  mkdirSync(keyDir);
  const keyFile = writeKeyFile(keyDir, world.gate);
  chmodSync(keyDir, 0o555);
  try {
    const r = loadPinnedTrust({ ...disk.input, keyFile });
    refusedWith(r, "STATE_DIR_NOT_WRITABLE");
    assert.match(r.ok ? "" : r.detail, /must be writable by the gate/);
  } finally {
    chmodSync(keyDir, 0o755);
  }
});
