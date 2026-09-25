/**
 * A supervisor-supplied boot, end to end: the boot identifier AND the boot's start instant.
 *
 * A supervisor that supplies `bootId` supplies `bootStartedAt` with it; the trust root takes that
 * instant as the boot's start. A hold whose gate-signed freeze time precedes the boot's start is not
 * this boot's, whatever boot identifier it records: decide issues no grant for it, exactly as the
 * effect owner commits nothing for it. And an engine refuses to run an effect owner that keeps its own
 * record of the grant's consumption under a supervisor-supplied boot identifier, because processes
 * sharing that identifier could each commit one grant.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { GateEngine } from "../src/engine.js";
import { resolveGateConfig } from "../src/config.js";
import { loadSchemas } from "../src/schemas.js";
import { InMemoryStore, type Store } from "../src/store.js";
import { parseGateRoster } from "../src/roster.js";
import { createInMemoryLedgerEffectOwner, type EffectOwner } from "../src/effect-owner.js";
import { createPinnedTrust, loadPinnedTrust, type CreatePinnedTrustInput, type GateTrust, type LoadPinnedTrustInput, type PinnedBoot, type PinnedRefusal } from "../src/trust.js";
import type { HoldEnvelope } from "../src/types.js";
import { body, makeClock, sampleCommandParams, signPhoneDecision, testSealer, type Clock } from "./helpers.js";
import { freshDir, newWorld, rosterBytes, rosterDoc, writeKeyFile, writeRoster, type RosterWorld } from "./helpers/pinned.js";
import { AGENT_1, DEFAULT_ACCOUNTS, LEDGER } from "./helpers/effect.js";

const SUPERVISOR_BOOT = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";
const MIN = 60 * 1000;

let seq = 0;
const ids = () => `boot-start-${(seq++).toString(16).padStart(8, "0")}`;

/** A pinned trust root built at the clock's current instant, with extra inputs (bootId, bootStartedAt). */
function trustAt(world: RosterWorld, clock: Clock, rosterAt: number, extra: Record<string, unknown>): GateTrust {
  const parsed = parseGateRoster(rosterBytes(rosterDoc(world, rosterAt)));
  if (!parsed.ok) throw new Error("fixture roster refused");
  return createPinnedTrust({
    roster: parsed.roster,
    rosterDigest: parsed.digest,
    activeApproverKid: parsed.activeApproverKid,
    expiresAtMs: parsed.expiresAtMs,
    gateKey: { kid: world.gate.kid, publicKey: world.gate.publicKey, privateKey: world.gate.privateKey },
    stateStatus: "INITIALIZED",
    now: () => clock.t,
    ids,
    ...extra,
  } as CreatePinnedTrustInput);
}

function engineOn(trust: GateTrust, store: Store, clock: Clock, owners: readonly EffectOwner[] = []): GateEngine {
  store.putAgent(AGENT_1);
  return new GateEngine({
    store,
    config: resolveGateConfig({ now: () => clock.t }),
    trust,
    schemas: loadSchemas(),
    sealDisplay: testSealer,
    unsafeInProcessGrantKey: true,
    effectOwners: owners,
  });
}

function commandHold(engine: GateEngine, chain: string): string {
  const created = engine.createHold(AGENT_1, `idem-${chain}`, body({
    mode: "ENFORCED",
    action: { canonical: "noa.command.exec", riskClass: "HIGH", reversible: false },
    params: sampleCommandParams(),
    chain,
  }));
  assert.equal(created.status, 201, JSON.stringify(created.body));
  return (created.body as { holdId: string }).holdId;
}

test("BOOT-START-DECIDE — a later boot that reuses the boot identifier issues no grant for a hold frozen before it started", () => {
  const world = newWorld();
  const clock = makeClock();
  const t0 = clock.t;
  const store = new InMemoryStore();
  const first = engineOn(trustAt(world, clock, t0, { bootId: SUPERVISOR_BOOT, bootStartedAt: new Date(t0).toISOString() }), store, clock);
  const holdId = commandHold(first, "boot-start-decide");
  clock.advance(MIN);
  // The supervisor restarted and handed the SAME boot identifier to the new boot, which started now.
  const laterTrust = trustAt(world, clock, t0, { bootId: SUPERVISOR_BOOT, bootStartedAt: new Date(clock.t).toISOString() });
  const later = engineOn(laterTrust, store, clock);
  const hold = store.getHold(holdId)!;
  const decision = body(signPhoneDecision({
    trust: laterTrust,
    deferredReceipt: hold.deferredReceipt,
    holdEnvelope: hold.holdEnvelope as HoldEnvelope,
    decision: "APPROVE",
    signer: { kid: world.approver.kid, privateKey: world.approver.ed.privateKey },
  }));
  const r = later.decide(holdId, decision);
  assert.equal(store.listGrants().length, 0, "consequence: no grant for a hold frozen before this boot started");
  assert.equal(store.getHold(holdId)!.status, "PENDING", "the hold is left as it was");
  assert.equal(r.status, 410, JSON.stringify(r.body));
  assert.equal((r.body as { error?: string }).error, "HOLD_FROM_DEAD_BOOT");
});

test("BOOT-START — a supervisor's boot start is the trust root's; a malformed, missing, unpaired or future one builds no trust root", () => {
  const world = newWorld();
  const clock = makeClock();
  const started = new Date(clock.t - 10 * MIN).toISOString();
  const trust = trustAt(world, clock, clock.t, { bootId: SUPERVISOR_BOOT, bootStartedAt: started });
  assert.equal(trust.uptimeResetAt, started, "consequence: the boot's start is the supervisor's instant, not this worker's clock");
  const cases: Array<[string, Record<string, unknown>]> = [
    ["no bootStartedAt with a bootId", { bootId: SUPERVISOR_BOOT }],
    ["a bootStartedAt without a bootId", { bootStartedAt: started }],
    ["a date without a time", { bootId: SUPERVISOR_BOOT, bootStartedAt: "2026-07-14" }],
    ["a non-canonical spelling", { bootId: SUPERVISOR_BOOT, bootStartedAt: "2026-07-14T11:50:00Z" }],
    ["an offset instead of Z", { bootId: SUPERVISOR_BOOT, bootStartedAt: "2026-07-14T13:50:00.000+02:00" }],
    ["not a date", { bootId: SUPERVISOR_BOOT, bootStartedAt: "yesterday" }],
    ["a start in the future", { bootId: SUPERVISOR_BOOT, bootStartedAt: new Date(clock.t + 10 * MIN).toISOString() }],
    ["a number", { bootId: SUPERVISOR_BOOT, bootStartedAt: clock.t }],
  ];
  for (const [label, extra] of cases) {
    let built: GateTrust | null = null;
    let refusal: unknown = null;
    try {
      built = trustAt(world, clock, clock.t, extra);
    } catch (e) {
      refusal = e;
    }
    assert.equal(built, null, `consequence: no trust root is built on ${label}`);
    assert.match(String(refusal), /^Error: BOOT_START_INVALID/, label);
  }
});

function onDisk(world: RosterWorld, nowMs: number, over: Partial<LoadPinnedTrustInput>): LoadPinnedTrustInput {
  const dir = freshDir("boot-start");
  return {
    rosterFile: writeRoster(dir, rosterDoc(world, nowMs)),
    keyFile: writeKeyFile(dir, world.gate),
    rosterSha256: undefined,
    unsafeSameUid: false,
    tenantEnv: undefined,
    grantSignerSocketSet: false,
    gateEuid: 4242,
    nowMs,
    now: () => nowMs,
    lockState: false,
    ...over,
  };
}

test("BOOT-START-LOAD — the boot loader refuses a malformed supervisor boot start before any file is read, and reports both sources", () => {
  const world = newWorld();
  const nowMs = Date.parse("2026-09-01T12:00:00.000Z");
  const started = new Date(nowMs - MIN).toISOString();
  const r = loadPinnedTrust(onDisk(world, nowMs, { bootId: SUPERVISOR_BOOT, bootStartedAt: "yesterday" } as Partial<LoadPinnedTrustInput>));
  assert.equal(r.ok, false, "consequence: no gate boots on a malformed boot start");
  assert.equal((r as PinnedRefusal).code, "BOOT_START_INVALID");
  // Before any file is read: a missing roster file is not what refuses it.
  const early = loadPinnedTrust(onDisk(world, nowMs, { bootId: SUPERVISOR_BOOT, bootStartedAt: "yesterday", rosterFile: "/nonexistent/roster.json" } as Partial<LoadPinnedTrustInput>));
  assert.equal((early as PinnedRefusal).code, "BOOT_START_INVALID");
  const ok = loadPinnedTrust(onDisk(world, nowMs, { bootId: SUPERVISOR_BOOT, bootStartedAt: started } as Partial<LoadPinnedTrustInput>));
  assert.equal(ok.ok, true, JSON.stringify(ok));
  const boot = ok as PinnedBoot & { bootStartSource?: string };
  assert.equal(boot.trust.uptimeResetAt, started);
  assert.deepEqual([boot.bootIdSource, boot.bootStartSource], ["SUPERVISOR", "SUPERVISOR"]);
  const own = loadPinnedTrust(onDisk(world, nowMs, {})) as PinnedBoot & { bootStartSource?: string };
  assert.deepEqual([own.bootIdSource, own.bootStartSource], ["SELF", "SELF"]);
});

test("EFFECT-SUPERVISOR-BOOT-UNSAFE — under a supervisor's boot identifier no engine runs an owner that keeps its own consumption record", () => {
  const world = newWorld();
  const clock = makeClock();
  const trust = trustAt(world, clock, clock.t, { bootId: SUPERVISOR_BOOT, bootStartedAt: new Date(clock.t).toISOString() });
  const owner = createInMemoryLedgerEffectOwner({ trust, now: () => clock.t, ledger: LEDGER, accounts: DEFAULT_ACCOUNTS });
  let engine: GateEngine | null = null;
  let refusal: unknown = null;
  try {
    engine = engineOn(trust, new InMemoryStore(), clock, [owner]);
  } catch (e) {
    refusal = e;
  }
  assert.equal(engine, null, "consequence: no engine commits with a per-process ledger under a boot identifier other processes may share");
  assert.match(String(refusal), /^Error: EFFECT_OWNER_SUPERVISOR_BOOT_UNSAFE/);
  assert.equal(owner.bound, false, "the refused owner was never bound");
  // An owner that records the consumption in the engine's own store is accepted under the same boot.
  const store = new InMemoryStore();
  const inner = createInMemoryLedgerEffectOwner({ trust, now: () => clock.t, ledger: LEDGER, accounts: DEFAULT_ACCOUNTS });
  const recording: EffectOwner = {
    canonical: inner.canonical,
    ledger: inner.ledger,
    bootId: inner.bootId,
    get bound() {
      return inner.bound;
    },
    bindEngine: (e: object) => inner.bindEngine(e),
    admit: (c: string) => inner.admit(c),
    find: (h: string) => inner.find(h),
    commit: (i, s) => inner.commit(i, s),
    inspect: () => inner.inspect(),
    recordsGrantConsumption: true,
    store,
  };
  assert.ok(engineOn(trust, store, clock, [recording]) instanceof GateEngine);
});
