/**
 * ONE TRANSITION OUT OF PENDING — decide, expiry (read, wait, sweep) and cancel, across processes.
 *
 * Two gate processes over one store are modelled as two engines, each over its own `DetachedStore`
 * view of ONE authoritative store: a read returns a detached copy, every write lands on the shared
 * state, exactly as two processes over one database behave. The interleaving seam
 * (`beforeFirstWrite`) runs the OTHER process's whole request immediately before this process's
 * first write for the hold — the moment at which both have read PENDING and neither has written.
 *
 * Every test asserts the consequence first: how many Gate-signed grant records exist for the hold,
 * and whether any caller was shown a signed terminal state the store does not hold.
 *
 * Proof ID referenced by scripts/resolver-inventory.json — do not rename without updating it:
 *   [PROOF:SETTLE-ONCE]
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { GateEngine, type EngineResult } from "../src/engine.js";
import { resolveGateConfig } from "../src/config.js";
import { loadSchemas } from "../src/schemas.js";
import { InMemoryStore, type Store } from "../src/store.js";
import type { AgentRecord, GrantRecord, GrantStatus, HoldRecord, HoldStatus } from "../src/types.js";
import { body, makeClock, sampleCommandParams, testSealer, type Clock } from "./helpers.js";
import { newWorld } from "./helpers/pinned.js";
import { countingSigner, decisionFor, effectGate, holdIdOf, idSource, type EffectGate } from "./helpers/effect.js";
import { DetachedStore } from "./store-cas-contract.js";

/** A store view that runs `hook` once, immediately before its first write for one hold. */
class InterleavedStore implements Store {
  private armed = false;
  private target = "";
  private hook: () => void = () => {};
  constructor(private readonly view: Store) {}

  beforeFirstWrite(holdId: string, hook: () => void): void {
    this.armed = true;
    this.target = holdId;
    this.hook = hook;
  }
  private fire(holdId: string): void {
    if (this.armed && holdId === this.target) {
      this.armed = false;
      this.hook();
    }
  }

  putAgent(a: AgentRecord): void { this.view.putAgent(a); }
  findAgentByApiKeyHash(hash: string): AgentRecord | undefined { return this.view.findAgentByApiKeyHash(hash); }
  putHold(h: HoldRecord): void { this.fire(h.id); this.view.putHold(h); }
  getHold(id: string): HoldRecord | undefined { return this.view.getHold(id); }
  getHoldByIdem(agentId: string, idempotencyKey: string): HoldRecord | undefined { return this.view.getHoldByIdem(agentId, idempotencyKey); }
  listHolds(filter: { status?: HoldStatus; agentId?: string }): HoldRecord[] { return this.view.listHolds(filter); }
  countPending(agentId: string): number { return this.view.countPending(agentId); }
  hasPendingOnChain(agentId: string, chain: string): boolean { return this.view.hasPendingOnChain(agentId, chain); }
  putGrant(g: GrantRecord): void { this.fire(g.holdId); this.view.putGrant(g); }
  getGrant(grantId: string): GrantRecord | undefined { return this.view.getGrant(grantId); }
  listGrants(): GrantRecord[] { return this.view.listGrants(); }
  claimGrantStatus(grantId: string, expected: GrantStatus, next: GrantStatus, at: number): GrantRecord | null {
    return this.view.claimGrantStatus(grantId, expected, next, at);
  }
  claimGrantReported(grantId: string, at: number): GrantRecord | null { return this.view.claimGrantReported(grantId, at); }
  settleHold(next: HoldRecord, grant: GrantRecord | null): boolean { this.fire(next.id); return this.view.settleHold(next, grant); }
}

/** Process A is `fx.engine` over `a`; process B is `engineB` over `b`; both over `inner`. */
function twoProcesses(clockB?: Clock): { inner: InMemoryStore; a: InterleavedStore; b: InterleavedStore; fx: EffectGate; engineB: GateEngine; clockB: Clock } {
  const inner = new InMemoryStore();
  const a = new InterleavedStore(new DetachedStore(inner));
  const b = new InterleavedStore(new DetachedStore(inner));
  const fx = effectGate({ world: newWorld(), clock: makeClock(), store: a, owner: false, ids: idSource("settle") });
  const cb = clockB ?? fx.clock;
  const engineB = new GateEngine({
    store: b,
    config: resolveGateConfig({ now: () => cb.t }),
    trust: fx.trust,
    schemas: loadSchemas(),
    sealDisplay: testSealer,
    executionSigner: countingSigner(fx.trust),
  });
  return { inner, a, b, fx, engineB, clockB: cb };
}

function commandHold(fx: EffectGate, chain: string): string {
  return holdIdOf(fx.engine.createHold(fx.agent, `idem-${chain}`, body({
    mode: "ENFORCED",
    action: { canonical: "noa.command.exec", riskClass: "HIGH", reversible: false },
    params: sampleCommandParams(),
    chain,
  })));
}

function grantsFor(inner: InMemoryStore, holdId: string): GrantRecord[] {
  return inner.listGrants().filter((g) => g.holdId === holdId);
}

function statusOf(r: EngineResult): unknown {
  return (r.body as Record<string, unknown>)["status"];
}

function resolutionOf(r: EngineResult): unknown {
  return (r.body as Record<string, unknown>)["holdResolution"];
}

/** A hold about to expire: process A (decide) is 1 s before its expiry, process B is 1 s after it. */
function expiringHold(chain: string) {
  const clockB = makeClock();
  const p = twoProcesses(clockB);
  const holdId = commandHold(p.fx, chain);
  const expiresAt = (p.inner.getHold(holdId) as HoldRecord).expiresAt;
  p.fx.clock.t = expiresAt - 1000;
  clockB.t = expiresAt + 1000;
  return { ...p, holdId, decision: body(decisionFor(p.fx, holdId)) };
}

test("[PROOF:SETTLE-ONCE] two gate processes deciding one hold at once persist one Gate-signed grant record; the loser answers 409 with nothing it signed", () => {
  const { inner, a, fx, engineB } = twoProcesses();
  const holdId = commandHold(fx, "settle-decide");
  const decision = body(decisionFor(fx, holdId));
  const other: EngineResult[] = [];
  a.beforeFirstWrite(holdId, () => {
    other.push(engineB.decide(holdId, decision));
  });
  const first = fx.engine.decide(holdId, decision);
  const grants = grantsFor(inner, holdId);
  assert.equal(grants.length, 1, "consequence: one approval, one Gate-signed grant record for the hold");
  assert.equal(other.length, 1, "fixture: the other process decided in between");
  const results = [first, other[0] as EngineResult];
  const handedOut = results
    .map((r) => (r.body as Record<string, unknown>)["executionGrant"] as { grantId?: string } | null | undefined)
    .filter((g) => g !== null && g !== undefined)
    .map((g) => g!.grantId);
  assert.deepEqual(handedOut, [grants[0]?.grant.grantId], "consequence: the only grant handed to any caller is the one the store holds");
  const stored = inner.getHold(holdId) as HoldRecord;
  for (const r of results.filter((x) => x.status === 200)) {
    assert.deepEqual(
      [resolutionOf(r), (r.body as Record<string, unknown>)["grantId"]],
      [stored.holdResolution, stored.grantId],
      "consequence: every caller shown a success holds the stored resolution and is told of the stored grant",
    );
  }
  assert.deepEqual(results.map((r) => r.status).sort(), [200, 409]);
  const winner = results.find((r) => r.status === 200) as EngineResult;
  const loser = results.find((r) => r.status === 409) as EngineResult;
  assert.equal((loser.body as Record<string, unknown>)["error"], "HOLD_ALREADY_RESOLVED");
  assert.equal(resolutionOf(loser), undefined, "the loser returns no signed resolution");
  assert.equal((winner.body as Record<string, unknown>)["grantId"], grants[0]?.grant.grantId);
  assert.equal(inner.getHold(holdId)?.grantId, grants[0]?.grant.grantId);
});

test("HOLD-SETTLE-EXPIRY — a read that expires a hold another process is approving never returns a signed EXPIRED it did not persist", () => {
  const { inner, b, fx, engineB, holdId, decision } = expiringHold("settle-read");
  const decided: EngineResult[] = [];
  b.beforeFirstWrite(holdId, () => {
    decided.push(fx.engine.decide(holdId, decision));
  });
  const read = engineB.getHold(holdId, fx.agent);
  const stored = inner.getHold(holdId) as HoldRecord;
  assert.equal(decided.length, 1, "fixture: the approval landed in between");
  assert.deepEqual(
    [...new Set([statusOf(decided[0] as EngineResult), statusOf(read)])],
    [stored.status],
    "consequence: every caller is shown the one terminal state the store holds",
  );
  assert.equal(stored.status, "APPROVED");
  assert.deepEqual(resolutionOf(read), stored.holdResolution);
  assert.equal(grantsFor(inner, holdId).length, 1);
});

test("HOLD-SETTLE-WAIT — a long-poll that expires a hold another process is approving answers with the approval", async () => {
  const { inner, b, fx, engineB, holdId, decision } = expiringHold("settle-wait");
  b.beforeFirstWrite(holdId, () => {
    fx.engine.decide(holdId, decision);
  });
  const waited = await engineB.wait(holdId, 0, fx.agent);
  const stored = inner.getHold(holdId) as HoldRecord;
  assert.deepEqual([statusOf(waited), stored.status], ["APPROVED", "APPROVED"], "consequence: the approval stands, and the long-poll shows it");
  assert.deepEqual(resolutionOf(waited), stored.holdResolution);
});

test("HOLD-SETTLE-SWEEP — the expiry sweep never overwrites an approval another process persisted in between", () => {
  const { inner, b, fx, engineB, holdId, decision } = expiringHold("settle-sweep");
  b.beforeFirstWrite(holdId, () => {
    fx.engine.decide(holdId, decision);
  });
  const swept = engineB.sweepExpired();
  const stored = inner.getHold(holdId) as HoldRecord;
  assert.equal(stored.status, "APPROVED", "consequence: the approval and its grant stand");
  assert.equal(grantsFor(inner, holdId).length, 1);
  assert.equal(stored.grantId, grantsFor(inner, holdId)[0]?.grant.grantId);
  assert.equal(swept, 0, "the sweep counts only the holds it expired");
});

test("HOLD-SETTLE-CANCEL — a cancel racing an approval never replaces it; the loser answers 409", () => {
  const { inner, b, fx, engineB } = twoProcesses();
  const holdId = commandHold(fx, "settle-cancel");
  const decision = body(decisionFor(fx, holdId));
  const decided: EngineResult[] = [];
  b.beforeFirstWrite(holdId, () => {
    decided.push(fx.engine.decide(holdId, decision));
  });
  const cancelled = engineB.cancelLocalStateLost(holdId, fx.agent);
  const stored = inner.getHold(holdId) as HoldRecord;
  const shown200 = [decided[0] as EngineResult, cancelled].filter((r) => r.status === 200).map(statusOf);
  assert.deepEqual(shown200, [stored.status], "consequence: only the persisted terminal state is ever shown as a success");
  assert.equal(stored.status, "APPROVED");
  assert.equal(cancelled.status, 409);
  assert.equal((cancelled.body as Record<string, unknown>)["error"], "HOLD_ALREADY_RESOLVED");
});
