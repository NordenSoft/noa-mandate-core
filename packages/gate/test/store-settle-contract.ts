/**
 * THE settleHold STORE CONTRACT (src/store.ts): what every store that serves the gate must do with the
 * one transition out of PENDING, as tests any store can run. `runSettleHoldStoreContract(label, open)`
 * registers them; `open()` returns two connections to ONE fresh state (`store` and `peer`; for an
 * in-memory store both may be the same object). test/store-settle-contract.test.ts runs it over the
 * in-memory store and over two detached views of one state; a durable store runs it over two of its
 * connections.
 *
 * Each test asserts the consequence first: which hold and which grant records the state holds.
 */
import { test as nodeTest } from "node:test";
import assert from "node:assert/strict";
import type { Store } from "../src/store.js";
import type { GrantRecord, HoldRecord } from "../src/types.js";
import { body, sampleCommandParams } from "./helpers.js";
import { effectGate, gateKey, holdIdOf, idSource, signedGrant, type EffectGate } from "./helpers/effect.js";

export type OpenSettleStores = () => { store: Store; peer: Store };

/** A real PENDING hold frozen by a gate over `store`, and a way to mint real grant records for it. */
function pendingHold(store: Store, chain: string): { fx: EffectGate; hold: HoldRecord; grantFor: () => GrantRecord } {
  const fx = effectGate({ store, owner: false, ids: idSource(`settle-contract-${chain}`) });
  const holdId = holdIdOf(fx.engine.createHold(fx.agent, `idem-${chain}`, body({
    mode: "ENFORCED",
    action: { canonical: "noa.command.exec", riskClass: "HIGH", reversible: false },
    params: sampleCommandParams(),
    chain,
  })));
  const hold = store.getHold(holdId) as HoldRecord;
  const grantFor = (): GrantRecord => ({
    grant: signedGrant(fx, holdId, gateKey(fx.world)),
    status: "UNUSED",
    holdId,
    reservedAt: null,
    reportedAt: null,
    unknownHintAt: null,
    claimedResult: null,
    claimedBy: null,
    claimedAt: null,
    consumption: null,
    uncertainty: null,
    createdAt: fx.clock.t,
  });
  return { fx, hold, grantFor };
}

function settled(hold: HoldRecord, status: "APPROVED" | "EXPIRED", grant: GrantRecord | null): HoldRecord {
  return { ...hold, status, decidedAt: hold.createdAt + 1, reasonCode: status === "APPROVED" ? "HUMAN_APPROVED_INTENT_NOT_EXECUTION_BOUND" : "APPROVAL_TIMEOUT", grantId: grant === null ? null : grant.grant.grantId };
}

function grantsOf(store: Store, holdId: string): string[] {
  return store.listGrants().filter((g) => g.holdId === holdId).map((g) => g.grant.grantId).sort();
}

/** Register the settleHold contract tests for the stores `open` returns, named with `label`. */
export function runSettleHoldStoreContract(label: string, open: OpenSettleStores): void {
  const test = (name: string, fn: () => void): void => {
    nodeTest(`${name} [${label}]`, fn);
  };

  test("STORE-SETTLE-WIN — settling a PENDING hold writes the hold and its grant in one step, visible to every connection", () => {
    const { store, peer } = open();
    const { hold, grantFor } = pendingHold(store, "win");
    const grant = grantFor();
    const won = store.settleHold(settled(hold, "APPROVED", grant), grant);
    assert.deepEqual(
      [peer.getHold(hold.id)?.status, peer.getHold(hold.id)?.grantId, grantsOf(peer, hold.id)],
      ["APPROVED", grant.grant.grantId, [grant.grant.grantId]],
      "consequence: the settled hold and its grant are both in the state",
    );
    assert.equal(won, true);
  });

  test("STORE-SETTLE-LOST — settling a hold that is no longer PENDING returns false and writes neither the hold nor the grant", () => {
    const { store, peer } = open();
    const { hold, grantFor } = pendingHold(store, "lost");
    const first = grantFor();
    assert.equal(store.settleHold(settled(hold, "APPROVED", first), first), true);
    const second = grantFor();
    const lost = peer.settleHold(settled(hold, "EXPIRED", second), second);
    assert.deepEqual(
      [store.getHold(hold.id)?.status, store.getHold(hold.id)?.grantId, grantsOf(store, hold.id)],
      ["APPROVED", first.grant.grantId, [first.grant.grantId]],
      "consequence: a lost settle writes no hold and no grant",
    );
    assert.equal(lost, false);
  });

  test("STORE-SETTLE-RACE — two connections that both read PENDING and both settle: exactly one wins, and one grant record exists", () => {
    const { store, peer } = open();
    const { hold, grantFor } = pendingHold(store, "race");
    const readByStore = store.getHold(hold.id) as HoldRecord;
    const readByPeer = peer.getHold(hold.id) as HoldRecord;
    assert.deepEqual([readByStore.status, readByPeer.status], ["PENDING", "PENDING"], "fixture: both read PENDING");
    const g1 = grantFor();
    const g2 = grantFor();
    const results = [store.settleHold(settled(readByStore, "APPROVED", g1), g1), peer.settleHold(settled(readByPeer, "APPROVED", g2), g2)];
    const winner = results[0] ? g1 : g2;
    assert.deepEqual(grantsOf(store, hold.id), [winner.grant.grantId], "consequence: one hold, one grant record");
    assert.deepEqual(results, [true, false], "the first settle wins, the second loses");
    assert.equal(store.getHold(hold.id)?.grantId, winner.grant.grantId);
  });

  test("STORE-SETTLE-UNKNOWN — settling a hold the state does not hold returns false and writes nothing", () => {
    const { store } = open();
    const { hold, grantFor } = pendingHold(store, "unknown");
    const grant = grantFor();
    const ghost: HoldRecord = { ...settled(hold, "APPROVED", grant), id: `${hold.id}-absent` };
    const r = store.settleHold(ghost, grant);
    assert.deepEqual([store.getHold(ghost.id), grantsOf(store, hold.id)], [undefined, []], "consequence: nothing is written for an unknown hold");
    assert.equal(r, false);
  });
}
