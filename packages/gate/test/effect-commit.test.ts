/**
 * Effect-owned commit through the engine and over HTTP (docs/gate-effect-owner.md).
 *
 * `noa.ledger.transfer` is committed by the gate itself: `POST /v1/holds/:holdId/commit` hands the
 * signed artifacts to the in-process effect owner, which re-verifies them and writes exactly one row.
 *
 * EVERY ATTACK TEST ASSERTS THE CONSEQUENCE FIRST — the row count, the balances, the grant record, the
 * signed bytes an agent could read — and the refusal code only after. A knockout that removes a
 * control must turn a consequence assertion red, not merely change which code is printed. Each
 * detector is named by a `EFFECT-…` id in its test title; `scripts/lint-control-knockout.mjs` names the
 * same id for the arm it measures.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyArtifact } from "noa-approval-artifacts";
import { verifyChain, projectLedgerTransfer, LEDGER_TRANSFER_CANONICAL } from "noa-receipt";
import { GateEngine } from "../src/engine.js";
import { resolveGateConfig } from "../src/config.js";
import { createGate, type Gate } from "../src/server.js";
import { loadSchemas } from "../src/schemas.js";
import { InMemoryStore } from "../src/store.js";
import { encodeDocument } from "../src/bytes.js";
import { createInMemoryLedgerEffectOwner } from "../src/effect-owner.js";
import type { GrantRecord, Receipt } from "../src/types.js";
import { body, makeClock, sampleCommandParams } from "./helpers.js";
import { approverKeys, newWorld, rosterDoc } from "./helpers/pinned.js";
import {
  ACCT_1,
  ACCT_2,
  AGENT_1_SECRET,
  DEFAULT_ACCOUNTS,
  HOUR,
  LEDGER,
  MIN,
  OTHER_LEDGER,
  approvalReceiptBy,
  approvedTransfer,
  balanceTotal,
  canonicalOf,
  countingSigner,
  createTransfer,
  decisionFor,
  effectGate,
  extendEnvelope,
  gateKey,
  grantOf,
  hold,
  holdIdOf,
  idSource,
  plantApproved,
  rowCount,
  signedGrant,
  transfer,
  transferRequest,
  type EffectGate,
} from "./helpers/effect.js";

const errorOf = (r: { body: unknown }): unknown => (r.body as { error?: unknown }).error;
const bodyOf = (r: { body: unknown }): Record<string, unknown> => r.body as Record<string, unknown>;

function balances(fx: EffectGate): Readonly<Record<string, number>> {
  return fx.owner!.inspect().balances;
}

class FlakyReportStore extends InMemoryStore {
  throwsLeft = 1;
  override claimGrantReported(grantId: string, at: number) {
    if (this.throwsLeft > 0) {
      this.throwsLeft--;
      throw new Error("test: the store is unavailable");
    }
    return super.claimGrantReported(grantId, at);
  }
}

// ── positive path ─────────────────────────────────────────────────────────────────────────────────

test("CONTROL — approve then commit: one EXECUTED row moves the amount, signs one attestation, and the signed artifacts verify", () => {
  const fx = effectGate();
  const created = createTransfer(fx, "pos");
  assert.equal(created.status, 201, JSON.stringify(created.body));
  const holdId = holdIdOf(created);
  const h = hold(fx, holdId);
  assert.equal(h.mode, "ENFORCED");
  assert.equal(h.action.reversible, false);
  assert.equal(h.canonicalParams, canonicalOf(transfer()), "the hold keeps the exact canonical text the adapter hashed");
  assert.equal(h.bootId, fx.trust.bootId);
  assert.equal(fx.engine.decide(holdId, body(decisionFor(fx, holdId))).status, 200);
  const totalBefore = balanceTotal(fx.owner!);
  const attestationsBefore = fx.signer.counts.attestation;

  const r = fx.engine.commit(holdId, fx.agent);
  assert.equal(r.status, 200, JSON.stringify(r.body));
  const b = bodyOf(r);
  assert.equal(b["outcome"], "EXECUTED");
  assert.equal(b["idempotent"], false);
  assert.equal(rowCount(fx.owner), 1);
  assert.deepEqual({ ...balances(fx) }, { [ACCT_1]: 900, [ACCT_2]: 100, "acct-example-3": 50 });
  assert.equal(balanceTotal(fx.owner!), totalBefore, "a transfer conserves the total");
  assert.equal(fx.signer.counts.attestation - attestationsBefore, 1, "exactly one attestation (the consumption) is signed by the commit");
  for (const hidden of ["salt", "canonicalParams", "balances"]) assert.equal(hidden in b, false, `the response never carries ${hidden}`);

  const grant = grantOf(fx, holdId);
  assert.equal(grant.status, "REPORTED", "the grant record mirrors the consumed authority");
  assert.deepEqual(grant.consumption, b["executionConsumption"]);
  // The consumption verifies against the trust root, and binds this grant and this attempt receipt.
  const consumption = b["executionConsumption"] as Record<string, unknown>;
  const ctx = encodeDocument({ schemas: loadSchemas(), keyring: fx.trust.keyring, now: new Date(fx.clock.t).toISOString() });
  assert.equal(verifyArtifact(encodeDocument(consumption), ctx).ok, true);
  // The EXECUTED receipt chains deferred -> approval -> executed under the gate's receipt keyring.
  const chain = verifyChain(encodeDocument([h.deferredReceipt, h.decisionReceipt, b["executedReceipt"]]), {
    keyring: encodeDocument(fx.trust.receiptKeyring),
    requireTenantConsistency: true,
  });
  assert.equal(chain.status, "VALID", JSON.stringify(chain));
  assert.equal((b["executedReceipt"] as { governance: { verdict: string } }).governance.verdict, "EXECUTED");
  // The hold resolution is unchanged: the gate is the witness of its own effect, so no stronger claim.
  assert.equal(hold(fx, holdId).status, "APPROVED");
  assert.equal(hold(fx, holdId).reasonCode, "HUMAN_APPROVED_INTENT_NOT_EXECUTION_BOUND");
});

test("EFFECT-VIEW-WITHHOLDS-GRANT — before the row exists the grant bytes appear in no decide, wait or getHold body", async () => {
  const fx = effectGate();
  const holdId = holdIdOf(createTransfer(fx, "view"));
  const decided = fx.engine.decide(holdId, body(decisionFor(fx, holdId)));
  const grant = grantOf(fx, holdId).grant;
  const got = fx.engine.getHold(holdId, fx.agent);
  const waited = await fx.engine.wait(holdId, 0, fx.agent);
  for (const [name, r] of [["decide", decided], ["getHold", got], ["wait", waited]] as const) {
    assert.equal(JSON.stringify(r.body).includes(grant.sig.value), false, `consequence: ${name} must not hand out the signed grant`);
    assert.equal(bodyOf(r)["executionGrant"], null, `${name}: executionGrant is withheld`);
    assert.equal(bodyOf(r)["effect"], null, `${name}: no effect yet`);
  }
  assert.equal(decided.status, 200);
  // After the commit the view reports the effect and may show the (now consumed) grant.
  const committed = fx.engine.commit(holdId, fx.agent);
  const after = bodyOf(fx.engine.getHold(holdId, fx.agent));
  assert.deepEqual(after["effect"], { effectId: bodyOf(committed)["effectId"], outcome: "EXECUTED" });
  assert.deepEqual(after["executionGrant"], grant);
});

test("EFFECT-RESERVE-REFUSED — reserve cannot spend an effect-owned grant, and nothing gate-signed follows", () => {
  const fx = effectGate();
  const holdId = approvedTransfer(fx, "reserve");
  const grantId = grantOf(fx, holdId).grant.grantId;
  const r = fx.engine.reserve(grantId, fx.agent);
  assert.equal(grantOf(fx, holdId).status, "UNUSED", "consequence: the grant is not reserved");
  assert.equal(grantOf(fx, holdId).reservedAt, null, "consequence: no reservation is recorded");
  const rep = fx.engine.report(grantId, body({ result: "DISPATCHED" }), fx.agent);
  assert.equal(grantOf(fx, holdId).consumption, null, "consequence: no consumption is signed without a row");
  assert.equal(rowCount(fx.owner), 0);
  assert.equal(r.status, 409, JSON.stringify(r.body));
  assert.equal(errorOf(r), "EFFECT_OWNED_ACTION_NOT_RESERVABLE");
  assert.equal(rep.status, 409, JSON.stringify(rep.body));
  // The commit route still works: the refusal closed a door, not the effect.
  assert.equal(fx.engine.commit(holdId, fx.agent).status, 200);
});

test("EFFECT-RESERVE-TABLE-KEYED — an engine WITHOUT an owner that shares the store cannot reserve either", () => {
  const fx = effectGate();
  const holdId = approvedTransfer(fx, "reserve-ownerless");
  const grantId = grantOf(fx, holdId).grant.grantId;
  // Same trust root and store, no effect owner configured: the refusal keys on the static table.
  const ownerless = new GateEngine({
    store: fx.store,
    config: resolveGateConfig({ now: () => fx.clock.t }),
    trust: fx.trust,
    schemas: loadSchemas(),
    executionSigner: countingSigner(fx.trust),
  });
  const r = ownerless.reserve(grantId, fx.agent);
  assert.equal(grantOf(fx, holdId).status, "UNUSED", "consequence: an owner-less engine reserves nothing");
  assert.equal(r.status, 409, JSON.stringify(r.body));
  assert.equal(errorOf(r), "EFFECT_OWNED_ACTION_NOT_RESERVABLE");
});

test("EFFECT-REPORT-REFUSED — an injected RESERVED grant plus DISPATCHED gets no gate-signed EXECUTED receipt", () => {
  const fx = effectGate();
  const holdId = approvedTransfer(fx, "report");
  const grantId = grantOf(fx, holdId).grant.grantId;
  // STORE SEAM: a RESERVED grant, as an injected store or a mixed build could hold it.
  assert.ok(fx.store.claimGrantStatus(grantId, "UNUSED", "RESERVED", fx.clock.t));
  const attestationsBefore = fx.signer.counts.attestation;
  const r = fx.engine.report(grantId, body({ result: "DISPATCHED" }), fx.agent);
  assert.equal(grantOf(fx, holdId).consumption, null, "consequence: no consumption is signed");
  assert.equal(grantOf(fx, holdId).reportedAt, null, "consequence: the report lock is not taken");
  assert.equal(fx.signer.counts.attestation, attestationsBefore, "consequence: nothing is signed");
  assert.equal(rowCount(fx.owner), 0);
  assert.equal(r.status, 409, JSON.stringify(r.body));
  assert.equal(errorOf(r), "EFFECT_OWNED_ACTION_NOT_REPORTABLE");
});

test("EFFECT-COMMIT-GRANT-UNUSED — no row is written while a RESERVED grant is still out", () => {
  const fx = effectGate();
  const holdId = approvedTransfer(fx, "reserved-out");
  const grantId = grantOf(fx, holdId).grant.grantId;
  assert.ok(fx.store.claimGrantStatus(grantId, "UNUSED", "RESERVED", fx.clock.t));
  const r = fx.engine.commit(holdId, fx.agent);
  assert.equal(rowCount(fx.owner), 0, "consequence: no row while another spender holds the grant");
  assert.equal(balances(fx)[ACCT_1], 1000, "consequence: nothing moved");
  assert.equal(r.status, 409, JSON.stringify(r.body));
  assert.equal(errorOf(r), "GRANT_NOT_UNUSED");
  assert.equal(bodyOf(r)["status"], "RESERVED");
  assert.equal(bodyOf(r)["retryable"], false);
});

/** Two gates on one store: same roster document, gate key and epoch; different boots and ledgers. */
function restartPair(): { a: EffectGate; b: EffectGate } {
  const world = newWorld();
  const clock = makeClock();
  const store = new InMemoryStore();
  const roster = rosterDoc(world, clock.t);
  const a = effectGate({ world, clock, store, roster, ids: idSource("boot-a") });
  const b = effectGate({ world, clock, store, roster, ids: idSource("boot-b") });
  assert.notEqual(a.trust.bootId, b.trust.bootId, "fixture: the restart draws a new bootId");
  assert.equal(a.trust.pinned!.rosterDigest, b.trust.pinned!.rosterDigest, "fixture: same roster");
  assert.equal(a.trust.gate.kid, b.trust.gate.kid, "fixture: same gate key");
  assert.equal(a.trust.gate.publicKey, b.trust.gate.publicKey, "fixture: same gate key");
  assert.equal(a.trust.keyManifestHash, b.trust.keyManifestHash, "fixture: same epoch");
  return { a, b };
}

test("EFFECT-DEAD-BOOT-COMMIT — a restarted gate (same roster, key and epoch) does not commit a hold frozen before the restart", () => {
  const { a, b } = restartPair();
  const holdId = approvedTransfer(a, "dead-boot-commit");
  const r = b.engine.commit(holdId, b.agent);
  assert.equal(rowCount(b.owner), 0, "consequence: the restarted gate writes no row");
  assert.equal(grantOf(a, holdId).status, "UNUSED", "consequence: the authority is not consumed");
  assert.equal(r.status, 410, JSON.stringify(r.body));
  assert.equal(errorOf(r), "HOLD_FROM_DEAD_BOOT");
  // Positive control: the boot that froze it commits it.
  assert.equal(a.engine.commit(holdId, a.agent).status, 200);
});

test("EFFECT-DEAD-BOOT-DECIDE — a restarted gate issues no grant on a hold frozen before the restart (effect-owned and command holds); the hold expires normally", () => {
  const { a, b } = restartPair();
  const transferHold = holdIdOf(createTransfer(a, "dead-boot-decide"));
  const commandHold = holdIdOf(a.engine.createHold(a.agent, "idem-dead-boot-cmd", body({
    mode: "ENFORCED",
    action: { canonical: "noa.command.exec", riskClass: "HIGH", reversible: false },
    params: sampleCommandParams(),
    chain: "dead-boot-cmd",
  })));
  for (const holdId of [transferHold, commandHold]) {
    const r = b.engine.decide(holdId, body(decisionFor(a, holdId)));
    assert.equal(a.store.listGrants().length, 0, "consequence: no grant is issued after a restart");
    assert.equal(hold(a, holdId).status, "PENDING", "consequence: the hold stays PENDING");
    assert.equal(hold(a, holdId).holdResolution, null, "consequence: nothing is signed for it");
    assert.equal(r.status, 410, JSON.stringify(r.body));
    assert.equal(errorOf(r), "HOLD_FROM_DEAD_BOOT");
  }
  // Terminality: the restarted gate's sweep expires both with a signed EXPIRED.
  a.clock.advance(16 * MIN);
  assert.equal(b.engine.sweepExpired(), 2);
  assert.equal(hold(a, transferHold).status, "EXPIRED");
  assert.ok(hold(a, transferHold).holdResolution);
});

test("EFFECT-GRANT-EXPIRY — a commit exactly at the grant's expiresAt is refused; one millisecond earlier it commits", () => {
  const fx = effectGate();
  const late = approvedTransfer(fx, "expiry-late");
  const onTime = approvedTransfer(fx, "expiry-on-time", transfer({ amount: "5" }));
  const lateExpiry = Date.parse(grantOf(fx, late).grant.expiresAt);
  const onTimeExpiry = Date.parse(grantOf(fx, onTime).grant.expiresAt);
  assert.equal(lateExpiry, onTimeExpiry, "fixture: both grants were issued at the same instant");
  fx.clock.t = lateExpiry;
  const r = fx.engine.commit(late, fx.agent);
  assert.equal(rowCount(fx.owner), 0, "consequence: an expired grant moves nothing");
  assert.equal(r.status, 410, JSON.stringify(r.body));
  assert.equal(errorOf(r), "GRANT_EXPIRED");
  fx.clock.t = onTimeExpiry - 1;
  assert.equal(fx.engine.commit(onTime, fx.agent).status, 200);
  assert.equal(rowCount(fx.owner), 1);
});

test("EFFECT-EXPIRY-CLAMP — a test-signed grant that outlives its hold does not commit after the hold expires", () => {
  const fx = effectGate();
  const holdId = approvedTransfer(fx, "clamp");
  const h = hold(fx, holdId);
  const real = grantOf(fx, holdId).grant;
  const envelopeExpiry = Date.parse(h.holdEnvelope.expiresAt);
  // Signed with the gate key the test holds; every binding is the hold's own, only expiresAt outlives it.
  const longGrant = signedGrant(fx, holdId, gateKey(fx.world), {
    grantId: real.grantId,
    issuedAt: real.issuedAt,
    nonce: real.nonce,
    expiresAt: new Date(envelopeExpiry + HOUR).toISOString(),
  });
  const rec = grantOf(fx, holdId);
  fx.store.putGrant({ ...rec, grant: longGrant } as GrantRecord);
  fx.clock.t = envelopeExpiry + MIN;
  const r = fx.engine.commit(holdId, fx.agent);
  assert.equal(rowCount(fx.owner), 0, "consequence: nothing commits after the hold's own expiry");
  assert.equal(r.status, 410, JSON.stringify(r.body));
  assert.equal(errorOf(r), "GRANT_EXPIRED");
});

test("EFFECT-FORGED-GRANT — a store-planted APPROVED hold whose grant the gate never signed commits nothing (token grant)", () => {
  const fx = effectGate();
  const holdId = holdIdOf(createTransfer(fx, "forged-grant"));
  const decision = decisionFor(fx, holdId);
  const attacker = approverKeys(8).ed;
  const forged = signedGrant(fx, holdId, { kid: fx.world.gate.kid, privateKey: attacker.privateKey }, {}, decision.receipt);
  plantApproved(fx, holdId, { decisionArtifact: decision.decisionArtifact, receipt: decision.receipt, grant: forged });
  const r = fx.engine.commit(holdId, fx.agent);
  assert.equal(rowCount(fx.owner), 0, "consequence: a forged grant moves nothing");
  assert.equal(balances(fx)[ACCT_1], 1000);
  assert.equal(r.status, 500, JSON.stringify(r.body));
  assert.equal(errorOf(r), "COMMIT_AUTHORITY_INVALID");
  assert.equal(bodyOf(r)["detail"], "grant");
});

/**
 * STORE SEAM with the gate key: the hold's envelope replaced by the same envelope re-signed with a
 * two-hour-later expiry, a gate-key grant bound to it, and the clock past the envelope the human
 * actually approved. Only the decision's binding to the approved envelope stands between this and a
 * commit outside the approved window.
 */
function pastApprovedWindow(fx: EffectGate, holdId: string, decisionArtifact: Record<string, unknown>, receipt: Receipt): void {
  const { original } = extendEnvelope(fx, holdId, 2 * HOUR);
  plantApproved(fx, holdId, {
    decisionArtifact,
    receipt,
    grant: signedGrant(fx, holdId, gateKey(fx.world), { expiresAt: new Date(Date.parse(original.expiresAt) + HOUR).toISOString() }, receipt),
  });
  fx.clock.t = Date.parse(original.expiresAt) + MIN;
}

test("EFFECT-DECISION-REBIND — the approver's decision for one envelope does not authorize a re-signed envelope with a later expiry (token decision)", () => {
  const fx = effectGate();
  const holdId = holdIdOf(createTransfer(fx, "rebind"));
  const genuine = decisionFor(fx, holdId);
  pastApprovedWindow(fx, holdId, genuine.decisionArtifact, genuine.receipt);
  const r = fx.engine.commit(holdId, fx.agent);
  assert.equal(rowCount(fx.owner), 0, "consequence: nothing commits outside the window the human approved");
  assert.equal(balances(fx)[ACCT_1], 1000);
  assert.equal(r.status, 500, JSON.stringify(r.body));
  assert.equal(errorOf(r), "COMMIT_AUTHORITY_INVALID");
  assert.equal(bodyOf(r)["detail"], "decision");
});

test("EFFECT-FORGED-DECISION — a decision the roster approver never signed, for a re-signed envelope, commits nothing (token decision)", () => {
  const fx = effectGate();
  const holdId = holdIdOf(createTransfer(fx, "forged-decision"));
  const genuine = decisionFor(fx, holdId);
  const { original } = extendEnvelope(fx, holdId, 2 * HOUR);
  // Signed by a key outside the roster under the roster approver's kid, bound to the re-signed envelope.
  const forged = decisionFor(fx, holdId, "APPROVE", { ...approverKeys(9), kid: fx.world.approver.kid });
  plantApproved(fx, holdId, {
    decisionArtifact: forged.decisionArtifact,
    receipt: genuine.receipt,
    grant: signedGrant(fx, holdId, gateKey(fx.world), { expiresAt: new Date(Date.parse(original.expiresAt) + HOUR).toISOString() }, genuine.receipt),
  });
  fx.clock.t = Date.parse(original.expiresAt) + MIN;
  const r = fx.engine.commit(holdId, fx.agent);
  assert.equal(rowCount(fx.owner), 0, "consequence: a forged decision authorizes nothing");
  assert.equal(balances(fx)[ACCT_1], 1000);
  assert.equal(r.status, 500, JSON.stringify(r.body));
  assert.equal(bodyOf(r)["detail"], "decision");
});

test("EFFECT-SNAPSHOT-SWAP — the stored snapshot rewritten to 999999999999999 does not move (PARAMS_SNAPSHOT_MISMATCH)", () => {
  const fx = effectGate({ accounts: { [ACCT_1]: 999999999999999, [ACCT_2]: 0 } });
  const holdId = approvedTransfer(fx, "swap");
  const h = hold(fx, holdId);
  h.canonicalParams = canonicalOf(transfer({ amount: "999999999999999" }));
  fx.store.putHold(h);
  const r = fx.engine.commit(holdId, fx.agent);
  assert.equal(rowCount(fx.owner), 0, "consequence: the swapped amount does not move");
  assert.equal(balances(fx)[ACCT_1], 999999999999999);
  assert.equal(r.status, 500, JSON.stringify(r.body));
  assert.equal(errorOf(r), "PARAMS_SNAPSHOT_MISMATCH");
});

test("EFFECT-REPLAY-FIRST — a retry after success returns the same effect idempotently, with no new signature, even after the grant expired", () => {
  const fx = effectGate();
  const holdId = approvedTransfer(fx, "replay");
  const first = fx.engine.commit(holdId, fx.agent);
  assert.equal(first.status, 200, JSON.stringify(first.body));
  const signed = fx.signer.counts.attestation;
  fx.clock.t = Date.parse(grantOf(fx, holdId).grant.expiresAt) + HOUR;
  const again = fx.engine.commit(holdId, fx.agent);
  assert.equal(again.status, 200, "consequence: an executed effect is never reported as refused on retry");
  assert.equal(bodyOf(again)["effectId"], bodyOf(first)["effectId"]);
  assert.equal(bodyOf(again)["idempotent"], true);
  assert.equal(fx.signer.counts.attestation, signed, "a replay signs nothing");
  assert.equal(rowCount(fx.owner), 1);
});

test("EFFECT-FOREIGN-COMMIT — agent-example-2 cannot commit agent-example-1's hold: the same 404 as an absent hold, no row", () => {
  const fx = effectGate();
  const holdId = approvedTransfer(fx, "foreign");
  const r = fx.engine.commit(holdId, fx.other);
  assert.equal(rowCount(fx.owner), 0, "consequence: a foreign agent moves nothing");
  assert.equal(grantOf(fx, holdId).status, "UNUSED");
  assert.equal(r.status, 404);
  assert.deepEqual(r.body, fx.engine.commit("no-such-hold", fx.other).body, "no existence oracle");
});

test("EFFECT-NO-OWNER-NO-HOLD — without an effect owner a transfer hold is refused (503) and no human is asked", () => {
  const fx = effectGate({ owner: false });
  const r = createTransfer(fx, "no-owner");
  assert.equal(fx.store.listHolds({}).length, 0, "consequence: nobody is asked to approve a transfer nothing can execute");
  assert.equal(r.status, 503, JSON.stringify(r.body));
  assert.equal(errorOf(r), "EFFECT_OWNER_UNCONFIGURED");
});

test("EFFECT-LEDGER-ID-CREATE — a transfer naming another ledger is refused at createHold (422) and no human is asked", () => {
  const fx = effectGate();
  const r = createTransfer(fx, "other-ledger", transfer({ ledger: OTHER_LEDGER }));
  assert.equal(fx.store.listHolds({}).length, 0, "consequence: no hold for a ledger this gate cannot commit");
  assert.equal(r.status, 422, JSON.stringify(r.body));
  assert.equal(errorOf(r), "LEDGER_NOT_OWNED");
});

test("EFFECT-REVERSIBLE — the gate signs reversible:false for every transfer; a caller's reversible member is refused whatever its value", () => {
  const fx = effectGate();
  for (const reversible of [true, false]) {
    const r = fx.engine.createHold(fx.agent, `idem-rev-${reversible}`, transferRequest(`rev-${reversible}`, transfer(), { reversible }));
    const signedTrue = fx.store.listHolds({}).filter((h) => h.deferredReceipt.action.reversible === true);
    assert.equal(signedTrue.length, 0, "consequence: the gate never signs a caller-chosen reversible:true");
    assert.equal(fx.store.listHolds({}).length, 0, `consequence: a request carrying reversible:${reversible} freezes no hold`);
    assert.equal(r.status, 422, JSON.stringify(r.body));
    assert.equal(errorOf(r), "REVERSIBLE_NOT_CALLER_SUPPLIED");
  }
  const ok = createTransfer(fx, "rev-absent");
  assert.equal(ok.status, 201);
  assert.equal(hold(fx, holdIdOf(ok)).deferredReceipt.action.reversible, false);
});

test("EFFECT-FUNDS — a transfer above the balance writes one terminal, unsigned REFUSED row and moves nothing", () => {
  const fx = effectGate();
  const holdId = approvedTransfer(fx, "funds", transfer({ fromAccount: "acct-example-3", amount: "51" }));
  const signed = fx.signer.counts.attestation;
  const r = fx.engine.commit(holdId, fx.agent);
  const rows = fx.owner!.inspect().rows;
  assert.equal(rows.filter((row) => row.outcome === "EXECUTED").length, 0, "consequence: nothing executes");
  assert.equal(balances(fx)["acct-example-3"], 50, "consequence: no balance goes negative");
  assert.equal(rows.length, 1);
  assert.equal(rows[0]!.outcome, "REFUSED");
  assert.equal(rows[0]!.attestation, null, "a refusal is never signed");
  assert.equal(fx.signer.counts.attestation, signed, "a refusal signs nothing");
  assert.equal(r.status, 409, JSON.stringify(r.body));
  assert.deepEqual(r.body, { error: "LEDGER_INSUFFICIENT_FUNDS", outcome: "REFUSED", idempotent: false, effectId: rows[0]!.effectId, retryable: false });
  // Terminal: a retry replays the refusal, and the view shows it.
  const again = fx.engine.commit(holdId, fx.agent);
  assert.equal(bodyOf(again)["idempotent"], true);
  assert.equal(bodyOf(again)["error"], "LEDGER_INSUFFICIENT_FUNDS");
  assert.deepEqual(bodyOf(fx.engine.getHold(holdId, fx.agent))["effect"], { effectId: rows[0]!.effectId, outcome: "REFUSED" });
  assert.equal(bodyOf(fx.engine.getHold(holdId, fx.agent))["executionGrant"], null);
  assert.equal(grantOf(fx, holdId).status, "UNUSED");
});

test("EFFECT-UNKNOWN-ACCOUNT — a transfer from or to an account the ledger does not hold writes a REFUSED row and moves nothing; accounts are not checked at createHold", () => {
  const fx = effectGate();
  const cases = [["unknown-to", transfer({ toAccount: "acct-example-99" })], ["unknown-from", transfer({ fromAccount: "acct-example-98" })]] as const;
  for (const [chain, params] of cases) {
    const created = createTransfer(fx, chain, params);
    assert.equal(created.status, 201, "no account oracle before a human approved anything");
    const holdId = holdIdOf(created);
    assert.equal(fx.engine.decide(holdId, body(decisionFor(fx, holdId))).status, 200);
    const r = fx.engine.commit(holdId, fx.agent);
    assert.equal(balanceTotal(fx.owner!), 1050, `consequence (${chain}): nothing is minted or lost`);
    assert.deepEqual({ ...balances(fx) }, { ...DEFAULT_ACCOUNTS }, `consequence (${chain}): no balance changes`);
    assert.equal(r.status, 409);
    assert.equal(errorOf(r), "LEDGER_ACCOUNT_UNKNOWN");
    assert.equal(bodyOf(r)["outcome"], "REFUSED");
  }
});

// ── other outcomes ────────────────────────────────────────────────────────────────────────────────

test("a denied hold and an expired hold commit nothing; two holds with the same tuple and salt are two rows", () => {
  const fx = effectGate();
  const denied = holdIdOf(createTransfer(fx, "denied"));
  assert.equal(fx.engine.decide(denied, body(decisionFor(fx, denied, "DENY"))).status, 200);
  const d = fx.engine.commit(denied, fx.agent);
  assert.equal(d.status, 409);
  assert.deepEqual(bodyOf(d), { error: "HOLD_NOT_APPROVED", status: "DENIED", retryable: false });

  const pending = holdIdOf(createTransfer(fx, "pending"));
  const p = fx.engine.commit(pending, fx.agent);
  assert.deepEqual(bodyOf(p), { error: "HOLD_NOT_APPROVED", status: "PENDING", retryable: true }, "retryable only while PENDING");
  fx.clock.advance(16 * MIN);
  const e = fx.engine.commit(pending, fx.agent);
  assert.deepEqual(bodyOf(e), { error: "HOLD_NOT_APPROVED", status: "EXPIRED", retryable: false });
  assert.equal(rowCount(fx.owner), 0);

  // paramsHash is not a de-duplication key: identical tuples, identical salt, two approvals, two rows.
  const one = approvedTransfer(fx, "dup-1");
  const two = approvedTransfer(fx, "dup-2");
  assert.equal(hold(fx, one).action.paramsHash, hold(fx, two).action.paramsHash);
  assert.equal(fx.engine.commit(one, fx.agent).status, 200);
  assert.equal(fx.engine.commit(two, fx.agent).status, 200);
  assert.equal(rowCount(fx.owner), 2);
  assert.equal(balances(fx)[ACCT_1], 800);
});

test("re-pointing hold.grantId after a commit gets 409 EFFECT_AUTHORITY_CONSUMED, not a second row", () => {
  const fx = effectGate();
  const holdId = approvedTransfer(fx, "repoint");
  assert.equal(fx.engine.commit(holdId, fx.agent).status, 200);
  const h = hold(fx, holdId);
  const second = signedGrant(fx, holdId, gateKey(fx.world));
  plantApproved(fx, holdId, { decisionArtifact: h.decisionArtifact!, receipt: h.decisionReceipt!, grant: second });
  const r = fx.engine.commit(holdId, fx.agent);
  assert.equal(rowCount(fx.owner), 1, "consequence: one approval, one row");
  assert.equal(r.status, 409);
  assert.equal(errorOf(r), "EFFECT_AUTHORITY_CONSUMED");
});

test("createHold negatives for a transfer: a caller paramsHash, mode RAW and a caller display are refused; riskClass LOW cannot lower the signed HIGH", () => {
  const fx = effectGate();
  const hash = fx.engine.createHold(fx.agent, "idem-neg-hash", transferRequest("neg-hash", transfer(), { paramsHash: "sha256:" + "a".repeat(64) }));
  assert.equal(errorOf(hash), "PARAMS_HASH_NOT_CALLER_SUPPLIED");
  const raw = fx.engine.createHold(fx.agent, "idem-neg-raw", transferRequest("neg-raw", transfer(), {}, { mode: "RAW" }));
  assert.equal(errorOf(raw), "MODE_NOT_CALLER_SELECTABLE");
  const display = fx.engine.createHold(fx.agent, "idem-neg-display", transferRequest("neg-display", transfer(), {}, { encryptedDisplay: { spec: "noa.encrypted-display/0.1" } }));
  assert.equal(errorOf(display), "DISPLAY_NOT_CALLER_SUPPLIED");
  assert.equal(fx.store.listHolds({}).length, 0);
  const low = fx.engine.createHold(fx.agent, "idem-neg-low", transferRequest("neg-low", transfer(), { riskClass: "LOW" }));
  assert.equal(low.status, 201);
  const h = hold(fx, holdIdOf(low));
  assert.equal(h.action.riskClass, "HIGH");
  assert.equal(h.deferredReceipt.action.riskClass, "HIGH", "the signed riskClass stays at the gate's floor");
});

test("a signer failure at commit writes nothing and is retryable; the retry commits once", () => {
  const fx = effectGate();
  const holdId = approvedTransfer(fx, "signer-down");
  fx.signer.failAttestations = 1;
  const r = fx.engine.commit(holdId, fx.agent);
  assert.equal(rowCount(fx.owner), 0);
  assert.equal(balances(fx)[ACCT_1], 1000);
  assert.equal(r.status, 503);
  assert.equal(errorOf(r), "EFFECT_SIGNER_UNAVAILABLE");
  assert.equal(bodyOf(r)["retryable"], true);
  assert.equal(fx.engine.commit(holdId, fx.agent).status, 200);
  assert.equal(rowCount(fx.owner), 1);
});

test("the grant mirror is not the record: a store whose report lock throws once still answers 200, and the retry replays one row", () => {
  const store = new FlakyReportStore();
  const logged: string[] = [];
  const fx = effectGate({ store, log: (event) => { logged.push(event); } });
  const holdId = approvedTransfer(fx, "mirror");
  const first = fx.engine.commit(holdId, fx.agent);
  assert.equal(first.status, 200, JSON.stringify(first.body));
  assert.ok(logged.includes("effect.grant_mirror_failed"));
  assert.equal(grantOf(fx, holdId).status, "UNUSED", "the mirror failed; the row is still the record");
  // reserve and report still refuse, whatever the grant record says.
  assert.equal(fx.engine.reserve(grantOf(fx, holdId).grant.grantId, fx.agent).status, 409);
  const again = fx.engine.commit(holdId, fx.agent);
  assert.equal(again.status, 200);
  assert.equal(bodyOf(again)["idempotent"], true);
  assert.equal(rowCount(fx.owner), 1);
});

// ── the commit route over HTTP ────────────────────────────────────────────────────────────────────

test("32 parallel HTTP commits of one hold: one row, 32 × 200 with one effectId, exactly one idempotent:false, one attestation", async () => {
  const world = newWorld();
  const clock = makeClock();
  const built: { gate?: Gate } = {};
  const fx = effectGate({
    world,
    clock,
    makeEngine: (deps) => {
      built.gate = createGate({
        trust: deps.trust,
        store: deps.store,
        ...(deps.sealDisplay ? { sealDisplay: deps.sealDisplay } : {}),
        ...(deps.executionSigner ? { executionSigner: deps.executionSigner } : {}),
        effectOwners: deps.effectOwners ?? [],
        config: { bindAddress: "127.0.0.1", port: 0, now: () => clock.t, rateLimitBurst: 200, peerRateLimitBurst: 1000 },
      });
      return built.gate.engine;
    },
  });
  const gate = built.gate!;
  const { port } = await gate.listen();
  try {
    const base = `http://127.0.0.1:${port}`;
    const auth = { authorization: `Bearer ${AGENT_1_SECRET}` };
    const holdId = approvedTransfer(fx, "http");
    const signed = fx.signer.counts.attestation;
    const results = await Promise.all(Array.from({ length: 32 }, () =>
      fetch(`${base}/v1/holds/${holdId}/commit`, { method: "POST", headers: auth }).then(async (res) => ({ status: res.status, body: await res.json() as Record<string, unknown> }))));
    assert.equal(rowCount(fx.owner), 1, "consequence: one approval, one row");
    assert.equal(fx.signer.counts.attestation - signed, 1, "one attestation across all 32 commits");
    assert.deepEqual(results.map((r) => r.status), Array.from({ length: 32 }, () => 200));
    assert.equal(new Set(results.map((r) => r.body["effectId"])).size, 1);
    assert.equal(results.filter((r) => r.body["idempotent"] === false).length, 1);
    // No body is read: a body is ignored, and a foreign agent's key gets the absent-hold 404.
    const foreign = await fetch(`${base}/v1/holds/${holdId}/commit`, { method: "POST", headers: { authorization: "Bearer noa_gateagent_example_2" } });
    assert.equal(foreign.status, 404);
    const unauthenticated = await fetch(`${base}/v1/holds/${holdId}/commit`, { method: "POST" });
    assert.equal(unauthenticated.status, 401);
  } finally {
    await gate.close();
  }
});

test("commit refuses a non-effect-owned hold (409 ACTION_NOT_EFFECT_OWNED) and a missing owner (503)", () => {
  const fx = effectGate();
  const cmd = holdIdOf(fx.engine.createHold(fx.agent, "idem-cmd", body({
    mode: "ENFORCED",
    action: { canonical: "noa.command.exec", riskClass: "HIGH", reversible: false },
    params: sampleCommandParams(),
    chain: "cmd",
  })));
  const r = fx.engine.commit(cmd, fx.agent);
  assert.equal(r.status, 409);
  assert.equal(errorOf(r), "ACTION_NOT_EFFECT_OWNED");
  // An engine on the same trust and store with no owner configured cannot commit the transfer.
  const holdId = approvedTransfer(fx, "ownerless-commit");
  const ownerless = new GateEngine({
    store: fx.store,
    config: resolveGateConfig({ now: () => fx.clock.t }),
    trust: fx.trust,
    schemas: loadSchemas(),
    executionSigner: countingSigner(fx.trust),
  });
  const n = ownerless.commit(holdId, fx.agent);
  assert.equal(rowCount(fx.owner), 0);
  assert.equal(n.status, 503);
  assert.equal(errorOf(n), "EFFECT_OWNER_UNCONFIGURED");
  assert.equal(hold(fx, holdId).action.canonical, LEDGER_TRANSFER_CANONICAL);
});

// ── precedence: one assertion per adjacent pair of each order ────────────────────────────────────

/** Two boots of one gate on one store with a roster that expires 20 minutes in. */
function shortRosterPair(): { a: EffectGate; b: EffectGate; t0: number } {
  const world = newWorld();
  const clock = makeClock();
  const store = new InMemoryStore();
  const roster = rosterDoc(world, clock.t, { expiresAt: new Date(clock.t + 20 * MIN).toISOString() });
  const a = effectGate({ world, clock, store, roster, ids: idSource("short-a") });
  const b = effectGate({ world, clock, store, roster, ids: idSource("short-b") });
  return { a, b, t0: clock.t };
}

function ownerless(fx: EffectGate, trust = fx.trust): GateEngine {
  return new GateEngine({
    store: fx.store,
    config: resolveGateConfig({ now: () => fx.clock.t }),
    trust,
    schemas: loadSchemas(),
    executionSigner: countingSigner(trust),
  });
}

function commandHold(fx: EffectGate, chain: string): string {
  return holdIdOf(fx.engine.createHold(fx.agent, `idem-${chain}`, body({
    mode: "ENFORCED",
    action: { canonical: "noa.command.exec", riskClass: "HIGH", reversible: false },
    params: sampleCommandParams(),
    chain,
  })));
}

test("precedence — the commit order, pair by pair: 1<2<3<4<5<6<7<8<9<owner", () => {
  // 1 ownership before 2 effect-owned: a foreign agent on a command hold gets the absent-hold 404.
  const fx = effectGate();
  const cmd = commandHold(fx, "p12");
  assert.equal(errorOf(fx.engine.commit(cmd, fx.other)), "UNKNOWN_HOLD");
  // 2 effect-owned before 3 owner configured.
  assert.equal(errorOf(ownerless(fx).commit(cmd, fx.agent)), "ACTION_NOT_EFFECT_OWNED");
  // 3 owner configured before 4 replay: an owner-less engine does not answer from another engine's row.
  const committed = approvedTransfer(fx, "p34");
  assert.equal(fx.engine.commit(committed, fx.agent).status, 200);
  assert.equal(errorOf(ownerless(fx).commit(committed, fx.agent)), "EFFECT_OWNER_UNCONFIGURED");
  // 4 replay before 5 status: a row answers even when the stored status no longer says APPROVED.
  const h = hold(fx, committed);
  h.status = "DENIED";
  fx.store.putHold(h);
  const replay = fx.engine.commit(committed, fx.agent);
  assert.equal(replay.status, 200);
  assert.equal(bodyOf(replay)["idempotent"], true);
  // 5 status before 6 completeness: a PENDING hold has no grant yet.
  const pending = holdIdOf(createTransfer(fx, "p56"));
  assert.deepEqual(bodyOf(fx.engine.commit(pending, fx.agent)), { error: "HOLD_NOT_APPROVED", status: "PENDING", retryable: true });
  // 6 completeness before 7 grant state.
  const incomplete = approvedTransfer(fx, "p67");
  assert.ok(fx.store.claimGrantStatus(grantOf(fx, incomplete).grant.grantId, "UNUSED", "RESERVED", fx.clock.t));
  const hi = hold(fx, incomplete);
  hi.canonicalParams = null;
  fx.store.putHold(hi);
  assert.equal(errorOf(fx.engine.commit(incomplete, fx.agent)), "HOLD_STATE_INVALID");

  const { a, b, t0 } = shortRosterPair();
  // 7 grant state before 8 trust-root binding: a RESERVED grant after the roster expired.
  const reserved = approvedTransfer(a, "p78");
  assert.ok(a.store.claimGrantStatus(grantOf(a, reserved).grant.grantId, "UNUSED", "RESERVED", a.clock.t));
  // 9 before the owner: a restarted gate refuses a planted forged grant as a dead boot.
  const forgedHold = holdIdOf(createTransfer(a, "p9o"));
  const decision = decisionFor(a, forgedHold);
  plantApproved(a, forgedHold, { decisionArtifact: decision.decisionArtifact, receipt: decision.receipt, grant: signedGrant(a, forgedHold, { kid: a.world.gate.kid, privateKey: approverKeys(8).ed.privateKey }, {}, decision.receipt) });
  assert.equal(errorOf(b.engine.commit(forgedHold, b.agent)), "HOLD_FROM_DEAD_BOOT");
  const deadBoot = approvedTransfer(a, "p89");
  a.clock.t = t0 + 21 * MIN;
  assert.equal(errorOf(a.engine.commit(reserved, a.agent)), "GRANT_NOT_UNUSED");
  // 8 trust-root binding before 9 boot: the roster expired and the hold is from another boot.
  const r89 = b.engine.commit(deadBoot, b.agent);
  assert.equal(r89.status, 503);
  assert.deepEqual(bodyOf(r89)["error"], "ROSTER_EXPIRED");
  assert.equal(bodyOf(r89)["retryable"], false);
  assert.equal(rowCount(a.owner) + rowCount(b.owner), 0);
});

test("precedence — decide: the roster class check before the boot check, the boot check before the body parse", () => {
  const world = newWorld();
  const clock = makeClock();
  const store = new InMemoryStore();
  const a = effectGate({ world, clock, store, ids: idSource("dec-a") });
  // Same gate key and epoch; this boot's roster names no quorum for HIGH.
  const narrowed = effectGate({ world, clock, store, ids: idSource("dec-b"), roster: rosterDoc(world, clock.t, { quorum: { CRITICAL: 1 } }) });
  const same = effectGate({ world, clock, store, ids: idSource("dec-c"), roster: rosterDoc(world, clock.t) });
  const holdId = holdIdOf(createTransfer(a, "dec"));
  assert.equal(errorOf(narrowed.engine.decide(holdId, body(decisionFor(a, holdId)))), "RISK_CLASS_NOT_IN_ROSTER");
  assert.equal(errorOf(same.engine.decide(holdId, new TextEncoder().encode("not json"))), "HOLD_FROM_DEAD_BOOT");
  assert.equal(store.listGrants().length, 0);
});

test("precedence — reserve and report: ownership, then the trust-root binding (report), then the effect-owned refusal, then status or body", () => {
  const fx = effectGate();
  const holdId = approvedTransfer(fx, "rr");
  const grantId = grantOf(fx, holdId).grant.grantId;
  assert.equal(errorOf(fx.engine.reserve(grantId, fx.other)), "UNKNOWN_GRANT", "reserve: ownership first");
  assert.equal(errorOf(fx.engine.report(grantId, body({ result: "DISPATCHED" }), fx.other)), "UNKNOWN_GRANT", "report: ownership first");
  const h = hold(fx, holdId);
  h.status = "DENIED";
  fx.store.putHold(h);
  assert.equal(errorOf(fx.engine.reserve(grantId, fx.agent)), "EFFECT_OWNED_ACTION_NOT_RESERVABLE", "reserve: the effect-owned refusal before HOLD_NOT_APPROVED");
  assert.equal(errorOf(fx.engine.report(grantId, new TextEncoder().encode("not json"), fx.agent)), "EFFECT_OWNED_ACTION_NOT_REPORTABLE", "report: the effect-owned refusal before the body parse");
  // A gate for another tenant on the same store: the binding check answers before the effect-owned one.
  const foreign = effectGate({ world: fx.world, clock: fx.clock, store: fx.store, ids: idSource("rr-foreign"), roster: rosterDoc(fx.world, fx.clock.t, { tenant: "tenant-example-2" }) });
  assert.equal(errorOf(foreign.engine.report(grantId, body({ result: "DISPATCHED" }), fx.agent)), "GATE_AUDIENCE_MISMATCH");
  assert.equal(grantOf(fx, holdId).status, "UNUSED");
});

test("precedence — createHold: the roster before the reversible refusal, that before the owner check, that before the ledger check", () => {
  const world = newWorld();
  const clock = makeClock();
  const expiring = effectGate({ world, clock, roster: rosterDoc(world, clock.t, { expiresAt: new Date(clock.t + MIN).toISOString() }) });
  clock.advance(2 * MIN);
  assert.equal(errorOf(expiring.engine.createHold(expiring.agent, "idem-c1", transferRequest("c1", transfer(), { reversible: false }))), "ROSTER_EXPIRED");
  const none = effectGate({ owner: false });
  assert.equal(errorOf(none.engine.createHold(none.agent, "idem-c2", transferRequest("c2", transfer({ ledger: OTHER_LEDGER }), { reversible: false }))), "REVERSIBLE_NOT_CALLER_SUPPLIED");
  assert.equal(errorOf(none.engine.createHold(none.agent, "idem-c3", transferRequest("c3", transfer({ ledger: OTHER_LEDGER })))), "EFFECT_OWNER_UNCONFIGURED");
  assert.equal(expiring.store.listHolds({}).length + none.store.listHolds({}).length, 0);
});

// ── regression attacks: each test fails on the tree it was written against ───────────────────────

function hash999(): string {
  const r = projectLedgerTransfer(canonicalOf(transfer({ amount: "999" })));
  assert.ok(r.ok);
  return r.paramsHash;
}

test("EFFECT-SEAL-VERIFIED-COPY — the gate signs the action and scope the owner verified, never a later read of mutable store state", () => {
  const fx = effectGate();
  const holdId = approvedTransfer(fx, "verified-copy");
  const h = hold(fx, holdId);
  const deferred = h.deferredReceipt;
  const honest = deferred.action;
  const fake = { ...honest, paramsHash: hash999(), riskClass: "LOW", reversible: true };
  let reads = 0;
  const { action: _action, ...rest } = deferred as unknown as Record<string, unknown>;
  const twoFaced: Record<string, unknown> = { ...rest };
  Object.defineProperty(twoFaced, "action", { enumerable: true, get() { reads++; return reads === 1 ? honest : fake; } });
  h.deferredReceipt = twoFaced as unknown as Receipt;
  h.chain = "rewritten-chain";
  h.tenant = "tenant-example-9";
  fx.store.putHold(h);
  const r = fx.engine.commit(holdId, fx.agent);
  const executed = bodyOf(r)["executedReceipt"] as { action?: Record<string, unknown>; scope?: Record<string, unknown> } | null;
  const row = fx.owner!.inspect().rows[0];
  assert.equal(executed?.action?.["paramsHash"], row?.paramsHash, "consequence: the gate-signed receipt names the amount that moved");
  assert.equal(executed?.action?.["riskClass"], "HIGH", "consequence: the signed risk class is the verified one");
  assert.equal(executed?.action?.["reversible"], false, "consequence: the signed reversible flag is the verified one");
  assert.deepEqual({ ...executed?.scope }, { ...deferred.scope }, "consequence: the signed scope is the approved chain's");
  const chain = verifyChain(encodeDocument([deferred, h.decisionReceipt, executed]), { keyring: encodeDocument(fx.trust.receiptKeyring), requireTenantConsistency: true });
  assert.equal(chain.status, "VALID", JSON.stringify(chain));
  assert.equal(r.status, 200, JSON.stringify(r.body));
});

test("EFFECT-RECEIPT-SIGNATURES — deferred and approval receipts whose signatures do not verify commit nothing and get nothing signed", () => {
  const fx = effectGate();
  const holdId = approvedTransfer(fx, "receipt-signatures");
  const h = hold(fx, holdId);
  const unsigned = (r: Receipt): Receipt => ({ ...r, sig: { ...r.sig, value: "AA==" } }) as Receipt;
  h.deferredReceipt = unsigned(h.deferredReceipt);
  h.decisionReceipt = unsigned(h.decisionReceipt!);
  h.verdictReceipt = h.decisionReceipt;
  fx.store.putHold(h);
  const signed = fx.signer.counts.attestation;
  const r = fx.engine.commit(holdId, fx.agent);
  assert.equal(fx.signer.counts.attestation, signed, "consequence: nothing is signed over receipts that do not verify");
  assert.equal(rowCount(fx.owner), 0, "consequence: no row");
  assert.equal(balances(fx)[ACCT_1], 1000, "consequence: nothing moved");
  assert.equal(r.status, 500, JSON.stringify(r.body));
  assert.equal(errorOf(r), "COMMIT_AUTHORITY_INVALID");
});

test("EFFECT-APPROVAL-VERDICT — an approval receipt whose verdict is BLOCKED authorizes nothing, whatever the decision says", () => {
  const fx = effectGate();
  const holdId = holdIdOf(createTransfer(fx, "verdict"));
  const approve = decisionFor(fx, holdId);
  const x = fx.world.approver;
  const blocked = approvalReceiptBy(fx, holdId, { kid: x.kid, privateKey: x.ed.privateKey }, { by: x.kid, verdict: "BLOCKED" });
  plantApproved(fx, holdId, { decisionArtifact: approve.decisionArtifact, receipt: blocked, grant: signedGrant(fx, holdId, gateKey(fx.world), {}, blocked) });
  const signed = fx.signer.counts.attestation;
  const r = fx.engine.commit(holdId, fx.agent);
  assert.equal(rowCount(fx.owner), 0, "consequence: a BLOCKED verdict moves nothing");
  assert.equal(balances(fx)[ACCT_1], 1000);
  assert.equal(fx.signer.counts.attestation, signed, "consequence: nothing is signed");
  assert.equal(r.status, 500, JSON.stringify(r.body));
});

test("EFFECT-APPROVER-IDENTITY — an approval receipt the deciding approver did not sign authorizes nothing", () => {
  const fx = effectGate();
  const holdId = holdIdOf(createTransfer(fx, "approver-identity"));
  const approve = decisionFor(fx, holdId);
  const gateSigned = approvalReceiptBy(fx, holdId, gateKey(fx.world), { by: fx.world.approver.kid, verdict: "ALLOWED" });
  plantApproved(fx, holdId, { decisionArtifact: approve.decisionArtifact, receipt: gateSigned, grant: signedGrant(fx, holdId, gateKey(fx.world), {}, gateSigned) });
  const signed = fx.signer.counts.attestation;
  const r = fx.engine.commit(holdId, fx.agent);
  assert.equal(rowCount(fx.owner), 0, "consequence: approval evidence the approver did not sign moves nothing");
  assert.equal(balances(fx)[ACCT_1], 1000);
  assert.equal(fx.signer.counts.attestation, signed, "consequence: nothing is signed");
  assert.equal(r.status, 500, JSON.stringify(r.body));
});

test("EFFECT-DECISION-DENY — a DENY decision with an ALLOWED receipt and a gate-key grant commits nothing", () => {
  const fx = effectGate();
  const holdId = holdIdOf(createTransfer(fx, "decision-deny"));
  const approve = decisionFor(fx, holdId);
  const deny = decisionFor(fx, holdId, "DENY");
  plantApproved(fx, holdId, { decisionArtifact: deny.decisionArtifact, receipt: approve.receipt, grant: signedGrant(fx, holdId, gateKey(fx.world), {}, approve.receipt) });
  const r = fx.engine.commit(holdId, fx.agent);
  assert.equal(rowCount(fx.owner), 0, "consequence: a denial moves nothing");
  assert.equal(balances(fx)[ACCT_1], 1000);
  assert.equal(r.status, 500, JSON.stringify(r.body));
  assert.equal(bodyOf(r)["detail"], "decision-not-approve");
});


test("EFFECT-TWO-ENGINES — a second effect-owning engine over the same trust root is refused, so a failed grant mirror cannot yield two effects", () => {
  const store = new FlakyReportStore();
  const fx = effectGate({ store });
  const second = createInMemoryLedgerEffectOwner({ trust: fx.trust, now: () => fx.clock.t, ledger: LEDGER, accounts: DEFAULT_ACCOUNTS });
  let engine2: GateEngine | null = null;
  let refusal: unknown = null;
  try {
    engine2 = new GateEngine({
      store,
      config: resolveGateConfig({ now: () => fx.clock.t }),
      trust: fx.trust,
      schemas: loadSchemas(),
      executionSigner: countingSigner(fx.trust),
      effectOwners: [second],
    });
  } catch (e) {
    refusal = e;
  }
  const holdId = approvedTransfer(fx, "two-engines");
  assert.equal(fx.engine.commit(holdId, fx.agent).status, 200);
  if (engine2 !== null) engine2.commit(holdId, fx.agent);
  assert.equal(rowCount(fx.owner) + rowCount(second), 1, "consequence: one approval, one effect across every engine on this trust root");
  assert.match(String(refusal), /EFFECT_OWNER_TRUST_IN_USE/);
});

// ── engine-path attacks on the held action and the boot (each fails on the tree it was written against) ──

test("EFFECT-APPROVAL-ACTION — an approval receipt whose action is not the held one (decide refuses it) is not committed either", () => {
  const fx = effectGate();
  const holdId = holdIdOf(createTransfer(fx, "approval-action"));
  const x = fx.world.approver;
  const approve = decisionFor(fx, holdId);
  const drifted = approvalReceiptBy(fx, holdId, { kid: x.kid, privateKey: x.ed.privateKey }, { by: x.kid, verdict: "ALLOWED", action: { riskClass: "LOW", reversible: true } });
  // decide refuses exactly this receipt.
  const probe = holdIdOf(createTransfer(fx, "approval-action-probe"));
  const probeApprove = decisionFor(fx, probe);
  const probeDrifted = approvalReceiptBy(fx, probe, { kid: x.kid, privateKey: x.ed.privateKey }, { by: x.kid, verdict: "ALLOWED", action: { riskClass: "LOW", reversible: true } });
  const decided = fx.engine.decide(probe, body({ receipt: probeDrifted, decisionArtifact: probeApprove.decisionArtifact }));
  assert.equal(errorOf(decided), "ACTION_BINDING_MISMATCH");
  plantApproved(fx, holdId, { decisionArtifact: approve.decisionArtifact, receipt: drifted, grant: signedGrant(fx, holdId, gateKey(fx.world), {}, drifted) });
  const r = fx.engine.commit(holdId, fx.agent);
  assert.equal(rowCount(fx.owner), 0, "consequence: an approval of another action moves nothing");
  assert.equal(balances(fx)[ACCT_1], 1000);
  assert.equal(r.status, 500, JSON.stringify(r.body));
});

test("EFFECT-TWO-ENGINES-COPY — a copy of the trust root does not let a second effect-owning engine commit the same approval", () => {
  const store = new FlakyReportStore();
  const fx = effectGate({ store });
  const copy = { ...fx.trust };
  const second = createInMemoryLedgerEffectOwner({ trust: copy, now: () => fx.clock.t, ledger: LEDGER, accounts: DEFAULT_ACCOUNTS });
  let engine2: GateEngine | null = null;
  let refusal: unknown = null;
  try {
    engine2 = new GateEngine({
      store,
      config: resolveGateConfig({ now: () => fx.clock.t }),
      trust: copy,
      schemas: loadSchemas(),
      executionSigner: countingSigner(copy),
      effectOwners: [second],
    });
  } catch (e) {
    refusal = e;
  }
  const holdId = approvedTransfer(fx, "two-engines-copy");
  assert.equal(fx.engine.commit(holdId, fx.agent).status, 200);
  if (engine2 !== null) engine2.commit(holdId, fx.agent);
  assert.equal(rowCount(fx.owner) + rowCount(second), 1, "consequence: one approval, one effect across every engine on this boot");
  assert.match(String(refusal), /EFFECT_OWNER_TRUST_IN_USE/);
});
