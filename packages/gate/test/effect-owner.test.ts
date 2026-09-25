/**
 * The in-process effect owner on its own (docs/gate-effect-owner.md, `src/effect-owner.ts`).
 *
 * The owner is called DIRECTLY here, the way a hostile caller of its commit API could call it: with
 * hostile input objects (getters, throwing members, forged or re-signed artifacts) and a hostile sealer
 * (NON-CLAIMS.md NC-S9.11). The caller supplies no authority of its own, so the owner reads its input
 * once and re-verifies every signed byte itself; its own code is trusted. Every attack test asserts the
 * consequence (rows, balances, seal calls) before any code.
 *
 * Proof ID referenced by scripts/resolver-inventory.json — do not rename without updating it:
 *   [PROOF:RES-PAR-GATE-EFFECT-OWNER]
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { refHash, signArtifact } from "noa-approval-artifacts";
import { GateEngine } from "../src/engine.js";
import { resolveGateConfig } from "../src/config.js";
import { loadSchemas } from "../src/schemas.js";
import { InMemoryStore } from "../src/store.js";
import { buildEffectAttestation, createInMemoryLedgerEffectOwner, type EffectAttestation, type EffectCommitInput, type EffectOutcome, type EffectOwner, type VerifiedAuthority } from "../src/effect-owner.js";
import { buildDeferredReceipt } from "../src/receipts.js";
import { buildConsumption } from "../src/grants.js";
import { buildReceipt, projectLedgerTransfer } from "noa-receipt";
import { getProjection } from "../src/projections.js";
import type { HoldEnvelope, Receipt } from "../src/types.js";
import { body, makeClock, setupGate, signPhoneDecision, testSealer } from "./helpers.js";
import { approverKeys, newWorld, rosterDoc } from "./helpers/pinned.js";
import { b } from "./helpers/bytes.js";
import {
  ACCT_1,
  ACCT_2,
  DEFAULT_ACCOUNTS,
  HOUR,
  LEDGER,
  MIN,
  OTHER_LEDGER,
  approvalReceiptBy,
  approvedTransfer,
  balanceTotal,
  canonicalOf,
  createTransfer,
  decisionFor,
  effectGate,
  extendEnvelope,
  gateKey,
  grantOf,
  hold,
  holdIdOf,
  idSource,
  ownerInput,
  ownerOn,
  plantApproved,
  sealerFor,
  rowCount,
  signedGrant,
  transfer,
  transferRequest,
} from "./helpers/effect.js";

const codeOf = (o: EffectOutcome): string => (o.kind === "NOT_COMMITTED" ? o.code : o.kind === "REFUSED" ? `REFUSED:${o.row.refusalCode}` : o.kind);
const detailOf = (o: EffectOutcome): string | null => (o.kind === "NOT_COMMITTED" ? o.detail : null);

// ── construction ─────────────────────────────────────────────────────────────────────────────────

test("EFFECT-OWNER-REQUIRES-PINNED — under alpha trust no owner exists, so a decision signed with the approver key on the gate's heap commits nothing", () => {
  const fx = setupGate();
  let owner: EffectOwner | null = null;
  let refusal: unknown = null;
  try {
    owner = createInMemoryLedgerEffectOwner({ trust: fx.trust, now: () => fx.clock.t, ledger: LEDGER, accounts: { [ACCT_1]: 1000, [ACCT_2]: 0 } });
  } catch (e) {
    refusal = e;
  }
  // If an owner could be built, run the attack end to end: alpha trust, the heap-held approver key.
  let rows = 0;
  if (owner !== null) {
    const engine = new GateEngine({
      store: fx.store,
      config: resolveGateConfig({ now: () => fx.clock.t }),
      trust: fx.trust,
      schemas: loadSchemas(),
      sealDisplay: testSealer,
      unsafeInProcessGrantKey: true,
      effectOwners: [owner],
    });
    const created = engine.createHold(fx.agent, "idem-alpha", transferRequest("alpha"));
    if (created.status === 201) {
      const holdId = (created.body as { holdId: string }).holdId;
      const h = fx.store.getHold(holdId)!;
      engine.decide(holdId, body(signPhoneDecision({ trust: fx.trust, deferredReceipt: h.deferredReceipt, holdEnvelope: h.holdEnvelope, decision: "APPROVE" })));
      engine.commit(holdId, fx.agent);
    }
    rows = owner.inspect().rows.length;
  }
  assert.equal(rows, 0, "consequence: nothing is committed on an alpha trust root");
  assert.match(String(refusal), /EFFECT_OWNER_REQUIRES_PINNED_TRUST/);
  // The engine applies the same rule to an owner built elsewhere.
  const pinned = effectGate();
  assert.throws(() => new GateEngine({
    store: new InMemoryStore(),
    config: resolveGateConfig({ now: () => fx.clock.t }),
    trust: fx.trust,
    schemas: loadSchemas(),
    unsafeInProcessGrantKey: true,
    effectOwners: [pinned.owner!],
  }), /EFFECT_OWNER_REQUIRES_PINNED_TRUST/);
});

test("construction hygiene — invalid ledger, account or balance; an owner of another trust root; two owners for one canonical; a non-effect-owned canonical", () => {
  const fx = effectGate();
  const build = (ledger: string, accounts: Record<string, number>) => () =>
    createInMemoryLedgerEffectOwner({ trust: fx.trust, now: () => fx.clock.t, ledger, accounts });
  assert.throws(build("Ledger-1", {}), /EFFECT_OWNER_LEDGER_INVALID/);
  assert.throws(build(LEDGER, { "ACCT-1": 1 }), /EFFECT_OWNER_LEDGER_INVALID/);
  assert.throws(build(LEDGER, { [ACCT_1]: -1 }), /EFFECT_OWNER_LEDGER_INVALID/);
  assert.throws(build(LEDGER, { [ACCT_1]: 1.5 }), /EFFECT_OWNER_LEDGER_INVALID/);
  assert.throws(build(LEDGER, { [ACCT_1]: Number.MAX_SAFE_INTEGER, [ACCT_2]: 1 }), /EFFECT_OWNER_LEDGER_INVALID/);
  assert.doesNotThrow(build(LEDGER, { [ACCT_1]: Number.MAX_SAFE_INTEGER, [ACCT_2]: 0 }));
  const engineWith = (owners: EffectOwner[]) => () => new GateEngine({
    store: new InMemoryStore(),
    config: resolveGateConfig({ now: () => fx.clock.t }),
    trust: fx.trust,
    schemas: loadSchemas(),
    executionSigner: fx.signer,
    effectOwners: owners,
  });
  const foreign = effectGate({ ids: idSource("other-boot") });
  assert.throws(engineWith([foreign.owner!]), /EFFECT_OWNER_TRUST_MISMATCH/);
  assert.throws(engineWith([fx.owner!, fx.owner!]), /EFFECT_OWNER_DUPLICATE/);
  assert.throws(engineWith([{ ...fx.owner!, canonical: "noa.command.exec" }]), /EFFECT_OWNER_CANONICAL_INVALID/);
  // One effect-owning engine per boot — a copy of the trust root is the same boot — and one engine per owner.
  const fresh = createInMemoryLedgerEffectOwner({ trust: fx.trust, now: () => fx.clock.t, ledger: LEDGER, accounts: DEFAULT_ACCOUNTS });
  assert.throws(engineWith([fresh]), /EFFECT_OWNER_TRUST_IN_USE/);
  assert.equal(fresh.bound, false, "a refused engine binds nothing");
  assert.throws(() => new GateEngine({
    store: new InMemoryStore(),
    config: resolveGateConfig({ now: () => fx.clock.t }),
    trust: { ...fx.trust },
    schemas: loadSchemas(),
    executionSigner: fx.signer,
    effectOwners: [fx.owner!],
  }), /EFFECT_OWNER_TRUST_IN_USE/);
  assert.equal(fx.owner!.bound, true);
  // An owner whose bindEngine throws leaves its boot usable: the boot is reserved only after binding.
  const spare = effectGate({ owner: false, ids: idSource("bind-throws") });
  const real = createInMemoryLedgerEffectOwner({ trust: spare.trust, now: () => spare.clock.t, ledger: LEDGER, accounts: DEFAULT_ACCOUNTS });
  const throwing: EffectOwner = { ...real, bound: false, bindEngine() { throw new Error("test: bind refused"); } };
  const buildEngine = (owner: EffectOwner) => () => new GateEngine({
    store: new InMemoryStore(),
    config: resolveGateConfig({ now: () => spare.clock.t }),
    trust: spare.trust,
    schemas: loadSchemas(),
    executionSigner: spare.signer,
    effectOwners: [owner],
  });
  assert.throws(buildEngine(throwing), /bind refused/);
  assert.doesNotThrow(buildEngine(real), "the boot is still free for an owner that binds");
});

// ── uniqueness ────────────────────────────────────────────────────────────────────────────────────

test("EFFECT-OWNER-UNIQUE — 32 identical direct commits write one row and seal once", () => {
  const fx = effectGate();
  const holdId = approvedTransfer(fx, "e3u", transfer({ amount: "1" }));
  const input = ownerInput(fx, holdId);
  const sealer = sealerFor(fx);
  const outcomes = Array.from({ length: 32 }, () => fx.owner!.commit(input, sealer.seal));
  assert.equal(rowCount(fx.owner), 1, "consequence: one authority, one row");
  assert.equal(fx.owner!.inspect().balances[ACCT_1], 999, "consequence: the amount moved once");
  assert.equal(sealer.calls.length, 1, "consequence: one authority, one signed EXECUTED receipt");
  assert.deepEqual(outcomes.map(codeOf), Array.from({ length: 32 }, () => "EXECUTED"));
  assert.equal(outcomes.filter((o) => o.kind === "EXECUTED" && o.idempotent === false).length, 1);
});

test("EFFECT-EXTRA-GRANTS — five validly signed grants for one envelope and one decision write one row; four are refused as consumed", () => {
  const fx = effectGate();
  const holdId = approvedTransfer(fx, "e4");
  const input = ownerInput(fx, holdId);
  const sealer = sealerFor(fx);
  const grants = [input.grant, ...Array.from({ length: 4 }, () => signedGrant(fx, holdId, gateKey(fx.world)))];
  assert.equal(new Set(grants.map((g) => g.grantId)).size, 5, "fixture: five distinct grant ids");
  const outcomes = grants.map((grant) => fx.owner!.commit({ ...input, grant }, sealer.seal));
  assert.equal(rowCount(fx.owner), 1, "consequence: one approval, one row, however many grants exist");
  assert.equal(fx.owner!.inspect().balances[ACCT_1], 900);
  assert.equal(sealer.calls.length, 1, "consequence: one approval, one signed EXECUTED receipt");
  assert.deepEqual(outcomes.map(codeOf), ["EXECUTED", "EFFECT_AUTHORITY_CONSUMED", "EFFECT_AUTHORITY_CONSUMED", "EFFECT_AUTHORITY_CONSUMED", "EFFECT_AUTHORITY_CONSUMED"]);
});

// ── the ledger identity ───────────────────────────────────────────────────────────────────────────

/**
 * A gate owning another ledger, and an owner of this ledger on the SAME roster and boot, with the same
 * account names: only the ledger check can tell them apart.
 */
function twoLedgers() {
  const theirs = effectGate({ ids: idSource("theirs"), ledger: OTHER_LEDGER });
  const mine = ownerOn(theirs, {}, "mine", LEDGER);
  return { mine, theirs };
}

test("EFFECT-LEDGER-ID-OWNER — an owner never writes a validly approved transfer that names another ledger", () => {
  const { mine, theirs } = twoLedgers();
  const holdId = approvedTransfer(theirs, "their-ledger", transfer({ ledger: OTHER_LEDGER }));
  const sealer = sealerFor(theirs);
  const o = mine.owner.commit(ownerInput(theirs, holdId), sealer.seal);
  assert.equal(rowCount(mine.owner), 0, "consequence: another ledger's authority moves nothing here");
  assert.equal(mine.owner.inspect().balances[ACCT_1], 1000);
  assert.equal(sealer.calls.length, 0);
  assert.equal(codeOf(o), "LEDGER_NOT_OWNED");
  // Positive control: the owner of that ledger commits it.
  assert.equal(codeOf(theirs.owner!.commit(ownerInput(theirs, holdId), sealer.seal)), "EXECUTED");
});

// ── O1: every signed byte ─────────────────────────────────────────────────────────────────────────

test("O1 — each leg refuses with its own token and writes nothing", () => {
  const fx = effectGate();
  const sealer = sealerFor(fx);
  const holdId = approvedTransfer(fx, "o1");
  const input = ownerInput(fx, holdId);
  const other = approvedTransfer(fx, "o1-other", transfer({ amount: "7" }));
  const otherInput = ownerInput(fx, other);
  const attacker = approverKeys(8).ed;
  const x = fx.world.approver;
  const env = input.holdEnvelope;
  const cmd = getProjection("noa.command.exec")!;
  const resigned = (over: Partial<HoldEnvelope>): HoldEnvelope => {
    const { sig: _sig, ...unsigned } = { ...env, ...over };
    return signArtifact(b(unsigned), "NOA-Hold-v0.1-sig", gateKey(fx.world)) as unknown as HoldEnvelope;
  };
  const denied = decisionFor(fx, holdId, "DENY");
  const unsignedApproval = { ...input.approvalReceipt, sig: { ...input.approvalReceipt.sig, value: "AA==" } } as Receipt;
  const blocked = approvalReceiptBy(fx, holdId, { kid: x.kid, privateKey: x.ed.privateKey }, { by: x.kid, verdict: "BLOCKED" });
  fx.clock.advance(1);
  const secondAllowed = approvalReceiptBy(fx, holdId, { kid: x.kid, privateKey: x.ed.privateKey }, { by: x.kid, verdict: "ALLOWED" });
  fx.clock.advance(-1);
  const gateSignedApproval = approvalReceiptBy(fx, holdId, gateKey(fx.world), { by: x.kid, verdict: "ALLOWED" });
  const fakeDisplay = { ...input.encryptedDisplay, aadHash: "sha256:" + "0".repeat(64) };
  const cases: Array<[string, Parameters<EffectOwner["commit"]>[0]]> = [
    ["envelope", { ...input, holdEnvelope: { ...env, expiresAt: new Date(Date.parse(env.expiresAt) + HOUR).toISOString() } }],
    ["deferred-binding", { ...input, deferredReceipt: otherInput.deferredReceipt }],
    ["projection-identity", { ...input, holdEnvelope: resigned({ actionSchema: cmd.actionSchema }) }],
    ["receipt-chain", { ...input, approvalReceipt: unsignedApproval }],
    ["approval-verdict", { ...input, approvalReceipt: blocked }],
    ["grant", { ...input, grant: signedGrant(fx, holdId, { kid: fx.world.gate.kid, privateKey: attacker.privateKey }) }],
    ["grant-binding:holdId", { ...input, grant: signedGrant(fx, holdId, gateKey(fx.world), { holdId: other }) }],
    ["grant-binding:holdEnvelopeHash", { ...input, grant: signedGrant(fx, holdId, gateKey(fx.world), { holdEnvelopeHash: refHash(otherInput.holdEnvelope) }) }],
    ["grant-binding:approvalReceiptHash", { ...input, approvalReceipt: secondAllowed }],
    ["grant-binding:paramsHash", { ...input, grant: signedGrant(fx, holdId, gateKey(fx.world), { paramsHash: hold(fx, other).action.paramsHash }) }],
    ["decision", { ...input, decisionArtifact: otherInput.decisionArtifact }],
    ["decision-not-approve", { ...input, decisionArtifact: denied.decisionArtifact }],
    ["approver-identity", { ...input, approvalReceipt: gateSignedApproval, grant: signedGrant(fx, holdId, gateKey(fx.world), {}, gateSignedApproval) }],
    ["display-binding", { ...input, encryptedDisplay: fakeDisplay }],
  ];
  for (const [token, attack] of cases) {
    const o = fx.owner!.commit(attack, sealer.seal);
    assert.equal(fx.owner!.inspect().balances[ACCT_1], 1000, `consequence (${token}): nothing moves`);
    assert.equal(rowCount(fx.owner), 0, `consequence (${token}): nothing is written`);
    assert.equal(codeOf(o), "COMMIT_AUTHORITY_INVALID", token);
    assert.equal(detailOf(o), token);
  }
  assert.equal(sealer.calls.length, 0, "consequence: nothing is signed for any of them");
  assert.equal(codeOf(fx.owner!.commit(input, sealer.seal)), "EXECUTED", "positive control: the real authority commits");
});

test("[PROOF:RES-PAR-GATE-EFFECT-OWNER] the owner's own keyring consume site: decisions verify only under the roster keyring, with activation at the decision's signed instant and revocation", () => {
  // (a) ACTIVATION IS EVALUATED AT THE GRANT'S SIGNED INSTANT, NEVER AT THE COMMIT CLOCK. The approver
  //     activates at t0+10min. A decision whose authorization instant (the grant's issuedAt) is t0 is
  //     refused even when the commit runs at t0+20min, after the activation, and even though the
  //     decision's own claimed time (a value its signer chooses) is after the activation too. The same
  //     decision under a grant issued after the activation commits.
  const world = newWorld();
  const clock = makeClock();
  const t0 = clock.t;
  const activation = t0 + 10 * MIN;
  const roster = rosterDoc(world, t0, {
    approvers: {
      [world.approver.kid]: { role: "approve-critical", publicKey: world.approver.ed.publicKey, hpkePublicKey: world.approver.x.publicKey, validFrom: new Date(activation).toISOString(), revokedAt: null },
    },
  });
  const fx = effectGate({ world, clock, roster });
  assert.equal(fx.trust.keyring[world.approver.kid]?.validFrom, new Date(activation).toISOString(), "carriage: the declared activation is in the keyring the owner consumes");
  const holdId = holdIdOf(fx.engine.createHold(fx.agent, "idem-activation", transferRequest("activation", transfer(), {}, { ttlMs: 60 * MIN })));
  const h = hold(fx, holdId);
  const decision = signPhoneDecision({
    trust: fx.trust,
    deferredReceipt: h.deferredReceipt,
    holdEnvelope: h.holdEnvelope,
    decision: "APPROVE",
    at: new Date(t0 + 15 * MIN).toISOString(),
    signer: { kid: world.approver.kid, privateKey: world.approver.ed.privateKey },
  });
  const early = signedGrant(fx, holdId, gateKey(world), { issuedAt: new Date(t0).toISOString(), expiresAt: new Date(t0 + 50 * MIN).toISOString() }, decision.receipt);
  plantApproved(fx, holdId, { decisionArtifact: decision.decisionArtifact, receipt: decision.receipt, grant: early });
  clock.t = t0 + 20 * MIN;
  const sealer = sealerFor(fx);
  const refused = fx.owner!.commit(ownerInput(fx, holdId), sealer.seal);
  assert.equal(rowCount(fx.owner), 0, "consequence: an authorization dated before the approver's activation moves nothing, whatever the commit clock says");
  assert.equal(detailOf(refused), "decision");
  const late = signedGrant(fx, holdId, gateKey(world), { issuedAt: new Date(t0 + 15 * MIN).toISOString(), expiresAt: new Date(t0 + 50 * MIN).toISOString() }, decision.receipt);
  plantApproved(fx, holdId, { decisionArtifact: decision.decisionArtifact, receipt: decision.receipt, grant: late });
  assert.equal(codeOf(fx.owner!.commit(ownerInput(fx, holdId), sealer.seal)), "EXECUTED", "the same decision authorized after activation commits");
  assert.equal(rowCount(fx.owner), 1);

  // (b) A revoked approver: refused whatever the instant.
  const world2 = newWorld();
  const clock2 = makeClock();
  const active = approverKeys(4);
  const roster2 = rosterDoc(world2, clock2.t, {
    approvers: {
      [world2.approver.kid]: { role: "approve-critical", publicKey: world2.approver.ed.publicKey, hpkePublicKey: world2.approver.x.publicKey, validFrom: new Date(clock2.t - 2 * HOUR).toISOString(), revokedAt: new Date(clock2.t - HOUR).toISOString() },
      [active.kid]: { role: "approve-critical", publicKey: active.ed.publicKey, hpkePublicKey: active.x.publicKey, validFrom: new Date(clock2.t - 2 * HOUR).toISOString(), revokedAt: null },
    },
  });
  const fx2 = effectGate({ world: world2, clock: clock2, roster: roster2 });
  assert.equal(fx2.trust.keyring[world2.approver.kid]?.revokedAt, new Date(clock2.t - HOUR).toISOString(), "carriage: the declared revocation is in the keyring");
  const hold2 = holdIdOf(createTransfer(fx2, "revoked"));
  const revokedDecision = decisionFor(fx2, hold2);
  plantApproved(fx2, hold2, { decisionArtifact: revokedDecision.decisionArtifact, receipt: revokedDecision.receipt, grant: signedGrant(fx2, hold2, gateKey(world2), {}, revokedDecision.receipt) });
  const r2 = fx2.owner!.commit(ownerInput(fx2, hold2), sealerFor(fx2).seal);
  assert.equal(rowCount(fx2.owner), 0, "consequence: a revoked approver's decision moves nothing");
  // Refused first by the receipt keyring's retirement of the same key.
  assert.equal(detailOf(r2), "receipt-chain");

  // (c) THE CONSUME SITE IS LOAD-BEARING: the decision verifies only under the roster keyring the owner
  //     consumes. A decision the roster approver never signed (a stranger's key under its kid), for an
  //     envelope the gate key re-signed with a later expiry, commits nothing after the approved window.
  const fx3 = effectGate();
  const hold3 = holdIdOf(createTransfer(fx3, "forged-decision-proof"));
  const genuine = decisionFor(fx3, hold3);
  const { original } = extendEnvelope(fx3, hold3, 2 * HOUR);
  const forged = decisionFor(fx3, hold3, "APPROVE", { ...approverKeys(9), kid: fx3.world.approver.kid });
  plantApproved(fx3, hold3, {
    decisionArtifact: forged.decisionArtifact,
    receipt: genuine.receipt,
    grant: signedGrant(fx3, hold3, gateKey(fx3.world), { expiresAt: new Date(Date.parse(original.expiresAt) + HOUR).toISOString() }, genuine.receipt),
  });
  fx3.clock.t = Date.parse(original.expiresAt) + MIN;
  const r3 = fx3.owner!.commit(ownerInput(fx3, hold3), sealerFor(fx3).seal);
  assert.equal(rowCount(fx3.owner), 0, "consequence: a decision the roster keyring does not verify moves nothing");
  assert.equal(fx3.owner!.inspect().balances[ACCT_1], 1000, "consequence: nothing moved");
  assert.equal(detailOf(r3), "decision");
});

// ── the order O1 … O9: one test per adjacent pair ────────────────────────────────────────────────

test("order: re-entry before the boot check, the boot check before O1", () => {
  const world = newWorld();
  const clock = makeClock();
  const store = new InMemoryStore();
  const roster = rosterDoc(world, clock.t);
  const a = effectGate({ world, clock, store, roster, ids: idSource("order-a") });
  const b = effectGate({ world, clock, store, roster, ids: idSource("order-b") });
  const holdId = approvedTransfer(a, "order-boot");
  // The boot check before O1: a pre-restart hold carrying a forged grant is refused as a dead boot.
  const forged = { ...ownerInput(a, holdId), grant: signedGrant(a, holdId, { kid: world.gate.kid, privateKey: approverKeys(8).ed.privateKey }) };
  assert.equal(codeOf(b.owner!.commit(forged, sealerFor(b).seal)), "HOLD_FROM_DEAD_BOOT");
  // Re-entry before the boot check: while a commit signs, even a dead-boot input is refused as re-entrant.
  const own = approvedTransfer(b, "order-reentry");
  const sealer = sealerFor(b);
  const inner: { outcome?: EffectOutcome } = {};
  b.owner!.commit(ownerInput(b, own), (at: number, ...rest: unknown[]) => {
    inner.outcome = b.owner!.commit(forged, sealer.seal);
    return sealer.seal(at, ...rest);
  });
  assert.equal(codeOf(inner.outcome!), "EFFECT_COMMIT_REENTRANT");
  assert.equal(rowCount(b.owner), 1);
});

test("EFFECT-ATTESTATION-MISMATCH — a validly signed attestation for another action is refused, and nothing is written", () => {
  const fx = effectGate();
  const holdId = approvedTransfer(fx, "attestation-mismatch");
  const sealer = sealerFor(fx);
  const t = transfer999();
  const o = fx.owner!.commit(ownerInput(fx, holdId), (at: number, ...rest: unknown[]) => {
    const v = rest[0] as { deferred: Record<string, unknown> };
    const action = { ...(v.deferred["action"] as Record<string, unknown>), paramsHash: t.paramsHash };
    return sealer.seal(at, { ...(rest[0] as object), deferred: { ...v.deferred, action } });
  });
  assert.equal(rowCount(fx.owner), 0, "consequence: evidence for another action is never recorded");
  assert.equal(fx.owner!.inspect().balances[ACCT_1], 1000);
  assert.equal(codeOf(o), "EFFECT_ATTESTATION_INVALID");
  assert.equal(detailOf(o), "executed-receipt-action");
});

test("order O1 before O2 — an invalid authority for an already consumed envelope is COMMIT_AUTHORITY_INVALID, not a replay", () => {
  const fx = effectGate();
  const holdId = approvedTransfer(fx, "o1o2");
  const input = ownerInput(fx, holdId);
  const sealer = sealerFor(fx);
  assert.equal(codeOf(fx.owner!.commit(input, sealer.seal)), "EXECUTED");
  const forged = signedGrant(fx, holdId, { kid: fx.world.gate.kid, privateKey: approverKeys(8).ed.privateKey });
  assert.equal(codeOf(fx.owner!.commit({ ...input, grant: forged }, sealer.seal)), "COMMIT_AUTHORITY_INVALID");
});

test("order O2 before O3 — after expiry a replay still answers with its row, and another grant is still EFFECT_AUTHORITY_CONSUMED", () => {
  const fx = effectGate();
  const holdId = approvedTransfer(fx, "o2o3");
  const input = ownerInput(fx, holdId);
  const second = signedGrant(fx, holdId, gateKey(fx.world));
  const sealer = sealerFor(fx);
  assert.equal(codeOf(fx.owner!.commit(input, sealer.seal)), "EXECUTED");
  fx.clock.advance(2 * HOUR);
  const replay = fx.owner!.commit(input, sealer.seal);
  assert.equal(codeOf(replay), "EXECUTED");
  assert.equal(replay.kind !== "NOT_COMMITTED" && replay.idempotent, true);
  assert.equal(codeOf(fx.owner!.commit({ ...input, grant: second }, sealer.seal)), "EFFECT_AUTHORITY_CONSUMED");
  assert.equal(sealer.calls.length, 1);
});

test("order O3 before O4 — an expired grant over a swapped snapshot is GRANT_EXPIRED", () => {
  const fx = effectGate();
  const holdId = approvedTransfer(fx, "o3o4");
  const input = { ...ownerInput(fx, holdId), canonicalParams: canonicalOf(transfer({ amount: "999" })) };
  fx.clock.t = Date.parse(input.grant.expiresAt);
  assert.equal(codeOf(fx.owner!.commit(input, sealerFor(fx).seal)), "GRANT_EXPIRED");
  assert.equal(rowCount(fx.owner), 0);
});

test("order O4 before O5 — a swapped snapshot naming another ledger is PARAMS_SNAPSHOT_MISMATCH", () => {
  const fx = effectGate();
  const holdId = approvedTransfer(fx, "o4o5");
  const input = { ...ownerInput(fx, holdId), canonicalParams: canonicalOf(transfer({ ledger: OTHER_LEDGER })) };
  assert.equal(codeOf(fx.owner!.commit(input, sealerFor(fx).seal)), "PARAMS_SNAPSHOT_MISMATCH");
  assert.equal(rowCount(fx.owner), 0);
});

test("order O5 before O6 — another ledger's transfer between unknown accounts is LEDGER_NOT_OWNED and writes no row", () => {
  const { mine, theirs } = twoLedgers();
  const holdId = approvedTransfer(theirs, "o5o6", transfer({ ledger: OTHER_LEDGER, fromAccount: "acct-example-7", toAccount: "acct-example-8" }));
  assert.equal(codeOf(mine.owner.commit(ownerInput(theirs, holdId), sealerFor(theirs).seal)), "LEDGER_NOT_OWNED");
  assert.equal(rowCount(mine.owner), 0);
});

test("order O6 before O7 — an unknown account with too large an amount is REFUSED as LEDGER_ACCOUNT_UNKNOWN", () => {
  const fx = effectGate();
  const holdId = approvedTransfer(fx, "o6o7", transfer({ toAccount: "acct-example-9", amount: "5000" }));
  assert.equal(codeOf(fx.owner!.commit(ownerInput(fx, holdId), sealerFor(fx).seal)), "REFUSED:LEDGER_ACCOUNT_UNKNOWN");
});

test("order O7 before O8 — insufficient funds is a REFUSED row and the sealer is never called", () => {
  const fx = effectGate();
  const holdId = approvedTransfer(fx, "o7o8", transfer({ amount: "1001" }));
  let sealCalls = 0;
  const o = fx.owner!.commit(ownerInput(fx, holdId), () => { sealCalls++; throw new Error("signer down"); });
  assert.equal(codeOf(o), "REFUSED:LEDGER_INSUFFICIENT_FUNDS");
  assert.equal(sealCalls, 0);
  assert.equal(fx.owner!.inspect().balances[ACCT_1], 1000);
});

test("order O8 before O9 — a sealer failure writes nothing and moves nothing; the retry writes the row", () => {
  const fx = effectGate();
  const holdId = approvedTransfer(fx, "o8o9");
  const input = ownerInput(fx, holdId);
  const total = balanceTotal(fx.owner!);
  const failed = fx.owner!.commit(input, () => { throw new Error("signer down"); });
  assert.equal(codeOf(failed), "EFFECT_SIGNER_UNAVAILABLE");
  assert.equal(rowCount(fx.owner), 0);
  assert.equal(fx.owner!.inspect().balances[ACCT_1], 1000);
  assert.equal(codeOf(fx.owner!.commit(input, sealerFor(fx).seal)), "EXECUTED");
  assert.equal(balanceTotal(fx.owner!), total, "the total is conserved");
});

// ── the row ───────────────────────────────────────────────────────────────────────────────────────

test("a row is frozen and null-prototype, binds its authority, and inspect() hands out copies", () => {
  const fx = effectGate();
  const holdId = approvedTransfer(fx, "row");
  const input = ownerInput(fx, holdId);
  const o = fx.owner!.commit(input, sealerFor(fx).seal);
  assert.ok(o.kind === "EXECUTED");
  const row = o.row;
  assert.ok(Object.isFrozen(row));
  assert.equal(Object.getPrototypeOf(row), null);
  assert.equal(row.holdEnvelopeHash, refHash(input.holdEnvelope));
  assert.equal(row.decisionRefHash, refHash(input.decisionArtifact));
  assert.equal(row.grantId, grantOf(fx, holdId).grant.grantId);
  assert.equal(row.amount, "100");
  assert.equal(row.sequence, 1);
  assert.equal(fx.owner!.find(row.holdEnvelopeHash), row);
  const view = fx.owner!.inspect();
  assert.ok(Object.isFrozen(view.balances) && Object.isFrozen(view.rows));
  assert.throws(() => { (view.balances as Record<string, number>)[ACCT_1] = 0; }, TypeError);
  assert.equal(fx.owner!.inspect().balances[ACCT_1], 900);
});

// ── regression attacks: each test fails on the tree it was written against ───────────────────────

test("EFFECT-REENTRY — a sealer that re-enters commit() gets no second row: one approval, one row, one debit", () => {
  const fx = effectGate();
  const holdId = approvedTransfer(fx, "reentry");
  const input = ownerInput(fx, holdId);
  const sealer = sealerFor(fx);
  const inner: { entered: boolean; outcome?: EffectOutcome } = { entered: false };
  const reentrant = (at: number, ...rest: unknown[]): EffectAttestation => {
    if (!inner.entered) {
      inner.entered = true;
      inner.outcome = fx.owner!.commit(input, sealer.seal);
    }
    return sealer.seal(at, ...rest);
  };
  const outer = fx.owner!.commit(input, reentrant);
  assert.equal(rowCount(fx.owner), 1, "consequence: one approval, one row");
  assert.equal(fx.owner!.inspect().balances[ACCT_1], 900, "consequence: one debit");
  assert.equal(balanceTotal(fx.owner!), 1050, "consequence: the total is conserved");
  assert.equal(sealer.calls.length, 1, "consequence: one signature for one approval");
  assert.equal(codeOf(outer), "EXECUTED");
  assert.equal(codeOf(inner.outcome!), "EFFECT_COMMIT_REENTRANT");
});

test("EFFECT-REENTRY-OTHER — a sealer that commits ANOTHER approval mid-commit cannot make one debit overwrite the other", () => {
  const fx = effectGate();
  const first = approvedTransfer(fx, "reentry-a");
  const second = approvedTransfer(fx, "reentry-b", transfer({ amount: "300" }));
  const sealer = sealerFor(fx);
  const inner: { entered: boolean; outcome?: EffectOutcome } = { entered: false };
  const reentrant = (at: number, ...rest: unknown[]): EffectAttestation => {
    if (!inner.entered) {
      inner.entered = true;
      inner.outcome = fx.owner!.commit(ownerInput(fx, second), sealer.seal);
    }
    return sealer.seal(at, ...rest);
  };
  fx.owner!.commit(ownerInput(fx, first), reentrant);
  const executed = fx.owner!.inspect().rows.filter((row) => row.outcome === "EXECUTED");
  let debited = 0;
  for (const row of executed) debited += Number(row.amount);
  assert.equal(fx.owner!.inspect().balances[ACCT_1], 1000 - debited, "consequence: every executed row is debited exactly once");
  assert.equal(balanceTotal(fx.owner!), 1050, "consequence: the total is conserved");
  assert.equal(codeOf(inner.outcome!), "EFFECT_COMMIT_REENTRANT");
});

test("EFFECT-OWNER-DEAD-BOOT — a restarted gate's owner, called directly with a hold frozen before the restart, writes nothing", () => {
  const world = newWorld();
  const clock = makeClock();
  const store = new InMemoryStore();
  const roster = rosterDoc(world, clock.t);
  const a = effectGate({ world, clock, store, roster, ids: idSource("odb-a") });
  const b = effectGate({ world, clock, store, roster, ids: idSource("odb-b") });
  assert.notEqual(a.trust.bootId, b.trust.bootId, "fixture: the restart draws a new bootId");
  const holdId = approvedTransfer(a, "owner-dead-boot");
  const sealer = sealerFor(b);
  const o = b.owner!.commit(ownerInput(a, holdId), sealer.seal);
  assert.equal(rowCount(b.owner), 0, "consequence: the restarted gate's owner writes no row");
  assert.equal(sealer.calls.length, 0, "consequence: nothing is signed for it");
  assert.equal(codeOf(o), "HOLD_FROM_DEAD_BOOT");
});

test("EFFECT-ATTESTATION-NULL — a sealer that returns no signed evidence gets no row and moves nothing", () => {
  const fx = effectGate();
  const holdId = approvedTransfer(fx, "attestation-null");
  const o = fx.owner!.commit(ownerInput(fx, holdId), () => ({ executedReceipt: null, executionConsumption: null }) as unknown as EffectAttestation);
  assert.equal(rowCount(fx.owner), 0, "consequence: no row without verified execution evidence");
  assert.equal(fx.owner!.inspect().balances[ACCT_1], 1000, "consequence: nothing moved");
  assert.equal(codeOf(o), "EFFECT_ATTESTATION_INVALID");
});

test("EFFECT-OWNER-EPOCH — an owner whose roster names another key-manifest epoch does not commit a hold frozen under this one", () => {
  const a = effectGate();
  const holdId = approvedTransfer(a, "owner-epoch");
  const other = ownerOn(a, { epoch: { keyManifestVersion: 3, keyManifestHash: "sha256:" + "3".repeat(64) } }, "owner-epoch");
  const sealer = sealerFor(a);
  const o = other.owner.commit(ownerInput(a, holdId), sealer.seal);
  assert.equal(rowCount(other.owner), 0, "consequence: another epoch's owner writes no row");
  assert.equal(sealer.calls.length, 0, "consequence: nothing is signed");
  assert.equal(codeOf(o), "COMMIT_AUTHORITY_INVALID");
});

test("EFFECT-OWNER-TENANT — an owner for another tenant, with the same keys, does not commit this tenant's hold", () => {
  const a = effectGate();
  const holdId = approvedTransfer(a, "owner-tenant");
  const other = ownerOn(a, { tenant: "tenant-example-2" }, "owner-tenant");
  const sealer = sealerFor(a);
  const o = other.owner.commit(ownerInput(a, holdId), sealer.seal);
  assert.equal(rowCount(other.owner), 0, "consequence: another tenant's owner writes no row");
  assert.equal(sealer.calls.length, 0, "consequence: nothing is signed");
  assert.equal(codeOf(o), "COMMIT_AUTHORITY_INVALID");
});

/** A hold approved in the store by approver Y, who was never sent its display; Y is a roster approver of `owner`. */
function nonRecipientApproval() {
  const a = effectGate();
  const y = approverKeys(6);
  const holdId = holdIdOf(createTransfer(a, "non-recipient"));
  const other = ownerOn(a, {
    approvers: {
      [y.kid]: { role: "approve-critical", publicKey: y.ed.publicKey, hpkePublicKey: y.x.publicKey, validFrom: new Date(a.clock.t - HOUR).toISOString(), revokedAt: null },
    },
  }, "non-recipient");
  const decision = decisionFor(a, holdId, "APPROVE", y);
  plantApproved(a, holdId, { decisionArtifact: decision.decisionArtifact, receipt: decision.receipt, grant: signedGrant(a, holdId, gateKey(a.world), {}, decision.receipt) });
  return { a, y, holdId, owner: other.owner };
}

test("EFFECT-DISPLAY-RECIPIENT — a decision by an approver the display was never sealed to commits nothing", () => {
  const { a, holdId, owner } = nonRecipientApproval();
  const sealer = sealerFor(a);
  const o = owner.commit(ownerInput(a, holdId), sealer.seal);
  assert.equal(rowCount(owner), 0, "consequence: an approver who never saw the display authorizes nothing");
  assert.equal(sealer.calls.length, 0, "consequence: nothing is signed");
  assert.equal(codeOf(o), "COMMIT_AUTHORITY_INVALID");
});

test("EFFECT-DISPLAY-BINDING — a substituted display that names the deciding approver does not stand in for the one the envelope binds", () => {
  const { a, y, holdId, owner } = nonRecipientApproval();
  const h = hold(a, holdId);
  const fake = { ...h.encryptedDisplay, recipients: [{ kid: y.kid, enc: "ZW5j", wrappedCek: "Y2Vr" }, ...(h.encryptedDisplay.recipients ?? [])] };
  const sealer = sealerFor(a);
  const o = owner.commit(Object.assign(ownerInput(a, holdId), { encryptedDisplay: fake }), sealer.seal);
  assert.equal(rowCount(owner), 0, "consequence: a display the envelope does not bind names nobody");
  assert.equal(sealer.calls.length, 0, "consequence: nothing is signed");
  assert.equal(codeOf(o), "COMMIT_AUTHORITY_INVALID");
});

/** A transfer of 999 in canonical form, and its params hash. */
function transfer999() {
  const canonical = canonicalOf(transfer({ amount: "999" }));
  const r = projectLedgerTransfer(canonical);
  assert.ok(r.ok);
  return { canonical, paramsHash: r.paramsHash };
}

test("EFFECT-GRANT-PARAMS — a gate-key grant for 999 over a human approval of 100 moves nothing", () => {
  const fx = effectGate();
  const holdId = approvedTransfer(fx, "grant-params");
  const t = transfer999();
  const sealer = sealerFor(fx);
  const attack = { ...ownerInput(fx, holdId), canonicalParams: t.canonical, grant: signedGrant(fx, holdId, gateKey(fx.world), { paramsHash: t.paramsHash }) };
  const o = fx.owner!.commit(attack, sealer.seal);
  assert.equal(fx.owner!.inspect().balances[ACCT_1], 1000, "consequence: an amount the human never approved does not move");
  assert.equal(rowCount(fx.owner), 0);
  assert.equal(sealer.calls.length, 0, "consequence: nothing is signed");
  assert.equal(codeOf(o), "COMMIT_AUTHORITY_INVALID");
});

test("EFFECT-DEFERRED-BINDING — a gate-key deferred receipt for 999 in place of the approved one moves nothing and signs nothing", () => {
  const fx = effectGate();
  const holdId = approvedTransfer(fx, "deferred-binding");
  const h = hold(fx, holdId);
  const t = transfer999();
  const forged = buildDeferredReceipt({
    id: h.deferredReceipt.id,
    ts: h.deferredReceipt.ts,
    tenant: h.tenant,
    chain: h.chain,
    agentId: h.agentId,
    action: { id: h.actionId, canonical: h.action.canonical, riskClass: h.action.riskClass, paramsHash: t.paramsHash, reversible: h.action.reversible },
    gate: { kid: fx.world.gate.kid, publicKey: fx.world.gate.publicKey, privateKey: fx.world.gate.privateKey },
  });
  const sealer = sealerFor(fx);
  const attack = {
    ...ownerInput(fx, holdId),
    deferredReceipt: forged,
    canonicalParams: t.canonical,
    grant: signedGrant(fx, holdId, gateKey(fx.world), { paramsHash: t.paramsHash }),
  };
  const o = fx.owner!.commit(attack, sealer.seal);
  assert.equal(sealer.calls.length, 0, "consequence: nothing is signed over a deferred receipt the envelope does not bind");
  assert.equal(fx.owner!.inspect().balances[ACCT_1], 1000, "consequence: an amount the human never approved does not move");
  assert.equal(rowCount(fx.owner), 0);
  assert.equal(codeOf(o), "COMMIT_AUTHORITY_INVALID");
});

test("self-transfer — a same-account transfer never reaches the ledger, so no balance can be minted", () => {
  const same = projectLedgerTransfer(JSON.stringify(transfer({ toAccount: ACCT_1 })));
  assert.equal(same.ok, false, "the kernel refuses a self-transfer (TRANSFER_SAME_ACCOUNT)");
  const fx = effectGate();
  const holdId = approvedTransfer(fx, "self-transfer");
  const input = { ...ownerInput(fx, holdId), canonicalParams: JSON.stringify(transfer({ toAccount: ACCT_1 })) };
  const o = fx.owner!.commit(input, sealerFor(fx).seal);
  assert.equal(balanceTotal(fx.owner!), 1050, "consequence: the total is conserved");
  assert.equal(rowCount(fx.owner), 0);
  assert.notEqual(codeOf(o), "EXECUTED");
  assert.deepEqual({ ...fx.owner!.inspect().balances }, { ...DEFAULT_ACCOUNTS });
});

// ── hostile input objects and attestations (each fails on the tree it was written against) ───────────

/** An input whose `field` is a getter: `onRead(n)` runs on the n-th read, and the getter returns `value(n)`. */
function withGetter(input: EffectCommitInput, field: keyof EffectCommitInput, value: (n: number) => unknown, onRead: (n: number) => void = () => {}): EffectCommitInput {
  const attack: Record<string, unknown> = { ...input };
  let reads = 0;
  Object.defineProperty(attack, field, { enumerable: true, get() { reads++; onRead(reads); return value(reads); } });
  return attack as unknown as EffectCommitInput;
}

/** A keyless sealer: it hands back the attestation the owner already recorded for this ledger, if any. */
function replaySealer(owner: EffectOwner): () => EffectAttestation {
  return () => owner.inspect().rows[0]?.attestation as EffectAttestation;
}

test("EFFECT-GETTER-REENTRY-CANONICAL — a canonicalParams getter that commits the same hold through the engine gets one approval one effect", () => {
  const fx = effectGate();
  const holdId = approvedTransfer(fx, "getter-canonical");
  const canonical = hold(fx, holdId).canonicalParams!;
  let fired = false;
  const attack = withGetter(ownerInput(fx, holdId), "canonicalParams", () => canonical, () => {
    if (!fired) { fired = true; fx.engine.commit(holdId, fx.agent); }
  });
  fx.owner!.commit(attack, replaySealer(fx.owner!));
  fx.engine.commit(holdId, fx.agent);
  assert.equal(rowCount(fx.owner), 1, "consequence: one approval, one row");
  assert.equal(fx.owner!.inspect().balances[ACCT_1], 900, "consequence: one debit");
});

test("EFFECT-GETTER-REENTRY-HOLDID — a holdId getter that commits the same hold on its second read gets one approval one effect", () => {
  const fx = effectGate();
  const holdId = approvedTransfer(fx, "getter-holdid");
  const attack = withGetter(ownerInput(fx, holdId), "holdId", () => holdId, (n) => {
    if (n === 2) fx.engine.commit(holdId, fx.agent);
  });
  fx.owner!.commit(attack, replaySealer(fx.owner!));
  fx.engine.commit(holdId, fx.agent);
  assert.equal(rowCount(fx.owner), 1, "consequence: one approval, one row");
  assert.equal(fx.owner!.inspect().balances[ACCT_1], 900, "consequence: one debit");
});

test("EFFECT-ROW-TEXT — the row records the canonical text that was checked and moved, never a later read", () => {
  const fx = effectGate();
  const holdId = approvedTransfer(fx, "row-text");
  const canonical = hold(fx, holdId).canonicalParams!;
  const attack = withGetter(ownerInput(fx, holdId), "canonicalParams", (n) => (n <= 2 ? canonical : '{"not":"what moved"}'));
  fx.owner!.commit(attack, sealerFor(fx).seal);
  const row = fx.owner!.inspect().rows[0];
  assert.equal(row?.canonicalParams, canonical, "consequence: the recorded text is the text that moved");
  assert.equal(row?.amount, "100");
});

test("EFFECT-ATTESTATION-TIME — an attestation signed for another instant is not recorded for this commit", () => {
  const fx = effectGate();
  const holdId = approvedTransfer(fx, "attestation-time");
  const future = Date.parse("2099-01-01T00:00:00.000Z");
  const o = fx.owner!.commit(ownerInput(fx, holdId), (_at: number, ...rest: unknown[]) =>
    buildEffectAttestation({ verified: rest[0] as VerifiedAuthority, atMs: future, receiptId: "arbitrary-id", gate: fx.trust.gate, signer: fx.signer }));
  assert.equal(rowCount(fx.owner), 0, "consequence: evidence dated at another instant is never recorded");
  assert.equal(fx.owner!.inspect().balances[ACCT_1], 1000);
  assert.equal(codeOf(o), "EFFECT_ATTESTATION_INVALID");
});

test("EFFECT-ATTESTATION-SHAPE — a gate-signed receipt with a member the gate's sealer never writes is not recorded", () => {
  const fx = effectGate();
  const holdId = approvedTransfer(fx, "attestation-shape");
  const o = fx.owner!.commit(ownerInput(fx, holdId), (at: number, ...rest: unknown[]) => {
    const v = rest[0] as { deferred: Receipt; approval: Receipt; grant: Record<string, unknown> };
    const ts = new Date(at).toISOString();
    const executedReceipt = buildReceipt(
      {
        id: "shape-receipt-1",
        ts,
        scope: { tenant: v.deferred.scope.tenant, chain: v.deferred.scope.chain },
        agent: { id: v.deferred.agent.id, model: "shadow-model", principal: "SERVICE" },
        action: { ...v.deferred.action, rollbackRef: null },
        governance: { mode: "approvals_on", verdict: "EXECUTED", ruleId: null, approval: null, sandboxed: false },
      },
      v.approval,
      { kid: fx.trust.gate.kid, privateKey: fx.trust.gate.privateKey },
    );
    const executionConsumption = buildConsumption({ grant: v.grant as never, consumedAt: ts, attemptReceipt: executedReceipt, result: "DISPATCHED", signer: fx.signer });
    return { executedReceipt, executionConsumption };
  });
  assert.equal(rowCount(fx.owner), 0, "consequence: evidence the gate's sealer would not write is never recorded");
  assert.equal(fx.owner!.inspect().balances[ACCT_1], 1000);
  assert.equal(codeOf(o), "EFFECT_ATTESTATION_INVALID");
});

test("EFFECT-ATTESTATION-THROWS — a sealer result that throws on read is refused, not thrown, and the owner stays usable", () => {
  const fx = effectGate();
  const holdId = approvedTransfer(fx, "attestation-throws");
  const hostile = {};
  Object.defineProperty(hostile, "executedReceipt", { enumerable: true, get() { throw new Error("test: hostile attestation"); } });
  let escaped: unknown = null;
  let o: EffectOutcome | null = null;
  try {
    o = fx.owner!.commit(ownerInput(fx, holdId), () => hostile as unknown as EffectAttestation);
  } catch (e) {
    escaped = e;
  }
  assert.equal(rowCount(fx.owner), 0, "consequence: nothing is written");
  assert.equal(escaped, null, "a hostile attestation is a refusal, never an exception out of commit()");
  assert.equal(codeOf(o!), "EFFECT_ATTESTATION_INVALID");
  assert.equal(codeOf(fx.owner!.commit(ownerInput(fx, holdId), sealerFor(fx).seal)), "EXECUTED", "the owner is not left busy");
});

test("EFFECT-ENVELOPE-HOLD — a gate-key grant for another hold id, with a matching input hold id, commits nothing", () => {
  const fx = effectGate();
  const holdId = approvedTransfer(fx, "envelope-hold");
  const forgedId = "hold-forged-0001";
  const attack = { ...ownerInput(fx, holdId), holdId: forgedId, grant: signedGrant(fx, holdId, gateKey(fx.world), { holdId: forgedId }) };
  const o = fx.owner!.commit(attack, sealerFor(fx).seal);
  assert.equal(rowCount(fx.owner), 0, "consequence: no row is recorded under a hold id the envelope does not name");
  assert.equal(fx.owner!.inspect().balances[ACCT_1], 1000);
  assert.equal(codeOf(o), "COMMIT_AUTHORITY_INVALID");
});

test("EFFECT-SIGNED-BOOT — a gate that booted after a hold was frozen does not commit it, even when told the hold is from its boot", () => {
  const world = newWorld();
  const clock = makeClock();
  const store = new InMemoryStore();
  const roster = rosterDoc(world, clock.t);
  const a = effectGate({ world, clock, store, roster, ids: idSource("sb-a") });
  const holdId = approvedTransfer(a, "signed-boot");
  clock.advance(MIN);
  const b = effectGate({ world, clock, store, roster, ids: idSource("sb-b") });
  const sealer = sealerFor(b);
  const o = b.owner!.commit({ ...ownerInput(a, holdId), holdBootId: b.trust.bootId }, sealer.seal);
  assert.equal(rowCount(b.owner), 0, "consequence: the later boot writes no row for an earlier boot's hold");
  assert.equal(sealer.calls.length, 0, "consequence: nothing is signed");
  assert.equal(codeOf(o), "HOLD_FROM_DEAD_BOOT");
});

test("EFFECT-KEYRING-CONSISTENCY — an owner whose receipt keyring and decision keyring disagree on the approver commits nothing", () => {
  const fx = effectGate();
  const holdId = holdIdOf(createTransfer(fx, "keyring-consistency"));
  const x = fx.world.approver;
  const impostor = approverKeys(7);
  const keys = fx.trust.receiptKeyring.keys as Record<string, { publicKey: string; retiredAt: string | null }>;
  const injected = {
    ...fx.trust,
    receiptKeyring: { ...fx.trust.receiptKeyring, keys: { ...keys, [x.kid]: { publicKey: impostor.ed.publicKey, retiredAt: null } } },
  };
  const owner = createInMemoryLedgerEffectOwner({ trust: injected, now: () => fx.clock.t, ledger: LEDGER, accounts: DEFAULT_ACCOUNTS });
  const approve = decisionFor(fx, holdId);
  const forgedReceipt = approvalReceiptBy(fx, holdId, { kid: x.kid, privateKey: impostor.ed.privateKey }, { by: x.kid, verdict: "ALLOWED" });
  plantApproved(fx, holdId, { decisionArtifact: approve.decisionArtifact, receipt: forgedReceipt, grant: signedGrant(fx, holdId, gateKey(fx.world), {}, forgedReceipt) });
  const o = owner.commit(ownerInput(fx, holdId), sealerFor(fx).seal);
  assert.equal(rowCount(owner), 0, "consequence: a receipt signed by a key the decision keyring does not name moves nothing");
  assert.equal(owner.inspect().balances[ACCT_1], 1000);
  assert.equal(codeOf(o), "COMMIT_AUTHORITY_INVALID");
});
