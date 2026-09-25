/**
 * The hooks a durable effect owner builds on (docs/gate-effect-owner.md): the owner's authority check
 * and ledger derivation exported as ONE implementation, an owner that records the grant's consumption
 * itself over the engine's own store, and a store outage that is retryable and writes nothing.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { GateEngine } from "../src/engine.js";
import { InMemoryStore, type Store } from "../src/store.js";
import { getProjection } from "../src/projections.js";
import * as effectOwnerModule from "../src/effect-owner.js";
import {
  buildEffectAttestation,
  deriveLedgerCommit,
  verifyEffectAuthority,
  type EffectAttestation,
  type EffectOwner,
  type EffectCommitInput,
  type VerifiedAuthority,
} from "../src/effect-owner.js";
import type { GateTrust } from "../src/trust.js";
import { LEDGER_TRANSFER_CANONICAL } from "noa-receipt";
import {
  ACCT_1,
  approvedTransfer,
  effectGate,
  grantOf,
  idSource,
  ownerInput,
  rowCount,
  sealerFor,
  type EffectGate,
} from "./helpers/effect.js";

/** An owner that behaves as `inner` except for the members given. */
function wrapped(inner: EffectOwner, extra: Partial<Pick<EffectOwner, "recordsGrantConsumption" | "store" | "commit">>): EffectOwner {
  return {
    canonical: inner.canonical,
    ledger: inner.ledger,
    bootId: inner.bootId,
    get bound() {
      return inner.bound;
    },
    bindEngine: (engine: object) => inner.bindEngine(engine),
    admit: (canonicalParams: string) => inner.admit(canonicalParams),
    find: (holdEnvelopeHash: string) => inner.find(holdEnvelopeHash),
    commit: extra.commit ?? ((input, seal) => inner.commit(input, seal)),
    inspect: () => inner.inspect(),
    ...(extra.recordsGrantConsumption ? { recordsGrantConsumption: extra.recordsGrantConsumption } : {}),
    ...(extra.store ? { store: extra.store } : {}),
  };
}

/** A gate whose engine is built with the in-memory owner replaced by `wrap(owner, store)`. */
function gateWith(prefix: string, wrap: (owner: EffectOwner, deps: { store: Store }) => EffectOwner): EffectGate {
  return effectGate({
    ids: idSource(prefix),
    makeEngine: (deps) => new GateEngine({ ...deps, effectOwners: [wrap((deps.effectOwners ?? [])[0] as EffectOwner, { store: deps.store })] }),
  });
}

test("EFFECT-AUTHORITY-EXPORT — the exported authority check and ledger derivation are the owner's: same verdicts, and the derived commit is the row it writes", () => {
  const fx = effectGate({ ids: idSource("export") });
  const holdId = approvedTransfer(fx, "export");
  const input = ownerInput(fx, holdId);
  const registered = getProjection(LEDGER_TRANSFER_CANONICAL);
  if (registered === undefined) throw new Error("fixture: the transfer projection is not registered");
  const nowIso = new Date(fx.clock.t).toISOString();

  // A tampered input: the exported check refuses it with the token the owner refuses it with.
  const tampered: EffectCommitInput = { ...input, holdId: "hold-forged-0001" };
  const refused = verifyEffectAuthority(fx.trust, registered, tampered, nowIso);
  const ownerRefusal = fx.owner!.commit(tampered, sealerFor(fx).seal);
  assert.equal(rowCount(fx.owner), 0, "consequence: the tampered input moves nothing");
  assert.deepEqual(
    refused.ok ? null : [refused.code, refused.detail],
    ownerRefusal.kind === "NOT_COMMITTED" ? [ownerRefusal.code, ownerRefusal.detail] : null,
  );

  const authority = verifyEffectAuthority(fx.trust, registered, input, nowIso);
  assert.ok(authority.ok, JSON.stringify(authority));
  assert.ok(Object.isFrozen(authority.input), "the input snapshot is frozen");
  const derived = deriveLedgerCommit(authority, fx.owner!.ledger, fx.clock.t);
  assert.ok(derived.ok, JSON.stringify(derived));
  const outcome = fx.owner!.commit(input, sealerFor(fx).seal);
  assert.equal(outcome.kind, "EXECUTED");
  const row = fx.owner!.inspect().rows[0]!;
  const c = derived.commit;
  assert.deepEqual(
    [row.ledger, row.fromAccount, row.toAccount, row.amount, row.unit, row.paramsHash, row.canonicalParams, row.holdId, row.holdEnvelopeHash, row.decisionRefHash, row.grantId],
    [c.ledger, c.fromAccount, c.toAccount, c.amount, c.unit, c.paramsHash, c.canonicalParams, c.holdId, c.holdEnvelopeHash, c.decisionRefHash, c.grantId],
  );
  assert.equal(c.units, 100);
  // Expired: the same instant rule as the owner's O3.
  const late = deriveLedgerCommit(authority, fx.owner!.ledger, fx.clock.t + 24 * 60 * 60 * 1000);
  assert.deepEqual(late.ok ? null : late.code, "GRANT_EXPIRED");
  assert.deepEqual((() => { const o = deriveLedgerCommit(authority, "ledger-example-2", fx.clock.t); return o.ok ? null : o.code; })(), "LEDGER_NOT_OWNED");
});

/** The exported attestation check (O8), looked up by name so this file compiles before it exists. */
type AttestationCheck = (trust: GateTrust, raw: unknown, verified: VerifiedAuthority, nowIso: string, alreadyRecorded: (receiptId: string) => boolean) => { problem: string | null; attestation: EffectAttestation };
const verifyEffectAttestation = (...a: Parameters<AttestationCheck>) => (effectOwnerModule as unknown as Record<string, AttestationCheck>)["verifyEffectAttestation"]!(...a);

test("EFFECT-ATTESTATION-EXPORT — the exported attestation check is the owner's: evidence for another instant is refused with the owner's token; this commit's evidence passes once", () => {
  const fx = effectGate({ ids: idSource("att-export") });
  const holdId = approvedTransfer(fx, "att-export");
  const input = ownerInput(fx, holdId);
  const registered = getProjection(LEDGER_TRANSFER_CANONICAL);
  if (registered === undefined) throw new Error("fixture: the transfer projection is not registered");
  const nowIso = new Date(fx.clock.t).toISOString();
  const authority = verifyEffectAuthority(fx.trust, registered, input, nowIso);
  assert.ok(authority.ok, JSON.stringify(authority));
  const seal = (atMs: number, receiptId: string) =>
    buildEffectAttestation({ verified: authority.verified, atMs, receiptId, gate: fx.trust.gate, signer: fx.signer });
  const elsewhen = seal(fx.clock.t + 1000, "sealed-elsewhen");
  const checked = verifyEffectAttestation(fx.trust, elsewhen, authority.verified, nowIso, () => false);
  assert.equal(checked.problem, "attestation-time", "consequence: evidence dated at another instant is refused");
  const ownerRefusal = fx.owner!.commit(input, () => elsewhen);
  assert.equal(rowCount(fx.owner), 0, "consequence: the owner records nothing for it either");
  assert.deepEqual([ownerRefusal.kind === "NOT_COMMITTED" ? ownerRefusal.detail : null], [checked.problem], "one implementation, one token");
  const good = seal(fx.clock.t, "sealed-good");
  assert.equal(verifyEffectAttestation(fx.trust, good, authority.verified, nowIso, () => false).problem, null);
  assert.equal(verifyEffectAttestation(fx.trust, good, authority.verified, nowIso, (id) => id === "sealed-good").problem, "executed-receipt-fresh", "an already recorded receipt id is refused");
});

test("EFFECT-OWNER-STORE-MISMATCH — an owner that records the grant's consumption in another store is refused at construction", () => {
  let built: EffectGate | null = null;
  let refusal: unknown = null;
  try {
    built = gateWith("mismatch", (owner) => wrapped(owner, { recordsGrantConsumption: true, store: new InMemoryStore() }));
  } catch (e) {
    refusal = e;
  }
  assert.equal(built, null, "consequence: no engine commits through an owner whose consumption record it cannot read");
  assert.match(String(refusal), /^Error: EFFECT_OWNER_STORE_MISMATCH/);
  // Over the engine's own store it is accepted.
  const fx = gateWith("match", (owner, deps) => wrapped(owner, { recordsGrantConsumption: true, store: deps.store }));
  assert.ok(fx.engine instanceof GateEngine);
});

test("EFFECT-MIRROR-SKIP — the engine does not mirror a consumption the owner records itself", () => {
  const fx = gateWith("mirror-skip", (owner, deps) => wrapped(owner, { recordsGrantConsumption: true, store: deps.store }));
  const holdId = approvedTransfer(fx, "mirror-skip");
  const committed = fx.engine.commit(holdId, fx.agent);
  assert.equal(committed.status, 200, JSON.stringify(committed.body));
  assert.equal(rowCount(fx.owner), 1);
  const grant = grantOf(fx, holdId);
  assert.equal(grant.reportedAt, null, "the engine left the grant record to the owner");
  assert.equal(grant.consumption, null);
});

test("EFFECT-STORE-UNAVAILABLE — an owner whose store is unreachable writes nothing, and the commit is answered 503 retryable", () => {
  const fx = gateWith("store-down", (owner) => wrapped(owner, {
    commit: () => ({ kind: "NOT_COMMITTED", code: "EFFECT_STORE_UNAVAILABLE", effectId: null, detail: "test: the owner's store is unreachable" }),
  }));
  const holdId = approvedTransfer(fx, "store-down");
  const before = fx.owner!.inspect().balances[ACCT_1];
  const r = fx.engine.commit(holdId, fx.agent);
  assert.equal(rowCount(fx.owner), 0, "consequence: nothing is written");
  assert.equal(fx.owner!.inspect().balances[ACCT_1], before);
  assert.equal(grantOf(fx, holdId).status, "UNUSED", "the authority is left unconsumed");
  assert.equal(r.status, 503);
  assert.equal((r.body as Record<string, unknown>)["error"], "EFFECT_STORE_UNAVAILABLE");
  assert.equal((r.body as Record<string, unknown>)["retryable"], true);
});
