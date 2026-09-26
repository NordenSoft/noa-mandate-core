/**
 * The hooks a durable effect owner builds on (docs/gate-effect-owner.md): the owner's authority check,
 * ledger derivation and ledger-definition check exported as ONE implementation, an owner that records
 * the grant's consumption itself over the engine's own store, a store outage that is retryable
 * and writes nothing, and the commit route's answer to every owner outcome that carries no row
 * (conformance/gate-commit-answers/vectors.json), including an outcome the owner cannot know.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { GateEngine } from "../src/engine.js";
import { InMemoryStore, type Store } from "../src/store.js";
import { getProjection } from "../src/projections.js";
import * as effectOwnerModule from "../src/effect-owner.js";
import {
  buildEffectAttestation,
  checkLedgerDefinition,
  createInMemoryLedgerEffectOwner,
  deriveLedgerCommit,
  verifyEffectAuthority,
  type EffectAttestation,
  type EffectOwner,
  type EffectCommitInput,
  type EffectOutcome,
  type EffectRefusalCode,
  type VerifiedAuthority,
} from "../src/effect-owner.js";
import type { GateTrust } from "../src/trust.js";
import { LEDGER_TRANSFER_CANONICAL } from "noa-receipt";
import {
  ACCT_1,
  ACCT_2,
  DEFAULT_ACCOUNTS,
  LEDGER,
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

test("EFFECT-LEDGER-DEFINITION-EXPORT — the exported ledger-definition check is the owner's: both refuse the same definitions with the same detail and accept the same balances", () => {
  const fx = effectGate({ owner: false, ids: idSource("ledger-definition") });
  const build = (ledger: unknown, accounts: unknown) => () =>
    createInMemoryLedgerEffectOwner({ trust: fx.trust, now: () => fx.clock.t, ledger: ledger as string, accounts: accounts as Record<string, number> });
  const refused: Array<[string, unknown, unknown]> = [
    ["ledger identifier", "Ledger-1", {}],
    ["empty ledger", "", {}],
    ["ledger of another type", 7, {}],
    ["accounts not an object", LEDGER, null],
    ["accounts an array", LEDGER, [1]],
    ["account identifier", LEDGER, { "ACCT-1": 1 }],
    ["negative balance", LEDGER, { [ACCT_1]: -1 }],
    ["fractional balance", LEDGER, { [ACCT_1]: 1.5 }],
    ["balance of another type", LEDGER, { [ACCT_1]: "10" }],
    ["unsafe balance", LEDGER, { [ACCT_1]: Number.MAX_SAFE_INTEGER + 1 }],
    ["sum past the bound", LEDGER, { [ACCT_1]: Number.MAX_SAFE_INTEGER, [ACCT_2]: 1 }],
  ];
  for (const [label, ledger, accounts] of refused) {
    const r = checkLedgerDefinition(ledger, accounts);
    assert.equal(r.ok, false, `${label}: the exported check refuses it`);
    if (r.ok) continue;
    assert.throws(build(ledger, accounts), (e: unknown) => e instanceof Error && e.message === `EFFECT_OWNER_LEDGER_INVALID: ${r.detail}`,
      `${label}: the owner refuses it with the exported check's detail`);
  }
  for (const accounts of [DEFAULT_ACCOUNTS, { [ACCT_1]: Number.MAX_SAFE_INTEGER, [ACCT_2]: 0 }, {}]) {
    const r = checkLedgerDefinition(LEDGER, accounts);
    assert.ok(r.ok, JSON.stringify(r));
    assert.equal(Object.getPrototypeOf(r.balances), null, "the balances are a null-prototype copy");
    assert.notEqual(r.balances, accounts);
    assert.deepEqual({ ...r.balances }, { ...accounts });
    assert.deepEqual({ ...build(LEDGER, accounts)().inspect().balances }, { ...r.balances }, "the owner holds exactly the balances the check accepted");
  }
});

test("EFFECT-LEDGER-DEFINITION-CHANGES — definitions the owner used to build or throw on are refused with a stable detail", () => {
  // Measured against the owner as it stood before the check was exported (it walked
  // Object.keys(accounts) and named a bad ledger by its JSON text): an array, a number, a function, a
  // bigint, a Map and a Set each built an EMPTY ledger; null and undefined threw a TypeError; a bigint
  // ledger threw a TypeError; a number ledger was named "7". Each is now refused with
  // EFFECT_OWNER_LEDGER_INVALID and one of two stable details.
  const fx = effectGate({ owner: false, ids: idSource("ledger-definition-changes") });
  const notPlain = "the accounts are not a plain object (prototype Object.prototype or null) of account identifiers and balances";
  const ledgerOfType = (t: string) => `the ledger identifier of type ${t} fails the noa.ledger.transfer/1 identifier rules`;
  const cases: Array<[string, unknown, unknown, string]> = [
    ["an array", LEDGER, [], notPlain],
    ["a number", LEDGER, 5, notPlain],
    ["a function", LEDGER, function accounts() {}, notPlain],
    ["null", LEDGER, null, notPlain],
    ["undefined", LEDGER, undefined, notPlain],
    ["a bigint", LEDGER, BigInt(10), notPlain],
    ["a Map", LEDGER, new Map([[ACCT_1, 5]]), notPlain],
    ["a Set", LEDGER, new Set([ACCT_1]), notPlain],
    ["a number ledger", 7, {}, ledgerOfType("number")],
    ["a bigint ledger", BigInt(10), {}, ledgerOfType("bigint")],
    ["an undefined ledger", undefined, {}, ledgerOfType("undefined")],
  ];
  for (const [label, ledger, accounts, detail] of cases) {
    assert.deepEqual(checkLedgerDefinition(ledger, accounts), { ok: false, detail }, `${label}: the exported check refuses it`);
    assert.throws(
      () => createInMemoryLedgerEffectOwner({ trust: fx.trust, now: () => fx.clock.t, ledger: ledger as string, accounts: accounts as Record<string, number> }),
      (e: unknown) => e instanceof Error && !(e instanceof TypeError) && e.message === `EFFECT_OWNER_LEDGER_INVALID: ${detail}`,
      `${label}: the owner refuses it with the same detail`,
    );
  }
  // Still accepted: a plain object and a null-prototype object.
  for (const accounts of [{ [ACCT_1]: 5 }, Object.assign(Object.create(null) as Record<string, number>, { [ACCT_1]: 5 })]) {
    const r = checkLedgerDefinition(LEDGER, accounts);
    assert.ok(r.ok, JSON.stringify(r));
    assert.equal(r.balances[ACCT_1], 5);
  }
});

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

/** Every NOT_COMMITTED code, once: the compiler refuses this literal when the union gains or loses one. */
const OWNER_REFUSAL_CODES: Record<EffectRefusalCode, true> = {
  HOLD_FROM_DEAD_BOOT: true,
  COMMIT_AUTHORITY_INVALID: true,
  EFFECT_COMMIT_REENTRANT: true,
  EFFECT_AUTHORITY_CONSUMED: true,
  GRANT_EXPIRED: true,
  PARAMS_SNAPSHOT_MISMATCH: true,
  LEDGER_NOT_OWNED: true,
  LEDGER_SAME_ACCOUNT: true,
  EFFECT_SIGNER_UNAVAILABLE: true,
  EFFECT_ATTESTATION_INVALID: true,
  EFFECT_STORE_UNAVAILABLE: true,
};

interface CommitAnswerVector {
  id: string;
  owner: { kind: "NOT_COMMITTED" | "OUTCOME_UNKNOWN"; code: string };
  expect: { status: number; error: string; retryable: boolean; written: "NOTHING" | "UNKNOWN"; bodyKeys: string[] };
}

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");

test("EFFECT-COMMIT-ANSWERS — the commit route answers every owner outcome without a row exactly as conformance/gate-commit-answers/vectors.json says, and records nothing for it", () => {
  const corpus = JSON.parse(readFileSync(join(REPO_ROOT, "conformance", "gate-commit-answers", "vectors.json"), "utf8")) as { vectors: CommitAnswerVector[] };
  // Completeness: one vector per NOT_COMMITTED code and one for OUTCOME_UNKNOWN, nothing else.
  const refusalCodes = corpus.vectors.filter((v) => v.owner.kind === "NOT_COMMITTED").map((v) => v.owner.code);
  assert.deepEqual([...refusalCodes].sort(), Object.keys(OWNER_REFUSAL_CODES).sort(), "one vector per NOT_COMMITTED code");
  assert.deepEqual(corpus.vectors.filter((v) => v.owner.kind === "OUTCOME_UNKNOWN").map((v) => v.owner.code), ["EFFECT_OUTCOME_UNKNOWN"]);
  assert.equal(corpus.vectors.length, refusalCodes.length + 1, "no vector of another kind");
  assert.equal(new Set(corpus.vectors.map((v) => v.id)).size, corpus.vectors.length, "vector ids are unique");
  // The claim each answer makes: a NOT_COMMITTED code says nothing was written; only OUTCOME_UNKNOWN says it is unknown.
  for (const v of corpus.vectors) assert.equal(v.expect.written, v.owner.kind === "OUTCOME_UNKNOWN" ? "UNKNOWN" : "NOTHING", v.id);
  for (const v of corpus.vectors) {
    const detail = `vector ${v.id}`;
    const outcome: EffectOutcome =
      v.owner.kind === "OUTCOME_UNKNOWN"
        ? { kind: "OUTCOME_UNKNOWN", code: "EFFECT_OUTCOME_UNKNOWN", detail }
        : { kind: "NOT_COMMITTED", code: v.owner.code as EffectRefusalCode, effectId: null, detail };
    const fx = gateWith(`answer-${v.id}`, (owner) => wrapped(owner, { commit: () => outcome }));
    const holdId = approvedTransfer(fx, v.id);
    const r = fx.engine.commit(holdId, fx.agent);
    assert.equal(rowCount(fx.owner), 0, `${v.id}: consequence: nothing is written for an answer without a row`);
    assert.deepEqual([grantOf(fx, holdId).status, grantOf(fx, holdId).reportedAt], ["UNUSED", null], `${v.id}: consequence: the engine records no consumption`);
    const b = r.body as Record<string, unknown>;
    assert.deepEqual(
      { status: r.status, error: b["error"], retryable: b["retryable"], bodyKeys: Object.keys(b).sort() },
      { status: v.expect.status, error: v.expect.error, retryable: v.expect.retryable, bodyKeys: v.expect.bodyKeys },
      v.id,
    );
    assert.equal(b["detail"], detail, `${v.id}: the owner's detail is carried`);
  }
});
