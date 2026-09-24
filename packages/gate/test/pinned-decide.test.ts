/**
 * Pinned trust — what a PINNED trust root changes at `createHold`, `decide` and `reserve`, and the checks that
 * run in BOTH modes (audience, epoch, display recipient, exact-set egress).
 *
 * THE SHAPE OF MOST ATTACKS BELOW: two engines share ONE store and differ in exactly one trust fact
 * (epoch, gate key, active approver, quorum). A hold is frozen by engine A; a decision reaches engine
 * B. With the in-memory store a restart already loses every hold, so these checks become load-bearing
 * exactly when a store outlives or is shared across trust roots — which is what a durable store does.
 * Each attack is preceded by its positive control: the SAME decision is accepted where it belongs.
 *
 * Proof ID referenced by scripts/resolver-inventory.json — do not rename without updating it:
 *   [PROOF:RES-PAR-GATE-PINNED-KEYRING]
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair, type KeyPair } from "noa-approval-artifacts";
import { GateEngine, type DisplaySealer } from "../src/engine.js";
import { resolveGateConfig } from "../src/config.js";
import { InMemoryStore, type Store } from "../src/store.js";
import { hashSecret } from "../src/auth.js";
import { loadSchemas } from "../src/schemas.js";
import { getProjection } from "../src/projections.js";
import type { GateTrust } from "../src/trust.js";
import type { AgentRecord, HoldEnvelope } from "../src/types.js";
import { body, makeClock, sampleCommandParams, setupGate, signPhoneDecision, testSealer, type Clock } from "./helpers.js";
import {
  AUDIT_KID,
  EXEC_KID,
  GATE_KID,
  approverKeys,
  newWorld,
  pinnedTrustFrom,
  rosterDoc,
  type ApproverKeys,
  type RosterWorld,
} from "./helpers/pinned.js";

const HOUR = 60 * 60 * 1000;
const MIN = 60 * 1000;
const schemas = loadSchemas();
const AGENT: AgentRecord = { id: "agent-1", name: "pinned-agent", apiKeyHash: hashSecret("noa_gateagent_pinned"), createdAt: 0 };

interface Engine {
  engine: GateEngine;
  trust: GateTrust;
}

function engineFor(trust: GateTrust, store: Store, clock: Clock, sealer: DisplaySealer = testSealer): Engine {
  const now = () => clock.t;
  store.putAgent(AGENT);
  const engine = new GateEngine({ store, config: resolveGateConfig({ now }), trust, schemas, sealDisplay: sealer, unsafeInProcessGrantKey: true });
  return { engine, trust };
}

let idSeq = 0;
const ids = () => `pin-${(idSeq++).toString(16).padStart(8, "0")}`;

function pinned(world: RosterWorld, clock: Clock, over: Record<string, unknown> = {}, gateKey: KeyPair = world.gate): GateTrust {
  return pinnedTrustFrom(rosterDoc(world, clock.t, over), gateKey, { now: () => clock.t, ids });
}

/** Roster `approvers` with exactly one active approver `a`. */
function only(a: ApproverKeys, validFrom: number): Record<string, unknown> {
  return {
    [a.kid]: { role: "approve-critical", publicKey: a.ed.publicKey, hpkePublicKey: a.x.publicKey, validFrom: new Date(validFrom).toISOString(), revokedAt: null },
  };
}

const HIGH_PARAMS = sampleCommandParams();
const CRITICAL_PARAMS = sampleCommandParams({ executable: "/bin/rm", argv: ["-rf", "/srv"] });
function derivedRisk(params: Record<string, unknown>): string {
  const run = getProjection("noa.command.exec")!.run(params);
  assert.ok(run.ok, "fixture command must project");
  return run.derivedRisk;
}

function createHold(e: Engine, chain: string, params: Record<string, unknown> = HIGH_PARAMS) {
  return e.engine.createHold(AGENT, `idem-${chain}`, body({
    mode: "ENFORCED",
    action: { canonical: "noa.command.exec", riskClass: "HIGH", reversible: false },
    params,
    chain,
  }));
}

function holdOf(store: Store, created: { status: number; body: unknown }) {
  assert.equal(created.status, 201, JSON.stringify(created.body));
  const holdId = (created.body as { holdId: string }).holdId;
  return store.getHold(holdId)!;
}

function decision(trust: GateTrust, store: Store, holdId: string, signer: ApproverKeys, d: "APPROVE" | "DENY" = "APPROVE", extra: Record<string, unknown> = {}) {
  const hold = store.getHold(holdId)!;
  const signed = signPhoneDecision({
    trust,
    deferredReceipt: hold.deferredReceipt,
    holdEnvelope: hold.holdEnvelope as HoldEnvelope,
    decision: d,
    signer: { kid: signer.kid, privateKey: signer.ed.privateKey },
  });
  return body({ ...signed, ...extra });
}

const errorOf = (r: { body: unknown }): string | undefined => (r.body as { error?: string }).error;

// ── positive paths ──────────────────────────────────────────────────────────────────────────────

test("CONTROL — a pinned gate freezes, seals to the roster's approver + audit, and grants on the roster approver's decision", () => {
  const world = newWorld();
  const clock = makeClock();
  const store = new InMemoryStore();
  const a = engineFor(pinned(world, clock), store, clock);
  const hold = holdOf(store, createHold(a, "pos"));
  assert.equal(hold.holdEnvelope.gateKid, GATE_KID);
  assert.equal(hold.holdEnvelope.keyManifestVersion, 2);
  assert.equal(hold.holdEnvelope.keyManifestHash, "sha256:" + "2".repeat(64));
  assert.equal(hold.holdEnvelope.tenant, "tenant-example-1");
  assert.deepEqual((hold.encryptedDisplay.recipients ?? []).map((r) => r.kid), [world.approver.kid, AUDIT_KID]);
  const decided = a.engine.decide(hold.id, decision(a.trust, store, hold.id, world.approver));
  assert.equal(decided.status, 200, JSON.stringify(decided.body));
  assert.equal(store.listGrants().length, 1);
  const reserved = a.engine.reserve(store.getHold(hold.id)!.grantId!, AGENT);
  assert.equal(reserved.status, 200, JSON.stringify(reserved.body));
});

test("a pinned DENY resolves the hold with no grant", () => {
  const world = newWorld();
  const clock = makeClock();
  const store = new InMemoryStore();
  const a = engineFor(pinned(world, clock), store, clock);
  const hold = holdOf(store, createHold(a, "deny"));
  const decided = a.engine.decide(hold.id, decision(a.trust, store, hold.id, world.approver, "DENY"));
  assert.equal(decided.status, 200, JSON.stringify(decided.body));
  assert.equal(store.getHold(hold.id)!.status, "DENIED");
  assert.equal(store.listGrants().length, 0);
});

test("quorum comes only from the roster: body extras (required_approvals, quorum) change nothing", () => {
  const world = newWorld();
  const clock = makeClock();
  const store = new InMemoryStore();
  const a = engineFor(pinned(world, clock), store, clock);
  const hold = holdOf(store, createHold(a, "extras"));
  const decided = a.engine.decide(hold.id, decision(a.trust, store, hold.id, world.approver, "APPROVE", { required_approvals: 2, quorum: { HIGH: 2 } }));
  assert.equal(decided.status, 200, JSON.stringify(decided.body));
  assert.equal(store.listGrants().length, 1);
});

// ── both modes: audience, epoch, display recipient ──────────────────────────────────────────────

test("K1 — a hold frozen under epoch v2 cannot be decided by a gate at epoch v3: 409 EPOCH_CHANGED, hold PENDING, no grant", () => {
  const world = newWorld();
  const clock = makeClock();
  const store = new InMemoryStore();
  const a = engineFor(pinned(world, clock), store, clock);
  const b = engineFor(pinned(world, clock, { epoch: { keyManifestVersion: 3, keyManifestHash: "sha256:" + "3".repeat(64) } }), store, clock);
  const hold = holdOf(store, createHold(a, "epoch"));
  const d = decision(a.trust, store, hold.id, world.approver);
  const r = b.engine.decide(hold.id, d);
  assert.equal(r.status, 409, JSON.stringify(r.body));
  assert.equal(errorOf(r), "EPOCH_CHANGED");
  assert.equal(store.getHold(hold.id)!.status, "PENDING");
  assert.equal(store.listGrants().length, 0);
  // Positive control: the same bytes are accepted by the gate whose epoch the hold carries.
  assert.equal(a.engine.decide(hold.id, d).status, 200);
});

test("K2 — a gate for another tenant cannot grant on this tenant's envelope: 409 GATE_AUDIENCE_MISMATCH (same keys, same epoch)", () => {
  const world = newWorld();
  const clock = makeClock();
  const store = new InMemoryStore();
  const a = engineFor(pinned(world, clock), store, clock);
  // Everything but the tenant is identical, so no signature, chain or epoch check can tell the two
  // gates apart: the audience check is the only thing between B and a grant on A's hold.
  const b = engineFor(pinned(world, clock, { tenant: "tenant-example-2" }), store, clock);
  const hold = holdOf(store, createHold(a, "audience"));
  const d = decision(a.trust, store, hold.id, world.approver);
  const r = b.engine.decide(hold.id, d);
  assert.equal(r.status, 409, JSON.stringify(r.body));
  assert.equal(errorOf(r), "GATE_AUDIENCE_MISMATCH");
  assert.equal(store.getHold(hold.id)!.status, "PENDING");
  assert.equal(store.listGrants().length, 0);
  assert.equal(a.engine.decide(hold.id, d).status, 200);
});

test("audience — a gate with another gate key is refused by kid before any signature work (GATE_AUDIENCE_MISMATCH)", () => {
  const world = newWorld();
  const clock = makeClock();
  const store = new InMemoryStore();
  const a = engineFor(pinned(world, clock), store, clock);
  const b = engineFor(pinned({ ...world, gate: generateKeyPair("gate-example-2") }, clock), store, clock);
  const hold = holdOf(store, createHold(a, "audience-key"));
  const r = b.engine.decide(hold.id, decision(a.trust, store, hold.id, world.approver));
  assert.equal(r.status, 409, JSON.stringify(r.body));
  assert.equal(errorOf(r), "GATE_AUDIENCE_MISMATCH");
  assert.equal(store.listGrants().length, 0);
});

test("K3 — an approver who was never sent the display cannot approve it: 422 APPROVER_NOT_DISPLAY_RECIPIENT (same epoch, same gate key)", () => {
  const world = newWorld();
  const clock = makeClock();
  const store = new InMemoryStore();
  const a = engineFor(pinned(world, clock), store, clock);
  const y = approverKeys(2);
  // Engine B's roster names Y as its active approver; nothing about the epoch or the gate changed, so
  // the epoch check alone cannot see this case.
  const b = engineFor(pinned(world, clock, { approvers: only(y, clock.t - HOUR) }), store, clock);
  const hold = holdOf(store, createHold(a, "recipient"));
  assert.deepEqual((hold.encryptedDisplay.recipients ?? []).map((r) => r.kid), [world.approver.kid, AUDIT_KID]);
  const r = b.engine.decide(hold.id, decision(b.trust, store, hold.id, y));
  assert.equal(r.status, 422, JSON.stringify(r.body));
  assert.equal(errorOf(r), "APPROVER_NOT_DISPLAY_RECIPIENT");
  assert.equal(store.getHold(hold.id)!.status, "PENDING");
  assert.equal(store.listGrants().length, 0);
});

test("alpha too: two alpha trust roots sharing one store — the second cannot decide the first's hold (EPOCH_CHANGED)", () => {
  const fxA = setupGate({ approverRole: "approve-critical" });
  const fxB = setupGate({ approverRole: "approve-critical", store: fxA.store });
  fxB.clock.t = fxA.clock.t;
  const created = fxA.engine.createHold(fxA.agent, "idem-alpha-shared", body({
    mode: "ENFORCED",
    action: { canonical: "noa.command.exec", riskClass: "HIGH", reversible: false },
    params: HIGH_PARAMS,
    chain: "alpha-shared",
  }));
  const hold = holdOf(fxA.store, created);
  const signed = signPhoneDecision({ trust: fxA.trust, deferredReceipt: hold.deferredReceipt, holdEnvelope: hold.holdEnvelope, decision: "APPROVE" });
  const r = fxB.engine.decide(hold.id, body(signed));
  assert.equal(r.status, 409, JSON.stringify(r.body));
  assert.equal(errorOf(r), "EPOCH_CHANGED");
  assert.equal(fxA.engine.decide(hold.id, body(signed)).status, 200);
});

// ── pinned only: quorum, class, expiry ──────────────────────────────────────────────────────────

test("K5 — an injected trust whose roster quorum is 2 refuses at decide: 500 QUORUM_UNSUPPORTED, never a one-approval grant", () => {
  const world = newWorld();
  const clock = makeClock();
  const store = new InMemoryStore();
  const trustA = pinned(world, clock);
  const a = engineFor(trustA, store, clock);
  // createGate accepts an injected GateTrust; the loader's refusal of q=2 does not protect this path.
  const injected: GateTrust = { ...trustA, pinned: Object.freeze({ ...trustA.pinned!, quorum: Object.freeze({ HIGH: 2, CRITICAL: 2 }) }) };
  const b = engineFor(injected, store, clock);
  const hold = holdOf(store, createHold(a, "quorum"));
  const r = b.engine.decide(hold.id, decision(a.trust, store, hold.id, world.approver));
  assert.equal(r.status, 500, JSON.stringify(r.body));
  assert.equal(errorOf(r), "QUORUM_UNSUPPORTED");
  assert.equal(store.listGrants().length, 0);
});

test("K6 — a class the roster does not name is refused at createHold, and at decide on a gate whose roster dropped it", () => {
  const world = newWorld();
  const clock = makeClock();
  const risk = derivedRisk(CRITICAL_PARAMS);
  assert.ok(risk === "CRITICAL" || risk === "IRREVERSIBLE", `fixture: the command must derive above HIGH, got ${risk}`);

  const store = new InMemoryStore();
  const highOnly = engineFor(pinned(world, clock, { quorum: { HIGH: 1 } }), store, clock);
  const refused = createHold(highOnly, "class-create", CRITICAL_PARAMS);
  assert.equal(refused.status, 422, JSON.stringify(refused.body));
  assert.equal(errorOf(refused), "RISK_CLASS_NOT_IN_ROSTER");
  assert.equal(store.listHolds({}).length, 0, "nobody is asked to approve a class this gate cannot accept");

  const store2 = new InMemoryStore();
  const full = engineFor(pinned(world, clock, { quorum: { HIGH: 1, CRITICAL: 1, IRREVERSIBLE: 1 } }), store2, clock);
  const narrowed = engineFor(pinned(world, clock, { quorum: { HIGH: 1 } }), store2, clock);
  const hold = holdOf(store2, createHold(full, "class-decide", CRITICAL_PARAMS));
  const r = narrowed.engine.decide(hold.id, decision(full.trust, store2, hold.id, world.approver));
  assert.equal(r.status, 422, JSON.stringify(r.body));
  assert.equal(errorOf(r), "RISK_CLASS_NOT_IN_ROSTER");
  assert.equal(store2.listGrants().length, 0);
});

test("K7 — past the roster's expiresAt the gate authorizes nothing: 503 ROSTER_EXPIRED at createHold, decide and reserve", () => {
  const world = newWorld();
  const clock = makeClock();
  const t0 = clock.t;
  const store = new InMemoryStore();
  const a = engineFor(pinned(world, clock, { expiresAt: new Date(t0 + 4 * MIN).toISOString() }), store, clock);
  const granted = holdOf(store, createHold(a, "exp-granted"));
  const pending = holdOf(store, createHold(a, "exp-pending"));
  clock.advance(MIN);
  assert.equal(a.engine.decide(granted.id, decision(a.trust, store, granted.id, world.approver)).status, 200);
  const grantId = store.getHold(granted.id)!.grantId!;
  const late = decision(a.trust, store, pending.id, world.approver);
  clock.advance(4 * MIN); // t0+5min: the roster expired at t0+4min; the hold and the grant have not.

  const c = createHold(a, "exp-new");
  assert.equal(c.status, 503, JSON.stringify(c.body));
  assert.equal(errorOf(c), "ROSTER_EXPIRED");
  const d = a.engine.decide(pending.id, late);
  assert.equal(d.status, 503, JSON.stringify(d.body));
  assert.equal(errorOf(d), "ROSTER_EXPIRED");
  assert.equal(store.getHold(pending.id)!.status, "PENDING");
  const r = a.engine.reserve(grantId, AGENT);
  assert.equal(r.status, 503, JSON.stringify(r.body));
  assert.equal(errorOf(r), "ROSTER_EXPIRED");
  assert.equal(store.getGrant(grantId)!.status, "UNUSED");
});

// ── keys the roster does not vouch for ──────────────────────────────────────────────────────────

test("a revoked roster approver is refused as revoked; a key the roster never named is refused; neither yields a grant", () => {
  const world = newWorld();
  const clock = makeClock();
  const old = approverKeys(7);
  const approvers = {
    ...only(world.approver, clock.t - HOUR),
    [old.kid]: { role: "approve-critical", publicKey: old.ed.publicKey, hpkePublicKey: old.x.publicKey, validFrom: new Date(clock.t - 10 * HOUR).toISOString(), revokedAt: new Date(clock.t - 2 * HOUR).toISOString() },
  };
  const store = new InMemoryStore();
  const a = engineFor(pinned(world, clock, { approvers }), store, clock);
  const hold = holdOf(store, createHold(a, "revoked"));
  const revoked = a.engine.decide(hold.id, decision(a.trust, store, hold.id, old));
  assert.equal(revoked.status, 422, JSON.stringify(revoked.body));
  assert.equal(errorOf(revoked), "DECISION_ARTIFACT_INVALID");
  assert.match(JSON.stringify(revoked.body), /revoked/);

  const stranger = approverKeys(5); // a delegate key issued somewhere else: never in the roster
  const unknown = a.engine.decide(hold.id, decision(a.trust, store, hold.id, stranger));
  assert.equal(unknown.status, 422, JSON.stringify(unknown.body));
  assert.equal(errorOf(unknown), "DECISION_ARTIFACT_INVALID");
  assert.equal(store.listGrants().length, 0);
});

test("a decision for hold A replayed on hold B is refused by the envelope binding", () => {
  const world = newWorld();
  const clock = makeClock();
  const store = new InMemoryStore();
  const a = engineFor(pinned(world, clock), store, clock);
  const h1 = holdOf(store, createHold(a, "replay-1"));
  const h2 = holdOf(store, createHold(a, "replay-2"));
  const r = a.engine.decide(h2.id, decision(a.trust, store, h1.id, world.approver));
  assert.equal(r.status, 422, JSON.stringify(r.body));
  assert.equal(store.listGrants().length, 0);
});

// ── exact-set egress (both modes) ───────────────────────────────────────────────────────────────

test("K16 — a sealer that ADDS a recipient (or repeats one) is refused: 422 DISPLAY_EGRESS_AAD_MISMATCH", () => {
  const appending: DisplaySealer = (args) => {
    const sealed = testSealer(args);
    return { ...sealed, recipients: [...(sealed.recipients ?? []), { kid: "eavesdropper-1", enc: "ZW5j", wrappedCek: "Y2Vr" }] };
  };
  const repeating: DisplaySealer = (args) => {
    const sealed = testSealer(args);
    const first = (sealed.recipients ?? [])[0]!;
    return { ...sealed, recipients: [first, first] };
  };
  for (const [name, sealer] of [["append", appending], ["repeat", repeating]] as const) {
    const fx = setupGate({ approverRole: "approve-critical", sealer });
    const r = fx.engine.createHold(fx.agent, `idem-egress-${name}`, body({
      mode: "ENFORCED",
      action: { canonical: "noa.command.exec", riskClass: "HIGH", reversible: false },
      params: HIGH_PARAMS,
      chain: `egress-${name}`,
    }));
    assert.equal(r.status, 422, `${name}: ${JSON.stringify(r.body)}`);
    assert.equal(errorOf(r), "DISPLAY_EGRESS_AAD_MISMATCH");
    assert.equal(fx.store.listHolds({}).length, 0);
  }
  // The pinned gate runs the same egress check.
  const world = newWorld();
  const clock = makeClock();
  const store = new InMemoryStore();
  const p = engineFor(pinned(world, clock), store, clock, appending);
  const r = createHold(p, "egress-pinned");
  assert.equal(errorOf(r), "DISPLAY_EGRESS_AAD_MISMATCH");
});

// ── resolver parity for the pinned keyring ──────────────────────────────────────────────────────

test("[PROOF:RES-PAR-GATE-PINNED-KEYRING] every roster-declared activation and revocation survives into the live keyrings", () => {
  const world = newWorld();
  const clock = makeClock();
  const old = approverKeys(7);
  const exec = generateKeyPair(EXEC_KID);
  const doc = rosterDoc(world, clock.t, {
    executionSigner: { kid: exec.kid, publicKey: exec.publicKey },
    approvers: {
      ...only(world.approver, clock.t - HOUR),
      [old.kid]: { role: "approve-high", publicKey: old.ed.publicKey, hpkePublicKey: old.x.publicKey, validFrom: new Date(clock.t - 10 * HOUR).toISOString(), revokedAt: new Date(clock.t - 2 * HOUR).toISOString() },
    },
  });
  const trust = pinnedTrustFrom(doc, world.gate, { now: () => clock.t, ids });
  const declared = doc["approvers"] as Record<string, { role: string; publicKey: string; validFrom: string; revokedAt: string | null }>;
  for (const [kid, d] of Object.entries(declared)) {
    const e = trust.keyring[kid];
    assert.ok(e, `approver ${kid} has no keyring entry`);
    assert.equal(e.type, "APPROVER");
    assert.deepEqual([...e.roles], [d.role]);
    assert.equal(e.publicKey, d.publicKey);
    assert.equal(e.validFrom, d.validFrom, `${kid}: declared validFrom not carried`);
    assert.equal(e.revokedAt, d.revokedAt, `${kid}: declared revokedAt not carried`);
    assert.equal(trust.receiptKeyring.keys[kid]?.publicKey, d.publicKey);
    assert.equal(trust.receiptKeyring.keys[kid]?.retiredAt, d.revokedAt, `${kid}: revocation not carried as retirement`);
  }
  const gate = trust.keyring[GATE_KID];
  assert.ok(gate);
  assert.equal(gate.validFrom, doc["validFrom"]);
  assert.equal(gate.revokedAt, null);
  assert.deepEqual([...gate.roles], ["hold-signer"]);
  assert.equal(trust.keyring[EXEC_KID]?.validFrom, doc["validFrom"]);
  const types = Object.values(trust.keyring).map((e) => e.type).sort();
  assert.deepEqual(types, ["APPROVER", "APPROVER", "GATE", "GATE"], "no ROOT or DELEGATED entry exists in a pinned keyring");
  assert.ok(Object.isFrozen(trust.keyring) && Object.getPrototypeOf(trust.keyring) === null);
});

test("[PROOF:RES-PAR-GATE-PINNED-KEYRING] live engine: an approver whose declared activation is in the future cannot mint a grant", () => {
  const world = newWorld();
  const clock = makeClock();
  // createPinnedTrust does not re-run the load-time clock check, and createGate accepts an injected
  // trust: the declared activation must still be enforced where the decision is verified.
  const trust = pinned(world, clock, { approvers: only(world.approver, clock.t + HOUR) });
  const store = new InMemoryStore();
  const a = engineFor(trust, store, clock);
  const hold = holdOf(store, createHold(a, "future-approver"));
  const r = a.engine.decide(hold.id, decision(trust, store, hold.id, world.approver));
  assert.equal(r.status, 422, JSON.stringify(r.body));
  assert.match(JSON.stringify(r.body), /before its validFrom/);
  assert.equal(store.listGrants().length, 0);
});
