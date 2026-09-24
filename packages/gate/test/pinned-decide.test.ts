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
import { generateKeyPair, verifyArtifact, type KeyPair } from "noa-approval-artifacts";
import { GateEngine, type DisplaySealer } from "../src/engine.js";
import { resolveGateConfig } from "../src/config.js";
import { InMemoryStore, type Store } from "../src/store.js";
import { hashSecret } from "../src/auth.js";
import { loadSchemas } from "../src/schemas.js";
import { getProjection } from "../src/projections.js";
import { createAlphaTrust, type GateTrust } from "../src/trust.js";
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
  x25519Pair,
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

/**
 * THE CONSEQUENCE, asserted before any code: no grant exists, and the hold is exactly as it was —
 * still PENDING, with no resolution signed for it. A knockout that removes a control must turn THIS
 * red, not merely change which refusal code a later check prints.
 */
function nothingHappened(store: Store, holdId: string, what: string): void {
  assert.equal(store.listGrants().length, 0, `consequence: ${what} — no grant may exist`);
  const h = store.getHold(holdId)!;
  assert.equal(h.status, "PENDING", `consequence: ${what} — the hold must stay PENDING`);
  assert.equal(h.holdResolution, null, `consequence: ${what} — no resolution may be signed`);
}

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
  nothingHappened(store, hold.id, "a gate at another epoch");
  assert.equal(r.status, 409, JSON.stringify(r.body));
  assert.equal(errorOf(r), "EPOCH_CHANGED");
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
  nothingHappened(store, hold.id, "a gate for another tenant");
  assert.equal(r.status, 409, JSON.stringify(r.body));
  assert.equal(errorOf(r), "GATE_AUDIENCE_MISMATCH");
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
  nothingHappened(store, hold.id, "a gate with another gate key");
  assert.equal(r.status, 409, JSON.stringify(r.body));
  assert.equal(errorOf(r), "GATE_AUDIENCE_MISMATCH");
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
  nothingHappened(store, hold.id, "an approver who never received the display");
  assert.equal(r.status, 422, JSON.stringify(r.body));
  assert.equal(errorOf(r), "APPROVER_NOT_DISPLAY_RECIPIENT");
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
  nothingHappened(fxA.store, hold.id, "a second alpha trust root");
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
  nothingHappened(store, hold.id, "one approval where the roster asks for two");
  assert.equal(r.status, 500, JSON.stringify(r.body));
  assert.equal(errorOf(r), "QUORUM_UNSUPPORTED");
});

test("K6 — a class the roster does not name is refused at createHold, and at decide on a gate whose roster dropped it", () => {
  const world = newWorld();
  const clock = makeClock();
  const risk = derivedRisk(CRITICAL_PARAMS);
  assert.ok(risk === "CRITICAL" || risk === "IRREVERSIBLE", `fixture: the command must derive above HIGH, got ${risk}`);

  const store = new InMemoryStore();
  const highOnly = engineFor(pinned(world, clock, { quorum: { HIGH: 1 } }), store, clock);
  const refused = createHold(highOnly, "class-create", CRITICAL_PARAMS);
  assert.equal(store.listHolds({}).length, 0, "consequence: nobody is asked to approve a class this gate cannot accept");
  assert.equal(refused.status, 422, JSON.stringify(refused.body));
  assert.equal(errorOf(refused), "RISK_CLASS_NOT_IN_ROSTER");

  const store2 = new InMemoryStore();
  const full = engineFor(pinned(world, clock, { quorum: { HIGH: 1, CRITICAL: 1, IRREVERSIBLE: 1 } }), store2, clock);
  const narrowed = engineFor(pinned(world, clock, { quorum: { HIGH: 1 } }), store2, clock);
  const hold = holdOf(store2, createHold(full, "class-decide", CRITICAL_PARAMS));
  const r = narrowed.engine.decide(hold.id, decision(full.trust, store2, hold.id, world.approver));
  nothingHappened(store2, hold.id, "a class the deciding gate's roster does not name");
  assert.equal(r.status, 422, JSON.stringify(r.body));
  assert.equal(errorOf(r), "RISK_CLASS_NOT_IN_ROSTER");
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
  assert.equal(store.listHolds({}).length, 2, "consequence: an expired roster freezes no new hold");
  assert.equal(c.status, 503, JSON.stringify(c.body));
  assert.equal(errorOf(c), "ROSTER_EXPIRED");
  const d = a.engine.decide(pending.id, late);
  assert.equal(store.listGrants().length, 1, "consequence: an expired roster issues no grant");
  assert.equal(store.getHold(pending.id)!.status, "PENDING", "consequence: the pending hold is left untouched");
  assert.equal(d.status, 503, JSON.stringify(d.body));
  assert.equal(errorOf(d), "ROSTER_EXPIRED");
  const r = a.engine.reserve(grantId, AGENT);
  assert.equal(store.getGrant(grantId)!.status, "UNUSED", "consequence: an expired roster reserves nothing");
  assert.equal(r.status, 503, JSON.stringify(r.body));
  assert.equal(errorOf(r), "ROSTER_EXPIRED");
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
  // The live keyring's own consumer, first: a decision the revoked key signed must not verify.
  const revokedDecision = signPhoneDecision({
    trust: a.trust, deferredReceipt: hold.deferredReceipt, holdEnvelope: hold.holdEnvelope, decision: "APPROVE",
    signer: { kid: old.kid, privateKey: old.ed.privateKey },
  }).decisionArtifact;
  const verdict = verifyArtifact(body(revokedDecision), body({
    schemas, keyring: a.trust.keyring, now: new Date(clock.t).toISOString(), authorizationTime: new Date(clock.t).toISOString(), riskClass: "HIGH",
  }));
  assert.equal(verdict.ok, false, "consequence: the live keyring must refuse a decision signed by a revoked approver");
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
    assert.equal(fx.store.listHolds({}).length, 0, `consequence: ${name} — no hold is frozen with a display a party the gate never named can open`);
    assert.equal(r.status, 422, `${name}: ${JSON.stringify(r.body)}`);
    assert.equal(errorOf(r), "DISPLAY_EGRESS_AAD_MISMATCH");
  }
  // The pinned gate runs the same egress check.
  const world = newWorld();
  const clock = makeClock();
  const store = new InMemoryStore();
  const p = engineFor(pinned(world, clock), store, clock, appending);
  const r = createHold(p, "egress-pinned");
  assert.equal(store.listHolds({}).length, 0, "consequence: the pinned gate freezes nothing either");
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
  assert.equal(store.listGrants().length, 0, "consequence: an approver before its declared activation mints no grant");
  assert.equal(r.status, 422, JSON.stringify(r.body));
  assert.match(JSON.stringify(r.body), /before its validFrom/);
});

// ── QA round 1: nothing is signed for a hold this trust root does not own ─────────────────────────

test("a foreign gate on a shared store signs nothing for another gate's holds: decide, sweep, read, cancel, report and uncertainty all leave them untouched", () => {
  const world = newWorld();
  const clock = makeClock();
  const store = new InMemoryStore();
  const a = engineFor(pinned(world, clock), store, clock);
  const b = engineFor(pinned(world, clock, { tenant: "tenant-example-2", epoch: { keyManifestVersion: 3, keyManifestHash: "sha256:" + "3".repeat(64) } }), store, clock);
  const pending = holdOf(store, createHold(a, "foreign-pending"));
  const granted = holdOf(store, createHold(a, "foreign-granted"));
  const unreserved = holdOf(store, createHold(a, "foreign-unreserved"));
  assert.equal(a.engine.decide(granted.id, decision(a.trust, store, granted.id, world.approver)).status, 200);
  assert.equal(a.engine.decide(unreserved.id, decision(a.trust, store, unreserved.id, world.approver)).status, 200);
  const grantId = store.getHold(granted.id)!.grantId!;
  const openGrantId = store.getHold(unreserved.id)!.grantId!;
  assert.equal(a.engine.reserve(grantId, AGENT).status, 200);
  // A foreign gate may not burn another gate's single use, even while the grant is still valid.
  const foreignReserve = b.engine.reserve(openGrantId, AGENT);
  assert.equal(store.getGrant(openGrantId)!.status, "UNUSED", "consequence: a foreign gate reserves nothing");
  assert.equal(foreignReserve.status, 409, JSON.stringify(foreignReserve.body));
  clock.advance(24 * HOUR); // the pending hold is overdue and the reserved grant is stuck

  const d = b.engine.decide(pending.id, body({}));
  const e = store.getHold(pending.id)!;
  assert.equal(e.status, "PENDING", "consequence: decide by a foreign gate must not expire the hold");
  assert.equal(e.holdResolution, null, "consequence: decide by a foreign gate must not sign a resolution");
  assert.equal(d.status, 409, JSON.stringify(d.body));

  assert.equal(b.engine.sweepExpired(), 0, "consequence: a foreign sweep expires nothing");
  assert.equal(b.engine.getHold(pending.id, AGENT).status, 200);
  const c = b.engine.cancelLocalStateLost(pending.id, AGENT);
  const afterForeign = store.getHold(pending.id)!;
  assert.equal(afterForeign.status, "PENDING", "consequence: no foreign sweep, read or cancel changes the hold");
  assert.equal(afterForeign.holdResolution, null, "consequence: no foreign sweep, read or cancel signs for it");
  assert.equal(c.status, 409, JSON.stringify(c.body));

  const rep = b.engine.report(grantId, body({ result: "DISPATCHED" }), AGENT);
  assert.equal(store.getGrant(grantId)!.consumption, null, "consequence: a foreign gate signs no consumption");
  assert.equal(store.getGrant(grantId)!.reportedAt, null, "consequence: a foreign report changes no grant state");
  assert.equal(rep.status, 409, JSON.stringify(rep.body));
  assert.equal(b.engine.sweepUncertainty(), 0, "consequence: a foreign sweep signs no uncertainty");
  assert.equal(store.getGrant(grantId)!.uncertainty, null, "consequence: a foreign sweep signs no uncertainty");

  // Transition the reorder creates: an already-resolved hold now meets the binding check first.
  const resolved = b.engine.decide(granted.id, decision(a.trust, store, granted.id, world.approver));
  assert.equal(errorOf(resolved), "GATE_AUDIENCE_MISMATCH", "a foreign gate is refused as foreign even for a resolved hold");

  // Positive control: the owning gate does sign these.
  assert.equal(a.engine.sweepExpired(), 1);
  assert.equal(store.getHold(pending.id)!.status, "EXPIRED");
  assert.equal(a.engine.sweepUncertainty(), 1);
});

test("expiry stops authority, not recording: after the roster expires, decide refuses without expiring, but a timeout, a cancellation and a reported execution are still recorded", () => {
  const world = newWorld();
  const clock = makeClock();
  const t0 = clock.t;
  const store = new InMemoryStore();
  const a = engineFor(pinned(world, clock, { expiresAt: new Date(t0 + 2 * MIN).toISOString() }), store, clock);
  const overdue = holdOf(store, createHold(a, "exp-overdue"));
  const toCancel = holdOf(store, createHold(a, "exp-cancel"));
  const resolved = holdOf(store, createHold(a, "exp-resolved"));
  assert.equal(a.engine.decide(resolved.id, decision(a.trust, store, resolved.id, world.approver)).status, 200);
  const grantId = store.getHold(resolved.id)!.grantId!;
  assert.equal(a.engine.reserve(grantId, AGENT).status, 200, "authorized and reserved before the roster expired");
  clock.advance(3 * MIN); // the roster expired at t0+2min; the holds (15 min) have not

  // AUTHORITY stops: decide refuses before it touches the hold, and a decided hold meets ROSTER_EXPIRED first.
  const late = a.engine.decide(toCancel.id, body({}));
  assert.equal(late.status, 503, JSON.stringify(late.body));
  assert.equal(errorOf(a.engine.decide(resolved.id, body({}))), "ROSTER_EXPIRED", "transition: ROSTER_EXPIRED now precedes HOLD_ALREADY_RESOLVED");

  // RECORDING continues: the execution authorized before expiry is recorded and signed.
  const reported = a.engine.report(grantId, body({ result: "DISPATCHED" }), AGENT);
  assert.ok(store.getGrant(grantId)!.consumption, "consequence: an execution reported after expiry is still recorded and signed");
  assert.equal(reported.status, 200, JSON.stringify(reported.body));
  // ...a local-state loss still closes its hold...
  const cancelled = a.engine.cancelLocalStateLost(toCancel.id, AGENT);
  assert.equal(store.getHold(toCancel.id)!.status, "CANCELLED_LOCAL_STATE_LOST", "consequence: a cancel after expiry still closes the hold");
  assert.ok(store.getHold(toCancel.id)!.holdResolution, "consequence: the cancellation is signed");
  assert.equal(cancelled.status, 200, JSON.stringify(cancelled.body));
  // ...and an overdue hold still gets its timeout.
  clock.advance(24 * HOUR);
  assert.equal(a.engine.sweepExpired(), 1, "consequence: the sweep still records the timeout");
  assert.equal(store.getHold(overdue.id)!.status, "EXPIRED");
});

test("a pinned grant never outlives its roster: the signed expiresAt is clamped to the roster's expiresAt", () => {
  const world = newWorld();
  const clock = makeClock();
  const t0 = clock.t;
  const rosterExpiry = t0 + 2 * MIN;
  const store = new InMemoryStore();
  const a = engineFor(pinned(world, clock, { expiresAt: new Date(rosterExpiry).toISOString() }), store, clock);
  const hold = holdOf(store, createHold(a, "clamp"));
  clock.advance(MIN);
  assert.equal(a.engine.decide(hold.id, decision(a.trust, store, hold.id, world.approver)).status, 200);
  const grant = store.getGrant(store.getHold(hold.id)!.grantId!)!.grant;
  assert.ok(Date.parse(grant.expiresAt) <= rosterExpiry, `consequence: the signed grant must not outlive the roster (${grant.expiresAt})`);
  assert.equal(grant.expiresAt, new Date(rosterExpiry).toISOString());
});

test("the requested recipients must be distinct: an alpha approver kid equal to the audit kid is refused at egress (DISPLAY_EGRESS_AAD_MISMATCH)", () => {
  const clock = makeClock();
  const approverEd = generateKeyPair("audit-1");
  const trust = createAlphaTrust({
    tenant: "alpha-tenant",
    now: () => clock.t,
    ids,
    approverPublicKey: { kid: "audit-1", publicKey: approverEd.publicKey, hpkePublicKey: x25519Pair().publicKey },
  });
  assert.equal(trust.auditKid, "audit-1", "fixture: the approver kid equals the audit kid");
  const store = new InMemoryStore();
  const e = engineFor(trust, store, clock);
  const r = createHold(e, "dup-recipient");
  assert.equal(store.listHolds({}).length, 0, "consequence: no hold is frozen with one party sealed twice");
  assert.equal(r.status, 422, JSON.stringify(r.body));
  assert.equal(errorOf(r), "DISPLAY_EGRESS_AAD_MISMATCH");
});
