/**
 * Test fixtures for the effect-owned commit path (docs/gate-effect-owner.md). Every key is generated in
 * the test process. Identifiers are synthetic: `tenant-example-1`, `gate-example-1`,
 * `approver-example-N`, `agent-example-N`, `acct-example-N`, `ledger-example-N`.
 *
 * The gate runs on a PINNED trust root (an effect owner refuses any other), with a counting execution
 * signer so a test can assert how many attestations a commit signed.
 */
import { refHash, receiptRefHash, signArtifact, type KeyPair } from "noa-approval-artifacts";
import { buildReceipt, LEDGER_TRANSFER_CANONICAL, projectLedgerTransfer } from "noa-receipt";
import { GateEngine, type GateEngineDeps } from "../../src/engine.js";
import { resolveGateConfig, type GateConfig } from "../../src/config.js";
import { InMemoryStore, type Store } from "../../src/store.js";
import { hashSecret } from "../../src/auth.js";
import { loadSchemas } from "../../src/schemas.js";
import { executionDomainFor, localExecutionSigner, type ExecutionSigner, type GrantApprovalProof } from "../../src/exec-signer.js";
import {
  buildEffectAttestation,
  createInMemoryLedgerEffectOwner,
  type EffectAttestation,
  type EffectCommitInput,
  type EffectOwner,
  type VerifiedAuthority,
} from "../../src/effect-owner.js";
import type { GateTrust } from "../../src/trust.js";
import type { AgentRecord, ExecutionGrant, GrantRecord, HoldEnvelope, HoldRecord, Receipt } from "../../src/types.js";
import { body, makeClock, signPhoneDecision, testSealer, type Clock } from "../helpers.js";
import { newWorld, pinnedTrustFrom, rosterDoc, type ApproverKeys, type RosterWorld } from "./pinned.js";
import { b } from "./bytes.js";

export const LEDGER = "ledger-example-1";
export const OTHER_LEDGER = "ledger-example-2";
export const ACCT_1 = "acct-example-1";
export const ACCT_2 = "acct-example-2";
export const ACCT_3 = "acct-example-3";
export const SALT = "000102030405060708090a0b0c0d0e0f";
export const MIN = 60 * 1000;
export const HOUR = 60 * MIN;

/** A six-member transfer. The default moves 100 XTS from acct-example-1 to acct-example-2. */
export function transfer(over: Record<string, string> = {}): Record<string, string> {
  return { amount: "100", fromAccount: ACCT_1, ledger: LEDGER, salt: SALT, toAccount: ACCT_2, unit: "XTS", ...over };
}

/** The canonical text of a transfer, as the kernel emits it. */
export function canonicalOf(params: Record<string, string>): string {
  const r = projectLedgerTransfer(JSON.stringify(params));
  if (!r.ok) throw new Error(`fixture transfer refused: ${r.reason}`);
  return r.canonical;
}

let idSourceSeq = 0;

/**
 * An id source with its own prefix, distinct for every call: two trust roots never share a bootId or any
 * id, even when a test builds the same fixture twice. (One effect-owning engine serves a boot per
 * process, so fixtures must not collide on boots.)
 */
export function idSource(prefix: string): () => string {
  const tag = `${prefix}.${(idSourceSeq++).toString(16)}`;
  let n = 0;
  return () => `${tag}-${(n++).toString(16).padStart(8, "0")}`;
}

/** The in-process signer, counting what it signs; `failAttestations` makes the next N attestations throw. */
export interface CountingSigner extends ExecutionSigner {
  readonly counts: { grant: number; attestation: number };
  failAttestations: number;
}
export function countingSigner(trust: GateTrust): CountingSigner {
  const inner = localExecutionSigner(trust.gate);
  const counts = { grant: 0, attestation: 0 };
  const signer: CountingSigner = {
    kid: inner.kid,
    publicKey: inner.publicKey,
    counts,
    failAttestations: 0,
    signGrant<T extends Record<string, unknown>>(doc: T, proof: GrantApprovalProof) {
      counts.grant++;
      return inner.signGrant(doc, proof);
    },
    signAttestation<T extends Record<string, unknown>>(doc: T) {
      if (signer.failAttestations > 0) {
        signer.failAttestations--;
        throw new Error("test: the execution signer is unavailable");
      }
      counts.attestation++;
      return inner.signAttestation(doc);
    },
  };
  return signer;
}

export interface EffectGate {
  world: RosterWorld;
  clock: Clock;
  trust: GateTrust;
  store: Store;
  engine: GateEngine;
  /** null when built with `owner: false`. */
  owner: EffectOwner | null;
  signer: CountingSigner;
  agent: AgentRecord;
  other: AgentRecord;
}

export const AGENT_1: AgentRecord = { id: "agent-example-1", name: "agent-example-1", apiKeyHash: hashSecret("noa_gateagent_example_1"), createdAt: 0 };
export const AGENT_2: AgentRecord = { id: "agent-example-2", name: "agent-example-2", apiKeyHash: hashSecret("noa_gateagent_example_2"), createdAt: 0 };
export const AGENT_1_SECRET = "noa_gateagent_example_1";

export const DEFAULT_ACCOUNTS: Readonly<Record<string, number>> = { [ACCT_1]: 1000, [ACCT_2]: 0, [ACCT_3]: 50 };

/**
 * Builds the effect owner a fixture runs: the in-memory reference owner by default, or any other owner
 * under test (the owner conformance runner, test/effect-owner-conformance.ts). `store` is the store the
 * fixture's engine uses; an owner that records the grant's consumption itself writes there.
 */
export type EffectOwnerFactory = (o: {
  trust: GateTrust;
  now: () => number;
  ledger: string;
  accounts: Readonly<Record<string, number>>;
  store: Store;
}) => EffectOwner;

export const inMemoryOwnerFactory: EffectOwnerFactory = (o) =>
  createInMemoryLedgerEffectOwner({ trust: o.trust, now: o.now, ledger: o.ledger, accounts: o.accounts });

/**
 * The in-memory reference owner as an owner that records the grant's consumption itself, in the store
 * it is built over (`recordsGrantConsumption`, `store`): after a new EXECUTED row it takes the grant's
 * report lock and writes the consumption there, as the engine's mirror would, and the engine leaves
 * the grant record to it. The engine refuses it over any other store (EFFECT_OWNER_STORE_MISMATCH), so
 * it runs the owner conformance runner only with the runner's stores paired. A test double, not a
 * durable owner: its row and the grant record are two writes.
 */
export const recordingOwnerFactory: EffectOwnerFactory = (o) => {
  const inner = inMemoryOwnerFactory(o);
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
    commit(input, seal) {
      const outcome = inner.commit(input, seal);
      if (outcome.kind === "EXECUTED" && !outcome.idempotent) {
        const locked = o.store.claimGrantReported(outcome.row.grantId, o.now());
        if (locked !== null) {
          locked.consumption = outcome.row.attestation !== null ? outcome.row.attestation.executionConsumption : null;
          o.store.putGrant(locked);
        }
      }
      return outcome;
    },
    inspect: () => inner.inspect(),
    recordsGrantConsumption: true,
    store: o.store,
  };
};

/**
 * A pinned gate with (by default) an in-memory ledger owner. Pass the same `world`, `clock`, `store` and
 * `roster` document with a different `ids` prefix to model a RESTART: same roster, gate key and epoch,
 * a new bootId, and a new (empty-history) ledger owner.
 */
export function effectGate(opts: {
  world?: RosterWorld;
  clock?: Clock;
  store?: Store;
  ids?: () => string;
  roster?: Record<string, unknown>;
  owner?: boolean;
  ledger?: string;
  accounts?: Readonly<Record<string, number>>;
  config?: Partial<GateConfig>;
  log?: (event: string, fields: Record<string, unknown>) => void;
  /** Builds the engine from its dependencies (default `new GateEngine(deps)`), e.g. through `createGate`. */
  makeEngine?: (deps: GateEngineDeps) => GateEngine;
  /** Builds the effect owner (default: the in-memory reference owner). */
  ownerFactory?: EffectOwnerFactory;
} = {}): EffectGate {
  const world = opts.world ?? newWorld();
  const clock = opts.clock ?? makeClock();
  const now = () => clock.t;
  const trust = pinnedTrustFrom(opts.roster ?? rosterDoc(world, clock.t), world.gate, { now, ids: opts.ids ?? idSource("fx") });
  const store = opts.store ?? new InMemoryStore();
  store.putAgent(AGENT_1);
  store.putAgent(AGENT_2);
  const signer = countingSigner(trust);
  const owner = opts.owner === false
    ? null
    : (opts.ownerFactory ?? inMemoryOwnerFactory)({ trust, now, ledger: opts.ledger ?? LEDGER, accounts: opts.accounts ?? DEFAULT_ACCOUNTS, store });
  const deps: GateEngineDeps = {
    store,
    config: resolveGateConfig({ now, ...(opts.config ?? {}) }),
    trust,
    schemas: loadSchemas(),
    sealDisplay: testSealer,
    executionSigner: signer,
    effectOwners: owner === null ? [] : [owner],
    ...(opts.log ? { log: opts.log } : {}),
  };
  const engine = opts.makeEngine ? opts.makeEngine(deps) : new GateEngine(deps);
  return { world, clock, trust, store, engine, owner, signer, agent: AGENT_1, other: AGENT_2 };
}

/** The createHold request body for a transfer. `action` members can be overridden or added. */
export function transferRequest(chain: string, params: Record<string, string> = transfer(), action: Record<string, unknown> = {}, extra: Record<string, unknown> = {}): Uint8Array {
  return body({ action: { canonical: LEDGER_TRANSFER_CANONICAL, riskClass: "HIGH", ...action }, params, chain, ...extra });
}

export function createTransfer(fx: EffectGate, chain: string, params: Record<string, string> = transfer()) {
  return fx.engine.createHold(fx.agent, `idem-${chain}`, transferRequest(chain, params));
}

export function holdIdOf(created: { status: number; body: unknown }): string {
  if (created.status !== 201) throw new Error(`fixture: createHold ${created.status} ${JSON.stringify(created.body)}`);
  return (created.body as { holdId: string }).holdId;
}

/** The roster approver's signed decision for a hold, as body bytes and as the two documents. */
export function decisionFor(fx: EffectGate, holdId: string, decision: "APPROVE" | "DENY" = "APPROVE", approver: ApproverKeys = fx.world.approver) {
  const hold = fx.store.getHold(holdId);
  if (!hold) throw new Error(`fixture: no hold ${holdId}`);
  return signPhoneDecision({
    trust: fx.trust,
    deferredReceipt: hold.deferredReceipt,
    holdEnvelope: hold.holdEnvelope,
    decision,
    signer: { kid: approver.kid, privateKey: approver.ed.privateKey },
  });
}

/** Create a transfer hold and have the roster approver approve it. Returns the hold id. */
export function approvedTransfer(fx: EffectGate, chain: string, params: Record<string, string> = transfer()): string {
  const holdId = holdIdOf(createTransfer(fx, chain, params));
  const decided = fx.engine.decide(holdId, body(decisionFor(fx, holdId)));
  if (decided.status !== 200) throw new Error(`fixture: decide ${decided.status} ${JSON.stringify(decided.body)}`);
  return holdId;
}

export function hold(fx: EffectGate, holdId: string): HoldRecord {
  const h = fx.store.getHold(holdId);
  if (!h) throw new Error(`fixture: no hold ${holdId}`);
  return h;
}

export function grantOf(fx: EffectGate, holdId: string): GrantRecord {
  const h = hold(fx, holdId);
  const g = h.grantId === null ? undefined : fx.store.getGrant(h.grantId);
  if (!g) throw new Error(`fixture: hold ${holdId} has no grant`);
  return g;
}

export function rowCount(owner: EffectOwner | null): number {
  return owner === null ? 0 : owner.inspect().rows.length;
}

export function balanceTotal(owner: EffectOwner): number {
  const balances = owner.inspect().balances;
  let t = 0;
  for (const k of Object.keys(balances)) t += balances[k] as number;
  return t;
}

/** The commit input exactly as the engine assembles it from the store. */
export function ownerInput(fx: EffectGate, holdId: string): EffectCommitInput {
  const h = hold(fx, holdId);
  const g = grantOf(fx, holdId);
  if (h.decisionArtifact === null || h.decisionReceipt === null || h.canonicalParams === null) {
    throw new Error("fixture: the hold is not an approved effect-owned hold");
  }
  return {
    holdId: h.id,
    holdBootId: h.bootId,
    canonicalParams: h.canonicalParams,
    holdEnvelope: h.holdEnvelope,
    deferredReceipt: h.deferredReceipt,
    encryptedDisplay: h.encryptedDisplay,
    decisionArtifact: h.decisionArtifact,
    approvalReceipt: h.decisionReceipt,
    grant: g.grant,
  };
}

let plantedSeq = 0;

/**
 * A grant signed under the execution-grant domain by `key` — the gate key a test holds (a "test-signed"
 * grant: the attacker who can plant store state AND sign with the gate key), or any other key (a forged
 * one). Fields default to the hold's real bindings.
 */
export function signedGrant(fx: EffectGate, holdId: string, key: { kid: string; privateKey: string }, over: Partial<Record<keyof ExecutionGrant, unknown>> = {}, approvalReceipt?: Receipt): ExecutionGrant {
  const h = hold(fx, holdId);
  const approval = approvalReceipt ?? h.decisionReceipt;
  const now = new Date(fx.clock.t).toISOString();
  const doc: Record<string, unknown> = {
    spec: "noa.execution-grant/0.1",
    grantId: `grant-planted-${(plantedSeq++).toString(16).padStart(4, "0")}`,
    holdId: h.id,
    paramsHash: h.action.paramsHash,
    holdEnvelopeHash: refHash(h.holdEnvelope),
    approvalReceiptHash: approval ? receiptRefHash(approval as unknown as Record<string, unknown>) : "sha256:" + "0".repeat(64),
    issuedAt: now,
    expiresAt: new Date(fx.clock.t + 5 * MIN).toISOString(),
    maxUses: 1,
    nonce: "ab".repeat(32),
    ...over,
  };
  return signArtifact(b(doc), executionDomainFor("noa.execution-grant/0.1"), key) as unknown as ExecutionGrant;
}

export function gateKey(world: RosterWorld): { kid: string; privateKey: string } {
  return { kid: world.gate.kid, privateKey: world.gate.privateKey };
}

/**
 * STORE SEAM: mark a hold APPROVED with the given decision, verdict receipt and grant, exactly as a
 * store that outlives or is shared with another writer could hold it. Nothing is verified here — the
 * effect owner is what must refuse a planted authority.
 */
export function plantApproved(fx: EffectGate, holdId: string, planted: { decisionArtifact: Record<string, unknown>; receipt: Receipt; grant: ExecutionGrant }): void {
  const h = hold(fx, holdId);
  h.status = "APPROVED";
  h.reasonCode = "HUMAN_APPROVED_INTENT_NOT_EXECUTION_BOUND";
  h.decisionArtifact = planted.decisionArtifact;
  h.decisionReceipt = planted.receipt;
  h.verdictReceipt = planted.receipt;
  h.decidedAt = fx.clock.t;
  h.grantId = planted.grant.grantId;
  fx.store.putHold(h);
  fx.store.putGrant({
    grant: planted.grant,
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
}

/**
 * A counting sealer for direct owner calls, bound to one gate's keys. Its `calls` count the attestations
 * the owner asked for — a signed-bytes consequence a test can assert.
 */
export function sealerFor(fx: EffectGate): { seal: (atMs: number, ...rest: unknown[]) => EffectAttestation; calls: number[] } {
  const calls: number[] = [];
  return {
    calls,
    seal: (atMs: number, ...rest: unknown[]) => {
      calls.push(atMs);
      return buildEffectAttestation({
        verified: rest[0] as VerifiedAuthority,
        atMs,
        receiptId: `sealed-${calls.length}`,
        gate: fx.trust.gate,
        signer: fx.signer,
      });
    },
  };
}

/**
 * STORE SEAM: replace a hold's envelope with one the test signs with the gate key it holds — the same
 * envelope with a later `expiresAt`. Returns the original and the replacement.
 */
export function extendEnvelope(fx: EffectGate, holdId: string, extraMs: number): { original: HoldEnvelope; extended: HoldEnvelope } {
  const h = hold(fx, holdId);
  const original = h.holdEnvelope;
  const { sig: _sig, ...unsigned } = original;
  const extended = signArtifact(
    b({ ...unsigned, expiresAt: new Date(Date.parse(original.expiresAt) + extraMs).toISOString() }),
    "NOA-Hold-v0.1-sig",
    gateKey(fx.world),
  ) as unknown as HoldEnvelope;
  h.holdEnvelope = extended;
  fx.store.putHold(h);
  return { original, extended };
}

/**
 * An effect owner over a trust root built from `fx`'s world (same gate key and approver keys) with the
 * roster changed by `rosterOver`, on `fx`'s BOOT: only the roster facts differ, so only the check under
 * test can refuse `fx`'s artifacts.
 */
export function ownerOn(fx: EffectGate, rosterOver: Record<string, unknown>, prefix: string, ledger: string = LEDGER, ownerFactory: EffectOwnerFactory = inMemoryOwnerFactory, store: Store = new InMemoryStore()): { trust: GateTrust; owner: EffectOwner } {
  const base = pinnedTrustFrom(rosterDoc(fx.world, fx.clock.t, rosterOver), fx.world.gate, { now: () => fx.clock.t, ids: idSource(prefix) });
  const trust: GateTrust = { ...base, bootId: fx.trust.bootId };
  // Its own store: this owner is called directly and must not share records with `fx`'s owner.
  const owner = ownerFactory({ trust, now: () => fx.clock.t, ledger, accounts: DEFAULT_ACCOUNTS, store });
  return { trust, owner };
}

/** A verdict receipt for a hold, chained onto its deferred receipt, signed by `signer` and naming `by`. */
export function approvalReceiptBy(fx: EffectGate, holdId: string, signer: { kid: string; privateKey: string }, opts: { by: string; verdict: "ALLOWED" | "BLOCKED"; action?: Record<string, unknown> }): Receipt {
  const h = hold(fx, holdId);
  const at = new Date(fx.clock.t).toISOString();
  return buildReceipt(
    {
      id: `verdict-${h.deferredReceipt.id}`,
      ts: at,
      scope: { tenant: h.deferredReceipt.scope.tenant, chain: h.deferredReceipt.scope.chain },
      agent: { id: "approver-human-1", model: null, principal: "HUMAN" },
      action: { ...h.deferredReceipt.action, ...(opts.action ?? {}) } as Receipt["action"],
      governance: {
        mode: "approvals_on",
        verdict: opts.verdict,
        ruleId: opts.verdict === "ALLOWED" ? "human-approved" : "human-denied",
        approval: { by: opts.by, at },
        sandboxed: false,
      },
    },
    h.deferredReceipt,
    signer,
  );
}

export type { KeyPair };
