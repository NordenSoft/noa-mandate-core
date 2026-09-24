/**
 * NOA Gate — trust bootstrap (alpha-simplified, F21/F11).
 *
 * The gate holds ONE Ed25519 signing key that is typed GATE in the manifest with BOTH roles
 * `hold-signer` (Hold Envelope, D1) and `execution-signer` (Grant / Consumption / Uncertainty /
 * Hold Resolution). The SAME key also signs the DEFERRED/EXECUTED/FAILED/timeout RECEIPTS under the
 * receipt domain (a receipt's `sig.kid` == the gate kid). Red Line 16 holds: the gate NEVER signs
 * the Key Manifest — that is signed by the tenant authority (the delegated manifest signer, F21),
 * whose delegation is signed by an offline root.
 *
 * Alpha (F21): a SINGLE static tenant-authority-signed manifest + one static root→authority
 * delegation, so the §6 signing hierarchy (root → delegated signer → gate/approver/audit keys) is
 * satisfiable even before beta's full offline-root → rotating-delegated-signer split ships.
 *
 * `bootId`/`uptimeResetAt` are the REQUIRED gate-external liveness (G3) the Execution Uncertainty
 * carries and the §13 verifier cross-checks — a bare, unverifiable "unknown" is never accepted.
 */

import { createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, randomUUID } from "node:crypto";
import { generateKeyPair, signArtifact, refHash, parseDocument, type KeyEntry } from "noa-approval-artifacts";
import { SIGNING_KEY_LIFECYCLE_SPEC, isHex64, intrinsics, type SigningKeyLifecycle } from "noa-receipt";
import { loadOrCreateKeyFile } from "noa-mcp-adapter-core";
import { describeThrown, thrownCode } from "noa-mcp-adapter-core/safe-throw";
import { encodeDocument } from "./bytes.js";
import { readPinnedFile, takeOverStaleLock, tryCreateLock, writeFileAtomic } from "./pinned-file.js";
import {
  checkRosterClock,
  isRosterId,
  parseGateRoster,
  type GateRoster,
  type RosterApprover,
  type RosterClockRefusalCode,
  type RosterRefusalCode,
} from "./roster.js";

const { hasOwn, objectCreateNull, objectFreeze, objectKeys, isSafeInteger } = intrinsics;

export interface GateKeyPair {
  kid: string;
  /** base64(DER SPKI) Ed25519 public key. */
  publicKey: string;
  /** base64(DER PKCS8) Ed25519 private key. */
  privateKey: string;
}

/**
 * The APPROVER (phone) key as the GATE knows it.
 *
 * `privateKey` is OPTIONAL and that optionality is the security property, not a convenience. The
 * approver's private half belongs on the phone; `createAlphaTrust` mints it in-process only for the
 * alpha demo and the test suite, and REFUSES to do so once the execution signer is external — see
 * `CreateTrustInput.approverPublicKey`. Typed optional so a path that needs the private half cannot
 * silently compile against a trust root that does not have one.
 */
export interface GateApproverKey {
  kid: string;
  publicKey: string;
  /** ALPHA/TEST ONLY. Absent whenever the approver key is externally held, which is REQUIRED
   *  whenever the grant signer is out of process. */
  privateKey?: string;
}

/** base64(DER SPKI) X25519 public key — real key material (HPKE recipient), unused by §8 itself. */
function generateX25519Public(): string {
  const { publicKey } = generateKeyPairSync("x25519");
  return (publicKey.export({ type: "spki", format: "der" }) as Buffer).toString("base64");
}

/** The PUBLIC half of an execution-signer key held OUTSIDE this process (the grant sidecar). */
export interface ExternalExecutionSignerKey {
  kid: string;
  /** base64(DER SPKI) Ed25519 public key. There is deliberately no private member on this type. */
  publicKey: string;
}

export interface CreateTrustInput {
  tenant: string;
  /**
   * When supplied, the manifest's authority is SPLIT and this process stops being able to authorize.
   *
   * The gate key drops to `["hold-signer"]` and this key becomes the only `execution-signer` in the
   * manifest, so a relying party rejects any Execution Grant signed by the gate's own key
   * (`verify.ts`'s F15 block; the shipped `execution-grant/reject-wrong-key` vector is exactly this
   * case). That is what makes "the compromised gate cannot mint a grant" a mechanical fact rather
   * than an assertion — and it is also why all four execution-signer artifacts must be signed
   * remotely once this is set (`exec-signer.ts`).
   */
  executionSigner?: ExternalExecutionSignerKey;
  /**
   * The approver device's PUBLIC half, enrolled out of band (the phone keeps the private half).
   *
   * ── REQUIRED WHENEVER `executionSigner` IS SET, AND THAT IS A CRITICAL FIX ────────────────────
   * The out-of-process grant signer authorizes on exactly one thing an attacker inside the gate
   * cannot forge: the APPROVER's signature. Until this input existed, the only shipped wiring for
   * the sidecar still called `createAlphaTrust()` with no approver argument — which GENERATES the
   * approver keypair and returns its PRIVATE half on the gate's heap. A compromised gate simply
   * read it, signed both required approver artifacts for parameters of its choosing, and asked the
   * real sidecar to sign. The boundary was decorative in its own default configuration
   * (adversarial review 2026-08-12), and this repository's own test file described that attack as
   * an "honest limit" while shipping it as the wiring.
   *
   * So the two are now coupled in the constructor: an external authority root with an in-process
   * approver key is refused outright rather than documented.
   */
  approverPublicKey?: { kid: string; publicKey: string; hpkePublicKey: string };
  /**
   * riskClass tier the single alpha approver is authorized for (F15). The tiers are ORDERED, not
   * disjoint: `approve-critical` strictly dominates `approve-high`, so a CRITICAL-authorized
   * approver also clears HIGH actions. Default `approve-critical` therefore does cover all tiers —
   * a claim that was FALSE until the lattice was unified, because approval-artifacts required
   * exactly `approve-high` for HIGH and rejected this very default with a 422.
   * AUTHORITY: `requiredApproverRole()` in packages/approval-artifacts/src/verify.ts; on any drift
   * that function wins. Cross-package test: packages/approval-artifacts/test/f15-lattice.test.mjs.
   */
  approverRole?: "approve-high" | "approve-critical";
  now?: () => number;
  /** Deterministic id source for tests (defaults to node:crypto randomUUID). */
  ids?: () => string;
  /**
   * Deterministic GRANT-NONCE source for tests (defaults to 32 CSPRNG bytes as 64 lowercase hex).
   *
   * ── WHY GRANT NONCES ARE NOT `newId()` (S4 / R-AD-3(ii), 2026-08-13) ──────────────────────────
   * `grant.nonce` is the `executionNonce` of the `noa.action-digest/0.1` projection, and under the
   * S4 correlation design (D7) it is ALSO the confidentiality-critical seed of the on-chain
   * correlation nonce: nine of the ten projection members are low-entropy or enumerable for a given
   * tenant, so the nonce is the ONLY thing standing between a public ledger and a confirmation
   * oracle over customers' private approvals. The real rule (corrected 2026-08-13 — an earlier
   * revision here cited a "128-bit floor the digest spec asserts", which does not exist
   * anywhere): the settlement-evidence spec's §3 seed rule requires `grant.nonce` to be
   * EXACTLY 32 bytes as lowercase hex so it serves as a full-entropy D7 seed, and the grant
   * schema pins `nonce` to `^[0-9a-f]{64}$`. `randomUUID()` satisfies neither the format nor the
   * 32-byte full-entropy requirement. Grant IDs and every other `newId()` use are identifiers,
   * not secrets, and stay on `randomUUID()`.
   */
  nonces?: () => string;
}

export interface GateTrust {
  tenant: string;
  now: () => number;
  newId: () => string;
  /** GRANT NONCES ONLY — 32 CSPRNG bytes as 64 lowercase hex (see `CreateTrustInput.nonces`).
   *  Never used for grant ids, hold ids, envelope nonces or any other identifier. */
  newNonce: () => string;

  /** The gate signing key. GATE + `hold-signer`, also the receipt signer — and `execution-signer`
   *  TOO unless `executionSigner` below is set, in which case that role has left this process. */
  gate: GateKeyPair;
  /** Set iff the execution-signer key lives outside this process. The gate holds the PUBLIC half
   *  only, for verification and for the manifest. */
  executionSigner?: ExternalExecutionSignerKey;
  /**
   * The approver device's PUBLIC half, enrolled out of band (the phone keeps the private half).
   *
   * ── REQUIRED WHENEVER `executionSigner` IS SET, AND THAT IS A CRITICAL FIX ────────────────────
   * The out-of-process grant signer authorizes on exactly one thing an attacker inside the gate
   * cannot forge: the APPROVER's signature. Until this input existed, the only shipped wiring for
   * the sidecar still called `createAlphaTrust()` with no approver argument — which GENERATES the
   * approver keypair and returns its PRIVATE half on the gate's heap. A compromised gate simply
   * read it, signed both required approver artifacts for parameters of its choosing, and asked the
   * real sidecar to sign. The boundary was decorative in its own default configuration
   * (adversarial review 2026-08-12), and this repository's own test file described that attack as
   * an "honest limit" while shipping it as the wiring.
   *
   * So the two are now coupled in the constructor: an external authority root with an in-process
   * approver key is refused outright rather than documented.
   */
  approverPublicKey?: { kid: string; publicKey: string; hpkePublicKey: string };
  /** The single alpha approver signing key (APPROVER). `privateKey` is present ONLY in the
   *  self-generated alpha/test configuration; when `approverPublicKey` was supplied — which is
   *  mandatory once the grant signer is external — the gate holds the public half and nothing else. */
  approver: GateApproverKey;
  approverHpkePublicKey: string;
  /** The AUDIT recipient's kid + HPKE public half (`roles: ["audit-decrypt"]` in the key manifest).
   *  The kid is exposed because the engine must be able to NAME this recipient when it seals a display;
   *  before ADR-0005 Slice 4 the key was provisioned and never used, so no auditor could decrypt
   *  anything the gate sealed. */
  auditKid: string;
  auditHpkePublicKey: string;

  /**
   * The key-manifest EPOCH this gate stamps into every envelope and resolution. In alpha it is the
   * manifest `createAlphaTrust` signs for itself; in pinned mode it is the (version, hash) the
   * operator copied from the manifest the approver devices hold. The gate never parses or trusts that
   * manifest — the pair is a consistency value `decide()` and `reserve()` compare against.
   */
  keyManifestVersion: number;
  keyManifestHash: string;
  /** ALPHA ONLY: the self-signed manifest and delegation. A pinned gate holds neither — it never
   *  signs a manifest, and nothing on the gate's decision path reads these two members. */
  keyManifest?: Record<string, unknown>;
  keyDelegation?: Record<string, unknown>;
  /** Set iff this trust root came from a pinned roster (`createPinnedTrust`). Frozen, null-prototype. */
  pinned?: PinnedTrustState;

  /** kid → KeyEntry for `verifyArtifact` (structural + role checks on the phone Decision Artifact). */
  keyring: Record<string, KeyEntry>;
  /** Atomic public-key plus retirement state for `verifyChain`. */
  receiptKeyring: SigningKeyLifecycle;

  /** REQUIRED gate liveness (G3), stable for this process, re-derived on restart. */
  bootId: string;
  uptimeResetAt: string;
}

/**
 * GRANT-NONCE source with the format guard, shared by both trust constructors so there is one copy.
 *
 * 32 CSPRNG bytes, hex — injectable for deterministic tests exactly the way `ids` is. EVERY draw is
 * format-validated at the trust boundary, so an injected bad nonce source fails HERE, loudly, instead
 * of minting schema-invalid (or worse, schema-valid but degenerate) grants that fail silently
 * downstream. Per-call rather than a one-off probe draw at construction: a probe draw would silently
 * shift injected deterministic sequences. Entropy is unenforceable at this boundary; format is what
 * CAN be checked, and is.
 */
function guardedNonceSource(injected: (() => string) | undefined, label: string): () => string {
  const nonceSource = injected ?? (() => randomBytes(32).toString("hex"));
  return () => {
    const nonce = nonceSource();
    // Validated with the kernel's captured-charCode `isHex64`, never a live `RegExp.prototype.test`
    // (which per spec does a dynamic Get(re,"exec") and is poisonable at the prototype); the guard
    // that refuses a bad nonce must not itself dispatch through a slot an attacker can rewrite.
    if (!isHex64(nonce)) {
      throw new Error(
        `${label}: newNonce() produced a value that is not 64 lowercase hex characters — ` +
          "grant nonces are the D7 correlation seed and must satisfy the grant schema's ^[0-9a-f]{64}$",
      );
    }
    return nonce;
  };
}

/**
 * Build a self-contained alpha trust root: a root authority, a delegated (== tenant-authority)
 * manifest signer, a gate key, and a single approver key + audit key. Deterministic-friendly
 * (inject `now`/`ids`). This is the alpha F21 single-static-manifest — issued once, never rotated.
 */
export function createAlphaTrust(input: CreateTrustInput): GateTrust {
  const now = input.now ?? (() => Date.now());
  const newId = input.ids ?? (() => randomUUID());
  const newNonce = guardedNonceSource(input.nonces, "createAlphaTrust");
  const tenant = input.tenant;
  const approverRole = input.approverRole ?? "approve-critical";

  const external = input.executionSigner;
  const enrolledApprover = input.approverPublicKey;
  // ── THE COUPLING, ENFORCED IN THE CONSTRUCTOR ────────────────────────────────────────────────
  // Moving the grant key out of the process while leaving the approver key IN it protects nothing:
  // the attacker mints the approval the sidecar asks for and the sidecar signs, correctly, because
  // every check passed. Refused here rather than documented, because a documented default is the
  // configuration people run.
  if (external && !enrolledApprover) {
    throw new Error(
      "createAlphaTrust: an EXTERNAL execution signer requires `approverPublicKey` (the phone's enrolled public half). " +
        "Generating the approver keypair in this process would leave the one signature the out-of-process signer relies on " +
        "in the memory of the process it is defending against, which makes the boundary decorative.",
    );
  }

  const root = generateKeyPair("tenant-root-1");
  const authority = generateKeyPair("tenant-authority-1"); // the delegated manifest signer (F21)
  const gate = generateKeyPair("gate-prod-1");
  // The approver keypair is generated ONLY when no enrolled public key was supplied — i.e. only in
  // the alpha/test configuration, which the check above forbids combining with an external signer.
  const approver: GateApproverKey = enrolledApprover
    ? { kid: enrolledApprover.kid, publicKey: enrolledApprover.publicKey }
    : generateKeyPair("approver-1-device-1");
  const approverHpke = enrolledApprover ? enrolledApprover.hpkePublicKey : generateX25519Public();
  const auditHpke = generateX25519Public();
  // The audit kid was a bare string literal inside the key-manifest entry below and existed NOWHERE
  // else, so nothing could name the audit recipient (ADR-0005 Slice 4). Bound once here and used by
  // both the manifest and `auditKid`, so the manifest entry and the recipient list cannot drift.
  const auditKidValue = "audit-1";

  // ONE authority table for the split, read by the manifest AND by the keyring below, so the two
  // cannot disagree about which key may authorize an execution.
  const gateRoles: string[] = external ? ["hold-signer"] : ["hold-signer", "execution-signer"];

  const iso = (ms: number) => new Date(ms).toISOString();
  const t0 = now();
  const validFrom = iso(t0 - 60_000);
  const expiresAt = iso(t0 + 365 * 24 * 60 * 60 * 1000); // long-lived alpha static

  // root-signed delegation (root → tenant-authority as the manifest signer), F11/F21.
  const keyDelegation = signArtifact(
    encodeDocument({
      spec: "noa.key-delegation/0.1",
      tenant,
      delegatedKid: authority.kid,
      delegatedPublicKey: authority.publicKey,
      permissions: ["key-manifest-sign"],
      validFrom,
      expiresAt,
    }),
    "NOA-KeyDelegation-v0.1-sig",
    { kid: root.kid, privateKey: root.privateKey },
  );

  // tenant-authority-signed manifest (F21 direct signature; the GATE never signs it — Red Line 16).
  const keyManifest = signArtifact(
    encodeDocument({
      spec: "noa.key-manifest/0.1",
      tenant,
      version: 1,
      issuedAt: iso(t0),
      expiresAt,
      previousManifestHash: null,
      keys: [
        {
          kid: gate.kid,
          type: "GATE",
          roles: gateRoles,
          publicKey: gate.publicKey,
          validFrom,
          revokedAt: null,
        },
        ...(external
          ? [{
              kid: external.kid,
              type: "GATE",
              roles: ["execution-signer"],
              publicKey: external.publicKey,
              validFrom,
              revokedAt: null,
            }]
          : []),
        {
          kid: approver.kid,
          type: "APPROVER",
          roles: [approverRole],
          publicKey: approver.publicKey,
          hpkePublicKey: approverHpke,
          validFrom,
          revokedAt: null,
        },
        {
          kid: auditKidValue,
          type: "AUDIT",
          roles: ["audit-decrypt"],
          hpkePublicKey: auditHpke,
          validFrom,
          revokedAt: null,
        },
      ],
    }),
    "NOA-KeyManifest-v0.1-sig",
    { kid: authority.kid, privateKey: authority.privateKey },
  );

  const keyManifestHash = refHash(keyManifest);

  // ── P0-5 (2026-07-31): THIS RESOLVER WAS THE THIRD ONE, AND IT DROPPED `validFrom` ───────────
  // The key manifest built 30 lines above declares `validFrom` on every key (:145, :154, …). This
  // keyring — the one `engine.ts:988` hands to `verifyArtifact` for LIVE Decision verification —
  // was rebuilt from the same inputs WITHOUT it, so `verifyArtifact` saw `undefined` and skipped
  // the activation check entirely. A future-activated approver could sign before activation and
  // pass. Current alpha constructors choose a past `validFrom`, which bounds the exposure, but
  // `createGate` accepts an injected `GateTrust`.
  //
  // I fixed the EVIDENCE resolver for this same class one batch earlier and wrote a test asserting
  // "the ROOT path and the MANIFEST path carry activation the SAME way" — without asking whether a
  // THIRD resolver existed. It did, and it is this one. That is the "fix landed on one sibling"
  // pattern for the third time in this file family.
  //
  // ── P0-7 (2026-07-31): THE SENTENCE THAT USED TO END THE PARAGRAPH ABOVE WAS FALSE ───────────
  // It read, verbatim: "the parity test added with this change is what makes a fourth one fail
  // loudly instead of silently." NO SUCH TEST EXISTED when that was written — `grep -rn "parity"
  // packages/gate/test/` returned nothing, and deleting all four `validFrom` properties below left
  // every then-existing test GREEN (re-measured 2026-07-31 before this correction). The claim is
  // WITHDRAWN and recorded here rather than deleted: a source comment asserting a control that is
  // not there is exactly the defect class the same batch was adjudicating. The control now exists,
  // is measured, and is registered so it cannot silently disappear:
  //   [proof: RES-PAR-GATE-KEYRING] test/keyring-resolver-parity.test.ts — goes RED (3 tests,
  //     214 pass/2 fail -> 211 pass/5 fail) under that exact four-deletion mutation; restoration
  //     hash-verified.
  //   [proof: RES-PAR-XRES-EQUIV] packages/e2e-demo/test/keyring-resolver-parity.test.ts —
  //     cross-resolver equivalence proven at the real verifier.
  //   scripts/lint-resolver-parity.mjs + scripts/resolver-inventory.json — a BLOCKING census gate:
  //     a resolver that appears or disappears, and a registered proof that stops resolving, each
  //     fail the gate for its own named reason.
  //
  // ── CORRECTED 2026-07-31 (batch-A QA, finding F-4) ────────────────────────────────────────────
  // The line above previously also claimed the census gate fails when a resolver "drops
  // validFrom/revokedAt". That is TRUE only for a STRUCTURAL drop (the property is deleted from the
  // literal, which changes the recorded carriage from `explicit` to `absent`). It is FALSE for a
  // VALUE substitution: writing `validFrom: null` keeps the property present, so the gate still
  // reads `explicit` and stays exit 0. MEASURED. The defect is not undetected — the e2e parity test
  // catches it (12 pass -> 11) — but the sentence overstated WHICH control catches it, and this
  // file's whole history is claims that named the wrong control. Value-provenance checking is
  // deliberately NOT built: the test layer already covers it, and a second mechanism would be
  // theatre. Tracked as P1 (F-4).
  const keyring: Record<string, KeyEntry> = {
    [gate.kid]: { publicKey: gate.publicKey, type: "GATE", roles: gateRoles, validFrom, revokedAt: null },
    ...(external
      ? { [external.kid]: { publicKey: external.publicKey, type: "GATE" as const, roles: ["execution-signer"], validFrom, revokedAt: null } }
      : {}),
    [approver.kid]: { publicKey: approver.publicKey, type: "APPROVER", roles: [approverRole], validFrom, revokedAt: null },
    [authority.kid]: { publicKey: authority.publicKey, type: "DELEGATED", roles: ["key-manifest-sign"], validFrom, revokedAt: null },
    [root.kid]: { publicKey: root.publicKey, type: "ROOT", roles: [], validFrom, revokedAt: null },
  };
  const receiptKeyring: SigningKeyLifecycle = {
    spec: SIGNING_KEY_LIFECYCLE_SPEC,
    keys: {
      [gate.kid]: { publicKey: gate.publicKey, retiredAt: null },
      [approver.kid]: { publicKey: approver.publicKey, retiredAt: null },
    },
  };

  return {
    tenant,
    now,
    newId,
    newNonce,
    gate,
    ...(external ? { executionSigner: { kid: external.kid, publicKey: external.publicKey } } : {}),
    approver,
    approverHpkePublicKey: approverHpke,
    auditKid: auditKidValue,
    auditHpkePublicKey: auditHpke,
    keyManifestVersion: keyManifest.version as number,
    keyManifestHash,
    keyManifest,
    keyDelegation,
    keyring,
    receiptKeyring,
    bootId: newId(),
    uptimeResetAt: iso(t0),
  };
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// PINNED TRUST — the gate's trust root read from an operator-provisioned roster (`noa.gate-roster/1`)
// ═════════════════════════════════════════════════════════════════════════════════════════════════
//
// WHY. `createAlphaTrust` mints a fresh root, authority and gate key on every boot and signs its own
// delegation and manifest, so the process that authorizes effects is also the source of the trust
// material that says it may — a control producing its own evidence. And whoever writes the keyring
// authorizes every effect: `/decision` is not scoped to the hold's owner, so the signature check
// against this keyring is the only thing between a request and a grant.
//
// A PINNED trust root holds a persistent gate key loaded from a file (never minted at boot), takes its
// approver, audit key, epoch and quorum ONLY from the roster on the gate host, and never falls back to
// alpha: every failure refuses the boot with a stable code. docs/gate-pinned-trust.md is the operator
// contract; NON-CLAIMS.md §S8 is what this does not establish.

/** How the roster high-water state compared on this boot. */
export type RosterStateStatus = "INITIALIZED" | "UNCHANGED" | "ADVANCED";

/** The pinned facts the engine re-checks at `createHold`, `decide` and `reserve`. Frozen, null-prototype. */
export interface PinnedTrustState {
  readonly rosterVersion: number;
  readonly rosterDigest: string;
  /** risk class -> required approvals. A /1 gate accepts only 1; anything else is refused at load AND at decide. */
  readonly quorum: Readonly<Record<string, number>>;
  /** Roster `expiresAt`, whole milliseconds rounded down. At or after it the gate authorizes nothing. */
  readonly expiresAtMs: number;
  readonly stateStatus: RosterStateStatus;
}

export interface CreatePinnedTrustInput {
  roster: GateRoster;
  rosterDigest: string;
  /** The roster's single active approver (`parseGateRoster` → `activeApproverKid`). */
  activeApproverKid: string;
  /** Roster `expiresAt` in whole milliseconds (`parseGateRoster` → `expiresAtMs`). */
  expiresAtMs: number;
  /**
   * The persistent gate key. PRECONDITION, enforced by `loadPinnedTrust` stage 9 and nowhere else so
   * that the control stays measurable: `{kid, publicKey}` equals `roster.gate` and the private key
   * derives that public key.
   */
  gateKey: GateKeyPair;
  stateStatus: RosterStateStatus;
  now?: () => number;
  ids?: () => string;
  nonces?: () => string;
}

function nullProto<T extends object>(src: T): T {
  const out = objectCreateNull<T>();
  const keys = objectKeys(src);
  for (let i = 0; i < keys.length; i++) {
    const k = keys[i] as string;
    (out as Record<string, unknown>)[k] = (src as Record<string, unknown>)[k];
  }
  return out;
}

/**
 * Build a GateTrust from a validated roster and the persistent gate key. Nothing here generates a key:
 * the approver's private half never exists in this process, so the co-residency rule `createAlphaTrust`
 * enforces for an external signer holds here by construction.
 */
export function createPinnedTrust(input: CreatePinnedTrustInput): GateTrust {
  const now = input.now ?? (() => Date.now());
  const newId = input.ids ?? (() => randomUUID());
  const newNonce = guardedNonceSource(input.nonces, "createPinnedTrust");
  const { roster } = input;
  const iso = (ms: number) => new Date(ms).toISOString();

  const active = roster.approvers[input.activeApproverKid] as RosterApprover;
  const exec = roster.executionSigner;
  // The authority split, from the roster: when an external execution signer is pinned, the gate key
  // keeps only `hold-signer` and a grant signed by it verifies nowhere.
  const pinnedGateRoles: string[] = exec !== null ? ["hold-signer"] : ["hold-signer", "execution-signer"];

  // The live keyring, built ONLY from the roster: no ROOT and no DELEGATED entry exists, because a
  // pinned gate never verifies or signs a manifest. Every entry carries its declared activation and
  // revocation; a revoked approver stays present so its decisions are refused as REVOKED rather than
  // as unknown. [proof: RES-PAR-GATE-PINNED-KEYRING] test/pinned-decide.test.ts.
  const keyring = objectCreateNull<Record<string, KeyEntry>>();
  keyring[roster.gate.kid] = objectFreeze(nullProto({
    publicKey: roster.gate.publicKey,
    type: "GATE" as const,
    roles: pinnedGateRoles,
    validFrom: roster.validFrom,
    revokedAt: null,
  }));
  if (exec !== null) {
    keyring[exec.kid] = objectFreeze(nullProto({
      publicKey: exec.publicKey,
      type: "GATE" as const,
      roles: ["execution-signer"],
      validFrom: roster.validFrom,
      revokedAt: null,
    }));
  }
  const approverKids = objectKeys(roster.approvers);
  const receiptKeys = objectCreateNull<Record<string, { publicKey: string; retiredAt: string | null }>>();
  receiptKeys[roster.gate.kid] = objectFreeze(nullProto({ publicKey: roster.gate.publicKey, retiredAt: null }));
  for (let i = 0; i < approverKids.length; i++) {
    const kid = approverKids[i] as string;
    const a = roster.approvers[kid] as RosterApprover;
    keyring[kid] = objectFreeze(nullProto({
      publicKey: a.publicKey,
      type: "APPROVER" as const,
      roles: [a.role],
      validFrom: a.validFrom,
      revokedAt: a.revokedAt,
    }));
    // A non-null retirement makes the kid unusable for current verification (src/verification-keyring.ts).
    receiptKeys[kid] = objectFreeze(nullProto({ publicKey: a.publicKey, retiredAt: a.revokedAt }));
  }
  const receiptKeyring: SigningKeyLifecycle = objectFreeze(nullProto({
    spec: SIGNING_KEY_LIFECYCLE_SPEC,
    keys: objectFreeze(receiptKeys),
  }));

  const pinned: PinnedTrustState = objectFreeze(nullProto({
    rosterVersion: roster.rosterVersion,
    rosterDigest: input.rosterDigest,
    quorum: roster.quorum,
    expiresAtMs: input.expiresAtMs,
    stateStatus: input.stateStatus,
  }));

  return {
    tenant: roster.tenant,
    now,
    newId,
    newNonce,
    gate: { kid: input.gateKey.kid, publicKey: input.gateKey.publicKey, privateKey: input.gateKey.privateKey },
    ...(exec !== null ? { executionSigner: { kid: exec.kid, publicKey: exec.publicKey } } : {}),
    approver: { kid: input.activeApproverKid, publicKey: active.publicKey },
    approverHpkePublicKey: active.hpkePublicKey,
    auditKid: roster.audit.kid,
    auditHpkePublicKey: roster.audit.hpkePublicKey,
    keyManifestVersion: roster.epoch.keyManifestVersion,
    keyManifestHash: roster.epoch.keyManifestHash,
    keyring: objectFreeze(keyring),
    receiptKeyring,
    pinned,
    bootId: newId(),
    uptimeResetAt: iso(now()),
  };
}

// ── boot: stages 0-11 ────────────────────────────────────────────────────────────────────────────

export type PinnedBootCode =
  | "PINNED_PLATFORM_UNSUPPORTED"
  | "CONFIG_PINNED_INCOMPLETE"
  | "CONFIG_SOURCE_CONFLICT"
  | "ROSTER_FILE_MISSING"
  | "ROSTER_FILE_UNSAFE"
  | RosterRefusalCode
  | RosterClockRefusalCode
  | "GATE_KEY_FILE_MISSING"
  | "GATE_KEY_FILE_UNSAFE"
  | "GATE_KEY_INCONSISTENT"
  | "GATE_KEY_NOT_PINNED"
  | "ROSTER_EXEC_SIGNER_MISMATCH"
  | "PINNED_ROOT_GATE"
  | "STATE_LOCKED"
  | "STATE_DIR_NOT_WRITABLE"
  | "STATE_FILE_UNSAFE"
  | "STATE_FILE_CORRUPT"
  | "ROSTER_ROLLBACK"
  | "ROSTER_EQUIVOCATION"
  | "STATE_FILE_WRITE_FAILED";

export interface PinnedRefusal {
  readonly ok: false;
  readonly code: PinnedBootCode;
  readonly detail: string;
}
const bootRefusal = (code: PinnedBootCode, detail: string): PinnedRefusal => ({ ok: false, code, detail });

/** The environment names that select pinned mode. ANY of them being present means pinned was asked for. */
const PINNED_ENV = ["NOA_GATE_ROSTER_FILE", "NOA_GATE_KEY_FILE", "NOA_GATE_ROSTER_SHA256", "NOA_GATE_UNSAFE_ROSTER_SAME_UID"] as const;

export type TrustModeRequest =
  | { readonly mode: "alpha" }
  | {
      readonly mode: "pinned";
      readonly rosterFile: string;
      readonly keyFile: string;
      readonly rosterSha256: string | undefined;
      readonly unsafeSameUid: boolean;
    }
  | PinnedRefusal;

/**
 * Stages 0-1: which trust root the environment asks for.
 *
 * Pinned mode is requested the moment ANY pinned variable is present — including an empty one, and
 * including the digest pin or the same-uid escape on their own. Treating a present-but-empty or
 * half-supplied pinned configuration as "not pinned" would boot the self-minting alpha root for an
 * operator who asked for the opposite; that is the downgrade this refuses.
 */
export function resolveTrustMode(env: Readonly<Record<string, string | undefined>>, platformHasEuid: boolean): TrustModeRequest {
  let requested = false;
  for (let i = 0; i < PINNED_ENV.length; i++) if (env[PINNED_ENV[i] as string] !== undefined) requested = true;
  if (!requested) return { mode: "alpha" };

  // stage 0 — the owner rule needs POSIX uids; without them it cannot be evaluated, only skipped.
  if (!platformHasEuid) {
    return bootRefusal("PINNED_PLATFORM_UNSUPPORTED", "pinned trust needs POSIX user ids to enforce the roster owner rule; this platform has none");
  }
  // stage 1 — both files, and no second source of identities.
  const rosterFile = env["NOA_GATE_ROSTER_FILE"];
  const keyFile = env["NOA_GATE_KEY_FILE"];
  if (rosterFile === undefined || rosterFile === "" || keyFile === undefined || keyFile === "") {
    return bootRefusal(
      "CONFIG_PINNED_INCOMPLETE",
      "pinned mode needs BOTH NOA_GATE_ROSTER_FILE and NOA_GATE_KEY_FILE (non-empty); a pinned variable was set without them",
    );
  }
  const conflict = pinnedEnvironmentConflict(env);
  if (conflict !== null) return conflict;
  return {
    mode: "pinned",
    rosterFile,
    keyFile,
    rosterSha256: env["NOA_GATE_ROSTER_SHA256"],
    unsafeSameUid: env["NOA_GATE_UNSAFE_ROSTER_SAME_UID"] === "1",
  };
}

/**
 * The second-identity-source rule, shared by `serve` (through `resolveTrustMode`) and `roster-check`:
 * any `NOA_GATE_APPROVER_*`, `NOA_GATE_GRANT_SIGNER_KID` or `NOA_GATE_GRANT_SIGNER_PUBLIC_KEY` present
 * is CONFIG_SOURCE_CONFLICT. Identities come only from the roster; a second source is refused, not ignored.
 */
export function pinnedEnvironmentConflict(env: Readonly<Record<string, string | undefined>>): PinnedRefusal | null {
  const conflicting: string[] = [];
  for (const name of objectKeys(env as Record<string, unknown>)) {
    if (env[name] === undefined) continue;
    if (name.startsWith("NOA_GATE_APPROVER_") || name === "NOA_GATE_GRANT_SIGNER_KID" || name === "NOA_GATE_GRANT_SIGNER_PUBLIC_KEY") {
      conflicting[conflicting.length] = name;
    }
  }
  if (conflicting.length === 0) return null;
  return bootRefusal(
    "CONFIG_SOURCE_CONFLICT",
    `${conflicting.sort().join(", ")} set in pinned mode; identities come only from the roster, and a second source is refused rather than ignored`,
  );
}

/** Largest accepted roster. It names a few keys; the bound exists so a hostile file cannot be large. */
export const ROSTER_MAX_BYTES = 64 * 1024;
const STATE_MAX_BYTES = 4 * 1024;
export const ROSTER_STATE_SPEC = "noa.gate-roster-state/1" as const;

/** The effective uid the key-file loader trusts (captured the same way `key-file.mjs` captures it). */
const PROCESS_EUID: number | null = typeof process.geteuid === "function" ? process.geteuid() : null;

export interface LoadPinnedTrustInput extends LoadPinnedRosterInput {
  keyFile: string;
  /** Whether NOA_GATE_GRANT_SIGNER_SOCKET is set: must agree with the roster's executionSigner. */
  grantSignerSocketSet: boolean;
  /** Take the high-water lock (default true). `roster-check` reads the state without it and never writes. */
  lockState?: boolean;
  /** TEST SEAM: the uid the state file's owner rule accepts besides root. Defaults to this process's euid. */
  stateOwnerEuid?: number;
  /** TEST SEAM: whether a lock holder's pid is alive. Defaults to a signal-0 probe. */
  isProcessAlive?: (pid: number) => boolean;
  now?: () => number;
  ids?: () => string;
  nonces?: () => string;
}

export interface PinnedBoot {
  readonly ok: true;
  readonly trust: GateTrust;
  readonly roster: GateRoster;
  readonly rosterDigest: string;
  readonly activeApproverKid: string;
  readonly stateStatus: RosterStateStatus;
  readonly rosterCustody: RosterCustody;
  /**
   * Stage 11's write: record this roster as the high-water mark. Call it only after every other check
   * has passed and before listening. The state is RE-READ and RE-COMPARED under the lock taken at load,
   * so a state file changed meanwhile (by anything that ignores the lock) is still caught. Releases the
   * lock. Returns null on success (or when nothing changed).
   */
  commitState(): PinnedRefusal | null;
  /** Release the state lock without writing (a boot that stops after loading must call it). Idempotent. */
  release(): void;
}

type StateRead =
  | { ok: true; state: { rosterVersion: number; rosterDigest: string } | null }
  | PinnedRefusal;

function readRosterState(statePath: string, ownerEuid: number | null): StateRead {
  const r = readPinnedFile(statePath, {
    maxBytes: STATE_MAX_BYTES,
    forbiddenModeBits: 0o077,
    requireSingleLink: true,
    // The key-file owner rule: the gate's own uid or root. The state is the gate's own custody.
    ownerAllowed: (uid) => uid === 0 || uid === ownerEuid,
    checkAncestors: false,
  });
  if (!r.ok) {
    if (r.token === "missing") return { ok: true, state: null };
    return bootRefusal("STATE_FILE_UNSAFE", r.detail);
  }
  const parsed = parseDocument(r.bytes, "roster state");
  if (!parsed.ok) return bootRefusal("STATE_FILE_CORRUPT", parsed.reason);
  const doc = parsed.value;
  if (typeof doc !== "object" || doc === null || Array.isArray(doc)) return bootRefusal("STATE_FILE_CORRUPT", "the state file is not a JSON object");
  const o = doc as Record<string, unknown>;
  const keys = objectKeys(o);
  for (let i = 0; i < keys.length; i++) {
    const k = keys[i] as string;
    if (k !== "spec" && k !== "rosterVersion" && k !== "rosterDigest") return bootRefusal("STATE_FILE_CORRUPT", `unrecognized member ${JSON.stringify(k)}`);
  }
  const spec = hasOwn(o, "spec") ? o["spec"] : undefined;
  const version = hasOwn(o, "rosterVersion") ? o["rosterVersion"] : undefined;
  const digest = hasOwn(o, "rosterDigest") ? o["rosterDigest"] : undefined;
  if (spec !== ROSTER_STATE_SPEC) return bootRefusal("STATE_FILE_CORRUPT", `spec must be ${JSON.stringify(ROSTER_STATE_SPEC)}`);
  if (typeof version !== "number" || !isSafeInteger(version) || version < 1) return bootRefusal("STATE_FILE_CORRUPT", "rosterVersion must be a safe integer >= 1");
  if (typeof digest !== "string" || digest.length !== 71 || !digest.startsWith("sha256:") || !isLowerHex(digest.slice(7))) {
    return bootRefusal("STATE_FILE_CORRUPT", "rosterDigest must be sha256: followed by 64 lowercase hex characters");
  }
  return { ok: true, state: { rosterVersion: version, rosterDigest: digest } };
}

function isLowerHex(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (!((c >= 0x30 && c <= 0x39) || (c >= 0x61 && c <= 0x66))) return false;
  }
  return true;
}

/**
 * Stage 9's post-load checks on the persistent gate key: a kid under the id rule, an Ed25519 private
 * key whose derived public key IS the stored public key, and a pair equal to the roster's `gate`.
 */
export function checkGateKey(key: GateKeyPair, pinned: { kid: string; publicKey: string }): PinnedRefusal | null {
  if (!isRosterId(key.kid)) return bootRefusal("GATE_KEY_INCONSISTENT", "the key file's kid does not satisfy the id rule (1-64 of [a-z0-9-], first [a-z], last [a-z0-9])");
  let derived: string;
  try {
    const priv = createPrivateKey({ key: Buffer.from(key.privateKey, "base64"), format: "der", type: "pkcs8" });
    if (priv.asymmetricKeyType !== "ed25519") return bootRefusal("GATE_KEY_INCONSISTENT", "the key file's private key is not Ed25519");
    derived = (createPublicKey(priv).export({ type: "spki", format: "der" }) as Buffer).toString("base64");
  } catch (err) {
    return bootRefusal("GATE_KEY_INCONSISTENT", `the key file's private key cannot be read (${describeThrown(err)})`);
  }
  if (derived !== key.publicKey) {
    return bootRefusal("GATE_KEY_INCONSISTENT", "the key file's publicKey is not the public half of its privateKey; the gate would sign envelopes nobody can verify");
  }
  if (key.kid !== pinned.kid || key.publicKey !== pinned.publicKey) {
    return bootRefusal("GATE_KEY_NOT_PINNED", `the key file's identity ${JSON.stringify(key.kid)} is not the roster's gate member ${JSON.stringify(pinned.kid)}`);
  }
  return null;
}

/**
 * What the boot banner says about who can rewrite the roster. Only ADMIN-OWNED is the protected posture:
 * the other two are development escapes that must be typed out (NOA_GATE_UNSAFE_ROSTER_SAME_UID=1).
 */
export type RosterCustody = "ADMIN-OWNED" | "SAME-UID (unsafe)" | "ROOT-GATE (unsafe)";

export interface LoadPinnedRosterInput {
  rosterFile: string;
  /** NOA_GATE_ROSTER_SHA256: compared exactly with the computed `sha256:<hex>` digest. */
  rosterSha256: string | undefined;
  /** NOA_GATE_UNSAFE_ROSTER_SAME_UID=1: accept a roster owned by the gate's own uid (development only). */
  unsafeSameUid: boolean;
  /** NOA_GATE_TENANT, when set: must equal the roster's tenant. */
  tenantEnv: string | undefined;
  /** The gate's effective uid. A PARAMETER so a test can stand in for another principal; the CLI passes process.geteuid(). */
  gateEuid: number;
  /** The gate's clock at load (whole milliseconds). */
  nowMs: number;
}

export interface PinnedRoster {
  readonly ok: true;
  readonly roster: GateRoster;
  readonly rosterDigest: string;
  readonly activeApproverKid: string;
  readonly expiresAtMs: number;
  readonly rosterCustody: RosterCustody;
}

/**
 * Stages 2-8 — the roster alone, first failure wins:
 *
 *    2 file     PINNED_ROOT_GATE (the gate's euid is 0) · ROSTER_FILE_MISSING · ROSTER_FILE_UNSAFE (detail
 *               token: path-form, symlink-ancestor, symlink, not-regular, nlink, size, mode, owner, ancestor,
 *               short-read, unreadable)
 *  3-6 roster   `parseGateRoster` (the digest pin, stage 4, runs before any semantic rule)
 *    7 tenant   CONFIG_SOURCE_CONFLICT when NOA_GATE_TENANT is set and differs from the roster
 *    8 clock    `checkRosterClock`
 */
export function loadPinnedRoster(input: LoadPinnedRosterInput): PinnedRoster | PinnedRefusal {
  // ── stage 2: the roster file ──────────────────────────────────────────────────────────────────
  const gateEuid = input.gateEuid;
  // A gate running as root can rewrite ANY roster — root-owned or an administrator's — and its rewrite
  // survives a restart, so the owner rule below would certify nothing while the banner said ADMIN-OWNED.
  if (gateEuid === 0 && !input.unsafeSameUid) {
    return bootRefusal(
      "PINNED_ROOT_GATE",
      "the gate runs as root, which can rewrite any roster; run it as a dedicated non-root uid (or set NOA_GATE_UNSAFE_ROSTER_SAME_UID=1 for development)",
    );
  }
  const file = readPinnedFile(input.rosterFile, {
    maxBytes: ROSTER_MAX_BYTES,
    forbiddenModeBits: 0o022,
    requireSingleLink: true,
    // Root, or an administrator uid OTHER than the gate's: a roster the gate's own uid can rewrite is a
    // roster a compromised gate (or an agent sharing its uid) can rewrite and have survive a restart.
    ownerAllowed: input.unsafeSameUid ? () => true : (uid) => uid === 0 || uid !== gateEuid,
    checkAncestors: true,
  });
  if (!file.ok) {
    if (file.token === "missing") return bootRefusal("ROSTER_FILE_MISSING", file.detail);
    return bootRefusal("ROSTER_FILE_UNSAFE", file.detail);
  }

  // ── stages 3-6 ─────────────────────────────────────────────────────────────────────────────────
  const parsed = parseGateRoster(file.bytes, input.rosterSha256 !== undefined ? { expectedDigest: input.rosterSha256 } : {});
  if (!parsed.ok) return bootRefusal(parsed.code, parsed.reason);
  const { roster } = parsed;

  // ── stage 7: one tenant ────────────────────────────────────────────────────────────────────────
  if (input.tenantEnv !== undefined && input.tenantEnv !== roster.tenant) {
    return bootRefusal("CONFIG_SOURCE_CONFLICT", `NOA_GATE_TENANT ${JSON.stringify(input.tenantEnv)} differs from the roster's tenant ${JSON.stringify(roster.tenant)}`);
  }

  // ── stage 8: the gate's clock ──────────────────────────────────────────────────────────────────
  const clock = checkRosterClock(roster, parsed.activeApproverKid, input.nowMs);
  if (!clock.ok) return bootRefusal(clock.code, clock.reason);

  return {
    ok: true,
    roster,
    rosterDigest: parsed.digest,
    activeApproverKid: parsed.activeApproverKid,
    expiresAtMs: parsed.expiresAtMs,
    rosterCustody: gateEuid === 0 ? "ROOT-GATE (unsafe)" : input.unsafeSameUid ? "SAME-UID (unsafe)" : "ADMIN-OWNED",
  };
}

/**
 * Load a pinned trust root, stages 2-11, first failure wins. Stages 0-1 are `resolveTrustMode`,
 * stages 2-8 are `loadPinnedRoster`, then:
 *
 *    9 key file GATE_KEY_FILE_MISSING · GATE_KEY_FILE_UNSAFE · GATE_KEY_INCONSISTENT · GATE_KEY_NOT_PINNED
 *   10 signer   ROSTER_EXEC_SIGNER_MISMATCH
 *   11 state    STATE_LOCKED · STATE_FILE_UNSAFE · STATE_FILE_CORRUPT · ROSTER_ROLLBACK · ROSTER_EQUIVOCATION
 *               (and, from `commitState`, the same comparison again plus STATE_FILE_WRITE_FAILED)
 *
 * There is no retry and no fallback: a caller that receives a refusal must not start a gate.
 */
export function loadPinnedTrust(input: LoadPinnedTrustInput): PinnedBoot | PinnedRefusal {
  const loaded = loadPinnedRoster(input);
  if (!loaded.ok) return loaded;
  const { roster } = loaded;

  // ── stage 9: the persistent gate key — LOAD ONLY ───────────────────────────────────────────────
  // The shared loader runs `mintKeyPair` before it creates anything, so a mint that throws gives
  // load-only behaviour and no file ever appears. `noa-gate keygen` is the only minting path.
  let mintAttempted = false;
  let gateKey: GateKeyPair;
  try {
    gateKey = loadOrCreateKeyFile({
      keyFile: input.keyFile,
      mintKeyPair: () => {
        mintAttempted = true;
        throw new Error("GATE_KEY_FILE_MISSING");
      },
      callerLabel: "noa-gate",
    });
  } catch (err) {
    if (mintAttempted) {
      return bootRefusal("GATE_KEY_FILE_MISSING", `${JSON.stringify(input.keyFile)} does not exist; create it with \`noa-gate keygen --key-file <path> --kid <kid>\``);
    }
    return bootRefusal("GATE_KEY_FILE_UNSAFE", describeThrown(err));
  }
  const keyProblem = checkGateKey(gateKey, roster.gate);
  if (keyProblem !== null) return keyProblem;

  // ── stage 10: signer posture ───────────────────────────────────────────────────────────────────
  if ((roster.executionSigner === null) === input.grantSignerSocketSet) {
    return bootRefusal(
      "ROSTER_EXEC_SIGNER_MISMATCH",
      roster.executionSigner === null
        ? "NOA_GATE_GRANT_SIGNER_SOCKET is set but the roster pins no executionSigner"
        : "the roster pins an executionSigner but NOA_GATE_GRANT_SIGNER_SOCKET is not set",
    );
  }

  // ── stage 11: anti-rollback high-water, read-compare-write under ONE lock ───────────────────────
  // Two overlapping boots that each read version N and then write their own higher version in the
  // opposite order would LOWER the floor; an atomic rename prevents torn writes, not that. The lock is
  // held from this read to the rename in `commitState` (or until `release`).
  const statePath = `${input.keyFile}.roster-state`;
  const stateOwner = input.stateOwnerEuid ?? PROCESS_EUID;
  let releaseLock: () => void = () => {};
  if (input.lockState !== false) {
    const lock = acquireStateLock(`${statePath}.lock`, input.isProcessAlive ?? processAlive);
    if (!lock.ok) return lock;
    releaseLock = lock.release;
  }
  const compared = compareHighWater(readRosterState(statePath, stateOwner), roster.rosterVersion, loaded.rosterDigest);
  if (!compared.ok) {
    releaseLock();
    return compared;
  }
  const stateStatus = compared.status;

  const trust = createPinnedTrust({
    roster,
    rosterDigest: loaded.rosterDigest,
    activeApproverKid: loaded.activeApproverKid,
    expiresAtMs: loaded.expiresAtMs,
    gateKey,
    stateStatus,
    ...(input.now ? { now: input.now } : {}),
    ...(input.ids ? { ids: input.ids } : {}),
    ...(input.nonces ? { nonces: input.nonces } : {}),
  });
  const stateBytes = encodeDocument({ rosterDigest: loaded.rosterDigest, rosterVersion: roster.rosterVersion, spec: ROSTER_STATE_SPEC });
  return {
    ok: true,
    trust,
    roster,
    rosterDigest: loaded.rosterDigest,
    activeApproverKid: loaded.activeApproverKid,
    stateStatus,
    rosterCustody: loaded.rosterCustody,
    commitState(): PinnedRefusal | null {
      try {
        // Re-read and re-compare under the lock: a state written meanwhile by anything that ignores the
        // lock (an administrator's restore, a stale holder) must not be overwritten with a lower floor.
        const again = compareHighWater(readRosterState(statePath, stateOwner), roster.rosterVersion, loaded.rosterDigest);
        if (!again.ok) return again;
        if (again.status === "UNCHANGED") return null;
        const w = writeFileAtomic(statePath, stateBytes);
        return w.ok ? null : bootRefusal("STATE_FILE_WRITE_FAILED", w.detail);
      } finally {
        releaseLock();
      }
    },
    release(): void {
      releaseLock();
    },
  };
}

/** Compare a roster against the recorded high-water mark. */
function compareHighWater(
  state: StateRead,
  rosterVersion: number,
  rosterDigest: string,
): { ok: true; status: RosterStateStatus } | PinnedRefusal {
  if (!state.ok) return state;
  if (state.state === null) return { ok: true, status: "INITIALIZED" };
  if (rosterVersion < state.state.rosterVersion) {
    return bootRefusal(
      "ROSTER_ROLLBACK",
      `roster version ${rosterVersion} is below the high-water mark ${state.state.rosterVersion}; an older roster may re-admit a revoked approver`,
    );
  }
  if (rosterVersion === state.state.rosterVersion) {
    if (rosterDigest !== state.state.rosterDigest) {
      return bootRefusal(
        "ROSTER_EQUIVOCATION",
        `roster version ${rosterVersion} was already loaded with digest ${state.state.rosterDigest}; a changed roster needs a new version`,
      );
    }
    return { ok: true, status: "UNCHANGED" };
  }
  return { ok: true, status: "ADVANCED" };
}

/** Signal 0 probes existence without delivering anything; EPERM means alive but not ours. */
function processAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return thrownCode(err) === "EPERM";
  }
}

/**
 * The high-water lock: exclusive create. A lock whose holder is alive is STATE_LOCKED. A lock whose
 * holder is dead is taken over ONCE by identity (`takeOverStaleLock`) and the create retried; if the
 * lock changed hands meanwhile, STATE_LOCKED. A directory the gate cannot create files in is
 * STATE_DIR_NOT_WRITABLE: the lock and the state file live beside the key file, so its directory must be
 * writable by the gate.
 */
function acquireStateLock(lockPath: string, isAlive: (pid: number) => boolean): { ok: true; release: () => void } | PinnedRefusal {
  for (let attempt = 0; attempt < 2; attempt++) {
    const a = tryCreateLock(lockPath);
    if (a.ok) return { ok: true, release: () => a.release() };
    if (a.kind === "unwritable") {
      return bootRefusal("STATE_DIR_NOT_WRITABLE", `${a.detail}; the key file's directory must be writable by the gate (the high-water state and its lock live there)`);
    }
    if (a.holderPid === null || a.holderIdentity === null) {
      return bootRefusal("STATE_LOCKED", `${a.detail} and names no readable holder; an administrator must inspect and remove it`);
    }
    if (isAlive(a.holderPid)) {
      return bootRefusal("STATE_LOCKED", `the roster high-water state is locked by live process ${a.holderPid}; another gate is starting on this key file`);
    }
    if (attempt === 0 && takeOverStaleLock(lockPath, a.holderIdentity) === "changed") {
      return bootRefusal("STATE_LOCKED", `${JSON.stringify(lockPath)} changed hands while its dead holder's lock was being taken over; another gate is starting on this key file`);
    }
  }
  return bootRefusal("STATE_LOCKED", `${JSON.stringify(lockPath)}: a stale lock could not be replaced`);
}
