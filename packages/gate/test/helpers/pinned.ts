/**
 * Test fixtures for the pinned roster (`noa.gate-roster/1`). Every key is generated here, in the test
 * process; nothing is read from the host. Identifiers are synthetic (`tenant-example-1`,
 * `gate-example-1`, `approver-example-N`, `audit-example-1`, `exec-example-1`).
 */
import { generateKeyPairSync } from "node:crypto";
import { chmodSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPair, type KeyPair } from "noa-approval-artifacts";
import { parseGateRoster } from "../../src/roster.js";
import { createPinnedTrust, type GateTrust, type RosterStateStatus } from "../../src/trust.js";

export const TENANT = "tenant-example-1";
export const GATE_KID = "gate-example-1";
export const AUDIT_KID = "audit-example-1";
export const EXEC_KID = "exec-example-1";
export const approverKid = (n: number): string => `approver-example-${n}`;

/** An X25519 recipient key: the roster's base64 DER SPKI public half and the raw 32-byte secret. */
export interface X25519Pair {
  publicKey: string;
  secretKey: Uint8Array;
}
export function x25519Pair(): X25519Pair {
  const { publicKey, privateKey } = generateKeyPairSync("x25519");
  const jwk = privateKey.export({ format: "jwk" }) as { d?: string };
  return {
    publicKey: (publicKey.export({ type: "spki", format: "der" }) as Buffer).toString("base64"),
    secretKey: new Uint8Array(Buffer.from(jwk.d as string, "base64url")),
  };
}

export interface ApproverKeys {
  kid: string;
  ed: KeyPair;
  x: X25519Pair;
}
export function approverKeys(n: number): ApproverKeys {
  const kid = approverKid(n);
  return { kid, ed: generateKeyPair(kid), x: x25519Pair() };
}

export interface RosterWorld {
  gate: KeyPair;
  approver: ApproverKeys;
  audit: X25519Pair;
}
export function newWorld(): RosterWorld {
  return { gate: generateKeyPair(GATE_KID), approver: approverKeys(1), audit: x25519Pair() };
}

const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;

/** A valid roster document around `nowMs`: one active approve-critical approver, quorum HIGH+CRITICAL. */
export function rosterDoc(world: RosterWorld, nowMs: number, over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    spec: "noa.gate-roster/1",
    tenant: TENANT,
    rosterVersion: 3,
    validFrom: new Date(nowMs - HOUR).toISOString(),
    expiresAt: new Date(nowMs + 30 * DAY).toISOString(),
    epoch: { keyManifestVersion: 2, keyManifestHash: "sha256:" + "2".repeat(64) },
    gate: { kid: world.gate.kid, publicKey: world.gate.publicKey },
    executionSigner: null,
    approvers: {
      [world.approver.kid]: {
        role: "approve-critical",
        publicKey: world.approver.ed.publicKey,
        hpkePublicKey: world.approver.x.publicKey,
        validFrom: new Date(nowMs - HOUR).toISOString(),
        revokedAt: null,
      },
    },
    audit: { kid: AUDIT_KID, hpkePublicKey: world.audit.publicKey },
    quorum: { HIGH: 1, CRITICAL: 1 },
    ...over,
  };
}

export const rosterBytes = (doc: unknown): Uint8Array => new TextEncoder().encode(JSON.stringify(doc));

/** Parse a roster document the way the loader does and build its trust root. Throws on refusal. */
export function pinnedTrustFrom(
  doc: Record<string, unknown>,
  gateKey: KeyPair,
  opts: { now?: () => number; ids?: () => string; stateStatus?: RosterStateStatus } = {},
): GateTrust {
  const parsed = parseGateRoster(rosterBytes(doc));
  if (!parsed.ok) throw new Error(`fixture roster refused: ${parsed.reason}`);
  return createPinnedTrust({
    roster: parsed.roster,
    rosterDigest: parsed.digest,
    activeApproverKid: parsed.activeApproverKid,
    expiresAtMs: parsed.expiresAtMs,
    gateKey: { kid: gateKey.kid, publicKey: gateKey.publicKey, privateKey: gateKey.privateKey },
    stateStatus: opts.stateStatus ?? "INITIALIZED",
    ...(opts.now ? { now: opts.now } : {}),
    ...(opts.ids ? { ids: opts.ids } : {}),
  });
}

const created: string[] = [];
let cleanupArmed = false;

/**
 * A fresh directory whose REAL path is returned, so the ancestor walk sees what the test sees. Every
 * directory made here is removed when the test process exits.
 */
export function freshDir(label: string): string {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), `noa-gate-${label}-`)));
  created.push(dir);
  if (!cleanupArmed) {
    cleanupArmed = true;
    process.on("exit", () => {
      for (const d of created) rmSync(d, { recursive: true, force: true });
    });
  }
  return dir;
}

export function writeRoster(dir: string, doc: unknown, name = "roster.json", mode = 0o644): string {
  const p = join(dir, name);
  writeFileSync(p, JSON.stringify(doc, null, 2), { mode });
  chmodSync(p, mode);
  return p;
}

export function writeKeyFile(dir: string, key: KeyPair, name = "gate.key.json"): string {
  const p = join(dir, name);
  writeFileSync(p, JSON.stringify({ kid: key.kid, privateKey: key.privateKey, publicKey: key.publicKey }), { mode: 0o600 });
  chmodSync(p, 0o600);
  return p;
}
