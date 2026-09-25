/**
 * #64-S5 — self-revoke, engine-level contract: idempotent (a second call is still success, never
 * an error), and it only ever touches `DeviceRecord.revokedAt` — the SAME shared 403 guard
 * (server.ts) then blocks every device route for free, proven at the HTTP layer in
 * test/http-self-revoke.test.ts.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair, spkiEd25519ToRawPublicKey, bytesToHex } from "noa-signer";
import { makeHarness, makeAgent, makeDevice, signDecisionReceipt, bodyOf, PARAMS_HASH } from "./helpers.js";
import { InMemoryStore } from "../src/store.js";
import { NoopLogPushProvider } from "../src/push.js";
import { resolveConfig } from "../src/config.js";
import { RelayEngine } from "../src/engine.js";

const ACTION = { canonical: "infra.deploy", riskClass: "HIGH" as const, paramsHash: PARAMS_HASH };

test("revokeSelf sets revokedAt exactly once; a second call is idempotent (still 204, timestamp unchanged)", () => {
  const h = makeHarness();
  const { agent } = makeAgent(h);
  const d = makeDevice(h, agent);
  assert.equal(d.device.revokedAt, null);

  const first = h.engine.revokeSelf(d.device);
  assert.equal(first.status, 204);
  const afterFirst = h.store.getDeviceById(d.device.id);
  assert.ok(afterFirst);
  assert.equal(typeof afterFirst!.revokedAt, "number");

  const revokedAtAfterFirst = afterFirst!.revokedAt;
  h.clock.t += 1000; // time moves; idempotency must NOT re-stamp
  const second = h.engine.revokeSelf(afterFirst!);
  assert.equal(second.status, 204);
  assert.equal(h.store.getDeviceById(d.device.id)!.revokedAt, revokedAtAfterFirst);
});

test("resolveDevice still finds a revoked device by its (unchanged) bearer secret hash", () => {
  const h = makeHarness();
  const { agent } = makeAgent(h);
  const d = makeDevice(h, agent);
  assert.equal(h.engine.revokeSelf(d.device).status, 204);

  const resolved = h.engine.resolveDevice(d.deviceSecret);
  assert.ok(resolved);
  assert.notEqual(resolved!.revokedAt, null);
});

test("R3 — revokeSelf reloads AUTHORITATIVE store state: calling it TWICE with the SAME stale (pre-revoke) record object never re-stamps revokedAt and never double-logs", () => {
  const clock = { t: 1_700_000_000_000 };
  const config = resolveConfig({ now: () => clock.t });
  const store = new InMemoryStore();
  const push = new NoopLogPushProvider();
  const events: Array<{ event: string; fields: Record<string, unknown> }> = [];
  const engine = new RelayEngine({ store, push, config, log: (event, fields) => events.push({ event, fields }) });

  const kid = "stale-record-device";
  const kp = generateKeyPair(kid, new Uint8Array(32).fill(3));
  const publicKeyHex = bytesToHex(spkiEd25519ToRawPublicKey(kp.publicKey));
  const reg = bodyOf<{ deviceId: string }>(engine.registerDevice({ kid, publicKeyHex }));
  const staleRecord = store.getDeviceById(reg.deviceId);
  if (!staleRecord) throw new Error("device not stored");
  assert.equal(staleRecord.revokedAt, null);

  const first = engine.revokeSelf(staleRecord);
  assert.equal(first.status, 204);
  const revokedAt = store.getDeviceById(reg.deviceId)!.revokedAt;
  assert.notEqual(revokedAt, null);

  clock.t += 5000; // time moves between the two calls
  // second call passes the EXACT SAME (now-stale, still revokedAt:null) object again — proves
  // revokeSelf must reload from the store rather than trust the caller-provided argument.
  const second = engine.revokeSelf(staleRecord);
  assert.equal(second.status, 204);
  assert.equal(store.getDeviceById(reg.deviceId)!.revokedAt, revokedAt, "revokedAt must not move on a stale-record double-call");

  const revokeLogs = events.filter((e) => e.event === "device.revoked");
  assert.equal(revokeLogs.length, 1, "revokeSelf must not re-log on an already-revoked device");
});

test("after revokeSelf, the signer-revoke check in decide() rejects — 403 DEVICE_REVOKED", () => {
  const h = makeHarness();
  const { agent } = makeAgent(h);
  const d = makeDevice(h, agent);
  const created = h.engine.createHold(agent, "idem-1", { action: ACTION });
  const { holdId } = bodyOf<{ holdId: string }>(created);

  assert.equal(h.engine.revokeSelf(d.device).status, 204);

  const receipt = signDecisionReceipt({
    kid: d.kid,
    privateKey: d.privateKey,
    canonical: ACTION.canonical,
    paramsHash: ACTION.paramsHash,
    verdict: "ALLOWED",
  });
  const res = h.engine.decide(d.device, holdId, { receipt });
  assert.equal(res.status, 403);
  assert.equal(bodyOf<{ error: string }>(res).error, "DEVICE_REVOKED");
});

test("decide() authenticates the receipt before naming the signer's state: a forgery is UNVERIFIED_SIGNATURE, never DEVICE_REVOKED or DEVICE_MISMATCH", () => {
  // DEVICE_REVOKED and DEVICE_MISMATCH describe the REGISTERED device whose kid the receipt names.
  // That is true of a receipt the device signed; for a signature it never made, the answer is that
  // the receipt is not authentic.
  const h = makeHarness();
  const { agent } = makeAgent(h);
  const d = makeDevice(h, agent, "approver-1", 7);
  const other = makeDevice(h, agent, "approver-2", 9);
  const forger = generateKeyPair("approver-1", new Uint8Array(32).fill(13));
  const created = h.engine.createHold(agent, "idem-forged", { action: ACTION });
  const { holdId } = bodyOf<{ holdId: string }>(created);
  const receiptBy = (kid: string, privateKey: string) => signDecisionReceipt({
    kid,
    privateKey,
    canonical: ACTION.canonical,
    paramsHash: ACTION.paramsHash,
    verdict: "ALLOWED",
  });
  const errorOf = (res: { status: number; body: unknown }) => `${res.status} ${bodyOf<{ error: string }>(res).error}`;

  // Another registered device's kid: authentic -> DEVICE_MISMATCH; forged -> UNVERIFIED_SIGNATURE.
  assert.equal(errorOf(h.engine.decide(d.device, holdId, { receipt: receiptBy(other.kid, other.privateKey) })), "403 DEVICE_MISMATCH");
  assert.equal(errorOf(h.engine.decide(d.device, holdId, { receipt: receiptBy(other.kid, forger.privateKey) })), "422 UNVERIFIED_SIGNATURE");

  // A revoked signer: authentic -> DEVICE_REVOKED; forged -> UNVERIFIED_SIGNATURE.
  assert.equal(h.engine.revokeSelf(d.device).status, 204);
  assert.equal(errorOf(h.engine.decide(d.device, holdId, { receipt: receiptBy(d.kid, d.privateKey) })), "403 DEVICE_REVOKED");
  assert.equal(errorOf(h.engine.decide(d.device, holdId, { receipt: receiptBy(d.kid, forger.privateKey) })), "422 UNVERIFIED_SIGNATURE");
});
