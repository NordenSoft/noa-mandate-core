/**
 * The artifacts a hold's approver and any relay need, obtained over the gate's public HTTP API only.
 *
 * An approval receipt chains onto the gate-signed DEFERRED receipt, so every party that builds or
 * checks an approval needs it. It must reach them from the 201 of `POST /v1/holds` and from every
 * hold view, never from the gate's in-process store. Nothing here reads the store.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { receiptRefHash } from "noa-approval-artifacts";
import { createGate, type Gate } from "../src/server.js";
import type { HoldEnvelope, Receipt } from "../src/types.js";
import { makeClock, sampleCommandParams, signPhoneDecision } from "./helpers.js";
import { newWorld } from "./helpers/pinned.js";
import { AGENT_1_SECRET, effectGate, idSource } from "./helpers/effect.js";

test("HOLD-DEFERRED-RECEIPT — over HTTP, the 201 of createHold and the hold view carry the gate-signed deferred receipt the envelope binds, and an approval built from them decides", async () => {
  const world = newWorld();
  const clock = makeClock();
  const built: { gate?: Gate } = {};
  const fx = effectGate({
    world,
    clock,
    owner: false,
    ids: idSource("http-artifacts"),
    makeEngine: (deps) => {
      built.gate = createGate({
        trust: deps.trust,
        store: deps.store,
        ...(deps.sealDisplay ? { sealDisplay: deps.sealDisplay } : {}),
        ...(deps.executionSigner ? { executionSigner: deps.executionSigner } : {}),
        config: { bindAddress: "127.0.0.1", port: 0, now: () => clock.t },
      });
      return built.gate.engine;
    },
  });
  const gate = built.gate as Gate;
  const { port } = await gate.listen();
  try {
    const base = `http://127.0.0.1:${port}`;
    const auth = { authorization: `Bearer ${AGENT_1_SECRET}`, "content-type": "application/json" };
    const createBody = JSON.stringify({
      mode: "ENFORCED",
      action: { canonical: "noa.command.exec", riskClass: "HIGH", reversible: false },
      params: sampleCommandParams(),
      chain: "http-artifacts",
    });
    const createdRes = await fetch(`${base}/v1/holds`, { method: "POST", headers: { ...auth, "idempotency-key": "idem-http-artifacts" }, body: createBody });
    assert.equal(createdRes.status, 201);
    const created = await createdRes.json() as Record<string, unknown>;
    const holdId = created["holdId"] as string;
    const envelope = created["holdEnvelope"] as HoldEnvelope;
    const deferred = created["deferredReceipt"] as Receipt | undefined;
    assert.ok(
      deferred !== undefined && receiptRefHash(deferred as unknown as Record<string, unknown>) === envelope.deferredReceiptHash,
      "consequence: a client that sees only HTTP holds the deferred receipt the envelope binds",
    );

    // A retried create (same key, same body) is the idempotent 200: it carries the same receipt.
    const replayRes = await fetch(`${base}/v1/holds`, { method: "POST", headers: { ...auth, "idempotency-key": "idem-http-artifacts" }, body: createBody });
    const replay = await replayRes.json() as Record<string, unknown>;
    assert.deepEqual(replay["deferredReceipt"], deferred, "consequence: a client whose first response was lost still obtains the deferred receipt");
    assert.deepEqual([replayRes.status, replay["idempotent"], replay["holdId"]], [200, true, holdId]);

    const viewRes = await fetch(`${base}/v1/holds/${holdId}`, { headers: auth });
    assert.equal(viewRes.status, 200);
    const view = await viewRes.json() as Record<string, unknown>;
    assert.deepEqual(view["deferredReceipt"], deferred, "every hold view carries the same deferred receipt");

    // The approval is built from the HTTP artifacts alone; the gate accepts it.
    const decision = signPhoneDecision({
      trust: fx.trust,
      deferredReceipt: deferred as Receipt,
      holdEnvelope: envelope,
      decision: "APPROVE",
      signer: { kid: world.approver.kid, privateKey: world.approver.ed.privateKey },
    });
    const decidedRes = await fetch(`${base}/v1/holds/${holdId}/decision`, { method: "POST", headers: auth, body: JSON.stringify(decision) });
    assert.equal(decidedRes.status, 200);
    const decided = await decidedRes.json() as Record<string, unknown>;
    assert.equal(decided["status"], "APPROVED");
    assert.deepEqual(decided["deferredReceipt"], deferred);
  } finally {
    await gate.close();
  }
});
