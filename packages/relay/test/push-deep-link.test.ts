import { test } from "node:test";
import assert from "node:assert/strict";
import { buildApprovalDeepLink } from "../src/engine.js";
import { makeHarness, makeAgent, makeDevice, bodyOf, PARAMS_HASH } from "./helpers.js";

const ACTION = { canonical: "infra.deploy", riskClass: "HIGH" as const, paramsHash: PARAMS_HASH };
const settle = () => new Promise((resolve) => setTimeout(resolve, 50));

function subscribeOwner(
  approvalDeepLinkBuilder?: (encodedHoldId: string) => string,
) {
  const h = makeHarness({}, undefined, approvalDeepLinkBuilder);
  const { agent } = makeAgent(h, "deep-link-agent", "deep-link-tenant");
  const device = makeDevice(h, agent, "deep-link-device", 17);
  h.engine.registerPush(device.device.id, { subscription: { token: "local-test" } });
  return { h, agent };
}

test("push deep-link keeps the legacy route and percent-encodes the hold-id segment", async () => {
  assert.equal(
    buildApprovalDeepLink("hold/with ? reserved#bytes"),
    "/app/approve/hold%2Fwith%20%3F%20reserved%23bytes",
  );

  const { h, agent } = subscribeOwner();
  const created = bodyOf<{ holdId: string }>(
    h.engine.createHold(agent, "deep-link-default", { action: ACTION }),
  );
  await settle();

  assert.equal(h.push.sent.length, 1);
  assert.equal(h.push.sent[0]?.msg.deepLink, `/app/approve/${encodeURIComponent(created.holdId)}`);
});

test("deployment builder receives an encoded segment and owns the final URI", async () => {
  let received: string | null = null;
  const { h, agent } = subscribeOwner((encodedHoldId) => {
    received = encodedHoldId;
    return `noa-example://approval/${encodedHoldId}`;
  });
  const created = bodyOf<{ holdId: string }>(
    h.engine.createHold(agent, "deep-link-override", { action: ACTION }),
  );
  await settle();

  assert.equal(received, encodeURIComponent(created.holdId));
  assert.equal(h.push.sent.length, 1);
  assert.equal(h.push.sent[0]?.msg.deepLink, `noa-example://approval/${encodeURIComponent(created.holdId)}`);
});

test("an invalid deployment builder degrades to polling without an unhandled rejection", async () => {
  const { h, agent } = subscribeOwner(() => "");
  bodyOf<{ holdId: string }>(
    h.engine.createHold(agent, "deep-link-invalid", { action: ACTION }),
  );
  await settle();

  assert.equal(h.push.sent.length, 0);
  assert.equal(h.logs.filter((entry) => entry.event === "push.deep_link.invalid").length, 1);
});
