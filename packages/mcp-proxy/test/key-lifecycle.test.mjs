import assert from "node:assert/strict";
import test from "node:test";
import { generateKeyPairSync } from "node:crypto";

import {
  buildOutcomeReceipt,
  verifyOutcomeReceipt,
} from "../src/outcome-receipt.mjs";
import { createRotatableSigner } from "../src/rotatable-signer.mjs";

function keyPair() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return {
    privateKey: privateKey.export({ type: "pkcs8", format: "der" }).toString("base64"),
    publicKey: publicKey.export({ type: "spki", format: "der" }).toString("base64"),
  };
}

function decisionReceipt(suffix) {
  return {
    spec: "noa.receipt/0.1",
    id: `decision-${suffix}`,
    chain: { hash: `sha256:${"1".repeat(64)}` },
    scope: { tenant: "tenant-a", chain: "chain-a" },
    agent: { id: "agent-a" },
    action: { id: "tool-a", paramsHash: `sha256:${"2".repeat(64)}` },
    governance: { verdict: "ALLOW" },
  };
}

test("P0-14 cached lifecycle handle stays current and retired keys fail closed", () => {
  const first = keyPair();
  const second = keyPair();
  let now = "2026-01-01T00:00:00.000Z";
  const signer = createRotatableSigner(
    { kid: "outcome-1", privateKey: first.privateKey, publicKey: first.publicKey },
    { now: () => Date.parse(now) },
  );

  const cachedLifecycle = signer.verificationLifecycle();
  const oldOutcome = buildOutcomeReceipt({
    decisionReceipt: decisionReceipt("old"),
    tool: "tool-a",
    outcome: "success",
    ts: now,
  }, signer);

  now = "2026-01-02T00:00:00.000Z";
  signer.rotate({ kid: "outcome-2", privateKey: second.privateKey, publicKey: second.publicKey });
  const newOutcome = buildOutcomeReceipt({
    decisionReceipt: decisionReceipt("new"),
    tool: "tool-a",
    outcome: "success",
    ts: now,
  }, signer);

  assert.equal(
    verifyOutcomeReceipt(newOutcome, { verification: cachedLifecycle }).ok,
    true,
    "a cached lifecycle handle must resolve the newly current key",
  );
  const retiredAttack = verifyOutcomeReceipt(oldOutcome, { verification: cachedLifecycle });
  assert.equal(retiredAttack.ok, false);
  assert.match(retiredAttack.reason ?? "", /retired/i);
  assert.equal(signer.historicalKeyring, undefined, "no lifecycle-stripping downgrade helper may be exposed");
});

test("retired outcome key: a forged signature is a signature mismatch, not a retirement", () => {
  // The kernel resolver checks the outcome's signature against the retired key's retained public
  // material before naming the refusal: only an authentic signature is reported as retired.
  const first = keyPair();
  const second = keyPair();
  let now = "2026-01-01T00:00:00.000Z";
  const signer = createRotatableSigner(
    { kid: "outcome-1", privateKey: first.privateKey, publicKey: first.publicKey },
    { now: () => Date.parse(now) },
  );
  const lifecycle = signer.verificationLifecycle();
  const oldOutcome = buildOutcomeReceipt({ decisionReceipt: decisionReceipt("old"), tool: "tool-a", outcome: "success", ts: now }, signer);
  const otherOutcome = buildOutcomeReceipt({ decisionReceipt: decisionReceipt("other"), tool: "tool-a", outcome: "error", ts: now }, signer);
  now = "2026-01-02T00:00:00.000Z";
  signer.rotate({ kid: "outcome-2", privateKey: second.privateKey, publicKey: second.publicKey });

  // Same content and kid, the signature of a different outcome.
  const forged = { ...oldOutcome, sig: { ...oldOutcome.sig, value: otherOutcome.sig.value } };
  const attack = verifyOutcomeReceipt(forged, { verification: lifecycle });
  assert.equal(attack.ok, false);
  assert.match(attack.reason ?? "", /invalid signature/, `a forged outcome naming a retired kid was labelled ${JSON.stringify(attack.reason)}`);
  assert.doesNotMatch(attack.reason ?? "", /retired/i);
  const authentic = verifyOutcomeReceipt(oldOutcome, { verification: lifecycle });
  assert.equal(authentic.ok, false);
  assert.match(authentic.reason ?? "", /retired/i);

  // The signed bytes are now built BEFORE the key is resolved, so an outcome that cannot be
  // canonicalized is refused as malformed whatever its kid (it was "not in keyring" for an unknown
  // kid before, and already malformed for a known one).
  const malformed = { ...oldOutcome, outcome: { ...oldOutcome.outcome, ratio: 0.5 }, sig: { ...oldOutcome.sig, kid: "outcome-unknown" } };
  const refused = verifyOutcomeReceipt(malformed, { verification: lifecycle });
  assert.equal(refused.ok, false);
  assert.match(refused.reason ?? "", /^verify threw: /);
});

test("P0-14 non-rotating consumers retain a multi-key static-map control", () => {
  const first = keyPair();
  const second = keyPair();
  const firstOutcome = buildOutcomeReceipt({
    decisionReceipt: decisionReceipt("static-1"),
    tool: "tool-a",
    outcome: "success",
  }, { kid: "static-1", privateKey: first.privateKey });
  const secondOutcome = buildOutcomeReceipt({
    decisionReceipt: decisionReceipt("static-2"),
    tool: "tool-a",
    outcome: "success",
  }, { kid: "static-2", privateKey: second.privateKey });
  const keyring = {
    "static-1": first.publicKey,
    "static-2": second.publicKey,
  };

  assert.equal(verifyOutcomeReceipt(firstOutcome, { verification: keyring }).ok, true);
  assert.equal(verifyOutcomeReceipt(secondOutcome, { verification: keyring }).ok, true);
});

test("P0-14 lifecycle snapshots remain frozen if Object.freeze is poisoned after module load", () => {
  const pair = keyPair();
  const originalFreeze = Object.freeze;
  Object.freeze = (value) => value;
  try {
    const signer = createRotatableSigner({
      kid: "outcome-1",
      privateKey: pair.privateKey,
      publicKey: pair.publicKey,
    });
    const lifecycle = signer.verificationLifecycle();
    assert.equal(Object.isFrozen(lifecycle), true);
    assert.equal(Object.isFrozen(lifecycle.keys), true);
    assert.equal(Object.isFrozen(lifecycle.keys["outcome-1"]), true);
  } finally {
    Object.freeze = originalFreeze;
  }
});

test("P0-14 a poisoned Map iterator cannot relabel a retired key as current", () => {
  const first = keyPair();
  const second = keyPair();
  const signer = createRotatableSigner(
    { kid: "outcome-1", privateKey: first.privateKey, publicKey: first.publicKey },
    { now: () => Date.parse("2026-01-02T00:00:00.000Z") },
  );
  const cachedLifecycle = signer.verificationLifecycle();
  const oldOutcome = buildOutcomeReceipt({
    decisionReceipt: decisionReceipt("map-poison"),
    tool: "tool-a",
    outcome: "success",
    ts: "2026-01-01T00:00:00.000Z",
  }, signer);
  signer.rotate({ kid: "outcome-2", privateKey: second.privateKey, publicKey: second.publicKey });

  const clean = verifyOutcomeReceipt(oldOutcome, { verification: cachedLifecycle });
  assert.equal(clean.ok, false);
  assert.match(clean.reason ?? "", /retired/i);

  const originalIterator = Map.prototype[Symbol.iterator];
  Map.prototype[Symbol.iterator] = function* forgedRetirementIterator() {
    yield ["outcome-1", { publicKey: first.publicKey, retiredAt: null }];
  };
  try {
    const attacked = verifyOutcomeReceipt(oldOutcome, { verification: cachedLifecycle });
    assert.equal(attacked.ok, false, "post-load iterator poison must not rewrite the lifecycle snapshot");
    assert.match(attacked.reason ?? "", /retired/i);
  } finally {
    Map.prototype[Symbol.iterator] = originalIterator;
  }
});
