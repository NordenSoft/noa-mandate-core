/**
 * `noa.ledger.transfer/1` inside the reference Gate — the sealed adapter that is deliberately NOT
 * registered (src/projections.ts, `ledgerTransferProjection`).
 *
 * What this file pins, and why each assertion exists:
 *
 *   1. NOT REGISTERED. `getProjection("noa.ledger.transfer")` is undefined and a hold for this
 *      canonical is refused with UNREGISTERED_CRITICAL_ACTION. A registered transfer would yield an
 *      agent-readable, gate-signed grant before any effect owner can consume it at commit time. A
 *      later revision of the reference Gate that registers it must flip BOTH assertions on purpose.
 *   2. ONE IDENTITY. The identity the gate measures from the kernel function equals the kernel's
 *      published pins (the module also throws at import if it does not).
 *   3. ONE DERIVATION. Every corpus vector whose text strict-parses, fed to `run()` as a parsed
 *      object, gives exactly the kernel's result — same hash, same display, same refusal code — and
 *      every accept carries the gate's fixed HIGH risk floor.
 *   4. ONE READ. A live object is serialized once, so a getter or Proxy cannot split what is hashed
 *      from what is shown, and a hostile throw comes back as a refusal, never as a raw exception.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseDocument } from "noa-approval-artifacts";
import {
  LEDGER_TRANSFER_CANONICAL,
  LEDGER_TRANSFER_SCHEMA_ID,
  LEDGER_TRANSFER_DISPLAY_ID,
  projectLedgerTransfer,
} from "noa-receipt";
import { getProjection, ledgerTransferProjection } from "../src/projections.js";
import { setupGate, body, sampleCommandParams } from "./helpers.js";

const HERE = dirname(fileURLToPath(import.meta.url));
// dist/test -> packages/gate -> packages -> repository root
const ROOT = join(HERE, "..", "..", "..", "..");

interface ParamsVector {
  name: string;
  group?: string;
  paramsText?: string;
  paramsHex?: string;
  expect: { ok: boolean; paramsHash?: string; display?: Record<string, string>; reasonCode?: string };
}
const corpus = JSON.parse(
  readFileSync(join(ROOT, "conformance", "ledger-transfer", "vectors.json"), "utf8"),
) as { canonical: string; vectors: ParamsVector[] };

const BASE = {
  amount: "12345",
  fromAccount: "acct-example-1",
  ledger: "ledger-example-1",
  salt: "000102030405060708090a0b0c0d0e0f",
  toAccount: "acct-example-2",
  unit: "XTS",
} as const;
const BASE_HASH = "sha256:aa9256899837f204583f28e483ed67129b204e7edabf378eaf60f296915aebd0";

/** Called WITHOUT a receiver on purpose: the adapter must not depend on `this`. */
const run = ledgerTransferProjection.run;

test("noa.ledger.transfer is NOT registered: no adapter is returned for it, and the reviewed adapter is unchanged", () => {
  assert.equal(corpus.canonical, LEDGER_TRANSFER_CANONICAL);
  assert.equal(ledgerTransferProjection.canonical, LEDGER_TRANSFER_CANONICAL);
  assert.equal(getProjection(LEDGER_TRANSFER_CANONICAL), undefined,
    "registering this adapter is a deliberate later change that must update this assertion");
  assert.ok(getProjection("noa.command.exec"), "the registry still carries its one reviewed adapter");
});

test("a hold for noa.ledger.transfer is refused as UNREGISTERED_CRITICAL_ACTION and leaves no state", () => {
  const fx = setupGate();
  const created = fx.engine.createHold(fx.agent, "idem-ledger-transfer", body({
    action: { canonical: LEDGER_TRANSFER_CANONICAL, riskClass: "HIGH", reversible: false },
    params: { ...BASE },
    chain: "chain-ledger-transfer",
  }));
  assert.equal(created.status, 422, JSON.stringify(created.body));
  assert.equal((created.body as { error: string }).error, "UNREGISTERED_CRITICAL_ACTION");
  // The store is keyed by a gate-generated hold id, so a lookup by chain name could never find
  // anything. Count every hold, and look the request up by the key the store actually indexes.
  assert.equal(fx.store.listHolds({}).length, 0, "a refused request must create no hold");
  assert.equal(fx.store.getHoldByIdem(fx.agent.id, "idem-ledger-transfer"), undefined);
  // Anti-vacuity: the same probes DO see a hold when one is created — here the registered adapter.
  const control = fx.engine.createHold(fx.agent, "idem-command-control", body({
    mode: "ENFORCED",
    action: { canonical: "noa.command.exec", riskClass: "HIGH", reversible: false },
    params: sampleCommandParams(),
    chain: "chain-command-control",
  }));
  assert.equal(control.status, 201, JSON.stringify(control.body));
  assert.equal(fx.store.listHolds({}).length, 1, "the probe must be able to see a created hold");
  assert.ok(fx.store.getHoldByIdem(fx.agent.id, "idem-command-control"));
});

test("the gate measures the same identity the kernel publishes", () => {
  assert.deepEqual({ ...ledgerTransferProjection.actionSchema }, { ...LEDGER_TRANSFER_SCHEMA_ID });
  assert.deepEqual({ ...ledgerTransferProjection.displayProjection }, { ...LEDGER_TRANSFER_DISPLAY_ID });
  assert.notEqual(ledgerTransferProjection.actionSchema.hash, ledgerTransferProjection.displayProjection.hash);
});

test("the adapter is sealed: it cannot be repointed after load", () => {
  assert.ok(Object.isFrozen(ledgerTransferProjection));
  assert.ok(Object.isFrozen(ledgerTransferProjection.actionSchema));
  assert.ok(Object.isFrozen(ledgerTransferProjection.run));
  assert.throws(() => {
    (ledgerTransferProjection as { run: unknown }).run = () => ({ ok: false, error: "replaced" });
  }, TypeError);
});

// ── ONE DERIVATION: the corpus, replayed through the gate's object entry point ──────────────────
let replayed = 0;
const notReplayed: string[] = [];
for (const vec of corpus.vectors) {
  if (typeof vec.paramsText !== "string") continue; // identity vectors and byte-level vectors
  const parsed = parseDocument(new TextEncoder().encode(vec.paramsText), "params");
  if (!parsed.ok) { // parse-layer vectors never reach an object entry point
    notReplayed.push(`${vec.name}:${vec.expect.reasonCode}`);
    continue;
  }
  replayed++;
  test(`ledger-transfer gate replay/${vec.name} → ${vec.expect.ok ? "ACCEPT at HIGH" : `REJECT ${vec.expect.reasonCode}`}`, () => {
    const res = run(parsed.value);
    if (vec.expect.ok) {
      assert.ok(res.ok, `unexpected refusal: ${res.ok ? "" : res.error}`);
      assert.equal(res.paramsHash, vec.expect.paramsHash);
      assert.deepEqual({ ...res.display }, vec.expect.display);
      assert.equal(res.derivedRisk, "HIGH", "the gate's risk floor for every transfer is HIGH, independent of the amount");
      assert.equal(res.actionSchema.hash, LEDGER_TRANSFER_SCHEMA_ID.hash);
      assert.equal(res.displayProjection.hash, LEDGER_TRANSFER_DISPLAY_ID.hash);
    } else {
      assert.equal(res.ok, false, "expected a refusal");
      assert.ok(!res.ok && res.error.startsWith(`${vec.expect.reasonCode}: `),
        `${vec.name}: refused for the WRONG reason: ${res.ok ? "" : res.error}`);
    }
  });
}

test("the gate replay covers the corpus (every vector that can reach an object entry point)", () => {
  // Pinned exactly: 146 text vectors, of which the 11 that are TRANSFER_PARSE cannot be expressed as
  // an object. Move this number only together with the corpus, and say which vectors moved it.
  assert.equal(replayed, 135, `the gate replayed ${replayed} vectors`);
  assert.equal(notReplayed.length, 11);
  for (const entry of notReplayed) {
    assert.ok(entry.endsWith(":TRANSFER_PARSE"), `${entry}: only parse-layer vectors may be skipped`);
  }
});

// ── ONE READ: hostile live objects ───────────────────────────────────────────────────────────────

test("a getter is read exactly once, and what is shown is what is hashed", () => {
  let reads = 0;
  const values = ["12345", "99999"];
  const hostile: Record<string, unknown> = { ...BASE };
  // Answers 12345 on the first read and 99999 on any later read — the classic hash/display split.
  Object.defineProperty(hostile, "amount", { enumerable: true, get() { return values[Math.min(reads++, 1)]; } });
  const res = run(hostile);
  assert.equal(reads, 1, "the caller's value must be read in one pass");
  assert.ok(res.ok);
  assert.equal(res.paramsHash, BASE_HASH);
  assert.equal((res.display as Record<string, string>)["Amount"], "12345 XTS");
  // And the display re-projects to the same hash through the kernel's byte entry point.
  const again = projectLedgerTransfer(JSON.stringify({ ...BASE, amount: "12345" }));
  assert.ok(again.ok && again.paramsHash === res.paramsHash);
});

test("hostile values come back as refusals, never as raw throws", () => {
  const { proxy, revoke } = Proxy.revocable({}, {});
  revoke();
  const throwing: Record<string, unknown> = { ...BASE };
  Object.defineProperty(throwing, "ledger", { enumerable: true, get() { throw proxy; } });
  const cases: Array<[unknown, string]> = [
    [throwing, "TRANSFER_PARSE"],
    [proxy, "TRANSFER_PARSE"],
    [{ ...BASE, toJSON: () => ({ ...BASE, amount: "1" }) }, "TRANSFER_PARSE"],
    [{ ...BASE, amount: 1.5 }, "TRANSFER_PARSE"],
    [{ ...BASE, amount: 12345n }, "TRANSFER_PARSE"],
    [{ ...BASE, amount: undefined }, "TRANSFER_PARSE"],
    [null, "TRANSFER_NOT_OBJECT"],
    [[BASE], "TRANSFER_NOT_OBJECT"],
    ["{}", "TRANSFER_NOT_OBJECT"],
    [{ ...BASE, memo: "rent" }, "TRANSFER_UNRECOGNIZED_MEMBER"],
  ];
  for (const [input, code] of cases) {
    let res: ReturnType<typeof run> | undefined;
    assert.doesNotThrow(() => { res = run(input); });
    assert.ok(res && !res.ok && res.error.startsWith(`${code}: `), `expected ${code}, got ${JSON.stringify(res)}`);
  }
});

test("what JCS cannot serialize cannot ride along: symbol-keyed and non-enumerable extras bind nothing", () => {
  const extra: Record<string | symbol, unknown> = { ...BASE, [Symbol("memo")]: "rent" };
  Object.defineProperty(extra, "memo", { enumerable: false, value: "rent" });
  const res = run(extra);
  // The canonical bytes carry the six members only, so the bound transfer is exactly the base one;
  // nothing outside those bytes reaches the display, the hash, or anything downstream of them.
  assert.ok(res.ok);
  assert.equal(res.paramsHash, BASE_HASH);
});
