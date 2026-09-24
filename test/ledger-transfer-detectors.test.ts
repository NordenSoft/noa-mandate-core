/**
 * `noa.ledger.transfer/1` — the NAMED DETECTORS for three knockout arms, in a file of their own.
 *
 * Three controls live inside `projectLedgerTransfer`'s own body: the strict parse, the hash over the
 * re-emitted canonical bytes, and the display's Salt row. `test/ledger-transfer.test.ts` also hashes
 * that body (the implementation-digest pin), so on that file any mutation of those three controls
 * is killed by the pin test alone, and the knockout would say nothing about the vector it names.
 * This file carries no pin test. Each of the three tests below is the one detector its arm names,
 * and each mutation turns only its own detector red (measured per arm before this file landed):
 *
 *   ledger-transfer-bytes-in-strict-parse  -> the duplicate-amount vector is refused as TRANSFER_PARSE
 *   ledger-transfer-hash-over-canonical    -> the escaped-spelling vector binds the base hash
 *   ledger-transfer-display-shows-salt     -> display completeness
 *
 * The knockout arms run this file through `npm run test:ledger-transfer:detectors` — a build step
 * and one `node --test` evidence step, the only suite shape the knockout runner's trusted script
 * grammar accepts for compiled TypeScript. The two vector detectors read the committed corpus, so
 * the vector they check is exactly the one the corpus publishes.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  LEDGER_TRANSFER_CANONICAL,
  projectLedgerTransfer,
  type LedgerTransferResult,
} from "../src/ledger-transfer.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..");

interface ParamsVector {
  name: string;
  paramsText?: string;
  expect: { ok: boolean; paramsHash?: string; canonical?: string; reasonCode?: string; reasonContains?: string };
}
const corpus = JSON.parse(
  readFileSync(join(ROOT, "conformance", "ledger-transfer", "vectors.json"), "utf8"),
) as { vectors: ParamsVector[] };

function vector(name: string): ParamsVector {
  const v = corpus.vectors.find((x) => x.name === name);
  assert.ok(v && typeof v.paramsText === "string", `the corpus must carry the text vector ${name}`);
  return v;
}

const MEMBERS = ["amount", "fromAccount", "ledger", "salt", "toAccount", "unit"] as const;
const baseParams = (overrides: Record<string, unknown> = {}): Record<string, unknown> => ({
  amount: "12345", fromAccount: "acct-example-1", ledger: "ledger-example-1",
  salt: "000102030405060708090a0b0c0d0e0f", toAccount: "acct-example-2", unit: "XTS", ...overrides,
});
const run = (params: unknown): LedgerTransferResult => projectLedgerTransfer(JSON.stringify(params));

test("named detector (strict parse): the duplicate-amount vector is refused at the parse layer", () => {
  const v = vector("reject-parse-duplicate-amount");
  assert.equal(v.expect.reasonCode, "TRANSFER_PARSE");
  const r = projectLedgerTransfer(String(v.paramsText));
  assert.ok(!r.ok, `a duplicate amount member must be refused, got ACCEPT ${r.ok ? r.paramsHash : ""}`);
  assert.equal(r.code, "TRANSFER_PARSE", `refused for the wrong reason: ${r.reason}`);
  assert.ok(r.reason.includes(String(v.expect.reasonContains)), `kernel reason drifted: ${r.reason}`);
});

test("named detector (hash over canonical): the escaped-spelling vector binds the base hash", () => {
  // Hash and canonical bytes only, never the display: this detector must not answer for the Salt row.
  const v = vector("accept-escaped-spelling");
  const base = vector("accept-base");
  assert.equal(v.expect.paramsHash, base.expect.paramsHash, "the corpus declares the two equivalent");
  const r = projectLedgerTransfer(String(v.paramsText));
  assert.ok(r.ok, r.ok ? "" : `unexpected refusal: ${r.reason}`);
  assert.equal(r.canonical, v.expect.canonical);
  assert.equal(r.paramsHash, v.expect.paramsHash, "an escape-spelled input must bind the hash of its canonical bytes");
});

/** Rows back to members — the offline-verifier procedure of spec §5.2 (deliberately not exported). */
function rebuild(display: Readonly<Record<string, string>>): Record<string, string> {
  const amountRow = String(display["Amount"]);
  const space = amountRow.indexOf(" ");
  assert.ok(space > 0 && amountRow.indexOf(" ", space + 1) < 0, "Amount is exactly `<digits> <unit>`");
  return {
    amount: amountRow.slice(0, space),
    fromAccount: String(display["From"]),
    ledger: String(display["Ledger"]),
    salt: String(display["Salt"]),
    toAccount: String(display["To"]),
    unit: amountRow.slice(space + 1),
  };
}

test("named detector (display completeness): every bound value is visible, nothing unbound is shown, and the rows rebuild the tuple", () => {
  const tuples = [
    baseParams(),
    baseParams({ amount: "1" }),
    baseParams({ amount: "9".repeat(15), salt: "f".repeat(32) }),
    baseParams({ fromAccount: "a".repeat(64), toAccount: "a-1-b", ledger: "z" }),
  ];
  for (const t of tuples) {
    const r = run(t);
    assert.ok(r.ok, JSON.stringify(r));
    // Mechanical completeness: each bound VALUE appears verbatim in the rendering. A hand-written
    // expectation stops being a completeness check the day a row is dropped; this arm does not.
    const rendered = Object.values(r.display).join("\u0000");
    for (const m of MEMBERS) {
      assert.ok(rendered.includes(String(t[m])), `bound member \`${m}\` is not visible to the approver`);
    }
    assert.deepEqual(Object.keys(r.display).sort(), ["Action", "Amount", "From", "Ledger", "Salt", "To"],
      "exactly six rows: every bound member visible and nothing unbound shown");
    assert.equal(r.display["Action"], LEDGER_TRANSFER_CANONICAL);
    // Completeness in the strong sense: the tuple is recoverable from the rows alone, and the rebuilt
    // tuple re-projects to the SAME hash — the check an auditor runs on an audit-decrypted display.
    const rebuilt = rebuild(r.display);
    assert.deepEqual(rebuilt, { ...r.value });
    const again = run(rebuilt);
    assert.ok(again.ok && again.paramsHash === r.paramsHash, "the rebuilt tuple must bind the same hash");
  }
});
