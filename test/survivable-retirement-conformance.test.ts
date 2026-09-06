import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyHistoricalChain, type HistoricalVerificationResult, type HistoricalVerifyOptions } from "../src/verify.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const CORPUS = join(__dirname, "..", "..", "conformance", "survivable-retirement");

interface CorpusCase {
  readonly id: string;
  readonly receipts: string;
  readonly keyring: string;
  readonly checkpoint?: string;
  readonly checkpointKeyring?: string;
  readonly expected: HistoricalVerificationResult;
}

interface Corpus {
  readonly spec: string;
  readonly cases: CorpusCase[];
}

function bytes(rel: string): Uint8Array {
  return readFileSync(join(CORPUS, rel));
}

function evaluate(c: CorpusCase): HistoricalVerificationResult {
  const opts: HistoricalVerifyOptions = { keyring: bytes(c.keyring) };
  if (c.checkpoint !== undefined) opts.checkpoint = bytes(c.checkpoint);
  if (c.checkpointKeyring !== undefined) opts.checkpointKeyring = bytes(c.checkpointKeyring);
  return verifyHistoricalChain(bytes(c.receipts), opts);
}

test("every survivable-retirement fixture reproduces its versioned result", () => {
  const corpus = JSON.parse(readFileSync(join(CORPUS, "cases.json"), "utf8")) as Corpus;
  assert.equal(corpus.spec, "noa.historical-verification-corpus/0.1");
  assert.equal(corpus.cases.length, 19);
  for (const c of corpus.cases) {
    assert.deepEqual(evaluate(c), c.expected, c.id);
  }
});

test("the corpus pins evidence monotonicity and never infers deliberate suppression", () => {
  const corpus = JSON.parse(readFileSync(join(CORPUS, "cases.json"), "utf8")) as Corpus;
  const results = new Map(corpus.cases.map((c) => [c.id, evaluate(c)]));
  const e = results.get("e-static-no-witness")!;
  const retirement = results.get("e-plus-retirement-no-witness")!;
  const witness = results.get("e-plus-witness-exact-head")!;
  const both = results.get("e-plus-retirement-and-witness")!;

  assert.equal(e.dimensions.integrity, "INTACT");
  assert.equal(retirement.dimensions.integrity, "INTACT");
  assert.equal(witness.dimensions.integrity, "INTACT");
  assert.equal(both.dimensions.integrity, "INTACT");
  assert.equal(e.dimensions.attribution, "UNATTRIBUTABLE");
  assert.equal(retirement.dimensions.attribution, "UNATTRIBUTABLE");
  assert.equal(witness.dimensions.attribution, "ATTRIBUTABLE_AS_OF");
  assert.equal(both.dimensions.attribution, "ATTRIBUTABLE_AS_OF");

  assert.equal(results.get("honest-stale-prefix")!.classification, "PARTIAL");
  assert.equal(results.get("checkpoint-after-explicit-activation")!.classification, "VERIFIED");
  assert.equal(results.get("checkpoint-at-explicit-activation")!.classification, "VERIFIED");
  assert.equal(results.get("checkpoint-one-nanosecond-before-activation")!.code, "CHECKPOINT_BEFORE_ACTIVATION");
  assert.equal(results.get("lowercase-rfc3339-activation-boundary")!.classification, "VERIFIED");
  assert.equal(results.get("invalid-lifecycle-interval")!.code, "RECEIPT_ROOT_INVALID");
  assert.equal(results.get("authenticated-same-seq-contradiction")!.dimensions.completeness, "CONFLICT");
  assert.equal(
    results.get("authenticated-checkpoint-ahead")!.dimensions.evidence.availability,
    "MISSING_RELATIVE_TO_CHECKPOINT",
  );
  for (const result of results.values()) {
    assert.notEqual(result.dimensions.evidence.availability, "PROVEN_SUPPRESSED");
  }
});
