import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalize, JcsError } from "../src/jcs.js";
import { safeParse } from "../src/safe-json.js";

// The shared literal-bytes pin (conformance/vectors/strict-bytes/jcs-literal-*.json), consumed by all
// five canonicalizers: astral-before-U+E000 key order, short escapes, lowercase \u00XX controls, a
// literal DEL and "/", literal non-ASCII, decomposed text kept decomposed, and the safe-integer bounds.
test("JCS literal bytes: the shared strict-bytes input canonicalizes to the authored expected bytes", () => {
  const dir = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "conformance", "vectors", "strict-bytes");
  const input = readFileSync(join(dir, "jcs-literal-input.json"), "utf8");
  const expected = readFileSync(join(dir, "jcs-literal-expected.json"));
  assert.ok(Buffer.from(canonicalize(safeParse(input)), "utf8").equals(expected));
  // The two keys whose UTF-16 and code-point orders disagree, pinned directly as well.
  assert.equal(canonicalize({ "": 1, "\u{1F600}": 2 }), '{"\u{1F600}":2,"":1}');
});

test("sorts object keys by UTF-16 code units", () => {
  assert.equal(canonicalize({ b: 1, a: 2, c: 3 }), '{"a":2,"b":1,"c":3}');
  assert.equal(canonicalize({ "é": 1, a: 2 }), '{"a":2,"é":1}');
});

test("emits non-ASCII literally (no \\u escaping), UTF-8 preserved", () => {
  assert.equal(canonicalize({ k: "café ☕" }), '{"k":"café ☕"}');
});

test("escapes control characters per RFC 8785", () => {
  assert.equal(canonicalize("\n\t\r\b\f"), '"\\n\\t\\r\\b\\f"');
  assert.equal(canonicalize(""), '"\\u0001"');
  assert.equal(canonicalize('a"b\\c'), '"a\\"b\\\\c"');
});

test("integers serialize plainly; -0 becomes 0", () => {
  assert.equal(canonicalize(42), "42");
  assert.equal(canonicalize(-0), "0");
  assert.equal(canonicalize(0), "0");
});

test("rejects floats, NaN, Infinity, bigint, unsafe ints", () => {
  assert.throws(() => canonicalize(1.5), JcsError);
  assert.throws(() => canonicalize(NaN), JcsError);
  assert.throws(() => canonicalize(Infinity), JcsError);
  assert.throws(() => canonicalize(10n as unknown as number), JcsError);
  assert.throws(() => canonicalize(Number.MAX_SAFE_INTEGER + 1), JcsError);
});

test("nested structures are deterministic regardless of insertion order", () => {
  const a = canonicalize({ z: [3, 2, 1], a: { y: 1, x: 2 } });
  const b = canonicalize({ a: { x: 2, y: 1 }, z: [3, 2, 1] });
  assert.equal(a, b);
  assert.equal(a, '{"a":{"x":2,"y":1},"z":[3,2,1]}');
});

test("rejects undefined values", () => {
  assert.throws(() => canonicalize({ a: undefined }), JcsError);
});

test("rejects unpaired surrogates (forgery-channel defense), accepts valid astral pairs", () => {
  // lone high / low surrogate — would collapse to U+FFFD at the UTF-8 hashing step
  assert.throws(() => canonicalize("transfer\uD800"), JcsError);
  assert.throws(() => canonicalize("\uDFFF"), JcsError);
  assert.throws(() => canonicalize({ "\uD834": 1 }), JcsError); // lone surrogate in a key
  // a valid surrogate PAIR (U+1D11E, musical G-clef) is well-formed and must serialize fine
  assert.equal(canonicalize("\u{1D11E}"), '"\u{1D11E}"');
  // two distinct lone surrogates must NOT be allowed to collide
  assert.throws(() => canonicalize("x\uD800"), JcsError);
  assert.throws(() => canonicalize("x\uDC00"), JcsError);
});
