#!/usr/bin/env node
import assert from "node:assert/strict";
import {
  exactRatchetProblems,
  parseCountSnapshot,
  ratchetIncreases,
  validCountSnapshot,
} from "./security-ratchet.mjs";

const rows = [
  { id: "L10", count: 37 },
  { id: "L2-adapter-core", count: 18 },
];

for (const invalid of [null, false, 0, "", [], [37], { L10: -1 }, { L10: 1.5 }, { L10: "37" }]) {
  assert.equal(validCountSnapshot(invalid), false, `accepted invalid snapshot ${JSON.stringify(invalid)}`);
}
assert.equal(validCountSnapshot({}), true);
assert.equal(validCountSnapshot({ L10: 37, "L2-adapter-core": 18 }), true);
assert.equal(validCountSnapshot({ L10: Number.MAX_SAFE_INTEGER }), true);
assert.equal(validCountSnapshot({ L10: Number.MAX_SAFE_INTEGER + 1 }), false);
assert.deepEqual(parseCountSnapshot('{"L10":37}'), { L10: 37 });
for (const invalidText of ["null", "false", "[]", '{"L10":-1}', '{"L10":1.5}', '{"L10":"37"}', "{"]) {
  assert.throws(() => parseCountSnapshot(invalidText));
}

assert.deepEqual(exactRatchetProblems(rows, { L10: 37, "L2-adapter-core": 18 }), []);
assert.deepEqual(exactRatchetProblems(rows, { "L2-adapter-core": 18 }), [
  { kind: "missing", id: "L10", current: 37 },
]);
assert.deepEqual(exactRatchetProblems(rows, { L10: 36, "L2-adapter-core": 18 }), [
  { kind: "rise", id: "L10", was: 36, current: 37 },
]);
assert.deepEqual(exactRatchetProblems(rows, { L10: 38, "L2-adapter-core": 18 }), [
  { kind: "fall", id: "L10", was: 38, current: 37 },
]);
assert.deepEqual(exactRatchetProblems(rows, { L10: 37, "L2-adapter-core": 18, OLD: 4 }), [
  { kind: "obsolete", id: "OLD", was: 4 },
]);
assert.deepEqual(ratchetIncreases(rows, { L10: 36, "L2-adapter-core": 19 }), [
  { kind: "rise", id: "L10", was: 36, current: 37 },
]);

console.log("security-ratchet selftest: PASS — invalid shapes plus exact/rise/fall/missing/obsolete states proven");
