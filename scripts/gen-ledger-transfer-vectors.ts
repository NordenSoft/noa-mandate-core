/**
 * Deterministic conformance-vector generator for `noa.ledger.transfer/1` (src/ledger-transfer.ts;
 * normative specification `docs/ledger-transfer-spec.md`).
 *
 * Output (`conformance/ledger-transfer/vectors.json`) is COMMITTED so anyone can re-derive and diff
 * it; CI regenerates it and fails on drift. Nothing here depends on the clock, on randomness or on
 * key material: this construct signs nothing, so every value is a pure function of the fixtures.
 *
 * ── THE GENERATOR REFUSES TO WRITE UNLESS EVERY CHECK HOLDS ──────────────────────────────────────
 *   1. the implementation-digest pin, both identity pins and the base `paramsHash` pin reproduce;
 *   2. every vector replays against the implementation with its exact code, hash, canonical bytes
 *      and display — and the text and byte entry points agree on every text vector;
 *   3. accept hashes are pairwise distinct, except vectors that declare `equivalentTo`, which must
 *      equal the vector they name;
 *   4. accept displays are pairwise distinct on the same terms, and every display rebuilds its
 *      canonical tuple (rows back to members) and re-projects to the same `paramsHash`;
 *   5. the canonical bytes of every accept equal the sorted-key template, byte for byte;
 *   6. every reachable refusal code occurs at least once, and every group has its declared count.
 * A corpus that no longer matches the code it describes is never committed, and the pins move only
 * in a deliberate commit that says why.
 *
 * ── THE PINS ARE NORMATIVE EXPECTED VALUES, NOT ATTESTATIONS ─────────────────────────────────────
 * They define what a conforming implementation must compute. They are not a statement from any
 * running system (`NON-CLAIMS.md` §S7).
 *
 * ── THE FIXTURE IS SYNTHETIC BY CONSTRUCTION ─────────────────────────────────────────────────────
 * Accounts come only from the reserved namespace `acct-example-N`, ledgers from `ledger-example-N`,
 * the unit is the ISO 4217 testing code `XTS`, and salts are counting patterns. The fixture is the
 * PREIMAGE of a published hash — anyone can read it back out of the vector file — so it must name
 * nothing real. Every identifier is spelled once below and derived everywhere else.
 *
 * ── WHY `npm test` RUNS THIS AFTER THE TEST RUNNER ───────────────────────────────────────────────
 * The replay makes this generator a detector for every kernel primitive a vector exercises. As a
 * preparation step it would abort the chain before `node --test` whenever such a primitive is
 * broken, and the knockout harness, which counts authored test-runner failures, would classify that
 * mutant as not built instead of measuring it. After the runner it still fails `npm test` on any
 * replay mismatch and still regenerates the committed file for the CI drift check.
 */

import { mkdirSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  LEDGER_TRANSFER_SPEC,
  LEDGER_TRANSFER_CANONICAL,
  LEDGER_TRANSFER_IMPLEMENTATION_DIGEST,
  LEDGER_TRANSFER_SCHEMA_ID,
  LEDGER_TRANSFER_DISPLAY_ID,
  projectLedgerTransfer,
  type LedgerTransferResult,
} from "../src/ledger-transfer.js";
import { projectionIdentityHash, type ProjectionIdentityDescriptor } from "../src/deploy-release.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUT_DIR = join(__dirname, "..", "..", "conformance", "ledger-transfer");

// ── THE NORMATIVE PINS ───────────────────────────────────────────────────────────────────────────
// Typed `string`, not a literal: the module constant is `as const`, and comparing two distinct
// literal types is a compile error — a drifted pin must reach this check and fail it, not fail tsc.
const PIN_IMPLEMENTATION: string = "sha256:2f4dce6dce395e77b93ecec4c19f2d34d303fa07d198a8464d254a1561423039";
const PIN_SCHEMA_HASH = "sha256:f34d508cfa9080eadaa771ed8852a0d34c09246d03f818d75f848abb4df25901";
const PIN_DISPLAY_HASH = "sha256:bb6e72d64700383a4ceabefeb8e8eb170a2877ca95a5522c90901466e9a421db";
const PIN_PARAMS_HASH = "sha256:aa9256899837f204583f28e483ed67129b204e7edabf378eaf60f296915aebd0";

function fail(message: string): never {
  throw new Error(`ledger-transfer generator: ${message}`);
}

const measuredImplementation =
  "sha256:" + createHash("sha256").update(Function.prototype.toString.call(projectLedgerTransfer), "utf8").digest("hex");
if (LEDGER_TRANSFER_IMPLEMENTATION_DIGEST !== PIN_IMPLEMENTATION || measuredImplementation !== PIN_IMPLEMENTATION) {
  fail(
    `the implementation digest does not reproduce the normative pin.\n  module constant: ${LEDGER_TRANSFER_IMPLEMENTATION_DIGEST}\n` +
      `  measured over the emitted function: ${measuredImplementation}\n  pin: ${PIN_IMPLEMENTATION}\n` +
      "Do NOT re-pin to agree with a drift; say in the commit whether behaviour or the toolchain changed.",
  );
}
if (LEDGER_TRANSFER_SCHEMA_ID.hash !== PIN_SCHEMA_HASH) fail(`schema identity ${LEDGER_TRANSFER_SCHEMA_ID.hash} != pin ${PIN_SCHEMA_HASH}`);
if (LEDGER_TRANSFER_DISPLAY_ID.hash !== PIN_DISPLAY_HASH) fail(`display identity ${LEDGER_TRANSFER_DISPLAY_ID.hash} != pin ${PIN_DISPLAY_HASH}`);

// ── THE FIXTURES (synthetic by construction; spelled once) ───────────────────────────────────────
const ACCT_1 = "acct-example-1";
const ACCT_2 = "acct-example-2";
const ACCT_3 = "acct-example-3";
const ACCT_9 = "acct-example-9";
const LEDGER_1 = "ledger-example-1";
const LEDGER_2 = "ledger-example-2";
const SALT_A = "000102030405060708090a0b0c0d0e0f";
const SALT_A_DRIFT = "000102030405060708090a0b0c0d0e0e";
const UNIT = "XTS";

const BASE: Readonly<Record<string, unknown>> = {
  amount: "12345",
  fromAccount: ACCT_1,
  ledger: LEDGER_1,
  salt: SALT_A,
  toAccount: ACCT_2,
  unit: UNIT,
};
const MEMBERS = ["amount", "fromAccount", "ledger", "salt", "toAccount", "unit"] as const;

/** BASE with members replaced in place (key position kept, so the text stays in JCS order). */
const withMembers = (o: Record<string, unknown>): Record<string, unknown> => ({ ...BASE, ...o });
const withoutMember = (k: string): Record<string, unknown> => {
  const c: Record<string, unknown> = { ...BASE };
  delete c[k];
  return c;
};

/**
 * JSON text of a fixture object. Invisible and bidirectional-override characters are written as
 * JSON escapes so the vector file stays readable; the parser decodes them to the same value.
 */
function jsonText(o: unknown): string {
  const raw = JSON.stringify(o);
  if (raw === undefined) fail("fixture is not JSON-serializable");
  let out = "";
  for (const ch of raw) {
    const cp = ch.codePointAt(0) as number;
    out += (cp >= 0x2000 && cp <= 0x206f) || cp === 0xfeff ? "\\u" + cp.toString(16).padStart(4, "0") : ch;
  }
  return out;
}

/** The base text with one member's JSON value replaced by a raw JSON fragment. */
function withRawValue(member: string, rawValue: string): string {
  const t = jsonText(BASE);
  const needle = `"${member}":${JSON.stringify(BASE[member])}`;
  const at = t.indexOf(needle);
  if (at < 0 || t.indexOf(needle, at + 1) >= 0) fail(`fixture member ${member} is not uniquely spelled`);
  return t.slice(0, at) + `"${member}":${rawValue}` + t.slice(at + needle.length);
}

const hexOf = (bytes: Uint8Array): string => Buffer.from(bytes).toString("hex");
const enc = new TextEncoder();

// ── THE VECTOR SHAPES ────────────────────────────────────────────────────────────────────────────
type Group =
  | "accept" | "parse" | "not-object" | "amount" | "from" | "ledger" | "salt" | "to" | "unit"
  | "unrecognized" | "same-account" | "precedence";

interface IdentityVector {
  name: string;
  note: string;
  descriptor: ProjectionIdentityDescriptor;
  expect: { hash: string };
}
interface AcceptExpect { ok: true; paramsHash: string; canonical: string; display: Record<string, string> }
interface RejectExpect { ok: false; reasonCode: string; reasonContains?: string }
interface ParamsVector {
  name: string;
  group: Group;
  note: string;
  /** The exact input text. Mutually exclusive with `paramsHex`. */
  paramsText?: string;
  /** The exact input bytes, lowercase hex — only for inputs no text form can carry. */
  paramsHex?: string;
  /** An accept that must bind exactly what the named vector binds. */
  equivalentTo?: string;
  expect: AcceptExpect | RejectExpect;
}

const GROUP_COUNTS: Readonly<Record<Group, number>> = {
  accept: 15, parse: 12, "not-object": 5, amount: 21, from: 21, ledger: 7, salt: 8, to: 7, unit: 8,
  unrecognized: 14, "same-account": 2, precedence: 5,
};

/** Every code of `/1`. The last one guards the render node and is unreachable by construction. */
const REFUSAL_CODES = [
  "TRANSFER_PARSE", "TRANSFER_NOT_OBJECT", "TRANSFER_AMOUNT_INVALID", "TRANSFER_FROM_INVALID",
  "TRANSFER_LEDGER_INVALID", "TRANSFER_SALT_INVALID", "TRANSFER_TO_INVALID", "TRANSFER_UNIT_INVALID",
  "TRANSFER_UNRECOGNIZED_MEMBER", "TRANSFER_SAME_ACCOUNT", "TRANSFER_CANONICAL_REPARSE",
] as const;
const UNREACHABLE_CODES = new Set<string>(["TRANSFER_CANONICAL_REPARSE"]);

const inputOf = (v: ParamsVector): string | Uint8Array =>
  typeof v.paramsText === "string" ? v.paramsText : Uint8Array.from(Buffer.from(v.paramsHex as string, "hex"));

function sameResult(a: LedgerTransferResult, b: LedgerTransferResult): boolean {
  if (a.ok !== b.ok) return false;
  if (a.ok && b.ok) {
    return a.paramsHash === b.paramsHash && a.canonical === b.canonical &&
      JSON.stringify(a.display) === JSON.stringify(b.display);
  }
  return !a.ok && !b.ok && a.reason === b.reason;
}

/** The sorted-key template: every permitted character is ASCII and none is `"`, `\` or a control. */
function template(p: Record<string, unknown>): string {
  return `{"amount":"${p["amount"]}","fromAccount":"${p["fromAccount"]}","ledger":"${p["ledger"]}",` +
    `"salt":"${p["salt"]}","toAccount":"${p["toAccount"]}","unit":"${p["unit"]}"}`;
}

/** Rows back to members (spec §5.2). Returns undefined if the display is not a well-formed /1 display. */
function rebuildFromDisplay(d: Readonly<Record<string, string>>): Record<string, string> | undefined {
  const keys = Object.keys(d).sort().join(",");
  if (keys !== "Action,Amount,From,Ledger,Salt,To" || d["Action"] !== LEDGER_TRANSFER_CANONICAL) return undefined;
  const amountRow = d["Amount"] as string;
  const space = amountRow.indexOf(" ");
  if (space < 0 || amountRow.indexOf(" ", space + 1) >= 0) return undefined;
  return {
    amount: amountRow.slice(0, space),
    fromAccount: d["From"] as string,
    ledger: d["Ledger"] as string,
    salt: d["Salt"] as string,
    toAccount: d["To"] as string,
    unit: amountRow.slice(space + 1),
  };
}

/** Replay gate: every vector must hold against the implementation BEFORE it is written. */
function check(v: ParamsVector): ParamsVector {
  const hasText = typeof v.paramsText === "string";
  const hasHex = typeof v.paramsHex === "string";
  if (hasText === hasHex) fail(`${v.name}: exactly one of paramsText / paramsHex is required`);
  const r = projectLedgerTransfer(inputOf(v));
  if (hasText) {
    const rb = projectLedgerTransfer(enc.encode(v.paramsText as string));
    if (!sameResult(r, rb)) fail(`${v.name}: the text and byte entry points disagree`);
  }
  if (v.expect.ok) {
    if (!r.ok) fail(`${v.name}: expected ACCEPT, got ${r.reason}`);
    if (r.paramsHash !== v.expect.paramsHash) fail(`${v.name}: paramsHash ${r.paramsHash} != ${v.expect.paramsHash}`);
    if (r.canonical !== v.expect.canonical) fail(`${v.name}: canonical drifted: ${r.canonical}`);
    if (JSON.stringify(r.display) !== JSON.stringify(v.expect.display)) fail(`${v.name}: display drifted`);
  } else {
    if (r.ok) fail(`${v.name}: expected ${v.expect.reasonCode}, got ACCEPT (${r.paramsHash})`);
    if (r.code !== v.expect.reasonCode) fail(`${v.name}: refused for the wrong reason: ${r.reason}`);
    if (!r.reason.startsWith(`${r.code}: `)) fail(`${v.name}: reason does not start with its code: ${r.reason}`);
    if (v.expect.reasonCode === "TRANSFER_PARSE") {
      if (typeof v.expect.reasonContains !== "string") fail(`${v.name}: a TRANSFER_PARSE vector must pin reasonContains`);
      if (!r.reason.includes(v.expect.reasonContains)) {
        fail(`${v.name}: kernel reason drifted.\n  got: ${r.reason}\n  expected to contain: ${v.expect.reasonContains}`);
      }
    } else if (v.expect.reasonContains !== undefined) {
      fail(`${v.name}: reasonContains is pinned only for TRANSFER_PARSE vectors`);
    }
  }
  return v;
}

/** An ACCEPT vector whose expectation is the implementation's own output for `text`. */
function accept(name: string, note: string, text: string, equivalentTo?: string): ParamsVector {
  const r = projectLedgerTransfer(text);
  if (!r.ok) fail(`${name}: expected a valid transfer, got ${r.reason}`);
  const v: ParamsVector = {
    name, group: "accept", note, paramsText: text,
    expect: { ok: true, paramsHash: r.paramsHash, canonical: r.canonical, display: { ...r.display } },
  };
  if (equivalentTo !== undefined) v.equivalentTo = equivalentTo;
  return check(v);
}

function reject(name: string, group: Group, note: string, text: string, reasonCode: string, reasonContains?: string): ParamsVector {
  const expect: RejectExpect = { ok: false, reasonCode };
  if (reasonContains !== undefined) expect.reasonContains = reasonContains;
  return check({ name, group, note, paramsText: text, expect });
}

const vectors: Array<IdentityVector | ParamsVector> = [];

// ── IDENTITY VECTORS ─────────────────────────────────────────────────────────────────────────────
for (const [name, id, kind, pin, note] of [
  ["identity-action-schema", "noa.ledger.transfer.schema", "actionSchema", PIN_SCHEMA_HASH,
    "hash = sha256:hex(SHA-256(UTF8(JCS(descriptor)))). `implementation` is SHA-256 of the emitted source " +
      "text of projectLedgerTransfer, which ships in the published package, so it is recomputable."],
  ["identity-display", "noa.ledger.transfer.display", "displayProjection", PIN_DISPLAY_HASH,
    "The same artifact under kind displayProjection. The two identities MUST differ."],
] as const) {
  const descriptor: ProjectionIdentityDescriptor = { id, version: 1, kind, implementation: PIN_IMPLEMENTATION };
  if (projectionIdentityHash(descriptor) !== pin) fail(`${name}: identity does not recompute from its descriptor`);
  vectors.push({ name, note, descriptor, expect: { hash: pin } });
}

// ── ACCEPT ───────────────────────────────────────────────────────────────────────────────────────
const baseText = jsonText(BASE);
const acceptBase = accept(
  "accept-base",
  "The conformance tuple. Its paramsHash is the normative base pin; its canonical bytes are the template.",
  baseText,
);
if ((acceptBase.expect as AcceptExpect).paramsHash !== PIN_PARAMS_HASH) {
  fail(`the base paramsHash ${(acceptBase.expect as AcceptExpect).paramsHash} does not reproduce the pin ${PIN_PARAMS_HASH}`);
}
const accepts: ParamsVector[] = [
  acceptBase,
  accept(
    "accept-key-order-and-whitespace",
    "Reverse key order plus insignificant whitespace binds the SAME value: JCS sorts keys and the hash " +
      "covers the re-emitted canonical bytes, never the input bytes.",
    `{ "unit" : "${UNIT}",\n  "toAccount":"${ACCT_2}",\t"salt":"${SALT_A}", "ledger":"${LEDGER_1}",\r\n` +
      ` "fromAccount":"${ACCT_1}" , "amount":"12345" }`,
    "accept-base",
  ),
  accept(
    "accept-escaped-spelling",
    "`\\u0061` is a JSON escape for `a`; after parsing the value is identical, so the hash is the base hash. " +
      "A hash over input bytes would differ here.",
    baseText.replace(`"fromAccount":"${ACCT_1}"`, `"fromAccount":"\\u0061${ACCT_1.slice(1)}"`),
    "accept-base",
  ),
  accept("accept-drift-amount", "One character of the amount (12345 -> 12346) moves the hash.", jsonText(withMembers({ amount: "12346" }))),
  accept("accept-drift-from", "One character of the source account moves the hash.", jsonText(withMembers({ fromAccount: ACCT_3 }))),
  accept("accept-drift-to", "One character of the destination account moves the hash.", jsonText(withMembers({ toAccount: ACCT_3 }))),
  accept("accept-drift-ledger", "One character of the ledger moves the hash.", jsonText(withMembers({ ledger: LEDGER_2 }))),
  accept("accept-drift-salt", "One character of the salt moves the hash.", jsonText(withMembers({ salt: SALT_A_DRIFT }))),
  accept(
    "accept-direction-swap",
    "The same two accounts in the opposite direction is a DIFFERENT transfer, with a different hash and display.",
    jsonText(withMembers({ fromAccount: ACCT_2, toAccount: ACCT_1 })),
  ),
  accept("accept-amount-min", "The smallest amount, 1 whole unit.", jsonText(withMembers({ amount: "1" }))),
  accept("accept-amount-max", "The largest amount: 15 nines, below 2^53.", jsonText(withMembers({ amount: "9".repeat(15) }))),
  accept("accept-identifier-64", "64 characters is the identifier bound, not 63.", jsonText(withMembers({ fromAccount: "a".repeat(64) }))),
  accept("accept-identifier-one-char", "A one-character identifier: its first and last character are the same letter.", jsonText(withMembers({ ledger: "a" }))),
  accept("accept-identifier-inner-hyphens", "Hyphens and digits are legal inside an identifier.", jsonText(withMembers({ toAccount: "a-1-b" }))),
  accept(
    "accept-salt-all-zero",
    "An all-zero salt is ACCEPTED: a projection cannot test randomness. This pins the non-claim that salt " +
      "privacy depends on an honest producer (NON-CLAIMS.md §S7).",
    jsonText(withMembers({ salt: "0".repeat(32) })),
  ),
];
vectors.push(...accepts);

// ── REFUSALS: parse layer (the kernel parser's reasons, measured) ────────────────────────────────
const P = "TRANSFER_PARSE";
const tail = baseText.slice(`{"amount":"12345",`.length);
if (`{"amount":"12345",${tail}` !== baseText) fail("base text does not start with the amount member");
const parseVectors: ParamsVector[] = [
  reject("reject-parse-duplicate-amount", "parse",
    "TWO amount members (1, then 100000). Last-wins parsing would bind a value the first reader never saw; the strict parser refuses the document.",
    `{"amount":"1","amount":"100000",${tail}`, P, "duplicate object key 'amount'"),
  reject("reject-parse-proto-key", "parse", "`__proto__` as an own key is refused at the parse boundary.",
    `{"__proto__":{"amount":"1"},${baseText.slice(1)}`, P, "forbidden object key '__proto__'"),
  reject("reject-parse-constructor-key", "parse", "`constructor` as an own key is refused at the parse boundary.",
    `{"constructor":"x",${baseText.slice(1)}`, P, "forbidden object key 'constructor'"),
  reject("reject-parse-truncated", "parse", "Truncated input.", `{"amount":"12345","fromAccount":`, P, "unexpected end of input"),
  reject("reject-parse-trailing-bytes", "parse", "A second value after the document.", `${baseText} {}`, P, "trailing characters after JSON value"),
  reject("reject-parse-float-amount", "parse", "A JSON float is refused by the parser before any member rule runs.",
    withRawValue("amount", "1.5"), P, "non-integer (float/exponent) number not allowed"),
  reject("reject-parse-exponent-amount", "parse", "A JSON exponent is refused by the parser.",
    withRawValue("amount", "1e4"), P, "non-integer (float/exponent) number not allowed"),
  reject("reject-parse-unsafe-integer-amount", "parse", "2^53+1 cannot be represented exactly and is refused by the parser.",
    withRawValue("amount", "9007199254740993"), P, "integer outside safe range"),
  reject("reject-parse-lone-surrogate-escape", "parse", "An escaped lone surrogate has no UTF-8 encoding.",
    withRawValue("fromAccount", `"\\ud800"`), P, "unpaired surrogate in string"),
  reject("reject-parse-raw-control-character", "parse", "A raw U+0001 inside a string is refused (escaped control characters parse, and are then refused by the member rule).",
    withRawValue("fromAccount", `"acct-\u0001example-1"`), P, "unescaped control character in string"),
  check({
    name: "reject-parse-bom", group: "parse",
    note: "A UTF-8 byte-order mark is not stripped: it reaches the parser as an unexpected character.",
    paramsHex: hexOf(Uint8Array.from([0xef, 0xbb, 0xbf, ...enc.encode(baseText)])),
    expect: { ok: false, reasonCode: P, reasonContains: "unexpected character" },
  }),
  check({
    name: "reject-parse-overlong-utf8", group: "parse",
    note: "0xC0 0xB1 is an overlong encoding of `1`. Decoding is fatal, never substituted: two byte strings must not decode to one text.",
    paramsHex: hexOf(Uint8Array.from([...enc.encode(`{"amount":"`), 0xc0, 0xb1, ...enc.encode(`2345",${tail}`)])),
    expect: { ok: false, reasonCode: P, reasonContains: "input is not valid UTF-8" },
  }),
];
vectors.push(...parseVectors);

// ── REFUSALS: not an object ──────────────────────────────────────────────────────────────────────
const N = "TRANSFER_NOT_OBJECT";
vectors.push(
  reject("reject-not-object-null", "not-object", "null is not a params object.", "null", N),
  reject("reject-not-object-array", "not-object", "An array is not a params object.", "[]", N),
  reject("reject-not-object-string", "not-object", "A bare string is not a params object.", `"${LEDGER_TRANSFER_CANONICAL}"`, N),
  reject("reject-not-object-number", "not-object", "A bare number is not a params object.", "12345", N),
  reject("reject-not-object-true", "not-object", "A bare boolean is not a params object.", "true", N),
);

/** absent / null / empty — one refusal for one member (an optional bound concept is a second spelling of absent). */
function missing(member: string, group: Group, code: string, label: string): ParamsVector[] {
  return [
    reject(`reject-${label}-absent`, group, `\`${member}\` missing entirely.`, jsonText(withoutMember(member)), code),
    reject(`reject-${label}-null`, group, `\`${member}\`: null is not a value.`, jsonText(withMembers({ [member]: null })), code),
    reject(`reject-${label}-empty`, group, `\`${member}\`: the empty string is "unspecified" spelled so a presence check cannot see it.`, jsonText(withMembers({ [member]: "" })), code),
  ];
}

// ── REFUSALS: amount ─────────────────────────────────────────────────────────────────────────────
const A = "TRANSFER_AMOUNT_INVALID";
const amountCase = (name: string, note: string, value: unknown): ParamsVector =>
  reject(`reject-amount-${name}`, "amount", note, jsonText(withMembers({ amount: value })), A);
vectors.push(
  ...missing("amount", "amount", A, "amount"),
  amountCase("number", "A JSON number is not an amount: amounts are strings, so no value passes through binary floating point.", 12345),
  reject("reject-amount-negative-zero", "amount", "`-0` parses as a number and is refused by the member rule.", withRawValue("amount", "-0"), A),
  amountCase("array", "An array holding the right string is not a string.", ["12345"]),
  amountCase("boolean", "A boolean is not an amount.", true),
  amountCase("zero", "Zero is not a transfer.", "0"),
  amountCase("leading-zero", "`012345` would be a second spelling of 12345. One spelling per amount.", "012345"),
  amountCase("plus-sign", "No sign.", "+12345"),
  amountCase("minus-sign", "No sign; a negative transfer is not a transfer.", "-12345"),
  amountCase("decimal-point", "Scale is 0: whole units only.", "123.45"),
  amountCase("exponent", "No exponent spelling.", "1e4"),
  amountCase("leading-space", "No whitespace.", " 12345"),
  amountCase("trailing-space", "No whitespace.", "12345 "),
  amountCase("comma-separator", "No grouping separator.", "1,000"),
  amountCase("underscore-separator", "No grouping separator.", "1_000"),
  amountCase("16-digits", "16 digits is past the bound (accept-amount-max holds the other side).", "1" + "0".repeat(15)),
  amountCase("fullwidth-digits", "U+FF11.. fullwidth digits look like digits and are not ASCII.", "１２３４５"),
  amountCase("arabic-indic-digits", "U+0661.. Arabic-Indic digits are digits in another script, not ASCII.", "١٢٣٤٥"),
  amountCase("hex", "No radix prefix.", "0x1f"),
);

// ── REFUSALS: identifiers ────────────────────────────────────────────────────────────────────────
const F = "TRANSFER_FROM_INVALID";
const fromCase = (name: string, note: string, value: unknown): ParamsVector =>
  reject(`reject-from-${name}`, "from", note, jsonText(withMembers({ fromAccount: value })), F);
vectors.push(
  ...missing("fromAccount", "from", F, "from"),
  fromCase("number", "A number is not an identifier.", 12345),
  fromCase("object", "An object is not an identifier; nothing is coerced to string.", {}),
  fromCase("uppercase", "Case variants are refused, never folded.", "acct-Example-1"),
  fromCase("trailing-space", "No whitespace.", `${ACCT_1} `),
  fromCase("escaped-newline", "An escaped newline passes the parser and is refused here: it could rewrite what the approver reads below it.", "acct-\nexample-1"),
  fromCase("escaped-nul", "An escaped NUL truncates in C-adjacent renderers.", "acct-\u0000example-1"),
  fromCase("escaped-ansi", "An escaped ANSI sequence can repaint a terminal renderer.", "acct-\u001b[31mexample-1"),
  fromCase("zero-width-space", "U+200B is invisible.", "acct-example​-1"),
  fromCase("cyrillic-homoglyph", "U+0430 CYRILLIC SMALL A renders as `a` and is not ASCII.", "acct-exаmple-1"),
  fromCase("rtl-override", "U+202E reverses the visual order of what follows.", "acct-‮example-1"),
  fromCase("65-chars", "65 characters is past the bound (accept-identifier-64 holds the other side).", "a".repeat(65)),
  fromCase("leading-hyphen", "The first character must be a letter.", `-${ACCT_1}`),
  fromCase("leading-digit", "The first character must be a letter.", "1acct-example"),
  fromCase("trailing-hyphen", "The last character must be a letter or digit.", `${ACCT_1}-`),
  fromCase("email", "`@` and `.` are not in the charset.", "a@example.invalid"),
  fromCase("dot", "`.` is not in the charset.", "acct.example-1"),
  fromCase("underscore", "`_` is not in the charset.", "acct_example-1"),
  fromCase("slash", "`/` is not in the charset.", "acct/example-1"),
);

const L = "TRANSFER_LEDGER_INVALID";
vectors.push(
  ...missing("ledger", "ledger", L, "ledger"),
  reject("reject-ledger-number", "ledger", "A number is not an identifier.", jsonText(withMembers({ ledger: 7 })), L),
  reject("reject-ledger-uppercase", "ledger", "Case variants are refused, never folded.", jsonText(withMembers({ ledger: "Ledger-example-1" })), L),
  reject("reject-ledger-65-chars", "ledger", "65 characters is past the bound.", jsonText(withMembers({ ledger: "l".repeat(65) })), L),
  reject("reject-ledger-escaped-ansi", "ledger", "An escaped ANSI clear-screen sequence.", jsonText(withMembers({ ledger: "ledger-\u001b[2Jexample-1" })), L),
);

const T = "TRANSFER_TO_INVALID";
vectors.push(
  ...missing("toAccount", "to", T, "to"),
  reject("reject-to-boolean", "to", "A boolean is not an identifier.", jsonText(withMembers({ toAccount: false })), T),
  reject("reject-to-uppercase", "to", "Case variants are refused, never folded.", jsonText(withMembers({ toAccount: ACCT_2.toUpperCase() })), T),
  reject("reject-to-65-chars", "to", "65 characters is past the bound.", jsonText(withMembers({ toAccount: "b".repeat(65) })), T),
  reject("reject-to-escaped-newline", "to", "An escaped newline.", jsonText(withMembers({ toAccount: "acct-example-\n2" })), T),
);

// ── REFUSALS: unit ───────────────────────────────────────────────────────────────────────────────
const U = "TRANSFER_UNIT_INVALID";
vectors.push(
  reject("reject-unit-lowercase", "unit", "The enum is exact; case variants are refused.", jsonText(withMembers({ unit: "xts" })), U),
  reject("reject-unit-trailing-space", "unit", "No whitespace.", jsonText(withMembers({ unit: "XTS " })), U),
  reject("reject-unit-other-code", "unit", "Only the testing code is in the /1 enum; a real currency is a new spec version.", jsonText(withMembers({ unit: "USD" })), U),
  reject("reject-unit-cyrillic-homoglyph", "unit", "U+0425 CYRILLIC CAPITAL HA renders as `X`.", jsonText(withMembers({ unit: "ХTS" })), U),
  reject("reject-unit-boolean", "unit", "A boolean is not a unit.", jsonText(withMembers({ unit: false })), U),
  ...missing("unit", "unit", U, "unit"),
);

// ── REFUSALS: salt ───────────────────────────────────────────────────────────────────────────────
const S = "TRANSFER_SALT_INVALID";
vectors.push(
  reject("reject-salt-uppercase", "salt", "Uppercase hex is refused, never normalized.", jsonText(withMembers({ salt: SALT_A.toUpperCase() })), S),
  reject("reject-salt-31-hex", "salt", "31 hex characters.", jsonText(withMembers({ salt: SALT_A.slice(0, 31) })), S),
  reject("reject-salt-33-hex", "salt", "33 hex characters.", jsonText(withMembers({ salt: SALT_A + "0" })), S),
  reject("reject-salt-non-hex", "salt", "`g` is not a hex character.", jsonText(withMembers({ salt: SALT_A.slice(0, 31) + "g" })), S),
  reject("reject-salt-number", "salt", "A number is not a salt.", jsonText(withMembers({ salt: 12345 })), S),
  ...missing("salt", "salt", S, "salt"),
);

// ── REFUSALS: the closed world ───────────────────────────────────────────────────────────────────
const X = "TRANSFER_UNRECOGNIZED_MEMBER";
const extras: Array<[string, string, Record<string, unknown>]> = [
  ["memo", "Free text the approver would not see.", { memo: "rent" }],
  ["fee", "A fee is policy, not a bound member.", { fee: "1" }],
  ["reference", "Another display surface with confusable characters; not bound.", { reference: "ref-1" }],
  ["reversible", "Reversibility is not a caller-supplied member.", { reversible: false }],
  ["risk-class", "Risk is derived by the enforcing gate, never supplied.", { riskClass: "LOW" }],
  ["idempotency-key", "Idempotency belongs to the request, not to the bound transfer.", { idempotencyKey: "idem-1" }],
  ["expires-at", "Time windows belong to the authorization, not to the transfer.", { expiresAt: "2026-01-01T00:00:00Z" }],
  ["approver", "Approvers belong to the authorization.", { approver: "approver-example-1" }],
  ["case-variant-amount", "`Amount` differs from `amount` only in case — still unrecognized.", { Amount: "99999" }],
  ["leading-space-amount", "` amount` is a different key.", { " amount": "99999" }],
  ["short-from", "`from` is not `fromAccount`.", { from: ACCT_9 }],
  ["case-variant-to", "`To` is not `toAccount`.", { To: ACCT_9 }],
  ["nested-meta", "A nested object.", { meta: { note: "x" } }],
  ["amount-minor", "A second amount beside `amount`: a scaled spelling must not ride along.", { amountMinor: "1234500" }],
];
for (const [name, why, o] of extras) {
  vectors.push(reject(`reject-extra-${name}`, "unrecognized", `${why} An unrecognized own member is refused.`, jsonText({ ...BASE, ...o }), X));
}

// ── REFUSALS: same account ───────────────────────────────────────────────────────────────────────
const SA = "TRANSFER_SAME_ACCOUNT";
vectors.push(
  reject("reject-same-account", "same-account", "A transfer from an account to itself is refused.", jsonText(withMembers({ toAccount: ACCT_1 })), SA),
  reject("reject-same-account-escaped-spelling", "same-account",
    "The escaped spelling `\\u0061cct-example-1` is the same account after parsing; the comparison runs on parsed values.",
    jsonText(withMembers({ toAccount: ACCT_1 })).replace(`"toAccount":"${ACCT_1}"`, `"toAccount":"\\u0061${ACCT_1.slice(1)}"`), SA),
);

// ── PRECEDENCE ───────────────────────────────────────────────────────────────────────────────────
vectors.push(
  reject("reject-precedence-parse-first", "precedence",
    "A duplicate key, a bad amount and an extra member at once: the parse layer answers first.",
    `{"amount":"012","amount":"012","memo":"x",${tail}`, P, "duplicate object key 'amount'"),
  reject("reject-precedence-amount-before-from", "precedence",
    "Bad amount and bad fromAccount: members are checked in JCS key order, so amount answers.",
    jsonText(withMembers({ amount: "0", fromAccount: "ACCT" })), A),
  reject("reject-precedence-unit-before-closed-world", "precedence",
    "Bad unit and an extra member: member rules run before the closed world.",
    jsonText({ ...withMembers({ unit: "USD" }), memo: "x" }), U),
  reject("reject-precedence-closed-world-before-same-account", "precedence",
    "An extra member and a self-transfer: the closed world runs before the two-member rule.",
    jsonText({ ...withMembers({ toAccount: ACCT_1 }), memo: "x" }), X),
  reject("reject-precedence-salt-before-same-account", "precedence",
    "Bad salt and a self-transfer: member rules run before the two-member rule.",
    jsonText(withMembers({ salt: SALT_A.toUpperCase(), toAccount: ACCT_1 })), S),
);

// ── CORPUS-WIDE CHECKS ───────────────────────────────────────────────────────────────────────────
const params = vectors.filter((v): v is ParamsVector => (v as ParamsVector).group !== undefined);

const names = new Set<string>();
for (const v of vectors) {
  if (names.has(v.name)) fail(`duplicate vector name ${v.name}`);
  names.add(v.name);
}

for (const g of Object.keys(GROUP_COUNTS) as Group[]) {
  const n = params.filter((v) => v.group === g).length;
  if (n !== GROUP_COUNTS[g]) fail(`group ${g}: ${n} vectors, declared ${GROUP_COUNTS[g]}`);
}

const seenCodes = new Set(params.filter((v) => !v.expect.ok).map((v) => (v.expect as RejectExpect).reasonCode));
for (const c of seenCodes) if (!(REFUSAL_CODES as readonly string[]).includes(c)) fail(`unknown refusal code ${c}`);
for (const c of REFUSAL_CODES) {
  if (!UNREACHABLE_CODES.has(c) && !seenCodes.has(c)) fail(`refusal code ${c} has no vector`);
  if (UNREACHABLE_CODES.has(c) && seenCodes.has(c)) fail(`refusal code ${c} is declared unreachable yet a vector reaches it`);
}

const acceptVectors = params.filter((v) => v.expect.ok);
const byName = new Map(acceptVectors.map((v) => [v.name, v]));
const distinctHashes = new Set<string>();
const distinctDisplays = new Set<string>();
for (const v of acceptVectors) {
  const e = v.expect as AcceptExpect;
  if (v.equivalentTo !== undefined) {
    const target = byName.get(v.equivalentTo);
    if (!target) fail(`${v.name}: equivalentTo names no accept vector`);
    const te = target.expect as AcceptExpect;
    if (te.paramsHash !== e.paramsHash || te.canonical !== e.canonical || JSON.stringify(te.display) !== JSON.stringify(e.display)) {
      fail(`${v.name}: declared equivalent to ${v.equivalentTo} but binds something else`);
    }
  } else {
    if (distinctHashes.has(e.paramsHash)) fail(`${v.name}: two different transfers share a paramsHash`);
    distinctHashes.add(e.paramsHash);
    const shown = JSON.stringify(Object.entries(e.display).sort());
    if (distinctDisplays.has(shown)) fail(`${v.name}: two different transfers render the same display`);
    distinctDisplays.add(shown);
  }
  const rebuilt = rebuildFromDisplay(e.display);
  if (!rebuilt) fail(`${v.name}: the display is not a well-formed /1 display`);
  if (template(rebuilt) !== e.canonical) fail(`${v.name}: the display does not rebuild the canonical tuple`);
  const reprojected = projectLedgerTransfer(JSON.stringify(rebuilt));
  if (!reprojected.ok || reprojected.paramsHash !== e.paramsHash) fail(`${v.name}: the rebuilt tuple does not re-project to the same hash`);
}

const out = {
  spec: LEDGER_TRANSFER_SPEC,
  canonical: LEDGER_TRANSFER_CANONICAL,
  generatedFrom: "scripts/gen-ledger-transfer-vectors.ts",
  implementationDigest: LEDGER_TRANSFER_IMPLEMENTATION_DIGEST,
  refusalCodes: [...REFUSAL_CODES],
  note:
    "Generated, committed and diff-gated. This construct signs nothing, so there is no keyring: every value " +
    "is a pure function of the fixtures, which are synthetic by construction (acct-example-N, ledger-example-N, " +
    "the ISO 4217 testing code XTS, counting-pattern salts). ACCEPT vectors pin paramsHash, canonical and the " +
    "full display; REJECT vectors pin reasonCode, and TRANSFER_PARSE vectors also pin reasonContains (the " +
    "reference kernel parser's reason; informative for other implementations). paramsHex carries inputs no " +
    "text form can (bytes are lowercase hex); every other vector carries paramsText. The pinned hashes are " +
    "NORMATIVE EXPECTED VALUES, not attestations about any running system (NON-CLAIMS.md §S7). " +
    "TRANSFER_CANONICAL_REPARSE guards the render node and is unreachable by any input, so no vector carries it.",
  vectors,
};

mkdirSync(OUT_DIR, { recursive: true });
writeFileSync(join(OUT_DIR, "vectors.json"), JSON.stringify(out, null, 2) + "\n");
console.error(`wrote conformance/ledger-transfer/vectors.json — ${vectors.length} vectors`);
