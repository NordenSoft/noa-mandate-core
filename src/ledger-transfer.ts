/**
 * `noa.ledger.transfer/1` — THE PUBLIC WIRE FORM OF A REFERENCE LEDGER TRANSFER.
 *
 * Normative specification: `docs/ledger-transfer-spec.md`. Conformance corpus:
 * `conformance/ledger-transfer/vectors.json`.
 *
 * ── WHY THIS EXISTS ──────────────────────────────────────────────────────────────────────────────
 *
 * A protected consequence that a ledger commits (move N units from one account to another) needs a
 * published rule for the values an authorization binds: which members, which spellings, which bytes
 * get hashed, and what the approver is shown. Without that rule a relying party holding a receipt's
 * `action.paramsHash` can only COMPARE it; it cannot RECOMPUTE it from a disclosed transfer, and it
 * cannot check that an audit-decrypted display describes the transfer the hash binds. This module is
 * that rule, in executable form, together with its conformance corpus.
 *
 * It commits nothing and registers nothing. It is a pure, network-less function from bytes to either
 * one bound tuple or one stable refusal code.
 *
 * ── THE CONSTRUCTION ─────────────────────────────────────────────────────────────────────────────
 *
 *     params     = { amount, fromAccount, ledger, salt, toAccount, unit }
 *                  every member REQUIRED, every member a JSON string, any OTHER own member REFUSED
 *                  · amount                       — 1..15 ASCII digits, no leading zero (1 .. 10^15-1
 *                    whole units; below 2^53, so binary64, int64 and arbitrary-precision integers
 *                    represent it exactly — binary32 and int32 do not)
 *                  · fromAccount / toAccount / ledger — 1..64 of [a-z0-9-], first [a-z], last [a-z0-9]
 *                  · salt                         — exactly 32 lowercase hex (128 bits)
 *                  · unit                         — the closed enum { "XTS" }, scale 0
 *                  and fromAccount !== toAccount
 *
 *     canonical  = JCS(params)                                   RFC 8785 over exactly the six members
 *     paramsHash = "sha256:" + hex(SHA-256(UTF8(canonical)))     no domain tag
 *
 *     display    = { Action, Ledger, From, To, Amount: amount + " " + unit, Salt }
 *                  derived from the RE-PARSED canonical bytes; every bound member is visible, nothing
 *                  unbound is shown, and the tuple can be rebuilt from the rows alone.
 *
 *     identity   = "sha256:" + hex(SHA-256(UTF8(JCS({id, version, kind, implementation}))))
 *                  where `implementation` is the SHA-256 of `projectLedgerTransfer`'s EMITTED source
 *                  text. Unlike the deployment bind, that function ships in this package, so the
 *                  pinned digest is recomputable by anyone holding the published build.
 *
 * WHY A SALT MEMBER. `paramsHash` travels in the clear wherever a receipt travels, while the display
 * is meant for the approver and the auditor only. Without a salt, anyone holding the hash could
 * confirm a guessed transfer by trying candidate tuples, because the value space of a transfer is
 * small. A 128-bit salt drawn by the producer's CSPRNG removes that; it is one more JCS member, so no
 * new cryptography is introduced. The limit — it protects only against hash holders, and only when
 * the producer is honest — is stated in `NON-CLAIMS.md` §S7.
 *
 * ── DISCIPLINE ON THIS PATH ──────────────────────────────────────────────────────────────────────
 *
 * Input is BYTES (ADR §3.1): the strict kernel parser refuses duplicate keys, `__proto__`,
 * `prototype`, `constructor`, floats, unsafe integers and malformed UTF-8 before any member rule
 * runs. Every membership decision is an own-property probe into a frozen null-prototype table; no
 * regular expression, no `startsWith`, no live prototype method decides anything here. Validators
 * test `typeof` first and walk indices bounded by `length`. Only captured intrinsics are called.
 *
 * ── WHAT A MATCH DOES NOT ESTABLISH ──────────────────────────────────────────────────────────────
 *
 *   - Not authorization, execution, settlement, balance sufficiency or account existence. Those are
 *     separate claims with their own evidence (`NON-CLAIMS.md` §S7).
 *   - The pinned hashes are NORMATIVE EXPECTED VALUES. They are not an attestation from any running
 *     system; the repository proves that implementation, corpus and literals agree and that each pin
 *     is load-bearing, and nothing more.
 *   - The identity commits to `projectLedgerTransfer`'s own source text. Behaviour reached through
 *     the helpers it calls (the validators, the canonicalizer, the parser) is outside it. Identity
 *     equality is a necessary signal for substitution, never a sufficient one for equivalence.
 *   - The risk class an enforcing gate assigns is that gate's policy, not part of this wire language.
 */

import { canonicalize } from "./jcs.js";
import { sha256Prefixed } from "./hash.js";
import { parseDocument } from "./bytes.js";
import { frozenTable } from "./inert.js";
import { projectionIdentityHash, type ProjectionIdentity } from "./deploy-release.js";
// CAPTURED INTRINSICS ONLY (ADR §5.5): every lookup on this path decides what bytes are hashed.
import { hasOwn, isArray, objectCreateNull, objectGetOwnPropertyNames } from "./intrinsics.js";

/** The spec identifier of this wire construct. */
export const LEDGER_TRANSFER_SPEC = "noa.ledger.transfer/1" as const;

/** The `action.canonical` this projection describes. */
export const LEDGER_TRANSFER_CANONICAL = "noa.ledger.transfer" as const;

/**
 * THE PINNED IMPLEMENTATION DIGEST: SHA-256 of `Function.prototype.toString(projectLedgerTransfer)`
 * over the EMITTED build of this module. It is recomputable from the published package, and
 * `test/ledger-transfer.test.ts` recomputes it on every run.
 *
 * Two causes can legitimately move it, and they need opposite explanations: a behaviour change in
 * `projectLedgerTransfer` (a new spec version), or a toolchain change that alters emitted text with
 * no behaviour change. Either way this constant, both identity vectors and the corpus move together
 * in one commit that says which cause it was. Deleting the pin is never a legitimate response.
 */
export const LEDGER_TRANSFER_IMPLEMENTATION_DIGEST =
  "sha256:2f4dce6dce395e77b93ecec4c19f2d34d303fa07d198a8464d254a1561423039" as const;

/** The pinned schema identity (kind `actionSchema`). */
export const LEDGER_TRANSFER_SCHEMA_ID: ProjectionIdentity = frozenTable(
  {
    id: "noa.ledger.transfer.schema",
    version: 1,
    hash: projectionIdentityHash({
      id: "noa.ledger.transfer.schema",
      version: 1,
      kind: "actionSchema",
      implementation: LEDGER_TRANSFER_IMPLEMENTATION_DIGEST,
    }),
  },
  "<ledger-transfer schema identity>",
);

/** The pinned display identity (kind `displayProjection`). MUST differ from the schema identity. */
export const LEDGER_TRANSFER_DISPLAY_ID: ProjectionIdentity = frozenTable(
  {
    id: "noa.ledger.transfer.display",
    version: 1,
    hash: projectionIdentityHash({
      id: "noa.ledger.transfer.display",
      version: 1,
      kind: "displayProjection",
      implementation: LEDGER_TRANSFER_IMPLEMENTATION_DIGEST,
    }),
  },
  "<ledger-transfer display identity>",
);

/** The closed unit enum, as a type. The runtime table below is the same rule; tests pin them together. */
export type LedgerTransferUnit = "XTS";

/** The validated six-member transfer tuple. Every member is a string; `amount` is never a number. */
export interface LedgerTransferParams {
  readonly amount: string;
  readonly fromAccount: string;
  readonly ledger: string;
  readonly salt: string;
  readonly toAccount: string;
  readonly unit: LedgerTransferUnit;
}

/**
 * The stable refusal codes of `/1`. Adding, renaming or reordering a code, or changing the order in
 * which they are evaluated, is a new spec version. `TRANSFER_CANONICAL_REPARSE` guards the render
 * node and cannot be reached by any input; it is kept so that "cannot fail" stays a checked claim.
 */
export type LedgerTransferRefusalCode =
  | "TRANSFER_PARSE"
  | "TRANSFER_NOT_OBJECT"
  | "TRANSFER_AMOUNT_INVALID"
  | "TRANSFER_FROM_INVALID"
  | "TRANSFER_LEDGER_INVALID"
  | "TRANSFER_SALT_INVALID"
  | "TRANSFER_TO_INVALID"
  | "TRANSFER_UNIT_INVALID"
  | "TRANSFER_UNRECOGNIZED_MEMBER"
  | "TRANSFER_SAME_ACCOUNT"
  | "TRANSFER_CANONICAL_REPARSE";

export type LedgerTransferResult =
  | {
      readonly ok: true;
      /** `sha256:` + hex over `canonical`. */
      readonly paramsHash: string;
      /** The exact JCS bytes the hash covers (UTF-8 of this string). */
      readonly canonical: string;
      /** The validated tuple, re-derived from `canonical` (frozen, null-rooted). */
      readonly value: LedgerTransferParams;
      /** The six display rows, re-derived from `canonical` (frozen, null-rooted). */
      readonly display: Readonly<Record<string, string>>;
      readonly actionSchema: ProjectionIdentity;
      readonly displayProjection: ProjectionIdentity;
    }
  | {
      readonly ok: false;
      readonly code: LedgerTransferRefusalCode;
      /** `code + ": " + detail`. The code is normative; the detail is informative. */
      readonly reason: string;
    };

/** Upper bound on an account or ledger identifier, in characters (all ASCII, so also in bytes). */
const MAX_IDENTIFIER = 64;
/** 15 digits: the largest amount is 999 999 999 999 999, which is below 2^53. */
const MAX_AMOUNT_DIGITS = 15;
/** 32 lowercase hex characters = 128 bits. */
const SALT_HEX_LENGTH = 32;

/** A frozen, null-prototype membership table over the characters of `chars`. */
function charTable(chars: string, path: string): Readonly<Record<string, true>> {
  const t = objectCreateNull<Record<string, true>>();
  for (let i = 0; i < chars.length; i++) t[chars[i] as string] = true;
  return frozenTable(t, path);
}

const ID_FIRST = charTable("abcdefghijklmnopqrstuvwxyz", "<ledger-transfer ID_FIRST>");
const ID_LAST = charTable("abcdefghijklmnopqrstuvwxyz0123456789", "<ledger-transfer ID_LAST>");
const ID_BODY = charTable("abcdefghijklmnopqrstuvwxyz0123456789-", "<ledger-transfer ID_BODY>");
const NONZERO_DIGIT = charTable("123456789", "<ledger-transfer NONZERO_DIGIT>");
const DIGIT = charTable("0123456789", "<ledger-transfer DIGIT>");
const LOWER_HEX = charTable("0123456789abcdef", "<ledger-transfer LOWER_HEX>");

/** The closed unit enum. A second unit is a new spec version, never a string a caller invents. */
const TRANSFER_UNITS: Readonly<Record<string, true>> = frozenTable(
  (() => {
    const t = objectCreateNull<Record<string, true>>();
    t["XTS"] = true;
    return t;
  })(),
  "<ledger-transfer TRANSFER_UNITS>",
);

/** The SIX recognized member names — the closed world, enforced in code. */
const RECOGNIZED_TRANSFER_KEYS: Readonly<Record<string, true>> = frozenTable(
  (() => {
    const t = objectCreateNull<Record<string, true>>();
    t["amount"] = true;
    t["fromAccount"] = true;
    t["ledger"] = true;
    t["salt"] = true;
    t["toAccount"] = true;
    t["unit"] = true;
    return t;
  })(),
  "<ledger-transfer RECOGNIZED_TRANSFER_KEYS>",
);

/** The informative detail for each fixed-detail refusal. The CODE is the normative part. */
const REFUSAL_DETAIL: Readonly<Record<string, string>> = frozenTable(
  (() => {
    const t = objectCreateNull<Record<string, string>>();
    t["TRANSFER_NOT_OBJECT"] = "params must be a JSON object";
    t["TRANSFER_AMOUNT_INVALID"] =
      "amount must be a JSON string of 1 to 15 ASCII digits with no leading zero";
    t["TRANSFER_FROM_INVALID"] =
      "fromAccount must be a JSON string of 1 to 64 characters from [a-z0-9-], first [a-z], last [a-z0-9]";
    t["TRANSFER_LEDGER_INVALID"] =
      "ledger must be a JSON string of 1 to 64 characters from [a-z0-9-], first [a-z], last [a-z0-9]";
    t["TRANSFER_SALT_INVALID"] = "salt must be a JSON string of exactly 32 lowercase hex characters";
    t["TRANSFER_TO_INVALID"] =
      "toAccount must be a JSON string of 1 to 64 characters from [a-z0-9-], first [a-z], last [a-z0-9]";
    t["TRANSFER_UNIT_INVALID"] = 'unit must be exactly "XTS"';
    t["TRANSFER_UNRECOGNIZED_MEMBER"] =
      "only { amount, fromAccount, ledger, salt, toAccount, unit } are permitted";
    t["TRANSFER_SAME_ACCOUNT"] = "fromAccount and toAccount must differ";
    t["TRANSFER_CANONICAL_REPARSE"] = "the canonical form did not re-derive the validated tuple";
    return t;
  })(),
  "<ledger-transfer REFUSAL_DETAIL>",
);

function refuse(code: LedgerTransferRefusalCode, detail?: string): LedgerTransferResult {
  const text = detail === undefined ? (REFUSAL_DETAIL[code] as string) : detail;
  return { ok: false, code, reason: `${code}: ${text}` };
}

/**
 * ⚠ THE `v[i]` READS BELOW ARE NOT PROTOTYPE DISPATCH. Each validator establishes
 * `typeof v === "string"` first, so an integer index below `v.length` is answered by the String
 * exotic object's own [[GetOwnProperty]] and never reaches `String.prototype`. That is why every walk
 * is bounded by `length`. The `typeof` test first also closes kind coercion: a number, a boolean, an
 * array of characters and an object are refused before any length or character test runs.
 */

/** 1..15 ASCII digits, first digit 1-9. ONE spelling per amount: no sign, zero pad, separator, exponent. */
function asAmount(v: unknown): string | undefined {
  if (typeof v !== "string") return undefined;
  const n = v.length;
  if (n === 0 || n > MAX_AMOUNT_DIGITS) return undefined;
  if (!hasOwn(NONZERO_DIGIT, v[0] as string)) return undefined;
  for (let i = 1; i < n; i++) {
    if (!hasOwn(DIGIT, v[i] as string)) return undefined;
  }
  return v;
}

/** 1..64 characters of [a-z0-9-], first [a-z], last [a-z0-9]. Case variants are refused, never folded. */
function asIdentifier(v: unknown): string | undefined {
  if (typeof v !== "string") return undefined;
  const n = v.length;
  if (n === 0 || n > MAX_IDENTIFIER) return undefined;
  if (!hasOwn(ID_FIRST, v[0] as string)) return undefined;
  if (!hasOwn(ID_LAST, v[n - 1] as string)) return undefined;
  for (let i = 1; i < n - 1; i++) {
    if (!hasOwn(ID_BODY, v[i] as string)) return undefined;
  }
  return v;
}

/** Exactly 32 lowercase hex characters. Uppercase is refused, never normalized. */
function asSalt(v: unknown): string | undefined {
  if (typeof v !== "string" || v.length !== SALT_HEX_LENGTH) return undefined;
  for (let i = 0; i < SALT_HEX_LENGTH; i++) {
    if (!hasOwn(LOWER_HEX, v[i] as string)) return undefined;
  }
  return v;
}

function asUnit(v: unknown): LedgerTransferUnit | undefined {
  if (typeof v !== "string") return undefined;
  // The probe IS the narrowing: `TRANSFER_UNITS` and `LedgerTransferUnit` state one closed rule, and
  // `test/ledger-transfer.test.ts` pins them against each other from the outside.
  return hasOwn(TRANSFER_UNITS, v) ? (v as LedgerTransferUnit) : undefined;
}

type TransferCheck =
  | { readonly ok: true; readonly value: LedgerTransferParams }
  | { readonly ok: false; readonly code: LedgerTransferRefusalCode };

/**
 * The member rules, in the normative order (spec §6): the six members in JCS key order, one read
 * each, first failure wins; then the closed world; then the one rule that compares two members,
 * which runs last because it needs both validated. Shared by the input path and the render node, so
 * the two can never apply different rules.
 */
function checkTransfer(o: Record<string, unknown>): TransferCheck {
  const amount = asAmount(o["amount"]);
  if (amount === undefined) return { ok: false, code: "TRANSFER_AMOUNT_INVALID" };
  const fromAccount = asIdentifier(o["fromAccount"]);
  if (fromAccount === undefined) return { ok: false, code: "TRANSFER_FROM_INVALID" };
  const ledger = asIdentifier(o["ledger"]);
  if (ledger === undefined) return { ok: false, code: "TRANSFER_LEDGER_INVALID" };
  const salt = asSalt(o["salt"]);
  if (salt === undefined) return { ok: false, code: "TRANSFER_SALT_INVALID" };
  const toAccount = asIdentifier(o["toAccount"]);
  if (toAccount === undefined) return { ok: false, code: "TRANSFER_TO_INVALID" };
  const unit = asUnit(o["unit"]);
  if (unit === undefined) return { ok: false, code: "TRANSFER_UNIT_INVALID" };

  // The closed world. Own STRING keys are the whole key set: JSON cannot carry symbol keys, and the
  // strict parser has already refused duplicates and `__proto__`. Without this rule `{six members}`
  // and `{six members, memo}` share one hash while the memo is invisible to the approver.
  const presentKeys = objectGetOwnPropertyNames(o);
  for (let i = 0; i < presentKeys.length; i++) {
    if (!hasOwn(RECOGNIZED_TRANSFER_KEYS, presentKeys[i] as string)) {
      return { ok: false, code: "TRANSFER_UNRECOGNIZED_MEMBER" };
    }
  }

  // Exact comparison of two already-validated ASCII strings. It runs after parsing, so an escaped
  // spelling of the same account is the same account.
  if (fromAccount === toAccount) return { ok: false, code: "TRANSFER_SAME_ACCOUNT" };

  return {
    ok: true,
    value: frozenTable({ amount, fromAccount, ledger, salt, toAccount, unit }, "<ledger-transfer tuple>"),
  };
}

type TransferView =
  | { readonly ok: true; readonly value: LedgerTransferParams }
  | { readonly ok: false; readonly detail: string };

/**
 * THE RENDER NODE: the display and the returned tuple are derived from OUR OWN canonical bytes,
 * parsed back through the same strict boundary and the same rules, so the value that was hashed and
 * the value the human reads have exactly one source. Parsing a string produced one line earlier
 * cannot fail on any input; the `ok:false` arms are kept and returned rather than asserted away.
 * This node is a structural invariant, not a measured control: no input reaches its refusal.
 */
function transferView(canonical: string): TransferView {
  const parsed = parseDocument(canonical, "canonical params");
  if (!parsed.ok) return { ok: false, detail: `canonical params did not re-parse: ${parsed.reason}` };
  const v = parsed.value;
  if (typeof v !== "object" || v === null || isArray(v)) {
    return { ok: false, detail: "canonical params are not an object" };
  }
  const checked = checkTransfer(v as Record<string, unknown>);
  if (!checked.ok) return { ok: false, detail: `canonical params failed re-validation (${checked.code})` };
  return { ok: true, value: checked.value };
}

/**
 * Validate a ledger transfer, canonicalize it, and derive its `paramsHash`, display and pinned
 * identities. BYTES IN (ADR §3.1): a caller-owned live object is refused without being traversed.
 *
 * Refusal order (normative, spec §6): parse → not an object → the six members in JCS key order →
 * closed world → same account. The hash covers the RE-EMITTED canonical bytes, never the input
 * bytes, so a key-shuffled or escape-spelled input binds the same value as its canonical form.
 *
 * @param paramsBytes the transfer tuple as JSON bytes or text
 */
export function projectLedgerTransfer(paramsBytes: Uint8Array | string): LedgerTransferResult {
  const parsed = parseDocument(paramsBytes, "params");
  if (!parsed.ok) return refuse("TRANSFER_PARSE", parsed.reason);
  const v = parsed.value;
  if (typeof v !== "object" || v === null || isArray(v)) return refuse("TRANSFER_NOT_OBJECT");
  const checked = checkTransfer(v as Record<string, unknown>);
  if (!checked.ok) return refuse(checked.code);

  let canonical: string;
  try {
    canonical = canonicalize(checked.value);
  } catch {
    return refuse("TRANSFER_CANONICAL_REPARSE", "the validated tuple is not JCS-canonicalizable");
  }
  const paramsHash = sha256Prefixed(canonical);
  const bound = transferView(canonical);
  if (!bound.ok) return refuse("TRANSFER_CANONICAL_REPARSE", bound.detail);
  const b = bound.value;

  // Six rows, every bound member visible, nothing unbound shown. `Amount` joins two members at a
  // single space: `amount` is digits only and `unit` letters only, so the split is unambiguous and
  // the tuple can be rebuilt from the rows alone.
  const display: Readonly<Record<string, string>> = frozenTable(
    {
      Action: LEDGER_TRANSFER_CANONICAL,
      Ledger: b.ledger,
      From: b.fromAccount,
      To: b.toAccount,
      Amount: `${b.amount} ${b.unit}`,
      Salt: b.salt,
    },
    "<ledger-transfer display>",
  );
  return {
    ok: true,
    paramsHash,
    canonical,
    value: b,
    display,
    actionSchema: LEDGER_TRANSFER_SCHEMA_ID,
    displayProjection: LEDGER_TRANSFER_DISPLAY_ID,
  };
}
