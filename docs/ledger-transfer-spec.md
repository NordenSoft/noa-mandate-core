# `noa.ledger.transfer/1` — the reference ledger-transfer bind

Status: **IMPLEMENTED as wire language** (`src/ledger-transfer.ts`), conformance corpus at
[`conformance/ledger-transfer/vectors.json`](../conformance/ledger-transfer/vectors.json). Indexed as
ADR-R-010 (`03_DECISIONS_ADR.md`), status PROPOSED until independent review. The reference Gate in
this repository defines an adapter for this action but does **not** register it (§15).

This document is written so an independent implementer can build a conforming producer and verifier
from it and the corpus alone. Every constant, byte order and refusal rule is stated here.

---

## 1. Problem

A ledger transfer — move `amount` whole units of `unit` from `fromAccount` to `toAccount` on `ledger`
— is a protected consequence. When such an action is authorized, a receipt carries
`action.paramsHash`, the producer's commitment to the parameters. `noa.receipt/0.1` deliberately does
not say what that hash is computed over (ADR-R-004). For this one declared `action.canonical` a
relying party needs more: a published rule that turns a disclosed transfer into `paramsHash`, a
published rendering of what the approver is shown, and a published way to check one against the
other.

`noa.ledger.transfer/1` is that rule. It fixes the member set, the spellings, the canonical bytes,
the digest, the display and the refusal codes, so that:

- two conforming implementations handed the same transfer compute the same `paramsHash` and the same
  display, byte for byte;
- two transfers that differ in any member produce different canonical bytes, hence different
  `paramsHash` values (barring a SHA-256 collision) and different displays;
- an auditor holding an audit-decrypted display can rebuild the transfer from the rows, recompute
  `paramsHash`, and compare it with the receipt — without trusting whoever stored the display.

It commits nothing, registers nothing and authorizes nothing.

---

## 2. Actors

| Actor | Role in this construct |
|---|---|
| Agent (proposer) | Proposes the six members only. It never supplies `paramsHash` or the display — an enforcing gate refuses those fields — and a risk class it sends is only a hint that can raise, never lower, the gate's own floor. |
| Enforcing gate | Derives `paramsHash`, the display and its own risk floor from the members, and binds them into what it signs. |
| Approver and auditor | The recipients of the display. They see every member, including the salt. |
| Relay or console | Carries envelopes and receipts. Assumed compromised: it may read `paramsHash` in the clear. |
| Offline verifier | Recomputes everything in this document from bytes. |
| Effect owner | The ledger that commits the transfer. Outside this specification (§12). |
| Independent implementer | Builds from this document and the corpus alone (§14). |

---

## 3. The bound parameter set

Exactly six members. All are REQUIRED. All are JSON **strings**. No other member is permitted.

| Member | Rule |
|---|---|
| `amount` | 1 to 15 characters: the first `1`–`9`, the rest `0`–`9`. So 1 to 999 999 999 999 999 whole units. |
| `fromAccount` | An identifier (§3.1). |
| `ledger` | An identifier (§3.1). Names the ledger instance the transfer targets. |
| `salt` | Exactly 32 characters from `0`–`9` `a`–`f` (128 bits, lowercase hex). |
| `toAccount` | An identifier (§3.1). |
| `unit` | Exactly `XTS`. |

And one rule across members: `fromAccount` and `toAccount` MUST differ, compared exactly after parsing.

### 3.1 Identifiers

1 to 64 characters. The first character is `a`–`z`; the last is `a`–`z` or `0`–`9`; every character in
between is `a`–`z`, `0`–`9` or `-`. A one-character identifier (`a`) is legal. Lengths are counted in
UTF-16 code units; every permitted character is ASCII, so code units, code points and bytes coincide.

No uppercase, no whitespace, no control characters, no punctuation other than `-`. Each of those is a
display-integrity rule: a newline or an ANSI escape can rewrite what an approver reads, and case
variants would give one account two spellings.

### 3.2 One spelling per value

Every rule above is a REFUSAL, never a normalization. `012345`, `+12345`, ` 12345`, `1e4`, `1,000`,
`0x1f`, fullwidth or Arabic-Indic digits, uppercase hex in `salt`, `xts` or `XTS ` in `unit`,
`Acct-…` in an identifier: all are refused, not repaired. An equivalence class is an attacker's
choice of representative, and a normalizer on a digest path is a forgery surface — two spellings of
one transfer would carry two commitments.

For `amount` this also means the value never passes through binary floating point: it is a string on
the wire, and 15 digits stay below 2^53, so an implementation that converts it to IEEE 754 binary64,
a signed 64-bit integer or an arbitrary-precision integer reads it exactly. Narrower types do not:
binary32 rounds `16777217`, and a 32-bit integer overflows above 2 147 483 647.

`unit` is the ISO 4217 code `XTS` ("codes specifically reserved for testing purposes", numeric 963,
minor unit N.A.). Scale is 0: `amount` counts whole units and is never rendered as a decimal. The
enum is closed; a second unit is a new version of this specification.

### 3.3 Absent, null, empty, wrong type

For every member, absent, `null`, `""`, a non-string (number, boolean, array, object) and a malformed
string are the SAME refusal for that member. A number `12345` is not the string `"12345"`.

### 3.4 Deliberately not bound

Memo, reference, fee, expiry, approver, idempotency key and reversibility are not members. They are
either free text an approver could misread, or properties of the AUTHORIZATION (window, approvers,
request identity) that the authorization layer already carries. A second, caller-supplied copy of an
authorization fact is how two planes come to disagree. Each is refused by the closed-world rule
(§6).

### 3.5 Not checked here

Account existence, balance, overdraft and ledger membership are facts only the effect owner holds at
commit time. This construct is pure and network-less and does not check them (§12).

---

## 4. Canonical bytes and `paramsHash` (normative)

```
canonical  = JCS(params)                                  RFC 8785, over exactly the six members
paramsHash = "sha256:" ++ lowerhex( SHA-256( UTF8( canonical ) ) )
```

No domain-separation tag, for the reason given for `noa.deploy.release/1`: `paramsHash` is a value an
enforcing producer computes over the parameter object itself, and nothing signs it directly — it is
bound into documents that are signed under their own tags (§9). No new cryptography is involved.

### 4.1 The JSON dialect

Input is BYTES (or text), parsed by the strict kernel parser before any member rule runs:

- duplicate object keys are refused (never last-wins);
- the keys `__proto__`, `prototype` and `constructor` are refused;
- numbers must be integers within the safe range (a float, an exponent or `9007199254740993` is
  refused here, before the member rules);
- input must be well-formed UTF-8, decoded fatally (an overlong form is refused, never substituted);
  a leading byte-order mark is not stripped and is refused as an unexpected character;
- unescaped control characters inside strings are refused; escaped ones parse (and are then refused
  by the member rules);
- the document limit is 16 MiB and the nesting limit is 64.

A conforming implementation MUST refuse what a permissive parser would silently repair. The sharpest
case is a duplicate `amount`: last-wins parsing binds a value a first reader never saw.

### 4.2 The hash covers the re-emitted bytes, never the input bytes

The digest is computed over `canonical`, which is produced from the validated members. A key-shuffled
input, an input with insignificant whitespace, and an input spelling `a` as `a` all bind the same
`paramsHash` as the canonical form (vectors `accept-key-order-and-whitespace`,
`accept-escaped-spelling`).

### 4.3 Template form (informative)

Every permitted character is ASCII and none is `"`, `\` or a control character, so the JCS output is
always exactly

```
{"amount":"<amount>","fromAccount":"<fromAccount>","ledger":"<ledger>","salt":"<salt>","toAccount":"<toAccount>","unit":"<unit>"}
```

with the members in this order. An implementer can build it without a JCS library; the generator
checks this equality for every accept vector. JCS does not normalize Unicode, and ASCII-only members
make that irrelevant here.

### 4.4 The base value

The conformance tuple `{amount "12345", fromAccount "acct-example-1", ledger "ledger-example-1",
salt "000102030405060708090a0b0c0d0e0f", toAccount "acct-example-2", unit "XTS"}` binds

```
paramsHash = sha256:aa9256899837f204583f28e483ed67129b204e7edabf378eaf60f296915aebd0
```

The same accounts in the opposite direction bind
`sha256:78c09338f519b071c893674301c0197ab2cd44821279a219dc3aeb6abb6b0b5c`.

---

## 5. The display projection (normative)

Derived from the canonical bytes, parsed back through the same strict boundary and the same rules
(the render node), so what is hashed and what is shown have one source. Six string rows:

```
Action = "noa.ledger.transfer"
Ledger = ledger
From   = fromAccount
To     = toAccount
Amount = amount ++ " " ++ unit
Salt   = salt
```

### 5.1 Properties

- **Complete.** Every bound member is visible and nothing unbound is shown.
- **Injective.** `Amount` is split at its single space: `amount` is digits only and `unit` is letters
  only, so the split is unambiguous. Every other row carries exactly one member. Two different
  transfers therefore never render the same rows.
- **Invertible.** Because it is complete and injective, the tuple can be rebuilt from the rows (§5.2).

The `Salt` row is shown on purpose. Hiding it would make the display incomplete: an auditor could no
longer rebuild the tuple and recompute `paramsHash` from the display alone.

### 5.2 Rebuilding the tuple from a display (the auditor's check)

1. Require exactly the six row names above and `Action = "noa.ledger.transfer"`.
2. Split `Amount` at its only space: the left part is `amount`, the right part is `unit`.
3. `fromAccount = From`, `toAccount = To`, `ledger = Ledger`, `salt = Salt`.
4. Run the tuple through §3–§4. Compare the result with the receipt's `action.paramsHash`.

A match shows that the display and the hash describe the same transfer, without trusting the store
that held the display. This procedure is normative text and is tested; it is deliberately not a
published function.

### 5.3 Rendering

A sealed display travels as `JCS(display)`, so row order is not carried on the wire. Renderers SHOULD
present rows in the order listed above, MUST show every row verbatim and untruncated with no locale
reformatting (no digit grouping, no currency symbol), and SHOULD use a monospace face so that
confusable ASCII pairs (`l`/`1`, `o`/`0`, `rn`/`m`) are easier to tell apart. Nothing in this
specification can verify what a renderer actually drew (§11).

---

## 6. Refusals (normative)

An implementation refuses in this order, and the first failure wins:

| # | Step | Code |
|---|---|---|
| 1 | Byte and parse layer (§4.1) | `TRANSFER_PARSE` |
| 2 | Top level is not an object (`null`, array, string, number, boolean) | `TRANSFER_NOT_OBJECT` |
| 3 | `amount` (§3) | `TRANSFER_AMOUNT_INVALID` |
| 4 | `fromAccount` | `TRANSFER_FROM_INVALID` |
| 5 | `ledger` | `TRANSFER_LEDGER_INVALID` |
| 6 | `salt` | `TRANSFER_SALT_INVALID` |
| 7 | `toAccount` | `TRANSFER_TO_INVALID` |
| 8 | `unit` | `TRANSFER_UNIT_INVALID` |
| 9 | Any own member outside the six | `TRANSFER_UNRECOGNIZED_MEMBER` |
| 10 | `fromAccount` equals `toAccount` | `TRANSFER_SAME_ACCOUNT` |
| 11 | The canonical form does not re-derive the validated tuple | `TRANSFER_CANONICAL_REPARSE` |

Steps 3–8 are the members in JCS key order. Member rules run before the closed world, and the
two-member rule runs last because it needs both members validated. Step 11 guards the render node;
no input can reach it, and no vector carries it.

The refusal carries the code and a reason of the form `<code>: <detail>`. **The code is normative.**
The detail is informative, except that for `TRANSFER_PARSE` the reference implementation's detail
contains the kernel parser's reason, and the corpus pins a substring of it (`reasonContains`); other
implementations are not required to reproduce that text.

The codes and their order are stable within `/1`. Adding, renaming or reordering a code, or changing
the precedence, is a new version.

Per-member codes are deliberate. A refusal for the wrong reason measures nothing: with one shared
code, a vector meant to test the salt rule would pass when the amount rule fired instead, and nobody
could tell whether each member's rule is actually wired.

---

## 7. Projection identity (normative)

```
identity = "sha256:" ++ lowerhex( SHA-256( UTF8( JCS( {
             id, version, kind, implementation } ) ) ) )
```

This is the construction of `noa.deploy.release/1` §6, exported as `projectionIdentityHash`.

| id | version | kind | hash |
|---|---|---|---|
| `noa.ledger.transfer.schema` | 1 | `actionSchema` | `sha256:f34d508cfa9080eadaa771ed8852a0d34c09246d03f818d75f848abb4df25901` |
| `noa.ledger.transfer.display` | 1 | `displayProjection` | `sha256:bb6e72d64700383a4ceabefeb8e8eb170a2877ca95a5522c90901466e9a421db` |

both over `implementation =
sha256:2f4dce6dce395e77b93ecec4c19f2d34d303fa07d198a8464d254a1561423039`. The two MUST differ.

`implementation` is the SHA-256 of the emitted source text of the function `projectLedgerTransfer`
(`Function.prototype.toString`), as built from `src/ledger-transfer.ts` and shipped in the npm
package under `dist/src/ledger-transfer.js`. Unlike the deployment bind, the measured artifact is
public, so anyone can recompute it from the published build; the repository's own test suite does so
on every run. Two causes can move it: a behaviour change (a new version of this specification) or a
toolchain change that alters the emitted text without changing behaviour. Either way the digest,
both identities and the corpus move together in one change that says which.

The identity commits to that one function's text. Behaviour reached through the helpers it calls —
the member validators, the canonicalizer, the parser — is outside it (§11).

---

## 8. Versioning and compatibility

The spec identifier `noa.ledger.transfer/1` is frozen at publication. Any change to the member set, a
character set, the unit enum, a range, a refusal code, the refusal order or the display is `/2`, with
new identity versions. The `paramsHash` of a `/1` tuple never changes.

An enforcing gate maps one `action.canonical` to one adapter, so `/1` and `/2` cannot both be served
under the same canonical name by one build; each signed envelope names the identity it was created
under.

Compatibility: this construct is additive and disjoint from `noa.receipt/0.1`, which gains no field
(ADR-R-001). Consistent with ADR-R-004 it does not make `paramsHash` a universal cross-producer digest;
it publishes the rule for one declared `action.canonical`. The new exports of the kernel package are a
permanent compatibility commitment.

---

## 9. Signature scope

This construct signs nothing. An enforcing gate places `paramsHash` in the deferred receipt it
embeds in the envelope it signs, and binds the display by encrypting it to the approver and auditor
and signing the ciphertext hash. The signature scope is therefore that of those documents, under
their own domain tags; this specification defines only the bytes they commit to.

---

## 10. Security and privacy considerations

**The salt.** `paramsHash` travels in the clear wherever a receipt travels, while the display is meant
for the approver and the auditor only. Without a salt, anyone holding the hash could confirm a guessed
transfer by trying candidate tuples, because the value space of a transfer is small. With a salt drawn
from a cryptographically secure generator and never shown to the hash holder, confirming a guess
requires guessing 128 random bits as well. This is the salted hash commitment used for selective
disclosure (RFC 9901 §9.3 recommends at least 128 bits of salt for the same purpose). It rests on
SHA-256 preimage resistance and on the salt staying secret from the hash holder; it is not a formal
hiding proof.

- The salt protects only against holders of the hash (a relay, a receipt store), and only when the
  producer is honest. A projection cannot test randomness: an all-zero salt is accepted
  (`accept-salt-all-zero`), which pins this limit rather than hiding it.
- The agent that proposes the transfer, the gate, the approver and the auditor all see the full tuple,
  salt included.
- A producer MUST reuse the same salt when it retries the same request. A new salt is a new
  `paramsHash`, so a retry with a fresh salt is a different request to an idempotent gate.
- `salt` carries no meaning. An effect owner MUST NOT read it for anything but the hash.
- Account and ledger identifiers SHOULD NOT carry personal data: they are shown to approvers and
  auditors and are the preimage of a published-shape hash.

**Confusables.** The character set removes non-ASCII homoglyphs, invisible characters and bidirectional
overrides (all refused, with vectors). It cannot remove confusable pairs that are inside the set
(`l`/`1`, `o`/`0`, `rn`/`m`); monospace rendering helps and proves nothing.

**Amounts.** The fixed 15-digit range keeps every amount exact in IEEE 754 binary64, in signed 64-bit
integers and in arbitrary-precision integers (§3.2); it is not exact in binary32 or in 32-bit
integers. An effect owner still has to use checked integer arithmetic on the validated string (§12).

**Splitting and rate.** Nothing here limits how many transfers are proposed or how an amount is split
across them. That is policy.

---

## 11. What a recomputed match does NOT establish

`NON-CLAIMS.md` §S7 is the normative list. In short, an accepted result is not authorization,
execution, settlement, balance sufficiency or account existence; not proof that a human understood
the display or that a device rendered it faithfully; not protection against in-set confusables or
against splitting; not real money (`XTS` only); and not a uniqueness key (`paramsHash` repeats for
identical tuples). The pinned hashes are normative expected values, not attestations about any
running system.

---

## 12. Requirements outside this specification (informative)

These are stated so that nobody mistakes this wire language for a complete control. They are not
part of `/1` conformance.

An **enforcing gate** that serves this action derives `paramsHash`, the display and both identities
only from the members; refuses a caller-supplied `paramsHash` or display; lets a caller's risk hint
only raise its floor, never lower it; and documents that floor as its own policy.

An **effect owner** that commits a transfer re-derives `paramsHash` from the stored canonical bytes
with this function and compares it with the authorization it consumes; refuses a tuple whose `ledger`
is not its own identifier; parses `amount` only from the validated string, with checked integer
arithmetic; and binds the consumption of the authorization and the ledger write to the same
transaction.

---

## 13. Conformance

**Conformance means following the normative rules of §3–§7**: the member set and spellings, the JSON
dialect, the canonical bytes and digest, the display, the refusal codes and their order, and the
identity construction. The corpus is the executable check of those rules, not a replacement for them:
an implementation that passes every vector while breaking a rule stated here does not conform, and the
corpus is extended when such a gap is found.

The executable check: an implementation passes the corpus iff, over every vector in
[`conformance/ledger-transfer/vectors.json`](../conformance/ledger-transfer/vectors.json), with no
skips:

1. every ACCEPT vector produces exactly the pinned `paramsHash`, `canonical` and `display`;
2. every REJECT vector refuses with exactly the pinned `reasonCode` (a refusal for the wrong reason
   is a failure; `reasonContains` binds the reference implementation and is informative for others);
3. both identity vectors recompute from their descriptors per §7;
4. the conformance claim names the SHA-256 of the corpus file it was measured against.

Input encoding: a vector carries either `paramsText` (the exact input string; feed its UTF-8 bytes) or
`paramsHex` (the exact input bytes, lowercase hex — used only for inputs no text form can carry, such
as an overlong UTF-8 sequence). Never both. An ACCEPT vector may carry `equivalentTo`, naming the
vector whose binding it must equal. A precedence vector carries `beats`: its input violates two
rules, the pinned `reasonCode` and the one named by `beats`, and the pinned code must win (§6). Every
adjacent pair of the §6 order from `TRANSFER_AMOUNT_INVALID` to `TRANSFER_SAME_ACCOUNT` has such a
vector, so an implementation that evaluates the rules in any other order fails at least one of them.

The corpus is generated by `scripts/gen-ledger-transfer-vectors.ts`, committed and diff-gated. The
generator replays every vector before writing and refuses to write unless the identity and base pins
reproduce, every accept hash and display is distinct (except declared equivalents), every display
rebuilds its canonical tuple, every canonical form equals the §4.3 template built from the vector's
own fixture, every reachable code occurs, and every adjacent refusal-order pair is pinned by a vector
whose input really violates both rules. The fixture is synthetic by construction: accounts
`acct-example-N`, ledgers `ledger-example-N`, the testing code `XTS`, counting-pattern salts.

---

## 14. Independent-implementation path

This repository contains one implementation of `/1`. An independent implementation is follow-up work
and is not claimed: the intended path is a standard-library-only addition to the existing Python
verifier (`impl-py/`) — duplicate-key refusal through an object-pairs hook, float and constant
refusal, the safe-integer and forbidden-key checks, the character tables, the §4.3 template and
`hashlib` — written by someone other than this implementation's author, from this document and the
corpus only. A conformance-matrix row appears only after it passes; until then there is no
independence claim, and ADR-R-007 stays UNRESOLVED.

---

## 15. Reference Gate status in this revision

`packages/gate` defines a sealed adapter for `noa.ledger.transfer`, built on `projectLedgerTransfer`,
and measures its identity from that function at load, refusing to load if the result differs from the
pins in §7. It does **not** register the adapter: a hold for `noa.ledger.transfer` is refused with
`UNREGISTERED_CRITICAL_ACTION`, exactly as for any unregistered action. Registration would make an
approved transfer yield an execution grant the requesting agent can read before any effect owner can
consume it at commit time; it is left to a later revision of the reference Gate that ships the
effect-owner path with it.

The adapter's risk floor is that Gate's own policy and not wire language: a fixed `HIGH` for every
transfer, independent of the amount, so that splitting a transfer cannot lower its approver tier. A
caller's hint can only raise it.

---

## 16. Packaging

`src/ledger-transfer.ts` ships in the npm package (compiled, via `dist/src`). This document and the
conformance corpus do not ship in the tarball; the public repository is their authoritative location.
