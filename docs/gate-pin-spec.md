# `noa.gate-pin/1` — the Gate-pin fingerprint

Status: **IMPLEMENTED** in the reference Gate (`packages/gate/src/gate-pin.ts`: `gatePinFingerprint`,
`gatePinFingerprintFromRaw`, `gatePinPublicKeyFromRaw`), conformance corpus at
[`conformance/gate-pin/vectors.json`](../conformance/gate-pin/vectors.json). Indexed as ADR-R-013
(`03_DECISIONS_ADR.md`), status PROPOSED until independent review.

This document is written so an independent implementer can build a conforming fingerprint function
from it and the corpus alone. Every constant, byte order and refusal rule is stated here.

---

## 1. Problem

An approver's device learns about a Gate from a source it does not trust as an authority — for
example a list of enrolled Gates offered by a console. Before the device accepts hold envelopes signed
by that Gate's key, a person confirms that the Gate identity the device was offered is the one the
Gate host actually runs. People cannot compare two 44-character keys reliably, so both sides show a
short, fixed-format string computed from the same three facts: the tenant, the Gate's key identifier
and the Gate's public key. The person compares the two strings; equal strings mean the same three facts.

## 2. Actors

- **The Gate host** prints the fingerprint of its own identity: the pinned `serve` banner and
  `noa-gate roster-check` print it as the member `gatePin` (`docs/gate-pinned-trust.md`).
- **The device** computes the fingerprint of the identity it was offered and shows it next to a
  confirm action.
- **The person** compares the two strings and confirms only when they are equal.

No party verifies a signature against the fingerprint, and no party accepts a key because of it.

## 3. The inputs (normative)

| Member | Rule | Refusal |
| --- | --- | --- |
| `tenant` | a string of 1 to 256 characters, each in 0x21–0x7E (printable ASCII, no space): the Gate roster's tenant rule | `GATE_PIN_TENANT_INVALID` |
| `gateKid` | a string of 1 to 64 characters of `[a-z0-9-]`, first `[a-z]`, last `[a-z0-9]`: the roster's id rule | `GATE_PIN_KID_INVALID` |
| `publicKey` | the canonical base64 (RFC 4648 §4, padded) of a DER SubjectPublicKeyInfo for an Ed25519 key (RFC 8410) that re-encodes byte for byte and passes strict key validation: canonical point encoding, not one of the eight small-order points, in the prime-order subgroup (`conformance/vectors/strict-ed25519/README.md`) | `GATE_PIN_KEY_INVALID` |

A member that is absent, `null`, of another type, or malformed is refused by that member's rule. An
input that is not a JSON object in the RFC 8259 sense — an array, a string, a number, `null` — or whose
members cannot be read is `GATE_PIN_INPUT_INVALID`. Members other than these three are ignored: they
are not part of the fingerprint.

### 3.1 A raw key

A source that holds the Gate key as its raw 32 bytes in unpadded base64url (RFC 4648 §5; exactly 43
characters of `[A-Za-z0-9_-]`) gives it as the member `publicKeyRaw` in place of `publicKey`. The input,
tenant and kid rules are the same; the key step converts the raw key first:

1. the value is a string of exactly 43 characters of that alphabet, else `GATE_PIN_RAW_KEY_INVALID`;
2. it is the one canonical spelling of 32 bytes — decoding and re-encoding gives the same string,
   which requires the two unused low bits of the last character to be zero — else
   `GATE_PIN_RAW_KEY_INVALID`;
3. `publicKey` = base64(`302a300506032b6570032100` ‖ the 32 bytes), the fixed RFC 8410 Ed25519
   SPKI prefix followed by the key; it must pass the §3 key rule, else `GATE_PIN_KEY_INVALID`.

## 4. Canonical bytes and the fingerprint (normative)

The canonical bytes are the RFC 8785 (JCS) serialization of the object

    {"spec":"noa.gate-pin/1","tenant":T,"gateKid":K,"publicKey":P}

that is, the UTF-8 bytes of

    {"gateKid":K,"publicKey":P,"spec":"noa.gate-pin/1","tenant":T}

with each value written as a JSON string (a quotation mark and a reverse solidus in the tenant are
escaped as `\"` and `\\`; no other §3 character needs escaping). The digest is
`sha256:` ‖ the 64 lowercase hexadecimal characters of SHA-256 over those bytes. The fingerprint is

    "NOAGP1-" ‖ h[0:4] ‖ "-" ‖ h[4:8] ‖ "-" ‖ h[8:12] ‖ "-" ‖ h[12:16] ‖ "-" ‖ h[16:20]

where `h` is that lowercase hexadecimal digest: five groups of four hexadecimal characters (80 bits),
separated by hyphen-minus (U+002D), all lowercase, 31 characters in total. It is shown as is: no word
list, no case change, no other separator.

## 5. Refusals (normative)

In this order; the first failure wins: `GATE_PIN_INPUT_INVALID`, `GATE_PIN_TENANT_INVALID`,
`GATE_PIN_KID_INVALID`, `GATE_PIN_KEY_INVALID`. For an input with `publicKeyRaw` (§3.1) the key step is
the conversion: `GATE_PIN_INPUT_INVALID`, `GATE_PIN_TENANT_INVALID`, `GATE_PIN_KID_INVALID`,
`GATE_PIN_RAW_KEY_INVALID`, `GATE_PIN_KEY_INVALID` — a malformed tenant or kid is reported before a
malformed raw key. A refusal produces no fingerprint: a device never shows a string for an identity it
refused.

## 6. Signature scope

None. The fingerprint is not signed and signs nothing. It is a display string compared by a person;
it is never an authority input.

## 7. Versioning and compatibility

`/1` is fixed by this document. Any change to the members, the canonical bytes, the hash, the
truncation length, the grouping or the prefix is a new version with a new prefix (`noa.gate-pin/2`,
`NOAGP2-`). A device and a Gate host that print different prefixes are not comparable and must not be
presented as if they were. This is a new format; nothing earlier is replaced.

## 8. Security and privacy considerations

- **Truncation.** 80 bits resist a targeted second preimage: an attacker who wants a key of their own
  whose fingerprint equals a given Gate's must do about 2^80 SHA-256 evaluations. They are not
  collision-resistant against an attacker who chooses both identities (about 2^40), which matters only
  if that attacker can also make the genuine Gate host print their chosen identity.
- **What equality establishes.** Equal strings mean the device was offered the tenant, kid and key the
  Gate host printed. They do not establish that the host is uncompromised, that the key is still the
  Gate's, or that the person compared carefully.
- **Binding.** The tenant and the kid are bound as well as the key: the same key under another kid or
  tenant gives another fingerprint.
- **Privacy.** The inputs are an identity a Gate already publishes; the fingerprint reveals nothing
  beyond a truncated hash of them.

## 9. Conformance

An implementation conforms when it follows §3–§5 and passes the corpus
[`conformance/gate-pin/vectors.json`](../conformance/gate-pin/vectors.json) with no skips:

1. every `fingerprint` ACCEPT vector produces exactly the pinned `digest` and `fingerprint`, and its
   canonical bytes are the pinned `canonical` text;
2. every `raw-key` vector carries `publicKeyRaw` in place of `publicKey`; an ACCEPT converts it to
   exactly the pinned `publicKey` and produces the pinned fingerprint (its `equivalentTo` vector's
   fingerprint);
3. every REJECT vector refuses with exactly the pinned `reasonCode`;
4. a precedence vector's input also violates the rule its `beats` names, and the pinned code wins.
   Each adjacent pair of both §5 orders is pinned (input before tenant, tenant before kid, kid before
   key; kid before raw key, raw spelling before key), and for the tenant–kid and kid–key pairs every
   category of the earlier member (absent, `null`, another type, malformed) appears against a malformed
   later member and a malformed earlier member against every category of the later one. The corpus
   also pins the shortest tenant (one character) and key spellings that decode to a valid key but are
   not its canonical spelling (unused bits set, extra padding, whitespace).

In a vector, an absent member is omitted from `input`. The corpus is synthetic (`tenant-example-N`,
`gate-example-N`, and the console-style tenant `org_00000000-0000-0000-0000-000000000000`, an all-zero
example UUID); its Ed25519 keys are freshly generated public keys with no use outside it, and its
refused keys come from `conformance/vectors/strict-ed25519`. `scripts/gen-gate-pin-vectors.mjs`
generates it (`--check` compares the committed file with its output) and writes only when the
implementation and its own `node:crypto` derivation agree on every vector;
`packages/gate/test/gate-pin.test.ts` recomputes every ACCEPT value without the implementation
(SHA-256 from `node:crypto` over a hand-built JCS text) before comparing the implementation with it.

## 10. Independent-implementation path

The reference Gate's implementation is one. The approver device's implementation is intended as the
second, written from this document and the corpus without reading the Gate's code; both must pass the
same vectors, and the comparison is recorded when it has been made. Until then there is no
independence claim.
