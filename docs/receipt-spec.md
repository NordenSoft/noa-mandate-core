# NOA Receipt — Specification v0.1

### An open, offline-verifiable format for AI-agent action provenance

> **Status:** v0.1 (2026-06-20). Apache-2.0. This is the normative specification for the open
> NOA Receipt protocol.
>
> **What changed from the early draft (after adversarial security review):** signatures
> are now **MANDATORY**, the signing-key identity is **bound into the hash** (key-swap
> defense), **genesis** and **tail-truncation** are defined explicitly, and the
> canonicalization rules are frozen and integer-only. An unsigned hash chain is just a
> checksum — it proves nothing against a party that can write the log — so v0.1 requires
> signatures from the start.

---

## 1. What a NOA Receipt is

A **NOA Receipt** is a signed, hash-chained, append-only record asserting:

> *Agent **A**, acting for principal **P**, attempted action **X** (params hashed to **H**),
> under governance mode **M**; the verdict was **V**; reversible via **R**; and this record
> is link-hashed to the previous one (**prevHash**) and signed by key **kid**.*

One action lifecycle emits one or more receipts (proposed → verdict → executed/blocked/
deferred → approved/rejected → rolled_back). Receipts for one `scope.chain` form a
**hash-chain**: altering any past receipt breaks every later hash.

**What it proves / does not prove (be precise):**
- ✅ Proves: *this exact record was produced under these rules and signed by this key, and
  the sequence has not been edited in the middle.*
- ❌ Does NOT prove: that the real-world action actually succeeded, that it was *wise*, that
  the agent didn't hallucinate the intent, that the recorded operation complied with a recorded
  policy decision (§2, "Independent fields"), or (without a checkpoint, §6) that recent records
  weren't **deleted from the tail**. See [THREAT-MODEL.md](../THREAT-MODEL.md).

---

## 2. Receipt object

Canonicalized per **RFC 8785 (JCS)** — with NOA hardening (§4) — before hashing/signing.

```json
{
  "spec": "noa.receipt/0.1",
  "id": "rcpt_01J...",
  "ts": "2026-06-20T07:30:54.123Z",
  "scope":   { "tenant": "store_or_org", "chain": "chain-partition-key" },
  "agent":   { "id": "agent-handle", "model": "vendor/model|null", "principal": "HUMAN|SERVICE|POLICY|SANDBOX_SIM" },
  "action":  { "id": "payment.refund", "canonical": "payment.refund",
               "riskClass": "LOW|MEDIUM|HIGH|CRITICAL|IRREVERSIBLE",
               "paramsHash": "sha256:…|hmac-sha256:…", "reversible": false, "rollbackRef": "snap_…|null" },
  "governance": { "mode": "off|shadow|approvals_on|on",
                  "verdict": "ALLOWED|BLOCKED|DEFERRED|EXECUTED|FAILED|ROLLED_BACK|SIMULATED",
                  "ruleId": "…|null", "approval": { "by": "…", "at": "…" } , "sandboxed": false },
  "chain":   { "seq": 42, "prevHash": "sha256:…|null", "hash": "sha256:…" },
  "sig":     { "alg": "ed25519", "kid": "noa-key-2026", "value": "base64…" }
}
```

### Field rules

- **Mandatory:** `spec, id, ts, scope.chain, agent.id, agent.principal,
  action.{id,canonical,riskClass,paramsHash,reversible}, governance.{mode,verdict,sandboxed},
  chain.{seq,prevHash,hash}, sig.{alg,kid,value}`.
- **Unknown fields are REJECTED** at every level (`additionalProperties:false`). This is a
  security control: it closes the "smuggle PII / data in an unrecognized field" channel and
  keeps the hashed surface exactly the documented surface.
- **PII-free producer obligation** (the format cannot enforce this — see THREAT-MODEL T9):
  producers MUST NOT embed raw params, customer data, secrets, or free text — only `paramsHash`
  and enum/id fields. Unknown fields are rejected, but PII placed in a known opaque field is not.
- **Integer-only:** all numbers are JSON integers in the safe range. Floats/exponents are
  rejected (removes number-serialization ambiguity entirely).
- **`id` is unique within its chain (producer obligation).** Every receipt in one `scope.chain`
  MUST carry a distinct `id`. Ids are compared as exact strings after JSON parsing: there is no
  Unicode normalization and no case folding, so `rcpt_A` and `rcpt_a` are different ids, and so are
  the NFC and NFD spellings of the same visible text (the JSON strings `"café"` and
  `"café"`; an NFD `id`
  already breaks the NFC rule of §4), while a JSON escape such as `e` spells the same id as the
  character it encodes. Producers SHOULD make ids globally unique, for example with a sortable
  ULID- or UUIDv7-style value. A verifier of this version reports a repeated `id` as the warning
  `duplicate-id` and never rejects the chain for it (§5).
- **`paramsHash`** is `sha256:<hex>` or, recommended for low-entropy params,
  `hmac-sha256:<hex>` with a tenant-scoped key (plain SHA-256 of an amount/id/bool is
  brute-forceable and identical across tenants → correlation; see THREAT-MODEL §params).
- **`ts` and `approval.at` MUST pass the real-instant range rule**, not merely match the RFC 3339
  shape: month `01`-`12`; day within the real length of that month in that year (leap years
  included); hour ≤ `23`; minute ≤ `59`; second ≤ `60`; offset ≤ `23:59`.
  `2026-13-45T99:99:99.000Z` matches the pattern and is **`MALFORMED`**. Fractional seconds are
  optional; when present they are **1 to 9 ASCII digits** (nanosecond precision at most), so
  `2026-06-20T07:30:54.1234567890Z`, valid RFC 3339, is **`MALFORMED`** here (the schema's `pattern`
  states the same bound).
- **Second `60` is ACCEPTED by the range rule, in any minute and at any offset** — a leap second is
  a real instant, and refusing one would refuse a truthful receipt. Which UTC minutes really carried
  one is an IERS table, not a property of the string, so the rule does **not** establish that a given
  second `60` was a real leap second: `2026-06-20T07:45:60Z` passes it although no leap second falls
  there. That needs external evidence. A stricter rule (for example, second `60` only at `23:59` UTC
  on the last day of a month) would refuse inputs this version accepts, so it can only come with a
  later format version.

### Coherence rules (cross-field)

Every rule above reads ONE field. A receipt can satisfy all of them and still be a statement that
argues both ways — `agent.principal: "SANDBOX_SIM"` (the actor was the sandbox simulator) beside
`governance.sandboxed: false` (this really happened), on a `CRITICAL` transfer, signed and
chain-valid. A verifier MUST reject these as **`MALFORMED`**:

| | Rule |
|---|---|
| **R1** | `agent.principal == "SANDBOX_SIM"` REQUIRES `governance.sandboxed == true` |
| **R2** | `governance.verdict == "SIMULATED"` REQUIRES `governance.sandboxed == true` |
| **R3** | `action.reversible == false` REQUIRES `action.rollbackRef` absent or `null` |
| **R4** | `governance.verdict == "ROLLED_BACK"` REQUIRES `action.reversible == true` |

Each is **one-directional**, and the converse is legitimate: a `SERVICE` agent may run inside a
sandbox (`sandboxed: true` with any principal is valid), and a reversible action need not carry a
`rollbackRef`.

These are decidable **with no key material at all** — a reader holding only the bytes can see the
contradiction — which is why they belong beside the unknown-field rule rather than in the signature
path. The same placement means a conformant *producer* cannot sign one either. R1-R4 are encoded in
[`schema/noa-receipt-0.1.schema.json`](../schema/noa-receipt-0.1.schema.json) `allOf`; the
real-instant rule above is **not** expressible in JSON Schema and is enforced only by the normative
validators. Pinned by `conformance/vectors/attack/coherence-*.json` (reject) and
`conformance/vectors/coherence-*.json` + `conformance/vectors/ts-leap-second.json` (must stay valid).

### Independent fields (what R1-R4 deliberately do not couple)

R1-R4 are the only cross-field rules of structural validation (§5 step 1). The chain checks of §5
(steps 2-7) also read several fields, within one receipt and across consecutive receipts, but none of
them relates the two fields of a pair below. The pairs below are independent by design: a verifier
MUST NOT reject a receipt because of how they combine, and a reader MUST NOT infer one field from the
other.

- **`action.riskClass` and `action.reversible`.** `riskClass` is an authorization-risk tier — how
  much scrutiny the action needs before it may run, a tier a policy may raise. `reversible` (with
  `rollbackRef`) carries the undo-capability claim. `riskClass: "IRREVERSIBLE"` beside
  `reversible: true` is accepted as written; reversibility is read from `reversible` only.
- **`governance.mode` and `governance.verdict` / `governance.approval`.** The mode labels the
  producer's enforcement mode. It does not establish that approval evidence is carried inline — a
  receipt under `approvals_on` may record `EXECUTED` with `approval: null`, the approval being
  evidenced outside the receipt — and it prescribes no further verdict combinations: `BLOCKED` under
  `off` or `shadow` is accepted as written.
- **`governance.compliance.verdict` and `governance.verdict`.** The first records the policy decision
  (`ALLOW` / `DENY`, §9); the second records the operational outcome. A receipt may truthfully record
  `EXECUTED` beside `DENY` — an execution despite a policy denial is evidence worth keeping. `VALID`
  means the bytes are intact, linked and signed by trusted keys; it never means the recorded
  operation complied with the recorded policy.
- **`governance.approval.at` and `ts`.** They may come from different clocks, and this version
  defines no common clock or required order between them. A verifier MUST NOT reject a receipt as an
  integrity failure because `approval.at` is later than `ts`; it MAY report it as a chronology
  warning. This version defines no stable code for such a warning, so none of the five verifiers in
  this repository reports one; a later revision may define a code.

Pinned by `conformance/vectors/independent-fields/`: genuine chains carrying each combination above,
which every verifier must accept as `VALID` with the keyring and without a timestamp-order warning.

### Hashing rule (frozen)

```
hash = sha256( JCS( receipt WITHOUT chain.hash AND WITHOUT sig.value ) )
```

`sig.alg` and `sig.kid` **are inside** the hashed bytes. Therefore an attacker cannot strip
the signature, swap to another key, and re-sign: changing `sig.kid` changes the hash, which
breaks linkage. `chain.hash = "sha256:" + hash`.

The **signature** is Ed25519 over a **domain-separated preimage**, not the bare digest:

```
sig.value = Ed25519_sign( privkey,  "NOA-Receipt-v0.1-sig:" ++ sha256(JCS(receipt \ chain.hash \ sig.value)) )
```

The domain tag (`NOA-Checkpoint-v0.1-sig:` for checkpoints) prevents cross-protocol signature
reuse — a signature over a 32-byte value in another context can never be replayed as a receipt
signature. Well-formed Unicode is required: **unpaired UTF-16 surrogates are rejected** (they
would collapse to U+FFFD at the UTF-8 hashing step, a forgery channel).

---

## 3. Hash-chain & key-pinning

For each `scope.chain`, receipts form an append-only chain:

```
R0(seq=0, prevHash=null) -> R1(prevHash=H(R0)) -> R2(prevHash=H(R1)) -> …
```

- **Genesis** is `seq == 0` with `prevHash == null`. A non-null genesis prevHash is rejected.
  The genesis receipt is signed; obtain its key out-of-band (the keyring is the trust root).
- **Key-pinning (continuity):** the first receipt for a given `agent.id` pins its `sig.kid`. A
  later receipt for the same `agent.id` under a **different** `kid` is rejected — a mid-chain key
  swap cannot pass even if the attacker holds a valid keypair. (Pinning is per `agent.id`; one
  `kid` MAY be shared across multiple `agent.id`s by design. This is key *continuity* — identity
  authenticity comes from the out-of-band keyring, not from first-sight.)
- Editing any `Ri` changes `H(Ri)` → mismatches `R(i+1).prevHash`. **Tamper-evident.**

---

## 4. Canonicalization (NOA-hardened JCS)

RFC 8785 with these frozen, test-pinned rules (see `conformance/`):

1. Object keys sorted by UTF-16 code units.
2. No whitespace.
3. Strings: escape `" \ \b \f \n \r \t` and control chars `< U+0020` as `\u00XX`; **all other
   code points emitted literally as UTF-8** (no `\u` escaping of non-control chars, **no
   Unicode normalization** — inputs MUST already be NFC).
4. Numbers: **integers only**, safe range; `-0` serializes as `0`; floats/NaN/Infinity/bigint
   rejected.
5. On parse (verifier side): **duplicate object keys are rejected** (no silent last-wins);
   `__proto__`/`constructor`/`prototype` keys rejected; depth and size bounded.

Conformance test vectors pin the exact bytes so a Rust producer and a TypeScript verifier
cannot disagree.

---

## 5. Verification (the open verifier)

Anyone — operator, auditor, receiving service, regulator — verifies a chain **offline**, no
NOA service, via `noa verify` (or the library `verifyChain`):

The default native verifier checks parsed receipt values. VALID means that the receipt structure, derived hashes, chain linkage, signatures and applicable supplied trust checks passed. It does not attest that the received JSON file was already canonically encoded. Whitespace, member order and equivalent JSON string escapes may differ without changing this verdict. VALID does not by itself establish the truth of recorded claims or successful execution of an action.

```
verify(receipts, { keyring?, checkpoint?, identityManifest? }):
  1. structural validate each receipt (strict; reject unknown fields;   -> else MALFORMED
     enforce the §2 coherence rules R1-R4 and the real-instant `ts` rule
     — all decidable with no key material)
  2. single chain partition; seqs contiguous 0..n-1, unique             -> else TAMPERED
  2b. tenant consistency, in seq order: every PRESENT scope.tenant      -> else TAMPERED
      equals the last present one; absence is allowed and never resets the comparison
  for each receipt in seq order:
  3. recompute hash = sha256(JCS(receipt \ chain.hash \ sig.value)); assert == chain.hash
  4. pin sig.kid per agent.id (reject mid-chain key swap)
  5. signatures, by keyring state:
       - keyring supplied AND kid known   -> ed25519_verify over the domain-separated preimage
                                             (curve-PINNED: a non-Ed25519 key is rejected, no alg-confusion)
       - keyring supplied AND kid UNKNOWN -> TAMPERED (no silent TOFU on attacker input)
       - no keyring at all                -> UNVERIFIED (cannot authenticate; never VALID)
       - lifecycle keyring AND kid RETIRED -> verify with the retained public key first: a bad
                                             signature is TAMPERED; an authentic one is remembered
                                             and the walk CONTINUES (it never becomes VALID)
  5b. identity binding (only if identityManifest supplied):
       - (agent.id, sig.kid) authorized in the manifest -> ok
       - else                                           -> UNTRUSTED (cross-agent impersonation:
                                                           authenticated key, but NOT authorized for
                                                           this agent.id). No manifest => kid-level
                                                           attribution + an explicit warning.
  6. linkage: seq 0 => prevHash null; else prevHash == prev.hash && seq == prev.seq+1
  6b. timestamp order (a WARNING, never a verdict): ts vs the previous receipt's ts at full
       precision after offset normalization -> ts-backwards / ts-not-comparable (see below)
  6c. id uniqueness (a WARNING, never a verdict): id equal to the id of a receipt with a lower
       seq, as exact strings after JSON parsing -> duplicate-id (see below); for one seq it
       follows that seq's 6b warning
  7. if checkpoint: assert head matches checkpoint (tail-truncation); and (if identityManifest
       supplied) the checkpoint sig.kid MUST be authorized for the GENESIS agent.id (the chain
       OPENER, seq 0) — NOT the mutable head — else UNTRUSTED (closes the re-heading attack); warn
       when the chain has >1 agent.id (opener-scoped completeness). A checkpoint whose kid is
       lifecycle-RETIRED is authenticated with the retained public key like step 5
  8. if every check above passed but step 5 or 7 remembered an authentic retired-key signature
       -> KEY_RETIRED (refused for current use; the first such signature is reported)
  -> VALID | UNVERIFIED | UNTRUSTED | TAMPERED | MALFORMED | KEY_RETIRED
```

CLI exit codes: `0` VALID · `1` UNVERIFIED (no keyring supplied) · `2` TAMPERED · `3` MALFORMED
· `4` usage · `5` UNTRUSTED (identity binding failed) · `9` KEY_RETIRED. **CI rule: treat any non-zero exit as failure** (do not special-case `==2`). Honest
by design: without a keyring, signatures are reported UNVERIFIED, never VALID; without a
checkpoint, the reference verifier emits an explicit tail-truncation warning; and it always emits a
fork/equivocation caveat (an offline verifier sees only the branch it was given). Every verifier
reports the timestamp-order warnings and the duplicate-id warning (see "Timestamp-order warnings"
and "Duplicate-id warning" below).

### Optional strict-bytes profile (`--profile strict-bytes`)

The optional strict-bytes profile is selected with --profile strict-bytes. Its byte-entry APIs accept original UTF-8 input bytes. For a chain file, the comparison unit is the complete JSON array in presented order, including every receipt member. After strict parsing and before receipt verification, the verifier MUST require the original bytes to equal the UTF-8 JCS serialization of that array. It MUST NOT strip a BOM, trim whitespace, translate line endings, normalize strings, reorder array elements or repair the input. A byte mismatch returns MALFORMED, exit 3, with discriminator NON_CANONICAL_BYTES. Equality permits ordinary verification to continue; it does not establish signature validity. This profile applies to current-use bare-chain verification and does not impose canonical encoding on auxiliary files.

The profile adds no verdict and no exit code: `NON_CANONICAL_BYTES` leads the TypeScript `reason` and the
`detail` of the Python, Go, Rust and C# verifiers. Omitting `--profile`, or `--profile native`, is the
default run above, unchanged. A missing, unknown or repeated `--profile`, or `--profile strict-bytes`
combined with `--purpose historical` or the witness flags, is a usage error (exit `4`); an API profile
value outside `native | strict-bytes` is `MALFORMED`. The comparison is not `receiptHashInput`, which
omits `chain.hash` and `sig.value`; it covers every byte of the file. The shared vectors are
`conformance/vectors/strict-bytes/` (authored expectations in its `manifest.json`).

**Tenant consistency (step 2b).** `scope.tenant` is optional, but within one `scope.chain` every
present value MUST equal the last present one in `seq` order; a different present value is a
cross-tenant splice and the chain is `TAMPERED`. An absent value is allowed and never resets the
comparison, so `acme -> absent -> globex` is refused exactly like `acme -> globex`, while
`acme -> absent -> acme` and `absent -> acme` stay valid. Pinned by
`conformance/vectors/attack/tenant-splice-via-absent*.json` and `conformance/vectors/tenant-*.json`.
Separately from this rule, the reference library offers `requireTenantConsistency: false`, which
reports the drift as a `tenant-drift:` warning instead of refusing; the CLIs and the other four
verifiers always apply step 2b.

**Timestamp-order warnings (stable codes).** For each receipt after the first, in `seq` order, a
verifier compares its `ts` with the previous receipt's `ts` at full precision — every fractional
digit, to the nanosecond — after normalizing both offsets to UTC. A millisecond clock, or a parser
that refuses second `60`, cannot do this. The result is a warning, never a verdict: it changes no
status and no accepted input. A second `60`, which the range rule (§2) admits in any minute, has two
readings: a leap second, after second `59` of its own minute, or an overflow, second `00` of the
next minute. Without a second `60` the two readings are the same comparison. Every conformant
verifier uses exactly these two codes:

- `ts-backwards: seq N` — under both readings, the `ts` of the receipt at `seq` N is strictly earlier
  than that of `seq` N-1.
- `ts-not-comparable: seq N` — exactly one reading puts it strictly earlier, so the bytes cannot
  order the pair: `10:01:00.1Z` then `10:00:60.5Z`, or `10:01:00Z` then `10:00:60Z`.

Otherwise the pair gets no warning: equal instants, however spelled, get none, and neither does a
pair that one reading puts later and the other makes equal (`10:00:60Z` then `10:01:00Z`). An
accepted timestamp is never skipped without a report.

`ts-not-comparable` says that the bytes cannot order the pair, not that a clock is wrong. A
correctly ordered pair across a real leap second can receive it: `2016-12-31T23:59:60.5Z` then
`2017-01-01T00:00:00.2Z` is in order as a leap second and backwards as an overflow.

**Duplicate-id warning (stable code).** For each receipt, in `seq` order, a verifier compares its
`id` with the ids of every receipt of a lower `seq` in the chain, as exact strings after JSON
parsing (§2: no Unicode normalization, case-sensitive). Every conformant verifier uses exactly this
code:

- `duplicate-id: seq N` — the `id` of the receipt at `seq` N equals the `id` of a receipt with a
  lower `seq`. The first receipt that carries an `id` gets no warning and every later one gets one,
  so an `id` held at `seq` 0, 2 and 3 yields `duplicate-id: seq 2`, then `duplicate-id: seq 3`,
  whatever the order of the receipts in the input array.

The result is a warning, never a verdict: it changes no status and no accepted input. When one
receipt receives both a timestamp-order code and `duplicate-id`, the timestamp-order code comes
first (`ts-backwards: seq 1`, then `duplicate-id: seq 1`), so the stable codes of a run are ordered
by `seq` and, within one `seq`, step 6b before step 6c. A repeated `id` is not evidence of
tampering: every receipt is still hashed, signed and linked. It records that the producer broke the
§2 obligation, and a consumer that keys receipts by `id` cannot rely on one `id` naming one receipt
unless the run reported no `duplicate-id`.

**Compatibility (duplicate ids).** A `noa.receipt/0.1` verifier MUST NOT reject a chain because two
of its receipts carry the same `id`. This version has accepted such chains, so a stricter rule would
refuse inputs this version accepts; it can only come with a later format version, which may make a
repeated `id` a rejection.

The reference library returns the codes in `warnings`; every CLI prints them, in `seq` order, in the
`warnings` array of its JSON result, which the Python, Go, Rust and C# CLIs add only when it is
non-empty. These three codes (`ts-backwards`, `ts-not-comparable`, `duplicate-id`) are the only
warnings that every verifier reports in the same form. Other warnings differ between
implementations: only the reference reports the tail-truncation and fork/equivocation caveats and a
non-NFC string in `warnings`, and the Go and Rust verifiers do not report the opener-scoped
checkpoint caveat. A consumer that compares verifiers compares these three codes only. Pinned for all
five verifiers by `conformance/vectors/ts-order/` and `conformance/vectors/duplicate-id/`.

**Retired keys (optional lifecycle trust root).** The static keyring above has no notion of
retirement. A verifier that also accepts the `noa.signing-key-lifecycle/0.1` trust root (the
reference verifier does) MUST refuse every non-null `retiredAt` for current use, and MUST
authenticate the signature against the retired key's retained public material before it decides
how to refuse. A signature that does not authenticate is `TAMPERED`, exactly as with a current key.
An authentic one is `KEY_RETIRED`, reported only when every other check passes, so it can never
stand in for a hash, signature, linkage, identity or checkpoint failure. `KEY_RETIRED` is not an
acceptance: the signer-chosen `ts` is not evidence of when the signature was made, so the result
does not establish that the receipt predates retirement. Attribution of such a receipt is the job
of the separate `noa.historical-verification/0.1` purpose, which requires an independently trusted
checkpoint. The reference verifier's `KEY_RETIRED` result carries a `key-retired:` warning that
names that purpose; no other status carries it.

**Public-key strictness (interop-normative).** A conformant verifier MUST apply strict public-key
validation to the Ed25519 public key `A` at key load, from the key bytes alone and before signature
verification: it refuses non-canonical and small-order key encodings (RFC 8032 §5.1.3 decoding +
small-order rejection). It **MUST reject** a key whose `y` coordinate is not canonical (`y ≥ q`), whose
`y` does not decode to a curve point, whose `x = 0` carries a set sign bit (RFC 8032 §5.1.3 step 4),
whose point lies in the torsion subgroup of order dividing 8 (any of the 8 points, in any spelling), or
whose point is not in the prime-order subgroup (`[L]A` is not the identity: a mixed-order key). A
refused key authenticates nothing: every receipt or checkpoint under it is `TAMPERED`. Which encodings a
library admits as a public key differs between libraries and versions (e.g. OpenSSL), so the rule is
enforced by the verifier itself; a legitimate signing key always passes it, so it rejects no genuine key.

**Signature strictness (interop-normative).** The signature's `R` **MUST** be canonically encoded (the
decoding steps above) and **MUST NOT** be one of the 8 small-order points; `S` **MUST** be canonical
(`S < L`). A verifier **MUST** evaluate the cofactorless equation `[S]B = R + [k]A` with
`k = SHA-512(R ‖ A ‖ M)` reduced mod `L`, over the signature's own `R` bytes. With a prime-order `A` and
this equation, no `R` outside the prime-order subgroup can verify; a verifier whose library evaluates
the cofactored equation instead MUST also require `R` in the prime-order subgroup, which yields the
same verdict. This is the pin for cross-impl agreement — **not** ZIP-215 semantics. The shared
conformance corpus (`conformance/vectors/strict-ed25519/`) pins the key vectors for all five verifiers.

---

## 6. Tail-truncation & checkpoints

`prevHash` catches mid-chain edits but **not** deletion of the most-recent receipts (an
attacker drops the tail; the prefix still validates). A signed **checkpoint** closes this:

```json
{ "spec": "noa.checkpoint/0.1", "chain": "…", "highestSeq": 42, "headHash": "sha256:…",
  "ts": "…", "sig": { "alg": "ed25519", "kid": "…", "value": "base64…" } }
```

A verifier given a checkpoint asserts the chain head equals `{highestSeq, headHash}` →
truncation/extension is detected. **The checkpoint signature is held to the same trust root as
receipts**: with a keyring supplied, a checkpoint signed by an unknown `kid` (or with a bad
signature) is `TAMPERED`, and `tailChecked` is set true **only** for an authenticated
checkpoint — otherwise an attacker could drop the tail and forge a checkpoint over the
truncated head with their own key. **Identity-bound (when an `identityManifest` is supplied):**
the checkpoint is authorized by the chain **OPENER** — its `sig.kid` MUST be authorized for the
**GENESIS** receipt's `agent.id` (the `seq == 0` receipt that opened the chain), else `UNTRUSTED`.
**The authority is the opener, NOT the mutable head** — this is deliberate: a `scope.chain` is a
*shared* partition with no opener/ownership binding, so any co-trusted key holder can APPEND its own
receipt onto a victim's prefix, become the head, drop the victim's tail, and forge a checkpoint over
its OWN head (the **re-heading** attack). Binding to the head would then check the
attacker's checkpoint against the attacker's OWN authorized `agent.id` → `VALID` while the victim's
tail is erased. The opener cannot be re-written by an appended tail, so genesis-binding rejects the
re-heading checkpoint as `UNTRUSTED` and strictly subsumes the legitimate opener-checkpoint case
(when the opener also heads, genesis == head). **Multi-agent caveat:** the checkpoint completeness it
proves is *opener-scoped*. When this check runs (a keyring, an `identityManifest` and a checkpoint are
supplied, and the checkpoint passes) and the chain holds more than one distinct `agent.id`, the
reference, Python and C# verifiers **warn** that a co-agent's tail is not separately certified by the
opener's checkpoint; the Go and Rust verifiers do not report this caveat (§5). **Residual (needs the
v1.0 external anchor):** the opener itself dropping a co-agent's tail, and the no-`identityManifest`
case (kid-level only — any keyring-trusted key can forge a checkpoint over any head). Without a
checkpoint, only the reference verifier **warns** that tail-truncation is undetectable offline; the
Python, Go, Rust and C# verifiers do not report it (§5). Stronger completeness claims need separately
trusted, externally obtained evidence; this specification does not provide it.

---

## 7. Current scope and non-goals

- **v0.1:** format + hardened JCS + mandatory Ed25519 + key-pinning + offline verifier
  + checkpoints + JSON-Schema + conformance suite.
- **Future revisions:** require their own normative text, compatibility rules, vectors, and release
  evidence. This document does not commit an implementation or governance roadmap.
- **Non-goals:** does NOT detect hallucination; does NOT undo irreversible real-world
  effects (it *gates before* them); does NOT replace your model or your framework.

---

*Reference implementation + conformance vectors: this repository (`src/`, `conformance/`).
Companion: [README](../README.md) · [THREAT-MODEL](../THREAT-MODEL.md) · [SECURITY](../SECURITY.md).*

---

## 8. The universal envelope — COSE_Sign1 / SCITT profile

A NOA Receipt is also expressible as a **COSE_Sign1** (RFC 9052) so it verifies in **any** conforming
COSE implementation — every language, hardware (TPM/FIDO), cloud KMS, RATS/EAT — **without NOA's code**.
That is what makes it universal rather than bespoke.

- **Algorithm:** Ed25519 (COSE alg `-19`, RFC 9864). The protected header alg (label `1`) MUST be `-19`;
  a verifier MUST reject any other `alg` to prevent algorithm confusion. We use the curve-specific `-19`
  rather than the generic EdDSA (`-8`, RFC 9053, deprecated Oct-2025): `-8` also admits Ed448, so pinning
  `-19` closes the Ed448 algorithm-confusion surface at the alg-id layer (complementing the node:crypto
  curve-type key pin). NOA *issues* the two-member protected header `{1: -19, 4: kid}` — CBOR leading
  bytes `a2 01 32 04 …`, the `…` being the kid byte string, so the header's length follows the kid's. On the
  *verify* side, per RFC 9052 §3.1, additional registered/non-critical protected headers (e.g. `kid`,
  `content type`, `CWT_Claims`) are accepted and any unknown header NOT listed in `crit` (label `2`) is
  ignored — so a draft-conformant peer that carries `kid`/`crit`/extra headers in the protected bucket
  still verifies; only the `alg` pin and `crit`-processability are enforced (a critical header the
  verifier cannot process is rejected, fail-closed).
- **kid:** NOA *emits* `kid` (label `4`) in the **protected** (signed) header, so the signature covers
  the emitter's identifier and it cannot be swapped for a same-length victim kid; the unprotected
  bucket is emitted empty. A verifier resolves the kid against its keyring from EITHER bucket,
  preferring the protected (signed) copy when present. An outer kid taken from the *unprotected*
  bucket MAY resolve a key and MUST NOT be reported as an identity.
- **TWO SIGNATURES, TWO CLAIMS (normative MUST — draft §6):** an enveloped receipt carries two
  identifiers and they answer different questions. The **native** `sig.kid` inside the payload
  attributes the **agent**: it is the key that signed the receipt into its chain and the identifier
  `agent.id` makes a claim about. The **outer** COSE kid attributes the party that **emitted the
  envelope** — an issuer submitting its own receipt, or a relay presenting someone else's. A verifier
  supplied an identity manifest MUST check it against the **native** `sig.kid`; MUST NOT let an
  authorized outer kid satisfy the agent check (an envelope signed by a key that happens to be
  authorized for `agent.id` says nothing about who signed the receipt inside it); MUST NOT reject a
  receipt solely because its outer signer is not one of the agent's keys (a relay is a legitimate
  presentation); and MUST report the two results separately. This profile defines no authorization
  list for the emitter: the manifest binds agents to keys, not envelopes to emitters.
  `receiptFromCose` therefore verifies **both** signatures — `ok:true` never means one of the two —
  and returns `nativeKid`/`agentClaim` beside `envelopeKid`/`envelopeClaim`. Vectors for both
  directions: `conformance/cose-attribution/vectors.json`.
- **Payload:** the JCS-canonical NOA receipt bytes (§2/§4). So a standard COSE verify authenticates the
  receipt; a NOA-native consumer then parses the payload and runs the hash-chain / policy checks (§3–§6).
- **Sig_structure:** the RFC 9052 `["Signature1", protected, external_aad(empty), payload]`, Ed25519-signed.
- **CBOR:** core-deterministic (RFC 8949 §4.2) — shortest-form heads, map keys sorted by encoded bytes.

**SCITT:** the same COSE_Sign1 is a **SCITT Signed Statement**. Registering it in a SCITT transparency
log yields a registration **receipt** + an append-only, witness-cosigned anchor — which supplies the
external non-equivocation / tail-truncation defense the self-signed hash-chain (§6) cannot give alone.

**Conformance:** NOA ships its own zero-dependency COSE_Sign1 producer/verifier. The conformance suite
also checks its output with off-the-shelf CBOR and Ed25519 libraries. This demonstrates compatibility
for the covered vectors; it does not prove universal interoperability or organizational independence.

---

## 9. L2 policy-compliance (optional, on-receipt)

A receipt MAY commit an `governance.compliance` block binding the decision to the exact policy + the
exact recorded inputs WITHOUT carrying raw inputs (which may be PII) — only their hashes:

```
"governance": { …, "compliance": {
  "policyHash":   "sha256:…",   // JCS-canonical policy identity
  "readSetHash":  "sha256:…",   // the policy's closed input read-set
  "inputsHash":   "sha256:…",   // JCS-canonical recorded decision inputs (hash only — no raw PII)
  "verdict":      "ALLOW|DENY"  // OPTIONAL: the recorded decision (re-run at commit time)
}}
```

`verifyReceiptCompliance(receipt, policy, inputs)` is the OFFLINE L2 proof: given the policy + the
recorded inputs out-of-band, it confirms the three committed hashes authenticate exactly that policy +
those inputs, then **re-runs the deterministic evaluator** to reproduce the verdict. When the commitment
also records a `verdict`, the verifier **REQUIRES the re-run verdict to equal the recorded one** — so a
receipt that commits inputs evaluating to DENY while recording ALLOW is rejected (`ok:false`). It is
fail-closed (any hash mismatch / verdict mismatch / non-canonicalizable input ⇒ `ok:false`) and never
throws. A substituted policy (policyHash mismatch — anti policy-swap) or substituted inputs (inputsHash
mismatch) is rejected. The `verdict` field is OPTIONAL and additive: a commitment without it stays
backward-compatible (no reconciliation; the verifier just returns the re-run verdict).

**CARRIER AUTHENTICITY (normative MUST):** the L2 check operates on the receipt's `governance.compliance`
block, which is attacker-mutable on a NON-authentic receipt — so by itself it does NOT establish that the
receipt is genuine. A verifier MUST authenticate the carrier before trusting an L2 `ok:true`, by EITHER
passing the keyring to `verifyReceiptCompliance(receipt, policy, inputs, { keyring })` (it then verifies the
carrier's own `chain.hash` + Ed25519 signature first; a non-authentic carrier ⇒ `ok:false`) OR calling
`verifyChain([...], { keyring })` and requiring `VALID` first. Reporting "compliant" off an un-authenticated
carrier is a conformance violation.

**ATTRIBUTION — KID-LEVEL vs AGENT-LEVEL:** `{ keyring }` carrier-auth is *kid-level* — it
proves "a keyring-trusted key signed this carrier", NOT "THIS `agent.id` signed it". In a multi-key keyring a
co-trusted key can sign a receipt claiming `agent.id=victim` and still pass carrier-auth, which is exactly the
cross-agent impersonation `verifyChain` rejects as `UNTRUSTED` *only* when also given an identityManifest. To
bind WHICH agent, pass `verifyReceiptCompliance(receipt, policy, inputs, { keyring, identityManifest })`: after
carrier-auth, an unauthorized `(agent.id, sig.kid)` pairing ⇒ `ok:false` (mirroring verify.ts §5 / the
`UNTRUSTED` verdict). Without an identityManifest, L2 attribution stays kid-level.

**Honesty razor (normative):** this proves *"policy P, re-run over the RECORDED inputs I, yields verdict
V, and V equals the decision the receipt recorded, on an authenticated carrier"* — it is
substitution-resistant (a receipt cannot commit DENY-inputs while claiming ALLOW), but it is NOT proof the
policy was in force at decision time, nor that I is true or complete, nor that P is a *good* rule, nor that
the recorded inputs reflect external ground truth (the oracle/input-authenticity limit — a lying agent can
emit a fully-valid receipt over inputs it fabricated). Carrier-auth via `{ keyring }` alone is *kid-level*:
it does NOT prove THIS `agent.id` signed — pass `{ keyring, identityManifest }` to bind the signer to the
agent (see "ATTRIBUTION" above). The reference policy DSL is integer-only / pure-logic; policies using
non-deterministic elements are out of scope for replay.
