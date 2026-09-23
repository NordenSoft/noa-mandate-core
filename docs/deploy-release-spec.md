# `noa.deploy.release/1` — the deployment action bind

Status: **IMPLEMENTED** (`src/deploy-release.ts`), conformance corpus at
[`conformance/deploy-release/vectors.json`](../conformance/deploy-release/vectors.json).

This document is written so an independent implementer can build a conforming producer and verifier
from it alone. Every constant, every byte order and every refusal rule is stated here; nothing is
left to "see the TypeScript".

---

## 1. What problem this value solves

A receipt for a deployment carries `action.paramsHash` — the producer's parameter-set commitment.
`noa.receipt/0.1` deliberately says nothing about what that hash is computed over: `paramsHash` is
defined as *the producer's* commitment, and the kernel's own invariants forbid reinterpreting it as
a universal cross-producer digest (ADR-R-004 in `03_DECISIONS_ADR.md`).

That is correct for the general case and insufficient for one specific, high-consequence case. When
the governed action is a **deployment**, a relying party is handed a receipt and, separately, a
description of the release it supposedly authorized — a repository, a commit, an environment, an
image digest, a target account, and whether this was a deploy or a rollback. Without a published
rule for turning those six values into `paramsHash`, that party can only COMPARE the hash to one it
was given; it cannot RECOMPUTE it. So it cannot answer the only question that matters:

> Is this disclosed deployment tuple the tuple that receipt actually bound?

`noa.deploy.release/1` is that rule. It fixes the field set, the validation, the canonicalization
and the digest, so that two independent implementations handed the same deployment compute the same
`paramsHash`, byte for byte — and any party holding a DIFFERENT deployment computes a different one.

It also fixes the **display projection**: the human-readable rendering an approver sees. A digest
nobody can read is not verified context, so the rendering is part of the wire contract rather than
each implementation's private business.

---

## 2. The bound parameter set

Exactly six members. All are REQUIRED. No other member is permitted.

| Member | Type | Rule |
|---|---|---|
| `repository` | string | 1–256 characters from the identifier charset (§2.1) |
| `commit` | string | exactly **40 lowercase hex** characters |
| `environment` | string | 1–256 characters from the identifier charset |
| `imageDigest` | string | `sha256:` followed by exactly **64 lowercase hex** characters |
| `targetAccount` | string | 1–256 characters from the identifier charset |
| `operation` | string | exactly one of `deploy`, `rollback` |

### 2.1 The identifier charset

```
A-Z  a-z  0-9  .  _  -  :  @  +  /
```

Nothing else. In particular **no whitespace and no control characters**, and this is a
display-integrity rule rather than tidiness: §4's `Release` row joins three bound values into one
line, and a repository containing a space or a newline would make that join ambiguous — two
different bound tuples could render identically to the approver. Refusing the characters keeps the
join injective by construction instead of relying on every renderer to escape them.

Lengths are counted in UTF-16 code units, consistent with the charset being ASCII-only: every
permitted character is one unit, so code units and code points coincide and the distinction cannot
change a verdict.

### 2.2 Why these six, and why not more

Each of the six is a value that, if changed, makes it a DIFFERENT deployment: a different source
(`repository`), a different revision (`commit`), a different blast radius (`environment`,
`targetAccount`), a different artifact (`imageDigest`), or a different direction (`operation`).
Binding fewer would let two materially different deployments share one commitment.

Deliberately NOT bound here, because they are properties of the AUTHORIZATION rather than of the
action: approval set, time window, use count, policy revision, credential audience, executor
identity. Those live on the grant and the envelope. Copying them into the action parameters would
create a second, caller-supplied copy of a value the authorization layer already carries — and two
copies of one fact is how the two planes come to disagree.

### 2.3 Case is REFUSED, never normalized

`commit` and `imageDigest` must be lowercase. An uppercase spelling is a refusal, not an input to
normalize. The reason is that an equivalence class is an attacker's choice of representative: if
`A1B2…` were lowercased and accepted, ONE deployment would have TWO valid spellings, a grant bound
to one would not match a re-derivation from the other, and the normalizer itself would be new
attack surface inside the trusted computing base whose bugs are digest forgeries.

For the same reason `imageDigest` must be an immutable content digest. A mutable tag (`latest`)
is refused: the approved artifact must not be "whatever the registry says tomorrow".

---

## 3. The digest (normative)

```
canonical  = JCS(params)                                  RFC 8785, over the six members
paramsHash = "sha256:" ++ lowerhex( SHA-256( UTF8( canonical ) ) )
```

There is **no domain-separation tag**. This is deliberate and is the one place this construction
differs from every other digest in this repository: `paramsHash` must reproduce a value that
producers already compute over the parameter object itself, so a tag would make the public rule
disagree with the thing it exists to let people check. (Contrast `noa.action-digest/0.1`, which is a
NEW value and therefore carries `NOA-ActionDigest-v0.1-dig`.) Nothing signs `paramsHash` directly;
it is bound INTO documents that are signed under their own tags.

JCS sorts members by UTF-16 code unit, so the digest is a property of the DEPLOYMENT and not of the
order a caller happened to serialize it in. Two honest producers describing one release must not
produce two grants.

### 3.1 The JSON dialect

Input is BYTES. The parser is strict and identical to the rest of the kernel:

- duplicate object keys are **rejected** (not last-wins);
- the keys `__proto__`, `prototype` and `constructor` are **rejected outright**;
- numbers must be integers within the safe-integer range;
- input must decode as UTF-8 with no BOM tolerance beyond the kernel's rule;
- the document byte ceiling is `MAX_INPUT_BYTES` (16 MiB) and nesting depth is 64.

A conforming implementation MUST refuse a document that a permissive parser would silently repair.
A duplicate `commit` member is the sharpest case: last-wins parsing lets the value an approver reads
and the value a producer binds differ by construction.

---

## 4. The display projection (normative)

```
Action      = "noa.deploy.release"
Release     = operation ++ " " ++ repository ++ "@" ++ commit
Environment = environment
Target      = targetAccount
Image       = imageDigest
```

Five rows, and **every bound member is visible in them**. A conforming renderer MUST NOT show an
approver a bound value that is absent from this rendering, and MUST NOT show a value that is not
bound.

**The `Release` join is injective, parsed from the RIGHT.** Read left to right it would not be: `@`
is a member of the identifier charset, so `repository` may legitimately contain one and the first
`@` is not necessarily the separator. Fixed width settles it — `commit` is exactly 40 hex
characters, so the final 41 characters are always `@` + commit; `repository` is everything between
the first space and that `@`, and it can contain no space of its own, so the first space always ends
`operation`. One rendered line, exactly one bound tuple.

---

## 5. Refusal rules and error stability (normative)

Every rule in §2 and §3.1 is a REFUSAL. There is no partial acceptance, no truncation, and no
repair. Absent, `null`, empty-string and malformed are the SAME refusal for a given member: an
optional bound concept would let two deployments with different targets share a digest.

**Unrecognized members are refused** (`additionalProperties: false`, enforced in code, not merely
declared in a schema). This is the load-bearing rule of the whole construct: without it,
`{six members}` and `{six members, force: true}` produce the SAME `paramsHash` while the extra
member is invisible in §4's rendering — so a member the approver never saw can ride an approved
authorization to whatever executes it.

### 5.1 Refusal precedence

A conforming implementation refuses in this order. The order is normative because a vector that
pins a refusal REASON must get the same reason from every implementation:

1. **Byte/parse layer** — decoding, byte ceiling, depth, duplicate keys, forbidden keys, non-integer
   numbers. (A float-shaped `commit` is refused HERE, before any member rule runs.)
2. **Not an object** — `null`, an array, a string, a number at the top level.
3. **Member rules** — the §2 table, evaluated over the six members.
4. **Closed-world** — any own member outside the six.

### 5.2 Error-message stability

Refusal reasons are **stable within a major version** for the four families below, and the
conformance corpus pins a substring of each. An implementation MAY add detail after these
substrings; it MUST NOT change or reorder them without a version bump.

| Family | Pinned substring |
|---|---|
| not an object | `params must be an object` |
| a member is absent, empty, or malformed | `deploy params require` |
| an unrecognized member is present | `unrecognized field` |
| parse-layer refusal | the kernel parser's own reason (e.g. `duplicate object key`, `forbidden object key`, `unexpected end of input`, `non-integer (float/exponent) number not allowed`, `integer outside safe range`) |

Deliberately, the "absent / empty / malformed" family shares ONE reason rather than naming the
offending member. Naming it would be friendlier and would also tell an attacker probing a validator
exactly which member to vary next; the corpus's `note` carries the intent for a human reader.

---

## 6. Projection identity (normative)

An implementation that ENFORCES this action advertises a pinned identity for the adapter it ran, so
a relying party can tell which reviewed renderer produced a display. The identity is:

```
identity = "sha256:" ++ lowerhex( SHA-256( UTF8( JCS( {
             id:             <string>,      e.g. "noa.deploy.release.schema"
             version:        <integer>,     1
             kind:           <string>,      "actionSchema" | "displayProjection"
             implementation: <string>       "sha256:" ++ lowerhex(SHA-256(emitted adapter source))
           } ) ) ) )
```

The two published identities for version 1 are:

| id | kind | hash |
|---|---|---|
| `noa.deploy.release.schema` | `actionSchema` | `sha256:181779a415d998bb89e3c07cd42fd247fb272303bbb164faa953a1bcf03d0b70` |
| `noa.deploy.release.display` | `displayProjection` | `sha256:75fdd2b6f5674b8a4c274fb08ba7329870501dbb76b9d4646b929a9643b33d3b` |

both over `implementation =
sha256:51db5df44718981eba71c80356858e1b254fe30ec017c4a4e82c7159f2137bcc`.

The two MUST differ: same artifact, different `kind`. If a construction ever collapsed them, one of
the two roles would be unpinned.

---

## 7. What these pinned values ARE, and what they are NOT

**They are NORMATIVE EXPECTED VALUES.** They define what a conforming implementation must compute.
An implementation that computes something else is non-conforming, and this document is the
authority for saying so.

**They are NOT attestations about any running system.** This repository proves that its
implementation, its committed corpus and its pinned literals agree, and that every pin is
load-bearing — a one-character change to any of them turns the test suite red. It does NOT prove
that any particular deployed producer currently computes them, because nothing here is signed by
one. A relying party that needs THAT assurance needs a signed, versioned parity manifest from the
producer; no such manifest exists at the time of writing, and its absence is stated rather than
papered over.

**The implementation digest is a fingerprint, not a secret.** Publishing
`sha256:51db5df4…` does not reveal the adapter's source, but it is not opaque either: it reveals
EQUALITY (whether two builds run the same artifact) and CONFIRMATION (anyone holding a candidate
source can test it and get a yes/no). Treat it as a stable fingerprint of a non-public artifact.

---

## 8. What a recomputed match does NOT establish

- **Not authorization.** A matching `paramsHash` says the disclosed tuple is the committed
  parameter set. It says nothing about whether the deployment was approved, by whom, under what
  policy, or whether the approval was still valid. That is the grant/receipt layer
  (`docs/action-digest-spec.md`; ADR-R-004 in `03_DECISIONS_ADR.md`).
- **Not execution, and not completion.** A receipt is a record of a decision, not evidence that
  anything ran (`NON-CLAIMS.md`). Authorization, dispatch, execution and physical completion are
  four distinct claims.
- **Not uniqueness across attempts.** `paramsHash` legitimately REPEATS across retries of the same
  deployment. It is not the shared action digest and must not be used as one — that is precisely
  the misuse `noa.action-digest/0.1` exists to correct.
- **Not risk.** The risk class an enforcing implementation derives from `environment` is its own
  reviewed policy, not part of this wire language. Freezing one operator's policy table into a
  public wire format would make every verifier inherit it.
- **Not a capability.** Knowing any value in this document authorizes nothing. Every constant here
  is safe to publish.

---

## 9. Conformance

An implementation is conforming for `noa.deploy.release/1` iff, over every vector in
[`conformance/deploy-release/vectors.json`](../conformance/deploy-release/vectors.json):

1. every ACCEPT vector produces exactly the pinned `paramsHash`, and where pinned, exactly the §4
   display;
2. every REJECT vector refuses, and the refusal reason contains the pinned substring (a refusal for
   the WRONG reason is a failure — a vector that passes because an unrelated earlier check fired
   measures nothing);
3. both identity vectors recompute from their descriptors per §6.

The corpus is generated by `scripts/gen-deploy-release-vectors.ts`, committed, and diff-gated: CI
regenerates it and fails on drift. The generator REPLAYS every vector against the implementation
before writing, and THROWS rather than writing if any pinned value fails to reproduce — so the
corpus can never be silently re-pinned to agree with a drifted implementation.

**The fixture is synthetic by construction.** `example.invalid/example-service` (RFC 2606 reserves
`.invalid`, so it can never resolve), account identifiers from the reserved synthetic namespace
`acct-example-N`, and counting-pattern digests that no content-addressed artifact produces. This matters because the fixture is the PREIMAGE of a
published hash: anyone can read those values straight back out of the vector file, so a fixture
naming a real system would publish that system's metadata.

---

## 10. Packaging

`src/deploy-release.ts` ships in the npm package (compiled, via `dist/src`). **This document and the
conformance corpus do NOT ship in the npm tarball** — `package.json`'s `files` list carries
`docs/receipt-spec.md` only, and no `conformance/` directory. That is a deliberate, stated choice
rather than an oversight: the tarball is the runtime artifact, and the normative text plus vectors
live in the public repository, where an independent implementer reads them without installing
anything. A future release MAY add them to `files`; until it does, the repository is the
authoritative location and this section is the notice that says so.
