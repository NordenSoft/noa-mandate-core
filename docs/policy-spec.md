# NOA Policy Specification — `noa.policy/0.2`

| Field | Value |
|---|---|
| **Status** | DRAFT — normative on ratification. Written for independent re-implementation. |
| **Date** | 2026-07-29 |
| **Purpose** | To let an implementer produce a conformant policy evaluator **without reading `src/policy/`.** An oracle derived from our source is a mirror, not a witness. |
| **Conformance** | An implementation is conformant iff it produces the identical `(verdict, ruleFired)` pair for every vector in the policy conformance corpus. One mismatch fails the whole class. |

Key words **MUST**, **MUST NOT**, **SHOULD**, **MAY** are to be interpreted as in RFC 2119.

> **How to read this document.** It states *intended semantics*, not the reference implementation's
> structure. Where a behaviour could not be specified without appealing to the implementation, it is
> recorded in **§9 Design findings** rather than papered over. Those findings are the most valuable
> part of this document for the project, and the most dangerous part for an implementer: they mark
> where two conformant-looking implementations may legitimately diverge.

---

## 1. Data model

### 1.1 Scalar

A **Scalar** is exactly one of: a string, a boolean, or an integer.

An integer **MUST** be exactly representable as a 64-bit-safe integer (|n| ≤ 2^53−1). A number that is
fractional, non-finite, or outside that range is **not** a Scalar.

There is no null, no array, no nested object in the scalar domain.

### 1.2 InputSnapshot

An **InputSnapshot** is a flat map from string keys to Scalars. Keys are opaque; they are **not** dotted
paths and **MUST NOT** be interpreted structurally. `"a.b"` is a single key, not a traversal.

Lookup **MUST** be an own-property test. An implementation **MUST NOT** consult any prototype,
inherited member, or default. In a language with inheritance, absence of an own key is absence.

### 1.3 Condition

```
Condition :=
  | { op: "eq"|"ne"|"lt"|"le"|"gt"|"ge", path: string, value: Scalar }
  | { op: "in",     path: string, values: Scalar[] }
  | { op: "exists"|"absent", path: string }
  | { op: "and"|"or", clauses: Condition[] }
  | { op: "not",    clause: Condition }
```

### 1.4 Rule and Policy

```
Rule   := { id: string, when: Condition, then: "ALLOW"|"DENY" }
Policy := { spec: "noa.policy/0.2", id: string,
            requiredPaths: string[], rules: Rule[] }
```

`rules` is **ordered**. `requiredPaths` is a set expressed as a list.

---

## 2. Policy validity (closed grammar)

A policy is **valid** iff every statement below holds. Validation is total: it **MUST NOT** depend on
the inputs.

1. `spec` **MUST** equal `"noa.policy/0.2"` exactly.
2. `id` **MUST** be a non-empty string.
3. `requiredPaths` **MUST** be an array of strings.
4. `rules` **MUST** be an array; each element **MUST** be an object with exactly the keys `id`, `when`,
   `then`.
5. `then` **MUST** be `"ALLOW"` or `"DENY"`.
6. Every `Condition` **MUST** carry a recognised `op` and exactly the member keys that `op` requires.
7. **No object anywhere in the policy may carry a key not named by this specification.** This is a
   *closed grammar*: unknown keys are a validity error, never ignored. (An open grammar is a
   smuggling channel — see §9-F1.)
8. Nesting depth of conditions **MUST** be bounded; an implementation **MUST** reject a policy that
   exceeds its bound rather than recursing without limit.
9. `clauses` (for `and` / `or`) **MUST** be a **non-empty** array.
10. `path` (for every op that takes one, `in` included) **MUST** be a **non-empty** string.
11. `values` (for `in`) **MUST** be a **non-empty** array; every member **MUST** be an allowed scalar
    (string | boolean | safe integer), and **all members MUST share one scalar type** — mixed-type
    membership has no defined comparison.
12. `value` (for `eq` `ne` `lt` `le` `gt` `ge`) **MUST** be an allowed scalar.
13. Rule `id` values **MUST** be unique across `rules`.

Items 9–13 are validity requirements and MUST be checked before condition evaluation. An invalid
policy does not acquire a truth value through evaluator short-circuiting.

An invalid policy does not produce a rule verdict. See §4.

---

## 3. Condition semantics

Let `get(k)` be the own-property lookup of key `k` in the InputSnapshot, or **absent**.

| `op` | Result |
|---|---|
| `exists` | true iff `get(path)` is present |
| `absent` | true iff `get(path)` is **not** present |
| `eq` `ne` `lt` `le` `gt` `ge` | if `get(path)` is absent ⇒ **false**. Otherwise compare (§3.1). |
| `in` | if `get(path)` is absent ⇒ **false**. Otherwise true iff some member of `values` compares equal. |
| `and` | true iff **every** clause is true. `clauses` MUST be non-empty — see below. |
| `or` | true iff **some** clause is true. `clauses` MUST be non-empty — see below. |
| `not` | logical negation of its single clause. |

> **Normative rule:** `clauses` MUST be a non-empty array. A condition with an empty `clauses` list
> makes the whole policy invalid; evaluation does not occur and the result is `DENY` with
> `ruleFired = "policy-invalid"` (§4 row 3). Empty clauses have no truth value in this specification.
> The conformance corpus MUST cover both `and` and `or` empty-clause cases as invalid policies.

> **Normative and easy to get wrong:** an absent path makes a comparison **false**, *including*
> `ne`. `{op:"ne", path:"x", value:1}` on an input without `x` is **false**, not true. Absence is not
> inequality. Use `absent` to test for absence.

### 3.1 Comparison

Comparison is defined only between two Scalars **of the same type**:

- **integer**: numeric ordering.
- **boolean**: `false < true`.
- **string**: ordering by Unicode code point, comparing code point by code point; a proper prefix
  sorts before its extension. Implementations **MUST NOT** use locale-, collation- or
  case-dependent ordering.

**A comparison between two different types is not false — it is an error** (§4, `eval-error`). This is
deliberate: silently returning false would let a type confusion masquerade as a clean non-match.

---

## 4. Evaluation

`evaluate(policyBytes, inputBytes) -> (verdict, ruleFired)`

Both arguments are **bytes** (or a string of bytes). An implementation **MUST NOT** accept a live
object from the caller in place of a document.

Steps, in this order. The order is normative and observable:

| # | Condition | Result |
|---|---|---|
| 1 | policy bytes do not parse | `DENY`, `ruleFired = "policy-invalid"` |
| 2 | input bytes do not parse | `DENY`, `ruleFired = "eval-error"` |
| 3 | policy fails §2 validity | `DENY`, `ruleFired = "policy-invalid"` |
| 4 | inputs are not a map (null, array, scalar) | `DENY`, `ruleFired = "input-invalid"` |
| 5 | some `p` in `requiredPaths` has no own key in inputs | `DENY`, `ruleFired = "required-input-absent:<p>"` — for the **first** such `p` in `requiredPaths` order |
| 6 | any input value is not a Scalar (§1.1) | `DENY`, `ruleFired = "eval-error"` |
| 7 | first rule whose `when` matches | `rule.then`, `ruleFired = rule.id` |
| 8 | no rule matched | `DENY`, `ruleFired = null` |
| 9 | any error raised during 5–7 | `DENY`, `ruleFired = "eval-error"` |

**Every failure path denies.** There is no configuration in which a malformed policy, malformed input
or internal error yields `ALLOW`.

Step 6 runs over **all** input keys, before any rule is evaluated — so a non-Scalar value denies even
if no rule reads that key. Step 5 precedes step 6: a missing required path is reported as such even
when another value is non-Scalar.

`ruleFired` is part of the conformance contract, not diagnostics. Two implementations returning the
same verdict with different `ruleFired` are **not** conformant.

---

## 5. Derived identities

### 5.1 `policyHash`

`policyHash(P) = "sha256:" || hex(SHA-256(JCS(P)))` where `JCS` is RFC 8785 canonicalization as
constrained by the NOA receipt specification (integer-only numbers, NFC strings, no lone surrogates).

Because JCS sorts member names, the hash is independent of key order in the source document. Because
§2.7 rejects unknown keys, a valid policy has no hash-affecting content outside this specification.

### 5.2 `readSet` and `readSetHash`

The **read set** is the set of every input key the policy could consult: all of `requiredPaths`, plus
the `path` of every leaf condition reachable from any rule (descending through `and`/`or`/`not`).

It **MUST** be deduplicated and sorted by the §3.1 string ordering.

`readSetHash(P) = "sha256:" || hex(SHA-256(JCS(readSet(P))))`.

> The read set is a **static over-approximation**. It names what the policy *may* read, never what a
> particular evaluation *did* read. It **MUST NOT** be used to prove that an input was consulted.

---

## 6. Compliance commitment

A receipt **MAY** carry a commitment binding it to a policy evaluation:

```
{ policyHash, inputsHash, readSetHash, engine, verdict?, ruleFired? }
```

`inputsHash` is over the canonicalized InputSnapshot. `engine` identifies the evaluator version.

**Verification** re-runs the evaluation over the supplied policy and inputs and requires:

1. the recomputed `policyHash`, `inputsHash` and `readSetHash` equal the committed values; **and**
2. **if** the commitment carries `verdict`, the recomputed verdict equals it.

> **§6.2 is conditional, and that is a known weakness — see §9-F4.** A commitment that omits `verdict`
> is schema-valid and reconciles on hashes alone. Such a commitment proves *which policy was run over
> which inputs*, and **nothing about the outcome**.

---

## 7. What this specification does not define

- **Where inputs come from.** The snapshot is caller-supplied; nothing here attests to its accuracy.
- **Time.** No condition is time-dependent; freshness is out of scope.
- **Path semantics.** Keys are opaque strings (§1.2), deliberately.
- **Policy distribution, versioning, or supersession.**

---

## 8. Conformance vectors

An implementation **MUST** be exercised against vectors covering, at minimum: each `op` including both
empty-`clauses` cases; absent-path behaviour for every comparison operator including `ne`; every
cross-type comparison pair; each of the nine outcome rows in §4; `requiredPaths` ordering; unknown-key
rejection at every nesting level; depth-bound rejection; and read-set dedup/sort.

**This corpus does not exist yet.** No implementation may claim conformance to this specification
until the public corpus exists and the implementation passes it.

---

## 9. Draft limitations

This draft is not a ratified conformance profile. Before any implementation claims conformance, a
normative revision must resolve and vector all of the following:

- validation of every `in.values` member before evaluation, independent of short-circuit order;
- the meaning of a commitment that omits `verdict` (it currently proves no outcome);
- one exact string-ordering rule, including astral-plane characters;
- a numeric maximum nesting depth; and
- stable error semantics that distinguish invalid policy from evaluation failure where required.

Until those items and the public corpus in §8 are complete, implementations may document observed
behavior but MUST NOT claim conformance to this draft.
