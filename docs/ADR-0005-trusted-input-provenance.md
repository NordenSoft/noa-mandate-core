# ADR-0005 — Trusted input provenance and single-read discipline

| Field | Value |
|---|---|
| **Status** | **PARTIALLY IMPLEMENTED.** The controls named below exist in the current public source and tests; this record is not deployment evidence. |
| **Scope** | Parse boundaries, immutable snapshots, derivation provenance, render consistency, and display-ciphertext egress verification. |
| **Out of scope** | Native isolation, provider execution, target-side enforcement, and production key custody. |

## 1. Decision

Trust decisions are derived from authenticated bytes through one parse boundary. The boundary must
not authorize from a caller-owned object graph or read a security-relevant value twice from mutable
input. A value is decoded once, validated once, retained as an inert snapshot, and every downstream
derivation names the bytes or snapshot from which it came.

## 2. Input classes

The implementation distinguishes:

- **wire bytes**: untrusted input, size-bounded before parsing;
- **validated snapshot**: a deeply immutable result of strict parsing and validation;
- **derived value**: computed inside the boundary from that snapshot;
- **authenticated document**: bytes whose signature, scope, time, and trust root were verified.

Moving a value between classes requires an explicit validator. TypeScript types and JSON Schema
alone do not make input trusted.

## 3. Slice 1 — bytes enter the boundary

The gate HTTP server retains request bodies as bytes and the engine performs the parse. Duplicate
keys, malformed JSON, oversize documents, unexpected fields, and invalid schema values fail closed.
The same byte string is used for validation and authorization; a caller cannot provide one object
for the check and another for later reads.

Current evidence:

- [`packages/gate/src/server.ts`](../packages/gate/src/server.ts)
- [`packages/gate/src/engine.ts`](../packages/gate/src/engine.ts)
- [`packages/gate/test/provenance-regression.test.ts`](../packages/gate/test/provenance-regression.test.ts)

## 4. Slices 2 and 3 — capture once and freeze deeply

Projection inputs are copied from the validated document, canonicalized once, and frozen before use.
Nested arrays and objects are included in the freeze walk. A getter, proxy, second property read, or
post-validation mutation must not change the action, risk class, display, or signed artifact.

Approval artifacts use their own bytes-in parse boundary and deeply immutable snapshot in
[`packages/approval-artifacts/src/parse-document.ts`](../packages/approval-artifacts/src/parse-document.ts).

## 5. Slice 4 — one render node and verified display egress

The display projection and the parameter commitment must be derived from the same canonical input.
The gate seals the rendered display for the approver and an audit recipient. Before releasing a
stored sealed display, it re-verifies the ciphertext against the expected associated data and hold
identity. Replaying ciphertext from another hold therefore fails closed.

The audit recipient is mandatory: a display that only the approver can decrypt cannot later be
examined by an independent auditor. This does not make the audit key independent of the deployment
that provisions it.

Current evidence:

- [`packages/gate/src/projections.ts`](../packages/gate/src/projections.ts)
- [`packages/gate/src/engine.ts`](../packages/gate/src/engine.ts)
- [`packages/gate/test/display-egress-aad.test.ts`](../packages/gate/test/display-egress-aad.test.ts)
- [`packages/gate/test/stage4-digest-display-agreement.test.ts`](../packages/gate/test/stage4-digest-display-agreement.test.ts)

## 6. Slice 5 — derive risk inside the boundary

The registered projection derives the action's risk class from the validated snapshot. A caller
hint may raise the floor but cannot lower the derived class. The registry is captured by the trusted
module; a tenant-authenticated, versioned projection manifest remains outside this ADR.

## 7. Required anti-vacuity checks

The controls are accepted only when negative tests demonstrate that removing or weakening them is
detected. The current knockout registry covers, among other controls:

- the bytes-in parse boundary;
- the single canonical render input;
- derived-risk non-downgrade;
- the mandatory audit recipient; and
- display associated-data verification on egress.

The current executable self-test for trusted-source coverage is
`node scripts/lint-trusted-roots.mjs --selftest`. It supersedes historical run reports; a zero finding
without a deliberately triggered negative control is not evidence that the layer works.

## 8. Residuals and non-claims

These controls prevent measured provenance and inconsistent-read failures in the current public
implementation. They do not establish:

- immunity from a pre-load or same-realm runtime attacker;
- authenticated or versioned tenant projection policy;
- protected signer or provider-credential custody;
- equality between the authorized command and an external side effect;
- production deployment or independent observation.

Those limits are addressed as separate architecture and release questions, principally in
[ADR-0002](ADR-0002-isolated-native-trust-boundary.md),
[ADR-0003](ADR-0003-enforcement-boundary.md), and
[ADR-0006](ADR-0006-typed-authority-pipeline.md).
