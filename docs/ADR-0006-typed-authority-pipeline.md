# ADR-0006 — Typed authority pipeline

| Field | Value |
|---|---|
| **Status** | **PARTIALLY IMPLEMENTED.** Input provenance and boundary-constructed command slices exist. Stages 8–10 are not complete. |
| **Scope** | Preserve exact intent across policy, approval, grant, dispatch, and evidence without upgrading authorization into execution proof. |

## 1. Problem

An approval pipeline can verify every signature and still authorize the wrong effect if successive
stages reconstruct intent from different values. Each stage therefore needs a named input type,
validator, canonical bytes, deterministic derivation, failure result, and audit artifact.

The central equality is not assumed:

```text
approved intent == granted intent == dispatched command == externally observed effect
```

Each equality requires evidence from an authority capable of establishing it.

## 2. Pipeline model

1. wire bytes;
2. strict validated snapshot;
3. canonical action intent;
4. intent and projection commitments;
5. deterministic policy decision;
6. signed hold envelope;
7. authenticated approval proof;
8. execution grant;
9. provider execution evidence; and
10. receipt claim constrained by the evidence actually available.

Stages 1–7 may establish what was requested and approved. They cannot alone establish what an
external provider executed.

## 3. Stages 1–3 — one canonical intent

The boundary receives bytes, rejects malformed input, creates a deeply immutable snapshot, and
constructs the action intent. No later stage may re-read caller-owned values. The resulting canonical
bytes are the authority source for commitments, display, and dispatch.

## 4. Stage 4 — commitments

The pipeline distinguishes two commitments:

- a content digest over canonical action bytes; and
- an implementation-artifact digest identifying the registered projection that produced the
  display and risk derivation.

### 4.1 Public action digest

[`action-digest-spec.md`](action-digest-spec.md) defines `noa.action-digest/0.1`. It correlates a
receipt and grant using versioned canonical bytes and domain separation. It is a linkage value, not
authentication, authorization, or proof of execution.

Current projection code and tests bind the display and parameter commitment to the same canonical
snapshot:

- [`packages/gate/src/projections.ts`](../packages/gate/src/projections.ts)
- [`packages/gate/test/stage4-digest-display-agreement.test.ts`](../packages/gate/test/stage4-digest-display-agreement.test.ts)

## 5. Stage 5 — policy decision

Policy evaluation must consume the canonical intent and a validated policy document. Its output is
a deterministic typed decision including the verdict and fired rule. A policy hash that commits only
to the question and omits the verdict is insufficient evidence.

The public reference evaluates bytes and fails closed on invalid policy or input. Authentication and
tenant-specific governance of the policy source remain separate trust-root concerns.

## 6. Stage 6 — hold envelope

The hold envelope binds the exact action commitment, display projection, risk class, tenant,
freshness, nonce, and relevant key-manifest references. It is an authorization request, not an
execution grant and not proof that a human understood the display.

## 7. Stage 7 — approval proof

The approval artifact is verified from bytes against its context, scope, time, and approver key.
The decision must name the hold it resolves. A denial cannot be converted into an approval through a
second read, a substituted reason, or a mismatched receipt.

## 8. Stage 8 — execution grant

A complete stage 8 requires the grant signer to reconstruct and validate the grant from authenticated
inputs, bind audience, executor, intent, expiry, and replay state, and expose no raw-sign route for
the grant key.

The current gate constructs a typed `ExecutionCommand` from the frozen authorized snapshot and gives
that command to the executor. This closes accidental post-approval parameter substitution inside the
wrapper. It does **not** prove that an untrusted executor used the command, and it does not by itself
establish protected signer custody or target-side capability validation.

Current evidence:

- [`packages/gate/src/wrapper.ts`](../packages/gate/src/wrapper.ts)
- [`packages/gate/test/provenance-regression.test.ts`](../packages/gate/test/provenance-regression.test.ts)
- [`scripts/lint-dispatch-surfaces.mjs`](../scripts/lint-dispatch-surfaces.mjs)

## 9. Stage 9 — provider execution evidence

### 9.1 No external-effect equality from a caller report

A callback result such as `{ ok, detail }` is supplied by the party being judged. It may describe a
dispatch attempt, but it cannot independently establish which external request ran or what effect the
provider committed. The typed command makes the intended dispatch auditable; it does not make the
executor honest.

Admissible evidence would require either:

1. boundary-owned credentials and dispatch, so the boundary constructs and sends the request; or
2. a target that validates a request-bound capability and returns evidence under an independently
   trusted key.

Neither property is established by this public repository. Unknown or unauthenticated outcomes must
remain `SIDE_EFFECT_UNCONFIRMED` or an equivalently bounded state.

## 10. Stage 10 — receipt claim

A receipt may state only what the available evidence proves. Approval is not execution; dispatch is
not completion; a gate-generated receipt is not independent provider evidence; and a digital receipt
is not proof of a physical-world outcome.

## 11. Acceptance criteria for completing the pipeline

Completion requires exact-current positive and negative evidence that:

- every stage consumes the previous stage's authenticated bytes or typed result;
- action, parameters, audience, expiry, nonce, and identity substitutions are refused;
- grant signing cannot be used as a raw-sign oracle;
- retries, restarts, replay, and unknown-after-dispatch states fail safely;
- external-effect claims come from the authority capable of observing them; and
- independent verification cannot be satisfied by the producer's own assertion.

Until then, this ADR records partial implementation and explicit non-claims, not a completed
authority or execution pipeline.
