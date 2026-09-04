# ADR-0003 — The enforcement boundary: authority, not verdicts

| Field | Value |
|---|---|
| **Status** | **PROPOSED.** This architecture record is not implementation, deployment, or release evidence. |
| **Date** | 2026-07-29 |
| **Scope** | Architecture proposal for capability enforcement, credential custody, and boundary-owned dispatch. |
| **Evidence class** | Recorded analysis. Exact-current implementation and deployment evidence must be established separately. |

## Public scope

This ADR evaluates generic enforcement-boundary patterns for implementers. It does not describe a
private deployment, provider, customer environment, or approved product roadmap. Any implementation
claim requires revision-bound code and test evidence; any deployment claim requires separate runtime
evidence.

## 1. Recorded architecture direction

The proposed direction is target-validated, boundary-issued capability enforcement, with
boundary-owned dispatch where target-native validation is unavailable. The boundary is scoped for
enforcement, credential custody, capability issuance, and optional dispatch; it is not merely a
signing or throughput service.

The central distinction is:

- a verifier can compute a correct `ALLOW` or `DENY`;
- an enforcement authority controls whether the governed effect can occur.

A verdict returned to an ambiently compromised caller is advisory. The caller can replace the
transport result or the check that consumes it. Protecting the computation alone therefore does not
establish enforcement.

## 2. Problem and threat boundary

The proposal addresses an attacker that can influence the caller process, dependencies, transport,
or application-visible result, but does not control the external enforcement authority or extract
its protected credential. It does not claim protection once the target authority, credential store,
or boundary itself is compromised.

The load-bearing invariant is:

> A governed effect is accepted only when the target validates a single-use, scope-bound capability,
> or when a boundary that exclusively controls the relevant credential performs the dispatch itself.

The following do not satisfy that invariant on their own:

- a signed verdict returned to the caller;
- a local `if (allowed)` branch;
- an audit record written after the effect;
- a receipt proving that a statement was signed;
- computation isolation without delivery and consumption integrity.

## 3. Alternatives

### 3.1 Boundary-owned credential and dispatch

The boundary holds the only usable action credential and invokes the target after authorization.

**Security property:** the caller cannot perform the governed action directly if it never possesses
the credential.

**Costs and risks:** the boundary becomes a high-availability dependency, a credential custodian,
and a concentration point. Rotation, least privilege, provider adapters, recovery, auditability,
timeouts, retry bounds, and idempotency become mandatory.

### 3.2 Target-native capability enforcement

The boundary issues a narrowly scoped capability that the target validates before accepting the
effect.

**Security property:** the target, rather than the caller, enforces audience, action, parameter,
expiry, and replay constraints.

**Costs and risks:** the target must support or integrate the validation contract. A bespoke token
format creates interoperability and downgrade risk; existing target-native mechanisms should be
reused where they provide the required bindings.

### 3.3 Evidence-only verification

The system records approvals, grants, receipts, and observations without controlling execution.

**Security property:** useful provenance and audit evidence within its stated limits.

**Limit:** it cannot prevent a caller from bypassing the verifier or invoking the target through an
uncontrolled path. It must not be described as enforcement.

## 4. Proposed hybrid

Use target-native capabilities where the target can validate all required bindings. Use
boundary-owned dispatch where it cannot. Keep evidence-only integrations explicitly classified and
do not upgrade their claims.

This hybrid is a proposal, not an accepted or implemented decision. A concrete integration must name
which branch it uses and prove that no parallel ungoverned credential or endpoint remains.

## 5. Required capability semantics

A capability or dispatch authorization must bind at least:

- issuer and trust anchor;
- intended target and audience;
- action identifier and canonical risk key;
- exact parameter commitment using versioned canonical bytes;
- authorization or approval evidence reference;
- issue time, expiry, and clock policy;
- single-use nonce or equivalent replay key;
- key and algorithm identifiers with rotation and revocation behavior;
- protocol version and downgrade refusal.

The target or boundary must validate every required field before the effect. Unknown versions,
algorithms, trust roots, missing bindings, expired grants, malformed canonical bytes, and replay
state uncertainty fail closed with stable errors.

## 6. Execution controls

Boundary-owned dispatch additionally requires:

- exclusive credential custody and narrowly scoped credentials;
- deterministic authorization before dispatch;
- an idempotency key bound to the exact authorized attempt;
- bounded timeouts and retries;
- durable terminal-state recording;
- recovery that distinguishes not-started, dispatched, succeeded, failed, and unknown;
- an audit trail that cannot be the sole source of its own truth;
- rollback or forward-fix procedures that do not restore an ungoverned path.

Authorization is not execution. Dispatch is not completion. A digital receipt is not proof of a
physical-world outcome. Each transition needs evidence from the authority that owns that claim.

## 7. Design-review lessons retained

- Verifier computation is not enforcement authority.
- Inventory and reuse analysis must precede migration design.
- Caller-delivered verdicts remain advisory under caller compromise.
- Freezing a wire format before authority and replay semantics are settled is premature.
- Entry integrity and log completeness are different properties.
- Display integrity limits the highest claim a human approval can support.
- Key custody can prevent durable offline forgery even when it cannot make a compromised caller
  trustworthy.

## 8. Verification criteria for any future implementation

An implementation cannot cite this ADR as proof. It must provide exact-current evidence that:

1. the governed target cannot be reached with an uncontrolled credential or endpoint;
2. altered action, parameters, audience, expiry, nonce, key, and version are rejected;
3. replay across retries, restarts, snapshots, and concurrent dispatch is rejected or resolved by a
   documented idempotency contract;
4. denial, expiry, revocation, provider timeout, partial failure, and unknown-after-dispatch all stop
   unsafe continuation;
5. recovery preserves authorization and attempt identity;
6. logs and receipts preserve raw evidence and do not claim more than the external authority proves;
7. independent negative tests exercise both the capability and boundary-dispatch paths.

## 9. Rollout and rollback

Rollout should proceed as reversible slices: inventory, canonical wire semantics, verify-only
integration, dual-path observation, then enforcement for one bounded action class. Each slice needs a
stop condition and evidence tied to exact bytes.

Rollback may disable a new governed action or return to evidence-only classification. It must never
restore a credential path that bypasses the boundary while continuing to claim enforcement.

## 10. Non-claims

This document does not establish implementation, deployment, production use, customer demand,
standards adoption, independent interoperability, or protection against compromise of the target or
enforcement authority. The status conflict at the top remains unresolved by this sanitized copy.
