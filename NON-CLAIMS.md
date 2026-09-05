# NON-CLAIMS — what NOA receipts, signatures, approvals, and evidence do **not** prove

This document is normative for claim boundaries. A missing limitation must never be read as a
positive claim. Five language-specific verifier implementations are checked for cross-implementation
verdict parity on covered vectors; organizational independence and independent decision paths are not
established.

## 0. How to use this document

Each entry states a claim the public protocol does not make. A deployment may establish a stronger
claim only with separately specified inputs, trust anchors, controls, and evidence. Code, tests,
publication, deployment, adoption, and real-world truth are separate facts.

## 1. Signed receipts

### NC-1.1 — A signature does not prove the signed statement is true

A valid signature establishes that a trusted key signed exact bytes. It does not establish that the
statement matches the external world.

### NC-1.2 — A signature proves nothing about the present

An authentic statement can be stale, revoked, replayed, or superseded. Current validity requires an
explicit freshness and revocation policy.

### NC-1.3 — A receipt does not prove the action described actually occurred

A receipt is evidence of a signed statement about an action. Proof of execution requires evidence
from the authority boundary or relevant system of record.

### NC-1.4 — `action.paramsHash` does not prove the parameters were reasonable

The field is a commitment to producer-supplied parameters under the specified semantics. It is not a
policy verdict, universal action digest, or proof that a human reviewed the parameters.

### NC-1.5 — A valid chain does not prove completeness

Verification establishes the integrity of records supplied to the verifier. It cannot prove that no
record was withheld, especially after the presented tail.

## 2. Execution outcomes

### NC-2.1 — A tool's claim that it failed is not proof that no side effect occurred

After dispatch, a timeout, exception, or negative response can mean either non-execution or execution
followed by a lost response. A determinate negative requires observation by a party that can establish
non-dispatch or evidence from the external system of record.

### NC-2.2 — “Failed after dispatch” is not a retry-safe state

The protocol does not distinguish failure after dispatch from success with a missing response unless
independent reconciliation evidence is supplied.

### NC-2.3 — A tool self-report is recorded, never promoted to independent evidence

Authentication can establish who made a report. It does not establish that the reported side effect
did or did not happen.

### NC-2.4 — An outcome receipt with `outcome: "error"` is not evidence of non-execution

It records the producer's observation of an error. Consumers must keep side-effect state unknown
unless a stronger, separately verified source establishes it.

### NC-2.7 — A terminal receipt applies only to its bound invocation

Two invocations may have the same action and parameter commitment. Correlate outcomes using the
protocol's invocation-, receipt-, chain-, or grant-specific binding, never action fields alone.

### NC-2.5 — Receipts do not guarantee exactly-once effects

Exactly-once effects require end-to-end idempotency, durable state, bounded retries, and reconciliation
with the external system. Receipt integrity alone cannot provide those properties.

### NC-2.6 — The absence of a verdict is not the absence of a side effect

Hosts need explicit timeouts and an `UNKNOWN` or equivalent state. Silence, transport loss, or an
unhandled error must not be converted into a safe retry claim.

## 3. Human approval

### NC-3.1 — An approval receipt does not prove a human understood what they approved

It can establish authorization by a key under the stated rules. Understanding, attention, and
informed consent are separate human-factors claims.

### NC-3.2 — `governance.approval.by` is an opaque identifier, not an identity proof

The value has only the meaning assigned by an authenticated identity contract outside the receipt.

### NC-3.3 — An approval does not expire merely because a consumer stopped observing it

Expiry and revocation must be explicit, authenticated, and checked against a stated clock policy.

### NC-3.4 — Nothing in a receipt proves the rendered display was seen

Binding display bytes or a projection proves a commitment to those bytes. It does not prove that a
person saw, understood, or acted on the rendered interface.

## 4. Federation, anchors, and completeness

### NC-4.1 — A quorum of witness keys does not prove organizational independence

Software can count distinct keys. Whether those keys belong to independently controlled parties is an
operational fact that requires external evidence.

### NC-4.2 — Freshness is not enforced unless the relying party supplies and checks a policy

An old but authentic anchor or checkpoint can replay. Omitted freshness must be reported, not treated
as current evidence.

### NC-4.2a — A lagging witness alone does not prove the presented later history

An anchor below the presented head can corroborate only the history position it actually commits to.
Detecting a rewrite requires comparing that position with the supplied chain; discarding lagging
evidence must not be described as a completeness proof.

### NC-4.3 — This repository does not operate a transparency log

Public formats and offline reference components are not evidence that a witness network is deployed,
complete, reachable, or independently operated.

### NC-4.3a — An anchor pool is not authenticated as complete

A scanner can detect contradictory signed views that it receives. It cannot prove that all relevant
views were delivered or decide which branch represents external truth.

### NC-4.4 — A bundle cannot prove a display binding unless it carries or references verifiable display evidence

A digest without the committed object cannot be recomputed by a third party. Any skipped display
check must remain explicit in the result.

### NC-4.5 — A checkpoint endorsement is not an external anchor

A trusted key signing a head proves that key endorsed the head. Independent observation requires
separately obtained witness evidence and its own trust policy.

## 5. Policy and compliance

### NC-5.1 — A compliance commitment does not prove the policy was adequate

It can bind a named policy and inputs to a result. It does not establish that the policy expressed the
right legal, safety, or business rule.

### NC-5.2 — `inputsHash` binds recorded inputs, not the world

If a source supplies false or incomplete inputs, a correct evaluator can produce a correctly committed
result over false premises.

### NC-5.3 — No certification is claimed, implied, or in progress

Passing repository checks is not certification, regulatory approval, a formal standard, or production
assurance.

## 6. Trust and enforcement boundaries

### NC-6.0 — The same-realm TypeScript verifier is not a hardened security boundary

Code already executing in the same JavaScript realm can affect computation. The in-process API makes
no claim of resistance to a compromised host runtime.

### NC-6.1 — Code that runs before the verifier can compromise its assumptions

Module-load capture can reduce later mutation risk; it cannot repair a runtime that was already
compromised before trusted code initialized.

### NC-6.2 — Process isolation protects computation, not consumption

A separate process raises the capability required to alter verification, but a compromised caller can
still discard, replace, or ignore the result.

### NC-6.3 — A text-taking API is not immune to a compromised runtime

Parsing bytes closes hostile-object accessor paths. It does not make the language runtime or calling
process trustworthy.

### NC-6.4 — Regression vectors do not establish universal attack resistance

Vectors demonstrate behavior for covered cases at an exact revision. Passing them does not prove that
all equivalent mechanisms or future inputs have been enumerated.

### NC-6.5 — An in-process guard is advisory

A wrapper governs only calls that pass through it. Place enforcement where credentials or write
authority cannot bypass the decision.

### NC-6.6 — A verdict returned to a compromised caller is not enforcement

Consequential authorization requires both authority control and intent binding. The intent presented
for approval, authorized by a capability, and executed at the target must refer to the same canonical
request. A signed decision without target-side enforcement does not make the action impossible to
bypass.

### NC-6.7 — A relay record is transport state, not approval evidence

A relay may authenticate a sender or preserve structural bindings without becoming a trust root.
Consumers must verify authoritative signed artifacts against trust material they control.

### NC-6.7b — COSE/SCITT interoperability is limited to published, measured coverage

Signer roles, protected headers, payload bytes, embedded signatures, detached payload behavior, and
native-chain verification are separate requirements. No interoperability claim extends beyond the
published vectors and exact revision that passed them.

### NC-6.8 — Public reference components do not take custody of downstream action credentials

An integration that deliberately holds credentials capable of performing the protected action has a
different trust boundary and cannot inherit this repository's non-claims by association.

### NC-6.9 — Mutable governance configuration is not inherently tamper-evident

Safe file access, ownership checks, and permissions reduce specific filesystem risks. They do not
authenticate mutable content against an attacker with equivalent write authority. Stronger claims
require signed configuration and separately protected trust material.

## S4. Settlement evidence

### NC-S4.0 — Activity outside enforced gateways is outside coverage

The evidence model says nothing about actions or settlements performed through an unobserved path.

### NC-S4.1 — Settlement is not delivery, and `RECONFIRMED` is not universal proof

A settlement observation can establish defined ledger facts. It does not prove service delivery,
legal finality in every jurisdiction, or the truth of unrelated business claims.

### NC-S4.2 — A rail-provided receipt is not load-bearing evidence by itself

Counterparty or facilitator reports require independent verification against the relevant system of
record before they can support a positive settlement claim.

### NC-S4.3 — `RECONFIRMED` is scoped to the verifier's stated observations

The verdict must name what was queried, under which trust and freshness policy, and which facts were
matched. It is not a claim about unqueried state.

### NC-S4.4 — Correlation proves a payer-key authorization, not human approval

Payment authorization and approval authority are different claims and need an explicit binding.

### NC-S4.5 — Absence of a settlement observation is not evidence of non-payment

Unavailable, incomplete, pruned, or delayed observations must remain unresolved.

### NC-S4.6 — An observer and execution signer are not automatically independent

Distinct keys, processes, or labels do not establish distinct organizational control.

### NC-S4.7 — Correlation data can be public and permanent

Privacy depends on the entropy and secrecy of the correlation construction. Publishing the material
needed to re-derive it can create a durable link.

### NC-S4.8 — Settlement evidence does not change the authorization root

It answers a downstream observation question; it does not retroactively authorize the action.

### NC-S4.9 — Settlement evidence depends on correct intent binding

Strong confirmation of the wrong request amplifies an upstream binding error rather than repairing it.

### NC-S4.10 — Relying-party recomputation reduces trust in an observer

When practical, the relying party should query the authoritative system itself and retain the inputs
and policy needed to reproduce the result.

### NC-S4.11 — An evidence bundle can be a durable correlation capability

Disclosure may allow future observers to rediscover linked public activity. Treat bundle retention and
sharing as a privacy decision.

### NC-S4.12 — Missing evidence does not distinguish “not yet” from “never”

The protocol needs an explicit terminal policy; indefinite absence must not become a positive or safe
retry result.

### NC-S4.13 — A reported failure may conceal a completed settlement

Front-running, transport loss, or stale observers can create false negatives. Reconciliation must
retain an unresolved state.

### NC-S4.14 — Evidence can disclose a payer relationship

Even when amounts or business context are omitted, addresses, nonces, and timing may enable durable
correlation.

### NC-S4.15 — No minimized-disclosure tier is implied

Unless a versioned profile defines one, a full evidence bundle should be treated as disclosing every
field it carries.

### NC-S4.16 — Same-process verification assumes an uncompromised runtime

A positive settlement verdict is conditional on the integrity of the process computing it. Where that
condition matters, verify in a trust context controlled by the relying party.

## S5. Action-class enrolment

### NC-S5.1 — A reader that supplies no registry cannot enforce registry requirements

Optional trust inputs cannot silently become mandatory. Results must say whether enrolment was
evaluated.

### NC-S5.2 — Enrolment alone does not prevent outcome shopping

A producer may choose among admissible artifact paths unless the protocol binds one required outcome
and rejects alternatives.

### NC-S5.3 — Registry equivocation can be detectable without being locally decidable

Conflicting authentic registry statements prove a conflict, not which statement is authoritative.

### NC-S5.4 — Producer timestamps do not establish an authoritative enrolment window

Window selection needs a trusted time source or a policy that explicitly accepts signer-asserted time.

### NC-S5.5 — A projection hash binds a renderer definition, not human perception

It can establish which deterministic projection was committed. It does not prove what a person saw or
understood.

### NC-S5.6 — Different authority names do not establish different custody

Independence requires evidence about key custody and operational control, not role labels alone.

### NC-S5.7 — Enrolment cannot grant authority absent from the bundle's delegation chain

Registry membership constrains evidence requirements; it does not create authorization by itself.

### NC-S5.8 — An enrolled class may have no positive offline verdict

If required external evidence is absent or cannot be checked, the correct result is inconclusive or
unverified, not success.

## 7. Changing this document

Removing or weakening a non-claim creates a stronger claim. Such a change requires an exact normative
revision, positive and negative evidence, compatibility analysis, and independent review. Private
incident details and unreleased vulnerability material belong in coordinated security handling, not
in this public claim-boundary document.
