# `SIDE_EFFECT_UNCONFIRMED` — the durable adapter commit protocol

**Status:** specification + executable state machine + adversarial fixtures. The protocol itself is
**not implemented**, deliberately. Nothing in this repository claims exactly-once delivery or
physical completion of a side effect, and this document does not change that.

- Executable state machine: [`packages/adapter-core/src/side-effect-state.mjs`](../packages/adapter-core/src/side-effect-state.mjs)
- Adversarial fixtures: [`packages/adapter-core/test/side-effect-state.test.mjs`](../packages/adapter-core/test/side-effect-state.test.mjs)
- The thrown type for the state today: [`packages/adapter-core/src/tool-outcome-not-recorded.mjs`](../packages/adapter-core/src/tool-outcome-not-recorded.mjs)

---

## 1. The state that had nowhere to go

Between "the tool was dispatched" and "the outcome is durably recorded" there is a window. If the
process dies, the network partitions, or the signer refuses, what happened to the side effect in
that window is **unknown**. It is not "succeeded" and it is not "failed".

Every layer used to round it to one of the two, and both roundings are wrong in the same way — an
indeterminate state reported as determinate:

| rounding | consequence |
|---|---|
| → `EXECUTED` | a signed attestation that something ran which may never have run |
| → `FAILED` | a caller retries a payment that may already have been made |

`SIDE_EFFECT_UNCONFIRMED` is that state, named. It is **terminal** for the adapter (there is nothing
further to observe) and **not safe to retry**. It resolves only through reconciliation against the
remote system of record — never through a timeout, never through an assumption, and never by an
adapter deciding it "probably failed".

## 2. Why the state machine is executable

A named state that nothing computes is decoration. `next(state, event)` is a pure reducer over the
events an adapter can actually **observe**; every scenario is replayed against the rules rather than
argued about in prose. Two properties in the fixture suite are load-bearing and hold over the whole
transition table, not over the cases someone happened to write down:

1. `SIDE_EFFECT_UNCONFIRMED` has exactly two exits, `RECONCILED_COMPLETED` and
   `RECONCILED_NOT_PERFORMED`. Every other event is refused.
2. After `DISPATCH_STARTED`, no event reaches a retry-safe state except a **proof** — the tool
   stating it did nothing, or reconciliation stating it. Absence of a success is never a proof.

An unmodelled `(state, event)` pair raises `IllegalSideEffectTransition` rather than inventing a
state. Guessing is precisely how an indeterminate outcome became a determinate lie.

## 3. Relationship to the §13 evidence layer

The frozen evidence outcome union already carries `UNKNOWN_AFTER_DISPATCH` for this condition at the
**gate** layer. Five language-specific verifier implementations are checked for cross-implementation
parity on that union; organizational and implementation independence are not established. The union
is **not widened** by this design — widening it is a spec change, not a bug fix. `SIDE_EFFECT_UNCONFIRMED` is the **adapter**
layer's name for the same fact, and `EVIDENCE_OUTCOME_FOR` is the mapping, stated once and asserted
by test.

## 4. Protocol prerequisites

A durable implementation requires all of the following as one coherent contract:

1. an idempotency key honored end to end by the remote system;
2. an operation reference that the authoritative system can return;
3. durable pre-dispatch state with documented crash and torn-write behavior; and
4. an authenticated reconciliation channel that can answer whether the operation occurred.

Implementing only a local token or journal does not provide exactly-once behavior. This document
defines the state and prerequisites; it is not evidence that a generic durable adapter is deployed.

## 5. Claims this design does NOT make

- **Not exactly-once.** `safeToRetry` means "no evidence of a side effect exists", never "a retry is
  harmless". Exactly-once is a property of the remote honouring an idempotency key end to end, and
  nothing here can assert it on the remote's behalf.
- **Not physical completion.** A reconciled `COMPLETED` is the system of record's claim, faithfully
  recorded. The receipt attests what the system of record said, not what physically happened.
- **Not a durability guarantee for the window itself.** Without a verified durable pre-dispatch
  record, a crash can leave nothing to reconcile. Naming the state does not make it recoverable.
