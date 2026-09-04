# noa-gate — generic HTTP approval gate reference

`noa-gate` is a public reference implementation of a hold, decision, grant, and execution-report
protocol for non-MCP HTTP clients. Repository code is prototype evidence, not a hosted-service,
production, or deployment claim.

## Gate and relay are different trust roles

`noa-relay` is untrusted transport: it routes and stores public or ciphertext artifacts and does not
become a trust root. A gate validates the configured trust inputs and can issue gate-side artifacts.
Consumers still verify every authoritative signed artifact against trust material they control.

The public artifact family includes:

| Artifact | Purpose |
| --- | --- |
| Hold Envelope | binds the action commitment, display commitment, and manifest revision |
| Decision Artifact | binds an approver-key decision to one hold |
| Execution Grant | carries bounded, request-specific execution authority |
| Execution Consumption | records use of a grant and the associated attempt |
| Execution Uncertainty | preserves an indeterminate post-dispatch state |
| Hold Resolution | records the gate's terminal view without proving a physical outcome |

The exact schemas and signing rules live in [`noa-approval-artifacts`](../approval-artifacts).

## Public HTTP contract

The reference server exposes versioned routes to create and inspect a hold, wait for a decision,
submit a signed decision, cancel a hold, reserve a grant before dispatch, and report the resulting
attempt. Mutating client routes require authentication and idempotency where specified by the API.

Route names and payloads are an implementation surface, not proof that a particular client,
identity provider, notification service, storage backend, or deployment is available.

## Intent binding and execution

A protected flow must bind three values to the same canonical request:

1. the intent rendered for the approver;
2. the intent authorized by the grant; and
3. the intent presented at the execution boundary.

The registered/typed mode derives the action commitment and display projection from a structured,
validated snapshot. A raw caller-provided display is only an opaque statement by that caller; it must
not be described as proof that the displayed request matches what executed.

Grant reservation is an at-most-once bookkeeping control only for callers that use the reservation
protocol. It is not exactly-once execution and does not prevent an actor holding separate downstream
authority from bypassing the gate. Enforcement must live where the action credentials or capability
are controlled.

## Security requirements

- Bind to loopback by default. A network listener requires explicit transport security and deployment
  review.
- Never add private product data or fields to the frozen receipt schema; use versioned side artifacts.
- Treat approver decisions, key manifests, policy, and trust configuration as untrusted until
  authenticated against independently provisioned trust material.
- Keep execution-signing authority outside a caller-controlled process when the threat model requires
  that separation. Process separation is not an HSM and does not establish organizational
  independence.
- Fail closed when required sealing, identity, intent-binding, replay, expiry, or trust checks cannot
  be performed.
- Preserve an explicit unknown state after dispatch; an error or missing response is not proof that no
  side effect occurred.

See [NON-CLAIMS.md](../../NON-CLAIMS.md) and [THREAT-MODEL.md](../../THREAT-MODEL.md) before relying on
this reference implementation.

## Reuse

The gate uses `noa-receipt` for receipts and `noa-approval-artifacts` for side-artifact signing,
verification, and reference hashes. It does not define new receipt cryptography.

## Development

```bash
npm test
```

The command is local test evidence only. A successful run is not release, deployment, or production
evidence.
