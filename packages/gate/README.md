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

Every route except health requires an agent bearer credential. Routes operating on a hold or grant
also enforce ownership, except `POST .../decision`: that route re-verifies the approver-signed
artifact cryptographically and deliberately does not treat the transport bearer as approval
authority.

| Method and route | Purpose |
| --- | --- |
| `GET /health` | Process health and declared trust role |
| `POST /v1/holds` | Create an idempotent hold from bounded request bytes |
| `GET /v1/holds/:id` | Read an owned hold |
| `GET /v1/holds/:id/wait?timeout=...` | Long-poll an owned hold; timeout is clamped to 25 seconds |
| `POST /v1/holds/:id/decision` | Submit signed approval material for gate verification |
| `POST /v1/holds/:id/cancel` | Record local-state loss without inventing an execution outcome |
| `POST /v1/grants/:id/reserve` | Atomically reserve a single-use grant before dispatch |
| `POST /v1/grants/:id/report` | Submit bounded attempt-report bytes; unknown outcomes remain explicit |

`POST /v1/holds` requires `Idempotency-Key`. Request bodies are size-bounded and delivered to the
engine as bytes rather than caller-owned objects.

Route names and payloads are an implementation surface, not proof that a particular client,
identity provider, notification service, storage backend, or deployment is available.

## Starting the reference server

`noa-gate serve` binds to `127.0.0.1:8899` by default. `NOA_GATE_TENANT`, `NOA_GATE_BIND`, and
`NOA_GATE_PORT` select the development tenant and listener. The command refuses to keep the execution
grant key silently in process memory: choose exactly one explicit posture.

For an out-of-process grant signer, provide:

```text
NOA_GATE_GRANT_SIGNER_SOCKET
NOA_GATE_GRANT_SIGNER_KID
NOA_GATE_GRANT_SIGNER_PUBLIC_KEY
NOA_GATE_APPROVER_KID
NOA_GATE_APPROVER_PUBLIC_KEY
NOA_GATE_APPROVER_HPKE_PUBLIC_KEY
```

For local development only, set `NOA_GATE_UNSAFE_IN_PROCESS_GRANT_KEY=1`. This is an acknowledged
weaker custody posture, not a protected deployment mode.

The command-line server does not provision a display sealer. Registered encrypted-display inputs
can be supplied by an embedder; a raw plaintext display fails closed.

## Out-of-process signer custody

Start `noa-gate-grant-signer` separately with `--key-file`, `--trust-file`, and `--socket`. Optional
bounds include `--max-approval-age-ms`, `--max-grant-ttl-ms`, and `--replay-file`.

- The key and trust files must be operator-provisioned and permission-restricted.
- The socket directory must be `0700`, or `0750` for a group shared with a separate gate OS user;
  world access and group write are refused.
- The socket defaults to mode `0600`; use `--socket-mode 660` only with an intentionally shared
  group.
- The gate pins the expected signer kid and public key from operator configuration. It does not ask
  the socket to define its own identity.
- Spent approvals are journaled durably so a restart cannot silently authorize a second grant from
  one approval.

Running both processes as the same OS user weakens the custody claim because that user may be able
to read the key file. Process separation alone is not an HSM.

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
