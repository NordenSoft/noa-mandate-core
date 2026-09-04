# noa-relay — untrusted transport reference

`noa-relay` is an Apache-licensed reference implementation for transporting hold and decision
artifacts between generic clients. It is prototype code, not a hosted-service, production, uptime,
notification-delivery, or managed-operations claim.

## Relay is not a gate or trust root

The relay routes and temporarily stores public or encrypted protocol artifacts. It does not mint an
approval, hold a downstream action credential, decide policy, or make its own database record
authoritative. A consumer must verify signed artifacts against trust material obtained independently
of the relay.

The relay may authenticate a client to control access to a transport route. That proves only which
transport credential was presented; it does not prove a human identity or confer approval authority.

## Public protocol behavior

The reference implementation supports generic operations to:

- create and inspect a hold;
- wait for a terminal transport state;
- submit a signed decision artifact;
- exchange versioned public trust artifacts; and
- register or rotate a client transport key under an explicit enrolment policy.

Exact routes and schemas are defined by the implementation and public side-artifact package. Their
presence is not evidence that a particular UI, mobile client, provider, database, or deployment exists.

## Required bindings

- A decision must bind to exactly one hold and its committed action/display material.
- Idempotency keys must return the same result for the same request and reject conflicting reuse.
- Tenant or namespace scope must be checked at every operation that accepts scoped artifacts.
- Expiry is transport state, not proof that the underlying action did or did not occur.
- The relay must not turn missing, malformed, unverifiable, or stale evidence into approval.

## Security posture

- Listen on loopback by default. Network exposure requires explicit TLS termination, authentication,
  rate limits, request-size limits, and deployment review.
- Treat all stored artifacts as attacker-controlled input when they are read back.
- Store secrets only through a deployment-provided secret mechanism; never embed production values in
  repository examples.
- Keep transport authentication separate from artifact-signing authority.
- Do not trust manifests or key material merely because the relay served them.
- Bound long polls, record counts, body size, and retained state to limit denial of service.

## Persistence

The storage interface may be implemented in memory for local tests or by a deployment-specific durable
driver. A durable driver must define atomicity, concurrency, retention, backup, corruption handling,
and recovery. This repository does not prescribe or disclose a production storage topology.

## Claim boundary

A relay record is bookkeeping by an untrusted transport. The authoritative input is the signed artifact
verified by the relying party. See [NON-CLAIMS.md](../../NON-CLAIMS.md#nc-67--a-relay-record-is-transport-state-not-approval-evidence)
and [THREAT-MODEL.md](../../THREAT-MODEL.md).

## Development

```bash
npm test
```

Local tests do not establish deployment, availability, external identity, notification delivery, or
production operation.
