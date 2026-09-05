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

| Authentication | Method and route | Purpose |
| --- | --- | --- |
| none | `GET /health` | Process health and the relay's untrusted-transport role |
| enrolment policy | `POST /v1/pairings` | Issue an agent-pairing token |
| enrolment policy | `POST /v1/pair` | Redeem an agent-pairing token |
| enrolment policy, development-only | `POST /v1/devices` | Register an untenanted device |
| enrolment policy | `POST /v1/device-pairings` | Issue a tenant- and kid-bound device token |
| device-pairing token | `POST /v1/devices/pair` | Redeem that short-lived, single-use device token |
| public read | `GET /v1/manifest?tenant=...` | Read the latest stored manifest for a tenant |
| public read | `GET /v1/trust?tenant=...` | Read the stored manifest plus delegation, when present |
| device bearer | `POST /v1/devices/self/revoke` | Idempotently revoke the calling device |
| device bearer | `POST /v1/devices/:id/push` | Register the calling device's push subscription |
| device bearer | `GET /v1/holds?status=pending` | List pending holds owned by the device's agent |
| device bearer | `GET /v1/holds/:id/display` | Read the owned encrypted display |
| device bearer | `GET /v1/holds/:id/context` | Read the owned envelope and deferred receipt |
| device bearer | `POST /v1/holds/:id/decision` | Submit the device-signed decision |
| agent bearer | `POST /v1/holds` | Create an idempotent hold |
| agent bearer | `GET /v1/holds/:id` | Read an owned hold |
| agent bearer | `GET /v1/holds/:id/wait?timeout=...` | Long-poll an owned hold |
| agent bearer | `POST /v1/devices/:id/claim` | Bind a compatible device to the agent |
| agent bearer | `POST /v1/manifest` | Publish a manifest within the agent's tenant scope |

Exact routes and schemas are defined by the implementation and public side-artifact package. Their
presence is not evidence that a particular UI, mobile client, provider, database, or deployment exists.

Credential-minting routes require `NOA_RELAY_ENROLMENT_SECRET` in an exposed deployment. Anonymous
enrolment is available only through the explicit `NOA_RELAY_ALLOW_ANON_ENROLMENT=1` loopback
development posture. A valid production secret does not open the untenanted `POST /v1/devices`
route; production-oriented device enrolment uses the tenant-bound pairing path in
[`ADR-0007`](../../docs/ADR-0007-device-enrolment-through-pairing.md).

Push notifications retain the legacy `/app/approve/<encoded-hold-id>` deep link by default. An
embedder may supply `approvalDeepLinkBuilder` to `createRelay`; it receives an already percent-encoded
hold-id segment and owns the final application URI. Notification delivery is best effort and clients
must retain the authenticated pull path.

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

The default is an in-memory store. Set both variables to select the public single-process file
driver:

```text
NOA_RELAY_STORE=file
NOA_RELAY_STORE_PATH=/deployment-owned/path/relay-state.json
```

`FileStore` writes a mode-`0600` temporary file, flushes it, atomically renames it, and attempts to
flush the containing directory. A failed write is reported and the corresponding in-memory mutation
is rolled back. Existing non-empty unreadable, malformed, or truncated state fails startup rather
than being treated as an empty database.

The driver takes an exclusive `<store-path>.lock`. It supports exactly one process per path; a stale
lock after an unclean kill requires operator inspection before removal. Individual store mutations
are durable, but multi-record engine operations are not a database transaction. Multi-instance/HA,
retention, backup, and point-in-time recovery require a deployment-provided `Store` implementation.

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
