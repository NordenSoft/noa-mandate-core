# Generic HTTP client example

This example shows the public HTTP contract from a shell or Python client: **create a hold, wait,
receive a signed ALLOWED/BLOCKED verdict, and verify it offline.** Any client that can make an HTTP
request can follow the same contract; no MCP client or Node runtime is required on the client side.

## Quickstart

Terminal 1 — stand up a real local relay + a headless auto-approver (both real code, no stubs):

```bash
cd packages/e2e-demo && npm install   # once
node examples/http-agent/run-local-stack.mjs
```

This prints a ready log and writes three files next to it: `session.env` (shell), `session.json`
(python), `keyring.json` (the offline-verify trust root). Leave it running.

Terminal 2 — gate a risky action from a shell script:

```bash
cd packages/e2e-demo/examples/http-agent && bash approve.sh
```

Or from Python (stdlib only, zero pip installs):

```bash
cd packages/e2e-demo/examples/http-agent && python3 approve.py
```

Both do the same round trip: `POST /v1/holds` (create, with an `Idempotency-Key`) →
`GET /v1/holds/:id/wait` (long-poll) → print the signed verdict → replay the same
Idempotency-Key (idempotent, no duplicate hold) → try an unauthorized request (`401`).
`approve.py` additionally writes the returned receipt to disk and shells out to the published
`noa verify` CLI to prove the signature checks out completely offline (no network, no relay, no
NOA anything — just the receipt bytes + the public key).

## The ~10-line integration

```bash
curl -s -X POST "$RELAY_BASE_URL/v1/holds" \
  -H "Authorization: Bearer $AGENT_API_KEY" \
  -H "Idempotency-Key: my-unique-key-1" \
  -H "Content-Type: application/json" \
  -d '{"action":{"canonical":"example.submit","riskClass":"HIGH","paramsHash":"sha256:<64-hex>"}}'
# -> {"holdId":"...","status":"PENDING","expiresAt":"..."}

curl -s "$RELAY_BASE_URL/v1/holds/<holdId>/wait?timeout=25" \
  -H "Authorization: Bearer $AGENT_API_KEY"
# -> long-polls (server clamps 0-25s) until a human decides, or returns EXPIRED at the TTL
```

`paramsHash` is `sha256:` + the hex digest of whatever bytes represent the actual parameters of the
action your code is about to run (so the eventual decision is cryptographically bound to *this*
call, not just the action name).

## Where the example decision comes from

`run-local-stack.mjs` starts the public relay and a local test signer using a genuine Ed25519 key.
Its deliberately simple example policy blocks `CRITICAL`/`IRREVERSIBLE` and allows other sample
requests. That proves the wire and signature flow; it is not evidence of human review, production
policy, identity proofing, or a deployment architecture. A real integrator supplies an approver
client and trust policy appropriate to its own environment.

The returned `decisionReceipt` is a full `noa.receipt/0.1` object, Ed25519-signed by that
approver key, structurally and cryptographically verifiable completely offline with no code from
this repo:

```bash
node <repo-root>/dist/src/cli.js verify receipt-chain.json --keyring keyring.json
# exit 0 = VALID (signature + hash-chain both check out against the published public key)
```

## Loopback-default security (verify this, don't take our word for it)

The relay refuses to bind anywhere except `127.0.0.1`/`::1`/`localhost` unless the caller explicitly
opts in with `unsafeListen: true` **and** `tlsTerminated: true` — see the bind guard at
`packages/relay/src/server.ts:59-72` (`listen()`) and the loopback allow-list at
`packages/relay/src/config.ts:42-46` (`isLoopbackAddress`, `LOOPBACK`). `run-local-stack.mjs` does
not set either override, so the socket this example opens can only ever be reached from the same
machine. Exposing a relay to the network is a deliberate, explicit, two-flag decision — never a
default.

## Auth + idempotency, exercised (not just asserted)

- **Auth**: every agent-facing route requires `Authorization: Bearer noa_agent_<secret>`; a missing
  or garbage bearer gets `401 AGENT_AUTH_REQUIRED` / `401 INVALID_AGENT_CREDENTIAL` (both scripts
  demonstrate this).
- **Idempotency**: `POST /v1/holds` requires an `Idempotency-Key`; replaying the same key with the
  same body returns the SAME `holdId` with `"idempotent":true` (never a duplicate hold); the same
  key with a *different* body is rejected `409 IDEMPOTENCY_CONFLICT`.

## Honesty — what this does and does not prove

- **Proven**: a non-Node HTTP client (curl, Python stdlib) can create a hold on the real relay,
  long-poll for a decision, receive a genuinely Ed25519-signed ALLOWED/BLOCKED receipt, and verify
  that signature completely offline against a published public key. Auth and idempotency are real
  relay code paths, not mocked.
- **Not claimed**: compatibility beyond the clients and paths shown here, human understanding,
  production readiness, or any particular approver-client topology. The local signer is test
  infrastructure, and its decision must not be represented as a human approval.
