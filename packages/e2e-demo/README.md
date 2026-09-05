# NOA public conformance harness

`noa-e2e-demo` is a private workspace package used to exercise public verification surfaces across
the receipt, approval-artifact, gate, relay, evidence, and signer packages. Despite the historical
package name, the current package is **not** a complete gate-to-device-to-executor product demo.

## What runs

```bash
npm run build:deps
npm run typecheck
npm test
```

The current test suite proves two bounded properties:

- the gate render path uses the same canonical projection input as the parameter commitment, and
  the independently exposed gate and evidence key resolvers agree on activation and retirement
  semantics; and
- the evidence wrapper preserves checkpoint-key retirement and does not grant checkpoint authority
  to an unrelated approver key.

See [`test/keyring-resolver-parity.test.ts`](test/keyring-resolver-parity.test.ts) and
[`test/verification-surface.test.ts`](test/verification-surface.test.ts).

## HTTP example

[`examples/http-agent`](examples/http-agent/) starts a loopback relay and local test signer, then
shows how shell and Python clients can create and wait on a hold, exercise authentication and
idempotency, receive a signed decision receipt, and verify it offline.

The local signer follows a deterministic example policy. It is test infrastructure, not a human,
production approver, identity provider, or deployment architecture.

## Non-claims

This package does not establish a production device integration, protected mobile key custody,
human understanding, boundary-owned provider dispatch, provider completion, or a physical-world
outcome. Cross-repository or private integrations must run in their owning repository against exact
pinned public bytes; they are not reconstructed here through aliases or copied device drivers.
