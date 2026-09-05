# ADR-0007 — Device enrolment through pairing

| Field | Value |
|---|---|
| **Status** | **PUBLIC RELAY MECHANISM IMPLEMENTED.** Integration with any private or production device application is not claimed. |
| **Scope** | How an approver device obtains relay credentials without anonymous production enrolment. |

## 1. Problem

Production relay configuration requires an enrolment secret for credential-minting routes. Giving
the same long-lived bearer secret to every device would be unattributable and difficult to rotate.
Anonymous enrolment is therefore confined to an explicit loopback-only development mode and is not a
production joining path.

## 2. Decision

An operator-authenticated pairing ceremony may issue a short-lived, single-use device token. The
device redeems that token at the dedicated device-pairing route and receives its relay credential.
The token projects the tenant and device-key identity established by the ceremony; it is not an
agent token and not a fleet-wide enrolment secret.

This public record specifies and tests the relay side. It does not assert that a particular device
application, deployment, or operator ceremony consumes the mechanism.

## 3. Binding constraints

1. **Device and agent tokens are disjoint.** Each redemption route refuses the other token type.
2. **Issuance remains operator-gated; redemption has a dedicated route.** The token is the redemption
   credential, so body-dependent exceptions are not added to the general enrolment gate.
3. **Tenant identity is carried onto the device record.** A device that declares a tenant can be
   claimed only by that tenant; missing tenant identity does not gain production authority.
4. **The token is bound to the device key identifier.** A different key cannot redeem a leaked
   token.
5. **The token has its own bounded TTL.** Expired tokens are refused.
6. **Tokens are hashed at rest.** Plaintext is returned only at issuance and is not stored as the
   lookup key.
7. **The carrier is outside the frozen pairing document.** Deployment integrations must preserve
   versioning and the mandatory key binding; this repository does not define a private application
   bundle format.
8. **The honest property is single-use and short-lived, not revocable.** No token-revocation API is
   claimed.

## 4. Public implementation surface

The relay implements issuance, redemption, tenant binding, token hashing, expiry, and type
separation in:

- [`packages/relay/src/server.ts`](../packages/relay/src/server.ts)
- [`packages/relay/src/engine.ts`](../packages/relay/src/engine.ts)
- [`packages/relay/src/store.ts`](../packages/relay/src/store.ts)
- [`packages/relay/src/config.ts`](../packages/relay/src/config.ts)

The public tests cover the successful real-HTTP path and negative controls:

- [`packages/relay/test/adr0007-e2e-http.test.ts`](../packages/relay/test/adr0007-e2e-http.test.ts)
- [`packages/relay/test/device-pairing-enrolment.test.ts`](../packages/relay/test/device-pairing-enrolment.test.ts)
- [`packages/relay/test/device-tenant-claim.test.ts`](../packages/relay/test/device-tenant-claim.test.ts)
- [`packages/relay/test/untenanted-enrolment-dev-only.test.ts`](../packages/relay/test/untenanted-enrolment-dev-only.test.ts)

## 5. Required refusals

The mechanism is conformant only if it refuses:

- an agent token at the device route and a device token at the agent route;
- redemption by a key other than the bound device key;
- second redemption of a consumed token;
- redemption after expiry;
- token issuance without tenant or device-key binding; and
- claim by a different or tenant-less principal when the device declares a tenant.

The suite also requires a successful issuance-and-redemption control so a route that refuses
everything cannot pass.

## 6. Residuals and non-claims

Device enrolment authenticates a device key to the relay. It does not by itself establish the human
identity behind that device, a tenant's governance decision, protected device-key custody, a trusted
notification channel, or an independent trust root. Development-only anonymous enrolment remains a
separately labelled loopback facility and must not be represented as this production-oriented
pairing path.
