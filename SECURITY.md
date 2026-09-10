# Security Policy

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/NordenSoft/noa-mandate-core/security/advisories/new)
for encrypted, repository-scoped coordination. If GitHub reporting is unavailable, email
**toratoraman@gmail.com** with details and a proof-of-concept if you have one. Please do not open a
public issue for a security report. We aim to acknowledge within 72 hours. This is an early-access
project; coordinated disclosure is appreciated.

## Supported versions

The `published` cells are badges that read the npm registry when this page is rendered. Verify the
registry and release artifact directly before relying on a version claim.

| package | published | supported |
|---|---|---|
| `noa-receipt` | [![noa-receipt on npm](https://img.shields.io/npm/v/noa-receipt)](https://www.npmjs.com/package/noa-receipt) | yes — fixes land here |
| `noa-mcp-adapter-core` | [![noa-mcp-adapter-core on npm](https://img.shields.io/npm/v/noa-mcp-adapter-core)](https://www.npmjs.com/package/noa-mcp-adapter-core) | yes |
| `noa-mcp-proxy` | [![noa-mcp-proxy on npm](https://img.shields.io/npm/v/noa-mcp-proxy)](https://www.npmjs.com/package/noa-mcp-proxy) | yes — **upgrade from 0.3.1**, see below |
| older releases | — | **no**. Upgrade to the current supported release shown above; compatibility and security changes are recorded in `CHANGELOG.md`. |

⚠ **The `noa-mcp-proxy` release published as 0.3.1 shipped a vulnerable `@hono/node-server`. Do not use that release; upgrade to the current supported release shown above.**

0.3.1's manifest declared `overrides: { "@hono/node-server": "^2.0.5" }`, and **npm ignores
`overrides` declared by a dependency** — they apply in the root project only. So the entry read as
a pin and protected nobody. Measured in a clean directory against 0.3.1: `@hono/node-server`
**1.19.17** (GHSA-frvp-7c67-39w9, path traversal), `npm audit` **3 moderate**.

Measured the same way against 0.3.2, after publication on 2026-08-04: `@hono/node-server` **2.1.0**,
`npm audit` **0 vulnerabilities at every severity**. The fix required moving
`@modelcontextprotocol/sdk` to 1.30.0 as well — 1.29.0 permits only `^1.19.9`.

`noa-mcp-adapter-core` is behaviour-identical across 0.3.1 and 0.3.2; it moved only because the two
packages release in lockstep. (The version is not typed next to the package name on purpose: a
literal there reads as a claim about the CURRENT release and goes false at the next one, which is
the same decay the table above removes.)

0.3.1 has not been unpublished. It is a real release whose own description is correct about the
forgery fixes it shipped and wrong about this one, which is why the correction is written where an
auditor would look.

**Unpublished modules are out of scope for the supported-version table but not for a report.** A
finding in any code in this repository is welcome even when there is no released version to name.

## Design stance

This is a **trust layer**, so it is built to be boring and hostile-input-safe:

- **Zero runtime dependencies.** The verifier and library use only the Node standard library
  (`node:crypto`). Measured against the root `package.json` on 2026-08-04: **`dependencies` is empty**,
  and the four `devDependencies` (`@types/node`, `typescript`, `vitest`, `cbor2`) are build- and
  test-time only — none is imported or executed by shipped code, and none is installed by a consumer.
  (`cbor2` is used by the COSE interop tests; the library's own COSE path does not depend on it.)
  Nothing is pulled from the network at verify time. Smaller supply chain = smaller attack surface.

  ⚠ This bullet describes the **kernel**. `noa-mcp-proxy` is a server, not a verifier, and does have
  runtime dependencies — see its own manifest. Reading this bullet as covering every published package
  would be a mistake: it does not.
- **Strict parser, and no way around it.** Receipts are parsed by a hardened JSON parser
  (`safeParse`) that rejects duplicate keys, `__proto__`/`constructor`/`prototype` keys,
  floats/exponents, unpaired surrogates, and over-deep or over-large input. Since `0.6.0` there is no
  entry point that lets a caller skip it: `verifyChain`, `verifyCheckpoint` and
  `verifyReceiptCompliance` take `Uint8Array | string` **only**, and `verifyChainText` is a pure
  alias of `verifyChain`. Handing one a pre-parsed object returns `MALFORMED` — *"a security-sensitive
  document is bytes, never a caller-owned object"* — rather than trusting your parse.

  *This bullet used to warn that `verifyChain(value)` with a pre-parsed object left the strict-parse
  checks for the caller to perform. That was true through `0.5.0` and has been false since `0.6.0`;
  it understated the shipped boundary, which is the direction nobody files a bug about.*
- **Strict schema.** Unknown fields are rejected everywhere (`additionalProperties:false`).
- **Mandatory signatures.** Ed25519 signatures are required; the signing key id is bound into
  the hash; keys are pinned per `agent.id` within a chain.
- **Honest verdicts.** The verifier never silently upgrades trust: no keyring ⇒ `UNVERIFIED`
  (exit 1), not `VALID`; an unknown `kid` while a keyring **is** supplied ⇒ `TAMPERED` (no
  silent trust-on-first-use of attacker input); no checkpoint ⇒ an explicit tail-truncation
  warning; plus an always-on fork/equivocation caveat and a non-monotonic-timestamp warning.
- **Well-formed Unicode required.** Unpaired UTF-16 surrogates are rejected by both the
  canonicalizer and the parser (they would otherwise collapse to U+FFFD at the UTF-8 hashing
  step — a hash-collision / forgery channel).

## Known limits (see THREAT-MODEL.md)

Any temporary third-party advisory exception must be recorded in dated public release evidence with
an accountable maintainer, evidence, compensating controls, and a review deadline. An accepted
exception is not a claim that the dependency is safe.

- Tail-truncation is only detectable with a signed checkpoint, and the checkpoint is held to the
  same keyring trust root as receipts (an unauthenticated checkpoint ⇒ `TAMPERED`, never a faked
  tail check). Stronger equivocation resistance requires an external witness or anchor and is not
  established by this repository alone.
- `noa.guard()` is **advisory** unless installed where the action's credentials/write
  authority actually live; the MCP proxy is designed to **fail-closed**. Unmanaged tools are
  outside the trust boundary — document which tools are governed.
- Private-key custody is the operator's responsibility (use KMS/HSM in production). See
  [docs/trust-root-checklist.md](https://github.com/NordenSoft/noa-mandate-core/blob/main/docs/trust-root-checklist.md) for the practical key-generation,
  keyring-distribution, checkpoint, and rotation checklist.

## Cryptography

- Hash: SHA-256. Signatures: Ed25519 (`node:crypto`). Canonicalization: RFC 8785 (JCS),
  hardened to integer-only. Conformance vectors pin exact bytes across implementations.
- The keypairs under `conformance/` are **test-only fixtures** (a chain signing key plus a
  second "adversary" key used to build the key-pinning attack vector) — their private keys are
  public on purpose and must never be used for anything real.

## What this software does NOT prove

Every claim here is narrow on purpose. The consolidated, versioned, normative statement of what
receipts, signatures, approvals and evidence do **not** establish is [NON-CLAIMS.md](NON-CLAIMS.md).
It is the first thing to read before relying on any artifact this project produces.

Weakening or removing a non-claim is a reviewed event with its own rules (NON-CLAIMS.md §7), because
a removed non-claim is a new claim.
