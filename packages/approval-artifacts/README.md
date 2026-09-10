# noa-approval-artifacts

The public side-artifact protocol for approval workflows: frozen JSON shapes,
signature/`refHash` conventions, and positive/negative conformance vectors shared by gates, relays,
approver clients, and evidence verifiers.

The receipt core stays **frozen** in `noa-receipt`; side artifacts do not add receipt fields. These
artifacts are the *non-receipt* half of the protocol — where custody-tier, decision reasons, holds,
grants, manifests, and pairing live. Zero runtime dependencies (`node:crypto` only).

## Why a separate package (location decision)

These artifacts need a **shared, dependency-light home** that gates, relays, approver clients, and
verifiers can all import, without:

- bloating the deliberately-minimal signing core `noa-signer` (`packages/signer-core`, with a hard
  zero-platform-SDK boundary), or
- adding an app-layer protocol to the **frozen** `noa-receipt` published package.

So this is its own package, mirroring the monorepo convention (`packages/<name>` + `node --test`) and
`noa-receipt`'s `schema/` + `conformance/` layout. It **reuses** the receipt signing *pattern*
(domain-tagged Ed25519 over `JCS(...)`) with distinct per-artifact domain tags.

## What ships

- `schema/*.schema.json` — 12 machine-readable schemas (`additionalProperties:false` everywhere), the
  enforced structural validator (executed directly by `src/schema-eval.ts`, a tiny zero-dep
  JSON-Schema-subset evaluator, so the shipped schema and the validator can never drift):
  Hold Envelope, Decision, Key Manifest, Key Delegation, Execution Grant, Execution Consumption,
  Execution Uncertainty, Hold Resolution, Pairing (CHALLENGE/CONFIRMATION/ACCEPTED, one discriminated
  union), Pairing Confirmation, and the two **unsigned** HPKE-AEAD blobs (Encrypted Display, Encrypted
  Reason).
- `conformance/<artifact>/` — the vectors: **1 valid + at least 7 rejection** per signed domain (the Hold
  Envelope and Decision carry an additional security regression); a valid + 7 structural/binding rejections for the
  two unsigned blobs. `keyring.json` is the shared trust root; `INDEX.json` the counts.
- `src/` — the reference verifier (`verifyArtifact`), the three `refHash` rules, the signing helper
  (`signArtifact`), the domain registry, and the schema evaluator.

Run the gate: `npm test` (build → regenerate vectors deterministically → `node --test`). A single
mismatch fails the build.

## The signature and `refHash` conventions

- **Signing preimage:** `UTF8("<DOMAIN>:") ++ SHA256(JCS(document_without_sig))` — the WHOLE `sig`
  object is excluded from the hashed bytes (distinct from a receipt, which keeps `sig.alg`/`sig.kid`
  and strips only `sig.value`). Each artifact has its own domain tag; all are mutually distinct and
  disjoint from `NOA-Receipt-v0.1-sig` / `NOA-Checkpoint-v0.1-sig`.
- **Side-artifact `refHash` (rule b):** `"sha256:" + SHA256(JCS(X including its sig))` — the hash of the signed
  bytes as received. Used for every side-artifact `*Hash` reference.
- **Rule a (receipt reference):** a receipt is referenced by its own `chain.hash`
  (`SHA256(JCS(receipt without chain.hash and sig.value))`).
- **Unsigned-blob binding (rule c):** `transcriptHash` and `displayCiphertextHash` hash the WHOLE object as-is
  (nothing stripped) — so a relay-added `recipients[]` entry breaks the parent's signed hash.
- **Activation and revocation:** a signed artifact's own timestamp is never evidence that its signing
  key was active. When a `KeyEntry` declares `validFrom`, caller-supplied `authorizationTime` (falling
  back to caller-supplied `now`) is required for acceptance. The artifact's claimed event time is
  reject-only: a claim before `validFrom` refuses, but can never activate the key. Any non-null
  `revokedAt` is refused outright because signer-chosen time cannot prove history. A static entry
  with no lifecycle fields remains always-active for compatibility.
- **Signer identity:** self-identifying signed artifacts enforce their declared signer field
  (`gateKid` or `approverKid`) against `sig.kid` inside `verifyArtifact`; callers cannot accidentally
  omit this binding and authorize one principal's receipt with another principal's Decision.

## The 7 rejection classes

`tampered-content · cross-artifact-hash-substitution · wrong-tenant · wrong-nonce · expired ·
wrong-key · unknown-property` (Hold Envelope adds `recipients-swap`). Where an artifact lacks the
literal field for a slot (e.g. a tenant-LESS Decision has no `tenant`), the slot is realized by the
genuine, spec-grounded binding that enforces the same property for that artifact — e.g. a Decision's
tenant is checked **transitively** through its `holdEnvelopeHash` and the referenced envelope's
`tenant`; a Key Delegation's cross-hash slot is a delegated-signer substitution; a manifest's
`wrong-key` is a gate-key or undelegated signature. Each vector's `description` and
`rejectionClass` state the concrete mutation and the check that catches it.

## Signature encoding

- **Signature encoding = standard base64**, matching the receipt/checkpoint ecosystem and
  `noa-signer`'s `bytesToBase64`. Using one encoding avoids client-specific special cases.

## Scope boundary

This package defines and conformance-tests the **shapes, signatures, and `refHash` bindings**. Full
stateful semantics — approver-client verification order, outcome-keyed Evidence Bundle verification,
anti-rollback manifest-version monotonicity across holds, and HPKE encrypt/decrypt round-trips — are
the consuming services' responsibility; `verifyArtifact` is the shared per-artifact core
they build on. HPKE keys in vectors are opaque test strings (no HPKE round-trip is performed here).

## What this package does not claim

[`NON-CLAIMS.md`](https://github.com/NordenSoft/noa-mandate-core/blob/main/NON-CLAIMS.md) is the normative record of what NOA does **not** do. It is
not shipped inside this tarball, so it is linked by URL rather than by a relative path that would
404 for exactly the reader who needs it.

Read it before you rely on this package for anything that matters. A boundary you have to infer
from silence is a boundary you will get wrong, and the failure this project is built around is a
forged or misattributed approval — not downtime, which is the one people plan for.

Alongside it: [`THREAT-MODEL.md`](https://github.com/NordenSoft/noa-mandate-core/blob/main/THREAT-MODEL.md) for what is defended against, and
[`SECURITY.md`](https://github.com/NordenSoft/noa-mandate-core/blob/main/SECURITY.md) for which versions get fixes and how to report a finding.
