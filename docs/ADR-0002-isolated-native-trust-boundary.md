# ADR-0002 — Isolate verdict-critical work from the caller realm

| Field | Value |
|---|---|
| **Status** | **HISTORICAL / SUPERSEDED IN PART by [ADR-0003](ADR-0003-enforcement-boundary.md).** The claim correction in §3 remains current. |
| **Scope** | Public architecture record for process isolation and a native trust boundary. |
| **Implementation evidence** | The TypeScript wire-protocol rehearsal is implemented; an isolated native enforcement kernel is **not** implemented by this repository. |

## 1. Problem

JavaScript code executing in the caller's realm shares mutable runtime state with the caller and its
dependencies. Capturing selected intrinsics is useful hardening, but it cannot establish that every
operation used by a verifier was captured before hostile code could alter it. A package loaded into
that realm therefore cannot prove immunity from a pre-load or same-realm attacker.

This is a boundary problem, not an invitation to extend an allowlist of primitives indefinitely.

## 2. Recorded direction

The architecture explored moving verdict-critical parsing, canonicalization, policy evaluation,
cryptography, and state-machine decisions into a separate native process with a bytes-only,
length-framed protocol. TypeScript would remain an untrusted transport and integration layer.

That direction does not by itself solve enforcement. A caller that can ignore or replace a correct
verdict can still invoke an ungoverned target. [ADR-0003](ADR-0003-enforcement-boundary.md) therefore
supersedes the verdict-provider goal with a stricter question: which authority actually controls the
credential, capability, or dispatch that makes the governed effect possible?

## 3. O-1 claim withdrawal

The TypeScript implementation **must not claim intrinsic-immunity**. A host or dependency can alter
shared runtime state before this package is evaluated, and a library cannot enforce that it was the
first code loaded into its host process.

The current intrinsic capture and hostile-runtime tests are defence in depth. They can detect and
prevent measured regressions, but they are not a security boundary and do not turn same-realm
TypeScript into trusted execution.

Consequences:

1. A same-realm TypeScript `ALLOW` or `DENY` is not protected from a caller that controls the realm.
2. A signed response does not help if the verification and consumption of that response happen in
   the same compromised realm.
3. Process isolation can protect computation from an application dependency graph, but only
   boundary-owned authority or target-side validation can protect the governed effect.

## 4. Target trust boundary

### 4.1 Untrusted side

The host application and TypeScript integration may frame requests, parse transport responses,
manage process lifecycle, and expose ergonomic APIs. None of those operations may be cited as
verdict integrity against a hostile caller realm.

### 4.2 Native-kernel trusted computing base

A future hardened native boundary would need to own every operation on which its decision depends:

- bounded, duplicate-key-rejecting byte parsing;
- canonical encoding and Unicode validation;
- receipt, checkpoint, policy, COSE, and federation validation;
- hashing, signature preimages, key validation, and trust-root resolution;
- state-machine decisions, replay protection, and durable terminal state;
- protected signing or dispatch authority, with keys held outside the caller realm.

The boundary would also require authenticated provisioning, binary identity, key rotation,
revocation, timeouts, resource limits, recovery, and rollback. A separate process without those
properties is only isolation, not a hardened kernel.

## 5. Stage 0.5 protocol rehearsal

The current `noa --serve` surface and
[`kernel-wire-protocol.md`](kernel-wire-protocol.md) exercise framing, correlation, error taxonomy,
and signed response envelopes. Conformance vectors live in
[`conformance/ipc-rehearsal`](../conformance/ipc-rehearsal/).

This rehearsal deliberately uses same-realm TypeScript and a trust-on-first-read ephemeral key. It
is executable protocol evidence, but it is **not** the isolated native kernel and is **not** an
enforcement boundary.

## 6. Verification criteria for a future hardened implementation

A future implementation must independently prove, at exact bytes and runtime configuration, that:

1. the caller and boundary do not share verdict-critical mutable state;
2. requests and responses are authenticated against an out-of-band trust root;
3. malformed, oversized, replayed, stale, and mismatched messages fail closed;
4. the governed effect cannot bypass boundary-owned dispatch or target-side capability validation;
5. private keys and provider credentials are unavailable to the caller;
6. restart, timeout, retry, and unknown-after-dispatch states preserve authorization and
   idempotency; and
7. an independent implementation passes the same published positive and negative vectors.

## 7. Non-claims

This ADR is not evidence of a native kernel, protected key custody, provider enforcement,
deployment, production use, or protection against a compromised operating system or target. The
implemented public artifact is the Stage 0.5 rehearsal only.
