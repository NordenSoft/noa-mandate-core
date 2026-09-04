# Post-Quantum Transition and Crypto-Agility Considerations

> **Status:** public design analysis, not an implemented transition profile. `noa.receipt/0.1` uses
> Ed25519 and is not claimed to be post-quantum secure. A future profile requires its own normative
> revision, algorithm identifiers, vectors, compatibility rules, and release evidence.

## 1. Current protocol state

The `noa.receipt/0.1` signature object has an `alg` member, but the frozen schema accepts only the
current Ed25519 identifier. Conforming verifiers reject unknown algorithms. The algorithm identifier,
key identifier, receipt body, and chain fields are covered by the signed/hash-bound representation,
so an attacker cannot silently relabel an Ed25519 signature as another algorithm.

This is algorithm identification, not complete crypto agility. Supporting another algorithm requires
an explicit specification change and implementations that agree on:

- the algorithm identifier and parameter set;
- public- and private-key encoding;
- signature encoding and canonicality rules;
- signing-domain and exact preimage;
- verification, error, and downgrade behavior;
- key rotation, revocation, recovery, and mixed-chain policy; and
- positive, negative, malformed, and cross-implementation vectors.

## 2. Compatibility constraints

Three compatibility axes must remain distinct:

1. the receipt wire-format identifier (`spec`);
2. the implementation/package version; and
3. any carrier-specific algorithm identifier, such as a COSE protected header.

A future algorithm must not be added to frozen `noa.receipt/0.1` by silently widening the schema.
Old verifiers are required to reject an algorithm they do not understand. That fail-closed behavior is
a security property and means an in-band algorithm change needs a new, versioned profile.

Existing Ed25519 receipts must remain verifiable under their original rules. A transition document
must say whether mixed algorithms are allowed within one chain, how the first new key is authorized,
and which verifier versions are expected to read each artifact.

## 3. Threat framing

Post-quantum signature migration addresses future signature forgery after a cryptographically
relevant quantum capability exists. It does not solve:

- confidentiality exposure or harvest-now-decrypt-later risk for encrypted payloads;
- compromise of signing devices or authorization workflows;
- false statements signed by an authentic key;
- stale, replayed, incomplete, or selectively disclosed histories; or
- trust-anchor and governance compromise.

Confidentiality requires a separately specified encryption/KEM transition. Signature migration must
not be marketed as a complete post-quantum security solution.

## 4. Transition patterns

The following patterns are candidates for a future versioned profile. This document does not select or
schedule one.

### 4.1 New in-band algorithm in a new receipt revision

A new `spec` revision can define an expanded algorithm registry and exact verifier dispatch. This is
simple after cutover but creates no overlap for old verifiers: they must reject the new receipt.

### 4.2 Detached parallel signature

A separately versioned side artifact can bind a post-quantum signature to the exact canonical receipt
or chain head while the frozen receipt remains Ed25519-verifiable. This can provide an overlap window,
but only if the side artifact defines its own canonical bytes, signature scope, correlation, downgrade
rules, and lifecycle. Its existence does not upgrade the original receipt's algorithm claim.

### 4.3 In-band multiple or composite signatures

A future schema could carry multiple signatures or a composite algorithm. This increases artifact
size and parsing complexity and must specify whether all or any listed signatures are required.
It is not compatible with the frozen `0.1` schema and therefore needs a new receipt revision.

### 4.4 External timestamp or witness evidence

External observation can show that an Ed25519-signed artifact existed before a particular time. It
does not make Ed25519 post-quantum secure, authenticate the receipt's own timestamp, or replace a
post-quantum signature profile.

## 5. Downgrade and negotiation requirements

A future verifier must fail closed when:

- the receipt revision requires an algorithm it does not support;
- an algorithm identifier is missing, ambiguous, unprotected, or inconsistent with the key;
- a transition artifact is detached from the wrong receipt, chain, or revision;
- a required classical or post-quantum branch is absent or invalid;
- a key transition lacks the required endorsement; or
- policy requires the stronger profile but only a legacy artifact is presented.

Negotiation must be based on authenticated, versioned policy rather than an attacker-controlled field.
Verifiers should report which branches were required, checked, skipped, or unsupported.

## 6. Key lifecycle

Algorithm transition and key rotation are related but not identical. A profile must define:

- how a new algorithm/key is authorized by the existing trust root;
- how compromise recovery works when the old key cannot safely endorse a successor;
- retirement and revocation semantics for both algorithms;
- whether historical signatures remain acceptable after retirement;
- how offline verifiers obtain updated trust material; and
- how mixed classical/post-quantum chains are evaluated.

Trust-on-first-use from receipt bytes is not an acceptable migration mechanism.

## 7. Size and implementation considerations

Post-quantum public keys and signatures can be materially larger than Ed25519 values. A future profile
must measure maximum artifact size, parser and memory bounds, transport framing, storage growth,
verification latency, batch behavior, and denial-of-service impact on each supported implementation.
No platform or hardware-backed custody claim is made without measurements for that platform and key
provider.

## 8. Conformance requirements

Before a transition profile can be called implemented, it needs:

- normative canonical-byte and signing-input examples;
- positive vectors for every allowed transition state;
- negative vectors for downgrade, removal, substitution, mixed-key, wrong-revision, malformed-key,
  malformed-signature, replay, and retirement cases;
- unchanged legacy vectors proving original receipts retain their defined behavior;
- stable verdict and error semantics; and
- cross-implementation results bound to exact revisions and toolchains.

Language count alone does not establish implementation independence. Any independence claim requires
evidence about requirements, decision paths, code reuse, dependencies, and organizational control.

## 9. Public non-claims

- Current NOA receipts are not quantum-safe or post-quantum secure.
- No post-quantum receipt profile is implemented or activated by this document.
- A detached experimental artifact does not change the security properties of the frozen receipt.
- External timestamps do not prove the receipt's signer timestamp or the truth of its content.
- Algorithm agility does not solve authorization, execution, completeness, or physical-world proof.

## References

- NIST FIPS 204, *Module-Lattice-Based Digital Signature Standard (ML-DSA)*
- NIST FIPS 203, *Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)*
- RFC 8032, *Edwards-Curve Digital Signature Algorithm (EdDSA)*
- RFC 9052, *CBOR Object Signing and Encryption (COSE): Structures and Process*
- RFC 9864, *Fully-Specified Algorithms for JOSE and COSE*
