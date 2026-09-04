# NOA Receipt — Threat Model

This document states the public protocol's security goals, trust boundaries, and residual risks. It
is not a security certification, deployment architecture, incident log, or promise that every threat
is closed. Normative claim limits are consolidated in [NON-CLAIMS.md](NON-CLAIMS.md).

## Security objective

For inputs accepted by a conforming verifier, a NOA receipt chain is intended to make unauthorized
changes to the supplied records detectable. Verification can establish byte integrity, signature
validity against caller-supplied trust material, and the specified chain relationships. It cannot by
itself establish that a statement is true, current, complete, understood by a human, or reflected in
the physical world.

## Assets and trust boundaries

- **Verification trust material:** keyrings, identity manifests, checkpoints, trust sets, and
  freshness policy are trusted inputs supplied out of band. Receipt bytes do not authenticate those
  inputs.
- **Signing keys:** compromise of a trusted private key lets its holder create authentic statements.
  Key custody, rotation, revocation, and recovery are deployment responsibilities unless a specific
  public profile says otherwise.
- **Untrusted inputs:** receipt and side-artifact bytes, storage, transport, remote-system reports,
  model/tool output, caller-provided identifiers, and clocks are untrusted until validated at their
  respective boundaries.
- **Verifier runtime:** code already executing in the verifier's process or language realm is outside
  the data-only threat boundary. A library cannot prove the integrity of its own compromised runtime.
- **Downstream action boundary:** a verifier result does not force an external system to honor it.
  Enforcement must live where the action authority or credentials are controlled.

## Attacker capabilities considered

The public conformance surface considers attackers that can alter, reorder, omit, duplicate, replay,
or replace supplied artifacts; choose hostile but syntactically plausible input; present unknown or
co-trusted keys; and exploit parser or canonicalization differences. Stronger attackers may control a
trusted signing key, trust-material distribution, the verifier runtime, or the downstream execution
path. Those stronger capabilities are residual trust assumptions, not silently treated as solved.

## Threats and controls

| ID | Threat | Public control | Remaining limit |
| --- | --- | --- | --- |
| T1 | Edit a receipt | Hash over canonical bytes plus signature verification | A trusted-key holder can author a new valid statement. |
| T2 | Reorder, splice, or remove a middle record | Sequence and previous-hash linkage | Removing only the tail needs a trusted checkpoint or external observation to detect. |
| T3 | Substitute a signing key mid-chain | Signing-key identifier is hash-bound and key continuity is checked | Initial attribution still depends on trusted key and identity inputs. |
| T4 | Corrupt or forge a signature | Strict Ed25519 verification against the supplied keyring | Key compromise and trust-material compromise remain decisive. |
| T5 | Parser or canonicalization disagreement | Strict JSON parsing, bounded input, integer-only JCS, and versioned vectors | Coverage is limited to published rules and vectors. |
| T6 | Duplicate keys, invalid Unicode, or unknown members | Reject duplicate keys, malformed Unicode, forbidden property names, and unknown schema members | Known opaque fields can still carry sensitive caller-provided data. |
| T7 | Cross-protocol signature reuse | Domain-separated signing input | Each new artifact type needs its own domain and conformance cases. |
| T8 | Cross-context or cross-tenant reuse | Signed scope fields and chain-consistency checks | Matching those fields to the relying party's expected context is caller policy. |
| T9 | Cross-agent impersonation by another trusted key | Optional identity manifest binds an agent identifier to allowed keys | Without that trusted manifest, attribution is to a key, not a real-world identity. |
| T10 | Replay or stale evidence | Caller-supplied checkpoint, freshness, and expected-head policy | A valid artifact is not automatically current. |
| T11 | Tail truncation or equivocation | Signed checkpoints and optional independently obtained witness material | A verifier cannot authenticate that it received every witness view. |
| T12 | False policy inputs or false action reports | Authenticate the carrier and keep input provenance explicit | Consistency over supplied inputs is not external truth or proof of execution. |
| T13 | Verifier-runtime compromise | Prefer a separate verifier process and independently re-checkable artifacts | A compromised caller can still discard or misreport a correct result. |
| T14 | Configuration replacement | Fail closed on malformed configuration and protect trust inputs outside the governed process | Mutable configuration is not tamper-evident merely because its path is checked. |
| T15 | Denial of service | Size, depth, count, and timeout bounds | Bounded refusal remains possible and should be observable. |

The conformance corpus is evidence only for the exact implementations, vectors, comparison topology,
and revision that ran. Five language-specific verifier implementations currently provide measured
cross-implementation verdict parity for covered vectors; organizational independence and independent
decision paths are not established. See [conformance/MATRIX.md](conformance/MATRIX.md).

## Residual risks and required operator decisions

### Completeness and freshness

A valid prefix remains valid after a tail is removed. A checkpoint can detect truncation only when it
is authentic, current enough for the relying party's policy, and compared with the intended chain.
Witness and timestamp artifacts add observations; they do not prove that every observation was
delivered. Offline verification cannot infer freshness from silence.

### Key and identity lifecycle

The keyring is a root of trust. Rotation, revocation, recovery, and distribution need explicit policy.
An unknown key must not become trusted from attacker-controlled input. An identity manifest can bind
an `agent.id` to allowed keys, but the manifest is itself a trusted input and does not prove a
real-world person's identity.

### Runtime and consumption integrity

The in-process API does not claim resistance to code already executing in the same JavaScript realm.
Moving verification into a separate process can protect computation from a data-only document, but it
does not force a compromised caller to honor the verdict. Where a decision is consequential, the
relying party should verify in a process and trust context it controls, and enforcement should occur
at the authority boundary.

### Configuration integrity

Filesystem ownership, permissions, and safe-open rules can reduce accidental or path-redirection
risk. They do not make mutable policy or trust configuration cryptographically authentic. A deployment
that requires tamper evidence must authenticate configuration with trust material stored outside the
process being constrained.

### Truth, execution, and the physical world

A receipt records a signed statement. It does not prove that an external side effect occurred, did
not occur, settled exactly once, or produced a physical outcome. Those claims need evidence from the
relevant system of record and an explicit correlation contract. A missing response is not proof that
nothing happened and must not be treated as retry-safe without independent evidence.

### Privacy

Hashes and opaque identifiers can still enable correlation or dictionary attacks. Do not place
personal data, customer data, secrets, or low-entropy sensitive values in public artifacts. Use a
documented keyed-digest or disclosure policy when equality leakage matters.

## Verification guidance

- Pin the expected protocol/profile revision and trust inputs.
- Treat JSON Schema as structural assistance, not the complete normative validator.
- Run positive and negative vectors, including malformed and adversarial inputs.
- Keep authorization, execution, verification, completeness, settlement, and physical outcome as
  separate claims.
- Preserve stable error and exit semantics; never convert unknown or partial evidence into success.
- Record which checks were requested, performed, skipped, or could not be completed.

## Clean-room / scope boundary

This public repository contains the receipt protocol, conformance material, language-specific
verifiers, and generic integration surfaces. It must not contain private product implementation,
managed-service topology, customer material, internal operations, proprietary strategy, or research
plans.

The public surface contains:

- no application-specific cognition, memory, planning, or model-routing implementation;
- no tenant/customer data, credentials, production endpoints, or real private keys (published test
  fixtures are explicitly non-production); and
- no proprietary policy content: a policy result may cross the boundary as a documented value, while
  the private engine that produced it does not.

A contribution that crosses this boundary is out of scope. Public protocol semantics, conformance
evidence, and generic integration contracts remain appropriate Apache-licensed material.
