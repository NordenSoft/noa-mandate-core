# Vault verification profile 0.1

This is a normative wire specification and conformance corpus. It does not install a
vault guard or supply a production transaction adapter. MUST, MUST NOT and SHOULD
express requirements on implementations of this profile. The existing receipt,
hold, decision and execution-grant formats remain unchanged.

## 1. Authority and scope

The vault is the authoritative owner of the protected state transition. It MUST
obtain its tenant, exact `vaultId`, owner-root kid and public key through local
administrative installation. Its local store holds two separately root-signed
statements: `noa.vault-approver-set/0.1` identifies keys, and
`noa.vault-class-policy/0.1` determines permitted actions. Neither a console's key
manifest nor an action-class enrolment nor a delegation substitutes for either
statement. The request carrier cannot supply or override the trust store.

Only an execution-signer key in the current pinned set may sign a grant. A console
or delegated identity is not an execution signer by virtue of its delegation.
Installation MUST exclude console/delegated keys from the set, including aliases
for the same public key. The root holder MUST establish this exclusion during the
key-confirmation ceremony: signatures and set membership alone cannot tell the
vault whether a listed key is also held by a console or used under a delegation.
The verifier enforces the resulting pins, not independent custody discovery.
The root, guard, probe, Gate and approver roles MUST NOT
share a key or kid. A Gate may hold both hold-signer and execution-signer roles.
A standby key has no broader powers than its listed roles.

This profile defines the ledger-transfer binding already specified in
[ledger-transfer-spec.md](../../docs/ledger-transfer-spec.md) and the diagnostic
binding in section 8. A verifier MUST refuse other action classes until it has an
explicitly supported, pinned specification for them; a root signature alone does
not install executable projection code.

## 2. Wire documents, bytes and cryptography

The six schemas in `schema/noa-vault-*.schema.json` and
`schema/noa-device-cosignature-0.1.schema.json` use JSON Schema 2020-12. References
resolve against schema `$id`s; `noa-receipt-0.1.schema.json` is the unchanged
[schema supplied by the receipt core](../../schema/noa-receipt-0.1.schema.json).
A consumer MUST load these from its trusted package, never fetch a schema URL
from request data. Objects reject unknown members at every level. The carrier's
`parameters` is a closed union of the two supported action shapes, selected
semantically by the deferred receipt's `action.canonical`.

Parsing MUST use the existing strict JSON boundary: well-formed UTF-8, no BOM,
no duplicate or prototype-sensitive object keys, no lone surrogates, depth at
most 64 and total document size at most 16 MiB. Numbers are safe integers; floats
and exponent notation are refused. Whitespace and object member order need not
be canonical on ingress. All signing and hashing operate on RFC 8785 JCS of the
parsed value, never the original whitespace. Array order is preserved.
Timestamps MUST denote real instants. Profile time calculations use UTC instants
with at most millisecond precision and refuse leap seconds or finer precision;
this narrows admission here without changing the general receipt format.

The existing side-artifact signing construction is reused:

```
message = UTF8(domain + ":") || SHA256(UTF8(JCS(document without the entire sig)))
refHash = "sha256:" + lowerhex(SHA256(UTF8(JCS(entire signed document))))
```

| Document | Domain | Algorithm / signer |
| --- | --- | --- |
| `noa.vault-approver-set/0.1` | `NOA-VaultApproverSet-v0.1-sig` | `ed25519`, installed owner root only |
| `noa.vault-class-policy/0.1` | `NOA-VaultClassPolicy-v0.1-sig` | `ed25519`, installed owner root only |
| `noa.vault-approver-join/0.1` | `NOA-VaultApproverJoin-v0.1-sig` | `ed25519`, joining decision key |
| `noa.vault-authority-bundle/0.1` | none | unsigned carrier |
| `noa.vault-result/0.1` | `NOA-VaultResult-v0.1-sig` | `ed25519`, pinned guard key |
| `noa.device-cosignature/0.1` | `NOA-DeviceCosignature-v0.1-sig` | `ES256`, pinned device co-sign key |

Existing domains, `ed25519` spelling, strict Ed25519 key/signature checks and
canonical padded standard base64 encoding are unchanged. Ed25519, X25519 and
P-256 public keys use base64 of canonical DER SPKI, with the actual algorithm
checked after decoding; an arbitrary DER key is not accepted. TLS and public-key
pins hash decoded canonical SPKI bytes, not their base64 text. Co-signatures use
ES256 (P-256 with SHA-256), the standard 64-byte, big-endian `R || S` form from
[RFC 7518 section 3.4](https://www.rfc-editor.org/rfc/rfc7518#section-3.4), encoded
as standard base64 like the other artifacts. This is not a JWS wrapper. ES256
signs the message above with SHA-256; it does not replace any Ed25519 signature.
Only valid curve points and scalars `1 <= R,S < n` are accepted.

Receipt references always use **rule a**, the receipt's verified `chain.hash`:
remove `chain.hash` and `sig.value`, retain `sig.alg` and `sig.kid`, JCS then
SHA-256. Receipt signatures use `NOA-Receipt-v0.1-sig` over that hash input.
Side-artifact references always use **rule b**, including the complete signature.
A receipt's rule-b hash MUST NOT substitute for its rule-a reference.
Unsigned display bindings use the existing whole-object rule c.

`subjectHash` in a detached co-signature is the rule-b hash of the signed subject;
`subjectSpec` distinguishes a decision from a join. `approverKid` and `sig.kid`
MUST both name the subject's approver. The key is that approver's
`cosignPublicKey`, not its Ed25519 decision key. Detached join co-signatures avoid
a circular hash: the join contains no co-signature of itself.

## 3. Installation, updates and revocation

Local installation caps are 2,592,000 seconds for each set and policy, and at most
60 seconds of skew. Normal grants default to at most 600 seconds; approval age
to at most 900 seconds; emergency grants to at most 300 seconds. A class may
narrow these limits. Extending them requires a separately reviewed profile and
explicit administrative reinstallation; an incoming document cannot raise them.

Both statements MUST have the installed tenant/vault identity and verify directly
with the installed root kid **and key** (`VV_ROOT_REQUIRED`). A valid delegated
signature is insufficient. Times MUST satisfy `issuedAt <= notBefore < expiresAt`;
`issuedAt <= now + skew`, `notBefore <= now`, and `now < expiresAt` are required
before activation. Expiry has no grace period. Excess lifetime for either
statement yields `VV_SET_LIFE`; invalid structure/coherence yields
`VV_POLICY_INVALID`. Skew MUST remain within the local installation cap.

Version 1 has a null predecessor and can be installed only into an empty store.
Every later version is exactly the current version plus one and carries the
current signed document's rule-b hash. Equal versions, skipped versions,
rollbacks and forks yield `VV_SET_ROLLBACK`. A kid MUST retain the same public key
across all retained history (`VV_KEY_REUSE`), including after removal. Set and
policy versions advance independently, under the same serialization boundary.
An incompatible set/policy pair MUST NOT become active.

Installation validates unique kids (including the probe kid), canonical public-key identities, class names,
role entries, required approvers and emergency eligible approvers. Quorum MUST be
attainable with distinct keys and device IDs. Aliasing one key under two kids
cannot increase quorum. `requiredApprovers` MUST be a subset of the current set.
Ledger limits contain both `maxAmount` (positive decimal integer string) and
`unit: "XTS"`; probe limits are empty. Unknown limit members are refused, not
ignored. Each class's audience member and both projection identities MUST match
its supported binding. `probe` is true only for `noa.vault.probe`.

An emergency policy identifies a separate class, its covered normal classes,
eligible approvers, quorum at least two, grant cap and limits. Its limits cannot
exceed any covered class's limits, and it cannot broaden targets, audience or
approver eligibility. This revision specifies no executable emergency action
projection: implementations MUST reject activation of a non-null `emergency`
with `VV_POLICY_INVALID` until a separately specified binding can enforce these
constraints. This also applies when installing a set against such a policy. It MUST NOT
be interpreted as permission to bypass ordinary verification.

Joins are proof of possession, not membership. The joining key verifies its own
statement with `sig.kid == kid`. The root holder confirms the key through an
independent local channel before signing a set entry whose `joinHash` binds that
join. Tenant, vault, keys, device identity and custody fields MUST agree. A
hardware claim requires independently checked attestation of the exact P-256
co-sign key and a detached join co-signature. Its `deviceId` is the SHA-256 SPKI
pin of that key; `attestationDigest` hashes JCS of the DER certificate array.
Software-native entries carry null co-sign key and attestation digest. A schema
or self-signed join cannot establish hardware custody or attestation freshness.

Removing an approver in a new set revokes it. Local suspension and freeze can
only narrow authority, persist across restarts and set updates, and are checked
at commit. Only a root-signed `liftSuspensions` entry matching both kid and SPKI
hash lifts a suspension. Install/update, suspend and freeze are local admin
operations; the Gate request endpoint MUST expose no route to perform them.
The local suspension record retains both kid and SPKI hash. An absent or
nonmatching lift leaves that record intact, including across a restart after
installation. A lift missing its key hash is structurally invalid
(`VV_MALFORMED`) and MUST NOT install any part of the candidate set.

## 4. Verification order and stable codes

The first failing numbered stage wins. Within a stage the listed checks run in
the order written; lists are traversed in wire order. Structural schema errors
are `VV_MALFORMED`; an unknown `spec` is classified at stage 2 before that
artifact's version-specific shape is interpreted. Installation errors are
separate from request verification. Corrupted or unauthentic local configuration
fails closed; it is never repaired from a bundle.

1. Enforce byte/parse limits and carrier shape (`VV_MALFORMED`). A carried set,
   policy, delegation or replacement trust anchor is an unknown member.
2. Check the carrier and every enclosed artifact version against the locally
   supported versions and the policy's closed `minArtifactVersions` map
   (`VV_SPEC_UNSUPPORTED`). Here every minimum and supported version is `0.1`;
   a numerically newer version is not automatically compatible. Validate the
   remaining artifact schemas (`VV_MALFORMED`).
3. Read authenticated set, policy, suspension/freeze revision and replay floor
   from the vault store. If either statement fails its installed root/identity
   check, fail with `VV_ROOT_REQUIRED` before checking expiry; return no signed
   result when the local signing/configuration state cannot be trusted.
   Reject expired set (`VV_APPROVER_SET_EXPIRED`), expired
   policy (`VV_POLICY_EXPIRED`), not-yet-active state (`VV_NOT_YET_VALID`), then
   freeze (`VV_FROZEN`). Record both versions and the suspension/freeze revision.
4. Verify hold signature against a pinned `hold-signer`; require `gateKid ==
   sig.kid`, exact tenant and `keyManifestHash` (`VV_HOLD_INVALID`). The manifest
   hash is an epoch binding, not authority to trust a console manifest.
5. Look up the deferred receipt's `action.canonical` (`VV_CLASS_NOT_ACCEPTED`).
   Require `hold.mode == "ENFORCED"`, `canonicalization == "JCS-RFC8785"` and
   exact equality of **id, version and hash** of both projections to the local
   class and supported implementation (`VV_PROJECTION`). Validate parameters by
   that class's rules and recompute its hash (`VV_PARAMS_MISMATCH`). Check the
   named audience member equals installed `vaultId` (`VV_AUDIENCE_MISMATCH`),
   then require the hash equals deferred `action.paramsHash`
   (`VV_PARAMS_MISMATCH`), then enforce class limits (`VV_LIMIT`). Never execute
   a second parameter copy or a sender-supplied digest.
6. Verify both receipt signatures under pinned hold-signer keys, their rule-a
   hashes, exact tenant, scope chain, action tuple and consecutive sequence.
   Require deferred verdict DEFERRED; approval verdict ALLOWED with non-null
   approval; approval `chain.prevHash` equals deferred `chain.hash`;
   hold's deferred ID/hash equal the deferred receipt (`VV_RECEIPT_LINK`). A
   receipt timestamp or its `approval.at` cannot refresh a decision's age.
7. For each decision require a currently pinned approver (`VV_APPROVER_UNKNOWN`),
   not locally suspended (`VV_APPROVER_SUSPENDED`), a valid signature with
   `approverKid == sig.kid`, and the rule-b hash of this hold
   (`VV_DECISION_INVALID`). A cryptographically valid DENY then yields
   `VV_DENIED`, even if approvals already satisfy quorum. Validate required
   hardware co-signatures over each decision (`VV_COSIG_REQUIRED`); reject
   unmatched or duplicate co-signatures with the same code. After all decisions
   are authenticated, deduplicate APPROVEs by actual pinned public key; different
   counted keys sharing a device ID yield `VV_DEVICE_DUPLICATE`. Too few distinct
   approving keys yield `VV_QUORUM_NOT_MET`; missing required approvers yields
   `VV_REQUIRED_APPROVER`. Duplicate decisions never add votes. Every supplied
   APPROVE, including duplicates, is subject to stage 9's age checks, so an
   earlier duplicate cannot be hidden by a later one. The approval receipt's
   `approval.by` MUST name one of these approvers (`VV_RECEIPT_LINK`).
8. Verify grant signature under a pinned `execution-signer` (`VV_GRANT_SIGNER`).
   Match `holdId`, hold rule-b hash, approval receipt rule-a hash and `maxUses=1`
   (`VV_GRANT_LINK`). Match grant `paramsHash` to the recomputed hash
   (`VV_PARAMS_MISMATCH`). A console or delegated signature is refused even if
   it passes its own trust system. No fallback to delegated verification exists.
9. Read the vault's own clock. Apply these predicates in order (seconds are exact
   durations, not rounded minutes):

   | Refusal predicate | Code |
   | --- | --- |
   | grant issuedAt > now + skew | `VV_NOT_YET_VALID` |
   | now >= grant expiresAt, or expiresAt <= issuedAt | `VV_EXPIRED` |
   | now >= hold expiresAt | `VV_HOLD_EXPIRED` |
   | any APPROVE decidedAt > now + skew | `VV_DECISION_FUTURE` |
   | any APPROVE now - decidedAt > class maxApprovalAgeSeconds | `VV_APPROVAL_STALE` |
   | grant expiresAt - issuedAt > class maxGrantLifeSeconds | `VV_GRANT_LIFE` |
   | grant issuedAt < durable replay floor | `VV_BELOW_FLOOR` |

   Exactly the skew and age bounds are accepted. Expiry at `now` is refused.
   Grant duration receives no skew allowance. Producers SHOULD clamp grant
   expiry to hold expiry; the vault checks both independently.
10. For an authenticated probe principal, return `VV_PROBE_STOP` with no commit
    capability. Otherwise apply the transaction requirements in section 5.
11. Sign a result with the guard key. A failure after commit cannot be reported
    as uncommitted or retryable.

A DENY omitted from the bundle is unknowable to the vault. Required approvers or
quorum equal to the whole eligible set provide stronger omission resistance;
this format makes no global-veto claim.

Additional stable codes: `VV_ROOT_REQUIRED` (installation and request stage 3),
`VV_POLICY_INVALID`, `VV_SET_LIFE`,
`VV_SET_ROLLBACK`, `VV_KEY_REUSE` (installation); `VV_SET_CHANGED`, `VV_RETRYABLE`,
`VV_ALREADY_CONSUMED`, `VV_EFFECT_REFUSED`, `VV_INDETERMINATE` (commit/recovery).
Codes and precedence are frozen within this profile. New behavior requires a new
profile/version, never silent acceptance of unknown fields or algorithms.

## 5. Atomic consumption and recovery (synthetic model: `packages/approval-artifacts/test/vault-spec-model.mjs:170-176`)

One authoritative transaction MUST serialize against set/policy updates,
suspensions, freeze and replay-floor movement. Acquire the authority lock first,
then re-read versions and revocation state. A change since stage 3 yields
`VV_SET_CHANGED`, without consumption; the caller may retry full verification.
Recheck the vault clock and every stage-9 bound after lock acquisition and
immediately before committing, so waiting for a lock cannot extend authority.

Within that transaction enforce uniqueness independently on `(tenant,vaultId,
grantId)`, `(tenant,vaultId,nonce)` and `(tenant,vaultId,holdId)`. Insert consumption,
perform the exact bound transition, and commit both together. Two guards serving
the same vault MUST share this authoritative state; process memory, a Gate's
journal and a replica read are insufficient. A deployment MUST refuse writes on
a read replica and MUST NOT support independent multi-primary consumption stores.

- Success commits consumption and the effect ID: `EXECUTED`.
- A terminal business refusal commits consumption with `VV_EFFECT_REFUSED` and a
  stable adapter `effectCode`, such as `INSUFFICIENT_BALANCE`. Funding the account
  later does not resurrect that grant.
- A known rollback before commit (serialization failure, deadlock, lock timeout)
  leaves no consumption: `VV_RETRYABLE`.
- A lost commit acknowledgement is `VV_INDETERMINATE`, with consumption unknown.
  It is never translated to “nothing happened.” Retry the same signed bytes to
  read the authoritative stored result.
- A uniqueness collision returns `VV_ALREADY_CONSUMED` with the first use's
  grant hash, original outcome, effect ID and effect code, never another effect.
  A standby's new grant for an already-consumed hold returns that original result.
- All pre-commit verification refusals and probe stops leave consumption unchanged.
  Invalid requests cannot burn a valid grant by carrying wrong parameters.

Consumption survives process restart. Retain rows at least the maximum grant
lifetime plus skew, and until a monotonic replay floor, moved atomically inside that
same transaction, makes the grants behind the removed rows invalid (floor refusal in
the synthetic model: `packages/approval-artifacts/test/vault-spec-model.mjs:84`). Retention alone is not permission to
forget a live authorization. Transaction/post-commit error handling MUST preserve
the stored outcome. The signed result is an observation, never a new grant.

## 6. Result semantics

`noa.vault-result/0.1` binds tenant, vault, `vaultInstanceId`, the locally read set
and policy versions, vault `checkedAt`, and `grantHash`. For a malformed request
with no identifiable grant, `grantHash` is null. If trusted signing/configuration
state is unavailable, fail without fabricating a signed result.
`consumed` is false for pre-commit refusals, true for committed success/terminal
refusal/replay, and null for an unknown commit outcome. `originalOutcome` is null
except for ALREADY_CONSUMED, where it is EXECUTED or REFUSED. A terminal refusal
has null effect ID and a non-null adapter effect code; a successful effect has
an effect ID and null effect code. Replay preserves these associations. An
INDETERMINATE result has null effect ID, effect code and original outcome.

## 7. Approver display requirements

An approver client MUST independently pin the action and display specifications.
Before offering APPROVE, it verifies the hold and deferred receipt, requires
ENFORCED and both exact projection identities, decrypts the bound display, then
rebuilds the parameters from exactly the rows it will render. The recomputed hash
MUST equal the authenticated deferred receipt's action hash. Failure is a trust
failure, with no approval action available.

For `noa.ledger.transfer`, require all six rows of the existing transfer spec:
Action, Ledger, From, To, Amount, Salt. Split Amount at its sole space into amount
and unit. Show every bound value verbatim, without truncation or locale changes;
Salt may be expanded in details but remains available in full. Identifiers that
share their first 48 characters must remain distinguishable. Hardware co-signing
occurs only after these checks. An unsupported display MUST NOT be portrayed as
verified, and cannot be used to approve an action under this profile.

## 8. Zero-effect diagnostic action

`noa.vault.probe/1`, canonical name `noa.vault.probe`, binds exactly two strings:
`vault` (the ledger identifier grammar, 1–64 ASCII characters) and `run` (32
lowercase hexadecimal characters). The producer chooses a fresh random 128-bit
run value and reuses it on retries. `paramsHash` is SHA-256 of UTF-8 JCS of these
parameters, with the usual `sha256:` prefix. No new hash construction is added.
The complete display is `Action="noa.vault.probe"`, `Vault=vault`, `Run=run`.
Rebuilding these three exact rows yields the parameter object; no truncation.

Projection descriptors use the existing `projectionIdentityHash` construction:
`{id,version,kind,implementation}`. Here `implementation` is the SHA-256 of UTF-8
JCS of the following normative, declarative binding descriptor (not source code):

```
{"canonical":"noa.vault.probe","members":["run","vault"],"rows":["Action","Vault","Run"],"spec":"noa.vault.probe/1"}
```

The schema ID is `noa.vault.probe.schema`, the display ID is
`noa.vault.probe.display`, version 1, kinds `actionSchema` and `displayProjection`
respectively. The corpus pins the resulting hashes. This different descriptor
basis does not change the ledger-transfer identities or their source-text basis.
The class has `audienceMember="vault"`, `probe=true`, and empty limits. A normal
execution principal may commit one diagnostic record and consumption, but MUST
NOT invoke a business-effect adapter. An authenticated probe principal stops
before either record is written, for every class. These are distinct operations.

## 9. Conformance and limits of the evidence

`conformance/vault-verification/INDEX.json` lists the ordered request and artifact
vector files in this additive corpus, separate from the legacy per-artifact vectors.
Its trusted `state` is a **test fixture for the vault
store**, never an API field. Every test computes its verdict from the artifacts,
clock and state; it does not read the expected verdict to choose behavior.
`requests` model retries/restart and concurrency serialization; `expected` pins
codes and the cumulative consumption/effect counts. Installation vectors also
assert whether the authority revision changed; `verifyAfterInstall` applies the
requests to the resulting local state, including when installation was refused.
`candidateSchemaValid` records intentional malformed installation inputs; all
other statements are structurally valid. The companion artifact
fixtures cover joins, co-signatures and results. All keys and names are synthetic.
Run `npm test` in this package after the repository build. To regenerate only
these vectors: `node test/vault-vector-fixtures.mjs --write`. Normal tests assert
byte-for-byte reproduction without rewriting them.

The test-only executable model reuses existing parsing, JCS, Ed25519, receipt
verification and ledger projection code. It is not an exported verifier, a
transaction adapter, independent verification, real database concurrency or crash
proof. A future implementation must consume this corpus and also demonstrate its
actual commit, rollback, restart and interleaving behavior. Passing the corpus is
necessary, not sufficient, for full normative conformance.

Acceptance proves matching signed bytes and counted pinned keys under the stated
trust/clock/store assumptions. **Keys are not people.** Distinct keys/device IDs
do not prove distinct humans, independence, understanding, informed consent or
absence of coercion. Software device IDs are self-asserted. A signature does not
prove hardware custody or truthful attestation. No result proves a physical
outcome, complete mediation of unknown routes, external settlement, or correctness
when the root, vault clock, administrators or authoritative store are compromised.
A vault administrator can reinstall different root pins; that remains within the
vault's trust boundary and must be independently observed. Carrier parameters and
join evidence can be sensitive: protect their transport/storage, bound retention,
and keep identity labels free of personal data.
