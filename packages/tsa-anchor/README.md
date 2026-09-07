# noa-tsa-anchor

Opt-in **independent anchoring** for `noa-receipt` witness anchors
(`buildAnchor`/`anchorForChainHead`, `src/federation/anchor.ts` in the parent package). Two additive
halves whose trust decisions run offline:

1. **RFC 3161 timestamps** — ask an independent Time-Stamping Authority for its attestation that a
   signed anchor existed by a given time, and authenticate that attestation offline against an
   explicit caller trust policy.
2. **Witness-quorum monitor** — read a pool of *published* witness anchors and report signed
   contradictions: one identity, two histories. Emits a proof object a third party re-checks itself.

Neither half modifies the anchor format, the receipt schema, the core `noa-receipt` package, or the
witness-federation acceptance rule — this is a wholly separate, disjoint opt-in package, the same
pattern as `packages/adapter-core` / `packages/mcp-proxy`.

## Why

A `noa-receipt` witness anchor's `ts` field is set by the WITNESS itself — like a receipt's own
`ts`, it is signer-asserted and therefore backdatable (see the parent package's
`THREAT-MODEL.md`, "Signer-asserted timestamps"). This package lets an operator additionally get
the anchor timestamped by an INDEPENDENT third party (a public or self-hosted RFC 3161 TSA), which
is bound by neither the receipt keyring nor the witness's own key.

## Design: what gets timestamped, and why

`noa-tsa` timestamps `sha256(canonicalize({chain, highestSeq, headHash, ts, sig}))` — the
JCS-canonical hash of the **complete signed anchor**, `sig` block included. This is deliberately
different from `anchorSigningInput` in the parent package's `src/federation/acceptance.ts`, which
excludes `sig` (that is the witness's OWN signing preimage, not what we timestamp).

Two alternatives were considered and rejected:
- **Timestamp only the bare `headHash`.** A `headHash` is a deterministic hash of chain content;
  anyone can request a TSA stamp on it WITHOUT ever obtaining a witness signature. That would let
  a stamp be presented as if it were witness-backed when no anchor was ever involved — decoupled
  from witness endorsement, and misleading.
- **Embed the TSA token inside the `Anchor` object itself.** `Anchor` is the parent package's
  `src/federation/acceptance.ts` structural-validation surface; extending its shape is a format
  change with golden-backcompat risk, and would put a dependency on this package's DER code into
  the core (which has a zero-runtime-dependency policy). Rejected — this package writes a
  **sidecar** file, never touching `anchors.json`.

Because the hash covers `sig`, two anchors over the identical frontier signed by two different
witnesses hash to two DIFFERENT values (this is intentional, not a bug — they are genuinely
different artifacts). `noa-tsa stamp` therefore issues one stamp per DISTINCT anchor, keyed by its
own hash.

## What noa-tsa proves — and does not

**An authenticated TSA token proves the TSA signed an assertion about the anchor and its creation
time — it does not prove receipts' own `ts` fields.**

Precisely:
- A TSA stamp that passes authenticated verification is evidence that a specific signed anchor
  (frontier + witness signature) existed no later than the token's authenticated latest creation-time
  bound when signed `Accuracy` is present. RFC 3161 defines that bound as `genTime + Accuracy`. It does
  **not** prove the anchor did not exist even earlier, and it does **not** prove anything about the
  underlying receipt chain's own `ts` fields, which remain signer-asserted (see the parent
  `THREAT-MODEL.md`).
- Signed `Accuracy` is returned as seconds/millis/micros plus exact `timeBounds.earliest/latest`.
  Missing components inside an explicit Accuracy SEQUENCE mean zero. A wholly omitted Accuracy
  instead returns `accuracy:null` and `{accuracyKnown:false, earliest:null, latest:null}`: RFC 3161
  says accuracy may then be available through the TSA policy, so omission is not treated as exact
  zero. Such a token remains usable as an authenticated TSA assertion at `genTime`, but this package
  does not claim a signed no-later-than bound. A cutoff consumer must require a non-null `latest` or
  independently resolve and enforce the accepted `TSAPolicyId` accuracy.
- A chain with no witness anchor has no TSA coverage at all — this package only ever timestamps
  anchors that already went through the opt-in witness-federation path
  (`noa verify --anchors/--trust-set` in the parent package).
- `stampAnchor` sends a random RFC 3161 nonce by default and rejects a response that does not echo
  it back verbatim — a stamp-time anti-replay freshness check, so a validly-formed but replayed
  token for the same digest cannot be accepted. `verifyStamp`, running offline against the stored
  bytes, has no original request to compare against and therefore does **not** re-check nonce
  freshness; that check is established once, by the client, at stamping time.
- A successful `stampAnchor`/`noa-tsa stamp` call means the response was structurally bound to the
  request. It is **not** an authenticated TSA trust verdict. The stored record becomes evidence only
  when `verifyStamp` returns `{ok:true, authenticated:true}` for the same anchor.
- `verifyStamp` has one authenticated success path. It requires an absolute OpenSSL 3 executable,
  caller-pinned CA roots, at least one allowed TSTInfo policy OID, complete CRLs under the explicit
  `crl-check-all` policy, and a trusted verification instant with a bounded future skew. It then
  verifies the SHA-256 `messageImprint`, exactly one CMS `SignerInfo`, the CMS signature, the
  authenticated TSTInfo bytes, the embedded signer certificate and chain, timestamp-signing EKU,
  certificate validity and CRL status across the authenticated creation-time interval when Accuracy
  is present, and the algorithm/security-level constraints. Before the final OpenSSL path checks,
  every available certificate and CRL candidate is restricted to exact original PEM blocks whose
  validity covers that complete interval; unrelated PEM block kinds are omitted. Selected
  `TRUSTED CERTIFICATE` blocks retain their original trust attributes. Missing trust, policy,
  revocation evidence, clock policy, or OpenSSL fails closed with a stable code.
- The signer certificate must be embedded in the CMS token. `untrustedCertificates` may contain
  chain intermediates only; it cannot supply an omitted signer certificate. Trust roots are always
  caller-supplied and are never inferred from the operating system. The compatible
  `certReq:false`/`--no-cert-req` request option remains available, but its result can authenticate
  only if that TSA embeds the signer certificate anyway.
- The message imprint is fixed to SHA-256. CMS signer digests are restricted to SHA-256/384/512,
  signature algorithms to the explicit RSA PKCS#1 v1.5/ECDSA/EdDSA OID allowlist in `verify.mjs`,
  and OpenSSL authentication level 2. RSASSA-PSS is refused until its hash, MGF, salt-length, and
  trailer parameters have a separately enforced profile. Revocation support is deliberately
  CRL-only and requires status for the whole chain; the verifier does not fetch OCSP or CRLs from
  the network.
- `clock.now` is a caller-supplied UTC RFC 3339 instant. `clock.maxFutureSkewMs` is required and is
  capped at 300000 ms; the signed latest creation-time bound, or `genTime` when Accuracy is absent,
  must fit within it. Certificate validity and CRL checks use both Accuracy endpoints when known and
  `genTime` otherwise, never the ambient wall clock. OpenSSL's verification instant has one-second
  resolution, so Accuracy endpoints are rounded outward (earliest down, latest up) for conservative
  checks. Tokens with fractional `genTime` remain rejected instead of being rounded across a
  certificate or CRL boundary.
- `inspectStamp` is the separate structural diagnostic API. It always returns
  `authenticated:false`, has no `ok` field, and cannot upgrade a parse result into a trust verdict.
  A manually run OpenSSL command is likewise diagnostic only and cannot change the API or CLI
  result.

## Witness quorum: finding an equivocating fork

The parent repo's federation spec states the gap this half fills, in its own words (§7):

> *Equivocation needs gossip; a lone offline verifier sees one branch. q independent co-signatures
> do not equal agreement on one history. An issuer can feed different, internally-consistent forks
> to different witnesses; each signs happily. Detection requires views to meet (gossip/monitors).*

`scanForEquivocation` is that monitor: the place where the views meet. It takes a **public pool of
witness anchors** plus your own pinned trust-set, and asks a question with no presented head in it —
*do these signed statements contradict each other?* It needs no database, no operator secret, and in
the same-height case not even the receipts.

Three finding kinds, in descending strength of attribution:

| kind | what it proves | attributable to |
| --- | --- | --- |
| `WITNESS_EQUIVOCATION` | one signing **key** validly signed two different heads at the same `(chain, seq)` | that witness — its own two signatures |
| `CHAIN_FORK` | two **different** pinned keys validly signed different heads at the same `(chain, seq)` | nobody: both witnesses may be honest, each anchored what it was shown. The chain was presented two ways |
| `HISTORY_CONTRADICTION` | a valid anchor states a head at seq S that the **presented** chain (or an endorsed checkpoint) contradicts at S | nobody: one of the two is false, and the anchor side is the signed one |

The first two need nothing but the pool. The third needs the artifact under adjudication — the chain
the prover handed you, or the checkpoint it asks you to accept — which is not private state.

`verifyEquivocationProof(finding, trustSet)` is what makes a finding evidence rather than an opinion:
a third party who holds only the finding and their own pinned keys re-derives the verdict, and the
result reports `transferable` separately from `ok` (see the honest limits below).

### What this does NOT buy you

- **Nothing authenticates that a pool is COMPLETE, and that is the cheapest evasion.** This scanner
  cannot distinguish an incomplete pool from a complete one, so withholding a single anchor is
  enough to make a forked chain read `CLEAN` — and it requires **no compromised signer and no forged
  signature at all**, only control over what reaches the verifier. Everything below is downstream of
  this one.
- **It does not make history immutable.** It makes a fork *detectable by whoever ends up holding
  both halves*. Whether they do is a distribution question this code does not touch.
- **It does not say which branch is true.** A proof shows two signed statements contradict each
  other. Deciding which is the real history needs evidence this package never sees.
- **It only sees what was published.** A branch shown to nobody leaves no anchor
  (`THREAT-MODEL.md`: *omission is not tampering*).
- **A height-extending rewrite is invisible from anchors alone.** Anchors at seq 2 and seq 4 look
  exactly like a chain that grew. Pass `history` to catch it, or wait for the inclusion/consistency
  proofs of federation-spec §10, which are dormant.
- **Witness independence is an assumption, not a check.** This code enforces distinct *keys*; whether
  those keys belong to distinct organisations is operational (`NON-CLAIMS.md` NC-4.1).
- **A name in a finding is the reader's own label.** `sig.kid` is not inside the bytes a witness
  signs, so attribution transfers at the **public key** (`attributedToPubkey`), never at the `kid`.
  `verifyEquivocationProof` therefore resolves a branch's witness **by key**, not by name, so a proof
  survives crossing organisations; a disagreement between the producer's label and yours is reported
  as `labelMismatch`, never treated as a cryptographic failure.
- **`trustSetDigest` is an integrity hint, not an authentication.** It is a digest of public data
  that any forwarder can recompute: it catches drift and accident, not an active attacker.
- **A TSA URL is a claim, not evidence.** It is not inside an RFC 3161 token, so it cannot be
  re-derived; it is carried as `tsaUrlClaimed` and never sits beside `verified:true` as if attested.
  Only an authenticated `verified` result and its `genTime`/Accuracy/time bounds are re-derived from
  the token bytes.

Every result object carries these limits in its own `undetected` array, including a `CLEAN` one —
which is exactly when a reader is most likely to over-read the answer.

### Verdicts, and why "nothing found" is not one word

`scanForEquivocation` returns one of five, and **`clean` is true for `CLEAN` alone**:

| verdict | meaning |
| --- | --- |
| `EQUIVOCATION` | a signed contradiction was found. Outranks a dirty pool — junk alongside a real fork does not make the fork less true |
| `CLEAN` | every admitted anchor was examined and they agree |
| `NO_EVIDENCE` | nothing was admitted, so nothing was examined. **Not** a clean bill |
| `INCOMPLETE_POOL` | entries were unusable, or a **pinned** kid's signature failed — the latter is an attack signal |
| `INVALID_INPUT` | the scan did not run: bad trust-set, malformed history, or a degenerate bound |

A **forward-compatible** anchor — one whose `sig` carries a member this version does not know, which
JSON extensibility makes routine — is admitted and compared, counted under `extensions.sigMembers`,
and never confused with a corrupt entry. An unsigned extra member cannot change an anchor's identity
either: `anchorHash` normalises `sig` to `{alg, kid, value}`, so one anchor has exactly one lookup
key and its TSA stamp attaches regardless.

Bound **truncation** is reported too (`truncated.findings`, `truncated.branches`) and forces
`clean:false`: a legal bound quietly dropping corroborating branches would leave a reader holding a
summary that looks like the whole picture.

Bounds are DoS ceilings, never switches: `maxAnchors`/`maxHistory`/`maxFindings` must be ≥ 1 and
`maxBranches` ≥ 2 (a proof carrying fewer than two anchors demonstrates nothing). A value below the
floor is **refused**, not silently clamped.

## API

- `stampAnchor(anchor, { tsaUrl, certReq?, includeNonce?, nonceValue?, timeoutMs? }) -> Promise<StampRecord>`
  — requests a timestamp; fail-closed (`TsaError`) on any transport failure, non-grant, or a
  response whose messageImprint does not match the submitted anchor hash.
- `verifyStamp(anchor, stampRecord, verification) -> { ok, authenticated, code, reason, genTime,
  accuracy, timeBounds, ... }` — never throws. `genTime` is preserved for compatibility;
  `accuracy:null` and null bounds mean the token omitted Accuracy. `verification` is:
  ```js
  {
    opensslExecutable: "/absolute/path/to/openssl", // OpenSSL 3.x
    trustRoots: rootsPem,                            // PEM string or Buffer
    allowedPolicyOids: ["1.2.3.4.5"],
    revocation: { mode: "crl-check-all", crls: crlsPem },
    clock: { now: "2026-06-23T10:30:00Z", maxFutureSkewMs: 300000 },
    untrustedCertificates: intermediatesPem,         // optional; never the signer
    timeoutMs: 5000                                  // optional, 100..30000
  }
  ```
- `inspectStamp(anchor, stampRecord) -> { structurallyValid, authenticated:false, code, ... }` —
  unauthenticated diagnostics only; there is intentionally no `ok` field.
- `scanForEquivocation(anchors, trustSet, opts?) -> ScanResult` — the monitor. `opts` accepts
  `history` (from `historyFromReceipts`), `stamps` (a `.tsr` sidecar map, so each branch of a finding
  carries an independent TSA time), `tsaVerification` (the same mandatory verification object), and
  the DoS bounds `maxAnchors` / `maxHistory` / `maxFindings` / `maxBranches`. Without
  `tsaVerification`, attached stamps remain unverified. The primary field is **`clean`**, true only
  when the scan ran to completion AND found nothing — malformed input leaves it `false`, so a caller
  reading nothing else still fails closed. Attached-stamp verification admits at most 16 unique
  canonical anchors, reuses one exact anchor/TSR verdict wherever that evidence repeats, and shares
  a fixed 96-process/30000-ms aggregate budget. Never throws.
- `verifyEquivocationProof(finding, trustSet, {tsaVerification}?) -> { ok, transferable, reason, ... }`
  — never throws. It independently re-verifies attached token bytes; a carried `verified` claim is
  never trusted. It refuses more than 16 carried branches before OpenSSL, deduplicates identical
  anchor/TSR jobs, and uses the same fixed aggregate budget. Resource exhaustion leaves every
  affected stamp unattested and returns `resourceLimited:true` / `VERIFICATION_RESOURCE_LIMIT`; it
  does not erase a separately valid signed-contradiction verdict.
- `checkpointCorroboration(checkpoint, anchors, trustSet, opts?) -> CorroborationResult` — how many
  **distinct** pinned witnesses independently anchored the head a checkpoint endorses. Optional
  `freshness: { now, maxAgeMs, skewMs? }`; without it, `freshnessEnforced:false` says so and an old
  corroboration is replayable. Does **not** check the checkpoint's own signature — that is the
  kernel's `verifyCheckpoint(cp, keyring)`, a separate question with a separate trust input.
- `historyFromReceipts(receipts) -> [{seq, hash, source}]` — read-only; does not verify the chain.
- `anchorHash(anchor) -> "sha256:<hex>"` / `anchorHashDigest(anchor) -> Buffer(32)`.
- `buildTimeStampReq(hashedMessage, opts?) -> Buffer` / `parseTimeStampResp(buf) -> {...}` — the
  RFC 3161 wire layer, if you need it directly.
- `derDecode` / `DerError` — the underlying minimal DER decoder (`src/der.mjs`).

## CLI

```bash
noa-tsa stamp       --anchors anchors.json --tsa-url http://freetsa.org/tsr [--out anchors.tsr.json] [--no-cert-req] [--no-nonce]
noa-tsa verify      --anchors anchors.json --tsr anchors.tsr.json \
  --openssl /absolute/path/to/openssl --tsa-trust-roots tsa-roots.pem \
  --tsa-policy 1.2.3.4.5 --tsa-crls tsa-chain.crl.pem \
  --tsa-now 2026-06-23T10:30:00Z --tsa-max-future-skew-ms 300000 \
  [--tsa-command-timeout-ms 30000]
noa-tsa fork-scan   --anchors pool.json --trust-set trust-set.json [--chain receipts.json] \
                    [--tsr anchors.tsr.json <TSA verification flags> [--tsa-command-timeout-ms 30000]]
noa-tsa corroborate --checkpoint checkpoint.json --anchors pool.json --trust-set trust-set.json \
                    [--now 2026-06-23T10:30:00Z --max-age-ms 86400000] \
                    [--tsr anchors.tsr.json <TSA verification flags> [--tsa-command-timeout-ms 30000]]
```

`<TSA verification flags>` means the six required flags shown on `verify`; optional
`--tsa-untrusted intermediate-chain.pem` supplies only intermediate certificates. Supplying
`--tsr` to either monitor command without all six required values is a usage error. The CLI never
falls back to structural inspection and never exits 0 for an unauthenticated stamp.

`verify`, plus `fork-scan` and `corroborate` whenever `--tsr` is present, hash the complete anchor
input before starting OpenSSL and admit at most **16 unique anchor contents** per command. Entries
with the same canonical `anchorHash` identity retain their original output positions and order, but
identical anchor/TSR evidence shares one cryptographic verdict; repeated branches cannot multiply
OpenSSL work. Seventeen or more unique anchors are refused in full before any OpenSSL process starts, with
`VERIFICATION_RESOURCE_LIMIT` and exit 7. The ceiling has no override: callers verifying a larger
collection with `verify` must submit explicit batches of at most 16 and require every batch to exit
0. Do not split a fork scan merely to fit this TSA bound, because a contradiction may straddle the
batches. Scan the complete pool without `--tsr`, then authenticate the bounded anchors carried by
each resulting finding with explicit `verify` batches.

Each admitted unique anchor receives at most six OpenSSL process credits, for a command maximum
of 96. A token with absent or explicit-zero Accuracy uses five because its endpoint checks coincide.
All credits also share one monotonic aggregate deadline: 30000 ms by default, optionally set
with `--tsa-command-timeout-ms` to an integer from 100 through 30000. This flag bounds the whole
OpenSSL phase and does not alter the trusted RFC 3161 `--tsa-now` value. Deadline or process-credit
exhaustion stops every remaining unique anchor without starting more processes and returns
`VERIFICATION_RESOURCE_LIMIT` with exit 7; work is never silently truncated into success.
`--tsa-command-timeout-ms` is accepted on a monitor command only together with `--tsr`.

The library's multi-stamp paths enforce the same boundary without making the CLI capability a
public option: `scanForEquivocation` and `checkpointCorroboration` mint a private fixed budget when
called directly, while `verifyEquivocationProof` also refuses proofs carrying more than 16 branches.
The capability token and its state are not exported from the package API, and an ordinary lookalike
object fails closed rather than extending work or manufacturing a verified result.

All TSA verification values are trusted verifier configuration: the OpenSSL executable itself,
CA roots, allowed policy OID, CRLs, and clock value must come from the verifier's controlled
configuration, not from the token, sidecar, or TSA response. For a historical creation-time
interval, every certificate or CRL candidate admitted to the final trust decision must cover the
whole interval; separate materials that cover only different points cannot be combined into
continuous evidence. The CRL bundle must contain archived issuer CRLs with status for every
non-trust-anchor certificate in the chain. When Accuracy is absent, the only checked instant is
`genTime`. This package performs no network retrieval or historical-CRL discovery; missing, stale,
not-yet-valid, or interval-incomplete CRL evidence fails closed.

Exit codes: **`0` means CLEAN and nothing else** · `1` MISMATCH (verify: an anchor is unstamped or
its stamp does not match; corroborate: quorum not met) · `2` TRANSPORT (stamp: the TSA request
failed) · `3` MALFORMED (bad JSON/DER input, an unusable trust-set, or a `--chain` that does not
verify) · `4` USAGE, including an empty `--anchors` array — "did nothing" is not "succeeded" ·
`5` EQUIVOCATION (a signed contradiction was found) · `6` NO_CLEAN_RESULT (`fork-scan` admitted no
evidence or could not read the complete pool) · `7` RESOURCE_LIMIT.

**Exit 7** is `RESOURCE_LIMIT`: authenticated verification exceeded its unique-anchor, aggregate
deadline, or OpenSSL-process bound. It is distinct from both a cryptographic mismatch and malformed
input so automation cannot mistake incomplete verification for a substantive negative or success.

`--chain` is **verified, not trusted**: the presented receipts are run through the kernel's own
offline `verifyChain` and the (chain, seq, hash) derivation must be total. A chain that does not
verify, or one only partly readable, exits `3` rather than quietly narrowing the comparison.

`--now` is parsed as strict RFC 3339 (`2026-06-23T10:30:00Z`); `2026` and `2026-06-23` are refused
rather than silently anchoring the freshness window to the start of a year.

**Exit 6** is separate from exit 1 on purpose: `1` is a substantive negative (this stamp does not
match; the quorum was not met), while `6` means the scan ran and earned no clean result — it
examined nothing, or the pool was not fully readable. Folding the two together left a pipeline
unable to tell them apart.

`--now` and `--max-age-ms` must be supplied together: half a freshness policy is an operator error,
and treating it as "no freshness" would silently re-open the replay gap the flag exists to close.

**Public TSA reachability is UNVERIFIED by this package's own test suite**. Transport tests use an
in-process mock, while authenticated tests generate a local CA, timestamp signer, CRLs, and signed
tokens with OpenSSL 3. No test contacts an external TSA. Before relying on a public endpoint such as
`http://freetsa.org/tsr` in a real workflow, confirm it is reachable from your environment:
```bash
curl -sS -X POST -H 'content-type: application/timestamp-query' --data-binary @/dev/null -o /dev/null -w '%{http_code}\n' http://freetsa.org/tsr
```
If it is unreachable, run your own TSA (`openssl ts` supports acting as one). The package's mock
TSA (`test/mock-tsa-server.mjs`) is for request/transport development only; its intentionally
unsigned tokens are rejected by authenticated verification.

## Cryptographic backend and dependencies

This package ships its own minimal RFC 3161 DER (ASN.1) encoder/decoder (`src/der.mjs`) rather
than a general-purpose ASN.1 library, and it has no npm runtime dependency beyond `noa-receipt`.
Full CMS/X.509/PKIX/CRL verification is not reimplemented. `verifyStamp` synchronously binds its
verdict to the maintained OpenSSL 3 command-line verifier, preserving the package's existing
synchronous API while avoiding invented cryptography.

The binding uses `shell:false`, fixed argument vectors, an absolute caller-selected executable, a
private fixed provider configuration, bounded timeout and output, and a mode-0700 temporary
workspace whose files are mode 0600 and are removed before return. OpenSSL absence, a non-3.x
version, a process failure, excess output, timeout, or cleanup failure all fail closed. OpenSSL exit
status is the security decision; parsed error text only selects a more useful stable failure code.
The CLI additionally mints an internal opaque resource capability, unavailable through the public
package API or ordinary verification options, and passes it through every OpenSSL invocation in one
TSA-enabled command. This binds all unique-anchor work to the same monotonic deadline and process
credits rather than resetting a per-process timeout for every anchor. Its private state is held by
a weak registry, so discarded command capabilities do not accumulate in a long-lived verifier.

## Development

This package depends on `noa-receipt` via `"file:../.."` (see `package.json`) so its tests measure
THIS repository's kernel rather than a registry copy of it. Run `npm run build` at the repo root
before `npm install` here — `import "noa-receipt"` resolves through the root's `main: dist/src/index.js`,
which exists only after that build.

`node scripts/knockout-cms-verification.mjs` builds fresh private package copies and independently
removes CMS authentication, content-hash deduplication, the unique-anchor preflight, and aggregate
deadline propagation. Each corresponding attack test must turn red. It never edits the working
source.

## Releasing

Publication is currently **frozen**. `.github/workflows/publish-tsa.yml` is a permanently
quarantined legacy workflow: manual dispatch only reports `RELEASE_FROZEN` and exits unsuccessfully.
It cannot build, stage, or publish candidate bytes. No tag, branch, package script, or local test in
this repository is release authority.

A future release controller must use a new workflow and independently establish its own reviewed
commit binding, protected environment, least-privilege provider permissions, immutable staged
tarball, dependency availability and kernel parity, package tests, published-surface checks, and
provenance policy. Until such a controller exists and passes its separate release gate, local
package and tarball results are candidate evidence only and do not mean this package was published.

## What this package does not claim

[`NON-CLAIMS.md`](https://github.com/NordenSoft/noa/blob/main/NON-CLAIMS.md) is the normative record of what NOA does **not** do. It is
not shipped inside this tarball, so it is linked by URL rather than by a relative path that would
404 for exactly the reader who needs it.

Read it before you rely on this package for anything that matters. A boundary you have to infer
from silence is a boundary you will get wrong, and the failure this project is built around is a
forged or misattributed approval — not downtime, which is the one people plan for.

Alongside it: [`THREAT-MODEL.md`](https://github.com/NordenSoft/noa/blob/main/THREAT-MODEL.md) for what is defended against, and
[`SECURITY.md`](https://github.com/NordenSoft/noa/blob/main/SECURITY.md) for which versions get fixes and how to report a finding.
