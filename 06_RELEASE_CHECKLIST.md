# NOA Receipt Release and Conformance Checklist

This checklist decides a candidate revision. It cannot convert earlier evidence into evidence for a new SHA; candidate-specific blockers and verdicts belong in that candidate's dated release evidence.

## Inputs and scope

- [ ] Record immutable commit SHA, package version, receipt `spec`, vector/profile version, and whether COSE carriage is included.
- [ ] Confirm all worktree changes are intentional; preserve unrelated user/concurrent changes.
- [ ] Identify frozen files, migration/compatibility scope, and forward-fix/rollback plan.
- [ ] **Every package whose source changed since its last publish carries a version bump in this release.** A fix that is merged but not released reaches nobody, and leaving the number unchanged makes one version mean two different contents.
- [ ] **After** the fixed version is on the registry, deprecate superseded vulnerable versions and link installers to the fixed version and advisory.

## Protocol and security

- [ ] Verify the normative revision, field semantics, canonical bytes, signature scope, key/algorithm identifiers, deterministic errors, extensions, and version negotiation.
- [ ] Confirm `action.id`, `action.canonical`, `paramsHash`, `SOURCE_ABSENT`, and `PARTIAL` semantics are preserved end to end.
- [ ] Confirm COSE protected headers, signer roles, embedded-signature presence, exact payload bytes, detached-payload behavior, and native-chain verification agree across normative prose, code, and vectors.
- [ ] Run positive and negative receipt, malformed-input, canonicalization, signature, key-lifecycle, replay, downgrade, and cross-owner/tenant vectors applicable to the candidate.
- [ ] Recheck [NON-CLAIMS.md](NON-CLAIMS.md) and [CORRECTIONS.md](CORRECTIONS.md); no release language may exceed their limits. Verify every `NC-` citation resolves to an entry that exists.
- [ ] **For each accepted residual in NON-CLAIMS.md, state what must remain true for it to stay acceptable, and verify those preconditions against the candidate.**

## Validation evidence

- [ ] Run the recorded typecheck, security, test, conformance, package/tarball, and publish-surface commands at the candidate SHA. **Record each required command's own exit status and terminal summary.**
- [ ] Obtain nonzero, successful hosted CI jobs for that same SHA; distinguish a failed, skipped, or zero-job run from green CI.
- [ ] Obtain an independent adversarial review of the frozen diff and reproduce or disposition each material finding. **A green suite does not substitute for adversarial review.**
- [ ] Re-measure every public status, test, control, and parity claim against the exact candidate tree; do not reuse a mutable summary as release evidence.
- [ ] Verify the release artifact version, integrity, contents, and rollback/forward-fix instructions.
- [ ] Release `noa-receipt` only through `.github/workflows/release-npm-noa-receipt.yml`, dispatched on `main` for the exact tip commit right after the release pull request merges (the main-push candidate it compares against expires after seven days). Approve the `npm-release` deployment within 24 hours (the staged artifact's retention); otherwise dispatch again. The `publish` job stages the tarball on npm and ends STAGED; its run summary names the stage id and the staged integrity. Before approving, a maintainer runs `npm stage download <stage id> --json` and requires its `integrity` to equal the run's staged integrity, then runs `npm stage approve <stage id>` (npm asks for the maintainer's second factor), or `npm stage reject <stage id>` if anything differs. The `readback` job verifies PRESENT, the integrity and the verified attestation identity: within the same run if the approval lands inside its polling window (about ten minutes), otherwise re-run the readback job after the approval. Afterwards record the run, the stage id, the staged integrity and the readback summary. A green controller run is release evidence of checked, merged, signed source plus two separate human approvals; it is not evidence of code review and not a release decision (`NON-CLAIMS.md` §R1).
- [ ] Operator setup, in this order, each step read back before the next. (1) Create the `npm-release` environment with the owner as required reviewer, admin bypass disabled and a custom branch policy allowing only `main`; read it back with `gh api repos/NordenSoft/noa-mandate-core/environments/npm-release` and `gh api repos/NordenSoft/noa-mandate-core/environments/npm-release/deployment-branch-policies`. (2) Only then bind npm trusted publishing for staging only: `npm login`, then `npm trust github noa-receipt --file release-npm-noa-receipt.yml --repo NordenSoft/noa-mandate-core --env npm-release --allow-stage-publish` (never `--allow-publish`), read back with `npm trust list noa-receipt`, whose permissions must read `stage publish` and nothing else. Never delete and recreate the environment while the binding exists: GitHub recreates a missing environment without protection the first time a job names it.
- [ ] At approval time, the environment approver reads the ruleset's bypass actors with an owner admin token, `gh api repos/NordenSoft/noa-mandate-core/rulesets/22911326 --jq '.bypass_actors'` (the field is returned only to ruleset writers, so an absent field is not an empty list), and records the output in the release receipt. The workflow's job token cannot see this field; no ruleset-editing credential is stored in the release environment.
- [ ] `scripts/lint-kernel-release-parity.mjs` is not part of the controller: it requires a `v<version>` tag, which this repository does not create, and compares against the kernel already on the registry, which for a new version does not exist yet. The controller's byte evidence is the exact-commit restage plus the independent main-push candidate.

## Interoperability and release decision

- [ ] Confirm consumer mappings are revision-bound and semantic-preserving; reject any integration that repurposes receipt fields.
- [ ] Run the declared conformance profile against each claimed independent implementation; document independence and all deviations.
- [ ] Publish an evidence summary that separates `TESTED`, `CI-VERIFIED`, `PUBLISHED`, `PILOT`, `STANDARDIZATION`, and `PRODUCTION` claims.
- [ ] Decide `GO`, `GO WITH CONDITIONS`, `NO-GO`, or `INDETERMINATE`, with named evidence and outstanding risk.

Record the candidate-specific verdict in a dated release record bound to the immutable revision. This checklist remains a stable gate definition.
