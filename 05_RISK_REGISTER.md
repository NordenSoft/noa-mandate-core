# NOA Receipt Risk Register

This register records durable public risk classes and required controls. Candidate-specific blockers belong in that candidate's release evidence.

| ID | Risk | Evidence status | Required control / exit evidence |
| --- | --- | --- | --- |
| R-01 | Frozen receipt semantics are changed or misread by a consumer. | Known integration risk; no current consumer-conformance claim. | Versioned mapping contract; field-level positive/negative vectors; consumer release gate. |
| R-02 | A receipt is interpreted as proof of physical completion or truth. | NORMATIVE NON-CLAIM. | Preserve [NON-CLAIMS.md](NON-CLAIMS.md); require an external evidence chain and explicit policy. |
| R-03 | `PARTIAL`, `UNKNOWN`, or tool self-report is treated as success/safe retry. | NORMATIVE NON-CLAIM. | Fail-closed outcome mapping; adversarial outcome vectors; no silent promotion. |
| R-04 | Replay, forgery, substitution, key theft, or signature confusion. | Threat class; controls partially IMPLEMENTED. | Strict canonical/signature/key validation, nonce/chain policy where applicable, negative vectors, and branch-local security results. |
| R-05 | Stale, revoked, or wrong trust-anchor/key material is accepted. | IMPLEMENTATION and policy gap must be revision-checked. | Explicit key lifecycle, freshness/revocation/anchor contracts, offline limits, and verifier tests. |
| R-06 | Canonicalization or parser differences break interoperability. | Known cross-implementation risk. | Frozen vectors, malformed/duplicate-key negatives, deterministic error taxonomy, independent implementations. |
| R-07 | Privacy loss through hashes, correlation, metadata, or retention. | NORMATIVE concern. | Data-minimization review; keyed-digest policy where appropriate; retention and disclosure documentation; privacy tests. |
| R-08 | Claimed conformance is not reproducible at the release SHA. | Candidate-specific; must be verified at each release. | Immutable SHA, published runner/profile, full CI and independent QA artifacts. |
| R-09 | Governance or registry capture creates a misleading trust claim. | Threat hypothesis until a concrete registry profile exists. | Explicit authority/delegation/revocation/governance model and emergency-abuse analysis. |
| R-10 | Users infer global-standard, pilot, or production status from source/published package. | UNKNOWN; evidence insufficient. | Evidence labels in releases/docs; external adoption and operating metrics before claim escalation. |
| R-11 | Independent implementations construct or verify incompatible COSE objects because prose and implementation disagree. | OBSERVED documentation/implementation contradiction. | One normative COSE construction and layered-verification contract; positive, negative, and cross-implementation vectors. |

| R-12 | A decision binds to an action but not to the exact request, allowing an approval for one request to be replayed against another equivalent request. | PARTIALLY CLOSED. Decisions chained to a deferred receipt are bound to that hold, and reuse of a deferred receipt across holds is refused. **RESIDUAL:** bare holds remain distinguishable only by transport state, not signed material. | Define a versioned contract that commits a bare decision to its exact `holdId`; add a cross-hold replay rejection vector and a positive bare-flow control before claiming the residual closed. |

Risk acceptance must name an accountable maintainer, scope, expiry, compensating controls, and an observable rollback or containment path.
