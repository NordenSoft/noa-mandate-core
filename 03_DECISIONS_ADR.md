# NOA Receipt Decision Index

This index routes decisions; it does not replace the cited source or its exact revision. A proposed document is not an accepted requirement. `CORRECTIONS.md` records the maintained public claim corrections.

| ID | Status | Decision | Authoritative source |
| --- | --- | --- | --- |
| ADR-R-001 | ACCEPTED / frozen scope | `noa.receipt/0.1` has stable wire semantics and must not gain convenience fields through adapters. | [docs/draft-noa-receipt-00.md](docs/draft-noa-receipt-00.md), [VERSIONING.md](VERSIONING.md) |
| ADR-R-002 | ACCEPTED | Native JSON verification, package semver, and optional COSE carriage/algorithm identifiers are separate compatibility axes. | [VERSIONING.md](VERSIONING.md), [docs/draft-noa-receipt-00.md](docs/draft-noa-receipt-00.md) |
| ADR-R-003 | ACCEPTED | Receipt signatures prove origin and integrity of a statement, not truth, current authorization, physical completion, completeness, exactly-once execution, or human understanding. | [NON-CLAIMS.md](NON-CLAIMS.md) |
| ADR-R-004 | ACCEPTED / field semantic preservation | `action.id` is the action/tool identifier; `action.canonical` is the risk-table key; `paramsHash` is not a universal re-derived digest; absent `0.1` fields are `SOURCE_ABSENT`; `PARTIAL` cannot silently become `PASS`. | [docs/draft-noa-receipt-00.md](docs/draft-noa-receipt-00.md), [NON-CLAIMS.md](NON-CLAIMS.md) |
| ADR-R-005 | PROPOSED | Trusted-input provenance must bind each trust input to its evidence origin and fail closed when provenance is absent or invalid. | [THREAT-MODEL.md](THREAT-MODEL.md), [05_RISK_REGISTER.md](05_RISK_REGISTER.md) |
| ADR-R-006 | UNRESOLVED | Define an additive, versioned integration contract that preserves receipt field semantics and detects consumer mismatch. | [04_ROADMAP.md](04_ROADMAP.md) |
| ADR-R-007 | UNRESOLVED | Define a public conformance profile and independence criteria before claiming two independent implementations. | [conformance/MATRIX.md](conformance/MATRIX.md), [04_ROADMAP.md](04_ROADMAP.md) |
| ADR-R-008 | PARTIALLY RESOLVED | Signer roles, `kid` binding, and layered native-chain verification are implemented and covered by conformance vectors. COSE protected-header placement, embedded-signature presence, exact payload bytes, and detached-payload binding still require revision-specific evidence before an interoperability claim. | [docs/receipt-spec.md](docs/receipt-spec.md), [docs/ietf/draft-noa-scitt-ai-agent-receipt.md](docs/ietf/draft-noa-scitt-ai-agent-receipt.md), `src/cose/receipt-cose.ts`, `src/cose/cose-sign1.ts` |
| ADR-0003 | RECORDED DIRECTION / PROPOSED ARCHITECTURE | Records an enforcement-boundary direction while retaining the detailed architecture as proposed; it establishes no implementation, deployment, or release claim. | [docs/ADR-0003-enforcement-boundary.md](docs/ADR-0003-enforcement-boundary.md) |

Future ADRs must name the problem, alternatives, accountable decision maker, exact normative revision, compatibility effect, security/privacy impact, required vectors, implementation work, and rollback/forward-fix path.
