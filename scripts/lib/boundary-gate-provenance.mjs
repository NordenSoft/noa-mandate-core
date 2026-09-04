import { createHash } from "node:crypto";

import {
  BOUNDARY_AUTHORITY_CLASS_CANDIDATE_TIER_A,
  BOUNDARY_AUTHORITY_CLASS_EXTERNAL,
  BOUNDARY_BOOTSTRAP_MODE_CANDIDATE_TIER_A_NON_AUTHORITY,
  BOUNDARY_CONTROL_MANIFEST_VERSION,
  CANDIDATE_TIER_A_NON_AUTHORITY_NON_CLAIM,
  canonicalBoundaryJson,
  EXTERNAL_SANITIZED_AUTHORIZATION_NON_CLAIM,
} from "./boundary-bootstrap.mjs";
import {
  GATE_PROVENANCE_SCHEMA_VERSION,
  normalizeGateProvenance,
  PROVENANCE_BOUND_GATE_EVENT_PROTOCOL,
  unverifiedGateProvenance,
} from "./gate-event-contract.mjs";

export const BOUNDARY_CANDIDATE_TIER_A_GATE_EXPECTATION = Object.freeze({
  authorityClass: BOUNDARY_AUTHORITY_CLASS_CANDIDATE_TIER_A,
  authorityNonClaim: CANDIDATE_TIER_A_NON_AUTHORITY_NON_CLAIM,
  bootstrapMode: BOUNDARY_BOOTSTRAP_MODE_CANDIDATE_TIER_A_NON_AUTHORITY,
  controlManifestVersion: BOUNDARY_CONTROL_MANIFEST_VERSION,
  externalAuthorizationSha256: null,
  protocol: PROVENANCE_BOUND_GATE_EVENT_PROTOCOL,
  schemaVersion: GATE_PROVENANCE_SCHEMA_VERSION,
  tier: null,
  verification: "VERIFIED_BOOTSTRAP",
  visibilitySource: null,
});

/**
 * Project one verified boundary-bootstrap observation onto the shared gate-event provenance
 * contract. This is evidence classification, never a source of authority: an absent, unknown, or
 * class/non-claim-inconsistent observation is represented explicitly as UNVERIFIED_BOOTSTRAP.
 */
export function boundaryGateProvenance(observed, { tier = null, visibilitySource = null } = {}) {
  const unverified = () => unverifiedGateProvenance({ tier, visibilitySource });
  if (observed === null || typeof observed !== "object" || Array.isArray(observed)) {
    return unverified();
  }
  try {
    if (observed.authorityClass !== BOUNDARY_AUTHORITY_CLASS_CANDIDATE_TIER_A
        && observed.authorityClass !== BOUNDARY_AUTHORITY_CLASS_EXTERNAL) {
      return unverified();
    }
    const candidateTierANonAuthority =
      observed.authorityClass === BOUNDARY_AUTHORITY_CLASS_CANDIDATE_TIER_A;
    const expectedNonClaim = candidateTierANonAuthority
      ? CANDIDATE_TIER_A_NON_AUTHORITY_NON_CLAIM
      : EXTERNAL_SANITIZED_AUTHORIZATION_NON_CLAIM;
    if (observed.authorityNonClaim !== expectedNonClaim
        || (candidateTierANonAuthority && observed.authorization !== null)
        || (!candidateTierANonAuthority
          && (observed.authorization === null || typeof observed.authorization !== "object"
            || Array.isArray(observed.authorization)))) {
      return unverified();
    }
    const externalAuthorizationSha256 = candidateTierANonAuthority
      ? null
      : createHash("sha256")
        .update(Buffer.from(`${canonicalBoundaryJson(observed.authorization)}\n`, "utf8"))
        .digest("hex");
    return normalizeGateProvenance({
      authorityClass: observed.authorityClass,
      authorityNonClaim: observed.authorityNonClaim,
      bootstrapMode: observed.mode,
      controlManifestDigest: observed.manifest.digest,
      controlManifestVersion: observed.manifest.version,
      externalAuthorizationSha256,
      schemaVersion: GATE_PROVENANCE_SCHEMA_VERSION,
      subject: observed.subject,
      tier,
      verification: "VERIFIED_BOOTSTRAP",
      visibilitySource,
    });
  } catch {
    return unverified();
  }
}
