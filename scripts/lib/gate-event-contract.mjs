export const GATE_EVENT_PROTOCOL = "noa-gate-runner/1";
export const PROVENANCE_BOUND_GATE_EVENT_PROTOCOL = "noa-gate-runner/2";
export const GATE_PROVENANCE_SCHEMA_VERSION = 1;
export const UNVERIFIED_BOOTSTRAP_AUTHORITY_CLASS = "UNVERIFIED_BOOTSTRAP_NO_AUTHORITY";
export const UNVERIFIED_BOOTSTRAP_NON_CLAIM =
  "UNVERIFIED_BOOTSTRAP_RESULT_IS_NOT_GATE_OR_RELEASE_AUTHORITY";

const HEX_40_OR_64_RE = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const HEX_64_RE = /^[0-9a-f]{64}$/;
const SAFE_AUTHORITY_LABEL_RE = /^[A-Z0-9_]{1,128}$/;
const SAFE_BOOTSTRAP_MODE_RE = /^[a-z0-9-]{1,64}$/;
const SAFE_REPOSITORY_RE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const PROVENANCE_KEYS = Object.freeze([
  "authorityClass", "authorityNonClaim", "bootstrapMode", "controlManifestDigest",
  "controlManifestVersion", "externalAuthorizationSha256", "schemaVersion", "subject", "tier",
  "verification", "visibilitySource",
]);

function exactKeys(value, expected) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function normalizeSubject(subject) {
  if (!exactKeys(subject, ["archiveSha256", "commit", "repository", "tree"])
      || !HEX_64_RE.test(String(subject.archiveSha256))
      || !HEX_40_OR_64_RE.test(String(subject.commit))
      || !SAFE_REPOSITORY_RE.test(String(subject.repository))
      || !HEX_40_OR_64_RE.test(String(subject.tree))) {
    throw new TypeError("verified gate provenance requires one exact public candidate subject");
  }
  return Object.freeze({
    archiveSha256: subject.archiveSha256,
    commit: subject.commit,
    repository: subject.repository,
    tree: subject.tree,
  });
}

export function normalizeGateProvenance(provenance) {
  if (!exactKeys(provenance, PROVENANCE_KEYS)
      || provenance.schemaVersion !== GATE_PROVENANCE_SCHEMA_VERSION
      || ![null, "a", "ab"].includes(provenance.tier)
      || ![null, "snapshot", "live"].includes(provenance.visibilitySource)) {
    throw new TypeError("gate provenance requires the exact schema-v1 field set");
  }
  if (provenance.verification === "UNVERIFIED_BOOTSTRAP") {
    if (provenance.authorityClass !== UNVERIFIED_BOOTSTRAP_AUTHORITY_CLASS
        || provenance.authorityNonClaim !== UNVERIFIED_BOOTSTRAP_NON_CLAIM
        || provenance.bootstrapMode !== null
        || provenance.controlManifestDigest !== null
        || provenance.controlManifestVersion !== null
        || provenance.externalAuthorizationSha256 !== null
        || provenance.subject !== null) {
      throw new TypeError("unverified gate provenance cannot carry bootstrap authority or subject claims");
    }
    return Object.freeze({ ...provenance });
  }
  if (provenance.verification !== "VERIFIED_BOOTSTRAP"
      || !SAFE_AUTHORITY_LABEL_RE.test(String(provenance.authorityClass))
      || !SAFE_AUTHORITY_LABEL_RE.test(String(provenance.authorityNonClaim))
      || !SAFE_BOOTSTRAP_MODE_RE.test(String(provenance.bootstrapMode))
      || !HEX_64_RE.test(String(provenance.controlManifestDigest))
      || !Number.isSafeInteger(provenance.controlManifestVersion)
      || provenance.controlManifestVersion <= 0
      || (provenance.externalAuthorizationSha256 !== null
        && !HEX_64_RE.test(String(provenance.externalAuthorizationSha256)))) {
    throw new TypeError("verified gate provenance is malformed");
  }
  return Object.freeze({ ...provenance, subject: normalizeSubject(provenance.subject) });
}

export function unverifiedGateProvenance({ tier = null, visibilitySource = null } = {}) {
  return normalizeGateProvenance({
    authorityClass: UNVERIFIED_BOOTSTRAP_AUTHORITY_CLASS,
    authorityNonClaim: UNVERIFIED_BOOTSTRAP_NON_CLAIM,
    bootstrapMode: null,
    controlManifestDigest: null,
    controlManifestVersion: null,
    externalAuthorizationSha256: null,
    schemaVersion: GATE_PROVENANCE_SCHEMA_VERSION,
    subject: null,
    tier,
    verification: "UNVERIFIED_BOOTSTRAP",
    visibilitySource,
  });
}

function normalizeFinding(finding) {
  if (
    finding === null || typeof finding !== "object" || Array.isArray(finding) ||
    typeof finding.rule !== "string" || finding.rule.length === 0 ||
    typeof finding.subject !== "string" || finding.subject.length === 0
  ) throw new TypeError("gate evidence finding requires non-empty rule and subject strings");
  return Object.freeze({
    rule: finding.rule,
    subject: finding.subject,
    detail: typeof finding.detail === "string" ? finding.detail : "",
  });
}

export function emitGateEvidence(gate, findings) {
  if (typeof gate !== "string" || gate.length === 0) throw new TypeError("gate evidence requires a gate id");
  const record = {
    protocol: GATE_EVENT_PROTOCOL,
    event: "complete",
    gate,
    findings: findings.map(normalizeFinding),
  };
  console.log(JSON.stringify(record));
  return record;
}

export function emitProvenanceBoundGateEvidence(gate, findings, provenance) {
  if (typeof gate !== "string" || gate.length === 0) throw new TypeError("gate evidence requires a gate id");
  const record = {
    protocol: PROVENANCE_BOUND_GATE_EVENT_PROTOCOL,
    event: "complete",
    gate,
    findings: findings.map(normalizeFinding),
    provenance: normalizeGateProvenance(provenance),
  };
  console.log(JSON.stringify(record));
  return record;
}

export function parseGateEvidence(output, { requireProvenance = false, strictOutput = false } = {}) {
  const lines = String(output).split(/\r?\n/).filter((line) => line.length > 0);
  const records = [];
  for (const [index, line] of lines.entries()) {
    let value;
    try { value = JSON.parse(line); }
    catch { continue; }
    if (value?.protocol === GATE_EVENT_PROTOCOL
        || value?.protocol === PROVENANCE_BOUND_GATE_EVENT_PROTOCOL) records.push({ index, value });
  }
  if (records.length !== 1) {
    return { protocolComplete: false, error: `expected exactly one gate terminal record, received ${records.length}`, findings: [] };
  }
  const [{ index, value }] = records;
  if (index !== lines.length - 1 || (strictOutput && lines.length !== 1)) {
    return { protocolComplete: false, error: "gate terminal record was not the final output record", findings: [] };
  }
  const provenanceBound = value.protocol === PROVENANCE_BOUND_GATE_EVENT_PROTOCOL;
  const expectedKeys = provenanceBound
    ? ["event", "findings", "gate", "protocol", "provenance"]
    : ["event", "findings", "gate", "protocol"];
  if (
    !exactKeys(value, expectedKeys) ||
    value.event !== "complete" || typeof value.gate !== "string" || value.gate.length === 0 ||
    !Array.isArray(value.findings) || (requireProvenance && !provenanceBound)
  ) return { protocolComplete: false, error: "gate terminal record is malformed", findings: [] };
  try {
    const findings = value.findings.map(normalizeFinding);
    const provenance = provenanceBound ? normalizeGateProvenance(value.provenance) : null;
    return {
      protocolComplete: true,
      error: null,
      gate: value.gate,
      findings,
      protocol: value.protocol,
      provenance,
    };
  } catch (error) {
    return { protocolComplete: false, error: String(error && error.message), findings: [] };
  }
}

export const gateFindingIdentity = ({ rule, subject }) => JSON.stringify([rule, subject]);

export function newGateFindingsBeyondBaseline(current, baseline = []) {
  const counts = new Map();
  for (const finding of baseline) {
    const identity = gateFindingIdentity(finding);
    counts.set(identity, (counts.get(identity) ?? 0) + 1);
  }
  const added = [];
  for (const finding of current) {
    const identity = gateFindingIdentity(finding);
    const remaining = counts.get(identity) ?? 0;
    if (remaining > 0) counts.set(identity, remaining - 1);
    else added.push(finding);
  }
  return added;
}
