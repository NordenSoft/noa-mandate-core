/**
 * THE KNOCKOUT RUNNER — evidence-based verdicts, hash-verified restoration, known baselines.
 *
 * ── WHY THIS REPLACED THE OLD LOOP ──────────────────────────────────────────────────────────────
 * The previous runner decided `verdict: r.green ? "SURVIVED" : "KILLED"`. Any non-zero exit was
 * KILLED — a real detection, a pre-existing failure, a compile error, a crash and a timeout were all
 * the same value. It also took no baseline, so a suite that was ALREADY red reported KILLED for
 * every mutation.
 *
 * MEASURED (R8-26/R8-27, 2026-07-31). Six of thirty-four entries target `packages/gate`, whose
 * baseline is `exit 1, 200 pass / 2 fail` — two owner-deferred ADR-0006 failures. Setting one
 * entry's `replace` to be BYTE-IDENTICAL to its `find`, so the source file does not change at all:
 *
 *     node scripts/lint-control-knockout.mjs --only grant-single-use-cas
 *     ok  grant-single-use-cas   …   killed 1/1
 *
 * A no-op scored a kill. Those six entries were measuring the two deferred failures, not their own
 * controls.
 *
 * And the mutation was written straight into the canonical worktree (`fs.writeFileSync(ROOT/…)`),
 * restored only in a `finally`, with nothing verifying that the restore actually matched. A crash
 * between write and restore left a weakened control on disk, and a concurrent build would have
 * compiled it. Round 8 observed `git status` rotating through modified `src/cose/cbor.ts`,
 * `src/intrinsics.ts` and `src/verify.ts` during a run.
 *
 * ── WHAT A KNOCKOUT NOW HAS TO PROVE ────────────────────────────────────────────────────────────
 * A knockout result is evidence only if the framework can show all six:
 *   1. the target file matched its expected baseline BEFORE the mutation (sha256);
 *   2. the mutation actually changed the bytes (post-mutation sha256 differs);
 *   3. the suite's CLEAN baseline is known, so "it failed" can be distinguished from "it was
 *      already failing";
 *   4. the failure set under mutation STRICTLY CONTAINS the baseline failure set — i.e. this
 *      knockout broke something the baseline did not;
 *   5. the file was restored to the exact baseline sha256;
 *   6. the worktree carries no residue.
 *
 * Anything else gets a verdict that says what actually happened, from a CLOSED taxonomy. There is
 * no "probably".
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import {
  executedProofFileFor,
  parseProofEvents,
  resolveProof,
  TYPESCRIPT_TEST_REGISTER,
} from "./proof-resolve.mjs";
import {
  GATE_EVENT_PROTOCOL,
  gateFindingIdentity,
  newGateFindingsBeyondBaseline,
  normalizeGateProvenance,
  parseGateEvidence,
  PROVENANCE_BOUND_GATE_EVENT_PROTOCOL,
} from "./gate-event-contract.mjs";
import {
  PROOF_EVENT_SOCKET_ENV,
  PROOF_EVENT_TOKEN_ENV,
  proofEventReporterNodeOption,
} from "./proof-event-contract.mjs";
import {
  BOUNDARY_CANDIDATE_TIER_A_GATE_EXPECTATION,
} from "./boundary-gate-provenance.mjs";
import { BOUNDARY_KNOCKOUT_BOOTSTRAP_ENV } from "./boundary-bootstrap.mjs";
import {
  acquireCooperativeSourceLease,
  acquireSourceLease,
  admitArmPlan,
  cancelAdmittedArm,
  cancelMaterializedArm,
  canonicalJsonBytes,
  captureAndSealCandidate,
  closeCooperativeSourceLease,
  consumeBoundaryKnockoutBootstrapToken,
  createKnockoutWorkerSubject,
  KNOCKOUT_WORKSPACE_ARM_WORKER_TIMEOUT_LIMIT_MS,
  KNOCKOUT_WORKSPACE_CAPTURE_TIMEOUT_LIMIT_MS,
  KNOCKOUT_WORKSPACE_COMMAND_TIMEOUT_LIMIT_MS,
  KNOCKOUT_SELFTEST_GATE,
  KNOCKOUT_WORKER_OPERATIONS,
  KNOCKOUT_WORKER_RELATIVE_PATH,
  knockoutBaselineKeySha256,
  knockoutBaselineObservationFromWire,
  knockoutCandidateSubject,
  knockoutResultEvidenceFromWire,
  knockoutSelftestKeySha256,
  knockoutWorkerSubjectSha256,
  LEGACY_TOMBSTONE_PROTOCOL,
  materializeArm,
  openKnockoutCustody,
  releaseSourceLease,
  runArmWorker,
  isKnockoutLegacyTombstoneForRoot as isLegacyTombstoneForRoot,
} from "./knockout-workspace.mjs";

export { LEGACY_TOMBSTONE_PROTOCOL } from "./knockout-workspace.mjs";

const KNOCKOUT_REPOSITORY_ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../..",
);
export const TRUSTED_TYPESCRIPT_TEST_REGISTER = TYPESCRIPT_TEST_REGISTER;

/**
 * CLOSED registry-entry schema. A spelling the runner does not implement is an ERROR, never inert
 * documentation: silently accepting one would let the registry describe a stronger experiment than
 * the runner actually performs.
 */
export const KNOCKOUT_ENTRY_KEYS = new Set([
  "id", "control", "file", "find", "replace", "also", "andAlso", "companionFile", "kind",
  "suite", "expectHang", "requires", "gateId", "expectedGateFindings",
  "expectedGateProvenance", "expectedSetupIntegrity",
]);

const ARM_TERMINAL_PREFIX = "NOA_BOUNDARY_ARM_TERMINAL ";
const ARM_TERMINAL_PROTOCOL = "noa-boundary-arm-terminal/1";
const ARM_CASE_PLAN_DIGEST_MISMATCH = "ARM_CASE_PLAN_DIGEST_MISMATCH";
const HEX_64_RE = /^[0-9a-f]{64}$/;
const ARM_CASE_ID_RE = /^case\.[\x21-\x7e]{1,250}$/;
const ARM_TERMINAL_KEYS = Object.freeze([
  "casePlanSha256", "duplicateCaseCount", "event", "failureCount", "missingCaseCount",
  "observedCaseCount", "plannedCaseCount", "protocol", "status", "unexpectedCaseCount",
]);
const KNOCKOUT_OBSERVATION_KEYS = Object.freeze([
  "armTerminalProtocolComplete", "armTerminalProtocolError", "armTerminalSummary", "exit",
  "failing", "failureEvents", "fileFailureCount", "findings", "gate", "gateFindings",
  "gateProtocol", "gateProtocolComplete", "gateProtocolError", "gateProvenance", "ms", "out",
  "protocolComplete", "protocolError", "signal", "testCount", "testEvents", "timedOut",
]);
const CONTAINED_OBSERVATION_RESPONSE_KEYS = Object.freeze([
  "exit", "machineDiagnostics", "machineOutput", "observationError", "ok", "out", "signal",
  "testEvents", "timedOut",
]);
// Candidate-derived subject and manifest digest cannot be hard-coded in the registry. The exact
// classifier properties can and must be. Runtime phase binding below keeps the dynamic values tied
// to the CLEAN candidate and proves that restoration returns to those exact bytes.
const EXPECTED_GATE_PROVENANCE_KEYS = Object.freeze([
  "authorityClass", "authorityNonClaim", "bootstrapMode", "controlManifestBinding",
  "controlManifestVersion", "externalAuthorizationSha256", "protocol", "schemaVersion",
  "subjectBinding", "tier", "verification", "visibilitySource",
]);
export const MUTATED_GATE_SUBJECT_BINDING = "MUTATED_EQUALS_BASELINE";
export const CHANGING_GATE_CONTROL_MANIFEST_BINDING =
  "MUTATED_DIFFERS_FROM_BASELINE";
export const BOUNDARY_CANDIDATE_TIER_A_KNOCKOUT_PROVENANCE_EXPECTATION = Object.freeze({
  ...BOUNDARY_CANDIDATE_TIER_A_GATE_EXPECTATION,
  controlManifestBinding: CHANGING_GATE_CONTROL_MANIFEST_BINDING,
  subjectBinding: MUTATED_GATE_SUBJECT_BINDING,
});
const SETUP_INTEGRITY_KEYS = Object.freeze([
  "baselineCaseCount", "baselineCasePlanSha256", "exitCode", "idSubstitution",
  "mutatedCaseCount", "mutatedCasePlanSha256", "stableError", "terminalProtocol",
  "terminalStatus",
]);
const SETUP_INTEGRITY_SUBSTITUTION_KEYS = Object.freeze(["from", "to"]);
const exactKeys = (value, keys) => value !== null && typeof value === "object" && !Array.isArray(value)
  && JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort());

/** Validate the one closed success response emitted by the contained observer. */
export function validateContainedObservationResponse(response) {
  if (response === null || typeof response !== "object" || Array.isArray(response)) {
    throw new Error("trusted contained knockout observer returned a non-object response");
  }
  if (response.ok !== true) {
    throw new Error(`trusted contained knockout observer refused: ${String(response.error)}`);
  }
  if (
    !exactKeys(response, CONTAINED_OBSERVATION_RESPONSE_KEYS) ||
    !(response.exit === null || Number.isInteger(response.exit)) ||
    !(response.signal === null || typeof response.signal === "string") ||
    typeof response.timedOut !== "boolean" || typeof response.out !== "string" ||
    typeof response.testEvents !== "string" || typeof response.machineOutput !== "string" ||
    typeof response.machineDiagnostics !== "string" ||
    !(response.observationError === null || typeof response.observationError === "string")
  ) {
    throw new Error("trusted contained knockout observer returned a malformed observation");
  }
  return Object.freeze({ ...response });
}

function validateExpectedGateProvenance(entry) {
  const expected = entry.expectedGateProvenance;
  if (!exactKeys(expected, EXPECTED_GATE_PROVENANCE_KEYS)) {
    throw new Error(
      `invalid knockout entry ${JSON.stringify(entry.id)}: expectedGateProvenance must contain ` +
        `exactly ${EXPECTED_GATE_PROVENANCE_KEYS.join(", ")}`,
    );
  }
  if (expected.protocol !== PROVENANCE_BOUND_GATE_EVENT_PROTOCOL
      || expected.verification !== "VERIFIED_BOOTSTRAP"
      || expected.subjectBinding !== MUTATED_GATE_SUBJECT_BINDING
      || expected.controlManifestBinding !== CHANGING_GATE_CONTROL_MANIFEST_BINDING) {
    throw new Error(
      `invalid knockout entry ${JSON.stringify(entry.id)}: expectedGateProvenance requires ` +
        `${PROVENANCE_BOUND_GATE_EVENT_PROTOCOL} VERIFIED_BOOTSTRAP evidence with exact ` +
        "mutated-subject and changing-control-manifest bindings",
    );
  }
  try {
    // Delegate the field grammar to the canonical gate-event contract. The two candidate-derived
    // values are syntactically valid sentinels here; real values are validated on every observation.
    normalizeGateProvenance({
      authorityClass: expected.authorityClass,
      authorityNonClaim: expected.authorityNonClaim,
      bootstrapMode: expected.bootstrapMode,
      controlManifestDigest: "0".repeat(64),
      controlManifestVersion: expected.controlManifestVersion,
      externalAuthorizationSha256: expected.externalAuthorizationSha256,
      schemaVersion: expected.schemaVersion,
      subject: {
        archiveSha256: "0".repeat(64),
        commit: "0".repeat(40),
        repository: "expected/subject",
        tree: "0".repeat(40),
      },
      tier: expected.tier,
      verification: expected.verification,
      visibilitySource: expected.visibilitySource,
    });
  } catch (error) {
    throw new Error(
      `invalid knockout entry ${JSON.stringify(entry.id)}: expectedGateProvenance is malformed: ` +
        `${String(error && error.message)}`,
    );
  }
}

function validateExpectedSetupIntegrity(entry) {
  const expected = entry.expectedSetupIntegrity;
  if (!exactKeys(expected, SETUP_INTEGRITY_KEYS)) {
    throw new Error(
      `invalid knockout entry ${JSON.stringify(entry.id)}: expectedSetupIntegrity must contain ` +
        `exactly ${SETUP_INTEGRITY_KEYS.join(", ")}`,
    );
  }
  if (
    expected.exitCode !== 2 || expected.terminalProtocol !== ARM_TERMINAL_PROTOCOL ||
    expected.terminalStatus !== "SETUP_FAILED" ||
    expected.stableError !== ARM_CASE_PLAN_DIGEST_MISMATCH
  ) {
    throw new Error(
      `invalid knockout entry ${JSON.stringify(entry.id)}: expectedSetupIntegrity supports only ` +
        `exit 2 ${ARM_TERMINAL_PROTOCOL} SETUP_FAILED ${ARM_CASE_PLAN_DIGEST_MISMATCH}`,
    );
  }
  if (
    !Number.isSafeInteger(expected.baselineCaseCount) || expected.baselineCaseCount < 1 ||
    !Number.isSafeInteger(expected.mutatedCaseCount) ||
    expected.mutatedCaseCount !== expected.baselineCaseCount
  ) {
    throw new Error(
      `invalid knockout entry ${JSON.stringify(entry.id)}: setup-integrity case counts must be the ` +
        "same positive safe integer",
    );
  }
  if (
    !HEX_64_RE.test(expected.baselineCasePlanSha256) ||
    !HEX_64_RE.test(expected.mutatedCasePlanSha256) ||
    expected.baselineCasePlanSha256 === expected.mutatedCasePlanSha256
  ) {
    throw new Error(
      `invalid knockout entry ${JSON.stringify(entry.id)}: setup-integrity plan digests must be ` +
        "distinct lowercase SHA-256 values",
    );
  }
  if (!exactKeys(expected.idSubstitution, SETUP_INTEGRITY_SUBSTITUTION_KEYS)) {
    throw new Error(
      `invalid knockout entry ${JSON.stringify(entry.id)}: idSubstitution must contain exactly from and to`,
    );
  }
  const { from, to } = expected.idSubstitution;
  if (!ARM_CASE_ID_RE.test(from) || !ARM_CASE_ID_RE.test(to) || from === to) {
    throw new Error(
      `invalid knockout entry ${JSON.stringify(entry.id)}: idSubstitution must contain two distinct ` +
        "bounded printable arm case IDs",
    );
  }
  if (entry.find !== from || entry.replace !== to) {
    throw new Error(
      `invalid knockout entry ${JSON.stringify(entry.id)}: setup-integrity find/replace must equal ` +
        "the declared from/to ID substitution",
    );
  }
  if (
    entry.also !== undefined || entry.andAlso !== undefined || entry.companionFile !== undefined ||
    entry.requires !== undefined
  ) {
    throw new Error(
      `invalid knockout entry ${JSON.stringify(entry.id)}: setup-integrity measurement permits ` +
        "exactly one file and one declared ID substitution with no dependency lane",
    );
  }
  if (entry.expectedGateFindings.length !== 1) {
    throw new Error(
      `invalid knockout entry ${JSON.stringify(entry.id)}: setup-integrity measurement requires ` +
        "exactly one expected gate finding",
    );
  }
}

/** Public knockouts may not depend on an unpublished source checkout. */
export const DEPENDENCY_PROBES = Object.freeze({});
const DECLARABLE_DEPENDENCIES = new Set();
/** Validate the whole registry before any suite is allowed to run. Returns its unambiguous id map. */
export function validateKnockoutRegistry(registry) {
  if (!Array.isArray(registry)) throw new Error("knockout registry must be an array");

  const byId = new Map();
  for (const entry of registry) {
    const id = entry && typeof entry.id === "string" ? entry.id : "<missing id>";
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      throw new Error(`invalid knockout entry ${JSON.stringify(id)}: entry must be an object`);
    }
    for (const key of Object.keys(entry)) {
      if (!KNOCKOUT_ENTRY_KEYS.has(key)) {
        throw new Error(`invalid knockout entry ${JSON.stringify(id)}: unknown key ${JSON.stringify(key)}`);
      }
    }
    if (typeof entry.id !== "string" || entry.id.length === 0) {
      throw new Error(`invalid knockout entry ${JSON.stringify(id)}: id must be a non-empty string`);
    }
    if (byId.has(entry.id)) {
      throw new Error(`invalid knockout entry ${JSON.stringify(entry.id)}: duplicate id`);
    }

    for (const key of ["control", "file", "find"]) {
      if (typeof entry[key] !== "string" || entry[key].length === 0) {
        throw new Error(
          `invalid knockout entry ${JSON.stringify(entry.id)}: ${key} must be a non-empty string`,
        );
      }
    }
    if (entry.requires !== undefined) {
      // Validated HERE, at registry load, not at partition time — an entry declaring a dependency
      // nobody can probe would otherwise sit inert until the day that dependency went missing, and
      // then quietly exclude itself from measurement instead of erroring.
      if (!Array.isArray(entry.requires) || entry.requires.length === 0) {
        throw new Error(
          `invalid knockout entry ${JSON.stringify(entry.id)}: requires must be a non-empty array`,
        );
      }
      for (const name of entry.requires) {
        if (!DECLARABLE_DEPENDENCIES.has(name)) {
          throw new Error(
            `invalid knockout entry ${JSON.stringify(entry.id)}: unknown dependency ` +
              `${JSON.stringify(name)}. Declarable: ${[...DECLARABLE_DEPENDENCIES].join(", ")}`,
          );
        }
      }
    }
    if (typeof entry.replace !== "string") {
      throw new Error(
        `invalid knockout entry ${JSON.stringify(entry.id)}: replace must be a string`,
      );
    }
    if (
      !Array.isArray(entry.suite) || entry.suite.length !== 3 ||
      typeof entry.suite[0] !== "string" || typeof entry.suite[1] !== "string" ||
      !Array.isArray(entry.suite[2]) || entry.suite[2].some((arg) => typeof arg !== "string")
    ) {
      throw new Error(
        `invalid knockout entry ${JSON.stringify(entry.id)}: suite must be [directory, command, stringArgs[]]`,
      );
    }
    if (entry.kind !== "tests" && entry.kind !== "gate") {
      throw new Error(
        `invalid knockout entry ${JSON.stringify(entry.id)}: kind must be exactly "tests" or "gate", ` +
          `got ${JSON.stringify(entry.kind)}`,
      );
    }
    if (entry.companionFile !== undefined && (
      typeof entry.companionFile !== "string" || entry.companionFile.length === 0
    )) {
      throw new Error(
        `invalid knockout entry ${JSON.stringify(entry.id)}: companionFile must be a non-empty string`,
      );
    }
    if (entry.expectHang !== undefined && typeof entry.expectHang !== "boolean") {
      throw new Error(
        `invalid knockout entry ${JSON.stringify(entry.id)}: expectHang must be a boolean`,
      );
    }
    if (entry.kind === "gate") {
      if (Object.prototype.hasOwnProperty.call(entry, "expectHang")) {
        throw new Error(
          `invalid knockout entry ${JSON.stringify(entry.id)}: gate kind cannot declare expectHang; ` +
            "a timeout has no completed structured terminal record and is never gate evidence",
        );
      }
      if (typeof entry.gateId !== "string" || entry.gateId.length === 0) {
        throw new Error(
          `invalid knockout entry ${JSON.stringify(entry.id)}: gate kind requires a non-empty gateId`,
        );
      }
      if (!Array.isArray(entry.expectedGateFindings) || entry.expectedGateFindings.length === 0) {
        throw new Error(
          `invalid knockout entry ${JSON.stringify(entry.id)}: gate kind requires a non-empty expectedGateFindings array`,
        );
      }
      const identities = new Set();
      for (const [index, finding] of entry.expectedGateFindings.entries()) {
        if (
          finding === null || typeof finding !== "object" || Array.isArray(finding) ||
          JSON.stringify(Object.keys(finding).sort()) !== JSON.stringify(["rule", "subject"])
        ) {
          throw new Error(
            `invalid knockout entry ${JSON.stringify(entry.id)}: expectedGateFindings[${index}] ` +
              "must contain exactly rule and subject",
          );
        }
        if (
          typeof finding.rule !== "string" || finding.rule.length === 0 ||
          typeof finding.subject !== "string" || finding.subject.length === 0
        ) {
          throw new Error(
            `invalid knockout entry ${JSON.stringify(entry.id)}: expectedGateFindings[${index}] ` +
              "requires non-empty rule and subject strings",
          );
        }
        const identity = gateFindingIdentity(finding);
        if (identities.has(identity)) {
          throw new Error(
            `invalid knockout entry ${JSON.stringify(entry.id)}: duplicate expected gate finding ${identity}`,
          );
        }
        identities.add(identity);
      }
      if (entry.expectedGateProvenance !== undefined) validateExpectedGateProvenance(entry);
      if (entry.expectedSetupIntegrity !== undefined) validateExpectedSetupIntegrity(entry);
    } else if (
      entry.gateId !== undefined || entry.expectedGateFindings !== undefined ||
      entry.expectedGateProvenance !== undefined || entry.expectedSetupIntegrity !== undefined
    ) {
      throw new Error(
        `invalid knockout entry ${JSON.stringify(entry.id)}: only gate entries may declare gate evidence bindings`,
      );
    }
    if (entry.also !== undefined) {
      if (!Array.isArray(entry.also)) {
        throw new Error(
          `invalid knockout entry ${JSON.stringify(entry.id)}: also must be an array`,
        );
      }
      for (let i = 0; i < entry.also.length; i++) {
        const edit = entry.also[i];
        if (!edit || typeof edit !== "object" || Array.isArray(edit)) {
          throw new Error(
            `invalid knockout entry ${JSON.stringify(entry.id)}: also[${i}] must be an object`,
          );
        }
        for (const key of Object.keys(edit)) {
          if (key !== "find" && key !== "replace") {
            throw new Error(
              `invalid knockout entry ${JSON.stringify(entry.id)}: unknown also[${i}] key ${JSON.stringify(key)}`,
            );
          }
        }
        if (typeof edit.find !== "string" || edit.find.length === 0) {
          throw new Error(
            `invalid knockout entry ${JSON.stringify(entry.id)}: also[${i}].find must be a non-empty string`,
          );
        }
        if (typeof edit.replace !== "string") {
          throw new Error(
            `invalid knockout entry ${JSON.stringify(entry.id)}: also[${i}].replace must be a string`,
          );
        }
      }
    }
    byId.set(entry.id, entry);
  }

  for (const entry of registry) {
    if (entry.andAlso === undefined) continue;
    if (typeof entry.andAlso !== "string" || entry.andAlso.length === 0) {
      throw new Error(
        `invalid knockout entry ${JSON.stringify(entry.id)}: andAlso must name a non-empty entry id`,
      );
    }
    if (!byId.has(entry.andAlso)) {
      throw new Error(
        `invalid knockout entry ${JSON.stringify(entry.id)}: andAlso references missing entry id ${JSON.stringify(entry.andAlso)}`,
      );
    }
  }
  return byId;
}

/** CLOSED verdict taxonomy. Every value is a statement about observed evidence. */
export const VERDICT = {
  /** the detector failed, and its failure set strictly contains the baseline's — a real kill */
  DETECTOR_TRIGGERED: "DETECTOR_TRIGGERED",
  /** the suite stayed exactly as green/red as its baseline — nothing measures this control */
  DETECTOR_DID_NOT_TRIGGER: "DETECTOR_DID_NOT_TRIGGER",
  /** the `find` text no longer matches, or matched more than once — the entry rotted */
  MUTATION_NOT_APPLIED: "MUTATION_NOT_APPLIED",
  /** the suite failed, but ONLY with the failures its baseline already had */
  ANTI_VACUITY_FAILED: "ANTI_VACUITY_FAILED",
  /** the run exceeded its timeout AND the entry declared a hang as its expected symptom */
  TIMEOUT_WITH_EXPECTED_SYMPTOM: "TIMEOUT_WITH_EXPECTED_SYMPTOM",
  /** the run exceeded its timeout and no hang was expected — proves nothing about the control */
  TIMEOUT_UNEXPLAINED: "TIMEOUT_UNEXPLAINED",
  /** the harness could not parse a result at all */
  INVALID_TEST: "INVALID_TEST",
  /**
   * the mutated suite produced NO test results at all — the replacement did not build.
   *
   * ── QA-16 (2026-07-31, cross-family reviewer, then MEASURED ────────────────────────────────────
   * This verdict exists because its absence was silently scoring compile errors as kills. The old
   * code INFERRED "is this a test suite?" from whether any failures were observed:
   *
   *     const isTestSuite = baseline.failing.size > 0 || ev.mutatedFailing.length > 0;
   *
   * For a compiled package whose baseline is GREEN, `baseline.failing.size` is 0. If the mutation
   * does not compile, `npm test` fails at `npm run build`, no test ever runs, and
   * `mutatedFailing.length` is 0 too — so `isTestSuite` came out FALSE, the run fell into the GATE
   * branch, and `baseline.exit === 0 && obs.exit !== 0` returned DETECTOR_TRIGGERED.
   *
   * MEASURED, by replacing one entry's `replace` with text that is not TypeScript at all:
   *     node scripts/lint-control-knockout.mjs --only r8-15-deep-copy-defineproperty
   *     ok  DETECTOR_TRIGGERED  r8-15-deep-copy-defineproperty
   *     proven load-bearing 1/1
   * The framework reported a control PROVEN when nothing had been tested. This repository's
   * standing rule is that a compile-only knockout proves an identifier exists, not that a check
   * runs — the rule was written down and the tool did the opposite.
   */
  MUTATION_DID_NOT_BUILD: "MUTATION_DID_NOT_BUILD",
  /** the file could not be returned to its baseline bytes */
  RESTORATION_FAILED: "RESTORATION_FAILED",
  /**
   * a dependency this entry DECLARES was absent, so the suite was NOT RUN and nothing was measured.
   * Missing setup is neither a kill nor a finding: the experiment did not happen. Public registry
   * validation rejects every external source dependency before measurement.
   */
  SETUP_FAILED: "SETUP_FAILED",
};

/**
 * Entries whose declared dependency is absent: `{ id, missing }`. NOT findings, NOT kills.
 *
 * Kept separate from both so the two counts stay honest — a SETUP_FAILED entry leaves the
 * `proven X/Y` DENOMINATOR as well as the numerator, because a control that was never measured did
 * not fail to prove itself; nobody asked it. Folding these into `Y` would quietly report a coverage
 * level the run never reached.
 */
export function partitionByDependency(registry, repoRoot, probes) {
  const runnable = [];
  const setupFailed = [];
  const resolved = new Map();
  const dependenciesByEntry = new Map();
  for (const entry of registry) {
    const requires = entry.requires ?? [];
    const missing = [];
    const dependencies = {};
    for (let i = 0; i < requires.length; i++) {
      const name = requires[i];
      const probe = probes[name];
      // An unknown dependency name is an ERROR, never a requirement that silently never holds:
      // otherwise any entry could exclude itself from measurement by misspelling its own dependency.
      if (typeof probe !== "function") {
        throw new Error(
          `knockout entry ${entry.id}: unknown dependency "${name}". Declarable names: ` +
            `${Object.keys(probes).join(", ")}. Add a probe before declaring it.`,
        );
      }
      if (!resolved.has(name)) {
        resolved.set(name, probe(repoRoot));
      }
      const dependency = resolved.get(name);
      if (dependency === null) missing[missing.length] = name;
      else dependencies[name] = dependency;
    }
    if (missing.length > 0) setupFailed[setupFailed.length] = { id: entry.id, missing };
    else {
      runnable[runnable.length] = entry;
      dependenciesByEntry.set(entry.id, Object.freeze(dependencies));
    }
  }
  return { runnable, setupFailed, dependenciesByEntry };
}

/**
 * Split an already dependency-filtered registry into `total` disjoint shards and return shard
 * `index` (0-based, matching GitHub's `strategy.job-index` so no arithmetic is needed in YAML).
 *
 * ── WHY SUITE-AFFINE CONTIGUOUS CHUNKS, AND NOT ROUND-ROBIN ─────────────────────────────────────
 * A baseline is measured once per DISTINCT SUITE among the entries a run selects, and an arm costs
 * one more run of that entry's suite. MEASURED on this registry: 208 dependency-runnable controls
 * across 18 suites, and badly skewed — 41 in packages/evidence, 39 in packages/signer-core, 27 at
 * the root, then 21, 19, 17, 12, 9, 8 and a tail of ones and twos. Round-robin would hand nearly
 * every suite to every shard, so eight shards would pay about 144 baselines. The current contiguous
 * slices pay 25 (the sum of the measured per-shard suite counts below), avoiding 119 repeated
 * baselines while keeping every slice within one entry of every other slice.
 *
 * So entries are grouped by suite first, in registry order, and the shards are contiguous slices of
 * that grouping. MEASURED on the current registry at eight shards: 26 entries each, touching 1, 2,
 * 6, 2, 3, 3, 2 and 6 suites — the sixes are where the tail of one-and-two-entry suites falls, not a
 * failure of affinity, and every shard is far below the eighteen a round-robin would hand each one.
 * The split stays a pure function of the registry: no timing data, no persisted state, no randomness.
 *
 * The partition is exact by construction — the slices are contiguous, disjoint and cover the whole
 * range — which is the property the sweep's coverage promise rests on. A shard that would be EMPTY
 * is returned as such and refused by the caller: a job that measures nothing must not report green.
 */
export function partitionIntoShards(entries, index, total) {
  if (!Number.isInteger(total) || total < 1) {
    throw new Error(`shard total must be an integer >= 1, got ${JSON.stringify(total)}`);
  }
  if (!Number.isInteger(index) || index < 0 || index >= total) {
    throw new Error(`shard index must be an integer in [0, ${total}), got ${JSON.stringify(index)}`);
  }
  const suiteOf = (entry) => JSON.stringify([entry.kind, entry.suite]);
  const bySuite = new Map();
  for (const entry of entries) {
    const key = suiteOf(entry);
    if (!bySuite.has(key)) bySuite.set(key, []);
    bySuite.get(key).push(entry);
  }
  const grouped = [];
  for (const group of bySuite.values()) for (const entry of group) grouped.push(entry);

  const size = Math.floor(grouped.length / total);
  const remainder = grouped.length % total;
  const start = index * size + Math.min(index, remainder);
  const take = size + (index < remainder ? 1 : 0);
  return grouped.slice(start, start + take);
}

const sha = (s) => crypto.createHash("sha256").update(s).digest("hex");

/* ══ THE BUILD STATE IS PART OF THE EXPERIMENT ═══════════════════════════════════════════════════
 *
 * ── THE DEFECT, ROOT-CAUSED THREE TIMES ────────────────────────────────────────────────────────
 * Everything above restores SOURCE and proves it byte-for-byte. Nothing restored what the source
 * had already been COMPILED INTO. A knockout writes a mutant into `src/`, the suite's own
 * `npm run build` turns that mutant into `dist/`, the mutant source is then restored — and the
 * mutant `dist/` stays. It is gitignored, so the residue check at the end of the sweep cannot see
 * it. Whatever runs next reads it.
 *
 * That is not theoretical; it was measured three times, twice as a mutant left on disk after an
 * interrupted run (`src/cose/cbor.ts`, `src/intrinsics.ts`,
 * `packages/adapter-core/src/side-effect-state.mjs`) and once as something far worse. Every package
 * here resolves the kernel through a symlink (`packages/evidence/node_modules/noa-receipt -> ../../..`)
 * and `packages/evidence`'s own test script is
 *
 *     npm run build && node dist/fixtures/gen-fixtures.js && node --test dist/test/*.test.js
 *
 * — a GENERATOR that writes COMMITTED conformance fixtures, built from whatever kernel `dist/`
 * happens to be on disk. A stale mutant kernel rewrote nine settlement fixtures locally, and on
 * 2026-08-14 rewrote `packages/evidence/conformance/settlement/s5-settlement-valid-base.json` in
 * GitHub CI, failing an unrelated pull request with WORKTREE RESIDUE. The residue guard was RIGHT
 * both times — a knockout that cannot restore the tree has not produced a security result — it was
 * simply the only thing left that could still see the damage, and by then the damage was in a
 * committed file.
 *
 * ── THE CLASS, NOT THE INSTANCE ────────────────────────────────────────────────────────────────
 * The rule this restores is: **an experiment owns everything it derives.** Source is one derived
 * surface among four, and it was the only one being returned:
 *
 *   1. the mutated source files            — restored + sha-verified above (was already correct)
 *   2. compiled output (`dist/`)           — byte-exact, from a pre-mutation snapshot
 *   3. generated files git TRACKS          — from this run's own byte snapshot when the path was
 *      (conformance fixtures, vectors)       already dirty, from HEAD when it was clean
 *   4. the INDEX entry of both of those    — `git checkout --` reads FROM the index, so a suite
 *                                            that stages its output would have had the mutation
 *                                            restored from the very thing that needed undoing
 *
 * ── WHY A SNAPSHOT AND NOT A REBUILD ───────────────────────────────────────────────────────────
 * "Rebuild the affected package after each arm" was the obvious repair and is the weaker one.
 *   • It is not byte-exact. `tsc` output is reproducible in practice but nothing here PROVES it,
 *     and a rebuild that differs by one byte is indistinguishable from a leak that differs by one
 *     byte. Restoring the exact bytes that were there before the mutation is provable by hash.
 *   • It cannot answer "which package". A suite is an arbitrary command; `packages/e2e-demo`'s
 *     builds six siblings. Guessing the affected package from the mutated file's directory is a
 *     model of the build, and this file's whole history is about models of a runner being wrong
 *     where the runner is ground truth. The snapshot MEASURES what changed instead.
 *   • It costs a `tsc` per arm (1076ms for the kernel, 4270ms for the six compiled packages)
 *     across 121 arms. The snapshot costs one content hash of ~3 MB of `dist/` per arm.
 *   • It is not crash-tolerant. A snapshot on disk plus an in-flight marker lets the NEXT run
 *     repair a tree the previous run died holding; a rebuild has nothing to rebuild FROM once the
 *     mutant source is also still on disk.
 * The rebuild is kept where it belongs — as the sweep-level backstop in the caller.
 *
 * ── FAIL-CLOSED, EVERYWHERE (panel rounds 1 and 2, 2026-08-14) ─────────────────────────────────
 * Two adversarial rounds found thirteen ways this guard could report success it had not earned,
 * and every one had the same shape as the defect it was written to fix: something could not be
 * verified, and the code carried on as though it had been. The rule underneath all of them, and
 * the one to apply to any future change here:
 *
 *     THIS GUARD MAY ONLY CLAIM WHAT IT CAN PROVE. WHERE IT CANNOT PROVE, THE RUN STOPS.
 *
 * Concretely, and each of these was once the opposite:
 *   • a marker that cannot be PARSED is not "no marker" — only ENOENT is (round 2 #1);
 *   • a recovery index that is missing or corrupt is not "an empty snapshot", which would have let
 *     recovery DELETE real build output as though the crashed arm had created it (round 2 #1);
 *   • a file that vanishes between enumeration and hashing is not "one fewer file to protect"
 *     (round 2 #4), and a stored copy is not trusted until it is re-hashed against the digest it
 *     was recorded under, in both directions;
 *   • `ps` refusing to answer is not "the process is dead" — it is UNKNOWN, and an unknown holder
 *     is treated exactly like a live one (round 2 #5). The reviewer's own runtime returned EPERM
 *     from `/bin/ps`, so this is a measured environment, not a hypothetical;
 *   • `git rev-parse` failing is not "this is not a work tree" (round 2 #6);
 *   • a `tsconfig` whose effective `outDir` cannot be RESOLVED — a chain that extends something
 *     missing, or a cycle — is not a package that emits to `dist` (round 2 #7);
 *   • a marker file whose deletion failed is not a cleared marker (round 2 #1).
 *
 * And the tree is protected from the FIRST BASELINE, not from the first mutation (round 2 #2):
 * `packages/evidence`'s baseline runs the fixture generator too, so a developer's uncommitted
 * fixture could be overwritten before any arm existed to protect it.
 *
 * Concurrency is a real lock, not a note in a file (round 2 #3): an `O_EXCL` create, an owner
 * nonce that must match before anything is replaced or removed, and per-run storage so two runs
 * cannot share a byte of state even if the lock itself were ever wrong.
 */

/**
 * Directories a derived-artefact walk must never enter: installed dependencies (which ship hundreds
 * of their own `dist/` trees — snapshotting those would cost more than the sweep) and every dot
 * directory (`.git`, `.venv`, tool scratch). No compiler in this repository emits into a dot
 * directory, and `.git` in particular must never be copied by anything.
 */
const skipWalk = (name) => name === "node_modules" || name.startsWith(".");

/**
 * Anything this guard could not PROVE. Every construction site is a place the run refuses rather
 * than continues — the type exists so a caller cannot accidentally treat one as a soft warning.
 */
export class IncompleteSnapshotError extends Error {
  constructor(message) {
    super(message);
    this.name = "IncompleteSnapshotError";
  }
}

const NOFOLLOW = fs.constants.O_NOFOLLOW ?? 0;

const fileIdentity = (stat) => `${stat.dev}:${stat.ino}`;

/**
 * Descriptor-bound regular-file observation. The path, opened descriptor, bytes and final link
 * count must all describe the same stable inode. Identity/link metadata is intentionally transient:
 * it is runtime custody evidence, not part of the durable v4 marker schema.
 */
function observeFileNoFollow(abs, retainedDescriptors = null) {
  let first;
  try { first = fs.lstatSync(abs, { bigint: true }); }
  catch (error) {
    if (error && error.code === "ENOENT") return null;
    throw error;
  }
  if (first.isSymbolicLink()) {
    throw new IncompleteSnapshotError(`${abs} is a symlink; refusing to follow it`);
  }
  if (!first.isFile()) throw new IncompleteSnapshotError(`${abs} is not a regular file`);

  let fd;
  try { fd = fs.openSync(abs, fs.constants.O_RDONLY | NOFOLLOW); }
  catch (error) {
    if (error && error.code === "ELOOP") {
      throw new IncompleteSnapshotError(`${abs} became a symlink while it was being observed`);
    }
    throw error;
  }
  try {
    const opened = fs.fstatSync(fd, { bigint: true });
    if (!opened.isFile() || fileIdentity(opened) !== fileIdentity(first)) {
      throw new IncompleteSnapshotError(`${abs} changed while it was being opened`);
    }
    const bytes = fs.readFileSync(fd);
    const after = fs.fstatSync(fd, { bigint: true });
    let atPath;
    try { atPath = fs.lstatSync(abs, { bigint: true }); }
    catch (error) {
      throw new IncompleteSnapshotError(`${abs} changed while its bytes were being observed: ${String(error && error.message)}`);
    }
    if (
      !after.isFile() || !atPath.isFile() ||
      fileIdentity(after) !== fileIdentity(opened) ||
      fileIdentity(atPath) !== fileIdentity(opened) ||
      after.nlink !== opened.nlink || after.size !== opened.size ||
      after.mtimeNs !== opened.mtimeNs || after.ctimeNs !== opened.ctimeNs
    ) {
      throw new IncompleteSnapshotError(`${abs} changed while its bytes were being observed`);
    }
    const observation = Object.freeze({
      bytes,
      identity: fileIdentity(opened),
      mode: Number(opened.mode & 0o777n),
      nlink: Number(opened.nlink),
      sha: sha(bytes),
    });
    if (retainedDescriptors !== null) {
      retainedDescriptors.push(fd);
      fd = undefined;
    }
    return observation;
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

/**
 * Read a file WITHOUT following a final symlink, and prove what was read is a regular file.
 *
 * The walk below rejects symlinks by their directory entry, but that check and the read that
 * follows it are two moments. A regular file swapped for a symlink in between would have been
 * hashed, copied and later WRITTEN THROUGH — pointing this guard's restore at a path outside the
 * repository. `O_NOFOLLOW` closes the window at the syscall, and `fstat` on the descriptor we
 * actually hold closes it for hard-linked and special files.
 */
function readFileNoFollow(abs) {
  const observed = observeFileNoFollow(abs);
  if (observed === null) {
    const error = new Error(`ENOENT: no such file or directory, open '${abs}'`);
    error.code = "ENOENT";
    throw error;
  }
  return observed.bytes;
}

/**
 * Replace bytes only through a descriptor that still matches the exact observation. Crucially,
 * O_TRUNC is not used at open time: an alias or replacement is refused before a byte can change.
 */
function rewriteObservedFileNoFollow(abs, bytes, expected, mode = null) {
  let fd;
  try { fd = fs.openSync(abs, fs.constants.O_RDWR | NOFOLLOW); }
  catch (error) {
    if (error && error.code === "ELOOP") {
      throw new IncompleteSnapshotError(`${abs} became a symlink; refusing to rewrite it`);
    }
    throw error;
  }
  try {
    const opened = fs.fstatSync(fd, { bigint: true });
    if (!opened.isFile()) throw new IncompleteSnapshotError(`${abs} is not a regular file`);
    const identity = fileIdentity(opened);
    if (identity !== expected.identity || Number(opened.nlink) !== expected.nlink || expected.nlink !== 1) {
      throw new IncompleteSnapshotError(
        `${abs} no longer has the exact single-link inode that was approved for rewriting`,
      );
    }
    const current = fs.readFileSync(fd);
    const afterRead = fs.fstatSync(fd, { bigint: true });
    const atPath = fs.lstatSync(abs, { bigint: true });
    if (
      sha(current) !== expected.sha || fileIdentity(afterRead) !== identity ||
      fileIdentity(atPath) !== identity || Number(afterRead.nlink) !== 1 ||
      afterRead.size !== opened.size || afterRead.mtimeNs !== opened.mtimeNs ||
      afterRead.ctimeNs !== opened.ctimeNs
    ) {
      throw new IncompleteSnapshotError(`${abs} changed before its approved rewrite`);
    }
    fs.ftruncateSync(fd, 0);
    let offset = 0;
    while (offset < bytes.length) {
      offset += fs.writeSync(fd, bytes, offset, bytes.length - offset, offset);
    }
    if (mode !== null) fs.fchmodSync(fd, mode);
  } finally { fs.closeSync(fd); }
}

/** Refuse cleanup writes through any hardlink or a currently protected mutation-source inode. */
function rewriteCleanupFileNoFollow(abs, bytes, mode, protectedIdentities) {
  const current = observeFileNoFollow(abs);
  if (current === null) {
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    let fd;
    try {
      fd = fs.openSync(
        abs,
        fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | NOFOLLOW,
        mode ?? 0o644,
      );
    } catch (error) {
      throw new IncompleteSnapshotError(
        `${abs} appeared before its approved cleanup creation: ${String(error && error.message)}`,
      );
    }
    try {
      let offset = 0;
      while (offset < bytes.length) {
        offset += fs.writeSync(fd, bytes, offset, bytes.length - offset, offset);
      }
      if (mode !== null) fs.fchmodSync(fd, mode);
    } finally { fs.closeSync(fd); }
    return;
  }
  if (current.nlink !== 1 || protectedIdentities.has(current.identity)) {
    throw new IncompleteSnapshotError(
      `${abs} aliases another inode under custody; refusing cleanup write`,
    );
  }
  rewriteObservedFileNoFollow(abs, bytes, current, mode);
}

/** Refuse cleanup deletion through any hardlink or a currently protected source inode. */
function removeCleanupFileNoFollow(abs, protectedIdentities) {
  const current = observeFileNoFollow(abs);
  if (current === null) return;
  if (current.nlink !== 1 || protectedIdentities.has(current.identity)) {
    throw new IncompleteSnapshotError(
      `${abs} aliases another inode under custody; refusing cleanup deletion`,
    );
  }
  const atPath = fs.lstatSync(abs, { bigint: true });
  if (!atPath.isFile() || fileIdentity(atPath) !== current.identity) {
    throw new IncompleteSnapshotError(`${abs} changed before its approved cleanup deletion`);
  }
  fs.unlinkSync(abs);
}

/** Write a file WITHOUT following a final symlink. Same window, the other direction. */
function writeFileNoFollow(abs, bytes, mode = null) {
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  const flags = fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_TRUNC | NOFOLLOW;
  let fd;
  try { fd = fs.openSync(abs, flags, 0o644); }
  catch (e) {
    if (e && e.code === "ELOOP") {
      throw new IncompleteSnapshotError(`${abs} is a symlink; refusing to write through it`);
    }
    throw e;
  }
  try {
    fs.writeSync(fd, bytes);
    if (mode !== null) fs.fchmodSync(fd, mode);
  } finally { fs.closeSync(fd); }
}

/** Change a regular file's mode through the exact no-follow descriptor that was opened. */
function chmodFileNoFollow(abs, mode) {
  let fd;
  try { fd = fs.openSync(abs, fs.constants.O_RDONLY | NOFOLLOW); }
  catch (e) {
    if (e && e.code === "ELOOP") {
      throw new IncompleteSnapshotError(`${abs} became a symlink while its mode was being restored`);
    }
    throw e;
  }
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile()) throw new IncompleteSnapshotError(`${abs} is not a regular file`);
    fs.fchmodSync(fd, mode);
  } finally { fs.closeSync(fd); }
}

/**
 * Every DERIVED build output under `root`: the full contents of every `dist/` tree plus any loose
 * `*.tsbuildinfo`. Returned as repo-relative paths, sorted.
 *
 * THROWS on any directory it cannot read. It used to `catch { return; }`, which silently produced a
 * SHORTER list — and a short list is not a smaller snapshot, it is a snapshot with holes that
 * restoration will never fill. An unreadable directory is a refusal, not a shrug.
 */
export function listBuildArtifacts(root) {
  const found = [];
  const read = (relDir) => {
    try {
      return fs.readdirSync(relDir ? path.join(root, relDir) : root, { withFileTypes: true });
    } catch (e) {
      throw new IncompleteSnapshotError(
        `cannot read ${relDir || "."} while listing build output: ${String(e && e.message)}`,
      );
    }
  };
  const collectAll = (relDir) => {
    for (const e of read(relDir)) {
      const rel = `${relDir}/${e.name}`;
      if (e.isSymbolicLink()) continue;
      if (e.isDirectory()) collectAll(rel);
      else if (e.isFile()) found.push(rel);
    }
  };
  const walk = (relDir) => {
    for (const e of read(relDir)) {
      const rel = relDir ? `${relDir}/${e.name}` : e.name;
      if (e.isSymbolicLink()) continue;
      if (e.isDirectory()) {
        if (skipWalk(e.name)) continue;
        // A `dist/` tree is taken WHOLE and not descended past — a `dist/` inside a `dist/` is
        // already part of the outer one.
        if (e.name === "dist") collectAll(rel);
        else walk(rel);
        continue;
      }
      if (e.isFile() && e.name.endsWith(".tsbuildinfo")) found.push(rel);
    }
  };
  walk("");
  return found.sort();
}

/**
 * Exact derived-state node census used by the post-restore evidence guard. Unlike the legacy byte
 * census above, symbolic links are material nodes: silently skipping one would let an observer
 * replace a reviewed link while the ordinary artifact hash still appeared unchanged.
 */
function listExactBuildNodes(root) {
  const found = [];
  const read = (relDir) => {
    try {
      return fs.readdirSync(relDir ? path.join(root, relDir) : root, { withFileTypes: true });
    } catch (e) {
      throw new IncompleteSnapshotError(
        `cannot read ${relDir || "."} while listing exact build state: ${String(e && e.message)}`,
      );
    }
  };
  const collectAll = (relDir) => {
    for (const entry of read(relDir)) {
      const rel = `${relDir}/${entry.name}`;
      if (entry.isSymbolicLink() || entry.isFile()) found.push(rel);
      else if (entry.isDirectory()) collectAll(rel);
      else throw new IncompleteSnapshotError(`derived output ${rel} is neither file, directory, nor symlink`);
    }
  };
  const walk = (relDir) => {
    for (const entry of read(relDir)) {
      const rel = relDir ? `${relDir}/${entry.name}` : entry.name;
      if (entry.isSymbolicLink()) {
        if (entry.name === "dist" || entry.name.endsWith(".tsbuildinfo")) found.push(rel);
        continue;
      }
      if (entry.isDirectory()) {
        if (skipWalk(entry.name)) continue;
        if (entry.name === "dist") collectAll(rel);
        else walk(rel);
        continue;
      }
      if (entry.isFile() && entry.name.endsWith(".tsbuildinfo")) found.push(rel);
      else if (!entry.isFile()) {
        throw new IncompleteSnapshotError(`repository entry ${rel} has an unsupported filesystem type`);
      }
    }
  };
  walk("");
  return [...new Set(found)].sort();
}

function runGit(root, args) {
  return execFileSync("git", args, {
    cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"],
  });
}

/** Git observation must never refresh or opportunistically lock the live index. */
function runGitReadOnly(root, args) {
  return execFileSync("git", args, {
    cwd: root,
    encoding: "utf8",
    env: { ...process.env, GIT_OPTIONAL_LOCKS: "0" },
    stdio: ["ignore", "pipe", "pipe"],
  });
}

/** Derive semantic index state from a private copy, never from the live index file. */
function runGitWithIndex(root, args, indexFile) {
  return execFileSync("git", args, {
    cwd: root,
    encoding: "utf8",
    env: { ...process.env, GIT_INDEX_FILE: indexFile, GIT_OPTIONAL_LOCKS: "0" },
    stdio: ["ignore", "pipe", "pipe"],
  });
}

/**
 * THREE-VALUED, because "git would not answer" and "this is not a repository" are opposite facts
 * and were returning the same `false`. Only a probe that RAN and said no means no.
 */
export function gitWorkTreeState(root) {
  try {
    return runGitReadOnly(root, ["rev-parse", "--is-inside-work-tree"]).trim() === "true" ? "yes" : "no";
  } catch (e) {
    const said = `${(e && e.stderr) || ""}`;
    if (/not a git repository|does not exist/i.test(said)) return "no";
    return "unknown";
  }
}

/** Boolean form for callers that must have an answer. An UNKNOWN throws rather than guessing. */
export function isGitWorkTree(root) {
  const state = gitWorkTreeState(root);
  if (state === "unknown") {
    throw new IncompleteSnapshotError(
      `cannot determine whether ${root} is a git work tree; refusing to assume it is not`,
    );
  }
  return state === "yes";
}

/**
 * `git status --porcelain -z` as a Map of path → two-letter status code.
 *
 * `-z` is not a detail: without it git QUOTES paths containing non-ASCII or spaces
 * (`core.quotePath`), and a quoted path handed back to `git checkout` names a file that does not
 * exist.
 *
 * Returns `null` ONLY where a probe RAN and proved there is no work tree — there, "nothing is
 * tracked" is a complete answer. Everything else throws.
 */
export function gitDirtyPaths(root) {
  let raw;
  try {
    raw = runGitReadOnly(root, ["status", "--porcelain", "-z"]);
  } catch (e) {
    if (gitWorkTreeState(root) === "no") return null;
    throw new IncompleteSnapshotError(
      `git status failed inside a git work tree at ${root}: ${String(e && e.message)}`,
    );
  }
  const fields = raw.split("\0");
  const dirty = new Map();
  for (let i = 0; i < fields.length; i++) {
    const entry = fields[i];
    if (entry.length < 4) continue;
    const code = entry.slice(0, 2);
    dirty.set(entry.slice(3), code);
    // A rename/copy entry is followed by its ORIGINAL path in the NEXT NUL-separated field.
    if (code[0] === "R" || code[0] === "C" || code[1] === "R" || code[1] === "C") i++;
  }
  return dirty;
}

/** JSON with comments — `tsconfig.json` is JSONC, and one of ours opens with a 15-line comment. */
function parseJsonc(text) {
  let out = "";
  let inString = false, inLine = false, inBlock = false, escaped = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i], next = text[i + 1];
    if (inLine) { if (c === "\n") { inLine = false; out += c; } continue; }
    if (inBlock) { if (c === "*" && next === "/") { inBlock = false; i++; } continue; }
    if (inString) {
      out += c;
      if (escaped) escaped = false;
      else if (c === "\\") escaped = true;
      else if (c === '"') inString = false;
      continue;
    }
    if (c === '"') { inString = true; out += c; continue; }
    if (c === "/" && next === "/") { inLine = true; i++; continue; }
    if (c === "/" && next === "*") { inBlock = true; i++; continue; }
    out += c;
  }
  return JSON.parse(out);
}

/** Every directory under `root` that holds a `tsconfig.json` — i.e. everything that can emit. */
export function typescriptProjectDirs(root) {
  const dirs = [];
  const walk = (relDir) => {
    let entries;
    try { entries = fs.readdirSync(relDir ? path.join(root, relDir) : root, { withFileTypes: true }); }
    catch (e) {
      throw new IncompleteSnapshotError(
        `cannot read ${relDir || "."} while looking for TypeScript projects: ${String(e && e.message)}`,
      );
    }
    for (const e of entries) {
      const rel = relDir ? `${relDir}/${e.name}` : e.name;
      if (e.isSymbolicLink()) continue;
      if (e.isDirectory()) { if (!skipWalk(e.name) && e.name !== "dist") walk(rel); continue; }
      if (e.isFile() && e.name === "tsconfig.json") dirs.push(relDir);
    }
  };
  walk("");
  return [...new Set(dirs)].sort();
}

/**
 * THE ARTIFACT-SET INVARIANT, asserted rather than assumed.
 *
 * This guard's walker knows exactly one artifact root: a directory called `dist`. Every TypeScript
 * project here emits there today, so the walker is complete today — but "complete because of a
 * convention nobody checks" is how a snapshot silently starts missing half the build. A package
 * that emitted to `build/`, or beside its sources, would be OUTSIDE both the walker and (being
 * gitignored) `git status`, and the guard would report a clean restore over a leak.
 *
 * Round 2 #7: the RESOLUTION was itself fail-open. An `extends` that pointed at something missing,
 * an extensionless base, a package-style base, a cycle, or a chain longer than the hop limit all
 * left the effective options unknown — and unknown was being accepted. A tsconfig whose `outDir`
 * cannot be resolved is now a refusal, in exactly the same way as one that resolves to the wrong
 * place, because the two are indistinguishable from the outside.
 */
export function unsupportedArtifactRoots(root, projectDirs) {
  const problems = [];
  const MAX_HOPS = 8;
  for (const rel of [...new Set(projectDirs)].sort()) {
    const start = path.join(root, rel, "tsconfig.json");
    if (!fs.existsSync(start)) continue;                 // nothing here emits; nothing to miss
    const name = rel || ".";
    const seen = new Set();
    let current = start;
    let options = null;
    let unresolved = null;
    for (let hop = 0; ; hop++) {
      if (hop >= MAX_HOPS) { unresolved = `its extends chain is longer than ${MAX_HOPS} hops`; break; }
      const key = path.resolve(current);
      if (seen.has(key)) { unresolved = "its extends chain is a cycle"; break; }
      seen.add(key);
      let config;
      try { config = parseJsonc(readFileNoFollow(current).toString("utf8")); }
      catch (e) { unresolved = `${path.relative(root, current)} cannot be read or parsed (${String(e && e.message)})`; break; }
      const co = (config && typeof config.compilerOptions === "object" && config.compilerOptions) || {};
      if (co.noEmit === true || typeof co.outDir === "string") { options = co; break; }
      if (typeof config.extends !== "string") { options = co; break; }
      if (!config.extends.startsWith(".") && !path.isAbsolute(config.extends)) {
        unresolved = `it extends the package-style base ${JSON.stringify(config.extends)}, whose outDir this guard cannot resolve`;
        break;
      }
      const base = path.resolve(path.dirname(current), config.extends);
      const candidate = fs.existsSync(base) ? base : `${base}.json`;
      if (!fs.existsSync(candidate)) { unresolved = `it extends ${JSON.stringify(config.extends)}, which does not exist`; break; }
      current = candidate;
    }
    if (unresolved !== null) {
      problems.push(`${name}: the effective outDir cannot be resolved — ${unresolved}`);
      continue;
    }
    if (options.noEmit === true) continue;               // nothing is emitted; nothing to snapshot
    const outDir = typeof options.outDir === "string" ? options.outDir : null;
    if (outDir === null) {
      problems.push(
        `${name}: tsconfig.json emits BESIDE its sources (no outDir). Compiled output would be ` +
        `outside this guard's snapshot and outside git, so a mutant build could survive the arm`,
      );
      continue;
    }
    const normalized = path.normalize(outDir).replace(/[\\/]+$/, "");
    if (normalized !== "dist") {
      problems.push(
        `${name}: tsconfig.json outDir is ${JSON.stringify(outDir)}, and this guard snapshots ` +
        `only "dist". The build output would not be restored`,
      );
    }
  }
  return problems;
}

let ACCOUNT_HOME = null;
function operatingSystemAccountHome() {
  if (ACCOUNT_HOME !== null) return ACCOUNT_HOME;
  let home;
  try { home = os.userInfo().homedir; }
  catch (error) {
    throw new IncompleteSnapshotError(`cannot resolve the operating-system account home: ${String(error && error.message)}`);
  }
  if (typeof home !== "string" || !path.isAbsolute(home)) {
    throw new IncompleteSnapshotError(`operating-system account home is not absolute: ${JSON.stringify(home)}`);
  }
  try { ACCOUNT_HOME = fs.realpathSync(home); }
  catch (error) {
    throw new IncompleteSnapshotError(`cannot resolve the operating-system account home ${home}: ${String(error && error.message)}`);
  }
  return ACCOUNT_HOME;
}

/**
 * The operating-system account's cache home. HOME and XDG_CACHE_HOME are launch input, not
 * authority: either can point the recovery store back inside the repository/runtime tree whose
 * immutability it is meant to police. `os.userInfo()` is resolved from the process account instead.
 */
export function userCacheHome() {
  return path.join(operatingSystemAccountHome(), ".cache");
}

/** The cache home a v3 process launched with this environment would have selected. */
function legacyLaunchCacheHome() {
  const xdg = process.env.XDG_CACHE_HOME;
  if (typeof xdg === "string" && xdg.length > 0 && path.isAbsolute(xdg)) {
    return path.resolve(xdg);
  }
  const home = os.homedir();
  if (typeof home !== "string" || !path.isAbsolute(home)) {
    throw new IncompleteSnapshotError(
      `the v3 launch environment resolves a non-absolute home directory: ${JSON.stringify(home)}`,
    );
  }
  return path.join(path.resolve(home), ".cache");
}

/**
 * The knockout store's private root.
 *
 * ── CodeQL js/insecure-temporary-file, and why the answer is NOT a safer temp path ─────────────
 * This store holds a run's pristine SOURCES, the mutant hashes recovery compares against, and the
 * lock that decides whether another run may touch the tree. It was written under the machine-wide
 * temporary directory at a path derived from the repository path alone — deterministic by design,
 * because crash recovery has to FIND it again, and therefore predictable to every other account.
 *
 * The first repair made that directory per-user and `0700`. It closed the hole, and the scanner
 * kept flagging every `open` underneath it, which turned out to be the right instinct rather than a
 * false positive: an argument that a shared directory is safe THIS time is exactly the kind of
 * reasoning this file exists to distrust. So the store leaves the shared directory entirely. Under
 * the user's own cache home it is private by construction rather than by argument, there is no
 * pre-creation or symlink window for anyone to race, and the cache home itself survives reboot.
 * The physical store key includes the filesystem's device number, which can change across a
 * remount on some filesystems; discovery therefore treats a stale-identity record whose lexical
 * root still resolves here as blocking recovery state and names the orphan instead of ignoring it.
 *
 * The refusal discipline below stays anyway. The surface shrank; the standard did not.
 *
 * `base` exists so the selftest can exercise all of that inside its own workspace instead of the
 * developer's real home directory. Nothing in the product passes it.
 */
export function privateFallbackRoot(base = userCacheHome()) {
  return path.join(base, "noa-knockout");
}

function openedDirectoryDescriptor(root) {
  const absolute = path.resolve(root);
  const directoryFlag = fs.constants.O_DIRECTORY ?? 0;
  if (NOFOLLOW === 0) {
    throw new IncompleteSnapshotError("this platform has no O_NOFOLLOW; repository identity cannot be bound safely");
  }
  let fd;
  try { fd = fs.openSync(absolute, fs.constants.O_RDONLY | directoryFlag | NOFOLLOW); }
  catch (error) {
    throw new IncompleteSnapshotError(`cannot open repository root ${absolute} without following a symlink: ${String(error && error.message)}`);
  }
  try {
    const stat = fs.fstatSync(fd, { bigint: true });
    if (!stat.isDirectory()) throw new IncompleteSnapshotError(`${absolute} is not a directory`);
    return Object.freeze({
      // Coordination cannot depend on birthtimeNs: libuv may expose mutable ctime there when a
      // platform or filesystem has no birth time. Device+inode remains stable for this directory's
      // lifetime, so every concurrent process converges on one lock on either implementation path.
      identity: `noa-directory/2:${stat.dev}:${stat.ino}`,
      // Recovery retains the generation signal. An inode reuse or mutable fallback therefore
      // refuses stale v4 recovery bytes; it never selects a second lock.
      generation: `noa-directory-generation/1:${stat.dev}:${stat.ino}:${stat.birthtimeNs}`,
    });
  } finally {
    fs.closeSync(fd);
  }
}

function openedDirectoryIdentity(root) {
  return openedDirectoryDescriptor(root).identity;
}

function statDirectoryIdentity(root) {
  try {
    const stat = fs.statSync(root, { bigint: true });
    return stat.isDirectory() ? `noa-directory/2:${stat.dev}:${stat.ino}` : null;
  } catch (error) {
    if (error && error.code === "ENOENT") return null;
    throw new IncompleteSnapshotError(`cannot inspect directory identity for ${root}: ${String(error && error.message)}`);
  }
}

function ancestorDirectoryIdentities(candidate) {
  const identities = new Set();
  let current = path.resolve(candidate);
  while (true) {
    const identity = statDirectoryIdentity(current);
    if (identity !== null) identities.add(identity);
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
  return identities;
}

/** Resolve the nearest existing ancestor, then project missing descendants below its real path. */
function projectedPhysicalPath(candidate) {
  let current = path.resolve(candidate);
  const missing = [];
  while (true) {
    try {
      fs.lstatSync(current);
    } catch (error) {
      if (!error || error.code !== "ENOENT") {
        throw new IncompleteSnapshotError(
          `cannot inspect path component ${current}: ${String(error && error.message)}`,
        );
      }
      const parent = path.dirname(current);
      if (parent === current) {
        throw new IncompleteSnapshotError(`cannot find an existing ancestor for ${path.resolve(candidate)}`);
      }
      missing.unshift(path.basename(current));
      current = parent;
      continue;
    }
    let physical;
    try { physical = fs.realpathSync(current); }
    catch (error) {
      throw new IncompleteSnapshotError(
        `cannot resolve existing path component ${current}: ${String(error && error.message)}`,
      );
    }
    return path.join(physical, ...missing);
  }
}

/** Refuse a prospective private path that physically contains, or is contained by, an evidence root. */
function assertPrivatePathDisjoint(privatePath, roots, label) {
  const privateIdentity = statDirectoryIdentity(privatePath);
  const privateAncestors = ancestorDirectoryIdentities(privatePath);
  const projectedPrivatePath = projectedPhysicalPath(privatePath);
  for (const root of roots) {
    const rootIdentity = openedDirectoryIdentity(root);
    const rootAncestors = ancestorDirectoryIdentities(root);
    let physicalRoot;
    try { physicalRoot = fs.realpathSync(root); }
    catch (error) {
      throw new IncompleteSnapshotError(
        `cannot resolve evidence root ${path.resolve(root)}: ${String(error && error.message)}`,
      );
    }
    if (
      privateAncestors.has(rootIdentity) ||
      (privateIdentity !== null && rootAncestors.has(privateIdentity)) ||
      pathIsInside(projectedPrivatePath, physicalRoot) ||
      pathIsInside(physicalRoot, projectedPrivatePath)
    ) {
      throw new IncompleteSnapshotError(
        `${label} ${path.resolve(privatePath)} projects to ${projectedPrivatePath} and overlaps ` +
          `evidence root ${path.resolve(root)} (${physicalRoot})`,
      );
    }
  }
  return path.resolve(privatePath);
}

/**
 * The cache home itself: created if missing, and proven to be a real directory belonging to this
 * user. Its MODE is not policed — `~/.cache` is a shared-by-design directory on most systems and
 * demanding `0700` of it would refuse to run on a perfectly ordinary machine. What must be private
 * is the leaf this guard writes into, and `ensurePrivateDir` proves that.
 */
function ensureOwnedDir(dir) {
  try { fs.mkdirSync(dir, { recursive: true }); }
  catch (e) { throw new IncompleteSnapshotError(`cannot create ${dir}: ${String(e && e.message)}`); }
  let st;
  try { st = fs.lstatSync(dir); }
  catch (e) { throw new IncompleteSnapshotError(`cannot inspect ${dir}: ${String(e && e.message)}`); }
  if (st.isSymbolicLink() || !st.isDirectory()) {
    throw new IncompleteSnapshotError(`${dir} is not a real directory; refusing to build this run's store under it`);
  }
  const uid = typeof process.getuid === "function" ? process.getuid() : null;
  if (uid !== null && st.uid !== uid) {
    throw new IncompleteSnapshotError(`${dir} is owned by uid ${st.uid}, not by this user (${uid}); refusing to use it`);
  }
  return dir;
}

/**
 * Create `dir` as a private `0700` directory, or PROVE the one already there is private and ours.
 *
 * Refuses rather than repairs, which is this guard's standing rule: a directory that is a symlink,
 * or owned by somebody else, or readable by the rest of the machine, is not something to quietly
 * `chmod` into acceptability — it is something whose history nobody here can account for.
 */
export function ensurePrivateDir(dir) {
  ensureOwnedDir(path.dirname(dir));
  try {
    fs.mkdirSync(dir, { mode: 0o700 });
    return dir;
  } catch (e) {
    if (!e || e.code !== "EEXIST") {
      throw new IncompleteSnapshotError(`cannot create the private store at ${dir}: ${String(e && e.message)}`);
    }
  }
  let st;
  try { st = fs.lstatSync(dir); }   // lstat: a symlink must be seen AS a symlink, never followed
  catch (e) { throw new IncompleteSnapshotError(`cannot inspect the private store at ${dir}: ${String(e && e.message)}`); }
  if (st.isSymbolicLink() || !st.isDirectory()) {
    throw new IncompleteSnapshotError(
      `${dir} exists and is not a real directory (it is a ${st.isSymbolicLink() ? "symlink" : "non-directory"}); ` +
      `refusing to write this run's pristine sources through it`,
    );
  }
  const uid = typeof process.getuid === "function" ? process.getuid() : null;
  if (uid !== null && st.uid !== uid) {
    throw new IncompleteSnapshotError(`${dir} is owned by uid ${st.uid}, not by this user (${uid}); refusing to use it`);
  }
  if ((st.mode & 0o777) !== 0o700) {
    throw new IncompleteSnapshotError(
      `${dir} is mode ${(st.mode & 0o777).toString(8)}, not 700 — this run's pristine sources and lock ` +
      `would be reachable by other accounts on this machine`,
    );
  }
  return dir;
}

/** One durable lock location per physical repository, independent of install state or path alias. */
function protectedEvidenceRoots(repoRoot, protectedRoots) {
  if (!Array.isArray(protectedRoots)) {
    throw new IncompleteSnapshotError("protectedRoots must be an array of absolute evidence roots");
  }
  const byIdentity = new Map();
  for (const candidate of [repoRoot, KNOCKOUT_REPOSITORY_ROOT, ...protectedRoots]) {
    if (typeof candidate !== "string" || !path.isAbsolute(candidate)) {
      throw new IncompleteSnapshotError(
        `protected evidence root must be an absolute path, received ${JSON.stringify(candidate)}`,
      );
    }
    const absolute = path.resolve(candidate);
    const identity = openedDirectoryIdentity(absolute);
    if (!byIdentity.has(identity)) {
      byIdentity.set(identity, Object.freeze({ path: absolute, identity }));
    }
  }
  return Object.freeze([...byIdentity.values()]);
}

function defaultArtifactCacheDir(rootIdentity, evidenceRoots) {
  const cacheDir = path.join(privateFallbackRoot(), sha(rootIdentity).slice(0, 16));
  return assertPrivatePathDisjoint(
    cacheDir,
    evidenceRoots.map((entry) => entry.path),
    "knockout recovery cache",
  );
}

const LEGACY_TOMBSTONE_STAGING = /^\.lock\.json\.[0-9a-f]{32}\.tombstone-tmp$/;

/** Persist one complete tombstone, then publish its name atomically without replacing a v3 lock. */
function publishLegacyTombstoneNoClobber(legacyLock, tombstone) {
  // The steady-state path must be read-only. In particular, the installed store is inside the
  // runtime closure hashed around every private-dependent observation; staging there merely to
  // discover that lock.json already exists creates a false tamper window. This check is only an
  // optimisation — linkSync below remains the atomic no-clobber decision on a lost race.
  try { fs.lstatSync(legacyLock); return false; }
  catch (error) {
    if (!error || error.code !== "ENOENT") {
      throw new IncompleteSnapshotError(
        `cannot inspect legacy lock ${legacyLock} before tombstone publication: ${String(error && error.message)}`,
      );
    }
  }
  const directory = path.dirname(legacyLock);
  const staging = path.join(
    directory,
    `.lock.json.${crypto.randomBytes(16).toString("hex")}.tombstone-tmp`,
  );
  let stagingFd;
  try {
    stagingFd = fs.openSync(staging, "wx", 0o600);
    fs.writeFileSync(stagingFd, tombstone);
    fs.fsyncSync(stagingFd);
    fs.closeSync(stagingFd);
    stagingFd = undefined;

    try { fs.linkSync(staging, legacyLock); }
    catch (error) {
      if (error && error.code === "EEXIST") return false;
      throw error;
    }

    let directoryFd;
    try {
      directoryFd = fs.openSync(
        directory,
        fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY ?? 0) | NOFOLLOW,
      );
      const stat = fs.fstatSync(directoryFd);
      if (!stat.isDirectory()) throw new IncompleteSnapshotError(`${directory} is not a directory`);
      fs.fsyncSync(directoryFd);
    } finally {
      if (directoryFd !== undefined) fs.closeSync(directoryFd);
    }
    return true;
  } finally {
    if (stagingFd !== undefined) fs.closeSync(stagingFd);
    try { fs.unlinkSync(staging); }
    catch (error) {
      if (!error || error.code !== "ENOENT") {
        throw new IncompleteSnapshotError(
          `cannot remove tombstone staging file ${staging}: ${String(error && error.message)}`,
        );
      }
    }
  }
}

const installedLegacyCacheDirFor = (root) =>
  path.join(path.resolve(root), "node_modules", ".cache", "noa-knockout");

/**
 * Dependency/runtime attestation must happen after the guard's one-time v3 migration barrier.
 * Otherwise the first guard start would add a tombstone beneath root node_modules after those
 * bytes were frozen and every contained observer would correctly reject the resulting drift.
 */
export function assertKnockoutMigrationBarrier(root) {
  const repoRoot = path.resolve(root);
  const expectedIdentity = openedDirectoryIdentity(repoRoot);
  const lock = path.join(installedLegacyCacheDirFor(repoRoot), "lock.json");
  let record;
  try { record = JSON.parse(readFileNoFollow(lock).toString("utf8")); }
  catch (error) {
    throw new IncompleteSnapshotError(
      `knockout migration barrier is absent or unreadable at ${lock}; start the default build-state guard before binding runtime evidence (${String(error && error.message)})`,
    );
  }
  if (!isLegacyTombstoneForRoot(record, expectedIdentity)) {
    throw new IncompleteSnapshotError(
      `knockout migration barrier at ${lock} does not describe this physical repository; start the default build-state guard before binding runtime evidence`,
    );
  }
  return true;
}

/**
 * Does this pid exist, and what durably identifies it?
 *
 * THREE-VALUED (round 2 #5). `ps` returning nothing because the process is gone and `ps` refusing
 * to run at all were the same `null`, and the second was being read as "dead" — so a run would
 * start recovering a tree another run might still be holding. The reviewer's own runtime returned
 * EPERM from `/bin/ps`; this is measured, not hypothetical.
 *
 * The identity is the process START TIME only. `comm` was in it and should not have been: it is
 * mutable, so a process that rewrote its own name would have been read as a different process.
 */
export function probeProcess(pid) {
  if (typeof pid !== "number" || !Number.isInteger(pid) || pid <= 0) {
    return { exists: "no", identity: null };
  }
  let exists = "unknown";
  try { process.kill(pid, 0); exists = "yes"; }
  catch (e) {
    if (e && e.code === "ESRCH") return { exists: "no", identity: null };
    if (e && e.code === "EPERM") exists = "yes";          // it exists; we simply may not signal it
  }
  let identity = null;
  try {
    const out = execFileSync("ps", ["-o", "lstart=", "-p", String(pid)], {
      encoding: "utf8", stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    if (out.length > 0) identity = out.replace(/\s+/g, " ");
    else if (exists !== "yes") return { exists: "no", identity: null };
  } catch { identity = null; }
  return { exists, identity };
}

/**
 * LIVE / DEAD / UNKNOWN for a recorded lock owner. Pure, so every branch is testable without
 * needing a real process in each state.
 *
 * UNKNOWN is treated by every caller exactly as LIVE is: nothing is recovered, nothing is taken
 * over, the run refuses and says what a human should check. "We could not tell" must never be the
 * cheaper answer than "it is running".
 */
export function classifyHolder(record, probe) {
  if (record && record.pid === process.pid) return "SELF";
  if (probe.exists === "no") return "DEAD";
  if (probe.exists === "unknown") return "UNKNOWN";
  // The pid exists. Whether it is the SAME process needs the identity on both sides.
  if (record && record.identityAvailable === false) return "UNKNOWN";
  if (typeof (record && record.identity) !== "string") return "UNKNOWN";
  if (probe.identity === null) return "UNKNOWN";
  return probe.identity === record.identity ? "LIVE" : "DEAD";
}

/**
 * The guard over derived state, for one repository root.
 *
 * Lifecycle:
 *   start()        — take the EXCLUSIVE lock. If another run holds it: refuse (`held`). If a dead
 *                    run left it: repair what is PROVABLY its leftovers and take the lock, or
 *                    refuse (`unrepaired`). If the lock or its metadata is unreadable: refuse
 *                    (`corrupt`). Nothing else in this object may run before this succeeds.
 *   beginPhase()   — snapshot what the phase can change: the byte contents of every `dist/` file
 *                    (unless the phase cannot build), the bytes AND index entry of every already-
 *                    dirty tracked path, and, for an arm, the pristine and mutant hashes of the
 *                    sources about to be written. Any of it failing THROWS and nothing is mutated.
 *   endPhase()     — put all of that back and clear the marker, but ONLY if the tree is provably
 *                    back. A cleared marker over an unrestored tree tells the next run there is
 *                    nothing to look at.
 *   commitRetainedArm() — for a disposable arm only, prove every mutation target is still the
 *                    exact single-link mutant inode this arm created, then retire recovery
 *                    authority without restoring those intentionally retained bytes.
 *   release()      — drop the lock at the end of the run.
 *
 * The snapshot is taken PER PHASE rather than once, because whatever is on disk when a phase
 * begins is that phase's ground truth — including a developer's own uncommitted work. The guard
 * returns the tree to where the phase found it; it never asserts a repo-wide opinion about what
 * `dist/` "should" contain.
 */
export function createBuildStateGuard(options = {}) {
  if (options === null || typeof options !== "object" || Array.isArray(options)) {
    throw new IncompleteSnapshotError("build-state guard options must be an object");
  }
  for (const key of Object.keys(options)) {
    if (!["root", "cacheDir", "protectedRoots"].includes(key)) {
      throw new IncompleteSnapshotError(`unknown build-state guard option ${JSON.stringify(key)}`);
    }
  }
  const { root, cacheDir: requestedCacheDir, protectedRoots = [] } = options;
  const repoRoot = path.resolve(root);
  const { identity: rootIdentity, generation: rootGeneration } = openedDirectoryDescriptor(repoRoot);
  const evidenceRoots = protectedEvidenceRoots(repoRoot, protectedRoots);
  const evidenceRootPaths = evidenceRoots.map((entry) => entry.path);
  // Default paths are security state and receive the full ownership/no-symlink/mode contract.
  // Caller-supplied paths exist only for bounded selftests that deliberately exercise bad stores.
  const usesDefaultCache = requestedCacheDir === undefined;
  const cacheDir = requestedCacheDir ?? defaultArtifactCacheDir(rootIdentity, evidenceRoots);
  const lockPath = path.join(cacheDir, "lock.json");

  let owner = null;          // { nonce, pid, identity, identityAvailable, startedAt, runDir }
  let index = new Map();     // rel → sha256 of the bytes this run's store holds
  let armed = null;
  let started = null;        // the result of start(), memoised
  let legacyScanWarnings = Object.freeze([]);

  const runPaths = (runDir) => ({
    store: path.join(runDir, "artifacts"),
    sources: path.join(runDir, "sources"),
    dirty: path.join(runDir, "dirty"),
    exact: path.join(runDir, "exact-custody"),
    gitIndex: path.join(runDir, "git-index.bin"),
    index: path.join(runDir, "index.json"),
    marker: path.join(runDir, "inflight.json"),
  });

  const digestOfBytes = (bytes) => sha(bytes);
  const isSafeRunNonce = (value) =>
    typeof value === "string" && value.length > 0 && value !== "." && value !== ".." &&
    !value.includes("/") && !value.includes("\\") && !value.includes("\0");
  const physicalRepoRoot = fs.realpathSync(repoRoot);

  /**
   * Resolve a path persisted by an interrupted run without letting corrupt recovery metadata name
   * a file outside this repository. Lexical containment alone is not enough: a parent symlink can
   * project an apparently in-tree path somewhere else, so the nearest-existing-ancestor projection
   * is bound to the physical repository too.
   */
  const recordedRepoFile = (rel, label) => {
    if (typeof rel !== "string" || rel.length === 0 || rel.includes("\0") || path.isAbsolute(rel)) {
      throw new IncompleteSnapshotError(`${label} is not a repository-relative file: ${JSON.stringify(rel)}`);
    }
    const segments = rel.split(/[\\/]/u);
    if (segments.some((segment) => segment === "" || segment === "." || segment === "..")) {
      throw new IncompleteSnapshotError(`${label} contains a non-canonical path segment: ${JSON.stringify(rel)}`);
    }
    const absolute = path.resolve(repoRoot, rel);
    if (absolute === repoRoot || !pathIsInside(absolute, repoRoot)) {
      throw new IncompleteSnapshotError(`${label} escapes repository root ${repoRoot}: ${JSON.stringify(rel)}`);
    }
    const projected = projectedPhysicalPath(absolute);
    if (projected === physicalRepoRoot || !pathIsInside(projected, physicalRepoRoot)) {
      throw new IncompleteSnapshotError(
        `${label} projects outside physical repository root ${physicalRepoRoot}: ${JSON.stringify(rel)} -> ${projected}`,
      );
    }
    return { absolute, segments };
  };

  /** A persisted artifact index may name only paths the artifact census itself can emit. */
  const recordedArtifactFile = (rel) => {
    const recorded = recordedRepoFile(rel, "the interrupted run's artifact path");
    const distIndex = recorded.segments.indexOf("dist");
    const insideWalkedDist = distIndex >= 0 &&
      !recorded.segments.slice(0, distIndex).some((segment) => skipWalk(segment));
    const looseTsBuildInfo = recorded.segments.at(-1).endsWith(".tsbuildinfo") &&
      !recorded.segments.slice(0, -1).some((segment) => skipWalk(segment));
    if (!insideWalkedDist && !looseTsBuildInfo) {
      throw new IncompleteSnapshotError(
        `the interrupted run's artifact path is outside the derived-output census: ${JSON.stringify(rel)}`,
      );
    }
    return recorded.absolute;
  };

  /**
   * Match both v4 physical identities and v3 lexical roots. The latter is resolved physically so
   * an old lock taken through /System/Volumes/Data or a parent symlink is still this repository's
   * recovery state, not an unrelated record that the new runner may step around.
   */
  const ROOT_RECORD = Object.freeze({
    MATCH: "MATCH",
    GENERATION_STALE: "GENERATION_STALE",
    IDENTITY_STALE: "IDENTITY_STALE",
    MISMATCH: "MISMATCH",
  });

  /**
   * Classify a record's root without collapsing stale recovery into a foreign record. Coordination
   * uses stable device+inode identity; recovery additionally requires the captured generation.
   * A lexical root that resolves to this directory while its stored identity differs is an orphan
   * from a remount/device-number change or inode generation and must be surfaced, never ignored.
   */
  const recordRootState = (record, { requireGeneration = false } = {}) => {
    if (record === null || typeof record !== "object" || Array.isArray(record)) {
      return ROOT_RECORD.MISMATCH;
    }
    if (record.rootIdentity !== undefined) {
      if (record.rootIdentity !== rootIdentity) {
        if (typeof record.root !== "string" || !path.isAbsolute(record.root)) {
          return ROOT_RECORD.MISMATCH;
        }
        return statDirectoryIdentity(record.root) === rootIdentity
          ? ROOT_RECORD.IDENTITY_STALE
          : ROOT_RECORD.MISMATCH;
      }
      if (requireGeneration || record.rootGeneration !== undefined || record.version === 4) {
        return record.rootGeneration === rootGeneration
          ? ROOT_RECORD.MATCH
          : ROOT_RECORD.GENERATION_STALE;
      }
      return ROOT_RECORD.MATCH;
    }
    if (requireGeneration || typeof record.root !== "string" || !path.isAbsolute(record.root)) {
      return ROOT_RECORD.MISMATCH;
    }
    return statDirectoryIdentity(record.root) === rootIdentity
      ? ROOT_RECORD.MATCH
      : ROOT_RECORD.MISMATCH;
  };
  const installedLegacyCacheDir = installedLegacyCacheDirFor(repoRoot);

  /**
   * v3 trusted XDG_CACHE_HOME/HOME launch input. v4 does not use it for active state, but migration
   * must close the exact store a concurrently launched v3 process would still select.
   */
  const legacySharedRoots = () => {
    const roots = new Set([privateFallbackRoot()]);
    const launchRoot = privateFallbackRoot(legacyLaunchCacheHome());
    if (!roots.has(launchRoot)) {
      roots.add(assertPrivatePathDisjoint(
        launchRoot,
        evidenceRootPaths,
        "environment-selected v3 knockout cache",
      ));
    }
    return roots;
  };

  /** Original default stores that predate the physical-identity external lock. */
  const knownLegacyCacheDirs = () => {
    const candidates = new Set([installedLegacyCacheDir]);
    for (const sharedRoot of legacySharedRoots()) {
      candidates.add(path.join(sharedRoot, sha(repoRoot).slice(0, 16)));
      candidates.add(path.join(sharedRoot, sha(fs.realpathSync(repoRoot)).slice(0, 16)));
    }
    candidates.delete(cacheDir);
    return candidates;
  };

  /**
   * Discover a v3 store created through another lexical alias. Only a lock/marker whose recorded
   * root resolves to this exact physical directory is associated with this guard.
   */
  const discoveredLegacyCacheDirs = () => {
    const candidates = knownLegacyCacheDirs();
    const warnings = [];
    try {
      for (const sharedRoot of legacySharedRoots()) {
        let entries;
        try {
          entries = fs.readdirSync(sharedRoot, { withFileTypes: true });
        } catch (error) {
          if (error && error.code === "ENOENT") continue;
          throw new IncompleteSnapshotError(
            `cannot inspect legacy knockout stores under ${sharedRoot}: ${String(error && error.message)}`,
          );
        }
        for (const entry of entries) {
          if (!/^[0-9a-f]{16}$/.test(entry.name) || !entry.isDirectory()) continue;
          const candidate = path.join(sharedRoot, entry.name);
          if (candidate === cacheDir || candidates.has(candidate)) continue;
          const records = [path.join(candidate, "lock.json")];
          const runs = path.join(candidate, "runs");
          try {
            for (const run of fs.readdirSync(runs, { withFileTypes: true })) {
              if (run.isDirectory()) records.push(path.join(runs, run.name, "inflight.json"));
            }
          } catch (error) {
            if (!error || error.code !== "ENOENT") {
              warnings.push(
                `unassociated legacy knockout runs directory ${runs} could not be listed and was ` +
                  `skipped (${String(error && error.message)})`,
              );
            }
          }
          for (const recordPath of records) {
            let bytes;
            try { bytes = readFileNoFollow(recordPath); }
            catch (error) {
              if (error && error.code === "ENOENT") continue;
              // A scanned alias store cannot be associated with this root without readable bytes.
              // Do not let damaged state belonging to another repository wedge every repository in
              // the account-wide v3 directory. This root's deterministic v3 names are already in
              // `candidates` and remain hard failures in installLegacyTombstones. A correctly live v3
              // owner from this account writes a readable 0600 record; after the installed tombstone
              // is planted, every newly launched v3 process selects that installed store.
              warnings.push(
                `unassociated legacy knockout record ${recordPath} was not readable and was skipped ` +
                  `(${String(error && error.message)})`,
              );
              continue;
            }
            let record;
            try { record = JSON.parse(bytes.toString("utf8")); }
            catch { continue; /* malformed bytes cannot associate another repository with this one */ }
            let rootState;
            try { rootState = recordRootState(record); }
            catch (error) {
              warnings.push(
                `unassociated legacy knockout record ${recordPath} names a root that could not be ` +
                  `inspected and was skipped (${String(error && error.message)})`,
              );
              continue;
            }
            if (rootState !== ROOT_RECORD.MISMATCH) {
              // MATCH covers v3 aliases. The stale states preserve v4 recovery after a remount or
              // generation change: the store is made a blocking migration candidate so its marker
              // and pristine bytes are named to the operator instead of becoming silent orphans.
              candidates.add(candidate);
              break;
            }
          }
        }
      }
      return candidates;
    } finally {
      // A later root may fail hard after earlier foreign state produced a warning. Preserve every
      // fact collected before the refusal, and never leak warnings from an earlier scan attempt.
      legacyScanWarnings = Object.freeze(warnings);
    }
  };

  const isOwnLegacyTombstone = (record) => isLegacyTombstoneForRoot(record, rootIdentity);

  /**
   * Create one old-store directory without following a symlinked path component. The installed
   * v3 store carried no source snapshots until a run armed, so its shell may retain the historical
   * 0755 mode; external v3 stores remain private 0700 directories.
   */
  const ensureLegacyCacheDir = (candidate) => {
    if (candidate === installedLegacyCacheDir) {
      ensureOwnedDir(path.join(repoRoot, "node_modules"));
      ensureOwnedDir(path.join(repoRoot, "node_modules", ".cache"));
      ensureOwnedDir(candidate);
      return;
    }
    const sharedRoot = [...legacySharedRoots()].find((root) => path.dirname(candidate) === root);
    if (sharedRoot === undefined) {
      throw new IncompleteSnapshotError(`${candidate} is not inside a recognized v3 cache root`);
    }
    ensurePrivateDir(sharedRoot);
    ensurePrivateDir(candidate);
  };

  /**
   * Permanently tombstone every v3 lock location before the v4 lock is taken. The atomic `wx`
   * create is the migration barrier: either this runner plants the tombstone and every old runner
   * refuses its deliberately non-v3 record, or an old runner wins and this migration refuses. A
   * read-only scan followed by taking only the v4 lock would leave a cross-version TOCTOU.
   */
  const installLegacyTombstones = () => {
    const problems = [];
    const candidates = [...discoveredLegacyCacheDirs()].sort((left, right) => {
      if (left === installedLegacyCacheDir) return -1;
      if (right === installedLegacyCacheDir) return 1;
      return Buffer.from(left).compare(Buffer.from(right));
    });
    for (const candidate of candidates) {
      try { ensureLegacyCacheDir(candidate); }
      catch (error) {
        problems.push(`${candidate} cannot be secured (${String(error && error.message)})`);
        continue;
      }
      const legacyLock = path.join(candidate, "lock.json");
      const tombstone = Buffer.from(JSON.stringify({
        protocol: LEGACY_TOMBSTONE_PROTOCOL,
        root: repoRoot,
        rootIdentity,
        migratedAt: new Date().toISOString(),
      }));
      let created = false;
      try {
        created = publishLegacyTombstoneNoClobber(legacyLock, tombstone);
      } catch (error) {
        problems.push(`${legacyLock} cannot be tombstoned (${String(error && error.message)})`);
        continue;
      }
      let record;
      try { record = JSON.parse(readFileNoFollow(legacyLock).toString("utf8")); }
      catch (error) {
        problems.push(`${legacyLock} cannot be read as a migration tombstone (${String(error && error.message)})`);
        continue;
      }
      if (!isOwnLegacyTombstone(record)) {
        problems.push(
          `${legacyLock} contains ${created ? "unexpected bytes after creation" : "pre-migration recovery state"}`,
        );
        continue;
      }
      let entries;
      try { entries = fs.readdirSync(candidate, { withFileTypes: true }); }
      catch (error) {
        problems.push(`${candidate} cannot be enumerated (${String(error && error.message)})`);
        continue;
      }
      const material = [];
      for (const entry of entries) {
        if (entry.name === "lock.json") continue;
        // A crash before/after the atomic link may strand only this inert, never-v3 staging file.
        if (entry.isFile() && LEGACY_TOMBSTONE_STAGING.test(entry.name)) continue;
        if (entry.name !== "runs" || !entry.isDirectory()) { material.push(entry.name); continue; }
        try {
          const runs = fs.readdirSync(path.join(candidate, "runs"));
          if (runs.length > 0) material.push(`runs/${runs.join(",runs/")}`);
        } catch (error) {
          material.push(`runs(unreadable: ${String(error && error.message)})`);
        }
      }
      if (material.length > 0) {
        problems.push(`${candidate} contains legacy recovery material ${material.join(", ")}`);
      }
    }
    if (problems.length > 0) {
      throw new IncompleteSnapshotError(
        `legacy knockout recovery state must be resolved before migration: ${problems.join("; ")}`,
      );
    }
  };

  /** Read a tree file for snapshotting. `null` ONLY when it is provably absent. */
  const readTreeFile = (abs) => {
    try { return readFileNoFollow(abs); }
    catch (e) {
      if (e && e.code === "ENOENT") return null;
      if (e instanceof IncompleteSnapshotError) throw e;
      throw new IncompleteSnapshotError(`cannot read ${path.relative(repoRoot, abs)}: ${String(e && e.message)}`);
    }
  };

  /**
   * Exact state of one worktree node. A symbolic link is recorded as a link, never followed; a
   * regular file carries both its bytes and permission mode. Absence is a first-class state so a
   * phase cannot turn a deleted tracked path into an unaccounted file.
   */
  const treeNodeSnapshot = (abs) => {
    let first;
    try { first = fs.lstatSync(abs, { bigint: true }); }
    catch (error) {
      if (error && error.code === "ENOENT") {
        return Object.freeze({
          bytes: null, identity: null, kind: "absent", linkTarget: null, mode: null,
          nlink: null, sha: null,
        });
      }
      throw new IncompleteSnapshotError(`cannot inspect ${abs}: ${String(error && error.message)}`);
    }
    if (first.isSymbolicLink()) {
      let linkTarget;
      let second;
      try {
        linkTarget = fs.readlinkSync(abs);
        second = fs.lstatSync(abs, { bigint: true });
      } catch (error) {
        throw new IncompleteSnapshotError(`cannot snapshot symbolic link ${abs}: ${String(error && error.message)}`);
      }
      if (!second.isSymbolicLink() || fileIdentity(first) !== fileIdentity(second)) {
        throw new IncompleteSnapshotError(`${abs} changed while its symbolic-link state was snapshotted`);
      }
      return Object.freeze({
        bytes: null,
        identity: fileIdentity(first),
        kind: "symlink",
        linkTarget,
        mode: Number(first.mode & 0o777n),
        nlink: Number(first.nlink),
        sha: digestOfBytes(Buffer.from(`symlink\0${linkTarget}`, "utf8")),
      });
    }
    if (!first.isFile()) {
      throw new IncompleteSnapshotError(`${abs} is neither a regular file nor a symbolic link`);
    }
    let fd;
    try { fd = fs.openSync(abs, fs.constants.O_RDONLY | NOFOLLOW); }
    catch (error) {
      if (error && error.code === "ELOOP") {
        throw new IncompleteSnapshotError(`${abs} became a symlink while it was being snapshotted`);
      }
      throw new IncompleteSnapshotError(`cannot open ${abs}: ${String(error && error.message)}`);
    }
    try {
      const opened = fs.fstatSync(fd, { bigint: true });
      if (!opened.isFile() || fileIdentity(opened) !== fileIdentity(first)) {
        throw new IncompleteSnapshotError(`${abs} changed while its regular-file state was snapshotted`);
      }
      const bytes = fs.readFileSync(fd);
      const after = fs.fstatSync(fd, { bigint: true });
      const atPath = fs.lstatSync(abs, { bigint: true });
      if (
        !after.isFile() || !atPath.isFile() ||
        fileIdentity(after) !== fileIdentity(opened) ||
        fileIdentity(atPath) !== fileIdentity(opened) ||
        after.nlink !== opened.nlink || after.size !== opened.size ||
        after.mtimeNs !== opened.mtimeNs || after.ctimeNs !== opened.ctimeNs
      ) {
        throw new IncompleteSnapshotError(`${abs} changed while its regular-file bytes were snapshotted`);
      }
      return Object.freeze({
        bytes,
        identity: fileIdentity(opened),
        kind: "file",
        linkTarget: null,
        mode: Number(opened.mode & 0o777n),
        nlink: Number(opened.nlink),
        sha: digestOfBytes(bytes),
      });
    } finally { fs.closeSync(fd); }
  };

  const persistedNodeState = (state) => Object.freeze({
    kind: state.kind,
    linkTarget: state.linkTarget,
    mode: state.mode,
    sha: state.sha,
  });
  const sameNodeState = (left, right) =>
    left.kind === right.kind && left.mode === right.mode && left.sha === right.sha
      && left.linkTarget === right.linkTarget;

  /** Restore only a node whose original identity is known; an unknown replacement is preserved. */
  const restoreKnownNode = ({ abs, saved, storePath, label, protectedIdentities = new Set() }) => {
    const current = treeNodeSnapshot(abs);
    if (sameNodeState(current, saved)) return Object.freeze({ changed: false, failure: null });
    try {
      if (saved.kind === "absent") {
        return Object.freeze({
          changed: false,
          failure: `${label} was absent before this phase but now exists; refusing to delete unknown data`,
        });
      }
      // Never unlink a regular file in order to restore a link, or follow a replacement link while
      // restoring a file. Either shape may contain concurrent user data and therefore remains for
      // inspection behind a failing recovery marker.
      if (saved.kind === "file") {
        if (current.kind !== "file" && current.kind !== "absent") {
          return Object.freeze({
            changed: false,
            failure: `${label} changed from a regular file to ${current.kind}; refusing to overwrite it`,
          });
        }
        const bytes = loadStored(storePath, saved.sha);
        rewriteCleanupFileNoFollow(abs, bytes, saved.mode, protectedIdentities);
      } else if (saved.kind === "symlink") {
        if (current.kind !== "symlink" && current.kind !== "absent") {
          return Object.freeze({
            changed: false,
            failure: `${label} changed from a symbolic link to ${current.kind}; refusing to delete it`,
          });
        }
        recordedRepoFile(path.relative(repoRoot, abs), `${label} restore path`);
        if (current.kind === "symlink") fs.unlinkSync(abs);
        fs.symlinkSync(saved.linkTarget, abs);
      } else {
        return Object.freeze({ changed: false, failure: `${label} has an unknown saved node kind` });
      }
      const verified = treeNodeSnapshot(abs);
      if (!sameNodeState(verified, saved)) {
        return Object.freeze({ changed: true, failure: `${label} did not return to its exact saved node state` });
      }
      return Object.freeze({ changed: true, failure: null });
    } catch (error) {
      return Object.freeze({ changed: false, failure: `could not restore ${label}: ${String(error && error.message)}` });
    }
  };

  /** Copy a tree file into this run's store and PROVE the stored copy matches what was hashed. */
  const storeBytes = (dest, bytes, digest) => {
    writeFileNoFollow(dest, bytes);
    const back = readFileNoFollow(dest);
    if (digestOfBytes(back) !== digest) {
      throw new IncompleteSnapshotError(`the stored copy of ${dest} does not match the bytes it was recorded under`);
    }
  };

  /** Read back from the store, VERIFYING the digest before anything is written to the tree. */
  const loadStored = (src, digest) => {
    const bytes = readFileNoFollow(src);
    if (digestOfBytes(bytes) !== digest) {
      throw new IncompleteSnapshotError(`the stored copy at ${src} no longer matches its recorded digest`);
    }
    return bytes;
  };

  const saveIndex = (p) => {
    fs.mkdirSync(path.dirname(p.index), { recursive: true });
    writeFileNoFollow(p.index, Buffer.from(JSON.stringify(Object.fromEntries(index))));
  };

  /**
   * Load a run's artifact index. THROWS when it is missing or corrupt while a marker exists:
   * an "empty snapshot" would make recovery treat every real build output as something the crashed
   * arm created, and DELETE it (round 2 #1).
   */
  const loadIndexOrThrow = (p) => {
    let raw;
    try { raw = readFileNoFollow(p.index); }
    catch (e) {
      if (e && e.code === "ENOENT") {
        throw new IncompleteSnapshotError(`the interrupted run's artifact index is missing (${p.index})`);
      }
      throw new IncompleteSnapshotError(`the interrupted run's artifact index cannot be read: ${String(e && e.message)}`);
    }
    try {
      const parsed = JSON.parse(raw.toString("utf8"));
      if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
        throw new Error("the artifact index is not an object");
      }
      const loaded = new Map();
      for (const [rel, digest] of Object.entries(parsed)) {
        recordedArtifactFile(rel);
        if (typeof digest !== "string" || !/^[0-9a-f]{64}$/.test(digest)) {
          throw new Error(`the artifact digest for ${JSON.stringify(rel)} is not sha256`);
        }
        loaded.set(rel, digest);
      }
      return loaded;
    } catch (e) {
      throw new IncompleteSnapshotError(`the interrupted run's artifact index is corrupt: ${String(e && e.message)}`);
    }
  };

  /** ENOENT means "no marker". EVERYTHING else means "refuse" (round 2 #1). */
  const readMarkerStrict = (p) => {
    let raw;
    try { raw = readFileNoFollow(p.marker); }
    catch (e) {
      if (e && e.code === "ENOENT") return null;
      throw new IncompleteSnapshotError(`the interrupted run's marker cannot be read: ${String(e && e.message)}`);
    }
    let marker;
    try { marker = JSON.parse(raw.toString("utf8")); }
    catch (e) {
      throw new IncompleteSnapshotError(`the interrupted run's marker is not valid JSON: ${String(e && e.message)}`);
    }
    if (marker === null || typeof marker !== "object" || Array.isArray(marker)) {
      throw new IncompleteSnapshotError("the interrupted run's marker is not an object");
    }
    const markerRootState = recordRootState(marker, { requireGeneration: true });
    if (marker.version !== 4 || markerRootState !== ROOT_RECORD.MATCH) {
      throw new IncompleteSnapshotError(
        `the interrupted run's marker describes ${JSON.stringify(marker && marker.root)} ` +
          `(${JSON.stringify(marker && marker.rootIdentity)}, ${markerRootState}), not ` +
          `${repoRoot} (${rootIdentity}, ${rootGeneration})`,
      );
    }
    if (!isSafeRunNonce(marker.nonce)) {
      throw new IncompleteSnapshotError("the interrupted run's marker has an unsafe run nonce");
    }
    const sources = marker.sources;
    if (!Array.isArray(sources)) {
      throw new IncompleteSnapshotError("the interrupted run's marker sources are not an array");
    }
    for (const source of sources) {
      if (source === null || typeof source !== "object" || Array.isArray(source)) {
        throw new IncompleteSnapshotError("the interrupted run's marker contains a malformed source record");
      }
      recordedRepoFile(source.rel, "the interrupted run's source path");
      if (typeof source.store !== "string" || !/^s[0-9]+$/.test(source.store)) {
        throw new IncompleteSnapshotError(
          `the interrupted run's source store is not a local snapshot leaf: ${JSON.stringify(source.store)}`,
        );
      }
      for (const field of ["pristineSha", "mutantSha"]) {
        if (typeof source[field] !== "string" || !/^[0-9a-f]{64}$/.test(source[field])) {
          throw new IncompleteSnapshotError(
            `the interrupted run's source ${field} is not sha256: ${JSON.stringify(source[field])}`,
          );
        }
      }
    }
    if (marker.dirtyBefore !== null && marker.dirtyBefore !== undefined) {
      if (!Array.isArray(marker.dirtyBefore)) {
        throw new IncompleteSnapshotError("the interrupted run's marker dirtyBefore is not an array");
      }
      for (const entry of marker.dirtyBefore) {
        if (
          !Array.isArray(entry) || entry.length !== 2 ||
          typeof entry[0] !== "string" || entry[0].length === 0 || entry[0].includes("\0") ||
          typeof entry[1] !== "string" || entry[1].length !== 2
        ) {
          throw new IncompleteSnapshotError(
            `the interrupted run's marker contains a malformed dirtyBefore entry: ${JSON.stringify(entry)}`,
          );
        }
      }
    }
    const validIndexEntry = (entry) => entry === null || (
      exactKeys(entry, ["blob", "mode", "stage"])
      && typeof entry.mode === "string" && /^\d+$/.test(entry.mode)
      && typeof entry.blob === "string" && /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(entry.blob)
      && typeof entry.stage === "string" && /^[0-3]$/.test(entry.stage)
    );
    const validateNodeRecord = (record, {
      expectedKeys,
      label,
      storePattern,
      requireEntry = true,
    }) => {
      if (!exactKeys(record, expectedKeys)) {
        throw new IncompleteSnapshotError(`${label} has an unexpected schema`);
      }
      recordedRepoFile(record.rel, `${label} path`);
      if (!['absent', 'file', 'symlink'].includes(record.kind)) {
        throw new IncompleteSnapshotError(`${label} has an unknown node kind`);
      }
      if (requireEntry && !validIndexEntry(record.entry)) {
        throw new IncompleteSnapshotError(`${label} has a malformed index entry`);
      }
      if (record.kind === "absent") {
        if (record.mode !== null || record.sha !== null || record.linkTarget !== null || record.store !== null) {
          throw new IncompleteSnapshotError(`${label} has malformed absent-node state`);
        }
        return;
      }
      if (!Number.isSafeInteger(record.mode) || record.mode < 0 || record.mode > 0o777
          || typeof record.sha !== "string" || !HEX_64_RE.test(record.sha)) {
        throw new IncompleteSnapshotError(`${label} has malformed mode or digest`);
      }
      if (record.kind === "file") {
        if (record.linkTarget !== null || typeof record.store !== "string"
            || !storePattern.test(record.store)) {
          throw new IncompleteSnapshotError(`${label} has malformed regular-file storage`);
        }
      } else if (typeof record.linkTarget !== "string" || record.linkTarget.includes("\0")
          || record.store !== null) {
        throw new IncompleteSnapshotError(`${label} has malformed symbolic-link state`);
      }
    };
    if (marker.protectedPaths !== undefined) {
      if (!Array.isArray(marker.protectedPaths)) {
        throw new IncompleteSnapshotError("the interrupted run's protectedPaths is not an array");
      }
      for (const record of marker.protectedPaths) {
        validateNodeRecord(record, {
          expectedKeys: [
            "code", "entry", "isTarget", "kind", "linkTarget", "mode", "rel", "sha", "store",
          ],
          label: "the interrupted run's protected path",
          storePattern: /^d[0-9]+$/,
        });
        if ((record.code !== null && (typeof record.code !== "string" || record.code.length !== 2))
            || typeof record.isTarget !== "boolean") {
          throw new IncompleteSnapshotError("the interrupted run's protected path metadata is malformed");
        }
      }
    }
    if (marker.exactCustody !== undefined) {
      if (!Array.isArray(marker.exactCustody)) {
        throw new IncompleteSnapshotError("the interrupted run's exactCustody is not an array");
      }
      for (const record of marker.exactCustody) {
        validateNodeRecord(record, {
          expectedKeys: ["entry", "kind", "linkTarget", "mode", "rel", "sha", "store"],
          label: "the interrupted run's exact-custody path",
          storePattern: /^x[0-9]+$/,
        });
      }
    }
    if (marker.exactArtifactPaths !== undefined) {
      if (!Array.isArray(marker.exactArtifactPaths)
          || marker.exactArtifactPaths.some((rel) => typeof rel !== "string" || rel.length === 0)) {
        throw new IncompleteSnapshotError("the interrupted run's exactArtifactPaths is malformed");
      }
      for (const rel of marker.exactArtifactPaths) recordedRepoFile(rel, "exact artifact path");
    }
    if (marker.exactGitIndex !== undefined && marker.exactGitIndex !== null) {
      const record = marker.exactGitIndex;
      if (!exactKeys(record, ["kind", "linkTarget", "mode", "path", "sha", "store", "tree"])
          || record.kind !== "file" || record.linkTarget !== null
          || !Number.isSafeInteger(record.mode) || record.mode < 0 || record.mode > 0o777
          || typeof record.sha !== "string" || !HEX_64_RE.test(record.sha)
          || record.store !== "git-index.bin" || typeof record.path !== "string"
          || !path.isAbsolute(record.path) || typeof record.tree !== "string"
          || !/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(record.tree)) {
        throw new IncompleteSnapshotError("the interrupted run's exact Git-index record is malformed");
      }
    }
    return marker;
  };

  /** Remove a file and PROVE it is gone. A deletion that silently failed is not a deletion. */
  const removeVerified = (p, what) => {
    try { fs.rmSync(p, { force: true }); }
    catch (e) { throw new IncompleteSnapshotError(`could not remove ${what} at ${p}: ${String(e && e.message)}`); }
    if (fs.existsSync(p)) throw new IncompleteSnapshotError(`${what} at ${p} still exists after removal`);
  };

  // ── the git index, which `git checkout --` reads FROM ───────────────────────────────────────
  const indexEntryOf = (rel) => {
    let out;
    try { out = runGitReadOnly(repoRoot, ["ls-files", "-s", "--", rel]).trim(); }
    catch (e) { throw new IncompleteSnapshotError(`cannot read the index entry for ${rel}: ${String(e && e.message)}`); }
    if (out === "") return null;
    const m = /^(\d+)\s+([0-9a-f]{40,64})\s+(\d+)\t/.exec(out);
    if (m === null) throw new IncompleteSnapshotError(`cannot parse the index entry for ${rel}: ${JSON.stringify(out)}`);
    return { mode: m[1], blob: m[2], stage: m[3] };
  };
  const sameIndexEntry = (a, b) =>
    (a === null && b === null) || (a !== null && b !== null && a.mode === b.mode && a.blob === b.blob && a.stage === b.stage);
  const restoreIndexEntry = (rel, want) => {
    // The three-argument `--cacheinfo` form, not `mode,sha,path`: a repository path may contain a
    // comma, and the packed form would split on it.
    if (want === null) runGit(repoRoot, ["update-index", "--force-remove", "--", rel]);
    else runGit(repoRoot, ["update-index", "--cacheinfo", want.mode, want.blob, rel]);
  };

  /** Bring this run's store to the tree's CURRENT bytes. */
  const syncStore = (p) => {
    const present = new Set();
    for (const rel of listBuildArtifacts(repoRoot)) {
      const abs = path.join(repoRoot, rel);
      const bytes = readTreeFile(abs);
      if (bytes === null) {
        // Round 2 #4: it was enumerated a moment ago and is gone now. Skipping it would leave a
        // hole, and if it came back, restoration would delete it as "created by the arm".
        throw new IncompleteSnapshotError(`${rel} vanished between enumeration and hashing`);
      }
      const digest = digestOfBytes(bytes);
      present.add(rel);
      const stored = path.join(p.store, rel);
      if (index.get(rel) === digest && fs.existsSync(stored)) continue;
      storeBytes(stored, bytes, digest);
      index.set(rel, digest);
    }
    for (const rel of [...index.keys()]) {
      if (present.has(rel)) continue;
      try { fs.rmSync(path.join(p.store, rel), { force: true }); } catch { /* already gone */ }
      index.delete(rel);
    }
    saveIndex(p);
  };

  /** Put every derived artefact back to the bytes the store holds. Byte-exact, verified twice. */
  const restoreStore = (p, protectedIdentities = new Set()) => {
    const restored = [];
    const removed = [];
    const failures = [];
    const present = new Set();
    let listing;
    try { listing = listBuildArtifacts(repoRoot); }
    catch (e) { return { restored, removed, failures: [String(e && e.message)] }; }
    for (const rel of listing) {
      const abs = path.join(repoRoot, rel);
      present.add(rel);
      const want = index.get(rel);
      if (want === undefined) {
        // Built during the phase and absent before it: returning the tree means it goes away. It is
        // derived from the MUTANT, so keeping it is the leak this guard exists to stop.
        try { removeCleanupFileNoFollow(abs, protectedIdentities); removed.push(rel); }
        catch (e) { failures.push(`could not delete mutant build output ${rel}: ${String(e && e.message)}`); }
        continue;
      }
      try {
        const current = readTreeFile(abs);
        if (current !== null && digestOfBytes(current) === want) continue;
        rewriteCleanupFileNoFollow(
          abs,
          loadStored(path.join(p.store, rel), want),
          null,
          protectedIdentities,
        );
        restored.push(rel);
      } catch (e) {
        failures.push(`could not restore build output ${rel}: ${String(e && e.message)}`);
      }
    }
    for (const rel of index.keys()) {
      if (present.has(rel)) continue;   // deleted by the phase (a build that cleans its own output)
      try {
        rewriteCleanupFileNoFollow(
          path.join(repoRoot, rel),
          loadStored(path.join(p.store, rel), index.get(rel)),
          null,
          protectedIdentities,
        );
        restored.push(rel);
      } catch (e) {
        failures.push(`could not restore deleted build output ${rel}: ${String(e && e.message)}`);
      }
    }
    return { restored: restored.sort(), removed: removed.sort(), failures };
  };

  /**
   * Snapshot the BYTES and the INDEX ENTRY of every tracked path that is already dirty, plus of
   * every path this phase is about to mutate.
   *
   * Round 1 #2 was the bytes: the guard used to skip already-dirty paths so as not to destroy a
   * developer's work, and by skipping destroyed exactly that — the phase's generator overwrites the
   * file, so their edit was gone and the mutant's content stayed, invisibly, because the residue
   * check compares status STRINGS and ` M fixture.json` is ` M fixture.json` either way.
   *
   * Round 2 #2 was the index: a path whose worktree, index and HEAD all differed got its worktree
   * restored and its index left holding whatever the suite staged — including a staged MUTATED
   * SOURCE, which the mutation-target exemption made worse rather than better.
   *
   * Untracked paths (`??`) are deliberately not snapshotted: porcelain collapses an untracked
   * DIRECTORY into one entry, so this would be an unbounded copy.
   */
  const snapshotProtected = (p, dirtyBefore, targets) => {
    fs.mkdirSync(p.dirty, { recursive: true });
    const saved = [];
    const wanted = new Map();
    if (dirtyBefore !== null) {
      for (const [rel, code] of dirtyBefore) if (code !== "??") wanted.set(rel, code);
    }
    for (const rel of targets) if (!wanted.has(rel)) wanted.set(rel, null);
    let n = 0;
    for (const [rel, code] of wanted) {
      const abs = path.join(repoRoot, rel);
      recordedRepoFile(rel, "protected worktree path");
      const state = treeNodeSnapshot(abs);
      const entry = dirtyBefore === null ? null : indexEntryOf(rel);
      const store = state.kind === "file" ? `d${n++}` : null;
      if (store !== null) storeBytes(path.join(p.dirty, store), state.bytes, state.sha);
      saved.push({
        rel,
        code,
        entry,
        isTarget: targets.has(rel),
        store,
        ...persistedNodeState(state),
      });
    }
    return saved;
  };

  /**
   * Mutation authority is granted only to distinct, single-link regular files whose exact pristine
   * bytes are still present. A hardlink is unsafe before mutation even when its other name is not
   * inside a derived-output directory: truncating either name would mutate both.
   */
  const assertSafeMutationSources = (sources) => {
    const identities = new Set();
    const states = new Map();
    for (const [rel, pristineBytes] of sources) {
      const state = treeNodeSnapshot(path.join(repoRoot, rel));
      if (state.kind !== "file" || state.nlink !== 1) {
        throw new IncompleteSnapshotError(
          `${rel} is not a single-link regular file; refusing to arm a source mutation`,
        );
      }
      if (state.sha !== digestOfBytes(Buffer.from(pristineBytes))) {
        throw new IncompleteSnapshotError(
          `${rel} changed after its pristine bytes were read; refusing to arm a source mutation`,
        );
      }
      if (identities.has(state.identity)) {
        throw new IncompleteSnapshotError(
          `${rel} shares an inode with another mutation target; refusing to arm`,
        );
      }
      identities.add(state.identity);
      states.set(rel, Object.freeze({
        identity: state.identity,
        mode: state.mode,
        nlink: state.nlink,
        pristineSha: state.sha,
      }));
    }
    return states;
  };

  /**
   * Second-phase custody over exact source/derived nodes. This is deliberately separate from the
   * long-standing artifact byte store: it adds mode and symlink identity without changing the
   * artifact API or making historical recovery interpret a new descriptor as an old digest.
   */
  const snapshotExactCustody = (p, relativePaths, { includeIndexEntries }) => {
    fs.mkdirSync(p.exact, { recursive: true });
    const saved = [];
    let n = 0;
    for (const rel of [...new Set(relativePaths)].sort()) {
      recordedRepoFile(rel, "exact post-restore custody path");
      const state = treeNodeSnapshot(path.join(repoRoot, rel));
      const store = state.kind === "file" ? `x${n++}` : null;
      if (store !== null) storeBytes(path.join(p.exact, store), state.bytes, state.sha);
      saved.push({
        rel,
        entry: includeIndexEntries ? indexEntryOf(rel) : null,
        store,
        ...persistedNodeState(state),
      });
    }
    return saved;
  };

  const restoreExactCustody = (
    p,
    saved,
    artifactPathsBefore,
    { restoreIndexEntries, protectedIdentities = new Set() },
  ) => {
    const restored = [];
    const additions = [];
    const failures = [];
    for (const record of saved) {
      const result = restoreKnownNode({
        abs: path.join(repoRoot, record.rel),
        saved: record,
        storePath: record.store === null ? null : path.join(p.exact, record.store),
        label: record.rel,
        protectedIdentities,
      });
      if (result.failure !== null) failures.push(result.failure);
      if (result.changed) restored.push(record.rel);
      if (restoreIndexEntries) {
        try {
          const currentEntry = indexEntryOf(record.rel);
          if (!sameIndexEntry(currentEntry, record.entry)) {
            restoreIndexEntry(record.rel, record.entry);
            if (!sameIndexEntry(indexEntryOf(record.rel), record.entry)) {
              failures.push(`${record.rel} index entry did not return to exact-custody state`);
            } else if (!restored.includes(record.rel)) restored.push(record.rel);
          }
        } catch (error) {
          failures.push(`could not restore ${record.rel} index entry: ${String(error && error.message)}`);
        }
      }
    }
    let artifactsAfter = [];
    try { artifactsAfter = listExactBuildNodes(repoRoot); }
    catch (error) { failures.push(String(error && error.message)); }
    const before = new Set(artifactPathsBefore);
    for (const rel of artifactsAfter) {
      if (!before.has(rel)) additions.push(rel);
    }
    return {
      additions: [...new Set(additions)].sort(),
      failures,
      restored: [...new Set(restored)].sort(),
    };
  };

  const gitIndexPath = () => {
    let raw;
    try { raw = runGitReadOnly(repoRoot, ["rev-parse", "--git-path", "index"]).trim(); }
    catch (error) {
      throw new IncompleteSnapshotError(`cannot resolve the active Git index: ${String(error && error.message)}`);
    }
    if (raw.length === 0 || raw.includes("\0") || raw.includes("\n") || raw.includes("\r")) {
      throw new IncompleteSnapshotError(`Git returned a malformed index path: ${JSON.stringify(raw)}`);
    }
    return path.isAbsolute(raw) ? path.normalize(raw) : path.resolve(repoRoot, raw);
  };

  const treeOfIndexState = (p, state, label) => {
    if (state.kind !== "file") {
      throw new IncompleteSnapshotError(`${label} Git index is not a regular file`);
    }
    const scratch = `${p.gitIndex}.tree-read`;
    if (fs.existsSync(scratch)) {
      throw new IncompleteSnapshotError(`private Git-index tree scratch already exists at ${scratch}`);
    }
    let tree;
    let created = false;
    try {
      writeFileNoFollow(scratch, state.bytes, 0o600);
      created = true;
      tree = runGitWithIndex(repoRoot, ["write-tree"], scratch).trim();
    } catch (error) {
      throw new IncompleteSnapshotError(
        `cannot derive the ${label} Git-index tree from its private copy: ${String(error && error.message)}`,
      );
    } finally {
      if (created) removeVerified(scratch, `${label} Git-index tree scratch`);
    }
    if (!/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(tree)) {
      throw new IncompleteSnapshotError(`Git returned a malformed ${label} index tree: ${JSON.stringify(tree)}`);
    }
    return tree;
  };

  const snapshotExactGitIndex = (p, { store = true, label = "pre-phase" } = {}) => {
    if (gitWorkTreeState(repoRoot) !== "yes") {
      throw new IncompleteSnapshotError("exact Git-index custody requires a proven work tree");
    }
    const indexPath = gitIndexPath();
    const state = treeNodeSnapshot(indexPath);
    if (state.kind !== "file") {
      throw new IncompleteSnapshotError(`the active Git index ${indexPath} is not a regular file`);
    }
    const tree = treeOfIndexState(p, state, label);
    if (store) storeBytes(p.gitIndex, state.bytes, state.sha);
    return Object.freeze({
      path: indexPath,
      store: path.basename(p.gitIndex),
      tree,
      ...persistedNodeState(state),
    });
  };

  const restoreExactGitIndex = (
    p,
    saved,
    observationBaseline = saved,
    observedAtPhaseEnd = null,
    protectedIdentities = new Set(),
  ) => {
    const failures = [];
    let changed = false;
    let observationChanged = true;
    let semanticChanged = true;
    let hashObserved = null;
    let treeObserved = null;
    let treeAfter = null;
    try {
      const currentPath = gitIndexPath();
      if (currentPath !== saved.path) {
        failures.push(`active Git index path changed from ${saved.path} to ${currentPath}`);
      } else {
        const current = treeNodeSnapshot(currentPath);
        const observed = observedAtPhaseEnd ?? {
          path: currentPath,
          tree: current.kind === "file" ? treeOfIndexState(p, current, "observed") : null,
          ...persistedNodeState(current),
        };
        hashObserved = observed.sha;
        observationChanged = observed.path !== observationBaseline.path
          || !sameNodeState(observed, observationBaseline);
        treeObserved = observed.tree;
        semanticChanged = treeObserved !== observationBaseline.tree;
        if (!sameNodeState(current, saved)) {
          if (current.kind !== "file" && current.kind !== "absent") {
            failures.push(`active Git index changed to ${current.kind}; refusing to overwrite it`);
          } else {
            rewriteCleanupFileNoFollow(
              currentPath,
              loadStored(p.gitIndex, saved.sha),
              saved.mode,
              protectedIdentities,
            );
            changed = true;
          }
        }
        const verified = treeNodeSnapshot(currentPath);
        if (!sameNodeState(verified, saved)) {
          failures.push("active Git index file did not return to its exact saved bytes and mode");
        } else {
          treeAfter = treeOfIndexState(p, verified, "restored");
        }
        if (treeAfter !== saved.tree) {
          failures.push(`active Git index tree changed from ${saved.tree} to ${treeAfter}`);
        }
      }
    } catch (error) {
      failures.push(`could not restore exact Git-index custody: ${String(error && error.message)}`);
    }
    return Object.freeze({
      changed,
      failures,
      hashAfter: failures.length === 0 ? saved.sha : null,
      hashBefore: saved.sha,
      hashObserved,
      observationChanged,
      semanticChanged,
      treeAfter,
      treeBefore: saved.tree,
      treeObserved,
    });
  };

  /**
   * Put back every tracked file this phase disturbed.
   *
   *   • protected (already dirty, or a mutation target) → restore this run's own BYTE SNAPSHOT and
   *     its INDEX ENTRY. A mutation target's bytes are restored by the caller and sha-verified
   *     there; its index entry is restored here, because nothing else does.
   *   • clean when the phase began → `git checkout HEAD --`, which resets the INDEX as well as the
   *     worktree. A path that is clean in porcelain has worktree == index == HEAD by definition,
   *     so HEAD is exactly the pre-phase content. Only in `tracked: "all"` mode: during the
   *     BASELINE phase a clean-before file that changed is a real drift in the repository, and
   *     silently reverting it would hide something the residue check should report.
   *   • newly ADDED to the index by the phase → unstaged and reported; it is not in HEAD.
   *   • untracked → REPORTED, never deleted. Deleting a file this process cannot prove it created
   *     is how a tool destroys work it does not own. It counts as a FAILURE, so the marker cannot
   *     clear over it (round 2 #1).
   */
  const restoreTracked = (
    before,
    protectedPaths,
    mode,
    preservedConcurrentSources,
    protectedIdentities = new Set(),
  ) => {
    const reverted = [];
    const preserved = [];
    const additions = [];
    const failures = [];
    let after;
    try { after = gitDirtyPaths(repoRoot); }
    catch (e) { return { reverted, preserved, additions, failures: [String(e && e.message)] }; }

    for (const saved of protectedPaths) {
      const abs = path.join(repoRoot, saved.rel);
      try {
        const current = treeNodeSnapshot(abs);
        if (!sameNodeState(current, saved)) {
          // A mutation target's bytes are the caller's business: it restores only bytes that still
          // equal the mutant it wrote, so a concurrent replacement is never erased. Mode-only
          // drift on the already-restored regular file is safe to return through its descriptor.
          if (saved.isTarget) {
            if (current.kind === "file" && saved.kind === "file" && current.sha === saved.sha) {
              chmodFileNoFollow(abs, saved.mode);
              reverted.push(saved.rel);
            } else if (
              current.kind === "file" &&
              preservedConcurrentSources.get(saved.rel)?.sha256 === current.sha
            ) {
              // The source restorer observed these exact user bytes after the suite stopped and
              // explicitly transferred their custody. Preserve them, while still restoring the
              // target's index entry and every independently derived node below.
              preserved.push(saved.rel);
            } else {
              failures.push(
                `${saved.rel} no longer has the exact source node this arm snapshotted; ` +
                  "refusing to overwrite a concurrent edit",
              );
            }
          } else {
            const restored = restoreKnownNode({
              abs,
              saved,
              storePath: saved.store === null ? null : path.join(runPathsOf().dirty, saved.store),
              label: saved.rel,
              protectedIdentities,
            });
            if (restored.failure !== null) failures.push(restored.failure);
            if (restored.changed) reverted.push(saved.rel);
          }
        }
        if (before !== null) {
          const nowEntry = indexEntryOf(saved.rel);
          if (!sameIndexEntry(nowEntry, saved.entry)) {
            restoreIndexEntry(saved.rel, saved.entry);
            const verifiedEntry = indexEntryOf(saved.rel);
            if (!sameIndexEntry(verifiedEntry, saved.entry)) {
              failures.push(`${saved.rel} index entry did not return to its exact pre-phase state`);
            }
            if (!reverted.includes(saved.rel)) reverted.push(saved.rel);
          }
        }
      } catch (e) {
        failures.push(`could not restore ${saved.rel}: ${String(e && e.message)}`);
      }
    }

    if (after === null || before === null) {
      return { reverted: reverted.sort(), preserved: preserved.sort(), additions, failures };
    }

    const protectedSet = new Set(protectedPaths.map((s) => s.rel));
    for (const [rel, code] of after) {
      if (protectedSet.has(rel)) continue;      // handled above
      if (before.has(rel)) continue;            // dirty before and not protected: not ours to touch
      if (code === "??") { additions.push(rel); continue; }
      if (mode !== "all") continue;             // baseline phase: a real drift, left for the residue check
      try {
        const node = treeNodeSnapshot(path.join(repoRoot, rel));
        if (
          node.kind === "file" &&
          (node.nlink !== 1 || protectedIdentities.has(node.identity))
        ) {
          failures.push(`${rel} aliases an inode under custody; refusing Git cleanup`);
          continue;
        }
      } catch (error) {
        failures.push(`could not inspect ${rel} before Git cleanup: ${String(error && error.message)}`);
        continue;
      }
      if (code[0] === "A") {
        try { runGit(repoRoot, ["reset", "-q", "--", rel]); } catch { /* reported as an addition */ }
        additions.push(rel);
        continue;
      }
      try {
        runGit(repoRoot, ["checkout", "HEAD", "--", rel]);
        reverted.push(rel);
      } catch (e) {
        failures.push(`could not revert generated file ${rel}: ${String(e && e.message)}`);
      }
    }
    return {
      reverted: reverted.sort(),
      preserved: preserved.sort(),
      additions: additions.sort(),
      failures,
    };
  };

  const runPathsOf = () => runPaths(owner.runDir);

  // ── the lock ────────────────────────────────────────────────────────────────────────────────
  /** Repair a dead run's leftovers. Returns a report; `clean` decides whether its lock may be taken. */
  const repairDeadRun = (record) => {
    const p = runPaths(record.runDir);
    const marker = readMarkerStrict(p);                    // throws on anything but ENOENT
    if (marker === null) {
      // The lock outlived its run without ever arming a phase: nothing was mutated.
      return { clean: true, entry: "<none>", startedAt: record.startedAt, sources: [], artifacts: [], removed: [], unresolved: [], suspect: [], failures: [] };
    }
    if (marker.nonce !== record.nonce) {
      throw new IncompleteSnapshotError(
        `the interrupted run's marker belongs to nonce ${JSON.stringify(marker.nonce)}, not ` +
          `${JSON.stringify(record.nonce)}`,
      );
    }
    index = loadIndexOrThrow(p);                           // throws when missing or corrupt

    const restoredSources = [];
    const unresolved = [];
    const failures = [];
    const recoveredSourceStates = new Map();
    const protectedSourceIdentities = new Set();
    for (const s of marker.sources ?? []) {
      const abs = path.join(repoRoot, s.rel);
      let current;
      try { current = treeNodeSnapshot(abs); }
      catch (e) { failures.push(String(e && e.message)); continue; }
      if (current.kind !== "file") {
        unresolved.push(
          `${s.rel} is ${current.kind}, not a regular file; recovery will not overwrite it`,
        );
        continue;
      }
      if (current.nlink !== 1) {
        unresolved.push(
          `${s.rel} has ${current.nlink} hardlinks; recovery will not write or clean through an alias`,
        );
        continue;
      }
      if (protectedSourceIdentities.has(current.identity)) {
        unresolved.push(`${s.rel} shares an inode with another recovery source`);
        continue;
      }
      if (current.sha === s.pristineSha) {
        recoveredSourceStates.set(s.rel, current);         // its `finally` did run
        protectedSourceIdentities.add(current.identity);
        continue;
      }
      if (current.sha !== s.mutantSha) {
        unresolved.push(
          `${s.rel} holds neither the pristine bytes nor the mutation the interrupted arm wrote; ` +
          `it was changed after the crash and this runner will not overwrite it`,
        );
        continue;
      }
      try {
        rewriteObservedFileNoFollow(
          abs,
          loadStored(path.join(p.sources, s.store), s.pristineSha),
          current,
        );
        const back = treeNodeSnapshot(abs);
        if (
          back.kind !== "file" || back.sha !== s.pristineSha || back.nlink !== 1 ||
          back.identity !== current.identity
        ) {
          failures.push(`${s.rel} did not return to its pristine sha256 after recovery`);
        } else {
          restoredSources.push(s.rel);
          recoveredSourceStates.set(s.rel, back);
          protectedSourceIdentities.add(back.identity);
        }
      } catch (e) {
        failures.push(`could not restore mutant source ${s.rel}: ${String(e && e.message)}`);
      }
    }

    const sourceRecoverySafe = failures.length === 0 && unresolved.length === 0;
    const artefacts = marker.artifacts === false || !sourceRecoverySafe
      ? { restored: [], removed: [], failures: [] }
      : restoreStore(p, protectedSourceIdentities);
    if (sourceRecoverySafe) {
      for (const [rel, beforeCleanup] of recoveredSourceStates) {
        try {
          const afterCleanup = treeNodeSnapshot(path.join(repoRoot, rel));
          if (
            afterCleanup.kind !== "file" || afterCleanup.identity !== beforeCleanup.identity ||
            afterCleanup.nlink !== 1 || afterCleanup.sha !== beforeCleanup.sha
          ) {
            unresolved.push(`${rel} changed while interrupted derived state was being cleaned`);
          }
        } catch (error) {
          failures.push(
            `could not revalidate recovered source ${rel}: ${String(error && error.message)}`,
          );
        }
      }
    }

    // The exact-custody records are intentionally NOT auto-restored after a crash. The window is
    // now unbounded, so changed bytes may be later user work. Verify the durable snapshot and keep
    // the lock/marker when anything differs; preserving evidence outranks guessing ownership.
    const sourceRecordRels = new Set((marker.sources ?? []).map((source) => source.rel));
    const verifyRecoveryNodes = (records, storeRoot, label, { includeIndexEntries }) => {
      for (const record of records ?? []) {
        if (sourceRecordRels.has(record.rel)
            && unresolved.some((detail) => detail.startsWith(`${record.rel} `))) {
          // The source recovery loop already recorded this exact path as a concurrent/post-crash
          // edit. Preserve one actionable problem rather than counting the same bytes twice.
          continue;
        }
        try {
          if (record.kind === "file") loadStored(path.join(storeRoot, record.store), record.sha);
          const current = treeNodeSnapshot(path.join(repoRoot, record.rel));
          if (!sameNodeState(current, record)) {
            unresolved.push(`${label} ${record.rel} differs from its exact pre-phase node state`);
          }
          if (includeIndexEntries && !sameIndexEntry(indexEntryOf(record.rel), record.entry)) {
            unresolved.push(`${label} ${record.rel} has a different Git index entry`);
          }
        } catch (error) {
          failures.push(`could not verify ${label} ${record.rel}: ${String(error && error.message)}`);
        }
      }
    };
    const recoveryHasGitIndex = marker.exactGitIndex !== null && marker.exactGitIndex !== undefined;
    verifyRecoveryNodes(marker.protectedPaths, p.dirty, "protected path", {
      includeIndexEntries: marker.dirtyBefore !== null && marker.dirtyBefore !== undefined,
    });
    verifyRecoveryNodes(marker.exactCustody, p.exact, "exact-custody path", {
      includeIndexEntries: recoveryHasGitIndex,
    });
    if (marker.exactGitIndex !== null && marker.exactGitIndex !== undefined) {
      try {
        loadStored(p.gitIndex, marker.exactGitIndex.sha);
        const currentPath = gitIndexPath();
        if (currentPath !== marker.exactGitIndex.path) {
          unresolved.push(
            `active Git index path differs from ${marker.exactGitIndex.path}: ${currentPath}`,
          );
        } else if (!sameNodeState(treeNodeSnapshot(currentPath), marker.exactGitIndex)) {
          unresolved.push("active Git index file differs from its exact pre-phase bytes or mode");
        }
        const currentTree = treeOfIndexState(p, treeNodeSnapshot(currentPath), "recovery");
        if (currentTree !== marker.exactGitIndex.tree) {
          unresolved.push(
            `active Git index tree differs from ${marker.exactGitIndex.tree}: ${currentTree}`,
          );
        }
      } catch (error) {
        failures.push(`could not verify exact Git-index recovery: ${String(error && error.message)}`);
      }
    }
    if (Array.isArray(marker.exactArtifactPaths)) {
      try {
        const beforeArtifacts = new Set(marker.exactArtifactPaths);
        for (const rel of listExactBuildNodes(repoRoot)) {
          if (!beforeArtifacts.has(rel)) {
            unresolved.push(
              `new exact derived-state node ${rel} remains after the interrupted phase; ` +
                "it is not deleted because ownership is no longer provable",
            );
          }
        }
      } catch (error) {
        failures.push(`could not verify exact derived-state recovery: ${String(error && error.message)}`);
      }
    }

    // Generated files are NOT auto-reverted here, and that is the honest limit of a crash path.
    // During a live phase this runner is the only actor in the window, so a tracked file that went
    // dirty is provably its output. After a crash the window is unbounded — hours, a rebase, a
    // colleague — so there is no proof, and the rule is the same as for sources: report it, refuse,
    // let a human look. Untracked leftovers count too (round 2 #1): a file the crashed arm created
    // is still a file nobody has accounted for.
    const suspect = [];
    let dirtyNow = null;
    try { dirtyNow = gitDirtyPaths(repoRoot); } catch (e) { failures.push(String(e && e.message)); }
    const dirtyThen = marker.dirtyBefore == null ? null : new Map(marker.dirtyBefore);
    if (dirtyNow !== null && dirtyThen !== null) {
      const sourceRels = new Set((marker.sources ?? []).map((s) => s.rel));
      for (const [rel] of dirtyNow) {
        if (dirtyThen.has(rel) || sourceRels.has(rel)) continue;
        suspect.push(rel);
      }
    }

    // `git status` above is the LAST Git command in recovery. Verify the raw index only now, with
    // direct filesystem reads, so a stat-cache refresh can never occur after recovery is credited.
    if (recoveryHasGitIndex) {
      try {
        const finalIndex = treeNodeSnapshot(marker.exactGitIndex.path);
        if (!sameNodeState(finalIndex, marker.exactGitIndex)) {
          unresolved.push(
            "active Git index changed after the final recovery Git observation; preserving the marker",
          );
        }
      } catch (error) {
        failures.push(
          `could not perform final raw Git-index recovery verification: ${String(error && error.message)}`,
        );
      }
    }

    const clean = failures.length === 0 && unresolved.length === 0 &&
      artefacts.failures.length === 0 && suspect.length === 0;
    return {
      clean,
      entry: marker.entry ?? "<unknown>",
      startedAt: marker.startedAt ?? record.startedAt ?? "<unknown>",
      sources: restoredSources,
      artifacts: artefacts.restored,
      removed: artefacts.removed,
      unresolved, suspect,
      failures: [...failures, ...artefacts.failures],
    };
  };

  const readLockStrict = () => {
    let raw;
    try { raw = readFileNoFollow(lockPath); }
    catch (e) {
      if (e && e.code === "ENOENT") return null;
      throw new IncompleteSnapshotError(`the knockout lock at ${lockPath} cannot be read: ${String(e && e.message)}`);
    }
    let record;
    try { record = JSON.parse(raw.toString("utf8")); }
    catch (e) {
      throw new IncompleteSnapshotError(`the knockout lock at ${lockPath} is not valid JSON: ${String(e && e.message)}`);
    }
    if (
      record === null || typeof record !== "object" || Array.isArray(record) ||
      typeof record.nonce !== "string" || typeof record.runDir !== "string"
    ) {
      throw new IncompleteSnapshotError(`the knockout lock at ${lockPath} does not describe a run of ${repoRoot}`);
    }
    if (!isSafeRunNonce(record.nonce)) {
      throw new IncompleteSnapshotError(`the knockout lock at ${lockPath} has an unsafe run nonce`);
    }
    const expectedRunDir = path.join(cacheDir, "runs", record.nonce);
    if (record.runDir !== expectedRunDir) {
      throw new IncompleteSnapshotError(
        `the knockout lock at ${lockPath} names run directory ${record.runDir}, not ${expectedRunDir}`,
      );
    }
    const physicalCacheDir = fs.realpathSync(cacheDir);
    const projectedRunDir = projectedPhysicalPath(record.runDir);
    if (projectedRunDir === physicalCacheDir || !pathIsInside(projectedRunDir, physicalCacheDir)) {
      throw new IncompleteSnapshotError(
        `the knockout lock at ${lockPath} projects its run outside ${physicalCacheDir}: ${projectedRunDir}`,
      );
    }
    const rootState = recordRootState(record, { requireGeneration: record.version === 4 });
    if (rootState === ROOT_RECORD.MISMATCH) {
      throw new IncompleteSnapshotError(`the knockout lock at ${lockPath} does not describe a run of ${repoRoot}`);
    }
    let recoveryUnsafe = null;
    if (rootState === ROOT_RECORD.GENERATION_STALE) {
      recoveryUnsafe =
        `the lock generation ${JSON.stringify(record.rootGeneration)} does not match current ` +
        `${JSON.stringify(rootGeneration)}`;
    } else if (rootState === ROOT_RECORD.IDENTITY_STALE) {
      recoveryUnsafe =
        `the lock identity ${JSON.stringify(record.rootIdentity)} is stale although its lexical root ` +
        `still resolves to this repository (${rootIdentity})`;
    } else if ((usesDefaultCache && record.version !== 4) || ![3, 4].includes(record.version)) {
      recoveryUnsafe =
        `the lock protocol version ${JSON.stringify(record.version)} cannot bind v4 recovery bytes`;
    }
    return { record, recoveryUnsafe };
  };

  /** Create the lock with O_EXCL, or say who holds it. Nothing shared is written before this wins. */
  const tryTakeLock = () => {
    const nonce = crypto.randomBytes(12).toString("hex");
    const probe = probeProcess(process.pid);
    const record = {
      version: 4, root: repoRoot, rootIdentity, rootGeneration, nonce, pid: process.pid,
      identity: probe.identity, identityAvailable: probe.identity !== null,
      startedAt: new Date().toISOString(),
      runDir: path.join(cacheDir, "runs", nonce),
    };
    // The shared root and exact deterministic child are proven real, uid-owned and private BEFORE
    // the first byte is written. This rejects a planted child symlink or permissive old directory.
    if (usesDefaultCache) {
      ensurePrivateDir(privateFallbackRoot());
      ensurePrivateDir(cacheDir);
      ensureOwnedDir(path.join(cacheDir, "runs"));
    } else {
      fs.mkdirSync(cacheDir, { recursive: true });
      fs.mkdirSync(path.join(cacheDir, "runs"), { recursive: true });
    }
    let fd;
    try { fd = fs.openSync(lockPath, "wx", usesDefaultCache ? 0o600 : 0o644); }
    catch (e) {
      if (e && e.code === "EEXIST") return null;
      throw new IncompleteSnapshotError(`cannot create the knockout lock at ${lockPath}: ${String(e && e.message)}`);
    }
    try { fs.writeSync(fd, JSON.stringify(record)); } finally { fs.closeSync(fd); }
    try {
      if (usesDefaultCache) ensureOwnedDir(record.runDir);
      else fs.mkdirSync(record.runDir);
    } catch (error) {
      try { removeVerified(lockPath, "the ownerless knockout lock"); }
      catch (cleanupError) {
        throw new IncompleteSnapshotError(
          `the knockout run directory could not be created (${String(error && error.message)}), and ` +
            `its ownerless lock could not be removed (${String(cleanupError && cleanupError.message)})`,
        );
      }
      if (error instanceof IncompleteSnapshotError) throw error;
      throw new IncompleteSnapshotError(
        `cannot create the knockout run directory at ${record.runDir}: ${String(error && error.message)}`,
      );
    }
    return record;
  };

  /** Memoise every terminal start state with the scan warnings that led to it. */
  const finishStart = (result) => {
    started = { ...result, warnings: legacyScanWarnings };
    return started;
  };

  const guard = {
    cacheDir,
    lockPath,
    rootIdentity,
    rootGeneration,
    protectedRoots: Object.freeze([...evidenceRootPaths]),
    protectedRootIdentities: Object.freeze(evidenceRoots.map((entry) => entry.identity)),
    get legacyCacheDirs() { return Object.freeze([...discoveredLegacyCacheDirs()]); },
    get legacyScanWarnings() { return legacyScanWarnings; },
    get ownerNonce() { return owner === null ? null : owner.nonce; },

    /**
     * Take the lock, or refuse. Memoised: the result of the first call is the state of this run.
     *   { ok: true, recovered? }        — this run owns the tree
     *   { ok: false, kind: "held" }     — another run owns it, or might (UNKNOWN counts as held)
     *   { ok: false, kind: "unrepaired" } — a dead run's leftovers could not be proven clean
     *   { ok: false, kind: "corrupt" }  — the lock or its metadata could not be read
     */
    start() {
      if (started !== null) return started;
      try {
        if (usesDefaultCache) {
          try { installLegacyTombstones(); }
          catch (error) {
            if (!(error instanceof IncompleteSnapshotError)) throw error;
            return finishStart({
              ok: false,
              kind: "legacy",
              detail: String(error.message),
              lockPath,
            });
          }
        }
        let taken = tryTakeLock();
        let recovered = null;
        if (taken === null) {
          const locked = readLockStrict();
          if (locked === null) {
            taken = tryTakeLock();          // it vanished between the failed create and the read
            if (taken === null) {
              return finishStart({
                ok: false, kind: "held", detail: "the lock is being contended right now", lockPath,
              });
            }
          } else {
            const { record, recoveryUnsafe } = locked;
            const state = classifyHolder(record, probeProcess(record.pid));
            if (state === "LIVE" || state === "UNKNOWN" || state === "SELF") {
              return finishStart({
                ok: false, kind: "held", pid: record.pid, startedAt: record.startedAt, lockPath,
                certainty: state === "UNKNOWN" ? "indeterminate" : "live",
                recoveryUnsafe,
                detail: (
                  state === "UNKNOWN"
                    ? `a run recorded as pid ${record.pid} may still be alive — this machine would not confirm either way`
                    : `pid ${record.pid} is running`
                ) + (recoveryUnsafe === null ? "" : `; ${recoveryUnsafe}`),
              });
            }
            if (recoveryUnsafe !== null) {
              return finishStart({
                ok: false,
                kind: "corrupt",
                detail:
                  `${recoveryUnsafe}; recorded holder pid ${record.pid} is not live, but these ` +
                  `recovery bytes cannot be applied to the current directory generation`,
                lockPath,
              });
            }
            recovered = repairDeadRun(record);
            if (!recovered.clean) {
              return finishStart({ ok: false, kind: "unrepaired", lockPath, recovered });
            }
            removeVerified(path.join(record.runDir, "inflight.json"), "the interrupted run's marker");
            removeVerified(lockPath, "the dead run's lock");
            taken = tryTakeLock();
            if (taken === null) {
              return finishStart({
                ok: false, kind: "held", detail: "another run took the lock during recovery", lockPath,
              });
            }
          }
        }
        owner = taken;
        index = new Map();
        return finishStart({ ok: true, recovered });
      } catch (e) {
        if (!(e instanceof IncompleteSnapshotError)) throw e;
        return finishStart({ ok: false, kind: "corrupt", detail: String(e.message), lockPath });
      }
    },

    /**
     * Snapshot everything this phase can change, and record on disk what it would take to undo it
     * if this process never reaches its `finally`.
     *
     * @param {object} o
     * @param {string} o.label           what the marker will call this phase
     * @param {Array}  [o.sources]       [rel, pristineBytes, mutantBytes] for an arm's mutations
     * @param {boolean}[o.artifacts]     false for a phase that cannot leave a mutant build
     * @param {"all"|"dirty-only"} [o.tracked]
     * @param {Array|null} [o.exactCustodyPaths] exact source nodes for a post-restore observation
     * @param {boolean} [o.exactGitIndex] preserve the complete index file and write-tree identity
     */
    beginPhase({
      label,
      sources = [],
      artifacts = true,
      tracked = "all",
      exactCustodyPaths = null,
      exactGitIndex = false,
    }) {
      const state = guard.start();
      if (!state.ok) {
        throw new IncompleteSnapshotError(
          state.kind === "held"
            ? `another knockout run holds this tree (${state.detail})`
            : state.kind === "unrepaired"
              ? `a previous run's leftovers could not be repaired; see ${lockPath}`
              : state.kind === "legacy"
                ? state.detail
              : `the knockout lock could not be read: ${state.detail}`,
        );
      }
      const clock = Date.now();
      const p = runPathsOf();

      if (!Array.isArray(sources)) {
        throw new IncompleteSnapshotError("phase sources must be an array");
      }
      if (exactCustodyPaths !== null && !Array.isArray(exactCustodyPaths)) {
        throw new IncompleteSnapshotError("exact custody paths must be null or an array");
      }
      if (typeof exactGitIndex !== "boolean") {
        throw new IncompleteSnapshotError("exact Git-index custody selector must be boolean");
      }
      for (const source of sources) {
        if (!Array.isArray(source) || source.length !== 3) {
          throw new IncompleteSnapshotError("each phase source must contain path, pristine bytes, and mutant bytes");
        }
        recordedRepoFile(source[0], "phase source path");
      }

      const mutationSourceStates = assertSafeMutationSources(sources);

      const unsupported = unsupportedArtifactRoots(repoRoot, typescriptProjectDirs(repoRoot));
      if (unsupported.length > 0) {
        throw new IncompleteSnapshotError(`unsupported artifact root — ${unsupported.join("; ")}`);
      }

      // The restore authority is the raw index that existed at phase entry. Capture it BEFORE
      // `git status` or any other guard setup can refresh stat-cache bytes. Semantic tree derivation
      // runs against a private copy, so taking the snapshot cannot itself modify the live index.
      const exactIndex = exactGitIndex
        ? snapshotExactGitIndex(p, { store: true, label: "phase-entry" })
        : null;
      fs.mkdirSync(p.sources, { recursive: true });
      if (artifacts) syncStore(p); else saveIndex(p);
      const dirtyBefore = gitDirtyPaths(repoRoot);
      const targets = new Set(sources.map(([rel]) => rel));
      const protectedPaths = snapshotProtected(p, dirtyBefore, targets);
      const artifactPathsBefore = exactCustodyPaths === null || !artifacts
        ? [] : listExactBuildNodes(repoRoot);
      const protectedPathSet = new Set(protectedPaths.map((record) => record.rel));
      const exactPaths = exactCustodyPaths === null
        ? []
        : [
            ...exactCustodyPaths,
            ...artifactPathsBefore,
            ...(dirtyBefore === null
              ? [] : [...dirtyBefore].filter(([, code]) => code !== "??").map(([rel]) => rel)),
          ].filter((rel) => !protectedPathSet.has(rel) && !targets.has(rel));
      // Mutation targets have their own stricter pristine/mutant restore protocol. They must never
      // acquire a second, unconditional exact-custody restore authority: when Git status is
      // unavailable there is no protected-path record to filter them indirectly, and that second
      // authority would overwrite a concurrent user edit after the source restorer refused it.
      // A post-restore observation has no mutation sources (`targets` is empty), so its requested
      // exact source custody remains intact.
      const exactCustody = exactCustodyPaths === null
        ? [] : snapshotExactCustody(p, exactPaths, { includeIndexEntries: exactGitIndex });
      // A second in-memory baseline separates observer writes from any metadata refresh caused by
      // the guard's own setup. The durable marker retains the phase-entry bytes as restore
      // authority; no observation starts until both snapshots and the marker exist.
      const exactIndexObservation = exactGitIndex
        ? snapshotExactGitIndex(p, { store: false, label: "observation-baseline" })
        : null;

      const marker = {
        version: 4, root: repoRoot, rootIdentity, rootGeneration, nonce: owner.nonce, pid: owner.pid,
        identity: owner.identity, identityAvailable: owner.identityAvailable,
        entry: label, startedAt: new Date().toISOString(),
        artifacts, tracked,
        dirtyBefore: dirtyBefore === null ? null : [...dirtyBefore],
        exactCustody: exactCustody.map((record) => ({ ...record })),
        exactGitIndex: exactIndex === null ? null : { ...exactIndex },
        exactArtifactPaths: artifactPathsBefore,
        protectedPaths: protectedPaths.map((record) => ({ ...record })),
        sources: [],
      };
      let n = 0;
      for (const [rel, pristineBytes, mutantBytes] of sources) {
        const store = `s${n++}`;
        const digest = digestOfBytes(Buffer.from(pristineBytes));
        storeBytes(path.join(p.sources, store), Buffer.from(pristineBytes), digest);
        marker.sources.push({ rel, store, pristineSha: digest, mutantSha: sha(mutantBytes) });
      }
      writeFileNoFollow(p.marker, Buffer.from(JSON.stringify(marker)));
      // The guard's OWN cost, so the sweep can report what this protection actually charges. It
      // must never include the suite run that happens between the two halves.
      armed = {
        artifactPathsBefore,
        artifacts,
        dirtyBefore,
        exactCustody,
        exactIndex,
        exactIndexObservation,
        label,
        ms: Date.now() - clock,
        mutationSourceStates,
        protectedPaths,
        sources: marker.sources.map((source) => ({ ...source })),
        targets,
        tracked,
      };
      return true;
    },

    /** Put the derived state back. Safe to call when no phase is in flight. */
    endPhase({ preservedConcurrentSources = [] } = {}) {
      if (armed === null) return null;
      const {
        artifactPathsBefore, artifacts, dirtyBefore, exactCustody, exactIndex,
        exactIndexObservation,
        protectedPaths, sources, tracked, ms,
      } = armed;
      if (!Array.isArray(preservedConcurrentSources)) {
        throw new IncompleteSnapshotError("preserved concurrent sources must be an array");
      }
      const sourceByRel = new Map(sources.map((source) => [source.rel, source]));
      const preservedSourceMap = new Map();
      for (const observation of preservedConcurrentSources) {
        if (
          !exactKeys(observation, ["identity", "nlink", "rel", "sha256"]) ||
          typeof observation.identity !== "string" || !/^\d+:\d+$/.test(observation.identity) ||
          !Number.isSafeInteger(observation.nlink) || observation.nlink < 1 ||
          !HEX_64_RE.test(observation.sha256)
        ) {
          throw new IncompleteSnapshotError(
            "each preserved concurrent source must contain exact inode identity, link count, rel, and lowercase sha256",
          );
        }
        recordedRepoFile(observation.rel, "preserved concurrent source path");
        const source = sourceByRel.get(observation.rel);
        if (source === undefined) {
          throw new IncompleteSnapshotError(
            `preserved concurrent source ${observation.rel} is not a target of this phase`,
          );
        }
        if (observation.sha256 === source.pristineSha || observation.sha256 === source.mutantSha) {
          throw new IncompleteSnapshotError(
            `preserved concurrent source ${observation.rel} is not distinct from this arm's source states`,
          );
        }
        if (preservedSourceMap.has(observation.rel)) {
          throw new IncompleteSnapshotError(
            `preserved concurrent source ${observation.rel} was observed more than once`,
          );
        }
        preservedSourceMap.set(observation.rel, Object.freeze({ ...observation }));
      }
      armed = null;
      const clock = Date.now();
      const p = runPathsOf();
      let exactIndexObserved = null;
      const exactIndexObservationFailures = [];
      if (exactIndex !== null) {
        try {
          // Observe before restoring any tracked path. `restoreTracked` can repair individual
          // entries, so waiting until afterwards would erase proof that the suite staged data.
          exactIndexObserved = snapshotExactGitIndex(p, {
            store: false,
            label: "phase-end-observed",
          });
        } catch (error) {
          exactIndexObservationFailures.push(
            `could not snapshot the phase-end Git index before restoration: ${String(error && error.message)}`,
          );
        }
      }
      // Transfer exact source custody BEFORE the first derived/tracked cleanup write. When a source
      // has acquired another hardlink, no path under cleanup may be allowed to truncate or delete
      // that shared inode; the whole cleanup remains recoverable behind the durable marker.
      const sourceCustodyFailures = [];
      const sourceStatesBeforeCleanup = new Map();
      const protectedSourceIdentities = new Set();
      for (const source of sources) {
        try {
          const current = treeNodeSnapshot(path.join(repoRoot, source.rel));
          if (current.kind !== "file") {
            sourceCustodyFailures.push(
              `${source.rel} is ${current.kind}, not a regular source file; refusing all cleanup`,
            );
            continue;
          }
          const preserved = preservedSourceMap.get(source.rel);
          if (preserved === undefined) {
            if (current.sha !== source.pristineSha) {
              sourceCustodyFailures.push(
                `${source.rel} is not pristine and has no transferred concurrent-byte custody; refusing all cleanup`,
              );
              continue;
            }
          } else if (
            current.sha !== preserved.sha256 || current.identity !== preserved.identity ||
            current.nlink !== preserved.nlink
          ) {
            sourceCustodyFailures.push(
              `${source.rel} changed after its concurrent source observation; refusing all cleanup`,
            );
            continue;
          }
          if (current.nlink !== 1) {
            sourceCustodyFailures.push(
              `${source.rel} has ${current.nlink} hardlinks; refusing cleanup through a source alias`,
            );
            continue;
          }
          if (protectedSourceIdentities.has(current.identity)) {
            sourceCustodyFailures.push(
              `${source.rel} shares its inode with another mutation target; refusing all cleanup`,
            );
            continue;
          }
          protectedSourceIdentities.add(current.identity);
          sourceStatesBeforeCleanup.set(source.rel, current);
        } catch (error) {
          sourceCustodyFailures.push(
            `could not transfer cleanup custody for ${source.rel}: ${String(error && error.message)}`,
          );
        }
      }
      const cleanupAllowed = sourceCustodyFailures.length === 0 &&
        exactIndexObservationFailures.length === 0;
      const artefacts = cleanupAllowed && artifacts
        ? restoreStore(p, protectedSourceIdentities)
        : { restored: [], removed: [], failures: [] };
      const trackedResult = cleanupAllowed
        ? restoreTracked(
            dirtyBefore,
            protectedPaths,
            tracked,
            preservedSourceMap,
            protectedSourceIdentities,
          )
        : { additions: [], failures: [], preserved: [], reverted: [] };
      const exactResult = !cleanupAllowed || exactCustody.length === 0
        ? { additions: [], failures: [], restored: [] }
        : restoreExactCustody(
            p,
            exactCustody,
            artifactPathsBefore,
            {
              restoreIndexEntries: exactIndex !== null,
              protectedIdentities: protectedSourceIdentities,
            },
          );
      const exactIndexResult = exactIndex === null
        ? {
            changed: false, failures: [], hashAfter: null, hashBefore: null, hashObserved: null,
            observationChanged: false, semanticChanged: false, treeAfter: null, treeBefore: null,
            treeObserved: null,
          }
        : cleanupAllowed
          ? restoreExactGitIndex(
              p,
              exactIndex,
              exactIndexObservation,
              exactIndexObserved,
              protectedSourceIdentities,
            )
          : {
              changed: false, failures: [], hashAfter: null, hashBefore: exactIndex.sha,
              hashObserved: exactIndexObserved?.sha ?? null, observationChanged: true,
              semanticChanged: true, treeAfter: null, treeBefore: exactIndex.tree,
              treeObserved: exactIndexObserved?.tree ?? null,
            };
      const sourcePostCleanupFailures = [];
      for (const [rel, beforeCleanup] of sourceStatesBeforeCleanup) {
        try {
          const afterCleanup = treeNodeSnapshot(path.join(repoRoot, rel));
          if (
            afterCleanup.kind !== "file" || afterCleanup.identity !== beforeCleanup.identity ||
            afterCleanup.nlink !== 1 || afterCleanup.sha !== beforeCleanup.sha
          ) {
            sourcePostCleanupFailures.push(
              `${rel} changed during cleanup; refusing to clear recovery custody`,
            );
          }
        } catch (error) {
          sourcePostCleanupFailures.push(
            `could not revalidate ${rel} after cleanup: ${String(error && error.message)}`,
          );
        }
      }
      // This direct byte/mode check is deliberately AFTER the last Git command above. No later Git
      // observation may refresh the live index after exact custody has been proved.
      const finalExactIndexFailures = [];
      if (exactIndex !== null) {
        try {
          const finalIndex = treeNodeSnapshot(exactIndex.path);
          if (!sameNodeState(finalIndex, exactIndex)) {
            finalExactIndexFailures.push(
              "active Git index changed after its final Git observation; refusing to clear recovery custody",
            );
          }
        } catch (error) {
          finalExactIndexFailures.push(
            `could not perform final raw Git-index verification: ${String(error && error.message)}`,
          );
        }
      }
      // Round 2 #1: an untracked leftover is a failure HERE, not a finding the caller derives
      // later — otherwise the marker clears while the tree still holds a file nobody accounted for.
      const failures = [
        ...sourceCustodyFailures,
        ...artefacts.failures,
        ...trackedResult.failures,
        ...exactResult.failures,
        ...exactIndexObservationFailures,
        ...exactIndexResult.failures,
        ...sourcePostCleanupFailures,
        ...finalExactIndexFailures,
        ...[...preservedSourceMap.keys()]
          .filter((rel) => !trackedResult.preserved.includes(rel))
          .map((rel) =>
            `${rel} changed after its concurrent source bytes were observed; refusing to claim custody`),
        ...trackedResult.additions.map((rel) =>
          `${rel} was created by this phase and git does not track it; this runner does not remove a ` +
          `file it cannot prove it created, so the tree is NOT as the phase found it`),
        ...exactResult.additions.map((rel) =>
          `${rel} is a new exact derived-state node; it is left in place because this runner does ` +
            "not delete an unproven symbolic link or unknown user data"),
      ];
      if (failures.length === 0) {
        // Only the recorded owner may remove its own marker (round 2 #3).
        try {
          const marker = readMarkerStrict(p);
          if (marker !== null && marker.nonce !== owner.nonce) {
            failures.push(`the in-flight marker belongs to run ${marker.nonce}, not to this one`);
          } else if (marker !== null) {
            removeVerified(p.marker, "this run's marker");
          }
        } catch (e) { failures.push(String(e && e.message)); }
      }
      return {
        artifactsRestored: artefacts.restored,
        artifactsRemoved: artefacts.removed,
        exactCustodyRestored: exactResult.restored,
        exactCustodyAdditions: exactResult.additions,
        exactGitIndexChanged: exactIndexResult.changed,
        exactGitIndexHashBefore: exactIndexResult.hashBefore,
        exactGitIndexHashAfter: exactIndexResult.hashAfter,
        exactGitIndexHashObserved: exactIndexResult.hashObserved,
        exactGitIndexObservationChanged: exactIndexResult.observationChanged,
        exactGitIndexSemanticChanged: exactIndexResult.semanticChanged,
        exactGitIndexTreeBefore: exactIndexResult.treeBefore,
        exactGitIndexTreeAfter: exactIndexResult.treeAfter,
        exactGitIndexTreeObserved: exactIndexResult.treeObserved,
        trackedReverted: trackedResult.reverted,
        concurrentSourcesPreserved: trackedResult.preserved,
        untrackedAdditions: trackedResult.additions,
        failures,
        ms: ms + (Date.now() - clock),
      };
    },

    /** An arm is a phase that mutates sources and can leave a mutant build. */
    beginArm({ entryId, sources }) {
      const workTreeState = gitWorkTreeState(repoRoot);
      if (workTreeState === "unknown") {
        throw new IncompleteSnapshotError("cannot determine Git worktree state before arming a knockout");
      }
      return guard.beginPhase({
        label: entryId,
        sources,
        exactCustodyPaths: sources.map(([rel]) => rel),
        exactGitIndex: workTreeState === "yes",
      });
    },
    endArm(options = {}) { return guard.endPhase(options); },

    /**
     * Retire crash-recovery authority for a deliberately retained disposable mutant arm.
     *
     * This is not a generic "forget the marker" escape hatch. The current lock and marker must
     * still belong to this exact run; the marker must describe the in-memory arm byte-for-byte;
     * and every source must still be the same inode, mode, single-link shape, and exact mutant
     * digest observed when the arm was admitted. Any mismatch leaves both marker and lock intact
     * so a later process cannot silently treat an unproved arm as committed evidence.
     */
    commitRetainedArm() {
      if (owner === null || armed === null || armed.sources.length === 0) {
        throw new IncompleteSnapshotError("no active mutated arm can be committed as retained evidence");
      }
      const p = runPathsOf();
      const locked = readLockStrict();
      if (
        locked === null || locked.recoveryUnsafe !== null ||
        locked.record.nonce !== owner.nonce || locked.record.runDir !== owner.runDir
      ) {
        throw new IncompleteSnapshotError("the retained arm lock no longer belongs to this exact run");
      }
      const marker = readMarkerStrict(p);
      if (marker === null || marker.nonce !== owner.nonce || marker.entry !== armed.label) {
        throw new IncompleteSnapshotError("the retained arm marker no longer belongs to this exact arm");
      }
      if (marker.sources.length !== armed.sources.length) {
        throw new IncompleteSnapshotError("the retained arm marker names a different source set");
      }
      for (let index = 0; index < armed.sources.length; index += 1) {
        const expected = armed.sources[index];
        const recorded = marker.sources[index];
        if (
          !exactKeys(recorded, ["mutantSha", "pristineSha", "rel", "store"]) ||
          !canonicalJsonBytes(recorded).equals(canonicalJsonBytes(expected))
        ) {
          throw new IncompleteSnapshotError("the retained arm marker source record changed");
        }
        loadStored(path.join(p.sources, recorded.store), recorded.pristineSha);
        const admitted = armed.mutationSourceStates.get(recorded.rel);
        const current = treeNodeSnapshot(path.join(repoRoot, recorded.rel));
        if (
          admitted === undefined || current.kind !== "file" || current.nlink !== 1 ||
          admitted.nlink !== 1 || current.identity !== admitted.identity ||
          current.mode !== admitted.mode || current.sha !== recorded.mutantSha ||
          admitted.pristineSha !== recorded.pristineSha
        ) {
          throw new IncompleteSnapshotError(
            `${recorded.rel} is not the exact retained single-link mutant inode admitted by this arm`,
          );
        }
      }
      const markerObservation = observeFileNoFollow(p.marker);
      if (markerObservation === null || markerObservation.nlink !== 1) {
        throw new IncompleteSnapshotError("the retained arm marker is absent or hardlinked");
      }
      let observedMarker;
      try { observedMarker = JSON.parse(markerObservation.bytes.toString("utf8")); }
      catch (error) {
        throw new IncompleteSnapshotError(
          `the retained arm marker changed before commit: ${String(error && error.message)}`,
        );
      }
      if (!canonicalJsonBytes(observedMarker).equals(canonicalJsonBytes(marker))) {
        throw new IncompleteSnapshotError("the retained arm marker changed before commit");
      }
      const atPath = fs.lstatSync(p.marker, { bigint: true });
      if (!atPath.isFile() || fileIdentity(atPath) !== markerObservation.identity) {
        throw new IncompleteSnapshotError("the retained arm marker changed before its approved removal");
      }
      fs.unlinkSync(p.marker);
      if (fs.existsSync(p.marker)) {
        throw new IncompleteSnapshotError("the retained arm marker still exists after approved removal");
      }
      armed = null;
      return true;
    },

    /**
     * Drop the lock — but ONLY if this run left nothing behind. A surviving in-flight marker means
     * a phase could not return the tree, and the lock is what makes the NEXT run find that marker
     * instead of starting on top of it. Releasing there would throw away the record of the damage.
     */
    release() {
      if (owner === null) return false;
      let released = false;
      try {
        const locked = readLockStrict();
        if (
          locked !== null && locked.recoveryUnsafe === null &&
          locked.record.nonce === owner.nonce && !fs.existsSync(runPathsOf().marker)
        ) {
          fs.rmSync(owner.runDir, { recursive: true, force: true });
          removeVerified(lockPath, "this run's lock");
          // Keep deterministic directory shells. Even a non-recursive rmdir after lock removal can
          // race a contender between its ensurePrivateDir() and open(lock), causing a spurious ENOENT.
          released = true;
        }
      } catch { /* a lock we cannot read is not ours to remove */ }
      owner = null;
      started = null;
      return released;
    },
  };
  return guard;
}

/** One guard per repository root, so a single run holds a single lock. */
const GUARDS = new Map();
export function buildStateGuardFor(root, options = {}) {
  if (options === null || typeof options !== "object" || Array.isArray(options)) {
    throw new IncompleteSnapshotError("buildStateGuardFor options must be an object");
  }
  for (const key of Object.keys(options)) {
    if (key !== "protectedRoots") {
      throw new IncompleteSnapshotError(`unknown buildStateGuardFor option ${JSON.stringify(key)}`);
    }
  }
  const { protectedRoots = [] } = options;
  // Path strings are not identities: macOS exposes the same directory through /Users and the
  // /System/Volumes/Data firmlink, and parent symlinks can do the same elsewhere. Key the in-process
  // singleton by the opened directory's stable device/inode identity, exactly like the external
  // lock. A separate birth-time generation binds recovery bytes without selecting the lock path.
  const resolvedRoot = path.resolve(root);
  const requestedEvidenceRoots = protectedEvidenceRoots(resolvedRoot, protectedRoots);
  const requested = openedDirectoryDescriptor(resolvedRoot);
  const key = requested.identity;
  let cached = GUARDS.get(key);
  if (cached !== undefined) {
    let current = null;
    let currentError = null;
    try { current = openedDirectoryDescriptor(cached.root); }
    catch (error) {
      if (!(error instanceof IncompleteSnapshotError)) throw error;
      currentError = error;
    }
    const bindingChanged = current === null || current.identity !== key ||
      current.generation !== cached.guard.rootGeneration;
    if (bindingChanged) {
      const detail = currentError === null
        ? `cached root now describes ${current.identity}, ${current.generation}`
        : currentError.message;
      if (cached.guard.ownerNonce !== null) {
        throw new IncompleteSnapshotError(
          `the active knockout guard for ${cached.root} no longer describes the requested ` +
            `repository root ${resolvedRoot}: ${detail}`,
        );
      }
      // An ownerless guard has no recovery authority to preserve. Rebuild it from the descriptor
      // that was just opened instead of returning a stale object for an inode-reused directory.
      GUARDS.delete(key);
      cached = undefined;
    }
  }
  if (cached === undefined) {
    const guard = createBuildStateGuard({ root: resolvedRoot, protectedRoots });
    if (guard.rootIdentity !== key || guard.rootGeneration !== requested.generation) {
      throw new IncompleteSnapshotError(`repository root changed while constructing its guard: ${root}`);
    }
    cached = Object.freeze({ guard, root: resolvedRoot });
    GUARDS.set(key, cached);
  } else {
    const existing = new Set(cached.guard.protectedRootIdentities);
    const missing = requestedEvidenceRoots.filter((entry) => !existing.has(entry.identity));
    if (missing.length > 0) {
      throw new IncompleteSnapshotError(
        `the existing knockout guard for ${path.resolve(root)} does not protect requested evidence ` +
          `root(s): ${missing.map((entry) => entry.path).join(", ")}`,
      );
    }
  }
  return cached.guard;
}

/**
 * Extract failing test names only from a completed, versioned TestsStream reporter protocol.
 * Presentation output (`✖`, TAP `not ok`, stdout/stderr) is untrusted and is never parsed. The
 * protocol must finish before any FAIL event can enter a knockout's failure-set comparison.
 */
export function failureEventIdentity(event) {
  if (
    event === null || typeof event !== "object" || typeof event.name !== "string" ||
    typeof event.file !== "string" || !Number.isInteger(event.line) || event.line < 1 ||
    !Number.isInteger(event.column) || event.column < 1
  ) return null;
  let file;
  try { file = fs.realpathSync(event.file); }
  catch { file = path.resolve(event.file); }
  return JSON.stringify([event.name, file, event.line, event.column]);
}

/** Preserve the exact authenticated authored-site identity of every completed test failure. */
export function failingTestEvents(output) {
  const parsed = parseProofEvents(output);
  const failures = [];
  if (!parsed.protocolComplete) return failures;
  for (const event of parsed.events) {
    if (
      event.event === "fail" && event.suite === false &&
      event.fileFailure === false && event.skipped === false && event.todo === false
    ) {
      const identity = failureEventIdentity(event);
      if (identity !== null) {
        failures.push(Object.freeze({
          name: event.name,
          file: JSON.parse(identity)[1],
          line: event.line,
          column: event.column,
        }));
      }
    }
  }
  return failures;
}

/** Multiset subtraction: duplicate names at different authored sites remain independent evidence. */
export function newFailureEventsBeyondBaseline(current, baseline = []) {
  const counts = new Map();
  for (const event of baseline) {
    const identity = failureEventIdentity(event);
    if (identity !== null) counts.set(identity, (counts.get(identity) ?? 0) + 1);
  }
  const added = [];
  for (const event of current) {
    const identity = failureEventIdentity(event);
    if (identity === null) continue;
    const remaining = counts.get(identity) ?? 0;
    if (remaining > 0) counts.set(identity, remaining - 1);
    else added.push(event);
  }
  return added;
}

/** True only when authenticated failure identity equals one exact statically authored proof site. */
export function hasFailureAtExpectedSite(failures, expectedSites) {
  const expected = new Set(
    expectedSites.map((site) => failureEventIdentity(site)).filter((identity) => identity !== null),
  );
  return failures.some((event) => expected.has(failureEventIdentity(event)));
}

function namedProofIdsFor(entry) {
  const ids = [];
  for (const match of entry.control.matchAll(/\[proof:\s*([^\]]+)\]/g)) {
    ids.push(...match[1].split(",").map((value) => value.trim()).filter(Boolean));
  }
  return [...new Set(ids)];
}

/**
 * Bind a detector verdict to the exact proof body executed inside the disposable arm. The root is
 * explicit so a supervisor can never accidentally resolve compiled proof sites from the live
 * source while scoring a mutant that ran elsewhere.
 */
export function requireNamedProofFailuresAtRoot(root, proofInventory, entry, result) {
  const ids = namedProofIdsFor(entry);
  if (ids.length === 0) return { ...result };
  const next = { ...result };
  const missing = ids.filter((id) => {
    const proof = proofInventory?.[id];
    if (
      proof === null || typeof proof !== "object" || typeof proof.file !== "string" ||
      typeof proof.marker !== "string" || !Array.isArray(next.newFailureEvents)
    ) return true;
    const executedFile = executedProofFileFor(root, proof.file);
    if (executedFile === null || !fs.existsSync(executedFile)) return true;
    const resolved = resolveProof(executedFile, proof.marker);
    if (resolved.status !== "live") return true;
    return !hasFailureAtExpectedSite(
      next.newFailureEvents,
      resolved.sites.filter((site) => site.status === "live"),
    );
  });
  if (missing.length === 0) {
    next.detail = `${next.detail}; named proof(s) went RED: ${ids.join(", ")}`;
    return next;
  }
  if (next.verdict === VERDICT.DETECTOR_TRIGGERED) next.verdict = VERDICT.ANTI_VACUITY_FAILED;
  next.detail = `${next.detail} Named proof(s) did not go RED: ${missing.join(", ")}. ` +
    "A different new failure cannot certify that these proof bodies measure the mutated control.";
  return next;
}

export function failingTestIds(output) {
  const ids = new Set();
  for (const event of failingTestEvents(output)) ids.add(event.name);
  return ids;
}

/** Did a non-empty `node:test` run complete the versioned structured reporter protocol? */
export function suiteEmittedTestMarkers(output) {
  const parsed = parseProofEvents(output);
  return parsed.protocolComplete && parsed.events.some((event) =>
    (event.event === "pass" || event.event === "fail") &&
    event.suite === false && event.fileFailure === false
  );
}

/**
 * Run a suite and return a structured observation. NEVER returns a bare boolean — the caller must
 * be able to tell a timeout from a failure from a crash.
 */
const KNOCKOUT_TEST_OBSERVER = fileURLToPath(
  new URL("./knockout-test-observer.mjs", import.meta.url),
);

// A process group is not a containment boundary: setsid(2), including Node's `detached: true`,
// creates a new group that a negative-PGID kill cannot reach. The complete observer therefore runs
// as PID 1 in a disposable Linux namespace. Docker does not return from `run --rm` until that
// namespace is gone, so source restoration cannot race a delayed writer. Digests pin the exact
// multi-architecture Docker Official Image manifests; mutable tags are not accepted as evidence.
const KNOCKOUT_NODE_IMAGES = Object.freeze({
  20: "docker.io/library/node@sha256:8f693eaa7e0a8e71560c9a82b55fd54c2ae920a2ba5d2cde28bac7d1c01c9ba5",
  22: "docker.io/library/node@sha256:62e4daa6819762bbd3072af77cc282ab72c631c4aed30dd7980192babaf385b3",
  24: "docker.io/library/node@sha256:934240a162082fd8b8a2f90cd5114446443f1eba1c5378f6687167ca405e6584",
});

// Docker is part of the evidence TCB, so a bare command name is not an acceptable way to select
// it. In particular, the closed gate environment deliberately removes the ambient PATH; on macOS
// that made the knockout selftest lose Docker at /usr/local/bin, start from a red baseline, and
// still receive credit because the gate classifier did not require a green baseline. Fixed
// absolute installation points preserve macOS/Linux availability without admitting an entire
// user-writable bin directory into every evidence child.
const FIXED_DOCKER_CLI_CANDIDATES = Object.freeze(process.platform === "win32"
  ? ["C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe"]
  : [
      "/usr/bin/docker",
      "/usr/local/bin/docker",
      "/opt/homebrew/bin/docker",
      "/Applications/Docker.app/Contents/Resources/bin/docker",
      "/snap/bin/docker",
    ]);

export function fixedDockerExecutable(candidates = FIXED_DOCKER_CLI_CANDIDATES) {
  if (!Array.isArray(candidates) || candidates.length === 0) {
    throw new Error("Docker evidence requires at least one fixed executable candidate");
  }
  for (const candidate of candidates) {
    if (typeof candidate !== "string" || !path.isAbsolute(candidate)) {
      throw new Error(`Docker evidence executable candidate must be absolute: ${JSON.stringify(candidate)}`);
    }
    try { fs.lstatSync(candidate); }
    catch (error) {
      if (error?.code === "ENOENT") continue;
      throw new Error(`cannot inspect fixed Docker evidence executable ${candidate}: ${String(error && error.message)}`);
    }
    let resolved;
    try {
      resolved = fs.realpathSync(candidate);
      const target = fs.statSync(resolved);
      if (!target.isFile()) {
        throw new Error(`${candidate} resolves to a non-regular object`);
      }
      fs.accessSync(resolved, fs.constants.X_OK);
    } catch (error) {
      throw new Error(`fixed Docker evidence executable ${candidate} is unusable: ${String(error && error.message)}`);
    }
    // Resolve and validate on every call. This closes ambient PATH selection; it does not claim an
    // atomic defence against an account that can replace the installed Docker binary itself.
    return resolved;
  }
  throw new Error(
    `Docker evidence executable is absent from fixed candidates: ${candidates.join(", ")}`,
  );
}

function knockoutEvidenceImage() {
  const major = Number.parseInt(process.versions.node.split(".", 1)[0], 10);
  const image = KNOCKOUT_NODE_IMAGES[major];
  if (image === undefined) {
    throw new Error(`knockout evidence requires supported Node 20, 22, or 24; current major is ${major}`);
  }
  return image;
}

function pathIsInside(candidate, parent) {
  const relative = path.relative(parent, candidate);
  return relative === "" || (relative !== ".." && !relative.startsWith(`..${path.sep}`));
}

function knockoutDockerMount(source, readOnly = false, destination = source) {
  if (source.includes(",") || destination.includes(",")) {
    throw new Error(`Docker evidence mount path contains a comma: ${source} -> ${destination}`);
  }
  return `type=bind,src=${source},dst=${destination}${readOnly ? ",readonly" : ""}`;
}

export function dependencyIdentity(dependencies = {}) {
  assertObserverDependencies(dependencies);
  return "[]";
}

function assertObserverDependencies(dependencies) {
  if (dependencies === null || typeof dependencies !== "object" || Array.isArray(dependencies)) {
    throw new Error("observer dependencies must be an object");
  }
  const names = Object.keys(dependencies);
  if (names.length > 0) {
    throw new Error(
      `public knockout evidence does not accept external source dependencies: ${names.sort().join(", ")}`,
    );
  }
}

/**
 * The public runner accepts no external source dependency. Keep this explicit export so callers
 * cannot mistake an unknown dependency for a silently absent one.
 */
export function bindObserverDependency(name) {
  throw new Error(`public knockout evidence does not support dependency ${JSON.stringify(name)}`);
}

function containedDependencySurface(dependencies, evidenceSnapshot) {
  assertObserverDependencies(dependencies);
  if (evidenceSnapshot !== null) {
    throw new Error("public knockout evidence does not accept an external evidence snapshot");
  }
  return { mounts: [], environment: [] };
}

export function prepareContainedEvidenceSnapshot(containerName, dependencies = {}) {
  assertObserverDependencies(dependencies);
  if (typeof containerName !== "string" || containerName.length === 0) {
    throw new Error("contained evidence requires a container name");
  }
  return null;
}

function fileSha256(file) {
  return crypto.createHash("sha256").update(readFileNoFollow(file)).digest("hex");
}

function removeKnockoutContainer(name) {
  try {
    execFileSync(fixedDockerExecutable(), ["rm", "--force", "--volumes", name], {
      encoding: "utf8",
      stdio: "pipe",
      timeout: 15_000,
      env: { ...process.env, NODE_OPTIONS: "" },
    });
    return null;
  } catch (error) {
    const diagnostic = `${error.stdout ?? ""}${error.stderr ?? ""}`;
    if (/No such container/i.test(diagnostic)) return null;
    return `could not remove evidence container ${name}: ${diagnostic.trim() || String(error && error.message)}`;
  }
}

function knockoutContainerExists(name) {
  try {
    execFileSync(fixedDockerExecutable(), ["container", "inspect", name], {
      encoding: "utf8",
      stdio: "pipe",
      timeout: 10_000,
      env: { ...process.env, NODE_OPTIONS: "" },
    });
    return true;
  } catch (error) {
    const diagnostic = `${error.stdout ?? ""}${error.stderr ?? ""}`;
    if (/No such (object|container)/i.test(diagnostic)) return false;
    throw new Error(
      `could not verify evidence-container removal: ${diagnostic.trim() || String(error && error.message)}`,
    );
  }
}

export const CONTAINED_SCRATCH_ROOT = "/noa-scratch";
export const CONTAINED_EVENTS_ROOT = "/noa-events";

export function containedGateScratchEnvironment(environment) {
  if (environment === null || typeof environment !== "object" || Array.isArray(environment)) {
    throw new Error("contained gate environment must be an object");
  }
  return { ...environment, TMPDIR: CONTAINED_SCRATCH_ROOT };
}

export function containedObserverArgs(
  cwd,
  containerName,
  { dependencies = {}, evidenceSnapshot = null } = {},
) {
  assertObserverDependencies(dependencies);
  if (evidenceSnapshot !== null) {
    throw new Error("public knockout evidence does not accept an external evidence snapshot");
  }
  const uid = typeof process.getuid === "function" ? process.getuid() : 65534;
  const gid = typeof process.getgid === "function" ? process.getgid() : 65534;
  const mounts = pathIsInside(cwd, KNOCKOUT_REPOSITORY_ROOT)
    ? [knockoutDockerMount(KNOCKOUT_REPOSITORY_ROOT)]
    : [knockoutDockerMount(cwd), knockoutDockerMount(KNOCKOUT_REPOSITORY_ROOT, true)];
  const dependencySurface = containedDependencySurface(dependencies, evidenceSnapshot);
  return [
    "run", "--rm", "--init", "--interactive", "--pull=missing",
    "--name", containerName,
    "--network", "none",
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
    "--read-only",
    "--tmpfs", `${CONTAINED_SCRATCH_ROOT}:rw,nosuid,nodev,size=1g,mode=0700,uid=${uid},gid=${gid}`,
    "--tmpfs", `${CONTAINED_EVENTS_ROOT}:rw,nosuid,nodev,size=16m,mode=0700,uid=${uid},gid=${gid}`,
    "--pids-limit", "4096",
    "--user", `${uid}:${gid}`,
    "--workdir", KNOCKOUT_REPOSITORY_ROOT,
    "--env", "HOME=/noa-scratch/home",
    "--env", "TMP=/noa-scratch",
    "--env", "npm_config_cache=/noa-scratch/npm-cache",
    ...dependencySurface.environment,
    ...mounts.flatMap((mount) => ["--mount", mount]),
    ...dependencySurface.mounts.flatMap((mount) => ["--mount", mount]),
    knockoutEvidenceImage(),
    "node", KNOCKOUT_TEST_OBSERVER,
  ];
}
const TOKEN_PATTERN = /^[0-9a-f]{64}$/;
const ROOT_TEST_FIND = "$(find dist/test -name '*.test.js' -not -path '*/dogfood/*')";
const ROOT_TEST_FIND_SENTINEL = "__NOA_TRUSTED_ROOT_TEST_FIND__";

function bytewiseStringOrder(left, right) {
  return Buffer.from(left).compare(Buffer.from(right));
}

function expandTrustedTestArgument(cwd, argument) {
  if (argument === ROOT_TEST_FIND_SENTINEL) {
    const root = path.join(cwd, "dist", "test");
    const found = [];
    const walk = (directory, relative = "") => {
      const entries = fs.readdirSync(directory, { withFileTypes: true })
        .sort((left, right) => bytewiseStringOrder(left.name, right.name));
      for (const entry of entries) {
        if (entry.isSymbolicLink()) {
          throw new Error(`trusted test discovery refuses symbolic link ${path.join(relative, entry.name)}`);
        }
        const next = relative === "" ? entry.name : path.join(relative, entry.name);
        if (entry.isDirectory()) {
          if (next.split(path.sep).includes("dogfood")) continue;
          walk(path.join(directory, entry.name), next);
        } else if (entry.isFile() && entry.name.endsWith(".test.js")) {
          found.push(path.join("dist", "test", next));
        }
      }
    };
    walk(root);
    if (found.length === 0) throw new Error("trusted root test discovery matched zero files");
    return found;
  }

  if (!argument.includes("*")) return [argument];
  if (argument.includes("?") || argument.includes("[") || path.isAbsolute(argument)) {
    throw new Error(`unsupported test glob ${JSON.stringify(argument)}`);
  }
  const directory = path.dirname(argument);
  const basename = path.basename(argument);
  if (directory.split(/[\\/]/).includes("..") || directory.includes("*")) {
    throw new Error(`test glob escapes or varies its directory: ${JSON.stringify(argument)}`);
  }
  const escaped = basename.replace(/[.+^${}()|[\]\\]/g, "\\$&").replaceAll("*", ".*");
  const matcher = new RegExp(`^${escaped}$`);
  const absoluteDirectory = path.resolve(cwd, directory);
  const relativeDirectory = path.relative(cwd, absoluteDirectory);
  if (relativeDirectory === ".." || relativeDirectory.startsWith(`..${path.sep}`)) {
    throw new Error(`test glob resolves outside its suite: ${JSON.stringify(argument)}`);
  }
  const matches = fs.readdirSync(absoluteDirectory, { withFileTypes: true })
    .sort((left, right) => bytewiseStringOrder(left.name, right.name))
    .filter((entry) => {
      if (entry.isSymbolicLink() && matcher.test(entry.name)) {
        throw new Error(`trusted test glob refuses symbolic link ${path.join(directory, entry.name)}`);
      }
      return entry.isFile() && matcher.test(entry.name);
    })
    .map((entry) => path.join(directory, entry.name));
  if (matches.length === 0) throw new Error(`test glob matched zero files: ${JSON.stringify(argument)}`);
  return matches;
}

function assertDirectTestArgs(args) {
  const testIndex = args.indexOf("--test");
  if (testIndex < 0 || args.lastIndexOf("--test") !== testIndex) {
    throw new Error("a test evidence step must carry exactly one --test option");
  }
  const prefix = args.slice(0, testIndex);
  const allowedPrefix =
    prefix.length === 0 ||
    (prefix.length === 1 && prefix[0] === "--enable-source-maps") ||
    (prefix.length === 2 && prefix[0] === "--import" && prefix[1] === "tsx") ||
    (
      prefix.length === 3 && prefix[0] === "--enable-source-maps" &&
      prefix[1] === "--import" && prefix[2] === "tsx"
    );
  if (!allowedPrefix) {
    throw new Error(`unsupported option before --test: ${JSON.stringify(prefix)}`);
  }
  if (args.some((arg) => arg.startsWith("--test-reporter"))) {
    throw new Error("a suite script may not select or redirect the evidence reporter");
  }
  if (args.slice(testIndex + 1).some((arg) => arg.startsWith("-"))) {
    throw new Error("unsupported option after --test in evidence step");
  }
}

function sourceMappedTestArgs(args) {
  const tsxIndex = args.findIndex(
    (argument, index) => argument === "--import" && args[index + 1] === "tsx",
  );
  if (tsxIndex < 0) return args;
  const normalized = [...args];
  normalized[tsxIndex + 1] = TRUSTED_TYPESCRIPT_TEST_REGISTER;
  return normalized.includes("--enable-source-maps")
    ? normalized
    : ["--enable-source-maps", ...normalized];
}

function parseTrustedNpmTestScript(cwd, script) {
  if (typeof script !== "string" || script.trim().length === 0) {
    throw new Error("npm test script is absent or empty");
  }
  const rootFindCount = script.split(ROOT_TEST_FIND).length - 1;
  if (rootFindCount > 1) throw new Error("root test discovery occurs more than once");
  const normalized = script.replace(ROOT_TEST_FIND, ROOT_TEST_FIND_SENTINEL);
  const withoutConjunctions = normalized.replace(/\s+&&\s+/g, " ");
  if (/[$`'";&|<>\\\n\r]/.test(withoutConjunctions)) {
    throw new Error("npm test script uses shell syntax outside the trusted command grammar");
  }
  const commands = normalized.split(/\s+&&\s+/);
  if (commands.length < 1 || commands.some((command) => command.trim().length === 0)) {
    throw new Error("npm test script has an empty command");
  }

  const steps = commands.map((command) => {
    const [name, ...rawArgs] = command.trim().split(/\s+/);
    if (name === "npm") {
      if (
        rawArgs.length !== 2 || rawArgs[0] !== "run" ||
        !/^[A-Za-z0-9:._-]+$/.test(rawArgs[1])
      ) {
        throw new Error(`unsupported npm preparation command ${JSON.stringify(command)}`);
      }
      return { cmd: "npm", args: rawArgs, evidence: false };
    }
    if (name !== "node") {
      throw new Error(`unsupported test command ${JSON.stringify(name)}`);
    }
    const evidence = rawArgs.includes("--test");
    if (evidence) assertDirectTestArgs(rawArgs);
    const args = evidence
      ? sourceMappedTestArgs(rawArgs).flatMap((argument) => expandTrustedTestArgument(cwd, argument))
      : rawArgs;
    return { cmd: process.execPath, args, evidence };
  });
  if (steps.filter((step) => step.evidence).length !== 1) {
    throw new Error("npm test script must decompose to exactly one direct node --test evidence step");
  }
  return steps;
}

/**
 * Every environment variable that can make a freshly started Node run code of someone else's
 * choosing, or make npm do it on Node's behalf.
 *
 * ── WHY THIS IS A LIST AND NOT JUST `NODE_OPTIONS` (reproduced 2026-08-24) ─────────────────────
 * The first repair of this defect checked `NODE_OPTIONS` only. MEASURED with `NODE_OPTIONS` unset
 * and `npm_config_node_options=--import=<data: URL>` set: npm run maps that config straight into the
 * child's `NODE_OPTIONS`, the data URL's exit handler printed a well-formed `noa-gate-runner/1`
 * record, and a gate that emitted nothing of its own and exited 1 came back as
 * `gateProtocolComplete: true`, gate identity "security-gates", findings [FORGED/ambient]. The same
 * value can arrive from a `.npmrc` `node-options` line with no environment variable at all, and
 * `script-shell` replaces the interpreter for every lifecycle script outright.
 *
 * The spelling was never the defect: routing evidence through npm was. The structural fix below
 * removes npm from the gate path entirely; this list is the second lock, so a hostile startup
 * surface is REPORTED rather than silently tolerated.
 */
// Every variable that can make a freshly started process run code of someone else's choosing.
//
// ── LD_LIBRARY_PATH IS ON THIS LIST DELIBERATELY, AND THE REASON IS A CORRECTION ───────────────
// A previous revision removed it, arguing that a library SEARCH PATH is not an injection hook. That
// is false at an evidence-trust boundary: the dynamic loader searches LD_LIBRARY_PATH directories
// BEFORE the default ones, so an attacker-controlled directory selects which shared object gets
// loaded at process start — substitution rather than pre-loading, but the same outcome. glibc's own
// hardening guidance says not to use LD_PRELOAD or LD_LIBRARY_PATH to change loader behaviour.
//
// The revision that removed it did so because GitHub's runner sets LD_LIBRARY_PATH and the required
// checks went red. That was fixing the wrong side: the answer is to clean the environment before the
// evidence-bearing process starts, not to teach the observer to accept a dirty one. An observer that
// is talked out of a refusal is not an observer.
//
// Where that cleaning happens matters, and two earlier attempts put it in the wrong place. `.github`
// now declares BOTH phases at every launch point: `evidenceLaunchEnv()` as a step-level `env:`, which
// the RUNNER applies when it creates the process so no user process starts under a hostile value, and
// `evidenceLaunchSanitizer()` on the command itself so the evidence child sees the keys ABSENT rather
// than merely neutral. A selftest derives both from THIS list, so a key cannot be added here and
// forgotten there. What each phase does and does not reach is stated on the helpers.
//
// ── TWO SETS, BECAUSE THE CONSUMERS MATCH BY DIFFERENT RULES ─────────────────────────────────────
// Splitting these is not tidiness. A refusal that does not match the way its consumer matches is
// either blind or noisy, and this list was blind: it compared names case-SENSITIVELY while npm
// resolves configuration from the environment case-INSENSITIVELY.
//
// Everything below is read by a program that compares the name EXACTLY — Node reads `NODE_OPTIONS`,
// Bash reads `BASH_ENV`, the dynamic loader reads `LD_PRELOAD`. `NoDe_OpTiOnS` is inert to all of
// them, so refusing on it would be a FALSE refusal.
const EVIDENCE_HOSTILE_EXACT_KEYS = Object.freeze([
  "NODE_OPTIONS", "NODE_REPL_EXTERNAL_MODULE",
  "BASH_ENV", "ENV", "SHELLOPTS",
  "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "DYLD_FRAMEWORK_PATH",
  "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT",
]);

// These three are read by NPM, which strips the `npm_config_` prefix and lowercases the rest — so
// every casing of the name is the same setting to npm and none of them is inert.
//
// MEASURED on npm 10.9.7, in a package whose `test` script writes a marker file:
//   npm_config_script_shell=<harmless stand-in shell>  →  exit 0, shell marker written, TEST NEVER RAN
//   NpM_CoNfIg_ScRiPt_ShElL=<the same>                 →  exit 0, shell marker written, TEST NEVER RAN
//   NpM_CoNfIg_Ignore_Scripts=true, npm publish        →  exit 0, prepublishOnly SKIPPED
// and the mixed-case spellings survived `/usr/bin/env -u npm_config_script_shell …` untouched,
// because `env -u` removes a name and these are a different name.
//
// The answer is NOT to enumerate spellings: a 23-character name has 2^18 casings, so any list of
// them is a list that is wrong. The rule below is npm's own rule, applied once.
const EVIDENCE_HOSTILE_NPM_CONFIG_KEYS = Object.freeze([
  "npm_config_node_options", "npm_config_script_shell", "npm_config_shell",
]);

/** npm's own resolution rule for a configuration name arriving from the environment. */
const npmConfigNameOf = (key) => key.toLowerCase();

const EVIDENCE_HOSTILE_ENV_KEYS = Object.freeze([
  EVIDENCE_HOSTILE_EXACT_KEYS[0], EVIDENCE_HOSTILE_EXACT_KEYS[1],
  ...EVIDENCE_HOSTILE_NPM_CONFIG_KEYS,
  ...EVIDENCE_HOSTILE_EXACT_KEYS.slice(2),
]);

/**
 * The exact `/usr/bin/env -u ...` prefix an evidence-bearing CI step must launch through, derived
 * from the refusal list itself so the two can never drift apart.
 *
 * ── THE PATH IS ABSOLUTE ON PURPOSE ───────────────────────────────────────────────────────────
 * A bare `env` is a command NAME, and Bash resolves a name against exported shell functions before
 * it ever looks at PATH. MEASURED: with `BASH_FUNC_env%%` exported as `() { echo INTERCEPTED; return
 * 0; }`, the launch printed INTERCEPTED, exited 0, and the Node evidence child never ran at all — a
 * green step that measured nothing. A path containing a slash is executed as a path: no function
 * lookup, and no PATH entry to hijack either.
 */
export const evidenceLaunchSanitizer = () =>
  `/usr/bin/env ${EVIDENCE_HOSTILE_ENV_KEYS.map((key) => `-u ${key}`).join(" ")}`;

/**
 * Variables whose value is a DIRECTORY SEARCH LIST. An empty element in one of these denotes the
 * current directory to the glibc loader, so "set it to empty" would point the search at wherever the
 * step happens to be running. They are neutralized with one directory that does not exist instead.
 */
const EVIDENCE_SEARCH_PATH_KEYS = new Set([
  "LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH", "DYLD_FRAMEWORK_PATH",
]);

/**
 * The exact step-level `env:` an evidence-bearing CI step must declare, derived from the refusal
 * list so the two cannot drift.
 *
 * ── WHY THIS IS THE BOUNDARY, AND WHY TWO EARLIER ATTEMPTS WERE NOT ───────────────────────────
 * The first attempt put `env -u` inside `run:`. That body is handed to a shell the runner has
 * ALREADY started, so it is too late for anything acting at shell startup: MEASURED, with `BASH_ENV`
 * pointing at a script, the script executed before the command.
 *
 * The second attempt declared a custom `shell: /usr/bin/env -u … bash`. That fixes BASH_ENV, but it
 * cannot support a clean-start claim for the loader: `/usr/bin/env` is itself the first user process
 * the runner execs, and the dynamic loader consumes an inherited LD_PRELOAD / LD_LIBRARY_PATH /
 * LD_AUDIT while loading `env` — before `env` can act on its own `-u` options.
 *
 * A step-level `env:` is applied by the RUNNER when it creates the process, so the shell is born
 * with these values and no user process ever starts under the hostile ones. MEASURED: a hostile
 * BASH_ENV executed its script with no override, and did nothing when the value was replaced before
 * the shell was created.
 *
 * This neutralizes; it does not unset — GitHub `env:` cannot remove a name. The keys are therefore
 * still PRESENT for the shell, which is why the `run:` line keeps its `env -u`: that is what makes
 * them ABSENT for the evidence child, and the observer's refusal reads the child.
 */
export function evidenceLaunchEnv() {
  const declared = {};
  for (const key of EVIDENCE_HOSTILE_ENV_KEYS) {
    declared[key] = EVIDENCE_SEARCH_PATH_KEYS.has(key) ? "/nonexistent" : "";
  }
  return declared;
}
// MEASURED before adding the npm keys: `npm run` sets none of node_options/script_shell/shell by
// itself, and this repository ships no `.npmrc`, so refusing on them cannot make an ordinary
// `npm run lint:knockout` refuse itself.

/**
 * The npm configuration flags an evidence-bearing launch pins on the COMMAND LINE.
 *
 * ── WHY THE COMMAND LINE, AND NOT A LONGER `env -u` LIST ─────────────────────────────────────────
 * `env -u` removes a NAME. npm reads a SETTING, and it finds that setting under any casing of the
 * name. Those two never meet: no list of names, however long, closes a bypass whose whole trick is
 * to arrive under a name nobody wrote down.
 *
 * npm's documented precedence puts command-line flags above environment variables, above every rc
 * file. A flag in argv therefore decides the setting outright, and argv has no casing dimension to
 * attack. That is why this is the control and the `env -u` prefix is not.
 *
 * Each value is npm's OWN default, so on an ordinary clean runner these three flags change nothing.
 * MEASURED with `npm config get`: ignore-scripts=false, script-shell=null (npm's POSIX default is
 * `/bin/sh`, named here absolutely so no PATH entry can move it), node-options=null.
 *
 * MEASURED against the reproduction, at all three launch shapes, on npm 10.9.7 — with
 * NpM_CoNfIg_ScRiPt_ShElL, NpM_CoNfIg_Ignore_Scripts and NpM_CoNfIg_NoDe_OpTiOnS all hostile:
 *   npm test …                  → the real test RAN, no shell hijack, child NODE_OPTIONS absent
 *   npm run lint:knockout …     → the real work RAN, no shell hijack
 *   npm publish --dry-run …     → prepublishOnly RAN
 * and without the flags the same environment produced exit 0 with nothing measured.
 */
/**
 * The script shell this repository pins, written ONCE and read by both sides of the same decision.
 *
 * The argv pin below puts this value in npm's command line; npm then hands it to every script child
 * as `npm_config_script_shell`, where the observer meets it again. Two literals would be two
 * opinions: change the pin and the observer starts refusing the very value the launch just chose.
 * MEASURED with them separate — the exact shipped launch ran 617 tests and FAILED 4, all four with
 * "knockout observer inherited npm_config_script_shell", refusing a value this repository had itself
 * put there one process earlier.
 */
const EVIDENCE_SCRIPT_SHELL = "/bin/sh";

/** The one canonical spelling npm produces for that setting. No other spelling is ours. */
const EVIDENCE_SCRIPT_SHELL_KEY = "npm_config_script_shell";

export const evidenceNpmPrecedenceFlags = () =>
  `--ignore-scripts=false --script-shell=${EVIDENCE_SCRIPT_SHELL} --node-options=`;

/**
 * The two settings only the PUBLISH launch needs pinned, on top of the shared ones.
 *
 * `--dry-run=false` because `NpM_CoNfIg_DrY_RuN=true` made `npm publish` report "(dry-run)" and exit
 * 0 against a registry that was not even listening — a release lane reporting success having
 * published nothing. `--registry` because the destination of a publish should be stated by the
 * workflow, not inherited from whatever configuration happens to be lying around.
 *
 * The pre-npm guard already closes that whole namespace; these are argv, which outranks every rc
 * file as well, so the two together mean neither an environment nor a file decides where this lane
 * publishes or whether it publishes at all.
 */
export const evidencePublishPins = () =>
  "--dry-run=false --registry=https://registry.npmjs.org/";

/** The flag that turns this module from a library into the pre-npm evidence launcher. */
const EVIDENCE_LAUNCH_FLAG = "--launch-evidence";

/**
 * The command a workflow puts between the sanitizer and npm, so the boundary exists BEFORE npm does.
 *
 * ── WHY A PIN IN NPM'S ARGV IS NOT ENOUGH, AND WHAT BROKE ────────────────────────────────────────
 * The publish lane is `npm publish` -> `prepublishOnly` -> `npm test`, so the argv we control is ONE
 * npm level away from the Node process that produces evidence. The outer npm exports its own config
 * to that child as lowercase `npm_config_*` and leaves the inherited mixed-case name untouched, so
 * the nested npm re-resolves both — and an EMPTY pin loses to a non-empty hostile value.
 *
 * MEASURED, identically on npm 10.9.7 and on 11.18.0 (the version publish.yml installs), with
 * `NpM_CoNfIg_NoDe_OpTiOnS=--import=<module>` and every pin in place:
 *     ATTACKER-RAN = TRUE, EVIDENCE-RAN = false, exit 0
 * `--import` runs that module BEFORE any application code, so the attacker owned the evidence
 * process before one line of this repository executed, and exited 0 in its place.
 *
 * That is why no refusal made from INSIDE the evidence process can be the boundary here: a control
 * cannot supply its own evidence. The boundary has to stand in a process the attacker's
 * configuration cannot reach.
 *
 * ── WHY THIS PROCESS IS THAT PROCESS ─────────────────────────────────────────────────────────────
 * Node reads `NODE_OPTIONS`, and the mixed-case `npm_config_*` spellings are INERT to it, because
 * only npm resolves that prefix. `NODE_OPTIONS` itself is exact-match, already neutralized by the
 * step-level `env:` the runner applies before the shell exists and made ABSENT by the `env -u`
 * prefix. So the first Node process on the launch line starts clean, and it starts before any npm.
 */
export const evidenceLaunchGuardCommand = () =>
  `node scripts/lib/knockout-runner.mjs ${EVIDENCE_LAUNCH_FLAG}`;

/**
 * npm's configuration namespace, and the ONE spelling this guard will let through it.
 *
 * ── WHY A DENYLIST OF SETTINGS IS THE WRONG SHAPE, MEASURED TWICE ────────────────────────────────
 * The first version of this refused three settings by name. Two separate bypasses walked past it:
 *   `NpM_CoNfIg_UsErCoNfIg` naming an rc file that set `node-options=--import=<module>` — the nested
 *     publish lane ran attacker code instead of the evidence and exited 0.
 *   `NpM_CoNfIg_DrY_RuN=true` — `npm publish` reported "(dry-run)" and exited 0 against a registry
 *     that was not even listening, so the lane could report success having published nothing.
 * npm has hundreds of settings. Any list of the dangerous ones is a list that is wrong, exactly as
 * any list of casings was. So the namespace is closed instead: whatever arrives under
 * `npm_config_*`, in whatever casing, does not reach npm.
 */
const NPM_CONFIG_PREFIX = "npm_config_";

/**
 * The single exception, admitted by CONTRACT rather than by trust.
 *
 * `actions/setup-node`, at the SHA both workflows pin, writes `$RUNNER_TEMP/.npmrc` and exports
 * `NPM_CONFIG_USERCONFIG` to point at it. That is the publish lane's registry configuration, so it
 * is admitted — but only under this exact spelling, only naming exactly that path, and only after
 * the file itself attests. Anything else about it is a refusal.
 */
const SETUP_NODE_USERCONFIG_SPELLING = "NPM_CONFIG_USERCONFIG";

/** A registry rc is two lines. Anything larger is not the file this guard expects. */
const ATTESTED_RC_MAX_BYTES = 8192;

/**
 * The EXACT file `actions/setup-node` writes for this workflow's `registry-url`, byte for byte.
 *
 * Read from the action's own source at the SHA both workflows pin: it composes
 * `authString + os.EOL + registryString` and writes NOTHING else — no `always-auth`, no comments,
 * no blank lines. So the attestation is equality, not a parse.
 *
 * An earlier version of this accepted any line matching a registry-ish or auth-ish pattern. That was
 * vacuous: it would have admitted an attacker's registry, a second placeholder variable, comments,
 * blank lines and duplicates. Matching the exact two lines admits the one file this lane actually
 * produces and nothing else, which is the only claim worth making about a file somebody else wrote.
 */
const SETUP_NODE_RC_BYTES =
  '//registry.npmjs.org/:_authToken=${NODE_AUTH_TOKEN}' + "\n" + "registry=https://registry.npmjs.org/";

/**
 * The exact revision those bytes were read from.
 *
 * The constant above is a claim about somebody else's program, so it is tied to the exact commit of
 * that program it was read at. Bump the action and this stops matching, which is the point: the
 * contract has to be re-read from the new source rather than assumed to have survived.
 */
export const SETUP_NODE_ATTESTED_REVISION = "820762786026740c76f36085b0efc47a31fe5020";

/**
 * Anything that reaches a log is quoted, stripped of control characters and bounded.
 *
 * These strings come from the environment, so they are attacker-shaped input: an unescaped one can
 * carry a newline and forge a second log line, or ANSI and repaint the terminal. No FILE CONTENT is
 * ever passed through here — only names, paths and line numbers — because an rc file can hold a
 * credential and this guard must not be the thing that prints it.
 */
const safeLabel = (value) => {
  const text = String(value).replace(/[\u0000-\u001f\u007f-\u009f]/g, "?");
  return JSON.stringify(text.length > 200 ? `${text.slice(0, 200)}...` : text);
};

/**
 * Read a file the attacker may have chosen, without letting the choice decide what happens.
 *
 * `O_NOFOLLOW` so a symlink cannot redirect the read, `O_NONBLOCK` so a FIFO cannot hang the launch,
 * `fstat` on the descriptor actually held so the answer is about that object, and a byte bound so a
 * huge or endless file cannot be read into memory. Both flags are REQUIRED: where the platform lacks
 * one, this refuses rather than performing a read it cannot describe.
 */
function readAttestableFile(file) {
  const { O_RDONLY, O_NOFOLLOW, O_NONBLOCK } = fs.constants;
  if (typeof O_NOFOLLOW !== "number" || O_NOFOLLOW === 0 ||
      typeof O_NONBLOCK !== "number" || O_NONBLOCK === 0) {
    return { status: "unattestable", reason: "this platform cannot open a file without following links" };
  }
  let fd;
  try { fd = fs.openSync(file, O_RDONLY | O_NOFOLLOW | O_NONBLOCK); }
  catch (e) {
    if (e.code === "ENOENT") return { status: "absent" };
    return { status: "unattestable", reason: `cannot be opened as a plain file (${e.code})` };
  }
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile()) return { status: "unattestable", reason: "is not a regular file" };
    if (stat.size > ATTESTED_RC_MAX_BYTES) {
      return { status: "unattestable", reason: `is larger than the ${ATTESTED_RC_MAX_BYTES} bytes this guard will read` };
    }
    const buffer = Buffer.alloc(stat.size);
    let read = 0;
    while (read < stat.size) {
      const n = fs.readSync(fd, buffer, read, stat.size - read, read);
      if (n === 0) break;
      read += n;
    }
    // The WHOLE file, or none of it: a short read means the object changed under us, and attesting
    // a prefix would be attesting a file that never existed.
    if (read !== stat.size) return { status: "unattestable", reason: "changed size while it was being read" };
    return { status: "read", text: buffer.toString("utf8") };
  } finally { fs.closeSync(fd); }
}

/**
 * A file this runner OWNS, holding bytes this runner verified.
 *
 * npm is never pointed at the path the environment named. Between attesting that path and npm
 * opening it, whoever chose it can replace what is there — so the verified BYTES are copied to a
 * private file this process created, and npm reads the copy. The attacker's path is read once, under
 * the bounded no-follow rules above, and never handed onward.
 */
function ownedRcFile(name, contents) {
  const root = privateFallbackRoot();
  assertPrivatePathDisjoint(root, [KNOCKOUT_REPOSITORY_ROOT], "owned npm-rc store");
  ensurePrivateDir(root);
  const file = path.join(root, name);
  let existing = null;
  try { existing = fs.lstatSync(file); }
  catch (e) { if (e.code !== "ENOENT") throw e; }
  if (existing !== null && (!existing.isFile() || existing.isSymbolicLink())) {
    throw new Error(`${file} is not the regular file this runner requires for an owned npm rc`);
  }
  fs.writeFileSync(file, contents, { mode: 0o600 });
  const attested = fs.lstatSync(file);
  if (!attested.isFile() || attested.isSymbolicLink() || attested.size !== Buffer.byteLength(contents)) {
    throw new Error(`${file} is not the exact owned npm rc this runner just wrote`);
  }
  return file;
}

/**
 * Attest the ONE rc file this guard admits: it must be setup-node's exact two lines, in order.
 *
 * Reports the FILE, never a line of it, for the reason above — an rc file can hold a credential and
 * this guard must not be the thing that prints one.
 */
function attestSetupNodeRc(file) {
  const result = readAttestableFile(file);
  if (result.status === "absent") return { refusals: [`${safeLabel(file)} is named as the runner's npm config but does not exist`], contents: null };
  if (result.status === "unattestable") return { refusals: [`${safeLabel(file)} ${result.reason}`], contents: null };
  // WHOLE-STRING EQUALITY. An earlier version split into lines and popped a trailing empty one,
  // which quietly made a trailing newline optional — and "optional" is how a second difference gets
  // in later. setup-node writes `authString + os.EOL + registryString` and stops, so the file either
  // is those bytes or it is not: empty, reversed, one newline longer and one line longer all fail
  // the same way, by not being equal.
  return result.text === SETUP_NODE_RC_BYTES
    ? { refusals: [], contents: result.text }
    : { refusals: [`${safeLabel(file)} is not byte-for-byte the two-line registry configuration setup-node writes`], contents: null };
}

/**
 * Inspect an environment the way npm resolves it, and hand back the one npm should be started with.
 *
 * ── WHAT IS CLOSED, AND HOW ──────────────────────────────────────────────────────────────────────
 * npm builds every setting from five sources. All five are answered:
 *     command line   the argv pins, which outrank everything below
 *     environment    the WHOLE `npm_config_*` namespace, case-folded: an empty one is dropped, a
 *                    non-empty one is REFUSED — except the one contract spelling above
 *     project rc     `<cwd>/.npmrc` is REFUSED if it exists at all; it is not parsed, because
 *                    deciding which of its lines are safe is the losing game this replaced
 *     user rc        the attested contract file, or a separately attested EMPTY file
 *     global rc      always a separately attested EMPTY file, which is also what neutralizes
 *                    `prefix` redirection: naming the global rc outright means no prefix, and no
 *                    default location derived from one, can supply anything
 *
 * The two empty files are DISTINCT: npm refuses to start when userconfig and globalconfig name the
 * same file ("double-loading config"), which is how an earlier attempt at this broke every build.
 */
export function evidenceLaunchGuard(environment, projectDirectory, options = {}) {
  const userRc = options.userRc ?? attestedEmptyRcFile("evidence-user.npmrc");
  const globalRc = options.globalRc ?? attestedEmptyRcFile("evidence-global.npmrc");
  const refusals = [];
  const sanitized = {};
  let contractUserconfig = null;

  const expectedUserconfig = typeof environment.RUNNER_TEMP === "string" && environment.RUNNER_TEMP.length !== 0
    ? path.join(environment.RUNNER_TEMP, ".npmrc")
    : null;

  for (const [key, value] of Object.entries(environment)) {
    if (!key.toLowerCase().startsWith(NPM_CONFIG_PREFIX)) { sanitized[key] = value; continue; }
    if (typeof value !== "string" || value.trim().length === 0) continue;   // carries no setting
    if (key === SETUP_NODE_USERCONFIG_SPELLING && expectedUserconfig !== null && value === expectedUserconfig) {
      contractUserconfig = value;
      continue;
    }
    refusals.push(`${safeLabel(key)} would reach npm as configuration; npm resolves that namespace case-insensitively`);
  }
  // The lane's own claim is OIDC with no token, so a token present here is either a leftover or an
  // attempt to publish as somebody. Either way it is refused, and it never reaches npm.
  const authToken = environment.NODE_AUTH_TOKEN;
  if (typeof authToken === "string" && authToken.trim().length !== 0) {
    refusals.push('"NODE_AUTH_TOKEN" is set, but this lane publishes through OIDC with no token');
  }
  delete sanitized.NODE_AUTH_TOKEN;

  let attestedContents = null;
  if (contractUserconfig !== null) {
    const attested = attestSetupNodeRc(contractUserconfig);
    refusals.push(...attested.refusals);
    attestedContents = attested.contents;
  }

  if (typeof projectDirectory === "string") {
    const projectRc = path.join(projectDirectory, ".npmrc");
    const found = readAttestableFile(projectRc);
    if (found.status !== "absent") {
      refusals.push(`${safeLabel(projectRc)} exists; a project rc is refused outright rather than parsed`);
    }
  }

  // npm reads a file this process wrote from bytes this process verified — never the path the
  // environment named.
  sanitized.npm_config_userconfig = refusals.length === 0 && attestedContents !== null
    ? (options.ownedRc ?? ownedRcFile)("evidence-registry.npmrc", attestedContents)
    : userRc;
  sanitized.npm_config_globalconfig = globalRc;
  return { refusals, environment: sanitized };
}

// The launcher runs ONLY when this file is executed directly with the flag. Importing the module is
// unchanged, which is what lets the boundary live in the library it belongs to.
if (process.argv[1] !== undefined &&
    path.resolve(fileURLToPath(import.meta.url)) === path.resolve(process.argv[1]) &&
    process.argv[2] === EVIDENCE_LAUNCH_FLAG) {
  const command = process.argv.slice(3);
  if (command.length === 0) {
    process.stderr.write(`${EVIDENCE_LAUNCH_FLAG} needs a command to launch, e.g. ${EVIDENCE_LAUNCH_FLAG} npm test\n`);
    process.exit(2);
  }
  const { refusals, environment } = evidenceLaunchGuard(process.env, process.cwd());
  if (refusals.length !== 0) {
    // REFUSE, and start nothing. Scrubbing quietly would hide a compromised runner, and standing
    // here is only worth anything because nothing downstream can be trusted to report it.
    process.stderr.write(`evidence launch refused: ${refusals.join("; ")}; no evidence process was started\n`);
    process.exit(78);
  }
  const launched = spawnSync(command[0], command.slice(1), { stdio: "inherit", env: environment, shell: false });
  if (launched.error) {
    process.stderr.write(`evidence launch could not start ${command[0]}: ${launched.error.message}\n`);
    process.exit(1);
  }
  // A signalled child is not a passing child, and `status` is null in exactly that case.
  process.exit(launched.signal ? 1 : launched.status ?? 1);
}

/**
 * Name every startup-injection variable present and non-empty, so the refusal can say which.
 *
 * Each set is matched the way ITS OWN consumer matches, which is the whole point of the split:
 * an exact-match consumer gets an exact lookup, and npm gets npm's case-folded rule. Matching npm's
 * keys exactly was blind (a mixed-case spelling walked past the refusal); matching the loader's keys
 * loosely would be noisy (a mixed-case `LD_PRELOAD` is inert, and refusing on it is a false alarm).
 *
 * The ACTUAL spelling found is reported, not the canonical one, so the refusal names what was really
 * in the environment rather than what the reader of this list expected to be there.
 */
function hostileStartupSurface(environment) {
  const present = [];
  for (const key of EVIDENCE_HOSTILE_EXACT_KEYS) {
    const value = environment[key];
    if (typeof value === "string" && value.trim().length !== 0) present.push(key);
  }
  const refusedNpmConfig = new Set(EVIDENCE_HOSTILE_NPM_CONFIG_KEYS.map(npmConfigNameOf));
  for (const key of Object.keys(environment)) {
    if (!refusedNpmConfig.has(npmConfigNameOf(key))) continue;
    const value = environment[key];
    if (typeof value !== "string" || value.trim().length === 0) continue;
    // THE ONE EXEMPTION, AND IT IS NARROW ON PURPOSE. npm exports the argv pin to every script child,
    // so this exact pair arrives on an HONEST run and refusing it fails the launch that set it. The
    // key is the canonical spelling npm itself produces and the value is the shared constant above:
    // both compared by equality, so `/bin/sh -x`, `/usr/bin/sh`, a trailing space, or any mixed-case
    // spelling is a different pair and is still refused. Provenance, not just value, is what this
    // narrowness preserves — the only pair admitted is the one this repository emits.
    if (key === EVIDENCE_SCRIPT_SHELL_KEY && value === EVIDENCE_SCRIPT_SHELL) continue;
    present.push(key);
  }
  return present;
}

/**
 * The child environment for a gate step is CONSTRUCTED, not filtered.
 *
 * A denylist is only ever as long as the last person's imagination — this defect already arrived
 * twice under two different spellings. So a gate step receives exactly the variables named here and
 * nothing else: no `NODE_OPTIONS`, no `npm_config_*` alias, no `BASH_ENV`, no `DYLD_*`/`LD_PRELOAD`,
 * and no inherited `PATH`.
 *
 * PATH is rebuilt rather than dropped because a proof recipe underneath a gate legitimately starts
 * `npm run build` in a package directory. It contains the directory of THIS Node executable — so the
 * npm that runs is the one shipped beside the runtime under measurement — plus the base system
 * directories, and nothing user-writable ahead of them.
 *
 * The `npm_config_*` values disarm the USER and GLOBAL rc files only, and that is stated exactly
 * because the obvious stronger claim is false: MEASURED, a PROJECT `.npmrc` beside a package still
 * won. With a project rc naming an attacker `script-shell` and an attacker `node-options`
 * import, `npm config get` returned both verbatim while `npm_config_node_options` was set empty
 * in this environment. No environment variable switches a project rc off. The place that used to
 * reach npm again underneath a gate — the proof recipe's build step in `proof-resolve.mjs` —
 * therefore no longer starts npm at all; these three are defence in depth, not the control.
 */
// No temporary-directory variable is handed down: this runner does not name the machine-wide
// temporary directory anywhere (its own selftest scans every line for that), and a gate step that
// needs scratch space can use its runtime's own default rather than one this layer chose for it.
const EVIDENCE_ENV_ALLOWLIST = Object.freeze([
  "HOME", "LANG", "LC_ALL", "LC_CTYPE", "USER", "LOGNAME", "CI",
  "SystemRoot", "SYSTEMROOT", "COMSPEC",
]);

/**
 * An empty, private, regular file this runner owns — created if missing and re-checked on every use.
 * If the path exists and is anything else (a symlink, a directory, a file with content), the run
 * REFUSES rather than overwriting: something else is using that name, and silently replacing it is
 * how a tool destroys state it does not own.
 */
function attestedEmptyRcFile(name, root = privateFallbackRoot()) {
  if (typeof root !== "string" || !path.isAbsolute(root)) {
    throw new Error(`neutral npm-rc store must be an absolute path, got ${JSON.stringify(root)}`);
  }
  assertPrivatePathDisjoint(root, [KNOCKOUT_REPOSITORY_ROOT], "neutral npm-rc store");
  ensurePrivateDir(root);
  const file = path.join(root, name);
  let stat = null;
  try { stat = fs.lstatSync(file); }
  catch (e) { if (e.code !== "ENOENT") throw e; }
  if (stat === null) fs.writeFileSync(file, "", { mode: 0o600, flag: "wx" });
  const attested = fs.lstatSync(file);
  if (!attested.isFile() || attested.isSymbolicLink() || attested.size !== 0) {
    throw new Error(`${file} is not the empty regular file this runner requires as a neutral npm rc`);
  }
  return file;
}

export function closedEvidenceEnvironment(source, options = {}) {
  const optionKeys = Object.keys(options).sort();
  if (optionKeys.some((key) => key !== "rcRoot")) {
    throw new Error(`closed evidence environment received unknown options: ${optionKeys.join(", ")}`);
  }
  const rcRoot = options.rcRoot;
  const environment = {};
  for (const key of EVIDENCE_ENV_ALLOWLIST) {
    const value = source[key];
    if (typeof value === "string") environment[key] = value;
  }
  environment.PATH = [
    path.dirname(process.execPath), "/usr/bin", "/bin", "/usr/sbin", "/sbin",
  ].join(path.delimiter);
  // Gate observations are read-only evidence. Git may otherwise refresh stat-cache bytes in the
  // live index during commands such as `status`, which makes the observation modify the exact state
  // it is meant to measure. Override rather than inherit so an ambient value cannot reopen writes.
  environment.GIT_OPTIONAL_LOCKS = "0";
  environment.npm_config_node_options = "";
  // Two DISTINCT files, each ATTESTED empty rather than assumed absent — "nobody will ever create
  // that path" is not a control. npm also refuses to start when `userconfig` and `globalconfig`
  // name the SAME file ("double-loading config ... as global, previously loaded as user"), which is
  // how an earlier attempt at this pointed both at the null device and broke every nested build.
  environment.npm_config_userconfig = attestedEmptyRcFile("evidence-user.npmrc", rcRoot);
  environment.npm_config_globalconfig = attestedEmptyRcFile("evidence-global.npmrc", rcRoot);
  return environment;
}

/**
 * Resolve a GATE suite into direct `node` steps — never `npm`.
 *
 * `package.json` stays the command source (a second copy of every gate command in the registry
 * would rot), but the script is decomposed here and each command is executed as the exact current
 * Node executable. The grammar is deliberately tiny and refuses anything it cannot separate safely.
 * This mirrors `trustedTestSteps` for the tests lane; it is written separately rather than shared
 * because that parser must find exactly one `--test` step and this one must find a terminal
 * evidence step, and merging the two on a release branch would put the tests lane at risk for no
 * gain.
 */
export function trustedGateSteps(root, [dir, cmd, args], depth = 0) {
  const cwd = path.join(root, dir);
  if (cmd === "node" || path.resolve(cmd) === path.resolve(process.execPath)) {
    return [{ cmd: process.execPath, args: [...args] }];
  }
  if (cmd !== "npm") {
    throw new Error(`gate suites must use npm or direct node, got ${JSON.stringify(cmd)}`);
  }
  if (depth > 2) throw new Error("gate script nesting exceeded its bound");
  let scriptName;
  if (args.length === 1 && args[0] === "test") scriptName = "test";
  else if (args.length === 2 && args[0] === "run" && /^[A-Za-z0-9:._-]+$/.test(args[1])) scriptName = args[1];
  else throw new Error(`unsupported npm gate arguments ${JSON.stringify(args)}`);

  const manifest = JSON.parse(fs.readFileSync(path.join(cwd, "package.json"), "utf8"));
  const script = manifest.scripts?.[scriptName];
  if (typeof script !== "string" || script.trim().length === 0) {
    throw new Error(`npm script ${JSON.stringify(scriptName)} is absent or empty`);
  }
  // No shell is ever started, so no shell syntax may be accepted — including the `script-shell`
  // an .npmrc could otherwise substitute for the interpreter.
  if (/[$`'";|<>\\\n\r]/.test(script.replace(/\s+&&\s+/g, " "))) {
    throw new Error(`npm script ${JSON.stringify(scriptName)} uses shell syntax outside the trusted gate grammar`);
  }
  const steps = [];
  for (const command of script.split(/\s+&&\s+/)) {
    const [name, ...rawArgs] = command.trim().split(/\s+/);
    if (name === "npm") {
      steps.push(...trustedGateSteps(root, [dir, "npm", rawArgs], depth + 1));
      continue;
    }
    if (name !== "node") throw new Error(`unsupported gate command ${JSON.stringify(name)}`);
    steps.push({ cmd: process.execPath, args: rawArgs });
  }
  if (steps.length === 0) throw new Error(`npm script ${JSON.stringify(scriptName)} decomposed to no commands`);
  return steps;
}

/**
 * Resolve a test suite into credential-free setup/post steps and one direct evidence-bearing
 * `node --test` step. `package.json` remains the command source; this parser refuses shell features
 * it cannot separate safely instead of copying the script into a second registry.
 */
export function trustedTestSteps(root, [dir, cmd, args]) {
  const cwd = path.join(root, dir);
  if (cmd === "node" || path.resolve(cmd) === path.resolve(process.execPath)) {
    assertDirectTestArgs(args);
    return [{
      cmd: process.execPath,
      args: sourceMappedTestArgs(args).flatMap((argument) => expandTrustedTestArgument(cwd, argument)),
      evidence: true,
    }];
  }
  if (cmd !== "npm") throw new Error(`test suites must use npm or direct node --test, got ${JSON.stringify(cmd)}`);
  let scriptName;
  if (args.length === 1 && args[0] === "test") scriptName = "test";
  else if (args.length === 2 && args[0] === "run" && /^[A-Za-z0-9:._-]+$/.test(args[1])) {
    scriptName = args[1];
  } else {
    throw new Error(`unsupported npm suite arguments ${JSON.stringify(args)}`);
  }
  const manifestPath = path.join(cwd, "package.json");
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  return parseTrustedNpmTestScript(cwd, manifest.scripts?.[scriptName]);
}

function withoutInheritedKnockoutReporter(sourceEnvironment) {
  const environment = { ...sourceEnvironment };
  const socketPath = environment[PROOF_EVENT_SOCKET_ENV];
  const token = environment[PROOF_EVENT_TOKEN_ENV];
  if (socketPath === undefined && token === undefined) return environment;
  if (typeof socketPath !== "string" || socketPath.length === 0 || !path.isAbsolute(socketPath)) {
    throw new Error(`${PROOF_EVENT_SOCKET_ENV} does not name an absolute event socket`);
  }
  if (typeof token !== "string" || !TOKEN_PATTERN.test(token)) {
    throw new Error(`${PROOF_EVENT_TOKEN_ENV} is not a 256-bit lowercase hexadecimal token`);
  }
  const privateRoot = `${path.resolve(privateFallbackRoot())}${path.sep}`;
  const resolvedSocket = path.resolve(socketPath);
  if (!resolvedSocket.startsWith(privateRoot) || path.basename(resolvedSocket) !== "events.sock") {
    throw new Error(`${PROOF_EVENT_SOCKET_ENV} points outside the private knockout event store`);
  }

  const controlledSuffix = proofEventReporterNodeOption();
  const inherited = environment.NODE_OPTIONS ?? "";
  if (inherited !== controlledSuffix && !inherited.endsWith(` ${controlledSuffix}`)) {
    throw new Error(
      `${PROOF_EVENT_SOCKET_ENV} is present but NODE_OPTIONS does not end in the exact controlled reporter option`,
    );
  }
  const remaining = inherited.slice(0, inherited.length - controlledSuffix.length).trimEnd();
  if (remaining.length === 0) delete environment.NODE_OPTIONS;
  else environment.NODE_OPTIONS = remaining;
  delete environment[PROOF_EVENT_SOCKET_ENV];
  delete environment[PROOF_EVENT_TOKEN_ENV];
  return environment;
}

export function observeSuite(
  root,
  [dir, cmd, args],
  timeoutMs = 900_000,
  { boundaryBootstrapToken = null, kind = "gate", dependencies = {} } = {},
) {
  const started = Date.now();
  // Public knockout evidence is self-contained; reject any external source dependency before an
  // observation starts.
  let dependencyAttestationError = null;
  try {
    assertObserverDependencies(dependencies);
  } catch (error) {
    dependencyAttestationError = `dependency attestation refused: ${String(error && error.message)}`;
  }
  let eventSocketPath = null;
  // `observeSuite` always starts an independent child run. When this API itself is exercised from
  // a node:test integration test, inheriting Node's private worker marker makes the nested process
  // emit V8-serialized TestsStream frames to its parent instead of invoking the selected reporter.
  // The result is neither JSONL nor an independent observation. Strip only that runner-internal
  // marker; all ordinary application environment remains intact.
  let environment = withoutInheritedKnockoutReporter(process.env);
  let startupSurfaceError = null;
  delete environment.NODE_TEST_CONTEXT;
  if (environment[BOUNDARY_KNOCKOUT_BOOTSTRAP_ENV] !== undefined) {
    startupSurfaceError =
      `knockout observer inherited ${BOUNDARY_KNOCKOUT_BOOTSTRAP_ENV}; ` +
      "the isolated bootstrap pipe must be created by the exact retained-arm worker";
    delete environment[BOUNDARY_KNOCKOUT_BOOTSTRAP_ENV];
  }
  // EVERY evidence lane needs a closed Node startup surface, not only the contained `tests` lane.
  // MEASURED: with this check scoped to `tests`, an inherited `NODE_OPTIONS=--import <module>` loaded
  // a module into the gate child that printed a well-formed `noa-gate-runner/1` terminal record at
  // exit. A gate that produced NO evidence of its own and exited 1 was read back as
  // `gateProtocolComplete: true`, gate identity "security-gates", and the exact rule/subject pair a
  // registry entry requires — manufacturing DETECTOR_TRIGGERED for every gate-kind knockout from the
  // environment alone. Refusing is deliberate rather than scrubbing NODE_OPTIONS: a hostile startup
  // surface is a fact about the run, and silently erasing it would hide the thing that must be seen.
  const hostileSurface = hostileStartupSurface(environment);
  if (hostileSurface.length !== 0) {
    startupSurfaceError =
      `knockout observer inherited ${hostileSurface.join(", ")}; ` +
      "contained evidence requires a closed Node startup surface";
  }
  if (kind === "tests") {
    // The protected socket lives only inside the observer's disposable namespace. Docker Desktop
    // cannot carry a host Unix-domain socket through its bind transport (ENOTSUP), and the host does
    // not need the descriptor: the observer serializes its bounded event stream in its final JSON.
    eventSocketPath = path.join(CONTAINED_EVENTS_ROOT, "events.sock");
    const inherited = environment.NODE_OPTIONS ?? "";
    if (/(?:^|\s)--test-reporter(?:-destination)?(?:=|\s)/.test(inherited)) {
      throw new Error("NODE_OPTIONS already selects a test reporter; knockout evidence requires its exact reporter");
    }
  }

  let exit = 0;
  let timedOut = false;
  let signal = null;
  let out = "";
  let machineOutput = "";
  let machineDiagnostics = "";
  let testEvents = "";
  let observationError = null;
  let containerName = null;
  let evidenceSnapshot = null;
  const containedLane = kind === "tests" || Object.keys(dependencies).length > 0;
  if (boundaryBootstrapToken !== null && (kind !== "gate" || containedLane)) {
    throw new Error(
      "isolated boundary bootstrap is permitted only for a direct dependency-free gate observation",
    );
  }
  // True only while the DESIGNATED terminal evidence step is executing.
  let executingTerminalGateStep = false;
  try {
    if (dependencyAttestationError !== null) throw new Error(dependencyAttestationError);
    if (containedLane) {
      if (startupSurfaceError !== null) throw new Error(startupSurfaceError);
      const steps = kind === "tests"
        ? trustedTestSteps(root, [dir, cmd, args]).map((step) => ({
            ...step,
            // Official Node images place the selected runtime here. Host-side npx/version-manager
            // paths are neither portable nor evidence; the inner observer requires this executable.
            cmd: step.cmd === process.execPath ? "/usr/local/bin/node" : step.cmd,
          }))
        : trustedGateSteps(root, [dir, cmd, args]).map((step, index, all) => {
            const evidence = index === all.length - 1;
            return {
              cmd: step.cmd === process.execPath ? "/usr/local/bin/node" : step.cmd,
              args: evidence && !step.args.includes("--knockout-json")
                ? [...step.args, "--knockout-json"]
                : step.args,
              evidence,
            };
          });
      containerName = `noa-knockout-${process.pid}-${crypto.randomBytes(8).toString("hex")}`;
      evidenceSnapshot = prepareContainedEvidenceSnapshot(containerName, dependencies);
      const request = JSON.stringify({
        cwd: path.join(root, dir),
        kind,
        steps,
        timeoutMs,
        socketPath: eventSocketPath,
      });
      const raw = execFileSync(
        fixedDockerExecutable(),
        containedObserverArgs(path.join(root, dir), containerName, { dependencies, evidenceSnapshot }),
        {
          cwd: KNOCKOUT_REPOSITORY_ROOT,
          encoding: "utf8",
          stdio: ["pipe", "pipe", "pipe"],
          input: request,
          timeout: timeoutMs + 10_000,
          maxBuffer: 40 * 1024 * 1024,
          env: { ...process.env, NODE_OPTIONS: "" },
        },
      );
      let response;
      try { response = JSON.parse(raw); }
      catch { throw new Error("trusted contained knockout observer returned non-JSON output"); }
      response = validateContainedObservationResponse(response);
      exit = response.exit;
      signal = response.signal;
      timedOut = response.timedOut;
      out = response.out;
      testEvents = response.testEvents;
      machineOutput = response.machineOutput;
      machineDiagnostics = response.machineDiagnostics;
      observationError = response.observationError;
    } else {
      if (startupSurfaceError !== null) throw new Error(startupSurfaceError);
      // NO npm ON THE EVIDENCE PATH. `npm run` maps `node-options` — from the environment OR from
      // any `.npmrc` — into the child's NODE_OPTIONS, and `script-shell` replaces the interpreter
      // outright, so routing gate evidence through npm handed a third party a code-execution hook
      // no amount of NODE_OPTIONS checking could see. package.json stays the command source; it is
      // decomposed here into exact `node` steps and each runs in a constructed environment.
      const steps = trustedGateSteps(root, [dir, cmd, args]);
      if (boundaryBootstrapToken !== null && (
        steps.length !== 1 || ![
          "scripts/lint-boundary.mjs",
          "scripts/lib/boundary-spool-arm.selftest.mjs",
        ].includes(steps[0]?.args?.[0])
      )) {
        throw new Error(
          "isolated boundary bootstrap is permitted only for one reviewed terminal boundary gate",
        );
      }
      const gateEnvironment = closedEvidenceEnvironment(environment);
      const cwd = path.join(root, dir);
      const deadline = Date.now() + timeoutMs;
      for (let index = 0; index < steps.length; index++) {
        const step = steps[index];
        const isEvidence = index === steps.length - 1;
        // Which step is running has to survive a throw: see the catch below.
        executingTerminalGateStep = isEvidence;
        const stepArgs = isEvidence && !step.args.includes("--knockout-json")
          ? [...step.args, "--knockout-json"]
          : step.args;
        const remaining = deadline - Date.now();
        if (remaining < 1) throw new Error("gate suite exhausted its timeout before its evidence step");
        const isolatedBootstrapBytes = isEvidence && boundaryBootstrapToken !== null
          ? consumeBoundaryKnockoutBootstrapToken(boundaryBootstrapToken)
          : null;
        const stepEnvironment = isolatedBootstrapBytes === null
          ? gateEnvironment
          : { ...gateEnvironment, [BOUNDARY_KNOCKOUT_BOOTSTRAP_ENV]: "0" };
        const stepResult = spawnSync(step.cmd, stepArgs, {
          cwd, encoding: "utf8", stdio: "pipe", timeout: remaining, env: stepEnvironment,
          ...(isolatedBootstrapBytes === null ? {} : { input: isolatedBootstrapBytes }),
          maxBuffer: 40 * 1024 * 1024,
        });
        const stepOutput = String(stepResult.stdout ?? "");
        const stepDiagnostics = String(stepResult.stderr ?? "");
        out += `${stepOutput}${stepDiagnostics}`;
        // Only the terminal step may speak the gate protocol: a preparation step's stdout is never
        // consulted, so it cannot contribute or forge the record the verdict is read from.
        if (isEvidence) {
          machineOutput = stepOutput;
          machineDiagnostics = stepDiagnostics;
        }
        if (stepResult.error !== undefined || stepResult.status !== 0 || stepResult.signal !== null) {
          timedOut = stepResult.error?.code === "ETIMEDOUT" || stepResult.signal === "SIGTERM";
          exit = Number.isInteger(stepResult.status) ? stepResult.status : null;
          signal = stepResult.signal ?? null;
          break;
        }
      }
    }
  } catch (e) {
    out = `${e.stdout ?? ""}${e.stderr ?? ""}`;
    // ── STEP IDENTITY SURVIVES THE THROW ──────────────────────────────────────────────────────
    // This used to assign `e.stdout` unconditionally, and the catch cannot see WHICH step threw.
    // MEASURED with a script `node prep.mjs && node terminal.mjs`: a preparation step that printed
    // one well-formed `noa-gate-runner/1` record and then exited 1 was read back as
    // gateProtocolComplete:true, identity "security-gates", findings [FORGED_PREP/prep] — while the
    // terminal evidence step never ran at all. A step that is not the designated terminal one
    // contributes NOTHING to the record the verdict is read from, whether it succeeds or fails; a
    // preparation failure therefore leaves the observation incomplete, which is a refusal.
    machineOutput = executingTerminalGateStep ? String(e.stdout ?? "") : "";
    machineDiagnostics = executingTerminalGateStep ? String(e.stderr ?? "") : "";
    // `execFileSync` surfaces a timeout as a SIGTERM kill, not as an exit code.
    timedOut = e.killed === true || e.signal === "SIGTERM" || e.code === "ETIMEDOUT";
    exit = typeof e.status === "number" ? e.status : null;
    signal = e.signal ?? null;
    observationError =
      containedLane || startupSurfaceError !== null || dependencyAttestationError !== null
        ? String(e && e.message)
        : observationError;
  } finally {
    let containerRemoved = containerName === null;
    if (containerName !== null) {
      try {
        if (knockoutContainerExists(containerName)) {
          observationError ??= `observer returned while evidence container ${containerName} remained alive`;
          const cleanupError = removeKnockoutContainer(containerName);
          if (cleanupError !== null) observationError ??= cleanupError;
        }
        if (knockoutContainerExists(containerName)) {
          observationError ??= `evidence container ${containerName} survived forced removal`;
        } else {
          containerRemoved = true;
        }
      } catch (error) {
        observationError ??= String(error && error.message);
      }
    }
    if (evidenceSnapshot !== null) {
      if (!containerRemoved) {
        observationError ??= `evidence snapshot ${evidenceSnapshot.root} retained for a surviving container`;
      } else {
        try { evidenceSnapshot.cleanup(); }
        catch (error) { observationError ??= `could not remove evidence snapshot: ${String(error && error.message)}`; }
      }
    }
    try {
      assertObserverDependencies(dependencies);
    } catch (error) {
      observationError ??= `dependency attestation changed during observation: ${String(error && error.message)}`;
    }
  }

  const parsed = kind === "tests" && observationError === null ? parseProofEvents(testEvents) : null;
  const parsedGate = kind === "gate" ? parseGateEvidence(machineOutput) : null;
  const parsedArmTerminal = kind === "gate"
    ? parseBoundaryArmTerminalEvidence(machineDiagnostics) : null;
  const fileFailures = parsed?.events.filter((event) =>
    event.event === "fail" && event.fileFailure === true
  ) ?? [];
  const failureEvents = kind === "tests" && observationError === null
    ? failingTestEvents(testEvents)
    : [];
  return projectKnockoutObservation({
    exit,
    timedOut,
    signal,
    out,
    testEvents,
    protocolComplete: observationError === null && parsed?.protocolComplete === true,
    protocolError: observationError ?? (parsed?.protocolComplete === false ? parsed.error : null),
    testCount: parsed?.protocolComplete === true ? parsed.plan.count : 0,
    fileFailureCount: fileFailures.length,
    failureEvents,
    failing: new Set(failureEvents.map((event) => event.name)),
    // A refused observation can never be a complete gate protocol, whatever bytes reached stdout.
    gateProtocolComplete: observationError === null && parsedGate?.protocolComplete === true,
    gateProtocolError: observationError
      ?? (parsedGate?.protocolComplete === false ? parsedGate.error : null),
    gate: parsedGate?.protocolComplete === true ? parsedGate.gate : null,
    gateFindings: parsedGate?.protocolComplete === true ? parsedGate.findings : [],
    gateProtocol: parsedGate?.protocolComplete === true ? parsedGate.protocol : null,
    gateProvenance: parsedGate?.protocolComplete === true ? parsedGate.provenance : null,
    findings: parsedGate?.protocolComplete === true ? parsedGate.findings.length : 0,
    armTerminalProtocolComplete: parsedArmTerminal?.protocolComplete === true,
    armTerminalProtocolError: parsedArmTerminal?.protocolComplete === false
      ? parsedArmTerminal.error : null,
    armTerminalSummary: parsedArmTerminal?.protocolComplete === true
      ? parsedArmTerminal.summary : null,
    ms: Date.now() - started,
  });
}

function isExactArmTerminalSummary(summary) {
  const counts = summary === null || typeof summary !== "object" || Array.isArray(summary)
    ? []
    : [
        summary.duplicateCaseCount,
        summary.failureCount,
        summary.missingCaseCount,
        summary.observedCaseCount,
        summary.plannedCaseCount,
        summary.unexpectedCaseCount,
      ];
  return exactKeys(summary, ARM_TERMINAL_KEYS)
    && summary.protocol === ARM_TERMINAL_PROTOCOL
    && summary.event === "complete"
    && ["PASS", "FAIL", "SETUP_FAILED"].includes(summary.status)
    && HEX_64_RE.test(summary.casePlanSha256)
    && counts.every((count) => Number.isSafeInteger(count) && count >= 0);
}

/** Parse exactly one machine-readable boundary-arm terminal record from its dedicated stderr. */
export function parseBoundaryArmTerminalEvidence(output) {
  const records = [];
  for (const line of String(output ?? "").split(/\r?\n/)) {
    if (!line.startsWith(ARM_TERMINAL_PREFIX)) continue;
    try { records.push(JSON.parse(line.slice(ARM_TERMINAL_PREFIX.length))); }
    catch { records.push(null); }
  }
  if (records.length !== 1 || !exactKeys(records[0], ARM_TERMINAL_KEYS)) {
    return Object.freeze({
      protocolComplete: false,
      error: `expected exactly one exact boundary-arm terminal record, received ${records.length}`,
      summary: null,
    });
  }
  const summary = records[0];
  if (!isExactArmTerminalSummary(summary)) {
    return Object.freeze({
      protocolComplete: false,
      error: "the boundary-arm terminal record is malformed",
      summary: null,
    });
  }
  return Object.freeze({ protocolComplete: true, error: null, summary: Object.freeze(summary) });
}

/**
 * Copy one observation through a closed, typed schema before it becomes knockout evidence.
 *
 * This is intentionally not `{ ...observation }`: baseline storage once hand-copied the ordinary
 * gate fields and silently dropped the separate boundary-arm terminal record, while the focused
 * classifier fixture passed the raw object and stayed green. Every evidence phase now crosses this
 * same projection, so adding, omitting, or changing a field is a reviewed schema change.
 */
export function projectKnockoutObservation(observation) {
  if (!exactKeys(observation, KNOCKOUT_OBSERVATION_KEYS)) {
    throw new Error(
      `knockout observation must contain exactly ${KNOCKOUT_OBSERVATION_KEYS.join(",")}`,
    );
  }
  const nullableString = (value) => value === null || typeof value === "string";
  const nonnegativeInteger = (value) => Number.isSafeInteger(value) && value >= 0;
  if (
    !(observation.exit === null || Number.isSafeInteger(observation.exit)) ||
    typeof observation.timedOut !== "boolean" || !nullableString(observation.signal) ||
    typeof observation.out !== "string" || typeof observation.testEvents !== "string" ||
    typeof observation.protocolComplete !== "boolean" ||
    !nullableString(observation.protocolError) || !nonnegativeInteger(observation.testCount) ||
    !nonnegativeInteger(observation.fileFailureCount) ||
    !Array.isArray(observation.failureEvents) || !(observation.failing instanceof Set) ||
    ![...observation.failing].every((name) => typeof name === "string") ||
    typeof observation.gateProtocolComplete !== "boolean" ||
    !nullableString(observation.gateProtocolError) || !nullableString(observation.gate) ||
    !nullableString(observation.gateProtocol) ||
    !(observation.gateProvenance === null
      || (typeof observation.gateProvenance === "object"
        && !Array.isArray(observation.gateProvenance))) ||
    !Array.isArray(observation.gateFindings) || !nonnegativeInteger(observation.findings) ||
    observation.findings !== observation.gateFindings.length ||
    typeof observation.armTerminalProtocolComplete !== "boolean" ||
    !nullableString(observation.armTerminalProtocolError) ||
    !nonnegativeInteger(observation.ms)
  ) {
    throw new Error("knockout observation contains a malformed typed field");
  }
  if (observation.armTerminalProtocolComplete) {
    if (observation.armTerminalProtocolError !== null
        || !isExactArmTerminalSummary(observation.armTerminalSummary)) {
      throw new Error("complete boundary-arm terminal evidence is malformed");
    }
  } else if (observation.armTerminalSummary !== null) {
    throw new Error("incomplete boundary-arm terminal evidence carried a summary");
  }
  let gateProvenance = null;
  if (observation.gateProtocolComplete) {
    if (observation.gateProtocol !== GATE_EVENT_PROTOCOL
        && observation.gateProtocol !== PROVENANCE_BOUND_GATE_EVENT_PROTOCOL) {
      throw new Error("complete gate evidence carried an unknown protocol");
    }
    if (observation.gateProtocol === PROVENANCE_BOUND_GATE_EVENT_PROTOCOL) {
      if (observation.gateProvenance === null) {
        throw new Error("provenance-bound gate evidence omitted provenance");
      }
      try { gateProvenance = normalizeGateProvenance(observation.gateProvenance); }
      catch (error) {
        throw new Error(`provenance-bound gate evidence is malformed: ${String(error && error.message)}`);
      }
    } else if (observation.gateProvenance !== null) {
      throw new Error("legacy gate evidence carried provenance");
    }
  } else if (observation.gateProtocol !== null || observation.gateProvenance !== null) {
    throw new Error("incomplete gate evidence carried protocol or provenance claims");
  }
  return Object.freeze({
    armTerminalProtocolComplete: observation.armTerminalProtocolComplete,
    armTerminalProtocolError: observation.armTerminalProtocolError,
    armTerminalSummary: observation.armTerminalSummary === null
      ? null : Object.freeze({
          casePlanSha256: observation.armTerminalSummary.casePlanSha256,
          duplicateCaseCount: observation.armTerminalSummary.duplicateCaseCount,
          event: observation.armTerminalSummary.event,
          failureCount: observation.armTerminalSummary.failureCount,
          missingCaseCount: observation.armTerminalSummary.missingCaseCount,
          observedCaseCount: observation.armTerminalSummary.observedCaseCount,
          plannedCaseCount: observation.armTerminalSummary.plannedCaseCount,
          protocol: observation.armTerminalSummary.protocol,
          status: observation.armTerminalSummary.status,
          unexpectedCaseCount: observation.armTerminalSummary.unexpectedCaseCount,
        }),
    exit: observation.exit,
    failing: new Set(observation.failing),
    failureEvents: Object.freeze([...observation.failureEvents]),
    fileFailureCount: observation.fileFailureCount,
    findings: observation.findings,
    gate: observation.gate,
    gateFindings: Object.freeze([...observation.gateFindings]),
    gateProtocol: observation.gateProtocol,
    gateProtocolComplete: observation.gateProtocolComplete,
    gateProtocolError: observation.gateProtocolError,
    gateProvenance,
    ms: observation.ms,
    out: observation.out,
    protocolComplete: observation.protocolComplete,
    protocolError: observation.protocolError,
    signal: observation.signal,
    testCount: observation.testCount,
    testEvents: observation.testEvents,
    timedOut: observation.timedOut,
  });
}

const sameGateSubject = (left, right) => left !== null && right !== null
  && left.archiveSha256 === right.archiveSha256
  && left.commit === right.commit
  && left.repository === right.repository
  && left.tree === right.tree;

/**
 * Bind an opt-in gate entry to exact verified authority semantics without weakening legacy entries.
 *
 * The registry owns every static claim. The clean observation owns the exact candidate subject and
 * initial control-manifest digest. A mutation must change the manifest bytes but never the Git
 * subject. If the caller performs a separately guarded post-restore observation, that phase must
 * return to both exact baseline values. The registry does not claim that every entry performs that
 * optional third observation; setup-integrity entries are the current callers that do.
 */
export function gateProvenanceProblem(
  observation,
  expected,
  { phase = "baseline", baselineProvenance = null } = {},
) {
  if (expected === undefined) return null;
  if (!["baseline", "mutated", "post-restore"].includes(phase)) {
    throw new Error(`unknown gate provenance phase ${JSON.stringify(phase)}`);
  }
  if (observation === null || typeof observation !== "object" || Array.isArray(observation)) {
    return `${phase} gate provenance observation is not an object`;
  }
  if (observation.gateProtocol !== expected.protocol) {
    return `${phase} gate protocol ${JSON.stringify(observation.gateProtocol)} does not equal ` +
      `${JSON.stringify(expected.protocol)}`;
  }
  const provenance = observation.gateProvenance;
  if (provenance === null || typeof provenance !== "object" || Array.isArray(provenance)) {
    return `${phase} gate omitted its required provenance`;
  }
  for (const key of EXPECTED_GATE_PROVENANCE_KEYS) {
    if (key === "protocol" || key === "subjectBinding" || key === "controlManifestBinding") continue;
    if (provenance[key] !== expected[key]) {
      return `${phase} gate provenance ${key} ${JSON.stringify(provenance[key])} does not equal ` +
        `${JSON.stringify(expected[key])}`;
    }
  }
  if (phase === "baseline") return null;
  if (baselineProvenance === null || typeof baselineProvenance !== "object"
      || Array.isArray(baselineProvenance)) {
    return `${phase} gate provenance has no exact clean-baseline binding`;
  }
  if (!sameGateSubject(provenance.subject, baselineProvenance.subject)) {
    return `${phase} gate provenance subject differs from the exact clean candidate`;
  }
  if (phase === "mutated"
      && expected.controlManifestBinding === CHANGING_GATE_CONTROL_MANIFEST_BINDING
      && provenance.controlManifestDigest === baselineProvenance.controlManifestDigest) {
    return "mutated gate provenance did not bind the changed reviewed-control manifest";
  }
  if (phase === "post-restore"
      && provenance.controlManifestDigest !== baselineProvenance.controlManifestDigest) {
    return "post-restore gate provenance did not return to the exact clean control manifest";
  }
  return null;
}

function setupIntegrityTerminalProblem(observation, expected, phase) {
  if (observation.armTerminalProtocolComplete !== true || observation.armTerminalSummary === null) {
    return `${phase} arm terminal evidence is incomplete ` +
      `(${observation.armTerminalProtocolError ?? "unknown terminal protocol failure"})`;
  }
  const summary = observation.armTerminalSummary;
  const baseline = phase === "baseline" || phase === "post-restore";
  const expectedDigest = baseline
    ? expected.baselineCasePlanSha256 : expected.mutatedCasePlanSha256;
  const expectedCount = baseline ? expected.baselineCaseCount : expected.mutatedCaseCount;
  const expectedStatus = baseline ? "PASS" : expected.terminalStatus;
  const expectedFailureCount = baseline ? 0 : 1;
  if (
    summary.protocol !== expected.terminalProtocol || summary.status !== expectedStatus ||
    summary.casePlanSha256 !== expectedDigest || summary.plannedCaseCount !== expectedCount ||
    summary.observedCaseCount !== expectedCount || summary.failureCount !== expectedFailureCount ||
    summary.missingCaseCount !== 0 || summary.unexpectedCaseCount !== 0 ||
    summary.duplicateCaseCount !== 0
  ) {
    return `${phase} arm terminal evidence does not match its exact reviewed ` +
      `${expectedStatus}/${expectedCount}/${expectedDigest} contract`;
  }
  return null;
}

/** A setup-integrity lane still requires an ordinary green, finding-free clean baseline. */
export function setupIntegrityBaselineProblem(observation, expected, phase = "baseline") {
  if (phase !== "baseline" && phase !== "post-restore") {
    throw new Error(`unknown setup-integrity baseline phase ${JSON.stringify(phase)}`);
  }
  const gateProblem = gateObservationProblem(observation, "baseline");
  if (gateProblem !== null) return gateProblem;
  return setupIntegrityTerminalProblem(observation, expected, phase);
}

const SETUP_INTEGRITY_DETAIL_KEYS = Object.freeze([
  "actualCasePlanSha256", "diagnosticExpectedCaseCount", "diagnosticPlannedCaseCount",
  "duplicateCaseCount", "missingCaseIds", "reviewedCasePlanSha256", "unexpectedCaseCount",
]);

/**
 * Accept only the one closed setup-integrity result described by the registry entry. Generic exit 2,
 * crashes, timeouts, unrelated findings, and malformed/duplicate terminal records remain invalid.
 */
export function setupIntegrityMutationProblem(observation, expected, expectedGateFindings) {
  if (observation === null || typeof observation !== "object" || Array.isArray(observation)) {
    return "mutated setup-integrity observation is not an object";
  }
  if (observation.timedOut !== false) return "mutated setup-integrity observation timed out";
  if (observation.signal !== null) return "mutated setup-integrity observation ended by signal";
  if (observation.gateProtocolComplete !== true) {
    return `mutated setup-integrity gate record is incomplete ` +
      `(${observation.gateProtocolError ?? "unknown gate protocol failure"})`;
  }
  if (observation.exit !== expected.exitCode) {
    return `mutated setup-integrity exit ${JSON.stringify(observation.exit)} does not equal ` +
      `${expected.exitCode}`;
  }
  if (!Array.isArray(observation.gateFindings)
      || observation.findings !== observation.gateFindings.length) {
    return "mutated setup-integrity finding count is incoherent";
  }
  if (observation.gateFindings.length !== expectedGateFindings.length) {
    return `mutated setup-integrity gate emitted ${observation.gateFindings.length} finding(s), ` +
      `expected exactly ${expectedGateFindings.length}`;
  }
  for (let index = 0; index < expectedGateFindings.length; index++) {
    if (gateFindingIdentity(observation.gateFindings[index])
        !== gateFindingIdentity(expectedGateFindings[index])) {
      return `mutated setup-integrity finding ${index} has the wrong exact identity`;
    }
  }
  const terminalProblem = setupIntegrityTerminalProblem(observation, expected, "mutated");
  if (terminalProblem !== null) return terminalProblem;
  let detail;
  try { detail = JSON.parse(observation.gateFindings[0].detail); }
  catch { return "mutated setup-integrity finding detail is not exact JSON"; }
  if (!exactKeys(detail, SETUP_INTEGRITY_DETAIL_KEYS)) {
    return "mutated setup-integrity finding detail has an unexpected schema";
  }
  if (
    detail.actualCasePlanSha256 !== expected.mutatedCasePlanSha256 ||
    detail.reviewedCasePlanSha256 !== expected.baselineCasePlanSha256 ||
    detail.diagnosticExpectedCaseCount !== expected.baselineCaseCount ||
    detail.diagnosticPlannedCaseCount !== expected.mutatedCaseCount ||
    detail.duplicateCaseCount !== 0 || detail.unexpectedCaseCount !== 0 ||
    !Array.isArray(detail.missingCaseIds) || detail.missingCaseIds.length !== 0
  ) {
    return `mutated setup-integrity finding does not prove exact ` +
      `${expected.stableError} evidence`;
  }
  return null;
}

/**
 * Bind a structured gate record to the process outcome that produced it.
 *
 * The JSON protocol alone cannot distinguish a clean gate, a detected finding, and a setup
 * refusal. A baseline is evidence only when it is green and finding-free. A mutated observation
 * has exactly two coherent states: green with no findings, or exit 1 with one or more findings.
 * Exit 2 is reserved by gates for setup failure and can never certify a load-bearing control.
 */
export function gateObservationProblem(observation, phase = "mutated") {
  if (phase !== "baseline" && phase !== "mutated") {
    throw new Error(`unknown gate observation phase ${JSON.stringify(phase)}`);
  }
  if (observation === null || typeof observation !== "object" || Array.isArray(observation)) {
    return `${phase} gate observation is not an object`;
  }
  if (observation.timedOut !== false) {
    return `${phase} gate observation did not complete before its timeout`;
  }
  if (observation.signal !== null) {
    return `${phase} gate observation ended by ${observation.signal ?? "an unknown signal"}`;
  }
  if (observation.gateProtocolComplete !== true) {
    return `${phase} gate produced no completed structured terminal record ` +
      `(${observation.gateProtocolError ?? "unknown protocol failure"})`;
  }
  if (!Number.isInteger(observation.exit)) {
    return `${phase} gate produced no integer exit status`;
  }
  if (!Array.isArray(observation.gateFindings)) {
    return `${phase} gate findings are not an array`;
  }
  const findingCount = observation.gateFindings.length;
  if (observation.findings !== findingCount) {
    return `${phase} gate finding count ${JSON.stringify(observation.findings)} disagrees with ` +
      `${findingCount} structured finding(s)`;
  }
  if (phase === "baseline") {
    if (observation.exit !== 0 || findingCount !== 0) {
      return `clean gate baseline must be exit 0 with zero findings; observed exit ` +
        `${observation.exit} with ${findingCount} finding(s)`;
    }
    return null;
  }
  if (observation.exit === 0 && findingCount === 0) return null;
  if (observation.exit === 1 && findingCount > 0) return null;
  return `mutated gate outcome is incoherent: exit ${observation.exit} with ` +
    `${findingCount} finding(s); only exit 0/zero findings or exit 1/non-zero findings is evidence`;
}

/**
 * A test suite may deliberately prove a hang detector. A structured gate may not: its evidence is
 * the completed terminal record, so a timeout means the evidence channel never completed.
 * Registry validation prevents that declaration; this classifier is the runtime backstop for an
 * unvalidated caller or a future registry-loading regression.
 */
export function timeoutObservationOutcome(kind, expectHang, elapsedMs) {
  if (kind === "gate") {
    return {
      verdict: VERDICT.INVALID_TEST,
      detail: `gate observation timed out after ${elapsedMs}ms without a completed structured ` +
        "terminal record; a timeout is never gate detection evidence",
    };
  }
  if (kind !== "tests") {
    throw new Error(`unknown timeout observation kind ${JSON.stringify(kind)}`);
  }
  if (expectHang === true) {
    return {
      verdict: VERDICT.TIMEOUT_WITH_EXPECTED_SYMPTOM,
      detail: `timed out after ${elapsedMs}ms, and this test entry declares a hang as its expected symptom`,
    };
  }
  return {
    verdict: VERDICT.TIMEOUT_UNEXPLAINED,
    detail: `timed out after ${elapsedMs}ms with no hang expected — a harness killing a process is not ` +
      "proof that the control was detected",
  };
}

/** Keep operator baseline output on the same evidence channel the classifier uses. */
export function baselineEvidenceSummary(kind, observation) {
  if (kind === "gate") {
    if (!Array.isArray(observation?.gateFindings)) {
      throw new Error("gate baseline summary requires structured gate findings");
    }
    const findings = observation.gateFindings;
    return {
      count: findings.length,
      label: "pre-existing gate finding(s)",
      details: findings.map((finding) => `${finding.rule}/${finding.subject}`),
    };
  }
  if (kind === "tests") {
    if (!(observation?.failing instanceof Set)) {
      throw new Error("test baseline summary requires a failing-test set");
    }
    const failures = [...observation.failing];
    return {
      count: failures.length,
      label: "pre-existing test failure(s)",
      details: failures,
    };
  }
  throw new Error(`unknown baseline evidence kind ${JSON.stringify(kind)}`);
}

/**
 * Execute one knockout with full evidence capture.
 *
 * @param {object} o
 * @param {string} o.root          repository root
 * @param {object} o.entry         the registry entry
 * @param {object[]} [o.registry]  same registry used to resolve entry.andAlso
 * @param {object} o.baseline      { exit, failing:Set, ms } for this entry's suite, measured CLEAN
 * @param {number} [o.timeoutMs]
 * @param {object} [o.guard]       derived-state guard; defaults to the one for this root
 * @param {object} [o.dependencies] exact-ref descriptors resolved for this entry
 * @returns {object} evidence record
 */
export function runKnockout({
  root, entry, registry = [entry], baseline, timeoutMs = 900_000, guard = buildStateGuardFor(root),
  boundaryBootstrapToken = null, dependencies = {}, setupIntegrityPostcheck = "inline",
  workspaceMode = "restoring",
}) {
  if (!["inline", "deferred"].includes(setupIntegrityPostcheck)) {
    throw new Error(`unknown setup-integrity postcheck mode ${JSON.stringify(setupIntegrityPostcheck)}`);
  }
  if (!["disposable", "restoring"].includes(workspaceMode)) {
    throw new Error(`unknown knockout workspace mode ${JSON.stringify(workspaceMode)}`);
  }
  const registryById = validateKnockoutRegistry(registry);
  const paired = entry.andAlso === undefined ? null : registryById.get(entry.andAlso);
  const ev = {
    id: entry.id,
    control: entry.control,
    file: entry.file,
    suite: entry.suite[0],
    baselineExit: baseline.exit,
    baselineFailing: [...baseline.failing].sort(),
    baselineFailureEvents: baseline.failureEvents ?? [],
    workspaceDisposition: workspaceMode === "disposable"
      ? "RETAINED_UNMODIFIED_ARM"
      : "RESTORED_IN_PLACE",
  };

  // A red or incoherent gate baseline cannot become a measuring instrument merely because a
  // mutation adds one more expected finding. Refuse before reading or changing any target byte.
  if (entry.kind === "gate") {
    const baselineProblem = gateObservationProblem(baseline, "baseline");
    if (baselineProblem !== null) {
      ev.verdict = VERDICT.INVALID_TEST;
      ev.detail = `entry declares kind "gate" but its CLEAN baseline is invalid: ${baselineProblem}`;
      ev.restored = true;
      return ev;
    }
    if (baseline.gate !== entry.gateId) {
      ev.verdict = VERDICT.INVALID_TEST;
      ev.detail =
        `clean gate identity ${JSON.stringify(baseline.gate)} does not match the registry-bound ` +
        `${JSON.stringify(entry.gateId)}`;
      ev.restored = true;
      return ev;
    }
    const baselineProvenanceProblem = gateProvenanceProblem(
      baseline,
      entry.expectedGateProvenance,
      { phase: "baseline" },
    );
    if (baselineProvenanceProblem !== null) {
      ev.verdict = VERDICT.INVALID_TEST;
      ev.detail = `CLEAN gate authority evidence is invalid: ${baselineProvenanceProblem}`;
      ev.restored = true;
      return ev;
    }
    if (entry.expectedGateProvenance !== undefined) {
      ev.baselineGateProtocol = baseline.gateProtocol;
      ev.baselineGateProvenance = baseline.gateProvenance;
    }
    if (entry.expectedSetupIntegrity !== undefined) {
      const integrityProblem = setupIntegrityBaselineProblem(
        baseline,
        entry.expectedSetupIntegrity,
      );
      if (integrityProblem !== null) {
        ev.verdict = VERDICT.INVALID_TEST;
        ev.detail = `setup-integrity CLEAN baseline is invalid: ${integrityProblem}`;
        ev.restored = true;
        return ev;
      }
      ev.baselineArmTerminal = baseline.armTerminalSummary;
    }
  }

  if (paired) ev.andAlso = paired.id;

  const mutations = [entry, ...(paired ? [paired] : [])];
  const targets = [...new Set(mutations.flatMap((mutation) => [
    mutation.file,
    ...(mutation.companionFile ? [mutation.companionFile] : []),
  ]))];
  const pristine = new Map();
  const pristineNodes = new Map();
  // Exact bytes the runner itself wrote. Restoration may overwrite only these bytes; if a suite or
  // concurrent editor changed a target again, preserving that unexpected change is safer than
  // silently erasing work and calling the pristine hash proof.
  const written = new Map();
  const targetIdentityDescriptors = [];
  let targetOperationError = null;

  // Keep the observed inode alive through execution and final custody checks. A closed descriptor
  // permits an unlink/create sequence to reuse the same device+inode number on Linux, making an
  // unrelated replacement look like the original target even when its bytes are identical.
  try {
  // ── (1) baseline hashes, captured BEFORE anything is touched ──────────────────────────────────
  for (const rel of targets) {
    const abs = path.join(root, rel);
    const observed = observeFileNoFollow(abs, targetIdentityDescriptors);
    if (observed === null) throw new IncompleteSnapshotError(`${rel} vanished before mutation setup`);
    pristineNodes.set(rel, observed);
    pristine.set(rel, observed.bytes.toString("utf8"));
  }
  ev.hashBefore = Object.fromEntries([...pristine].map(([k, v]) => [k, sha(v)]));

  try {
    // ── stage every mutation in memory, requiring EXACTLY ONE match for every edit ─────────────
    // Nothing reaches disk until BOTH halves of an andAlso pair have proven applicable.
    const mutated = new Map(pristine);
    for (const mutation of mutations) {
      const edits = [{ find: mutation.find, replace: mutation.replace }, ...(mutation.also ?? [])];
      let src = mutated.get(mutation.file);
      const mutationHashBefore = sha(src);
      for (const e of edits) {
        const hits = src.split(e.find).length - 1;
        if (hits !== 1) {
          ev.verdict = entry.expectedSetupIntegrity === undefined
            ? VERDICT.MUTATION_NOT_APPLIED : VERDICT.INVALID_TEST;
          ev.detail = `${mutation.id}: \`find\` matched ${hits}× (must be exactly 1) — the control moved or the entry rotted`;
          return ev;
        }
        src = src.replace(e.find, e.replace);
      }

      // ── (2) EACH mutation must actually CHANGE its target bytes ─────────────────────────────
      if (sha(src) === mutationHashBefore) {
        ev.verdict = VERDICT.MUTATION_NOT_APPLIED;
        ev.detail =
          `${mutation.id}: the mutated bytes are IDENTICAL to the original — \`replace\` is a no-op, ` +
          "so any suite result would be about something else. This is the exact shape that let a " +
          "no-op score a kill.";
        return ev;
      }
      mutated.set(mutation.file, src);
    }

    // Two individually effective same-file mutations can cancel (A→B followed by B→A). Running the
    // clean suite after that sequence would not be a paired measurement.
    for (const mutation of mutations) {
      if (sha(mutated.get(mutation.file)) === ev.hashBefore[mutation.file]) {
        ev.verdict = VERDICT.MUTATION_NOT_APPLIED;
        ev.detail =
          `the combined mutation sequence leaves ${mutation.file} byte-identical to its pristine ` +
          `content — the pair cancelled itself before the suite ran`;
        return ev;
      }
    }

    const toWrite = new Map();
    for (const [rel, src] of mutated) {
      if (sha(src) !== ev.hashBefore[rel]) toWrite.set(rel, src);
    }
    if (entry.expectedSetupIntegrity !== undefined
        && (toWrite.size !== 1 || !toWrite.has(entry.file))) {
      ev.verdict = VERDICT.INVALID_TEST;
      ev.detail = "setup-integrity mutation did not resolve to exactly its one declared target file";
      return ev;
    }
    // ARMED BEFORE THE FIRST BYTE REACHES DISK. The snapshot of every derived artefact, and the
    // on-disk marker that lets the NEXT run undo this arm, must both exist before the mutation does
    // — a marker written afterwards describes a window it was not covering. And if the snapshot
    // cannot be taken, the mutation does NOT happen: an experiment that cannot promise to give the
    // tree back is not run at a lower standard, it is refused.
    try {
      guard.beginArm({
        entryId: entry.id,
        // pristine AND mutant bytes. A crash recovery may only touch a file that still holds the
        // exact mutation this arm wrote; without the mutant hash, "differs from pristine" also
        // matches a legitimate edit made after the crash, and recovery would revert a human.
        sources: [...toWrite].map(([rel, mutant]) => [rel, pristine.get(rel), mutant]),
      });
    } catch (e) {
      ev.verdict = VERDICT.RESTORATION_FAILED;
      ev.detail =
        `the derived-state guard could not snapshot this tree (${String(e && e.message)}), so NOTHING ` +
        `was mutated and no experiment was performed. A knockout that cannot promise to restore the ` +
        `build state must not create one.`;
      return ev;
    }
    // `written` is populated only as bytes actually reach disk, so the restore loop in `finally`
    // never tries to un-write a mutation that was never applied.
    for (const [rel, src] of toWrite) {
      written.set(rel, src);
      rewriteObservedFileNoFollow(
        path.join(root, rel),
        Buffer.from(src),
        pristineNodes.get(rel),
      );
    }
    ev.hashMutated = sha(mutated.get(entry.file));
    if (paired) {
      ev.hashMutatedByFile = Object.fromEntries(
        [...mutated].map(([rel, src]) => [rel, sha(src)]),
      );
    }

    const obs = projectKnockoutObservation(
      observeSuite(root, entry.suite, timeoutMs, {
        boundaryBootstrapToken,
        dependencies,
        kind: entry.kind,
      }),
    );
    ev.mutatedExit = obs.exit;
    ev.mutatedMs = obs.ms;
    ev.mutatedSignal = obs.signal;
    ev.mutatedFailing = [...obs.failing].sort();
    ev.mutatedFailureEvents = obs.failureEvents;
    ev.stderrTail = obs.out.slice(-400);

    // ── (3)(4) classify against the KNOWN baseline ─────────────────────────────────────────────
    if (obs.timedOut) {
      const outcome = timeoutObservationOutcome(entry.kind, entry.expectHang === true, obs.ms);
      ev.verdict = outcome.verdict;
      ev.detail = outcome.detail;
      return ev;
    }

    const newFailureEvents = newFailureEventsBeyondBaseline(
      obs.failureEvents,
      baseline.failureEvents ?? [],
    );
    const newFailures = [...new Set(newFailureEvents.map((event) => event.name))];
    ev.newFailureEvents = newFailureEvents;
    ev.newFailures = newFailures;
    ev.baselineFindings = baseline.findings ?? 0;
    ev.mutatedFindings = obs.findings ?? 0;
    ev.baselineGate = baseline.gate ?? null;
    ev.mutatedGate = obs.gate ?? null;
    ev.baselineGateFindings = baseline.gateFindings ?? [];
    ev.mutatedGateFindings = obs.gateFindings ?? [];
    ev.newGateFindings = newGateFindingsBeyondBaseline(
      obs.gateFindings ?? [],
      baseline.gateFindings ?? [],
    );

    // ── QA-16: THE SUITE KIND IS DECLARED, NEVER INFERRED ─────────────────────────────────────
    // What stood here was:
    //     const isTestSuite = baseline.failing.size > 0 || ev.mutatedFailing.length > 0;
    // i.e. "it is a test suite if we saw failures". A GREEN compiled package whose mutation does
    // not build produces no failures on either side, so it was classified a GATE and its build
    // error was scored DETECTOR_TRIGGERED. Measured; see VERDICT.MUTATION_DID_NOT_BUILD.
    //
    // The declaration was schema-validated before any baseline or mutation. It is then
    // CROSS-CHECKED against the measured clean baseline rather than trusted: an entry that calls
    // itself a test suite whose baseline printed no test footer is a broken entry, and saying so is
    // the whole point of a taxonomy that can express "I could not measure this".
    const declared = entry.kind;
    if (declared === "tests") {
      if (
        baseline.protocolComplete !== true || !Number.isInteger(baseline.testCount) ||
        baseline.testCount < 1 || (baseline.fileFailureCount ?? 0) > 0
      ) {
        ev.verdict = VERDICT.INVALID_TEST;
        ev.detail =
          `entry declares kind "tests" but its CLEAN baseline produced no completed structured ` +
          `node:test protocol with at least one authored test and no file-wrapper failure — the ` +
          `declaration and suite disagree`;
        return ev;
      }
      if (
        obs.protocolComplete !== true || !Number.isInteger(obs.testCount) || obs.testCount < 1 ||
        obs.fileFailureCount > 0
      ) {
        ev.verdict = VERDICT.MUTATION_DID_NOT_BUILD;
        ev.detail =
          `the mutated suite produced no completed structured node:test protocol with at least one ` +
          `authored test and no file-wrapper failure (exit ${obs.exit}; ` +
          `${obs.protocolError ?? (obs.fileFailureCount > 0 ? `${obs.fileFailureCount} file-wrapper failure(s)` : "zero tests")}), ` +
          `so the replacement did not ` +
          `reach a measurable test run. Presentation text cannot substitute for runner events.`;
        return ev;
      }
      if (obs.exit === 0) {
        ev.verdict = VERDICT.DETECTOR_DID_NOT_TRIGGER;
        ev.detail = "the suite stayed GREEN without this control";
        return ev;
      }
      // Only a runner-owned FAIL event from a completed protocol may certify a test knockout.
      if (newFailureEvents.length > 0) {
        ev.verdict = VERDICT.DETECTOR_TRIGGERED;
        ev.detail = `${newFailureEvents.length} NEW authenticated authored-site failure(s) beyond baseline: ${newFailures.slice(0, 3).join("; ")}`;
        return ev;
      }
      ev.verdict = VERDICT.ANTI_VACUITY_FAILED;
      ev.detail =
        `the suite failed, but ONLY with the ${baseline.failing.size} failure(s) its baseline already had` +
        (baseline.failing.size ? ` (${[...baseline.failing].join("; ")})` : "") +
        `. Nothing new broke, so this knockout measured the pre-existing failures rather than its own control.`;
      return ev;
    }
    {
      const mutatedProvenanceProblem = gateProvenanceProblem(
        obs,
        entry.expectedGateProvenance,
        {
          baselineProvenance: baseline.gateProvenance,
          phase: "mutated",
        },
      );
      if (mutatedProvenanceProblem !== null) {
        ev.verdict = VERDICT.INVALID_TEST;
        ev.detail = `mutated gate authority evidence is invalid: ${mutatedProvenanceProblem}`;
        return ev;
      }
      if (entry.expectedGateProvenance !== undefined) {
        ev.mutatedGateProtocol = obs.gateProtocol;
        ev.mutatedGateProvenance = obs.gateProvenance;
      }
      if (entry.expectedSetupIntegrity !== undefined) {
        if (obs.gate !== entry.gateId) {
          ev.verdict = VERDICT.INVALID_TEST;
          ev.detail =
            `mutated setup-integrity gate identity ${JSON.stringify(obs.gate)} does not match ` +
            `${JSON.stringify(entry.gateId)}`;
          return ev;
        }
        const integrityProblem = setupIntegrityMutationProblem(
          obs,
          entry.expectedSetupIntegrity,
          entry.expectedGateFindings,
        );
        if (integrityProblem !== null) {
          ev.verdict = VERDICT.INVALID_TEST;
          ev.detail = integrityProblem;
          return ev;
        }
        ev.mutatedArmTerminal = obs.armTerminalSummary;
        ev.verdict = VERDICT.DETECTOR_TRIGGERED;
        ev.detail =
          `the exact one-ID substitution produced reviewed ${entry.expectedSetupIntegrity.stableError} ` +
          `setup-integrity evidence`;
        return ev;
      }
      const mutatedGateProblem = gateObservationProblem(obs, "mutated");
      if (mutatedGateProblem !== null) {
        ev.verdict = VERDICT.INVALID_TEST;
        ev.detail = `${mutatedGateProblem}; a crash, setup refusal, or presentation text is not detection evidence`;
        return ev;
      }
      if (obs.gate !== entry.gateId) {
        ev.verdict = VERDICT.INVALID_TEST;
        ev.detail =
          `mutated gate identity ${JSON.stringify(obs.gate)} does not match the registry-bound ` +
          `${JSON.stringify(entry.gateId)}`;
        return ev;
      }
      if (obs.exit === 0) {
        ev.verdict = VERDICT.DETECTOR_DID_NOT_TRIGGER;
        ev.detail = "the suite stayed GREEN without this control";
        return ev;
      }
      const actualFindingIdentities = new Set(ev.newGateFindings.map(gateFindingIdentity));
      const missingExpectedFindings = entry.expectedGateFindings.filter(
        (finding) => !actualFindingIdentities.has(gateFindingIdentity(finding)),
      );
      if (missingExpectedFindings.length === 0) {
        ev.verdict = VERDICT.DETECTOR_TRIGGERED;
        ev.detail =
          `the registry-bound gate reported every expected exact finding among ` +
          `${ev.newGateFindings.length} new finding(s): ` +
          `${entry.expectedGateFindings.map((finding) => `${finding.rule}/${finding.subject}`).join("; ")}`;
        return ev;
      }
      ev.verdict = VERDICT.DETECTOR_DID_NOT_TRIGGER;
      ev.detail =
        `the registry-bound gate did not emit expected exact finding(s): ` +
        `${missingExpectedFindings.map((finding) => `${finding.rule}/${finding.subject}`).join("; ")}. ` +
        `Unrelated findings cannot prove this control.`;
      return ev;
    }
  } finally {
    if (workspaceMode === "disposable") {
      // Option-B disposable arms are retained evidence. Rewriting their mutant bytes to pristine
      // would add destructive authority and duplicate work without protecting the read-only source.
      // A zero-write early semantic refusal remains unmodified; a started mutation remains exactly
      // as the arm produced it for later inspection.
      ev.hashAfter = {};
      const retainedTargetProblems = [];
      for (const rel of targets) {
        try {
          const observed = observeFileNoFollow(path.join(root, rel));
          const before = pristineNodes.get(rel);
          const expectedBytes = written.get(rel) ?? pristine.get(rel);
          ev.hashAfter[rel] = observed?.sha ?? null;
          if (observed === null) retainedTargetProblems.push(`${rel} is missing from the retained arm`);
          else if (before === undefined || expectedBytes === undefined) {
            retainedTargetProblems.push(`${rel} has no exact pre-mutation custody record`);
          } else if (observed.identity !== before.identity) {
            retainedTargetProblems.push(`${rel} was replaced by a different inode in the retained arm`);
          } else if (observed.nlink !== 1 || before.nlink !== 1) {
            retainedTargetProblems.push(`${rel} is not the exact retained single-link inode`);
          } else if (observed.mode !== before.mode) {
            retainedTargetProblems.push(
              `${rel} mode changed from ${before.mode.toString(8)} to ${observed.mode.toString(8)}`,
            );
          } else if (!observed.bytes.equals(Buffer.from(expectedBytes))) {
            retainedTargetProblems.push(`${rel} does not retain the exact expected bytes`);
          }
        } catch (error) {
          ev.hashAfter[rel] = null;
          retainedTargetProblems.push(
            `${rel} could not be re-observed in the retained arm: ${String(error && error.message)}`,
          );
        }
      }
      ev.restored = written.size === 0 && retainedTargetProblems.length === 0;
      ev.workspaceDisposition = retainedTargetProblems.length > 0
        ? "RETAINED_DISPOSABLE_ARM_DRIFTED"
        : written.size === 0
          ? "RETAINED_UNMODIFIED_ARM"
          : "RETAINED_DISPOSABLE_MUTANT";
      if (retainedTargetProblems.length > 0) {
        ev.verdict = VERDICT.INVALID_TEST;
        ev.detail = `retained disposable-arm state is invalid: ${retainedTargetProblems.join("; ")}`;
      }
      if (written.size > 0 && retainedTargetProblems.length === 0) {
        try {
          if (guard.commitRetainedArm() !== true) {
            throw new IncompleteSnapshotError("the guard did not confirm retained-arm commit");
          }
        } catch (error) {
          retainedTargetProblems.push(
            `retained-arm recovery authority was not closed: ${String(error && error.message)}`,
          );
          ev.restored = false;
          ev.workspaceDisposition = "RETAINED_DISPOSABLE_ARM_DRIFTED";
          ev.verdict = VERDICT.INVALID_TEST;
          ev.detail = `retained disposable-arm state is invalid: ${retainedTargetProblems.join("; ")}`;
        }
      }
      if (entry.expectedSetupIntegrity !== undefined && setupIntegrityPostcheck === "deferred") {
        ev.postRestoreBaselineVerified = false;
      }
    } else {
    // ── (5) restore, and PROVE it ─────────────────────────────────────────────────────────────
    const restorationFailures = [];
    const preservedConcurrentSources = [];
    for (const [rel, expectedMutant] of written) {
      try {
        const abs = path.join(root, rel);
        const current = observeFileNoFollow(abs);
        if (current === null) throw new IncompleteSnapshotError(`${rel} vanished while the suite ran`);
        const currentSha = current.sha;
        if (currentSha !== sha(expectedMutant)) {
          restorationFailures.push(
            `${rel} changed unexpectedly while the suite ran; refusing to overwrite a concurrent edit`,
          );
          if (currentSha !== sha(pristine.get(rel))) {
            preservedConcurrentSources.push({
              identity: current.identity,
              nlink: current.nlink,
              rel,
              sha256: currentSha,
            });
          }
          continue;
        }
        rewriteObservedFileNoFollow(abs, Buffer.from(pristine.get(rel)), current);
      } catch (e) {
        restorationFailures.push(`could not restore ${rel}: ${String(e && e.message)}`);
      }
    }

    // ── (5b) the DERIVED state goes back too, before anything else can consume it ───────────────
    // Source first (above), then everything compiled or generated from it. The order matters only
    // in one direction: nothing may read this tree between the two, and nothing does — both happen
    // inside the same synchronous `finally`.
    let derived = null;
    let derivedOk = true;
    try {
      derived = guard.endArm({ preservedConcurrentSources });
    } catch (e) {
      derivedOk = false;
      // A guard that throws must not swallow the verdict this arm just produced, and must not be
      // reported as a clean restore either.
      restorationFailures.push(`the derived-state guard threw while restoring: ${String(e && e.message)}`);
    }
    if (derived !== null) {
      ev.buildState = {
        artifactsRestored: derived.artifactsRestored,
        artifactsRemoved: derived.artifactsRemoved,
        trackedReverted: derived.trackedReverted,
        untrackedAdditions: derived.untrackedAdditions,
        ms: derived.ms,
      };
      for (const failure of derived.failures) restorationFailures.push(failure);
      for (const added of derived.untrackedAdditions) {
        restorationFailures.push(
          `the mutated suite created ${added}, which git does not track. It is left on disk rather ` +
          `than deleted — this runner does not remove a file it cannot prove it created — so the ` +
          `tree is NOT as the arm found it`,
        );
      }
    }

    ev.hashAfter = {};
    for (const rel of targets) {
      try {
        ev.hashAfter[rel] = sha(readFileNoFollow(path.join(root, rel)).toString("utf8"));
      } catch (e) {
        ev.hashAfter[rel] = null;
        restorationFailures.push(`could not hash restored ${rel}: ${String(e && e.message)}`);
      }
      if (
        ev.hashAfter[rel] !== ev.hashBefore[rel] &&
        !restorationFailures.some((detail) => detail.startsWith(`${rel} `))
      ) {
        restorationFailures.push(
          `${rel} did not return to its baseline sha256 — a weakened control may be on disk`,
        );
      }
    }
    // "Restored" means the tree, not the source file. A run that returns `src/` byte-for-byte and
    // leaves a mutant `dist/` behind has restored nothing that matters to whatever runs next.
    ev.restored =
      targets.every((rel) => ev.hashAfter[rel] === ev.hashBefore[rel]) && derivedOk &&
      (derived === null || (derived.failures.length === 0 && derived.untrackedAdditions.length === 0));
    if (entry.expectedSetupIntegrity !== undefined && setupIntegrityPostcheck === "deferred") {
      ev.postRestoreBaselineVerified = false;
    }
    if (entry.expectedSetupIntegrity !== undefined && setupIntegrityPostcheck === "inline" && written.size === 1
        && restorationFailures.length === 0 && ev.restored) {
      let postRestore = null;
      let postRestorePhaseStarted = false;
      let postRestoreState = null;
      ev.postRestoreBaselineVerified = false;
      try {
        const workTreeState = gitWorkTreeState(root);
        if (workTreeState === "unknown") {
          throw new IncompleteSnapshotError(
            "cannot determine Git worktree state before the post-restore observation",
          );
        }
        // This is a second, separately durable phase. The first arm's marker has already closed;
        // no clean re-observation executes in an unguarded gap after restoration proof.
        guard.beginPhase({
          label: `${entry.id}:post-restore-observation`,
          sources: [],
          artifacts: true,
          tracked: "all",
          exactCustodyPaths: targets,
          exactGitIndex: workTreeState === "yes",
        });
        postRestorePhaseStarted = true;
        postRestore = projectKnockoutObservation(
          observeSuite(root, entry.suite, timeoutMs, {
            kind: entry.kind,
            dependencies,
          }),
        );
      } catch (error) {
        restorationFailures.push(
          `post-restore observation custody failed: ${String(error && error.message)}`,
        );
      } finally {
        if (postRestorePhaseStarted) {
          try { postRestoreState = guard.endPhase(); }
          catch (error) {
            restorationFailures.push(
              `post-restore custody guard threw while restoring: ${String(error && error.message)}`,
            );
          }
        }
      }

      if (postRestoreState !== null) {
        ev.postRestoreState = {
          artifactsRemoved: postRestoreState.artifactsRemoved,
          artifactsRestored: postRestoreState.artifactsRestored,
          exactCustodyAdditions: postRestoreState.exactCustodyAdditions,
          exactCustodyRestored: postRestoreState.exactCustodyRestored,
          exactGitIndexChanged: postRestoreState.exactGitIndexChanged,
          exactGitIndexHashAfter: postRestoreState.exactGitIndexHashAfter,
          exactGitIndexHashBefore: postRestoreState.exactGitIndexHashBefore,
          exactGitIndexHashObserved: postRestoreState.exactGitIndexHashObserved,
          exactGitIndexObservationChanged: postRestoreState.exactGitIndexObservationChanged,
          exactGitIndexSemanticChanged: postRestoreState.exactGitIndexSemanticChanged,
          exactGitIndexTreeAfter: postRestoreState.exactGitIndexTreeAfter,
          exactGitIndexTreeBefore: postRestoreState.exactGitIndexTreeBefore,
          exactGitIndexTreeObserved: postRestoreState.exactGitIndexTreeObserved,
          trackedReverted: postRestoreState.trackedReverted,
          untrackedAdditions: postRestoreState.untrackedAdditions,
        };
        for (const failure of postRestoreState.failures) restorationFailures.push(failure);
      }

      // Rehash only AFTER the second guard has returned every node and the complete Git index.
      ev.postRestoreHashAfter = {};
      for (const rel of targets) {
        try {
          ev.postRestoreHashAfter[rel] = sha(readFileNoFollow(path.join(root, rel)).toString("utf8"));
        } catch (error) {
          ev.postRestoreHashAfter[rel] = null;
          restorationFailures.push(
            `could not rehash ${rel} after post-restore custody: ${String(error && error.message)}`,
          );
        }
        if (ev.postRestoreHashAfter[rel] !== ev.hashBefore[rel]) {
          restorationFailures.push(
            `${rel} did not return to its baseline sha256 after post-restore observation`,
          );
        }
      }

      if (postRestore !== null && postRestoreState !== null && restorationFailures.length === 0) {
        ev.postRestoreBaselineExit = postRestore.exit;
        ev.postRestoreArmTerminal = postRestore.armTerminalSummary;
        let postRestoreProblem = postRestore.gate === entry.gateId
          ? setupIntegrityBaselineProblem(
              postRestore,
              entry.expectedSetupIntegrity,
              "post-restore",
            )
          : `post-restore gate identity ${JSON.stringify(postRestore.gate)} does not match ` +
            `${JSON.stringify(entry.gateId)}`;
        if (postRestoreProblem === null) {
          postRestoreProblem = gateProvenanceProblem(
            postRestore,
            entry.expectedGateProvenance,
            {
              baselineProvenance: baseline.gateProvenance,
              phase: "post-restore",
            },
          );
        }
        if (entry.expectedGateProvenance !== undefined) {
          ev.postRestoreGateProtocol = postRestore.gateProtocol;
          ev.postRestoreGateProvenance = postRestore.gateProvenance;
        }
        const postRestoreChangedState =
          postRestoreState.artifactsRestored.length > 0
          || postRestoreState.artifactsRemoved.length > 0
          || postRestoreState.trackedReverted.length > 0
          || postRestoreState.untrackedAdditions.length > 0
          || postRestoreState.exactCustodyRestored.length > 0
          || postRestoreState.exactCustodyAdditions.length > 0
          || postRestoreState.exactGitIndexObservationChanged
          || postRestoreState.exactGitIndexSemanticChanged;
        if (postRestoreProblem === null && !postRestoreChangedState) {
          ev.postRestoreBaselineVerified = true;
        } else {
          ev.verdict = VERDICT.INVALID_TEST;
          ev.detail = postRestoreProblem === null
            ? "setup-integrity post-restore observation modified guarded source, artifact, worktree, or Git-index state"
            : `setup-integrity post-restore clean re-observation failed: ${postRestoreProblem}`;
        }
      }
    }
    if (restorationFailures.length > 0) {
      ev.verdict = VERDICT.RESTORATION_FAILED;
      ev.detail = restorationFailures.join("; ");
    }
    ev.workspaceDisposition = ev.restored === true ? "RESTORED_IN_PLACE" : "RESTORATION_FAILED";
    }
  }
  } catch (error) {
    targetOperationError = error;
    throw error;
  } finally {
    const closeFailures = [];
    for (const fd of targetIdentityDescriptors) {
      try { fs.closeSync(fd); }
      catch (error) { closeFailures.push(error); }
    }
    if (closeFailures.length > 0) {
      throw new AggregateError(
        targetOperationError === null ? closeFailures : [targetOperationError, ...closeFailures],
        "mutation-target identity descriptor cleanup failed",
      );
    }
  }
}

/**
 * Finalize an expectedSetupIntegrity knockout from a fresh, seed-derived POSTCHECK arm. The mutant
 * arm is already terminal and retained as disposable evidence; this function can only downgrade
 * its semantic verdict.
 */
export function finalizeIsolatedSetupIntegrityPostcheck({
  baseline,
  entry,
  postcheck,
  postcheckState,
  result,
}) {
  if (entry?.expectedSetupIntegrity === undefined) {
    throw new Error("fresh setup-integrity postcheck requires an expectedSetupIntegrity entry");
  }
  if (
    result?.id !== entry.id ||
    result.workspaceDisposition !== "RETAINED_DISPOSABLE_MUTANT"
  ) {
    throw new Error("fresh setup-integrity postcheck requires the matching disposable mutant result");
  }
  const stateKeys = [
    "artifactsRemoved", "artifactsRestored", "exactCustodyAdditions", "exactCustodyRestored",
    "exactGitIndexObservationChanged", "exactGitIndexSemanticChanged", "freshArm",
    "trackedReverted", "untrackedAdditions",
  ];
  if (
    postcheckState === null || typeof postcheckState !== "object" || Array.isArray(postcheckState) ||
    Object.keys(postcheckState).sort().join("\0") !== [...stateKeys].sort().join("\0") ||
    postcheckState.freshArm !== true ||
    [
      "artifactsRemoved", "artifactsRestored", "exactCustodyAdditions", "exactCustodyRestored",
      "trackedReverted", "untrackedAdditions",
    ].some((key) => !Array.isArray(postcheckState[key])) ||
    typeof postcheckState.exactGitIndexObservationChanged !== "boolean" ||
    typeof postcheckState.exactGitIndexSemanticChanged !== "boolean"
  ) {
    throw new Error("fresh setup-integrity postcheck state is malformed");
  }
  const finalized = {
    ...result,
    postRestoreArmTerminal: postcheck.armTerminalSummary,
    postRestoreBaselineExit: postcheck.exit,
    postRestoreBaselineVerified: false,
    postRestoreGateProtocol: postcheck.gateProtocol,
    postRestoreGateProvenance: postcheck.gateProvenance,
    postRestoreHashAfter: null,
    postRestoreState: postcheckState,
  };
  let problem = postcheck.gate === entry.gateId
    ? setupIntegrityBaselineProblem(postcheck, entry.expectedSetupIntegrity, "post-restore")
    : `post-restore gate identity ${JSON.stringify(postcheck.gate)} does not match ` +
      `${JSON.stringify(entry.gateId)}`;
  if (problem === null) {
    problem = gateProvenanceProblem(
      postcheck,
      entry.expectedGateProvenance,
      { baselineProvenance: baseline.gateProvenance, phase: "post-restore" },
    );
  }
  const changedState =
    postcheckState.artifactsRestored.length > 0 ||
    postcheckState.artifactsRemoved.length > 0 ||
    postcheckState.trackedReverted.length > 0 ||
    postcheckState.untrackedAdditions.length > 0 ||
    postcheckState.exactCustodyRestored.length > 0 ||
    postcheckState.exactCustodyAdditions.length > 0 ||
    postcheckState.exactGitIndexObservationChanged ||
    postcheckState.exactGitIndexSemanticChanged;
  if (problem === null && !changedState) {
    finalized.postRestoreBaselineVerified = true;
  } else {
    finalized.verdict = VERDICT.INVALID_TEST;
    finalized.detail = problem === null
      ? "setup-integrity fresh postcheck modified guarded source, artifact, worktree, or Git-index state"
      : `setup-integrity fresh postcheck failed: ${problem}`;
  }
  return Object.freeze(finalized);
}

/** Verdicts that count as a control being proven load-bearing. */
export const PASSING = new Set([VERDICT.DETECTOR_TRIGGERED, VERDICT.TIMEOUT_WITH_EXPECTED_SYMPTOM]);

export function createIsolatedCustodyRoot(cacheHome = userCacheHome()) {
  // The account-owned cache home is commonly 0755 on macOS and Linux. It is only the stable
  // discovery parent; candidate bytes never live directly there. The atomically-created NOA leaf
  // is the privacy boundary and must remain an owned, real 0700 directory. Requiring the generic
  // cache home itself to be 0700 contradicts ensureOwnedDir's contract and makes the production CLI
  // fail closed on an otherwise ordinary machine.
  const ownedCacheHome = ensureOwnedDir(path.resolve(cacheHome));
  const parent = ensurePrivateDir(path.join(ownedCacheHome, "noa-knockout-isolated"));
  const custodyRoot = fs.mkdtempSync(path.join(parent, "sweep-"));
  fs.chmodSync(custodyRoot, 0o700);
  return custodyRoot;
}

export const ISOLATED_KNOCKOUT_SWEEP_TIMEOUTS = Object.freeze({
  captureTimeoutMs: KNOCKOUT_WORKSPACE_CAPTURE_TIMEOUT_LIMIT_MS,
  minimumWorkerEnvelopeMs: KNOCKOUT_WORKSPACE_COMMAND_TIMEOUT_LIMIT_MS,
  suiteTimeoutMs: KNOCKOUT_WORKSPACE_ARM_WORKER_TIMEOUT_LIMIT_MS -
    KNOCKOUT_WORKSPACE_COMMAND_TIMEOUT_LIMIT_MS,
  workerTimeoutMs: KNOCKOUT_WORKSPACE_ARM_WORKER_TIMEOUT_LIMIT_MS,
});

function isolatedSweepFailure(code, message, cause = null, details = null) {
  const error = new Error(message, cause === null ? undefined : { cause });
  error.name = "IsolatedKnockoutSweepError";
  error.code = code;
  error.details = details;
  return error;
}

/**
 * Execute the selected knockout registry only in candidate-bound disposable workspaces. This
 * function owns every asynchronous lifecycle edge and returns verdict-bearing bytes only after the
 * cooperative lease has re-opened all worker evidence and revalidated both source and sealed seed.
 * Capture, inner-suite, and outer-worker deadlines are deliberately independent. `timeoutMs` is a
 * compatibility alias for `suiteTimeoutMs`; the worker must retain its fixed cleanup envelope.
 */
export async function runIsolatedKnockoutSweep({
  candidateSubject = null,
  captureTimeoutMs = ISOLATED_KNOCKOUT_SWEEP_TIMEOUTS.captureTimeoutMs,
  custodyRoot: requestedCustodyRoot = null,
  maxRetainedArms,
  maxRetainedBytes,
  onProgress = null,
  rawDependenciesByEntry,
  registry,
  root,
  selected,
  suiteTimeoutMs = undefined,
  timeoutMs = undefined,
  workerTimeoutMs = ISOLATED_KNOCKOUT_SWEEP_TIMEOUTS.workerTimeoutMs,
}) {
  const resolvedSuiteTimeoutMs = suiteTimeoutMs === undefined
    ? (timeoutMs === undefined ? ISOLATED_KNOCKOUT_SWEEP_TIMEOUTS.suiteTimeoutMs : timeoutMs)
    : suiteTimeoutMs;
  if (
    timeoutMs !== undefined && suiteTimeoutMs !== undefined &&
    timeoutMs !== suiteTimeoutMs
  ) {
    throw isolatedSweepFailure(
      "SWEEP_TIMEOUT_INVALID",
      "isolated sweep timeoutMs alias conflicts with suiteTimeoutMs",
    );
  }
  if (
    !Number.isSafeInteger(captureTimeoutMs) || captureTimeoutMs < 1 ||
    captureTimeoutMs > KNOCKOUT_WORKSPACE_CAPTURE_TIMEOUT_LIMIT_MS
  ) {
    throw isolatedSweepFailure(
      "SWEEP_TIMEOUT_INVALID",
      `isolated sweep captureTimeoutMs must be between 1 and ${KNOCKOUT_WORKSPACE_CAPTURE_TIMEOUT_LIMIT_MS}`,
    );
  }
  if (
    !Number.isSafeInteger(resolvedSuiteTimeoutMs) || resolvedSuiteTimeoutMs < 1 ||
    resolvedSuiteTimeoutMs > ISOLATED_KNOCKOUT_SWEEP_TIMEOUTS.suiteTimeoutMs
  ) {
    throw isolatedSweepFailure(
      "SWEEP_TIMEOUT_INVALID",
      `isolated sweep suite timeout must be between 1 and ${ISOLATED_KNOCKOUT_SWEEP_TIMEOUTS.suiteTimeoutMs}`,
    );
  }
  if (
    !Number.isSafeInteger(workerTimeoutMs) || workerTimeoutMs < 1 ||
    workerTimeoutMs > KNOCKOUT_WORKSPACE_ARM_WORKER_TIMEOUT_LIMIT_MS
  ) {
    throw isolatedSweepFailure(
      "SWEEP_TIMEOUT_INVALID",
      `isolated sweep workerTimeoutMs must be between 1 and ${KNOCKOUT_WORKSPACE_ARM_WORKER_TIMEOUT_LIMIT_MS}`,
    );
  }
  if (
    workerTimeoutMs - resolvedSuiteTimeoutMs <
    ISOLATED_KNOCKOUT_SWEEP_TIMEOUTS.minimumWorkerEnvelopeMs
  ) {
    throw isolatedSweepFailure(
      "SWEEP_TIMEOUT_INVALID",
      `isolated sweep workerTimeoutMs must reserve at least ${ISOLATED_KNOCKOUT_SWEEP_TIMEOUTS.minimumWorkerEnvelopeMs}ms beyond the suite timeout`,
    );
  }
  const registryById = validateKnockoutRegistry(registry);
  if (!Array.isArray(selected) || selected.length < 1) {
    throw isolatedSweepFailure("NOTHING_SELECTED", "isolated knockout sweep requires at least one entry");
  }
  if (!(rawDependenciesByEntry instanceof Map)) {
    throw isolatedSweepFailure(
      "DEPENDENCY_MAP_INVALID",
      "isolated knockout sweep requires the exact dependency map produced by registry partitioning",
    );
  }
  if (!(onProgress === null || typeof onProgress === "function")) {
    throw isolatedSweepFailure("PROGRESS_CALLBACK_INVALID", "isolated knockout progress callback is malformed");
  }
  const selectedEntries = selected.map((entry) => {
    const canonical = registryById.get(entry?.id);
    if (canonical === undefined) {
      throw isolatedSweepFailure(
        "SELECTION_INVALID",
        `selected knockout ${JSON.stringify(entry?.id)} is absent from the validated registry`,
      );
    }
    return canonical;
  });
  const boundarySubjectRequired = selectedEntries.some(
    (entry) => entry.expectedGateProvenance !== undefined,
  );
  const boundCandidateSubject = candidateSubject === null
    ? null
    : knockoutCandidateSubject(candidateSubject);
  if (boundarySubjectRequired && boundCandidateSubject === null) {
    throw isolatedSweepFailure(
      "BOUNDARY_SUBJECT_MISSING",
      "a provenance-bound boundary knockout requires one supervisor-observed public candidate subject",
    );
  }
  const sourceRoot = path.resolve(root);
  const registrySha256 = sha(canonicalJsonBytes(registry));
  let capture = null;
  let sourceLease = null;
  let cooperativeLease = null;
  let currentPlan = null;
  let currentArm = null;
  let currentArmId = null;
  let acceptedPredecessorTerminalSha256 = null;
  let closeEvidence = null;
  let selftest = null;
  const baselines = [];
  const mutants = [];
  const postchecks = [];
  const results = [];
  const baselineByKey = new Map();
  const baselineDefinitionByKey = new Map();

  const rawDependenciesFor = (entry) => {
    if (!rawDependenciesByEntry.has(entry.id)) {
      throw isolatedSweepFailure(
        "DEPENDENCY_MAP_INCOMPLETE",
        `raw dependency map omits selected knockout ${entry.id}`,
      );
    }
    const value = rawDependenciesByEntry.get(entry.id);
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
      throw isolatedSweepFailure(
        "DEPENDENCY_DESCRIPTOR_INVALID",
        `raw dependency descriptor for ${entry.id} is malformed`,
      );
    }
    return value;
  };
  const baselineKeyFor = (entry) => knockoutBaselineKeySha256({
    dependencies: rawDependenciesFor(entry),
    kind: entry.kind,
    suite: entry.suite,
  });
  const runOneArm = async ({ armId, role, subject }) => {
    currentArmId = armId;
    currentPlan = admitArmPlan(cooperativeLease, {
      arms: [{ armId, role, subjectSha256: knockoutWorkerSubjectSha256(subject) }],
    });
    currentArm = materializeArm(currentPlan, armId);
    const completed = await runArmWorker(cooperativeLease, currentArm, {
      subject,
      timeoutMs: workerTimeoutMs,
    });
    currentPlan = null;
    currentArm = null;
    currentArmId = null;
    if (completed.status !== "COMPLETE" || completed.workerResult?.status !== "COMPLETE") {
      throw isolatedSweepFailure(
        "ARM_REFUSED",
        `isolated ${role.toLowerCase()} arm ${armId} did not complete`,
        null,
        {
          status: completed.status,
          terminalSha256: completed.terminalPublication?.sha256 ?? null,
        },
      );
    }
    const observedPredecessor = completed.terminalPublication?.terminal
      ?.predecessorTerminalSha256;
    if (observedPredecessor !== acceptedPredecessorTerminalSha256) {
      throw isolatedSweepFailure(
        "TERMINAL_CHAIN_MISMATCH",
        `isolated ${role.toLowerCase()} arm ${armId} does not continue the accepted terminal chain`,
        null,
        {
          expectedPredecessorTerminalSha256: acceptedPredecessorTerminalSha256,
          observedPredecessorTerminalSha256: observedPredecessor ?? null,
          terminalSha256: completed.terminalPublication?.sha256 ?? null,
        },
      );
    }
    acceptedPredecessorTerminalSha256 = completed.terminalPublication.sha256;
    return completed;
  };

  for (const entry of selectedEntries) {
    const baselineKeySha256 = baselineKeyFor(entry);
    if (!baselineDefinitionByKey.has(baselineKeySha256)) {
      baselineDefinitionByKey.set(baselineKeySha256, entry);
    }
  }
  const plannedArmCount = 1 + baselineDefinitionByKey.size + selectedEntries.length +
    selectedEntries.filter((entry) => entry.expectedSetupIntegrity !== undefined).length;
  if (!Number.isSafeInteger(maxRetainedArms) || maxRetainedArms < plannedArmCount) {
    throw isolatedSweepFailure(
      "RETENTION_BUDGET_INSUFFICIENT",
      `isolated sweep requires ${plannedArmCount} retained arms before capture`,
      null,
      { maxRetainedArms: maxRetainedArms ?? null, plannedArmCount },
    );
  }
  if (!Number.isSafeInteger(maxRetainedBytes) || maxRetainedBytes < 1) {
    throw isolatedSweepFailure(
      "RETENTION_BUDGET_INSUFFICIENT",
      "isolated sweep requires an explicit positive retained-byte budget before capture",
    );
  }

  // Do not create even an empty private custody directory for an invalid selection or budget.
  // Admission preflight above is side-effect free; custody begins only after it succeeds.
  const custodyRoot = requestedCustodyRoot === null
    ? createIsolatedCustodyRoot()
    : path.resolve(requestedCustodyRoot);

  try {
    capture = captureAndSealCandidate({
      custodyRoot,
      operationTimeoutMs: captureTimeoutMs,
      sourceRoot,
    });
    const workerPath = path.join(
      capture.workspaceRoot,
      ...KNOCKOUT_WORKER_RELATIVE_PATH.split("/"),
    );
    const workerSha256 = fileSha256(workerPath);
    const custodyOptions = {};
    if (maxRetainedArms !== undefined) custodyOptions.maxRetainedArms = maxRetainedArms;
    if (maxRetainedBytes !== undefined) custodyOptions.maxRetainedBytes = maxRetainedBytes;
    const custody = openKnockoutCustody(capture, custodyOptions);
    sourceLease = acquireSourceLease(custody);
    cooperativeLease = await acquireCooperativeSourceLease(sourceLease);

    const selftestKeySha256 = knockoutSelftestKeySha256();
    const selftestSubject = createKnockoutWorkerSubject({
      operation: KNOCKOUT_WORKER_OPERATIONS.RUN_KNOCKOUT_SELFTEST,
      request: { selftestKeySha256, suiteTimeoutMs: resolvedSuiteTimeoutMs },
      workerSha256,
    });
    const selftestCompleted = await runOneArm({
      armId: "selftest-0001",
      role: "SELFTEST",
      subject: selftestSubject,
    });
    const selftestWire = selftestCompleted.workerResult.observation.selftest;
    const selftestObservation = knockoutBaselineObservationFromWire(selftestWire, {
      workspaceRoot: selftestCompleted.workspaceRoot,
    });
    const selftestProblem = gateObservationProblem(selftestObservation, "baseline");
    if (
      selftestProblem !== null || selftestObservation.gate !== KNOCKOUT_SELFTEST_GATE ||
      selftestObservation.gateProtocol !== GATE_EVENT_PROTOCOL ||
      selftestObservation.gateProvenance !== null ||
      selftestObservation.exit !== 0 || selftestObservation.timedOut ||
      selftestObservation.signal !== null || selftestObservation.findings !== 0 ||
      selftestObservation.gateFindings.length !== 0
    ) {
      throw isolatedSweepFailure(
        "SELFTEST_FAILED",
        `isolated knockout selftest did not establish a clean ${KNOCKOUT_SELFTEST_GATE} gate`,
        null,
        {
          exit: selftestObservation.exit,
          gate: selftestObservation.gate,
          gateFindings: selftestObservation.gateFindings,
          gateProtocol: selftestObservation.gateProtocol,
          gateProtocolError: selftestObservation.gateProtocolError,
          problem: selftestProblem,
          resultSha256: selftestCompleted.resultPublication.sha256,
          signal: selftestObservation.signal,
          terminalSha256: selftestCompleted.terminalPublication.sha256,
          timedOut: selftestObservation.timedOut,
        },
      );
    }
    selftest = Object.freeze({
      observation: selftestObservation,
      resultSha256: selftestCompleted.resultPublication.sha256,
      terminalSha256: selftestCompleted.terminalPublication.sha256,
      wire: selftestWire,
      workspaceRoot: selftestCompleted.workspaceRoot,
    });

    let baselineIndex = 0;
    for (const [baselineKeySha256, entry] of baselineDefinitionByKey) {
      baselineIndex += 1;
      const subject = createKnockoutWorkerSubject({
        operation: KNOCKOUT_WORKER_OPERATIONS.OBSERVE_KNOCKOUT_BASELINE,
        request: {
          baselineKeySha256,
          ...(entry.expectedGateProvenance === undefined
            ? {}
            : { candidateSubject: boundCandidateSubject }),
          dependencies: rawDependenciesFor(entry),
          entryId: entry.id,
          kind: entry.kind,
          registrySha256,
          suite: entry.suite,
          suiteTimeoutMs: resolvedSuiteTimeoutMs,
        },
        workerSha256,
      });
      const armId = `baseline-${String(baselineIndex).padStart(4, "0")}`;
      const completed = await runOneArm({ armId, role: "BASELINE", subject });
      const wire = completed.workerResult.observation.baseline;
      const observation = knockoutBaselineObservationFromWire(wire, {
        workspaceRoot: completed.workspaceRoot,
      });
      const baseline = Object.freeze({
        baselineKeySha256,
        kind: entry.kind,
        observation,
        resultSha256: completed.resultPublication.sha256,
        suite: entry.suite,
        terminalSha256: completed.terminalPublication.sha256,
        wire,
        workspaceRoot: completed.workspaceRoot,
      });
      baselineByKey.set(baselineKeySha256, baseline);
      baselines.push(baseline);
    }

    for (const [index, entry] of selectedEntries.entries()) {
      const baseline = baselineByKey.get(baselineKeyFor(entry));
      if (baseline === undefined) {
        throw isolatedSweepFailure("BASELINE_MISSING", `no baseline exists for ${entry.id}`);
      }
      if (baseline.observation.timedOut) {
        results.push(Object.freeze({
          control: entry.control,
          detail: "the suite's CLEAN baseline timed out, so no mutation result from it can mean anything",
          file: entry.file,
          id: entry.id,
          restored: true,
          suite: entry.suite[0],
          verdict: VERDICT.INVALID_TEST,
        }));
        onProgress?.(Object.freeze({
          completed: index + 1,
          id: entry.id,
          total: selectedEntries.length,
          verdict: VERDICT.INVALID_TEST,
        }));
        continue;
      }
      const pairedEntry = entry.andAlso === undefined ? null : registryById.get(entry.andAlso) ?? null;
      if (entry.andAlso !== undefined && pairedEntry === null) {
        throw isolatedSweepFailure("PAIRED_ENTRY_MISSING", `paired knockout ${entry.andAlso} is absent`);
      }
      const subject = createKnockoutWorkerSubject({
        operation: KNOCKOUT_WORKER_OPERATIONS.RUN_KNOCKOUT,
        request: {
          baseline: baseline.wire,
          baselineResultSha256: baseline.resultSha256,
          baselineTerminalSha256: baseline.terminalSha256,
          ...(entry.expectedGateProvenance === undefined
            ? {}
            : { candidateSubject: boundCandidateSubject }),
          dependencies: rawDependenciesFor(entry),
          entry,
          pairedEntry,
          registrySha256,
          suiteTimeoutMs: resolvedSuiteTimeoutMs,
        },
        workerSha256,
      });
      const armId = `mutant-${String(index + 1).padStart(4, "0")}`;
      const completed = await runOneArm({ armId, role: "MUTANT", subject });
      const mutantWire = completed.workerResult.observation.knockout;
      let result = knockoutResultEvidenceFromWire(mutantWire, {
        baseline: baseline.wire,
        entry,
      });
      mutants.push(Object.freeze({
        entryId: entry.id,
        resultSha256: completed.resultPublication.sha256,
        terminalSha256: completed.terminalPublication.sha256,
        wire: mutantWire,
        workspaceRoot: completed.workspaceRoot,
      }));
      if (![
        "RETAINED_DISPOSABLE_ARM_DRIFTED", "RETAINED_DISPOSABLE_MUTANT",
        "RETAINED_UNMODIFIED_ARM",
      ].includes(result.workspaceDisposition)) {
        throw isolatedSweepFailure(
          "MUTANT_DISPOSITION_INVALID",
          `isolated mutant arm ${entry.id} did not retain a disposable result`,
          null,
          { entryId: entry.id, workspaceDisposition: result.workspaceDisposition },
        );
      }
      if (PASSING.has(result.verdict) && result.workspaceDisposition !== "RETAINED_DISPOSABLE_MUTANT") {
        throw isolatedSweepFailure(
          "MUTANT_DISPOSITION_INVALID",
          `isolated mutant arm ${entry.id} cannot receive credit without exact retained mutant state`,
          null,
          { entryId: entry.id, verdict: result.verdict, workspaceDisposition: result.workspaceDisposition },
        );
      }
      if (
        entry.expectedSetupIntegrity !== undefined &&
        result.workspaceDisposition === "RETAINED_DISPOSABLE_MUTANT"
      ) {
        const postcheckSubject = createKnockoutWorkerSubject({
          operation: KNOCKOUT_WORKER_OPERATIONS.OBSERVE_KNOCKOUT_POSTCHECK,
          request: {
            baseline: baseline.wire,
            baselineResultSha256: baseline.resultSha256,
            baselineTerminalSha256: baseline.terminalSha256,
            ...(entry.expectedGateProvenance === undefined
              ? {}
              : { candidateSubject: boundCandidateSubject }),
            dependencies: rawDependenciesFor(entry),
            entry,
            mutant: mutantWire,
            mutantResultSha256: completed.resultPublication.sha256,
            mutantTerminalSha256: completed.terminalPublication.sha256,
            pairedEntry,
            registrySha256,
            suiteTimeoutMs: resolvedSuiteTimeoutMs,
          },
          workerSha256,
        });
        const postcheckArmId = `postcheck-${String(index + 1).padStart(4, "0")}`;
        const postcheckCompleted = await runOneArm({
          armId: postcheckArmId,
          role: "POSTCHECK",
          subject: postcheckSubject,
        });
        const postcheckWire = postcheckCompleted.workerResult.observation.knockout;
        result = knockoutResultEvidenceFromWire(postcheckWire, {
          baseline: baseline.wire,
          entry,
        });
        if (typeof result.postRestoreBaselineVerified !== "boolean") {
          throw isolatedSweepFailure(
            "POSTCHECK_INCOMPLETE",
            `isolated postcheck arm ${entry.id} omitted its final setup-integrity state`,
          );
        }
        postchecks.push(Object.freeze({
          entryId: entry.id,
          resultSha256: postcheckCompleted.resultPublication.sha256,
          terminalSha256: postcheckCompleted.terminalPublication.sha256,
          wire: postcheckWire,
          workspaceRoot: postcheckCompleted.workspaceRoot,
        }));
      }
      result = Object.freeze({ ...result });
      results.push(result);
      onProgress?.(Object.freeze({
        completed: index + 1,
        id: entry.id,
        total: selectedEntries.length,
        verdict: result.verdict,
      }));
      if (result.verdict === VERDICT.RESTORATION_FAILED) {
        throw isolatedSweepFailure(
          "MUTANT_ARM_RESTORATION_FAILED",
          `isolated mutant arm ${entry.id} reported a restoration failure in disposable mode`,
          null,
          { entryId: entry.id, verdict: result.verdict },
        );
      }
    }

    closeEvidence = await closeCooperativeSourceLease(cooperativeLease);
    cooperativeLease = null;
    sourceLease = null;
    return Object.freeze({
      baselines: Object.freeze(baselines),
      candidateManifestSha256: capture.candidateManifestSha256,
      closeEvidence,
      custodyRoot,
      mutants: Object.freeze(mutants),
      postchecks: Object.freeze(postchecks),
      results: Object.freeze(results),
      retainedPrivateRoots: closeEvidence.sourceRelease.retainedPrivateRoots,
      selftest,
      sourceSnapshotSha256: closeEvidence.sourceRelease.sourceSnapshotSha256,
      status: "COMPLETE",
    });
  } catch (primary) {
    let closeFailure = null;
    if (cooperativeLease !== null) {
      if (currentPlan !== null && currentArmId !== null) {
        try {
          if (currentArm === null) cancelAdmittedArm(currentPlan, currentArmId, "SWEEP_ABORTED");
          else cancelMaterializedArm(cooperativeLease, currentArm, "SWEEP_ABORTED");
        } catch {}
      }
      try { await closeCooperativeSourceLease(cooperativeLease); }
      catch (error) { closeFailure = error; }
      cooperativeLease = null;
      sourceLease = null;
    } else if (sourceLease !== null) {
      try { releaseSourceLease(sourceLease); }
      catch (error) { closeFailure = error; }
      sourceLease = null;
    }
    if (closeFailure !== null) {
      throw isolatedSweepFailure(
        "SWEEP_AND_CLOSE_FAILED",
        "isolated knockout sweep failed and its lease close was not proven",
        new AggregateError([primary, closeFailure]),
        { custodyRoot },
      );
    }
    if (primary !== null && typeof primary === "object") {
      if (primary.details === null || primary.details === undefined) primary.details = { custodyRoot };
      else if (typeof primary.details === "object" && !Array.isArray(primary.details)) {
        primary.details = { ...primary.details, custodyRoot };
      }
    }
    throw primary;
  }
}
