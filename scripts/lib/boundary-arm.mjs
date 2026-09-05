/**
 * boundary-arm.mjs — L12's ARM: the thing that proves the gate can still bite.
 *
 * ─── THE TRAP THIS IS BUILT AROUND ───────────────────────────────────────────────────────────────
 *
 * The neighbouring surface lint records it in its own source: a violation planted in `src/` produced
 * ZERO findings and read as "the gate is clean" — TWICE, on a control being introduced as coverage.
 * The file was never in the enumerated set. A pure fixture can prove a scanner FIRES; nothing but a
 * plant in the REAL enumerated surface can prove the gate LOOKS THERE.
 *
 * So this arm does not test strings. It builds a real git repository in a scratch directory, copies
 * the gate BYTE-FOR-BYTE into it, and then, for every one of the eight lanes:
 *
 *   1. plants a canary where only THAT lane's enumerator can reach it,
 *   2. requires the gate to exit 1 and name it,
 *   3. removes it, and requires the same lane to go back to exit 0.
 *
 * Step 3 is not ceremony. A lane stuck red satisfies step 2 forever and measures nothing.
 *
 * ─── WHY A COPY OF THE GATE, RATHER THAN FLAGS ───────────────────────────────────────────────────
 *
 * The gate resolves its root and its three baseline files from ITS OWN LOCATION. Copying it into the
 * scratch repository therefore redirects every one of those without adding a single override flag —
 * no `--root`, no config-directory environment variable, nothing a human could later use to point
 * the real gate somewhere friendlier. The arm gets total control and the gate gains no bypass.
 *
 * ─── THE CANARY ──────────────────────────────────────────────────────────────────────────────────
 *
 * A synthetic label whose HMAC is committed beside the real ones and whose plaintext lives beside
 * them too, outside the repository. Publishing its digest discloses nothing, and because it travels
 * the identical path — key load, candidate extraction, digest lookup — a lane that finds the canary
 * has demonstrably been able to find a real token. It carries no digits and no RFC4122 shape on
 * purpose: if a Tier-A rule could also match it, catching it would prove nothing about Tier B.
 */

import { spawn, spawnSync } from "node:child_process";
import {
  existsSync,
  readFileSync,
  writeFileSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  copyFileSync,
  chmodSync,
  linkSync,
  readdirSync,
  symlinkSync,
  lstatSync,
  rmdirSync,
  openSync,
  closeSync,
  unlinkSync,
  realpathSync,
} from "node:fs";
import { basename, join, dirname, delimiter, relative, resolve, sep } from "node:path";
import { homedir, tmpdir } from "node:os";
import { createHash, createHmac, randomBytes } from "node:crypto";

import {
  BOUNDARY_CANDIDATE_TIER_A_GATE_EXPECTATION,
  boundaryGateProvenance,
} from "./boundary-gate-provenance.mjs";
import {
  emitProvenanceBoundGateEvidence,
  GATE_EVENT_PROTOCOL,
  parseGateEvidence,
  unverifiedGateProvenance,
} from "./gate-event-contract.mjs";
import { APPROVED_BOUNDARY_LANES, assertLaneRegistry, BOUNDARY_LANES } from "./boundary-lanes.mjs";
import {
  boundaryScannerAuthority,
  contentKey,
  commitToken,
  pathContentKey,
  tokenForms,
  tokenNgramSize,
} from "./boundary-scan.mjs";
import {
  BOUNDARY_AUTHORITY_CLASS_EXTERNAL,
  BOUNDARY_CONTROL_MANIFEST_VERSION,
  BOUNDARY_KNOCKOUT_BOOTSTRAP_ENV,
  canonicalBoundaryJson,
  deriveBoundaryCandidateSubject,
  deriveBoundaryControlManifest,
  EXTERNAL_SANITIZED_AUTHORIZATION_NON_CLAIM,
  prepareNestedBoundaryScannerSelftestBootstrap,
  PREVIOUS_REVIEWED_CONTROL_PATHS,
  REVIEWED_CONTROL_PATHS,
} from "./boundary-bootstrap.mjs";
import {
  createBoundaryRuntimeAuthorization,
  deriveBoundaryAuthorityBundleIdentity,
} from "./boundary-external-authority.mjs";
import {
  appendBoundaryLedgerRecord,
  BOUNDARY_EVIDENCE_SPOOL_VERSION,
  boundaryEvidenceSpoolDirectory,
  boundarySpoolArtifactCustodyProblem,
  boundarySpoolPrimitiveCountsForSelftest,
  boundarySpoolTestDependencies,
  canonicalJson,
  inspectBoundaryEvidenceSpool,
  prepareBoundaryEvidenceRecord,
} from "./boundary-ledger.mjs";
import { custodyBarrierCountsForSelftest } from "./boundary-custody.mjs";

const bold = (s) => `\u001b[1m${s}\u001b[0m`;
const red = (s) => `\u001b[31m${s}\u001b[0m`;
const green = (s) => `\u001b[32m${s}\u001b[0m`;

const ARM_TERMINAL_PROTOCOL = "noa-boundary-arm-terminal/1";
const ARM_TERMINAL_PREFIX = "NOA_BOUNDARY_ARM_TERMINAL ";
const ARM_CHILD_OUTPUT_MAX_BYTES = 1024 * 1024;
// Counts are diagnostics only. The domain-separated, reviewed ID-set digests below are the case-plan
// authority; both manifests were recalculated from these exact registered bytes by independent
// execution and syntax-tree calculators.
const ARM_DIAGNOSTIC_FULL_CASE_COUNT = 254;
const ARM_DIAGNOSTIC_SPOOL_ONLY_CASE_COUNT = 23;
const ARM_REVIEWED_FULL_CASE_PLAN_SHA256 = "f9f32d81c09d933e1c900b46c5fec5dbbb8fe9d0e21aefb27fe83adb53fbb12a";
const ARM_REVIEWED_SPOOL_ONLY_CASE_PLAN_SHA256 = "a03420b437d9c15e9c0213844f6d911fc01494cba6ab658be242f22f2875e188";
const ARM_TERMINAL_WATCHDOG_MS = 10 * 60 * 1000;

const ARM_CASE_MODE_FULL = "FULL";
const ARM_CASE_MODE_SPOOL_ONLY = "SPOOL_ONLY";
const EXTERNAL_BOOTSTRAP_MODE_BY_OPERATION = Object.freeze({
  RECOVERY_ONLY: "recovery",
  RUNTIME: "runtime",
});
const ARM_CASE_ID_RE = /^[a-z0-9][a-z0-9._:-]{0,159}$/;
const armCaseRegistry = new Map();
const ARM_FULL_ONLY = Object.freeze([ARM_CASE_MODE_FULL]);
const ARM_SPOOL_ONLY = Object.freeze([ARM_CASE_MODE_SPOOL_ONLY]);
const ARM_BOTH_MODES = Object.freeze([ARM_CASE_MODE_FULL, ARM_CASE_MODE_SPOOL_ONLY]);

function defineArmCase(id, label, modes) {
  if (typeof id !== "string" || Buffer.byteLength(id, "utf8") > 160 || !ARM_CASE_ID_RE.test(id)
      || id.includes("\0")) throw new Error("invalid bounded ASCII boundary-arm case ID");
  if (typeof label !== "string" || label.length === 0 || label.includes("\0")) {
    throw new Error("invalid boundary-arm case label");
  }
  if (!Array.isArray(modes) || modes.length === 0
      || modes.some((mode) => mode !== ARM_CASE_MODE_FULL && mode !== ARM_CASE_MODE_SPOOL_ONLY)
      || new Set(modes).size !== modes.length) {
    throw new Error("invalid boundary-arm case mode registry");
  }
  if (armCaseRegistry.has(id)) throw new Error(`duplicate boundary-arm case ID: ${id}`);
  const descriptor = Object.freeze({ id, label, modes: Object.freeze([...modes]) });
  armCaseRegistry.set(id, descriptor);
  return descriptor;
}

const ARM_STATIC_CASES = Object.freeze({
  case_the_arm_terminal_supervisor_refuses_missing_duplicate_incomplet_0d29a4a2: defineArmCase("case.the-arm-terminal-supervisor-refuses-missing-duplicate-incomplete-failed-signaled-timed-out-and-late-0d29a4a2", "the arm child supervisors refuse incomplete terminal evidence and unverified gate authority", ARM_BOTH_MODES),
  case_the_lane_registry_matches_its_owner_visible_ratchet: defineArmCase("case.the-lane-registry-matches-its-owner-visible-ratchet", "the lane registry matches its owner-visible ratchet", ARM_BOTH_MODES),
  case_the_scanner_safe_synthetic_review_session_construction_preserve_7a464f86: defineArmCase("case.the-scanner-safe-synthetic-review-session-construction-preserves-the-exact-uuid-value", "the scanner-safe synthetic review-session construction preserves the exact UUID value", ARM_BOTH_MODES),
  case_a_lane_added_without_updating_the_ratchet_is_refused: defineArmCase("case.a-lane-added-without-updating-the-ratchet-is-refused", "a lane added without updating the ratchet is REFUSED", ARM_BOTH_MODES),
  case_the_pure_scanner_fixtures_pass_in_both_directions: defineArmCase("case.the-pure-scanner-fixtures-pass-in-both-directions", "the pure scanner fixtures pass in both directions", ARM_BOTH_MODES),
  case_authenticated_carrier_closures_include_the_immutable_publish_ar_322e8d21: defineArmCase("case.authenticated-carrier-closures-include-the-immutable-publish-artifact-executor", "authenticated carrier closures include the immutable publish-artifact executor", ARM_BOTH_MODES),
  case_the_synthetic_gate_carries_its_exact_locked_scanner_runtime: defineArmCase("case.the-synthetic-gate-carries-its-exact-locked-scanner-runtime", "the synthetic gate carries its exact locked scanner runtime", ARM_BOTH_MODES),
  case_the_real_push_hook_environment_selects_only_the_isolated_arm_ho_f3fb7966: defineArmCase("case.the-real-push-hook-environment-selects-only-the-isolated-arm-home-and-state-roots", "the real-push hook environment selects only the isolated arm HOME and state roots", ARM_BOTH_MODES),
  case_the_arm_uses_isolated_synthetic_tier_b_custody: defineArmCase("case.the-arm-uses-isolated-synthetic-tier-b-custody", "the arm uses isolated synthetic Tier-B custody", ARM_BOTH_MODES),
  case_the_real_working_tree_is_exactly_as_the_focused_spool_arm_found_it: defineArmCase("case.the-real-working-tree-is-exactly-as-the-focused-spool-arm-found-it", "the real working tree is exactly as the focused spool arm found it", ARM_SPOOL_ONLY),
  case_the_untouched_synthetic_repository_is_green_in_all_eight_lanes: defineArmCase("case.the-untouched-synthetic-repository-is-green-in-all-eight-lanes", "the untouched synthetic repository is GREEN in all eight lanes", ARM_FULL_ONLY),
  case_l_pack_never_executes_or_attempts_a_package_lifecycle_script: defineArmCase("case.l-pack-never-executes-or-attempts-a-package-lifecycle-script", "L-PACK never executes or attempts a package lifecycle script", ARM_FULL_ONLY),
  case_the_real_push_hook_selects_and_writes_only_its_isolated_arm_evi_0331903f: defineArmCase("case.the-real-push-hook-selects-and-writes-only-its-isolated-arm-evidence-spool", "the real-push hook selects and writes only its isolated arm evidence spool", ARM_FULL_ONLY),
  case_pre_push_new_branch_destination_refs_are_used_and_an_older_blob_864a9483: defineArmCase("case.pre-push-new-branch-destination-refs-are-used-and-an-older-blob-version-is-found", "pre-push new branch: destination refs are used and an older blob version is FOUND", ARM_FULL_ONLY),
  case_pre_push_new_branch_the_same_destination_derived_path_goes_clea_0d02024c: defineArmCase("case.pre-push-new-branch-the-same-destination-derived-path-goes-clean-without-the-plant", "pre-push new branch: the same destination-derived path goes CLEAN without the plant", ARM_FULL_ONLY),
  case_pre_push_new_branch_ignores_unavailable_destination_tips_and_finds_older_blob: defineArmCase("case.pre-push-new-branch-ignores-unavailable-destination-tips-and-finds-older-blob", "pre-push new branch: unavailable disconnected destination tips broaden scanning and an older blob is FOUND", ARM_FULL_ONLY),
  case_pre_push_new_branch_with_unavailable_destination_tips_goes_clean: defineArmCase("case.pre-push-new-branch-with-unavailable-destination-tips-goes-clean", "pre-push new branch: unavailable disconnected destination tips still permit a fully scanned CLEAN result", ARM_FULL_ONLY),
  case_pre_push_existing_ref_with_unavailable_destination_tip_finds_older_blob: defineArmCase("case.pre-push-existing-ref-with-unavailable-destination-tip-finds-older-blob", "pre-push existing ref: an unavailable disconnected destination tip broadens scanning and an older blob is FOUND", ARM_FULL_ONLY),
  case_pre_push_existing_ref_with_unavailable_destination_tip_goes_clean: defineArmCase("case.pre-push-existing-ref-with-unavailable-destination-tip-goes-clean", "pre-push existing ref: an unavailable disconnected destination tip still permits a fully scanned CLEAN result", ARM_FULL_ONLY),
  case_pre_push_annotated_tag_the_tag_object_annotation_is_found_even__c2aeff84: defineArmCase("case.pre-push-annotated-tag-the-tag-object-annotation-is-found-even-when-its-commit-already-exists-remotely", "pre-push annotated tag: the tag object annotation is FOUND even when its commit already exists remotely", ARM_FULL_ONLY),
  case_pre_push_annotated_tag_the_exact_destination_tag_name_is_found__63c9c60f: defineArmCase("case.pre-push-annotated-tag-the-exact-destination-tag-name-is-found-independently-of-local-name", "pre-push annotated tag: the exact destination tag name is FOUND independently of local name", ARM_FULL_ONLY),
  case_pre_push_annotated_tag_clean_object_and_clean_names_go_clean: defineArmCase("case.pre-push-annotated-tag-clean-object-and-clean-names-go-clean", "pre-push annotated tag: clean object and clean names go CLEAN", ARM_FULL_ONLY),
  case_pre_push_tag_targeting_non_commit_object_fails_closed: defineArmCase("case.pre-push-tag-targeting-non-commit-object-fails-closed", "pre-push tag: a blob target is refused because commit-history lanes cannot enumerate it", ARM_FULL_ONLY),
  case_the_working_tree_lane_is_clean_again_after_every_shape_plant: defineArmCase("case.the-working-tree-lane-is-clean-again-after-every-shape-plant", "the working-tree lane is clean again after every shape plant", ARM_FULL_ONLY),
  case_ratchet_a_finding_with_no_ledger_entry_blocks: defineArmCase("case.ratchet-a-finding-with-no-ledger-entry-blocks", "ratchet: a finding with no ledger entry BLOCKS", ARM_FULL_ONLY),
  case_ratchet_the_same_finding_with_a_reviewed_entry_is_carried: defineArmCase("case.ratchet-the-same-finding-with-a-reviewed-entry-is-carried", "ratchet: the same finding with a reviewed entry is CARRIED", ARM_FULL_ONLY),
  case_ratchet_editing_the_file_makes_the_entry_stop_applying_a_suppre_a5d0fb95: defineArmCase("case.ratchet-editing-the-file-makes-the-entry-stop-applying-a-suppression-cannot-generalise", "ratchet: editing the file makes the entry stop applying — a suppression cannot generalise", ARM_FULL_ONLY),
  case_key_custody_a_regular_32_byte_0600_single_link_key_in_an_owner__d0eea8e7: defineArmCase("case.key-custody-a-regular-32-byte-0600-single-link-key-in-an-owner-only-directory-passes", "key custody: a regular 32-byte, 0600, single-link key in an owner-only directory passes", ARM_FULL_ONLY),
  case_key_custody_an_in_place_writer_is_refused_by_ctime_and_stable_d_0aeb5dae: defineArmCase("case.key-custody-an-in-place-writer-is-refused-by-ctime-and-stable-double-read-evidence", "key custody: an in-place writer is refused by ctime and stable double-read evidence", ARM_FULL_ONLY),
  case_exclusion_migration_valid_reviewed_input_creates_one_0600_singl_e5f7cabb: defineArmCase("case.exclusion-migration-valid-reviewed-input-creates-one-0600-single-link-canonical-v3-policy-and-print-e5f7cabb", "exclusion migration: valid reviewed input creates one 0600 single-link canonical v3 policy and prints no values", ARM_FULL_ONLY),
  case_exclusion_policy_an_authenticated_narrowed_current_control_mani_9a94c19e: defineArmCase("case.exclusion-policy-an-authenticated-narrowed-current-control-manifest-is-refused", "exclusion policy: an authenticated narrowed current control manifest is refused", ARM_FULL_ONLY),
  case_exclusion_policy_an_authenticated_wrong_current_control_manifes_1cfef9ee: defineArmCase("case.exclusion-policy-an-authenticated-wrong-current-control-manifest-version-is-refused", "exclusion policy: an authenticated wrong current control-manifest version is refused", ARM_FULL_ONLY),
  case_exclusion_policy_a_corrupt_hmac_is_refused: defineArmCase("case.exclusion-policy-a-corrupt-hmac-is-refused", "exclusion policy: a corrupt HMAC is refused", ARM_FULL_ONLY),
  case_exclusion_policy_hmac_binds_document_level_review_metadata: defineArmCase("case.exclusion-policy-hmac-binds-document-level-review-metadata", "exclusion policy: HMAC binds document-level review metadata", ARM_FULL_ONLY),
  case_exclusion_policy_an_authenticated_token_set_mismatch_with_retai_4a2d1ccb: defineArmCase("case.exclusion-policy-an-authenticated-token-set-mismatch-with-retained-legacy-semantics-is-refused", "exclusion policy: an authenticated token-set mismatch with retained legacy semantics is refused", ARM_FULL_ONLY),
  case_exclusion_policy_noncanonical_whitespace_and_key_formatting_are_2d34f901: defineArmCase("case.exclusion-policy-noncanonical-whitespace-and-key-formatting-are-refused-before-hmac", "exclusion policy: noncanonical whitespace and key formatting are refused before HMAC", ARM_FULL_ONLY),
  case_exclusion_policy_duplicate_json_keys_are_refused_even_when_the__f7fceecd: defineArmCase("case.exclusion-policy-duplicate-json-keys-are-refused-even-when-the-semantic-value-is-unchanged", "exclusion policy: duplicate JSON keys are refused even when the semantic value is unchanged", ARM_FULL_ONLY),
  case_exclusion_policy_a_changed_reviewed_control_manifest_is_refused: defineArmCase("case.exclusion-policy-a-changed-reviewed-control-manifest-is-refused", "exclusion policy: a changed reviewed control manifest is refused", ARM_FULL_ONLY),
  case_exclusion_policy_retained_legacy_byte_drift_is_refused: defineArmCase("case.exclusion-policy-retained-legacy-byte-drift-is-refused", "exclusion policy: retained legacy byte drift is refused", ARM_FULL_ONLY),
  case_exclusion_recovery_registry_the_immutable_historical_stage_rema_e5705291: defineArmCase("case.exclusion-recovery-registry-the-immutable-historical-stage-remains-exactly-schema-v3-with-seven-rev-e5705291", "exclusion recovery registry: the immutable historical stage remains exactly schema-v3 with seven reviewed paths", ARM_FULL_ONLY),
  case_exclusion_recovery_ordering_fresh_rotation_refuses_unfinished_s_090b31db: defineArmCase("case.exclusion-recovery-ordering-fresh-rotation-refuses-unfinished-schema-v2-state-without-changing-eith-090b31db", "exclusion recovery ordering: fresh rotation refuses unfinished schema-v2 state without changing either predecessor", ARM_FULL_ONLY),
  case_exclusion_recovery_ordering_recovery_only_preserves_exact_histo_82404d7d: defineArmCase("case.exclusion-recovery-ordering-recovery-only-preserves-exact-historical-active-bytes-and-durably-recei-82404d7d", "exclusion recovery ordering: recovery-only preserves exact historical active bytes and durably receipts v2 before cleanup", ARM_FULL_ONLY),
  case_exclusion_rotation_a_separate_fresh_transaction_binds_expanded__5cdbcff7: defineArmCase("case.exclusion-rotation-a-separate-fresh-transaction-binds-expanded-current-bytes-only-after-historical-recovery", "exclusion rotation: a separate fresh transaction binds expanded current bytes only after historical recovery", ARM_FULL_ONLY),
  case_exclusion_rotation_a_corrupt_receipt_hmac_is_refused_before_raw_051ac9fa: defineArmCase("case.exclusion-rotation-a-corrupt-receipt-hmac-is-refused-before-raw-predecessor-deletion", "exclusion rotation: a corrupt receipt HMAC is refused before raw predecessor deletion", ARM_FULL_ONLY),
  case_exclusion_rotation_an_authenticated_receipt_to_successor_mismat_c785dfbb: defineArmCase("case.exclusion-rotation-an-authenticated-receipt-to-successor-mismatch-retains-the-raw-predecessor", "exclusion rotation: an authenticated receipt-to-successor mismatch retains the raw predecessor", ARM_FULL_ONLY),
  case_exclusion_rotation_exact_valid_receipt_resumes_cleanup_idempote_aad9ac51: defineArmCase("case.exclusion-rotation-exact-valid-receipt-resumes-cleanup-idempotently-without-value-output", "exclusion rotation: exact valid receipt resumes cleanup idempotently without value output", ARM_FULL_ONLY),
  case_exclusion_rotation_compatibility_authenticated_receipt_v1_remai_b5daeef9: defineArmCase("case.exclusion-rotation-compatibility-authenticated-receipt-v1-remains-readable-terminal-evidence-withou-b5daeef9", "exclusion rotation compatibility: authenticated receipt v1 remains readable terminal evidence without deletion authority", ARM_FULL_ONLY),
  case_exclusion_rotation_compatibility_a_receipt_v1_cannot_bypass_man_96617897: defineArmCase("case.exclusion-rotation-compatibility-a-receipt-v1-cannot-bypass-mandatory-v2-recovery-before-fresh-rotation", "exclusion rotation compatibility: a receipt v1 cannot bypass mandatory v2 recovery before fresh rotation", ARM_FULL_ONLY),
  case_exclusion_rotation_evidence_recovery_and_fresh_rotation_retain__aaa013a7: defineArmCase("case.exclusion-rotation-evidence-recovery-and-fresh-rotation-retain-two-exact-non-overlapping-receipts", "exclusion rotation evidence: recovery and fresh rotation retain two exact non-overlapping receipts", ARM_FULL_ONLY),
  case_exclusion_rotation_concurrency_one_live_writer_excludes_a_secon_575d2c2b: defineArmCase("case.exclusion-rotation-concurrency-one-live-writer-excludes-a-second-and-stale-lock-recovery-completes", "exclusion rotation concurrency: one live writer excludes a second and stale-lock recovery completes", ARM_FULL_ONLY),
  case_exclusion_rotation_staged_create_direct_final_publication_never_fb2add8a: defineArmCase("case.exclusion-rotation-staged-create-direct-final-publication-never-replaces-a-competing-exact-winner", "exclusion rotation staged create: direct final publication never replaces a competing exact winner", ARM_FULL_ONLY),
  case_exclusion_rotation_stale_lock_race_a_delayed_reader_cannot_remo_ca1ba2f9: defineArmCase("case.exclusion-rotation-stale-lock-race-a-delayed-reader-cannot-remove-the-elected-live-successor-lock", "exclusion rotation stale-lock race: a delayed reader cannot remove the elected live successor lock", ARM_FULL_ONLY),
  case_exclusion_rotation_retained_claim_ownership_only_the_exact_live_1e0229b4: defineArmCase("case.exclusion-rotation-retained-claim-ownership-only-the-exact-live-replacement-writer-consumes-its-stale-claim", "exclusion rotation retained-claim ownership: only the exact live replacement writer consumes its stale claim", ARM_FULL_ONLY),
  case_exclusion_rotation_retained_claim_recovery_a_dead_replacement_a_eeec040b: defineArmCase("case.exclusion-rotation-retained-claim-recovery-a-dead-replacement-and-exact-stale-claim-resume-forward-once", "exclusion rotation retained-claim recovery: a dead replacement and exact stale claim resume forward once", ARM_FULL_ONLY),
  case_exclusion_rotation_recovery_unknown_transaction_artifacts_fail__031adaee: defineArmCase("case.exclusion-rotation-recovery-unknown-transaction-artifacts-fail-closed-without-deletion", "exclusion rotation recovery: unknown transaction artifacts fail closed without deletion", ARM_FULL_ONLY),
  case_exclusion_rotation_staged_create_an_unknown_destination_target__61d5b1e1: defineArmCase("case.exclusion-rotation-staged-create-an-unknown-destination-target-fails-before-lock-mutation-and-is-retained", "exclusion rotation staged create: an unknown destination target fails before lock mutation and is retained", ARM_FULL_ONLY),
  case_exclusion_rotation_staged_create_a_corrupt_exact_shaped_stage_f_df43955a: defineArmCase("case.exclusion-rotation-staged-create-a-corrupt-exact-shaped-stage-fails-closed-without-deletion", "exclusion rotation staged create: a corrupt exact-shaped stage fails closed without deletion", ARM_FULL_ONLY),
  case_exclusion_rotation_staged_create_two_valid_competing_complete_l_0a8ee299: defineArmCase("case.exclusion-rotation-staged-create-two-valid-competing-complete-lock-stages-fail-closed-without-deletion", "exclusion rotation staged create: two valid competing complete lock stages fail closed without deletion", ARM_FULL_ONLY),
  case_exclusion_rotation_staged_create_an_unknown_hard_link_cannot_pu_c35ca15d: defineArmCase("case.exclusion-rotation-staged-create-an-unknown-hard-link-cannot-publish-or-delete-a-complete-stage", "exclusion rotation staged create: an unknown hard link cannot publish or delete a complete stage", ARM_FULL_ONLY),
  case_exclusion_rotation_recovery_corrupt_intent_fails_closed_without_ee980a0e: defineArmCase("case.exclusion-rotation-recovery-corrupt-intent-fails-closed-without-deleting-its-evidence", "exclusion rotation recovery: corrupt intent fails closed without deleting its evidence", ARM_FULL_ONLY),
  case_exclusion_rotation_recovery_multiple_authenticated_predecessors_0ff4b31d: defineArmCase("case.exclusion-rotation-recovery-multiple-authenticated-predecessors-fail-closed-without-deletion", "exclusion rotation recovery: multiple authenticated predecessors fail closed without deletion", ARM_FULL_ONLY),
  case_exclusion_rotation_name_recovery_crash_after_full_receipt_publi_e51c8b4d: defineArmCase("case.exclusion-rotation-name-recovery-crash-after-full-receipt-publication-resumes-one-authenticated-alias", "exclusion rotation name recovery: crash after full receipt publication resumes one authenticated alias", ARM_FULL_ONLY),
  case_exclusion_rotation_name_recovery_byte_different_authenticated_r_3872b421: defineArmCase("case.exclusion-rotation-name-recovery-byte-different-authenticated-receipt-aliases-fail-closed-without-deletion", "exclusion rotation name recovery: byte-different authenticated receipt aliases fail closed without deletion", ARM_FULL_ONLY),
  case_exclusion_rotation_name_recovery_crash_after_raw_legacy_tombsto_c2c918b6: defineArmCase("case.exclusion-rotation-name-recovery-crash-after-raw-legacy-tombstone-normalization-resumes-forward", "exclusion rotation name recovery: crash after raw legacy-tombstone normalization resumes forward", ARM_FULL_ONLY),
  case_exclusion_rotation_name_recovery_crash_after_receipt_bound_dele_0a6df53f: defineArmCase("case.exclusion-rotation-name-recovery-crash-after-receipt-bound-deleting-tombstone-normalization-resumes-deletion", "exclusion rotation name recovery: crash after receipt-bound deleting tombstone normalization resumes deletion", ARM_FULL_ONLY),
  case_exclusion_rotation_recovery_sole_legacy_random_tombstone_withou_83b6125c: defineArmCase("case.exclusion-rotation-recovery-sole-legacy-random-tombstone-without-receipt-returns-to-deterministic-custody", "exclusion rotation recovery: sole legacy random tombstone without receipt returns to deterministic custody", ARM_FULL_ONLY),
  case_exclusion_rotation_recovery_sole_legacy_random_tombstone_with_e_cb509a13: defineArmCase("case.exclusion-rotation-recovery-sole-legacy-random-tombstone-with-exact-receipt-resumes-authenticated-deletion", "exclusion rotation recovery: sole legacy random tombstone with exact receipt resumes authenticated deletion", ARM_FULL_ONLY),
  case_boundary_refresh_ordering_combined_public_snapshot_and_token_re_40b2f791: defineArmCase("case.boundary-refresh-ordering-combined-public-snapshot-and-token-refresh-is-rejected-before-mutation", "boundary refresh ordering: combined public-snapshot and token refresh is rejected before mutation", ARM_FULL_ONLY),
  case_commitment_refresh_tamper_then_refresh_cannot_bless_a_shrunken__d3b68323: defineArmCase("case.commitment-refresh-tamper-then-refresh-cannot-bless-a-shrunken-predecessor", "commitment refresh: tamper-then-refresh cannot bless a shrunken predecessor", ARM_FULL_ONLY),
  case_key_custody_first_refresh_creates_one_regular_32_byte_0600_key__c42bfd20: defineArmCase("case.key-custody-first-refresh-creates-one-regular-32-byte-0600-key-in-a-0700-directory", "key custody: first refresh creates one regular 32-byte 0600 key in a 0700 directory", ARM_FULL_ONLY),
  case_without_a_key_tier_a_still_runs_and_labels_the_gap: defineArmCase("case.without-a-key-tier-a-still-runs-and-labels-the-gap", "without a key, --tier a still runs and LABELS the gap", ARM_FULL_ONLY),
  case_pre_push_local_selector_head_resolves_to_and_is_bound_to_the_ex_06e6f3ec: defineArmCase("case.pre-push-local-selector-head-resolves-to-and-is-bound-to-the-exact-supplied-object-id", "pre-push local selector: HEAD resolves to and is bound to the exact supplied object ID", ARM_FULL_ONLY),
  case_pre_push_local_selector_head_resolves_behind_the_option_boundar_d31e2d1f: defineArmCase("case.pre-push-local-selector-head-resolves-behind-the-option-boundary-to-the-exact-supplied-object-id", "pre-push local selector: HEAD~ resolves behind the option boundary to the exact supplied object ID", ARM_FULL_ONLY),
  case_fail_closed_the_gate_is_not_at_the_root_of_the_tree_it_scans_exits_2: defineArmCase("case.fail-closed-the-gate-is-not-at-the-root-of-the-tree-it-scans-exits-2", "fail-closed: the gate is not at the root of the tree it scans exits 2", ARM_FULL_ONLY),
  case_fail_closed_a_lane_deriving_zero_units_exits_2: defineArmCase("case.fail-closed-a-lane-deriving-zero-units-exits-2", "fail-closed: a lane deriving zero units exits 2", ARM_FULL_ONLY),
  case_custody_durability_real_operations_exercise_both_file_and_direc_80be3bf0: defineArmCase("case.custody-durability-real-operations-exercise-both-file-and-directory-synchronization-barriers", "custody durability: real operations exercise both file and directory synchronization barriers", ARM_FULL_ONLY),
  case_the_real_working_tree_is_exactly_as_the_arm_found_it: defineArmCase("case.the-real-working-tree-is-exactly-as-the-arm-found-it", "the real working tree is exactly as the arm found it", ARM_FULL_ONLY),
  case_evidence_spool_concurrency_25_unique_writers_publish_the_exact__b28c797d: defineArmCase("case.evidence-spool-concurrency-25-unique-writers-publish-the-exact-record-id-multiset", "evidence spool concurrency: 25 unique writers publish the exact record-id multiset", ARM_BOTH_MODES),
  case_evidence_spool_provenance_concurrent_legacy_and_v2_writers_muta_b4058f4f: defineArmCase("case.evidence-spool-provenance-concurrent-legacy-and-v2-writers-mutate-disjoint-paths-only", "evidence spool provenance: concurrent legacy and v2 writers mutate disjoint paths only", ARM_BOTH_MODES),
  case_evidence_spool_idempotency_24_concurrent_stable_id_writers_conv_ad1f6605: defineArmCase("case.evidence-spool-idempotency-24-concurrent-stable-id-writers-converge-on-one-exact-final", "evidence spool idempotency: 24 concurrent stable-id writers converge on one exact final", ARM_BOTH_MODES),
  case_evidence_spool_primitives_o_excl_publication_executes_exact_rea_a3653b8f: defineArmCase("case.evidence-spool-primitives-o-excl-publication-executes-exact-readback-both-file-fsyncs-and-one-final-a3653b8f", "evidence spool primitives: O_EXCL publication executes exact readback, both file fsyncs, and one final directory fsync", ARM_BOTH_MODES),
  case_evidence_spool_o_excl_an_occupied_deterministic_pending_name_is_f620f964: defineArmCase("case.evidence-spool-o-excl-an-occupied-deterministic-pending-name-is-refused-and-preserved-exactly", "evidence spool O_EXCL: an occupied deterministic pending name is refused and preserved exactly", ARM_BOTH_MODES),
  case_evidence_spool_schema_a_raw_top_level_field_is_rejected_before__1f68ad45: defineArmCase("case.evidence-spool-schema-a-raw-top-level-field-is-rejected-before-filesystem-mutation-or-rendering", "evidence spool schema: a raw top-level field is rejected before filesystem mutation or rendering", ARM_BOTH_MODES),
  case_evidence_spool_collision_the_same_recordid_with_changed_bytes_i_adffa499: defineArmCase("case.evidence-spool-collision-the-same-recordid-with-changed-bytes-is-refused-without-overwrite", "evidence spool collision: the same recordId with changed bytes is refused without overwrite", ARM_BOTH_MODES),
  case_evidence_spool_crash_matrix_create_partial_fsync_link_dir_fsync_cb85698e: defineArmCase("case.evidence-spool-crash-matrix-create-partial-fsync-link-dir-fsync-retained-alias-states-stay-truthful", "evidence spool crash matrix: create/partial/fsync/link/dir-fsync/retained-alias states stay truthful", ARM_BOTH_MODES),
  case_evidence_spool_reader_a_partial_pending_artifact_is_never_count_17d91c2f: defineArmCase("case.evidence-spool-reader-a-partial-pending-artifact-is-never-counted-as-a-valid-record", "evidence spool reader: a partial pending artifact is never counted as a valid record", ARM_BOTH_MODES),
  case_evidence_spool_storage_faults_reserve_enospc_zero_write_fsync_r_809a55df: defineArmCase("case.evidence-spool-storage-faults-reserve-enospc-zero-write-fsync-retained-alias-and-close-report-exact-state", "evidence spool storage faults: reserve, ENOSPC, zero-write, fsync, retained alias, and close report exact state", ARM_BOTH_MODES),
  case_evidence_spool_census_symlink_mode_owner_name_hash_extra_link_a_612a77dc: defineArmCase("case.evidence-spool-census-symlink-mode-owner-name-hash-extra-link-anomalies-remain-malformed-and-retained", "evidence spool census: symlink/mode-owner/name/hash/extra-link anomalies remain malformed and retained", ARM_BOTH_MODES),
  case_evidence_spool_streams_boundary_and_pre_push_records_use_disjoi_f2c12c2e: defineArmCase("case.evidence-spool-streams-boundary-and-pre-push-records-use-disjoint-schema-v2-roots", "evidence spool streams: boundary and pre-push records use disjoint schema-v2 roots", ARM_BOTH_MODES),
  case_evidence_spool_package_containment_scripts_are_absent_from_exac_abc830ea: defineArmCase("case.evidence-spool-package-containment-scripts-are-absent-from-exact-packed-package-bytes", "evidence spool package containment: scripts are absent from exact packed-package bytes", ARM_BOTH_MODES),
});

const ARM_FAIL_CLOSED_CASES = Object.freeze({
  fail_the_commitments_file_is_missing: defineArmCase("fail.the-commitments-file-is-missing", "fail-closed: the commitments file is missing exits 2", ARM_FULL_ONLY),
  fail_the_commitments_file_carries_zero_digests: defineArmCase("fail.the-commitments-file-carries-zero-digests", "fail-closed: the commitments file carries zero digests exits 2", ARM_FULL_ONLY),
  fail_the_key_does_not_match_the_committed_digests: defineArmCase("fail.the-key-does-not-match-the-committed-digests", "fail-closed: the key does not match the committed digests exits 2", ARM_FULL_ONLY),
  fail_the_commitments_are_older_than_the_freshness_limit: defineArmCase("fail.the-commitments-are-older-than-the-freshness-limit", "fail-closed: the commitments are older than the freshness limit exits 2", ARM_FULL_ONLY),
  fail_the_commitments_timestamp_is_beyond_future_skew_tolerance: defineArmCase("fail.the-commitments-timestamp-is-beyond-future-skew-tolerance", "fail-closed: the commitments timestamp is beyond future-skew tolerance exits 2 with its exact setup failure", ARM_FULL_ONLY),
  fail_a_digest_is_shorter_than_full_sha_256: defineArmCase("fail.a-digest-is-shorter-than-full-sha-256", "fail-closed: a digest is shorter than full SHA-256 exits 2", ARM_FULL_ONLY),
  fail_an_authenticated_commitment_set_is_shrunk: defineArmCase("fail.an-authenticated-commitment-set-is-shrunk", "fail-closed: an authenticated commitment set is shrunk exits 2 with its exact setup failure", ARM_FULL_ONLY),
  fail_the_public_repository_allowlist_has_zero_organisations: defineArmCase("fail.the-public-repository-allowlist-has-zero-organisations", "fail-closed: the public-repository allowlist has zero organisations exits 2", ARM_FULL_ONLY),
  fail_live_provider_truth_has_drifted_from_the_committed_public_snapshot: defineArmCase("fail.live-provider-truth-has-drifted-from-the-committed-public-snapshot", "fail-closed: live provider truth has drifted from the committed PUBLIC snapshot exits 2 with its exact setup failure", ARM_FULL_ONLY),
  fail_a_new_or_downgraded_live_private_repository_is_absent_from_auth_dbff75d4: defineArmCase("fail.a-new-or-downgraded-live-private-repository-is-absent-from-authenticated-inputs", "fail-closed: a new or downgraded live PRIVATE repository is absent from authenticated inputs exits 2 with its exact setup failure", ARM_FULL_ONLY),
  fail_live_visibility_cannot_disable_the_keyed_private_input_comparis_4dba7040: defineArmCase("fail.live-visibility-cannot-disable-the-keyed-private-input-comparison-with-tier-a", "fail-closed: live visibility cannot disable the keyed PRIVATE-input comparison with --tier a exits 2 with its exact setup failure", ARM_FULL_ONLY),
  fail_a_known_exposure_entry_has_no_remediation: defineArmCase("fail.a-known-exposure-entry-has-no-remediation", "fail-closed: a known-exposure entry has no remediation exits 2", ARM_FULL_ONLY),
  fail_the_boundary_key_is_missing: defineArmCase("fail.the-boundary-key-is-missing", "fail-closed: the boundary key is missing exits 2", ARM_FULL_ONLY),
  fail_a_31_byte_boundary_key: defineArmCase("fail.a-31-byte-boundary-key", "fail-closed: a 31-byte boundary key exits 2 with its exact setup failure", ARM_FULL_ONLY),
  fail_a_group_world_readable_boundary_key: defineArmCase("fail.a-group-world-readable-boundary-key", "fail-closed: a group/world-readable boundary key exits 2 with its exact setup failure", ARM_FULL_ONLY),
  fail_a_symbolic_link_boundary_key: defineArmCase("fail.a-symbolic-link-boundary-key", "fail-closed: a symbolic-link boundary key exits 2 with its exact setup failure", ARM_FULL_ONLY),
  fail_a_hard_linked_boundary_key: defineArmCase("fail.a-hard-linked-boundary-key", "fail-closed: a hard-linked boundary key exits 2 with its exact setup failure", ARM_FULL_ONLY),
  fail_a_group_world_searchable_boundary_key_directory: defineArmCase("fail.a-group-world-searchable-boundary-key-directory", "fail-closed: a group/world-searchable boundary key directory exits 2 with its exact setup failure", ARM_FULL_ONLY),
  fail_a_symbolic_link_boundary_key_directory: defineArmCase("fail.a-symbolic-link-boundary-key-directory", "fail-closed: a symbolic-link boundary key directory exits 2 with its exact setup failure", ARM_FULL_ONLY),
  fail_a_symbolic_link_boundary_canary: defineArmCase("fail.a-symbolic-link-boundary-canary", "fail-closed: a symbolic-link boundary canary exits 2 with its exact setup failure", ARM_FULL_ONLY),
  fail_a_missing_dedicated_boundary_canary: defineArmCase("fail.a-missing-dedicated-boundary-canary", "fail-closed: a missing dedicated boundary canary exits 2 with its exact setup failure", ARM_FULL_ONLY),
  fail_a_hard_linked_boundary_canary: defineArmCase("fail.a-hard-linked-boundary-canary", "fail-closed: a hard-linked boundary canary exits 2 with its exact setup failure", ARM_FULL_ONLY),
  fail_a_symbolic_link_extra_token_input: defineArmCase("fail.a-symbolic-link-extra-token-input", "fail-closed: a symbolic-link extra token input exits 2 with its exact setup failure", ARM_FULL_ONLY),
  fail_a_hard_linked_governed_exclusion_policy: defineArmCase("fail.a-hard-linked-governed-exclusion-policy", "fail-closed: a hard-linked governed exclusion policy exits 2 with its exact setup failure", ARM_FULL_ONLY),
  fail_an_unknown_lane_id: defineArmCase("fail.an-unknown-lane-id", "fail-closed: an unknown lane id exits 2", ARM_FULL_ONLY),
  fail_an_unknown_flag: defineArmCase("fail.an-unknown-flag", "fail-closed: an unknown flag exits 2", ARM_FULL_ONLY),
  fail_an_unknown_tier: defineArmCase("fail.an-unknown-tier", "fail-closed: an unknown tier exits 2", ARM_FULL_ONLY),
  fail_pre_push_ref_input_is_empty: defineArmCase("fail.pre-push-ref-input-is-empty", "fail-closed: pre-push ref input is empty exits 2 with its exact setup failure", ARM_FULL_ONLY),
  fail_pre_push_ref_input_contains_an_internal_blank_record: defineArmCase("fail.pre-push-ref-input-contains-an-internal-blank-record", "fail-closed: pre-push ref input contains an internal blank record exits 2 with its exact setup failure", ARM_FULL_ONLY),
  fail_pre_push_local_selector_and_object_id_disagree: defineArmCase("fail.pre-push-local-selector-and-object-id-disagree", "fail-closed: pre-push local selector and object ID disagree exits 2 with its exact setup failure", ARM_FULL_ONLY),
  fail_pre_push_local_selector_names_a_nonexistent_object: defineArmCase("fail.pre-push-local-selector-names-a-nonexistent-object", "fail-closed: pre-push local selector names a nonexistent object exits 2 with its exact setup failure", ARM_FULL_ONLY),
  fail_pre_push_local_selector_is_option_like: defineArmCase("fail.pre-push-local-selector-is-option-like", "fail-closed: pre-push local selector is option-like exits 2 with its exact setup failure", ARM_FULL_ONLY),
  fail_pre_push_local_selector_contains_a_control_byte: defineArmCase("fail.pre-push-local-selector-contains-a-control-byte", "fail-closed: pre-push local selector contains a control byte exits 2 with its exact setup failure", ARM_FULL_ONLY),
  fail_pre_push_local_selector_contains_whitespace: defineArmCase("fail.pre-push-local-selector-contains-whitespace", "fail-closed: pre-push local selector contains whitespace exits 2 with its exact setup failure", ARM_FULL_ONLY),
  fail_pre_push_local_selector_exceeds_its_byte_bound: defineArmCase("fail.pre-push-local-selector-exceeds-its-byte-bound", "fail-closed: pre-push local selector exceeds its byte bound exits 2 with its exact setup failure", ARM_FULL_ONLY),
  fail_pre_push_zero_local_object_id_lacks_the_deletion_marker: defineArmCase("fail.pre-push-zero-local-object-id-lacks-the-deletion-marker", "fail-closed: pre-push zero local object ID lacks the deletion marker exits 2 with its exact setup failure", ARM_FULL_ONLY),
  fail_pre_push_deletion_marker_carries_a_nonzero_local_object_id: defineArmCase("fail.pre-push-deletion-marker-carries-a-nonzero-local-object-id", "fail-closed: pre-push deletion marker carries a nonzero local object ID exits 2 with its exact setup failure", ARM_FULL_ONLY),
  fail_pre_push_remote_ref_is_not_a_full_exact_ref: defineArmCase("fail.pre-push-remote-ref-is-not-a-full-exact-ref", "fail-closed: pre-push remote ref is not a full exact ref exits 2 with its exact setup failure", ARM_FULL_ONLY),
  fail_pre_push_local_object_id_is_malformed: defineArmCase("fail.pre-push-local-object-id-is-malformed", "fail-closed: pre-push local object ID is malformed exits 2 with its exact setup failure", ARM_FULL_ONLY),
  fail_every_selected_lane_skipped: defineArmCase("fail.every-selected-lane-skipped", "fail-closed: every selected lane skipped exits 2", ARM_FULL_ONLY),
  fail_a_required_lane_has_no_input: defineArmCase("fail.a-required-lane-has-no-input", "fail-closed: a required lane has no input exits 2", ARM_FULL_ONLY),
  fail_git_is_not_on_path: defineArmCase("fail.git-is-not-on-path", "fail-closed: git is not on PATH exits 2", ARM_FULL_ONLY),
  fail_a_tracked_file_cannot_be_read: defineArmCase("fail.a-tracked-file-cannot-be-read", "fail-closed: a tracked file cannot be read exits 2", ARM_FULL_ONLY),
});

const ARM_MANIFEST_MISSING_CASES = Object.freeze({
  manifest_the_public_repository_allowlist_is_missing: defineArmCase("manifest.the-public-repository-allowlist-is-missing", "fail-closed: the public-repository allowlist is missing exits 2 at the exact candidate Tier-A bootstrap path", ARM_FULL_ONLY),
  manifest_the_known_exposure_ledger_is_missing: defineArmCase("manifest.the-known-exposure-ledger-is-missing", "fail-closed: the known-exposure ledger is missing exits 2 at the exact candidate Tier-A bootstrap path", ARM_FULL_ONLY),
});

const ARM_MIGRATION_FAILURE_CASES = Object.freeze({
  migration_a_legacy_token_with_no_existing_inline_reason: defineArmCase("migration.a-legacy-token-with-no-existing-inline-reason", "exclusion migration: a legacy token with no existing inline reason is refused without creating output", ARM_FULL_ONLY),
  migration_a_validity_window_over_30_days: defineArmCase("migration.a-validity-window-over-30-days", "exclusion migration: a validity window over 30 days is refused without creating output", ARM_FULL_ONLY),
  migration_a_future_review_time: defineArmCase("migration.a-future-review-time", "exclusion migration: a future review time is refused without creating output", ARM_FULL_ONLY),
  migration_an_existing_destination: defineArmCase("migration.an-existing-destination", "exclusion migration: an existing destination is refused without creating output", ARM_FULL_ONLY),
});

const ARM_LANE_CASES = Object.freeze(Object.fromEntries(APPROVED_BOUNDARY_LANES.map((laneId) => {
  const stableLane = laneId.toLowerCase();
  return [laneId, Object.freeze({
    found: defineArmCase(
      `lane.${stableLane}.found`,
      `${laneId}: the canary planted in its own enumerated surface is FOUND`,
      ARM_FULL_ONLY,
    ),
    clean: defineArmCase(
      `lane.${stableLane}.clean`,
      `${laneId}: and the same lane goes CLEAN once it is removed`,
      ARM_FULL_ONLY,
    ),
  })];
})));
const ARM_LANES_ARMED_CASE = defineArmCase(
  "lane.registry-armed",
  "every registered lane is armed",
  ARM_FULL_ONLY,
);

const ARM_SHAPE_FIXTURES = Object.freeze([
  Object.freeze({
    rule: "repo-not-public",
    text: ({ orgOfAllowlist }) => `mirrors ${orgOfAllowlist}/a-repository-the-forge-does-not-list nightly`,
  }),
  Object.freeze({ rule: "home-path", text: ({ homeShape }) => `built from ${homeShape}/proj` }),
  Object.freeze({
    rule: "privacy-adjacency",
    text: ({ homeShape }) => `The internal build spec lives at ${homeShape}.`,
  }),
  Object.freeze({ rule: "infra-account-id", text: () => ["tenant acct-", "4711-eu-north-1 is live"].join("") }),
  Object.freeze({ rule: "planning-dir", text: () => ["quoted from .", "plan/BUILD-SPEC.md"].join("") }),
]);
const ARM_SHAPE_CASES = Object.freeze(Object.fromEntries(ARM_SHAPE_FIXTURES.map(({ rule }) => [
  rule,
  defineArmCase(
    `shape.${rule}`,
    `shape ${rule}: planted in the working tree and named by the gate`,
    ARM_FULL_ONLY,
  ),
])));

const ARM_ROTATION_CRASH_POINTS = Object.freeze([
  "intent-durable",
  "predecessor-durable",
  "successor-durable",
  "successor-activated",
  "successor-readback",
  "receipt-durable",
  "receipt-readback",
  "deleting-durable",
  "predecessor-in-deleting-custody",
  "predecessor-deleted",
  "intent-removed",
  "lock-removed",
]);
const ARM_ROTATION_CRASH_CASES = Object.freeze(Object.fromEntries(ARM_ROTATION_CRASH_POINTS.map((point) => [
  point,
  defineArmCase(
    `rotation.crash.${point}`,
    `exclusion rotation crash recovery: ${point} resumes forward to one exact terminal state`,
    ARM_FULL_ONLY,
  ),
])));

const ARM_ROTATION_CUSTODY_FAULTS = Object.freeze([
  Object.freeze({
    code: "EIO",
    point: "create-write:exclusion-policy-rotation.lock",
    expectedSubject: "the exclusion rotation lock could not be created durably and exclusively",
    manualRecoverySubject: "the exclusion rotation lock is corrupt",
    manualTargetKind: "lock",
  }),
  Object.freeze({
    code: "ENOSPC",
    point: "create-partial-write:exclusion-policy-rotation-intent-",
    expectedSubject: "the exclusion rotation intent could not be created durably and exclusively",
    manualRecoverySubject: "the exclusion rotation intent is not JSON",
    manualTargetKind: "intent",
  }),
  Object.freeze({
    code: "EIO",
    point: "create-file-sync:exclusion-policy-rotation-intent-",
    expectedSubject: "the exclusion rotation intent could not be created durably and exclusively",
  }),
  Object.freeze({
    code: "EIO",
    point: "create-directory-sync:exclusion-policy-rotation-intent-",
    expectedSubject: "the exclusion rotation intent could not be created durably and exclusively",
  }),
  Object.freeze({
    code: "ENOSPC",
    point: "replace-rename:exclusions.pending-successor-v3-",
    expectedSubject: "the exclusion policy successor could not be activated durably",
  }),
  Object.freeze({
    code: "EINVAL",
    point: "unlink:exclusions.deleting-v",
    expectedSubject: "the receipt-bound deleting predecessor could not be removed durably",
  }),
  Object.freeze({
    code: "EIO",
    point: "replace-directory-sync:exclusions.json",
    expectedSubject: "the exclusion policy successor could not be activated durably",
  }),
  Object.freeze({
    code: "ENOSPC",
    point: "create-directory-sync:exclusion-policy-rotation-v3-",
    expectedSubject: "the exclusion rotation receipt could not be created durably and exclusively",
  }),
  Object.freeze({
    code: "EIO",
    point: "create-partial-write:exclusion-policy-rotation-v3-",
    expectedSubject: "the exclusion rotation receipt could not be created durably and exclusively",
    manualRecoverySubject: "the exclusion rotation receipt is not JSON",
    manualTargetKind: "receipt",
  }),
  Object.freeze({
    code: "EINVAL",
    point: "create-link:exclusion-policy-rotation-v3-",
    expectedSubject: "the exclusion rotation receipt could not be created durably and exclusively",
  }),
  Object.freeze({
    code: "EINVAL",
    point: "unlink-directory-sync:exclusions.deleting-v",
    expectedSubject: "the receipt-bound deleting predecessor could not be removed durably",
  }),
]);
const ARM_ROTATION_CUSTODY_CASES = Object.freeze(Object.fromEntries(ARM_ROTATION_CUSTODY_FAULTS.map((fault) => {
  const outcome = fault.manualRecoverySubject === undefined
    ? "resumes exactly once" : "fails closed for manual recovery";
  return [fault.point, defineArmCase(
    `rotation.custody.${fault.code.toLowerCase()}.${fault.point}`,
    `exclusion rotation I/O recovery: ${fault.code} at ${fault.point} retains evidence and ${outcome}`,
    ARM_FULL_ONLY,
  )];
})));

const ARM_ROTATION_DIRECT_FINAL_CRASHES = Object.freeze([
  Object.freeze({
    point: "create-partial-write:exclusion-policy-rotation.lock",
    manualRecoverySubject: "the exclusion rotation lock is corrupt",
    manualTargetKind: "lock",
  }),
  Object.freeze({ point: "create-final-synced:exclusion-policy-rotation-intent-" }),
  Object.freeze({
    point: "create-final-linked:exclusion-policy-rotation-v3-",
    manualRecoverySubject: "the exclusion rotation receipt is not JSON",
    manualTargetKind: "receipt",
  }),
]);
const ARM_ROTATION_DIRECT_FINAL_CASES = Object.freeze(Object.fromEntries(
  ARM_ROTATION_DIRECT_FINAL_CRASHES.map((crashCase) => {
    const outcome = crashCase.manualRecoverySubject === undefined
      ? "resumes from exact durable evidence" : "retains partial evidence for manual recovery";
    return [crashCase.point, defineArmCase(
      `rotation.direct-final.${crashCase.point}`,
      `exclusion rotation direct-final crash custody: ${crashCase.point} ${outcome}`,
      ARM_FULL_ONLY,
    )];
  }),
));

// These cases preserve the path, history and diagnostic-redaction attacks established by the
// earlier boundary hardening work. They are registered before the plan is frozen so the terminal
// supervisor can prove that every retained case ran exactly once against the provenance-bound gate.
const ARM_TASK3_CASES = Object.freeze({
  tagAnnotationBranchShadowFound: defineArmCase(
    "task3.tag.annotation-branch-shadow.found",
    "L-TAG annotation: an independently benign tag name cannot hide a confidential annotation",
    ARM_FULL_ONLY,
  ),
  tagAnnotationExactPrepushFound: defineArmCase(
    "task3.tag.annotation-exact-prepush.found",
    "L-TAG annotation: the exact pre-push tag ref enumerates the annotation exactly once",
    ARM_FULL_ONLY,
  ),
  tagAnnotationClean: defineArmCase(
    "task3.tag.annotation-branch-shadow.clean",
    "L-TAG annotation: deleting the annotated tag restores CLEAN",
    ARM_FULL_ONLY,
  ),
  refExactFound: defineArmCase(
    "task3.ref.exact.found",
    "L-MSG exact confidential ref is blocked without disclosure",
    ARM_FULL_ONLY,
  ),
  refHyphenFound: defineArmCase(
    "task3.ref.hyphen-compound.found",
    "L-MSG hyphen-compound confidential ref is blocked without disclosure",
    ARM_FULL_ONLY,
  ),
  refUnderscoreFound: defineArmCase(
    "task3.ref.underscore-compound.found",
    "L-MSG underscore-compound confidential ref is blocked without disclosure",
    ARM_FULL_ONLY,
  ),
  refClean: defineArmCase(
    "task3.ref.benign.clean",
    "L-MSG benign ref control stays CLEAN",
    ARM_FULL_ONLY,
  ),
  mapFileFound: defineArmCase(
    "task3.map.decoded-file.found",
    "L-MAP decoded file bytes are scanned without disclosure",
    ARM_FULL_ONLY,
  ),
  mapFileClean: defineArmCase(
    "task3.map.decoded-file.clean",
    "L-MAP decoded file control stays CLEAN",
    ARM_FULL_ONLY,
  ),
  mapSourceRootFound: defineArmCase(
    "task3.map.decoded-source-root.found",
    "L-MAP decoded sourceRoot bytes are scanned without disclosure",
    ARM_FULL_ONLY,
  ),
  mapSourceRootClean: defineArmCase(
    "task3.map.decoded-source-root.clean",
    "L-MAP decoded sourceRoot control stays CLEAN",
    ARM_FULL_ONLY,
  ),
  mapSourcesFound: defineArmCase(
    "task3.map.decoded-sources.found",
    "L-MAP decoded sources bytes are scanned without disclosure",
    ARM_FULL_ONLY,
  ),
  mapSourcesClean: defineArmCase(
    "task3.map.decoded-sources.clean",
    "L-MAP decoded sources control stays CLEAN",
    ARM_FULL_ONLY,
  ),
  mapStructuralRedacted: defineArmCase(
    "task3.map.structural-redaction.found",
    "L-MAP escaped absolute source blocks without reflecting decoded bytes",
    ARM_FULL_ONLY,
  ),
  mapCombinedContainmentFound: defineArmCase(
    "task3.map.combined-containment.found",
    "L-MAP resolves sourceRoot and source together",
    ARM_FULL_ONLY,
  ),
  mapCombinedContainmentClean: defineArmCase(
    "task3.map.combined-containment.clean",
    "L-MAP package-local source stays CLEAN",
    ARM_FULL_ONLY,
  ),
  mapMalformedRedacted: defineArmCase(
    "task3.map.malformed.redacted",
    "L-MAP invalid input blocks without diagnostic reflection",
    ARM_FULL_ONLY,
  ),
  mapMalformedClean: defineArmCase(
    "task3.map.malformed.clean",
    "L-MAP valid map control stays CLEAN",
    ARM_FULL_ONLY,
  ),
  pathWtFound: defineArmCase("task3.path.l-wt.found", "L-WT published path is found without disclosure", ARM_FULL_ONLY),
  pathWtClean: defineArmCase("task3.path.l-wt.clean", "L-WT path control returns CLEAN", ARM_FULL_ONLY),
  pathIdxFound: defineArmCase("task3.path.l-idx.found", "L-IDX published path is found without disclosure", ARM_FULL_ONLY),
  pathIdxClean: defineArmCase("task3.path.l-idx.clean", "L-IDX path control returns CLEAN", ARM_FULL_ONLY),
  pathPushFound: defineArmCase("task3.path.l-push.found", "L-PUSH published path is found without disclosure", ARM_FULL_ONLY),
  pathPushClean: defineArmCase("task3.path.l-push.clean", "L-PUSH path control returns CLEAN", ARM_FULL_ONLY),
  pathPackFound: defineArmCase("task3.path.l-pack.found", "L-PACK published path is found without disclosure", ARM_FULL_ONLY),
  pathPackClean: defineArmCase("task3.path.l-pack.clean", "L-PACK path control returns CLEAN", ARM_FULL_ONLY),
  pathMapFound: defineArmCase("task3.path.l-map-map.found", "L-MAP map path is found without disclosure", ARM_FULL_ONLY),
  pathMapClean: defineArmCase("task3.path.l-map-map.clean", "L-MAP map path control returns CLEAN", ARM_FULL_ONLY),
  pathDeclarationFound: defineArmCase("task3.path.l-map-declaration.found", "L-MAP declaration path is found without disclosure", ARM_FULL_ONLY),
  pathDeclarationClean: defineArmCase("task3.path.l-map-declaration.clean", "L-MAP declaration path control returns CLEAN", ARM_FULL_ONLY),
  pathFixFound: defineArmCase("task3.path.l-fix.found", "L-FIX directory path is found without disclosure", ARM_FULL_ONLY),
  pathFixClean: defineArmCase("task3.path.l-fix.clean", "L-FIX directory path control returns CLEAN", ARM_FULL_ONLY),
  pathRegistryArmed: defineArmCase(
    "task3.path.registry-armed",
    "every distinct published file-path representation is armed",
    ARM_FULL_ONLY,
  ),
  compoundHyphenFound: defineArmCase("task3.path.compound-hyphen.found", "hyphen compound path token is found without disclosure", ARM_FULL_ONLY),
  compoundHyphenClean: defineArmCase("task3.path.compound-hyphen.clean", "hyphen compound path returns CLEAN", ARM_FULL_ONLY),
  compoundUnderscoreFound: defineArmCase("task3.path.compound-underscore.found", "underscore compound path token is found without disclosure", ARM_FULL_ONLY),
  compoundUnderscoreClean: defineArmCase("task3.path.compound-underscore.clean", "underscore compound path returns CLEAN", ARM_FULL_ONLY),
  symlinkFixture: defineArmCase("task3.symlink.git-mode", "working-tree symlink fixture is a published Git symlink", ARM_FULL_ONLY),
  symlinkFound: defineArmCase("task3.symlink.target-bytes.found", "published symlink target bytes are scanned without following the target", ARM_FULL_ONLY),
  symlinkClean: defineArmCase("task3.symlink.target-bytes.clean", "removing the symlink restores CLEAN", ARM_FULL_ONLY),
  composedRedactionFound: defineArmCase("task3.redaction.composed.found", "cross-rule findings do not reproduce confidential text", ARM_FULL_ONLY),
  composedRedactionClean: defineArmCase("task3.redaction.composed.clean", "composed-report control returns CLEAN", ARM_FULL_ONLY),
  pathDedupe: defineArmCase("task3.path.dedupe", "one canonical path reached through four lanes is one finding", ARM_FULL_ONLY),
  pathRatchetBlocks: defineArmCase("task3.path.ratchet.blocks", "an unreviewed path finding blocks", ARM_FULL_ONLY),
  pathRatchetCarries: defineArmCase("task3.path.ratchet.carries", "the exact reviewed path is carried", ARM_FULL_ONLY),
  pathRatchetRenameBlocks: defineArmCase("task3.path.ratchet.rename-blocks", "renaming a reviewed path changes identity and blocks", ARM_FULL_ONLY),
  nestedPathBlocks: defineArmCase("task3.path.nested-repo.blocks", "an unlisted nested repository path blocks without disclosure", ARM_FULL_ONLY),
  nestedPathClean: defineArmCase("task3.path.nested-repo.clean", "an allowlisted nested repository path stays CLEAN", ARM_FULL_ONLY),
  filenameSuppressionRefused: defineArmCase("task3.path.filename-suppression.refused", "a filename cannot carry an inline suppression comment", ARM_FULL_ONLY),
  scopedIndexFound: defineArmCase("task3.scope.l-idx.found", "staged bytes retain canonical path scope", ARM_FULL_ONLY),
  scopedIndexClean: defineArmCase("task3.scope.l-idx.clean", "staged synthetic namespace stays CLEAN", ARM_FULL_ONLY),
  scopedPushFound: defineArmCase("task3.scope.l-push.found", "pushed bytes retain canonical path scope", ARM_FULL_ONLY),
  scopedPushClean: defineArmCase("task3.scope.l-push.clean", "pushed synthetic namespace stays CLEAN", ARM_FULL_ONLY),
  historyEveryBlobFound: defineArmCase("task3.history.every-blob.found", "every reachable pushed blob version is scanned", ARM_FULL_ONLY),
  historyEveryBlobClean: defineArmCase("task3.history.every-blob.clean", "clean history stays CLEAN", ARM_FULL_ONLY),
  mergeFixture: defineArmCase("task3.history.merge.two-parent", "merge fixture is a real two-parent commit", ARM_FULL_ONLY),
  mergeFound: defineArmCase("task3.history.merge-result.found", "merge-result blob versions are scanned", ARM_FULL_ONLY),
  mergeClean: defineArmCase("task3.history.merge-result.clean", "clean merge topology stays CLEAN", ARM_FULL_ONLY),
  replacementRemoteProof: defineArmCase("task3.git-replace.remote-original", "remote receives the original object bytes", ARM_FULL_ONLY),
  replacementFound: defineArmCase("task3.git-replace.original.found", "scanner reads the original objects that push publishes", ARM_FULL_ONLY),
  replacementClean: defineArmCase("task3.git-replace.benign.clean", "the actual benign object stays CLEAN", ARM_FULL_ONLY),
  replacementReverseClean: defineArmCase("task3.git-replace.reverse.clean", "a confidential local replacement cannot taint benign published bytes", ARM_FULL_ONLY),
  graftRefused: defineArmCase("task3.git-graft.refused", "a legacy graft is refused with terminal setup evidence", ARM_FULL_ONLY),
  graftClean: defineArmCase("task3.git-graft.clean", "removing the graft restores CLEAN", ARM_FULL_ONLY),
  parentlessFound: defineArmCase("task3.history.parentless.found", "root-commit paths and blobs are scanned", ARM_FULL_ONLY),
  parentlessClean: defineArmCase("task3.history.parentless.clean", "the same root tree without the token stays CLEAN", ARM_FULL_ONLY),
  unparsableBaselineRedacted: defineArmCase("task3.failclosed.unparsable-baseline.redacted", "an unparsable baseline fails closed without reflecting input", ARM_FULL_ONLY),
  unreadablePathRedacted: defineArmCase("task3.failclosed.unreadable-path.redacted", "an unreadable confidential path fails closed without disclosure", ARM_FULL_ONLY),
});

const ARM_CASE_PLAN_DOMAIN = "noa-boundary-arm-case-plan/v1\0";
const armCasePlanForMode = (mode) => {
  const ids = [...armCaseRegistry.values()]
    .filter((descriptor) => descriptor.modes.includes(mode))
    .map((descriptor) => descriptor.id)
    .sort();
  const bytes = `${ARM_CASE_PLAN_DOMAIN}${canonicalJson(ids)}`;
  return Object.freeze({
    diagnosticCaseCount: ids.length,
    ids: Object.freeze(ids),
    idSet: new Set(ids),
    sha256: createHash("sha256").update(bytes, "utf8").digest("hex"),
  });
};
const ARM_CASE_PLANS = Object.freeze({
  [ARM_CASE_MODE_FULL]: armCasePlanForMode(ARM_CASE_MODE_FULL),
  [ARM_CASE_MODE_SPOOL_ONLY]: armCasePlanForMode(ARM_CASE_MODE_SPOOL_ONLY),
});

export function boundaryArmCasePlansForReview() {
  return Object.freeze({
    full: Object.freeze({
      diagnosticCaseCount: ARM_CASE_PLANS[ARM_CASE_MODE_FULL].diagnosticCaseCount,
      ids: ARM_CASE_PLANS[ARM_CASE_MODE_FULL].ids,
      sha256: ARM_CASE_PLANS[ARM_CASE_MODE_FULL].sha256,
    }),
    spoolOnly: Object.freeze({
      diagnosticCaseCount: ARM_CASE_PLANS[ARM_CASE_MODE_SPOOL_ONLY].diagnosticCaseCount,
      ids: ARM_CASE_PLANS[ARM_CASE_MODE_SPOOL_ONLY].ids,
      sha256: ARM_CASE_PLANS[ARM_CASE_MODE_SPOOL_ONLY].sha256,
    }),
  });
}

function exactArmTerminalSummary(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const keys = Object.keys(value).sort();
  const expected = [
    "casePlanSha256", "duplicateCaseCount", "event", "failureCount", "missingCaseCount",
    "observedCaseCount", "plannedCaseCount", "protocol", "status", "unexpectedCaseCount",
  ];
  return canonicalJson(keys) === canonicalJson(expected)
    && value.protocol === ARM_TERMINAL_PROTOCOL
    && value.event === "complete"
    && ["PASS", "FAIL", "SETUP_FAILED"].includes(value.status)
    && /^[0-9a-f]{64}$/.test(value.casePlanSha256)
    && [
      value.duplicateCaseCount,
      value.failureCount,
      value.missingCaseCount,
      value.observedCaseCount,
      value.plannedCaseCount,
      value.unexpectedCaseCount,
    ]
      .every((count) => Number.isSafeInteger(count) && count >= 0);
}

function armTerminalSummaries(output) {
  const summaries = [];
  for (const line of String(output ?? "").split(/\r?\n/)) {
    if (!line.startsWith(ARM_TERMINAL_PREFIX)) continue;
    try {
      const parsed = JSON.parse(line.slice(ARM_TERMINAL_PREFIX.length));
      if (exactArmTerminalSummary(parsed)) summaries.push(parsed);
      else summaries.push(null);
    } catch { summaries.push(null); }
  }
  return summaries;
}

export function classifyArmChildTerminal({
  exitCode,
  signal = null,
  timedOut = false,
  output = "",
  expectedCasePlanSha256,
  expectedCaseCount,
}) {
  const summaries = armTerminalSummaries(output);
  if (timedOut || signal !== null || exitCode === null || summaries.length !== 1 || summaries[0] === null) {
    return Object.freeze({ code: 2, reason: "ARM_CHILD_TERMINAL_EVIDENCE_INVALID" });
  }
  const summary = summaries[0];
  if (!/^[0-9a-f]{64}$/.test(expectedCasePlanSha256)
      || summary.casePlanSha256 !== expectedCasePlanSha256) {
    return Object.freeze({ code: 2, reason: "ARM_CHILD_CASE_PLAN_DIGEST_MISMATCH" });
  }
  if (!Number.isSafeInteger(expectedCaseCount) || expectedCaseCount < 1
      || summary.plannedCaseCount !== expectedCaseCount
      || summary.observedCaseCount !== expectedCaseCount) {
    return Object.freeze({ code: 2, reason: "ARM_CHILD_CASE_PLAN_COUNT_MISMATCH" });
  }
  if (summary.plannedCaseCount !== summary.observedCaseCount
      || summary.missingCaseCount !== 0
      || summary.unexpectedCaseCount !== 0
      || summary.duplicateCaseCount !== 0) {
    return Object.freeze({ code: 2, reason: "ARM_CHILD_CASE_PLAN_INCOMPLETE" });
  }
  if (exitCode !== 0 || summary.status !== "PASS" || summary.failureCount !== 0) {
    return Object.freeze({ code: 1, reason: "ARM_CHILD_REPORTED_FAILURE" });
  }
  return Object.freeze({ code: 0, reason: "ARM_CHILD_PASS" });
}

function waitForArmChildClose(child, {
  maxOutputBytes = ARM_CHILD_OUTPUT_MAX_BYTES,
  timeoutMs = 2_000,
} = {}) {
  if (!Number.isSafeInteger(maxOutputBytes) || maxOutputBytes < 1
      || maxOutputBytes > ARM_CHILD_OUTPUT_MAX_BYTES) {
    throw new TypeError("arm child output limit must be a positive safe integer within the fixed maximum");
  }
  return new Promise((resolveWait) => {
    let settled = false;
    let timedOut = false;
    let error = null;
    let outputLimitExceeded = false;
    const stdout = { buffer: Buffer.alloc(maxOutputBytes), bytes: 0 };
    const stderr = { buffer: Buffer.alloc(maxOutputBytes), bytes: 0 };
    let timeout;
    let fallback;
    const stopForOutputLimit = () => {
      if (outputLimitExceeded) return;
      outputLimitExceeded = true;
      error ??= Object.assign(new Error("arm child output exceeded its fixed per-stream byte limit"), {
        code: "ERR_CHILD_PROCESS_STDIO_MAXBUFFER",
      });
      if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
      child.stdout?.destroy();
      child.stderr?.destroy();
    };
    const collect = (target, chunk) => {
      if (outputLimitExceeded) return;
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), "utf8");
      const remaining = maxOutputBytes - target.bytes;
      if (remaining > 0) {
        const retainedLength = Math.min(bytes.length, remaining);
        bytes.copy(target.buffer, target.bytes, 0, retainedLength);
        target.bytes += retainedLength;
      }
      if (bytes.length > remaining) stopForOutputLimit();
    };
    child.stdout?.on("data", (chunk) => { collect(stdout, chunk); });
    child.stderr?.on("data", (chunk) => { collect(stderr, chunk); });
    const settle = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      clearTimeout(fallback);
      resolveWait(Object.freeze({
        code: child.exitCode,
        error,
        outputLimitExceeded,
        signal: child.signalCode,
        stderr: stderr.buffer.subarray(0, stderr.bytes).toString("utf8"),
        stderrBytes: stderr.bytes,
        stdout: stdout.buffer.subarray(0, stdout.bytes).toString("utf8"),
        stdoutBytes: stdout.bytes,
        timedOut,
      }));
    };
    child.once("error", (childError) => { error ??= childError; settle(); });
    child.once("close", settle);
    timeout = setTimeout(() => {
      timedOut = true;
      if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
      // `close` remains the authority because it proves stdio closed too. This second bound handles
      // a runtime that fails to deliver close after kill without leaving an unresolved Promise.
      fallback = setTimeout(settle, 1_000);
    }, timeoutMs);
    // The child may have closed before this waiter was created. Checking both before and after
    // listener installation removes that race; queueMicrotask keeps settlement consistently async.
    if (child.exitCode !== null || child.signalCode !== null) queueMicrotask(settle);
  });
}

function writeArmChildInput(child, bytes, { timeoutMs = 5_000 } = {}) {
  return new Promise((resolveWrite) => {
    let completed = false;
    let error = null;
    let settled = false;
    let timedOut = false;
    let timeout;
    const settle = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      resolveWrite(Object.freeze({ completed, error, timedOut }));
    };
    const stdin = child.stdin;
    if (stdin === null || stdin === undefined || typeof stdin.end !== "function") {
      error = new Error("nested scanner bootstrap stdin is unavailable");
      settle();
      return;
    }
    // Keep the listener installed through child close. A pipe can report EPIPE asynchronously after
    // end() returns, so try/catch alone cannot make this channel fail closed.
    stdin.once("error", (streamError) => {
      error = streamError;
      settle();
    });
    timeout = setTimeout(() => {
      timedOut = true;
      stdin.destroy();
      if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
      settle();
    }, timeoutMs);
    try {
      stdin.end(bytes, (finishError) => {
        if (finishError) error = finishError;
        else completed = true;
        settle();
      });
    } catch (streamError) {
      error = streamError;
      stdin.destroy();
      if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
      settle();
    }
  });
}

function classifyScannerSelftestChild({ delivery, observed }) {
  if (delivery === null || typeof delivery !== "object" || Array.isArray(delivery)
      || observed === null || typeof observed !== "object" || Array.isArray(observed)
      || delivery.completed !== true || delivery.error !== null || delivery.timedOut !== false
      || observed.error !== null || observed.signal !== null || observed.timedOut !== false
      || !Number.isSafeInteger(observed.code)) {
    return Object.freeze({ code: 2, reason: "SCANNER_SELFTEST_CHILD_TERMINAL_EVIDENCE_INVALID" });
  }
  if (observed.code !== 0) {
    return Object.freeze({ code: 1, reason: "SCANNER_SELFTEST_CHILD_REPORTED_FAILURE" });
  }
  return Object.freeze({ code: 0, reason: "SCANNER_SELFTEST_CHILD_PASS" });
}

const GATE_PROVENANCE_EXPECTATION_FIELDS = Object.freeze([
  "authorityClass",
  "authorityNonClaim",
  "bootstrapMode",
  "controlManifestDigest",
  "controlManifestVersion",
  "externalAuthorizationSha256",
  "schemaVersion",
  "tier",
  "verification",
  "visibilitySource",
]);

function gateChildAuthorityProblem(parsed, expectation) {
  if (!parsed.protocolComplete) {
    return `GATE_CHILD_PROTOCOL_INVALID: ${parsed.error ?? "unknown gate terminal failure"}`;
  }
  if (parsed.gate !== "boundary") return "GATE_CHILD_ID_MISMATCH";
  if (expectation === null || typeof expectation !== "object" || Array.isArray(expectation)) {
    return "GATE_CHILD_EXPECTATION_INVALID";
  }
  if (parsed.protocol !== expectation.protocol) return "GATE_CHILD_PROTOCOL_MISMATCH";
  if (parsed.provenance === null) return "GATE_CHILD_PROVENANCE_MISSING";
  for (const field of GATE_PROVENANCE_EXPECTATION_FIELDS) {
    if (Object.hasOwn(expectation, field)
        && parsed.provenance[field] !== expectation[field]) {
      return `GATE_CHILD_PROVENANCE_${field.toUpperCase()}_MISMATCH`;
    }
  }
  if (Object.hasOwn(expectation, "subject")
      && canonicalBoundaryJson(parsed.provenance.subject)
        !== canonicalBoundaryJson(expectation.subject)) {
    return "GATE_CHILD_PROVENANCE_SUBJECT_MISMATCH";
  }
  return null;
}

function boundedChildProcessError(error) {
  if (error === null || error === undefined) return Object.freeze({ code: null, message: null });
  const code = typeof error.code === "string" ? error.code.slice(0, 80) : null;
  return Object.freeze({ code, message: "<withheld>" });
}

function observeBoundaryGateChild({
  code,
  error = null,
  signal = null,
  stdout = "",
  stderr = "",
  expectation,
}) {
  const parsed = parseGateEvidence(stdout, { requireProvenance: true });
  const authorityProblem = gateChildAuthorityProblem(parsed, expectation);
  const accepted = authorityProblem === null;
  const processError = boundedChildProcessError(error);
  const processDiagnostic = Object.freeze({
    authorityProblem,
    errorCode: processError.code,
    errorMessage: processError.message,
    signal,
    status: code,
  });
  const abnormalProcessDiagnostic = !accepted || error !== null || code === null || signal !== null
    ? `\nBOUNDARY_ARM_CHILD_PROCESS ${canonicalBoundaryJson(processDiagnostic)}\n`
    : "";
  return Object.freeze({
    authorityProblem,
    childProcess: processDiagnostic,
    code: accepted ? code : null,
    findings: accepted ? parsed.findings : Object.freeze([]),
    observedCode: code,
    observedFindings: Object.freeze([...(parsed.findings ?? [])]),
    out: `${stdout}${stderr}${abnormalProcessDiagnostic}`,
    protocol: parsed.protocol ?? null,
    protocolComplete: accepted,
    provenance: parsed.provenance ?? null,
    signal,
  });
}

function normalizedArmGateOption(actualArgs, flag, fallback) {
  const positions = [];
  for (const [index, arg] of actualArgs.entries()) {
    if (arg === flag) positions.push(index);
    else if (typeof arg === "string" && arg.startsWith(`${flag}=`)) return null;
  }
  if (positions.length === 0) return Object.freeze({ value: fallback });
  if (positions.length !== 1) return null;
  const value = actualArgs[positions[0] + 1];
  if (typeof value !== "string" || value.startsWith("--")) return null;
  return Object.freeze({ value: value.toLowerCase() });
}

// This is the supervisor's independent projection of the child's closed CLI grammar. A malformed
// tier/visibility option produces no expectation, so even a forged verified terminal record cannot
// turn that child's OS exit into credit.
function boundaryGateMeasurementExpectation(actualArgs) {
  const tier = normalizedArmGateOption(actualArgs, "--tier", "ab");
  const visibility = normalizedArmGateOption(actualArgs, "--repo-visibility-source", null);
  if (tier === null || visibility === null) return null;
  return Object.freeze({ tier: tier.value, visibilitySource: visibility.value });
}

function externalGateExpectation({
  bootstrapMode,
  manifest,
  authorizationSha256,
  subject,
  tier,
  visibilitySource,
}) {
  return Object.freeze({
    authorityClass: BOUNDARY_AUTHORITY_CLASS_EXTERNAL,
    authorityNonClaim: EXTERNAL_SANITIZED_AUTHORIZATION_NON_CLAIM,
    bootstrapMode,
    controlManifestDigest: manifest.digest,
    controlManifestVersion: BOUNDARY_CONTROL_MANIFEST_VERSION,
    externalAuthorizationSha256: authorizationSha256,
    protocol: BOUNDARY_CANDIDATE_TIER_A_GATE_EXPECTATION.protocol,
    schemaVersion: BOUNDARY_CANDIDATE_TIER_A_GATE_EXPECTATION.schemaVersion,
    subject,
    tier,
    verification: BOUNDARY_CANDIDATE_TIER_A_GATE_EXPECTATION.verification,
    visibilitySource,
  });
}

export async function runArmTerminalSupervisorMetaSelftest() {
  const expectedCasePlanSha256 = ARM_REVIEWED_SPOOL_ONLY_CASE_PLAN_SHA256;
  const expectedCaseCount = ARM_DIAGNOSTIC_SPOOL_ONLY_CASE_COUNT;
  const passSummary = {
    casePlanSha256: expectedCasePlanSha256,
    duplicateCaseCount: 0,
    event: "complete",
    failureCount: 0,
    missingCaseCount: 0,
    observedCaseCount: expectedCaseCount,
    plannedCaseCount: expectedCaseCount,
    protocol: ARM_TERMINAL_PROTOCOL,
    status: "PASS",
    unexpectedCaseCount: 0,
  };
  const failSummary = { ...passSummary, failureCount: 1, status: "FAIL" };
  const incompleteSchemaSummary = { ...passSummary };
  delete incompleteSchemaSummary.missingCaseCount;
  const wrongDigestSummary = { ...passSummary, casePlanSha256: ARM_REVIEWED_FULL_CASE_PLAN_SHA256 };
  const missingCaseSummary = { ...passSummary, missingCaseCount: 1, observedCaseCount: 2 };
  const unexpectedCaseSummary = { ...passSummary, unexpectedCaseCount: 1 };
  const duplicateCaseSummary = { ...passSummary, duplicateCaseCount: 1 };
  const zeroCaseSummary = { ...passSummary, observedCaseCount: 0, plannedCaseCount: 0 };
  const shortCaseSummary = {
    ...passSummary,
    observedCaseCount: expectedCaseCount - 1,
    plannedCaseCount: expectedCaseCount - 1,
  };
  const longCaseSummary = {
    ...passSummary,
    observedCaseCount: expectedCaseCount + 1,
    plannedCaseCount: expectedCaseCount + 1,
  };
  const fullPassSummary = {
    ...passSummary,
    casePlanSha256: ARM_REVIEWED_FULL_CASE_PLAN_SHA256,
    observedCaseCount: ARM_DIAGNOSTIC_FULL_CASE_COUNT,
    plannedCaseCount: ARM_DIAGNOSTIC_FULL_CASE_COUNT,
  };
  const child = (source) => spawnSync(process.execPath, ["-e", source], {
    encoding: "utf8", shell: false,
  });
  const missing = child("process.exit(0)");
  const explicitFailure = child(`process.stdout.write(${JSON.stringify(ARM_TERMINAL_PREFIX)} + JSON.stringify(${canonicalJson(failSummary)}) + "\\n")`);
  const duplicate = child(`const p=${JSON.stringify(ARM_TERMINAL_PREFIX)}; const s=JSON.stringify(${canonicalJson(passSummary)}); process.stdout.write(p+s+"\\n"+p+s+"\\n")`);
  const incomplete = child(`process.stdout.write(${JSON.stringify(ARM_TERMINAL_PREFIX)} + JSON.stringify(${canonicalJson(incompleteSchemaSummary)}) + "\\n")`);
  const wrongDigest = child(`process.stdout.write(${JSON.stringify(ARM_TERMINAL_PREFIX)} + JSON.stringify(${canonicalJson(wrongDigestSummary)}) + "\\n")`);
  const missingCase = child(`process.stdout.write(${JSON.stringify(ARM_TERMINAL_PREFIX)} + JSON.stringify(${canonicalJson(missingCaseSummary)}) + "\\n")`);
  const unexpectedCase = child(`process.stdout.write(${JSON.stringify(ARM_TERMINAL_PREFIX)} + JSON.stringify(${canonicalJson(unexpectedCaseSummary)}) + "\\n")`);
  const duplicateCase = child(`process.stdout.write(${JSON.stringify(ARM_TERMINAL_PREFIX)} + JSON.stringify(${canonicalJson(duplicateCaseSummary)}) + "\\n")`);
  const zeroCase = child(`process.stdout.write(${JSON.stringify(ARM_TERMINAL_PREFIX)} + JSON.stringify(${canonicalJson(zeroCaseSummary)}) + "\\n")`);
  const shortCase = child(`process.stdout.write(${JSON.stringify(ARM_TERMINAL_PREFIX)} + JSON.stringify(${canonicalJson(shortCaseSummary)}) + "\\n")`);
  const longCase = child(`process.stdout.write(${JSON.stringify(ARM_TERMINAL_PREFIX)} + JSON.stringify(${canonicalJson(longCaseSummary)}) + "\\n")`);
  const immediateNonzero = child("process.exit(2)");
  const signaled = child('process.kill(process.pid, "SIGTERM")');
  const lateWaitChild = spawn(process.execPath, ["-e", "process.exit(2)"], {
    stdio: ["ignore", "pipe", "pipe"],
  });
  await new Promise((resolveTurn) => setTimeout(resolveTurn, 25));
  const lateWait = await waitForArmChildClose(lateWaitChild, { timeoutMs: 250 });
  const timeoutChild = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], {
    stdio: ["ignore", "pipe", "pipe"],
  });
  const timedOut = await waitForArmChildClose(timeoutChild, { timeoutMs: 25 });
  const outputLimitBytes = 64 * 1024;
  const outputLimitChild = spawn(process.execPath, ["-e", [
    `process.stdout.write(Buffer.alloc(${outputLimitBytes * 2}, 0x78));`,
    "setInterval(() => {}, 1000);",
  ].join("\n")], {
    stdio: ["ignore", "pipe", "pipe"],
  });
  const outputLimited = await waitForArmChildClose(outputLimitChild, {
    maxOutputBytes: outputLimitBytes,
    timeoutMs: 2_000,
  });
  const inheritedPipeChild = spawn(process.execPath, ["-e", [
    'const { spawn } = require("node:child_process");',
    'spawn(process.execPath, ["-e", "setTimeout(() => {}, 3000)"], { stdio: ["ignore", 1, 2] });',
    // The direct child cannot exit until the waiter is installed. This preserves the exact
    // exit-0/open-descendant-stdio failure mode without depending on scheduler timing.
    'process.stdin.once("data", () => process.exit(0));',
  ].join("\n")], {
    stdio: ["pipe", "pipe", "pipe"],
  });
  const inheritedPipeWaiting = waitForArmChildClose(inheritedPipeChild, { timeoutMs: 2_000 });
  inheritedPipeChild.stdin.end("exit-after-waiter-installation\n");
  const inheritedPipe = await inheritedPipeWaiting;
  const successfulDelivery = Object.freeze({ completed: true, error: null, timedOut: false });
  const inheritedPipeClassification = classifyScannerSelftestChild({
    delivery: successfulDelivery,
    observed: inheritedPipe,
  });
  const outputLimitClassification = classifyScannerSelftestChild({
    delivery: successfulDelivery,
    observed: outputLimited,
  });
  const scannerChildContractResults = [
    classifyScannerSelftestChild({
      delivery: Object.freeze({ completed: false, error: null, timedOut: false }),
      observed: Object.freeze({ code: 0, error: null, signal: null, timedOut: false }),
    }),
    classifyScannerSelftestChild({
      delivery: Object.freeze({ completed: false, error: new Error("synthetic EPIPE"), timedOut: false }),
      observed: Object.freeze({ code: 0, error: null, signal: null, timedOut: false }),
    }),
    classifyScannerSelftestChild({
      delivery: Object.freeze({ completed: false, error: null, timedOut: true }),
      observed: Object.freeze({ code: 0, error: null, signal: null, timedOut: false }),
    }),
    classifyScannerSelftestChild({
      delivery: successfulDelivery,
      observed: Object.freeze({ code: 0, error: new Error("synthetic child error"), signal: null, timedOut: false }),
    }),
    classifyScannerSelftestChild({
      delivery: successfulDelivery,
      observed: Object.freeze({ code: 0, error: null, signal: "SIGTERM", timedOut: false }),
    }),
    classifyScannerSelftestChild({
      delivery: successfulDelivery,
      observed: Object.freeze({ code: 0, error: null, signal: null, timedOut: true }),
    }),
    classifyScannerSelftestChild({
      delivery: successfulDelivery,
      observed: Object.freeze({ code: 1, error: null, signal: null, timedOut: false }),
    }),
    classifyScannerSelftestChild({
      delivery: successfulDelivery,
      observed: Object.freeze({ code: 0, error: null, signal: null, timedOut: false }),
    }),
  ];
  const classify = (result, extra = {}) => classifyArmChildTerminal({
    exitCode: result.status,
    signal: result.signal,
    output: result.stdout,
    expectedCasePlanSha256,
    expectedCaseCount,
    ...extra,
  });
  const results = [
    classify(missing),
    classify(explicitFailure),
    classify(duplicate),
    classify(incomplete),
    classify(wrongDigest),
    classify(missingCase),
    classify(unexpectedCase),
    classify(duplicateCase),
    classify(zeroCase),
    classify(shortCase),
    classify(longCase),
    classify(zeroCase, { expectedCaseCount: 0 }),
    classify(immediateNonzero),
    classify(signaled),
    classifyArmChildTerminal({
      exitCode: lateWait.code,
      signal: lateWait.signal,
      output: `${lateWait.stdout}${lateWait.stderr}`,
      expectedCasePlanSha256,
      expectedCaseCount,
    }),
    classifyArmChildTerminal({
      exitCode: timedOut.code,
      signal: timedOut.signal,
      timedOut: timedOut.timedOut,
      output: `${timedOut.stdout}${timedOut.stderr}`,
      expectedCasePlanSha256,
      expectedCaseCount,
    }),
    classifyArmChildTerminal({
      exitCode: 0,
      output: `${ARM_TERMINAL_PREFIX}${canonicalJson(passSummary)}\n`,
      expectedCasePlanSha256,
      expectedCaseCount,
    }),
    classifyArmChildTerminal({
      exitCode: 0,
      output: `${ARM_TERMINAL_PREFIX}${canonicalJson(fullPassSummary)}\n`,
      expectedCasePlanSha256: ARM_REVIEWED_FULL_CASE_PLAN_SHA256,
      expectedCaseCount: ARM_DIAGNOSTIC_FULL_CASE_COUNT,
    }),
  ];
  const candidateSubject = Object.freeze({
    archiveSha256: "a".repeat(64),
    commit: "b".repeat(40),
    repository: "ExampleArmOrg/public-arm",
    tree: "c".repeat(40),
  });
  const {
    protocol: candidateProtocol,
    ...candidateStaticProvenance
  } = BOUNDARY_CANDIDATE_TIER_A_GATE_EXPECTATION;
  const candidateProvenance = Object.freeze({
    ...candidateStaticProvenance,
    controlManifestDigest: "d".repeat(64),
    subject: candidateSubject,
  });
  const gateRecord = (protocol, provenance) => `${canonicalJson({
    event: "complete",
    findings: [],
    gate: "boundary",
    protocol,
    ...(provenance === undefined ? {} : { provenance }),
  })}\n`;
  const externalRuntimeProvenance = Object.freeze({
    ...candidateProvenance,
    authorityClass: BOUNDARY_AUTHORITY_CLASS_EXTERNAL,
    authorityNonClaim: EXTERNAL_SANITIZED_AUTHORIZATION_NON_CLAIM,
    bootstrapMode: EXTERNAL_BOOTSTRAP_MODE_BY_OPERATION.RUNTIME,
    externalAuthorizationSha256: "e".repeat(64),
    tier: "ab",
    visibilitySource: "snapshot",
  });
  const externalRuntimeMeasurement = boundaryGateMeasurementExpectation([
    "--repo-visibility-source", "SNAPSHOT",
  ]);
  const externalTierALiveMeasurement = boundaryGateMeasurementExpectation([
    "--tier", "A", "--repo-visibility-source", "LIVE",
  ]);
  const externalRecoveryMeasurement = boundaryGateMeasurementExpectation([
    "--recover-exclusion-rotation",
  ]);
  const malformedExternalMeasurement = boundaryGateMeasurementExpectation([
    "--tier", "a", "--tier", "ab", "--repo-visibility-source", "snapshot",
  ]);
  const externalRuntimeExpectation = externalGateExpectation({
    authorizationSha256: externalRuntimeProvenance.externalAuthorizationSha256,
    bootstrapMode: EXTERNAL_BOOTSTRAP_MODE_BY_OPERATION.RUNTIME,
    manifest: { digest: externalRuntimeProvenance.controlManifestDigest },
    subject: candidateSubject,
    ...externalRuntimeMeasurement,
  });
  const wrongExternalModeProvenance = Object.freeze({
    ...externalRuntimeProvenance,
    bootstrapMode: EXTERNAL_BOOTSTRAP_MODE_BY_OPERATION.RECOVERY_ONLY,
  });
  const wrongExternalTierProvenance = Object.freeze({
    ...externalRuntimeProvenance,
    tier: "a",
  });
  const wrongExternalVisibilityProvenance = Object.freeze({
    ...externalRuntimeProvenance,
    visibilitySource: "live",
  });
  const invalidGateContractResults = [
    observeBoundaryGateChild({
      code: 0,
      stdout: "",
      expectation: BOUNDARY_CANDIDATE_TIER_A_GATE_EXPECTATION,
    }),
    observeBoundaryGateChild({
      code: 0,
      stdout: gateRecord(GATE_EVENT_PROTOCOL, undefined),
      expectation: BOUNDARY_CANDIDATE_TIER_A_GATE_EXPECTATION,
    }),
    observeBoundaryGateChild({
      code: 0,
      stdout: gateRecord(candidateProtocol, unverifiedGateProvenance()),
      expectation: BOUNDARY_CANDIDATE_TIER_A_GATE_EXPECTATION,
    }),
    observeBoundaryGateChild({
      code: 0,
      stdout: gateRecord(candidateProtocol, externalRuntimeProvenance),
      expectation: BOUNDARY_CANDIDATE_TIER_A_GATE_EXPECTATION,
    }),
    observeBoundaryGateChild({
      code: 0,
      stdout: gateRecord(candidateProtocol, wrongExternalModeProvenance),
      expectation: externalRuntimeExpectation,
    }),
    observeBoundaryGateChild({
      code: 0,
      stdout: gateRecord(candidateProtocol, wrongExternalTierProvenance),
      expectation: externalRuntimeExpectation,
    }),
    observeBoundaryGateChild({
      code: 0,
      stdout: gateRecord(candidateProtocol, wrongExternalVisibilityProvenance),
      expectation: externalRuntimeExpectation,
    }),
  ];
  const syntheticSpawnError = Object.assign(new Error("spawnSync synthetic ENOBUFS"), {
    code: "ENOBUFS",
  });
  const spawnErrorContractResult = observeBoundaryGateChild({
    code: null,
    error: syntheticSpawnError,
    signal: "SIGTERM",
    stdout: "",
    expectation: BOUNDARY_CANDIDATE_TIER_A_GATE_EXPECTATION,
  });
  const acceptedGateContractResults = [
    observeBoundaryGateChild({
      code: 0,
      stdout: gateRecord(candidateProtocol, candidateProvenance),
      expectation: BOUNDARY_CANDIDATE_TIER_A_GATE_EXPECTATION,
    }),
    observeBoundaryGateChild({
      code: 0,
      stdout: gateRecord(candidateProtocol, externalRuntimeProvenance),
      expectation: externalRuntimeExpectation,
    }),
  ];
  const gateContractResults = [...invalidGateContractResults, ...acceptedGateContractResults];
  const terminalContractOk = results.slice(0, -2).every((result) => result.code !== 0)
    && results.slice(-2).every((result) => result.code === 0)
    && inheritedPipe.code === 0
    && inheritedPipe.timedOut === true
    && inheritedPipe.signal === null
    && inheritedPipeClassification.code !== 0
    && outputLimited.error?.code === "ERR_CHILD_PROCESS_STDIO_MAXBUFFER"
    && outputLimited.outputLimitExceeded === true
    && outputLimited.stdoutBytes <= outputLimitBytes
    && outputLimited.stderrBytes <= outputLimitBytes
    && outputLimited.code === null
    && outputLimited.signal === "SIGKILL"
    && outputLimited.timedOut === false
    && outputLimitClassification.code !== 0
    && scannerChildContractResults.slice(0, -1).every((result) => result.code !== 0)
    && scannerChildContractResults.at(-1)?.code === 0;
  const gateContractOk = invalidGateContractResults.every((result) =>
    result.code === null && result.observedCode === 0 && !result.protocolComplete)
    && externalRuntimeMeasurement?.tier === "ab"
    && externalRuntimeMeasurement?.visibilitySource === "snapshot"
    && externalTierALiveMeasurement?.tier === "a"
    && externalTierALiveMeasurement?.visibilitySource === "live"
    && externalRecoveryMeasurement?.tier === "ab"
    && externalRecoveryMeasurement?.visibilitySource === null
    && malformedExternalMeasurement === null
    && invalidGateContractResults[0].authorityProblem?.startsWith("GATE_CHILD_PROTOCOL_INVALID:")
    && invalidGateContractResults[0].childProcess.status === 0
    && invalidGateContractResults[0].out.includes("BOUNDARY_ARM_CHILD_PROCESS")
    && invalidGateContractResults[3].protocol === candidateProtocol
    && invalidGateContractResults[3].provenance?.authorityClass
      === BOUNDARY_AUTHORITY_CLASS_EXTERNAL
    && invalidGateContractResults[4].provenance?.bootstrapMode
      === EXTERNAL_BOOTSTRAP_MODE_BY_OPERATION.RECOVERY_ONLY
    && invalidGateContractResults[5].provenance?.tier === "a"
    && invalidGateContractResults[6].provenance?.visibilitySource === "live"
    && spawnErrorContractResult.code === null
    && spawnErrorContractResult.childProcess.errorCode === "ENOBUFS"
    && spawnErrorContractResult.childProcess.errorMessage === "<withheld>"
    && spawnErrorContractResult.childProcess.status === null
    && spawnErrorContractResult.childProcess.signal === "SIGTERM"
    && spawnErrorContractResult.out.includes("BOUNDARY_ARM_CHILD_PROCESS")
    && acceptedGateContractResults.every((result) =>
      result.code === 0 && result.protocolComplete);
  return Object.freeze({
    ok: terminalContractOk && gateContractOk,
    results: Object.freeze([
      ...results,
      ...gateContractResults,
      spawnErrorContractResult,
      Object.freeze({
        code: inheritedPipe.code,
        classification: inheritedPipeClassification,
        signal: inheritedPipe.signal,
        timedOut: inheritedPipe.timedOut,
      }),
      Object.freeze({
        capturedStderrBytes: outputLimited.stderrBytes,
        capturedStdoutBytes: outputLimited.stdoutBytes,
        classification: outputLimitClassification,
        code: outputLimited.code,
        errorCode: outputLimited.error?.code ?? null,
        outputLimitExceeded: outputLimited.outputLimitExceeded,
        signal: outputLimited.signal,
        timedOut: outputLimited.timedOut,
      }),
      ...scannerChildContractResults,
    ]),
  });
}

function reviewedControlGateFiles() {
  return REVIEWED_CONTROL_PATHS
    // The synthetic repository owns a deliberately minimal package manifest. Every other reviewed
    // control is copied byte-for-byte; no second allowlist is permitted to drift from the manifest.
    .filter((controlPath) => controlPath !== "package.json")
    .map((controlPath) => controlPath.startsWith("scripts/")
      ? controlPath.slice("scripts/".length)
      : `../${controlPath}`);
}

const GATE_FILES = Object.freeze(reviewedControlGateFiles());

// boundary-scan deliberately uses TypeScript's real parser instead of a hand-written JavaScript
// lexer. The arm executes a byte-for-byte copy of that scanner in a synthetic repository, so the
// parser runtime is part of the executable closure even though node_modules is never part of the
// repository surface under test. Keep this list minimal and verify every copied byte below.
const TYPESCRIPT_RUNTIME_FILES = Object.freeze([
  "package.json",
  "lib/typescript.js",
]);

// The copied scanner selftest deliberately contains synthetic coordinates that its own private
// fixture snapshot classifies as non-public. The outer arm scans that selftest as ordinary source,
// so its separate synthetic provider snapshot must classify every reviewed fixture coordinate as
// public. This does not weaken the selftest: its direct calls still receive their own intentionally
// narrower snapshot. A newly added coordinate fails the untouched-repository arm until this explicit
// list is reviewed, preventing automatic whitelisting of an accidentally copied real identity.
const SYNTHETIC_SCANNER_FIXTURE_PUBLIC_REPOS = Object.freeze({
  examplearmorg: Object.freeze([
    "bootstrap-fixture",
    "public-arm",
    "synthetic-confidential-repo",
    "synthetic-confidential-repo-renamed",
    "synthetic-public-repo",
  ]),
  examplecorp: Object.freeze([
    "-public-dash",
    "-unlisted-sibling",
    ".public-dot",
    ".unlisted-sibling",
    "_public-underscore",
    "_unlisted-sibling",
    "another-public",
    "public-thing",
    "unlisted-sibling",
  ]),
  samplearmorg: Object.freeze([
    "synthetic-confidential-repo",
    "synthetic-public-library",
  ]),
});

const SYNTHETIC_KEY = Buffer.alloc(32, 0x5a);
const SYNTHETIC_CANARY = `noaboundarycanary${"a".repeat(24)}`;
const SYNTHETIC_REVIEW_SESSION = ["00000000", "0000", "4000", "8000", "000000000010"].join("-");
const EXPECTED_SYNTHETIC_REVIEW_SESSION = Buffer.from(
  "30303030303030302d303030302d343030302d383030302d303030303030303030303130",
  "hex",
).toString("utf8");
const KEY_MODE = 0o600;
const KEY_DIR_MODE = 0o700;
const EXCLUSION_POLICY_SCHEMA_VERSION = 3;

const keyedRecord = (key, domain, value) => createHmac("sha256", key)
  .update(`noa-boundary/${domain}\0`, "utf8")
  .update(JSON.stringify(value), "utf8")
  .digest("hex");

const keyedCanonicalRecord = (key, domain, value) => createHmac("sha256", key)
  .update(`noa-boundary/${domain}\0`, "utf8")
  .update(canonicalJson(value), "utf8")
  .digest("hex");

const commitmentPayload = (doc) => ({
  schemaVersion: doc.schemaVersion,
  note: doc.note,
  alg: doc.alg,
  keyId: doc.keyId,
  refreshedAt: doc.refreshedAt,
  governanceStatus: doc.governanceStatus,
  count: doc.count,
  excludedCount: doc.excludedCount,
  ngramSizes: doc.ngramSizes,
  canaryDigest: doc.canaryDigest,
  extraInputsCommitment: doc.extraInputsCommitment,
  exclusionPolicyCommitment: doc.exclusionPolicyCommitment,
  digests: doc.digests,
  privateInputCount: doc.privateInputCount,
  privateInputsCommitment: doc.privateInputsCommitment,
});

const emptyExclusionPolicyBody = (keyId) => ({
  schemaVersion: EXCLUSION_POLICY_SCHEMA_VERSION,
  keyId,
  entries: [],
});

function syntheticCommitments(key, canary, overrides = {}) {
  const keyId = createHash("sha256").update(key).digest("hex");
  const canaryForm = tokenForms(canary)[0];
  // Hex-decoded so the arm's own source does not contain the committed token it uses to prove that
  // a commitment-set shrink is authenticated. The copied gate scans this file like every other file.
  const secondaryForm = tokenForms(Buffer.from("61726d7365636f6e64617279", "hex").toString("utf8"))[0];
  const forms = [canaryForm, secondaryForm];
  const exclusionBody = emptyExclusionPolicyBody(keyId);
  const doc = {
    schemaVersion: 3,
    note: "Synthetic authenticated commitments used only by the boundary arm scratch repository.",
    alg: "HMAC-SHA256",
    keyId,
    refreshedAt: new Date().toISOString(),
    governanceStatus: "AUTHENTICATED",
    count: forms.length,
    excludedCount: 0,
    ngramSizes: [...new Set(forms.map(tokenNgramSize))].sort((a, b) => a - b),
    canaryDigest: commitToken(key, canaryForm),
    extraInputsCommitment: keyedRecord(key, "extra-inputs/v1", []),
    exclusionPolicyCommitment: keyedCanonicalRecord(key, "exclusion-policy/v3-empty", exclusionBody),
    privateInputCount: 1,
    privateInputsCommitment: keyedRecord(key, "private-inputs/v1", ["arm-private"]),
    digests: forms.map((form) => commitToken(key, form)).sort(),
    ...overrides,
  };
  doc.count = doc.digests.length;
  doc.commitmentMac = keyedRecord(key, "commitments/v3", commitmentPayload(doc));
  return doc;
}

function writeSyntheticCustody(directory, key = SYNTHETIC_KEY, canary = SYNTHETIC_CANARY) {
  mkdirSync(directory, { recursive: true, mode: KEY_DIR_MODE });
  chmodSync(directory, KEY_DIR_MODE);
  writeFileSync(join(directory, "key"), key, { mode: KEY_MODE });
  chmodSync(join(directory, "key"), KEY_MODE);
  writeFileSync(join(directory, "canary.txt"), `${canary}\n`, { mode: KEY_MODE });
  chmodSync(join(directory, "canary.txt"), KEY_MODE);
}

function materializeScannerRuntime(sourceRoot, destinationRoot) {
  let lock;
  let manifest;
  try {
    lock = JSON.parse(readFileSync(join(sourceRoot, "package-lock.json"), "utf8"));
    manifest = JSON.parse(readFileSync(
      join(sourceRoot, "node_modules", "typescript", "package.json"),
      "utf8",
    ));
  } catch {
    throw new Error("SCANNER_RUNTIME_MANIFEST_INVALID");
  }
  const locked = lock?.packages?.["node_modules/typescript"];
  if (typeof locked?.version !== "string"
      || manifest?.version !== locked.version
      || manifest?.main !== "./lib/typescript.js") {
    throw new Error("SCANNER_RUNTIME_LOCK_MISMATCH");
  }
  const packageRoot = join(sourceRoot, "node_modules", "typescript");
  const packageStat = lstatSync(packageRoot);
  if (!packageStat.isDirectory() || packageStat.isSymbolicLink()) {
    throw new Error("SCANNER_RUNTIME_PACKAGE_REJECTED");
  }
  const copied = [];
  for (const relativePath of TYPESCRIPT_RUNTIME_FILES) {
    const sourcePath = join(packageRoot, relativePath);
    const sourceStat = lstatSync(sourcePath);
    if (!sourceStat.isFile() || sourceStat.isSymbolicLink()) {
      throw new Error("SCANNER_RUNTIME_FILE_REJECTED");
    }
    const sourceBytes = readFileSync(sourcePath);
    const destinationPath = join(destinationRoot, "node_modules", "typescript", relativePath);
    mkdirSync(dirname(destinationPath), { recursive: true, mode: KEY_DIR_MODE });
    writeFileSync(destinationPath, sourceBytes, { flag: "wx", mode: KEY_MODE });
    const destinationBytes = readFileSync(destinationPath);
    if (destinationBytes.length !== sourceBytes.length
        || createHash("sha256").update(destinationBytes).digest("hex")
          !== createHash("sha256").update(sourceBytes).digest("hex")) {
      throw new Error("SCANNER_RUNTIME_COPY_MISMATCH");
    }
    copied.push(relativePath);
  }
  return Object.freeze({ files: Object.freeze(copied), version: locked.version });
}

export async function runArm({ root, knockoutJson, spoolOnly = false }) {
  // Captured FIRST. The arm never touches the real tree, and the closing check compares against this
  // snapshot rather than against "clean" — so a tree that was already dirty when the arm started is
  // not blamed on the arm, and a tree the arm DID change cannot hide behind that.
  const treeAtStart = String(spawnSync("git", ["status", "--porcelain"], { cwd: root, encoding: "utf8", shell: false }).stdout).trim();
  const failures = [];
  const notes = [];
  const caseMode = spoolOnly ? ARM_CASE_MODE_SPOOL_ONLY : ARM_CASE_MODE_FULL;
  const casePlan = ARM_CASE_PLANS[caseMode];
  const reviewedCasePlanSha256 = spoolOnly
    ? ARM_REVIEWED_SPOOL_ONLY_CASE_PLAN_SHA256 : ARM_REVIEWED_FULL_CASE_PLAN_SHA256;
  const diagnosticExpectedCaseCount = spoolOnly
    ? ARM_DIAGNOSTIC_SPOOL_ONLY_CASE_COUNT : ARM_DIAGNOSTIC_FULL_CASE_COUNT;
  const executedCaseIds = new Set();
  let duplicateCaseCount = 0;
  let unexpectedCaseCount = 0;
  let terminalEmitted = false;
  const terminalWatchdog = setTimeout(() => {
    if (terminalEmitted) return;
    const missingCaseCount = casePlan.ids.filter((id) => !executedCaseIds.has(id)).length;
    const summary = {
      casePlanSha256: casePlan.sha256,
      duplicateCaseCount,
      event: "complete",
      failureCount: failures.length + 1,
      missingCaseCount,
      observedCaseCount: executedCaseIds.size,
      plannedCaseCount: casePlan.ids.length,
      protocol: ARM_TERMINAL_PROTOCOL,
      status: "SETUP_FAILED",
      unexpectedCaseCount,
    };
    process.stderr.write(`${ARM_TERMINAL_PREFIX}${canonicalJson(summary)}\n`);
    process.exit(2);
  }, ARM_TERMINAL_WATCHDOG_MS);
  const custodyBarriersAtStart = custodyBarrierCountsForSelftest();
  const log = (line) => { if (!knockoutJson) process.stderr.write(`${line}\n`); };
  const check = (descriptor, ok, detail) => {
    const suppliedId = descriptor !== null && typeof descriptor === "object"
      && typeof descriptor.id === "string" ? descriptor.id : "<invalid>";
    const registered = suppliedId === "<invalid>" ? undefined : armCaseRegistry.get(suppliedId);
    const exactExpectedDescriptor = registered === descriptor && casePlan.idSet.has(suppliedId);
    const name = registered === descriptor ? descriptor.label : "unregistered boundary-arm case";
    if (!exactExpectedDescriptor) {
      unexpectedCaseCount++;
      ok = false;
      detail = `${detail ? `${detail}; ` : ""}unexpected case descriptor ${JSON.stringify(suppliedId)} for ${caseMode}`;
    } else if (executedCaseIds.has(suppliedId)) {
      duplicateCaseCount++;
      ok = false;
      detail = `${detail ? `${detail}; ` : ""}duplicate arm case ID ${JSON.stringify(suppliedId)}`;
    } else executedCaseIds.add(suppliedId);
    if (ok) log(`  ${green("ok")}     ${name}`);
    else {
      failures.push({ caseId: suppliedId, name, detail: detail ?? "" });
      log(`  ${red("FAIL")}   ${name}${detail ? `\n         ${detail}` : ""}`);
    }
    return ok;
  };
  const finishArm = (finalNotes = []) => {
    return finish(failures, knockoutJson, log, finalNotes, {
      casePlan,
      diagnosticExpectedCaseCount,
      duplicateCaseCount,
      executedCaseIds,
      markTerminalEmitted: () => {
        terminalEmitted = true;
        clearTimeout(terminalWatchdog);
      },
      reviewedCasePlanSha256,
      unexpectedCaseCount,
    });
  };

  log(bold("\n  L12 arm\n"));

  const supervisorMeta = await runArmTerminalSupervisorMetaSelftest();
  check(
    ARM_STATIC_CASES.case_the_arm_terminal_supervisor_refuses_missing_duplicate_incomplet_0d29a4a2,
    supervisorMeta.ok,
    canonicalJson(supervisorMeta.results),
  );

  // ── 0. the registry ratchet, in process ────────────────────────────────────────────────────────
  try {
    assertLaneRegistry();
    check(ARM_STATIC_CASES.case_the_lane_registry_matches_its_owner_visible_ratchet, true);
  } catch {
    check(ARM_STATIC_CASES.case_the_lane_registry_matches_its_owner_visible_ratchet, false, "lane registry refused");
  }
  check(
    ARM_STATIC_CASES.case_the_scanner_safe_synthetic_review_session_construction_preserve_7a464f86,
    SYNTHETIC_REVIEW_SESSION === EXPECTED_SYNTHETIC_REVIEW_SESSION,
  );
  let drifted = false;
  try { assertLaneRegistry([...BOUNDARY_LANES, { id: "L-SNEAK", title: "t", enumerator: "e", covers: "c", mustNotBeEmpty: false, needsInput: false }]); }
  catch { drifted = true; }
  check(ARM_STATIC_CASES.case_a_lane_added_without_updating_the_ratchet_is_refused, drifted);

  // ── 1. the pure scanners ───────────────────────────────────────────────────────────────────────
  {
    const nestedBootstrapIssuer = prepareNestedBoundaryScannerSelftestBootstrap(
      boundaryScannerAuthority,
    );
    const scannerSelftestEnvironment = { ...process.env };
    for (const name of [
      "NOA_BOUNDARY_AUTHORIZATION_FD",
      "NOA_BOUNDARY_AUTHORIZATION_FILE",
      "NOA_BOUNDARY_INTERNAL_BOOTSTRAP_MODE",
      "NOA_BOUNDARY_SCANNER_SELFTEST_CHILD",
      BOUNDARY_KNOCKOUT_BOOTSTRAP_ENV,
    ]) delete scannerSelftestEnvironment[name];
    if (nestedBootstrapIssuer !== null) {
      scannerSelftestEnvironment[BOUNDARY_KNOCKOUT_BOOTSTRAP_ENV] = "0";
      scannerSelftestEnvironment.NOA_BOUNDARY_SCANNER_SELFTEST_CHILD = "1";
    }
    let r;
    if (nestedBootstrapIssuer === null) {
      r = spawnSync(
        process.execPath,
        [join(root, "scripts", "lib", "boundary-scan.selftest.mjs")],
        {
          cwd: root,
          encoding: "utf8",
          env: scannerSelftestEnvironment,
          shell: false,
        },
      );
    } else {
      const child = spawn(
        process.execPath,
        [join(root, "scripts", "lib", "boundary-scan.selftest.mjs")],
        {
          cwd: root,
          env: scannerSelftestEnvironment,
          shell: false,
          stdio: ["pipe", "pipe", "pipe"],
        },
      );
      const waiting = waitForArmChildClose(child, { timeoutMs: 30_000 });
      let delivery;
      try {
        const bootstrapBytes = nestedBootstrapIssuer.issueForChild(child.pid);
        delivery = writeArmChildInput(child, bootstrapBytes);
      } catch (error) {
        delivery = Promise.resolve(Object.freeze({
          completed: false,
          error,
          timedOut: false,
        }));
        child.stdin.destroy();
        if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
      }
      const [observed, delivered] = await Promise.all([waiting, delivery]);
      const classification = classifyScannerSelftestChild({
        delivery: delivered,
        observed,
      });
      r = {
        accepted: classification.code === 0,
        cwd: root,
        error: delivered.error ?? observed.error,
        signal: observed.signal,
        status: observed.code,
        stderr: observed.stderr,
        stdout: observed.stdout,
      };
    }
    const accepted = nestedBootstrapIssuer === null
      ? r.status === 0 && r.error === undefined && r.signal === null
      : r.accepted;
    check(ARM_STATIC_CASES.case_the_pure_scanner_fixtures_pass_in_both_directions, accepted, String(r.stdout ?? "").split("\n").slice(-3).join("\n"));
  }

  // The public-artifact executor is an actual authority: the immutable bootstrap executes it and it
  // imports the staging controller. Every reviewed control except the deliberately synthetic package
  // manifest must be copied exactly once. The copy list is constructed from the canonical registry;
  // this independent equality check makes a later filter or appended extra path fail closed.
  {
    const executorGatePath = "lib/publish-artifact-executor.mjs";
    const expectedGateFiles = reviewedControlGateFiles();
    const missingReviewedCopies = expectedGateFiles.filter((entry) => !GATE_FILES.includes(entry));
    const extraGateCopies = GATE_FILES.filter((entry) => !expectedGateFiles.includes(entry));
    const carried = GATE_FILES.includes(executorGatePath)
      && GATE_FILES.length === expectedGateFiles.length
      && missingReviewedCopies.length === 0
      && extraGateCopies.length === 0;
    check(
      ARM_STATIC_CASES.case_authenticated_carrier_closures_include_the_immutable_publish_ar_322e8d21,
      carried,
      `executor ${GATE_FILES.includes(executorGatePath)}; missing reviewed copies ` +
        `${canonicalJson(missingReviewedCopies)}; extra copies ${canonicalJson(extraGateCopies)}`,
    );
  }

  // macOS exposes its temporary directory through a logical /var alias whose physical path is
  // /private/var. The candidate bootstrap intentionally refuses such aliases, so canonicalize the
  // freshly created harness root before deriving any synthetic repository subject from it.
  const work = realpathSync(mkdtempSync(join(tmpdir(), "noa-boundary-arm-")));
  try {
    const repo = join(work, "repo");
    buildSyntheticRepo(repo, root);
    let scannerRuntime;
    try {
      scannerRuntime = materializeScannerRuntime(root, repo);
    } catch {
      check(
        ARM_STATIC_CASES.case_the_synthetic_gate_carries_its_exact_locked_scanner_runtime,
        false,
        "SCANNER_RUNTIME_SETUP_FAILED",
      );
      return finishArm();
    }
    check(
      ARM_STATIC_CASES.case_the_synthetic_gate_carries_its_exact_locked_scanner_runtime,
      scannerRuntime.files.length === TYPESCRIPT_RUNTIME_FILES.length,
      `TypeScript ${scannerRuntime.version}; ${scannerRuntime.files.length} runtime files`,
    );
    const gate = join(repo, "scripts", "lint-boundary.mjs");
    const armHome = join(work, "arm-home");
    const armBoundaryDir = join(armHome, ".noa-boundary");
    mkdirSync(armHome, { mode: KEY_DIR_MODE });
    const hookEnvironment = isolatedArmHookEnvironment(armHome);
    const hostBoundaryDirectory = join(homedir(), ".noa-boundary");
    const isolatedPrepushSpool = boundaryEvidenceSpoolDirectory(armBoundaryDir, "PREPUSH_GATE_VERDICT");
    const hostPrepushSpool = boundaryEvidenceSpoolDirectory(hostBoundaryDirectory, "PREPUSH_GATE_VERDICT");
    const hostPrepushBefore = snapshotSpoolForIsolation(hostPrepushSpool);
    if (!check(
      ARM_STATIC_CASES.case_the_real_push_hook_environment_selects_only_the_isolated_arm_ho_f3fb7966,
      hookEnvironmentTargetsArmHome(hookEnvironment, armHome)
        && resolve(armBoundaryDir) !== resolve(hostBoundaryDirectory)
        && resolve(isolatedPrepushSpool).startsWith(`${resolve(armHome)}${sep}`)
        && !Object.values(hookEnvironment).some((value) => typeof value === "string"
          && (value === hostBoundaryDirectory || value.startsWith(`${hostBoundaryDirectory}${sep}`)))
        && hostPrepushBefore.safe,
      "the real-push harness refused to start because its state-root isolation is incomplete",
    )) return finishArm();
    writeSyntheticCustody(armBoundaryDir);
    const canary = SYNTHETIC_CANARY;
    check(ARM_STATIC_CASES.case_the_arm_uses_isolated_synthetic_tier_b_custody, !existsSync(join(armBoundaryDir, "tokens.txt")));

    const normalizeArmArgs = (args) => {
      const actualArgs = [...args];
      if (!actualArgs.includes("--repo-visibility-source")
          && !actualArgs.includes("--migrate-exclusions")
          && !actualArgs.includes("--recover-exclusion-rotation")
          && !actualArgs.includes("--rotate-exclusions")) {
        actualArgs.push("--repo-visibility-source", "snapshot");
      }
      return actualArgs;
    };
    const prepareAuthorizedArmInvocation = (args, opts = {}) => {
      const actualArgs = normalizeArmArgs(args);
      const measurementExpectation = boundaryGateMeasurementExpectation(actualArgs);
      const targetRoot = opts.cwd ?? repo;
      const targetGate = opts.gate ?? gate;
      const manifest = deriveBoundaryControlManifest(targetRoot);
      const subject = deriveBoundaryCandidateSubject(targetRoot);
      const authorizationLegacy = Buffer.from("synthetic-token # arm authorization fixture\n", "utf8");
      const authorizationKeyId = createHash("sha256").update(SYNTHETIC_KEY).digest("hex");
      const now = Date.now();
      const recoveryOnly = actualArgs.includes("--recover-exclusion-rotation");
      const operation = recoveryOnly ? "RECOVERY_ONLY" : "RUNTIME";
      const bootstrapMode = EXTERNAL_BOOTSTRAP_MODE_BY_OPERATION[operation];
      const policyManifest = recoveryOnly
        ? { digest: createHash("sha256").update("synthetic historical seven-path manifest").digest("hex"), files: PREVIOUS_REVIEWED_CONTROL_PATHS, version: 1 }
        : { digest: manifest.digest, files: manifest.paths, version: manifest.version };
      const policyBody = {
        schemaVersion: 3,
        keyId: authorizationKeyId,
        reviewer: "synthetic boundary arm supervisor",
        reviewedAt: new Date(now - 1_000).toISOString(),
        expiresAt: new Date(now + 120_000).toISOString(),
        reviewSession: SYNTHETIC_REVIEW_SESSION,
        classification: "PUBLIC_DERIVED_COLLISION",
        publicArtifact: "synthetic-arm-package@0.0.0",
        publicArtifactSRI: `sha512-${Buffer.alloc(64, 0x31).toString("base64")}`,
        controlManifestVersion: policyManifest.version,
        controlManifestFiles: [...policyManifest.files],
        controlManifestDigest: policyManifest.digest,
        legacyByteLength: authorizationLegacy.length,
        legacySha256: createHash("sha256").update(authorizationLegacy).digest("hex"),
        entries: [{ token: "synthetic-token", reason: "arm authorization fixture" }],
      };
      const policy = {
        ...policyBody,
        mac: createHmac("sha256", SYNTHETIC_KEY)
          .update("noa-boundary/exclusion-policy/v3\0", "utf8")
          .update(canonicalBoundaryJson(policyBody), "utf8")
          .digest("hex"),
      };
      const policyBytes = Buffer.from(`${canonicalBoundaryJson(policy)}\n`, "utf8");
      const bundleIdentity = deriveBoundaryAuthorityBundleIdentity({
        version: "boundary-arm-pinned-fixture-v1",
        files: manifest.files.filter((file) => [
          "scripts/lib/boundary-bootstrap.mjs",
          "scripts/lib/boundary-external-authority.mjs",
          "scripts/lib/boundary-token.mjs",
        ].includes(file.path)),
      });
      const authorization = createBoundaryRuntimeAuthorization({
        bundleIdentity,
        candidateManifest: manifest,
        expiresAt: new Date(now + 120_000).toISOString(),
        issuedAt: new Date(now).toISOString(),
        nonce: randomBytes(32).toString("hex"),
        operation,
        policyBytes,
        subject,
        keyBytes: SYNTHETIC_KEY,
        legacyBytes: authorizationLegacy,
        tierBResult: {
          archiveSha256: subject.archiveSha256,
          candidateFormCount: 0,
          controlManifestDigest: manifest.digest,
          findingCount: 0,
          inputDigest: createHash("sha256").update("boundary-arm-tier-b-input").digest("hex"),
          policySha256: createHash("sha256").update(policyBytes).digest("hex"),
          resultDigest: createHash("sha256").update("boundary-arm-tier-b-pass").digest("hex"),
          scannedUnitCount: 1,
          scannerId: "noa-boundary-tier-b/v1",
          schemaVersion: 1,
          verdict: "PASS",
        },
      });
      const authorizationPath = join(work, `authorization-${randomBytes(8).toString("hex")}.json`);
      writeFileSync(authorizationPath, authorization.authorizationBytes, { flag: "wx", mode: KEY_MODE });
      const authorizationFd = openSync(authorizationPath, "r");
      unlinkSync(authorizationPath);
      return {
        actualArgs,
        authorizationFd,
        gateExpectation: measurementExpectation === null
          ? null
          : externalGateExpectation({
            authorizationSha256: authorization.observation.authorizationSha256,
            bootstrapMode,
            manifest,
            subject,
            ...measurementExpectation,
          }),
        cwd: opts.cwd ?? repo,
        gate: targetGate,
        env: {
          ...(opts.env ?? { ...process.env, HOME: armHome }),
          NOA_BOUNDARY_AUTHORIZATION_FD: "3",
          NOA_BOUNDARY_SYNTHETIC_SUPERVISOR_FIXTURE: "1",
        },
      };
    };
    const spawnAuthorizedArm = (args, opts = {}) => {
      const prepared = prepareAuthorizedArmInvocation(args, opts);
      try {
        const child = spawn(process.execPath, [prepared.gate, ...prepared.actualArgs, "--knockout-json"], {
          cwd: prepared.cwd,
          env: prepared.env,
          shell: false,
          stdio: [opts.stdin ?? "ignore", "pipe", "pipe", prepared.authorizationFd],
        });
        return Object.freeze({ child, gateExpectation: prepared.gateExpectation });
      } finally {
        closeSync(prepared.authorizationFd);
      }
    };
    const run = (args, opts = {}) => {
      const actualArgs = normalizeArmArgs(args);
      if (opts.candidateTierABootstrap === true) {
        if (!actualArgs.includes("--tier")) actualArgs.push("--tier", "a");
        const candidateEnvironment = { ...(opts.env ?? { ...process.env, HOME: armHome }) };
        for (const name of [
          "NOA_BOUNDARY_AUTHORIZATION_FD",
          "NOA_BOUNDARY_AUTHORIZATION_FILE",
          "NOA_BOUNDARY_INTERNAL_BOOTSTRAP_MODE",
          "NOA_BOUNDARY_SYNTHETIC_SUPERVISOR_FIXTURE",
        ]) delete candidateEnvironment[name];
        const candidate = spawnSync(process.execPath, [opts.gate ?? gate, ...actualArgs, "--knockout-json"], {
          cwd: opts.cwd ?? repo,
          encoding: "utf8",
          shell: false,
          env: candidateEnvironment,
          input: opts.input ?? "",
        });
        return observeBoundaryGateChild({
          code: candidate.status,
          error: candidate.error,
          signal: candidate.signal,
          stdout: candidate.stdout ?? "",
          stderr: candidate.stderr ?? "",
          expectation: BOUNDARY_CANDIDATE_TIER_A_GATE_EXPECTATION,
        });
      }
      const prepared = prepareAuthorizedArmInvocation(actualArgs, opts);
      let r;
      try {
        r = spawnSync(process.execPath, [prepared.gate, ...prepared.actualArgs, "--knockout-json"], {
          cwd: prepared.cwd, encoding: "utf8", shell: false,
          env: prepared.env,
          input: opts.input ?? "",
          stdio: ["pipe", "pipe", "pipe", prepared.authorizationFd],
        });
      } finally {
        closeSync(prepared.authorizationFd);
      }
      return observeBoundaryGateChild({
        code: r.status,
        error: r.error,
        signal: r.signal,
        stdout: r.stdout ?? "",
        stderr: r.stderr ?? "",
        expectation: prepared.gateExpectation,
      });
    };

    // ── 2. disjoint immutable schema-v2 evidence spools ───────────────────────────────────────
    await runEvidenceSpoolHarness({ canary, check, repo, root, run, work });

    if (spoolOnly) {
      notes.push("focused schema-v2 evidence-spool arm; no unrelated lane or rotation repetition");
      const dirty = spawnSync("git", ["status", "--porcelain"], { cwd: root, encoding: "utf8", shell: false });
      check(
        ARM_STATIC_CASES.case_the_real_working_tree_is_exactly_as_the_focused_spool_arm_found_it,
        dirty.status === 0 && String(dirty.stdout).trim() === treeAtStart,
        "a focused arm that cannot return the tree it borrowed is a failing verdict",
      );
      return finishArm(notes);
    }

    // A run over the untouched synthetic repository must be GREEN in every lane. If it is not, every
    // "the lane fired" result below would be unattributable.
    const baseSha = readFileSync(join(repo, ".arm-base"), "utf8").trim();
    const base = run(["--lane", APPROVED_BOUNDARY_LANES.join(","), "--range", `${baseSha}..HEAD`]);
    if (!check(ARM_STATIC_CASES.case_the_untouched_synthetic_repository_is_green_in_all_eight_lanes, base.code === 0, `exit ${base.code}\n${base.out.slice(0, 2000)}`)) {
      return finishArm();
    }

    // ── 3. one canary per lane, in the surface only that lane can reach ─────────────────────────
    const armed = new Set();
    // Check NAMES are stable identifiers: the knockout registry binds to them as expected gate
    // findings, so they are never padded, numbered or reworded casually.
    const laneCase = (id, plant, unplant, extraArgs = [], expectRules = ["token-commitment"]) => {
      const laneCases = ARM_LANE_CASES[id];
      if (laneCases === undefined) throw new Error(`unregistered boundary-arm lane case: ${id}`);
      plant();
      const hot = run(["--lane", id, ...extraArgs]);
      const named = expectRules.every((rule) => hot.findings.some((f) => f.rule === rule));
      const leaked = hot.out.includes(canary);
      const fired = check(laneCases.found,
        hot.code === 1 && named && !leaked,
        `exit ${hot.code}; rules seen: ${JSON.stringify(hot.findings.map((f) => f.rule))}; `
          + `raw canary disclosed: ${leaked}\n${leaked ? "output withheld" : hot.out.slice(0, 900)}`);
      unplant();
      const cold = run(["--lane", id, ...extraArgs]);
      const clean = check(laneCases.clean,
        cold.code === 0, `exit ${cold.code} — a lane stuck red measures nothing\n${cold.out.slice(0, 900)}`);
      if (fired && clean) armed.add(id);
    };

    const wtFile = join(repo, "notes.md");
    laneCase("L-WT",
      () => writeFileSync(wtFile, `# notes\n\nowner ${canary}\n`),
      () => writeFileSync(wtFile, "# notes\n\nnothing here\n"));

    const idxFile = join(repo, "staged.md");
    laneCase("L-IDX",
      () => {
        writeFileSync(idxFile, `# staged\n\n${canary}\n`);
        git(repo, ["add", "staged.md"]);
        // THE POINT OF THIS LANE: the disk copy is scrubbed AFTER staging. Only a lane that reads
        // `git show :<path>` still sees it. A lane that read the worktree would report clean here.
        writeFileSync(idxFile, "# staged\n\nnothing here\n");
      },
      // The clean half must leave something STAGED. Unstaging everything makes the lane report
      // SKIPPED, and the gate then exits 2 because every selected lane skipped — which is the right
      // behaviour for the gate and a worthless discrimination test for the arm. So the canary is
      // replaced by benign staged content: the lane still runs, still reads the index, and must
      // find nothing.
      () => { writeFileSync(idxFile, "# staged\n\nnothing here\n"); git(repo, ["add", "staged.md"]); });

    // The canary goes into a NON-TIP commit message, and a second commit is stacked on top. A lane
    // that read only the tip would pass this by — which is the registered knockout
    // `l12-msg-range-is-full`, and the shape of the branch that published 99 labelled messages.
    laneCase("L-MSG",
      () => {
        writeFileSync(join(repo, "msg.md"), "# msg\n");
        git(repo, ["add", "msg.md"]);
        git(repo, ["commit", "-q", "-m", `chore: touch ${canary}`]);
        git(repo, ["commit", "-q", "--allow-empty", "-m", "chore: a later commit, so the canary is not the tip"]);
      },
      () => { git(repo, ["reset", "-q", "--hard", "HEAD~2"]); rmSync(join(repo, "msg.md"), { force: true }); },
      ["--range", `${baseSha}..HEAD`]);

    laneCase("L-TAG",
      () => { git(repo, ["tag", "-a", `v9.9.9-${canary}`, "-m", `release ${canary}`, "HEAD"]); },
      () => { git(repo, ["tag", "-d", `v9.9.9-${canary}`]); },
      ["--range", `${baseSha}..HEAD`]);

    laneCase("L-PUSH",
      () => { writeFileSync(join(repo, "blob.md"), `# blob\n\n${canary}\n`); git(repo, ["add", "blob.md"]); git(repo, ["commit", "-q", "-m", "chore: add a blob"]); },
      () => { git(repo, ["reset", "-q", "--hard", "HEAD~1"]); rmSync(join(repo, "blob.md"), { force: true }); },
      ["--range", `${baseSha}..HEAD`]);

    // THE PACKED-SET TRAP. The lane itself must prove that README.md reached the exact tarball; asking
    // a package-manager preview first can execute `prepare` and would make the arm the hazard.
    laneCase("L-PACK",
      () => writeFileSync(join(repo, "README.md"), `# synthetic\n\nowner ${canary}\n`),
      () => writeFileSync(join(repo, "README.md"), "# synthetic\n\nnothing here\n"));

    // Package-manager preview paths can execute prepare despite script-suppression flags. This path must
    // neither execute nor merely attempt lifecycle code: the snapshot is read-only, so an attempted
    // write would turn this run into exit 2 instead of the required clean verdict.
    {
      const manifestPath = join(repo, "package.json");
      const original = readFileSync(manifestPath);
      const manifest = JSON.parse(original.toString("utf8"));
      manifest.scripts = {
        prepare: "node -e \"require('node:fs').writeFileSync('LIFECYCLE_EXECUTED','yes')\"",
      };
      writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
      const lifecycle = run(["--lane", "L-PACK"]);
      check(
        ARM_STATIC_CASES.case_l_pack_never_executes_or_attempts_a_package_lifecycle_script,
        lifecycle.code === 0 && !existsSync(join(repo, "LIFECYCLE_EXECUTED")),
        `exit ${lifecycle.code}; sentinel ${existsSync(join(repo, "LIFECYCLE_EXECUTED"))}; ${lifecycle.out.slice(0, 900)}`,
      );
      writeFileSync(manifestPath, original);
      rmSync(join(repo, "LIFECYCLE_EXECUTED"), { force: true });
    }

    // ── THE L-MAP PLANT, REWRITTEN AFTER ITS KNOCKOUT CAME BACK GREEN ─────────────────────────────
    //
    // The first version put the canary into `sourcesContent` as plain text. The lane found it — and
    // the knockout that DELETES the sourcesContent scan still came back green, because the raw `.map`
    // file is scanned as text too, and plain text inside JSON is still plain text. Two controls
    // closing one shape means neither is individually observable: this repository's own definition
    // of a control that is not one.
    //
    // So the canary is written JSON-\u-escaped. The bytes on disk do not contain it; only a reader
    // that PARSES the map and decodes the string can see it. That is also a real evasion rather than
    // a contrivance — a packed sourcemap can carry any source, escaped any way the emitter likes.
    const mapPath = join(repo, "dist", "index.js.map");
    const cleanMap = { version: 3, file: "index.js", sources: ["../src/index.ts"], sourcesContent: ["export const a = 1;\n"], mappings: "" };
    const uEscape = (s) => [...s].map((c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`).join("");
    laneCase("L-MAP",
      () => {
        const text = JSON.stringify({
          ...cleanMap,
          // Absolute AND escaping the package: a structural finding on its own, independent of content.
          sources: [`${"/synth" + "etic"}/build/root/src/index.ts`],
          sourcesContent: [`export const owner = ${JSON.stringify(canary)};\n`],
        }).split(canary).join(uEscape(canary));
        if (text.includes(canary)) throw new Error("the L-MAP plant must not leave the canary readable in the raw file");
        if (JSON.parse(text).sourcesContent[0].indexOf(canary) < 0) throw new Error("the L-MAP plant must still decode to the canary");
        writeFileSync(mapPath, text);
      },
      () => writeFileSync(mapPath, JSON.stringify(cleanMap)),
      [], ["token-commitment", "sourcemap-escapes-package"]);

    // Escaped JSON can hide path-bearing source-map fields from a raw-byte scan. Exercise every
    // decoded metadata field as an independent scanner unit and require redacted evidence.
    for (const [descriptorHot, descriptorCold, field, doc] of [
      [ARM_TASK3_CASES.mapFileFound, ARM_TASK3_CASES.mapFileClean,
        "file", { ...cleanMap, file: `bundle-${canary}.js` }],
      [ARM_TASK3_CASES.mapSourceRootFound, ARM_TASK3_CASES.mapSourceRootClean,
        "sourceRoot", { ...cleanMap, sourceRoot: `../src/${canary}/` }],
      [ARM_TASK3_CASES.mapSourcesFound, ARM_TASK3_CASES.mapSourcesClean,
        "sources", { ...cleanMap, sources: [`../src/unit-${canary}.ts`] }],
    ]) {
      const encoded = JSON.stringify(doc).split(canary).join(uEscape(canary));
      if (encoded.includes(canary)) throw new Error("a decoded source-map path plant remained in raw JSON");
      writeFileSync(mapPath, encoded);
      const hot = run(["--lane", "L-MAP"]);
      const leaked = hot.out.includes(canary);
      check(
        descriptorHot,
        hot.code === 1 && hot.findings.some((finding) => finding.rule === "token-commitment") && !leaked,
        `field ${field}; exit ${hot.code}; rules ${JSON.stringify(hot.findings.map((finding) => finding.rule))}; `
          + `raw canary disclosed: ${leaked}`,
      );
      writeFileSync(mapPath, JSON.stringify(cleanMap));
      const cold = run(["--lane", "L-MAP"]);
      check(
        descriptorCold,
        cold.code === 0,
        `field ${field}; exit ${cold.code}; rules ${JSON.stringify(cold.findings.map((finding) => finding.rule))}`,
      );
    }

    {
      const encoded = JSON.stringify({ ...cleanMap, sources: [`/build/${canary}/index.ts`] })
        .split(canary).join(uEscape(canary));
      writeFileSync(mapPath, encoded);
      const structuralHot = run(["--lane", "L-MAP"]);
      const structuralLeaked = structuralHot.out.includes(canary);
      check(
        ARM_TASK3_CASES.mapStructuralRedacted,
        structuralHot.code === 1
          && structuralHot.findings.some((finding) => finding.rule === "sourcemap-escapes-package")
          && !structuralLeaked,
        `exit ${structuralHot.code}; rules ${JSON.stringify(structuralHot.findings.map((finding) => finding.rule))}; `
          + `raw canary disclosed: ${structuralLeaked}`,
      );
      writeFileSync(mapPath, JSON.stringify({ ...cleanMap, sourceRoot: "../", sources: ["../outside.ts"] }));
      const combined = run(["--lane", "L-MAP", "--tier", "a"]);
      check(
        ARM_TASK3_CASES.mapCombinedContainmentFound,
        combined.code === 1
          && combined.findings.some((finding) => finding.rule === "sourcemap-escapes-package"),
        `exit ${combined.code}; rules ${JSON.stringify(combined.findings.map((finding) => finding.rule))}`,
      );
      writeFileSync(mapPath, JSON.stringify(cleanMap));
      const combinedCold = run(["--lane", "L-MAP"]);
      check(
        ARM_TASK3_CASES.mapCombinedContainmentClean,
        combinedCold.code === 0,
        `exit ${combinedCold.code}; rules ${JSON.stringify(combinedCold.findings.map((finding) => finding.rule))}`,
      );
    }

    {
      writeFileSync(mapPath, canary);
      const malformed = run(["--lane", "L-MAP"]);
      const malformedLeaked = malformed.out.includes(canary);
      check(
        ARM_TASK3_CASES.mapMalformedRedacted,
        malformed.code === 1 && !malformedLeaked,
        `exit ${malformed.code}; raw canary disclosed: ${malformedLeaked}`,
      );
      writeFileSync(mapPath, JSON.stringify(cleanMap));
      const valid = run(["--lane", "L-MAP"]);
      check(
        ARM_TASK3_CASES.mapMalformedClean,
        valid.code === 0,
        `exit ${valid.code}; rules ${JSON.stringify(valid.findings.map((finding) => finding.rule))}`,
      );
    }

    const fixPath = join(repo, "conformance", "vectors.json");
    laneCase("L-FIX",
      () => writeFileSync(fixPath, JSON.stringify({ vectors: [{ id: "v1", note: canary }] }, null, 2)),
      () => writeFileSync(fixPath, JSON.stringify({ vectors: [{ id: "v1", note: "synthetic" }] }, null, 2)));

    // Content arms do not prove that externally published file names are inspected. Plant the
    // same committed canary in each distinct path representation and require the gate to withhold
    // the rejected name from its own evidence.
    const pathArmed = new Set();
    const pathLaneCase = (name, descriptors, id, plant, unplant, extraArgs = []) => {
      plant();
      const hot = run(["--lane", id, ...extraArgs]);
      const named = hot.findings.some((finding) => finding.rule === "token-commitment");
      const leaked = hot.out.includes(canary);
      const fired = check(
        descriptors.found,
        hot.code === 1 && named && !leaked,
        `exit ${hot.code}; rules ${JSON.stringify(hot.findings.map((finding) => finding.rule))}; `
          + `raw path disclosed: ${leaked}`,
      );
      unplant();
      const cold = run(["--lane", id, ...extraArgs]);
      const clean = check(
        descriptors.clean,
        cold.code === 0,
        `exit ${cold.code}; rules ${JSON.stringify(cold.findings.map((finding) => finding.rule))}`,
      );
      if (fired && clean) pathArmed.add(name);
    };

    const wtPath = join(repo, `${canary}.md`);
    pathLaneCase("L-WT path", { found: ARM_TASK3_CASES.pathWtFound, clean: ARM_TASK3_CASES.pathWtClean }, "L-WT",
      () => writeFileSync(wtPath, "# harmless path fixture\n"),
      () => rmSync(wtPath));

    const idxRel = join("staged-path", `${canary}.md`);
    const idxPath = join(repo, idxRel);
    pathLaneCase("L-IDX path", { found: ARM_TASK3_CASES.pathIdxFound, clean: ARM_TASK3_CASES.pathIdxClean }, "L-IDX",
      () => {
        mkdirSync(dirname(idxPath), { recursive: true });
        writeFileSync(idxPath, "# harmless staged path fixture\n");
        git(repo, ["add", idxRel]);
        rmSync(idxPath);
      },
      () => {
        git(repo, ["reset", "-q", "HEAD", "--", idxRel]);
        const cleanRel = join("staged-path", "clean.md");
        writeFileSync(join(repo, cleanRel), "# harmless staged path control\n");
        git(repo, ["add", cleanRel]);
      });

    const pushRel = join("pushed-path", `${canary}.md`);
    const pushPath = join(repo, pushRel);
    pathLaneCase("L-PUSH path", { found: ARM_TASK3_CASES.pathPushFound, clean: ARM_TASK3_CASES.pathPushClean }, "L-PUSH",
      () => {
        mkdirSync(dirname(pushPath), { recursive: true });
        writeFileSync(pushPath, "# harmless pushed path fixture\n");
        git(repo, ["add", pushRel]);
        git(repo, ["commit", "-q", "-m", "test: add a path fixture"]);
      },
      () => {
        git(repo, ["reset", "-q", "--hard", "HEAD~1"]);
        rmSync(dirname(pushPath), { recursive: true, force: true });
      },
      ["--range", `${baseSha}..HEAD`]);

    const packPath = join(repo, "dist", `${canary}.js`);
    pathLaneCase("L-PACK path", { found: ARM_TASK3_CASES.pathPackFound, clean: ARM_TASK3_CASES.pathPackClean }, "L-PACK",
      () => writeFileSync(packPath, "export const harmless = true;\n"),
      () => rmSync(packPath));

    const mapNamePath = join(repo, "dist", `${canary}.js.map`);
    pathLaneCase("L-MAP map path", { found: ARM_TASK3_CASES.pathMapFound, clean: ARM_TASK3_CASES.pathMapClean }, "L-MAP",
      () => writeFileSync(mapNamePath, JSON.stringify(cleanMap)),
      () => rmSync(mapNamePath));

    const declarationPath = join(repo, "dist", `${canary}.d.ts`);
    pathLaneCase(
      "L-MAP declaration path",
      { found: ARM_TASK3_CASES.pathDeclarationFound, clean: ARM_TASK3_CASES.pathDeclarationClean },
      "L-MAP",
      () => writeFileSync(declarationPath, "export declare const harmless: boolean;\n"),
      () => rmSync(declarationPath),
    );

    const fixPathRel = join("conformance", canary, "vectors.json");
    const fixPathName = join(repo, fixPathRel);
    pathLaneCase("L-FIX directory path", { found: ARM_TASK3_CASES.pathFixFound, clean: ARM_TASK3_CASES.pathFixClean }, "L-FIX",
      () => {
        mkdirSync(dirname(fixPathName), { recursive: true });
        writeFileSync(fixPathName, JSON.stringify({ vectors: [] }));
        git(repo, ["add", fixPathRel]);
      },
      () => {
        git(repo, ["reset", "-q", "HEAD", "--", fixPathRel]);
        rmSync(dirname(fixPathName), { recursive: true, force: true });
      });

    check(
      ARM_TASK3_CASES.pathRegistryArmed,
      pathArmed.size === 7,
      `armed ${pathArmed.size}/7; missing ${[
        "L-WT path", "L-IDX path", "L-PUSH path", "L-PACK path", "L-MAP map path",
        "L-MAP declaration path", "L-FIX directory path",
      ].filter((name) => !pathArmed.has(name)).join(", ")}`,
    );

    for (const [hotDescriptor, coldDescriptor, kind, separator] of [
      [ARM_TASK3_CASES.compoundHyphenFound, ARM_TASK3_CASES.compoundHyphenClean, "hyphen", "-"],
      [ARM_TASK3_CASES.compoundUnderscoreFound, ARM_TASK3_CASES.compoundUnderscoreClean, "underscore", "_"],
    ]) {
      const target = join(repo, `release${separator}${canary}${separator}notes.md`);
      writeFileSync(target, "# harmless compound-path fixture\n");
      const hot = run(["--lane", "L-WT"]);
      const leaked = hot.out.includes(canary);
      check(
        hotDescriptor,
        hot.code === 1 && hot.findings.some((finding) => finding.rule === "token-commitment") && !leaked,
        `kind ${kind}; exit ${hot.code}; rules ${JSON.stringify(hot.findings.map((finding) => finding.rule))}; `
          + `raw canary disclosed: ${leaked}`,
      );
      rmSync(target);
      const cold = run(["--lane", "L-WT"]);
      check(coldDescriptor, cold.code === 0, `kind ${kind}; exit ${cold.code}`);
    }

    {
      const externalTarget = join(work, `${canary}.txt`);
      const linkPath = join(repo, "published-link.md");
      writeFileSync(externalTarget, "# harmless external target bytes\n");
      symlinkSync(externalTarget, linkPath);
      git(repo, ["add", "published-link.md"]);
      const linkMode = git(repo, ["ls-files", "-s", "--", "published-link.md"]).stdout.trim().split(/\s+/)[0];
      check(ARM_TASK3_CASES.symlinkFixture, linkMode === "120000", `mode ${linkMode}`);
      const hot = run(["--lane", "L-WT"]);
      const leaked = hot.out.includes(canary);
      check(
        ARM_TASK3_CASES.symlinkFound,
        hot.code === 1 && hot.findings.some((finding) => finding.rule === "token-commitment") && !leaked,
        `exit ${hot.code}; rules ${JSON.stringify(hot.findings.map((finding) => finding.rule))}; `
          + `raw canary disclosed: ${leaked}`,
      );
      git(repo, ["reset", "-q", "HEAD", "--", "published-link.md"]);
      rmSync(linkPath);
      rmSync(externalTarget);
      const cold = run(["--lane", "L-WT"]);
      check(ARM_TASK3_CASES.symlinkClean, cold.code === 0, `exit ${cold.code}`);
    }

    {
      writeFileSync(wtFile, `${"."}plan/ reference ${canary}\n`);
      const composed = run(["--lane", "L-WT"]);
      const leaked = composed.out.includes(canary);
      check(
        ARM_TASK3_CASES.composedRedactionFound,
        composed.code === 1
          && composed.findings.some((finding) => finding.rule === "planning-dir")
          && composed.findings.some((finding) => finding.rule === "token-commitment")
          && !leaked,
        `exit ${composed.code}; rules ${JSON.stringify(composed.findings.map((finding) => finding.rule))}; `
          + `raw canary disclosed: ${leaked}`,
      );
      writeFileSync(wtFile, "# notes\n\nnothing here\n");
      const cold = run(["--lane", "L-WT"]);
      check(ARM_TASK3_CASES.composedRedactionClean, cold.code === 0, `exit ${cold.code}`);
    }

    {
      const sharedRel = join("dist", `${canary}.d.ts`);
      const sharedPath = join(repo, sharedRel);
      writeFileSync(sharedPath, "export declare const harmless: boolean;\n");
      git(repo, ["add", sharedRel]);
      const shared = run(["--lane", "L-WT,L-IDX,L-PACK,L-MAP"]);
      const pathHits = shared.findings.filter((finding) => finding.rule === "token-commitment");
      check(
        ARM_TASK3_CASES.pathDedupe,
        shared.code === 1 && pathHits.length === 1 && !shared.out.includes(canary),
        `exit ${shared.code}; token findings ${pathHits.length}; raw path disclosed: ${shared.out.includes(canary)}`,
      );
      git(repo, ["reset", "-q", "HEAD", "--", sharedRel]);
      rmSync(sharedPath);
    }

    {
      const ledgerPath = join(repo, "scripts", "boundary-known-exposure.json");
      const ledgerWas = readFileSync(ledgerPath, "utf8");
      const firstRel = `${canary}.md`;
      const firstPath = join(repo, firstRel);
      writeFileSync(firstPath, "# harmless path ratchet fixture\n");
      check(ARM_TASK3_CASES.pathRatchetBlocks, run(["--lane", "L-WT"]).code === 1);
      writeFileSync(ledgerPath, JSON.stringify({
        ...JSON.parse(ledgerWas),
        entries: [{
          key: `${pathContentKey(firstRel)}:token-commitment`, count: 1,
          why: "arm fixture", remediation: "arm fixture", reviewedAt: new Date().toISOString(),
        }],
      }, null, 2));
      check(ARM_TASK3_CASES.pathRatchetCarries, run(["--lane", "L-WT"]).code === 0);
      const renamedRel = join("renamed", `${canary}.md`);
      const renamedPath = join(repo, renamedRel);
      mkdirSync(dirname(renamedPath), { recursive: true });
      writeFileSync(renamedPath, "# harmless path ratchet fixture\n");
      rmSync(firstPath);
      const renamed = run(["--lane", "L-WT"]);
      check(
        ARM_TASK3_CASES.pathRatchetRenameBlocks,
        renamed.code === 1
          && renamed.findings.some((finding) => finding.rule === "token-commitment")
          && !renamed.out.includes(canary),
        `exit ${renamed.code}; rules ${JSON.stringify(renamed.findings.map((finding) => finding.rule))}; `
          + `raw path disclosed: ${renamed.out.includes(canary)}`,
      );
      writeFileSync(ledgerPath, ledgerWas);
      rmSync(dirname(renamedPath), { recursive: true, force: true });
    }

    {
      const allowlist = JSON.parse(readFileSync(join(repo, "scripts", "boundary-public-repos.json"), "utf8"));
      const org = Object.keys(allowlist.orgs)[0];
      const publicRepo = allowlist.orgs[org][0];
      const privatePath = join(repo, "docs", org, "not-on-the-public-list", "note.md");
      mkdirSync(dirname(privatePath), { recursive: true });
      writeFileSync(privatePath, "# harmless nested path fixture\n");
      const blocked = run(["--lane", "L-WT"]);
      check(
        ARM_TASK3_CASES.nestedPathBlocks,
        blocked.code === 1
          && blocked.findings.some((finding) => finding.rule === "repo-not-public")
          && !blocked.out.includes("not-on-the-public-list"),
        `exit ${blocked.code}; rules ${JSON.stringify(blocked.findings.map((finding) => finding.rule))}; `
          + `raw path disclosed: ${blocked.out.includes("not-on-the-public-list")}`,
      );
      rmSync(join(repo, "docs"), { recursive: true, force: true });
      const publicPath = join(repo, "docs", org, publicRepo, "note.md");
      mkdirSync(dirname(publicPath), { recursive: true });
      writeFileSync(publicPath, "# harmless nested public path control\n");
      const clean = run(["--lane", "L-WT"]);
      check(ARM_TASK3_CASES.nestedPathClean, clean.code === 0, `exit ${clean.code}`);
      rmSync(join(repo, "docs"), { recursive: true, force: true });
    }

    {
      const suppressionRel = join(
        ".plan",
        `noa-boundary-ok:${contentKey([".", "plan/"].join("")).slice(0, 8)}:filename-is-not-a-comment`,
        "note.md",
      );
      const suppressionPath = join(repo, suppressionRel);
      mkdirSync(dirname(suppressionPath), { recursive: true });
      writeFileSync(suppressionPath, "# harmless path suppression fixture\n");
      const blocked = run(["--lane", "L-WT"]);
      check(
        ARM_TASK3_CASES.filenameSuppressionRefused,
        blocked.code === 1
          && blocked.findings.some((finding) => finding.rule === "planning-dir")
          && !blocked.out.includes(".plan"),
        `exit ${blocked.code}; rules ${JSON.stringify(blocked.findings.map((finding) => finding.rule))}; `
          + `raw path disclosed: ${blocked.out.includes(".plan")}`,
      );
      rmSync(join(repo, ".plan"), { recursive: true, force: true });
    }

    // ── 3a. real pre-push protocol, including the two cases local --all gets wrong ─────────────
    // A new branch has an all-zero destination object. Its baseline must come from the actual
    // destination refs, excluding the ref being created; local refs may contain unrelated objects
    // and therefore cannot establish what the destination already has. The canary is in an older
    // version of one path and scrubbed at the tip, proving L-PUSH reads every pushed version too.
    {
      const remote = join(work, "arm-remote.git");
      git(work, ["init", "-q", "--bare", remote], true);
      // Push to the exact destination path, as Git permits, instead of adding a second persistent
      // remote. The candidate bootstrap deliberately accepts only the canonical public `origin`
      // identity, so test-only transport configuration must not broaden the candidate's authority.
      const initialPush = git(
        repo,
        ["push", "-q", remote, "HEAD:refs/heads/main"],
        false,
        hookEnvironment,
      );
      const initialPushOutput = `${initialPush.stdout ?? ""}${initialPush.stderr ?? ""}`;
      const isolatedPrepushCensus = inspectBoundaryEvidenceSpool({
        spoolDirectoryPath: isolatedPrepushSpool,
        event: "PREPUSH_GATE_VERDICT",
      });
      const isolatedNames = readdirSync(isolatedPrepushSpool).sort();
      const isolatedPendingNamePattern = new RegExp(
        `^\\.pending-v${BOUNDARY_EVIDENCE_SPOOL_VERSION}-[0-9a-f]{64}-`
          + "[1-9][0-9]{0,15}-p[1-9][0-9]{0,15}-[0-9a-f]{32}\\.json$",
      );
      const isolatedPendingNames = isolatedNames.filter((name) =>
        isolatedPendingNamePattern.test(name));
      const everyIsolatedArtifactContained = isolatedNames.every((name) =>
        resolve(join(isolatedPrepushSpool, name)).startsWith(`${resolve(armHome)}${sep}`));
      if (isolatedPrepushCensus.validCount === 1
          && isolatedPrepushCensus.pendingCount === 1
          && isolatedPrepushCensus.cleanupResidueCount === 1
          && isolatedPendingNames.length === 1
          && everyIsolatedArtifactContained) {
        // This alias is inside a newly-created disposable HOME exclusively owned by this arm. The
        // production writer correctly retained it because it cannot assume such exclusive custody.
        unlinkSync(join(isolatedPrepushSpool, isolatedPendingNames[0]));
      }
      const isolatedPrepushTerminal = inspectBoundaryEvidenceSpool({
        spoolDirectoryPath: isolatedPrepushSpool,
        event: "PREPUSH_GATE_VERDICT",
      });
      const hostPrepushAfter = snapshotSpoolForIsolation(hostPrepushSpool);
      const outputUsesHomeRelativeSpoolLabel =
        initialPushOutput.includes("~/.noa-boundary/evidence-spool/")
        && !initialPushOutput.includes(armHome)
        && !initialPushOutput.includes(hostBoundaryDirectory);
      check(
        ARM_STATIC_CASES.case_the_real_push_hook_selects_and_writes_only_its_isolated_arm_evi_0331903f,
        outputUsesHomeRelativeSpoolLabel
          && isolatedPrepushCensus.validCount === 1
          && isolatedPrepushCensus.pendingCount === 1
          && isolatedPrepushCensus.cleanupResidueCount === 1
          && everyIsolatedArtifactContained
          && isolatedPrepushTerminal.validCount === 1
          && isolatedPrepushTerminal.pendingCount === 0
          && isolatedPrepushTerminal.cleanupResidueCount === 0
          && hostPrepushAfter.safe
          && hostPrepushAfter.digest === hostPrepushBefore.digest,
        `isolated observed/terminal ${canonicalJson(isolatedPrepushCensus)}/${canonicalJson(isolatedPrepushTerminal)}; `
          + `home-relative output ${outputUsesHomeRelativeSpoolLabel}; `
          + `host unchanged ${hostPrepushAfter.digest === hostPrepushBefore.digest}`,
      );
      const before = git(repo, ["rev-parse", "HEAD"]).stdout.trim();
      const objectFormat = git(repo, ["rev-parse", "--show-object-format"]).stdout.trim();
      const zeros = "0".repeat(objectFormat === "sha256" ? 64 : 40);
      const refArgs = [
        "--lane", "L-WT", "--refs-from-stdin",
        "--pre-push-remote", remote, "--pre-push-url", remote,
      ];

      writeFileSync(join(repo, "new-branch.md"), `historical ${canary}\n`);
      git(repo, ["add", "new-branch.md"]);
      git(repo, ["commit", "-q", "-m", "chore: first new-branch version"]);
      writeFileSync(join(repo, "new-branch.md"), "clean at the tip\n");
      git(repo, ["add", "new-branch.md"]);
      git(repo, ["commit", "-q", "-m", "chore: scrub new-branch tip"]);
      const newBranchSha = git(repo, ["rev-parse", "HEAD"]).stdout.trim();
      const hotBranch = run(refArgs, {
        input: `HEAD ${newBranchSha} refs/heads/arm-new ${zeros}\n`,
      });
      check(
        ARM_STATIC_CASES.case_pre_push_new_branch_destination_refs_are_used_and_an_older_blob_864a9483,
        hotBranch.code === 1 && hotBranch.findings.some((finding) => finding.rule === "token-commitment"),
        `exit ${hotBranch.code}; rules ${JSON.stringify(hotBranch.findings.map((finding) => finding.rule))}`,
      );
      git(repo, ["reset", "-q", "--hard", before]);

      git(repo, ["commit", "-q", "--allow-empty", "-m", "chore: clean new branch"]);
      const cleanBranchSha = git(repo, ["rev-parse", "HEAD"]).stdout.trim();
      const coldBranch = run(refArgs, {
        input: `HEAD ${cleanBranchSha} refs/heads/arm-clean ${zeros}\n`,
      });
      check(ARM_STATIC_CASES.case_pre_push_new_branch_the_same_destination_derived_path_goes_clea_0d02024c, coldBranch.code === 0,
        `exit ${coldBranch.code}\n${coldBranch.out.slice(0, 700)}`);
      git(repo, ["reset", "-q", "--hard", before]);

      // Clean-history publication cannot possess the destination's old object graph. Model that
      // topology with an unrelated source repository and prove both pre-push modes scan the full
      // locally-known ancestry instead of passing a missing remote OID to `rev-list --not`.
      const disconnectedSource = join(work, "arm-disconnected-source");
      const disconnectedRemote = join(work, "arm-disconnected-remote.git");
      buildSyntheticRepo(disconnectedSource, root);
      git(work, ["init", "-q", "--bare", disconnectedRemote], true);
      git(disconnectedSource, ["push", "--no-verify", "-q", disconnectedRemote, "HEAD:refs/heads/main"]);
      const unavailableRemoteSha = git(disconnectedSource, ["rev-parse", "HEAD"]).stdout.trim();
      const accidentalLocalCopy = git(
        repo,
        ["cat-file", "-e", `${unavailableRemoteSha}^{object}`],
        true,
      );
      if (accidentalLocalCopy.status === 0) {
        throw new Error("the disconnected-history arm accidentally shares its destination tip");
      }
      const disconnectedRefArgs = [
        "--lane", "L-WT", "--refs-from-stdin",
        "--pre-push-remote", disconnectedRemote, "--pre-push-url", disconnectedRemote,
      ];
      const disconnectedBase = git(repo, ["rev-parse", "HEAD"]).stdout.trim();
      writeFileSync(join(repo, "disconnected-history.md"), `historical ${canary}\n`);
      git(repo, ["add", "disconnected-history.md"]);
      git(repo, ["commit", "-q", "-m", "chore: disconnected history plant"]);
      writeFileSync(join(repo, "disconnected-history.md"), "clean at the disconnected tip\n");
      git(repo, ["add", "disconnected-history.md"]);
      git(repo, ["commit", "-q", "-m", "chore: scrub disconnected history tip"]);
      const disconnectedHotSha = git(repo, ["rev-parse", "HEAD"]).stdout.trim();
      const disconnectedNewHot = run(disconnectedRefArgs, {
        input: `HEAD ${disconnectedHotSha} refs/heads/clean-candidate ${zeros}\n`,
      });
      check(
        ARM_STATIC_CASES.case_pre_push_new_branch_ignores_unavailable_destination_tips_and_finds_older_blob,
        disconnectedNewHot.code === 1
          && disconnectedNewHot.findings.some((finding) => finding.rule === "token-commitment")
          && !disconnectedNewHot.out.includes(canary),
        `exit ${disconnectedNewHot.code}; rules ${JSON.stringify(disconnectedNewHot.findings.map((finding) => finding.rule))}`,
      );
      const disconnectedExistingHot = run(disconnectedRefArgs, {
        input: `HEAD ${disconnectedHotSha} refs/heads/main ${unavailableRemoteSha}\n`,
      });
      check(
        ARM_STATIC_CASES.case_pre_push_existing_ref_with_unavailable_destination_tip_finds_older_blob,
        disconnectedExistingHot.code === 1
          && disconnectedExistingHot.findings.some((finding) => finding.rule === "token-commitment")
          && !disconnectedExistingHot.out.includes(canary),
        `exit ${disconnectedExistingHot.code}; rules ${JSON.stringify(disconnectedExistingHot.findings.map((finding) => finding.rule))}`,
      );
      git(repo, ["reset", "-q", "--hard", disconnectedBase]);
      git(repo, ["commit", "-q", "--allow-empty", "-m", "chore: clean disconnected candidate"]);
      const disconnectedColdSha = git(repo, ["rev-parse", "HEAD"]).stdout.trim();
      const disconnectedNewCold = run(disconnectedRefArgs, {
        input: `HEAD ${disconnectedColdSha} refs/heads/clean-candidate ${zeros}\n`,
      });
      check(
        ARM_STATIC_CASES.case_pre_push_new_branch_with_unavailable_destination_tips_goes_clean,
        disconnectedNewCold.code === 0,
        `exit ${disconnectedNewCold.code}\n${disconnectedNewCold.out.slice(0, 700)}`,
      );
      const disconnectedExistingCold = run(disconnectedRefArgs, {
        input: `HEAD ${disconnectedColdSha} refs/heads/main ${unavailableRemoteSha}\n`,
      });
      check(
        ARM_STATIC_CASES.case_pre_push_existing_ref_with_unavailable_destination_tip_goes_clean,
        disconnectedExistingCold.code === 0,
        `exit ${disconnectedExistingCold.code}\n${disconnectedExistingCold.out.slice(0, 700)}`,
      );
      git(repo, ["reset", "-q", "--hard", before]);

      const annotatedName = "arm-annotated";
      git(repo, ["tag", "-a", annotatedName, "-m", `release ${canary}`, "HEAD"]);
      const annotatedSha = git(repo, ["rev-parse", `refs/tags/${annotatedName}`]).stdout.trim();
      const hotAnnotation = run(refArgs, {
        input: `refs/tags/${annotatedName} ${annotatedSha} refs/tags/${annotatedName} ${zeros}\n`,
      });
      check(
        ARM_STATIC_CASES.case_pre_push_annotated_tag_the_tag_object_annotation_is_found_even__c2aeff84,
        hotAnnotation.code === 1 && hotAnnotation.findings.some((finding) => finding.rule === "token-commitment"),
        `exit ${hotAnnotation.code}; rules ${JSON.stringify(hotAnnotation.findings.map((finding) => finding.rule))}`,
      );
      git(repo, ["tag", "-d", annotatedName]);

      const cleanTag = "arm-clean-annotation";
      git(repo, ["tag", "-a", cleanTag, "-m", "synthetic release", "HEAD"]);
      const cleanTagSha = git(repo, ["rev-parse", `refs/tags/${cleanTag}`]).stdout.trim();
      const hotRemoteName = run(refArgs, {
        input: `refs/tags/${cleanTag} ${cleanTagSha} refs/tags/${canary} ${zeros}\n`,
      });
      check(
        ARM_STATIC_CASES.case_pre_push_annotated_tag_the_exact_destination_tag_name_is_found__63c9c60f,
        hotRemoteName.code === 1 && hotRemoteName.findings.some((finding) => finding.rule === "token-commitment"),
        `exit ${hotRemoteName.code}; rules ${JSON.stringify(hotRemoteName.findings.map((finding) => finding.rule))}`,
      );
      const cleanTagRun = run(refArgs, {
        input: `refs/tags/${cleanTag} ${cleanTagSha} refs/tags/${cleanTag} ${zeros}\n`,
      });
      check(ARM_STATIC_CASES.case_pre_push_annotated_tag_clean_object_and_clean_names_go_clean, cleanTagRun.code === 0,
        `exit ${cleanTagRun.code}\n${cleanTagRun.out.slice(0, 700)}`);
      git(repo, ["tag", "-d", cleanTag]);

      const blobFixturePath = join(repo, "arm-non-commit-tag-target.txt");
      writeFileSync(blobFixturePath, "harmless blob tag target\n");
      const blobTargetSha = git(repo, ["hash-object", "-w", blobFixturePath]).stdout.trim();
      unlinkSync(blobFixturePath);
      const blobTag = "arm-blob-target";
      git(repo, ["update-ref", `refs/tags/${blobTag}`, blobTargetSha]);
      const blobTagRun = run(["--lane", "L-TAG", ...refArgs.slice(2)], {
        input: `refs/tags/${blobTag} ${blobTargetSha} refs/tags/${blobTag} ${zeros}\n`,
      });
      check(
        ARM_STATIC_CASES.case_pre_push_tag_targeting_non_commit_object_fails_closed,
        blobTagRun.code === 2
          && blobTagRun.findings.some((finding) =>
            finding.rule === "SETUP_FAILED"
              && finding.subject === "a pushed tag terminates at a non-commit object"),
        `exit ${blobTagRun.code}; findings ${JSON.stringify(blobTagRun.findings.map((finding) => [finding.rule, finding.subject]))}`,
      );
      git(repo, ["update-ref", "-d", `refs/tags/${blobTag}`]);

      // A tag whose benign name resembles another full ref must still be dereferenced through its
      // exact refs/tags identity; short-name resolution may not let a branch shadow its annotation.
      const annotationTag = "refs/heads/main";
      git(repo, ["tag", "-a", annotationTag, "-m", `release ${canary}`, "HEAD"]);
      const shadowHot = run(["--lane", "L-TAG", "--range", `${baseSha}..HEAD`]);
      const shadowLeaked = shadowHot.out.includes(canary);
      check(
        ARM_TASK3_CASES.tagAnnotationBranchShadowFound,
        shadowHot.code === 1
          && shadowHot.findings.some((finding) => finding.rule === "token-commitment")
          && !shadowLeaked,
        `exit ${shadowHot.code}; rules ${JSON.stringify(shadowHot.findings.map((finding) => finding.rule))}; `
          + `raw canary disclosed: ${shadowLeaked}`,
      );
      const shadowSha = git(repo, ["rev-parse", `refs/tags/${annotationTag}`]).stdout.trim();
      const shadowDirect = run(["--lane", "L-TAG", ...refArgs.slice(2)], {
        input: `refs/tags/${annotationTag} ${shadowSha} refs/tags/${annotationTag} ${zeros}\n`,
      });
      const shadowDirectLeaked = shadowDirect.out.includes(canary);
      check(
        ARM_TASK3_CASES.tagAnnotationExactPrepushFound,
        shadowDirect.code === 1
          && shadowDirect.findings.some((finding) => finding.rule === "token-commitment")
          && !shadowDirectLeaked,
        `exit ${shadowDirect.code}; rules ${JSON.stringify(shadowDirect.findings.map((finding) => finding.rule))}; `
          + `raw canary disclosed: ${shadowDirectLeaked}`,
      );
      git(repo, ["tag", "-d", annotationTag]);
      check(
        ARM_TASK3_CASES.tagAnnotationClean,
        run(["--lane", "L-TAG", "--range", `${baseSha}..HEAD`]).code === 0,
      );

      // Ref names themselves are publication bytes. Make each local selector real so the exact
      // pre-push parser can bind it to the supplied object before its public label is scanned.
      const localRefSha = git(repo, ["rev-parse", "HEAD"]).stdout.trim();
      const refCases = [
        [ARM_TASK3_CASES.refExactFound, `refs/heads/${canary}`],
        [ARM_TASK3_CASES.refHyphenFound, `refs/heads/release-${canary}`],
        [ARM_TASK3_CASES.refUnderscoreFound, `refs/heads/release_${canary}`],
      ];
      for (const [descriptor, confidentialRef] of refCases) {
        git(repo, ["update-ref", confidentialRef, localRefSha]);
        const refHot = run(["--lane", "L-MSG", ...refArgs.slice(2)], {
          input: `${confidentialRef} ${localRefSha} refs/heads/arm-ref-probe ${zeros}\n`,
        });
        const refLeaked = refHot.out.includes(canary);
        check(
          descriptor,
          refHot.code === 1
            && refHot.findings.some((finding) => finding.rule === "token-commitment")
            && !refLeaked,
          `exit ${refHot.code}; rules ${JSON.stringify(refHot.findings.map((finding) => finding.rule))}; `
            + `raw canary disclosed: ${refLeaked}`,
        );
        git(repo, ["update-ref", "-d", confidentialRef]);
      }
      const safeRef = "refs/heads/arm-safe-ref";
      git(repo, ["update-ref", safeRef, localRefSha]);
      const refCold = run(["--lane", "L-MSG", ...refArgs.slice(2)], {
        input: `${safeRef} ${localRefSha} refs/heads/arm-safe-ref ${zeros}\n`,
      });
      check(
        ARM_TASK3_CASES.refClean,
        refCold.code === 0,
        `exit ${refCold.code}; rules ${JSON.stringify(refCold.findings.map((finding) => finding.rule))}`,
      );
      git(repo, ["update-ref", "-d", safeRef]);
    }

    // Scope-sensitive rules receive canonical repository paths, never lane-decorated report labels.
    {
      const scopeRepo = join(work, "scoped-paths");
      buildSyntheticRepo(scopeRepo, root);
      materializeScannerRuntime(root, scopeRepo);
      const scopeGate = join(scopeRepo, "scripts", "lint-boundary.mjs");
      const scopeRel = join("conformance", "scoped-account.json");
      const scopePath = join(scopeRepo, scopeRel);
      const hotBody = '{"sub":"acct-7probe"}\n';
      const coldBody = '{"sub":"acct-example-7"}\n';

      writeFileSync(scopePath, hotBody);
      git(scopeRepo, ["add", scopeRel]);
      writeFileSync(scopePath, coldBody);
      const idxHot = run(["--lane", "L-IDX", "--tier", "a"], { gate: scopeGate, cwd: scopeRepo });
      check(
        ARM_TASK3_CASES.scopedIndexFound,
        idxHot.code === 1 && idxHot.findings.some((finding) => finding.rule === "fixture-account-shape"),
        `exit ${idxHot.code}; rules ${JSON.stringify(idxHot.findings.map((finding) => finding.rule))}`,
      );
      git(scopeRepo, ["add", scopeRel]);
      const idxCold = run(["--lane", "L-IDX", "--tier", "a"], { gate: scopeGate, cwd: scopeRepo });
      check(ARM_TASK3_CASES.scopedIndexClean, idxCold.code === 0, `exit ${idxCold.code}`);

      git(scopeRepo, ["reset", "-q", "--hard", "HEAD"]);
      const scopeBase = git(scopeRepo, ["rev-parse", "HEAD"]).stdout.trim();
      writeFileSync(scopePath, hotBody);
      git(scopeRepo, ["add", scopeRel]);
      git(scopeRepo, ["commit", "-q", "-m", "test: scoped push fixture"]);
      const pushHot = run(["--lane", "L-PUSH", "--tier", "a", "--range", `${scopeBase}..HEAD`], {
        gate: scopeGate, cwd: scopeRepo,
      });
      check(
        ARM_TASK3_CASES.scopedPushFound,
        pushHot.code === 1 && pushHot.findings.some((finding) => finding.rule === "fixture-account-shape"),
        `exit ${pushHot.code}; rules ${JSON.stringify(pushHot.findings.map((finding) => finding.rule))}`,
      );
      git(scopeRepo, ["reset", "-q", "--hard", scopeBase]);
      writeFileSync(scopePath, coldBody);
      git(scopeRepo, ["add", scopeRel]);
      git(scopeRepo, ["commit", "-q", "-m", "test: clean scoped push fixture"]);
      const pushCold = run(["--lane", "L-PUSH", "--tier", "a", "--range", `${scopeBase}..HEAD`], {
        gate: scopeGate, cwd: scopeRepo,
      });
      check(ARM_TASK3_CASES.scopedPushClean, pushCold.code === 0, `exit ${pushCold.code}`);
    }

    // Every reachable version of a pushed path remains public even when the tip has been scrubbed.
    {
      const historyPath = join(repo, "history.md");
      const historyBase = git(repo, ["rev-parse", "HEAD"]).stdout.trim();
      writeFileSync(historyPath, "# harmless first version\n");
      git(repo, ["add", "history.md"]);
      git(repo, ["commit", "-q", "-m", "test: add history fixture"]);
      writeFileSync(historyPath, `# hidden intermediate version\n${canary}\n`);
      git(repo, ["add", "history.md"]);
      git(repo, ["commit", "-q", "-m", "test: change history fixture"]);
      writeFileSync(historyPath, "# harmless final version\n");
      git(repo, ["add", "history.md"]);
      git(repo, ["commit", "-q", "-m", "test: clean history fixture"]);
      const hot = run(["--lane", "L-PUSH", "--range", `${historyBase}..HEAD`]);
      const leaked = hot.out.includes(canary);
      check(
        ARM_TASK3_CASES.historyEveryBlobFound,
        hot.code === 1 && hot.findings.some((finding) => finding.rule === "token-commitment") && !leaked,
        `exit ${hot.code}; rules ${JSON.stringify(hot.findings.map((finding) => finding.rule))}; `
          + `raw canary disclosed: ${leaked}`,
      );
      git(repo, ["reset", "-q", "--hard", historyBase]);
      const cold = run(["--lane", "L-PUSH", "--range", `${baseSha}..HEAD`]);
      check(ARM_TASK3_CASES.historyEveryBlobClean, cold.code === 0, `exit ${cold.code}`);
    }

    // Merge-result trees are omitted unless diff-tree is invoked with explicit merge handling.
    {
      const mergeRepo = join(work, "merge-history");
      buildSyntheticRepo(mergeRepo, root);
      materializeScannerRuntime(root, mergeRepo);
      const mergeGate = join(mergeRepo, "scripts", "lint-boundary.mjs");
      const mergeBase = git(mergeRepo, ["rev-parse", "HEAD"]).stdout.trim();
      git(mergeRepo, ["checkout", "-q", "-b", "arm-left", mergeBase]);
      writeFileSync(join(mergeRepo, "merge.md"), "# harmless left parent\n");
      git(mergeRepo, ["add", "merge.md"]);
      git(mergeRepo, ["commit", "-q", "-m", "test: left merge parent"]);
      git(mergeRepo, ["checkout", "-q", "-b", "arm-right", mergeBase]);
      writeFileSync(join(mergeRepo, "right.md"), "# harmless right parent\n");
      git(mergeRepo, ["add", "right.md"]);
      git(mergeRepo, ["commit", "-q", "-m", "test: right merge parent"]);
      git(mergeRepo, ["checkout", "-q", "arm-left"]);
      git(mergeRepo, ["merge", "-q", "--no-ff", "--no-commit", "arm-right"]);
      writeFileSync(join(mergeRepo, "merge.md"), `# merge-only bytes\n${canary}\n`);
      git(mergeRepo, ["add", "merge.md"]);
      git(mergeRepo, ["commit", "-q", "-m", "test: merge-only boundary fixture"]);
      const mergeSha = git(mergeRepo, ["rev-parse", "HEAD"]).stdout.trim();
      const parentCount = git(mergeRepo, ["rev-list", "--parents", "-n", "1", mergeSha]).stdout.trim().split(/\s+/).length - 1;
      check(ARM_TASK3_CASES.mergeFixture, parentCount === 2, `parents ${parentCount}`);
      writeFileSync(join(mergeRepo, "merge.md"), "# harmless clean child\n");
      git(mergeRepo, ["add", "merge.md"]);
      git(mergeRepo, ["commit", "-q", "-m", "test: clean after merge fixture"]);
      const mergeHot = run(["--lane", "L-PUSH", "--range", `${mergeBase}..HEAD`], {
        gate: mergeGate, cwd: mergeRepo,
      });
      const mergeLeaked = mergeHot.out.includes(canary);
      check(
        ARM_TASK3_CASES.mergeFound,
        mergeHot.code === 1
          && mergeHot.findings.some((finding) => finding.rule === "token-commitment")
          && !mergeLeaked,
        `exit ${mergeHot.code}; rules ${JSON.stringify(mergeHot.findings.map((finding) => finding.rule))}; `
          + `raw canary disclosed: ${mergeLeaked}`,
      );

      const cleanRepo = join(work, "merge-history-clean");
      buildSyntheticRepo(cleanRepo, root);
      materializeScannerRuntime(root, cleanRepo);
      const cleanGate = join(cleanRepo, "scripts", "lint-boundary.mjs");
      const cleanBase = git(cleanRepo, ["rev-parse", "HEAD"]).stdout.trim();
      git(cleanRepo, ["checkout", "-q", "-b", "arm-left", cleanBase]);
      writeFileSync(join(cleanRepo, "merge.md"), "# harmless left parent\n");
      git(cleanRepo, ["add", "merge.md"]);
      git(cleanRepo, ["commit", "-q", "-m", "test: clean left merge parent"]);
      git(cleanRepo, ["checkout", "-q", "-b", "arm-right", cleanBase]);
      writeFileSync(join(cleanRepo, "right.md"), "# harmless right parent\n");
      git(cleanRepo, ["add", "right.md"]);
      git(cleanRepo, ["commit", "-q", "-m", "test: clean right merge parent"]);
      git(cleanRepo, ["checkout", "-q", "arm-left"]);
      git(cleanRepo, ["merge", "-q", "--no-ff", "--no-commit", "arm-right"]);
      git(cleanRepo, ["commit", "-q", "-m", "test: clean merge result"]);
      const mergeCold = run(["--lane", "L-PUSH", "--range", `${cleanBase}..HEAD`], {
        gate: cleanGate, cwd: cleanRepo,
      });
      check(ARM_TASK3_CASES.mergeClean, mergeCold.code === 0, `exit ${mergeCold.code}`);
    }

    // Replacement refs change local presentation but not the object a normal push publishes.
    {
      const replaceRepo = join(work, "replacement-view");
      buildSyntheticRepo(replaceRepo, root);
      materializeScannerRuntime(root, replaceRepo);
      const replaceGate = join(replaceRepo, "scripts", "lint-boundary.mjs");
      const replaceBase = git(replaceRepo, ["rev-parse", "HEAD"]).stdout.trim();
      const replacePath = join(replaceRepo, "replacement-view.md");
      writeFileSync(replacePath, `${canary}\n`);
      git(replaceRepo, ["add", "replacement-view.md"]);
      git(replaceRepo, ["commit", "-q", "-m", "test: original object"]);
      const originalSha = git(replaceRepo, ["rev-parse", "HEAD"]).stdout.trim();
      git(replaceRepo, ["checkout", "-q", "-b", "benign-view", replaceBase]);
      writeFileSync(replacePath, "# harmless replacement view\n");
      git(replaceRepo, ["add", "replacement-view.md"]);
      git(replaceRepo, ["commit", "-q", "-m", "test: benign replacement object"]);
      const benignSha = git(replaceRepo, ["rev-parse", "HEAD"]).stdout.trim();
      git(replaceRepo, ["checkout", "-q", "main"]);
      const replaceRefDirectory = join(replaceRepo, ".git", "refs", "replace");
      const removeEmptyReplaceRefDirectory = () => {
        if (!existsSync(replaceRefDirectory)) return;
        if (readdirSync(replaceRefDirectory).length !== 0) {
          throw new Error("the synthetic replacement ref directory remained populated after deletion");
        }
        rmdirSync(replaceRefDirectory);
      };
      git(replaceRepo, ["replace", originalSha, benignSha]);

      const bare = join(work, "replacement-remote.git");
      git(work, ["init", "-q", "--bare", bare], true);
      // This disposable local transfer measures raw Git replacement semantics. The real committed
      // hook correctly refuses a repository while refs/replace exists, so bypass only that hook for
      // this synthetic proof and inspect the exact object received by the isolated bare repository.
      git(replaceRepo, ["push", "--no-verify", "-q", bare, `${originalSha}:refs/heads/probe`]);
      const remoteBody = git(replaceRepo, ["--git-dir", bare, "show", "refs/heads/probe:replacement-view.md"]).stdout;
      check(ARM_TASK3_CASES.replacementRemoteProof, remoteBody.includes(canary));
      git(replaceRepo, ["replace", "-d", originalSha]);
      removeEmptyReplaceRefDirectory();

      const replacementHot = run(["--lane", "L-PUSH", "--range", `${replaceBase}..${originalSha}`], {
        gate: replaceGate, cwd: replaceRepo,
      });
      const replacementLeaked = replacementHot.out.includes(canary);
      check(
        ARM_TASK3_CASES.replacementFound,
        replacementHot.code === 1
          && replacementHot.findings.some((finding) => finding.rule === "token-commitment")
          && !replacementLeaked,
        `exit ${replacementHot.code}; rules ${JSON.stringify(replacementHot.findings.map((finding) => finding.rule))}; `
          + `raw canary disclosed: ${replacementLeaked}`,
      );
      git(replaceRepo, ["checkout", "-q", "-f", "benign-view"]);
      const replacementCold = run(["--lane", "L-PUSH", "--range", `${replaceBase}..${benignSha}`], {
        gate: replaceGate, cwd: replaceRepo,
      });
      check(ARM_TASK3_CASES.replacementClean, replacementCold.code === 0, `exit ${replacementCold.code}`);

      git(replaceRepo, ["replace", benignSha, originalSha]);
      git(replaceRepo, ["push", "--no-verify", "-q", bare, `${benignSha}:refs/heads/reverse-probe`]);
      const reverseRemoteBody = git(
        replaceRepo,
        ["--git-dir", bare, "show", "refs/heads/reverse-probe:replacement-view.md"],
      ).stdout;
      check(
        ARM_TASK3_CASES.replacementReverseClean,
        reverseRemoteBody === "# harmless replacement view\n",
        `remote body remained benign: ${!reverseRemoteBody.includes(canary)}`,
      );
      git(replaceRepo, ["replace", "-d", benignSha]);
      removeEmptyReplaceRefDirectory();

      const graftPath = git(
        replaceRepo,
        ["rev-parse", "--path-format=absolute", "--git-path", "info/grafts"],
      ).stdout.trim();
      if (graftPath !== join(replaceRepo, ".git", "info", "grafts")) {
        throw new Error("the synthetic graft path escaped its disposable repository");
      }
      mkdirSync(dirname(graftPath), { recursive: true });
      writeFileSync(graftPath, `${benignSha}\n`);
      // The external supervisor must not derive authority for a repository whose history view is
      // already ambiguous. Exercise this invalid-layout case through the closed candidate Tier-A
      // bootstrap instead, then credit only its observed (non-authoritative) terminal refusal.
      const grafted = run(["--lane", "L-WT"], {
        candidateTierABootstrap: true,
        gate: replaceGate,
        cwd: replaceRepo,
      });
      const graftSetupFailure = grafted.observedFindings.some((finding) =>
        finding.rule === "SETUP_FAILED"
          && finding.subject === "Git graft history override"
          && finding.detail.startsWith("BOUNDARY_BOOTSTRAP_GIT_LAYOUT_INVALID:"));
      check(
        ARM_TASK3_CASES.graftRefused,
        grafted.code === null && grafted.observedCode === 2 && !grafted.protocolComplete
          && grafted.protocol === BOUNDARY_CANDIDATE_TIER_A_GATE_EXPECTATION.protocol
          && grafted.provenance?.verification === "UNVERIFIED_BOOTSTRAP"
          && grafted.authorityProblem?.startsWith("GATE_CHILD_PROVENANCE_")
          && grafted.findings.length === 0 && graftSetupFailure,
        `credited/observed exit ${grafted.code}/${grafted.observedCode}; `
          + `authority ${grafted.authorityProblem}; observed rules `
          + `${JSON.stringify(grafted.observedFindings.map((finding) => finding.rule))}`,
      );
      rmSync(graftPath);
      const graftCold = run(["--lane", "L-WT"], { gate: replaceGate, cwd: replaceRepo });
      check(ARM_TASK3_CASES.graftClean, graftCold.code === 0, `exit ${graftCold.code}`);
    }

    // A root commit has no parent; --root is required for its complete path set.
    {
      const rootRepo = join(work, "root-push");
      buildSyntheticRepo(rootRepo, root);
      materializeScannerRuntime(root, rootRepo);
      const rootFixture = join(rootRepo, "root-fixture.md");
      writeFileSync(rootFixture, `${canary}\n`);
      git(rootRepo, ["add", "-A"]);
      const hotTree = git(rootRepo, ["write-tree"]).stdout.trim();
      const hotRootSha = git(rootRepo, ["commit-tree", hotTree, "-m", "test: parentless push fixture"]).stdout.trim();
      git(rootRepo, ["update-ref", "refs/heads/main", hotRootSha]);
      git(rootRepo, ["reset", "-q", "--hard", hotRootSha]);
      const parentLine = git(rootRepo, ["rev-list", "--parents", "-n", "1", hotRootSha]).stdout.trim().split(/\s+/);
      if (parentLine.length !== 1) throw new Error("the parentless arm fixture unexpectedly has a parent");
      const rootRemote = join(work, "root-push-remote.git");
      git(work, ["init", "-q", "--bare", rootRemote], true);
      const rootObjectFormat = git(rootRepo, ["rev-parse", "--show-object-format"]).stdout.trim();
      const rootZeros = "0".repeat(rootObjectFormat === "sha256" ? 64 : 40);
      const rootArgs = [
        "--lane", "L-PUSH,L-MSG", "--refs-from-stdin",
        "--pre-push-remote", rootRemote, "--pre-push-url", rootRemote,
      ];
      const rootGate = join(rootRepo, "scripts", "lint-boundary.mjs");
      const rootHot = run(rootArgs, {
        gate: rootGate, cwd: rootRepo,
        input: `HEAD ${hotRootSha} refs/heads/new ${rootZeros}\n`,
      });
      const rootLeaked = rootHot.out.includes(canary);
      check(
        ARM_TASK3_CASES.parentlessFound,
        rootHot.code === 1
          && rootHot.findings.some((finding) => finding.rule === "token-commitment")
          && !rootLeaked,
        `exit ${rootHot.code}; rules ${JSON.stringify(rootHot.findings.map((finding) => finding.rule))}; `
          + `raw canary disclosed: ${rootLeaked}`,
      );
      writeFileSync(rootFixture, "# harmless root fixture\n");
      git(rootRepo, ["add", "root-fixture.md"]);
      const coldTree = git(rootRepo, ["write-tree"]).stdout.trim();
      const coldRootSha = git(rootRepo, ["commit-tree", coldTree, "-m", "test: clean parentless push fixture"]).stdout.trim();
      git(rootRepo, ["update-ref", "refs/heads/main", coldRootSha]);
      git(rootRepo, ["reset", "-q", "--hard", coldRootSha]);
      const rootCold = run(rootArgs, {
        gate: rootGate, cwd: rootRepo,
        input: `HEAD ${coldRootSha} refs/heads/new ${rootZeros}\n`,
      });
      check(ARM_TASK3_CASES.parentlessClean, rootCold.code === 0, `exit ${rootCold.code}`);
    }

    // ARMED-LANE COUNT vs THE REGISTRY. Both sides derived; neither hand-written. A lane that claims
    // coverage and that nothing armed fails here, which is the only way "eight lanes" means eight.
    check(
      ARM_LANES_ARMED_CASE,
      armed.size === APPROVED_BOUNDARY_LANES.length,
      `armed ${armed.size}/${APPROVED_BOUNDARY_LANES.length}; not armed: `
        + APPROVED_BOUNDARY_LANES.filter((id) => !armed.has(id)).join(", "),
    );

    // ── 3b. TIER A, planted in the real surface too ────────────────────────────────────────────
    //
    // The canary proves the exact-token tier reaches each lane. It says nothing about the shape
    // rules, and the INVERSION in particular — a repository reference measured against the forge's
    // list of public repositories — has no canary at all. So each of these is planted for real, in
    // a file the working-tree lane enumerates, and required to produce ITS OWN named rule.
    const orgOfAllowlist = Object.keys(JSON.parse(readFileSync(join(repo, "scripts", "boundary-public-repos.json"), "utf8")).orgs)[0];
    // Keep the planted bytes inside this disposable repository. A call is intentionally used so
    // the source scanner does not reconstruct its own negative fixture as a real disclosure.
    const HOME_SHAPE = ["/User", "s/someone-else/notes"].join("");
    for (const fixture of ARM_SHAPE_FIXTURES) {
      const { rule } = fixture;
      const text = fixture.text({ homeShape: HOME_SHAPE, orgOfAllowlist });
      writeFileSync(wtFile, `# notes\n\n${text}\n`);
      const hot = run(["--lane", "L-WT"]);
      check(ARM_SHAPE_CASES[rule],
        hot.code === 1 && hot.findings.some((f) => f.rule === rule),
        `exit ${hot.code}; rules seen: ${JSON.stringify(hot.findings.map((f) => f.rule))}`);
    }
    writeFileSync(wtFile, "# notes\n\nnothing here\n");
    check(ARM_STATIC_CASES.case_the_working_tree_lane_is_clean_again_after_every_shape_plant, run(["--lane", "L-WT"]).code === 0);

    // ── 3c. THE RATCHET, measured on its own semantics ─────────────────────────────────────────
    //
    // The known-exposure ledger is the only thing that lets this gate be switched on over an
    // already-dirty history without lying. Three properties, each of which would otherwise be a
    // claim: an unlisted finding BLOCKS, a listed one is CARRIED, and a listed one STOPS being
    // carried the moment the file changes — because the key is the content digest, so a suppression
    // can never generalise to tomorrow's edit.
    {
      const ledgerPath = join(repo, "scripts", "boundary-known-exposure.json");
      const ledgerWas = readFileSync(ledgerPath, "utf8");
      const body = `# notes\n\nmirrors ${orgOfAllowlist}/a-repository-the-forge-does-not-list nightly\n`;
      writeFileSync(wtFile, body);
      check(ARM_STATIC_CASES.case_ratchet_a_finding_with_no_ledger_entry_blocks, run(["--lane", "L-WT"]).code === 1);

      const key = `${contentKey(body)}:repo-not-public`;
      writeFileSync(ledgerPath, JSON.stringify({
        ...JSON.parse(ledgerWas),
        entries: [{ key, count: 1, why: "arm fixture", remediation: "arm fixture", reviewedAt: new Date().toISOString() }],
      }, null, 2));
      check(ARM_STATIC_CASES.case_ratchet_the_same_finding_with_a_reviewed_entry_is_carried, run(["--lane", "L-WT"]).code === 0);

      writeFileSync(wtFile, `${body}\nand one more line\n`);
      check(ARM_STATIC_CASES.case_ratchet_editing_the_file_makes_the_entry_stop_applying_a_suppre_a5d0fb95,
        run(["--lane", "L-WT"]).code === 1);

      writeFileSync(ledgerPath, ledgerWas);
      writeFileSync(wtFile, "# notes\n\nnothing here\n");
    }

    // ── 4. IT CANNOT FAIL OPEN ─────────────────────────────────────────────────────────────────
    //
    // Every one of these is a REAL run of a REAL copy of the gate against a REAL broken input, and
    // every one must exit 2 — never 0. This is the block the whole design rests on, so it is
    // measured rather than asserted.
    const cfg = (name) => join(repo, "scripts", name);
    const backup = new Map();
    for (const n of [
      "boundary-commitments.json",
      "boundary-public-repos.json",
      "boundary-known-exposure.json",
    ]) backup.set(n, readFileSync(cfg(n), "utf8"));
    const restore = () => { for (const [n, v] of backup) writeFileSync(cfg(n), v); };
    // The outer source-scan fixture intentionally carries reviewed coordinates for several
    // synthetic owners. Live-provider refresh is a different contract: one invocation is scoped to
    // exactly one reviewed owner. Give those tests their own single-owner baseline, then restore the
    // wider source-scan fixture after every run.
    const prepareSingleOwnerLiveBaseline = () => {
      const snapshot = JSON.parse(backup.get("boundary-public-repos.json"));
      snapshot.orgs = { examplearmorg: ["public-arm"] };
      writeFileSync(cfg("boundary-public-repos.json"), `${JSON.stringify(snapshot, null, 2)}\n`);
    };

    const setupFailureObservation = (result, expectedSubject = null) => {
      const verifiedGateFailure = result.code === 2 && result.protocolComplete;
      const refusedUnverifiedFailure = result.code === null && result.observedCode === 2
        && !result.protocolComplete
        && result.protocol === BOUNDARY_CANDIDATE_TIER_A_GATE_EXPECTATION.protocol
        && result.provenance?.verification === "UNVERIFIED_BOOTSTRAP"
        && result.authorityProblem?.startsWith("GATE_CHILD_PROVENANCE_")
        && result.findings.length === 0;
      const diagnosticFindings = verifiedGateFailure ? result.findings : result.observedFindings;
      const exactSetupFailure = diagnosticFindings.some((finding) =>
        finding.rule === "SETUP_FAILED"
          && (expectedSubject === null || finding.subject === expectedSubject));
      return Object.freeze({
        diagnosticFindings,
        ok: (verifiedGateFailure || refusedUnverifiedFailure) && exactSetupFailure,
      });
    };
    const failClosed = (descriptor, prepare, args = ["--lane", "L-WT"], opts = {}, expectedSubject = null) => {
      prepare();
      const r = run(args, opts);
      const observedFailure = setupFailureObservation(r, expectedSubject);
      const leaked = r.out.includes(canary);
      check(
        descriptor,
        observedFailure.ok && !leaked,
        `credited/observed exit ${r.code}/${r.observedCode}; authority ${r.authorityProblem}; subjects `
          + `${JSON.stringify(observedFailure.diagnosticFindings.map((finding) => finding.subject))}\n`
          + `raw canary disclosed: ${leaked}${leaked ? "; output withheld" : ""}`,
      );
      restore();
    };
    const manifestMissingFailClosed = (descriptor, relativePath) => {
      rmSync(join(repo, relativePath));
      const r = run(["--lane", "L-WT"], { candidateTierABootstrap: true });
      const exactBootstrapFailure = r.observedFindings.some((finding) =>
        finding.rule === "SETUP_FAILED"
          && finding.subject === `reviewed control ${relativePath}`
          && finding.detail.startsWith("BOUNDARY_BOOTSTRAP_PATH_MISSING:"));
      check(
        descriptor,
        r.code === null && r.observedCode === 2 && !r.protocolComplete
          && r.protocol === BOUNDARY_CANDIDATE_TIER_A_GATE_EXPECTATION.protocol
          && r.provenance?.verification === "UNVERIFIED_BOOTSTRAP"
          && r.authorityProblem?.startsWith("GATE_CHILD_PROVENANCE_")
          && r.findings.length === 0 && exactBootstrapFailure,
        `credited/observed exit ${r.code}/${r.observedCode}; authority ${r.authorityProblem}; `
          + `observed findings ${canonicalJson(r.observedFindings)}`,
      );
      restore();
    };

    failClosed(ARM_FAIL_CLOSED_CASES.fail_the_commitments_file_is_missing, () => rmSync(cfg("boundary-commitments.json")));
    failClosed(
      ARM_TASK3_CASES.unparsableBaselineRedacted,
      () => writeFileSync(cfg("boundary-commitments.json"), canary),
    );
    failClosed(ARM_FAIL_CLOSED_CASES.fail_the_commitments_file_carries_zero_digests, () => {
      const d = JSON.parse(backup.get("boundary-commitments.json"));
      writeFileSync(cfg("boundary-commitments.json"), JSON.stringify({ ...d, digests: [], count: 0 }));
    });
    failClosed(ARM_FAIL_CLOSED_CASES.fail_the_key_does_not_match_the_committed_digests, () => {
      const d = JSON.parse(backup.get("boundary-commitments.json"));
      writeFileSync(cfg("boundary-commitments.json"), JSON.stringify({ ...d, keyId: "deadbeef" }));
    });
    failClosed(ARM_FAIL_CLOSED_CASES.fail_the_commitments_are_older_than_the_freshness_limit, () => {
      const d = JSON.parse(backup.get("boundary-commitments.json"));
      writeFileSync(cfg("boundary-commitments.json"), JSON.stringify({ ...d, refreshedAt: "2020-01-01T00:00:00.000Z" }));
    });
    failClosed(
      ARM_FAIL_CLOSED_CASES.fail_the_commitments_timestamp_is_beyond_future_skew_tolerance,
      () => writeFileSync(
        cfg("boundary-commitments.json"),
        JSON.stringify(syntheticCommitments(SYNTHETIC_KEY, SYNTHETIC_CANARY, {
          refreshedAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
        })),
      ),
      ["--lane", "L-WT"],
      {},
      "the token commitments.refreshedAt is in the future beyond the clock-skew bound",
    );
    failClosed(ARM_FAIL_CLOSED_CASES.fail_a_digest_is_shorter_than_full_sha_256, () => {
      const d = JSON.parse(backup.get("boundary-commitments.json"));
      d.digests[0] = d.digests[0].slice(0, 8);
      writeFileSync(cfg("boundary-commitments.json"), JSON.stringify(d));
    });
    failClosed(
      ARM_FAIL_CLOSED_CASES.fail_an_authenticated_commitment_set_is_shrunk,
      () => {
        const d = JSON.parse(backup.get("boundary-commitments.json"));
        d.digests = d.digests.filter((digest) => digest === d.canaryDigest);
        d.count = d.digests.length;
        writeFileSync(cfg("boundary-commitments.json"), JSON.stringify(d));
      },
      ["--lane", "L-WT"],
      {},
      "the token commitments authentication failed",
    );
    manifestMissingFailClosed(
      ARM_MANIFEST_MISSING_CASES.manifest_the_public_repository_allowlist_is_missing,
      "scripts/boundary-public-repos.json",
    );
    failClosed(ARM_FAIL_CLOSED_CASES.fail_the_public_repository_allowlist_has_zero_organisations, () => {
      writeFileSync(cfg("boundary-public-repos.json"), JSON.stringify({ refreshedAt: new Date().toISOString(), orgs: {} }));
    });
    {
      const fakeBin = join(work, "visibility-fake-bin");
      mkdirSync(fakeBin, { mode: KEY_DIR_MODE });
      const fakeGh = join(fakeBin, "gh");
      const fakeSource = `#!/usr/bin/env node
const args = process.argv.slice(2);
if (args[0] === "repo" && args[1] === "list") {
  const visibility = args[args.indexOf("--visibility") + 1];
  const names = visibility === "public" ? ["public-arm", "new-public"] : ["arm-private"];
  process.stdout.write(JSON.stringify(names.map((name) => ({
    name, nameWithOwner: args[2] + "/" + name, visibility: visibility.toUpperCase(),
  }))));
  process.exit(0);
}
if (args[0] === "repo" && args[1] === "view") {
  process.stdout.write(JSON.stringify({ nameWithOwner: args[2], visibility: "PRIVATE" }));
  process.exit(0);
}
process.exit(9);
`;
      writeFileSync(fakeGh, fakeSource, { mode: 0o755 });
      chmodSync(fakeGh, 0o755);
      failClosed(
        ARM_FAIL_CLOSED_CASES.fail_live_provider_truth_has_drifted_from_the_committed_public_snapshot,
        prepareSingleOwnerLiveBaseline,
        ["--lane", "L-WT", "--repo-visibility-source", "live"],
        { env: { ...process.env, HOME: armHome, PATH: `${fakeBin}${delimiter}${process.env.PATH ?? ""}` } },
        "the committed PUBLIC-repository snapshot has drifted from live provider truth",
      );
    }
    {
      const fakeBin = join(work, "private-drift-fake-bin");
      mkdirSync(fakeBin, { mode: KEY_DIR_MODE });
      const fakeGh = join(fakeBin, "gh");
      writeFileSync(fakeGh, `#!/usr/bin/env node
const args = process.argv.slice(2);
if (args[0] === "repo" && args[1] === "list") {
  const visibility = args[args.indexOf("--visibility") + 1];
  const names = visibility === "public" ? ["public-arm"] : ["arm-private", "newly-private"];
  process.stdout.write(JSON.stringify(names.map((name) => ({
    name, nameWithOwner: args[2] + "/" + name, visibility: visibility.toUpperCase(),
  }))));
  process.exit(0);
}
if (args[0] === "repo" && args[1] === "view") {
  process.stdout.write(JSON.stringify({ nameWithOwner: args[2], visibility: "PRIVATE" }));
  process.exit(0);
}
process.exit(9);
`, { mode: 0o755 });
      chmodSync(fakeGh, 0o755);
      failClosed(
        ARM_FAIL_CLOSED_CASES.fail_a_new_or_downgraded_live_private_repository_is_absent_from_auth_dbff75d4,
        prepareSingleOwnerLiveBaseline,
        ["--lane", "L-WT", "--repo-visibility-source", "live"],
        { env: { ...process.env, HOME: armHome, PATH: `${fakeBin}${delimiter}${process.env.PATH ?? ""}` } },
        "live PRIVATE inputs differ from the authenticated commitment",
      );
      failClosed(
        ARM_FAIL_CLOSED_CASES.fail_live_visibility_cannot_disable_the_keyed_private_input_comparis_4dba7040,
        prepareSingleOwnerLiveBaseline,
        ["--lane", "L-WT", "--tier", "a", "--repo-visibility-source", "live"],
        { env: { ...process.env, HOME: armHome, PATH: `${fakeBin}${delimiter}${process.env.PATH ?? ""}` } },
        "live visibility was requested with Tier B disabled",
      );
    }
    manifestMissingFailClosed(
      ARM_MANIFEST_MISSING_CASES.manifest_the_known_exposure_ledger_is_missing,
      "scripts/boundary-known-exposure.json",
    );
    failClosed(ARM_FAIL_CLOSED_CASES.fail_a_known_exposure_entry_has_no_remediation, () => {
      writeFileSync(cfg("boundary-known-exposure.json"), JSON.stringify({
        entries: [{ key: "abc:home-path", count: 1, why: "because", reviewedAt: new Date().toISOString() }],
      }));
    });

    // The key itself. HOME is redirected to an empty directory, so `~/.noa-boundary/key` does not
    // exist for the child — the same shape as a fresh machine or an outside contributor.
    const emptyHome = join(work, "empty-home");
    mkdirSync(emptyHome, { recursive: true });
    failClosed(ARM_FAIL_CLOSED_CASES.fail_the_boundary_key_is_missing, () => {}, ["--lane", "L-WT"], { env: { ...process.env, HOME: emptyHome } });

    // Key custody is tested through real child executions of the copied gate. The synthetic key is
    // deliberately non-secret, and the copied commitments' public keyId is changed to match it. That
    // produces a clean positive control first; each negative would therefore return 0 if its custody
    // check disappeared instead of being accidentally rescued by the fingerprint mismatch.
    const keyFixtureHome = join(work, "key-fixture-home");
    const keyFixtureVault = join(work, "key-fixture-vault");
    const keyFixtureDir = join(keyFixtureHome, ".noa-boundary");
    const fixtureKey = Buffer.alloc(32, 0x5a);
    const fixtureEnv = { ...process.env, HOME: keyFixtureHome };

    const prepareKeyFixture = ({
      bytes = fixtureKey,
      keyMode = 0o600,
      keyKind = "regular",
      canaryKind = "regular",
      extraKind = "absent",
      exclusionKind = "absent",
      directoryMode = 0o700,
      directoryKind = "regular",
    } = {}) => {
      rmSync(keyFixtureHome, { recursive: true, force: true });
      rmSync(keyFixtureVault, { recursive: true, force: true });
      mkdirSync(keyFixtureHome, { recursive: true, mode: 0o700 });
      chmodSync(keyFixtureHome, 0o700);

      let actualDirectory = keyFixtureDir;
      if (directoryKind === "symlink") {
        mkdirSync(keyFixtureVault, { mode: directoryMode });
        chmodSync(keyFixtureVault, directoryMode);
        symlinkSync(keyFixtureVault, keyFixtureDir);
        actualDirectory = keyFixtureVault;
      } else {
        mkdirSync(keyFixtureDir, { mode: directoryMode });
        chmodSync(keyFixtureDir, directoryMode);
      }

      const fixtureFile = (name, contents, kind = "regular", mode = KEY_MODE) => {
        if (kind === "absent") return;
        const path = join(actualDirectory, name);
        if (kind === "symlink") {
          const targetName = `${name}-target`;
          const target = join(actualDirectory, targetName);
          writeFileSync(target, contents, { mode });
          chmodSync(target, mode);
          symlinkSync(targetName, path);
        } else if (kind === "hardlink") {
          const target = join(actualDirectory, `${name}-target`);
          writeFileSync(target, contents, { mode });
          chmodSync(target, mode);
          linkSync(target, path);
        } else {
          writeFileSync(path, contents, { mode });
          chmodSync(path, mode);
        }
      };

      fixtureFile("key", bytes, keyKind, keyMode);
      fixtureFile("canary.txt", `${SYNTHETIC_CANARY}\n`, canaryKind);
      fixtureFile("extra-tokens.txt", "synthetic-arm-extra\n", extraKind);
      fixtureFile("exclusions.json", "{}\n", exclusionKind);

      writeFileSync(
        cfg("boundary-commitments.json"),
        `${JSON.stringify(syntheticCommitments(bytes, SYNTHETIC_CANARY), null, 2)}\n`,
      );
    };

    prepareKeyFixture();
    {
      const r = run(["--lane", "L-WT"], { env: fixtureEnv });
      check(
        ARM_STATIC_CASES.case_key_custody_a_regular_32_byte_0600_single_link_key_in_an_owner__d0eea8e7,
        r.code === 0,
        `exit ${r.code}\n${r.out.slice(0, 600)}`,
      );
      restore();
    }
    {
      prepareKeyFixture({ extraKind: "regular" });
      const target = join(keyFixtureDir, "extra-tokens.txt");
      const ready = join(keyFixtureHome, "writer-ready");
      writeFileSync(target, Buffer.alloc(1024 * 1024, 0x61), { mode: KEY_MODE });
      chmodSync(target, KEY_MODE);
      const writer = spawn(process.execPath, ["-e", `
const fs = require("node:fs");
const target = process.argv[1];
const ready = process.argv[2];
const size = 1024 * 1024;
let turn = 0;
fs.writeFileSync(ready, "ready");
process.stdout.write("ready\\n");
while (true) {
  const fd = fs.openSync(target, "r+");
  const bytes = Buffer.alloc(size, turn++ % 2 === 0 ? 0x61 : 0x62);
  fs.writeSync(fd, bytes, 0, bytes.length, 0);
  fs.closeSync(fd);
}
`, target, ready], { stdio: ["ignore", "pipe", "ignore"] });
      await new Promise((resolveReady, rejectReady) => {
        const timeout = setTimeout(() => rejectReady(new Error("race writer did not become ready")), 2_000);
        writer.stdout.once("data", () => { clearTimeout(timeout); resolveReady(); });
        writer.once("error", (error) => { clearTimeout(timeout); rejectReady(error); });
      });
      const raced = run(["--lane", "L-WT"], { env: fixtureEnv });
      writer.kill("SIGKILL");
      check(
        ARM_STATIC_CASES.case_key_custody_an_in_place_writer_is_refused_by_ctime_and_stable_d_0aeb5dae,
        raced.code === 2 && raced.findings.some((finding) =>
          finding.subject === "the opened extra token inputs changed during the stable double-read"
          || finding.subject === "the extra token inputs custody changed during the read"),
        `exit ${raced.code}; subjects ${JSON.stringify(raced.findings.map((finding) => finding.subject))}`,
      );
      restore();
    }
    failClosed(
      ARM_FAIL_CLOSED_CASES.fail_a_31_byte_boundary_key,
      () => prepareKeyFixture({ bytes: Buffer.alloc(31, 0x5a) }),
      ["--lane", "L-WT"],
      { env: fixtureEnv },
      "the boundary key has the wrong length",
    );
    failClosed(
      ARM_FAIL_CLOSED_CASES.fail_a_group_world_readable_boundary_key,
      () => prepareKeyFixture({ keyMode: 0o644 }),
      ["--lane", "L-WT"],
      { env: fixtureEnv },
      "the boundary key permissions are unsafe",
    );
    failClosed(
      ARM_FAIL_CLOSED_CASES.fail_a_symbolic_link_boundary_key,
      () => prepareKeyFixture({ keyKind: "symlink" }),
      ["--lane", "L-WT"],
      { env: fixtureEnv },
      "the boundary key is not a regular non-symlink file",
    );
    failClosed(
      ARM_FAIL_CLOSED_CASES.fail_a_hard_linked_boundary_key,
      () => prepareKeyFixture({ keyKind: "hardlink" }),
      ["--lane", "L-WT"],
      { env: fixtureEnv },
      "the boundary key has multiple hard links",
    );
    failClosed(
      ARM_FAIL_CLOSED_CASES.fail_a_group_world_searchable_boundary_key_directory,
      () => prepareKeyFixture({ directoryMode: 0o755 }),
      ["--lane", "L-WT"],
      { env: fixtureEnv },
      "the boundary key directory permissions are unsafe",
    );
    failClosed(
      ARM_FAIL_CLOSED_CASES.fail_a_symbolic_link_boundary_key_directory,
      () => prepareKeyFixture({ directoryKind: "symlink" }),
      ["--lane", "L-WT"],
      { env: fixtureEnv },
      "the boundary key directory is not a real directory",
    );
    failClosed(
      ARM_FAIL_CLOSED_CASES.fail_a_symbolic_link_boundary_canary,
      () => prepareKeyFixture({ canaryKind: "symlink" }),
      ["--lane", "L-WT"],
      { env: fixtureEnv },
      "the boundary canary is not a regular non-symlink file",
    );
    failClosed(
      ARM_FAIL_CLOSED_CASES.fail_a_missing_dedicated_boundary_canary,
      () => prepareKeyFixture({ canaryKind: "absent" }),
      ["--lane", "L-WT"],
      { env: fixtureEnv },
      "the dedicated boundary canary is missing",
    );
    failClosed(
      ARM_FAIL_CLOSED_CASES.fail_a_hard_linked_boundary_canary,
      () => prepareKeyFixture({ canaryKind: "hardlink" }),
      ["--lane", "L-WT"],
      { env: fixtureEnv },
      "the boundary canary has multiple hard links",
    );
    failClosed(
      ARM_FAIL_CLOSED_CASES.fail_a_symbolic_link_extra_token_input,
      () => prepareKeyFixture({ extraKind: "symlink" }),
      ["--lane", "L-WT"],
      { env: fixtureEnv },
      "the extra token inputs is not a regular non-symlink file",
    );
    failClosed(
      ARM_FAIL_CLOSED_CASES.fail_a_hard_linked_governed_exclusion_policy,
      () => prepareKeyFixture({ exclusionKind: "hardlink" }),
      ["--lane", "L-WT"],
      { env: fixtureEnv },
      "the governed exclusion policy has multiple hard links",
    );
    notes.push("POSIX uid ownership is enforced at runtime; the arm does not change file ownership because that requires elevated privilege on normal runners");

    // The schema-v3 migration receives review metadata only. Exact tokens and their existing
    // inline reasons are copied from the retained owner-only legacy file in memory and must never
    // appear in argv or output. Every case uses a fresh scratch HOME so create-exclusive behaviour
    // is measured rather than simulated.
    {
      const migrationHome = join(work, "migration-home");
      const migrationDir = join(migrationHome, ".noa-boundary");
      const migrationEnv = { ...process.env, HOME: migrationHome };
      const migrationToken = Buffer.from("61726d6d6967726174696f6e636f6c6c6973696f6e", "hex").toString("utf8");
      const migrationReason = Buffer.from("6578616374207075626c6963206465726976656420636f6c6c6973696f6e", "hex").toString("utf8");
      const validLegacy = `${migrationToken}   # ${migrationReason}\n`;
      const reviewSession = Buffer.from("30313962376534372d326663312d376131312d386234322d366561326335633462313139", "hex").toString("utf8");
      const publicArtifactSri = `sha512-${Buffer.alloc(64, 0x2a).toString("base64")}`;
      const reviewedAt = new Date(Date.now() - 60_000).toISOString();
      const expiresAt = new Date(Date.now() + 29 * 86_400_000).toISOString();
      const freshReviewedAt = new Date(Date.parse(reviewedAt) + 1_000).toISOString();
      const freshReviewSession = ["00000000", "0000", "4000", "8000", "000000000011"].join("-");
      const freshPublicArtifact = "arm-public@1.2.4";
      const resetMigrationHome = (legacyText = validLegacy, { existingDestination = false } = {}) => {
        rmSync(migrationHome, { recursive: true, force: true });
        mkdirSync(migrationDir, { recursive: true, mode: KEY_DIR_MODE });
        chmodSync(migrationDir, KEY_DIR_MODE);
        writeFileSync(join(migrationDir, "key"), SYNTHETIC_KEY, { mode: KEY_MODE });
        chmodSync(join(migrationDir, "key"), KEY_MODE);
        writeFileSync(join(migrationDir, "canary.txt"), `${SYNTHETIC_CANARY}\n`, { mode: KEY_MODE });
        chmodSync(join(migrationDir, "canary.txt"), KEY_MODE);
        writeFileSync(join(migrationDir, "exclude-tokens.txt"), legacyText, { mode: KEY_MODE });
        chmodSync(join(migrationDir, "exclude-tokens.txt"), KEY_MODE);
        if (existingDestination) {
          writeFileSync(join(migrationDir, "exclusions.json"), "{}\n", { mode: KEY_MODE });
          chmodSync(join(migrationDir, "exclusions.json"), KEY_MODE);
        }
      };
      const migrationArgs = (overrides = {}, mode = "--migrate-exclusions") => {
        const freshRotation = mode === "--rotate-exclusions";
        const values = {
          reviewer: freshRotation
            ? "Codex synthetic fresh-rotation reviewer, owner-delegated"
            : "Codex synthetic independent reviewer, owner-delegated",
          reviewedAt: freshRotation ? freshReviewedAt : reviewedAt,
          expiresAt,
          reviewSession: freshRotation ? freshReviewSession : reviewSession,
          classification: "PUBLIC_DERIVED_COLLISION",
          publicArtifact: freshRotation ? freshPublicArtifact : "arm-public@1.2.3",
          publicArtifactSri,
          ...overrides,
        };
        return [
          mode,
          "--reviewer", values.reviewer,
          "--reviewed-at", values.reviewedAt,
          "--expires-at", values.expiresAt,
          "--review-session", values.reviewSession,
          "--classification", values.classification,
          "--public-artifact", values.publicArtifact,
          "--public-artifact-sri", values.publicArtifactSri,
        ];
      };
      const migrationFailure = (descriptor, legacyText, overrides, expectedSubject, options = {}) => {
        resetMigrationHome(legacyText, options);
        const r = run(migrationArgs(overrides), { env: migrationEnv });
        check(
          descriptor,
          r.code === 2 && r.findings.some((finding) => finding.rule === "SETUP_FAILED" && finding.subject === expectedSubject)
            && (options.existingDestination || !existsSync(join(migrationDir, "exclusions.json"))),
          `exit ${r.code}; subjects ${JSON.stringify(r.findings.map((finding) => finding.subject))}`,
        );
      };

      migrationFailure(
        ARM_MIGRATION_FAILURE_CASES.migration_a_legacy_token_with_no_existing_inline_reason,
        `${migrationToken}\n`,
        {},
        "legacy exclusion input line 1 has no inline reason",
      );
      migrationFailure(
        ARM_MIGRATION_FAILURE_CASES.migration_a_validity_window_over_30_days,
        validLegacy,
        { expiresAt: new Date(Date.parse(reviewedAt) + 31 * 86_400_000).toISOString() },
        "the exclusion policy is expired or has an invalid window",
      );
      migrationFailure(
        ARM_MIGRATION_FAILURE_CASES.migration_a_future_review_time,
        validLegacy,
        {
          reviewedAt: new Date(Date.now() + 60 * 60_000).toISOString(),
          expiresAt: new Date(Date.now() + 2 * 86_400_000).toISOString(),
        },
        "the exclusion policy review time is in the future",
      );
      migrationFailure(
        ARM_MIGRATION_FAILURE_CASES.migration_an_existing_destination,
        validLegacy,
        {},
        "the governed exclusion policy destination already exists",
        { existingDestination: true },
      );

      resetMigrationHome();
      const legacyBefore = readFileSync(join(migrationDir, "exclude-tokens.txt"));
      const exactMigrationManifest = deriveBoundaryControlManifest(repo);
      const success = run(migrationArgs(), { env: migrationEnv });
      const policyPath = join(migrationDir, "exclusions.json");
      const created = existsSync(policyPath) ? lstatSync(policyPath) : null;
      let createdPolicy = null;
      try { createdPolicy = JSON.parse(readFileSync(policyPath, "utf8")); } catch { /* asserted below */ }
      check(
        ARM_STATIC_CASES.case_exclusion_migration_valid_reviewed_input_creates_one_0600_singl_e5f7cabb,
        success.code === 0 && created?.isFile() && !created.isSymbolicLink()
          && (created.mode & 0o7777) === KEY_MODE && created.nlink === 1
          && createdPolicy?.controlManifestVersion === BOUNDARY_CONTROL_MANIFEST_VERSION
          && createdPolicy.controlManifestVersion === exactMigrationManifest.version
          && canonicalJson(createdPolicy.controlManifestFiles) === canonicalJson(REVIEWED_CONTROL_PATHS)
          && canonicalJson(createdPolicy.controlManifestFiles) === canonicalJson(exactMigrationManifest.paths)
          && createdPolicy.controlManifestDigest === exactMigrationManifest.digest
          && readFileSync(join(migrationDir, "exclude-tokens.txt")).equals(legacyBefore)
          && !success.out.includes(migrationToken) && !success.out.includes(migrationReason)
          && !success.out.includes(SYNTHETIC_KEY.toString("hex")),
        `exit ${success.code}; output bytes ${Buffer.byteLength(success.out)}; destination ${created === null ? "absent" : "present"}`,
      );

      if (success.code === 0 && created !== null) {
        const originalPolicyText = readFileSync(policyPath, "utf8");
        const originalPolicy = JSON.parse(originalPolicyText);
        const authenticatedCommitments = syntheticCommitments(SYNTHETIC_KEY, SYNTHETIC_CANARY, {
          excludedCount: originalPolicy.entries.length,
          exclusionPolicyCommitment: originalPolicy.mac,
        });
        writeFileSync(cfg("boundary-commitments.json"), `${JSON.stringify(authenticatedCommitments, null, 2)}\n`);

        const narrowedManifest = {
          ...originalPolicy,
          controlManifestFiles: originalPolicy.controlManifestFiles.slice(0, -1),
        };
        const { mac: ignoredNarrowedMac, ...narrowedManifestBody } = narrowedManifest;
        narrowedManifest.mac = keyedCanonicalRecord(SYNTHETIC_KEY, "exclusion-policy/v3", narrowedManifestBody);
        writeFileSync(policyPath, `${canonicalJson(narrowedManifest)}\n`, { mode: KEY_MODE });
        const narrowedControl = run(["--lane", "L-WT"], { env: migrationEnv });
        check(
          ARM_STATIC_CASES.case_exclusion_policy_an_authenticated_narrowed_current_control_mani_9a94c19e,
          narrowedControl.code === 2 && narrowedControl.findings.some((finding) =>
            finding.subject === "the exclusion policy reviewed-control manifest is malformed or narrowed"),
          `exit ${narrowedControl.code}; subjects ${JSON.stringify(narrowedControl.findings.map((finding) => finding.subject))}`,
        );

        const wrongManifestVersion = {
          ...originalPolicy,
          controlManifestVersion: BOUNDARY_CONTROL_MANIFEST_VERSION + 1,
        };
        const { mac: ignoredWrongVersionMac, ...wrongManifestVersionBody } = wrongManifestVersion;
        wrongManifestVersion.mac = keyedCanonicalRecord(SYNTHETIC_KEY, "exclusion-policy/v3", wrongManifestVersionBody);
        writeFileSync(policyPath, `${canonicalJson(wrongManifestVersion)}\n`, { mode: KEY_MODE });
        const malformedControlVersion = run(["--lane", "L-WT"], { env: migrationEnv });
        check(
          ARM_STATIC_CASES.case_exclusion_policy_an_authenticated_wrong_current_control_manifes_1cfef9ee,
          malformedControlVersion.code === 2 && malformedControlVersion.findings.some((finding) =>
            finding.subject === "the exclusion policy reviewed-control manifest is malformed or narrowed"),
          `exit ${malformedControlVersion.code}; subjects ${JSON.stringify(malformedControlVersion.findings.map((finding) => finding.subject))}`,
        );

        const macCorrupt = { ...originalPolicy, mac: `${originalPolicy.mac.slice(0, 63)}${originalPolicy.mac.endsWith("0") ? "1" : "0"}` };
        writeFileSync(policyPath, `${canonicalJson(macCorrupt)}\n`, { mode: KEY_MODE });
        const badMac = run(["--lane", "L-WT"], { env: migrationEnv });
        check(
          ARM_STATIC_CASES.case_exclusion_policy_a_corrupt_hmac_is_refused,
          badMac.code === 2 && badMac.findings.some((finding) => finding.subject === "the governed exclusion policy authentication failed"),
          `exit ${badMac.code}; subjects ${JSON.stringify(badMac.findings.map((finding) => finding.subject))}`,
        );

        const metadataChanged = { ...originalPolicy, reviewer: `${originalPolicy.reviewer} changed` };
        writeFileSync(policyPath, `${canonicalJson(metadataChanged)}\n`, { mode: KEY_MODE });
        const badMetadata = run(["--lane", "L-WT"], { env: migrationEnv });
        check(
          ARM_STATIC_CASES.case_exclusion_policy_hmac_binds_document_level_review_metadata,
          badMetadata.code === 2 && badMetadata.findings.some((finding) => finding.subject === "the governed exclusion policy authentication failed"),
          `exit ${badMetadata.code}; subjects ${JSON.stringify(badMetadata.findings.map((finding) => finding.subject))}`,
        );

        const otherToken = Buffer.from("61726d6d6967726174696f6e7369626c696e67", "hex").toString("utf8");
        const tokenChanged = { ...originalPolicy, entries: [{ ...originalPolicy.entries[0], token: otherToken }] };
        const { mac: ignoredMac, ...tokenChangedBody } = tokenChanged;
        tokenChanged.mac = keyedCanonicalRecord(SYNTHETIC_KEY, "exclusion-policy/v3", tokenChangedBody);
        writeFileSync(policyPath, `${canonicalJson(tokenChanged)}\n`, { mode: KEY_MODE });
        const badToken = run(["--lane", "L-WT"], { env: migrationEnv });
        check(
          ARM_STATIC_CASES.case_exclusion_policy_an_authenticated_token_set_mismatch_with_retai_4a2d1ccb,
          badToken.code === 2 && badToken.findings.some((finding) => finding.subject === "the governed exclusion migration changes legacy semantics"),
          `exit ${badToken.code}; subjects ${JSON.stringify(badToken.findings.map((finding) => finding.subject))}`,
        );

        writeFileSync(policyPath, `${JSON.stringify(originalPolicy, null, 2)}\n`, { mode: KEY_MODE });
        const nonCanonical = run(["--lane", "L-WT"], { env: migrationEnv });
        check(
          ARM_STATIC_CASES.case_exclusion_policy_noncanonical_whitespace_and_key_formatting_are_2d34f901,
          nonCanonical.code === 2 && nonCanonical.findings.some((finding) => finding.subject === "the governed exclusion policy is not in exact canonical JSON form"),
          `exit ${nonCanonical.code}; subjects ${JSON.stringify(nonCanonical.findings.map((finding) => finding.subject))}`,
        );

        writeFileSync(policyPath, originalPolicyText.replace("{", `{"schemaVersion":${originalPolicy.schemaVersion},`), { mode: KEY_MODE });
        const duplicateKey = run(["--lane", "L-WT"], { env: migrationEnv });
        check(
          ARM_STATIC_CASES.case_exclusion_policy_duplicate_json_keys_are_refused_even_when_the__f7fceecd,
          duplicateKey.code === 2 && duplicateKey.findings.some((finding) => finding.subject === "the governed exclusion policy is not in exact canonical JSON form"),
          `exit ${duplicateKey.code}; subjects ${JSON.stringify(duplicateKey.findings.map((finding) => finding.subject))}`,
        );

        writeFileSync(policyPath, originalPolicyText, { mode: KEY_MODE });
        const reviewedControl = join(repo, "scripts", "pre-push-gate.mjs");
        const reviewedControlBefore = readFileSync(reviewedControl);
        writeFileSync(reviewedControl, Buffer.concat([reviewedControlBefore, Buffer.from("\n// synthetic control drift\n")]));
        const staleControl = run(["--lane", "L-WT"], { env: migrationEnv });
        check(
          ARM_STATIC_CASES.case_exclusion_policy_a_changed_reviewed_control_manifest_is_refused,
          staleControl.code === 2 && staleControl.findings.some((finding) => finding.subject === "the reviewed exclusion control manifest is stale"),
          `exit ${staleControl.code}; subjects ${JSON.stringify(staleControl.findings.map((finding) => finding.subject))}`,
        );
        writeFileSync(reviewedControl, reviewedControlBefore);

        writeFileSync(policyPath, originalPolicyText, { mode: KEY_MODE });
        writeFileSync(join(migrationDir, "exclude-tokens.txt"), `${validLegacy}# byte-drift\n`, { mode: KEY_MODE });
        const byteDrift = run(["--lane", "L-WT"], { env: migrationEnv });
        check(
          ARM_STATIC_CASES.case_exclusion_policy_retained_legacy_byte_drift_is_refused,
          byteDrift.code === 2 && byteDrift.findings.some((finding) => finding.subject === "the retained legacy exclusion bytes changed after review"),
          `exit ${byteDrift.code}; subjects ${JSON.stringify(byteDrift.findings.map((finding) => finding.subject))}`,
        );

        writeFileSync(join(migrationDir, "exclude-tokens.txt"), validLegacy, { mode: KEY_MODE });
        const previousBody = {
          schemaVersion: 2,
          keyId: originalPolicy.keyId,
          reviewer: originalPolicy.reviewer,
          reviewedAt: originalPolicy.reviewedAt,
          expiresAt: originalPolicy.expiresAt,
          reviewSession: originalPolicy.reviewSession,
          repositoryHead: git(repo, ["rev-parse", "HEAD"]).stdout.trim(),
          classification: originalPolicy.classification,
          publicArtifact: originalPolicy.publicArtifact,
          publicArtifactSRI: originalPolicy.publicArtifactSRI,
          legacyByteLength: originalPolicy.legacyByteLength,
          legacySha256: originalPolicy.legacySha256,
          entries: originalPolicy.entries.map((entry) => ({ token: entry.token, reason: entry.reason })),
        };
        const previousDoc = { ...previousBody, mac: keyedRecord(SYNTHETIC_KEY, "exclusion-policy/v2", previousBody) };
        const previousText = `${JSON.stringify(previousDoc, null, 2)}\n`;
        const predecessorDigest = createHash("sha256").update(previousText).digest("hex");
        const predecessorPath = join(migrationDir, `exclusions.superseded-v2-${predecessorDigest}.json`);
        const previousControlPaths = [...PREVIOUS_REVIEWED_CONTROL_PATHS];
        const { mac: ignoredIntermediateMac, ...intermediateBodyBase } = originalPolicy;
        const intermediateBody = {
          ...intermediateBodyBase,
          controlManifestVersion: 1,
          controlManifestFiles: previousControlPaths,
          controlManifestDigest: "c".repeat(64),
        };
        const intermediateDoc = {
          ...intermediateBody,
          mac: keyedCanonicalRecord(SYNTHETIC_KEY, "exclusion-policy/v3", intermediateBody),
        };
        const intermediateText = `${canonicalJson(intermediateDoc)}\n`;
        const intermediateDigest = createHash("sha256").update(intermediateText).digest("hex");
        const freshPredecessorPath = join(
          migrationDir,
          `exclusions.superseded-v3-${intermediateDigest}.json`,
        );

        check(
          ARM_STATIC_CASES.case_exclusion_recovery_registry_the_immutable_historical_stage_rema_e5705291,
          BOUNDARY_CONTROL_MANIFEST_VERSION !== 1
            && previousControlPaths.length === 7
            && canonicalJson(previousControlPaths) === canonicalJson(PREVIOUS_REVIEWED_CONTROL_PATHS)
            && intermediateDoc.controlManifestVersion === 1
            && canonicalJson(intermediateDoc.controlManifestFiles) === canonicalJson(PREVIOUS_REVIEWED_CONTROL_PATHS),
          `current v${BOUNDARY_CONTROL_MANIFEST_VERSION}; historical paths ${previousControlPaths.length}`,
        );

        resetMigrationHome();
        writeFileSync(policyPath, intermediateText, { mode: KEY_MODE });
        chmodSync(policyPath, KEY_MODE);
        writeFileSync(predecessorPath, previousText, { mode: KEY_MODE });
        chmodSync(predecessorPath, KEY_MODE);
        const freshBeforeRecovery = run(migrationArgs({}, "--rotate-exclusions"), { env: migrationEnv });
        check(
          ARM_STATIC_CASES.case_exclusion_recovery_ordering_fresh_rotation_refuses_unfinished_s_090b31db,
          freshBeforeRecovery.code === 2
            && freshBeforeRecovery.findings.some((finding) => finding.subject
              === "fresh exclusion rotation encountered unfinished schema-v2 recovery state")
            && readFileSync(policyPath, "utf8") === intermediateText
            && readFileSync(predecessorPath, "utf8") === previousText,
          `exit ${freshBeforeRecovery.code}; subjects ${JSON.stringify(freshBeforeRecovery.findings.map((finding) => finding.subject))}`,
        );
        const recovery = run(["--recover-exclusion-rotation"], { env: migrationEnv });
        const recoveryReceiptPath = join(
          migrationDir,
          `exclusion-policy-rotation-v2-${predecessorDigest}-to-v3-${intermediateDigest}.json`,
        );
        const recoveryReceiptText = existsSync(recoveryReceiptPath)
          ? readFileSync(recoveryReceiptPath, "utf8") : "";
        let recoveryReceiptDoc = null;
        try { recoveryReceiptDoc = JSON.parse(recoveryReceiptText); } catch { /* asserted below */ }
        check(
          ARM_STATIC_CASES.case_exclusion_recovery_ordering_recovery_only_preserves_exact_histo_82404d7d,
          recovery.code === 0 && recoveryReceiptDoc !== null
            && recoveryReceiptDoc.body.predecessor.sha256 === predecessorDigest
            && recoveryReceiptDoc.body.observedActive.sha256 === intermediateDigest
            && recoveryReceiptDoc.body.successor.sha256 === intermediateDigest
            && readFileSync(policyPath, "utf8") === intermediateText
            && !existsSync(predecessorPath)
            && !recovery.out.includes(migrationToken) && !recovery.out.includes(migrationReason),
          `exit ${recovery.code}; receipt ${recoveryReceiptDoc === null ? "absent" : "present"}; raw ${existsSync(predecessorPath)}`,
        );

        const rotation = run(migrationArgs({}, "--rotate-exclusions"), { env: migrationEnv });
        const rotatedText = existsSync(policyPath) ? readFileSync(policyPath, "utf8") : "";
        let rotatedCanonical = false;
        try { rotatedCanonical = rotatedText === `${canonicalJson(JSON.parse(rotatedText))}\n`; } catch { /* checked below */ }
        const successorDigest = createHash("sha256").update(rotatedText).digest("hex");
        const rotatedDoc = JSON.parse(rotatedText);
        const receiptIntentDocument = (body) => {
          const intentBody = {
            schemaVersion: 2,
            event: "EXCLUSION_POLICY_ROTATION_INTENT",
            predecessor: body.predecessor,
            observedActive: body.observedActive,
            successor: body.successor,
            legacy: body.legacy,
            entryCount: body.entryCount,
            keyId: body.keyId,
            durabilityProfile: body.durabilityProfile,
          };
          return {
            body: intentBody,
            intentMac: keyedCanonicalRecord(SYNTHETIC_KEY, "exclusion-policy-rotation-intent/v2", intentBody),
          };
        };
        const receiptIntentDigest = (body) => createHash("sha256")
          .update(`${canonicalJson(receiptIntentDocument(body))}\n`, "utf8")
          .digest("hex");
        const receiptPath = join(
          migrationDir,
          `exclusion-policy-rotation-v3-${intermediateDigest}-to-v3-${successorDigest}.json`,
        );
        const receiptText = existsSync(receiptPath) ? readFileSync(receiptPath, "utf8") : "";
        let receiptValid = false;
        let receiptDoc = null;
        try {
          receiptDoc = JSON.parse(receiptText);
          receiptValid = receiptText === `${canonicalJson(receiptDoc)}\n`
            && receiptDoc.body.schemaVersion === 2
            && receiptDoc.body.event === "EXCLUSION_POLICY_ROTATED"
            && receiptDoc.body.predecessor.byteLength === Buffer.byteLength(intermediateText)
            && receiptDoc.body.predecessor.sha256 === intermediateDigest
            && receiptDoc.body.predecessor.policyMac === intermediateDoc.mac
            && receiptDoc.body.observedActive.byteLength === Buffer.byteLength(intermediateText)
            && receiptDoc.body.observedActive.sha256 === intermediateDigest
            && receiptDoc.body.observedActive.policyMac === intermediateDoc.mac
            && receiptDoc.body.successor.byteLength === Buffer.byteLength(rotatedText)
            && receiptDoc.body.successor.sha256 === successorDigest
            && receiptDoc.body.successor.policyMac === rotatedDoc.mac
            && receiptDoc.body.legacy.byteLength === legacyBefore.length
            && receiptDoc.body.legacy.sha256 === createHash("sha256").update(legacyBefore).digest("hex")
            && receiptDoc.body.durabilityProfile === "NODE_FSYNC_PROCESS_RESTART_V1"
            && receiptDoc.body.intentSha256 === receiptIntentDigest(receiptDoc.body)
            && receiptDoc.receiptMac === keyedCanonicalRecord(
              SYNTHETIC_KEY,
              "exclusion-policy-rotation-receipt/v2",
              receiptDoc.body,
            );
        } catch { /* asserted below */ }
        const receiptStat = existsSync(receiptPath) ? lstatSync(receiptPath) : null;
        check(
          ARM_STATIC_CASES.case_exclusion_rotation_a_separate_fresh_transaction_binds_expanded__5cdbcff7,
          rotation.code === 0 && !existsSync(freshPredecessorPath) && rotatedCanonical && receiptValid
            && receiptStat?.isFile() && !receiptStat.isSymbolicLink()
            && (receiptStat.mode & 0o7777) === KEY_MODE && receiptStat.nlink === 1
            && existsSync(recoveryReceiptPath) && recoveryReceiptPath !== receiptPath
            && recoveryReceiptText !== receiptText
            && rotatedDoc.controlManifestVersion === BOUNDARY_CONTROL_MANIFEST_VERSION
            && canonicalJson(rotatedDoc.controlManifestFiles) === canonicalJson(REVIEWED_CONTROL_PATHS)
            && rotatedDoc.reviewedAt === freshReviewedAt
            && rotatedDoc.reviewSession === freshReviewSession
            && intermediateDoc.reviewedAt === originalPolicy.reviewedAt
            && rotatedDoc.reviewedAt !== intermediateDoc.reviewedAt
            && readFileSync(join(migrationDir, "exclude-tokens.txt")).equals(legacyBefore)
            && !rotation.out.includes(migrationToken) && !rotation.out.includes(migrationReason)
            && !rotation.out.includes(SYNTHETIC_KEY.toString("hex")),
          `exit ${rotation.code}; predecessor ${existsSync(freshPredecessorPath) ? "present" : "absent"}; receipt ${receiptStat === null ? "absent" : "present"}; ` +
            `valid ${receiptValid}; subjects ${JSON.stringify(rotation.findings.map((finding) => finding.subject))}; output bytes ${Buffer.byteLength(rotation.out)}`,
        );

        if (rotation.code === 0 && receiptDoc !== null) {
          // Replant only the synthetic predecessor, then corrupt the existing create-exclusive
          // receipt. Rotation must stop before unlinking it and must not echo its reviewed value.
          writeFileSync(freshPredecessorPath, intermediateText, { mode: KEY_MODE });
          chmodSync(freshPredecessorPath, KEY_MODE);
          const corruptReceipt = {
            ...receiptDoc,
            receiptMac: `${receiptDoc.receiptMac.slice(0, 63)}${receiptDoc.receiptMac.endsWith("0") ? "1" : "0"}`,
          };
          writeFileSync(receiptPath, `${canonicalJson(corruptReceipt)}\n`, { mode: KEY_MODE });
          chmodSync(receiptPath, KEY_MODE);
          const corruptReceiptRun = run(migrationArgs({}, "--rotate-exclusions"), { env: migrationEnv });
          check(
            ARM_STATIC_CASES.case_exclusion_rotation_a_corrupt_receipt_hmac_is_refused_before_raw_051ac9fa,
            corruptReceiptRun.code === 2 && existsSync(freshPredecessorPath)
              && readFileSync(freshPredecessorPath, "utf8") === intermediateText
              && corruptReceiptRun.findings.some((finding) => finding.subject === "the exclusion rotation receipt authentication failed")
              && !corruptReceiptRun.out.includes(migrationToken) && !corruptReceiptRun.out.includes(migrationReason),
            `exit ${corruptReceiptRun.code}; predecessor ${existsSync(freshPredecessorPath) ? "present" : "absent"}; ` +
              `subjects ${JSON.stringify(corruptReceiptRun.findings.map((finding) => finding.subject))}`,
          );

          const mismatchedBody = {
            ...receiptDoc.body,
            successor: { ...receiptDoc.body.successor, byteLength: receiptDoc.body.successor.byteLength + 1 },
          };
          mismatchedBody.intentSha256 = receiptIntentDigest(mismatchedBody);
          const mismatchedReceipt = {
            body: mismatchedBody,
            receiptMac: keyedCanonicalRecord(SYNTHETIC_KEY, "exclusion-policy-rotation-receipt/v2", mismatchedBody),
          };
          writeFileSync(receiptPath, `${canonicalJson(mismatchedReceipt)}\n`, { mode: KEY_MODE });
          chmodSync(receiptPath, KEY_MODE);
          const mismatchRun = run(migrationArgs({}, "--rotate-exclusions"), { env: migrationEnv });
          check(
            ARM_STATIC_CASES.case_exclusion_rotation_an_authenticated_receipt_to_successor_mismat_c785dfbb,
            mismatchRun.code === 2 && existsSync(freshPredecessorPath)
              && mismatchRun.findings.some((finding) => finding.subject === "the exclusion rotation receipt does not bind the exact current evidence")
              && !mismatchRun.out.includes(migrationToken) && !mismatchRun.out.includes(migrationReason),
            `exit ${mismatchRun.code}; predecessor ${existsSync(freshPredecessorPath) ? "present" : "absent"}; ` +
              `subjects ${JSON.stringify(mismatchRun.findings.map((finding) => finding.subject))}`,
          );

          // The authenticated-but-mismatched receipt test deliberately leaves an incompatible
          // forward intent. Do not silently delete that evidence. Rebuild the exact completed
          // transaction state to measure idempotent receipt-based recovery independently.
          resetMigrationHome();
          writeFileSync(policyPath, rotatedText, { mode: KEY_MODE });
          chmodSync(policyPath, KEY_MODE);
          writeFileSync(freshPredecessorPath, intermediateText, { mode: KEY_MODE });
          chmodSync(freshPredecessorPath, KEY_MODE);
          writeFileSync(receiptPath, receiptText, { mode: KEY_MODE });
          chmodSync(receiptPath, KEY_MODE);
          const resumed = run(migrationArgs({}, "--rotate-exclusions"), { env: migrationEnv });
          check(
            ARM_STATIC_CASES.case_exclusion_rotation_exact_valid_receipt_resumes_cleanup_idempote_aad9ac51,
            resumed.code === 0 && !existsSync(freshPredecessorPath)
              && readFileSync(receiptPath, "utf8") === receiptText
              && !resumed.out.includes(migrationToken) && !resumed.out.includes(migrationReason)
              && !resumed.out.includes(SYNTHETIC_KEY.toString("hex")),
            `exit ${resumed.code}; predecessor ${existsSync(freshPredecessorPath) ? "present" : "absent"}; ` +
              `subjects ${JSON.stringify(resumed.findings.map((finding) => finding.subject))}`,
          );

          const legacyReceiptBody = {
            schemaVersion: 1,
            event: receiptDoc.body.event,
            recordedAt: receiptDoc.body.recordedAt,
            verifiedAt: receiptDoc.body.verifiedAt,
            predecessor: receiptDoc.body.predecessor,
            successor: receiptDoc.body.successor,
            legacy: receiptDoc.body.legacy,
            entryCount: receiptDoc.body.entryCount,
            keyId: receiptDoc.body.keyId,
          };
          const legacyReceiptDoc = {
            body: legacyReceiptBody,
            receiptMac: keyedCanonicalRecord(
              SYNTHETIC_KEY,
              "exclusion-policy-rotation-receipt/v1",
              legacyReceiptBody,
            ),
          };
          const legacyReceiptText = `${canonicalJson(legacyReceiptDoc)}\n`;
          resetMigrationHome();
          writeFileSync(policyPath, rotatedText, { mode: KEY_MODE });
          chmodSync(policyPath, KEY_MODE);
          writeFileSync(receiptPath, legacyReceiptText, { mode: KEY_MODE });
          chmodSync(receiptPath, KEY_MODE);
          const legacyReceiptRecovery = run(migrationArgs({}, "--rotate-exclusions"), { env: migrationEnv });
          check(
            ARM_STATIC_CASES.case_exclusion_rotation_compatibility_authenticated_receipt_v1_remai_b5daeef9,
            legacyReceiptRecovery.code === 0 && !existsSync(freshPredecessorPath)
              && readFileSync(receiptPath, "utf8") === legacyReceiptText
              && readFileSync(policyPath, "utf8") === rotatedText
              && !legacyReceiptRecovery.out.includes(migrationToken)
              && !legacyReceiptRecovery.out.includes(migrationReason),
            `exit ${legacyReceiptRecovery.code}; predecessor ${existsSync(freshPredecessorPath) ? "present" : "absent"}; ` +
              `subjects ${JSON.stringify(legacyReceiptRecovery.findings.map((finding) => finding.subject))}`,
          );

          resetMigrationHome();
          writeFileSync(policyPath, intermediateText, { mode: KEY_MODE });
          chmodSync(policyPath, KEY_MODE);
          writeFileSync(predecessorPath, previousText, { mode: KEY_MODE });
          chmodSync(predecessorPath, KEY_MODE);
          writeFileSync(receiptPath, legacyReceiptText, { mode: KEY_MODE });
          chmodSync(receiptPath, KEY_MODE);
          const legacyGapRun = run(migrationArgs({}, "--rotate-exclusions"), { env: migrationEnv });
          const retainedIntentName = readdirSync(migrationDir)
            .find((name) => name.startsWith("exclusion-policy-rotation-intent-"));
          const retainedIntentPath = retainedIntentName === undefined ? null : join(migrationDir, retainedIntentName);
          const deletingAfterLegacyGap = readdirSync(migrationDir)
            .filter((name) => name.startsWith("exclusions.deleting-"));
          check(
            ARM_STATIC_CASES.case_exclusion_rotation_compatibility_a_receipt_v1_cannot_bypass_man_96617897,
            legacyGapRun.code === 2
              && legacyGapRun.findings.some((finding) => finding.subject
                === "fresh exclusion rotation encountered unfinished schema-v2 recovery state")
              && existsSync(predecessorPath) && readFileSync(predecessorPath, "utf8") === previousText
              && retainedIntentPath === null
              && deletingAfterLegacyGap.length === 0
              && readFileSync(receiptPath, "utf8") === legacyReceiptText
              && !legacyGapRun.out.includes(migrationToken) && !legacyGapRun.out.includes(migrationReason),
            `exit ${legacyGapRun.code}; raw ${existsSync(predecessorPath)}; intent ${retainedIntentName ?? "absent"}; ` +
              `deleting ${deletingAfterLegacyGap.length}; subjects ${JSON.stringify(legacyGapRun.findings.map((finding) => finding.subject))}`,
          );

          resetMigrationHome();
          writeFileSync(policyPath, intermediateText, { mode: KEY_MODE });
          chmodSync(policyPath, KEY_MODE);
          writeFileSync(predecessorPath, previousText, { mode: KEY_MODE });
          chmodSync(predecessorPath, KEY_MODE);
          const bridgedRecovery = run(["--recover-exclusion-rotation"], { env: migrationEnv });
          const bridged = run(migrationArgs({}, "--rotate-exclusions"), { env: migrationEnv });
          const bridgedReceiptText = existsSync(receiptPath) ? readFileSync(receiptPath, "utf8") : "";
          let bridgedReceipt = null;
          try { bridgedReceipt = JSON.parse(bridgedReceiptText); } catch { /* asserted below */ }
          check(
            ARM_STATIC_CASES.case_exclusion_rotation_evidence_recovery_and_fresh_rotation_retain__aaa013a7,
            bridgedRecovery.code === 0 && bridged.code === 0 && bridgedReceipt !== null
              && bridgedReceipt.body.schemaVersion === 2
              && bridgedReceipt.body.predecessor.sha256 === intermediateDigest
              && bridgedReceipt.body.observedActive.sha256 === intermediateDigest
              && bridgedReceipt.body.observedActive.policyMac === intermediateDoc.mac
              && bridgedReceipt.body.successor.sha256 === successorDigest
              && bridgedReceipt.body.intentSha256 === receiptIntentDigest(bridgedReceipt.body)
              && existsSync(recoveryReceiptPath) && recoveryReceiptPath !== receiptPath
              && readFileSync(policyPath, "utf8") === rotatedText
              && !existsSync(predecessorPath)
              && !bridged.out.includes(migrationToken) && !bridged.out.includes(migrationReason),
            `recovery ${bridgedRecovery.code}; fresh ${bridged.code}; receipt ${bridgedReceipt === null ? "absent" : `v${bridgedReceipt.body.schemaVersion}`}; ` +
              `subjects ${JSON.stringify(bridged.findings.map((finding) => finding.subject))}`,
          );

          const seedPreviousPolicy = () => {
            resetMigrationHome();
            writeFileSync(policyPath, intermediateText, { mode: KEY_MODE });
            chmodSync(policyPath, KEY_MODE);
            writeFileSync(predecessorPath, previousText, { mode: KEY_MODE });
            chmodSync(predecessorPath, KEY_MODE);
            const recoveredHistorical = run(["--recover-exclusion-rotation"], { env: migrationEnv });
            return recoveredHistorical.code === 0
              && readFileSync(policyPath, "utf8") === intermediateText
              && !existsSync(predecessorPath)
              && existsSync(recoveryReceiptPath);
          };
          const transactionResidue = () => readdirSync(migrationDir).filter((name) =>
            name === "exclusion-policy-rotation.lock"
              || name === ".noa-boundary-create-v1"
              || name.startsWith("exclusion-policy-rotation-lock-claim-")
              || name.startsWith("exclusion-policy-rotation-intent-")
              || name.startsWith("exclusions.superseded-")
              || name.startsWith("exclusions.pending-successor-")
              || name.startsWith("exclusions.deleting-")
              || name.startsWith(".exclusion-policy-delete-"));
          const manualTargetPathFor = (kind, residueNames) => {
            if (kind === "lock") return join(migrationDir, "exclusion-policy-rotation.lock");
            if (kind === "receipt") return receiptPath;
            if (kind === "intent") {
              const name = residueNames.find((candidate) =>
                candidate.startsWith("exclusion-policy-rotation-intent-"));
              return name === undefined ? null : join(migrationDir, name);
            }
            return null;
          };
          for (const point of ARM_ROTATION_CRASH_POINTS) {
            seedPreviousPolicy();
            const crashed = run(migrationArgs({}, "--rotate-exclusions"), {
              env: {
                ...migrationEnv,
                NOA_BOUNDARY_ROTATION_TEST_MODE: "1",
                NOA_BOUNDARY_ROTATION_CRASH_AFTER: point,
              },
            });
            const recovered = run(migrationArgs({}, "--rotate-exclusions"), { env: migrationEnv });
            const finalText = existsSync(policyPath) ? readFileSync(policyPath, "utf8") : "";
            const finalDigest = createHash("sha256").update(finalText).digest("hex");
            const pointReceipt = join(
              migrationDir,
              `exclusion-policy-rotation-v3-${intermediateDigest}-to-v3-${finalDigest}.json`,
            );
            check(
              ARM_ROTATION_CRASH_CASES[point],
              crashed.code === null && recovered.code === 0 && transactionResidue().length === 0
                && existsSync(pointReceipt) && readFileSync(policyPath, "utf8") === rotatedText
                && !recovered.out.includes(migrationToken) && !recovered.out.includes(migrationReason),
              `crash exit ${crashed.code}; recovery exit ${recovered.code}; residue ${transactionResidue().length}; ` +
                `subjects ${JSON.stringify(recovered.findings.map((finding) => finding.subject))}`,
            );
          }

          for (const fault of ARM_ROTATION_CUSTODY_FAULTS) {
            seedPreviousPolicy();
            const faulted = run(migrationArgs({}, "--rotate-exclusions"), {
              env: {
                ...migrationEnv,
                NOA_BOUNDARY_ROTATION_TEST_MODE: "1",
                NOA_BOUNDARY_CUSTODY_FAIL_AT: fault.point,
                NOA_BOUNDARY_CUSTODY_FAIL_CODE: fault.code,
              },
            });
            const residueAfterFault = transactionResidue();
            const manualTargetPath = fault.manualTargetKind === undefined
              ? null
              : manualTargetPathFor(fault.manualTargetKind, residueAfterFault);
            const manualTargetBefore = manualTargetPath === null ? null : readFileSync(manualTargetPath);
            const policyBeforeRecovery = readFileSync(policyPath);
            const recovered = run(migrationArgs({}, "--rotate-exclusions"), { env: migrationEnv });
            const finalText = existsSync(policyPath) ? readFileSync(policyPath, "utf8") : "";
            const finalDigest = createHash("sha256").update(finalText).digest("hex");
            const pointReceipt = join(
              migrationDir,
              `exclusion-policy-rotation-v3-${intermediateDigest}-to-v3-${finalDigest}.json`,
            );
            const manualRecovery = fault.manualRecoverySubject !== undefined;
            const manualTargetRetained = manualTargetPath !== null && manualTargetBefore !== null
              && existsSync(manualTargetPath) && readFileSync(manualTargetPath).equals(manualTargetBefore)
              && readFileSync(policyPath).equals(policyBeforeRecovery);
            const recoveryMatches = manualRecovery
              ? recovered.code === 2
                && recovered.findings.some((finding) => finding.subject === fault.manualRecoverySubject)
                && manualTargetRetained
              : recovered.code === 0 && transactionResidue().length === 0
                && existsSync(pointReceipt) && readFileSync(policyPath, "utf8") === rotatedText;
            check(
              ARM_ROTATION_CUSTODY_CASES[fault.point],
              faulted.code === 2
                && faulted.findings.some((finding) => finding.subject === fault.expectedSubject)
                && residueAfterFault.length > 0
                && recoveryMatches
                && !faulted.out.includes(migrationToken) && !faulted.out.includes(migrationReason)
                && !recovered.out.includes(migrationToken) && !recovered.out.includes(migrationReason),
              `fault exit ${faulted.code}; recovery exit ${recovered.code}; ` +
                `fault residue ${JSON.stringify(residueAfterFault)}; terminal residue ${transactionResidue().length}; ` +
                `target retained ${manualTargetRetained}; fault/recovery subjects ` +
                `${JSON.stringify([
                  faulted.findings.map((finding) => finding.subject),
                  recovered.findings.map((finding) => finding.subject),
                ])}`,
            );
          }

          const stagedFinalsCanonical = () => readdirSync(migrationDir)
            .filter((name) => name === "exclusion-policy-rotation.lock"
              || name.startsWith("exclusion-policy-rotation-intent-")
              || name.startsWith("exclusion-policy-rotation-v"))
            .every((name) => {
              try {
                const text = readFileSync(join(migrationDir, name), "utf8");
                return text.length > 0 && text === `${canonicalJson(JSON.parse(text))}\n`;
              } catch { return false; }
            });
          for (const crashCase of ARM_ROTATION_DIRECT_FINAL_CRASHES) {
            seedPreviousPolicy();
            const crashed = run(migrationArgs({}, "--rotate-exclusions"), {
              env: {
                ...migrationEnv,
                NOA_BOUNDARY_ROTATION_TEST_MODE: "1",
                NOA_BOUNDARY_CUSTODY_CRASH_AFTER: crashCase.point,
              },
            });
            const crashFinalsCanonical = stagedFinalsCanonical();
            const crashResidue = transactionResidue();
            const manualTargetPath = crashCase.manualTargetKind === undefined
              ? null
              : manualTargetPathFor(crashCase.manualTargetKind, crashResidue);
            const manualTargetBefore = manualTargetPath === null ? null : readFileSync(manualTargetPath);
            const policyBeforeRecovery = readFileSync(policyPath);
            const recovered = run(migrationArgs({}, "--rotate-exclusions"), { env: migrationEnv });
            const manualRecovery = crashCase.manualRecoverySubject !== undefined;
            const manualTargetRetained = manualTargetPath !== null && manualTargetBefore !== null
              && existsSync(manualTargetPath) && readFileSync(manualTargetPath).equals(manualTargetBefore)
              && readFileSync(policyPath).equals(policyBeforeRecovery);
            const recoveryMatches = manualRecovery
              ? !crashFinalsCanonical && recovered.code === 2
                && recovered.findings.some((finding) => finding.subject === crashCase.manualRecoverySubject)
                && manualTargetRetained
              : crashFinalsCanonical && recovered.code === 0 && transactionResidue().length === 0
                && readFileSync(policyPath, "utf8") === rotatedText;
            check(
              ARM_ROTATION_DIRECT_FINAL_CASES[crashCase.point],
              crashed.code === null && recoveryMatches,
              `crash exit ${crashed.code}; canonical finals ${crashFinalsCanonical}; recovery ${recovered.code}; `
                + `crash/terminal residue ${JSON.stringify(crashResidue)}/${JSON.stringify(transactionResidue())}; `
                + `target retained ${manualTargetRetained}; subjects `
                + `${JSON.stringify(recovered.findings.map((finding) => finding.subject))}`,
            );
          }

          seedPreviousPolicy();
          const pausedInvocation = spawnAuthorizedArm(migrationArgs({}, "--rotate-exclusions"), {
            env: {
              ...migrationEnv,
              NOA_BOUNDARY_ROTATION_TEST_MODE: "1",
              NOA_BOUNDARY_ROTATION_PAUSE_AT: "lock-acquired",
            },
          });
          const paused = pausedInvocation.child;
          const pausedClose = waitForArmChildClose(paused, { timeoutMs: 30_000 });
          const lockPath = join(migrationDir, "exclusion-policy-rotation.lock");
          for (let attempt = 0; attempt < 200 && !existsSync(lockPath); attempt++) {
            await new Promise((resolvePoll) => setTimeout(resolvePoll, 10));
          }
          const concurrent = run(migrationArgs({}, "--rotate-exclusions"), { env: migrationEnv });
          if (paused.exitCode === null && paused.signalCode === null) paused.kill("SIGKILL");
          const pausedResult = await pausedClose;
          const afterConcurrentCrash = run(migrationArgs({}, "--rotate-exclusions"), { env: migrationEnv });
          check(
            ARM_STATIC_CASES.case_exclusion_rotation_concurrency_one_live_writer_excludes_a_secon_575d2c2b,
            concurrent.code === 2 && concurrent.findings.some((finding) => finding.subject === "another exclusion rotation writer is active")
              && !pausedResult.timedOut && pausedResult.error === null
              && pausedResult.signal === "SIGKILL"
              && afterConcurrentCrash.code === 0 && transactionResidue().length === 0,
            `concurrent exit ${concurrent.code}; recovered exit ${afterConcurrentCrash.code}; ` +
              `paused ${pausedResult.code}/${pausedResult.signal}/${pausedResult.timedOut}; `
              + `subjects ${JSON.stringify(concurrent.findings.map((finding) => finding.subject))}`,
          );

          const staleLockDoc = {
            schemaVersion: 1,
            event: "EXCLUSION_POLICY_ROTATION_LOCK",
            pid: 2_147_483_647,
            startedAt: new Date(Date.now() - 60_000).toISOString(),
            nonce: "d".repeat(64),
          };
          const spawnCheckpointed = (args, pauseAt, pauseMs, extraEnv = {}) => {
            const launched = spawnAuthorizedArm(args, {
              env: {
                ...migrationEnv,
                NOA_BOUNDARY_ROTATION_TEST_MODE: "1",
                NOA_BOUNDARY_ROTATION_TRACE_CHECKPOINTS: "1",
                NOA_BOUNDARY_ROTATION_PAUSE_AT: pauseAt,
                NOA_BOUNDARY_ROTATION_PAUSE_MS: String(pauseMs),
                ...extraEnv,
              },
            });
            const child = launched.child;
            let stdout = "";
            let stderr = "";
            let checkpointResolve;
            const checkpoint = new Promise((resolveCheckpoint) => { checkpointResolve = resolveCheckpoint; });
            child.stdout.on("data", (chunk) => { stdout += chunk.toString("utf8"); });
            child.stderr.on("data", (chunk) => {
              stderr += chunk.toString("utf8");
              if (stderr.includes(`NOA_ROTATION_CHECKPOINT ${pauseAt}\n`)) checkpointResolve(true);
            });
            const done = new Promise((resolveDone) => child.once("close", (code, signal) => {
              resolveDone(observeBoundaryGateChild({
                code,
                signal,
                stdout,
                stderr,
                expectation: launched.gateExpectation,
              }));
            }));
            return { child, checkpoint, done };
          };
          const raceChildEvents = async (events, records) => {
            let watchdogId;
            const watchdog = new Promise((resolveWatchdog) => {
              watchdogId = setTimeout(() => {
                for (const record of records) {
                  if (record.child.exitCode === null && record.child.signalCode === null) {
                    record.child.kill("SIGKILL");
                  }
                }
                resolveWatchdog({ kind: "watchdog" });
              }, 30_000);
            });
            const result = await Promise.race([...events, watchdog]);
            clearTimeout(watchdogId);
            return result;
          };
          const checkpointOrClose = (record, records = [record]) => raceChildEvents([
            record.checkpoint.then(() => ({ kind: "checkpoint" })),
            record.done.then((result) => ({ kind: "closed", result })),
          ], records);
          const closeOrWatchdog = (record, records = [record]) => raceChildEvents([
            record.done.then((result) => ({ kind: "closed", result })),
          ], records);
          const releaseCheckpoint = (path) => {
            writeFileSync(path, "release\n", { mode: KEY_MODE, flag: "wx" });
            chmodSync(path, KEY_MODE);
          };
          const failedChildResult = Object.freeze({
            code: null,
            signal: "WATCHDOG",
            out: "",
            findings: [],
            protocolComplete: false,
          });

          seedPreviousPolicy();
          const noClobberReleasePath = join(migrationDir, ".rotation-test-release-no-clobber");
          const noClobber = spawnCheckpointed(
            migrationArgs({}, "--rotate-exclusions"),
            "create-link:exclusion-policy-rotation.lock",
            10_000,
            { NOA_BOUNDARY_ROTATION_RELEASE_FILE: noClobberReleasePath },
          );
          const noClobberEvent = await checkpointOrClose(noClobber);
          const noClobberObserved = noClobberEvent.kind === "checkpoint";
          const competingLockDoc = {
            schemaVersion: 1,
            event: "EXCLUSION_POLICY_ROTATION_LOCK",
            pid: process.pid,
            startedAt: new Date().toISOString(),
            nonce: "e".repeat(64),
          };
          const competingLockBytes = Buffer.from(`${canonicalJson(competingLockDoc)}\n`, "utf8");
          if (noClobberObserved) {
            writeFileSync(lockPath, competingLockBytes, { mode: KEY_MODE, flag: "wx" });
            chmodSync(lockPath, KEY_MODE);
            releaseCheckpoint(noClobberReleasePath);
          }
          const noClobberClose = noClobberEvent.kind === "closed"
            ? noClobberEvent
            : await closeOrWatchdog(noClobber);
          const noClobberResult = noClobberClose.kind === "closed"
            ? noClobberClose.result
            : failedChildResult;
          rmSync(noClobberReleasePath, { force: true });
          const competingLockAfter = existsSync(lockPath) ? readFileSync(lockPath) : null;
          const noClobberResidue = transactionResidue().filter((name) => name !== basename(lockPath));
          check(
            ARM_STATIC_CASES.case_exclusion_rotation_staged_create_direct_final_publication_never_fb2add8a,
            noClobberObserved && noClobberResult.code === 2
              && noClobberResult.findings.some((finding) => finding.subject
                === "the exclusion rotation lock could not be created durably and exclusively")
              && competingLockAfter !== null && competingLockAfter.equals(competingLockBytes)
              && noClobberResidue.length === 0,
            `observed ${noClobberObserved}; exit ${noClobberResult.code}; winner retained `
              + `${competingLockAfter?.equals(competingLockBytes) ?? false}; `
              + `residue ${JSON.stringify(noClobberResidue)}; subjects `
              + `${JSON.stringify(noClobberResult.findings.map((finding) => finding.subject))}`,
          );
          rmSync(lockPath, { force: true });

          seedPreviousPolicy();
          writeFileSync(lockPath, `${canonicalJson(staleLockDoc)}\n`, { mode: KEY_MODE });
          chmodSync(lockPath, KEY_MODE);
          const delayedReleasePath = join(migrationDir, ".rotation-test-release-delayed");
          const delayed = spawnCheckpointed(
            migrationArgs({ publicArtifact: "arm-public@9.9.9" }, "--rotate-exclusions"),
            "stale-lock-source-opened",
            10_000,
            { NOA_BOUNDARY_ROTATION_RELEASE_FILE: delayedReleasePath },
          );
          const delayedEvent = await checkpointOrClose(delayed);
          const delayedObserved = delayedEvent.kind === "checkpoint";
          const winnerReleasePath = join(migrationDir, ".rotation-test-release-delayed-winner");
          const winner = delayedObserved ? spawnCheckpointed(
            migrationArgs({}, "--rotate-exclusions"),
            "lock-acquired",
            10_000,
            { NOA_BOUNDARY_ROTATION_RELEASE_FILE: winnerReleasePath },
          ) : null;
          const winnerEvent = winner === null
            ? { kind: "not-started" }
            : await checkpointOrClose(winner, [winner, delayed]);
          const winnerAcquired = winnerEvent.kind === "checkpoint";
          const liveWinnerBytes = winnerAcquired && existsSync(lockPath) ? readFileSync(lockPath) : null;
          const liveWinnerDoc = liveWinnerBytes === null ? null : JSON.parse(liveWinnerBytes.toString("utf8"));
          if (delayedObserved) releaseCheckpoint(delayedReleasePath);
          const delayedClose = delayedEvent.kind === "closed"
            ? delayedEvent
            : await closeOrWatchdog(delayed, winner === null ? [delayed] : [delayed, winner]);
          const delayedResult = delayedClose.kind === "closed" ? delayedClose.result : failedChildResult;
          const liveAfterDelayed = existsSync(lockPath) ? readFileSync(lockPath) : null;
          if (winnerAcquired) releaseCheckpoint(winnerReleasePath);
          const winnerClose = winnerEvent.kind === "closed"
            ? winnerEvent
            : (winner === null ? { kind: "not-started" } : await closeOrWatchdog(winner, [winner]));
          const winnerResult = winnerClose.kind === "closed" ? winnerClose.result : failedChildResult;
          rmSync(delayedReleasePath, { force: true });
          rmSync(winnerReleasePath, { force: true });
          check(
            ARM_STATIC_CASES.case_exclusion_rotation_stale_lock_race_a_delayed_reader_cannot_remo_ca1ba2f9,
            delayedObserved && winnerAcquired && delayedResult.code === 2
              && liveWinnerDoc?.pid === winner?.child.pid
              && liveWinnerBytes !== null && liveAfterDelayed !== null && liveAfterDelayed.equals(liveWinnerBytes)
              && winnerResult.code === 0 && transactionResidue().length === 0,
            `observed ${delayedObserved}; winner ${winnerAcquired}; delayed exit ${delayedResult.code}; `
              + `winner exit ${winnerResult.code}; live pid ${liveWinnerDoc?.pid ?? "absent"}; `
              + `residue ${JSON.stringify(transactionResidue())}; delayed subjects `
              + `${JSON.stringify(delayedResult.findings.map((finding) => finding.subject))}`,
          );

          resetMigrationHome();
          writeFileSync(policyPath, intermediateText, { mode: KEY_MODE });
          chmodSync(policyPath, KEY_MODE);
          const claimOnlyBytes = Buffer.from(`${canonicalJson(staleLockDoc)}\n`, "utf8");
          const claimOnlyDigest = createHash("sha256").update(claimOnlyBytes).digest("hex");
          const claimOnlyPath = join(
            migrationDir,
            `exclusion-policy-rotation-lock-claim-${claimOnlyDigest}.lock`,
          );
          writeFileSync(claimOnlyPath, claimOnlyBytes, { mode: KEY_MODE });
          chmodSync(claimOnlyPath, KEY_MODE);
          const sameFixtureIdentity = (left, right) => left.dev === right.dev && left.ino === right.ino;
          const ownerReleasePath = join(migrationDir, ".rotation-test-release-claim-owner");
          const electedOwner = spawnCheckpointed(
            migrationArgs({}, "--rotate-exclusions"),
            "replacement-lock-published-before-claim-cleanup",
            10_000,
            { NOA_BOUNDARY_ROTATION_RELEASE_FILE: ownerReleasePath },
          );
          const ownerEvent = await checkpointOrClose(electedOwner);
          const ownerPublished = ownerEvent.kind === "checkpoint";
          const claimBeforeObserver = ownerPublished && existsSync(claimOnlyPath)
            ? { bytes: readFileSync(claimOnlyPath), stat: lstatSync(claimOnlyPath) }
            : null;
          const lockBeforeObserver = ownerPublished && existsSync(lockPath)
            ? { bytes: readFileSync(lockPath), stat: lstatSync(lockPath) }
            : null;
          let electedLockDoc = null;
          try { electedLockDoc = lockBeforeObserver === null ? null : JSON.parse(lockBeforeObserver.bytes.toString("utf8")); }
          catch { /* asserted below */ }
          const vulnerableStateObserved = claimBeforeObserver !== null && lockBeforeObserver !== null
            && claimBeforeObserver.bytes.equals(claimOnlyBytes)
            && claimBeforeObserver.stat.nlink === 1 && lockBeforeObserver.stat.nlink === 1
            && !sameFixtureIdentity(claimBeforeObserver.stat, lockBeforeObserver.stat)
            && electedLockDoc?.pid === electedOwner.child.pid;
          const observer = ownerPublished ? spawnCheckpointed(
            migrationArgs({ publicArtifact: "arm-public@8.8.8" }, "--rotate-exclusions"),
            "observer-must-not-pause",
            10_000,
          ) : null;
          const observerClose = observer === null
            ? { kind: "not-started" }
            : await closeOrWatchdog(observer, [electedOwner, observer]);
          const observerResult = observerClose.kind === "closed" ? observerClose.result : failedChildResult;
          const claimAfterObserver = existsSync(claimOnlyPath)
            ? { bytes: readFileSync(claimOnlyPath), stat: lstatSync(claimOnlyPath) }
            : null;
          const lockAfterObserver = existsSync(lockPath)
            ? { bytes: readFileSync(lockPath), stat: lstatSync(lockPath) }
            : null;
          const observerRetainedOwnerState = claimBeforeObserver !== null && lockBeforeObserver !== null
            && claimAfterObserver !== null && lockAfterObserver !== null
            && claimAfterObserver.bytes.equals(claimBeforeObserver.bytes)
            && lockAfterObserver.bytes.equals(lockBeforeObserver.bytes)
            && sameFixtureIdentity(claimAfterObserver.stat, claimBeforeObserver.stat)
            && sameFixtureIdentity(lockAfterObserver.stat, lockBeforeObserver.stat);
          const observerExactActiveFailure = observerResult.code === 2 && observerResult.protocolComplete
            && observerResult.findings.length === 1
            && observerResult.findings[0].rule === "SETUP_FAILED"
            && observerResult.findings[0].subject === "another exclusion rotation writer is active";
          if (ownerPublished) releaseCheckpoint(ownerReleasePath);
          const ownerClose = ownerEvent.kind === "closed"
            ? ownerEvent
            : await closeOrWatchdog(electedOwner, [electedOwner]);
          const ownerResult = ownerClose.kind === "closed" ? ownerClose.result : failedChildResult;
          rmSync(ownerReleasePath, { force: true });
          const successorAfterElection = existsSync(policyPath) ? readFileSync(policyPath, "utf8") : "";
          let successorAfterElectionDoc = null;
          try { successorAfterElectionDoc = JSON.parse(successorAfterElection); } catch { /* asserted below */ }
          const contenderResults = [ownerResult, observerResult];
          const acquiredCount = contenderResults.reduce((count, result) => count
            + (result.out.match(/NOA_ROTATION_CHECKPOINT lock-acquired\n/g)?.length ?? 0), 0);
          check(
            ARM_STATIC_CASES.case_exclusion_rotation_retained_claim_ownership_only_the_exact_live_1e0229b4,
            ownerPublished && vulnerableStateObserved && observerRetainedOwnerState
              && observerExactActiveFailure
              && ownerResult.code === 0 && ownerResult.protocolComplete
              && acquiredCount === 1 && successorAfterElection === rotatedText
              && successorAfterElectionDoc?.publicArtifact === freshPublicArtifact
              && successorAfterElectionDoc?.publicArtifact !== "arm-public@8.8.8"
              && transactionResidue().length === 0,
            `published ${ownerPublished}; vulnerable ${vulnerableStateObserved}; retained ${observerRetainedOwnerState}; `
              + `observer exact ${observerExactActiveFailure}; acquired ${acquiredCount}; `
              + `exits ${contenderResults.map((result) => result.code).join("/")}; `
              + `residue ${JSON.stringify(transactionResidue())}; subjects `
              + `${JSON.stringify(contenderResults.map((result) => result.findings.map((finding) => finding.subject)))}`,
          );

          resetMigrationHome();
          writeFileSync(policyPath, intermediateText, { mode: KEY_MODE });
          chmodSync(policyPath, KEY_MODE);
          writeFileSync(claimOnlyPath, claimOnlyBytes, { mode: KEY_MODE });
          chmodSync(claimOnlyPath, KEY_MODE);
          const deadReplacementDoc = {
            schemaVersion: 1,
            event: "EXCLUSION_POLICY_ROTATION_LOCK",
            pid: 2_147_483_647,
            startedAt: new Date(Date.now() - 30_000).toISOString(),
            nonce: "f".repeat(64),
          };
          const deadReplacementBytes = Buffer.from(`${canonicalJson(deadReplacementDoc)}\n`, "utf8");
          writeFileSync(lockPath, deadReplacementBytes, { mode: KEY_MODE });
          chmodSync(lockPath, KEY_MODE);
          const deadReplacementRecovery = run(migrationArgs({}, "--rotate-exclusions"), { env: migrationEnv });
          check(
            ARM_STATIC_CASES.case_exclusion_rotation_retained_claim_recovery_a_dead_replacement_a_eeec040b,
            deadReplacementRecovery.code === 0 && deadReplacementRecovery.protocolComplete
              && readFileSync(policyPath, "utf8") === rotatedText
              && transactionResidue().length === 0,
            `exit ${deadReplacementRecovery.code}; protocol ${deadReplacementRecovery.protocolComplete}; `
              + `residue ${JSON.stringify(transactionResidue())}; subjects `
              + `${JSON.stringify(deadReplacementRecovery.findings.map((finding) => finding.subject))}`,
          );

          seedPreviousPolicy();
          const unknownPath = join(migrationDir, "exclusions.pending-successor-v3-not-a-digest.json");
          writeFileSync(unknownPath, "unknown\n", { mode: KEY_MODE });
          chmodSync(unknownPath, KEY_MODE);
          const activeBeforeUnknown = readFileSync(policyPath);
          const unknownBefore = readFileSync(unknownPath);
          const unknownRun = run(migrationArgs({}, "--rotate-exclusions"), { env: migrationEnv });
          check(
            ARM_STATIC_CASES.case_exclusion_rotation_recovery_unknown_transaction_artifacts_fail__031adaee,
            unknownRun.code === 2 && unknownRun.findings.some((finding) => finding.subject === "unknown exclusion rotation artifacts are present")
              && readFileSync(policyPath).equals(activeBeforeUnknown) && readFileSync(unknownPath).equals(unknownBefore),
              `exit ${unknownRun.code}; subjects ${JSON.stringify(unknownRun.findings.map((finding) => finding.subject))}`,
          );

          const stageDestinationDigest = (name) => createHash("sha256")
            .update(`noa-boundary-create-destination/v1\0${name}`, "utf8")
            .digest("hex");
          const installStage = (targetName, payload, claimedDigest = createHash("sha256").update(payload).digest("hex"), nonce = "a".repeat(32)) => {
            const stageTarget = join(migrationDir, ".noa-boundary-create-v1", targetName);
            mkdirSync(stageTarget, { recursive: true, mode: KEY_DIR_MODE });
            chmodSync(join(migrationDir, ".noa-boundary-create-v1"), KEY_DIR_MODE);
            chmodSync(stageTarget, KEY_DIR_MODE);
            const stagePath = join(
              stageTarget,
              `create-v1-${stageDestinationDigest(targetName)}-${claimedDigest}-${payload.length}`
                + `-p2147483647-${nonce}.stage`,
            );
            writeFileSync(stagePath, payload, { mode: KEY_MODE });
            chmodSync(stagePath, KEY_MODE);
            return stagePath;
          };
          seedPreviousPolicy();
          const unknownStageTarget = join(migrationDir, ".noa-boundary-create-v1", "not-a-boundary-destination");
          mkdirSync(unknownStageTarget, { recursive: true, mode: KEY_DIR_MODE });
          chmodSync(join(migrationDir, ".noa-boundary-create-v1"), KEY_DIR_MODE);
          chmodSync(unknownStageTarget, KEY_DIR_MODE);
          const unknownStageTargetRun = run(migrationArgs({}, "--rotate-exclusions"), { env: migrationEnv });
          check(
            ARM_STATIC_CASES.case_exclusion_rotation_staged_create_an_unknown_destination_target__61d5b1e1,
            unknownStageTargetRun.code === 2 && existsSync(unknownStageTarget) && !existsSync(lockPath)
              && unknownStageTargetRun.findings.some((finding) => finding.subject
                === "unknown boundary create stages are present"),
            `exit ${unknownStageTargetRun.code}; target ${existsSync(unknownStageTarget)}; `
              + `lock ${existsSync(lockPath)}; subjects `
              + `${JSON.stringify(unknownStageTargetRun.findings.map((finding) => finding.subject))}`,
          );

          seedPreviousPolicy();
          const corruptStageTargetName = basename(receiptPath);
          const corruptStageOpaqueId = `stage:sha256:${createHash("sha256")
            .update(`noa-boundary:stage:v1\0${corruptStageTargetName}`, "utf8")
            .digest("hex")}`;
          const corruptStage = installStage(corruptStageTargetName, Buffer.from("corrupt\n"), "a".repeat(64));
          const corruptStageBefore = readFileSync(corruptStage);
          const corruptStageRun = run(migrationArgs({}, "--rotate-exclusions"), { env: migrationEnv });
          check(
            ARM_STATIC_CASES.case_exclusion_rotation_staged_create_a_corrupt_exact_shaped_stage_f_df43955a,
            corruptStageRun.code === 2 && existsSync(corruptStage)
              && readFileSync(corruptStage).equals(corruptStageBefore)
              && !corruptStageRun.out.includes(corruptStageTargetName)
              && corruptStageRun.findings.some((finding) => finding.subject
                === `the retired staged boundary file ${corruptStageOpaqueId} requires manual recovery`),
            `exit ${corruptStageRun.code}; stage ${existsSync(corruptStage)}; `
              + `subjects ${JSON.stringify(corruptStageRun.findings.map((finding) => finding.subject))}`,
          );

          seedPreviousPolicy();
          const stagedLockA = Buffer.from(`${canonicalJson({
            schemaVersion: 1,
            event: "EXCLUSION_POLICY_ROTATION_LOCK",
            pid: 2_147_483_646,
            startedAt: new Date(Date.now() - 120_000).toISOString(),
            nonce: "1".repeat(64),
          })}\n`, "utf8");
          const stagedLockB = Buffer.from(`${canonicalJson({
            schemaVersion: 1,
            event: "EXCLUSION_POLICY_ROTATION_LOCK",
            pid: 2_147_483_647,
            startedAt: new Date(Date.now() - 60_000).toISOString(),
            nonce: "2".repeat(64),
          })}\n`, "utf8");
          const stageLockPathA = installStage(basename(lockPath), stagedLockA, undefined, "b".repeat(32));
          const stageLockPathB = installStage(basename(lockPath), stagedLockB, undefined, "c".repeat(32));
          const multipleStageRun = run(migrationArgs({}, "--rotate-exclusions"), { env: migrationEnv });
          check(
            ARM_STATIC_CASES.case_exclusion_rotation_staged_create_two_valid_competing_complete_l_0a8ee299,
            multipleStageRun.code === 2 && existsSync(stageLockPathA) && existsSync(stageLockPathB)
              && readFileSync(stageLockPathA).equals(stagedLockA) && readFileSync(stageLockPathB).equals(stagedLockB)
              && multipleStageRun.findings.some((finding) => finding.subject
                === "the retired exclusion rotation lock staging state requires manual recovery"),
            `exit ${multipleStageRun.code}; stages ${existsSync(stageLockPathA)}/${existsSync(stageLockPathB)}; `
              + `subjects ${JSON.stringify(multipleStageRun.findings.map((finding) => finding.subject))}`,
          );

          seedPreviousPolicy();
          const linkedStage = installStage(basename(lockPath), stagedLockA, undefined, "4".repeat(32));
          const unknownStageAlias = join(migrationDir, "unrelated-stage-hardlink");
          linkSync(linkedStage, unknownStageAlias);
          const linkedStageRun = run(migrationArgs({}, "--rotate-exclusions"), { env: migrationEnv });
          check(
            ARM_STATIC_CASES.case_exclusion_rotation_staged_create_an_unknown_hard_link_cannot_pu_c35ca15d,
            linkedStageRun.code === 2 && existsSync(linkedStage) && existsSync(unknownStageAlias)
              && readFileSync(linkedStage).equals(stagedLockA)
              && readFileSync(unknownStageAlias).equals(stagedLockA)
              && !existsSync(lockPath)
              && linkedStageRun.findings.some((finding) => finding.subject
                === "the retired exclusion rotation lock staging state requires manual recovery"),
            `exit ${linkedStageRun.code}; stage/alias ${existsSync(linkedStage)}/${existsSync(unknownStageAlias)}; `
              + `final ${existsSync(lockPath)}; subjects `
              + `${JSON.stringify(linkedStageRun.findings.map((finding) => finding.subject))}`,
          );

          seedPreviousPolicy();
          const intentSeed = run(migrationArgs({}, "--rotate-exclusions"), {
            env: {
              ...migrationEnv,
              NOA_BOUNDARY_ROTATION_TEST_MODE: "1",
              NOA_BOUNDARY_ROTATION_CRASH_AFTER: "intent-durable",
            },
          });
          const generatedIntentName = readdirSync(migrationDir).find((name) => name.startsWith("exclusion-policy-rotation-intent-"));
          const generatedIntentPath = generatedIntentName === undefined ? null : join(migrationDir, generatedIntentName);
          const generatedIntent = generatedIntentPath === null ? null : JSON.parse(readFileSync(generatedIntentPath, "utf8"));
          const corruptIntent = generatedIntent === null ? null : {
            ...generatedIntent,
            intentMac: `${generatedIntent.intentMac.slice(0, 63)}${generatedIntent.intentMac.endsWith("0") ? "1" : "0"}`,
          };
          const corruptIntentBytes = Buffer.from(`${canonicalJson(corruptIntent)}\n`, "utf8");
          const corruptIntentPath = join(
            migrationDir,
            `exclusion-policy-rotation-intent-${createHash("sha256").update(corruptIntentBytes).digest("hex")}.json`,
          );
          if (generatedIntentPath !== null) rmSync(generatedIntentPath, { force: true });
          writeFileSync(corruptIntentPath, corruptIntentBytes, { mode: KEY_MODE });
          chmodSync(corruptIntentPath, KEY_MODE);
          const corruptIntentRun = run(migrationArgs({}, "--rotate-exclusions"), { env: migrationEnv });
          check(
            ARM_STATIC_CASES.case_exclusion_rotation_recovery_corrupt_intent_fails_closed_without_ee980a0e,
            intentSeed.code === null && corruptIntentRun.code === 2
              && corruptIntentRun.findings.some((finding) => finding.subject === "the exclusion rotation intent authentication failed")
              && existsSync(corruptIntentPath)
              && readFileSync(corruptIntentPath).equals(corruptIntentBytes),
            `seed exit ${intentSeed.code}; exit ${corruptIntentRun.code}; ` +
              `subjects ${JSON.stringify(corruptIntentRun.findings.map((finding) => finding.subject))}`,
          );

          seedPreviousPolicy();
          const firstRaw = freshPredecessorPath;
          const otherRawBytes = Buffer.from(originalPolicyText, "utf8");
          const otherRaw = join(
            migrationDir,
            `exclusions.superseded-v3-${createHash("sha256").update(otherRawBytes).digest("hex")}.json`,
          );
          writeFileSync(firstRaw, intermediateText, { mode: KEY_MODE });
          writeFileSync(otherRaw, otherRawBytes, { mode: KEY_MODE });
          chmodSync(firstRaw, KEY_MODE);
          chmodSync(otherRaw, KEY_MODE);
          const multipleRun = run(migrationArgs({}, "--rotate-exclusions"), { env: migrationEnv });
          check(
            ARM_STATIC_CASES.case_exclusion_rotation_recovery_multiple_authenticated_predecessors_0ff4b31d,
            multipleRun.code === 2 && existsSync(firstRaw) && existsSync(otherRaw)
              && readFileSync(firstRaw, "utf8") === intermediateText && readFileSync(otherRaw).equals(otherRawBytes)
              && multipleRun.findings.some((finding) => finding.subject
                === "multiple raw predecessor files do not form one exact name-normalization state"),
              `exit ${multipleRun.code}; subjects ${JSON.stringify(multipleRun.findings.map((finding) => finding.subject))}`,
          );

          const legacyReceiptAliasPath = join(
            migrationDir,
            `exclusion-policy-rotation-v3-${intermediateDigest.slice(0, 16)}`
              + `-to-v3-${successorDigest.slice(0, 16)}.json`,
          );
          resetMigrationHome();
          writeFileSync(policyPath, rotatedText, { mode: KEY_MODE });
          chmodSync(policyPath, KEY_MODE);
          writeFileSync(freshPredecessorPath, intermediateText, { mode: KEY_MODE });
          chmodSync(freshPredecessorPath, KEY_MODE);
          writeFileSync(legacyReceiptAliasPath, receiptText, { mode: KEY_MODE });
          chmodSync(legacyReceiptAliasPath, KEY_MODE);
          const receiptAliasCrash = run(migrationArgs({}, "--rotate-exclusions"), {
            env: {
              ...migrationEnv,
              NOA_BOUNDARY_ROTATION_TEST_MODE: "1",
              NOA_BOUNDARY_ROTATION_CRASH_AFTER: "legacy-receipt-full-durable",
            },
          });
          const receiptPairAtCrash = existsSync(legacyReceiptAliasPath) && existsSync(receiptPath)
            && readFileSync(legacyReceiptAliasPath).equals(readFileSync(receiptPath));
          const receiptAliasRecovered = run(migrationArgs({}, "--rotate-exclusions"), { env: migrationEnv });
          check(
            ARM_STATIC_CASES.case_exclusion_rotation_name_recovery_crash_after_full_receipt_publi_e51c8b4d,
            receiptAliasCrash.code === null && receiptPairAtCrash && receiptAliasRecovered.code === 0
              && !existsSync(legacyReceiptAliasPath) && existsSync(receiptPath)
              && readFileSync(receiptPath, "utf8") === receiptText && transactionResidue().length === 0,
            `crash ${receiptAliasCrash.code}; pair ${receiptPairAtCrash}; recovery ${receiptAliasRecovered.code}; `
              + `legacy ${existsSync(legacyReceiptAliasPath)}; residue ${JSON.stringify(transactionResidue())}; `
              + `subjects ${JSON.stringify(receiptAliasRecovered.findings.map((finding) => finding.subject))}`,
          );

          resetMigrationHome();
          writeFileSync(policyPath, rotatedText, { mode: KEY_MODE });
          chmodSync(policyPath, KEY_MODE);
          writeFileSync(freshPredecessorPath, intermediateText, { mode: KEY_MODE });
          chmodSync(freshPredecessorPath, KEY_MODE);
          writeFileSync(receiptPath, receiptText, { mode: KEY_MODE });
          chmodSync(receiptPath, KEY_MODE);
          writeFileSync(legacyReceiptAliasPath, legacyReceiptText, { mode: KEY_MODE });
          chmodSync(legacyReceiptAliasPath, KEY_MODE);
          const receiptAliasConflict = run(migrationArgs({}, "--rotate-exclusions"), { env: migrationEnv });
          check(
            ARM_STATIC_CASES.case_exclusion_rotation_name_recovery_byte_different_authenticated_r_3872b421,
            receiptAliasConflict.code === 2 && existsSync(receiptPath) && existsSync(legacyReceiptAliasPath)
              && readFileSync(receiptPath, "utf8") === receiptText
              && readFileSync(legacyReceiptAliasPath, "utf8") === legacyReceiptText,
            `exit ${receiptAliasConflict.code}; full ${existsSync(receiptPath)}; legacy ${existsSync(legacyReceiptAliasPath)}; `
              + `subjects ${JSON.stringify(receiptAliasConflict.findings.map((finding) => finding.subject))}`,
          );

          const legacyRandom = join(migrationDir, ".exclusion-policy-delete-4242-0123456789abcdef.tmp");
          resetMigrationHome();
          writeFileSync(policyPath, intermediateText, { mode: KEY_MODE });
          chmodSync(policyPath, KEY_MODE);
          writeFileSync(legacyRandom, previousText, { mode: KEY_MODE });
          chmodSync(legacyRandom, KEY_MODE);
          const legacyRawPairCrash = run(["--recover-exclusion-rotation"], {
            env: {
              ...migrationEnv,
              NOA_BOUNDARY_ROTATION_TEST_MODE: "1",
              NOA_BOUNDARY_ROTATION_CRASH_AFTER: "legacy-tombstone-deterministic-durable",
            },
          });
          const rawPairAtCrash = existsSync(legacyRandom) && existsSync(predecessorPath)
            && readFileSync(legacyRandom).equals(readFileSync(predecessorPath));
          const legacyRawPairRecovered = run(["--recover-exclusion-rotation"], { env: migrationEnv });
          check(
            ARM_STATIC_CASES.case_exclusion_rotation_name_recovery_crash_after_raw_legacy_tombsto_c2c918b6,
            legacyRawPairCrash.code === null && rawPairAtCrash && legacyRawPairRecovered.code === 0
              && !existsSync(legacyRandom) && transactionResidue().length === 0,
            `crash ${legacyRawPairCrash.code}; pair ${rawPairAtCrash}; recovery ${legacyRawPairRecovered.code}; `
              + `residue ${JSON.stringify(transactionResidue())}; subjects `
              + `${JSON.stringify(legacyRawPairRecovered.findings.map((finding) => finding.subject))}`,
          );

          resetMigrationHome();
          writeFileSync(policyPath, intermediateText, { mode: KEY_MODE });
          chmodSync(policyPath, KEY_MODE);
          writeFileSync(recoveryReceiptPath, recoveryReceiptText, { mode: KEY_MODE });
          chmodSync(recoveryReceiptPath, KEY_MODE);
          writeFileSync(legacyRandom, previousText, { mode: KEY_MODE });
          chmodSync(legacyRandom, KEY_MODE);
          const deletingPairPath = join(migrationDir, `exclusions.deleting-v2-${predecessorDigest}.json`);
          const legacyDeletingPairCrash = run(["--recover-exclusion-rotation"], {
            env: {
              ...migrationEnv,
              NOA_BOUNDARY_ROTATION_TEST_MODE: "1",
              NOA_BOUNDARY_ROTATION_CRASH_AFTER: "legacy-tombstone-deterministic-durable",
            },
          });
          const deletingPairAtCrash = existsSync(legacyRandom) && existsSync(deletingPairPath)
            && readFileSync(legacyRandom).equals(readFileSync(deletingPairPath));
          const legacyDeletingPairRecovered = run(["--recover-exclusion-rotation"], { env: migrationEnv });
          check(
            ARM_STATIC_CASES.case_exclusion_rotation_name_recovery_crash_after_receipt_bound_dele_0a6df53f,
            legacyDeletingPairCrash.code === null && deletingPairAtCrash && legacyDeletingPairRecovered.code === 0
              && !existsSync(legacyRandom) && !existsSync(deletingPairPath) && transactionResidue().length === 0,
            `crash ${legacyDeletingPairCrash.code}; pair ${deletingPairAtCrash}; recovery ${legacyDeletingPairRecovered.code}; `
              + `legacy ${existsSync(legacyRandom)}; deleting ${existsSync(deletingPairPath)}; `
              + `subjects ${JSON.stringify(legacyDeletingPairRecovered.findings.map((finding) => finding.subject))}`,
          );

          resetMigrationHome();
          writeFileSync(policyPath, intermediateText, { mode: KEY_MODE });
          chmodSync(policyPath, KEY_MODE);
          writeFileSync(legacyRandom, previousText, { mode: KEY_MODE });
          chmodSync(legacyRandom, KEY_MODE);
          const legacyNoReceipt = run(["--recover-exclusion-rotation"], { env: migrationEnv });
          check(
            ARM_STATIC_CASES.case_exclusion_rotation_recovery_sole_legacy_random_tombstone_withou_83b6125c,
            legacyNoReceipt.code === 0 && !existsSync(legacyRandom) && transactionResidue().length === 0,
            `exit ${legacyNoReceipt.code}; residue ${transactionResidue().length}; ` +
              `subjects ${JSON.stringify(legacyNoReceipt.findings.map((finding) => finding.subject))}`,
          );

          const currentReceipt = readdirSync(migrationDir).find((name) => name.startsWith("exclusion-policy-rotation-v2-"));
          writeFileSync(legacyRandom, previousText, { mode: KEY_MODE });
          chmodSync(legacyRandom, KEY_MODE);
          const legacyWithReceipt = run(["--recover-exclusion-rotation"], { env: migrationEnv });
          check(
            ARM_STATIC_CASES.case_exclusion_rotation_recovery_sole_legacy_random_tombstone_with_e_cb509a13,
            currentReceipt !== undefined && legacyWithReceipt.code === 0 && !existsSync(legacyRandom)
              && transactionResidue().length === 0,
            `exit ${legacyWithReceipt.code}; receipt ${currentReceipt === undefined ? "absent" : "present"}; ` +
              `subjects ${JSON.stringify(legacyWithReceipt.findings.map((finding) => finding.subject))}`,
          );
        }
      }
      restore();
    }

    {
      const publicBefore = readFileSync(cfg("boundary-public-repos.json"));
      const commitmentsBefore = readFileSync(cfg("boundary-commitments.json"));
      const combined = run([
        "--repo-visibility-source", "live", "--refresh-public-repos", "--refresh-tokens",
      ]);
      const combinedFailure = setupFailureObservation(
        combined,
        "public-repository and token refresh were combined",
      );
      check(
        ARM_STATIC_CASES.case_boundary_refresh_ordering_combined_public_snapshot_and_token_re_40b2f791,
        combinedFailure.ok
          && readFileSync(cfg("boundary-public-repos.json")).equals(publicBefore)
          && readFileSync(cfg("boundary-commitments.json")).equals(commitmentsBefore),
        `credited/observed exit ${combined.code}/${combined.observedCode}; authority `
          + `${combined.authorityProblem}; subjects `
          + `${JSON.stringify(combinedFailure.diagnosticFindings.map((finding) => finding.subject))}`,
      );
    }

    // A refresh may only extend an authenticated predecessor. Tampering first and then asking the
    // live refresh to issue a new MAC must not turn a shrunken set into a valid baseline.
    {
      const fakeBin = join(work, "refresh-ratchet-fake-bin");
      mkdirSync(fakeBin, { mode: KEY_DIR_MODE });
      const fakeGh = join(fakeBin, "gh");
      writeFileSync(fakeGh, `#!/usr/bin/env node
const args = process.argv.slice(2);
if (args[0] === "repo" && args[1] === "list") {
  const visibility = args[args.indexOf("--visibility") + 1];
  const names = visibility === "public" ? ["public-arm"] : ["arm-private"];
  process.stdout.write(JSON.stringify(names.map((name) => ({ name, nameWithOwner: args[2] + "/" + name, visibility: visibility.toUpperCase() }))));
  process.exit(0);
}
if (args[0] === "repo" && args[1] === "view") {
  process.stdout.write(JSON.stringify({ nameWithOwner: args[2], visibility: "PRIVATE" }));
  process.exit(0);
}
process.exit(9);
`, { mode: 0o755 });
      chmodSync(fakeGh, 0o755);
      prepareSingleOwnerLiveBaseline();
      const tampered = JSON.parse(backup.get("boundary-commitments.json"));
      tampered.digests = [tampered.canaryDigest];
      tampered.count = 1;
      const tamperedBytes = `${JSON.stringify(tampered, null, 2)}\n`;
      writeFileSync(cfg("boundary-commitments.json"), tamperedBytes);
      const r = run(["--refresh-tokens", "--repo-visibility-source", "live"], {
        env: { ...process.env, HOME: armHome, PATH: `${fakeBin}${delimiter}${process.env.PATH ?? ""}` },
      });
      check(
        ARM_STATIC_CASES.case_commitment_refresh_tamper_then_refresh_cannot_bless_a_shrunken__d3b68323,
        r.code === 2
          && r.findings.some((finding) => finding.subject === "the token commitments authentication failed")
          && readFileSync(cfg("boundary-commitments.json"), "utf8") === tamperedBytes,
        `exit ${r.code}; subjects ${JSON.stringify(r.findings.map((finding) => finding.subject))}`,
      );
      restore();
    }

    // Exercise the first-run creation branch without contacting a forge or touching the real key.
    // The fake `gh` is constrained to the scratch process PATH and returns one synthetic private
    // label; the generated key remains in the scratch HOME until the arm removes the whole tree.
    {
      const refreshHome = join(work, "refresh-home");
      const fakeBin = join(work, "fake-bin");
      mkdirSync(refreshHome, { mode: 0o700 });
      chmodSync(refreshHome, 0o700);
      mkdirSync(fakeBin, { mode: 0o700 });
      const fakeGh = join(fakeBin, "gh");
      writeFileSync(fakeGh, `#!/usr/bin/env node
const args = process.argv.slice(2);
if (args[0] === "repo" && args[1] === "list") {
  const visibility = args[args.indexOf("--visibility") + 1];
  const names = visibility === "public" ? ["public-arm"] : ["arm-private"];
  process.stdout.write(JSON.stringify(names.map((name) => ({
    name, nameWithOwner: args[2] + "/" + name, visibility: visibility.toUpperCase(),
  }))));
  process.exit(0);
}
if (args[0] === "repo" && args[1] === "view") {
  process.stdout.write(JSON.stringify({ nameWithOwner: args[2], visibility: "PRIVATE" }));
  process.exit(0);
}
process.exit(9);
      `, { mode: 0o755 });
      chmodSync(fakeGh, 0o755);
      prepareSingleOwnerLiveBaseline();
      rmSync(cfg("boundary-commitments.json"));

      const r = run(["--refresh-tokens", "--repo-visibility-source", "live"], {
        env: { ...process.env, HOME: refreshHome, PATH: `${fakeBin}${delimiter}${process.env.PATH ?? ""}` },
      });
      if (r.code !== 0) {
        check(ARM_STATIC_CASES.case_key_custody_first_refresh_creates_one_regular_32_byte_0600_key__c42bfd20, false,
          `exit ${r.code}\n${r.out.slice(0, 800)}`);
      } else {
        const createdDirectory = lstatSync(join(refreshHome, ".noa-boundary"));
        const createdKey = lstatSync(join(refreshHome, ".noa-boundary", "key"));
        const createdCanary = lstatSync(join(refreshHome, ".noa-boundary", "canary.txt"));
        const uid = typeof process.geteuid === "function"
          ? process.geteuid()
          : (typeof process.getuid === "function" ? process.getuid() : null);
        check(
          ARM_STATIC_CASES.case_key_custody_first_refresh_creates_one_regular_32_byte_0600_key__c42bfd20,
          createdDirectory.isDirectory() && !createdDirectory.isSymbolicLink() &&
            (createdDirectory.mode & 0o7777) === 0o700 &&
            createdKey.isFile() && !createdKey.isSymbolicLink() && createdKey.size === 32 &&
            (createdKey.mode & 0o7777) === 0o600 && createdKey.nlink === 1 &&
            createdCanary.isFile() && !createdCanary.isSymbolicLink() &&
            (createdCanary.mode & 0o7777) === 0o600 && createdCanary.nlink === 1 &&
            !existsSync(join(refreshHome, ".noa-boundary", "tokens.txt")) &&
            (uid === null || (createdDirectory.uid === uid && createdKey.uid === uid)),
          `directory mode ${(createdDirectory.mode & 0o7777).toString(8)}; ` +
            `key mode ${(createdKey.mode & 0o7777).toString(8)}, bytes ${createdKey.size}, links ${createdKey.nlink}`,
        );
      }
      restore();
    }

    // …and with the key missing, `--tier a` is the DELIBERATE, LABELLED way through — it must still
    // run, and it must say TIER-B UNMEASURED rather than printing an unqualified green.
    {
      const r = spawnSync(process.execPath, [gate, "--lane", "L-WT", "--tier", "a", "--repo-visibility-source", "snapshot"], {
        cwd: repo, encoding: "utf8", shell: false, env: { ...process.env, HOME: emptyHome },
      });
      check(ARM_STATIC_CASES.case_without_a_key_tier_a_still_runs_and_labels_the_gap,
        r.status === 0 && /TIER-B UNMEASURED/.test(`${r.stdout}${r.stderr}`), `exit ${r.status}`);
    }

    failClosed(ARM_FAIL_CLOSED_CASES.fail_an_unknown_lane_id, () => {}, ["--lane", "L-NOPE"]);
    failClosed(ARM_FAIL_CLOSED_CASES.fail_an_unknown_flag, () => {}, ["--lane", "L-WT", "--go-faster"]);
    failClosed(ARM_FAIL_CLOSED_CASES.fail_an_unknown_tier, () => {}, ["--lane", "L-WT", "--tier", "z"]);
    {
      const remote = join(work, "arm-remote.git");
      const refArgs = [
        "--refs-from-stdin", "--pre-push-remote", remote, "--pre-push-url", remote,
      ];
      failClosed(
        ARM_FAIL_CLOSED_CASES.fail_pre_push_ref_input_is_empty,
        () => {},
        refArgs,
        { input: "" },
        "pre-push ref input is empty",
      );
      const sha = git(repo, ["rev-parse", "HEAD"]).stdout.trim();
      const parentSha = git(repo, ["rev-parse", "HEAD~"]).stdout.trim();
      const zeros = "0".repeat(sha.length);
      const selectorHead = run(["--lane", "L-WT", ...refArgs], {
        input: `HEAD ${sha} refs/heads/selector-head ${zeros}\n`,
      });
      check(
        ARM_STATIC_CASES.case_pre_push_local_selector_head_resolves_to_and_is_bound_to_the_ex_06e6f3ec,
        selectorHead.code === 0,
        `exit ${selectorHead.code}\n${selectorHead.out.slice(0, 600)}`,
      );
      const selectorParent = run(["--lane", "L-WT", ...refArgs], {
        input: `HEAD~ ${parentSha} refs/heads/selector-parent ${zeros}\n`,
      });
      check(
        ARM_STATIC_CASES.case_pre_push_local_selector_head_resolves_behind_the_option_boundar_d31e2d1f,
        selectorParent.code === 0,
        `exit ${selectorParent.code}\n${selectorParent.out.slice(0, 600)}`,
      );
      failClosed(
        ARM_FAIL_CLOSED_CASES.fail_pre_push_ref_input_contains_an_internal_blank_record,
        () => {},
        refArgs,
        { input: `refs/heads/one ${sha} refs/heads/one ${zeros}\n\nrefs/heads/two ${sha} refs/heads/two ${zeros}\n` },
        "pre-push ref input contains an empty record",
      );
      failClosed(
        ARM_FAIL_CLOSED_CASES.fail_pre_push_local_selector_and_object_id_disagree,
        () => {},
        refArgs,
        { input: `HEAD ${parentSha} refs/heads/mismatch ${zeros}\n` },
        "a pre-push local selector does not resolve to its supplied object ID",
      );
      const nonexistentSha = "f".repeat(sha.length);
      failClosed(
        ARM_FAIL_CLOSED_CASES.fail_pre_push_local_selector_names_a_nonexistent_object,
        () => {},
        refArgs,
        { input: `${nonexistentSha} ${nonexistentSha} refs/heads/nonexistent ${zeros}\n` },
        "a pre-push local selector cannot be resolved",
      );
      failClosed(
        ARM_FAIL_CLOSED_CASES.fail_pre_push_local_selector_is_option_like,
        () => {},
        refArgs,
        { input: `--help ${sha} refs/heads/option ${zeros}\n` },
        "a pre-push local selector is malformed",
      );
      failClosed(
        ARM_FAIL_CLOSED_CASES.fail_pre_push_local_selector_contains_a_control_byte,
        () => {},
        refArgs,
        { input: `HEAD${String.fromCharCode(1)} ${sha} refs/heads/control ${zeros}\n` },
        "a pre-push local selector is malformed",
      );
      failClosed(
        ARM_FAIL_CLOSED_CASES.fail_pre_push_local_selector_contains_whitespace,
        () => {},
        refArgs,
        { input: `HEAD extra ${sha} refs/heads/space ${zeros}\n` },
        "a pre-push ref line is malformed",
      );
      failClosed(
        ARM_FAIL_CLOSED_CASES.fail_pre_push_local_selector_exceeds_its_byte_bound,
        () => {},
        refArgs,
        { input: `${"a".repeat(4097)} ${sha} refs/heads/long ${zeros}\n` },
        "a pre-push local selector is malformed",
      );
      failClosed(
        ARM_FAIL_CLOSED_CASES.fail_pre_push_zero_local_object_id_lacks_the_deletion_marker,
        () => {},
        refArgs,
        { input: `HEAD ${zeros} refs/heads/delete-shape ${sha}\n` },
        "a pre-push deletion does not use the exact deletion marker",
      );
      failClosed(
        ARM_FAIL_CLOSED_CASES.fail_pre_push_deletion_marker_carries_a_nonzero_local_object_id,
        () => {},
        refArgs,
        { input: `(delete) ${sha} refs/heads/delete-shape ${sha}\n` },
        "a pre-push non-deletion uses the deletion marker",
      );
      failClosed(
        ARM_FAIL_CLOSED_CASES.fail_pre_push_remote_ref_is_not_a_full_exact_ref,
        () => {},
        refArgs,
        { input: `HEAD ${sha} remote-short-name ${zeros}\n` },
        "a pre-push remote ref is not an exact git ref",
      );
      failClosed(
        ARM_FAIL_CLOSED_CASES.fail_pre_push_local_object_id_is_malformed,
        () => {},
        refArgs,
        { input: `HEAD abc refs/heads/malformed-oid ${zeros}\n` },
        "a pre-push ref line has a malformed object ID",
      );
    }
    failClosed(ARM_FAIL_CLOSED_CASES.fail_every_selected_lane_skipped, () => {}, ["--lane", "L-IDX"]);
    failClosed(ARM_FAIL_CLOSED_CASES.fail_a_required_lane_has_no_input, () => {}, ["--lane", "L-WT", "--require-lane", "L-IDX"]);

    // A missing external tool. PATH is emptied, so `git` cannot be started at all.
    failClosed(ARM_FAIL_CLOSED_CASES.fail_git_is_not_on_path, () => {}, ["--lane", "L-WT"], { env: { ...process.env, PATH: join(work, "no-tools") } });

    // An unreadable file. A skipped file is not a clean file.
    const lockedRel = "locked.md";
    failClosed(ARM_FAIL_CLOSED_CASES.fail_a_tracked_file_cannot_be_read, () => {
      writeFileSync(join(repo, lockedRel), "content\n");
      git(repo, ["add", lockedRel]);
      chmodSync(join(repo, lockedRel), 0o000);
    });
    chmodSync(join(repo, lockedRel), 0o644);
    git(repo, ["rm", "-q", "--cached", lockedRel]);
    rmSync(join(repo, lockedRel), { force: true });

    // Exit-2 diagnostics are also a publication boundary: a confidential unreadable name must be
    // identified only by an opaque key and must never be copied into CI evidence.
    {
      const lockedSecretRel = join("locked", `${canary}.md`);
      const lockedSecretPath = join(repo, lockedSecretRel);
      mkdirSync(dirname(lockedSecretPath), { recursive: true });
      writeFileSync(lockedSecretPath, "harmless unreadable fixture\n");
      git(repo, ["add", lockedSecretRel]);
      chmodSync(lockedSecretPath, 0o000);
      const unreadable = run(["--lane", "L-WT"]);
      const leaked = unreadable.out.includes(canary);
      check(
        ARM_TASK3_CASES.unreadablePathRedacted,
        unreadable.code === 2 && unreadable.protocolComplete
          && unreadable.findings.some((finding) => finding.rule === "SETUP_FAILED")
          && !leaked,
        `exit ${unreadable.code}; protocol complete ${unreadable.protocolComplete}; `
          + `raw path disclosed: ${leaked}`,
      );
      chmodSync(lockedSecretPath, 0o644);
      git(repo, ["rm", "-q", "--cached", lockedSecretRel]);
      rmSync(dirname(lockedSecretPath), { recursive: true, force: true });
    }

    // The wrong root. The gate is copied one directory DEEPER, so its own location no longer equals
    // git's toplevel — the shape of a gate invoked against a tree it does not belong to.
    {
      const deep = join(repo, "sub");
      mkdirSync(join(deep, "scripts", "lib"), { recursive: true });
      mkdirSync(join(deep, ".github", "workflows"), { recursive: true });
      copyAllowlistedGateFiles(root, deep);
      for (const n of backup.keys()) writeFileSync(join(deep, "scripts", n), backup.get(n));
      const r = spawnSync(process.execPath, [
        join(deep, "scripts", "lint-boundary.mjs"), "--lane", "L-WT",
        "--repo-visibility-source", "snapshot", "--knockout-json",
      ], { cwd: repo, encoding: "utf8", shell: false, env: { ...process.env, HOME: armHome } });
      const observed = observeBoundaryGateChild({
        code: r.status,
        error: r.error,
        signal: r.signal,
        stdout: r.stdout ?? "",
        stderr: r.stderr ?? "",
        expectation: BOUNDARY_CANDIDATE_TIER_A_GATE_EXPECTATION,
      });
      check(
        ARM_STATIC_CASES.case_fail_closed_the_gate_is_not_at_the_root_of_the_tree_it_scans_exits_2,
        r.status === 2 && observed.code === null && observed.observedCode === 2
          && !observed.protocolComplete && observed.findings.length === 0,
        `observed exit ${r.status}; credited exit ${observed.code}; protocol complete ${observed.protocolComplete}`,
      );
      rmSync(deep, { recursive: true, force: true });
    }

    // An empty derivation where empty is impossible.
    {
      const bare = join(work, "bare");
      mkdirSync(join(bare, "scripts", "lib"), { recursive: true });
      mkdirSync(join(bare, ".github", "workflows"), { recursive: true });
      git(bare, ["init", "-q", "-b", "main"], true);
      copyAllowlistedGateFiles(root, bare);
      for (const n of backup.keys()) writeFileSync(join(bare, "scripts", n), backup.get(n));
      materializeScannerRuntime(root, bare);
      // Nothing is tracked and everything present is excluded, so L-WT derives zero units.
      writeFileSync(join(bare, ".gitignore"), "*\n");
      const r = spawnSync(process.execPath, [
        join(bare, "scripts", "lint-boundary.mjs"), "--lane", "L-WT",
        "--repo-visibility-source", "snapshot", "--knockout-json",
      ], { cwd: bare, encoding: "utf8", shell: false, env: { ...process.env, HOME: armHome } });
      check(
        ARM_STATIC_CASES.case_fail_closed_a_lane_deriving_zero_units_exits_2,
        r.status === 2,
        `observed exit ${r.status}; child output withheld`,
      );
    }

    notes.push(
      `${armed.size} content lane(s) and ${pathArmed.size} published-path representation(s) armed; `
        + "L-PACK/L-MAP consumed lifecycle-free exact tarball bytes",
    );
    const custodyBarriersAtEnd = custodyBarrierCountsForSelftest();
    check(
      ARM_STATIC_CASES.case_custody_durability_real_operations_exercise_both_file_and_direc_80be3bf0,
      custodyBarriersAtEnd.file > custodyBarriersAtStart.file
        && custodyBarriersAtEnd.directory > custodyBarriersAtStart.directory,
      `file barriers ${custodyBarriersAtEnd.file - custodyBarriersAtStart.file}; ` +
        `directory barriers ${custodyBarriersAtEnd.directory - custodyBarriersAtStart.directory}`,
    );
  } finally {
    rmSync(work, { recursive: true, force: true });
  }

  // ── 5. the real tree is exactly as it was found ────────────────────────────────────────────────
  const dirty = spawnSync("git", ["status", "--porcelain"], { cwd: root, encoding: "utf8", shell: false });
  check(ARM_STATIC_CASES.case_the_real_working_tree_is_exactly_as_the_arm_found_it,
    dirty.status === 0 && String(dirty.stdout).trim() === treeAtStart,
    "an arm that cannot return the tree it borrowed is a failing verdict, not a passing one");

  return finishArm(notes);
}

async function runEvidenceSpoolHarness({ canary, check, repo, root, run, work }) {
  const event = "BOUNDARY_GATE_VERDICT";
  const aggregateMetrics = {
    blocking: 0,
    carried: 0,
    keyId: "b".repeat(64),
    lanes: [{ id: "L-WT", status: "scanned", units: 1 }],
    ledgerEntries: 0,
    privateInputsEvidence: "SNAPSHOT_NON_CLAIM",
    repositoryVisibilityEvidence: "SNAPSHOT_NON_CLAIM",
    repositoryVisibilityObservedAt: "2026-08-30T00:00:00.000Z",
    scannedUnits: 1,
    suppressed: 0,
    tier: "ab",
  };
  const prepushMetrics = {
    greenSteps: 1,
    overrideReasonSha256: null,
    overrideReasonUtf8Bytes: 0,
    redSteps: 0,
    setupFailedSteps: 0,
    skippedSteps: 0,
    stepCount: 1,
  };
  const makeSpool = (label, recordEvent = event) => {
    const container = join(work, label);
    mkdirSync(container, { recursive: true, mode: KEY_DIR_MODE });
    return boundaryEvidenceSpoolDirectory(join(container, ".noa-boundary"), recordEvent);
  };
  const payload = (spoolDirectoryPath, overrides = {}) => ({
    spoolDirectoryPath,
    event,
    repositoryHead: "a".repeat(40),
    verdict: "GREEN",
    metrics: aggregateMetrics,
    at: "2026-08-30T00:00:01.000Z",
    ...overrides,
  });
  const dependencyOptions = (index, overrides = {}) => ({
    recordNonceHex: index.toString(16).padStart(64, "0"),
    pendingNonceHex: (index + 1000).toString(16).padStart(32, "0"),
    ...overrides,
  });

  // One monotonic deadline covers readiness, release, crashes, and completion. Each await consumes
  // the remaining budget; there are no stacked fixed-duration watchdogs.
  const harnessDeadline = process.hrtime.bigint() + 45_000_000_000n;
  const killLive = (records) => {
    for (const record of records) {
      if (record.child.exitCode === null && record.child.signalCode === null) record.child.kill("SIGKILL");
    }
  };
  const withinHarnessDeadline = async (promise, records) => {
    const remainingNs = harnessDeadline - process.hrtime.bigint();
    if (remainingNs <= 0n) {
      killLive(records);
      return { deadline: true, value: null };
    }
    let timer;
    const deadline = new Promise((resolveDeadline) => {
      const remainingMs = Number((remainingNs + 999_999n) / 1_000_000n);
      timer = setTimeout(() => {
        killLive(records);
        resolveDeadline({ deadline: true, value: null });
      }, remainingMs);
    });
    const settled = await Promise.race([
      promise.then((value) => ({ deadline: false, value })),
      deadline,
    ]);
    clearTimeout(timer);
    return settled;
  };

  const spoolModulePath = join(repo, "scripts", "lib", "boundary-ledger.mjs");
  const spoolChildSource = `
    import { existsSync } from "node:fs";
    import { pathToFileURL } from "node:url";
    const [modulePath, payloadText, optionsText, releasePath, deadlineText] = process.argv.slice(1);
    const payload = JSON.parse(Buffer.from(payloadText, "base64url").toString("utf8"));
    const options = JSON.parse(Buffer.from(optionsText, "base64url").toString("utf8"));
    const { appendBoundaryLedgerRecord, boundarySpoolTestDependencies } = await import(pathToFileURL(modulePath).href);
    process.stdout.write("READY\\n");
    const wait = new Int32Array(new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT));
    const deadline = BigInt(deadlineText);
    while (!existsSync(releasePath) && process.hrtime.bigint() < deadline) Atomics.wait(wait, 0, 0, 2);
    if (!existsSync(releasePath)) throw new Error("absolute spool harness deadline expired");
    const result = appendBoundaryLedgerRecord(payload, boundarySpoolTestDependencies(options));
    process.stdout.write(\`RESULT \${JSON.stringify(result)}\\n\`);
  `;
  const spawnSpoolChild = (recordPayload, options, releasePath) => {
    const child = spawn(process.execPath, [
      "--input-type=module", "--eval", spoolChildSource,
      spoolModulePath,
      Buffer.from(JSON.stringify(recordPayload), "utf8").toString("base64url"),
      Buffer.from(JSON.stringify(options), "utf8").toString("base64url"),
      releasePath,
      harnessDeadline.toString(),
    ], { cwd: repo, stdio: ["ignore", "pipe", "pipe"], env: process.env });
    let stdout = "";
    let stderr = "";
    let readySeen = false;
    let readyResolve;
    const ready = new Promise((resolveReady) => { readyResolve = resolveReady; });
    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString("utf8");
      if (!readySeen && stdout.includes("READY\n")) {
        readySeen = true;
        readyResolve(true);
      }
    });
    child.stderr.on("data", (chunk) => { stderr += chunk.toString("utf8"); });
    const done = new Promise((resolveDone) => child.once("close", (code, signal) => {
      if (!readySeen) readyResolve(false);
      const line = stdout.split(/\r?\n/).find((candidate) => candidate.startsWith("RESULT "));
      let result = null;
      try { result = line === undefined ? null : JSON.parse(line.slice(7)); } catch { /* asserted */ }
      resolveDone({ code, signal, result, out: `${stdout}${stderr}` });
    }));
    return { child, done, ready };
  };

  const legacyChildSource = `
    import { closeSync, constants, existsSync, fsyncSync, openSync, writeSync } from "node:fs";
    const [path, bytesText, releasePath, deadlineText] = process.argv.slice(1);
    const bytes = Buffer.from(bytesText, "base64url");
    process.stdout.write("READY\\n");
    const wait = new Int32Array(new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT));
    const deadline = BigInt(deadlineText);
    while (!existsSync(releasePath) && process.hrtime.bigint() < deadline) Atomics.wait(wait, 0, 0, 2);
    if (!existsSync(releasePath)) throw new Error("absolute spool harness deadline expired");
    const fd = openSync(path, constants.O_WRONLY | constants.O_APPEND);
    const written = writeSync(fd, bytes);
    fsyncSync(fd);
    closeSync(fd);
    process.stdout.write(\`RESULT \${JSON.stringify({ written })}\\n\`);
  `;
  const spawnLegacyChild = (path, bytes, releasePath) => {
    const child = spawn(process.execPath, [
      "--input-type=module", "--eval", legacyChildSource,
      path, Buffer.from(bytes).toString("base64url"), releasePath, harnessDeadline.toString(),
    ], { cwd: repo, stdio: ["ignore", "pipe", "pipe"], env: process.env });
    let stdout = "";
    let stderr = "";
    let readySeen = false;
    let readyResolve;
    const ready = new Promise((resolveReady) => { readyResolve = resolveReady; });
    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString("utf8");
      if (!readySeen && stdout.includes("READY\n")) { readySeen = true; readyResolve(true); }
    });
    child.stderr.on("data", (chunk) => { stderr += chunk.toString("utf8"); });
    const done = new Promise((resolveDone) => child.once("close", (code, signal) => {
      if (!readySeen) readyResolve(false);
      const line = stdout.split(/\r?\n/).find((candidate) => candidate.startsWith("RESULT "));
      let result = null;
      try { result = line === undefined ? null : JSON.parse(line.slice(7)); } catch { /* asserted */ }
      resolveDone({ code, signal, result, out: `${stdout}${stderr}` });
    }));
    return { child, done, ready };
  };

  let releaseSequence = 0;
  const releaseBatch = async (recordsOrFactory) => {
    const releasePath = join(work, `.spool-release-${++releaseSequence}`);
    const records = typeof recordsOrFactory === "function"
      ? recordsOrFactory(releasePath)
      : recordsOrFactory;
    for (const record of records) record.releasePath = releasePath;
    const ready = await withinHarnessDeadline(Promise.all(records.map((record) => record.ready)), records);
    if (!ready.deadline && ready.value.every(Boolean)) {
      writeFileSync(releasePath, "release\n", { flag: "wx", mode: KEY_MODE });
      chmodSync(releasePath, KEY_MODE);
    }
    const done = await withinHarnessDeadline(Promise.all(records.map((record) => record.done)), records);
    rmSync(releasePath, { force: true });
    return {
      ready: !ready.deadline && ready.value.every(Boolean),
      results: done.deadline ? [] : done.value,
    };
  };

  // 25 distinct records race while an actual legacy append mutates only its historical JSONL.
  const concurrentSpool = makeSpool("spool-concurrent");
  const boundaryRoot = dirname(dirname(concurrentSpool));
  mkdirSync(boundaryRoot, { recursive: true, mode: KEY_DIR_MODE });
  chmodSync(boundaryRoot, KEY_DIR_MODE);
  const legacyBoundaryPath = join(boundaryRoot, "ledger.jsonl");
  const legacyPrepushPath = join(boundaryRoot, "prepush-ledger.jsonl");
  const legacyInitial = Buffer.from("legacy-boundary-v1\n", "utf8");
  const legacyAppend = Buffer.from("legacy-writer-concurrent\n", "utf8");
  const legacyPrepushInitial = Buffer.from("legacy-prepush-v1\n", "utf8");
  writeFileSync(legacyBoundaryPath, legacyInitial, { mode: KEY_MODE });
  writeFileSync(legacyPrepushPath, legacyPrepushInitial, { mode: KEY_MODE });
  chmodSync(legacyBoundaryPath, KEY_MODE);
  chmodSync(legacyPrepushPath, KEY_MODE);
  const legacyBoundaryBefore = lstatSync(legacyBoundaryPath);
  const legacyPrepushBefore = lstatSync(legacyPrepushPath);
  const uniqueCount = 25;
  const uniqueInputs = Array.from({ length: uniqueCount }, (_, index) => payload(concurrentSpool, {
    at: `2026-08-30T00:00:${String(index + 10).padStart(2, "0")}.000Z`,
  }));
  const uniqueOptions = uniqueInputs.map((_input, index) => dependencyOptions(index + 1));
  const uniquePrepared = uniqueInputs.map((input, index) => prepareBoundaryEvidenceRecord(
    input,
    boundarySpoolTestDependencies(uniqueOptions[index]),
  ));
  const uniqueRelease = join(work, `.spool-release-${releaseSequence + 1}`);
  const uniqueChildren = uniqueInputs.map((input, index) => spawnSpoolChild(input, uniqueOptions[index], uniqueRelease));
  const legacyChild = spawnLegacyChild(legacyBoundaryPath, legacyAppend, uniqueRelease);
  const uniquePhase = await releaseBatch([...uniqueChildren, legacyChild]);
  const uniqueResults = uniquePhase.results.slice(0, uniqueCount);
  const legacyResult = uniquePhase.results[uniqueCount] ?? null;
  const uniqueCensus = inspectBoundaryEvidenceSpool({ spoolDirectoryPath: concurrentSpool, event });
  const expectedIds = uniquePrepared.map((entry) => entry.recordId).sort();
  const actualIds = uniqueResults.map((entry) => entry.result?.recordId).sort();
  const finalNames = readdirSync(concurrentSpool).filter((name) => name.startsWith("record-v2-")).sort();
  const expectedNames = uniquePrepared.map((entry) => entry.filename).sort();
  check(
    ARM_STATIC_CASES.case_evidence_spool_concurrency_25_unique_writers_publish_the_exact__b28c797d,
    uniquePhase.ready && uniqueResults.length === uniqueCount
      && uniqueResults.every((entry) => entry.code === 0 && entry.signal === null && entry.result?.ok)
      && canonicalJson(actualIds) === canonicalJson(expectedIds)
      && canonicalJson(finalNames) === canonicalJson(expectedNames)
      && uniqueCensus.validCount === uniqueCount && uniqueCensus.pendingCount === uniqueCount
      && uniqueCensus.cleanupResidueCount === uniqueCount && uniqueCensus.malformedCount === 0,
    `ready ${uniquePhase.ready}; results ${uniqueResults.length}/${uniqueCount}; `
      + `valid/pending/residue/malformed ${uniqueCensus.validCount}/${uniqueCensus.pendingCount}/`
      + `${uniqueCensus.cleanupResidueCount}/${uniqueCensus.malformedCount}`,
  );
  const expectedLegacyBoundary = Buffer.concat([legacyInitial, legacyAppend]);
  const legacyBoundaryAfter = lstatSync(legacyBoundaryPath);
  const legacyPrepushAfter = lstatSync(legacyPrepushPath);
  check(
    ARM_STATIC_CASES.case_evidence_spool_provenance_concurrent_legacy_and_v2_writers_muta_b4058f4f,
    legacyResult?.code === 0 && legacyResult?.result?.written === legacyAppend.length
      && legacyBoundaryAfter.ino === legacyBoundaryBefore.ino
      && legacyBoundaryAfter.size === expectedLegacyBoundary.length
      && readFileSync(legacyBoundaryPath).equals(expectedLegacyBoundary)
      && createHash("sha256").update(readFileSync(legacyBoundaryPath)).digest("hex")
        === createHash("sha256").update(expectedLegacyBoundary).digest("hex")
      && legacyPrepushAfter.ino === legacyPrepushBefore.ino
      && legacyPrepushAfter.size === legacyPrepushBefore.size
      && readFileSync(legacyPrepushPath).equals(legacyPrepushInitial),
    `legacy child ${legacyResult?.code}/${legacyResult?.signal}; boundary inode stable `
      + `${legacyBoundaryAfter.ino === legacyBoundaryBefore.ino}; prepush bytes stable `
      + `${readFileSync(legacyPrepushPath).equals(legacyPrepushInitial)}`,
  );

  // Same body and injected nonce means one stable recordId; concurrent retries converge on one final.
  const idempotentSpool = makeSpool("spool-idempotent");
  const sameInput = payload(idempotentSpool);
  const sameOptions = dependencyOptions(900);
  const samePrepared = prepareBoundaryEvidenceRecord(sameInput, boundarySpoolTestDependencies(sameOptions));
  const sameRelease = join(work, `.spool-release-${releaseSequence + 1}`);
  const sameChildren = Array.from({ length: 24 }, () => spawnSpoolChild(sameInput, sameOptions, sameRelease));
  const samePhase = await releaseBatch(sameChildren);
  const sameCensus = inspectBoundaryEvidenceSpool({ spoolDirectoryPath: idempotentSpool, event });
  const samePendingPids = readdirSync(idempotentSpool)
    .map((name) => /-p([1-9][0-9]{0,15})-[0-9a-f]{32}\.json$/.exec(name)?.[1] ?? null)
    .filter((pid) => pid !== null);
  const sameChildPids = new Set(sameChildren.map((record) => String(record.child.pid)));
  check(
    ARM_STATIC_CASES.case_evidence_spool_idempotency_24_concurrent_stable_id_writers_conv_ad1f6605,
    samePhase.ready && samePhase.results.length === sameChildren.length
      && samePhase.results.every((entry) => entry.code === 0 && entry.signal === null
        && entry.result?.ok && entry.result.recordId === samePrepared.recordId)
      && samePhase.results.filter((entry) => entry.result?.created).length === 1
      && sameCensus.validCount === 1 && sameCensus.pendingCount === samePendingPids.length
      && sameCensus.pendingCount >= sameCensus.cleanupResidueCount
      && sameCensus.pendingCount <= sameChildren.length
      && new Set(samePendingPids).size === samePendingPids.length
      && samePendingPids.every((pid) => sameChildPids.has(pid))
      && sameCensus.cleanupResidueCount === 1 && sameCensus.malformedCount === 0,
    `ready ${samePhase.ready}; results ${samePhase.results.length}/24; created `
      + `${samePhase.results.filter((entry) => entry.result?.created).length}; `
      + `ok ${samePhase.results.filter((entry) => entry.result?.ok).length}; `
      + `ids ${new Set(samePhase.results.map((entry) => entry.result?.recordId)).size}; `
      + `codes ${canonicalJson(samePhase.results.map((entry) => entry.result?.code ?? "OK"))}; `
      + `valid/pending/residue/malformed ${sameCensus.validCount}/${sameCensus.pendingCount}/`
      + `${sameCensus.cleanupResidueCount}/${sameCensus.malformedCount}; `
      + `pending child pids ${samePendingPids.length}/${sameChildren.length}`,
  );

  await runEvidenceSpoolFaultHarness({
    aggregateMetrics, canary, check, dependencyOptions, event, harnessDeadline, makeSpool,
    payload, prepushMetrics, releaseBatch, repo, root, run, spawnSpoolChild, work,
  });
}

async function runEvidenceSpoolFaultHarness({
  aggregateMetrics,
  canary,
  check,
  dependencyOptions,
  event,
  makeSpool,
  payload,
  prepushMetrics,
  releaseBatch,
  repo,
  run,
  spawnSpoolChild,
  work,
}) {
  // Load-bearing primitive counts make removing readback or either spool-specific synchronization
  // call observable even on a filesystem whose cache happens to survive the test process.
  const primitiveSpool = makeSpool("spool-primitives");
  const primitiveInput = payload(primitiveSpool);
  const primitiveOptions = dependencyOptions(1001);
  const countsBefore = boundarySpoolPrimitiveCountsForSelftest();
  const primitiveResult = appendBoundaryLedgerRecord(
    primitiveInput,
    boundarySpoolTestDependencies(primitiveOptions),
  );
  const countsAfter = boundarySpoolPrimitiveCountsForSelftest();
  check(
    ARM_STATIC_CASES.case_evidence_spool_primitives_o_excl_publication_executes_exact_rea_a3653b8f,
    primitiveResult.ok
      && countsAfter.pendingReadback - countsBefore.pendingReadback === 1
      && countsAfter.fileSync - countsBefore.fileSync === 2
      && countsAfter.directorySync - countsBefore.directorySync === 1,
    `ok ${primitiveResult.ok}; readback ${countsAfter.pendingReadback - countsBefore.pendingReadback}; `
      + `file fsync ${countsAfter.fileSync - countsBefore.fileSync}; `
      + `directory fsync ${countsAfter.directorySync - countsBefore.directorySync}`,
  );

  // A deterministic pending-name collision is the O_EXCL discriminator. The existing artifact is
  // exact-length so a mutant that merely opens it can overwrite and consume it.
  const collisionSpool = makeSpool("spool-o-excl-collision");
  mkdirSync(collisionSpool, { recursive: true, mode: KEY_DIR_MODE });
  chmodSync(dirname(dirname(collisionSpool)), KEY_DIR_MODE);
  chmodSync(dirname(collisionSpool), KEY_DIR_MODE);
  chmodSync(collisionSpool, KEY_DIR_MODE);
  const collisionInput = payload(collisionSpool);
  const collisionOptions = dependencyOptions(1002);
  const collisionPrepared = prepareBoundaryEvidenceRecord(
    collisionInput,
    boundarySpoolTestDependencies(collisionOptions),
  );
  const collisionPending = join(
    collisionSpool,
    `.pending-v${collisionPrepared.schemaVersion}-${collisionPrepared.recordId}-${collisionPrepared.bytes.length}`
      + `-p${process.pid}-${collisionOptions.pendingNonceHex}.json`,
  );
  const collisionSentinel = Buffer.alloc(collisionPrepared.bytes.length, 0x5a);
  writeFileSync(collisionPending, collisionSentinel, { flag: "wx", mode: KEY_MODE });
  chmodSync(collisionPending, KEY_MODE);
  const collisionResult = appendBoundaryLedgerRecord(
    collisionInput,
    boundarySpoolTestDependencies(collisionOptions),
  );
  const collisionPreserved = existsSync(collisionPending)
    && readFileSync(collisionPending).equals(collisionSentinel);
  check(
    ARM_STATIC_CASES.case_evidence_spool_o_excl_an_occupied_deterministic_pending_name_is_f620f964,
    !collisionResult.ok && collisionResult.code === "PENDING_NAME_COLLISION"
      && collisionPreserved
      && !existsSync(join(collisionSpool, collisionPrepared.filename)),
    `ok ${collisionResult.ok}; code ${collisionResult.code}; sentinel preserved `
      + `${collisionPreserved}`,
  );

  const rawMarker = "boundary-spool-raw-marker-must-never-appear";
  const rawSpool = makeSpool("spool-raw-field");
  const rawResult = appendBoundaryLedgerRecord(
    { ...payload(rawSpool), raw: rawMarker },
    boundarySpoolTestDependencies(dependencyOptions(1003)),
  );
  check(
    ARM_STATIC_CASES.case_evidence_spool_schema_a_raw_top_level_field_is_rejected_before__1f68ad45,
    !rawResult.ok && rawResult.code === "RECORD_SCHEMA_REJECTED"
      && !rawResult.warning.includes(rawMarker) && !existsSync(rawSpool),
    `ok ${rawResult.ok}; code ${rawResult.code}; warning bytes ${Buffer.byteLength(rawResult.warning ?? "")}`,
  );

  // Stable ID plus changed final bytes is conflict/tamper, never idempotent success.
  const tamperSpool = makeSpool("spool-tamper");
  const tamperInput = payload(tamperSpool);
  const tamperOptions = dependencyOptions(1004);
  const tamperDependencies = boundarySpoolTestDependencies(tamperOptions);
  const tamperFirst = appendBoundaryLedgerRecord(tamperInput, tamperDependencies);
  const tamperPath = join(tamperSpool, tamperFirst.filename);
  const tamperedBytes = Buffer.from(readFileSync(tamperPath));
  tamperedBytes[Math.floor(tamperedBytes.length / 2)] ^= 0x01;
  chmodSync(tamperPath, KEY_MODE);
  writeFileSync(tamperPath, tamperedBytes);
  chmodSync(tamperPath, 0o400);
  const tamperRetry = appendBoundaryLedgerRecord(tamperInput, tamperDependencies);
  check(
    ARM_STATIC_CASES.case_evidence_spool_collision_the_same_recordid_with_changed_bytes_i_adffa499,
    tamperFirst.ok && !tamperRetry.ok && tamperRetry.code === "SPOOL_RECORD_CONFLICT"
      && tamperRetry.evidenceState === "NOT_PERSISTED"
      && readFileSync(tamperPath).equals(tamperedBytes),
    `first ${tamperFirst.ok}; retry ${tamperRetry.ok}; code ${tamperRetry.code}; `
      + `state ${tamperRetry.evidenceState}`,
  );

  // Crash matrix: pending-only never becomes a record; link-before-directory-sync is indeterminate;
  // directory-synced link plus reserved alias is persisted with explicit cleanup residue.
  const crashCases = [
    { name: "create", point: "pending-create-after", writeChunkBytes: null, state: "NOT_PERSISTED" },
    { name: "partial-write", point: "partial-write", writeChunkBytes: 17, state: "NOT_PERSISTED" },
    { name: "file-fsync", point: "content-file-fsync-after", writeChunkBytes: null, state: "NOT_PERSISTED" },
    { name: "link", point: "final-link-after", writeChunkBytes: null, state: "INDETERMINATE" },
    { name: "directory-fsync", point: "publish-dir-fsync-after", writeChunkBytes: null, state: "PERSISTED" },
    {
      name: "retained-alias",
      point: "candidate-retained-before-return",
      writeChunkBytes: null,
      state: "PERSISTED",
    },
  ];
  const crashObservations = [];
  for (const [index, crashCase] of crashCases.entries()) {
    const spoolDirectoryPath = makeSpool(`spool-crash-${crashCase.name}`);
    const recordPayload = payload(spoolDirectoryPath);
    const options = dependencyOptions(1100 + index, {
      faultAction: "crash",
      faultCode: "EIO",
      faultPoint: crashCase.point,
      ...(crashCase.writeChunkBytes === null ? {} : { writeChunkBytes: crashCase.writeChunkBytes }),
    });
    const prepared = prepareBoundaryEvidenceRecord(
      recordPayload,
      boundarySpoolTestDependencies(options),
    );
    const phase = await releaseBatch((releasePath) => [spawnSpoolChild(recordPayload, options, releasePath)]);
    const child = phase.results[0] ?? null;
    const census = inspectBoundaryEvidenceSpool({ spoolDirectoryPath, event });
    const finalExists = existsSync(join(spoolDirectoryPath, prepared.filename));
    const observedState = !finalExists
      ? "NOT_PERSISTED"
      : (crashCase.state === "PERSISTED" ? "PERSISTED" : "INDETERMINATE");
    crashObservations.push({
      ...crashCase,
      child,
      census,
      finalExists,
      observedState,
      ready: phase.ready,
    });
  }
  check(
    ARM_STATIC_CASES.case_evidence_spool_crash_matrix_create_partial_fsync_link_dir_fsync_cb85698e,
    crashObservations.every((entry) => entry.ready && entry.child?.code === null
      && entry.child?.signal === "SIGKILL" && entry.child?.result === null
      && entry.observedState === entry.state
      && (entry.state === "NOT_PERSISTED"
        ? entry.census.validCount === 0 && entry.census.pendingCount === 1
        : entry.census.validCount === 1 && entry.census.pendingCount === 1
          && entry.census.cleanupResidueCount === 1)),
    canonicalJson(crashObservations.map((entry) => ({
      name: entry.name,
      signal: entry.child?.signal,
      state: entry.observedState,
      valid: entry.census.validCount,
      pending: entry.census.pendingCount,
      residue: entry.census.cleanupResidueCount,
    }))),
  );
  const partialObservation = crashObservations.find((entry) => entry.name === "partial-write");
  check(
    ARM_STATIC_CASES.case_evidence_spool_reader_a_partial_pending_artifact_is_never_count_17d91c2f,
    partialObservation?.census.validCount === 0 && partialObservation?.census.pendingCount === 1,
  );

  const faultCases = [
    {
      name: "storage reserve",
      options: dependencyOptions(1200, { statfs: { bavail: "1", blocks: "1000000", bsize: "4096" } }),
      code: "SPOOL_CAPACITY_REACHED",
      state: "NOT_PERSISTED",
    },
    {
      name: "ENOSPC",
      options: dependencyOptions(1201, { faultAction: "throw", faultCode: "ENOSPC", faultPoint: "pending-write-before" }),
      code: "INJECTED_ENOSPC",
      state: "NOT_PERSISTED",
    },
    {
      name: "zero write",
      options: dependencyOptions(1202, { faultAction: "zero-write", faultCode: "EIO", faultPoint: "pending-write" }),
      code: "SHORT_WRITE",
      state: "NOT_PERSISTED",
    },
    {
      name: "file fsync",
      options: dependencyOptions(1203, { faultAction: "throw", faultCode: "EIO", faultPoint: "content-file-fsync-before" }),
      code: "INJECTED_EIO",
      state: "NOT_PERSISTED",
    },
    {
      name: "directory fsync",
      options: dependencyOptions(1204, { faultAction: "throw", faultCode: "EIO", faultPoint: "publish-dir-fsync-before" }),
      code: "INJECTED_EIO",
      state: "INDETERMINATE",
    },
    {
      name: "retained alias",
      options: dependencyOptions(1205, {
        faultAction: "throw",
        faultCode: "EIO",
        faultPoint: "candidate-retained-before-return",
      }),
      code: "INJECTED_EIO",
      state: "PERSISTED",
    },
    {
      name: "close",
      options: dependencyOptions(1206, { faultAction: "throw", faultCode: "EIO", faultPoint: "close" }),
      code: "INJECTED_EIO",
      state: "PERSISTED",
    },
  ];
  const faultResults = faultCases.map((faultCase, index) => {
    const spoolDirectoryPath = makeSpool(`spool-fault-${index}`);
    const result = appendBoundaryLedgerRecord(
      payload(spoolDirectoryPath),
      boundarySpoolTestDependencies(faultCase.options),
    );
    const census = inspectBoundaryEvidenceSpool({ spoolDirectoryPath, event });
    return { ...faultCase, census, result };
  });
  const shortSpool = makeSpool("spool-short-write-success");
  const shortResult = appendBoundaryLedgerRecord(
    payload(shortSpool),
    boundarySpoolTestDependencies(dependencyOptions(1210, { writeChunkBytes: 7 })),
  );
  check(
    ARM_STATIC_CASES.case_evidence_spool_storage_faults_reserve_enospc_zero_write_fsync_r_809a55df,
    shortResult.ok && faultResults.every((entry) => !entry.result.ok
      && entry.result.code === entry.code && entry.result.evidenceState === entry.state
      && (entry.state === "PERSISTED") === entry.result.evidencePersisted),
    canonicalJson(faultResults.map((entry) => ({
      name: entry.name, code: entry.result.code ?? "OK", state: entry.result.evidenceState ?? "UNKNOWN",
      valid: entry.census.validCount, pending: entry.census.pendingCount,
    }))),
  );

  // Census rejects every reader-confusing shape and exposes physical/logical pressure without
  // deleting it: bad names, hash mismatch, symlink, wrong mode, and unexplained extra hard link.
  const malformedSpool = makeSpool("spool-malformed");
  const malformedInput = payload(malformedSpool);
  const malformedOptions = dependencyOptions(1300);
  const malformedFirst = appendBoundaryLedgerRecord(
    malformedInput,
    boundarySpoolTestDependencies(malformedOptions),
  );
  const validPath = join(malformedSpool, malformedFirst.filename);
  const validBytes = readFileSync(validPath);
  const externalAlias = join(dirname(dirname(malformedSpool)), "extra-hard-link-alias");
  linkSync(validPath, externalAlias);
  writeFileSync(join(malformedSpool, `record-v2-${"f".repeat(64)}-${validBytes.length}.json`), validBytes, { mode: 0o400 });
  const wrongModePath = join(malformedSpool, `record-v2-${"e".repeat(64)}-${validBytes.length}.json`);
  writeFileSync(wrongModePath, validBytes, { mode: KEY_MODE });
  chmodSync(wrongModePath, KEY_MODE);
  const symlinkTarget = join(dirname(malformedSpool), "symlink-target");
  writeFileSync(symlinkTarget, "unchanged\n", { mode: KEY_MODE });
  symlinkSync(symlinkTarget, join(malformedSpool, `record-v2-${"d".repeat(64)}-10.json`));
  writeFileSync(join(malformedSpool, "record-v2-malformed.json"), "malformed\n", { mode: 0o400 });
  const malformedCensus = inspectBoundaryEvidenceSpool({ spoolDirectoryPath: malformedSpool, event });
  const extraLinkRetry = appendBoundaryLedgerRecord(
    malformedInput,
    boundarySpoolTestDependencies(malformedOptions),
  );
  const ownerStat = lstatSync(wrongModePath);
  check(
    ARM_STATIC_CASES.case_evidence_spool_census_symlink_mode_owner_name_hash_extra_link_a_612a77dc,
    !extraLinkRetry.ok && extraLinkRetry.code === "FILE_LINK_COUNT_REJECTED"
      && malformedCensus.validCount === 0 && malformedCensus.malformedCount >= 5
      && BigInt(malformedCensus.logicalBytes) > 0n && BigInt(malformedCensus.allocatedBytes) > 0n
      && boundarySpoolArtifactCustodyProblem(ownerStat, {
        allowLinks: [1], allowedModes: [KEY_MODE], expectedUid: ownerStat.uid + 1,
      }) === "FILE_OWNER_REJECTED"
      && existsSync(externalAlias) && existsSync(wrongModePath),
    `retry ${extraLinkRetry.code}; valid/pending/malformed `
      + `${malformedCensus.validCount}/${malformedCensus.pendingCount}/${malformedCensus.malformedCount}; `
      + `logical/allocated ${malformedCensus.logicalBytes}/${malformedCensus.allocatedBytes}`,
  );

  // The second production stream is a disjoint directory, not a dual write into the boundary stream.
  const prepushSpool = makeSpool("spool-prepush", "PREPUSH_GATE_VERDICT");
  const prepushResult = appendBoundaryLedgerRecord({
    spoolDirectoryPath: prepushSpool,
    event: "PREPUSH_GATE_VERDICT",
    repositoryHead: "c".repeat(40),
    verdict: "GREEN",
    metrics: prepushMetrics,
    at: "2026-08-30T00:01:00.000Z",
  }, boundarySpoolTestDependencies(dependencyOptions(1400)));
  const prepushCensus = inspectBoundaryEvidenceSpool({
    spoolDirectoryPath: prepushSpool,
    event: "PREPUSH_GATE_VERDICT",
  });
  check(
    ARM_STATIC_CASES.case_evidence_spool_streams_boundary_and_pre_push_records_use_disjoi_f2c12c2e,
    prepushResult.ok && basename(prepushSpool) === "prepush"
      && prepushCensus.validCount === 1 && prepushCensus.pendingCount === 1
      && prepushCensus.cleanupResidueCount === 1
      && !existsSync(join(dirname(dirname(prepushSpool)), "ledger.jsonl"))
      && !existsSync(join(dirname(dirname(prepushSpool)), "prepush-ledger.jsonl")),
  );

  // Actual lifecycle-free pack bytes must exclude scripts/**. Planting the tier-B canary only in
  // the copied writer proves L-WT can see it while L-PACK cannot because package.json excludes it.
  const copiedWriter = join(repo, "scripts", "lib", "boundary-ledger.mjs");
  const copiedWriterBefore = readFileSync(copiedWriter, "utf8");
  writeFileSync(copiedWriter, `${copiedWriterBefore}\n// ${canary}\n`);
  const packed = run(["--lane", "L-PACK"]);
  const worktree = run(["--lane", "L-WT"]);
  writeFileSync(copiedWriter, copiedWriterBefore);
  check(
    ARM_STATIC_CASES.case_evidence_spool_package_containment_scripts_are_absent_from_exac_abc830ea,
    packed.code === 0 && worktree.code === 1
      && worktree.findings.some((finding) => finding.rule === "token-commitment"),
    `L-PACK ${packed.code}; L-WT ${worktree.code}; rules `
      + `${canonicalJson(worktree.findings.map((finding) => finding.rule))}\n`
      + `${worktree.out.slice(0, 900)}`,
  );
}

function isolatedArmHookEnvironment(armHome) {
  const environment = { ...process.env };
  for (const name of [
    "NOA_BOUNDARY_AUTHORIZATION_FD",
    "NOA_BOUNDARY_AUTHORIZATION_FILE",
    "NOA_BOUNDARY_INTERNAL_BOOTSTRAP_MODE",
    "NOA_BOUNDARY_SYNTHETIC_SUPERVISOR_FIXTURE",
    "NOA_BOUNDARY_ROTATION_RELEASE_FILE",
    "NOA_BOUNDARY_IMMUTABLE_RELEASE_FILE",
  ]) delete environment[name];
  Object.assign(environment, {
    HOME: armHome,
    XDG_CACHE_HOME: join(armHome, ".cache"),
    XDG_CONFIG_HOME: join(armHome, ".config"),
    XDG_DATA_HOME: join(armHome, ".local", "share"),
    XDG_STATE_HOME: join(armHome, ".local", "state"),
    GIT_CONFIG_GLOBAL: join(armHome, ".gitconfig"),
    GIT_CONFIG_NOSYSTEM: "1",
    NPM_CONFIG_CACHE: join(armHome, ".npm-cache"),
    NPM_CONFIG_USERCONFIG: join(armHome, ".npmrc"),
    NOA_SKIP_PREPUSH: "synthetic arm exercises the mandatory boundary step only",
    npm_config_cache: join(armHome, ".npm-cache"),
    npm_config_userconfig: join(armHome, ".npmrc"),
  });
  return Object.freeze(environment);
}

function hookEnvironmentTargetsArmHome(environment, armHome) {
  const expected = resolve(armHome);
  return environment.HOME === armHome
    && [
      environment.XDG_CACHE_HOME,
      environment.XDG_CONFIG_HOME,
      environment.XDG_DATA_HOME,
      environment.XDG_STATE_HOME,
      environment.GIT_CONFIG_GLOBAL,
      environment.NPM_CONFIG_CACHE,
      environment.NPM_CONFIG_USERCONFIG,
      environment.npm_config_cache,
      environment.npm_config_userconfig,
    ].every((path) => resolve(path).startsWith(`${expected}${sep}`))
    && environment.NOA_BOUNDARY_AUTHORIZATION_FD === undefined
    && environment.NOA_BOUNDARY_AUTHORIZATION_FILE === undefined
    && environment.NOA_BOUNDARY_INTERNAL_BOOTSTRAP_MODE === undefined;
}

function snapshotSpoolForIsolation(spoolPath) {
  const digest = createHash("sha256");
  let directory;
  try { directory = lstatSync(spoolPath, { throwIfNoEntry: false }); } catch { return Object.freeze({ digest: "UNREADABLE", safe: false }); }
  if (directory === undefined) {
    digest.update("ABSENT\0", "utf8");
    return Object.freeze({ digest: digest.digest("hex"), entryCount: 0, safe: true });
  }
  if (directory.isSymbolicLink() || !directory.isDirectory()) return Object.freeze({ digest: "UNSAFE", entryCount: null, safe: false });
  let names;
  try { names = readdirSync(spoolPath).sort(); } catch { return Object.freeze({ digest: "UNREADABLE", entryCount: null, safe: false }); }
  digest.update(
    `DIRECTORY\0${directory.dev}\0${directory.ino}\0${directory.mode}\0${directory.nlink}\0`
      + `${directory.size}\0${directory.mtimeMs}\0${directory.ctimeMs}\0`,
    "utf8",
  );
  for (const name of names) {
    const path = join(spoolPath, name);
    let stat;
    try { stat = lstatSync(path); } catch { return Object.freeze({ digest: "UNSTABLE", entryCount: null, safe: false }); }
    digest.update(`${name}\0${stat.dev}\0${stat.ino}\0${stat.mode}\0${stat.nlink}\0${stat.size}\0${stat.mtimeMs}\0${stat.ctimeMs}\0`, "utf8");
    if (stat.isFile() && !stat.isSymbolicLink()) {
      try { digest.update(readFileSync(path)); } catch { return Object.freeze({ digest: "UNREADABLE", entryCount: null, safe: false }); }
    }
  }
  return Object.freeze({ digest: digest.digest("hex"), entryCount: names.length, safe: true });
}

function git(cwd, args, allowInit = false, env = undefined) {
  const r = spawnSync("git", args, { cwd, encoding: "utf8", shell: false, ...(env === undefined ? {} : { env }) });
  if (r.status !== 0 && !allowInit) throw new Error("a synthetic Git fixture operation failed");
  return r;
}

function ensureDisposableDirectoryTree(disposableRoot, directory) {
  const exactRoot = resolve(disposableRoot);
  const exactDirectory = resolve(directory);
  const relativeDirectory = relative(exactRoot, exactDirectory);
  if (relativeDirectory === ".." || relativeDirectory.startsWith(`..${sep}`)) {
    throw new Error("the allowlisted gate copy destination escaped its disposable root");
  }
  let cursor = exactRoot;
  const rootStat = lstatSync(cursor, { throwIfNoEntry: false });
  if (rootStat === undefined || rootStat.isSymbolicLink() || !rootStat.isDirectory()) {
    throw new Error("the disposable gate-copy root is not a real directory");
  }
  for (const component of relativeDirectory.split(sep).filter(Boolean)) {
    cursor = join(cursor, component);
    let stat = lstatSync(cursor, { throwIfNoEntry: false });
    if (stat === undefined) {
      mkdirSync(cursor);
      stat = lstatSync(cursor);
    }
    if (stat.isSymbolicLink() || !stat.isDirectory()) {
      throw new Error("an allowlisted gate copy parent is not a real directory");
    }
  }
}

function copyAllowlistedGateFiles(sourceRoot, disposableRoot) {
  const exactSourceRoot = resolve(sourceRoot);
  const exactDisposableRoot = resolve(disposableRoot);
  for (const entry of GATE_FILES) {
    const source = resolve(exactSourceRoot, "scripts", entry);
    const target = resolve(exactDisposableRoot, "scripts", entry);
    const sourceRelative = relative(exactSourceRoot, source);
    const targetRelative = relative(exactDisposableRoot, target);
    if (sourceRelative === ".." || sourceRelative.startsWith(`..${sep}`)
        || targetRelative === ".." || targetRelative.startsWith(`..${sep}`)) {
      throw new Error("an allowlisted gate copy path escaped its reviewed repository or disposable root");
    }
    const sourceStat = lstatSync(source, { throwIfNoEntry: false });
    if (sourceStat === undefined || sourceStat.isSymbolicLink() || !sourceStat.isFile()) {
      throw new Error("an allowlisted gate copy source is not a regular non-symlink file");
    }
    ensureDisposableDirectoryTree(exactDisposableRoot, dirname(target));
    if (lstatSync(target, { throwIfNoEntry: false }) !== undefined) {
      throw new Error("an allowlisted gate copy destination already exists");
    }
    copyFileSync(source, target);
    const targetStat = lstatSync(target);
    if (targetStat.isSymbolicLink() || !targetStat.isFile()) {
      throw new Error("an allowlisted gate copy destination is not a regular non-symlink file");
    }
  }
}

function buildSyntheticRepo(repo, sourceRoot) {
  mkdirSync(join(repo, "scripts", "lib"), { recursive: true });
  mkdirSync(join(repo, ".github", "workflows"), { recursive: true });
  mkdirSync(join(repo, "dist"), { recursive: true });
  mkdirSync(join(repo, "conformance"), { recursive: true });
  copyAllowlistedGateFiles(sourceRoot, repo);

  writeFileSync(join(repo, "scripts", "boundary-public-repos.json"), `${JSON.stringify({
    note: "Synthetic PUBLIC provider snapshot used only by the boundary arm scratch repository.",
    source: "synthetic arm fixture",
    refreshedAt: new Date().toISOString(),
    orgs: {
      examplearmorg: [
        ...SYNTHETIC_SCANNER_FIXTURE_PUBLIC_REPOS.examplearmorg,
      ],
      examplecorp: [...SYNTHETIC_SCANNER_FIXTURE_PUBLIC_REPOS.examplecorp],
      samplearmorg: [...SYNTHETIC_SCANNER_FIXTURE_PUBLIC_REPOS.samplearmorg],
    },
  }, null, 2)}\n`);
  writeFileSync(
    join(repo, "scripts", "boundary-commitments.json"),
    `${JSON.stringify(syntheticCommitments(SYNTHETIC_KEY, SYNTHETIC_CANARY), null, 2)}\n`,
  );

  writeFileSync(join(repo, "package.json"), `${JSON.stringify({
    name: "synthetic-arm-package", version: "0.0.0", private: false, license: "Apache-2.0",
    files: ["dist", "README.md"], main: "dist/index.js", types: "dist/index.d.ts",
    devDependencies: { typescript: "5.9.3" },
  }, null, 2)}\n`);
  writeFileSync(join(repo, "README.md"), "# synthetic\n\nnothing here\n");
  writeFileSync(join(repo, "dist", "index.js"), "export const a = 1;\n");
  writeFileSync(join(repo, "dist", "index.d.ts"), "export declare const a: number;\n");
  writeFileSync(join(repo, "dist", "index.js.map"), JSON.stringify({ version: 3, file: "index.js", sources: ["../src/index.ts"], sourcesContent: ["export const a = 1;\n"], mappings: "" }));
  writeFileSync(join(repo, "conformance", "vectors.json"), JSON.stringify({ vectors: [{ id: "v1", note: "synthetic" }] }, null, 2));
  writeFileSync(join(repo, "notes.md"), "# notes\n\nnothing here\n");
  writeFileSync(join(repo, ".gitignore"), "node_modules/\n");

  git(repo, ["init", "-q", "-b", "main"], true);
  git(repo, ["config", "user.email", "arm@example.invalid"]);
  git(repo, ["config", "user.name", "arm"]);
  git(repo, ["config", "commit.gpgsign", "false"]);
  git(repo, ["config", "tag.gpgsign", "false"]);
  git(repo, ["config", "core.hooksPath", "scripts/hooks"]);
  git(repo, ["remote", "add", "origin", "https://github.com/ExampleArmOrg/public-arm.git"]);
  git(repo, ["add", "-A"]);
  git(repo, ["commit", "-q", "-m", "chore: synthetic base"]);
  const base = git(repo, ["rev-parse", "HEAD"]).stdout.trim();
  git(repo, ["commit", "-q", "--allow-empty", "-m", "chore: second commit so a range has depth"]);
  writeFileSync(join(repo, ".arm-base"), `${base}\n`);
  git(repo, ["add", ".arm-base"]);
  git(repo, ["commit", "-q", "-m", "chore: record the range base"]);
}

function finish(failures, knockoutJson, log, notes = [], supervisor) {
  const missingCaseIds = supervisor.casePlan.ids.filter((id) => !supervisor.executedCaseIds.has(id));
  const reviewedDigestMatches = /^[0-9a-f]{64}$/.test(supervisor.reviewedCasePlanSha256)
    && supervisor.casePlan.sha256 === supervisor.reviewedCasePlanSha256;
  const casePlanInvalid = !reviewedDigestMatches
    || missingCaseIds.length !== 0
    || supervisor.unexpectedCaseCount !== 0
    || supervisor.duplicateCaseCount !== 0;
  if (casePlanInvalid) {
    failures.push({
      name: "the arm executed its exact reviewed case plan once",
      detail: canonicalJson({
        actualCasePlanSha256: supervisor.casePlan.sha256,
        diagnosticExpectedCaseCount: supervisor.diagnosticExpectedCaseCount,
        diagnosticPlannedCaseCount: supervisor.casePlan.ids.length,
        duplicateCaseCount: supervisor.duplicateCaseCount,
        missingCaseIds,
        reviewedCasePlanSha256: supervisor.reviewedCasePlanSha256,
        unexpectedCaseCount: supervisor.unexpectedCaseCount,
      }),
    });
  }
  const status = casePlanInvalid ? "SETUP_FAILED" : (failures.length === 0 ? "PASS" : "FAIL");
  const summary = {
    casePlanSha256: supervisor.casePlan.sha256,
    duplicateCaseCount: supervisor.duplicateCaseCount,
    event: "complete",
    failureCount: failures.length,
    missingCaseCount: missingCaseIds.length,
    observedCaseCount: supervisor.executedCaseIds.size,
    plannedCaseCount: supervisor.casePlan.ids.length,
    protocol: ARM_TERMINAL_PROTOCOL,
    status,
    unexpectedCaseCount: supervisor.unexpectedCaseCount,
  };
  if (knockoutJson) {
    emitProvenanceBoundGateEvidence(
      "boundary-selftest",
      failures.map((f) => ({ rule: "SELFTEST", subject: f.name, detail: f.detail })),
      boundaryGateProvenance(boundaryScannerAuthority),
    );
    process.stderr.write(`${ARM_TERMINAL_PREFIX}${canonicalJson(summary)}\n`);
    supervisor.markTerminalEmitted();
    return casePlanInvalid ? 2 : (failures.length === 0 ? 0 : 1);
  }
  for (const n of notes) log(`\n  ${n}`);
  log(failures.length === 0
    ? green(bold("\n  ARM PASS — every lane fired on a real plant, went clean when it was removed, and every fail-closed path exited 2.\n"))
    : red(bold(`\n  ARM FAIL — ${failures.length} check(s): ${failures.map((f) => f.name).join("; ")}\n`)));
  process.stderr.write(`${ARM_TERMINAL_PREFIX}${canonicalJson(summary)}\n`);
  supervisor.markTerminalEmitted();
  return casePlanInvalid ? 2 : (failures.length === 0 ? 0 : 1);
}
