import {
  canonicalJsonBytes,
  claimArmWorkerCapabilityFromFd,
  createBoundaryKnockoutBootstrapToken,
  KNOCKOUT_SELFTEST_SUITE,
  KNOCKOUT_WORKER_OPERATIONS,
  knockoutBaselineObservationFromWire,
  knockoutBaselineWireFromObservation,
  knockoutResultEvidenceFromWire,
  knockoutResultWireFromEvidence,
  knockoutSelftestKeySha256,
  knockoutWorkerOperationRole,
  writeArmWorkerResultToFd,
} from "./knockout-workspace.mjs";
import crypto from "node:crypto";
import path from "node:path";

/**
 * Fixed descriptor-only worker entrypoint for disposable knockout arms.
 *
 * The supervisor supplies no command, authority, or request through argv or environment. The
 * worker claims its exact PID/PPID/cwd/executable-bound capability from FD 3 and returns one closed
 * result on FD 4. It never writes terminal evidence.
 */

function refusal(operation, reasonCode) {
  return { observation: { operation, reasonCode }, status: "REFUSED" };
}

function rawDependencyRoots(dependencies) {
  return Object.values(dependencies).flatMap((descriptor) =>
    typeof descriptor?.root === "string" ? [descriptor.root] : []);
}

function canonicalEqual(left, right) {
  return canonicalJsonBytes(left).equals(canonicalJsonBytes(right));
}

function canonicalClone(value) {
  return JSON.parse(canonicalJsonBytes(value).toString("utf8"));
}

async function bindCapturedRegistry(capability, runner) {
  const registryModule = await import("../lint-control-knockout.mjs");
  if (typeof registryModule.knockoutRegistrySnapshot !== "function") {
    throw new Error("captured knockout registry accessor is absent");
  }
  const rawSnapshot = registryModule.knockoutRegistrySnapshot();
  if (
    rawSnapshot === null || typeof rawSnapshot !== "object" || Array.isArray(rawSnapshot) ||
    !canonicalEqual(Object.keys(rawSnapshot).sort(), ["proofInventory", "registry"])
  ) {
    throw new Error("captured knockout registry snapshot has an open schema");
  }
  const registry = canonicalClone(rawSnapshot.registry);
  const proofInventory = canonicalClone(rawSnapshot.proofInventory);
  const registrySha256 = crypto.createHash("sha256")
    .update(canonicalJsonBytes(registry))
    .digest("hex");
  if (registrySha256 !== capability.request.registrySha256) {
    throw new Error("captured knockout registry digest differs from the supervisor subject");
  }
  const registryById = runner.validateKnockoutRegistry(registry);
  const entryId = capability.operation === KNOCKOUT_WORKER_OPERATIONS.OBSERVE_KNOCKOUT_BASELINE
    ? capability.request.entryId
    : capability.request.entry.id;
  const entry = registryById.get(entryId);
  if (entry === undefined) throw new Error("selected knockout is absent from the captured registry");
  const dependencyNames = Object.keys(capability.request.dependencies).sort();
  const requiredNames = [...(entry.requires ?? [])].sort();
  if (!canonicalEqual(dependencyNames, requiredNames)) {
    throw new Error("selected knockout dependencies differ from the captured registry");
  }
  if (capability.operation === KNOCKOUT_WORKER_OPERATIONS.OBSERVE_KNOCKOUT_BASELINE) {
    if (entry.kind !== capability.request.kind || !canonicalEqual(entry.suite, capability.request.suite)) {
      throw new Error("baseline definition differs from the captured registry");
    }
  } else {
    if (!canonicalEqual(entry, capability.request.entry)) {
      throw new Error("mutant entry differs from the captured registry");
    }
    const pairedId = entry.andAlso ?? null;
    const pairedEntry = pairedId === null ? null : registryById.get(pairedId);
    if (
      (pairedId !== null && pairedEntry === undefined) ||
      !canonicalEqual(pairedEntry ?? null, capability.request.pairedEntry)
    ) {
      throw new Error("paired mutant entry differs from the captured registry");
    }
  }
  if (proofInventory === null || typeof proofInventory !== "object" || Array.isArray(proofInventory)) {
    throw new Error("captured proof inventory is malformed");
  }
  return Object.freeze({ entry, proofInventory, registry });
}

async function executeRunnerOperation(capability) {
  const runner = await import("./knockout-runner.mjs");
  if (capability.operation === KNOCKOUT_WORKER_OPERATIONS.RUN_KNOCKOUT_SELFTEST) {
    const observation = runner.projectKnockoutObservation(runner.observeSuite(
      capability.workspaceRoot,
      KNOCKOUT_SELFTEST_SUITE,
      capability.request.suiteTimeoutMs,
      { dependencies: {}, kind: "gate" },
    ));
    return {
      observation: {
        operation: capability.operation,
        selftest: knockoutBaselineWireFromObservation(
          knockoutSelftestKeySha256(),
          observation,
          { workspaceRoot: capability.workspaceRoot },
        ),
      },
      status: "COMPLETE",
    };
  }
  let captured;
  try { captured = await bindCapturedRegistry(capability, runner); }
  catch { return refusal(capability.operation, "REGISTRY_REFUSED"); }
  const boundaryBootstrapToken = captured.entry.expectedGateProvenance === undefined
    ? null
    : createBoundaryKnockoutBootstrapToken(capability);
  const cacheDir = path.join(capability.evidenceRoot, "runner-state");
  const guard = runner.createBuildStateGuard({
    cacheDir,
    protectedRoots: rawDependencyRoots(capability.request.dependencies),
    root: capability.workspaceRoot,
  });
  let start;
  try { start = guard.start(); }
  catch { return refusal(capability.operation, "GUARD_REFUSED"); }
  if (!start?.ok) return refusal(capability.operation, "GUARD_REFUSED");

  let dependencies;
  try {
    dependencies = Object.freeze(Object.fromEntries(
      Object.entries(capability.request.dependencies).map(([name, descriptor]) => [
        name,
        runner.bindObserverDependency(name, descriptor, { armCapability: capability }),
      ]),
    ));
  } catch {
    try { guard.release(); }
    catch {}
    return refusal(capability.operation, "DEPENDENCY_REFUSED");
  }

  if (capability.operation === KNOCKOUT_WORKER_OPERATIONS.OBSERVE_KNOCKOUT_BASELINE) {
    let observation;
    let restore;
    try {
      guard.beginPhase({
        artifacts: false,
        label: `<isolated baseline ${capability.request.baselineKeySha256}>`,
        tracked: "dirty-only",
      });
      try {
        observation = runner.projectKnockoutObservation(runner.observeSuite(
          capability.workspaceRoot,
          captured.entry.suite,
          capability.request.suiteTimeoutMs,
          { boundaryBootstrapToken, dependencies, kind: captured.entry.kind },
        ));
      } finally {
        restore = guard.endPhase();
      }
    } catch (error) {
      try { guard.release(); }
      catch {}
      if (restore?.failures?.length > 0) {
        return refusal(capability.operation, "BASELINE_RESTORE_FAILED");
      }
      throw error;
    }
    const released = guard.release();
    if (restore?.failures?.length > 0 || released !== true) {
      return refusal(capability.operation, "BASELINE_RESTORE_FAILED");
    }
    return {
      observation: {
        baseline: knockoutBaselineWireFromObservation(
          capability.request.baselineKeySha256,
          observation,
          { workspaceRoot: capability.workspaceRoot },
        ),
        operation: capability.operation,
      },
      status: "COMPLETE",
    };
  }

  if (capability.operation === KNOCKOUT_WORKER_OPERATIONS.OBSERVE_KNOCKOUT_POSTCHECK) {
    const baseline = knockoutBaselineObservationFromWire(
      capability.request.baseline,
      { workspaceRoot: capability.workspaceRoot },
    );
    const mutant = knockoutResultEvidenceFromWire(capability.request.mutant, {
      baseline: capability.request.baseline,
      entry: capability.request.entry,
    });
    const paired = captured.entry.andAlso === undefined
      ? null
      : captured.registry.find((entry) => entry.id === captured.entry.andAlso) ?? null;
    const targets = [...new Set([captured.entry, ...(paired === null ? [] : [paired])].flatMap((entry) => [
      entry.file,
      ...(entry.companionFile === undefined ? [] : [entry.companionFile]),
    ]))];
    let observation;
    let restore;
    try {
      const workTreeState = runner.gitWorkTreeState(capability.workspaceRoot);
      if (workTreeState === "unknown") throw new Error("postcheck Git worktree state is unknown");
      guard.beginPhase({
        artifacts: true,
        exactCustodyPaths: targets,
        exactGitIndex: workTreeState === "yes",
        label: `${captured.entry.id}:fresh-postcheck`,
        sources: [],
        tracked: "all",
      });
      try {
        observation = runner.projectKnockoutObservation(runner.observeSuite(
          capability.workspaceRoot,
          captured.entry.suite,
          capability.request.suiteTimeoutMs,
          { boundaryBootstrapToken, dependencies, kind: captured.entry.kind },
        ));
      } finally {
        restore = guard.endPhase();
      }
    } catch (error) {
      try { guard.release(); }
      catch {}
      if (restore?.failures?.length > 0) {
        return refusal(capability.operation, "POSTCHECK_RESTORE_FAILED");
      }
      throw error;
    }
    const released = guard.release();
    if (restore?.failures?.length > 0 || released !== true) {
      return refusal(capability.operation, "POSTCHECK_RESTORE_FAILED");
    }
    const postcheckState = {
      artifactsRemoved: restore.artifactsRemoved,
      artifactsRestored: restore.artifactsRestored,
      exactCustodyAdditions: restore.exactCustodyAdditions,
      exactCustodyRestored: restore.exactCustodyRestored,
      exactGitIndexObservationChanged: restore.exactGitIndexObservationChanged,
      exactGitIndexSemanticChanged: restore.exactGitIndexSemanticChanged,
      freshArm: true,
      trackedReverted: restore.trackedReverted,
      untrackedAdditions: restore.untrackedAdditions,
    };
    const finalized = runner.finalizeIsolatedSetupIntegrityPostcheck({
      baseline,
      entry: captured.entry,
      postcheck: observation,
      postcheckState,
      result: mutant,
    });
    return {
      observation: {
        knockout: knockoutResultWireFromEvidence({
          baselineKeySha256: capability.request.baseline.baselineKeySha256,
          entryId: captured.entry.id,
          result: finalized,
        }),
        operation: capability.operation,
      },
      status: "COMPLETE",
    };
  }

  let result;
  let released = false;
  try {
    const baseline = knockoutBaselineObservationFromWire(
      capability.request.baseline,
      { workspaceRoot: capability.workspaceRoot },
    );
    result = runner.runKnockout({
      baseline,
      boundaryBootstrapToken,
      dependencies,
      entry: captured.entry,
      guard,
      registry: captured.registry,
      root: capability.workspaceRoot,
      setupIntegrityPostcheck: "deferred",
      timeoutMs: capability.request.suiteTimeoutMs,
      workspaceMode: "disposable",
    });
    result = runner.requireNamedProofFailuresAtRoot(
      capability.workspaceRoot,
      captured.proofInventory,
      captured.entry,
      result,
    );
  } finally {
    try { released = guard.release(); }
    catch { released = false; }
  }
  if (released !== true) {
    return refusal(capability.operation, "MUTANT_RETENTION_FAILED");
  }
  return {
    observation: {
      knockout: knockoutResultWireFromEvidence({
        baselineKeySha256: capability.request.baseline.baselineKeySha256,
        entryId: captured.entry.id,
        result,
      }),
      operation: capability.operation,
    },
    status: "COMPLETE",
  };
}

try {
  const capability = claimArmWorkerCapabilityFromFd();
  const requestKeys = Object.keys(capability.request).sort();
  let outcome;
  if (capability.operation === KNOCKOUT_WORKER_OPERATIONS.ATTEST_ARM) {
    outcome = requestKeys.length === 0
      ? {
          observation: {
            operation: KNOCKOUT_WORKER_OPERATIONS.ATTEST_ARM,
            role: capability.role,
            workspaceBound: true,
          },
          status: "COMPLETE",
        }
      : refusal(capability.operation, "ATTEST_REQUEST_NOT_EMPTY");
  } else if (!Object.values(KNOCKOUT_WORKER_OPERATIONS).includes(capability.operation)) {
    outcome = refusal(capability.operation, "OPERATION_UNSUPPORTED");
  } else {
    const expectedRole = knockoutWorkerOperationRole(capability.operation);
    outcome = capability.role === expectedRole
      ? await executeRunnerOperation(capability)
      : refusal(capability.operation, "ROLE_MISMATCH");
  }
  writeArmWorkerResultToFd(capability, outcome);
} catch (error) {
  const code = typeof error?.code === "string" ? error.code : "WORKER_FAILURE";
  process.stderr.write(`${code}\n`);
  process.exitCode = 70;
}
