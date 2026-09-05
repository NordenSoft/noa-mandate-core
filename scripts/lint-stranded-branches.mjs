#!/usr/bin/env node
/**
 * STRANDED-BRANCH GATE — work that exists only on a branch nobody is landing.
 *
 * WHY THIS EXISTS. A pushed branch with no pull request can carry unreviewed product, security, or
 * planning work while emitting no signal on the default branch. Manual reconstruction is slow and
 * non-repeatable, so this gate derives the answer from repository and pull-request state.
 *
 * The root cause is not laziness, it is INVISIBILITY: a pushed branch with no pull request emits no
 * signal anywhere. CI never runs on it, no reviewer sees it, no dashboard lists it. It looks exactly
 * like finished work to the person who pushed it, because pushing is the last thing they did.
 *
 * WHAT THIS MEASURES. For every branch, one question with a mechanical answer:
 *
 *     Does this exact branch tip carry commits that are not in main, without qualifying PR evidence?
 *
 * A branch is STRANDED when all three hold:
 *   1. its tip is not an ancestor of main (it has commits main does not),
 *   2. no same-repository OPEN PR records this exact OID as its current tip,
 *   3. it is older than the grace period (default 3 days), so work in progress is not nagged.
 *
 * WHAT IT DELIBERATELY DOES NOT DO. It does not judge whether the CONTENT is already in main. A
 * squash-merged branch keeps commits main never took, and an old branch's lines can be superseded by
 * a better implementation. Both defeat naive line comparison. Content triage needs a human
 * reading the diff; this gate measures current review visibility at the exact provider tip.
 *
 * WHY OPEN EXACT TIP AND NOT BRANCH NAME ALONE. A closed-unmerged PR remains visible history but does
 * not review a live branch forever. A merged record is not Git ancestry; only the commit graph proves
 * that the current tip landed. A same-named fork or PR for an earlier incarnation says nothing about
 * new commits now at the live tip. Repository identity, branch name, OID, and OPEN state must match.
 *
 * THE FIX IT ASKS FOR IS ONE COMMAND. Open a draft PR the moment a branch is pushed:
 *     gh pr create --draft --fill
 * From that point the work is visible, CI runs on it, and this gate is silent.
 *
 * USAGE
 *   node scripts/lint-stranded-branches.mjs                 # report + exit 1 if any
 *   node scripts/lint-stranded-branches.mjs --grace-days 7
 *   node scripts/lint-stranded-branches.mjs --warn-only     # report, always exit 0
 *   node scripts/lint-stranded-branches.mjs --selftest      # prove the gate can fail
 *   node scripts/lint-stranded-branches.mjs --prepare-github-actions-refs
 *   node scripts/lint-stranded-branches.mjs --github-actions --grace-days 3
 *
 * EXIT 0 clean · 1 stranded branches found · 2 the gate could not measure (fails closed, never
 * silently passes: an unreachable `gh` or a shallow clone means UNKNOWN, and UNKNOWN is not GREEN).
 */
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { appendFileSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const WORKFLOW = join(ROOT, ".github", "workflows", "branch-hygiene.yml");
const DEFAULT_GRACE_DAYS = 3;
const MAX_GRACE_DAYS = 3650;
const MAX_PULL_REQUEST_PAGES = 1000;
const PULL_REQUESTS_PER_PAGE = 100;
const MAX_ACTION_SUMMARY_BYTES = 1 << 20;
const GITHUB_API_VERSION = "2022-11-28";
// This digest closes the whole Actions authority surface: events, permissions, one job, action
// pins/inputs, step order/ids/conditions/environments, and exact shell/Node invocations. It binds
// every raw byte because a trimmed `#` line is YAML comment only outside a block scalar; inside
// `run: |` it remains content whose GitHub expressions are expanded before the shell sees it.
// Exact bytes also reject CR, NEL, LS, PS, and mixed-separator parser differentials.
const CANONICAL_WORKFLOW_SHA256 =
  "25b1d7d92770a7e15d1181e6b5ee7a9a68146305a4c6209b227c623e1e13c4e2";
const OBJECT_ID = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u;
const GITHUB_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/u;
const ORIGIN_URL_COMMAND = Object.freeze(["remote", "get-url", "--all", "origin"]);
const REMOTE_HEADS_COMMAND = Object.freeze(["ls-remote", "--heads", "--refs", "origin"]);
const FETCH_ALL_REMOTE_HEADS_COMMAND = Object.freeze([
  "fetch",
  "--no-tags",
  "--prune",
  "--force",
  "origin",
  "+refs/heads/*:refs/remotes/origin/*",
]);
const LOCAL_REF_SNAPSHOT_COMMAND = Object.freeze([
  "for-each-ref",
  "--format=%(refname)%00%(objectname)%00%(symref)",
  "refs/heads/",
  "refs/remotes/origin/",
]);
const repositoryIdentityCommand = (identity) => Object.freeze([
  "api",
  "--hostname", identity.host,
  "-H", "Accept: application/vnd.github+json",
  "-H", `X-GitHub-Api-Version: ${GITHUB_API_VERSION}`,
  `/repos/${encodeURIComponent(identity.owner)}/${encodeURIComponent(identity.repo)}`,
]);
const pullRequestPageCommand = (identity, page) => Object.freeze([
  "api",
  "--hostname", identity.host,
  "-H", "Accept: application/vnd.github+json",
  "-H", `X-GitHub-Api-Version: ${GITHUB_API_VERSION}`,
  `/repos/${encodeURIComponent(identity.owner)}/${encodeURIComponent(identity.repo)}` +
    `/pulls?state=all&sort=created&direction=asc&per_page=${PULL_REQUESTS_PER_PAGE}&page=${page}`,
]);

class MeasurementFailure extends Error {
  constructor(message) {
    super(message);
    this.name = "MeasurementFailure";
  }
}

function stripOneTerminalNewline(value) {
  if (value.endsWith("\r\n")) return value.slice(0, -2);
  if (value.endsWith("\n")) return value.slice(0, -1);
  return value;
}

function command(program, commandArgs, { environment = process.env } = {}) {
  try {
    return {
      ok: true,
      stdout: stripOneTerminalNewline(
        execFileSync(program, commandArgs, {
          cwd: ROOT,
          encoding: "utf8",
          env: environment,
          maxBuffer: 1 << 26,
          stdio: ["ignore", "pipe", "ignore"],
        }),
      ),
      exitCode: 0,
      errorCode: null,
      signal: null,
    };
  } catch (error) {
    return {
      ok: false,
      stdout: "",
      exitCode:
        typeof error === "object" && error !== null && Number.isInteger(error.status)
          ? error.status
          : null,
      errorCode:
        typeof error === "object" && error !== null && typeof error.code === "string"
          ? error.code
          : null,
      signal:
        typeof error === "object" && error !== null && typeof error.signal === "string"
          ? error.signal
          : null,
    };
  }
}

const git = (...commandArgs) => command("git", commandArgs);
const gh = (...commandArgs) => command("gh", commandArgs);

function commandFailure(tool, result) {
  if (result?.ok === true) return `${tool} returned malformed output`;
  if (result?.exitCode !== null && result?.exitCode !== undefined) {
    return `${tool} exited ${result.exitCode}`;
  }
  if (result?.signal) return `${tool} was terminated by ${result.signal}`;
  if (result?.errorCode) return `${tool} could not run (${result.errorCode})`;
  return `${tool} returned no usable result`;
}

function requiredGit(runGit, purpose, ...command) {
  const result = runGit(...command);
  if (result?.ok !== true || typeof result.stdout !== "string") {
    throw new MeasurementFailure(`${purpose} failed: ${commandFailure("git", result)}`);
  }
  return result.stdout;
}

function requiredGh(runGh, purpose, ...commandArgs) {
  const result = runGh(...commandArgs);
  if (result?.ok !== true || typeof result.stdout !== "string") {
    throw new MeasurementFailure(`${purpose} failed: ${commandFailure("gh", result)}`);
  }
  return result.stdout;
}

function parseOptions(argv) {
  const options = { graceDays: DEFAULT_GRACE_DAYS, warnOnly: false, mode: "measure" };
  const seen = new Set();
  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index];
    if (arg === "--warn-only") {
      if (seen.has(arg)) throw new MeasurementFailure(`${arg} may be supplied only once`);
      seen.add(arg);
      options.warnOnly = true;
      continue;
    }
    if (
      arg === "--selftest" ||
      arg === "--github-actions" ||
      arg === "--prepare-github-actions-refs" ||
      arg === "--validate-github-actions-output"
    ) {
      if (seen.has("mode")) throw new MeasurementFailure("exactly one execution mode may be selected");
      seen.add("mode");
      options.mode = arg === "--selftest"
        ? "selftest"
        : arg === "--github-actions"
          ? "github-actions"
          : arg === "--prepare-github-actions-refs"
            ? "prepare-github-actions-refs"
          : "validate-github-actions-output";
      continue;
    }
    if (arg === "--grace-days") {
      if (seen.has(arg)) throw new MeasurementFailure(`${arg} may be supplied only once`);
      seen.add(arg);
      const raw = argv[index + 1];
      if (typeof raw !== "string" || !/^(?:0|[1-9]\d*)$/u.test(raw)) {
        throw new MeasurementFailure(
          `${arg} needs a canonical base-10 integer from 0 through ${MAX_GRACE_DAYS}`,
        );
      }
      const value = Number(raw);
      if (!Number.isSafeInteger(value) || value > MAX_GRACE_DAYS) {
        throw new MeasurementFailure(
          `${arg} needs a safe integer from 0 through ${MAX_GRACE_DAYS}`,
        );
      }
      options.graceDays = value;
      index++;
      continue;
    }
    throw new MeasurementFailure(`unknown argument ${JSON.stringify(arg)}`);
  }
  if (options.mode !== "measure" && options.warnOnly) {
    throw new MeasurementFailure("--warn-only is permitted only in direct measurement mode");
  }
  if (
    (
      options.mode === "selftest" ||
      options.mode === "prepare-github-actions-refs" ||
      options.mode === "validate-github-actions-output"
    ) &&
    seen.has("--grace-days")
  ) {
    throw new MeasurementFailure(`--grace-days is not valid in ${options.mode} mode`);
  }
  return options;
}

function assertFullHistory(runGit) {
  const shallow = requiredGit(runGit, "checking shallow-clone state", "rev-parse", "--is-shallow-repository");
  if (shallow === "true") {
    throw new MeasurementFailure("shallow clone — cannot compare branch history. Check out with fetch-depth: 0.");
  }
  if (shallow !== "false") {
    throw new MeasurementFailure(`unexpected shallow-repository result ${JSON.stringify(shallow)}`);
  }
}

function parseJson(raw, purpose) {
  try {
    return JSON.parse(raw);
  } catch {
    throw new MeasurementFailure(`${purpose} returned malformed JSON`);
  }
}

function canonicalHost(value, purpose) {
  if (
    typeof value !== "string" ||
    !/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[1-9]\d{0,4})?$/iu.test(value)
  ) {
    throw new MeasurementFailure(`${purpose} has an invalid host`);
  }
  return value.toLowerCase();
}

function canonicalRepositoryPart(value, purpose) {
  if (
    typeof value !== "string" ||
    value === "." ||
    value === ".." ||
    !/^[A-Za-z0-9_.-]+$/u.test(value)
  ) {
    throw new MeasurementFailure(`${purpose} has an invalid repository component`);
  }
  return value;
}

function originIdentityFromUrl(raw) {
  if (typeof raw !== "string" || raw === "" || /[\0\r\n]/u.test(raw)) {
    throw new MeasurementFailure("origin must have exactly one non-empty URL");
  }

  let host;
  let owner;
  let repository;
  let transport;
  const scp = raw.match(/^git@([^:/\s]+):([^/\s]+)\/([^/\s]+)$/u);
  if (scp !== null) {
    [, host, owner, repository] = scp;
    transport = "ssh";
  } else {
    let parsed;
    try {
      parsed = new URL(raw);
    } catch {
      throw new MeasurementFailure("origin URL is not a canonical GitHub HTTPS/SSH URL");
    }
    if (parsed.protocol !== "https:" && parsed.protocol !== "ssh:") {
      throw new MeasurementFailure("origin URL must use HTTPS or SSH");
    }
    if (parsed.search !== "" || parsed.hash !== "" || parsed.pathname.includes("%")) {
      throw new MeasurementFailure("origin URL contains ambiguous query, fragment, or encoding");
    }
    if (parsed.protocol === "https:" && (parsed.username !== "" || parsed.password !== "")) {
      throw new MeasurementFailure("origin HTTPS URL must not embed credentials");
    }
    if (parsed.protocol === "ssh:" && (parsed.username !== "git" || parsed.password !== "")) {
      throw new MeasurementFailure("origin SSH URL must use the git account without a password");
    }
    const path = parsed.pathname.split("/");
    if (path.length !== 3 || path[0] !== "" || path[1] === "" || path[2] === "") {
      throw new MeasurementFailure("origin URL must identify exactly owner/repository");
    }
    host = parsed.host;
    owner = path[1];
    repository = path[2];
    transport = parsed.protocol === "https:" ? "https" : "ssh";
  }

  // Git itself accepts the conventional clone-form suffix, while actions/checkout's pinned HTTPS
  // implementation records `${server}/${owner}/${repository}` without it. Both identify the same
  // exact repository path; strip one terminal transport suffix when present and reject empty names.
  if (repository.endsWith(".git")) repository = repository.slice(0, -4);
  if (repository === "") {
    throw new MeasurementFailure("origin URL has an empty repository name after its transport suffix");
  }
  const identity = {
    host: canonicalHost(host, "origin URL"),
    owner: canonicalRepositoryPart(owner, "origin URL"),
    repo: canonicalRepositoryPart(repository, "origin URL"),
    transport,
  };
  return { ...identity, nameWithOwner: `${identity.owner}/${identity.repo}` };
}

function readOriginIdentity(runGit = git) {
  const url = requiredGit(runGit, "reading the exact origin URL", ...ORIGIN_URL_COMMAND);
  return { url, identity: originIdentityFromUrl(url) };
}

function assertAmbientIdentity(environment, identity) {
  if (environment === null || typeof environment !== "object") {
    throw new MeasurementFailure("process environment is unavailable");
  }
  if (typeof environment.GH_HOST === "string" && environment.GH_HOST !== "") {
    if (canonicalHost(environment.GH_HOST, "GH_HOST") !== identity.host) {
      throw new MeasurementFailure("GH_HOST conflicts with the canonical origin host");
    }
  }
  if (typeof environment.GH_REPO === "string" && environment.GH_REPO !== "") {
    const parts = environment.GH_REPO.split("/");
    let host = identity.host;
    let owner;
    let repo;
    if (parts.length === 2) {
      [owner, repo] = parts;
    } else if (parts.length === 3) {
      [host, owner, repo] = parts;
    } else {
      throw new MeasurementFailure("GH_REPO is malformed and cannot be reconciled with origin");
    }
    const same =
      canonicalHost(host, "GH_REPO") === identity.host &&
      canonicalRepositoryPart(owner, "GH_REPO").toLowerCase() === identity.owner.toLowerCase() &&
      canonicalRepositoryPart(repo, "GH_REPO").toLowerCase() === identity.repo.toLowerCase();
    if (!same) throw new MeasurementFailure("GH_REPO conflicts with the canonical origin repository");
  }
}

function authenticatedGitEnvironment(environment, identity) {
  const token = environment.GH_TOKEN;
  if (identity.transport !== "https" || typeof token !== "string" || token === "") {
    return environment;
  }
  const rawCount = environment.GIT_CONFIG_COUNT;
  if (rawCount !== undefined && !/^(?:0|[1-9]\d*)$/u.test(String(rawCount))) {
    throw new MeasurementFailure("GIT_CONFIG_COUNT is malformed");
  }
  const count = rawCount === undefined ? 0 : Number(rawCount);
  if (!Number.isSafeInteger(count) || count > 1000) {
    throw new MeasurementFailure("GIT_CONFIG_COUNT exceeds the safe bound");
  }
  if (
    Object.hasOwn(environment, `GIT_CONFIG_KEY_${count}`) ||
    Object.hasOwn(environment, `GIT_CONFIG_VALUE_${count}`)
  ) {
    throw new MeasurementFailure("Git config environment has an occupied next credential slot");
  }
  return {
    ...environment,
    GIT_CONFIG_COUNT: String(count + 1),
    [`GIT_CONFIG_KEY_${count}`]: `http.https://${identity.host}/.extraheader`,
    [`GIT_CONFIG_VALUE_${count}`]:
      `AUTHORIZATION: basic ${Buffer.from(`x-access-token:${token}`, "utf8").toString("base64")}`,
  };
}

function remoteGitRunner(runGit, runRemoteGit, environment, identity) {
  if (typeof runRemoteGit === "function") return runRemoteGit;
  if (runGit !== git) return runGit;
  const networkEnvironment = authenticatedGitEnvironment(environment, identity);
  return (...commandArgs) => command("git", commandArgs, { environment: networkEnvironment });
}

/**
 * Materialize the authoritative provider-head set before the Actions measurement.
 *
 * `actions/checkout` establishes a full-history repository but is not evidence that every provider
 * head has a corresponding `refs/remotes/origin/*` ref. This exact positive wildcard refspec makes
 * that set explicit. Snapshot A must equal the resulting tracking refs, then snapshot B must still
 * equal A; a partial fetch, stale ref, malformed row, or provider race therefore stops the job.
 */
function prepareGithubActionsRefs({
  runGit = git,
  runRemoteGit = null,
  environment = process.env,
} = {}) {
  assertFullHistory(runGit);
  const origin = readOriginIdentity(runGit);
  assertAmbientIdentity(environment, origin.identity);
  const networkGit = remoteGitRunner(runGit, runRemoteGit, environment, origin.identity);

  const authoritativeA = parseRemoteHeads(
    requiredGit(networkGit, "reading authoritative remote heads before preparation", ...REMOTE_HEADS_COMMAND),
    "authoritative remote heads before preparation",
  );
  if (!authoritativeA.has("main")) {
    throw new MeasurementFailure("authoritative remote heads before preparation has no main head");
  }

  requiredGit(
    networkGit,
    "materializing every authoritative remote head",
    ...FETCH_ALL_REMOTE_HEADS_COMMAND,
  );
  const localSnapshot = snapshotLocalRefs(runGit);
  assertEqualHeads(
    authoritativeA,
    localSnapshot.remoteTracking,
    "post-fetch origin-tracking refs do not exactly match authoritative remote heads",
  );

  const authoritativeB = parseRemoteHeads(
    requiredGit(networkGit, "reading authoritative remote heads after preparation", ...REMOTE_HEADS_COMMAND),
    "authoritative remote heads after preparation",
  );
  assertEqualHeads(
    authoritativeA,
    authoritativeB,
    "authoritative remote heads changed during Actions preparation",
  );
  const finalOriginUrl = requiredGit(
    runGit,
    "re-reading the exact origin URL after Actions preparation",
    ...ORIGIN_URL_COMMAND,
  );
  if (finalOriginUrl !== origin.url) {
    throw new MeasurementFailure("origin URL changed during Actions preparation");
  }
  return 0;
}

function repositoryIdentity(runGh, originIdentity) {
  const parsed = parseJson(
    requiredGh(
      runGh,
      "reading canonical GitHub repository identity",
      ...repositoryIdentityCommand(originIdentity),
    ),
    "current GitHub repository identity",
  );
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new MeasurementFailure("current GitHub repository identity is not an object");
  }
  if (typeof parsed.node_id !== "string" || parsed.node_id === "" || /\s/u.test(parsed.node_id)) {
    throw new MeasurementFailure("current GitHub repository identity has no valid immutable node_id");
  }
  if (
    typeof parsed.full_name !== "string" ||
    !/^[^/\s]+\/[^/\s]+$/u.test(parsed.full_name)
  ) {
    throw new MeasurementFailure("current GitHub repository identity has no valid full_name");
  }
  if (parsed.full_name.toLowerCase() !== originIdentity.nameWithOwner.toLowerCase()) {
    throw new MeasurementFailure("provider repository identity conflicts with the exact origin URL");
  }
  return { nodeId: parsed.node_id, nameWithOwner: parsed.full_name };
}

function validBranchName(name) {
  if (
    typeof name !== "string" ||
    name === "" ||
    name === "@" ||
    name.startsWith("/") ||
    name.endsWith("/") ||
    name.endsWith(".") ||
    name.includes("//") ||
    name.includes("..") ||
    name.includes("@{") ||
    /[\0-\x20\x7f~^:?*\\[]/u.test(name)
  ) return false;
  return name.split("/").every(
    (part) => part !== "" && !part.startsWith(".") && !part.endsWith(".lock"),
  );
}

function assertConsistentObjectIds(heads, label) {
  let width = null;
  for (const oid of heads.values()) {
    if (width === null) width = oid.length;
    else if (oid.length !== width) {
      throw new MeasurementFailure(`${label} mixes object-ID widths`);
    }
  }
}

function parseRemoteHeads(raw, label) {
  const heads = new Map();
  if (raw === "") return heads;
  for (const [index, line] of raw.split("\n").entries()) {
    const match = line.match(/^([0-9a-f]{40}|[0-9a-f]{64})\trefs\/heads\/(.+)$/u);
    if (match === null || !validBranchName(match?.[2])) {
      throw new MeasurementFailure(`${label} row ${index + 1} is malformed`);
    }
    const [, oid, name] = match;
    if (heads.has(name)) throw new MeasurementFailure(`${label} contains a duplicate head`);
    heads.set(name, oid);
  }
  assertConsistentObjectIds(heads, label);
  return heads;
}

function snapshotLocalRefs(runGit) {
  const raw = requiredGit(
    runGit,
    "snapshotting local and origin-tracking object IDs",
    ...LOCAL_REF_SNAPSHOT_COMMAND,
  );
  const localHeads = new Map();
  const remoteTracking = new Map();
  if (raw === "") return { localHeads, remoteTracking };

  const refs = new Set();
  for (const [index, line] of raw.split("\n").entries()) {
    const fields = line.split("\0");
    if (fields.length !== 3) {
      throw new MeasurementFailure(`local ref snapshot row ${index + 1} is malformed`);
    }
    const [ref, oid, symref] = fields;
    if (refs.has(ref)) throw new MeasurementFailure("local ref snapshot contains a duplicate ref");
    refs.add(ref);
    if (!OBJECT_ID.test(oid)) {
      throw new MeasurementFailure(`local ref snapshot row ${index + 1} has an invalid object ID`);
    }
    if (ref === "refs/remotes/origin/HEAD" && symref !== "") continue;
    if (symref !== "") {
      throw new MeasurementFailure(`local ref snapshot row ${index + 1} has an unexpected symref`);
    }

    let target;
    let name;
    if (ref.startsWith("refs/heads/")) {
      target = localHeads;
      name = ref.slice("refs/heads/".length);
    } else if (ref.startsWith("refs/remotes/origin/")) {
      target = remoteTracking;
      name = ref.slice("refs/remotes/origin/".length);
    } else {
      throw new MeasurementFailure(`local ref snapshot row ${index + 1} has an unexpected ref`);
    }
    if (!validBranchName(name)) {
      throw new MeasurementFailure(`local ref snapshot row ${index + 1} has an invalid branch name`);
    }
    if (target.has(name)) throw new MeasurementFailure("local ref snapshot contains a duplicate head");
    target.set(name, oid);
  }
  assertConsistentObjectIds(localHeads, "local branch snapshot");
  assertConsistentObjectIds(remoteTracking, "origin-tracking snapshot");
  return { localHeads, remoteTracking };
}

function assertEqualHeads(expected, actual, label) {
  let missing = 0;
  let extra = 0;
  let mismatched = 0;
  for (const [name, oid] of expected) {
    if (!actual.has(name)) missing++;
    else if (actual.get(name) !== oid) mismatched++;
  }
  for (const name of actual.keys()) {
    if (!expected.has(name)) extra++;
  }
  if (missing !== 0 || extra !== 0 || mismatched !== 0) {
    throw new MeasurementFailure(
      `${label}: missing=${missing} extra=${extra} oid-mismatch=${mismatched}`,
    );
  }
}

function localEvidence(localHeads, providerHeads) {
  let localOnly = 0;
  let locallyDiverged = 0;
  for (const [name, oid] of localHeads) {
    if (!providerHeads.has(name)) localOnly++;
    else if (providerHeads.get(name) !== oid) locallyDiverged++;
  }
  return { localOnly, locallyDiverged };
}

function githubTimestampMillis(value) {
  if (typeof value !== "string" || !GITHUB_TIMESTAMP.test(value)) return null;
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds)) return null;
  // Date.parse normalizes impossible dates on some runtimes (for example February 31). Re-encoding
  // prevents a merely parseable timestamp from passing as the canonical GitHub UTC representation.
  return new Date(milliseconds).toISOString() === `${value.slice(0, -1)}.000Z`
    ? milliseconds
    : null;
}

function parsePullRequestPage(raw, page, nowSeconds) {
  const parsed = parseJson(raw, `pull-request page ${page}`);
  if (!Array.isArray(parsed)) {
    throw new MeasurementFailure(`pull-request page ${page} is not an array`);
  }
  if (parsed.length > PULL_REQUESTS_PER_PAGE) {
    throw new MeasurementFailure(`pull-request page ${page} exceeds ${PULL_REQUESTS_PER_PAGE} rows`);
  }

  return parsed.map((row, index) => {
    const label = `pull-request page ${page} row ${index + 1}`;
    if (row === null || typeof row !== "object" || Array.isArray(row)) {
      throw new MeasurementFailure(`${label} is not an object`);
    }
    if (!Number.isSafeInteger(row.number) || row.number < 1) {
      throw new MeasurementFailure(`${label} has invalid number`);
    }
    if (row.state !== "open" && row.state !== "closed") {
      throw new MeasurementFailure(`${label} has invalid state ${JSON.stringify(row.state)}`);
    }
    let closedAt = null;
    let mergedAt = null;
    if (row.state === "open") {
      if (row.closed_at !== null || row.merged_at !== null) {
        throw new MeasurementFailure(`${label} has incoherent open-state terminal timestamps`);
      }
    } else {
      closedAt = githubTimestampMillis(row.closed_at);
      if (closedAt === null || closedAt > nowSeconds * 1000) {
        throw new MeasurementFailure(`${label} has no valid closed_at terminal timestamp`);
      }
      if (row.merged_at !== null) {
        mergedAt = githubTimestampMillis(row.merged_at);
        if (mergedAt === null || mergedAt > closedAt || mergedAt > nowSeconds * 1000) {
          throw new MeasurementFailure(`${label} has invalid merged_at timestamp`);
        }
      }
    }
    if (row.head === null || typeof row.head !== "object" || Array.isArray(row.head)) {
      throw new MeasurementFailure(`${label} has no head object`);
    }
    if (
      typeof row.head.ref !== "string" || row.head.ref === "" ||
      /[\0\r\n]/u.test(row.head.ref)
    ) {
      throw new MeasurementFailure(`${label} has invalid head.ref`);
    }
    if (typeof row.head.sha !== "string" || !OBJECT_ID.test(row.head.sha)) {
      throw new MeasurementFailure(`${label} has invalid head.sha`);
    }
    if (!Object.hasOwn(row.head, "repo")) {
      throw new MeasurementFailure(`${label} is missing head.repo`);
    }
    // GitHub legitimately returns null after a fork is deleted. It is complete negative evidence:
    // this PR cannot identify the still-live current repository, so it may never qualify a branch.
    // A missing property remains malformed and fails the whole measurement above.
    if (row.head.repo === null) {
      return {
        number: row.number,
        state: row.state,
        closedAt,
        mergedAt,
        headRef: row.head.ref,
        headOid: row.head.sha,
        headRepositoryId: null,
        headRepositoryName: null,
        merged: mergedAt !== null,
      };
    }
    if (typeof row.head.repo !== "object" || Array.isArray(row.head.repo)) {
      throw new MeasurementFailure(`${label} has invalid head.repo`);
    }
    if (
      typeof row.head.repo.node_id !== "string" || row.head.repo.node_id === "" ||
      /\s/u.test(row.head.repo.node_id)
    ) {
      throw new MeasurementFailure(`${label} has invalid head repository node_id`);
    }
    if (
      typeof row.head.repo.full_name !== "string" ||
      !/^[^/\s]+\/[^/\s]+$/u.test(row.head.repo.full_name)
    ) {
      throw new MeasurementFailure(`${label} has invalid head repository full_name`);
    }
    return {
      number: row.number,
      state: row.state,
      closedAt,
      mergedAt,
      headRef: row.head.ref,
      headOid: row.head.sha,
      headRepositoryId: row.head.repo.node_id,
      headRepositoryName: row.head.repo.full_name,
      merged: mergedAt !== null,
    };
  });
}

/** Fetch every REST page explicitly; one failed, malformed, or duplicated page makes PR evidence UNKNOWN. */
function allPullRequests(runGh, originIdentity, nowSeconds) {
  const rows = [];
  const numbers = new Set();
  for (let page = 1; page <= MAX_PULL_REQUEST_PAGES; page++) {
    const parsed = parsePullRequestPage(
      requiredGh(
        runGh,
        `reading pull-request page ${page}`,
        ...pullRequestPageCommand(originIdentity, page),
      ),
      page,
      nowSeconds,
    );
    for (const row of parsed) {
      if (numbers.has(row.number)) {
        throw new MeasurementFailure(`pull-request pagination repeated PR #${row.number}`);
      }
      numbers.add(row.number);
      rows.push(row);
    }
    if (parsed.length < PULL_REQUESTS_PER_PAGE) return rows;
  }
  throw new MeasurementFailure(
    `pull-request pagination exceeded ${MAX_PULL_REQUEST_PAGES * PULL_REQUESTS_PER_PAGE} rows`,
  );
}

const tipIdentity = (branchName, oid) => JSON.stringify([branchName, oid]);

/**
 * Only an OPEN PR is current review evidence. Closed-unmerged records remain visible but do not
 * qualify, and a merged record is never used as a substitute for Git ancestry: GitHub does not
 * promise that historical `head.sha` is an immutable terminal snapshot for this gate's purpose.
 */
function pullRequestEvidence(pullRequests, currentRepository) {
  const open = new Set();
  const closedUnmerged = new Set();
  const merged = new Set();
  for (const pr of pullRequests) {
    if (
      typeof pr.headRepositoryId !== "string" ||
      typeof pr.headRepositoryName !== "string" ||
      pr.headRepositoryId !== currentRepository.nodeId ||
      pr.headRepositoryName.toLowerCase() !== currentRepository.nameWithOwner.toLowerCase()
    ) continue;
    const identity = tipIdentity(pr.headRef, pr.headOid);
    if (pr.state === "open") open.add(identity);
    else if (pr.merged) merged.add(identity);
    else closedUnmerged.add(identity);
  }
  return { open, closedUnmerged, merged };
}

/**
 * Canonicalize every PR row that can affect a measured provider tip. Matching either its branch
 * name or OID makes entry/exit, stale-incarnation, alias-branch, cross-fork, and repository-identity
 * changes visible. Unrelated historical PR churn cannot make the daily gate unavailable.
 */
function canonicalRelevantPullRequestState(pullRequests, providerHeads) {
  const relevantNames = new Set();
  const relevantOids = new Set();
  for (const [name, oid] of providerHeads) {
    if (name === "main") continue;
    relevantNames.add(name);
    relevantOids.add(oid);
  }
  return JSON.stringify(
    pullRequests
      .filter((pr) => relevantNames.has(pr.headRef) || relevantOids.has(pr.headOid))
      .map((pr) => [
        pr.number,
        pr.state,
        pr.closedAt,
        pr.mergedAt,
        pr.headRef,
        pr.headOid,
        pr.headRepositoryId,
        pr.headRepositoryName,
      ])
      .sort((left, right) => left[0] - right[0]),
  );
}

function assertStableRepositoryIdentity(expected, actual) {
  if (
    expected.nodeId !== actual.nodeId ||
    expected.nameWithOwner !== actual.nameWithOwner
  ) {
    throw new MeasurementFailure("provider repository identity changed during measurement");
  }
}

function isAncestor(runGit, branchOid, mainOid, branchName) {
  const result = runGit("merge-base", "--is-ancestor", branchOid, mainOid);
  if (result?.ok === true) return true;
  // `git merge-base --is-ancestor` documents exit 1 as the one ordinary negative answer. Every
  // other failure means the branch could not be measured, never that it is outstanding.
  if (result?.exitCode === 1) return false;
  throw new MeasurementFailure(`checking ancestry for ${branchName} failed: ${commandFailure("git", result)}`);
}

function ageDays(runGit, branchOid, branchName, nowSeconds) {
  const raw = requiredGit(
    runGit,
    `reading commit age for ${branchName}`,
    "show", "-s", "--format=%ct", branchOid,
  );
  if (!/^\d+$/u.test(raw)) {
    throw new MeasurementFailure(
      `reading commit age for ${branchName} returned invalid timestamp ${JSON.stringify(raw)}`,
    );
  }
  const ts = Number(raw);
  if (!Number.isSafeInteger(ts)) {
    throw new MeasurementFailure(
      `reading commit age for ${branchName} returned unsafe timestamp ${JSON.stringify(raw)}`,
    );
  }
  if (ts > nowSeconds) {
    throw new MeasurementFailure(
      `reading commit age for ${branchName} returned a future timestamp ${JSON.stringify(raw)}`,
    );
  }
  return (nowSeconds - ts) / 86400;
}

function aheadCount(runGit, mainOid, branchOid, branchName) {
  const raw = requiredGit(
    runGit,
    `counting commits ahead for ${branchName}`,
    "rev-list",
    "--count",
    `${mainOid}..${branchOid}`,
  );
  if (!/^\d+$/u.test(raw)) {
    throw new MeasurementFailure(
      `counting commits ahead for ${branchName} returned invalid count ${JSON.stringify(raw)}`,
    );
  }
  const count = Number(raw);
  if (!Number.isSafeInteger(count)) {
    throw new MeasurementFailure(
      `counting commits ahead for ${branchName} returned unsafe count ${JSON.stringify(raw)}`,
    );
  }
  return count;
}

function measureRepository({
  runGit = git,
  runRemoteGit = null,
  runGh = gh,
  environment = process.env,
  nowSeconds = Date.now() / 1000,
  graceDays = DEFAULT_GRACE_DAYS,
  warnOnly = false,
  decideExitCode = (strandedCount, isWarnOnly) =>
    strandedCount === 0 || isWarnOnly ? 0 : 1,
  write = (text) => process.stdout.write(text),
} = {}) {
  if (!Number.isSafeInteger(graceDays) || graceDays < 0 || graceDays > MAX_GRACE_DAYS) {
    throw new MeasurementFailure(`graceDays must be a safe integer from 0 through ${MAX_GRACE_DAYS}`);
  }
  if (!Number.isFinite(nowSeconds) || nowSeconds < 0) {
    throw new MeasurementFailure("measurement clock is invalid");
  }
  if (typeof write !== "function") throw new MeasurementFailure("measurement writer is not callable");
  if (typeof decideExitCode !== "function") {
    throw new MeasurementFailure("measurement verdict function is not callable");
  }

  assertFullHistory(runGit);
  const origin = readOriginIdentity(runGit);
  const originIdentity = origin.identity;
  assertAmbientIdentity(environment, originIdentity);
  const networkGit = remoteGitRunner(runGit, runRemoteGit, environment, originIdentity);

  const authoritativeA = parseRemoteHeads(
    requiredGit(networkGit, "reading authoritative remote heads snapshot A", ...REMOTE_HEADS_COMMAND),
    "authoritative remote heads snapshot A",
  );
  const mainOid = authoritativeA.get("main");
  if (mainOid === undefined) {
    throw new MeasurementFailure("authoritative remote heads snapshot A has no main head");
  }

  const localSnapshot = snapshotLocalRefs(runGit);
  assertEqualHeads(
    authoritativeA,
    localSnapshot.remoteTracking,
    "origin-tracking refs do not exactly match authoritative remote heads",
  );
  const nonProviderLocal = localEvidence(localSnapshot.localHeads, authoritativeA);

  const currentRepositoryA = repositoryIdentity(runGh, originIdentity);
  const pullRequestsA = allPullRequests(runGh, originIdentity, nowSeconds);
  const relevantPullRequestStateA = canonicalRelevantPullRequestState(
    pullRequestsA,
    authoritativeA,
  );
  const prEvidence = pullRequestEvidence(pullRequestsA, currentRepositoryA);

  const stranded = [];
  const young = [];
  let reviewed = 0;
  let landed = 0;
  let exactClosedUnmerged = 0;
  let exactMergedRecord = 0;

  const providerBranches = [...authoritativeA.entries()]
    .filter(([name]) => name !== "main")
    .map(([name, oid]) => ({ name, oid }))
    .sort((a, b) => a.name.localeCompare(b.name, "en"));

  for (const branch of providerBranches) {
    const identity = tipIdentity(branch.name, branch.oid);
    const closedVisible = prEvidence.closedUnmerged.has(identity);
    const mergedRecorded = prEvidence.merged.has(identity);
    if (closedVisible) exactClosedUnmerged++;
    if (mergedRecorded) exactMergedRecord++;

    // Reachable from main => nothing of its own is outstanding.
    if (isAncestor(runGit, branch.oid, mainOid, branch.name)) {
      landed++;
      continue;
    }
    if (prEvidence.open.has(identity)) {
      reviewed++;
      continue;
    }
    const age = ageDays(runGit, branch.oid, branch.name, nowSeconds);
    const ahead = aheadCount(runGit, mainOid, branch.oid, branch.name);
    if (ahead === 0) {
      throw new MeasurementFailure(
        `${branch.name} is not an ancestor of main but has zero exact-OID commits ahead`,
      );
    }
    const entry = {
      name: branch.name,
      age: Math.floor(age),
      ahead,
      tip: branch.oid.slice(0, 12),
      priorPr: closedVisible
        ? "closed-unmerged PR visible; not qualifying"
        : mergedRecorded
          ? "merged PR record visible; ancestry still required"
          : null,
    };
    if (age < graceDays) young.push(entry);
    else stranded.push(entry);
  }

  stranded.sort((x, y) => y.age - x.age);

  const report = [];
  report.push(`STRANDED-BRANCH GATE — grace ${graceDays}d\n`);
  report.push(`  authoritative provider heads           : ${authoritativeA.size}\n`);
  report.push(`  reachable from main                    : ${landed}\n`);
  report.push(`  exact same-repository OPEN PR tip       : ${reviewed}\n`);
  report.push(`  closed-unmerged PR visible/nonqualifying: ${exactClosedUnmerged}\n`);
  report.push(`  merged PR record; ancestry still needed : ${exactMergedRecord}\n`);
  report.push(`  inside grace period                    : ${young.length}\n`);
  report.push(`  STRANDED                               : ${stranded.length}\n`);
  report.push(`  local-only heads (NON-PROVIDER)         : ${nonProviderLocal.localOnly}\n`);
  report.push(`  locally diverged heads (NON-PROVIDER)   : ${nonProviderLocal.locallyDiverged}\n`);

  if (stranded.length === 0) {
    report.push("\nGREEN: no authoritative provider branch currently violates the policy.\n");
  } else {
    report.push("\nProvider branches carrying commits main does not have, with NO qualifying OPEN PR:\n\n");
    for (const s of stranded) {
      report.push(`  ${s.name}\n      ${s.ahead} commit(s) ahead · tip ${s.tip} · ${s.age} days old`);
      report.push(`${s.priorPr === null ? "" : ` · ${s.priorPr}`}\n`);
    }
    report.push(
      "\nEach one is provider-visible work without current review. Review its exact delta and disposition.\n" +
        "Create a draft PR only for material approved for this repository.\n" +
        "Preserve private recovery evidence before any separately authorized branch retirement.\n" +
        "A clean visibility result alone does not authorize deletion or publication of archived work.\n",
    );
  }

  // The second provider snapshot begins the closing side of the stable window. Nothing is
  // published, including a GREEN line, until provider heads, every relevant PR row, repository
  // identity, and the exact origin URL have all been re-read and proved unchanged.
  const authoritativeB = parseRemoteHeads(
    requiredGit(networkGit, "reading authoritative remote heads snapshot B", ...REMOTE_HEADS_COMMAND),
    "authoritative remote heads snapshot B",
  );
  assertEqualHeads(
    authoritativeA,
    authoritativeB,
    "authoritative remote heads changed during measurement",
  );
  const pullRequestsB = allPullRequests(runGh, originIdentity, nowSeconds);
  const relevantPullRequestStateB = canonicalRelevantPullRequestState(
    pullRequestsB,
    authoritativeA,
  );
  if (relevantPullRequestStateA !== relevantPullRequestStateB) {
    throw new MeasurementFailure("relevant pull-request state changed during measurement");
  }
  const currentRepositoryB = repositoryIdentity(runGh, originIdentity);
  assertStableRepositoryIdentity(currentRepositoryA, currentRepositoryB);
  const finalOriginUrl = requiredGit(
    runGit,
    "re-reading the exact origin URL after measurement",
    ...ORIGIN_URL_COMMAND,
  );
  if (finalOriginUrl !== origin.url) {
    throw new MeasurementFailure("origin URL changed during measurement");
  }

  const rendered = report.join("");
  write(rendered);
  return decideExitCode(stranded.length, warnOnly);
}

function executeMeasurement(options, dependencies = {}) {
  const output = [];
  const outcome = measurementOutcome(() => measureRepository({
    ...dependencies,
    graceDays: options.graceDays,
    warnOnly: options.warnOnly,
    write: (text) => output.push(text),
  }));
  return { outcome, report: output.join("") };
}

function main(options, dependencies = {}) {
  const writeOut = dependencies.writeOut ?? ((text) => process.stdout.write(text));
  const writeError = dependencies.writeError ?? ((text) => process.stderr.write(text));
  const { outcome, report } = executeMeasurement(options, dependencies);
  if (report !== "") writeOut(report);
  if (outcome.problem !== null) {
    writeError(`lint-stranded-branches: ${outcome.problem}\n`);
  }
  return outcome.exitCode;
}

function prepareGithubActionsMain(dependencies = {}) {
  const writeOut = dependencies.writeOut ?? ((text) => process.stdout.write(text));
  const writeError = dependencies.writeError ?? ((text) => process.stderr.write(text));
  const outcome = measurementOutcome(() => prepareGithubActionsRefs(dependencies));
  if (outcome.problem !== null) {
    writeError(`lint-stranded-branches: ${outcome.problem}\n`);
  } else {
    writeOut("Authoritative provider heads were materialized and proved stable.\n");
  }
  return outcome.exitCode;
}

function measurementOutcome(action) {
  try {
    const exitCode = action();
    if (exitCode !== 0 && exitCode !== 1) {
      throw new MeasurementFailure(`measurement returned unsupported exit code ${JSON.stringify(exitCode)}`);
    }
    return { exitCode, problem: null };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      exitCode: 2,
      problem: error instanceof MeasurementFailure ? message : `unexpected measurement failure: ${message}`,
    };
  }
}

function actionPath(environment, key) {
  const value = environment[key];
  if (
    typeof value !== "string" ||
    value === "" ||
    !isAbsolute(value) ||
    /[\0\r\n]/u.test(value)
  ) {
    throw new MeasurementFailure(`${key} must be a non-empty absolute path`);
  }
  return resolve(value);
}

function githubActionPaths(environment) {
  const output = actionPath(environment, "GITHUB_OUTPUT");
  const summary = actionPath(environment, "GITHUB_STEP_SUMMARY");
  const runnerTemp = actionPath(environment, "RUNNER_TEMP");
  const report = join(runnerTemp, "noa-stranded-branches-report.txt");
  if (new Set([output, summary, report]).size !== 3) {
    throw new MeasurementFailure("GitHub Actions output, summary, and report paths must be distinct");
  }
  return { output, summary, report };
}

function actionSummary(report) {
  return `## Stranded-branch sweep\n\n~~~text\n${report}${report.endsWith("\n") ? "" : "\n"}~~~\n`;
}

function publishGithubActionResult(
  outcome,
  report,
  environment,
  io = { appendFile: appendFileSync, writeFile: writeFileSync },
) {
  if (outcome.problem !== null || (outcome.exitCode !== 0 && outcome.exitCode !== 1)) {
    throw new MeasurementFailure("only an exact measured 0/1 outcome may be published");
  }
  const paths = githubActionPaths(environment);
  const summary = actionSummary(report);
  if (Buffer.byteLength(summary, "utf8") > MAX_ACTION_SUMMARY_BYTES) {
    throw new MeasurementFailure("GitHub Actions summary exceeds the 1 MiB upload limit");
  }
  io.writeFile(paths.report, report, { encoding: "utf8", flag: "wx", mode: 0o600 });
  io.appendFile(paths.summary, summary, { encoding: "utf8" });
  // Write the step outputs last. If any earlier publication fails, no downstream condition can see
  // a clean/finding code from an incomplete action result.
  io.appendFile(
    paths.output,
    `code=${outcome.exitCode}\nreport=${paths.report}\n`,
    { encoding: "utf8" },
  );
  return paths;
}

function githubActionsMain(options, dependencies = {}) {
  const environment = dependencies.environment ?? process.env;
  const writeOut = dependencies.writeOut ?? ((text) => process.stdout.write(text));
  const writeError = dependencies.writeError ?? ((text) => process.stderr.write(text));
  try {
    // Validate publication authority before spending network calls on a result that cannot be used.
    githubActionPaths(environment);
    const { outcome, report } = executeMeasurement(options, { ...dependencies, environment });
    if (outcome.problem !== null) {
      writeError(`lint-stranded-branches: ${outcome.problem}\n`);
      return 2;
    }
    publishGithubActionResult(outcome, report, environment, dependencies.io);
    writeOut(report);
    return 0;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    writeError(`lint-stranded-branches: GitHub Actions publication failed: ${message}\n`);
    return 2;
  }
}

function validateGithubActionsOutput(
  environment,
  inspect = (path) => statSync(path),
) {
  if (environment.SWEEP_OUTCOME !== "success") {
    throw new MeasurementFailure("the sweep step did not finish successfully");
  }
  if (environment.SWEEP_CODE !== "0" && environment.SWEEP_CODE !== "1") {
    throw new MeasurementFailure("the sweep output code is missing or malformed");
  }
  const report = actionPath(environment, "SWEEP_REPORT");
  let status;
  try {
    status = inspect(report);
  } catch {
    throw new MeasurementFailure("the sweep report output is missing or unreadable");
  }
  if (status === null || typeof status !== "object" || status.isFile?.() !== true) {
    throw new MeasurementFailure("the sweep report output is not a regular file");
  }
  return 0;
}

function validateGithubActionsMain(dependencies = {}) {
  const environment = dependencies.environment ?? process.env;
  const writeError = dependencies.writeError ?? ((text) => process.stderr.write(text));
  const outcome = measurementOutcome(() =>
    validateGithubActionsOutput(environment, dependencies.inspect));
  if (outcome.problem !== null) {
    writeError(`lint-stranded-branches: ${outcome.problem}\n`);
  }
  return outcome.exitCode;
}

/** Bind every byte to one reviewed workflow authority shape; no partial YAML parser. */
function workflowActionProblem(workflow) {
  if (typeof workflow !== "string") return "workflow bytes are unavailable";
  const actual = createHash("sha256").update(workflow, "utf8").digest("hex");
  return actual === CANONICAL_WORKFLOW_SHA256
    ? null
    : `workflow bytes are outside the canonical closed shape (${actual})`;
}

// ── selftest: every fail-closed arm executes the actual production measurement/publication path ──
function selftest() {
  let bad = 0;
  const report = (name, ok, detail = "") => {
    if (!ok) bad++;
    process.stdout.write(`  ${ok ? "PASS" : "FAIL"}  ${name}${detail ? ` (${detail})` : ""}\n`);
  };
  const commandOk = (stdout = "") => ({
    ok: true, stdout, exitCode: 0, errorCode: null, signal: null,
  });
  const commandError = (exitCode, errorCode = null) => ({
    ok: false, stdout: "", exitCode, errorCode, signal: null,
  });
  const fixtureCommand = (entries) => {
    const outcomes = new Map();
    for (const [commandArgs, result] of entries) {
      const key = JSON.stringify(commandArgs);
      if (!outcomes.has(key)) outcomes.set(key, []);
      outcomes.get(key).push(result);
    }
    const calls = [];
    const run = (...commandArgs) => {
      calls.push(commandArgs);
      const queue = outcomes.get(JSON.stringify(commandArgs));
      return queue?.shift() ?? commandError(97, "UNEXPECTED_FIXTURE_COMMAND");
    };
    run.calls = calls;
    return run;
  };

  const MAIN_OID = "a".repeat(40);
  const TOPIC_OID = "b".repeat(40);
  const STALE_OID = "c".repeat(40);
  const LOCAL_OID = "d".repeat(40);
  const OTHER_OID = "e".repeat(40);
  const REPOSITORY_ID = "R_fixture_repository";
  const REPOSITORY_NAME = "Example/noa";
  const ORIGIN_URL = "https://github.example/Example/noa.git";
  const ACTIONS_ORIGIN_URL = "https://github.example/Example/noa";
  const ORIGIN_IDENTITY = originIdentityFromUrl(ORIGIN_URL);
  const NOW = Math.floor(Date.parse("2026-08-31T12:00:00Z") / 1000);
  const CLOSED_AT = "2026-08-01T00:00:00Z";

  const remoteHeads = (entries) =>
    entries.map(([name, oid]) => `${oid}\trefs/heads/${name}`).join("\n");
  const localRefs = ({ local = [], tracking = [] } = {}) => [
    ...local.map(([name, oid]) => `refs/heads/${name}\0${oid}\0`),
    ...tracking.map(([name, oid]) => `refs/remotes/origin/${name}\0${oid}\0`),
  ].join("\n");
  const pullRequest = ({
    number = 1,
    state = "open",
    ref = "topic",
    sha = TOPIC_OID,
    repositoryId = REPOSITORY_ID,
    repositoryName = REPOSITORY_NAME,
    closedAt = CLOSED_AT,
    merged = false,
  } = {}) => ({
    number,
    state,
    closed_at: state === "closed" ? closedAt : null,
    merged_at: state === "closed" && merged ? closedAt : null,
    head: {
      ref,
      sha,
      repo: repositoryId === null
        ? null
        : { node_id: repositoryId, full_name: repositoryName },
    },
  });

  const buildFixture = ({
    branchName = "topic",
    branchOid = TOPIC_OID,
    authoritativeEntries = null,
    authoritativeRaw = null,
    authoritativeBRaw = null,
    localRaw = null,
    localEntries = null,
    trackingEntries = null,
    originUrl = ORIGIN_URL,
    originUrlB = originUrl,
    shallowResult = commandOk("false"),
    authoritativeAResult = null,
    authoritativeBResult = null,
    localSnapshotResult = null,
    ancestryResult = commandError(1),
    showResult = commandOk(String(NOW - 99 * 86400)),
    aheadResult = commandOk("3"),
    pageResults = [commandOk("[]")],
    pageResultsB = pageResults,
    repositoryResult = commandOk(JSON.stringify({
      node_id: REPOSITORY_ID,
      full_name: REPOSITORY_NAME,
    })),
    repositoryResultB = repositoryResult,
    environment = {},
    warnOnly = false,
    decideExitCode = undefined,
  } = {}) => {
    const provider = authoritativeEntries ?? [
      ["main", MAIN_OID],
      ...(branchName === null ? [] : [[branchName, branchOid]]),
    ];
    const snapshotA = authoritativeRaw ?? remoteHeads(provider);
    const snapshotB = authoritativeBRaw ?? snapshotA;
    const tracking = trackingEntries ?? provider;
    const local = localEntries ?? [
      ["main", MAIN_OID],
      ...(branchName === null ? [] : [[branchName, LOCAL_OID]]),
    ];
    const frozenLocal = localRaw ?? localRefs({ local, tracking });
    const gitEntries = [
      [["rev-parse", "--is-shallow-repository"], shallowResult],
      [[...ORIGIN_URL_COMMAND], commandOk(originUrl)],
      [[...REMOTE_HEADS_COMMAND], authoritativeAResult ?? commandOk(snapshotA)],
      [[...LOCAL_REF_SNAPSHOT_COMMAND], localSnapshotResult ?? commandOk(frozenLocal)],
      [["merge-base", "--is-ancestor", branchOid, MAIN_OID], ancestryResult],
      [["show", "-s", "--format=%ct", branchOid], showResult],
      [["rev-list", "--count", `${MAIN_OID}..${branchOid}`], aheadResult],
      [[...REMOTE_HEADS_COMMAND], authoritativeBResult ?? commandOk(snapshotB)],
      [[...ORIGIN_URL_COMMAND], commandOk(originUrlB)],
    ];
    const gitRunner = fixtureCommand(gitEntries);
    const ghEntries = [
      [[...repositoryIdentityCommand(ORIGIN_IDENTITY)], repositoryResult],
      ...pageResults.map((result, index) => [
        [...pullRequestPageCommand(ORIGIN_IDENTITY, index + 1)],
        result,
      ]),
      ...pageResultsB.map((result, index) => [
        [...pullRequestPageCommand(ORIGIN_IDENTITY, index + 1)],
        result,
      ]),
      [[...repositoryIdentityCommand(ORIGIN_IDENTITY)], repositoryResultB],
    ];
    const ghRunner = fixtureCommand(ghEntries);
    return {
      dependencies: {
        runGit: gitRunner,
        runRemoteGit: gitRunner,
        runGh: ghRunner,
        environment,
        nowSeconds: NOW,
        ...(decideExitCode === undefined ? {} : { decideExitCode }),
      },
      gitRunner,
      ghRunner,
      warnOnly,
    };
  };

  const fixtureMeasurement = (fixtureOptions = {}) => {
    const fixture = buildFixture(fixtureOptions);
    const output = [];
    const outcome = measurementOutcome(() => measureRepository({
      ...fixture.dependencies,
      graceDays: DEFAULT_GRACE_DAYS,
      warnOnly: fixture.warnOnly,
      write: (text) => output.push(text),
    }));
    return {
      ...outcome,
      output: output.join(""),
      gitCalls: fixture.gitRunner.calls,
      fixture,
    };
  };
  const expectFixture = (name, options, exitCode, outputPattern = null, problemPattern = null) => {
    const result = fixtureMeasurement(options);
    const ok =
      result.exitCode === exitCode &&
      (outputPattern === null || outputPattern.test(result.output)) &&
      (problemPattern === null || problemPattern.test(result.problem ?? ""));
    report(name, ok, `exit=${result.exitCode} problem=${result.problem ?? "none"}`);
    return result;
  };
  const expectParseFailure = (name, argv) => {
    const outcome = measurementOutcome(() => {
      parseOptions(argv);
      return 0;
    });
    report(name, outcome.exitCode === 2, outcome.problem ?? "none");
  };

  // The production Actions preparation path uses one explicit wildcard refspec, not checkout's
  // incidental local view, and proves the materialized tracking set against stable A/B snapshots.
  const preparationProvider = [["main", MAIN_OID], ["topic", TOPIC_OID]];
  const preparationRunner = fixtureCommand([
    [["rev-parse", "--is-shallow-repository"], commandOk("false")],
    [[...ORIGIN_URL_COMMAND], commandOk(ACTIONS_ORIGIN_URL)],
    [[...REMOTE_HEADS_COMMAND], commandOk(remoteHeads(preparationProvider))],
    [[...FETCH_ALL_REMOTE_HEADS_COMMAND], commandOk()],
    [[...LOCAL_REF_SNAPSHOT_COMMAND], commandOk(localRefs({ tracking: preparationProvider }))],
    [[...REMOTE_HEADS_COMMAND], commandOk(remoteHeads(preparationProvider))],
    [[...ORIGIN_URL_COMMAND], commandOk(ACTIONS_ORIGIN_URL)],
  ]);
  const preparationMessages = [];
  const preparationExit = prepareGithubActionsMain({
    runGit: preparationRunner,
    runRemoteGit: preparationRunner,
    environment: {},
    writeOut: (text) => preparationMessages.push(text),
    writeError: (text) => preparationMessages.push(text),
  });
  report(
    "Actions preparation uses the exact all-head refspec and proves stable equality",
    preparationExit === 0 &&
      preparationRunner.calls.filter(
        (call) => JSON.stringify(call) === JSON.stringify([...FETCH_ALL_REMOTE_HEADS_COMMAND]),
      ).length === 1 &&
      preparationRunner.calls.filter(
        (call) => JSON.stringify(call) === JSON.stringify([...REMOTE_HEADS_COMMAND]),
      ).length === 2 &&
      /proved stable/u.test(preparationMessages.join("")),
  );
  report(
    "pinned actions/checkout HTTPS origin shape resolves to the same canonical identity",
    JSON.stringify(originIdentityFromUrl(ACTIONS_ORIGIN_URL)) === JSON.stringify(ORIGIN_IDENTITY),
  );
  const preparationFailureRunner = fixtureCommand([
    [["rev-parse", "--is-shallow-repository"], commandOk("false")],
    [[...ORIGIN_URL_COMMAND], commandOk(ORIGIN_URL)],
    [[...REMOTE_HEADS_COMMAND], commandOk(remoteHeads(preparationProvider))],
    [[...FETCH_ALL_REMOTE_HEADS_COMMAND], commandError(128)],
  ]);
  report(
    "Actions all-head fetch failure is UNKNOWN, never GREEN",
    prepareGithubActionsMain({
      runGit: preparationFailureRunner,
      runRemoteGit: preparationFailureRunner,
      environment: {},
      writeOut: () => {},
      writeError: () => {},
    }) === 2,
  );

  // Core decision semantics, all through the production measurement.
  const exact = expectFixture(
    "exact authoritative/local snapshots, old branch, no PR => finding",
    {},
    1,
    /STRANDED\s+: 1/u,
  );
  report(
    "clean/finding measurement takes authoritative snapshots A and B",
    exact.gitCalls.filter((call) => JSON.stringify(call) === JSON.stringify([...REMOTE_HEADS_COMMAND])).length === 2,
  );
  expectFixture("ancestor of main => clean", { ancestryResult: commandOk() }, 0, /reachable from main\s+: 1/u);
  const stableOpen = expectFixture(
    "same-repository OPEN PR at exact current tip => reviewed",
    { pageResults: [commandOk(JSON.stringify([pullRequest()]))] },
    0,
    /OPEN PR tip\s+: 1/u,
  );
  report(
    "qualifying evidence takes exact PR and repository identity snapshots A and B",
    stableOpen.fixture.ghRunner.calls.filter(
      (call) => JSON.stringify(call) ===
        JSON.stringify([...pullRequestPageCommand(ORIGIN_IDENTITY, 1)]),
    ).length === 2 &&
      stableOpen.fixture.ghRunner.calls.filter(
        (call) => JSON.stringify(call) ===
          JSON.stringify([...repositoryIdentityCommand(ORIGIN_IDENTITY)]),
      ).length === 2,
  );
  expectFixture(
    "qualifying OPEN exact-tip PR closing between A and B => UNKNOWN",
    {
      pageResults: [commandOk(JSON.stringify([pullRequest()]))],
      pageResultsB: [commandOk(JSON.stringify([pullRequest({ state: "closed" })]))],
    },
    2,
    null,
    /relevant pull-request state changed/u,
  );
  expectFixture(
    "qualifying PR head changing between A and B => UNKNOWN",
    {
      pageResults: [commandOk(JSON.stringify([pullRequest()]))],
      pageResultsB: [commandOk(JSON.stringify([pullRequest({ sha: STALE_OID })]))],
    },
    2,
    null,
    /relevant pull-request state changed/u,
  );
  expectFixture(
    "qualifying PR repository identity changing between A and B => UNKNOWN",
    {
      pageResults: [commandOk(JSON.stringify([pullRequest()]))],
      pageResultsB: [commandOk(JSON.stringify([
        pullRequest({ repositoryId: "R_fork", repositoryName: "Fork/noa" }),
      ]))],
    },
    2,
    null,
    /relevant pull-request state changed/u,
  );
  expectFixture(
    "provider immutable identity changing between A and B => UNKNOWN",
    {
      repositoryResultB: commandOk(JSON.stringify({
        node_id: "R_replaced_repository",
        full_name: REPOSITORY_NAME,
      })),
    },
    2,
    null,
    /provider repository identity changed/u,
  );
  expectFixture(
    "closed-unmerged exact-tip PR is visible but does not qualify",
    { pageResults: [commandOk(JSON.stringify([pullRequest({ state: "closed" })]))] },
    1,
    /closed-unmerged PR visible; not qualifying/u,
  );
  expectFixture(
    "merged PR record cannot replace ancestry",
    { pageResults: [commandOk(JSON.stringify([pullRequest({ state: "closed", merged: true })]))] },
    1,
    /merged PR record visible; ancestry still required/u,
  );
  expectFixture(
    "merged tip becomes clean only when Git proves ancestry",
    {
      ancestryResult: commandOk(),
      pageResults: [commandOk(JSON.stringify([pullRequest({ state: "closed", merged: true })]))],
    },
    0,
  );
  expectFixture(
    "same-named fork OPEN PR cannot hide provider work",
    {
      pageResults: [commandOk(JSON.stringify([
        pullRequest({ repositoryId: "R_fork", repositoryName: "Fork/noa" }),
      ]))],
    },
    1,
  );
  expectFixture(
    "stale OPEN PR from a prior branch incarnation cannot hide new work",
    { pageResults: [commandOk(JSON.stringify([pullRequest({ sha: STALE_OID })]))] },
    1,
  );
  expectFixture(
    "inside grace period is measured but not yet a finding",
    { showResult: commandOk(String(NOW - 86400)) },
    0,
    /inside grace period\s+: 1/u,
  );
  expectFixture("warn-only is explicit direct-mode reporting", { warnOnly: true }, 0, /STRANDED\s+: 1/u);

  // Authoritative provider completeness and race closure.
  expectFixture(
    "main-only remote-tracking snapshot plus local topic cannot hide extra provider head",
    {
      trackingEntries: [["main", MAIN_OID]],
      localEntries: [["main", MAIN_OID], ["topic", TOPIC_OID]],
    },
    2,
    null,
    /missing=1/u,
  );
  expectFixture(
    "stale extra origin-tracking head => UNKNOWN",
    {
      branchName: null,
      trackingEntries: [["main", MAIN_OID], ["stale", STALE_OID]],
    },
    2,
    null,
    /extra=1/u,
  );
  expectFixture(
    "origin-tracking OID mismatch => UNKNOWN",
    { trackingEntries: [["main", MAIN_OID], ["topic", STALE_OID]] },
    2,
    null,
    /oid-mismatch=1/u,
  );
  expectFixture(
    "malformed authoritative head row => UNKNOWN",
    { authoritativeRaw: `not-an-oid\trefs/heads/main` },
    2,
    null,
    /row 1 is malformed/u,
  );
  expectFixture(
    "duplicate authoritative head => UNKNOWN",
    {
      authoritativeRaw: remoteHeads([
        ["main", MAIN_OID],
        ["topic", TOPIC_OID],
        ["topic", TOPIC_OID],
      ]),
    },
    2,
    null,
    /duplicate head/u,
  );
  expectFixture(
    "provider head movement between snapshot A and B => UNKNOWN",
    {
      authoritativeBRaw: remoteHeads([["main", MAIN_OID], ["topic", OTHER_OID]]),
    },
    2,
    null,
    /changed during measurement/u,
  );
  expectFixture(
    "origin URL movement during measurement => UNKNOWN",
    { originUrlB: "https://github.example/Other/noa.git" },
    2,
    null,
    /origin URL changed during measurement/u,
  );
  expectFixture(
    "local-only branch is explicit NON-PROVIDER evidence and cannot change provider completeness",
    {
      branchName: null,
      localEntries: [["main", MAIN_OID], ["local-only", LOCAL_OID]],
    },
    0,
    /local-only heads \(NON-PROVIDER\)\s+: 1/u,
  );
  expectFixture(
    "human-creatable dependabot prefix is measured, never name-exempted",
    { branchName: "dependabot/human-made" },
    1,
    /dependabot\/human-made/u,
  );
  expectFixture(
    "gh-pages is measured without authenticated exemption authority",
    { branchName: "gh-pages" },
    1,
    /gh-pages/u,
  );

  // Identity, API completeness, and terminal-time ambiguity.
  expectFixture(
    "conflicting ambient GH_REPO => UNKNOWN before provider measurement",
    { environment: { GH_REPO: "Other/noa" } },
    2,
    null,
    /GH_REPO conflicts/u,
  );
  expectFixture(
    "conflicting ambient GH_HOST => UNKNOWN before provider measurement",
    { environment: { GH_HOST: "other.example" } },
    2,
    null,
    /GH_HOST conflicts/u,
  );
  const authenticatedEnvironment = authenticatedGitEnvironment(
    { GH_TOKEN: "fixture-token" },
    ORIGIN_IDENTITY,
  );
  report(
    "HTTPS ls-remote receives token only through an isolated Git config environment",
    authenticatedEnvironment.GIT_CONFIG_COUNT === "1" &&
      authenticatedEnvironment.GIT_CONFIG_KEY_0 ===
        "http.https://github.example/.extraheader" &&
      /^AUTHORIZATION: basic /u.test(authenticatedEnvironment.GIT_CONFIG_VALUE_0) &&
      !authenticatedEnvironment.GIT_CONFIG_VALUE_0.includes("fixture-token"),
  );
  expectFixture(
    "provider identity disagreement with exact origin URL => UNKNOWN",
    {
      repositoryResult: commandOk(JSON.stringify({
        node_id: REPOSITORY_ID,
        full_name: "Other/noa",
      })),
    },
    2,
    null,
    /conflicts with the exact origin/u,
  );
  expectFixture(
    "multiple origin URLs => UNKNOWN",
    { originUrl: `${ORIGIN_URL}\nhttps://github.example/Other/noa.git` },
    2,
    null,
    /exactly one/u,
  );
  expectFixture(
    "future closed PR data => UNKNOWN, never terminal-tip green",
    {
      pageResults: [commandOk(JSON.stringify([
        pullRequest({ state: "closed", closedAt: "2026-09-01T00:00:00Z" }),
      ]))],
    },
    2,
    null,
    /closed_at terminal timestamp/u,
  );

  const firstFullPage = Array.from({ length: PULL_REQUESTS_PER_PAGE }, (_, index) =>
    pullRequest({
      number: index + 1,
      ref: `fork-${index + 1}`,
      sha: STALE_OID,
      repositoryId: "R_fork",
      repositoryName: "Fork/noa",
    }));
  expectFixture(
    "PR evidence fully paginates past 100 rows",
    {
      pageResults: [
        commandOk(JSON.stringify(firstFullPage)),
        commandOk(JSON.stringify([pullRequest({ number: 101 })])),
      ],
    },
    0,
    /OPEN PR tip\s+: 1/u,
  );
  expectFixture(
    "failed later PR page => UNKNOWN, never partial evidence",
    { pageResults: [commandOk(JSON.stringify(firstFullPage)), commandError(1)] },
    2,
    null,
    /pull-request page 2 failed/u,
  );
  expectFixture(
    "duplicate PR across pages => UNKNOWN",
    {
      pageResults: [
        commandOk(JSON.stringify(firstFullPage)),
        commandOk(JSON.stringify([pullRequest({ number: 1 })])),
      ],
    },
    2,
    null,
    /repeated PR #1/u,
  );
  expectFixture(
    "malformed PR row => UNKNOWN",
    {
      pageResults: [commandOk(JSON.stringify([
        { number: 1, state: "open", closed_at: null, merged_at: null },
      ]))],
    },
    2,
    null,
    /has no head object/u,
  );
  expectFixture(
    "deleted-fork null repository is nonqualifying, not green",
    {
      pageResults: [commandOk(JSON.stringify([
        pullRequest({ repositoryId: null }),
      ]))],
    },
    1,
  );

  // Git failures and contradictory local object evidence remain UNKNOWN.
  expectFixture(
    "authoritative snapshot without main => UNKNOWN",
    {
      authoritativeEntries: [["topic", TOPIC_OID]],
      trackingEntries: [["topic", TOPIC_OID]],
    },
    2,
    null,
    /has no main head/u,
  );
  expectFixture(
    "shallow repository => UNKNOWN",
    { shallowResult: commandOk("true") },
    2,
    null,
    /shallow clone/u,
  );
  expectFixture(
    "unexpected ancestry command failure => UNKNOWN",
    { ancestryResult: commandError(128) },
    2,
    null,
    /checking ancestry/u,
  );
  expectFixture(
    "not-ancestor with zero commits ahead => UNKNOWN contradiction",
    { aheadResult: commandOk("0") },
    2,
    null,
    /zero exact-OID commits ahead/u,
  );
  expectFixture(
    "future commit timestamp => UNKNOWN",
    { showResult: commandOk(String(NOW + 86400)) },
    2,
    null,
    /future timestamp/u,
  );

  // Strict CLI grammar.
  report(
    "strict grace parser accepts the safe maximum",
    parseOptions(["--grace-days", String(MAX_GRACE_DAYS)]).graceDays === MAX_GRACE_DAYS,
  );
  for (const [label, argv] of [
    ["missing value", ["--grace-days"]],
    ["trailing junk", ["--grace-days", "3days"]],
    ["fraction", ["--grace-days", "1.5"]],
    ["leading plus", ["--grace-days", "+3"]],
    ["leading zero", ["--grace-days", "03"]],
    ["negative", ["--grace-days", "-1"]],
    ["unsafe", ["--grace-days", "9007199254740992"]],
    ["above bound", ["--grace-days", String(MAX_GRACE_DAYS + 1)]],
    ["duplicate", ["--grace-days", "3", "--grace-days", "4"]],
    ["action warn-only broadening", ["--github-actions", "--warn-only"]],
    ["preparation grace broadening", ["--prepare-github-actions-refs", "--grace-days", "3"]],
    ["multiple modes", ["--selftest", "--github-actions"]],
  ]) expectParseFailure(`invalid CLI ${label} => UNKNOWN`, argv);

  // Mutation sensitivity: the normal old-branch fixture is 1; an injected unconditional-green
  // production verdict changes it to 0, so the exact same fixture kills that material mutation.
  const greenMutant = fixtureMeasurement({ decideExitCode: () => 0 });
  report(
    "unconditional-green production verdict mutant is killed",
    exact.exitCode === 1 && greenMutant.exitCode === 0,
    `baseline=${exact.exitCode} mutant=${greenMutant.exitCode}`,
  );
  const unsupportedOutcome = measurementOutcome(() => 7);
  report(
    "unsupported production exit code => UNKNOWN",
    unsupportedOutcome.exitCode === 2 && /unsupported exit code 7/u.test(unsupportedOutcome.problem ?? ""),
  );

  // Actual GitHub Actions production publication path, including tilde-fence injection safety.
  const memoryIo = ({ failPath = null } = {}) => {
    const files = new Map();
    return {
      files,
      writeFile(path, value, options) {
        if (path === failPath) throw new Error("fixture write failure");
        if (options?.flag === "wx" && files.has(path)) throw new Error("fixture exists");
        files.set(path, String(value));
      },
      appendFile(path, value) {
        if (path === failPath) throw new Error("fixture append failure");
        files.set(path, (files.get(path) ?? "") + String(value));
      },
      inspect(path) {
        if (!files.has(path)) throw new Error("fixture missing");
        return { isFile: () => true };
      },
    };
  };
  const actionEnvironment = {
    GITHUB_OUTPUT: "/runner/output",
    GITHUB_STEP_SUMMARY: "/runner/summary",
    RUNNER_TEMP: "/runner/temp",
  };
  const markdownBranch = "topic`inline-code`";
  const markdownFixture = buildFixture({ branchName: markdownBranch });
  const io = memoryIo();
  const actionStdout = [];
  const actionErrors = [];
  const actionExit = githubActionsMain(
    { mode: "github-actions", graceDays: DEFAULT_GRACE_DAYS, warnOnly: false },
    {
      ...markdownFixture.dependencies,
      environment: actionEnvironment,
      io,
      writeOut: (text) => actionStdout.push(text),
      writeError: (text) => actionErrors.push(text),
    },
  );
  const actionOutput = io.files.get("/runner/output") ?? "";
  const actionSummaryText = io.files.get("/runner/summary") ?? "";
  report(
    "GitHub Actions mode publishes finding output through the real production path",
    actionExit === 0 && /^code=1\nreport=\/runner\/temp\/noa-stranded-branches-report\.txt\n$/u.test(actionOutput),
    `exit=${actionExit} errors=${actionErrors.length}`,
  );
  report(
    "backtick-bearing ref is contained by a tilde-fenced summary",
    actionSummaryText.startsWith("## Stranded-branch sweep\n\n~~~text\n") &&
      actionSummaryText.includes(markdownBranch) &&
      !actionSummaryText.includes("```"),
  );
  report(
    "GitHub Actions output validator accepts exact successful 0/1 plus regular report",
    validateGithubActionsMain({
      environment: {
        SWEEP_OUTCOME: "success",
        SWEEP_CODE: "1",
        SWEEP_REPORT: "/runner/temp/noa-stranded-branches-report.txt",
      },
      inspect: (path) => io.inspect(path),
      writeError: () => {},
    }) === 0,
  );
  report(
    "missing GitHub Actions output fails closed",
    validateGithubActionsMain({
      environment: { SWEEP_OUTCOME: "success", SWEEP_CODE: "", SWEEP_REPORT: "" },
      inspect: () => ({ isFile: () => true }),
      writeError: () => {},
    }) === 2,
  );
  const outputFailureIo = memoryIo({ failPath: "/runner/output" });
  const outputFailureFixture = buildFixture();
  report(
    "GitHub Actions output-write failure fails the production action",
    githubActionsMain(
      { mode: "github-actions", graceDays: DEFAULT_GRACE_DAYS, warnOnly: false },
      {
        ...outputFailureFixture.dependencies,
        environment: actionEnvironment,
        io: outputFailureIo,
        writeOut: () => {},
        writeError: () => {},
      },
    ) === 2,
  );
  const summaryFailureIo = memoryIo({ failPath: "/runner/summary" });
  const summaryFailureFixture = buildFixture();
  report(
    "GitHub Actions summary-write failure fails before publishing outputs",
    githubActionsMain(
      { mode: "github-actions", graceDays: DEFAULT_GRACE_DAYS, warnOnly: false },
      {
        ...summaryFailureFixture.dependencies,
        environment: actionEnvironment,
        io: summaryFailureIo,
        writeOut: () => {},
        writeError: () => {},
      },
    ) === 2 && !summaryFailureIo.files.has("/runner/output"),
  );
  const oversizedIo = memoryIo();
  let oversizedSummaryRefused = false;
  try {
    publishGithubActionResult(
      { exitCode: 0, problem: null },
      "x".repeat(MAX_ACTION_SUMMARY_BYTES),
      actionEnvironment,
      oversizedIo,
    );
  } catch (error) {
    oversizedSummaryRefused =
      error instanceof MeasurementFailure && /exceeds the 1 MiB/u.test(error.message);
  }
  report(
    "oversized GitHub summary fails before report/output publication",
    oversizedSummaryRefused && oversizedIo.files.size === 0,
  );

  // Closed workflow custody: any event, permission, job, action/input, step/order, condition,
  // environment, shell body, anchor/alias, or even comment-byte drift is outside the one reviewed
  // shape. These mutations reproduce the previously accepted actionlint-valid authority changes.
  let checkedInWorkflow = null;
  try {
    checkedInWorkflow = readFileSync(WORKFLOW, "utf8");
  } catch (error) {
    report("checked-in workflow is readable", false, error instanceof Error ? error.message : String(error));
  }
  if (checkedInWorkflow !== null) {
    const problem = workflowActionProblem(checkedInWorkflow);
    report("checked-in workflow is the one canonical raw-byte shape", problem === null, problem ?? "");
    const rejectWorkflowDrift = (name, mutated) => report(
      name,
      mutated !== checkedInWorkflow && workflowActionProblem(mutated) !== null,
    );
    const safeRun = "        run: node scripts/lint-stranded-branches.mjs --github-actions --grace-days 3";
    const broadened = checkedInWorkflow.replace(
      safeRun,
      `${safeRun} --warn-only\n` +
        "\n      # Decoy only; comments are not executable evidence:\n" +
        `      # ${safeRun.trim()}\n` +
        "      - name: Safe-looking decoy\n" +
        "        run: node scripts/lint-stranded-branches.mjs --github-actions --grace-days 3",
    );
    rejectWorkflowDrift(
      "decoy/comment cannot hide a broadened real workflow invocation",
      broadened,
    );
    const preparationBroadened = checkedInWorkflow.replace(
      "        run: node scripts/lint-stranded-branches.mjs --prepare-github-actions-refs",
      "        run: node scripts/lint-stranded-branches.mjs --prepare-github-actions-refs --warn-only",
    );
    rejectWorkflowDrift(
      "workflow cannot broaden the authoritative-head preparation invocation",
      preparationBroadened,
    );
    const validationBroadened = checkedInWorkflow.replace(
      "        run: node scripts/lint-stranded-branches.mjs --validate-github-actions-output",
      "        run: node scripts/lint-stranded-branches.mjs --validate-github-actions-output\n" +
        "        continue-on-error: true",
    );
    rejectWorkflowDrift(
      "continue-on-error cannot broaden the output-validation step",
      validationBroadened,
    );
    rejectWorkflowDrift(
      "continue-on-error cannot broaden the sweep step",
      checkedInWorkflow.replace(safeRun, `${safeRun}\n        continue-on-error: true`),
    );
    rejectWorkflowDrift(
      "contents write authority drift is rejected",
      checkedInWorkflow.replace("  contents: read\n", "  contents: write\n"),
    );
    rejectWorkflowDrift(
      "id-token authority drift is rejected",
      checkedInWorkflow.replace(
        "  contents: read\n",
        "  contents: read\n  id-token: write\n",
      ),
    );
    rejectWorkflowDrift(
      "alternate checkout repository is rejected",
      checkedInWorkflow.replace(
        "        with:\n          persist-credentials: false",
        "        with:\n          repository: Other/noa\n          persist-credentials: false",
      ),
    );
    rejectWorkflowDrift(
      "action pin drift is rejected",
      checkedInWorkflow.replace(
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
        "actions/checkout@main",
      ),
    );
    rejectWorkflowDrift(
      "action input drift is rejected",
      checkedInWorkflow.replace("          node-version: 22", "          node-version: 23"),
    );
    rejectWorkflowDrift(
      "step id drift is rejected",
      checkedInWorkflow.replace("        id: sweep", "        id: shadow-sweep"),
    );
    rejectWorkflowDrift(
      "step environment drift is rejected",
      checkedInWorkflow.replace(
        "          SWEEP_CODE: ${{ steps.sweep.outputs.code }}",
        "          SWEEP_CODE: 0",
      ),
    );
    rejectWorkflowDrift(
      "output condition drift is rejected",
      checkedInWorkflow.replace(
        "        if: steps.sweep.outputs.code == '1'",
        "        if: always()",
      ),
    );
    rejectWorkflowDrift(
      "issue shell-body drift is rejected",
      checkedInWorkflow.replace('            cat "$REPORT_FILE"', "            true"),
    );
    rejectWorkflowDrift(
      "pull_request_target authority is rejected",
      checkedInWorkflow.replace("on:\n", "on:\n  pull_request_target:\n"),
    );
    rejectWorkflowDrift(
      "extra issue-close step is rejected",
      checkedInWorkflow.replace(
        "      - name: Close the tracking issue when the sweep is clean",
        "      - name: Shadow issue close\n" +
          "        if: always()\n" +
          "        run: gh issue close 1\n\n" +
          "      - name: Close the tracking issue when the sweep is clean",
      ),
    );
    rejectWorkflowDrift(
      "extra job is rejected",
      `${checkedInWorkflow}  shadow:\n` +
        "    runs-on: ubuntu-latest\n" +
        "    steps:\n" +
        "      - run: echo shadow\n",
    );
    rejectWorkflowDrift(
      "YAML anchor and alias shadow steps are rejected",
      checkedInWorkflow.replace(
        "      - name: Prove the gate can still fail",
        "      - &shadow_step\n" +
          "        name: Shadow authority\n" +
          "        run: echo shadow\n" +
          "      - *shadow_step\n\n" +
          "      - name: Prove the gate can still fail",
      ),
    );
    rejectWorkflowDrift(
      "comment-looking scalar content inside run block is bound, not dropped as a YAML comment",
      checkedInWorkflow.replace(
        "        run: |\n          set -euo pipefail",
        "        run: |\n          # ${{ github.token }}\n          set -euo pipefail",
      ),
    );
    rejectWorkflowDrift(
      "CRLF workflow bytes are outside the canonical LF shape",
      checkedInWorkflow.replaceAll("\n", "\r\n"),
    );
    for (const [label, separator] of [
      ["bare CR", "\r"],
      ["NEL", "\u0085"],
      ["LINE SEPARATOR", "\u2028"],
      ["PARAGRAPH SEPARATOR", "\u2029"],
    ]) {
      rejectWorkflowDrift(
        `${label} workflow separator is rejected`,
        checkedInWorkflow.replace("\n", separator),
      );
    }
  }

  process.stdout.write(bad === 0 ? "\nSELFTEST PASS\n" : `\nSELFTEST FAIL (${bad})\n`);
  return bad === 0 ? 0 : 2;
}

let options;
try {
  options = parseOptions(process.argv.slice(2));
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`lint-stranded-branches: ${message}\n`);
  process.exit(2);
}

if (options.mode === "selftest") process.exit(selftest());
if (options.mode === "prepare-github-actions-refs") process.exit(prepareGithubActionsMain());
if (options.mode === "github-actions") process.exit(githubActionsMain(options));
if (options.mode === "validate-github-actions-output") {
  process.exit(validateGithubActionsMain());
}
process.exit(main(options));
