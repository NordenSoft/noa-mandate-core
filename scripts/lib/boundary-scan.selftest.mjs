#!/usr/bin/env node
/**
 * boundary-scan.selftest.mjs — the PURE half of L12's arm.
 *
 * Every case is a two-way fixture: text that MUST produce a finding, and text that MUST NOT. The
 * anti-vacuity assertion at the end is the load-bearing part — a scanner that flags everything
 * satisfies every "finding" case, and one that flags nothing satisfies every "clean" case. Requiring
 * both directions non-empty is what makes the pair mean anything, and it is the assertion the
 * neighbouring claim lint added after discovering it had been testing one direction only.
 *
 * Scanner fixtures are PURE and synthetic: no provider, network, secret, or real repository identity.
 * One local-only source-hygiene assertion reads the bootstrap-authenticated candidate subject solely
 * to prove this test source does not contain or reconstruct it; the identity is never printed or used
 * as a fixture.
 * The lane arm — planting a canary in the REAL enumerated surface of each lane — lives in
 * `lint-boundary.mjs --selftest`, because fixtures can prove the scanner fires and can never prove the
 * gate LOOKS anywhere.
 */

import { spawnSync } from "node:child_process";
import { createHash, createHmac, randomBytes } from "node:crypto";
import {
  closeSync,
  mkdtempSync,
  openSync,
  readFileSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import {
  armCandidateTierANonAuthorityBootstrap,
  BOUNDARY_KNOCKOUT_BOOTSTRAP_ENV,
  canonicalBoundaryJson,
  deriveBoundaryCandidateSubject,
  deriveBoundaryControlManifest,
  prepareNestedBoundaryScannerSelftestBootstrap,
} from "./boundary-bootstrap.mjs";
import {
  createBoundaryRuntimeAuthorization,
  deriveBoundaryAuthorityBundleIdentity,
} from "./boundary-external-authority.mjs";

const SELFTEST_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const isolatedScannerSelftest = process.env[BOUNDARY_KNOCKOUT_BOOTSTRAP_ENV] !== undefined;
if (isolatedScannerSelftest) {
  if (process.env.NOA_BOUNDARY_SCANNER_SELFTEST_CHILD !== "1") {
    throw new Error("isolated scanner selftest bootstrap requires the fixed direct-child route");
  }
  armCandidateTierANonAuthorityBootstrap({ root: SELFTEST_ROOT });
}
if (process.env.NOA_BOUNDARY_SCANNER_SELFTEST_CHILD !== "1") {
  const key = Buffer.alloc(32, 0x73);
  const keyId = createHash("sha256").update(key).digest("hex");
  const manifest = deriveBoundaryControlManifest(SELFTEST_ROOT);
  const subject = deriveBoundaryCandidateSubject(SELFTEST_ROOT);
  const legacyBytes = Buffer.from("synthetic-token # scanner selftest collision\n", "utf8");
  const now = Date.now();
  const body = {
    schemaVersion: 3,
    keyId,
    reviewer: "synthetic scanner selftest",
    reviewedAt: new Date(now - 1_000).toISOString(),
    expiresAt: new Date(now + 120_000).toISOString(),
    reviewSession: "00000000-0000-4000-8000-000000000000",
    classification: "PUBLIC_DERIVED_COLLISION",
    publicArtifact: "synthetic-scanner@0.0.0",
    publicArtifactSRI: `sha512-${Buffer.alloc(64).toString("base64")}`,
    controlManifestVersion: manifest.version,
    controlManifestFiles: [...manifest.paths],
    controlManifestDigest: manifest.digest,
    legacyByteLength: legacyBytes.length,
    legacySha256: createHash("sha256").update(legacyBytes).digest("hex"),
    entries: [{ token: "synthetic-token", reason: "scanner selftest collision" }],
  };
  const policy = {
    ...body,
    mac: createHmac("sha256", key)
      .update("noa-boundary/exclusion-policy/v3\0", "utf8")
      .update(canonicalBoundaryJson(body), "utf8")
      .digest("hex"),
  };
  const policyBytes = Buffer.from(`${canonicalBoundaryJson(policy)}\n`, "utf8");
  const issuedAt = new Date(now).toISOString();
  const bundleIdentity = deriveBoundaryAuthorityBundleIdentity({
    version: "scanner-selftest-pinned-fixture-v1",
    files: manifest.files.filter((file) => [
      "scripts/lib/boundary-bootstrap.mjs",
      "scripts/lib/boundary-external-authority.mjs",
      "scripts/lib/boundary-token.mjs",
    ].includes(file.path)),
  });
  const policySha256 = createHash("sha256").update(policyBytes).digest("hex");
  const authorization = createBoundaryRuntimeAuthorization({
    bundleIdentity,
    candidateManifest: manifest,
    expiresAt: new Date(now + 120_000).toISOString(),
    issuedAt,
    nonce: randomBytes(32).toString("hex"),
    operation: "RUNTIME",
    policyBytes,
    subject,
    keyBytes: key,
    legacyBytes,
    tierBResult: {
      archiveSha256: subject.archiveSha256,
      candidateFormCount: 0,
      controlManifestDigest: manifest.digest,
      findingCount: 0,
      inputDigest: createHash("sha256").update("scanner-selftest-tier-b-input").digest("hex"),
      policySha256,
      resultDigest: createHash("sha256").update("scanner-selftest-tier-b-pass").digest("hex"),
      scannedUnitCount: 1,
      scannerId: "noa-boundary-tier-b/v1",
      schemaVersion: 1,
      verdict: "PASS",
    },
  });
  key.fill(0);
  const work = mkdtempSync(join(tmpdir(), "noa-boundary-scanner-selftest-"));
  const authorizationPath = join(work, "authorization.json");
  writeFileSync(authorizationPath, authorization.authorizationBytes, { mode: 0o600 });
  const authorizationFd = openSync(authorizationPath, "r");
  unlinkSync(authorizationPath);
  const child = spawnSync(process.execPath, [fileURLToPath(import.meta.url)], {
    cwd: SELFTEST_ROOT,
    encoding: "utf8",
    env: {
      ...process.env,
      NOA_BOUNDARY_AUTHORIZATION_FD: "3",
      NOA_BOUNDARY_SCANNER_SELFTEST_CHILD: "1",
    },
    shell: false,
    stdio: ["ignore", "pipe", "pipe", authorizationFd],
  });
  closeSync(authorizationFd);
  rmSync(work, { recursive: true, force: true });
  process.stdout.write(String(child.stdout ?? ""));
  process.stderr.write(String(child.stderr ?? ""));
  process.exit(child.status ?? 1);
}

const {
  boundaryScannerAuthority,
  scanShapes, scanRepoRefs, scanPrivacyAdjacency, scanTokens, scanSourceMap,
  extractCandidates, collapseDigits, tokenForms, reachableTokenForms,
  tokenNgramSize, commitToken, contentKey, pathContentKey,
  isDeclarationArtifactPath, safeBoundaryLabel, mask, SEVERITY, __testing,
} = await import("./boundary-scan.mjs");
if (isolatedScannerSelftest
    && prepareNestedBoundaryScannerSelftestBootstrap(boundaryScannerAuthority) !== null) {
  throw new Error("nested scanner selftest authority must be a non-delegable leaf");
}

const ALLOWLIST = {
  orgs: {
    examplecorp: [
      "public-thing", "another-public", ".public-dot", "_public-underscore", "-public-dash",
    ],
  },
};
const SYNTHETIC_OWNER = "examplearmorg";
const SYNTHETIC_REPOSITORY = "synthetic-confidential-repo";
const SYNTHETIC_COORDINATE = `${SYNTHETIC_OWNER}/${SYNTHETIC_REPOSITORY}`;
const SECOND_SYNTHETIC_OWNER = "samplearmorg";
const SYNTHETIC_ALLOWLIST = {
  orgs: {
    [SYNTHETIC_OWNER]: [
      "synthetic-public-repo", ".synthetic-public-repo", "_synthetic-public-repo", "-synthetic-public-repo",
    ],
    [SECOND_SYNTHETIC_OWNER]: ["synthetic-public-library"],
  },
};
const SYNTHETIC_FORM = reachableTokenForms(SYNTHETIC_REPOSITORY)[0];
const SYNTHETIC_KEY = Buffer.from("synthetic-local-boundary-key-v1", "utf8");
const SYNTHETIC_DIGEST = commitToken(SYNTHETIC_KEY, SYNTHETIC_FORM);
const SYNTHETIC_LOOKUP = (candidate) => commitToken(SYNTHETIC_KEY, candidate) === SYNTHETIC_DIGEST;
const SYNTHETIC_NGRAMS = [tokenNgramSize(SYNTHETIC_FORM)];
const percentEncodeAllAscii = (value) => [...value]
  .map((character) => `%${character.charCodeAt(0).toString(16).padStart(2, "0")}`)
  .join("");
// Deliberately outside the static evaluator's claim: this builds synthetic fixtures at runtime so
// the public-boundary gate does not mistake its own test source for a disclosure. Each argument is
// independently harmless; the scanner under test receives the joined value explicitly.
const runtimeJoin = (...parts) => parts.join("");
const runtimeAscii = (...codeUnits) => {
  if (codeUnits.length === 0 || codeUnits.length > 16
      || codeUnits.some((unit) => !Number.isInteger(unit) || unit < 0x20 || unit > 0x7e)) {
    throw new TypeError("synthetic runtime ASCII fixture is outside its bounded grammar");
  }
  return String.fromCharCode(...codeUnits);
};
const TOKEN_SEPARATORS = Object.freeze(["-", "_", " ", "/"]);
const TOKEN_SEPARATOR_CASES = Object.freeze([
  ...TOKEN_SEPARATORS.flatMap((left) => TOKEN_SEPARATORS.map((right) => ({
    name: `a three-part token written with ${JSON.stringify(left)} then ${JSON.stringify(right)}`,
    expect: "finding",
    rule: "token-commitment",
    run: () => scanTokens(
      "docs/a.md",
      `the widget${left}label${right}programme`,
      (candidate) => candidate === "widget-label-programme",
      [1, 3],
    ),
  }))),
  ...TOKEN_SEPARATORS.flatMap((left) => TOKEN_SEPARATORS.map((right) => ({
    name: `a numbered family written with ${JSON.stringify(left)} then ${JSON.stringify(right)}`,
    expect: "finding",
    rule: "token-commitment",
    run: () => scanTokens(
      "docs/a.md",
      `closes PROG${left}alpha${right}77`,
      (candidate) => candidate === "prog-alpha-#",
      [1, 3],
    ),
  }))),
  ...TOKEN_SEPARATORS.map((separator) => ({
    name: `a dotted token segment followed by ${JSON.stringify(separator)}`,
    expect: "finding",
    rule: "token-commitment",
    run: () => scanTokens(
      "docs/a.md",
      `the widget.label${separator}programme`,
      (candidate) => candidate === "widget.label-programme",
      [1, 2],
    ),
  })),
]);
const syntheticCombined = (source, file = "synthetic/input.mjs") => {
  const repo = scanRepoRefs(file, source, SYNTHETIC_ALLOWLIST);
  const token = scanTokens(file, source, SYNTHETIC_LOOKUP, SYNTHETIC_NGRAMS);
  return { findings: [...repo.findings, ...token.findings], suppressed: [...repo.suppressed, ...token.suppressed] };
};
const syntheticRaw = (source, file = "synthetic/input.mjs") => {
  const repo = __testing.scanRepoRefsRaw(file, source, SYNTHETIC_ALLOWLIST);
  const token = __testing.scanTokensRaw(file, source, SYNTHETIC_LOOKUP, SYNTHETIC_NGRAMS);
  return { findings: [...repo.findings, ...token.findings], suppressed: [...repo.suppressed, ...token.suppressed] };
};
const syntheticRepoOnly = (source, file = "synthetic/input.mjs") => scanRepoRefs(file, source, SYNTHETIC_ALLOWLIST);
const criticalRepoSuppressionProbe = () => {
  const baseline = syntheticRepoOnly(SYNTHETIC_COORDINATE, "synthetic/suppression.md");
  const digest = baseline.findings[0]?.digest;
  if (digest === undefined) return baseline;
  return syntheticRepoOnly(
    `${SYNTHETIC_COORDINATE} // noa-boundary-ok:${digest}:synthetic-fixture`,
    "synthetic/suppression.md",
  );
};
// Assembled from parts so this selftest is not itself an instance of what it tests. The gate scans
// its own source like every other file, and it FOUND both of these on the first run — which is the
// only reason they are written this way rather than exempted.
const HOME = runtimeJoin("/User", "s/");
const UUID = runtimeJoin("a1b2c3d4-5e6f-4a7b-", "8c9d-0e1f2a3b4c5d");
const SUPPRESSION_MARKER = "noa-boundary-ok:";
const SUPPRESSION_REASON = "published-vector-id";
const suppressedUuidFixture = ({
  marker = SUPPRESSION_MARKER,
  reason = SUPPRESSION_REASON,
  digest = __testing.digest8(UUID),
} = {}) => scanShapes(
  "docs/a.md",
  `id ${UUID}  <!-- ${marker}${digest}:${reason} -->`,
);

const CASES = [
  // ── Tier A: must FIRE ──────────────────────────────────────────────────────────────────────────
  { name: "absolute home path", expect: "finding", rule: "home-path",
    run: () => scanShapes("docs/a.md", `see ${HOME}someone/proj/file.md line 3`) },
  { name: "planning directory pointer", expect: "finding", rule: "planning-dir",
    run: () => scanShapes("docs/a.md", runtimeJoin("quoted from ", ".", "plan/BUILD-SPEC.md §4")) },
  { name: "agent doctrine directory", expect: "finding", rule: "agent-doctrine-dir",
    run: () => scanShapes("docs/a.md", runtimeJoin("the scratch dir under .", "claude/scratch holds it")) },
  // Synthetic fixtures are assembled through runtimeJoin so the gate does not treat its own source
  // as a disclosure. Suppression behavior itself is exercised separately, including its knockouts.
  { name: "private worktree root", expect: "finding", rule: "worktree-dir",
    run: () => scanShapes("docs/a.md", runtimeJoin("built in noa-", "worktrees/feature-x")) },
  { name: "hosting provider hostname", expect: "finding", rule: "infra-vendor-host",
    run: () => scanShapes("docs/a.md", runtimeJoin("proxy at monorail", ".rlwy", ".net")) },
  { name: "hosting provider environment variable", expect: "finding", rule: "infra-vendor-host",
    run: () => scanShapes("docs/a.md", runtimeJoin("reads RAILWAY", "_PROJECT_ID at boot")) },
  { name: "numbered account identifier", expect: "finding", rule: "infra-account-id",
    run: () => scanShapes("docs/a.md", runtimeJoin("tenant acct-", "4711-eu-north-1 is live")) },
  { name: "database connection URL", expect: "finding", rule: "infra-db-url",
    run: () => scanShapes("docs/a.md", runtimeJoin("postgres", "://u:p@db.internal.exa", "mple-corp.io", ":5432/app")) },
  { name: "database scheme matching is case-equivalent", expect: "finding", rule: "infra-db-url",
    run: () => scanShapes("docs/a.md", runtimeJoin("PoStGrEs", "://u:p@db.synthetic-", "corp.io", ":5432/app")) },
  { name: "a reserved word in credentials cannot allow a foreign database authority", expect: "finding", rule: "infra-db-url",
    run: () => scanShapes("docs/a.md", runtimeJoin("postgres", "://user:localhost@db.synthetic-", "corp.io", ":5432/app")) },
  { name: "a reserved host in a database query cannot allow a foreign authority", expect: "finding", rule: "infra-db-url",
    run: () => scanShapes("docs/a.md", runtimeJoin("postgres", "://db.synthetic-", "corp.io", ":5432/app?next=localhost")) },
  { name: "a reserved host in a database path cannot allow a foreign authority", expect: "finding", rule: "infra-db-url",
    run: () => scanShapes("docs/a.md", runtimeJoin("postgres", "://db.synthetic-", "corp.io", ":5432/example.com")) },
  { name: "a reserved host in a database fragment cannot allow a foreign authority", expect: "finding", rule: "infra-db-url",
    run: () => scanShapes("docs/a.md", runtimeJoin("postgres", "://db.synthetic-", "corp.io", ":5432/app#localhost")) },
  { name: "dialable host and port", expect: "finding", rule: "infra-host-port",
    run: () => scanShapes("docs/a.md", runtimeJoin("endpoint shuttle.proxy.corp-h", "ost.io", ":41883")) },
  { name: "a two-label dialable host and port", expect: "finding", rule: "infra-host-port",
    run: () => scanShapes("docs/a.md", runtimeJoin("endpoint shuttle.", "synthetic:41883")) },
  { name: "a reserved-host substring cannot allow a foreign authority", expect: "finding", rule: "infra-host-port",
    run: () => scanShapes("docs/a.md", runtimeJoin("endpoint github.com.", "synthetic:41883")) },
  { name: "a standalone source-like two-label host and range remains an endpoint", expect: "finding", rule: "infra-host-port",
    run: () => scanShapes("docs/a.md", runtimeJoin("engine.ts", runtimeAscii(58), "41883-41900")) },
  { name: "a URL authority remains an endpoint", expect: "finding", rule: "infra-host-port",
    run: () => scanShapes("docs/a.md", runtimeJoin("https://engine.ts", runtimeAscii(58), "41883/path")) },
  { name: "a URL userinfo authority remains an endpoint", expect: "finding", rule: "infra-host-port",
    run: () => scanShapes("docs/a.md", runtimeJoin("https://user@engine.ts", runtimeAscii(58), "41883/path")) },
  { name: "an inline path-like non-source host and range remains an endpoint", expect: "finding", rule: "infra-host-port",
    run: () => scanShapes("docs/a.md", runtimeJoin("`routes/service.synthetic", runtimeAscii(58), "41883-41900`")) },
  { name: "a non-loopback IPv4 database authority", expect: "finding", rule: "infra-db-url",
    run: () => scanShapes("docs/a.md", runtimeJoin("post", "gres", runtimeAscii(58, 47, 47), "u:p@10.20.30.40:5432/db")) },
  { name: "a non-loopback balanced IPv6 database authority", expect: "finding", rule: "infra-db-url",
    run: () => scanShapes("docs/a.md", runtimeJoin("post", "gres", runtimeAscii(58, 47, 47), "u:p@[fd00::42]:5432/db")) },
  { name: "home paths are case-equivalent", expect: "finding", rule: "home-path",
    run: () => scanShapes("docs/a.md", runtimeJoin("/uSeRs/", "SyntheticOperator/private/file")) },
  { name: "worktree roots are case-equivalent", expect: "finding", rule: "worktree-dir",
    run: () => scanShapes("docs/a.md", runtimeJoin("NOA-", "WORKTREES/feature/file")) },
  { name: "provider DNS is case-equivalent", expect: "finding", rule: "infra-vendor-host",
    run: () => scanShapes("docs/a.md", runtimeJoin("Synthetic", ".RlWy", ".NeT")) },
  { name: "a split static provider host is reconstructed for shape scanning", expect: "finding", rule: "infra-vendor-host",
    run: () => scanShapes("synthetic/input.mjs", "const endpoint = \"synthetic\" + \".rlwy\" + \".net\";") },
  { name: "a JSON-cooked home path is reconstructed for shape scanning", expect: "finding", rule: "home-path",
    run: () => scanShapes("synthetic/input.json", '{"path":"\\u002fUsers\\u002fSyntheticOperator\\u002fnotes"}') },
  { name: "RFC4122 identifier in prose", expect: "finding", rule: "uuid",
    run: () => scanShapes("docs/a.md", `environment ${UUID} is production`) },
  { name: "numbered account in a conformance vector", expect: "finding", rule: "fixture-account-shape",
    run: () => scanShapes("conformance/vectors/v1.json", runtimeJoin('{ "sub": "acct-', '90210-x" }')) },
  { name: "absolute path compiled into a published artefact", expect: "finding", rule: "artefact-absolute-path",
    run: () => scanShapes("dist/src/index.d.ts", `//# ${HOME}someone/build/src/index.ts`) },
  { name: "absolute path compiled into a published ESM declaration artefact", expect: "finding", rule: "artefact-absolute-path",
    run: () => scanShapes("dist/src/index.d.mts", `//# ${HOME}someone/build/src/index.ts`) },
  { name: "absolute path compiled into a published CommonJS declaration artefact", expect: "finding", rule: "artefact-absolute-path",
    run: () => scanShapes("dist/src/index.d.cts", `//# ${HOME}someone/build/src/index.ts`) },
  { name: "an absolute path under dist/ is an artefact path", expect: "finding", rule: "artefact-absolute-path",
    run: () => scanShapes("packages/x/dist/index.js", "const p = '/opt" + "ional/build/root/thing';") },

  // ── Tier A: must NOT fire ──────────────────────────────────────────────────────────────────────
  { name: "CI runner home is not an operator home", expect: "clean",
    run: () => scanShapes("docs/a.md", `${HOME}runner/work/repo/repo/dist`) },
  { name: "a repo-relative path is not a disclosure", expect: "clean",
    run: () => scanShapes("docs/a.md", "see packages/gate/src/engine.ts:88") },
  { name: "a repository source line-range citation is not a dialable endpoint", expect: "clean",
    run: () => scanShapes("docs/a.md", "`packages/gate/src/engine.ts:1265-1275`") },
  { name: "a package-relative source line-range citation is not a dialable endpoint", expect: "clean",
    run: () => scanShapes("docs/a.md", "`gate/src/engine.ts:1054-1064`") },
  { name: "a documented placeholder connection string", expect: "clean",
    run: () => scanShapes("docs/a.md", "postgres" + "://user:pass@localhost:5432/db") },
  { name: "a case-equivalent reserved database authority remains a placeholder", expect: "clean",
    run: () => scanShapes("docs/a.md", "POSTGRES://user:pass@API.EXAMPLE.COM:5432/db?next=foreign.invalid.attacker") },
  { name: "a trailing DNS root dot is normalized on the database authority only", expect: "clean",
    run: () => scanShapes("docs/a.md", "POSTGRES://user:pass@API.EXAMPLE.COM.:5432/db") },
  { name: "an authority variable is allowed only as the complete database host", expect: "clean",
    run: () => scanShapes("docs/a.md", "postgres://${DB_HOST}:5432/db") },
  { name: "a reserved authority remains a placeholder for the AMQP scheme", expect: "clean",
    run: () => scanShapes("docs/a.md", "amqp://user:pass@localhost:5672/vhost") },
  { name: "a reserved example host with a port", expect: "clean",
    run: () => scanShapes("docs/a.md", "https://api.example.com:8443/v1") },
  { name: "an exact two-label reserved host with a port", expect: "clean",
    run: () => scanShapes("docs/a.md", "example.com:8443") },
  { name: "a balanced IPv6 loopback database authority", expect: "clean",
    run: () => scanShapes("docs/a.md", "postgres://user:pass@[::1]:5432/db") },
  { name: "a provider suffix followed by another DNS label is not the provider", expect: "clean",
    run: () => scanShapes("docs/a.md", runtimeJoin("railway.app.", "synthetic")) },
  { name: "a provider name embedded inside a larger DNS label is not the provider", expect: "clean",
    run: () => scanShapes("docs/a.md", runtimeJoin("notrailway", ".app")) },
  { name: "a short provider suffix followed by another DNS label is not the provider", expect: "clean",
    run: () => scanShapes("docs/a.md", runtimeJoin("rlwy.net.", "synthetic")) },
  { name: "the all-zero example identifier", expect: "clean",
    run: () => scanShapes("docs/a.md", "id 00000000-0000-4000-8000-000000000000") },
  { name: "a version string is not an account id", expect: "clean",
    run: () => scanShapes("conformance/vectors/v1.json", '{ "v": "0.8.0", "acct": "acct-example-1" }') },
  { name: "a system path in an artefact carries no identity", expect: "clean",
    run: () => scanShapes("dist/src/index.js", "require('/usr/lib/node/foo/bar.js')") },
  { name: "a source path is not an artefact path", expect: "clean",
    run: () => scanShapes("src/index.ts", "// see /some/deep/relative/looking/thing") },
  // Measured false positive from the first draft: `.mjs` alone made every SCRIPT an artefact, and 17
  // lines of ordinary source — badge URLs, example invoice URIs, a system volume path — went red.
  { name: "a build-tool script is not a build artefact", expect: "clean",
    run: () => scanShapes("scripts/tool.mjs", "// see /some/deep/relative/looking/thing") },
  { name: "a URL path is not a filesystem path", expect: "clean",
    run: () => scanShapes("dist/src/index.js", "// https://img.shields.io/npm/v/pkg and https://github.com/o/r") },

  // ── the INVERSION ──────────────────────────────────────────────────────────────────────────────
  { name: "an org repo absent from the public list", expect: "finding", rule: "repo-not-public",
    run: () => scanRepoRefs("docs/a.md", "mirrors examplecorp/unlisted-sibling nightly", ALLOWLIST) },
  { name: "the same reference as a full forge URL", expect: "finding", rule: "repo-not-public",
    run: () => scanRepoRefs("docs/a.md", "https://github.com/examplecorp/unlisted-sibling.git", ALLOWLIST) },
  { name: "a scheme-less forge host cannot sanitise a non-public repository path", expect: "finding", rule: "repo-not-public",
    run: () => scanRepoRefs("docs/a.md", "github.com/examplecorp/unlisted-sibling", ALLOWLIST) },
  { name: "an XML eref target remains subject to the repository inversion", expect: "finding", rule: "repo-not-public",
    run: () => scanRepoRefs(
      "docs/a.xml",
      '<eref target="https://github.com/examplecorp/unlisted-sibling">source</eref>',
      ALLOWLIST,
    ) },
  { name: "a forge URL soft-wrapped after its owner remains subject to the inversion", expect: "finding", rule: "repo-not-public",
    run: () => scanRepoRefs("docs/a.txt", "https://github.com/examplecorp/\n   unlisted-sibling", ALLOWLIST) },
  { name: "a forge URL soft-wrapped after host and owner remains subject to the inversion", expect: "finding", rule: "repo-not-public",
    run: () => scanRepoRefs("docs/a.txt", "https://github.com/\n   examplecorp/\n   unlisted-sibling", ALLOWLIST) },
  { name: "a DNS-equivalent mixed-case forge URL fires", expect: "finding", rule: "repo-not-public",
    run: () => scanRepoRefs("docs/a.md", "https://GitHub.com/examplecorp/unlisted-sibling.git", ALLOWLIST) },
  { name: "a slash-prefixed known-owner coordinate fires", expect: "finding", rule: "repo-not-public",
    run: () => scanRepoRefs("docs/a.md", "/examplecorp/unlisted-sibling", ALLOWLIST) },
  { name: "a raw-content known-owner coordinate fires", expect: "finding", rule: "repo-not-public",
    run: () => scanRepoRefs("docs/a.md", "https://raw.githubusercontent.com/examplecorp/unlisted-sibling/main/file", ALLOWLIST) },
  { name: "a GitLab known-owner coordinate fires", expect: "finding", rule: "repo-not-public",
    run: () => scanRepoRefs("docs/a.md", "https://gitlab.com/examplecorp/unlisted-sibling/-/raw/main/file", ALLOWLIST) },
  { name: "an overlapping filesystem segment reaches the known owner", expect: "finding", rule: "repo-not-public",
    run: () => scanRepoRefs("docs/a.md", "/workspace/cache/examplecorp/unlisted-sibling/file", ALLOWLIST) },
  { name: "an overlapping Windows segment reaches the known owner", expect: "finding", rule: "repo-not-public",
    run: () => scanRepoRefs("docs/a.md", "C:\\workspace\\examplecorp\\unlisted-sibling\\file", ALLOWLIST) },
  { name: "a dot-leading repository name fires in a forge URL", expect: "finding", rule: "repo-not-public",
    run: () => scanRepoRefs("docs/a.md", "https://github.com/examplecorp/.unlisted-sibling", ALLOWLIST) },
  { name: "an underscore-leading repository name fires on raw content", expect: "finding", rule: "repo-not-public",
    run: () => scanRepoRefs("docs/a.md", "https://raw.githubusercontent.com/examplecorp/_unlisted-sibling/main/file", ALLOWLIST) },
  { name: "a dash-leading repository name fires on GitLab", expect: "finding", rule: "repo-not-public",
    run: () => scanRepoRefs("docs/a.md", "https://gitlab.com/examplecorp/-unlisted-sibling/-/raw/main/file", ALLOWLIST) },
  { name: "a punctuation-leading repository name fires in a filesystem path", expect: "finding", rule: "repo-not-public",
    run: () => scanRepoRefs("docs/a.md", "/workspace/examplecorp/.unlisted-sibling/file", ALLOWLIST) },
  { name: "a derived punctuation-leading repository name fires", expect: "finding", rule: "repo-not-public",
    run: () => scanRepoRefs(
      "synthetic/repo.ts",
      'const source = "examplecorp" + "/" + "_unlisted-sibling";',
      ALLOWLIST,
    ) },
  { name: "an org repo that IS public", expect: "clean",
    run: () => scanRepoRefs("docs/a.md", "see examplecorp/public-thing for the spec", ALLOWLIST) },
  { name: "an allowlisted bare repo with a .git suffix is public", expect: "clean",
    run: () => scanRepoRefs("docs/a.md", "clone examplecorp/public-thing.git for the spec", ALLOWLIST) },
  { name: "a scheme-less forge path is clean only when the snapshot lists the repository", expect: "clean",
    run: () => scanRepoRefs("docs/a.md", "github.com/examplecorp/public-thing", ALLOWLIST) },
  { name: "a public XML eref target remains clean", expect: "clean",
    run: () => scanRepoRefs(
      "docs/a.xml",
      '<eref target="https://github.com/examplecorp/public-thing">source</eref>',
      ALLOWLIST,
    ) },
  { name: "a public soft-wrapped forge URL remains clean", expect: "clean",
    run: () => scanRepoRefs("docs/a.txt", "https://github.com/examplecorp/\n   public-thing", ALLOWLIST) },
  { name: "a forge hostname alone is not a repository reference", expect: "clean",
    run: () => scanRepoRefs("docs/a.md", "github.com", ALLOWLIST) },
  { name: "a public coordinate stays clean on raw content", expect: "clean",
    run: () => scanRepoRefs("docs/a.md", "https://raw.githubusercontent.com/examplecorp/public-thing/main/file", ALLOWLIST) },
  { name: "a public dot-leading coordinate stays clean in a forge URL", expect: "clean",
    run: () => scanRepoRefs("docs/a.md", "https://github.com/examplecorp/.public-dot", ALLOWLIST) },
  { name: "a public underscore-leading coordinate stays clean on raw content", expect: "clean",
    run: () => scanRepoRefs("docs/a.md", "https://raw.githubusercontent.com/examplecorp/_public-underscore/main/file", ALLOWLIST) },
  { name: "a public dash-leading coordinate stays clean on GitLab", expect: "clean",
    run: () => scanRepoRefs("docs/a.md", "https://gitlab.com/examplecorp/-public-dash/-/raw/main/file", ALLOWLIST) },
  { name: "a public punctuation-leading coordinate stays clean in a filesystem path", expect: "clean",
    run: () => scanRepoRefs("docs/a.md", "/workspace/examplecorp/.public-dot/file", ALLOWLIST) },
  { name: "an npm scope is not invented into a repository", expect: "clean",
    run: () => scanRepoRefs("docs/a.md", "install @examplecorp/unlisted-sibling", ALLOWLIST) },
  { name: "a known-owner suffix inside an underscore segment is not invented into a repository", expect: "clean",
    run: () => scanRepoRefs("docs/a.md", "cache/foo_examplecorp/unlisted-sibling", ALLOWLIST) },
  { name: "a synthetic non-public repository reference fires", expect: "finding", rule: "repo-not-public",
    run: () => syntheticRepoOnly(`source at ${SYNTHETIC_COORDINATE}`, "synthetic/reference.md") },
  { name: "a reserved IPv6 database authority does not hide a confidential path", expect: "finding", rule: "repo-not-public",
    run: () => syntheticRepoOnly(
      `postgres://user:pass@[::1]:5432/${SYNTHETIC_COORDINATE}?next=${SYNTHETIC_OWNER}%2F${SYNTHETIC_REPOSITORY}`,
      "synthetic/reference.md",
    ) },
  { name: "a renamed synthetic repository reference fires", expect: "finding", rule: "repo-not-public",
    run: () => syntheticRepoOnly(`source at ${SYNTHETIC_COORDINATE}-renamed`, "synthetic/reference.md") },
  { name: "the same synthetic repository name under another synthetic owner fires", expect: "finding", rule: "repo-not-public",
    run: () => syntheticRepoOnly(`source at ${SECOND_SYNTHETIC_OWNER}/${SYNTHETIC_REPOSITORY}`, "synthetic/reference.md") },
  { name: "a CRITICAL repository finding ignores an exact inline digest", expect: "finding", rule: "repo-not-public",
    run: criticalRepoSuppressionProbe },
  { name: "an unknown org is not this repository's business", expect: "clean",
    run: () => scanRepoRefs("docs/a.md", "vendored from someoneelse/their-lib", ALLOWLIST) },
  { name: "a workspace path is not an org-qualified repo", expect: "clean",
    run: () => scanRepoRefs("docs/a.md", "packages/gate and dist/src and node_modules/typescript", ALLOWLIST) },

  // ── parser-based source reconstruction and bounded repeated encoding ──────────────────────────
  // Every confidential input is synthetic and authenticated through the same HMAC lookup shape as
  // Tier B. The source values all resolve to the same coordinate; only their source spelling differs.
  { name: "an authenticated coordinate written contiguously still fires", expect: "finding", rule: "token-commitment",
    run: () => syntheticCombined(`const source = "${SYNTHETIC_OWNER}/${SYNTHETIC_REPOSITORY}";`) },
  { name: "an authenticated coordinate in a full forge URL still fires", expect: "finding", rule: "token-commitment",
    run: () => syntheticCombined(`const source = "https://github.com/${SYNTHETIC_OWNER}/${SYNTHETIC_REPOSITORY}.git";`) },
  { name: "same-line literal concatenation fires", expect: "finding", rule: "token-commitment",
    run: () => syntheticCombined(`const source = "${SYNTHETIC_OWNER}/" + "synthetic-" + "confidential-repo";`) },
  { name: "multiline literal concatenation fires", expect: "finding", rule: "token-commitment",
    run: () => syntheticCombined(`const source =\n  "${SYNTHETIC_OWNER}" +\n  "/" +\n  "synthetic-" +\n  "confidential-repo";`) },
  { name: "multiline no-substitution template concatenation fires", expect: "finding", rule: "token-commitment",
    run: () => syntheticCombined(`const source =\n  \`${SYNTHETIC_OWNER}\` +\n  \`/\` +\n  \`synthetic-\` +\n  \`confidential-repo\`;`) },
  { name: "parenthesized literal concatenation with comments fires", expect: "finding", rule: "token-commitment",
    run: () => syntheticCombined(`const source = ("${SYNTHETIC_OWNER}" /* join */ + "/") + ("synthetic-" + "confidential-repo");`) },
  { name: "a percent-encoded coordinate separator fires", expect: "finding", rule: "token-commitment",
    run: () => syntheticCombined(`const source = "${SYNTHETIC_OWNER}%2F${SYNTHETIC_REPOSITORY}";`) },
  { name: "a percent-encoded forge URL separator fires", expect: "finding", rule: "token-commitment",
    run: () => syntheticCombined(`const source = "https://github.com/${SYNTHETIC_OWNER}%2F${SYNTHETIC_REPOSITORY}.git";`) },
  { name: "a fully percent-encoded coordinate fires", expect: "finding", rule: "token-commitment",
    run: () => syntheticCombined(`const source = "${percentEncodeAllAscii(`${SYNTHETIC_OWNER}/${SYNTHETIC_REPOSITORY}`)}";`) },
  { name: "a JavaScript Unicode-escaped coordinate separator fires", expect: "finding", rule: "token-commitment",
    run: () => syntheticCombined(`const source = "${SYNTHETIC_OWNER}\\u002f${SYNTHETIC_REPOSITORY}";`) },
  { name: "JavaScript hex-escaped separators fire", expect: "finding", rule: "token-commitment",
    run: () => syntheticCombined(`const source = "${SYNTHETIC_OWNER}\\x2fsynthetic\\x2dconfidential\\x2drepo";`) },
  { name: "legacy CommonJS octal-escaped separators fire", expect: "finding", rule: "token-commitment",
    run: () => syntheticCombined(`const source = "${SYNTHETIC_OWNER}\\057synthetic\\055confidential\\055repo";`, "synthetic/input.cjs") },
  { name: "export default does not turn an untagged template into a tagged template", expect: "finding", rule: "repo-not-public",
    run: () => syntheticRepoOnly(
      `export default \`${SYNTHETIC_OWNER}\\u002fsynthetic\\u002dconfidential\\u002drepo\`;`,
      "synthetic/input.mjs",
    ) },
  { name: "a block boundary preserves an untagged no-substitution template", expect: "finding", rule: "repo-not-public",
    run: () => syntheticRepoOnly(
      `{ \`${SYNTHETIC_OWNER}\\u002fsynthetic\\u002dconfidential\\u002drepo\`; }`,
      "synthetic/input.mjs",
    ) },
  { name: "all-static template substitutions are reconstructed", expect: "finding", rule: "repo-not-public",
    run: () => syntheticRepoOnly(
      "const source = `example${\"armorg\"}${\"/\"}synthetic-${\"confidential\"}-repo`;",
      "synthetic/input.ts",
    ) },
  { name: "scope-safe const propagation crosses TypeScript as and non-null wrappers", expect: "finding", rule: "repo-not-public",
    run: () => syntheticRepoOnly(
      `const owner = "example" + "armorg";\nconst slash = "\\u002f";\nconst repo = \`synthetic\${"-"}confidential\${"-"}repo\`;\nexport default ((owner + slash + repo) as string)!;`,
      "synthetic/input.ts",
    ) },
  { name: "scope-safe const propagation crosses TypeScript satisfies", expect: "finding", rule: "repo-not-public",
    run: () => syntheticRepoOnly(
      `const owner = "example" + "armorg";\nconst slash = "\\u002f";\nconst repo = "synthetic" + "-confidential-repo";\nconst source = (owner + slash + repo) satisfies string;`,
      "synthetic/input.ts",
    ) },
  { name: "scope-safe const propagation crosses a TypeScript type assertion", expect: "finding", rule: "repo-not-public",
    run: () => syntheticRepoOnly(
      `const owner = "example" + "armorg";\nconst slash = "\\u002f";\nconst repo = "synthetic" + "-confidential-repo";\nconst source = <string>(owner + slash + repo);`,
      "synthetic/input.ts",
    ) },
  { name: "JSON string cooking finds Unicode and punctuation escapes", expect: "finding", rule: "repo-not-public",
    run: () => syntheticCombined(
      `{"source":"${SYNTHETIC_OWNER}\\u002fsynthetic\\u002dconfidential\\u002drepo"}`,
      "synthetic/input.json",
    ) },
  { name: "JSON string cooking traverses nested values and property names", expect: "finding", rule: "repo-not-public",
    run: () => syntheticRepoOnly(
      `{"outer":[{"${SYNTHETIC_OWNER}\\u002fsynthetic\\u002dconfidential\\u002drepo":true}]}`,
      "synthetic/input.json",
    ) },
  { name: "JSON cooking does not lose an overwritten duplicate-key value", expect: "finding", rule: "repo-not-public",
    run: () => syntheticRepoOnly(
      `{"slot":"${SYNTHETIC_OWNER}\\u002fsynthetic\\u002dconfidential\\u002drepo","slot":"synthetic-public"}`,
      "synthetic/input.json",
    ) },
  { name: "unrelated adjacent declarations are not concatenated", expect: "clean",
    run: () => syntheticCombined(`const owner = "${SYNTHETIC_OWNER}";\nconst slash = "/";\nconst prefix = "synthetic-";\nconst suffix = "confidential-repo";`) },
  { name: "dynamic expressions are not guessed into a coordinate", expect: "clean",
    run: () => syntheticCombined(`const source = "${SYNTHETIC_OWNER}" + dynamicSlash + "synthetic-" + dynamicSuffix;`) },
  { name: "a tagged raw template is not treated as a cooked literal", expect: "clean",
    run: () => syntheticCombined(`const source = String.raw\`${SYNTHETIC_OWNER}\\u002fsynthetic\\u002dconfidential\\u002drepo\`;`) },
  { name: "a dynamic function call is not invented from separate literals", expect: "clean",
    run: () => syntheticRepoOnly(
      `const source = makeCoordinate("${SYNTHETIC_OWNER}", "\\u002f", "synthetic" + "-confidential-repo");`,
      "synthetic/input.ts",
    ) },
  { name: "a dynamic shadow blocks propagation from an outer const", expect: "clean",
    run: () => syntheticRepoOnly(
      `const owner = "${SYNTHETIC_OWNER}";\n{ let owner = externalOwner; const source = owner + "\\u002f" + "synthetic" + "-confidential-repo"; }`,
      "synthetic/input.ts",
    ) },
  { name: "a function parameter blocks propagation from an outer const", expect: "clean",
    run: () => syntheticRepoOnly(
      `const owner = "${SYNTHETIC_OWNER}";\nfunction build(owner) { return owner + "\\u002f" + "synthetic" + "-confidential-repo"; }`,
      "synthetic/input.ts",
    ) },
  { name: "a runtime enum value shadows an outer static string", expect: "clean",
    run: () => syntheticRepoOnly(
      `const owner = "${SYNTHETIC_OWNER}";\n{ enum owner { marker } const repo = "synthetic" + "-confidential-repo"; const source = owner + "\\u002f" + repo; }`,
      "synthetic/input.ts",
    ) },
  { name: "a runtime namespace value shadows an outer static string", expect: "clean",
    run: () => syntheticRepoOnly(
      `const owner = "${SYNTHETIC_OWNER}";\nnamespace Box { export namespace owner { export const marker = 1; } const repo = "synthetic" + "-confidential-repo"; export const source = owner + "\\u002f" + repo; }`,
      "synthetic/input.ts",
    ) },
  { name: "a runtime module value shadows an outer static string", expect: "clean",
    run: () => syntheticRepoOnly(
      `const owner = "${SYNTHETIC_OWNER}";\nmodule Box { export module owner { export const marker = 1; } const repo = "synthetic" + "-confidential-repo"; export const source = owner + "\\u002f" + repo; }`,
      "synthetic/input.ts",
    ) },
  { name: "an import-equals runtime alias shadows a parent static string", expect: "clean",
    run: () => syntheticRepoOnly(
      `namespace Runtime { export namespace Owner { export const marker = 1; } }\nnamespace Box { const owner = "${SYNTHETIC_OWNER}"; export namespace Inner { import owner = Runtime.Owner; const repo = "synthetic" + "-confidential-repo"; export const source = owner + "\\u002f" + repo; } }`,
      "synthetic/input.ts",
    ) },
  { name: "the synthetic public coordinate remains clean", expect: "clean",
    run: () => syntheticCombined(`const source = "${SYNTHETIC_OWNER}/synthetic-public-repo";`) },
  { name: "a malformed percent escape is not decoded", expect: "clean",
    run: () => syntheticCombined(`const source = "${SYNTHETIC_OWNER}%2G${SYNTHETIC_REPOSITORY}";`) },
  { name: "double percent encoding is decoded to the same coordinate", expect: "finding", rule: "repo-not-public",
    run: () => syntheticCombined(`const source = "${SYNTHETIC_OWNER}%252F${SYNTHETIC_REPOSITORY}";`) },
  { name: "triple percent encoding is decoded within the fixed round bound", expect: "finding", rule: "repo-not-public",
    run: () => syntheticCombined(`const source = "${SYNTHETIC_OWNER}%25252F${SYNTHETIC_REPOSITORY}";`) },
  { name: "a valid separator still decodes beside a malformed percent suffix", expect: "finding", rule: "repo-not-public",
    run: () => syntheticCombined(`const source = "${SYNTHETIC_OWNER}%2F${SYNTHETIC_REPOSITORY}%2G";`) },
  { name: "a valid separator still decodes beside a non-ASCII percent suffix", expect: "finding", rule: "repo-not-public",
    run: () => syntheticCombined(`const source = "${SYNTHETIC_OWNER}%2F${SYNTHETIC_REPOSITORY}%C3%A9";`) },

  // ── privacy adjacency: names the shape without naming the subject ──────────────────────────────
  { name: "a confidentiality word beside a NON-public forge identity", expect: "finding", rule: "privacy-adjacency",
    run: () => scanPrivacyAdjacency("docs/a.md", "The sibling examplecorp/unlisted-sibling is PRIVATE.", ALLOWLIST) },
  { name: "a confidentiality word beside an operator home path", expect: "finding", rule: "privacy-adjacency",
    run: () => scanPrivacyAdjacency("docs/a.md", `The internal spec lives at ${HOME}someone/notes.`, ALLOWLIST) },
  { name: "a confidentiality word beside a private-suffixed host", expect: "finding", rule: "privacy-adjacency",
    run: () => scanPrivacyAdjacency(
      "docs/a.md",
      runtimeJoin("The internal console is at https://console.some-org.cor", "p/admin."),
      ALLOWLIST,
    ) },
  { name: "a confidentiality word with no identity to look up", expect: "clean",
    run: () => scanPrivacyAdjacency("docs/a.md", "Some capabilities remain proprietary and are not described here.", ALLOWLIST) },
  { name: "an identity with no confidentiality word", expect: "clean",
    run: () => scanPrivacyAdjacency("docs/a.md", "Docs at https://example.com/spec explain the wire format.", ALLOWLIST) },
  { name: "the confidentiality word is in a DIFFERENT sentence", expect: "clean",
    run: () => scanPrivacyAdjacency("docs/a.md", `Some work is private. The build ran under ${HOME}someone/x.`, ALLOWLIST) },
  // MEASURED FALSE POSITIVE, kept as a permanent fixture: the first draft counted any https URL as
  // an identity, so a public badge sitting beside the word "unpublished", and this repository's OWN
  // public forge URL sitting beside the word "public", both went red. A URL anyone can already open
  // is not a disclosure, and a rule that says otherwise teaches people to route around it.
  { name: "a PUBLIC repo named beside a confidentiality word", expect: "clean",
    run: () => scanPrivacyAdjacency("docs/a.md", "Confirmed: examplecorp/public-thing is not private.", ALLOWLIST) },
  { name: "a non-public identity beside a confidentiality claim fires", expect: "finding", rule: "privacy-adjacency",
    run: () => scanPrivacyAdjacency(
      "synthetic/privacy.md",
      `Provider visibility for ${SYNTHETIC_COORDINATE} is PRIVATE.`,
      SYNTHETIC_ALLOWLIST,
    ) },
  { name: "a split static confidentiality sentence is reconstructed", expect: "finding", rule: "privacy-adjacency",
    run: () => scanPrivacyAdjacency(
      "synthetic/privacy.mjs",
      `const note = "PRIVATE " + "${SYNTHETIC_OWNER}" + "/" + "${SYNTHETIC_REPOSITORY}.";`,
      SYNTHETIC_ALLOWLIST,
    ) },
  { name: "a percent-encoded confidentiality identity is reconstructed", expect: "finding", rule: "privacy-adjacency",
    run: () => scanPrivacyAdjacency(
      "synthetic/privacy.mjs",
      `const note = "PRIVATE ${SYNTHETIC_OWNER}%2F${SYNTHETIC_REPOSITORY}.";`,
      SYNTHETIC_ALLOWLIST,
    ) },
  { name: "privacy lookup treats a sentence fragment as text rather than a source file", expect: "finding", rule: "privacy-adjacency",
    run: () => scanPrivacyAdjacency(
      "synthetic/privacy.mjs",
      `const note = "PRIVATE ${SYNTHETIC_COORDINATE}! next sentence";`,
      SYNTHETIC_ALLOWLIST,
    ) },
  { name: "a public CDN URL beside a confidentiality word", expect: "clean",
    run: () => scanPrivacyAdjacency("docs/a.md", "A badge for an unpublished package: https://img.shields.io/npm/v/x.", ALLOWLIST) },

  // ── sourcemaps ─────────────────────────────────────────────────────────────────────────────────
  { name: "a sourcemap whose sources[] is absolute", expect: "finding", rule: "sourcemap-escapes-package",
    run: () => scanSourceMap("dist/i.js.map", JSON.stringify({ version: 3, sources: [`${HOME}someone/p/src/i.ts`] })) },
  { name: "a sourcemap that climbs out of the package", expect: "finding", rule: "sourcemap-escapes-package",
    run: () => scanSourceMap("dist/i.js.map", JSON.stringify({ version: 3, sources: ["../../../elsewhere/i.ts"] })) },
  { name: "a sourcemap whose Windows path climbs out of the package", expect: "finding", rule: "sourcemap-escapes-package",
    run: () => scanSourceMap("dist/i.js.map", JSON.stringify({ version: 3, sources: ["..\\..\\elsewhere\\i.ts"] })) },
  { name: "a sourcemap whose source is a UNC path", expect: "finding", rule: "sourcemap-escapes-package",
    run: () => scanSourceMap("dist/i.js.map", JSON.stringify({ version: 3, sources: ["\\\\server\\share\\i.ts"] })) },
  { name: "a terminal two-parent sourceRoot climbs out of the package", expect: "finding", rule: "sourcemap-escapes-package",
    run: () => scanSourceMap("dist/i.js.map", JSON.stringify({ version: 3, sourceRoot: "../..", sources: ["i.ts"] })) },
  { name: "sourceRoot and sources cannot split an escaping traversal", expect: "finding", rule: "sourcemap-escapes-package",
    run: () => scanSourceMap("dist/i.js.map", JSON.stringify({ version: 3, sourceRoot: "..", sources: ["../elsewhere/i.ts"] })) },
  { name: "a root-level sourcemap whose source climbs out of the package", expect: "finding", rule: "sourcemap-escapes-package",
    run: () => scanSourceMap("i.js.map", JSON.stringify({ version: 3, sources: ["../elsewhere/i.ts"] })) },
  { name: "a packed sourcemap that cannot be parsed", expect: "finding", rule: "sourcemap-unparsable",
    run: () => scanSourceMap("dist/i.js.map", "{ not json") },
  { name: "a packed sourcemap beyond the structural depth bound", expect: "finding", rule: "sourcemap-unscannable",
    run: () => scanSourceMap(
      "dist/i.js.map",
      runtimeJoin('{"extension":', "[".repeat(513), "0", "]".repeat(513), "}"),
    ) },
  { name: "a scalar sourcemap fails closed", expect: "finding", rule: "sourcemap-invalid-shape",
    run: () => scanSourceMap("dist/i.js.map", "3") },
  { name: "an array sourcemap fails closed", expect: "finding", rule: "sourcemap-invalid-shape",
    run: () => scanSourceMap("dist/i.js.map", "[]") },
  { name: "a sourcemap with malformed known fields fails closed", expect: "finding", rule: "sourcemap-invalid-shape",
    run: () => scanSourceMap("dist/i.js.map", JSON.stringify({ version: 3, sources: "../src/i.ts" })) },
  { name: "an external indexed sourcemap section fails closed", expect: "finding", rule: "sourcemap-external-section",
    run: () => scanSourceMap("dist/i.js.map", JSON.stringify({
      version: 3,
      sections: [{ offset: { line: 0, column: 0 }, url: "next.map" }],
    })) },
  { name: "an overwritten duplicate sources occurrence is still scanned", expect: "finding", rule: "sourcemap-escapes-package",
    run: () => scanSourceMap(
      "dist/i.js.map",
      runtimeJoin('{"version":3,"sources":["/Users/', 'SyntheticOperator/build/i.ts"],"sources":["../src/i.ts"]}'),
    ) },
  { name: "a percent-encoded escaping source is normalised structurally", expect: "finding", rule: "sourcemap-escapes-package",
    run: () => scanSourceMap("dist/i.js.map", '{"version":3,"sources":["%2e%2e%2f%2e%2e%2fsecret.ts"]}') },
  { name: "a well-formed relative sourcemap", expect: "clean",
    run: () => scanSourceMap("dist/i.js.map", JSON.stringify({ version: 3, sources: ["../src/i.ts"], sourcesContent: ["export const a = 1;"] })) },
  { name: "a sourceRoot segment can be cancelled without inventing a second parent", expect: "clean",
    run: () => scanSourceMap("dist/i.js.map", JSON.stringify({ version: 3, sourceRoot: "../src", sources: ["../generated/i.ts"] })) },
  { name: "a bounded percent-encoded relative source stays clean", expect: "clean",
    run: () => scanSourceMap("dist/i.js.map", '{"version":3,"sources":["..%2fsrc%2fi.ts"]}') },
  { name: "a fully embedded indexed sourcemap stays clean", expect: "clean",
    run: () => scanSourceMap("dist/i.js.map", JSON.stringify({
      version: 3,
      sections: [{
        offset: { line: 0, column: 0 },
        map: { version: 3, sources: ["../src/i.ts"], mappings: "" },
      }],
    })) },

  // ── Tier B ─────────────────────────────────────────────────────────────────────────────────────
  { name: "a committed token, exact", expect: "finding", rule: "token-commitment",
    run: () => scanTokens("docs/a.md", "governed by widgetlabel today", (c) => c === "widgetlabel") },
  { name: "a committed token reached through a path segment", expect: "finding", rule: "token-commitment",
    run: () => scanTokens("docs/a.md", "quoted from widgetlabel/notes/x.md", (c) => c === "widgetlabel") },
  { name: "a one-word committed token inside a hyphenated label", expect: "finding", rule: "token-commitment",
    run: () => scanTokens("docs/a.md", "release-widgetlabel-notes", (c) => c === "widgetlabel") },
  { name: "a one-word committed token inside an underscored label", expect: "finding", rule: "token-commitment",
    run: () => scanTokens("docs/a.md", "release_widgetlabel_notes", (c) => c === "widgetlabel") },
  { name: "a one-word committed token before a file extension", expect: "finding", rule: "token-commitment",
    run: () => scanTokens("docs/a.md", "release-widgetlabel.js", (c) => c === "widgetlabel") },
  { name: "a public compound does not inherit a private subsegment finding", expect: "clean",
    run: () => scanTokens("docs/a.md", "public-widgetlabel", (c) => c === "widgetlabel", [1], {
      safeCompounds: new Set(["public-widgetlabel"]),
    }) },
  { name: "a numbered family, matched through digit collapse", expect: "finding", rule: "token-commitment",
    run: () => scanTokens("docs/a.md", "closes PROG-77 and PROG-78", (c) => c === "prog-#") },
  { name: "a multi-word label written with spaces", expect: "finding", rule: "token-commitment",
    run: () => scanTokens("docs/a.md", "the widget label programme", (c) => c === "widget-label-programme", [1, 3]) },
  ...TOKEN_SEPARATOR_CASES,
  { name: "prose with no committed token", expect: "clean",
    run: () => scanTokens("docs/a.md", "the receipt chain is verified offline", (c) => c === "widgetlabel") },
  { name: "a version string must not collide with a collapsed family", expect: "clean",
    run: () => scanTokens("docs/a.md", "released noa-0.8 today", (c) => c === "prog-#") },

  // ── suppressions: pinned to the matched text, and never available to CRITICAL ─────────────────
  { name: "a digest-pinned suppression silences its own HIGH finding", expect: "clean",
    run: () => suppressedUuidFixture() },
  { name: "a suppression cannot silence a CRITICAL finding", expect: "finding", rule: "infra-account-id",
    run: () => {
      const account = runtimeJoin("acct-", "4711-eu-north-1");
      return scanShapes("docs/a.md", runtimeJoin(account, " <!-- noa-boundary-ok:", __testing.digest8(account), ":wishful -->"));
    } },
  { name: "a suppression for a DIFFERENT text does not carry over", expect: "finding", rule: "uuid",
    run: () => scanShapes("docs/a.md", `id ${UUID} <!-- noa-boundary-ok:deadbeef:stale -->`) },
  { name: "a marker-looking JSON string is not suppression authority", expect: "finding", rule: "uuid",
    run: () => scanShapes(
      "synthetic/suppression.json",
      `{"value":"${UUID} noa-boundary-ok:${__testing.digest8(UUID)}:string-data"}`,
    ) },
  { name: "a marker-looking JavaScript string is not suppression authority", expect: "finding", rule: "uuid",
    run: () => scanShapes(
      "synthetic/suppression.mjs",
      `const value = "${UUID} // noa-boundary-ok:${__testing.digest8(UUID)}:string-data";`,
    ) },
  { name: "a marker-looking quoted documentation string is not suppression authority", expect: "finding", rule: "uuid",
    run: () => scanShapes(
      "synthetic/suppression.md",
      `"${UUID} // noa-boundary-ok:${__testing.digest8(UUID)}:string-data"`,
    ) },
  { name: "a derived marker-looking JavaScript string is not suppression authority", expect: "finding", rule: "uuid",
    run: () => scanShapes(
      "synthetic/suppression.mjs",
      `const value = "a1b2c3d4-5e6f-4a7b-" + "8c9d-0e1f2a3b4c5d // noa-boundary-ok:${__testing.digest8(UUID)}:derived-string";`,
    ) },
  { name: "an original physical comment suppresses its derived HIGH finding", expect: "clean",
    run: () => scanShapes(
      "synthetic/suppression.mjs",
      `const value = "a1b2c3d4-5e6f-4a7b-" + "8c9d-0e1f2a3b4c5d"; // noa-boundary-ok:${__testing.digest8(UUID)}:derived-comment`,
    ) },
];

function severityOf(result) {
  return result.findings.map((f) => f.severity);
}

let failures = 0;
for (const c of CASES) {
  const result = c.run();
  const got = result.findings;
  let ok = c.expect === "finding" ? got.length > 0 : got.length === 0;
  if (ok && c.expect === "finding" && c.rule !== undefined) {
    ok = got.some((f) => f.rule === c.rule);
  }
  if (!ok) {
    failures++;
    console.error(`  FAIL   expect ${c.expect.padEnd(7)} ${c.name}`);
    console.error(`         got ${JSON.stringify(got.map((f) => `${f.rule}:${f.shown}`))}`);
  } else {
    console.log(`  ok     expect ${c.expect.padEnd(7)} ${c.name}`);
  }
}

// ── ANTI-VACUITY ─────────────────────────────────────────────────────────────────────────────────
const findingCases = CASES.filter((c) => c.expect === "finding").length;
const cleanCases = CASES.length - findingCases;
if (findingCases === 0 || cleanCases === 0) {
  console.error("  FAIL   the selftest tests only one direction — it cannot tell a working scanner from a stuck one");
  failures++;
}

// Every rule the gate ships MUST have at least one firing fixture. A rule nobody armed is a coverage
// claim with nothing behind it, and this repository has paid for exactly that before.
const armedRules = new Set(CASES.flatMap((c) => (c.expect === "finding" && c.rule ? [c.rule] : [])));
const shippedRules = [
  ...(await import("./boundary-scan.mjs")).SHAPE_RULES.map((r) => r.id),
  "artefact-absolute-path", "repo-not-public", "privacy-adjacency", "token-commitment",
  "sourcemap-escapes-package", "sourcemap-unparsable", "sourcemap-unscannable",
  "sourcemap-invalid-shape", "sourcemap-external-section",
];
const unarmed = shippedRules.filter((id) => !armedRules.has(id));
if (unarmed.length > 0) {
  console.error(`  FAIL   ${unarmed.length} shipped rule(s) have no firing fixture: ${unarmed.join(", ")}`);
  failures++;
}

// Helper invariants that the rules above depend on, asserted rather than assumed.
if (collapseDigits("xyz-04") !== "xyz-#") { console.error("  FAIL   digit collapse"); failures++; }
if (tokenNgramSize("a-b-c") !== 3) { console.error("  FAIL   token word count"); failures++; }
if (tokenForms("  A_B ")[0] !== "a-b") { console.error("  FAIL   token normalisation"); failures++; }
if (!extractCandidates("Alpha Beta", [2]).has("alpha-beta")) { console.error("  FAIL   n-gram candidate"); failures++; }
if (!extractCandidates("Alpha_Beta", [1]).has("alpha-beta")) { console.error("  FAIL   underscore scanner round-trip"); failures++; }
if (reachableTokenForms("prog-#")[0] !== "prog-#") { console.error("  FAIL   numbered-family token round-trip"); failures++; }
if (pathContentKey("docs/a.md") === contentKey("docs/a.md")) { console.error("  FAIL   path identity domain separation"); failures++; }
if (pathContentKey("docs/a.md") !== pathContentKey("docs/a.md")) { console.error("  FAIL   path identity stability"); failures++; }
if (mask("supersecret").includes("persecre")) { console.error("  FAIL   mask leaks the middle"); failures++; }
if (severityOf(scanShapes("d.md", runtimeJoin("acct-", "4711-eu-north-1")))[0] !== SEVERITY.CRITICAL) {
  console.error("  FAIL   infrastructure identifiers must be CRITICAL"); failures++;
}

for (const declaration of ["index.d.ts", "index.d.mts", "index.d.cts", "INDEX.D.MTS"]) {
  if (!isDeclarationArtifactPath(declaration)) {
    console.error(`  FAIL   declaration artefact suffix was not classified: ${declaration}`);
    failures++;
  }
}
for (const source of ["index.ts", "index.mts", "index.cts", "index.d.ts.map"]) {
  if (isDeclarationArtifactPath(source)) {
    console.error(`  FAIL   a non-declaration path was classified as a declaration: ${source}`);
    failures++;
  }
}

const assertDerivedOnly = ({ name, present, removed, rule, line }) => {
  const hits = present.findings.filter((finding) => finding.rule === rule);
  if (hits.length !== 1 || hits[0].line !== line || removed.findings.some((finding) => finding.rule === rule)) {
    console.error(`  FAIL   ${name} is not a single physical-line-bound derived finding`);
    failures++;
  } else {
    console.log(`  ok     ${name} is derived once on physical line ${line}`);
  }
};

const splitShapeSource = runtimeJoin(
  "const safe = 1;\nconst endpoint = ",
  '"synthetic" + ".rlwy" + ".net";',
);
assertDerivedOnly({
  name: "static JavaScript shape reconstruction",
  present: scanShapes("synthetic/derived.mjs", splitShapeSource),
  removed: __testing.scanShapesRaw("synthetic/derived.mjs", splitShapeSource),
  rule: "infra-vendor-host",
  line: 2,
});

const jsonShapeSource = runtimeJoin(
  "{\n  \"path\":\"\\u002fUsers\\u002fSyntheticOperator\\u002fnotes\"\n}",
);
assertDerivedOnly({
  name: "JSON-cooked shape reconstruction",
  present: scanShapes("synthetic/derived.json", jsonShapeSource),
  removed: __testing.scanShapesRaw("synthetic/derived.json", jsonShapeSource),
  rule: "home-path",
  line: 2,
});

const directAndDerivedShapeSource = runtimeJoin(
  "const safe = 1;\nconst endpoint = \"synthetic", ".rlwy", ".net\";",
);
const directAndDerivedShape = scanShapes("synthetic/dedup.mjs", directAndDerivedShapeSource);
if (directAndDerivedShape.findings.filter((finding) => finding.rule === "infra-vendor-host").length !== 1) {
  console.error("  FAIL   raw and derived shape views emitted a duplicate finding");
  failures++;
} else {
  console.log("  ok     raw and derived shape views deduplicate by physical finding identity");
}

const splitPrivacySource = runtimeJoin(
  "const safe = 1;\nconst note = \"PRIVATE \" + \"",
  SYNTHETIC_OWNER,
  '\" + "/" + \"',
  SYNTHETIC_REPOSITORY,
  '\";',
);
assertDerivedOnly({
  name: "static JavaScript privacy reconstruction",
  present: scanPrivacyAdjacency("synthetic/privacy.mjs", splitPrivacySource, SYNTHETIC_ALLOWLIST),
  removed: __testing.scanPrivacyAdjacencyRaw("synthetic/privacy.mjs", splitPrivacySource, SYNTHETIC_ALLOWLIST),
  rule: "privacy-adjacency",
  line: 2,
});

const percentPrivacySource = runtimeJoin(
  "const safe = 1;\nconst note = \"PRIVATE ", SYNTHETIC_OWNER, "%2F", SYNTHETIC_REPOSITORY, '\";',
);
assertDerivedOnly({
  name: "percent-decoded privacy reconstruction",
  present: scanPrivacyAdjacency("synthetic/privacy.mjs", percentPrivacySource, SYNTHETIC_ALLOWLIST),
  removed: __testing.scanPrivacyAdjacencyRaw("synthetic/privacy.mjs", percentPrivacySource, SYNTHETIC_ALLOWLIST),
  rule: "privacy-adjacency",
  line: 2,
});

const boundedDerivedViews = __testing.derivedConfidentialViews(
  "synthetic/derived.mjs",
  runtimeJoin('const value = "', SYNTHETIC_OWNER, "%252F", SYNTHETIC_REPOSITORY, '\";'),
);
if (boundedDerivedViews.length !== 5 || new Set(boundedDerivedViews.map((view) => `${view.line}\0${view.text}`)).size !== 5) {
  console.error("  FAIL   derived scanning recursed or emitted duplicate views");
  failures++;
} else {
  console.log("  ok     derived scanning is one-pass, bounded and duplicate-free");
}

const assertConstantRedaction = (name, result, confidentialForms) => {
  const redacted = result.findings.filter((finding) => finding.redact === true);
  const serialized = JSON.stringify(redacted).toLowerCase();
  const leaked = confidentialForms.some((form) => serialized.includes(form.toLowerCase()));
  if (redacted.length === 0 || leaked || redacted.some((finding) =>
    finding.matched !== "" || finding.shown !== "<redacted>" || finding.snippet !== "<redacted>")) {
    console.error(`  FAIL   ${name} retained confidential plaintext in a finding/evidence field`);
    failures++;
  } else {
    console.log(`  ok     ${name} uses constant-safe finding/evidence fields`);
  }
};

const normalizedToken = runtimeJoin("ultra", "_hidden", "_label");
assertConstantRedaction(
  "normalised token redaction",
  scanTokens("synthetic/redaction.md", normalizedToken, (candidate) => candidate === "ultra-hidden-label"),
  [normalizedToken, "ultra-hidden-label"],
);
const spacedToken = runtimeJoin("quiet", " programme", " label");
assertConstantRedaction(
  "spaced token redaction",
  scanTokens("synthetic/redaction.md", spacedToken, (candidate) => candidate === "quiet-programme-label", [3]),
  [spacedToken, "quiet-programme-label"],
);
const numberedToken = runtimeJoin("PROG-", "77");
assertConstantRedaction(
  "digit-collapse token redaction",
  scanTokens("synthetic/redaction.md", numberedToken, (candidate) => candidate === "prog-#"),
  [numberedToken],
);
assertConstantRedaction(
  "reconstructed repository redaction",
  syntheticRepoOnly(
    runtimeJoin('const source = "', SYNTHETIC_OWNER, '/" + "synthetic-" + "confidential-repo";'),
    "synthetic/redaction.mjs",
  ),
  [SYNTHETIC_COORDINATE],
);
const confidentialDatabaseUrl = runtimeJoin(
  "postgres", "://private-user:private-pass@db.synthetic-", "corp.io", ":5432/private-db?token=private-token#private-fragment",
);
const confidentialDatabaseFinding = scanShapes("synthetic/redaction.md", confidentialDatabaseUrl);
assertConstantRedaction(
  "database URL redaction",
  confidentialDatabaseFinding,
  [confidentialDatabaseUrl, "private-user", "private-pass", "private-token", "private-fragment"],
);
const mixedRedactionPath = runtimeJoin("/Users/", "SyntheticOperator/private/file");
const publicPlanningMatch = runtimeJoin(".", "plan/");
const mixedRuleResult = scanShapes(
  "synthetic/redaction.md",
  runtimeJoin("see .", "plan/public-note and ", mixedRedactionPath),
);
if (JSON.stringify(mixedRuleResult).includes(mixedRedactionPath)
    || mixedRuleResult.findings.find((finding) => finding.rule === "planning-dir")?.snippet !== publicPlanningMatch) {
  console.error("  FAIL   a public-safe finding snippet echoed a neighbouring redacted match");
  failures++;
} else {
  console.log("  ok     public-safe findings never echo a neighbouring redacted match");
}

for (const [name, label, options] of [
  ["shape-bearing output label", runtimeJoin("/Users/", "SyntheticOperator/private/file"), {}],
  ["database-bearing output label", confidentialDatabaseUrl, {}],
  ["repository-bearing output label", SYNTHETIC_COORDINATE, { allowlist: SYNTHETIC_ALLOWLIST }],
  ["token-bearing output label", numberedToken, { lookup: (candidate) => candidate === "prog-#" }],
  [
    "privacy-only output label",
    runtimeJoin("PRI", "VATE ", runtimeAscii(104, 116, 116, 112, 115, 58, 47, 47), "10.20.30.40/resource"),
    { allowlist: SYNTHETIC_ALLOWLIST },
  ],
  [
    "inline-suppressed output label",
    runtimeJoin(UUID, " noa-boundary-ok:", __testing.digest8(UUID), ":published-vector-id"),
    {},
  ],
]) {
  const safe = safeBoundaryLabel(label, options);
  if (safe !== "<redacted>" || safe.toLowerCase().includes(label.toLowerCase())) {
    console.error(`  FAIL   ${name} was exposed to CLI/JSON evidence`);
    failures++;
  } else {
    console.log(`  ok     ${name} is masked for CLI/JSON evidence`);
  }
}
if (safeBoundaryLabel(runtimeJoin("/Users/", "FirstSynthetic/private/file"))
    !== safeBoundaryLabel(runtimeJoin("/Users/", "SecondSynthetic/private/file"))) {
  console.error("  FAIL   confidential labels use a correlatable output mask");
  failures++;
} else {
  console.log("  ok     confidential labels share one non-correlatable constant mask");
}
if (safeBoundaryLabel("scripts/public-file.mjs", { allowlist: SYNTHETIC_ALLOWLIST }) !== "scripts/public-file.mjs") {
  console.error("  FAIL   a public-safe output label was needlessly redacted");
  failures++;
}

const staticConcatSource = (partCount) => {
  const parts = [SYNTHETIC_COORDINATE, ...Array.from({ length: partCount - 1 }, () => "")];
  return `const coordinate = ${parts.map((part) => JSON.stringify(part)).join(" + ")};`;
};
const maximumFlatConcat = syntheticRepoOnly(staticConcatSource(128), "synthetic/flat.ts");
if (!maximumFlatConcat.findings.some((finding) => finding.rule === "repo-not-public")) {
  console.error("  FAIL   a flat static concatenation at MAX_STATIC_PARTS was rejected as nesting");
  failures++;
} else {
  console.log("  ok     a flat static concatenation reaches MAX_STATIC_PARTS without false nesting");
}
try {
  syntheticRepoOnly(staticConcatSource(129), "synthetic/flat.ts");
  console.error("  FAIL   a flat static concatenation exceeded MAX_STATIC_PARTS");
  failures++;
} catch (error) {
  if (error?.code !== "STATIC_PART_LIMIT") {
    console.error(`  FAIL   an over-part flat concatenation failed with ${error?.code ?? error}`);
    failures++;
  } else {
    console.log("  ok     a flat static concatenation fails closed beyond MAX_STATIC_PARTS");
  }
}

const suppressionContract = suppressedUuidFixture();
const suppressionEntry = suppressionContract.suppressed[0];
if (SUPPRESSION_MARKER !== "noa-boundary-ok:" || SUPPRESSION_REASON !== "published-vector-id"
    || suppressionContract.findings.length !== 0 || suppressionContract.suppressed.length !== 1
    || suppressionEntry.rule !== "uuid" || suppressionEntry.digest !== __testing.digest8(UUID)
    || suppressionEntry.suppressionReason !== "published-vector-id") {
  console.error("  FAIL   the inline suppression entry/rule/digest/reason contract changed");
  failures++;
} else {
  console.log("  ok     inline suppression preserves its exact entry/rule/digest/reason contract");
}
for (const [name, probe] of [
  ["removed marker", suppressedUuidFixture({ marker: "noa-boundary-disabled:" })],
  ["changed digest", suppressedUuidFixture({ digest: "deadbeef" })],
]) {
  if (probe.findings.length !== 1 || probe.suppressed.length !== 0 || probe.findings[0].rule !== "uuid") {
    console.error(`  FAIL   suppression ${name} knockout did not go red`);
    failures++;
  } else {
    console.log(`  ok     suppression ${name} knockout goes red`);
  }
}

const decodedMapCoordinate = SYNTHETIC_COORDINATE;
const decodedMapValue = `${SECOND_SYNTHETIC_OWNER}/${SYNTHETIC_REPOSITORY}`;
const decodedPathMarker = "widgetlabel";
const decodedPathMap = scanSourceMap(
  "dist/decoded-path.js.map",
  JSON.stringify({
    version: 3,
    file: `${decodedPathMarker}.js`,
    sourceRoot: "../src",
    sources: [`${decodedPathMarker}.ts`],
  }),
);
const expectedDecodedPaths = [
  { field: "file", index: 0, value: `${decodedPathMarker}.js` },
  { field: "sourceRoot", index: 0, value: "../src" },
  { field: "sources", index: 0, value: `${decodedPathMarker}.ts` },
];
if (JSON.stringify(decodedPathMap.paths) !== JSON.stringify(expectedDecodedPaths)) {
  console.error("  FAIL   decoded sourcemap paths were omitted, reordered, or changed");
  failures++;
} else {
  console.log("  ok     decoded sourcemap paths retain their field/index/value contract");
}
const unparsablePathMap = scanSourceMap("dist/unparsable.js.map", decodedPathMarker);
if (!Array.isArray(unparsablePathMap.paths) || unparsablePathMap.paths.length !== 0
    || JSON.stringify(unparsablePathMap.findings).includes(decodedPathMarker)) {
  console.error("  FAIL   sourcemap refusal exposed input bytes or returned untrusted paths");
  failures++;
} else {
  console.log("  ok     sourcemap refusal withholds input bytes and returns no path metadata");
}
const decodedMap = scanSourceMap(
  "dist/decoded.js.map",
  runtimeJoin(
    '{"version":3,"sources":[],"\\u0065xamplearmorg\\u002fsynthetic-confidential-repo":',
    '"samplearmorg\\u002fsynthetic-confidential-repo"}',
  ),
);
if (decodedMap.contents.filter((value) => value === decodedMapCoordinate).length !== 1
    || decodedMap.contents.filter((value) => value === decodedMapValue).length !== 1) {
  console.error("  FAIL   decoded sourcemap property names/values were omitted or duplicated");
  failures++;
} else {
  console.log("  ok     all decoded sourcemap property names/values hand off once");
}

const overwrittenMapValue = scanSourceMap(
  "dist/duplicate-key.js.map",
  runtimeJoin(
    '{"version":3,"sources":[],"extension":"\\u0065xamplearmorg\\u002fsynthetic-confidential-repo",',
    '"extension":"public-placeholder"}',
  ),
);
if (overwrittenMapValue.contents.filter((value) => value === decodedMapCoordinate).length !== 1) {
  console.error("  FAIL   an overwritten decoded sourcemap string occurrence was lost");
  failures++;
} else {
  console.log("  ok     overwritten decoded sourcemap string occurrences remain in the handoff");
}

const nestedMap = scanSourceMap("dist/indexed.js.map", JSON.stringify({
  version: 3,
  sections: [{
    offset: { line: 0, column: 0 },
    map: {
      version: 3,
      sources: ["../src/index.ts"],
      sourcesContent: [decodedMapCoordinate, decodedMapCoordinate],
      extension: { nested: decodedMapCoordinate },
      mappings: "",
    },
  }],
}));
if (nestedMap.contents.filter((value) => value === decodedMapCoordinate).length !== 3) {
  console.error("  FAIL   indexed-map nested sourcesContent/string traversal was omitted or duplicated");
  failures++;
} else {
  console.log("  ok     indexed-map nested sourcesContent/string traversal hands off once");
}

const repeatedEscapingMap = scanSourceMap(
  "dist/repeated.js.map",
  runtimeJoin(
    '{"version":3,"sources":["/Users/',
    'SyntheticOperator/build/source.ts"],"sources":["/Users/',
    'SyntheticOperator/build/source.ts"]}',
  ),
);
if (repeatedEscapingMap.findings.filter((finding) => finding.rule === "sourcemap-escapes-package").length !== 1) {
  console.error("  FAIL   top-level and indexed-map structural findings were not deduplicated");
  failures++;
} else {
  console.log("  ok     top-level and indexed-map structural findings deduplicate");
}

const nestedOnlyEscapingMap = scanSourceMap("dist/nested-only.js.map", JSON.stringify({
  version: 3,
  sections: [{ offset: { line: 0, column: 0 }, map: {
    version: 3,
    sources: [runtimeJoin("/Users/", "SyntheticOperator/build/nested.ts")],
  } }],
}));
if (nestedOnlyEscapingMap.findings.filter((finding) => finding.rule === "sourcemap-escapes-package").length !== 1) {
  console.error("  FAIL   indexed-map structural recursion omitted a nested escaping source");
  failures++;
} else {
  console.log("  ok     indexed-map structural recursion scans nested sources/sourceRoot");
}

const overStringMap = Object.fromEntries(Array.from(
  { length: 16_385 },
  (_, index) => [`extension-${index.toString(16).padStart(5, "0")}`, false],
));
const overStringMapResult = scanSourceMap("dist/strings.js.map", JSON.stringify(overStringMap));
if (overStringMapResult.findings.length !== 1 || overStringMapResult.findings[0].rule !== "sourcemap-unscannable"
    || overStringMapResult.contents.length !== 0) {
  console.error("  FAIL   sourcemap decoded-string traversal did not fail closed at its bound");
  failures++;
} else {
  console.log("  ok     sourcemap decoded-string traversal fails closed at its bound");
}

// Load-bearing control proof: the complete scanner catches each runtime-equivalent spelling, while
// the exact raw scanners (the same detector with reconstruction/decoding removed) stay clean. A
// future deletion of any derived-view control therefore makes this selftest RED rather than merely
// reducing a count that nobody inspects.
const RECONSTRUCTION_KNOCKOUTS = [
  {
    name: "multiline literal reconstruction",
    source: `const source =\n  "${SYNTHETIC_OWNER}" +\n  "/" +\n  "synthetic-" +\n  "confidential-repo";`,
  },
  {
    name: "percent decoding",
    source: `const source = "${SYNTHETIC_OWNER}%2F${SYNTHETIC_REPOSITORY}";`,
  },
  {
    name: "JavaScript escape cooking",
    source: `const source = "${SYNTHETIC_OWNER}\\u002f${SYNTHETIC_REPOSITORY}";`,
  },
  {
    name: "TypeScript AST const propagation",
    source: `const owner = "example" + "armorg";\nconst slash = "\\u002f";\nconst repo = "synthetic" + "-confidential-repo";\nexport default (owner + slash + repo) satisfies string;`,
    file: "synthetic/input.ts",
    rule: "repo-not-public",
  },
  {
    name: "JSON cooked-string traversal",
    source: `{"source":"${SYNTHETIC_OWNER}\\u002fsynthetic\\u002dconfidential\\u002drepo"}`,
    file: "synthetic/input.json",
  },
  {
    name: "repeated percent decoding",
    source: `const source = "${SYNTHETIC_OWNER}%252F${SYNTHETIC_REPOSITORY}";`,
  },
];
for (const control of RECONSTRUCTION_KNOCKOUTS) {
  const present = syntheticCombined(control.source, control.file);
  const removed = syntheticRaw(control.source, control.file);
  const loadBearingRule = control.rule ?? "token-commitment";
  if (!present.findings.some((finding) => finding.rule === loadBearingRule)) {
    console.error(`  FAIL   ${control.name} does not detect the authenticated synthetic input`);
    failures++;
  } else if (removed.findings.some((finding) => finding.rule === loadBearingRule)) {
    console.error(`  FAIL   ${control.name} knockout is vacuous; the raw scanner already detected it`);
    failures++;
  } else {
    console.log(`  ok     ${control.name} is load-bearing`);
  }
}

const repeatedDecoded = __testing.percentDecodedValues(`${SYNTHETIC_OWNER}%252F${SYNTHETIC_REPOSITORY}`);
if (repeatedDecoded.at(-1) !== SYNTHETIC_COORDINATE || repeatedDecoded.length !== 2) {
  console.error("  FAIL   double percent encoding did not reach the exact coordinate in two bounded passes");
  failures++;
}
if (__testing.percentDecodedValues(`${SYNTHETIC_OWNER}%2G${SYNTHETIC_REPOSITORY}`).length !== 0) {
  console.error("  FAIL   a malformed separator was invented into a decoded value");
  failures++;
}
try {
  __testing.percentDecodedValues(`x${"%41".repeat(257)}`);
  console.error("  FAIL   over-limit percent encoding was accepted");
  failures++;
} catch (error) {
  if (error?.code !== "PERCENT_ESCAPE_LIMIT") {
    console.error(`  FAIL   over-limit percent encoding failed with ${error?.code ?? error}`);
    failures++;
  } else {
    console.log("  ok     percent decoder fails closed at its escape bound");
  }
}

try {
  __testing.percentDecodedValues(`${SYNTHETIC_OWNER}%${"25".repeat(4)}2F${SYNTHETIC_REPOSITORY}`);
  console.error("  FAIL   over-round percent encoding was accepted without a fail-closed verdict");
  failures++;
} catch (error) {
  if (error?.code !== "PERCENT_DECODE_ROUND_LIMIT") {
    console.error(`  FAIL   over-round percent encoding failed with ${error?.code ?? error}`);
    failures++;
  } else {
    console.log("  ok     percent decoder fails closed at its round bound");
  }
}

const criticalSuppression = criticalRepoSuppressionProbe();
if (criticalSuppression.findings.length !== 1 || criticalSuppression.suppressed.length !== 0) {
  console.error("  FAIL   a CRITICAL repository finding moved into inline-suppressed results");
  failures++;
} else {
  console.log("  ok     CRITICAL repository findings are not inline-suppressible");
}

const expectScannerError = (name, code, operation, exactMessage = null) => {
  try {
    operation();
    console.error(`  FAIL   ${name} did not fail closed`);
    failures++;
  } catch (error) {
    if (error?.code !== code || (exactMessage !== null && error.message !== exactMessage)
        || /maximum call stack size exceeded/i.test(String(error?.message))) {
      console.error(`  FAIL   ${name} failed with an unstable diagnostic`);
      failures++;
    } else {
      console.log(`  ok     ${name} fails closed with ${code}`);
    }
  }
};

expectScannerError(
  "case-insensitive duplicate public-snapshot owners",
  "PUBLIC_REPOSITORY_SNAPSHOT_DUPLICATE_OWNER",
  () => scanRepoRefs(
    "synthetic/snapshot.md",
    SYNTHETIC_COORDINATE,
    { orgs: { ExampleArmOrg: ["synthetic-public-repo"], examplearmorg: ["synthetic-other-public"] } },
  ),
  "PUBLIC_REPOSITORY_SNAPSHOT_DUPLICATE_OWNER: owner keys must be unique case-insensitively",
);

expectScannerError(
  "one thousand nested source parentheses",
  "STATIC_SYNTAX_DEPTH_LIMIT",
  () => __testing.extractStaticJsValues(
    "synthetic/deep.ts",
    `const value = ${"(".repeat(1_000)}"safe"${")".repeat(1_000)};`,
  ),
);
expectScannerError(
  "one thousand nested JavaScript parentheses",
  "STATIC_SYNTAX_DEPTH_LIMIT",
  () => __testing.extractStaticJsValues(
    "synthetic/deep.mjs",
    `const value = ${"(".repeat(1_000)}"safe"${")".repeat(1_000)};`,
  ),
);
expectScannerError(
  "a parser-recursive unary chain",
  "STATIC_SOURCE_PARSE_DEPTH_LIMIT",
  () => __testing.extractStaticJsValues(
    "synthetic/deep.ts",
    `const value = ${"!".repeat(4_000)}true;`,
  ),
);
expectScannerError(
  "an over-deep but parser-safe AST",
  "STATIC_AST_DEPTH_LIMIT",
  () => __testing.extractStaticJsValues(
    "synthetic/deep.ts",
    `const value = ${"!".repeat(600)}"safe";`,
  ),
);
expectScannerError(
  "an over-deep static evaluator path",
  "STATIC_PAREN_LIMIT",
  () => __testing.extractStaticJsValues(
    "synthetic/deep.ts",
    `const value = "a" + ${"(".repeat(40)}"b"${")".repeat(40)};`,
  ),
);

const longShallowSource = `/*${"(".repeat(2_000)}${"x".repeat(1_000_000)}*/\nconst value = "safe";`;
const longShallowValues = __testing.extractStaticJsValues("synthetic/long.ts", longShallowSource);
if (!longShallowValues.some((value) => value.text === "safe")) {
  console.error("  FAIL   a valid long-but-shallow source did not remain scannable");
  failures++;
} else {
  console.log("  ok     a valid long-but-shallow source remains scannable");
}

const templateTick = String.fromCharCode(96);
const rawTemplateSource = `const value = ${templateTick}${"(".repeat(1_000)}${templateTick};`;
const rawTemplateValues = __testing.extractStaticJsValues("synthetic/template.ts", rawTemplateSource);
if (!rawTemplateValues.some((value) => value.text === "(".repeat(1_000))) {
  console.error("  FAIL   template raw text was counted as lexical nesting");
  failures++;
} else {
  console.log("  ok     template raw delimiters do not consume the syntax-depth budget");
}

const regexDelimiterSource = `const pattern = /${"(".repeat(600)}x${")".repeat(600)}/;\nconst value = "safe";`;
const regexDelimiterValues = __testing.extractStaticJsValues("synthetic/regex.mjs", regexDelimiterSource);
if (!regexDelimiterValues.some((value) => value.text === "safe")) {
  console.error("  FAIL   regular-expression glyphs were counted as source nesting");
  failures++;
} else {
  console.log("  ok     regular-expression glyphs remain parser-owned rather than lexical nesting");
}

const cookedNewline = scanTokens(
  "synthetic/line-map.mjs",
  `const source = "prefix\\nsynthetic\\u002dconfidential\\u002drepo";`,
  SYNTHETIC_LOOKUP,
  SYNTHETIC_NGRAMS,
);
if (cookedNewline.findings.length !== 1 || cookedNewline.findings[0].line !== 1) {
  console.error("  FAIL   a cooked newline moved a derived finding away from its physical literal start line");
  failures++;
} else {
  console.log("  ok     cooked newlines preserve the physical literal start line");
}

const cookedNewlineThenPercent = scanRepoRefs(
  "synthetic/line-map.mjs",
  `const source = "prefix\\n${SYNTHETIC_OWNER}%2F${SYNTHETIC_REPOSITORY}";`,
  SYNTHETIC_ALLOWLIST,
);
if (cookedNewlineThenPercent.findings.length !== 1 || cookedNewlineThenPercent.findings[0].line !== 1) {
  console.error("  FAIL   decoding after a cooked newline moved a finding away from its physical literal start line");
  failures++;
} else {
  console.log("  ok     decoded cooked values retain the physical literal start line");
}

for (const [name, source, code] of [
  [
    "malformed relevant JSON",
    `{"source":"${SYNTHETIC_OWNER}\\u002fsynthetic\\u002dconfidential\\u002drepo"`,
    "STATIC_JSON_PARSE_FAILED",
  ],
  ["over-deep JSON", `${"[".repeat(513)}"\\u002f"${"]".repeat(513)}`, "STATIC_JSON_DEPTH_LIMIT"],
  ["over-node JSON", `["\\u002f",${"0,".repeat(262_143)}0]`, "STATIC_JSON_NODE_LIMIT"],
  ["over-size JSON", `"\\u0061${"a".repeat(1_048_576)}"`, "STATIC_SOURCE_LIMIT"],
]) {
  try {
    syntheticRepoOnly(source, "synthetic/bounded.json");
    console.error(`  FAIL   ${name} did not fail closed`);
    failures++;
  } catch (error) {
    if (error?.code !== code) {
      console.error(`  FAIL   ${name} failed with ${error?.code ?? error}, expected ${code}`);
      failures++;
    } else {
      console.log(`  ok     ${name} fails closed with ${code}`);
    }
  }
}

// This is not a fixture and never prints the result. It binds the source-hygiene assertion to the
// bootstrap-authenticated candidate subject, then proves neither raw source nor any statically
// reconstructed source value contains its coordinate or owner. All behavioral cases remain synthetic.
try {
  const selfPath = fileURLToPath(import.meta.url);
  const repository = boundaryScannerAuthority?.subject?.repository;
  const match = /^([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)$/.exec(String(repository ?? ""));
  if (match === null) throw new Error("authenticated-candidate-identity-unavailable");
  const candidateCoordinate = `${match[1]}/${match[2]}`.toLowerCase();
  const candidateOwnerCompact = match[1].toLowerCase().replace(/[^a-z0-9]/g, "");
  const selfSource = readFileSync(selfPath, "utf8");
  const reconstructed = __testing.extractStaticJsValues(selfPath, selfSource);
  const sourceForms = [selfSource, ...reconstructed.map((view) => view.text)];
  const embedsCandidateIdentity = sourceForms.some((value) => {
    const lower = value.toLowerCase();
    const compact = lower.replace(/[^a-z0-9]/g, "");
    return lower.includes(candidateCoordinate)
      || (candidateOwnerCompact.length >= 6 && compact.includes(candidateOwnerCompact));
  });
  if (embedsCandidateIdentity) throw new Error("candidate-identity-in-selftest");
  const sourceBoundary = [
    scanShapes("scripts/lib/boundary-scan.selftest.mjs", selfSource),
    scanPrivacyAdjacency("scripts/lib/boundary-scan.selftest.mjs", selfSource),
  ];
  if (sourceBoundary.some((result) => result.findings.length !== 0 || result.suppressed.length !== 0)) {
    throw new Error("boundary-finding-in-selftest-source");
  }
  console.log("  ok     selftest source contains no authenticated candidate identity fixture");
  console.log("  ok     selftest source is clean under shape and privacy scanning");
} catch {
  console.error("  FAIL   authenticated-candidate source-hygiene assertion failed (identity withheld)");
  failures++;
}

for (const [name, value] of [
  ["Unicode token", "caf\u00e9-secret"],
  ["homoglyph token", "n\u043ea-secret"],
  ["overlong token", `a${"b".repeat(64)}`],
  ["unsupported punctuation", "secret+label"],
  ["more than six spaced components", "one two three four five six seven"],
]) {
  try {
    reachableTokenForms(value);
    console.error(`  FAIL   token grammar accepted ${name}`);
    failures++;
  } catch (error) {
    if (!String(error?.message).startsWith("TOKEN_INPUT_UNREACHABLE:")) {
      console.error(`  FAIL   token grammar rejected ${name} with an unexpected error: ${error}`);
      failures++;
    } else {
      console.log(`  ok     token grammar rejects ${name}`);
    }
  }
}

console.log(
  failures === 0
    ? `\nboundary-scan selftest: ${findingCases} caught, ${cleanCases} let through, ${shippedRules.length} rules armed — it fires and it discriminates.`
    : `\nboundary-scan selftest: ${failures} FAILURE(S) — the scanner that judges the publish boundary is itself wrong.`,
);
test("boundary scanner contracts stay load-bearing", () => {
  if (failures !== 0) {
    throw new Error(`boundary scanner selftest recorded ${failures} contract failure(s)`);
  }
});
