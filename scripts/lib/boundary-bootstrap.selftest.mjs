#!/usr/bin/env node

import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve, sep } from "node:path";
import { test } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import ts from "typescript";
import {
  BOUNDARY_AUTHORITY_CLASS_CANDIDATE_TIER_A,
  BOUNDARY_AUTHORITY_CLASS_EXTERNAL,
  BOUNDARY_KNOCKOUT_BOOTSTRAP_ENV,
  CANDIDATE_TIER_A_NON_AUTHORITY_NON_CLAIM,
  canonicalBoundaryJson,
  deriveBoundaryCandidateSubject,
  deriveBoundaryControlManifest,
  deriveBoundaryKnockoutCandidateSubject,
  EXTERNAL_SANITIZED_AUTHORIZATION_NON_CLAIM,
  PREVIOUS_REVIEWED_CONTROL_PATHS,
  readOnlyGitOutput,
  REVIEWED_CONTROL_PATHS,
  scrubbedReadOnlyGitEnvironment,
  validateSanitizedAuthorizationBytes,
} from "./boundary-bootstrap.mjs";
import {
  createBoundaryRuntimeAuthorization,
  createBoundaryV3PolicyBytes,
  deriveBoundaryAuthorityBundleIdentity,
} from "./boundary-external-authority.mjs";
import {
  parseGateEvidence,
  PROVENANCE_BOUND_GATE_EVENT_PROTOCOL,
  UNVERIFIED_BOOTSTRAP_AUTHORITY_CLASS,
  UNVERIFIED_BOOTSTRAP_NON_CLAIM,
} from "./gate-event-contract.mjs";

const SOURCE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const opaquePathSubject = (path) => `path:sha256:${sha256(`noa-boundary:path:v1\0${String(path)}`)}`;
const syntheticKey = Buffer.alloc(32, 0x42);
const legacyBytes = Buffer.from("synthetic-token # bootstrap selftest collision\n", "utf8");
const EXPECTED_CANDIDATE_AUTHORITY_CLASS = "CANDIDATE_TIER_A_NON_AUTHORITY";
const EXPECTED_CANDIDATE_NON_CLAIM =
  "CANDIDATE_TIER_A_RESULT_IS_NOT_N_MINUS_1_TIER_B_OR_RELEASE_AUTHORITY";
const RAW_NUL_SOURCE_PATH = "src/raw-nul.ts";
const rawNulSourceBytes = () => Buffer.concat([
  Buffer.from('export const rawNulValue = "', "utf8"),
  Buffer.from([0]),
  Buffer.from('unknown";\n', "utf8"),
]);
const syntheticReviewSession = (suffix) => [
  "00000000", "0000", "4000", "8000", String(suffix).padStart(12, "0"),
].join("-");
const BOOTSTRAP_REVIEW_SESSION = syntheticReviewSession(20);
const REFUSAL_REVIEW_SESSION = syntheticReviewSession(21);
const LOCAL_SOURCE_EXTENSIONS = Object.freeze([
  ".mjs", ".cjs", ".js", ".json", ".ts", ".tsx", ".jsx",
]);
const REVIEWED_BOUNDARY_WORKER_CLOSURE = Object.freeze([
  "scripts/lib/boundary-spool-arm.selftest.mjs",
  "scripts/lib/knockout-test-observer.mjs",
  "scripts/lib/knockout-workspace-worker.mjs",
  "scripts/lib/knockout-workspace.mjs",
  "scripts/lib/proof-event-contract.mjs",
  "scripts/lib/proof-event-reporter.mjs",
  "scripts/lib/proof-resolve.mjs",
  "scripts/lib/typescript-test-hooks.mjs",
  "scripts/lib/typescript-test-register.mjs",
]);
assert.equal(
  BOOTSTRAP_REVIEW_SESSION,
  Buffer.from("30303030303030302d303030302d343030302d383030302d303030303030303030303230", "hex").toString("utf8"),
);
assert.equal(
  REFUSAL_REVIEW_SESSION,
  Buffer.from("30303030303030302d303030302d343030302d383030302d303030303030303030303231", "hex").toString("utf8"),
);

function git(root, args) {
  const result = spawnSync("git", args, { cwd: root, encoding: "utf8", shell: false });
  if (result.status !== 0) throw new Error(`git ${args.join(" ")} failed: ${result.stderr}`);
  return String(result.stdout ?? "").trim();
}

function copyExact(from, to) {
  mkdirSync(dirname(to), { recursive: true });
  copyFileSync(from, to);
}

const slashPath = (value) => value.split(sep).join("/");

function resolvedLocalSource(importer, specifier, { optionalFile = false } = {}) {
  if (typeof specifier !== "string" || !specifier.startsWith(".")) return null;
  const base = resolve(SOURCE_ROOT, dirname(importer), specifier);
  const candidates = [
    base,
    ...LOCAL_SOURCE_EXTENSIONS.map((extension) => `${base}${extension}`),
    ...LOCAL_SOURCE_EXTENSIONS.map((extension) => join(base, `index${extension}`)),
  ];
  for (const candidate of candidates) {
    try {
      if (!statSync(candidate).isFile()) continue;
      const local = slashPath(relative(SOURCE_ROOT, candidate));
      assert.equal(local === ".." || local.startsWith("../"), false,
        `${importer} local dependency escaped the repository: ${specifier}`);
      return local;
    } catch (error) {
      if (error?.code !== "ENOENT" && error?.code !== "ENOTDIR") throw error;
    }
  }
  if (optionalFile) return null;
  throw new Error(`${importer} has an unresolved local module dependency ${specifier}`);
}

function importMetaUrl(node) {
  return ts.isPropertyAccessExpression(node)
    && node.name.text === "url"
    && ts.isMetaProperty(node.expression)
    && node.expression.keywordToken === ts.SyntaxKind.ImportKeyword
    && node.expression.name.text === "meta";
}

function localSourceDependencies(relativePath) {
  if (relativePath.endsWith(".json") || !/\.(?:[cm]?js|tsx?|jsx)$/.test(relativePath)) return [];
  const source = readFileSync(join(SOURCE_ROOT, relativePath), "utf8");
  const ast = ts.createSourceFile(
    relativePath,
    source,
    ts.ScriptTarget.ESNext,
    true,
    ts.ScriptKind.JS,
  );
  assert.equal(ast.parseDiagnostics.length, 0, `${relativePath} did not parse for closure analysis`);
  const dependencies = new Set();
  const visit = (node) => {
    let specifier = null;
    let optionalFile = false;
    if (ts.isVariableDeclaration(node)
        && ts.isIdentifier(node.name)
        && node.name.text.endsWith("_WORKER_RELATIVE_PATH")
        && node.initializer !== undefined
        && ts.isStringLiteralLike(node.initializer)
        && node.initializer.text.startsWith("scripts/")
        && node.initializer.text.endsWith(".mjs")) {
      const dependency = resolvedLocalSource(relativePath, `../../${node.initializer.text}`);
      dependencies.add(dependency);
    }
    if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node))
        && node.moduleSpecifier && ts.isStringLiteralLike(node.moduleSpecifier)) {
      specifier = node.moduleSpecifier.text;
    } else if (ts.isCallExpression(node)
        && node.expression.kind === ts.SyntaxKind.ImportKeyword
        && node.arguments.length === 1 && ts.isStringLiteralLike(node.arguments[0])) {
      specifier = node.arguments[0].text;
    } else if (ts.isNewExpression(node) && ts.isIdentifier(node.expression)
        && node.expression.text === "URL" && node.arguments?.length === 2
        && ts.isStringLiteralLike(node.arguments[0]) && importMetaUrl(node.arguments[1])) {
      specifier = node.arguments[0].text;
      // A module-relative URL may deliberately name a directory root. Only existing files join the
      // executable closure; local imports above must always resolve to a file.
      optionalFile = true;
    }
    if (specifier?.startsWith(".")) {
      const dependency = resolvedLocalSource(relativePath, specifier, { optionalFile });
      if (dependency !== null) dependencies.add(dependency);
    }
    ts.forEachChild(node, visit);
  };
  visit(ast);
  return [...dependencies].sort();
}

function propertyAssignment(object, name) {
  return object.properties.find((property) => ts.isPropertyAssignment(property)
    && ((ts.isIdentifier(property.name) && property.name.text === name)
      || (ts.isStringLiteralLike(property.name) && property.name.text === name))) ?? null;
}

function provenanceRequiredBoundarySuiteRoots() {
  const relativePath = "scripts/lint-control-knockout.mjs";
  const source = readFileSync(join(SOURCE_ROOT, relativePath), "utf8");
  const ast = ts.createSourceFile(relativePath, source, ts.ScriptTarget.ESNext, true, ts.ScriptKind.JS);
  assert.equal(ast.parseDiagnostics.length, 0, "knockout registry did not parse for suite closure");
  const roots = new Set();
  const visit = (node) => {
    if (ts.isObjectLiteralExpression(node)) {
      const provenance = propertyAssignment(node, "expectedGateProvenance");
      const suite = propertyAssignment(node, "suite");
      if (provenance !== null && suite !== null
          && ts.isIdentifier(provenance.initializer)
          && provenance.initializer.text
            === "BOUNDARY_CANDIDATE_TIER_A_KNOCKOUT_PROVENANCE_EXPECTATION"
          && ts.isArrayLiteralExpression(suite.initializer)) {
        const [cwd, executable, args] = suite.initializer.elements;
        assert.equal(ts.isStringLiteralLike(cwd) ? cwd.text : null, ".");
        assert.equal(ts.isStringLiteralLike(executable) ? executable.text : null, "node");
        assert.equal(ts.isArrayLiteralExpression(args), true);
        const entrypoint = args.elements
          .filter(ts.isStringLiteralLike)
          .map((argument) => argument.text)
          .find((argument) => argument.startsWith("scripts/") && argument.endsWith(".mjs"));
        assert.equal(typeof entrypoint, "string", "a provenance-required boundary suite has no script");
        roots.add(entrypoint);
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(ast);
  return [...roots].sort();
}

function missingReviewedControlClosure(registry) {
  const reviewed = new Set(registry);
  const reached = new Set([...registry, ...provenanceRequiredBoundarySuiteRoots()]);
  const pending = [...reached];
  while (pending.length > 0) {
    const current = pending.shift();
    for (const dependency of localSourceDependencies(current)) {
      if (reached.has(dependency)) continue;
      reached.add(dependency);
      pending.push(dependency);
    }
  }
  return [...reached].filter((path) => !reviewed.has(path)).sort();
}

function buildFixture(work) {
  const root = join(work, "candidate");
  mkdirSync(root, { recursive: true });
  for (const relativePath of REVIEWED_CONTROL_PATHS) {
    copyExact(join(SOURCE_ROOT, relativePath), join(root, relativePath));
  }
  for (const relativePath of [
    "node_modules/typescript/package.json",
    "node_modules/typescript/lib/typescript.js",
  ]) {
    copyExact(join(SOURCE_ROOT, relativePath), join(root, relativePath));
  }
  writeFileSync(join(root, ".gitignore"), "node_modules/\n");
  git(root, ["init", "-q", "-b", "main"]);
  git(root, ["config", "user.email", "bootstrap-selftest@example.invalid"]);
  git(root, ["config", "user.name", "bootstrap selftest"]);
  git(root, ["config", "commit.gpgsign", "false"]);
  git(root, ["config", "tag.gpgsign", "false"]);
  git(root, ["config", "core.hooksPath", "scripts/hooks"]);
  git(root, ["remote", "add", "origin", "https://github.com/ExampleArmOrg/bootstrap-fixture.git"]);
  git(root, ["add", "-A"]);
  git(root, ["commit", "-q", "-m", "chore: exact bootstrap fixture"]);
  return realpathSync(root);
}

function buildWorkflowFixture(work) {
  const root = buildFixture(work);
  writeFileSync(join(root, "package.json"), `${JSON.stringify({
    name: "synthetic-workflow-candidate",
    version: "0.0.0",
    private: false,
    license: "Apache-2.0",
    files: ["dist", "README.md"],
    main: "dist/index.js",
    types: "dist/index.d.ts",
    devDependencies: { typescript: "5.9.3" },
  }, null, 2)}\n`);
  mkdirSync(join(root, "dist"), { recursive: true });
  writeFileSync(join(root, "dist", "index.js"), "export const value = 1;\n");
  writeFileSync(join(root, "dist", "index.d.ts"), "export declare const value: number;\n");
  writeFileSync(join(root, "dist", "index.js.map"), JSON.stringify({
    version: 3,
    file: "index.js",
    sources: ["../src/index.ts"],
    sourcesContent: ["export const value = 1;\n"],
    mappings: "",
  }));
  mkdirSync(join(root, "src"), { recursive: true });
  writeFileSync(join(root, RAW_NUL_SOURCE_PATH), rawNulSourceBytes());
  // A publication path is metadata, not JavaScript source. If scanExternalPath accidentally enables
  // parser reconstruction, this valid tracked file name produces TypeScript parse diagnostics and
  // the credential-free gate below fails closed instead of returning its expected clean verdict.
  writeFileSync(join(root, "src", "unclosed(.ts"), "export const pathMetadataControl = true;\n");
  mkdirSync(join(root, "conformance"), { recursive: true });
  writeFileSync(join(root, "conformance", "vectors.json"), "{\"vectors\":[]}\n");
  writeFileSync(join(root, "README.md"), "# Synthetic workflow candidate\n");
  writeFileSync(join(root, "scripts", "boundary-public-repos.json"), `${JSON.stringify({
    note: "Synthetic public-only snapshot for the credential-free workflow bootstrap selftest.",
    source: "synthetic bootstrap fixture",
    refreshedAt: "2026-08-30T00:00:00.000Z",
    orgs: {
      examplearmorg: [
        "bootstrap-fixture",
        "public-arm",
        "synthetic-confidential-repo",
        "synthetic-confidential-repo-renamed",
        "synthetic-public-repo",
      ],
      examplecorp: [
        "-public-dash", "-unlisted-sibling", ".public-dot", ".unlisted-sibling",
        "_public-underscore", "_unlisted-sibling", "another-public", "public-thing",
        "unlisted-sibling",
      ],
      samplearmorg: ["synthetic-confidential-repo", "synthetic-public-library"],
    },
  }, null, 2)}\n`);
  git(root, ["add", "-A"]);
  git(root, ["commit", "-q", "-m", "chore: synthetic workflow fixture"]);
  const base = git(root, ["rev-parse", "HEAD"]);
  writeFileSync(join(root, "README.md"), "# Synthetic workflow candidate\n\nExact Tier-A range.\n");
  git(root, ["add", "README.md"]);
  git(root, ["commit", "-q", "-m", "docs: exact tier a range"]);
  return { range: `${base}..HEAD`, root };
}

function authorizationFor(root) {
  const manifest = deriveBoundaryControlManifest(root);
  const subject = deriveBoundaryCandidateSubject(root);
  const nowMs = Date.now();
  const policyBytes = createBoundaryV3PolicyBytes({
    candidateManifest: manifest,
    keyBytes: syntheticKey,
    legacyBytes,
    nowMs,
    review: {
      classification: "PUBLIC_DERIVED_COLLISION",
      expiresAt: new Date(nowMs + 120_000).toISOString(),
      publicArtifact: "bootstrap-fixture@0.0.0",
      publicArtifactSRI: `sha512-${Buffer.alloc(64, 0x44).toString("base64")}`,
      reviewedAt: new Date(nowMs - 1_000).toISOString(),
      reviewer: "synthetic bootstrap supervisor",
      reviewSession: BOOTSTRAP_REVIEW_SESSION,
    },
  });
  const bundleIdentity = deriveBoundaryAuthorityBundleIdentity({
    version: "bootstrap-selftest-pinned-fixture-v1",
    files: manifest.files.filter((file) => [
      "scripts/lib/boundary-bootstrap.mjs",
      "scripts/lib/boundary-external-authority.mjs",
      "scripts/lib/boundary-token.mjs",
    ].includes(file.path)),
  });
  return createBoundaryRuntimeAuthorization({
    bundleIdentity,
    candidateManifest: manifest,
    expiresAt: new Date(nowMs + 120_000).toISOString(),
    issuedAt: new Date(nowMs).toISOString(),
    keyBytes: syntheticKey,
    legacyBytes,
    nonce: randomBytes(32).toString("hex"),
    operation: "RUNTIME",
    policyBytes,
    subject,
    tierBResult: {
      archiveSha256: subject.archiveSha256,
      candidateFormCount: 0,
      controlManifestDigest: manifest.digest,
      findingCount: 0,
      inputDigest: sha256("bootstrap-selftest-tier-b-input"),
      policySha256: sha256(policyBytes),
      resultDigest: sha256("bootstrap-selftest-tier-b-pass"),
      scannedUnitCount: 1,
      scannerId: "noa-boundary-tier-b/v1",
      schemaVersion: 1,
      verdict: "PASS",
    },
  });
}

function publicAuthorizationFile(work, bytes) {
  const path = join(work, `authorization-${randomBytes(8).toString("hex")}.json`);
  writeFileSync(path, bytes, { flag: "wx", mode: 0o400 });
  chmodSync(path, 0o400);
  return path;
}

function parseExactMachineEvidence(result, label) {
  const evidence = parseGateEvidence(result.stdout, {
    requireProvenance: true,
    strictOutput: true,
  });
  assert.equal(evidence.protocolComplete, true, `${label}: ${evidence.error}\n${result.stdout}\n${result.stderr}`);
  assert.equal(evidence.protocol, PROVENANCE_BOUND_GATE_EVENT_PROTOCOL, label);
  assert.equal(evidence.gate, "boundary", label);
  return evidence;
}

function assertCandidateMachineProvenance(provenance, root, label) {
  assert.equal(provenance.verification, "VERIFIED_BOOTSTRAP", label);
  assert.equal(provenance.authorityClass, BOUNDARY_AUTHORITY_CLASS_CANDIDATE_TIER_A, label);
  assert.equal(provenance.authorityNonClaim, CANDIDATE_TIER_A_NON_AUTHORITY_NON_CLAIM, label);
  assert.equal(provenance.bootstrapMode, "candidate-tier-a-non-authority", label);
  assert.equal(provenance.controlManifestDigest, deriveBoundaryControlManifest(root).digest, label);
  assert.equal(provenance.externalAuthorizationSha256, null, label);
  assert.equal(provenance.subject.commit, git(root, ["rev-parse", "HEAD"]), label);
  assert.equal(provenance.subject.repository, "ExampleArmOrg/bootstrap-fixture", label);
  assert.equal(provenance.tier, "a", label);
  assert.equal(provenance.visibilitySource, "snapshot", label);
}

function runLintFailure(root, work, authorizationBytes, sentinelPath) {
  const authorizationPath = publicAuthorizationFile(work, authorizationBytes);
  const sandboxHome = join(work, "sandbox-home-with-no-boundary-key");
  mkdirSync(sandboxHome, { mode: 0o700 });
  const result = spawnSync(process.execPath, [
    join(root, "scripts", "lint-boundary.mjs"),
    "--tier", "a",
    "--repo-visibility-source", "snapshot",
    "--knockout-json",
  ], {
    cwd: root,
    encoding: "utf8",
    env: {
      ...process.env,
      HOME: sandboxHome,
      NOA_BOUNDARY_AUTHORIZATION_FILE: authorizationPath,
      NOA_BOUNDARY_SENTINEL_PATH: sentinelPath,
    },
    shell: false,
  });
  return result;
}

function verifyViaReadOnlyFile(root, work, authorizationBytes) {
  const authorizationPath = publicAuthorizationFile(work, authorizationBytes);
  const bootstrapUrl = pathToFileURL(join(root, "scripts", "lib", "boundary-bootstrap.mjs")).href;
  return spawnSync(process.execPath, ["--input-type=module", "--eval", [
    `import { verifyBoundaryBootstrap } from ${JSON.stringify(bootstrapUrl)};`,
    `const result = verifyBoundaryBootstrap({ root: ${JSON.stringify(root)}, mode: "runtime" });`,
    `process.stdout.write(JSON.stringify({ authorityClass: result.authorityClass, authorization: result.authorization !== null, runtime: result.runtime !== null }));`,
  ].join("\n")], {
    cwd: root,
    encoding: "utf8",
    env: {
      ...process.env,
      HOME: join(work, "empty-home"),
      NOA_BOUNDARY_AUTHORIZATION_FILE: authorizationPath,
    },
    shell: false,
  });
}

test("pure bytes and read-only mounted-file adapters validate without candidate key custody", () => {
  const work = mkdtempSync(join(tmpdir(), "noa-boundary-bootstrap-positive-"));
  try {
    const root = buildFixture(work);
    const authorization = authorizationFor(root);
    assert.equal(validateSanitizedAuthorizationBytes(authorization.authorizationBytes).operation, "RUNTIME");
    const result = verifyViaReadOnlyFile(root, work, authorization.authorizationBytes);
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout), {
      authorityClass: BOUNDARY_AUTHORITY_CLASS_EXTERNAL,
      authorization: true,
      runtime: true,
    });
    assert.equal(existsSync(join(work, "empty-home", ".noa-boundary", "key")), false);
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
});

test("inherited pipe adapter consumes only sanitized public bytes", async () => {
  const work = mkdtempSync(join(tmpdir(), "noa-boundary-bootstrap-pipe-"));
  try {
    const root = buildFixture(work);
    const authorization = authorizationFor(root);
    const bootstrapUrl = pathToFileURL(join(root, "scripts", "lib", "boundary-bootstrap.mjs")).href;
    const child = spawn(process.execPath, ["--input-type=module", "--eval", [
      `import { verifyBoundaryBootstrap } from ${JSON.stringify(bootstrapUrl)};`,
      `const result = verifyBoundaryBootstrap({ root: ${JSON.stringify(root)}, mode: "runtime" });`,
      `process.stdout.write(result.runtime === null ? "FAIL" : "OK");`,
    ].join("\n")], {
      cwd: root,
      env: { ...process.env, HOME: join(work, "empty-home"), NOA_BOUNDARY_AUTHORIZATION_FD: "3" },
      stdio: ["ignore", "pipe", "pipe", "pipe"],
    });
    const stdout = [];
    const stderr = [];
    child.stdout.on("data", (chunk) => stdout.push(chunk));
    child.stderr.on("data", (chunk) => stderr.push(chunk));
    child.stdio[3].end(authorization.authorizationBytes);
    const status = await new Promise((resolveStatus) => child.on("close", resolveStatus));
    assert.equal(status, 0, Buffer.concat(stderr).toString("utf8"));
    assert.equal(Buffer.concat(stdout).toString("utf8"), "OK");
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
});

test("an unopened inherited authorization descriptor retains its stable invalid-fd diagnosis", () => {
  const bootstrapUrl = pathToFileURL(
    join(SOURCE_ROOT, "scripts", "lib", "boundary-bootstrap.mjs"),
  ).href;
  const result = spawnSync(process.execPath, ["--input-type=module", "--eval", [
    `import { verifyBoundaryBootstrap } from ${JSON.stringify(bootstrapUrl)};`,
    "try { verifyBoundaryBootstrap({ mode: 'runtime' }); }",
    "catch (error) { process.stdout.write(String(error.code)); process.exit(0); }",
    "process.exit(1);",
  ].join("\n")], {
    cwd: SOURCE_ROOT,
    encoding: "utf8",
    env: { ...process.env, NOA_BOUNDARY_AUTHORIZATION_FD: "999" },
    shell: false,
    stdio: ["ignore", "pipe", "pipe"],
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, "BOUNDARY_BOOTSTRAP_AUTHORIZATION_FD_INVALID");
});

test("credential-free workflow command is exact Tier-A non-authority and writes no external evidence", () => {
  const work = mkdtempSync(join(tmpdir(), "noa-boundary-workflow-invocation-"));
  try {
    const { range, root } = buildWorkflowFixture(work);
    const workflow = readFileSync(join(root, ".github", "workflows", "boundary.yml"), "utf8");
    assert.match(
      workflow,
      /node scripts\/lint-boundary\.mjs --repo-visibility-source snapshot --tier a --explain --range "\$\{\{ steps\.range\.outputs\.range \}\}"/,
    );
    const sandboxHome = join(work, "candidate-home");
    mkdirSync(sandboxHome, { mode: 0o700 });
    const environment = { ...process.env, HOME: sandboxHome };
    delete environment.NOA_BOUNDARY_AUTHORIZATION_FD;
    delete environment.NOA_BOUNDARY_AUTHORIZATION_FILE;
    delete environment.NOA_BOUNDARY_SYNTHETIC_SUPERVISOR_FIXTURE;

    const rawBytes = readFileSync(join(root, RAW_NUL_SOURCE_PATH));
    const rawNulOffsets = [...rawBytes.keys()].filter((offset) => rawBytes[offset] === 0);
    assert.deepEqual(rawNulOffsets, [Buffer.byteLength('export const rawNulValue = "', "utf8")]);
    const rawText = new TextDecoder("utf-8", { fatal: true }).decode(rawBytes);
    const nulCharacterOffset = rawText.indexOf(String.fromCharCode(0));
    assert.equal(nulCharacterOffset, rawNulOffsets[0]);
    assert.equal(rawText.charCodeAt(nulCharacterOffset), 0);
    assert.equal(rawText.slice(nulCharacterOffset), `${String.fromCharCode(0)}unknown";\n`);

    const bootstrapUrl = pathToFileURL(join(root, "scripts", "lib", "boundary-bootstrap.mjs")).href;
    const parserProof = spawnSync(process.execPath, ["--input-type=module", "--eval", [
      'import { readFileSync } from "node:fs";',
      `import { armCandidateTierANonAuthorityBootstrap, loadTrustedTypeScript } from ${JSON.stringify(bootstrapUrl)};`,
      `const root = ${JSON.stringify(root)};`,
      `const sourcePath = ${JSON.stringify(join(root, RAW_NUL_SOURCE_PATH))};`,
      "armCandidateTierANonAuthorityBootstrap({ root });",
      "const { authority, typescript } = await loadTrustedTypeScript({ root });",
      "const bytes = readFileSync(sourcePath);",
      'const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);',
      "const nulOffset = text.indexOf(String.fromCharCode(0));",
      `const source = typescript.createSourceFile(${JSON.stringify(RAW_NUL_SOURCE_PATH)}, text, typescript.ScriptTarget.Latest, true, typescript.ScriptKind.TS);`,
      "process.stdout.write(JSON.stringify({ authorityClass: authority.authorityClass, byteNulCount: [...bytes].filter((value) => value === 0).length, charCode: text.charCodeAt(nulOffset), diagnostics: source.parseDiagnostics.length, nulOffset, value: text.slice(nulOffset) }));",
    ].join("\n")], {
      cwd: root,
      encoding: "utf8",
      env: environment,
      shell: false,
    });
    assert.equal(parserProof.status, 0, parserProof.stderr);
    assert.deepEqual(JSON.parse(parserProof.stdout), {
      authorityClass: BOUNDARY_AUTHORITY_CLASS_CANDIDATE_TIER_A,
      byteNulCount: 1,
      charCode: 0,
      diagnostics: 0,
      nulOffset: rawNulOffsets[0],
      value: `${String.fromCharCode(0)}unknown";\n`,
    });

    const result = spawnSync(process.execPath, [
      "scripts/lint-boundary.mjs",
      "--repo-visibility-source", "snapshot",
      "--tier", "a",
      "--explain",
      "--range", range,
    ], {
      cwd: root,
      encoding: "utf8",
      env: environment,
      shell: false,
    });
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
    assert.match(result.stderr, new RegExp(`BOUNDARY_BOOTSTRAP_AUTHORITY_CLASS=${BOUNDARY_AUTHORITY_CLASS_CANDIDATE_TIER_A}`));
    assert.match(result.stderr, new RegExp(`BOUNDARY_BOOTSTRAP_NON_CLAIM=${CANDIDATE_TIER_A_NON_AUTHORITY_NON_CLAIM}`));
    assert.match(result.stderr, /external evidence ledger NOT_WRITTEN/);
    assert.equal(existsSync(join(sandboxHome, ".noa-boundary")), false);

    const candidateMachine = spawnSync(process.execPath, [
      "scripts/lint-boundary.mjs",
      "--repo-visibility-source", "snapshot",
      "--tier", "a",
      "--lane", "L-WT",
      "--range", range,
      "--knockout-json",
    ], {
      cwd: root,
      encoding: "utf8",
      env: environment,
      shell: false,
    });
    assert.equal(candidateMachine.status, 0, `${candidateMachine.stdout}\n${candidateMachine.stderr}`);
    const candidateEvidence = parseExactMachineEvidence(candidateMachine, "candidate machine evidence");
    assert.deepEqual(candidateEvidence.findings, []);
    assertCandidateMachineProvenance(candidateEvidence.provenance, root, "candidate machine evidence");

    const outputContract = spawnSync(process.execPath, [
      "scripts/lint-boundary.mjs",
      "--output-contract-selftest",
      "--knockout-json",
    ], {
      cwd: root,
      encoding: "utf8",
      env: environment,
      shell: false,
    });
    assert.equal(outputContract.status, 0, `${outputContract.stdout}\n${outputContract.stderr}`);
    const outputContractEvidence = parseExactMachineEvidence(outputContract, "output contract machine evidence");
    assert.deepEqual(outputContractEvidence.findings, []);
    assert.equal(outputContractEvidence.provenance.verification, "VERIFIED_BOOTSTRAP");
    assert.equal(outputContractEvidence.provenance.authorityClass, BOUNDARY_AUTHORITY_CLASS_CANDIDATE_TIER_A);
    assert.equal(outputContractEvidence.provenance.authorityNonClaim, CANDIDATE_TIER_A_NON_AUTHORITY_NON_CLAIM);
    assert.equal(outputContractEvidence.provenance.bootstrapMode, "candidate-tier-a-non-authority");
    assert.equal(outputContractEvidence.provenance.externalAuthorizationSha256, null);
    assert.equal(outputContractEvidence.provenance.tier, null);
    assert.equal(outputContractEvidence.provenance.visibilitySource, null);

    const runTransientFinding = (relativePath, bytes) => {
      const target = join(root, relativePath);
      writeFileSync(target, bytes);
      try {
        const observed = spawnSync(process.execPath, [
          "scripts/lint-boundary.mjs",
          "--repo-visibility-source", "snapshot",
          "--tier", "a",
          "--lane", "L-WT",
          "--knockout-json",
        ], {
          cwd: root,
          encoding: "utf8",
          env: environment,
          shell: false,
        });
        assert.equal(observed.status, 1, `${relativePath}: ${observed.stdout}\n${observed.stderr}`);
        const evidence = parseExactMachineEvidence(observed, relativePath);
        assert.equal(evidence.protocolComplete, true, `${relativePath}: ${evidence.error}`);
        assert.equal(evidence.gate, "boundary");
        assertCandidateMachineProvenance(evidence.provenance, root, relativePath);
        assert.deepEqual(
          evidence.findings.map(({ rule, subject }) => ({ rule, subject })),
          [
            { rule: "home-path", subject: opaquePathSubject(relativePath) },
            { rule: "privacy-adjacency", subject: opaquePathSubject(relativePath) },
          ],
        );
        assert.equal(observed.stdout.includes(relativePath), false, `${relativePath}: rejected path leaked to stdout`);
        assert.equal(observed.stderr.includes(relativePath), false, `${relativePath}: rejected path leaked to stderr`);
        assert.doesNotMatch(observed.stdout, /STATIC_SOURCE_PARSE_FAILED|SETUP_FAILED/);
      } finally {
        rmSync(target, { force: true });
      }
    };

    const sensitiveHomePath = ["/Us", "ers/", "operator", "/private.txt"].join("");
    runTransientFinding(
      "src/raw-nul-sensitive.ts",
      Buffer.concat([
        Buffer.from('export const sensitive = "/Users/" + /*', "utf8"),
        Buffer.from([0]),
        Buffer.from('*/ "operator/private.txt";\n', "utf8"),
      ]),
    );
    runTransientFinding(
      "src/malformed-binary.ts",
      Buffer.concat([
        Buffer.from([0xff, 0xfe, 0]),
        Buffer.from(sensitiveHomePath, "utf8"),
        Buffer.from([0]),
      ]),
    );

    const externalAuthorization = authorizationFor(root);
    const externalAuthorizationPath = publicAuthorizationFile(
      work,
      externalAuthorization.authorizationBytes,
    );
    const external = spawnSync(process.execPath, [
      "scripts/lint-boundary.mjs",
      "--repo-visibility-source", "snapshot",
      "--tier", "a",
      "--lane", "L-MSG",
      "--range", range,
    ], {
      cwd: root,
      encoding: "utf8",
      env: {
        ...environment,
        HOME: join(work, "external-home"),
        NOA_BOUNDARY_AUTHORIZATION_FILE: externalAuthorizationPath,
      },
      shell: false,
    });
    assert.equal(external.status, 0, `${external.stdout}\n${external.stderr}`);
    assert.match(external.stderr, new RegExp(`BOUNDARY_BOOTSTRAP_AUTHORITY_CLASS=${BOUNDARY_AUTHORITY_CLASS_EXTERNAL}`));
    assert.doesNotMatch(external.stderr, new RegExp(`BOUNDARY_BOOTSTRAP_AUTHORITY_CLASS=${BOUNDARY_AUTHORITY_CLASS_CANDIDATE_TIER_A}`));

    const externalMachine = spawnSync(process.execPath, [
      "scripts/lint-boundary.mjs",
      "--repo-visibility-source", "snapshot",
      "--tier", "a",
      "--lane", "L-MSG",
      "--range", range,
      "--knockout-json",
    ], {
      cwd: root,
      encoding: "utf8",
      env: {
        ...environment,
        HOME: join(work, "external-machine-home"),
        NOA_BOUNDARY_AUTHORIZATION_FILE: externalAuthorizationPath,
      },
      shell: false,
    });
    assert.equal(externalMachine.status, 0, `${externalMachine.stdout}\n${externalMachine.stderr}`);
    const externalEvidence = parseExactMachineEvidence(externalMachine, "external machine evidence");
    assert.deepEqual(externalEvidence.findings, []);
    assert.equal(externalEvidence.provenance.verification, "VERIFIED_BOOTSTRAP");
    assert.equal(externalEvidence.provenance.authorityClass, BOUNDARY_AUTHORITY_CLASS_EXTERNAL);
    assert.equal(externalEvidence.provenance.authorityNonClaim, EXTERNAL_SANITIZED_AUTHORIZATION_NON_CLAIM);
    assert.equal(externalEvidence.provenance.bootstrapMode, "runtime");
    assert.match(externalEvidence.provenance.externalAuthorizationSha256, /^[0-9a-f]{64}$/);
    assert.equal(externalEvidence.provenance.controlManifestDigest, deriveBoundaryControlManifest(root).digest);
    assert.equal(externalEvidence.provenance.subject.commit, git(root, ["rev-parse", "HEAD"]));
    assert.equal(externalEvidence.provenance.tier, "a");
    assert.equal(externalEvidence.provenance.visibilitySource, "snapshot");
    assert.notEqual(externalMachine.stdout, candidateMachine.stdout);

    const scannerUrl = pathToFileURL(join(root, "scripts", "lib", "boundary-scan.mjs")).href;
    const contract = spawnSync(process.execPath, ["--input-type=module", "--eval", [
      `import { armCandidateTierANonAuthorityBootstrap } from ${JSON.stringify(bootstrapUrl)};`,
      `armCandidateTierANonAuthorityBootstrap({ root: ${JSON.stringify(root)} });`,
      `const scanner = await import(${JSON.stringify(scannerUrl)});`,
      "const value = scanner.boundaryScannerAuthority;",
      "process.stdout.write(JSON.stringify({ authorityClass: value.authorityClass, authorityNonClaim: value.authorityNonClaim, authorization: value.authorization, frozen: Object.isFrozen(value), mode: value.mode }));",
    ].join("\n")], {
      cwd: root,
      encoding: "utf8",
      env: environment,
      shell: false,
    });
    assert.equal(contract.status, 0, contract.stderr);
    assert.deepEqual(JSON.parse(contract.stdout), {
      authorityClass: BOUNDARY_AUTHORITY_CLASS_CANDIDATE_TIER_A,
      authorityNonClaim: CANDIDATE_TIER_A_NON_AUTHORITY_NON_CLAIM,
      authorization: null,
      frozen: true,
      mode: "candidate-tier-a-non-authority",
    });

    const direct = spawnSync(process.execPath, ["--input-type=module", "--eval",
      `await import(${JSON.stringify(scannerUrl)});`], {
      cwd: root,
      encoding: "utf8",
      env: environment,
      shell: false,
    });
    assert.notEqual(direct.status, 0);
    assert.match(direct.stderr, /BOUNDARY_BOOTSTRAP_AUTHORIZATION_CHANNEL_AMBIGUOUS/);

    const injected = spawnSync(process.execPath, ["--input-type=module", "--eval",
      `await import(${JSON.stringify(scannerUrl)});`], {
      cwd: root,
      encoding: "utf8",
      env: { ...environment, NOA_BOUNDARY_INTERNAL_BOOTSTRAP_MODE: "CANDIDATE_TIER_A_NON_AUTHORITY" },
      shell: false,
    });
    assert.notEqual(injected.status, 0);
    assert.match(injected.stderr, /BOUNDARY_BOOTSTRAP_AUTHORIZATION_CHANNEL_AMBIGUOUS/);
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
});

test("isolated knockout bootstrap is direct-pipe-bound, remote-free, and fail-closed", () => {
  const work = mkdtempSync(join(tmpdir(), "noa-boundary-knockout-bootstrap-"));
  try {
    const root = buildFixture(work);
    git(root, ["remote", "set-url", "origin", "https://github.com/FixtureIdentityOrg/bootstrap-fixture.git"]);
    const candidateSubject = deriveBoundaryKnockoutCandidateSubject(root);

    git(root, ["remote", "remove", "origin"]);
    for (const key of ["user.email", "user.name", "commit.gpgsign", "tag.gpgsign"]) {
      git(root, ["config", "--unset-all", key]);
    }
    for (const [key, value] of [
      ["core.ignorecase", "true"],
      ["core.precomposeunicode", "true"],
      ["core.symlinks", "true"],
      ["core.fsmonitor", "false"],
      ["core.splitIndex", "false"],
      ["core.untrackedCache", "false"],
      ["core.hooksPath", "/dev/null"],
      ["gc.auto", "0"],
      ["maintenance.auto", "false"],
    ]) {
      git(root, ["config", key, value]);
    }

    const environment = {
      ...process.env,
      HOME: join(work, "closed-home"),
      [BOUNDARY_KNOCKOUT_BOOTSTRAP_ENV]: "0",
    };
    delete environment.NOA_BOUNDARY_AUTHORIZATION_FD;
    delete environment.NOA_BOUNDARY_AUTHORIZATION_FILE;
    delete environment.NOA_BOUNDARY_SYNTHETIC_SUPERVISOR_FIXTURE;
    const contextFor = (subject = candidateSubject, workerPid = process.pid) => Buffer.from(`${canonicalBoundaryJson({
      candidateSubject: subject,
      protocol: "noa-boundary-knockout-bootstrap/1",
      workerCapabilitySha256: "a".repeat(64),
      workerPid,
    })}\n`, "utf8");
    const invoke = ({
      args = ["--output-contract-selftest", "--knockout-json"],
      env = environment,
      input = contextFor(),
    } = {}) => spawnSync(process.execPath, ["scripts/lint-boundary.mjs", ...args], {
      cwd: root,
      encoding: "utf8",
      env,
      input,
      shell: false,
    });

    const success = invoke();
    assert.equal(success.status, 0, `${success.stdout}\n${success.stderr}`);
    const evidence = parseExactMachineEvidence(success, "isolated knockout bootstrap");
    assert.deepEqual(evidence.findings, []);
    assert.deepEqual(evidence.provenance.subject, candidateSubject);
    assert.equal(evidence.provenance.verification, "VERIFIED_BOOTSTRAP");
    assert.equal(evidence.provenance.authorityClass, BOUNDARY_AUTHORITY_CLASS_CANDIDATE_TIER_A);
    assert.equal(evidence.provenance.authorityNonClaim, CANDIDATE_TIER_A_NON_AUTHORITY_NON_CLAIM);
    assert.equal(evidence.provenance.bootstrapMode, "candidate-tier-a-non-authority");
    assert.equal(evidence.provenance.controlManifestDigest, deriveBoundaryControlManifest(root).digest);
    assert.equal(evidence.provenance.externalAuthorizationSha256, null);
    assert.equal(evidence.provenance.tier, null);
    assert.equal(evidence.provenance.visibilitySource, null);
    assert.equal(git(root, ["remote"]), "");
    assert.equal(git(root, ["config", "--get", "core.hooksPath"]), "/dev/null");
    const remoteConfig = spawnSync("git", ["config", "--local", "--get-regexp", "^remote\\."], {
      cwd: root,
      encoding: "utf8",
      shell: false,
    });
    assert.equal(remoteConfig.status, 1, remoteConfig.stderr);
    assert.equal(remoteConfig.stdout, "");
    assert.equal(git(root, ["status", "--short"]), "");
    assert.equal(existsSync(join(work, "closed-home", ".noa-boundary")), false);

    const bootstrapUrl = pathToFileURL(join(root, "scripts", "lib", "boundary-bootstrap.mjs")).href;
    const scannerUrl = pathToFileURL(join(root, "scripts", "lib", "boundary-scan.mjs")).href;
    const scannerSelftestPath = join(root, "scripts", "lib", "boundary-scan.selftest.mjs");
    const nested = spawnSync(process.execPath, ["--input-type=module", "--eval", [
      `import { spawn, spawnSync } from "node:child_process";`,
      `import { armCandidateTierANonAuthorityBootstrap, BOUNDARY_KNOCKOUT_BOOTSTRAP_ENV, prepareNestedBoundaryScannerSelftestBootstrap } from ${JSON.stringify(bootstrapUrl)};`,
      `armCandidateTierANonAuthorityBootstrap({ root: ${JSON.stringify(root)} });`,
      `const { boundaryScannerAuthority } = await import(${JSON.stringify(scannerUrl)});`,
      `const nestedBootstrapIssuer = prepareNestedBoundaryScannerSelftestBootstrap(boundaryScannerAuthority);`,
      `let reuseCode = null;`,
      `try { prepareNestedBoundaryScannerSelftestBootstrap(boundaryScannerAuthority); } catch (error) { reuseCode = error?.code ?? null; }`,
      `const fakeAuthorityRejected = prepareNestedBoundaryScannerSelftestBootstrap(Object.freeze({ ...boundaryScannerAuthority })) === null;`,
      `const childEnvironment = { ...process.env };`,
      `delete childEnvironment.NOA_BOUNDARY_AUTHORIZATION_FD;`,
      `delete childEnvironment.NOA_BOUNDARY_AUTHORIZATION_FILE;`,
      `delete childEnvironment.NOA_BOUNDARY_INTERNAL_BOOTSTRAP_MODE;`,
      `childEnvironment[BOUNDARY_KNOCKOUT_BOOTSTRAP_ENV] = "0";`,
      `childEnvironment.NOA_BOUNDARY_SCANNER_SELFTEST_CHILD = "1";`,
      // Deliberately unsupported poison input: candidate identity must remain the authenticated
      // bootstrap subject. A future environment-based repository override must make this test fail.
      `childEnvironment.NOA_BOUNDARY_SCANNER_SELFTEST_REPOSITORY_OVERRIDE = "examplearmorg/synthetic-confidential-repo";`,
      `const child = spawn(process.execPath, [${JSON.stringify(scannerSelftestPath)}], { cwd: ${JSON.stringify(root)}, env: childEnvironment, shell: false, stdio: ["pipe", "pipe", "pipe"] });`,
      `let childStdout = ""; let childStderr = "";`,
      `child.stdout.on("data", (chunk) => { childStdout += String(chunk); });`,
      `child.stderr.on("data", (chunk) => { childStderr += String(chunk); });`,
      `const childClosed = new Promise((resolveClose) => child.once("close", (status) => resolveClose(status)));`,
      `const nestedBootstrap = nestedBootstrapIssuer.issueForChild(child.pid);`,
      `const nestedDocument = JSON.parse(nestedBootstrap.toString("utf8"));`,
      `child.stdin.end(nestedBootstrap);`,
      `const replayChild = spawnSync(process.execPath, [${JSON.stringify(scannerSelftestPath)}], { cwd: ${JSON.stringify(root)}, encoding: "utf8", env: childEnvironment, input: nestedBootstrap, shell: false });`,
      `const childStatus = await childClosed;`,
      `process.stdout.write(JSON.stringify({ childStatus, childStderr: childStderr.slice(-1000), childSummary: childStdout.includes("151 caught, 62 let through, 19 rules armed"), fakeAuthorityRejected, nestedAudiencePid: nestedDocument.audiencePid, nestedSubject: nestedDocument.candidateSubject, replayStderr: String(replayChild.stderr ?? "").slice(-1000), replayStatus: replayChild.status, reuseCode }));`,
    ].join("\n")], {
      cwd: root,
      encoding: "utf8",
      env: environment,
      input: contextFor(),
      shell: false,
    });
    assert.equal(nested.status, 0, `${nested.stdout}\n${nested.stderr}`);
    const nestedEvidence = JSON.parse(nested.stdout);
    assert.equal(nestedEvidence.childStatus, 0, nestedEvidence.childStderr);
    assert.equal(nestedEvidence.childSummary, true);
    assert.equal(nestedEvidence.fakeAuthorityRejected, true);
    assert.equal(Number.isSafeInteger(nestedEvidence.nestedAudiencePid), true);
    assert.equal(nestedEvidence.nestedAudiencePid > 0, true);
    assert.deepEqual(nestedEvidence.nestedSubject, candidateSubject);
    assert.notEqual(nestedEvidence.replayStatus, 0, "nested bootstrap bytes must reject a sibling replay");
    assert.match(nestedEvidence.replayStderr, /BOUNDARY_BOOTSTRAP_SCHEMA_INVALID/);
    assert.equal(nestedEvidence.reuseCode, "BOUNDARY_BOOTSTRAP_NESTED_CAPABILITY_REUSED");
    assert.equal(git(root, ["remote"]), "");
    assert.equal(git(root, ["config", "--get", "core.hooksPath"]), "/dev/null");
    assert.equal(git(root, ["status", "--short"]), "");

    const armUrl = pathToFileURL(join(root, "scripts", "lib", "boundary-arm.mjs")).href;
    const terminalSupervisor = spawnSync(process.execPath, ["--input-type=module", "--eval", [
      `import { armCandidateTierANonAuthorityBootstrap } from ${JSON.stringify(bootstrapUrl)};`,
      `armCandidateTierANonAuthorityBootstrap({ root: ${JSON.stringify(root)} });`,
      `const { runArmTerminalSupervisorMetaSelftest } = await import(${JSON.stringify(armUrl)});`,
      "const result = await runArmTerminalSupervisorMetaSelftest();",
      'process.stdout.write(JSON.stringify(result));',
      "process.exit(result.ok ? 0 : 1);",
    ].join("\n")], {
      cwd: root,
      encoding: "utf8",
      env: environment,
      input: contextFor(),
      shell: false,
    });
    assert.equal(terminalSupervisor.status, 0, `${terminalSupervisor.stdout}\n${terminalSupervisor.stderr}`);

    const wrongEntrypointChildSource = [
      `import { armCandidateTierANonAuthorityBootstrap } from ${JSON.stringify(bootstrapUrl)};`,
      `armCandidateTierANonAuthorityBootstrap({ root: ${JSON.stringify(root)} });`,
      `await import(${JSON.stringify(scannerUrl)});`,
    ].join("\n");
    const wrongEntrypoint = spawnSync(process.execPath, ["--input-type=module", "--eval", [
      'import { spawn } from "node:child_process";',
      `import { armCandidateTierANonAuthorityBootstrap, BOUNDARY_KNOCKOUT_BOOTSTRAP_ENV, prepareNestedBoundaryScannerSelftestBootstrap } from ${JSON.stringify(bootstrapUrl)};`,
      `armCandidateTierANonAuthorityBootstrap({ root: ${JSON.stringify(root)} });`,
      `const { boundaryScannerAuthority } = await import(${JSON.stringify(scannerUrl)});`,
      "const issuer = prepareNestedBoundaryScannerSelftestBootstrap(boundaryScannerAuthority);",
      "const childEnvironment = { ...process.env };",
      "delete childEnvironment.NOA_BOUNDARY_AUTHORIZATION_FD;",
      "delete childEnvironment.NOA_BOUNDARY_AUTHORIZATION_FILE;",
      "delete childEnvironment.NOA_BOUNDARY_INTERNAL_BOOTSTRAP_MODE;",
      'childEnvironment[BOUNDARY_KNOCKOUT_BOOTSTRAP_ENV] = "0";',
      `const child = spawn(process.execPath, ["--input-type=module", "--eval", ${JSON.stringify(wrongEntrypointChildSource)}], { cwd: ${JSON.stringify(root)}, env: childEnvironment, shell: false, stdio: ["pipe", "pipe", "pipe"] });`,
      'let stdout = ""; let stderr = ""; let stdinError = null;',
      'child.stdout.on("data", (chunk) => { stdout += String(chunk); });',
      'child.stderr.on("data", (chunk) => { stderr += String(chunk); });',
      'child.stdin.on("error", (error) => { stdinError = error?.code ?? "UNKNOWN"; });',
      'const closed = new Promise((resolveClose) => child.once("close", (status, signal) => resolveClose({ signal, status })));',
      "child.stdin.end(issuer.issueForChild(child.pid));",
      "const observed = await closed;",
      "process.stdout.write(JSON.stringify({ ...observed, stderr: stderr.slice(-1000), stdinError, stdout: stdout.slice(-1000) }));",
    ].join("\n")], {
      cwd: root,
      encoding: "utf8",
      env: environment,
      input: contextFor(),
      shell: false,
    });
    assert.equal(wrongEntrypoint.status, 0, `${wrongEntrypoint.stdout}\n${wrongEntrypoint.stderr}`);
    const wrongEntrypointEvidence = JSON.parse(wrongEntrypoint.stdout);
    assert.notEqual(wrongEntrypointEvidence.status, 0);
    assert.equal(wrongEntrypointEvidence.signal, null);
    assert.equal(wrongEntrypointEvidence.stdinError, null);
    assert.match(
      `${wrongEntrypointEvidence.stdout}\n${wrongEntrypointEvidence.stderr}`,
      /BOUNDARY_BOOTSTRAP_NESTED_AUDIENCE_MISMATCH/,
    );

    const mismatchedSubject = { ...candidateSubject, tree: "0".repeat(candidateSubject.tree.length) };
    const mismatch = invoke({ input: contextFor(mismatchedSubject) });
    assert.equal(mismatch.status, 2, `${mismatch.stdout}\n${mismatch.stderr}`);
    assert.match(mismatch.stdout, /SETUP_FAILED/);
    assert.match(mismatch.stdout, /BOUNDARY_BOOTSTRAP_SUBJECT_MISMATCH/);

    const wrongParent = invoke({ input: contextFor(candidateSubject, process.pid + 1) });
    assert.equal(wrongParent.status, 2, `${wrongParent.stdout}\n${wrongParent.stderr}`);
    assert.match(wrongParent.stdout, /BOUNDARY_BOOTSTRAP_SCHEMA_INVALID/);

    const malformed = invoke({ input: Buffer.from("{}\n", "utf8") });
    assert.equal(malformed.status, 2, `${malformed.stdout}\n${malformed.stderr}`);
    assert.match(malformed.stdout, /BOUNDARY_BOOTSTRAP_SCHEMA_INVALID/);

    const nullDocument = invoke({ input: Buffer.from("null\n", "utf8") });
    assert.equal(nullDocument.status, 2, `${nullDocument.stdout}\n${nullDocument.stderr}`);
    assert.match(nullDocument.stdout, /BOUNDARY_BOOTSTRAP_SCHEMA_INVALID/);

    const mixedAuthority = invoke({
      env: { ...environment, NOA_BOUNDARY_AUTHORIZATION_FD: "999" },
    });
    assert.equal(mixedAuthority.status, 2, `${mixedAuthority.stdout}\n${mixedAuthority.stderr}`);
    assert.match(mixedAuthority.stdout, /isolated knockout bootstrap scope/);

    const privileged = invoke({
      args: ["--tier", "ab", "--repo-visibility-source", "snapshot", "--knockout-json"],
    });
    assert.equal(privileged.status, 2, `${privileged.stdout}\n${privileged.stderr}`);
    assert.match(privileged.stdout, /isolated knockout bootstrap scope/);

    const wrongDescriptor = invoke({
      env: { ...environment, [BOUNDARY_KNOCKOUT_BOOTSTRAP_ENV]: "3" },
    });
    assert.equal(wrongDescriptor.status, 2, `${wrongDescriptor.stdout}\n${wrongDescriptor.stderr}`);
    const wrongDescriptorEvidence = parseExactMachineEvidence(
      wrongDescriptor,
      "isolated knockout wrong descriptor",
    );
    assert.deepEqual(wrongDescriptorEvidence.findings.map(({ rule, subject }) => ({ rule, subject })), [
      { rule: "SETUP_FAILED", subject: "the gate itself threw" },
    ]);
    assert.equal(wrongDescriptorEvidence.provenance.verification, "UNVERIFIED_BOOTSTRAP");
    assert.doesNotMatch(wrongDescriptor.stdout, /BOUNDARY_BOOTSTRAP_AUTHORIZATION_FD_MISSING/);
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
});

test("lock, attestation, parser-byte, and parser-symlink drift fail before parser top level", () => {
  const cases = [
    {
      name: "lock",
      code: "BOUNDARY_BOOTSTRAP_LOCK_DIGEST_MISMATCH",
      mutate: (root) => writeFileSync(join(root, "package-lock.json"), `${readFileSync(join(root, "package-lock.json"), "utf8")} `),
    },
    {
      name: "attestation",
      code: "BOUNDARY_BOOTSTRAP_SCHEMA_INVALID",
      mutate: (root) => writeFileSync(join(root, "scripts", "boundary-runtime-attestation.json"), "{}\n"),
    },
    {
      name: "parser bytes with top-level sentinel",
      code: "BOUNDARY_BOOTSTRAP_RUNTIME_DIGEST_MISMATCH",
      mutate: (root, sentinelPath) => {
        const parserPath = join(root, "node_modules", "typescript", "lib", "typescript.js");
        writeFileSync(
          parserPath,
          `require("node:fs").writeFileSync(process.env.NOA_BOUNDARY_SENTINEL_PATH,"EXECUTED");\n${readFileSync(parserPath, "utf8")}`,
        );
      },
    },
    {
      name: "parser symlink",
      code: "BOUNDARY_BOOTSTRAP_PATH_IDENTITY_INVALID",
      mutate: (root) => {
        const parserPath = join(root, "node_modules", "typescript", "lib", "typescript.js");
        const targetPath = `${parserPath}.real`;
        renameSync(parserPath, targetPath);
        symlinkSync(targetPath, parserPath);
      },
    },
  ];
  for (const fixture of cases) {
    const work = mkdtempSync(join(tmpdir(), "noa-boundary-bootstrap-negative-"));
    try {
      const root = buildFixture(work);
      const sentinelPath = join(work, "PARSER_TOP_LEVEL_EXECUTED");
      fixture.mutate(root, sentinelPath);
      const authorization = authorizationFor(root);
      const result = runLintFailure(root, work, authorization.authorizationBytes, sentinelPath);
      assert.equal(result.status, 2, `${fixture.name}: ${result.stdout}\n${result.stderr}`);
      assert.match(result.stdout, /SETUP_FAILED/, fixture.name);
      assert.match(result.stdout, new RegExp(fixture.code), fixture.name);
      assert.throws(() => readFileSync(sentinelPath), /ENOENT/, `${fixture.name}: parser top-level sentinel executed`);
    } finally {
      rmSync(work, { recursive: true, force: true });
    }
  }
});

test("reviewed controls close every local worker and provenance-required boundary suite", () => {
  assert.deepEqual(
    provenanceRequiredBoundarySuiteRoots(),
    ["scripts/lib/boundary-spool-arm.selftest.mjs", "scripts/lint-boundary.mjs"],
    "the explicit provenance-required boundary suite frontier drifted",
  );
  assert.deepEqual(missingReviewedControlClosure(REVIEWED_CONTROL_PATHS), []);

  const preClosureRegistry = REVIEWED_CONTROL_PATHS.filter((path) =>
    !REVIEWED_BOUNDARY_WORKER_CLOSURE.includes(path));
  assert.deepEqual(
    missingReviewedControlClosure(preClosureRegistry),
    REVIEWED_BOUNDARY_WORKER_CLOSURE,
    "the closure negative no longer exposes every direct, transitive, URL-sealed, and suite worker",
  );
  for (const removed of REVIEWED_BOUNDARY_WORKER_CLOSURE) {
    assert.deepEqual(
      missingReviewedControlClosure(REVIEWED_CONTROL_PATHS.filter((path) => path !== removed)),
      [removed],
      `${removed} could be removed without reopening the reviewed-control closure`,
    );
  }
});

test("candidate Git observation is standalone, closed-environment, exact-commit, and config bounded", () => {
  const hostileEnvironment = {
    ...process.env,
    DYLD_INSERT_LIBRARIES: "/tmp/hostile.dylib",
    GIT_OBJECT_DIRECTORY: "/tmp/hostile-objects",
    GIT_REPLACE_REF_BASE: "refs/hostile/",
    GH_TOKEN: "synthetic-never-forwarded",
    HOME: "/tmp/hostile-home",
    LD_PRELOAD: "/tmp/hostile.so",
    PATH: "/tmp/hostile-bin",
    XDG_CONFIG_HOME: "/tmp/hostile-xdg",
  };
  assert.deepEqual(scrubbedReadOnlyGitEnvironment(hostileEnvironment), {
    GCM_INTERACTIVE: "Never",
    GIT_ATTR_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_SYSTEM: "/dev/null",
    GIT_NO_REPLACE_OBJECTS: "1",
    GIT_OPTIONAL_LOCKS: "0",
    GIT_PAGER: "cat",
    GIT_TERMINAL_PROMPT: "0",
    HOME: "/var/empty/noa-boundary-git-home",
    LANG: "C",
    LC_ALL: "C",
    PAGER: "cat",
    PATH: "/usr/bin:/bin",
    XDG_CONFIG_HOME: "/var/empty/noa-boundary-git-home",
  });

  const work = mkdtempSync(join(tmpdir(), "noa-boundary-bootstrap-git-"));
  try {
    const root = buildFixture(work);
    const expectedCommit = git(root, ["rev-parse", "HEAD"]);
    const subject = deriveBoundaryCandidateSubject(root);
    assert.equal(subject.commit, expectedCommit);
    assert.equal(subject.tree, git(root, ["rev-parse", `${expectedCommit}^{tree}`]));
    const baselineArchive = readOnlyGitOutput(
      root,
      ["archive", "--format=tar", expectedCommit],
      { binary: true },
    );
    assert.equal(sha256(baselineArchive), subject.archiveSha256);
    assert.throws(
      () => readOnlyGitOutput(root, ["status", "--short"]),
      /BOUNDARY_BOOTSTRAP_GIT_ARGUMENT_REJECTED/,
    );
    assert.throws(
      () => readOnlyGitOutput(root, ["archive", "--format=tar", "HEAD"]),
      /BOUNDARY_BOOTSTRAP_GIT_ARGUMENT_REJECTED/,
      "archive must bind an immutable object id rather than a moving ref",
    );

    git(root, ["config", "filter.hostile.clean", "/tmp/never-execute"]);
    assert.throws(
      () => deriveBoundaryCandidateSubject(root),
      /BOUNDARY_BOOTSTRAP_GIT_CONFIG_INVALID/,
    );
    git(root, ["config", "--unset-all", "filter.hostile.clean"]);

    git(root, ["config", "tag.gpgsign", "true"]);
    assert.throws(
      () => deriveBoundaryCandidateSubject(root),
      /BOUNDARY_BOOTSTRAP_GIT_CONFIG_INVALID/,
      "candidate observation must reject tag signing rather than inheriting key access",
    );
    git(root, ["config", "tag.gpgsign", "false"]);

    writeFileSync(join(root, ".git", "info", "attributes"), "package.json export-ignore\n");
    const overriddenArchive = readOnlyGitOutput(
      root,
      ["archive", "--format=tar", expectedCommit],
      { binary: true },
    );
    assert.equal(git(root, ["rev-parse", "HEAD"]), expectedCommit);
    assert.equal(git(root, ["rev-parse", `${expectedCommit}^{tree}`]), subject.tree);
    assert.notEqual(
      sha256(overriddenArchive),
      subject.archiveSha256,
      "uncommitted info attributes must be demonstrated to alter the same commit/tree archive",
    );
    assert.throws(
      () => deriveBoundaryCandidateSubject(root),
      /BOUNDARY_BOOTSTRAP_GIT_LAYOUT_INVALID/,
      "an uncommitted info/attributes override must not omit committed archive paths",
    );
    rmSync(join(root, ".git", "info", "attributes"));

    git(root, ["gc", "--prune=now"]);
    const packDirectory = join(root, ".git", "objects", "pack");
    const externalPackDirectory = join(work, "external-pack");
    renameSync(packDirectory, externalPackDirectory);
    symlinkSync(externalPackDirectory, packDirectory, "dir");
    assert.throws(
      () => deriveBoundaryCandidateSubject(root),
      /BOUNDARY_BOOTSTRAP_GIT_LAYOUT_INVALID/,
      "an externally symlinked object pack must not become standalone candidate storage",
    );
    rmSync(packDirectory);
    renameSync(externalPackDirectory, packDirectory);

    const linked = join(work, "linked");
    git(root, ["worktree", "add", "--detach", linked, "HEAD"]);
    assert.throws(
      () => deriveBoundaryCandidateSubject(root),
      /BOUNDARY_BOOTSTRAP_GIT_LAYOUT_INVALID/,
      "a root that shares its Git storage with a linked writer is not standalone",
    );
    assert.throws(
      () => deriveBoundaryCandidateSubject(realpathSync(linked)),
      /BOUNDARY_BOOTSTRAP_PATH_IDENTITY_INVALID|BOUNDARY_BOOTSTRAP_GIT_LAYOUT_INVALID/,
      "linked-worktree common/object storage must not become candidate authority",
    );
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
});

test("all parser-backed routes carry bootstrap and candidate bootstrap has no key discovery", () => {
  const bootstrap = readFileSync(join(SOURCE_ROOT, "scripts", "lib", "boundary-bootstrap.mjs"), "utf8");
  const scanner = readFileSync(join(SOURCE_ROOT, "scripts", "lib", "boundary-scan.mjs"), "utf8");
  const scannerSelftest = readFileSync(join(SOURCE_ROOT, "scripts", "lib", "boundary-scan.selftest.mjs"), "utf8");
  const arm = readFileSync(join(SOURCE_ROOT, "scripts", "lib", "boundary-arm.mjs"), "utf8");
  const provenance = readFileSync(
    join(SOURCE_ROOT, "scripts", "lib", "boundary-gate-provenance.mjs"),
    "utf8",
  );
  const lint = readFileSync(join(SOURCE_ROOT, "scripts", "lint-boundary.mjs"), "utf8");
  const rootPackage = JSON.parse(readFileSync(join(SOURCE_ROOT, "package.json"), "utf8"));
  assert.doesNotMatch(bootstrap, /from\s+["']node:os["']/);
  assert.doesNotMatch(bootstrap, /createHmac|\.noa-boundary|KEY_FILE|keyBytes/);
  assert.equal(BOUNDARY_AUTHORITY_CLASS_CANDIDATE_TIER_A, EXPECTED_CANDIDATE_AUTHORITY_CLASS);
  assert.equal(CANDIDATE_TIER_A_NON_AUTHORITY_NON_CLAIM, EXPECTED_CANDIDATE_NON_CLAIM);
  assert.doesNotMatch(scanner, /from\s+["']typescript["']/);
  assert.match(scanner, /await loadTrustedTypeScript/);
  assert.match(lint, /await import\("\.\/lib\/boundary-scan\.mjs"\)/);
  assert.match(lint, /candidateTierANonAuthorityEligible\(opts, argv\)/);
  assert.match(lint, /clearUntrustedBoundaryBootstrapModeMarker\(\)/);
  assert.match(scannerSelftest, /NOA_BOUNDARY_AUTHORIZATION_FD/);
  assert.match(scannerSelftest, /await import\("\.\/boundary-scan\.mjs"\)/);
  assert.match(arm, /from "\.\/boundary-scan\.mjs"/);
  assert.match(arm, /from "\.\/boundary-gate-provenance\.mjs"/);
  assert.match(arm, /boundaryGateProvenance\(boundaryScannerAuthority\)/);
  assert.match(lint, /from "\.\/lib\/boundary-gate-provenance\.mjs"/);
  assert.match(lint, /boundaryGateProvenance\(boundaryBootstrapAuthority/);
  assert.match(provenance, /from "\.\/boundary-bootstrap\.mjs"/);
  assert.match(provenance, /from "\.\/gate-event-contract\.mjs"/);
  assert.match(arm, /const GATE_FILES = Object\.freeze\(reviewedControlGateFiles\(\)\);/);
  assert.match(arm, /return REVIEWED_CONTROL_PATHS/);
  assert.equal(
    rootPackage.scripts["lint:boundary"],
    "node scripts/lint-boundary.mjs --selftest && node scripts/lint-boundary.mjs --repo-visibility-source snapshot --tier a",
  );
  for (const requiredPath of [
    ".github/workflows/boundary.yml",
    "package-lock.json",
    "scripts/boundary-runtime-attestation.json",
    "scripts/hooks/pre-push",
    "scripts/install-hooks.mjs",
    "scripts/lib/boundary-bootstrap.mjs",
    "scripts/lib/boundary-external-authority.mjs",
    "scripts/lib/boundary-gate-provenance.mjs",
    "scripts/lib/knockout-runner.mjs",
    "scripts/lib/knockout-test-observer.mjs",
    "scripts/lib/knockout-workspace-worker.mjs",
    "scripts/lib/knockout-workspace.mjs",
    "scripts/lib/boundary-token.mjs",
    "scripts/lib/proof-event-contract.mjs",
    "scripts/lib/proof-event-reporter.mjs",
    "scripts/lib/proof-resolve.mjs",
    "scripts/lib/publish-artifact-executor.mjs",
    "scripts/lib/typescript-test-hooks.mjs",
    "scripts/lib/typescript-test-register.mjs",
    "scripts/lint-control-knockout.mjs",
    "scripts/prepush-baseline.json",
    "scripts/stage-publish-artifacts.selftest.mjs",
  ]) {
    assert.equal(REVIEWED_CONTROL_PATHS.includes(requiredPath), true, requiredPath);
  }
  assert.deepEqual(
    PREVIOUS_REVIEWED_CONTROL_PATHS,
    [
      "package.json",
      "scripts/boundary-repo-reference-policy.json",
      "scripts/lib/boundary-arm.mjs",
      "scripts/lib/boundary-scan.mjs",
      "scripts/lib/boundary-scan.selftest.mjs",
      "scripts/lint-boundary.mjs",
      "scripts/pre-push-gate.mjs",
    ],
  );

  const work = mkdtempSync(join(tmpdir(), "noa-boundary-supervisor-refusal-"));
  try {
    const environment = {
      ...process.env,
      HOME: join(work, "empty-home"),
    };
    delete environment.NOA_BOUNDARY_AUTHORIZATION_FD;
    delete environment.NOA_BOUNDARY_AUTHORIZATION_FILE;
    delete environment.NOA_BOUNDARY_SYNTHETIC_SUPERVISOR_FIXTURE;
    const reviewMetadata = [
      "--reviewer", "synthetic external supervisor",
      "--reviewed-at", "2026-08-30T00:00:00.000Z",
      "--expires-at", "2026-08-30T00:05:00.000Z",
      "--review-session", REFUSAL_REVIEW_SESSION,
      "--classification", "PUBLIC_DERIVED_COLLISION",
      "--public-artifact", "bootstrap-fixture@0.0.0",
      "--public-artifact-sri", `sha512-${Buffer.alloc(64, 0x45).toString("base64")}`,
    ];
    const privilegedInvocations = [
      ["default Tier AB", []],
      ["explicit Tier AB", ["--tier", "ab", "--repo-visibility-source", "snapshot"]],
      ["live visibility", ["--tier", "a", "--repo-visibility-source", "live"]],
      ["publish path", ["--tier", "a", "--repo-visibility-source", "snapshot", "--publish-path"]],
      ["public snapshot refresh", ["--tier", "a", "--repo-visibility-source", "live", "--refresh-public-repos"]],
      ["token refresh", ["--tier", "a", "--repo-visibility-source", "live", "--refresh-tokens"]],
      ["known-exposure mutation", ["--tier", "a", "--repo-visibility-source", "snapshot", "--tighten-known-exposure"]],
      ["initial migration", ["--migrate-exclusions", ...reviewMetadata]],
      ["recovery", ["--recover-exclusion-rotation"]],
      ["fresh rotation", ["--rotate-exclusions", ...reviewMetadata]],
    ];
    for (const [label, args] of privilegedInvocations) {
      const result = spawnSync(process.execPath, [
        join(SOURCE_ROOT, "scripts", "lint-boundary.mjs"),
        ...args,
        "--knockout-json",
      ], {
        cwd: SOURCE_ROOT,
        encoding: "utf8",
        env: environment,
        shell: false,
      });
      assert.equal(result.status, 2, `${label}: ${result.stdout}\n${result.stderr}`);
      assert.match(result.stdout, /EXTERNAL_BOUNDARY_SUPERVISOR_REQUIRED/, label);
      assert.doesNotMatch(result.stdout, /BOUNDARY_BOOTSTRAP_/, label);
    }
    const closedArgumentInvocations = [
      ["positional", ["unexpected-positional", "--tier", "a", "--repo-visibility-source", "snapshot"], "an unexpected positional argument was supplied", "unexpected-positional"],
      ["unknown flag", ["--tier", "a", "--repo-visibility-source", "snapshot", "--unknown-candidate-flag"], "unknown flag argument:sha256:f5a5d030cde0d2bb952918968d246ce28259e54891bbb53cef33c7d11bf782ee", "--unknown-candidate-flag"],
      ["duplicate tier", ["--tier", "ab", "--tier", "a", "--repo-visibility-source", "snapshot"], "the flag argument:sha256:9eac2b0d2615e9183f64a183622ed12cb35c58bd7ed6ac915273f79111569e5b was supplied more than once", "--tier"],
      ["duplicate visibility", ["--tier", "a", "--repo-visibility-source", "live", "--repo-visibility-source", "snapshot"], "the flag argument:sha256:9b5d614a814c3656a8b502276a1c957e478a99200c00c2b7aa800d8fef67d019 was supplied more than once", "--repo-visibility-source"],
      ["duplicate boolean", ["--tier", "a", "--repo-visibility-source", "snapshot", "--explain", "--explain"], "the flag argument:sha256:5c18beb5e397ee4deed89591b90cfa2142e1b86f17ebfd59077777115e864ed0 was supplied more than once", "--explain"],
    ];
    for (const [label, args, expectedSubject, rejectedCanary] of closedArgumentInvocations) {
      const result = spawnSync(process.execPath, [
        join(SOURCE_ROOT, "scripts", "lint-boundary.mjs"),
        ...args,
        "--knockout-json",
      ], {
        cwd: SOURCE_ROOT,
        encoding: "utf8",
        env: environment,
        shell: false,
      });
      assert.equal(result.status, 2, `${label}: ${result.stdout}\n${result.stderr}`);
      assert.equal(result.stdout.includes(rejectedCanary), false, `${label}: rejected argument leaked to stdout`);
      assert.equal(result.stderr.includes(rejectedCanary), false, `${label}: rejected argument leaked to stderr`);
      const evidence = parseExactMachineEvidence(result, label);
      assert.deepEqual(evidence.findings.map(({ rule, subject }) => ({ rule, subject })), [
        { rule: "SETUP_FAILED", subject: expectedSubject },
      ]);
      assert.deepEqual(evidence.provenance, {
        authorityClass: UNVERIFIED_BOOTSTRAP_AUTHORITY_CLASS,
        authorityNonClaim: UNVERIFIED_BOOTSTRAP_NON_CLAIM,
        bootstrapMode: null,
        controlManifestDigest: null,
        controlManifestVersion: null,
        externalAuthorizationSha256: null,
        schemaVersion: 1,
        subject: null,
        tier: null,
        verification: "UNVERIFIED_BOOTSTRAP",
        visibilitySource: null,
      });
      assert.doesNotMatch(result.stdout, /BOUNDARY_BOOTSTRAP_/, label);
    }
    const disallowedCandidateFlag = spawnSync(process.execPath, [
      join(SOURCE_ROOT, "scripts", "lint-boundary.mjs"),
      "--tier", "a",
      "--repo-visibility-source", "snapshot",
      "--packed",
      "--knockout-json",
    ], {
      cwd: SOURCE_ROOT,
      encoding: "utf8",
      env: environment,
      shell: false,
    });
    assert.equal(disallowedCandidateFlag.status, 2, `${disallowedCandidateFlag.stdout}\n${disallowedCandidateFlag.stderr}`);
    const disallowedEvidence = parseExactMachineEvidence(disallowedCandidateFlag, "packed candidate classification");
    assert.deepEqual(disallowedEvidence.findings.map(({ rule, subject }) => ({ rule, subject })), [
      { rule: "SETUP_FAILED", subject: "EXTERNAL_BOUNDARY_SUPERVISOR_REQUIRED" },
    ]);
    assert.equal(disallowedEvidence.provenance.verification, "UNVERIFIED_BOOTSTRAP");
    assert.equal(disallowedEvidence.provenance.tier, "a");
    assert.equal(disallowedEvidence.provenance.visibilitySource, "snapshot");

    const externalWork = join(work, "external-tier-ab");
    const externalRoot = buildFixture(externalWork);
    const externalAuthorization = authorizationFor(externalRoot);
    const externalAuthorizationPath = publicAuthorizationFile(
      externalWork,
      externalAuthorization.authorizationBytes,
    );
    const sentinelPath = join(externalWork, "PARSER_TOP_LEVEL_EXECUTED");
    const parserPath = join(externalRoot, "node_modules", "typescript", "lib", "typescript.js");
    writeFileSync(
      parserPath,
      `require("node:fs").writeFileSync(process.env.NOA_BOUNDARY_SENTINEL_PATH,"EXECUTED");\n${readFileSync(parserPath, "utf8")}`,
    );
    const externalPrivileged = spawnSync(process.execPath, [
      join(externalRoot, "scripts", "lint-boundary.mjs"),
      "--tier", "ab",
      "--repo-visibility-source", "snapshot",
      "--knockout-json",
    ], {
      cwd: externalRoot,
      encoding: "utf8",
      env: {
        ...environment,
        HOME: join(externalWork, "empty-home"),
        NOA_BOUNDARY_AUTHORIZATION_FILE: externalAuthorizationPath,
        NOA_BOUNDARY_SENTINEL_PATH: sentinelPath,
      },
      shell: false,
    });
    assert.equal(externalPrivileged.status, 2, `${externalPrivileged.stdout}\n${externalPrivileged.stderr}`);
    const externalPrivilegedEvidence = parseExactMachineEvidence(
      externalPrivileged,
      "external transport privileged refusal",
    );
    assert.deepEqual(externalPrivilegedEvidence.findings.map(({ rule, subject }) => ({ rule, subject })), [
      { rule: "SETUP_FAILED", subject: "EXTERNAL_BOUNDARY_SUPERVISOR_REQUIRED" },
    ]);
    assert.equal(externalPrivilegedEvidence.provenance.verification, "UNVERIFIED_BOOTSTRAP");
    assert.doesNotMatch(externalPrivileged.stdout, /BOUNDARY_BOOTSTRAP_/);
    assert.equal(existsSync(sentinelPath), false, "external privileged route imported parser before supervisor refusal");

    const injectedEnvironment = {
      ...environment,
      NOA_BOUNDARY_INTERNAL_BOOTSTRAP_MODE: "CANDIDATE_TIER_A_NON_AUTHORITY",
    };
    const injected = spawnSync(process.execPath, [
      join(SOURCE_ROOT, "scripts", "lint-boundary.mjs"),
      "--tier", "ab",
      "--repo-visibility-source", "snapshot",
      "--knockout-json",
    ], {
      cwd: SOURCE_ROOT,
      encoding: "utf8",
      env: injectedEnvironment,
      shell: false,
    });
    assert.equal(injected.status, 2, `${injected.stdout}\n${injected.stderr}`);
    assert.match(injected.stdout, /EXTERNAL_BOUNDARY_SUPERVISOR_REQUIRED/);
    assert.doesNotMatch(injected.stdout, /BOUNDARY_BOOTSTRAP_/);
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
});

test("baseline, hook, and exact hooksPath are mandatory release-call closure", async () => {
  const work = mkdtempSync(join(tmpdir(), "noa-boundary-bootstrap-hook-"));
  try {
    const root = buildFixture(work);
    const bootstrap = await import(pathToFileURL(join(root, "scripts", "lib", "boundary-bootstrap.mjs")).href);
    assert.equal(bootstrap.verifyBoundaryHookActivation(root).hooksPath, "scripts/hooks");
    git(root, ["config", "core.hooksPath", "scripts/hooks "]);
    assert.throws(() => bootstrap.verifyBoundaryHookActivation(root), /BOUNDARY_BOOTSTRAP_HOOKS_PATH_MISMATCH/);
    git(root, ["config", "core.hooksPath", ".git/hooks"]);
    assert.throws(() => bootstrap.verifyBoundaryHookActivation(root), /BOUNDARY_BOOTSTRAP_HOOKS_PATH_MISMATCH/);
    git(root, ["config", "core.hooksPath", "scripts/hooks"]);
    rmSync(join(root, "scripts", "hooks", "pre-push"));
    assert.throws(() => bootstrap.verifyBoundaryHookActivation(root), /BOUNDARY_BOOTSTRAP_PATH_MISSING/);
    copyExact(join(SOURCE_ROOT, "scripts", "hooks", "pre-push"), join(root, "scripts", "hooks", "pre-push"));
    rmSync(join(root, "scripts", "prepush-baseline.json"));
    assert.throws(() => bootstrap.deriveBoundaryControlManifest(root), /BOUNDARY_BOOTSTRAP_PATH_MISSING/);
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
});
