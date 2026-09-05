#!/usr/bin/env node

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  chmodSync,
  existsSync,
  linkSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { gunzipSync, gzipSync } from "node:zlib";
import { dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import {
  CANDIDATE_STATUS,
  closedGitEnvForSelftest,
  EXPECTED_HOST_NODE,
  EXPECTED_NODE,
  EXPECTED_NPM,
  EXPECTED_PACK_STACK,
  MANIFEST_SCHEMA,
  NODE_IMAGE,
  OFFLINE_CACHE_LIMITS,
  PUBLISH_TOOLCHAIN_CONTRACT,
  SetupFailure,
  ValidationFailure,
  createDockerRunArgs,
  cleanupExactDockerContainerForSelftest,
  derivePackageInventory,
  digestRealTree,
  loadGitSource,
  loadPublishArtifactPolicy,
  materializeCandidateOutputForSelftest,
  materializeExactControllerForSelftest,
  parseGitLsTree,
  packFrozenPackageArtifact,
  planReleaseManifests,
  snapshotOfflineCacheForSelftest,
  validatePublicPackageMetadata,
  validateDockerRunArgs,
  validateRepositoryPath,
  verifyCandidateSetForSelftest,
  verifyMaterializedGitSource,
  ensureNoContainerResidue,
  withOwnedScratchPairForSelftest,
} from "./lib/publish-artifact-staging.mjs";
import { PUBLISH_CONTAINER_TOOLCHAIN } from "./lib/publish-container-driver.mjs";
import { canonicalJson, readSafeNpmTarball, readSafeNpmTarballBytes, readSafeNpmTarballBytesForSelftest, sha256Hex } from "./lib/safe-npm-tarball.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..");
const DRIVER = join(HERE, "lib", "publish-container-driver.mjs");
const EXECUTOR_CLI = join(HERE, "lib", "publish-artifact-executor.mjs");
const NPM_HOMEDIR_OVERRIDE = join(HERE, "lib", "npm-homedir-override.cjs");
const STAGING_CLI = join(HERE, "lib", "stage-publish-artifacts.mjs");
const SURFACE_LINTER = join(HERE, "lint-published-surface.mjs");
const PUBLIC_REPOS = join(HERE, "boundary-public-repos.json");
const PUBLISH_WORKFLOW = join(REPO_ROOT, ".github", "workflows", "publish-surface-lint.yml");
const RUNTIME_ATTESTATION = join(HERE, "boundary-runtime-attestation.json");
const NODE_VERSION_FILE = join(REPO_ROOT, ".node-version");
const DOCKER_CANDIDATES = [
  "/Applications/Docker.app/Contents/Resources/bin/docker",
  "/usr/local/bin/docker",
  "/usr/bin/docker",
];
const TEST_ROOT = mkdtempSync(join(tmpdir(), "noa-publish-artifact-selftest-"));
let checks = 0;
const FIXTURE_NOTICE_TITLE = "NOA Fixture — public package metadata fixture";
const FIXTURE_MANIFEST_POLICY = Object.freeze({
  enginesNode: ">=20",
  homepage: "https://noatrust.com",
  license: "Apache-2.0",
  provenanceRequired: true,
});
const EXPECTED_PUBLISH_SURFACE_SCRIPT = "node scripts/lib/stage-publish-artifacts.mjs --verify";
const EXPECTED_PUBLISH_SURFACE_SELFTEST_SCRIPT = "node scripts/lint-published-surface.mjs --selftest";
const EXPECTED_PREPUBLISH_REFUSAL = String.raw`node -e "process.stderr.write('RELEASE_FROZEN: direct mutable-directory publication is disabled. Only a separately governed controller may verify and publish immutable tarball bytes; this hook grants no release authority.\n'); process.exit(1)"`;
const EXPECTED_TOOLCHAIN_CONTRACT = Object.freeze({
  image:
    "docker.io/library/node@sha256:62e4daa6819762bbd3072af77cc282ab72c631c4aed30dd7980192babaf385b3",
  node: "22.22.2",
  npm: "10.9.7",
  packStack: Object.freeze({
    arborist: "8.0.4",
    npmPacklist: "9.0.0",
    tar: "7.5.11",
  }),
});
function check(name, fn) {
  fn();
  checks++;
  process.stdout.write(`PASS ${checks}: ${name}\n`);
}

function singleCapture(source, pattern, label) {
  const matches = [...source.matchAll(pattern)];
  assert.equal(matches.length, 1, `${label} must occur exactly once`);
  return matches[0][1];
}

function expectValidation(fn, pattern) {
  assert.throws(fn, (error) => error instanceof ValidationFailure && pattern.test(error.message));
}

function fixtureGit(cwd, args) {
  const result = spawnSync("/usr/bin/git", args, { cwd, encoding: "utf8" });
  assert.equal(result.status, 0, `${args.join(" ")}\n${result.stdout}${result.stderr}`);
  return result.stdout.trim();
}

function tarOctal(buffer, offset, length, value) {
  const raw = value.toString(8).padStart(length - 1, "0");
  buffer.write(raw, offset, length - 1, "ascii");
  buffer[offset + length - 1] = 0;
}

function tarString(buffer, offset, length, value) {
  const bytes = Buffer.from(value, "utf8");
  assert.ok(bytes.length < length, `test tar field too long: ${value}`);
  bytes.copy(buffer, offset);
}

function tarHeader({ link = "", mode = 0o644, path, size, type = "0" }) {
  const header = Buffer.alloc(512);
  tarString(header, 0, 100, path);
  tarOctal(header, 100, 8, mode);
  tarOctal(header, 108, 8, 0);
  tarOctal(header, 116, 8, 0);
  tarOctal(header, 124, 12, size);
  tarOctal(header, 136, 12, 499_162_500);
  header.fill(0x20, 148, 156);
  header[156] = type.charCodeAt(0);
  tarString(header, 157, 100, link);
  Buffer.from([0x75, 0x73, 0x74, 0x61, 0x72, 0x00]).copy(header, 257);
  Buffer.from("00", "ascii").copy(header, 263);
  tarOctal(header, 329, 8, 0);
  tarOctal(header, 337, 8, 0);
  let checksum = 0;
  for (const byte of header) checksum += byte;
  const checksumRaw = checksum.toString(8).padStart(6, "0");
  header.write(checksumRaw, 148, 6, "ascii");
  header[154] = 0;
  header[155] = 0x20;
  return header;
}

function canonicalGzip(raw) {
  const compressed = gzipSync(raw, { level: 9 });
  compressed[9] = 0xff;
  return compressed;
}

function createTarball(path, entries) {
  const chunks = [];
  for (const entry of entries) {
    const content = Buffer.from(entry.content ?? "", "utf8");
    chunks.push(tarHeader({ ...entry, size: content.length }), content);
    const padding = Math.ceil(content.length / 512) * 512 - content.length;
    if (padding > 0) chunks.push(Buffer.alloc(padding));
  }
  chunks.push(Buffer.alloc(1024));
  writeFileSync(path, canonicalGzip(Buffer.concat(chunks)));
  return readSafeNpmTarball(path);
}

function rewriteTarChecksum(header) {
  header.fill(0x20, 148, 156);
  let checksum = 0;
  for (const byte of header) checksum += byte;
  header.write(checksum.toString(8).padStart(6, "0"), 148, 6, "ascii");
  header[154] = 0;
  header[155] = 0x20;
}

function withTarHeaderMetadata(compressed, start, width, value) {
  const raw = gunzipSync(compressed);
  const header = raw.subarray(0, 512);
  header.fill(0, start, start + width);
  Buffer.from(value, "utf8").copy(header, start);
  rewriteTarChecksum(header);
  return { compressed: canonicalGzip(raw), raw };
}

function withGzipOptionalMetadata(compressed, flag, value) {
  const header = Buffer.from(compressed.subarray(0, 10));
  header[3] |= flag;
  return Buffer.concat([header, Buffer.from(`${value}\0`, "utf8"), compressed.subarray(10)]);
}

function minimalPackageEntries(extra = []) {
  return [
    { path: "package/package.json", content: `${JSON.stringify(fixtureManifest())}\n` },
    { path: "package/LICENSE", content: "Apache-2.0 fixture license.\n" },
    { path: "package/NOTICE", content: `${FIXTURE_NOTICE_TITLE}\n` },
    ...extra,
  ];
}

function fixtureManifest(overrides = {}) {
  return {
    name: "noa-fixture",
    version: "1.0.0",
    engines: { node: ">=20" },
    exports: { ".": "./dist/src/index.js" },
    files: ["dist/src", "README.md", "LICENSE", "NOTICE"],
    homepage: "https://noatrust.com",
    keywords: ["fixture", "governance", "provenance"],
    license: "Apache-2.0",
    main: "dist/src/index.js",
    publishConfig: { access: "public", provenance: true },
    ...overrides,
  };
}

function fakeGitSource(manifests, extras = [], modes = {}) {
  const blobs = new Map();
  for (const [path, manifest] of Object.entries(manifests)) {
    blobs.set(path, Buffer.from(typeof manifest === "string" ? manifest : `${JSON.stringify(manifest)}\n`));
  }
  for (const [path, content] of extras) blobs.set(path, Buffer.from(content));
  const records = [...blobs.entries()].map(([path, bytes]) => ({
    mode: modes[path] ?? "100644",
    oid: createHash("sha1").update(`blob ${bytes.length}\0`).update(bytes).digest("hex"),
    path,
    size: bytes.length,
  })).sort((left, right) => Buffer.from(left.path).compare(Buffer.from(right.path)));
  const inventoryRows = records.map(({ mode, oid, path, size }) => ({ mode, oid, path, size }));
  return {
    blobs,
    commit: "a".repeat(40),
    commitTime: 0,
    inventoryDigest: sha256Hex(Buffer.from(canonicalJson(inventoryRows))),
    objectFormat: "sha1",
    records,
    tree: "b".repeat(40),
  };
}

function writeCandidateSet(root, mutate = () => {}) {
  mkdirSync(root);
  const offlineCache = join(
    TEST_ROOT,
    `fixture-offline-cache-${randomBytes(6).toString("hex")}`,
  );
  mkdirSync(offlineCache);
  writeFileSync(join(offlineCache, "cache-entry"), "fixture dependency cache bytes\n");
  const cacheEvidence = digestRealTree(offlineCache);
  const tarballPath = join(root, "noa-fixture-1.0.0.tgz");
  const buildContent = "export const fixture = 1;\n";
  const parsed = createTarball(tarballPath, minimalPackageEntries([
    { path: "package/README.md", content: "A modest fixture.\n" },
    { path: "package/dist/src/index.js", content: buildContent },
  ]));
  const packageJson = parsed.entries.find((entry) => entry.path === "package.json");
  const buildEntry = parsed.entries.find((entry) => entry.path === "dist/src/index.js");
  const gitSource = fakeGitSource({
    "package.json": fixtureManifest(),
  }, [
    ["LICENSE", "Apache-2.0 fixture license.\n"],
    ["NOTICE", `${FIXTURE_NOTICE_TITLE}\n`],
    ["README.md", "A modest fixture.\n"],
  ]);
  const sourceManifest = gitSource.records.find((entry) => entry.path === "package.json");
  const paths = parsed.entries.map((entry) => entry.path);
  const pathSetSha256 = sha256Hex(Buffer.from(canonicalJson(paths)));
  const policy = {
    allowedBuildOutputPrefixes: ["dist/src/"],
    manifestPolicy: { ...FIXTURE_MANIFEST_POLICY },
    packages: [{
      name: "noa-fixture",
      noticeTitle: FIXTURE_NOTICE_TITLE,
      packagePath: ".",
      pathCount: paths.length,
      pathSetSha256,
    }],
    schema: "noa.publish-artifact-policy/2",
    sha256: "5".repeat(64),
  };
  const buildOutput = {
    mode: "100644",
    path: "dist/src/index.js",
    sha256: buildEntry.sha256,
    size: buildEntry.size,
  };
  const independentBuildOutputs = [{ ...buildOutput }];
  const frozenRows = gitSource.records.map((record) => ({
    mode: record.mode,
    path: record.path,
    sha256: sha256Hex(gitSource.blobs.get(record.path)),
    size: record.size,
  }));
  frozenRows.push(buildOutput);
  frozenRows.sort((left, right) => Buffer.from(left.path).compare(Buffer.from(right.path)));
  const artifact = {
    compressedSize: parsed.compressedSize,
    filename: "noa-fixture-1.0.0.tgz",
    name: "noa-fixture",
    packlistCount: parsed.packlistCount,
    packlistDigest: parsed.packlistDigest,
    packlistSize: parsed.packlistSize,
    packagePath: ".",
    pathSetSha256,
    releaseManifestSha256: sha256Hex(packageJson.content),
    sourceManifestGitOid: sourceManifest.oid,
    sourceManifestSha256: sha256Hex(packageJson.content),
    surfaceLinterSha256: sha256Hex(readFileSync(SURFACE_LINTER)),
    tarballSha256: parsed.tarballSha256,
    transformations: [],
    uncompressedSize: parsed.uncompressedSize,
    version: "1.0.0",
  };
  const manifest = {
    build: {
      dependencyInput: {
        count: cacheEvidence.count,
        sha256: cacheEvidence.digest,
        size: cacheEvidence.size,
      },
      network: "offline",
      outputs: [buildOutput],
      tsconfigs: ["tsconfig.json", "packages/approval-artifacts/tsconfig.json"],
    },
    controller: {
      driverSha256: sha256Hex(readFileSync(DRIVER)),
      image: NODE_IMAGE,
      node: EXPECTED_NODE,
      npm: EXPECTED_NPM,
      packStack: EXPECTED_PACK_STACK,
      platform: platform(),
    },
    frozenSnapshot: {
      fileCount: frozenRows.length,
      sha256: sha256Hex(Buffer.from(canonicalJson(frozenRows))),
      size: frozenRows.reduce((sum, row) => sum + row.size, 0),
    },
    packages: [artifact],
    policy: {
      path: "scripts/lib/publish-artifact-policy.json",
      schema: policy.schema,
      sha256: policy.sha256,
    },
    releaseAuthorized: false,
    schema: MANIFEST_SCHEMA,
    source: {
      commit: gitSource.commit,
      commitTime: gitSource.commitTime,
      fileCount: gitSource.records.length,
      inventorySha256: gitSource.inventoryDigest,
      objectFormat: gitSource.objectFormat,
      tree: gitSource.tree,
    },
    status: CANDIDATE_STATUS,
  };
  mutate(manifest, tarballPath, {
    frozenRows,
    gitSource,
    independentBuildOutputs,
    offlineCache,
    policy,
  });
  const bytes = Buffer.from(canonicalJson(manifest));
  writeFileSync(join(root, "publish-artifacts.manifest.json"), bytes);
  writeFileSync(join(root, "publish-artifacts.manifest.sha256"), `${sha256Hex(bytes)}\n`);
  writeFileSync(
    join(root, "CANDIDATE-NON-RELEASE.txt"),
    `${CANDIDATE_STATUS}\nThese tarballs are not authorized for publication or release.\n`,
  );
  return { gitSource, independentBuildOutputs, manifest, offlineCache, policy, tarballPath };
}

function verifyFixtureCandidate(root, fixture) {
  return verifyCandidateSetForSelftest(
    root,
    {
      gitSource: fixture.gitSource,
      independentBuildOutputs: fixture.independentBuildOutputs,
      offlineCache: fixture.offlineCache,
    },
    fixture.policy,
  );
}

function resolveDocker() {
  for (const path of DOCKER_CANDIDATES) if (existsSync(path)) return path;
  throw new SetupFailure("Docker executable is unavailable for the containment selftest");
}

function platform() {
  if (process.arch === "arm64") return "linux/arm64";
  if (process.arch === "x64") return "linux/amd64";
  throw new SetupFailure(`unsupported selftest architecture ${process.arch}`);
}

function runDocker(docker, args, name) {
  let result;
  try {
    result = spawnSync(docker, args, { encoding: "utf8", maxBuffer: 32 * 1024 * 1024 });
    if (result.error) throw new SetupFailure(`Docker selftest could not start: ${result.error.message}`);
    if (result.status !== 0) {
      throw new Error(
        `Docker selftest failed ${result.status}: stdout=${JSON.stringify(result.stdout)} stderr=${JSON.stringify(result.stderr)}`,
      );
    }
    return result;
  } finally {
    ensureNoContainerResidue(docker, name);
  }
}

function writeLifecyclePackage(root, manifest) {
  mkdirSync(root, { recursive: true });
  writeFileSync(join(root, "package.json"), `${JSON.stringify(manifest, null, 2)}\n`);
}

function setTreeWritable(root, writable) {
  const visit = (path) => {
    const stat = lstatSync(path);
    if (stat.isDirectory()) {
      if (writable) chmodSync(path, 0o700);
      for (const entry of readdirSync(path)) visit(join(path, entry));
      if (!writable) chmodSync(path, 0o555);
    } else chmodSync(path, writable ? 0o600 : (stat.mode & 0o111) !== 0 ? 0o555 : 0o444);
  };
  visit(root);
}

try {
  check("workflow, staging, driver, runtime attestation, and real image share one exact toolchain contract", () => {
    assert.deepEqual(PUBLISH_TOOLCHAIN_CONTRACT, PUBLISH_CONTAINER_TOOLCHAIN);
    assert.deepEqual(PUBLISH_TOOLCHAIN_CONTRACT, EXPECTED_TOOLCHAIN_CONTRACT);
    assert.equal(NODE_IMAGE, EXPECTED_TOOLCHAIN_CONTRACT.image);
    assert.equal(EXPECTED_HOST_NODE, EXPECTED_TOOLCHAIN_CONTRACT.node);
    assert.equal(EXPECTED_NODE, EXPECTED_TOOLCHAIN_CONTRACT.node);
    assert.equal(EXPECTED_NPM, EXPECTED_TOOLCHAIN_CONTRACT.npm);
    assert.deepEqual(EXPECTED_PACK_STACK, EXPECTED_TOOLCHAIN_CONTRACT.packStack);

    const workflow = readFileSync(PUBLISH_WORKFLOW, "utf8");
    assert.equal(
      singleCapture(workflow, /^\s*node-version:\s*([^\s#]+)\s*$/gmu, "workflow Node version"),
      EXPECTED_TOOLCHAIN_CONTRACT.node,
    );
    assert.equal(
      singleCapture(workflow, /^\s*image='([^']+)'\s*$/gmu, "workflow image"),
      EXPECTED_TOOLCHAIN_CONTRACT.image,
    );
    const runtimeAttestation = JSON.parse(readFileSync(RUNTIME_ATTESTATION, "utf8"));
    assert.equal(runtimeAttestation.node.version, EXPECTED_TOOLCHAIN_CONTRACT.node);
    assert.equal(readFileSync(NODE_VERSION_FILE, "utf8").trim(), EXPECTED_TOOLCHAIN_CONTRACT.node);

    const docker = resolveDocker();
    const name = `noa-toolchain-parity-${process.pid}-${randomBytes(4).toString("hex")}`;
    const probeSource = String.raw`
      const { createRequire } = require("node:module");
      const { readFileSync } = require("node:fs");
      const fromNpm = createRequire("/usr/local/lib/node_modules/npm/package.json");
      const observed = {
        node: process.version.slice(1),
        npm: JSON.parse(readFileSync("/usr/local/lib/node_modules/npm/package.json", "utf8")).version,
        packStack: {
          arborist: fromNpm("@npmcli/arborist/package.json").version,
          npmPacklist: fromNpm("npm-packlist/package.json").version,
          tar: fromNpm("tar/package.json").version,
        },
      };
      process.stdout.write(JSON.stringify(observed));
    `;
    const probe = runDocker(docker, [
      "run", "--rm", "--name", name, "--pull=never", `--platform=${platform()}`,
      "--network=none", "--cap-drop=ALL", "--security-opt=no-new-privileges",
      "--read-only", "--pids-limit=64", "--memory=256m", "--memory-swap=256m",
      "--cpus=1", "--entrypoint=node", NODE_IMAGE, "-e", probeSource,
    ], name);
    assert.deepEqual(JSON.parse(probe.stdout), {
      node: EXPECTED_TOOLCHAIN_CONTRACT.node,
      npm: EXPECTED_TOOLCHAIN_CONTRACT.npm,
      packStack: EXPECTED_TOOLCHAIN_CONTRACT.packStack,
    });
  });

  check("safe tarball parser accepts one canonical npm package", () => {
    const parsed = createTarball(join(TEST_ROOT, "valid.tgz"), minimalPackageEntries());
    assert.equal(parsed.packlistCount, 3);
  });

  for (const [name, entry, pattern] of [
    ["traversal", { path: "package/../escape", content: "x" }, /not canonical/u],
    ["absolute path", { path: "/package/escape", content: "x" }, /unsafe tar entry path/u],
    ["symbolic link", { path: "package/link", type: "2", link: "target" }, /type 2 is forbidden/u],
    ["PAX extended header", { path: "package/pax", type: "x" }, /type x is forbidden/u],
    ["hard link", { path: "package/link", type: "1", link: "package/package.json" }, /type 1 is forbidden/u],
    ["FIFO", { path: "package/pipe", type: "6" }, /type 6 is forbidden/u],
    ["character device", { path: "package/device", type: "3" }, /type 3 is forbidden/u],
    ["setuid permission", { path: "package/setuid", mode: 0o4755, content: "x" }, /special permission bits/u],
  ]) {
    check(`safe tarball parser rejects ${name}`, () => {
      const path = join(TEST_ROOT, `${name.replaceAll(" ", "-")}.tgz`);
      assert.throws(
        () => createTarball(path, minimalPackageEntries([entry])),
        pattern,
      );
    });
  }

  check("safe tarball parser rejects duplicate archive paths", () => {
    const path = join(TEST_ROOT, "duplicate.tgz");
    assert.throws(
      () => createTarball(path, minimalPackageEntries([
        { path: "package/package.json", content: "{}\n" },
      ])),
      /duplicate tar entry/u,
    );
  });

  check("safe tarball parser rejects a bad checksum", () => {
    const path = join(TEST_ROOT, "bad-checksum.tgz");
    createTarball(path, minimalPackageEntries());
    const compressed = readFileSync(path);
    const raw = gunzipSync(compressed);
    raw[0] ^= 1;
    writeFileSync(path, canonicalGzip(raw));
    assert.throws(() => readSafeNpmTarball(path), /checksum mismatch/u);
  });

  for (const [name, start, width] of [
    ["tar uname", 265, 32],
    ["tar gname", 297, 32],
  ]) {
    check(`safe tarball parser rejects same-packlist ${name} metadata`, () => {
      const path = join(TEST_ROOT, `${name.replaceAll(" ", "-")}.tgz`);
      createTarball(path, minimalPackageEntries());
      const original = readFileSync(path);
      const altered = withTarHeaderMetadata(original, start, width, "fixture-owner");
      // Only the outer header/checksum changes: retained package payload bytes stay identical.
      assert.equal(altered.raw.subarray(512).equals(gunzipSync(original).subarray(512)), true);
      writeFileSync(path, altered.compressed);
      assert.throws(() => readSafeNpmTarball(path), /owner-name metadata/u);
    });
  }

  check("safe tarball parser rejects same-packlist tar mtime metadata", () => {
    const path = join(TEST_ROOT, "tar-mtime.tgz");
    createTarball(path, minimalPackageEntries());
    const original = readFileSync(path);
    const altered = withTarHeaderMetadata(original, 136, 12, "00000000001");
    assert.equal(altered.raw.subarray(512).equals(gunzipSync(original).subarray(512)), true);
    writeFileSync(path, altered.compressed);
    assert.throws(() => readSafeNpmTarball(path), /timestamp metadata/u);
  });

  for (const [name, flag] of [["gzip FNAME", 0x08], ["gzip FCOMMENT", 0x10]]) {
    check(`safe tarball parser rejects same-packlist ${name} metadata`, () => {
      const path = join(TEST_ROOT, `${name.replaceAll(" ", "-")}.tgz`);
      createTarball(path, minimalPackageEntries());
      const original = readFileSync(path);
      writeFileSync(path, withGzipOptionalMetadata(original, flag, "fixture-metadata"));
      assert.throws(() => readSafeNpmTarball(path), /forbidden optional header metadata/u);
    });
  }

  check("safe tarball parser rejects every appended gzip member and raw suffix", () => {
    const path = join(TEST_ROOT, "single-gzip-member.tgz");
    createTarball(path, minimalPackageEntries());
    const original = readFileSync(path);
    const syntheticCarrier = "https://github.com/exampleorg/hidden-one";
    const cases = [
      ["second canonical member", canonicalGzip(Buffer.alloc(0))],
      ["second FNAME member", withGzipOptionalMetadata(canonicalGzip(Buffer.alloc(0)), 0x08, syntheticCarrier)],
      ["second FCOMMENT member", withGzipOptionalMetadata(canonicalGzip(Buffer.alloc(0)), 0x10, syntheticCarrier)],
      ["raw suffix", Buffer.from(syntheticCarrier, "utf8")],
    ];
    for (const [, suffix] of cases) {
      const candidate = Buffer.concat([original, suffix]);
      assert.equal(candidate.includes(Buffer.from(syntheticCarrier, "utf8")), suffix !== cases[0][1]);
      assert.throws(
        () => readSafeNpmTarballBytes(candidate),
        /exactly one canonical member with no trailing bytes/u,
      );
    }
  });

  check("Node-20 gzip trailer fallback validates a single framed member", () => {
    const path = join(TEST_ROOT, "single-gzip-member-node20-fallback.tgz");
    createTarball(path, minimalPackageEntries());
    const original = readFileSync(path);
    assert.equal(readSafeNpmTarballBytesForSelftest(original, { crc32: undefined }).packlistCount, 3);
    const corruptTrailer = Buffer.from(original);
    corruptTrailer[corruptTrailer.length - 8] ^= 0x01;
    assert.throws(
      () => readSafeNpmTarballBytesForSelftest(corruptTrailer, { crc32: undefined }),
      /trailer CRC32 or size is invalid/u,
    );
  });

  check("safe tarball parser rejects a symlink masquerading as a tarball", () => {
    const real = join(TEST_ROOT, "real-tarball.tgz");
    createTarball(real, minimalPackageEntries());
    const link = join(TEST_ROOT, "linked-tarball.tgz");
    symlinkSync(real, link);
    assert.throws(() => readSafeNpmTarball(link), /real regular file/u);
  });

  check("safe tarball parser rejects a hard-linked tarball alias", () => {
    const real = join(TEST_ROOT, "single-link-tarball.tgz");
    createTarball(real, minimalPackageEntries());
    const alias = join(TEST_ROOT, "hard-linked-tarball.tgz");
    linkSync(real, alias);
    assert.throws(() => readSafeNpmTarball(real), /exactly one hard link/u);
    assert.throws(() => readSafeNpmTarball(alias), /exactly one hard link/u);
  });

  check("repository paths reject empty, LF, CR, traversal, and backslash", () => {
    for (const path of ["", "line\nfeed", "carriage\rreturn", "../escape", "a\\b"]) {
      expectValidation(() => validateRepositoryPath(path), /unsafe/u);
    }
  });

  check("workflow-command-like Git paths remain data and one physical JSON line", () => {
    const path = "packages/::error file=fake::not-a-command/package.json";
    assert.equal(validateRepositoryPath(path), path);
    assert.equal(/[\r\n]/u.test(JSON.stringify({ path })), false);
  });

  check("Git inventory rejects duplicate paths and symlink entries", () => {
    const oid = "a".repeat(40);
    const duplicate = Buffer.concat([
      Buffer.from(`100644 blob ${oid} 2\tpackage.json`, "utf8"),
      Buffer.from([0]),
      Buffer.from(`100644 blob ${oid} 2\tpackage.json`, "utf8"),
      Buffer.from([0]),
    ]);
    expectValidation(() => parseGitLsTree(duplicate, "sha1"), /duplicate Git path/u);
    const symlink = Buffer.concat([
      Buffer.from(`120000 blob ${oid} 4\tpackages/linked`, "utf8"),
      Buffer.from([0]),
    ]);
    expectValidation(() => parseGitLsTree(symlink, "sha1"), /forbidden non-regular/u);
  });

  check("Git inventory rejects a regular file directly under packages", () => {
    const source = fakeGitSource(
      { "package.json": { name: "noa-root", version: "1.0.0" } },
      [["packages/README.md", "unexpected\n"]],
    );
    expectValidation(() => derivePackageInventory(source), /non-directory root entry/u);
  });

  check("materialized source verification rejects a Git inventory byte mismatch", () => {
    const root = join(TEST_ROOT, "git-inventory-mismatch");
    mkdirSync(root);
    const bytes = Buffer.from("expected\n");
    writeFileSync(join(root, "package.json"), "attacker\n");
    const oid = createHash("sha1").update(`blob ${bytes.length}\0`).update(bytes).digest("hex");
    const source = {
      blobs: new Map([["package.json", bytes]]),
      objectFormat: "sha1",
      records: [{ mode: "100644", oid, path: "package.json", size: bytes.length }],
    };
    expectValidation(() => verifyMaterializedGitSource(source, root), /bytes mismatch/u);
  });

  check("publishable inventory is exact and excludes only explicit private packages", () => {
    const source = fakeGitSource({
      "package.json": { name: "noa-root", version: "1.0.0" },
      "packages/a/package.json": { name: "noa-a", version: "1.0.0" },
      "packages/private/package.json": { name: "noa-private", private: true, version: "1.0.0" },
    });
    assert.deepEqual(derivePackageInventory(source).map((entry) => entry.name), ["noa-root", "noa-a"]);
  });

  check("private package inventory rejects contradictory public publish intent", () => {
    const source = fakeGitSource({
      "package.json": { name: "noa-root", version: "1.0.0" },
      "packages/private/package.json": {
        name: "noa-private",
        private: true,
        publishConfig: { access: "public" },
        version: "1.0.0",
      },
    });
    expectValidation(() => derivePackageInventory(source), /contradictory public publish access/u);
  });

  check("inventory rejects duplicate package names/identities", () => {
    const source = fakeGitSource({
      "package.json": { name: "noa-root", version: "1.0.0" },
      "packages/a/package.json": { name: "noa-same", version: "1.0.0" },
      "packages/b/package.json": { name: "noa-same", version: "2.0.0" },
    });
    expectValidation(() => derivePackageInventory(source), /duplicate public package name/u);
  });

  check("public-package metadata contract rejects every previously escaped identity field", () => {
    const policy = {
      allowedBuildOutputPrefixes: ["dist/src/"],
      manifestPolicy: { ...FIXTURE_MANIFEST_POLICY },
      packages: [{
        name: "noa-fixture",
        noticeTitle: FIXTURE_NOTICE_TITLE,
        packagePath: ".",
        pathCount: 1,
        pathSetSha256: "0".repeat(64),
      }],
      schema: "noa.publish-artifact-policy/2",
    };
    const sourceFor = (overrides = {}, noticeTitle = FIXTURE_NOTICE_TITLE) => fakeGitSource(
      { "package.json": fixtureManifest(overrides) },
      [
        ["LICENSE", "Apache-2.0 fixture license.\n"],
        ["NOTICE", `${noticeTitle}\n`],
        ["README.md", "A modest fixture.\n"],
      ],
    );
    const validate = (overrides, noticeTitle) => {
      const source = sourceFor(overrides, noticeTitle);
      validatePublicPackageMetadata(planReleaseManifests(derivePackageInventory(source)), policy, source);
    };
    assert.doesNotThrow(() => validate({}));
    for (const [overrides, noticeTitle, pattern] of [
      [{ license: "MIT" }, FIXTURE_NOTICE_TITLE, /license/u],
      [{ homepage: "https://example.invalid" }, FIXTURE_NOTICE_TITLE, /homepage/u],
      [{ publishConfig: { access: "public", provenance: false } }, FIXTURE_NOTICE_TITLE, /publishConfig/u],
      [{ engines: { node: ">=18" } }, FIXTURE_NOTICE_TITLE, /Node engine/u],
      [{ keywords: ["duplicate", "duplicate", "third"] }, FIXTURE_NOTICE_TITLE, /keywords/u],
      [{ files: ["dist/src", "README.md", "LICENSE"] }, FIXTURE_NOTICE_TITLE, /files inventory/u],
      [{ exports: undefined }, FIXTURE_NOTICE_TITLE, /root export/u],
      [{}, "Wrong package identity", /NOTICE title/u],
    ]) {
      expectValidation(() => validate(overrides, noticeTitle), pattern);
    }
    assert.doesNotThrow(() => validate({ repository: { type: "git", url: "https://example.invalid/private.git" } }));
  });

  check("publish-artifact policy rejects provider visibility and private classification fields", () => {
    const base = JSON.parse(readFileSync(join(HERE, "lib", "publish-artifact-policy.json"), "utf8"));
    for (const field of ["providerVisibility", "privateClassification"]) {
      const path = join(TEST_ROOT, `policy-${field}.json`);
      writeFileSync(path, `${JSON.stringify({ ...base, [field]: "PRIVATE" })}\n`);
      expectValidation(() => loadPublishArtifactPolicy(path), /exactly|unsupported|schema/u);
    }
  });

  check("release manifests transform every local dependency to the measured target version", () => {
    const source = fakeGitSource({
      "package.json": { name: "noa-root", version: "2.3.4" },
      "packages/a/package.json": {
        name: "noa-a",
        version: "1.0.0",
        dependencies: { "noa-root": "file:../.." },
      },
    });
    const planned = planReleaseManifests(derivePackageInventory(source));
    const a = planned.find((entry) => entry.name === "noa-a");
    assert.equal(a.releaseManifest.dependencies["noa-root"], "^2.3.4");
    assert.equal(a.transformations.length, 1);
  });

  check("release manifest planning rejects path escape and mismatched dependency identity", () => {
    const escaped = fakeGitSource({
      "package.json": { name: "noa-root", version: "1.0.0" },
      "packages/a/package.json": {
        name: "noa-a", version: "1.0.0", dependencies: { outside: "file:../../.." },
      },
    });
    expectValidation(
      () => planReleaseManifests(derivePackageInventory(escaped)),
      /escapes repository/u,
    );
    const mismatched = fakeGitSource({
      "package.json": { name: "noa-root", version: "1.0.0" },
      "packages/a/package.json": {
        name: "noa-a", version: "1.0.0", dependencies: { wrong: "file:../b" },
      },
      "packages/b/package.json": { name: "noa-b", version: "1.0.0" },
    });
    expectValidation(
      () => planReleaseManifests(derivePackageInventory(mismatched)),
      /named noa-b/u,
    );
  });

  check("exact fixture source strips private repository metadata from the release manifest", () => {
    const source = fakeGitSource({ "package.json": fixtureManifest({ repository: { type: "git", url: "https://example.invalid/private.git" } }) });
    const planned = planReleaseManifests(derivePackageInventory(source));
    assert.equal(planned.length, 1);
    assert.equal(Object.prototype.hasOwnProperty.call(planned[0].releaseManifest, "repository"), false);
    assert.equal(planned[0].transformations[0].field, "repository");
    assert.equal(planned[0].releaseManifestBytes.equals(planned[0].sourceManifestBytes), false);
  });

  check("exact Git controller materialization enforces every authority and its Git mode", () => {
    const paths = [
      "scripts/boundary-public-repos.json",
      "scripts/lib/npm-homedir-override.cjs",
      "scripts/lib/publish-artifact-executor.mjs",
      "scripts/lib/publish-artifact-policy.json",
      "scripts/lib/publish-artifact-staging.mjs",
      "scripts/lib/publish-container-driver.mjs",
      "scripts/lib/safe-npm-tarball.mjs",
      "scripts/lib/stage-publish-artifacts.mjs",
      "scripts/lint-published-surface.mjs",
    ];
    const controllerModes = { "scripts/lint-published-surface.mjs": "100755" };
    const source = fakeGitSource(
      {},
      paths.map((path) => [path, readFileSync(join(REPO_ROOT, path))]),
      controllerModes,
    );
    const root = mkdtempSync(join(TEST_ROOT, "exact-controller-"));
    const controller = materializeExactControllerForSelftest(source, root);
    assert.equal(readFileSync(controller.driver).equals(readFileSync(join(REPO_ROOT, "scripts/lib/publish-container-driver.mjs"))), true);
    assert.equal(readFileSync(controller.executor).equals(readFileSync(EXECUTOR_CLI)), true);
    assert.equal(readFileSync(controller.safeTarballParser).equals(readFileSync(join(REPO_ROOT, "scripts/lib/safe-npm-tarball.mjs"))), true);
    assert.equal(readFileSync(controller.staging).equals(readFileSync(join(REPO_ROOT, "scripts/lib/publish-artifact-staging.mjs"))), true);
    assert.equal(readFileSync(controller.bootstrap).equals(readFileSync(STAGING_CLI)), true);
    assert.equal(readFileSync(controller.npmHomedirOverride).equals(readFileSync(join(REPO_ROOT, "scripts/lib/npm-homedir-override.cjs"))), true);
    for (const authority of paths) {
      const omitted = fakeGitSource(
        {},
        paths.filter((path) => path !== authority).map((path) => [path, readFileSync(join(REPO_ROOT, path))]),
        controllerModes,
      );
      expectValidation(
        () => materializeExactControllerForSelftest(omitted, mkdtempSync(join(TEST_ROOT, "exact-controller-omitted-"))),
        /lacks regular file/u,
      );
    }

    const wrongLinterMode = fakeGitSource(
      {},
      paths.map((path) => [path, readFileSync(join(REPO_ROOT, path))]),
    );
    expectValidation(
      () => materializeExactControllerForSelftest(
        wrongLinterMode,
        mkdtempSync(join(TEST_ROOT, "exact-controller-wrong-mode-")),
      ),
      /lint-published-surface\.mjs with mode 100755/u,
    );

    const wrongPolicyMode = fakeGitSource(
      {},
      paths.map((path) => [path, readFileSync(join(REPO_ROOT, path))]),
      { ...controllerModes, "scripts/lib/publish-artifact-policy.json": "100755" },
    );
    expectValidation(
      () => materializeExactControllerForSelftest(
        wrongPolicyMode,
        mkdtempSync(join(TEST_ROOT, "exact-controller-wrong-mode-")),
      ),
      /publish-artifact-policy\.json with mode 100644/u,
    );

    const selftest = spawnSync(process.execPath, [controller.linter, "--selftest"], { encoding: "utf8" });
    assert.equal(selftest.status, 0, `${selftest.stdout}${selftest.stderr}`);
    const tarball = join(root, "controller-graph.tgz");
    createTarball(tarball, minimalPackageEntries());
    const clean = spawnSync(process.execPath, [controller.linter, "--tarball", tarball, "--public-repos", controller.publicRepos], {
      encoding: "utf8",
    });
    assert.equal(clean.status, 0, `${clean.stdout}${clean.stderr}`);

    const diagnosticTarball = join(root, "controller-diagnostic-path.tgz");
    const syntheticHiddenCoordinate = "https://github.com/exampleorg/hidden-one";
    createTarball(diagnosticTarball, minimalPackageEntries([{
      content: `round-1 ${syntheticHiddenCoordinate}\n`,
      path: "package/diagnostic-k4.md",
    }, {
      content: `This public package is unhackable ${syntheticHiddenCoordinate}\n`,
      path: "package/diagnostic-k5.md",
    }, {
      content: `All comparisons are constant-time ${syntheticHiddenCoordinate}\n`,
      path: "package/diagnostic-k6.md",
    }]));
    const diagnostic = spawnSync(process.execPath, [controller.linter, "--tarball", diagnosticTarball, "--public-repos", controller.publicRepos], {
      encoding: "utf8",
    });
    assert.equal(diagnostic.status, 1, `${diagnostic.stdout}${diagnostic.stderr}`);
    assert.match(diagnostic.stderr, /\[redacted artifact file\]:1\s+\[K4\]/u);
    assert.match(diagnostic.stderr, /\[redacted artifact file\]:1\s+\[K5\]/u);
    assert.match(diagnostic.stderr, /\[redacted artifact file\]:1\s+\[K6\]/u);
    assert.match(diagnostic.stderr, /\[redacted artifact file\]:1\s+\[K7\]/u);
    assert.doesNotMatch(diagnostic.stderr, /diagnostic-k[456]\.md/u);
    assert.doesNotMatch(diagnostic.stderr, /exampleorg\/hidden-one/u);
    assert.match(diagnostic.stderr, /\[redacted artifact content\]/u);

    const invalidPathTarball = join(root, "controller-invalid-path.tgz");
    createTarball(invalidPathTarball, minimalPackageEntries([{
      content: "synthetic\n",
      path: "package/placeholder.md",
    }]));
    const invalidPathRaw = gunzipSync(readFileSync(invalidPathTarball));
    const invalidPathHeader = invalidPathRaw.subarray(3 * 1024, 4 * 1024);
    invalidPathHeader.fill(0, 0, 100);
    tarString(invalidPathHeader, 0, 100, `package/../${syntheticHiddenCoordinate}`);
    rewriteTarChecksum(invalidPathHeader);
    writeFileSync(invalidPathTarball, canonicalGzip(invalidPathRaw));
    const invalidPath = spawnSync(process.execPath, [controller.linter, "--tarball", invalidPathTarball, "--public-repos", controller.publicRepos], {
      encoding: "utf8",
    });
    assert.equal(invalidPath.status, 2, `${invalidPath.stdout}${invalidPath.stderr}`);
    assert.match(invalidPath.stderr, /TARBALL_INVALID/u);
    assert.doesNotMatch(invalidPath.stderr, /exampleorg\/hidden-one/u);

    const appendedMemberTarball = join(root, "controller-appended-member.tgz");
    createTarball(appendedMemberTarball, minimalPackageEntries());
    writeFileSync(
      appendedMemberTarball,
      Buffer.concat([
        readFileSync(appendedMemberTarball),
        withGzipOptionalMetadata(canonicalGzip(Buffer.alloc(0)), 0x10, syntheticHiddenCoordinate),
      ]),
    );
    const appendedMember = spawnSync(process.execPath, [controller.linter, "--tarball", appendedMemberTarball, "--public-repos", controller.publicRepos], {
      encoding: "utf8",
    });
    assert.equal(appendedMember.status, 2, `${appendedMember.stdout}${appendedMember.stderr}`);
    assert.match(appendedMember.stderr, /TARBALL_INVALID/u);
    assert.doesNotMatch(appendedMember.stderr, /exampleorg\/hidden-one/u);

    const substituted = fakeGitSource({}, paths.map((path) => [
      path,
      path === "scripts/lib/safe-npm-tarball.mjs"
        ? Buffer.from('export function readSafeNpmTarball() { throw new Error("exact-controller-parser-substitution"); }\n', "utf8")
        : readFileSync(join(REPO_ROOT, path)),
    ]), controllerModes);
    const substitutedController = materializeExactControllerForSelftest(substituted, mkdtempSync(join(TEST_ROOT, "exact-controller-substituted-")));
    const rejected = spawnSync(process.execPath, [substitutedController.linter, "--tarball", tarball, "--public-repos", substitutedController.publicRepos], {
      encoding: "utf8",
    });
    assert.notEqual(rejected.status, 0);
    assert.match(`${rejected.stdout}${rejected.stderr}`, /TARBALL_INVALID/u);
    assert.doesNotMatch(`${rejected.stdout}${rejected.stderr}`, /exact-controller-parser-substitution/u);
  });

  check("streamed bootstrap ignores mutable checkout bootstrap and executor substitutions", () => {
    const repo = join(TEST_ROOT, "bootstrap-exact-executor-repo");
    mkdirSync(repo);
    const paths = [
      "scripts/boundary-public-repos.json",
      "scripts/lib/npm-homedir-override.cjs",
      "scripts/lib/publish-artifact-executor.mjs",
      "scripts/lib/publish-artifact-policy.json",
      "scripts/lib/publish-artifact-staging.mjs",
      "scripts/lib/publish-container-driver.mjs",
      "scripts/lib/safe-npm-tarball.mjs",
      "scripts/lib/stage-publish-artifacts.mjs",
      "scripts/lint-published-surface.mjs",
    ];
    for (const path of paths) {
      const target = join(repo, ...path.split("/"));
      mkdirSync(dirname(target), { recursive: true });
      writeFileSync(target, readFileSync(join(REPO_ROOT, path)));
      chmodSync(target, path === "scripts/lint-published-surface.mjs" ? 0o755 : 0o644);
    }
    fixtureGit(repo, ["init", "--quiet"]);
    fixtureGit(repo, ["add", "."]);
    fixtureGit(repo, ["-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid", "commit", "--quiet", "-m", "fixture"]);
    const commit = fixtureGit(repo, ["rev-parse", "HEAD"]);
    assert.match(
      fixtureGit(repo, ["ls-tree", commit, "--", "scripts/lint-published-surface.mjs"]),
      /^100755 blob [0-9a-f]+\tscripts\/lint-published-surface\.mjs$/u,
    );
    const streamed = spawnSync("/usr/bin/git", ["show", `${commit}:scripts/lib/stage-publish-artifacts.mjs`], {
      cwd: repo,
      encoding: "buffer",
    });
    assert.equal(streamed.status, 0, `${streamed.stdout}${streamed.stderr}`);
    const trustedBootstrap = join(TEST_ROOT, "streamed-exact-stage-publish-artifacts.mjs");
    writeFileSync(trustedBootstrap, streamed.stdout);
    writeFileSync(
      join(repo, "scripts", "lib", "stage-publish-artifacts.mjs"),
      "process.stderr.write('MUTABLE_BOOTSTRAP_SELECTED\\n'); process.exit(96);\n",
    );
    writeFileSync(
      join(repo, "scripts", "lib", "publish-artifact-executor.mjs"),
      "process.stderr.write('MUTABLE_EXECUTOR_SELECTED\\n'); process.exit(97);\n",
    );
    const result = spawnSync(process.execPath, [
      trustedBootstrap,
      "--repo-root", repo, "--verify", join(repo, "missing-candidate"), "--git-ref", commit,
    ], { cwd: repo, encoding: "utf8" });
    assert.notEqual(result.status, 96, `${result.stdout}${result.stderr}`);
    assert.notEqual(result.status, 97, `${result.stdout}${result.stderr}`);
    assert.doesNotMatch(`${result.stdout}${result.stderr}`, /MUTABLE_BOOTSTRAP_SELECTED|MUTABLE_EXECUTOR_SELECTED/u);
    assert.match(`${result.stdout}${result.stderr}`, /stage-publish-artifacts: STOP/u);
  });

  check("source reads close Git config without repurposing HOME", () => {
    assert.deepEqual(closedGitEnvForSelftest(), {
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_NO_REPLACE_OBJECTS: "1",
      LANG: "C",
      LC_ALL: "C",
      PATH: "/usr/bin:/bin",
    });
  });

  check("fixture package scripts bind publish lint to verification and freeze direct publication", () => {
    const source = fakeGitSource({
      "package.json": fixtureManifest({ scripts: {
        "lint:publish-surface": EXPECTED_PUBLISH_SURFACE_SCRIPT,
        "lint:publish-surface:selftest": EXPECTED_PUBLISH_SURFACE_SELFTEST_SCRIPT,
        prepublishOnly: EXPECTED_PREPUBLISH_REFUSAL,
      } }),
    });
    const manifest = JSON.parse(source.blobs.get("package.json").toString("utf8"));
    assert.equal(manifest.scripts["lint:publish-surface"], EXPECTED_PUBLISH_SURFACE_SCRIPT);
    assert.equal(manifest.scripts["lint:publish-surface:selftest"], EXPECTED_PUBLISH_SURFACE_SELFTEST_SCRIPT);
    assert.equal(manifest.scripts.prepublishOnly, EXPECTED_PREPUBLISH_REFUSAL);
  });

  check("publish workflow streams exact bootstrap before staging and verifies without candidate code", () => {
    const workflow = readFileSync(PUBLISH_WORKFLOW, "utf8");
    assert.match(
      workflow,
      /show "\$GITHUB_SHA:scripts\/lib\/stage-publish-artifacts\.mjs" > "\$bootstrap"/u,
    );
    assert.match(
      workflow,
      /run_exact_bootstrap --verify "\$output" --git-ref "\$GITHUB_SHA"/u,
    );
    assert.doesNotMatch(workflow, /node scripts\/lib\/stage-publish-artifacts\.mjs/u);
    const stage = workflow.indexOf("- name: Stage and scan immutable real tarballs");
    const upload = workflow.indexOf("- name: Upload immutable candidate evidence");
    const selftest = workflow.indexOf("- name: Prove staging rejects lifecycle, inventory, tar, manifest, and containment mutations");
    assert.ok(stage >= 0 && upload > stage && selftest > upload, "candidate selftest must run only after upload custody");
  });

  check("--selftest cannot bypass the authoritative candidate verifier", () => {
    for (const args of [["--selftest"], ["--verify", "--selftest"]]) {
      const result = spawnSync(process.execPath, [STAGING_CLI, ...args], { encoding: "utf8" });
      assert.equal(result.status, 2);
      assert.match(result.stderr, /--git-ref is required|--git-ref must appear exactly once/u);
      assert.doesNotMatch(result.stdout, /verification: PASS/u);
    }
    const linter = spawnSync(
      process.execPath,
      [SURFACE_LINTER, "--tarball", "missing.tgz", "--selftest"],
      { encoding: "utf8" },
    );
    assert.equal(linter.status, 2);
    assert.match(linter.stderr, /Unknown argument: --selftest/u);
    assert.doesNotMatch(linter.stdout, /K6 selftest/u);
  });

  check("direct prepublish refusal exits before a following sentinel", () => {
    const sentinel = join(TEST_ROOT, "PREPUBLISH_SENTINEL");
    const sentinelProgram = `require("node:fs").writeFileSync(${JSON.stringify(sentinel)}, "executed")`;
    const command = `${EXPECTED_PREPUBLISH_REFUSAL} && ${JSON.stringify(process.execPath)} -e ${JSON.stringify(sentinelProgram)}`;
    const result = spawnSync("/bin/sh", ["-c", command], {
      encoding: "utf8",
      env: {
        LANG: "C.UTF-8",
        LC_ALL: "C.UTF-8",
        PATH: `${dirname(process.execPath)}:/usr/bin:/bin`,
        TZ: "UTC",
      },
    });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /RELEASE_FROZEN/u);
    assert.equal(existsSync(sentinel), false);
  });

  check("Docker plan is fail-closed for no-network, read-only, pull, and authority drift", () => {
    const args = createDockerRunArgs({
      buildNetwork: "none",
      commitTime: 0,
      containerName: "noa-plan-fixture",
      driver: DRIVER,
      homedirOverride: NPM_HOMEDIR_OVERRIDE,
      mode: "pack",
      output: TEST_ROOT,
      packagePath: ".",
      platform: platform(),
      source: REPO_ROOT,
      uid: process.getuid(),
      gid: process.getgid(),
    });
    validateDockerRunArgs(args, "pack", "none");
    assert.equal(args.some((arg, index) => args[index - 1] === "--env" && arg.startsWith("HOME=")), false);
    assert.equal(args.includes("--entrypoint=/usr/bin/env"), true);
    assert.equal(
      args.includes("-u") && args.includes("HOME") && args.includes("--require") && args.includes("/noa-npm-homedir-override.cjs"),
      true,
    );
    assert.equal(args.some((arg) => arg.includes("dst=/noa-npm-homedir-override.cjs,readonly")), true);
    assert.equal(args.includes("NOA_NPM_HOMEDIR=/noa-tmp/npm-home"), true);
    const mutate = (find, replacement) => args.map((arg) => arg === find ? replacement : arg);
    expectValidation(() => validateDockerRunArgs(mutate("--network=none", "--network=bridge"), "pack", "none"), /network/u);
    expectValidation(() => validateDockerRunArgs(mutate("--pull=never", "--pull=always"), "pack", "none"), /omitted/u);
    expectValidation(() => validateDockerRunArgs(args.filter((arg) => arg !== "--read-only"), "pack", "none"), /omitted/u);
    const writable = args.map((arg) => arg.includes("dst=/workspace,readonly") ? arg.replace(",readonly", "") : arg);
    expectValidation(() => validateDockerRunArgs(writable, "pack", "none"), /read-only frozen/u);
    const labelIndex = args.indexOf("--label");
    assert.notEqual(labelIndex, -1);
    assert.equal(args[labelIndex + 1], "io.noa.publish-artifact-staging.owner=noa-plan-fixture");
    expectValidation(
      () => validateDockerRunArgs(args.filter((_, index) => index !== labelIndex && index !== labelIndex + 1), "pack", "none"),
      /ownership label/u,
    );
    expectValidation(() => validateDockerRunArgs([...args, "NPM_TOKEN=fake"], "pack", "none"), /forbidden authority/u);
    expectValidation(() => validateDockerRunArgs([...args, "--env", "HOME=/noa-tmp/home"], "pack", "none"), /passes HOME/u);
  });

  check("production Docker cleanup distinguishes an exact-query failure from absence", () => {
    const calls = [];
    assert.throws(
      () => cleanupExactDockerContainerForSelftest("noa-query-failure", (args, label) => {
        calls.push({ args, label });
        return { status: 1, stderr: "daemon unavailable", stdout: "" };
      }),
      (error) => error instanceof SetupFailure && /query failed/u.test(error.message),
    );
    assert.equal(calls.length, 1);
    assert.deepEqual(calls[0].args.slice(0, 4), ["container", "ls", "--all", "--no-trunc"]);
    assert.ok(calls[0].args.includes("label=io.noa.publish-artifact-staging.owner=noa-query-failure"));
  });

  check("production Docker cleanup refuses a failed rm -f", () => {
    const id = "a".repeat(64);
    const replies = [
      { status: 0, stderr: "", stdout: `${id}\n` },
      { status: 1, stderr: "removal refused", stdout: "" },
    ];
    const calls = [];
    assert.throws(
      () => cleanupExactDockerContainerForSelftest("noa-removal-failure", (args) => {
        calls.push(args);
        return replies.shift();
      }),
      (error) => error instanceof SetupFailure && /removal failed/u.test(error.message),
    );
    assert.deepEqual(calls[1], ["rm", "-f", id]);
    assert.equal(replies.length, 0);
  });

  check("production Docker cleanup bounds persistent post-removal residue", () => {
    const id = "b".repeat(64);
    const replies = [
      { status: 0, stderr: "", stdout: `${id}\n` },
      { status: 0, stderr: "", stdout: "" },
      { status: 0, stderr: "", stdout: `${id}\n` },
      { status: 0, stderr: "", stdout: "" },
      { status: 0, stderr: "", stdout: `${id}\n` },
      { status: 0, stderr: "", stdout: "" },
    ];
    assert.throws(
      () => cleanupExactDockerContainerForSelftest(
        "noa-post-removal-residue",
        () => replies.shift(),
        { maxQueries: 3 },
      ),
      (error) => error instanceof SetupFailure && /did not reach 2 consecutive quiet observations/u.test(error.message),
    );
    assert.equal(replies.length, 0);
  });

  check("one status-zero empty Docker query is not load-bearing proof of absence", () => {
    const replies = [
      { status: 0, stderr: "", stdout: "" },
      { status: 1, stderr: "late daemon query failed", stdout: "" },
    ];
    assert.throws(
      () => cleanupExactDockerContainerForSelftest("noa-one-empty-is-not-proof", () => replies.shift()),
      (error) => error instanceof SetupFailure && /query failed/u.test(error.message),
    );
    assert.equal(replies.length, 0);
  });

  check("production Docker cleanup requires two consecutive quiet observations", () => {
    let calls = 0;
    cleanupExactDockerContainerForSelftest("noa-clean-absence", () => {
      calls++;
      return { status: 0, stderr: "", stdout: "" };
    });
    assert.equal(calls, 2);
  });

  check("production Docker cleanup catches late creation after an empty query", () => {
    const id = "c".repeat(64);
    const replies = [
      { status: 0, stderr: "", stdout: "" },
      { status: 0, stderr: "", stdout: `${id}\n` },
      { status: 0, stderr: "", stdout: "" },
      { status: 0, stderr: "", stdout: "" },
      { status: 0, stderr: "", stdout: "" },
    ];
    const calls = [];
    expectValidation(
      () => cleanupExactDockerContainerForSelftest("noa-late-residue", (args) => {
        calls.push(args);
        return replies.shift();
      }),
      /residue was found and removed/u,
    );
    assert.equal(replies.length, 0);
    assert.deepEqual(calls.map((args) => args[0]), ["container", "container", "rm", "container", "container"]);
    assert.deepEqual(calls[2], ["rm", "-f", id]);
  });

  check("production Docker cleanup enforces its wall-clock budget", () => {
    const times = [0, 0, 30_001];
    let queries = 0;
    assert.throws(
      () => cleanupExactDockerContainerForSelftest(
        "noa-cleanup-time-budget",
        () => {
          queries++;
          return { status: 0, stderr: "", stdout: "" };
        },
        { now: () => times.shift() ?? 30_001, timeBudgetMs: 30_000 },
      ),
      (error) => error instanceof SetupFailure && /time budget/u.test(error.message),
    );
    assert.equal(queries, 1);
  });

  check("offline cache snapshot is exact, read-only, and breaks caller hard links", () => {
    const source = join(TEST_ROOT, "offline-cache-hardlink-source");
    const destination = join(TEST_ROOT, "offline-cache-hardlink-snapshot");
    mkdirSync(source);
    const firstSource = join(source, "first");
    const secondSource = join(source, "second");
    writeFileSync(firstSource, "shared cache bytes\n");
    linkSync(firstSource, secondSource);
    assert.equal(lstatSync(firstSource).nlink, 2);
    const before = digestRealTree(source);
    let snapshot;
    try {
      snapshot = snapshotOfflineCacheForSelftest({ source, destination });
      assert.deepEqual(snapshot.evidence.rows, before.rows);
      for (const name of ["first", "second"]) {
        const sourceStat = lstatSync(join(source, name));
        const snapshotStat = lstatSync(join(destination, name));
        assert.equal(snapshotStat.isFile(), true);
        assert.equal(snapshotStat.nlink, 1);
        assert.notEqual(snapshotStat.ino, sourceStat.ino);
        assert.equal((snapshotStat.mode & 0o222), 0);
        assert.equal(readFileSync(join(destination, name), "utf8"), "shared cache bytes\n");
      }
      assert.equal((lstatSync(destination).mode & 0o222), 0);
    } finally {
      if (existsSync(destination)) setTreeWritable(destination, true);
    }
  });

  check("offline cache snapshot rejects symlinked cache entries without residue", () => {
    const source = join(TEST_ROOT, "offline-cache-symlink-source");
    const destination = join(TEST_ROOT, "offline-cache-symlink-snapshot");
    mkdirSync(source);
    const real = join(TEST_ROOT, "offline-cache-symlink-target");
    writeFileSync(real, "cache bytes\n");
    symlinkSync(real, join(source, "linked"));
    expectValidation(
      () => snapshotOfflineCacheForSelftest({ source, destination }),
      /contains a symbolic link/u,
    );
    assert.equal(existsSync(destination), false);
  });

  check("offline cache snapshot detects a concurrent change-and-restore attempt", () => {
    const source = join(TEST_ROOT, "offline-cache-change-restore-source");
    const destination = join(TEST_ROOT, "offline-cache-change-restore-snapshot");
    mkdirSync(source);
    const original = "original cache bytes\n";
    writeFileSync(join(source, "entry"), original);
    let mutated = false;
    expectValidation(
      () => snapshotOfflineCacheForSelftest({
        source,
        destination,
        afterRead: ({ sourcePath }) => {
          if (mutated) return;
          mutated = true;
          writeFileSync(sourcePath, "temporary cache bytes\n");
          writeFileSync(sourcePath, original);
        },
      }),
      /changed while snapshotting/u,
    );
    assert.equal(mutated, true);
    assert.equal(readFileSync(join(source, "entry"), "utf8"), original);
    assert.equal(existsSync(destination), false);
  });

  check("production offline-cache budgets leave explicit headroom below the 2 GiB tmpfs", () => {
    assert.deepEqual(OFFLINE_CACHE_LIMITS, {
      fileCount: 4_096,
      perFileBytes: 192 * 1024 * 1024,
      totalBytes: 512 * 1024 * 1024,
    });
    assert.ok(OFFLINE_CACHE_LIMITS.perFileBytes < OFFLINE_CACHE_LIMITS.totalBytes);
    assert.ok(OFFLINE_CACHE_LIMITS.totalBytes < 2 * 1024 * 1024 * 1024);
  });

  check("offline cache file-count budget accepts just under and rejects over without residue", () => {
    const limits = { fileCount: 3, perFileBytes: 16, totalBytes: 48 };
    const under = join(TEST_ROOT, "offline-cache-count-under");
    const underSnapshot = join(TEST_ROOT, "offline-cache-count-under-snapshot");
    mkdirSync(under);
    writeFileSync(join(under, "a"), "a");
    writeFileSync(join(under, "b"), "b");
    try {
      const snapshot = snapshotOfflineCacheForSelftest({ source: under, destination: underSnapshot, limits });
      assert.equal(snapshot.evidence.count, 2);
    } finally {
      if (existsSync(underSnapshot)) setTreeWritable(underSnapshot, true);
    }
    const over = join(TEST_ROOT, "offline-cache-count-over");
    const overSnapshot = join(TEST_ROOT, "offline-cache-count-over-snapshot");
    mkdirSync(over);
    for (const name of ["a", "b", "c", "d"]) writeFileSync(join(over, name), name);
    expectValidation(
      () => snapshotOfflineCacheForSelftest({ source: over, destination: overSnapshot, limits }),
      /3-file limit/u,
    );
    assert.equal(existsSync(overSnapshot), false);
  });

  check("offline cache per-file budget accepts just under and rejects over without residue", () => {
    const limits = { fileCount: 2, perFileBytes: 8, totalBytes: 16 };
    const under = join(TEST_ROOT, "offline-cache-file-under");
    const underSnapshot = join(TEST_ROOT, "offline-cache-file-under-snapshot");
    mkdirSync(under);
    writeFileSync(join(under, "entry"), "1234567");
    try {
      const snapshot = snapshotOfflineCacheForSelftest({ source: under, destination: underSnapshot, limits });
      assert.equal(snapshot.evidence.size, 7);
    } finally {
      if (existsSync(underSnapshot)) setTreeWritable(underSnapshot, true);
    }
    const over = join(TEST_ROOT, "offline-cache-file-over");
    const overSnapshot = join(TEST_ROOT, "offline-cache-file-over-snapshot");
    mkdirSync(over);
    writeFileSync(join(over, "entry"), "123456789");
    expectValidation(
      () => snapshotOfflineCacheForSelftest({ source: over, destination: overSnapshot, limits }),
      /8-byte per-file limit/u,
    );
    assert.equal(existsSync(overSnapshot), false);
  });

  check("offline cache total-byte budget accepts just under and rejects over without residue", () => {
    const limits = { fileCount: 3, perFileBytes: 10, totalBytes: 10 };
    const under = join(TEST_ROOT, "offline-cache-total-under");
    const underSnapshot = join(TEST_ROOT, "offline-cache-total-under-snapshot");
    mkdirSync(under);
    writeFileSync(join(under, "a"), "1234");
    writeFileSync(join(under, "b"), "12345");
    try {
      const snapshot = snapshotOfflineCacheForSelftest({ source: under, destination: underSnapshot, limits });
      assert.equal(snapshot.evidence.size, 9);
    } finally {
      if (existsSync(underSnapshot)) setTreeWritable(underSnapshot, true);
    }
    const over = join(TEST_ROOT, "offline-cache-total-over");
    const overSnapshot = join(TEST_ROOT, "offline-cache-total-over-snapshot");
    mkdirSync(over);
    writeFileSync(join(over, "a"), "123456");
    writeFileSync(join(over, "b"), "12345");
    expectValidation(
      () => snapshotOfflineCacheForSelftest({ source: over, destination: overSnapshot, limits }),
      /10-byte total limit/u,
    );
    assert.equal(existsSync(overSnapshot), false);
  });

  check("offline cache snapshot rejects a special file without residue", () => {
    const source = join(TEST_ROOT, "offline-cache-special-source");
    const destination = join(TEST_ROOT, "offline-cache-special-snapshot");
    mkdirSync(source);
    const fifo = join(source, "pipe");
    const created = spawnSync("/usr/bin/mkfifo", [fifo], { encoding: "utf8" });
    if (created.status !== 0) throw new SetupFailure(`mkfifo fixture failed: ${created.stderr}`);
    expectValidation(
      () => snapshotOfflineCacheForSelftest({ source, destination }),
      /special filesystem entry/u,
    );
    assert.equal(existsSync(destination), false);
  });

  check("offline cache snapshot never deletes a pre-existing destination", () => {
    const source = join(TEST_ROOT, "offline-cache-existing-source");
    const destination = join(TEST_ROOT, "offline-cache-existing-destination");
    mkdirSync(source);
    writeFileSync(join(source, "entry"), "cache bytes");
    mkdirSync(destination);
    writeFileSync(join(destination, "owner-data"), "must survive");
    expectValidation(
      () => snapshotOfflineCacheForSelftest({ source, destination }),
      /snapshot destination already exists/u,
    );
    assert.equal(readFileSync(join(destination, "owner-data"), "utf8"), "must survive");
  });

  check("second scratch creation failure removes the first owned scratch", () => {
    const outputParent = join(TEST_ROOT, "scratch-pair-parent");
    mkdirSync(outputParent);
    let firstScratch;
    let calls = 0;
    assert.throws(
      () => withOwnedScratchPairForSelftest(
        outputParent,
        () => assert.fail("operation must not run after second-scratch failure"),
        (prefix) => {
          calls++;
          if (calls === 2) throw new Error("deterministic second-scratch failure");
          firstScratch = mkdtempSync(prefix);
          return firstScratch;
        },
      ),
      /deterministic second-scratch failure/u,
    );
    assert.equal(calls, 2);
    assert.equal(existsSync(firstScratch), false);
    assert.deepEqual(readdirSync(outputParent), []);
  });

  check("failed scratch cleanup unlinks generated links/special entries without following targets", () => {
    const outputParent = join(TEST_ROOT, "scratch-special-parent");
    const externalTarget = join(TEST_ROOT, "scratch-external-target");
    mkdirSync(outputParent);
    writeFileSync(externalTarget, "must survive");
    let workRoot;
    let finalScratch;
    assert.throws(
      () => withOwnedScratchPairForSelftest(outputParent, (paths) => {
        ({ finalScratch, workRoot } = paths);
        symlinkSync(externalTarget, join(workRoot, "generated-link"));
        const fifo = spawnSync("/usr/bin/mkfifo", [join(workRoot, "generated-pipe")], { encoding: "utf8" });
        if (fifo.status !== 0) throw new SetupFailure(`mkfifo scratch fixture failed: ${fifo.stderr}`);
        throw new ValidationFailure("deterministic failed build");
      }),
      /deterministic failed build/u,
    );
    assert.equal(existsSync(workRoot), false);
    assert.equal(existsSync(finalScratch), false);
    assert.equal(readFileSync(externalTarget, "utf8"), "must survive");
  });

  check("materialization never overwrites a pre-existing empty output directory", () => {
    const source = join(TEST_ROOT, "materialize-preexisting-source");
    const output = join(TEST_ROOT, "materialize-preexisting-output");
    mkdirSync(source);
    writeFileSync(join(source, "candidate.tgz"), "candidate bytes");
    mkdirSync(output);
    let verified = false;
    expectValidation(
      () => materializeCandidateOutputForSelftest({
        output,
        source,
        verify: () => { verified = true; },
      }),
      /already exists; refusing overwrite/u,
    );
    assert.equal(verified, false);
    assert.deepEqual(readdirSync(output), []);
  });

  check("materialization loses an output race without touching the winner", () => {
    const source = join(TEST_ROOT, "materialize-race-source");
    const output = join(TEST_ROOT, "materialize-race-output");
    mkdirSync(source);
    writeFileSync(join(source, "candidate.tgz"), "candidate bytes");
    expectValidation(
      () => materializeCandidateOutputForSelftest({
        beforeReserve: () => {
          mkdirSync(output);
          writeFileSync(join(output, "winner-data"), "do not delete");
        },
        output,
        source,
        verify: () => assert.fail("race winner must prevent candidate verification"),
      }),
      /already exists; refusing overwrite/u,
    );
    assert.equal(readFileSync(join(output, "winner-data"), "utf8"), "do not delete");
    assert.deepEqual(readdirSync(output), ["winner-data"]);
  });

  check("post-materialization verification failure removes exact generated output", () => {
    const source = join(TEST_ROOT, "materialize-postverify-source");
    const output = join(TEST_ROOT, "materialize-postverify-output");
    mkdirSync(source);
    writeFileSync(join(source, "candidate.tgz"), "candidate bytes");
    expectValidation(
      () => materializeCandidateOutputForSelftest({
        output,
        source,
        verify: () => { throw new ValidationFailure("deterministic final verification failure"); },
      }),
      /deterministic final verification failure/u,
    );
    assert.equal(existsSync(output), false);
  });

  check("cleanup identity mismatch fails closed and preserves replacement data", () => {
    const source = join(TEST_ROOT, "materialize-identity-source");
    const output = join(TEST_ROOT, "materialize-identity-output");
    const movedGenerated = join(TEST_ROOT, "materialize-identity-moved-generated");
    mkdirSync(source);
    writeFileSync(join(source, "candidate.tgz"), "candidate bytes");
    expectValidation(
      () => materializeCandidateOutputForSelftest({
        afterMaterialize: () => {
          renameSync(output, movedGenerated);
          mkdirSync(output);
          writeFileSync(join(output, "replacement-data"), "must survive");
        },
        output,
        source,
        verify: () => { throw new ValidationFailure("verification sees replacement"); },
      }),
      /identity changed; refusing to touch replacement path/u,
    );
    assert.equal(readFileSync(join(output, "replacement-data"), "utf8"), "must survive");
    assert.equal(readFileSync(join(movedGenerated, "candidate.tgz"), "utf8"), "candidate bytes");
  });

  check("candidate verifier accepts exact tarball bytes and canonical manifest", () => {
    const root = join(TEST_ROOT, "candidate-valid");
    const fixture = writeCandidateSet(root);
    assert.equal(verifyFixtureCandidate(root, fixture).packages.length, 1);
  });

  // Assemble a wholly synthetic non-public coordinate only while creating disposable tarballs.
  // Its adjacent synthetic policy proves K7 uses the supplied public allowlist without embedding
  // or reconstructing any real organization-private repository relationship in public source.
  const artifactNonPublicCoordinate = ["Example", "ArmOrg/hidden-receipt-fixture"].join("");
  const artifactPublicRepos = join(TEST_ROOT, "artifact-public-repos.json");
  writeFileSync(artifactPublicRepos, `${JSON.stringify({
    note: "synthetic artifact-coordinate selftest policy",
    source: "synthetic local fixture",
    refreshedAt: "2026-01-01T00:00:00.000Z",
    orgs: { ExampleArmOrg: ["public-receipt-fixture"] },
  })}\n`);
  for (const [name, path, content] of [
    ["package.json", "package/package.json", JSON.stringify(fixtureManifest({ repository: { url: `https://github.com/${artifactNonPublicCoordinate}.git` } }))],
    ["README.md", "package/README.md", `source: ${artifactNonPublicCoordinate}\n`],
    ["NOTICE", "package/NOTICE", `${FIXTURE_NOTICE_TITLE}\nsource: ${artifactNonPublicCoordinate}\n`],
    ["sourcemap", "package/dist/src/index.js.map", JSON.stringify({ version: 3, sources: [`https://github.com/${artifactNonPublicCoordinate}/src/index.ts`] })],
  ]) {
    check(`artifact coordinate gate rejects packed ${name} reinsertion`, () => {
      const tarball = join(TEST_ROOT, `artifact-coordinate-${name.replaceAll(".", "-")}.tgz`);
      const entries = minimalPackageEntries().filter((entry) => entry.path !== path);
      entries.push({ path, content });
      createTarball(tarball, entries);
      const result = spawnSync(process.execPath, [SURFACE_LINTER, "--tarball", tarball, "--public-repos", artifactPublicRepos], {
        encoding: "utf8",
      });
      assert.equal(result.status, 1);
      assert.match(result.stderr, /\[K7\] non-public repository coordinate/u);
    });
  }

  check("offline candidate verification requires the exact cache input", () => {
    const root = join(TEST_ROOT, "candidate-offline-cache-missing");
    const fixture = writeCandidateSet(root);
    expectValidation(
      () => verifyCandidateSetForSelftest(
        root,
        {
          gitSource: fixture.gitSource,
          independentBuildOutputs: fixture.independentBuildOutputs,
        },
        fixture.policy,
      ),
      /requires the exact --offline-cache dependency input/u,
    );
  });

  check("offline candidate verification rejects the wrong cache bytes", () => {
    const root = join(TEST_ROOT, "candidate-offline-cache-wrong");
    const fixture = writeCandidateSet(root);
    const wrongCache = join(TEST_ROOT, "fixture-offline-cache-wrong");
    mkdirSync(wrongCache);
    writeFileSync(join(wrongCache, "cache-entry"), "different dependency cache bytes\n");
    expectValidation(
      () => verifyCandidateSetForSelftest(
        root,
        {
          gitSource: fixture.gitSource,
          independentBuildOutputs: fixture.independentBuildOutputs,
          offlineCache: wrongCache,
        },
        fixture.policy,
      ),
      /does not match the candidate dependency-input digest/u,
    );
  });

  check("candidate verifier rejects Git commit/tree/inventory substitution", () => {
    const root = join(TEST_ROOT, "candidate-git-substitution");
    const fixture = writeCandidateSet(root, (manifest) => {
      manifest.source.commit = "c".repeat(40);
      manifest.source.tree = "d".repeat(40);
      manifest.source.inventorySha256 = "e".repeat(64);
    });
    expectValidation(
      () => verifyFixtureCandidate(root, fixture),
      /does not match the requested immutable Git tree/u,
    );
  });

  for (const [name, mutate, pattern] of [
    ["tarball digest substitution", (m) => { m.packages[0].tarballSha256 = "f".repeat(64); }, /tarballSha256/u],
    ["packlist digest substitution", (m) => { m.packages[0].packlistDigest = "e".repeat(64); }, /packlistDigest/u],
    ["packlist count substitution", (m) => { m.packages[0].packlistCount += 1; }, /packlistCount/u],
    ["packlist size substitution", (m) => { m.packages[0].packlistSize += 1; }, /packlistSize/u],
    ["release manifest digest substitution", (m) => { m.packages[0].releaseManifestSha256 = "d".repeat(64); }, /metadata is not derived from Git|manifest identity\/digest/u],
  ]) {
    check(`candidate verifier rejects ${name}`, () => {
      const root = join(TEST_ROOT, `candidate-${name.replaceAll(" ", "-")}`);
      const fixture = writeCandidateSet(root, mutate);
      expectValidation(() => verifyFixtureCandidate(root, fixture), pattern);
    });
  }

  check("candidate verifier rejects duplicate path/name/version identity", () => {
    const root = join(TEST_ROOT, "candidate-duplicate-identity");
    const fixture = writeCandidateSet(
      root,
      (manifest) => manifest.packages.push({ ...manifest.packages[0] }),
    );
    expectValidation(
      () => verifyFixtureCandidate(root, fixture),
      /artifact count does not match|duplicate artifact identity/u,
    );
  });

  check("candidate verifier rejects a digest sidecar substitution", () => {
    const root = join(TEST_ROOT, "candidate-sidecar-substitution");
    const fixture = writeCandidateSet(root);
    writeFileSync(join(root, "publish-artifacts.manifest.sha256"), `${"0".repeat(64)}\n`);
    expectValidation(() => verifyFixtureCandidate(root, fixture), /digest sidecar/u);
  });

  for (const [name, filename] of [
    ["manifest", "publish-artifacts.manifest.json"],
    ["digest sidecar", "publish-artifacts.manifest.sha256"],
    ["NON-RELEASE label", "CANDIDATE-NON-RELEASE.txt"],
  ]) {
    check(`candidate verifier rejects a symlinked ${name}`, () => {
      const root = join(TEST_ROOT, `candidate-symlink-${name.replaceAll(" ", "-")}`);
      const fixture = writeCandidateSet(root);
      const target = join(root, filename);
      const backup = join(TEST_ROOT, `candidate-symlink-${name.replaceAll(" ", "-")}-bytes`);
      writeFileSync(backup, readFileSync(target));
      rmSync(target);
      symlinkSync(backup, target);
      expectValidation(() => verifyFixtureCandidate(root, fixture), /must be a real regular file/u);
    });
  }

  check("candidate verifier rejects a policy-permitted missing public carrier file", () => {
    const root = join(TEST_ROOT, "candidate-missing-notice");
    const fixture = writeCandidateSet(root, (manifest, tarballPath, context) => {
      const changed = createTarball(tarballPath, [
        {
          path: "package/package.json",
          content: `${JSON.stringify(fixtureManifest())}\n`,
        },
        { path: "package/LICENSE", content: "Apache-2.0 fixture license.\n" },
        { path: "package/README.md", content: "A modest fixture.\n" },
        { path: "package/dist/src/index.js", content: "export const fixture = 1;\n" },
      ]);
      const artifact = manifest.packages[0];
      for (const field of [
        "compressedSize", "packlistCount", "packlistDigest", "packlistSize",
        "tarballSha256", "uncompressedSize",
      ]) artifact[field] = changed[field];
      const paths = changed.entries.map((entry) => entry.path);
      const pathSetSha256 = sha256Hex(Buffer.from(canonicalJson(paths)));
      artifact.pathSetSha256 = pathSetSha256;
      context.policy.packages[0].pathCount = paths.length;
      context.policy.packages[0].pathSetSha256 = pathSetSha256;
    });
    expectValidation(
      () => verifyFixtureCandidate(root, fixture),
      /lacks required public carrier file NOTICE/u,
    );
  });

  check("candidate verifier rejects self-authored tar metrics for a policy-external injected file", () => {
    const root = join(TEST_ROOT, "candidate-injected-file");
    const fixture = writeCandidateSet(root, (manifest, tarballPath) => {
      const injected = createTarball(tarballPath, minimalPackageEntries([
        { path: "package/ATTACKER-INJECTED.md", content: "This package is unhackable.\n" },
        { path: "package/README.md", content: "A modest fixture.\n" },
        { path: "package/dist/src/index.js", content: "export const fixture = 1;\n" },
      ]));
      const artifact = manifest.packages[0];
      for (const field of [
        "compressedSize", "packlistCount", "packlistDigest", "packlistSize",
        "tarballSha256", "uncompressedSize",
      ]) artifact[field] = injected[field];
      artifact.pathSetSha256 = sha256Hex(Buffer.from(canonicalJson(injected.entries.map((entry) => entry.path))));
    });
    expectValidation(
      () => verifyFixtureCandidate(root, fixture),
      /published path set does not match the trusted policy/u,
    );
  });

  check("candidate verifier reruns the real linter over a policy-permitted build output", () => {
    const root = join(TEST_ROOT, "candidate-build-output-overclaim");
    const fixture = writeCandidateSet(root, (manifest, tarballPath, context) => {
      const hostileBuild = "export const claim = 'unhackable';\n";
      const changed = createTarball(tarballPath, minimalPackageEntries([
        { path: "package/README.md", content: "A modest fixture.\n" },
        { path: "package/dist/src/index.js", content: hostileBuild },
      ]));
      const artifact = manifest.packages[0];
      for (const field of [
        "compressedSize", "packlistCount", "packlistDigest", "packlistSize",
        "tarballSha256", "uncompressedSize",
      ]) artifact[field] = changed[field];
      const buildEntry = changed.entries.find((entry) => entry.path === "dist/src/index.js");
      manifest.build.outputs[0] = {
        mode: "100644",
        path: "dist/src/index.js",
        sha256: buildEntry.sha256,
        size: buildEntry.size,
      };
      context.independentBuildOutputs[0] = { ...manifest.build.outputs[0] };
      const rows = context.frozenRows.map((row) =>
        row.path === "dist/src/index.js" ? manifest.build.outputs[0] : row);
      manifest.frozenSnapshot = {
        fileCount: rows.length,
        sha256: sha256Hex(Buffer.from(canonicalJson(rows))),
        size: rows.reduce((sum, row) => sum + row.size, 0),
      };
    });
    expectValidation(
      () => verifyFixtureCandidate(root, fixture),
      /tarball linter rejected candidate/u,
    );
  });

  check("candidate verifier rejects a clean semantic build-output substitution", () => {
    const root = join(TEST_ROOT, "candidate-semantic-build-substitution");
    const fixture = writeCandidateSet(root, (manifest, tarballPath, context) => {
      const substitutedBuild = "export const fixture = 2;\n";
      const changed = createTarball(tarballPath, minimalPackageEntries([
        { path: "package/README.md", content: "A modest fixture.\n" },
        { path: "package/dist/src/index.js", content: substitutedBuild },
      ]));
      const artifact = manifest.packages[0];
      for (const field of [
        "compressedSize", "packlistCount", "packlistDigest", "packlistSize",
        "tarballSha256", "uncompressedSize",
      ]) artifact[field] = changed[field];
      const buildEntry = changed.entries.find((entry) => entry.path === "dist/src/index.js");
      manifest.build.outputs[0] = {
        mode: "100644",
        path: "dist/src/index.js",
        sha256: buildEntry.sha256,
        size: buildEntry.size,
      };
      const rows = context.frozenRows.map((row) =>
        row.path === "dist/src/index.js" ? manifest.build.outputs[0] : row);
      manifest.frozenSnapshot = {
        fileCount: rows.length,
        sha256: sha256Hex(Buffer.from(canonicalJson(rows))),
        size: rows.reduce((sum, row) => sum + row.size, 0),
      };
    });
    expectValidation(
      () => verifyFixtureCandidate(root, fixture),
      /independently reproduced build output/u,
    );
  });

  check("candidate verifier rejects an independently carried output omitted from the manifest", () => {
    const root = join(TEST_ROOT, "candidate-second-output-omitted");
    const fixture = writeCandidateSet(root, (_manifest, _tarballPath, context) => {
      const bytes = Buffer.from("export const second = true;\n");
      context.independentBuildOutputs.push({
        mode: "100644",
        path: "dist/src/second.js",
        sha256: sha256Hex(bytes),
        size: bytes.length,
      });
    });
    expectValidation(
      () => verifyFixtureCandidate(root, fixture),
      /does not match independently reproduced build output/u,
    );
  });

  check("candidate verifier rejects a manifest-only extra carried output", () => {
    const root = join(TEST_ROOT, "candidate-second-output-extra");
    const fixture = writeCandidateSet(root, (manifest) => {
      const bytes = Buffer.from("export const second = true;\n");
      manifest.build.outputs.push({
        mode: "100644",
        path: "dist/src/second.js",
        sha256: sha256Hex(bytes),
        size: bytes.length,
      });
    });
    expectValidation(
      () => verifyFixtureCandidate(root, fixture),
      /does not match independently reproduced build output/u,
    );
  });

  for (const [name, mutate, pattern] of [
    ["fake controller digest", (manifest) => { manifest.controller.driverSha256 = "8".repeat(64); }, /controller driver digest/u],
    ["fake frozen digest", (manifest) => { manifest.frozenSnapshot.sha256 = "9".repeat(64); }, /complete Git/u],
    ["self-authored Docker evidence", (manifest) => { manifest.docker = { serverVersion: "27.4.0" }; }, /candidate manifest keys are not exact/u],
    ["self-authored host Node evidence", (manifest) => { manifest.controller.hostNode = process.version; }, /candidate controller keys are not exact/u],
  ]) {
    check(`candidate verifier rejects ${name}`, () => {
      const root = join(TEST_ROOT, `candidate-${name.replaceAll(" ", "-")}`);
      const fixture = writeCandidateSet(root, mutate);
      expectValidation(() => verifyFixtureCandidate(root, fixture), pattern);
    });
  }

  check("legacy directory lint refuses without executing candidate lifecycle", () => {
    const root = join(TEST_ROOT, "legacy-lint-lifecycle");
    mkdirSync(root);
    writeLifecyclePackage(root, {
      name: "noa-legacy-lint-lifecycle",
      version: "1.0.0",
      scripts: {
        prepare: "node -e \"require('node:fs').writeFileSync('LIFECYCLE_EXECUTED','yes')\"",
      },
    });
    const result = spawnSync(process.execPath, [SURFACE_LINTER, "--dir", root], { encoding: "utf8" });
    assert.equal(result.status, 2);
    assert.match(result.stderr, /mutable-directory mode is disabled/u);
    assert.equal(existsSync(join(root, "LIFECYCLE_EXECUTED")), false);
  });

  check("contained offline build never executes candidate lifecycle scripts", () => {
    const docker = resolveDocker();
    const image = spawnSync(docker, ["image", "inspect", NODE_IMAGE], { encoding: "utf8" });
    if (image.status !== 0) throw new SetupFailure("pinned Node image is unavailable for selftest");
    const source = join(TEST_ROOT, "build-lifecycle-source");
    mkdirSync(source);
    const sentinelCommand = "node -e \"require('node:fs').writeFileSync('LIFECYCLE_EXECUTED','yes')\"";
    const scripts = { install: sentinelCommand, postinstall: sentinelCommand, preinstall: sentinelCommand, prepare: sentinelCommand };
    writeLifecyclePackage(source, { name: "noa-build-lifecycle", version: "1.0.0", scripts });
    writeFileSync(join(source, "package-lock.json"), `${JSON.stringify({
      name: "noa-build-lifecycle",
      version: "1.0.0",
      lockfileVersion: 3,
      requires: true,
      packages: { "": { name: "noa-build-lifecycle", version: "1.0.0", scripts } },
    })}\n`);
    const cache = join(TEST_ROOT, "empty-cache");
    mkdirSync(cache);
    const name = `noa-build-selftest-${process.pid}-${randomBytes(4).toString("hex")}`;
    const args = createDockerRunArgs({
      buildNetwork: "offline",
      cacheInput: cache,
      commitTime: 0,
      containerName: name,
      driver: DRIVER,
      homedirOverride: NPM_HOMEDIR_OVERRIDE,
      mode: "build",
      platform: platform(),
      source,
      tsconfigs: [],
      uid: process.getuid(),
      gid: process.getgid(),
    });
    runDocker(docker, args, name);
    assert.equal(existsSync(join(source, "LIFECYCLE_EXECUTED")), false);
  });

  check("direct tarball publish bypasses package lifecycle and therefore cannot enforce staging", () => {
    const docker = resolveDocker();
    const tarball = join(TEST_ROOT, "direct-publish-bypass.tgz");
    const sentinel = join(TEST_ROOT, "DIRECT_PUBLISH_LIFECYCLE_EXECUTED");
    const sentinelCommand =
      "node -e \"require('node:fs').writeFileSync('/out/DIRECT_PUBLISH_LIFECYCLE_EXECUTED','yes')\"";
    const scripts = {
      postpack: sentinelCommand,
      postpublish: sentinelCommand,
      prepack: sentinelCommand,
      prepare: sentinelCommand,
      prepublishOnly: sentinelCommand,
      publish: sentinelCommand,
    };
    const parsed = createTarball(tarball, [{
      path: "package/package.json",
      content: `${JSON.stringify({ name: "noa-direct-publish-bypass", scripts, version: "1.0.0" })}\n`,
    }]);
    const before = parsed.tarballSha256;
    const name = `noa-direct-publish-selftest-${process.pid}-${randomBytes(4).toString("hex")}`;
    const args = [
      "run",
      "--rm",
      "--name", name,
      "--pull=never",
      `--platform=${platform()}`,
      "--network=none",
      "--cap-drop=ALL",
      "--security-opt=no-new-privileges",
      "--security-opt=seccomp=builtin",
      "--read-only",
      "--pids-limit=128",
      "--memory=512m",
      "--memory-swap=512m",
      "--cpus=1",
      "--user", `${process.getuid()}:${process.getgid()}`,
      "--workdir=/out",
      "--tmpfs", `/tmp:rw,nosuid,nodev,size=128m,mode=0700,uid=${process.getuid()},gid=${process.getgid()}`,
      "--mount", `type=bind,src=${TEST_ROOT},dst=/out`,
      "--env", "npm_config_userconfig=/tmp/user.npmrc",
      "--env", "npm_config_globalconfig=/tmp/global.npmrc",
      "--entrypoint=node",
      NODE_IMAGE,
      "/usr/local/lib/node_modules/npm/bin/npm-cli.js",
      "publish",
      "/out/direct-publish-bypass.tgz",
      "--dry-run",
      "--registry=http://127.0.0.1:9",
      "--cache=/tmp/npm-cache",
      "--no-audit",
      "--no-fund",
      "--loglevel=error",
    ];
    runDocker(docker, args, name);
    assert.equal(existsSync(sentinel), false);
    assert.equal(readSafeNpmTarball(tarball).tarballSha256, before);
  });

  check("shared frozen-pack API emits one no-network lifecycle-free NON-RELEASE tarball", () => {
    const source = join(TEST_ROOT, "shared-frozen-pack-source");
    const output = join(TEST_ROOT, "shared-frozen-pack-output");
    mkdirSync(source);
    const sentinelCommand =
      "node -e \"require('node:fs').writeFileSync('/out/LIFECYCLE_EXECUTED','yes')\"";
    writeLifecyclePackage(source, {
      files: ["index.js"],
      name: "noa-shared-frozen-pack",
      scripts: {
        postpack: sentinelCommand,
        prepack: sentinelCommand,
        prepare: sentinelCommand,
      },
      version: "1.0.0",
    });
    writeFileSync(join(source, "index.js"), "export const value = 1;\n");
    const before = readFileSync(join(source, "package.json"));
    setTreeWritable(source, false);
    try {
      const result = packFrozenPackageArtifact({ commitTime: 0, output, source });
      assert.equal(result.status, CANDIDATE_STATUS);
      assert.equal(result.releaseAuthorized, false);
      assert.equal(result.tarball.packlistCount, 2);
      assert.deepEqual(
        result.entries.map(({ content, path, sha256, size }) => ({
          content: content.toString("utf8"), path, sha256, size,
        })),
        readSafeNpmTarball(join(output, "noa-shared-frozen-pack-1.0.0.tgz")).entries
          .map(({ content, path, sha256, size }) => ({
            content: content.toString("utf8"), path, sha256, size,
          })),
      );
      assert.deepEqual(readdirSync(output), ["noa-shared-frozen-pack-1.0.0.tgz"]);
      assert.equal(existsSync(join(output, "LIFECYCLE_EXECUTED")), false);
      assert.equal(readFileSync(join(source, "package.json")).equals(before), true);
    } finally {
      setTreeWritable(source, true);
    }
  });

  check("fresh no-network pack containers defeat cross-package prepare swaps", () => {
    const docker = resolveDocker();
    const source = join(TEST_ROOT, "cross-package-source");
    const packageB = join(source, "packages", "b");
    mkdirSync(packageB, { recursive: true });
    const script =
      "node -e \"const f=require('node:fs');f.writeFileSync('/out/LIFECYCLE_EXECUTED','yes');" +
      "f.writeFileSync('/workspace/packages/b/README.md','A harmless replacement.\\n')\"";
    writeLifecyclePackage(source, {
      name: "noa-cross-package-a",
      version: "1.0.0",
      files: ["index.js"],
      scripts: { postpack: script, prepack: script, prepare: script },
    });
    writeFileSync(join(source, "index.js"), "export const value = 1;\n");
    writeLifecyclePackage(packageB, {
      name: "noa-cross-package-b",
      version: "1.0.0",
      files: ["README.md"],
    });
    const hostile = "This package is unhackable.\n";
    writeFileSync(join(packageB, "README.md"), hostile);
    const outA = join(TEST_ROOT, "cross-out-a");
    const outB = join(TEST_ROOT, "cross-out-b");
    mkdirSync(outA);
    mkdirSync(outB);
    for (const [index, packagePath, output] of [[0, ".", outA], [1, "packages/b", outB]]) {
      const name = `noa-pack-selftest-${process.pid}-${index}-${randomBytes(4).toString("hex")}`;
      const args = createDockerRunArgs({
        buildNetwork: "none",
        commitTime: 0,
        containerName: name,
        driver: DRIVER,
        homedirOverride: NPM_HOMEDIR_OVERRIDE,
        mode: "pack",
        output,
        packagePath,
        platform: platform(),
        source,
        uid: process.getuid(),
        gid: process.getgid(),
      });
      runDocker(docker, args, name);
    }
    assert.deepEqual(readdirSync(outA), ["noa-cross-package-a-1.0.0.tgz"]);
    assert.equal(existsSync(join(outA, "LIFECYCLE_EXECUTED")), false);
    assert.equal(readFileSync(join(packageB, "README.md"), "utf8"), hostile);
    const lint = spawnSync(
      process.execPath,
      [SURFACE_LINTER, "--tarball", join(outB, "noa-cross-package-b-1.0.0.tgz"), "--public-repos", PUBLIC_REPOS],
      { encoding: "utf8" },
    );
    assert.equal(lint.status, 1);
    assert.match(lint.stderr, /\[K5\] unhackable/u);
  });

  process.stdout.write(`stage-publish-artifacts selftest: PASS ${checks}/${checks}\n`);
} catch (error) {
  const status = error instanceof SetupFailure ? 2 : 1;
  process.stderr.write(
    `stage-publish-artifacts selftest: ${status === 2 ? "STOP" : "FAIL"} ${JSON.stringify(String(error && error.stack ? error.stack : error))}\n`,
  );
  process.exitCode = status;
} finally {
  rmSync(TEST_ROOT, { recursive: true, force: true });
  if (existsSync(TEST_ROOT)) {
    process.stderr.write("stage-publish-artifacts selftest: FAIL fixture residue remains\n");
    process.exitCode = 1;
  }
}
