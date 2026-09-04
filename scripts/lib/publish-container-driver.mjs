#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import {
  cpSync,
  existsSync,
  lstatSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { createRequire } from "node:module";
import { basename, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const WORKSPACE = "/workspace";
const SCRATCH = "/noa-tmp";
const OUTPUT = "/out";
export const PUBLISH_CONTAINER_TOOLCHAIN = Object.freeze({
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
const EXPECTED_NODE = PUBLISH_CONTAINER_TOOLCHAIN.node;
const EXPECTED_NPM = PUBLISH_CONTAINER_TOOLCHAIN.npm;
const EXPECTED_ARBORIST = PUBLISH_CONTAINER_TOOLCHAIN.packStack.arborist;
const EXPECTED_NPM_PACKLIST = PUBLISH_CONTAINER_TOOLCHAIN.packStack.npmPacklist;
const EXPECTED_TAR = PUBLISH_CONTAINER_TOOLCHAIN.packStack.tar;
const NPM_ROOT = "/usr/local/lib/node_modules/npm";
const NPM_CLI = `${NPM_ROOT}/bin/npm-cli.js`;
const NPM_HOMEDIR_PRELOAD = "/noa-npm-homedir-override.cjs";
const requireFromNpm = createRequire(`${NPM_ROOT}/package.json`);
const FORBIDDEN_PATH_CHARS_RE = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/u;

function fail(message) {
  throw new Error(`publish-container-driver: ${message}`);
}

function assertEnvironment(mode) {
  const buildNetwork = process.env.NOA_BUILD_NETWORK;
  if (mode === "build" && buildNetwork !== "online" && buildNetwork !== "offline") {
    fail("NOA_BUILD_NETWORK must be online or offline in build mode");
  }
  if (mode === "pack" && buildNetwork !== "none") {
    fail("NOA_BUILD_NETWORK must be none in pack mode");
  }
  const allowed = new Set([
    "HOSTNAME",
    "LANG",
    "LC_ALL",
    "NODE_VERSION",
    "NOA_BUILD_NETWORK",
    "NOA_NPM_HOMEDIR",
    "NO_COLOR",
    "PATH",
    "PWD",
    "SHLVL",
    "SOURCE_DATE_EPOCH",
    "TEMP",
    "TMP",
    "TZ",
    "TMPDIR",
    "YARN_VERSION",
    "_",
    "CI",
    "npm_config_audit",
    "npm_config_cache",
    "npm_config_color",
    "npm_config_fund",
    "npm_config_globalconfig",
    "npm_config_ignore_scripts",
    "npm_config_offline",
    "npm_config_progress",
    "npm_config_script_shell",
    "npm_config_update_notifier",
    "npm_config_userconfig",
  ]);
  const unexpected = Object.keys(process.env).filter((name) => !allowed.has(name)).sort();
  if (unexpected.length > 0) fail(`unexpected environment names: ${unexpected.join(", ")}`);
  const exact = {
    LANG: "C.UTF-8",
    LC_ALL: "C.UTF-8",
    NODE_VERSION: EXPECTED_NODE,
    NO_COLOR: "1",
    NOA_NPM_HOMEDIR: "/noa-tmp/npm-home",
    TZ: "UTC",
    TEMP: SCRATCH,
    TMP: SCRATCH,
    TMPDIR: SCRATCH,
    CI: "1",
    npm_config_audit: "false",
    npm_config_cache: `${SCRATCH}/npm-cache`,
    npm_config_color: "false",
    npm_config_fund: "false",
    npm_config_globalconfig: `${SCRATCH}/global.npmrc`,
    npm_config_ignore_scripts: "true",
    npm_config_offline: mode === "pack" || buildNetwork === "offline" ? "true" : "false",
    npm_config_progress: "false",
    npm_config_script_shell: "/bin/false",
    npm_config_update_notifier: "false",
    npm_config_userconfig: `${SCRATCH}/user.npmrc`,
  };
  for (const [name, value] of Object.entries(exact)) {
    if (process.env[name] !== value) fail(`environment ${name} is not the closed value`);
  }
  if (!/^[0-9]+$/u.test(process.env.SOURCE_DATE_EPOCH ?? "")) {
    fail("SOURCE_DATE_EPOCH is not a non-negative integer");
  }
  if (process.version !== `v${EXPECTED_NODE}`) {
    fail(`Node version ${process.version} does not equal v${EXPECTED_NODE}`);
  }
  const npm = JSON.parse(readFileSync(`${NPM_ROOT}/package.json`, "utf8"));
  if (npm.version !== EXPECTED_NPM) fail(`npm version ${npm.version} does not equal ${EXPECTED_NPM}`);
  const internals = [
    ["@npmcli/arborist", EXPECTED_ARBORIST],
    ["npm-packlist", EXPECTED_NPM_PACKLIST],
    ["tar", EXPECTED_TAR],
  ];
  for (const [name, version] of internals) {
    const actual = requireFromNpm(`${name}/package.json`).version;
    if (actual !== version) fail(`${name} version ${actual} does not equal ${version}`);
  }
}

function assertInsideWorkspace(candidate, label) {
  if (typeof candidate !== "string" || candidate === "" || candidate.startsWith("/") ||
      candidate.includes("\\") || FORBIDDEN_PATH_CHARS_RE.test(candidate)) {
    fail(`${label} is not a safe relative path: ${JSON.stringify(candidate)}`);
  }
  if (candidate !== "." && candidate.split("/").some((part) => part === "" || part === "." || part === "..")) {
    fail(`${label} is not a canonical relative path: ${JSON.stringify(candidate)}`);
  }
  const absolute = resolve(WORKSPACE, candidate);
  const rel = relative(WORKSPACE, absolute);
  if (rel === ".." || rel.startsWith(`..${sep}`) || resolve(absolute) !== absolute) {
    fail(`${label} escaped the workspace: ${JSON.stringify(candidate)}`);
  }
  return absolute;
}

function assertKernelConfinement() {
  const status = readFileSync("/proc/self/status", "utf8");
  if (!/^NoNewPrivs:\s+1$/mu.test(status)) fail("no-new-privileges is not active");
  if (!/^Seccomp:\s+2$/mu.test(status)) fail("seccomp filtering is not active");
  if (!/^CapEff:\s+0+$/mu.test(status)) fail("effective Linux capabilities are not empty");
  const probe = "/.noa-root-write-probe";
  try {
    writeFileSync(probe, "must fail", { flag: "wx" });
  } catch (error) {
    if (error && (error.code === "EROFS" || error.code === "EACCES" || error.code === "EPERM")) return;
    throw error;
  }
  try { rmSync(probe, { force: true }); } catch {}
  fail("container root filesystem is writable");
}

function spawnChecked(label, args, cwd) {
  const result = spawnSync(process.execPath, args, {
    cwd,
    env: process.env,
    stdio: "inherit",
  });
  if (result.error) fail(`${label} could not start: ${result.error.message}`);
  if (result.signal) fail(`${label} terminated by signal ${result.signal}`);
  if (result.status !== 0) fail(`${label} exited ${String(result.status)}`);
}

function npmArgs(args) {
  return ["--require", NPM_HOMEDIR_PRELOAD, ...args];
}

function lifecycleFixture(prefix) {
  const root = mkdtempSync(join(SCRATCH, `${prefix}-`));
  const sentinel = join(root, "LIFECYCLE_EXECUTED");
  const command = `${JSON.stringify(process.execPath)} -e ` +
    JSON.stringify(`require("node:fs").writeFileSync(${JSON.stringify(sentinel)}, "executed")`);
  const scripts = { install: command, postinstall: command, preinstall: command, prepare: command };
  writeFileSync(
    join(root, "package.json"),
    `${JSON.stringify({ name: "noa-lifecycle-sentinel", version: "1.0.0", scripts })}\n`,
  );
  writeFileSync(
    join(root, "package-lock.json"),
    `${JSON.stringify({
      name: "noa-lifecycle-sentinel",
      version: "1.0.0",
      lockfileVersion: 3,
      requires: true,
      packages: {
        "": { name: "noa-lifecycle-sentinel", version: "1.0.0", scripts },
      },
    })}\n`,
  );
  return { root, sentinel };
}

function proveNpmCiIgnoresLifecycle() {
  const fixture = lifecycleFixture("npm-ci-lifecycle");
  try {
    writeFileSync(join(fixture.root, ".npmrc"), "ignore-scripts=false\nscript-shell=/bin/sh\n");
    spawnChecked(
      "npm ci ignore-scripts proof",
      npmArgs([
        NPM_CLI,
        "ci",
        "--ignore-scripts",
        `--userconfig=${process.env.npm_config_userconfig}`,
        `--globalconfig=${process.env.npm_config_globalconfig}`,
        "--no-audit",
        "--no-fund",
      ]),
      fixture.root,
    );
    if (existsSync(fixture.sentinel)) fail("npm ci executed a lifecycle sentinel under ignore-scripts");
  } finally {
    rmSync(fixture.root, { recursive: true, force: true });
  }
}

function parseRepeatedOption(argv, option) {
  const values = [];
  for (let index = 0; index < argv.length; index++) {
    if (argv[index] !== option) fail(`unknown argument ${JSON.stringify(argv[index])}`);
    if (index + 1 >= argv.length) fail(`${option} requires a value`);
    values.push(argv[++index]);
  }
  return values;
}

function build(argv) {
  const tsconfigs = parseRepeatedOption(argv, "--tsconfig");
  if (new Set(tsconfigs).size !== tsconfigs.length) {
    fail("build requires a unique --tsconfig list");
  }
  writeFileSync(process.env.npm_config_globalconfig, "", { flag: "wx" });
  writeFileSync(process.env.npm_config_userconfig, "", { flag: "wx" });
  proveNpmCiIgnoresLifecycle();
  if (process.env.NOA_BUILD_NETWORK === "offline") {
    const cacheInput = "/cache-input";
    const cacheStat = lstatSync(cacheInput);
    if (cacheStat.isSymbolicLink() || !cacheStat.isDirectory()) {
      fail("offline cache input is not a real directory");
    }
    mkdirSync(process.env.npm_config_cache, { recursive: true });
    cpSync(cacheInput, join(process.env.npm_config_cache, "_cacache"), {
      recursive: true,
      dereference: false,
      errorOnExist: true,
      force: false,
    });
  }
  spawnChecked(
    "npm ci",
    npmArgs([
      NPM_CLI,
      "ci",
      "--ignore-scripts",
      `--userconfig=${process.env.npm_config_userconfig}`,
      `--globalconfig=${process.env.npm_config_globalconfig}`,
      "--no-audit",
      "--no-fund",
    ]),
    WORKSPACE,
  );
  if (tsconfigs.length > 0) {
    const tsc = join(WORKSPACE, "node_modules", "typescript", "bin", "tsc");
    const tscStat = lstatSync(tsc);
    if (tscStat.isSymbolicLink() || !tscStat.isFile()) fail("TypeScript compiler is not a real file");
    for (const tsconfig of tsconfigs) {
      const configPath = assertInsideWorkspace(tsconfig, "TypeScript config");
      const stat = lstatSync(configPath);
      if (stat.isSymbolicLink() || !stat.isFile()) fail(`TypeScript config is not a real file: ${tsconfig}`);
      spawnChecked(`tsc ${tsconfig}`, [tsc, "-p", configPath], WORKSPACE);
    }
  }
  process.stdout.write(`NOA_BUILD_RESULT ${JSON.stringify({ tsconfigs })}\n`);
}

function assertNoNetworkNamespace() {
  const ipv4Routes = readFileSync("/proc/net/route", "utf8").trim().split("\n").slice(1).filter(Boolean);
  if (ipv4Routes.length !== 0) {
    fail(`pack container has IPv4 routes: ${JSON.stringify(ipv4Routes)}`);
  }
  const ipv6Routes = readFileSync("/proc/net/ipv6_route", "utf8").trim().split("\n").filter(Boolean);
  if (ipv6Routes.some((line) => line.trim().split(/\s+/u).at(-1) !== "lo")) {
    fail(`pack container has a non-loopback IPv6 route: ${JSON.stringify(ipv6Routes)}`);
  }
  const ipv6Addresses = readFileSync("/proc/net/if_inet6", "utf8").trim().split("\n").filter(Boolean);
  if (ipv6Addresses.some((line) => line.trim().split(/\s+/u).at(-1) !== "lo")) {
    fail(`pack container has a non-loopback IPv6 address: ${JSON.stringify(ipv6Addresses)}`);
  }
}

function assertReadOnlyWorkspace() {
  const probe = join(WORKSPACE, ".noa-read-only-probe");
  try {
    writeFileSync(probe, "must fail", { flag: "wx" });
  } catch (error) {
    if (error && (error.code === "EROFS" || error.code === "EACCES" || error.code === "EPERM")) return;
    throw error;
  }
  try { rmSync(probe, { force: true }); } catch {}
  fail("pack container workspace mount is writable");
}

function validatePacklistFile(packageRoot, file, seen) {
  if (typeof file !== "string" || file === "" || file.startsWith("/") || file.startsWith("@") ||
      file.includes("\\") || FORBIDDEN_PATH_CHARS_RE.test(file)) {
    fail(`npm-packlist returned an unsafe path: ${JSON.stringify(file)}`);
  }
  const components = file.split("/");
  if (components.some((component) => component === "" || component === "." || component === "..")) {
    fail(`npm-packlist returned a non-canonical path: ${JSON.stringify(file)}`);
  }
  if (seen.has(file)) fail(`npm-packlist returned duplicate path ${JSON.stringify(file)}`);
  seen.add(file);
  const absolute = resolve(packageRoot, file);
  const rel = relative(packageRoot, absolute);
  if (rel === ".." || rel.startsWith(`..${sep}`)) fail(`npm-packlist path escaped package: ${file}`);
  const stat = lstatSync(absolute);
  if (stat.isSymbolicLink() || !stat.isFile()) {
    fail(`npm-packlist path is not a real regular file: ${JSON.stringify(file)}`);
  }
  const resolved = realpathSync(absolute);
  const realRoot = realpathSync(packageRoot);
  const realRel = relative(realRoot, resolved);
  if (realRel === ".." || realRel.startsWith(`..${sep}`)) {
    fail(`npm-packlist path resolved outside package: ${JSON.stringify(file)}`);
  }
  return file;
}

async function packWithoutLifecycle(packageRoot, destination) {
  const Arborist = requireFromNpm("@npmcli/arborist");
  const packlist = requireFromNpm("npm-packlist");
  const tar = requireFromNpm("tar");
  const tarCreateOptions = requireFromNpm(
    `${NPM_ROOT}/node_modules/pacote/lib/util/tar-create-options.js`,
  );
  const manifest = JSON.parse(readFileSync(join(packageRoot, "package.json"), "utf8"));
  const tree = await new Arborist({ path: packageRoot }).loadActual();
  const files = await packlist(tree, { path: packageRoot });
  const seen = new Set();
  const checked = files.map((file) => validatePacklistFile(packageRoot, file, seen));
  if (checked.length === 0 || !seen.has("package.json")) {
    fail("npm-packlist did not produce a non-empty package containing package.json");
  }
  const filename = `${manifest.name}-${manifest.version}.tgz`.replace(/^@/u, "").replace("/", "-");
  if (basename(filename) !== filename || !/^[A-Za-z0-9@._+-]+\.tgz$/u.test(filename)) {
    fail(`package metadata produced an unsafe tarball filename: ${JSON.stringify(filename)}`);
  }
  const destinationPath = join(destination, filename);
  await tar.c(
    { ...tarCreateOptions({ ...manifest, _resolved: packageRoot }), file: destinationPath },
    checked,
  );
  return { filename, packlist: checked };
}

async function provePackerHasNoLifecyclePath() {
  const fixture = lifecycleFixture("packer-lifecycle");
  try {
    const manifest = JSON.parse(readFileSync(join(fixture.root, "package.json"), "utf8"));
    const command = manifest.scripts.prepare;
    manifest.scripts = {
      install: command,
      postinstall: command,
      postpack: command,
      preinstall: command,
      prepack: command,
      prepare: command,
    };
    writeFileSync(join(fixture.root, "package.json"), `${JSON.stringify(manifest)}\n`);
    const destination = join(fixture.root, "out");
    mkdirSync(destination);
    await packWithoutLifecycle(fixture.root, destination);
    if (existsSync(fixture.sentinel)) fail("lifecycle-free packer executed a lifecycle sentinel");
    const produced = readdirSync(destination);
    if (produced.length !== 1 || !produced[0].endsWith(".tgz")) {
      fail(`lifecycle-free packer proof produced unexpected output: ${JSON.stringify(produced)}`);
    }
  } finally {
    rmSync(fixture.root, { recursive: true, force: true });
  }
}

async function pack(argv) {
  if (argv.length !== 2 || argv[0] !== "--package") fail("pack requires exactly --package <path>");
  assertNoNetworkNamespace();
  assertReadOnlyWorkspace();
  const packageRoot = assertInsideWorkspace(argv[1], "package");
  const packageStat = lstatSync(packageRoot);
  if (packageStat.isSymbolicLink() || !packageStat.isDirectory()) fail("package is not a real directory");
  const before = readdirSync(OUTPUT);
  if (before.length !== 0) fail(`pack output is not empty: ${JSON.stringify(before)}`);
  await provePackerHasNoLifecyclePath();
  const { filename, packlist } = await packWithoutLifecycle(packageRoot, OUTPUT);
  const produced = readdirSync(OUTPUT);
  if (produced.length !== 1 || produced[0] !== filename) {
    fail(`pack produced unexpected output: ${JSON.stringify(produced)}`);
  }
  process.stdout.write(
    `NOA_PACK_RESULT ${JSON.stringify({ filename, package: argv[1], packlistCount: packlist.length })}\n`,
  );
}

async function main() {
  const [mode, ...argv] = process.argv.slice(2);
  if (mode !== "build" && mode !== "pack") fail(`unknown mode ${JSON.stringify(mode)}`);
  assertEnvironment(mode);
  assertKernelConfinement();
  if (mode === "pack" || process.env.NOA_BUILD_NETWORK === "offline") {
    assertNoNetworkNamespace();
  }
  if (mode === "build") build(argv);
  else if (mode === "pack") await pack(argv);
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`${String(error && error.stack ? error.stack : error)}\n`);
    process.exit(1);
  });
}
