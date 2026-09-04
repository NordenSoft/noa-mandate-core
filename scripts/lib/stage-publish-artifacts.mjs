#!/usr/bin/env node

// Minimal bootstrap authority. It intentionally imports no mutable controller module: after it
// resolves --git-ref to one commit with closed Git configuration, it copies the exact executor and
// its direct parser dependency from that tree and asks a new Node process to execute those bytes.
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const THIS_DIR = dirname(fileURLToPath(import.meta.url));
const DEFAULT_REPO_ROOT = realpathSync(resolve(THIS_DIR, "../.."));
const GIT = "/usr/bin/git";
const EXACT_BOOTSTRAP_PATHS = Object.freeze([
  "scripts/lib/publish-artifact-executor.mjs",
  "scripts/lib/publish-artifact-staging.mjs",
  "scripts/lib/safe-npm-tarball.mjs",
]);
const CLOSED_GIT_ENV = Object.freeze({
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_NO_REPLACE_OBJECTS: "1",
  LANG: "C",
  LC_ALL: "C",
  PATH: "/usr/bin:/bin",
});

class BootstrapFailure extends Error {}

function stop(message) {
  throw new BootstrapFailure(message);
}

function gitText(repoRoot, args, label) {
  const result = spawnSync(GIT, args, {
    cwd: repoRoot,
    encoding: "utf8",
    env: CLOSED_GIT_ENV,
    maxBuffer: 64 * 1024 * 1024,
  });
  if (result.error || result.signal || result.status !== 0) stop(`${label} failed`);
  return result.stdout.trim();
}

function gitBlob(repoRoot, commit, path) {
  const result = spawnSync(GIT, ["show", `${commit}:${path}`], {
    cwd: repoRoot,
    env: CLOSED_GIT_ENV,
    maxBuffer: 64 * 1024 * 1024,
  });
  if (result.error || result.signal || result.status !== 0 || !Buffer.isBuffer(result.stdout)) {
    stop(`read exact Git blob ${path} failed`);
  }
  return Buffer.from(result.stdout);
}

function parseAndPinGitRef(argv) {
  let gitRef;
  let repoRoot = DEFAULT_REPO_ROOT;
  const exactArgs = [];
  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index];
    if (arg === "--repo-root") {
      if (index + 1 >= argv.length || argv[index + 1].startsWith("--")) stop("--repo-root requires a directory");
      try {
        repoRoot = realpathSync(argv[++index]);
        if (!statSync(repoRoot).isDirectory()) stop("--repo-root is not a directory");
      } catch (error) {
        if (error instanceof BootstrapFailure) throw error;
        stop("--repo-root is unavailable");
      }
      continue;
    }
    exactArgs.push(arg);
    if (arg !== "--git-ref") continue;
    if (gitRef !== undefined || index + 1 >= argv.length || argv[index + 1].startsWith("--")) {
      stop("--git-ref must appear exactly once with a value");
    }
    gitRef = argv[index + 1];
    exactArgs.push(argv[++index]);
  }
  if (gitRef === undefined) stop("--git-ref is required before immutable controller materialization");
  const commit = gitText(repoRoot, ["rev-parse", "--verify", "--end-of-options", `${gitRef}^{commit}`], "resolve exact Git commit");
  if (!/^[0-9a-f]{40,64}$/u.test(commit)) stop("resolved Git commit is malformed");
  for (let index = 0; index < exactArgs.length; index++) {
    if (exactArgs[index] === "--git-ref") exactArgs[index + 1] = commit;
  }
  return { commit, exactArgs, repoRoot };
}

function materializeExactBootstrap(repoRoot, commit) {
  const root = mkdtempSync(join(tmpdir(), "noa-publish-artifact-bootstrap-"));
  try {
    for (const path of EXACT_BOOTSTRAP_PATHS) {
      const bytes = gitBlob(repoRoot, commit, path);
      const target = join(root, ...path.split("/"));
      mkdirSync(dirname(target), { recursive: true, mode: 0o700 });
      writeFileSync(target, bytes, { flag: "wx", mode: 0o400 });
    }
    return root;
  } catch (error) {
    rmSync(root, { force: true, recursive: true });
    throw error;
  }
}

function main() {
  const { commit, exactArgs, repoRoot } = parseAndPinGitRef(process.argv.slice(2));
  let root;
  try {
    root = materializeExactBootstrap(repoRoot, commit);
    const executor = join(root, "scripts", "lib", "publish-artifact-executor.mjs");
    const result = spawnSync(process.execPath, [executor, ...exactArgs], {
      cwd: repoRoot,
      encoding: "utf8",
      env: { ...process.env, NOA_PUBLISH_ARTIFACT_REPO_ROOT: repoRoot },
      maxBuffer: 512 * 1024 * 1024,
    });
    if (result.stdout) process.stdout.write(result.stdout);
    if (result.stderr) process.stderr.write(result.stderr);
    if (result.error || result.signal || result.status === null) stop("exact Git executor could not complete");
    return result.status;
  } finally {
    if (root !== undefined) rmSync(root, { force: true, recursive: true });
  }
}

try { process.exit(main()); }
catch (error) {
  const message = error instanceof BootstrapFailure ? error.message : "exact Git bootstrap materialization failed";
  process.stderr.write(`stage-publish-artifacts: STOP ${JSON.stringify(message)}\n`);
  process.exit(2);
}
