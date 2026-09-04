#!/usr/bin/env node

// This entrypoint is never selected from the mutable checkout by the public staging command.
// `stage-publish-artifacts.mjs` materializes this file and its executor dependency from the exact
// requested Git commit before Node evaluates either module.
import {
  SetupFailure,
  ValidationFailure,
  stagePublishArtifacts,
  verifyCandidateSet,
} from "./publish-artifact-staging.mjs";

function usage(message) {
  if (message) process.stderr.write(`stage-publish-artifacts: ${message}\n`);
  process.stderr.write(
    "usage:\n" +
      "  node scripts/lib/stage-publish-artifacts.mjs --git-ref <commit> --output <new-dir> [--offline-cache <_cacache-dir>]\n" +
      "  node scripts/lib/stage-publish-artifacts.mjs --verify <candidate-dir> --git-ref <commit> [--offline-cache <_cacache-dir>]\n",
  );
  process.exit(2);
}

function parseArgs(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index];
    if (arg !== "--git-ref" && arg !== "--output" && arg !== "--offline-cache" && arg !== "--verify") {
      usage(`unknown argument ${JSON.stringify(arg)}`);
    }
    if (index + 1 >= argv.length || argv[index + 1].startsWith("--")) usage(`${arg} requires a value`);
    const key = arg.slice(2).replace(/-([a-z])/gu, (_match, letter) => letter.toUpperCase());
    if (options[key] !== undefined) usage(`duplicate argument ${arg}`);
    options[key] = argv[++index];
  }
  if (options.verify !== undefined) {
    if (options.output !== undefined) usage("--verify cannot be combined with --output");
    if (options.gitRef === undefined) usage("verification requires --git-ref");
    return {
      gitRef: options.gitRef,
      mode: "verify",
      offlineCache: options.offlineCache,
      path: options.verify,
    };
  }
  if (options.gitRef === undefined || options.output === undefined) usage("staging requires --git-ref and --output");
  return { mode: "stage", options };
}

async function main() {
  const parsed = parseArgs(process.argv.slice(2));
  if (parsed.mode === "verify") {
    const manifest = verifyCandidateSet(parsed.path, {
      gitRef: parsed.gitRef,
      ...(parsed.offlineCache === undefined ? {} : { offlineCache: parsed.offlineCache }),
    });
    process.stdout.write(
      `publish-artifact verification: PASS ${JSON.stringify({
        commit: manifest.source.commit,
        packages: manifest.packages.length,
        status: manifest.status,
      })}\n`,
    );
    return;
  }
  const result = stagePublishArtifacts(parsed.options);
  process.stdout.write(
    `publish-artifact staging: PASS ${JSON.stringify({
      commit: result.manifest.source.commit,
      output: result.output,
      packages: result.manifest.packages.length,
      status: result.manifest.status,
    })}\n`,
  );
}

main().catch((error) => {
  const message = String(error && error.stack ? error.stack : error);
  process.stderr.write(`stage-publish-artifacts: STOP ${JSON.stringify(message)}\n`);
  if (error instanceof SetupFailure) process.exit(2);
  if (error instanceof ValidationFailure) process.exit(1);
  process.exit(2);
});
