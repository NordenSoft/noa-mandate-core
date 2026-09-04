/**
 * PROOF RESOLUTION — is the claimed control a REAL, RUNNING test? Answered structurally.
 *
 * ── WHY THIS REPLACED A LINE SCAN (P0-13, 2026-07-31) ───────────────────────────────────────────
 * The first version of this check read the marker's LINE and rejected a disabled proof only in the
 * exact same-line spelling `test.skip(` / `test.todo(`. MEASURED: converting the three gate proofs
 * to node:test's OBJECT form
 *
 *     test("[PROOF:RES-PAR-GATE-KEYRING] …", { skip: true }, () => { … })
 *
 * gave `gate: pass 211, skipped 3`, node exit 0, and `lint:resolver-parity` **exit 0 still calling
 * every proof live**. The gate built to close P0-7 — "a claimed control must exist and run" — was
 * bypassed by a different spelling of the same intent. That is the P0-7 defect one layer up: the
 * control existed and did not measure what its name claimed.
 *
 * ── P0-15b (2026-07-31): A SENTENCE THAT STOOD HERE IS WITHDRAWN ────────────────────────────────
 * The paragraph below used to read, verbatim: "A line scan cannot fix this by adding spellings.
 * `{ skip: true }` may sit on the next line, the options object may be a variable, the whole block
 * may be inside a block comment, and `describe` may be skipped around a live-looking `test`."
 * Written to justify replacing the line scan, it names "the options object may be a variable" as a
 * case this module handles — and `optionsVerdict` then does `if (!ts.isObjectLiteralExpression(arg))
 * continue`, which skips exactly that case: `const opts = { skip: true }; test(m, opts, fn)`
 * resolved LIVE while the runner skipped it. A comment claiming a property the code does not
 * deliver, for the third time, inside the fix for the second occurrence. The property is now
 * delivered — by the RUNNER TIER below (P0-15), not by this parse, which is exactly the point:
 *
 * ── THE INSTRUMENT WAS THE ROOT CAUSE (P0-15) ───────────────────────────────────────────────────
 * This control was bypassed in three consecutive rounds: a line scan (batch A), then this AST parse
 * (batch B) — each round's fix added static sophistication and was defeated by a spelling it did
 * not anticipate (measured: an indirect options object, a computed `["skip"]` key, an aliased
 * `describe.skip`, a dead `if (false)` branch — all four resolved LIVE here while a real run
 * skipped or never executed them). Static analysis is a MODEL of the runner; the runner is ground
 * truth. So liveness is now answered by executing the proof file with the repository's versioned
 * TestsStream reporter: a registered proof must produce a runner-owned PASS event in a completed,
 * exit-zero one-file run. Test stdout/stderr, built-in reporter glyphs and presentation text are
 * never evidence. The spelling of "skip" stops mattering forever. The AST tier below is retained
 * as fast, precise DIAGNOSIS (it names
 * WHICH spelling disabled a proof, and fails cheaply before any build is spent) — its verdict is
 * advisory; the runner's is authoritative.
 *
 * COST, stated as a decision and then MEASURED rather than estimated: the runner tier builds each
 * compiled package (`npm run build` — which also kills the stale-`dist/` hazard recorded in
 * evidence/test/root-activation-window.test.ts) and executes each proof-bearing test FILE once.
 * Measured on the current four files: ~2.3s total (each `tsc -p` here is ~0.6s; the expensive part
 * of a full `npm test` is vector/fixture generation, which this tier deliberately does not run —
 * proof files read COMMITTED fixtures). The first draft of this sentence said "tens of seconds"
 * from memory; the measurement said otherwise, and an unmeasured cost claim has no more standing
 * here than an unmeasured security claim. Paid inside `lint:resolver-parity` per invocation.
 *
 * The AST tier parses the file with the TypeScript compiler API and asks structural questions:
 *
 *   1. the marker is a STRING LITERAL that is the first argument of a call to `test` / `it`
 *      (any spelling: `test`, `it`, `node:test`'s imported alias). A marker inside a comment is not
 *      a node, so it can never resolve — comments are not parsed as expressions.
 *   2. the callee is not `.skip` / `.todo` on any spelling, AND
 *   3. no argument is an object literal carrying `skip: <truthy>` or `todo: <truthy>`, AND
 *   4. no enclosing `describe` / `suite` call is skipped the same two ways.
 *
 * ── STATED LIMIT ────────────────────────────────────────────────────────────────────────────────
 * A dynamic disable — `{ skip: someRuntimeFlag }`, `if (cond) return;` in the body, an env var — is
 * NOT detected here; a truthiness the parser cannot evaluate is reported as an UNDECIDABLE finding
 * rather than silently accepted, because "I could not tell" and "it runs" must never be the same
 * value (the repository's standing verdict rule). Full behavioural proof that a test EXECUTED is a
 * different instrument: the knockout runner, which observes the suite's failure set change.
 */
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import ts from "typescript";
import { fileURLToPath } from "node:url";
import { PROOF_EVENT_PROTOCOL, PROOF_EVENT_REPORTER } from "./proof-event-contract.mjs";

const TEST_FNS = new Set(["test", "it"]);
const SUITE_FNS = new Set(["describe", "suite"]);
const DISABLING_PROPS = new Set(["skip", "todo"]);
export { PROOF_EVENT_REPORTER } from "./proof-event-contract.mjs";
export const TYPESCRIPT_TEST_REGISTER = fileURLToPath(
  new URL("./typescript-test-register.mjs", import.meta.url),
);

/**
 * The one canonical Node test-runner invocation used by both production proof runs and their
 * selftest. Never consume Node's version/TTY-dependent default reporter as a machine contract.
 */
export function proofRunnerNodeArgs(testFile, { importModule } = {}) {
  return [
    ...(importModule === undefined ? [] : ["--import", importModule]),
    "--test",
    `--test-reporter=${PROOF_EVENT_REPORTER}`,
    testFile,
  ];
}

function scriptKindFor(file) {
  if (file.endsWith(".tsx")) return ts.ScriptKind.TSX;
  if (file.endsWith(".jsx")) return ts.ScriptKind.JSX;
  return ts.ScriptKind.TS;
}

/** `test` / `it` / `describe` — bare, or `x.skip` / `x.todo` / `x.only`. Returns {base, modifier}. */
function calleeParts(expr) {
  if (ts.isIdentifier(expr)) return { base: expr.text, modifier: null };
  if (ts.isPropertyAccessExpression(expr) && ts.isIdentifier(expr.expression) && ts.isIdentifier(expr.name)) {
    return { base: expr.expression.text, modifier: expr.name.text };
  }
  return { base: null, modifier: null };
}

/**
 * Does any argument carry a DISABLING option (`skip`/`todo`)?
 * @returns {"disabled"|"live"|"undecidable"}
 */
function optionsVerdict(call) {
  let verdict = "live";
  for (const arg of call.arguments) {
    if (!ts.isObjectLiteralExpression(arg)) continue;
    for (const p of arg.properties) {
      // A SPREAD can carry `skip` from anywhere, so the object's contents are not knowable here.
      // Found by this module's own selftest: `test(name, { ...o }, fn)` was read as LIVE, which is
      // the same bypass class as P0-13 one spelling further out.
      if (ts.isSpreadAssignment(p)) { verdict = "undecidable"; continue; }
      const name = p.name && (ts.isIdentifier(p.name) || ts.isStringLiteral(p.name)) ? p.name.text : null;
      if (name === null || !DISABLING_PROPS.has(name)) continue;
      if (!ts.isPropertyAssignment(p)) { verdict = "undecidable"; continue; } // shorthand / method
      const v = p.initializer;
      if (v.kind === ts.SyntaxKind.TrueKeyword || ts.isStringLiteral(v)) return "disabled"; // `skip: "reason"` disables too
      if (v.kind === ts.SyntaxKind.FalseKeyword) continue; // explicitly enabled
      verdict = "undecidable"; // a variable, a call, a template — the parser cannot decide truthiness
    }
  }
  return verdict;
}

/**
 * Resolve one proof marker inside one file.
 *
 * @param {string} absFile
 * @param {string} marker exact substring expected in the test's NAME string literal
 * @returns {{ status: "live"|"disabled"|"absent"|"undecidable", detail: string, matches: number,
 *   sites: Array<{name: string, file: string, line: number, column: number, status: string}> }}
 */
export function resolveProof(absFile, marker) {
  const text = fs.readFileSync(absFile, "utf8");
  const sf = ts.createSourceFile(absFile, text, ts.ScriptTarget.Latest, true, scriptKindFor(absFile));

  const results = [];

  const visit = (node) => {
    if (ts.isCallExpression(node)) {
      const { base, modifier } = calleeParts(node.expression);
      const first = node.arguments[0];
      const isMarkerCall =
        base !== null &&
        TEST_FNS.has(base) &&
        first !== undefined &&
        (ts.isStringLiteral(first) || ts.isNoSubstitutionTemplateLiteral(first)) &&
        first.text.includes(marker);

      if (isMarkerCall) {
        // node:test reports a modifier call (`test.skip`, `test.todo`, `test.only`) at the modifier
        // property's start, while a bare call is reported at the call expression's start.
        const locationNode = ts.isPropertyAccessExpression(node.expression) ? node.expression.name : node;
        const { line, character } = sf.getLineAndCharacterOfPosition(locationNode.getStart());
        const reasons = [];
        let status = "live";

        if (modifier === "skip" || modifier === "todo") {
          status = "disabled";
          reasons.push(`${base}.${modifier}(...)`);
        }
        const opts = optionsVerdict(node);
        if (opts === "disabled") { status = "disabled"; reasons.push("an options object sets skip/todo"); }
        else if (opts === "undecidable" && status === "live") { status = "undecidable"; reasons.push("skip/todo is set to a value this parser cannot evaluate"); }

        // An enclosing suite disables everything inside it, however the inner test is spelled.
        for (let n = node.parent; n; n = n.parent) {
          if (!ts.isCallExpression(n)) continue;
          const outer = calleeParts(n.expression);
          if (outer.base === null || !SUITE_FNS.has(outer.base)) continue;
          if (outer.modifier === "skip" || outer.modifier === "todo") {
            status = "disabled";
            reasons.push(`an enclosing ${outer.base}.${outer.modifier}(...)`);
          }
          const oo = optionsVerdict(n);
          if (oo === "disabled") { status = "disabled"; reasons.push(`an enclosing ${outer.base}(...) sets skip/todo`); }
          else if (oo === "undecidable" && status === "live") { status = "undecidable"; reasons.push(`an enclosing ${outer.base}(...) sets skip/todo to an unevaluable value`); }
        }

        results.push({
          status,
          name: first.text,
          file: path.resolve(absFile),
          line: line + 1,
          column: character + 1,
          reasons,
        });
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);

  if (results.length === 0) {
    // Deliberately distinguishes "not there at all" from "there but in a comment": a marker that
    // appears in the text yet parses to no test call is a doc mention — the exact P0-7 shape.
    const mentioned = text.includes(marker);
    return {
      status: "absent",
      matches: 0,
      sites: [],
      detail: mentioned
        ? "the marker appears in the file but NOT as the name of a test() / it() call — a comment or " +
          "doc mention of a control is not a control (this is the P0-7 shape exactly)"
        : "no test() / it() call carries this marker",
    };
  }

  const live = results.filter((r) => r.status === "live");
  if (live.length > 0) return {
    status: "live",
    matches: results.length,
    sites: results.map(({ name, file, line, column, status }) => ({ name, file, line, column, status })),
    detail: `${live.length} live test(s) at line(s) ${live.map((r) => r.line).join(", ")}`,
  };

  const undecidable = results.filter((r) => r.status === "undecidable");
  if (undecidable.length > 0) {
    return {
      status: "undecidable",
      matches: results.length,
      sites: results.map(({ name, file, line, column, status }) => ({ name, file, line, column, status })),
      detail: `line(s) ${undecidable.map((r) => r.line).join(", ")}: ${[...new Set(undecidable.flatMap((r) => r.reasons))].join("; ")}`,
    };
  }

  return {
    status: "disabled",
    matches: results.length,
    sites: results.map(({ name, file, line, column, status }) => ({ name, file, line, column, status })),
    detail: `line(s) ${results.map((r) => r.line).join(", ")}: ${[...new Set(results.flatMap((r) => r.reasons))].join("; ")}`,
  };
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// THE RUNNER TIER (P0-15) — ground truth. Everything above is diagnosis; this is the verdict.
// ─────────────────────────────────────────────────────────────────────────────────────────────────

/**
 * How to RUN the file a proof lives in. ONE derivation rule, no per-entry recipe drift:
 *   - `packages/e2e-demo/test/*` runs from source via tsx (that is how its own suite runs);
 *   - every other `packages/<p>/test/*` builds first (`npm run build` — a stale `dist/` measuring
 *     yesterday's code is the exact hazard recorded in evidence/test/root-activation-window.test.ts)
 *     and then executes the COMPILED test file with `node --test`.
 * A file outside `packages/<p>/test/` has no recipe and fails closed at the caller.
 */
const RESOLVE_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
/** The one build script this resolver knows how to run WITHOUT npm. */
const TRUSTED_BUILD_SCRIPT = "tsc -p tsconfig.json";

/**
 * Compile a proof package with its OWN TypeScript, started as an ordinary Node script.
 *
 * ── WHY NOT `npm run build` (reproduced 2026-08-24) ───────────────────────────────────────────
 * This step used to be `npm run build`, and it runs inside the evidence-bearing gate child. npm
 * resolves `node-options` and `script-shell` from the PROJECT `.npmrc` next to the package, and
 * project rc beats environment config: MEASURED with a `.npmrc` carrying
 * `script-shell=/tmp/attacker-shell` and `node-options=--import=/tmp/attacker.mjs`, `npm config get`
 * returned exactly those values even with `npm_config_node_options` set empty in the environment.
 * There is no environment variable that switches a project rc off, so the only provable fix is to
 * stop starting npm here at all.
 *
 * The build script is verified to be EXACTLY the one shape this resolver can reproduce; anything
 * else is refused rather than silently compiled differently from what the package declares. That
 * matters for a package like `signer-core`, whose build also runs a dependency-hash check: this must
 * fail loudly rather than quietly skip it.
 */
function trustedBuildStep(cwd) {
  const manifestPath = path.join(RESOLVE_ROOT, cwd, "package.json");
  const build = JSON.parse(fs.readFileSync(manifestPath, "utf8")).scripts?.build;
  if (build !== TRUSTED_BUILD_SCRIPT) {
    throw new Error(
      `${cwd}: build script ${JSON.stringify(build)} is not the exact reproducible build ` +
      `${JSON.stringify(TRUSTED_BUILD_SCRIPT)}; a proof recipe will not start npm to run it`,
    );
  }
  const compiler = path.join(RESOLVE_ROOT, cwd, "node_modules", "typescript", "bin", "tsc");
  const stat = fs.lstatSync(compiler);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new Error(`${cwd}: its TypeScript compiler is not a regular file at ${compiler}`);
  }
  return ["node", [compiler, "-p", "tsconfig.json"]];
}

/**
 * WHICH package a proof file runs in, and whether that package must be BUILT first — decided here,
 * once, so CI and the runner cannot disagree about it.
 *
 * `runRecipeFor` below is the only other reader, and it calls this rather than repeating the rule.
 * CI needs the same answer BEFORE anything is installed, which is why this is a pure function of the
 * path: `trustedBuildStep` cannot answer it, because it `lstat`s a compiler that is not there yet.
 * MEASURED on the run this exists to prevent: resolver parity died with
 * `ENOENT ... packages/evidence/node_modules/typescript/bin/tsc` because the job installed the two
 * packages someone had listed by hand rather than the ones the recipes actually build.
 */
export function proofRecipePackage(relFile) {
  const m = /^packages\/([^/]+)\/test\/(.+\.(?:ts|mts|mjs|js))$/.exec(relFile);
  if (!m) return null;
  const [, pkg, rest] = m;
  // e2e-demo runs straight from source through tsx; every other package runs its compiled output.
  return { cwd: `packages/${pkg}`, rest, buildsLocally: pkg !== "e2e-demo" };
}

/**
 * Everything that must be INSTALLED before a package-backed proof or knockout suite may run, in an
 * order that satisfies the local `file:` links between those packages.
 *
 * The package a proof file lands in is not the whole answer, and assuming it was is what broke CI
 * twice. Two shapes the recipe alone does not reveal:
 *   • `packages/e2e-demo` runs from SOURCE through tsx, so it has no build step of its own — but its
 *     proofs import six siblings' compiled output, which is what its `build:deps` script produces.
 *   • `packages/evidence` links `noa-rail-x402` as `file:../rail-x402`, which npm installs as a
 *     SYMLINK: imports inside rail-x402 resolve from its REAL path, so it needs its own
 *     `node_modules` even though no proof file lives in it.
 * Both fall out of the manifests, so both are derived here rather than remembered by someone. The
 * same rule covers a suite that starts source from an optional local package even when no proof file
 * lives there: `mcp-proxy` starts `signer-sidecar/src/sidecar.mjs` directly, and signer-sidecar's own
 * local dependencies must therefore be installed in a clean checkout too.
 *
 * The root link (`file:../..`) is deliberately not in the plan: the job installs the root before any
 * of this, and a package's own `npm ci` runs the root's `prepare` through the link anyway.
 *
 */
export function localPackageDependencyOrder(root, packageDirs) {
  const manifestOf = (cwd) => JSON.parse(fs.readFileSync(path.join(root, cwd, "package.json"), "utf8"));
  // EVERY local link is accounted for, and exactly one is allowed to be omitted.
  //
  // The earlier shape kept a link only when its lexical target began `packages/` and quietly dropped
  // everything else — a target outside this repository, a target in another checkout, and a package
  // linking ITSELF all disappeared without a word. Silence is the wrong answer for all three: a plan
  // that cannot see a dependency cannot prepare it, and a plan that cannot name what it refuses is
  // not fail-closed. The ONE omission is the repository root (`file:../..` in the current
  // manifests), because the job installs the root before any of this and a package's own `npm ci`
  // runs the root's `prepare` through the link anyway. Everything else must resolve to an exact
  // `packages/<name>` inside THIS root and be traversed, or stop the plan before any npm runs.
  const localDepsOf = (cwd) => {
    const manifest = manifestOf(cwd);
    const found = [];
    for (const field of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
      for (const [name, spec] of Object.entries(manifest[field] ?? {})) {
        if (typeof spec !== "string" || !spec.startsWith("file:")) continue;
        const target = path.resolve(root, cwd, spec.slice("file:".length));
        const rel = path.relative(root, target);
        // The repository root itself: separately authoritative, deliberately not planned.
        if (rel === "") continue;
        if (rel.startsWith("..") || path.isAbsolute(rel)) {
          throw new Error(
            `${cwd} links ${name} to ${JSON.stringify(spec)}, which resolves outside this repository ` +
            `(${rel}); a preparation plan cannot prepare it and will not ignore it`,
          );
        }
        if (!/^packages\/[A-Za-z0-9_-]+$/.test(rel)) {
          throw new Error(
            `${cwd} links ${name} to ${JSON.stringify(spec)}, which is neither the repository root nor ` +
            `an exact packages/<name> (${rel})`,
          );
        }
        if (rel === cwd) {
          throw new Error(`${cwd} links ${name} to itself (${JSON.stringify(spec)}); a self dependency cannot be ordered`);
        }
        if (!found.includes(rel)) found.push(rel);
      }
    }
    return found;
  };

  const wanted = [];
  for (const cwd of packageDirs) {
    if (!/^packages\/[A-Za-z0-9_-]+$/.test(cwd)) {
      throw new Error(`preparation order refuses a path that is not an exact packages/<name>: ${JSON.stringify(cwd)}`);
    }
    if (!wanted.includes(cwd)) wanted.push(cwd);
  }

  // Dependencies first, so a package is never built against a sibling that is not there yet.
  const ordered = [];
  const visiting = new Set();
  const visit = (cwd) => {
    if (ordered.includes(cwd)) return;
    if (visiting.has(cwd)) throw new Error(`local package dependency cycle reaches ${cwd}`);
    visiting.add(cwd);
    for (const dep of localDepsOf(cwd)) visit(dep);
    visiting.delete(cwd);
    ordered.push(cwd);
  };
  for (const cwd of wanted.slice().sort()) visit(cwd);

  if (ordered.length === 0) throw new Error("package dependency order is empty; nothing would be prepared");
  return ordered;
}

/**
 * The proof resolver's install closure plus its build actions.
 *
 * ── ONLY `build`, NEVER `build:deps` ─────────────────────────────────────────────────────────────
 * A package's own `build` is the only action emitted. `build:deps` is a package's private recipe for
 * rebuilding its siblings, and this plan already walks those siblings: `packages/evidence`'s
 * `build:deps` rebuilds the root and approval-artifacts, and `packages/e2e-demo`'s rebuilds
 * signer-core, the root, approval-artifacts, gate, relay and evidence — every one of which this plan
 * builds itself, in dependency order. Emitting both would build the same trees twice and let a
 * package's private script decide the order this function exists to decide. A source-only package
 * such as `packages/e2e-demo` therefore appears with NO action at all: it is installed, and the
 * siblings its proofs import are built by their own entries.
 */
export function proofPreparationPlan(root, files) {
  const wanted = [];
  for (const file of files) {
    const resolved = proofRecipePackage(file);
    if (resolved !== null && !wanted.includes(resolved.cwd)) wanted.push(resolved.cwd);
  }

  const ordered = localPackageDependencyOrder(root, wanted);
  const manifestOf = (cwd) => JSON.parse(fs.readFileSync(path.join(root, cwd, "package.json"), "utf8"));

  // FAIL CLOSED on anything this plan is not allowed to name. It decides what a workflow points
  // `npm --prefix` at, so a path that is not an exact `packages/<name>`, or a package named twice,
  // is refused here rather than validated downstream by whoever remembers to.
  const plan = ordered.map((cwd) => {
    if (!/^packages\/[A-Za-z0-9_-]+$/.test(cwd)) {
      throw new Error(`preparation plan refuses a path that is not an exact packages/<name>: ${JSON.stringify(cwd)}`);
    }
    const scripts = manifestOf(cwd).scripts ?? {};
    return { cwd, actions: typeof scripts.build === "string" ? ["build"] : [] };
  });
  const seen = new Set();
  for (const { cwd } of plan) {
    if (seen.has(cwd)) throw new Error(`preparation plan names ${cwd} more than once`);
    seen.add(cwd);
  }
  if (plan.length === 0) throw new Error("preparation plan is empty; nothing would be prepared");
  return plan;
}

export function runRecipeFor(relFile) {
  const resolved = proofRecipePackage(relFile);
  if (resolved === null) return null;
  const { cwd, rest, buildsLocally } = resolved;
  if (!buildsLocally) {
    return {
      cwd,
      steps: [["node", ["--enable-source-maps", ...proofRunnerNodeArgs(`test/${rest}`, { importModule: TYPESCRIPT_TEST_REGISTER })]]],
    };
  }
  return {
    cwd,
    steps: [
      trustedBuildStep(cwd),
      ["node", proofRunnerNodeArgs(`dist/test/${rest.replace(/\.(ts|mts)$/, ".js")}`)],
    ],
  };
}

/** Resolve the one evidence-bearing file a registered source proof recipe actually executes. */
export function executedProofFileFor(root, relFile) {
  const recipe = runRecipeFor(relFile);
  if (recipe === null) return null;
  const evidenceSteps = recipe.steps.filter(([cmd, args]) => cmd === "node" && args.includes("--test"));
  if (evidenceSteps.length !== 1) return null;
  return path.resolve(root, recipe.cwd, evidenceSteps[0][1].at(-1));
}

/**
 * Parse the custom reporter's complete stdout stream. Every non-empty stdout line must be one
 * valid protocol record, and exactly one terminal top-level plan must exist. Raw text on this
 * machine channel is a protocol failure, never something to skip until a preferred answer appears.
 */
export function parseProofEvents(output) {
  const events = [];
  const lines = String(output).split(/\r?\n/);
  for (let index = 0; index < lines.length; index++) {
    const line = lines[index];
    if (line === "") continue;

    let value;
    try {
      value = JSON.parse(line);
    } catch {
      return { events: [], protocolComplete: false, error: `reporter stdout line ${index + 1} is not JSON` };
    }
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
      return { events: [], protocolComplete: false, error: `reporter stdout line ${index + 1} is not an object` };
    }
    if (value.protocol !== PROOF_EVENT_PROTOCOL) {
      return { events: [], protocolComplete: false, error: `reporter stdout line ${index + 1} has an unknown protocol` };
    }

    if (value.event === "plan") {
      if (!Number.isInteger(value.count) || value.count < 0) {
        return { events: [], protocolComplete: false, error: `reporter plan at line ${index + 1} has an invalid count` };
      }
      events.push(value);
      continue;
    }

    if (value.event === "pass" || value.event === "fail") {
      if (
        typeof value.name !== "string" ||
        typeof value.skipped !== "boolean" ||
        typeof value.todo !== "boolean" ||
        typeof value.suite !== "boolean" ||
        typeof value.fileFailure !== "boolean" ||
        !(value.file === null || typeof value.file === "string") ||
        !(value.line === null || (Number.isInteger(value.line) && value.line > 0)) ||
        !(value.column === null || (Number.isInteger(value.column) && value.column > 0)) ||
        !(value.failureType === null || typeof value.failureType === "string") ||
        !(value.message === null || typeof value.message === "string")
      ) {
        return { events: [], protocolComplete: false, error: `reporter test event at line ${index + 1} is malformed` };
      }
      events.push(value);
      continue;
    }

    return { events: [], protocolComplete: false, error: `reporter stdout line ${index + 1} has an unknown event` };
  }

  const plans = events.filter((event) => event.event === "plan");
  if (plans.length !== 1) {
    return { events, protocolComplete: false, error: `expected exactly one terminal plan, received ${plans.length}` };
  }
  if (events.at(-1) !== plans[0]) {
    return { events, protocolComplete: false, error: "the reporter plan was not the terminal protocol record" };
  }
  return { events, protocolComplete: true, plan: plans[0] };
}

/**
 * What did the runner say about this exact marker?
 *
 * A PASS certifies only when it is a non-suite, non-skipped, single-line test event, the protocol
 * completed, and the isolated file exited zero. A marker printed by test stdout never reaches this
 * stream. A marker embedded in a suite name or multiline name is deliberately non-evidence. A
 * marker may deliberately name a proof group (the gate parity proof has three complementary
 * tests). Every runtime event must match the exact name, file, line and column of one authored call
 * in the executed file and every member must pass; a dynamic marker substitute cannot answer for a
 * dead registered call.
 */
export function runnerStatusFor(output, marker, exitCode = 0, { expectedSites = [] } = {}) {
  const parsed = parseProofEvents(output);
  if (!parsed.protocolComplete) return "protocol-error";
  if (!Number.isInteger(exitCode)) return "could-not-run";

  const hits = parsed.events.filter((event) =>
    (event.event === "pass" || event.event === "fail") &&
    event.suite === false && event.fileFailure === false &&
    !event.name.includes("\n") &&
    event.name.includes(marker)
  );
  if (hits.length === 0) return exitCode === 0 ? "absent" : "run-failed-without-proof";
  if (!Array.isArray(expectedSites) || expectedSites.length < 1 || expectedSites.some((site) =>
    site === null || typeof site !== "object" ||
    typeof site.name !== "string" || typeof site.file !== "string" ||
    !Number.isInteger(site.line) || site.line < 1 ||
    !Number.isInteger(site.column) || site.column < 1
  )) return "site-binding-missing";
  if (hits.length !== expectedSites.length) return "site-mismatch";

  const canonicalFile = (file) => {
    try {
      return fs.realpathSync(file);
    } catch {
      return path.resolve(file);
    }
  };
  const identity = ({ name, file, line, column }) => JSON.stringify([
    name,
    canonicalFile(file),
    line,
    column,
  ]);
  const expectedIdentities = new Map();
  for (const site of expectedSites) {
    const key = identity(site);
    expectedIdentities.set(key, (expectedIdentities.get(key) ?? 0) + 1);
  }
  for (const hit of hits) {
    if (hit.file === null || hit.line === null || hit.column === null) return "site-mismatch";
    const key = identity(hit);
    const remaining = expectedIdentities.get(key) ?? 0;
    if (remaining < 1) return "site-mismatch";
    expectedIdentities.set(key, remaining - 1);
  }
  if ([...expectedIdentities.values()].some((remaining) => remaining !== 0)) return "site-mismatch";
  if (hits.some((hit) => hit.event === "fail")) return "failing";
  if (hits.some((hit) => hit.skipped || hit.todo)) return "skipped";
  return exitCode === 0 ? "passing" : "run-failed-after-proof";
}

/**
 * Execute every distinct proof-bearing file once. `ok` means the versioned reporter protocol
 * completed, not that the file passed: an ordinary red test run has an integer non-zero exit and
 * authenticated events that remain useful for diagnosis. Build errors, reporter drift, malformed
 * output, signals and timeouts are could-not-run failures.
 */
export function runProofFiles(root, relFiles, { timeoutMs = 300_000 } = {}) {
  const results = new Map();
  for (const relFile of [...new Set(relFiles)].sort()) {
    const recipe = runRecipeFor(relFile);
    if (recipe === null) {
      results.set(relFile, { ok: false, error: `no run recipe for "${relFile}" — proofs must live under packages/<p>/test/` });
      continue;
    }

    const started = Date.now();
    let output = "";
    let exitCode = null;
    let failed = null;
    const executedFile = executedProofFileFor(root, relFile);
    for (const [cmd, args] of recipe.steps) {
      const isTestStep = cmd === "node" && args.includes("--test");
      try {
        const stepOutput = execFileSync(cmd, args, {
          cwd: path.join(root, recipe.cwd),
          encoding: "utf8",
          stdio: "pipe",
          timeout: timeoutMs,
          maxBuffer: 4 * 1024 * 1024,
        });
        if (!isTestStep) continue;

        output = stepOutput;
        exitCode = 0;
        const parsed = parseProofEvents(output);
        if (!parsed.protocolComplete) {
          failed = `proof reporter protocol did not complete in ${recipe.cwd}: ${parsed.error}`;
          break;
        }
      } catch (error) {
        if (!isTestStep) {
          failed = `step \`${cmd} ${args.join(" ")}\` failed in ${recipe.cwd} (${error.status ?? error.signal ?? "?"})`;
          break;
        }
        if (!Number.isInteger(error.status)) {
          failed = `proof test step did not complete in ${recipe.cwd} (${error.signal ?? error.code ?? "unknown signal/timeout"})`;
          break;
        }

        output = String(error.stdout ?? "");
        exitCode = error.status;
        const parsed = parseProofEvents(output);
        if (!parsed.protocolComplete) {
          failed = `proof reporter protocol did not complete in ${recipe.cwd}: ${parsed.error}`;
          break;
        }
      }
    }

    const ms = Date.now() - started;
    if (failed !== null) results.set(relFile, { ok: false, error: failed, ms });
    else if (!Number.isInteger(exitCode)) results.set(relFile, { ok: false, error: "the recipe executed no proof test step", ms });
    else if (executedFile === null) results.set(relFile, { ok: false, error: "the recipe did not identify its executed proof file", ms });
    else results.set(relFile, { ok: true, output, exitCode, executedFile, ms });
  }
  return results;
}
