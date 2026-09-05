#!/usr/bin/env node
/**
 * L4 — CONTROL KNOCKOUT: every security control must have a test that fails when the control is
 * REMOVED (ADR §8.2). A control nothing measures is deleted or fixed.
 *
 * WHY KNOCKOUT AND NOT MUTATION TOOLING. A blanket mutation runner over the TCB would spend hours
 * flipping arithmetic operators in a canonicalizer and produce a survival percentage — a number
 * that answers a question nobody asked. The question here is exact and small: *for this specific
 * security control, is there a test that goes red without it?* That is answered by deleting the
 * control and running the suite. Twelve targeted knockouts that each name a real defensive
 * mechanism are worth more than a 90%-mutation-score badge, and they can be read in a minute.
 *
 * WHY THIS EXISTS AT ALL. `packages/gate/test/grant-atomic.test.ts:66` asserted the C-04 defect as
 * correct behaviour and passed for months. Nothing in the repository disagreed with it, because the
 * suite's only opinion on the matter WAS that test. Knockout is the mechanical form of the question
 * "and what, exactly, would have caught this?"
 *
 * THE RULE: a knockout that leaves the suite GREEN is a finding. It means either the control is not
 * load-bearing (delete it) or nothing tests it (write the test).
 *
 * ⚠ HISTORICAL CORRECTION. This scanner once claimed to use a scratch copy while mutating the live
 * checkout, then tried to restore source and derived state. Crashes and generator side effects
 * proved that authority unsafe. Since 2026-09-03 the source checkout is capture-only: one sealed
 * candidate feeds fresh retained SELFTEST, BASELINE, MUTANT, and conditional POSTCHECK arms. A
 * mutant is never restored in place, and isolation failure has no live-root fallback.
 *
 * And the verdict is no longer `green ? SURVIVED : KILLED`. That treated a real detection, a
 * pre-existing failure, a compile error, a crash and a timeout as one value. Six of the entries
 * below target `packages/gate`, whose baseline is `exit 1, 200/2` — so they reported KILLED for any
 * mutation. Proven by making one entry's `replace` byte-identical to its `find`: the source did not
 * change at all and the runner still printed `killed 1/1`. Verdicts now come from the closed
 * taxonomy in `lib/knockout-runner.mjs`, and a kill requires a failure the CLEAN baseline did not
 * already have.
 *
 * Run:  node scripts/lint-control-knockout.mjs [--warn]
 *         [--only <id> | --shard <zero-based-index>/<total>]
 * Internal read-only mode: --print-suite-packages
 * Internal negative fixture: --selftest-unknown-kind
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  BOUNDARY_CANDIDATE_TIER_A_KNOCKOUT_PROVENANCE_EXPECTATION,
  baselineEvidenceSummary, partitionIntoShards, PASSING,
  ISOLATED_KNOCKOUT_SWEEP_TIMEOUTS, runIsolatedKnockoutSweep, validateKnockoutRegistry,
} from "./lib/knockout-runner.mjs";
import {
  deriveBoundaryKnockoutCandidateSubject,
  loadAttestedTypeScriptForKnockout,
} from "./lib/boundary-bootstrap.mjs";
import { KNOCKOUT_WORKSPACE_ARM_LIMITS } from "./lib/knockout-workspace.mjs";
import { localPackageDependencyOrder } from "./lib/proof-resolve.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const DIRECT_ENTRY = typeof process.argv[1] === "string" &&
  path.resolve(fileURLToPath(import.meta.url)) === path.resolve(process.argv[1]);
const CLI_ARGS = DIRECT_ENTRY ? process.argv.slice(2) : [];
const CLI_VALUE_OPTIONS = new Set(["--only", "--shard"]);
const CLI_FLAG_OPTIONS = new Set(["--print-suite-packages", "--selftest-unknown-kind", "--warn"]);

function cliArgumentProblem(args) {
  const seen = new Set();
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === "--requires") {
      return "--requires is not supported by the self-contained public knockout registry";
    }
    if (CLI_VALUE_OPTIONS.has(argument)) {
      if (seen.has(argument)) return `${argument} may be supplied exactly once`;
      seen.add(argument);
      const value = args[index + 1];
      if (typeof value !== "string" || value.length === 0 || value.startsWith("--")) {
        return `${argument} requires one non-option value`;
      }
      index += 1;
      continue;
    }
    if (CLI_FLAG_OPTIONS.has(argument)) {
      if (seen.has(argument)) return `${argument} may be supplied exactly once`;
      seen.add(argument);
      continue;
    }
    return `unknown or unconsumed argument ${JSON.stringify(argument)}`;
  }
  if (seen.has("--print-suite-packages") && args.length !== 1) {
    return "--print-suite-packages must be used alone";
  }
  if (seen.has("--selftest-unknown-kind") && args.length !== 1) {
    return "--selftest-unknown-kind must be used alone";
  }
  return null;
}

if (DIRECT_ENTRY) {
  const problem = cliArgumentProblem(CLI_ARGS);
  if (problem !== null) {
    console.error(`CLI_ARGUMENT_REFUSED: ${problem}`);
    process.exit(1);
  }
}

/**
 * Recurrence guard for the filesystem-custody authority boundary. This is an AST/import check, not
 * a spelling grep: formatting and import ordering cannot hide a copied transaction. Ledger policy
 * may inspect names/capacity/census, while stable reads and immutable publication stay in custody.
 */
function boundaryCustodyAuthorityProblems() {
  const parseSource = (relativePath, source) => {
    const ast = ts.createSourceFile(
      relativePath,
      source,
      ts.ScriptTarget.ES2022,
      true,
      ts.ScriptKind.JS,
    );
    return { ast, relativePath };
  };
  const parse = (relativePath) => parseSource(
    relativePath,
    fs.readFileSync(path.join(ROOT, relativePath), "utf8"),
  );
  const imported = ({ ast }, specifier) => {
    const names = new Set();
    let declarations = 0;
    let unsupportedBinding = false;
    for (const statement of ast.statements) {
      if (!ts.isImportDeclaration(statement) || !ts.isStringLiteral(statement.moduleSpecifier)
          || statement.moduleSpecifier.text !== specifier) continue;
      declarations++;
      const clause = statement.importClause;
      if (clause?.name !== undefined || (clause?.namedBindings !== undefined
          && !ts.isNamedImports(clause.namedBindings))) unsupportedBinding = true;
      if (clause?.namedBindings !== undefined && ts.isNamedImports(clause.namedBindings)) {
        for (const element of clause.namedBindings.elements) {
          names.add(element.propertyName?.text ?? element.name.text);
        }
      }
    }
    return { declarations, names, unsupportedBinding };
  };
  const functionCalls = ({ ast }, functionName = null) => {
    const calls = [];
    let target = ast;
    if (functionName !== null) {
      target = ast.statements.find((statement) =>
        ts.isFunctionDeclaration(statement) && statement.name?.text === functionName) ?? null;
      if (target === null) return null;
    }
    const visit = (node) => {
      if (ts.isCallExpression(node)) {
        const expression = node.expression;
        if (ts.isIdentifier(expression)) calls.push(expression.text);
        else if (ts.isPropertyAccessExpression(expression)) calls.push(expression.name.text);
        else if (ts.isElementAccessExpression(expression)
            && ts.isStringLiteral(expression.argumentExpression)) calls.push(expression.argumentExpression.text);
      }
      ts.forEachChild(node, visit);
    };
    visit(target);
    return calls;
  };
  const reachableFunctionCalls = ({ ast }, rootFunctionName) => {
    const sourceFileName = "/__noa_boundary_authority_guard__.js";
    const boundAst = ts.createSourceFile(
      sourceFileName,
      ast.text,
      ts.ScriptTarget.ES2022,
      true,
      ts.ScriptKind.JS,
    );
    const compilerOptions = {
      allowJs: true,
      checkJs: true,
      module: ts.ModuleKind.ESNext,
      noLib: true,
      noResolve: true,
      target: ts.ScriptTarget.ES2022,
    };
    const baseHost = ts.createCompilerHost(compilerOptions);
    const host = {
      ...baseHost,
      fileExists: (name) => name === sourceFileName,
      getCanonicalFileName: (name) => name,
      getCurrentDirectory: () => "/",
      getDefaultLibFileName: () => "/__noa_empty_lib__.d.ts",
      getNewLine: () => "\n",
      getSourceFile: (name) => name === sourceFileName ? boundAst : undefined,
      readFile: (name) => name === sourceFileName ? boundAst.text : undefined,
      useCaseSensitiveFileNames: () => true,
      writeFile: () => {},
    };
    const checker = ts.createProgram([sourceFileName], compilerOptions, host).getTypeChecker();
    const forbiddenModules = new Set(["fs", "fs/promises", "node:fs", "node:fs/promises"]);
    const unresolvedAuthorityCall = "__UNRESOLVED_FORBIDDEN_FILESYSTEM_AUTHORITY__";
    const assignments = new Map();
    const resolvingFunctionReturns = new Set();
    const isFunctionNode = (node) => ts.isFunctionDeclaration(node)
      || ts.isFunctionExpression(node) || ts.isArrowFunction(node);
    const emptyResolution = () => ({
      authority: false,
      functions: new Set(),
      names: new Set(),
      unresolvedAuthority: false,
    });
    const mergeResolution = (target, source) => {
      target.authority ||= source.authority;
      target.unresolvedAuthority ||= source.unresolvedAuthority;
      for (const fn of source.functions) target.functions.add(fn);
      for (const name of source.names) target.names.add(name);
      return target;
    };
    const importDeclarationFor = (node) => {
      let current = node;
      while (current !== undefined && !ts.isSourceFile(current)) {
        if (ts.isImportDeclaration(current)) return current;
        current = current.parent;
      }
      return null;
    };
    const importModuleFor = (node) => {
      const declaration = importDeclarationFor(node);
      return declaration !== null && ts.isStringLiteral(declaration.moduleSpecifier)
        ? declaration.moduleSpecifier.text
        : null;
    };
    const staticPropertyName = (node) => {
      if (node === undefined) return null;
      if (ts.isIdentifier(node) || ts.isStringLiteral(node)
          || ts.isNoSubstitutionTemplateLiteral(node)) return node.text;
      return null;
    };
    const staticElementName = (node) => {
      if (node === undefined) return null;
      if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return node.text;
      return null;
    };
    const unwrap = (node) => {
      let current = node;
      while (ts.isParenthesizedExpression(current)
          || ts.isAsExpression(current)
          || ts.isNonNullExpression(current)
          || ts.isTypeAssertionExpression(current)
          || (typeof ts.isSatisfiesExpression === "function" && ts.isSatisfiesExpression(current))) {
        current = current.expression;
      }
      return current;
    };
    const collectAssignments = (node) => {
      if (ts.isBinaryExpression(node)
          && node.operatorToken.kind === ts.SyntaxKind.EqualsToken
          && ts.isIdentifier(node.left)) {
        const symbol = checker.getSymbolAtLocation(node.left);
        if (symbol !== undefined) {
          const values = assignments.get(symbol) ?? [];
          values.push(node.right);
          assignments.set(symbol, values);
        }
      }
      ts.forEachChild(node, collectAssignments);
    };
    collectAssignments(boundAst);

    function resolveBindingElement(declaration, seenSymbols) {
      const properties = [];
      let current = declaration;
      let variable = null;
      let dynamic = false;
      while (ts.isBindingElement(current)) {
        if (current.dotDotDotToken !== undefined) dynamic = true;
        const pattern = current.parent;
        if (ts.isObjectBindingPattern(pattern)) {
          const property = staticPropertyName(current.propertyName)
            ?? (ts.isIdentifier(current.name) ? current.name.text : null);
          if (property === null) dynamic = true;
          else properties.unshift(property);
        } else {
          dynamic = true;
        }
        const owner = pattern.parent;
        if (ts.isVariableDeclaration(owner)) {
          variable = owner;
          break;
        }
        if (!ts.isBindingElement(owner)) {
          dynamic = true;
          break;
        }
        current = owner;
      }
      const result = variable?.initializer === undefined
        ? emptyResolution()
        : resolveExpression(variable.initializer, seenSymbols);
      for (const property of properties) result.names.add(property);
      if (dynamic && result.authority) result.unresolvedAuthority = true;
      return result;
    }

    function resolveSymbol(symbol, seenSymbols) {
      const result = emptyResolution();
      if (seenSymbols.has(symbol)) {
        return result;
      }
      const nextSeen = new Set(seenSymbols);
      nextSeen.add(symbol);
      for (const declaration of symbol.declarations ?? []) {
        if (isFunctionNode(declaration)) {
          result.functions.add(declaration);
          if (declaration.name !== undefined && ts.isIdentifier(declaration.name)) {
            result.names.add(declaration.name.text);
          }
        } else if (ts.isVariableDeclaration(declaration) && declaration.initializer !== undefined) {
          mergeResolution(result, resolveExpression(declaration.initializer, nextSeen));
        } else if (ts.isBindingElement(declaration)) {
          mergeResolution(result, resolveBindingElement(declaration, nextSeen));
        } else if (ts.isImportSpecifier(declaration)) {
          const importedName = declaration.propertyName?.text ?? declaration.name.text;
          result.names.add(importedName);
          if (forbiddenModules.has(importModuleFor(declaration))) result.authority = true;
        } else if (ts.isNamespaceImport(declaration)) {
          if (forbiddenModules.has(importModuleFor(declaration))) result.authority = true;
        } else if (ts.isImportClause(declaration)) {
          if (forbiddenModules.has(importModuleFor(declaration))) {
            result.authority = true;
            result.unresolvedAuthority = true;
          }
        }
      }
      for (const assigned of assignments.get(symbol) ?? []) {
        mergeResolution(result, resolveExpression(assigned, nextSeen));
      }
      return result;
    }

    function resolveFunctionReturns(functionNode, seenSymbols) {
      const result = emptyResolution();
      if (resolvingFunctionReturns.has(functionNode)) return result;
      resolvingFunctionReturns.add(functionNode);
      try {
        if (ts.isArrowFunction(functionNode) && !ts.isBlock(functionNode.body)) {
          return mergeResolution(result, resolveExpression(functionNode.body, seenSymbols));
        }
        const visit = (node) => {
          if (node !== functionNode && isFunctionNode(node)) return;
          if (ts.isReturnStatement(node) && node.expression !== undefined) {
            mergeResolution(result, resolveExpression(node.expression, seenSymbols));
            return;
          }
          ts.forEachChild(node, visit);
        };
        visit(functionNode);
        return result;
      } finally {
        resolvingFunctionReturns.delete(functionNode);
      }
    }

    function resolveExpression(rawExpression, seenSymbols = new Set()) {
      const expression = unwrap(rawExpression);
      const result = emptyResolution();
      if (ts.isIdentifier(expression)) {
        result.names.add(expression.text);
        const symbol = checker.getSymbolAtLocation(expression);
        if (symbol !== undefined) mergeResolution(result, resolveSymbol(symbol, seenSymbols));
        return result;
      }
      if (isFunctionNode(expression)) {
        result.functions.add(expression);
        return result;
      }
      if (ts.isCallExpression(expression)) {
        const callee = resolveExpression(expression.expression, seenSymbols);
        for (const functionNode of callee.functions) {
          mergeResolution(result, resolveFunctionReturns(functionNode, seenSymbols));
        }
        return result;
      }
      if (ts.isPropertyAccessExpression(expression)) {
        mergeResolution(result, resolveExpression(expression.expression, seenSymbols));
        result.names.add(expression.name.text);
        return result;
      }
      if (ts.isElementAccessExpression(expression)) {
        mergeResolution(result, resolveExpression(expression.expression, seenSymbols));
        const property = staticElementName(expression.argumentExpression);
        if (property === null) {
          if (result.authority) result.unresolvedAuthority = true;
        } else {
          result.names.add(property);
        }
        return result;
      }
      const nestedIdentifiers = [];
      const collectIdentifiers = (node) => {
        if (ts.isIdentifier(node)) nestedIdentifiers.push(node);
        ts.forEachChild(node, collectIdentifiers);
      };
      collectIdentifiers(expression);
      for (const identifier of nestedIdentifiers) {
        mergeResolution(result, resolveExpression(identifier, seenSymbols));
      }
      if (result.authority) result.unresolvedAuthority = true;
      return result;
    }

    let root = null;
    for (const statement of boundAst.statements) {
      if (ts.isFunctionDeclaration(statement) && statement.name?.text === rootFunctionName) {
        root = statement;
        break;
      }
      if (ts.isVariableStatement(statement)) {
        for (const declaration of statement.declarationList.declarations) {
          if (ts.isIdentifier(declaration.name) && declaration.name.text === rootFunctionName
              && declaration.initializer !== undefined && isFunctionNode(declaration.initializer)) {
            root = declaration.initializer;
            break;
          }
        }
      }
      if (root !== null) break;
    }
    if (root === null) return null;

    const calls = new Set();
    const pending = [root];
    const visited = new Set();
    while (pending.length > 0) {
      const currentFunction = pending.pop();
      if (visited.has(currentFunction)) continue;
      visited.add(currentFunction);
      const visit = (node) => {
        if (node !== currentFunction && isFunctionNode(node)) return;
        if (ts.isCallExpression(node)) {
          const resolution = resolveExpression(node.expression);
          for (const name of resolution.names) calls.add(name);
          if (resolution.unresolvedAuthority) calls.add(unresolvedAuthorityCall);
          for (const target of resolution.functions) {
            if (!visited.has(target)) pending.push(target);
          }
        }
        ts.forEachChild(node, visit);
      };
      visit(currentFunction);
    }
    return [...calls];
  };

  const custody = parse("scripts/lib/boundary-custody.mjs");
  const ledger = parse("scripts/lib/boundary-ledger.mjs");
  const boundary = parse("scripts/lint-boundary.mjs");
  const problems = [];
  for (const parsed of [custody, ledger, boundary]) {
    for (const diagnostic of parsed.ast.parseDiagnostics) {
      problems.push(`${parsed.relativePath}: parse failed: ${ts.flattenDiagnosticMessageText(diagnostic.messageText, " ")}`);
    }
  }

  const ledgerFs = imported(ledger, "node:fs");
  const ledgerFsSpecifiers = ledger.ast.statements
    .filter((statement) => ts.isImportDeclaration(statement)
      && ts.isStringLiteral(statement.moduleSpecifier)
      && ["fs", "fs/promises", "node:fs", "node:fs/promises"].includes(statement.moduleSpecifier.text))
    .map((statement) => statement.moduleSpecifier.text);
  const allowedLedgerFs = new Set(["lstatSync", "readdirSync", "statfsSync"]);
  const extraLedgerFs = [...ledgerFs.names].filter((name) => !allowedLedgerFs.has(name)).sort();
  if (ledgerFs.declarations !== 1 || ledgerFs.unsupportedBinding || extraLedgerFs.length > 0
      || ledgerFsSpecifiers.length !== 1 || ledgerFsSpecifiers[0] !== "node:fs") {
    problems.push(
      `scripts/lib/boundary-ledger.mjs: raw filesystem authority import recurrence (${extraLedgerFs.join(", ") || "non-canonical import shape"})`,
    );
  }
  const ledgerCustody = imported(ledger, "./boundary-custody.mjs");
  for (const required of [
    "durablePublishImmutableByLink",
    "ownerOnlyFileCustodyProblem",
    "readStableOwnerOnlyFile",
  ]) {
    if (!ledgerCustody.names.has(required)) {
      problems.push(`scripts/lib/boundary-ledger.mjs: missing custody authority import ${required}`);
    }
  }
  const ledgerCalls = functionCalls(ledger) ?? [];
  const forbiddenLedgerCalls = [
    "closeSync", "fchmodSync", "fstatSync", "fsyncSync", "linkSync", "openSync", "readSync",
    "renameSync", "unlinkSync", "writeSync", "syncDirectory", "syncFileDescriptor",
  ];
  const copiedCalls = forbiddenLedgerCalls.filter((name) => ledgerCalls.includes(name));
  if (copiedCalls.length > 0) {
    problems.push(`scripts/lib/boundary-ledger.mjs: copied custody call recurrence (${copiedCalls.join(", ")})`);
  }
  if (ledgerCalls.filter((name) => name === "durablePublishImmutableByLink").length !== 1) {
    problems.push("scripts/lib/boundary-ledger.mjs: immutable publication must route exactly once through custody");
  }

  const confidentialCalls = reachableFunctionCalls(boundary, "readConfidentialFile");
  const boundaryCustody = imported(boundary, "./lib/boundary-custody.mjs");
  if (!boundaryCustody.names.has("readStableOwnerOnlyFile")) {
    problems.push("scripts/lint-boundary.mjs: missing Tier-B custody reader import");
  }
  if (confidentialCalls === null) {
    problems.push("scripts/lint-boundary.mjs: readConfidentialFile is missing");
  } else {
    if (confidentialCalls.filter((name) => name === "readStableOwnerOnlyFile").length !== 1) {
      problems.push("scripts/lint-boundary.mjs: Tier-B reads must route exactly once through custody");
    }
    const forbiddenTierBCalls = [
      "closeSync", "fstatSync", "inspectPath", "lstatSync", "openSync", "readFileSync", "readSync",
      "requiredFsFlag", "__UNRESOLVED_FORBIDDEN_FILESYSTEM_AUTHORITY__",
    ].filter((name) => confidentialCalls.includes(name));
    if (forbiddenTierBCalls.length > 0) {
      problems.push(`scripts/lint-boundary.mjs: copied Tier-B read recurrence (${forbiddenTierBCalls.join(", ")})`);
    }
  }
  const helperRecurrenceFixtures = [
    {
      id: "named-import-and-helper-alias",
      source: `
        import { readSync as loadRaw } from "node:fs";
        function copiedReadHelper(path) {
          const rawOpen = openSync;
          const fd = rawOpen(path);
          return loadRaw(fd);
        }
        const copiedReadAlias = copiedReadHelper;
        function readConfidentialFile(path) { return copiedReadAlias(path); }
      `,
      expected: ["openSync", "readSync"],
    },
    {
      id: "namespace-property-member-chain",
      source: `
        import * as fs from "node:fs";
        const rawNamespace = fs;
        const rawMembers = rawNamespace;
        function copiedReadHelper(fd) {
          const loadRaw = rawMembers.readSync;
          return loadRaw(fd);
        }
        function readConfidentialFile(fd) { return copiedReadHelper(fd); }
      `,
      expected: ["readSync"],
    },
    {
      id: "namespace-static-destructure",
      source: `
        import * as fs from "node:fs";
        const rawNamespace = fs;
        const { readSync: loadRaw } = rawNamespace;
        function readConfidentialFile(fd) { return loadRaw(fd); }
      `,
      expected: ["readSync"],
    },
    {
      id: "namespace-returned-by-helper",
      source: `
        import * as fs from "node:fs";
        function rawNamespace() { return fs; }
        const loadRaw = rawNamespace().readSync;
        function readConfidentialFile(fd) { return loadRaw(fd); }
      `,
      expected: ["readSync"],
    },
    {
      id: "namespace-dynamic-member-fails-closed",
      source: `
        import * as fs from "node:fs";
        const operation = "readSync";
        const loadRaw = fs[operation];
        function readConfidentialFile(fd) { return loadRaw(fd); }
      `,
      expected: ["__UNRESOLVED_FORBIDDEN_FILESYSTEM_AUTHORITY__"],
    },
    {
      id: "reachable-publication-helper-delete-alias",
      rootFunction: "publishImmutableByLinkInternal",
      source: `
        import { unlinkSync as removeName } from "node:fs";
        function hiddenCleanup(path) {
          const removeAlias = removeName;
          removeAlias(path);
        }
        function publishImmutableByLinkInternal(path) { hiddenCleanup(path); }
      `,
      expected: ["unlinkSync"],
    },
  ];
  for (const fixture of helperRecurrenceFixtures) {
    const calls = reachableFunctionCalls(
      parseSource(`<tier-b-${fixture.id}-selftest>`, fixture.source),
      fixture.rootFunction ?? "readConfidentialFile",
    ) ?? [];
    if (fixture.expected.some((name) => !calls.includes(name))) {
      problems.push(
        `scripts/lint-control-knockout.mjs: Tier-B recurrence guard self-test failed (${fixture.id})`,
      );
    }
  }
  const durableCreateCalls = functionCalls(custody, "durableCreateExclusive");
  if (durableCreateCalls === null
      || durableCreateCalls.filter((name) => name === "publishImmutableByLinkInternal").length !== 1) {
    problems.push("scripts/lib/boundary-custody.mjs: rotation create must share immutable publication primitive");
  }
  const retiredRecoveryCalls = reachableFunctionCalls(custody, "recoverDurableCreateForPath") ?? [];
  const forbiddenRecoveryCalls = [
    "__UNRESOLVED_FORBIDDEN_FILESYSTEM_AUTHORITY__", "durableUnlinkExact", "linkSync",
    "renameSync", "rmdirSync", "unlinkSync",
  ].filter((name) => retiredRecoveryCalls.includes(name));
  if (retiredRecoveryCalls.filter((name) => name === "stageEntriesForPath").length !== 1
      || !retiredRecoveryCalls.includes("refuse") || forbiddenRecoveryCalls.length > 0) {
    problems.push(
      `scripts/lib/boundary-custody.mjs: retired staged-create recovery regained mutation authority (${forbiddenRecoveryCalls.join(", ") || "non-canonical shape"})`,
    );
  }
  const immutablePublishCalls = reachableFunctionCalls(custody, "publishImmutableByLinkInternal") ?? [];
  if (immutablePublishCalls.includes("unlinkSync")
      || immutablePublishCalls.includes("durableUnlinkExact")
      || immutablePublishCalls.includes("unlinkImmutableCandidate")
      || immutablePublishCalls.includes("__UNRESOLVED_FORBIDDEN_FILESYSTEM_AUTHORITY__")) {
    problems.push("scripts/lib/boundary-custody.mjs: immutable publication regained pathname cleanup authority");
  }
  return problems;
}

function assertBoundaryCustodyAuthority() {
  const problems = boundaryCustodyAuthorityProblems();
  if (problems.length > 0) {
    throw new Error(
      `boundary custody authority recurrence guard failed:\n${problems.map((problem) => `- ${problem}`).join("\n")}`,
    );
  }
}

const WARN_ONLY = CLI_ARGS.includes("--warn");
const KIND_SCHEMA_SELFTEST = CLI_ARGS.includes("--selftest-unknown-kind");
function singleCliOption(name) {
  const index = CLI_ARGS.indexOf(name);
  return index === -1 ? null : CLI_ARGS[index + 1];
}
const ONLY = singleCliOption("--only");
// --shard <index>/<total>: run one deterministic slice of the dependency-runnable registry.
//
// 0-BASED ON PURPOSE. GitHub's `strategy.job-index` is 0-based and its expression language has no
// arithmetic, so any 1-based convention would need a hand-written number beside the matrix — and a
// hand-written number beside a coverage promise is the thing this repository keeps removing.
//
// Every malformed shape refuses BEFORE anything is measured, because the failure this exists to
// prevent is a misconfigured matrix reporting green while measuring nothing.
const shardIndexes = CLI_ARGS.flatMap((arg, index) => arg === "--shard" ? [index] : []);
if (shardIndexes.length > 1) {
  console.error(`--shard may be supplied exactly once, got ${shardIndexes.length} occurrences`);
  process.exit(1);
}
const shardIdx = shardIndexes[0] ?? -1;
const SHARD_ARG = shardIdx > -1 ? CLI_ARGS[shardIdx + 1] : null;
let SHARD = null;
if (SHARD_ARG !== null) {
  const parsed = /^([0-9]+)\/([0-9]+)$/.exec(SHARD_ARG ?? "");
  if (parsed === null) {
    console.error(`--shard must be <index>/<total> with 0-based index, got ${JSON.stringify(SHARD_ARG)}`);
    process.exit(1);
  }
  const index = Number(parsed[1]);
  const total = Number(parsed[2]);
  if (!Number.isSafeInteger(index) || !Number.isSafeInteger(total) || total < 1 || index >= total) {
    console.error(`--shard ${SHARD_ARG}: index must be an integer in [0, total) and total >= 1`);
    process.exit(1);
  }
  // AMBIGUOUS SELECTORS REFUSE. `--only` names one control, while a shard names one complete
  // deterministic slice. A coverage claim with two possible selections is not a coverage claim.
  if (ONLY !== null) {
    console.error(
      `--shard cannot be combined with --only: the selection ` +
      `would be ambiguous, and a sharded run must be able to state exactly what it measured.`,
    );
    process.exit(1);
  }
  SHARD = { index, total };
}

// Parser authority belongs to the direct supervisor only. Disposable arm workers import this
// module solely to bind the captured source-only registry; forcing those imports through candidate
// bootstrap would require reintroducing the source remote and active hooks into an intentionally
// remote-free, hooks-disabled arm. The direct entry still verifies the recurrence guard before it
// captures any candidate bytes.
let ts = null;
if (DIRECT_ENTRY) {
  ({ typescript: ts } = await loadAttestedTypeScriptForKnockout({ root: ROOT }));
}

const PROOF_INVENTORY = JSON.parse(
  fs.readFileSync(path.join(ROOT, "scripts", "resolver-inventory.json"), "utf8"),
).proofs ?? {};

/** Machine-readable proof bindings carried inside an entry's already-required control string. */
function proofIdsFor(entry) {
  const ids = [];
  for (const match of entry.control.matchAll(/\[proof:\s*([^\]]+)\]/g)) {
    ids.push(...match[1].split(",").map((v) => v.trim()).filter(Boolean));
  }
  return [...new Set(ids)];
}

/**
 * Each entry names ONE defensive mechanism, the exact source edit that removes it, and the suite
 * that must go red. `find` must match EXACTLY ONCE — an ambiguous knockout is not a knockout, and
 * a `find` that stops matching means the control moved and this entry has rotted (which is itself
 * reported, so the registry cannot silently stop describing the code).
 */
const KNOCKOUTS = [
  {
    id: "boundary-reviewed-controls-carry-publish-artifact-executor",
    control:
      "The authenticated reviewed-control registry includes the immutable publish-artifact executor. " +
      "Without it, a mutable executor could select public-artifact staging behavior outside review evidence.",
    file: "scripts/lib/boundary-bootstrap.mjs",
    find: '  "scripts/lib/publish-artifact-executor.mjs",',
    replace: "  // knockout: omit immutable publish-artifact executor from reviewed controls",
    kind: "tests",
    suite: [".", "node", ["scripts/lint-boundary.mjs", "--selftest", "--knockout-json"]],
  },
  {
    id: "boundary-arm-copy-set-equals-reviewed-control-registry",
    control:
      "The boundary arm derives its authenticated copy set from the one canonical reviewed-control registry " +
      "and independently rejects a missing or extra copy before synthetic execution.",
    file: "scripts/lib/boundary-arm.mjs",
    find: "const GATE_FILES = Object.freeze(reviewedControlGateFiles());",
    replace:
      "const GATE_FILES = Object.freeze(reviewedControlGateFiles()" +
      ".filter((entry) => entry !== \"lib/knockout-test-observer.mjs\"));",
    kind: "gate",
    gateId: "boundary-selftest",
    expectedGateProvenance: BOUNDARY_CANDIDATE_TIER_A_KNOCKOUT_PROVENANCE_EXPECTATION,
    expectedGateFindings: [{
      rule: "SELFTEST",
      subject: "authenticated carrier closures include the immutable publish-artifact executor",
    }],
    suite: [".", "node", ["scripts/lint-boundary.mjs", "--selftest", "--knockout-json"]],
  },
  {
    id: "boundary-reviewed-controls-close-local-worker-imports",
    control:
      "Every local worker imported or sealed by a reviewed control is part of the same exact control " +
      "manifest. Omitting the observer reopens a mutable machine-evidence interpreter outside review.",
    file: "scripts/lib/boundary-bootstrap.mjs",
    find: '  "scripts/lib/knockout-test-observer.mjs",',
    replace: "  // knockout: omit the machine-evidence observer from reviewed control closure",
    kind: "tests",
    suite: [".", "node", ["--test", "scripts/lib/boundary-bootstrap.selftest.mjs"]],
  },
  {
    id: "boundary-reviewed-controls-close-transitive-sealed-workers",
    control:
      "The reviewed worker closure walks transitively through module-relative sealed resources. " +
      "The proof event contract cannot read mutable reporter bytes outside the manifest.",
    file: "scripts/lib/boundary-bootstrap.mjs",
    find: '  "scripts/lib/proof-event-reporter.mjs",',
    replace: "  // knockout: omit the reporter sealed by the proof event contract",
    kind: "tests",
    suite: [".", "node", ["--test", "scripts/lib/boundary-bootstrap.selftest.mjs"]],
  },
  {
    id: "boundary-spool-cleanup-follows-canonical-evidence-version",
    control:
      "The real-push arm removes only the pending alias for the canonical evidence-spool version. " +
      "A hard-coded historical version strands current residue and makes clean custody unprovable.",
    file: "scripts/lib/boundary-arm.mjs",
    find: "`^\\\\.pending-v${BOUNDARY_EVIDENCE_SPOOL_VERSION}-[0-9a-f]{64}-`",
    replace: "`^\\\\.pending-v2-[0-9a-f]{64}-`",
    kind: "gate",
    gateId: "boundary-selftest",
    expectedGateProvenance: BOUNDARY_CANDIDATE_TIER_A_KNOCKOUT_PROVENANCE_EXPECTATION,
    expectedGateFindings: [{
      rule: "SELFTEST",
      subject: "the real-push hook selects and writes only its isolated arm evidence spool",
    }],
    suite: [".", "node", ["scripts/lint-boundary.mjs", "--selftest", "--knockout-json"]],
  },
  {
    id: "boundary-successful-operations-emit-provenance-terminal",
    control:
      "Every successful machine-mode operation emits one provenance-bound empty finding terminal " +
      "before exit zero; bare OS success is never boundary evidence.",
    file: "scripts/lint-boundary.mjs",
    find: "  if (opts.knockoutJson) emitBoundaryGateEvidence([]);",
    replace: "  // knockout: bare exit zero without a provenance-bound terminal",
    kind: "gate",
    gateId: "boundary",
    expectedGateProvenance: BOUNDARY_CANDIDATE_TIER_A_KNOCKOUT_PROVENANCE_EXPECTATION,
    expectedGateFindings: [{
      rule: "SELFTEST",
      subject: "boundary successful operation paths emit one provenance-bound machine terminal",
    }],
    suite: [".", "node", ["scripts/lint-boundary.mjs", "--output-contract-selftest", "--knockout-json"]],
  },
  {
    id: "boundary-arm-case-plan-digest-rejects-equal-count-substitution",
    control:
      "The reviewed boundary-arm case-plan digest binds the exact stable ID set, not only its count. " +
      "Replacing one valid BOTH-mode ID with a different valid unique ID preserves grammar, modes, " +
      "cardinality, and execution while the exact digest must still fail closed.",
    file: "scripts/lib/boundary-arm.mjs",
    find: "case.the-arm-terminal-supervisor-refuses-missing-duplicate-incomplete-failed-signaled-timed-out-and-late-0d29a4a2",
    replace: "case.the-arm-terminal-supervisor-refuses-missing-duplicate-incomplete-failed-signaled-timed-out-and-late-0d29a4a3",
    kind: "gate",
    gateId: "boundary-selftest",
    expectedGateProvenance: BOUNDARY_CANDIDATE_TIER_A_KNOCKOUT_PROVENANCE_EXPECTATION,
    expectedGateFindings: [{
      rule: "SELFTEST",
      subject: "the arm executed its exact reviewed case plan once",
    }],
    expectedSetupIntegrity: {
      baselineCaseCount: 249,
      baselineCasePlanSha256: "2f9bb551b3be2bcace728b3340aa438504189fcf82dbe1faecbb6ee4617ee35d",
      exitCode: 2,
      idSubstitution: {
        from: "case.the-arm-terminal-supervisor-refuses-missing-duplicate-incomplete-failed-signaled-timed-out-and-late-0d29a4a2",
        to: "case.the-arm-terminal-supervisor-refuses-missing-duplicate-incomplete-failed-signaled-timed-out-and-late-0d29a4a3",
      },
      mutatedCaseCount: 249,
      mutatedCasePlanSha256: "548ea3be121c23528e1d3a5f3aa2b4b1bd6ea532f9097f95fce4e476ec3483ed",
      stableError: "ARM_CASE_PLAN_DIGEST_MISMATCH",
      terminalProtocol: "noa-boundary-arm-terminal/1",
      terminalStatus: "SETUP_FAILED",
    },
    suite: [".", "node", ["scripts/lint-boundary.mjs", "--selftest", "--knockout-json"]],
  },
  {
    id: "boundary-spool-arm-case-plan-digest-rejects-equal-count-substitution",
    control:
      "The reviewed SPOOL_ONLY boundary-arm case-plan digest is independently load-bearing: " +
      "replacing one valid BOTH-mode ID preserves grammar, SPOOL_ONLY membership, cardinality, and " +
      "execution while the exact reviewed SPOOL_ONLY digest must still fail closed.",
    file: "scripts/lib/boundary-arm.mjs",
    find: "case.the-arm-terminal-supervisor-refuses-missing-duplicate-incomplete-failed-signaled-timed-out-and-late-0d29a4a2",
    replace: "case.the-arm-terminal-supervisor-refuses-missing-duplicate-incomplete-failed-signaled-timed-out-and-late-0d29a4a3",
    kind: "gate",
    gateId: "boundary-selftest",
    expectedGateProvenance: BOUNDARY_CANDIDATE_TIER_A_KNOCKOUT_PROVENANCE_EXPECTATION,
    expectedGateFindings: [{
      rule: "SELFTEST",
      subject: "the arm executed its exact reviewed case plan once",
    }],
    expectedSetupIntegrity: {
      baselineCaseCount: 23,
      baselineCasePlanSha256: "a03420b437d9c15e9c0213844f6d911fc01494cba6ab658be242f22f2875e188",
      exitCode: 2,
      idSubstitution: {
        from: "case.the-arm-terminal-supervisor-refuses-missing-duplicate-incomplete-failed-signaled-timed-out-and-late-0d29a4a2",
        to: "case.the-arm-terminal-supervisor-refuses-missing-duplicate-incomplete-failed-signaled-timed-out-and-late-0d29a4a3",
      },
      mutatedCaseCount: 23,
      mutatedCasePlanSha256: "2cd11b6329f5ea74114e439f853edb07316181457dac7fc094d5dbe099d46f20",
      stableError: "ARM_CASE_PLAN_DIGEST_MISMATCH",
      terminalProtocol: "noa-boundary-arm-terminal/1",
      terminalStatus: "SETUP_FAILED",
    },
    suite: [".", "node", ["scripts/lib/boundary-spool-arm.selftest.mjs"]],
  },
  {
    id: "boundary-parser-loads-only-after-bootstrap",
    control:
      "The scanner obtains reviewed runtime authority only through the stdlib bootstrap after exact candidate, " +
      "manifest, lock, attestation, and runtime-byte verification; removing that call bypasses verification.",
    file: "scripts/lib/boundary-scan.mjs",
    find: "const { authority: boundaryScannerAuthority } = await loadTrustedTypeScript();",
    replace: "const { default: ts } = await import(\"typescript\");\nconst boundaryScannerAuthority = null;",
    kind: "tests",
    suite: [".", "node", ["--test", "scripts/lib/boundary-bootstrap.selftest.mjs"]],
  },
  {
    id: "boundary-candidate-tier-a-route-is-explicit",
    control:
      "Only the closed keyless snapshot Tier-A classification arms the in-process non-authority " +
      "bootstrap before parser import. Removing that arm makes the documented credential-free workflow fail.",
    file: "scripts/lint-boundary.mjs",
    find: "  if (candidateTierANonAuthority) {\n    armCandidateTierANonAuthorityBootstrap({ root: ROOT });",
    replace: "  if (false) {\n    armCandidateTierANonAuthorityBootstrap({ root: ROOT });",
    kind: "tests",
    suite: [".", "node", ["--test", "scripts/lib/boundary-bootstrap.selftest.mjs"]],
  },
  {
    id: "boundary-candidate-tier-a-result-remains-non-authority",
    control:
      "Candidate Tier-A output carries one exact non-claim that forbids credit as N-1, Tier-B, or release " +
      "authority. Relabeling it as authority must fail the frozen output contract.",
    file: "scripts/lib/boundary-bootstrap.mjs",
    find: '  "CANDIDATE_TIER_A_RESULT_IS_NOT_N_MINUS_1_TIER_B_OR_RELEASE_AUTHORITY";',
    replace: '  "CANDIDATE_TIER_A_RELEASE_AUTHORITY";',
    kind: "tests",
    suite: [".", "node", ["--test", "scripts/lib/boundary-bootstrap.selftest.mjs"]],
  },
  {
    id: "boundary-prepush-command-selects-tier-a",
    control:
      "The canonical credential-free pre-push command explicitly selects Tier A. Falling back to the " +
      "default AB request would either demand external custody or make the local record unusable.",
    file: "scripts/pre-push-gate.mjs",
    find: 'export function buildBoundaryPrePushArgs({ destination, remoteGitDir, root, remote }) {\n  return Object.freeze([\n    join(root, "scripts", "lint-boundary.mjs"),\n    "--explain",\n    "--knockout-json",\n    "--tier", "a",',
    replace: 'export function buildBoundaryPrePushArgs({ destination, remoteGitDir, root, remote }) {\n  return Object.freeze([\n    join(root, "scripts", "lint-boundary.mjs"),\n    "--explain",\n    "--knockout-json",\n    "--tier", "ab",',
    kind: "tests",
    suite: [".", "node", ["scripts/pre-push-gate.mjs", "--selftest"]],
  },
  {
    id: "boundary-bootstrap-binds-exact-lock-digest",
    control:
      "The runtime bootstrap binds the full package-lock bytes in addition to checking the resolved " +
      "TypeScript version, so a semantically plausible but unreviewed lock cannot authorize parser execution.",
    file: "scripts/lib/boundary-bootstrap.mjs",
    find: "  if (!exactHex(sha256(lockBytes), attestation.lock.sha256)) {",
    replace: "  if (false) {",
    kind: "tests",
    suite: [".", "node", ["--test", "scripts/lib/boundary-bootstrap.selftest.mjs"]],
  },
  {
    id: "boundary-bootstrap-binds-parser-runtime-bytes",
    control:
      "Every TypeScript runtime file must match the reviewed length and SHA-256 before its top level can " +
      "execute; deleting that comparison turns node_modules into mutable parser authority.",
    file: "scripts/lib/boundary-bootstrap.mjs",
    find: "    if (bytes.length !== file.byteLength || !exactHex(sha256(bytes), file.sha256)) {",
    replace: "    if (false) {",
    kind: "tests",
    suite: [".", "node", ["--test", "scripts/lib/boundary-bootstrap.selftest.mjs"]],
  },
  {
    id: "boundary-candidate-bootstrap-refuses-key-discovery",
    control:
      "Candidate bootstrap is keyless and cannot discover a home directory. Reintroducing even an unused " +
      "homedir capability reopens the path by which candidate code previously read the boundary HMAC key.",
    file: "scripts/lib/boundary-bootstrap.mjs",
    find: 'import { spawnSync } from "node:child_process";',
    replace: 'import { spawnSync } from "node:child_process";\nimport { homedir } from "node:os";',
    kind: "tests",
    suite: [".", "node", ["--test", "scripts/lib/boundary-bootstrap.selftest.mjs"]],
  },
  {
    id: "boundary-historical-registry-remains-exact-seven",
    control:
      "The recovery predecessor registry remains the exact historical seven paths. Adding current controls " +
      "or removing an old one changes predecessor identity and lets recovery authenticate the wrong state.",
    file: "scripts/lib/boundary-bootstrap.mjs",
    find: '  "scripts/lint-boundary.mjs",\n  "scripts/pre-push-gate.mjs",\n]);\n\nexport const REVIEWED_CONTROL_PATHS',
    replace: '  "scripts/lint-boundary.mjs",\n  // knockout: historical pre-push gate omitted\n]);\n\nexport const REVIEWED_CONTROL_PATHS',
    kind: "tests",
    suite: [".", "node", ["--test", "scripts/lib/boundary-bootstrap.selftest.mjs"]],
  },
  {
    id: "boundary-authority-closure-carries-prepush-baseline",
    control:
      "The exact broad pre-push baseline is an input to the release-call closure even though parser bootstrap " +
      "remains a smaller layer; omitting it lets the release claim ignore a changed aggregate gate.",
    file: "scripts/lib/boundary-bootstrap.mjs",
    find: '  "scripts/prepush-baseline.json",',
    replace: "  // knockout: omit exact pre-push baseline",
    kind: "tests",
    suite: [".", "node", ["--test", "scripts/lib/boundary-bootstrap.selftest.mjs"]],
  },
  {
    id: "boundary-authority-closure-carries-tier-a-workflow",
    control:
      "The exact credential-free Tier-A workflow command is inside the current control manifest. Omitting " +
      "its bytes lets the invocation drift outside the reviewed bootstrap closure.",
    file: "scripts/lib/boundary-bootstrap.mjs",
    find: '  ".github/workflows/boundary.yml",',
    replace: "  // knockout: omit credential-free Tier-A workflow",
    kind: "tests",
    suite: [".", "node", ["--test", "scripts/lib/boundary-bootstrap.selftest.mjs"]],
  },
  {
    id: "boundary-authority-closure-carries-committed-hook",
    control:
      "The committed pre-push hook bytes are inside the exact control manifest. Removing that carrier makes " +
      "core.hooksPath measurement point at code that was not part of the reviewed authority closure.",
    file: "scripts/lib/boundary-bootstrap.mjs",
    find: '  "scripts/hooks/pre-push",',
    replace: "  // knockout: omit committed pre-push hook",
    kind: "tests",
    suite: [".", "node", ["--test", "scripts/lib/boundary-bootstrap.selftest.mjs"]],
  },
  {
    id: "boundary-authority-closure-carries-knockout-runner",
    control:
      "The exact runner that mutates, observes, and restores every reviewed knockout is itself inside " +
      "the current control manifest. Omitting it lets mutable runner semantics manufacture control evidence.",
    file: "scripts/lib/boundary-bootstrap.mjs",
    find: '  "scripts/lib/knockout-runner.mjs",',
    replace: "  // knockout: omit exact knockout runner",
    kind: "tests",
    suite: [".", "node", ["--test", "scripts/lib/boundary-bootstrap.selftest.mjs"]],
  },
  {
    id: "boundary-authority-closure-carries-publish-selftest",
    control:
      "The exact publish-artifact selftest executed by the reviewed workflow is inside the current " +
      "control manifest. Omitting it lets mutable parity fixtures approve a different container toolchain.",
    file: "scripts/lib/boundary-bootstrap.mjs",
    find: '  "scripts/stage-publish-artifacts.selftest.mjs",',
    replace: "  // knockout: omit exact publish-artifact selftest",
    kind: "tests",
    suite: [".", "node", ["--test", "scripts/lib/boundary-bootstrap.selftest.mjs"]],
  },
  {
    id: "boundary-recovery-pre-effect-receipt-precedes-delete",
    control:
      "Recovery durably creates and validates its exact pre-effect receipt before raw v2 deletion. Removing " +
      "that create makes a crash capable of deleting predecessor evidence without prior durable authority.",
    file: "scripts/lib/boundary-external-authority.mjs",
    find: "    ensureDurable(custody, RECOVERY_AUTHORIZATION_NAME, authorizationBytes);",
    replace: "    // knockout: omit recovery pre-effect receipt",
    kind: "tests",
    suite: [".", "node", ["--test", "scripts/lib/boundary-external-authority.selftest.mjs"]],
  },
  {
    id: "boundary-rotation-pre-effect-receipt-precedes-replace",
    control:
      "Fresh rotation durably creates and validates its exact pre-effect receipt before replacing active " +
      "policy bytes. Removing it recreates the effect-before-authorization crash window.",
    file: "scripts/lib/boundary-external-authority.mjs",
    find: "    ensureDurable(custody, ROTATION_AUTHORIZATION_NAME, authorizationBytes);",
    replace: "    // knockout: omit rotation pre-effect receipt",
    kind: "tests",
    suite: [".", "node", ["--test", "scripts/lib/boundary-external-authority.selftest.mjs"]],
  },
  {
    id: "boundary-completion-does-not-invent-time",
    control:
      "The completion record carries no completedAt/verifiedAt claim; chronology belongs to the " +
      "outer controller. Reusing intent time as completion time would fabricate an observation.",
    file: "scripts/lib/boundary-external-authority.mjs",
    find: '    event: "EXCLUSION_POLICY_COMPLETED_AFTER_EXACT_EFFECT_READBACK",\n    evidenceStatus: "POST_EFFECT_EXACT_STATE_READ_BACK",',
    replace: '    completedAt: intentBody.recordedAt,\n    event: "EXCLUSION_POLICY_COMPLETED_AFTER_EXACT_EFFECT_READBACK",\n    evidenceStatus: "POST_EFFECT_EXACT_STATE_READ_BACK",',
    kind: "tests",
    suite: [".", "node", ["--test", "scripts/lib/boundary-external-authority.selftest.mjs"]],
  },
  // ── R8-32 (2026-07-31): THE GATES ADR-0005 §7 PROMISED AND NEVER SHIPPED ───────────────────────
  // The ADR's table names four knockouts by id — G3 `parse-boundary-strictness`,
  // G4 `render-node-single-input`, G5 `display-aad-egress-check`, G6 `riskclass-derived-not-accepted`
  // — each with "must go red" as its anti-vacuity clause. None existed. G3 and G6 are registered;
  // the G4 registry claim and G5 claim are withdrawn below rather than represented by false-green
  // entries. The canonical ADR/release-status correction is outside this batch's authorized files.
  //
  // G5 WAS FORMALLY WITHDRAWN AND IS NOW REGISTERED (2026-08-03). The withdrawal note read: "Its
  // instruction is 'delete the egress AAD verification', and that verification does not exist… A
  // knockout deletes a control; there is nothing here to delete, so writing a G5 entry would have
  // manufactured the appearance of coverage over a control that was never built."
  //
  // That refusal is why this gap was findable at all — the registry declined to fake coverage, and the
  // hole stayed visible instead of reading as closed. The control now exists
  // (`verifySealedDisplayEgress`, engine.ts), so the condition the withdrawal named is discharged and
  // the entry is registered in the SAME commit that built it. Never the other way round.
  {
    id: "p1-9-key-encoding-index-assembly",
    control:
      "P1-9 — the PKCS8 key encoder assembles by INDEX, never `.set()`. `der.set(seed, 16)` handed the " +
      "RAW 32-BYTE ED25519 PRIVATE SEED to `Uint8Array.prototype.set`, a writable global. Unlike the " +
      "#77-A defect this repeats, a replacement here need not corrupt anything: it can copy the seed, " +
      "call through, and leave the DER byte-identical with every test green. That is EXFILTRATION, and " +
      "an output comparison is structurally blind to it — which is why the test asserts a HIT-COUNT of " +
      "zero on a counting, non-destructive poison rather than comparing bytes.",
    file: "packages/signer-core/src/der.ts",
    find: "    for (let i = 0; i < seedLength; i++) der[p + i] = source[i] as number;",
    replace: "    der.set(source, p);",
    kind: "tests",
    suite: ["packages/signer-core", "npm", ["test"]],
  },
  {
    id: "g5-display-aad-egress-check",
    control:
      "ADR-0005 §5/§7 G5 (M5 cross-hold display replay) — the gate VERIFIES the sealed display it is " +
      "about to sign: the returned envelope's tenant/holdId/deferredReceiptHash/expiresAt must equal " +
      "what the gate asked for, its aadHash must equal the gate's OWN derivation over those values, " +
      "and every requested recipient — including the always-present AUDIT key — must have survived. " +
      "The sealer is INJECTED, so without this the gate signed whatever a component it does not " +
      "control handed back, and a blob describing a DIFFERENT hold produced a gate-signed envelope " +
      "binding the human's approval to a display they never saw, with every downstream check green.",
    file: "packages/gate/src/engine.ts",
    // Deleting the refusal is the honest mutation: the check still runs, its verdict is discarded.
    // Deleting the CALL instead would leave `egress` unused and fail to compile — a build error scores
    // as MUTATION_DID_NOT_BUILD and tests nothing, which is the trap G3's comment above records.
    find: "      if (egress !== null) {\n        return err(422, \"DISPLAY_EGRESS_AAD_MISMATCH\", { detail: egress });\n      }",
    replace: "      void egress;",
    kind: "tests",
    suite: ["packages/gate", "npm", ["test"]],
  },
  {
    id: "g3-parse-boundary-strictness",
    control: "ADR-0005 §7 G3 — stage 0: every request body enters through parseDocument. PROVEN SCOPE (2026-07-31): replacing it with a LENIENT parser breaks the three bytes-in refusals, so the boundary is load-bearing. NOT yet isolated: whether non-strict JSON specifically is refused — that half needs a mutant that reproduces decodeDocument's exact reason string, and until one exists this entry does not claim it.",
    file: "packages/gate/src/engine.ts",
    find: 'const parsed = parseDocument(body, "request body");',
    // ── FIXED 2026-07-31 (R815-QA-16 found the cause) ──────────────────────────────────────────
    // The old replacement was:
    //     const parsed = { ok: true as const, value: body as unknown };
    // `ok: true as const` narrows `!parsed.ok` to `never`, so the very next line's `parsed.reason`
    // stops type-checking. It NEVER COMPILED, so this entry never tested anything — and the runner
    // scored the build failure as ANTI_VACUITY_FAILED, then (once the taxonomy could say so) as
    // MUTATION_DID_NOT_BUILD. The union annotation keeps both branches reachable, so the mutant
    // compiles and the bypass is BEHAVIOURAL rather than a type error. This is the same
    // narrowing-loss trap that cost three earlier attempts on this branch.
    replace: 'const parsed: { ok: true; value: unknown } | { ok: false; reason: string } = (() => {\n      try {\n        const raw = typeof body === "string" ? body : new TextDecoder().decode(body as Uint8Array);\n        return { ok: true as const, value: JSON.parse(raw) as unknown };\n      } catch {\n        return { ok: false as const, reason: "request body: lenient parse failed" };\n      }\n    })();',
    kind: "tests",
    suite: ["packages/gate", "npm", ["test"]],
  },
  // G4 BATCH-I CORRECTION (2026-08-01): the exact historical mutant IS distinguishable.
  // The exact historical mutation was recovered from commit 4ff3a76:
  //
  //   commandView(canonical)
  //     -> commandView(canonicalize(snapshot as Record<string, unknown>))
  //
  // WITHDRAWN CLAIM (verbatim): "No reachable caller can distinguish the security-relevant return value; the mutant only repeats work."
  // `canonicalize` reads live `Object.keys`. A stateful post-load replacement can return the complete
  // snapshot keys for the first canonicalization and omit `targetEnv` on the next matching call. The
  // shipped path renders the first canonical string and remains accepted; the exact mutant performs
  // the second canonicalization and loses a required field. The public `getProjection().run()` surface
  // reaches this distinction without a caller-owned object surviving the capture-once boundary.
  //
  // NUMBERS, re-measured in Batch F without the two owner-deferred ADR-0006 failures: the source has
  // 2 first-party `.run()` call sites (engine + wrapper) and 1 public direct-call surface. The scoped
  // public-surface Slice-2 run was clean 6/6 GREEN and mutated 6/6 GREEN, including the honest-path
  // anti-vacuity test. A separate clean-vs-mutant differential corpus was 10/10 return-value
  // identical (6 accepted, 4 rejected: honest, destructive and adversarial capture shapes).
  // WITHDRAWN CLAIM (verbatim): "`DETECTOR_DID_NOT_TRIGGER` is therefore the correct result for an observationally equivalent mutant, not evidence that canonical bytes are unimportant."
  // The previous 6/6 and 10/10 corpora did not include a stateful mutable-intrinsic probe. The
  // registered knockout below now applies the exact mutant and runs a test that does.
  //
  // WITHDRAWN CLAIM (verbatim): "ADR-0005 §7 G4 — the render node reads the CANONICAL BYTES, so the display and the paramsHash cannot disagree (M7)"
  //
  // The older claim above remains preserved as history; this entry measures the current correction.
  {
    id: "adr0007-device-token-kid-binding",
    control:
      "ADR-0007 constraint 4 — a device-pairing token names the ONLY key permitted to redeem it. " +
      "The gate sees the approver-device public key in the CONFIRMATION before it authors ACCEPTED, so the " +
      "token can be issued kid-bound; a leaked paste bundle is then worthless without that device's " +
      "private key. This is the property a shared operator secret cannot have at any price, and it " +
      "is why option A (teach the app one static secret) was rejected: a fleet-wide bearer " +
      "credential is not per-device, not attributable, and unrevocable without rotating every device.",
    file: "packages/relay/src/engine.ts",
    find: "    if (rec.kid !== kid) {",
    replace: "    if (rec.kid !== rec.kid) {",
    kind: "tests",
    suite: ["packages/relay", "npm", ["test"]],
  },
  {
    id: "adr0007-device-token-single-use",
    control:
      "ADR-0007 constraint 8 — a device token is SINGLE-USE, and single-use is the honest word: no " +
      "revoke API exists for these tokens, so one use plus a short TTL is the entire mechanism. " +
      "Accepting a second redemption would turn a replayable paste artifact into a standing " +
      "credential. Recovery for an approver client that LOST its response is a SEPARATE path — a fresh token " +
      "re-mints onto the existing device — and its own control pins that this refusal does not " +
      "brick the kid, because revokeSelf needs the very secret that was lost.",
    file: "packages/relay/src/engine.ts",
    find: "    if (rec.usedAt !== null) {",
    replace: "    if (rec.usedAt !== rec.usedAt) {",
    kind: "tests",
    suite: ["packages/relay", "npm", ["test"]],
  },
  {
    id: "adr0007-device-token-hashed-at-rest",
    control:
      "ADR-0007 constraint 6 — the device token is HASHED at rest; the plaintext is returned once " +
      "at issuance and never stored. PairingRecord stores its token raw, unlike apiKeyHash and " +
      "deviceSecretHash — a pre-existing inconsistency the device namespace does not inherit. " +
      "NOTE THE MUTATION SHAPE: it changes BOTH the write and the lookup. Changing only the write " +
      "was tried first and broke FIVE tests on lookup consistency instead of one on secrecy — it " +
      "measured the wrong property, and a knockout that kills for the wrong reason certifies nothing.",
    file: "packages/relay/src/engine.ts",
    find: "      tokenHash: hashSecret(token), tenant, kid, usedAt: null, expiresAt, createdAt: this.now(),",
    replace: "      tokenHash: token, tenant, kid, usedAt: null, expiresAt, createdAt: this.now(),",
    also: [
      {
        find: "    const rec = this.store.getDevicePairingByHash(hashSecret(token));",
        replace: "    const rec = this.store.getDevicePairingByHash(token);",
      },
    ],
    kind: "tests",
    suite: ["packages/relay", "npm", ["test"]],
  },
  {
    id: "adr0007-untenanted-enrolment-dev-only",
    control:
      "ADR-0007 — a VALID enrolment secret must NOT open the untenanted device route. Constraint 3 " +
      "gave DeviceRecord a tenant and made claimDevice match on it, but that match only fires when " +
      "device.tenant !== null (engine.ts:254) and anonymous POST /v1/devices records tenant: null " +
      "(engine.ts:212). So a correctly-authenticated PRODUCTION operator could still mint devices " +
      "claimable by any tenant — the first-claimer-wins race constraint 3 closed, reopened through " +
      "the side door by the same change that closed it. The route survives, confined to the loopback " +
      "development opt-in where the demo, e2e and simulator flows live; production gets exactly one " +
      "device-minting path, the one that stamps a tenant.",
    file: "packages/relay/src/config.ts",
    find: "  if (opts.untenanted === true) {",
    replace: "  if (false) {",
    kind: "tests",
    suite: ["packages/relay", "npm", ["test"]],
  },
  {
    id: "adr0007-device-tenant-claim",
    control:
      "ADR-0007 constraint 3 — a device that DECLARES a tenant is claimable only by that tenant. " +
      "claimDevice refuses an unknown device and someone else's device identically, and that part " +
      "was always right; the gap was the UNCLAIMED device, whose agentId === null satisfies the " +
      "ownership check for EVERY authenticated agent. The window between a device enrolling and its " +
      "own operator claiming it is a window in which a different customer on the same relay takes " +
      "it, and from then on sees and decides everything that device is shown — the same consequence " +
      "DeviceRecord.agentId records for an unscoped device, reached through a different door. No " +
      "forgery and no stolen credential: just an unowned object and two parties entitled to ask.",
    file: "packages/relay/src/engine.ts",
    find: "    if (device.tenant !== null && device.tenant !== agent.tenant) {",
    // The mutation KEEPS the `device.tenant !== null` narrowing TypeScript relies on further down.
    // A plain `if (false)` looked like the obvious knockout and came back MUTATION_DID_NOT_BUILD:
    // dropping the narrowing makes `device` possibly-undefined at :257, so the experiment measured
    // the compiler rather than the control. `x !== x` is always false and narrows identically.
    replace: "    if (device.tenant !== null && device.tenant !== device.tenant) {",
    kind: "tests",
    suite: ["packages/relay", "npm", ["test"]],
  },
  {
    id: "stage4-digest-display-disagreement",
    control:
      "ADR-0006 §5 stage 4 — the DIGEST and the DISPLAY must commit to the same bytes. NOA's " +
      "catastrophic failure is a genuine human genuinely approving a DIFFERENT action from the one " +
      "that executes, and that becomes possible the moment a displayed field is derived from a " +
      "caller-controlled value instead of from the canonical bytes. Measured before this control " +
      "existed: bypassing the render node turned ZERO tests red (projections.ts:196-215 records it, " +
      "and this file's oracle re-measured it). SCOPE, stated rather than implied: this mutation is " +
      "the A+B state — the display reads the CALLER's argv. Mutation B alone (the display reads our " +
      "own pre-canonical snapshot) still turns nothing red, because while capture-once holds that " +
      "array is ours and yields the identical string. The oracle closes the CONSEQUENCE a human is " +
      "harmed by, not the render node's redundancy.",
    file: "packages/gate/src/projections.ts",
    find: "      Args: view.argsJoined,",
    replace: '      Args: (argv as unknown as string[]).join(" "),',
    kind: "tests",
    suite: ["packages/gate", "npm", ["test"]],
  },
  {
    id: "g4-render-node-single-input",
    control: "ADR-0005 §7 G4 — the render node consumes the first canonical byte string. Re-canonicalizing the local snapshot lets a stateful post-load Object.keys replacement supply a different second key set, so the display/risk input can differ from the bytes hashed into paramsHash.",
    file: "packages/gate/src/projections.ts",
    find: "    const view = commandView(canonical);",
    replace: "    const view = commandView(canonicalize(snapshot as Record<string, unknown>));",
    kind: "tests",
    suite: ["packages/e2e-demo", "node", ["--import", "tsx", "--test", "test/keyring-resolver-parity.test.ts"]],
  },
  {
    id: "g6-riskclass-derived-not-accepted",
    control: "ADR-0005 §7 G6 — riskClass is DERIVED inside the boundary; the caller's hint may raise the floor and can never lower it (M2)",
    file: "packages/gate/src/engine.ts",
    find: "effectiveRisk = maxRisk(run.derivedRisk, riskClass);",
    replace: 'effectiveRisk = riskClass ?? run.derivedRisk;',
    kind: "tests",
    suite: ["packages/gate", "npm", ["test"]],
  },
  // ── ADR-0005 (2026-07-30) ───────────────────────────────────────────────────────────────────────
  // This registry carried 28 entries and NOT ONE covered ADR-0005, while its own header says a fix
  // without a knockout is a claim. Seven controls were built or repaired in that work and every one
  // of them was knocked out by hand at the time; these entries make that permanent, so the next
  // refactor cannot quietly restore a defect the tests would then pass over.
  //
  // Every find/replace below is BEHAVIOURAL and COMPILES. Three of my first attempts were compile
  // errors, which this file already refuses (see the header): a compile error proves the identifier
  // exists, not that the check runs.
  {
    id: "adr5-relay-cross-agent-ownership",
    control: "E-3 — a foreign agent cannot read another agent's hold, receipt or decisionArtifact (F29-authz, ported)",
    file: "packages/relay/src/engine.ts",
    find: 'if (!this.ownsHold(hold, agent, "getHold")) return err(404, "UNKNOWN_HOLD");',
    replace: 'if (!hold) return err(404, "UNKNOWN_HOLD");',
    kind: "tests",
    suite: ["packages/relay", "npm", ["test"]],
  },
  {
    id: "adr5-relay-inert-receipt-snapshot",
    control: "R-ING-01 — one accessor-free snapshot, so a two-faced verdict cannot sign a DENIAL and record an approval",
    file: "packages/relay/src/engine.ts",
    find: "    const inertReceipt = inertSnapshot(rawReceipt);",
    replace: "    const inertReceipt: unknown = rawReceipt;",
    kind: "tests",
    suite: ["packages/relay", "npm", ["test"]],
  },
  {
    id: "adr5-relay-exposure-from-real-socket",
    control: "R-1 shape (A) — exposure is classified from the OS-bound address, not from config.bindAddress",
    file: "packages/relay/src/server.ts",
    find: "    handle(req, res, engine, effectiveConfig(), limiter).catch(() => {",
    replace: "    handle(req, res, engine, config, limiter).catch(() => {",
    kind: "tests",
    suite: ["packages/relay", "npm", ["test"]],
  },
  {
    id: "adr5-relay-declared-exposure",
    control: "R-1 shape (B) — tlsTerminated or unsafeListen means EXPOSED, whatever the bind address says",
    file: "packages/relay/src/config.ts",
    find: "    const declaredExposed = config.tlsTerminated || config.unsafeListen;",
    replace: "    const declaredExposed = false;",
    kind: "tests",
    suite: ["packages/relay", "npm", ["test"]],
  },
  {
    id: "adr5-signer-producer-inert-copy",
    control: "C-01 sibling (producer) — what is signed is what is returned; no writable global between them",
    file: "packages/signer-core/src/sign.ts",
    find: "  const signed = inertDeepCopy(core);",
    replace: "  const signed = structuredClone(core);",
    kind: "tests",
    suite: ["packages/signer-core", "npm", ["test"]],
  },
  {
    id: "adr5-gate-b1-fail-closed-floor",
    control: "B-1 — an unmatched action classifies to the highest tier and fails closed, whatever tier the caller names",
    file: "packages/gate/src/engine.ts",
    find: '    if (mode === "RAW") {',
    replace: '    if (mode === "RAW" && (riskClass === "CRITICAL" || riskClass === "IRREVERSIBLE")) {',
    kind: "tests",
    suite: ["packages/gate", "npm", ["test"]],
  },
  {
    id: "c04-gate-observation",
    control: "C-04 — report() signs no determinate negative in ANY state (the UNUSED 409 and the attributed-claim 202)",
    file: "packages/gate/src/engine.ts",
    find: 'if (result === "FAILED_BEFORE_DISPATCH") {',
    replace: 'if (false as boolean) {',
    kind: "tests",
    suite: ["packages/gate", "npm", ["test"]],
  },
  {
    id: "h02c-read-before-transition",
    control: "H-02c — the tool's self-report is read BEFORE any reducer transition",
    file: "packages/gate/src/wrapper.ts",
    find: "    const ok = r.ok;\n    const detail = r.detail;\n    if (ok) {",
    replace: "    const ok = r.ok;\n    if (ok) {",
    also: [{ find: "    execDetail = detail;\n  } catch (e) {", replace: "    execDetail = r.detail;\n  } catch (e) {" }],
    kind: "tests",
    suite: ["packages/gate", "npm", ["test"]],
  },
  {
    id: "h02a-reducer-routed-outcome",
    control: "H-02a — the framework adapter's terminal outcome comes from the reducer, not from `threw`",
    file: "packages/framework-adapters/src/wrap-tool.mjs",
    find: "      if (recordedState === null) {",
    replace: "      if (false) {",
    kind: "tests",
    suite: ["packages/framework-adapters", "npm", ["test"]],
  },
  {
    id: "h02b-host-discriminator",
    control: "H-02b — the host-visible McpError carries the anti-retry discriminator",
    file: "packages/mcp-proxy/src/create-proxy-server.mjs",
    find: `        {
          executionHappened: true,
          sideEffectState: dispatchState,
          evidenceOutcome: EVIDENCE_OUTCOME_FOR[dispatchState],
          safeToRetry: isSafeToRetry(dispatchState),
        },`,
    replace: "        undefined,",
    kind: "tests",
    suite: ["packages/mcp-proxy", "npm", ["test"]],
  },
  {
    id: "reducer-no-retry-safe-exit",
    control: "the reducer has NO exit from DISPATCHED to a retry-safe state without a RECONCILED_* event",
    file: "packages/adapter-core/src/side-effect-state.mjs",
    find: '    TOOL_REPORTED_NO_DISPATCH: "SIDE_EFFECT_UNCONFIRMED",',
    replace: '    TOOL_REPORTED_NO_DISPATCH: "FAILED_NO_SIDE_EFFECT",',
    kind: "tests",
    suite: ["packages/adapter-core", "npm", ["test"]],
  },
  {
    id: "reducer-immutability",
    control: "the side-effect state table is deep-frozen so safeToRetry cannot be flipped at runtime",
    file: "packages/adapter-core/src/side-effect-state.mjs",
    find: "export const SIDE_EFFECT_STATES = deepFreeze({",
    replace: "export const SIDE_EFFECT_STATES = ({",
    kind: "tests",
    suite: ["packages/adapter-core", "npm", ["test"]],
  },
  {
    id: "grant-single-use-cas",
    // MOVED 2026-08-13 (S2). This used to target `if (rec.status !== "UNUSED") return 409` — the
    // read-compare-write that made single-use a property of the in-memory DRIVER rather than of the
    // gate. That line no longer exists: the comparison happens inside the store, where a durable
    // driver expresses it as one `UPDATE ... WHERE status = 'UNUSED'`. The registry caught the move
    // ITSELF (`find` matched 0×, MUTATION_NOT_APPLIED) instead of quietly certifying a control that
    // had been rewritten out from under it — which is the entire reason the match count is checked.
    control: "F8a — the single-use burn is a compare-and-swap IN THE STORE, not a local read-compare-write",
    file: "packages/gate/src/engine.ts",
    find: 'const claimed = this.store.claimGrantStatus(grantId, "UNUSED", "RESERVED", this.now());',
    // Knock it out by claiming whatever the status already is: the store is told to move the grant to
    // RESERVED from wherever it stands, so a second caller wins too. That is the DURABLE defect
    // exactly — two callers authorized from one human approval — and `single-use-durable.test.ts` is
    // what turns red for it.
    replace: 'const claimed = this.store.claimGrantStatus(grantId, this.store.getGrant(grantId)!.status, "RESERVED", this.now());',
    kind: "tests",
    suite: ["packages/gate", "npm", ["test"]],
  },
  {
    id: "s3-correlation-nonce-binds-seed",
    control: "S3(a) — the correlation nonce binds a high-entropy seed, so it is not a bare digest of the deal",
    file: "packages/rail-x402/src/correlation-nonce.mjs",
    // RE-PINNED when the derivation stopped feeding a live incremental hash object and started
    // hashing ONE assembled preimage (identical bytes, identical digest — only the dispatch moved
    // onto load-time captures). The registry CAUGHT the rot as `find` matching 0x rather than
    // certifying a control it could no longer see, which is exactly what this layer is for, and is
    // the second time this entry has been re-pinned by that mechanism instead of by someone
    // remembering to.
    find: '    label("seed", seedBytes), seedBytes,',
    // Drop the seed from the preimage and the nonce becomes a deterministic function of five PUBLIC
    // fields — exactly the refuted design: equality leaks, and an observer who can guess the deal can
    // confirm it against the chain. The dictionary-recovery test is what turns red.
    replace: '',
    kind: "tests",
    suite: ["packages/rail-x402", "npm", ["test"]],
  },
  {
    id: "s3-settlement-needs-transfer",
    control: "S3(c) — settlement proof requires a matching ERC-20 Transfer, not just a consumed authorization",
    file: "packages/rail-x402/src/settlement-proof.mjs",
    // The anchor was written BEFORE this file's containers were made inert, so `reasons.push(` became
    // `arrayPush(reasons, ` and the entry rotted the same day it was added. The registry caught it
    // (`find` matched 0x) rather than certifying a control it could no longer find — which is the
    // behaviour, and the reason a knockout entry is worth having.
    find: '  if (!o.transfer) arrayPush(reasons, "no matching ERC-20 Transfer observed");',
    // Without this part, a CANCELLED authorization reads as a settled payment: Circle sets the same
    // state bit for cancellation as for use, so "the nonce was consumed" is not "the money moved".
    replace: '  if (false) arrayPush(reasons, "no matching ERC-20 Transfer observed");',
    kind: "tests",
    suite: ["packages/rail-x402", "npm", ["test"]],
  },
  {
    id: "s4-d7-correlation-recomputed-never-accepted",
    control: "S4/D7 — the correlation is RECOMPUTED from the bundle's own grant seed; an artifact-supplied value is never accepted",
    file: "packages/rail-x402/src/settlement-evidence.mjs",
    find: "  if (derivedNonceHex !== artifactCorrelationHex) {",
    // Neutralize the comparison and the reconciler accepts whatever 32 bytes the artifact carries —
    // exactly the sibling-seed attack: same grant, different seed, a REAL on-chain settlement, and
    // recomputation is the only thing standing between it and a positive verdict.
    // `reject-sibling-seed` (and every other correlation vector) is what turns red.
    replace: "  if (false && derivedNonceHex !== artifactCorrelationHex) {",
    kind: "tests",
    suite: ["packages/rail-x402", "npm", ["test"]],
  },
  {
    id: "s4-transfer-log-address-constraint",
    control: "S4/R-19(b) — a recovered Transfer must come from the approved token CONTRACT, not merely from the payer",
    file: "packages/rail-x402/src/settlement-evidence.mjs",
    find: "  if (lc(transfer.address) !== approvedToken) {",
    // Drop the address constraint and a batched transaction carrying (i) a genuine USDC Transfer
    // payer->mallory and (ii) a worthless-token Transfer payer->approved-payee for a compliant
    // amount recovers (ii): every bound passes, RECONFIRMED, and the money went to mallory.
    // `reject-decoy-transfer-log` is what turns red.
    replace: "  if (false && lc(transfer.address) !== approvedToken) {",
    kind: "tests",
    suite: ["packages/rail-x402", "npm", ["test"]],
  },
  {
    id: "s4-transfer-tx-binding",
    control: "S4 — the recovered transfer must come from the AuthorizationUsed log's OWN transaction (txHash equality)",
    file: "packages/rail-x402/src/settlement-evidence.mjs",
    find: "  if (lc(transfer.txHash) !== lc(log.txHash)) {",
    // Drop the same-transaction binding and a decoy transfer in a DIFFERENT transaction — approved
    // token, payer->approved-payee, compliant amount — reconfirms a settlement whose actual
    // transaction paid someone else. `reject-transfer-foreign-tx` is what turns red.
    replace: "  if (false && lc(transfer.txHash) !== lc(log.txHash)) {",
    kind: "tests",
    suite: ["packages/rail-x402", "npm", ["test"]],
  },
  {
    id: "s4-authorization-state-conjunction",
    control: "S4 — the one-log path requires authorizationState == true BEFORE the log is processed (spec §5(6) conjunction)",
    file: "packages/rail-x402/src/settlement-evidence.mjs",
    find: "  if (facts.authorizationState !== true) {",
    // Skip the conjunction and a record carrying a SUCCESS log with state false — an impossible
    // chain state no honest node returns — earns the positive. `reject-state-false-with-log` is
    // what turns red.
    replace: "  if (false && facts.authorizationState !== true) {",
    kind: "tests",
    suite: ["packages/rail-x402", "npm", ["test"]],
  },
  {
    id: "s4-same-key-cap-on-bytes",
    control: "S4 — the R-16 SAME_SIGNING_KEY cap keys on public-key BYTES resolved through the keyring, not on the kid string",
    file: "packages/rail-x402/src/settlement-evidence.mjs",
    find: "  if (artifact.observerKid === grant?.sig?.kid || sameSigningKeyMaterial) {",
    // Revert to kid-string equality and the grant signer's key registered under a second kid — the
    // alias registration, which is also the legitimate dual-role shape — signs 'and it settled'
    // uncapped. `control-alias-kid-observer` is what turns red.
    replace: "  if (artifact.observerKid === grant?.sig?.kid) {",
    kind: "tests",
    suite: ["packages/rail-x402", "npm", ["test"]],
  },
  {
    id: "s4-settledat-instant-corroboration",
    control: "S4 — R-20's settledAt arm: a reported settledAt disagreeing with the resolved blockTimestamp as INSTANTS contradicts",
    file: "packages/rail-x402/src/settlement-evidence.mjs",
    find: "    if (a === null || b === null || a !== b) {",
    // Neutralize the arm and a fabricated in-window settledAt sails past the only check that reads
    // it against the chain. `reject-settledAt-contradicts-blocktime` is what turns red — before
    // that vector existed NO test executed this arm (measured GREEN-uncovered by both reviewers).
    replace: "    if (false) {",
    kind: "tests",
    suite: ["packages/rail-x402", "npm", ["test"]],
  },
  {
    id: "s4-cancel-log-nonce-binding",
    control: "S4/R-21b — a canceled log may burn or contradict THIS correlation only if it names OUR (payer, nonce)",
    file: "packages/rail-x402/src/settlement-evidence.mjs",
    find: "    if (lc(canceled[i].nonce) !== expectedOnChainNonce) {",
    // Drop the canceled-log nonce binding and a SUCCESSFUL cancel for a FOREIGN nonce burns this
    // correlation — the record cannot even express whose cancel it is. `reject-cancel-foreign-nonce`
    // is what turns red (SETTLEMENT_CHAIN_CONTRADICTED -> SETTLEMENT_CORRELATION_BURNED).
    replace: "    if (false && lc(canceled[i].nonce) !== expectedOnChainNonce) {",
    kind: "tests",
    suite: ["packages/rail-x402", "npm", ["test"]],
  },
  {
    id: "s4-parseinstant-true-year",
    control: "S4 — parseInstant reads the LITERAL year, so years 0000-0099 never alias onto 1900-1999",
    file: "packages/rail-x402/src/settlement-evidence.mjs",
    // RE-PINNED when the epoch computation stopped using the Date family altogether. The previous
    // anchor was the explicit `setUTCFullYear` that REPAIRED the aliasing; the repair itself sat on
    // a rewritable prototype method on the positive path, so the arithmetic replaced it. The
    // registry caught the rot (`find` matched 0x) instead of quietly certifying a control that no
    // longer existed.
    //
    // The mutation reproduces the ORIGINAL defect through the new code: fold years 0-99 into the
    // 1900s, which is precisely what `Date.UTC(year, …)` did.
    find: "  const days = daysFromCivil(year, month, day);",
    // With this, a settledAt of 0099-08-13 aliases to 1999-08-13 and matches a resolved
    // blockTimestamp of 1999-08-13 as instants -> the R-20 arm passes and the artifact earns the
    // positive. `reject-year-0099-not-1999` is what turns red.
    replace: "  const days = daysFromCivil(year < 100 ? year + 1900 : year, month, day);",
    kind: "tests",
    suite: ["packages/rail-x402", "npm", ["test"]],
  },
  {
    id: "s3-consumed-nonce-reconciles",
    control: "S3(b) — a front-run (consumed) nonce is reconciled against chain state, never reported as failure",
    file: "packages/rail-x402/src/settlement-proof.mjs",
    find: "  if (verdict.proven) return { outcome: \"SETTLED\", reasons: [] };",
    // Never return SETTLED and the false negative returns: a payment that actually happened is
    // reported as failed, and a human may pay twice.
    replace: "  if (false) return { outcome: \"SETTLED\", reasons: [] };",
    kind: "tests",
    suite: ["packages/rail-x402", "npm", ["test"]],
  },
  {
    id: "grant-terminal-report-cas",
    control: "F8c — the one-shot TERMINAL report lock is a compare-and-swap, not the pre-check 120 lines above it",
    file: "packages/gate/src/engine.ts",
    find: "const locked = this.store.claimGrantReported(grantId, this.now());",
    // Same shape: hand back a record without ever asking the store to claim, so a second terminal
    // report takes the "lock" as well.
    replace: 'const locked = { ...this.store.getGrant(grantId)!, reportedAt: this.now(), status: "REPORTED" as const };',
    kind: "tests",
    suite: ["packages/gate", "npm", ["test"]],
  },
  {
    id: "grant-ownership-before-cas",
    control: "F29-authz — hold ownership is checked BEFORE any state transition or signature",
    file: "packages/gate/src/engine.ts",
    find: 'if (!this.ownsHold(this.store.getHold(rec.holdId), agent, "report")) return err(404, "UNKNOWN_GRANT");',
    replace: 'if (false as boolean) return err(404, "UNKNOWN_GRANT");',
    kind: "tests",
    suite: ["packages/gate", "npm", ["test"]],
  },
  {
    id: "uncertainty-requires-corroboration",
    control: "F8c — an Execution Uncertainty is signed only after the gate's own sweep window elapsed",
    file: "packages/gate/src/engine.ts",
    find: "if (this.now() - rec.reservedAt < this.cfg.uncertaintySweepWindowMs) return false;",
    replace: "if (false as boolean) return false;",
    kind: "tests",
    suite: ["packages/gate", "npm", ["test"]],
  },
  {
    id: "safe-json-proto-rejection",
    control: "the strict parser rejects __proto__ / prototype / constructor keys",
    file: "src/safe-json.ts",
    // RE-AIMED 2026-07-28. The control moved from a module-level `const FORBIDDEN_KEYS = new Set(…)`
    // to a `isForbiddenKey()` comparing against literals, because `Set.prototype.has` is a writable
    // global slot and the parse boundary cannot decide anything by calling a method it does not own
    // (ADR §5.5). This gate FOUND the move — it reported ROTTED rather than passing, which is exactly
    // what a knockout is for: an entry that silently stops matching measures nothing.
    //
    // The knockout is now a BEHAVIOURAL one rather than a rename. Renaming the function would only
    // fail to compile, which proves the identifier exists, not that the check runs. Inverting the
    // predicate's body makes the parser ACCEPT `__proto__` and the suite must go red.
    find: "return key === \"__proto__\"",
    replace: "return false && key === \"__proto__\"",
    kind: "tests",
    suite: [".", "npm", ["test"]],
  },
  // ── ADDED 2026-07-29 (round-3). One entry per finding, because the previous rounds' fixes shipped
  // with NO knockout at all: nothing in the repository would have gone red if any of them had been
  // reverted, which is why the same class kept reappearing one call deeper and kept being reported as
  // "new". A fix without a knockout is a claim.
  {
    id: "t17-crypto-verify-capture",
    control: "T17 — the Ed25519 signature verdict goes through the LOAD-TIME snapshot of crypto.verify, not a live ESM binding",
    file: "src/keys.ts",
    // Restores the vulnerability exactly: a live `node:crypto` import binding used as the verdict.
    find: "    return ed25519Verify(message, key, sigBytes);",
    replace: "    return _liveVerify(null, message, key as never, sigBytes);",
    also: [{
      find: "import {\n  bufferFrom, bufToString, bufEquals, bufSubarray, byteLength,",
      replace: "import { verify as _liveVerify } from \"node:crypto\";\nimport {\n  bufferFrom, bufToString, bufEquals, bufSubarray, byteLength,",
    }],
    kind: "tests",
    suite: [".", "npm", ["test"]],
  },
  {
    id: "t18-bigint-capture",
    control: "T18 — the y<q canonicality gate builds its comparand with the CAPTURED BigInt, not the bare global",
    file: "src/keys.ts",
    find: "toBigInt(yBytes[i]!)",
    replace: "BigInt(yBytes[i]!)",
    kind: "tests",
    suite: [".", "npm", ["test"]],
  },
  {
    id: "t18-curve-pin-accessor",
    control: "T18b — the Ed25519 curve pin reads asymmetricKeyType through the CAPTURED accessor",
    file: "src/keys.ts",
    find: "    if (asymmetricKeyType(key) !== \"ed25519\") return false;",
    replace: "    if ((key as { asymmetricKeyType?: string }).asymmetricKeyType !== \"ed25519\") return false;",
    kind: "tests",
    suite: [".", "npm", ["test"]],
  },
  {
    id: "t19-parser-inert-arrays",
    control: "T19 — safeParse re-roots every array it emits onto INERT_ARRAY_PROTOTYPE (the ROOT of the iterator/HOF class)",
    file: "src/safe-json.ts",
    find: "        return inertArray(arr);",
    replace: "        return arr;",
    kind: "tests",
    suite: [".", "npm", ["test"]],
  },
  {
    id: "t19-validator-index-walk",
    // WITHDRAWN CLAIM (verbatim): "T19 — the policy validator walks `rules` by INDEX, so a no-op forEach cannot skip every rule"
    // That wording implied an independently load-bearing control. Measured at HEAD 3af47d0: the
    // index-walk mutation alone stayed GREEN. The parser mutation alone caused 3 new failures; the
    // pair caused 4, adding the forEach policy regression. The pair therefore proves the index walk
    // as defence-in-depth behind an independently load-bearing inert-array parser.
    control: "T19 PAIR — safeParse inert-array re-rooting is independently load-bearing (3 new failures alone); with it removed, the validator index walk supplies defence-in-depth (paired removal: 4 new failures, including the forEach policy regression). The index walk alone stayed GREEN at HEAD 3af47d0.",
    file: "src/policy/validate.ts",
    find: "    for (let i = 0; i < pol.rules.length; i++) {\n      const r = pol.rules[i];",
    replace: "    (pol.rules as unknown[]).forEach((r, i) => {",
    also: [{
      find: "      validateCondition(rule.when, `policy.rules[${i}].when`, errors, 0);\n    }",
      replace: "      validateCondition(rule.when, `policy.rules[${i}].when`, errors, 0);\n    });",
    }, { find: "        continue;\n      }\n      const rule = r as Record<string, unknown>;", replace: "        return;\n      }\n      const rule = r as Record<string, unknown>;" }],
    // WITHDRAWN CLAIM (verbatim):
    // The parser's re-rooting independently defeats this poison, so knocking out ONE layer leaves the
    // other measuring it and the run would report a false "nothing measures this". Both come out
    // together — which is also the honest statement of the design: two layers, each load-bearing.
    // Correction: only the parser is independently load-bearing; the extra paired failure is the
    // measured basis for calling the index walk defence-in-depth.
    andAlso: "t19-parser-inert-arrays",
    kind: "tests",
    suite: [".", "npm", ["test"]],
  },
  {
    id: "t19b-cbor-inert-arrays",
    control: "T19b — the CBOR decoder re-roots decoded arrays AND each map pair (destructuring dispatches through the pair's own iterator)",
    file: "src/cose/cbor.ts",
    find: "      return { t: \"map\", v: inertArray(m) };",
    replace: "      return { t: \"map\", v: m };",
    also: [{
      find: "        arrayPush(m, inertArray([key, val]) as [CborValue, CborValue]);",
      replace: "        arrayPush(m, [key, val] as [CborValue, CborValue]);",
    }],
    kind: "tests",
    suite: [".", "npm", ["test"]],
  },
  {
    id: "inert-proto-refuses-accessors",
    control: "INERT_ARRAY_PROTOTYPE copies DATA descriptors only — a pre-load accessor is refused (absent), never copied",
    // RE-AIMED 2026-07-29 (round-4, A1). The construction MOVED from `src/inert.ts` to
    // `src/intrinsics.ts` so the captured wrappers could re-root the arrays they manufacture through
    // it without an import cycle. This entry reported ROTTED on the first run after the move, which
    // is exactly what a knockout registry is for: an entry that silently stops matching measures
    // nothing, and the runner says so instead of passing.
    file: "src/intrinsics.ts",
    find: "    if (!(_apply(_hasOwnProperty, d as never, [\"value\"] as never) as boolean)) continue;",
    replace: "    if (!(_apply(_hasOwnProperty, d as never, [\"value\"] as never) as boolean)) { _apply(_objectDefineProperty, undefined as never, [proto, key, { get: d.get, set: d.set, enumerable: false, configurable: false }] as never); continue; }",
    kind: "tests",
    suite: [".", "npm", ["test"]],
  },
  {
    id: "t20-l8-selftest",
    control: "T20/A5 — every AST-gate rule is proven to BITE against a known-positive sample (a gate reading 0 because it matches nothing is the false-green pathology)",
    // RE-AIMED 2026-07-29 (round-4, A5): L8 is no longer a set of regexes, so the string this entry
    // used to defang does not exist. It now defangs a NODE-KIND test in the analyser itself. The
    // evasion matrix's `for-of` positive sample must go unflagged and L8-selftest must go red.
    file: "scripts/lib/dispatch-ast.mjs",
    find: "      if (ts.isForOfStatement(node) && deferred) {",
    replace: "      if (false && ts.isForOfStatement(node) && deferred) {",
    kind: "gate",
    gateId: "security-gates",
    expectedGateFindings: [{ rule: "L8-selftest", subject: "scripts/lib/dispatch-ast.mjs" }],
    suite: [".", "npm", ["run", "lint:security-gates"]],
  },
  {
    id: "t20-source-lock-scope",
    control: "T20 — the source lock's subject is the WHOLE derived TCB, not a hand-picked five",
    file: "test/security/intrinsic-poisoning.test.ts",
    // Aimed at the DERIVATION, not at the scan loop. Narrowing the loop alone is unmeasurable once
    // the tree is clean — nothing is found either way — which is precisely the trap: a scope
    // regression is invisible until an offender exists, so the SCOPE ITSELF has to be the assertion.
    // Replacing the derived list with the hand-picked five this lock used to carry is the exact
    // regression that left src/keys.ts unlocked while it held a live `verify` binding on the
    // signature verdict, and it turns the coverage test red immediately.
    find: "  return (block![1]!.match(/\"([^\"]+)\"/g) ?? []).map((s) => s.slice(1, -1));",
    replace: "  return [\"src/hash.ts\", \"src/signing.ts\", \"src/cose/cbor.ts\", \"src/nfc.ts\", \"src/verify.ts\"];",
    kind: "tests",
    suite: [".", "npm", ["test"]],
  },
  // ── ADDED 2026-07-29 (round-4). One entry per control this pass introduced. The previous three
  // rounds' fixes shipped with NO knockout, which is why the same class kept reappearing one call
  // deeper and kept being reported as "new". A fix without a knockout is a claim.
  {
    id: "r4-a1-inert-wrappers",
    control: "A1 — the captured wrappers that MANUFACTURE arrays (objectKeys/ownNames/ownKeys/slice/split/…) return INERT-rooted arrays, so a fresh array is never rooted on the live Array.prototype",
    file: "src/intrinsics.ts",
    // The root of the whole round-4 class, in one edit: make the re-rooting a no-op.
    find: "function _inert<T>(a: T[]): T[] {\n  _apply(_objectSetPrototypeOf, undefined as never, [a, INERT_ARRAY_PROTOTYPE] as never);\n  return a;\n}",
    replace: "function _inert<T>(a: T[]): T[] {\n  return a;\n}",
    kind: "tests",
    suite: [".", "npm", ["test"]],
  },
  {
    id: "r4-a2-noextrakeys-index-walk",
    // WITHDRAWN CLAIM (verbatim): "A2 — the policy closed-grammar check walks keys by INDEX, so a skipping iterator cannot hide an unknown key (DENY/policy-invalid -> ALLOW/allow-x, measured)"
    control: "A2 PAIR — inert array-manufacturing wrappers are independently load-bearing (1 new failure alone); with them removed, the policy closed-grammar index walk supplies defence-in-depth (paired removal: 4 new failures, including the hidden-key regression). The index walk alone stayed GREEN at HEAD 3af47d0.",
    file: "src/policy/validate.ts",
    find: "  const keys = objectKeys(obj);\n  for (let i = 0; i < keys.length; i++) {\n    const k = keys[i] as string;",
    replace: "  for (const k of objectKeys(obj)) {",
    // WITHDRAWN CLAIM (verbatim):
    // A1 independently defeats this poison, so knocking out ONE layer leaves the other measuring it
    // and the run would report a false "nothing measures this". Both come out together — which is
    // also the honest statement of the design: two layers, each load-bearing.
    // Correction: only A1 is independently load-bearing; the three additional paired failures are
    // the measured basis for calling this index walk defence-in-depth.
    andAlso: "r4-a1-inert-wrappers",
    kind: "tests",
    suite: [".", "npm", ["test"]],
  },
  {
    id: "r4-a2-checkpoint-index-walk",
    // WITHDRAWN CLAIM (verbatim): "A2 — the checkpoint closed-schema walk is an INDEX walk, so a skipping iterator cannot hide a smuggled (and honestly re-signed) field (TAMPERED -> VALID/tailChecked, measured)"
    control: "A2 PAIR — inert array-manufacturing wrappers are independently load-bearing (1 new failure alone); with them removed, the checkpoint closed-schema index walk supplies defence-in-depth (paired removal: 3 new failures, including chain and standalone checkpoint regressions). The index walk alone stayed GREEN at HEAD 3af47d0.",
    file: "src/verify.ts",
    find: "  const cKeys = objectKeys(c);\n  for (let i = 0; i < cKeys.length; i++) {\n    if (!arrayIncludes(CHECKPOINT_KEYS, cKeys[i] as string)) return \"malformed checkpoint\";\n  }",
    replace: "  for (const k of objectKeys(c)) {\n    if (!arrayIncludes(CHECKPOINT_KEYS, k)) return \"malformed checkpoint\";\n  }",
    andAlso: "r4-a1-inert-wrappers",
    kind: "tests",
    suite: [".", "npm", ["test"]],
  },
  {
    id: "r4-a2-manifest-index-walk",
    // WITHDRAWN CLAIM (verbatim): "A2 — the identity-manifest walk is an INDEX walk, so a skipping iterator cannot hide a malformed entry from validation (MALFORMED -> VALID, measured)"
    control: "A2 PAIR — inert array-manufacturing wrappers are independently load-bearing (1 new failure alone); with them removed, the identity-manifest index walk supplies defence-in-depth (paired removal: 3 new failures, including verifyChain and substituted-key regressions). The index walk alone stayed GREEN at HEAD 3af47d0.",
    file: "src/verify.ts",
    find: "      const aids = objectGetOwnPropertyNames(live);\n      for (let ai = 0; ai < aids.length; ai++) {\n        const aid = aids[ai] as string;",
    replace: "      for (const aid of objectGetOwnPropertyNames(live)) {",
    andAlso: "r4-a1-inert-wrappers",
    kind: "tests",
    suite: [".", "npm", ["test"]],
  },
  {
    id: "r4-t06-newset-captured-add",
    control: "R4-T06 — newSet(init) fills through the CAPTURED Set.prototype.add; `new Set(iterable)` reads `this.add` off the instance and calls it per element, so a no-op add silently empties the committed read-set",
    file: "src/intrinsics.ts",
    find: "  const s = new _Set() as Set<T>;\n  if (init !== undefined) {\n    for (let i = 0; i < (init as { length: number }).length; i++) _apply(_setAdd, s as never, [init[i]] as never);\n  }\n  return s;",
    replace: "  return new _Set(init as never) as Set<T>;",
    kind: "tests",
    suite: [".", "npm", ["test"]],
  },
  {
    id: "r4-t07-audit-captured-weakset",
    control: "R4-T07 — the policy-table audit's cycle guard uses the CAPTURED WeakSet.prototype.has; a live `has -> true` made inertViolations return [] , i.e. the control that hunts mutable policy tables reported CLEAN exactly when an attacker was present",
    file: "src/inert.ts",
    find: "    if (weakSetHas(seen, value as object)) return;\n    weakSetAdd(seen, value as object);",
    replace: "    if (seen.has(value as object)) return;\n    seen.add(value as object);",
    kind: "tests",
    suite: [".", "npm", ["test"]],
  },
  {
    id: "r4-a1c-publication-boundary",
    control: "A1c — a CALLER-OWNED public result (readSet, warnings, inertViolations) is published as an ORDINARY array; shipping the inert internal breaks `instanceof Array` and `deepStrictEqual` for every consumer",
    file: "src/intrinsics.ts",
    find: "export function publishArray<T>(a: readonly T[]): T[] {\n  const out: T[] = [];\n  for (let i = 0; i < (a as { length: number }).length; i++) _apply(_push, out as never, [a[i]]);\n  return out;\n}",
    replace: "export function publishArray<T>(a: readonly T[]): T[] {\n  return a as T[];\n}",
    kind: "tests",
    suite: [".", "npm", ["test"]],
  },
  {
    id: "r4-a5-ast-load-time-exemption",
    control: "A5 — the AST gate's load-time exemption is STRUCTURAL (a parameter default is call-time, an IIFE at module level is load-time); widening it to 'everything is load-time' must not be able to silence the gate",
    file: "scripts/lib/dispatch-ast.mjs",
    find: "function isLoadTime(node) {\n  let n = node;",
    replace: "function isLoadTime(node) {\n  if (node) return true;\n  let n = node;",
    kind: "gate",
    gateId: "security-gates",
    expectedGateFindings: [{ rule: "L8-selftest", subject: "scripts/lib/dispatch-ast.mjs" }],
    suite: [".", "npm", ["run", "lint:security-gates"]],
  },
  {
    id: "r4-a5-ast-symbol-resolution",
    control: "A5 — the AST gate resolves the leftmost identifier's SYMBOL to decide 'ambient global or ours'; degrading that to 'never a global' is the one-line way to make the gate read 0 forever",
    file: "scripts/lib/dispatch-ast.mjs",
    find: "  if (!BUILTIN_GLOBALS.has(id.text) && !BARE_GLOBAL_CALLS.has(id.text)) return false;",
    replace: "  if (id) return false;\n  if (!BUILTIN_GLOBALS.has(id.text) && !BARE_GLOBAL_CALLS.has(id.text)) return false;",
    kind: "gate",
    gateId: "security-gates",
    expectedGateFindings: [{ rule: "L8-selftest", subject: "scripts/lib/dispatch-ast.mjs" }],
    suite: [".", "npm", ["run", "lint:security-gates"]],
  },
  {
    id: "r8-15-deep-copy-defineproperty",
    control: "R8-15 \u2014 inertDeepCopy builds its output with defineProperty, NEVER assignment. `out[key] = v` on a plain object consults the prototype chain for a setter, and `Object.prototype.__proto__` is one \u2014 so an own `__proto__` (which JSON.parse produces from ordinary untrusted input) was consumed by the setter instead of copied. The signature covered bytes the returned receipt did not contain, and an injected approval read back as a phantom that is in no wire byte.",
    file: "packages/signer-core/src/deep-copy.ts",
    find: "    objectDefineProperty(out, key, {\n      value: copyValue(d.value, `${path}.${key}`, depth + 1),\n      writable: true,\n      enumerable: true,\n      configurable: true,\n    });",
    replace: "    out[key] = copyValue(d.value, `${path}.${key}`, depth + 1);",
    kind: "tests",
    suite: ["packages/signer-core", "npm", ["test"]],
  },
  {
    id: "r8-15b-deep-copy-array-defineproperty",
    control: "R8-15b \u2014 the ARRAY branch of inertDeepCopy also builds with defineProperty. `out` is a fresh array rooted on the LIVE Array.prototype \u2014 the one prototype this file cannot capture \u2014 so an index accessor defined there OWNED the element write. Measured: a copy of [\"HONEST-FIRST-ELEMENT\",\"second\"] serialised as [\"ATTACKER\",\"second\"]. The source-element accessor guard does not reach it; that guard inspects the SOURCE, the hostile accessor is on the DESTINATION's prototype.",
    file: "packages/signer-core/src/deep-copy.ts",
    find: "      objectDefineProperty(out, i, {\n        value: copyValue(d.value, `${path}[${i}]`, depth + 1),\n        writable: true,\n        enumerable: true,\n        configurable: true,\n      });",
    replace: "      out[i] = copyValue(d.value, `${path}[${i}]`, depth + 1);",
    kind: "tests",
    suite: ["packages/signer-core", "npm", ["test"]],
  },
  {
    id: "p01-root-validfrom-carried",
    control: "P0-1 \u2014 asRootKeyEntryMap carries `validFrom` on ROOT entries. It carried revokedAt but DROPPED validFrom, and verify.ts:234 enforces activation only when the field is non-null \u2014 so a trust-root signature dated BEFORE its own declared activation verified clean. The manifest sibling (trust.ts:156) was fixed for exactly this class and says so; the ROOT resolver 80 lines above was not. [proof: RES-PAR-EVID-ROOT, RES-PAR-ROOT-ENFORCED-E2E]",
    file: "packages/evidence/src/trust.ts",
    find: "validFrom: e.validFrom ?? null, revokedAt: e.revokedAt ?? null };",
    replace: "revokedAt: e.revokedAt ?? null };",
    kind: "tests",
    suite: ["packages/evidence", "npm", ["test"]],
  },
  {
    id: "p05-gate-keyring-validfrom-carried",
    control: "P0-5 — createAlphaTrust carries the generated GATE activation into the live keyring; deleting it makes the registered resolver proof itself fail. [proof: RES-PAR-GATE-KEYRING]",
    file: "packages/gate/src/trust.ts",
    // RE-AIMED 2026-08-12 (S0 authority-root split). The literal role array on this line became
    // `gateRoles` when the execution-signer role moved out of the gate process, so `find` matched
    // 0x and the runner correctly reported MUTATION_NOT_APPLIED — the control was UNMEASURED, not
    // passing. Same control, same mutation (delete the carried activation), re-aimed at the line as
    // it is now written.
    find: '    [gate.kid]: { publicKey: gate.publicKey, type: "GATE", roles: gateRoles, validFrom, revokedAt: null },',
    replace: '    [gate.kid]: { publicKey: gate.publicKey, type: "GATE", roles: gateRoles, revokedAt: null },',
    kind: "tests",
    suite: ["packages/gate", "npm", ["test"]],
  },
  {
    id: "s0-grant-authority-out-of-gate-process",
    control:
      "S0 — the gate process holds NO key the KEY MANIFEST lets sign an Execution Grant. Give the gate " +
      "key back its `execution-signer` role and a compromised gate can mint grants with its own key again, " +
      "which is the defect NON-CLAIMS.md's authority-root corollary recorded.",
    file: "packages/gate/src/trust.ts",
    find: '  const gateRoles: string[] = external ? ["hold-signer"] : ["hold-signer", "execution-signer"];',
    replace: '  const gateRoles: string[] = ["hold-signer", "execution-signer"];',
    kind: "tests",
    suite: ["packages/gate", "npm", ["test"]],
  },
  {
    id: "s0-cross-keyring-kid-agreement",
    control:
      "S0 (adversarial review 2026-08-12, CRITICAL) — the grant signer refuses a trust file in which one kid " +
      "denotes DIFFERENT public keys in the artifact keyring and the receipt keyring. Without it a genuine approver-client " +
      "Decision and a gate-forged ALLOWED receipt carrying attacker parameters both verify under one kid string, " +
      "and the sidecar signs a grant the shipped verifier then accepts.",
    file: "packages/gate/src/grant-sidecar.ts",
    find: '    if (receiptPub !== entry["publicKey"]) {',
    replace: "    if (false) {",
    kind: "tests",
    suite: ["packages/gate", "npm", ["test"]],
  },
  {
    id: "s0-approver-key-not-co-resident",
    control:
      "S0 (adversarial review 2026-08-12, CRITICAL) — an EXTERNAL execution signer may not be combined with a " +
      "gate-generated approver key. The sidecar authorizes on the one signature an attacker inside the gate cannot " +
      "forge; generating that key in the gate makes the whole boundary decorative, and it was the only shipped wiring.",
    file: "packages/gate/src/trust.ts",
    find: "  if (external && !enrolledApprover) {",
    replace: "  if (false) {",
    kind: "tests",
    suite: ["packages/gate", "npm", ["test"]],
  },
  {
    id: "s0-returned-signature-is-verified",
    control:
      "S0 (adversarial review 2026-08-12, HIGH) — the gate cryptographically verifies every signature the signer " +
      "returns before treating it as its own authority. Without it a response echoing the document with a junk " +
      "sig value made decide() return 200 and persist an APPROVED hold with a grant record.",
    file: "packages/gate/src/exec-signer.ts",
    find: '  if (!verifyEd25519(expectPublicKey, signingMessage(domain, signHashInput(signed)), s["value"] as string)) {',
    replace: "  if (false) {",
    kind: "tests",
    suite: ["packages/gate", "npm", ["test"]],
  },
  {
    id: "s0-grant-params-bound-to-approval",
    control:
      "S0 — the out-of-process grant signer refuses to sign a grant whose paramsHash is not the one a human " +
      "approved. This is the single check that separates a policy gate from a bare signing oracle: without it " +
      "an attacker who can merely REACH the socket has the key in effect.",
    file: "packages/gate/src/grant-sidecar.ts",
    find: '  if (grant["paramsHash"] !== approvedParamsHash) {',
    replace: '  if (grant["paramsHash"] !== approvedParamsHash && false) {',
    kind: "tests",
    suite: ["packages/gate", "npm", ["test"]],
  },
  {
    id: "p06-activation-time-strict",
    control: "P0-6 — a non-canonical declared activation is refused instead of being normalised by Date.parse into a usable instant. [proof: RES-PAR-AA-STRICT]",
    file: "packages/approval-artifacts/src/verify.ts",
    // RE-AIMED 2026-08-01. The previous pair targeted `CANONICAL_INSTANT.test(v)`, a regex guard that
    // batch C deleted when `parseTime` became epoch arithmetic. `find` then matched 0×, the runner
    // reported MUTATION_NOT_APPLIED, and this control went UNMEASURED — its test kept passing and
    // proved nothing, because nothing was mutating the line it was supposed to watch. A knockout whose
    // anchor rots is worse than no knockout: it keeps printing a row in a table people read as coverage.
    //
    // NARROWED 2026-08-03 after a redteam review REFUTED the previous justification. That comment
    // claimed the whole-function wrapper was "the only shape that removes the control without also
    // changing what the parser accepts". It is not. The reviewer built this one and measured it
    // breaking ONLY the named proof, where the wrapper broke three tests:
    //     wrapper (withdrawn)  DETECTOR_TRIGGERED, 3 new failures: Batch N; P0-6 proof; P0-9
    //     this one            DETECTOR_TRIGGERED, 1 new failure:  P0-6 proof
    //
    // The claim was wrong in a specific and instructive way: two narrower mutations HAD failed to
    // kill the control (structural guard alone => the schema refuses first; schema check alone =>
    // the structural guard refuses), and from "these two did not work" I concluded "nothing narrower
    // can". That is an argument, not a measurement, and it is exactly the move this file exists to
    // catch — the strictness IS layered, but a mutation aimed at one INPUT CLASS slips between the
    // layers, which neither of my two attempts did.
    //
    // A knockout that kills three tests still passes anti-vacuity (the runner requires the named
    // proof among the new failures, not that it be alone), so nothing would have flagged this. It
    // would simply have made the next person read a wider blast radius as evidence of a wider control.
    //
    // Its `marker` in resolver-inventory.json was the FULL TEXT OF THE TEST NAME, so tagging the test
    // with [PROOF:RES-PAR-AA-STRICT] unbound it instantly. Changed to the tag form that
    // RES-PAR-ROOT-ENFORCED already used: a marker that is a sentence is one rewording away from
    // silently certifying nothing.
    find: 'function parseTime(v: unknown, timeSchema: Record<string, unknown> | null): bigint | null {',
    replace: 'function parseTime(v: unknown, timeSchema: Record<string, unknown> | null): bigint | null {\n  if (typeof v === "string" && v.length === 1) {\n    const ms = Date.parse(v);\n    if (ms === ms) return toBigInt(ms) * 1_000_000n;\n  }',
    kind: "tests",
    suite: ["packages/approval-artifacts", "npm", ["test"]],
  },
  {
    id: "c77-display-captured-decode",
    control: "#77-C/1 \u2014 openEncryptedDisplay interprets the AUTHENTICATED plaintext through a CAPTURED TextDecoder.prototype.decode and a CAPTURED JSON.parse. Live, the AEAD verified and the human was shown \"Refund EUR 1.00 to Alice\" while the sealed display said \"Wire EUR 2,400,000 to NEW payee GmbH\" \u2014 the product's core failure mode via prototype pollution alone.",
    file: "packages/signer-core/src/encrypted-display.ts",
    find: "    const plaintextText = reflectApply(textDecoderDecode, sharedDecoder, [plaintext]) as string;\n    const parsed = reflectApply(jsonParse, JSONObject, [plaintextText]) as unknown;",
    replace: "    const parsed = JSON.parse(new TextDecoder().decode(plaintext)) as unknown;",
    kind: "tests",
    suite: ["packages/signer-core", "npm", ["test"]],
  },
  {
    id: "c77-display-recipient-index-walk",
    control: "#77-C/2 \u2014 sealEncryptedDisplay builds the recipient set with an INDEX WALK, not Array.prototype.map. A recipients Proxy installs the poison after the entry fence; a vulnerable map call selects the attacker and self-restores before the final fence. The index walk invokes it zero times, so the final fence sees and rejects the still-installed poison before any CEK exists.",
    file: "packages/signer-core/src/encrypted-display.ts",
    find: "  const normalizedRecipients: Array<{ kid: string; publicKey: Uint8Array }> = [];\n  for (let i = 0; i < recipientCount; i++) {\n    // Template substitution uses the language's internal number-to-string operation. A live\n    // `String(i)` lookup lets a recipients Proxy replace globalThis.String, redirect this index,\n    // self-restore, and leave the final integrity fence looking clean.\n    const recipient = ownDataValue(recipientsInput, `${i}`, \"sealEncryptedDisplay.recipients\", true);\n    const kid = ownString(recipient, \"kid\", `sealEncryptedDisplay.recipients[${i}]`);\n    const publicKeyText = ownString(recipient, \"hpkePublicKey\", `sealEncryptedDisplay.recipients[${i}]`);\n    normalizedRecipients[i] = {\n      kid,\n      publicKey: copyHpkeBytes(decodeX25519PublicKey(publicKeyText), `sealEncryptedDisplay.recipients[${i}].hpkePublicKey`),\n    };\n  }",
    replace: "  const normalizedRecipients = (recipientsInput as DisplayRecipient[]).map((recipient, i) => {\n    const kid = ownString(recipient, \"kid\", `sealEncryptedDisplay.recipients[${i}]`);\n    const publicKeyText = ownString(recipient, \"hpkePublicKey\", `sealEncryptedDisplay.recipients[${i}]`);\n    return {\n      kid,\n      publicKey: copyHpkeBytes(decodeX25519PublicKey(publicKeyText), `sealEncryptedDisplay.recipients[${i}].hpkePublicKey`),\n    };\n  });",
    kind: "tests",
    suite: ["packages/signer-core", "npm", ["test"]],
  },
  {
    id: "b77-jcs-captured-sort",
    control: "#77-B/3 \u2014 jcs sorts keys with a CAPTURED Array.prototype.sort. Live, a sort that empties the list made {a:1,b:2} and {x:\"production.delete.all\"} both canonicalize to \"{}\"; a sort that is the identity made the SAME document in two key orders produce TWO canonical forms.",
    file: "packages/signer-core/src/jcs.ts",
    find: "  reflectApply(arraySortRaw, ks, []);",
    replace: "  ks.sort();",
    kind: "tests",
    suite: ["packages/signer-core", "npm", ["test"]],
  },
  {
    id: "b77-jcs-captured-keys",
    control: "#77-B/3 \u2014 jcs enumerates with a CAPTURED Object.keys. Live, `Object.keys -> []` erased every field from the commitment and distinct documents collapsed.",
    file: "packages/signer-core/src/jcs.ts",
    find: "  const ks = objectKeys(o);",
    replace: "  const ks = Object.keys(o);",
    kind: "tests",
    suite: ["packages/signer-core", "npm", ["test"]],
  },
  {
    id: "b77-jcs-captured-iswellformed",
    control: "#77-B/3 \u2014 the unpaired-surrogate refusal reads a CAPTURED String.prototype.isWellFormed. Live and forced true, U+D800 and U+D801 both encoded to 7b2273223a22efbfbd227d \u2014 2048 code points into one hash bucket, the forgery channel serializeString exists to close.",
    file: "packages/signer-core/src/jcs.ts",
    find: "  if (!(reflectApply(strIsWellFormed, s, []) as boolean)) {",
    replace: "  if (!s.isWellFormed()) {",
    kind: "tests",
    suite: ["packages/signer-core", "npm", ["test"]],
  },
  {
    id: "b77-deepcopy-non-enumerable-refusal",
    control: "#77-B/1 \u2014 inertDeepCopy REFUSES an own non-enumerable property. jcs.ts walks Object.keys (own+ENUMERABLE) while deep-copy walks getOwnPropertyNames (own, incl. non-enumerable) and defines everything enumerable:true \u2014 so such a field was invisible to the hash and visible in the returned receipt. Measured end to end: signed governance had no approval, returned governance carried HUMAN:cfo-victim, root verdict TAMPERED.",
    file: "packages/signer-core/src/deep-copy.ts",
    find: "    if (d.enumerable !== true) {",
    replace: "    if (false) {",
    kind: "tests",
    suite: ["packages/signer-core", "npm", ["test"]],
  },
  {
    id: "b77-jcs-named-array-refusal",
    control: "#77-B/2 \u2014 canonicalize() is a PUBLIC EXPORT and must be injective: an array carrying a named property canonicalized to the same bytes as one without it ([1] either way). Not reachable via producer or wire, but reachable directly through the export.",
    file: "packages/signer-core/src/jcs.ts",
    find: "      if (name === \"length\") continue;",
    replace: "      if (name === \"length\") continue;\n      if (name) continue;",
    kind: "tests",
    suite: ["packages/signer-core", "npm", ["test"]],
  },
  {
    id: "k4-gate-refuses-inherited-library-search-path",
    control: "L4 evidence integrity — an inherited LD_LIBRARY_PATH refuses an evidence observation. The dynamic loader searches those directories BEFORE the default ones, so a writable entry selects which shared object starts the process; glibc hardening guidance says not to use LD_PRELOAD or LD_LIBRARY_PATH to change loader behaviour. An earlier revision removed it from the refusal list because GitHub's runner sets it, which fixed the wrong side: the environment is cleaned at the launch point instead.",
    file: "scripts/lib/knockout-runner.mjs",
    find: "  \"LD_PRELOAD\", \"LD_LIBRARY_PATH\", \"LD_AUDIT\",",
    replace: "  \"LD_PRELOAD\", \"LD_AUDIT\",",
    kind: "gate",
    gateId: "knockout-selftest",
    expectedGateFindings: [{
      rule: "SELFTEST",
      subject: "an inherited LD_LIBRARY_PATH is REFUSED, and removing it at the launch point restores the run",
    }],
    suite: [".", "node", ["scripts/lint-control-knockout.selftest.mjs"]],
  },
  {
    id: "k4-proof-steps-install-before-they-resolve",
    control: "L4 evidence integrity — the single preparation runner installs every package a proof or knockout lane resolves through BEFORE that lane consumes it, exactly once per directory, and DERIVES the list from the resolver and knockout registry rather than keeping it by hand. Reproduced twice: first the packages were installed inside the R7 exploit step, several steps below the proof steps that need them; then a hand-kept list named gate and approval-artifacts while the runner also builds packages/evidence, and CI died with \"ENOENT ... packages/evidence/node_modules/typescript/bin/tsc\" inside lint-resolver-parity. This mutation replaces the derivation with the hand-kept two-package list that failed.",
    file: "scripts/prepare-proof-packages.mjs",
    find: "const lines = derive(\"proof-package\", [\"scripts/lint-resolver-parity.mjs\", \"--print-proof-packages\"]);",
    replace: "const lines = [\"packages/approval-artifacts\\tbuild\", \"packages/gate\\tbuild\"];",
    kind: "gate",
    gateId: "knockout-selftest",
    expectedGateFindings: [{
      rule: "SELFTEST",
      subject: "the preparation runner validates the WHOLE plan before it installs anything, and refuses bad plans",
    }],
    suite: [".", "node", ["scripts/lint-control-knockout.selftest.mjs"]],
  },
  {
    id: "k4-suite-preparation-closes-local-file-deps",
    control: "L4 evidence integrity — a knockout suite's preparation includes the dependency-first closure of every local file: link, not only the package directory that owns the suite. Reproduced on a clean checkout: mcp-proxy's smoke suite starts signer-sidecar/src/sidecar.mjs directly; without signer-sidecar's own install, that source cannot resolve noa-mcp-adapter-core and the clean baseline never completes node:test. A populated developer tree hid the omission. This mutation restores the direct-package-only census that failed in CI.",
    file: "scripts/lib/proof-resolve.mjs",
    find: "    for (const dep of localDepsOf(cwd)) visit(dep);",
    replace: "    for (const dep of []) visit(dep);",
    kind: "gate",
    gateId: "knockout-selftest",
    expectedGateFindings: [{
      rule: "SELFTEST",
      subject: "the preparation planner orders a synthetic file: chain, and fails closed on every bad plan",
    }],
    suite: [".", "node", ["scripts/lint-control-knockout.selftest.mjs"]],
  },
  {
    id: "k4-inner-observer-escalates-sigterm-to-sigkill",
    control: "L4 evidence integrity — inside the disposable namespace the observer escalates SIGTERM to SIGKILL, so a descendant that ignores the polite signal cannot outlive the suite whose deadline expired. A process group is not the boundary and the runner says so: setsid(2) makes a negative-PGID kill unreachable, which is why containment is the namespace and escalation happens within it. The regression spawns a descendant that installs a SIGTERM handler, announces READY, records SIGTERM_SEEN when signalled and SURVIVED_SIGTERM shortly after, then stays alive; the suite hangs until the deadline. All three markers must appear, the run must report a timeout, and the observer must not come back saying a descendant was left alive or that the process group survived SIGKILL escalation. This mutation downgrades the escalation to a second SIGTERM, which the descendant is written to ignore. An earlier attempt mutated the OUTER runner's timedOut flag instead; that was invalid — it changed a report rather than the escalation, and it did not trigger.",
    file: "scripts/lib/knockout-test-observer.mjs",
    find: "          terminateTree(child, \"SIGKILL\");",
    replace: "          terminateTree(child, \"SIGTERM\");",
    kind: "gate",
    gateId: "knockout-selftest",
    expectedGateFindings: [{
      rule: "SELFTEST",
      subject: "a timeout tears down the evidence namespace, so a SIGTERM-resistant descendant cannot outlive it",
    }],
    suite: [".", "node", ["scripts/lint-control-knockout.selftest.mjs"]],
  },
  {
    id: "k4-steady-tombstone-does-not-stage",
    control: "L4 recovery integrity — once a complete migration tombstone exists, every contender returns before opening staging bytes inside the public runtime closure. This mutation removes that early return, so the no-transient-write regression must detect the staging open even though the atomic link later loses with EEXIST.",
    file: "scripts/lib/knockout-runner.mjs",
    find: "  try { fs.lstatSync(legacyLock); return false; }",
    replace: "  try { fs.lstatSync(legacyLock); }",
    kind: "gate",
    gateId: "knockout-selftest",
    expectedGateFindings: [{
      rule: "SELFTEST",
      subject: "an already-migrated contender creates no transient tombstone staging file",
    }],
    suite: [".", "node", ["scripts/lint-control-knockout.selftest.mjs"]],
  },
  {
    id: "k4-lock-loser-publishes-no-run-state",
    control: "L4 recovery integrity — a contender publishes its nonce-specific run directory only after O_EXCL proves it owns the lock. A loser that creates one first leaves unowned recovery shells on every contention and makes the cache grow without bound.",
    file: "scripts/lib/knockout-runner.mjs",
    find: "      if (e && e.code === \"EEXIST\") return null;",
    replace: "      if (e && e.code === \"EEXIST\") { fs.mkdirSync(record.runDir); return null; }",
    kind: "gate",
    gateId: "knockout-selftest",
    expectedGateFindings: [{
      rule: "SELFTEST",
      subject: "the lock is EXCLUSIVE: a second guard on the same cache cannot start",
    }],
    suite: [".", "node", ["scripts/lint-control-knockout.selftest.mjs"]],
  },
  {
    id: "k4-generation-drift-keeps-live-holder-authoritative",
    control: "L4 recovery integrity — LIVE, UNKNOWN and SELF holder states refuse before recovery-safety classification. A stale generation changes whether dead bytes may be applied; it must never turn a process that is still live or indeterminate into removable corruption.",
    file: "scripts/lib/knockout-runner.mjs",
    find: "            if (state === \"LIVE\" || state === \"UNKNOWN\" || state === \"SELF\") {",
    replace: "            if ((state === \"LIVE\" || state === \"UNKNOWN\" || state === \"SELF\") && recoveryUnsafe === null) {",
    kind: "gate",
    gateId: "knockout-selftest",
    expectedGateFindings: [{
      rule: "SELFTEST",
      subject: "birth-time drift cannot split one physical repository into two locks",
    }],
    suite: [".", "node", ["scripts/lint-control-knockout.selftest.mjs"]],
  },
  {
    id: "k4-in-process-guard-cache-revalidates-root",
    control: "L4 recovery integrity — an in-process guard cache hit reopens the cached lexical root and compares both physical identity and recovery generation before reuse. If the previous directory was deleted and its device+inode identity reused, an active stale guard refuses and an ownerless stale guard is rebuilt; neither may be handed to the replacement tree.",
    file: "scripts/lib/knockout-runner.mjs",
    find: "    if (bindingChanged) {",
    replace: "    if (false) {",
    kind: "gate",
    gateId: "knockout-selftest",
    expectedGateFindings: [{
      rule: "SELFTEST",
      subject: "cached in-process guards revalidate their physical root before reuse",
    }],
    suite: [".", "node", ["scripts/lint-control-knockout.selftest.mjs"]],
  },
  {
    id: "k4-startup-surface-fixture-releases-owned-guard",
    control: "L4 self-verification hygiene — the startup-surface adversarial fixture owns an explicit guard/cache and proves release before deleting the guarded root. A fixture that silently leaves its default singleton behind can poison a later inode-reused fixture and make the judge order-dependent.",
    file: "scripts/lint-control-knockout.selftest.mjs",
    find: "    const released = workspaceGuard.ownerNonce === null || workspaceGuard.release();",
    replace: "    const released = (workspaceGuard.ownerNonce === null || workspaceGuard.release()) && false;",
    kind: "gate",
    gateId: "knockout-selftest",
    expectedGateFindings: [{
      rule: "SELFTEST",
      subject: "a GATE observation refuses an inherited Node startup hook instead of reading its output",
    }],
    suite: [".", "node", ["scripts/lint-control-knockout.selftest.mjs"]],
  },
  {
    id: "k4-terminal-start-states-carry-scan-warnings",
    control: "L4 operator evidence — every memoized start result carries the exact warnings collected by migration discovery, including success, held, corrupt and unrepaired outcomes. Dropping them at the one terminal-result constructor erases evidence without changing the refusal verdict.",
    file: "scripts/lib/knockout-runner.mjs",
    find: "    started = { ...result, warnings: legacyScanWarnings };",
    replace: "    started = { ...result, warnings: [] };",
    kind: "gate",
    gateId: "knockout-selftest",
    expectedGateFindings: [{
      rule: "SELFTEST",
      subject: "a foreign unreadable scanned v3 store warns without wedging this repository",
    }],
    suite: [".", "node", ["scripts/lint-control-knockout.selftest.mjs"]],
  },
  {
    id: "k4-v4-recovery-rejects-generationless-locks",
    control: "L4 recovery integrity — a record found at the default v4 lock path is automatically recoverable only when its exact v4 protocol and generation are bound. This mutation admits a v3-shaped generationless record and the regression must prove that it is neither recovered nor deleted.",
    file: "scripts/lib/knockout-runner.mjs",
    find: "    } else if ((usesDefaultCache && record.version !== 4) || ![3, 4].includes(record.version)) {",
    replace: "    } else if (![3, 4].includes(record.version)) {",
    kind: "gate",
    gateId: "knockout-selftest",
    expectedGateFindings: [{
      rule: "SELFTEST",
      subject: "a generationless record at the v4 lock path is never accepted for recovery",
    }],
    suite: [".", "node", ["scripts/lint-control-knockout.selftest.mjs"]],
  },
  {
    id: "k4-remount-stale-identity-remains-discoverable",
    control: "L4 recovery integrity — a stale physical identity whose lexical root still resolves to this repository is recovery state, not a foreign record. Reclassifying it as mismatch silently strands the old store after remount or device-number drift.",
    file: "scripts/lib/knockout-runner.mjs",
    find: "        return statDirectoryIdentity(record.root) === rootIdentity\n          ? ROOT_RECORD.IDENTITY_STALE\n          : ROOT_RECORD.MISMATCH;",
    replace: "        return ROOT_RECORD.MISMATCH;",
    kind: "gate",
    gateId: "knockout-selftest",
    expectedGateFindings: [{
      rule: "SELFTEST",
      subject: "a remount-stale identity cannot silently orphan recovery state",
    }],
    suite: [".", "node", ["scripts/lint-control-knockout.selftest.mjs"]],
  },
  {
    id: "k4-recovery-source-paths-stay-in-repository",
    control: "L4 recovery integrity — every persisted source path is re-confined lexically and physically before recovery reads or writes it. Trusting the record lets dot-dot segments or a parent symlink redirect byte-exact restoration outside the repository.",
    file: "scripts/lib/knockout-runner.mjs",
    find: "      recordedRepoFile(source.rel, \"the interrupted run's source path\");",
    replace: "      path.resolve(repoRoot, source.rel);",
    kind: "gate",
    gateId: "knockout-selftest",
    expectedGateFindings: [{
      rule: "SELFTEST",
      subject: "recovery metadata cannot escape repository, artifact, or cache boundaries",
    }],
    suite: [".", "node", ["scripts/lint-control-knockout.selftest.mjs"]],
  },
  {
    id: "k4-recovery-artifact-index-stays-derived-and-contained",
    control: "L4 recovery integrity — artifact-index keys loaded from disk must name only physically contained paths emitted by the derived-output census. This mutation accepts an arbitrary key, including a path outside the repository.",
    file: "scripts/lib/knockout-runner.mjs",
    find: "        recordedArtifactFile(rel);",
    replace: "        path.resolve(repoRoot, rel);",
    kind: "gate",
    gateId: "knockout-selftest",
    expectedGateFindings: [{
      rule: "SELFTEST",
      subject: "recovery metadata cannot escape repository, artifact, or cache boundaries",
    }],
    suite: [".", "node", ["scripts/lint-control-knockout.selftest.mjs"]],
  },
  {
    id: "k4-recovery-run-directory-stays-in-cache",
    control: "L4 recovery integrity — a persisted lock may name only runs/<nonce> inside this exact cache, including physical projection. Otherwise recovery and release can read or recursively remove a directory the guard never created.",
    file: "scripts/lib/knockout-runner.mjs",
    find: "    if (!isSafeRunNonce(record.nonce)) {\n      throw new IncompleteSnapshotError(`the knockout lock at ${lockPath} has an unsafe run nonce`);\n    }\n    const expectedRunDir = path.join(cacheDir, \"runs\", record.nonce);\n    if (record.runDir !== expectedRunDir) {\n      throw new IncompleteSnapshotError(\n        `the knockout lock at ${lockPath} names run directory ${record.runDir}, not ${expectedRunDir}`,\n      );\n    }\n    const physicalCacheDir = fs.realpathSync(cacheDir);\n    const projectedRunDir = projectedPhysicalPath(record.runDir);\n    if (projectedRunDir === physicalCacheDir || !pathIsInside(projectedRunDir, physicalCacheDir)) {\n      throw new IncompleteSnapshotError(\n        `the knockout lock at ${lockPath} projects its run outside ${physicalCacheDir}: ${projectedRunDir}`,\n      );\n    }\n",
    replace: "",
    kind: "gate",
    gateId: "knockout-selftest",
    expectedGateFindings: [{
      rule: "SELFTEST",
      subject: "recovery metadata cannot escape repository, artifact, or cache boundaries",
    }],
    suite: [".", "node", ["scripts/lint-control-knockout.selftest.mjs"]],
  },
  {
    id: "k4-null-lock-record-refuses-through-corrupt-result",
    control: "L4 recovery integrity — every JSON value other than an object-shaped lock is converted into the memoized corrupt result. A JSON null body must not escape as TypeError and bypass warning/operator evidence.",
    file: "scripts/lib/knockout-runner.mjs",
    find: "      record === null || typeof record !== \"object\" || Array.isArray(record) ||",
    replace: "      typeof record !== \"object\" || Array.isArray(record) ||",
    kind: "gate",
    gateId: "knockout-selftest",
    expectedGateFindings: [{
      rule: "SELFTEST",
      subject: "null and malformed recovery records return corrupt without losing evidence",
    }],
    suite: [".", "node", ["scripts/lint-control-knockout.selftest.mjs"]],
  },
  {
    id: "k4-null-marker-record-refuses-through-corrupt-result",
    control: "L4 recovery integrity — a parsed marker must be an object before any version/root field is read. JSON null is corrupt evidence, not an exception that may escape the guard result contract.",
    file: "scripts/lib/knockout-runner.mjs",
    find: "    if (marker === null || typeof marker !== \"object\" || Array.isArray(marker)) {",
    replace: "    if (false) {",
    kind: "gate",
    gateId: "knockout-selftest",
    expectedGateFindings: [{
      rule: "SELFTEST",
      subject: "null and malformed recovery records return corrupt without losing evidence",
    }],
    suite: [".", "node", ["scripts/lint-control-knockout.selftest.mjs"]],
  },
  {
    id: "k4-marker-sources-remain-an-exact-array",
    control: "L4 recovery integrity — the v4 marker sources field is structurally required. Treating null as an empty list throws during iteration or can hide source recovery state instead of refusing before any repair.",
    file: "scripts/lib/knockout-runner.mjs",
    find: "    const sources = marker.sources;\n    if (!Array.isArray(sources)) {",
    replace: "    const sources = marker.sources;\n    if (false) {",
    kind: "gate",
    gateId: "knockout-selftest",
    expectedGateFindings: [{
      rule: "SELFTEST",
      subject: "null and malformed recovery records return corrupt without losing evidence",
    }],
    suite: [".", "node", ["scripts/lint-control-knockout.selftest.mjs"]],
  },
  {
    id: "k4-marker-dirty-snapshot-is-iterable-before-recovery",
    control: "L4 recovery integrity — dirtyBefore is null or an array of exact path/status pairs before Map construction. A primitive or malformed entry must become corrupt evidence rather than throw outside finishStart.",
    file: "scripts/lib/knockout-runner.mjs",
    find: "    if (marker.dirtyBefore !== null && marker.dirtyBefore !== undefined) {",
    replace: "    if (false) {",
    kind: "gate",
    gateId: "knockout-selftest",
    expectedGateFindings: [{
      rule: "SELFTEST",
      subject: "null and malformed recovery records return corrupt without losing evidence",
    }],
    suite: [".", "node", ["scripts/lint-control-knockout.selftest.mjs"]],
  },
  {
    id: "k4-marker-nonce-binds-the-lock-owner",
    control: "L4 recovery integrity — the marker inside runs/<nonce> must name the same nonce as its lock before any stored byte is applied. A marker from another run is evidence mismatch, not this lock owners recovery plan.",
    file: "scripts/lib/knockout-runner.mjs",
    find: "    if (marker.nonce !== record.nonce) {",
    replace: "    if (false) {",
    kind: "gate",
    gateId: "knockout-selftest",
    expectedGateFindings: [{
      rule: "SELFTEST",
      subject: "null and malformed recovery records return corrupt without losing evidence",
    }],
    suite: [".", "node", ["scripts/lint-control-knockout.selftest.mjs"]],
  },
  {
    id: "k4-midscan-refusal-preserves-earlier-warnings",
    control: "L4 operator evidence — warning state is published in a finally block so a later shared-root refusal cannot erase facts already collected from an earlier root. This mutation restores success-path-only publication.",
    file: "scripts/lib/knockout-runner.mjs",
    find: "      return candidates;\n    } finally {\n      // A later root may fail hard after earlier foreign state produced a warning. Preserve every\n      // fact collected before the refusal, and never leak warnings from an earlier scan attempt.\n      legacyScanWarnings = Object.freeze(warnings);\n    }",
    replace: "      legacyScanWarnings = Object.freeze(warnings);\n      return candidates;\n    } finally {\n      /* MUTANT: warnings are published only on the success path */\n    }",
    kind: "gate",
    gateId: "knockout-selftest",
    expectedGateFindings: [{
      rule: "SELFTEST",
      subject: "legacy scan warnings survive a later shared-root refusal",
    }],
    suite: [".", "node", ["scripts/lint-control-knockout.selftest.mjs"]],
  },
  {
    id: "k4-unreadable-unassociated-runs-never-vanish-silently",
    control: "L4 operator evidence — an unreadable runs directory without an associating lock cannot globally wedge other repositories, but it must remain visible as a scoped warning. A bare catch silently orphans the only remaining recovery record.",
    file: "scripts/lib/knockout-runner.mjs",
    find: "          } catch (error) {\n            if (!error || error.code !== \"ENOENT\") {\n              warnings.push(\n                `unassociated legacy knockout runs directory ${runs} could not be listed and was ` +\n                  `skipped (${String(error && error.message)})`,\n              );\n            }\n          }",
    replace: "          } catch { /* MUTANT: unreadable unassociated runs vanish silently */ }",
    kind: "gate",
    gateId: "knockout-selftest",
    expectedGateFindings: [{
      rule: "SELFTEST",
      subject: "an unassociated lock-absent unreadable runs directory is never skipped silently",
    }],
    suite: [".", "node", ["scripts/lint-control-knockout.selftest.mjs"]],
  },
  {
    id: "k4-contained-typescript-loader-is-platform-neutral",
    control: "L4 evidence availability — contained source tests must not carry a host-native tsx/esbuild binary into the pinned Linux observer. Measured on macOS arm64: the clean test passed 6/6 on the host but the Linux container loaded @esbuild/darwin-arm64, required @esbuild/linux-arm64, and died as a file-wrapper failure before any authored test ran. The runner now replaces only the trusted `--import tsx` token with the attested, pure-JavaScript TypeScript loader while preserving source maps and the original suite source. This mutation restores the host-native token; the grammar selftest must refuse that platform-dependent evidence command on every host.",
    file: "scripts/lib/knockout-runner.mjs",
    find: "  normalized[tsxIndex + 1] = TRUSTED_TYPESCRIPT_TEST_REGISTER;",
    replace: "  normalized[tsxIndex + 1] = \"tsx\";",
    kind: "gate",
    gateId: "knockout-selftest",
    expectedGateFindings: [{
      rule: "SELFTEST",
      subject: "contained TypeScript tests use the platform-neutral attested loader",
    }],
    suite: [".", "node", ["scripts/lint-control-knockout.selftest.mjs"]],
  },
  {
    id: "k4-contained-gate-scratch-is-private-and-writable",
    control: "L4 evidence availability — a dependency-contained gate has a read-only root and exactly one writable per-container tmpfs. Gate preparations such as proof-resolve selftests create bounded scratch fixtures through os.tmpdir(); without an explicit TMPDIR binding they fall back to the read-only host `/tmp`, fail before the terminal gate record, and make every affected knockout INVALID_TEST. This mutation redirects the closed gate child to `/tmp`; the arbitrary-UID namespace proof must go red before any control can claim evidence from that lane.",
    file: "scripts/lib/knockout-runner.mjs",
    find: "  return { ...environment, TMPDIR: CONTAINED_SCRATCH_ROOT };",
    replace: "  return { ...environment, TMPDIR: \"/tmp\" };",
    kind: "gate",
    gateId: "knockout-selftest",
    expectedGateFindings: [{
      rule: "SELFTEST",
      subject: "contained gate children bind their writable private scratch root",
    }],
    suite: [".", "node", ["scripts/lint-control-knockout.selftest.mjs"]],
  },
  {
    id: "k4-proof-recipes-use-platform-neutral-loader",
    control: "L4 proof availability — resolver-parity executes e2e proof files from source inside the same pinned Linux namespace as dependency-bearing knockouts. Its recipe must therefore select the attested pure-JavaScript TypeScript loader too; normalizing only the top-level test suite leaves nested proof execution on host-native tsx/esbuild and turns a clean resolver gate red with PROOF_UNRESOLVED. This mutation restores `tsx` in the canonical proof recipe; the proof-resolve selftest binds the exact portable command.",
    file: "scripts/lib/proof-resolve.mjs",
    find: "proofRunnerNodeArgs(`test/${rest}`, { importModule: TYPESCRIPT_TEST_REGISTER })",
    replace: "proofRunnerNodeArgs(`test/${rest}`, { importModule: \"tsx\" })",
    kind: "gate",
    gateId: "proof-resolve-selftest",
    expectedGateFindings: [{
      rule: "SELFTEST",
      subject: "e2e proof recipe uses the platform-neutral loader and pins the structured event reporter",
    }],
    suite: [".", "node", ["scripts/lib/proof-resolve.selftest.mjs"]],
  },
  {
    id: "k4-evidence-launch-guard-closes-npm-config-namespace",
    control: "L4 evidence integrity — the pre-npm guard closes npm's WHOLE case-insensitive npm_config_* namespace rather than naming settings inside it. A denylist of settings failed the same way a list of casings did: NpM_CoNfIg_UsErCoNfIg pointed npm at an rc that set node-options and the nested publish lane ran attacker code instead of the evidence, and NpM_CoNfIg_DrY_RuN=true made npm publish report (dry-run) and exit 0 against a registry that was not listening — a lane reporting success having published nothing. npm has hundreds of settings, so this mutation restores the three-name denylist and the namespace proofs must go red.",
    file: "scripts/lib/knockout-runner.mjs",
    find: "    if (!key.toLowerCase().startsWith(NPM_CONFIG_PREFIX)) { sanitized[key] = value; continue; }",
    replace: "    if (!EVIDENCE_HOSTILE_NPM_CONFIG_KEYS.map(npmConfigNameOf).includes(key.toLowerCase())) { sanitized[key] = value; continue; }",
    kind: "gate",
    gateId: "knockout-selftest",
    expectedGateFindings: [{
      rule: "SELFTEST",
      subject: "the pre-npm guard closes npm's whole config namespace before npm exists",
    }],
    suite: [".", "node", ["scripts/lint-control-knockout.selftest.mjs"]],
  },
  {
    id: "k4-evidence-launch-guard-precedes-npm",
    control: "L4 evidence integrity — the evidence launch passes through a Node process BEFORE any npm, and that process refuses a hostile npm configuration in any casing. Reproduced on npm 10.9.7 and 11.18.0 with NpM_CoNfIg_NoDe_OpTiOnS=--import=<module> and every argv pin in place: the NESTED publish lane (npm publish -> prepublishOnly -> npm test) started the evidence Node under attacker code which exited 0 in its place — exit 0, ATTACKER-RAN true, EVIDENCE-RAN false. A refusal made inside that process would be the control supplying its own evidence, so the boundary has to precede npm. Node is the right place to stand because it reads NODE_OPTIONS and nothing else, which makes every mixed-case npm_config_* spelling inert to it.",
    file: "scripts/lib/knockout-runner.mjs",
    find: "export const evidenceLaunchGuardCommand = () =>\n  `node scripts/lib/knockout-runner.mjs ${EVIDENCE_LAUNCH_FLAG}`;",
    replace: "export const evidenceLaunchGuardCommand = () =>\n  `node scripts/lib/knockout-runner.mjs --print-version`;",
    kind: "gate",
    gateId: "knockout-selftest",
    expectedGateFindings: [{
      rule: "SELFTEST",
      subject: "the pre-npm guard closes npm's whole config namespace before npm exists",
    }],
    suite: [".", "node", ["scripts/lint-control-knockout.selftest.mjs"]],
  },
  {
    id: "k4-evidence-launch-pins-node-options",
    control: "L4 evidence integrity — the node-options pin specifically. `npm_config_node_options` is the one npm setting that becomes a NODE flag: npm hands it to the script child as NODE_OPTIONS, which is how a configuration name reaches the evidence process itself. Reproduced with the harmless payload `NpM_CoNfIg_NoDe_OpTiOnS=--title=pwned`: unpinned, the child ran with NODE_OPTIONS=--title=pwned and process.title pwned; pinned, with NODE_OPTIONS absent. This mutation removes ONLY that pin and leaves script-shell and ignore-scripts intact, so neither of them can stand in for its proof.",
    file: "scripts/lib/knockout-runner.mjs",
    find: "export const evidenceNpmPrecedenceFlags = () =>\n  `--ignore-scripts=false --script-shell=${EVIDENCE_SCRIPT_SHELL} --node-options=`;",
    replace: "export const evidenceNpmPrecedenceFlags = () =>\n  `--ignore-scripts=false --script-shell=${EVIDENCE_SCRIPT_SHELL}`;",
    kind: "gate",
    gateId: "knockout-selftest",
    expectedGateFindings: [{
      rule: "SELFTEST",
      subject: "the node-options pin is the only thing keeping a mixed-case spelling out of NODE_OPTIONS",
    }],
    suite: [".", "node", ["scripts/lint-control-knockout.selftest.mjs"]],
  },
  {
    id: "k4-evidence-launch-pins-npm-config",
    control: "L4 evidence integrity — every evidence-bearing launch pins npm's script-shell, ignore-scripts and node-options on the COMMAND LINE, where npm's precedence puts them above every environment spelling and every rc file. Reproduced on npm 10.9.7: npm resolves a config name case-INSENSITIVELY, so `NpM_CoNfIg_ScRiPt_ShElL=<stand-in shell>` replaced the script shell, `npm test` exited 0, and the real test never ran — while `/usr/bin/env -u npm_config_script_shell` removed a different name and saw nothing. A name list cannot close this; argv has no casing to attack.",
    file: "scripts/lib/knockout-runner.mjs",
    find: "export const evidenceNpmPrecedenceFlags = () =>\n  `--ignore-scripts=false --script-shell=${EVIDENCE_SCRIPT_SHELL} --node-options=`;",
    replace: "export const evidenceNpmPrecedenceFlags = () =>\n  `--ignore-scripts=false --node-options=`;",
    kind: "gate",
    gateId: "knockout-selftest",
    expectedGateFindings: [{
      rule: "SELFTEST",
      subject: "npm resolves a config name case-INSENSITIVELY, so the pinned flags are the control",
    }],
    suite: [".", "node", ["scripts/lint-control-knockout.selftest.mjs"]],
  },
  {
    id: "k4-script-shell-exemption-is-one-exact-pair",
    control: "L4 evidence integrity — the observer's ONE npm-config exemption admits exactly the pair this repository emits: the canonical spelling npm produces for the script shell, and the exact value the argv pin is composed from, both by equality. npm exports the argv pin to every script child, so refusing it fails the launch that set it — measured on the exact shipped launch, Node 22: 617 tests, 4 failed, all four 'knockout observer inherited npm_config_script_shell'; with the exemption, 617/617. This mutation keeps the key check and drops the VALUE check, so an attacker-chosen shell under the same canonical name would be admitted while the honest pin still passes — the exemption would look load-bearing while protecting nothing.",
    file: "scripts/lib/knockout-runner.mjs",
    find: "    if (key === EVIDENCE_SCRIPT_SHELL_KEY && value === EVIDENCE_SCRIPT_SHELL) continue;",
    replace: "    if (key === EVIDENCE_SCRIPT_SHELL_KEY) continue;",
    kind: "gate",
    gateId: "knockout-selftest",
    expectedGateFindings: [{
      rule: "SELFTEST",
      subject: "the observer admits the script shell THIS repository pins, and nothing else that resembles it",
    }],
    suite: [".", "node", ["scripts/lint-control-knockout.selftest.mjs"]],
  },
  {
    id: "k4-evidence-refusal-folds-npm-config-case",
    control: "L4 evidence integrity — the observer's fail-closed refusal matches npm's configuration names the way NPM matches them, by folding case over the whole environment, and reports the spelling actually found. Matching them exactly was blind: `NpM_CoNfIg_ScRiPt_ShElL` walked past the refusal untouched. The loader and shell names keep their exact match on purpose, because a mixed-case `LD_pReLoAd` is inert and refusing on it would be a false alarm on an honest run.",
    file: "scripts/lib/knockout-runner.mjs",
    find: "  for (const key of Object.keys(environment)) {\n    if (!refusedNpmConfig.has(npmConfigNameOf(key))) continue;",
    replace: "  for (const key of EVIDENCE_HOSTILE_NPM_CONFIG_KEYS) {\n    if (!refusedNpmConfig.has(key)) continue;",
    kind: "gate",
    gateId: "knockout-selftest",
    expectedGateFindings: [{
      rule: "SELFTEST",
      subject: "the observer refuses the spelling npm would have honoured, and stays quiet on an inert one",
    }],
    suite: [".", "node", ["scripts/lint-control-knockout.selftest.mjs"]],
  },
  {
    id: "k4-evidence-step-pins-npm-config",
    control: "L4 evidence integrity — the npm configuration pin is bound to THIS evidence step, not counted across the file. A launch that keeps the env -u prefix and drops the flags is exactly the shape the reproduction walked through, and file-wide counting would let one step lose its pin while its siblings kept the total intact.",
    file: ".github/workflows/ci.yml",
    find: "        run: /usr/bin/env -u NODE_OPTIONS -u NODE_REPL_EXTERNAL_MODULE -u npm_config_node_options -u npm_config_script_shell -u npm_config_shell -u BASH_ENV -u ENV -u SHELLOPTS -u DYLD_INSERT_LIBRARIES -u DYLD_LIBRARY_PATH -u DYLD_FRAMEWORK_PATH -u LD_PRELOAD -u LD_LIBRARY_PATH -u LD_AUDIT node scripts/lib/knockout-runner.mjs --launch-evidence npm run lint:knockout --ignore-scripts=false --script-shell=/bin/sh --node-options=",
    replace: "        run: /usr/bin/env -u NODE_OPTIONS -u NODE_REPL_EXTERNAL_MODULE -u npm_config_node_options -u npm_config_script_shell -u npm_config_shell -u BASH_ENV -u ENV -u SHELLOPTS -u DYLD_INSERT_LIBRARIES -u DYLD_LIBRARY_PATH -u DYLD_FRAMEWORK_PATH -u LD_PRELOAD -u LD_LIBRARY_PATH -u LD_AUDIT node scripts/lib/knockout-runner.mjs --launch-evidence npm run lint:knockout",
    kind: "gate",
    gateId: "knockout-selftest",
    expectedGateFindings: [{
      rule: "SELFTEST",
      subject: "every evidence-bearing CI launch point sanitizes the exact refusal list",
    }],
    suite: [".", "node", ["scripts/lint-control-knockout.selftest.mjs"]],
  },
  {
    id: "k4-evidence-launcher-is-an-absolute-path",
    control: "L4 evidence integrity — the sanitizing launcher is written as an absolute path. A bare `env` is a command NAME, and Bash resolves names against exported shell functions before PATH, so the environment a step is trying to clean can replace the cleaner. Reproduced: with BASH_FUNC_env%% exported as `() { echo INTERCEPTED; return 0; }`, the launch printed INTERCEPTED, exited 0, and the Node evidence child never ran — a green step that measured nothing.",
    file: "scripts/lib/knockout-runner.mjs",
    find: "export const evidenceLaunchSanitizer = () =>\n  `/usr/bin/env ${EVIDENCE_HOSTILE_ENV_KEYS.map((key) => `-u ${key}`).join(\" \")}`;",
    replace: "export const evidenceLaunchSanitizer = () =>\n  `env ${EVIDENCE_HOSTILE_ENV_KEYS.map((key) => `-u ${key}`).join(\" \")}`;",
    kind: "gate",
    gateId: "knockout-selftest",
    expectedGateFindings: [{
      rule: "SELFTEST",
      subject: "the runner's step env neutralizes a hostile launch that the shell would otherwise obey",
    }],
    suite: [".", "node", ["scripts/lint-control-knockout.selftest.mjs"]],
  },
  {
    id: "k4-evidence-step-neutralizes-bash-env",
    control: "L4 evidence integrity — the knockout step's OWN step-level env neutralizes BASH_ENV. A step-level `env:` is the only boundary the runner applies BEFORE it creates the shell process: an `env -u` inside `run:` is handed to a shell that has already started (MEASURED: a hostile BASH_ENV executed its script first), and a custom `shell: /usr/bin/env -u … bash` cannot help the loader because `/usr/bin/env` is itself the first user process. The neutralization is bound to THIS step, because counting blocks file-wide let one be parked on a step that launches no evidence.",
    file: ".github/workflows/ci.yml",
    find: "          BASH_ENV: \"\"\n          ENV: \"\"\n          SHELLOPTS: \"\"\n          DYLD_INSERT_LIBRARIES: \"\"\n          DYLD_LIBRARY_PATH: \"/nonexistent\"\n          DYLD_FRAMEWORK_PATH: \"/nonexistent\"\n          LD_PRELOAD: \"\"\n          LD_LIBRARY_PATH: \"/nonexistent\"\n          LD_AUDIT: \"\"\n        # PHASES 2 and 3 \u2014 exactly as at the first evidence step in this file.\n        run: /usr/bin/env -u NODE_OPTIONS -u NODE_REPL_EXTERNAL_MODULE -u npm_config_node_options -u npm_config_script_shell -u npm_config_shell -u BASH_ENV -u ENV -u SHELLOPTS -u DYLD_INSERT_LIBRARIES -u DYLD_LIBRARY_PATH -u DYLD_FRAMEWORK_PATH -u LD_PRELOAD -u LD_LIBRARY_PATH -u LD_AUDIT node scripts/lib/knockout-runner.mjs --launch-evidence npm run lint:knockout --ignore-scripts=false --script-shell=/bin/sh --node-options=",
    replace: "          BASH_ENV: \"/tmp/attacker-startup.sh\"\n          ENV: \"\"\n          SHELLOPTS: \"\"\n          DYLD_INSERT_LIBRARIES: \"\"\n          DYLD_LIBRARY_PATH: \"/nonexistent\"\n          DYLD_FRAMEWORK_PATH: \"/nonexistent\"\n          LD_PRELOAD: \"\"\n          LD_LIBRARY_PATH: \"/nonexistent\"\n          LD_AUDIT: \"\"\n        # PHASES 2 and 3 \u2014 exactly as at the first evidence step in this file.\n        run: /usr/bin/env -u NODE_OPTIONS -u NODE_REPL_EXTERNAL_MODULE -u npm_config_node_options -u npm_config_script_shell -u npm_config_shell -u BASH_ENV -u ENV -u SHELLOPTS -u DYLD_INSERT_LIBRARIES -u DYLD_LIBRARY_PATH -u DYLD_FRAMEWORK_PATH -u LD_PRELOAD -u LD_LIBRARY_PATH -u LD_AUDIT node scripts/lib/knockout-runner.mjs --launch-evidence npm run lint:knockout --ignore-scripts=false --script-shell=/bin/sh --node-options=",
    kind: "gate",
    gateId: "knockout-selftest",
    expectedGateFindings: [{
      rule: "SELFTEST",
      subject: "every evidence-bearing CI launch point sanitizes the exact refusal list",
    }],
    suite: [".", "node", ["scripts/lint-control-knockout.selftest.mjs"]],
  },
  {
    id: "k4-ci-launch-points-sanitize-evidence-surface",
    control: "L4 evidence integrity — every CI step that starts a root suite or the knockout launches through the exact env -u sanitizer derived from the observer's refusal list. Without it the observer's fail-closed refusal makes the required checks red on an ordinary runner, and the tempting repair is to weaken the observer; this control keeps the cleaning where it belongs and pins the two spellings together.",
    file: ".github/workflows/ci.yml",
    find: "        run: /usr/bin/env -u NODE_OPTIONS -u NODE_REPL_EXTERNAL_MODULE -u npm_config_node_options -u npm_config_script_shell -u npm_config_shell -u BASH_ENV -u ENV -u SHELLOPTS -u DYLD_INSERT_LIBRARIES -u DYLD_LIBRARY_PATH -u DYLD_FRAMEWORK_PATH -u LD_PRELOAD -u LD_LIBRARY_PATH -u LD_AUDIT node scripts/lib/knockout-runner.mjs --launch-evidence npm run lint:knockout --ignore-scripts=false --script-shell=/bin/sh --node-options=",
    replace: "        run: npm run lint:knockout",
    kind: "gate",
    gateId: "knockout-selftest",
    expectedGateFindings: [{
      rule: "SELFTEST",
      subject: "every evidence-bearing CI launch point sanitizes the exact refusal list",
    }],
    suite: [".", "node", ["scripts/lint-control-knockout.selftest.mjs"]],
  },
  {
    id: "l12-legacy-publisher-refuses-npm-publish",
    control:
      "L12 release quarantine — publish.yml contains no npm execution at all. This mutation inserts " +
      "npm publish between the preserved RELEASE_FROZEN report and terminal refusal, isolating " +
      "command reintroduction from trigger, checkout, secret, and OIDC controls; the quarantine " +
      "contract must go red.",
    file: ".github/workflows/publish.yml",
    find:
      "          echo \"::error::RELEASE_FROZEN: publish.yml is quarantined and is not a release authority.\"\n" +
      "          exit 1",
    replace:
      "          echo \"::error::RELEASE_FROZEN: publish.yml is quarantined and is not a release authority.\"\n" +
      "          npm publish\n" +
      "          exit 1",
    kind: "gate",
    gateId: "knockout-selftest",
    expectedGateFindings: [{
      rule: "SELFTEST",
      subject: "legacy publisher workflow IDs are inert fail-closed quarantine",
    }],
    suite: [".", "node", ["scripts/lint-control-knockout.selftest.mjs"]],
  },
  {
    id: "k4-launch-coverage-counts-are-exact",
    control: "L4 evidence integrity — the launch-point coverage asserts EXACT counts, not merely that the sanitized launches it finds are sanitized. Without the count a launch point can disappear, or be added unsanitized, while the check stays green on its siblings — which is precisely how the npm publish launch went unnoticed.",
    file: ".github/workflows/ci.yml",
    find: "        run: /usr/bin/env -u NODE_OPTIONS -u NODE_REPL_EXTERNAL_MODULE -u npm_config_node_options -u npm_config_script_shell -u npm_config_shell -u BASH_ENV -u ENV -u SHELLOPTS -u DYLD_INSERT_LIBRARIES -u DYLD_LIBRARY_PATH -u DYLD_FRAMEWORK_PATH -u LD_PRELOAD -u LD_LIBRARY_PATH -u LD_AUDIT node scripts/lib/knockout-runner.mjs --launch-evidence npm test --ignore-scripts=false --script-shell=/bin/sh --node-options=\n      - name: Go verifier == Python reference",
    replace: "        run: npm run build\n      - name: Go verifier == Python reference",
    kind: "gate",
    gateId: "knockout-selftest",
    expectedGateFindings: [{
      rule: "SELFTEST",
      subject: "every evidence-bearing CI launch point sanitizes the exact refusal list",
    }],
    suite: [".", "node", ["scripts/lint-control-knockout.selftest.mjs"]],
  },
  {
    id: "a77-hardening-clock-is-captured-at-load",
    control: "#77-A supply-chain boundary — the expiry gate's default clock is a Date.now captured at module load. This policy exists to stop being trusted on a date, and a live Date.now hands that date to whoever replaced it.",
    file: "packages/signer-core/scripts/apply-dependency-hardening.mjs",
    find: "  now = reflectApply(dateNow, Date, []),",
    replace: "  now = Date.now(),",
    kind: "tests",
    suite: ["packages/signer-core", "node", ["--test", "test/dependency-hardening.test.mjs"]],
  },
  {
    id: "a77-attestation-opens-through-captured-fs",
    control: "#77-A supply-chain boundary — the attestation opens and lists through fs/promises functions captured at module initialization. A named import from a Node builtin is a LIVE BINDING: replacing the property on the CommonJS object and calling syncBuiltinESMExports() re-points every importer. Reproduced: 194 opens and 8 readdirs redirected to pristine copies, evidence=3, malicious file still on disk.",
    file: "packages/signer-core/scripts/apply-dependency-hardening.mjs",
    find: "    return await fsOpen(absolutePath, O_RDONLY | symlinkSafeOpenFlag() | nonBlockingOpenFlag() | extraFlags);",
    replace: "    return await open(absolutePath, O_RDONLY | symlinkSafeOpenFlag() | nonBlockingOpenFlag() | extraFlags);",
    also: [
      {
        find: "    const entries = reflectApply(\n      arraySort,\n      await fsReaddir(directory, { withFileTypes: true }),",
        replace: "    const entries = reflectApply(\n      arraySort,\n      await readdir(directory, { withFileTypes: true }),",
      },
    ],
    kind: "tests",
    suite: ["packages/signer-core", "node", ["--test", "test/dependency-hardening.test.mjs"]],
  },
  {
    id: "a77-attestation-resolves-through-captured-path-resolve",
    control: "#77-A supply-chain boundary — package roots are resolved through a path.resolve captured at module initialization. Reproduced with only that one binding re-pointed: three redirects, one per package root, and the attestation returned evidence=3 for trees it never read.",
    file: "packages/signer-core/scripts/apply-dependency-hardening.mjs",
    find: "  for (let index = 0; index < segments.length; index++) directory = pathResolve(directory, segments[index]);",
    replace: "  for (let index = 0; index < segments.length; index++) directory = resolve(directory, segments[index]);",
    kind: "tests",
    suite: ["packages/signer-core", "node", ["--test", "test/dependency-hardening.test.mjs"]],
  },
  {
    id: "a77-attestation-joins-paths-through-captured-path-join",
    control: "#77-A supply-chain boundary — every entry path is built through a path.join captured at module initialization. Reproduced with only that one binding re-pointed: a SINGLE redirect of the changed file's path was enough for evidence=3 with the malicious bytes still present, so join is load-bearing on its own and not merely alongside fs.",
    file: "packages/signer-core/scripts/apply-dependency-hardening.mjs",
    find: "      const absolutePath = pathJoin(directory, entry.name);",
    replace: "      const absolutePath = join(directory, entry.name);",
    kind: "tests",
    suite: ["packages/signer-core", "node", ["--test", "test/dependency-hardening.test.mjs"]],
  },
  {
    id: "a77-attestation-appends-records-through-captured-push",
    control: "#77-A supply-chain boundary — every per-file record is appended through an Array.prototype.push captured at module load. Reproduced: replacing the live push and handing back the 165 clean records in order makes a same-count tampered tree produce the pinned digests. Once bytes are hashed they are never consulted again, so whatever reaches the record list IS the measurement.",
    file: "packages/signer-core/scripts/apply-dependency-hardening.mjs",
    find: "      reflectApply(arrayPush, records, [`${relativePath}\\0${sha256(bytes)}`]);",
    replace: "      records.push(`${relativePath}\\0${sha256(bytes)}`);",
    kind: "tests",
    suite: ["packages/signer-core", "node", ["--test", "test/dependency-hardening.test.mjs"]],
  },
  {
    id: "a77-attestation-joins-records-through-captured-join",
    control: "#77-A supply-chain boundary — the aggregate input for each tree is built through an Array.prototype.join captured at module load. Reproduced: replacing the live join and handing back the three clean aggregate inputs substitutes each tree's entire measurement in a single call, with no per-file tampering at all.",
    file: "packages/signer-core/scripts/apply-dependency-hardening.mjs",
    find: "    sha256: sha256(reflectApply(arrayJoin, records, [\"\\n\"])),",
    replace: "    sha256: sha256(records.join(\"\\n\")),",
    kind: "tests",
    suite: ["packages/signer-core", "node", ["--test", "test/dependency-hardening.test.mjs"]],
  },
  {
    id: "a77-attestation-dispatches-through-captured-reflect-apply",
    control: "#77-A supply-chain boundary — the dispatcher itself is captured. Every captured intrinsic in this file is invoked through one `Reflect.apply` bound at module initialization; if that dispatcher is live, a post-load replacement intercepts EVERY captured call and can substitute its result, which makes capturing the individual methods worthless. Reproduced against a live-dispatcher mutant: 2236 dispatches, 168 of them digests, forged at the derived aggregate positions, evidence=3.",
    file: "packages/signer-core/scripts/apply-dependency-hardening.mjs",
    find: "const reflectApply = Reflect.apply;",
    replace: "const reflectApply = (target, thisArg, args) => Reflect.apply(target, thisArg, args);",
    kind: "tests",
    suite: ["packages/signer-core", "node", ["--test", "test/dependency-hardening.test.mjs"]],
  },
  {
    id: "a77-attestation-hashes-through-captured-dispatch",
    control: "#77-A supply-chain boundary — every digest the attestation takes goes through Hash update/digest captured at module load. Reproduced against a live-hash mutant: with all three real trees copied and one file changed WITHOUT changing the file count, replacing Hash.prototype.digest so only each tree's AGGREGATE call returns its pinned digest produced evidence=3 after 168 calls. A digest function is the last thing a measurement passes through, so replacing it replaces the measurement without touching a single byte on disk.",
    file: "packages/signer-core/scripts/apply-dependency-hardening.mjs",
    find: "const sha256 = (value) => reflectApply(\n  hashDigest,\n  reflectApply(hashUpdate, cryptoCreateHash(\"sha256\"), [value]),\n  [\"hex\"],\n);",
    replace: "const sha256 = (value) => createHash(\"sha256\").update(value).digest(\"hex\");",
    kind: "tests",
    suite: ["packages/signer-core", "node", ["--test", "test/dependency-hardening.test.mjs"]],
  },
  {
    id: "a77-attestation-freezes-through-captured-object-freeze",
    control: "#77-A supply-chain boundary — the attestation's own return value is frozen through an Object.freeze captured at module load. Reproduced: patching the live Object.freeze so that only {files, sha256} digest objects came back as the pinned expectations, in sequence, made the attestation return normally with the exact 33/72/60 evidence while every real dependency tree contained nothing but MALICIOUS.txt. The last function a measurement passes through can replace the measurement.",
    file: "packages/signer-core/scripts/apply-dependency-hardening.mjs",
    find: "  await walk(packageDirectory);\n  return objectFreeze({",
    replace: "  await walk(packageDirectory);\n  return Object.freeze({",
    kind: "tests",
    suite: ["packages/signer-core", "node", ["--test", "test/dependency-hardening.test.mjs"]],
  },
  {
    id: "a77-attestation-iterates-a-fixed-work-list",
    control: "#77-A supply-chain boundary — the attestation walks its pinned package list by index and checks afterwards that it measured all of it. Reproduced: replacing Array.prototype[Symbol.iterator] for that exact exported array with an empty iterator made the function return normally having measured NOTHING, and the caller read no-throw as a pass. A work list an adversary can empty is not a work list.",
    file: "packages/signer-core/scripts/apply-dependency-hardening.mjs",
    find: "  for (let index = 0; index < HARDENED_PACKAGE_TREES.length; index++) {\n    const expected = HARDENED_PACKAGE_TREES[index];",
    replace: "  for (const expected of HARDENED_PACKAGE_TREES) {",
    kind: "tests",
    suite: ["packages/signer-core", "node", ["--test", "test/dependency-hardening.test.mjs"]],
  },
  {
    id: "a77-attestation-resolves-through-captured-string-ops",
    control: "#77-A supply-chain boundary — package names are resolved to directories through a String.prototype.split captured at module load. Reproduced: patching split for the three package names redirected resolution to clean copies outside node_modules, and patching startsWith to true silenced the containment check, so every exact expected digest was returned while the real trees still held a malicious file.",
    file: "packages/signer-core/scripts/apply-dependency-hardening.mjs",
    find: "  const segments = reflectApply(stringSplit, name, [\"/\"]);",
    replace: "  const segments = name.split(\"/\");",
    kind: "tests",
    suite: ["packages/signer-core", "node", ["--test", "test/dependency-hardening.test.mjs"]],
  },
  {
    id: "a77-attestation-reads-through-captured-intrinsics",
    control: "#77-A supply-chain boundary — the dependency-tree attestation reads through FileHandle intrinsics captured at module load, not live prototype dispatch. Reproduced: import this module first, then replace FileHandle.prototype.readFile so one held inode returns the original clean bytes, and the attestation returned PASS with the exact expected counts and digests while the file on disk was malicious. Evidence read through a slot the adversary can replace is not evidence.",
    file: "packages/signer-core/scripts/apply-dependency-hardening.mjs",
    find: "        else if (reflectApply(statsIsFile, held, [])) bytes = await reflectApply(handleReadFile, handle, []);",
    replace: "        else if (reflectApply(statsIsFile, held, [])) bytes = await handle.readFile();",
    kind: "tests",
    suite: ["packages/signer-core", "node", ["--test", "test/dependency-hardening.test.mjs"]],
  },
  {
    id: "a77-attestation-carries-directory-identity-into-descent",
    control: "L4 supply chain — the tree walk carries the identity of the directory the PARENT listed into the descent, so a child cannot re-baseline against whatever is at its path when it is re-opened. Reproduced deterministically by replacing fs.promises.open before the module captures it and moving a different real directory into place between the parent's open and the child's: the earlier revision digested the replacement and both of its identity probes agreed, because each was asking about the object it had just opened rather than the object its parent listed. The documented limit is unchanged — a swap made and undone between two probes leaves nothing to observe.",
    file: "packages/signer-core/scripts/apply-dependency-hardening.mjs",
    find: "        await walk(absolutePath, relativePath, childDirectory);",
    replace: "        await walk(absolutePath, relativePath);",
    kind: "tests",
    suite: ["packages/signer-core", "node", ["--test", "test/dependency-hardening.test.mjs"]],
  },
  {
    id: "a77-attestation-binds-directory-identity",
    control: "#77-A supply-chain boundary — a directory's listing is bound to the identity of the directory it came from. Reproduced: rename a package subdirectory away immediately after its fstat and leave a symlink to an identical directory outside the package tree, and the attestation returned PASS with the exact expected digests for a traversal that had left the package. Node has no openat, so the traversal is not atomic: re-opening the name and requiring the same device and inode refuses a substitution that is STILL PRESENT at a probe, and claims nothing about a swap made and undone between probes.",
    file: "packages/signer-core/scripts/apply-dependency-hardening.mjs",
    find: "    // The listing is only evidence about the directory it actually came from.\n    await assertDirectoryUnchanged(directory, label, identity);",
    replace: "",
    kind: "tests",
    suite: ["packages/signer-core", "node", ["--test", "test/dependency-hardening.test.mjs"]],
  },
  {
    id: "a77-attestation-opens-without-blocking",
    control: "#77-A availability of the evidence path — every tree entry is opened non-blocking. A blocking O_RDONLY on a FIFO waits for a writer that may never come: MEASURED, a dependency tree containing one made the attestation print its first line and then hang until it was killed at six seconds, which is a denial of service on the release gate from a file type alone. Non-blocking, the FIFO is rejected by fstat as a non-regular entry.",
    file: "packages/signer-core/scripts/apply-dependency-hardening.mjs",
    find: "    return await fsOpen(absolutePath, O_RDONLY | symlinkSafeOpenFlag() | nonBlockingOpenFlag() | extraFlags);",
    replace: "    return await fsOpen(absolutePath, O_RDONLY | symlinkSafeOpenFlag() | extraFlags);",
    kind: "tests",
    suite: ["packages/signer-core", "node", ["--test", "test/dependency-hardening.test.mjs"]],
  },
  {
    id: "a77-hardening-refuses-without-o-nofollow",
    control: "#77-A supply-chain boundary — the dependency-tree attestation refuses to run where O_NOFOLLOW is unavailable instead of degrading to a following open. `fsConstants.O_NOFOLLOW ?? 0` produced exactly that silent degradation: a NO-OP flag, an ordinary following open, and surrounding code claiming symlink safety.",
    file: "packages/signer-core/scripts/apply-dependency-hardening.mjs",
    find: "  const flag = constants.O_NOFOLLOW;",
    replace: "  const flag = constants.O_NOFOLLOW ?? 0;\n  if (flag === 0) return 0;",
    kind: "tests",
    suite: ["packages/signer-core", "node", ["--test", "test/dependency-hardening.test.mjs"]],
  },
  {
    id: "a77-hardening-check-refuses-an-unseeable-tree",
    control: "#77-A supply-chain boundary — the transformer's two modes disagree on purpose about an absent dependency tree. npm runs a linked package's postinstall with no node_modules beside it, so --apply reports that it transformed nothing; --check is the gate the build depends on, so a tree it cannot see is a refusal and never a pass.",
    file: "packages/signer-core/scripts/apply-dependency-hardening.mjs",
    find: "    if (error?.code !== \"ENOENT\") throw error;\n    if (checkOnly) {",
    replace: "    if (error?.code !== \"ENOENT\") throw error;\n    if (false) {",
    kind: "tests",
    suite: ["packages/signer-core", "node", ["--test", "test/dependency-hardening.test.mjs"]],
  },
  {
    id: "k4-proof-recipe-builds-without-npm",
    control: "L4 evidence integrity — a proof recipe compiles its package with exact Node and its own TypeScript, never `npm run build`. That build step executes inside the evidence-bearing gate child, and npm reads `node-options` and `script-shell` from the PROJECT `.npmrc` beside the package; project rc beats environment config, so no variable can disarm it. Removing npm from the step is the only thing that closes it.",
    file: "scripts/lib/proof-resolve.mjs",
    find: "      trustedBuildStep(cwd),",
    replace: "      [\"npm\", [\"run\", \"build\"]],",
    kind: "gate",
    gateId: "knockout-selftest",
    expectedGateFindings: [{
      rule: "SELFTEST",
      subject: "a project .npmrc cannot reach an evidence step, because no npm runs there",
    }],
    suite: [".", "node", ["scripts/lint-control-knockout.selftest.mjs"]],
  },
  {
    id: "k4-gate-evidence-only-terminal-step-counts",
    control: "L4 evidence integrity — only the DESIGNATED terminal step of a decomposed gate script may supply the gate record. The catch that handles a non-zero exit cannot see which step threw; assigning its stdout unconditionally let a preparation step print a terminal record, exit 1, and be read back as a complete protocol with an identity and findings for a terminal step that never executed.",
    file: "scripts/lib/knockout-runner.mjs",
    find: "    machineOutput = executingTerminalGateStep ? String(e.stdout ?? \"\") : \"\";",
    replace: "    machineOutput = String(e.stdout ?? \"\");",
    kind: "gate",
    gateId: "knockout-selftest",
    expectedGateFindings: [{
      rule: "SELFTEST",
      subject: "a failing PREPARATION step is never credited as the gate's terminal evidence",
    }],
    suite: [".", "node", ["scripts/lint-control-knockout.selftest.mjs"]],
  },
  {
    id: "k4-gate-evidence-runs-node-not-npm",
    control: "L4 evidence integrity — a gate step receives a CONSTRUCTED environment, not the ambient one. Checking NODE_OPTIONS alone was never enough: `npm run` maps `node-options` from `npm_config_node_options` OR from any `.npmrc` into the child's NODE_OPTIONS, and `script-shell` replaces the interpreter, so the ambient environment was a code-execution hook into every gate. The registry's npm scripts are now decomposed into direct `node` steps and run with an allowlisted environment that carries no NODE_OPTIONS, no npm_config_* alias, no BASH_ENV and no DYLD_/LD_ loader hook.",
    file: "scripts/lib/knockout-runner.mjs",
    find: "  const environment = {};\n  for (const key of EVIDENCE_ENV_ALLOWLIST) {",
    replace: "  const environment = { ...source };\n  for (const key of EVIDENCE_ENV_ALLOWLIST) {",
    kind: "gate",
    gateId: "knockout-selftest",
    expectedGateFindings: [{
      rule: "SELFTEST",
      subject: "a GATE step runs exact Node with a constructed environment, never npm with the ambient one",
    }],
    suite: [".", "node", ["scripts/lint-control-knockout.selftest.mjs"]],
  },
  {
    id: "k4-gate-evidence-closed-startup-surface",
    control: "L4 evidence integrity — the closed-Node-startup-surface refusal covers EVERY evidence lane, not only the contained `tests` lane. Scoped to `tests`, an inherited NODE_OPTIONS=--import <module> printed a well-formed noa-gate-runner/1 terminal record from the gate child at exit: a gate that emitted nothing of its own and exited 1 was read back as a completed protocol with the identity and the exact rule/subject pair a registry entry requires, manufacturing DETECTOR_TRIGGERED for every gate-kind knockout from the environment alone.",
    file: "scripts/lib/knockout-runner.mjs",
    find: "  if (hostileSurface.length !== 0) {",
    replace: "  if (kind === \"tests\" && hostileSurface.length !== 0) {",
    kind: "gate",
    gateId: "knockout-selftest",
    expectedGateFindings: [{
      rule: "SELFTEST",
      subject: "a GATE observation refuses an inherited Node startup hook instead of reading its output",
    }],
    suite: [".", "node", ["scripts/lint-control-knockout.selftest.mjs"]],
  },
  {
    id: "a77-ed25519-final-secret-fence",
    control: "#77-A — every production Ed25519 sign/key-derivation operation runs the shared exact-descriptor fence immediately before a normalized private seed reaches Noble. A post-load _SHA512.process hook otherwise receives the complete 32-byte seed while the resulting signature still verifies, making the leak silent.",
    file: "packages/signer-core/src/ed25519-runtime.ts",
    find: "    // LOAD-BEARING: no secret byte may enter mutable dependency dispatch before this final fence.\n    assertEd25519RuntimeIntegrity();\n    const output = operation(secret);",
    replace: "    // MUTANT: the final pre-secret fence is absent.\n    const output = operation(secret);",
    kind: "tests",
    suite: ["packages/signer-core", "npm", ["test"]],
  },
  {
    id: "a77-hpke-rejects-detached-input",
    control: "#77-C input snapshot — HPKE distinguishes a detached ArrayBuffer from a legitimate empty byte string before encryption. TypedArray length and ArrayBuffer byteLength both collapse detached non-empty input to zero; a captured native zero-length DataView attachment check prevents silent encryption of different bytes than the caller supplied without invoking ArrayBuffer constructor/@@species hooks.",
    file: "packages/signer-core/src/runtime-integrity.ts",
    find: "    reflectApply(arrayBufferByteLengthGetter, sourceBuffer, []);\n    // The byteLength getter distinguishes SharedArrayBuffer but reports zero for a detached\n    // ArrayBuffer. Constructing a zero-length native DataView is the captured, cross-realm\n    // attachment check: unlike ArrayBuffer.prototype.slice it performs no caller-controlled\n    // constructor/@@species lookup, succeeds for a legitimate empty buffer, and throws if detached.\n    new DataViewCtor(sourceBuffer as ArrayBuffer, 0, 0);",
    replace: "    reflectApply(arrayBufferByteLengthGetter, sourceBuffer, []);",
    kind: "tests",
    suite: ["packages/signer-core", "npm", ["test"]],
  },
  {
    id: "a77-byte-codecs-snapshot-attached-input",
    control: "#77-A/#77-C byte boundary — byte encoders first take an attached, non-shared intrinsic copy. Otherwise a detached non-empty value is silently encoded as empty and a SharedArrayBuffer can change between length and index reads.",
    file: "packages/signer-core/src/bytes.ts",
    find: "function normalizeCodecBytes(value: Uint8Array, label: string): Uint8Array {\n  return copyUnsharedUint8Array(value, label);\n}",
    replace: "function normalizeCodecBytes(value: Uint8Array, _label: string): Uint8Array {\n  return value;\n}",
    kind: "tests",
    suite: ["packages/signer-core", "npm", ["test"]],
  },
  {
    id: "a77-base64-no-live-byte-length",
    control: "#77-A private-byte boundary — base64 encoding reads the normalized byte length through the captured TypedArray brand getter. A live self-restoring length getter otherwise receives the complete Ed25519 private DER while leaving the emitted base64 byte-identical.",
    file: "packages/signer-core/src/bytes.ts",
    find: "    let binary = \"\";\n    const length = cryptoByteLength(source);\n    for (let i = 0; i < length; i++) {",
    replace: "    let binary = \"\";\n    const length = source.length;\n    for (let i = 0; i < length; i++) {",
    kind: "tests",
    suite: ["packages/signer-core", "npm", ["test"]],
  },
  {
    id: "a77-pkcs8-encoder-snapshots-private-seed",
    control: "#77-A public private-key encoder boundary — rawSeedToPkcs8Der takes an attached, non-shared intrinsic snapshot before reading a seed. Without it, a SharedArrayBuffer-backed seed can be changed by another worker while canonical PKCS8 bytes are assembled.",
    file: "packages/signer-core/src/der.ts",
    find: "  const source = normalizeDerBytes(seed, \"rawSeedToPkcs8Der.seed\");",
    replace: "  const source = seed;",
    kind: "tests",
    suite: ["packages/signer-core", "npm", ["test"]],
  },
  {
    id: "a77-pkcs8-no-live-byte-length",
    control: "#77-A private-key decode — PKCS8 length is read through the captured TypedArray brand getter. An untrusted receipt Proxy otherwise installs a self-restoring live length getter that receives all 48 private DER bytes, copies the 32-byte seed, restores itself, and leaves signing apparently healthy.",
    file: "packages/signer-core/src/der.ts",
    find: "  try {\n    const derLength = cryptoByteLength(der);",
    replace: "  try {\n    const derLength = der.length;",
    kind: "tests",
    suite: ["packages/signer-core", "npm", ["test"]],
  },
  {
    id: "a77-pkcs8-no-live-slice",
    control: "#77-A private-key decode — the raw seed is copied by fixed integer indexes, never TypedArray.prototype.slice. A self-restoring slice hook otherwise receives and exfiltrates the complete private DER before calling through and producing the expected seed.",
    file: "packages/signer-core/src/der.ts",
    find: "    return copyByteRange(der, 16, 32);",
    replace: "    return der.slice(16);",
    kind: "tests",
    suite: ["packages/signer-core", "npm", ["test"]],
  },
  {
    id: "c77-display-spki-length-is-captured",
    control: "#77-C/2 — X25519 raw/SPKI length is read through the captured TypedArray brand getter. A recipients Proxy otherwise installs a self-restoring live length getter that rewrites the intended SPKI to an attacker key; the final fence sees restored descriptors, the attacker opens the CEK under the intended kid, and the intended device is locked out.",
    file: "packages/signer-core/src/encrypted-display.ts",
    find: "  const rawLength = cryptoByteLength(raw);",
    replace: "  const rawLength = raw.length;",
    kind: "tests",
    suite: ["packages/signer-core", "npm", ["test"]],
  },
  {
    id: "a77-ed25519-invocation-local-multiplier",
    control: "#77-A — every secret Ed25519 multiplication receives a fresh ScalarMultiplier. A multiplier retained from an earlier public call otherwise keeps closure-private state reachable after every prototype descriptor is restored; mutating its RNG or identity point can disclose the exact private scalar or corrupt signing without tripping a prototype-only fence.",
    file: "packages/signer-core/node_modules/@noble/curves/abstract/edwards.js",
    find: "            // Secret multiplication must not reuse state reachable through earlier public calls.\n            // This fresh instance takes the fixed-window isolated path and becomes unreachable here.\n            const secretMultiplier = new ScalarMultiplier(Point, randomBytes);\n            const { p, f } = secretMultiplier.mulSecretIsolated(this, scalar, cofactor, baseCanBeBlinded);",
    replace: "            const { p, f } = wnaf.mulSecret(this, scalar, cofactor, normalize);",
    kind: "tests",
    // Run the already-built end-to-end attack corpus directly: `npm test` first invokes the exact
    // dependency-byte verifier, which would reject the deliberate mutant before its exploit runs.
    suite: ["packages/signer-core", "node", ["--test", "dist/test/ed25519-runtime-integrity.test.js"]],
  },
  {
    id: "a77-ed25519-no-shared-window-cache",
    control: "#77-A — the invocation-local secret multiplier is not enough by itself: its secret path must force the fixed-window implementation and never read Noble's module-global pointWindowSizes or wnafPrecomputes state. A retained WeakMap reference plus a stateful window value otherwise reaches the blinded digits and reconstructs the private scalar after all descriptors are restored.",
    file: "packages/signer-core/node_modules/@noble/curves/abstract/curve.js",
    find: "        return useBlinding\n            ? this.mulCTBlinded(point, scalar, undefined, true)\n            : this.mulCT(point, scalar, undefined, true);",
    replace: "        return useBlinding\n            ? this.mulCTBlinded(point, scalar)\n            : this.mulCT(point, scalar);",
    kind: "tests",
    suite: ["packages/signer-core", "node", ["--test", "dist/test/ed25519-runtime-integrity.test.js"]],
  },
  {
    id: "a77-signer-packs-hardening-transformer",
    control: "#77-A supply-chain boundary — the signer tarball includes the exact postinstall transformer it names. Excluding that file produces an artifact whose installation cannot establish the seven dependency hashes and fails only after distribution.",
    file: "packages/signer-core/package.json",
    find: "    \"scripts/apply-dependency-hardening.mjs\",",
    replace: "    \"scripts/not-the-hardening-transformer.mjs\",",
    kind: "tests",
    suite: ["packages/signer-core", "node", ["--test", "test/dependency-hardening.test.mjs"]],
  },
  {
    id: "a77-signer-postinstall-exact-transformer",
    control: "#77-A supply-chain boundary — installation invokes the one exact hash-locked hardening transformer. A renamed or bypassed lifecycle target would leave pristine vulnerable Noble bytes under an otherwise healthy package manifest.",
    file: "packages/signer-core/package.json",
    find: "    \"postinstall\": \"node scripts/apply-dependency-hardening.mjs --apply\",",
    replace: "    \"postinstall\": \"node scripts/not-the-hardening-transformer.mjs --apply\",",
    kind: "tests",
    suite: ["packages/signer-core", "node", ["--test", "test/dependency-hardening.test.mjs"]],
  },
  {
    id: "a77-signer-bundles-hardened-dependencies",
    control: "#77-A supply-chain boundary — all three exact Noble packages are bundled beneath noa-signer. Letting one hoist to a consumer root either bypasses the package-local transformer or forces it to mutate dependencies shared with unrelated packages.",
    file: "packages/signer-core/package.json",
    find: "  \"bundledDependencies\": [\n    \"@noble/ciphers\",\n    \"@noble/curves\",\n    \"@noble/hashes\"\n  ],",
    replace: "  \"bundledDependencies\": [\n    \"@noble/ciphers\",\n    \"@noble/curves\"\n  ],",
    kind: "tests",
    suite: ["packages/signer-core", "node", ["--test", "test/dependency-hardening.test.mjs"]],
  },
  {
    id: "a77-signer-attests-complete-bundled-trees",
    control: "#77-A supply-chain boundary — hardening refuses any added, removed or changed byte across the three complete bundled Noble trees, not only the seven transformed files. Otherwise an unlisted executable can enter the tarball and receive private signing material while every patch hash stays green.",
    file: "packages/signer-core/scripts/apply-dependency-hardening.mjs",
    find: "  const trees = await attestHardenedDependencyTrees({ packageRoot });",
    replace: "  const trees = [];",
    kind: "tests",
    suite: ["packages/signer-core", "node", ["--test", "test/dependency-hardening.test.mjs"]],
  },
  {
    id: "c77-hpke-extract-expand-scope-covers-prk",
    control: "#77-C secret lifetime, HELPER reachability — extractAndExpand derives the DHKEM extract PRK INSIDE the scope that clears it. Derived first, a failing expand returns with a PRK that regenerates the shared secret still resident and nothing to clear it.",
    file: "packages/signer-core/src/hpke.ts",
    find: "  let eaePrk: Uint8Array | undefined;\n  try {\n    eaePrk = labeledExtract(KEM_SUITE_ID, EMPTY, \"eae_prk\", dh);\n    return labeledExpand(KEM_SUITE_ID, eaePrk, \"shared_secret\", kemContext, N_SECRET);\n  } finally {\n    if (eaePrk !== undefined) zeroCryptoBytes(eaePrk);\n  }",
    replace: "  const eaePrk = labeledExtract(KEM_SUITE_ID, EMPTY, \"eae_prk\", dh);\n  try {\n    return labeledExpand(KEM_SUITE_ID, eaePrk, \"shared_secret\", kemContext, N_SECRET);\n  } finally {\n    zeroCryptoBytes(eaePrk);\n  }",
    kind: "tests",
    suite: ["packages/signer-core", "npm", ["test"]],
  },
  {
    id: "c77-hpke-encap-scope-covers-ephemeral-scalar",
    control: "#77-C secret lifetime, HELPER reachability — encap draws the ephemeral X25519 scalar INSIDE the scope that clears it. Drawn first, a failing ladder call returns with a live ephemeral secret and nothing to clear it.",
    file: "packages/signer-core/src/hpke.ts",
    find: "  try {\n    // Do not call x25519.keygen(): Noble resolves globalThis.crypto.getRandomValues at call time.\n    // All randomness in this module must come through the module-load captured native CSPRNG.\n    skE = ephemeralSecretKey ?? hpkeRandomBytes(32);",
    replace: "  skE = ephemeralSecretKey ?? hpkeRandomBytes(32);\n  try {",
    kind: "tests",
    suite: ["packages/signer-core", "npm", ["test"]],
  },
  {
    id: "c77-hpke-seal-scope-covers-plaintext",
    control: "#77-C secret lifetime, EXPORTED reachability — hpkeSealBase snapshots the plaintext INSIDE the scope that clears it. The plaintext is the display content-encryption key on the production path; snapshotted first, the integrity fence and both length checks could each return holding it with nothing to clear it.",
    file: "packages/signer-core/src/hpke.ts",
    find: "  try {\n    plaintext = copyHpkeBytes(\n      ownDataValue(input, \"plaintext\", \"hpkeSealBase\", true),\n      \"hpkeSealBase.plaintext\",\n    );",
    replace: "  plaintext = copyHpkeBytes(\n    ownDataValue(input, \"plaintext\", \"hpkeSealBase\", true),\n    \"hpkeSealBase.plaintext\",\n  );\n  try {",
    kind: "tests",
    suite: ["packages/signer-core", "npm", ["test"]],
  },
  {
    id: "c77-hpke-seal-clears-plaintext",
    control: "#77-C secret lifetime, EXPORTED cleanup — hpkeSealBase clears its OWN plaintext snapshot in its OWN finally. The name `plaintext` also exists in openEncryptedDisplay, so a file-wide search for it stays green while this function's cleanup is gone.",
    file: "packages/signer-core/src/hpke.ts",
    find: "    if (plaintext !== undefined) zeroCryptoBytes(plaintext);\n    if (ephemeralSecretKey !== undefined) zeroCryptoBytes(ephemeralSecretKey);",
    replace: "    if (ephemeralSecretKey !== undefined) zeroCryptoBytes(ephemeralSecretKey);",
    kind: "tests",
    suite: ["packages/signer-core", "npm", ["test"]],
  },
  {
    id: "c77-display-seal-clears-canonical-display",
    control: "#77-C secret lifetime, EXPORTED cleanup — sealEncryptedDisplay clears the canonical display bytes in its OWN finally. Those bytes are the approval content a human is about to be shown; the name `displayBytes` appears nowhere else, but `cek` does, so only a scope-aware check catches the loss.",
    file: "packages/signer-core/src/encrypted-display.ts",
    find: "    if (cek !== undefined) zeroCryptoBytes(cek);\n    if (displayBytes !== undefined) zeroCryptoBytes(displayBytes);",
    replace: "    if (cek !== undefined) zeroCryptoBytes(cek);",
    kind: "tests",
    suite: ["packages/signer-core", "npm", ["test"]],
  },
  {
    id: "c77-display-seal-scope-covers-canonicalization",
    control: "#77-C secret lifetime, EXPORTED reachability — sealEncryptedDisplay canonicalizes the caller's display INSIDE the scope that clears the resulting bytes. Canonicalization refuses shapes it cannot represent, so performed ahead of the scope it returns with the approval content already materialized and nothing to clear it.",
    file: "packages/signer-core/src/encrypted-display.ts",
    find: "  let deterministicCek: Uint8Array | undefined;",
    replace: "  const earlyDisplayBytes = capturedTextEncode(canonicalize(display));\n  let deterministicCek: Uint8Array | undefined;",
    kind: "tests",
    suite: ["packages/signer-core", "npm", ["test"]],
  },
  {
    id: "c77-hpke-decap-scope-covers-raw-dh",
    control: "#77-C secret lifetime, HELPER reachability — decap opens its cleanup scope BEFORE the first scalar multiplication. With the scope opening after all three statements, a failing second ladder call or a failing concat returned with the raw X25519 shared secret resident and nothing to clear it. The caller-level assertions cannot see inside a helper, which is why this is pinned by name.",
    file: "packages/signer-core/src/hpke.ts",
    find: "  let dh: Uint8Array | undefined;\n  try {\n    dh = x25519ScalarMult(recipientSecretKey, enc);\n    const pkRm = x25519ScalarMult(recipientSecretKey, X25519_BASEPOINT);\n    const kemContext = concatBytes(enc, pkRm);\n    return extractAndExpand(dh, kemContext);\n  } finally {\n    if (dh !== undefined) zeroCryptoBytes(dh);\n  }",
    replace: "  const dh = x25519ScalarMult(recipientSecretKey, enc);\n  const pkRm = x25519ScalarMult(recipientSecretKey, X25519_BASEPOINT);\n  const kemContext = concatBytes(enc, pkRm);\n  try {\n    return extractAndExpand(dh, kemContext);\n  } finally {\n    zeroCryptoBytes(dh);\n  }",
    kind: "tests",
    suite: ["packages/signer-core", "npm", ["test"]],
  },
  {
    id: "c77-hpke-labeled-extract-clears-labeled-ikm",
    control: "#77-C secret lifetime — labeledExtract clears the labeled IKM buffer it builds. On the DHKEM path that buffer CONTAINS the raw X25519 result under a different name, so leaving it uncleared keeps raw DH resident after every single encapsulation and decapsulation, no failure required.",
    file: "packages/signer-core/src/hpke.ts",
    find: "  let labeledIkm: Uint8Array | undefined;\n  try {\n    labeledIkm = concatBytes(capturedTextEncode(HPKE_VERSION), suiteId, capturedTextEncode(label), ikm);\n    return extract(sha256, labeledIkm, salt);\n  } finally {\n    if (labeledIkm !== undefined) zeroCryptoBytes(labeledIkm);\n  }",
    replace: "  const labeledIkm = concatBytes(capturedTextEncode(HPKE_VERSION), suiteId, capturedTextEncode(label), ikm);\n  return extract(sha256, labeledIkm, salt);",
    kind: "tests",
    suite: ["packages/signer-core", "npm", ["test"]],
  },
  {
    id: "c77-hpke-keyschedule-transfers-after-both-outputs",
    control: "#77-C secret lifetime, PARTIAL DERIVATION — keyScheduleBase marks ownership transferred only after BOTH the AEAD key and the base nonce exist. The key is derived first, so an early flag makes a failure between the two derivations skip cleanup and leave a complete content key with no owner; the flag is also what stops the opposite error of handing the caller zeroed key material.",
    file: "packages/signer-core/src/hpke.ts",
    find: "    secret = labeledExtract(HPKE_SUITE_ID, sharedSecret, \"secret\", EMPTY);\n    key = labeledExpand(HPKE_SUITE_ID, secret, \"key\", keyScheduleContext, N_K);",
    replace: "    transferred = true;\n    secret = labeledExtract(HPKE_SUITE_ID, sharedSecret, \"secret\", EMPTY);\n    key = labeledExpand(HPKE_SUITE_ID, secret, \"key\", keyScheduleContext, N_K);",
    kind: "tests",
    suite: ["packages/signer-core", "npm", ["test"]],
  },
  {
    id: "c77-hpke-cleanup-scope-covers-throw-sites",
    control: "#77-C secret lifetime, REACHABILITY — the cleanup scope opens before the first sensitive copy, so no statement that can throw runs while an uncleared secret exists. MEASURED: with the scope opening after the device-secret snapshot and the integrity fence, a poisoned-intrinsic refusal or a wrong-length argument returned holding a complete private X25519 device key that nothing cleared. A presence-only check reports that shape GREEN, which is why the assertion is positional.",
    file: "packages/signer-core/src/hpke.ts",
    find: "  try {\n    recipientSecretKey = copyHpkeBytes(\n      ownDataValue(input, \"recipientSecretKey\", \"hpkeOpenBase\", true),\n      \"hpkeOpenBase.recipientSecretKey\",\n    );",
    replace: "  recipientSecretKey = copyHpkeBytes(\n    ownDataValue(input, \"recipientSecretKey\", \"hpkeOpenBase\", true),\n    \"hpkeOpenBase.recipientSecretKey\",\n  );\n  assertHpkeRuntimeIntegrity();\n  try {",
    kind: "tests",
    suite: ["packages/signer-core", "npm", ["test"]],
  },
  {
    id: "c77-hpke-clears-invocation-owned-secrets",
    control: "#77-C secret lifetime — hpkeOpenBase clears its PRIVATE snapshot of the device secret key from a finally block. The snapshot is this invocation's own copy, so nothing else will ever clear it; a tag mismatch, a poisoned-intrinsic refusal or an ordinary return otherwise leaves a complete X25519 device key in heap memory long after the approval it decrypted.",
    file: "packages/signer-core/src/hpke.ts",
    find: "    if (recipientSecretKey !== undefined) zeroCryptoBytes(recipientSecretKey);\n    if (sharedSecret !== undefined) zeroCryptoBytes(sharedSecret);",
    replace: "    if (sharedSecret !== undefined) zeroCryptoBytes(sharedSecret);",
    kind: "tests",
    suite: ["packages/signer-core", "npm", ["test"]],
  },
  {
    id: "c77-display-clears-cek-and-plaintext",
    control: "#77-C secret lifetime — openEncryptedDisplay clears the device-secret snapshot and the decrypted display bytes from a finally block. Without it a failed or refused open leaves the approval plaintext a human was about to read, plus the key that recovered it, resident after the call that was supposed to fail closed.",
    file: "packages/signer-core/src/encrypted-display.ts",
    find: "    if (recipientSecretKey !== undefined) zeroCryptoBytes(recipientSecretKey);\n    if (cek !== undefined) zeroCryptoBytes(cek);\n    if (plaintext !== undefined) zeroCryptoBytes(plaintext);",
    replace: "    if (cek !== undefined) zeroCryptoBytes(cek);",
    kind: "tests",
    suite: ["packages/signer-core", "npm", ["test"]],
  },
  {
    id: "a77-signreceipt-zeroes-seed-on-pre-sign-throw",
    control: "#77-A private-key lifecycle — signReceipt enters a finally-backed zeroing scope immediately after PKCS8 seed extraction. Receipt hashing and canonicalization can throw before Ed25519 runs; those paths must not retain the raw private seed.",
    file: "packages/signer-core/src/sign.ts",
    find: "  return withZeroedCryptoBytes(seed, (privateSeed) => {",
    replace: "  return ((privateSeed: Uint8Array) => {",
    also: [
      {
        find: "    return signed;\n  });",
        replace: "    return signed;\n  })(seed);",
      },
    ],
    kind: "tests",
    suite: ["packages/signer-core", "npm", ["test"]],
  },
  {
    id: "a77-signing-index-writes",
    control: "#77-A \u2014 signingMessageBytes assembles the Ed25519 message by INTEGER INDEX, never `.set()`. `Uint8Array.prototype.set` is a writable global; with it a no-op the message became 53 zero bytes, so every receipt was signed over the same constant.",
    file: "packages/signer-core/src/signing.ts",
    find: "  const n = cryptoByteLength(domainBytes);\n  const m = cryptoByteLength(digest);\n  const out = new Uint8ArrayCtor(n + m);\n  for (let i = 0; i < n; i++) out[i] = domainBytes[i] as number;\n  for (let i = 0; i < m; i++) out[n + i] = digest[i] as number;",
    replace: "  const n = cryptoByteLength(domainBytes);\n  const m = cryptoByteLength(digest);\n  const out = new Uint8ArrayCtor(n + m);\n  out.set(domainBytes, 0);\n  out.set(digest, n);",
    kind: "tests",
    suite: ["packages/signer-core", "npm", ["test"]],
  },
  {
    id: "a77-hash-primitive-kat",
    control: "#77-A \u2014 the signing path runs a KNOWN-ANSWER TEST on SHA-256 before signing. `@noble/hashes` builds blocks with `Uint8Array.prototype.set` (_md.js:94), so a poisoned prototype neutralises the hash itself and sha256(A) === sha256(B). Not fixable inside this package; the guarantee is that signing REFUSES rather than emitting a digest that is not a digest.",
    file: "packages/signer-core/src/signing.ts",
    find: "  assertSha256Intact();",
    replace: "  if (Math.abs(1) === 1) { /* KAT removed */ }",
    kind: "tests",
    suite: ["packages/signer-core", "npm", ["test"]],
  },
  {
    id: "a77-hash-captured-encoder",
    control: "#77-A \u2014 hash.ts encodes through a CAPTURED TextEncoder.prototype.encode. It decides WHAT GETS HASHED; live, an attacker returning an empty array made two different receipts share a signature.",
    file: "packages/signer-core/src/hash.ts",
    find: "  const buf = typeof data === \"string\" ? (reflectApply(textEncoderEncode, encoder, [data]) as Uint8Array) : data;",
    replace: "  const buf = typeof data === \"string\" ? encoder.encode(data) : data;",
    kind: "tests",
    suite: ["packages/signer-core", "npm", ["test"]],
  },
  {
    id: "r815-qa17-array-named-property-refusal",
    control: "R815-QA-17 \u2014 a NAMED property on an array is REFUSED, not silently dropped. The index walk copies indices only, so `arr.foo` vanished without a word; JCS emits neither so the wire bytes are unaffected, but silent reshaping on a signing path is exactly what this function refuses to do. Covers the \"4294967295\" boundary, which is a named property rather than an index.",
    file: "packages/signer-core/src/deep-copy.ts",
    find: "      if (name === \"length\") continue;",
    replace: "      if (name === \"length\") continue;\n      if (name) continue;",
    kind: "tests",
    suite: ["packages/signer-core", "npm", ["test"]],
  },
  {
    id: "r815-qa12-forbidden-key-refusal",
    control: "R815-QA-12 \u2014 the producer REFUSES the three keys the strict parser refuses (__proto__/prototype/constructor). What the authoritative verifier will not read, the producer must not write: signing such a document produces an artefact that can never verify. This LAYERS with the defineProperty class closure; it does not replace it.",
    file: "packages/signer-core/src/deep-copy.ts",
    find: "    if (key === \"__proto__\" || key === \"prototype\" || key === \"constructor\") {",
    replace: "    if (false) {",
    kind: "tests",
    suite: ["packages/signer-core", "npm", ["test"]],
  },
  {
    id: "r815-qa14-object-class-not-spelling",
    control: "R815-QA-14 \u2014 the deep copy closes the CLASS of inherited setters, not the `__proto__` SPELLING. A fix that defineProperty'd only the one key the tests named would leave every other inherited setter live, and it passed the whole suite 50/50 before this control existed.",
    file: "packages/signer-core/src/deep-copy.ts",
    find: "    objectDefineProperty(out, key, {\n      value: copyValue(d.value, `${path}.${key}`, depth + 1),\n      writable: true,\n      enumerable: true,\n      configurable: true,\n    });",
    replace: "    if (key === \"__proto__\") {\n      objectDefineProperty(out, key, {\n        value: copyValue(d.value, `${path}.${key}`, depth + 1),\n        writable: true, enumerable: true, configurable: true,\n      });\n    } else {\n      out[key] = copyValue(d.value, `${path}.${key}`, depth + 1);\n    }",
    kind: "tests",
    suite: ["packages/signer-core", "npm", ["test"]],
  },
  {
    id: "r815-qa14-array-class-not-index0",
    control: "R815-QA-14 \u2014 the ARRAY branch closes the class for EVERY index, not index 0. A fix that defineProperty'd only element 0 also passed 50/50; the control is an `Array.prototype` accessor on a NON-ZERO index.",
    file: "packages/signer-core/src/deep-copy.ts",
    find: "      objectDefineProperty(out, i, {\n        value: copyValue(d.value, `${path}[${i}]`, depth + 1),\n        writable: true,\n        enumerable: true,\n        configurable: true,\n      });",
    replace: "      if (i === 0) {\n        objectDefineProperty(out, i, {\n          value: copyValue(d.value, `${path}[${i}]`, depth + 1),\n          writable: true, enumerable: true, configurable: true,\n        });\n      } else {\n        out[i] = copyValue(d.value, `${path}[${i}]`, depth + 1);\n      }",
    kind: "tests",
    suite: ["packages/signer-core", "npm", ["test"]],
  },
  // ── RESOLVER PARITY + THE CENSUS GATE ─────────────────────────────────────────────────────────
  {
    id: "res-inventory-reconcile-blocks",
    control: "P0-8 census — a resolver REMOVED from the inventory turns the reconciliation gate RED (the tree is re-derived from the AST on every run; the inventory is never trusted)",
    file: "scripts/resolver-inventory.json",
    find: '    {\n      "id": "approval-artifacts-keyring-tenant-authority-1-0",\n      "package": "approval-artifacts",\n      "file": "packages/approval-artifacts/scripts/gen-vectors.ts",\n      "scope": "keyring>tenant-authority-1",\n      "ordinal": 0,\n      "line": 59,\n      "kind": "construct",\n      "class": "vector-gen",\n      "input": "hardcoded vector key material",\n      "output": "KeyEntry (vector fixture)",\n      "validFrom": "absent",\n      "revokedAt": "absent",\n      "missingValue": "verifier-keyring vector entries deliberately pin the legacy always-active behaviour",\n      "malformedValue": "rejection vectors declare malformed values on purpose",\n      "timestampParser": "hardcoded canonical constants",\n      "consumer": "conformance vector runner (§6)",\n      "proofs": [],\n      "exception": "EX-TEST-FIXTURES"\n    },\n',
    replace: "",
    kind: "gate",
    gateId: "resolver-parity",
    expectedGateFindings: [{
      rule: "NEW_SITE",
      subject: "packages/approval-artifacts/scripts/gen-vectors.ts::keyring>tenant-authority-1::0",
    }],
    suite: [".", "npm", ["run", "lint:resolver-parity"]],
  },
  {
    id: "res-vocabulary-reconciles-signer-display-test",
    control: "Resolver vocabulary census — the signer display-substitution test's raw X25519 publicKeyHex is explicitly classified as recipient material, not silently mistaken for or hidden from the KeyEntry resolver inventory",
    file: "scripts/resolver-inventory.json",
    find: '    "packages/signer-core/test/display-substitution.test.ts": "signer-core encrypted-display recipient-routing regression tests: publicKeyHex is a raw X25519 device recipient key encoded for HPKE input; this file constructs no KeyEntry, resolves no trust keyring, and never reads validFrom/revokedAt/roles",\n',
    replace: "",
    kind: "gate",
    gateId: "resolver-parity",
    expectedGateFindings: [{
      rule: "VOCAB_UNCLASSIFIED",
      subject: "packages/signer-core/test/display-substitution.test.ts",
    }],
    suite: [".", "node", ["scripts/lint-resolver-parity.mjs"]],
  },
  {
    id: "res-parity-proof-must-resolve",
    control: "P0-7 — a registered parity proof must RESOLVE to a live test; skipping it turns the reconciliation gate RED (a source claim about a control that does not run is the exact defect this batch adjudicated)",
    file: "packages/e2e-demo/test/keyring-resolver-parity.test.ts",
    find: "test('[PROOF:RES-PAR-XRES-EQUIV] evidence and gate resolvers enforce the same activation semantics', () => {",
    replace: "test.skip('[PROOF:RES-PAR-XRES-EQUIV] evidence and gate resolvers enforce the same activation semantics', () => {",
    kind: "gate",
    gateId: "resolver-parity",
    expectedGateFindings: [{ rule: "PROOF_UNRESOLVED", subject: "RES-PAR-XRES-EQUIV" }],
    suite: [".", "npm", ["run", "lint:resolver-parity"]],
  },
  // ── noa.action-digest/0.1 (round-2 QA, 2026-08-12) ────────────────────────────────────────────
  // Round-2 QA observed that this module had NO entry here at all, so none of its controls were in
  // the repository's own L4 ratchet — its knockout evidence lived in a scratch script, which is the
  // "asserted census" shape this whole gate exists to end. These are the controls that can be
  // ISOLATED: each mutation leaves every other rule intact, so the named vector is the only thing
  // that can go red.
  //
  // Deliberately ABSENT, and this is the corrected half of the same finding: there is no entry for
  // the projection's `actionId`, `actionCanonical`, `actionParamsHash`, `executionGrantId` or
  // `executionNonce` members. They cannot be isolated by construction — `authorizationReceiptHash`
  // and `executionGrantHash` are hashes over the whole receipt and the whole grant, so any source
  // mutation that moves one of those five moves a whole-document hash too, and the attack is refused
  // either way. Registering a knockout that "passes" for that reason would be vacuous. See
  // docs/action-digest-spec.md §7.
  {
    id: "ad-verdict-must-be-allowed",
    control: "HIGH-1 — an action digest may only be built from an ALLOWED receipt. Without this check a cryptographically VALID human DENIAL correlates as the authorization for the action it denied: verifyChain VALID, verifyArtifact ok, digest MATCHED. Same class as the relay's APPROVED-over-a-denial defect, recurring in a new module.",
    file: "src/action-digest.ts",
    find: '  if (governance["verdict"] !== AUTHORIZING_VERDICT) {',
    replace: '  if (governance["verdict"] === "\\u0000never") {',
    kind: "tests",
    suite: [".", "npm", ["run", "test:action-digest"]],
  },
  {
    id: "ad-scope-identifier-not-blank",
    control: "HIGH-2 — emptiness is a property of the TRIMMED value. `length === 0` refused \"\" and accepted \"   \", so the semantic \"unknown tenant\" passed every verifier, and a padded tenant aliased to a different one anywhere that trims.",
    file: "src/action-digest.ts",
    find: '  if (strTrim(v).length === 0) return "blank";\n  if (strTrim(v) !== v) return "padded";',
    replace: '  if (v.length === 0) return "blank";',
    kind: "tests",
    suite: [".", "npm", ["run", "test:action-digest"]],
  },
  {
    id: "ad-chain-must-authenticate",
    control: "HIGH-3 — verifyActionDigest authenticates its own inputs by delegating to verifyChain. Without it, an attacker's key claiming the victim's kid mints an entire authorization and a matching digest; the previous revision disclosed that in prose instead, and prose does not enforce call ordering.",
    file: "src/action-digest.ts",
    find: '  if (chainVerdict.status !== "VALID" || chainVerdict.signaturesVerified !== true) {',
    replace: '  if (chainVerdict.count === -1) {',
    kind: "tests",
    suite: [".", "npm", ["run", "test:action-digest"]],
  },
  {
    id: "ad-grant-signature-verified",
    control: "HIGH-3 (grant half) — the grant's Ed25519 signature is verified under its own §6 domain tag with the key resolved by resolveVerificationKey, so an outsider cannot mint a grant. Role/expiry semantics remain verifyArtifact's and are documented as a residual, not claimed here.",
    file: "src/action-digest.ts",
    find: '  if (!verifyEd25519(grantKey.publicKey, signingMessage(GRANT_SIG_DOMAIN, canonicalize(grantWithoutSig)), grantSig["value"])) {',
    replace: '  if (grantSig["value"] === "\\u0000never") {',
    kind: "tests",
    suite: [".", "npm", ["run", "test:action-digest"]],
  },
  {
    id: "ad-grant-sig-object-is-closed",
    control: "MEDIUM-4 — the grant's nested `sig` object is closed, not just its top level. `sig.extra` does not break the §6 signature (the preimage is JCS(doc without sig)), so only the closed-world rule can refuse it — and verifyArtifact does.",
    file: "src/action-digest.ts",
    find: '    if (!arrayIncludes(GRANT_SIG_KEYS, k)) {',
    replace: '    if (k === "\\u0000never") {',
    kind: "tests",
    suite: [".", "npm", ["run", "test:action-digest"]],
  },
  {
    id: "ad-authorization-selected-by-grant-binding",
    control: "HIGH-3 (substitution) — the authorization receipt is selected from the verified chain by the grant's OWN approvalReceiptHash, so a caller cannot aim the verifier at a receipt the grant does not reference.",
    file: "src/action-digest.ts",
    find: '    if (sha256Prefixed(receiptHashInput(candidate as unknown as Receipt)) === wanted) {',
    replace: '    if (true) {',
    kind: "tests",
    suite: [".", "npm", ["run", "test:action-digest"]],
  },
  {
    id: "ad-expected-scope-enforced",
    control: "The ONE job `tenant`/`chain` do that the whole-document hashes do not: answering \"are these documents MINE?\". No property of the digest can answer it, because the digest knows nothing about who is asking.",
    file: "src/action-digest.ts",
    find: '  if (built.projection.tenant !== expect["tenant"]) {',
    replace: '  if (built.projection.tenant === "\\u0000never") {',
    kind: "tests",
    suite: [".", "npm", ["run", "test:action-digest"]],
  },
  {
    id: "ad-domain-separation-applied",
    control: "The digest is the projection hashed under NOA-ActionDigest-v0.1-dig, a tag disjoint from every SIGNING tag. Pointing it at the receipt signing tag makes reject-wrong-domain-tag verify — cross-protocol reuse of a value another verifier already accepts.",
    file: "src/action-digest.ts",
    find: 'export const ACTION_DIGEST_DOMAIN = "NOA-ActionDigest-v0.1-dig";',
    replace: 'export const ACTION_DIGEST_DOMAIN = "NOA-Receipt-v0.1-sig";',
    kind: "tests",
    suite: [".", "npm", ["run", "test:action-digest"]],
  },
  // ── P0-12 / P0-13 (2026-07-31, micro-batch B): HARDENING WHAT BATCH A BUILT ────────────────────
  // Both entries below exist because a control that batch A added did not hold: ROOT activation was
  // carried and never enforced, and the proof-resolution rule was defeated by a second spelling of
  // "skip". Each knockout targets the NEW control, not the old defect.
  {
    id: "p12-root-activation-enforced",
    control: "P0-12 — a trust ROOT is subject to its OWN activation window. Exempting ROOT from the activation branch left 1040 tests across five suites green before these proofs existed: carriage (P0-1) was proven, enforcement was not. [proof: RES-PAR-ROOT-ENFORCED]",
    file: "packages/approval-artifacts/src/verify.ts",
    find: "    if (entry.validFrom != null) {",
    replace: '    if (entry.validFrom != null && entry.type !== "ROOT") {',
    kind: "tests",
    suite: ["packages/approval-artifacts", "npm", ["test"]],
  },
  {
    id: "p13-proof-resolution-is-structural",
    control: "P0-13 — proof resolution reads the AST, so a control cannot be disabled by a spelling the matcher does not know. Defanging the options-object rule makes `test(name, { skip: true }, fn)` certify as live again — the exact measured bypass (gate: skipped 3, lint exit 0). Since P0-15 this AST tier is DIAGNOSIS; the selftest ahead of the gate is what turns this mutation red.",
    file: "scripts/lib/proof-resolve.mjs",
    find: 'if (v.kind === ts.SyntaxKind.TrueKeyword || ts.isStringLiteral(v)) return "disabled";',
    replace: 'if (false) return "disabled";',
    kind: "gate",
    gateId: "proof-resolve-selftest",
    expectedGateFindings: [{
      rule: "SELFTEST",
      subject: "{ skip: true } object form is DISABLED  <- THE P0-13 BYPASS",
    }],
    suite: [".", "node", ["scripts/lib/proof-resolve.selftest.mjs"]],
  },
  // ── P0-15 (2026-07-31, micro-batch B2): LIVENESS COMES FROM THE RUNNER, NOT FROM A MODEL OF IT ─
  // The proof-liveness control was bypassed in three consecutive rounds (line scan → {skip:true};
  // AST → indirect options, computed ["skip"], aliased describe.skip, dead if(false)). This entry
  // uses the FIRST of the four runtime-only spellings — an options object behind a variable, which
  // the AST tier provably resolves "live" — so it goes red only if the RUNNER tier catches it.
  // A knockout using a statically-visible spelling would prove the wrong tier.
  {
    id: "p15-proof-liveness-from-runner",
    control: "P0-15 — a registered proof must appear as a PASSING test in a REAL `node --test` run; a skip spelled so that no static parse can see it (indirect options object) is still refused, because the runner is ground truth and the parser is only a model of it.",
    file: "packages/e2e-demo/test/keyring-resolver-parity.test.ts",
    find: "test('[PROOF:RES-PAR-XRES-EQUIV] evidence and gate resolvers enforce the same activation semantics', () => {",
    replace: "const __p15 = { skip: true };\ntest('[PROOF:RES-PAR-XRES-EQUIV] evidence and gate resolvers enforce the same activation semantics', __p15, () => {",
    kind: "gate",
    gateId: "resolver-parity",
    expectedGateFindings: [{ rule: "PROOF_UNRESOLVED", subject: "RES-PAR-XRES-EQUIV" }],
    suite: [".", "npm", ["run", "lint:resolver-parity"]],
  },
  {
    id: "p15-proof-events-bind-authored-sites",
    control: "P0-15 — a runner PASS must match the exact authored name, file, line and column in the executed test file. A dead literal proof plus a dynamically constructed passing marker may not substitute for the registered control.",
    file: "scripts/lib/proof-resolve.mjs",
    find: "    const key = identity(hit);",
    replace: "    const key = identity(expectedSites.shift());",
    kind: "gate",
    gateId: "proof-resolve-selftest",
    expectedGateFindings: [{
      rule: "SELFTEST",
      subject: "ATTACK: a dynamic passing marker cannot answer for a dead authored proof site",
    }],
    suite: [".", "node", ["scripts/lib/proof-resolve.selftest.mjs"]],
  },
  {
    id: "res-proof-knockout-coverage-required",
    control: "F-4 — removing the sole declared knockout binding for one registered proof makes resolver parity fail with PROOF_WITHOUT_KNOCKOUT_BINDING. This meta-gate proves the binding rule only; requireNamedProofFailures separately checks behaviour when the tagged knockout executes.",
    file: "scripts/lint-control-knockout.mjs",
    find: '    control: "P0-6 — a non-canonical declared activation is refused instead of being normalised by Date.parse into a usable instant. [proof: RES-PAR-AA-STRICT]",\n    file: "packages/approval-artifacts/src/verify.ts",',
    replace: '    control: "P0-6 — a non-canonical declared activation is refused instead of being normalised by Date.parse into a usable instant.",\n    file: "packages/approval-artifacts/src/verify.ts",',
    kind: "gate",
    gateId: "resolver-parity",
    expectedGateFindings: [{
      rule: "PROOF_WITHOUT_KNOCKOUT_BINDING",
      subject: "RES-PAR-AA-STRICT",
    }],
    suite: [".", "node", ["scripts/lint-resolver-parity.mjs"]],
  },
  // ── L11 — INERT-BEFORE-WRITE (2026-08-12) ─────────────────────────────────────────────────────
  // A class that no gate in this repository could express until now. `scripts/lint-security-gates.mjs`
  // models dispatch as a CALL or a READ; `packages/adapter-core/src/policy-change-guard.mjs:58-60`
  // states it in the source: L2 and L8 "have no grammar for a write". So an ordinary `[]` or `{}`
  // filled on a decision path contributed ZERO findings to either budget, and the three files that
  // got fixed got fixed because a human read them.
  //
  // The two entries below are deliberately of DIFFERENT kinds, because they measure different
  // controls. The first is the fix itself and is measured by TESTS. The second is the ORDERING —
  // creation-time versus fill-time — and is measured by the GATE, because the two orderings are
  // behaviourally identical on every honest input and only differ while a poison is installed
  // mid-fill.
  {
    id: "l11-precheck-fallback-container-inert",
    control:
      "L11 — canonicalParamsHash's fallback stringifier builds its `parts`/`items` containers INERT " +
      "BEFORE the first write. The captured `arrayPush` applies the PRISTINE push, but push is " +
      "defined as Set(O, \"0\", v) and [[Set]] walks the RECEIVER's prototype chain, so an accessor at " +
      "Object.prototype[\"0\"] swallows the first element while `length` still moves. MEASURED: two " +
      "different tool calls collapsed onto ONE paramsHash, so an approval minted for a 10-unit " +
      "transfer authorises a 900,000-unit one — with NO builtin replaced at all.",
    file: "packages/adapter-core/src/pre-check.mjs",
    find: "    const parts = [];\n    objectSetPrototypeOf(parts, INERT_ARRAY_PROTOTYPE);",
    replace: "    const parts = [];",
    kind: "tests",
    suite: ["packages/adapter-core", "npm", ["test"]],
  },
  {
    id: "l11-reroot-at-creation-not-after-fill",
    control:
      "L11 — a container is re-rooted at CREATION, never after the fill. This is the distinction the " +
      "whole layer exists for, and it is not hypothetical: the fix that shipped for this class once " +
      "re-derived the house pattern and got it wrong by re-rooting AFTER the loop. The mutation moves " +
      "`objectSetPrototypeOf` below the fill — identical output on every honest input — and " +
      "`lint:inert-containers` must report it as L11-B. A gate that scored both orderings the same " +
      "way would pass the exact code that shipped the defect.",
    file: "packages/adapter-core/src/policy-change-guard.mjs",
    find: "  const canon = [];\n  objectSetPrototypeOf(canon, INERT_ARRAY_PROTOTYPE);\n  for (let i = 0; i < arr.length; i += 1) arrayPush(canon, sortKeysDeep(arr[i]));",
    replace: "  const canon = [];\n  for (let i = 0; i < arr.length; i += 1) arrayPush(canon, sortKeysDeep(arr[i]));\n  objectSetPrototypeOf(canon, INERT_ARRAY_PROTOTYPE);",
    kind: "gate",
    gateId: "inert-containers",
    expectedGateFindings: [{
      rule: "L11-B",
      subject: "packages/adapter-core/src/policy-change-guard.mjs",
    }],
    suite: [".", "npm", ["run", "lint:inert-containers"]],
  },
  {
    id: "settlement-exit-six-splits-inconclusive",
    control:
      "The settlement ladder — an INCONCLUSIVE result whose settlement question was ASKED AND NOT " +
      "ANSWERED exits 6, not 3. Collapsing it into 3 is not a cosmetic loss: 3 already means \"stale " +
      "or absent checkpoint\", and a script that special-cases 3 as \"refresh the anchor and retry\" " +
      "would retry its way straight past the one state the ladder exists to surface. The mutation " +
      "makes every INCONCLUSIVE exit 3 — the exact shape of an exit table authored beside its rules " +
      "instead of derived from them.",
    file: "packages/evidence/src/exit-codes.ts",
    find: "  if (verdict === \"INCONCLUSIVE\") return SETTLEMENT_UNRESOLVED.has(settlement) ? 6 : 3;",
    replace: "  if (verdict === \"INCONCLUSIVE\") return 3;",
    kind: "tests",
    suite: ["packages/evidence", "npm", ["test"]],
  },
  {
    id: "settlement-completed-run-says-nobody-asked",
    control:
      "A run that completes the whole pipeline reports `settlement: NO_EXECUTION_BINDING` — no " +
      "execution binding was established for this bundle, because nothing asked for one. Reporting " +
      "`UNCHECKED` there would say \"the rule never ran\", which is true of a pipeline that stopped " +
      "early and false of one that finished; the two are the difference between an unfinished check " +
      "and an unasked question, and the result carries exactly one of them.",
    file: "packages/evidence/src/verify-evidence.ts",
    find: "    { integrity: \"INTACT\", authorization: ctx.authorization, settlement: \"NO_EXECUTION_BINDING\" },",
    replace: "    { integrity: \"INTACT\", authorization: ctx.authorization, settlement: \"UNCHECKED\" },",
    kind: "tests",
    suite: ["packages/evidence", "npm", ["test"]],
  },
  {
    id: "settlement-attestation-may-not-ride-a-positive",
    control:
      "Only two settlement states may ride a POSITIVE verdict: a re-query by the relying party's own " +
      "node, and the honest \"nobody asked\". Admitting the offline ceiling — an attestation this " +
      "verifier did not verify — onto that list is the defect the two-word name exists to prevent: " +
      "the caveat lives in a field nobody reads while the claim lives in the exit code every payment " +
      "script reads.",
    file: "packages/evidence/src/exit-codes.ts",
    find: "export const SETTLEMENT_ADMISSIBLE_ON_POSITIVE: FrozenSet<SettlementDimension> = frozenSet<SettlementDimension>([\n  \"RECONFIRMED\",\n  \"NO_EXECUTION_BINDING\",\n]);",
    replace: "export const SETTLEMENT_ADMISSIBLE_ON_POSITIVE: FrozenSet<SettlementDimension> = frozenSet<SettlementDimension>([\n  \"RECONFIRMED\",\n  \"NO_EXECUTION_BINDING\",\n  \"ATTESTED_UNVERIFIED\",\n]);",
    kind: "tests",
    suite: ["packages/evidence", "npm", ["test"]],
  },
  {
    id: "settlement-unresolved-set-membership",
    control:
      "The three states that exit 6 are the ones where the settlement question was ASKED AND NOT " +
      "ANSWERED — never the state where the rule simply did not run. Widening the set to include " +
      "\"the rule did not run\" fires 6 on every stopped pipeline, which re-verdicts historical " +
      "evidence and, worse, makes 6 a code that varies with nothing: a signal that never varies gets " +
      "`|| true`'d inside a sprint, and then the real state is invisible again.",
    file: "packages/evidence/src/exit-codes.ts",
    find: "  \"BOUNDS_UNCHECKABLE\", // no verified preimage, so the money was compared to nothing\n]);",
    replace: "  \"BOUNDS_UNCHECKABLE\", // no verified preimage, so the money was compared to nothing\n  \"UNCHECKED\",\n]);",
    kind: "tests",
    suite: ["packages/evidence", "npm", ["test"]],
  },
  {
    id: "settlement-cli-exit-wire-carries-the-verdict",
    control:
      "The CLI hands the SHELL the code the mapper computed. This is not a hypothetical: a reviewer " +
      "replaced this line with `process.exit(0)` and the whole suite stayed green, because every " +
      "assertion called the mapper and none started the binary. Every rejection would have exited 0 " +
      "on the exact channel a payment script reads, while the suite reported health. A doctrine that " +
      "calls the exit code \"the only channel most consumers use\" has to measure the process, not " +
      "the function one call short of it.",
    file: "packages/evidence/src/cli.ts",
    find: "  process.exit(code);",
    replace: "  process.exit(0);",
    kind: "tests",
    suite: ["packages/evidence", "npm", ["test"]],
  },
  {
    id: "settlement-cli-usage-error-is-not-success",
    control:
      "A usage or IO error exits 5, never 0. \"The arguments were wrong\" and \"the evidence says X\" " +
      "must not share a number, or a script reads a typo as a verification result — and it reads it " +
      "in the direction of the claim. Measured: turning this into 0 left the pre-wire suite green.",
    file: "packages/evidence/src/cli.ts",
    find: "  process.exit(USAGE_EXIT_CODE);",
    replace: "  process.exit(0);",
    kind: "tests",
    suite: ["packages/evidence", "npm", ["test"]],
  },
  {
    id: "settlement-inadmissible-tuple-refused-not-answered",
    control:
      "A tuple the assignment rules cannot produce is REFUSED by the mapper, and the CLI turns that " +
      "refusal into exit 7. Answering by verdict alone — the shape this replaced — returns 0 at the " +
      "money boundary for exactly the inputs a defective rule delivers. The mutation removes the " +
      "admissible pair every honest run uses, so a valid bundle now produces a tuple the table does " +
      "not list: the binary must exit 7 with the error's name on stderr rather than 0. That is the " +
      "throw-to-exit path proven end to end, without a fixture that lies.",
    file: "packages/evidence/src/exit-codes.ts",
    find: "  NOT_EVALUATED: frozenSet<SettlementDimension>([\"NO_EXECUTION_BINDING\"]),",
    replace: "  NOT_EVALUATED: frozenSet<SettlementDimension>([]),",
    kind: "tests",
    suite: ["packages/evidence", "npm", ["test"]],
  },
  {
    id: "settlement-dimensions-are-not-shared-between-results",
    control:
      "Each result gets its OWN dimensions object. Handing every early-return result one shared " +
      "object means a caller that writes to a result it owns silently rewrites the dimensions of " +
      "every LATER verification in that process, including ones it never saw — measured, it turned a " +
      "later INVALID result into INTACT / VALID_NOW / RECONFIRMED. Bundle bytes cannot do it; an " +
      "in-process consumer can, and a verifier whose past answers its own caller can edit is not " +
      "offering a verdict. The mutation restores the shared object.",
    file: "packages/evidence/src/verify-evidence.ts",
    find: "function nothingProven(): VerdictDimensions {\n  return { integrity: \"BROKEN\", authorization: \"UNCHECKED\", settlement: \"UNCHECKED\" };\n}",
    replace: "const SHARED_NOTHING_PROVEN: VerdictDimensions = { integrity: \"BROKEN\", authorization: \"UNCHECKED\", settlement: \"UNCHECKED\" };\nfunction nothingProven(): VerdictDimensions {\n  return SHARED_NOTHING_PROVEN;\n}",
    kind: "tests",
    suite: ["packages/evidence", "npm", ["test"]],
  },
  {
    id: "settlement-cli-refusal-exits-seven",
    control:
      "A refused tuple leaves this process as exit 7, and nothing else. Measured: this line and the " +
      "stderr write beside it BOTH survived a full green suite, because the only thing exercising " +
      "the refusal was a knockout — and a knockout scores any new red as a detection, so it could " +
      "not tell 7 from 2 from 0. The forced-refusal harness asserts the number, so a catch that " +
      "exits 0 on a verifier contradicting itself is now a failure with a name.",
    file: "packages/evidence/src/cli.ts",
    find: "    process.exit(INTERNAL_INVARIANT_EXIT_CODE);",
    replace: "    process.exit(0);",
    kind: "tests",
    suite: ["packages/evidence", "npm", ["test"]],
  },
  {
    id: "settlement-cli-refusal-names-its-cause",
    control:
      "A refused tuple is EXPLAINED on stderr, not merely signalled. Deleting the message leaves a " +
      "bare non-zero exit that sends an operator to re-read the evidence when the fault is in the " +
      "verifier. This is registered separately from the exit-code knockout on purpose: the two " +
      "defects masked each other while one assertion covered both, so the harness asserts the status " +
      "and the message in different tests and each mutation breaks exactly one.",
    file: "packages/evidence/src/cli.ts",
    find:
      "    process.stderr.write(\n" +
      "      `error: the exit mapper refused this result instead of returning a code. Expected cause: ` +\n" +
      "        `${INADMISSIBLE_TUPLE_ERROR_NAME} — (verdict, enrolment, settlement) = ` +\n" +
      "        `(${res.verdict}, ${res.enrolment}, ${res.dimensions.settlement}) is a tuple no assignment rule ` +\n" +
      "        `produces. This is a defect in this verifier, not a statement about the evidence.\\n`,\n" +
      "    );\n",
    replace: "",
    kind: "tests",
    suite: ["packages/evidence", "npm", ["test"]],
  },
  {
    id: "settlement-not-conditioned-on-what-the-caller-asked-for",
    control:
      "The settlement value does not depend on `purpose`. An audit run and an authorization run " +
      "examined the same settlement evidence — none — so a purpose-conditional value would be a " +
      "verdict that changes with who is asking. The mutation is the one a reviewer chose precisely " +
      "because the corpus runner never passes `purpose`: it was invisible to every fixture-driven " +
      "assertion, which is why the behavioural two-run pin exists.",
    file: "packages/evidence/src/verify-evidence.ts",
    find: "    { integrity: \"INTACT\", authorization: ctx.authorization, settlement: \"NO_EXECUTION_BINDING\" },\n    // REPORTED, not hardcoded",
    replace: "    { integrity: \"INTACT\", authorization: ctx.authorization, settlement: purpose === \"authorize\" ? \"ATTESTED_UNVERIFIED\" : \"NO_EXECUTION_BINDING\" },\n    // REPORTED, not hardcoded",
    kind: "tests",
    suite: ["packages/evidence", "npm", ["test"]],
  },
  {
    id: "consumption-result-failure-outcome-refuses-a-dispatch",
    control:
      "An EXECUTION_FAILED bundle may not ride a consumption that says the request was DISPATCHED. " +
      "The outcome claims the tool was never invoked; the consumption says it was handed off; before " +
      "this rule step 11 read that field NOWHERE and the bundle verified with both statements in it. " +
      "A determinate negative is claimable only on a non-executing party's observation " +
      "(NON-CLAIMS.md NC-2.1), and FAILED_BEFORE_DISPATCH is the value carrying it. The mutation " +
      "removes the check — the exact code that shipped before — so the corpus's step-11 rejection " +
      "must go red rather than quietly returning to VALID_FULL_CHAIN.",
    file: "packages/evidence/src/steps.ts",
    find:
      "  const resultErr = checkConsumptionResult(ctx, S, \"E_EXECUTION_FAILED\", \"FAILED_BEFORE_DISPATCH\");\n" +
      "  if (resultErr) return resultErr;\n",
    replace: "",
    kind: "tests",
    suite: ["packages/evidence", "npm", ["test"]],
  },
  {
    id: "consumption-result-failure-outcome-is-not-the-executed-one",
    control:
      "The two outcomes require OPPOSITE consumption results, and requiring the executed outcome's " +
      "value on the failure path is a DIFFERENT defect from having no rule at all — it is the one a " +
      "specification draft actually made, twice. Registered separately from the deletion knockout " +
      "because the two are told apart only by a corpus that fills all four cells of (outcome × " +
      "result): a suite that asserted only the two rejections would score this mutation as healthy " +
      "while the shipped VALID failure bundle became INVALID.",
    file: "packages/evidence/src/steps.ts",
    find: "  const resultErr = checkConsumptionResult(ctx, S, \"E_EXECUTION_FAILED\", \"FAILED_BEFORE_DISPATCH\");",
    replace: "  const resultErr = checkConsumptionResult(ctx, S, \"E_EXECUTION_FAILED\", \"DISPATCHED\");",
    kind: "tests",
    suite: ["packages/evidence", "npm", ["test"]],
  },
  {
    id: "consumption-result-executed-outcome-requires-a-dispatch",
    control:
      "The executed outcome's half of the same rule, which had no knockout for as long as it has " +
      "existed. EXECUTED means the gate handed the request off, and the consumption is the artifact " +
      "that says so; without this check a bundle could claim EXECUTED over a consumption reporting " +
      "that the tool was never invoked. Registered as its own entry so the two halves are proven " +
      "independently — one shared arm would let a mutation on either side be scored by the other " +
      "side's fixture.",
    file: "packages/evidence/src/steps.ts",
    find:
      "  const resultErr = checkConsumptionResult(ctx, S, \"E_EXECUTED\", \"DISPATCHED\");\n" +
      "  if (resultErr) return resultErr;\n",
    replace: "",
    kind: "tests",
    suite: ["packages/evidence", "npm", ["test"]],
  },
  {
    id: "settlement-plane-is-checked",
    control:
      "The S5 settlement artifact plane (R1/R2/R3) runs inside step 10 and is the only thing between " +
      "a bundle carrying a bad or unverifiable settlement artifact and a VALID_FULL_CHAIN / exit 0. " +
      "Remove the call and every settlement rejection fixture — a wrong correlation, a supplied-but- " +
      "wrong preimage, an out-of-bounds payee, a determinate non-settlement, an artifact with no " +
      "verifiable preimage — returns to the positive verdict it carried when no step examined it. This " +
      "is the F1/F2 control at the money boundary: without it, 'the money was compared to nothing' " +
      "reads as 'verified'.",
    file: "packages/evidence/src/steps.ts",
    find:
      "  const settlementErr = checkSettlement(ctx, S);\n" +
      "  if (settlementErr) return settlementErr;\n",
    replace: "",
    kind: "tests",
    suite: ["packages/evidence", "npm", ["test"]],
  },
  {
    id: "settlement-supplied-wrong-preimage-is-a-rejection",
    control:
      "R2 splits ONE reconciler code (SETTLEMENT_BOUNDS_UNCHECKABLE) two ways: an ABSENT or KEYED " +
      "preimage is INCONCLUSIVE (the producer withheld a checkable preimage — asked and unanswered, " +
      "exit 6), while a SUPPLIED preimage that does not hash to the approval is a producer LIE and a " +
      "HARD rejection (INVALID / E_PARAMS_PREIMAGE_MISMATCH, exit 2). Forcing the uncheckable branch " +
      "always-taken collapses the lie into the honest-withholding case, so the two SUPPLIED-preimage " +
      "fixtures — the hash mismatch and the unknown seventh member — flip from INVALID to " +
      "INCONCLUSIVE, while the two absent/keyed fixtures are UNAFFECTED. That asymmetry is what makes " +
      "this an independent pin on the distinction rather than on the settlement rule at large: a " +
      "mutation that broke the plane wholesale would move the absent/keyed fixtures too.",
    file: "packages/evidence/src/steps.ts",
    find: "      if (preimageUncheckable) {",
    replace: "      if (true) {",
    kind: "tests",
    suite: ["packages/evidence", "npm", ["test"]],
  },
  {
    id: "params-preimage-may-not-ride-alone",
    control:
      "The container admits `actionParamsPreimage` and `settlementEvidence` INDEPENDENTLY, and every " +
      "check that reads the preimage — the hash, the six-member shape, the bounds — sits behind the " +
      "artifact. Without the co-presence rule an attacker holding NO signing key appends a preimage " +
      "member to an otherwise valid signed EXECUTED bundle and still gets VALID_FULL_CHAIN and exit 0, " +
      "with those bytes examined by nothing. That is the precise 'positive verdict over a member no " +
      "step looked at' class the outcome union exists to close, reopened one member later. Removing " +
      "the rule must red the preimage-without-artifact vector.",
    file: "packages/evidence/src/steps.ts",
    find: "    if (b.actionParamsPreimage !== undefined) {",
    replace: "    if (false) {",
    kind: "tests",
    suite: ["packages/evidence", "npm", ["test"]],
  },
  {
    id: "params-preimage-must-be-canonical-bytes",
    control:
      "The preimage's hash proves only that the receipt committed to THESE bytes — not that the bytes " +
      "are the canonical (JCS) encoding the rule names. Without the re-canonicalize-and-compare, a " +
      "preimage carrying insignificant whitespace, unsorted members or non-minimal string escaping is " +
      "accepted under a 'canonical JCS' label, so one set of approved parameters can carry several " +
      "different valid paramsHash values. That is the same two-parties-two-hashes ambiguity the " +
      "unknown-member refusal exists to prevent, reached by a different door. Removing it must red the " +
      "three non-canonical vectors.",
    file: "packages/rail-x402/src/settlement-evidence.mjs",
    find: "  if (bufToString(rawBuf, \"utf8\") !== canonicalize(p)) {",
    replace: "  if (false) {",
    kind: "tests",
    suite: ["packages/rail-x402", "npm", ["test"]],
  },
  {
    id: "tampered-checkpoint-dominates-an-unanswered-settlement",
    control:
      "A settlement failure stops the pipeline BEFORE the chain/checkpoint step, so that step runs out " +
      "of band — and its result must be CAPTURED, not merely consulted for the integrity dimension. " +
      "`E_SETTLEMENT_BOUNDS_UNCHECKABLE` is SOFT (the question could not be answered: INCONCLUSIVE, " +
      "exit 6); a step-17 failure is HARD (a signature that does not verify, a chain that is not " +
      "genesis-rooted: INVALID, exit 2). Drop the dominance and a bundle carrying BOTH reports only the " +
      "soft one, so ATTACHING A SETTLEMENT ARTIFACT DOWNGRADES AUTHENTICATED-DATA TAMPERING from exit 2 " +
      "to exit 6 — across the exact boundary those two numbers exist to separate, and in the direction " +
      "that tells an automation 'unanswered, retry later' about forged bytes. The same bundle without " +
      "the settlement members already returned exit 2, which is what makes it a boundary crossing " +
      "rather than a difference of opinion. Must red the uncheckable-over-tampered-checkpoint vector.",
    file: "packages/evidence/src/verify-evidence.ts",
    find: "        if (!cp.ok && isSoftS5Failure(r.code)) failing = cp;",
    replace: "        if (false) failing = cp;",
    kind: "tests",
    suite: ["packages/evidence", "npm", ["test"]],
  },
  {
    id: "settlement-label-survives-a-later-failure",
    control:
      "`UNCHECKED` means exactly one thing — the settlement rule never ran — so a run in which the " +
      "rule DID run must never report it. The success branch records what it found on the context; " +
      "without that record the failure path falls back to `UNCHECKED`, and a bundle whose artifact was " +
      "examined AND ACCEPTED reports 'the rule never ran' as soon as any later step fails. That is a " +
      "false statement about which checks were performed, in the field a reader consults to find out " +
      "exactly that, and it contradicts the package's own published definition of the value. Removing " +
      "the assignment must red the label regression.",
    file: "packages/evidence/src/steps.ts",
    find: "      ctx.settlement = \"NO_EXECUTION_BINDING\";\n      return null;",
    replace: "      return null;",
    kind: "tests",
    suite: ["packages/evidence", "npm", ["test"]],
  },

  // ── S5 SLICE I4 — THE ENROLMENT PLANE ─────────────────────────────────────────────────────────
  //
  // Every entry below removes ONE rule and requires the corpus to notice. The set is organised
  // around one sentence: SUPPLYING A REGISTRY MAY ONLY EVER MAKE A VERDICT HARDER TO REACH. Each
  // mutation is a different way of making that false, and the design's own predecessor failed the
  // first one — an absent class bought the legacy positive, so narrowing a registry was a bypass.
  {
    id: "enrolment-absence-buys-nothing",
    control:
      "A class positively ABSENT from a selected, in-window, closed registry is UNVERIFIED — never a " +
      "blessing. This is the single most important rule in the plane, because the design it replaced " +
      "got it backwards: there, an absent class received the legacy VALID_FULL_CHAIN with no " +
      "settlement evidence at all, so a registry NARROWED to omit the payment class was MORE " +
      "permissive for that class than one that enrolled it — and the same document recommended " +
      "narrowing, shipping a recommended practice that doubled as the bypass. The mutation restores " +
      "exactly that behaviour: absence falls through to 'nobody asked'. The class-absent and " +
      "empty-registry fixtures must go from UNVERIFIED / exit 4 back to VALID_FULL_CHAIN / exit 0.",
    file: "packages/evidence/src/enrolment.ts",
    find:
      "  if (!enrolled) {\n" +
      "    ctx.enrolment = \"CLASS_ABSENT\";\n" +
      "    return fail(S, \"E_ENROLMENT_CLASS_ABSENT\",\n" +
      "      \"this bundle's action class is absent from every selected, in-window enrolment registry — an omission is an unanswered question, never a statement that the class is unenrolled (R7)\");\n" +
      "  }\n",
    replace: "  if (!enrolled) return null;\n",
    kind: "tests",
    suite: ["packages/evidence", "npm", ["test"]],
  },
  {
    id: "enrolment-requires-a-reader-identity",
    control:
      "Registries supplied with no `--audience` are REFUSED, not consulted. An unscoped registry is " +
      "the hole the audience field exists to close: without a reader identity, 'a registry scoped to " +
      "one relying party' and 'a policy downgrade' are the same bytes and no verifier can tell them " +
      "apart. The mutation makes a missing identity harmless, so a document written for somebody " +
      "else applies here silently — which is the whole attack.",
    file: "packages/evidence/src/enrolment.ts",
    find: "  if (audience === undefined || audience === \"\") {",
    replace: "  if (false) {",
    kind: "tests",
    suite: ["packages/evidence", "npm", ["test"]],
  },
  {
    id: "enrolment-audience-match-is-exact",
    control:
      "A registry is consulted only when it NAMES this reader — exact string membership, no wildcard, " +
      "no prefix, no case folding. The mutation accepts any registry with a non-empty audience, which " +
      "is the lenient matcher a reviewer would have to squint at: it looks like a scoping check and " +
      "selects every registry that reaches the reader. The audience-mismatch fixture must notice.",
    file: "packages/evidence/src/enrolment.ts",
    find: "    if (!isArray(aud) || !arraySome(aud, (a: unknown) => a === audience)) {",
    replace: "    if (!isArray(aud) || aud.length === 0) {",
    kind: "tests",
    suite: ["packages/evidence", "npm", ["test"]],
  },
  {
    id: "enrolment-open-registry-is-never-consulted",
    control:
      "`closed: false` is a refusal, not a weaker statement. An open registry makes no complete claim " +
      "for its audience and window, so every omission in it is ambiguous between 'not enrolled' and " +
      "'not mentioned' — and this design refuses to read either as a permission. The mutation " +
      "consults it anyway. Registered separately from the schema, DELIBERATELY: the schema types " +
      "`closed` as a boolean precisely so this rule is the refuser and the operator is told WHICH " +
      "thing is wrong instead of the generic 'does not authenticate'.",
    file: "packages/evidence/src/enrolment.ts",
    find: "    if (r.doc.closed !== true) {",
    replace: "    if (false) {",
    kind: "tests",
    suite: ["packages/evidence", "npm", ["test"]],
  },
  {
    id: "enrolment-window-must-contain-the-authorization-instant",
    control:
      "A registry governs a bundle only when its window contains the bundle's gate-signed " +
      "authorization instant. The mutation treats every selected registry as in-window, which is how " +
      "a stale or not-yet-live registry silently governs traffic it was never issued for. The window " +
      "is REJECT-ONLY by construction — every failure on this plane is non-positive — so removing it " +
      "cannot be defended as 'still fail-closed': it changes WHICH governance applies.",
    file: "packages/evidence/src/enrolment.ts",
    find: "    if (receivedAt >= nb && receivedAt <= na) arrayPush(inWindow, r);",
    replace: "    arrayPush(inWindow, r);",
    kind: "tests",
    suite: ["packages/evidence", "npm", ["test"]],
  },
  {
    id: "enrolment-wrong-tenant-is-a-contradiction",
    control:
      "A registry that AUTHENTICATES under this bundle's own root delegation while declaring a " +
      "different tenant is a CONTRADICTION — our own governance making a statement about somebody " +
      "else, handed over as if it governed this bundle. The mutation lets it govern. Note the " +
      "asymmetry this pins: a registry that does not authenticate is merely unusable (UNVERIFIED), " +
      "while one that does and disagrees is an accusation (INVALID), and the two must not collapse.",
    file: "packages/evidence/src/enrolment.ts",
    find: "    if (t !== ctx.tenant) {",
    replace: "    if (false) {",
    kind: "tests",
    suite: ["packages/evidence", "npm", ["test"]],
  },
  {
    id: "enrolment-class-key-is-a-pair",
    control:
      "The class key is the PAIR (actionSchema, displayProjection), and the projection half is what " +
      "makes enrolment fall out on a rendering change — fail-closed on drift, by construction. The " +
      "mutation drops the projection comparison, so a row that names this class while pinning a " +
      "DIFFERENT renderer hash enrols it anyway. That is the de-enrolment attack in reverse: an " +
      "attacker who can substitute the projection hash keeps the class enrolled under a renderer " +
      "nobody approved.",
    file: "packages/evidence/src/enrolment.ts",
    find: "        if (!projection.exact) {",
    replace: "        if (false) {",
    kind: "tests",
    suite: ["packages/evidence", "npm", ["test"]],
  },
  {
    id: "enrolment-actionid-crosscheck-binds-the-namespace",
    control:
      "The row's `actionId` must equal `deferredReceipt.action.id` — the ACTION-SCHEMA namespace, not " +
      "the display-projection one. This is what turns a known console↔kernel identifier drift from " +
      "silent semantic divergence into a blocking defect for enrolled classes, and it is the " +
      "regression pin for a correction an earlier design got wrong in the other direction: it keyed " +
      "the whole class on the projection alone, i.e. on a namespace that never equals `action.id`. " +
      "The mutation removes the cross-check; the id-drift and namespace fixtures must both notice.",
    file: "packages/evidence/src/enrolment.ts",
    find: "        if (rowActionId !== deferredActionId) {",
    replace: "        if (false) {",
    kind: "tests",
    suite: ["packages/evidence", "npm", ["test"]],
  },
  {
    id: "enrolment-raw-mode-is-never-enrollable",
    control:
      "A RAW hold is never enrollable: on a RAW hold the display a human approved and the params a " +
      "grant authorizes are two unrelated fields, so half the class key does not exist and the other " +
      "half cannot be tied to a rendering. A registry claiming the class enrolled there is asserting " +
      "something the gate-signed envelope cannot support. The mutation admits it, which would let a " +
      "RAW flow acquire the appearance of an enrolled, human-approved class.",
    file: "packages/evidence/src/enrolment.ts",
    find: "        if (asStr(env?.mode) !== \"ENFORCED\") {",
    replace: "        if (false) {",
    kind: "tests",
    suite: ["packages/evidence", "npm", ["test"]],
  },
  {
    id: "enrolled-class-requires-settlement-evidence",
    control:
      "THE RULE THE WHOLE SLICE EXISTS FOR. For an ENROLLED class an EXECUTED claim owes settlement " +
      "evidence, and a dispatch — the gate's own self-report about its own paperwork — is no longer " +
      "enough. The mutation removes the requirement, so an enrolled class with NO witness at all " +
      "returns to VALID_FULL_CHAIN and exit 0, which is the exact sentence this design was built to " +
      "stop being true. The headline fixture must go red.",
    file: "packages/evidence/src/steps.ts",
    find:
      "  if (ctx.enrolment === \"ENROLLED\") {\n" +
      "    const requiredErr = checkSettlementRequired(ctx, S, ctx.settlementFacts ?? null);\n" +
      "    if (requiredErr) return requiredErr;\n" +
      "  }\n",
    replace: "",
    kind: "tests",
    suite: ["packages/evidence", "npm", ["test"]],
  },
  {
    id: "enrolment-attestation-is-not-a-settlement",
    control:
      "THE CEILING. An authentic, bound, in-bounds, determinate settlement artifact that NOBODY " +
      "RE-QUERIED is INCONCLUSIVE, never a positive: an offline verifier can establish that an " +
      "assertion is well-formed and bound to this approval, and can never establish that it is TRUE, " +
      "because the signer of the assertion is not the world. The mutation returns the offline tier as " +
      "a pass — which is precisely the shipped defect this ladder replaced, where a self-consistent " +
      "forged SETTLED artifact signed by any authorized observer produced VALID_FULL_CHAIN and exit 0 " +
      "with nothing queried.",
    file: "packages/evidence/src/enrolment.ts",
    find: "  ctx.settlement = \"ATTESTED_UNVERIFIED\";\n  return fail(S, \"E_SETTLEMENT_UNRECONFIRMED\",",
    replace: "  ctx.settlement = \"ATTESTED_UNVERIFIED\";\n  if (true) return null;\n  return fail(S, \"E_SETTLEMENT_UNRECONFIRMED\",",
    kind: "tests",
    suite: ["packages/evidence", "npm", ["test"]],
  },
  {
    id: "enrolment-self-witnessed-settlement-is-not-admissible",
    control:
      "A key that says 'I dispatched it' saying 'and it settled' is one party attesting to its own " +
      "effect, and for an enrolled class that observation is not admissible. It is CAPPED rather than " +
      "REJECTED on purpose — this is today's honest deployment shape, and refusing it outright would " +
      "refuse the only shape that currently exists. The mutation admits it, which would let the " +
      "executing party supply its own settlement witness. The two fixtures differ by ONE key, so this " +
      "arm is independent of the requirement rule above.",
    file: "packages/evidence/src/enrolment.ts",
    find: "  if (facts.observerRelationship === \"SAME_SIGNING_KEY\") {",
    replace: "  if (false) {",
    kind: "tests",
    suite: ["packages/evidence", "npm", ["test"]],
  },
  {
    id: "enrolled-failure-may-not-ride-the-gates-word",
    control:
      "THE CARRY-FORWARD. `EXECUTION_FAILED` is a POSITIVE outcome that pays no step-15 " +
      "fresh-checkpoint tax, so the moment enrolment gives EXECUTED a price it becomes the ONLY " +
      "outcome that is both step-15-exempt AND settlement-free — the cheap relabelling path for a " +
      "gate hiding a spend. The mutation removes the rule, so an enrolled class relabelled as a " +
      "failure returns to VALID_FULL_CHAIN and exit 0 on the gate's own word. The rule is scoped to " +
      "enrolled classes, so its CONTROL fixture — the same bundle with no registry — must stay green " +
      "under the mutation, which is what makes this an arm on the asymmetry rather than on step 11.",
    file: "packages/evidence/src/steps.ts",
    find:
      "  const witnessErr = checkNonDispatchWitnessed(ctx, S);\n" +
      "  if (witnessErr) return witnessErr;\n",
    replace: "",
    kind: "tests",
    suite: ["packages/evidence", "npm", ["test"]],
  },
  // ── PANEL ROUND 1 — one arm per finding, each proving the FIX is what the corpus measures ──────
  {
    id: "enrolment-supplied-collection-shape-is-refused",
    control:
      "THE HIGH FINDING. A SUPPLIED registry collection this verifier cannot read as a list is " +
      "REFUSED — it never softens into \"no registry supplied\", which is the PERMISSIVE branch. The " +
      "mutation restores the shipped normalization (anything not an array becomes `undefined`), so a " +
      "reader that handed over the registry bytes directly, or an array-LIKE object, or a Set, has " +
      "supplied governance and receives VALID_FULL_CHAIN / NOT_EVALUATED / exit 0. This is the only " +
      "route in the plane that skips the plane entirely, and it is reachable from the PUBLISHED " +
      "runtime API — TypeScript does not make malformed JavaScript calls impossible.",
    file: "packages/evidence/src/verify-evidence.ts",
    find: "      registryShapeRefusal = `enrolmentRegistries was supplied as ${typeof suppliedRegistries === \"object\" && suppliedRegistries !== null ? \"a non-array object\" : JSON.stringify(typeof suppliedRegistries)} — a registry collection this verifier cannot read as a list is REFUSED, never treated as \"no registry supplied\". Softening an unrecognised trust-input shape into the unconfigured branch would return a positive verdict for a reader that did supply governance`;",
    replace: "      optEnrolmentRegistries = undefined;",
    kind: "tests",
    suite: ["packages/evidence", "npm", ["test"]],
  },
  {
    id: "enrolment-collection-copied-by-index-not-by-iterator",
    control:
      "The registry collection is snapshotted BY INDEX through `length`, never through the caller's " +
      "iterator. On a genuine array `length` is a non-configurable data property, so there is nothing " +
      "to lie; `Symbol.iterator` is an ordinary own slot, so there is. The mutation restores the " +
      "spread, and a REAL array — one `Array.isArray` calls an array — carrying an own iterator that " +
      "yields nothing copies to `[]`: the no-registry branch and exit 0 again, through a different " +
      "door than the shape check above. Registered separately for exactly that reason.",
    file: "packages/evidence/src/verify-evidence.ts",
    find: "      for (let i = 0; i < len; i++) arrayPush(snapshot, suppliedRegistries[i] as Uint8Array | string);",
    replace: "      for (const item of [...(suppliedRegistries as unknown[])]) arrayPush(snapshot, item as Uint8Array | string);",
    kind: "tests",
    suite: ["packages/evidence", "npm", ["test"]],
  },
  {
    id: "enrolment-window-arithmetic-is-nanosecond-exact",
    control:
      "Registry windows are compared in EXACT nanoseconds, through the grammar that admitted the " +
      "document. The mutation restores millisecond `Date.parse`, which collapses a one-nanosecond " +
      "rotation boundary: two contiguous, non-overlapping, strictly-versioned registries both match " +
      "the same authorization instant, the SUCCESSOR carrying the rotated projection hash is selected " +
      "too, and an honest archived bundle is reported INVALID / E_ENROLMENT_MISMATCH for an ordinary " +
      "governance rotation. A hard rejection of good evidence produced entirely by the arithmetic — " +
      "which is why the fix reuses the parser the artifact layer already runs for key activation " +
      "rather than a second one that can drift from it.",
    file: "packages/evidence/src/enrolment.ts",
    find: "  return rfc3339Nanos(v, ctx.schemas[ENROLMENT_SPEC]);",
    replace: "  const ms = typeof v === \"string\" ? Date.parse(v) : NaN;\n  return Number.isNaN(ms) ? null : BigInt(ms) * 1000000n;",
    kind: "tests",
    suite: ["packages/evidence", "npm", ["test"]],
  },
  {
    id: "enrolment-class-selection-requires-the-action-side",
    control:
      "Only an ACTION-side handle may select a registry row for adjudication. The class is the PAIR, " +
      "the ACTION half identifies it, and the projection half is what the pair is checked AGAINST once " +
      "the row is known to be about this class. The mutation restores selection on the projection id " +
      "alone — and projection identifiers are a SHARED namespace, so a registry enrolling a genuinely " +
      "different action class that renders through the same projection becomes INVALID / " +
      "E_ENROLMENT_MISMATCH. That is an accusation aimed at a registry which merely does not mention " +
      "this class, where the honest answer is CLASS_ABSENT. The error runs in the ACCUSING direction, " +
      "which is why it gets its own arm instead of being folded into the pair check.",
    file: "packages/evidence/src/enrolment.ts",
    find: "      const candidate =\n        schema.idMatch\n",
    replace: "      const candidate =\n        schema.idMatch\n        || projection.idMatch\n",
    kind: "tests",
    suite: ["packages/evidence", "npm", ["test"]],
  },
  {
    id: "cli-numeric-flag-is-refused-not-dropped",
    control:
      "A malformed NUMERIC flag is a usage error, and the run does not continue with the option " +
      "quietly removed. Measured on a DENIED fixture: `--max-age-hours 0` exits 3 because the " +
      "freshness rule fires, while `--max-age-hours definitely-not-a-number` exited 0 — `Number()` " +
      "answered NaN, and a `Number.isFinite` guard at the call site OMITTED maxAgeMs, restoring the " +
      "permissive 24-hour default. A mistyped SAFETY option produced a positive verdict, across the " +
      "usage/verdict boundary. The mutation removes the validation so the malformed value flows " +
      "through again; the wire suite must catch it at the process boundary, which is the only place " +
      "the exit code is real.",
    file: "packages/evidence/src/cli.ts",
    find: "    if (raw.trim() === \"\" || !Number.isFinite(n)) {",
    replace: "    if (false) {",
    kind: "tests",
    suite: ["packages/evidence", "npm", ["test"]],
  },
  {
    id: "cli-singleton-flag-refuses-repetition",
    control:
      "A singleton flag given twice is a USAGE error, never last-wins. Measured: " +
      "`--audience hostile --audience good` exited 6 and `--audience good --audience hostile` exited " +
      "4, so whoever appends to the command line LAST decided the answer, silently. That is the shape " +
      "a wrapper script, a CI template or an injected argument exploits, and it applied to " +
      "`--tenant-root` as much as to `--audience`. The mutation restores last-wins.",
    file: "packages/evidence/src/cli.ts",
    find: "    if (seen.has(flag)) {",
    replace: "    if (false) {",
    kind: "tests",
    suite: ["packages/evidence", "npm", ["test"]],
  },
  {
    id: "cli-singleton-flag-requires-a-value",
    control:
      "A singleton flag with no value is a USAGE error, and the run does not continue. Measured: an " +
      "otherwise valid invocation ending in a bare `--audience` consumed `undefined`, VERIFIED ANYWAY " +
      "and exited 0 — the operator typed a flag, got a verdict, and nothing said the flag did nothing. " +
      "The same check refuses a flag whose \"value\" is the NEXT FLAG, which is how a bare flag in the " +
      "middle of a command line silently eats its successor. The mutation restores the bare read.",
    file: "packages/evidence/src/cli.ts",
    find:
      "    if (v === undefined || v.startsWith(\"--\")) {\n" +
      "      usage(`${flag} needs a value${v === undefined ? \"\" : ` (got the next flag ${v})`}`);\n" +
      "    }\n" +
      "    return v;\n",
    replace: "    return v as string;\n",
    kind: "tests",
    suite: ["packages/evidence", "npm", ["test"]],
  },
  {
    id: "enrolment-refusals-are-not-all-hard-rejections",
    control:
      "The verdict map is THREE-way. An unconfigured or unaddressed reader is UNVERIFIED — a " +
      "statement about THIS VERIFIER — while missing evidence is INCONCLUSIVE and only a " +
      "contradiction is INVALID. The mutation collapses the UNVERIFIED branch onto the INVALID " +
      "default, which is SAFE (it does not over-claim) and WRONG: it accuses cryptographically " +
      "perfect evidence of being broken because the reader's own configuration could not answer, and " +
      "an auditor who learns the verdict word lies stops reading it. This is the exact mistake an " +
      "implementer makes by adding one code to one ternary.",
    file: "packages/evidence/src/verify-evidence.ts",
    find: "        UNVERIFIED_CODES.has(failing.code ?? \"\")\n          ? \"UNVERIFIED\"",
    replace: "        false\n          ? \"UNVERIFIED\"",
    kind: "tests",
    suite: ["packages/evidence", "npm", ["test"]],
  },

  // ── CROSS-FIELD COHERENCE (2026-08-14) — A SIGNED RECEIPT MAY NOT CONTRADICT ITSELF ────────────
  //
  // Five receipts, each cryptographically PERFECT, were run through all five shipped verifiers on
  // identical bytes: 25 of 25 came back VALID. Every check in the shape validator read ONE field, so
  // a receipt could satisfy all of them and still argue both ways after the fact. Each entry below
  // removes exactly ONE of the five rules and requires the suite to notice.
  //
  // Each mutation is chosen so the file still COMPILES and the surrounding code is untouched: the
  // condition still evaluates, the message is still built — it is pushed onto a THROWAWAY array
  // instead of `errors`. That is precisely "the control ran and reported nothing", which is the
  // shape a real regression takes here (a rule quietly stops being load-bearing), and it is a
  // stronger knockout than deleting the branch, because a deleted branch also removes the evidence
  // that anyone ever intended the rule.
  {
    id: "coherence-r1-sandbox-principal-requires-sandboxed",
    control:
      "R1 — `agent.principal: \"SANDBOX_SIM\"` REQUIRES `governance.sandboxed: true`. Without it a " +
      "receipt names the SANDBOX SIMULATOR as the actor while denying it was a simulation, on a " +
      "CRITICAL wire.transfer, signed and chain-valid — and a reader can be told either story " +
      "afterwards. Decidable with NO key material, so a verifier that misses it is not being " +
      "lenient about a formality; it is publishing an unfalsifiable statement. Must red the R1 " +
      "coherence test AND the coherence-sandbox-principal conformance vector.",
    file: "src/schema.ts",
    find: "    if (principal === \"SANDBOX_SIM\" && sandboxed === false)\n      arrayPush(errors, 'receipt.governance.sandboxed: must be true when agent.principal is \"SANDBOX_SIM\"');",
    replace: "    if (principal === \"SANDBOX_SIM\" && sandboxed === false)\n      arrayPush([] as string[], 'receipt.governance.sandboxed: must be true when agent.principal is \"SANDBOX_SIM\"');",
    kind: "tests",
    suite: [".", "npm", ["test"]],
  },
  {
    id: "coherence-r2-simulated-verdict-requires-sandboxed",
    control:
      "R2 — `governance.verdict: \"SIMULATED\"` REQUIRES `governance.sandboxed: true`. The same " +
      "contradiction in the OUTCOME rather than the actor: the receipt records that nothing really " +
      "happened while the sandbox flag says it did. Must red the R2 coherence test AND the " +
      "coherence-simulated-not-sandboxed vector.",
    file: "src/schema.ts",
    find: "    if (verdict === \"SIMULATED\" && sandboxed === false)\n      arrayPush(errors, 'receipt.governance.sandboxed: must be true when governance.verdict is \"SIMULATED\"');",
    replace: "    if (verdict === \"SIMULATED\" && sandboxed === false)\n      arrayPush([] as string[], 'receipt.governance.sandboxed: must be true when governance.verdict is \"SIMULATED\"');",
    kind: "tests",
    suite: [".", "npm", ["test"]],
  },
  {
    id: "coherence-r3-irreversible-carries-no-rollbackref",
    control:
      "R3 — `action.reversible: false` REQUIRES `rollbackRef` absent or null. An action declared " +
      "impossible to undo, carrying the reference used to undo it, is a receipt that answers the " +
      "one question an incident reviewer actually asks — can this be reversed — in both directions " +
      "at once. Must red the R3 coherence test AND the coherence-irreversible-with-rollbackref " +
      "vector, while leaving the two R3 negative controls (null, and absent) GREEN.",
    file: "src/schema.ts",
    find: "    if (reversible === false && rollbackRefPresent)\n      arrayPush(errors, \"receipt.action.rollbackRef: must be absent or null when action.reversible is false\");",
    replace: "    if (reversible === false && rollbackRefPresent)\n      arrayPush([] as string[], \"receipt.action.rollbackRef: must be absent or null when action.reversible is false\");",
    kind: "tests",
    suite: [".", "npm", ["test"]],
  },
  {
    id: "coherence-r4-rolled-back-requires-reversible",
    control:
      "R4 — `governance.verdict: \"ROLLED_BACK\"` REQUIRES `action.reversible: true`. The receipt " +
      "asserts the action WAS undone while declaring it could not be. Must red the R4 coherence " +
      "test AND the coherence-rolled-back-irreversible vector, while leaving the honest rollback " +
      "(ROLLED_BACK on a reversible action) VALID.",
    file: "src/schema.ts",
    find: "    if (verdict === \"ROLLED_BACK\" && reversible === false)\n      arrayPush(errors, 'receipt.action.reversible: must be true when governance.verdict is \"ROLLED_BACK\"');",
    replace: "    if (verdict === \"ROLLED_BACK\" && reversible === false)\n      arrayPush([] as string[], 'receipt.action.reversible: must be true when governance.verdict is \"ROLLED_BACK\"');",
    kind: "tests",
    suite: [".", "npm", ["test"]],
  },
  {
    id: "coherence-r5-ts-must-denote-a-real-instant",
    control:
      "R5 — the CALENDAR layer of `isRfc3339Instant`. The lexical scanner alone accepted " +
      "`2026-13-45T99:99:99.000Z` on a signed CRITICAL receipt in all five implementations: month " +
      "13, day 45, hour 99. A `ts` that denotes no instant cannot be ordered against its " +
      "neighbours, so the chain's own non-monotonic-timestamp warning is blind to it. The mutation " +
      "widens every field bound to 99 — the exact laxness the lexical `[0-9]{2}` already had — so " +
      "the function still runs, still compiles, and decides nothing. Must red the R5 coherence " +
      "test, the scan-parity calendar oracle, AND the coherence-ts-not-an-instant vector, while " +
      "leaving the leap-second acceptance (second 60) GREEN.",
    file: "src/scan.ts",
    find: "  if (month < 1 || month > 12) return false;\n  if (day < 1 || day > daysInMonth(year, month)) return false;\n  if (num2(s, 11) > 23) return false; // time-hour\n  if (num2(s, 14) > 59) return false; // time-minute\n  if (num2(s, 17) > 60) return false; // time-second — 60 is the leap second, and it is legal",
    replace: "  if (month < 1 || month > 99) return false;\n  if (day < 1 || day > 99 || daysInMonth(year, month) < 0) return false;\n  if (num2(s, 11) > 99) return false; // time-hour\n  if (num2(s, 14) > 99) return false; // time-minute\n  if (num2(s, 17) > 99) return false; // time-second",
    kind: "tests",
    suite: [".", "npm", ["test"]],
  },
  // ── ADDED 2026-08-15: TWO-SIGNATURE ATTRIBUTION ON THE COSE ENTRY POINT (spec §6) ───────────────
  // `receiptFromCose` checked the identity manifest against the OUTER COSE kid and never verified the
  // receipt's own signature. Both verdicts were the exact reverse of the rule and both were measured
  // against the built package: a rogue-signed receipt wrapped by a key authorized for the victim
  // returned ok:true (laundering), and a correctly agent-signed receipt presented by a relay returned
  // ok:false (a legitimate presentation refused). NOTHING in the repository went red for either — the
  // COSE identity path had no knockout entry at all, which is why one line could hold two inverted
  // security verdicts through a green suite. Six entries, one per control, all measured.
  {
    id: "cose-manifest-binds-the-native-kid",
    control:
      "THE fix. The identity manifest is checked against the receipt's NATIVE sig.kid — the key that " +
      "signed it into its chain and the one agent.id makes a claim about — never against the outer " +
      "COSE kid, which names whoever emitted the envelope. The mutation restores the original line " +
      "verbatim, and it fails in BOTH directions at once, which is why the corpus needs both: an " +
      "envelope signed by a key authorized for alice launders a rogue-signed receipt into ok:true, " +
      "and a receipt genuinely signed by alice is refused because the RELAY is not one of alice's " +
      "keys. A verifier that only refuses the first can do it by refusing everything.",
    file: "src/cose/receipt-cose.ts",
    find: "    if (allowed === undefined || !arrayIncludes(allowed, nativeKid)) {",
    replace: "    if (allowed === undefined || r.kid === null || !arrayIncludes(allowed, r.kid)) {",
    kind: "tests",
    suite: [".", "npm", ["test"]],
  },
  {
    id: "cose-native-signature-is-verified",
    control:
      "Moving the manifest check onto sig.kid is worthless unless the signature under that kid is " +
      "verified: sig.kid is a field of a payload the emitter controls, so an unverified one is a " +
      "self-asserted string an attacker relabels for free. The mutation removes the Ed25519 " +
      "verification and keeps the pairing check, which is the plausible half-fix — the vector that " +
      "catches it names k-alice as its signer, pairs perfectly with the manifest, and was signed by " +
      "k-rogue.",
    file: "src/cose/receipt-cose.ts",
    find: "  if (!verifyEd25519(nativePub, signingMessage(RECEIPT_SIG_DOMAIN, hashInput), receipt.sig.value)) {",
    replace: "  if (false as boolean) {",
    kind: "tests",
    suite: [".", "npm", ["test"]],
  },
  {
    id: "cose-native-chain-hash-is-self-consistent",
    control:
      "chain.hash is EXCLUDED from the receipt's hash input, so the native signature does not pin it. " +
      "Without this check a receipt carries any chain.hash it likes while every signature verifies — " +
      "and chain.hash is what the NEXT receipt links to, so the caller is handed an attacker-chosen " +
      "successor link with an ok:true beside it. The mutation removes the re-derivation.",
    file: "src/cose/receipt-cose.ts",
    find: "  if (\"sha256:\" + sha256Hex(hashInput) !== receipt.chain.hash) {",
    replace: "  if (false as boolean) {",
    kind: "tests",
    suite: [".", "npm", ["test"]],
  },
  {
    id: "cose-unknown-native-key-is-refused",
    control:
      "A native kid absent from the keyring is a refusal, not a fallback: the envelope authenticates " +
      "its EMITTER and never the agent inside it. The mutation does not delete the check, it does the " +
      "tempting thing — falls back to the ENVELOPE's key — which is the historical shape of this bug " +
      "and still produces an ok:false, just with the wrong reason. The vector asserts the reason, so " +
      "a refusal for the wrong cause is still a detection.",
    file: "src/cose/receipt-cose.ts",
    find: "  const nativePub = keyring[nativeKid];",
    replace: "  const nativePub = keyring[nativeKid] ?? keyring[r.kid ?? \"\"];",
    kind: "tests",
    suite: [".", "npm", ["test"]],
  },
  {
    id: "cose-unprotected-outer-kid-is-not-an-identity",
    control:
      "H4, kept and repointed. An outer kid taken from the UNPROTECTED header MAY resolve a key and " +
      "MUST NOT be reported as an identity, because an unsigned label is swappable between keyring " +
      "aliases. The result therefore reports it under `kid` (what resolved the key) and leaves " +
      "`envelopeKid` null. The mutation promotes the unauthenticated kid to the identity field, which " +
      "is invisible to any assertion that only reads `ok`.",
    file: "src/cose/receipt-cose.ts",
    find: "  const envelopeKid = envelopeAuthenticated ? r.kid : null;",
    replace: "  const envelopeKid = r.kid;",
    kind: "tests",
    suite: [".", "npm", ["test"]],
  },
  {
    id: "cose-retired-native-key-is-refused",
    control:
      "The retired-key rule applies to the RECEIPT's own key, not only the envelope's. The outer " +
      "check cannot see it: a live relay key re-presenting a receipt signed by a superseded agent key " +
      "is exactly how a retired key comes back, and it is a signer-chosen timestamp with no " +
      "independent witness. The mutation removes the native-side check while leaving the outer one, " +
      "so only the enveloped P0-14 case — two DIFFERENT keys — goes red.",
    file: "src/cose/receipt-cose.ts",
    find: "  if (verification.retiredKids[nativeKid] === true) {",
    replace: "  if (false as boolean) {",
    kind: "tests",
    suite: [".", "npm", ["test"]],
  },
  // ── L12: THE OPEN-CORE PUBLISH BOUNDARY ──────────────────────────────────────────────────────
  //
  // These entries exist because a prior measurement found published boundary disclosures while the
  // predecessor control falsely passed over files that carried them. Each entry below removes ONE
  // reason the new gate can see what that one could not.
  //
  // All nine are `kind: "gate"` bound to `boundary-selftest` — the arm, which plants a canary in each
  // lane's REAL enumerated surface. A knockout that leaves the arm green IS a finding: it would mean
  // the arm is decorative, which is precisely the failure the audit found in its predecessor.
  {
    id: "l12-wt-lane-scans",
    control:
      "L12 L-WT — the working-tree lane enumerates what git says is there (tracked plus untracked-" +
      "not-ignored), not a subset the gate picked for itself. This is the base lane; if it can be " +
      "narrowed silently, every other lane's coverage claim rests on nothing. The mutation replaces " +
      "the derivation with a single hard-coded path, which is exactly the shape of the defect that " +
      "let a lint report a partial file count as if it were the whole surface.",
    file: "scripts/lint-boundary.mjs",
    find: "  const paths = [...new Set([...tracked, ...untracked])].sort();",
    replace: "  const paths = [\"package.json\"];",
    kind: "gate",
    gateId: "boundary-selftest",
    expectedGateProvenance: BOUNDARY_CANDIDATE_TIER_A_KNOCKOUT_PROVENANCE_EXPECTATION,
    expectedGateFindings: [{
      rule: "SELFTEST",
      subject: "L-WT: the canary planted in its own enumerated surface is FOUND",
    }],
    suite: [".", "node", ["scripts/lint-boundary.mjs", "--selftest", "--knockout-json"]],
  },
  {
    id: "l12-idx-reads-index",
    control:
      "L12 L-IDX — the staged lane reads content from the INDEX (`git show :<path>`), not from disk. " +
      "Without that it is a duplicate of the working-tree lane and blind to the one case it exists " +
      "for: a secret staged and then scrubbed on disk before the commit. The arm stages the canary " +
      "and then overwrites the worktree copy, so a disk read reports clean while the bytes are still " +
      "on their way out.",
    file: "scripts/lint-boundary.mjs",
    find: "    const r = capture(\"git\", [\"show\", `:${p}`], { cwd: ctx.root, encoding: \"buffer\", tolerate: true });",
    replace: "    const r = { code: 0, out: readFileSync(join(ctx.root, p)) };",
    kind: "gate",
    gateId: "boundary-selftest",
    expectedGateProvenance: BOUNDARY_CANDIDATE_TIER_A_KNOCKOUT_PROVENANCE_EXPECTATION,
    expectedGateFindings: [{
      rule: "SELFTEST",
      subject: "L-IDX: the canary planted in its own enumerated surface is FOUND",
    }],
    suite: [".", "node", ["scripts/lint-boundary.mjs", "--selftest", "--knockout-json"]],
  },
  {
    id: "l12-msg-range-is-full",
    control:
      "L12 L-MSG/L-PUSH/L-TAG — a range means every commit it adds, not its tip. A verified prior " +
      "incident placed a confidential label in a non-tip commit message beneath later commits. A " +
      "tip-only reading therefore scored that history as clean. The mutation reduces " +
      "the shared range derivation to `rev-list -1`; the arm plants its canary in a non-tip commit " +
      "message with a later commit stacked on top, so the difference is observable.",
    file: "scripts/lint-boundary.mjs",
    find: "    args = [\"rev-list\", descriptor.range];",
    replace: "    args = [\"rev-list\", \"-1\", descriptor.range];",
    kind: "gate",
    gateId: "boundary-selftest",
    expectedGateProvenance: BOUNDARY_CANDIDATE_TIER_A_KNOCKOUT_PROVENANCE_EXPECTATION,
    expectedGateFindings: [{
      rule: "SELFTEST",
      subject: "L-MSG: the canary planted in its own enumerated surface is FOUND",
    }],
    suite: [".", "node", ["scripts/lint-boundary.mjs", "--selftest", "--knockout-json"]],
  },
  {
    id: "l12-pack-scans-every-exact-tarball-entry",
    control:
      "L12 L-PACK — every entry emitted by the lifecycle-free exact tarball builder is scanned, never " +
      "a guessed subset. The neighbouring surface lint recorded false greens when published bytes " +
      "fell outside its guessed directory. The mutation filters README.md from the exact entry stream, " +
      "and the arm plants its canary in that shipped root-level document.",
    file: "scripts/lint-boundary.mjs",
    find: "function lanePACK(ctx) {\n  const units = [];\n  for (const set of ctx.packed) {\n    for (const entry of set.entries) {",
    replace: "function lanePACK(ctx) {\n  const units = [];\n  for (const set of ctx.packed) {\n    for (const entry of set.entries.filter(({ path }) => path !== \"README.md\")) {",
    kind: "gate",
    gateId: "boundary-selftest",
    expectedGateProvenance: BOUNDARY_CANDIDATE_TIER_A_KNOCKOUT_PROVENANCE_EXPECTATION,
    expectedGateFindings: [{
      rule: "SELFTEST",
      subject: "L-PACK: the canary planted in its own enumerated surface is FOUND",
    }],
    suite: [".", "node", ["scripts/lint-boundary.mjs", "--selftest", "--knockout-json"]],
  },
  {
    id: "l12-pack-derivation-is-lifecycle-free",
    control:
      "L12 L-PACK — scope and bytes come from the one lifecycle-free npm-packlist/tar " +
      "implementation's actual, safely parsed tgz. `npm pack --dry-run --json --ignore-scripts` " +
      "is not an enumerator because prepare may still execute. The mutation restores that unsafe " +
      "path and reads its listed files from disk; the arm's prepare sentinel must expose the attempt.",
    file: "scripts/lint-boundary.mjs",
    find: "        packed = packFrozenPackageArtifact({ commitTime: 0, output, packagePath: dir, source });",
    replace:
      "        packed = (() => {\n" +
      "          const cwd = dir === \".\" ? source : join(source, ...dir.split(\"/\"));\n" +
      "          const raw = capture(\"npm\", [\"pack\", \"--dry-run\", \"--json\", \"--ignore-scripts\"], { cwd }).out;\n" +
      "          const files = JSON.parse(raw)[0].files.map((entry) => entry.path);\n" +
      "          const entries = files.map((path) => { const content = readFileSync(join(cwd, path)); return { content, mode: 0o644, path, sha256: \"\", size: content.length }; });\n" +
      "          return { entries, releaseAuthorized: false, status: \"CANDIDATE / NON-RELEASE\", tarball: { packlistCount: entries.length } };\n" +
      "        })();",
    kind: "gate",
    gateId: "boundary-selftest",
    expectedGateProvenance: BOUNDARY_CANDIDATE_TIER_A_KNOCKOUT_PROVENANCE_EXPECTATION,
    expectedGateFindings: [{
      rule: "SELFTEST",
      subject: "L-PACK never executes or attempts a package lifecycle script",
    }],
    suite: [".", "node", ["scripts/lint-boundary.mjs", "--selftest", "--knockout-json"]],
  },
  {
    id: "l12-map-sources-scanned",
    control:
      "L12 L-MAP — `sourcesContent[]` is the ORIGINAL SOURCE, verbatim, inside the tarball, so it is " +
      "scanned with the full rule set rather than treated as opaque map data. Measured today: zero " +
      "sourcemaps are packed, which is exactly why this must be load-bearing BEFORE `sourceMap` or " +
      "`declarationMap` is switched on — the day it is, nobody will think to look. The mutation " +
      "returns the map's structural findings but discards its embedded source.",
    file: "scripts/lib/boundary-scan.mjs",
    find: "  const contents = Array.isArray(map?.sourcesContent)\n    ? map.sourcesContent.filter((c) => typeof c === \"string\")\n    : [];",
    replace: "  const contents = [];",
    kind: "gate",
    gateId: "boundary-selftest",
    expectedGateProvenance: BOUNDARY_CANDIDATE_TIER_A_KNOCKOUT_PROVENANCE_EXPECTATION,
    expectedGateFindings: [{
      rule: "SELFTEST",
      subject: "L-MAP: the canary planted in its own enumerated surface is FOUND",
    }],
    suite: [".", "node", ["scripts/lint-boundary.mjs", "--selftest", "--knockout-json"]],
  },
  {
    // THE MOST IMPORTANT ENTRY IN THIS BLOCK. Everything else measures coverage; this measures
    // whether "could not run" and "passed" can ever share an exit code. A commitments file that
    // EXISTS but carries nothing is the dangerous shape: the run still prints a scan count, still
    // prints a lane table, and measures no exact token at all.
    id: "l12-missing-commitments-fails-closed",
    control:
      "L12 fail-closed — an unmeasurable token tier is exit 2, never a quiet tier-A-only pass. " +
      "Missing commitments, a zero digest count, a count that disagrees with the array, or a key " +
      "whose fingerprint does not match the committed keyId all refuse. The mutation makes the " +
      "zero-count branch unreachable, so a commitments file with no digests would scan every file, " +
      "match nothing, and report GREEN — a control printing green over an unmeasured class, which is " +
      "the exact defect this whole gate was built after.",
    file: "scripts/lint-boundary.mjs",
    find: "doc.digests.length === 0",
    replace: "false",
    kind: "gate",
    gateId: "boundary-selftest",
    expectedGateProvenance: BOUNDARY_CANDIDATE_TIER_A_KNOCKOUT_PROVENANCE_EXPECTATION,
    expectedGateFindings: [{
      rule: "SELFTEST",
      subject: "fail-closed: the commitments file carries zero digests exits 2",
    }],
    suite: [".", "node", ["scripts/lint-boundary.mjs", "--selftest", "--knockout-json"]],
  },
  {
    id: "l12-token-compare-real",
    control:
      "L12 tier B — the candidate digest is really compared against the committed set under the key. " +
      "A lookup that always answers false leaves every lane enumerating correctly, every file read, " +
      "every count printed, and every exact confidential label passed through. Nothing in the output " +
      "would look different; the arm's canary is the only thing that can tell the two apart.",
    file: "scripts/lint-boundary.mjs",
    find: "      hit = set.has(commitToken(key, candidate));",
    replace: "      hit = false;",
    kind: "gate",
    gateId: "boundary-selftest",
    expectedGateProvenance: BOUNDARY_CANDIDATE_TIER_A_KNOCKOUT_PROVENANCE_EXPECTATION,
    expectedGateFindings: [{
      rule: "SELFTEST",
      subject: "L-WT: the canary planted in its own enumerated surface is FOUND",
    }],
    suite: [".", "node", ["scripts/lint-boundary.mjs", "--selftest", "--knockout-json"]],
  },
  {
    id: "l12-repo-allowlist-inversion",
    control:
      "L12 the INVERSION — a repository reference is a finding unless the forge lists it as PUBLIC. " +
      "The alternative, a denylist of the repositories that must not be named, would BE the " +
      "disclosure and would always be one repository behind reality. The mutation replaces the " +
      "allowlist test with an empty-denylist test: structurally identical code, and it flags nothing " +
      "for ever. The arm plants an org-qualified reference the forge does not list.",
    file: "scripts/lib/boundary-scan.mjs",
    find: "      if (known.has(repo)) continue;",
    replace: "      if (![].includes(repo)) continue;",
    kind: "gate",
    gateId: "boundary-selftest",
    expectedGateProvenance: BOUNDARY_CANDIDATE_TIER_A_KNOCKOUT_PROVENANCE_EXPECTATION,
    expectedGateFindings: [{
      rule: "SELFTEST",
      subject: "shape repo-not-public: planted in the working tree and named by the gate",
    }],
    suite: [".", "node", ["scripts/lint-boundary.mjs", "--selftest", "--knockout-json"]],
  },
  {
    id: "l12-known-exposure-cannot-grow",
    control:
      "L12 the ratchet — a finding with no reviewed ledger entry BLOCKS. The ledger exists so the gate " +
      "can be switched on over an already-dirty history without printing green over a real finding; " +
      "it stops being that the moment it can absorb a new key on its own. This repository has already " +
      "paid for a baseline that wrote its own new number: a forbidden construct went red on an " +
      "authorisation path and the repository's own command then raised the floor and turned it green. " +
      "The mutation lets an unknown key be carried silently.",
    file: "scripts/lint-boundary.mjs",
    find: "    if (entry === undefined) { blocking.push(...group); continue; }",
    replace: "    if (entry === undefined) { carried.push({ key, entry: { count: group.length, why: \"auto\", remediation: \"auto\" }, group }); continue; }",
    kind: "gate",
    gateId: "boundary-selftest",
    expectedGateProvenance: BOUNDARY_CANDIDATE_TIER_A_KNOCKOUT_PROVENANCE_EXPECTATION,
    expectedGateFindings: [{
      rule: "SELFTEST",
      subject: "ratchet: a finding with no ledger entry BLOCKS",
    }],
    suite: [".", "node", ["scripts/lint-boundary.mjs", "--selftest", "--knockout-json"]],
  },
];

/**
 * Read-only candidate-local registry surface for disposable workers. The supervisor sends only
 * the canonical registry digest and selected entry bytes; every retained arm imports this captured
 * module and checks those values against the same candidate-local registry.
 */
export function knockoutRegistrySnapshot() {
  validateKnockoutRegistry(KNOCKOUTS);
  for (const entry of KNOCKOUTS) {
    for (const id of proofIdsFor(entry)) {
      if (!PROOF_INVENTORY[id]) {
        throw new Error(
          `invalid knockout entry ${JSON.stringify(entry.id)}: unknown proof id ${JSON.stringify(id)}`,
        );
      }
    }
  }
  return Object.freeze({ proofInventory: PROOF_INVENTORY, registry: KNOCKOUTS });
}

if (DIRECT_ENTRY) {
  try {
    assertBoundaryCustodyAuthority();
    knockoutRegistrySnapshot();
  } catch (error) {
    console.error(
      `knockout registry boundary refused before measurement: ${String(error && error.message)}`,
    );
    process.exit(1);
  }

  // The closed-kind fixture mutates only an in-memory entry and must refuse before capture.
  const REGISTRY_TO_VALIDATE = KIND_SCHEMA_SELFTEST
    ? [{ ...KNOCKOUTS[0], id: "__selftest_unknown_kind__", kind: "future-kind" }, ...KNOCKOUTS]
    : KNOCKOUTS;
  try {
    validateKnockoutRegistry(REGISTRY_TO_VALIDATE);
  } catch (error) {
    console.error(`knockout registry refused before measurement: ${String(error && error.message)}`);
    process.exit(1);
  }
  if (KIND_SCHEMA_SELFTEST) {
    console.error("knockout registry selftest failure: unknown kind was accepted before measurement");
    process.exit(2);
  }

  // The public registry is source-only and self-contained. External dependency selectors and
  // descriptors are rejected above, before candidate capture or any suite execution.
  const RUNNABLE = KNOCKOUTS;

  if (CLI_ARGS.includes("--print-suite-packages")) {
    const dirs = new Set();
    for (const entry of RUNNABLE) {
      const dir = entry.suite?.[0];
      if (typeof dir === "string" && dir !== ".") dirs.add(dir);
    }
    for (const dir of localPackageDependencyOrder(ROOT, [...dirs])) console.log(dir);
    process.exit(0);
  }

  const selected = ONLY
    ? RUNNABLE.filter((entry) => entry.id === ONLY)
    : SHARD
      ? partitionIntoShards(RUNNABLE, SHARD.index, SHARD.total)
      : RUNNABLE;

  if (SHARD && selected.length === 0) {
    console.error(
      `--shard ${SHARD.index}/${SHARD.total}: 0 runnable entries in this slice ` +
      `(${RUNNABLE.length} registry entries). ` +
      "The experiment did not happen; refusing to report a pass.",
    );
    process.exit(1);
  }
  if (ONLY && selected.length === 0) {
    console.error(
      `NOTHING_SELECTED: --only ${ONLY} does not name a registered knockout`,
    );
    process.exit(1);
  }
  if (selected.length === 0) {
    console.error("NOTHING_SELECTED: the public registry contains no runnable entries");
    process.exit(1);
  }

  const rawDependenciesByEntry = new Map(
    selected.map((entry) => [entry.id, Object.freeze({})]),
  );
  const candidateSubject = selected.some((entry) => entry.expectedGateProvenance !== undefined)
    ? deriveBoundaryKnockoutCandidateSubject(ROOT)
    : null;
  const shardLabel = SHARD ? `shard ${SHARD.index}/${SHARD.total} ` : "";
  let sweep = null;
  try {
    sweep = await runIsolatedKnockoutSweep({
      captureTimeoutMs: ISOLATED_KNOCKOUT_SWEEP_TIMEOUTS.captureTimeoutMs,
      maxRetainedArms: KNOCKOUT_WORKSPACE_ARM_LIMITS.maxRetainedArms,
      maxRetainedBytes: KNOCKOUT_WORKSPACE_ARM_LIMITS.maxRetainedBytes,
      onProgress: ({ completed, id, total, verdict }) => {
        process.stdout.write(`  progress ${shardLabel}${completed}/${total} ${verdict} ${id}\n`);
      },
      rawDependenciesByEntry,
      registry: KNOCKOUTS,
      root: ROOT,
      selected,
      candidateSubject,
      suiteTimeoutMs: ISOLATED_KNOCKOUT_SWEEP_TIMEOUTS.suiteTimeoutMs,
      workerTimeoutMs: ISOLATED_KNOCKOUT_SWEEP_TIMEOUTS.workerTimeoutMs,
    });
  } catch (error) {
    const code = typeof error?.code === "string" ? error.code : "ISOLATED_SWEEP_FAILED";
    console.error(`\n${code}: ${String(error?.message ?? error)}`);
    if (typeof error?.details?.custodyRoot === "string") {
      console.error(`  retained custody: ${error.details.custodyRoot}`);
    }
    process.exitCode = 1;
  }

  if (sweep !== null) {
    const { baselines, results } = sweep;
    const infrastructureErrors = [];
    if (
      sweep.status !== "COMPLETE" || sweep.selftest === null ||
      sweep.closeEvidence?.status !== "RELEASED" ||
      sweep.closeEvidence?.helperReaped !== true ||
      sweep.closeEvidence?.sourceRelease?.status !== "RELEASED"
    ) {
      infrastructureErrors.push(
        "  ISOLATED CLOSE INCOMPLETE  the supervisor returned without exact selftest/source/lease close evidence",
      );
    }
    if (results.length !== selected.length) {
      infrastructureErrors.push(
        `  RESULT CARDINALITY         received ${results.length}/${selected.length} selected verdicts`,
      );
    }

    console.log(`L4 control knockout: ${results.length} controls\n`);
    console.log(
      `  evidence candidate: ${sweep.candidateManifestSha256}\n` +
      `  source snapshot:    ${sweep.sourceSnapshotSha256}\n` +
      `  selftest terminal:  ${sweep.selftest?.terminalSha256 ?? "MISSING"}\n` +
      `  retained custody:   ${sweep.custodyRoot}`,
    );
    console.log("  suite baselines (one fresh retained arm per unique clean suite):");
    for (const baseline of baselines) {
      const summary = baselineEvidenceSummary(baseline.kind, baseline.observation);
      console.log(
        `    ${baseline.suite[0].padEnd(28)} exit ` +
        `${String(baseline.observation.exit).padEnd(4)} ${summary.count} ${summary.label}`,
      );
      for (const detail of summary.details) console.log(`      already present: ${detail}`);
    }
    console.log();

    for (const result of results) {
      const mark = PASSING.has(result.verdict) ? "ok      " : "FINDING ";
      console.log(
        `  ${mark} ${String(result.verdict).padEnd(28)} ` +
        `${result.id.padEnd(34)} ${result.control}`,
      );
      if (result.detail) console.log(`           ${result.detail}`);
    }

    const passed = results.filter((result) => PASSING.has(result.verdict));
    console.log(`\nproven load-bearing ${passed.length}/${results.length}`);
    console.log(
      `retained evidence arms: selftest 1, baselines ${baselines.length}, ` +
      `mutants ${sweep.mutants.length}, postchecks ${sweep.postchecks.length}`,
    );

    if (infrastructureErrors.length > 0) {
      console.error(`\n${infrastructureErrors.length} infrastructure failure(s):`);
      for (const error of infrastructureErrors) console.error(error);
      process.exitCode = 1;
    }

    const findings = results.filter((result) => !PASSING.has(result.verdict));
    if (findings.length > 0) {
      console.error(`\n${findings.length} completed knockout finding(s):`);
      for (const result of findings) {
        console.error(
          `  ${result.verdict.padEnd(26)} ${result.id} — ${result.detail || "(no detail)"}`,
        );
      }
      if (WARN_ONLY) {
        console.error("(--warn: completed semantic findings reported, not blocking)");
      } else {
        process.exitCode = 1;
      }
    }
  }
}
