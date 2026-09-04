/**
 * Closed TypeScript source loader for contained knockout tests.
 *
 * This is deliberately not a general-purpose package resolver. It transpiles regular `.ts` files
 * only inside the public repository and maps a missing relative `.js` import only to its same-path
 * `.ts` source. Everything else remains Node's decision through `nextResolve`/`nextLoad`.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import ts from "typescript";

const PUBLIC_ROOT = fs.realpathSync(path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../.."));
const SOURCE_EXTENSION = new Map([
  [".js", ".ts"],
  [".mjs", ".mts"],
  [".cjs", ".cts"],
  [".jsx", ".tsx"],
]);

function pathIsInside(candidate, parent) {
  const relative = path.relative(parent, candidate);
  return relative === "" || (relative !== ".." && !relative.startsWith(`..${path.sep}`));
}

function sourceBoundary(candidate) {
  if (pathIsInside(candidate, PUBLIC_ROOT)) return PUBLIC_ROOT;
  throw new Error(`TypeScript evidence source is outside the public repository: ${candidate}`);
}

function exactSourceUrl(candidate) {
  const absolute = path.resolve(candidate);
  const boundary = sourceBoundary(absolute);
  const stat = fs.lstatSync(absolute);
  if (stat.isSymbolicLink() || !stat.isFile()) {
    throw new Error(`TypeScript evidence source is not a regular file: ${absolute}`);
  }
  const canonical = fs.realpathSync(absolute);
  if (!pathIsInside(canonical, boundary)) {
    throw new Error(`TypeScript evidence source resolves outside its attested root: ${absolute}`);
  }
  return pathToFileURL(canonical).href;
}

function missingRelativeSource(specifier, parentURL) {
  if (
    typeof parentURL !== "string" || !parentURL.startsWith("file:") ||
    (!specifier.startsWith("./") && !specifier.startsWith("../"))
  ) return null;
  const extension = path.extname(specifier);
  const sourceExtension = SOURCE_EXTENSION.get(extension);
  if (sourceExtension === undefined) return null;
  const requested = fileURLToPath(new URL(specifier, parentURL));
  try {
    fs.lstatSync(requested);
    return null;
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  const candidate = requested.slice(0, -extension.length) + sourceExtension;
  try {
    return exactSourceUrl(candidate);
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
}

export function resolve(specifier, context, nextResolve) {
  const mapped = missingRelativeSource(specifier, context.parentURL);
  if (mapped !== null) return { url: mapped, shortCircuit: true };
  return nextResolve(specifier, context);
}

export function load(url, context, nextLoad) {
  if (!url.startsWith("file:")) return nextLoad(url, context);
  const file = fileURLToPath(url);
  if (file.endsWith(".json")) {
    exactSourceUrl(file);
    const value = JSON.parse(fs.readFileSync(file, "utf8"));
    return {
      format: "module",
      source: `export default ${JSON.stringify(value)};\n`,
      shortCircuit: true,
    };
  }
  if (!/[.]([cm]?ts|tsx)$/.test(file)) return nextLoad(url, context);
  exactSourceUrl(file);
  const source = fs.readFileSync(file, "utf8");
  const result = ts.transpileModule(source, {
    fileName: file,
    reportDiagnostics: true,
    compilerOptions: {
      target: ts.ScriptTarget.ES2022,
      module: ts.ModuleKind.ESNext,
      moduleResolution: ts.ModuleResolutionKind.Bundler,
      isolatedModules: true,
      verbatimModuleSyntax: false,
      inlineSourceMap: true,
      inlineSources: true,
    },
  });
  const errors = (result.diagnostics ?? []).filter(
    (diagnostic) => diagnostic.category === ts.DiagnosticCategory.Error,
  );
  if (errors.length > 0) {
    throw new Error(ts.formatDiagnostics(errors, {
      getCanonicalFileName: (name) => name,
      getCurrentDirectory: () => PUBLIC_ROOT,
      getNewLine: () => "\n",
    }));
  }
  return { format: "module", source: result.outputText, shortCircuit: true };
}
