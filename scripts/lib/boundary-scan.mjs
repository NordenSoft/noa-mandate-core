/**
 * boundary-scan.mjs — the PURE scanners behind L12, the open-core boundary gate.
 *
 * Apache-2.0, part of noa-receipt. Node >=20 with the repository's pinned TypeScript parser.
 *
 * ─── WHY PURE ────────────────────────────────────────────────────────────────────────────────────
 *
 * Every function here takes text and returns findings. No fs, no child_process, no network. That is
 * not tidiness: it is what lets `lint-boundary.mjs --selftest` drive the SAME functions the gate
 * runs, in process, with fixtures in both directions. The neighbouring surface lint learned this the
 * expensive way — a violation planted in a file the gate never enumerated produced ZERO findings and
 * read as "the gate is clean", twice, on a control being introduced as coverage.
 *
 * ─── WHY TWO PATTERNS CARRY A ONE-CHARACTER CLASS IN THE MIDDLE OF A WORD ────────────────────────
 *
 * A pattern table that describes forbidden shapes is written IN those shapes. The obvious fix — let
 * the scanner skip its own source file — is the exact defect this repository has already paid for:
 * a control that defines its own scope has no scope. So the rules file is scanned like every other
 * file, and the two patterns that would otherwise match themselves are written with a one-character
 * class (`[l]`) that is regex-identical and text-distinct. No file is exempt.
 *
 * ─── THE THREE TIERS, AND THE LIMIT SAID OUT LOUD ────────────────────────────────────────────────
 *
 *   TIER A — SHAPES. Forms anyone could guess: absolute home paths, planning-directory names,
 *     infrastructure identifiers, database URLs, live host:port pairs, RFC4122 UUIDs in prose.
 *     Safe to publish because they describe a FORM, never an instance.
 *
 *   TIER A INVERSION — the most important rule in the file. Repository references are matched
 *     against an allowlist of PUBLIC repositories, which is public information and therefore
 *     harmless to commit. Anything not on that list is a finding. Allowlist the public; never
 *     denylist the private. A denylist would BE the disclosure, and it is always one repository
 *     behind reality; the inversion discloses nothing and is complete by construction.
 *
 *   TIER B — TOKEN COMMITMENTS. Exact labels with no public counterpart are matched by HMAC digest
 *     against a key that lives outside this repository. The committed file holds digests only, so
 *     the forbidden list is not itself a wordlist. See `scanTokens`.
 *
 * WHAT THIS CANNOT DO, in the house's own voice, because an over-claimed gate is the defect being
 * fixed here: Tier A is shapes and Tier B is exact tokens. Prose that DESCRIBES a confidential
 * programme without naming it passes both. This makes an accidental leak near-certainly detected;
 * it does not adjudicate meaning, and a lint claiming to would be the overclaim this repository
 * deletes on sight.
 */

import { createHash } from "node:crypto";
import { posix } from "node:path";
import { loadTrustedTypeScript } from "./boundary-bootstrap.mjs";
import {
  collapseDigits,
  commitToken,
  extractCandidates,
  reachableTokenForms,
  tokenForms,
  tokenNgramSize,
} from "./boundary-token.mjs";

export {
  collapseDigits,
  commitToken,
  extractCandidates,
  reachableTokenForms,
  tokenForms,
  tokenNgramSize,
} from "./boundary-token.mjs";

// No parser byte executes until the stdlib-only bootstrap has verified the exact reviewed control
// manifest, candidate subject, lock resolution, runtime attestation, and runtime file identity. An
// external sanitized authorization is mandatory for privileged routes. The entry point may instead
// arm one keyless snapshot Tier-A load whose frozen authority class is explicitly NON-AUTHORITY.
// The bootstrap executes the already-verified parser bytes from memory, closing the verify/open gap.
const { authority: boundaryScannerAuthority, typescript: ts } = await loadTrustedTypeScript();
export { boundaryScannerAuthority };

export const SEVERITY = Object.freeze({ CRITICAL: "critical", HIGH: "high", MEDIUM: "medium" });

/**
 * A CRITICAL finding may never be silenced by an inline suppression comment. It can only be carried
 * by the reviewed, dated known-exposure ledger, which prints on every run. Shapes may be suppressed
 * inline because a shape can be wrong about a line; an infrastructure identifier cannot.
 */
export const INLINE_SUPPRESSIBLE = Object.freeze(new Set([SEVERITY.HIGH, SEVERITY.MEDIUM]));

const digest8 = (text) => createHash("sha256").update(text, "utf8").digest("hex").slice(0, 8);
export const contentKey = (text) => createHash("sha256").update(text, "utf8").digest("hex");
export const pathContentKey = (path) => contentKey(`noa-boundary:path:v1\0${String(path)}`);

/** Redaction is constant by construction: prefixes and suffixes are still confidential plaintext. */
export function mask(_text) {
  return "<redacted>";
}

const ALLOWED_DATABASE_PROTOCOLS = new Set([
  "postgres:", "postgresql:", "mysql:", "mongodb:", "mongodb+srv:", "redis:", "amqp:", "amqps:",
]);

const RESERVED_AUTHORITY_HOSTS = Object.freeze([
  "example.com", "example.org", "example.net", "github.com", "registry.npmjs.org",
]);

function normaliseAuthorityHost(hostname) {
  return String(hostname).toLowerCase().replace(/\.$/, "");
}

function authorityHostIsReserved(hostname, { variables = false } = {}) {
  const host = normaliseAuthorityHost(hostname);
  if (variables && (/^\$\{[a-z_][a-z0-9_]*\}$/i.test(host) || /^\$[a-z_][a-z0-9_]*$/i.test(host))) return true;
  if (["localhost", "127.0.0.1", "0.0.0.0", "[::1]"].includes(host)) return true;
  if (host.endsWith(".localhost") || host.endsWith(".invalid") || host.endsWith(".test") || host.endsWith(".local")) return true;
  return RESERVED_AUTHORITY_HOSTS.some((reserved) => host === reserved || host.endsWith(`.${reserved}`));
}

function databaseAuthorityIsReserved(value) {
  let parsed;
  try { parsed = new URL(value); } catch { return false; }
  if (!ALLOWED_DATABASE_PROTOCOLS.has(parsed.protocol.toLowerCase())) return false;
  return authorityHostIsReserved(parsed.hostname, { variables: true });
}

function hostPortAuthorityIsReserved(value) {
  const match = /^([A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+):(\d{4,5})$/.exec(String(value));
  if (match === null) return false;
  const port = Number(match[2]);
  return port <= 65_535 && authorityHostIsReserved(match[1]);
}

/**
 * A source line-range citation can contain the same source-name-plus-line-number byte shape as a
 * two-label endpoint.  The exception is therefore bound to the COMPLETE citation grammar, not to a
 * source suffix or the apparent port number: paired single-backtick inline code, at least two
 * repository-relative
 * path segments, a JavaScript/TypeScript source suffix, and an ordered line range.  A standalone
 * host, URL authority, userinfo authority, fenced block, or path without a closing range remains an
 * endpoint finding.  This function receives the original physical/derived line and exact match
 * offset so an attacker cannot manufacture the exception by changing only the matched substring.
 */
function sourceLineRangeCitationIsNonEndpoint(line, index, matched) {
  const source = String(line);
  if (!Number.isInteger(index) || index < 0 || index + matched.length > source.length) return false;

  const before = source.slice(0, index);
  const opening = before.lastIndexOf("`");
  if (opening < 0 || (opening > 0 && source[opening - 1] === "`")) return false;

  const after = source.slice(index + matched.length);
  const closing = /^-(\d{1,7})(`)(?!`)/.exec(after);
  if (closing === null) return false;

  const citation = `${source.slice(opening + 1, index)}${matched}-${closing[1]}`;
  const shape = /^(?:[A-Za-z0-9._-]+\/){2,}[A-Za-z0-9._-]+\.(?:[cm]?[jt]s|[jt]sx):(\d{4,5})-(\d{1,7})$/i.exec(citation);
  if (shape === null) return false;

  const firstLine = Number(shape[1]);
  const lastLine = Number(shape[2]);
  return firstLine > 0 && lastLine >= firstLine;
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// TIER A — shape rules
// ─────────────────────────────────────────────────────────────────────────────────────────────────

/**
 * `allow` is a WHITELIST OF THE MATCH ITSELF, never of the file. A rule may say "this instance is a
 * documented placeholder"; no rule may say "this file is out of scope".
 */
export const SHAPE_RULES = Object.freeze([
  {
    id: "home-path",
    severity: SEVERITY.CRITICAL,
    redact: true,
    why: "an absolute home path publishes the operator's account name and local machine layout",
    fix: "quote the path relative to the repository root, or write it as ~/… with the account name removed",
    re: /(?:\/Users\/|\/home\/|[A-Za-z]:\\Users\\)[A-Za-z0-9._-]{2,}[/\\]/gi,
    allow: /(?:\/Users\/|\/home\/|Users\\)(?:runner|user|username|example|ci|node|app|root|USER)[/\\]/i,
  },
  {
    id: "planning-dir",
    severity: SEVERITY.CRITICAL,
    redact: false,
    why: "the confidential planning directory is quoted, which tells a reader where the unpublished material lives",
    fix: "cite the public document that carries the decision, or delete the pointer",
    re: /(?<![A-Za-z0-9_-])\.plan[/\\]/g,
    allow: null,
  },
  {
    // Written `\.c[l]aude` on purpose — see the header. Regex-identical, text-distinct.
    id: "agent-doctrine-dir",
    severity: SEVERITY.HIGH,
    redact: false,
    why: "the agent-doctrine directory name discloses the operator's private toolchain layout",
    fix: "name the artefact, not the directory it happens to live in on one machine",
    re: /(?<![A-Za-z0-9_.-])\.c[l]aude(?![A-Za-z0-9_-])/g,
    allow: null,
  },
  {
    id: "worktree-dir",
    severity: SEVERITY.MEDIUM,
    redact: true,
    why: "a private worktree root discloses the local branch topology of unpublished work",
    fix: "reference the branch, not the checkout directory",
    re: /(?<![A-Za-z0-9_-])[a-z][a-z0-9]*-worktrees[/\\]/gi,
    allow: null,
  },
  {
    id: "infra-vendor-host",
    severity: SEVERITY.CRITICAL,
    redact: true,
    why: "a hosting-provider hostname or environment variable identifies the operator's live deployment",
    fix: "delete it; deployment topology has no place in a public repository",
    re: /(?<![A-Za-z0-9_-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)*(?:railway\.app|rlwy\.net)(?![A-Za-z0-9_.-])|(?<![A-Za-z0-9_])RAILWAY_[A-Z][A-Z0-9_]*(?![A-Za-z0-9_])/gi,
    allow: null,
  },
  {
    id: "infra-account-id",
    severity: SEVERITY.CRITICAL,
    redact: true,
    why: "a numbered account identifier bound to a region is a real tenant, not an example",
    fix: "use the reserved synthetic namespace (acct-example-1)",
    re: /(?<![A-Za-z0-9-])acct-\d{3,}-[a-z]{2}-[a-z]+-\d(?![A-Za-z0-9-])/g,
    allow: null,
  },
  {
    id: "infra-db-url",
    severity: SEVERITY.CRITICAL,
    redact: true,
    why: "a database connection URL names a reachable service",
    fix: "delete it; use a placeholder host from the reserved namespace if an example is needed",
    re: /(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?):\/\/(?:\[[^\]\s"'`<>()]+\]|[^\s"'`<>()\[\]])+/gi,
    allow: null,
    allowMatch: databaseAuthorityIsReserved,
  },
  {
    id: "infra-host-port",
    severity: SEVERITY.HIGH,
    redact: true,
    why: "a dotted hostname with a port is an endpoint someone can dial",
    fix: "delete it, or replace the host with one from the reserved namespace",
    re: /(?<![A-Za-z0-9._-])(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}:\d{4,5}(?![0-9])/gi,
    allow: null,
    allowMatch: hostPortAuthorityIsReserved,
    allowContext: sourceLineRangeCitationIsNonEndpoint,
  },
  {
    id: "uuid",
    severity: SEVERITY.HIGH,
    redact: true,
    why: "an RFC4122 UUID in prose is almost always a real resource, session or tenant identifier",
    fix: "delete it, or replace it with an all-zero example UUID",
    re: /(?<![A-Za-z0-9-])[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}(?![A-Za-z0-9-])/gi,
    allow: /^0{8}-0{4}-[1-8]0{3}-[89ab]0{3}-0{12}$/i,
  },
  {
    id: "fixture-account-shape",
    severity: SEVERITY.HIGH,
    redact: true,
    scope: /^conformance[/\\]/,
    why: "a conformance vector must draw identifiers from the declared synthetic namespace; a numbered account publishes the SHAPE of a real deployment even under a different number",
    fix: "regenerate the vector with acct-example-N from the generator's reserved namespace",
    re: /(?<![A-Za-z0-9-])acct-\d[A-Za-z0-9-]*/g,
    allow: null,
  },
]);

/**
 * Absolute paths that survive into a BUILD ARTEFACT are a distinct class: nobody reads them, they
 * ship to every installer, and they appear the day a compiler flag changes.
 *
 * SCOPE, narrowed after measuring: an ARTEFACT is a declaration file, a sourcemap, or anything under
 * a `dist/` directory. The first draft said "any .js/.mjs", which flagged 17 lines of ordinary
 * SOURCE — badge URLs, a system volume path in the test runner, example invoice URIs in a vector
 * generator. None was a disclosure, and a rule that cries on source is how a gate gets switched off.
 *
 * The lookbehind excludes `:` and `/` so a URL's own path is not read as a filesystem path — the
 * first draft flagged `https://github.com/...` as an absolute path, which is both wrong and exactly
 * the kind of noise the false-positive section warns about.
 */
const ARTEFACT_ABS_PATH_RE = /(?<![A-Za-z0-9._~:/-])\/(?!usr\/|tmp\/|opt\/|etc\/|var\/|bin\/|sbin\/|dev\/|proc\/|sys\/|lib\/|System\/|Library\/|Applications\/|private\/tmp\/)(?:[A-Za-z0-9._-]+\/){2,}[A-Za-z0-9._-]+/g;
const IS_ARTEFACT_RE = /(?:^|\/)dist\//;
export const isDeclarationArtifactPath = (file) => /\.d\.(?:ts|mts|cts)$/i.test(String(file));

const SUPPRESSION_RE = /noa-boundary-ok:([0-9a-f]{8}):([^\s*/]+)/g;
const JS_SOURCE_RE = /\.(?:[cm]?[jt]s|[jt]sx)$/i;
const JSON_SOURCE_RE = /\.json$/i;
export const isBoundaryStaticSourcePath = (file) => JS_SOURCE_RE.test(String(file));

function suppressionsOnLine(line) {
  const found = new Map();
  for (const m of line.matchAll(SUPPRESSION_RE)) found.set(m[1], m[2]);
  return found;
}

function mergeLineSuppressions(index, line, fragment) {
  const found = suppressionsOnLine(fragment);
  if (found.size === 0) return;
  const prior = index.get(line) ?? new Map();
  for (const [digest, reason] of found) prior.set(digest, reason);
  index.set(line, prior);
}

function sourceLineStarts(source) {
  const starts = [0];
  for (let index = 0; index < source.length; index++) {
    if (source.charCodeAt(index) === 10) starts.push(index + 1);
  }
  return starts;
}

function physicalLineAt(starts, position) {
  let low = 0, high = starts.length;
  while (low + 1 < high) {
    const middle = (low + high) >>> 1;
    if (starts[middle] <= position) low = middle;
    else high = middle;
  }
  return low + 1;
}

function addCommentFragment(index, startLine, text) {
  const lines = String(text).split(/\r?\n/);
  for (let offset = 0; offset < lines.length; offset++) {
    mergeLineSuppressions(index, startLine + offset, lines[offset]);
  }
}

/**
 * Inline suppression authority comes only from comment bytes in the ORIGINAL physical source.
 * Derived/cooked views receive this immutable line index; they never discover new authority inside
 * a JSON string, JavaScript literal, percent-decoded value, or reconstructed concatenation.
 */
function physicalSuppressionIndex(file, text) {
  const source = String(text);
  const index = new Map();
  if (JSON_SOURCE_RE.test(file)) return index;

  if (JS_SOURCE_RE.test(file)) {
    const scriptKind = ts.getScriptKindFromFileName(file);
    const lineStarts = sourceLineStarts(source);
    const scanner = ts.createScanner(ts.ScriptTarget.Latest, false, ts.getLanguageVariant(scriptKind), source);
    for (;;) {
      const token = scanner.scan();
      if (token === ts.SyntaxKind.EndOfFileToken) break;
      if (token === ts.SyntaxKind.SingleLineCommentTrivia || token === ts.SyntaxKind.MultiLineCommentTrivia) {
        addCommentFragment(index, physicalLineAt(lineStarts, scanner.getTokenPos()), scanner.getTokenText());
      }
    }
    return index;
  }

  // Non-JS publication inputs use explicit, review-visible comment delimiters. Track block/HTML
  // comments across lines and accept line comments only at a lexical boundary. This deliberately
  // does not treat a marker-looking substring inside ordinary quoted data as authority.
  const lines = source.split(/\r?\n/);
  let blockEnd = null;
  for (let offset = 0; offset < lines.length; offset++) {
    const line = lines[offset];
    let cursor = 0;
    let quote = null;
    while (cursor < line.length) {
      if (blockEnd !== null) {
        const end = line.indexOf(blockEnd, cursor);
        const stop = end === -1 ? line.length : end + blockEnd.length;
        mergeLineSuppressions(index, offset + 1, line.slice(cursor, stop));
        if (end === -1) break;
        cursor = stop;
        blockEnd = null;
        continue;
      }

      const character = line[cursor];
      if (quote !== null) {
        if (character === "\\") cursor += 2;
        else {
          if (character === quote) quote = null;
          cursor++;
        }
        continue;
      }
      if (character === '"' || character === "'" || character === "`") {
        quote = character;
        cursor++;
        continue;
      }
      const block = line.startsWith("<!--", cursor)
        ? { end: "-->", width: 4 }
        : line.startsWith("/*", cursor) ? { end: "*/", width: 2 } : null;
      if (block !== null) {
        const end = line.indexOf(block.end, cursor + block.width);
        const stop = end === -1 ? line.length : end + block.end.length;
        mergeLineSuppressions(index, offset + 1, line.slice(cursor, stop));
        if (end === -1) {
          blockEnd = block.end;
          break;
        }
        cursor = stop;
        continue;
      }
      const lineComment = (line.startsWith("//", cursor) || character === "#")
        && (cursor === 0 || /\s/.test(line[cursor - 1]));
      if (lineComment) {
        mergeLineSuppressions(index, offset + 1, line.slice(cursor));
        break;
      }
      cursor++;
    }
  }
  return index;
}

function suppressionAuthority(file, text, inherited) {
  return inherited ?? physicalSuppressionIndex(file, text);
}

function makeFinding(file, lineNo, rule, matched, line) {
  const redact = rule.redact === true;
  return {
    file,
    line: lineNo,
    rule: rule.id,
    severity: rule.severity,
    redact,
    matched: redact ? "" : matched,
    shown: redact ? mask(matched) : matched,
    digest: digest8(matched),
    why: rule.why,
    fix: rule.fix,
    // A non-redacted rule match may share its source line with a different redacted finding. Echo
    // only this rule's reviewed-safe match, never the surrounding line.
    snippet: redact ? "<redacted>" : matched,
  };
}

function suppressionEvidence(finding, reason) {
  return { ...finding, suppressionReason: reason };
}

/**
 * Scan one unit of text for Tier-A shapes.
 *
 * A unit is a file, a commit message, a ref name or an annotation — the scanner does not care, which
 * is why the lanes can enumerate all four and share one rule table.
 *
 * Returns `{ findings, suppressed }`. Suppressed entries are RETURNED, never discarded: a
 * suppression that nobody counts is an allowlist wearing a disguise.
 */
function scanShapesRaw(file, text, rules, sourceLine = 1, fixedSourceLine = false, suppressionIndex = null) {
  const findings = [];
  const suppressed = [];
  const lines = String(text).split(/\r?\n/);
  const isArtefact = isDeclarationArtifactPath(file) || /\.map$/i.test(file) || IS_ARTEFACT_RE.test(file);
  const physicalSuppressions = suppressionAuthority(file, text, suppressionIndex);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.length === 0) continue;
    const findingLine = fixedSourceLine ? sourceLine : sourceLine + i;
    const supp = physicalSuppressions.get(findingLine) ?? new Map();
    for (const rule of rules) {
      if (rule.scope && !rule.scope.test(file)) continue;
      for (const m of line.matchAll(rule.re)) {
        const matched = m[0];
        const matchAllowed = rule.allowMatch ? rule.allowMatch(matched) : rule.allow && rule.allow.test(matched);
        const contextAllowed = rule.allowContext?.(line, m.index, matched) === true;
        if (matchAllowed || contextAllowed) continue;
        const finding = makeFinding(file, findingLine, rule, matched, line);
        const reason = supp.get(finding.digest);
        if (reason !== undefined && INLINE_SUPPRESSIBLE.has(rule.severity)) {
          suppressed.push(suppressionEvidence(finding, reason));
        } else {
          findings.push(finding);
        }
      }
    }
    if (isArtefact) {
      for (const m of line.matchAll(ARTEFACT_ABS_PATH_RE)) {
        const rule = {
          id: "artefact-absolute-path",
          severity: SEVERITY.HIGH,
          redact: true,
          why: "an absolute path compiled into a published artefact publishes the build machine's layout to every installer",
          fix: "build with paths relative to the package root (check sourceRoot / rootDir / declarationDir)",
        };
        const finding = makeFinding(file, findingLine, rule, m[0], line);
        const reason = supp.get(finding.digest);
        if (reason !== undefined) suppressed.push(suppressionEvidence(finding, reason));
        else findings.push(finding);
      }
    }
  }
  return { findings, suppressed };
}

export function scanShapes(file, text, options = {}) {
  const rules = options.rules ?? SHAPE_RULES;
  const suppressionIndex = physicalSuppressionIndex(file, text);
  const results = [scanShapesRaw(file, text, rules, 1, false, suppressionIndex)];
  for (const view of derivedConfidentialViews(file, text, options)) {
    results.push(scanShapesRaw(file, view.text, rules, view.line, view.fixedLine === true, suppressionIndex));
  }
  return mergeScanResults(results);
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// TIER A INVERSION — repository references measured against the PUBLIC allowlist
// ─────────────────────────────────────────────────────────────────────────────────────────────────

// Candidate pairs are deliberately host-agnostic. Visibility comes from the known-owner snapshot,
// so the same coordinate cannot disappear merely by moving from github.com to raw content, GitLab,
// or a filesystem path. The scanner advances to the second segment after every match so overlapping
// `prefix/known-owner/repository` paths are measured without treating ordinary unknown pairs as repos.
const REPO_REF_RE = /([A-Za-z0-9][A-Za-z0-9-]{0,38})([\\/])([A-Za-z0-9._-]{1,100})/g;

// Static source reconstruction is intentionally bounded AST evaluation, not a text join. Arbitrary
// line joining turns unrelated prose and declarations into invented secrets. It accepts only cooked
// string/template literals, binary `+`, transparent TypeScript wrappers, and scope-safe earlier
// `const` bindings. It never executes source, folds calls, or guesses dynamic values.
const MAX_STATIC_SOURCE_UNITS = 1_048_576;
const MAX_STATIC_TOKENS = 262_144;
const MAX_STATIC_VALUES = 16_384;
const MAX_STATIC_VALUE_UNITS = 4_096;
const MAX_STATIC_PARTS = 128;
const MAX_STATIC_PAREN_DEPTH = 32;
const MAX_STATIC_SYNTAX_DEPTH = 512;
const MAX_STATIC_AST_DEPTH = 512;
const MAX_PERCENT_CANDIDATE_UNITS = 4_096;
const MAX_PERCENT_ESCAPES = 256;
const MAX_PERCENT_DECODE_ROUNDS = 4;
const MAX_DERIVED_VIEWS = 32_768;
// The published UTF-16 edge corpus intentionally reaches depth 507. The next power-of-two ceiling
// preserves that measured corpus while keeping adversarial recursion finite and review-visible.
const MAX_STATIC_JSON_DEPTH = 512;
const PERCENT_CANDIDATE_RE = /(?:[A-Za-z0-9]|%[0-9a-fA-F]{2})[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]{2,}/g;
const JSON_RELEVANT_ESCAPE_RE = /\\(?:["\\/bfnrt]|u)/;

function scanLimit(code, message) {
  const error = new RangeError(`${code}: ${message}`);
  error.code = code;
  throw error;
}

function appendStatic(value, part) {
  const next = value + part;
  if (next.length > MAX_STATIC_VALUE_UNITS) {
    scanLimit("STATIC_STRING_VALUE_LIMIT", `a reconstructed static string exceeds ${MAX_STATIC_VALUE_UNITS} code units`);
  }
  return next;
}

function scanParseFailure(code, message) {
  const error = new SyntaxError(`${code}: ${message}`);
  error.code = code;
  throw error;
}

function safeTypeScriptDiagnosticContext(file, sourceFile, diagnostics) {
  const extension = /\.([A-Za-z0-9]{1,8})$/.exec(String(file))?.[1]?.toLowerCase() ?? "none";
  const summaries = diagnostics.slice(0, 4).map((diagnostic) => {
    const position = sourceFile.getLineAndCharacterOfPosition(Math.max(0, diagnostic.start ?? 0));
    return `TS${diagnostic.code}@${position.line + 1}:${position.character + 1}`;
  });
  return `source-id=${digest8(String(file))}; extension=${extension}; diagnostics=${summaries.join(",")}`;
}

function safeSourceContext(file) {
  const extension = /\.([A-Za-z0-9]{1,8})$/.exec(String(file))?.[1]?.toLowerCase() ?? "none";
  return `source-id=${digest8(String(file))}; extension=${extension}`;
}

function isNativeStackOverflow(error) {
  return error instanceof RangeError && /maximum call stack size exceeded/i.test(String(error.message));
}

/**
 * Bound parser input structurally without counting delimiter-looking bytes inside comments, string
 * literals or template raw text. This is a resource guard, not a syntax validator: mismatched
 * delimiters and TSX remain the parser's authority, and native parser overflow is translated below.
 */
function enforceStaticSyntaxDepth(file, source, scriptKind) {
  const languageVariant = ts.getLanguageVariant(scriptKind);
  if (scriptKind === ts.ScriptKind.JSX || scriptKind === ts.ScriptKind.TSX) return;

  const scanner = ts.createScanner(ts.ScriptTarget.Latest, true, languageVariant, source);
  const delimiters = [];
  const templateFrames = [];
  let depth = 0;
  let maximum = 0;
  let structurallyAmbiguous = false;
  const open = (token) => {
    delimiters.push(token);
    depth++;
    maximum = Math.max(maximum, depth);
  };
  const close = (expected) => {
    if (delimiters.at(-1) !== expected) {
      structurallyAmbiguous = true;
      return;
    }
    delimiters.pop();
    depth--;
  };

  for (;;) {
    const token = scanner.scan();
    if (token === ts.SyntaxKind.EndOfFileToken) break;
    // The context-free scanner cannot distinguish division from a regular-expression literal.
    // Either form is parser-safe input authority, so do not let regex delimiter glyphs create a
    // lexical-depth verdict; the parser and the translated overflow guard below remain decisive.
    if (token === ts.SyntaxKind.SlashToken || token === ts.SyntaxKind.SlashEqualsToken) {
      structurallyAmbiguous = true;
    }
    if (token === ts.SyntaxKind.TemplateHead) {
      templateFrames.push({ braceDepth: 0 });
      depth++;
      maximum = Math.max(maximum, depth);
      continue;
    }
    if (token === ts.SyntaxKind.OpenParenToken) open(token);
    else if (token === ts.SyntaxKind.OpenBracketToken) open(token);
    else if (token === ts.SyntaxKind.OpenBraceToken) {
      open(token);
      if (templateFrames.length > 0) templateFrames.at(-1).braceDepth++;
    } else if (token === ts.SyntaxKind.CloseParenToken) close(ts.SyntaxKind.OpenParenToken);
    else if (token === ts.SyntaxKind.CloseBracketToken) close(ts.SyntaxKind.OpenBracketToken);
    else if (token === ts.SyntaxKind.CloseBraceToken) {
      const frame = templateFrames.at(-1);
      if (frame !== undefined && frame.braceDepth === 0) {
        const rescanned = scanner.reScanTemplateToken(false);
        if (rescanned === ts.SyntaxKind.TemplateMiddle) continue;
        if (rescanned === ts.SyntaxKind.TemplateTail) {
          templateFrames.pop();
          depth--;
          continue;
        }
        structurallyAmbiguous = true;
      } else {
        if (frame !== undefined) frame.braceDepth--;
        close(ts.SyntaxKind.OpenBraceToken);
      }
    }
  }

  if (delimiters.length !== 0 || templateFrames.length !== 0 || depth !== 0) {
    structurallyAmbiguous = true;
  }
  if (!structurallyAmbiguous && maximum > MAX_STATIC_SYNTAX_DEPTH) {
    scanLimit(
      "STATIC_SYNTAX_DEPTH_LIMIT",
      `a JavaScript/TypeScript source exceeds ${MAX_STATIC_SYNTAX_DEPTH} nested lexical delimiters; ${safeSourceContext(file)}`,
    );
  }
}

function staticResult(value, parts = 1) {
  if (value.length > MAX_STATIC_VALUE_UNITS) {
    scanLimit("STATIC_STRING_VALUE_LIMIT", `a reconstructed static string exceeds ${MAX_STATIC_VALUE_UNITS} code units`);
  }
  if (parts > MAX_STATIC_PARTS) {
    scanLimit("STATIC_PART_LIMIT", `a static expression exceeds ${MAX_STATIC_PARTS} string parts`);
  }
  return { value, parts };
}

function scopeNode(node) {
  return ts.isSourceFile(node)
    || ts.isModuleBlock(node)
    || ts.isBlock(node)
    || ts.isCaseBlock(node)
    || ts.isCatchClause(node)
    || ts.isFunctionLike(node)
    || ts.isClassDeclaration(node)
    || ts.isClassExpression(node)
    || ts.isForStatement(node)
    || ts.isForInStatement(node)
    || ts.isForOfStatement(node)
    || node.kind === ts.SyntaxKind.ClassStaticBlockDeclaration;
}

function extractStaticJsValues(file, text) {
  if (!JS_SOURCE_RE.test(file)) return [];
  const source = String(text);
  if (source.length > MAX_STATIC_SOURCE_UNITS) {
    scanLimit("STATIC_SOURCE_LIMIT", `a JavaScript/TypeScript source exceeds ${MAX_STATIC_SOURCE_UNITS} code units`);
  }

  const scriptKind = ts.getScriptKindFromFileName(file);
  enforceStaticSyntaxDepth(file, source, scriptKind);
  let sourceFile;
  try {
    sourceFile = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true, scriptKind);
  } catch (error) {
    if (isNativeStackOverflow(error)) {
      scanLimit(
        "STATIC_SOURCE_PARSE_DEPTH_LIMIT",
        `the TypeScript parser exceeded its bounded structural depth; ${safeSourceContext(file)}`,
      );
    }
    throw error;
  }
  const parseDiagnostics = sourceFile.parseDiagnostics ?? [];
  // TypeScript reports legacy octal string escapes as TS1487 even in a `.cjs` script where a
  // non-strict CommonJS runtime still cooks them. Its AST retains the exact cooked string, so this
  // one diagnostic is safe to scan; every other syntax error remains fail-closed.
  const safelyCookedLegacyCjs = /\.cjs$/i.test(file)
    && parseDiagnostics.length > 0
    && parseDiagnostics.every((diagnostic) => diagnostic.code === 1487);
  if (parseDiagnostics.length > 0 && !safelyCookedLegacyCjs) {
    scanParseFailure(
      "STATIC_SOURCE_PARSE_FAILED",
      `a JavaScript/TypeScript source cannot be parsed safely; ${safeTypeScriptDiagnosticContext(file, sourceFile, parseDiagnostics)}`,
    );
  }

  const nodeScopes = new WeakMap();
  const makeScope = (parent, functionBoundary = false) => ({ parent, functionBoundary, bindings: new Map() });
  const rootScope = makeScope(null, true);
  const dynamicBinding = Object.freeze({ kind: "dynamic" });
  let nodeCount = 0;

  const addBinding = (scope, name, binding) => {
    if (!name) return;
    if (scope.bindings.has(name)) scope.bindings.set(name, dynamicBinding);
    else scope.bindings.set(name, binding);
  };
  const addBindingName = (scope, name, binding) => {
    if (ts.isIdentifier(name)) addBinding(scope, name.text, binding);
    else for (const element of name.elements ?? []) {
      if (ts.isBindingElement(element)) addBindingName(scope, element.name, dynamicBinding);
    }
  };
  const functionScopeFor = (scope) => {
    let current = scope;
    while (current.parent !== null && !current.functionBoundary) current = current.parent;
    return current;
  };

  const indexStack = [{ node: sourceFile, inheritedScope: rootScope, depth: 0 }];
  while (indexStack.length > 0) {
    const { node, inheritedScope, depth } = indexStack.pop();
    if (depth > MAX_STATIC_AST_DEPTH) {
      scanLimit("STATIC_AST_DEPTH_LIMIT", `a JavaScript/TypeScript AST exceeds ${MAX_STATIC_AST_DEPTH} levels`);
    }
    nodeCount++;
    if (nodeCount > MAX_STATIC_TOKENS) {
      scanLimit("STATIC_TOKEN_LIMIT", `a JavaScript/TypeScript source exceeds ${MAX_STATIC_TOKENS} AST nodes`);
    }

    if (ts.isFunctionDeclaration(node) && node.name) addBinding(inheritedScope, node.name.text, dynamicBinding);
    if (ts.isClassDeclaration(node) && node.name) addBinding(inheritedScope, node.name.text, dynamicBinding);
    if (ts.isEnumDeclaration(node)) addBinding(inheritedScope, node.name.text, dynamicBinding);
    if (ts.isModuleDeclaration(node)
        && ts.isIdentifier(node.name)
        && !ts.isModuleDeclaration(node.parent)) {
      addBinding(inheritedScope, node.name.text, dynamicBinding);
    }

    const createsScope = node !== sourceFile && scopeNode(node);
    const activeScope = createsScope ? makeScope(inheritedScope, ts.isFunctionLike(node)) : inheritedScope;
    nodeScopes.set(node, activeScope);

    if (ts.isFunctionExpression(node) && node.name) addBinding(activeScope, node.name.text, dynamicBinding);
    if ((ts.isClassDeclaration(node) || ts.isClassExpression(node)) && node.name) {
      addBinding(activeScope, node.name.text, dynamicBinding);
    }
    if (ts.isParameter(node)) addBindingName(activeScope, node.name, dynamicBinding);
    if (ts.isCatchClause(node) && node.variableDeclaration) {
      addBindingName(activeScope, node.variableDeclaration.name, dynamicBinding);
    }
    if (ts.isImportClause(node) && node.name) addBinding(activeScope, node.name.text, dynamicBinding);
    if (ts.isNamespaceImport(node)) addBinding(activeScope, node.name.text, dynamicBinding);
    if (ts.isImportSpecifier(node)) addBinding(activeScope, node.name.text, dynamicBinding);
    if (ts.isImportEqualsDeclaration(node)) addBinding(activeScope, node.name.text, dynamicBinding);
    if (ts.isVariableDeclaration(node) && ts.isVariableDeclarationList(node.parent)) {
      const declarationList = node.parent;
      const blockScoped = (declarationList.flags & ts.NodeFlags.BlockScoped) !== 0;
      const bindingScope = blockScoped ? activeScope : functionScopeFor(activeScope);
      const isConst = (declarationList.flags & ts.NodeFlags.Const) !== 0;
      const binding = isConst && ts.isIdentifier(node.name) && node.initializer
        ? { kind: "const", declaration: node, initializer: node.initializer }
        : dynamicBinding;
      addBindingName(bindingScope, node.name, binding);
    }

    const children = [];
    ts.forEachChild(node, (child) => { children.push(child); });
    for (let index = children.length - 1; index >= 0; index--) {
      indexStack.push({ node: children[index], inheritedScope: activeScope, depth: depth + 1 });
    }
  }

  const resolveBinding = (identifier) => {
    let scope = nodeScopes.get(identifier) ?? rootScope;
    while (scope !== null) {
      const binding = scope.bindings.get(identifier.text);
      if (binding !== undefined) return binding;
      scope = scope.parent;
    }
    return null;
  };
  const cache = new WeakMap();
  const resolving = new Set();
  const evaluate = (node, depth = 0) => {
    if (depth > MAX_STATIC_PAREN_DEPTH) {
      scanLimit("STATIC_PAREN_LIMIT", `a static expression exceeds ${MAX_STATIC_PAREN_DEPTH} evaluation levels`);
    }
    if (cache.has(node)) return cache.get(node);
    let result = null;

    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
      if (!(ts.isTaggedTemplateExpression(node.parent) && node.parent.template === node)) {
        result = staticResult(node.text);
      }
    } else if (ts.isTemplateExpression(node)) {
      if (!(ts.isTaggedTemplateExpression(node.parent) && node.parent.template === node)) {
        let value = node.head.text;
        let parts = 1;
        for (const span of node.templateSpans) {
          const expression = evaluate(span.expression, depth + 1);
          if (expression === null) { value = null; break; }
          value = appendStatic(value, expression.value);
          value = appendStatic(value, span.literal.text);
          parts += expression.parts + 1;
          if (parts > MAX_STATIC_PARTS) {
            scanLimit("STATIC_PART_LIMIT", `a static template exceeds ${MAX_STATIC_PARTS} string parts`);
          }
        }
        if (value !== null) result = staticResult(value, parts);
      }
    } else if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) {
      // A flat `a + b + c` is one bounded concatenation, not semantic nesting. TypeScript stores it
      // as a left-deep binary tree, so recursive evaluation incorrectly exhausted the nesting guard
      // long before the explicit part limit. Flatten only unparenthesized `+` nodes iteratively;
      // parentheses and transparent wrappers remain operands and therefore retain real depth.
      const pending = [node];
      const operands = [];
      while (pending.length > 0) {
        const current = pending.pop();
        if (ts.isBinaryExpression(current) && current.operatorToken.kind === ts.SyntaxKind.PlusToken) {
          pending.push(current.right, current.left);
          if (pending.length + operands.length > MAX_STATIC_PARTS) {
            scanLimit("STATIC_PART_LIMIT", `a static concatenation exceeds ${MAX_STATIC_PARTS} string parts`);
          }
        } else {
          operands.push(current);
        }
      }
      let value = "";
      let parts = 0;
      for (const operand of operands) {
        const evaluated = evaluate(operand, depth + 1);
        if (evaluated === null) { value = null; break; }
        value = appendStatic(value, evaluated.value);
        parts += evaluated.parts;
        if (parts > MAX_STATIC_PARTS) {
          scanLimit("STATIC_PART_LIMIT", `a static concatenation exceeds ${MAX_STATIC_PARTS} string parts`);
        }
      }
      if (value !== null) result = staticResult(value, parts);
    } else if (ts.isParenthesizedExpression(node)
        || ts.isAsExpression(node)
        || ts.isSatisfiesExpression(node)
        || ts.isTypeAssertionExpression(node)
        || ts.isNonNullExpression(node)) {
      result = evaluate(node.expression, depth + 1);
    } else if (ts.isIdentifier(node)) {
      const binding = resolveBinding(node);
      if (binding?.kind === "const"
          && binding.declaration.end <= node.getStart(sourceFile)
          && !resolving.has(binding.declaration)) {
        resolving.add(binding.declaration);
        result = evaluate(binding.initializer, depth + 1);
        resolving.delete(binding.declaration);
      }
    }

    cache.set(node, result);
    return result;
  };

  const values = [];
  const seen = new Set();
  const add = (node, result, kind) => {
    if (result === null || result.value.length < 3) return;
    const line = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1;
    const key = `${line}\0${result.value}`;
    if (seen.has(key)) return;
    seen.add(key);
    values.push({ text: result.value, line, kind, fixedLine: true });
    if (values.length > MAX_STATIC_VALUES) {
      scanLimit("STATIC_VALUE_COUNT_LIMIT", `a JavaScript/TypeScript source exceeds ${MAX_STATIC_VALUES} static values`);
    }
  };
  const collectStack = [{ node: sourceFile, depth: 0 }];
  while (collectStack.length > 0) {
    const { node, depth } = collectStack.pop();
    if (depth > MAX_STATIC_AST_DEPTH) {
      scanLimit("STATIC_AST_DEPTH_LIMIT", `a JavaScript/TypeScript AST exceeds ${MAX_STATIC_AST_DEPTH} levels`);
    }
    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
      add(node, evaluate(node), "js-literal");
    } else if (ts.isTemplateExpression(node)) {
      add(node, evaluate(node), "js-static-template");
    } else if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) {
      add(node, evaluate(node), "js-static-concat");
    }
    const children = [];
    ts.forEachChild(node, (child) => { children.push(child); });
    for (let index = children.length - 1; index >= 0; index--) {
      collectStack.push({ node: children[index], depth: depth + 1 });
    }
  }
  return values;
}

function extractStaticJsonValues(file, text) {
  if (!JSON_SOURCE_RE.test(file)) return [];
  const source = String(text);
  // Raw scanners already see unescaped JSON strings byte-for-byte. Parse only when JSON escaping
  // can change the effective string; this keeps intentional malformed conformance vectors and
  // JSON-with-comments configuration in raw-scan scope while malformed escape-bearing JSON fails.
  if (!JSON_RELEVANT_ESCAPE_RE.test(source)) return [];
  if (source.length > MAX_STATIC_SOURCE_UNITS) {
    scanLimit("STATIC_SOURCE_LIMIT", `a JSON source exceeds ${MAX_STATIC_SOURCE_UNITS} code units`);
  }
  let root;
  try {
    root = JSON.parse(source);
  } catch {
    scanParseFailure("STATIC_JSON_PARSE_FAILED", `a JSON source cannot be parsed safely; source-id=${digest8(String(file))}`);
  }

  const values = [];
  const seen = new Set();
  let nodes = 0;
  const add = (value, line) => {
    const key = `${line}\0${value}`;
    if (value.length < 3 || seen.has(key)) return;
    if (value.length > MAX_STATIC_VALUE_UNITS) {
      scanLimit("STATIC_STRING_VALUE_LIMIT", `a JSON string exceeds ${MAX_STATIC_VALUE_UNITS} code units`);
    }
    seen.add(key);
    values.push({ text: value, line, kind: "json-string", fixedLine: true });
    if (values.length > MAX_STATIC_VALUES) {
      scanLimit("STATIC_VALUE_COUNT_LIMIT", `a JSON source exceeds ${MAX_STATIC_VALUES} distinct strings`);
    }
  };
  const visit = (value, depth) => {
    if (depth > MAX_STATIC_JSON_DEPTH) {
      scanLimit("STATIC_JSON_DEPTH_LIMIT", `a JSON source exceeds ${MAX_STATIC_JSON_DEPTH} nesting levels`);
    }
    nodes++;
    if (nodes > MAX_STATIC_TOKENS) {
      scanLimit("STATIC_JSON_NODE_LIMIT", `a JSON source exceeds ${MAX_STATIC_TOKENS} values`);
    }
    if (Array.isArray(value)) for (const item of value) visit(item, depth + 1);
    else if (value !== null && typeof value === "object") {
      for (const item of Object.values(value)) visit(item, depth + 1);
    }
  };
  visit(root, 0);

  // JSON.parse is the strict syntax and semantic boundary above. The TypeScript JSON AST is used
  // only to retain each cooked string's physical location and duplicate-key occurrences that the
  // parsed object model intentionally overwrites; it never broadens the accepted JSON grammar.
  const jsonFile = ts.parseJsonText(file, source);
  if ((jsonFile.parseDiagnostics?.length ?? 0) > 0) {
    scanParseFailure(
      "STATIC_JSON_PARSE_FAILED",
      `a JSON source cannot be parsed safely; ${safeTypeScriptDiagnosticContext(file, jsonFile, jsonFile.parseDiagnostics)}`,
    );
  }
  const stack = [jsonFile];
  let astNodes = 0;
  while (stack.length > 0) {
    const node = stack.pop();
    astNodes++;
    if (astNodes > MAX_STATIC_TOKENS) {
      scanLimit("STATIC_JSON_NODE_LIMIT", `a JSON source exceeds ${MAX_STATIC_TOKENS} syntax nodes`);
    }
    if (ts.isStringLiteral(node)) {
      const line = jsonFile.getLineAndCharacterOfPosition(node.getStart(jsonFile)).line + 1;
      add(node.text, line);
    }
    const children = [];
    ts.forEachChild(node, (child) => { children.push(child); });
    for (let index = children.length - 1; index >= 0; index--) stack.push(children[index]);
  }
  return values;
}

function decodePrintablePercentPass(value) {
  if (value.length > MAX_PERCENT_CANDIDATE_UNITS) {
    scanLimit("PERCENT_CANDIDATE_LIMIT", `a percent-encoded candidate exceeds ${MAX_PERCENT_CANDIDATE_UNITS} code units`);
  }
  let output = "";
  let escapes = 0;
  let changed = false;
  for (let index = 0; index < value.length; index++) {
    if (value[index] !== "%") {
      output += value[index];
      continue;
    }
    const hex = value.slice(index + 1, index + 3);
    if (!/^[0-9a-fA-F]{2}$/.test(hex)) {
      output += "%";
      continue;
    }
    const byte = Number.parseInt(hex, 16);
    escapes++;
    if (escapes > MAX_PERCENT_ESCAPES) {
      scanLimit("PERCENT_ESCAPE_LIMIT", `a percent-encoded candidate exceeds ${MAX_PERCENT_ESCAPES} escapes`);
    }
    if (byte >= 0x20 && byte <= 0x7e) {
      output += String.fromCharCode(byte);
      changed = true;
    } else {
      output += value.slice(index, index + 3);
    }
    index += 2;
  }
  return { value: output, changed };
}

function percentDecodedValues(value) {
  if (!/%[0-9a-fA-F]{2}/.test(value)) return [];
  const decoded = [];
  let current = value;
  for (let round = 0; round < MAX_PERCENT_DECODE_ROUNDS; round++) {
    const pass = decodePrintablePercentPass(current);
    if (!pass.changed) return decoded;
    current = pass.value;
    decoded.push(current);
  }
  if (/%(?:2[0-9a-fA-F]|[3-6][0-9a-fA-F]|7[0-9a-eA-E])/.test(current)) {
    scanLimit("PERCENT_DECODE_ROUND_LIMIT", `a percent-encoded candidate exceeds ${MAX_PERCENT_DECODE_ROUNDS} decode rounds`);
  }
  return decoded;
}

function percentDecodedViews(text, sourceLine = 1, fixedSourceLine = false) {
  const views = [];
  const lines = String(text).split(/\r?\n/);
  for (let offset = 0; offset < lines.length; offset++) {
    const line = lines[offset];
    for (const match of line.matchAll(PERCENT_CANDIDATE_RE)) {
      for (const [round, decoded] of percentDecodedValues(match[0]).entries()) {
        views.push({
          // Keep the bounded line/value context around the decoded candidate. Repository/token
          // matching needs only the candidate, but privacy adjacency also needs the neighbouring
          // confidentiality word. Replacing one matched span at a time avoids arbitrary line joining
          // and keeps the derived-view count bounded by candidates x decode rounds.
          text: `${line.slice(0, match.index)}${decoded}${line.slice(match.index + match[0].length)}`,
          line: fixedSourceLine ? sourceLine : sourceLine + offset,
          kind: `percent-decoded-${round + 1}`,
          fixedLine: true,
        });
      }
    }
  }
  return views;
}

function derivedConfidentialViews(file, text, { structuredSource = true } = {}) {
  const views = [];
  const seen = new Set();
  const add = (view) => {
    const key = `${view.line}\0${view.text}`;
    if (seen.has(key)) return;
    seen.add(key);
    views.push(view);
    if (views.length > MAX_DERIVED_VIEWS) scanLimit("DERIVED_VIEW_LIMIT", `a source exceeds ${MAX_DERIVED_VIEWS} derived scan views`);
  };
  for (const view of percentDecodedViews(text)) add(view);
  const staticValues = structuredSource
    ? [...extractStaticJsValues(file, text), ...extractStaticJsonValues(file, text)] : [];
  for (const value of staticValues) {
    add(value);
    // Cooked newlines do not correspond to additional physical source lines. Once a value comes
    // from an AST literal, conservatively retain that literal's start line through later decoding.
    for (const decoded of percentDecodedViews(value.text, value.line, true)) add(decoded);
  }
  return views;
}

const REPO_OWNER_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/;
const REPO_NAME_RE = /^[A-Za-z0-9._-]{1,100}$/;
const WRAPPED_FORGE_RE = /(?<![A-Za-z0-9._-])(?:https?:\/\/)?(?:github\.com|raw\.githubusercontent\.com|gitlab\.com)\/(?:[ \t]*\r?\n[ \t]{1,32})?([A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?)\/[ \t]*\r?\n[ \t]{1,32}([A-Za-z0-9._-]{1,100})(?![A-Za-z0-9_-])/gi;

function normaliseRepoCoordinate(value, subject) {
  if (typeof value !== "string" || value.length === 0 || value !== value.trim()) {
    throw new TypeError(`${subject} must be a trimmed owner/repository coordinate`);
  }
  if (/[*?\[\]{}]/.test(value)) {
    throw new TypeError(`${subject} must not contain wildcard or pattern syntax`);
  }
  const parts = value.split("/");
  if (parts.length !== 2 || !REPO_OWNER_RE.test(parts[0]) || !REPO_NAME_RE.test(parts[1]) || parts[1] === "." || parts[1] === "..") {
    throw new TypeError(`${subject} must name exactly one owner/repository`);
  }
  return `${parts[0].toLowerCase()}/${parts[1].toLowerCase()}`;
}

function publicRepoSnapshot(allowlist) {
  if (allowlist === null || typeof allowlist !== "object" || Array.isArray(allowlist)
      || typeof allowlist.orgs !== "object" || allowlist.orgs === null || Array.isArray(allowlist.orgs)) {
    throw new TypeError("a public-repository snapshot with an orgs object is required; visibility cannot be guessed");
  }
  const foldedOwners = new Set();
  for (const owner of Object.keys(allowlist.orgs)) {
    const folded = owner.toLowerCase();
    if (foldedOwners.has(folded)) {
      const error = new TypeError(
        "PUBLIC_REPOSITORY_SNAPSHOT_DUPLICATE_OWNER: owner keys must be unique case-insensitively",
      );
      error.code = "PUBLIC_REPOSITORY_SNAPSHOT_DUPLICATE_OWNER";
      throw error;
    }
    foldedOwners.add(folded);
  }
  const orgs = new Map();
  const coordinates = new Set();
  for (const [owner, repos] of Object.entries(allowlist.orgs)) {
    if (!Array.isArray(repos)) {
      throw new TypeError(`public-repository snapshot for ${owner} must be an array`);
    }
    const normalisedRepos = new Set();
    for (const repo of repos) {
      const coordinate = normaliseRepoCoordinate(`${owner}/${repo}`, `public snapshot entry ${owner}/${String(repo)}`);
      const repoName = coordinate.slice(coordinate.indexOf("/") + 1);
      normalisedRepos.add(repoName);
      coordinates.add(coordinate);
    }
    orgs.set(owner.toLowerCase(), normalisedRepos);
  }
  return { orgs, coordinates };
}

/**
 * THE INVERSION. `allowlist` is `{ orgs: {<org>: [<publicRepoName>, …]} }` — public information,
 * safe to commit, and derived from the forge's own answer rather than typed by hand.
 *
 * Only references qualified by a KNOWN ORG are considered, which is what keeps `packages/gate` and
 * `dist/src` out of the result set while `<org>/<unlisted-repo>` lands as CRITICAL.
 */
const REPO_NOT_PUBLIC_RULE = Object.freeze({
  id: "repo-not-public",
  severity: SEVERITY.CRITICAL,
  redact: true,
  why: "this repository is not on the forge's list of PUBLIC repositories for its organisation, so naming it discloses a repository that was deliberately not published",
  fix: "remove the reference; if the repository has since been made public, refresh the allowlist with --refresh-public-repos",
});

function repoReferencesIn(line, snapshot) {
  const references = [];
  REPO_REF_RE.lastIndex = 0;
  for (;;) {
    const match = REPO_REF_RE.exec(line);
    if (match === null) break;
    const separatorOffset = match[0].indexOf(match[2]);
    const overlapStart = match.index + separatorOffset + 1;
    REPO_REF_RE.lastIndex = overlapStart;

    const before = match.index === 0 ? "" : line[match.index - 1];
    if (before !== "" && /[A-Za-z0-9@._-]/.test(before)) continue;
    const after = line[match.index + match[0].length] ?? "";
    if (after !== "" && /[A-Za-z0-9_-]/.test(after)) continue;

    const owner = match[1].toLowerCase();
    const known = snapshot.orgs.get(owner);
    if (known === undefined) continue;
    const rawRepo = match[3].replace(/\.+$/, "");
    if (match[2] === "\\" && /^(?:u[0-9a-f]{4}|x[0-9a-f]{2}|[0-7]{1,3})/i.test(rawRepo)) continue;
    const repo = rawRepo.toLowerCase().replace(/\.git$/, "");
    if (!REPO_NAME_RE.test(repo) || repo === "." || repo === "..") continue;
    if (known.has(repo)) continue;
    references.push({ matched: `${match[1]}${match[2]}${rawRepo}`, owner, repo });
  }
  return references;
}

/**
 * Generated RFC text may soft-wrap a forge URL between its owner slash and repository name. Join
 * only that exact, bounded grammar: a recognised forge host, an owner authenticated by the public
 * snapshot, one physical newline, and at most 32 continuation spaces. This is deliberately not a
 * general line join. The normal repository inversion still decides whether the reconstructed
 * coordinate is public, and the finding remains bound to the physical line where the URL starts.
 */
function wrappedForgeRepoViews(text, snapshot) {
  const source = String(text);
  const views = [];
  let line = 1;
  let cursor = 0;
  WRAPPED_FORGE_RE.lastIndex = 0;
  for (const match of source.matchAll(WRAPPED_FORGE_RE)) {
    while (cursor < match.index) {
      const newline = source.indexOf("\n", cursor);
      if (newline < 0 || newline >= match.index) break;
      line++;
      cursor = newline + 1;
    }
    const owner = match[1].toLowerCase();
    if (!snapshot.orgs.has(owner)) continue;
    views.push({ text: `${match[1]}/${match[2]}`, line, fixedLine: true, kind: "wrapped-forge-repository" });
    if (views.length > MAX_DERIVED_VIEWS) {
      scanLimit("DERIVED_VIEW_LIMIT", `a source exceeds ${MAX_DERIVED_VIEWS} derived scan views`);
    }
  }
  return views;
}

function scanRepoRefsRaw(file, text, snapshot, sourceLine = 1, fixedSourceLine = false, suppressionIndex = null) {
  const rule = {
    ...REPO_NOT_PUBLIC_RULE,
  };
  const findings = [];
  const suppressed = [];
  const lines = String(text).split(/\r?\n/);
  const physicalSuppressions = suppressionAuthority(file, text, suppressionIndex);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.length === 0) continue;
    const findingLine = fixedSourceLine ? sourceLine : sourceLine + i;
    const supp = physicalSuppressions.get(findingLine) ?? new Map();
    for (const reference of repoReferencesIn(line, snapshot)) {
      const finding = makeFinding(file, findingLine, rule, reference.matched, line);
      const reason = supp.get(finding.digest);
      if (reason !== undefined && INLINE_SUPPRESSIBLE.has(rule.severity)) {
        suppressed.push(suppressionEvidence(finding, reason));
      } else {
        findings.push(finding);
      }
    }
  }
  return { findings, suppressed };
}

function mergeScanResults(results) {
  const findings = [];
  const suppressed = [];
  const findingKeys = new Set();
  const suppressedKeys = new Set();
  for (const result of results) {
    for (const finding of result.findings) {
      const key = `${finding.rule}\0${finding.line}\0${finding.digest}`;
      if (!findingKeys.has(key)) { findingKeys.add(key); findings.push(finding); }
    }
    for (const finding of result.suppressed) {
      const key = `${finding.rule}\0${finding.line}\0${finding.digest}\0${finding.suppressionReason}`;
      if (!suppressedKeys.has(key)) { suppressedKeys.add(key); suppressed.push(finding); }
    }
  }
  return { findings, suppressed };
}

export function scanRepoRefs(file, text, allowlist, options = {}) {
  const snapshot = publicRepoSnapshot(allowlist);
  const suppressionIndex = physicalSuppressionIndex(file, text);
  const results = [scanRepoRefsRaw(file, text, snapshot, 1, false, suppressionIndex)];
  for (const view of wrappedForgeRepoViews(text, snapshot)) {
    results.push(scanRepoRefsRaw(file, view.text, snapshot, view.line, true, suppressionIndex));
  }
  for (const view of derivedConfidentialViews(file, text, options)) {
    results.push(scanRepoRefsRaw(file, view.text, snapshot, view.line, view.fixedLine === true, suppressionIndex));
  }
  return mergeScanResults(results);
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// TIER A — privacy adjacency
// ─────────────────────────────────────────────────────────────────────────────────────────────────

const PRIVACY_WORD_RE = /(?<![A-Za-z0-9_-])(?:private|internal|proprietary|confidential|unpublished)(?![A-Za-z0-9_-])/i;
/**
 * An IDENTITY token: something that points at a place a reader could NOT otherwise find.
 *
 * NARROWED AFTER MEASURING. The first draft counted any `https://` URL, which flagged a shields.io
 * badge sitting in the same sentence as the word "unpublished", and the repository's own public
 * forge URL sitting in the same sentence as the word "public". A URL anyone can already open is not
 * a disclosure, and a rule that says otherwise trains people to route around it.
 *
 * What remains is exactly the disclosing shapes: an operator home path, a Windows user path, a
 * private-suffixed or bare-IP host, and — through the caller's allowlist — an org-qualified
 * repository reference that the forge does NOT report as public. The inversion again.
 */
const IDENTITY_TOKEN_RE = /(?:\/(?:Users|home)\/[A-Za-z0-9._-]+)|(?:[A-Za-z]:\\Users\\)|(?:https?:\/\/(?:\d{1,3}(?:\.\d{1,3}){3}|[A-Za-z0-9.-]+\.(?:internal|corp|intranet|lan|local|vpn))(?::\d+)?[^\s"'`<>)\]]*)/i;
const SENTENCE_SPLIT_RE = /(?<=[.!?])\s+/;
const PRIVACY_ADJACENCY_RULE = Object.freeze({
  id: "privacy-adjacency",
  severity: SEVERITY.HIGH,
  redact: true,
  why: "a confidentiality word sits in the same sentence as a lookup-able identity, which tells a reader exactly which unpublished thing to go and find",
  fix: "drop the identity, or drop the sentence; describing what is withheld defeats withholding it",
});

/**
 * "sibling repository X (PRIVATE)" is caught WITHOUT this file ever naming X. That is the whole
 * point: the rule fires on the CO-OCCURRENCE of a confidentiality word and a lookup-able identity
 * token inside one sentence, so it needs no knowledge of what is confidential.
 *
 * Scoped to a sentence rather than a line for the reason the neighbouring claim lint records: an
 * item-wide window lets an unrelated word elsewhere in the paragraph decide this sentence's verdict.
 *
 * `allowlist` is optional; when supplied, an org-qualified repository reference that the forge does
 * not report as public also counts as an identity.
 */
function scanPrivacyAdjacencyRaw(file, text, publicSnapshot, sourceLine = 1, fixedSourceLine = false, suppressionIndex = null) {
  const rule = PRIVACY_ADJACENCY_RULE;
  const findings = [];
  const suppressed = [];
  const nonPublicRepoIn = (sentence) => {
    if (publicSnapshot === null) return null;
    // `sentence` is a punctuation-delimited fragment, not a standalone source file. Parsing that
    // fragment as JavaScript/TypeScript can manufacture an unterminated literal and fail a valid
    // containing file. The complete file is independently reconstructed by `scanRepoRefs`; this
    // adjacency lookup needs only the literal repository reference present in this sentence.
    return repoReferencesIn(sentence, publicSnapshot)[0]?.matched ?? null;
  };
  const lines = String(text).split(/\r?\n/);
  const physicalSuppressions = suppressionAuthority(file, text, suppressionIndex);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.length === 0) continue;
    const findingLine = fixedSourceLine ? sourceLine : sourceLine + i;
    const supp = physicalSuppressions.get(findingLine) ?? new Map();
    for (const sentence of line.split(SENTENCE_SPLIT_RE)) {
      if (!PRIVACY_WORD_RE.test(sentence)) continue;
      const matchedIdentity = IDENTITY_TOKEN_RE.exec(sentence)?.[0] ?? nonPublicRepoIn(sentence);
      if (matchedIdentity === null || matchedIdentity === undefined) continue;
      const finding = makeFinding(file, findingLine, rule, matchedIdentity, line);
      const reason = supp.get(finding.digest);
      if (reason !== undefined) suppressed.push(suppressionEvidence(finding, reason));
      else findings.push(finding);
    }
  }
  return { findings, suppressed };
}

export function scanPrivacyAdjacency(file, text, allowlist = null, options = {}) {
  const publicSnapshot = allowlist === null ? null : publicRepoSnapshot(allowlist);
  const suppressionIndex = physicalSuppressionIndex(file, text);
  const results = [scanPrivacyAdjacencyRaw(file, text, publicSnapshot, 1, false, suppressionIndex)];
  for (const view of derivedConfidentialViews(file, text, options)) {
    results.push(scanPrivacyAdjacencyRaw(file, view.text, publicSnapshot, view.line, view.fixedLine === true, suppressionIndex));
  }
  return mergeScanResults(results);
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// TIER B — token commitments
// ─────────────────────────────────────────────────────────────────────────────────────────────────

/**
 * Tier B. `lookup(candidate) -> boolean` is injected so the gate can memoise HMACs across a whole
 * run and so the selftest can drive this function without a key on disk.
 */
const TOKEN_COMMITMENT_RULE = Object.freeze({
  id: "token-commitment",
  severity: SEVERITY.CRITICAL,
  redact: true,
  why: "this exact label is committed as confidential; its digest matched under the key held outside this repository",
  fix: "remove the label; if it has been declassified, regenerate the commitments with --refresh-tokens",
});

function scanTokensRaw(
  file,
  text,
  lookup,
  ngramSizes = [1],
  sourceLine = 1,
  fixedSourceLine = false,
  suppressionIndex = null,
  options = {},
) {
  const rule = {
    ...TOKEN_COMMITMENT_RULE,
  };
  const findings = [];
  const suppressed = [];
  const lines = String(text).split(/\r?\n/);
  const physicalSuppressions = suppressionAuthority(file, text, suppressionIndex);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.length === 0) continue;
    const hits = new Set();
    for (const candidate of extractCandidates(line, ngramSizes, options)) {
      if (lookup(candidate)) hits.add(candidate);
      else if (lookup(collapseDigits(candidate))) hits.add(candidate);
    }
    if (hits.size === 0) continue;
    const findingLine = fixedSourceLine ? sourceLine : sourceLine + i;
    const supp = physicalSuppressions.get(findingLine) ?? new Map();
    for (const hit of [...hits].sort()) {
      const finding = makeFinding(file, findingLine, rule, hit, line);
      // CRITICAL is not inline-suppressible; the ledger is the only route, and it is loud.
      const reason = supp.get(finding.digest);
      if (reason !== undefined && INLINE_SUPPRESSIBLE.has(rule.severity)) {
        suppressed.push(suppressionEvidence(finding, reason));
      } else {
        findings.push(finding);
      }
    }
  }
  return { findings, suppressed };
}

export function scanTokens(file, text, lookup, ngramSizes = [1], options = {}) {
  if (typeof lookup !== "function") throw new TypeError("scanTokens requires a commitment lookup function");
  const suppressionIndex = physicalSuppressionIndex(file, text);
  const results = [scanTokensRaw(file, text, lookup, ngramSizes, 1, false, suppressionIndex, options)];
  for (const view of derivedConfidentialViews(file, text, options)) {
    results.push(scanTokensRaw(
      file,
      view.text,
      lookup,
      ngramSizes,
      view.line,
      view.fixedLine === true,
      suppressionIndex,
      options,
    ));
  }
  return mergeScanResults(results);
}

/**
 * Operator output and machine evidence are part of the confidentiality boundary too: a path or
 * label can itself be the value the scanners just refused. Return the original label only when the
 * same enabled tiers find nothing; otherwise return one non-correlatable constant mask. Scanner failures
 * propagate so an unmeasurable label can never be printed as though it were clean.
 */
export function safeBoundaryLabel(label, { allowlist = null, lookup = null, ngramSizes = [1] } = {}) {
  const text = String(label);
  const measured = [scanShapes("label", text), scanPrivacyAdjacency("label", text, allowlist)];
  if (allowlist !== null) measured.push(scanRepoRefs("label", text, allowlist));
  if (lookup !== null) measured.push(scanTokens("label", text, lookup, ngramSizes));
  const unsafe = measured.some((result) => result.findings.length > 0 || result.suppressed.length > 0);
  return unsafe ? mask(text) : text;
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// SOURCEMAPS
// ─────────────────────────────────────────────────────────────────────────────────────────────────

const sourcePathKind = (value) => {
  const raw = String(value);
  const portable = raw.replace(/\\/g, "/");
  if (raw.startsWith("\\\\") || portable.startsWith("//")) return "absolute";
  if (portable.startsWith("/") || /^[A-Za-z]:\//.test(portable)) return "absolute";
  const scheme = /^([A-Za-z][A-Za-z0-9+.-]*):/.exec(portable)?.[1]?.toLowerCase() ?? null;
  if (scheme === "file") return "absolute";
  if (scheme !== null) return "url";
  return "relative";
};

function sourceEscapesPackage(mapPath, sourceRoot, source) {
  const sourceKind = sourcePathKind(source);
  if (sourceKind === "absolute") return true;
  if (sourceKind === "url") return false;
  const rootKind = sourcePathKind(sourceRoot);
  if (rootKind === "absolute") return true;
  if (rootKind === "url") return false;

  const portableMap = String(mapPath).replace(/\\/g, "/");
  const base = posix.dirname(portableMap);
  const pieces = [base === "." ? "" : base, String(sourceRoot), String(source)]
    .join("/").replace(/\\/g, "/").split("/");
  let depth = 0;
  for (const piece of pieces) {
    if (piece.length === 0 || piece === ".") continue;
    if (piece === "..") {
      if (depth === 0) return true;
      depth--;
    } else {
      depth++;
    }
  }
  return false;
}

/**
 * A packed sourcemap is scanned STRUCTURALLY as well as textually: a `sources[]` entry that is
 * absolute, or that escapes the package root, is a finding on its own regardless of content — it
 * publishes the build machine's directory tree. Measured on the current tree: 0 maps are packed
 * today, which is exactly why this must exist BEFORE `declarationMap`/`sourceMap` is switched on.
 * The day it is, nobody will think to look.
 */
export function scanSourceMap(file, text, options = {}) {
  const rule = {
    id: "sourcemap-escapes-package",
    severity: SEVERITY.HIGH,
    redact: true,
    why: "a sources[] entry that is absolute or climbs out of the package publishes the build machine's directory tree to every installer",
    fix: "set sourceRoot, or build with rootDir inside the package so sources[] stays relative",
  };
  const refuse = (id, why) => ({
    findings: [{
      file,
      line: 1,
      rule: id,
      severity: SEVERITY.HIGH,
      redact: true,
      matched: "",
      shown: "<redacted>",
      digest: digest8(file),
      why,
      fix: "regenerate or unpublish the map; an unscannable packed file is not a clean packed file",
      snippet: "<redacted>",
    }],
    suppressed: [],
    contents: [],
    paths: [],
  });
  const invalidShape = (why) => refuse("sourcemap-invalid-shape", why);
  const source = String(text);
  if (source.length > MAX_STATIC_SOURCE_UNITS) {
    return refuse("sourcemap-unscannable", "a packed sourcemap exceeds the bounded structural scanner input limit");
  }
  try {
    JSON.parse(source);
  } catch {
    return refuse("sourcemap-unparsable", "a packed sourcemap that cannot be parsed cannot be scanned");
  }

  // JSON.parse is the strict syntax boundary. The JSON syntax tree is the cooking/occurrence
  // boundary: unlike the parsed object model it retains overwritten duplicate-key values, so every
  // decoded property name and string occurrence reaches the scanner even when a later key wins.
  const contents = [];
  const paths = [];
  const pathIndexes = new Map();
  const recordPath = (field, value) => {
    if (value.length === 0) return;
    const index = pathIndexes.get(field) ?? 0;
    paths.push({ field, index, value });
    pathIndexes.set(field, index + 1);
  };
  let jsonFile;
  try {
    jsonFile = ts.parseJsonText(file, source);
  } catch {
    return refuse("sourcemap-unscannable", "the packed sourcemap JSON syntax tree exceeded the bounded parser");
  }
  if ((jsonFile.parseDiagnostics?.length ?? 0) > 0) {
    return refuse("sourcemap-unparsable", "a packed sourcemap that cannot be parsed cannot be scanned");
  }
  const traversal = [{ node: jsonFile, depth: 0, isPropertyName: false }];
  let nodes = 0;
  while (traversal.length > 0) {
    const { node, depth, isPropertyName } = traversal.pop();
    if (depth > MAX_STATIC_JSON_DEPTH) {
      return refuse("sourcemap-unscannable", "a packed sourcemap exceeds the bounded structural nesting limit");
    }
    nodes++;
    if (nodes > MAX_STATIC_TOKENS) {
      return refuse("sourcemap-unscannable", "a packed sourcemap exceeds the bounded structural node limit");
    }
    if (ts.isStringLiteral(node)) {
      if (node.text.length > MAX_STATIC_VALUE_UNITS) {
        return refuse("sourcemap-unscannable", "a packed sourcemap contains a decoded string beyond the bounded scanner limit");
      }
      let values;
      try {
        values = [node.text, ...percentDecodedValues(node.text)];
      } catch {
        return refuse("sourcemap-unscannable", "a packed sourcemap contains percent-encoded data beyond the bounded scanner limit");
      }
      for (const value of values) {
        // Preserve OCCURRENCES, including duplicate keys and repeated values. A later JSON property
        // may overwrite an earlier one at runtime, but it cannot erase bytes already in the packed
        // artefact. Percent-normalised variants remain adjacent to the exact occurrence that made
        // them, and the same global bound prevents multiplicative expansion.
        contents.push(value);
        if (contents.length > MAX_STATIC_VALUES) {
          return refuse("sourcemap-unscannable", "a packed sourcemap exceeds the bounded decoded-string limit");
        }
      }
    }
    const children = [];
    ts.forEachChild(node, (child) => { children.push(child); });
    for (let index = children.length - 1; index >= 0; index--) {
      const child = children[index];
      traversal.push({
        node: child,
        depth: depth + 1,
        isPropertyName: ts.isPropertyAssignment(node) && node.name === child,
      });
    }
  }

  const rootStatement = jsonFile.statements[0];
  const rootExpression = rootStatement !== undefined && ts.isExpressionStatement(rootStatement)
    ? rootStatement.expression
    : null;
  if (rootExpression === null || !ts.isObjectLiteralExpression(rootExpression)) {
    return invalidShape("a packed sourcemap root must be a JSON object");
  }

  const propertyAssignments = (object, name) => object.properties.filter(
    (property) => ts.isPropertyAssignment(property)
      && ts.isStringLiteral(property.name)
      && property.name.text === name,
  );
  const physicalLine = (node) => jsonFile.getLineAndCharacterOfPosition(node.getStart(jsonFile)).line + 1;
  const literalString = (node) => ts.isStringLiteral(node) ? node.text : null;
  const naturalNumber = (node) => ts.isNumericLiteral(node) && Number.isSafeInteger(Number(node.text)) && Number(node.text) >= 0;
  const mapPath = options.mapPath ?? file;
  const pathVariants = (value) => {
    try { return [value, ...percentDecodedValues(value)]; } catch { return null; }
  };

  const findings = [];
  const maps = [{ node: rootExpression, depth: 0 }];
  while (maps.length > 0) {
    const current = maps.pop();
    if (current.depth > MAX_STATIC_JSON_DEPTH) {
      return refuse("sourcemap-unscannable", "an indexed sourcemap exceeds the bounded nested-map limit");
    }
    const object = current.node;
    if (!ts.isObjectLiteralExpression(object)) {
      return invalidShape("an indexed sourcemap contains a non-object map");
    }
    if (object.properties.some((property) => !ts.isPropertyAssignment(property) || !ts.isStringLiteral(property.name))) {
      return invalidShape("a packed sourcemap contains a non-JSON property");
    }

    const versions = propertyAssignments(object, "version");
    if (versions.length === 0 || versions.some((property) => !ts.isNumericLiteral(property.initializer)
        || Number(property.initializer.text) !== 3)) {
      return invalidShape("every packed sourcemap object must declare numeric version 3");
    }

    const sourcesProperties = propertyAssignments(object, "sources");
    const sectionsProperties = propertyAssignments(object, "sections");
    if ((sourcesProperties.length === 0) === (sectionsProperties.length === 0)) {
      return invalidShape("a packed sourcemap must be exactly one regular sources map or indexed sections map");
    }

    for (const name of ["file", "mappings", "sourceRoot"]) {
      if (propertyAssignments(object, name).some((property) => literalString(property.initializer) === null)) {
        return invalidShape(`sourcemap ${name} must be a string when present`);
      }
    }
    for (const property of propertyAssignments(object, "file")) {
      const value = literalString(property.initializer);
      recordPath("file", value);
      const variants = pathVariants(value);
      if (variants === null) {
        return refuse("sourcemap-unscannable", "a sourcemap file path exceeds bounded percent normalisation");
      }
      for (const variant of variants) {
        if (sourceEscapesPackage(mapPath, "", variant)) {
          findings.push(makeFinding(file, physicalLine(property.initializer), rule, variant, variant));
        }
      }
    }
    for (const name of ["names", "sourcesContent"]) {
      for (const property of propertyAssignments(object, name)) {
        if (!ts.isArrayLiteralExpression(property.initializer)) {
          return invalidShape(`sourcemap ${name} must be an array when present`);
        }
        for (const element of property.initializer.elements) {
          const nullAllowed = name === "sourcesContent" && element.kind === ts.SyntaxKind.NullKeyword;
          if (!nullAllowed && !ts.isStringLiteral(element)) {
            return invalidShape(`sourcemap ${name} contains a non-string entry`);
          }
        }
      }
    }

    if (sourcesProperties.length > 0) {
      const roots = [];
      for (const property of propertyAssignments(object, "sourceRoot")) {
        const value = literalString(property.initializer);
        recordPath("sourceRoot", value);
        const variants = pathVariants(value);
        if (variants === null) {
          return refuse("sourcemap-unscannable", "a sourcemap sourceRoot exceeds bounded percent normalisation");
        }
        for (const variant of variants) {
          const escapes = variant.length > 0 && sourceEscapesPackage(mapPath, "", variant);
          roots.push({ value: variant });
          if (escapes) findings.push(makeFinding(file, physicalLine(property.initializer), rule, variant, variant));
        }
      }
      if (roots.length === 0) roots.push({ value: "" });

      let combinations = 0;
      for (const property of sourcesProperties) {
        if (!ts.isArrayLiteralExpression(property.initializer)) {
          return invalidShape("sourcemap sources must be an array");
        }
        for (const element of property.initializer.elements) {
          if (!ts.isStringLiteral(element) || element.text.length === 0) {
            return invalidShape("sourcemap sources contains an empty or non-string entry");
          }
          recordPath("sources", element.text);
          const variants = pathVariants(element.text);
          if (variants === null) {
            return refuse("sourcemap-unscannable", "a sourcemap source exceeds bounded percent normalisation");
          }
          for (const sourceValue of variants) {
            for (const root of roots) {
              combinations++;
              if (combinations > MAX_STATIC_VALUES) {
                return refuse("sourcemap-unscannable", "sourcemap sourceRoot/source combinations exceed the bounded structural limit");
              }
              const combined = root.value.length === 0 ? sourceValue : `${root.value}/${sourceValue}`;
              if (sourceEscapesPackage(mapPath, root.value, sourceValue)) {
                findings.push(makeFinding(file, physicalLine(element), rule, combined, combined));
              }
            }
          }
        }
      }
      continue;
    }

    for (const property of sectionsProperties) {
      if (!ts.isArrayLiteralExpression(property.initializer)) {
        return invalidShape("indexed sourcemap sections must be an array");
      }
      for (let index = property.initializer.elements.length - 1; index >= 0; index--) {
        const section = property.initializer.elements[index];
        if (!ts.isObjectLiteralExpression(section)) {
          return invalidShape("an indexed sourcemap section must be an object");
        }
        const offsets = propertyAssignments(section, "offset");
        if (offsets.length !== 1 || !ts.isObjectLiteralExpression(offsets[0].initializer)) {
          return invalidShape("an indexed sourcemap section must have one offset object");
        }
        for (const coordinate of ["line", "column"]) {
          const values = propertyAssignments(offsets[0].initializer, coordinate);
          if (values.length !== 1 || !naturalNumber(values[0].initializer)) {
            return invalidShape(`an indexed sourcemap offset ${coordinate} must be one non-negative integer`);
          }
        }
        const urls = propertyAssignments(section, "url");
        if (urls.length > 0) {
          return refuse("sourcemap-external-section", "an indexed sourcemap external section is outside the authenticated packed bytes");
        }
        const nestedMaps = propertyAssignments(section, "map");
        if (nestedMaps.length === 0 || nestedMaps.some((entry) => !ts.isObjectLiteralExpression(entry.initializer))) {
          return invalidShape("an indexed sourcemap section must embed at least one object map");
        }
        for (let nested = nestedMaps.length - 1; nested >= 0; nested--) {
          maps.push({ node: nestedMaps[nested].initializer, depth: current.depth + 1 });
        }
      }
    }
  }

  // `sourcesContent`, extension values and decoded property names remain included through the
  // complete occurrence-preserving traversal above; nested indexed maps receive the same handoff.
  const merged = mergeScanResults([{ findings, suppressed: [] }]);
  return { findings: merged.findings, suppressed: merged.suppressed, contents, paths };
}

export const __testing = Object.freeze({
  digest8,
  suppressionsOnLine,
  physicalSuppressionIndex,
  ARTEFACT_ABS_PATH_RE,
  REPO_REF_RE,
  extractStaticJsValues,
  extractStaticJsonValues,
  percentDecodedValues,
  derivedConfidentialViews,
  databaseAuthorityIsReserved,
  hostPortAuthorityIsReserved,
  repoReferencesIn: (text, allowlist) => repoReferencesIn(String(text), publicRepoSnapshot(allowlist)),
  scanShapesRaw: (file, text, options = {}) => scanShapesRaw(file, text, options.rules ?? SHAPE_RULES),
  scanPrivacyAdjacencyRaw: (file, text, allowlist = null) => scanPrivacyAdjacencyRaw(
    file,
    text,
    allowlist === null ? null : publicRepoSnapshot(allowlist),
  ),
  scanRepoRefsRaw: (file, text, allowlist) => scanRepoRefsRaw(file, text, publicRepoSnapshot(allowlist)),
  scanTokensRaw,
});
