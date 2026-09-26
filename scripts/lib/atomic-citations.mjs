/**
 * ATOMIC CITATIONS — a published "atomic" names the lines that make it so, and the citation stays true.
 *
 * The published-surface gate (K6 in `scripts/lint-published-surface.mjs`) lets "atomic" through only
 * when the same sentence carries a code anchor that RESOLVES, and it says plainly that it checks the
 * anchor's form, never its truth. A `file:line` anchor resolves as long as the file exists, so the day
 * an edit above a cited block shifts it, the sentence still passes while it points at other code.
 * That happened: a citation of the effect owner's in-process commit named lines that, one refactor
 * later, held something else.
 *
 * THE RULE. Every line citation (`path:N` or `path:N-M`) in a sentence of a checked document that uses
 * the term must name EXACTLY one tagged block: line N carries `ATOMIC-BLOCK: <id>`, line M carries
 * `ATOMIC-BLOCK-END: <id>` with the same id, and no other tag sits between them. The tags live in the
 * source as comments inside the cited block, so moving the block, moving a tag, or shifting any line
 * above or inside it breaks the citation, and this check names the sentence to fix. A path cited
 * without lines is not checked here (it cannot drift). What the block DOES is still a human's call:
 * the tag binds the sentence to the lines, it does not prove the property.
 *
 * Pure: `readSource(path)` supplies file text (or null), so `--selftest` in `lint-doc-truth.mjs` runs it
 * on injected sources, and a gate test runs it on the real tree.
 */

/** The term, as K6 matches it. */
export const ATOMIC_TERM_RE = /\batomic(?:ally|ity)?\b/i;

const CITATION_RE = /^([^\s:]+\.(?:ts|tsx|mjs|cjs|js|go|rs|py|cs)):(\d+)(?:-(\d+))?$/;
const OPEN_TAG_RE = /\bATOMIC-BLOCK: ([a-z0-9][a-z0-9-]*)\b/;
const CLOSE_TAG_RE = /\bATOMIC-BLOCK-END: ([a-z0-9][a-z0-9-]*)\b/;
const LIST_MARKER_RE = /^\s*(?:[-*+]|\d+\.)\s+/;

/** Markdown into items (paragraphs, list entries, headings), skipping fenced code; each keeps its first line number. */
function itemsOf(md) {
  const items = [];
  let current = null;
  let fenced = false;
  const lines = md.split("\n");
  const close = () => {
    if (current !== null) items.push(current);
    current = null;
  };
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/^\s*```/.test(line)) {
      close();
      fenced = !fenced;
      continue;
    }
    if (fenced) continue;
    if (line.trim() === "") {
      close();
      continue;
    }
    if (/^#{1,6}\s/.test(line)) {
      close();
      items.push({ line: i + 1, text: line });
      continue;
    }
    if (LIST_MARKER_RE.test(line)) close();
    if (current === null) current = { line: i + 1, text: line.trim() };
    else current.text += ` ${line.trim()}`;
  }
  close();
  return items;
}

/** Sentences of one item, split like K6: on `.`, `!` or `?` followed by whitespace or the end. */
function sentencesOf(text) {
  const out = [];
  const re = /[.!?]+(?:\s+|$)/g;
  let start = 0;
  let m;
  while ((m = re.exec(text)) !== null) {
    out.push(text.slice(start, m.index + m[0].length));
    start = m.index + m[0].length;
    if (re.lastIndex <= m.index) re.lastIndex = m.index + 1;
  }
  if (start < text.length) out.push(text.slice(start));
  return out;
}

/** Judge one line citation against the source text; returns a problem string or null. */
function citationProblem(path, from, to, text) {
  if (text === null) return `cites ${path}, which is not a file in this repository`;
  const lines = text.split("\n");
  if (from < 1 || to < from || to > lines.length) {
    return `cites ${path}:${from}-${to}, outside the file's ${lines.length} lines`;
  }
  const open = OPEN_TAG_RE.exec(lines[from - 1]);
  if (open === null) return `cites ${path}:${from}-${to}, but line ${from} carries no ATOMIC-BLOCK tag: the cited lines have moved`;
  const shut = CLOSE_TAG_RE.exec(lines[to - 1]);
  if (shut === null) return `cites ${path}:${from}-${to}, but line ${to} carries no ATOMIC-BLOCK-END tag: the cited lines have moved`;
  if (open[1] !== shut[1]) return `cites ${path}:${from}-${to}, which opens block "${open[1]}" and closes block "${shut[1]}"`;
  for (let i = from; i < to - 1; i++) {
    if (OPEN_TAG_RE.test(lines[i]) || CLOSE_TAG_RE.test(lines[i])) {
      return `cites ${path}:${from}-${to}, which spans another ATOMIC-BLOCK tag at line ${i + 1}`;
    }
  }
  return null;
}

/**
 * Every line citation in a sentence of `md` that uses the term, judged against `readSource`.
 * Returns the problems (each naming the document line) and the citations checked, so a caller can
 * refuse a vacuous run.
 */
export function atomicCitationFindings(md, readSource, docName) {
  const problems = [];
  const checked = [];
  for (const item of itemsOf(md)) {
    for (const sentence of sentencesOf(item.text)) {
      if (!ATOMIC_TERM_RE.test(sentence.replace(/`[^`]*`/g, ""))) continue;
      for (const m of sentence.matchAll(/`([^`]+)`/g)) {
        const cite = CITATION_RE.exec(m[1].trim());
        if (cite === null) continue;
        const path = cite[1];
        const from = Number(cite[2]);
        const to = cite[3] === undefined ? from : Number(cite[3]);
        const unsafe = path.startsWith("/") || path.includes("\\") || path.split("/").some((p) => p === "" || p === "." || p === "..");
        const problem = citationProblem(path, from, to, unsafe ? null : readSource(path));
        checked.push({ doc: docName, line: item.line, citation: m[1].trim() });
        if (problem !== null) problems.push(`${docName}:${item.line} ${problem}`);
      }
    }
  }
  return { problems, checked };
}
