/** Canonical stdlib-only token grammar shared by recovery and the parser-backed scanner. */

import { createHmac } from "node:crypto";

const WORD_RE = /[A-Za-z0-9][A-Za-z0-9._]*/g;
const TOKEN_RE = /[A-Za-z0-9][A-Za-z0-9._-]{2,63}/g;
const COMMITTED_TOKEN_RE = /^[a-z0-9][a-z0-9.#-]{1,62}[a-z0-9#]$/;

const normalizeTokenCandidate = (value) => value
  .toLowerCase()
  .replace(/[\s_/]+/g, "-")
  .replace(/[.\-]+$/, "");

export const collapseDigits = (value) => value.replace(/\d+/g, "#");

export function extractCandidates(text, ngramSizes = [1], options = {}) {
  const out = new Set();
  const sizes = [...new Set(ngramSizes)].filter(
    (size) => Number.isInteger(size) && size >= 1 && size <= 6,
  );
  const safeCompounds = options.safeCompounds instanceof Set ? options.safeCompounds : new Set();

  for (const raw of String(text).split(/\r?\n/)) {
    if (raw.length === 0) continue;
    const protectedRanges = [];
    for (const match of raw.matchAll(TOKEN_RE)) {
      const token = normalizeTokenCandidate(match[0]);
      if (token.length >= 3) out.add(token);
      if (safeCompounds.has(token)) {
        protectedRanges.push([match.index, match.index + match[0].length]);
      } else {
        for (const segment of token.split(/[./\\]/)) {
          if (segment.length >= 3) out.add(segment);
        }
      }
    }

    // Use the same separator grammar as tokenForms(). One-word forms are load-bearing: a
    // committed label remains confidential inside a hyphenated, underscored, or dotted label.
    const words = [...raw.matchAll(WORD_RE)]
      .filter((match) => !protectedRanges.some(
        ([start, end]) => match.index >= start && match.index < end,
      ))
      .flatMap((match) => normalizeTokenCandidate(match[0]).split("-"))
      .filter((word) => word.length > 0);

    if (sizes.includes(1)) {
      for (const word of words) {
        if (word.length >= 3 && word.length <= 64) out.add(word);
        for (const segment of word.split(".")) {
          if (segment.length >= 3 && segment.length <= 64) out.add(segment);
        }
      }
    }
    for (const size of sizes) {
      if (size < 2) continue;
      for (let index = 0; index + size <= words.length; index += 1) {
        const joined = words.slice(index, index + size).join("-");
        if (joined.length <= 64) out.add(joined);
      }
    }
  }
  return out;
}

export const commitToken = (key, candidate) =>
  createHmac("sha256", key).update(candidate, "utf8").digest("hex");

export function tokenForms(line) {
  const token = line.replace(/\s+#.*$/, "").trim().toLowerCase();
  if (token.length === 0 || token.startsWith("#!") || token.startsWith("//")) return [];
  const normalized = normalizeTokenCandidate(token);
  if (normalized.length < 3) return [];
  return [normalized];
}

export const tokenNgramSize = (form) => form.split("-").filter(Boolean).length;

export function reachableTokenForms(line) {
  if (typeof line !== "string" || /[^\x00-\x7f]/.test(line)) {
    throw new TypeError(
      "TOKEN_INPUT_UNREACHABLE: token inputs must use the version-1 ASCII scanner grammar",
    );
  }
  const forms = tokenForms(line);
  if (forms.length === 0) return forms;
  if (forms.length !== 1
      || !COMMITTED_TOKEN_RE.test(forms[0])
      || tokenNgramSize(forms[0]) > 6) {
    throw new TypeError("TOKEN_INPUT_UNREACHABLE: token input is outside the exact scanner grammar");
  }
  const form = forms[0];
  const probe = form.replace(/#/g, "7");
  const candidates = extractCandidates(probe, [tokenNgramSize(form)]);
  if (![...candidates].some(
    (candidate) => candidate === form || collapseDigits(candidate) === form,
  )) {
    throw new TypeError("TOKEN_INPUT_UNREACHABLE: token input cannot round-trip through the scanner");
  }
  return forms;
}
