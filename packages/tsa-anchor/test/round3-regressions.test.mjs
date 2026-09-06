/**
 * ROUND-3 REGRESSIONS — the mirror defects.
 *
 * Every finding in this file has the same shape: round 2 fixed the reported defect and created its
 * opposite. A detector that refuses honest input is not safer than one that accepts hostile input;
 * it is the same instrument, broken in the other direction, and in an accusation tool a STANDING
 * FALSE ALARM costs as much as a missed fork — it trains the reader to ignore the output.
 *
 * F8 is the clearest case and it was in my own fix: closing the `sig` schema to stop an anchor being
 * double-keyed made every forward-compatible anchor "malformed", and the round-2 verdict ladder then
 * turned ONE such entry in an otherwise honest pool into a permanent INCOMPLETE_POOL / exit 1.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { generateKeyPair, buildReceipt, buildAnchor, sha256Prefixed } from "noa-receipt";
import { scanForEquivocation, verifyEquivocationProof } from "../src/equivocation.mjs";
import { anchorHash } from "../src/anchor-hash.mjs";
import { verifyStamp } from "../src/verify.mjs";
import { createAuthenticatedTsaFixture } from "./openssl-tsa-fixture.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const WORKFLOW = readFileSync(join(HERE, "..", "..", "..", ".github", "workflows", "publish-tsa.yml"), "utf8");
const CLI_SRC = readFileSync(join(HERE, "..", "src", "cli.mjs"), "utf8");

const CHAIN = "tenant-acme/orders";
const AUTHOR = generateKeyPair("author-r3");
const AUTHOR_SIGNER = { kid: AUTHOR.kid, privateKey: AUTHOR.privateKey };
const W1 = generateKeyPair("witness-r3-1");
const W2 = generateKeyPair("witness-r3-2");
const pin = (kp) => ({ kid: kp.kid, pubkey: kp.publicKey });
const TRUST_SET = { witnesses: [pin(W1), pin(W2)], quorum: 2 };

function buildChainOf(params) {
  const out = [];
  let prev = null;
  for (let i = 0; i < params.length; i++) {
    prev = buildReceipt(
      {
        id: `rcpt_${i}`,
        ts: `2026-06-20T00:0${i}:00.000Z`,
        scope: { tenant: "t", chain: CHAIN },
        agent: { id: "a1", model: null, principal: "SERVICE" },
        action: { id: "db.write", canonical: "db.write", riskClass: "LOW", paramsHash: sha256Prefixed(params[i]), reversible: true, rollbackRef: null },
        governance: { mode: "on", verdict: "EXECUTED", ruleId: "r", approval: null, sandboxed: false },
      },
      prev,
      AUTHOR_SIGNER,
    );
    out.push(prev);
  }
  return out;
}
const anchorOn = (kp, receipts, seq, ts) =>
  buildAnchor({ chain: CHAIN, highestSeq: seq, headHash: receipts[seq].chain.hash, ts }, { kid: kp.kid, privateKey: kp.privateKey });

/** A newer witness that adds a member to `sig` — conventional JSON extensibility, not an attack. */
function withExtendedSig(anchor) {
  const a = JSON.parse(JSON.stringify(anchor));
  a.sig.x5c = ["MIIB-not-a-real-cert"];
  return a;
}

function tsaVerification(fixture) {
  return {
    opensslExecutable: fixture.executable,
    trustRoots: fixture.trustRoots,
    allowedPolicyOids: [fixture.policyOid],
    revocation: { mode: "crl-check-all", crls: fixture.crls },
    clock: { now: new Date().toISOString(), maxFutureSkewMs: 300000 },
  };
}

// ── F8 ──────────────────────────────────────────────────────────────────────────────────────────

test("F8 — one forward-compatible anchor does not condemn an honest pool", () => {
  const chain = buildChainOf(["p0", "p1", "p2"]);
  const pool = [
    anchorOn(W1, chain, 2, "2026-06-23T10:00:00Z"),
    withExtendedSig(anchorOn(W2, chain, 2, "2026-06-23T10:00:01Z")), // a newer witness
  ];
  const res = scanForEquivocation(pool, TRUST_SET);
  assert.equal(res.verdict, "CLEAN", `an added sig member is not an attack signal: ${res.reason}`);
  assert.equal(res.clean, true);
  assert.equal(res.admitted, 2, "the extended anchor must still be ADMITTED and compared");
  assert.equal(res.rejected.malformed, 0);
});

test("F8 — an extended sig is counted as an extension, distinct from bit-rot", () => {
  const chain = buildChainOf(["p0", "p1", "p2"]);
  const res = scanForEquivocation(
    [anchorOn(W1, chain, 2, "2026-06-23T10:00:00Z"), withExtendedSig(anchorOn(W2, chain, 2, "2026-06-23T10:00:01Z")), {}],
    TRUST_SET,
  );
  // A consumer must be able to tell "a newer producer" from "a corrupt entry".
  assert.equal(res.extensions.sigMembers, 1);
  assert.equal(res.rejected.malformed, 1, "the genuinely unusable entry is still counted separately");
});

test("F8 — the double-keying L14 closed stays closed: one anchor, one hash, authenticated stamp attaches", () => {
  const chain = buildChainOf(["p0", "p1", "p2"]);
  const plain = anchorOn(W1, chain, 2, "2026-06-23T10:00:00Z");
  const extended = withExtendedSig(plain);
  const fixture = createAuthenticatedTsaFixture(plain);
  try {
    // THE FIX IS AT THE HASH, NOT THE SCHEMA: an unsigned, unauthenticated extra `sig` member must
    // not change the identity of the anchor, because neither the Ed25519 signature nor the TSA
    // token covers it. Same anchor => same key => the stamp attaches either way.
    assert.equal(anchorHash(extended), anchorHash(plain), "an unsigned extra member must not re-key the anchor");

    const policy = tsaVerification(fixture);
    assert.equal(verifyStamp(extended, fixture.valid, policy).ok, true, "a stamp taken on the plain anchor still covers the extended one");

    const res = scanForEquivocation([extended], TRUST_SET, {
      stamps: { [anchorHash(extended)]: fixture.valid },
      tsaVerification: policy,
    });
    assert.equal(res.admitted, 1);
  } finally {
    fixture.cleanup();
  }
});

test("F8 — a smuggled member still cannot change what the anchor SAYS", () => {
  // The permissive read applies to the sig envelope only. Anything that would alter the frontier is
  // still refused, so "accept unknown members" is not "accept anything".
  const chain = buildChainOf(["p0", "p1", "p2"]);
  const a = JSON.parse(JSON.stringify(anchorOn(W1, chain, 2, "2026-06-23T10:00:00Z")));
  a.sig.alg = "ed448";
  assert.equal(scanForEquivocation([a], TRUST_SET).admitted, 0, "an unknown alg is still refused");

  const b = JSON.parse(JSON.stringify(anchorOn(W1, chain, 2, "2026-06-23T10:00:00Z")));
  b.headHash = "sha256:" + "f".repeat(64);
  const res = scanForEquivocation([b], TRUST_SET);
  assert.equal(res.admitted, 0);
  assert.equal(res.rejected.badSignature, 1, "a rewritten frontier still fails the signature");
});

// ── F11 ─────────────────────────────────────────────────────────────────────────────────────────

test("F11 — the legacy workflow cannot turn an unreviewed tag into a release", () => {
  assert.doesNotMatch(WORKFLOW, /refs\/tags|\bpush:\s*\n|GITHUB_REF|GITHUB_SHA/);
  assert.doesNotMatch(WORKFLOW, /actions\/checkout|npm publish/);
  assert.match(WORKFLOW, /future release controller must use a new\s*\n# workflow file/i);
});

test("F11 — the quarantined workflow owns no deployment environment or write permission", () => {
  assert.doesNotMatch(WORKFLOW, /^\s{4}environment:/m);
  assert.match(WORKFLOW, /^permissions:\s*\{\}\s*$/m);
});

test("F11 — the quarantine contains no candidate checkout or release command", () => {
  assert.doesNotMatch(WORKFLOW, /actions\/checkout|git\s+(?:fetch|checkout)|npm\s+(?:pack|publish)|gh\s+release/);
  assert.match(WORKFLOW, /can never build, stage, or publish candidate bytes/i);
});

// ── F10 ─────────────────────────────────────────────────────────────────────────────────────────

test("F10 — the workflow comment states what is true about workflow_dispatch", () => {
  assert.match(WORKFLOW, /Manual dispatch exists only to make the\s*\n# fail-closed state observable/i);
  assert.match(WORKFLOW, /can never build, stage, or publish candidate bytes/i);
  assert.match(WORKFLOW, /^\s*exit 1\s*$/m);
});

// ── F13 ─────────────────────────────────────────────────────────────────────────────────────────

test("F13 — a valid proof survives crossing a naming domain", () => {
  const a = buildChainOf(["p0", "p1", "x"]);
  const b = buildChainOf(["p0", "p1", "y"]);
  const res = scanForEquivocation(
    [anchorOn(W1, a, 2, "2026-06-23T10:00:00Z"), anchorOn(W1, b, 2, "2026-06-23T10:00:05Z")],
    TRUST_SET,
  );
  const f = res.findings.find((x) => x.kind === "WITNESS_EQUIVOCATION");

  // The recipient pins the SAME key under their own name. `attributedTo` is unauthenticated text;
  // hard-failing on it made the "transferable" proof transferable only inside one organisation.
  const theirs = { witnesses: [{ kid: "their-name-for-w1", pubkey: W1.publicKey }, pin(W2)], quorum: 2 };
  const check = verifyEquivocationProof(f, theirs);
  assert.equal(check.ok, true, `cryptography must not depend on a label: ${check.reason}`);
  assert.equal(check.transferable, true);
  assert.equal(check.attributedToPubkey[0], W1.publicKey);
  assert.deepEqual(check.attributedTo, ["their-name-for-w1"], "attribution is reported in the READER's names");
  assert.equal(check.labelMismatch, true, "...and the disagreement is surfaced, not hidden");
  assert.equal(check.attributedToClaimed[0], W1.kid, "the producer's own label is preserved for comparison");
});

test("F13 — the trust-set digest covers quorum and is labelled as an unauthenticated hint", () => {
  const sameKeysDifferentPolicy = { witnesses: [pin(W1), pin(W2)], quorum: 2 };
  const a = scanForEquivocation([], sameKeysDifferentPolicy);
  const b = scanForEquivocation([], { witnesses: [pin(W1), pin(W2)], quorum: 3 });
  assert.notEqual(a.trustSetDigest, b.trustSetDigest, "trust-sets differing only in quorum must not report the same digest");
});

// ── F12 ─────────────────────────────────────────────────────────────────────────────────────────

test("F12 — a TSA URL is never laundered into re-derived evidence", () => {
  const a = buildChainOf(["p0", "p1", "x"]);
  const b = buildChainOf(["p0", "p1", "y"]);
  const a1 = anchorOn(W1, a, 2, "2026-06-23T10:00:00Z");
  const a2 = anchorOn(W2, b, 2, "2026-06-23T10:00:05Z");
  const fixture = createAuthenticatedTsaFixture(a1);
  try {
    const policy = tsaVerification(fixture);
    const stamps = { [anchorHash(a1)]: fixture.valid, [anchorHash(a2)]: fixture.stampFor(a2) };
    const res = scanForEquivocation([a1, a2], TRUST_SET, { stamps, tsaVerification: policy });

    const f = JSON.parse(JSON.stringify(res.findings[0]));
    f.branches[0].stamp.tsaUrl = "http://attacker.example/tsr"; // the token bytes are untouched
    const check = verifyEquivocationProof(f, TRUST_SET, { tsaVerification: policy });

    const ev = check.stampEvidence[0];
    assert.equal(ev.verified, true, "the token itself still verifies");
    assert.equal(ev.authenticated, true, "re-derived stamp evidence uses the authenticated path");
    assert.equal(ev.code, "OK");
    // A URL is not inside an RFC 3161 token, so it CANNOT be re-derived. It must not sit in a field
    // that reads as re-derived evidence next to `verified:true`.
    assert.equal(ev.tsaUrl, undefined, "no field may present an unauthenticated URL as re-derived");
    assert.equal(ev.tsaUrlClaimed, "http://attacker.example/tsr", "it is carried, but explicitly as a claim");
  } finally {
    fixture.cleanup();
  }
});

// ── F14 / F15 ───────────────────────────────────────────────────────────────────────────────────

test("F14 — no unreachable return follows a fatal exit", () => {
  assert.doesNotMatch(CLI_SRC, /fail\(EXIT\.[A-Z]+,[^\n]*\);\s*\n\s*return EXIT\./, "dead code after fail() misleads the reader about the exit path");
});

test("F15 — 'the scan examined nothing' has its own exit code", () => {
  // Exit 1 covered verify-mismatch, NO_EVIDENCE and INCOMPLETE_POOL, so a pipeline could not tell
  // "this stamp does not match" from "the scan never examined anything".
  assert.match(CLI_SRC, /NO_CLEAN_RESULT:\s*6/, "a distinct code for a scan that ran but earned nothing");
  assert.match(CLI_SRC, /EXIT\.NO_CLEAN_RESULT/);
});

// ── still-open from round 2: truncation must be visible ─────────────────────────────────────────

test("F1/F4/F5 — bound TRUNCATION is reported, not only refused at the floor", () => {
  // One witness signing THREE different heads at one frontier: the finding genuinely carries three
  // branches, so `maxBranches:2` drops one. A legal bound quietly discarding corroboration leaves
  // the reader holding a summary that looks like the whole picture.
  const a = buildChainOf(["p0", "p1", "x"]);
  const b = buildChainOf(["p0", "p1", "y"]);
  const c = buildChainOf(["p0", "p1", "z"]);
  const pool = [
    anchorOn(W1, a, 2, "2026-06-23T10:00:00Z"),
    anchorOn(W1, b, 2, "2026-06-23T10:00:01Z"),
    anchorOn(W1, c, 2, "2026-06-23T10:00:02Z"),
  ];
  const full = scanForEquivocation(pool, TRUST_SET);
  const eq = full.findings.find((f) => f.kind === "WITNESS_EQUIVOCATION");
  assert.equal(eq.branches.length, 3, "all three conflicting heads are carried when nothing is capped");
  assert.equal(full.truncated.branches, 0);
  assert.equal(full.clean, false, "an equivocation is never clean");

  const capped = scanForEquivocation(pool, TRUST_SET, { maxBranches: 2 });
  assert.equal(capped.verdict, "EQUIVOCATION");
  assert.equal(typeof capped.truncated, "object", "truncation must be a reported quantity, not a silent cap");
  assert.ok(capped.truncated.branches > 0, "branches were dropped from a finding and the result must say so");
  // ...and the proof that IS emitted still stands on its own.
  const check = verifyEquivocationProof(capped.findings[0], TRUST_SET);
  assert.equal(check.ok, true, check.reason);
});

test("F6 — an unverified history is reported as the caller's assertion", () => {
  const chain = buildChainOf(["p0", "p1", "p2"]);
  const pool = [anchorOn(W1, chain, 2, "2026-06-23T10:00:00Z"), anchorOn(W2, chain, 2, "2026-06-23T10:00:01Z")];
  const history = [{ chain: CHAIN, seq: 2, hash: chain[2].chain.hash }];

  const unverified = scanForEquivocation(pool, TRUST_SET, { history });
  assert.equal(unverified.historyChecked, true);
  assert.equal(unverified.historyVerified, false, "the library cannot verify a history it was handed; it must say so");

  const declared = scanForEquivocation(pool, TRUST_SET, { history, historyVerified: true });
  assert.equal(declared.historyVerified, true, "a caller that DID verify (the CLI) can declare it");
});
