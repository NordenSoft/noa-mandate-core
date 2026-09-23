/**
 * Deterministic conformance-vector generator for `noa.deploy.release/1` (src/deploy-release.ts;
 * normative specification `docs/deploy-release-spec.md`).
 *
 * Output (`conformance/deploy-release/vectors.json`) is COMMITTED so anyone can re-derive and diff
 * it; CI regenerates and fails on drift. Nothing here depends on the clock, on randomness, or on
 * key material — this construct signs nothing, so unlike the action-digest corpus there is no
 * keyring: every value is a pure function of the committed fixtures.
 *
 * ── THE NORMATIVE PINS, AND WHAT THEY ARE NOT ────────────────────────────────────────────────────
 * The three hex constants below are NORMATIVE EXPECTED VALUES for `noa.deploy.release/1`: a
 * conforming implementation must compute exactly these. The generator THROWS instead of writing if
 * a regeneration cannot reproduce them, so the corpus can never be quietly re-pinned to agree with
 * a drifted implementation — the pins move only in a deliberate commit that says why.
 *
 * They are NOT an authenticated statement from any running system, and an earlier revision of this
 * header wrongly implied otherwise by sourcing them to a private build. This repository can prove
 * that its implementation, its corpus and its literals agree, and that every pin is load-bearing;
 * it CANNOT prove agreement with a non-public producer, because nothing here is signed by one. See
 * the "NORMATIVE EXPECTED VALUES" section of `src/deploy-release.ts` for that limit in full and for
 * the parity manifest that would close it.
 *
 * ── THE FIXTURE IS SYNTHETIC BY CONSTRUCTION ─────────────────────────────────────────────────────
 * `example.invalid/…` (RFC 2606 reserves `.invalid`, so it can never resolve), account ids from the
 * reserved synthetic namespace (`acct-example-N`), and counting-pattern digests that no
 * content-addressed artifact produces. This matters
 * because the fixture is the PREIMAGE of a published hash: anyone can read these values straight
 * back out of the vector file, so a fixture naming a real system would publish that system's
 * metadata. Values that name nothing cannot.
 *
 * Each rejection vector pins the SUBSTRING of the refusal reason it is testing, and the generator
 * REPLAYS every vector against the implementation before writing — a corpus that no longer matches
 * the code it claims to describe is never committed. A rejection that only asserted `ok:false`
 * would pass when an unrelated earlier check fired, which is how a corpus goes green while
 * measuring nothing.
 *
 * ── WHY `npm test` RUNS THIS AFTER THE TEST RUNNER, NOT BEFORE IT ───────────────────────────────
 * The replay makes this generator a detector for every kernel primitive a vector exercises (the
 * strict parser, JCS, SHA-256). As a PREPARATION step it aborted the chain before `node --test`
 * started whenever such a primitive was broken, so the L4 knockout harness, which counts only
 * authored test-runner failures, classified a product-suite mutant of that primitive (measured:
 * `safe-json-proto-rejection`) as MUTATION_DID_NOT_BUILD instead of measuring it. After the
 * runner it still fails `npm test` on any replay mismatch and still regenerates the committed file
 * for the CI drift check, while the authored tests, which replay the committed corpus
 * independently, are observed first.
 */

import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  DEPLOY_RELEASE_SPEC,
  DEPLOY_RELEASE_CANONICAL,
  DEPLOY_RELEASE_IMPLEMENTATION_DIGEST,
  DEPLOY_RELEASE_SCHEMA_ID,
  DEPLOY_RELEASE_DISPLAY_ID,
  projectDeployRelease,
  type ProjectionIdentityDescriptor,
} from "../src/deploy-release.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUT_DIR = join(__dirname, "..", "..", "conformance", "deploy-release");

// ── THE NORMATIVE PINS (see the header: expected values, not attestations) ───────────────────────
const PIN_SCHEMA_HASH = "sha256:181779a415d998bb89e3c07cd42fd247fb272303bbb164faa953a1bcf03d0b70";
const PIN_DISPLAY_HASH = "sha256:75fdd2b6f5674b8a4c274fb08ba7329870501dbb76b9d4646b929a9643b33d3b";
const PIN_PARAMS_HASH = "sha256:97fff28779b378933054a67648b3e4c22dc9f774c7374d6f32f2fec990c58f7a";

if (DEPLOY_RELEASE_SCHEMA_ID.hash !== PIN_SCHEMA_HASH) {
  throw new Error(
    `deploy-release generator: the schema identity does not reproduce the normative pin.\n` +
      `  recomputed: ${DEPLOY_RELEASE_SCHEMA_ID.hash}\n  authority:  ${PIN_SCHEMA_HASH}\n` +
      `Do NOT re-pin to match a drifted implementation; the pin is the normative value. Diagnose the construction or the ` +
      `implementation digest first.`,
  );
}
if (DEPLOY_RELEASE_DISPLAY_ID.hash !== PIN_DISPLAY_HASH) {
  throw new Error(
    `deploy-release generator: the display identity does not reproduce the normative pin.\n` +
      `  recomputed: ${DEPLOY_RELEASE_DISPLAY_ID.hash}\n  authority:  ${PIN_DISPLAY_HASH}`,
  );
}

// ── THE FIXTURES (synthetic by construction, see the header; `_B` values differ in ONE character, because a
// refusal that fires only on an obviously-different value proves the comparison notices something,
// while a one-character drift proves it binds the WHOLE value) ───────────────────────────────────
const COMMIT_A = "0123456789abcdef0123456789abcdef01234567";
const COMMIT_B = "0123456789abcdef0123456789abcdef01234568";
const DIGEST_A = "sha256:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const DIGEST_B = "sha256:00112233445566778899aabbccddeeff00112233445566778899aabbccddeefe";
// Account ids come ONLY from the reserved synthetic namespace `acct-example-N`: a numbered account
// publishes the SHAPE of a real deployment even under a different number. Spelled once, derived
// everywhere below, including inside the raw-JSON literals.
const TARGET_ACCOUNT = "acct-example-1";
const TARGET_ACCOUNT_B = "acct-example-2";

function baseParams(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    repository: "example.invalid/example-service",
    commit: COMMIT_A,
    environment: "staging",
    imageDigest: DIGEST_A,
    targetAccount: TARGET_ACCOUNT,
    operation: "deploy",
    ...overrides,
  };
}

// ── THE VECTOR SHAPES ────────────────────────────────────────────────────────────────────────────
interface IdentityVector {
  name: string;
  note: string;
  descriptor: ProjectionIdentityDescriptor;
  expect: { hash: string };
}
interface ParamsVector {
  name: string;
  note: string;
  /** JSON params document; mutually exclusive with `paramsText`. */
  params?: unknown;
  /** Literal bytes (duplicate keys, `__proto__`, floats, truncation — shapes JSON.stringify of a
   *  parsed value cannot reproduce). */
  paramsText?: string;
  expect:
    | { ok: true; paramsHash: string; display?: Record<string, string> }
    | { ok: false; reasonContains: string };
}
type Vector = IdentityVector | ParamsVector;

const bytesOf = (v: ParamsVector): string =>
  typeof v.paramsText === "string" ? v.paramsText : JSON.stringify(v.params);

/** Replay gate: every vector must hold against the implementation BEFORE it is written. */
function check(v: ParamsVector): ParamsVector {
  const r = projectDeployRelease(bytesOf(v));
  if (v.expect.ok) {
    if (!r.ok) throw new Error(`generator: ${v.name}: expected ACCEPT, got refusal: ${r.reason}`);
    if (r.paramsHash !== v.expect.paramsHash) {
      throw new Error(`generator: ${v.name}: paramsHash ${r.paramsHash} != pinned ${v.expect.paramsHash}`);
    }
    if (v.expect.display && JSON.stringify(r.display) !== JSON.stringify(v.expect.display)) {
      throw new Error(`generator: ${v.name}: display drifted: ${JSON.stringify(r.display)}`);
    }
  } else {
    if (r.ok) throw new Error(`generator: ${v.name}: expected a refusal, got ACCEPT (${r.paramsHash})`);
    if (!r.reason.includes(v.expect.reasonContains)) {
      throw new Error(
        `generator: ${v.name}: refused for the wrong reason.\n  got:      ${r.reason}\n` +
          `  expected: contains "${v.expect.reasonContains}"`,
      );
    }
  }
  return v;
}

/** The paramsHash of a tuple the implementation accepts — for the distinct-digest accept family. */
function hashOf(name: string, params: Record<string, unknown>): string {
  const r = projectDeployRelease(JSON.stringify(params));
  if (!r.ok) throw new Error(`generator: ${name}: expected a valid tuple, got: ${r.reason}`);
  return r.paramsHash;
}

// The refusal families are keyed on the implementation's own phrasings. Absent, null, empty and malformed are
// deliberately ONE refusal (an optional bound concept would let two deployments share a digest),
// so within that family the vector's `note` carries the intent and the reason pins the family.
const REASON_REQUIRE = "deploy params require";
const REASON_EXTRA = "unrecognized field";
const REASON_NOT_OBJECT = "params must be an object";

const vectors: Vector[] = [];

// ── IDENTITY VECTORS — the registry entry, recomputable ──────────────────────────────────────────
vectors.push(
  {
    name: "identity-action-schema",
    note:
      "hash = sha256:hex(SHA-256(UTF8(JCS(descriptor)))). `implementation` is the pinned digest of " +
      "the registered adapter's emitted run() source (ADR-0006-A shape) — a within-build " +
      "commitment published as an expected value, so an offline verifier recomputes the identity " +
      "a signed envelope advertises instead of trusting opaque hex.",
    descriptor: {
      id: "noa.deploy.release.schema",
      version: 1,
      kind: "actionSchema",
      implementation: DEPLOY_RELEASE_IMPLEMENTATION_DIGEST,
    },
    expect: { hash: PIN_SCHEMA_HASH },
  },
  {
    name: "identity-display",
    note:
      "The same artifact under kind displayProjection. The two identities MUST differ: same " +
      "artifact, different role — if a construction ever collapsed them, one of the two roles " +
      "would be unpinned.",
    descriptor: {
      id: "noa.deploy.release.display",
      version: 1,
      kind: "displayProjection",
      implementation: DEPLOY_RELEASE_IMPLEMENTATION_DIGEST,
    },
    expect: { hash: PIN_DISPLAY_HASH },
  },
);

// ── THE ACCEPT VECTORS ───────────────────────────────────────────────────────────────────────────
vectors.push(
  check({
    name: "valid",
    note:
      "The gate's own conformance tuple. paramsHash is the AUTHORITY pin — the exact value the " +
      "a conforming implementation must derive for this deployment.",
    params: baseParams(),
    expect: {
      ok: true,
      paramsHash: PIN_PARAMS_HASH,
      display: {
        Action: DEPLOY_RELEASE_CANONICAL,
        Release: `deploy example.invalid/example-service@${COMMIT_A}`,
        Environment: "staging",
        Target: TARGET_ACCOUNT,
        Image: DIGEST_A,
      },
    },
  }),
  check({
    name: "accept-key-order-irrelevant",
    note:
      "The same deployment serialized in reverse key order binds the SAME digest: JCS sorts keys, " +
      "so the digest is a property of the deployment, not of the caller's serialization. Without " +
      "this, two honest descriptions of one release would produce two grants.",
    paramsText:
      `{"operation":"deploy","targetAccount":"${TARGET_ACCOUNT}","imageDigest":"${DIGEST_A}",` +
      `"environment":"staging","commit":"${COMMIT_A}","repository":"example.invalid/example-service"}`,
    expect: { ok: true, paramsHash: PIN_PARAMS_HASH },
  }),
  check({
    name: "accept-label-at-bound",
    note: "256 characters is the identifier bound, not 255 — the boundary accepts.",
    params: baseParams({ repository: "a".repeat(256) }),
    expect: { ok: true, paramsHash: hashOf("accept-label-at-bound", baseParams({ repository: "a".repeat(256) })) },
  }),
);

// The single-field separation family — the params-plane form of the exact-binding
// attacks 1-3 (change the commit / environment / image digest) plus the remaining three fields.
// Each attacked tuple is itself VALID: an enforcing implementation refuses it because it is DIFFERENT,
// not because it is malformed, so here each must ACCEPT with a digest distinct from every other.
const separations: Array<[string, string, Record<string, unknown>]> = [
  ["accept-distinct-commit", "One character of the SHA — the revision NEXT to the reviewed one.", { commit: COMMIT_B }],
  ["accept-distinct-environment", "A staging approval must never alias production.", { environment: "production" }],
  ["accept-distinct-image", "One character of the artifact digest.", { imageDigest: DIGEST_B }],
  ["accept-distinct-repository", "A different source repository.", { repository: "example.invalid/other-service" }],
  ["accept-distinct-target", "A different target account.", { targetAccount: TARGET_ACCOUNT_B }],
  ["accept-distinct-operation", "A rollback is a DIFFERENT bound action, never a cheaper spelling of the same one.", { operation: "rollback" }],
];
const separationHashes = [PIN_PARAMS_HASH];
for (const [name, why, o] of separations) {
  const h = hashOf(name, baseParams(o));
  separationHashes.push(h);
  vectors.push(
    check({
      name,
      note: `${why} A single-field change MUST move the digest — exact authority permits only the exact attempt.`,
      params: baseParams(o),
      expect: { ok: true, paramsHash: h },
    }),
  );
}
if (new Set(separationHashes).size !== separationHashes.length) {
  throw new Error("generator: two different deployments share a paramsHash — the binding is broken");
}

// The injective-Release-line adversaria: repositories that END in `@`+40-hex, so a left-to-right
// display parser would split at the wrong `@`. Each accepts, and no two may render one line.
const atTail: Array<[string, Record<string, unknown>]> = [
  ["accept-repo-with-at-and-hex-tail", { repository: `example.invalid/svc@${COMMIT_A}` }],
  ["accept-repo-at-tail-other-commit", { repository: `example.invalid/svc@${COMMIT_A}`, commit: COMMIT_B }],
  ["accept-repo-at-tail-transposed", { repository: `example.invalid/svc@${COMMIT_B}`, commit: COMMIT_A }],
];
const releaseLines = new Set<string>();
for (const [name, o] of atTail) {
  const r = projectDeployRelease(JSON.stringify(baseParams(o)));
  if (!r.ok) throw new Error(`generator: ${name}: expected a valid deployment: ${r.reason}`);
  releaseLines.add(r.display["Release"] as string);
  vectors.push(
    check({
      name,
      note:
        "`@` IS a legal identifier character, so the Release line is injective only because " +
        "`commit` is fixed-width and the join is parsed from the RIGHT. Two of these tuples " +
        "rendering one line would mean the human authorizes one of two deployments and cannot " +
        "tell which.",
      params: baseParams(o),
      expect: { ok: true, paramsHash: r.paramsHash },
    }),
  );
}
if (releaseLines.size !== atTail.length) {
  throw new Error("generator: two different deployments rendered the SAME Release line");
}

// ── REFUSALS: not an object ──────────────────────────────────────────────────────────────────────
vectors.push(
  check({ name: "reject-null-params", note: "null is not a params object.", paramsText: "null", expect: { ok: false, reasonContains: REASON_NOT_OBJECT } }),
  check({ name: "reject-string-params", note: "A bare string is not a params object.", paramsText: '"noa.deploy.release"', expect: { ok: false, reasonContains: REASON_NOT_OBJECT } }),
  check({ name: "reject-array-params", note: "An array is not a params object.", paramsText: "[]", expect: { ok: false, reasonContains: REASON_NOT_OBJECT } }),
);

// ── REFUSALS: every field is REQUIRED; absent, null and empty are the SAME refusal ───────────────
for (const k of ["repository", "commit", "environment", "imageDigest", "targetAccount", "operation"]) {
  const absent = baseParams();
  delete absent[k];
  vectors.push(
    check({ name: `reject-${k}-absent`, note: `\`${k}\` missing entirely: an optional bound concept would let two deployments share a digest.`, params: absent, expect: { ok: false, reasonContains: REASON_REQUIRE } }),
    check({ name: `reject-${k}-null`, note: `\`${k}\`: null is not a value, and null-means-default is a second spelling of absent.`, params: baseParams({ [k]: null }), expect: { ok: false, reasonContains: REASON_REQUIRE } }),
    check({ name: `reject-${k}-empty`, note: `\`${k}\`: the empty string is the semantic "unspecified", spelled so a presence check cannot see it.`, params: baseParams({ [k]: "" }), expect: { ok: false, reasonContains: REASON_REQUIRE } }),
  );
}

// ── REFUSALS: kind coercion — a value of the wrong TYPE must never be read as the right one ──────
vectors.push(
  check({
    name: "reject-commit-float-number",
    note:
      "A JSON float shaped like a SHA-sized number. Refused at the BYTE BOUNDARY (the strict " +
      "parser admits integers only) — one layer EARLIER than an object-API validator would refuse " +
      "it, which is the fail-closed direction.",
    paramsText: `{"repository":"example.invalid/example-service","commit":5.1e+39,"environment":"staging","imageDigest":"${DIGEST_A}","targetAccount":"${TARGET_ACCOUNT}","operation":"deploy"}`,
    expect: { ok: false, reasonContains: "non-integer (float/exponent) number not allowed" },
  }),
  check({
    name: "reject-commit-40-digit-integer",
    note: "Forty DIGITS are not forty hex characters, and an unsafe integer is refused at the byte boundary before any field rule runs.",
    paramsText: `{"repository":"example.invalid/example-service","commit":${"1".repeat(40)},"environment":"staging","imageDigest":"${DIGEST_A}","targetAccount":"${TARGET_ACCOUNT}","operation":"deploy"}`,
    expect: { ok: false, reasonContains: "integer outside safe range" },
  }),
  check({ name: "reject-commit-char-array", note: "An array of 40 one-character strings is not a string.", params: baseParams({ commit: COMMIT_A.split("") }), expect: { ok: false, reasonContains: REASON_REQUIRE } }),
  check({ name: "reject-operation-boolean", note: "A boolean is not an operation.", params: baseParams({ operation: true }), expect: { ok: false, reasonContains: REASON_REQUIRE } }),
  check({ name: "reject-repository-object", note: "An object is not a repository identifier — nothing is coerced to string on this path.", params: baseParams({ repository: {} }), expect: { ok: false, reasonContains: REASON_REQUIRE } }),
);

// ── REFUSALS: the commit is EXACTLY 40 lowercase hex ─────────────────────────────────────────────
vectors.push(
  check({ name: "reject-commit-39-hex", note: "39 hex is not a full SHA — a near-miss must not be a near-accept.", params: baseParams({ commit: COMMIT_A.slice(0, 39) }), expect: { ok: false, reasonContains: REASON_REQUIRE } }),
  check({ name: "reject-commit-41-hex", note: "41 hex is not a full SHA.", params: baseParams({ commit: COMMIT_A + "0" }), expect: { ok: false, reasonContains: REASON_REQUIRE } }),
  check({ name: "reject-commit-uppercase", note: "Uppercase is REFUSED, not normalized: an equivalence class is an attacker's choice of representative, and a normalizer on a digest path is a forgery surface.", params: baseParams({ commit: COMMIT_A.toUpperCase() }), expect: { ok: false, reasonContains: REASON_REQUIRE } }),
  check({ name: "reject-commit-non-hex-g", note: "`g` is not a hex character.", params: baseParams({ commit: COMMIT_A.slice(0, 39) + "g" }), expect: { ok: false, reasonContains: REASON_REQUIRE } }),
  check({ name: "reject-commit-cyrillic-homoglyph", note: "U+0430 CYRILLIC SMALL A renders as `a` and is not hex — a homoglyph must not survive a charset walk.", params: baseParams({ commit: COMMIT_A.slice(0, 39) + "а" }), expect: { ok: false, reasonContains: REASON_REQUIRE } }),
);

// ── REFUSALS: the image digest is `sha256:` + exactly 64 lowercase hex ───────────────────────────
vectors.push(
  check({ name: "reject-image-no-prefix", note: "64 bare hex without the `sha256:` prefix is not the OCI spelling.", params: baseParams({ imageDigest: DIGEST_A.slice(7) }), expect: { ok: false, reasonContains: REASON_REQUIRE } }),
  check({ name: "reject-image-sha512-prefix", note: "A different hash family is a different identity scheme, not a variant spelling.", params: baseParams({ imageDigest: "sha512:" + DIGEST_A.slice(7) }), expect: { ok: false, reasonContains: REASON_REQUIRE } }),
  check({ name: "reject-image-63-hex", note: "63 hex after the prefix.", params: baseParams({ imageDigest: "sha256:" + "3".repeat(63) }), expect: { ok: false, reasonContains: REASON_REQUIRE } }),
  check({ name: "reject-image-65-hex", note: "65 hex after the prefix.", params: baseParams({ imageDigest: "sha256:" + "3".repeat(65) }), expect: { ok: false, reasonContains: REASON_REQUIRE } }),
  check({ name: "reject-image-mutable-tag", note: "`latest` is a mutable tag; the bound artifact must be an immutable digest or the approved image is whatever the registry says tomorrow.", params: baseParams({ imageDigest: "latest" }), expect: { ok: false, reasonContains: REASON_REQUIRE } }),
);

// ── REFUSALS: the operation is a CLOSED enum ─────────────────────────────────────────────────────
vectors.push(
  check({ name: "reject-operation-not-a-member", note: "`restart` is not in {deploy, rollback}; a third operation is a code change and a new reviewed identity.", params: baseParams({ operation: "restart" }), expect: { ok: false, reasonContains: REASON_REQUIRE } }),
  check({ name: "reject-operation-case-sensitive", note: "`DEPLOY` is not `deploy` — the enum is exact.", params: baseParams({ operation: "DEPLOY" }), expect: { ok: false, reasonContains: REASON_REQUIRE } }),
  check({ name: "reject-operation-proto-string", note: "A null-prototype membership table has no inherited members: `__proto__` as a VALUE is just a non-member string.", params: baseParams({ operation: "__proto__" }), expect: { ok: false, reasonContains: REASON_REQUIRE } }),
  check({ name: "reject-operation-constructor-string", note: "Same class: `constructor` is not an operation.", params: baseParams({ operation: "constructor" }), expect: { ok: false, reasonContains: REASON_REQUIRE } }),
  check({ name: "reject-operation-tostring-string", note: "Same class: `toString` is not an operation.", params: baseParams({ operation: "toString" }), expect: { ok: false, reasonContains: REASON_REQUIRE } }),
);

// ── REFUSALS: identifiers — bounded, no whitespace, no control characters ────────────────────────
vectors.push(
  check({ name: "reject-repository-space", note: "A space would make the rendered Release line ambiguous — two bound tuples, one line.", params: baseParams({ repository: "example.invalid/svc staging" }), expect: { ok: false, reasonContains: REASON_REQUIRE } }),
  check({ name: "reject-repository-newline", note: "A newline can rewrite what the approver reads below it.", params: baseParams({ repository: "example.invalid/svc\nstaging" }), expect: { ok: false, reasonContains: REASON_REQUIRE } }),
  check({ name: "reject-environment-tab", note: "A tab is a control character.", params: baseParams({ environment: "stag\ting" }), expect: { ok: false, reasonContains: REASON_REQUIRE } }),
  check({ name: "reject-target-nul", note: "A NUL byte truncates in every C-adjacent renderer it meets.", params: baseParams({ targetAccount: "acct\u0000-4711" }), expect: { ok: false, reasonContains: REASON_REQUIRE } }),
  check({ name: "reject-target-ansi-escape", note: "An ANSI escape can repaint a terminal renderer over the value the human is comparing.", params: baseParams({ targetAccount: "acct\u001b[31m-4711" }), expect: { ok: false, reasonContains: REASON_REQUIRE } }),
  check({ name: "reject-repository-over-max-label", note: "257 characters — one past the bound (`accept-label-at-bound` holds the other side).", params: baseParams({ repository: "a".repeat(257) }), expect: { ok: false, reasonContains: REASON_REQUIRE } }),
);

// ── REFUSALS: additionalProperties:false — NO KEY RIDES THAT THE APPROVER DID NOT SEE ────────────
// The exact reproduction of the extra-keys CRITICAL: before the rule existed, every tuple below
// was ACCEPTED with the SAME paramsHash as `valid`, the extras were invisible to the approver, and
// an enforcing implementation would hand them to the executor under an approved clean grant.
const extras: Array<[string, string, Record<string, unknown>]> = [
  ["reject-extra-force", "A scalar extra — the flag from the measured finding.", { force: true }],
  ["reject-extra-deployment-command", "A string extra that would drive a side effect.", { deploymentCommand: "delete-before-deploy" }],
  ["reject-extra-nested-object", "A nested-object extra.", { nested: { replicas: 9000 } }],
  ["reject-extra-full-hostile-tuple", "The full hostile tuple from the finding.", { force: true, deploymentCommand: "delete-before-deploy", nested: { replicas: 9000 } }],
  ["reject-extra-case-variant-key", "`Operation` differs from a recognized key only in case — still unrecognized.", { Operation: "rollback" }],
  ["reject-extra-leading-space-key", "A leading-space variant of a recognized key.", { " operation": "rollback" }],
  ["reject-extra-lookalike-key", "`operation2`, a lookalike.", { operation2: "rollback" }],
  ["reject-extra-junk-x", "An arbitrary unrecognized key.", { x: "anything" }],
  ["reject-extra-proto-lookalike", "`__proto__x` — prototype-flavoured but just an unrecognized own key.", { __proto__x: "anything" }],
  ["reject-extra-command-exec-argv", "A key from ANOTHER action schema (`argv`) does not become legal here.", { argv: ["-rf", "/srv"] }],
  ["reject-extra-command-exec-cwd", "Same class: `cwd`.", { cwd: "/srv" }],
  ["reject-extra-command-exec-executable", "Same class: `executable`.", { executable: "/bin/sh" }],
  ["reject-extra-command-exec-target-env", "Same class: `targetEnv`.", { targetEnv: "prod" }],
];
for (const [name, why, o] of extras) {
  vectors.push(
    check({
      name,
      note: `${why} An unrecognized own key is refused at validation, exactly like an absent or malformed field.`,
      params: { ...baseParams(), ...o },
      expect: { ok: false, reasonContains: REASON_EXTRA },
    }),
  );
}

// ── REFUSALS: the byte boundary itself ───────────────────────────────────────────────────────────
vectors.push(
  check({
    name: "reject-duplicate-commit-key",
    note:
      "TWO `commit` members, different SHAs. Every mainstream JSON.parse keeps the LAST silently, " +
      "so the approver-visible value and the last-writer value can disagree; the strict boundary " +
      "refuses the document instead of choosing a winner.",
    paramsText:
      `{"repository":"example.invalid/example-service","commit":"${COMMIT_B}","commit":"${COMMIT_A}",` +
      `"environment":"staging","imageDigest":"${DIGEST_A}","targetAccount":"${TARGET_ACCOUNT}","operation":"deploy"}`,
    expect: { ok: false, reasonContains: "duplicate object key" },
  }),
  check({
    name: "reject-proto-own-key",
    note: "`__proto__` as an OWN KEY is refused at the parse boundary before this projection sees a value.",
    paramsText:
      `{"__proto__":{"operation":"rollback"},"repository":"example.invalid/example-service","commit":"${COMMIT_A}",` +
      `"environment":"staging","imageDigest":"${DIGEST_A}","targetAccount":"${TARGET_ACCOUNT}","operation":"deploy"}`,
    expect: { ok: false, reasonContains: "forbidden object key" },
  }),
  check({
    name: "reject-truncated-json",
    note: "Truncated bytes. The refusal comes from the shared strict parser, and the pinned reason says so.",
    paramsText: '{"repository":',
    expect: { ok: false, reasonContains: "unexpected end of input" },
  }),
);

const out = {
  spec: DEPLOY_RELEASE_SPEC,
  canonical: DEPLOY_RELEASE_CANONICAL,
  generatedFrom: "scripts/gen-deploy-release-vectors.ts",
  implementationDigest: DEPLOY_RELEASE_IMPLEMENTATION_DIGEST,
  note:
    "Generated, committed and diff-gated. This construct signs nothing, so there is no keyring: " +
    "every value is a pure function of the committed fixtures, and the fixture tuple is SYNTHETIC " +
    "BY CONSTRUCTION (RFC 2606 `.invalid` host, reserved `acct-example-N` accounts, counting-pattern digests) — it " +
    "describes no real system. The three pinned hashes (both projection identities and the `valid` " +
    "vector's paramsHash) are NORMATIVE EXPECTED VALUES: they define what a conforming " +
    "implementation MUST compute, and the generator refuses to write if a regeneration cannot " +
    "reproduce them byte-identically. They are NOT attestations about any running system, and this " +
    "corpus cannot prove agreement with a non-public producer — every copy compared here is public, " +
    "so all of them could move together while some other implementation differed. Closing that gap " +
    "needs a signed cross-implementation parity manifest, which does not exist (NON-CLAIMS.md §S6).",
  vectors,
};

mkdirSync(OUT_DIR, { recursive: true });
writeFileSync(join(OUT_DIR, "vectors.json"), JSON.stringify(out, null, 2) + "\n");
console.error(`wrote conformance/deploy-release/vectors.json — ${vectors.length} vectors`);
