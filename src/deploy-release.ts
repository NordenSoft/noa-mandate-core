/**
 * `noa.deploy.release/1` — THE PUBLIC WIRE FORM OF THE DEPLOYMENT BIND.
 *
 * Normative specification: `docs/deploy-release-spec.md`. Conformance corpus:
 * `conformance/deploy-release/vectors.json`.
 *
 * ── WHY THIS EXISTS, STATED AS THE DEFECT IT CLOSES ──────────────────────────────────────────────
 *
 * A deployment receipt carries `action.paramsHash` — the producer's parameter-set commitment
 * (docs/receipt-spec.md; ADR-R-004 in 03_DECISIONS_ADR.md). The enforcing component that produces that
 * hash for a governed deployment is a separate, non-public implementation and does not ship in this
 * package. Without the projection's public form, the hash is therefore a value an offline verifier
 * can only COMPARE, never RECOMPUTE: it cannot check that a disclosed six-field deployment tuple is
 * THE tuple a receipt bound, and two planes that cannot recompute each other's commitment is the
 * exact silent-disagreement class `src/action-digest.ts` was built to close one layer up.
 *
 * This module is the public half, and the split is deliberate: the projection, its registry
 * identity, its canonicalization and its conformance vectors are PUBLIC wire language, because an
 * independent verifier needs every one of them; the enforcement, credential and evidence machinery
 * that OPERATE the language are not part of it. The module is self-contained — it imports nothing
 * that is not already this package's own published primitive.
 *
 * ── THE CONSTRUCTION ─────────────────────────────────────────────────────────────────────────────
 *
 *     params     = { repository, commit, environment, imageDigest, targetAccount, operation }
 *                  every field REQUIRED; any OTHER own key REFUSED (additionalProperties:false);
 *                  · repository / environment / targetAccount — 1..256 chars of
 *                    [A-Za-z0-9._\-:@+/] (no whitespace, no control characters)
 *                  · commit      — exactly 40 LOWERCASE hex (a git SHA; uppercase is REFUSED,
 *                    never normalized: an equivalence class is an attacker's choice of
 *                    representative, and a normalizer on a digest path is a forgery surface)
 *                  · imageDigest — "sha256:" + exactly 64 lowercase hex (the OCI spelling of an
 *                    immutable artifact identity; a mutable tag is refused)
 *                  · operation   — "deploy" | "rollback" (a CLOSED enum; a third value is a code
 *                    change and a new reviewed identity, never a string a caller invents)
 *
 *     paramsHash = "sha256:" + hex(SHA-256(UTF8(JCS(params))))          — RFC 8785 JCS, no domain
 *                  tag: an enforcing producer's derivation must reproduce this byte-identically.
 *
 *     identity   = "sha256:" + hex(SHA-256(UTF8(JCS({id, version, kind, implementation}))))
 *                  where `implementation` is the SHA-256 of the registered adapter's EMITTED
 *                  SOURCE TEXT, pinned here as `DEPLOY_RELEASE_IMPLEMENTATION_DIGEST`.
 *
 *     display    = { Action, Release: "<operation> <repository>@<commit>", Environment, Target,
 *                    Image } — derived from the canonical bytes, one row per bound concern, every
 *                  bound field visible. The `Release` join is INJECTIVE parsed from the RIGHT:
 *                  `commit` is fixed-width (40 hex), so the final 41 characters are always
 *                  `@` + commit, and the charset admits no whitespace, so the first space always
 *                  ends `operation`. Two different bound tuples can never render the same line.
 *
 * WHY NAMED PARAMS AND NOT AN OPAQUE COMMAND STRING: inside a command line those six values are ONE
 * opaque token to every layer above the shell — the human reads flag soup, and re-ordering two
 * flags mints a different `paramsHash` for the identical deployment. As NAMED fields each one is
 * separately validated, separately canonicalized, separately rendered, and JCS key ordering makes
 * the digest a property of the DEPLOYMENT rather than of the caller's serialization order.
 *
 * THE EXTRA-KEYS RULE IS THE LOAD-BEARING HALF. Without it, `{six fields}` and `{six fields,
 * force:true}` share a digest while the extra field is invisible to the approver — so a key the
 * human never saw could ride an approved grant to the executor. An unrecognized own key is refused
 * at validation, exactly like an absent or malformed one. Input arrives as BYTES (ADR §3.1), so
 * symbol keys, accessors, Proxies, inherited properties and revisable reads are unreachable by
 * construction: JSON cannot express them, and the strict parse boundary (`parseDocument`) refuses
 * duplicate keys and `__proto__` before this module sees a value.
 *
 * ── THE PINNED VALUES ARE NORMATIVE EXPECTED VALUES, NOT ATTESTATIONS ────────────────────────────
 *
 * `DEPLOY_RELEASE_IMPLEMENTATION_DIGEST`, the two projection identities and the conformance
 * corpus's `paramsHash` vectors are NORMATIVE: they define what a conforming implementation of
 * `noa.deploy.release/1` must compute. They are NOT evidence about any running system, and the
 * distinction is load-bearing enough to state before anyone builds on them.
 *
 * WHAT THE PUBLIC TESTS ACTUALLY PROVE: that this implementation, the committed corpus and the
 * pinned literals all agree, and that each pin is LOAD-BEARING — a one-character change to any of
 * them turns the suite red (`test/deploy-release.test.ts` asserts exactly that, by mutation, so the
 * pins cannot decay into decoration). That is internal consistency plus anti-vacuity.
 *
 * WHAT THEY CANNOT PROVE, and an earlier revision of this file wrongly implied by calling these
 * "the gate's own vectors" and "deployed reality": nothing here is an authenticated statement from
 * the non-public enforcing implementation. Public CI compares copies of the same literals against
 * this module; if every copy were updated together while the non-public side differed, all public
 * tests would stay green and an offline verifier built from this package would silently disagree
 * with the producer. Cross-plane agreement is established OUT OF BAND (the non-public build runs
 * this corpus) and is NOT re-established by anything in this repository. A signed, versioned parity
 * manifest is the mechanism that would make it checkable here; it does not exist yet, and until it
 * does, "these values match the producer" is a claim this repository cannot verify and therefore
 * does not make.
 *
 * ── WHAT THIS DOES NOT ESTABLISH (read before relying on a match) ────────────────────────────────
 *
 *   - A recomputed `paramsHash` proves the disclosed tuple is the committed parameter set — NOT
 *     that the deployment was authorized, dispatched, executed, or completed. Authorization is the
 *     grant/receipt layer (`docs/action-digest-spec.md`; `src/action-digest.ts`); execution and physical
 *     completion are separate evidence claims (NON-CLAIMS.md). `paramsHash` may legitimately
 *     repeat across retries and is NOT the shared action digest.
 *   - The projection identities are PUBLISHED EXPECTED VALUES, not remote attestation. The
 *     implementation digest is a WITHIN-BUILD commitment computed by the process that runs the
 *     adapter: it proves the identity TRACKS an artifact, never that any particular deployment
 *     actually ran that artifact, and never who reviewed it. An off-box verifier recomputes the
 *     identity from the pinned digest and compares — that is the whole, honest claim.
 *   - The identity commits to the adapter's `run()` source text only; behaviour reached through
 *     its free variables is outside the commitment. Identity equality is a NECESSARY signal for
 *     substitution, never a SUFFICIENT one for equivalence.
 *   - The gate's derived RISK CLASS is deliberately NOT part of this wire language. Risk floors
 *     are an enforcing implementation's own reviewed policy tables — authorization-side policy, not
 *     protocol — and freezing them into a public wire form would turn one operator's policy into
 *     every verifier's constant. What IS protocol: the six bound fields, their refusal rules, the
 *     canonicalization, the digest, the display derivation, and the pinned identities.
 *   - Knowing any value here authorizes nothing. Every constant in this module is safe to publish.
 */

import { canonicalize } from "./jcs.js";
import { sha256Prefixed } from "./hash.js";
import { parseDocument } from "./bytes.js";
import { frozenTable } from "./inert.js";
// CAPTURED INTRINSICS ONLY (ADR §5.5). This module decides what bytes get hashed into a value that
// receipts commit to, so no lookup on a decision path may go through a live, writable slot.
import { hasOwn, isArray, objectCreateNull, objectGetOwnPropertyNames } from "./intrinsics.js";

/** The spec identifier of this wire construct. */
export const DEPLOY_RELEASE_SPEC = "noa.deploy.release/1" as const;

/** The `action.canonical` this projection is registered for. */
export const DEPLOY_RELEASE_CANONICAL = "noa.deploy.release" as const;

/**
 * THE PINNED IMPLEMENTATION-ARTIFACT DIGEST: SHA-256 of the registered adapter's emitted `run()`
 * source text (ADR-0006-A part A shape). It is an INPUT to the identity construction below, not a
 * value this package can re-derive — the artifact is not public; the digest is, and publishing it
 * is what lets an offline verifier recompute the identity instead of trusting a bare hex constant.
 *
 * ⚠ WHAT PUBLISHING THIS DIGEST DOES AND DOES NOT LEAK, stated precisely because an earlier
 * revision of this comment claimed "a digest reveals nothing of the source", which is FALSE and was
 * caught in review. SHA-256 does not yield an unknown preimage — that much is true and is the only
 * true part. It DOES reveal (a) EQUALITY: whether two builds, releases or environments run the same
 * artifact, and (b) CONFIRMATION: anyone holding a candidate source — guessed, leaked, or obtained
 * independently — can test it against this value and get a yes/no. A reviewer of this very module
 * used the published digest to confirm the exact artifact it names. Treat it as a stable
 * FINGERPRINT of a non-public artifact, never as a confidentiality boundary; the security argument
 * for publishing it is that a fingerprint is what an offline verifier needs and that the artifact's
 * secrecy is not load-bearing for any claim made here.
 *
 * If the adapter is ever legitimately re-emitted (a behaviour change or a toolchain bump), this
 * constant, both identity vectors and the conformance corpus move TOGETHER in one commit that says
 * which of the two causes it was. Deleting the pin is never a legitimate response.
 */
export const DEPLOY_RELEASE_IMPLEMENTATION_DIGEST =
  "sha256:51db5df44718981eba71c80356858e1b254fe30ec017c4a4e82c7159f2137bcc" as const;

/** The descriptor a projection identity commits to. JCS sorts the keys; order here is cosmetic. */
export interface ProjectionIdentityDescriptor {
  readonly id: string;
  readonly version: number;
  readonly kind: "actionSchema" | "displayProjection";
  /** `sha256:<64 hex>` over the adapter's emitted source text. */
  readonly implementation: string;
}

/** A pinned projection identity — the `{id, version, hash}` a signed envelope advertises. */
export interface ProjectionIdentity {
  readonly id: string;
  readonly version: number;
  readonly hash: string;
}

/**
 * The identity construction: `sha256Prefixed(JCS(descriptor))`. Exported so a verifier recomputes
 * the pinned identities below from their descriptors instead of comparing against opaque hex.
 */
export function projectionIdentityHash(descriptor: ProjectionIdentityDescriptor): string {
  return sha256Prefixed(
    canonicalize({
      id: descriptor.id,
      version: descriptor.version,
      kind: descriptor.kind,
      implementation: descriptor.implementation,
    }),
  );
}

/**
 * THE REGISTRY ENTRY, as data. An enforcing implementation's projection registry is sealed at load
 * and maps `noa.deploy.release` to an adapter carrying these two identities; the adapter's CODE is
 * that implementation's, the identities are wire language, so the public form of "the registry entry" is the
 * canonical name plus the two pinned identities — and deliberately NOT a runtime registry with a
 * register function, which is the exact attack surface such a seal exists to remove.
 */
export const DEPLOY_RELEASE_SCHEMA_ID: ProjectionIdentity = frozenTable(
  {
    id: "noa.deploy.release.schema",
    version: 1,
    hash: projectionIdentityHash({
      id: "noa.deploy.release.schema",
      version: 1,
      kind: "actionSchema",
      implementation: DEPLOY_RELEASE_IMPLEMENTATION_DIGEST,
    }),
  },
  "<deploy-release schema identity>",
);

export const DEPLOY_RELEASE_DISPLAY_ID: ProjectionIdentity = frozenTable(
  {
    id: "noa.deploy.release.display",
    version: 1,
    hash: projectionIdentityHash({
      id: "noa.deploy.release.display",
      version: 1,
      kind: "displayProjection",
      implementation: DEPLOY_RELEASE_IMPLEMENTATION_DIGEST,
    }),
  },
  "<deploy-release display identity>",
);

/**
 * The closed operation enum, as a TYPE. Published as a union rather than `string` because the
 * validator's rule IS closed: widening the published type to `string` would have told every
 * consumer that a third operation is representable when the runtime refuses it — a type that
 * disagrees with its own validator is a spec defect, and it was caught in review as one.
 */
export type DeployOperation = "deploy" | "rollback";

/** The validated six-field deployment tuple. */
export interface DeployReleaseParams {
  readonly repository: string;
  readonly commit: string;
  readonly environment: string;
  readonly imageDigest: string;
  readonly targetAccount: string;
  readonly operation: DeployOperation;
}

export type DeployReleaseResult =
  | {
      readonly ok: true;
      /** `sha256:` + hex over the JCS canonical form of the six bound fields. */
      readonly paramsHash: string;
      /** The gate-authored approver rendering — every bound field visible, never caller free text. */
      readonly display: Readonly<Record<string, string>>;
      readonly actionSchema: ProjectionIdentity;
      readonly displayProjection: ProjectionIdentity;
    }
  | { readonly ok: false; readonly reason: string };

function fail(reason: string): { readonly ok: false; readonly reason: string } {
  return { ok: false, reason };
}

/**
 * Upper bound on a free-text identifier. Not a DoS control — `parseDocument`'s byte ceiling already
 * bounds the input — but 256 is far beyond any real repository, environment or account identifier
 * and far below anything that could make the approver's rendered line unreadable.
 */
const MAX_LABEL = 256;

/**
 * The character tables, built at module load as frozen null-prototype data (`frozenTable`), so
 * membership is a direct own-property probe rather than a regex. A regex would be one line and is
 * refused on this path: `RegExp.prototype.test` performs a dynamic `exec` lookup on its receiver,
 * so a validator deciding whether 40 characters are a commit SHA would be asking a slot an attacker
 * with code execution can replace.
 */
const LOWER_HEX: Readonly<Record<string, true>> = (() => {
  const t = objectCreateNull<Record<string, true>>();
  const digits = "0123456789abcdef";
  for (let i = 0; i < digits.length; i++) t[digits[i] as string] = true;
  return frozenTable(t, "<deploy-release LOWER_HEX>");
})();

/**
 * The identifier charset: letters, digits, and the separators real deployment targets are spelled
 * with (`.` `_` `-` `:` `@` `+` `/`). WHITESPACE AND CONTROL CHARACTERS ARE REFUSED, and that is a
 * display-integrity control, not tidiness: the `Release` line joins three bound values, and a
 * repository containing a space or newline would make that join ambiguous — two different bound
 * tuples rendering one line is precisely the "the human approved something other than what
 * executed" failure this projection exists to prevent. Refusing the characters keeps the join
 * injective by construction instead of relying on the renderer to escape them.
 */
const LABEL_CHARS: Readonly<Record<string, true>> = (() => {
  const t = objectCreateNull<Record<string, true>>();
  const allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-:@+/";
  for (let i = 0; i < allowed.length; i++) t[allowed[i] as string] = true;
  return frozenTable(t, "<deploy-release LABEL_CHARS>");
})();

/** The closed operation enum. */
const DEPLOY_OPERATIONS: Readonly<Record<string, true>> = frozenTable(
  (() => {
    const t = objectCreateNull<Record<string, true>>();
    t["deploy"] = true;
    t["rollback"] = true;
    return t;
  })(),
  "<deploy-release DEPLOY_OPERATIONS>",
);

/** The SIX recognized param names — `additionalProperties:false`, enforced in code. */
const RECOGNIZED_DEPLOY_KEYS: Readonly<Record<string, true>> = frozenTable(
  (() => {
    const t = objectCreateNull<Record<string, true>>();
    t["repository"] = true;
    t["commit"] = true;
    t["environment"] = true;
    t["imageDigest"] = true;
    t["targetAccount"] = true;
    t["operation"] = true;
    return t;
  })(),
  "<deploy-release RECOGNIZED_DEPLOY_KEYS>",
);

/**
 * ⚠ THE `v[i]` READS BELOW ARE INTENTIONAL AND ARE NOT A PROTOTYPE DISPATCH. Each validator
 * establishes `typeof v === "string"` FIRST, so `v` is a primitive string, and an integer index
 * below `v.length` is resolved by the String exotic object's own [[GetOwnProperty]] — it never
 * consults `String.prototype`. That is why every walk is bounded by `length` rather than by a
 * sentinel: an out-of-range index WOULD reach the prototype. The `typeof` test first is also what
 * closes the kind-coercion class: a Number holding 40 digits, a boolean, and an array of
 * characters are all refused before any length or character test runs.
 */
function asLabel(v: unknown): string | undefined {
  if (typeof v !== "string") return undefined;
  const n = v.length;
  if (n === 0 || n > MAX_LABEL) return undefined;
  for (let i = 0; i < n; i++) {
    if (!hasOwn(LABEL_CHARS, v[i] as string)) return undefined;
  }
  return v;
}

/** Exactly `len` LOWERCASE hex characters. Uppercase is refused, never normalized (see header). */
function asLowerHex(v: unknown, len: number): string | undefined {
  if (typeof v !== "string" || v.length !== len) return undefined;
  for (let i = 0; i < len; i++) {
    if (!hasOwn(LOWER_HEX, v[i] as string)) return undefined;
  }
  return v;
}

const IMAGE_DIGEST_PREFIX = "sha256:";

/** `sha256:` + 64 lowercase hex. The prefix is compared character by character — `startsWith` is a
 *  dispatch, and this module's rule is that no membership decision goes through one. */
function asImageDigest(v: unknown): string | undefined {
  if (typeof v !== "string" || v.length !== IMAGE_DIGEST_PREFIX.length + 64) return undefined;
  for (let i = 0; i < IMAGE_DIGEST_PREFIX.length; i++) {
    if (v[i] !== IMAGE_DIGEST_PREFIX[i]) return undefined;
  }
  for (let i = IMAGE_DIGEST_PREFIX.length; i < v.length; i++) {
    if (!hasOwn(LOWER_HEX, v[i] as string)) return undefined;
  }
  return v;
}

function asOperation(v: unknown): DeployOperation | undefined {
  if (typeof v !== "string") return undefined;
  // The membership probe IS the narrowing: `DEPLOY_OPERATIONS` is the same closed table the type
  // enumerates, so the cast restates a fact the line above just established rather than asserting
  // one it did not. If the table and the union ever diverge, that is a bug in one of two places —
  // `test/deploy-release.test.ts` pins them against each other so the divergence cannot be silent.
  return hasOwn(DEPLOY_OPERATIONS, v) ? (v as DeployOperation) : undefined;
}

/**
 * THE RENDER NODE: the display is derived from OUR OWN canonical bytes, parsed back through the
 * same strict boundary the input came through — so the value that was hashed and the value the
 * human reads have exactly ONE source and cannot describe different deployments. Parsing a string
 * we produced one line earlier cannot fail on hostile input; the `ok:false` arms are kept and
 * returned rather than asserted away, because "this cannot fail" is how checks rot into
 * assumptions.
 */
type DeployView = { ok: true; value: DeployReleaseParams } | { ok: false; reason: string };

function deployView(canonical: string): DeployView {
  const parsed = parseDocument(canonical, "canonical params");
  if (!parsed.ok) return { ok: false, reason: `canonical params did not re-parse: ${parsed.reason}` };
  const v = parsed.value;
  if (typeof v !== "object" || v === null || isArray(v)) {
    return { ok: false, reason: "canonical params are not an object" };
  }
  const o = v as Record<string, unknown>;
  const repository = asLabel(o["repository"]);
  const commit = asLowerHex(o["commit"], 40);
  const environment = asLabel(o["environment"]);
  const imageDigest = asImageDigest(o["imageDigest"]);
  const targetAccount = asLabel(o["targetAccount"]);
  const operation = asOperation(o["operation"]);
  if (!repository || !commit || !environment || !imageDigest || !targetAccount || !operation) {
    return { ok: false, reason: "canonical params lost a required field" };
  }
  return { ok: true, value: { repository, commit, environment, imageDigest, targetAccount, operation } };
}

/**
 * Validate a deployment tuple, canonicalize it, and derive its `paramsHash`, display and pinned
 * identities. BYTES IN (ADR §3.1): the params are a DOCUMENT, parsed by the same strict boundary
 * every other document takes — a caller-owned live object is refused without being traversed.
 *
 * EVERY FIELD IS REQUIRED, and absent, null, empty and malformed are the SAME refusal: an optional
 * bound concept would let two deployments with different targets share a digest, which is the
 * exact-binding property this construct exists to provide. Then the closed-world check: an
 * unrecognized own key is refused so that NO KEY REACHES AN EXECUTOR THAT WAS NOT IN THE BOUND,
 * DISPLAYED SET.
 *
 * @param paramsBytes the deployment tuple as JSON bytes or text
 */
export function projectDeployRelease(paramsBytes: Uint8Array | string): DeployReleaseResult {
  const parsed = parseDocument(paramsBytes, "params");
  if (!parsed.ok) return fail(parsed.reason);
  const v = parsed.value;
  if (typeof v !== "object" || v === null || isArray(v)) {
    return fail("params must be an object");
  }
  const p = v as Record<string, unknown>;
  // ONE READ PER FIELD; each validator returns the very string it was handed. With bytes-in this is
  // trivially capture-once — parsed JSON is plain data — and the discipline is kept anyway so the
  // shape survives a future caller that is not.
  const repository = asLabel(p["repository"]);
  const commit = asLowerHex(p["commit"], 40);
  const environment = asLabel(p["environment"]);
  const imageDigest = asImageDigest(p["imageDigest"]);
  const targetAccount = asLabel(p["targetAccount"]);
  const operation = asOperation(p["operation"]);
  if (!repository || !commit || !environment || !imageDigest || !targetAccount || !operation) {
    return fail(
      "deploy params require { repository, commit:40 lowercase hex, environment, " +
        "imageDigest:sha256 + 64 lowercase hex, targetAccount, operation:deploy|rollback }",
    );
  }

  // additionalProperties:false. Own STRING keys are the whole key set here: JSON cannot carry
  // symbol keys and the strict parser has already refused duplicates and `__proto__`.
  const presentKeys = objectGetOwnPropertyNames(p);
  for (let i = 0; i < presentKeys.length; i++) {
    if (!hasOwn(RECOGNIZED_DEPLOY_KEYS, presentKeys[i] as string)) {
      return fail(
        "deploy params carry an unrecognized field; only " +
          "{ repository, commit, environment, imageDigest, targetAccount, operation } are permitted",
      );
    }
  }

  const snapshot = { repository, commit, environment, imageDigest, targetAccount, operation };

  let canonical: string;
  try {
    canonical = canonicalize(snapshot);
  } catch {
    return fail("params are not JCS-canonicalizable");
  }
  const paramsHash = sha256Prefixed(canonical);
  const bound = deployView(canonical);
  if (!bound.ok) return fail(bound.reason);
  const b = bound.value;

  // Five rows, every bound field visible. The `Release` join is injective parsed from the right —
  // `commit` is fixed-width and the charset admits no whitespace (see the header).
  const display: Record<string, string> = {
    Action: DEPLOY_RELEASE_CANONICAL,
    Release: `${b.operation} ${b.repository}@${b.commit}`,
    Environment: b.environment,
    Target: b.targetAccount,
    Image: b.imageDigest,
  };
  return {
    ok: true,
    paramsHash,
    display,
    actionSchema: DEPLOY_RELEASE_SCHEMA_ID,
    displayProjection: DEPLOY_RELEASE_DISPLAY_ID,
  };
}
