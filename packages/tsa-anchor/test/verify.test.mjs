import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { generateKeyPair, buildAnchor } from "noa-receipt";
import { stampAnchor } from "../src/client.mjs";
import { createVerificationResourceBudget, inspectStamp, verifyStamp } from "../src/verify.mjs";
import * as packageApi from "noa-tsa-anchor";
import { anchorHashDigest } from "../src/anchor-hash.mjs";
import { SHA256_OID } from "../src/tsq.mjs";
import { derDecode, encInteger, encOid, encNull, encOctetString, encSequence, encSet, encContext, encGeneralizedTime, readOid } from "../src/der.mjs";
import { startMockTsa } from "./mock-tsa-server.mjs";
import { createAuthenticatedTsaFixture } from "./openssl-tsa-fixture.mjs";

function mkAnchor(headHashSuffix, kid) {
  const kp = generateKeyPair(kid);
  const frontier = { chain: "tenant-acme/orders", highestSeq: 5, headHash: "sha256:" + headHashSuffix.repeat(64), ts: "2026-06-23T10:00:00Z" };
  return buildAnchor(frontier, { kid: kp.kid, privateKey: kp.privateKey });
}

const ID_SIGNED_DATA = "1.2.840.113549.1.7.2";
const ID_CT_TST_INFO = "1.2.840.113549.1.9.16.1.4";

/** Forge a structurally matching but deliberately unsigned TimeStampResp. */
function forgeToken({ hashAlgOid, hashedMessage, policy = encOid("1.2.3.4.5") }) {
  const messageImprint = encSequence([encSequence([encOid(hashAlgOid), encNull()]), encOctetString(hashedMessage)]);
  const tstInfo = encSequence([encInteger(1), policy, messageImprint, encInteger(1), encGeneralizedTime(new Date())]);
  const encap = encSequence([encOid(ID_CT_TST_INFO), encContext(0, encOctetString(tstInfo))]);
  const signedData = encSequence([encInteger(3), encSet([encSequence([encOid(SHA256_OID), encNull()])]), encap, encSet([])]);
  const resp = encSequence([encSequence([encInteger(0)]), encSequence([encOid(ID_SIGNED_DATA), encContext(0, signedData)])]);
  return resp.toString("base64");
}

const authenticatedAnchor = mkAnchor("a", "witness-verify-authenticated");
let fixture;
let policy;

before(() => {
  fixture = createAuthenticatedTsaFixture(authenticatedAnchor);
  policy = {
    opensslExecutable: fixture.executable,
    trustRoots: fixture.trustRoots,
    allowedPolicyOids: [fixture.policyOid],
    revocation: { mode: "crl-check-all", crls: fixture.crls },
    clock: { now: new Date().toISOString(), maxFutureSkewMs: 300000 },
  };
});

after(() => fixture?.cleanup());

test("package surface exports authenticated verification and explicit unauthenticated inspection", () => {
  assert.equal(packageApi.verifyStamp, verifyStamp);
  assert.equal(packageApi.inspectStamp, inspectStamp);
  assert.equal(packageApi.createVerificationResourceBudget, undefined, "the CLI resource capability is internal, not public API");
  assert.equal(packageApi.OPENSSL_PROCESS_BUDGET_PER_STAMP, undefined);
  assert.equal(packageApi.MAX_VERIFICATION_UNIQUE_ANCHORS, undefined);
});

test("verifyStamp: a cryptographically signed trusted RFC 3161 token passes the one authenticated path", () => {
  const res = verifyStamp(authenticatedAnchor, fixture.valid, policy);
  assert.equal(res.ok, true, res.reason);
  assert.equal(res.authenticated, true);
  assert.equal(res.code, "OK");
  assert.equal(res.verification.backend, "openssl-3");
  assert.equal(res.verification.revocation.status, "GOOD");
  assert.match(res.genTime, /^\d{4}-\d{2}-\d{2}T/);
});

test("verifyStamp: a caller cannot forge the CLI's opaque resource-budget capability", () => {
  const forgedArgument = verifyStamp(authenticatedAnchor, fixture.valid, policy, {});
  assert.equal(forgedArgument.ok, false);
  assert.equal(forgedArgument.code, "VERIFICATION_RESOURCE_LIMIT");

  const forgedOption = verifyStamp(authenticatedAnchor, fixture.valid, { ...policy, resourceBudget: {} });
  assert.equal(forgedOption.ok, false);
  assert.equal(forgedOption.code, "VERIFICATION_POLICY_INVALID");
});

test("resource budget registry: discarded capability tokens are not strongly retained", () => {
  const verifyModule = new URL("../src/verify.mjs", import.meta.url).href;
  const source = `
    const { createVerificationResourceBudget } = await import(${JSON.stringify(verifyModule)});
    const collect = () => { for (let i = 0; i < 8; i++) globalThis.gc(); };
    for (let warmup = 0; warmup < 2; warmup++) {
      for (let i = 0; i < 250000; i++) createVerificationResourceBudget(100, 1);
      collect();
    }
    const before = process.memoryUsage().heapUsed;
    for (let i = 0; i < 250000; i++) createVerificationResourceBudget(100, 1);
    collect();
    const after = process.memoryUsage().heapUsed;
    process.stdout.write(JSON.stringify({ before, after, delta: after - before }));
  `;
  const child = spawnSync(process.execPath, ["--expose-gc", "--input-type=module", "--eval", source], {
    encoding: "utf8",
    shell: false,
    timeout: 30000,
    maxBuffer: 1024 * 1024,
  });
  assert.equal(child.status, 0, child.stderr || child.error?.message);
  const observed = JSON.parse(child.stdout);
  assert.ok(
    observed.delta < 2 * 1024 * 1024,
    `discarded resource capabilities must not be strongly retained after GC: delta=${observed.delta}`,
  );
});

test("resource budget registry: captured WeakMap operations resist same-realm poisoning", () => {
  const OriginalWeakMap = globalThis.WeakMap;
  const globalDescriptor = Object.getOwnPropertyDescriptor(globalThis, "WeakMap");
  const getDescriptor = Object.getOwnPropertyDescriptor(OriginalWeakMap.prototype, "get");
  const setDescriptor = Object.getOwnPropertyDescriptor(OriginalWeakMap.prototype, "set");
  let poisonCalls = 0;
  let token;
  let authenticated;
  let forged;
  try {
    Object.defineProperty(globalThis, "WeakMap", {
      ...globalDescriptor,
      value: function PoisonedWeakMap() {
        poisonCalls++;
        throw new Error("live WeakMap constructor invoked");
      },
    });
    Object.defineProperty(OriginalWeakMap.prototype, "get", {
      ...getDescriptor,
      value() {
        poisonCalls++;
        throw new Error("live WeakMap.prototype.get invoked");
      },
    });
    Object.defineProperty(OriginalWeakMap.prototype, "set", {
      ...setDescriptor,
      value() {
        poisonCalls++;
        throw new Error("live WeakMap.prototype.set invoked");
      },
    });
    token = createVerificationResourceBudget(30000, 5);
    authenticated = verifyStamp(authenticatedAnchor, fixture.valid, policy, token);
    forged = verifyStamp(authenticatedAnchor, fixture.valid, policy, {});
  } finally {
    Object.defineProperty(globalThis, "WeakMap", globalDescriptor);
    Object.defineProperty(OriginalWeakMap.prototype, "get", getDescriptor);
    Object.defineProperty(OriginalWeakMap.prototype, "set", setDescriptor);
  }
  assert.notEqual(token, null);
  assert.equal(authenticated.ok, true, authenticated.reason);
  assert.equal(forged.code, "VERIFICATION_RESOURCE_LIMIT");
  assert.equal(poisonCalls, 0, "resource capability state must use captured WeakMap operations only");
});

test("verifyStamp: REJECTS a stamp checked against a DIFFERENT anchor (wrong-hash-tsr rejection)", async () => {
  const anchorB = mkAnchor("b", "witness-verify-2b");
  const res = verifyStamp(anchorB, fixture.valid, policy);
  assert.equal(res.ok, false, "a stamp for anchor A must NOT verify against anchor B");
  assert.equal(res.code, "MESSAGE_IMPRINT_MISMATCH");
  assert.match(res.reason, /does not match/i);
});

test("verifyStamp: REJECTS a stamp whose stored anchorHash field was tampered", async () => {
  const tampered = { ...fixture.valid, anchorHash: "sha256:" + "0".repeat(64) };
  const res = verifyStamp(authenticatedAnchor, tampered, policy);
  assert.equal(res.ok, false);
  assert.equal(res.code, "ANCHOR_HASH_MISMATCH");
});

test("verifyStamp: REJECTS a .tsr obtained for a rejected/no-token response (never fabricates a pass)", async () => {
  // Simulate an operator hand-editing a stamp record to reference a rejection .tsr — verifyStamp
  // must independently re-derive granted:false from the DER bytes, not trust any caller-supplied field.
  const mock = await startMockTsa({ mode: "reject" });
  const rejectedRaw = await new Promise((resolve) => {
    // Directly hit the mock's "reject" behaviour by making the same request the client would.
    import("../src/tsq.mjs").then(async ({ buildTimeStampReq }) => {
      const req = buildTimeStampReq(Buffer.alloc(32, 0x01), { certReq: false });
      const res = await fetch(mock.url, { method: "POST", headers: { "content-type": "application/timestamp-query" }, body: req });
      resolve(Buffer.from(await res.arrayBuffer()));
    });
  });
  await mock.close();
  const anchor = mkAnchor("d", "witness-verify-4");
  const fakeStamp = { anchorHash: undefined, tsr: rejectedRaw.toString("base64") };
  const res = verifyStamp(anchor, fakeStamp);
  assert.equal(res.ok, false);
  assert.match(res.reason, /not grant/i);
});

test("verifyStamp: REJECTS a token that carries the correct digest bytes but LIES about the hashAlgorithm", () => {
  const anchor = mkAnchor("f", "witness-verify-alg");
  const digest = anchorHashDigest(anchor); // the anchor's real 32-byte sha256 digest
  // A conformant token would label these bytes sha256; this one claims sha384 (2.16.840.1.101.3.4.2.2).
  // The messageImprint bytes still equal expectedDigest, so the bytes-only check alone would pass.
  const forged = forgeToken({ hashAlgOid: "2.16.840.1.101.3.4.2.2", hashedMessage: digest });
  const res = verifyStamp(anchor, { tsr: forged });
  assert.equal(res.ok, false, "a wrong-hashAlg token must not verify even when the digest bytes match");
  assert.match(res.reason, /hashAlgorithm/i);
  // Control: the same bytes labelled sha256 pass structural inspection, but an unsigned token can
  // never become an authenticated success.
  const honest = forgeToken({ hashAlgOid: SHA256_OID, hashedMessage: digest });
  assert.equal(inspectStamp(anchor, { tsr: honest }).structurallyValid, true);
  assert.equal(verifyStamp(anchor, { tsr: honest }, policy).code, "CMS_SIGNER_COUNT_INVALID");
});

test("verifyStamp: never throws — malformed/corrupted base64 returns ok:false", () => {
  const anchor = mkAnchor("e", "witness-verify-5");
  assert.doesNotThrow(() => {
    const res = verifyStamp(anchor, { tsr: "***not-base64-der***" });
    assert.equal(res.ok, false);
  });
  assert.doesNotThrow(() => {
    const res = verifyStamp(anchor, {});
    assert.equal(res.ok, false);
  });
});

test("control knockout: removing CMS signerInfos from matching content turns authenticated PASS red", () => {
  assert.equal(verifyStamp(authenticatedAnchor, fixture.valid, policy).ok, true, "control-present token must authenticate");
  const unsigned = { tsr: forgeToken({ hashAlgOid: SHA256_OID, hashedMessage: anchorHashDigest(authenticatedAnchor) }) };
  const inspected = inspectStamp(authenticatedAnchor, unsigned);
  assert.equal(inspected.structurallyValid, true, "knockout retains the same structural imprint control");
  assert.equal(inspected.authenticated, false);
  const removed = verifyStamp(authenticatedAnchor, unsigned, policy);
  assert.equal(removed.ok, false);
  assert.equal(removed.code, "CMS_SIGNER_COUNT_INVALID");
});

test("verifyStamp: rejects bad CMS signature, wrong root, validity, EKU, policy, security level, and revocation failures", () => {
  const cases = [
    ["bad CMS signature", fixture.badSignature, policy, "RFC3161_AUTHENTICATION_FAILED"],
    ["wrong trust root", fixture.valid, { ...policy, trustRoots: fixture.wrongTrustRoots }, "TRUST_CHAIN_INVALID"],
    ["expired signer", fixture.expired, policy, "SIGNER_CERTIFICATE_EXPIRED"],
    ["not-yet-valid signer", fixture.future, policy, "SIGNER_CERTIFICATE_NOT_YET_VALID"],
    ["wrong timestamp EKU", fixture.wrongEku, policy, "TIMESTAMP_SIGNER_EKU_INVALID"],
    ["disallowed TSTInfo policy", fixture.otherPolicy, policy, "TSTINFO_POLICY_DISALLOWED"],
    ["weak signing key", fixture.weak, policy, "ALGORITHM_SECURITY_LEVEL_NOT_MET"],
    ["revoked signer", fixture.revoked, policy, "SIGNER_CERTIFICATE_REVOKED"],
    ["stale required CRL", fixture.valid, { ...policy, revocation: { mode: "crl-check-all", crls: fixture.staleCrls } }, "REVOCATION_EVIDENCE_UNAVAILABLE"],
  ];
  for (const [label, stamp, verificationPolicy, code] of cases) {
    const res = verifyStamp(authenticatedAnchor, stamp, verificationPolicy);
    assert.equal(res.ok, false, `${label} must fail closed`);
    assert.equal(res.authenticated, false, label);
    assert.equal(res.code, code, label);
  }
});

test("verifyStamp: RSASSA-PSS with an unsupported SHA-1 MGF profile is rejected by OID allowlist", () => {
  const inspected = inspectStamp(authenticatedAnchor, fixture.pssMgf1Sha1);
  assert.equal(inspected.signerSignatureAlgOid, "1.2.840.113549.1.1.10");
  const res = verifyStamp(authenticatedAnchor, fixture.pssMgf1Sha1, policy);
  assert.equal(res.ok, false);
  assert.equal(res.code, "CMS_SIGNATURE_ALGORITHM_DISALLOWED");
});

test("verifyStamp: missing explicit trust, policy, revocation, clock, or backend configuration fails with stable codes", () => {
  const cases = [
    [undefined, "VERIFICATION_POLICY_REQUIRED"],
    [{ ...policy, opensslExecutable: undefined }, "OPENSSL_EXECUTABLE_REQUIRED"],
    [{ ...policy, trustRoots: undefined }, "TRUST_ROOTS_REQUIRED"],
    [{ ...policy, allowedPolicyOids: undefined }, "TSTINFO_POLICY_REQUIRED"],
    [{ ...policy, revocation: undefined }, "REVOCATION_POLICY_REQUIRED"],
    [{ ...policy, revocation: { mode: "crl-check-all" } }, "REVOCATION_EVIDENCE_REQUIRED"],
    [{ ...policy, clock: undefined }, "CLOCK_POLICY_REQUIRED"],
    [{ ...policy, clock: { now: new Date().toISOString(), maxFutureSkewMs: 300001 } }, "CLOCK_POLICY_INVALID"],
  ];
  for (const [verificationPolicy, code] of cases) {
    const res = verifyStamp(authenticatedAnchor, fixture.valid, verificationPolicy);
    assert.equal(res.ok, false);
    assert.equal(res.code, code);
  }
  const unavailable = verifyStamp(authenticatedAnchor, fixture.valid, { ...policy, opensslExecutable: "/definitely/not/an/openssl" });
  assert.equal(unavailable.code, "OPENSSL_UNAVAILABLE");
});

test("verifyStamp: explicit clock rejects a trusted-key token whose signed genTime is too far in the future", () => {
  const res = verifyStamp(authenticatedAnchor, fixture.futureGenTime, policy);
  assert.equal(res.ok, false);
  assert.equal(res.code, "GENTIME_IN_FUTURE");
});

test("verifyStamp: fractional genTime is refused rather than rounded across certificate or CRL boundaries", () => {
  const res = verifyStamp(authenticatedAnchor, fixture.fractionalGenTime, policy);
  assert.equal(res.ok, false);
  assert.equal(res.code, "GENTIME_PRECISION_UNSUPPORTED");
});

test("verifyStamp: signer certificate must be embedded; caller untrusted material cannot supply it", () => {
  const inspected = inspectStamp(authenticatedAnchor, fixture.noCertificate);
  assert.equal(inspected.structurallyValid, true);
  assert.equal(inspected.embeddedCertificateCount, 0);
  const res = verifyStamp(authenticatedAnchor, fixture.noCertificate, {
    ...policy,
    untrustedCertificates: fixture.signerCertificate,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "CMS_SIGNER_CERTIFICATE_MISSING");
});

test("verifyStamp: Proxy, accessor, exotic, and flip-on-read policy inputs are refused without invocation", () => {
  let traps = 0;
  const proxied = new Proxy(policy, {
    get() { traps++; return undefined; },
    ownKeys() { traps++; return []; },
  });
  assert.equal(verifyStamp(authenticatedAnchor, fixture.valid, proxied).code, "VERIFICATION_POLICY_INVALID");
  assert.equal(traps, 0, "Proxy detection must not execute a trap");

  let getterCalls = 0;
  const accessorPolicy = { ...policy };
  Object.defineProperty(accessorPolicy, "trustRoots", { enumerable: true, get() { getterCalls++; return fixture.trustRoots; } });
  assert.equal(verifyStamp(authenticatedAnchor, fixture.valid, accessorPolicy).code, "VERIFICATION_POLICY_INVALID");
  assert.equal(getterCalls, 0, "top-level accessor must not run");

  const oidList = [fixture.policyOid];
  Object.defineProperty(oidList, "0", { enumerable: true, configurable: true, get() { getterCalls++; return fixture.policyOid; } });
  assert.equal(verifyStamp(authenticatedAnchor, fixture.valid, { ...policy, allowedPolicyOids: oidList }).code, "VERIFICATION_POLICY_INVALID");
  assert.equal(getterCalls, 0, "OID element accessor must not run");

  const exotic = Object.create({ opensslExecutable: fixture.executable });
  assert.equal(verifyStamp(authenticatedAnchor, fixture.valid, exotic).code, "VERIFICATION_POLICY_INVALID");
});

test("parser same-realm knockout: prototype poisons neither block valid authentication nor allow a wrong policy", () => {
  const original = {
    arrayJoin: Array.prototype.join,
    arrayPush: Array.prototype.push,
    arraySlice: Array.prototype.slice,
    bufferFrom: Buffer.from,
    bufferEquals: Buffer.prototype.equals,
    bufferSubarray: Buffer.prototype.subarray,
    bufferToString: Buffer.prototype.toString,
    stringCharCodeAt: String.prototype.charCodeAt,
    stringSlice: String.prototype.slice,
  };
  let poisonedJoinCalls = 0;
  const unsigned = { tsr: forgeToken({ hashAlgOid: SHA256_OID, hashedMessage: anchorHashDigest(authenticatedAnchor) }) };
  let inspectedSigned;
  let inspectedUnsigned;
  let wrongPolicyResult;
  try {
    Array.prototype.join = function (separator) {
      if (separator === "." && this.length === 5) {
        poisonedJoinCalls++;
        return fixture.policyOid;
      }
      return Reflect.apply(original.arrayJoin, this, [separator]);
    };
    Array.prototype.push = function () { throw new Error("poisoned Array.push reached"); };
    Array.prototype.slice = function () { throw new Error("poisoned Array.slice reached"); };
    Buffer.from = function () { throw new Error("poisoned Buffer.from reached"); };
    Buffer.prototype.equals = function () { throw new Error("poisoned Buffer.equals reached"); };
    Buffer.prototype.subarray = function () { throw new Error("poisoned Buffer.subarray reached"); };
    Buffer.prototype.toString = function () { throw new Error("poisoned Buffer.toString reached"); };
    String.prototype.charCodeAt = function () { throw new Error("poisoned String.charCodeAt reached"); };
    String.prototype.slice = function () { throw new Error("poisoned String.slice reached"); };
    inspectedSigned = inspectStamp(authenticatedAnchor, fixture.valid);
    inspectedUnsigned = inspectStamp(authenticatedAnchor, unsigned);
  } finally {
    Array.prototype.join = original.arrayJoin;
    Array.prototype.push = original.arrayPush;
    Array.prototype.slice = original.arraySlice;
    Buffer.from = original.bufferFrom;
    Buffer.prototype.equals = original.bufferEquals;
    Buffer.prototype.subarray = original.bufferSubarray;
    Buffer.prototype.toString = original.bufferToString;
    String.prototype.charCodeAt = original.stringCharCodeAt;
    String.prototype.slice = original.stringSlice;
  }
  assert.equal(inspectedSigned.structurallyValid, true);
  assert.equal(inspectedUnsigned.structurallyValid, true);

  // The targeted policy poison is left active across the authenticated call. Before the captured
  // parser, it rewrote 1.2.3.4.6 to the allowed 1.2.3.4.5; the cryptographic backend does not know
  // caller policy, so this assertion is the end-to-end bypass knockout.
  try {
    Array.prototype.join = function (separator) {
      if (separator === "." && this.length === 5) {
        poisonedJoinCalls++;
        return fixture.policyOid;
      }
      return Reflect.apply(original.arrayJoin, this, [separator]);
    };
    wrongPolicyResult = verifyStamp(authenticatedAnchor, fixture.otherPolicy, policy);
  } finally {
    Array.prototype.join = original.arrayJoin;
  }
  assert.equal(verifyStamp(authenticatedAnchor, fixture.valid, policy).ok, true, "restored control must authenticate");
  assert.equal(wrongPolicyResult.code, "TSTINFO_POLICY_DISALLOWED");
  assert.equal(poisonedJoinCalls, 0, "the policy parser must use its captured join, never the poisoned live prototype");
});

test("readOid: oversized policy arcs are rejected before Number precision can alias distinct encodings", () => {
  const hugeA = Buffer.from([0x06, 0x0a, 0x2a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]);
  const hugeB = Buffer.from([0x06, 0x0a, 0x2a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x7f]);
  assert.throws(() => readOid(derDecode(hugeA)), /safe integer range/);
  assert.throws(() => readOid(derDecode(hugeB)), /safe integer range/);
  const malformedPolicyToken = {
    tsr: forgeToken({ hashAlgOid: SHA256_OID, hashedMessage: anchorHashDigest(authenticatedAnchor), policy: hugeA }),
  };
  assert.equal(inspectStamp(authenticatedAnchor, malformedPolicyToken).code, "MALFORMED");
  assert.equal(verifyStamp(authenticatedAnchor, malformedPolicyToken, policy).code, "MALFORMED");
});
