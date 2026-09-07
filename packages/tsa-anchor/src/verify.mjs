/**
 * Authenticated RFC 3161 verification.
 *
 * `verifyStamp` has one success path: after a structural preflight, a fixed-argument OpenSSL 3
 * pipeline verifies the TimeStampResp signature and messageImprint, extracts and independently
 * verifies the CMS signer, binds the authenticated eContent back to the bytes parsed here, and
 * validates that signer across authenticated Accuracy bounds (or at genTime when Accuracy is
 * absent) against caller-supplied roots and CRLs. Missing policy is an error; this package never
 * falls back to structural success.
 *
 * `inspectStamp` is the deliberately unauthenticated counterpart. It is useful for diagnostics but
 * has no `ok` field and always reports `authenticated:false`, so a structural parse cannot be
 * mistaken for the trust verdict.
 */
import { spawnSync as nodeSpawnSync } from "node:child_process";
import {
  chmodSync as nodeChmodSync,
  mkdtempSync as nodeMkdtempSync,
  readFileSync as nodeReadFileSync,
  rmSync as nodeRmSync,
  writeFileSync as nodeWriteFileSync,
} from "node:fs";
import { tmpdir as nodeTmpdir } from "node:os";
import { isAbsolute as nodeIsAbsolute, join as nodeJoin } from "node:path";
import { hrtime as nodeHrtime } from "node:process";
import { frozenTable, intrinsics } from "noa-receipt";
import { parseTimeStampResp, SHA256_OID } from "./tsq.mjs";
import { anchorHashDigest } from "./anchor-hash.mjs";
import { DerError, derElementBounds } from "./der.mjs";

// Capture live Node built-in bindings once. `syncBuiltinESMExports()` after module load cannot
// redirect a verification step or the private-workspace lifecycle.
const spawnSync = nodeSpawnSync;
const chmodSync = nodeChmodSync;
const mkdtempSync = nodeMkdtempSync;
const readFileSync = nodeReadFileSync;
const rmSync = nodeRmSync;
const writeFileSync = nodeWriteFileSync;
const tmpdir = nodeTmpdir;
const isAbsolute = nodeIsAbsolute;
const pathJoin = nodeJoin;
const monotonicNowNs = nodeHrtime.bigint;
const NativeDate = Date;
const dateToISOString = Date.prototype.toISOString;
const reflectApply = Reflect.apply;
const DER_ERROR_PROTOTYPE = DerError.prototype;
const {
  arrayLength,
  arrayPush,
  bufEquals,
  bufSubarray,
  bufToString,
  bigIntToNumber,
  bufferAlloc,
  bufferConcat,
  bufferFrom,
  byteLength,
  dateParse,
  getOwnPropertyDescriptor,
  getPrototypeOf,
  hasOwn,
  isArray,
  isBuffer,
  isFiniteNumber,
  isProxy,
  isSafeInteger,
  mapHas,
  newSet,
  newWeakMap,
  ownKeys,
  numToString,
  setAdd,
  setHas,
  strCharCodeAt,
  strIncludes,
  strPadStart,
  strSlice,
  strStartsWith,
  toBigInt,
  toNumber,
  weakMapGet,
  weakMapSet,
  ARRAY_PROTOTYPE,
  OBJECT_PROTOTYPE,
} = intrinsics;

const MAX_TSR_BYTES = 16 * 1024 * 1024;
const MAX_TSR_BASE64_CHARS = 22369624; // ceil(MAX_TSR_BYTES / 3) * 4
const MAX_PKI_MATERIAL_BYTES = 16 * 1024 * 1024;
const MAX_PKI_PEM_BLOCKS = 4096;
const MAX_OPENSSL_OUTPUT_BYTES = 256 * 1024;
const DEFAULT_TIMEOUT_MS = 5000;
const MAX_TIMEOUT_MS = 30000;
const MAX_POLICY_OIDS = 64;
const MAX_FUTURE_SKEW_MS = 5 * 60 * 1000;
const MAX_RFC3339_EPOCH_MICROSECONDS = 253402300799999999n;
const MAX_INTERNAL_RESOURCE_PROCESSES = 1024;
const AUTH_LEVEL = "2";
const VERIFY_DEPTH = "8";

// One authenticated success invokes five fixed OpenSSL operations, plus one additional `verify`
// when signed Accuracy creates distinct conservative certificate/CRL endpoints. The CLI multiplies
// this worst-case constant by its admitted unique-anchor count.
export const OPENSSL_PROCESS_BUDGET_PER_STAMP = 6;
export const MAX_VERIFICATION_UNIQUE_ANCHORS = 16;
export const DEFAULT_VERIFICATION_COMMAND_TIMEOUT_MS = 30000;
export const MIN_VERIFICATION_COMMAND_TIMEOUT_MS = 100;
export const MAX_VERIFICATION_COMMAND_TIMEOUT_MS = 30000;

// Opaque capabilities, deliberately outside the caller's ordinary verification-options object.
// The private WeakMap makes a lookalike object useless: only this module can mint a token with
// state, while discarded per-command tokens and their state remain garbage-collectable in a
// long-lived process. The CLI holds one token across the whole command, so every synchronous
// OpenSSL invocation spends from the same monotonic deadline and process-credit budget.
const verificationResourceBudgets = newWeakMap();

export function createVerificationResourceBudget(durationMs, maxProcesses) {
  if (
    !isSafeInteger(durationMs) ||
    durationMs < MIN_VERIFICATION_COMMAND_TIMEOUT_MS ||
    durationMs > MAX_VERIFICATION_COMMAND_TIMEOUT_MS ||
    !isSafeInteger(maxProcesses) || maxProcesses < 1 || maxProcesses > MAX_INTERNAL_RESOURCE_PROCESSES
  ) {
    return null;
  }
  const token = frozenTable({});
  weakMapSet(verificationResourceBudgets, token, {
    deadlineNs: monotonicNowNs() + toBigInt(durationMs) * 1000000n,
    remainingProcesses: maxProcesses,
  });
  return token;
}

const ALLOWED_SIGNER_DIGEST_OIDS = frozenTable({
  "2.16.840.1.101.3.4.2.1": true, // sha256
  "2.16.840.1.101.3.4.2.2": true, // sha384
  "2.16.840.1.101.3.4.2.3": true, // sha512
});
const ALLOWED_SIGNATURE_OIDS = frozenTable({
  "1.2.840.113549.1.1.1": true, // rsaEncryption (digest is carried separately in SignerInfo)
  "1.2.840.113549.1.1.11": true, // sha256WithRSAEncryption
  "1.2.840.113549.1.1.12": true, // sha384WithRSAEncryption
  "1.2.840.113549.1.1.13": true, // sha512WithRSAEncryption
  "1.2.840.10045.4.3.2": true, // ecdsa-with-SHA256
  "1.2.840.10045.4.3.3": true, // ecdsa-with-SHA384
  "1.2.840.10045.4.3.4": true, // ecdsa-with-SHA512
  "1.3.101.112": true, // Ed25519
  "1.3.101.113": true, // Ed448
});
const VERIFICATION_OPTION_KEYS = frozenTable({
  opensslExecutable: true,
  trustRoots: true,
  allowedPolicyOids: true,
  revocation: true,
  untrustedCertificates: true,
  timeoutMs: true,
  clock: true,
});
const REVOCATION_OPTION_KEYS = frozenTable({ mode: true, crls: true });
const CLOCK_OPTION_KEYS = frozenTable({ now: true, maxFutureSkewMs: true });

// A private, deterministic OpenSSL configuration prevents ambient provider configuration from
// changing the algorithm implementation selected by the verifier. Every invocation additionally
// pins the default provider and its property query on the argument vector.
const OPENSSL_CONFIG =
  "openssl_conf = noa_openssl_init\n" +
  "config_diagnostics = 1\n" +
  "[noa_openssl_init]\n" +
  "providers = noa_provider_section\n" +
  "[noa_provider_section]\n" +
  "default = noa_default_provider\n" +
  "[noa_default_provider]\n" +
  "activate = 1\n";

function failure(code, reason) {
  return { ok: false, authenticated: false, code, reason };
}

function resourceFailure(reason) {
  return failure("VERIFICATION_RESOURCE_LIMIT", reason);
}

function isDerResourceError(error) {
  if (typeof error !== "object" || error === null || isProxy(error)) return false;
  if (getPrototypeOf(error) !== DER_ERROR_PROTOTYPE) return false;
  const code = getOwnPropertyDescriptor(error, "code");
  return code !== undefined && hasOwn(code, "value") && code.value === "DER_RESOURCE_LIMIT";
}

function structuralFailure(code, reason) {
  return { valid: false, code, reason };
}

function validCanonicalBase64(s) {
  const n = s.length;
  if (n === 0 || n > MAX_TSR_BASE64_CHARS || n % 4 !== 0) return false;
  let padding = 0;
  for (let i = 0; i < n; i++) {
    const c = strCharCodeAt(s, i);
    const alpha = (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a);
    const digit = c >= 0x30 && c <= 0x39;
    if (alpha || digit || c === 0x2b || c === 0x2f) {
      if (padding !== 0) return false;
      continue;
    }
    if (c !== 0x3d || i < n - 2) return false;
    padding++;
    if (padding > 2) return false;
  }
  return true;
}

function structurallyInspect(anchor, stampRecord) {
  let expectedDigest;
  let expectedHash;
  try {
    expectedDigest = anchorHashDigest(anchor);
    expectedHash = `sha256:${bufToString(expectedDigest, "hex")}`;
  } catch {
    return structuralFailure("MALFORMED", "malformed anchor");
  }

  if (typeof stampRecord !== "object" || stampRecord === null) {
    return structuralFailure("MALFORMED", "stampRecord must be an object");
  }
  let tsr;
  let recordedAnchorHash;
  try {
    tsr = stampRecord.tsr;
    recordedAnchorHash = stampRecord.anchorHash;
  } catch {
    return structuralFailure("MALFORMED", "stampRecord fields could not be read");
  }
  if (typeof tsr !== "string" || !validCanonicalBase64(tsr)) {
    return structuralFailure("MALFORMED", "stampRecord.tsr must be canonical non-empty base64 within the size limit");
  }
  if (recordedAnchorHash !== undefined && recordedAnchorHash !== expectedHash) {
    return structuralFailure(
      "ANCHOR_HASH_MISMATCH",
      `stampRecord.anchorHash does not match the recomputed anchor hash ${expectedHash} (wrong anchor/stamp pairing)`,
    );
  }

  let raw;
  try {
    raw = bufferFrom(tsr, "base64");
  } catch {
    return structuralFailure("MALFORMED", "stampRecord.tsr could not be decoded");
  }
  if (byteLength(raw) === 0 || byteLength(raw) > MAX_TSR_BYTES || bufToString(raw, "base64") !== tsr) {
    return structuralFailure("MALFORMED", "stampRecord.tsr is not canonical base64 within the size limit");
  }

  let parsed;
  try {
    parsed = parseTimeStampResp(raw);
  } catch (error) {
    if (isDerResourceError(error)) {
      return structuralFailure("VERIFICATION_RESOURCE_LIMIT", "TimeStampResp exceeded the DER parsing resource limit");
    }
    return structuralFailure("MALFORMED", "malformed TimeStampResp");
  }
  if (!parsed.granted) {
    return structuralFailure("TSA_STATUS_NOT_GRANTED", `TSA response did not grant the request (status=${parsed.status})`);
  }
  if (parsed.hashAlgOid !== SHA256_OID) {
    return structuralFailure(
      "MESSAGE_IMPRINT_ALGORITHM_DISALLOWED",
      `TSA token uses hashAlgorithm ${parsed.hashAlgOid}, expected sha256 (${SHA256_OID})`,
    );
  }
  if (!bufEquals(parsed.hashedMessage, expectedDigest)) {
    return structuralFailure(
      "MESSAGE_IMPRINT_MISMATCH",
      `TSA messageImprint does not match the anchor's own hash (anchor hash ${expectedHash}, token covers sha256:${bufToString(parsed.hashedMessage, "hex")})`,
    );
  }
  return { valid: true, raw, parsed, expectedDigest, expectedHash };
}

export function inspectStamp(anchor, stampRecord) {
  try {
    const inspected = structurallyInspect(anchor, stampRecord);
    if (!inspected.valid) {
      return {
        structurallyValid: false,
        authenticated: false,
        code: inspected.code,
        reason: inspected.reason,
      };
    }
    return {
      structurallyValid: true,
      authenticated: false,
      code: "UNAUTHENTICATED",
      reason: "RFC 3161 structure and sha256 messageImprint match; no cryptographic trust verdict was attempted",
      genTime: inspected.parsed.genTime,
      policyOid: inspected.parsed.policyOid,
      hashAlgOid: inspected.parsed.hashAlgOid,
      signerInfoCount: inspected.parsed.signerInfoCount,
      embeddedCertificateCount: inspected.parsed.embeddedCertificateCount,
      signerDigestAlgOid: inspected.parsed.signerDigestAlgOid,
      signerSignatureAlgOid: inspected.parsed.signerSignatureAlgOid,
    };
  } catch {
    return {
      structurallyValid: false,
      authenticated: false,
      code: "MALFORMED",
      reason: "stamp inspection failed closed",
    };
  }
}

function validOid(s) {
  if (typeof s !== "string" || s.length < 3) return false;
  let segmentLength = 0;
  for (let i = 0; i < s.length; i++) {
    const c = strCharCodeAt(s, i);
    if (c >= 0x30 && c <= 0x39) {
      segmentLength++;
      continue;
    }
    if (c !== 0x2e || segmentLength === 0) return false;
    segmentLength = 0;
  }
  return segmentLength > 0;
}

function decimalAt(s, start, count) {
  let value = 0;
  for (let i = start; i < start + count; i++) {
    const c = strCharCodeAt(s, i);
    if (c < 0x30 || c > 0x39) return -1;
    value = value * 10 + (c - 0x30);
  }
  return value;
}

function parseUtcInstant(s, minimumYear = 1970) {
  if (typeof s !== "string" || s.length < 20) return undefined;
  if (
    strCharCodeAt(s, 4) !== 0x2d || strCharCodeAt(s, 7) !== 0x2d ||
    strCharCodeAt(s, 10) !== 0x54 || strCharCodeAt(s, 13) !== 0x3a ||
    strCharCodeAt(s, 16) !== 0x3a || strCharCodeAt(s, s.length - 1) !== 0x5a
  ) return undefined;
  const year = decimalAt(s, 0, 4);
  const month = decimalAt(s, 5, 2);
  const day = decimalAt(s, 8, 2);
  const hour = decimalAt(s, 11, 2);
  const minute = decimalAt(s, 14, 2);
  const second = decimalAt(s, 17, 2);
  if (year < minimumYear || month < 1 || month > 12 || hour < 0 || hour > 23 || minute < 0 || minute > 59 || second < 0 || second > 59) {
    return undefined;
  }
  let maxDay = 31;
  if (month === 4 || month === 6 || month === 9 || month === 11) maxDay = 30;
  if (month === 2) {
    const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
    maxDay = leap ? 29 : 28;
  }
  if (day < 1 || day > maxDay) return undefined;
  if (s.length === 20) {
    if (strCharCodeAt(s, 19) !== 0x5a) return undefined;
  } else {
    if (strCharCodeAt(s, 19) !== 0x2e || s.length < 22) return undefined;
    for (let i = 20; i < s.length - 1; i++) {
      const c = strCharCodeAt(s, i);
      if (c < 0x30 || c > 0x39) return undefined;
    }
  }
  const parsed = dateParse(s);
  if (!isFiniteNumber(parsed) || !isSafeInteger(parsed)) return undefined;
  return parsed;
}

function epochMicroseconds(s, parsedMilliseconds) {
  const wholeSecondMicroseconds = toBigInt(parsedMilliseconds - (parsedMilliseconds % 1000)) * 1000n;
  if (s.length === 20) return wholeSecondMicroseconds;
  const availableDigits = s.length - 21;
  const usedDigits = availableDigits < 6 ? availableDigits : 6;
  let fractionalMicroseconds = decimalAt(s, 20, usedDigits);
  for (let i = usedDigits; i < 6; i++) fractionalMicroseconds *= 10;
  // The authenticated upper bound has microsecond precision. Flooring any finer caller precision
  // preserves the exact ordering against that integral-microsecond boundary.
  return wholeSecondMicroseconds + toBigInt(fractionalMicroseconds);
}

function formatEpochMicroseconds(epochMicroseconds) {
  const epochMilliseconds = bigIntToNumber(epochMicroseconds / 1000n);
  const iso = reflectApply(dateToISOString, new NativeDate(epochMilliseconds), []);
  const withinSecond = bigIntToNumber(epochMicroseconds % 1000000n);
  if (withinSecond === 0) return `${strSlice(iso, 0, 19)}Z`;
  let fraction = strPadStart(numToString(withinSecond), 6, "0");
  let end = 6;
  while (end > 0 && strCharCodeAt(fraction, end - 1) === 0x30) end--;
  fraction = strSlice(fraction, 0, end);
  return `${strSlice(iso, 0, 19)}.${fraction}Z`;
}

function authenticatedTimePolicy(parsed, genTimeMs) {
  const genTimeMicroseconds = toBigInt(genTimeMs) * 1000n;
  if (parsed.accuracy === undefined) {
    const attime = `${genTimeMs / 1000}`;
    return {
      valid: true,
      accuracy: null,
      timeBounds: { accuracyKnown: false, earliest: null, latest: null },
      lowerAttime: attime,
      upperAttime: attime,
      upperMicroseconds: genTimeMicroseconds,
    };
  }
  const accuracyMicroseconds = toBigInt(parsed.accuracy.totalMicroseconds);
  const lowerMicroseconds = genTimeMicroseconds - accuracyMicroseconds;
  const upperMicroseconds = genTimeMicroseconds + accuracyMicroseconds;
  if (lowerMicroseconds < 0n || upperMicroseconds > MAX_RFC3339_EPOCH_MICROSECONDS) {
    return { valid: false, result: failure("ACCURACY_RANGE_UNSUPPORTED", "authenticated Accuracy produces a time bound outside supported RFC 3339 years 1970 through 9999") };
  }
  const lowerSeconds = lowerMicroseconds / 1000000n;
  const upperSeconds = (upperMicroseconds + 999999n) / 1000000n;
  return {
    valid: true,
    accuracy: parsed.accuracy,
    timeBounds: {
      accuracyKnown: true,
      earliest: formatEpochMicroseconds(lowerMicroseconds),
      latest: formatEpochMicroseconds(upperMicroseconds),
    },
    lowerAttime: `${lowerSeconds}`,
    upperAttime: `${upperSeconds}`,
    upperMicroseconds,
  };
}

function policyAllows(allowed, actual) {
  return setHas(allowed, actual);
}

function validatePlainRecord(value, allowedKeys, label) {
  if (isProxy(value)) return { valid: false, result: failure("VERIFICATION_POLICY_INVALID", `${label} must not be a Proxy`) };
  if (typeof value !== "object" || value === null || isArray(value)) {
    return { valid: false, result: failure("VERIFICATION_POLICY_INVALID", `${label} must be a plain object`) };
  }
  const proto = getPrototypeOf(value);
  if (proto !== OBJECT_PROTOTYPE && proto !== null) {
    return { valid: false, result: failure("VERIFICATION_POLICY_INVALID", `${label} has an exotic prototype`) };
  }
  const keys = ownKeys(value);
  const n = arrayLength(keys);
  for (let i = 0; i < n; i++) {
    const key = keys[i];
    if (typeof key !== "string" || !hasOwn(allowedKeys, key)) {
      return { valid: false, result: failure("VERIFICATION_POLICY_INVALID", `${label} contains an unknown or symbol key`) };
    }
  }
  return { valid: true };
}

function readOwnData(value, key, label) {
  const descriptor = getOwnPropertyDescriptor(value, key);
  if (descriptor === undefined) return { valid: true, present: false, value: undefined };
  if (!hasOwn(descriptor, "value")) {
    return { valid: false, result: failure("VERIFICATION_POLICY_INVALID", `${label}.${key} must be an own data property`) };
  }
  return { valid: true, present: true, value: descriptor.value };
}

function snapshotOidList(value) {
  if (isProxy(value)) {
    return { valid: false, result: failure("VERIFICATION_POLICY_INVALID", "allowedPolicyOids must not be a Proxy") };
  }
  if (!isArray(value) || getPrototypeOf(value) !== ARRAY_PROTOTYPE) {
    return { valid: false, result: failure("TSTINFO_POLICY_REQUIRED", "allowedPolicyOids must be a plain non-empty array") };
  }
  const lengthDescriptor = getOwnPropertyDescriptor(value, "length");
  if (lengthDescriptor === undefined || !hasOwn(lengthDescriptor, "value")) {
    return { valid: false, result: failure("VERIFICATION_POLICY_INVALID", "allowedPolicyOids has no stable own length") };
  }
  const n = lengthDescriptor.value;
  if (!isSafeInteger(n) || n < 1 || n > MAX_POLICY_OIDS) {
    return { valid: false, result: failure("TSTINFO_POLICY_REQUIRED", "allowedPolicyOids must contain 1 through 64 OIDs") };
  }
  const keys = ownKeys(value);
  if (arrayLength(keys) !== n + 1) {
    return { valid: false, result: failure("VERIFICATION_POLICY_INVALID", "allowedPolicyOids must be dense and contain no extra keys") };
  }
  const snapshot = newSet();
  for (let i = 0; i < n; i++) {
    const item = readOwnData(value, `${i}`, "allowedPolicyOids");
    if (!item.valid) return item;
    if (!item.present || !validOid(item.value)) {
      return { valid: false, result: failure("TSTINFO_POLICY_INVALID", "allowedPolicyOids contains a missing or invalid OID") };
    }
    setAdd(snapshot, item.value);
  }
  return { valid: true, value: snapshot };
}

function snapshotVerificationPolicy(options) {
  if (options === undefined || options === null) {
    return { valid: false, result: failure("VERIFICATION_POLICY_REQUIRED", "authenticated TSA verification options are required") };
  }
  const outer = validatePlainRecord(options, VERIFICATION_OPTION_KEYS, "verification options");
  if (!outer.valid) return outer;
  const executable = readOwnData(options, "opensslExecutable", "verification options");
  if (!executable.valid) return executable;
  const roots = readOwnData(options, "trustRoots", "verification options");
  if (!roots.valid) return roots;
  const policies = readOwnData(options, "allowedPolicyOids", "verification options");
  if (!policies.valid) return policies;
  const revocation = readOwnData(options, "revocation", "verification options");
  if (!revocation.valid) return revocation;
  const untrusted = readOwnData(options, "untrustedCertificates", "verification options");
  if (!untrusted.valid) return untrusted;
  const timeout = readOwnData(options, "timeoutMs", "verification options");
  if (!timeout.valid) return timeout;
  const clock = readOwnData(options, "clock", "verification options");
  if (!clock.valid) return clock;

  if (!revocation.present || revocation.value === undefined || revocation.value === null) {
    return { valid: false, result: failure("REVOCATION_POLICY_REQUIRED", "an explicit revocation policy is required") };
  }
  const revocationRecord = validatePlainRecord(revocation.value, REVOCATION_OPTION_KEYS, "verification options.revocation");
  if (!revocationRecord.valid) return revocationRecord;
  const mode = readOwnData(revocation.value, "mode", "verification options.revocation");
  if (!mode.valid) return mode;
  const crls = readOwnData(revocation.value, "crls", "verification options.revocation");
  if (!crls.valid) return crls;
  const oidList = snapshotOidList(policies.value);
  if (!oidList.valid) return oidList;
  if (!clock.present || clock.value === undefined || clock.value === null) {
    return { valid: false, result: failure("CLOCK_POLICY_REQUIRED", "an explicit verification clock policy is required") };
  }
  const clockRecord = validatePlainRecord(clock.value, CLOCK_OPTION_KEYS, "verification options.clock");
  if (!clockRecord.valid) return clockRecord;
  const clockNow = readOwnData(clock.value, "now", "verification options.clock");
  if (!clockNow.valid) return clockNow;
  const clockSkew = readOwnData(clock.value, "maxFutureSkewMs", "verification options.clock");
  if (!clockSkew.valid) return clockSkew;

  return {
    valid: true,
    executable: executable.value,
    trustRoots: roots.value,
    allowedPolicyOids: oidList.value,
    revocationMode: mode.value,
    crls: crls.value,
    untrustedCertificates: untrusted.value,
    timeoutMs: timeout.present && timeout.value !== undefined ? timeout.value : DEFAULT_TIMEOUT_MS,
    clockNow: clockNow.value,
    maxFutureSkewMs: clockSkew.value,
  };
}

function normalizeMaterial(value, requiredCode, invalidCode, label) {
  if (value === undefined || value === null || value === "") {
    return { valid: false, result: failure(requiredCode, `${label} is required`) };
  }
  if (typeof value !== "string" && isProxy(value)) {
    return { valid: false, result: failure(invalidCode, `${label} must not be a Proxy`) };
  }
  if (typeof value !== "string" && !isBuffer(value)) {
    return { valid: false, result: failure(invalidCode, `${label} must be a PEM string or Buffer`) };
  }
  if (typeof value === "string") {
    // PEM is ASCII. Scan and bound before UTF-8 allocation so a caller cannot turn the configured
    // byte ceiling into a multi-byte allocation several times larger than that ceiling.
    if (value.length > MAX_PKI_MATERIAL_BYTES) {
      return { valid: false, result: failure(invalidCode, `${label} exceeds the size limit`) };
    }
    for (let i = 0; i < value.length; i++) {
      if (strCharCodeAt(value, i) > 0x7f) {
        return { valid: false, result: failure(invalidCode, `${label} PEM must contain ASCII only`) };
      }
    }
  } else if (byteLength(value) > MAX_PKI_MATERIAL_BYTES) {
    return { valid: false, result: failure(invalidCode, `${label} exceeds the size limit`) };
  }
  let bytes;
  try {
    bytes = isBuffer(value) ? bufferFrom(value) : bufferFrom(value, "utf8");
  } catch {
    return { valid: false, result: failure(invalidCode, `${label} could not be copied`) };
  }
  const n = byteLength(bytes);
  if (n === 0 || n > MAX_PKI_MATERIAL_BYTES) {
    return { valid: false, result: failure(invalidCode, `${label} is empty or exceeds the size limit`) };
  }
  return { valid: true, bytes };
}

const PEM_CERTIFICATE_BEGIN = "-----BEGIN CERTIFICATE-----";
const PEM_CERTIFICATE_END = "-----END CERTIFICATE-----";
const PEM_X509_CERTIFICATE_BEGIN = "-----BEGIN X509 CERTIFICATE-----";
const PEM_X509_CERTIFICATE_END = "-----END X509 CERTIFICATE-----";
const PEM_TRUSTED_CERTIFICATE_BEGIN = "-----BEGIN TRUSTED CERTIFICATE-----";
const PEM_TRUSTED_CERTIFICATE_END = "-----END TRUSTED CERTIFICATE-----";
const PEM_CRL_BEGIN = "-----BEGIN X509 CRL-----";
const PEM_CRL_END = "-----END X509 CRL-----";

function relativeIndex(text, cursor, needle) {
  const limit = text.length - needle.length;
  const first = strCharCodeAt(needle, 0);
  for (let i = cursor; i <= limit; i++) {
    if (strCharCodeAt(text, i) !== first) continue;
    let matched = true;
    for (let j = 1; j < needle.length; j++) {
      if (strCharCodeAt(text, i + j) !== strCharCodeAt(needle, j)) {
        matched = false;
        break;
      }
    }
    if (matched) return i;
  }
  return -1;
}

function matchesAt(text, offset, needle) {
  if (offset + needle.length > text.length) return false;
  for (let i = 0; i < needle.length; i++) {
    if (strCharCodeAt(text, offset + i) !== strCharCodeAt(needle, i)) return false;
  }
  return true;
}

function nextPemHeader(text, cursor, kind) {
  for (let i = cursor; i < text.length; i++) {
    if (kind === "crl") {
      if (matchesAt(text, i, PEM_CRL_BEGIN)) {
        return { start: i, begin: PEM_CRL_BEGIN, end: PEM_CRL_END, trusted: false };
      }
      continue;
    }
    if (matchesAt(text, i, PEM_CERTIFICATE_BEGIN)) {
      return { start: i, begin: PEM_CERTIFICATE_BEGIN, end: PEM_CERTIFICATE_END, trusted: false };
    }
    if (matchesAt(text, i, PEM_X509_CERTIFICATE_BEGIN)) {
      return { start: i, begin: PEM_X509_CERTIFICATE_BEGIN, end: PEM_X509_CERTIFICATE_END, trusted: false };
    }
    if (matchesAt(text, i, PEM_TRUSTED_CERTIFICATE_BEGIN)) {
      return { start: i, begin: PEM_TRUSTED_CERTIFICATE_BEGIN, end: PEM_TRUSTED_CERTIFICATE_END, trusted: true };
    }
  }
  return undefined;
}

function parsePemBlocks(bytes, kind) {
  const n = byteLength(bytes);
  for (let i = 0; i < n; i++) {
    if (bytes[i] > 0x7f) throw new DerError("PEM material contains non-ASCII bytes");
  }
  const text = bufToString(bytes, "ascii");
  const blocks = [];
  let cursor = 0;
  while (cursor < text.length) {
    const header = nextPemHeader(text, cursor, kind);
    if (header === undefined) break;
    if (arrayLength(blocks) === MAX_PKI_PEM_BLOCKS) {
      throw new DerError("PEM block budget exceeded", "DER_RESOURCE_LIMIT");
    }
    const bodyStart = header.start + header.begin.length;
    const endStart = relativeIndex(text, bodyStart, header.end);
    if (endStart < 0) throw new DerError("unterminated PEM block");
    const blockEnd = endStart + header.end.length;
    arrayPush(blocks, {
      text: strSlice(text, header.start, blockEnd),
      body: strSlice(text, bodyStart, endStart),
      trusted: header.trusted,
    });
    cursor = blockEnd;
  }
  if (arrayLength(blocks) === 0) throw new DerError(`no ${kind} PEM blocks found`);
  return blocks;
}

function pemBodyDer(body) {
  const compact = bufferAlloc(body.length);
  let compactLength = 0;
  for (let i = 0; i < body.length; i++) {
    const c = strCharCodeAt(body, i);
    if (c === 0x09 || c === 0x0a || c === 0x0d || c === 0x20) continue;
    if (c > 0x7f) throw new DerError("PEM base64 contains non-ASCII bytes");
    compact[compactLength] = c;
    compactLength++;
  }
  const encoded = bufToString(bufSubarray(compact, 0, compactLength), "ascii");
  if (!validCanonicalBase64(encoded)) throw new DerError("PEM body is not canonical base64");
  const der = bufferFrom(encoded, "base64");
  if (bufToString(der, "base64") !== encoded) throw new DerError("PEM body did not decode canonically");
  return der;
}

function expectUniversal(bounds, constructed, tagNumber, label) {
  if (bounds.tagClass !== 0 || bounds.constructed !== constructed || bounds.tagNumber !== tagNumber) {
    throw new DerError(`${label} has an unexpected DER tag`);
  }
  return bounds;
}

function nextElement(buf, cursor, parent, label) {
  if (cursor >= parent.contentEnd) throw new DerError(`${label} is missing`);
  return derElementBounds(buf, cursor, parent.contentEnd);
}

function parseCertificateDer(block) {
  const der = pemBodyDer(block.body);
  const certificate = expectUniversal(derElementBounds(der), true, 16, "Certificate");
  if (!block.trusted && certificate.nextOffset !== byteLength(der)) {
    throw new DerError("Certificate PEM contains trailing DER");
  }
  if (block.trusted) {
    let auxCursor = certificate.nextOffset;
    let auxElements = 0;
    while (auxCursor < byteLength(der)) {
      if (auxElements === 8) throw new DerError("trusted certificate AUX element budget exceeded", "DER_RESOURCE_LIMIT");
      auxCursor = derElementBounds(der, auxCursor, byteLength(der)).nextOffset;
      auxElements++;
    }
  }
  return { der, certificate };
}

function parseDerTimeSeconds(buf, bounds) {
  if (bounds.tagClass !== 0 || bounds.constructed || (bounds.tagNumber !== 23 && bounds.tagNumber !== 24)) {
    throw new DerError("certificate or CRL time has an unexpected DER tag");
  }
  const text = bufToString(bufSubarray(buf, bounds.contentStart, bounds.contentEnd), "ascii");
  const digitCount = bounds.tagNumber === 23 ? 12 : 14;
  if (text.length !== digitCount + 1 || strCharCodeAt(text, digitCount) !== 0x5a) {
    throw new DerError("certificate or CRL time has unsupported precision or timezone");
  }
  for (let i = 0; i < digitCount; i++) {
    const c = strCharCodeAt(text, i);
    if (c < 0x30 || c > 0x39) throw new DerError("certificate or CRL time is malformed");
  }
  let instant;
  if (bounds.tagNumber === 23) {
    const shortYear = decimalAt(text, 0, 2);
    const year = shortYear >= 50 ? 1900 + shortYear : 2000 + shortYear;
    instant = `${year}-${strSlice(text, 2, 4)}-${strSlice(text, 4, 6)}T${strSlice(text, 6, 8)}:${strSlice(text, 8, 10)}:${strSlice(text, 10, 12)}Z`;
  } else {
    instant = `${strSlice(text, 0, 4)}-${strSlice(text, 4, 6)}-${strSlice(text, 6, 8)}T${strSlice(text, 8, 10)}:${strSlice(text, 10, 12)}:${strSlice(text, 12, 14)}Z`;
  }
  // RFC 5280 UTCTime represents years 1950 through 2049. PKI validity may therefore predate the
  // Unix epoch even though authenticated genTime and caller clock policy remain restricted to 1970+.
  const milliseconds = parseUtcInstant(instant, 1950);
  if (milliseconds === undefined || milliseconds % 1000 !== 0) throw new DerError("certificate or CRL time is invalid");
  return toBigInt(milliseconds / 1000);
}

function certificateInterval(block) {
  const { der, certificate } = parseCertificateDer(block);
  const tbsCertificate = expectUniversal(nextElement(der, certificate.contentStart, certificate, "TBSCertificate"), true, 16, "TBSCertificate");
  let cursor = tbsCertificate.contentStart;
  let field = nextElement(der, cursor, tbsCertificate, "TBSCertificate serialNumber");
  if (field.tagClass === 2 && field.constructed && field.tagNumber === 0) {
    cursor = field.nextOffset;
    field = nextElement(der, cursor, tbsCertificate, "TBSCertificate serialNumber");
  }
  cursor = field.nextOffset;
  cursor = nextElement(der, cursor, tbsCertificate, "TBSCertificate signature").nextOffset;
  cursor = nextElement(der, cursor, tbsCertificate, "TBSCertificate issuer").nextOffset;
  const validity = expectUniversal(nextElement(der, cursor, tbsCertificate, "TBSCertificate validity"), true, 16, "TBSCertificate validity");
  const notBefore = nextElement(der, validity.contentStart, validity, "Certificate notBefore");
  const notAfter = nextElement(der, notBefore.nextOffset, validity, "Certificate notAfter");
  if (notAfter.nextOffset !== validity.contentEnd) throw new DerError("Certificate validity contains extra fields");
  const start = parseDerTimeSeconds(der, notBefore);
  const end = parseDerTimeSeconds(der, notAfter);
  if (start > end) throw new DerError("Certificate validity interval is inverted");
  return { start, end };
}

function crlInterval(block) {
  const der = pemBodyDer(block.body);
  const certificateList = expectUniversal(derElementBounds(der), true, 16, "CertificateList");
  if (certificateList.nextOffset !== byteLength(der)) throw new DerError("CRL PEM contains trailing DER");
  const tbsCertList = expectUniversal(nextElement(der, certificateList.contentStart, certificateList, "TBSCertList"), true, 16, "TBSCertList");
  let cursor = tbsCertList.contentStart;
  let field = nextElement(der, cursor, tbsCertList, "TBSCertList signature");
  if (field.tagClass === 0 && !field.constructed && field.tagNumber === 2) {
    cursor = field.nextOffset;
    field = nextElement(der, cursor, tbsCertList, "TBSCertList signature");
  }
  cursor = field.nextOffset;
  cursor = nextElement(der, cursor, tbsCertList, "TBSCertList issuer").nextOffset;
  const thisUpdate = nextElement(der, cursor, tbsCertList, "CRL thisUpdate");
  const nextUpdate = nextElement(der, thisUpdate.nextOffset, tbsCertList, "CRL nextUpdate");
  const start = parseDerTimeSeconds(der, thisUpdate);
  const end = parseDerTimeSeconds(der, nextUpdate);
  if (start > end) throw new DerError("CRL validity interval is inverted");
  return { start, end };
}

function joinPemBlocks(blocks) {
  const chunks = [];
  const n = arrayLength(blocks);
  for (let i = 0; i < n; i++) {
    arrayPush(chunks, bufferFrom(blocks[i].text, "ascii"));
    arrayPush(chunks, bufferFrom("\n", "ascii"));
  }
  return bufferConcat(chunks);
}

function filterIntervalMaterial(bytes, kind, lowerSeconds, upperSeconds, invalidCode, label) {
  try {
    const blocks = parsePemBlocks(bytes, kind);
    const selected = [];
    let startsAfterLower = false;
    let endsBeforeUpper = false;
    const n = arrayLength(blocks);
    for (let i = 0; i < n; i++) {
      const interval = kind === "crl" ? crlInterval(blocks[i]) : certificateInterval(blocks[i]);
      if (interval.start > lowerSeconds) startsAfterLower = true;
      if (interval.end < upperSeconds) endsBeforeUpper = true;
      if (interval.start <= lowerSeconds && interval.end >= upperSeconds) arrayPush(selected, blocks[i]);
    }
    return {
      valid: true,
      bytes: joinPemBlocks(selected),
      selected: arrayLength(selected),
      startsAfterLower,
      endsBeforeUpper,
    };
  } catch (error) {
    if (isDerResourceError(error)) {
      return { valid: false, result: resourceFailure(`${label} exceeded the PEM/DER parsing resource limit`) };
    }
    return { valid: false, result: failure(invalidCode, `${label} is not valid bounded PEM/DER material`) };
  }
}

function validatePolicy(options, parsed) {
  const snapshot = snapshotVerificationPolicy(options);
  if (!snapshot.valid) return snapshot;
  const executable = snapshot.executable;
  const allowedPolicyOids = snapshot.allowedPolicyOids;
  const timeoutMs = snapshot.timeoutMs;
  if (typeof executable !== "string" || executable.length === 0) {
    return { valid: false, result: failure("OPENSSL_EXECUTABLE_REQUIRED", "an absolute OpenSSL 3 executable path is required") };
  }
  if (!isAbsolute(executable)) {
    return { valid: false, result: failure("OPENSSL_EXECUTABLE_INVALID", "opensslExecutable must be an absolute path") };
  }
  if (!policyAllows(allowedPolicyOids, parsed.policyOid)) {
    return {
      valid: false,
      result: failure("TSTINFO_POLICY_DISALLOWED", "the authenticated token policy is not allowed by caller policy"),
    };
  }
  if (snapshot.revocationMode !== "crl-check-all") {
    return { valid: false, result: failure("REVOCATION_POLICY_UNSUPPORTED", "revocation.mode must be crl-check-all") };
  }
  if (!isSafeInteger(timeoutMs) || !isFiniteNumber(timeoutMs) || timeoutMs < 100 || timeoutMs > MAX_TIMEOUT_MS) {
    return { valid: false, result: failure("VERIFICATION_POLICY_INVALID", "timeoutMs must be an integer from 100 through 30000") };
  }

  const roots = normalizeMaterial(snapshot.trustRoots, "TRUST_ROOTS_REQUIRED", "TRUST_ROOTS_INVALID", "trustRoots");
  if (!roots.valid) return roots;
  const crls = normalizeMaterial(snapshot.crls, "REVOCATION_EVIDENCE_REQUIRED", "REVOCATION_EVIDENCE_INVALID", "revocation.crls");
  if (!crls.valid) return crls;
  let untrusted;
  if (snapshot.untrustedCertificates !== undefined && snapshot.untrustedCertificates !== null && snapshot.untrustedCertificates !== "") {
    untrusted = normalizeMaterial(snapshot.untrustedCertificates, "UNTRUSTED_CERTIFICATES_INVALID", "UNTRUSTED_CERTIFICATES_INVALID", "untrustedCertificates");
    if (!untrusted.valid) return untrusted;
  }

  const genTimeMs = parseUtcInstant(parsed.genTime);
  if (genTimeMs === undefined) {
    return { valid: false, result: failure("GENTIME_INVALID", "TSTInfo genTime is not a usable UTC instant") };
  }
  // OpenSSL's `-attime` contract is integer epoch seconds. Rounding a fractional genTime down can
  // accept a certificate just after notAfter; rounding it up can accept one just before notBefore.
  // Refuse the ambiguous precision instead of making either boundary fail open.
  if (parsed.genTime.length !== 20) {
    return { valid: false, result: failure("GENTIME_PRECISION_UNSUPPORTED", "fractional TSTInfo genTime cannot be validated against second-resolution certificate and CRL boundaries") };
  }
  const timePolicy = authenticatedTimePolicy(parsed, genTimeMs);
  if (!timePolicy.valid) return timePolicy;
  const clockNowMs = parseUtcInstant(snapshot.clockNow);
  if (clockNowMs === undefined) {
    return { valid: false, result: failure("CLOCK_POLICY_INVALID", "clock.now must be a valid UTC RFC 3339 instant") };
  }
  if (!isSafeInteger(snapshot.maxFutureSkewMs) || snapshot.maxFutureSkewMs < 0 || snapshot.maxFutureSkewMs > MAX_FUTURE_SKEW_MS) {
    return { valid: false, result: failure("CLOCK_POLICY_INVALID", "clock.maxFutureSkewMs must be an integer from 0 through 300000") };
  }
  const clockNowMicroseconds = epochMicroseconds(snapshot.clockNow, clockNowMs);
  const maxFutureSkewMicroseconds = toBigInt(snapshot.maxFutureSkewMs) * 1000n;
  if (timePolicy.upperMicroseconds > clockNowMicroseconds + maxFutureSkewMicroseconds) {
    return { valid: false, result: failure("GENTIME_IN_FUTURE", "the latest authenticated creation-time bound exceeds the trusted verification instant and allowed future skew") };
  }
  let trustRoots = roots.bytes;
  let crlBytes = crls.bytes;
  let untrustedCertificates = untrusted?.bytes;
  if (timePolicy.accuracy !== null) {
    const lowerSeconds = toBigInt(timePolicy.lowerAttime);
    const upperSeconds = toBigInt(timePolicy.upperAttime);
    const filteredRoots = filterIntervalMaterial(trustRoots, "certificate", lowerSeconds, upperSeconds, "TRUST_ROOTS_INVALID", "trustRoots");
    if (!filteredRoots.valid) return filteredRoots;
    if (filteredRoots.selected === 0) {
      return { valid: false, result: failure("TRUST_CHAIN_INVALID", "no configured trust root covers the complete authenticated creation-time interval") };
    }
    trustRoots = filteredRoots.bytes;
    const filteredCrls = filterIntervalMaterial(crlBytes, "crl", lowerSeconds, upperSeconds, "REVOCATION_EVIDENCE_INVALID", "revocation.crls");
    if (!filteredCrls.valid) return filteredCrls;
    if (filteredCrls.selected === 0) {
      return { valid: false, result: failure("REVOCATION_EVIDENCE_UNAVAILABLE", "no configured CRL covers the complete authenticated creation-time interval") };
    }
    crlBytes = filteredCrls.bytes;
    if (untrustedCertificates !== undefined) {
      const filteredUntrusted = filterIntervalMaterial(untrustedCertificates, "certificate", lowerSeconds, upperSeconds, "UNTRUSTED_CERTIFICATES_INVALID", "untrustedCertificates");
      if (!filteredUntrusted.valid) return filteredUntrusted;
      untrustedCertificates = filteredUntrusted.selected === 0 ? undefined : filteredUntrusted.bytes;
    }
  }
  return {
    valid: true,
    executable,
    allowedPolicyOids,
    trustRoots,
    crls: crlBytes,
    untrustedCertificates,
    timeoutMs,
    attime: `${genTimeMs / 1000}`,
    lowerAttime: timePolicy.lowerAttime,
    upperAttime: timePolicy.upperAttime,
    accuracy: timePolicy.accuracy,
    timeBounds: timePolicy.timeBounds,
    intervalMaterialFiltered: timePolicy.accuracy !== null,
    clockNow: snapshot.clockNow,
    maxFutureSkewMs: snapshot.maxFutureSkewMs,
  };
}

function reserveOpenSslProcess(resourceBudget, timeoutMs) {
  if (resourceBudget === undefined) return { valid: true, timeoutMs, deadlineLimited: false };
  const state = weakMapGet(verificationResourceBudgets, resourceBudget);
  if (state === undefined) {
    return { valid: false, result: resourceFailure("the internal verification resource capability is invalid") };
  }
  if (state.remainingProcesses < 1) {
    return { valid: false, result: resourceFailure("the command exhausted its OpenSSL process budget") };
  }
  const remainingNs = state.deadlineNs - monotonicNowNs();
  const remainingMs = remainingNs < 1000000n ? 0 : toNumber(remainingNs / 1000000n);
  if (!isSafeInteger(remainingMs) || remainingMs < 1) {
    return { valid: false, result: resourceFailure("the command exhausted its aggregate OpenSSL deadline") };
  }
  state.remainingProcesses--;
  return {
    valid: true,
    timeoutMs: remainingMs < timeoutMs ? remainingMs : timeoutMs,
    deadlineLimited: remainingMs <= timeoutMs,
  };
}

function resourceDeadlineExpired(resourceBudget) {
  if (resourceBudget === undefined) return false;
  const state = weakMapGet(verificationResourceBudgets, resourceBudget);
  return state === undefined || monotonicNowNs() >= state.deadlineNs;
}

function runProcess(executable, args, cwd, configPath, timeoutMs, resourceBudget) {
  const reservation = reserveOpenSslProcess(resourceBudget, timeoutMs);
  if (!reservation.valid) return { ran: false, result: reservation.result };
  let child;
  try {
    child = spawnSync(executable, args, {
      cwd,
      env: { LANG: "C", LC_ALL: "C", OPENSSL_CONF: configPath },
      shell: false,
      windowsHide: true,
      timeout: reservation.timeoutMs,
      killSignal: "SIGKILL",
      maxBuffer: MAX_OPENSSL_OUTPUT_BYTES,
    });
  } catch {
    return { ran: false, result: failure("OPENSSL_EXECUTION_FAILED", "OpenSSL could not be executed") };
  }
  let errorCode;
  try {
    errorCode = child.error?.code;
  } catch {
    return { ran: false, result: failure("OPENSSL_EXECUTION_FAILED", "OpenSSL returned an unreadable process result") };
  }
  if (errorCode === "ENOENT" || errorCode === "EACCES") {
    return { ran: false, result: failure("OPENSSL_UNAVAILABLE", "the configured OpenSSL executable is unavailable") };
  }
  if (errorCode === "ETIMEDOUT") {
    if (reservation.deadlineLimited) {
      return { ran: false, result: resourceFailure("the command exhausted its aggregate OpenSSL deadline") };
    }
    return { ran: false, result: failure("OPENSSL_TIMEOUT", "OpenSSL verification exceeded its timeout") };
  }
  if (resourceDeadlineExpired(resourceBudget)) {
    return { ran: false, result: resourceFailure("the command exhausted its aggregate OpenSSL deadline") };
  }
  if (errorCode === "ENOBUFS") {
    return { ran: false, result: failure("OPENSSL_OUTPUT_LIMIT", "OpenSSL verification exceeded its output limit") };
  }
  if (errorCode !== undefined || child.status === null) {
    return { ran: false, result: failure("OPENSSL_EXECUTION_FAILED", "OpenSSL verification did not complete normally") };
  }
  return { ran: true, status: child.status, stdout: child.stdout, stderr: child.stderr };
}

function outputText(run) {
  const chunks = [];
  if (isBuffer(run.stdout)) arrayPush(chunks, run.stdout);
  if (isBuffer(run.stderr)) arrayPush(chunks, run.stderr);
  if (arrayLength(chunks) === 0) return "";
  return bufToString(bufferConcat(chunks), "utf8");
}

function classifyCertificateFailure(run, fallbackCode, fallbackReason) {
  const out = outputText(run);
  if (strIncludes(out, "key too weak") || strIncludes(out, "key size too small")) {
    return failure("ALGORITHM_SECURITY_LEVEL_NOT_MET", "the timestamp signer does not meet OpenSSL authentication level 2");
  }
  if (strIncludes(out, "certificate revoked")) {
    return failure("SIGNER_CERTIFICATE_REVOKED", "the timestamp signer certificate is revoked at a checked creation time");
  }
  if (strIncludes(out, "CRL has expired") || strIncludes(out, "unable to get certificate CRL") || strIncludes(out, "unable to get CRL")) {
    return failure("REVOCATION_EVIDENCE_UNAVAILABLE", "required CRL evidence was unavailable at a checked creation time");
  }
  if (strIncludes(out, "certificate has expired")) {
    return failure("SIGNER_CERTIFICATE_EXPIRED", "the timestamp signer certificate was expired at a checked creation time");
  }
  if (strIncludes(out, "certificate is not yet valid")) {
    return failure("SIGNER_CERTIFICATE_NOT_YET_VALID", "the timestamp signer certificate was not yet valid at a checked creation time");
  }
  if (strIncludes(out, "unsuitable certificate purpose") || strIncludes(out, "invalid purpose")) {
    return failure("TIMESTAMP_SIGNER_EKU_INVALID", "the signer certificate is not valid for timestamp signing");
  }
  if (
    strIncludes(out, "unable to get local issuer certificate") ||
    strIncludes(out, "unable to verify the first certificate") ||
    strIncludes(out, "self-signed certificate") ||
    strIncludes(out, "certificate signature failure")
  ) {
    return failure("TRUST_CHAIN_INVALID", "the timestamp signer chain does not terminate at a configured trust root");
  }
  return failure(fallbackCode, fallbackReason);
}

function addProviderArgs(args) {
  arrayPush(args, "-provider");
  arrayPush(args, "default");
  arrayPush(args, "-propquery");
  arrayPush(args, "provider=default");
  return args;
}

function writePrivate(path, bytes) {
  writeFileSync(path, bytes, { flag: "wx", mode: 0o600 });
}

function runOpenSslSequence(paths, inspected, policy, resourceBudget) {
  let run = runProcess(policy.executable, ["version"], paths.dir, paths.config, policy.timeoutMs, resourceBudget);
  if (!run.ran) return run.result;
  if (run.status !== 0 || !strStartsWith(outputText(run), "OpenSSL 3.")) {
    return failure("OPENSSL_UNSUPPORTED", "authenticated timestamp verification requires OpenSSL 3.x");
  }

  const tsArgs = [
    "ts", "-verify", "-in", paths.response, "-digest", bufToString(inspected.expectedDigest, "hex"),
    "-CAfile", paths.roots, "-purpose", "timestampsign",
    "-attime", policy.attime, "-auth_level", AUTH_LEVEL, "-verify_depth", VERIFY_DEPTH,
    "-x509_strict", "-check_ss_sig", "-trusted_first",
  ];
  if (paths.callerUntrusted !== undefined) {
    arrayPush(tsArgs, "-untrusted");
    arrayPush(tsArgs, paths.callerUntrusted);
  }
  addProviderArgs(tsArgs);
  run = runProcess(policy.executable, tsArgs, paths.dir, paths.config, policy.timeoutMs, resourceBudget);
  if (!run.ran) return run.result;
  if (run.status !== 0) {
    return classifyCertificateFailure(
      run,
      "RFC3161_AUTHENTICATION_FAILED",
      "the RFC 3161 signature, imprint, signer purpose, validity, or trust chain did not verify",
    );
  }

  const tokenArgs = addProviderArgs(["ts", "-reply", "-in", paths.response, "-token_out", "-out", paths.token]);
  run = runProcess(policy.executable, tokenArgs, paths.dir, paths.config, policy.timeoutMs, resourceBudget);
  if (!run.ran) return run.result;
  if (run.status !== 0) return failure("OPENSSL_PROTOCOL_ERROR", "OpenSSL could not extract the verified CMS token");

  // Deliberately do not pass caller-supplied certificates to CMS signer discovery. The signer
  // certificate must be embedded in the token; `untrustedCertificates` may extend only its chain.
  const cmsArgs = [
    "cms", "-verify", "-binary", "-inform", "DER", "-in", paths.token, "-noverify",
    "-signer", paths.signer, "-certsout", paths.embedded, "-out", paths.content,
  ];
  addProviderArgs(cmsArgs);
  run = runProcess(policy.executable, cmsArgs, paths.dir, paths.config, policy.timeoutMs, resourceBudget);
  if (!run.ran) return run.result;
  if (run.status !== 0) return failure("CMS_SIGNATURE_INVALID", "the CMS SignerInfo signature did not verify");

  let authenticatedContent;
  let signerBytes;
  let embeddedBytes;
  try {
    authenticatedContent = readFileSync(paths.content);
    signerBytes = readFileSync(paths.signer);
    embeddedBytes = readFileSync(paths.embedded);
  } catch {
    return failure("OPENSSL_OUTPUT_INVALID", "OpenSSL did not produce the authenticated CMS artifacts");
  }
  if (!bufEquals(authenticatedContent, inspected.parsed.tstInfoBytes)) {
    return failure("CMS_CONTENT_MISMATCH", "authenticated CMS content differs from the structurally inspected TSTInfo");
  }
  if (byteLength(signerBytes) === 0) {
    return failure("CMS_SIGNER_CERTIFICATE_MISSING", "the verified CMS signer certificate is missing");
  }

  if (policy.intervalMaterialFiltered) {
    const lowerSeconds = toBigInt(policy.lowerAttime);
    const upperSeconds = toBigInt(policy.upperAttime);
    const filteredSigner = filterIntervalMaterial(
      signerBytes,
      "certificate",
      lowerSeconds,
      upperSeconds,
      "OPENSSL_OUTPUT_INVALID",
      "the extracted CMS signer certificate",
    );
    if (!filteredSigner.valid) return filteredSigner.result;
    if (filteredSigner.selected === 0) {
      if (filteredSigner.startsAfterLower) {
        return failure("SIGNER_CERTIFICATE_NOT_YET_VALID", "the timestamp signer certificate does not cover the earliest authenticated creation time");
      }
      if (filteredSigner.endsBeforeUpper) {
        return failure("SIGNER_CERTIFICATE_EXPIRED", "the timestamp signer certificate does not cover the latest authenticated creation time");
      }
      return failure("TRUST_CHAIN_INVALID", "the timestamp signer certificate does not cover the complete authenticated creation-time interval");
    }
    const filteredEmbedded = filterIntervalMaterial(
      embeddedBytes,
      "certificate",
      lowerSeconds,
      upperSeconds,
      "OPENSSL_OUTPUT_INVALID",
      "the extracted CMS certificate set",
    );
    if (!filteredEmbedded.valid) return filteredEmbedded.result;
    if (filteredEmbedded.selected === 0) {
      return failure("TRUST_CHAIN_INVALID", "no embedded certificate covers the complete authenticated creation-time interval");
    }
    signerBytes = filteredSigner.bytes;
    embeddedBytes = filteredEmbedded.bytes;
    try {
      writeFileSync(paths.signer, signerBytes, { flag: "w", mode: 0o600 });
    } catch {
      return failure("OPENSSL_WORKSPACE_FAILED", "could not restrict the extracted signer certificate for interval verification");
    }
  }

  let untrustedBytes = embeddedBytes;
  if (policy.untrustedCertificates !== undefined) {
    untrustedBytes = bufferConcat([embeddedBytes, bufferFrom("\n", "utf8"), policy.untrustedCertificates]);
  }
  if (byteLength(untrustedBytes) === 0 || byteLength(untrustedBytes) > MAX_PKI_MATERIAL_BYTES) {
    return failure("UNTRUSTED_CERTIFICATES_INVALID", "the extracted certificate set is empty or exceeds the size limit");
  }
  try {
    writePrivate(paths.untrusted, untrustedBytes);
  } catch {
    return failure("OPENSSL_WORKSPACE_FAILED", "could not prepare the extracted signer chain for verification");
  }

  const endpointAttimes = policy.lowerAttime === policy.upperAttime
    ? [policy.lowerAttime]
    : [policy.lowerAttime, policy.upperAttime];
  for (let i = 0; i < arrayLength(endpointAttimes); i++) {
    const verifyArgs = addProviderArgs([
      "verify", "-CAfile", paths.roots, "-no-CApath", "-no-CAstore", "-untrusted", paths.untrusted,
      "-CRLfile", paths.crls, "-crl_check_all", "-purpose", "timestampsign", "-attime", endpointAttimes[i],
      "-auth_level", AUTH_LEVEL, "-verify_depth", VERIFY_DEPTH, "-x509_strict", "-check_ss_sig",
      "-trusted_first",
    ]);
    arrayPush(verifyArgs, paths.signer);
    run = runProcess(policy.executable, verifyArgs, paths.dir, paths.config, policy.timeoutMs, resourceBudget);
    if (!run.ran) return run.result;
    if (run.status !== 0) {
      return classifyCertificateFailure(
        run,
        "REVOCATION_STATUS_NOT_GOOD",
        "the signer chain and required CRL status did not verify across the authenticated creation-time interval",
      );
    }
  }

  return {
    ok: true,
    authenticated: true,
    code: "OK",
    reason: "RFC 3161 timestamp signature, signer chain, policy, purpose, validity, algorithms, imprint, and CRL status verified",
    genTime: inspected.parsed.genTime,
    accuracy: policy.accuracy,
    timeBounds: policy.timeBounds,
    policyOid: inspected.parsed.policyOid,
    hashAlgOid: inspected.parsed.hashAlgOid,
    signerDigestAlgOid: inspected.parsed.signerDigestAlgOid,
    signerSignatureAlgOid: inspected.parsed.signerSignatureAlgOid,
    verification: {
      backend: "openssl-3",
      securityLevel: 2,
      certificatePurpose: "timestampsign",
      clock: { now: policy.clockNow, maxFutureSkewMs: policy.maxFutureSkewMs },
      revocation: {
        mode: "crl-check-all",
        status: "GOOD",
        at: inspected.parsed.genTime,
        checkedTimeBounds: policy.timeBounds,
      },
    },
  };
}

function authenticateWithOpenSsl(inspected, policy, resourceBudget) {
  let dir;
  let result;
  try {
    dir = mkdtempSync(pathJoin(tmpdir(), "noa-tsa-"));
    chmodSync(dir, 0o700);
    const paths = {
      dir,
      config: pathJoin(dir, "openssl.cnf"),
      response: pathJoin(dir, "response.tsr"),
      roots: pathJoin(dir, "roots.pem"),
      crls: pathJoin(dir, "revocation.pem"),
      callerUntrusted: policy.untrustedCertificates === undefined ? undefined : pathJoin(dir, "caller-untrusted.pem"),
      token: pathJoin(dir, "token.der"),
      content: pathJoin(dir, "tstinfo.der"),
      signer: pathJoin(dir, "signer.pem"),
      embedded: pathJoin(dir, "embedded.pem"),
      untrusted: pathJoin(dir, "verified-untrusted.pem"),
    };
    writePrivate(paths.config, bufferFrom(OPENSSL_CONFIG, "utf8"));
    writePrivate(paths.response, inspected.raw);
    writePrivate(paths.roots, policy.trustRoots);
    writePrivate(paths.crls, policy.crls);
    if (paths.callerUntrusted !== undefined) writePrivate(paths.callerUntrusted, policy.untrustedCertificates);
    result = runOpenSslSequence(paths, inspected, policy, resourceBudget);
  } catch {
    result = failure("OPENSSL_WORKSPACE_FAILED", "could not create the private OpenSSL verification workspace");
  } finally {
    if (dir !== undefined) {
      try {
        rmSync(dir, { recursive: true, force: false, maxRetries: 0 });
      } catch {
        result = failure("OPENSSL_WORKSPACE_CLEANUP_FAILED", "could not remove the private OpenSSL verification workspace");
      }
    }
  }
  return result;
}

export function verifyStamp(anchor, stampRecord, options, resourceBudget) {
  try {
    const inspected = structurallyInspect(anchor, stampRecord);
    if (!inspected.valid) return failure(inspected.code, inspected.reason);
    if (inspected.parsed.signerInfoCount !== 1) {
      return failure("CMS_SIGNER_COUNT_INVALID", "the timestamp token must contain exactly one CMS SignerInfo");
    }
    if (inspected.parsed.embeddedCertificateCount < 1) {
      return failure("CMS_SIGNER_CERTIFICATE_MISSING", "the timestamp token must embed its CMS signer certificate");
    }
    if (!hasOwn(ALLOWED_SIGNER_DIGEST_OIDS, inspected.parsed.signerDigestAlgOid)) {
      return failure("CMS_DIGEST_ALGORITHM_DISALLOWED", "the CMS signer digest algorithm is not allowed");
    }
    if (!hasOwn(ALLOWED_SIGNATURE_OIDS, inspected.parsed.signerSignatureAlgOid)) {
      return failure("CMS_SIGNATURE_ALGORITHM_DISALLOWED", "the CMS signature algorithm is not allowed");
    }
    const policy = validatePolicy(options, inspected.parsed);
    if (!policy.valid) return policy.result;
    return authenticateWithOpenSsl(inspected, policy, resourceBudget);
  } catch {
    return failure("VERIFICATION_FAILED_CLOSED", "timestamp verification failed closed");
  }
}
