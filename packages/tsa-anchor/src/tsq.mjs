/**
 * RFC 3161 §2.4.1/§2.4.2 wire structures — TimeStampReq builder + TimeStampResp/TSTInfo parser.
 * Built entirely on top of ./der.mjs's generic DER primitives. Parsing remains structural; the
 * authenticated verdict is owned by verify.mjs and its fixed-argument OpenSSL 3 binding.
 */
import { DerError, encInteger, encOid, encNull, encOctetString, encBoolean, encSequence, derDecode, readInteger, readIntegerBig, readOid, readGeneralizedTime } from "./der.mjs";
import { frozenTable, intrinsics } from "noa-receipt";

const { arrayLength, arrayPush, byteLength, isBuffer, toBigInt } = intrinsics;

export const SHA256_OID = "2.16.840.1.101.3.4.2.1";
const ID_SIGNED_DATA = "1.2.840.113549.1.7.2";
const ID_CT_TST_INFO = "1.2.840.113549.1.9.16.1.4";
// Frozen + null-rooted at construction (ADR §5.6): this table names the PKIStatus a caller
// branches on, so a writable `Object.prototype[2]` or a mutated entry would let "rejection"
// read back as something else for every caller at once.
const PKI_STATUS = frozenTable({ 0: "granted", 1: "grantedWithMods", 2: "rejection", 3: "waiting", 4: "revocationWarning", 5: "revocationNotification" });

/**
 * Build a DER-encoded RFC 3161 TimeStampReq over an ALREADY-COMPUTED digest. `hashedMessage` MUST
 * be the raw digest bytes (32 bytes for sha256) — never a hex/base64 string; the caller computes
 * the hash (see anchor-hash.mjs), this module only encodes the wire request. Field order (RFC 3161
 * §2.4.1): version, messageImprint, [nonce], [certReq] — reqPolicy/extensions are never emitted.
 */
export function buildTimeStampReq(hashedMessage, opts = {}) {
  if (!isBuffer(hashedMessage) || byteLength(hashedMessage) === 0) {
    throw new TypeError("buildTimeStampReq: hashedMessage must be a non-empty Buffer");
  }
  const hashAlgOid = opts.hashAlgOid ?? SHA256_OID;
  const certReq = opts.certReq ?? true; // default true: most public TSAs (e.g. FreeTSA) embed the signing cert only when asked
  const messageImprint = encSequence([encSequence([encOid(hashAlgOid), encNull()]), encOctetString(hashedMessage)]);
  const parts = [encInteger(1), messageImprint];
  if (opts.nonce !== undefined) arrayPush(parts, encInteger(opts.nonce));
  if (certReq) arrayPush(parts, encBoolean(true)); // DER canonical: DEFAULT FALSE is OMITTED, never encoded as FALSE
  return encSequence(parts);
}

function assertSequence(node, label) {
  if (!node || node.tagClass !== 0 || !node.constructed || node.tagNumber !== 0x10) {
    throw new DerError(`expected ${label} to be a SEQUENCE`);
  }
}
function unwrapExplicit(node, label) {
  if (!node || node.tagClass !== 2 || !node.constructed || !node.children || arrayLength(node.children) !== 1) {
    throw new DerError(`expected ${label} to be an EXPLICIT context tag wrapping exactly one value`);
  }
  return node.children[0];
}

function readImplicitAccuracyInteger(node, tagNumber, label) {
  if (!node || node.tagClass !== 2 || node.constructed || node.tagNumber !== tagNumber) {
    throw new DerError(`TSTInfo.accuracy.${label} must be a primitive IMPLICIT INTEGER`);
  }
  return readInteger({ tagClass: 0, constructed: false, tagNumber: 0x02, content: node.content });
}

function readAccuracy(node) {
  assertSequence(node, "TSTInfo.accuracy");
  let seconds = 0;
  let millis = 0;
  let micros = 0;
  let lastField = -1;
  const n = arrayLength(node.children);
  for (let i = 0; i < n; i++) {
    const field = node.children[i];
    if (field.tagClass === 0 && !field.constructed && field.tagNumber === 0x02) {
      if (lastField >= 0) throw new DerError("TSTInfo.accuracy.seconds is duplicated or out of order");
      seconds = readInteger(field);
      lastField = 0;
      continue;
    }
    if (field.tagClass === 2 && !field.constructed && field.tagNumber === 0) {
      if (lastField >= 1) throw new DerError("TSTInfo.accuracy.millis is duplicated or out of order");
      millis = readImplicitAccuracyInteger(field, 0, "millis");
      if (millis < 1 || millis > 999) throw new DerError("TSTInfo.accuracy.millis must be from 1 through 999");
      lastField = 1;
      continue;
    }
    if (field.tagClass === 2 && !field.constructed && field.tagNumber === 1) {
      if (lastField >= 2) throw new DerError("TSTInfo.accuracy.micros is duplicated or out of order");
      micros = readImplicitAccuracyInteger(field, 1, "micros");
      if (micros < 1 || micros > 999) throw new DerError("TSTInfo.accuracy.micros must be from 1 through 999");
      lastField = 2;
      continue;
    }
    throw new DerError("TSTInfo.accuracy contains an unknown or malformed field");
  }
  const totalMicroseconds = toBigInt(seconds) * 1000000n + toBigInt(millis) * 1000n + toBigInt(micros);
  return { seconds, millis, micros, totalMicroseconds: `${totalMicroseconds}` };
}

/**
 * Parse a DER-encoded RFC 3161 TimeStampResp far enough to extract what this package needs: the
 * PKIStatus, and — on a granted response — the embedded TSTInfo's policy, genTime and
 * messageImprint plus the CMS SignerInfo algorithm identifiers. STRUCTURAL PARSE ONLY: this
 * function never authenticates those values. verifyStamp binds them to a successful CMS/X.509/CRL
 * verification before returning ok:true. Navigates TimeStampResp -> ContentInfo -> SignedData ->
 * encapContentInfo -> eContent(OCTET STRING) -> TSTInfo BY FIXED FIELD POSITION (all TSTInfo fields
 * read here are mandatory and precede optional trailing fields).
 */
export function parseTimeStampResp(buf) {
  const resp = derDecode(buf);
  assertSequence(resp, "TimeStampResp");
  const statusInfo = resp.children[0];
  assertSequence(statusInfo, "PKIStatusInfo");
  const statusCode = readInteger(statusInfo.children[0]);
  const status = PKI_STATUS[statusCode] ?? `unknown(${statusCode})`;
  if (statusCode !== 0 && statusCode !== 1) {
    return { granted: false, statusCode, status };
  }
  if (arrayLength(resp.children) < 2) throw new DerError("TimeStampResp: status granted but timeStampToken is missing");

  const contentInfo = resp.children[1];
  assertSequence(contentInfo, "ContentInfo");
  const contentType = readOid(contentInfo.children[0]);
  if (contentType !== ID_SIGNED_DATA) throw new DerError(`ContentInfo.contentType is not id-signedData (got ${contentType})`);
  const signedData = unwrapExplicit(contentInfo.children[1], "ContentInfo.content");
  assertSequence(signedData, "SignedData");
  if (arrayLength(signedData.children) < 4) throw new DerError("SignedData is missing mandatory fields");

  const encapContentInfo = signedData.children[2]; // [0]=version [1]=digestAlgorithms [2]=encapContentInfo
  assertSequence(encapContentInfo, "EncapsulatedContentInfo");
  const eContentType = readOid(encapContentInfo.children[0]);
  if (eContentType !== ID_CT_TST_INFO) throw new DerError(`EncapsulatedContentInfo.eContentType is not id-ct-TSTInfo (got ${eContentType})`);
  if (arrayLength(encapContentInfo.children) < 2) throw new DerError("EncapsulatedContentInfo: eContent is missing");
  const eContentOctets = unwrapExplicit(encapContentInfo.children[1], "EncapsulatedContentInfo.eContent");
  if (eContentOctets.tagClass !== 0 || eContentOctets.constructed || eContentOctets.tagNumber !== 0x04) {
    throw new DerError("EncapsulatedContentInfo.eContent is not an OCTET STRING");
  }

  const tstInfo = derDecode(eContentOctets.content);
  assertSequence(tstInfo, "TSTInfo");
  if (arrayLength(tstInfo.children) < 5) throw new DerError("TSTInfo is missing mandatory fields");
  const policyOid = readOid(tstInfo.children[1]);
  const messageImprint = tstInfo.children[2]; // [0]=version [1]=policy [2]=messageImprint [3]=serialNumber [4]=genTime
  assertSequence(messageImprint, "TSTInfo.messageImprint");
  const hashAlgSeq = messageImprint.children[0];
  assertSequence(hashAlgSeq, "MessageImprint.hashAlgorithm");
  const hashAlgOid = readOid(hashAlgSeq.children[0]);
  const hashedMessageNode = messageImprint.children[1];
  if (hashedMessageNode.tagClass !== 0 || hashedMessageNode.constructed || hashedMessageNode.tagNumber !== 0x04) {
    throw new DerError("MessageImprint.hashedMessage is not an OCTET STRING");
  }
  const genTime = readGeneralizedTime(tstInfo.children[4]);
  const accuracyNode = tstInfo.children[5];
  const accuracy = accuracyNode?.tagClass === 0 && accuracyNode.tagNumber === 0x10
    ? readAccuracy(accuracyNode)
    : undefined;

  // signerInfos is the mandatory final SignedData field. Certificates [0] and CRLs [1] may occur
  // before it, but cannot move it away from the final position. Do not mistake an empty SET for an
  // authenticated token: verifyStamp rejects count != 1 before invoking the cryptographic backend.
  const signedDataLength = arrayLength(signedData.children);
  const signerInfos = signedData.children[signedDataLength - 1];
  if (!signerInfos || signerInfos.tagClass !== 0 || !signerInfos.constructed || signerInfos.tagNumber !== 0x11) {
    throw new DerError("SignedData.signerInfos is not a SET");
  }
  const signerInfoCount = arrayLength(signerInfos.children);
  let embeddedCertificateCount = 0;
  for (let k = 3; k < signedDataLength - 1; k++) {
    const candidate = signedData.children[k];
    if (candidate.tagClass === 2 && candidate.tagNumber === 0) {
      if (!candidate.constructed) throw new DerError("SignedData.certificates must be constructed");
      const certificateCount = arrayLength(candidate.children);
      for (let c = 0; c < certificateCount; c++) {
        const certificateChoice = candidate.children[c];
        // RFC 5652 CertificateChoices uses a bare Certificate SEQUENCE for an X.509 certificate;
        // the context-tagged alternatives are not signer certificates usable by OpenSSL here.
        if (certificateChoice.tagClass === 0 && certificateChoice.constructed && certificateChoice.tagNumber === 0x10) {
          embeddedCertificateCount++;
        }
      }
    }
  }
  let signerDigestAlgOid;
  let signerSignatureAlgOid;
  if (signerInfoCount === 1) {
    const signerInfo = signerInfos.children[0];
    assertSequence(signerInfo, "SignerInfo");
    if (arrayLength(signerInfo.children) < 5) throw new DerError("SignerInfo is missing mandatory fields");
    const digestAlgorithm = signerInfo.children[2];
    assertSequence(digestAlgorithm, "SignerInfo.digestAlgorithm");
    signerDigestAlgOid = readOid(digestAlgorithm.children[0]);

    // signedAttrs is [0] IMPLICIT and optional. The signatureAlgorithm follows it when present.
    let signatureAlgorithmIndex = 3;
    const possibleSignedAttrs = signerInfo.children[signatureAlgorithmIndex];
    if (possibleSignedAttrs?.tagClass === 2 && possibleSignedAttrs.tagNumber === 0) signatureAlgorithmIndex++;
    const signatureAlgorithm = signerInfo.children[signatureAlgorithmIndex];
    assertSequence(signatureAlgorithm, "SignerInfo.signatureAlgorithm");
    signerSignatureAlgOid = readOid(signatureAlgorithm.children[0]);
    const signature = signerInfo.children[signatureAlgorithmIndex + 1];
    if (!signature || signature.tagClass !== 0 || signature.constructed || signature.tagNumber !== 0x04 || byteLength(signature.content) === 0) {
      throw new DerError("SignerInfo.signature must be a non-empty OCTET STRING");
    }
  }

  // Optional nonce (RFC 3161 TSTInfo, after genTime). The trailing optional fields are accuracy
  // (SEQUENCE), ordering (BOOLEAN), nonce (INTEGER), tsa/[0], extensions/[1]; the nonce is the only
  // universal-primitive INTEGER among them, so the first bare INTEGER after index 4 is it. Returned
  // as a BigInt (nonces are up to 64-bit) or undefined when the TSA did not echo one.
  let nonce;
  const tstInfoLength = arrayLength(tstInfo.children);
  for (let k = 5; k < tstInfoLength; k++) {
    const ch = tstInfo.children[k];
    if (ch.tagClass === 0 && !ch.constructed && ch.tagNumber === 0x02) {
      nonce = readIntegerBig(ch);
      break;
    }
  }

  return {
    granted: true,
    statusCode,
    status,
    policyOid,
    hashAlgOid,
    hashedMessage: hashedMessageNode.content,
    genTime,
    accuracy,
    nonce,
    signerInfoCount,
    embeddedCertificateCount,
    signerDigestAlgOid,
    signerSignatureAlgOid,
    tstInfoBytes: eContentOctets.content,
  };
}
