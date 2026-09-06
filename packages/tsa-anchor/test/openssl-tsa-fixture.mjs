import { spawnSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { anchorHashDigest } from "../src/anchor-hash.mjs";
import { buildTimeStampReq } from "../src/tsq.mjs";
import { derDecode, encGeneralizedTime, encInteger, encSequence } from "../src/der.mjs";

const POLICY = "1.2.3.4.5";
const OTHER_POLICY = "1.2.3.4.6";

function findOpenSsl() {
  const candidates = [];
  if (typeof process.env.OPENSSL_BIN === "string") candidates.push(process.env.OPENSSL_BIN);
  candidates.push("/opt/homebrew/bin/openssl", "/usr/local/bin/openssl", "/usr/bin/openssl");
  for (const candidate of candidates) {
    if (!candidate || !existsSync(candidate)) continue;
    const executable = realpathSync(candidate);
    const probe = spawnSync(executable, ["version"], { encoding: "utf8", timeout: 5000 });
    if (probe.status === 0 && probe.stdout.startsWith("OpenSSL 3.")) return executable;
  }
  throw new Error("OpenSSL 3.x is required for the authenticated RFC 3161 tests (set OPENSSL_BIN to its absolute path)");
}

function shellQuote(value) {
  return `'${value.replaceAll("'", `'\\''`)}'`;
}

/** Test-only process counter that preserves the exact OpenSSL argv unless `stall` is requested. */
export function createCountingOpenSsl(dir, executable, { stall = false } = {}) {
  const callsPath = join(dir, "openssl-calls.log");
  const wrapperPath = join(dir, "openssl-counting");
  const command = stall ? "exec /bin/sleep 2" : `exec ${shellQuote(executable)} "$@"`;
  writeFileSync(
    wrapperPath,
    `#!/bin/sh\nprintf 'call\\n' >> ${shellQuote(callsPath)}\n${command}\n`,
    { mode: 0o700 },
  );
  chmodSync(wrapperPath, 0o700);
  return {
    executable: wrapperPath,
    count() {
      if (!existsSync(callsPath)) return 0;
      const text = readFileSync(callsPath, "utf8");
      return text === "" ? 0 : text.trim().split("\n").length;
    },
  };
}

function run(executable, args, cwd) {
  const result = spawnSync(executable, args, {
    cwd,
    encoding: "utf8",
    timeout: 30000,
    maxBuffer: 2 * 1024 * 1024,
  });
  if (result.status !== 0) {
    throw new Error(`fixture command failed (${args.join(" ")}): ${result.stderr || result.stdout}`);
  }
}

function utcTime(date) {
  const iso = date.toISOString();
  return iso.slice(0, 4) + iso.slice(5, 7) + iso.slice(8, 10) + iso.slice(11, 13) + iso.slice(14, 16) + iso.slice(17, 19) + "Z";
}

function encodeLength(n) {
  if (n < 0x80) return Buffer.from([n]);
  const bytes = [];
  let v = n;
  while (v > 0) {
    bytes.unshift(v & 0xff);
    v = Math.floor(v / 256);
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function encodeNode(node, children = node.children) {
  const tag = (node.tagClass << 6) | (node.constructed ? 0x20 : 0) | node.tagNumber;
  const content = node.constructed ? Buffer.concat(children.map((child) => encodeNode(child))) : node.content;
  return Buffer.concat([Buffer.from([tag]), encodeLength(content.length), content]);
}

function encodeGeneralizedTimeText(value) {
  const content = Buffer.from(value, "ascii");
  return Buffer.concat([Buffer.from([0x18]), encodeLength(content.length), content]);
}

/** Remove SignedData.certificates without touching its signed content or SignerInfo. */
function withoutEmbeddedCertificates(response) {
  const root = derDecode(response);
  const contentInfo = root.children[1];
  const explicitSignedData = contentInfo.children[1];
  const signedData = explicitSignedData.children[0];
  const kept = signedData.children.filter((node) => !(node.tagClass === 2 && node.tagNumber === 0));
  const rebuiltSignedData = encodeNode(signedData, kept);
  const rebuiltExplicit = Buffer.concat([Buffer.from([0xa0]), encodeLength(rebuiltSignedData.length), rebuiltSignedData]);
  const rebuiltContentInfo = encSequence([encodeNode(contentInfo.children[0]), rebuiltExplicit]);
  return encSequence([encodeNode(root.children[0]), rebuiltContentInfo]);
}

function writeTsaConfig(dir, name, cert, key) {
  const path = join(dir, `${name}.cnf`);
  writeFileSync(
    path,
    `[ tsa ]\n` +
      `default_tsa = tsa_config\n` +
      `[ tsa_config ]\n` +
      `dir = ${dir}\n` +
      `serial = $dir/tsaserial\n` +
      `signer_cert = $dir/${cert}\n` +
      `certs = $dir/root.pem\n` +
      `signer_key = $dir/${key}\n` +
      `signer_digest = sha256\n` +
      `default_policy = ${POLICY}\n` +
      `other_policies = ${OTHER_POLICY}\n` +
      `digests = sha256\n` +
      `accuracy = secs:1\n` +
      `ordering = no\n` +
      `tsa_name = yes\n` +
      `ess_cert_id_chain = yes\n` +
      `ess_cert_id_alg = sha256\n`,
    { mode: 0o600 },
  );
  return path;
}

function issue(executable, dir, name, extension, dates, bits = 3072) {
  run(executable, ["req", "-newkey", `rsa:${bits}`, "-sha256", "-nodes", "-subj", `/CN=${name}`, "-keyout", `${name}.key`, "-out", `${name}.csr`], dir);
  const args = ["ca", "-batch", "-config", "ca.cnf", "-extensions", extension, "-in", `${name}.csr`, "-out", `${name}.pem`];
  if (dates) args.push("-startdate", dates.start, "-enddate", dates.end);
  run(executable, args, dir);
}

function stamp(executable, dir, config, output, extra = [], query = "request.tsq") {
  run(executable, ["ts", "-reply", "-config", config, "-section", "tsa_config", "-queryfile", query, ...extra, "-out", output], dir);
}

export function createAuthenticatedTsaFixture(anchor) {
  const executable = findOpenSsl();
  const dir = mkdtempSync(join(tmpdir(), "noa-tsa-test-"));
  chmodSync(dir, 0o700);
  try {
    mkdirSync(join(dir, "newcerts"), { mode: 0o700 });
    writeFileSync(join(dir, "index.txt"), "", { mode: 0o600 });
    writeFileSync(join(dir, "serial"), "1000\n", { mode: 0o600 });
    writeFileSync(join(dir, "crlnumber"), "1000\n", { mode: 0o600 });
    writeFileSync(join(dir, "tsaserial"), "01\n", { mode: 0o600 });
    writeFileSync(
      join(dir, "ca.cnf"),
      `[ ca ]\n` +
        `default_ca = CA_default\n` +
        `[ CA_default ]\n` +
        `dir = ${dir}\n` +
        `database = $dir/index.txt\n` +
        `new_certs_dir = $dir/newcerts\n` +
        `certificate = $dir/root.pem\n` +
        `private_key = $dir/root.key\n` +
        `serial = $dir/serial\n` +
        `crlnumber = $dir/crlnumber\n` +
        `default_md = sha256\n` +
        `default_days = 3650\n` +
        `default_crl_days = 30\n` +
        `policy = policy_any\n` +
        `unique_subject = no\n` +
        `copy_extensions = none\n` +
        `[ policy_any ]\n` +
        `commonName = supplied\n` +
        `[ tsa_ext ]\n` +
        `basicConstraints = critical,CA:FALSE\n` +
        `keyUsage = critical,digitalSignature\n` +
        `extendedKeyUsage = critical,timeStamping\n` +
        `subjectKeyIdentifier = hash\n` +
        `authorityKeyIdentifier = keyid,issuer\n` +
        `[ wrong_eku_ext ]\n` +
        `basicConstraints = critical,CA:FALSE\n` +
        `keyUsage = critical,digitalSignature\n` +
        `extendedKeyUsage = critical,codeSigning\n` +
        `subjectKeyIdentifier = hash\n` +
        `authorityKeyIdentifier = keyid,issuer\n`,
      { mode: 0o600 },
    );

    run(executable, ["req", "-x509", "-newkey", "rsa:3072", "-sha256", "-nodes", "-days", "3650", "-subj", "/CN=NOA-Test-Root", "-keyout", "root.key", "-out", "root.pem", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"], dir);
    run(executable, ["req", "-x509", "-newkey", "rsa:3072", "-sha256", "-nodes", "-days", "3650", "-subj", "/CN=Wrong-Test-Root", "-keyout", "wrong-root.key", "-out", "wrong-root.pem", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"], dir);

    const now = Date.now();
    issue(executable, dir, "valid-tsa", "tsa_ext");
    issue(executable, dir, "expired-tsa", "tsa_ext", {
      start: utcTime(new Date(now - 4 * 86400000)),
      end: utcTime(new Date(now - 2 * 86400000)),
    });
    issue(executable, dir, "future-tsa", "tsa_ext", {
      start: utcTime(new Date(now + 2 * 86400000)),
      end: utcTime(new Date(now + 30 * 86400000)),
    });
    issue(executable, dir, "wrong-eku-tsa", "wrong_eku_ext");
    issue(executable, dir, "weak-tsa", "tsa_ext", undefined, 1024);
    issue(executable, dir, "revoked-tsa", "tsa_ext");
    run(executable, ["ca", "-config", "ca.cnf", "-revoke", "revoked-tsa.pem", "-crl_reason", "keyCompromise"], dir);
    run(executable, ["ca", "-gencrl", "-config", "ca.cnf", "-out", "root.crl.pem"], dir);
    run(executable, ["ca", "-gencrl", "-config", "ca.cnf", "-crl_lastupdate", "20200101000000Z", "-crl_nextupdate", "20200102000000Z", "-out", "stale.crl.pem"], dir);

    writeFileSync(join(dir, "request.tsq"), buildTimeStampReq(anchorHashDigest(anchor), { certReq: true }), { mode: 0o600 });
    const validConfig = writeTsaConfig(dir, "valid", "valid-tsa.pem", "valid-tsa.key");
    const expiredConfig = writeTsaConfig(dir, "expired", "expired-tsa.pem", "expired-tsa.key");
    const futureConfig = writeTsaConfig(dir, "future", "future-tsa.pem", "future-tsa.key");
    const revokedConfig = writeTsaConfig(dir, "revoked", "revoked-tsa.pem", "revoked-tsa.key");
    const weakConfig = writeTsaConfig(dir, "weak", "weak-tsa.pem", "weak-tsa.key");
    stamp(executable, dir, validConfig, "valid.tsr");
    stamp(executable, dir, validConfig, "other-policy.tsr", ["-tspolicy", OTHER_POLICY]);
    stamp(executable, dir, expiredConfig, "expired.tsr");
    stamp(executable, dir, futureConfig, "future.tsr");
    stamp(executable, dir, revokedConfig, "revoked.tsr");
    stamp(executable, dir, weakConfig, "weak.tsr");

    run(executable, ["ts", "-reply", "-in", "valid.tsr", "-token_out", "-out", "valid.token.der"], dir);
    run(executable, ["cms", "-verify", "-binary", "-inform", "DER", "-in", "valid.token.der", "-noverify", "-out", "valid.tstinfo.der"], dir);
    const validTstInfo = derDecode(readFileSync(join(dir, "valid.tstinfo.der")));
    const farFuture = new Date(now + 3 * 365 * 86400000);
    farFuture.setUTCMilliseconds(0);
    const futureFields = validTstInfo.children.map((node, index) => index === 4 ? encGeneralizedTime(farFuture) : encodeNode(node));
    writeFileSync(join(dir, "future-gentime.tstinfo.der"), encSequence(futureFields), { mode: 0o600 });
    const wholeGenTime = validTstInfo.children[4].content.toString("ascii");
    const fractionalFields = validTstInfo.children.map((node, index) =>
      index === 4 ? encodeGeneralizedTimeText(wholeGenTime.slice(0, -1) + ".500Z") : encodeNode(node));
    writeFileSync(join(dir, "fractional-gentime.tstinfo.der"), encSequence(fractionalFields), { mode: 0o600 });
    run(executable, ["cms", "-sign", "-binary", "-nodetach", "-cades", "-nosmimecap", "-in", "future-gentime.tstinfo.der", "-signer", "valid-tsa.pem", "-inkey", "valid-tsa.key", "-md", "sha256", "-econtent_type", "1.2.840.113549.1.9.16.1.4", "-outform", "DER", "-out", "future-gentime.token.der"], dir);
    run(executable, ["cms", "-sign", "-binary", "-nodetach", "-cades", "-nosmimecap", "-in", "fractional-gentime.tstinfo.der", "-signer", "valid-tsa.pem", "-inkey", "valid-tsa.key", "-md", "sha256", "-econtent_type", "1.2.840.113549.1.9.16.1.4", "-outform", "DER", "-out", "fractional-gentime.token.der"], dir);
    run(executable, ["cms", "-sign", "-binary", "-nodetach", "-cades", "-nosmimecap", "-in", "valid.tstinfo.der", "-signer", "wrong-eku-tsa.pem", "-inkey", "wrong-eku-tsa.key", "-md", "sha256", "-econtent_type", "1.2.840.113549.1.9.16.1.4", "-outform", "DER", "-out", "wrong-eku.token.der"], dir);
    run(executable, ["cms", "-sign", "-binary", "-nodetach", "-cades", "-nosmimecap", "-in", "valid.tstinfo.der", "-signer", "valid-tsa.pem", "-inkey", "valid-tsa.key", "-md", "sha256", "-keyopt", "rsa_padding_mode:pss", "-keyopt", "rsa_mgf1_md:sha1", "-keyopt", "rsa_pss_saltlen:digest", "-econtent_type", "1.2.840.113549.1.9.16.1.4", "-outform", "DER", "-out", "pss-mgf1-sha1.token.der"], dir);
    const wrongEkuResponse = encSequence([encSequence([encInteger(0)]), readFileSync(join(dir, "wrong-eku.token.der"))]);
    const futureGenTimeResponse = encSequence([encSequence([encInteger(0)]), readFileSync(join(dir, "future-gentime.token.der"))]);
    const fractionalGenTimeResponse = encSequence([encSequence([encInteger(0)]), readFileSync(join(dir, "fractional-gentime.token.der"))]);
    const pssMgf1Sha1Response = encSequence([encSequence([encInteger(0)]), readFileSync(join(dir, "pss-mgf1-sha1.token.der"))]);
    const validResponse = readFileSync(join(dir, "valid.tsr"));
    const badSignature = Buffer.from(validResponse);
    badSignature[badSignature.length - 1] ^= 0x01;

    const record = (bytes) => ({ tsr: bytes.toString("base64") });
    let additionalStampNumber = 0;
    return {
      executable,
      policyOid: POLICY,
      otherPolicyOid: OTHER_POLICY,
      trustRoots: readFileSync(join(dir, "root.pem")),
      wrongTrustRoots: readFileSync(join(dir, "wrong-root.pem")),
      crls: readFileSync(join(dir, "root.crl.pem")),
      staleCrls: readFileSync(join(dir, "stale.crl.pem")),
      signerCertificate: readFileSync(join(dir, "valid-tsa.pem")),
      valid: record(validResponse),
      otherPolicy: record(readFileSync(join(dir, "other-policy.tsr"))),
      expired: record(readFileSync(join(dir, "expired.tsr"))),
      future: record(readFileSync(join(dir, "future.tsr"))),
      futureGenTime: record(futureGenTimeResponse),
      futureGenTimeValue: farFuture.toISOString(),
      fractionalGenTime: record(fractionalGenTimeResponse),
      revoked: record(readFileSync(join(dir, "revoked.tsr"))),
      weak: record(readFileSync(join(dir, "weak.tsr"))),
      wrongEku: record(wrongEkuResponse),
      pssMgf1Sha1: record(pssMgf1Sha1Response),
      badSignature: record(badSignature),
      noCertificate: record(withoutEmbeddedCertificates(validResponse)),
      stampFor(otherAnchor) {
        additionalStampNumber++;
        const requestName = `additional-${additionalStampNumber}.tsq`;
        const responseName = `additional-${additionalStampNumber}.tsr`;
        writeFileSync(join(dir, requestName), buildTimeStampReq(anchorHashDigest(otherAnchor), { certReq: true }), { mode: 0o600 });
        stamp(executable, dir, validConfig, responseName, [], requestName);
        return record(readFileSync(join(dir, responseName)));
      },
      cleanup() {
        rmSync(dir, { recursive: true, force: true });
      },
    };
  } catch (error) {
    rmSync(dir, { recursive: true, force: true });
    throw error;
  }
}
