/**
 * Public resolver-parity proofs.
 *
 * G4 pins one canonical projection snapshot. RES-PAR-XRES-EQUIV compares the
 * independently exposed evidence and gate resolvers at the real verifier and
 * checks the public root-key decoder's declared-versus-absent field semantics.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createAlphaTrust, loadSchemas } from 'noa-gate';
import { getProjection as getGateProjectionSource } from '../../gate/src/projections.js';
import {
  ARTIFACTS,
  generateKeyPair,
  signArtifact,
  verifyArtifact,
  type KeyEntry,
} from 'noa-approval-artifacts';
import {
  asRootKeyEntryMap,
  buildResolvedKeyring,
  type DelegationDoc,
  type ManifestDoc,
} from 'noa-approval-evidence';
import { encodeDocument } from '../src/bytes.js';

const TENANT = 'example-tenant';
const schemas = loadSchemas();

type J = Record<string, unknown>;
const enc = (o: unknown): Uint8Array => encodeDocument(o as J);

test('G4: render uses the first canonical bytes when a stateful Object.keys changes its second face', () => {
  const projection = getGateProjectionSource('noa.command.exec');
  assert.ok(projection !== undefined, 'fixture: noa.command.exec projection is registered');
  const params = {
    executable: 'rm',
    argv: ['--help'],
    cwd: '/srv',
    targetEnv: 'production',
    allowedEnvHash: null,
    stdinHash: null,
  };
  const honest = projection.run(params);
  assert.equal(honest.ok, true, 'control: the ordinary projection input must be accepted');

  const realObjectKeys = Object.keys;
  let matchingReads = 0;
  Object.keys = (value: object): string[] => {
    const keys = realObjectKeys(value);
    const isSnapshotShape = keys.includes('executable') && keys.includes('argv') && keys.includes('targetEnv');
    if (!isSnapshotShape) return keys;
    matchingReads++;
    return matchingReads === 2 ? keys.filter((key) => key !== 'targetEnv') : keys;
  };
  let underPoison: ReturnType<typeof projection.run>;
  try {
    underPoison = projection.run(params);
  } finally {
    Object.keys = realObjectKeys;
  }

  assert.equal(matchingReads, 2, 'fixture: the stateful poison never reached its second face');
  assert.deepEqual(
    underPoison,
    honest,
    'render re-canonicalized the snapshot instead of consuming the same canonical bytes as paramsHash',
  );
});

function domainOf(spec: string): string {
  const domain = ARTIFACTS[spec]?.domain;
  assert.ok(typeof domain === 'string', `fixture: no signing domain registered for ${spec}`);
  return domain;
}

function entryOf(map: Record<string, KeyEntry>, kid: string, what: string): KeyEntry {
  const entry = map[kid];
  assert.ok(entry !== undefined, `fixture: ${what} has no entry for kid "${kid}"`);
  return entry;
}

const VALID_FROM = '2026-07-14T10:00:00.000Z';
const BEFORE_VALID_FROM = '2026-07-14T08:00:00.000Z';
const AFTER_VALID_FROM = '2026-07-14T12:00:00.000Z';
const REVOKED_AT = '2026-07-14T11:00:00.000Z';
const EXPIRES_AT = '2027-01-01T00:00:00.000Z';
const ENVELOPE_HASH = 'sha256:' + '1'.repeat(64);

function decisionBy(kid: string, privateKey: string, decidedAt: string): J {
  return signArtifact(
    enc({
      spec: 'noa.decision/0.1',
      holdEnvelopeHash: ENVELOPE_HASH,
      decision: 'APPROVE',
      reasonCode: 'vendor-verified',
      reasonEncryption: null,
      decidedAt,
      approverKid: kid,
    }),
    domainOf('noa.decision/0.1'),
    { kid, privateKey },
  );
}

function verdict(
  decision: J,
  keyring: Record<string, KeyEntry>,
  authorizationTime: string,
): { ok: boolean; reason?: string } {
  return verifyArtifact(
    enc(decision),
    enc({ schemas, keyring, now: AFTER_VALID_FROM, authorizationTime, riskClass: 'HIGH' }),
  );
}

test('[PROOF:RES-PAR-XRES-EQUIV] evidence and gate resolvers enforce the same activation semantics', () => {
  const outcomes: Record<string, { preRefused: boolean; postAccepted: boolean }> = {};

  {
    const root = generateKeyPair('xr-root-1');
    const authority = generateKeyPair('xr-authority-1');
    const approver = generateKeyPair('xr-approver-1');
    const revoked = generateKeyPair('xr-approver-revoked');
    const legacy = generateKeyPair('xr-approver-legacy');
    const malformed = generateKeyPair('xr-approver-malformed');
    const delegation = signArtifact(
      enc({
        spec: 'noa.key-delegation/0.1',
        tenant: TENANT,
        delegatedKid: authority.kid,
        delegatedPublicKey: authority.publicKey,
        permissions: ['key-manifest-sign'],
        validFrom: VALID_FROM,
        expiresAt: EXPIRES_AT,
      }),
      domainOf('noa.key-delegation/0.1'),
      { kid: root.kid, privateKey: root.privateKey },
    ) as unknown as DelegationDoc;
    const manifest = signArtifact(
      enc({
        spec: 'noa.key-manifest/0.1',
        tenant: TENANT,
        version: 1,
        issuedAt: AFTER_VALID_FROM,
        expiresAt: EXPIRES_AT,
        previousManifestHash: null,
        keys: [
          {
            kid: approver.kid,
            type: 'APPROVER',
            roles: ['approve-high'],
            publicKey: approver.publicKey,
            validFrom: VALID_FROM,
            revokedAt: null,
          },
          {
            kid: revoked.kid,
            type: 'APPROVER',
            roles: ['approve-high'],
            publicKey: revoked.publicKey,
            validFrom: VALID_FROM,
            revokedAt: REVOKED_AT,
          },
          {
            kid: legacy.kid,
            type: 'APPROVER',
            roles: ['approve-high'],
            publicKey: legacy.publicKey,
            validFrom: null,
            revokedAt: null,
          },
          {
            kid: malformed.kid,
            type: 'APPROVER',
            roles: ['approve-high'],
            publicKey: malformed.publicKey,
            validFrom: 'not-a-timestamp',
            revokedAt: null,
          },
        ],
      }),
      domainOf('noa.key-manifest/0.1'),
      { kid: authority.kid, privateKey: authority.privateKey },
    ) as unknown as ManifestDoc;
    const keyring = buildResolvedKeyring({}, delegation, manifest);

    const pre = verdict(decisionBy(approver.kid, approver.privateKey, BEFORE_VALID_FROM), keyring, BEFORE_VALID_FROM);
    const post = verdict(decisionBy(approver.kid, approver.privateKey, AFTER_VALID_FROM), keyring, AFTER_VALID_FROM);
    assert.match(pre.reason ?? '', /before its validFrom/, `evidence resolver: pre-activation reason: ${pre.reason}`);
    outcomes['evidence.buildResolvedKeyring'] = { preRefused: !pre.ok, postAccepted: post.ok };

    const revokedResult = verdict(
      decisionBy(revoked.kid, revoked.privateKey, AFTER_VALID_FROM),
      keyring,
      AFTER_VALID_FROM,
    );
    assert.equal(revokedResult.ok, false, 'a decision signed after the declared revocation verified clean');
    assert.match(revokedResult.reason ?? '', /was revoked at/, `revocation reason: ${revokedResult.reason}`);

    const legacyResult = verdict(
      decisionBy(legacy.kid, legacy.privateKey, BEFORE_VALID_FROM),
      keyring,
      BEFORE_VALID_FROM,
    );
    assert.equal(
      legacyResult.ok,
      true,
      `legacy entry without declared validFrom must stay active: ${legacyResult.reason}`,
    );

    const malformedResult = verdict(
      decisionBy(malformed.kid, malformed.privateKey, AFTER_VALID_FROM),
      keyring,
      AFTER_VALID_FROM,
    );
    assert.equal(malformedResult.ok, false, 'a malformed declared validFrom was dropped');
    assert.match(
      malformedResult.reason ?? '',
      /cannot evaluate activation time/,
      `malformed activation reason: ${malformedResult.reason}`,
    );
  }

  {
    const declared = asRootKeyEntryMap(
      enc({
        'root-x': {
          type: 'ROOT',
          publicKey: 'aa'.repeat(32),
          roles: [],
          validFrom: VALID_FROM,
          revokedAt: null,
        },
      }),
    );
    assert.equal(entryOf(declared, 'root-x', 'asRootKeyEntryMap(declared)').validFrom, VALID_FROM, 'declared field was dropped');

    const terse = asRootKeyEntryMap(enc({ 'root-y': 'aa'.repeat(32) }));
    assert.equal(
      entryOf(terse, 'root-y', 'asRootKeyEntryMap(terse)').validFrom,
      undefined,
      'an absent field was replaced with an invented activation',
    );
  }

  {
    const now = Date.parse(AFTER_VALID_FROM);
    const alpha = createAlphaTrust({ tenant: TENANT, now: () => now });
    const alphaValidFrom = entryOf(alpha.keyring, alpha.approver.kid, 'alpha keyring').validFrom;
    assert.ok(typeof alphaValidFrom === 'string', 'gate resolver dropped validFrom');
    const before = new Date(Date.parse(alphaValidFrom) - 3_600_000).toISOString();
    const after = new Date(now + 1_000).toISOString();
    const alphaApproverPrivateKey = alpha.approver.privateKey;
    assert.ok(typeof alphaApproverPrivateKey === 'string', 'alpha fixture has no approver signing key');

    const pre = verdict(decisionBy(alpha.approver.kid, alphaApproverPrivateKey, before), alpha.keyring, before);
    const post = verdict(decisionBy(alpha.approver.kid, alphaApproverPrivateKey, after), alpha.keyring, after);
    assert.match(pre.reason ?? '', /before its validFrom/, `gate resolver: pre-activation reason: ${pre.reason}`);
    outcomes['gate.createAlphaTrust'] = { preRefused: !pre.ok, postAccepted: post.ok };
  }

  for (const [resolver, outcome] of Object.entries(outcomes)) {
    assert.deepEqual(
      outcome,
      { preRefused: true, postAccepted: true },
      `resolver "${resolver}" diverges from declared activation semantics: ${JSON.stringify(outcome)}`,
    );
  }
  assert.equal(Object.keys(outcomes).length, 2, 'equivalence table lost a public resolver');
});
