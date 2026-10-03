// Deterministic synthetic fixtures. Seeds here are public test data, never deployment keys.
import { createPrivateKey, createPublicKey, createHash } from 'node:crypto';
import { mkdirSync, readdirSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import { join as joinPath } from 'node:path';
import { pathToFileURL } from 'node:url';
import { canonicalize } from '../dist/src/jcs.js';
import { signArtifact } from '../dist/src/sign.js';
import { refHash, receiptRefHash } from '../dist/src/refhash.js';
import { signingMessage, signEd25519, sha256Prefixed } from '../dist/src/crypto.js';
import { receiptHashInput } from '../../../dist/src/canonicalize.js';
import { LEDGER_TRANSFER_SCHEMA_ID, LEDGER_TRANSFER_DISPLAY_ID, projectLedgerTransfer } from '../../../dist/src/ledger-transfer.js';
import { projectionIdentityHash } from '../../../dist/src/deploy-release.js';
import { corpusDir } from './vault-schema-fixtures.mjs';

export const NOW = '2030-01-02T12:00:00.000Z';
export const domains = {
  'noa.vault-approver-set/0.1': 'NOA-VaultApproverSet-v0.1-sig',
  'noa.vault-class-policy/0.1': 'NOA-VaultClassPolicy-v0.1-sig',
  'noa.vault-approver-join/0.1': 'NOA-VaultApproverJoin-v0.1-sig',
  'noa.vault-result/0.1': 'NOA-VaultResult-v0.1-sig',
  'noa.device-cosignature/0.1': 'NOA-DeviceCosignature-v0.1-sig',
  'noa.hold/0.1': 'NOA-Hold-v0.1-sig',
  'noa.decision/0.1': 'NOA-Decision-v0.1-sig',
  'noa.execution-grant/0.1': 'NOA-ExecGrant-v0.1-sig',
};
export const keys = Object.fromEntries(['root-example','gate-example','guard-example','approver-example-1','approver-example-2','console-example','unknown-example'].map(kid => {
  const seed = createHash('sha256').update(`vault-conformance-test-only:${kid}`).digest();
  const privateKey = createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),seed]),format:'der',type:'pkcs8'});
  return [kid, {kid, privateKey:privateKey.export({format:'der',type:'pkcs8'}).toString('base64'), publicKey:createPublicKey(privateKey).export({format:'der',type:'spki'}).toString('base64')}];
}));
export const pin = key => sha256Prefixed(Buffer.from(key, 'base64'));
export const timestamp = delta => new Date(Date.parse(NOW) + delta * 1000).toISOString();
export function signed(doc, kid = doc.sig?.kid) {
  const unsigned = structuredClone(doc); delete unsigned.sig;
  return signArtifact(JSON.stringify(unsigned), domains[doc.spec], keys[kid]);
}
function receipt(doc, kid = 'gate-example') {
  const value = structuredClone(doc);
  value.sig = {alg:'ed25519',kid,value:''};
  value.chain.hash = receiptRefHash(value);
  value.sig.value = signEd25519(keys[kid].privateKey, signingMessage('NOA-Receipt-v0.1-sig',receiptHashInput(value)));
  return value;
}
const probeDescriptor = {canonical:'noa.vault.probe',members:['run','vault'],rows:['Action','Vault','Run'],spec:'noa.vault.probe/1'};
export const probeImplementation = refHash(probeDescriptor);
export const probeIdentities = Object.fromEntries([['actionSchema','schema'],['displayProjection','display']].map(([kind,suffix]) => {
  const d={id:`noa.vault.probe.${suffix}`,version:1,kind,implementation:probeImplementation};
  return [kind,{id:d.id,version:1,hash:projectionIdentityHash(d)}];
}));
export function projection(parameters, canonical) {
  if (canonical === 'noa.ledger.transfer') return projectLedgerTransfer(JSON.stringify(parameters));
  if (canonical === 'noa.vault.probe') return {ok:true,paramsHash:refHash(parameters),display:{Action:canonical,Vault:parameters.vault,Run:parameters.run},...probeIdentities};
  return {ok:false};
}
export function join(kid) {
  return signed({spec:'noa.vault-approver-join/0.1',tenant:'tenant-example',vaultId:'vault-example',kid,publicKey:keys[kid].publicKey,
    hpkePublicKey:'MCowBQYDK2VuAyEAB9IPISUDRCsglgSq+XTYZdgcCIzkZautSZc+kpo/iHA=',deviceId:`device-${kid}`,custody:'software-native',cosignPublicKey:null,attestationChain:null,createdAt:timestamp(-3600)},kid);
}
export function bind(w) {
  const b=w.bundle;
  w.state.set=signed(w.state.set, w.state.set.sig?.kid ?? 'root-example');
  w.state.policy=signed(w.state.policy, w.state.policy.sig?.kid ?? 'root-example');
  b.deferredReceipt=receipt(b.deferredReceipt,b.deferredReceipt.sig?.kid);
  b.approvalReceipt.chain.prevHash=b.deferredReceipt.chain.hash;
  b.approvalReceipt=receipt(b.approvalReceipt,b.approvalReceipt.sig?.kid);
  b.hold.deferredReceiptHash=b.deferredReceipt.chain.hash;
  b.hold=signed(b.hold,b.hold.gateKid);
  b.decisions=b.decisions.map(d=>signed({...d,holdEnvelopeHash:refHash(b.hold)},d.approverKid));
  b.grant=signed({...b.grant,holdEnvelopeHash:refHash(b.hold),approvalReceiptHash:b.approvalReceipt.chain.hash},b.grant.sig?.kid ?? 'gate-example');
  return w;
}
export function world() {
  const parameters={amount:'25',fromAccount:'account-example-1',ledger:'vault-example',salt:'000102030405060708090a0b0c0d0e0f',toAccount:'account-example-2',unit:'XTS'};
  const p=projectLedgerTransfer(JSON.stringify(parameters));
  const action={id:'transfer-example',canonical:'noa.ledger.transfer',riskClass:'HIGH',paramsHash:p.paramsHash,reversible:false};
  const makeReceipt=(id,seq,verdict)=>({spec:'noa.receipt/0.1',id,ts:timestamp(-30),scope:{tenant:'tenant-example',chain:'chain-example'},agent:{id:'gate-example',principal:'SERVICE'},action:{...action},governance:{mode:'on',verdict,sandboxed:false,...(seq?{approval:{by:'approver-example-1',at:timestamp(-30)}}:{})},chain:{seq,prevHash:null,hash:refHash({})}});
  const lifecycle={tenant:'tenant-example',vaultId:'vault-example',version:1,issuedAt:timestamp(-3600),notBefore:timestamp(-3600),expiresAt:timestamp(86400)};
  return bind({state:{pins:{tenant:'tenant-example',vaultId:'vault-example',rootKid:'root-example',rootPublicKey:keys['root-example'].publicKey,maxSetLifeSeconds:2592000,maxPolicyLifeSeconds:2592000,maxClockSkewSeconds:60},
    set:{spec:'noa.vault-approver-set/0.1',...lifecycle,previousSetHash:null,keyManifestHash:refHash({epoch:1}),gateKeys:[{kid:'gate-example',publicKey:keys['gate-example'].publicKey,roles:['hold-signer','execution-signer'],standby:false,tlsClientSpki:refHash({test:'gate-tls'})}],guardKey:{kid:'guard-example',publicKey:keys['guard-example'].publicKey},approvers:['approver-example-1','approver-example-2'].map(kid=>({kid,publicKey:keys[kid].publicKey,deviceId:`device-${kid}`,custody:'software-native',cosignPublicKey:null,attestationDigest:null,joinHash:refHash(join(kid))})),probe:{kid:'probe-example',tlsClientSpki:refHash({test:'probe-tls'})},liftSuspensions:[],clockSkewSeconds:60},
    policy:{spec:'noa.vault-class-policy/0.1',...lifecycle,previousPolicyHash:null,minArtifactVersions:Object.fromEntries(['noa.vault-authority-bundle','noa.hold','noa.receipt','noa.decision','noa.execution-grant','noa.device-cosignature'].map(x=>[x,'0.1'])),classes:[{canonical:'noa.ledger.transfer',actionSchema:LEDGER_TRANSFER_SCHEMA_ID,displayProjection:LEDGER_TRANSFER_DISPLAY_ID,audienceMember:'ledger',quorum:1,requiredApprovers:[],maxGrantLifeSeconds:600,maxApprovalAgeSeconds:900,limits:{maxAmount:'100',unit:'XTS'},probe:false},{canonical:'noa.vault.probe',...probeIdentities,audienceMember:'vault',quorum:1,requiredApprovers:[],maxGrantLifeSeconds:600,maxApprovalAgeSeconds:900,limits:{},probe:true}],emergency:null},
    now:NOW,floor:timestamp(-7200),suspended:[],frozen:false,revision:1,consumptions:[]},
    bundle:{spec:'noa.vault-authority-bundle/0.1',hold:{spec:'noa.hold/0.1',holdId:'hold-example',deferredReceiptId:'receipt-deferred-example',deferredReceiptHash:refHash({}),mode:'ENFORCED',displayCiphertextHash:refHash(p.display),actionSchema:LEDGER_TRANSFER_SCHEMA_ID,displayProjection:LEDGER_TRANSFER_DISPLAY_ID,canonicalization:'JCS-RFC8785',keyManifestVersion:1,keyManifestHash:refHash({epoch:1}),tenant:'tenant-example',expiresAt:timestamp(600),nonce:'hold-nonce-example',gateKid:'gate-example'},
    deferredReceipt:makeReceipt('receipt-deferred-example',0,'DEFERRED'),approvalReceipt:makeReceipt('receipt-approval-example',1,'ALLOWED'),decisions:[{spec:'noa.decision/0.1',holdEnvelopeHash:refHash({}),decision:'APPROVE',reasonCode:null,reasonEncryption:null,decidedAt:timestamp(-30),approverKid:'approver-example-1'}],cosignatures:[],grant:{spec:'noa.execution-grant/0.1',grantId:'grant-example',holdId:'hold-example',paramsHash:p.paramsHash,holdEnvelopeHash:refHash({}),approvalReceiptHash:refHash({}),issuedAt:timestamp(-10),expiresAt:timestamp(300),maxUses:1,nonce:'10'.repeat(32)},parameters}});
}

export function buildCorpus() {
  const vectors=[];
  function add(id,code,mutate=()=>{}, options={}) {
    const w=world(); mutate(w);
    vectors.push({id,operation:options.operation??'verify',state:w.state,...(options.candidate?{candidate:options.candidate(w),candidateSchemaValid:options.candidateSchemaValid??true}:{}),...(options.verifyAfterInstall?{verifyAfterInstall:true}:{}),requests:options.requests?.(w)??[{bundle:w.bundle,...options.request}],expected:options.expected??[{code,consumptions:code==='VV_OK'?1:0,effects:code==='VV_OK'?1:0}],schemaValid:options.schemaValid??true});
  }
  const rebind=fn=>w=>{fn(w);bind(w);};
  add('accept-exact-authority','VV_OK');
  add('accept-distinct-quorum','VV_OK',rebind(w=>{w.state.policy.classes[0].quorum=2;w.bundle.decisions.push({...w.bundle.decisions[0],approverKid:'approver-example-2'});}));
  add('accept-approval-age-boundary','VV_OK',rebind(w=>w.bundle.decisions[0].decidedAt=timestamp(-900)));
  add('accept-skew-boundary','VV_OK',rebind(w=>w.bundle.grant.issuedAt=timestamp(60)));
  add('accept-grant-life-boundary','VV_OK',rebind(w=>w.bundle.grant.expiresAt=timestamp(590)));
  add('accept-diagnostic-record','VV_OK',rebind(w=>{const b=w.bundle;b.parameters={vault:'vault-example',run:'20'.repeat(16)};const p=projection(b.parameters,'noa.vault.probe');b.hold.actionSchema=p.actionSchema;b.hold.displayProjection=p.displayProjection;b.hold.displayCiphertextHash=refHash(p.display);for(const r of [b.deferredReceipt,b.approvalReceipt]) {r.action.canonical='noa.vault.probe';r.action.paramsHash=p.paramsHash;} b.grant.paramsHash=p.paramsHash;}));
  add('wrong-grant-key','VV_GRANT_SIGNER',w=>w.bundle.grant=signed(w.bundle.grant,'unknown-example'));
  add('console-signed-grant','VV_GRANT_SIGNER',w=>w.bundle.grant=signed(w.bundle.grant,'console-example'));
  add('hold-only-key-cannot-grant','VV_GRANT_SIGNER',rebind(w=>w.state.set.gateKeys[0].roles=['hold-signer']));
  add('raw-hold','VV_PROJECTION',rebind(w=>w.bundle.hold.mode='RAW'));
  add('foreign-display-projection','VV_PROJECTION',rebind(w=>w.bundle.hold.displayProjection={...w.bundle.hold.displayProjection,hash:refHash({foreign:true})}));
  add('foreign-action-schema','VV_PROJECTION',rebind(w=>w.bundle.hold.actionSchema={...w.bundle.hold.actionSchema,version:2}));
  add('deferred-parameter-substitution','VV_PARAMS_MISMATCH',rebind(w=>{w.bundle.parameters.amount='26';w.bundle.grant.paramsHash=projection(w.bundle.parameters,'noa.ledger.transfer').paramsHash;}));
  add('grant-parameter-substitution','VV_PARAMS_MISMATCH',w=>w.bundle.grant=signed({...w.bundle.grant,paramsHash:refHash({foreign:true})},'gate-example'));
  add('expired-hold','VV_HOLD_EXPIRED',rebind(w=>w.bundle.hold.expiresAt=NOW));
  add('stale-approval','VV_APPROVAL_STALE',rebind(w=>w.bundle.decisions[0].decidedAt=timestamp(-900.001)));
  add('grant-life-exceeded','VV_GRANT_LIFE',rebind(w=>w.bundle.grant.expiresAt=timestamp(590.001)));
  add('grant-clock-skew','VV_NOT_YET_VALID',rebind(w=>w.bundle.grant.issuedAt=timestamp(60.001)));
  add('decision-clock-skew','VV_DECISION_FUTURE',rebind(w=>w.bundle.decisions[0].decidedAt=timestamp(60.001)));
  add('expired-grant','VV_EXPIRED',rebind(w=>w.bundle.grant.expiresAt=NOW));
  add('below-replay-floor','VV_BELOW_FLOOR',w=>w.state.floor=NOW);
  add('deny-in-bundle','VV_DENIED',rebind(w=>w.bundle.decisions.push({...w.bundle.decisions[0],approverKid:'approver-example-2',decision:'DENY'})));
  add('quorum-short','VV_QUORUM_NOT_MET',rebind(w=>w.state.policy.classes[0].quorum=2));
  add('duplicate-key-not-quorum','VV_QUORUM_NOT_MET',rebind(w=>{w.state.policy.classes[0].quorum=2;w.bundle.decisions.push(structuredClone(w.bundle.decisions[0]));}));
  add('required-approver-missing','VV_REQUIRED_APPROVER',rebind(w=>w.state.policy.classes[0].requiredApprovers=['approver-example-2']));
  add('duplicate-device','VV_DEVICE_DUPLICATE',rebind(w=>{w.state.policy.classes[0].quorum=2;w.state.set.approvers[1].deviceId=w.state.set.approvers[0].deviceId;w.bundle.decisions.push({...w.bundle.decisions[0],approverKid:'approver-example-2'});}));
  add('set-expired','VV_APPROVER_SET_EXPIRED',rebind(w=>w.state.set.expiresAt=NOW));
  add('policy-expired','VV_POLICY_EXPIRED',rebind(w=>w.state.policy.expiresAt=NOW));
  add('class-not-in-policy','VV_CLASS_NOT_ACCEPTED',rebind(w=>w.state.policy.classes=w.state.policy.classes.filter(c=>c.probe)));
  add('revoked-approver','VV_APPROVER_UNKNOWN',rebind(w=>w.state.set.approvers=w.state.set.approvers.slice(1)));
  const suspend=w=>w.state.suspended=[{kid:'approver-example-1',publicKeyHash:pin(keys['approver-example-1'].publicKey)}];
  add('suspended-approver','VV_APPROVER_SUSPENDED',suspend);
  add('gate-key-cannot-approve','VV_APPROVER_UNKNOWN',rebind(w=>w.bundle.decisions[0].approverKid='gate-example'));
  add('invalid-decision-signature','VV_DECISION_INVALID',w=>w.bundle.decisions[0].sig.value=Buffer.alloc(64).toString('base64'));
  add('hardware-cosignature-missing','VV_COSIG_REQUIRED',rebind(w=>{w.state.set.approvers[0].custody='hardware-attested';w.state.set.approvers[0].cosignPublicKey=hardwareFixture().publicKey;w.state.set.approvers[0].attestationDigest=refHash({test:'attestation'});}));
  add('software-stray-cosignature','VV_COSIG_REQUIRED',w=>w.bundle.cosignatures=[hardwareFixture().cosignature]);
  add('wrong-audience','VV_AUDIENCE_MISMATCH',rebind(w=>{
    w.bundle.parameters.ledger='foreign-vault';
    const p=projection(w.bundle.parameters,'noa.ledger.transfer');
    for(const r of [w.bundle.deferredReceipt,w.bundle.approvalReceipt]) r.action.paramsHash=p.paramsHash;
    w.bundle.grant.paramsHash=p.paramsHash;w.bundle.hold.displayCiphertextHash=refHash(p.display);
  }));
  add('class-amount-limit','VV_LIMIT',rebind(w=>w.state.policy.classes[0].limits.maxAmount='24'));
  add('stale-manifest-epoch','VV_HOLD_INVALID',rebind(w=>w.bundle.hold.keyManifestHash=refHash({epoch:0})));
  add('wrong-hold-signer','VV_HOLD_INVALID',w=>w.bundle.hold=signed(w.bundle.hold,'console-example'));
  add('receipt-chain-link','VV_RECEIPT_LINK',w=>w.bundle.approvalReceipt=receipt({...w.bundle.approvalReceipt,chain:{...w.bundle.approvalReceipt.chain,prevHash:refHash({foreign:true})}}));
  add('receipt-signature-invalid','VV_RECEIPT_LINK',w=>w.bundle.approvalReceipt.sig.value=Buffer.alloc(64).toString('base64'));
  add('receipt-approver-not-counted','VV_RECEIPT_LINK',rebind(w=>w.bundle.approvalReceipt.governance.approval.by='approver-example-2'));
  add('grant-hold-link','VV_GRANT_LINK',w=>w.bundle.grant=signed({...w.bundle.grant,holdId:'another-hold'},'gate-example'));
  add('bundle-trust-injection','VV_MALFORMED',w=>w.bundle.approverSet=w.state.set,{schemaValid:false});
  add('unsupported-artifact-version','VV_SPEC_UNSUPPORTED',w=>w.bundle.grant.spec='noa.execution-grant/9.0',{schemaValid:false});
  add('vault-frozen','VV_FROZEN',w=>w.state.frozen=true);
  add('set-not-active','VV_NOT_YET_VALID',rebind(w=>w.state.set.notBefore=timestamp(1)));
  add('request-untrusted-set','VV_ROOT_REQUIRED',w=>w.state.set=signed(w.state.set,'console-example'));
  add('request-untrusted-policy','VV_ROOT_REQUIRED',w=>w.state.policy=signed(w.state.policy,'console-example'));
  add('request-untrusted-expired-set','VV_ROOT_REQUIRED',w=>w.state.set=signed({...w.state.set,expiresAt:NOW},'console-example'));
  add('request-untrusted-expired-policy','VV_ROOT_REQUIRED',w=>w.state.policy=signed({...w.state.policy,expiresAt:NOW},'console-example'));
  add('probe-principal-stop','VV_PROBE_STOP',()=>{},{request:{principal:'probe'}});
  add('authority-changed-before-commit','VV_SET_CHANGED',()=>{},{request:{atCommit:{revision:2}}});
  add('expired-while-waiting-for-lock','VV_EXPIRED',()=>{},{request:{atCommit:{now:timestamp(300)}}});
  add('transient-rollback','VV_RETRYABLE',()=>{},{request:{effect:'transient'}});
  add('terminal-refusal-consumes','VV_EFFECT_REFUSED',()=>{},{request:{effect:'terminal'},expected:[{code:'VV_EFFECT_REFUSED',consumptions:1,effects:0}]});
  add('replay-after-restart','VV_ALREADY_CONSUMED',()=>{},{requests:w=>[{bundle:w.bundle},{bundle:w.bundle,restart:true}],expected:[{code:'VV_OK',consumptions:1,effects:1},{code:'VV_ALREADY_CONSUMED',consumptions:1,effects:1}]});
  add('refused-grant-replay-after-funding','VV_ALREADY_CONSUMED',()=>{},{requests:w=>[{bundle:w.bundle,effect:'terminal'},{bundle:w.bundle,restart:true}],expected:[{code:'VV_EFFECT_REFUSED',consumptions:1,effects:0},{code:'VV_ALREADY_CONSUMED',consumptions:1,effects:0}]});
  add('transient-retry-can-commit','VV_OK',()=>{},{requests:w=>[{bundle:w.bundle,effect:'transient'},{bundle:w.bundle}],expected:[{code:'VV_RETRYABLE',consumptions:0,effects:0},{code:'VV_OK',consumptions:1,effects:1}]});
  add('lost-acknowledgement-reconciles','VV_ALREADY_CONSUMED',()=>{},{requests:w=>[{bundle:w.bundle,effect:'lost-ack'},{bundle:w.bundle}],expected:[{code:'VV_INDETERMINATE',consumptions:1,effects:1},{code:'VV_ALREADY_CONSUMED',consumptions:1,effects:1}]});
  add('two-guards-share-consumption','VV_ALREADY_CONSUMED',()=>{},{requests:w=>[{bundle:w.bundle,guard:'guard-example-a'},{bundle:w.bundle,guard:'guard-example-b'}],expected:[{code:'VV_OK',consumptions:1,effects:1},{code:'VV_ALREADY_CONSUMED',consumptions:1,effects:1}]});
  add('fresh-grant-same-hold','VV_ALREADY_CONSUMED',()=>{},{requests:w=>[{bundle:w.bundle},{bundle:{...w.bundle,grant:signed({...w.bundle.grant,grantId:'standby-grant',nonce:'30'.repeat(32)},'gate-example')}}],expected:[{code:'VV_OK',consumptions:1,effects:1},{code:'VV_ALREADY_CONSUMED',consumptions:1,effects:1}]});
  for(const identity of ['grantId','nonce']) add(`replay-${identity}-only`,'VV_ALREADY_CONSUMED',()=>{},{requests:w=>{
    const next=structuredClone(w);
    next.bundle.hold.holdId='another-hold';next.bundle.hold.nonce='another-hold-nonce';
    next.bundle.grant.holdId=next.bundle.hold.holdId;
    if(identity==='grantId') next.bundle.grant.nonce='40'.repeat(32);
    else next.bundle.grant.grantId='another-grant';
    bind(next);
    return [{bundle:w.bundle},{bundle:next.bundle}];
  },expected:[{code:'VV_OK',consumptions:1,effects:1},{code:'VV_ALREADY_CONSUMED',consumptions:1,effects:1}]});
  const candidate=w=>signed({...w.state.set,version:2,previousSetHash:refHash(w.state.set)},'root-example');
  const policyCandidate=w=>({...structuredClone(w.state.policy),version:2,previousPolicyHash:refHash(w.state.policy)});
  const emergency={class:'noa.emergency.example',covers:['noa.ledger.transfer'],eligibleApprovers:['approver-example-1','approver-example-2'],quorum:2,maxGrantLifeSeconds:300,limits:{maxAmount:'50',unit:'XTS'}};
  add('accept-set-successor','VV_OK',()=>{},{operation:'install-set',candidate,expected:[{code:'VV_OK',consumptions:0,effects:0}]});
  add('accept-policy-successor','VV_OK',()=>{},{operation:'install-policy',candidate:w=>signed(policyCandidate(w),'root-example'),expected:[{code:'VV_OK',consumptions:0,effects:0}]});
  add('emergency-policy-refused','VV_POLICY_INVALID',()=>{},{operation:'install-policy',candidate:w=>signed({...policyCandidate(w),emergency},'root-example')});
  add('set-with-emergency-policy-refused','VV_POLICY_INVALID',rebind(w=>w.state.policy.emergency=emergency),{operation:'install-set',candidate});
  add('policy-life-exceeded','VV_SET_LIFE',()=>{},{operation:'install-policy',candidate:w=>signed({...policyCandidate(w),expiresAt:new Date(Date.parse(w.state.policy.issuedAt)+2592001*1000).toISOString()},'root-example')});
  for(const [id,lift,code] of [
    ['suspension-survives-set-install',[], 'VV_APPROVER_SUSPENDED'],
    ['suspension-wrong-hash',[{kid:'approver-example-1',publicKeyHash:pin(keys['approver-example-2'].publicKey)}], 'VV_APPROVER_SUSPENDED'],
    ['suspension-wrong-kid',[{kid:'approver-example-2',publicKeyHash:pin(keys['approver-example-1'].publicKey)}], 'VV_APPROVER_SUSPENDED'],
    ['accept-suspension-lift',[{kid:'approver-example-1',publicKeyHash:pin(keys['approver-example-1'].publicKey)}], 'VV_OK'],
  ]) add(id,code,suspend,{operation:'install-set',candidate:w=>signed({...candidate(w),liftSuspensions:lift},'root-example'),verifyAfterInstall:true,request:{restart:true},expected:[{code:'VV_OK',consumptions:0,effects:0},{code,consumptions:code==='VV_OK'?1:0,effects:code==='VV_OK'?1:0}]});
  add('suspension-kid-only-lift','VV_MALFORMED',suspend,{operation:'install-set',candidate:w=>signed({...candidate(w),liftSuspensions:[{kid:'approver-example-1'}]},'root-example'),candidateSchemaValid:false,verifyAfterInstall:true,expected:[{code:'VV_MALFORMED',consumptions:0,effects:0},{code:'VV_APPROVER_SUSPENDED',consumptions:0,effects:0}]});
  add('set-quorum-device-short','VV_POLICY_INVALID',rebind(w=>w.state.policy.classes[0].quorum=2),{operation:'install-set',candidate:w=>{const c=candidate(w);c.approvers[1].deviceId=c.approvers[0].deviceId;return signed(c,'root-example');}});
  for(const role of ['kid','publicKey']) add(`root-${role}-in-set`,'VV_POLICY_INVALID',()=>{},{operation:'install-set',candidate:w=>{const c=candidate(w);c.approvers[0].kid='another-approver';c.approvers[0][role]=keys['root-example'][role];return signed(c,'root-example');}});
  for(const kid of ['gate-example','root-example']) add(`probe-kid-alias-${kid}`,'VV_POLICY_INVALID',()=>{},{operation:'install-set',candidate:w=>{const c=candidate(w);c.probe.kid=kid;return signed(c,'root-example');}});
  for(const [index,kind] of [[0,'ledger'],[1,'probe']]) for(const field of ['actionSchema','displayProjection']) add(`policy-${kind}-${field}-unsupported`,'VV_POLICY_INVALID',()=>{},{operation:'install-policy',candidate:w=>{const p=policyCandidate(w);p.classes[index][field]={...p.classes[index][field],hash:refHash({unsupported:true})};return signed(p,'root-example');}});
  add('set-life-exceeded','VV_SET_LIFE',()=>{},{operation:'install-set',candidate:w=>signed({...candidate(w),expiresAt:timestamp(2592001)},'root-example')});
  add('set-rollback','VV_SET_ROLLBACK',()=>{},{operation:'install-set',candidate:w=>w.state.set});
  add('set-fork','VV_SET_ROLLBACK',()=>{},{operation:'install-set',candidate:w=>signed({...candidate(w),previousSetHash:refHash({fork:true})},'root-example')});
  add('kid-reused-with-new-key','VV_KEY_REUSE',()=>{},{operation:'install-set',candidate:w=>{const c=candidate(w);c.approvers[0].publicKey=keys['unknown-example'].publicKey;return signed(c,'root-example');}});
  add('delegated-set-signer','VV_ROOT_REQUIRED',()=>{},{operation:'install-set',candidate:w=>signed(candidate(w),'console-example')});
  add('policy-required-key-absent','VV_POLICY_INVALID',()=>{},{operation:'install-policy',candidate:w=>{const p=structuredClone(w.state.policy);p.version=2;p.previousPolicyHash=refHash(w.state.policy);p.classes[0].requiredApprovers=['unknown-example'];return signed(p,'root-example');}});
  add('delegated-policy-signer','VV_ROOT_REQUIRED',()=>{},{operation:'install-policy',candidate:w=>signed({...w.state.policy,version:2,previousPolicyHash:refHash(w.state.policy)},'console-example')});
  const base=world();
  const result=signed({spec:'noa.vault-result/0.1',tenant:'tenant-example',vaultId:'vault-example',vaultInstanceId:'instance-example',grantHash:refHash(base.bundle.grant),effectId:'effect-example',checkedAt:NOW,setVersion:1,policyVersion:1,outcome:'EXECUTED',code:null,consumed:true,originalOutcome:null,effectCode:null},'guard-example');
  const artifacts=[base.state.set,base.state.policy,join('approver-example-1'),base.bundle,result,hardwareFixture().cosignature];
  const artifactVectors=artifacts.flatMap(artifact=>[
    {id:`${artifact.spec}-valid`,artifact,valid:true},
    {id:`${artifact.spec}-unknown-property`,artifact:{...artifact,unexpected:true},valid:false},
    {id:`${artifact.spec}-missing-member`,artifact:Object.fromEntries(Object.entries(artifact).filter(([k])=>k!==(artifact.spec==='noa.vault-authority-bundle/0.1'?'grant':'sig'))),valid:false},
  ]);
  return {spec:'noa.vault-conformance/0.1',now:NOW,artifactVectors,probe:{descriptor:probeDescriptor,implementation:probeImplementation,...probeIdentities},vectors};
}
export function hardwareFixture() {
  return JSON.parse(readFileSync(new URL('../conformance/vault-hardware-fixture.json',import.meta.url),'utf8'));
}
export function corpusFiles(corpus) {
  const files=new Map();
  function add(vector) {
    const name=vector.id.replace(/[^A-Za-z0-9._-]/g,'-')+'.json';
    if(name==='INDEX.json' || files.has(name)) throw new Error(`Duplicate corpus file: ${name}`);
    files.set(name,JSON.stringify(vector,null,2)+'\n');
    return name;
  }
  const index={spec:corpus.spec,now:corpus.now,probe:corpus.probe,
    vectors:corpus.vectors.map(add),artifactVectors:corpus.artifactVectors.map(add)};
  files.set('INDEX.json',JSON.stringify(index,null,2)+'\n');
  return files;
}
if (process.argv[1] && import.meta.url===pathToFileURL(process.argv[1]).href && process.argv[2]==='--write') {
  const files=corpusFiles(buildCorpus());
  mkdirSync(corpusDir,{recursive:true});
  // Only this corpus's generated JSON files are owned by this writer.
  for(const entry of readdirSync(corpusDir,{withFileTypes:true})) {
    if(entry.isFile() && entry.name.endsWith('.json') && !files.has(entry.name)) unlinkSync(joinPath(corpusDir,entry.name));
  }
  for(const [name,text] of files) writeFileSync(joinPath(corpusDir,name),text);
}
