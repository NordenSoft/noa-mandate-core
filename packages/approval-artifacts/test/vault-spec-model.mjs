// Executable specification for synthetic conformance tests ONLY. No production exports or I/O.
// Transaction events below are model inputs; they do not prove a real database implementation.
import { createPublicKey, verify as verifyCrypto } from 'node:crypto';
import { canonicalize } from '../dist/src/jcs.js';
import { parseDocument } from '../dist/src/parse-document.js';
import { signingMessage, verifyEd25519, isStrictEd25519PublicKey } from '../dist/src/crypto.js';
import { refHash, signHashInput } from '../dist/src/refhash.js';
import { verifyChain } from '../../../dist/src/verify.js';
import { isRfc3339Instant } from '../../../dist/src/scan.js';
import { schemaCheck } from './vault-schema-fixtures.mjs';
import { domains, projection, pin, signed, probeIdentities } from './vault-vector-fixtures.mjs';
import { LEDGER_TRANSFER_SCHEMA_ID, LEDGER_TRANSFER_DISPLAY_ID } from '../../../dist/src/ledger-transfer.js';

const ms = value => Date.parse(value);
const same = (a,b) => canonicalize(a)===canonicalize(b);
export function authentic(doc, publicKey) {
  return doc.sig?.alg==='ed25519' && verifyEd25519(publicKey,signingMessage(domains[doc.spec],signHashInput(doc)),doc.sig.value);
}
export function validCosignature(c, subject, member) {
  if(c.subjectSpec!==subject.spec || c.subjectHash!==refHash(subject) || c.approverKid!==member.kid || c.sig.kid!==member.kid || c.sig.alg!=='ES256') return false;
  try {
    const der=Buffer.from(member.cosignPublicKey,'base64');
    const key=createPublicKey({key:der,format:'der',type:'spki'});
    if(der.toString('base64')!==member.cosignPublicKey || !key.export({format:'der',type:'spki'}).equals(der) || key.asymmetricKeyType!=='ec' || key.asymmetricKeyDetails.namedCurve!=='prime256v1') return false;
    const signature=Buffer.from(c.sig.value,'base64');
    if(signature.length!==64 || signature.toString('base64')!==c.sig.value) return false;
    return verifyCrypto('sha256',signingMessage(domains[c.spec],signHashInput(c)),{key,dsaEncoding:'ieee-p1363'},signature);
  } catch { return false; }
}
function trusted(doc,state) {
  return doc.sig.kid===state.pins.rootKid && authentic(doc,state.pins.rootPublicKey) && doc.tenant===state.pins.tenant && doc.vaultId===state.pins.vaultId;
}
function policyValid(policy,set) {
  if(policy.emergency!==null) return false; // No executable emergency projection is defined here.
  const names=new Set();
  for(const c of policy.classes) {
    if(names.has(c.canonical)) return false; names.add(c.canonical);
    if(c.requiredApprovers.some(k=>!set.approvers.some(a=>a.kid===k))) return false;
    if(new Set(c.requiredApprovers).size!==c.requiredApprovers.length || c.quorum>new Set(set.approvers.map(a=>a.publicKey)).size) return false;
    if(c.quorum>new Set(set.approvers.map(a=>a.deviceId)).size) return false;
    if(c.canonical==='noa.ledger.transfer') {
      if(c.probe || c.audienceMember!=='ledger' || !c.limits.maxAmount || c.limits.unit!=='XTS') return false;
      if(!same(c.actionSchema,LEDGER_TRANSFER_SCHEMA_ID) || !same(c.displayProjection,LEDGER_TRANSFER_DISPLAY_ID)) return false;
    } else if(c.canonical==='noa.vault.probe') {
      if(!c.probe || c.audienceMember!=='vault' || Object.keys(c.limits).length) return false;
      if(!same(c.actionSchema,probeIdentities.actionSchema) || !same(c.displayProjection,probeIdentities.displayProjection)) return false;
    } else return false;
  }
  return true;
}
export function install(candidate,state,kind) {
  if(!schemaCheck(candidate).ok) return 'VV_MALFORMED';
  if(!trusted(candidate,state)) return 'VV_ROOT_REQUIRED';
  const old=kind==='set'?state.set:state.policy;
  const cap=kind==='set'?state.pins.maxSetLifeSeconds:state.pins.maxPolicyLifeSeconds;
  if(ms(candidate.expiresAt)-ms(candidate.issuedAt)>cap*1000) return 'VV_SET_LIFE';
  const previous=kind==='set'?'previousSetHash':'previousPolicyHash';
  if(candidate.version!==old.version+1 || candidate[previous]!==refHash(old)) return 'VV_SET_ROLLBACK';
  if(!(ms(candidate.issuedAt)<=ms(candidate.notBefore) && ms(candidate.notBefore)<ms(candidate.expiresAt))) return 'VV_POLICY_INVALID';
  if(ms(candidate.issuedAt)>ms(state.now)+state.set.clockSkewSeconds*1000 || ms(candidate.notBefore)>ms(state.now)) return 'VV_NOT_YET_VALID';
  if(ms(candidate.expiresAt)<=ms(state.now)) return kind==='set'?'VV_APPROVER_SET_EXPIRED':'VV_POLICY_EXPIRED';
  if(kind==='set') {
    const entries=[...candidate.gateKeys,candidate.guardKey,...candidate.approvers];
    const historical=new Map([...state.set.gateKeys,state.set.guardKey,...state.set.approvers,...(state.keyHistory??[])].map(a=>[a.kid,a.publicKey]));
    if(entries.some(a=>historical.has(a.kid) && historical.get(a.kid)!==a.publicKey)) return 'VV_KEY_REUSE';
    const kids=[...entries.map(a=>a.kid),candidate.probe.kid];
    if(new Set(kids).size!==kids.length || candidate.probe.kid===state.pins.rootKid || new Set(entries.map(a=>a.publicKey)).size!==entries.length || entries.some(a=>!isStrictEd25519PublicKey(a.publicKey) || a.kid===state.pins.rootKid || a.publicKey===state.pins.rootPublicKey) || candidate.clockSkewSeconds>state.pins.maxClockSkewSeconds) return 'VV_POLICY_INVALID';
    if(!policyValid(state.policy,candidate)) return 'VV_POLICY_INVALID';
    state.suspended=state.suspended.filter(s=>!candidate.liftSuspensions.some(l=>l.kid===s.kid && l.publicKeyHash===s.publicKeyHash));
    state.keyHistory=[...historical].map(([kid,publicKey])=>({kid,publicKey}));
  } else if(!policyValid(candidate,state.set)) return 'VV_POLICY_INVALID';
  state[kind==='set'?'set':'policy']=structuredClone(candidate);
  state.revision++;
  return 'VV_OK';
}
function timeCode(b,c,state,now) {
  const t=ms(now), skew=state.set.clockSkewSeconds*1000;
  if(ms(b.grant.issuedAt)>t+skew) return 'VV_NOT_YET_VALID';
  if(t>=ms(b.grant.expiresAt) || ms(b.grant.expiresAt)<=ms(b.grant.issuedAt)) return 'VV_EXPIRED';
  if(t>=ms(b.hold.expiresAt)) return 'VV_HOLD_EXPIRED';
  if(b.decisions.some(d=>d.decision==='APPROVE' && ms(d.decidedAt)>t+skew)) return 'VV_DECISION_FUTURE';
  if(b.decisions.some(d=>d.decision==='APPROVE' && t-ms(d.decidedAt)>c.maxApprovalAgeSeconds*1000)) return 'VV_APPROVAL_STALE';
  if(ms(b.grant.expiresAt)-ms(b.grant.issuedAt)>c.maxGrantLifeSeconds*1000) return 'VV_GRANT_LIFE';
  if(ms(b.grant.issuedAt)<ms(state.floor)) return 'VV_BELOW_FLOOR';
  return null;
}
function datesValid(b) {
  const times=[b.hold.expiresAt,b.grant.issuedAt,b.grant.expiresAt,b.deferredReceipt.ts,b.approvalReceipt.ts,b.approvalReceipt.governance.approval?.at,...b.decisions.map(d=>d.decidedAt)].filter(x=>x!==undefined);
  return times.every(t=>typeof t==='string' && isRfc3339Instant(t) && !/\.\d{4}/.test(t) && Number.isFinite(ms(t)));
}
function verifyRequest(b,state,request) {
  if(!b || typeof b!=='object' || Array.isArray(b) || !Array.isArray(b.decisions) || !Array.isArray(b.cosignatures)) return 'VV_MALFORMED';
  const list=[b,b.hold,b.deferredReceipt,b.approvalReceipt,b.grant,...(b.decisions??[]),...(b.cosignatures??[])];
  if(list.some(a=>!a || typeof a.spec!=='string')) return 'VV_MALFORMED';
  for(const a of list) {
    const [family,version]=a.spec.split('/');
    if(version!=='0.1' || state.policy.minArtifactVersions[family]!==version) return 'VV_SPEC_UNSUPPORTED';
  }
  if(!schemaCheck(b).ok || !datesValid(b)) return 'VV_MALFORMED';
  if(!trusted(state.set,state) || !trusted(state.policy,state)) return 'VV_ROOT_REQUIRED';
  if(ms(state.now)>=ms(state.set.expiresAt)) return 'VV_APPROVER_SET_EXPIRED';
  if(ms(state.now)>=ms(state.policy.expiresAt)) return 'VV_POLICY_EXPIRED';
  if(ms(state.now)<ms(state.set.notBefore) || ms(state.now)<ms(state.policy.notBefore)) return 'VV_NOT_YET_VALID';
  if(state.frozen) return 'VV_FROZEN';
  const holdKey=state.set.gateKeys.find(k=>k.kid===b.hold.sig.kid && k.roles.includes('hold-signer'));
  if(!holdKey || b.hold.gateKid!==holdKey.kid || !authentic(b.hold,holdKey.publicKey) || b.hold.tenant!==state.pins.tenant || b.hold.keyManifestHash!==state.set.keyManifestHash) return 'VV_HOLD_INVALID';
  const c=state.policy.classes.find(c=>c.canonical===b.deferredReceipt.action.canonical);
  if(!c) return 'VV_CLASS_NOT_ACCEPTED';
  const p=projection(b.parameters,c.canonical);
  if(b.hold.mode!=='ENFORCED' || !same(b.hold.actionSchema,c.actionSchema) || !same(b.hold.displayProjection,c.displayProjection) || (p.ok && (!same(p.actionSchema,c.actionSchema) || !same(p.displayProjection,c.displayProjection)))) return 'VV_PROJECTION';
  if(!p.ok) return 'VV_PARAMS_MISMATCH';
  if(b.parameters[c.audienceMember]!==state.pins.vaultId) return 'VV_AUDIENCE_MISMATCH';
  if(p.paramsHash!==b.deferredReceipt.action.paramsHash) return 'VV_PARAMS_MISMATCH';
  if(c.limits.maxAmount && (BigInt(b.parameters.amount)>BigInt(c.limits.maxAmount) || b.parameters.unit!==c.limits.unit)) return 'VV_LIMIT';
  const receipts=[b.deferredReceipt,b.approvalReceipt];
  const keyring=Object.fromEntries(state.set.gateKeys.filter(k=>k.roles.includes('hold-signer')).map(k=>[k.kid,k.publicKey]));
  const verified=verifyChain(JSON.stringify(receipts),{keyring:JSON.stringify(keyring)});
  if(verified.status!=='VALID' || receipts.some(r=>r.scope.tenant!==state.pins.tenant) || b.hold.deferredReceiptId!==receipts[0].id || b.hold.deferredReceiptHash!==receipts[0].chain.hash || receipts[0].governance.verdict!=='DEFERRED' || receipts[1].governance.verdict!=='ALLOWED' || !receipts[1].governance.approval || !same(receipts[0].action,receipts[1].action)) return 'VV_RECEIPT_LINK';
  const votes=new Map(); const usedCosigs=new Set();
  for(const d of b.decisions) {
    const a=state.set.approvers.find(a=>a.kid===d.approverKid);
    if(!a) return 'VV_APPROVER_UNKNOWN';
    if(state.suspended.some(s=>s.kid===a.kid && s.publicKeyHash===pin(a.publicKey))) return 'VV_APPROVER_SUSPENDED';
    if(d.sig.kid!==a.kid || !authentic(d,a.publicKey) || d.holdEnvelopeHash!==refHash(b.hold)) return 'VV_DECISION_INVALID';
    if(d.decision==='DENY') return 'VV_DENIED';
    if(a.custody==='hardware-attested') {
      const found=b.cosignatures.filter(x=>x.subjectHash===refHash(d) && x.approverKid===a.kid);
      if(found.length!==1 || !validCosignature(found[0],d,a)) return 'VV_COSIG_REQUIRED';
      usedCosigs.add(found[0]);
    }
    votes.set(a.publicKey,a);
  }
  if(usedCosigs.size!==b.cosignatures.length) return 'VV_COSIG_REQUIRED';
  const voters=[...votes.values()];
  if(new Set(voters.map(a=>a.deviceId)).size!==voters.length) return 'VV_DEVICE_DUPLICATE';
  if(votes.size<c.quorum) return 'VV_QUORUM_NOT_MET';
  if(c.requiredApprovers.some(k=>!voters.some(a=>a.kid===k))) return 'VV_REQUIRED_APPROVER';
  if(!voters.some(a=>a.kid===b.approvalReceipt.governance.approval.by)) return 'VV_RECEIPT_LINK';
  const grantKey=state.set.gateKeys.find(k=>k.kid===b.grant.sig.kid && k.roles.includes('execution-signer'));
  if(!grantKey || !authentic(b.grant,grantKey.publicKey)) return 'VV_GRANT_SIGNER';
  if(b.grant.holdId!==b.hold.holdId || b.grant.holdEnvelopeHash!==refHash(b.hold) || b.grant.approvalReceiptHash!==b.approvalReceipt.chain.hash || b.grant.maxUses!==1) return 'VV_GRANT_LINK';
  if(b.grant.paramsHash!==p.paramsHash) return 'VV_PARAMS_MISMATCH';
  const time=timeCode(b,c,state,state.now); if(time) return time;
  if(request.principal==='probe') return 'VV_PROBE_STOP';
  if(request.atCommit?.revision!==undefined && request.atCommit.revision!==state.revision) return 'VV_SET_CHANGED';
  return timeCode(b,c,state,request.atCommit?.now??state.now) ?? 'VV_OK';
}
function result(state,b,code,stored=null) {
  const isReplay=code==='VV_ALREADY_CONSUMED';
  const outcome=code==='VV_OK'?'EXECUTED':isReplay?'ALREADY_CONSUMED':code==='VV_INDETERMINATE'?'INDETERMINATE':'REFUSED';
  return signed({spec:'noa.vault-result/0.1',tenant:state.pins.tenant,vaultId:state.pins.vaultId,vaultInstanceId:'instance-example',grantHash:stored?.grantHash??(b?.grant?refHash(b.grant):null),effectId:stored?.effectId??null,checkedAt:state.now,setVersion:state.set.version,policyVersion:state.policy.version,outcome,code:code==='VV_OK'?null:code,consumed:code==='VV_INDETERMINATE'?null:code==='VV_OK'||isReplay||code==='VV_EFFECT_REFUSED',originalOutcome:isReplay?stored.outcome:null,effectCode:stored?.effectCode??null},'guard-example');
}
export function runVector(vector) {
  let state=structuredClone(vector.state);
  let effects=state.consumptions.filter(c=>c.outcome==='EXECUTED').length;
  const observations=[];
  if(vector.operation.startsWith('install-')) {
    const kind=vector.operation.slice(8), revision=state.revision;
    const code=install(vector.candidate,state,kind);
    observations.push({code,consumptions:state.consumptions.length,effects,installed:state.revision!==revision});
    if(!vector.verifyAfterInstall) return observations;
  }
  return observations.concat(vector.requests.map(request=>{
    if(request.restart) state=JSON.parse(JSON.stringify(state)); // Durable snapshot survives a model restart.
    const parsed=parseDocument(request.bundleText??JSON.stringify(request.bundle),'bundle');
    const b=parsed.ok?parsed.value:null;
    let code=parsed.ok?verifyRequest(b,state,request):'VV_MALFORMED';
    let stored=null;
    if(code==='VV_OK') {
      stored=state.consumptions.find(c=>c.grantId===b.grant.grantId || c.nonce===b.grant.nonce || c.holdId===b.grant.holdId);
      if(stored) code='VV_ALREADY_CONSUMED';
      else if(request.effect==='transient') code='VV_RETRYABLE';
      else {
        const terminal=request.effect==='terminal';
        stored={grantId:b.grant.grantId,nonce:b.grant.nonce,holdId:b.grant.holdId,grantHash:refHash(b.grant),outcome:terminal?'REFUSED':'EXECUTED',effectId:terminal?null:`effect-example-${effects+1}`,effectCode:terminal?'INSUFFICIENT_BALANCE':null};
        state.consumptions.push(stored); if(!terminal) effects++;
        code=terminal?'VV_EFFECT_REFUSED':request.effect==='lost-ack'?'VV_INDETERMINATE':'VV_OK';
      }
    }
    // Unknown acknowledgement must not disclose a made-up definitive effect observation.
    const observation=code==='VV_INDETERMINATE'?null:stored;
    return {code,consumptions:state.consumptions.length,effects,...(code==='VV_ROOT_REQUIRED'?{}:{result:result(state,b,code,observation)})};
  }));
}
