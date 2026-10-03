import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { refHash } from '../dist/src/refhash.js';
import { ARTIFACTS } from '../dist/src/domains.js';
import { evalSchema } from '../dist/src/schema-eval.js';
import { schemaCheck, schemaFor, corpusPath } from './vault-schema-fixtures.mjs';
import { buildCorpus, domains, world, hardwareFixture, keys, signed, join, pin, probeIdentities, bind } from './vault-vector-fixtures.mjs';
import { runVector, authentic, validCosignature } from './vault-spec-model.mjs';
import { projectLedgerTransfer } from '../../../dist/src/ledger-transfer.js';

const corpus=JSON.parse(readFileSync(corpusPath,'utf8'));
const spec=readFileSync(new URL('../vault-verification.md',import.meta.url),'utf8');

test('vault corpus is deterministic and all stable codes have an executable case',()=>{
  assert.equal(JSON.stringify(buildCorpus(),null,2)+'\n',readFileSync(corpusPath,'utf8'));
  assert.equal(new Set(corpus.vectors.map(v=>v.id)).size,corpus.vectors.length);
  const codes=new Set(corpus.vectors.flatMap(v=>v.expected.map(x=>x.code)));
  for(const code of new Set(spec.match(/VV_[A-Z_]+/g))) assert.ok(codes.has(code),`no vector for ${code}`);
  for(const code of codes) if(code!=='VV_OK') assert.ok(spec.includes('`'+code+'`'),`undocumented ${code}`);
});
for(const v of corpus.vectors) test(`vault verdict: ${v.id}`,()=>{
  for(const doc of [v.state.set,v.state.policy]) {
    const checked=schemaCheck(doc);assert.ok(checked.ok,checked.errors.join('; '));
  }
  if(v.candidate) {
    const checked=schemaCheck(v.candidate);
    assert.equal(checked.ok,v.candidateSchemaValid,checked.errors.join('; '));
  }
  for(const request of v.requests) {
    const checked=schemaCheck(request.bundle);
    assert.equal(checked.ok,v.schemaValid,`${v.id}: ${checked.errors.join('; ')}`);
  }
  const actual=runVector(v);
  // Check the modeled consequence before its diagnostic label.
  if(v.operation.startsWith('install-')) assert.equal(actual[0].installed,v.expected[0].code==='VV_OK','installation changed authority');
  assert.deepEqual(actual.map(({consumptions,effects})=>({consumptions,effects})),v.expected.map(({consumptions,effects})=>({consumptions,effects})));
  assert.deepEqual(actual.map(x=>x.code),v.expected.map(x=>x.code));
  for(const a of actual) if(a.code==='VV_ROOT_REQUIRED') assert.equal(a.result,undefined);
  for(const a of actual) if(a.result) {
    const checked=schemaCheck(a.result);assert.ok(checked.ok,checked.errors.join('; '));
    assert.ok(authentic(a.result,v.state.set.guardKey.publicKey));
  }
  if(actual.at(-1).code==='VV_ALREADY_CONSUMED') {
    assert.equal(actual.at(-1).result.grantHash,refHash(v.requests[0].bundle.grant));
    assert.equal(actual.at(-1).result.originalOutcome,actual[0].code==='VV_EFFECT_REFUSED'?'REFUSED':'EXECUTED');
  }
});
for(const v of corpus.artifactVectors) test(`vault schema: ${v.id}`,()=>{
  const checked=schemaCheck(v.artifact);
  assert.equal(checked.ok,v.valid,checked.errors.join('; '));
});
test('all six new schemas close every object and resolve every reference',()=>{
  const names=['noa-vault-approver-set-0.1','noa-vault-class-policy-0.1','noa-vault-approver-join-0.1','noa-vault-authority-bundle-0.1','noa-vault-result-0.1','noa-device-cosignature-0.1'];
  function visit(node) {
    if(!node || typeof node!=='object') return;
    if(node.type==='object' || (Array.isArray(node.type)&&node.type.includes('object'))) assert.equal(node.additionalProperties,false);
    for(const child of Object.values(node)) visit(child);
  }
  for(const name of names) visit(schemaFor(name));
});
test('new signature domains are distinct from each other and the frozen registry',()=>{
  const all=[...Object.values(ARTIFACTS).map(a=>a.domain).filter(Boolean),'NOA-Receipt-v0.1-sig','NOA-Checkpoint-v0.1-sig',...Object.entries(domains).filter(([s])=>!ARTIFACTS[s]).map(([,d])=>d)];
  assert.equal(new Set(all).size,all.length);
});
test('join possession, root statements and guard result signatures bind all members',()=>{
  for(const v of corpus.artifactVectors.filter(v=>v.valid && v.artifact.sig?.alg==='ed25519')) {
    const doc=v.artifact;
    assert.ok(authentic(doc,keys[doc.sig.kid].publicKey));
    assert.equal(authentic({...doc,tenant:'other-tenant'},keys[doc.sig.kid].publicKey),false);
  }
  const j=join('approver-example-1');assert.equal(j.kid,j.sig.kid);assert.equal(refHash(j),world().state.set.approvers[0].joinHash);
});
test('fixed ES256 bytes verify only for the bound decision and pinned co-sign key',()=>{
  const f=hardwareFixture(),member={kid:'approver-example-1',cosignPublicKey:f.publicKey};
  assert.ok(schemaCheck(f.cosignature).ok);
  assert.equal(refHash(f.subject),refHash(world().bundle.decisions[0]));
  assert.ok(validCosignature(f.cosignature,f.subject,member));
  assert.equal(validCosignature(f.cosignature,{...f.subject,decision:'DENY'},member),false);
  assert.equal(validCosignature({...f.cosignature,subjectSpec:'noa.vault-approver-join/0.1'},f.subject,member),false);
  assert.equal(validCosignature(f.cosignature,f.subject,{...member,cosignPublicKey:keys['approver-example-1'].publicKey}),false);
  const w=world();w.state.set.approvers[0]={...w.state.set.approvers[0],custody:'hardware-attested',cosignPublicKey:f.publicKey,deviceId:pin(f.publicKey),attestationDigest:refHash([])};
  w.state.set=signed(w.state.set,'root-example');w.bundle.cosignatures=[f.cosignature];
  const actual=runVector({operation:'verify',state:w.state,requests:[{bundle:w.bundle}]});
  assert.equal(actual[0].effects,1);assert.equal(actual[0].code,'VV_OK');
});
test('unknown nested members and wrong algorithms are rejected in every new artifact',()=>{
  for(const v of corpus.artifactVectors.filter(v=>v.valid)) {
    const bad=structuredClone(v.artifact);
    if(bad.sig) bad.sig.unexpected=true;
    else bad.grant.sig.unexpected=true;
    assert.equal(schemaCheck(bad).ok,false,v.id);
    if(v.artifact.sig) {
      const alg=structuredClone(v.artifact);alg.sig.alg='none';
      assert.equal(schemaCheck(alg).ok,false,v.id);
    }
  }
});
test('display rebuild detects substitution and preserves long distinguishable identifiers',()=>{
  const params=world().bundle.parameters;
  const a={...params,toAccount:'a'.repeat(48)+'-one'},b={...params,toAccount:'a'.repeat(48)+'-two'};
  const pa=projectLedgerTransfer(JSON.stringify(a)),pb=projectLedgerTransfer(JSON.stringify(b));
  assert.ok(pa.ok&&pb.ok);assert.notEqual(pa.paramsHash,pb.paramsHash);assert.notEqual(pa.display.To,pb.display.To);
  assert.equal(pa.display.To,a.toAccount);assert.equal(pb.display.To,b.toAccount);
  function rebuild(rows) {
    assert.deepEqual(Object.keys(rows).sort(),['Action','Amount','From','Ledger','Salt','To']);
    assert.equal(rows.Action,'noa.ledger.transfer');
    const parts=rows.Amount.split(' ');assert.equal(parts.length,2);
    return projectLedgerTransfer(JSON.stringify({amount:parts[0],unit:parts[1],fromAccount:rows.From,ledger:rows.Ledger,salt:rows.Salt,toAccount:rows.To}));
  }
  assert.equal(rebuild(pa.display).paramsHash,pa.paramsHash);
  assert.notEqual(rebuild(pb.display).paramsHash,pa.paramsHash);
});
test('probe projection is distinct, invertible and strictly shaped',()=>{
  assert.deepEqual(corpus.probe.actionSchema,probeIdentities.actionSchema);
  assert.notEqual(corpus.probe.actionSchema.hash,corpus.probe.displayProjection.hash);
  const v=corpus.vectors.find(v=>v.id==='accept-diagnostic-record');
  const params=v.requests[0].bundle.parameters;
  const rows={Action:'noa.vault.probe',Vault:params.vault,Run:params.run};
  assert.equal(refHash({vault:rows.Vault,run:rows.Run}),v.requests[0].bundle.grant.paramsHash);
  assert.equal(evalSchema(schemaFor('noa-vault-authority-bundle-0.1').$defs.probeParameters,{...params,amount:'1'}).ok,false);
});
test('strict parser rejects duplicate keys before the model can consume',()=>{
  const w=world();const text=JSON.stringify(w.bundle).replace('"spec":"noa.vault-authority-bundle/0.1"','"spec":"noa.vault-authority-bundle/0.1","spec":"noa.vault-authority-bundle/0.1"');
  const a=runVector({operation:'verify',state:w.state,requests:[{bundleText:text}]})[0];
  assert.equal(a.effects,0);assert.equal(a.consumptions,0);assert.equal(a.code,'VV_MALFORMED');
});
test('malformed carriers fail closed without throwing or consuming',()=>{
  for(const bundle of [null,[],{},42,{...world().bundle,decisions:42}]) {
    const a=runVector({operation:'verify',state:world().state,requests:[{bundle}]})[0];
    assert.equal(a.code,'VV_MALFORMED');assert.equal(a.consumptions,0);assert.equal(a.effects,0);
  }
});
test('result schema binds replay and unknown outcomes to coherent effect fields',()=>{
  for(const id of ['replay-after-restart','refused-grant-replay-after-funding','lost-acknowledgement-reconciles']) {
    const results=runVector(corpus.vectors.find(v=>v.id===id));
    for(const {result} of results) {
      assert.ok(schemaCheck(result).ok);
      assert.equal(schemaCheck({...result,effectId:'invented-effect',effectCode:'INVENTED'}).ok,false);
      if(result.outcome==='ALREADY_CONSUMED') assert.equal(schemaCheck({...result,originalOutcome:result.originalOutcome==='EXECUTED'?'REFUSED':'EXECUTED'}).ok,false);
    }
  }
});
test('empty public keys are structurally invalid',()=>{
  const j=join('approver-example-1');
  for(const key of ['publicKey','hpkePublicKey','cosignPublicKey']) assert.equal(schemaCheck({...j,[key]:''}).ok,false);
  const set=world().state.set;set.approvers[0].publicKey='';assert.equal(schemaCheck(set).ok,false);
});
test('clock admission reuses real-instant validation and preserves equivalent offsets',()=>{
  const offset=world();offset.bundle.decisions[0].decidedAt='2030-01-02T12:59:30.000+01:00';bind(offset);
  assert.equal(runVector({operation:'verify',state:offset.state,requests:[{bundle:offset.bundle}]})[0].code,'VV_OK');
  for(const time of ['2030-02-30T12:00:00Z','2030-01-02T11:59:30.0001Z','2030-01-02T11:59:60Z']) {
    const w=world();w.bundle.decisions[0].decidedAt=time;bind(w);
    assert.equal(runVector({operation:'verify',state:w.state,requests:[{bundle:w.bundle}]})[0].code,'VV_MALFORMED');
  }
});
