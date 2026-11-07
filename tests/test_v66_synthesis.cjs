'use strict';
const assert=require('node:assert/strict');
require('../dam_policy_compare.js');
require('../workflow_pattern.js');
require('../comparison_readiness.js');
const X=require('../evidence_synthesis.js');
const PRIVATE='PRIVATE_SECRET_ABCDEFGHIJKLMNOPQRSTUVWXYZ_012345';
const URL='https://dam.example.test/path/'+PRIVATE+'?token='+PRIVATE;
const context={accessRole:'same',workflow:'same',assetScope:'same',hostPermissions:'same',devtoolsTiming:'both-early'};
function sample(id,{n=200,denied=false,pattern='balanced',dropped=0,ended=true}={}){
 const kinds=pattern==='balanced'?['image','fetch','image','script','image','fetch','stylesheet','image','main_frame','fetch']:['fetch'];
 const requests=Array.from({length:n},(_,i)=>({type:kinds[i%kinds.length],method:'GET',mime:kinds[i%kinds.length]==='image'?'image/jpeg':'application/json',
   status:denied&&i%10===0?403:200,url:URL,traceparent:PRIVATE,
   signedQuery:i%10===2,attachmentDisposition:i%40===3,
   at:new Date(Date.UTC(2026,9,24,10,0,i)).toISOString()}));
 return [{origin:'https://dam.example.test',captureGroupId:id,segmentIndex:0,
  endedAt:ended?'2026-10-24T10:40:00Z':null,
  requests,counters:dropped?{requestsDropped:dropped}:{},raw:PRIVATE}];
}
const a=sample('a'),b=sample('b');
let report=X.synthesize(a,b,context);
assert.equal(report.format,'trufflehog-evidence-weighted-dam-review');
assert.equal(report.assessment,'Operator-declared alignment — descriptive review only');
assert.equal(report.rows.length,6);
assert.equal(report.verifiedEquivalentContexts,false);
assert.equal(report.securityDefectEstablished,false);
assert.equal(report.overview.requestMixDifferencePercent,0);
assert.deepEqual(report.rows.map(r=>r.interpretation),Array(6).fill('No material recorded difference'));
report=X.synthesize(a,b,{...context,assetScope:'different'});
assert.match(report.assessment,/mismatch/);
assert.equal(report.overview.operatorMismatch,true);
report=X.synthesize(a,b,{...context,accessRole:'unknown'});
assert.equal(report.assessment,'Limited descriptive evidence');
assert.equal(report.overview.unknownContext,true);
report=X.synthesize(a,sample('c',{pattern:'api'}),context);
assert.match(report.assessment,/Different observed workflows/);
assert(report.limitations.some(x=>/patterns differ/.test(x)));
report=X.synthesize(sample('d',{n:15}),sample('e',{n:15}),context);
assert.equal(report.assessment,'Limited descriptive evidence');
assert(report.rows.some(x=>/Small sample/.test(x.interpretation)));
report=X.synthesize(a,sample('f',{dropped:5}),context);
assert.equal(report.assessment,'Limited descriptive evidence');
assert(report.limitations.some(x=>/Capture limits/.test(x)));
const missing=X.synthesize(sample('d',{n:0}),sample('e',{n:0}),context);
assert.match(missing.assessment,/missing HTTP evidence/);
assert.throws(()=>X.synthesize(a,a,context),/different saved capture groups/);
assert.throws(()=>X.synthesize(a,[{...b[0],origin:'https://another.example.test'}],context),/same exact/);
// A controlled delivered-versus-denied delta is reported as an observation,
// never as an authenticated-bypass claim.
const mostlyGood=sample('early',{n:200});
const denied=sample('late',{n:200,denied:true});
report=X.synthesize(mostlyGood,denied,context);
assert(report.rows.some(r=>r.differencePerThousand!==0));
assert.equal(report.securityDefectEstablished,false);
for(const r of [report,missing,X.synthesize(a,sample('g',{pattern:'api'}),context),X.synthesize(a,b,{...context,workflow:PRIVATE})]){
 const json=JSON.stringify(r);
 assert(!json.includes(PRIVATE));assert(!json.includes(URL));assert(!json.includes('dam.example.test'));
 assert(!/"(url|origin|host|captureGroupId|requestId|token|traceparent|secret)"\s*:/.test(json));
}
console.log('PASS v6.6 strictly redacted evidence synthesis, confidence gates, mismatches and same-origin constraints');
