 'use strict';
const assert=require('node:assert/strict');
const P=require('../workflow_pattern.js');
require('../dam_policy_compare.js');
const R=require('../comparison_readiness.js');
const SECRET='CREDENTIAL_NEVER_IN_THE_REPORT_abc123';
const host='https://archive.example';
function make(id,pattern='balanced',n=160,opts={}){
 const types=pattern==='balanced'?['image','fetch','script','stylesheet','main_frame']:
              pattern==='api'?['fetch','fetch','fetch','xmlhttprequest','fetch']:['image','image','image','image','image'];
 const requests=Array.from({length:n},(_,i)=>({type:types[i%types.length],method:i%9?'GET':'POST',
   mime:types[i%types.length]==='image'?'image/jpeg':'application/json',status:i%11?200:403,
   url:host+'/'+SECRET+'?token='+SECRET,secret:SECRET, at:new Date(Date.UTC(2026,9,24,12,0,i)).toISOString()}));
 return [{origin:host,captureGroupId:id,segmentIndex:1,endedAt:opts.endedAt===undefined?'2026-10-24T12:30:00Z':opts.endedAt,
  requests,counters:opts.counters||{},downloadEvents:[{stage:'download-state',downloadStatus:'complete',downloadRef:SECRET,filename:SECRET}],raw:SECRET}];
}
const same=P.compare(make('a'),make('b'));
assert.equal(same.assessment,'Similar observed request composition');
assert.equal(same.overview.requestMixDifferencePercent,0);
assert.equal(same.overview.baselineCompletedDownloads,1);
assert.equal(same.rows.length,9);
const mismatch=P.compare(make('a','api'),make('b','image'));
assert.equal(mismatch.assessment,'Materially different observed request pattern');
const withReadiness=R.assess(make('a','api'),make('b','image'),{accessRole:'same',workflow:'same',assetScope:'same',hostPermissions:'same',devtoolsTiming:'both-early'});
assert(withReadiness.cautions.some(x=>/pattern differs/.test(x)));
assert.equal(withReadiness.comparisonAllowedAsEquivalent,false);
const short=P.compare(make('a','api',12),make('b','image',12));
assert.equal(short.assessment,'Insufficient captured observations');
const old=make('a');old[0].requests.forEach(x=>delete x.at);
const incomplete=P.compare(old,make('b'));
assert.equal(incomplete.overview.sequenceEvidence,'Partial: fallback record order');
assert(incomplete.limitations.some(x=>/record order/.test(x)));
const dropped=P.compare(make('a','balanced',160,{counters:{requestsDropped:4}}),make('b'));
assert(dropped.limitations.some(x=>/dropped/i.test(x)));
const malicious=make('a');malicious[0].requests[0].type=SECRET;malicious[0].requests[0].mime=SECRET;
for(const report of [same,mismatch,short,incomplete,dropped,P.compare(malicious,make('b')),withReadiness]){
 const t=JSON.stringify(report);
 assert(!t.includes(SECRET));assert(!t.includes(host));assert(!t.includes('token='));
 assert(!t.includes('downloadRef'));assert(!t.includes('url'));assert(!t.includes('captureGroupId'));
}
assert.throws(()=>P.compare(make('a'),make('a')), /different saved capture groups/);
assert.throws(()=>P.compare(make('a'),[{...make('b')[0],origin:'https://other.example'}]),/same exact origin/);
assert.equal(P.category({attachmentDisposition:true,type:'image'}),'Downloads');
assert.equal(P.category({type:'fetch',method:'POST'}),'API writes');
console.log('PASS v6.5 observed request patterns, limits, redacted exports and readiness integration');
