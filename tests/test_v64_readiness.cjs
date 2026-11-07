'use strict';
const assert=require('node:assert/strict');
require('../dam_policy_compare.js');
const M=require('../comparison_readiness.js');
const SECRET='PRIVATE_SECRET_CANNOT_APPEAR_IN_READINESS_EXPORT';
const host='https://photo.example';
function group(id,n=60,extra={}){
 return [{origin:host,captureGroupId:id,segmentIndex:0,endedAt:'2026-10-24T12:00:00Z',
  counters:{},requests:Array.from({length:n},(_,i)=>({type:i%2?'image':'fetch',mime:i%2?'image/jpeg':'application/json',status:200,url:'https://private.example/'+SECRET+'?token='+SECRET,authorization:SECRET})),
  rawSecret:SECRET, ...extra}];
}
const all={accessRole:'same',workflow:'same',assetScope:'same',hostPermissions:'same',devtoolsTiming:'both-early'};
const good=M.assess(group('a'),group('b'),all);
assert.equal(good.outcome,'Operator-declared matching context');
assert.equal(good.comparisonAllowedAsEquivalent,false,'never claims verified equivalence');
assert.equal(good.counts.baselineRequests,60);
assert.equal(good.context.length,5);
const uncertain=M.assess(group('a'),group('b'),{});
assert.equal(uncertain.outcome,'Limited descriptive comparison');
assert(uncertain.cautions.some(x=>/not confirmed/.test(x)));
const mismatch=M.assess(group('a'),group('b'),{...all,accessRole:'different'});
assert.equal(mismatch.outcome,'Do not compare as equivalent');
assert(mismatch.blocking.some(x=>/Access role/.test(x)));
const devtools=M.assess(group('a'),group('b'),{...all,devtoolsTiming:'not-both-early'});
assert.equal(devtools.outcome,'Do not compare as equivalent');
const dropped=M.assess(group('a',60,{counters:{requestsDropped:2},endedAt:null}),group('b',60),all);
assert.equal(dropped.outcome,'Limited descriptive comparison');
assert(dropped.cautions.some(x=>/dropped/i.test(x)));
const skew=M.assess(group('a',60),group('b',250),all);
assert(skew.cautions.some(x=>/3×/.test(x)));
const empty=M.assess(group('a',0),group('b',60),all);
assert.equal(empty.outcome,'Do not compare as equivalent');
const injected=M.assess(group('a'),group('b'),{...all,accessRole:SECRET,nonExisting:SECRET});
assert.equal(injected.context[0].status,'Not established');
for(const x of [good,uncertain,mismatch,devtools,dropped,skew,empty,injected]){
 const string=JSON.stringify(x);assert(!string.includes(SECRET));
 assert(!string.includes(host));assert(!string.includes('private.example'));
 assert(!string.includes('captureGroupId'));assert(!string.includes('requests:[{'));
}
assert.throws(()=>M.assess(group('a'),group('a'),all),/different saved capture/i);
assert.throws(()=>M.assess(group('a'),[{...group('b')[0],origin:'https://other.example'}],all),/exact same/i);
console.log('PASS v6.4 operator-declared comparability, unknown/mismatch/DevTools, limits, cross-origin and strict redaction');
