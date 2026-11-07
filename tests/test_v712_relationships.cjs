'use strict';
const assert=require('node:assert/strict');
const Agent=require('../generic_relationship_confidence.js');
const secret='MY_PRIVATE_TOKEN_5555_DO_NOT_EXPORT';
const host='private-dam.company.test';
const t=n=>'2026-10-24T12:00:'+String(n).padStart(2,'0')+'.000Z';
const request=(n,frame,doc,extra={})=>({at:t(n),type:'fetch',url:`https://${host}/api?api_key=${secret}`,document:doc,frameId:frame,initiatorOrigin:`https://${host}`,...extra});
const page=`https://${host}/private?session=${secret}`;
const record={endedAt:t(59),downloadObserverEverEnabled:true,counters:{requestsDropped:2},downloadEventsDropped:1,
 requests:[
  request(0,0,page), request(1,0,page),// structural
  request(2,1,page),// timing due frame difference
  request(3,1,page,{document:''}),// timing due missing context
  request(3,1,page),// tie
  request(4,1,page),// adjacent to tie excluded
  request(45,1,page),// 41s gap
  request(48,1,page,{at:'invalid'}),
 ],
 downloadEvents:[
  {stage:'request',requestId:'a',payload:secret},
  {stage:'headers',requestId:'a',headerNames:['Authorization'],raw:secret},
  {stage:'complete',requestId:'a'},
  {stage:'request',requestId:'b'},
  {stage:'complete',requestId:'c'},
  {stage:'download-start',downloadRef:'DL1',url:page},
  {stage:'download-state',downloadRef:'DL1',downloadStatus:'interrupted',raw:secret},
  {stage:'download-start',downloadRef:'DL2'},
  {stage:'download-state',downloadRef:'DL3',downloadStatus:'complete'},
  {stage:'request',requestId:''},
  {stage:'download-state',downloadRef:'a-token',downloadStatus:'complete'}
 ]};
const before=JSON.stringify(record),report=Agent.analyze(record);
assert.equal(before,JSON.stringify(record),'record not mutated');
assert.equal(report.overview.exactHTTPGroups,1);
assert.equal(report.overview.exactDownloadGroups,1);
assert.equal(report.overview.incompleteHTTPGroups,2);
assert.equal(report.overview.incompleteDownloadGroups,2);
assert.equal(report.overview.structuralContextPairs,1);
assert.equal(report.overview.timingOnlyPairs,1);
assert.equal(report.overview.ambiguousTimestampPairs,3);
assert.equal(report.overview.longGaps,1);
assert.equal(report.overview.missingOrInvalidTimes,1);
assert.equal(report.overview.missingContext,1);
assert.equal(report.overview.missingGroupingLabels,2);
assert.equal(report.overview.droppedObservations,3);
assert.equal(report.rows.length,4);
for(const item of report.rows)assert.equal(typeof item.count,'number');
const exportText=JSON.stringify(report);
for(const value of [secret,host,page,'DL1','Authorization','api_key','requestId','http://','https://']){
 assert(!exportText.includes(value),'must redact: '+value);
}
assert.equal(report.noAdditionalRequests,true);
assert.equal(report.platformIdentificationRequired,false);
assert.equal(report.credentialsRetained,false);
// Only sharing a hostname does not create structural evidence.
const noContext=Agent.analyze({endedAt:t(59),requests:[
 {at:t(1),url:`https://${host}/a`},{at:t(2),url:`https://${host}/b`}]});
assert.equal(noContext.overview.structuralContextPairs,0);
assert.equal(noContext.overview.timingOnlyPairs,1);
assert(noContext.warnings.some(x=>x.includes('observer')));
// Invalid, tied and out-of-order input cannot invent chronology.
const tied=Agent.analyze({endedAt:t(59),requests:[request(1,0,page),request(1,0,page),request(2,0,page)]});
assert.equal(tied.overview.structuralContextPairs,0);
assert.equal(tied.overview.timingOnlyPairs,0);
assert.equal(tied.overview.ambiguousTimestampPairs,2);
const reversed=Agent.analyze({endedAt:t(59),requests:[request(2,0,page),request(1,0,page)]});
assert.equal(reversed.overview.structuralContextPairs,1);
// Limit processing and do not export arbitrary extra record attributes.
const capped=Agent.analyze({requests:Array(3100).fill(request(1,0,page)),downloadEvents:Array(3100).fill({stage:'request',requestId:'x'})});
assert.equal(capped.overview.timedHTTP,3000);
assert.equal(capped.overview.sampleCapped,true);
assert(!JSON.stringify(capped).includes(secret));
for(const r of [Agent.analyze(null),Agent.analyze({requests:[null,{},'x']})])
 assert(r.rows.every(x=>Number.isSafeInteger(x.count)&&x.count>=0));
console.log('PASS v7.12 graded evidence, private grouping keys, redaction, timestamps, omissions and caps');
