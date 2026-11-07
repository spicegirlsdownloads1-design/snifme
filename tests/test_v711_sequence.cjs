'use strict';
const assert=require('node:assert/strict');
const Sequence=require('../generic_sequence.js');
const secret='Bearer_SECRET_DO_NOT_EXPORT_753';
const site='hidden-company.example.test';
const request=(at,type,extra={})=>({at,type,url:`https://${site}/path?token=${secret}`,status:200,...extra});
const record={endedAt:'2026-10-24T00:01:00.000Z',downloadObserverEverEnabled:true,
 requests:[
  request('2026-10-24T00:00:00.000Z','main_frame'),
  request('2026-10-24T00:00:01.000Z','script'),
  request('2026-10-24T00:00:03.000Z','xmlhttprequest',{method:'POST'}),
  request('2026-10-24T00:00:04.000Z','fetch',{method:'GET'}),
  request('2026-10-24T00:00:05.000Z','image'),
  request('2026-10-24T00:00:05.000Z','other',{attachmentDisposition:true}),
  request('2026-10-24T00:00:40.000Z','image'),
  request('2026-10-24T00:01:20.000Z','image'),
  request('invalid time','script')
 ],
 downloadEvents:[
  {stage:'request',requestId:'request-A',body:secret},
  {stage:'headers',requestId:'request-A',headerNames:['Authorization'],value:secret},
  {stage:'response-headers',requestId:'request-A'},
  {stage:'redirect',requestId:'request-A',redirectHost:site},
  {stage:'complete',requestId:'request-A'},
  {stage:'complete',requestId:'request-B'},
  {stage:'request',requestId:'request-C'},
  {stage:'request',requestId:'request-D'},
  {stage:'error',requestId:'request-D'},
  {stage:'request',requestId:''},
  {stage:'download-start',downloadRef:'DL1',url:secret},
  {stage:'download-state',downloadRef:'DL1',downloadStatus:'complete'},
  {stage:'download-start',downloadRef:'DL2'},
  {stage:'download-state',downloadRef:'DL3',downloadStatus:'complete'},
  {stage:'download-state',downloadRef:'DL4',downloadStatus:'interrupted'},
  {stage:'download-state',downloadRef:secret,downloadStatus:'complete'}
 ],counters:{requestsDropped:2},downloadEventsDropped:3};
const before=JSON.stringify(record),report=Sequence.analyze(record);
assert.equal(JSON.stringify(record),before,'source untouched');
assert.equal(report.overview.observedHTTP,9);
assert.equal(report.overview.timedHTTP,8);
assert.equal(report.overview.adjacentPairs,3);
assert.equal(report.overview.timestampTies,1);
assert.equal(report.overview.ambiguousNeighbourPairs,2);
assert.equal(report.overview.largeGaps,1);
assert.equal(report.overview.untimedOrInvalid,1);
assert.equal(report.overview.groupedHTTPLifecycles,4);
assert.equal(report.overview.groupedBrowserDownloads,4);
assert.equal(report.overview.droppedObservations,5);
const transition=k=>report.transitions.find(x=>x.transition===k)?.count;
for(const k of ['Document → Script/style','Script/style → API write','API write → API read'])assert.equal(transition(k),1,k);
assert.equal(transition('API read → Image/media'),0,'ambiguous timestamp boundary is not a definite transition');
assert.equal(transition('Image/media → Attachment'),0,'simultaneous ordering is ambiguous');
assert.equal(report.transitions.length,Sequence.labels.length**2);
const stage=k=>report.lifecycles.find(x=>x.stage===k)?.count;
for(const [k,n] of [
 ['HTTP starts paired with terminal event',2],['HTTP starts without terminal event',1],
 ['HTTP terminals without start event',1],['HTTP lifecycle redirect observed',1],
 ['HTTP request-header stage observed',1],['HTTP response-header stage observed',1],
 ['HTTP error terminal observed',1],['HTTP events without a grouping ID',1],
 ['Browser downloads with start and terminal',1],['Browser download starts without terminal',1],
 ['Browser download terminals without start',2],['Browser downloads completed',2],
 ['Browser downloads interrupted',1],['Browser download events without grouping ID',1]
])assert.equal(stage(k),n,k);
const exported=JSON.stringify(report);
for(const prohibited of [secret,site,'request-A','DL1','token','Authorization','http://'])assert(!exported.includes(prohibited),'Leak detected: '+prohibited);
assert.equal(report.credentialsRetained,false);
assert.equal(report.platformIdentificationRequired,false);
assert.equal(report.noAdditionalRequests,true);
assert(report.warnings.some(x=>/Equal timestamps/.test(x)));
const unavailable=Sequence.analyze({downloadObserverEverEnabled:false,requests:[{type:'fetch',at:null}]});
assert.equal(unavailable.overview.adjacentPairs,0);
assert(unavailable.warnings.some(x=>/observer/.test(x)));
const capped=Sequence.analyze({endedAt:'2026-10-24T00:00:00Z',requests:Array(3050).fill(request('2026-10-24T00:00:00.000Z','image')),
 downloadEvents:Array(3050).fill({stage:'headers',requestId:'a'})});
assert.equal(capped.overview.timedHTTP,3000);
assert.equal(capped.overview.sampleCapped,true);
assert(capped.warnings.some(x=>/sample cap/.test(x)));
assert(capped.transitions.every(x=>Number.isSafeInteger(x.count)&&x.count>=0));
console.log('PASS v7.11 observed traffic transitions, exact lifecycle pairing, redaction, incomplete times and caps');
