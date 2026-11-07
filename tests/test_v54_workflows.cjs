'use strict';
const assert=require('node:assert/strict');
const WF=require('../workflow_intel.js');
const t=Date.parse('2026-10-24T12:00:00.000Z');
const at=offset=>new Date(t+offset*1000).toISOString();
const secret='ACCESS_SECRET_VALUE_SHOULD_NOT_APPEAR_143';
const item=(requestId,stage,seconds,more={})=>({requestId,stage,at:at(seconds),host:'dam.example',method:'POST',...more});
const data=[
 item(secret,'request',0,{method:'POST',bodyState:'opaque',signedIndicators:[]}),
 item(secret,'headers',1,{method:'POST',authentication:'Bearer',token:secret}),
 item(secret,'response-headers',2,{method:'POST',status:202}),
 item(secret,'complete',3,{method:'POST',status:202}),
 item('get-2','request',8,{method:'GET'}),
 item('get-2','complete',9,{method:'GET',status:200,fileType:'application/json'}),
 item('get-3','request',12,{method:'GET',signedIndicators:['URL signing fields']}),
 item('get-3','response-headers',13,{method:'GET',fileType:'application/zip',attachment:true}),
 item('get-3','complete',14,{method:'GET',status:200,attachment:true}),
 {stage:'download-start',at:at(16),downloadRef:'DL12345678901230001',host:'cdn.example',referrerHost:'dam.example',downloadStatus:'started',filename:'/home/'+secret+'.zip'},
 {stage:'download-state',at:at(19),downloadRef:'DL12345678901230001',downloadStatus:'complete',totalBytes:100,receivedBytes:100},
];
const record={downloadObserverEverEnabled:true,downloadEvents:data,downloadEventsDropped:0,autoScanCoverage:{eligible:4,scanned:3}};
const output=WF.analyse(record);
assert.equal(output.workflows.length,1);
assert.equal(output.workflows[0].httpStatus,202);
assert.match(output.workflows[0].classification,/Possible asynchronous export/);
assert.equal(output.workflows[0].downloadRef,'DL12345678901230001');
assert.equal(output.workflows[0].outcome,'Download completed in browser');
assert(output.workflows[0].related.some(x=>x.step==='Attachment response'));
assert.equal(output.unassociatedDownloads.length,0);
assert(!JSON.stringify(WF.exportReport(record)).includes(secret));
assert(!JSON.stringify(output).includes('get-2'));
assert(!JSON.stringify(output).includes('ACCESS_SECRET'));
const coverage=WF.coverage(record,{});
assert.equal(coverage.checks.find(c=>c.id==='opt-in').state,'observed');
assert.equal(coverage.checks.find(c=>c.id==='devtools').state,'partial');
assert.equal(coverage.counts.downloadLabels,1);
const ambiguous={...record,downloadEvents:[...data,item('second','request',5),item('second','complete',6,{status:200})]};
const ambiguousResult=WF.analyse(ambiguous);
assert(ambiguousResult.workflows.every(w=>!w.downloadRef));
assert.equal(ambiguousResult.unassociatedDownloads.length,1);
const upload={downloadEvents:[item('up','request',0,{awsDam:{operation:'S3 presigned POST request observed'}}),item('up','complete',2,{awsDam:{operation:'S3 presigned POST request observed'},status:204})]};
assert.equal(WF.analyse(upload).workflows.length,0,'presigned POST uploads are not download candidates');
const old={downloadEvents:[{stage:'download-start',at:at(1),downloadStatus:'started'}]};
assert.equal(WF.coverage(old).checks.find(c=>c.id==='opt-in').state,'unknown');
assert.equal(WF.analyse(old).totals.downloadsWithoutLocalRefs,1);
const corrupt={downloadEvents:[{...data[0],host:secret+'.com',downloadRef:secret,stage:'request',at:secret},...data]};
assert(!JSON.stringify(WF.exportReport(corrupt)).includes(secret));
console.log('PASS v5.4 workflow: job clue, request grouping, ambiguity, upload exclusion, old record, privacy, coverage');
