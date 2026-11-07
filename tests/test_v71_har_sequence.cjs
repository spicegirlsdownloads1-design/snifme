'use strict';
const assert=require('node:assert/strict');
const {audit}=require('../har_sequence.js');
const SECRET='TOPSECRET_REPLAY_TOKEN_DO_NOT_COPY';
const H=(url,method,status,headers=[],extra={})=>({
 startedDateTime:extra.at||'2026-10-24T10:00:00Z',
 request:{url,method,headers:extra.requestHeaders||[],...extra.request},
 response:{status,headers,content:{mimeType:extra.mime||'application/json'}}
});
const har={log:{entries:[
 H('https://api.captureweb.net/export/create?sig='+SECRET,'POST',202,[],{at:'2026-10-24T10:00:00Z',request:{postData:{text:SECRET,mimeType:'application/json'}}}),
 H('https://api.captureweb.net/job/status?token='+SECRET,'GET',200,[],{at:'2026-10-24T10:00:01Z'}),
 H('https://cdn.cloudfront.net/opaque?X-Amz-Signature='+SECRET,'GET',302,[{name:'Location',value:'https://secret.invalid/'+SECRET}],{at:'2026-10-24T10:00:03Z'}),
 H('https://cdn.cloudfront.net/download?token='+SECRET,'GET',200,[{name:'Content-Disposition',value:'attachment; filename="'+SECRET+'.jpg"'}],{at:'2026-10-24T10:00:05Z',mime:'image/jpeg'}),
 H('https://foo.s3.amazonaws.com/upload','POST',204,[],{at:'2026-10-24T10:00:07Z',request:{postData:{mimeType:'multipart/form-data',params:[{name:'policy',value:SECRET},{name:'x-amz-signature',value:SECRET}]}}}),
 H('https://api.example.invalid/a','GET',403,[],{at:'2026-10-24T10:00:03Z'}),
 H('https://api.example.invalid/a','GET',206,[],{at:'BAD TIME',mime:'video/mp4'}),
 H('https://api.example.invalid/a','GET',200,[],{at:'2026-10-24T10:02:00Z',mime:'image/jpeg'}),
 {request:{url:'file:///'+SECRET,method:'GET'},response:{status:200}},
 null
]}};
const report=audit(har),serialized=JSON.stringify(report);
assert.equal(report.format,'trufflehog-har-sequence');
assert.equal(report.coverage.totalEntries,10);
assert.equal(report.coverage.invalidEntries,2);
assert.equal(report.coverage.inspectedHttp,8);
assert.equal(report.coverage.shownStageEvents,8);
assert.equal(report.coverage.missingTimestamps,1);
assert.equal(report.coverage.nonMonotonicTimestamps,1);
assert.deepEqual(report.events.slice(0,4).map(x=>x.stage),[
 'Export preparation request clue','Export status request clue','HTTP redirect response','Attachment delivery response']);
assert.equal(report.events[0].provider,'Capture service');
assert.equal(report.events[3].provider,'CloudFront CDN');
assert.equal(report.events[4].stage,'Upload / resumable transfer clue');
assert.equal(report.events[5].stage,'Access denied response');
assert.equal(report.events[6].stage,'Partial-content response');
assert.equal(report.events[7].stage,'Media response');
assert.equal(report.events[1].timeBand,'Under 2 seconds');
assert.equal(report.events[3].timeBand,'2–10 seconds');
assert.equal(report.events[6].timeBand,'Not available');
assert.equal(report.patterns[1].count,1);
for(const value of [SECRET,'api.captureweb.net','cdn.cloudfront.net','/job/status','filename','x-amz','2026-10-24T10:00:00Z'])assert(!serialized.includes(value),'leak '+value);
const large={log:{entries:Array.from({length:500},(_,i)=>H('https://foo.example.invalid/asset.jpg?q='+SECRET,'GET',200,[],{mime:'image/jpeg'}))}};
const bound=audit(large);assert.equal(bound.coverage.shownStageEvents,240);assert.equal(bound.coverage.omittedStageEvents,260);
assert.throws(()=>audit({}),/log.entries/);assert.throws(()=>audit({log:{entries:Array.from({length:12001},()=>({}))}}),/12,000/);
const poison={log:{entries:[H('https://'+SECRET+'.invalid/export/create?'+SECRET+'='+SECRET,'POST',202,[{name:SECRET,value:SECRET}],{request:{postData:{params:[{name:SECRET,value:SECRET}]}}})]}};
assert(!JSON.stringify(audit(poison)).includes(SECRET));
console.log('PASS v7.1: bounded HAR stage sequence, inference limits, time bins, upload separation, malformed input and privacy');
