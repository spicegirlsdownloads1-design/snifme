 'use strict';
const assert=require('node:assert/strict');
require('../scanner.js');
const X=require('../har_coverage.js');
const token='SECRET_TOKEN_ABC123456789';
const target='https://archive.example.test';
const link=target+'/api/download?token='+token+'&page=3';
const ts=n=>new Date(Date.UTC(2026,9,24,13,10,n)).toISOString();
const record={origin:target,captureGroupId:'session-a',segmentIndex:0,endedAt:ts(12),requests:[
 {url:link,method:'POST',status:202,type:'xmlhttprequest',mime:'application/json',at:ts(1)},
 {url:target+'/photos/preview.jpg',method:'GET',status:200,type:'image',mime:'image/jpeg',at:ts(2)},
 {url:'https://cdn.example.test/photo.jpg?Signature='+token,method:'GET',status:200,type:'image',mime:'image/jpeg',at:ts(3)},
 {url:target+'/only-extension',method:'GET',status:200,type:'script',mime:'text/javascript',at:ts(4)}
 ],counters:{requestsDropped:0},raw:token};
const entry=(url,method,status,mime,time)=>({startedDateTime:ts(time),request:{url,method,headers:[{name:'Authorization',value:'Bearer '+token}],postData:{text:token}},response:{status,content:{mimeType:mime,text:token}}});
const har={log:{version:'1.2',entries:[
 entry(link,'POST',202,'application/json',1),entry(target+'/photos/preview.jpg','GET',200,'image/jpeg',2),
 entry('https://cdn.example.test/photo.jpg?Signature='+token,'GET',403,'image/jpeg',3),
 entry(target+'/har-only.css','GET',200,'text/css',5)
]}};
const result=X.reconcile(har,[record]);
assert.equal(result.format,'trufflehog-har-coverage-reconciliation');
assert.equal(result.coverage.exactMatches,2);
assert.equal(result.coverage.statusDifferentMatches,1);
assert.equal(result.coverage.harOnly,1);
assert.equal(result.coverage.savedOnly,1);
assert.equal(result.coverage.harRequests,4);
assert.equal(result.coverage.savedRequests,4);
assert.equal(result.coverage.harBodyEntriesIgnored,4);
assert.equal(result.coverage.timeOverlapConfirmed,true);
assert.equal(result.rows.find(x=>x.category==='Styles').harOnly,1);
assert.equal(result.rows.find(x=>x.category==='Scripts').captureOnly,1);
assert(result.warnings.some(w=>w.includes('body')||w.includes('bodies')));
const exported=JSON.stringify(result);
for(const forbidden of [token,'archive.example.test','cdn.example.test','/api/download','/photos/preview','Authorization','Bearer','session-a','postData','traceId'])assert(!exported.includes(forbidden),forbidden);
assert(!/(?:"url"|"origin"|"host"|"requestId"|"token")\s*:/.test(exported));
const repeated={log:{entries:[entry(link,'POST',202,'application/json',1),entry(link,'POST',202,'application/json',1)]}};
const out=X.reconcile(repeated,[{...record,requests:[record.requests[0]]}]);
assert.equal(out.coverage.exactMatches,1);assert.equal(out.coverage.harOnly,1);
assert.throws(()=>X.reconcile({log:{entries:[entry('https://other.test/x','GET',200,'image/png',1)]}},[record]),/site origin/);
assert.throws(()=>X.reconcile({log:{entries:[]}},[record]),/no eligible/);
assert.throws(()=>X.reconcile({entries:[]},[record]),/valid HAR/);
assert.throws(()=>X.reconcile({log:{entries:Array.from({length:12001},()=>entry(link,'GET',200,'text/html',1))}},[record]),/too many/);
assert.throws(()=>X.reconcile(har,[{...record,origin:'https://other.test'}]),/origin/);
const drift=X.reconcile({...har,log:{...har.log,entries:har.log.entries.map(e=>({...e,startedDateTime:'2026-01-01T01:00:00Z'}))}},[record]);
assert.equal(drift.coverage.timeOverlapConfirmed,false);
assert.match(drift.assessment,/Time windows differ/);
const dropped=X.reconcile(har,[{...record,counters:{requestsDropped:8}}]);
assert.equal(dropped.coverage.savedDropped,8);
assert(dropped.warnings.some(x=>/dropped/.test(x)));
console.log('PASS v6.7 HAR independent coverage, duplicate multiplicity, time gaps, strict redaction, caps and source validation');
