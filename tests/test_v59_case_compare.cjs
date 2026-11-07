'use strict';
const assert=require('node:assert/strict');
const T=require('../case_compare.js');
(async()=>{
 const secret='DO_NOT_EXPORT_PRIVATE_SECRET_99999';
 const start=(group,session,when)=>({origin:'https://archive.example.test/private/'+secret+'?token='+secret,
  captureGroupId:group,sessionId:session,segmentIndex:1,createdAt:when,endedAt:new Date(Date.parse(when)+5000).toISOString(),
  requests:[],findings:[],verifications:[],downloadEvents:[],counters:{},autoScanCoverage:{eligible:2,scanned:2}});
 const a=start('before-has-SECRET-'+secret,'sessionA','2026-10-23T10:00:00Z');
 const b=start('after-has-SECRET-'+secret,'sessionB','2026-10-24T11:00:00Z');
 a.requests=[{at:a.createdAt,url:'https://cdn.example.test/preview.jpg?token='+secret,mime:'image/jpeg',type:'image',status:200,cacheScope:'private',cacheMaxAge:10}];
 b.requests=[{at:b.createdAt,url:'https://cdn.example.test/master.jpg?token='+secret,mime:'image/jpeg',type:'image',status:200,cacheScope:'public',cacheMaxAge:86400,signedQuery:true},
 {at:b.createdAt,url:'https://cdn.example.test/protected.jpg',mime:'image/jpeg',type:'image',status:403}];
 b.findings=[{type:'unknown',masked:secret,changeState:'changed'}];
 b.downloadEvents=[{downloadStatus:'complete',url:'https://download.example.test/file?sig='+secret}];
 const r=T.compare([a],[b]);
 assert.equal(r.siteOrigin,'https://archive.example.test');
 assert.equal(r.metrics.find(x=>x.label==='Recorded HTTP requests').delta,1);
 assert.equal(r.metrics.find(x=>x.label==='Public-cache responses with TTL of 24h+').later,1);
 assert.equal(r.metrics.find(x=>x.label==='Locally marked changed indicators').later,1);
 assert(r.notes.some(x=>x.priority==='Owner review'));
 assert.equal(r.comparisonConfidence,'Descriptive only; not a security certification');
 assert(!JSON.stringify(r).includes(secret));
 assert(!JSON.stringify(r).includes('cdn.example.test'));
 assert(!JSON.stringify(r).includes('before-has-SECRET'));
 assert(!JSON.stringify(r).includes('/private/'));
 assert(!T.csv(r).includes(secret));
 const pack=await T.pack(r);assert.match(pack.sha256,/^[0-9a-f]{64}$/);
 const injected={...r,unexpectedSecret:secret,metrics:r.metrics.map((x,i)=>i===0?{...x,qualification:secret}:x),
  limitations:[secret]};
 const sanitised=await T.pack(injected);
 assert(!JSON.stringify(sanitised).includes(secret),'Malicious report field smuggled into export');
 assert(!T.csv(injected).includes(secret),'Malicious report qualifier smuggled into CSV');
 await assert.rejects(()=>T.pack({...r,metrics:r.metrics.map((x,i)=>i===0?{...x,label:secret}:x)}),/Unsupported comparison metric/);
 const duplicate={...b,requests:[...b.requests,{...b.requests[0],carriedFromSegment:true}]};
 assert.equal(T.compare([a],[duplicate]).metrics.find(x=>x.label==='Public-cache responses with TTL of 24h+').later,1,
  'Carried forward request must not inflate CDN policy counts');
 const weaker={...b,autoScanCoverage:{eligible:10,scanned:2},segmentIndex:2,counters:{requestsDropped:2}};
 const r2=T.compare([a],[weaker]);
 assert.match(r2.comparisonConfidence,/Limited/);assert(r2.blindspots.length>0);
 assert.throws(()=>T.compare([a],[{...b,origin:'https://other.example.test'}]),/same website origin/);
 assert.throws(()=>T.compare([a],[{...b,captureGroupId:a.captureGroupId}]),/different capture groups/);
 assert.throws(()=>T.compare([a],[]),/Select two/);
 console.log('PASS v5.9 same-origin case drift, platform-safe labels, media policy evidence, coverage, exports and redaction');
})().catch(e=>{console.error(e);process.exitCode=1});
