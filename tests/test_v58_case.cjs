'use strict';
const assert=require('node:assert/strict');
const T=require('../case_intel.js');
(async()=>{
 const marker='DONT_INCLUDE_83FGF82',origin='https://samples.example.test';
 const a={sessionId:'session-aaabbbaaa',captureGroupId:'group-example-1122',segmentIndex:1,origin:origin+'/sensitive/'+marker+'?secret='+marker,createdAt:'2026-10-24T11:00:00Z',endedAt:'2026-10-24T11:30:00Z',
 requests:[{url:'https://api.example.test/token/'+marker,at:'2026-10-24T11:02:00Z',method:'POST',status:202},{url:'https://api.example.test/secret/'+marker,at:'2026-10-24T11:03:00Z',status:403}],
 findings:[{at:'2026-10-24T11:03:05Z',type:marker,masked:marker,secret:marker}],verifications:[{sha256:marker,at:'2026-10-24T11:04:00Z'}],
 downloadEvents:[{at:'2026-10-24T11:10:00Z',downloadStatus:'complete',url:marker}],counters:{'requestsDropped':2},autoScanCoverage:{eligible:5,scanned:2}};
 const b={...a,sessionId:'session-aaabbbbbb',segmentIndex:3,createdAt:'2026-10-24T12:00:00Z',endedAt:'2026-10-24T12:05:00Z',
 requests:[{at:'2026-10-24T12:01:00Z',status:200}],findings:[],verifications:[],downloadEvents:[],counters:{}};
 const report=T.build([b,a]);
 assert.equal(report.siteOrigin,origin);assert.equal(report.counts.requests,3);assert.equal(report.httpStatuses['4xx observed'],1);
 assert.equal(report.segmentSummary.missingCount,1);assert.equal(report.segmentSummary.highestSegment,3);
 assert.equal(report.downloads.completed,1);assert.equal(report.review.unverifiedCategories>0,true);
 assert.equal(report.scanner.coverageIncompleteOrUnknown,true);
 assert(report.evidence.some(e=>e.category==='Masked indicators'&&e.status==='Observed'));
 assert(!JSON.stringify(report).includes(marker),'Secret/content leaked');
 assert(!JSON.stringify(report).includes('api.example.test'),'External private service host leaked');
 assert(!JSON.stringify(report).includes('/sensitive/'),'Path leaked');
 assert(!JSON.stringify(report).includes('group-example'),'Capture-group ID leaked');
 assert(report.timeline.every(x=>['HTTP request','Masked security indicator','Browser download event','Observed file verification'].includes(x.kind)));
 const packed=await T.pack(report);assert.equal(await T.verify(packed),true);
 await assert.rejects(()=>T.verify({...packed,report:{...report,counts:{...report.counts,requests:42}}}),/integrity mismatch/);
 assert.throws(()=>T.build([a,{...b,origin:'https://other.example.test'}]),/one site origin/);
 assert.throws(()=>T.build([a,{...a}]),/repeated capture segment/);
 assert(!T.csv(report).includes(marker));
 console.log('PASS v5.8 dossier: grouped segments, status counts, continuity warnings, redaction, hash integrity');
})().catch(e=>{console.error(e);process.exitCode=1});
