'use strict';
const assert=require('node:assert/strict');
const R=require('../har_range_evidence.js');
const SECRET='VERY_PRIVATE_DO_NOT_INCLUDE_IN_OUTPUT';
const host='https://media-secret.example.invalid';
const h=(name,value)=>({name,value});
const item=(path,status,opt={})=>({
 startedDateTime:'2026-10-24T13:00:00.123Z',comment:SECRET,
 request:{url:host+path+'?signature='+SECRET,method:'GET',headers:opt.reqHeaders??[],postData:{text:SECRET}},
 response:{status,headers:opt.resHeaders??[],content:{mimeType:opt.mime||'image/jpeg',text:SECRET},bodySize:900}
});
const part=(path,from,to,total,{etag='"TAG-SENSITIVE"',len,encoding,reqHeaders=[]}={})=>item(path,206,{reqHeaders, resHeaders:[h('Content-Range',`bytes ${from}-${to}/${total}`),...(etag?[h('ETag',etag)]:[]),...(len===undefined?[]:[h('Content-Length',String(len))]),...(encoding?[h('Content-Encoding',encoding)]:[])]});
const entries=[
 part('/one.jpg',0,499,1000,{len:500,reqHeaders:[h('Range','bytes=0-499')]}),
 part('/one.jpg',500,999,1000,{len:500,reqHeaders:[h('Range','bytes=500-999'),h('If-Range',SECRET)]}),
 part('/two.jpg',0,199,1000,{etag:'"DIFFERENT-SECRET"'}),
 part('/two.jpg',100,249,1000,{etag:'"DIFFERENT-SECRET"'}),
 part('/weak.jpg',0,50,200,{etag:'W/"weak"'}),
 part('/missing.jpg',0,50,200,{etag:''}),
 item('/multi.zip',206,{mime:'multipart/byteranges; boundary='+SECRET,resHeaders:[h('Content-Type','multipart/byteranges; boundary='+SECRET)]}),
 item('/invalid.jpg',206,{resHeaders:[h('Content-Range','bytes 900-1000/1000')]}),
 item('/unknown.jpg',206,{resHeaders:[h('Content-Range','bytes 0-49/*'),h('ETag','"TAG-SECRET"')]}),
 part('/mismatch.jpg',0,99,400,{len:15}),
 item('/fallback.jpg',200,{reqHeaders:[h('Range','bytes=0-500')],resHeaders:[h('Accept-Ranges','none')]}),
 item('/unsatisfied.jpg',416,{resHeaders:[h('Content-Range','bytes */1000')]}),
 item('/bad-416.jpg',416,{resHeaders:[h('Content-Range','bytes something-private')]}),
 item('/accept.jpg',200,{resHeaders:[h('Accept-Ranges','bytes')]}),
 {request:{url:'ftp://bad.invalid/file',method:'GET'},response:{status:206,headers:[h('Content-Range','bytes 0-4/5')]}}
];
const base={log:{entries}};const result=R.audit(base);
const get=s=>result.signals.find(x=>x.category===s).count;
assert.equal(result.coverage.totalEntries,15);
assert.equal(result.coverage.inspectedHttp,14);
assert.equal(result.coverage.partialResponses,10);
assert.equal(result.coverage.validRangeResponses,8);
assert.equal(result.coverage.stableTagGroups,3); // one, two, mismatch
assert.equal(result.coverage.groupsWithOverlap,1);
assert.equal(get('206 valid single-part Content-Range with known total'),7);
assert.equal(get('206 valid single-part Content-Range with unknown total'),1);
assert.equal(get('206 multipart/byteranges response (body not inspected)'),1);
assert.equal(get('206 invalid or missing Content-Range'),1);
assert.equal(get('206 Content-Length disagrees with declared single-part range'),1);
assert.equal(get('Range request answered with HTTP 200'),1);
assert.equal(get('416 with unsatisfied Content-Range'),1);
assert.equal(get('416 without valid unsatisfied Content-Range'),1);
assert.equal(get('206 without strong ETag (not grouped)'),2);
assert.equal(get('Overlapping declared spans in stable-tag groups'),1);
assert.equal(result.spanBuckets.find(x=>x.category.includes('100%')).count,1);
assert.equal(result.spanBuckets.find(x=>x.category.includes('25–49%')).count,2);
for(const word of [SECRET,'TAG-SENSITIVE','DIFFERENT-SECRET','media-secret.example.invalid','2026-10-24','signature=','W/"weak"','bytes 0-49','/one.jpg'])assert(!JSON.stringify(result).includes(word),`leak: ${word}`);
assert.throws(()=>R.audit({}),/log.entries/);
assert.throws(()=>R.audit({log:{entries:Array(12001).fill({})}}),/limit/);
const comparison=R.compare(base,base,{sameSite:'yes',sameActions:'yes',sameAccount:'yes',sameScope:'yes',sameBrowserCoverage:'yes'});
assert.equal(comparison.readiness,'Context declared comparable');
assert.equal(comparison.signals[0].baselinePer1000Partial,300);
assert.equal(R.compare(base,base,{sameSite:'no'}).readiness,'Not comparable');
for(const word of [SECRET,'media-secret.example.invalid','TAG-SENSITIVE','signature='])assert(!JSON.stringify(comparison).includes(word));
// Same URL with different strong ETag: never merge spans.
const different=R.audit({log:{entries:[part('/same',0,499,1000,{etag:'"first"'}),part('/same',500,999,1000,{etag:'"second"'})]}});
assert.equal(different.coverage.stableTagGroups,2);
assert.equal(different.spanBuckets.find(x=>x.category.includes('100%')).count,0);
// Same URL and ETag but different content coding: never merge spans.
const encoding=R.audit({log:{entries:[part('/same',0,499,1000,{encoding:'gzip'}),part('/same',500,999,1000,{encoding:'br'})]}});
assert.equal(encoding.coverage.stableTagGroups,2);
// Large or invalid Content-Range values rejected rather than rounded.
const huge=R.audit({log:{entries:[item('/huge',206,{resHeaders:[h('Content-Range','bytes 0-999999999999999999999/9999999999999999999999')]})]}});
assert.equal(huge.coverage.validRangeResponses,0);
// Entire declared span does not establish file integrity; no output filename, hash or reconstructed file.
assert(!Object.keys(result).some(x=>/downloaded|completedFile|reconstructed/i.test(x)));
console.log('PASS v7.7: range headers, grouping safeguards, comparison, no raw values');
