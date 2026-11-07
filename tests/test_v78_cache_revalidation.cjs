'use strict';
const assert=require('node:assert/strict');
const C=require('../har_cache_revalidation.js');
const S='SECRET-NEVER-LEAK-83a9';
const h=(name,value)=>({name,value});
const item=(path,status,{method='GET',req=[],res=[],type='image/jpeg',body=false}={})=>({
 startedDateTime:'2026-10-24T14:02:00.111Z',
 request:{method,url:'https://secret-host.invalid/'+path+'?x-amz-signature='+S,headers:[...req,h('Cookie','token='+S)],postData:{text:S}},
 response:{status,headers:[...res,h('Set-Cookie','session='+S)],content:{mimeType:type,...(body?{text:S}:{})}}
});
const data={log:{entries:[
 item('asset.jpg',304,{req:[h('If-None-Match','"'+S+'"')],res:[h('ETag','"'+S+'"'),h('Cache-Control','private, max-age=60'),h('Vary','Accept-Encoding')]}),
 item('asset.jpg',200,{req:[h('If-None-Match','W/"'+S+'"'),h('If-Modified-Since','Tue, 01 Jan 2019 00:00:00 GMT')],res:[h('ETag','W/"'+S+'"'),h('Last-Modified','Tue, 01 Jan 2019 00:00:00 GMT'),h('Age','90'),h('Cache-Control','public, max-age=60, stale-while-revalidate=30, must-revalidate'),h('CF-Cache-Status','HIT')]}),
 item('media.mp4',304,{res:[h('Cache-Control','no-cache, no-store'),h('Vary','*')],body:true}),
 item('other.webp',206,{req:[h('If-Modified-Since',S),h('If-Range',S)],res:[h('Age','18'),h('Cache-Control','s-maxage=19, immutable')]}),
 item('edit',412,{method:'PUT',req:[h('If-Match',S)],res:[h('Cache-Control','private')]}),
 item('read',200,{req:[h('If-Match',S),h('If-Unmodified-Since',S)],res:[h('X-Cache','Miss from cloudfront')]}),
 {request:{method:'GET',url:'ftp://bad.invalid/',headers:[]},response:{status:304,headers:[]}},
 item('missing',304,{req:[h('If-None-Match',S)],res:[h('ETag','"'+S+'"')],type:'application/json'})
 ]}};
const out=C.audit(data),get=s=>out.signals.find(x=>x.category===s)?.count;
assert.equal(out.coverage.inspectedHttp,7);
assert.equal(out.coverage.conditionalSafeRequests,4);
assert.equal(out.coverage.notModifiedResponses,3);
assert.equal(get('Conditional GET/HEAD with If-None-Match'),3);
assert.equal(get('Conditional GET/HEAD with If-Modified-Since'),2);
assert.equal(get('Conditional GET/HEAD with both validators (ETag takes precedence)'),1);
assert.equal(get('HTTP 304 Not Modified observed'),3);
assert.equal(get('304 following a conditional GET/HEAD in the same HAR entry'),2);
assert.equal(get('304 with no conditional request header visible'),1);
assert.equal(get('HTTP 200 following a conditional GET/HEAD'),1);
assert.equal(get('HTTP 206 following a conditional GET/HEAD'),1);
assert.equal(get('HTTP 412 Precondition Failed observed'),1);
assert.equal(get('Response strong ETag header present'),2);
assert.equal(get('Response weak ETag header present'),1);
assert.equal(get('Response Cache-Control: no-store'),1);
assert.equal(get('Response Cache-Control: stale-while-revalidate'),1);
assert.equal(get('Response Age exceeds explicit max-age or s-maxage (header clue only)'),1);
assert.equal(get('Response cache HIT indicator'),1);
assert.equal(get('Response cache MISS indicator'),1);
assert.equal(get('Response Vary: * present'),1);
assert.equal(get('304 with response body text in HAR (export artefact or anomaly)'),1);
assert.equal(get('HTTP 304 on media MIME or media-suffix request (clue only)'),2);
for(const forbidden of [S,'secret-host.invalid','asset.jpg','2026-10-24','x-amz-signature','Set-Cookie','Tue, 01 Jan 2019'])assert(!JSON.stringify(out).includes(forbidden),'leak: '+forbidden);
const cmp=C.compare(data,data,{sameSite:'yes',sameActions:'yes',sameAccount:'yes',sameScope:'yes',sameBrowserCoverage:'yes'});
assert.equal(cmp.readiness,'Context or coverage review needed'); // fewer than 5 conditionals
assert.equal(C.compare(data,data,{sameAccount:'no'}).readiness,'Not comparable');
assert.equal(cmp.signals.length,out.signals.length);
for(const forbidden of [S,'secret-host.invalid','asset.jpg','x-amz-signature'])assert(!JSON.stringify(cmp).includes(forbidden));
assert.throws(()=>C.audit({}),/log.entries/);
assert.throws(()=>C.audit({log:{entries:new Array(12001).fill({})}}),/limit/);
// 304 without a request method/headers is observed but not treated as a confirmed revalidation.
const sparse=C.audit({log:{entries:[{request:{url:'https://example.invalid/a'},response:{status:304}}]}});
assert.equal(sparse.coverage.notModifiedResponses,1);
assert.equal(sparse.coverage.conditionalSafeRequests,0);
assert.equal(sparse.coverage.missingHeaderEntries,1);
console.log('PASS v7.8 cache revalidation: validated counters, sparse data, compare and redaction');
