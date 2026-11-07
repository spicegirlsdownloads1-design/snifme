'use strict';
const assert=require('node:assert/strict');
const DP=require('../har_delivery_posture.js');
const SECRET='UNREDACTABLE_PREVIEW_TOKEN_SHOULD_NEVER_BE_EXPORTED';
function e(path,{code=200,mime='image/jpeg',reqHeaders=[],respHeaders=[],method='GET',postValue=''}={}){
 return {startedDateTime:'2026-10-24T11:23:45Z',request:{method,url:'https://secret-archive.example/photos/'+path+'?X-Amz-Signature='+SECRET+'&X-Amz-Expires=3600&session='+SECRET,
 headers:reqHeaders,postData:{text:postValue,params:[{name:'session',value:SECRET}]}},
 response:{status:code,headers:respHeaders,content:{mimeType:mime}},comment:SECRET};
}
const hd=(name,value)=>({name,value});
const a={log:{entries:[
 e('img-01.jpg',{reqHeaders:[hd('Authorization','Bearer '+SECRET),hd('Cookie','session='+SECRET)],respHeaders:[hd('Cache-Control','public,max-age=86401'),hd('CF-Cache-Status','HIT'),hd('Content-Length','46000')]}),
 e('img-02.webp',{respHeaders:[hd('Cache-Control','private, no-store,max-age=1'),hd('X-Cache','Miss from cloudfront')]}),
 e('img-03.jpeg',{code:403,mime:'text/html',respHeaders:[hd('Cache-Control','no-cache')]}),
 e('img-04.jpg',{code:302,mime:'text/html',respHeaders:[hd('Location','https://secret-archive.example/next?x='+SECRET)]}),
 e('file.zip',{mime:'application/zip',respHeaders:[hd('Content-Disposition','attachment;filename="'+SECRET+'.zip"'),hd('Cache-Control','public,s-maxage=60')]}),
 e('another.jpg',{code:206,respHeaders:[hd('CF-Cache-Status','BYPASS'),hd('Content-Disposition','inline;filename=PRIVATE.jpg')]}),
 e('unrelated.css',{mime:'text/css'}),
 {request:{method:'GET',url:'chrome-extension://illegal/page'},response:{status:200,headers:[]}},
 {request:{method:'GET',url:'https://secret-archive.example/a.jpg'}}
]}};
const r=DP.audit(a);const counts=Object.fromEntries(r.rows.map(x=>[x.category,x.count]));
assert.equal(r.format,'trufflehog-har-delivery-posture');
assert.equal(r.coverage.totalEntries,9);
assert.equal(r.coverage.inspectedHttp,7);
assert.equal(r.coverage.excludedEntries,2);
assert.equal(r.coverage.deliveryRelevantResponses,6);
assert.equal(counts['Observed image/media response'],3); // jpg, webp, 206 jpg
assert.equal(counts['Media denial response (401/403)'],1);
assert.equal(counts['Media redirect response (3xx)'],1);
assert.equal(counts['Response redirect target header present'],1);
assert.equal(counts['Partial media response (206)'],1);
assert.equal(counts['Attachment disposition observed'],1);
assert.equal(counts['Inline disposition observed'],1);
assert.equal(counts['Cache-Control public on media response'],2);
assert.equal(counts['Cache-Control private on media response'],1);
assert.equal(counts['Cache-Control no-store on media response'],1);
assert.equal(counts['Media cache max-age above 24 hours'],1);
assert.equal(counts['CDN cache HIT on media response'],1);
assert.equal(counts['CDN cache MISS on media response'],1);
assert.equal(counts['CDN cache BYPASS or DYNAMIC on media response'],1);
assert.equal(counts['Media response with public cache and signing-name indicator'],2);
assert.equal(counts['Media response with public cache and request authentication header'],1);
assert.equal(counts['Media response with public cache and request cookie'],1);
assert.equal(counts['Media response body absent in HAR'],3);
const b={log:{entries:[e('sample.webp',{respHeaders:[hd('Cache-Control','no-store')]}),e('test.webp',{respHeaders:[hd('cache-control','private')]}),e('foo.css',{mime:'text/css'})]}};
const d=DP.compare(a,b);
assert.equal(d.rows.find(x=>x.category==='Cache-Control public on media response').baseline,2);
assert.equal(d.rows.find(x=>x.category==='Cache-Control public on media response').comparison,0);
assert.equal(d.rows.find(x=>x.category==='Observed image/media response').baselinePer1000Delivery,500);
assert.equal(d.reviewCandidates[0].baseline,2);assert.equal(d.reviewCandidates[0].comparison,0);
for(const x of [r,d]){
 const str=JSON.stringify(x);
 for(const forbidden of [SECRET,'secret-archive','2026-10-24','img-01','PRIVATE.jpg','Bearer','session=','attachment;','X-Amz-Signature'])assert(!str.includes(forbidden),forbidden);
 assert(/not proof|not establish|not a security/.test(str.toLowerCase()),'missing caution');
}
const e0=DP.compare({log:{entries:[]}},{log:{entries:[]}});
assert.equal(e0.rows[0].baselinePer1000Delivery,null);
assert.throws(()=>DP.audit({log:{entries:Array(12001).fill(null)}}),/limit/);
assert.throws(()=>DP.audit({}),/log.entries/);
const noLeak=DP.audit({log:{entries:[e(SECRET+'.jpg',{respHeaders:[hd('Cache-Control','public,max-age='+SECRET)]})]}});
assert(!JSON.stringify(noLeak).includes(SECRET));
console.log('PASS v7.4: media delivery posture, signed/cache review, 403 and redirect clues, stage/dimension scopes, strict redaction');
