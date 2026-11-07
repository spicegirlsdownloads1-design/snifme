'use strict';
const assert=require('node:assert/strict');
const A=require('../har_access_matrix.js');
const SECRET='PRIVATE_DOWNLOAD_GRANT_SHOULD_NOT_SURVIVE_OUTPUT';
const H=(name,value)=>({name,value});
function e(path,{status=200,mime='image/jpeg',reqHeaders=[],respHeaders=[],missingReq=false,missingResp=false}={}){
 return {startedDateTime:'2026-10-24T12:01:02.000Z',request:{method:'GET',url:'https://secret-site.invalid/'+path+'?SECRET='+SECRET+'&x-amz-signature='+SECRET,headers:missingReq?undefined:reqHeaders,postData:{text:SECRET}},response:{status,headers:missingResp?undefined:respHeaders,content:{mimeType:mime,text:SECRET}},comment:SECRET};
}
const base={log:{entries:[
 e('one.jpg',{reqHeaders:[H('Authorization','Bearer '+SECRET)],respHeaders:[H('Cache-Control','public,max-age=3600')]}),
 e('two.webp',{reqHeaders:[H('Cookie','session='+SECRET)],respHeaders:[H('Cache-Control','private')]}),
 e('three.jpg',{status:403,mime:'text/html',missingReq:true,missingResp:true}),
 e('four.jpg',{status:302,mime:'text/html',reqHeaders:[H('Authorization','Bearer '+SECRET)],respHeaders:[H('Location','https://site.invalid/?sig='+SECRET)]}),
 e('five.jpg',{status:206,respHeaders:[H('Cache-Control','no-cache')]}),
 e('six.zip',{mime:'application/zip',reqHeaders:[H('Authorization','Bearer '+SECRET)],respHeaders:[H('Content-Disposition','attachment; filename="'+SECRET+'.zip"'),H('Cache-Control','no-store')]}),
 e('style.css',{mime:'text/css'}),
 {request:{url:'ftp://site.invalid/file.jpg'},response:{status:200,content:{mimeType:'image/jpeg'}}},
 {request:{method:'GET',url:'https://secret-site.invalid/no.jpg'}}
]}};
const report=A.audit(base);const get=(auth,outcome)=>report.authOutcomes.find(x=>x.authentication===auth&&x.outcome===outcome).count;
assert.equal(report.coverage.totalEntries,9);
assert.equal(report.coverage.inspectedHttp,7);
assert.equal(report.coverage.excludedEntries,2);
assert.equal(report.coverage.deliveryRelevant,6);
assert.equal(report.coverage.mediaMime2xx,3);
assert.equal(report.coverage.attachment2xx,1);
// Signed parameter present on every eligible request: authorization+signing counts as Mixed.
assert.equal(get('Mixed authentication indicators','Delivered media or attachment (2xx)'),3);
assert.equal(get('Signed URL parameter names','Denied media-like request (401/403)'),1);
assert.equal(get('Mixed authentication indicators','Media-like redirect (3xx)'),1);
assert.equal(get('Signed URL parameter names','Partial media/attachment (206)'),1);
assert.equal(report.authOutcomes.reduce((n,x)=>n+x.count,0),6);
assert.equal(report.authCache.reduce((n,x)=>n+x.count,0),6);
assert.equal(report.coverage.missingRequestHeaders,1);
let str=JSON.stringify(report);
for(const p of [SECRET,'secret-site.invalid','2026-10-24','one.jpg','Bearer ', 'session=','filename=', 'Location', 'X-Amz-Signature'])assert(!str.includes(p),p);
assert(!('url' in report));
const b={log:{entries:[e('unknown.jpg',{status:200,mime:'text/html'}),e('other.jpg',{status:401,mime:'text/html'})]}};
const compare=A.compare(base,b,{sameSite:'yes',sameActions:'yes',sameAccount:'yes',sameScope:'yes',sameBrowserCoverage:'yes'});
assert.equal(compare.readiness,'Context or coverage review needed');
assert.equal(compare.authOutcomes.reduce((n,x)=>n+x.baseline,0),6);
assert.equal(compare.authOutcomes.reduce((n,x)=>n+x.comparison,0),1);
assert.equal(compare.authOutcomes.find(x=>x.baseline===3).baselinePer1000Delivery,500);
assert.equal(A.compare(base,b,{sameSite:'no'}).readiness,'Not comparable');
assert.equal(A.compare({log:{entries:[]}},{log:{entries:[]}}).authOutcomes[0].comparisonPer1000Delivery,null);
for(const p of [SECRET,'secret-site.invalid','2026-10-24','one.jpg','Bearer ', 'session=','filename=', 'X-Amz-Signature'])assert(!JSON.stringify(compare).includes(p),p);
assert.throws(()=>A.audit({log:{entries:Array(12001).fill({})}}),/limit/);
assert.throws(()=>A.audit({}),/log.entries/);
// Chrome sanitised HAR can have empty header arrays: absence of indicators is not an anonymous session.
const clean={log:{entries:[{request:{url:'https://test.invalid/file.webp',headers:[]},response:{status:200,headers:[],content:{mimeType:'image/webp'}}}]}};
assert.equal(A.audit(clean).authOutcomes.find(x=>x.count===1).authentication,'No authentication indicator observed');
const unknown={log:{entries:[{request:{url:'https://test.invalid/file.webp'},response:{status:200,content:{mimeType:'image/webp'}}}]}};
assert.equal(A.audit(unknown).authOutcomes.find(x=>x.count===1).authentication,'Request headers unavailable');
// Never claim a returned HTML error page at .jpg path is successful delivery.
assert.equal(A.audit({log:{entries:[e('fake.jpg',{status:200,mime:'text/html'})]}}).coverage.deliveryRelevant,0);
console.log('PASS v7.5: access observation matrix, outcome/cache differentiation, missing headers, context, strict privacy');
