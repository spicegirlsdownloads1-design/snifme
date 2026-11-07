'use strict';
const assert=require('node:assert/strict');
const N=require('../har_image_negotiation.js');
const secret='SENSITIVE-SIGNING-MATERIAL-91b8';
const header=(name,value)=>({name,value});
function item(path,status,{method='GET',request=[],response=[],mime='image/webp',missingReq=false,missingRes=false}={}){
  return {startedDateTime:'2026-10-24T15:30:00.000Z',
    request:{method,url:'https://private-gallery.invalid/'+path+'?X-Amz-Signature='+secret,
      ...(missingReq?{}:{headers:[...request,header('Cookie','auth='+secret)]}),postData:{text:secret}},
    response:{status,...(missingRes?{}:{headers:[...response,header('Set-Cookie','secret='+secret)]}),content:{mimeType:mime,text:secret}}};
}
const h={log:{entries:[
 item('one.avif',200,{request:[header('Accept','image/avif,image/webp;q=0.8,image/*;q=0.6'),header('Sec-CH-Width','750'),header('Accept-Encoding','gzip,br'),header('Save-Data','on')],response:[header('Content-Type','image/avif'),header('Vary','Accept,Sec-CH-Width'),header('Accept-CH','Sec-CH-Width, Sec-CH-DPR'),header('Content-DPR','1.5')]}),
 item('two.webp',200,{request:[header('Accept','image/webp,image/jpeg'),header('Sec-CH-DPR','2')],response:[header('Content-Type','image/webp'),header('Vary','Accept-Encoding'),header('Content-Encoding','br')]}),
 item('three.jpg',206,{request:[header('Accept','image/jpeg,image/avif')],response:[header('Content-Type','image/jpeg'),header('Vary','Accept-Language'),header('Content-Encoding','gzip')]}),
 item('revalidate.avif',304,{request:[header('Accept','image/avif')],response:[header('Content-Type','image/avif'),header('Vary','*')]}),
 item('x.svg',200,{request:[header('Accept','image/*')],response:[header('Content-Type','image/svg+xml'),header('Content-Encoding','zstd')]}),
 item('no-content-type.jpg',200,{mime:'application/octet-stream',response:[header('Content-Encoding','identity')]}),
 item('missing.webp',200,{missingReq:true,missingRes:true,mime:'image/webp'}),
 item('negotiate.gif',200,{request:[header('Accept','*/*')],response:[header('Vary','Cookie, Authorization'),header('Content-Type','image/gif')]}),
 item('write',200,{method:'POST',response:[header('Content-Type','image/jpeg')]}),
 {request:{url:'file:///private.jpg',method:'GET',headers:[]},response:{status:200,headers:[],content:{mimeType:'image/jpeg'}}}
]}};
const res=N.audit(h),get=k=>res.signals.find(v=>v.category===k)?.count;
assert.equal(res.coverage.totalEntries,10);
assert.equal(res.coverage.inspectedHttp,9);
assert.equal(res.coverage.imageResponses,6);
assert.equal(res.coverage.media304Clues,1);
assert.equal(get('Observed image/avif representation (200/206)'),1);
assert.equal(get('Observed image/webp representation (200/206)'),2);
assert.equal(get('Observed image/jpeg representation (200/206)'),1);
assert.equal(get('Observed image/svg+xml representation (200/206)'),1);
assert.equal(get('Observed image/gif representation (200/206)'),1);
assert.equal(get('Observed image/avif response and request advertises image/avif'),1);
assert.equal(get('Response Vary declares Accept'),1);
assert.equal(get('Response Vary declares client image hints'),1);
assert.equal(get('Response Vary declares Accept-Encoding'),1);
assert.equal(get('Response Vary: *'),1);
assert.equal(get('Response Vary declares Cookie or Authorization'),1);
assert.equal(get('Request image sizing client hint visible'),2);
assert.equal(get('Response Accept-CH asks for image sizing hints'),1);
assert.equal(get('Media response with no visible Accept request header'),1);
assert.equal(get('Image-suffix request without a confirmed delivered image MIME'),1);
assert.equal(get('Request header array unavailable'),1);
assert.equal(get('Response header array unavailable'),1);
assert.equal(get('Response Content-Encoding zstd'),1);
assert.equal(get('Media-related HTTP 304 (no representation body proven)'),1);
for(const bad of [secret,'private-gallery.invalid','one.avif','no-content-type.jpg','2026-10-24T15:30','auth='+secret,'750','1.5']){
 assert(!JSON.stringify(res).includes(bad),'Report leaks '+bad);
}
const options={sameSite:'yes',sameActions:'yes',sameAccount:'yes',sameScope:'yes',sameBrowserCoverage:'yes'};
const cmp=N.compare(h,h,options);
assert.equal(cmp.readiness,'Context declared comparable');
assert.equal(N.compare(h,h,{sameSite:'no'}).readiness,'Not comparable');
assert.equal(N.compare(h,h,{sameSite:'yes'}).readiness,'Context or coverage review needed');
assert(cmp.signals.some(x=>x.category==='Observed image/avif representation (200/206)'&&x.baseline===1&&x.comparison===1));
for(const bad of [secret,'private-gallery.invalid','one.avif','2026-10-24'])assert(!JSON.stringify(cmp).includes(bad),'Comparison leaks '+bad);
assert.throws(()=>N.audit(null),/log.entries/);
assert.throws(()=>N.audit({log:{entries:Array(12001).fill({})}}),/12,000-entry limit/);
const only304=N.audit({log:{entries:[item('a.avif',304,{mime:'image/avif'})]}});
assert.equal(only304.coverage.imageResponses,0);
assert.equal(only304.coverage.media304Clues,1);
console.log('PASS v7.9 image negotiation: formats, 304, hints, compare and privacy');
