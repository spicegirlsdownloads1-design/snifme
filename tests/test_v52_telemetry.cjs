'use strict';
const assert=require('node:assert/strict');
const T=require('../dam_telemetry.js');
const D=require('../download_observer.js');
const secret='SECRET_NEVER_SAVE_2026',token='ACCESS_NEVER_SAVE_2026';
const parent='00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01';
const headers=[{name:'Authorization',value:'AWS4-HMAC-SHA256 Credential='+secret+'/20261024/eu-west-2/s3/aws4_request, Signature='+token},
 {name:'traceparent',value:parent},{name:'tracestate',value:'tenant='+secret},
 {name:'CF-Ray',value:secret},{name:'x-amz-cf-id',value:secret},{name:'x-request-id',value:secret}];
const h=T.headerEvidence(headers,'tab-12-capture-1');
assert.equal(h.authentication,'AWS SigV4');assert.equal(h.signatureScheme,'AWS SigV4');
assert.equal(h.traceRef,'Trace 1');assert.equal(h.traceSampled,true);assert.equal(h.tracestatePresent,true);
assert.equal(h.cdnEvidence.length,2);assert.equal(h.requestIdHeaderPresent,true);
assert.equal(T.headerEvidence(headers,'tab-12-capture-1').traceRef,'Trace 1');
assert.equal(T.headerEvidence(headers,'tab-12-capture-2').traceRef,'Trace 1');
assert.equal(T.parseTrace('00-'+'0'.repeat(32)+'-00f067aa0ba902b7-01'),null);
const r=T.responseEvidence([{name:'Cache-Control',value:'private, max-age=240'},
 {name:'Content-Length',value:'12450'},{name:'ETag',value:secret},{name:'Last-Modified',value:token}]);
assert.deepEqual(r,{contentLengthBytes:12450,cachePolicy:'private',cacheMaxAgeSeconds:240,etagPresent:true,lastModifiedPresent:true});
assert.equal(T.errorCategory('NETWORK_TIMEOUT'),'network');assert.equal(T.errorCategory('USER_CANCELED'),'user action');
const progress=T.sizeFacts({bytesReceived:125,totalBytes:500,canResume:true});assert.equal(progress.percent,25);
const request={tabId:12,url:'https://dam.example/api/download?token='+secret,method:'POST',requestId:'request-1',timeStamp:Date.now(),type:'xmlhttprequest'};
const before=D.classify('headers',{...request,requestHeaders:headers},'tab-12-capture-1');
assert.equal(before.traceRef,'Trace 1');
const reply=D.classify('response-headers',{...request,responseHeaders:[{name:'Content-Length',value:'500'},{name:'Cache-Control',value:'public, max-age=60'},
 {name:'CF-Ray',value:secret},{name:'Content-Disposition',value:'attachment; filename="'+secret+'.jpg"'}]},'tab-12-capture-1');
assert.equal(reply.cachePolicy,'public');assert.equal(reply.contentLengthBytes,500);assert.equal(reply.attachment,true);
const dl=D.download('created',{id:91,url:'https://dam.example/?token='+secret,referrer:'https://dam.example/',totalBytes:500,bytesReceived:125,filename:'C:/'+secret+'.jpg'});
assert.equal(dl.percent,25);
const rows=D.summaries([before,reply,dl]);assert(rows.some(x=>x.trace==='Trace 1'));
const cloud=T.cloudEvents([before,reply,dl,{stage:'download-state',at:new Date().toISOString(),downloadStatus:'interrupted',errorCategory:'server'}], 'capture-a');
assert.equal(cloud.length,4);assert.equal(cloud[0].specversion,'1.0');assert.equal(cloud[0].source,'/trufflehog/local-download-observer');
for(const hidden of [secret,token,'tenant=','Signature=','filename=',parent,'C:/']){
  assert(!JSON.stringify({h,r,progress,before,reply,dl,rows,cloud}).includes(hidden),'leaked '+hidden);
}
console.log('PASS v5.2 passive tracing, CDN/cache, download sizes, local CloudEvents and strict redaction');
