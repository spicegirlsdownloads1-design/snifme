'use strict';
const assert=require('node:assert/strict');
const Generic=require('../generic_intelligence.js');
const secret='SECRET_AUTH_VALUE_DO_NOT_EXPORT_406',site='custom-internal.example.test';
const record={origin:`https://${site}`,endedAt:'2026-10-24T12:12:00.000Z',downloadObserverEverEnabled:true,
 requests:[
  {url:`https://${site}/home?token=${secret}`,method:'GET',type:'main_frame',mime:'text/html',status:200},
  {url:`https://${site}/javascript/embedded.js?access_token=${secret}`,method:'GET',type:'script',mime:'application/javascript',status:200},
  {url:`https://${site}/whatever-custom-api`,method:'POST',type:'xmlhttprequest',mime:'application/json',status:202},
  {url:`https://${site}/image/raw.jpg?Signature=${secret}`,method:'GET',type:'image',mime:'image/jpeg',status:206,signedQuery:true,cacheScope:'public',cacheMaxAge:90000},
  {url:`https://cdn.private-test.example/data?token=${secret}`,method:'GET',type:'image',mime:'image/jpeg',status:302,authQueryClasses:['credential query present']},
  {url:`https://${site}/file`,method:'GET',type:'other',mime:'application/octet-stream',status:200,attachmentDisposition:true},
  {url:`https://${site}/restricted`,method:'GET',type:'xmlhttprequest',status:403},
  {url:`https://${site}/limit`,method:'GET',type:'xmlhttprequest',status:429},
  {url:`https://${site}/error`,method:'GET',type:'other',status:500,error:`error ${secret}`}
 ],
 downloadEvents:[
  {stage:'headers',headerIndicators:['Authorization header present'],headerValue:secret},
  {stage:'redirect',redirectHost:'cdn.private-test.example',url:secret},
  {stage:'download-state',downloadStatus:'complete',downloadRef:'DL123456'},
  {stage:'download-state',downloadStatus:'interrupted',error:secret}
 ],
 responses:[{fields:[{name:secret}]}],configs:[{value:secret}],findings:[{masked:'********',raw:secret}],
 counters:{requestsDropped:5,assetsDropped:2}
};
const before=JSON.stringify(record);
const result=Generic.analyze(record);
assert.equal(JSON.stringify(record),before,'source records must not be mutated');
assert.equal(result.overview.observedRequests,9);
assert.equal(result.overview.sameOriginRequests,8);
assert.equal(result.overview.externalOriginRequests,1);
assert.equal(result.overview.droppedEvents,7);
const value=k=>result.rows.find(r=>r.category===k)?.count;
for(const [k,n] of [
 ['Documents',1],['Scripts and styles',1],['API writes',1],['Image and media responses',2],
 ['HTTP 202 accepted',1],['HTTP 206 partial',1],['HTTP redirects',1],['HTTP 401/403',1],
 ['HTTP 429',1],['HTTP failures',1],['Signed-query indicators',1],['Credential-query indicators',1],
 ['Attachment responses',1],['Long public-cache responses',1],['Request authentication indicators',1],
 ['Redirect lifecycle steps',1],['Browser downloads completed',1],['Browser downloads interrupted',1],
 ['JSON response shapes',1],['Public configuration clues',1],['Masked secret indicators',1]
])assert.equal(value(k),n,k);
assert.equal(result.platformIdentificationRequired,false);
assert.equal(result.noAdditionalRequests,true);
assert.equal(result.credentialsRetained,false);
assert(result.warnings.some(w=>/dropped/.test(w)));
const exported=JSON.stringify(result);
for(const forbidden of [secret,site,'cdn.private-test.example','whatever-custom-api','DL123456','raw.jpg','Bearer']){
 assert(!exported.includes(forbidden),'report leaked: '+forbidden);
}
assert(result.rows.every(x=>Number.isSafeInteger(x.count)&&x.count>=0));

const unknown=Generic.analyze({origin:'https://surprise.example',requests:[{url:'https://surprise.example/',type:'other',status:200}],endedAt:'2026-10-24T00:00:00Z'});
assert.equal(unknown.overview.observedRequests,1,'unknown platform must work');
assert.equal(unknown.platformIdentificationRequired,false);
assert(unknown.warnings.some(w=>/observer/.test(w)));

const bad=Generic.analyze({origin:'data:text/plain,x',requests:[{url:'not a URL',type:'other',status:200}],downloadEvents:[{stage:'headers',headerIndicators:[secret]}]});
assert.equal(bad.overview.externalOriginRequests,0);
assert.equal(bad.rows.find(x=>x.category==='Request authentication indicators').count,0,'unknown strings ignored');
assert(bad.warnings.some(w=>/origin/.test(w)));
assert(!JSON.stringify(bad).includes(secret));

// Bounded source arrays cannot force unbounded output or expose raw values.
const cap=Generic.analyze({origin:'https://example.test',requests:Array(3020).fill({url:'https://example.test/',status:200}),
 downloadEvents:Array(3020).fill({stage:'redirect',redirectHost:'secret.example'})});
assert.equal(cap.overview.observedRequests,3000);
assert.equal(cap.overview.observerEvents,3000);
assert.equal(cap.overview.sampleCapped,true);
assert(cap.warnings.some(w=>/cap reached/.test(w)));
assert.equal(cap.rows.length,result.rows.length,'fixed output categories');
console.log('PASS v7.10 generic unknown-site intelligence, fixed labels, observed-only counters, privacy and cap limits');
