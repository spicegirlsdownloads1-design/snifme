'use strict';
const assert=require('node:assert/strict');
require('../scanner.js');
const {analyze}=require('../generic_boundary_review.js');
const privateHost='private-cdn.company.invalid',privateKey='token-super-secret-should-not-export';
const sample='https://'+privateHost+'/media/image.jpg?X-Amz-Signature='+privateKey+'&X-Amz-Expires=100000&X-Amz-Credential='+privateKey;
const safe=globalThis.THI.urlInfo(sample);
assert.equal(safe.signatureKeyPresent,true);
assert.equal(safe.signedValidityWindow,'24h-to-7d');
assert(!safe.url.includes(privateKey));
for(const [seconds,expected] of [['900','up-to-15m'],['901','15m-to-24h'],['86399','15m-to-24h'],['86400','24h-to-7d'],['604800','24h-to-7d'],['604801','over-7d'],['0','invalid-declaration'],['-1','invalid-declaration'],['123abc','invalid-declaration']]){
 const result=globalThis.THI.signingEvidence('https://'+privateHost+'/pic?x-amz-signature='+privateKey+'&X-Amz-Expires='+seconds);
 assert.equal(result.signedValidityWindow,expected,seconds);
}
assert.equal(globalThis.THI.signingEvidence('https://some.tld/pic?token='+privateKey+'&expires=9999999').signatureKeyPresent,false);
assert.equal(globalThis.THI.signingEvidence('https://some.tld/pic?x-goog-signature='+privateKey+'&x-goog-expires=45').signedValidityWindow,'up-to-15m');
assert.equal(globalThis.THI.signingEvidence('https://some.tld/pic?signature='+privateKey+'&expires=9999999').signedValidityWindow,'unknown');
const row=(report,name)=>report.rows.find(r=>r.category===name)?.count;
const record={origin:'https://shop.company.invalid',endedAt:'2026-10-25T01:00:00.000Z',downloadObserverEverEnabled:true,
 requests:[
  {url:safe.url,status:200,signatureKeyPresent:true,signedValidityWindow:'24h-to-7d',signedQuery:true,cacheScope:'public',cacheMaxAge:86400,cacheNoStore:false,mime:'image/jpeg',type:'image',attachmentDisposition:true,secret:privateKey},
  {url:'https://shop.company.invalid/api',method:'POST',type:'xmlhttprequest',status:202},
  {url:'https://shop.company.invalid/range',status:206},
  {url:'https://shop.company.invalid/forbidden',status:403},
  {url:'https://shop.company.invalid/error',status:503},
  {url:'https://shop.company.invalid/image',status:200,signedQuery:true}, // legacy unclassified
  {url:'https://shop.company.invalid/?token='+privateKey,status:200,signedQuery:true,signatureKeyPresent:false}, // explicitly not a signature
  {url:'https://shop.company.invalid/nowhere',status:200,signatureKeyPresent:true,signedValidityWindow:'unknown',cacheScope:'private'},
 ],downloadEvents:[
  {stage:'redirect',host:'shop.company.invalid',redirectHost:privateHost,signedIndicators:['URL signing fields'],private:privateKey},
  {stage:'redirect',host:privateHost,redirectHost:privateHost,signedIndicators:[]},
  {stage:'download-start',downloadRef:'DL1',raw:privateKey}
 ],counters:{requestsDropped:3},downloadEventsDropped:1,secret:privateKey};
const before=JSON.stringify(record),report=analyze(record);
assert.equal(before,JSON.stringify(record),'must not mutate input');
assert.equal(row(report,'Explicit URL-signing fields'),2);
assert.equal(row(report,'Signed delivery to another origin'),1);
assert.equal(row(report,'Signed response with public cache directive'),1);
assert.equal(row(report,'Signed response with public cache at least 24 hours'),1);
assert.equal(row(report,'Declared signing window 24 hours to 7 days'),1);
assert.equal(row(report,'Signed request with no classified expiry'),1);
assert.equal(row(report,'Signed-query metadata unavailable'),1);
assert.equal(row(report,'Cross-origin redirect step'),1);
assert.equal(row(report,'Signed redirect step'),1);
assert.equal(row(report,'Attachment delivery response'),1);
assert.equal(row(report,'API-like write accepted asynchronously'),1);
assert.equal(row(report,'Partial-content response'),1);
assert.equal(row(report,'Access-denied response'),1);
assert.equal(row(report,'Server-error response'),1);
assert.equal(report.overview.droppedObservations,4);
const out=JSON.stringify(report);
for(const value of [privateHost,privateKey,'DL1','shop.company.invalid','/api','X-Amz-Signature','http://','https://','signatureKeyPresent','requestId'])assert(!out.includes(value),`privacy leak ${value}`);
assert.equal(report.noAdditionalRequests,true);
assert.equal(report.platformIdentificationRequired,false);
assert.equal(report.credentialValuesRetained,false);
assert.equal(row(analyze({requests:[{signedQuery:true,signatureKeyPresent:false,url:sample}]}),'Explicit URL-signing fields'),0);
const capped=analyze({requests:Array(3100).fill({signatureKeyPresent:true,signedValidityWindow:'up-to-15m'}),downloadEvents:Array(3100).fill({stage:'download-start'})});
assert.equal(capped.overview.inspectedHTTP,3000);
assert.equal(capped.overview.sampleCapped,true);
assert.equal(row(capped,'Explicit URL-signing fields'),3000);
for(const x of [null,{}, {requests:[null,'invalid',{},3],downloadEvents:[null]}])assert(analyze(x).rows.every(r=>Number.isSafeInteger(r.count)));
console.log('PASS v7.13 universal boundary review, signed protocol bands, no false signature promotion, hard redaction and limits');
