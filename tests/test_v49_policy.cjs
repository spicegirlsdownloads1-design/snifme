'use strict';
const assert=require('node:assert/strict');
const P=require('../dam_delivery_policy.js');
const secret='secret-link-token-DO-NOT-RETAIN';
const rec={origin:'https://gallery.example',requests:[
 {url:`https://cdn.example.org/preview/12.jpg?token=${secret}`,type:'image',mime:'image/jpeg',status:200,cacheScope:'private',cacheMaxAge:120},
 {url:`https://cdn.example.org/master/12.jpg?X-Amz-Signature=${secret}`,type:'image',mime:'image/jpeg',status:200,signedQuery:true,cacheScope:'public',cacheMaxAge:86400},
 {url:`https://files.example.org/download/12.jpg?key=${secret}`,type:'other',mime:'application/octet-stream',status:200,attachmentDisposition:true,cacheNoStore:true},
 {url:'https://cdn.example.org/original/13.jpg',type:'image',mime:'image/jpeg',status:403,cacheScope:'public',cacheMaxAge:86400},
 {url:'https://cdn.example.org/rendition/1.jpeg',type:'image',mime:'image/jpeg',status:200,cacheScope:'public',cacheMaxAge:3600}
 ],responses:[{fields:[{path:'$.asset.originalUrl',type:'string'},{path:'$.asset.license',type:'string'},{path:'$.asset.previewUrl',type:'string'},{path:'$.asset.downloadUrl',type:'string'},{path:'$.asset.assetId',type:'string'}]}]};
const result=P.analyze(rec);
assert.equal(result.summary.mediaRequests,5);
assert.equal(result.summary.received,4);
assert.equal(result.summary.restricted,1);
assert.equal(result.summary.attachments,1);
assert.equal(result.summary.signed,1);
assert.equal(result.summary.publicLongCache,1);
assert(result.rows.some(x=>x.representation==='Original/master-labelled image'&&x.status==='Delivered in current browser session'));
assert(result.rows.some(x=>x.representation==='Download attachment delivery'&&x.cachePolicy==='No-store observed'));
assert(result.rows.some(x=>x.status==='Restricted response (401/403)'));
assert.equal(result.metadata.length,5);
assert(!JSON.stringify(result).includes(secret));
assert(!JSON.stringify(result).includes('/master/'));
assert(!JSON.stringify(result).includes('12.jpg'));
assert(!JSON.stringify(result).includes('originalUrl'));
assert(!result.caveat.includes('anonymous access confirmed'));
assert.equal(P.analyze({requests:[]}).summary.mediaRequests,0);
assert.equal(P.pathClue('not-a-url'),'unspecified');
assert.equal(P.statusOf({status:200}),'Delivered in current browser session');
assert.equal(P.statusOf({status:403}),'Restricted response (401/403)');
const truncated=P.analyze({requests:[],counters:{requestsDropped:4}});
assert.equal(truncated.summary.truncated,true);
console.log('PASS v4.9 permission policy: delivery states, signed & cache evidence, metadata names redacted, no URLs exposed');
