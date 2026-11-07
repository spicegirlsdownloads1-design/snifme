'use strict';
const assert=require('node:assert/strict');
const M=require('../dam_review_matrix.js');
const bad='SIGNATURE_opaque_secret_DO_NOT_LEAK';
const record={origin:'https://private-gallery.example',requests:[
  {url:'https://api.captureweb.net/v1/assets?id=1&access_token='+bad,method:'GET',type:'xmlhttprequest',status:200,authQueryClasses:['legacy-access-token-query']},
  {url:'https://api.captureweb.net/v1/rendition?signature='+bad,type:'image',mime:'image/jpeg',signedQuery:true,status:200,cacheScope:'public',cacheMaxAge:86400},
  {url:'https://private-gallery.example/image/secret.jpg?auth='+bad,type:'image',status:403,cacheScope:'private'},
  {url:'https://private-gallery.example/download?token='+bad,attachmentDisposition:true,status:200,type:'other'},
  {url:'https://res.cloudinary.com/tenant/image/authenticated/a.jpg?signature='+bad,type:'image',signedQuery:true,status:200},
  {url:'https://private-gallery.example/search?q='+bad,type:'xmlhttprequest',status:200,authQueryClasses:['ambiguous-token-query']}
],counters:{requestsDropped:2},rawSecret:bad};
const specialists={profiles:[
 {id:'capture',confidence:'Strong indication'},
 {id:'cloudinary',confidence:'Moderate indication'},
 {id:'resourcespace',confidence:'Weak clue'}]};
const r=M.evaluate(record,specialists);
assert.equal(r.overview.platformCandidates,3);
assert.equal(r.overview.observedRequests,6);
assert.equal(r.overview.retentionDrops,2);
const sw=r.rows.filter(x=>x.scopeKind==='site-wide');
const value=category=>sw.find(x=>x.category===category);
assert.equal(value('API authentication').count,1);
assert.equal(value('Signed delivery').count,2);
assert.equal(value('Media access').count,1);
assert.equal(value('CDN caching').count,1);
assert.equal(value('Download attachment').count,1);
const capture=r.rows.filter(x=>x.scope==='Capture DAM');
assert.equal(capture.find(x=>x.category==='API authentication').count,1);
assert.equal(capture.find(x=>x.category==='CDN caching').count,1);
assert(!capture.some(x=>x.category==='Media access'), 'Never attribute site-wide denial to vendor host');
assert(!r.rows.some(x=>x.scope==='ResourceSpace'), 'Weak schema-only clue never receives attributed network findings');
assert.equal(r.platforms.find(x=>x.platform==='ResourceSpace').observedRequests,0);
assert.equal(r.platforms.find(x=>x.platform==='Cloudinary').observedRequests,1);
assert.equal(r.rows.find(x=>x.category==='Evidence retention').assessment,'Owner review');
const text=JSON.stringify(r);
for(const fragment of [bad,'private-gallery.example','api.captureweb.net','res.cloudinary.com','/v1/rendition','/download?', 'secret.jpg','tenant'])assert(!text.includes(fragment),fragment+' leaked');
assert.match(text,/not proof/i);
assert(!/vulnerability confirmed/i.test(text));
assert.equal(M.evaluate({requests:[]}).rows.filter(x=>x.scopeKind==='site-wide').every(x=>x.assessment==='Not observed in sample'),true);
assert.equal(M.evaluate(null).overview.observedRequests,0);
assert.equal(M.evaluate({requests:[{url:'https://api.captureweb.net/thing',type:'image',status:201,cacheScope:'public',cacheMaxAge:'garbage'}]}, {profiles:[{id:'capture'}]}).overview.reviewItems,0);
const hostile=M.evaluate({requests:[{url:'https://evil.cloudinary.com.evil.tld/media',type:'image',status:200,signedQuery:true,foo:bad}]},{profiles:[{id:'cloudinary'}]});
assert.equal(hostile.platforms[0].observedRequests,0, 'Protect vendor host suffix boundaries');
assert(!JSON.stringify(hostile).includes(bad));
console.log('PASS v6.2 DAM security review: scoped attribution, sample uncertainty, bounded counts, privacy and vendor boundaries');
