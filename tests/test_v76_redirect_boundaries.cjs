'use strict';
const assert=require('node:assert/strict');
const B=require('../har_redirect_boundaries.js');
const SECRET='DO_NOT_EXPORT_SIGNED_VALUE_NEVER';
const hdr=(name,value)=>({name,value});
const entry=(url,status,{loc,mime='text/html',reqHeaders=[],respHeaders=[],missingReqHeaders=false,redirectURL='',method='GET'}={})=>({
 request:{method,url,headers:missingReqHeaders?undefined:reqHeaders,postData:{text:'private:'+SECRET}},
 response:{status,headers:[...(loc===undefined?[]:[hdr('Location',loc)]),...respHeaders],redirectURL,content:{mimeType:mime,text:SECRET}},
 startedDateTime:'2026-10-24T11:00:00.123Z',comment:SECRET
});
const src='https://dam.example.invalid';const cdn='https://cdn.example.invalid';
const base={log:{entries:[
 entry(src+'/start',302,{loc:cdn+'/asset.jpg?x-amz-signature='+SECRET}),
 entry(cdn+'/asset.jpg?x-amz-signature='+SECRET,200,{mime:'image/jpeg',reqHeaders:[hdr('Authorization','Bearer '+SECRET),hdr('Cookie','sid='+SECRET)],respHeaders:[hdr('Cache-Control','public')]}),
 entry(src+'/same',303,{loc:'/next'}),entry(src+'/next',200),
 entry(src+'/missing',302,{loc:cdn+'/uncaptured.zip?token='+SECRET}),
 entry(src+'/ambiguous',307,{loc:cdn+'/duplicate'}),entry(cdn+'/duplicate',200),entry(cdn+'/duplicate',200),
 entry('https://secure.example.invalid/leave',302,{loc:'http://cdn.example.invalid/file.webp'}),
 entry('http://cdn.example.invalid/file.webp',206,{mime:'image/webp',missingReqHeaders:true}),
 entry(src+'/bad',302,{loc:'javascript:alert(1)'}),entry(src+'/none',302),
 entry(src+'/denied',302,{loc:cdn+'/no-access.jpg'}),entry(cdn+'/no-access.jpg',403),
 entry(src+'/attachment',302,{loc:cdn+'/export?token='+SECRET}),entry(cdn+'/export?token='+SECRET,200,{mime:'application/zip',respHeaders:[hdr('Content-Disposition','attachment; filename="'+SECRET+'.zip"')]}),
 entry('ftp://other.invalid/invisible',302,{loc:cdn+'/somewhere'})
]}};
const r=B.audit(base);const get=c=>r.boundaries.find(x=>x.category===c).count;const signal=c=>r.indicators.find(x=>x.category===c).count;
assert.equal(r.coverage.totalEntries,17);assert.equal(r.coverage.inspectedHttp,16);
assert.equal(r.coverage.redirectResponses,9);
assert.equal(r.coverage.redirectLocations,8);
assert.equal(r.coverage.uniquelyMatched,5);
assert.equal(r.coverage.matchedCrossOrigin,4);
assert.equal(get('Same-origin redirect with unique observed target'),1);
assert.equal(get('Cross-origin redirect with unique observed target'),4);
assert.equal(get('Redirect target not captured'),1);
assert.equal(get('Ambiguous repeated target requests'),1);
assert.equal(get('Unsupported or invalid redirect destination'),1);
assert.equal(get('Redirect without destination metadata'),1);
assert.equal(signal('Cross-origin target: Authorization or API-key header name present'),1);
assert.equal(signal('Cross-origin target: Cookie header name present'),1);
assert.equal(signal('Cross-origin target: signing query-parameter name present'),2);
assert.equal(signal('Cross-origin target: request headers unavailable'),1);
assert.equal(signal('Cross-origin HTTPS-to-HTTP redirect destination'),1);
assert.equal(signal('Cross-origin target: MIME-confirmed 2xx media response'),2);
assert.equal(signal('Cross-origin target: 2xx attachment response'),1);
assert.equal(signal('Cross-origin target: 401/403 denial response'),1);
const forbidden=[SECRET,'dam.example.invalid','cdn.example.invalid','2026-10-24','asset.jpg','filename=', 'Bearer','x-amz-signature','sid='];
for(const word of forbidden)assert(!JSON.stringify(r).includes(word),word);
assert.equal(r.boundaries.reduce((n,x)=>n+x.count,0),9);
const a=JSON.parse(JSON.stringify(base));const b=JSON.parse(JSON.stringify(base));
const cmp=B.compare(a,b,{sameSite:'yes',sameAccount:'yes',sameActions:'yes',sameScope:'yes',sameBrowserCoverage:'yes'});
assert.equal(cmp.readiness,'Context or coverage review needed'); // only 9 redirects
assert.equal(cmp.boundaries.reduce((n,x)=>n+x.baseline,0),9);
assert.equal(cmp.boundaries[1].baselinePer1000Redirect,444.44);
assert.equal(B.compare(a,b,{sameSite:'no'}).readiness,'Not comparable');
for(const word of forbidden)assert(!JSON.stringify(cmp).includes(word),word);
assert.throws(()=>B.audit({}),/log.entries/);
assert.throws(()=>B.audit({log:{entries:Array(12001).fill({})}}),/limit/);
// Redirect without target must not invent a match from proximity.
const unlinked=B.audit({log:{entries:[entry(src+'/start',302,{loc:cdn+'/not-here'}),entry(cdn+'/another',200,{mime:'image/jpeg'})]}});
assert.equal(unlinked.coverage.uniquelyMatched,0);
// Earlier requests with the same URL cannot be mistakenly linked.
const earlier=B.audit({log:{entries:[entry(cdn+'/first',200),entry(src+'/redirect',301,{loc:cdn+'/first'})]}});
assert.equal(earlier.coverage.uniquelyMatched,0);
// Response.redirectURL serves as fallback when Location not in headers.
const fallback=B.audit({log:{entries:[entry(src+'/r',302,{redirectURL:cdn+'/fallback'}),entry(cdn+'/fallback',200,{mime:'image/jpeg'})]}});
assert.equal(fallback.coverage.uniquelyMatched,1);
// Empty but present request headers are not evidence of anonymous access.
const empty=B.audit({log:{entries:[entry(src+'/r',302,{loc:cdn+'/h'}),entry(cdn+'/h',200,{mime:'image/jpeg'})]}});
assert.equal(empty.indicators.find(x=>x.category.includes('no authentication')).count,1);
// Duplicate destination events remain ambiguous and never double-counted.
console.log('PASS v7.6: explicit redirect boundary, media signals, same-origin, ambiguity, HTTP downgrade and privacy');
