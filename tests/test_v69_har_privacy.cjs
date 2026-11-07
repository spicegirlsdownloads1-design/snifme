'use strict';
const assert=require('node:assert/strict');
const P=require('../har_privacy.js');
const rawSecret='VERY_PRIVATE_SAMPLE_TOKEN_491828';
const host='archive-demo-private.example.test';
const payload={log:{version:'1.2',pages:[{id:'sensitive-page',title:rawSecret}],entries:[
 {request:{method:'POST',url:`https://user:${rawSecret}@${host}/download?Signature=${rawSecret}&page=2`,
  headers:[{name:'Authorization',value:'Bearer '+rawSecret},{name:'Cookie',value:'SESSION='+rawSecret},
   {name:'traceparent',value:rawSecret},{name:'X-Request-ID',value:rawSecret}],
  cookies:[{name:'sid',value:rawSecret}],queryString:[{name:'Signature',value:rawSecret}],
  postData:{mimeType:'application/json',text:'{"secret":"'+rawSecret+'"}'}},
  response:{status:302,headers:[{name:'Location',value:`https://${host}/images/file?token=${rawSecret}`},
   {name:'Set-Cookie',value:'sid='+rawSecret}],content:{text:rawSecret}}},
 {request:{method:'GET',url:'https://cdn.example.test/photo.jpg',headers:[]},response:{status:200,headers:[],content:{}}}
]}};
const r=P.audit(payload);
assert.equal(r.format,'trufflehog-har-privacy-preflight');
assert.equal(r.coverage.entries,2);
assert.equal(r.coverage.pages,1);
const map=Object.fromEntries(r.rows.map(x=>[x.category,x.count]));
assert.equal(map['Authentication-related header names'],1);
assert.equal(map['Browser cookie field evidence'],1);
assert.equal(map['URLs with query parameters'],1);
assert.equal(map['Credential-like query parameter names'],1);
assert.equal(map['URL-embedded username/password'],1);
assert.equal(map['Request body / form values present'],1);
assert.equal(map['Response body text present'],1);
assert.equal(map['Redirect destination headers'],1);
assert.equal(map['Trace and request-correlation header names'],1);
assert.equal(map['HAR page titles / navigation metadata'],1);
const out=JSON.stringify(r);
for(const secret of [rawSecret,host,'sensitive-page','cdn.example.test','/download','/images/file','Authorization','Set-Cookie','traceparent','Location','Bearer','Signature']){
 assert(!out.includes(secret),`Leaked source indicator: ${secret}`);
}
assert.deepEqual(Object.keys(r).sort(),['advice','assessment','coverage','format','limitations','noAdditionalRequests','rawValuesRetained','rows','version'].sort());
assert.equal(r.rawValuesRetained,false);
assert.throws(()=>P.audit({}),/valid HAR/);
assert.throws(()=>P.audit({log:{entries:Array(12001).fill({request:{url:'https://a.test'},response:{}})}}),/too many entries/);
const malformed=P.audit({log:{entries:[null,{request:{url:'ftp://x/a'},response:{}},{request:{url:'https://a.test'},response:{}}]}});
assert.equal(malformed.coverage.malformed,1);assert.equal(malformed.coverage.nonHttp,1);
const clean=P.audit({log:{entries:[{request:{url:'https://example.test/',headers:[]},response:{headers:[],content:{}}}]}});
assert.match(clean.assessment,/NOT verified/);
console.log('PASS v6.9 HAR privacy preflight: no identifiers, secret-bearing fields, bounds, invalids, and fixed-label outputs');
