'use strict';
const assert=require('node:assert/strict');
const dam=require('../har_dam_workflows.js');
const priv=require('../har_privacy.js');
const secret='SECRET_AWS_ACCESS_7fdabcDoNotExpose';
const entry=(url,method='GET',status=200,h=[],rh=[],other={})=>({
 request:{url,method,headers:h,...other},response:{status,headers:rh,content:{mimeType:other.mime||'application/json'}}
});
const har={log:{entries:[
 entry('https://api.captureweb.net/v3/download?X-Amz-Signature='+secret,'POST',202,[{name:'Authorization',value:'Bearer '+secret},{name:'X-Csrf-Token',value:secret}],[],{postData:{mimeType:'application/json',text:secret}}),
 entry('https://s3.eu-west-2.amazonaws.com/super-private/asset?uploadId='+secret+'&partNumber=1','PUT',200),
 entry('https://images.example.test/export/prepare','POST',202),
 entry('https://images.example.test/job/status','GET',200),
 entry('https://d32.cloudfront.net/asset.jpg','GET',206,[],[{name:'Content-Type',value:'image/jpeg'},{name:'Cache-Control',value:'public, max-age=900'}, {name:'X-Amz-Cf-Id',value:secret}],{mime:'image/jpeg'}),
 entry('https://download.example.test/restricted','GET',403,[],[{name:'Content-Disposition',value:'attachment; filename="'+secret+'.zip"'}]),
 entry('https://store.blob.core.windows.net/a?comp=block','PUT',201),
 entry('https://storage.googleapis.com/up?uploadType=resumable','POST',201),
 entry('https://uploader.example.test/upload','PATCH',204,[{name:'Tus-Resumable',value:'1.0.0'}]),
 entry('https://files.example.test/a','GET',302,[],[{name:'Location',value:'https://sensitive.invalid/'+secret}]),
 {request:{url:'file:///Users/'+secret,method:'GET'},response:{status:200}},
 null,
 entry('https://api.evilamazonaws.com/v1','GET',200),
],pages:[{title:secret}]}};
const r=dam.audit(har),as=JSON.stringify(r);
assert.equal(r.format,'trufflehog-har-dam-workflows');
assert.equal(r.coverage.totalEntries,13);
assert.equal(r.coverage.inspectedHttp,11);
assert.equal(r.coverage.excludedEntries,2);
for(const input of [secret,'api.captureweb.net','/export/prepare','filename','x-amz','private/asset','download.example.test']){
 assert(!as.includes(input),`unredacted source substring: ${input}`);
}
const count=(array,name)=>array.find(x=>x.category===name)?.count;
assert.equal(count(r.providers,'Capture DAM (service signal)'),1);
assert.equal(count(r.providers,'Amazon S3 (storage signal)'),1);
assert.equal(count(r.providers,'Amazon CloudFront (CDN signal)'),1);
assert.equal(count(r.providers,'Azure Blob Storage (storage signal)'),1);
assert.equal(count(r.providers,'Google Cloud Storage (storage signal)'),1);
assert.equal(count(r.stages,'Export-job request clue'),1);
assert.equal(count(r.stages,'Export-status check clue'),1);
assert.equal(count(r.stages,'HTTP redirect'),1);
assert.equal(count(r.stages,'HTTP authorisation denial'),1);
assert.equal(count(r.stages,'Attachment disposition header'),1);
assert.equal(count(r.indicators,'Signing / token query field name'),1);
assert.equal(count(r.indicators,'tus protocol header'),1);
assert.equal(count(r.indicators,'S3 multipart parameter names'),1);
assert.equal(count(r.indicators,'Presigned POST field names'),0);
const postDam=dam.audit({log:{entries:[entry('https://demo.s3.amazonaws.com/post','POST',204,[],[],{postData:{mimeType:'multipart/form-data',params:[{name:'policy',value:secret},{name:'x-amz-signature',value:secret}]}}),entry('https://example.test/noop','GET',200)]}});
assert.equal(count(postDam.indicators,'Presigned POST field names'),1);
assert.equal(count(postDam.stages,'Upload / multipart request clue'),1);
assert(!JSON.stringify(postDam).includes(secret));
assert.equal(count(r.indicators,'Public cache directive present'),1);
assert.equal(count(r.statuses,'2xx'),9);
assert.equal(count(r.statuses,'4xx'),1);
assert.ok(priv.audit(har).rows.length);
assert.throws(()=>dam.audit({}),/log.entries/);
assert.throws(()=>dam.audit({log:{entries:Array.from({length:12001},()=>({}))}}),/12,000/);
// Inputs from a synthetic malformed HAR cannot influence output labels.
const injected={log:{entries:[entry('https://'+secret+'.invalid/?secret='+secret,'POST',200,[{name:'__proto__',value:secret}],[{name:secret,value:secret}],{postData:{params:[{name:secret,value:secret}]}})]}};
assert(!JSON.stringify(dam.audit(injected)).includes(secret));
console.log('PASS v7.0 offline HAR DAM workflow: service/stage/signing labels, privacy, bounded inputs, no arbitrary source strings');
