'use strict';
const assert=require('node:assert/strict');
const AWS=require('../aws_dam_intel.js');
const secret='DO_NOT_STORE_UPLOAD_TOKEN_XYZ';
const s3='https://assets-prod.s3.eu-west-2.amazonaws.com/?X-Amz-Signature='+secret;
const post={url:s3,method:'POST',statusCode:204,requestBody:{formData:{
 'key':['private/asset/'+secret+'.jpg'], 'policy':[secret], 'x-amz-credential':[secret],
 'x-amz-signature':[secret],'x-amz-date':['20261024T120000Z'],'x-amz-security-token':[secret],
 'success_action_status':['201'],'ACL':['private'], 'file':[secret]
 }}};
assert.equal(AWS.hostClass(s3),'S3 endpoint hostname');
const upload=AWS.classify('request',post);
assert.equal(upload.operation,'S3 presigned POST request observed');
assert.equal(upload.postSignature,'S3 presigned POST field structure');
assert(upload.fieldTypes.includes('Temporary session-token field'));
assert.equal(upload.policyContents,'not inspected');
assert.equal(upload.signedQueryPresent,true);
assert.equal(AWS.hostClass('https://xyz.execute-api.eu-west-2.amazonaws.com/demo/assets'),'API Gateway hostname');
const api=AWS.classify('response',{url:'https://xyz.execute-api.eu-west-2.amazonaws.com/demo/assets',method:'POST',statusCode:202});
assert.equal(api.operation,'Asset/workflow API request observed');
assert.equal(api.status,202);
assert.equal(AWS.classify('request',{url:'https://example.org/api/assets',method:'GET'}),null);
const local=AWS.classify('request',{url:'https://127.0.0.1:8765/api/upload',method:'POST',requestBody:post.requestBody});
assert.equal(local.operation,'Presigned POST field pattern; service unverified');
const schema=AWS.responseHints({fields:[{path:'executionArn',type:'string'},{path:'overallStatus',type:'string'},
 {path:'aimlResults.rekognition',type:'object'},{path:'NextToken',type:'string'},
 {path:'owner',type:'string'},{path:'secretKey',type:'string'}]});
assert(schema.includes('Workflow execution reference field'));
assert(schema.includes('AI analysis result container'));
assert(schema.includes('Pagination continuation field'));
const record={downloadEvents:[{requestId:'req-1',at:'2026-10-24T12:00:00.000Z',host:'assets-prod.s3.eu-west-2.amazonaws.com',awsDam:upload},
 {requestId:'req-1',at:'2026-10-24T12:00:00.300Z',host:'assets-prod.s3.eu-west-2.amazonaws.com',awsDam:AWS.classify('complete',{...post,requestBody:null})},
 {requestId:'req-2',at:'2026-10-24T12:01:00.000Z',host:'xyz.execute-api.eu-west-2.amazonaws.com',awsDam:api}],
 responses:[{at:'2026-10-24T12:02:00Z',host:'xyz.execute-api.eu-west-2.amazonaws.com',method:'GET',status:200,url:'https://xyz.execute-api.eu-west-2.amazonaws.com/demo/assets',fields:[{path:'overallStatus',type:'string'}]}]};
const rows=AWS.rows(record);
assert.equal(rows.length,3);
assert.equal(rows.filter(x=>/presigned POST/.test(x.kind)).length,1);
assert(rows.some(x=>/schema clues/.test(x.kind)));
for(const v of [secret,'private/asset/','20261024T120000Z','assets-prod.s3.eu-west-2.amazonaws.com/?', 'secretKey']){
 assert(!JSON.stringify({upload,api,local,rows,schema}).includes(v),'leak '+v);
}
const poisoned={downloadEvents:[{requestId:'x',host:'token='+secret,at:secret,awsDam:{operation:'AWS-related observation',service:'unclassified',evidence:secret,postSignature:secret,fieldTypes:[secret],status:900}}]};
assert(!JSON.stringify(AWS.rows(poisoned)).includes(secret));
console.log('PASS v5.3 AWS DAM opt-in observation, presigned POST names, response shape clues and redaction');
