'use strict';
const assert=require('node:assert/strict');
const ROLES=require('../har_role_flow.js');
const SEQ=require('../har_sequence.js');
const COMP=require('../har_stage_compare.js');
const secret='Bearer EXTREMELY_PRIVATE_PHOTO_AGENCY_SECRET_AND_SESSION';
const entry=(host,path,method='GET',status=200,mime='application/json',extra={})=>({
 startedDateTime:'2026-10-24T08:22:31Z',
 request:{url:'https://'+host+'/'+path+'?access_token='+encodeURIComponent(secret),method,headers:[{name:'authorization',value:secret}]},
 response:{status,headers:[],content:{mimeType:mime}},...extra
});
const attach=(host)=>entry(host,'original/download','GET',200,'image/jpeg',{response:{status:200,headers:[{name:'Content-Disposition',value:'attachment; filename="SHOULD_NEVER_APPEAR.jpg"'}],content:{mimeType:'image/jpeg'}}});
const a={log:{entries:[
 entry('example.captureweb.net','export/request','POST',202),
 entry('x.execute-api.eu-west-1.amazonaws.com','task/status'),
 entry('x.s3.eu-west-1.amazonaws.com','upload/part','POST',200,'text/plain',{request:{url:'https://x.s3.eu-west-1.amazonaws.com/upload?uploads=1&X-Amz-Signature=NOT_TO_EXPORT',method:'POST',postData:{mimeType:'multipart/form-data;boundary=private',params:[{name:'policy',value:secret}]},headers:[]},response:{status:200,headers:[],content:{mimeType:'text/plain'}}}),
 attach('abcdef.cloudfront.net'),
 entry('example.captureweb.net','api/list','GET',200,'application/json'),
 entry('other.example','css/styles','GET',200,'text/css'), // not a classified stage
 entry('other.example','api/query','GET',200,'application/json')
]}};
const b={log:{entries:[
 entry('example.captureweb.net','export/request','POST',202),
 attach('abcdef.cloudfront.net'),
 entry('example.captureweb.net','export/request','POST',202),
 attach('abcdef.cloudfront.net'),
 entry('other.example','denied','GET',403,'text/html')
]}};
const r=ROLES.audit(a);
assert.equal(r.format,'trufflehog-har-role-flow');
assert.equal(r.coverage.classifiedStages,6);
assert.equal(r.coverage.adjacentPairs,5);
const roles=Object.fromEntries(r.roleRows.map(x=>[x.category,x.count]));
assert.equal(roles['DAM vendor service'],2);
assert.equal(roles['API gateway'],1);
assert.equal(roles['Object storage'],1);
assert.equal(roles['CDN delivery'],1);
assert.equal(roles['Other/unknown service'],1);
assert.equal(r.nearbyRows.find(x=>x.category==='DAM/API to CDN').count,0);
assert.equal(r.nearbyRows.find(x=>x.category==='Storage to CDN').count,1);
assert.equal(r.nearbyRows.find(x=>x.category==='DAM/API to storage').count,1);
assert.equal(r.stageRows.find(x=>x.service==='Object storage'&&x.stage==='Upload / resumable transfer clue').count,1);
const signal=SEQ.stageSignal(a.log.entries[0]);
assert.deepEqual(signal,{stage:'Export preparation request clue',provider:'Capture service'});
assert.equal(SEQ.stageSignal(a.log.entries[5]),null);
const comp=COMP.audit(a,b,{sameSite:'yes',sameActions:'yes',sameAccount:'yes',sameScope:'yes',sameBrowserCoverage:'yes'});
assert.equal(comp.roleRows.find(x=>x.category==='CDN delivery').baseline,1);
assert.equal(comp.roleRows.find(x=>x.category==='CDN delivery').comparison,2);
assert.equal(comp.handoffRows.find(x=>x.category==='DAM/API to CDN').comparison,2);
assert.equal(comp.roleCoverage[0].classifiedStages,6);
assert(comp.roleStageRows.some(x=>x.service==='DAM vendor service'&&x.stage==='Export preparation request clue'));
const text=JSON.stringify([r,comp]);
for(const forbidden of ['EXTREMELY_PRIVATE','SHOULD_NEVER_APPEAR','access_token','boundary=private','example.captureweb','2026-10-24','X-Amz-Signature','upload/part','SECRET_AND_SESSION'])assert(!text.includes(forbidden),forbidden);
const far=ROLES.audit({log:{entries:[a.log.entries[0],...Array(7).fill(entry('other.example','styles.css','GET',200,'text/css')),attach('abcdef.cloudfront.net')]}});
assert.equal(far.coverage.adjacentPairs,0);assert.equal(far.coverage.notNearbyPairs,1);
const many=ROLES.audit({log:{entries:Array(401).fill(0).map((_,i)=>entry(i%2?'zz.cloudfront.net':'example.captureweb.net',i%2?'images/photo.jpg':'export/create',i%2?'GET':'POST',200,i%2?'image/jpeg':'application/json'))}});
assert.equal(many.coverage.classifiedStages,401);
assert.equal(many.coverage.adjacentPairs,400);
assert.equal(many.roleRows.find(x=>x.category==='DAM vendor service').count,201);
assert.throws(()=>ROLES.audit({log:{entries:Array(12001).fill(null)}}),/limit/);
assert.equal(COMP.audit({log:{entries:[]}},{log:{entries:[]}}).roleRows[0].baselinePer1000,null);
const malicious=entry('evil.example','export/'+encodeURIComponent('<script>EXPLOIT_AND_PRIVATE</script>'),'POST');
assert(!JSON.stringify(ROLES.audit({log:{entries:[malicious]}})).includes('EXPLOIT_AND_PRIVATE'));
console.log('PASS v7.3: classified full-HAR service role comparisons, bounded adjacency, privacy, ambiguity');
