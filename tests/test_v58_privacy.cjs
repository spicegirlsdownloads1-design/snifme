'use strict';
const assert=require('node:assert/strict'),T=require('../case_intel.js');
(async()=>{
 const adversarial='MY_SECRET_BEARER_919191919191';
 const x={sessionId:'session-safetest',captureGroupId:'group-safetest',segmentIndex:1,origin:'https://archive.example/path?token='+adversarial,createdAt:'2026-10-24T12:00:00Z',endedAt:'2026-10-24T12:01:00Z',
 requests:[{url:'https://evil.example/'+adversarial,method:'POST',status:200,at:'2026-10-24T12:00:30Z',headers:{Authorization:adversarial},body:adversarial}],
 findings:[{type:adversarial,masked:adversarial,value:adversarial,at:'2026-10-24T12:00:45Z'}],technologyHints:[{id:adversarial,value:adversarial}],responses:[{fields:[{path:adversarial,type:adversarial}]}],notes:adversarial};
 const result=JSON.stringify(T.build([x]));
 assert(!result.includes(adversarial));assert(!result.includes('evil.example'));
 assert(!result.includes('Authorization'));assert(!result.includes('session-safetest'));
 const report=T.build([x]);const env=await T.pack(report);
 const wrong={...env,report:{...report,evidence:report.evidence.map(e=>({...e,statement:adversarial}))}};
 await assert.rejects(()=>T.verify(wrong),/integrity mismatch/);
 console.log('PASS v5.8 privacy: hostile imported values absent from dossier and exports');
})().catch(e=>{console.error(e);process.exitCode=1});
