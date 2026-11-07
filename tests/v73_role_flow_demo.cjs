'use strict';
const cmp=require('../har_stage_compare.js');
const host=(h,stage)=>({startedDateTime:'2026-10-24T00:00:00Z',request:{url:'https://'+h+'/'+stage,method:stage.includes('export')?'POST':'GET'},response:{status:200,headers:stage==='download'?[{name:'Content-Disposition',value:'attachment;filename=private.jpg'}]:[],content:{mimeType:stage==='download'?'image/jpeg':'application/json'}}});
const baseline={log:{entries:[host('c.captureweb.net','export'),host('edge.cloudfront.net','download')]}};
const later={log:{entries:[host('c.captureweb.net','export'),host('edge.cloudfront.net','download'),host('edge.cloudfront.net','download')]}};
const report=cmp.audit(baseline,later,{});
console.log(JSON.stringify({format:report.format,readiness:report.readiness,roles:report.roleRows,handoffs:report.handoffRows,warningCount:report.warnings.length},null,2));
