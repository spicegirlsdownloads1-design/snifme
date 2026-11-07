'use strict';
const run=require('../har_dam_workflows.js').audit;
const h={log:{entries:[
 {request:{method:'POST',url:'https://api.captureweb.net/export/jobs',headers:[{name:'authorization',value:'Bearer DUMMY_REDACTED'}]},response:{status:202,headers:[],content:{mimeType:'application/json'}}},
 {request:{method:'GET',url:'https://abc.cloudfront.net/dl?id=DEMO',headers:[]},response:{status:200,headers:[{name:'content-disposition',value:'attachment; filename="PRIVATE_ASSET.jpg"'},{name:'content-type',value:'image/jpeg'}],content:{mimeType:'image/jpeg'}}}
 ]}};
console.log(JSON.stringify(run(h),null,2));
