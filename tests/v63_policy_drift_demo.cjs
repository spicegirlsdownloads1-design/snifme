'use strict';
const M=require('../dam_policy_compare.js');
function capture(group,changed){
 return [{origin:'https://archive.example',captureGroupId:group,segmentIndex:0,endedAt:'2026-10-24T13:00:00Z',counters:{},requests:Array.from({length:40},(_,i)=>({
   type:'image',mime:'image/jpeg',status:changed&&i<8?403:200,signedQuery:changed?i%2===0:i%3===0,
   cacheScope:i%4===0?'public':'private',cacheMaxAge:i%4===0?86400:0,
   url:'https://cdn.example/image/illustrative-'+i+'.jpg?signature=EXAMPLE_REMOVED'
 }))}];
}
const report=M.compare(capture('example-baseline',false),capture('example-later',true));
console.log(JSON.stringify(report,null,2));
