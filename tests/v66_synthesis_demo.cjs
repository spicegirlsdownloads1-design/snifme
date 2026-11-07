'use strict';
require('../dam_policy_compare.js');require('../workflow_pattern.js');require('../comparison_readiness.js');
const {synthesize}=require('../evidence_synthesis.js');
function create(group,kind='baseline'){
 const requests=Array.from({length:180},(_,i)=>({
  type:i%3===0?'image':i%3===1?'fetch':'script',
  mime:i%3===0?'image/jpeg':'application/json',
  method:'GET',status:(kind==='later'&&i%12===0)?403:200,
  at:new Date(2026,9,24,11,0,i).toISOString()
 }));
 return [{origin:'https://example.invalid',captureGroupId:group,segmentIndex:0,
   endedAt:'2026-10-24T11:30:00Z',requests,counters:{}}];
}
const choices={accessRole:'same',workflow:'same',assetScope:'same',hostPermissions:'same',devtoolsTiming:'both-early'};
const r=synthesize(create('before'),create('after','later'),choices);
console.log(JSON.stringify(r,null,2));
