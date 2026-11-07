'use strict';
const assert=require('node:assert/strict');
const {createFakeIndexedDB}=require('./fake_indexeddb_v719.js');
global.indexedDB=createFakeIndexedDB();global.IDBKeyRange={};
const j=require('../capture_journal.js');
const record={tabId:31,sessionId:'session-synthetic-98765432',origin:'https://example.invalid',requests:[],securityObservations:[],counters:{requestsDropped:0},createdAt:new Date().toISOString()};
(async()=>{
 assert(j.supported());
 await j.replace(31,record);
 assert.equal((await j.read(31)).sessionId,record.sessionId);
 let before=await j.read(31);
 for(let i=1;i<=205;i++){
  const after=JSON.parse(JSON.stringify(before));
  after.requests.push({id:i,url:'https://example.invalid/resource/'+i});
  if(i===56)after.securityObservations.push({ruleId:'SYNTHETIC',occurrences:1});
  if(i===57)after.securityObservations[0].occurrences=2;
  if(i===87)after.counters.requestsDropped=1;
  const result=await j.append(31,before,after);
  assert(result.changed);assert.equal(result.sequence,i);
  before=await j.read(31); // Simulates tearing down the MV3 worker between updates.
  assert.equal(before.requests.length,i);
 }
 const recovered=await j.read(31);
 assert.equal(recovered.requests.length,205);assert.equal(recovered.securityObservations[0].occurrences,2);
 assert.equal(recovered.counters.requestsDropped,1);
 assert.equal(recovered.journalSequence,205);
 const health=await j.stats(31);
 assert.equal(health.mode,'indexeddb-journal');assert.equal(health.checkpointSequence,192);
 assert.equal(health.pendingDeltas,13);
 const nochange=await j.append(31,recovered,JSON.parse(JSON.stringify(recovered)));
 assert.equal(nochange.changed,false);
 const after=JSON.parse(JSON.stringify(recovered));after.requests.shift();
 const replacement=await j.patch(recovered,after);
 assert(Array.isArray(replacement.set.requests));assert(!replacement.append.requests);
 await j.remove(31);assert.equal(await j.read(31),null);
 console.log('PASS v7.19 transactional delta replay, modifications, 96-change compaction, simulated restarts, no-op and deletion');
})().catch(error=>{console.error(error);process.exitCode=1;});
