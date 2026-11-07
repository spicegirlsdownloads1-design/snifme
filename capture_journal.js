/* Trufflehog v7.19 — durable, incremental local capture journal.
   The browser already supplies redacted metadata. This module never fetches URLs,
   inspects bodies or stores raw credentials. IndexedDB transactions commit a delta
   before the worker acknowledges a record update. Browser restarts are handled by
   replaying deltas from the most recent compacted snapshot. */
(function(root){
'use strict';
const NAME='TrufflehogCaptureJournal', VERSION=1, BASE='checkpoints', DELTAS='deltas';
const COMPACT_EVERY=96;
const goodTab=id=>Number.isSafeInteger(id)&&id>=0;
const own=(o,k)=>Object.prototype.hasOwnProperty.call(o,k);
const clone=v=>JSON.parse(JSON.stringify(v));
const equal=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
function patch(before,after){
 if(!before||!after||typeof before!=='object'||typeof after!=='object')throw Error('Two capture records are required');
 const change={set:{},append:{},remove:[]};
 for(const key of new Set([...Object.keys(before),...Object.keys(after)])){
  if(key==='journalSequence')continue;
  if(!own(after,key)){change.remove.push(key);continue;}
  const left=before[key],right=after[key];
  if(left===right||equal(left,right))continue;
  if(Array.isArray(left)&&Array.isArray(right)&&right.length>=left.length &&
     equal(left,right.slice(0,left.length))){
    if(right.length>left.length)change.append[key]=clone(right.slice(left.length));
  }else change.set[key]=clone(right);
 }
 return change;
}
function isEmpty(p){return !Object.keys(p.set).length&&!Object.keys(p.append).length&&!p.remove.length;}
function replay(record,change,sequence){
 if(!record||!change||!Number.isSafeInteger(sequence))throw Error('Invalid journal delta');
 const result=clone(record);
 for(const key of change.remove||[])delete result[key];
 for(const [key,value] of Object.entries(change.set||{}))result[key]=clone(value);
 for(const [key,values] of Object.entries(change.append||{})){
  if(!Array.isArray(result[key])||!Array.isArray(values))throw Error('Invalid journal append operation');
  result[key].push(...clone(values));
 }
 result.journalSequence=sequence;
 return result;
}
// IDBKeyRange is a browser-standard companion to IndexedDB; older minimal
// test shims implement neither indexes nor ranges and must use legacy fallback.
function supported(){return typeof indexedDB!=='undefined'&&typeof IDBKeyRange!=='undefined';}
// Share a database connection for the worker's lifetime instead of opening and
// closing IndexedDB for every network observation. Chrome closes it on shutdown.
let connection=null,opening=null;
function open(){
 if(!supported())return Promise.reject(Error('IndexedDB unavailable'));
 if(connection)return Promise.resolve(connection);
 if(opening)return opening;
 opening=new Promise((resolve,reject)=>{
  const req=indexedDB.open(NAME,VERSION);
  req.onupgradeneeded=()=>{
   const db=req.result;
   if(!db.objectStoreNames.contains(BASE))db.createObjectStore(BASE,{keyPath:'tabId'});
   if(!db.objectStoreNames.contains(DELTAS)){
    const store=db.createObjectStore(DELTAS,{keyPath:['tabId','sequence']});
    store.createIndex('tabId','tabId');
   }
  };
  req.onsuccess=()=>{
   connection=req.result;
   connection.onversionchange=()=>{connection.close();connection=null;};
   resolve(connection);
  };
  req.onerror=()=>reject(req.error||Error('Unable to open capture journal'));
  req.onblocked=()=>reject(Error('Capture journal upgrade blocked by an open extension page'));
 }).finally(()=>{opening=null;});
 return opening;
}
async function transaction(mode,callback){
 const db=await open();
 return new Promise((resolve,reject)=>{
  const tx=db.transaction([BASE,DELTAS],mode),base=tx.objectStore(BASE),deltas=tx.objectStore(DELTAS);
  let value,fatal=null;
  tx.oncomplete=()=>fatal?reject(fatal):resolve(value);
  tx.onerror=()=>reject(tx.error||Error('Capture journal transaction failed'));
  tx.onabort=()=>reject(fatal||tx.error||Error('Capture journal transaction aborted'));
  const fail=error=>{fatal=error;try{tx.abort();}catch{reject(error);}};
  try{callback(base,deltas,x=>{value=x;},fail);}catch(error){try{tx.abort();}catch{}reject(error);}
 });
}
function deleteDeltas(deltas,tabId){
 const index=deltas.index('tabId');
 const req=index.openKeyCursor(tabId);
 req.onsuccess=()=>{const cursor=req.result;if(cursor){deltas.delete(cursor.primaryKey);cursor.continue();}};
}
async function replace(tabId,record){
 if(!goodTab(tabId)||!record||record.tabId!==tabId)throw Error('Invalid journal checkpoint');
 const data=clone(record);
 data.journalSequence=Number.isSafeInteger(record.journalSequence)?record.journalSequence:0;
 return transaction('readwrite',(base,deltas)=>{
  base.put({tabId,sequence:data.journalSequence,record:data,updatedAt:Date.now()});
  deleteDeltas(deltas,tabId);
 });
}
async function ensure(tabId,fallback){
 if(!goodTab(tabId)||!fallback||fallback.tabId!==tabId)throw Error('Invalid migration record');
 return transaction('readwrite',(base,deltas,done)=>{
  const req=base.get(tabId);
  req.onsuccess=()=>{
   if(req.result){done(false);return;}
   const data=clone(fallback);data.journalSequence=0;
   base.add({tabId,sequence:0,record:data,updatedAt:Date.now()});
   deleteDeltas(deltas,tabId);
   done(true);
  };
 });
}
async function read(tabId){
 if(!goodTab(tabId))return null;
 return transaction('readonly',(base,deltas,done,fail)=>{
  let checkpoint=null,changes=null;
  const b=base.get(tabId),d=deltas.index('tabId').getAll(tabId);
  b.onsuccess=()=>{checkpoint=b.result||null;if(changes!==null)finish();};
  d.onsuccess=()=>{changes=d.result||[];if(checkpoint!==null||b.readyState==='done')finish();};
  function finish(){
   try{
   if(!checkpoint){done(null);return;}
   let record=clone(checkpoint.record),seq=checkpoint.sequence;
   for(const item of changes.sort((a,b)=>a.sequence-b.sequence)){
    if(item.sequence<=seq)continue;
    if(item.sequence!==seq+1)throw Error('Capture journal has a missing delta at '+(seq+1));
    record=replay(record,item.patch,item.sequence);seq=item.sequence;
   }
   done(record);
   }catch(error){fail(error);}
  }
 });
}
async function append(tabId,before,after){
 if(!goodTab(tabId)||before?.tabId!==tabId||after?.tabId!==tabId)throw Error('Invalid capture record update');
 const change=patch(before,after);
 if(isEmpty(change))return {changed:false,sequence:before.journalSequence||0,compacted:false};
 const current=Number.isSafeInteger(before.journalSequence)?before.journalSequence:0;
 const seq=current+1;
 after.journalSequence=seq;
 const compact=seq%COMPACT_EVERY===0;
 return transaction('readwrite',(base,deltas,done)=>{
  if(compact){
   base.put({tabId,sequence:seq,record:clone(after),updatedAt:Date.now()});
   deleteDeltas(deltas,tabId);
  }else deltas.add({tabId,sequence:seq,patch:change});
  done({changed:true,sequence:seq,compacted:compact});
 });
}
async function remove(tabId){
 if(!goodTab(tabId))return;
 return transaction('readwrite',(base,deltas)=>{base.delete(tabId);deleteDeltas(deltas,tabId);});
}
async function stats(tabId){
 if(!goodTab(tabId))return {mode:'unavailable'};
 if(!supported())return {mode:'legacy-local',reason:'IndexedDB unavailable in this environment'};
 return transaction('readonly',(base,deltas,done)=>{
  let checkpoint,deltaCount;
  const a=base.get(tabId),b=deltas.index('tabId').count(tabId);
  a.onsuccess=()=>{checkpoint=a.result||null;if(deltaCount!==undefined)finish();};
  b.onsuccess=()=>{deltaCount=b.result||0;if(a.readyState==='done')finish();};
  function finish(){done(checkpoint?{mode:'indexeddb-journal',checkpointSequence:checkpoint.sequence,pendingDeltas:deltaCount,compactEvery:COMPACT_EVERY,updatedAt:checkpoint.updatedAt}:{mode:'legacy-local',pendingDeltas:0});}
 });
}
root.THICaptureJournal={supported,patch,replay,replace,ensure,read,append,remove,stats,COMPACT_EVERY};
if(typeof module!=='undefined'&&module.exports)module.exports=root.THICaptureJournal;
})(typeof self!=='undefined'?self:globalThis);
