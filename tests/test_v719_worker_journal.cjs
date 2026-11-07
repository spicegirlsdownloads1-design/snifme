'use strict';
const assert=require('node:assert/strict');
const fs=require('node:fs');const vm=require('node:vm');const crypto=require('node:crypto');
const {createFakeIndexedDB}=require('./fake_indexeddb_v719.js');
const indexedDB=createFakeIndexedDB(),IDBKeyRange={};
const local=new Map(),session=new Map();let localWrites=0;
const storage=(map,observe=false)=>({
 get:async keys=>keys===null?Object.fromEntries(map):Array.isArray(keys)?Object.fromEntries(keys.map(k=>[k,map.get(k)])):{[keys]:map.get(keys)},
 set:async object=>{for(const [key,value]of Object.entries(object)){if(observe&&key.startsWith('record:'))localWrites++;map.set(key,structuredClone(value));}},
 remove:async keys=>{for(const key of Array.isArray(keys)?keys:[keys])map.delete(key)},
 getBytesInUse:async key=>JSON.stringify(map.get(key)||{}).length
});
let callbacks,workerCount=0;
function newWorker(){
 workerCount++;
 const events={};callbacks=events;
 const origin='https://capture.example.invalid';
 const chrome={storage:{local:storage(local,true),session:storage(session)},
  tabs:{get:async id=>({id,url:origin+'/gallery'}),query:async()=>[],sendMessage:async()=>({ok:true}),onUpdated:{addListener:f=>events.updated=f},onRemoved:{addListener:f=>events.removed=f}},
  scripting:{executeScript:async()=>{}},permissions:{contains:async()=>true,onRemoved:{addListener:()=>{}}},
  action:{setBadgeText:async()=>{},setBadgeBackgroundColor:async()=>{}},
  notifications:{create:async()=>{},onClicked:{addListener:()=>{}},onButtonClicked:{addListener:()=>{}}},
  downloads:{onCreated:{addListener:()=>{}},onChanged:{addListener:()=>{}},search:async()=>[]},
  webRequest:{onBeforeRequest:{addListener:f=>events.before=f},onBeforeSendHeaders:{addListener:()=>{}},onHeadersReceived:{addListener:()=>{}},onBeforeRedirect:{addListener:()=>{}},onCompleted:{addListener:f=>events.completed=f},onErrorOccurred:{addListener:()=>{}}},
  runtime:{getURL:x=>'chrome-extension://test/'+x,getManifest:()=>require('../manifest.json'),onMessage:{addListener:f=>events.message=f},onInstalled:{addListener:()=>{}},onStartup:{addListener:()=>{}}}
 };
 const ctx=vm.createContext({indexedDB,IDBKeyRange,chrome,URL,URLSearchParams,console,Date,Promise,setTimeout,clearTimeout,AbortController,TextDecoder,TextEncoder,crypto:crypto.webcrypto});ctx.globalThis=ctx;
 ctx.importScripts=(...files)=>files.forEach(f=>vm.runInContext(fs.readFileSync(f,'utf8'),ctx,{filename:f}));
 vm.runInContext(fs.readFileSync('background.js','utf8'),ctx,{filename:'background.js'});
 return {events,send:(type,data={})=>new Promise(resolve=>events.message({type,tabId:44,...data},{url:chrome.runtime.getURL('dashboard.html')},resolve))};
}
const poll=async(condition,timeout=10000)=>{const end=Date.now()+timeout;while(Date.now()<end){if(await condition())return;await new Promise(r=>setTimeout(r,30));}throw Error('Timed out waiting for journal commit');};
(async()=>{
 let w=newWorker();
 const url='https://capture.example.invalid/gallery';
 w.events.before({tabId:44,requestId:'nav',type:'main_frame',url,method:'GET',timeStamp:Date.now()});
 await poll(async()=>!!(await w.send('GET_STATE')).recording?.enabled);
 const body='NOT_A_REAL_TOKEN_SHOULD_NEVER_PERSIST_12345';
 for(let i=0;i<60;i++){
  const d={tabId:44,requestId:'req-'+i,type:'xmlhttprequest',method:'GET',url:`https://media.example.invalid/api/assets/${i}?access_token=${body}`,
   documentUrl:url,initiator:'https://capture.example.invalid',timeStamp:Date.now(),statusCode:200,responseHeaders:[{name:'content-type',value:'application/json'}]};
  w.events.before(d);w.events.completed(d);
 }
 await poll(async()=>(await w.send('GET_STATE')).record?.requests?.length===60);
 const beforeRestart=await w.send('GET_STATE');
 assert.equal(beforeRestart.record.requests.length,60);
 assert(!JSON.stringify(beforeRestart.record).includes(body));
 const checkpointWrites=localWrites;
 assert(checkpointWrites<=4,'journal should reduce chrome.storage.local full-record writes');
 // Lose all worker-level caches, then open another instance of the same extension.
 w=newWorker();const recovered=await w.send('GET_STATE');
 assert.equal(recovered.record.requests.length,60);
 assert.equal(recovered.record.sessionId,beforeRestart.record.sessionId);
 const diag=await w.send('GET_CAPTURE_DIAGNOSTICS');
 assert.equal(diag.diagnostics.journal.mode,'indexeddb-journal');
 assert(diag.diagnostics.journal.pendingDeltas>=1);
 // Upgrade a v7.18-style local-only live record without changing its identity.
 const legacy=structuredClone(recovered.record);legacy.tabId=45;legacy.sessionId='session-legacy-upgrade';
 legacy.requests=[{url:'https://capture.example.invalid/old',host:'capture.example.invalid',at:new Date().toISOString()}];
 delete legacy.journalSequence;
 local.set('record:45',legacy);
 session.set('active:45',{origin:'https://capture.example.invalid',enabled:true,startedAt:legacy.createdAt,downloadObserver:false});
 const existing=await w.send('GET_STATE',{tabId:45});assert.equal(existing.record.requests.length,1);
 const newEvent={tabId:45,requestId:'new-post-upgrade',type:'xmlhttprequest',method:'GET',
  url:'https://capture.example.invalid/api/new',documentUrl:'https://capture.example.invalid/gallery',
  initiator:'https://capture.example.invalid',timeStamp:Date.now(),statusCode:200,responseHeaders:[]};
 w.events.completed(newEvent);
 await poll(async()=>(await w.send('GET_STATE',{tabId:45})).record?.requests?.length===2);
 w=newWorker();
 const upgraded=await w.send('GET_STATE',{tabId:45});
 assert.equal(upgraded.record.sessionId,'session-legacy-upgrade');
 assert.equal(upgraded.record.requests.length,2);
 assert.equal((await w.send('GET_CAPTURE_DIAGNOSTICS',{tabId:45})).diagnostics.journal.mode,'indexeddb-journal');
 const stop=await w.send('STOP_CAPTURE');assert.equal(stop.archiveWarning,'');
 const vault=await w.send('GET_SAVED_SESSION',{sessionId:recovered.record.sessionId});
 assert.equal(vault.record.requests.length,60);
 console.log('PASS v7.19 worker restart restores 60 journaled requests, migrates legacy live record, reduces local writes, preserves vault and token redaction');
})().catch(error=>{console.error(error);process.exitCode=1;});
