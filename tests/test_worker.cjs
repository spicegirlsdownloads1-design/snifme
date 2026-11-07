const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const local=new Map(),session=new Map(),callbacks={};
function storage(m){return {get:async(key)=>({[key]:m.get(key)}),set:async(values)=>{for(const [k,v] of Object.entries(values))m.set(k,v)},remove:async(key)=>m.delete(key)}}
const chrome={
  storage:{local:storage(local),session:storage(session)},
  tabs:{get:async()=>({id:7,url:'https://photos.example.test/gallery'}),sendMessage:async()=>({ok:true}),onUpdated:{addListener:fn=>callbacks.updated=fn},onRemoved:{addListener:fn=>callbacks.removed=fn}},
  scripting:{executeScript:async()=>{}},
  action:{setBadgeText:async()=>{},setBadgeBackgroundColor:async()=>{}},
  webRequest:{onCompleted:{addListener:fn=>callbacks.completed=fn},onErrorOccurred:{addListener:fn=>callbacks.error=fn}},
  runtime:{onMessage:{addListener:fn=>callbacks.message=fn},onInstalled:{addListener:fn=>callbacks.installed=fn},getURL:page=>`chrome-extension://unit-test/${page}`}
};
const ctx=vm.createContext({chrome,URL,URLSearchParams,console,Date,Promise,setTimeout,clearTimeout,AbortController,TextDecoder});ctx.globalThis=ctx;
ctx.importScripts=(...names)=>names.forEach(name=>vm.runInContext(fs.readFileSync(name,'utf8'),ctx,{filename:name}));
vm.runInContext(fs.readFileSync('background.js','utf8'),ctx,{filename:'background.js'});
const send=(type, extra={}, sender={})=>new Promise((resolve,reject)=>{let settled=false;
  const ok=callbacks.message({type,tabId:7,...extra},sender,reply=>{settled=true;resolve(reply)});
  if(!ok&&!settled)reject(new Error('No reply'));
});
(async()=>{
 const trusted={url:'chrome-extension://unit-test/devtools.html'};
 assert.equal((await send('GET_STATE')).record,null);
 assert.equal((await send('VERIFIED_IMAGE',{payload:{url:'https://cdn.test/a.jpg',sha256:'a'.repeat(64),byteLength:10,mime:'image/jpeg'}},trusted)).ok,false);
 assert.equal((await send('START_CAPTURE')).ok,true);
 assert.equal((await send('GET_IMAGE_PERMISSION',{},trusted)).enabled,true);
 assert.equal((await send('TOGGLE_IMAGE_VERIFICATION',{enabled:true})).enabled,true);
 assert.equal((await send('GET_IMAGE_PERMISSION',{},{})).ok,false);
 assert.equal((await send('GET_IMAGE_PERMISSION',{},trusted)).enabled,true);
 const proof={url:'https://cdn.example.test/00440011.jpg?token=SECRETDO_NOT_KEEP&w=800',sha256:'f'.repeat(64),byteLength:12345,width:800,height:600,format:'JPEG',mime:'image/jpeg'};
 assert.equal((await send('VERIFIED_IMAGE',{payload:proof},{})).ok,false);
 assert.equal((await send('VERIFIED_IMAGE',{payload:{...proof,sha256:'invalid'}},trusted)).ok,false);
 assert.equal((await send('VERIFIED_IMAGE',{payload:{...proof,byteLength:5*1024*1024}},trusted)).ok,false);
 assert.equal((await send('VERIFIED_IMAGE',{payload:proof},trusted)).ok,true);
 let state=await send('GET_STATE');
 assert.equal(state.record.verifications.length,1);
 assert.equal(state.record.verifications[0].url,'https://cdn.example.test/00440011.jpg?w=800');
 assert.equal(JSON.stringify(state.record).includes('SECRETDO_NOT_KEEP'),false);
 assert.equal((await send('TOGGLE_IMAGE_VERIFICATION',{enabled:false})).enabled,false);
 assert.equal((await send('VERIFIED_IMAGE',{payload:proof},trusted)).ok,false);
 await send('STOP_CAPTURE');
 assert.equal((await send('GET_IMAGE_PERMISSION',{},trusted)).enabled,false);
 assert.equal((await send('VERIFIED_IMAGE',{payload:proof},trusted)).ok,false);
 state=await send('GET_STATE');assert.equal(state.record.verifications.length,1);
 console.log('PASS v2.2 worker: opt-in, sender gate, SHA validation, URL redaction, retention, stop');
})().catch(e=>{console.error(e);process.exitCode=1});
