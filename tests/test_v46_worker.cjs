'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const local=new Map(),session=new Map(),cb={},notices=[];
function storage(map){return {get:async k=>k===null?Object.fromEntries(map):{[k]:map.get(k)},set:async o=>{for(const [k,v]of Object.entries(o))map.set(k,v)},remove:async k=>map.delete(k)};}
const chrome={storage:{local:storage(local),session:storage(session)},tabs:{get:async()=>({id:42,url:'https://gallery.example/photos'}),sendMessage:async()=>({}),onUpdated:{addListener:f=>cb.updated=f},onRemoved:{addListener:f=>cb.removed=f},create:async()=>{}},scripting:{executeScript:async()=>{}},webRequest:{onCompleted:{addListener:f=>cb.completed=f},onErrorOccurred:{addListener:f=>cb.error=f}},action:{setBadgeText:async()=>{},setBadgeBackgroundColor:async()=>{}},notifications:{create:async(id,p)=>{notices.push(p);return id},onClicked:{addListener:()=>{}},onButtonClicked:{addListener:()=>{}}},runtime:{getURL:f=>'chrome-extension://test/'+f,onMessage:{addListener:f=>cb.msg=f},onInstalled:{addListener:()=>{}}}};
const ctx=vm.createContext({chrome,URL,URLSearchParams,Date,console,Promise,AbortController,TextDecoder,setTimeout,clearTimeout});ctx.globalThis=ctx;ctx.importScripts=(...fsx)=>fsx.forEach(f=>vm.runInContext(fs.readFileSync(f,'utf8'),ctx,{filename:f}));vm.runInContext(fs.readFileSync('background.js','utf8'),ctx,{filename:'background.js'});
const send=(type,more={},sender={})=>new Promise(done=>cb.msg({type,tabId:42,...more},sender,done));
const trusted={url:'chrome-extension://test/devtools.html'},url='https://static.example/app.js';
const payload={url,kind:'javascript',byteCount:100,sha256:'a'.repeat(64),findings:[{type:'GitHub token indicator',masked:'ghp_…[redacted] (44 chars)',offset:14,line:2,column:5,fingerprint:'a'.repeat(64),fingerprintKeyId:'1'.repeat(16)}]};
(async()=>{
 for(let round=0;round<3;round++){
  assert.equal((await send('START_CAPTURE')).ok,true);
  await cb.completed({tabId:42,url,type:'script',method:'GET',statusCode:200,initiator:'https://gallery.example',timeStamp:Date.now(),responseHeaders:[]});
  await new Promise(r=>setTimeout(r,35));
  payload.findings[0].fingerprint=(round===2?'b':'a').repeat(64);
  // First: new, second: unchanged, third: same location but changed value.
  assert.equal((await send('AUTO_RESOURCE_SCAN',{payload},trusted)).ok,true);
  const rec=(await send('GET_STATE')).record;
  assert.equal(rec.findings[0].changeState,['new','unchanged','changed'][round]);
  assert.equal(rec.unreviewedAlerts,[1,0,1][round]);
  assert.equal(rec.findings[0].knownPrevious,round>0);
  if(round===2){
   assert.equal(notices.length,1,'Previous one-minute notification cooldown still applies');
   const key=rec.findings[0]._key;
   assert((await send('SET_FINDING_REVIEW',{findingKey:key,status:'resolved'})).ok);
   const edited=(await send('GET_STATE')).record;
   assert.equal(edited.findings[0].reviewHistory.length,1);
   assert.equal(edited.findings[0].reviewHistory[0].to,'resolved');
  }
  await send('STOP_CAPTURE');
 }
 const siteState=local.get('thi-v46-seen:'+encodeURIComponent('https://gallery.example'));
 assert.equal(siteState.length,1);assert.equal(siteState[0].fingerprint,'b'.repeat(64));
 // Disable desktop notifications for changes without disabling the red badge / evidence.
 local.set('secretChangeDesktopAlerts',false);session.delete('last-secret-notice:42');
 assert.equal((await send('START_CAPTURE')).ok,true);
 await cb.completed({tabId:42,url,type:'script',method:'GET',statusCode:200,initiator:'https://gallery.example',timeStamp:Date.now(),responseHeaders:[]});
 await new Promise(r=>setTimeout(r,35));
 payload.findings[0].fingerprint='c'.repeat(64);
 assert.equal((await send('AUTO_RESOURCE_SCAN',{payload},trusted)).ok,true);
 const suppressed=(await send('GET_STATE')).record;
 assert.equal(suppressed.findings[0].changeState,'changed');
 assert.equal(suppressed.unreviewedAlerts,1);
 assert.equal(notices.length,1,'change alert preference disables desktop notice only');
 await send('STOP_CAPTURE');
 assert(!JSON.stringify([...local]).includes('actual-secret'));
 console.log('PASS v4.6 worker: new / unchanged / changed HMAC evidence, review timeline and safe storage');
})().catch(e=>{console.error(e);process.exitCode=1});
