'use strict';
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const crypto=require('node:crypto');
const local=new Map(),session=new Map();
let current='https://first.example.invalid/a';
const makeStorage=(map)=>({
 get:async (keys)=>keys===null?Object.fromEntries(map):Array.isArray(keys)?Object.fromEntries(keys.map(k=>[k,map.get(k)])):{[keys]:map.get(keys)},
 set:async data=>{for(const [k,v] of Object.entries(data))map.set(k,v)},
 remove:async keys=>{for(const k of Array.isArray(keys)?keys:[keys])map.delete(k)}
});
function worker(){
 const callbacks={};
 const chrome={
  storage:{local:makeStorage(local),session:makeStorage(session)},
  tabs:{get:async tabId=>({id:tabId,url:current}),query:async()=>[{id:55,url:current}],sendMessage:async()=>({ok:true}),
    onUpdated:{addListener:fn=>callbacks.tabUpdated=fn},onRemoved:{addListener:fn=>callbacks.tabRemoved=fn}},
  scripting:{executeScript:async()=>{}},permissions:{contains:async()=>true,onRemoved:{addListener:()=>{}}},
  action:{setBadgeText:async()=>{},setBadgeBackgroundColor:async()=>{}},
  notifications:{create:async()=>{},onClicked:{addListener:()=>{}},onButtonClicked:{addListener:()=>{}}},
  downloads:{onCreated:{addListener:fn=>callbacks.downloadStart=fn},onChanged:{addListener:fn=>callbacks.downloadChange=fn},
    search:async ({id})=>[{id,mime:'image/jpeg',totalBytes:1245,bytesReceived:1245}]},
  webRequest:{onBeforeRequest:{addListener:fn=>callbacks.requestStart=fn},onBeforeSendHeaders:{addListener:()=>{}},onHeadersReceived:{addListener:()=>{}},onBeforeRedirect:{addListener:()=>{}},onCompleted:{addListener:fn=>callbacks.requestEnd=fn},onErrorOccurred:{addListener:fn=>callbacks.requestError=fn}},
  runtime:{getURL:x=>'chrome-extension://test/'+x,getManifest:()=>require('../manifest.json'),onMessage:{addListener:fn=>callbacks.message=fn},onInstalled:{addListener:()=>{}},onStartup:{addListener:()=>{}}}
 };
 const context=vm.createContext({chrome,URL,URLSearchParams,console,Date,Promise,setTimeout,clearTimeout,AbortController,TextDecoder,TextEncoder,crypto:crypto.webcrypto});context.globalThis=context;
 context.importScripts=(...files)=>files.forEach(f=>vm.runInContext(fs.readFileSync(f,'utf8'),context,{filename:f}));
 vm.runInContext(fs.readFileSync('background.js','utf8'),context,{filename:'background.js'});
 const send=(type,data={})=>new Promise(resolve=>callbacks.message({type,tabId:55,...data},{url:chrome.runtime.getURL('popup.html')},resolve));
 return {callbacks,send};
}
const delay=()=>new Promise(resolve=>setTimeout(resolve,110));
const headers=[{name:'Content-Type',value:'application/json'}];
const req=(url,id,type='xmlhttprequest')=>({tabId:55,url,documentUrl:current,method:'GET',type,requestId:id,timeStamp:Date.now(),statusCode:200,responseHeaders:headers});
(async()=>{
 let w=worker();
 let first=req(current,'nav-a','main_frame');w.callbacks.requestStart(first);await delay();w.callbacks.requestEnd(first);await delay();
 let original=await w.send('GET_STATE');assert.equal(original.record.requests.length,1);
 const old=req('https://old-cdn.example.invalid/images/old.jpg','old-asset','image');
 w.callbacks.requestStart(old);
 current='https://second.example.invalid/b';const next=req(current,'nav-b','main_frame');
 w.callbacks.requestStart(next);await delay();
 // The stale request began before navigation, but finished afterwards.
 const stale={...old,timeStamp:Date.now()+100,documentUrl:'https://first.example.invalid/a'};
 w.callbacks.requestEnd(stale);w.callbacks.requestEnd(next);await delay();
 let state=await w.send('GET_STATE');
 assert.equal(state.recording.origin,'https://second.example.invalid');
 assert.equal(state.record.requests.length,1,'old-page response must not pollute the new capture');
 const cdn=req('https://third.example.invalid/file.png','new-cdn','image');
 w.callbacks.requestStart(cdn);w.callbacks.requestEnd({...cdn,timeStamp:Date.now()});await delay();
 state=await w.send('GET_STATE');assert.equal(state.record.requests.length,2,'current CDN request should be kept with its request-start generation');
 // Missing start and no initiator/document evidence are not attributed to a new site.
 const ambiguous={...req('https://other.example.invalid/unknown.jpg','unknown-new','image'),documentUrl:'',initiator:''};
 w.callbacks.requestEnd(ambiguous);await delay();
 assert.equal((await w.send('GET_STATE')).record.requests.length,2);
 // Browser downloads are linked to a capture only with an unambiguous referrer origin.
 // Simulate a long session with stale pending download checkpoints.
 for(let id=100;id<615;id++)session.set('pending-download:'+id,{tabId:55,downloadRef:'DL12345678901230001',sessionId:'old',origin:'https://second.example.invalid',at:Date.now()-5*3600*1000});
 w.callbacks.downloadStart({id:37,referrer:'https://second.example.invalid/b',url:'https://media.example.invalid/allowed.jpg',mime:'image/jpeg',state:'in_progress',startTime:new Date().toISOString()});
 await delay();
 assert(session.has('pending-download:37'));
 assert([...session.keys()].filter(k=>k.startsWith('pending-download:')).length<=500,'pending download checkpoints must stay bounded');
 const before=await w.send('GET_STATE');
 assert(before.record.downloadEvents.some(e=>e.stage==='download-start'));
 // Restart the MV3 worker: its ordinary Map is gone, chrome.storage.session remains.
 w=worker();w.callbacks.downloadChange({id:37,state:{current:'complete'}});await delay();
 state=await w.send('GET_STATE');
 assert(state.record.downloadEvents.some(e=>e.stage==='download-state'&&e.downloadStatus==='complete'));
 assert.equal(session.has('pending-download:37'),false,'terminal download must remove restart checkpoint');
 const full=JSON.stringify(state.record);
 assert(!full.includes('https://media.example.invalid/allowed.jpg'),'download URL must not leak into stored record');
 console.log('PASS v7.17 stale navigation completion filtering, eligible CDN traffic, ambiguous evidence exclusion, MV3 pending-download restart recovery');
})().catch(err=>{console.error(err);process.exitCode=1});
