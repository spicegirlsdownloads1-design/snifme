'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const local=new Map(),session=new Map(),listeners={};
const storage=map=>({get:async k=>k===null?Object.fromEntries(map):{[k]:map.get(k)},set:async vals=>{for(const [k,v]of Object.entries(vals))map.set(k,v)},remove:async k=>map.delete(k)});
const chrome={
 storage:{local:storage(local),session:storage(session)},
 tabs:{get:async()=>({url:'http://127.0.0.1:8765/acceptance-lab.html'}),sendMessage:async()=>({ok:true,inspectorPresent:true,observing:true,origin:'http://127.0.0.1:8765'}),onUpdated:{addListener:()=>{}},onRemoved:{addListener:()=>{}}},
 scripting:{executeScript:async()=>{}},
 permissions:{contains:async()=>true,onRemoved:{addListener:()=>{}}},
 action:{setBadgeText:async()=>{},setBadgeBackgroundColor:async()=>{}},
 webRequest:{onCompleted:{addListener:()=>{}},onErrorOccurred:{addListener:()=>{}}},
 runtime:{getURL:s=>'chrome-extension://internal/'+s,onMessage:{addListener:f=>listeners.message=f},onInstalled:{addListener:()=>{}}}
};
const ctx=vm.createContext({chrome,console,URL,URLSearchParams,Date,Promise,setTimeout,clearTimeout,AbortController,TextDecoder});ctx.globalThis=ctx;
ctx.importScripts=(...files)=>files.forEach(f=>vm.runInContext(fs.readFileSync(f,'utf8'),ctx,{filename:f}));
vm.runInContext(fs.readFileSync('background.js','utf8'),ctx,{filename:'background.js'});
const send=(type,url)=>new Promise(resolve=>listeners.message({type,tabId:42},{url},resolve));
(async()=>{
 const token='PRIVATE_DO_NOT_EXPORT_THIS_TOKEN';
 const rec={origin:'http://127.0.0.1:8765',sessionId:'fake',createdAt:new Date().toISOString(),
  requests:[{url:'http://127.0.0.1:8765/test?token='+token,status:200}],
  findings:[{type:'Named secret assignment',masked:'some…[redacted]'}],
  autoScanCoverage:{eligible:2,scanned:2},devtoolsHeartbeatAt:new Date().toISOString(),counters:{requestsDropped:0}};
 await chrome.storage.local.set({'record:42':rec});
 await chrome.storage.session.set({'active:42':{origin:'http://127.0.0.1:8765',enabled:true}});
 const denied=await send('GET_ACCEPTANCE_REPORT','http://127.0.0.1:8765/acceptance-lab.html');assert.equal(denied.ok,false);
 const accepted=await send('GET_ACCEPTANCE_REPORT','chrome-extension://internal/dashboard.html');assert.equal(accepted.ok,true);
 assert.equal(accepted.report.checks.find(x=>x.id==='requests').status,'pass');
 assert.equal(accepted.report.checks.find(x=>x.id==='content').status,'pass');
 assert.equal(accepted.report.checks.find(x=>x.id==='response-scanning').status,'pass');
 assert.equal(accepted.report.checks.find(x=>x.id==='desktop-notification').status,'not-tested');
 const json=JSON.stringify(accepted);
 assert(!json.includes(token));assert(!json.includes('http://127.0.0.1:8765'));
 console.log('PASS v5.0 worker: extension-only acceptance, real stored counters, active content response, no URL/secret leak');
})().catch(e=>{console.error(e);process.exitCode=1});
