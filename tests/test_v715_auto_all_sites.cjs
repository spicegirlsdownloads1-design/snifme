'use strict';
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const crypto=require('node:crypto');
const manifest=require('../manifest.json');
assert.equal(manifest.version,'7.19.0');
assert.deepEqual(manifest.host_permissions,['http://*/*','https://*/*']);
assert.equal(manifest.optional_host_permissions,undefined);
assert.equal('debugger' in manifest.permissions,false);
const l=new Map(),ss=new Map(),listeners={};
let currentUrl='https://unknown-a.test/index';
function storage(map){return {
  get:async key=>key===null?Object.fromEntries(map):Array.isArray(key)?Object.fromEntries(key.map(k=>[k,map.get(k)])):{[key]:map.get(key)},
  set:async x=>{for(const [k,v] of Object.entries(x))map.set(k,v)},
  remove:async x=>{for(const k of Array.isArray(x)?x:[x])map.delete(k)}
};}
const chrome={
 storage:{local:storage(l),session:storage(ss)},
 tabs:{get:async id=>({id,url:currentUrl}),query:async()=>[{id:55,url:currentUrl}],sendMessage:async()=>({ok:true}),
   onUpdated:{addListener:fn=>listeners.updated=fn},onRemoved:{addListener:fn=>listeners.removed=fn}},
 scripting:{executeScript:async()=>{}},
 permissions:{contains:async arg=>arg.origins.every(x=>!x.includes('restricted.test')),onRemoved:{addListener:fn=>listeners.permRemoved=fn}},
 action:{setBadgeText:async()=>{},setBadgeBackgroundColor:async()=>{}},
 notifications:{create:async()=>{},onClicked:{addListener:()=>{}},onButtonClicked:{addListener:()=>{}}},
 downloads:{onCreated:{addListener:()=>{}},onChanged:{addListener:()=>{}},search:async()=>[]},
 webRequest:{onBeforeRequest:{addListener:fn=>listeners.before=fn},onBeforeSendHeaders:{addListener:()=>{}},onHeadersReceived:{addListener:()=>{}},onBeforeRedirect:{addListener:()=>{}},onCompleted:{addListener:fn=>listeners.completed=fn},onErrorOccurred:{addListener:fn=>listeners.error=fn}},
 runtime:{getURL:x=>'chrome-extension://test/'+x,getManifest:()=>manifest,onMessage:{addListener:fn=>listeners.msg=fn},onInstalled:{addListener:fn=>listeners.installed=fn},onStartup:{addListener:fn=>listeners.startup=fn}}
};
const ctx=vm.createContext({chrome,URL,URLSearchParams,console,Date,Promise,setTimeout,clearTimeout,AbortController,TextDecoder,TextEncoder,crypto:crypto.webcrypto});ctx.globalThis=ctx;
ctx.importScripts=(...paths)=>paths.forEach(p=>vm.runInContext(fs.readFileSync(p,'utf8'),ctx,{filename:p}));
vm.runInContext(fs.readFileSync('background.js','utf8'),ctx,{filename:'background.js'});
const send=(type,extra={},sender={})=>new Promise(ok=>listeners.msg({type,tabId:55,...extra},sender,ok));
const delay=()=>new Promise(ok=>setTimeout(ok,100));
const begin=(url,timeStamp=Date.now()-50)=>listeners.before({tabId:55,type:'main_frame',url,method:'GET',timeStamp,requestId:'synthetic-1'});
const finish=(url,timeStamp=Date.now()-40)=>listeners.completed({tabId:55,type:'main_frame',url,method:'GET',timeStamp,statusCode:200,responseHeaders:[{name:'Content-Type',value:'text/html'}]});
(async()=>{
 assert.equal((await send('GET_AUTO_CAPTURE')).enabled,true);
 begin(currentUrl);await delay();finish(currentUrl);await delay();
 let state=await send('GET_STATE');
 assert.equal(state.recording.origin,'https://unknown-a.test');
 assert.equal(state.recording.enabled,true);
 for(const k of ['responseShapes','verifyImages','viewerManifests','autoSecretScan','verifyMetadata','verifyVisual','downloadObserver'])assert.equal(state.recording[k],true,k);
 assert.equal(state.record.requests.length,1,'navigation must be recorded even when storage starts asynchronously');
 assert.equal(state.record.requests[0].status,200);
 // First-party and third-party resources from this page are recorded within tab scope.
 listeners.completed({tabId:55,type:'xmlhttprequest',documentUrl:'https://unknown-a.test/index',url:'https://cdn.unknown-b.test/api?q=hello&token=SECRET_DO_NOT_SAVE',method:'GET',timeStamp:Date.now(),statusCode:200,responseHeaders:[{name:'Content-Type',value:'application/json'}]});
 await delay();state=await send('GET_STATE');assert.equal(state.record.requests.length,2);
 assert(!JSON.stringify(state.record).includes('SECRET_DO_NOT_SAVE'));
 // A new origin automatically starts a new capture; it never mixes previous records.
 currentUrl='https://unknown-b.test/gallery';begin(currentUrl);await delay();finish(currentUrl);await delay();
 state=await send('GET_STATE');assert.equal(state.recording.origin,'https://unknown-b.test');
 assert.equal(state.record.requests.length,1);
 // Global pause terminates active sessions and prevents the next navigation capture.
 const ui={url:chrome.runtime.getURL('popup.html')};
 assert.equal((await send('SET_AUTO_CAPTURE',{enabled:false},ui)).enabled,false);
 assert.equal((await send('GET_STATE')).recording,null);
 currentUrl='https://unknown-c.test/';begin(currentUrl);await delay();
 assert.equal((await send('GET_STATE')).recording,null);
 // Resume starts capture on existing, permitted HTTP(S) tabs again.
 assert.equal((await send('SET_AUTO_CAPTURE',{enabled:true},ui)).enabled,true);
 state=await send('GET_STATE');assert.equal(state.recording.origin,'https://unknown-c.test');
 // Chrome restrictions are respected: missing permission must not be overridden.
 currentUrl='https://restricted.test/';begin(currentUrl);await delay();
 state=await send('GET_STATE');assert.equal(state.recording.origin,'https://unknown-c.test');
 assert.equal((await send('SET_AUTO_CAPTURE',{enabled:false},{url:'https://thirdparty.test/'})).ok,false);
 console.log('PASS v7.15 automatic navigation, default-on switches, sanitized records, new-origin separation, pause/resume and Chrome permission gating');
})().catch(e=>{console.error(e);process.exitCode=1;});
