'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const data=new Map(),session=new Map(),hooks={};
const storage=m=>({get:async keys=>keys===null?Object.fromEntries(m):Array.isArray(keys)?Object.fromEntries(keys.map(k=>[k,m.get(k)])):{[keys]:m.get(keys)},set:async o=>{for(const [k,v] of Object.entries(o))m.set(k,v)},remove:async k=>m.delete(k)});
const listen=k=>({addListener:fn=>hooks[k]=fn});
const chrome={storage:{local:storage(data),session:storage(session)},tabs:{get:async()=>({url:'https://dam.example/gallery'}),sendMessage:async()=>({}),onUpdated:listen('updated'),onRemoved:listen('removed'),create:async()=>{}},scripting:{executeScript:async()=>{}},permissions:{contains:async()=>true,onRemoved:listen('removedperm')},
 webRequest:{onBeforeRequest:listen('before'),onBeforeSendHeaders:listen('headers'),onHeadersReceived:listen('responseHeaders'),onBeforeRedirect:listen('redirect'),onCompleted:listen('complete'),onErrorOccurred:listen('error')},
 downloads:{onCreated:listen('created'),onChanged:listen('changed'),search:async()=>[]},action:{setBadgeText:async()=>{},setBadgeBackgroundColor:async()=>{}},notifications:{create:async()=>{},onClicked:listen('noticeClick'),onButtonClicked:listen('noticeButton')},runtime:{getURL:f=>'chrome-extension://local/'+f,getManifest:()=>({version:'5.9.0'}),onMessage:listen('msg'),onInstalled:listen('installed')}};
const ctx=vm.createContext({chrome,console,URL,URLSearchParams,Date,Promise,setTimeout,clearTimeout,AbortController,TextDecoder});ctx.globalThis=ctx;
ctx.importScripts=(...names)=>names.forEach(file=>vm.runInContext(fs.readFileSync(file,'utf8'),ctx,{filename:file}));
vm.runInContext(fs.readFileSync('background.js','utf8'),ctx,{filename:'background.js'});
const send=(type,props={})=>new Promise(resolve=>hooks.msg({type,tabId:49,...props},{url:'chrome-extension://local/dashboard.html'},resolve));
const flush=()=>new Promise(resolve=>setTimeout(resolve,140));
(async()=>{
 assert((await send('START_CAPTURE')).ok);
 assert((await send('TOGGLE_DOWNLOAD_OBSERVER',{enabled:true})).enabled);
 const secret='NEVER_STORE_X_AMZ_SECRET_K3973';
 const base={tabId:49,requestId:'req1',url:'https://storage.googleapis.com/upload/storage/v1/b/bucket/o?uploadType=resumable&key='+secret,method:'POST',type:'xmlhttprequest',timeStamp:Date.now()};
 hooks.before({...base,requestBody:{raw:[{bytes:[secret]}]}});
 hooks.complete({...base,statusCode:202,responseHeaders:[]});await flush();
 const stored=data.get('record:49').downloadEvents;
 assert(stored.some(e=>e.uploadProtocol?.provider==='Google Cloud Storage-compatible'));
 assert(!JSON.stringify(stored).includes(secret));
 assert((await send('TOGGLE_DOWNLOAD_OBSERVER',{enabled:false})).ok);
 const n=stored.length;hooks.before({...base,requestId:'second'});await flush();
 assert.equal(data.get('record:49').downloadEvents.length,n);
 console.log('PASS v5.6 worker: opt-in protocol evidence, secret values excluded, disabled observation');
})().catch(e=>{console.error(e);process.exitCode=1});
