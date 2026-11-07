'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const data=new Map(),session=new Map(),hooks={};
const storage=m=>({get:async keys=>keys===null?Object.fromEntries(m):Array.isArray(keys)?Object.fromEntries(keys.map(k=>[k,m.get(k)])):{[keys]:m.get(keys)},set:async o=>{for(const [k,v] of Object.entries(o))m.set(k,v)},remove:async k=>m.delete(k)});
const listen=k=>({addListener:fn=>hooks[k]=fn});
const chrome={storage:{local:storage(data),session:storage(session)},tabs:{get:async()=>({url:'https://dam.example/photo'}),sendMessage:async()=>({}),onUpdated:listen('updated'),onRemoved:listen('removed'),create:async()=>{}},scripting:{executeScript:async()=>{}},permissions:{contains:async()=>true,onRemoved:listen('permissionRemoved')},
 webRequest:{onBeforeRequest:listen('before'),onBeforeSendHeaders:listen('headers'),onHeadersReceived:listen('responseHeaders'),onBeforeRedirect:listen('redirect'),onCompleted:listen('complete'),onErrorOccurred:listen('error')},
 downloads:{onCreated:listen('created'),onChanged:listen('changed'),search:async()=>[{id:99,bytesReceived:800,totalBytes:1000,canResume:false,error:'SERVER_BAD_CONTENT',filename:'C:/SECRETFILE.jpg'}]},
 action:{setBadgeText:async()=>{},setBadgeBackgroundColor:async()=>{}},notifications:{create:async()=>{},onClicked:listen('noticeClick'),onButtonClicked:listen('noticeButton')},
 runtime:{getURL:f=>'chrome-extension://local/'+f,getManifest:()=>({version:'5.2.0'}),onMessage:listen('msg'),onInstalled:listen('installed')}};
const ctx=vm.createContext({chrome,console,URL,URLSearchParams,Date,Promise,setTimeout,clearTimeout,AbortController,TextDecoder});ctx.globalThis=ctx;
ctx.importScripts=(...names)=>names.forEach(file=>vm.runInContext(fs.readFileSync(file,'utf8'),ctx,{filename:file}));
vm.runInContext(fs.readFileSync('background.js','utf8'),ctx,{filename:'background.js'});
const send=(type,props={})=>new Promise(resolve=>hooks.msg({type,tabId:23,...props},{url:'chrome-extension://local/dashboard.html'},resolve));
const flush=()=>new Promise(resolve=>setTimeout(resolve,100));
(async()=>{
 assert((await send('START_CAPTURE')).ok);assert((await send('TOGGLE_DOWNLOAD_OBSERVER',{enabled:true})).enabled);
 const base={tabId:23,requestId:'req-1',url:'https://dam.example/download?token=SECRETFILE',method:'POST',type:'xmlhttprequest',timeStamp:Date.now()};
 hooks.before({...base,requestBody:{formData:{assetId:['asset1'],token:['SECRETFILE']}}});
 hooks.headers({...base,requestHeaders:[{name:'authorization',value:'Bearer SECRETFILE'},{name:'traceparent',value:'00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'}]});
 hooks.responseHeaders({...base,statusCode:200,responseHeaders:[{name:'cache-control',value:'private, max-age=120'},{name:'content-length',value:'1000'},{name:'x-amz-cf-id',value:'SECRETFILE'}]});
 hooks.complete({...base,statusCode:200,responseHeaders:[{name:'content-type',value:'image/jpeg'}]});
 await flush();let ev=data.get('record:23').downloadEvents;
 assert(ev.some(x=>x.traceRef==='Trace 1'));assert(ev.some(x=>x.cachePolicy==='private'));assert(ev.some(x=>x.contentLengthBytes===1000));
 hooks.created({id:99,referrer:'https://dam.example/photo',finalUrl:'https://cdn.example/?sig=SECRETFILE',filename:'C:/SECRETFILE.jpg',totalBytes:1000,bytesReceived:0});
 await flush();hooks.changed({id:99,state:{current:'interrupted'},error:{current:'SERVER_BAD_CONTENT'}});await flush();
 ev=data.get('record:23').downloadEvents;
 assert(ev.some(x=>x.downloadStatus==='interrupted'&&x.errorCategory==='server'&&x.receivedBytes===800));
 assert(!JSON.stringify(ev).includes('SECRETFILE'));assert(!JSON.stringify(ev).includes('4bf92f3577b34da6a3ce929d0e0e4736'));
 await send('TOGGLE_DOWNLOAD_OBSERVER',{enabled:false});let count=data.get('record:23').downloadEvents.length;
 hooks.responseHeaders({...base,requestId:'req-2',responseHeaders:[]});await flush();assert.equal(data.get('record:23').downloadEvents.length,count);
 console.log('PASS v5.2 background trace+response+download lifecycle, privacy, opt-in');
})().catch(e=>{console.error(e);process.exitCode=1});
