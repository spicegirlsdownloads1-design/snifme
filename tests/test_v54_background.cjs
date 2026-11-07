'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const data=new Map(),session=new Map(),hooks={};
const storage=m=>({get:async keys=>keys===null?Object.fromEntries(m):Array.isArray(keys)?Object.fromEntries(keys.map(k=>[k,m.get(k)])):{[keys]:m.get(keys)},set:async o=>{for(const [k,v] of Object.entries(o))m.set(k,v)},remove:async k=>m.delete(k)});
const listen=k=>({addListener:fn=>hooks[k]=fn});
const chrome={storage:{local:storage(data),session:storage(session)},tabs:{get:async()=>({url:'https://dam.example/gallery'}),sendMessage:async()=>({}),onUpdated:listen('updated'),onRemoved:listen('removed'),create:async()=>{}},scripting:{executeScript:async()=>{}},permissions:{contains:async()=>true,onRemoved:listen('permissionRemoved')},
 webRequest:{onBeforeRequest:listen('before'),onBeforeSendHeaders:listen('headers'),onHeadersReceived:listen('responseHeaders'),onBeforeRedirect:listen('redirect'),onCompleted:listen('complete'),onErrorOccurred:listen('error')},
 downloads:{onCreated:listen('created'),onChanged:listen('changed'),search:async()=>[]},
 action:{setBadgeText:async()=>{},setBadgeBackgroundColor:async()=>{}},notifications:{create:async()=>{},onClicked:listen('noticeClick'),onButtonClicked:listen('noticeButton')},
 runtime:{getURL:f=>'chrome-extension://local/'+f,getManifest:()=>({version:'5.9.0'}),onMessage:listen('msg'),onInstalled:listen('installed')}};
const ctx=vm.createContext({chrome,console,URL,URLSearchParams,Date,Promise,setTimeout,clearTimeout,AbortController,TextDecoder});ctx.globalThis=ctx;
ctx.importScripts=(...names)=>names.forEach(file=>vm.runInContext(fs.readFileSync(file,'utf8'),ctx,{filename:file}));
vm.runInContext(fs.readFileSync('background.js','utf8'),ctx,{filename:'background.js'});
const send=(type,props={})=>new Promise(resolve=>hooks.msg({type,tabId:49,...props},{url:'chrome-extension://local/dashboard.html'},resolve));
const flush=()=>new Promise(resolve=>setTimeout(resolve,125));
(async()=>{
 assert((await send('START_CAPTURE')).ok);
 assert((await send('TOGGLE_DOWNLOAD_OBSERVER',{enabled:true})).enabled);
 const secret='PLEASE_NEVER_PERSIST_983123';
 const base={tabId:49,requestId:'upload-1',url:'https://sample.s3.eu-west-2.amazonaws.com/?X-Amz-Signature='+secret,method:'POST',type:'xmlhttprequest',timeStamp:Date.now()};
 hooks.before({...base,requestBody:{formData:{policy:[secret],key:['private/'+secret],
 'x-amz-credential':[secret],'x-amz-signature':[secret],
 'x-amz-security-token':[secret],file:[secret]}}});
 hooks.headers({...base,requestHeaders:[{name:'Authorization',value:'AWS4-HMAC-SHA256 Credential='+secret+', Signature='+secret}]});
 hooks.complete({...base,statusCode:204,responseHeaders:[{name:'content-length',value:'0'}]});
 await flush();
 const ev=data.get('record:49').downloadEvents;
 assert.equal(data.get('record:49').downloadObserverEverEnabled,true,'opt-in persisted');
 assert(ev.some(x=>x.awsDam?.operation==='S3 presigned POST request observed'));
 assert(ev.some(x=>x.awsDam?.fieldTypes?.includes('Temporary session-token field')));
 assert(!JSON.stringify(ev).includes(secret));
 assert(!JSON.stringify(ev).includes('/private/'));
 assert(!JSON.stringify(ev).includes('Credential='+secret));
 hooks.created({id:85,referrer:'https://dam.example/gallery',finalUrl:'https://dam.example/export.zip?token='+secret,filename:'C:/file-'+secret+'.zip'});
 await flush();
 const first=data.get('record:49').downloadEvents.find(x=>x.stage==='download-start');
 assert(/^DL\d+$/.test(first?.downloadRef),'new local download label, not Chrome ID');
 hooks.changed({id:85,state:{current:'complete'}});await flush();
 const ends=data.get('record:49').downloadEvents.find(x=>x.stage==='download-state');
 assert.equal(ends.downloadRef,first.downloadRef);
 assert(!JSON.stringify(data.get('record:49').downloadEvents).includes(secret));
 assert((await send('TOGGLE_DOWNLOAD_OBSERVER',{enabled:false})).ok);
 const before=data.get('record:49').downloadEvents.length;
 hooks.before({...base,requestId:'upload-2'});await flush();
 assert.equal(data.get('record:49').downloadEvents.length,before);
 console.log('PASS v5.4 background opt-in S3 form observation, no body values and disable');
})().catch(e=>{console.error(e);process.exitCode=1});
