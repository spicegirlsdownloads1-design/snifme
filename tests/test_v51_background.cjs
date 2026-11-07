'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const local=new Map(),session=new Map(),hooks={};
const storage=map=>({get:async keys=>keys===null?Object.fromEntries(map):Array.isArray(keys)?Object.fromEntries(keys.map(k=>[k,map.get(k)])):{[keys]:map.get(keys)},set:async x=>{for(const [k,v] of Object.entries(x))map.set(k,v)},remove:async key=>map.delete(key)});
const listener=key=>({addListener:fn=>hooks[key]=fn});
const chrome={
 storage:{local:storage(local),session:storage(session)},
 tabs:{get:async()=>({url:'https://gallery.example/photos'}),sendMessage:async()=>({}),onUpdated:listener('updated'),onRemoved:listener('removed'),create:async()=>{}},
 scripting:{executeScript:async()=>{}},
 permissions:{contains:async()=>true,onRemoved:listener('permissionRemoved')},
 webRequest:{onBeforeRequest:listener('before'),onBeforeSendHeaders:listener('headers'),onBeforeRedirect:listener('redirect'),onCompleted:listener('completed'),onErrorOccurred:listener('error')},
 downloads:{onCreated:listener('downloadCreated'),onChanged:listener('downloadChanged')},
 action:{setBadgeText:async()=>{},setBadgeBackgroundColor:async()=>{}},
 notifications:{create:async()=>{},onClicked:listener('noticeClick'),onButtonClicked:listener('noticeButton')},
 runtime:{getURL:f=>'chrome-extension://internal/'+f,getManifest:()=>({version:'5.1.0'}),onMessage:listener('msg'),onInstalled:listener('installed')}
};
const ctx=vm.createContext({chrome,console,URL,URLSearchParams,Date,Promise,setTimeout,clearTimeout,AbortController,TextDecoder});ctx.globalThis=ctx;
ctx.importScripts=(...files)=>files.forEach(f=>vm.runInContext(fs.readFileSync(f,'utf8'),ctx,{filename:f}));
vm.runInContext(fs.readFileSync('background.js','utf8'),ctx,{filename:'background.js'});
const send=(type,props={},url='chrome-extension://internal/dashboard.html')=>new Promise(resolve=>hooks.msg({type,tabId:42,...props},{url},resolve));
const flush=async()=>new Promise(resolve=>setTimeout(resolve,85));
(async()=>{
  const secret='TOPSECRET_TEST_ONLY_513020', sig='SIG_XYZ_13057';
  assert.equal((await send('START_CAPTURE')).ok,true);
  assert.equal((await send('TOGGLE_DOWNLOAD_OBSERVER',{enabled:true},'https://gallery.example/photos')).ok,false,'website cannot arm observer');
  assert.equal((await send('TOGGLE_DOWNLOAD_OBSERVER',{enabled:true})).enabled,true);
  const q='https://gallery.example/api/download?X-Amz-Signature='+sig+'&access_token='+secret;
  const base={tabId:42,requestId:'22',url:q,method:'POST',type:'xmlhttprequest',timeStamp:Date.now()};
  hooks.before({...base,requestBody:{formData:{assetId:['18'],password:[secret],nonce:[sig]}}});
  hooks.headers({...base,requestHeaders:[{name:'authorization',value:secret},{name:'x-hmac-signature',value:sig}]});
  hooks.redirect({...base,redirectUrl:'https://cdn.example/p/'+secret+'?s='+sig,statusCode:302});
  hooks.completed({...base,statusCode:200,responseHeaders:[{name:'Content-Disposition',value:'attachment; filename="'+secret+'.jpg"'}]});
  await flush();
  const started=local.get('record:42');
  assert(started.downloadEvents.length>=4,'all lifecycle events recorded');
  assert(!JSON.stringify(started.downloadEvents).includes(secret),'raw bearer not saved');
  assert(!JSON.stringify(started.downloadEvents).includes(sig),'signature value not saved');
  assert(started.downloadEvents.some(e=>e.stage==='headers'&&e.headerIndicators.includes('Authorization header present')));
  assert(started.downloadEvents.some(e=>e.stage==='redirect'&&e.redirectHost==='cdn.example'));
  hooks.downloadCreated({id:701,referrer:'https://gallery.example/photos',finalUrl:'https://cdn.example/f/'+secret+'?s='+sig,filename:'C:/Users/'+secret+'.jpg'});
  await flush();
  assert(local.get('record:42').downloadEvents.some(e=>e.stage==='download-start'));
  hooks.downloadChanged({id:701,state:{current:'complete'}});
  await flush();
  assert(local.get('record:42').downloadEvents.some(e=>e.downloadStatus==='complete'));
  assert.equal((await send('TOGGLE_DOWNLOAD_OBSERVER',{enabled:false})).enabled,false);
  const before=local.get('record:42').downloadEvents.length;
  hooks.before({...base,requestId:'23'});await flush();
  assert.equal(local.get('record:42').downloadEvents.length,before);
  assert.equal((await send('STOP_CAPTURE')).ok,true);
  assert(!JSON.stringify(local.get('record:42').downloadEvents).includes(secret));
  console.log('PASS v5.1 background: explicit opt-in, no webpage enabling, POST/headers/redirect/download, disabled capture, privacy');
})().catch(e=>{console.error(e);process.exitCode=1;});
