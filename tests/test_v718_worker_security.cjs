'use strict';
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const crypto=require('node:crypto');
const local=new Map(),session=new Map(),callbacks={};
const makeStorage=map=>({get:async keys=>keys===null?Object.fromEntries(map):Array.isArray(keys)?Object.fromEntries(keys.map(k=>[k,map.get(k)])):{[keys]:map.get(keys)},set:async data=>{for(const [k,v] of Object.entries(data))map.set(k,v)},remove:async keys=>{for(const k of Array.isArray(keys)?keys:[keys])map.delete(k)}});
const host='https://app.example.invalid',token='THIS_IS_A_FAKE_NON_WORKING_TOKEN_123456';
const chrome={
 storage:{local:makeStorage(local),session:makeStorage(session)},
 tabs:{get:async id=>({id,url:host+'/home'}),query:async()=>[{id:22,url:host+'/home'}],sendMessage:async()=>({ok:true}),onUpdated:{addListener:fn=>callbacks.tabUpdated=fn},onRemoved:{addListener:fn=>callbacks.tabRemoved=fn}},
 scripting:{executeScript:async()=>{}},permissions:{contains:async()=>true,onRemoved:{addListener:()=>{}}},
 action:{setBadgeText:async()=>{},setBadgeBackgroundColor:async()=>{}},
 notifications:{create:async()=>{},onClicked:{addListener:()=>{}},onButtonClicked:{addListener:()=>{}}},
 downloads:{onCreated:{addListener:()=>{}},onChanged:{addListener:()=>{}},search:async()=>[]},
 webRequest:{onBeforeRequest:{addListener:fn=>callbacks.before=fn},onBeforeSendHeaders:{addListener:fn=>callbacks.reqHeaders=fn},onHeadersReceived:{addListener:fn=>callbacks.respHeaders=fn},onBeforeRedirect:{addListener:fn=>callbacks.redirect=fn},onCompleted:{addListener:fn=>callbacks.complete=fn},onErrorOccurred:{addListener:fn=>callbacks.error=fn}},
 runtime:{getURL:x=>'chrome-extension://test/'+x,getManifest:()=>require('../manifest.json'),onMessage:{addListener:fn=>callbacks.message=fn},onInstalled:{addListener:()=>{}},onStartup:{addListener:()=>{}}}
};
const context=vm.createContext({chrome,URL,URLSearchParams,console,Date,Promise,setTimeout,clearTimeout,AbortController,TextDecoder,TextEncoder,crypto:crypto.webcrypto});context.globalThis=context;
context.importScripts=(...files)=>files.forEach(f=>vm.runInContext(fs.readFileSync(f,'utf8'),context,{filename:f}));
vm.runInContext(fs.readFileSync('background.js','utf8'),context,{filename:'background.js'});
const send=(type)=>new Promise(resolve=>callbacks.message({type,tabId:22},{url:chrome.runtime.getURL('popup.html')},resolve));
const delay=()=>new Promise(resolve=>setTimeout(resolve,200));
const ts=()=>Date.now();
(async()=>{
 callbacks.before({tabId:22,type:'main_frame',requestId:'NAV-1',url:host+'/home',method:'GET',timeStamp:ts()});await delay();
 const url='https://api.example.invalid/api/auth/reset?access_token='+token;
 const d={tabId:22,type:'xmlhttprequest',requestId:'API-1',url,documentUrl:host+'/home',initiator:host,method:'POST',timeStamp:ts(),statusCode:302};
 callbacks.before({...d,requestBody:{formData:{client_secret:[token],csrf_token:[token]}}});
 callbacks.reqHeaders({...d,requestHeaders:[{name:'Referer',value:host+'/callback?access_token='+token}]});
 callbacks.respHeaders({...d,responseHeaders:[{name:'Access-Control-Allow-Origin',value:'*'},{name:'Access-Control-Allow-Credentials',value:'true'}]});
 callbacks.redirect({...d,redirectUrl:'https://idp.example.invalid/callback?code='+token});
 await delay();
 const state=await send('GET_STATE');assert(state.ok);
 const obs=state.record.securityObservations||[],ids=obs.map(o=>o.ruleId);
 for(const id of ['SECRET_QUERY','MUTATION_CONTEXT','FORM_FIELD_CONTEXT','REFERER_SECRET','CORS_WILDCARD_CREDENTIALS','OAUTH_REDIRECT_DATA'])assert(ids.includes(id),'missing '+id);
 assert(!JSON.stringify(state.record).includes(token),'worker may not store synthetic token in live record');
 assert(!obs.some(x=>x.route.includes('callback')&&x.route.includes(token)));
 assert(!state.record.securityObservationsDropped);
 console.log('PASS v7.18 integrated MV3 worker request/headers/redirect security capture and raw-token exclusion');
})().catch(e=>{console.error(e);process.exitCode=1});
