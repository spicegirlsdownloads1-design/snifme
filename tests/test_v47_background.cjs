'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const local=new Map(),session=new Map(),hooks={};
const storage=map=>({get:async key=>key===null?Object.fromEntries(map):({[key]:map.get(key)}),set:async values=>{for(const [k,v]of Object.entries(values))map.set(k,v)},remove:async key=>map.delete(key)});
const chrome={storage:{local:storage(local),session:storage(session)},
  tabs:{get:async()=>({id:17,url:'https://gallery.test/g'}),sendMessage:async()=>({}),onUpdated:{addListener:f=>hooks.updated=f},onRemoved:{addListener:f=>hooks.removed=f}},
  scripting:{executeScript:async()=>{}},action:{setBadgeText:async()=>{},setBadgeBackgroundColor:async()=>{}},
  webRequest:{onCompleted:{addListener:f=>hooks.completed=f},onErrorOccurred:{addListener:f=>hooks.failed=f}},
  runtime:{onMessage:{addListener:f=>hooks.message=f},onInstalled:{addListener:f=>hooks.installed=f},getURL:path=>'chrome-extension://fixture/'+path}};
const ctx=vm.createContext({chrome,console,URL,URLSearchParams,Date,Promise,setTimeout,clearTimeout,AbortController,TextDecoder,TextEncoder});ctx.globalThis=ctx;
ctx.importScripts=(...names)=>names.forEach(n=>vm.runInContext(fs.readFileSync(n,'utf8'),ctx,{filename:n}));
vm.runInContext(fs.readFileSync('background.js','utf8'),ctx,{filename:'background.js'});
const send=(type,extra={},sender={})=>new Promise(resolve=>hooks.message({type,tabId:17,...extra},sender,resolve));
(async()=>{
 assert.equal((await send('START_CAPTURE')).ok,true);
 const payload={embeddedContexts:[
  {kind:'embedded-frame',origin:'https://cdn.test/frame?token=REALLYSECRET',sandboxed:true,evidence:'iframe element'},
  {kind:'controlled-service-worker',origin:'https://gallery.test/sw.js?key=REALLYSECRET',evidence:'service worker controller'},
  {kind:'worker-resource-hint',origin:'https://cdn.test/worker.js?q=REALLYSECRET',evidence:'resource timing hint'},
  {kind:'embedded-frame',origin:'javascript:alert(1)',evidence:'iframe element'}]};
 const sender={tab:{id:17},frameId:0,url:'https://gallery.test/g'};
 assert.equal((await send('PAGE_REPORT',{payload},{...sender,frameId:2})).ok,false);
 assert.equal((await send('PAGE_REPORT',{payload},sender)).ok,true);
 const rec=(await send('GET_STATE')).record;
 assert.equal(rec.embeddedContexts.length,3);
 assert(!JSON.stringify(rec).includes('REALLYSECRET'));
 assert(!JSON.stringify(rec).includes('/sw.js'));
 assert.equal(rec.embeddedContexts.filter(x=>x.relationship==='same-origin').length,1);
 await send('STOP_CAPTURE');
 const after=(await send('PAGE_REPORT',{payload},sender));assert.equal(after.ok,false);
 console.log('PASS v4.7 worker intake: frame-origin gate, permission scope, sanitised facts, stopped capture');
})().catch(e=>{console.error(e);process.exitCode=1});
