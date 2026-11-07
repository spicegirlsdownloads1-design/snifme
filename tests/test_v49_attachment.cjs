'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm'),crypto=require('node:crypto');
const local=new Map(),session=new Map(),listeners={};
const storage=m=>({get:async k=>k===null?Object.fromEntries(m):{[k]:m.get(k)},set:async obj=>{for(const [k,v]of Object.entries(obj))m.set(k,v)},remove:async k=>m.delete(k)});
const chrome={storage:{local:storage(local),session:storage(session)},tabs:{get:async()=>({id:88,url:'https://gallery.test/photos'}),sendMessage:async()=>({}),onUpdated:{addListener:f=>listeners.updated=f},onRemoved:{addListener:f=>listeners.removed=f}},scripting:{executeScript:async()=>{}},action:{setBadgeText:async()=>{},setBadgeBackgroundColor:async()=>{}},webRequest:{onCompleted:{addListener:f=>listeners.completed=f},onErrorOccurred:{addListener:f=>listeners.error=f}},runtime:{onMessage:{addListener:f=>listeners.message=f},onInstalled:{addListener:f=>listeners.installed=f},getURL:s=>'chrome-extension://test/'+s}};
const ctx=vm.createContext({chrome,console,URL,URLSearchParams,Date,Promise,setTimeout,clearTimeout,AbortController,TextDecoder,TextEncoder,crypto:crypto.webcrypto});ctx.globalThis=ctx;ctx.importScripts=(...files)=>files.forEach(f=>vm.runInContext(fs.readFileSync(f,'utf8'),ctx,{filename:f}));vm.runInContext(fs.readFileSync('background.js','utf8'),ctx,{filename:'background.js'});
const send=type=>new Promise(resolve=>listeners.message({type,tabId:88},{},resolve));
(async()=>{
 assert((await send('START_CAPTURE')).ok);
 await listeners.completed({tabId:88,documentUrl:'https://gallery.test/photos',url:'https://media.test/download/image.jpeg?token=FORBIDDEN_TOKEN',type:'other',statusCode:200,method:'GET',timeStamp:Date.now(),responseHeaders:[
 {name:'Content-Type',value:'application/octet-stream'},{name:'Content-Disposition',value:'attachment; filename="PRIVATE_CUSTOMER_ID_SECRET.jpg"'},
 {name:'Cache-Control',value:'private, max-age=3600'}]});
 for(let i=0;i<24;i++)await Promise.resolve();
 const state=await send('GET_STATE');assert.equal(state.record.requests.length,1);
 const event=state.record.requests[0];assert.equal(event.attachmentDisposition,true);
 assert.equal(event.cacheScope,'private');
 assert(!JSON.stringify(state.record).includes('PRIVATE_CUSTOMER_ID_SECRET'));
 assert(!JSON.stringify(state.record).includes('FORBIDDEN_TOKEN'));
 assert(!JSON.stringify(state.record).includes('Content-Disposition'));
 console.log('PASS v4.9 background: attachment flag recorded; filenames, raw headers and signed tokens discarded');
})().catch(e=>{console.error(e);process.exitCode=1});
