const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const local=new Map(),session=new Map(),cb={};
const store=m=>({get:async k=>k===null?Object.fromEntries(m):{[k]:m.get(k)},set:async o=>{for(const [k,v] of Object.entries(o))m.set(k,v)},remove:async k=>m.delete(k)});
const chrome={storage:{local:store(local),session:store(session)},
 tabs:{get:async()=>({id:21,url:'https://gallery.test/page'}),sendMessage:async()=>({}),onUpdated:{addListener:f=>cb.updated=f},onRemoved:{addListener:f=>cb.removed=f}},
 scripting:{executeScript:async()=>{}},action:{setBadgeText:async()=>{},setBadgeBackgroundColor:async()=>{}},
 webRequest:{onCompleted:{addListener:f=>cb.completed=f},onErrorOccurred:{addListener:f=>cb.failed=f}},
 runtime:{onMessage:{addListener:f=>cb.message=f},onInstalled:{addListener:f=>cb.installed=f},getURL:p=>'chrome-extension://fixture/'+p}};
const ctx=vm.createContext({chrome,console,URL,URLSearchParams,Date,Promise,setTimeout,clearTimeout,AbortController,TextDecoder,TextEncoder});ctx.globalThis=ctx;
ctx.importScripts=(...files)=>files.forEach(f=>vm.runInContext(fs.readFileSync(f,'utf8'),ctx,{filename:f}));
vm.runInContext(fs.readFileSync('background.js','utf8'),ctx,{filename:'background.js'});
const send=(type,p={},sender={})=>new Promise(resolve=>cb.message({type,tabId:21,...p},sender,resolve));
(async()=>{
 assert.equal((await send('START_CAPTURE')).ok,true);
 const origin='https://gallery.test';
 const sender={tab:{id:21},frameId:0,url:origin+'/page'};
 const data={frameCoverage:[{index:1,status:'inspected',origin,inlineScripts:2,inspectedCharacters:100},
 {index:2,status:'inspected',origin:'https://wrong.test',inlineScripts:11},
 {index:3,status:'cross-origin',origin:'https://external.test?secret=TOKEN'}],
 workerScripts:[{url:origin+'/service-worker.js?token=NEVER_SAVE',kind:'controller-reference',inspected:false},
 {url:'https://external.test/w.js',kind:'controller-reference',inspected:false}],
 findings:[{type:'GitHub token indicator',masked:'ghp_…[redacted] (29 chars)',source:'same-origin frame 1 inline script 1',offset:4}]};
 assert.equal((await send('PAGE_REPORT',{payload:data},{...sender,frameId:1})).ok,false);
 assert.equal((await send('PAGE_REPORT',{payload:data},sender)).ok,true);
 const record=(await send('GET_STATE')).record;
 assert.equal(record.frameCoverage.length,2);
 assert.equal(record.frameCoverage[0].status,'inspected');
 assert.equal(record.workerScripts.length,1);
 assert.equal(record.workerScripts[0].inspected,false);
 assert.equal(record.findings.length,1);
 assert(!JSON.stringify(record).includes('NEVER_SAVE'));
 assert(!JSON.stringify(record).includes('TOKEN'));
 await send('STOP_CAPTURE');
 assert.equal((await send('PAGE_REPORT',{payload:data},sender)).ok,false);
 console.log('PASS v4.8 worker: trusted top-frame ingestion, strict origin checks and no secret retention');
})().catch(e=>{console.error(e);process.exitCode=1});
