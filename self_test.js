/* v3.7: On-demand non-invasive diagnostics. No page probing or credential storage. */
(function(root){
'use strict';
const TIMEOUT_MS=4500;
const timeout=(promise,ms=TIMEOUT_MS)=>new Promise((resolve,reject)=>{
  const t=setTimeout(()=>reject(new Error('Timed out')),ms);
  Promise.resolve(promise).then(v=>{clearTimeout(t);resolve(v);},e=>{clearTimeout(t);reject(e);});
});
async function run(tabId, deps){
  const results=[];
  const add=(id,status,detail)=>results.push({id,status,detail:String(detail||'').slice(0,140)});
  async function check(id,fn){try{const detail=await timeout(fn());add(id,'pass',detail||'Verified');}catch(e){add(id,'fail',e?.message||'Unavailable');}}
  const version=chrome.runtime.getManifest?.().version||'unknown';
  add('worker','pass','MV3 background responded · v'+version);
  let tab=null,origin='',granted=false,recording=null;
  await check('active-tab',async()=>{
    tab=await chrome.tabs.get(tabId);
    origin=deps.originOf(tab?.url||'');
    if(!origin)throw new Error('Open an ordinary HTTP/HTTPS webpage');
    return 'Page origin resolved';
  });
  if(origin){
    await check('site-permission',async()=>{
      granted=await deps.hasHostAccess(origin);
      if(!granted)throw new Error('Not granted: use Grant site access in popup');
      return 'Approved website access is present';
    });
  }else add('site-permission','skip','No HTTP/HTTPS tab');
  try{recording=await timeout(deps.active(tabId));}
  catch(e){add('capture-state','fail',e?.message||'Unknown error');}
  if(recording?.enabled&&recording.origin===origin)add('capture-state','pass','Capture is active for the approved website');
  else add('capture-state','skip','Start capture to exercise the content inspector');
  await check('local-storage',async()=>{
    const key='__trufflehog_health_local__';
    try{
      await chrome.storage.local.set({[key]:'test-only'});
      const values=await chrome.storage.local.get(key);
      if(values[key]!=='test-only')throw new Error('Readback mismatch');
      return 'Write/read/remove OK';
    }finally{await chrome.storage.local.remove(key);}
  });
  await check('session-storage',async()=>{
    const key='__trufflehog_health_session__';
    try{
      await chrome.storage.session.set({[key]:'test-only'});
      const values=await chrome.storage.session.get(key);
      if(values[key]!=='test-only')throw new Error('Readback mismatch');
      return 'Write/read/remove OK';
    }finally{await chrome.storage.session.remove(key);}
  });
  if(typeof indexedDB==='undefined')add('evidence-vault','skip','IndexedDB not exposed in this test environment');
  else await check('evidence-vault',async()=>{
    // A synthetic one-record transaction verifies the real extension database.
    const id=deps.THIVault.newId();
    const rec={sessionId:id,origin:'http://127.0.0.1',createdAt:new Date().toISOString(),findings:[],requests:[],assets:[],schema:13,diagnostic:true};
    try{
      await deps.THIVault.save(rec);
      const loaded=await deps.THIVault.get(id);
      if(!loaded||loaded.sessionId!==id||loaded.origin!==rec.origin)throw new Error('Vault readback mismatch');
      return 'IndexedDB write/read/remove OK';
    }finally{await deps.THIVault.remove(id);}
  });
  if(granted&&recording?.enabled&&recording.origin===origin){
    await check('content-inspector',async()=>{
      const r=await chrome.tabs.sendMessage(tabId,{type:'TRUFFLEHOG_HEALTH_PING'});
      if(!r?.ok||!r.inspectorPresent||r.origin!==origin)throw new Error('Inspector missing or wrong origin');
      if(!r.observing)throw new Error('Inspector injected but not observing');
      return 'Content script replied and is observing';
    });
  }else add('content-inspector','skip','Requires site access and an active capture');
  if(chrome.notifications?.create)add('notification-api','pass','Notifications API available; click Test notification to check desktop delivery');
  else add('notification-api','fail','Notifications API unavailable');
  // The heartbeat proves a DevTools observer is alive, not that all page files were seen.
  if(typeof deps.readRecord==='function'&&deps.THIHealth){
    try{
      const rec=await timeout(deps.readRecord(tabId));
      const h=deps.THIHealth.assess(rec,recording);
      if(!recording?.enabled){add('devtools-live','skip','Start capture and open website DevTools to test response inspection');}
      else if(h.fresh){add('devtools-live','pass',`DevTools observer heartbeat present; ${h.scanned}/${h.eligible} observed eligible files scanned`);}
      else if(h.heartbeatAt){add('devtools-live','fail','DevTools observer heartbeat is stale; reopen DevTools and reload');}
      else add('devtools-live','skip','No DevTools observer heartbeat yet; open website DevTools, then reload');
    }catch(e){add('devtools-live','fail',String(e?.message||'Diagnostic failed').slice(0,120));}
  } else add('devtools-live','skip','Open website DevTools and reload to test scanned-file coverage');
  return {ok:true,version,at:new Date().toISOString(),results,summary:{passed:results.filter(x=>x.status==='pass').length,failed:results.filter(x=>x.status==='fail').length,skipped:results.filter(x=>x.status==='skip').length}};
}
async function notification(){
  if(!chrome.notifications?.create)return {ok:false,error:'Notifications API unavailable'};
  try{
    await chrome.notifications.create('trufflehog-health-'+Date.now(),{
      type:'basic', iconUrl:'icon128.png', title:'Trufflehog test notification',
      message:'This is a manual display test. No sensitive secret was found.', priority:1
    });
    return {ok:true,message:'Notification submitted to Chrome. Windows or Chrome settings may prevent a visible banner.'};
  }catch(e){return {ok:false,error:String(e?.message||e).slice(0,120)};}
}
root.THISelfTest={run,notification};
if(typeof module!=='undefined'&&module.exports)module.exports=root.THISelfTest;
})(typeof self!=='undefined'?self:globalThis);
