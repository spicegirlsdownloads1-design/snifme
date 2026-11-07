/* v2.9 Persistent evidence vault. Local IndexedDB only; never fetches URLs.
   Only sanitized, metadata-only capture records belong here. */
(function(root){
'use strict';
const DB='TrufflehogEvidenceVault',STORE='sessions',VERSION=1;
const FIELDS=['securityObservations','pimObservations','pimMediaObservations','licensingObservations','downloadEvents','frameCoverage','workerScripts','embeddedContexts','interactions','resourceScans','galleryEvents','galleryAssets','viewerResources','viewerManifests','viewerHints','requests','assets','assetLinks','routes','scripts','findings','clues','maps','operations','configs','responses','pagination','verifications','technologyHints','scannedScripts'];
const safeId=x=>typeof x==='string'&&/^[a-zA-Z0-9_-]{8,90}$/.test(x)?x:'';
const newId=()=> typeof crypto!=='undefined'&&crypto.randomUUID?'session-'+crypto.randomUUID():'session-'+Date.now()+'-'+Math.random().toString(36).slice(2,11);
function summary(record){
 const arr=k=>Array.isArray(record?.[k])?record[k]:[];
 return {id:record.sessionId,captureGroupId:record.captureGroupId||record.sessionId,segmentIndex:record.segmentIndex||1,previousSegmentId:record.previousSegmentId||null,origin:record.origin,startedAt:record.createdAt,endedAt:record.endedAt||null,
  requests:arr('requests').length,images:arr('assets').length,findings:arr('findings').length,
  verified:arr('verifications').length,apiRoutes:arr('routes').length,assetIds:arr('galleryAssets').length};
}
function open(){
 if(typeof indexedDB==='undefined')return Promise.reject(new Error('IndexedDB unavailable. Open the installed Chrome extension.'));
 return new Promise((resolve,reject)=>{
  const r=indexedDB.open(DB,VERSION);
  r.onupgradeneeded=()=>{const db=r.result;if(!db.objectStoreNames.contains(STORE)){const store=db.createObjectStore(STORE,{keyPath:'sessionId'});store.createIndex('createdAt','createdAt');store.createIndex('origin','origin');}};
  r.onsuccess=()=>resolve(r.result);
  r.onerror=()=>reject(r.error||new Error('Unable to open evidence vault'));
  r.onblocked=()=>reject(new Error('Close other extension pages and retry the vault upgrade'));
 });
}
async function transact(mode,fn){
 const db=await open();
 try{return await new Promise((resolve,reject)=>{
  const tx=db.transaction(STORE,mode),store=tx.objectStore(STORE);
  let result;tx.oncomplete=()=>resolve(result);tx.onerror=()=>reject(tx.error||new Error('Vault operation failed'));
  tx.onabort=()=>reject(tx.error||new Error('Vault operation aborted'));
  try{fn(store,x=>{result=x;});}catch(e){tx.abort();reject(e);}
 });}finally{db.close();}
}
async function save(record){
 if(!record||!record.sessionId||!safeId(record.sessionId)||!/^https?:\/\//.test(record.origin||''))throw new Error('Invalid session metadata');
 // Keep copies, not mutable references, so later live-record changes cannot alter history.
 const data=JSON.parse(JSON.stringify(record));
 return transact('readwrite',(store)=>{store.put(data);});
}
async function get(id){
 if(!safeId(id))return null;
 return transact('readonly',(store,done)=>{const req=store.get(id);req.onsuccess=()=>done(req.result||null);});
}
async function list(){
 const data=await transact('readonly',(store,done)=>{const req=store.getAll();req.onsuccess=()=>done(req.result||[]);});
 return data.map(summary).sort((a,b)=>String(b.startedAt).localeCompare(String(a.startedAt)));
}
async function all(){return transact('readonly',(store,done)=>{const req=store.getAll();req.onsuccess=()=>done(req.result||[]);});}
async function saveMany(records){
 if(!Array.isArray(records)||!records.length||records.length>120)throw new Error('Invalid capture-group import');
 for(const r of records)if(!safeId(r?.sessionId)||!/^https?:\/\//.test(r.origin||''))throw new Error('Invalid session in group');
 // All-or-nothing IndexedDB transaction: partial archive imports are not committed.
 return transact('readwrite',store=>{for(const r of records)store.add(JSON.parse(JSON.stringify(r)));});
}
async function remove(id){
 if(!safeId(id))throw new Error('Invalid session identifier');
 return transact('readwrite',store=>{store.delete(id);});
}
function unique(record,field,extract){
 const out=new Set();for(const r of (record?.[field]||[])){
  const v=extract(r);if(typeof v==='string'&&v.length>0)out.add(v);
 }return out;
}
const intersect=(a,b)=>[...a].filter(x=>b.has(x)).sort();
const difference=(a,b)=>[...a].filter(x=>!b.has(x)).sort();
function compare(a,b){
 if(!a||!b)return null;
 const hosts=r=>unique(r,'requests',x=>x.host);
 const routes=r=>unique(r,'routes',x=>x.observed===true&&x.url?`${x.method||'GET'} ${x.url}`:'');
 const images=r=>unique(r,'assets',x=>x.url);
 const hashes=r=>unique(r,'verifications',x=>/^[a-f0-9]{64}$/i.test(x.sha256||'')?x.sha256.toLowerCase():'');
 const ids=r=>unique(r,'galleryAssets',x=>x.assetId);
 const out={a:summary(a),b:summary(b),groups:{}};
 for(const [name,getter] of [['hosts',hosts],['observedApiRoutes',routes],['observedImageUrls',images],['exactByteHashes',hashes],['declaredGalleryIds',ids]]){
  const left=getter(a),right=getter(b);
  out.groups[name]={shared:intersect(left,right).slice(0,100),onlyA:difference(left,right).slice(0,100),onlyB:difference(right,left).slice(0,100),sharedCount:intersect(left,right).length,onlyACount:difference(left,right).length,onlyBCount:difference(right,left).length};
 }
 out.assessment='Exact SHA-256 matches establish identical bytes. Asset IDs, matching URLs or shared hosts alone do not prove a common original, provider or right to download.';
 return out;
}
// Import is intentionally metadata-only, not a general purpose arbitrary JSON importer.
// Unexpected objects, files/response bodies, raw headers, and unmasked findings are discarded.
function sanitizeImport(input,sanitizeUrl){
 if(input?.format!=='trufflehog-vault-session'||input?.version!==1||!input.record||typeof input.record!=='object')throw new Error('Not a supported Trufflehog session backup');
 const source=input.record;
 const sanitizedOrigin=sanitizeUrl(source.origin||'');
 let origin='';
 try{const u=new URL(sanitizedOrigin);if(!/^https?:$/.test(u.protocol)||u.pathname!=='/'||u.search||u.hash)throw new Error('bad');origin=u.origin;}catch{throw new Error('Invalid origin');}
 const output={sessionId:newId(),origin,createdAt:(typeof source.createdAt==='string'&&!isNaN(Date.parse(source.createdAt)))?source.createdAt:new Date().toISOString(),endedAt:new Date().toISOString(),schema:21,imported:true,tabId:null,unreviewedAlerts:0,counters:{}};
 const safeText=(v,k)=>{
  if(typeof v!=='string')return typeof v==='number'&&Number.isFinite(v)?v:typeof v==='boolean'?v:null;
  if(/(?:secret|password|credential|authorization|cookie|^token$|^raw|^body|^content|^headers)$/i.test(k))return null;
  if(/(?:url|origin|^source$|^script$|^document$|^page$|^family$)/i.test(k)&&/^https?:\/\//i.test(v))return sanitizeUrl(v)||'';
  if(/^(?:masked|value)$/i.test(k))return '[redacted import]';
  // For other strings import only short, printable metadata, never long opaque token material.
  if(v.length>256||/[\r\n\x00-\x08]/.test(v)||/\b(?:ghp_|glpat-|sk_live_|xox[bapors]-|eyJ[A-Za-z0-9_-]{20,})/i.test(v))return '[omitted]';
  return v;
 };
 function copy(obj,depth=0){
  if(depth>5||obj===null||obj===undefined)return null;
  if(Array.isArray(obj))return obj.slice(0,1500).map(x=>copy(x,depth+1));
  if(typeof obj==='object'){
   const result={};for(const [k,v] of Object.entries(obj).slice(0,90)){
    if(!/^[a-zA-Z][\w-]{0,40}$/.test(k)||k==='_key'||/(?:secret|password|credential|authorization|cookie|rawBody|headers)/i.test(k))continue;
    result[k]=copyField(v,k,depth+1);
   }return result;
  }return safeText(obj,'');
 }
 function copyField(v,k,depth){
  if(typeof v==='string')return safeText(v,k);
  return copy(v,depth);
 }
 // Preserve segment group information only if imported with a safe local-looking identifier.
 // Imported segments are independent local sessions; never share a foreign group's identity.
 output.captureGroupId=output.sessionId;
 output.segmentIndex=1;
 for(const field of FIELDS){
  const values=Array.isArray(source[field])?source[field]:[];
  output[field]=values.slice(0,1500).map(v=>copy(v)).filter(v=>v&&typeof v==='object');
 }
 // Preserve bounded numeric coverage counters and DevTools status without trusting foreign alert state.
 for(const key of ['securityObservationsDropped','downloadEventsDropped','licensingObservationsDropped','pimObservationsDropped','pimMediaDropped']){
  if(Number.isSafeInteger(source[key])&&source[key]>=0&&source[key]<=1000000)output[key]=source[key];
 }
 output.downloadObserverEverEnabled=source.downloadObserverEverEnabled===true;
 if(source.autoScanCoverage&&typeof source.autoScanCoverage==='object')output.autoScanCoverage=copy(source.autoScanCoverage);
 if(source.counters&&typeof source.counters==='object'){
  const safeCounters=['requestsDropped','assetsDropped','responsesDropped','paginationDropped','verificationsDropped','viewerResourcesDropped','contextsDropped','galleryEventsDropped','galleryAssetsDropped'];
  for(const k of safeCounters)if(Number.isSafeInteger(source.counters[k])&&source.counters[k]>=0&&source.counters[k]<=1000000)output.counters[k]=source.counters[k];
 }
 // Recalculate all alert states: import must never fire a desktop notification.
 output.findings=output.findings.map(f=>({...f,masked:'[redacted import]'}));
 output.verifications=output.verifications.map(v=>({...v,visual:root.THIVisual?.validate(v.visual)||null,metadata:Array.isArray(v.metadata)?v.metadata.slice(0,16)
   .filter(m=>['EXIF','IPTC','XMP','ICC','C2PA'].includes(m?.kind)&&/^[a-f0-9]{64}$/i.test(m?.sha256||''))
   .map(m=>({kind:m.kind,sha256:m.sha256.toLowerCase()})):[]}));
 return output;
}
root.THIVault={open,save,saveMany,get,all,list,remove,summary,compare,newId,sanitizeImport,fields:FIELDS};
if(typeof module!=='undefined'&&module.exports)module.exports=root.THIVault;
})(typeof self!=='undefined'?self:globalThis);
