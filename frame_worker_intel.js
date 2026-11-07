/* v4.7: bounded, passive embedded-frame and worker context evidence.
 * No frame body access, no frame path/query, no worker instrumentation or fetches.
 */
(function(root){'use strict';
const KINDS=new Set(['embedded-frame','controlled-service-worker','worker-resource-hint']);
const EVIDENCE={'embedded-frame':'iframe element','controlled-service-worker':'service worker controller','worker-resource-hint':'resource timing hint'};
function originOf(value){try{const x=new URL(String(value||''));return /^https?:$/.test(x.protocol)?x.origin:'';}catch{return '';}}
function clean(value,pageOrigin){
 if(!value||!KINDS.has(value.kind))return null;
 const origin=originOf(value.origin),owner=originOf(pageOrigin);
 if(!origin||!owner||value.evidence!==EVIDENCE[value.kind])return null;
 return {kind:value.kind,origin,relationship:origin===owner?'same-origin':'cross-origin',
  sandboxed:value.kind==='embedded-frame'&&value.sandboxed===true,
  evidence:EVIDENCE[value.kind]};
}
function analyze(record){
 const owner=originOf(record?.origin),map=new Map();
 for(const raw of (record?.embeddedContexts||[]).slice(0,180)){
  const x=clean(raw,owner);if(!x)continue;
  const key=[x.kind,x.origin,x.relationship,x.sandboxed].join('|');
  const old=map.get(key)||{...x,sightings:0,observed:'Page DOM / browser state'};
  old.sightings++;map.set(key,old);
 }
 // sub_frame is a genuine completed/error network request, not proof that
 // the embedded document was inspected or permitted for content scanning.
 for(const r of (record?.requests||[]).slice(0,1800)){
  if(r?.type!=='sub_frame')continue;
  const origin=originOf(r.url);if(!origin||!owner)continue;
  const key=['embedded-frame',origin,origin===owner?'same-origin':'cross-origin',false].join('|');
  const old=map.get(key)||{kind:'embedded-frame',origin,
    relationship:origin===owner?'same-origin':'cross-origin',sandboxed:false,
    evidence:'completed sub-frame request',sightings:0,observed:'Network only'};
  old.sightings++;
  if(old.observed==='Network only')old.evidence='completed sub-frame request';
  map.set(key,old);
 }
 const rows=[...map.values()].sort((a,b)=>a.kind.localeCompare(b.kind)||a.origin.localeCompare(b.origin)).slice(0,120);
 return {rows,embedded:rows.filter(x=>x.kind==='embedded-frame').length,
  workerClues:rows.filter(x=>x.kind!=='embedded-frame').length,
  note:'Only accessible same-origin iframe DOMs are inspected by the optional frame scope; cross-origin contents are excluded. Resource-timing worker hints are not proof of worker execution or script-content inspection.'};
}
const api={originOf,clean,analyze};root.THIContexts=api;
if(typeof module!=='undefined'&&module.exports)module.exports=api;
})(typeof self!=='undefined'?self:globalThis);
