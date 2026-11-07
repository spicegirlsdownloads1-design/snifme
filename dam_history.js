/* v4.1 - Offline comparison of already-recorded DAM/CMS fingerprints.
 * No URL query values, response content, credentials or network activity.
 * "Not observed" is never treated as proof of absence or service removal.
 */
(function(root){'use strict';
const MAX_SEGMENTS=40;
const HOST_LIMIT=160;
function hostOf(value){try{const u=new URL(String(value||''));return /^https?:$/.test(u.protocol)?u.hostname.toLowerCase():'';}catch{return '';}}
function apiLike(request){
 try{const u=new URL(String(request?.url||''));
  return /^\/(?:api(?:\/|$)|graphql(?:\/|$)|rest(?:\/|$)|v[1-9](?:\/|$))/i.test(u.pathname)
    || /^(?:xhr|xmlhttprequest|fetch)$/i.test(String(request?.type||''));
 }catch{return false;}
}
function snapshot(input,profiles=[],engines={}){
 const DAM=engines.DAM||root.THIDAM, CUSTOM=engines.CUSTOM||root.THICustomProfiles;
 if(!DAM?.analyze||!CUSTOM?.inspect)throw Error('DAM recognition engines unavailable');
 const records=(Array.isArray(input)?input:[input]).filter(x=>x&&typeof x==='object');
 if(records.length>MAX_SEGMENTS)throw Error('This comparison is limited to '+MAX_SEGMENTS+' capture segments per group');
 const byTech=new Map(),byHost=new Map();
 let totalRequests=0,totalAssets=0,scannedSegments=0;
 for(const record of records){
  scannedSegments++;
  const observed=DAM.analyze(record);
  for(const item of observed.profiles||[]){
   const id='builtin:'+item.id,prior=byTech.get(id);
   const signals=Number(item.independentSignals)||0;
   if(!prior)byTech.set(id,{id,name:item.name,layer:item.layer,method:'Built-in',bestScore:Math.min(10,Number(item.score)||0),signals,segments:1,observed:item.assessment?.includes('resource observed')||item.evidence?.some(e=>e.kind==='observed-request')||false});
   else {prior.segments++;prior.bestScore=Math.max(prior.bestScore,Math.min(10,Number(item.score)||0));prior.signals=Math.max(prior.signals,signals);prior.observed ||= item.evidence?.some(e=>e.kind==='observed-request')||false;}
  }
  const custom=CUSTOM.inspect(profiles,record);
  for(const item of custom){
   const id='custom:'+item.id,prior=byTech.get(id);
   const observedOnly=(item.evidence||[]).some(e=>e.kind==='Observed HTTP request'||e.kind==='Observed image'||e.kind==='Observed API request');
   if(!prior)byTech.set(id,{id,name:item.name,layer:item.layer,method:'User rule',bestScore:null,signals:item.count,segments:1,observed:observedOnly});
   else{prior.segments++;prior.signals+=item.count;prior.observed ||= observedOnly;}
  }
  const mark=(raw,role)=>{
   const host=hostOf(raw);if(!host||byHost.size>=HOST_LIMIT&&!byHost.has(role+'|'+host))return;
   const id=role+'|'+host;
   const row=byHost.get(id)||{id,host,role,sightings:0};row.sightings++;byHost.set(id,row);
  };
  for(const req of (record.requests||[]).slice(0,2000)){
   totalRequests++;
   mark(req.url,apiLike(req)?'Observed API / data':'Observed web request');
  }
  for(const asset of (record.assets||[]).slice(0,1800)){
   totalAssets++;
   if(asset.source==='network'||asset.source==='DevTools network'||asset.source==='network image')mark(asset.url,'Image delivery');
  }
 }
 return {origin:records.length?hostOf(records[0].origin):'',segments:scannedSegments,requests:totalRequests,assets:totalAssets,
   technologies:[...byTech.values()].sort((a,b)=>a.name.localeCompare(b.name)).slice(0,80),
   hosts:[...byHost.values()].sort((a,b)=>a.role.localeCompare(b.role)||a.host.localeCompare(b.host)).slice(0,HOST_LIMIT),
   note:'Matches are evidence of observed or referenced infrastructure. Custom rules are interpreted using the definitions installed at comparison time. Missing observations cannot establish removals.'};
}
function compare(first,second){
 if(!first||!second)throw Error('Two snapshots required');
 const categories=[['Technology',first.technologies||[],second.technologies||[]],['Observed host role',first.hosts||[],second.hosts||[]]];
 const rows=[];
 for(const [type,a,b]of categories){
  const left=new Map(a.map(x=>[x.id,x])),right=new Map(b.map(x=>[x.id,x]));
  for(const id of new Set([...left.keys(),...right.keys()])){
   const l=left.get(id),r=right.get(id);
   const status=!l?'Newly observed in second':!r?'Not observed in second':'Observed in both';
   rows.push({kind:type,identity:l?.name||r?.name||r?.host||l?.host||id,
    layer:r?.layer||l?.layer||r?.role||l?.role||'',status,
    firstSightings:type==='Technology'?(l?.segments||0):(l?.sightings||0),
    secondSightings:type==='Technology'?(r?.segments||0):(r?.sightings||0),
    evidence:type==='Technology'?(r?.method||l?.method||''):'Host only; no requests replayed'});
  }
 }
 const order={'Newly observed in second':0,'Not observed in second':1,'Observed in both':2};
 rows.sort((a,b)=>order[a.status]-order[b.status]||a.identity.localeCompare(b.identity));
 return {rows:rows.slice(0,260),total:rows.length,truncated:rows.length>260,
  first:{origin:first.origin,segments:first.segments,requests:first.requests,assets:first.assets},
  second:{origin:second.origin,segments:second.segments,requests:second.requests,assets:second.assets},
  assessment:'Offline comparison of recorded evidence, not a live service check. "Not observed" can mean incomplete capture, changed browsing, changed profile definitions or a genuine change. Shared hosts do not prove a shared DAM database.'};
}
const api={MAX_SEGMENTS,snapshot,compare};root.THIDAMHistory=api;
if(typeof module!=='undefined'&&module.exports)module.exports=api;
})(typeof self!=='undefined'?self:globalThis);
