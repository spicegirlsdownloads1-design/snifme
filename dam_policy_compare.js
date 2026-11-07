/* Trufflehog Intelligence 6.3 — strictly local DAM delivery observation comparisons.
 * This module never reads source bodies, requests URLs, compares signing values,
 * or declares an authorization/withdrawal defect based on browser observations.
 */
(function(root){'use strict';
const MAX_SEGMENTS=40,MAX_REQUESTS=12000,MAX_PER_SEGMENT=3000;
const METRICS=Object.freeze([
 {key:'deliveredMedia',label:'Media returned 2xx',denominator:'media',limit:'Delivered in the recorded browser session; not necessarily public or licensed.'},
 {key:'deniedMedia',label:'Media returned 401/403',denominator:'media',limit:'Observed denial only; other assets and roles were not tested.'},
 {key:'signedMedia',label:'Media with signed URL indicators',denominator:'media',limit:'Signing indicators do not verify expiration, entitlement or enforcement.'},
 {key:'longPublicCache',label:'Media with public cache TTL ≥24h',denominator:'media',limit:'Browser headers do not prove cached asset revocation failed.'},
 {key:'downloadAttachments',label:'Successful attachment responses',denominator:'requests',limit:'An attachment header does not establish original quality or download rights.'},
 {key:'apiAuthQueries',label:'API request with credential-like query class',denominator:'api',limit:'Query-field classification alone does not establish an exposed privileged secret.'}
]);
const SAFE_FIELDS=new Set(METRICS.map(m=>m.key));
const isObj=x=>!!x&&typeof x==='object'&&!Array.isArray(x);
const safeInt=v=>Number.isSafeInteger(v)&&v>=0?Math.min(v,1e6):0;
function origin(value){try{const u=new URL(String(value||''));return /^https?:$/.test(u.protocol)?u.origin:'';}catch{return '';}}
function groupId(record){return String(record?.captureGroupId||record?.sessionId||'');}
function isMedia(r){return r?.type==='image'||/^image\//i.test(String(r?.mime||''))||r?.attachmentDisposition===true;}
function isApi(r){return ['fetch','xmlhttprequest'].includes(String(r?.type||'').toLowerCase());}
function aggregate(records){
 if(!Array.isArray(records)||!records.length)throw Error('Select a saved capture group');
 const selected=records.slice(0,MAX_SEGMENTS);
 const expected=origin(selected[0]?.origin);
 if(!expected)throw Error('Saved group has no valid HTTP origin');
 const ids=new Set();
 const counts={requests:0,media:0,api:0,deliveredMedia:0,deniedMedia:0,signedMedia:0,longPublicCache:0,downloadAttachments:0,apiAuthQueries:0};
 let omitted=records.length>MAX_SEGMENTS,unfinalized=0,drops=0,missingSequence=false,missingRequests=false,seen=0;
 const indices=[];
 for(const segment of selected){
  if(origin(segment?.origin)!==expected)throw Error('Mixed-origin group is not comparable');
  const id=groupId(segment);if(id)ids.add(id);
  const ix=segment?.segmentIndex;
  if(Number.isSafeInteger(ix)&&ix>=0)indices.push(ix);
  if(!segment?.endedAt)unfinalized++;
  for(const [key,val] of Object.entries(isObj(segment?.counters)?segment.counters:{})){
   if(/Dropped$/i.test(key))drops+=safeInt(val);
  }
  if(!Array.isArray(segment?.requests)){missingRequests=true;continue;}
  const items=segment.requests.slice(-MAX_PER_SEGMENT);
  if(items.length<segment.requests.length)omitted=true;
  for(const req of items){
   if(seen>=MAX_REQUESTS){omitted=true;break;}
   if(!isObj(req)||req.carriedFromSegment===true)continue;
   seen++;counts.requests++;
   const api=isApi(req),media=isMedia(req),status=Number(req.status||0);
   if(api)counts.api++;
   if(media){
    counts.media++;
    if(status>=200&&status<300)counts.deliveredMedia++;
    if(status===401||status===403)counts.deniedMedia++;
    if(req.signedQuery===true)counts.signedMedia++;
    if(status>=200&&status<300&&req.cacheScope==='public'&&Number.isFinite(Number(req.cacheMaxAge))&&Number(req.cacheMaxAge)>=86400)counts.longPublicCache++;
   }
   if(req.attachmentDisposition===true&&status>=200&&status<300)counts.downloadAttachments++;
   if(api&&Array.isArray(req.authQueryClasses)&&req.authQueryClasses.some(x=>x==='api-credential-query'||x==='legacy-access-token-query'))counts.apiAuthQueries++;
  }
 }
 if(indices.length>1){const sorted=[...new Set(indices)].sort((a,b)=>a-b);for(let n=1;n<sorted.length;n++)if(sorted[n]>sorted[n-1]+1)missingSequence=true;}
 const blindspots=[];
 if(omitted)blindspots.push('Request or segment analysis limit reached');
 if(unfinalized)blindspots.push('Unfinalized capture segments');
 if(drops)blindspots.push('Recorded dropped events');
 if(missingSequence)blindspots.push('Missing segment index in saved group');
 if(missingRequests)blindspots.push('Segment without request list');
 if(!counts.requests)blindspots.push('No observed requests');
 return {origin:expected,group:ids.size===1?[...ids][0]:null,counts,segments:selected.length,blindspots,coverageLimited:blindspots.length>0,retentionDrops:drops};
}
function rate(count,denom){return denom>0?Number((count*1000/denom).toFixed(1)):null;}
function compare(first,second){
 const earlier=aggregate(first),later=aggregate(second);
 if(earlier.origin!==later.origin)throw Error('Compare saved captures from the same exact site origin');
 if(earlier.group&&later.group&&earlier.group===later.group)throw Error('Select two different saved capture groups');
 const flags=[...earlier.blindspots.map(x=>'Earlier: '+x),...later.blindspots.map(x=>'Later: '+x)];
 const rows=METRICS.map(m=>{
  const da=earlier.counts[m.denominator],db=later.counts[m.denominator],a=earlier.counts[m.key],b=later.counts[m.key];
  const insufficient=da<20||db<20;
  const ar=rate(a,da),br=rate(b,db);
  return {category:m.label,denominator:m.denominator==='api'?'API requests':m.denominator==='media'?'Media requests':'All requests',
   earlierCount:a,laterCount:b,earlierSample:da,laterSample:db,
   earlierPerThousand:ar,laterPerThousand:br,
   assessment:!da||!db?'Not comparable (no sample)':insufficient?'Small sample; descriptive only':(br>ar?'Higher observed share':br<ar?'Lower observed share':'Same observed share'),
   evidenceQuality:flags.length?'Capture limitations present':insufficient?'Small sample':'Descriptive comparison only',
   qualification:m.limit};
 });
 const reliable=flags.length===0&&rows.every(r=>r.earlierSample>=20&&r.laterSample>=20);
 return {format:'trufflehog-dam-policy-drift',version:1,
  overview:{earlierRequests:earlier.counts.requests,laterRequests:later.counts.requests,earlierSegments:earlier.segments,laterSegments:later.segments,
   comparableSample:reliable,blindspotCount:flags.length,earlierRetainedDrops:earlier.retentionDrops,laterRetainedDrops:later.retentionDrops},
  rows,blindspots:flags,
  ownerReview:['Confirm comparable browsing steps, login role and host permissions before interpreting differences.',
   'Review original/derivative access policies and CDN withdrawal with a system owner; no access-control testing was performed.',
   'A changed observation rate does not prove a new vulnerability, a fixed issue or public master-file availability.'],
  caveat:'Same-origin saved evidence only. Rates are observations per 1,000 relevant recorded requests, not a measurement of server policy or effective security.'};
}
const API={aggregate,compare,metrics:METRICS.map(x=>({key:x.key,label:x.label}))};root.THIPolicyDrift=API;
if(typeof module==='object'&&module.exports)module.exports=API;
})(typeof self!=='undefined'?self:globalThis);
