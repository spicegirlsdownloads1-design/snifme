/* Trufflehog Intelligence v6.7 — independently exported HAR versus saved capture.
 * Offline, bounded analysis. URLs may be used for ephemeral local matching, but
 * only fixed category labels and numerical totals are returned or exported.
 * Saved capture and HAR are not assumed to have identical browser visibility.
 */
(function(root){'use strict';
const TYPES=Object.freeze(['Documents','Scripts','Styles','API reads','API writes','Images','Other media','Downloads','Other']);
const MAX_HAR=12000,MAX_SAVED=12000,MAX_SEGMENTS=40;
const safe=n=>Number.isSafeInteger(n)&&n>=0?Math.min(n,1e6):0;
const safeUrl=value=>{
 // Browser version uses the existing redaction semantics; matching tokens
 // are deliberately local and never returned, logged, or stored.
 try {return root.THI?.sanitizedUrl?.(value)||'';}catch{return '';}
};
const parsed=value=>{try{const u=new URL(value);return /^https?:$/.test(u.protocol)?u:null;}catch{return null;}};
const method=x=>/^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)$/.test(String(x||'GET').toUpperCase())?String(x||'GET').toUpperCase():'OTHER';
const status=x=>Number.isInteger(x)&&x>=0&&x<=599?x:0;
const kind=(x)=>{
 const m=method(x.method),t=String(x.type||x._resourceType||'').toLowerCase(),mime=String(x.mime||x.mimeType||x.response?.content?.mimeType||'').toLowerCase();
 if(x.attachmentDisposition===true)return 'Downloads';
 if(['document','main_frame','sub_frame'].includes(t)||mime.startsWith('text/html'))return 'Documents';
 if(t==='script'||/javascript/.test(mime))return 'Scripts';
 if(t==='stylesheet'||mime.startsWith('text/css'))return 'Styles';
 if(t==='image'||mime.startsWith('image/'))return 'Images';
 if(['media','video','audio'].includes(t)||/^(audio|video)\//.test(mime))return 'Other media';
 if(['fetch','xhr','xmlhttprequest'].includes(t)||mime.includes('json'))return ['POST','PUT','PATCH','DELETE'].includes(m)?'API writes':'API reads';
 // HAR resource types are often absent. Do not guess that every POST is an API.
 return 'Other';
};
function validateHar(har){
 const log=har&&typeof har==='object'&&!Array.isArray(har)?har.log:null;
 if(!log||!Array.isArray(log.entries))throw Error('Select a valid HAR 1.2 file containing log.entries');
 if(log.entries.length>MAX_HAR)throw Error('HAR has too many entries; export a shorter session (maximum 12,000)');
 return log.entries;
}
function savedEntries(segments){
 if(!Array.isArray(segments)||segments.length===0||segments.length>MAX_SEGMENTS)throw Error('Select one saved capture group containing 1–40 segments');
 const origin=parsed(segments[0]?.origin)?.origin;
 if(!origin)throw Error('Saved capture has no valid HTTP origin');
 let truncated=false,drop=0,unfinalized=0,skipped=0,missingSegments=0;
 const ids=[],out=[];const groupIDs=new Set();
 for(const rec of segments){
  if(parsed(rec?.origin)?.origin!==origin)throw Error('Saved capture segments have different origins');
  if(rec.captureGroupId)groupIDs.add(String(rec.captureGroupId));
  if(Number.isInteger(rec.segmentIndex)&&rec.segmentIndex>=0)ids.push(rec.segmentIndex);
  if(!rec.endedAt)unfinalized++;
  if(!Array.isArray(rec.requests)){missingSegments++;continue;}
  for(const [key,n] of Object.entries(rec.counters||{}))if(/Dropped$/i.test(key))drop+=safe(n);
  if(rec.requests.length>MAX_SAVED)truncated=true;
  for(const r of rec.requests){
   if(out.length>=MAX_SAVED){truncated=true;break;}
   if(r?.carriedFromSegment===true)continue;
   const url=safeUrl(r?.url),u=parsed(url);
   if(!u){skipped++;continue;}
   const stamp=Date.parse(r?.at||'');
   out.push({url,origin:u.origin,method:method(r.method),status:status(r.status),category:kind(r),at:Number.isFinite(stamp)?stamp:null});
  }
 }
 if(groupIDs.size>1)throw Error('Select segments belonging to one capture group');
 ids.sort((a,b)=>a-b);
 for(let i=1;i<ids.length;i++)if(ids[i]>ids[i-1]+1)missingSegments++;
 return {origin,entries:out,coverage:{truncated,drop,unfinalized,skipped,missingSegments}};
}
function harEntries(har){
 const raw=validateHar(har);const out=[];let invalid=0,withContent=0;
 for(const e of raw){
  if(!e||typeof e!=='object'){invalid++;continue;}
  if(e.response?.content?.text!==undefined)withContent++;
  const url=safeUrl(e.request?.url),u=parsed(url);
  if(!u){invalid++;continue;}
  const stamp=Date.parse(e.startedDateTime||'');
  const mime=String(e.response?.content?.mimeType||'');
  out.push({url,origin:u.origin,method:method(e.request?.method),status:status(e.response?.status),category:kind({method:e.request?.method,_resourceType:e._resourceType,mime}),at:Number.isFinite(stamp)?stamp:null});
 }
 return {entries:out,invalid,withContent};
}
const span=rows=>{
 const ts=rows.map(r=>r.at).filter(Number.isFinite);
 return {min:ts.length?Math.min(...ts):null,max:ts.length?Math.max(...ts):null,coverage:rows.length?ts.length/rows.length:0};
};
function reconcile(har,segments){
 const H=harEntries(har),C=savedEntries(segments);
 if(!H.entries.length)throw Error('HAR contains no eligible HTTP observations');
 if(!C.entries.length)throw Error('Saved capture contains no usable HTTP observations');
 if(!H.entries.some(e=>e.origin===C.origin))throw Error('HAR does not contain the saved site origin; check the selected file');
 const pool=new Map(),near=new Map(),used=new Uint8Array(C.entries.length);
 const key=e=>e.method+'|'+e.url;const strict=e=>key(e)+'|'+e.status;
 C.entries.forEach((e,i)=>{
  const a=strict(e),b=key(e);
  if(!pool.has(a))pool.set(a,[]);pool.get(a).push(i);
  if(!near.has(b))near.set(b,[]);near.get(b).push(i);
 });
 function claim(map,k){const arr=map.get(k)||[];while(arr.length){const i=arr.pop();if(!used[i]){used[i]=1;return i;}}return -1;}
 const stats=Object.fromEntries(TYPES.map(label=>[label,{category:label,harObserved:0,captureObserved:0,harOnly:0,captureOnly:0}]));
 const SCOPES=['Same-site origin','External origins'];
 const scopeFor=e=>e.origin===C.origin?SCOPES[0]:SCOPES[1];
 const scopeStats=Object.fromEntries(SCOPES.map(label=>[label,{scope:label,harObserved:0,captureObserved:0,harOnly:0,captureOnly:0}]));
 const countsFor=rows=>{const m=new Map();for(const e of rows){const k=e.method+'|'+e.url;m.set(k,(m.get(k)||0)+1);}return m;};
 const harCounts=countsFor(H.entries),savedCounts=countsFor(C.entries);
 const repeatedKeys=new Set([...harCounts,...savedCounts].filter(([,n])=>n>1).map(([key])=>key)).size;

 for(const e of H.entries){stats[e.category].harObserved++;scopeStats[scopeFor(e)].harObserved++;}
 for(const e of C.entries){stats[e.category].captureObserved++;scopeStats[scopeFor(e)].captureObserved++;}
 let exact=0,statusDifferent=0,harOnly=0,captureOnly=0;
 for(const e of H.entries){
  let i=claim(pool,strict(e));
  if(i!==-1){exact++;continue;}
  i=claim(near,key(e));
  if(i!==-1){statusDifferent++;continue;}
  stats[e.category].harOnly++;scopeStats[scopeFor(e)].harOnly++;harOnly++;
 }
 C.entries.forEach((e,i)=>{if(!used[i]){stats[e.category].captureOnly++;scopeStats[scopeFor(e)].captureOnly++;captureOnly++;}});
 const ha=span(H.entries),ca=span(C.entries);
 const timeKnown=ha.coverage>=.9&&ca.coverage>=.9;
 // Starts and finishes need not match exactly: request start versus completion.
 const disjoint=timeKnown&&(ha.max<ca.min-300000||ca.max<ha.min-300000);
 const warnings=[];
 if(!timeKnown)warnings.push('One or both traces lack enough valid timestamps');
 if(disjoint)warnings.push('HAR and saved capture time windows do not overlap within five minutes');
 if(H.invalid)warnings.push('HAR contains unsupported or invalid request entries');
 if(H.entries.length>=MAX_HAR)warnings.push('HAR reached the maximum supported entry count');
 if(C.coverage.drop)warnings.push('Saved capture reports dropped records');
 if(C.coverage.truncated)warnings.push('Saved capture requests were capped for analysis');
 if(C.coverage.missingSegments)warnings.push('Saved capture has missing segments or request lists');
 if(C.coverage.unfinalized)warnings.push('Saved capture includes unfinalized segments');
 if(C.coverage.skipped)warnings.push('Some saved request URLs were unavailable for matching');
 if(H.withContent)warnings.push('Imported HAR contained response bodies; they were ignored and not exported');
 if(statusDifferent)warnings.push('Some matched method/URL pairs have different HTTP statuses');
 let assessment='Partial overlap observed — not a coverage certification';
 if(disjoint)assessment='Time windows differ — equivalence not established';
 else if(!exact&&!statusDifferent)assessment='No matching request identities observed';
 else if(!warnings.length&&harOnly===0&&captureOnly===0&&statusDifferent===0)assessment='All compared request identities matched — completeness not proven';
 const coverage={harRequests:safe(H.entries.length),savedRequests:safe(C.entries.length),
  exactMatches:safe(exact),statusDifferentMatches:safe(statusDifferent),harOnly:safe(harOnly),savedOnly:safe(captureOnly),
  harInvalid:safe(H.invalid),savedDropped:safe(C.coverage.drop),savedUnfinalized:safe(C.coverage.unfinalized),
  timeOverlapConfirmed:timeKnown&&!disjoint,harBodyEntriesIgnored:safe(H.withContent),repeatedComparableKeys:safe(repeatedKeys)};
 return {format:'trufflehog-har-coverage-reconciliation',version:1,assessment,
  coverage,rows:TYPES.map(x=>stats[x]),scopeRows:SCOPES.map(x=>scopeStats[x]),warnings:warnings.slice(0,20),
  certainty:'Only same-method and sanitised-URL matches; status matching strengthens but does not prove event identity. Repeated requests, URL redaction collisions, caches, different HAR options and capture timing can alter counts. HAR is an independent observation, not a full network ground truth.',
  noAdditionalRequests:true,credentialsRetained:false};
}
const API={reconcile,validateHar,category:kind};root.THIHARCoverage=API;
if(typeof module==='object'&&module.exports)module.exports=API;
})(typeof self!=='undefined'?self:globalThis);
