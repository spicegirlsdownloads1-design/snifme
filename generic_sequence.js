/* Trufflehog Intelligence v7.11 — universal observed traffic sequence.
 * Offline only. Fixed labels and numeric aggregates; never export input
 * hostnames, URLs, request IDs, download refs, headers or raw event values.
 * Adjacent HTTP completions are NOT a causal/parent-child relationship.
 */
(function(root){'use strict';
const MAX_REQUESTS=3000,MAX_EVENTS=3000,MAX_GROUPS=3000,MAX_COUNT=1000000,WINDOW_MS=30000;
const KINDS=Object.freeze(['Document','Script/style','API read','API write','Image/media','Attachment','Other']);
const max=n=>Number.isSafeInteger(n)&&n>=0?Math.min(n,MAX_COUNT):0;
const time=x=>{
 if(typeof x!=='string'||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(x))return null;
 const n=Date.parse(x);return Number.isFinite(n)?n:null;
};
const write=m=>['POST','PUT','PATCH','DELETE'].includes(String(m||'').toUpperCase());
function kind(r){
 const type=String(r?.type||'').toLowerCase(),mime=String(r?.mime||'').toLowerCase();
 if(r?.attachmentDisposition===true)return 'Attachment';
 if(type==='main_frame'||type==='sub_frame'||mime.startsWith('text/html'))return 'Document';
 if(type==='script'||type==='stylesheet'||/javascript/.test(mime)||mime.startsWith('text/css'))return 'Script/style';
 if(type==='image'||type==='media'||type==='video'||type==='audio'||/^(image|audio|video)\//.test(mime))return 'Image/media';
 if(type==='fetch'||type==='xmlhttprequest'||mime.includes('json'))return write(r?.method)?'API write':'API read';
 return 'Other';
}
const DEFINITIONS=Object.freeze([
 ['HTTP starts paired with terminal event','Same private browser request ID: request and complete/error'],
 ['HTTP starts without terminal event','Incomplete lifecycle in this capture, not proof of an ongoing request'],
 ['HTTP terminals without start event','Start was not recorded for this browser request ID'],
 ['HTTP lifecycle redirect observed','Redirect step seen for this browser request ID'],
 ['HTTP request-header stage observed','Header stage seen for this browser request ID; individual headers may be unavailable'],
 ['HTTP response-header stage observed','Response-header stage seen for this browser request ID; individual headers may be unavailable'],
 ['HTTP error terminal observed','Error step seen for this browser request ID'],
 ['HTTP events without a grouping ID','Event lacked a usable local browser request label'],
 ['Browser downloads with start and terminal','Same local download label had start and complete/interrupted'],
 ['Browser download starts without terminal','Recorded start but no terminal in the capture'],
 ['Browser download terminals without start','Recorded terminal but no paired start'],
 ['Browser downloads completed','Chrome recorded a completion state'],
 ['Browser downloads interrupted','Chrome recorded an interruption state'],
 ['Browser download events without grouping ID','Download event lacked a usable local label']
]);
function analyze(record){
 const rec=record&&typeof record==='object'&&!Array.isArray(record)?record:{};
 const requests=Array.isArray(rec.requests)?rec.requests:[];
 const events=Array.isArray(rec.downloadEvents)?rec.downloadEvents:[];
 const timeline=[];let untimed=0,invalid=0;
 for(const r of requests.slice(0,MAX_REQUESTS)){
  if(!r||typeof r!=='object'||Array.isArray(r)){invalid++;continue;}
  const t=time(r.at);if(t===null){untimed++;continue;}
  timeline.push({at:t,kind:kind(r)});
 }
 timeline.sort((a,b)=>a.at-b.at);
 const timestampCounts=new Map();
 for(const e of timeline)timestampCounts.set(e.at,(timestampCounts.get(e.at)||0)+1);
 const matrix=Object.fromEntries(KINDS.flatMap(a=>KINDS.map(b=>[a+' → '+b,0])));
 let pairs=0,gaps=0,ties=0,ambiguous=0;
 for(let i=1;i<timeline.length;i++){
  const a=timeline[i-1],b=timeline[i],diff=b.at-a.at;
  if(diff===0){ties++;continue;}
  if(timestampCounts.get(a.at)>1||timestampCounts.get(b.at)>1){ambiguous++;continue;}
  if(diff>WINDOW_MS){gaps++;continue;}
  matrix[a.kind+' → '+b.kind]++;pairs++;
 }
 const transitions=KINDS.flatMap(from=>KINDS.map(to=>({
  transition:from+' → '+to,count:max(matrix[from+' → '+to]),
  evidence:'Adjacent recorded HTTP completion times, within 30 seconds',
  qualification:'Sequence only; no causality, session relationship or entitlement inferred'
 }))).sort((a,b)=>b.count-a.count||a.transition.localeCompare(b.transition));
 const http=new Map(),downloads=new Map();let withoutHTTPId=0,withoutDownloadId=0;
 const httpStages=new Set(['request','headers','response-headers','redirect','complete','error']);
 for(const event of events.slice(0,MAX_EVENTS)){
  if(!event||typeof event!=='object'||Array.isArray(event))continue;
  if(httpStages.has(event.stage)){
   if(typeof event.requestId!=='string'||!event.requestId||event.requestId.length>120){withoutHTTPId++;continue;}
   if(!http.has(event.requestId)){
    if(http.size>=MAX_GROUPS)continue;
    http.set(event.requestId,new Set());
   }
   http.get(event.requestId).add(event.stage);
  }else if(event.stage==='download-start'||event.stage==='download-state'){
   if(typeof event.downloadRef!=='string'||!/^DL\d{1,26}$/.test(event.downloadRef)){withoutDownloadId++;continue;}
   if(!downloads.has(event.downloadRef)){
    if(downloads.size>=MAX_GROUPS)continue;
    downloads.set(event.downloadRef,{started:false,completed:false,interrupted:false});
   }
   const d=downloads.get(event.downloadRef);
   if(event.stage==='download-start')d.started=true;
   if(event.stage==='download-state'&&event.downloadStatus==='complete')d.completed=true;
   if(event.stage==='download-state'&&event.downloadStatus==='interrupted')d.interrupted=true;
  }
 }
 const stageCounts=Object.fromEntries(DEFINITIONS.map(([label])=>[label,0]));
 for(const s of http.values()){
  const started=s.has('request'),terminal=s.has('complete')||s.has('error');
  if(started&&terminal)stageCounts['HTTP starts paired with terminal event']++;
  if(started&&!terminal)stageCounts['HTTP starts without terminal event']++;
  if(!started&&terminal)stageCounts['HTTP terminals without start event']++;
  if(s.has('redirect'))stageCounts['HTTP lifecycle redirect observed']++;
  if(s.has('headers'))stageCounts['HTTP request-header stage observed']++;
  if(s.has('response-headers'))stageCounts['HTTP response-header stage observed']++;
  if(s.has('error'))stageCounts['HTTP error terminal observed']++;
 }
 stageCounts['HTTP events without a grouping ID']=withoutHTTPId;
 for(const d of downloads.values()){
  const terminal=d.completed||d.interrupted;
  if(d.started&&terminal)stageCounts['Browser downloads with start and terminal']++;
  if(d.started&&!terminal)stageCounts['Browser download starts without terminal']++;
  if(!d.started&&terminal)stageCounts['Browser download terminals without start']++;
  if(d.completed)stageCounts['Browser downloads completed']++;
  if(d.interrupted)stageCounts['Browser downloads interrupted']++;
 }
 stageCounts['Browser download events without grouping ID']=withoutDownloadId;
 const lifecycles=DEFINITIONS.map(([stage,evidence])=>({stage,count:max(stageCounts[stage]),evidence,
  qualification:'Only explicit opt-in events retained by this capture; missing stages are unknown'}));
 const counters=rec.counters&&typeof rec.counters==='object'&&!Array.isArray(rec.counters)?rec.counters:{};
 let dropped=max(rec.downloadEventsDropped);
 for(const [key,value] of Object.entries(counters))if(/Dropped$/i.test(key))dropped=Math.min(MAX_COUNT,dropped+max(value));
 const capped=requests.length>MAX_REQUESTS||events.length>MAX_EVENTS;
 const warnings=[];
 if(!rec.endedAt)warnings.push('Capture may still be active or was not finalised');
 if(rec.downloadObserverEverEnabled!==true)warnings.push('Download observer was not confirmed enabled; HTTP lifecycle and browser download gaps are unknown');
 if(!timeline.length)warnings.push('No usable HTTP completion timestamps were available');
 if(untimed||invalid)warnings.push('Some HTTP requests lacked usable completion timestamps');
 if(ties)warnings.push('Equal timestamps cannot establish event order; those and neighbouring ambiguous transition pairs were excluded');
 if(gaps)warnings.push('Some adjacent responses were more than 30 seconds apart; no transition recorded');
 if(dropped)warnings.push('Recorded capture caps dropped some observations');
 if(capped)warnings.push('Analysis sample cap reached');
 return {format:'trufflehog-universal-traffic-sequence',version:1,
  overview:{observedHTTP:max(requests.length),timedHTTP:max(timeline.length),adjacentPairs:max(pairs),
   timestampTies:max(ties),ambiguousNeighbourPairs:max(ambiguous),largeGaps:max(gaps),untimedOrInvalid:max(untimed+invalid),
   groupedHTTPLifecycles:max(http.size),groupedBrowserDownloads:max(downloads.size),
   observedObserverEvents:max(Math.min(events.length,MAX_EVENTS)),droppedObservations:dropped,sampleCapped:capped},
  transitions,lifecycles,warnings:warnings.slice(0,8),
  noAdditionalRequests:true,platformIdentificationRequired:false,credentialsRetained:false,
  caution:'Neighbouring HTTP completion times are not evidence of a workflow, redirect chain, shared asset, download attribution or causal link. Exact private request/download IDs pair stages of one local event only. Missing stages never prove that a request did not occur.'};
}
const API={analyze,kind,labels:KINDS};root.THIGenericSequence=API;
if(typeof module==='object'&&module.exports)module.exports=API;
})(typeof self!=='undefined'?self:globalThis);
