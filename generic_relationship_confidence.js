/* Trufflehog Intelligence v7.12 — generic relationship evidence confidence.
 * No network IO or vendor rules. Analyses ONLY existing opt-in local records.
 * Output is strictly schema-fixed labels and bounded numbers; private grouping
 * keys (browser IDs, document URLs, origins) are discarded before returning.
 */
(function(root){'use strict';
const REQUEST_LIMIT=3000, EVENT_LIMIT=3000, GROUP_LIMIT=3000, COUNT_LIMIT=1000000, WINDOW_MS=30000;
const MAX=n=>Number.isSafeInteger(n)&&n>=0?Math.min(n,COUNT_LIMIT):0;
const START=new Set(['request']), TERMINAL=new Set(['complete','error']);
const HTTP=new Set(['request','headers','response-headers','redirect','complete','error']);
const iso=s=>{
 if(typeof s!=='string'||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(s))return null;
 const n=Date.parse(s);return Number.isFinite(n)?n:null;
};
const recordObj=x=>x&&typeof x==='object'&&!Array.isArray(x);
const validRequestId=x=>typeof x==='string'&&x.length>0&&x.length<=120;
const validDL=x=>typeof x==='string'&&/^DL\d{1,26}$/.test(x);
// The private URL and origin strings are used only as in-memory equality keys.
// Requiring frame+document+initiator reduces spurious "same host" correlations.
const context=r=>{
 if(typeof r?.document!=='string'||!/^https?:\/\//i.test(r.document)||r.document.length>2048)return null;
 if(!Number.isInteger(r.frameId)||r.frameId<0||r.frameId>1000000)return null;
 if(typeof r.initiatorOrigin!=='string'||!/^https?:\/\//i.test(r.initiatorOrigin)||r.initiatorOrigin.length>256)return null;
 return JSON.stringify([r.document,r.frameId,r.initiatorOrigin]);
};
const definitions=Object.freeze([
 {grade:'Exact lifecycle',signal:'HTTP start and terminal share a browser request ID',scope:'Same browser-observed HTTP request stages; not proof of a separate response dependency'},
 {grade:'Exact lifecycle',signal:'Browser download start and outcome share a local reference',scope:'Same browser download lifecycle; not proof of the source HTTP request'},
 {grade:'Structural context',signal:'Responses share document, frame and initiator context',scope:'Same browser page context within 30 seconds; no dependency or same-asset claim'},
 {grade:'Timing clue',signal:'Nearby responses without a shared recorded context',scope:'Strictly ordered completions within 30 seconds; no causal relationship'}
]);
function analyze(input){
 const rec=recordObj(input)?input:{};
 const requests=Array.isArray(rec.requests)?rec.requests:[];
 const events=Array.isArray(rec.downloadEvents)?rec.downloadEvents:[];
 const sampleCapped=requests.length>REQUEST_LIMIT||events.length>EVENT_LIMIT;
 const timeline=[];let missingTime=0,missingContext=0,invalid=0;
 for(const r of requests.slice(0,REQUEST_LIMIT)){
  if(!recordObj(r)){invalid++;continue;}
  const at=iso(r.at);if(at===null){missingTime++;continue;}
  const ctx=context(r);if(!ctx)missingContext++;
  timeline.push({at,ctx});
 }
 timeline.sort((a,b)=>a.at-b.at);
 const occurrences=new Map();for(const x of timeline)occurrences.set(x.at,(occurrences.get(x.at)||0)+1);
 let structural=0,timing=0,ties=0,ambiguous=0,gaps=0;
 for(let i=1;i<timeline.length;i++){
  const prev=timeline[i-1],next=timeline[i],gap=next.at-prev.at;
  if(gap===0){ties++;continue;}
  if(occurrences.get(prev.at)>1||occurrences.get(next.at)>1){ambiguous++;continue;}
  if(gap>WINDOW_MS){gaps++;continue;}
  if(prev.ctx&&prev.ctx===next.ctx)structural++;
  else timing++;
 }
 const http=new Map(),downloads=new Map();
 let missingHTTPId=0,missingDLId=0,groupOverflow=0;
 for(const e of events.slice(0,EVENT_LIMIT)){
  if(!recordObj(e))continue;
  if(HTTP.has(e.stage)){
   if(!validRequestId(e.requestId)){missingHTTPId++;continue;}
   if(!http.has(e.requestId)){
    if(http.size>=GROUP_LIMIT){groupOverflow++;continue;}
    http.set(e.requestId,new Set());
   }
   http.get(e.requestId).add(e.stage);
  }else if(e.stage==='download-start'||e.stage==='download-state'){
   if(!validDL(e.downloadRef)){missingDLId++;continue;}
   if(!downloads.has(e.downloadRef)){
    if(downloads.size>=GROUP_LIMIT){groupOverflow++;continue;}
    downloads.set(e.downloadRef,new Set());
   }
   if(e.stage==='download-start')downloads.get(e.downloadRef).add('start');
   else if(e.downloadStatus==='complete'||e.downloadStatus==='interrupted')downloads.get(e.downloadRef).add('terminal');
  }
 }
 let exactHTTP=0,exactDL=0,incompleteHTTP=0,incompleteDL=0;
 for(const s of http.values()){
  const started=[...START].some(v=>s.has(v)),ended=[...TERMINAL].some(v=>s.has(v));
  if(started&&ended)exactHTTP++;
  else incompleteHTTP++;
 }
 for(const s of downloads.values()){
  if(s.has('start')&&s.has('terminal'))exactDL++;
  else incompleteDL++;
 }
 const nums=[exactHTTP,exactDL,structural,timing];
 const rows=definitions.map((d,i)=>({...d,count:MAX(nums[i]),evidence:i<2?'Exact local event-label equality':i===2?'Identical private page/frame/initiator keys and bounded chronology':'Adjacent unique completion timestamps only'}));
 const dropped=Object.entries(recordObj(rec.counters)?rec.counters:{}).reduce((sum,[key,value])=>
  /Dropped$/i.test(key)?Math.min(COUNT_LIMIT,sum+MAX(value)):sum,MAX(rec.downloadEventsDropped));
 const warnings=[];
 if(rec.downloadObserverEverEnabled!==true)warnings.push('Optional download observer not confirmed enabled; absence of lifecycle evidence is unknown');
 if(!rec.endedAt)warnings.push('Capture is not confirmed finalised');
 if(missingTime||invalid)warnings.push('Some HTTP completion records had invalid or missing timestamps');
 if(missingContext)warnings.push('Some timed HTTP records lacked complete page/frame/initiator context');
 if(ties||ambiguous)warnings.push('Equal timestamps and affected neighbours were excluded from ordered pairs');
 if(gaps)warnings.push('Response gaps over 30 seconds were excluded');
 if(incompleteHTTP||incompleteDL||missingHTTPId||missingDLId)warnings.push('Some observed event stages could not form complete exact lifecycle groups');
 if(dropped)warnings.push('Capture limits discarded some observations; relationship coverage is incomplete');
 if(sampleCapped||groupOverflow)warnings.push('Local analysis caps limited the evidence sample');
 if(timeline.length<2)warnings.push('Fewer than two usable HTTP completion records; response-pair analysis unavailable');
 return {
  format:'trufflehog-generic-relationship-confidence',version:1,
  overview:{timedHTTP:MAX(timeline.length),uniqueOrderedPairs:MAX(structural+timing),
   exactHTTPGroups:MAX(exactHTTP),exactDownloadGroups:MAX(exactDL),
   structuralContextPairs:MAX(structural),timingOnlyPairs:MAX(timing),
   incompleteHTTPGroups:MAX(incompleteHTTP),incompleteDownloadGroups:MAX(incompleteDL),
   ambiguousTimestampPairs:MAX(ties+ambiguous),missingOrInvalidTimes:MAX(missingTime+invalid),
   missingContext:MAX(missingContext),longGaps:MAX(gaps),missingGroupingLabels:MAX(missingHTTPId+missingDLId),
   droppedObservations:dropped,sampleCapped:!!(sampleCapped||groupOverflow)},
  rows,warnings:warnings.slice(0,12),
  grading:'Exact is limited to the lifecycle of one labelled browser event. Structural means shared browsing context, not direct linkage. Timing means proximity only. Counts from exact lifecycles and response pairs have different denominators and must not be summed.',
  caution:'No classification proves that one HTTP response caused another, that an API returned a media URL, that a download belongs to an HTTP request, or that an asset is an accessible original. Observer gaps, browser restarts and truncation can hide stages.',
  noAdditionalRequests:true,platformIdentificationRequired:false,credentialsRetained:false
 };
}
const API={analyze};root.THIGenericRelationshipConfidence=API;
if(typeof module==='object'&&module.exports)module.exports=API;
})(typeof self!=='undefined'?self:globalThis);
