/* Trufflehog Intelligence v6.5 — observed browser traffic patterns.
 * No requests, cookies, URL paths, hostnames, credentials, request IDs, or
 * response-body values are copied into reports. Differences are descriptive.
 */
(function(root){'use strict';
const LABELS=Object.freeze(['Documents','Scripts','Styles','API reads','API writes','Images','Other media','Downloads','Other']);
const MAX_SEGMENTS=40,PER_SEGMENT=3000,MAX_REQUESTS=12000;
function validOrigin(input){try{const u=new URL(String(input||''));return /^https?:$/.test(u.protocol)?u.origin:'';}catch{return '';}}
const safeCount=n=>Number.isSafeInteger(n)&&n>=0?Math.min(n,1e6):0;
function category(req){
 const method=String(req.method||'').toUpperCase(),type=String(req.type||'').toLowerCase(),mime=String(req.mime||'').toLowerCase();
 if(req.attachmentDisposition===true)return 'Downloads';
 if(type==='main_frame'||type==='sub_frame'||mime.startsWith('text/html'))return 'Documents';
 if(type==='script'||/javascript/.test(mime))return 'Scripts';
 if(type==='stylesheet'||mime==='text/css')return 'Styles';
 if(type==='image'||mime.startsWith('image/'))return 'Images';
 if(['video','media','audio'].includes(type)||/^(?:video|audio)\//.test(mime))return 'Other media';
 if(['fetch','xmlhttprequest'].includes(type)||mime.includes('json')){
  return ['POST','PUT','PATCH','DELETE'].includes(method)?'API writes':'API reads';
 }
 return 'Other';
}
function summary(records){
 if(!Array.isArray(records)||!records.length)throw Error('Select a saved capture group');
 const origin=validOrigin(records[0]?.origin);
 if(!origin)throw Error('Capture has no valid HTTP origin');
 let omitted=records.length>MAX_SEGMENTS,missing=false,dropped=0,unfinalized=0;
 const selected=records.slice(0,MAX_SEGMENTS).slice().sort((a,b)=>(safeCount(a?.segmentIndex)||0)-(safeCount(b?.segmentIndex)||0));
 const groups=new Set();const entries=[];const indexes=[];let seen=0,stamps=0;
 let dlCompleted=0,dlInterrupted=0;
 for(const segment of selected){
  if(validOrigin(segment?.origin)!==origin)throw Error('Mixed-origin capture group');
  const group=String(segment?.captureGroupId||segment?.sessionId||'');if(group)groups.add(group);
  if(!segment?.endedAt)unfinalized++;
  if(Number.isSafeInteger(segment?.segmentIndex)&&segment.segmentIndex>=0)indexes.push(segment.segmentIndex);
  const counters=segment?.counters&&typeof segment.counters==='object'&&!Array.isArray(segment.counters)?segment.counters:{};
  for(const [key,value] of Object.entries(counters))if(/Dropped$/i.test(key))dropped+=safeCount(value);
  if(!Array.isArray(segment?.requests)){missing=true;continue;}
  if(segment.requests.length>PER_SEGMENT)omitted=true;
  for(const r of segment.requests.slice(0,PER_SEGMENT)){
   if(seen>=MAX_REQUESTS){omitted=true;break;}
   if(!r||typeof r!=='object'||Array.isArray(r)||r.carriedFromSegment===true)continue;
   seen++;
   const time=Date.parse(r.at||'');
   if(Number.isFinite(time))stamps++;
   entries.push({kind:category(r),time:Number.isFinite(time)?time:null,seq:entries.length});
  }
  for(const e of (Array.isArray(segment?.downloadEvents)?segment.downloadEvents.slice(0,2000):[])){
   if(e?.stage!=='download-state')continue;
   if(e.downloadStatus==='complete')dlCompleted++;
   if(e.downloadStatus==='interrupted')dlInterrupted++;
  }
 }
 const ordered=stamps===entries.length&&entries.length>0?entries.sort((a,b)=>a.time-b.time||a.seq-b.seq):entries;
 const chronology=stamps===entries.length&&entries.length>0?'HTTP completion timestamps':'Segment record order (timestamps incomplete)';
 const counts=Object.fromEntries(LABELS.map(x=>[x,0]));
 const phases=Array.from({length:4},()=>Object.fromEntries(LABELS.map(x=>[x,0])));
 ordered.forEach((e,i)=>{counts[e.kind]++;phases[Math.min(3,Math.floor(i*4/ordered.length))][e.kind]++;});
 const total=ordered.length;
 const shares=Object.fromEntries(LABELS.map(x=>[x,total?counts[x]/total:0]));
 const phaseShares=phases.map(p=>{const n=Object.values(p).reduce((a,b)=>a+b,0);return Object.fromEntries(LABELS.map(k=>[k,n?p[k]/n:0]));});
 const orderedIndexes=[...new Set(indexes)].sort((a,b)=>a-b);
 const missingSequence=orderedIndexes.some((v,i)=>i>0&&v>orderedIndexes[i-1]+1);
 const limitations=[];
 if(omitted)limitations.push('Analysis sample cap reached');
 if(missing)limitations.push('Some segments lack request lists');
 if(dropped)limitations.push('Recorded dropped events');
 if(unfinalized)limitations.push('Unfinalized segments');
 if(missingSequence)limitations.push('Missing segment sequence');
 if(chronology!=='HTTP completion timestamps')limitations.push('Request timestamps missing or partial; record order substituted');
 if(!total)limitations.push('No usable HTTP observations');
 return {origin,group:groups.size===1?[...groups][0]:null,counts,shares,phaseShares,
  total,segments:selected.length,limitations,chronology,downloadCompleted:dlCompleted,downloadInterrupted:dlInterrupted};
}
function distance(a,b){return LABELS.reduce((sum,k)=>sum+Math.abs((a[k]||0)-(b[k]||0)),0)/2;}
const percent=v=>Math.round(v*1000)/10;
function compare(first,second){
 const a=summary(first),b=summary(second);
 if(a.origin!==b.origin)throw Error('Compare saved captures from the same exact origin');
 if(a.group&&b.group&&a.group===b.group)throw Error('Select different saved capture groups');
 const mixture=distance(a.shares,b.shares);
 const phaseDifference=a.phaseShares.reduce((sum,p,i)=>sum+distance(p,b.phaseShares[i]),0)/4;
 const sampleAdequate=a.total>=40&&b.total>=40;
 const coverageLimited=a.limitations.some(x=>!/Request timestamps missing/.test(x))||b.limitations.some(x=>!/Request timestamps missing/.test(x));
 const timingComplete=a.chronology==='HTTP completion timestamps'&&b.chronology==='HTTP completion timestamps';
 let assessment='Insufficient captured observations';
 if(sampleAdequate){
  if(mixture>=0.35||(timingComplete&&phaseDifference>=0.45))assessment='Materially different observed request pattern';
  else if(mixture<=0.15&&(!timingComplete||phaseDifference<=0.25))assessment='Similar observed request composition';
  else assessment='Some differences in observed request patterns';
 }
 const limitations=[...new Set([...a.limitations.map(x=>'Baseline: '+x),...b.limitations.map(x=>'Comparison: '+x)])];
 if(!timingComplete)limitations.push('Sequence comparison uses record order and may be unreliable');
 if(coverageLimited)limitations.push('Incomplete capture limits all pattern comparisons');
 if(a.total&&b.total&&Math.max(a.total,b.total)/Math.min(a.total,b.total)>3)limitations.push('Request volumes differ by more than 3×');
 const rows=LABELS.map(label=>({category:label,baseline:a.counts[label],comparison:b.counts[label],
  baselinePercent:percent(a.shares[label]),comparisonPercent:percent(b.shares[label]),
  differencePoints:Math.round((b.shares[label]-a.shares[label])*1000)/10}));
 const phaseRows=a.phaseShares.map((p,i)=>{
  const x=LABELS.reduce((best,k)=>p[k]>p[best]?k:best,LABELS[0]);
  const q=b.phaseShares[i];const y=LABELS.reduce((best,k)=>q[k]>q[best]?k:best,LABELS[0]);
  return {phase:'Quarter '+(i+1),baselineDominant:x,comparisonDominant:y,
   differencePercent:percent(distance(p,q))};
 });
 return {format:'trufflehog-observed-workflow-pattern',version:1,
  assessment,hasEquivalentContextProof:false,
  overview:{baselineRequests:a.total,comparisonRequests:b.total,
   requestMixDifferencePercent:percent(mixture),phasePatternDifferencePercent:percent(phaseDifference),
   enoughSamples:sampleAdequate,sequenceEvidence:timingComplete?'HTTP completion timestamps':'Partial: fallback record order',
   baselineCompletedDownloads:a.downloadCompleted,comparisonCompletedDownloads:b.downloadCompleted,
   baselineInterruptedDownloads:a.downloadInterrupted,comparisonInterruptedDownloads:b.downloadInterrupted},
  rows,phaseRows,limitations:limitations.slice(0,20),
  caution:'Similar recorded HTTP patterns do not verify identical actions, account roles, gallery scopes, host permissions, image entitlements or complete capture. Different patterns do not prove an access-control or CDN-policy change.'};
}
const API={compare,summary,category,labels:LABELS};root.THIWorkflowPattern=API;
if(typeof module==='object'&&module.exports)module.exports=API;
})(typeof self!=='undefined'?self:globalThis);
