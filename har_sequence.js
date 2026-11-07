/* Trufflehog Intelligence v7.1 — offline, privacy-bounded HAR stage timeline.
   Invariant: return only fixed categorical labels, bounded integers, and fixed
   warnings. Never return source-derived URLs, paths, hostnames, identifiers,
   timestamps, credentials, request/response bodies, headers, or arbitrary text.
   No network calls and NO inference of a causal chain from temporal proximity.
*/
(function(root){'use strict';
const LIMIT=12000, MAX_EVENTS=240, MAX_HEADERS=80, MAX_PARAMS=120;
const METHODS=Object.freeze(['GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS','OTHER']);
const PROVIDERS=Object.freeze(['Capture service','ResourceSpace service','PhotoShelter service','Bynder service','Cloudinary service','Canto service','FotoWare service','S3 storage','CloudFront CDN','AWS API gateway','Google Cloud Storage','Azure Blob','Unknown/other service']);
const STAGES=Object.freeze(['Upload / resumable transfer clue','Export preparation request clue','Export status request clue','Attachment delivery response','HTTP redirect response','Access denied response','Partial-content response','Media response','Structured API response']);
const TIME_BANDS=Object.freeze(['Under 2 seconds','2–10 seconds','10–60 seconds','1–5 minutes','Over 5 minutes','Not available','Before first valid timestamp']);
const statusClass=s=>{const n=Number(s);return Number.isInteger(n)&&n>=100&&n<=599?Math.floor(n/100)+'xx':'Unavailable'};
function headers(a){const o=new Map();if(!Array.isArray(a))return o;for(const h of a.slice(0,MAX_HEADERS)){
 const k=String(h?.name||'').toLowerCase();if(/^[a-z0-9-]{1,128}$/.test(k)&&!o.has(k))o.set(k,String(h?.value||'').slice(0,256));
}return o;}
function hostRole(host){const h=host.toLowerCase(),ends=d=>h===d||h.endsWith('.'+d);
 if(ends('captureweb.net'))return PROVIDERS[0];if(ends('resourcespace.com'))return PROVIDERS[1];
 if(ends('photoshelter.com')||ends('photoshelter.net'))return PROVIDERS[2];
 if(['bynder.com','bynder.io','getbynder.com'].some(ends))return PROVIDERS[3];
 if(ends('cloudinary.com'))return PROVIDERS[4];if(ends('canto.com')||ends('canto.global'))return PROVIDERS[5];
 if(ends('fotoware.com'))return PROVIDERS[6];
 if(/(^|\.)s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com$/.test(h)||/\.s3[.-][a-z0-9-]+\.amazonaws\.com$/.test(h))return PROVIDERS[7];
 if(ends('cloudfront.net'))return PROVIDERS[8];
 if(/(^|\.)execute-api\.[a-z0-9-]+\.amazonaws\.com$/.test(h))return PROVIDERS[9];
 if(ends('storage.googleapis.com')||h==='storage.cloud.google.com')return PROVIDERS[10];
 if(ends('blob.core.windows.net'))return PROVIDERS[11];
 return PROVIDERS[12];
}
function getTime(s){if(typeof s!=='string'||s.length>48||!/^\d{4}-\d\d-\d\dT/.test(s))return null;const t=Date.parse(s);return Number.isFinite(t)?t:null;}
function band(delta){if(delta===null)return TIME_BANDS[5];if(delta<0)return TIME_BANDS[6];if(delta<2000)return TIME_BANDS[0];if(delta<10000)return TIME_BANDS[1];if(delta<60000)return TIME_BANDS[2];if(delta<300000)return TIME_BANDS[3];return TIME_BANDS[4];}
function classify(e){
 if(!e||typeof e!=='object'||!e.request||!e.response)return null;
 const req=e.request,resp=e.response;let u;
 try{if(typeof req.url!=='string'||req.url.length>8192)throw 0;u=new URL(req.url);if(u.protocol!=='http:'&&u.protocol!=='https:')throw 0;}catch{return null;}
 const method=String(req.method||'').toUpperCase(),m=METHODS.includes(method)?method:'OTHER',p=u.pathname.slice(0,800);
 const qNames=new Set([...u.searchParams.keys()].slice(0,MAX_PARAMS).map(x=>x.toLowerCase()));
 const qHas=x=>qNames.has(x);
 const reqH=headers(req.headers),respH=headers(resp.headers),code=Number(resp.status);
 const type=String(resp.content?.mimeType||respH.get('content-type')||'').slice(0,96).toLowerCase();
 const postType=String(req.postData?.mimeType||reqH.get('content-type')||'').slice(0,96).toLowerCase();
 const names=new Set((Array.isArray(req.postData?.params)?req.postData.params.slice(0,MAX_PARAMS):[]).map(x=>String(x?.name||'').toLowerCase().slice(0,96)));
 const isUpload=['POST','PUT','PATCH'].includes(m)&&(
  ['policy','x-amz-signature','x-amz-credential'].some(x=>names.has(x))||
  ['uploads','uploadid','partnumber','uploadtype'].some(qHas)||
  reqH.has('tus-resumable')||reqH.has('upload-offset')||reqH.has('x-goog-resumable')||
  ['block','blocklist'].includes(u.searchParams.get('comp'))||postType.startsWith('multipart/form-data'));
 const exportClue=['POST','PUT'].includes(m)&&/\b(export|render|generate|prepare)(?:\b|[_/-])/i.test(p);
 const statusClue=m==='GET'&&/\b(job|task|status|progress)(?:\b|[_/-])/i.test(p);
 const attachment=/^\s*attachment\b/i.test(respH.get('content-disposition')||'');
 const redirect=Number.isInteger(code)&&code>=300&&code<400&&respH.has('location');
 const denied=code===401||code===403;
 const partial=code===206;
 const media=/^(?:image|video|audio)\//.test(type);
 const api=/json|graphql/.test(type);
 // Precedence deliberately prevents one response being counted as several "events".
 const stage=isUpload?STAGES[0]:exportClue?STAGES[1]:statusClue?STAGES[2]:attachment?STAGES[3]:redirect?STAGES[4]:denied?STAGES[5]:partial?STAGES[6]:media?STAGES[7]:api?STAGES[8]:null;
 if(!stage)return {relevant:false,time:getTime(e.startedDateTime)};
 const basis=[STAGES[0],STAGES[1],STAGES[2]].includes(stage)?'Protocol or path-name clue':
  stage===STAGES[3]||stage===STAGES[4]?'Response header observed':
  stage===STAGES[5]||stage===STAGES[6]?'HTTP status observed':'MIME type observed';
 return {relevant:true,stage,method:m,status:statusClass(resp.status),provider:hostRole(u.hostname),basis,time:getTime(e.startedDateTime)};
}
function audit(har){
 const source=har?.log?.entries;if(!Array.isArray(source))throw Error('HAR must contain log.entries');
 if(source.length>LIMIT)throw Error('HAR exceeds the 12,000-entry limit');
 const events=[];let considered=0,invalid=0,unclassified=0,omitted=0,missingTimes=0,backwards=0,first=null,last=null;
 const stageTotals=new Map(STAGES.map(stage=>[stage,0]));
 let exportIndex=-1,statusSeen=0;
 const lastCandidates=[];
 for(let i=0;i<source.length;i++){
  const item=classify(source[i]);if(!item){invalid++;continue;}considered++;
  if(item.time===null)missingTimes++;
  if(item.time!==null){if(first===null)first=item.time;if(last!==null&&item.time<last)backwards++;last=item.time;}
  if(!item.relevant){unclassified++;continue;}
  stageTotals.set(item.stage,(stageTotals.get(item.stage)||0)+1);
  // The entire source is considered for counts; only a bounded sample is shown.
  if(events.length>=MAX_EVENTS){omitted++;continue;}
  const ordinal=i+1;const output={order:ordinal,stage:item.stage,method:item.method,status:item.status,
   provider:item.provider,basis:item.basis,timeBand:band(first===null||item.time===null?null:item.time-first)};
  events.push(output);
  if(item.stage===STAGES[1]){exportIndex=i;statusSeen=0;}
  else if(exportIndex>=0&&i-exportIndex<=40){
   if(item.stage===STAGES[2])statusSeen++;
   if(item.stage===STAGES[3])lastCandidates.push({statusSeen:statusSeen>0});
  }
 }
 // These summaries describe ORDER only. No claims of same asset/account/causality.
 const patterns=[
  {category:'Export preparation followed by attachment within 40 HAR entries',count:lastCandidates.length},
  {category:'Export preparation, status check, then attachment within 40 HAR entries',count:lastCandidates.filter(x=>x.statusSeen).length},
  {category:'Events excluded from bounded timeline',count:omitted}];
 return Object.freeze({format:'trufflehog-har-sequence',version:1,coverage:{totalEntries:source.length,
  inspectedHttp:considered,invalidEntries:invalid,unclassifiedHttp:unclassified,
  candidateStageEvents:events.length+omitted,shownStageEvents:events.length,omittedStageEvents:omitted,
  missingTimestamps:missingTimes,nonMonotonicTimestamps:backwards},stageCounts:STAGES.map(category=>({category,count:stageTotals.get(category)||0})),events,patterns,
  limitations:[
   'Rows follow original HAR entry order; this may not be chronological. Time bands are relative and never contain original timestamps.',
   'Matching stage names and proximity do not prove causal linkage, asset identity, authorisation or successful download completion.',
   'Request URL paths are read transiently only to classify broad clues; no URL or raw request identifier is exported.',
   'HAR exports may omit response content, browser downloads, worker requests, headers or events; absent evidence is inconclusive.',
   'The displayed timeline is capped at 240 relevant requests; counts include subsequent classified entries.',
   'This report uses fixed labels and numeric fields only; the original HAR is neither stored nor replayed.']});
}
// Strictly categorical projection: no original time, host, path or identifier escapes.
function stageSignal(entry){const x=classify(entry);return x&&x.relevant?Object.freeze({stage:x.stage,provider:x.provider}):null;}
const API=Object.freeze({audit,stageSignal});root.THIHARSequence=API;
if(typeof module==='object'&&module.exports)module.exports=API;
})(typeof self!=='undefined'?self:globalThis);
