/* Trufflehog Intelligence v7.10 — generic-first, single-capture intelligence.
 * Strictly offline analysis of observations already stored by an opted-in
 * capture. Unknown/custom systems are first-class: no vendor lookup is used.
 * Exports contain fixed labels and bounded counts ONLY, not observed values.
 */
(function(root){'use strict';
const MAX_REQUESTS=3000,MAX_EVENTS=3000,MAX_COUNT=1000000;
const safeCount=n=>Number.isSafeInteger(n)&&n>=0?Math.min(n,MAX_COUNT):0;
const rowsDefinition=Object.freeze([
 ['Documents','Observed browser document responses','Documents may include navigation and embedded frames.'],
 ['Scripts and styles','Observed JavaScript or stylesheet responses','Loaded file visibility is limited to what this capture recorded.'],
 ['API reads','Fetch/XHR reads or JSON responses','API-like traffic does not identify a backend product.'],
 ['API writes','Fetch/XHR POST, PUT, PATCH or DELETE','A write method does not prove state changed or a download started.'],
 ['Image and media responses','Observed images, video or audio','A received preview is not proof of a master/original file.'],
 ['External-origin requests','Recorded requests to origins other than the selected site','External hosts may be CDNs, APIs, analytics or unrelated services.'],
 ['HTTP 202 accepted','Responses with HTTP 202','May indicate an asynchronous operation; no job linkage established.'],
 ['HTTP 206 partial','Responses with HTTP 206','Partial transfers can be expected behaviour, not an error.'],
 ['HTTP redirects','Responses with HTTP 3xx','A redirect is not evidence of an entitlement change.'],
 ['HTTP 401/403','Responses with HTTP 401 or 403','Denied requests are observations, not bypass opportunities.'],
 ['HTTP 429','Responses with HTTP 429','Rate limiting was observed; do not automatically retry.'],
 ['HTTP failures','HTTP 5xx or recorded transport errors','An unsuccessful observation does not identify a root cause.'],
 ['Attachment responses','Responses marked with attachment disposition','Attachment presence does not establish a verified completed download.'],
 ['Signed-query indicators','Requests with recognised signed URL parameter classes','Only signing-field presence was observed, not its value or validity.'],
 ['Credential-query indicators','Requests with recognised credential-like query classes','A query-key pattern is not proof of a real credential or exposure.'],
 ['Long public-cache responses','Public cache evidence with TTL of 24 hours or more','CDN revocation and access policies require owner-side verification.'],
 ['Request authentication indicators','Opt-in header-name observations suggesting authentication','Header values, cookies and credentials are not retained or exported.'],
 ['Redirect lifecycle steps','Opt-in redirect observations in the download workflow','Steps may be missing and are not automatically joined across requests.'],
 ['Browser downloads completed','Opt-in Chrome download completion events','Download attribution remains conditional and may be lost on worker restart.'],
 ['Browser downloads interrupted','Opt-in Chrome download interruption events','A coarse browser outcome is not an HTTP access-control finding.'],
 ['JSON response shapes','Observed field-name/type summaries','Fields and types are evidence of structure, not the contents of a response.'],
 ['Public configuration clues','Captured public configuration-key summaries','A key name does not establish a leaked credential or vulnerability.'],
 ['Masked secret indicators','Potential masked secret-shaped findings','An indicator is not proof that a real credential exists or works.']
]);
const readMethod=x=>['POST','PUT','PATCH','DELETE'].includes(String(x||'').toUpperCase());
const status=x=>Number.isInteger(x)&&x>=100&&x<=599?x:0;
const originOf=x=>{try{const u=new URL(String(x||''));return /^https?:$/.test(u.protocol)?u.origin:'';}catch{return '';}};
const fixedIndicators=new Set([
 'Authorization header present','Cookie header present','API key header present',
 'CSRF header present','AWS session token header present',
 'Signature header present','Request signature header present','HMAC signature header present'
]);
function category(r){
 const type=String(r?.type||'').toLowerCase(),mime=String(r?.mime||'').toLowerCase();
 if(['main_frame','sub_frame'].includes(type)||mime.startsWith('text/html'))return 'Documents';
 if(['script','stylesheet'].includes(type)||/javascript/.test(mime)||mime.startsWith('text/css'))return 'Scripts and styles';
 if(type==='image'||type==='media'||/^(?:image|video|audio)\//.test(mime))return 'Image and media responses';
 if(['xmlhttprequest','fetch'].includes(type)||mime.includes('json'))return readMethod(r.method)?'API writes':'API reads';
 return '';
}
function analyze(record){
 const counts=Object.fromEntries(rowsDefinition.map(([label])=>[label,0]));
 const rec=record&&typeof record==='object'&&!Array.isArray(record)?record:{};
 const requests=Array.isArray(rec.requests)?rec.requests:[];
 const events=Array.isArray(rec.downloadEvents)?rec.downloadEvents:[];
 const origin=originOf(rec.origin);
 const counters=rec.counters&&typeof rec.counters==='object'&&!Array.isArray(rec.counters)?rec.counters:{};
 let dropped=safeCount(rec.downloadEventsDropped);
 for(const [k,v] of Object.entries(counters))if(/Dropped$/i.test(k))dropped=Math.min(MAX_COUNT,dropped+safeCount(v));
 let matchedOrigin=0,invalidScope=0,observed=0;
 for(const r of requests.slice(0,MAX_REQUESTS)){
  if(!r||typeof r!=='object'||Array.isArray(r))continue;
  const type=category(r);if(type)counts[type]++;
  const requestOrigin=originOf(r.url);
  if(requestOrigin&&origin){
   if(requestOrigin===origin)matchedOrigin++;
   else counts['External-origin requests']++;
  }else invalidScope++;
  observed++;
  const s=status(r.status);
  if(s===202)counts['HTTP 202 accepted']++;
  if(s===206)counts['HTTP 206 partial']++;
  if(s>=300&&s<400)counts['HTTP redirects']++;
  if(s===401||s===403)counts['HTTP 401/403']++;
  if(s===429)counts['HTTP 429']++;
  if(s>=500||r.error)counts['HTTP failures']++;
  if(r.attachmentDisposition===true)counts['Attachment responses']++;
  if(r.signedQuery===true)counts['Signed-query indicators']++;
  if(Array.isArray(r.authQueryClasses)&&r.authQueryClasses.length>0)counts['Credential-query indicators']++;
  if(r.cacheScope==='public'&&safeCount(r.cacheMaxAge)>=86400)counts['Long public-cache responses']++;
 }
 for(const e of events.slice(0,MAX_EVENTS)){
  if(!e||typeof e!=='object'||Array.isArray(e))continue;
  if(e.stage==='headers'&&Array.isArray(e.headerIndicators)&&e.headerIndicators.some(x=>fixedIndicators.has(x)))counts['Request authentication indicators']++;
  if(e.stage==='redirect')counts['Redirect lifecycle steps']++;
  if(e.stage==='download-state'&&e.downloadStatus==='complete')counts['Browser downloads completed']++;
  if(e.stage==='download-state'&&e.downloadStatus==='interrupted')counts['Browser downloads interrupted']++;
 }
 counts['JSON response shapes']=Math.min(MAX_COUNT,Array.isArray(rec.responses)?rec.responses.length:0);
 counts['Public configuration clues']=Math.min(MAX_COUNT,Array.isArray(rec.configs)?rec.configs.length:0);
 counts['Masked secret indicators']=Math.min(MAX_COUNT,Array.isArray(rec.findings)?rec.findings.length:0);
 const warnings=[];
 if(!origin)warnings.push('Capture origin missing or invalid; origin relationship counts may be incomplete');
 if(invalidScope)warnings.push('Some request origins were unavailable for classification');
 if(dropped)warnings.push('Some capture records were dropped due to local limits');
 if(requests.length>MAX_REQUESTS||events.length>MAX_EVENTS)warnings.push('Generic analysis sample cap reached');
 if(!rec.endedAt)warnings.push('Capture may still be active or was not finalised');
 if(rec.downloadObserverEverEnabled!==true)warnings.push('Download observer was not confirmed enabled; missing header/download evidence is unknown');
 if(!observed)warnings.push('No usable HTTP completion observations in this record');
 return {
  format:'trufflehog-generic-capture-intelligence',version:1,
  assessment:observed?'Generic observed traffic — platform identification unnecessary':'No usable HTTP evidence — cannot assess traffic',
  overview:{observedRequests:safeCount(observed),sameOriginRequests:safeCount(matchedOrigin),
   externalOriginRequests:safeCount(counts['External-origin requests']),observerEvents:safeCount(Math.min(events.length,MAX_EVENTS)),
   droppedEvents:dropped,sampleCapped:requests.length>MAX_REQUESTS||events.length>MAX_EVENTS},
  rows:rowsDefinition.map(([category,evidenceLimit,meaning])=>({category,count:safeCount(counts[category]),evidence:'Browser observation only',meaning:evidenceLimit,qualification:meaning})),
  warnings:warnings.slice(0,8),platformIdentificationRequired:false,
  noAdditionalRequests:true,credentialsRetained:false,
  caution:'A structural clue or HTTP response is not proof of a credential leak, accessible original asset, authorization weakness, platform identity, complete request coverage or causal connection between events.'
 };
}
const API={analyze,category};root.THIGenericIntelligence=API;
if(typeof module==='object'&&module.exports)module.exports=API;
})(typeof self!=='undefined'?self:globalThis);
