/* Trufflehog Intelligence v7.13 — universal delivery-boundary evidence.
 * Pure, offline, fixed-label security-review indicators from an authorised
 * capture. NO URL values, secrets, browser IDs, hostnames or raw input fields
 * are ever returned. Not a vulnerability scanner or permissions test.
 */
(function(root){'use strict';
 const REQ_LIMIT=3000, EVENT_LIMIT=3000, COUNT_LIMIT=1000000;
 const bounded=n=>Number.isSafeInteger(n)&&n>=0?Math.min(COUNT_LIMIT,n):0;
 const isRecord=x=>!!x&&typeof x==='object'&&!Array.isArray(x);
 const origin=x=>{try{const u=new URL(String(x||''));return /^https?:$/.test(u.protocol)?u.origin:'';}catch{return '';}};
 const WRITE=new Set(['POST','PUT','PATCH','DELETE']);
 const BANDS=new Set(['up-to-15m','15m-to-24h','24h-to-7d','over-7d','invalid-declaration','unknown']);
 const SIGNALS=Object.freeze([
  ['Explicit URL-signing fields','Direct request metadata','A recognised signature-parameter name was observed, not a verified signing key or valid link.'],
  ['Signed delivery to another origin','Request metadata plus site-origin equality','Signed request origin differs from the captured tab origin; CDN ownership and access policy unknown.'],
  ['Signed response with public cache directive','Signature marker plus observed cache headers','A public cache directive does not establish unauthenticated access or a leak.'],
  ['Signed response with public cache at least 24 hours','Signature marker plus bounded cache seconds','Review cache/withdrawal controls; cache duration is not a signed-link validity guarantee.'],
  ['Declared signing window up to 15 minutes','Recognised numeric signed-query expiry parameter','Declared duration only; effective validity can be shorter.'],
  ['Declared signing window over 15 minutes, under 24 hours','Recognised numeric signed-query expiry parameter','Declared duration only; signature scope and effective expiry unverified.'],
  ['Declared signing window 24 hours to 7 days','Recognised numeric signed-query expiry parameter','A longer advertised window warrants owner policy review, not a vulnerability finding.'],
  ['Declared signing window over 7 days','Recognised numeric signed-query expiry parameter','The declared duration can be unsupported by the signing service. Do not infer validity.'],
  ['Signed request with no classified expiry','Signature marker without validated duration metadata','Other signing protocols or older captures may not expose an interpretable expiry duration.'],
  ['Unclassifiable declared expiry','Invalid numeric expiry on recognised signed-query format','Malformed or out-of-range declaration is not evidence a signing service accepted it.'],
  ['Cross-origin redirect step','Opt-in browser redirect event','Source and destination hosts differed; no entitlement or data-flow dependency inferred.'],
  ['Signed redirect step','Opt-in browser redirect event','A signing-parameter marker occurred in this redirect event; destination rights unknown.'],
  ['Attachment delivery response','Observed attachment Content-Disposition flag','The response indicated an attachment, not a verified downloaded or original file.'],
  ['API-like write accepted asynchronously','HTTP 202 on an observed Fetch/XHR write','May indicate a job; job status and resulting media are not established.'],
  ['Partial-content response','HTTP 206 from observed browser request','Partial content may be normal media streaming/range delivery.'],
  ['Access-denied response','HTTP 401 or 403','Denied means denied in this context, not evidence of alternative access.'],
  ['Server-error response','HTTP 5xx','A server error alone cannot diagnose an injection or parser flaw.'],
  ['Signed-query metadata unavailable','Legacy signed-query flag without an explicit signing marker','A token/expiry-like name alone is not a signature. Older records may lack new classifications.']
 ]);
 const index=Object.fromEntries(SIGNALS.map(([category],i)=>[category,i]));
 function analyze(input){
  const rec=isRecord(input)?input:{},requests=Array.isArray(rec.requests)?rec.requests:[],events=Array.isArray(rec.downloadEvents)?rec.downloadEvents:[];
  const count=new Array(SIGNALS.length).fill(0),site=origin(rec.origin);
  let invalid=0,ignored=0,knownMarkers=0;
  const add=label=>{count[index[label]]=bounded(count[index[label]]+1);};
  for(const r of requests.slice(0,REQ_LIMIT)){
   if(!isRecord(r)){invalid++;continue;}
   const explicit=r.signatureKeyPresent===true;
   if(explicit){
    knownMarkers++;
    add('Explicit URL-signing fields');
    const requestOrigin=origin(r.url);
    if(site&&requestOrigin&&requestOrigin!==site)add('Signed delivery to another origin');
    if(r.cacheScope==='public'&&r.cacheNoStore!==true){
     add('Signed response with public cache directive');
     if(Number.isFinite(r.cacheMaxAge)&&r.cacheMaxAge>=86400)add('Signed response with public cache at least 24 hours');
    }
    const band= BANDS.has(r.signedValidityWindow)?r.signedValidityWindow:'unknown';
    if(band==='up-to-15m')add('Declared signing window up to 15 minutes');
    else if(band==='15m-to-24h')add('Declared signing window over 15 minutes, under 24 hours');
    else if(band==='24h-to-7d')add('Declared signing window 24 hours to 7 days');
    else if(band==='over-7d')add('Declared signing window over 7 days');
    else if(band==='invalid-declaration')add('Unclassifiable declared expiry');
    else add('Signed request with no classified expiry');
   } else if(r.signedQuery===true && r.signatureKeyPresent!==false){
    // Legacy records lack signatureKeyPresent, while signedQuery can also mean
    // bearer tokens or a bare expiry field. Avoid upgrading either to a signature.
    add('Signed-query metadata unavailable');
   }
   if(r.attachmentDisposition===true)add('Attachment delivery response');
   const code=Number.isInteger(r.status)?r.status:0;
   if(code===202 && ['fetch','xmlhttprequest'].includes(String(r.type||'').toLowerCase()) && WRITE.has(String(r.method||'').toUpperCase()))add('API-like write accepted asynchronously');
   if(code===206)add('Partial-content response');
   if(code===401||code===403)add('Access-denied response');
   if(code>=500&&code<=599)add('Server-error response');
  }
  for(const e of events.slice(0,EVENT_LIMIT)){
   if(!isRecord(e)){ignored++;continue;}
   if(e.stage!=='redirect')continue;
   const src=typeof e.host==='string'?e.host:'',dest=typeof e.redirectHost==='string'?e.redirectHost:'';
   if(src&&dest&&src!==dest)add('Cross-origin redirect step');
   if(Array.isArray(e.signedIndicators)&&e.signedIndicators.includes('URL signing fields'))add('Signed redirect step');
  }
  const dropped=Object.entries(isRecord(rec.counters)?rec.counters:{}).reduce((total,[name,n])=>
    /Dropped$/i.test(name)?Math.min(COUNT_LIMIT,total+bounded(n)):total,bounded(rec.downloadEventsDropped));
  const warnings=[];
  if(!requests.length)warnings.push('No browser HTTP records were available; zero counts are not negative findings.');
  if(rec.downloadObserverEverEnabled!==true)warnings.push('Optional download observer not confirmed enabled; redirect coverage is unknown.');
  if(requests.length>REQ_LIMIT||events.length>EVENT_LIMIT)warnings.push('Analysis sample cap reached; additional records were not examined.');
  if(dropped)warnings.push('Capture retention dropped observations, so coverage is incomplete.');
  if(count[index['Signed-query metadata unavailable']])warnings.push('Some older signed-query flags cannot distinguish signatures from other sensitive query classes.');
  if(invalid||ignored)warnings.push('Invalid stored entries were excluded.');
  if(!rec.endedAt)warnings.push('Current capture may still be in progress.');
  return {
   format:'trufflehog-universal-delivery-boundaries',version:1,
   overview:{inspectedHTTP:bounded(Math.min(requests.length,REQ_LIMIT)),inspectedObserverEvents:bounded(Math.min(events.length,EVENT_LIMIT)),explicitSigningRequests:bounded(knownMarkers),droppedObservations:dropped,sampleCapped:requests.length>REQ_LIMIT||events.length>EVENT_LIMIT},
   rows:SIGNALS.map(([category,evidence,qualification],i)=>({category,count:bounded(count[i]),evidence,qualification})),
   warnings:warnings.slice(0,9),
   interpretation:'Review indicators from browser-observed traffic, not confirmed vulnerabilities, access control results, rights or original-file status.',
   notTested:'XXE, path traversal, remote code execution, parser patches, cloud role privileges, bearer validity, policy enforcement and anonymous access cannot be established from passive network records.',
   noAdditionalRequests:true,platformIdentificationRequired:false,credentialValuesRetained:false
  };
 }
 const API={analyze};root.THIUniversalBoundaryReview=API;
 if(typeof module==='object'&&module.exports)module.exports=API;
})(typeof self!=='undefined'?self:globalThis);
