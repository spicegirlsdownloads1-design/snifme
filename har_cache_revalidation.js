/* Trufflehog v7.8: user-selected HAR cache/revalidation evidence, in-memory only.
 * No URL, header value, ETag, cookie, credential, request ID, body, file, or time
 * is retained or returned. No network operations or requests are performed.
 */
(function(root){'use strict';
const MAX=12000;
const CATEGORIES=Object.freeze([
 'Conditional GET/HEAD with If-None-Match',
 'Conditional GET/HEAD with If-Modified-Since',
 'Conditional GET/HEAD with both validators (ETag takes precedence)',
 'GET/HEAD with If-Match or If-Unmodified-Since (other precondition)',
 'If-Range observed (range precondition, not cache revalidation)',
 'HTTP 304 Not Modified observed',
 '304 following a conditional GET/HEAD in the same HAR entry',
 '304 with no conditional request header visible',
 'HTTP 200 following a conditional GET/HEAD',
 'HTTP 206 following a conditional GET/HEAD',
 'HTTP 412 Precondition Failed observed',
 '304 with Cache-Control header',
 '304 with ETag header',
 '304 with Vary header',
 '304 with response body text in HAR (export artefact or anomaly)',
 'Response strong ETag header present',
 'Response weak ETag header present',
 'Response Last-Modified header present',
 'Response Vary header present',
 'Response Vary: * present',
 'Response Cache-Control: no-store',
 'Response Cache-Control: no-cache',
 'Response Cache-Control: private',
 'Response Cache-Control: public',
 'Response Cache-Control: immutable',
 'Response Cache-Control: must-revalidate',
 'Response Cache-Control: stale-while-revalidate',
 'Response Cache-Control: stale-if-error',
 'Response Cache-Control: s-maxage',
 'Response Cache-Control: max-age',
 'Response Age header present',
 'Response Age exceeds explicit max-age or s-maxage (header clue only)',
 'Response cache HIT indicator',
 'Response cache MISS indicator',
 'Response cache BYPASS or DYNAMIC indicator',
 'HTTP 304 on media MIME or media-suffix request (clue only)',
 'Missing request or response header arrays'
]);
const WARNINGS=Object.freeze([
 'HTTP 304 means a conditional request did not require retransmission of the selected representation. It is NOT a delivered asset, proof of download, evidence of public access or a cache-revocation test.',
 'If-None-Match takes precedence over If-Modified-Since for ordinary cache revalidation. If-Match, If-Unmodified-Since and If-Range serve different conditional-request purposes.',
 'A 200 after a conditional request is not proof that media was changed or that a cache malfunctioned. Preconditions, intermediaries and browser HAR coverage can alter observed outcomes.',
 'Age greater than a declared freshness lifetime is a header-only review clue. It is NOT proof of incorrect caching; response timing and stale-serving policy must be considered.',
 'A public Cache-Control directive alone does not establish that a signed or authenticated original is accessible anonymously. Vary and cache status indicators are likewise not access-control tests.',
 'HAR entries may omit request headers, cached responses, worker activity, redirect stages and downloaded bytes. These results are observational and cannot certify delivery, entitlements or invalidation.',
 'Reports export only fixed category labels, bounded numeric counts and yes/no/unknown comparisons. No source URLs, hosts, ETags, field values, credentials, timestamps or file paths are returned.'
]);
const CONTEXT=Object.freeze([['sameSite','Same website'],['sameActions','Same browser actions'],['sameAccount','Same account or role'],['sameScope','Same asset/gallery scope'],['sameBrowserCoverage','Equivalent browser capture coverage']]);
function headers(raw){const out=new Map();if(!Array.isArray(raw))return out;for(const h of raw.slice(0,150)){
 const k=typeof h?.name==='string'?h.name.toLowerCase().trim().slice(0,96):'';
 if(/^[a-z0-9-]{1,96}$/.test(k)&&!out.has(k))out.set(k,typeof h.value==='string'?h.value.slice(0,2048):'');
}return out;}
function http(raw){if(typeof raw!=='string'||raw.length>8192)return null;try{const u=new URL(raw);return ['http:','https:'].includes(u.protocol)?u:null;}catch{return null;}}
function ccDirective(raw,name){return new RegExp('(?:^|,)\\s*'+name+'(?:\\s*(?:=|,|$))','i').test(raw);}
function ageValue(raw){if(typeof raw!=='string'||!/^\s*(0|[1-9][0-9]{0,12})\s*$/.test(raw))return null;const num=Number(raw.trim());return Number.isSafeInteger(num)?num:null;}
function maxAge(raw){const shared=/(?:^|,)\s*s-maxage\s*=\s*"?(\d{1,12})"?(?:\s*,|\s*$)/i.exec(raw);const normal=/(?:^|,)\s*max-age\s*=\s*"?(\d{1,12})"?(?:\s*,|\s*$)/i.exec(raw);return shared?ageValue(shared[1]):normal?ageValue(normal[1]):null;}
function audit(har){
 const entries=har?.log?.entries;
 if(!Array.isArray(entries))throw Error('HAR must contain log.entries');
 if(entries.length>MAX)throw Error('HAR exceeds the 12,000-entry limit');
 const counter=Object.fromEntries(CATEGORIES.map(s=>[s,0]));const count=s=>{counter[s]++;};
 const coverage={totalEntries:entries.length,inspectedHttp:0,excludedEntries:0,conditionalSafeRequests:0,notModifiedResponses:0,missingHeaderEntries:0};
 for(const e of entries){
  const req=e?.request,res=e?.response,u=http(req?.url);
  if(!u||!res||typeof res!=='object'){coverage.excludedEntries++;continue;}
  coverage.inspectedHttp++;
  const requestHeaders=headers(req.headers),responseHeaders=headers(res.headers);
  const status=Number(res.status),method=String(req.method||'').toUpperCase();
  const safe=method==='GET'||method==='HEAD';
  if(!Array.isArray(req.headers)||!Array.isArray(res.headers)){coverage.missingHeaderEntries++;count('Missing request or response header arrays');}
  const inm=requestHeaders.has('if-none-match'),ims=requestHeaders.has('if-modified-since');
  const conditional=safe&&(inm||ims);
  if(safe&&inm)count('Conditional GET/HEAD with If-None-Match');
  if(safe&&ims)count('Conditional GET/HEAD with If-Modified-Since');
  if(safe&&inm&&ims)count('Conditional GET/HEAD with both validators (ETag takes precedence)');
  if(safe&&(requestHeaders.has('if-match')||requestHeaders.has('if-unmodified-since')))count('GET/HEAD with If-Match or If-Unmodified-Since (other precondition)');
  if(requestHeaders.has('if-range'))count('If-Range observed (range precondition, not cache revalidation)');
  if(conditional)coverage.conditionalSafeRequests++;
  if(status===304){
   coverage.notModifiedResponses++;count('HTTP 304 Not Modified observed');
   count(conditional?'304 following a conditional GET/HEAD in the same HAR entry':'304 with no conditional request header visible');
   if(responseHeaders.has('cache-control'))count('304 with Cache-Control header');
   if(responseHeaders.has('etag'))count('304 with ETag header');
   if(responseHeaders.has('vary'))count('304 with Vary header');
   if(typeof res.content?.text==='string'&&res.content.text.length)count('304 with response body text in HAR (export artefact or anomaly)');
   const mime=String(res.content?.mimeType||responseHeaders.get('content-type')||'').toLowerCase().slice(0,96);
   if(/^(?:image|video|audio)\//.test(mime)||/\.(?:jpe?g|png|gif|webp|avif|tiff?|svg|mp4|webm|mov)(?:$)/i.test(u.pathname.slice(-32)))count('HTTP 304 on media MIME or media-suffix request (clue only)');
  }
  if(conditional&&status===200)count('HTTP 200 following a conditional GET/HEAD');
  if(conditional&&status===206)count('HTTP 206 following a conditional GET/HEAD');
  if(status===412)count('HTTP 412 Precondition Failed observed');
  const etag=responseHeaders.get('etag');
  if(typeof etag==='string'){
   if(/^W\/"[^"\r\n]{0,512}"$/.test(etag))count('Response weak ETag header present');
   else if(/^"[^"\r\n]{0,512}"$/.test(etag))count('Response strong ETag header present');
  }
  if(responseHeaders.has('last-modified'))count('Response Last-Modified header present');
  if(responseHeaders.has('vary')){count('Response Vary header present');if(responseHeaders.get('vary').trim()==='*')count('Response Vary: * present');}
  const cc=String(responseHeaders.get('cache-control')||'').toLowerCase();
  for(const name of ['no-store','no-cache','private','public','immutable','must-revalidate','stale-while-revalidate','stale-if-error','s-maxage','max-age']){
   if(ccDirective(cc,name))count('Response Cache-Control: '+name);
  }
  const age=ageValue(responseHeaders.get('age'));
  if(responseHeaders.has('age'))count('Response Age header present');
  const freshness=maxAge(cc);
  if(age!==null&&freshness!==null&&age>freshness)count('Response Age exceeds explicit max-age or s-maxage (header clue only)');
  const cacheStatus=String(responseHeaders.get('cf-cache-status')||responseHeaders.get('x-cache')||'').toUpperCase().slice(0,120);
  if(/\bHIT\b/.test(cacheStatus))count('Response cache HIT indicator');
  else if(/\bMISS\b/.test(cacheStatus))count('Response cache MISS indicator');
  else if(/\b(BYPASS|DYNAMIC)\b/.test(cacheStatus))count('Response cache BYPASS or DYNAMIC indicator');
 }
 return Object.freeze({format:'trufflehog-har-cache-revalidation',version:1,coverage,signals:CATEGORIES.map(category=>({category,count:counter[category]})),warnings:[...WARNINGS,...(coverage.conditionalSafeRequests<5?['Fewer than five conditional safe requests: revalidation rates may be unstable.']:[])]});
}
const rate=(n,d)=>d?Math.round(n*100000/d)/100:null;
function compare(a,b,context={}){
 const x=audit(a),y=audit(b);
 const ctx=CONTEXT.map(([key,category])=>({category,answer:context[key]==='yes'||context[key]==='no'?context[key]:'unknown'}));
 const readiness=ctx.some(c=>c.answer==='no')?'Not comparable':ctx.every(c=>c.answer==='yes')&&x.coverage.conditionalSafeRequests>=5&&y.coverage.conditionalSafeRequests>=5?'Context declared comparable':'Context or coverage review needed';
 return Object.freeze({format:'trufflehog-har-cache-revalidation-comparison',version:1,readiness,context:ctx,
  coverage:[{capture:'Baseline HAR',...x.coverage},{capture:'Comparison HAR',...y.coverage}],
  signals:x.signals.map((r,i)=>({category:r.category,baseline:r.count,comparison:y.signals[i].count,
   baselinePer1000Http:rate(r.count,x.coverage.inspectedHttp),comparisonPer1000Http:rate(y.signals[i].count,y.coverage.inspectedHttp)})),
  warnings:[...WARNINGS,...(readiness!=='Context declared comparable'?['Do not treat these differences as evidence of media availability, policy drift or security exposure without comparable captures and owner-side validation.']:[])]});
}
const API=Object.freeze({audit,compare});root.THIHARCacheRevalidation=API;
if(typeof module==='object'&&module.exports)module.exports=API;
})(typeof self!=='undefined'?self:globalThis);
