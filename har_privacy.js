/* Trufflehog Intelligence v6.9 — offline HAR privacy preflight.
 * Browser-only inspection of a user-selected HAR; no network, storage or secrets.
 * Never return any source-supplied string, filename, URL, header or field name.
 */
(function(root){'use strict';
const LIMIT=12000;
const SIGNALS=Object.freeze([
 ['authorization','Authentication-related header names'],
 ['cookies','Browser cookie field evidence'],
 ['urlQuery','URLs with query parameters'],
 ['sensitiveQuery','Credential-like query parameter names'],
 ['urlCredentials','URL-embedded username/password'],
 ['requestBody','Request body / form values present'],
 ['responseBody','Response body text present'],
 ['responseRedirect','Redirect destination headers'],
 ['requestMetadata','HAR query/cookie parameter arrays'],
 ['tracing','Trace and request-correlation header names'],
 ['pageMetadata','HAR page titles / navigation metadata']
]);
const isObj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const arr=x=>Array.isArray(x)?x:[];
const headerNames=x=>arr(x).slice(0,2000).map(h=>typeof h?.name==='string'?h.name.toLowerCase().slice(0,128):'');
const has=n=>name=>n.includes(name);
const sensitiveQueryName=name=>/^(?:access[_-]?token|api[_-]?key|secret|token|auth|authorization|jwt|session|password|passwd|signature|sig|x-amz-(?:credential|signature|security-token|algorithm|date)|x-goog-(?:credential|signature|security-token|algorithm|date)|policy|key-pair-id|expires|oauth[_-]?token|client[_-]?secret|code)$/i.test(name);
const counters=()=>Object.fromEntries(SIGNALS.map(([id])=>[id,0]));
const safeCount=n=>Number.isSafeInteger(n)&&n>=0?Math.min(n,LIMIT):0;
function audit(har){
 const log=isObj(har)?har.log:null;
 if(!isObj(log)||!Array.isArray(log.entries))throw Error('Select a valid HAR file containing log.entries');
 if(log.entries.length>LIMIT)throw Error('HAR has too many entries for bounded offline inspection (maximum 12,000)');
 const count=counters();let malformed=0,nonHttp=0;
 for(const item of log.entries){
  if(!isObj(item)||!isObj(item.request)||!isObj(item.response)){malformed++;continue;}
  const req=item.request,resp=item.response;
  // Parsing URLs is read-only. Neither the URL nor its parsed fields leave this call.
  let parsed=null;
  try{parsed=new URL(String(req.url||'').slice(0,8192));}catch{}
  if(!parsed||!/^https?:$/.test(parsed.protocol)){nonHttp++;continue;}
  const rq=headerNames(req.headers),rs=headerNames(resp.headers),all=[...rq,...rs],includes=has(all);
  if(all.some(x=>['authorization','proxy-authorization','x-api-key','api-key','x-auth-token','x-amz-security-token'].includes(x)))count.authorization++;
  if(includes('cookie')||includes('set-cookie')||arr(req.cookies).length>0||arr(resp.cookies).length>0)count.cookies++;
  if(parsed.search)count.urlQuery++;
  if(parsed.username||parsed.password)count.urlCredentials++;
  if(Array.from(parsed.searchParams.keys()).some(k=>sensitiveQueryName(k.slice(0,128)))||arr(req.queryString).some(p=>sensitiveQueryName(String(p?.name||'').slice(0,128))))count.sensitiveQuery++;
  if(Object.hasOwn(req.postData||{},'text')||arr(req.postData?.params).length>0)count.requestBody++;
  if(Object.hasOwn(resp.content||{},'text'))count.responseBody++;
  if(includes('location'))count.responseRedirect++;
  if(arr(req.queryString).length>0||arr(req.cookies).length>0||arr(resp.cookies).length>0||arr(req.postData?.params).length>0)count.requestMetadata++;
  if(all.some(x=>['traceparent','tracestate','cf-ray','x-request-id','x-amz-cf-id','x-b3-traceid','x-correlation-id'].includes(x)))count.tracing++;
 }
 count.pageMetadata=arr(log.pages).length>0?Math.min(arr(log.pages).length,LIMIT):0;
 const severe=count.authorization+count.cookies+count.sensitiveQuery+count.urlCredentials+count.requestBody+count.responseBody;
 const assessment=severe?'Potentially sensitive HAR structures observed — restrict sharing':
   count.urlQuery||count.requestMetadata||count.responseRedirect||count.tracing||count.pageMetadata?
   'Potentially identifying HAR metadata observed — review before sharing':
   'No listed high-risk structures observed — sharing safety NOT verified';
 const rows=SIGNALS.map(([id,label])=>({category:label,count:safeCount(count[id])}));
 const advice=[
  'Keep the original HAR private; URLs, paths, custom headers and file names can be sensitive even when no listed indicator is detected.',
  'Use Chrome DevTools sanitised HAR export when available; independently review the exported file before sharing.',
  'The numeric privacy preflight report never includes HAR request/response values or identifiers.',
  'Do not upload or share the original HAR as part of a support request unless specifically authorised.'
 ];
 return {format:'trufflehog-har-privacy-preflight',version:1,assessment,
  coverage:{entries:safeCount(log.entries.length),malformed:safeCount(malformed),nonHttp:safeCount(nonHttp),pages:safeCount(arr(log.pages).length)},
  rows,advice,noAdditionalRequests:true,rawValuesRetained:false,
  limitations:'Structure-only checks; this is not a complete secret scan or certification that a HAR is safe to share. The selected file remains locally accessible to the browser while in use.'};
}
const API=Object.freeze({audit});root.THIHARPrivacy=API;
if(typeof module==='object'&&module.exports)module.exports=API;
})(typeof self!=='undefined'?self:globalThis);
