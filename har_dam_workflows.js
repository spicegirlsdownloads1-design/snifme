/* Trufflehog Intelligence v7.0 — offline HAR DAM workflow inventory.
   Zero network calls. Every output label is hard-coded and every count is numeric.
   Source-supplied strings, request IDs, URLs, headers, cookies and field names are
   inspected transiently ONLY; none are returned or retained by this module.
*/
(function(root){'use strict';
const MAX_ENTRIES=12000,MAX_HEADERS=80, MAX_PARAMS=120;
const providerNames=Object.freeze([
 'Capture DAM (service signal)','ResourceSpace (service signal)','PhotoShelter (service signal)',
 'Bynder (service signal)','Cloudinary (service signal)','Canto (service signal)',
 'FotoWare (service signal)','Amazon S3 (storage signal)','Amazon API Gateway (API signal)',
 'Amazon CloudFront (CDN signal)','Google Cloud Storage (storage signal)',
 'Azure Blob Storage (storage signal)','Cloudflare (edge-header signal)']);
const stages=Object.freeze([
 'API / JSON response','Image / media response','Attachment disposition header',
 'Download / rendition request clue','Export-job request clue','Export-status check clue',
 'Upload / multipart request clue','HTTP redirect','HTTP partial-content response',
 'HTTP authorisation denial','HTTP server / invalid-status indicator','Other observed HTTP request']);
const indicators=Object.freeze([
 'Authorization header present','Cookie-related header present','CSRF header present',
 'AWS SigV4 structure','Signing / token query field name','Presigned POST field names',
 'S3 multipart parameter names','Google resumable-upload clue','Azure block-upload clue',
 'tus protocol header','Tracing / request-ID header present','CDN edge header present',
 'Cache-Control header present','Public cache directive present','Image bytes unavailable in HAR',
 'Incomplete request or response metadata']);
const names=(arr)=>Object.fromEntries(arr.map(n=>[n,0]));
function hMap(hdrs){const out=new Map();if(!Array.isArray(hdrs))return out;
 for(const h of hdrs.slice(0,MAX_HEADERS)){
  const name=String(h?.name||'').toLowerCase().slice(0,128);
  if(/^[a-z0-9-]{1,128}$/.test(name)&&!out.has(name))out.set(name,String(h?.value||'').slice(0,256));
 }return out;
}
function hHas(map,key){return map.has(key)}
function matchDomain(h,domain){return h===domain||h.endsWith('.'+domain)}
function providerLabels(h, reqH,respH){
 const found=[];
 if(matchDomain(h,'captureweb.net'))found.push(providerNames[0]);
 if(matchDomain(h,'resourcespace.com'))found.push(providerNames[1]);
 if(matchDomain(h,'photoshelter.com')||matchDomain(h,'photoshelter.net'))found.push(providerNames[2]);
 if(['bynder.com','bynder.io','getbynder.com'].some(x=>matchDomain(h,x)))found.push(providerNames[3]);
 if(matchDomain(h,'cloudinary.com'))found.push(providerNames[4]);
 if(matchDomain(h,'canto.com')||matchDomain(h,'canto.global'))found.push(providerNames[5]);
 if(matchDomain(h,'fotoware.com'))found.push(providerNames[6]);
 if(/(^|\.)s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com$/.test(h)||/\.s3[.-][a-z0-9-]+\.amazonaws\.com$/.test(h))found.push(providerNames[7]);
 if(/(^|\.)execute-api\.[a-z0-9-]+\.amazonaws\.com$/.test(h))found.push(providerNames[8]);
 if(matchDomain(h,'cloudfront.net'))found.push(providerNames[9]);
 if(matchDomain(h,'storage.googleapis.com')||h==='storage.cloud.google.com')found.push(providerNames[10]);
 if(matchDomain(h,'blob.core.windows.net'))found.push(providerNames[11]);
 if(hHas(reqH,'cf-ray')||hHas(respH,'cf-ray'))found.push(providerNames[12]);
 return found;
}
function audit(har){
 const entries=har?.log?.entries;
 if(!Array.isArray(entries))throw Error('HAR must contain log.entries');
 if(entries.length>MAX_ENTRIES)throw Error('HAR exceeds the 12,000-entry processing limit');
 const providerCounts=names(providerNames), stageCounts=names(stages), signals=names(indicators), methods=names(['GET','POST','PUT','PATCH','DELETE','HEAD','OTHER']);
 const status=names(['2xx','3xx','4xx','5xx','No valid HTTP status']);
 let inspected=0,excluded=0,missingHeaders=0;
 for(const e of entries){
  if(!e||typeof e!=='object'||!e.request||!e.response){excluded++;continue;}
  const req=e.request,resp=e.response;
  let u;
  try{if(typeof req.url!=='string'||req.url.length>8192)throw Error('URL');u=new URL(req.url);if(!['https:','http:'].includes(u.protocol))throw Error('scheme');}catch{excluded++;continue;}
  const h=u.hostname.toLowerCase(),path=u.pathname.slice(0,800),q=u.searchParams;
  const queryNames=new Set([...q.keys()].slice(0,MAX_PARAMS).map(x=>String(x).toLowerCase()));
  const queryHas=k=>queryNames.has(k.toLowerCase());
  inspected++;
  const reqH=hMap(req.headers),respH=hMap(resp.headers);
  if(!Array.isArray(req.headers)||!Array.isArray(resp.headers)){signals['Incomplete request or response metadata']++;missingHeaders++;}
  const method=String(req.method||'').toUpperCase();methods[Object.hasOwn(methods,method)?method:'OTHER']++;
  const code=Number(resp.status);
  if(Number.isInteger(code)&&code>=200&&code<600){status[Math.floor(code/100)+'xx']++;}
  else status['No valid HTTP status']++;
  for(const label of providerLabels(h,reqH,respH))providerCounts[label]++;
  const type=String(resp.content?.mimeType||respH.get('content-type')||'').toLowerCase().slice(0,96);
  const requestType=String(req.postData?.mimeType||reqH.get('content-type')||'').toLowerCase().slice(0,96);
  const dispo=String(respH.get('content-disposition')||'').toLowerCase();
  const allHeaders=new Set([...reqH.keys(),...respH.keys()]);
  if(reqH.has('authorization')||reqH.has('proxy-authorization')||reqH.has('x-api-key'))signals['Authorization header present']++;
  if(allHeaders.has('cookie')||allHeaders.has('set-cookie'))signals['Cookie-related header present']++;
  if([...allHeaders].some(k=>/^(?:x-csrf|x-xsrf|csrf-token)/.test(k)))signals['CSRF header present']++;
  if(/^AWS4-HMAC-SHA256\s/i.test(reqH.get('authorization')||'')||queryHas('X-Amz-Algorithm'))signals['AWS SigV4 structure']++;
  if(['x-amz-signature','x-goog-signature','signature','sig','policy','token','expires','key-pair-id'].some(k=>queryHas(k)||queryHas(k.replaceAll('-','_'))))signals['Signing / token query field name']++;
  const postParams=Array.isArray(req.postData?.params)?req.postData.params.slice(0,MAX_PARAMS):[];
  const postKeys=new Set(postParams.map(x=>String(x?.name||'').toLowerCase().slice(0,96)));
  const hasPresignPost=['policy','x-amz-signature','x-amz-credential'].some(x=>postKeys.has(x));
  if(hasPresignPost)signals['Presigned POST field names']++;
  if(queryHas('uploadId')||queryHas('partNumber')||queryHas('uploads'))signals['S3 multipart parameter names']++;
  if(q.get('uploadType')==='resumable'||reqH.has('x-goog-resumable'))signals['Google resumable-upload clue']++;
  if(['block','blocklist'].includes(q.get('comp')||''))signals['Azure block-upload clue']++;
  if([...allHeaders].some(k=>['tus-resumable','upload-offset','upload-length','upload-metadata'].includes(k)))signals['tus protocol header']++;
  if([...allHeaders].some(k=>['traceparent','tracestate','x-request-id','x-amz-cf-id','x-correlation-id'].includes(k)))signals['Tracing / request-ID header present']++;
  if([...allHeaders].some(k=>['cf-ray','cf-cache-status','x-amz-cf-pop','x-amz-cf-id','x-cache'].includes(k)))signals['CDN edge header present']++;
  const cache=respH.get('cache-control')||'';
  if(respH.has('cache-control'))signals['Cache-Control header present']++;
  if(/(?:^|,)\s*public\b/i.test(cache))signals['Public cache directive present']++;
  if(type.startsWith('image/')&&!(typeof resp.content?.text==='string'))signals['Image bytes unavailable in HAR']++;
  // Multiple stage labels may apply to the same request, by design.
  let categorized=false;
  const inc=k=>{stageCounts[k]++;categorized=true};
  if(/json|graphql/.test(type))inc('API / JSON response');
  if(/^(image|video|audio)\//.test(type))inc('Image / media response');
  if(/^\s*attachment\b/.test(dispo))inc('Attachment disposition header');
  if(/\b(download|rendition|derivative|preview)(?:\b|[_/-])/i.test(path))inc('Download / rendition request clue');
  if(['POST','PUT'].includes(method)&&/\b(export|render|generate|prepare)(?:\b|[_/-])/i.test(path))inc('Export-job request clue');
  if(method==='GET'&&/\b(job|task|status|progress)(?:\b|[_/-])/i.test(path))inc('Export-status check clue');
  if(['POST','PUT','PATCH'].includes(method)&&(hasPresignPost||queryHas('uploadId')||queryHas('partNumber')||queryHas('uploads')||q.has('uploadType')||reqH.has('tus-resumable')||requestType.startsWith('multipart/form-data')))inc('Upload / multipart request clue');
  if(code>=300&&code<400&&respH.has('location'))inc('HTTP redirect');
  if(code===206)inc('HTTP partial-content response');
  if(code===401||code===403)inc('HTTP authorisation denial');
  if(!Number.isInteger(code)||code===0||code>=500)inc('HTTP server / invalid-status indicator');
  if(!categorized)inc('Other observed HTTP request');
 }
 const toRows=map=>Object.entries(map).map(([category,count])=>({category,count}));
 return Object.freeze({format:'trufflehog-har-dam-workflows',version:1,
  coverage:{totalEntries:entries.length,inspectedHttp:inspected,excludedEntries:excluded,missingHeaderArrays:missingHeaders},
  providers:toRows(providerCounts),stages:toRows(stageCounts),indicators:toRows(signals),
  methods:toRows(methods),statuses:toRows(status),
  limitations:[
   'Vendor-domain and protocol indicators show services observed, not the owner or product running the DAM.',
   'An observed response may be authenticated. Download and export stages are counts, not proven causal chains or file entitlements.',
   'A HAR may omit requests, bodies, download completion, worker traffic and authenticated events. Missing evidence is not a security finding.',
   'This local report contains only fixed category labels and counts; imported HAR contents are not saved, replayed or exported.',
   'Signed URLs, signing policies and credentials are neither tested nor retained.']});
}
const API=Object.freeze({audit});root.THIHARDAM=API;
if(typeof module==='object'&&module.exports)module.exports=API;
})(typeof self!=='undefined'?self:globalThis);
