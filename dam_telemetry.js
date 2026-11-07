/* Trufflehog v5.2 — privacy-bounded, passive DAM delivery telemetry.
 * Opaque trace headers are held in a bounded, service-worker-only map and
 * replaced with session-local labels before any persisted event is created.
 * This extension neither creates server traces nor emits external CloudEvents.
 */
'use strict';
const THITelemetry = (() => {
  const traceGroups=new Map();
  const maxContexts=60,maxTracesPerContext=300;
  const getHeader=(headers,name)=>Array.isArray(headers)?headers.find(h=>String(h?.name||'').toLowerCase()===name)?.value:'';
  const hasHeader=(headers,name)=>Array.isArray(headers)&&headers.some(h=>String(h?.name||'').toLowerCase()===name);
  function parseTrace(value){
    const text=String(value||'').trim();
    const m=/^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$/i.exec(text);
    if(!m||m[1].toLowerCase()==='ff'||/^0{32}$/.test(m[2])||/^0{16}$/.test(m[3]))return null;
    return {id:m[2].toLowerCase(),version:m[1].toLowerCase(),sampled:!!(parseInt(m[4],16)&1)};
  }
  function traceLabel(value,context){
    const parsed=parseTrace(value);
    if(!parsed)return null;
    const scope=String(context||'unknown').slice(0,120);
    let map=traceGroups.get(scope);
    if(!map){
      if(traceGroups.size>=maxContexts)traceGroups.delete(traceGroups.keys().next().value);
      map={labels:new Map(),next:1};traceGroups.set(scope,map);
    }
    if(!map.labels.has(parsed.id)){
      if(map.labels.size>=maxTracesPerContext)map.labels.delete(map.labels.keys().next().value);
      map.labels.set(parsed.id,'Trace '+(map.next++));
    }
    return {label:map.labels.get(parsed.id),version:parsed.version,sampled:parsed.sampled};
  }
  function headerEvidence(headers,scope){
    const auth=String(getHeader(headers,'authorization')||'');
    let authentication='not observed';
    if(/^Bearer\s/i.test(auth))authentication='Bearer';
    else if(/^Basic\s/i.test(auth))authentication='Basic';
    else if(/^AWS4-HMAC-SHA256(?:\s|$)/i.test(auth))authentication='AWS SigV4';
    else if(auth)authentication='Other authorization';
    else if(hasHeader(headers,'cookie'))authentication='Cookie present';
    const scheme=/^(?:AWS4-HMAC-SHA256)(?:\s|$)/i.test(auth)?'AWS SigV4':
      hasHeader(headers,'x-hmac-signature')?'HMAC header':
      hasHeader(headers,'x-request-signature')||hasHeader(headers,'x-signature')?'Signature header':'not observed';
    const raw=getHeader(headers,'traceparent');
    const parsed=traceLabel(raw,scope);
    const cdn=['cf-ray','x-amz-cf-id','x-amz-cf-pop','x-cache','via'].filter(n=>hasHeader(headers,n)).map(n=>({
      'cf-ray':'Cloudflare request ID present','x-amz-cf-id':'CloudFront request ID present',
      'x-amz-cf-pop':'CloudFront POP header present','x-cache':'Cache result header present',
      'via':'Proxy Via header present'}[n]));
    return {authentication,signatureScheme:scheme,traceRef:parsed?.label||'',traceVersion:parsed?.version||'',
      traceSampled:parsed?parsed.sampled:null,traceHeaderPresent:!!raw,
      traceFormatValid:!!parsed,tracestatePresent:hasHeader(headers,'tracestate'),
      cdnEvidence:cdn,requestIdHeaderPresent:hasHeader(headers,'x-request-id')||hasHeader(headers,'x-correlation-id')};
  }
  function responseEvidence(headers){
    const rawLength=getHeader(headers,'content-length');
    const contentLength=rawLength===''||rawLength===undefined?NaN:Number(rawLength);
    const bytes=Number.isSafeInteger(contentLength)&&contentLength>=0&&contentLength<=1e13?contentLength:null;
    const cc=String(getHeader(headers,'cache-control')||'').toLowerCase().slice(0,300);
    const ageMatch=/(?:^|,)\s*(?:s-maxage|max-age)\s*=\s*(\d{1,10})\b/i.exec(cc);
    const cacheAge=ageMatch?Math.min(315360000,Number(ageMatch[1])):null;
    let cachePolicy='not observed';
    if(/\bno-store\b/.test(cc))cachePolicy='no-store';
    else if(/\bprivate\b/.test(cc))cachePolicy='private';
    else if(/\bpublic\b/.test(cc))cachePolicy='public';
    else if(/\bno-cache\b/.test(cc))cachePolicy='no-cache';
    else if(cc)cachePolicy='other directive';
    return {contentLengthBytes:bytes,cachePolicy,cacheMaxAgeSeconds:cacheAge,
      etagPresent:hasHeader(headers,'etag'),lastModifiedPresent:hasHeader(headers,'last-modified')};
  }
  function sizeFacts(item){
    const size=x=>Number.isSafeInteger(x)&&x>=0&&x<=1e13?x:null;
    const total=size(item?.totalBytes),received=size(item?.bytesReceived);
    return {totalBytes:total,receivedBytes:received,percent:total>0&&received!==null?Math.min(100,Math.round(received/total*100)):null,
      canResume:typeof item?.canResume==='boolean'?item.canResume:null};
  }
  function errorCategory(err){
    if(typeof err!=='string')return 'unknown';
    if(/^NETWORK_/.test(err))return 'network';
    if(/^SERVER_/.test(err))return 'server';
    if(/^FILE_/.test(err))return 'filesystem';
    if(/^USER_/.test(err))return 'user action';
    if(/^CRASH/.test(err))return 'browser';
    return 'other';
  }
  const safeHost=h=>/^[a-z0-9.-]{1,255}$/i.test(String(h||''))?String(h).toLowerCase():'';
  function cloudEvents(events,sessionId){
    const sid=/^[a-z0-9-]{1,80}$/i.test(String(sessionId||''))?String(sessionId):'local';
    return (Array.isArray(events)?events:[]).slice(0,3000).map((e,i)=>({
      specversion:'1.0',id:`${sid}-${i+1}`,source:'/trufflehog/local-download-observer',
      type:'com.trufflehog.observation.download.step',
      time:/^\d{4}-\d{2}-\d{2}T/.test(String(e.at||''))?e.at:new Date(0).toISOString(),
      datacontenttype:'application/json',
      data:{stage:['request','headers','response-headers','redirect','complete','error','download-start','download-state'].includes(e.stage)?e.stage:'other',
        method:['GET','POST','PUT','PATCH','DELETE','HEAD'].includes(e.method)?e.method:'OTHER',
        host:safeHost(e.host),status:Number.isInteger(e.status)?e.status:null,
        traceRef:/^Trace \d{1,4}$/.test(e.traceRef||'')?e.traceRef:null,
        authentication:['Bearer','Basic','AWS SigV4','Other authorization','Cookie present','not observed'].includes(e.authentication)?e.authentication:null,
        downloadStatus:['started','progress','complete','interrupted'].includes(e.downloadStatus)?e.downloadStatus:null,
        errorCategory:['unknown','network','server','filesystem','user action','browser','other'].includes(e.errorCategory)?e.errorCategory:null,
        ...sizeFacts({bytesReceived:e.receivedBytes,totalBytes:e.totalBytes,canResume:e.canResume})}
    }));
  }
  return {parseTrace,traceLabel,headerEvidence,responseEvidence,sizeFacts,errorCategory,cloudEvents};
})();
if(typeof globalThis!=='undefined')globalThis.THITelemetry=THITelemetry;
if(typeof module!=='undefined'&&module.exports)module.exports=THITelemetry;
