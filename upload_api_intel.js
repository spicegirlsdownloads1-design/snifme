/* v5.6: read-only DAM upload protocol and schema-shape comparison.
 * Inputs are events Chrome already observed after explicit opt-in, and optionally
 * saved DevTools JSON field-name/type shapes. Never store request query VALUES,
 * signing material, upload IDs, bucket/object keys, body bytes or backend claims.
 * Do not initiate network requests here.
 */
'use strict';
const THIUploadAPI = (() => {
  const PROVIDERS=['S3-compatible','Azure Blob-compatible','Google Cloud Storage-compatible','tus-compatible','Multipart-form-compatible'];
  const PHASES=['initiate','part transfer','block transfer','resumable transfer','offset check','commit request','single-form upload','protocol handshake','upload-related response'];
  const SIGNS=['multipart-initiation key','upload-session key','part-index key','Azure block operation','Azure block-list operation','GCS resumable initiation','GCS upload-session key','tus protocol header','tus offset header','tus length header','tus checksum header','tus metadata header','form upload field','multipart content type','S3 signing field','storage service hostname'];
  const METHODS=['GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS'];
  const hostOf=url=>{try{const u=new URL(url);return /^https?:$/.test(u.protocol)?u.hostname.toLowerCase():'';}catch{return ''}};
  const safeHost=h=>typeof h==='string' && h.length<=253 && /^(?=.{1,253}$)[a-z0-9.-]+$/.test(h) && !h.includes('..') && !/(?:token|secret|password|credential|signature|bearer|apikey|privatekey)/i.test(h)?h:'';
  const safeAt=x=>typeof x==='string'&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(x)?x.slice(0,24):'';
  const safeStatus=n=>Number.isInteger(n)&&n>=100&&n<=599?n:null;
  const cleanMethod=m=>METHODS.includes(String(m||'').toUpperCase())?String(m).toUpperCase():'OTHER';
  function detect(stage,d){
    if(!d?.url||!['request','headers','response-headers','complete','error','redirect'].includes(stage))return null;
    let u;try{u=new URL(d.url);if(!/^https?:$/.test(u.protocol))return null;}catch{return null}
    const hostname=u.hostname.toLowerCase(),method=cleanMethod(d.method),keys=new Set([...u.searchParams.keys()].map(x=>x.toLowerCase()));
    const headerNames=new Set([...Array.isArray(d.requestHeaders)?d.requestHeaders:[],...Array.isArray(d.responseHeaders)?d.responseHeaders:[]].map(h=>String(h?.name||'').toLowerCase()));
    const has=h=>headerNames.has(h);
    const marks=[],put=m=>{if(SIGNS.includes(m)&&!marks.includes(m))marks.push(m)};
    const s3=/(?:^|\.)s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com(?:\.cn)?$/.test(hostname);
    const azure=/(?:^|\.)blob\.core\.windows\.net$/.test(hostname);
    const gcs=hostname==='storage.googleapis.com'||/(?:^|\.)storage\.googleapis\.com$/.test(hostname);
    let provider='',phase='';
    if(has('tus-resumable')||has('tus-version')||has('upload-offset')||has('upload-length')||has('upload-metadata')){
      provider='tus-compatible';
      if(has('tus-resumable')||has('tus-version'))put('tus protocol header');
      if(has('upload-offset'))put('tus offset header');
      if(has('upload-length'))put('tus length header');
      if(has('upload-checksum'))put('tus checksum header');
      if(has('upload-metadata'))put('tus metadata header');
      phase=method==='HEAD'?'offset check':method==='PATCH'?'resumable transfer':method==='POST'?'initiate':'protocol handshake';
    }else if((s3||keys.has('uploadid')||keys.has('partnumber')||keys.has('uploads')) &&
      (keys.has('uploads')||keys.has('uploadid')||keys.has('partnumber'))){
      provider='S3-compatible';
      if(keys.has('uploads'))put('multipart-initiation key');
      if(keys.has('uploadid'))put('upload-session key');
      if(keys.has('partnumber'))put('part-index key');
      if(s3)put('storage service hostname');
      phase=method==='POST'&&keys.has('uploads')?'initiate':method==='PUT'&&keys.has('partnumber')?'part transfer':
        method==='POST'&&keys.has('uploadid')?'commit request':'upload-related response';
    }else if((azure||keys.has('comp'))&&['block','blocklist'].includes(String(u.searchParams.get('comp')||'').toLowerCase())){
      provider='Azure Blob-compatible';
      const component=String(u.searchParams.get('comp')).toLowerCase();
      put(component==='block'?'Azure block operation':'Azure block-list operation');
      if(azure)put('storage service hostname');
      phase=component==='blocklist'?'commit request':'block transfer';
    }else if((gcs||keys.has('uploadtype')||keys.has('upload_id'))&&
      (keys.has('uploadtype')||keys.has('upload_id')||has('x-goog-resumable'))){
      provider='Google Cloud Storage-compatible';
      if(keys.has('upload_id'))put('GCS upload-session key');
      const uploadType=String(u.searchParams.get('uploadType')||'').toLowerCase();
      if(uploadType==='resumable'||has('x-goog-resumable'))put('GCS resumable initiation');
      if(gcs)put('storage service hostname');
      phase=method==='POST'?'initiate':method==='PUT'?'resumable transfer':'upload-related response';
    }else{
      const form=d.requestBody?.formData;
      const names=form&&typeof form==='object'&&!Array.isArray(form)?Object.keys(form).map(k=>String(k).toLowerCase()):[];
      const uploadForm=names.some(x=>['file','files','upload','uploads','image','images'].includes(x));
      const contentType=(d.requestHeaders||[]).find(h=>String(h?.name||'').toLowerCase()==='content-type')?.value||'';
      // Only use Content-Type prefix locally; never store multipart boundaries.
      if(uploadForm||(/^multipart\/form-data\s*(?:;|$)/i.test(String(contentType))&&/upload|ingest|media|asset/i.test(u.pathname))){
        provider='Multipart-form-compatible';phase='single-form upload';
        if(uploadForm)put('form upload field');
        if(/^multipart\/form-data/i.test(String(contentType)))put('multipart content type');
      }
    }
    if(!provider)return null;
    return {provider,phase,markers:marks.slice(0,12),method,
      status:safeStatus(d.statusCode),
      evidence:(s3||azure||gcs)?'Recognised storage hostname and protocol clues':'Observed structural protocol clues; provider unverified',
      limitation:'Request identity, upload parts, policy contents and payload values are not retained'};
  }
  function rows(record){
    const grouped=new Map();
    for(const e of (Array.isArray(record?.downloadEvents)?record.downloadEvents:[]).slice(-2000)){
      const p=e?.uploadProtocol;
      if(!p||!PROVIDERS.includes(p.provider)||!PHASES.includes(p.phase)||!e.requestId)continue;
      const key=String(e.requestId); // in-memory grouping only, not exported
      if(!grouped.has(key))grouped.set(key,{at:safeAt(e.at),host:safeHost(e.host),provider:p.provider,method:cleanMethod(p.method),
        phase:p.phase,status:null,stages:[],markers:[],evidence:'Observed protocol structure; authorisation and completion not verified'});
      const r=grouped.get(key);
      if(e.stage==='request'||e.stage==='headers')r.phase=p.phase;
      r.stages.push(['request','headers','response-headers','complete','error','redirect'].includes(e.stage)?e.stage:'unknown');
      for(const m of Array.isArray(p.markers)?p.markers:[])if(SIGNS.includes(m)&&!r.markers.includes(m))r.markers.push(m);
      const status=safeStatus(p.status);if(status!==null)r.status=status;
    }
    return [...grouped.values()].map((r,i)=>({...r,reference:`UP${i+1}`,stages:[...new Set(r.stages)].join(', '),markers:r.markers.join('; '),
      outcome:r.stages.includes('error')?'Browser request failed':r.stages.includes('complete')?'HTTP request completed (asset status unknown)':'Request completion not observed'}))
      .sort((a,b)=>String(b.at).localeCompare(String(a.at))).slice(0,500);
  }
  function analyse(record){
    const items=rows(record);
    const counts={observations:items.length,initiations:items.filter(x=>x.phase==='initiate').length,
      transferRequests:items.filter(x=>['part transfer','block transfer','resumable transfer','single-form upload'].includes(x.phase)).length,
      commitRequests:items.filter(x=>x.phase==='commit request').length,
      incompleteLifecycles:items.filter(x=>!x.stages.includes('complete')&&!x.stages.includes('error')).length};
    return {format:'trufflehog-upload-protocols',version:1,rows:items,counts,
      limitations:['An HTTP 200/201/204 response does not certify an upload is durable or processed by a DAM.',
        'Upload IDs, object keys, part indices, signature/policy values and content are not saved, so separate upload requests cannot be proven to belong to one asset.',
        'Third-party provider labels are compatibility classifications unless the storage service hostname is confirmed.',
        'Observation is opt-in, per tab/site and subject to Chrome host access and request visibility.']};
  }
  const riskyName=/(?:token|secret|pass|auth|session|cookie|credential|email|phone|address|user|personal|payment|card|name|jwt|key|signature|policy)/i;
  function canonical(r){
    let url;try{url=new URL(r.url);if(!/^https?:$/.test(url.protocol))return null;}catch{return null}
    const host=safeHost(url.hostname.toLowerCase());if(!host)return null;
    const method=cleanMethod(r.method);if(method==='OTHER')return null;
    // Normalise only common variable path segments in memory; never export paths.
    const rawPath=url.pathname;
    if(rawPath.length>500)return null;
    const route=rawPath.split('/').map(x=>/^(?:\d{1,15}|[a-f0-9]{8}-[a-f0-9-]{27,}|[a-f0-9]{24,64})$/i.test(x)?':id':x).join('/');
    const key=host+'|'+method+'|'+route;
    const fieldMap=new Map();
    for(const f of (Array.isArray(r.fields)?r.fields:[]).slice(0,80)){
      const path=String(f?.path||'');
      if(path.length>200||!path||path.split('.').some(x=>riskyName.test(x))||!/^[A-Za-z_$][\w$-]*(?:\.(?:[A-Za-z_$][\w$-]*|\[\])){0,5}$/.test(path))continue;
      if(['string','number','boolean','null','object','array'].includes(f.type))fieldMap.set(path,f.type);
    }
    if(!fieldMap.size)return null;
    const category=/\/search(?:\/|$)/i.test(rawPath)?'Search':/\/assets?(?:\/|$)/i.test(rawPath)?'Assets':/\/gallery|\/collection/i.test(rawPath)?'Gallery or collection':/\/api\//i.test(rawPath)?'API':'Other JSON';
    return {key,host,method,category,fields:fieldMap};
  }
  function groupedSchemas(record){
    const groups=new Map();
    for(const r of (Array.isArray(record?.responses)?record.responses:[]).slice(0,300)){
      const c=canonical(r);if(!c)continue;
      if(!groups.has(c.key))groups.set(c.key,c);
      else {const existing=groups.get(c.key);for(const [k,v] of c.fields)existing.fields.set(k,v);}
    }
    return groups;
  }
  function compare(baseline,current){
    if(baseline?.origin && current?.origin && baseline.origin!==current.origin)return {error:'Choose captures of the same exact origin.',rows:[],totals:{}};
    const a=groupedSchemas(baseline),b=groupedSchemas(current);
    const keys=[...new Set([...a.keys(),...b.keys()])].sort().slice(0,200);
    const rows=keys.map((key,i)=>{
      const before=a.get(key),after=b.get(key),ref=after||before;
      let added=0,removed=0,changedType=0;
      if(before&&after){for(const [p,t] of after.fields)if(!before.fields.has(p))added++;else if(before.fields.get(p)!==t)changedType++;
        for(const p of before.fields.keys())if(!after.fields.has(p))removed++;}
      const status=!before?'Newly observed endpoint shape':!after?'Not observed in current capture':added||removed||changedType?'Observed field/type differences':'Same observed field/type shape';
      return {endpoint:`API${i+1}`,host:ref.host,method:ref.method,category:ref.category,
        baselineFields:before?.fields.size??0,currentFields:after?.fields.size??0,added,removed,typeChanges:changedType,status,
        qualification:!before||!after?'Different browsing or missed DevTools responses may explain absence.':
          added||removed||changedType?'Observed JSON structure differed; API contract change not proven.':'Matching recorded shapes do not prove server API stability.'};
    });
    return {format:'trufflehog-api-schema-diff',version:1,rows,
      totals:{baselineEndpoints:a.size,currentEndpoints:b.size,changedShapes:rows.filter(r=>r.status==='Observed field/type differences').length,
        newlyObserved:rows.filter(r=>r.status==='Newly observed endpoint shape').length,
        notObserved:rows.filter(r=>r.status==='Not observed in current capture').length},
      limitations:['Only opt-in DevTools-observed JSON field names and primitive types are compared; response values are never analysed.',
        'Comparisons use in-memory normalised endpoints; exported reports contain opaque local labels instead of URL paths or query values.',
        'Endpoint absence may reflect browsing and DevTools coverage gaps, not a server deployment change.']};
  }
  return {detect,rows,analyse,compare};
})();
if(typeof globalThis!=='undefined')globalThis.THIUploadAPI=THIUploadAPI;
if(typeof module!=='undefined'&&module.exports)module.exports=THIUploadAPI;
