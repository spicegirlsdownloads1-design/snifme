/* Trufflehog v5.1: read-only, opt-in observations of authorised download steps.
   No POST values, raw bodies, cookies, authentication headers, full signed URLs,
   signature bytes, download filenames, or response bodies are retained. */
'use strict';
const THIDownload = (() => {
  const fields = {
    assetid:'asset ID',imageid:'image ID',fileid:'file ID',collectionid:'collection ID',
    rendition:'rendition',variant:'variant',downloadtype:'download type',
    format:'format',size:'size',quality:'quality',width:'width',height:'height',
    type:'type',action:'action',id:'ID',files:'file references',
    assets:'asset references',items:'item references',exporttype:'export type',
    jobid:'job ID',callback:'callback field',token:'credential field present',
    signature:'signature field present',nonce:'nonce field present',
    csrftoken:'CSRF field present',publicid:'public asset identifier',
    uploadpreset:'upload preset',resourcetype:'resource type',structuredmetadata:'structured metadata',
    context:'context metadata',tags:'taxonomy tags',originalfilename:'filename field',
    folder:'folder classification',overwrite:'overwrite setting',transformation:'transformation rule',
    eager:'transformation option',file:'file/upload field',filesize:'file size',
    xamzsignature:'AWS signature field present',xamzcredential:'AWS credential scope present',
    xamzalgorithm:'AWS signing algorithm field',xamzdate:'AWS signing date field',
    xamzsecuritytoken:'AWS temporary session-token field',policy:'Upload policy field',
    successactionstatus:'Upload response-code field',acl:'ACL field'
  };
  const headerClasses={
    authorization:'Authorization header present',cookie:'Cookie header present',
    'x-api-key':'API key header present','x-csrf-token':'CSRF header present',
    'x-xsrf-token':'CSRF header present','x-amz-date':'AWS signing date present',
    'x-amz-security-token':'AWS session token header present',
    'x-amz-content-sha256':'AWS content digest present',
    'x-signature':'Signature header present','x-request-signature':'Request signature header present',
    'x-hmac-signature':'HMAC signature header present','x-nonce':'Nonce header present',
    'content-type':'Content-Type header present'
  };
  const cleanMethod=m=>['GET','POST','PUT','PATCH','DELETE','HEAD'].includes(String(m||'').toUpperCase())?String(m).toUpperCase():'OTHER';
  const queryKinds=url=>{
    let u;try{u=new URL(url)}catch{return []}
    const keys=new Set([...u.searchParams.keys()].map(x=>x.toLowerCase()));
    const kinds=[];
    if([...keys].some(x=>/^(?:x-amz-signature|signature|sig|policy|key-pair-id|cloudfront-signature|hmac|hash)$/.test(x)))kinds.push('URL signing fields');
    if([...keys].some(x=>/^(?:x-amz-expires|expires|expiry|exp|se|x-goog-expires)$/.test(x)))kinds.push('URL expiry field');
    if([...keys].some(x=>/^(?:token|access_token|auth|api_key|apikey|jwt|session)$/.test(x)))kinds.push('URL credential field');
    if([...keys].some(x=>/^(?:x-amz-algorithm|x-goog-algorithm)$/.test(x)))kinds.push('Cloud signing algorithm field');
    return kinds;
  };
  function postShape(requestBody){
    if(!requestBody)return {bodyState:'not provided',fieldCategories:[]};
    if(requestBody.formData && typeof requestBody.formData==='object'){
      const categories=[...new Set(Object.keys(requestBody.formData).slice(0,80)
        .map(k=>fields[String(k).toLowerCase().replace(/[^a-z0-9]/g,'')]||'other field'))].slice(0,18);
      return {bodyState:'form field names classified',fieldCategories:categories};
    }
    // Never decode or parse the raw requestBody bytes. They may contain secrets.
    if(requestBody.raw)return {bodyState:'opaque body not inspected',fieldCategories:[]};
    return {bodyState:'body shape unavailable',fieldCategories:[]};
  }
  function headerShape(headers){
    const present=new Set((Array.isArray(headers)?headers:[]).map(h=>String(h?.name||'').toLowerCase()));
    return Object.entries(headerClasses).filter(([name])=>present.has(name)).map(([,value])=>value);
  }
  const hostOf=url=>{try{let u=new URL(url);return /^https?:$/.test(u.protocol)?u.hostname.toLowerCase():'';}catch{return '';}};
  // Only numeric byte-range metadata; never store raw headers or resource paths.
  function rangeEvidence(headers,isRequest){
    const list=Array.isArray(headers)?headers:[];
    const byName=name=>list.find(h=>String(h?.name||'').toLowerCase()===name)?.value;
    if(isRequest)return {rangeRequested:typeof byName('range')==='string'};
    const present=typeof byName('accept-ranges')==='string';
    const allowed=String(byName('accept-ranges')||'').trim().toLowerCase()==='bytes';
    const value=String(byName('content-range')||'');
    const m=/^bytes (\d{1,16})-(\d{1,16})\/(\d{1,16}|\*)$/.exec(value.trim());
    const result={rangeSupportHeaderPresent:present,rangeSupported:allowed,contentRangePresent:!!value};
    if(m){
      const start=Number(m[1]),end=Number(m[2]),total=m[3]==='*'?null:Number(m[3]);
      if(Number.isSafeInteger(start)&&Number.isSafeInteger(end)&&start>=0&&end>=start&&
         (total===null||(Number.isSafeInteger(total)&&total>0&&end<total))){
        result.rangeStart=start;result.rangeEnd=end;result.rangeTotalBytes=total;
      }
    }
    return result;
  }
  function classify(stage,d,scope){
    if(!d||typeof d!=='object'||!Number.isInteger(d.tabId)||d.tabId<0)return null;
    // Reduce unrelated third-party noise. Opt-in is additionally checked by the worker.
    const method=cleanMethod(d.method);
    let pathname='';try{pathname=new URL(d.url).pathname;}catch{return null;}
    const pathClue=/(?:download|export|rendition|attachment|archive|asset|media|original|file|zip|order|license|licence)/i.test(pathname);
    const postLike=['POST','PUT','PATCH'].includes(method);
    const headerAttachment=(d.responseHeaders||[]).some(h=>String(h.name||'').toLowerCase()==='content-disposition' && /^\s*attachment(?:\s*;|\s*$)/i.test(String(h.value||'')));
    const fileContent=(d.responseHeaders||[]).some(h=>String(h.name||'').toLowerCase()==='content-type'&&/^(?:application\/(?:zip|pdf|octet-stream)|image\/(?:jpeg|png|tiff))/i.test(String(h.value||'')));
    const uploadProtocol=typeof THIUploadAPI!=='undefined'?THIUploadAPI.detect(stage,d):null;
    const awsRelevant=typeof THIAwsDam!=='undefined' && THIAwsDam.classify(stage,d)!==null;
    if(!postLike&&!pathClue&&!awsRelevant&&!uploadProtocol&&!headerAttachment&&!(stage==='complete'&&fileContent&&d.type==='main_frame'))return null;
    const requestId=String(d.requestId||'').slice(0,90);
    if(!requestId)return null;
    const result={stage,requestId,at:new Date(Number.isFinite(d.timeStamp)?d.timeStamp:Date.now()).toISOString(),
      method,type:['xmlhttprequest','main_frame','sub_frame','other','image','media'].includes(d.type)?d.type:'other',
      host:hostOf(d.url),signedIndicators:queryKinds(d.url),status:null,bodyState:'',fieldCategories:[],headerIndicators:[],
      redirectHost:'',errorClass:'',fileType:'',attachment:false,traceRef:'',cdnEvidence:[]};
    if(!result.host)return null;
    if(stage==='request')Object.assign(result,postShape(d.requestBody));
    if(stage==='headers'){
      Object.assign(result,rangeEvidence(d.requestHeaders,true));
      result.headerIndicators=headerShape(d.requestHeaders);
      if(typeof THITelemetry!=='undefined')Object.assign(result,THITelemetry.headerEvidence(d.requestHeaders,scope));
    }
    if(stage==='response-headers')Object.assign(result,rangeEvidence(d.responseHeaders,false));
    if(stage==='response-headers'&&typeof THITelemetry!=='undefined'){
      Object.assign(result,THITelemetry.responseEvidence(d.responseHeaders));
      const hdr=THITelemetry.headerEvidence(d.responseHeaders,scope);
      Object.assign(result,{traceRef:hdr.traceRef,traceVersion:hdr.traceVersion,
        traceSampled:hdr.traceSampled,tracestatePresent:hdr.tracestatePresent,
        cdnEvidence:hdr.cdnEvidence,requestIdHeaderPresent:hdr.requestIdHeaderPresent});
    }
    if(stage==='redirect'){
      result.status=Number.isInteger(d.statusCode)?d.statusCode:null;
      result.redirectHost=hostOf(d.redirectUrl);
    }
    if(stage==='complete'||stage==='error'||stage==='response-headers'){
      result.status=Number.isInteger(d.statusCode)?d.statusCode:null;
      const content=(d.responseHeaders||[]).find(h=>String(h.name||'').toLowerCase()==='content-type');
      if(content){const typ=String(content.value||'').split(';')[0].trim().toLowerCase();result.fileType=/^(image|video|audio|application)\/[a-z0-9.+-]{1,50}$/.test(typ)?typ:'';}
      result.attachment=(d.responseHeaders||[]).some(h=>String(h.name||'').toLowerCase()==='content-disposition'&&/^\s*attachment(?:\s*;|\s*$)/i.test(String(h.value||'')));
      if(stage==='error')result.errorClass='request failed'; // Never store raw Chrome error strings.
    }
    if(typeof THIAwsDam!=='undefined')result.awsDam=THIAwsDam.classify(stage,d);
    if(uploadProtocol)result.uploadProtocol=uploadProtocol;
    return result;
  }
  function download(kind,item){
    if(!item||typeof item!=='object')return null;
    const originHost=hostOf(item.referrer||'');
    const deliveredHost=hostOf(item.finalUrl||item.url||'');
    return {stage:kind==='created'?'download-start':'download-state',requestId:'',
      at:new Date().toISOString(),host:deliveredHost,referrerHost:originHost,
      method:'',type:'download',status:null,signedIndicators:[],fieldCategories:[],headerIndicators:[],
      fileType:(/^(?:image\/(?:jpeg|png|webp|gif|avif|tiff|bmp)|application\/(?:zip|pdf|octet-stream))$/i.test(String(item.mime||''))?String(item.mime).toLowerCase():''),attachment:false,downloadStatus:kind==='created'?'started':(['complete','interrupted'].includes(kind)?kind:'progress'),
      association:'Referrer-origin correlation only; browser download event does not provide tab ID',
      ...(typeof THITelemetry!=='undefined'?THITelemetry.sizeFacts(item):{})};
  }
  function summaries(events){
    const map=new Map(),downloadRows=new Map(),rows=[];
    const safeSize=n=>Number.isSafeInteger(n)&&n>=0?n:null;
    const formatSize=e=>{
      const received=safeSize(e.receivedBytes),total=safeSize(e.totalBytes);
      return received===null?'':`${received} / ${total===null?'?':total} bytes`;
    };
    const downloadRow=e=>({
      requestId:'',at:e.at,method:'DOWNLOAD',host:e.host||'',status:'started',
      auth:'Not inspected',body:'Not applicable',fields:'',signature:'',redirect:'',file:'Browser download event',
      trace:'',cdn:'',cache:'',error:'',bytes:formatSize(e),
      evidence:'Referrer-origin association only; HTTP request linkage unverified; completion not observed'
    });
    for(const e of (Array.isArray(events)?events:[])){
      if(!e||!e.stage)continue;
      if(e.requestId){
        if(!map.has(e.requestId))map.set(e.requestId,{requestId:e.requestId,at:e.at,method:e.method,host:e.host,
          status:'unconfirmed',auth:'Not observed',body:'Not observed',fields:'',signature:'',redirect:'',file:'',trace:'',cdn:'',cache:'',bytes:'',error:'',evidence:'Request lifecycle, matched requestId'});
        const r=map.get(e.requestId);
        if(e.stage==='request'){r.body=e.bodyState||'Not observed';r.fields=(e.fieldCategories||[]).join(', ');}
        if(e.stage==='headers'){
          r.auth=e.authentication&&e.authentication!=='not observed'?e.authentication:((e.headerIndicators||[]).join('; ')||'No recognised headers observed');
          if(e.signatureScheme&&e.signatureScheme!=='not observed')r.signature=e.signatureScheme;
        }
        if(e.traceRef)r.trace=e.traceRef;
        if(e.cdnEvidence?.length)r.cdn=[...new Set([...(r.cdn?r.cdn.split('; '):[]),...e.cdnEvidence])].join('; ');
        if(e.stage==='response-headers'){
          r.cache=e.cachePolicy||'';r.bytes=e.contentLengthBytes===null?'':String(e.contentLengthBytes);
        }
        if(e.stage==='redirect')r.redirect=e.redirectHost||'';
        if(e.stage==='complete'||e.stage==='error'){r.status=e.stage==='error'?'Failed':String(e.status??'Unknown');r.file=e.attachment?'Attachment response':(e.fileType||'');}
        r.signature=[...new Set([...(r.signature?r.signature.split('; '):[]),...(e.signedIndicators||[])])].join('; ');
      }else if(e.stage==='download-start'||e.stage==='download-state'){
        // Chrome download IDs are intentionally absent. Pair ONLY the opaque,
        // session-local downloadRef generated by our observer; never infer a
        // match from hostname, timing, filename or a POST request.
        const ref=typeof e.downloadRef==='string'&&/^DL\d{1,25}$/.test(e.downloadRef)?e.downloadRef:null;
        if(!ref){
          const legacy=downloadRow(e);
          legacy.status=['complete','interrupted'].includes(e.downloadStatus)?e.downloadStatus:'unconfirmed';
          legacy.error=e.errorCategory||'';
          legacy.evidence='Referrer-origin correlation only; no trusted local download reference for lifecycle pairing';
          rows.push(legacy);
          continue;
        }
        if(!downloadRows.has(ref))downloadRows.set(ref,{row:downloadRow(e),sawStart:false,sawEnd:false});
        const item=downloadRows.get(ref),r=item.row;
        if(e.stage==='download-start'){
          item.sawStart=true;
          if(e.at && (!r.at || String(e.at)<String(r.at)))r.at=e.at;
          if(e.host)r.host=e.host;
        }
        if(e.stage==='download-state'){
          if(['complete','interrupted'].includes(e.downloadStatus)){
            item.sawEnd=true;
            r.status=e.downloadStatus;
            r.error=e.downloadStatus==='interrupted'?(e.errorCategory||'') : '';
          }
          const bytes=formatSize(e);
          if(bytes)r.bytes=bytes;
        }
      }
    }
    for(const {row,sawStart,sawEnd} of downloadRows.values()){
      if(sawStart&&sawEnd)row.evidence='Paired by local download reference; HTTP request linkage unverified';
      else if(sawEnd)row.evidence='Terminal download state observed; start was not recorded';
      else row.evidence='Download start observed; completion unobserved (in progress or missed)';
      rows.push(row);
    }
    return [...map.values(),...rows].sort((a,b)=>String(b.at).localeCompare(String(a.at)));
  }
  return {classify,download,summaries,postShape,headerShape,queryKinds,hostOf};
})();
if(typeof globalThis!=='undefined')globalThis.THIDownload=THIDownload;
if(typeof module!=='undefined'&&module.exports)module.exports=THIDownload;
