/* v7.16 vendor-neutral observed role and delivery-stage inventory. No requests. */
(function(root,factory){const api=factory();if(typeof module==='object'&&module.exports)module.exports=api;else root.THIHybridWorkflow=api;})(typeof globalThis!=='undefined'?globalThis:this,function(){'use strict';
function analyze(record,productReport){
 const requests=(Array.isArray(record?.requests)?record.requests:[]).slice(0,1500);
 const downloads=(Array.isArray(record?.downloadEvents)?record.downloadEvents:[]).slice(0,1000);
 const stages={document:0,apiRead:0,apiWrite:0,apiAccepted:0,mediaHttp:0,attachmentHttp:0,httpDenied:0,redirect:0,browserDownloaded:0,browserInterrupted:0};
 const groups=new Map();let invalid=0;let differentOrigin=0;
 let pageOrigin='';try{pageOrigin=new URL(record?.origin).origin;}catch{}
 for(const req of requests){
  if(!req||typeof req!=='object')continue;
  const mime=String(req.mime||'').toLowerCase(),method=String(req.method||'').toUpperCase(),status=Number(req.status);
  let origin='';try{origin=new URL(req.url).origin;}catch{invalid++;}
  if(origin&&pageOrigin&&origin!==pageOrigin)differentOrigin++;
  const kind=String(req.type||req.resourceType||'').toLowerCase();
  if(kind==='main_frame'||mime.includes('text/html')&&kind==='document')stages.document++;
  if((mime.includes('json')||kind==='xmlhttprequest'||kind==='fetch')&&method==='GET')stages.apiRead++;
  if((mime.includes('json')||kind==='xmlhttprequest'||kind==='fetch')&&['POST','PATCH','PUT','DELETE'].includes(method))stages.apiWrite++;
  if(status===202)stages.apiAccepted++;
  if([200,206].includes(status)&&/^(?:image|video|audio)\//.test(mime))stages.mediaHttp++;
  if([200,206].includes(status)&&(req.attachmentDisposition===true||/application\/(?:zip|pdf|octet-stream)/.test(mime)))stages.attachmentHttp++;
  if(status===401||status===403)stages.httpDenied++;
  if([301,302,303,307,308].includes(status))stages.redirect++;
  // Classification does not require a known platform or expose a URL.
  if(origin){const band=origin===pageOrigin?'site origin':'external origin';groups.set(band,(groups.get(band)||0)+1);}
 }
 const completed=new Set(),interrupted=new Set();
 for(const e of downloads){if(!e||e.stage!=='download-state'||typeof e.downloadRef!=='string')continue;if(e.downloadStatus==='complete')completed.add(e.downloadRef);else if(e.downloadStatus==='interrupted')interrupted.add(e.downloadRef);}
 stages.browserDownloaded=completed.size;stages.browserInterrupted=interrupted.size;
 const labels={document:'Document responses',apiRead:'API-shaped reads',apiWrite:'API-shaped writes',apiAccepted:'Async job-like HTTP 202 responses',mediaHttp:'Media HTTP deliveries',attachmentHttp:'Attachment/file HTTP responses',httpDenied:'HTTP access-denied outcomes',redirect:'HTTP redirects',browserDownloaded:'Browser download completions',browserInterrupted:'Browser download interruptions'};
 const rows=Object.entries(stages).filter(([,count])=>count).map(([name,count])=>({name:labels[name],count,quality:name==='browserDownloaded'||name==='browserInterrupted'?'Browser lifecycle':'Observed HTTP metadata',interpretation:name==='apiAccepted'?'202 is not proof a background job completed':name==='attachmentHttp'||name==='mediaHttp'?'File response is not proof of a native original':'No server-side architecture or causality asserted'}));
 const pim=productReport||(typeof THIProductAsset!=='undefined'?THIProductAsset.analyze(record):null);
 return {version:'7.17',overview:{requests:requests.length,externalOriginResponses:differentOrigin,invalidURLCount:invalid,distinctContextRoles:groups.size,exactProductMediaMatches:pim?.overview?.exactRelationships||0,assetFamilyProductMediaMatches:pim?.overview?.assetFamilyRelationships||0,dropped:Math.max(0,Number(record?.counters?.requestsDropped)||0)},rows,limits:['HTTP role/stage counts do not establish internal CMS, DAM, PIM, licensing or storage boundaries.','Nearby requests are not causally linked without a shared identifier or exact browser lifecycle evidence.','No request replay or endpoint enumeration was performed.']};
}
return Object.freeze({analyze});});
