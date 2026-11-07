/* Trufflehog Intelligence v4.9 — passive DAM permission and CDN-delivery evidence.
 * Analysis only; no probes, requests, URL guessing, token validation or byte access.
 * No URL paths/query values leave this function: the output contains hostnames,
 * classifications, counts, and owner-side verification advice only.
 */
(function(root){'use strict';
const MAX_REQUESTS=4000, MAX_ROWS=160;
const TRANSLATIONS=Object.freeze({
 preview:'Preview-labelled image', original:'Original/master-labelled image', derivative:'Transformed/derivative image', unspecified:'Unclassified image delivery', attachment:'Download attachment delivery'
});
const FIELD_PATTERNS=Object.freeze([
 ['Original-file reference', /(?:^|\.)(?:original(?:url|uri|file|image)?|master(?:url|uri|file)?|originalasset)(?:$|\.)/i],
 ['Download reference', /(?:^|\.)(?:download(?:url|uri|link|file)?|downloadlocation)(?:$|\.)/i],
 ['Preview / thumbnail reference', /(?:^|\.)(?:preview(?:url|uri|file)?|thumbnail(?:url|uri|file)?|thumb(?:url|uri)?)(?:$|\.)/i],
 ['Rights / licence metadata', /(?:^|\.)(?:license|licence|rights|usageRights|embargo|copyright)(?:$|\.)/i],
 ['Asset identifier', /(?:^|\.)(?:assetId|mediaId|photoId|imageId)(?:$|\.)/i]
]);
function host(raw){try{const u=new URL(String(raw||''));return /^https?:$/.test(u.protocol)?u.hostname.toLowerCase().slice(0,160):'';}catch{return '';}}
function imageLike(r){return String(r?.type||'').toLowerCase()==='image'||/^image\//i.test(String(r?.mime||''))||r?.attachmentDisposition===true;}
function pathClue(raw){
 let p='';try{p=decodeURIComponent(new URL(raw).pathname).slice(0,800);}catch{return 'unspecified';}
 // Treat common path labels as hints only; different DAMs use different naming.
 if(/(?:^|[\/_-])(?:original|master|full[-_]?res)(?:[\/_\-.]|$)/i.test(p))return 'original';
 if(/(?:^|[\/_-])(?:thumbnail|thumb|preview|low[-_]?res)(?:[\/_\-.]|$)/i.test(p))return 'preview';
 if(/(?:^|[\/_-])(?:resize|rendition|derivative|transform|crop|w\d{2,5}|h\d{2,5})(?:[\/_\-.]|$)/i.test(p))return 'derivative';
 return 'unspecified';
}
function cache(r){
 if(r?.cacheNoStore===true)return 'No-store observed';
 const scope=['public','private'].includes(r?.cacheScope)?r.cacheScope:'unspecified';
 const seconds=Number.isFinite(Number(r?.cacheMaxAge))?Math.max(0,Math.min(31536000,Number(r.cacheMaxAge))):0;
 if(!seconds)return scope==='unspecified'?'Cache policy not recorded':scope+'; TTL not established';
 const band=seconds>=86400?'24h+':seconds>=3600?'1–24h':'Under 1h';
 return scope+'; '+band;
}
function statusOf(r){let n=Number(r?.status);if(!Number.isInteger(n)||n<=0)return 'No verified HTTP result';
 if(n>=200&&n<300)return 'Delivered in current browser session';
 if(n===401||n===403)return 'Restricted response (401/403)';
 if(n>=300&&n<400)return 'Redirect observed';
 if(n>=400&&n<500)return 'Other client error';
 if(n>=500)return 'Server error';return 'Other response';}
function policyNote(row){
 if(row.status==='Restricted response (401/403)')return 'This request was denied; do not infer broader access or probe other representations.';
 if(row.signed==='Signed delivery clue')return 'A signed/expiring query structure was observed; expiry and origin protection are not verified.';
 if(row.representation==='Original/master-labelled image')return 'Original/master is a URL label only; the delivered bytes may be a preview or a licensed rendition.';
 if(row.representation==='Download attachment delivery')return 'The server indicated a download; file quality, identity and licence were not verified.';
 return 'Observed delivery only. Anonymous accessibility and original-file availability remain unknown.';
}
function analyze(record){
 const requests=Array.isArray(record?.requests)?record.requests.slice(-MAX_REQUESTS):[];
 const grouped=new Map();const fields=new Map();let received=0,restricted=0,signed=0,attachments=0,publicLongCache=0,sourceDropped=0,mediaRequests=0;
 for(const r of requests){
  if(!r||typeof r!=='object'||!imageLike(r))continue;
  const h=host(r.url);if(!h)continue;
  mediaRequests++;
  const result=statusOf(r),clue=pathClue(r.url),attachment=r.attachmentDisposition===true;
  const representation=attachment?TRANSLATIONS.attachment:TRANSLATIONS[clue];
  const signature=r.signedQuery===true?'Signed delivery clue':'Signing not established';
  const cachePolicy=cache(r);
  const key=JSON.stringify([h,representation,result,signature,cachePolicy]);
  if(!grouped.has(key)){
   if(grouped.size>=MAX_ROWS){sourceDropped++;continue;}
   grouped.set(key,{host:h,representation,status:result,signed:signature,cachePolicy,attachment:attachment?'Attachment header observed':'Not observed',observations:0,
    verifiedFileDimensions:0,confidence:'HTTP response observation + heuristic labels'});
  }
  const row=grouped.get(key);row.observations++;
  if(result==='Delivered in current browser session')received++;
  if(result==='Restricted response (401/403)')restricted++;
  if(r.signedQuery===true)signed++;
  if(attachment)attachments++;
  if(result==='Delivered in current browser session'&&r.cacheScope==='public'&&Number(r.cacheMaxAge)>=86400)publicLongCache++;
 }
 const rows=[...grouped.values()].map(r=>({...r,ownerReview:policyNote(r)})).sort((a,b)=>b.observations-a.observations);
 for(const item of (Array.isArray(record?.responses)?record.responses:[]).slice(-250)){
  for(const f of (Array.isArray(item.fields)?item.fields:[]).slice(0,120)){
   const path=String(f?.path||'').slice(0,250);
   const found=FIELD_PATTERNS.find(([,rx])=>rx.test(path));if(found)fields.set(found[0],(fields.get(found[0])||0)+1);
  }
 }
 const metadata=[...fields].map(([category,sightings])=>({category,sightings,evidence:'JSON field name only; no value or file accessed',assessment:'A field name is not evidence that an asset or download is accessible.'}));
 const notes=[];
 if(publicLongCache)notes.push({priority:'Owner review',kind:'Cache / withdrawal',count:publicLongCache,
  evidence:'Public cache-control at least 24h on an observed successful media response',action:'Confirm link withdrawal, CDN invalidation, and intended cache lifetime with the archive owner.'});
 if(attachments)notes.push({priority:'Information',kind:'Download delivery',count:attachments,
  evidence:'Content-Disposition attachment observed',action:'Confirm file permissions, rendition policies and logging with the archive owner.'});
 if(signed)notes.push({priority:'Information',kind:'Signed media',count:signed,
  evidence:'Signed URL parameter class observed; values discarded',action:'Confirm token expiry and storage-origin protection in authorised server-side review.'});
 if(restricted)notes.push({priority:'Information',kind:'Denied asset request',count:restricted,
  evidence:'Recorded 401/403 HTTP response',action:'Denied responses are not authorisation bypasses. Do not attempt alternative URLs.'});
 return {rows,metadata,notes,summary:{observedRequests:requests.length,mediaRequests,received,restricted,signed,attachments,publicLongCache,unclassified:rows.filter(r=>r.representation===TRANSLATIONS.unspecified).reduce((n,r)=>n+r.observations,0),truncated:sourceDropped>0||record?.counters?.requestsDropped>0,omittedRows:sourceDropped},
  caveat:'A 2xx image response shows delivery in the current browser session, not anonymous access, licence rights, the original master, a bypass or policy compliance. Only already-recorded evidence is used; no requests are made.'};
}
const API={analyze,host,pathClue,statusOf,cache};root.THIDeliveryPolicy=API;
if(typeof module==='object'&&module.exports)module.exports=API;
})(typeof globalThis!=='undefined'?globalThis:this);
