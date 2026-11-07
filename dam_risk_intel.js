/* Trufflehog Intelligence v4.2 — passive, platform-aware DAM risk evidence.
 * Processes only facts already recorded by the extension; never requests
 * resources, authenticates, validates keys or attempts permissions bypasses.
 * Output contains hostnames, aggregate counts, and category labels only.
 */
(function(root){
'use strict';
const MAX_REQUESTS=3000;
const HOST_LIMIT=100;
const REVIEW_CHECKS=Object.freeze({
 capture:['Review whether CMS-to-DAM service credentials are scoped and rotated.','Confirm legacy URL-based API authentication is disabled or restricted where supported.','Check asset rendition and permission separation.'],
 resourcespace:['Check supported application/PHP versions and patch status with the operator.','Review API key custody, group permissions and public collection links.'],
 bynder:['Review public-original settings, cached public URLs and withdrawal/invalidation policy.','Confirm CDN and DAM sharing permissions are aligned.'],
 photoshelter:['Review password protection, direct-link revocation and permitted download sizes.'],
 canto:['Review selective/structured shares, restricted assets, original-download permissions and link expiry.'],
 fotoware:['Review API application permissions, renditions, archive roles and sharing settings.']
});
function host(raw){
 try{const u=new URL(String(raw||''));return /^https?:$/.test(u.protocol)?u.hostname.toLowerCase().slice(0,170):'';}catch{return '';}
}
function apiLike(req){
 if(['xmlhttprequest','fetch'].includes(String(req?.type||'').toLowerCase()))return true;
 try{return /(?:\/api\/|\/graphql(?:\/|$)|\/rest\/|\/v[1-9]\/)/i.test(new URL(String(req?.url||'')).pathname);}catch{return false;}
}
function role(req){
 if(req?.type==='image'||String(req?.mime||'').startsWith('image/'))return 'Image delivery';
 if(apiLike(req))return 'Observed API / search';
 if(req?.type==='script')return 'Loaded script';
 return 'Other web resource';
}
function safeClasses(value){
 const allow=new Set(['api-credential-query','legacy-access-token-query','auth-header-style-query','ambiguous-token-query','signed-media-query']);
 return [...new Set((Array.isArray(value)?value:[]).filter(x=>typeof x==='string'&&allow.has(x)))];
}
function analyze(record,platformAnalysis){
 const empty={findings:[],services:[],connections:[],reviews:[],stats:{requests:0,serviceHosts:0,credentialQueryRequests:0,signedMediaRequests:0,confidence:'Unknown'}};
 if(!record||typeof record!=='object')return empty;
 const req=(Array.isArray(record.requests)?record.requests:[]).slice(-MAX_REQUESTS);
 const site=host(record.origin)||'Current website';
 const byHost=new Map(),findings=[];
 let legacy=0,apiKey=0,ambiguous=0,signed=0,original=0,longCache=0,hostLimit=0;
 function addFinding(severity,category,title,count,meaning,ownerAction,evidence='Observed request metadata'){
  if(!count||findings.length>=24)return;
  findings.push({severity,category,title,observations:count,meaning,ownerAction,evidence});
 }
 for(const r of req){
  if(!r||typeof r!=='object')continue;
  const h=host(r.url)||host(r.host?.startsWith('http')?r.host:'https://'+String(r.host||''));
  if(!h)continue;
  const k=role(r),id=k+'|'+h;
  if(!byHost.has(id)){
   if(byHost.size>=HOST_LIMIT){hostLimit++;continue;}
   byHost.set(id,{host:h,role:k,requests:0,successful:0,denied:0,signedMedia:0,legacyAuth:0,classification:'Observed resource; backend ownership not established'});
  }
  const item=byHost.get(id);item.requests++;
  if(Number(r.status)>=200&&Number(r.status)<400)item.successful++;
  if(r.status===401||r.status===403)item.denied++;
  const cl=safeClasses(r.authQueryClasses);
  // Query-key classes deliberately omit parameter names and all values.
  if(apiLike(r)&&cl.includes('legacy-access-token-query')){legacy++;item.legacyAuth++;}
  if(apiLike(r)&&cl.includes('api-credential-query')){apiKey++;item.legacyAuth++;}
  if(apiLike(r)&&(cl.includes('auth-header-style-query')||cl.includes('ambiguous-token-query')))ambiguous++;
  if(r.signedQuery===true&&(k==='Image delivery'||cl.includes('signed-media-query'))){signed++;item.signedMedia++;}
  const image=k==='Image delivery',success=Number(r.status)>=200&&Number(r.status)<300;
  let originalLabel=false;
  if(image&&success){
   try{originalLabel=/(?:^|\/)(?:original|master|full[-_]?res)(?:\/|[._-]|$)/i.test(new URL(r.url).pathname);}catch{}
  }
  if(originalLabel){
   original++;
   if(r.cacheScope==='public'&&Number(r.cacheMaxAge)>=86400)longCache++;
  }
 }
 addFinding('Owner review','Possible URL-based API authentication','API requests with legacy access-token parameter class',legacy,
  'A query-key pattern was seen in an observed API request. It does not establish a valid token, missing authentication, or a vulnerable platform.',
  'Check whether query-string credentials are required, how request logs handle them, and whether header-based authentication is available.');
 addFinding('Owner review','Possible URL-based API authentication','API requests with key parameter class',apiKey,
  'An API credential-like query-key was observed; browser-visible values are not retained or tested.',
  'Review whether the parameter represents a public identifier or privileged credential and apply least-privilege controls.');
 addFinding('Informational','Authentication architecture','Other token-like API query-key patterns',ambiguous,
  'Generic token parameter names can describe harmless workflow values or access controls.',
  'Confirm the intended authentication mechanism with the service owner.');
 addFinding('Informational','CDN delivery','Signed/expiring media query structure observed',signed,
  'A parameter shape suggests signed delivery, not a bypass or a secret exposure.',
  'Review intended link expiry, origin protection and revocation behaviour.');
 addFinding('Owner review','Image delivery','Successful image responses on original/master-labelled paths',original,
  'The path label does not prove the file is an original, unlicensed, or unintentionally public.',
  'Review the asset permission and actual rendition against publication policy.');
 addFinding('Owner review','Caching & withdrawal','Original-labelled image with long public cache policy',longCache,
  'An observed label and caching policy together warrant a revocation-policy review; they do not prove a security failure.',
  'Review CDN invalidation, link expiry, takedown and embargo procedures.');
 const profiles=(Array.isArray(platformAnalysis?.profiles)?platformAnalysis.profiles:[]);
 const reviews=profiles.filter(p=>REVIEW_CHECKS[p.id]).slice(0,12).map(p=>({
  platform:String(p.name||p.id).slice(0,75),confidence:p.confidence||'Unverified',
  limitation:'Technology clue, not verified vendor deployment',checks:REVIEW_CHECKS[p.id].join(' · ')
 }));
 const services=[...byHost.values()].sort((a,b)=>b.requests-a.requests).slice(0,HOST_LIMIT);
 const connections=services.map(s=>({
  from:site,to:s.host,role:s.role,observedRequests:s.requests,denied:s.denied,
  evidence:'Recorded HTTP activity in this browser tab',
  limitation:'An observed host does not prove a direct CMS-to-DAM backend link, shared database, or public permissions.'
 }));
 return {findings,services,connections,reviews,stats:{requests:req.length,serviceHosts:new Set(services.map(s=>s.host)).size,
  credentialQueryRequests:legacy+apiKey,signedMediaRequests:signed,hostLimitExceeded:hostLimit,
  confidence:req.length?'Observed resources only — not a full security assessment':'Not observed — open DevTools before loading the page'},
  caveat:'Only browser-observed and previously recorded evidence. No endpoint testing, credential access, hidden file discovery, or vulnerability validation.'};
}
const API={analyze,REVIEW_CHECKS};
root.THIDAMRisk=API;
if(typeof module==='object'&&module.exports)module.exports=API;
})(typeof globalThis!=='undefined'?globalThis:this);
