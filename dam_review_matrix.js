/* Trufflehog Intelligence v6.2 — passive DAM security review matrix.
 * Analyse existing request metadata only; zero network activity, no private
 * media access, no token/URL/path values in output. Never infer vulnerabilities.
 */
(function(root){'use strict';
const PROFILES=Object.freeze({
 capture:{name:'Capture DAM',domains:['captureweb.net'],checks:['Review CMS-to-DAM service credential scopes with the owner.','Confirm legacy URL authentication settings and asset permissions with the owner.']},
 resourcespace:{name:'ResourceSpace',domains:['resourcespace.com'],checks:['Review signed API key custody, account-group permissions and supported patches.']},
 photoshelter:{name:'PhotoShelter',domains:['photoshelter.com','photoshelter.net'],checks:['Confirm public gallery visibility is separate from original-download rights.']},
 bynder:{name:'Bynder',domains:['bynder.com','bynder.io','getbynder.com'],checks:['Review media-download roles, public-link expiry and cache invalidation.']},
 cloudinary:{name:'Cloudinary',domains:['cloudinary.com'],checks:['Verify original and derivative delivery-type policies and transformation restrictions.']},
 canto:{name:'Canto',domains:['canto.com','canto.global'],checks:['Confirm OAuth client-secret custody, public portals and link expiry.']},
 fotoware:{name:'FotoWare / FotoWeb',domains:['fotoware.com'],checks:['Check API scopes, archive roles and sharing restrictions.']}
});
const LIMIT=3000;
const NOTE='No evidence of a condition in this capture is not proof of its absence. These are owner-review prompts, not security findings.';
const safeCount=x=>Number.isSafeInteger(x)&&x>=0?Math.min(x,1000000):0;
function host(url){try{const u=new URL(String(url||''));return (u.protocol==='https:'||u.protocol==='http:')?u.hostname.toLowerCase():'';}catch{return '';}}
function belongs(h,d){return h===d||h.endsWith('.'+d);}
function isMedia(r){return r?.type==='image'||/^image\//i.test(String(r?.mime||''))||r?.attachmentDisposition===true;}
function isApi(r){return ['xmlhttprequest','fetch'].includes(String(r?.type||'').toLowerCase());}
function summary(requests){
 const s={requests:0,apiCredentialQueries:0,signedMedia:0,restrictedMedia:0,publicLongCache:0,attachments:0};
 for(const r of requests){if(!r||typeof r!=='object')continue;s.requests++;
  const media=isMedia(r);const status=Number(r.status||0);
  if(isApi(r)&&Array.isArray(r.authQueryClasses)&&r.authQueryClasses.some(x=>x==='api-credential-query'||x==='legacy-access-token-query'))s.apiCredentialQueries++;
  if(media&&r.signedQuery===true)s.signedMedia++;
  if(media&&(status===401||status===403))s.restrictedMedia++;
  if(media&&status>=200&&status<300&&r.cacheScope==='public'&&Number(r.cacheMaxAge)>=86400)s.publicLongCache++;
  if(r.attachmentDisposition===true&&status>=200&&status<300)s.attachments++;
 }
 return s;
}
const CHECKS=Object.freeze([
 {field:'apiCredentialQueries',category:'API authentication',observation:'URL credential-like parameter class in observed API request',followup:'Confirm whether the parameter is a public identifier or a privileged secret, and review log exposure and rotation.'},
 {field:'signedMedia',category:'Signed delivery',observation:'Media delivery with signed-query indicator',followup:'Confirm intended link expiry and that storage-origin permissions are independently enforced.'},
 {field:'restrictedMedia',category:'Media access',observation:'HTTP 401/403 on an observed media request',followup:'Review intended role and rendition restrictions; do not retry other IDs or URLs.'},
 {field:'publicLongCache',category:'CDN caching',observation:'Successful media response with public cache lifetime of at least 24 hours',followup:'Confirm embargo and withdrawal procedures, link expiry and cache invalidation with the system owner.'},
 {field:'attachments',category:'Download attachment',observation:'Successful response labelled as downloadable attachment',followup:'Verify download entitlements, licensing and permitted rendition quality with the system owner.'}
]);
function row(scope,kind,field,check,count,limit,qualifier){return {
 scope,scopeKind:kind,category:check.category,observation:check.observation,
 assessment:count>0?(field==='apiCredentialQueries'||field==='publicLongCache'?'Owner review':'Observed; owner verification needed'):'Not observed in sample',
 count,qualification:qualifier,ownerAction:check.followup,
 evidence:count>0?'Browser-recorded HTTP metadata':'No matching HTTP metadata recorded',
 limit
};}
function evaluate(record,specialistAnalysis){
 const requests=Array.isArray(record?.requests)?record.requests.slice(-LIMIT):[];
 const all=summary(requests);
 const dropped=Object.entries(record?.counters||{}).filter(([k])=>/Dropped$/i.test(k)).reduce((a,[,v])=>a+safeCount(v),0);
 const specialists=specialistAnalysis&&Array.isArray(specialistAnalysis.profiles)?specialistAnalysis:root.THIDAMSpecialists?.analyze?.(record);
 const detected=(Array.isArray(specialists?.profiles)?specialists.profiles:[]).filter(p=>Object.prototype.hasOwnProperty.call(PROFILES,String(p?.id)));
 const resultRows=CHECKS.map(c=>row('Observed site session','site-wide',c.field,c,all[c.field],'Site-wide association only; not attributed to a particular DAM.',NOTE));
 const platformGroups=[];
 for(const p of detected.slice(0,12)){
  const id=String(p.id),config=PROFILES[id];
  const matched=requests.filter(r=>config.domains.some(d=>belongs(host(r?.url),d)));
  const scoped=summary(matched);
  const confidence=['Strong indication','Moderate indication','Weak clue'].includes(p.confidence)?p.confidence:'Weak clue';
  const status=matched.length?'Vendor-associated requests observed':'Product clue only; vendor traffic not observed';
  platformGroups.push({platform:config.name,confidence,relationship:status,observedRequests:matched.length,
   ownerChecklist:config.checks.join(' '),qualification:'Vendor-host presence does not establish that this website uses the vendor as its main repository.'});
  if(!matched.length)continue; // do not assign site-wide findings to code-only clues
  const limitation='Only traffic to recognised vendor-associated hosts; custom domains and self-hosted services may not match.';
  for(const c of CHECKS)if(scoped[c.field]>0)resultRows.push(row(config.name,'vendor-associated',c.field,c,scoped[c.field],limitation,NOTE));
 }
 if(dropped){resultRows.push({scope:'Observed site session',scopeKind:'coverage',category:'Evidence retention',observation:'Local dropped-record counters indicate possible coverage loss',assessment:'Owner review',count:dropped,evidence:'Local bounded retention counters',ownerAction:'Consult Capture diagnostics and check all saved Evidence Vault segments.',qualification:'Observed count is not a count of security incidents.',limit:'Some prior requests may be absent from the sample.'});}
 return {format:'trufflehog-dam-security-review',version:1,
  overview:{observedRequests:all.requests,platformCandidates:platformGroups.length,reviewItems:resultRows.filter(x=>x.assessment==='Owner review').length,retentionDrops:dropped,requestSampleLimited:Array.isArray(record?.requests)&&record.requests.length>LIMIT},
  platforms:platformGroups,rows:resultRows,
  caveats:['Browser-observed metadata only; no active endpoint testing, signature validation or protected downloads.',
   'A recorded 2xx response does not prove anonymous/public access, original-file quality or licence rights.',
   'Vendor-associated requests do not establish ownership of the main DAM repository.',
   'Not observed means unknown, not safe; a sample cannot establish a complete security posture.',
   'Authorisation, origin protection, token expiry, sharing policy and patch state require system-owner verification.']};
}
function pack(record,specialists){return evaluate(record,specialists);}
const API={evaluate,pack};root.THIDAMReview=API;
if(typeof module==='object'&&module.exports)module.exports=API;
})(typeof self!=='undefined'?self:globalThis);
