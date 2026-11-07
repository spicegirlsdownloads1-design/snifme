/* Trufflehog Intelligence v3.5 — passive DAM security evidence review.
 * No privileged requests, guessed URLs, credential replay, or CVE claims
 * from technology fingerprints. All returned evidence is redacted/generalized.
 */
(function(root){
'use strict';
const PROFILES=Object.freeze([
 {id:'capture',name:'Capture DAM',check:'Review front-end/DAM integration account scopes, public API field policy and preview/original separation.'},
 {id:'resourcespace',name:'ResourceSpace',check:'Review user groups, collection visibility, supported version, plugins and signing-key custody.'},
 {id:'photoshelter',name:'PhotoShelter',check:'Review gallery permissions, direct-link expiry and download-size policies.'},
 {id:'bynder',name:'Bynder',check:'Review public-original settings, external CDN TTL and link revocation expectations.'},
 {id:'canto',name:'Canto',check:'Review external portal sharing, expiration settings, groups and DAM integrations.'},
 {id:'fotoware',name:'FotoWare / FotoWeb',check:'Review rendition permissions, archive roles, exports and API application access.'}
]);
const ADVISORIES=Object.freeze([
 {id:'CVE-2021-41765',product:'resourcespace',title:'Historical ResourceSpace SQL injection',source:'https://www.horizon3.ai/multiple-vulnerabilities-in-resourcespace/',detail:'9.5 and 9.6 revisions before 18274; verify exact build and vendor fixes.'},
 {id:'CVE-2024-12706',product:'opentext-dam',title:'OpenText DAM SQL injection advisory',source:'https://nvd.nist.gov/vuln/detail/CVE-2024-12706',detail:'Versions through 24.4 affected per NVD; authenticated-user issue. Verify actual deployment and vendor mitigation.'}
]);
const versionOK=s=>/^\d+(?:\.\d+){0,3}$/.test(s)&&s.length<=35;
function advisoryLookup(product,version){
 const id=String(product||'').toLowerCase(),v=String(version||'').trim();
 if(!['resourcespace','opentext-dam'].includes(id))return {status:'unknown-product',results:[]};
 if(!versionOK(v))return {status:'invalid-version',results:[]};
 const a=ADVISORIES.find(x=>x.product===id);
 if(id==='resourcespace'){
  const parts=v.split('.').map(Number);let status='no-identified-match';
  if(parts[0]===9&&parts[1]===5)status='review-version';
  if(parts[0]===9&&parts[1]===6) status=parts.length<3?'review-build':parts[2]<18274?'review-version':'no-identified-match';
  return {status,results:status.startsWith('review')?[a]:[]};
 }
 const pieces=v.split('.').map(Number);
 const status=pieces[0]<24||(pieces[0]===24&&(pieces[1]||0)<=4)?'review-version':'no-identified-match';
 return {status,results:status==='review-version'?[a]:[]};
}
function host(value){try{const u=new URL(String(value||''));return /^https?:$/.test(u.protocol)?u.hostname.toLowerCase().slice(0,150):'';}catch{return '';}}
function add(rows,kind,level,title,evidence,explanation,next,confidence='Observed signal'){
 if(rows.length>=80)return;
 rows.push({kind,level,title,evidence:String(evidence||'').slice(0,180),explanation,next,confidence});
}
function analyze(rec,platformAnalysis){
 if(!rec||typeof rec!=='object')return {findings:[],profiles:[],stats:{observedRequests:0,maskedIndicators:0}};
 const req=(Array.isArray(rec.requests)?rec.requests:[]).slice(-2500);
 const assets=(Array.isArray(rec.assets)?rec.assets:[]).slice(-1800);
 const findings=(Array.isArray(rec.findings)?rec.findings:[]).slice(-300);
 const responses=(Array.isArray(rec.responses)?rec.responses:[]).slice(-400);
 const verifications=(Array.isArray(rec.verifications)?rec.verifications:[]).slice(-400);
 const out=[];
 const levels=new Map();
 for(const f of findings){
  if(f.reviewStatus==='false-positive'||f.reviewStatus==='resolved')continue;
  const k=String(f.type||'').slice(0,90),level=f.severity==='potentially sensitive'?'Review promptly':f.severity==='review'?'Review':'Informational';
  if(!levels.has(k))levels.set(k,{level,count:0,hosts:new Set()});const g=levels.get(k);g.count++;const h=host(f.source);if(h)g.hosts.add(h);
 }
 for(const [kind,g] of [...levels].slice(0,30)){
  if(g.level==='Informational')continue;
  add(out,'Credential indicator',g.level,'Masked '+kind,`${g.count} indicator(s); source host(s): ${[...g.hosts].slice(0,3).join(', ')||'unattributed'}`,
   'Pattern match, not verified credential exposure or validity.',
   'Owner: review the originating file and revoke/rotate only if a genuine credential is confirmed.');
 }
 const signed=req.filter(r=>r.signedQuery===true);
 if(signed.length)add(out,'Signed delivery','Informational','Signed-query delivery observed',`${signed.length} request(s) on ${new Set(signed.map(r=>r.host).filter(Boolean)).size} host(s)`,
  'Token-like query parameters were observed, but their values were discarded. This does not imply a bypass.',
  'Owner: verify link lifetime, origin protection and revocation policy.');
 const access=req.filter(r=>r.status===401||r.status===403);
 if(access.length)add(out,'Access controls','Informational','Restricted responses observed',`${access.length} HTTP 401/403 response(s)`,
 'These responses indicate denial, not a vulnerability.',
 'Owner: test object-level access using separately authorised test accounts if needed.');
 const download=req.filter(r=>r.status>=200&&r.status<300&&/(?:^|\/)\b(?:original|master|download|full[-_]?res)\b(?:\/|[._-]|$)/i.test((()=>{try{return new URL(r.url).pathname}catch{return ''}})()));
 if(download.length)add(out,'Asset delivery','Review','Original/download-labelled paths observed',`${download.length} successful request(s) with a delivery-related pathname`,
  'URL terminology alone does not establish that an original file was provided or that sharing is unintended.',
  'Owner: verify whether the corresponding asset is intentionally public and which size was actually served.');
 const cache=req.filter(r=>r.cacheScope==='public'&&r.cacheMaxAge>=86400&&(r.type==='image'||String(r.mime||'').startsWith('image/')));
 if(cache.length)add(out,'CDN caching','Review','Long-lived public image caching observed',`${cache.length} image response(s) with public max-age of at least 24 hours`,
  'A public cache directive is not an exposure by itself; revocation can depend on CDN invalidation.',
  'Owner: compare image withdrawal/embargo policy with invalidation and TTL settings.');
 const wildcard=req.filter(r=>r.corsWildcard===true&&r.status>=200&&r.status<300);
 if(wildcard.length)add(out,'Cross-origin headers','Informational','Wildcard CORS header observed',`${wildcard.length} successful response(s) with Access-Control-Allow-Origin: *`,
 'Wildcard CORS is common for public assets; it is not evidence of private data disclosure.',
 'Owner: ensure sensitive authenticated responses use the intended origin and credential controls.');
 const rightsFields=new Set(),privateFields=new Set();
 const PRIV=/(?:^|\.)(?:email|phone|gps|latitude|longitude|internal|private|embargo|releaseDate|userId|personalData)(?:\.|\[|$)/i;
 const RIGHTS=/(?:^|\.)(?:copyright|creator|credit|licen[cs]e|rights|photographer|agency)(?:\.|\[|$)/i;
 for(const r of responses)for(const f of (Array.isArray(r.fields)?r.fields:[]).slice(0,150)){
  const path=String(f.path||'');if(path.length>160)continue;
  if(PRIV.test(path))privateFields.add(path.split('.').at(-1));
  if(RIGHTS.test(path))rightsFields.add(path.split('.').at(-1));
 }
 if(privateFields.size)add(out,'Schema privacy','Review','Potentially sensitive metadata field names in observed JSON',`${privateFields.size} distinct field name(s) classified, without saving values`,
 'Field names do not prove values were populated, sensitive or unauthorised.',
 'Owner: confirm response-level data minimisation and field authorisation.');
 if(rightsFields.size)add(out,'Rights metadata','Informational','Rights/credit-related JSON fields present',`${rightsFields.size} distinct field name(s)`,
  'These may be correct publication fields; no field values were retained.',
  'Owner: check published attribution and licence policy.');
 const metadata=new Set();for(const v of verifications)for(const m of (v.metadata||[])){
   if(['EXIF','IPTC','XMP','ICC','C2PA'].includes(m?.kind))metadata.add(m.kind);
 }
 if(metadata.size)add(out,'Image metadata','Informational','Embedded metadata block types observed',`Types: ${[...metadata].sort().join(', ')}`,
  'Block fingerprints do not reveal personal information or establish whether GPS/PII is present.',
  'Owner: inspect permitted original samples separately if privacy review is required.');
 const coverage=rec.autoScanCoverage;
 if(coverage&&Number(coverage.eligible)>Number(coverage.scanned)+(Number(coverage.duplicates)||0))
  add(out,'Inspection coverage','Incomplete','Not all eligible loaded files were confirmed inspected',`${coverage.scanned||0} scanned of ${coverage.eligible||0} eligible sightings`,
    'DevTools may also have missed files loaded before it was opened.',
    'Owner: check the Auto-scanned files panel and reload with DevTools open.');
 const platformNames=(platformAnalysis?.profiles||[]).filter(p=>PROFILES.some(x=>x.id===p.id))
  .slice(0,20).map(p=>{const base=PROFILES.find(x=>x.id===p.id);return {id:p.id,name:base.name,confidence:p.confidence,assessment:p.assessment,check:base.check};});
 return {findings:out,profiles:platformNames,stats:{observedRequests:req.length,maskedIndicators:findings.length,observedAssets:assets.length,observedSchemas:responses.length,riskReview:out.filter(x=>x.level.startsWith('Review')).length,incomplete:out.some(x=>x.level==='Incomplete')}};
}
root.THIDAMSecurity={PROFILES,ADVISORIES,advisoryLookup,analyze};
if(typeof module==='object'&&module.exports)module.exports=root.THIDAMSecurity;
})(typeof globalThis!=='undefined'?globalThis:this);
