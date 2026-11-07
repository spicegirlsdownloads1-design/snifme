/* Trufflehog Intelligence 5.7 — passive, bounded specialist DAM interpretation.
 * Zero network calls. Never stores full paths, query values, header values,
 * tokens, URLs, resource IDs or source code. Explicit source-qualification.
 */
(function(root){
'use strict';
const SPECS=Object.freeze([
 {id:'capture',name:'Capture DAM',kind:'DAM',domains:['captureweb.net'],review:'Confirm tenant permissions, licensing and download entitlements in the owner console; browser observations cannot certify access controls.'},
 {id:'resourcespace',name:'ResourceSpace',kind:'DAM',domains:['resourcespace.com'],review:'Verify API user permissions, key management, native session safeguards and CSRF handling with the owner.'},
 {id:'photoshelter',name:'PhotoShelter',kind:'DAM',domains:['photoshelter.com'],review:'Review gallery visibility and separate download permissions using owner settings.'},
 {id:'bynder',name:'Bynder',kind:'DAM',domains:['bynder.com','bynder.io','getbynder.com'],review:'Check API scopes, media-download roles and separately managed public sharing policies.'},
 {id:'cloudinary',name:'Cloudinary',kind:'Image delivery',domains:['cloudinary.com'],review:'Verify original/derivative access, strict transformations and signed-delivery policies in the owner account.'},
 {id:'canto',name:'Canto',kind:'DAM',domains:['canto.com','canto.global'],review:'Verify OAuth client-secret custody and portal/share permissions with the owner.'},
 {id:'fotoware',name:'FotoWare / FotoWeb',kind:'DAM',domains:['fotoware.com'],review:'Review authenticated download, sharing and API scopes using the owner configuration.'}
]);
const S_BY_ID=Object.fromEntries(SPECS.map(s=>[s.id,s]));
const LIMIT={requests:1300,responses:160,assets:700,maxPerVendor:12};
function saneURL(input){
 try{
  const u=new URL(String(input||''));
  if(!['https:','http:'].includes(u.protocol))return null;
  const h=u.hostname.toLowerCase();if(h.length>253 || /[^a-z0-9.:-]/.test(h))return null;
  // Only used *in memory* to evaluate documented patterns. Never return path values in results.
  return {host:h,path:u.pathname.slice(0,800),query:u.searchParams};
 }catch{return null;}
}
function owns(host,domain){return host===domain||host.endsWith('.'+domain);}
function sourceRole(origin,host){return host===origin?'Captured site origin':'Observed external service (not proof of backend ownership)';}
function asStatus(n){const v=Number(n);return Number.isInteger(v)&&v>=100&&v<=599?v:0;}
function analyze(record,tech){
 const empty={profiles:[],stats:{requestCount:0,platforms:0,observed:0},limits:{...LIMIT},qualification:'No network requests are generated. Presence of service traffic or schema clues is not an authorisation or security finding.'};
 if(!record||typeof record!=='object')return empty;
 const origin=saneURL(record.origin)?.host||'';
 const recognized=new Map();
 const named=tech?.profiles && Array.isArray(tech.profiles) ? tech.profiles : (root.THIDAM?.analyze?.(record)?.profiles||[]);
 for(const s of SPECS){
  const old=named.find(p=>p?.id===s.id);
  if(old)recognized.set(s.id,{spec:s,old, evidence:[],seen:new Set(), network:0, hosted:0, observedCodes:new Set(),statuses:new Set(),deliveryTypes:new Set(),foundHostRoles:new Set(),structural:0});
 }
 function get(id){
  if(!S_BY_ID[id])return null;
  if(!recognized.has(id))recognized.set(id,{spec:S_BY_ID[id],old:null,evidence:[],seen:new Set(),network:0,hosted:0,observedCodes:new Set(),statuses:new Set(),deliveryTypes:new Set(),foundHostRoles:new Set(),structural:0});
  return recognized.get(id);
 }
 function add(id,code,kind,detail,weight=1,observed=false,host=''){
  const g=get(id);if(!g||!code||g.evidence.length>=LIMIT.maxPerVendor)return;
  const k=code+'|'+kind;if(g.seen.has(k))return;
  g.seen.add(k);g.evidence.push({code,kind,detail,weight,observed:!!observed});
  if(observed){g.network++; if(host && origin && host!==origin)g.foundHostRoles.add('external'); else if(host && host===origin)g.foundHostRoles.add('same-origin');}
  if(code==='vendor-host')g.hosted++;
  if(code.startsWith('delivery-'))g.deliveryTypes.add(code.replace('delivery-',''));
  if(code==='schema-fields')g.structural++;
 }
 const requestList=Array.isArray(record.requests)?record.requests.slice(-LIMIT.requests):[];
 for(const r of requestList){
  const u=saneURL(r?.url);if(!u)continue;
  const method=String(r.method||'GET').toUpperCase();
  const status=asStatus(r.status||r.statusCode);
  for(const s of SPECS){
   if(s.domains.some(d=>owns(u.host,d))) {
    const g=get(s.id);g.statuses.add(status?Math.floor(status/100)+'xx':'unknown');
    add(s.id,'vendor-host','observed network','Request to a recognised vendor-associated hostname; service use, not deployment proof',3,true,u.host);
    const label=sourceRole(origin,u.host);if(label.startsWith('Observed external'))g.foundHostRoles.add('external');
   }
  }
  const path=u.path;
  // Vendor-specific, documented patterns. Do not evaluate resource IDs or query values.
  if((/\/api\/v4\/media(?:\/|$)/i.test(path) && (owns(u.host,'getbynder.com')||/bynder/i.test(u.host)))){
   if(/\/api\/v4\/media\/[^/]+\/(?:\d+\/)?download\/?$/i.test(path)) add('bynder','media-download','documented API pattern','Bynder media-version download-location API request observed',4,true,u.host);
   else add('bynder','media-list','documented API pattern','Bynder media API request observed',3,true,u.host);
  }
  if(/\/api\/(?:index\.php)?\/?$/i.test(path)){
   // Generic path is insufficient to attribute ResourceSpace. Require named vendor evidence or distinctive signed function fields.
   const keyCount=['user','function','sign'].filter(k=>u.query.has(k)).length;
   if(keyCount===3) add('resourcespace','signed-api-fields','documented parameter-name shape','Signed user/function/sign API parameter names observed (ResourceSpace-compatible, not unique)',2,true,u.host);
   else if(u.query.has('authmode') && u.query.has('function'))add('resourcespace','native-api-fields','documented parameter-name shape','authmode/function names observed (ResourceSpace-compatible, not unique)',1,true,u.host);
  }
  if(owns(u.host,'res.cloudinary.com') || owns(u.host,'api.cloudinary.com')){
   const d=path.match(/^\/(?:[^/]+)\/(?:image|video|raw)\/(upload|private|authenticated)(?:\/|$)/i);
   if(d){const delivery=d[1].toLowerCase();add('cloudinary','delivery-'+delivery,'documented delivery type','Cloudinary '+delivery+' delivery URL structure observed; policy enforcement not tested',4,true,u.host);}
   if(/^\/v1_1\/[^/]+\/(?:image|video|raw)\/upload\/?$/i.test(path))add('cloudinary','upload-api','documented API pattern','Cloudinary upload API request observed',3,true,u.host);
  }
  if(owns(u.host,'api.captureweb.net'))add('capture','capture-api','vendor API host','Capture API host used during capture',4,true,u.host);
  if((owns(u.host,'photoshelter.com')||owns(u.host,'photoshelter.net'))&&/\/psapi\//i.test(path))add('photoshelter','api-service','vendor path clue','PhotoShelter-labelled API path observed',2,true,u.host);
 }
 // Reuse pre-existing validated technology identifications, without exporting its raw sources.
 for(const [id,g] of recognized){
  if(g.old){
   const conf=g.old.confidence==='Strong indication'?'strong':g.old.confidence==='Moderate indication'?'moderate':'weak';
   add(id,'recognition-'+conf,'existing validated recognition','Earlier technology-recognition layer reported '+conf+' evidence',conf==='strong'?3:conf==='moderate'?2:1,false);
  }
 }
 // JSON shape: only a restrained pair of field *names*. Does not retain values or paths.
 for(const item of (Array.isArray(record.responses)?record.responses.slice(-LIMIT.responses):[])){
  if(!Array.isArray(item?.fields))continue;
  const fields=new Set(item.fields.slice(0,160).map(v=>String(v?.path||'').toLowerCase().split('.').at(-1)).filter(v=>/^[a-z0-9_]{1,40}$/.test(v)));
  if(fields.has('idasset')&&fields.has('org_filename'))add('capture','schema-fields','observed JSON shape','Capture-compatible idasset + org_filename names observed; not unique',1,false);
 }
 // Do not assert that standalone common field names/paths establish ResourceSpace or Capture.
 const profiles=[];
 for(const g of recognized.values()){
  if(!g.evidence.length)continue;
  const s=g.spec, e=g.evidence;
  const hostFlag=e.some(x=>x.code==='vendor-host');
  const specific=e.some(x=>['capture-api','media-list','media-download','upload-api','delivery-upload','delivery-private','delivery-authenticated'].includes(x.code));
  const recognitionStrong=e.some(x=>x.code==='recognition-strong');
  const genericOnly=!hostFlag&&!specific&&!recognitionStrong;
  const confidence=(!genericOnly&&specific&&(hostFlag||recognitionStrong))?'Strong indication':(hostFlag||recognitionStrong||specific)?'Moderate indication':'Weak clue';
  const role=g.foundHostRoles.has('same-origin')?'Site-host observation':g.foundHostRoles.has('external')?'External service observed':'Unconfirmed (code or schema clues only)';
  const signals=e.map(x=>x.detail);
  const access=g.deliveryTypes.size ? [...g.deliveryTypes].sort().map(v=>v==='private'?'private URL type: original usually requires signing; derivatives may not':v==='authenticated'?'authenticated URL type: originals and derivatives require authorisation': 'upload URL type: often publicly deliverable; account policy may restrict').join('; ') :
    e.some(x=>x.code==='media-download')?'Media download-location route observed; server-side permissions not evaluated':'Not established from these observations';
  profiles.push({id:s.id,vendor:s.name,kind:s.kind,confidence,role,signalCount:e.length,observedRequests:g.network,networkEvidence:g.network?'Yes':'No', evidence:signals.join(' · '),access,ownerReview:s.review,qualifier:'Browser observations only; never proof of site ownership, public access, valid credentials, or permission failures.'});
 }
 const order={'Strong indication':0,'Moderate indication':1,'Weak clue':2};
 profiles.sort((a,b)=>order[a.confidence]-order[b.confidence]||b.observedRequests-a.observedRequests||a.vendor.localeCompare(b.vendor));
 return {profiles,stats:{requestCount:requestList.length,platforms:profiles.length,observed:profiles.filter(p=>p.observedRequests>0).length},limits:{...LIMIT},qualification:empty.qualification};
}
function report(record,tech){
 const analysis=analyze(record,tech);
 // Export only generated static text, numeric counters and allowlisted vendor IDs.
 return {version:'5.7',kind:'dam-specialists',...analysis};
}
root.THIDAMSpecialists={SPECS:SPECS.map(s=>({id:s.id,name:s.name,kind:s.kind})),analyze,report};
})(globalThis);
