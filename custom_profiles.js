/* v4.0: Strictly declarative, local-only custom technology fingerprints.
   No code execution, regex supplied by users, network access or secret collection. */
(function(root){'use strict';
const STORAGE_KEY='thiCustomProfilesV4';
const LAYERS=['DAM','CMS','Headless CMS','Image delivery','Gallery viewer','Other'];
const MAX_PROFILES=24;
function safeName(v){return typeof v==='string'&&v.trim().length>=2&&v.trim().length<=64&&!/[\u0000-\u001f\u007f<>]/.test(v);}
function validHost(v){return typeof v==='string' && v.length<=190 && /^(?=.{4,190}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(v) && !v.includes('..');}
function validPrefix(v){return typeof v==='string'&&v.startsWith('/')&&v.length<=100&&!/[?#%*\\\u0000-\u001f\u007f<>]/.test(v)&&/^\/[A-Za-z0-9._~!$&'()*+,;=:@/-]*$/.test(v)&&!v.includes('..');}
function parseList(value){return (Array.isArray(value)?value:typeof value==='string'?value.split(/[\n,]/):[]).map(v=>String(v).trim()).filter(Boolean);}
function normalize(raw){
 if(!raw || typeof raw!=='object'||Array.isArray(raw))throw Error('Profile must be an object');
 const name=String(raw.name||'').trim(), layer=String(raw.layer||'');
 if(!safeName(name))throw Error('Name must contain 2–64 safe characters');
 if(!LAYERS.includes(layer))throw Error('Unsupported platform category');
 const domains=[...new Set(parseList(raw.domains).map(x=>x.toLowerCase()))];
 const prefixes=[...new Set(parseList(raw.prefixes))];
 if(!domains.length||domains.length>5||domains.some(x=>!validHost(x)))throw Error('Provide 1–5 valid domain suffixes (e.g. archive.example.com)');
 if(prefixes.length>6||prefixes.some(x=>!validPrefix(x)))throw Error('Use at most six literal paths starting with /; no query, fragments or wildcard patterns');
 const id=typeof raw.id==='string'&&/^custom-[a-z0-9-]{6,60}$/.test(raw.id)?raw.id:'';
 return {id,name,layer,domains,prefixes};
}
function validateAll(raw){
 if(!Array.isArray(raw)||raw.length>MAX_PROFILES)throw Error('Too many custom profiles (maximum 24)');
 const output=[],keys=new Set(),labels=new Set();
 for(const item of raw){
  const p=normalize(item);
  if(!p.id)throw Error('Saved profiles require a valid custom ID');
  const duplicateKey=p.id||p.name.toLowerCase();
  if(keys.has(duplicateKey)||labels.has(p.name.toLowerCase()))throw Error('Duplicate profile ID or name');
  keys.add(duplicateKey);labels.add(p.name.toLowerCase());output.push(p);
 }
 return output;
}
function cleanUrl(value){
 try{const u=new URL(String(value));if(u.protocol!=='http:'&&u.protocol!=='https:')return null;
 return {host:u.hostname.toLowerCase(),path:u.pathname.slice(0,220)};
 }catch{return null;}
}
function inspect(profiles,record){
 const urls=[];
 for(const r of (record?.requests||[]).slice(-1500))urls.push({url:r.url,kind:'Observed HTTP request'});
 for(const a of (record?.assets||[]).slice(-1200))urls.push({url:a.url,kind:'Observed image'});
 for(const s of (record?.scripts||[]).slice(-350))urls.push({url:s.url,kind:'Loaded script reference'});
 for(const rt of (record?.routes||[]).slice(-600))urls.push({url:rt.url,kind:rt.observed?'Observed API request':'Static API reference'});
 const result=[];
 for(const p of validateAll(profiles)){
  const seen=new Set(),evidence=[];
  for(const entry of urls){
   const url=cleanUrl(entry.url);if(!url)continue;
   if(!p.domains.some(d=>url.host===d||url.host.endsWith('.'+d)))continue;
   if(p.prefixes.length&&!p.prefixes.some(prefix=>url.path.startsWith(prefix)))continue;
   const key=entry.kind+'|'+url.host+url.path;
   if(seen.has(key))continue;seen.add(key);
   if(evidence.length<12)evidence.push({kind:entry.kind,host:url.host,matchedPrefix:p.prefixes.find(prefix=>url.path.startsWith(prefix))||'(any path)',note:'Raw URL path and query values excluded'});
  }
  if(evidence.length)result.push({id:p.id,name:p.name,layer:p.layer,count:seen.size,evidence,
    assessment:'Custom host/path rule matched observed or referenced resources. Provider ownership and deployment are not verified.'});
 }
 return result;
}
function add(profiles,profile){
 const validated=validateAll(profiles),normalized=normalize(profile);
 if(!normalized.id)throw Error('Missing custom profile ID');
 return validateAll([...validated.filter(p=>p.id!==normalized.id),normalized]);
}
const api={STORAGE_KEY,LAYERS,MAX_PROFILES,normalize,validateAll,inspect,add};
root.THICustomProfiles=api;
if(typeof module!=='undefined'&&module.exports)module.exports=api;
})(typeof self!=='undefined'?self:globalThis);
