/* Offline, evidence-limited comparison of JS files and already-redacted findings. */
(function(root){'use strict';
const DIGEST=/^[a-f0-9]{64}$/i;
function scripts(rec){
 const out=new Map();
 for(const r of rec?.resourceScans||[]){
  if(r.kind!=='javascript'||typeof r.url!=='string'||!/^https?:\/\//.test(r.url))continue;
  const old=out.get(r.url),hash=DIGEST.test(r.sha256||'')?r.sha256.toLowerCase():'';
  // Prefer a verified hash if a duplicate URL had an older unverifiable capture.
  if(!old||hash||!old.sha256)out.set(r.url,{url:r.url,host:r.host||'',sha256:hash,bytes:Number(r.byteCount)||0,at:r.at||''});
 }
 return out;
}
function findingKey(r){
 // Location signature is intentionally constructed exclusively from REDACTED fields.
 // Equal signatures do not prove equal secret values; different underlying values
 // with identical mask/source/offset can look the same. No raw token digest stored.
 return [String(r.type||'').slice(0,80),String(r.source||'').slice(0,600),
   Number.isSafeInteger(Number(r.offset))?Number(r.offset):0,String(r.masked||'').slice(0,150)].join('|');
}
function signatureKey(r){
 // Compact deterministic identifier of a MASKED location, not a cryptographic
 // fingerprint of the secret. This avoids keeping large duplicated URL strings.
 const value=findingKey(r);let hash=0xcbf29ce484222325n;
 for(let i=0;i<value.length;i++)hash=((hash^BigInt(value.charCodeAt(i)))*0x100000001b3n)&0xffffffffffffffffn;
 return hash.toString(16).padStart(16,'0');
}
function jsFinding(r){return r&&/\.m?js(?:\?|$)/i.test(String(r.source||''))&&
 (String(r.masked||'').includes('[redacted]'));}
function findings(record){return new Map((record?.findings||[]).filter(jsFinding)
 .map(f=>[findingKey(f),f]));}
function compare(previous,current){
 if(!previous||!current)return {rows:[],newIndicators:[],missingIndicators:[],stats:{},assessment:'Choose a baseline and a current investigation.'};
 const a=scripts(previous),b=scripts(current),rows=[];
 for(const u of new Set([...a.keys(),...b.keys()])){
  const left=a.get(u),right=b.get(u);let status='';
  if(!right)status='Not observed now';
  else if(!left)status='Newly observed URL';
  else if(!left.sha256||!right.sha256)status='Cannot verify change';
  else status=left.sha256===right.sha256?'Identical decoded text':'Changed decoded text';
  rows.push({url:u,status,previousHash:left?.sha256||'',currentHash:right?.sha256||'',previousBytes:left?.bytes??'',currentBytes:right?.bytes??'',at:right?.at||left?.at||''});
 }
 const fa=findings(previous),fb=findings(current);
 const newIndicators=[...fb.entries()].filter(([key])=>!fa.has(key)).map(([,f])=>({type:f.type,source:f.source,masked:f.masked,line:f.line??null,column:f.column??null,severity:f.severity||''}));
 const missingIndicators=[...fa.entries()].filter(([key])=>!fb.has(key)).map(([,f])=>({type:f.type,source:f.source,masked:f.masked}));
 rows.sort((x,y)=>x.status.localeCompare(y.status)||x.url.localeCompare(y.url));
 const stats={previousObserved:a.size,currentObserved:b.size,changed:rows.filter(r=>r.status==='Changed decoded text').length,
 unchanged:rows.filter(r=>r.status==='Identical decoded text').length,newFiles:rows.filter(r=>r.status==='Newly observed URL').length,
 missing:rows.filter(r=>r.status==='Not observed now').length,unverified:rows.filter(r=>r.status==='Cannot verify change').length,
 newIndicators:newIndicators.length};
 return {rows,newIndicators,missingIndicators,stats,assessment:'Only observed, scanned JS responses are compared. Missing files do not mean deleted; changed SHA-256 proves changed browser-decoded text, not a security issue. Masked indicator location changes do not verify changed credentials. DevTools and scan gaps may affect both sessions.'};
}
root.THIChanges={scripts,findingKey,signatureKey,compare};
if(typeof module!=='undefined'&&module.exports)module.exports=root.THIChanges;
})(typeof self!=='undefined'?self:globalThis);
