/* Trufflehog v3.3 - offline evidence bundles, integrity, replay and search.
   Analyses existing redacted observations only. Never contacts an investigated host. */
(function(root){
'use strict';
const KEYS=['interactions','resourceScans','galleryEvents','galleryAssets','viewerResources','viewerManifests','viewerHints','requests','assets','assetLinks','routes','scripts','findings','clues','maps','operations','configs','responses','pagination','verifications','technologyHints','scannedScripts'];
const badKey=/(?:password|secret|credential|authorization|cookie|rawBody|responseBody|requestBody|bearer|privateKey|accessToken|refreshToken|headers|fullContent|sourceContent|sourceText|tokenValue)/i;
function cleanUrl(value){try{const u=new URL(value);if(!/^https?:$/.test(u.protocol))return '[unavailable URL]';return u.origin+u.pathname;}catch{return '[unavailable URL]';}}
function scrub(value,key='',depth=0){
 if(depth>8)return null;
 if(Array.isArray(value))return value.slice(0,2500).map(v=>scrub(v,'',depth+1)).filter(x=>x!==undefined);
 if(value&&typeof value==='object'){
  const result={};for(const [k,v] of Object.entries(value).slice(0,140)){
   if(badKey.test(k)||k==='_key'||!/^[-\w]{1,48}$/.test(k))continue;
   const clean=scrub(v,k,depth+1);if(clean!==undefined)result[k]=clean;
  }return result;
 }
 if(typeof value==='number')return Number.isFinite(value)?value:null;
 if(typeof value==='boolean'||value===null)return value;
 if(typeof value!=='string')return undefined;
 if(key==='masked'||key==='value'&&value.length>0)return '[redacted]';
 if(/(?:url|uri|^source$|^script$|^document$|^page$|^family$|^referer$)/i.test(key)&&/^https?:\/\//i.test(value))return cleanUrl(value);
 if(/^https?:\/\//i.test(value))return cleanUrl(value);
 if(value.length>1000||/[\r\n\x00-\x08]/.test(value)||/\b(?:ghp_|glpat-|sk_live_|xox[bapors]-|AIza[\w-]{20}|eyJ[A-Za-z0-9_-]{20,})/i.test(value))return '[redacted]';
 return value;
}
function safeRecord(record){
 if(!record||typeof record!=='object'||!/^https?:\/\//.test(record.origin||''))throw Error('Invalid saved session');
 const out={sessionId:String(record.sessionId||''),captureGroupId:String(record.captureGroupId||record.sessionId||''),
 segmentIndex:Number(record.segmentIndex)||1,previousSegmentId:record.previousSegmentId||null,
 origin:new URL(record.origin).origin,createdAt:record.createdAt,endedAt:record.endedAt||null,
 counters:scrub(record.counters||{}),autoScanCoverage:scrub(record.autoScanCoverage||null),schema:record.schema||13};
 for(const k of KEYS)out[k]=scrub(Array.isArray(record[k])?record[k]:[],k);
 return out;
}
function groupRows(summaries){
 const map=new Map();for(const r of summaries){const id=r.captureGroupId||r.id;
  if(!map.has(id))map.set(id,{id,origin:r.origin,segments:[],first:r.startedAt,last:r.endedAt,requests:0,findings:0,images:0});
  const g=map.get(id);g.segments.push(r);g.requests+=r.requests||0;g.findings+=r.findings||0;g.images+=r.images||0;
  if((r.startedAt||'')<(g.first||''))g.first=r.startedAt;
  if((r.endedAt||'')>(g.last||''))g.last=r.endedAt;
 }
 return [...map.values()].map(g=>({...g,count:g.segments.length,segments:g.segments.sort((a,b)=>(a.segmentIndex||1)-(b.segmentIndex||1)||String(a.startedAt).localeCompare(String(b.startedAt)))})).sort((a,b)=>String(b.first).localeCompare(String(a.first)));
}
async function hash(s){if(!root.crypto?.subtle)throw Error('WebCrypto SHA-256 unavailable');
 const bytes=new TextEncoder().encode(s),digest=await root.crypto.subtle.digest('SHA-256',bytes);
 return [...new Uint8Array(digest)].map(x=>x.toString(16).padStart(2,'0')).join('');}
async function bundle(records){
 if(!Array.isArray(records)||!records.length)throw Error('Select a nonempty capture group');
 const safe=records.map(safeRecord).sort((a,b)=>a.segmentIndex-b.segmentIndex||String(a.createdAt).localeCompare(String(b.createdAt)));
 const gid=safe[0].captureGroupId;if(safe.some(r=>r.captureGroupId!==gid))throw Error('Capture group mismatch');
 if(new Set(safe.map(r=>r.sessionId)).size!==safe.length)throw Error('Repeated session ID');
 const manifest=[];for(const r of safe){const body=JSON.stringify(r);manifest.push({id:r.sessionId,segmentIndex:r.segmentIndex,bytes:new TextEncoder().encode(body).length,sha256:await hash(body)});}
 return {format:'trufflehog-vault-group',version:1,exportedAt:new Date().toISOString(),sourceGroup:gid,segmentCount:safe.length,manifest,rootHash:await hash(manifest.map(x=>x.sha256).join('\n')),records:safe,
  notice:'Integrity hashes detect accidental changes; they do not authenticate the source. Sensitive values are redacted. No rights to private assets are conveyed.'};
}
async function verify(input){
 if(input?.format!=='trufflehog-vault-group'||input?.version!==1||!Array.isArray(input.records)||!Array.isArray(input.manifest)||!Number.isInteger(input.segmentCount)||input.segmentCount<1||input.segmentCount>120||input.records.length!==input.segmentCount||input.manifest.length!==input.segmentCount)throw Error('Not a supported capture-group backup');
 if(!/^[\w-]{8,90}$/.test(input.sourceGroup||''))throw Error('Invalid capture-group ID');
 const ids=new Set(),indices=new Set(),digests=[];
 for(let i=0;i<input.records.length;i++){
  const r=input.records[i],m=input.manifest[i];
  if(!r||!m||r.captureGroupId!==input.sourceGroup||r.sessionId!==m.id||r.segmentIndex!==m.segmentIndex||!Number.isInteger(r.segmentIndex)||r.segmentIndex<1||ids.has(r.sessionId)||indices.has(r.segmentIndex))throw Error('Duplicate or mismatched segment');
  ids.add(r.sessionId);indices.add(r.segmentIndex);
  const content=JSON.stringify(r),bytes=new TextEncoder().encode(content).length;
  const actual=await hash(content);
  if(actual!==m.sha256||bytes!==m.bytes)throw Error('Integrity mismatch in segment '+r.segmentIndex);
  digests.push(actual);
 }
 if(await hash(digests.join('\n'))!==input.rootHash)throw Error('Bundle manifest integrity mismatch');
 const sorted=[...indices].sort((a,b)=>a-b),missing=[];
 for(let n=1;n<=sorted[sorted.length-1]&&missing.length<100;n++)if(!indices.has(n))missing.push(n);
 return {ok:true,segments:input.segmentCount,missing,originCount:new Set(input.records.map(x=>x.origin)).size,group:input.sourceGroup};
}
function safeEvent(row,kind,part,group){
 const t=row?.at||row?.time||row?.timestamp||row?.createdAt||'';
 if(typeof t!=='string'||!Number.isFinite(Date.parse(t)))return null;
 const desc=kind==='Network request'?`${row.method||'GET'} ${row.status||'—'} ${row.url?cleanUrl(row.url):row.host||''}`:
  kind==='Masked indicator'?`${row.type||'Indicator'} · ${row.reviewStatus||'new'} · ${row.source?cleanUrl(row.source):''}`:
  kind==='Gallery activity'?`${row.kind||row.event||'Gallery observation'} · ${row.cardCount||row.cards||''}`:
  kind==='Interaction'?`${row.kind||'Site action'} (values excluded)`:
  kind==='File scan'?`${row.kind||'Resource'} · ${row.url?cleanUrl(row.url):''}`:
  kind==='Image verification'?`${row.sha256?'SHA-256 '+row.sha256.slice(0,12)+'…':'Image evidence'} · ${row.url?cleanUrl(row.url):''}`:kind;
 return {at:t,kind,detail:scrub(desc,'detail'),segmentIndex:part,group};
}
function timeline(records,limit=1500){const result=[],by=[['requests','Network request'],['interactions','Interaction'],['galleryEvents','Gallery activity'],['resourceScans','File scan'],['findings','Masked indicator'],['verifications','Image verification']];
 for(const r of records){for(const [field,kind]of by)for(const item of r[field]||[]){if(item?.carriedFromSegment)continue;const e=safeEvent(item,kind,r.segmentIndex||1,r.captureGroupId||r.sessionId);if(e)result.push(e);}}
 result.sort((a,b)=>a.at.localeCompare(b.at)||a.segmentIndex-b.segmentIndex);return {total:result.length,rows:result.slice(0,limit),truncated:result.length>limit};
}
function search(records,q,limit=300){const needle=String(q||'').trim().toLowerCase();if(needle.length<2)return {rows:[],total:0,truncated:false};
 const hits=[];for(const r of records)for(const f of r.findings||[]){
  if(f?.carriedFromSegment)continue;
  const fields=[f.type,f.source,f.note,f.reviewStatus,f.severity,f.masked].map(x=>typeof x==='string'?x:'');
  if(!fields.some(x=>x.toLowerCase().includes(needle)))continue;
  hits.push({sessionId:r.sessionId,origin:r.origin,segmentIndex:r.segmentIndex||1,type:f.type||'',source:scrub(f.source||'','source'),
   masked:'[redacted]',reviewStatus:f.reviewStatus||'new',at:f.at||'',severity:f.severity||''});
 }return {rows:hits.slice(0,limit),total:hits.length,truncated:hits.length>limit};
}
root.THIPro={safeRecord,groupRows,bundle,verify,timeline,search,hash};
if(typeof module!=='undefined'&&module.exports)module.exports=root.THIPro;
})(typeof self!=='undefined'?self:globalThis);
