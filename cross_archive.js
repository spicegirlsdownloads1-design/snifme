/* v3.0 Cross-Archive Explorer. Pure analysis of *saved, observed* metadata.
   No requests, probing, original-file inference, or credential access. */
(function(root){
'use strict';
const Visual=root.THIVisual||(typeof require==='function'?require('./visual_intel.js'):null);
const take=(r,k,n=2000)=>Array.isArray(r?.[k])?r[k].slice(0,n):[];
const validHash=v=>typeof v==='string'&&/^[a-f0-9]{64}$/i.test(v);
const safeId=v=>typeof v==='string'&&/^[a-z0-9][a-z0-9_.:-]{4,90}$/i.test(v)?v.toLowerCase():'';
const safeUrl=v=>{try{const u=new URL(v);if(!/^https?:$/.test(u.protocol)||u.username||u.password||u.href.length>700)return '';u.search='';u.hash='';return u.href;}catch{return '';}};
const safeOrigin=v=>{try{const u=new URL(v);return /^https?:$/.test(u.protocol)?u.origin:'';}catch{return '';}};
function entries(record){
 const hashes=new Map(),metadata=new Map(),urls=new Map(),ids=new Map(),names=new Map(),schemas=new Map();
 const push=(index,key,source)=>{if(!key)return; if(!index.has(key))index.set(key,new Set());if(index.get(key).size<12)index.get(key).add(String(source).slice(0,700));};
 for(const v of take(record,'verifications')){
  const url=safeUrl(v.url);if(url&&validHash(v.sha256))push(hashes,v.sha256.toLowerCase(),url);
  for(const m of (Array.isArray(v.metadata)?v.metadata.slice(0,16):[])){
   if(['EXIF','IPTC','XMP','C2PA'].includes(m.kind)&&validHash(m.sha256))
     push(metadata,`${m.kind}:${m.sha256.toLowerCase()}`,url||'observed image metadata');
  }
 }
 for(const v of [...take(record,'assets'),...take(record,'verifications')]){
  const url=safeUrl(v.url);if(!url)continue;
  push(urls,url,url);
  try{
   const u=new URL(url),base=decodeURIComponent(u.pathname.split('/').pop()||'').toLowerCase();
   // Only a distinctive filename is useful across sites; ignore common placeholders.
   if(base.length>=10&&base.length<=110&&/\d{5,}/.test(base)&&/\.(?:jpe?g|png|webp|avif|tiff?)$/.test(base)) push(names,base,url);
  }catch{}
 }
 for(const v of take(record,'galleryAssets'))push(ids,safeId(v.assetId),`collection ${safeId(v.collectionId)||'unspecified'}, page ${String(v.page||'?').slice(0,10)}`);
 for(const v of take(record,'assetLinks'))push(ids,safeId(v.assetId),safeUrl(v.imageUrl)||'gallery DOM relationship');
 for(const r of take(record,'responses')){
  // Schema comparison only: keys/types, never values or response bodies.
  for(const f of (Array.isArray(r.fields)?r.fields.slice(0,100):[])){
   const path=String(f.path||'').slice(0,100),type=String(f.type||'').slice(0,25);
   if(path&&/^[a-z\d_.$\[\]-]{1,100}$/i.test(path)&&/^[a-z]+$/i.test(type))push(schemas,`${path}:${type}`,safeUrl(r.url)||'observed JSON shape');
  }
 }
 return {hashes,metadata,urls,ids,names,schemas};
}
function matchIndex(left,right,kind,grade,meaning,limit=70){
 const output=[];let total=0;
 for(const [key,a] of left){
  if(!right.has(key))continue;total++;
  if(output.length>=limit)continue;
  output.push({kind,grade,identity:key,leftEvidence:[...a].slice(0,4),rightEvidence:[...right.get(key)].slice(0,4),meaning});
 }
 return {total,items:output};
}
const CONFIG=[
 ['metadata','Identical embedded metadata block','Clue','Identical EXIF/IPTC/XMP/C2PA block bytes observed. Metadata is sometimes boilerplate or shared across unrelated photographs; this is not evidence of image identity, creator identity or rights.'],
 ['hashes','Identical image bytes','Verified','Same SHA-256 of already-observed image responses. Does not establish rights, ownership or unobserved originals.'],
 ['urls','Matching image URL path','Reference','Same recorded image URL path after stripping query/fragment values; not proof of identical content.'],
 ['ids','Matching gallery/asset ID','Clue','Matching declared ID alone does not prove a shared image or provider.'],
 ['names','Distinctive shared filename','Clue','Identical distinctive filename is a weak clue, not image identity.'],
 ['schemas','Matching JSON field structure','Structural','Same JSON field path/type, not necessarily the same backend.']
];
function analyze(a,b){
 if(!a||!b||a.sessionId===b.sessionId)throw new Error('Select two different saved sessions');
 const left=entries(a),right=entries(b),matches=[],counts={};
 for(const [key,kind,grade,meaning] of CONFIG){
  const found=matchIndex(left[key],right[key],kind,grade,meaning);counts[kind]=found.total;
  matches.push(...found.items);
 }
 const visual=Visual?Visual.compare(take(a,'verifications'),take(b,'verifications'),50):{rows:[],total:0,truncated:false};
 counts['Visual similarity candidates']=visual.total;
 for(const v of visual.rows)matches.push({kind:v.kind,grade:'Candidate',identity:`dHash distance ${v.distance}`,leftEvidence:[v.left],rightEvidence:[v.right],meaning:v.details+' No inference about shared original, rights, or licensing.'});
 return {left:{id:a.sessionId,origin:safeOrigin(a.origin),startedAt:a.createdAt||''},right:{id:b.sessionId,origin:safeOrigin(b.origin),startedAt:b.createdAt||''},
  counts,matches:matches.slice(0,300),totalMatches:Object.values(counts).reduce((n,v)=>n+v,0),
  truncation:visual.truncated||Object.values(counts).reduce((n,v)=>n+v,0)>matches.length,
  assessment:'Only recorded evidence is compared. Exact image hashes establish identical bytes; identical embedded metadata hashes are weak clues and do not establish image identity; URLs, identifiers, filenames and shared schemas are progressively weaker clues. No original-file availability or access rights are inferred. Visual similarity and crop hints are manual-review candidates only.'};
}
const LIMITS={requests:750,assets:800,responses:120,verifications:260,pagination:220,galleryEvents:400,galleryAssets:1200,resourceScans:280,findings:200,viewerResources:350};
function diagnostics(record,recording,bytes){
 const counts={},warnings=[];
 for(const [field,limit] of Object.entries(LIMITS)){
  const observed=take(record,field,100000).length,drop=Number(record?.counters?.[field+'Dropped']||0);
  counts[field]={observed,limit,dropped:drop};
  if(drop>0)warnings.push(`${field}: ${drop} record(s) dropped or overwritten due to capture limits`);
  else if(observed>=limit)warnings.push(`${field}: at the ${limit}-record cap; further events may not be retained`);
 }
 if(!record)warnings.push('No record is available for this tab');
 if(recording?.enabled)warnings.push('Recording is active. Stop and archive it before relying on a durable saved session.');
 warnings.push('Chrome DevTools connection and initial page-request coverage are not independently verified. Open DevTools before reloading for loaded-file scans.');
 return {sessionId:record?.sessionId||'',origin:safeOrigin(record?.origin),capturing:!!recording?.enabled,
  startedAt:record?.createdAt||'',endedAt:record?.endedAt||null,
  bytes:typeof bytes==='number'&&Number.isFinite(bytes)?bytes:null,limits:counts,warnings,
  unreviewedAlerts:Math.max(0,Number(record?.unreviewedAlerts)||0)};
}
root.THICross={analyze,diagnostics,entries};
if(typeof module!=='undefined'&&module.exports)module.exports=root.THICross;
})(typeof self!=='undefined'?self:globalThis);
