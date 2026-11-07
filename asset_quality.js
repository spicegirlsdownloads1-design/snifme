/* Trufflehog Intelligence v5.5 — bounded, OFFLINE rendition-quality evidence.
 * Uses assets and opted-in image verifications already received. This module
 * makes NO requests and never derives or tests alternative rendition URLs.
 * Export contains only aggregate family labels and controlled categorical facts,
 * never raw asset paths, query strings, filenames, image bytes or credentials.
 */
(function(root){
'use strict';
const SHA=/^[a-f0-9]{64}$/i;
const MAX_IMAGES=800,MAX_VERIFICATIONS=260,MAX_FAMILIES=250;
const mimeAllowed=/^(?:image\/(?:jpeg|png|gif|webp|avif|bmp|tiff)|application\/(?:zip|pdf|octet-stream))$/i;
const plausible=n=>Number.isSafeInteger(n)&&n>0&&n<=100000;
const validSize=n=>Number.isSafeInteger(n)&&n>=0&&n<=Number.MAX_SAFE_INTEGER;
function host(raw){
 try{const u=new URL(raw);return /^https?:$/.test(u.protocol)&&!u.username&&!u.password&&/^[a-z0-9.-]{1,253}$/i.test(u.hostname)&&!/(?:secret|password|token|credential|bearer|jwt)/i.test(u.hostname)?u.hostname.toLowerCase():'';}
 catch{return '';}
}
function mime(raw){const s=String(raw||'').toLowerCase().split(';')[0].trim();return mimeAllowed.test(s)?s:'';}
function dimensions(v){return plausible(v?.width)&&plausible(v?.height)?{width:v.width,height:v.height,pixels:v.width*v.height}:null;}
function downloadEvents(rec){
 const events=(Array.isArray(rec?.downloadEvents)?rec.downloadEvents:[]).slice(-450);
 let starts=0,complete=0,interrupted=0,rangeReq=0,rangePartial=0,rangeMeasured=0;
 const kinds=new Map(),failureCategories=new Map(),actualSizes=[];
 for(const e of events){
  if(e?.stage==='download-start')starts++;
  if(e?.stage==='download-state'&&e.downloadStatus==='complete')complete++;
  if(e?.stage==='download-state'&&e.downloadStatus==='interrupted'){
   interrupted++;const category=['network','server','filesystem','user action','browser','other','unknown'].includes(e.errorCategory)?e.errorCategory:'unknown';failureCategories.set(category,(failureCategories.get(category)||0)+1);
  }
  if(e?.rangeRequested===true)rangeReq++;
  if(e?.status===206){rangePartial++;if(validSize(e.rangeTotalBytes)&&e.rangeTotalBytes>0&&validSize(e.rangeStart)&&validSize(e.rangeEnd)&&e.rangeStart<=e.rangeEnd&&e.rangeEnd<e.rangeTotalBytes)rangeMeasured++;}
  if(e?.stage==='download-state'&&e.downloadStatus==='complete'){
   const kind=mime(e.fileType)||'Unknown MIME';kinds.set(kind,(kinds.get(kind)||0)+1);
   if(validSize(e.receivedBytes)&&e.receivedBytes>0)actualSizes.push(e.receivedBytes);
  }
 }
 return {starts,complete,interrupted,rangeRequests:rangeReq,partialResponses:rangePartial,
  measuredRanges:rangeMeasured,completedMimeTypes:[...kinds.entries()].sort().map(([kind,count])=>({kind,count})),
  failureClasses:[...failureCategories.entries()].sort().map(([kind,count])=>({kind,count})),
  completedReceivedBytes:actualSizes.length,largestCompletedReceivedBytes:actualSizes.length?Math.max(...actualSizes):null,
  downloadAttribution:'Downloads are separate browser events; no image-version match is claimed.'};
}
function analyze(record){
 const assets=Array.isArray(record?.assets)?record.assets.slice(0,MAX_IMAGES):[];
 const verifications=Array.isArray(record?.verifications)?record.verifications.slice(0,MAX_VERIFICATIONS):[];
 const rows=(root.THIImages?.rows?root.THIImages.rows(assets,verifications):[]).slice(0,MAX_IMAGES+MAX_VERIFICATIONS);
 const families=new Map(),verifiedHashes=new Map(),stats={imageObservations:rows.length,verifiedFiles:0,measuredDimensions:0,
  browserOnlyDimensions:0,unmeasured:0,exactDuplicateSets:0,unverifiedFamilies:0,truncated:((record?.assets||[]).length>MAX_IMAGES)||((record?.verifications||[]).length>MAX_VERIFICATIONS),
  verificationDrops:Number.isSafeInteger(record?.counters?.verificationsDropped)?record.counters.verificationsDropped:0};
 for(const a of rows){
  if(!a||!host(a.url))continue;
  const enc=dimensions({width:a.encodedWidth,height:a.encodedHeight});
  const browser=dimensions({width:a.width,height:a.height});
  const isVerified=SHA.test(a.sha256||'')&&validSize(a.encodedBytes)&&a.encodedBytes>0;
  if(isVerified)stats.verifiedFiles++;
  if(enc&&isVerified)stats.measuredDimensions++;
  else if(browser)stats.browserOnlyDimensions++;
  else stats.unmeasured++;
  const family=typeof a.family==='string'&&a.family.length>0&&a.family.length<900?a.family:'';
  if(family){if(!families.has(family))families.set(family,[]);families.get(family).push({a,enc,browser,isVerified});}
  if(isVerified){
   const hash=a.sha256.toLowerCase();if(!verifiedHashes.has(hash))verifiedHashes.set(hash,[]);
   verifiedHashes.get(hash).push({host:host(a.url),enc,bytes:a.encodedBytes});
  }
 }
 const out=[];let index=0;
 for(const list of families.values()){
  if(out.length>=MAX_FAMILIES){stats.truncated=true;break;}
  index++;
  // A family is a SAME-HOST pathname heuristic, not proof of one source image.
  const verified=list.filter(x=>x.isVerified&&x.enc).sort((x,y)=>y.enc.pixels-x.enc.pixels);
  const browserOnly=list.filter(x=>!x.isVerified&&x.browser).sort((x,y)=>y.browser.pixels-x.browser.pixels);
  const best=verified[0]||null;
  const smallest=verified.length?verified.at(-1):null;
  const imageHost=host(list[0].a.url);
  const formats=[...new Set(list.map(x=>mime(x.a.mime)||({JPEG:'image/jpeg',PNG:'image/png',WebP:'image/webp',GIF:'image/gif',BMP:'image/bmp'}[x.a.format]||'')).filter(Boolean))].sort();
  const differingRatios=new Set(verified.map(x=>(x.enc.width/x.enc.height).toFixed(3)));
  const hashes=new Set(list.filter(x=>x.isVerified).map(x=>x.a.sha256.toLowerCase()));
  out.push({familyRef:'F'+index,host:imageHost,observedVariants:list.length,verifiedFiles:list.filter(x=>x.isVerified).length,
   verifiedPixelSizes:verified.length,browserOnlySizes:browserOnly.length,
   highestVerifiedPixels:best?`${best.enc.width} × ${best.enc.height}`:'Not measured',
   highestVerifiedPixelCount:best?best.enc.pixels:null,
   largestVerifiedBytes:best?best.a.encodedBytes:null,
   verifiedPixelRatio:smallest&&best&&verified.length>1?Number((best.enc.pixels/smallest.enc.pixels).toFixed(2)):null,
   biggestBrowserReported:browserOnly.length?`${browserOnly[0].browser.width} × ${browserOnly[0].browser.height}`:'—',
   strongestEvidence:best?'Encoded image dimensions verified from received bytes':browserOnly.length?'Browser-reported dimensions only':'Observed URL without verified dimensions',
   exactRepeatedFiles:list.filter(x=>x.isVerified).length-hashes.size,
   differentAspectRatios:differingRatios.size>1,
   formats:formats.join(', ')||'Unknown',
   assessment:best?'Largest VERIFIED OBSERVED rendition; not a claim about the master or licence':
      'No verified encoded dimensions; original resolution unknown'});
 }
 out.sort((a,b)=>(b.highestVerifiedPixelCount||0)-(a.highestVerifiedPixelCount||0)||b.observedVariants-a.observedVariants);
 out.forEach((x,i)=>x.familyRef='F'+String(i+1));
 const duplicates=[];let dupIndex=0;
 for(const list of verifiedHashes.values()){
  if(list.length<2)continue;
  const consistent=list.every(x=>x.bytes===list[0].bytes&&(!x.enc||!list[0].enc||(x.enc.width===list[0].enc.width&&x.enc.height===list[0].enc.height)));
  if(!consistent)continue;
  dupIndex++;
  duplicates.push({duplicateRef:'D'+dupIndex,receivedCopies:list.length,distinctHosts:new Set(list.map(x=>x.host)).size,
    verifiedBytes:list[0].bytes,dimensions:list[0].enc?`${list[0].enc.width} × ${list[0].enc.height}`:'Not measured',
    confidence:'Exact SHA-256 of received bytes',assessment:'Byte-identical observations; not evidence of ownership or licensing'});
  if(duplicates.length>=100){stats.truncated=true;break;}
 }
 stats.exactDuplicateSets=duplicates.length;
 stats.unverifiedFamilies=out.filter(x=>x.verifiedPixelSizes===0).length;
 const transfers=downloadEvents(record);
 return {version:'5.5',families:out,duplicates,transfers,stats,
  limitations:[
   'Best observed rendition means only the largest file with VERIFIED ENCODED PIXELS in this saved capture.',
   'Same-host filename families are heuristic; unrelated assets may share apparent naming patterns.',
   'Hashes establish exact received-byte equality; perceptual similarity and ownership are separate questions.',
   'Browser download events are NOT attributed to images without exact received-byte evidence.',
   'No requests, URL guessing, protected downloads, watermarks changes, pixel reconstruction or credential testing.']};
}
function exportReport(record){return analyze(record);}
root.THIQuality={analyze,exportReport,downloadEvents};
if(typeof module!=='undefined'&&module.exports)module.exports=root.THIQuality;
})(typeof self!=='undefined'?self:globalThis);
