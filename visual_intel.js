/* v3.4: bounded, offline perceptual image evidence. No images or pixels retained.
 * A 64-bit difference hash is a candidate-match heuristic, NOT evidence of
 * identical source files, common ownership, licence, or accessible masters. */
(function(root){
'use strict';
const CROPS={center:[.12,.12,.76,.76],centerSmall:[.25,.25,.5,.5],left:[0,0,.65,1],right:[.35,0,.65,1],top:[0,0,1,.65],bottom:[0,.35,1,.65]};
const hex64=/^[a-f0-9]{16}$/i;
function sampleHash(pixels,width,height,rect=[0,0,1,1]){
 if(!(pixels instanceof Uint8ClampedArray||pixels instanceof Uint8Array)||!Number.isInteger(width)||!Number.isInteger(height)||width<9||height<8||width>512||height>512||pixels.length!==width*height*4)return '';
 const [rx,ry,rw,rh]=rect; if([rx,ry,rw,rh].some(x=>!Number.isFinite(x))||rx<0||ry<0||rw<=0||rh<=0||rx+rw>1.000001||ry+rh>1.000001)return '';
 const v=[];
 for(let y=0;y<8;y++)for(let x=0;x<9;x++){
  const px=Math.min(width-1,Math.floor((rx+rw*(x+.5)/9)*width));
  const py=Math.min(height-1,Math.floor((ry+rh*(y+.5)/8)*height));
  const at=(py*width+px)*4;
  v.push(Math.round((pixels[at]*299+pixels[at+1]*587+pixels[at+2]*114)/1000));
 }
 let bits=0n;
 for(let y=0;y<8;y++)for(let x=0;x<8;x++)bits=(bits<<1n)|BigInt(v[y*9+x]>v[y*9+x+1]?1:0);
 return bits.toString(16).padStart(16,'0');
}
function fingerprint(pixels,w,h){
 const full=sampleHash(pixels,w,h); if(!full)return null;
 const crops={};for(const [key,rect] of Object.entries(CROPS))crops[key]=sampleHash(pixels,w,h,rect);
 return {algorithm:'dhash64-v1',full,crops};
}
function validate(v){
 if(!v||v.algorithm!=='dhash64-v1'||!hex64.test(v.full))return null;
 const crops={};for(const key of Object.keys(CROPS))if(hex64.test(v.crops?.[key]||''))crops[key]=v.crops[key].toLowerCase();
 return {algorithm:'dhash64-v1',full:v.full.toLowerCase(),crops};
}
function distance(a,b){
 if(!hex64.test(a||'')||!hex64.test(b||''))return 64;
 let n=BigInt('0x'+a)^BigInt('0x'+b),d=0;
 while(n){n&=n-1n;d++;}return d;
}
function cleanURL(raw){try{const u=new URL(raw);if(!/^https?:$/.test(u.protocol)||u.username||u.password)return '';u.search='';u.hash='';return u.href.slice(0,700);}catch{return '';}}
function candidate(a,b){
 const va=validate(a.visual),vb=validate(b.visual);
 if(!va||!vb)return null;
 if(a.sha256&&b.sha256&&a.sha256===b.sha256)return null; // Already reported as exact bytes.
 // Flat or almost-monotone thumbnails have low-information dHashes and cause false positives.
 const informative=h=>{const count=BigInt('0x'+h).toString(2).replace(/0/g,'').length;return count>=7&&count<=57;};
 if(!informative(va.full)||!informative(vb.full))return null;
 const primary=distance(va.full,vb.full);
 let result=null;
 const ar1=(a.width||0)/(a.height||1),ar2=(b.width||0)/(b.height||1);
 const ratioKnown=ar1>0&&ar2>0;const ratioDelta=ratioKnown?Math.abs(Math.log(ar1/ar2)):null;
 if(primary<=6&&(!ratioKnown||ratioDelta<0.12))result={kind:'Similar composition',distance:primary,confidence:'Visual candidate',details:'Full-image dHash resembles another received image; manual review required.'};
 // Only call something a possible crop when the source/target aspect ratios differ
 // or a crop signature is materially closer than the full-image signature.
 if(primary>3){
  for(const [key,h] of Object.entries(va.crops)){
   const d=distance(h,vb.full);
   if(d<=5&&d+3<=primary&&(ratioDelta===null||ratioDelta>=0.07||d<=2)&&(!result||d<result.distance))result={kind:'Possible crop',distance:d,confidence:'Visual candidate',details:`${key} region of first image resembles second image; heuristic only.`};
  }
  for(const [key,h] of Object.entries(vb.crops)){
   const d=distance(h,va.full);
   if(d<=5&&d+3<=primary&&(ratioDelta===null||ratioDelta>=0.07||d<=2)&&(!result||d<result.distance))result={kind:'Possible crop',distance:d,confidence:'Visual candidate',details:`${key} region of second image resembles first image; heuristic only.`};
  }
 }
 return result;
}
function compare(a,b,limit=70){
 const av=(a||[]).filter(x=>validate(x.visual)).slice(0,140),bv=(b||[]).filter(x=>validate(x.visual)).slice(0,140);
 const rows=[];let evaluated=0;for(const left of av)for(const right of bv){
  if(left.url===right.url)continue;
  evaluated++;const c=candidate(left,right);if(!c)continue;
  rows.push({...c,left:cleanURL(left.url),right:cleanURL(right.url),leftDimensions:left.width&&left.height?`${left.width} × ${left.height}`:'Unknown',rightDimensions:right.width&&right.height?`${right.width} × ${right.height}`:'Unknown'});
 }
 rows.sort((a,b)=>a.distance-b.distance);return {rows:rows.slice(0,limit),total:rows.length,evaluated,truncated:rows.length>limit||a.length>140||b.length>140};
}
function within(record){const v=record?.verifications||[];const rows=[];
 for(let i=0;i<Math.min(v.length,180);i++)for(let j=i+1;j<Math.min(v.length,180);j++){
  const c=candidate(v[i],v[j]);if(c)rows.push({...c,left:cleanURL(v[i].url),right:cleanURL(v[j].url)});
 }
 return rows.sort((a,b)=>a.distance-b.distance).slice(0,80);
}
function metadataGroups(record){const index=new Map();
 for(const v of (record?.verifications||[]).slice(0,500))for(const m of (v.metadata||[])){
  if(!['EXIF','IPTC','XMP','ICC','C2PA'].includes(m.kind)||!/^[a-f0-9]{64}$/.test(m.sha256||''))continue;
  const key=m.kind+':'+m.sha256;
  if(!index.has(key))index.set(key,new Set());index.get(key).add(cleanURL(v.url));
 }
 return [...index.entries()].filter(([,s])=>s.size>1).slice(0,100).map(([k,s])=>({kind:k.split(':')[0],fingerprint:k.split(':')[1].slice(0,16)+'…',images:s.size,urls:[...s].join(' · '),assessment:'Identical metadata BLOCK; may be boilerplate, not proof of identical photographs.'}));
}
function matrix(assets){const groups=new Map();
 for(const a of assets){if(!a.family)continue;let group=groups.get(a.family);if(!group){group=[];groups.set(a.family,group)}group.push(a);}
 const out=[];
 for(const [family,list] of groups){
  const widths=list.map(x=>x.encodedWidth).filter(Number.isInteger),heights=list.map(x=>x.encodedHeight).filter(Number.isInteger);
  const ratios=new Set(list.filter(x=>x.encodedWidth&&x.encodedHeight).map(x=>(x.encodedWidth/x.encodedHeight).toFixed(2)));
  out.push({family,observed:list.length,verified:list.filter(x=>!!x.sha256).length,visual:list.filter(x=>!!x.visualHash).length,
   formats:[...new Set(list.map(x=>x.format||x.mime).filter(Boolean))].join(', ')||'Unknown',
   resolutionRange:widths.length?`${Math.min(...widths)}–${Math.max(...widths)} × ${Math.min(...heights)}–${Math.max(...heights)}`:'Unverified',
   aspectRatios:[...ratios].join(' · ')||'Unverified',cropClue:ratios.size>1?'Different aspect ratios observed (not proof of cropping)':'No verified aspect-ratio difference',
   urls:list.slice(0,12).map(x=>cleanURL(x.url)).join(' · ')});
 }
 return out.sort((a,b)=>b.observed-a.observed).slice(0,250);
}
root.THIVisual={sampleHash,fingerprint,validate,distance,candidate,compare,within,metadataGroups,matrix,CROPS};
if(typeof module!=='undefined'&&module.exports)module.exports=root.THIVisual;
})(typeof self!=='undefined'?self:globalThis);
