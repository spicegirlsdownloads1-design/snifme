/* v3.1 metadata fingerprint inspector. Never decode, persist or forward metadata values.
   Read-only parsing of image buffers already obtained from Chrome DevTools. */
(function(root){
'use strict';
const MAX_PART=256*1024, MAX_TOTAL=4*1024*1024;
function parse(data){
 const b=data instanceof Uint8Array?data:new Uint8Array(0);
 const blocks=[], seen=new Set();
 const add=(kind,start,length)=>{
  if(!['EXIF','XMP','IPTC','ICC','C2PA'].includes(kind)||!Number.isSafeInteger(start)||!Number.isSafeInteger(length)||length<1||length>MAX_PART||start<0||start+length>b.length)return;
  const key=kind+':'+start;if(seen.has(key)||blocks.length>=16)return;
  seen.add(key); blocks.push({kind,start,length});
 };
 const ascii=(off,size)=>{let out='';for(let j=off;j<off+size&&j<b.length;j++)out+=String.fromCharCode(b[j]);return out;};
 if(b.length<12||b.length>MAX_TOTAL)return blocks;
 // JPEG segments; skip compressed image data rather than scanning arbitrary pixels for strings.
 if(b[0]===0xff&&b[1]===0xd8){
  let i=2;
  while(i+4<=b.length){
   if(b[i]!==0xff)break;
   const marker=b[i+1];i+=2;
   if(marker===0xd9||marker===0xda)break;
   if(marker===0xff)continue;
   if(marker===0x01||(marker>=0xd0&&marker<=0xd7))continue;
   const segmentLength=(b[i]<<8)|b[i+1];
   if(segmentLength<2||i+segmentLength>b.length)break;
   const start=i+2,n=segmentLength-2;
   const prefix=ascii(start,Math.min(n,90));
   if(marker===0xe1&&prefix.startsWith('Exif\u0000\u0000'))add('EXIF',start,n);
   else if(marker===0xe1&&prefix.startsWith('http://ns.adobe.com/xap/1.0/'))add('XMP',start,n);
   else if(marker===0xed&&prefix.startsWith('Photoshop 3.0'))add('IPTC',start,n);
   else if(marker===0xe2&&prefix.startsWith('ICC_PROFILE'))add('ICC',start,n);
   else if((marker===0xeb||marker===0xe2)&&/^(?:JUMBF|c2pa)/i.test(prefix))add('C2PA',start,n);
   i+=segmentLength;
  }
 } else if(ascii(0,8)==='\x89PNG\r\n\x1a\n'){
  let i=8;
  while(i+12<=b.length){
   const n=(((b[i]<<24)>>>0)+(b[i+1]<<16)+(b[i+2]<<8)+b[i+3])>>>0;
   const type=ascii(i+4,4);if(n>MAX_TOTAL||i+12+n>b.length)break;
   if(['eXIf','iTXt','tEXt','zTXt','iCCP','caBX'].includes(type)){
    // Hash whole compressed/text chunk; do not decode or expose its contents.
    add(type==='eXIf'?'EXIF':type==='iCCP'?'ICC':type==='caBX'?'C2PA':'XMP',i+8,n);
   }
   i+=12+n;if(type==='IEND')break;
  }
 } else if(ascii(0,4)==='RIFF'&&ascii(8,4)==='WEBP'){
  let i=12;
  while(i+8<=b.length){
   const type=ascii(i,4);const n=(b[i+4]+(b[i+5]<<8)+(b[i+6]<<16)+((b[i+7]<<24)>>>0))>>>0;
   if(n>MAX_TOTAL||i+8+n>b.length)break;
   if(['EXIF','XMP ','ICCP','C2PA'].includes(type))add(type==='XMP '?'XMP':type==='ICCP'?'ICC':type,i+8,n);
   i+=8+n+(n%2);
  }
 }
 return blocks;
}
async function fingerprint(bytes,digest){
 const blocks=parse(bytes),results=[];
 if(typeof digest!=='function')throw new Error('SHA-256 digest function required');
 for(const b of blocks){
  const hash=await digest(bytes.subarray(b.start,b.start+b.length));
  if(/^[a-f0-9]{64}$/i.test(hash))results.push({kind:b.kind,sha256:hash.toLowerCase()});
 }
 return results.slice(0,16);
}
root.THIMetadata={parse,fingerprint};
if(typeof module!=='undefined'&&module.exports)module.exports=root.THIMetadata;
})(typeof self!=='undefined'?self:globalThis);
