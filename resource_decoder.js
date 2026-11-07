/* Response content decoding, limited to textual MIME types and strict byte bounds.
 * No network requests or decoding of binary media, secrets are never returned to storage. */
(function(root){
 'use strict';
 const MAX_BYTES=2*1024*1024;
 function isTextMime(mime){
   const m=String(mime||'').split(';',1)[0].trim().toLowerCase();
   return /^(?:text\/(?:javascript|ecmascript|plain|html|css|xml|csv|x-javascript)|application\/(?:javascript|x-javascript|ecmascript|json|ld\+json|manifest\+json|xml|[^/]+\+(?:json|xml)))$/.test(m);
 }
 function decode(body,encoding='',mime='text/plain',limit=MAX_BYTES){
   const max=Math.min(MAX_BYTES,Math.max(1,Number(limit)||MAX_BYTES));
   if(!isTextMime(mime))return {status:'unsupported',reason:'non-text MIME'};
   if(typeof body!=='string')return {status:'unavailable',reason:'missing text body'};
   if(!encoding||encoding==='utf8'||encoding==='utf-8'){
     if(body.length>max)return {status:'oversized',reason:'text exceeds limit'};
     return {status:'decoded',text:body,decodedBytes:body.length};
   }
   if(encoding!=='base64')return {status:'unsupported',reason:'unknown response encoding'};
   if(body.length>Math.ceil(max*4/3)+8)return {status:'oversized',reason:'encoded body exceeds limit'};
   if(!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(body))return {status:'unsupported',reason:'invalid base64'};
   try{
     if(typeof root.atob!=='function'||typeof root.TextDecoder!=='function')return {status:'unsupported',reason:'decoder unavailable'};
     const binary=root.atob(body);
     if(binary.length>max)return {status:'oversized',reason:'decoded body exceeds limit'};
     const bytes=new Uint8Array(binary.length);
     for(let i=0;i<binary.length;i++)bytes[i]=binary.charCodeAt(i);
     const text=new root.TextDecoder('utf-8',{fatal:true}).decode(bytes);
     return {status:'decoded',text,decodedBytes:bytes.length};
   }catch{return {status:'unsupported',reason:'invalid UTF-8 text'};}
 }
 root.THIResourceDecoder={decode,isTextMime,MAX_BYTES};
})(globalThis);
