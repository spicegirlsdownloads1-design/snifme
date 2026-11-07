/* v4.6: site-scoped HMAC fingerprints of *already-detected* values.
   Raw matches never leave the DevTools context, no network or credential tests. */
(function(root){'use strict';
 const STORAGE_KEY='thi-v46-private-fingerprint-key';
 let cached=null;
 const hex=a=>Array.from(a,n=>n.toString(16).padStart(2,'0')).join('');
 const unhex=s=>new Uint8Array((s.match(/../g)||[]).map(x=>parseInt(x,16)));
 async function keyFor(storage,api){
   if(cached)return cached;
   if(!storage?.get||!storage?.set||!api?.subtle||!api?.getRandomValues)return null;
   try{
     let obj=(await storage.get(STORAGE_KEY))[STORAGE_KEY];
     if(!obj||!/^([a-f0-9]{64})$/.test(obj.hex||'')||!/^[a-f0-9]{16}$/.test(obj.id||'')){
       const bytes=api.getRandomValues(new Uint8Array(32));
       obj={hex:hex(bytes),id:hex(api.getRandomValues(new Uint8Array(8)))};
       await storage.set({[STORAGE_KEY]:obj});
       // A concurrent inspector may have initialised the key. Re-read the winner.
       obj=(await storage.get(STORAGE_KEY))[STORAGE_KEY];
     }
     if(!obj||!/^[a-f0-9]{64}$/.test(obj.hex||'')||!/^[a-f0-9]{16}$/.test(obj.id||''))return null;
     const key=await api.subtle.importKey('raw',unhex(obj.hex),{name:'HMAC',hash:'SHA-256'},false,['sign']);
     cached={key,id:obj.id};return cached;
   }catch{return null;}
 }
 async function fingerprint(raw,type,source,storage,api){
   if(typeof raw!=='string'||raw.length<12||raw.length>500)return null;
   const k=await keyFor(storage,api);if(!k)return null;
   const origin=(()=>{try{return new URL(source).origin;}catch{return 'local';}})();
   const input=new TextEncoder().encode(origin+'\0'+String(type).slice(0,80)+'\0'+raw);
   const signed=await api.subtle.sign('HMAC',k.key,input);
   return {fingerprint:hex(new Uint8Array(signed)),fingerprintKeyId:k.id};
 }
 root.THISecretFingerprint={fingerprint};
 if(typeof module!=='undefined'&&module.exports)module.exports=root.THISecretFingerprint;
})(typeof self!=='undefined'?self:globalThis);
