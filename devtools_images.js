/* Separate opt-in analysis of image response bytes already captured by Chrome DevTools.
 * No new requests, no body storage, no cookies/headers, no protected-file retrieval. */
'use strict';
(() => {
  const tabId=chrome.devtools.inspectedWindow.tabId;
  const MAX_BYTES=4*1024*1024;
  const MAX_PER_SESSION=160;
  const MAX_INFLIGHT=2;
  const imageMime=/^image\/(?:jpeg|png|gif|webp|bmp|avif)$/i;
  const inspected=new Set();
  let inflight=0;
  const pending=new Set();
  function process(request) {
    const mime=(request.response?.content?.mimeType||'').split(';')[0];
    const url=request.request?.url||'';
    if(request.request?.method!=='GET'||!imageMime.test(mime)||!/^https?:\/\//i.test(url))return;
    if((request.response?.status||0)!==200)return;
    if((request.response?.content?.size||0)>MAX_BYTES)return;
    if(inspected.has(url)||pending.has(url)||inspected.size>=MAX_PER_SESSION||inflight>=MAX_INFLIGHT)return;
    pending.add(url);inflight++;
    // Concurrency slot remains held until getContent and SHA-256 have finished.
    let finished=false;
    const finish=()=>{if(finished)return;finished=true;clearTimeout(watchdog);pending.delete(url);inflight=Math.max(0,inflight-1);};
    const watchdog=setTimeout(finish,15000);
    void(async()=>{
      const allowed=await chrome.runtime.sendMessage({type:'GET_IMAGE_PERMISSION',tabId});
      if(!allowed?.ok||!allowed.enabled){finish();return;}
      inspected.add(url);
      try {
        request.getContent((content,encoding)=>{
          void(async()=>{
            try {
              if(encoding!=='base64'||typeof content!=='string'||content.length>Math.ceil(MAX_BYTES*4/3)+16)return;
              const raw=atob(content);
              if(!raw.length||raw.length>MAX_BYTES)return;
              const bytes=Uint8Array.from(raw,c=>c.charCodeAt(0));
              const digest=await crypto.subtle.digest('SHA-256',bytes);
              const sha256=Array.from(new Uint8Array(digest),n=>n.toString(16).padStart(2,'0')).join('');
              const size=THIHeader.dimensions(bytes);
              // Explicit opt-in. Only SHA-256 of exact embedded metadata blocks and
              // bounded block-type labels leave this DevTools process.
              let metadata=[];
              try{
                const consent=await chrome.runtime.sendMessage({type:'GET_METADATA_PERMISSION',tabId});
                if(consent?.ok&&consent.enabled&&typeof THIMetadata!=='undefined'){
                  metadata=await THIMetadata.fingerprint(bytes,async part=>{
                    const rawHash=await crypto.subtle.digest('SHA-256',part);
                    return Array.from(new Uint8Array(rawHash),n=>n.toString(16).padStart(2,'0')).join('');
                  });
                }
              }catch{/* no metadata consent or analysis unavailable */}
              let visual=null;
              try {
                const consent=await chrome.runtime.sendMessage({type:'GET_VISUAL_PERMISSION',tabId});
                if(consent?.ok&&consent.enabled&&typeof THIVisual!=='undefined'){
                  const blob=new Blob([bytes],{type:mime});
                  const bitmap=await createImageBitmap(blob);
                  try{
                    const canvas=document.createElement('canvas');canvas.width=96;canvas.height=96;
                    const context=canvas.getContext('2d',{willReadFrequently:true});
                    if(context){context.drawImage(bitmap,0,0,96,96);
                      const data=context.getImageData(0,0,96,96);
                      visual=THIVisual.fingerprint(data.data,96,96);}
                  }finally{bitmap.close();}
                }
              }catch{/* Unsupported image codec, canvas, permission or animated source. */}
              await chrome.runtime.sendMessage({type:'VERIFIED_IMAGE',tabId,
                payload:{url,sha256,byteLength:bytes.length,width:size.width,height:size.height,format:size.format,mime,metadata,visual}});
            }catch{/* Unsupported encoding, unavailable response, or extension reload. */}
            finally{finish();}
          })();
        });
      }catch{finish();}
    })().catch(()=>finish());
  }
  chrome.devtools.network.onRequestFinished.addListener(process);
})();
