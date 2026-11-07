/* v2.6: opt-in parsing of already-delivered specialist viewer manifests.
 * Never fetch a URL, save source XML/JSON, or generate tiles. */
'use strict';
(() => {
 const inspectedTabId=chrome.devtools.inspectedWindow.tabId;
 const LIMIT=256*1024;
 const completed=new Set();let active=0;
 chrome.devtools.network.onRequestFinished.addListener(request=>{
   void (async()=>{
     const url=request.request?.url||'',mime=(request.response?.content?.mimeType||'').split(';')[0];
     const classified=THIViewer.classifyUrl(url);
     if(!classified||!['manifest reference','image info reference','presentation reference'].includes(classified.kind))return;
     if(request.request?.method!=='GET'||request.response?.status!==200||
       (request.response?.content?.size||0)>LIMIT||active>=2||completed.has(url))return;
     const allowed=await chrome.runtime.sendMessage({type:'GET_VIEWER_PERMISSION',tabId:inspectedTabId});
     if(!allowed?.ok||!allowed.enabled)return;
     completed.add(url);active++;
     let done=false;const finish=()=>{if(done)return;done=true;clearTimeout(timer);active=Math.max(0,active-1);};
     const timer=setTimeout(finish,10000);
     try{request.getContent((text,encoding)=>{
       try{
         if(done||encoding==='base64'||typeof text!=='string'||text.length>LIMIT)return;
         const summary=THIViewer.parseManifest(text,mime,url);
         if(!summary)return;
         void chrome.runtime.sendMessage({type:'VIEWER_MANIFEST',tabId:inspectedTabId,payload:{url,summary}}).catch(()=>{});
       }catch{}finally{finish();}
     });}catch{finish();}
   })().catch(()=>{});
 });
})();
