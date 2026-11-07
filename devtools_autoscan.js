/* Automatic, bounded, passive scanning of already-loaded DevTools responses.
 * Never fetches resources, tests credentials or stores raw bodies/tokens.
 * Scans only on a captured tab with its DevTools window open. */
'use strict';
(()=>{
 const tabId=chrome.devtools.inspectedWindow.tabId;
 const MAX_BODY=2*1024*1024;
 const CHUNK=420000,OVERLAP=512;
 let sessionStart='';
 let progressTimer=null;
 let queue=null;
 function eligible(request){
  const url=request.request?.url||'',status=request.response?.status||0;
  if(!/^https?:\/\//i.test(url)||status<200||status>=300)return '';
  if(!['GET','POST'].includes(request.request?.method||''))return '';
  const mime=(request.response?.content?.mimeType||'').split(';')[0].toLowerCase();
  const path=(()=>{try{return new URL(url).pathname;}catch{return '';}})();
  return /\.m?js$/i.test(path)?'javascript':/\.(?:html?|xhtml)$/i.test(path)?'html':/\.css$/i.test(path)?'css':/\.json$/i.test(path)?'json':
   /(?:javascript|ecmascript)/.test(mime)?'javascript':/html/.test(mime)?'html':/css/.test(mime)?'css':/(?:json|\+json)/.test(mime)?'json':/(?:xml|\+xml)/.test(mime)?'xml':'';
 }
 function getContent(request){
   return new Promise((resolve,reject)=>{
     let done=false;
     const end=(fn,v)=>{if(done)return;done=true;clearTimeout(timeout);fn(v);};
     const timeout=setTimeout(()=>end(reject,new Error('timeout')),14000);
     try{request.getContent((body,encoding)=>end(resolve,{body,encoding}));}
     catch(e){end(reject,e);}
   });
 }
 async function indicatorsInChunks(body,source){
  const results=[],dedupe=new Set(),transientMatches=[];
  const newlineOffsets=[]; for(let i=0;i<body.length;i++)if(body.charCodeAt(i)===10)newlineOffsets.push(i);
  const position=offset=>{let low=0,high=newlineOffsets.length;while(low<high){const mid=(low+high)>>1;if(newlineOffsets[mid]<offset)low=mid+1;else high=mid;}return {line:low+1,column:offset-(low?newlineOffsets[low-1]+1:0)+1};};
  for(let start=0;start<body.length;start+=CHUNK-OVERLAP){
   const piece=body.slice(start,start+CHUNK);
   for(const finding of THI.secretIndicators(piece,source,raw=>{
      transientMatches.push({...raw,offset:raw.offset+start});
   })){ 
     const offset=(finding.offset||0)+start;
     const key=finding.type+'|'+offset;
     if(dedupe.has(key))continue;
     dedupe.add(key);results.push({...finding,source,offset,...position(offset)});
     if(results.length>=100)break;
   }
  }
  // Fingerprints are HMACs, never unkeyed hashes. Raw candidates exist only
  // briefly in the isolated DevTools context and are discarded before messaging.
  if(typeof THISecretFingerprint!=='undefined'){
    const index=new Map(transientMatches.map(x=>[x.type+'|'+x.offset,x.value]));
    for(const item of results){
      const value=item.type==='Private key material'?undefined:index.get(item.type+'|'+item.offset);
      if(value===undefined)continue;
      const signed=await THISecretFingerprint.fingerprint(value,item.type,source,chrome.storage?.local,typeof crypto!=='undefined'?crypto:null);
      if(signed)Object.assign(item,signed);
    }
    index.clear();
  }
  transientMatches.length=0;
  return results.slice(0,100);
 }
 let lastStats=null;
 const flush=()=>{
   progressTimer=null;
   if(!lastStats||!sessionStart)return;
   void chrome.runtime.sendMessage({type:'AUTO_SCAN_PROGRESS',tabId,startedAt:sessionStart,stats:lastStats}).catch(()=>{});
 };
 const changes=(stats,expectedStart)=>{
   if(sessionStart!==expectedStart)return; // Ignore metrics from a previous capture.
   lastStats=stats;
   const idle=!stats.running&&!stats.queued;
   if(progressTimer!==null){
     if(!idle)return;
     clearTimeout(progressTimer);
   }
   progressTimer=setTimeout(flush,idle?60:400);
 };
 function newQueue(startedAt){
   if(progressTimer!==null){clearTimeout(progressTimer);progressTimer=null;}
   lastStats=null;
   return THIAutoQueue.create({onChange:s=>changes(s,startedAt),maxConcurrent:3,maxQueued:600,maxSeen:1500,worker:async item=>{
     let permission;
     try{permission=await chrome.runtime.sendMessage({type:'GET_AUTO_SCAN_PERMISSION',tabId});}
     catch{return {status:'permissionBlocked'};}
     if(!permission?.ok||!permission.enabled||permission.startedAt!==item.startedAt)return {status:'permissionBlocked'};
     let result;
     try{result=await getContent(item.request);}catch(e){return {status:e?.message==='timeout'?'timeout':'unavailable'};}
     const {body,encoding}=result;
     const decoded=THIResourceDecoder.decode(body,encoding,item.request.response?.content?.mimeType||'',MAX_BODY);
     if(decoded.status!=='decoded')return {status:decoded.status};
     const textBody=decoded.text;
     const url=THI.sanitizedUrl(item.request.request.url);
     if(!url)return {status:'unsupported'};
     const findings=await indicatorsInChunks(textBody,url);
     // A digest of full, already-delivered JavaScript bytes; never persist body text.
     let sha256='';
     if(item.kind==='javascript' && typeof crypto!=='undefined' && crypto.subtle && typeof TextEncoder!=='undefined'){
       try{const bytes=new TextEncoder().encode(textBody);
         const hash=await crypto.subtle.digest('SHA-256',bytes);
         sha256=[...new Uint8Array(hash)].map(n=>n.toString(16).padStart(2,'0')).join('');
       }catch{/* A missing digest is explicitly displayed as unverified. */}
     }
     // Neither raw file content nor unsanitized URL is sent to the background worker.
     let ack;
     // The Chrome webRequest record can commit a moment after DevTools delivers the
     // response. Retry only the already-extracted, redacted metadata; never refetch.
     for(let attempt=0;attempt<3;attempt++){
       try{ack=await chrome.runtime.sendMessage({type:'AUTO_RESOURCE_SCAN',tabId,startedAt:item.startedAt,
         payload:{url,kind:item.kind,byteCount:decoded.decodedBytes,sha256,findings}});}
       catch{return {status:'deliveryError'};}
       if(ack?.ok)break;
       if(ack?.error!=='Response was not recorded in this capture.'||attempt===2)break;
       await new Promise(resolve=>setTimeout(resolve,150*(attempt+1)));
     }
     if(!ack?.ok)return {status:ack?.error==='Response was not recorded in this capture.'?'unrecorded':'deliveryError'};
     return {status:'scanned',indicators:findings.length};
   }});
 }
 async function heartbeat(){
   try{
     const response=await chrome.runtime.sendMessage({type:'GET_AUTO_SCAN_PERMISSION',tabId});
     if(!response?.ok||!response.enabled||!response.startedAt)return;
     await chrome.runtime.sendMessage({type:'DEVTOOLS_HEARTBEAT',tabId,startedAt:response.startedAt});
   }catch{/* The DevTools context can outlive an extension reload. */}
 }
 // A heartbeat establishes only that the DevTools observer is alive.
 // It does not mean past resources were captured or scanned.
 if(typeof setInterval==='function'){
   setTimeout(()=>{void heartbeat();},1200);
   setInterval(()=>{void heartbeat();},12000);
 }
 chrome.devtools.network.onRequestFinished.addListener(async request=>{
   const kind=eligible(request);if(!kind)return;
   let permission;
   try{permission=await chrome.runtime.sendMessage({type:'GET_AUTO_SCAN_PERMISSION',tabId});}
   catch{return;}
   if(!permission?.ok||!permission.enabled||!permission.startedAt)return;
   const startedAt=permission.startedAt;
   // Stale async responses must never reset a newer capture's queue.
   if(sessionStart&&startedAt<sessionStart)return;
   if(!queue||startedAt!==sessionStart){sessionStart=startedAt;queue=newQueue(startedAt);}
   const key=String(request.request.url)+'|'+String(request.startedDateTime||'')+'|'+String(request.request.method||'GET');
   if((request.response?.content?.size||0)>MAX_BODY){queue.skip(key,'oversized');return;}
   queue.enqueue(key,{request,kind,startedAt});
 });
})();
