/* Local-only HAR/file inspection. Never persists source text, HTTP headers or credential values.
 * Imported material is untrusted. Only explicit user-selected files are examined. */
(function(root){
 'use strict';
 const MAX_FILE=12*1024*1024,MAX_TEXT=2*1024*1024,MAX_FILES=40,MAX_TOTAL=40*1024*1024;
 const MAX_HAR_ENTRIES=1200,MAX_FINDINGS=150;
 const CHUNK=300000,OVERLAP=4096;
 const ALLOWED=/\.(?:js|mjs|cjs|json|jsonl|css|html?|xhtml|xml|txt)$/i;
 function kindFrom(name,mime){
   const path=String(name||'').split('?')[0].split('#')[0];
   if(/\.(?:m?js|cjs)$/i.test(path))return 'javascript';
   if(/\.css$/i.test(path))return 'css';
   if(/\.(?:html?|xhtml)$/i.test(path))return 'html';
   if(/\.(?:json|jsonl)$/i.test(path))return 'json';
   if(/\.xml$/i.test(path))return 'xml';
   if(/\.txt$/i.test(path))return 'text';
   const m=String(mime||'').toLowerCase();
   if(/javascript|ecmascript/.test(m))return 'javascript';
   if(/json/.test(m))return 'json';
   if(/html/.test(m))return 'html';
   if(/css/.test(m))return 'css';
   if(/xml/.test(m))return 'xml';
   if(m.startsWith('text/plain'))return 'text';
   return '';
 }
 function sourceName(i,kind){return `Imported ${kind||'resource'} #${i}`;}
 function location(text,offset){
   let line=1,column=1;for(let i=0;i<offset;i++){if(text.charCodeAt(i)===10){line++;column=1;}else column++;}
   return {line,column};
 }
 function scan(text,source,kind){
   if(typeof text!=='string'||text.length>MAX_TEXT)return {status:'oversized',findings:[],reason:'text exceeds 2 MiB limit'};
   const results=[],seen=new Set();
   for(let start=0;start<text.length;start+=CHUNK-OVERLAP){
     const chunk=text.slice(start,start+CHUNK);
     const raw=root.THI.secretIndicators(chunk,source);
     for(const r of raw){
       const offset=start+Number(r.offset||0),id=r.type+'|'+offset;
       if(seen.has(id))continue;seen.add(id);
       const pos=location(text,offset);
       // Do not export original matches, partial values, or surrounding source text.
       results.push({type:String(r.type).slice(0,70),masked:'[redacted]',severity:/private key|secret|github|gitlab|sendgrid|slack token|webhook|stripe secret/i.test(r.type)?'review':'informational',source,kind,offset,line:pos.line,column:pos.column});
       if(results.length>=MAX_FINDINGS)return {status:'scanned',findings:results,truncated:true};
     }
   }
   return {status:'scanned',findings:results,truncated:false};
 }
 function record(source,kind,status,bytes,reason='',findings=[],more={}){
   return {source,kind,status,bytes:Math.max(0,Number(bytes)||0),reason:String(reason).slice(0,100),findings, ...more};
 }
 function textFile(source,kind,text){
   if(!kind)return record(source,'unknown','unsupported',String(text||'').length,'not an eligible textual file');
   const outcome=scan(text,source,kind);
   return record(source,kind,outcome.status,text.length,outcome.reason||'',outcome.findings,{truncated:!!outcome.truncated});
 }
 function harObject(input){
   if(!input||typeof input!=='object'||!input.log||!Array.isArray(input.log.entries))throw new Error('Not a valid HAR 1.x log with entries');
   const entries=input.log.entries,records=[];
   const limit=Math.min(entries.length,MAX_HAR_ENTRIES);
   for(let i=0;i<limit;i++){
     const e=entries[i];
     if(!e||typeof e!=='object'){records.push(record(sourceName(i+1,'HAR'),'unknown','unavailable',0,'missing entry'));continue;}
     const response=e.response||{},content=response.content||{},req=e.request||{};
     const sanitized=root.THI.sanitizedUrl(String(req.url||''));
     // No HAR request headers, cookies, POST bodies, response headers, or query values are retained.
     const source=sanitized||sourceName(i+1,'HAR');
     const mime=String(content.mimeType||'');
     const kind=kindFrom(source,mime);
     if(!kind || !root.THIResourceDecoder.isTextMime(mime||'text/plain')){
       records.push(record(source,kind||'binary','unsupported',0,'non-text or unsupported MIME'));continue;
     }
     if(typeof content.text!=='string'){
       records.push(record(source,kind,'missingBody',0,'HAR entry has no embedded response body'));continue;
     }
     const result=root.THIResourceDecoder.decode(content.text,content.encoding||'',mime||'text/plain',MAX_TEXT);
     if(result.status!=='decoded'){
       records.push(record(source,kind,result.status,0,result.reason));continue;
     }
     records.push(textFile(source,kind,result.text));
   }
   if(entries.length>limit)records.push(record('HAR remainder','unknown','capacity',0,`${entries.length-limit} entries beyond ${MAX_HAR_ENTRIES} limit`,[],{skippedCount:entries.length-limit}));
   return records;
 }
 function summarize(records){
   const counts={total:0,scanned:0,missingBody:0,oversized:0,unsupported:0,unavailable:0,capacity:0,failed:0,findings:0,truncated:0};
   for(const r of records){
     counts.total+=r.skippedCount||1;
     if(counts[r.status]!==undefined)counts[r.status]+=(r.skippedCount||1);
     counts.findings+=r.findings?.length||0;
     if(r.truncated)counts.truncated++;
   }
   counts.excluded=counts.total-counts.scanned;
   counts.label=counts.total===0?'Nothing imported':counts.excluded||counts.truncated?'Partial — imported material only':'Provided resources scanned (not site-wide)';
   return counts;
 }
 function exportReport(records){
   // The export intentionally omits bodies, HAR headers, cookies and matched values.
   return {schema:'trufflehog-offline-v1',generatedAt:new Date().toISOString(),scope:'User-selected local files only; no website-wide coverage claim',summary:summarize(records),resources:records.map(r=>({source:r.source,kind:r.kind,status:r.status,bytes:r.bytes,reason:r.reason,truncated:!!r.truncated,skippedCount:r.skippedCount||1,findings:(r.findings||[]).map(f=>({type:f.type,masked:'[redacted]',severity:f.severity,source:f.source,line:f.line,column:f.column}))}))};
 }
 root.THIOffline={MAX_FILE,MAX_TEXT,MAX_FILES,MAX_TOTAL,MAX_HAR_ENTRIES,kindFrom,sourceName,scan,textFile,harObject,summarize,exportReport};
})(globalThis);
