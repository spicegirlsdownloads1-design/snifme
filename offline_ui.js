'use strict';
const node=id=>document.getElementById(id);
let results=[];
const text=(tag,value,className='')=>{const n=document.createElement(tag);n.textContent=String(value);n.className=className;return n;};
function status(message,error=false){node('status').textContent=message;node('status').className='offline-status '+(error?'offline-danger':'');}
function addRow(target,cells){const tr=document.createElement('tr');for(const cell of cells)tr.appendChild(text('td',cell));target.appendChild(tr);}
function render(){
 const summary=THIOffline.summarize(results);
 const metrics=node('metrics');metrics.replaceChildren();
 for(const [value,label] of [[summary.total,'Resources represented'],[summary.scanned,'Text resources scanned'],[summary.excluded,'Unscanned / excluded'],[summary.findings,'Masked indicators']]){
   const div=text('div','','offline-metric');div.appendChild(text('strong',value));div.appendChild(text('span',label));metrics.appendChild(div);
 }
 const resources=node('resources'),findings=node('findings');resources.replaceChildren();findings.replaceChildren();
 for(const r of results){
   addRow(resources,[r.source,r.kind,r.status,r.bytes?new Intl.NumberFormat().format(r.bytes)+' chars':'—',r.findings?.length||0,r.reason||(r.truncated?'Finding limit reached':'—')]);
   for(const f of r.findings||[])addRow(findings,[f.source,f.type,f.severity,f.line,f.column,'[redacted]']);
 }
 if(!results.length){addRow(resources,['No imported resources','—','—','—','—','—']);addRow(findings,['No indicators','—','—','—','—','—']);}
 else if(!summary.findings)addRow(findings,['No indicators identified in inspected files','—','—','—','—','—']);
 node('json').disabled=node('csv').disabled=!results.length;
}
async function inspect(){
 const files=[...(node('files').files||[])];if(!files.length){status('Select at least one file.',true);return;}
 if(files.length>THIOffline.MAX_FILES){status(`Choose at most ${THIOffline.MAX_FILES} files.`,true);return;}
 const totalBytes=files.reduce((sum,f)=>sum+f.size,0);
 if(totalBytes>THIOffline.MAX_TOTAL){status('Selected files exceed the 40 MiB total limit.',true);return;}
 node('run').disabled=true;results=[];render();
 try{
  for(let i=0;i<files.length;i++){
    const file=files[i],alias=THIOffline.sourceName(i+1,'file');
    if(file.size>THIOffline.MAX_FILE){results.push({source:alias,kind:'file',status:'oversized',bytes:file.size,reason:'file exceeds 12 MiB',findings:[]});continue;}
    status(`Inspecting ${i+1}/${files.length} local file(s)…`);
    // File contents remain in this page and are not uploaded or stored.
    const content=await file.text();
    const isHAR=/\.har$/i.test(file.name);
    const kind=THIOffline.kindFrom(file.name,'');
    if(isHAR||/\.(?:json)$/i.test(file.name)&&content.trimStart().startsWith('{')){
      let parsed;try{parsed=JSON.parse(content);}catch(e){if(isHAR){results.push({source:alias,kind:'HAR',status:'failed',bytes:file.size,reason:'Invalid HAR JSON',findings:[]});continue;}}
      if(parsed?.log?.entries){results.push(...THIOffline.harObject(parsed));continue;}
      if(isHAR){results.push({source:alias,kind:'HAR',status:'failed',bytes:file.size,reason:'Not a HAR log',findings:[]});continue;}
    }
    results.push(THIOffline.textFile(alias,kind,content));
    // Provide UI updates during large batches, without background work.
    if(i%5===4){render();await new Promise(resolve=>setTimeout(resolve,0));}
  }
  const s=THIOffline.summarize(results);status(`${s.label} · ${s.scanned} scanned · ${s.excluded} not scanned · ${s.findings} masked indicators. Imported files only.`);
 }catch(e){status('Local file inspection failed: '+(e.message||'unknown error'),true);}
 finally{render();node('run').disabled=false;}
}
function save(name,body,type){
 const blob=new Blob([body],{type}),url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),4000);
}
function csvSafe(v){const s=String(v??'');return '"'+(/^[\s]*[=+@-]/.test(s)?"'"+s:s).replaceAll('"','""')+'"';}
node('run').addEventListener('click',()=>{void inspect();});
node('reset').addEventListener('click',()=>{node('files').value='';results=[];render();status('Local results cleared. No records were saved.');});
node('json').addEventListener('click',()=>{const out=THIOffline.exportReport(results);save('trufflehog-offline-redacted.json',JSON.stringify(out,null,2),'application/json');});
node('csv').addEventListener('click',()=>{
 const header=['source','kind','status','bytes','reason','indicator_type','severity','line','column'];
 const rows=[header];for(const r of results){if(!r.findings?.length)rows.push([r.source,r.kind,r.status,r.bytes,r.reason,'','','','']);else for(const f of r.findings)rows.push([r.source,r.kind,r.status,r.bytes,r.reason,f.type,f.severity,f.line,f.column]);}
 save('trufflehog-offline-redacted.csv','\uFEFF'+rows.map(row=>row.map(csvSafe).join(',')).join('\r\n'),'text/csv;charset=utf-8');
});
render();
