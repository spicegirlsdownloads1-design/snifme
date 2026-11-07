/* Same-origin iframe DOM summary, bounded and private by construction.
 * No network calls. Never reads cross-origin frame documents or srcdoc.
 * Callers supply the existing masked indicator detector. */
(function(root){'use strict';
const LIMIT_FRAMES=35, MAX_INLINE_CHARS=320000, MAX_INLINE_SCRIPT=90000;
function origin(value){try{const u=new URL(value);return /^https?:$/.test(u.protocol)?u.origin:'';}catch{return '';}}
function safeNumber(value,max){return Number.isSafeInteger(value)&&value>=0?Math.min(value,max):0;}
function cleanRow(row,owner){
 const status=String(row?.status||'');
 if(!['inspected','cross-origin','inaccessible','unsupported'].includes(status))return null;
 const index=safeNumber(row.index,1000);
 if(!index)return null;
 const rowOrigin=origin(row.origin);
 if(status==='inspected' && rowOrigin!==owner)return null;
 return {index,status,origin:rowOrigin||'',depth:Math.min(2,safeNumber(row.depth,2)),
  scriptReferences:safeNumber(row.scriptReferences,200),inlineScripts:safeNumber(row.inlineScripts,200),
  inspectedCharacters:safeNumber(row.inspectedCharacters,320000),images:safeNumber(row.images,2000),
  maskedIndicators:safeNumber(row.maskedIndicators,100),evidence:'same-origin DOM inspection'};
}
function inspect(doc,ownerOrigin,{indicators,urlInfo}={}){
 const owner=origin(ownerOrigin), rows=[], findings=[], scripts=[], documents=[];
 if(!owner||!doc||typeof indicators!=='function'||typeof urlInfo!=='function')return {rows,findings,scripts,documents};
 let used=0, number=0;
 const scan=(parent,depth)=>{
  if(depth>2||number>=LIMIT_FRAMES)return;
  let frames=[];try{frames=[...parent.querySelectorAll('iframe')].slice(0,LIMIT_FRAMES-number);}catch{return;}
  for(const frame of frames){
   if(number>=LIMIT_FRAMES)break;
   const index=++number;
   const raw=frame.getAttribute?.('src')||'';
   let candidate;
   try{candidate=raw&&!frame.hasAttribute?.('srcdoc')?new URL(raw,parent.baseURI||owner+'/'):null;}catch{candidate=null;}
   const srcOrigin=candidate&&/^https?:$/.test(candidate.protocol)?candidate.origin:'';
   let status=!srcOrigin?'unsupported':srcOrigin!==owner?'cross-origin':'inaccessible';
   const row={index,status,origin:srcOrigin,depth,scriptReferences:0,inlineScripts:0,inspectedCharacters:0,images:0,maskedIndicators:0};
   // In particular, do NOT touch contentDocument for a cross-origin frame.
   if(srcOrigin!==owner){rows.push(row);continue;}
   let child=null;
   try{if(frame.contentWindow?.location?.origin===owner)child=frame.contentDocument||null;}catch{}
   if(!child){rows.push(row);continue;}
   row.status='inspected';documents.push(child);
   try{row.images=Math.min(2000,child.images?.length||0);}catch{}
   let children=[];try{children=[...child.querySelectorAll('script')].slice(0,80);}catch{}
   for(let n=0;n<children.length;n++){
    const node=children[n];
    if(node.hasAttribute?.('src')){
     const info=urlInfo(node.getAttribute('src'),child.baseURI||owner+'/');
     if(info){scripts.push({url:info.url,signedQuery:!!info.signedQuery});row.scriptReferences++;}
     continue;
    }
    const data=String(node.textContent||'');
    if(!data||data.length>MAX_INLINE_SCRIPT||used+data.length>MAX_INLINE_CHARS)continue;
    used+=data.length;row.inspectedCharacters+=data.length;row.inlineScripts++;
    const source=`same-origin frame ${index} inline script ${n+1}`;
    for(const x of indicators(data,source).slice(0,20)){
     if(findings.length>=80)break;
     const prefix=data.slice(0,x.offset||0),lines=prefix.split('\n');
     findings.push({...x,source,line:lines.length,column:(lines.at(-1)?.length||0)+1});row.maskedIndicators++;
    }
   }
   rows.push(row);
   scan(child,depth+1);
  }
 };
 scan(doc,1);
 return {rows,findings,scripts,documents};
}
const api={origin,cleanRow,inspect};root.THIFrameScope=api;
if(typeof module!=='undefined'&&module.exports)module.exports=api;
})(typeof self!=='undefined'?self:globalThis);
