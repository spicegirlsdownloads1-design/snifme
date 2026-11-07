/* Trufflehog v7.7: local, read-only byte-range metadata observations from reviewed HARs.
 * Full URLs, ETags, timestamps, byte offsets and body content are used transiently
 * only, and NEVER returned/exported. No response payloads are reassembled or fetched.
 */
(function(root){'use strict';
const MAX=12000;
const SIGNALS=Object.freeze([
 'Range request header present',
 'If-Range request header present',
 'Accept-Ranges: bytes response',
 'Accept-Ranges: none response',
 '206 valid single-part Content-Range with known total',
 '206 valid single-part Content-Range with unknown total',
 '206 multipart/byteranges response (body not inspected)',
 '206 invalid or missing Content-Range',
 '206 Content-Length disagrees with declared single-part range',
 'Range request answered with HTTP 200',
 '416 with unsatisfied Content-Range',
 '416 without valid unsatisfied Content-Range',
 '206 without strong ETag (not grouped)',
 'Overlapping declared spans in stable-tag groups'
]);
const SPANS=Object.freeze([
 'Strong-ETag group: 0–24% of declared span',
 'Strong-ETag group: 25–49% of declared span',
 'Strong-ETag group: 50–74% of declared span',
 'Strong-ETag group: 75–99% of declared span',
 'Strong-ETag group: 100% of declared span'
]);
const LIMITATIONS=Object.freeze([
 'Only HTTP response-header claims are compared. A 206, even with 100% declared range span, is NOT proof of payload receipt, verified bytes, file reconstruction, a completed download, or permission to access an original.',
 'Content-Range offsets and ETags are parsed transiently, but are never exported. The grouping requires the exact same original URL and strong ETag; missing validators and newly signed URLs remain ungrouped.',
 'Multipart/byteranges bodies are never inspected or reconstructed. A 206 Content-Length describes transferred representation content, not the total image or media file size.',
 'HAR exports may omit redirects, bodies, request headers and cache hits. The number of observed parts can change solely because of browser coverage or user actions.',
 'Different complete lengths, encodings, URLs, ETags or authorisation contexts prevent a confident identity claim. Stable strong ETags are evidence, not cryptographic proof that the browser received the bytes.',
 'All outputs use fixed labels, counts and rates only. No host, asset ID, filename, URL, signing material, cookie, payload, range offset, validator or exact timestamp is returned.'
]);
function headers(raw){const out=new Map();if(!Array.isArray(raw))return out;for(const h of raw.slice(0,150)){
 const k=typeof h?.name==='string'?h.name.toLowerCase().slice(0,96):'';
 if(/^[a-z0-9-]{1,96}$/.test(k)&&!out.has(k))out.set(k,typeof h.value==='string'?h.value.slice(0,8192):'');
}return out;}
function http(raw){try{if(typeof raw!=='string'||raw.length>8192)return null;const u=new URL(raw);return u.protocol==='http:'||u.protocol==='https:'?u:null;}catch{return null;}}
function unsignedInteger(raw){if(typeof raw!=='string'||!/^(0|[1-9][0-9]{0,15})$/.test(raw))return null;const n=Number(raw);return Number.isSafeInteger(n)&&n>=0?n:null;}
function range(raw){if(typeof raw!=='string'||raw.length>128)return null;
 const known=/^bytes\s+(\d+)-(\d+)\/(\d+)$/i.exec(raw.trim());
 const unknown=/^bytes\s+(\d+)-(\d+)\/\*$/i.exec(raw.trim());
 const m=known||unknown;if(!m)return null;
 const first=unsignedInteger(m[1]),last=unsignedInteger(m[2]),total=known?unsignedInteger(m[3]):null;
 if(first===null||last===null||last<first||(known&&(total===null||total<=last)))return null;
 return {first,last,total};
}
function unsatisfied(raw){const m=/^bytes\s+\*\/(\d+)$/i.exec(String(raw||'').trim());return !!(m&&unsignedInteger(m[1])!==null);}
function bins(pct){if(pct<25)return 0;if(pct<50)return 1;if(pct<75)return 2;if(pct<100)return 3;return 4;}
function audit(har){
 const entries=har?.log?.entries;
 if(!Array.isArray(entries))throw Error('HAR must contain log.entries');
 if(entries.length>MAX)throw Error('HAR exceeds 12,000-entry limit');
 const values=Object.fromEntries(SIGNALS.map(s=>[s,0]));
 const buckets=SPANS.map(category=>({category,count:0}));
 const groups=new Map(); // raw URL, strong ETag, content coding and total in memory only
 const totals={totalEntries:entries.length,inspectedHttp:0,excludedEntries:0,partialResponses:0,validRangeResponses:0,rangeResponsesWithoutStrongValidator:0,stableTagGroups:0,groupsWithOverlap:0,multipartResponses:0};
 const count=s=>{values[s]++;};
 for(const e of entries){
  const req=e?.request,res=e?.response,u=http(req?.url);
  if(!u||!res||typeof res!=='object'){totals.excludedEntries++;continue;}
  totals.inspectedHttp++;
  const rq=headers(req?.headers),rs=headers(res.headers),status=Number(res.status);
  const hasRange=rq.has('range'),hasIfRange=rq.has('if-range');
  if(hasRange)count(SIGNALS[0]);if(hasIfRange)count(SIGNALS[1]);
  const ar=String(rs.get('accept-ranges')||'').trim().toLowerCase();
  if(ar==='bytes')count(SIGNALS[2]);else if(ar==='none')count(SIGNALS[3]);
  if(hasRange&&status===200)count(SIGNALS[9]);
  if(status===416){count(unsatisfied(rs.get('content-range'))?SIGNALS[10]:SIGNALS[11]);continue;}
  if(status!==206)continue;
  totals.partialResponses++;
  const mime=String(rs.get('content-type')||res.content?.mimeType||'').trim().toLowerCase();
  if(/^multipart\/byteranges(?:\s*;|\s*$)/.test(mime)){count(SIGNALS[6]);totals.multipartResponses++;continue;}
  const parsed=range(rs.get('content-range'));
  if(!parsed){count(SIGNALS[7]);continue;}
  totals.validRangeResponses++;
  count(parsed.total===null?SIGNALS[5]:SIGNALS[4]);
  const contentLength=rs.get('content-length');
  if(contentLength!==undefined){const len=unsignedInteger(contentLength.trim());if(len!==null&&(parsed.last-parsed.first+1)!==len)count(SIGNALS[8]);}
  const etag=String(rs.get('etag')||'');
  // Only *strong*, quoted HTTP ETags can serve as conservative in-HAR identity evidence.
  if(!/^(?:"[^"\r\n]{1,256}")$/.test(etag)){
   count(SIGNALS[12]);totals.rangeResponsesWithoutStrongValidator++;continue;
  }
  if(parsed.total===null)continue;
  const coding=String(rs.get('content-encoding')||'identity').toLowerCase().slice(0,80);
  const key=JSON.stringify([u.href,etag,coding,parsed.total]);
  if(!groups.has(key))groups.set(key,{total:parsed.total,segments:[]});
  groups.get(key).segments.push([parsed.first,parsed.last]);
 }
 for(const g of groups.values()){
  totals.stableTagGroups++;
  let covered=0,anyOverlap=false,end=-1;
  g.segments.sort((a,b)=>a[0]-b[0]||a[1]-b[1]);
  for(const [first,last] of g.segments){
   if(first<=end){anyOverlap=true;count(SIGNALS[13]);}
   const lo=Math.max(first,end+1);
   if(lo<=last)covered+=last-lo+1;
   end=Math.max(end,last);
  }
  if(anyOverlap)totals.groupsWithOverlap++;
  const pct=100*covered/g.total;
  buckets[bins(pct)].count++;
 }
 return Object.freeze({format:'trufflehog-har-byte-range-evidence',version:1,coverage:totals,
   signals:SIGNALS.map(category=>({category,count:values[category]})),spanBuckets:buckets,warnings:[...LIMITATIONS,...(totals.partialResponses<10?['Fewer than ten 206 responses: results and rates are unstable.']:[])]});
}
const rate=(n,d)=>d?Math.round(n*100000/d)/100:null;
function compare(a,b,context={}){
 const x=audit(a),y=audit(b);
 const ctx=['sameSite','sameActions','sameAccount','sameScope','sameBrowserCoverage'].map((k,i)=>({category:['Same website','Same browser actions','Same account or role','Same asset/gallery scope','Equivalent browser capture coverage'][i],answer:context[k]==='yes'||context[k]==='no'?context[k]:'unknown'}));
 const readiness=ctx.some(x=>x.answer==='no')?'Not comparable':ctx.every(x=>x.answer==='yes')&&x.coverage.partialResponses>=10&&y.coverage.partialResponses>=10?'Context declared comparable':'Context or coverage review needed';
 const join=(kind)=>x[kind].map((row,i)=>({category:row.category,baseline:row.count,comparison:y[kind][i].count,baselinePer1000Partial:rate(row.count,x.coverage.partialResponses),comparisonPer1000Partial:rate(y[kind][i].count,y.coverage.partialResponses)}));
 return Object.freeze({format:'trufflehog-har-byte-range-comparison',version:1,readiness,context:ctx,coverage:[{capture:'Baseline HAR',...x.coverage},{capture:'Comparison HAR',...y.coverage}],signals:join('signals'),spanBuckets:join('spanBuckets'),warnings:[...LIMITATIONS,...(readiness!=='Context declared comparable'?['Do not treat these counts as an asset quality, content-integrity, licensing or policy change without comparable captures and owner-side evidence.']:[])]});
}
const API=Object.freeze({audit,compare});root.THIHARRangeEvidence=API;
if(typeof module==='object'&&module.exports)module.exports=API;
})(typeof self!=='undefined'?self:globalThis);
