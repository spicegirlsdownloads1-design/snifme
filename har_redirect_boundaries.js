/* Trufflehog v7.6 — local HAR redirect boundary evidence, fixed-label output.
 * URL values and request header values are only used transiently for matching;
 * no endpoint identifiers, request payloads, cookies or signatures leave audit().
 */
(function(root){'use strict';
const LIMIT=12000;
const REDIRECT=new Set([301,302,303,307,308]);
const CATEGORIES=Object.freeze([
 'Same-origin redirect with unique observed target',
 'Cross-origin redirect with unique observed target',
 'Redirect target not captured',
 'Ambiguous repeated target requests',
 'Unsupported or invalid redirect destination',
 'Redirect without destination metadata'
]);
const INDICATORS=Object.freeze([
 'Cross-origin target: Authorization or API-key header name present',
 'Cross-origin target: Cookie header name present',
 'Cross-origin target: signing query-parameter name present',
 'Cross-origin target: no authentication indicator observed',
 'Cross-origin target: request headers unavailable',
 'Cross-origin HTTPS-to-HTTP redirect destination',
 'Cross-origin target: MIME-confirmed 2xx media response',
 'Cross-origin target: 2xx attachment response',
 'Cross-origin target: 401/403 denial response'
]);
const WARNINGS=Object.freeze([
 'Only an explicit Location/redirectURL pointing to one later request yields a matched boundary. Timing proximity alone is not a match.',
 'Cross-origin redirects, signed URLs, cookies and Authorization header names may be expected in legitimate DAM/CDN operations; none proves leaked media or incorrect access control.',
 'A sanitised HAR may omit authentication headers, redirects, browser cache hits and completed downloads. No header observed is not evidence of anonymous access.',
 'An HTTP 2xx MIME-confirmed media response does not prove a licensed original or a completed disk download.',
 'An HTTPS-to-HTTP redirect is a review indicator; HAR evidence cannot establish whether usable credentials were transmitted or intercepted.',
 'Results contain fixed category labels and counts only, not asset IDs, hosts, paths, URLs, request IDs, signatures or exact timestamps.'
]);
function url(x,base){try{if(typeof x!=='string'||x.length>8192||!x.trim())return null;const u=new URL(x,base);return /^https?:$/.test(u.protocol)?u:null;}catch{return null;}}
function headers(a){const s=new Map();if(Array.isArray(a))for(const item of a.slice(0,150)){
 const k=typeof item?.name==='string'?item.name.toLowerCase().slice(0,80):'';
 if(/^[a-z0-9-]{1,80}$/.test(k)&&!s.has(k))s.set(k,typeof item.value==='string'?item.value.slice(0,8192):'');
}return s;}
function signed(u){const keys=['x-amz-signature','x-amz-credential','x-amz-algorithm','x-goog-signature','x-goog-credential','x-goog-algorithm','signature','sig','policy','key-pair-id','token','access_token'];return [...u.searchParams.keys()].some(k=>keys.includes(k.toLowerCase()));}
function classDest(entry){const res=entry?.response||{},hs=headers(res.headers),mime=String(res.content?.mimeType||hs.get('content-type')||'').toLowerCase().slice(0,128),status=Number(res.status);
 return {media:status>=200&&status<300&&/^(image|audio|video)\//.test(mime),attachment:status>=200&&status<300&&/^\s*attachment\b/i.test(hs.get('content-disposition')||''),denied:status===401||status===403};}
function audit(har){
 const entries=har?.log?.entries;if(!Array.isArray(entries))throw Error('HAR must contain log.entries');if(entries.length>LIMIT)throw Error('HAR exceeds 12,000-entry limit');
 const index=new Map(),links=Object.fromEntries(CATEGORIES.map(s=>[s,0])),flags=Object.fromEntries(INDICATORS.map(s=>[s,0]));
 let inspectedHttp=0;
 // Map observed request URLs in memory. Do not return or retain this index.
 entries.forEach((e,i)=>{const u=url(e?.request?.url);if(!u||!e?.response)return;inspectedHttp++;const k=u.href;if(!index.has(k))index.set(k,[]);index.get(k).push(i);});
 let redirectResponses=0,redirectLocations=0,crossOrigin=0,matched=0,missingRequestHeaders=0;
 for(let i=0;i<entries.length;i++){
  const e=entries[i],source=url(e?.request?.url);if(!source||!e?.response||!REDIRECT.has(Number(e.response.status)))continue;
  redirectResponses++;
  const h=headers(e.response.headers),raw=h.get('location')||(typeof e.response.redirectURL==='string'?e.response.redirectURL:'');
  if(!raw){links[CATEGORIES[5]]++;continue;}
  redirectLocations++;
  const dest=url(raw,source.href);if(!dest){links[CATEGORIES[4]]++;continue;}
  const possible=(index.get(dest.href)||[]).filter(j=>j>i);
  if(!possible.length){links[CATEGORIES[2]]++;continue;}
  if(possible.length>1){links[CATEGORIES[3]]++;continue;}
  const target=entries[possible[0]],isCross=source.origin!==dest.origin;
  links[CATEGORIES[isCross?1:0]]++;matched++;
  if(!isCross)continue;
  crossOrigin++;
  const rq=headers(target.request?.headers),hasHeaders=Array.isArray(target.request?.headers);
  const hasAuth=rq.has('authorization')||rq.has('x-api-key')||rq.has('proxy-authorization');
  const hasCookie=rq.has('cookie'),hasSign=signed(dest);
  if(hasAuth)flags[INDICATORS[0]]++;
  if(hasCookie)flags[INDICATORS[1]]++;
  if(hasSign)flags[INDICATORS[2]]++;
  if(!hasAuth&&!hasCookie&&!hasSign&&hasHeaders)flags[INDICATORS[3]]++;
  if(!hasHeaders){flags[INDICATORS[4]]++;missingRequestHeaders++;}
  if(source.protocol==='https:'&&dest.protocol==='http:')flags[INDICATORS[5]]++;
  const kind=classDest(target);
  if(kind.media)flags[INDICATORS[6]]++;
  if(kind.attachment)flags[INDICATORS[7]]++;
  if(kind.denied)flags[INDICATORS[8]]++;
 }
 const coverage={totalEntries:entries.length,inspectedHttp,redirectResponses,redirectLocations,uniquelyMatched:matched,matchedCrossOrigin:crossOrigin,missingCrossOriginRequestHeaders:missingRequestHeaders};
 return Object.freeze({format:'trufflehog-har-redirect-boundary-observations',version:1,coverage,
  boundaries:CATEGORIES.map(category=>({category,count:links[category]})),indicators:INDICATORS.map(category=>({category,count:flags[category]})),warnings:[...WARNINGS,...(redirectResponses<10?['Fewer than ten redirect responses: rates and comparisons may be unstable.']:[])]});
}
function rate(n,d){return d?Math.round((n/d)*100000)/100:null;}
function compare(a,b,context={}){
 const x=audit(a),y=audit(b),names=['sameSite','sameActions','sameAccount','sameScope','sameBrowserCoverage'];
 const declared=names.map(n=>({category:({sameSite:'Same website',sameActions:'Same browser actions',sameAccount:'Same user account/role',sameScope:'Same asset/gallery scope',sameBrowserCoverage:'Equivalent browser capture coverage'})[n],answer:context[n]==='yes'||context[n]==='no'?context[n]:'unknown'}));
 const readiness=declared.some(x=>x.answer==='no')?'Not comparable':declared.every(x=>x.answer==='yes')&&x.coverage.redirectResponses>=10&&y.coverage.redirectResponses>=10?'Context declared comparable':'Context or coverage review needed';
 const joined=(kind)=>x[kind].map((row,i)=>({category:row.category,baseline:row.count,comparison:y[kind][i].count,baselinePer1000Redirect:rate(row.count,x.coverage.redirectResponses),comparisonPer1000Redirect:rate(y[kind][i].count,y.coverage.redirectResponses)}));
 return Object.freeze({format:'trufflehog-har-redirect-boundary-comparison',version:1,readiness,context:declared,
  coverage:[{capture:'Baseline HAR',...x.coverage},{capture:'Comparison HAR',...y.coverage}],boundaries:joined('boundaries'),indicators:joined('indicators'),warnings:[...WARNINGS,...(readiness!=='Context declared comparable'?['Do not treat differing counts as a DAM/CDN policy change unless browser coverage and workflow context are comparable.']:[])]});
}
const API=Object.freeze({audit,compare});root.THIHARRedirectBoundaries=API;
if(typeof module==='object'&&module.exports)module.exports=API;
})(typeof self!=='undefined'?self:globalThis);
