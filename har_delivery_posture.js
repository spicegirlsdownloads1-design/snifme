/* Trufflehog Intelligence v7.4 — passive, privacy-bounded HAR delivery posture.
 * Fixed labels and counts only. Input HAR never stored or requested from networks.
 * Neither a signed URL nor a delivered image proves anonymous access or entitlement.
 */
(function(root){'use strict';
const MAX=12000;
const CATEGORIES=Object.freeze([
 'Observed image/media response','Attachment disposition observed','Inline disposition observed',
 'Partial media response (206)','Media denial response (401/403)','Media redirect response (3xx)',
 'Signed query name on media request','AWS/Google signing scheme name on media request',
 'Expiry-related query name on media request','Authorization header on media request',
 'Cookie header on media request','Set-Cookie header on media response',
 'Cache-Control public on media response','Cache-Control private on media response',
 'Cache-Control no-store on media response','Cache-Control no-cache on media response',
 'Cache-Control immutable on media response','Media cache max-age at most 1 hour',
 'Media cache max-age above 1 hour through 24 hours','Media cache max-age above 24 hours',
 'Media cache lifetime unclassified','Media response missing Cache-Control',
 'CDN cache HIT on media response','CDN cache MISS on media response',
 'CDN cache BYPASS or DYNAMIC on media response','CDN cache status other or unclassified',
 'Media response with public cache and signing-name indicator',
 'Media response with public cache and request authentication header',
 'Media response with public cache and request cookie',
 'Media response body absent in HAR','Media response with Content-Length header',
 'Response redirect target header present','Incomplete request or response headers'
]);
const WARNINGS=Object.freeze([
 'HAR evidence may omit authorization context, internal redirects, response bodies, memory-cache events and browser download completion.',
 'The presence of signing field names does not validate a signature or establish that the request was anonymous.',
 'Cache-Control directives and CDN cache status are observed headers, not proof of origin or CDN invalidation policy.',
 'A public caching directive combined with a signed request is an owner-review clue only, not proof of data exposure.',
 'Comparisons across different accounts, actions, assets, browser settings or capture coverage cannot demonstrate permission drift.',
 'Only fixed classifications and numeric counts are exported. No raw URL, hostname, path, token, header value, file name or resource ID is retained.'
]);
const mk=()=>Object.fromEntries(CATEGORIES.map(s=>[s,0]));
function headerMap(list){const m=new Map(); if(!Array.isArray(list))return m;
 for(const h of list.slice(0,120)){
  const n=typeof h?.name==='string'?h.name.toLowerCase().slice(0,96):'';
  if(/^[a-z0-9-]{1,96}$/.test(n)&&!m.has(n))m.set(n,typeof h?.value==='string'?h.value.slice(0,256):'');
 }
 return m;
}
const media=(mime)=>/^(?:image|audio|video)\//.test(mime);
function audit(har){
 const entries=har?.log?.entries;
 if(!Array.isArray(entries))throw Error('HAR must contain log.entries');
 if(entries.length>MAX)throw Error('HAR exceeds the 12,000-entry limit');
 const counts=mk();let inspected=0,excluded=0,mediaResponses=0,missingHeaders=0,withContentType=0;
 for(const entry of entries){
  const req=entry?.request,resp=entry?.response;
  if(!req||!resp||typeof req!=='object'||typeof resp!=='object'){excluded++;continue;}
  let url;try{
   if(typeof req.url!=='string'||req.url.length>8192)throw Error('bad URL');
   url=new URL(req.url);if(!['http:','https:'].includes(url.protocol))throw Error('bad scheme');
  }catch{excluded++;continue;}
  inspected++;
  const rh=headerMap(req.headers),sh=headerMap(resp.headers);
  const incomplete=!Array.isArray(req.headers)||!Array.isArray(resp.headers);
  if(incomplete){missingHeaders++;counts['Incomplete request or response headers']++;}
  const ct=String(resp.content?.mimeType||sh.get('content-type')||'').toLowerCase().slice(0,110);
  if(ct)withContentType++;
  const dispo=String(sh.get('content-disposition')||'').toLowerCase();
  const isAttachment=/^\s*attachment\b/.test(dispo);
  const isInline=/^\s*inline\b/.test(dispo);
  // An attachment may be an archive or another file type. Include separately
  // in delivery-scope counts, but do not call it a verified image.
  const isMedia=media(ct);
  // Failed/redirected media requests often have HTML or no MIME body. Path
  // suffix is a request *clue*, not proof of a delivered or stored image.
  const mediaPath=/\.(?:jpe?g|png|webp|gif|avif|tiff?|heic|bmp|svg|mp4|webm|mov|mp3|wav)$/i.test(url.pathname.slice(-16));
  const relevant=isMedia||isAttachment||mediaPath;
  if(!relevant)continue;
  mediaResponses++;
  const inc=n=>{counts[n]++};
  if(isMedia)inc('Observed image/media response');
  if(isAttachment)inc('Attachment disposition observed');
  if(isInline)inc('Inline disposition observed');
  const status=Number(resp.status);
  if(status===206)inc('Partial media response (206)');
  if(status===401||status===403)inc('Media denial response (401/403)');
  if(status>=300&&status<400)inc('Media redirect response (3xx)');
  if(status>=300&&status<400&&sh.has('location'))inc('Response redirect target header present');
  const keynames=new Set(Array.from(url.searchParams.keys()).slice(0,160).map(x=>String(x).toLowerCase().slice(0,96)));
  const signed=['x-amz-signature','x-goog-signature','signature','sig','policy','key-pair-id','key_pair_id','token','access_token'].some(k=>keynames.has(k));
  const awsGoogle=['x-amz-signature','x-goog-signature','x-amz-algorithm','x-goog-algorithm','x-amz-credential','x-goog-credential'].some(k=>keynames.has(k));
  const expiry=['expires','expiry','expiration','x-amz-expires','x-goog-expires','exp'].some(k=>keynames.has(k));
  if(signed)inc('Signed query name on media request');
  if(awsGoogle)inc('AWS/Google signing scheme name on media request');
  if(expiry)inc('Expiry-related query name on media request');
  const auth=rh.has('authorization')||rh.has('x-api-key')||rh.has('proxy-authorization');
  if(auth)inc('Authorization header on media request');
  if(rh.has('cookie'))inc('Cookie header on media request');
  if(sh.has('set-cookie'))inc('Set-Cookie header on media response');
  const cc=(sh.get('cache-control')||'').toLowerCase();
  if(!sh.has('cache-control'))inc('Media response missing Cache-Control');
  const directive=(key)=>new RegExp('(?:^|,)\\s*'+key+'(?:\\b|\\s*=)','i').test(cc);
  if(directive('public'))inc('Cache-Control public on media response');
  if(directive('private'))inc('Cache-Control private on media response');
  if(directive('no-store'))inc('Cache-Control no-store on media response');
  if(directive('no-cache'))inc('Cache-Control no-cache on media response');
  if(directive('immutable'))inc('Cache-Control immutable on media response');
  const ageMatch=cc.match(/(?:^|,)\s*(?:s-maxage|max-age)\s*=\s*(\d{1,10})(?:\b|$)/i);
  if(ageMatch){const n=Number(ageMatch[1]);if(n<=3600)inc('Media cache max-age at most 1 hour');
   else if(n<=86400)inc('Media cache max-age above 1 hour through 24 hours');
   else inc('Media cache max-age above 24 hours');
  }else if(sh.has('cache-control'))inc('Media cache lifetime unclassified');
  const cache=String(sh.get('cf-cache-status')||sh.get('x-cache')||'').toUpperCase().slice(0,120);
  if(cache){
   if(/\bHIT\b/.test(cache))inc('CDN cache HIT on media response');
   else if(/\bMISS\b/.test(cache))inc('CDN cache MISS on media response');
   else if(/\b(?:BYPASS|DYNAMIC)\b/.test(cache))inc('CDN cache BYPASS or DYNAMIC on media response');
   else inc('CDN cache status other or unclassified');
  }
  if(signed&&directive('public'))inc('Media response with public cache and signing-name indicator');
  if(auth&&directive('public'))inc('Media response with public cache and request authentication header');
  if(rh.has('cookie')&&directive('public'))inc('Media response with public cache and request cookie');
  if(isMedia&&!Object.hasOwn(resp.content||{},'text'))inc('Media response body absent in HAR');
  if(sh.has('content-length'))inc('Media response with Content-Length header');
 }
 return Object.freeze({format:'trufflehog-har-delivery-posture',version:1,
  coverage:{totalEntries:entries.length,inspectedHttp:inspected,excludedEntries:excluded,deliveryRelevantResponses:mediaResponses,missingHeaderEntries:missingHeaders,withContentType},
  rows:CATEGORIES.map(category=>({category,count:counts[category]})),
  reviewCandidates:[
   {category:'Public cache and signing-name combination: owner review',count:counts['Media response with public cache and signing-name indicator']},
   {category:'Public cache and authorization-header combination: owner review',count:counts['Media response with public cache and request authentication header']},
   {category:'Public cache and request-cookie combination: owner review',count:counts['Media response with public cache and request cookie']}
  ],limitations:[...WARNINGS]});
}
const rate=(count,den)=>den?Math.round(count/den*100000)/100:null;
function compare(first,second){const a=audit(first),b=audit(second);
 return Object.freeze({format:'trufflehog-har-delivery-comparison',version:1,
  coverage:[{capture:'Baseline HAR',...a.coverage},{capture:'Comparison HAR',...b.coverage}],
  rows:a.rows.map((x,i)=>({category:x.category,baseline:x.count,comparison:b.rows[i].count,
   baselinePer1000:rate(x.count,a.coverage.inspectedHttp),comparisonPer1000:rate(b.rows[i].count,b.coverage.inspectedHttp),
   baselinePer1000Delivery:rate(x.count,a.coverage.deliveryRelevantResponses),comparisonPer1000Delivery:rate(b.rows[i].count,b.coverage.deliveryRelevantResponses)})),
  reviewCandidates:a.reviewCandidates.map((x,i)=>({category:x.category,baseline:x.count,comparison:b.reviewCandidates[i].count})),
  warnings:[...WARNINGS, ...(a.coverage.deliveryRelevantResponses<5||b.coverage.deliveryRelevantResponses<5?
   ['One or both HARs include fewer than five delivery-relevant responses; apparent differences are especially unreliable.']:[])],
  conclusions:'Descriptive observations only — not an access-control or cache-revocation test.'});
}
const API=Object.freeze({audit,compare});root.THIHARDeliveryPosture=API;
if(typeof module==='object'&&module.exports)module.exports=API;
})(typeof self!=='undefined'?self:globalThis);
