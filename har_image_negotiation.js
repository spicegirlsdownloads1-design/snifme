/* Trufflehog v7.9: passive HAR representation and image negotiation evidence.
 * Inspect user-selected local files only. No fetches, probes or payload exports.
 * Every exported string is an internal fixed category or documentation warning.
 */
(function(root){'use strict';
const MAX=12000;
const CATEGORIES=Object.freeze([
 'Observed image/jpeg representation (200/206)',
 'Observed image/png representation (200/206)',
 'Observed image/webp representation (200/206)',
 'Observed image/avif representation (200/206)',
 'Observed image/gif representation (200/206)',
 'Observed image/svg+xml representation (200/206)',
 'Observed other image media type (200/206)',
 'Image-suffix request without a confirmed delivered image MIME',
 'Media-related HTTP 304 (no representation body proven)',
 'Request Accept lists image/avif',
 'Request Accept lists image/webp',
 'Request Accept lists image/jpeg',
 'Request Accept lists image/* or */*',
 'Media response with no visible Accept request header',
 'Observed image/avif response and request advertises image/avif',
 'Observed image/webp response and request advertises image/webp',
 'Observed image/jpeg response and request advertises image/jpeg',
 'Response Vary declares Accept',
 'Response Vary declares Accept-Encoding',
 'Response Vary declares Accept-Language',
 'Response Vary declares client image hints',
 'Response Vary declares Cookie or Authorization',
 'Response Vary: *',
 'Media response with Vary header absent (not a violation)',
 'Request Accept-Encoding visible',
 'Response Content-Encoding gzip',
 'Response Content-Encoding br',
 'Response Content-Encoding zstd',
 'Response Content-Encoding identity',
 'Response Content-Encoding other present',
 'Response Accept-CH asks for image sizing hints',
 'Request image sizing client hint visible',
 'Request Save-Data present',
 'Response Content-DPR header present',
 'Media response Content-Type missing but HAR MIME supplied',
 'Request header array unavailable',
 'Response header array unavailable'
]);
const WARNINGS=Object.freeze([
 'Accept lists browser preferences; it does not prove that alternative formats or larger image renditions exist at the origin.',
 'Content-Type and HAR MIME labels identify an observed HTTP representation, not its pixel dimensions, image integrity, master-file status, licensing or anonymous accessibility.',
 'HTTP 304 does not carry a newly delivered image body. Media-suffix clues or HAR content mimeType cannot change that.',
 'Vary identifies possible cache selection headers, not a verified server negotiation, cache configuration flaw or bypass. Missing Vary cannot alone establish a defect.',
 'Client hints may depend on server opt-in, browser support and cross-origin permissions. Header presence never proves that an asset was resized.',
 'Only pre-existing HAR request/response headers and MIME metadata are inspected. No URLs are constructed or fetched, no bodies are read, and no secret, origin, file or header value is exported.',
 'HAR captures may omit headers, cached resources and worker traffic. Compare rates only after checking browser, role, page actions and capture coverage.'
]);
const CONTEXT=Object.freeze([['sameSite','Same website'],['sameActions','Same browser actions'],['sameAccount','Same account or role'],['sameScope','Same asset/gallery scope'],['sameBrowserCoverage','Equivalent browser capture coverage']]);
function headers(raw){const m=new Map();if(!Array.isArray(raw))return m;for(const obj of raw.slice(0,150)){
 const name=typeof obj?.name==='string'?obj.name.trim().toLowerCase().slice(0,96):'';
 if(/^[a-z0-9-]{1,96}$/.test(name)&&!m.has(name))m.set(name,typeof obj.value==='string'?obj.value.slice(0,2048):'');
}return m;}
function http(s){if(typeof s!=='string'||s.length>8192)return null;try{const u=new URL(s);return ['http:','https:'].includes(u.protocol)?u:null;}catch{return null;}}
function listed(value,term){if(typeof value!=='string')return false;return value.split(',').some(item=>item.split(';')[0].trim().toLowerCase()===term);}
function tokenList(value){return String(value||'').toLowerCase().split(',').slice(0,48).map(v=>v.trim()).filter(v=>v==='*'||/^[a-z0-9-]{1,50}$/.test(v));}
function hasHintName(n){return /^(?:width|dpr|viewport-width|sec-ch-width|sec-ch-dpr|sec-ch-viewport-width)$/.test(n);}
function imageType(raw){const m=/^\s*(image\/[a-z0-9.+_-]+)(?:\s*(?:;|$))/i.exec(String(raw||'').slice(0,160));return m?m[1].toLowerCase():'';}
function audit(har){const entries=har?.log?.entries;if(!Array.isArray(entries))throw Error('HAR must contain log.entries');if(entries.length>MAX)throw Error('HAR exceeds the 12,000-entry limit');
 const tally=Object.fromEntries(CATEGORIES.map(k=>[k,0]));const inc=k=>{tally[k]++;};
 const coverage={totalEntries:entries.length,inspectedHttp:0,excludedEntries:0,imageResponses:0,media304Clues:0,imageRequestsWithAcceptHeader:0,missingHeaderEntries:0};
 for(const e of entries){const req=e?.request,res=e?.response,u=http(req?.url);if(!u||!res||typeof res!=='object'){coverage.excludedEntries++;continue;}
  coverage.inspectedHttp++;
  const rq=headers(req.headers),rh=headers(res.headers),status=Number(res.status),method=String(req.method||'').toUpperCase(),safe=method==='GET'||method==='HEAD';
  if(!Array.isArray(req.headers)){inc('Request header array unavailable');coverage.missingHeaderEntries++;}
  if(!Array.isArray(res.headers)){inc('Response header array unavailable');coverage.missingHeaderEntries++;}
  const fromHeader=imageType(rh.get('content-type')),fromHar=imageType(res.content?.mimeType);
  const mime=fromHeader||fromHar;
  const suffix=/\.(?:jpe?g|png|gif|webp|avif|svg|tiff?|bmp)$/i.test(u.pathname.slice(-70));
  const delivered=safe&&(status===200||status===206)&&mime.startsWith('image/');
  const media304=safe&&status===304&&(mime.startsWith('image/')||suffix);
  if(delivered){coverage.imageResponses++;
   const key=['image/jpeg','image/png','image/webp','image/avif','image/gif','image/svg+xml'].includes(mime)?mime:'other';
   inc(key==='other'?'Observed other image media type (200/206)':'Observed '+key+' representation (200/206)');
   if(!fromHeader&&fromHar)inc('Media response Content-Type missing but HAR MIME supplied');
  }else if(suffix&&!mime.startsWith('image/'))inc('Image-suffix request without a confirmed delivered image MIME');
  if(media304){coverage.media304Clues++;inc('Media-related HTTP 304 (no representation body proven)');}
  const accept=rq.get('accept')||'';
  const avif=listed(accept,'image/avif'),webp=listed(accept,'image/webp'),jpeg=listed(accept,'image/jpeg')||listed(accept,'image/jpg');
  if(avif)inc('Request Accept lists image/avif');
  if(webp)inc('Request Accept lists image/webp');
  if(jpeg)inc('Request Accept lists image/jpeg');
  if(listed(accept,'image/*')||listed(accept,'*/*'))inc('Request Accept lists image/* or */*');
  if(delivered){if(rq.has('accept'))coverage.imageRequestsWithAcceptHeader++;else inc('Media response with no visible Accept request header');
   if(mime==='image/avif'&&avif)inc('Observed image/avif response and request advertises image/avif');
   if(mime==='image/webp'&&webp)inc('Observed image/webp response and request advertises image/webp');
   if(mime==='image/jpeg'&&jpeg)inc('Observed image/jpeg response and request advertises image/jpeg');
  }
  if(delivered&&!rh.has('vary'))inc('Media response with Vary header absent (not a violation)');
  if(rh.has('vary')){const vary=tokenList(rh.get('vary'));
   if(vary.includes('accept'))inc('Response Vary declares Accept');
   if(vary.includes('accept-encoding'))inc('Response Vary declares Accept-Encoding');
   if(vary.includes('accept-language'))inc('Response Vary declares Accept-Language');
   if(vary.some(hasHintName))inc('Response Vary declares client image hints');
   if(vary.includes('cookie')||vary.includes('authorization'))inc('Response Vary declares Cookie or Authorization');
   if(vary.includes('*'))inc('Response Vary: *');
  }
  if(rq.has('accept-encoding'))inc('Request Accept-Encoding visible');
  if(rh.has('content-encoding')){const coding=String(rh.get('content-encoding')).trim().toLowerCase();
   inc(coding==='gzip'?'Response Content-Encoding gzip':coding==='br'?'Response Content-Encoding br':coding==='zstd'?'Response Content-Encoding zstd':coding==='identity'?'Response Content-Encoding identity':'Response Content-Encoding other present');
  }
  if(tokenList(rh.get('accept-ch')).some(hasHintName))inc('Response Accept-CH asks for image sizing hints');
  if([...rq.keys()].some(hasHintName))inc('Request image sizing client hint visible');
  if(rq.has('save-data'))inc('Request Save-Data present');
  if(rh.has('content-dpr'))inc('Response Content-DPR header present');
 }
 return Object.freeze({format:'trufflehog-har-image-negotiation',version:1,coverage,signals:CATEGORIES.map(category=>({category,count:tally[category]})),warnings:[...WARNINGS,...(coverage.imageResponses<5?['Fewer than five observed image representations: format shares may be unstable.']:[])]});
}
function rate(n,d){return d?Math.round(n*100000/d)/100:null;}
function compare(a,b,context={}){const x=audit(a),y=audit(b);
 const ctx=CONTEXT.map(([key,category])=>({category,answer:context[key]==='yes'||context[key]==='no'?context[key]:'unknown'}));
 const readiness=ctx.some(v=>v.answer==='no')?'Not comparable':ctx.every(v=>v.answer==='yes')&&x.coverage.imageResponses>=5&&y.coverage.imageResponses>=5?'Context declared comparable':'Context or coverage review needed';
 return Object.freeze({format:'trufflehog-har-image-negotiation-comparison',version:1,readiness,context:ctx,
  coverage:[{capture:'Baseline HAR',...x.coverage},{capture:'Comparison HAR',...y.coverage}],
  signals:x.signals.map((s,i)=>({category:s.category,baseline:s.count,comparison:y.signals[i].count,
   baselinePer1000Http:rate(s.count,x.coverage.inspectedHttp),comparisonPer1000Http:rate(y.signals[i].count,y.coverage.inspectedHttp)})),
  warnings:[...WARNINGS,...(readiness!=='Context declared comparable'?['Observed format and client-hint differences cannot establish alternate originals, server-side transformations, or a changed policy without comparable captures.']:[])]});
}
const API=Object.freeze({audit,compare});root.THIHARImageNegotiation=API;
if(typeof module==='object'&&module.exports)module.exports=API;
})(typeof self!=='undefined'?self:globalThis);
