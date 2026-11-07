/* Trufflehog v7.5: passive HAR delivery-by-auth observation matrix.
 * Processes selected HAR objects in memory; reports fixed, non-identifying categories and counts.
 * No network requests, request replay, extracted secrets, URL or asset identifiers.
 */
(function(root){'use strict';
const MAX=12000;
const AUTH=Object.freeze(['Mixed authentication indicators','Signed URL parameter names','Authorization header present','Cookie header present','No authentication indicator observed','Request headers unavailable']);
const OUTCOME=Object.freeze(['Delivered media or attachment (2xx)','Partial media/attachment (206)','Denied media-like request (401/403)','Media-like redirect (3xx)','Other / inconclusive response']);
const CACHE=Object.freeze(['Public cache directive','Private or no-store directive','No-cache directive','Other cache directive','No Cache-Control observed']);
const WARN=Object.freeze([
 'HAR visibility is incomplete: Chrome may omit cookies and authorization headers in sanitised exports. No indicator observed does not mean anonymous access.',
 'Response outcomes describe only requests included in a HAR; neither an HTTP 2xx nor an attachment proves a licensed or completed disk download.',
 'A signature-name clue is not signature verification, permission checking, or evidence of an exposed master image.',
 'Cache-Control header classifications do not establish actual CDN enforcement, revocation or origin protections.',
 'All cross-HAR differences are observational; account, browser coverage, workflow, asset scope and site context must be equivalent before any trend is interpreted.'
]);
function head(list){const out=new Map();if(!Array.isArray(list))return out;for(const h of list.slice(0,120)){if(typeof h?.name!=='string')continue;const k=h.name.toLowerCase().slice(0,96);if(/^[a-z0-9-]{1,96}$/.test(k)&&!out.has(k))out.set(k,typeof h.value==='string'?h.value.slice(0,256):'');}return out;}
function isSigned(params){for(const k of params.keys()){if(['x-amz-signature','x-amz-credential','x-amz-algorithm','x-goog-signature','x-goog-credential','x-goog-algorithm','signature','sig','policy','key-pair-id','key_pair_id','token','access_token'].includes(String(k).toLowerCase()))return true;}return false;}
function audit(har){
 const entries=har?.log?.entries;if(!Array.isArray(entries))throw Error('HAR must contain log.entries');if(entries.length>MAX)throw Error('HAR exceeds 12,000-entry limit');
 const matrix=AUTH.flatMap(authentication=>OUTCOME.map(outcome=>({authentication,outcome,count:0})));
 const cache=AUTH.flatMap(authentication=>CACHE.map(policy=>({authentication,policy,count:0})));
 const totals={totalEntries:entries.length,inspectedHttp:0,excludedEntries:0,deliveryRelevant:0,missingRequestHeaders:0,missingResponseHeaders:0, mediaMime2xx:0,attachment2xx:0};
 for(const e of entries){
  const req=e?.request,res=e?.response;if(!req||!res||typeof req!=='object'||typeof res!=='object'){totals.excludedEntries++;continue;}
  let url;try{if(typeof req.url!=='string'||req.url.length>8192)throw Error('invalid');url=new URL(req.url);if(!['http:','https:'].includes(url.protocol))throw Error('invalid');}catch{totals.excludedEntries++;continue;}
  totals.inspectedHttp++;
  const rq=head(req.headers),rs=head(res.headers),validReqHeaders=Array.isArray(req.headers),validResHeaders=Array.isArray(res.headers);
  const mime=String(res.content?.mimeType||rs.get('content-type')||'').toLowerCase().slice(0,120);
  const attachment=/^\s*attachment\b/i.test(rs.get('content-disposition')||'');
  const mediaMime=/^(?:image|video|audio)\//.test(mime);
  const mediaPath=/\.(?:jpe?g|png|webp|gif|avif|tiff?|heic|bmp|svg|mp4|webm|mov|mp3|wav)$/i.test(url.pathname.slice(-16));
  const status=Number(res.status);
  // Only failure/redirect classification uses path as a clue; 2xx HTML at a .jpg path is not a delivered image.
  const relevant=mediaMime||attachment||(mediaPath&&(status===401||status===403||(status>=300&&status<400)));
  if(!relevant)continue;
  totals.deliveryRelevant++;
  if(!validReqHeaders)totals.missingRequestHeaders++;
  if(!validResHeaders)totals.missingResponseHeaders++;
  const signed=isSigned(url.searchParams),authorization=rq.has('authorization')||rq.has('x-api-key')||rq.has('proxy-authorization'),cookie=rq.has('cookie');
  const signals=Number(signed)+Number(authorization)+Number(cookie);
  const auth=!validReqHeaders&&!signed?'Request headers unavailable':signals>1?'Mixed authentication indicators':signed?'Signed URL parameter names':authorization?'Authorization header present':cookie?'Cookie header present':'No authentication indicator observed';
  const outcome=status===206?'Partial media/attachment (206)':status===401||status===403?'Denied media-like request (401/403)':status>=300&&status<400?'Media-like redirect (3xx)':status>=200&&status<300&& (mediaMime||attachment)?'Delivered media or attachment (2xx)':'Other / inconclusive response';
  matrix[AUTH.indexOf(auth)*OUTCOME.length+OUTCOME.indexOf(outcome)].count++;
  if(status>=200&&status<300){if(mediaMime)totals.mediaMime2xx++;if(attachment)totals.attachment2xx++;}
  const raw=rs.get('cache-control');const cc=String(raw||'').toLowerCase();
  const has=k=>new RegExp('(?:^|,)\\s*'+k+'(?:\\b|\\s*=)','i').test(cc);
  const policy=!rs.has('cache-control')?'No Cache-Control observed':has('private')||has('no-store')?'Private or no-store directive':has('no-cache')?'No-cache directive':has('public')?'Public cache directive':'Other cache directive';
  cache[AUTH.indexOf(auth)*CACHE.length+CACHE.indexOf(policy)].count++;
 }
 return Object.freeze({format:'trufflehog-har-access-observation-matrix',version:1,coverage:totals,authOutcomes:matrix,authCache:cache,
  warnings:[...WARN,...(totals.deliveryRelevant<10?['Fewer than ten delivery-relevant HAR entries; rates and differences are fragile.']:[]),...(totals.missingRequestHeaders>0?['Some request headers were unavailable; authentication indicator categories may be undercounted.']:[])]});
}
const per1000=(n,d)=>d?Math.round(n/d*100000)/100:null;
function compare(a,b,context={}){
 const x=audit(a),y=audit(b);
 const fields=['sameSite','sameActions','sameAccount','sameScope','sameBrowserCoverage'];
 const contextRows=fields.map(field=>({category:({sameSite:'Same site',sameActions:'Same actions',sameAccount:'Same account or role',sameScope:'Same asset or gallery scope',sameBrowserCoverage:'Equivalent capture coverage'})[field],answer:context[field]==='yes'||context[field]==='no'?context[field]:'unknown'}));
 const ready=contextRows.some(r=>r.answer==='no')?'Not comparable':contextRows.every(r=>r.answer==='yes')&&x.coverage.deliveryRelevant>=10&&y.coverage.deliveryRelevant>=10?'Context declared comparable':'Context or coverage review needed';
 const row=(ra,rb,fields)=>ra.map((r,i)=>{const s=rb[i];return {...Object.fromEntries(fields.map(k=>[k,r[k]])),baseline:r.count,comparison:s.count,baselinePer1000Delivery:per1000(r.count,x.coverage.deliveryRelevant),comparisonPer1000Delivery:per1000(s.count,y.coverage.deliveryRelevant)};});
 return Object.freeze({format:'trufflehog-har-access-observation-comparison',version:1,readiness:ready,context:contextRows,
  coverage:[{capture:'Baseline HAR',...x.coverage},{capture:'Comparison HAR',...y.coverage}],
  authOutcomes:row(x.authOutcomes,y.authOutcomes,['authentication','outcome']),authCache:row(x.authCache,y.authCache,['authentication','policy']),warnings:[...WARN,...(ready!=='Context declared comparable'?['Do not interpret a difference as permission or security-policy drift without comparable capture contexts and adequate samples.']:[]),...x.warnings.slice(WARN.length),...y.warnings.slice(WARN.length)]});
}
const API=Object.freeze({audit,compare});root.THIHARAccessMatrix=API;
if(typeof module==='object'&&module.exports)module.exports=API;
})(typeof self!=='undefined'?self:globalThis);
