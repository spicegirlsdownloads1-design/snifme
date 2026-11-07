/* Trufflehog Security Intelligence v7.18
 * Passive browser/HAR security-condition classification. NO probing, token
 * validation, request replay, raw header/credential persistence or CVE claims.
 * Findings describe observable facts, not exploitation. */
(function(root){
'use strict';
const VERSION='1.0';
const META={
 SECRET_QUERY:['Potential credential in request URL','high-review','A credential-like parameter was present in a browser URL. Validity and privileges are unknown.','Keep reusable credentials out of URLs and review logging, referrer and history exposure.'],
 SESSION_QUERY:['Session-like identifier in request URL','review','A session-named parameter was present; it may be a benign correlation identifier.','Prefer cookie or header-based session handling; assess whether the value grants access.'],
 SIGNED_URL_WINDOW:['Signed-resource expiry declaration','review','A signed-delivery marker and declared time window were observed; effective access is not verified.','Review signing lifetime, scope and referrer exposure.'],
 REFERER_SECRET:['Credential-like parameter sent in cross-origin Referer','high-review','A browser request sent a Referer containing a credential-like parameter to a different origin. Ownership and credential validity are not established.','Review Referrer-Policy and remove reusable credentials from navigable URLs.'],
 CORS_WILDCARD_CREDENTIALS:['Wildcard CORS with credential allowance','review','The response advertised wildcard ACAO and ACAC=true. Browsers reject this combination for credentialed requests.','Review CORS configuration; do not assume data can be read by a hostile origin.'],
 CORS_CREDENTIAL_SCOPE:['Cross-origin credentialed CORS response','info','The observed response grants credentialed CORS access to a specific origin; this does not prove arbitrary origin reflection.','Confirm allowed origins are trusted and no sensitive data is exposed unnecessarily.'],
 CORS_NULL_ORIGIN:['Credentialed CORS response to null origin','review','The response advertised credentialed access for the null origin. Browser enforcement and context matter.','Review why null origin is trusted and whether the response contains private data.'],
 OAUTH_REDIRECT_DATA:['Authentication value in cross-origin redirect','review','An observed cross-origin redirect included an OAuth-like code or token parameter. Legitimate SSO flows can do this.','Validate redirect allowlists, state binding and expected identity-provider flow.'],
 MUTATION_CONTEXT:['Sensitive state-changing API operation observed','info','A state-changing request targeted an authentication, admin, account, upload or licensing-like path. No CSRF or authorisation weakness has been established.','Review authentication, CSRF and object-level authorisation using authorised application tests.'],
 FORM_FIELD_CONTEXT:['Sensitive POST form field categories observed','info','Only recognised form-field names were observed. No values were read or retained; missing protection or a vulnerability cannot be concluded.','Review the endpoint protection and confirm sensitive values are protected in transit and logs.'],
 COOKIE_FLAGS:['Session-like cookie security flags merit review','review','Cookie attribute metadata suggests a missing protective flag or browser-rejected SameSite combination. Actual risk depends on cookie purpose and environment.','Use Secure on HTTPS session cookies, HttpOnly where script access is unnecessary, and an appropriate SameSite policy.']
};
const rule=(id,ctx,markers=[],extra={})=>{
 const [title,severity,limit,advice]=META[id];
 return {ruleId:id,title,severity,confidence:extra.confidence||'exact-observation',stage:ctx.stage,host:ctx.host,route:ctx.route,method:ctx.method,
  status:ctx.status,at:ctx.at,requestRef:ctx.ref,markers:[...new Set(markers.map(x=>String(x).replace(/[^a-zA-Z0-9_-]/g,'').slice(0,40)))].slice(0,12),
  classification:extra.classification||'',declaration:extra.declaration||'',scope:extra.scope||'',
  evidence:extra.evidence||limit,limitation:limit,recommendation:advice};
};
const origin=x=>{try{const u=new URL(x);return /^https?:$/.test(u.protocol)?u.origin:'';}catch{return '';}};
const safeHost=x=>{try{return new URL(x).hostname.slice(0,150);}catch{return '';}};
// Only a small vocabulary of generic, non-unique endpoint labels is retained.
// Never persist arbitrary path segments: even short alphabetic strings can be secrets.
const ROUTE_WORDS=new Set(['api','rest','graphql','auth','login','logout','oauth','callback','password','reset','recover','admin','user','users','account','accounts','permission','permissions','order','orders','checkout','upload','uploads','import','imports','download','downloads','license','licenses','licence','licences','purchase','purchases','token','tokens','session','sessions','product','products','media','image','images','file','files','asset','assets','catalog','catalogue','ecom','basket','baskets']);
const safeRoute=url=>{try{
 const u=new URL(url);return u.pathname.split('/').slice(1,7).map(s=>{
  let v='';try{v=decodeURIComponent(s).toLowerCase();}catch{v=s.toLowerCase();}
  return ROUTE_WORDS.has(v)||/^v[1-9][0-9]?$/.test(v)?v:'{segment}';
 }).join('/').slice(0,145);
}catch{return '';}};
const headers=(arr)=>{const m=new Map();for(const h of Array.isArray(arr)?arr:[]){
 const key=String(h?.name||'').toLowerCase();if(!key||m.has(key))continue;
 m.set(key,typeof h.value==='string'?h.value:'');
}return m;};
const secretNames=new Set(['access_token','accesstoken','refresh_token','refreshtoken','client_secret','api_secret','private_key','password','passwd','authorization','bearer','auth_token']);
const sessionNames=new Set(['session','sessionid','session_id','sid','phpsessid','jsessionid','session_token']);
const publicKeyNames=new Set(['api_key','apikey','x_api_key','key']);
const signedMarkers=new Set(['x-amz-signature','x-goog-signature','sig','signature','cloudfront-signature']);
const norm=x=>String(x||'').toLowerCase().replace(/-/g,'_');
const nonPlaceholder=x=>typeof x==='string'&&x.length>=8&&!/^(?:0+|x+|test|demo|example|placeholder|changeme|undefined|null)$/i.test(x);
function queryInfo(url){
 try{const u=new URL(url),pairs=[...u.searchParams.entries()];
  const out={secret:[],session:[],signed:false,family:'',window:'unknown',code:[]};
  const get=k=>{const x=pairs.find(([n])=>n.toLowerCase()===k);return x?x[1]:'';};
  for(const [k,v] of pairs){const n=norm(k);
   if(secretNames.has(n)&&nonPlaceholder(v))out.secret.push(n);
   else if(sessionNames.has(n)&&nonPlaceholder(v))out.session.push(n);
   else if(publicKeyNames.has(n)&&nonPlaceholder(v)&&v.length>=20)out.secret.push('potential_public_api_key');
   if(['code','id_token','access_token','token'].includes(n)&&nonPlaceholder(v))out.code.push(n);
  }
  out.signed=pairs.some(([k,v])=>signedMarkers.has(k.toLowerCase())&&!!v);
  if(out.signed){
   if(get('x-amz-signature')){out.family='aws-v4';out.window=duration(get('x-amz-expires'));}
   else if(get('x-goog-signature')){out.family='gcs-v4';out.window=duration(get('x-goog-expires'));}
   else if(get('sig')&&get('se')){out.family='azure-sas';out.window='expiry-timestamp-present';}
   else {out.family='signed-unknown';out.window='unknown';}
  }
  return out;
 }catch{return {secret:[],session:[],signed:false,family:'',window:'unknown',code:[]};}
}
function duration(value){if(!/^\d{1,9}$/.test(String(value||'')))return 'unknown';const s=Number(value);
 if(s<1)return 'invalid';if(s<=900)return 'up-to-15m';if(s<=3600)return '15m-to-1h';if(s<=86400)return '1h-to-24h';if(s<=604800)return '1d-to-7d';return 'over-7d';}
function context(stage,d){const u=origin(d?.url);if(!u)return null;
 const ref=typeof d.requestId==='string'||Number.isSafeInteger(d.requestId)?String(d.requestId).slice(0,55).replace(/[^a-zA-Z0-9:_-]/g,''):'';
 return {stage,host:safeHost(d.url),route:safeRoute(d.url),method:/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)$/i.test(d.method||'')?d.method.toUpperCase():'OTHER',status:Number.isInteger(d.statusCode)?d.statusCode:null,at:new Date(Number.isFinite(d.timeStamp)?d.timeStamp:Date.now()).toISOString(),ref};
}
function classify(stage,d){const ctx=context(stage,d);if(!ctx)return [];
 const out=[],q=queryInfo(d.url),originUrl=origin(d.url);
 if(stage==='request'){
  if(q.secret.length){
   const publishableOnly=q.secret.every(n=>n==='potential_public_api_key');
   const finding=rule('SECRET_QUERY',ctx,q.secret,{classification:publishableOnly?'potentially-publishable-key':'credential-name',confidence:'exact-observation'});
   if(publishableOnly){finding.title='API-key-named parameter observed in URL';finding.severity='review';}
   out.push(finding);
  }
  if(q.session.length)out.push(rule('SESSION_QUERY',ctx,q.session));
  if(q.signed){
   const finding=rule('SIGNED_URL_WINDOW',ctx,['signature'],{classification:q.family,declaration:q.window});
   if(['up-to-15m','15m-to-1h','unknown','expiry-timestamp-present'].includes(q.window))finding.severity='info';
   if(q.window==='over-7d')finding.severity='high-review';
   out.push(finding);
  }
  if(['POST','PUT','PATCH','DELETE'].includes(ctx.method)&&/(?:^|\/)(?:login|logout|auth|password|reset|recover|admin|users?|accounts?|permissions?|orders?|checkout|uploads?|imports?|licen[sc]es?|purchases?)(?:\/|$)/i.test(ctx.route))out.push(rule('MUTATION_CONTEXT',ctx,[ctx.method],{confidence:'exact-observation',classification:'sensitive-operation-shape'}));
  // Chrome can expose formData on multipart/form-encoded POST. Read field NAMES
  // only, from a fixed vocabulary. Never inspect values or raw body bytes.
  const form=d?.requestBody?.formData;
  if(['POST','PUT','PATCH'].includes(ctx.method)&&form&&typeof form==='object'){
   const categories=[];
   for(const name of Object.keys(form).slice(0,120)){
    const n=norm(name);
    if(['password','passwd','current_password','new_password','password_confirmation'].includes(n))categories.push('password-field');
    else if(['access_token','refresh_token','id_token','client_secret','api_key','api_secret'].includes(n))categories.push('credential-field');
    else if(['csrf_token','csrf','_csrf','_token','authenticity_token'].includes(n))categories.push('csrf-field-present');
    else if(['file','files','upload','attachment','attachments'].includes(n))categories.push('file-field');
    else if(['redirect_uri','return_url','callback_url'].includes(n))categories.push('redirect-field');
   }
   if(categories.length)out.push(rule('FORM_FIELD_CONTEXT',ctx,categories,{classification:'request-form-field-names-only'}));
  }
 }
 if(stage==='request-headers'){
  const h=headers(d.requestHeaders),referer=h.get('referer')||h.get('referrer')||'';
  const refOrigin=origin(referer),r=queryInfo(referer);
  if(refOrigin&&refOrigin!==originUrl&&(r.secret.length||r.session.length||r.signed)){
   out.push(rule('REFERER_SECRET',ctx,[...r.secret,...r.session,...(r.signed?['signed-delivery']:[])],{scope:'cross-origin',classification:'observed-referer-header'}));
  }
 }
 if(stage==='response-headers'){
  const h=headers(d.responseHeaders),allow=(h.get('access-control-allow-origin')||'').trim(),cred=(h.get('access-control-allow-credentials')||'').trim().toLowerCase()==='true';
  const init=origin(d.initiator||d.documentUrl||'');
  if(allow==='*'&&cred)out.push(rule('CORS_WILDCARD_CREDENTIALS',ctx,['ACAO-wildcard','ACAC-true']));
  else if(allow==='null'&&cred)out.push(rule('CORS_NULL_ORIGIN',ctx,['ACAO-null','ACAC-true']));
  else if(cred&&allow&&init&&allow===init&&init!==originUrl)out.push(rule('CORS_CREDENTIAL_SCOPE',ctx,['ACAC-true','specific-origin'],{scope:'cross-origin',confidence:'structural-review'}));
  const setCookies=(Array.isArray(d.responseHeaders)?d.responseHeaders:[]).filter(h=>String(h.name||'').toLowerCase()==='set-cookie');
  for(const h of setCookies.slice(0,15)){
   if(typeof h.value!=='string')continue;
   const v=h.value, cookieName=v.split('=',1)[0].trim();
   if(!/(?:session|auth|sid|login|token)/i.test(cookieName))continue;
   const hasSecure=/(?:^|;)\s*secure\s*(?:;|$)/i.test(v);
   const missingSecure=originUrl.startsWith('https:')&&!hasSecure;
   const missingHttpOnly=!/(?:^|;)\s*httponly\s*(?:;|$)/i.test(v);
   const noneWithoutSecure=/(?:^|;)\s*samesite\s*=\s*none(?:\s*;|\s*$)/i.test(v)&&!hasSecure;
   if(noneWithoutSecure||missingSecure||missingHttpOnly){
    const flags=[...(missingSecure?['no-Secure']:[]),...(missingHttpOnly?['no-HttpOnly']:[]),...(noneWithoutSecure?['SameSite-None-without-Secure']:[])];
    out.push(rule('COOKIE_FLAGS',ctx,flags,{classification:'session-like-cookie-name',confidence:'structural-review'}));
    break;
   }
  }
 }
 if(stage==='redirect'){
  const target=String(d.redirectUrl||'');const to=origin(target),next=queryInfo(target);
  if(to&&to!==originUrl&&next.code.length){
   out.push(rule('OAUTH_REDIRECT_DATA',ctx,next.code,{scope:'cross-origin',classification:'auth-callback-parameter',confidence:'exact-observation'}));
  }
 }
 return out;
}
// HAR is read in-memory by the dashboard only. Never modify source or retain raw headers.
function analyzeHar(value,maxEntries=3000){
 let har=value;
 if(typeof har==='string'){
  if(har.length>12*1024*1024)return {ok:false,reason:'HAR exceeds 12 MB analysis cap'};
  try{har=JSON.parse(har);}catch{return {ok:false,reason:'Invalid HAR JSON'};}
 }
 const rows=har?.log?.entries;
 if(!Array.isArray(rows))return {ok:false,reason:'No HAR log.entries array'};
 const result=[],limit=Math.max(0,Math.min(3000,Number(maxEntries)||3000));
 for(let i=0;i<Math.min(rows.length,limit);i++){
  const e=rows[i]||{},req=e.request||{},resp=e.response||{};
  const at=Date.parse(e.startedDateTime)||Date.now();
  const originHeader=headers(req.headers).get('origin')||'';
  const params=Array.isArray(req.postData?.params)?req.postData.params.slice(0,100):[];
  // HAR supplies form names separately; never inspect postData.text or values.
  const formData=Object.create(null);
  for(const item of params){if(typeof item?.name==='string'&&item.name.length<=70)formData[item.name]=[];}
  const base={url:req.url,method:req.method,timeStamp:at,requestId:'har-'+i,initiator:origin(originHeader),statusCode:resp.status,requestBody:{formData}};
  result.push(...classify('request',base),...classify('request-headers',{...base,requestHeaders:req.headers}));
  result.push(...classify('response-headers',{...base,responseHeaders:resp.headers}));
  let location=resp.redirectURL||headers(resp.headers).get('location')||'';
  if(location){try{location=new URL(location,req.url).href;}catch{location='';}}
  if(location)result.push(...classify('redirect',{...base,redirectUrl:location}));
 }
 return {ok:true,reviewed:Math.min(rows.length,limit),total:rows.length,truncated:rows.length>limit,observations:result.slice(0,1200),
  dropped:Math.max(0,result.length-1200),mode:'offline-har',limits:['No live request testing performed','The HAR may omit sensitive or blocked headers','A rule does not prove exploitable vulnerability']};
}
function summarize(items){const rows=[],map=new Map();for(const r of Array.isArray(items)?items:[]){
 if(!META[r?.ruleId])continue;
 const k=r.ruleId+'|'+r.severity+'|'+r.title,entry=map.get(k)||{ruleId:r.ruleId,title:r.title||META[r.ruleId][0],severity:r.severity||META[r.ruleId][1],count:0,confidence:r.confidence||'exact-observation'};
 entry.count++;map.set(k,entry);
}rows.push(...map.values());return rows.sort((a,b)=>b.count-a.count||a.ruleId.localeCompare(b.ruleId));}
root.THISecurityIntelligence={classify,analyzeHar,summarize,meta:META,version:VERSION};
if(typeof module!=='undefined'&&module.exports)module.exports=root.THISecurityIntelligence;
})(typeof self!=='undefined'?self:globalThis);
