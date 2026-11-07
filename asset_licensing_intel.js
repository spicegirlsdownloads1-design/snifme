/* v7.14: vendor-neutral, opt-in licensing response intelligence.
 * Never return response values, raw IDs, URLs, filenames, descriptions,
 * credential-like strings, or source JSON. The in-memory caller provides
 * random, nonreversible identifiers. No network or Chrome APIs here. */
(function(root,factory){
  const api=factory();
  if(typeof module==='object'&&module.exports)module.exports=api;
  else root.THIAssetLicensing=api;
})(typeof globalThis!=='undefined'?globalThis:this,function(){
'use strict';
const CLASSES=new Set(['LICENSE_METADATA','ASSET_METADATA','PRICING_METADATA','SIZE_CATALOGUE','PREVIEW_DELIVERY','DOWNLOAD_ELIGIBILITY','DOWNLOAD_REQUEST','DOWNLOAD_RESPONSE','ORIGINAL_DELIVERY_CONFIRMED','UNKNOWN']);
const OBS_LIMIT=50, NODE_LIMIT=900, DEPTH_LIMIT=9;
const key=k=>String(k).replace(/[^a-z0-9]/ig,'').toLowerCase();
const asNum=(n,max=1e9)=>typeof n==='number'&&Number.isFinite(n)&&n>=0&&n<=max?n:null;
const asBool=x=>typeof x==='boolean'?x:null;
const safeRef=x=>typeof x==='string'&&/^ref-[a-f0-9-]{12,55}$/i.test(x)?x:null;
const maybe=(o,...keys)=>{if(!o||typeof o!=='object'||Array.isArray(o))return undefined;for(const [k,v] of Object.entries(o)){if(keys.includes(key(k)))return v;}return undefined;};
const textKind=(s)=>{
 if(typeof s!=='string'||s.length>240)return 'other';
 const a=s.toLowerCase();
 if(/\b(?:original|full[ -]?size|native resolution|uncompressed master)\b/.test(a))return 'original';
 if(/\b(?:thumbnail|thumb|icon|small preview)\b/.test(a))return 'thumbnail';
 if(/\b(?:preview|watermarked|watermark|sample)\b/.test(a))return 'preview';
 if(/\b(?:web|screen|online|digital)\b/.test(a))return 'web';
 if(/\b(?:print|press|editorial|magazine|newspaper)\b/.test(a))return 'print';
 return 'other';
};
const usageKind=(s)=>{
 if(typeof s!=='string')return 'unspecified';
 if(/editorial|newspaper|press|magazine/i.test(s))return 'editorial';
 if(/commercial|advertising|promotional|marketing/i.test(s))return 'commercial';
 if(/social|website|digital|web use/i.test(s))return 'digital';
 if(/broadcast|television|video/i.test(s))return 'broadcast';
 return 'other';
};
function inspect(root,meta={},anon){
 const ref=typeof anon==='function'?anon:((kind,value)=>'ref-'+('0000000000000000000'+String(++counter)).slice(-19));let counter=0;
 const o={categories:[],assetRef:null,licences:[],sizes:[],prices:[],status:'Not verified',evidence:['DevTools JSON response'],limits:[],checkedNodes:0,original:{advertised:false,selectable:false,authorised:false,delivered:false,status:'Not verified'}};
 const cats=new Set();const seen=new WeakSet();let truncated=false;
 const sourceMeta={status:Number(meta.status)||null,method:String(meta.method||'GET').slice(0,8)};
 function idRef(kind,v){if((typeof v!=='string'&&typeof v!=='number')||String(v).length>100)return null;const r=ref(kind,String(v));return safeRef(r)?r:null;}
 // URLs are examined only in-memory. A route-specific ID can help link
 // the same asset across ordinary observed endpoints without persisting it.
 // Reject arbitrary final segments unless an asset-related path precedes them.
 if(meta&&typeof meta.url==='string'&&meta.url.length<4096){
   try{
     const u=new URL(meta.url);
     if(/^https?:$/.test(u.protocol)){
       const parts=u.pathname.split('/').filter(Boolean);
       const last=parts.at(-1)||'';
       const parent=parts.slice(0,-1).join('/').toLowerCase();
       if(/(?:^|\/)(?:asset|assets|image|images|photo|photos|media)(?:\/|$)|(?:^|\/)licen[sc]e\/(?:available|options)(?:\/|$)/.test(parent)&&/^(?:[0-9]{2,20}|[a-f0-9-]{18,40})$/i.test(last)){
         o.assetRef=idRef('asset',last);
       }
     }
   }catch{}
 }
 function visit(obj,level,parentLicense=null){
  if(!obj||typeof obj!=='object'||seen.has(obj)||o.checkedNodes>=NODE_LIMIT||level>DEPTH_LIMIT){if(level>DEPTH_LIMIT||o.checkedNodes>=NODE_LIMIT)truncated=true;return;}
  seen.add(obj);o.checkedNodes++;
  if(Array.isArray(obj)){for(const node of obj.slice(0,100))visit(node,level+1,parentLicense);if(obj.length>100)truncated=true;return;}
  const entries=Object.entries(obj).slice(0,80);
  if(Object.keys(obj).length>80)truncated=true;
  const sizeId=maybe(obj,'downloadsizeid','sizeid');
  const licenseId=maybe(obj,'ecomlicenseid','licenseid','licenceid','licenceuuid','licenseuuid');
  const assetId=maybe(obj,'assetid','imageid','photoid','mediaid','productid');
  const sizeName=maybe(obj,'name','label','title','sizename','downloadsizename');
  const children=maybe(obj,'children','sublicenses','sublicences');
  const sizes=maybe(obj,'downloadsizes','imagesizes','availabledownloadsizes','availablesizes','resolutions','sizeoptions');
  const selectable=asBool(maybe(obj,'selectable','canselect','isselectable'));
  const allowed=asBool(maybe(obj,'downloadallowed','candownload','entitled','hasentitlement','downloadeligible'));
  const rawPrice=maybe(obj,'price','netprice','baseprice','grossprice','amount','totalprice');
  const net=asNum(maybe(obj,'netprice','netamount','pricebeforetax'));
  const gross=asNum(maybe(obj,'grossprice','grossamount','priceincludingtax'));
  const base=asNum(maybe(obj,'baseprice'));
  const credits=asNum(maybe(obj,'credits','creditcost','requiredcredits'),1000000);
  const factor=asNum(maybe(obj,'pricefactor','pricingfactor','multiplier'),10000);
  const surcharge=asNum(maybe(obj,'surcharge','additionalfee'));
  const explicitlyFree=asBool(maybe(obj,'free','isfree','freelicense','freelicence'))===true;
  const price=asNum(rawPrice);
  const currencyValue=maybe(obj,'currency','currencycode','currencyiso');
  const currency=typeof currencyValue==='string'&&/^[A-Za-z]{3}$/.test(currencyValue)?currencyValue.toUpperCase():null;
  const tax=asNum(maybe(obj,'taxrate','taxpercent','vatrate','taxpercentage'),100);
  const width=asNum(maybe(obj,'width','pixelwidth','imagewidth'),200000);
  const height=asNum(maybe(obj,'height','pixelheight','imageheight'),200000);
  const recommended=asBool(maybe(obj,'recommended','isrecommended'));
  const originalFlag=asBool(maybe(obj,'isoriginal','originalsize','isfullsize'));
  const labelPixels=(()=>{if(typeof sizeName!=='string')return null;const m=/\b(\d{2,6})\s*(?:pixels|px)\b/i.exec(sizeName);return m?asNum(Number(m[1]),200000):null;})();
  if(assetId!==undefined){o.assetRef ||= idRef('asset',assetId);cats.add('ASSET_METADATA');}
  const looksLicense=licenseId!==undefined || (children!==undefined && (selectable!==null || sizes!==undefined));
  const looksSize=sizeId!==undefined && (sizeName!==undefined||recommended!==null||width!==null);
  let currentLicense=parentLicense;
  if(looksLicense){
    cats.add('LICENSE_METADATA');
    const licenseRef=idRef('licence',licenseId) || ref('synthetic-licence',`${level}:${o.checkedNodes}`);
    currentLicense=safeRef(licenseRef)?licenseRef:null;
    const recommendedSizeRef=idRef('size',maybe(obj,'recommendeddownloadsizeid'));
    const maxSizeRef=idRef('size',maybe(obj,'maxdownloadsizeid'));
    if(o.licences.length<OBS_LIMIT)o.licences.push({ref:currentLicense,parentRef:parentLicense,selectable,allowed,usage:usageKind(sizeName),hasChildren:Array.isArray(children)&&children.length>0,recommendedSizeRef,maxSizeRef});
    if(allowed!==null)cats.add('DOWNLOAD_ELIGIBILITY');
    if(price!==null){cats.add('PRICING_METADATA');if(o.prices.length<OBS_LIMIT)o.prices.push({licenceRef:currentLicense,amount:price,net,gross,base,credits,factor,surcharge,currency,tax,kind:selectable===false?'non-selectable parent':explicitlyFree&&selectable===true&&allowed===true?'explicit free flag (entitlement observed)':selectable===true?'selectable licence':'conditional/unknown'});}
  }
  if(looksSize){
    cats.add('SIZE_CATALOGUE');
    const type=originalFlag===true?'original':textKind(sizeName);
    const sr=idRef('size',sizeId);
    if(o.sizes.length<OBS_LIMIT)o.sizes.push({ref:sr,licenceRef:currentLicense,type,width,height,labelPixels,recommended,selectable});
    if(type==='original'){
      o.original.advertised=true;
      // `selectable` belongs to the licence or the size, never its parent.
      if(selectable===true||(selectable===null&&looksLicense&&asBool(maybe(obj,'selectable'))===true))o.original.selectable=true;
      if(allowed===true)o.original.authorised=true;
    }
  }
  if(Array.isArray(sizes)&&sizes.length){cats.add('SIZE_CATALOGUE');}
  if(price!==null&&!looksLicense){cats.add('PRICING_METADATA');if(o.prices.length<OBS_LIMIT)o.prices.push({licenceRef:currentLicense,amount:price,net,gross,base,credits,factor,surcharge,currency,tax,kind:'conditional/unknown'});}
  if(allowed!==null)cats.add('DOWNLOAD_ELIGIBILITY');
  for(const [k,v] of entries){
    const name=key(k);
    if(name==='licenses'||name==='licences'||name==='availablelicenses'||name==='availablelicences')cats.add('LICENSE_METADATA');
    if(name==='downloadsizes'||name==='availablesizes'||name==='resolutions')cats.add('SIZE_CATALOGUE');
    if(name==='prices'||name==='pricing'||name==='priceoptions')cats.add('PRICING_METADATA');
    if(v&&typeof v==='object')visit(v,level+1,currentLicense);
  }
 }
 visit(root,0,null);
 // Stronger selectable signal: original size belongs directly to a selectable licence.
 const lic=new Map(o.licences.map(x=>[x.ref,x]));
 for(const s of o.sizes){if(s.type!=='original')continue;const parent=lic.get(s.licenceRef);if(s.selectable===true||parent?.selectable===true)o.original.selectable=true;if(parent?.allowed===true)o.original.authorised=true;}
 // No parsed listing can establish that original bytes were delivered.
 o.original.delivered=false;
 o.original.status=o.original.authorised?'Conditional':o.original.selectable?'Conditional':o.original.advertised?'Advertised only':'Not verified';
 if(sourceMeta.status===401||sourceMeta.status===403)o.status='Access denied';
 else if(o.original.advertised)o.status=o.original.status;
 else if(o.licences.length||o.sizes.length)o.status='Conditional';
 if(truncated)o.limits.push('JSON depth, node, field or entry safety cap reached');
 if(!cats.size){o.categories=['UNKNOWN'];o.assetRef=null;}else o.categories=[...cats].filter(x=>CLASSES.has(x));
 if(!o.categories.includes('UNKNOWN'))o.evidence.push('Observed licensing / asset field structure');
 return o;
}
function sanitize(input){
 if(!input||typeof input!=='object'||Array.isArray(input))return null;
 const o={categories:[],assetRef:safeRef(input.assetRef),licences:[],sizes:[],prices:[],status:'Not verified',original:{advertised:false,selectable:false,authorised:false,delivered:false,status:'Not verified'},limits:[]};
 const statuses=new Set(['Confirmed','Advertised only','Conditional','Not verified','Access denied']);
 o.categories=(Array.isArray(input.categories)?input.categories:[]).filter(x=>CLASSES.has(x)&&x!=='ORIGINAL_DELIVERY_CONFIRMED').slice(0,10);
 for(const li of (Array.isArray(input.licences)?input.licences:[]).slice(0,OBS_LIMIT)){
  if(!li||typeof li!=='object')continue;
  o.licences.push({ref:safeRef(li.ref),parentRef:safeRef(li.parentRef),selectable:asBool(li.selectable),allowed:asBool(li.allowed),usage:['editorial','commercial','digital','broadcast','other','unspecified'].includes(li.usage)?li.usage:'unspecified',hasChildren:li.hasChildren===true,recommendedSizeRef:safeRef(li.recommendedSizeRef),maxSizeRef:safeRef(li.maxSizeRef)});
 }
 for(const sz of (Array.isArray(input.sizes)?input.sizes:[]).slice(0,OBS_LIMIT)){
  if(!sz||typeof sz!=='object')continue;
  o.sizes.push({ref:safeRef(sz.ref),licenceRef:safeRef(sz.licenceRef),type:['original','thumbnail','preview','web','print','other'].includes(sz.type)?sz.type:'other',width:asNum(sz.width,200000),height:asNum(sz.height,200000),labelPixels:asNum(sz.labelPixels,200000),recommended:asBool(sz.recommended),selectable:asBool(sz.selectable)});
 }
 for(const p of (Array.isArray(input.prices)?input.prices:[]).slice(0,OBS_LIMIT)){
  if(!p||typeof p!=='object')continue;
  o.prices.push({licenceRef:safeRef(p.licenceRef),amount:asNum(p.amount),net:asNum(p.net),gross:asNum(p.gross),base:asNum(p.base),credits:asNum(p.credits,1000000),factor:asNum(p.factor,10000),surcharge:asNum(p.surcharge),currency:typeof p.currency==='string'&&/^[A-Z]{3}$/.test(p.currency)?p.currency:null,tax:asNum(p.tax,100),kind:['non-selectable parent','selectable licence','conditional/unknown','explicit free flag (entitlement observed)'].includes(p.kind)?p.kind:'conditional/unknown'});
 }
 o.original.advertised=o.sizes.some(s=>s.type==='original');
 o.original.selectable=o.sizes.some(s=>s.type==='original'&&(s.selectable===true||o.licences.some(l=>l.ref&&l.ref===s.licenceRef&&l.selectable===true)));
 o.original.authorised=o.sizes.some(s=>s.type==='original'&&o.licences.some(l=>l.ref&&l.ref===s.licenceRef&&l.allowed===true));
 o.original.status=o.original.authorised||o.original.selectable?'Conditional':o.original.advertised?'Advertised only':'Not verified';
 o.status=statuses.has(input.status)?input.status:o.original.status;
 o.limits=(Array.isArray(input.limits)?input.limits:[]).filter(s=>s==='JSON depth, node, field or entry safety cap reached').slice(0,1);
 if(!o.categories.length)o.categories=['UNKNOWN'];
 return o;
}
function analyze(record){
 const observations=Array.isArray(record?.licensingObservations)?record.licensingObservations:[];
 const requests=Array.isArray(record?.requests)?record.requests:[];
 const downloads=Array.isArray(record?.downloadEvents)?record.downloadEvents:[];
 const count={LICENSE_METADATA:0,ASSET_METADATA:0,PRICING_METADATA:0,SIZE_CATALOGUE:0,PREVIEW_DELIVERY:0,DOWNLOAD_ELIGIBILITY:0,DOWNLOAD_REQUEST:0,DOWNLOAD_RESPONSE:0,ORIGINAL_DELIVERY_CONFIRMED:0,UNKNOWN:0};
 let advertised=0,selectable=0,authorised=0,denied=0;
 for(const o of observations){
   for(const type of new Set(o.categories||[]))if(type in count)count[type]++;
   if(o.original?.advertised)advertised++;
   if(o.original?.selectable)selectable++;
   if(o.original?.authorised)authorised++;
   if(o.status==='Access denied')denied++;
 }
 let delivered=0;
 for(const r of requests){
  if(!r||typeof r!=='object')continue;
  const u=typeof r.url==='string'?r.url:'';
  const path=(()=>{try{return new URL(u).pathname.toLowerCase();}catch{return '';}})();
  const kind=String(r.mime||'').toLowerCase();
  const status=Number(r.status);
  if(status===200||status===206){
   if((kind.startsWith('image/')||kind.startsWith('video/'))&&/(?:^|[\/_.-])(?:preview(?:s)?|thumb(?:nail)?s?|small)(?:[\/_.-]|$)/.test(path))count.PREVIEW_DELIVERY++;
   if(r.attachmentDisposition===true||/application\/(?:zip|octet-stream|pdf)/.test(kind)){
     count.DOWNLOAD_RESPONSE++;delivered++;
   }
  }
  if(/(?:^|\/)(?:download|export|delivery|fulfil|fulfill)(?:\/|$)/.test(path)&&['POST','GET'].includes(String(r.method).toUpperCase()))count.DOWNLOAD_REQUEST++;
 }
 const deliveries=requests.filter(r=>r&&(r.status===200||r.status===206)&&(r.attachmentDisposition===true||/application\/(?:zip|octet-stream|pdf)/i.test(String(r.mime||'')))).slice(-40).map(r=>({method:['GET','POST','PUT','PATCH','HEAD'].includes(String(r.method))?r.method:'OTHER',status:r.status,mime:/^(?:image\/|video\/|application\/)(?:[a-z0-9.+-]{1,36})$/i.test(String(r.mime||''))?r.mime:'other',bytes:Number.isSafeInteger(r.bytes)&&r.bytes>=0?r.bytes:null,attachment:r.attachmentDisposition===true,original:'Not verified'}));
 const confirmedBrowserDownloads=new Set(downloads.filter(e=>e?.stage==='download-state'&&e.downloadStatus==='complete'&&typeof e.downloadRef==='string').map(e=>e.downloadRef)).size;
 const rows=Object.entries(count).filter(([k,v])=>v>0).map(([category,value])=>({category,count:value,basis:observations.length&&['LICENSE_METADATA','ASSET_METADATA','PRICING_METADATA','SIZE_CATALOGUE','DOWNLOAD_ELIGIBILITY'].includes(category)?'Opt-in JSON structure and bounded fields':'Observed HTTP metadata only',confidence:category==='ORIGINAL_DELIVERY_CONFIRMED'?'Not verified':category==='DOWNLOAD_RESPONSE'?'Confirmed HTTP response':'Observed only'}));
 return {version:'7.14',overview:{inspectedJSON:observations.length,originalAdvertised:advertised,originalSelectable:selectable,originalAuthorised:authorised,originalDeliveredVerified:0,httpFileResponses:delivered,browserDownloadsCompleted:confirmedBrowserDownloads,accessDenied:denied,dropped:Number(record?.licensingObservationsDropped||0)},rows,deliveries,observations:observations.map(o=>({at:o.at,method:o.method,httpStatus:o.httpStatus,assetRef:o.assetRef,categories:o.categories,licences:o.licences,sizes:o.sizes,prices:o.prices,original:o.original,status:o.status,limits:o.limits})),limitations:['No raw asset identifiers, credentials, descriptions, filenames, URLs or JSON bodies retained by this module.','Listings, size labels, zero prices and successful file transfers do not verify an original-resolution master.','Only responses inspected while DevTools is open and JSON inspection is enabled can yield licensing field values.','Anonymous references may reset when DevTools closes; unrelated requests are not associated by timing alone.','An HTTP file response is not the same as a completed browser download.']};
}
return Object.freeze({inspect,sanitize,analyze});
});
