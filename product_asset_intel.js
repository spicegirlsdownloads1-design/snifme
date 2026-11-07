/* Universal product/asset relationship intelligence v7.16.
 * Never stores input JSON, raw identifiers, media URLs, cookies or signatures.
 * All refs come from a caller-owned ephemeral map and are only meaningful
 * inside the same DevTools lifetime. No network or browser APIs. */
(function(root,factory){const api=factory();if(typeof module==='object'&&module.exports)module.exports=api;else root.THIProductAsset=api;})(typeof globalThis!=='undefined'?globalThis:this,function(){
'use strict';
const TYPES=Object.freeze(['PRODUCT_RECORD','VARIANT_MATRIX','CATEGORY_TAXONOMY','ATTRIBUTE_ENRICHMENT','CHANNEL_PUBLICATION','DAM_ASSET_ASSOCIATION','MEDIA_RENDITION','COMMERCE_PRICE','CATALOG_EXPORT','UNKNOWN']);
const goodRef=x=>typeof x==='string'&&/^ref-[a-f0-9-]{12,55}$/i.test(x)?x:null;
const normalize=k=>String(k).replace(/[^a-z0-9]/ig,'').toLowerCase();
const field=(o,keys)=>{if(!o||typeof o!=='object'||Array.isArray(o))return undefined;for(const [k,v] of Object.entries(o)){if(keys.includes(normalize(k)))return v;}};
const validId=v=>(typeof v==='string'||typeof v==='number')&&String(v).length>0&&String(v).length<=100;
const opaque=(anon,kind,v)=>validId(v)?goodRef(anon(kind,String(v))):null;
const LIMIT={nodes:650,depth:8,products:50,mediaRefs:80,entries:90};
function route(url){try{const u=new URL(url);return /^https?:$/.test(u.protocol)&&u.href.length<=4096?u.origin+u.pathname:null;}catch{return null;}}
// Rendition identity is deliberately stronger than asset-family/path identity.
// Only deterministic transformation parameters are included; secret/signing values
// are NEVER copied into saved summaries, or into a reference-map key.
const renditionParams=new Set(['w','width','h','height','q','quality','f','format','fm','fit','crop','resize','dpr','scale','size','sizeid','downloadsizeid','rendition','variant','auto','mode','gravity','bg','background']);
function renditionKey(url){
 try{
  const u=new URL(url);if(!/^https?:$/.test(u.protocol)||u.href.length>4096)return null;
  const details=[];let ambiguous=false;
  for(const [rawKey,rawValue] of u.searchParams){
   const key=normalize(rawKey);
   if(/^(?:xamz|xgoog|xms|awsaccesskeyid|signature|sig|token|auth|authorization|key|apikey|expires|expiry|exp|policy|credential|session|jwt|se|sp|sv|sr|st)$/.test(key)||/^(?:xamz|xgoog|xms)/.test(key))continue;
   if(!renditionParams.has(key)||rawValue.length>80||/[\x00-\x1f]/.test(rawValue)){ambiguous=true;break;}
   details.push([key,rawValue]);
  }
  if(ambiguous)return null;
  details.sort((a,b)=>a[0].localeCompare(b[0])||a[1].localeCompare(b[1]));
  return u.origin+u.pathname+'?'+details.map(([k,v])=>encodeURIComponent(k)+'='+encodeURIComponent(v)).join('&');
 }catch{return null;}
}
const mediaDirectories=new Set(['asset','assets','media','image','images','photo','photos','file','files','rendition','renditions']);
const metaWords=new Set(['thumbnail','thumb','preview','original','master','rendition','resize','download','file','image','images','medium','large','small','web']);
function routeAssetId(url){
 try{const u=new URL(url);if(!/^https?:$/.test(u.protocol))return null;
 const p=u.pathname.split('/').filter(Boolean);
 for(let i=0;i<p.length-1;i++)if(mediaDirectories.has(p[i].toLowerCase())){
   const candidate=decodeURIComponent(p[i+1]);
   if(candidate.length>=3&&candidate.length<=100&&!metaWords.has(candidate.toLowerCase())&&!/\.(?:jpg|png|jpeg|pdf|webp|gif|svg|mp4|zip)$/i.test(candidate))return candidate;
 }return null;
 }catch{return null;}
}
function inspect(value,meta={},anon){
 const local=new Map();const make=typeof anon==='function'?anon:(k,v)=>{const t=k+'|'+v;if(!local.has(t))local.set(t,'ref-'+String(local.size+1).padStart(16,'0'));return local.get(t);};
 const labels=new Set(),seen=new WeakSet(),productMap=new Map();let nodes=0,truncated=false;
 const summary={version:'7.17',labels:[],products:[],mediaRefs:[],mediaRouteRefs:[],mediaRenditionRefs:[],priceRecords:0,coverage:{nodes:0,truncated:false},status:Number(meta.status)||null};
 const mediaRefs=new Set(),mediaRoutes=new Set(),mediaRenditions=new Set();
 function walk(obj,depth,withinProduct=false){
  if(!obj||typeof obj!=='object'||seen.has(obj))return;
  if(depth>LIMIT.depth||nodes>=LIMIT.nodes){truncated=true;return;}
  seen.add(obj);nodes++;
  if(Array.isArray(obj)){for(const entry of obj.slice(0,LIMIT.entries))walk(entry,depth+1,withinProduct);if(obj.length>LIMIT.entries)truncated=true;return;}
  const rawKeys=Object.keys(obj);if(rawKeys.length>LIMIT.entries)truncated=true;
  const keys=new Set(rawKeys.slice(0,LIMIT.entries).map(normalize));
  const ident=field(obj,['sku','productid','productcode','itemcode','itemid','productsku','code']);
  const attributes=field(obj,['attributes','properties','specifications','specs','fields']);
  const variants=field(obj,['variants','variations','productvariants','variantoptions']);
  const categories=field(obj,['categories','families','productcategories','taxonomies','category']);
  const channels=field(obj,['channels','saleschannels','distributionchannels','syndication','publicationchannels']);
  const locales=field(obj,['locales','translations','localized','localisations','localizations','languages','regions']);
  const assets=field(obj,['assets','media','images','pictures','assetlinks','mediaassets','imageassets','gallery']);
  const price=field(obj,['price','unitprice','amount','saleprice','baseprice','grossprice']);
  if(price!==undefined&&(typeof price==='number'||typeof price==='object')){labels.add('COMMERCE_PRICE');summary.priceRecords=Math.min(100,summary.priceRecords+1);}
  // A SKU or a cart line alone must not count as a product record.
  const traits=[attributes,variants,categories,channels,locales,assets].filter(x=>x!==undefined);
  const productLike=validId(ident)&&traits.length>=2;
  if(productLike){
   labels.add('PRODUCT_RECORD');
   const ref=opaque(make,'product',ident);
   if(ref&&!productMap.has(ref)&&productMap.size<LIMIT.products){
    const item={ref,variantCount:Array.isArray(variants)?Math.min(variants.length,1000):0,
     attributeCount:attributes&&typeof attributes==='object'?Math.min(Object.keys(attributes).length,1000):0,
     categoryCount:Array.isArray(categories)?Math.min(categories.length,1000):categories!==undefined?1:0,
     localeCount:locales&&typeof locales==='object'?Math.min(Object.keys(locales).length,1000):0,
     channelCount:Array.isArray(channels)?Math.min(channels.length,1000):channels!==undefined?1:0,
     mediaRefs:[],mediaRouteRefs:[],mediaRenditionRefs:[]};
    productMap.set(ref,item);
   }
   if(Array.isArray(variants)&&variants.length)labels.add('VARIANT_MATRIX');
   if(categories!==undefined)labels.add('CATEGORY_TAXONOMY');
   if(attributes!==undefined||locales!==undefined)labels.add('ATTRIBUTE_ENRICHMENT');
   if(channels!==undefined)labels.add('CHANNEL_PUBLICATION');
   if(assets!==undefined){
    const all=[];const urls=[];const renditions=[];
    const scanMedia=(node,n=0)=>{if(n>4||!node||typeof node!=='object')return;
     if(Array.isArray(node)){for(const v of node.slice(0,50))scanMedia(v,n+1);return;}
     const id=field(node,['assetid','mediaid','imageid','pictureid','fileid','assetref','mediaref','ref']);
     if(validId(id)){const r=opaque(make,'asset',id);if(r)all.push(r);}
     const v=field(node,['url','src','mediaurl','imageurl','downloadurl','previewurl','fileurl','href']);
     if(typeof v==='string'){
      const base=route(v);if(base){const r=opaque(make,'media-route',base);if(r)urls.push(r);}
      const variant=renditionKey(v);if(variant){const r=opaque(make,'media-rendition',variant);if(r)renditions.push(r);}
     }
     for(const [k,v] of Object.entries(node).slice(0,50))if(typeof v==='object'&&v!==null)scanMedia(v,n+1);
    };
    scanMedia(assets);
    if(all.length||urls.length||renditions.length){labels.add('DAM_ASSET_ASSOCIATION');
     const prod=productMap.get(ref);if(prod){prod.mediaRefs=[...new Set(all)].slice(0,50);prod.mediaRouteRefs=[...new Set(urls)].slice(0,50);prod.mediaRenditionRefs=[...new Set(renditions)].slice(0,50);}
     for(const x of all)mediaRefs.add(x);for(const x of urls)mediaRoutes.add(x);for(const x of renditions)mediaRenditions.add(x);
    }
   }
  }
  // A record with product-related fields but no product identity is not a PIM claim.
  if(keys.has('downloadurl')||keys.has('rendition')||keys.has('transformation'))labels.add('MEDIA_RENDITION');
  if(keys.has('channelpublished')||keys.has('publishstatus'))labels.add('CHANNEL_PUBLICATION');
  // Explicit export task evidence still requires matching HTTP response for confirmation.
  if(keys.has('catalogexport')||keys.has('exportjobid'))labels.add('CATALOG_EXPORT');
  for(const child of Object.values(obj).slice(0,LIMIT.entries))if(child&&typeof child==='object')walk(child,depth+1,productLike||withinProduct);
 }
 walk(value,0);
 summary.coverage={nodes,truncated};summary.labels=labels.size?[...labels]:['UNKNOWN'];summary.products=[...productMap.values()];
 summary.mediaRefs=[...mediaRefs].slice(0,LIMIT.mediaRefs);summary.mediaRouteRefs=[...mediaRoutes].slice(0,LIMIT.mediaRefs);summary.mediaRenditionRefs=[...mediaRenditions].slice(0,LIMIT.mediaRefs);
 return summary;
}
function inspectMedia(meta,anon){
 if(typeof anon!=='function')return null;
 const base=route(meta?.url);if(!base)return null;
 const status=Number(meta?.status);
 const mime=String(meta?.mime||'').toLowerCase().split(';')[0].trim();
 if(!/^(?:image|video|audio)\/[a-z0-9.+-]{1,55}$/.test(mime))return null;
 const ref=opaque(anon,'media-route',base);
 const variant=renditionKey(meta.url);
 const id=routeAssetId(meta.url);
 return {routeRef:ref,renditionRef:variant?opaque(anon,'media-rendition',variant):null,assetRef:id?opaque(anon,'asset',id):null,
  status:Number.isInteger(status)&&status>=100&&status<=599?status:null,
  mimeClass:mime.split('/')[0],httpDelivered:status===200||status===206,
  source:'DevTools observed media response'};
}
function sanitize(x){
 if(!x||typeof x!=='object'||Array.isArray(x))return null;
 const labels=(Array.isArray(x.labels)?x.labels:[]).filter(v=>TYPES.includes(v)).slice(0,10);
 const unique=(xs,n=80)=>[...new Set((Array.isArray(xs)?xs:[]).map(goodRef).filter(Boolean))].slice(0,n);
 const count=v=>Number.isSafeInteger(v)&&v>=0&&v<=1000?v:0;
 const products=(Array.isArray(x.products)?x.products:[]).slice(0,50).map(p=>({ref:goodRef(p?.ref),variantCount:count(p?.variantCount),attributeCount:count(p?.attributeCount),categoryCount:count(p?.categoryCount),localeCount:count(p?.localeCount),channelCount:count(p?.channelCount),mediaRefs:unique(p?.mediaRefs,50),mediaRouteRefs:unique(p?.mediaRouteRefs,50),mediaRenditionRefs:unique(p?.mediaRenditionRefs,50)})).filter(p=>p.ref);
 return {version:'7.17',labels:labels.length?labels:['UNKNOWN'],products,mediaRefs:unique(x.mediaRefs),mediaRouteRefs:unique(x.mediaRouteRefs),mediaRenditionRefs:unique(x.mediaRenditionRefs),priceRecords:count(x.priceRecords),coverage:{nodes:count(x.coverage?.nodes),truncated:x.coverage?.truncated===true},status:Number.isInteger(x.status)&&x.status>=100&&x.status<=599?x.status:null};
}
function sanitizeMedia(x){if(!x||typeof x!=='object')return null;
 const status=Number(x.status);
 return {routeRef:goodRef(x.routeRef),renditionRef:goodRef(x.renditionRef),assetRef:goodRef(x.assetRef),status:Number.isInteger(status)&&status>=100&&status<=599?status:null,mimeClass:['image','video','audio'].includes(x.mimeClass)?x.mimeClass:'other',httpDelivered:x.httpDelivered===true&&[200,206].includes(status)};
}
function analyze(rec){
 const observations=(Array.isArray(rec?.pimObservations)?rec.pimObservations:[]).map(sanitize).filter(Boolean);
 const media=(Array.isArray(rec?.pimMediaObservations)?rec.pimMediaObservations:[]).map(sanitizeMedia).filter(Boolean);
 const mediaById=new Map(),mediaByRoute=new Map(),mediaByRendition=new Map();
 const push=(map,key,item)=>{if(!key)return;if(!map.has(key))map.set(key,[]);map.get(key).push(item);};
 for(const m of media){push(mediaById,m.assetRef,m);push(mediaByRoute,m.routeRef,m);push(mediaByRendition,m.renditionRef,m);}
 let exact=0,family=0,unverified=0,successful=0,familyResponses=0,denied=0,products=0,anonymous=0,clipped=0;
 const rows=[];const categories=new Map();
 for(const obs of observations){for(const label of new Set(obs.labels))categories.set(label,(categories.get(label)||0)+1);products+=obs.products.length;if(obs.coverage.truncated)clipped++;
  for(const p of obs.products){
   const exactMatches=[...new Set(p.mediaRenditionRefs.flatMap(id=>mediaByRendition.get(id)||[]))];
   const familyMatches=[...new Set([...p.mediaRefs.flatMap(id=>mediaById.get(id)||[]),...p.mediaRouteRefs.flatMap(id=>mediaByRoute.get(id)||[])])];
   const matches=exactMatches.length?exactMatches:familyMatches;
   if(exactMatches.length){exact++;if(exactMatches.some(m=>m.httpDelivered))successful++;}
   else if(familyMatches.length){family++;if(familyMatches.some(m=>m.httpDelivered))familyResponses++;}
   else if(p.mediaRefs.length||p.mediaRouteRefs.length||p.mediaRenditionRefs.length)unverified++;
   if(matches.some(m=>m.status===401||m.status===403))denied++;
   rows.push({productRef:p.ref,variants:p.variantCount,assets:p.mediaRefs.length+p.mediaRouteRefs.length+p.mediaRenditionRefs.length,channels:p.channelCount,locales:p.localeCount,
    confidence:exactMatches.length?'Matching rendition descriptor (observed HTTP)':familyMatches.length?'Shared asset family; rendition unverified':'Advertised relation only',
    delivery:exactMatches.some(m=>m.httpDelivered)?'Matching rendition HTTP response observed':familyMatches.some(m=>m.httpDelivered)?'Related media response; rendition unverified':matches.length?'Response observed; not delivered':'Not verified'});
  }
  if(obs.labels.length===1&&obs.labels[0]==='UNKNOWN')anonymous++;
 }
 const types=[...categories].map(([label,count])=>({label,count,evidence:'Bounded DevTools JSON classification',qualification:'Technology/vendor unidentified'}));
 return {version:'7.17',overview:{jsonResponses:observations.length,productRecords:products,mediaResponses:media.length,exactRelationships:exact,assetFamilyRelationships:family,httpMediaDeliveries:successful,assetFamilyMediaResponses:familyResponses,unverifiedRelations:unverified,accessDenied:denied,truncatedJSON:clipped,unknown:anonymous,dropped:Number(rec?.pimObservationsDropped||0)+Number(rec?.pimMediaDropped||0)},types,rows:rows.slice(-100),limits:['A shared asset ID or path supports an asset-family association; it does not prove the same rendition or identical bytes.','A matching rendition descriptor is not proof of the same binary, native original resolution, entitlement or download completion.','Unknown query parameters prevent an exact rendition match; signing values are never copied to stored references.','DevTools must be open for JSON fields and media linkage; previously loaded traffic cannot be reconstructed.']};
}
return Object.freeze({inspect,inspectMedia,sanitize,sanitizeMedia,analyze});
});
