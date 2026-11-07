'use strict';
const assert=require('node:assert/strict');const fs=require('node:fs');
const pim=require('../product_asset_intel.js');const flow=require('../hybrid_workflow_intel.js');
const refs=new Map();let n=0;const ref=(kind,id)=>{const key=kind+'|'+id;if(!refs.has(key))refs.set(key,'ref-'+String(++n).padStart(16,'0'));return refs.get(key);};
const example={product:{sku:'sku-test-001',attributes:{name:'Poster',material:'paper'},categories:[{code:'music-posters'}],locales:{en_GB:{title:'Poster'},fr_FR:{title:'Affiche'}},channels:[{code:'web-shop',published:true}],variants:[{id:'a',size:'A3'},{id:'b',size:'A2'}],assets:[{asset_id:'media-0042',role:'hero',rendition:'preview'}]}};
const x=pim.sanitize(pim.inspect(example,{status:200},ref));
for(const k of ['PRODUCT_RECORD','VARIANT_MATRIX','CATEGORY_TAXONOMY','ATTRIBUTE_ENRICHMENT','CHANNEL_PUBLICATION','DAM_ASSET_ASSOCIATION','MEDIA_RENDITION'])assert(x.labels.includes(k),k);
assert.equal(x.products.length,1);assert.equal(x.products[0].variantCount,2);
const media=pim.sanitizeMedia(pim.inspectMedia({url:'https://media.example.invalid/v1/assets/media-0042/preview?signature=SUPER_SECRET_123456789',status:200,mime:'image/jpeg'},ref));
assert.equal(media.assetRef,x.products[0].mediaRefs[0]);
assert.equal(media.httpDelivered,true);assert(!JSON.stringify(media).includes('SECRET'));
const report=pim.analyze({pimObservations:[x],pimMediaObservations:[media]});
assert.equal(report.overview.exactRelationships,0);assert.equal(report.overview.assetFamilyRelationships,1);assert.equal(report.overview.httpMediaDeliveries,0);assert.equal(report.overview.assetFamilyMediaResponses,1);
assert.equal(report.rows[0].delivery,'Related media response; rendition unverified');
assert(!JSON.stringify(report).includes('media-0042'));
assert(!JSON.stringify(report).includes('sku-test-001'));
assert(!JSON.stringify(report).includes('media.example.invalid'));
const unobserved=pim.analyze({pimObservations:[x],pimMediaObservations:[]});
assert.equal(unobserved.overview.exactRelationships,0);assert.equal(unobserved.overview.unverifiedRelations,1);
const distinct=pim.inspectMedia({url:'https://media.example.invalid/v1/assets/media-0043/preview',status:200,mime:'image/jpeg'},ref);
assert.equal(pim.analyze({pimObservations:[x],pimMediaObservations:[distinct]}).overview.exactRelationships,0);
const cart=pim.inspect({items:[{sku:'sku-test-001',unit_price:0,currency:'GBP'}],checkout_required:true},{status:200},ref);
assert(!cart.labels.includes('PRODUCT_RECORD'));assert(cart.labels.includes('COMMERCE_PRICE'));
const anon=pim.inspect({entries:[{code:'item-x',fields:[{key:'texture',value:'matte'}],media:{primary:{ref:'picture-z'}},regions:['GB','FR']}]},{status:200},ref);
assert(anon.labels.includes('PRODUCT_RECORD'));assert(anon.labels.includes('DAM_ASSET_ASSOCIATION'));
const logo=pim.inspectMedia({url:'https://media.example.invalid/files/Original_Master_Logo_4k.jpg',status:200,mime:'image/jpeg'},ref);
assert(logo);assert(!('originalDelivered' in logo));
const denied=pim.inspectMedia({url:'https://media.example.invalid/assets/media-0042/preview',status:403,mime:'image/jpeg'},ref);
assert(!denied.httpDelivered);
const deniedReport=pim.analyze({pimObservations:[x],pimMediaObservations:[denied]});assert.equal(deniedReport.overview.httpMediaDeliveries,0);assert.equal(deniedReport.overview.accessDenied,1);
let deep={sku:'x',attributes:{},assets:[{asset_id:'1'}]};for(let i=0;i<15;i++)deep={child:deep};assert(pim.inspect(deep,{},ref).coverage.truncated);
const cyc={sku:'cycle',attributes:{},categories:['a']};cyc.self=cyc;assert(pim.inspect(cyc,{},ref).labels.includes('PRODUCT_RECORD'));
const polluted={...x,products:[{...x.products[0],ref:'token-EXPLOIT',mediaRefs:['Bearer SECRET'],mediaRouteRefs:[x.products[0].mediaRefs[0]]}],session:'private',url:'https://s.example/?sig=secret'};
const clean=pim.sanitize(polluted);assert(!JSON.stringify(clean).includes('EXPLOIT'));assert(!JSON.stringify(clean).includes('Bearer'));assert(!JSON.stringify(clean).includes('private'));
assert.equal(pim.inspect({sku:'only-a-sku'}, {},ref).labels[0],'UNKNOWN');
assert.equal(pim.inspectMedia({url:'javascript:alert(1)',status:200,mime:'image/jpeg'},ref),null);
const hybrid=flow.analyze({origin:'https://frontend.example.invalid',requests:[
 {url:'https://frontend.example.invalid/',type:'main_frame',method:'GET',status:200,mime:'text/html'},
 {url:'https://frontend.example.invalid/v1/item',type:'xmlhttprequest',method:'GET',status:200,mime:'application/json'},
 {url:'https://api.example.invalid/jobs',type:'xmlhttprequest',method:'POST',status:202,mime:'application/json'},
 {url:'https://media.example.invalid/assets/media-0042/preview',type:'image',method:'GET',status:200,mime:'image/jpeg'},
 {url:'https://files.example.invalid/attachment',type:'other',method:'GET',status:200,mime:'application/zip',attachmentDisposition:true}],
 downloadEvents:[{stage:'download-state',downloadStatus:'complete',downloadRef:'local-only-1'}],pimObservations:[x],pimMediaObservations:[media]},pim.analyze({pimObservations:[x],pimMediaObservations:[media]}));
assert.equal(hybrid.overview.exactProductMediaMatches,0);assert.equal(hybrid.overview.externalOriginResponses,3);
assert(hybrid.rows.some(t=>t.name==='Browser download completions'));
assert(!JSON.stringify(hybrid).includes('local-only-1'));assert(!JSON.stringify(hybrid).includes('files.example.invalid'));
const main=fs.readFileSync('dashboard.js','utf8'),html=fs.readFileSync('dashboard.html','utf8'),bg=fs.readFileSync('background.js','utf8'),dev=fs.readFileSync('devtools.js','utf8'),devHTML=fs.readFileSync('devtools.html','utf8');
for(const n of ['product-assets','hybrid-workflow'])assert(html.includes('data-view="'+n+'"'));
assert(html.includes('product_asset_intel.js'));assert(html.includes('hybrid_workflow_intel.js'));
assert(devHTML.includes('product_asset_intel.js'));assert(dev.includes('THIProductAsset.inspect(data'));assert(dev.includes('PIM_MEDIA_OBSERVATION'));
assert(bg.includes('ingestPimMedia('));assert(bg.includes('THIProductAsset.sanitize(payload.pim)'));
assert(main.includes('renderProductAssetRelationships('));assert(main.includes('renderHybridWorkflow('));
assert(!/(?:fetch|XMLHttpRequest|WebSocket)\s*\(/.test(fs.readFileSync('product_asset_intel.js','utf8')));
console.log('PASS v7.17 generic PIM, rendition-aware and family-only correlation, unknown schema, false positives, redaction, coverage limits and UI wiring');
