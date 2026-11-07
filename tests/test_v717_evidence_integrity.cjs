'use strict';
const assert=require('node:assert/strict');
const THIProductAsset=require('../product_asset_intel.js');
const THIVault=require('../evidence_vault.js');
const THIHybridWorkflow=require('../hybrid_workflow_intel.js');
const refs=new Map();let n=0;
const anon=(kind,raw)=>{const key=kind+'|'+raw;if(!refs.has(key))refs.set(key,'ref-'+String(++n).padStart(16,'0'));return refs.get(key);};
const base='https://media.example.invalid/images/asset-X';
const productJson={items:[{sku:'poster-X',attributes:{title:'Poster'},categories:['memorabilia'],images:[{url:base+'?width=1024&format=webp&signature=PRIVATE123'}]}]};
const product=THIProductAsset.sanitize(THIProductAsset.inspect(productJson,{status:200},anon));
assert.equal(product.products.length,1);
const small=THIProductAsset.sanitizeMedia(THIProductAsset.inspectMedia({url:base+'?width=32&format=jpeg&signature=PRIVATE456',status:200,mime:'image/jpeg'},anon));
const falseMatch=THIProductAsset.analyze({pimObservations:[product],pimMediaObservations:[small]});
assert.equal(falseMatch.overview.exactRelationships,0,'different transformations are not exact');
assert.equal(falseMatch.overview.assetFamilyRelationships,1,'same path may establish asset family only');
assert.equal(falseMatch.rows[0].confidence,'Shared asset family; rendition unverified');
assert.equal(falseMatch.overview.httpMediaDeliveries,0);
const matching=THIProductAsset.sanitizeMedia(THIProductAsset.inspectMedia({url:base+'?format=webp&width=1024&signature=SECOND_TOKEN',status:200,mime:'image/webp'},anon));
const yes=THIProductAsset.analyze({pimObservations:[product],pimMediaObservations:[matching]});
assert.equal(yes.overview.exactRelationships,1,'identical transformation descriptors correlate');
assert.equal(yes.overview.httpMediaDeliveries,1);
const ambiguous=THIProductAsset.sanitizeMedia(THIProductAsset.inspectMedia({url:base+'?width=1024&format=webp&opaqueProviderParameter=unknown',status:200,mime:'image/webp'},anon));
const unknown=THIProductAsset.analyze({pimObservations:[product],pimMediaObservations:[ambiguous]});
assert.equal(unknown.overview.exactRelationships,0,'unknown query parameter prevents rendition-level correlation');
const safeStr=JSON.stringify([product,small,matching,ambiguous,falseMatch,yes,unknown]);
for(const secret of ['PRIVATE123','PRIVATE456','SECOND_TOKEN','poster-X','asset-X','media.example.invalid'])assert(!safeStr.includes(secret),secret);
assert.equal(THIHybridWorkflow.analyze({requests:[],pimObservations:[product],pimMediaObservations:[small]},falseMatch).overview.assetFamilyProductMediaMatches,1);

const record={origin:'https://store.example.invalid',createdAt:'2026-11-06T10:00:00.000Z',
 pimObservations:[product],pimMediaObservations:[matching],
 licensingObservations:[{categories:['LICENSE_METADATA'],licences:[{ref:'ref-0123456789abcdef',selectable:true}],at:'2026-11-06T10:01:00.000Z'}],
 downloadEvents:[{stage:'download-state',downloadRef:'DL12345678901230001',downloadStatus:'complete'}],
 frameCoverage:[{frameId:2,origin:'https://store.example.invalid',observed:true}],
 workerScripts:[{kind:'worker',source:'https://store.example.invalid/worker.js'}],
 requests:[{status:200,url:'https://store.example.invalid/items'}],
 downloadEventsDropped:2,pimMediaDropped:3,pimObservationsDropped:1,licensingObservationsDropped:4,
 counters:{requestsDropped:3,assetsDropped:2},
 password:'TOPLEVEL_SECRET',internalUnsupported:[{opaque:'TOPLEVEL_SECRET'}]};
const imported=THIVault.sanitizeImport({format:'trufflehog-vault-session',version:1,record},
 (v)=>{try{const u=new URL(v);return u.origin+u.pathname;}catch{return '';}});
for(const field of ['pimObservations','pimMediaObservations','licensingObservations','downloadEvents','frameCoverage','workerScripts','requests']){
 assert.equal(imported[field].length,record[field].length,field+' must survive export/import');
}
assert.equal(imported.pimMediaObservations[0].renditionRef,matching.renditionRef);
assert.equal(imported.pimObservations[0].products[0].mediaRenditionRefs[0],product.products[0].mediaRenditionRefs[0]);
assert.equal(imported.counters.requestsDropped,3);
assert.equal(imported.pimMediaDropped,3);
assert.equal(imported.licensingObservationsDropped,4);
assert.equal(imported.downloadObserverEverEnabled,false);
assert(!JSON.stringify(imported).includes('TOPLEVEL_SECRET'));
assert(!('internalUnsupported' in imported));
assert.equal(imported.schema,21);
console.log('PASS v7.17 lossless supported evidence families, exact rendition vs asset-family, ambiguous query handling, counter retention and privacy');
