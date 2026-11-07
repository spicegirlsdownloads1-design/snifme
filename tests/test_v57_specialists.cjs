'use strict';
const assert=require('node:assert/strict');const fs=require('node:fs'),vm=require('node:vm');
const ctx=vm.createContext({URL,console});ctx.globalThis=ctx;
vm.runInContext(fs.readFileSync('dam_intel.js','utf8'),ctx,{filename:'dam_intel.js'});
vm.runInContext(fs.readFileSync('dam_specialists.js','utf8'),ctx,{filename:'dam_specialists.js'});
const A=ctx.THIDAMSpecialists;
function pick(rec,name){return A.analyze(rec).profiles.find(p=>p.vendor===name)}
const bynder=pick({origin:'https://photos.example',requests:[
 {url:'https://tenant.getbynder.com/api/v4/media/?page=1',status:200},
 {url:'https://tenant.getbynder.com/api/v4/media/THIS_ASSET_ID/3/download?token=SECRET_KEY',method:'GET',status:403}
]},'Bynder');
assert(bynder);assert.equal(bynder.confidence,'Strong indication');assert(/download-location/.test(bynder.evidence));assert.equal(bynder.role,'External service observed');
const cdn=pick({origin:'https://archive.example',requests:[
 {url:'https://res.cloudinary.com/demo/image/private/my_photo.jpg?sig=SECRET'},
 {url:'https://res.cloudinary.com/demo/image/authenticated/my_other_photo.jpg'}
]},'Cloudinary');
assert(cdn);assert.equal(cdn.confidence,'Strong indication');assert(cdn.access.includes('private URL type'));assert(cdn.access.includes('authenticated URL type'));
const capture=pick({origin:'https://archive.example',requests:[{url:'https://api.captureweb.net/api/search?q=HIDDEN_SECRET'}]},'Capture DAM');
assert(capture);assert.equal(capture.confidence,'Strong indication');assert(capture.evidence.includes('Capture API host'));
const resourcespace=pick({origin:'https://selfhosted.example',requests:[{url:'https://selfhosted.example/api/index.php?user=admin&function=get_resource_path&sign=HMAC_SECRET'}]},'ResourceSpace');
assert(resourcespace);assert.equal(resourcespace.confidence,'Weak clue');
assert(resourcespace.evidence.includes('not unique'));
const model=pick({responses:[{fields:[{path:'asset.idasset'},{path:'asset.org_filename'}]}]},'Capture DAM');
assert(model);assert.equal(model.confidence,'Weak clue');
assert.equal(A.analyze({origin:'https://example.com',requests:[{url:'https://captureweb.net.evil.test/api/search'}]}).profiles.length,0);
assert.equal(A.analyze({requests:[{url:'https://example.test/api/assets/12'}]}).profiles.length,0);
for(const p of A.analyze({origin:'https://example.test',requests:[{url:'https://example.test/test?token=SECRET'}]}).profiles){assert(!p.access.includes('SECRET'));}
console.log('PASS v5.7 DAM specialists: Bynder download, Cloudinary types, Capture API, selfhosted ResourceSpace clue, unknown hosts');
