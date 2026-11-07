'use strict';
const assert=require('node:assert/strict'),vm=require('node:vm'),fs=require('node:fs');
const ctx=vm.createContext({URL});ctx.globalThis=ctx;
for(const file of ['dam_intel.js','dam_specialists.js'])vm.runInContext(fs.readFileSync(file,'utf8'),ctx);
const secret='SHOULD_NEVER_BE_EXPORTED_9182736',path='PRIVATE_ASSET_PATH_33',host='foo.example';
const record={origin:`https://${host}/folder/${path}?token=${secret}`,requests:[
 {url:`https://tenant.getbynder.com/api/v4/media/${path}/2/download?Authorization=${secret}`,status:200},
 {url:`https://res.cloudinary.com/acct/image/private/${path}.jpg?api_key=${secret}&signature=${secret}`},
 {url:`https://${host}/api/index.php?user=${secret}&function=download&sign=${secret}`}
 ],responses:[{url:`https://${host}/private/${secret}`,fields:[{path:'data.idasset',type:'string'},{path:'data.org_filename',type:'string'},{path:'data.'+secret,type:secret}]}],technologyHints:[{id:'resourcespace',signalId:'resourcespace-code',source:'file-'+secret}]};
const analysis=ctx.THIDAMSpecialists.report(record);
const json=JSON.stringify(analysis);
for(const sensitive of [secret,path,host,'Authorization=','api_key='])assert(!json.includes(sensitive),'Leaked '+sensitive);
assert(!json.includes('tenant.getbynder.com'));assert(!json.includes('res.cloudinary.com'));
assert(analysis.profiles.some(p=>p.vendor==='Bynder'));assert(analysis.profiles.some(p=>p.vendor==='ResourceSpace'));
const polluted={origin:'javascript:alert(1)',requests:[{url:'http://captureweb.net.evil.test/path'}]};assert.equal(ctx.THIDAMSpecialists.report(polluted).profiles.length,0);
assert.equal(ctx.THIDAMSpecialists.report(null).profiles.length,0);
console.log('PASS v5.7 privacy: no request paths, secret query values, schema-field values, untrusted hint sources or raw hosts in report');
