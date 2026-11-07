'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs');
const read=f=>fs.readFileSync(f,'utf8');
const manifest=require('../manifest.json');
assert.equal(manifest.version,'7.19.0');
assert(!manifest.permissions.includes('debugger'));
assert(!manifest.permissions.includes('webRequestBlocking'));
assert(!manifest.permissions.includes('cookies'));
const html=read('dashboard.html'),js=read('dashboard.js'),bg=read('background.js'),obs=read('download_observer.js');
for(const v of ['upload-protocols','api-schema-diff']){
 assert(html.includes(`data-view="${v}"`));assert(js.includes(`view==='${v}'`));
}
assert(html.includes('<script src="upload_api_intel.js"></script>'));
assert(bg.indexOf("'upload_api_intel.js'")<bg.indexOf("'download_observer.js'"));
assert(obs.includes('THIUploadAPI.detect(stage,d)'));
assert(js.includes('THIUploadAPI.compare(apiSchemaBaseline,record)'));
assert(js.includes('THIUploadAPI.analyse(record)'));
assert(fs.existsSync('tests/protocol_lab.py'));
console.log('PASS v5.6 wiring: opt-in existing observer, upload + API views, manifest scope, privacy report');
