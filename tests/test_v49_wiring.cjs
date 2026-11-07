'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs');
const t=f=>fs.readFileSync(require('node:path').join(__dirname,'..',f),'utf8');
assert.equal(JSON.parse(t('manifest.json')).version,'7.19.0');
assert(t('dashboard.html').includes('dam_delivery_policy.js'));
for(const v of ['dam-access','cdn-policy']){
 assert(t('dashboard.html').includes(`data-view="${v}"`));
 assert(t('dashboard.js').includes(`case '${v}'`));
}
assert(t('background.js').includes('attachmentDisposition:'));
assert(t('background.js').includes('content-disposition'));
assert(!t('manifest.json').includes('"debugger"'));
assert(!t('manifest.json').includes('"webNavigation"'));
console.log('PASS v4.9 wiring: permission/CDN views + attachment presence only, no expanded permissions');
