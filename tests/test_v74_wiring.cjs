'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const root=path.resolve(__dirname,'..');const read=f=>fs.readFileSync(path.join(root,f),'utf8');
const manifest=JSON.parse(read('manifest.json'));
assert.equal(manifest.version,'7.19.0');
for(const extra of ['cookies','debugger','webRequestBlocking'])assert(!manifest.permissions.includes(extra));
assert.deepEqual(manifest.permissions,['storage','tabs','scripting','webRequest','downloads','notifications']);
const html=read('dashboard.html'),js=read('dashboard.js');
assert(html.includes('<script src="har_triage.js"></script><script src="har_delivery_posture.js"></script><script src="har_access_matrix.js"></script><script src="har_redirect_boundaries.js"></script><script src="har_range_evidence.js"></script><script src="dashboard.js"></script>'));
for(const name of ['2b. Inspect delivery policies (offline)','Offline asset delivery policy inventory','Observed delivery policy and signing differences',
 'Export media delivery inventory (redacted JSON)','Export delivery policy comparison (redacted JSON)',
 'Export delivery policy comparison (redacted CSV)','trufflehog-har-delivery-compare.csv',
 'THIHARDeliveryPosture.compare(firstParsed,secondParsed)','if(inspectedFile!==file)','if(reviewedSecondFile!==secondFile)',
 'THIHARPrivacy.audit(firstParsed);THIHARPrivacy.audit(secondParsed)'])assert(js.includes(name),name);
assert(js.indexOf('THIHARPrivacy.audit(firstParsed);THIHARPrivacy.audit(secondParsed)')<js.indexOf('THIHARDeliveryPosture.compare(firstParsed,secondParsed)'));
assert(!/chrome\.downloads\.download|fetch\s*\(/.test(read('har_delivery_posture.js')));
console.log('PASS v7.4: privacy-gated single and dual HAR delivery analysis, exports, no new permissions or network');
