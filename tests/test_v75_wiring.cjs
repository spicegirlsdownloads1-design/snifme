'use strict';const assert=require('node:assert/strict');const fs=require('fs');const path=require('path');const read=f=>fs.readFileSync(path.join(__dirname,'..',f),'utf8');
const m=JSON.parse(read('manifest.json'));assert.equal(m.version,'7.19.0');
assert.deepEqual(m.permissions,['storage','tabs','scripting','webRequest','downloads','notifications']);
assert(read('dashboard.html').includes('<script src="har_delivery_posture.js"></script><script src="har_access_matrix.js"></script><script src="har_redirect_boundaries.js"></script><script src="har_range_evidence.js"></script><script src="dashboard.js"></script>'));
const js=read('dashboard.js');for(const s of ['2c. Inspect access evidence (offline)','Offline access indicators × delivery outcomes','Offline access-indicator comparison','THIHARAccessMatrix.audit(parsed)','THIHARAccessMatrix.compare(firstParsed,secondParsed,declared)','Export access observation matrix (redacted JSON)','Export access observation matrix (redacted CSV)','Export access comparison (redacted CSV)','inspectedFile!==file','reviewedSecondFile!==secondFile'])assert(js.includes(s),s);
assert(!/chrome\.downloads\.download|\bfetch\s*\(|XMLHttpRequest/.test(read('har_access_matrix.js')));
assert(js.indexOf('THIHARPrivacy.audit(firstParsed);THIHARPrivacy.audit(secondParsed)')<js.indexOf('THIHARAccessMatrix.compare(firstParsed,secondParsed,declared)'));
console.log('PASS v7.5: gated single/two HAR access matrix and redacted exports with no new permissions');
