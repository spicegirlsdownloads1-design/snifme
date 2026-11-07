'use strict';const a=require('node:assert/strict'),fs=require('node:fs'),p=require('node:path');
const read=x=>fs.readFileSync(p.join(__dirname,'..',x),'utf8'),m=JSON.parse(read('manifest.json'));
a.equal(m.version,'7.19.0');a.deepEqual(m.permissions,['storage','tabs','scripting','webRequest','downloads','notifications']);
a(read('dashboard.html').includes('<script src="har_access_matrix.js"></script><script src="har_redirect_boundaries.js"></script><script src="har_range_evidence.js"></script><script src="dashboard.js"></script>'));
const js=read('dashboard.js');for(const x of ['THIHARRedirectBoundaries.audit(parsed)','THIHARRedirectBoundaries.compare(firstParsed,secondParsed,declared)','2d. Inspect redirect boundaries (offline)','Offline redirect & authentication boundaries','Offline redirect-boundary comparison','Export redirect boundaries (redacted JSON)','Export redirect boundaries (redacted CSV)','Export redirect comparison (redacted CSV)','inspectedFile!==file','reviewedSecondFile!==secondFile'])a(js.includes(x),x);
a(js.indexOf('THIHARPrivacy.audit(firstParsed);THIHARPrivacy.audit(secondParsed)')<js.indexOf('THIHARRedirectBoundaries.compare(firstParsed,secondParsed,declared)'));
a(!/\bfetch\s*\(|XMLHttpRequest|chrome\.downloads\.download|chrome\.webRequest/.test(read('har_redirect_boundaries.js')));
console.log('PASS v7.6 wiring and privacy guard');
