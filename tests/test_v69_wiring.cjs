'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const dir=path.join(__dirname,'..');
const m=require('../manifest.json');assert.equal(m.version,'7.19.0');
for(const banned of ['cookies','debugger','webRequestBlocking'])assert(!m.permissions.includes(banned));
const html=fs.readFileSync(path.join(dir,'dashboard.html'),'utf8');
const js=fs.readFileSync(path.join(dir,'dashboard.js'),'utf8');
assert(html.includes('<script src="har_privacy.js"></script><script src="har_dam_workflows.js"></script><script src="har_sequence.js"></script><script src="har_role_flow.js"></script><script src="har_stage_compare.js"></script><script src="har_coverage.js"></script><script src="har_triage.js"></script>'));
for(const text of ['THIHARPrivacy.audit(parsed)','function renderHARPrivacyReport','Inspect HAR privacy locally',
 'Reconcile reviewed HAR with capture','if(inspectedFile!==file)','trufflehog-har-privacy.json','trufflehog-har-privacy.csv',
 'THIHARCoverage.reconcile(parsed,records)','Run offline coverage triage']) assert(js.includes(text),text);
for(const name of ['dam-specialists','download-traces','har-coverage','evidence-synthesis','quality-ledger'])assert(html.includes('data-view="'+name+'"'));
console.log('PASS v6.9 HAR privacy preflight dashboard integration, gated comparison and inherited views');
