'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs');
const rd=x=>fs.readFileSync(x,'utf8');
const m=require('../manifest.json');
assert.equal(m.version,'7.19.0');
assert(!m.permissions.includes('debugger'),'No new debugger power requested');
assert(!m.permissions.includes('webRequestBlocking'),'Passive only');
const bg=rd('background.js'),ui=rd('dashboard.js'),html=rd('dashboard.html');
assert.match(bg,/importScripts\([^\n]*'workflow_intel.js'/);
assert.match(bg,/downloadObserverEverEnabled=true/);
assert.match(bg,/safe.downloadRef=downloadRef/);
assert.match(bg,/downloadRef:match.downloadRef/);
for(const view of ['workflow-chains','workflow-coverage']){
 assert(html.includes(`data-view="${view}"`));
 assert(ui.includes(`view==='${view}'`));
}
assert(html.includes('<script src="workflow_intel.js"></script><script src="upload_api_intel.js"></script><script src="asset_quality.js"></script><script src="dam_specialists.js"></script><script src="case_intel.js"></script><script src="case_crypto.js"></script><script src="case_compare.js"></script><script src="lab_acceptance.js"></script><script src="capture_repair.js"></script><script src="dam_review_matrix.js"></script><script src="workflow_pattern.js"></script><script src="comparison_readiness.js"></script><script src="dam_policy_compare.js"></script><script src="evidence_synthesis.js"></script><script src="har_privacy.js"></script><script src="har_dam_workflows.js"></script><script src="har_sequence.js"></script><script src="har_role_flow.js"></script><script src="har_stage_compare.js"></script><script src="har_coverage.js"></script><script src="har_triage.js"></script><script src="har_delivery_posture.js"></script><script src="har_access_matrix.js"></script><script src="har_redirect_boundaries.js"></script><script src="har_range_evidence.js"></script><script src="dashboard.js"></script>'));
assert(ui.includes('THIWorkflow.exportReport(record,recording)'));
assert(fs.existsSync('tests/workflow_lab.py'));
console.log('PASS v5.4 wiring: new views, no extra permissions, redacted report integration, background linkage');
