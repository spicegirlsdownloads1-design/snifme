'use strict';
const assert=require('node:assert/strict');const fs=require('node:fs');
const read=f=>fs.readFileSync(f,'utf8');
const manifest=require('../manifest.json');assert.equal(manifest.version,'7.19.0');
assert(!manifest.permissions.includes('debugger'));assert(!manifest.permissions.includes('webRequestBlocking'));
const h=read('dashboard.html'),s=read('dashboard.js'),d=read('download_observer.js'),b=read('background.js');
assert(h.includes('<script src="asset_quality.js"></script><script src="dam_specialists.js"></script><script src="case_intel.js"></script><script src="case_crypto.js"></script><script src="case_compare.js"></script><script src="lab_acceptance.js"></script><script src="capture_repair.js"></script><script src="dam_review_matrix.js"></script><script src="workflow_pattern.js"></script><script src="comparison_readiness.js"></script><script src="dam_policy_compare.js"></script><script src="evidence_synthesis.js"></script><script src="har_privacy.js"></script><script src="har_dam_workflows.js"></script><script src="har_sequence.js"></script><script src="har_role_flow.js"></script><script src="har_stage_compare.js"></script><script src="har_coverage.js"></script><script src="har_triage.js"></script><script src="har_delivery_posture.js"></script><script src="har_access_matrix.js"></script><script src="har_redirect_boundaries.js"></script><script src="har_range_evidence.js"></script><script src="dashboard.js"></script>'));
for(const view of ['quality-ledger','quality-transfers']){
 assert(h.includes('data-view="'+view+'"'));
 assert(s.includes("view==='"+view+"'"));
}
assert(s.includes('THIQuality.exportReport(record)'));
assert(d.includes("rangeEvidence(d.responseHeaders,false)"));
assert(b.includes('fileType:/^(?:image'));
assert(fs.existsSync('tests/quality_lab.py'));
console.log('PASS v5.5: dashboard, range metadata, download MIME, no new permissions, fixture');
