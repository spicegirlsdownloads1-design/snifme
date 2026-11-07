'use strict';
const assert=require('node:assert/strict');const fs=require('node:fs');const path=require('node:path');
const R=require('../har_range_evidence.js');
const src=name=>JSON.parse(fs.readFileSync(path.join(__dirname,name),'utf8'));
const first=src('v77-range-baseline.har'),second=src('v77-range-comparison.har');
const a=R.audit(first),b=R.audit(second),comparison=R.compare(first,second,{sameSite:'yes',sameActions:'yes',sameAccount:'yes',sameScope:'yes',sameBrowserCoverage:'yes'});
assert.equal(a.coverage.stableTagGroups,1);
assert.equal(a.spanBuckets.find(r=>r.category.includes('100%')).count,1);
assert.equal(b.coverage.partialResponses,1);
assert.equal(b.spanBuckets.find(r=>r.category.includes('25–49%')).count,1);
assert.equal(comparison.readiness,'Context or coverage review needed');
for(const report of [a,b,comparison]){
 const s=JSON.stringify(report);
 for(const value of ['fictional-asset','secret_very_fake','signed-example','cdn.example.invalid','2026-10-24','etag-dummy'])assert(!s.includes(value),value);
}
if(require.main===module)console.log(JSON.stringify({baseline:a.coverage,comparison:b.coverage,declaredSpanBaseline:a.spanBuckets,declaredSpanComparison:b.spanBuckets,comparisonReadiness:comparison.readiness,warnings:a.warnings},null,2));
