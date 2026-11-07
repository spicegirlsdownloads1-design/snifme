'use strict';
const assert=require('node:assert/strict');
const A=require('../acceptance_intel.js');
const base={requests:[{status:200},{status:200}],autoScanCoverage:{eligible:2,scanned:2},
  findings:[{type:'Named secret assignment',masked:'[redacted]'}],counters:{requestsDropped:0},sessionId:'test-session'};
const good=A.evaluate({record:base,recording:{enabled:true},permission:true,inspector:true,archive:true,
  health:{code:'observed-complete'}});
assert.equal(good.verdict,'incomplete'); // Windows notification banner not verified by programmatic checks.
assert.equal(good.checks.find(x=>x.id==='response-scanning').status,'pass');
assert.equal(good.checks.find(x=>x.id==='vault').status,'pass');
assert.equal(good.checks.find(x=>x.id==='desktop-notification').status,'not-tested');
assert.equal(good.totals.requests,2);
const partial=A.evaluate({record:{...base,autoScanCoverage:{eligible:5,scanned:3},counters:{requestsDropped:4}},recording:{enabled:true},permission:true,inspector:false,archive:false,health:{code:'partial'}});
assert.equal(partial.verdict,'needs-review');
assert.equal(partial.checks.find(x=>x.id==='response-scanning').status,'warn');
assert.equal(partial.checks.find(x=>x.id==='retention').actual,4);
const empty=A.evaluate();assert.equal(empty.checks.find(x=>x.id==='requests').status,'not-tested');
assert(!JSON.stringify(good).includes('test-session'));
assert(!JSON.stringify(good).includes('[redacted]'));
assert(!JSON.stringify(good).includes('https://'));
console.log('PASS v5.0 acceptance: real counters, partial evidence, no raw source data, notification unverified');
