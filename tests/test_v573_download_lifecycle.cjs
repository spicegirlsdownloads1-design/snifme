'use strict';
const assert=require('node:assert/strict');
const observer=require('../download_observer.js');

const start=(ref,at='2026-10-24T12:00:00.000Z')=>({
  stage:'download-start',downloadRef:ref,at,host:'cdn.example',downloadStatus:'started',
  association:'Referrer-origin correlation only',receivedBytes:null,totalBytes:null
});
const end=(ref,status='complete',at='2026-10-24T12:00:02.000Z')=>({
  stage:'download-state',downloadRef:ref,at,downloadStatus:status,
  receivedBytes:1024,totalBytes:1024,errorCategory:status==='interrupted'?'Network error':null
});

// One locally-correlated browser download is one row, not one row per event.
let rows=observer.summaries([start('DL1234'),end('DL1234')]);
assert.equal(rows.length,1);
assert.equal(rows[0].status,'complete');
assert.equal(rows[0].host,'cdn.example');
assert.equal(rows[0].bytes,'1024 / 1024 bytes');
assert.match(rows[0].evidence,/Paired by local download reference/);

// Arrival order should not affect pairing; terminal state is never downgraded.
rows=observer.summaries([end('DL1234'),start('DL1234')]);
assert.equal(rows.length,1);
assert.equal(rows[0].status,'complete');
assert.equal(rows[0].at,'2026-10-24T12:00:00.000Z');

// Interrupted downloads retain only the coarse error category.
rows=observer.summaries([start('DL2222'),end('DL2222','interrupted')]);
assert.equal(rows.length,1);
assert.equal(rows[0].status,'interrupted');
assert.equal(rows[0].error,'Network error');

// Missing events must be identified as missing, rather than fabricated.
rows=observer.summaries([start('DL3333'),end('DL4444')]);
assert.equal(rows.length,2);
assert(rows.some(r=>r.status==='started'&&/completion unobserved/.test(r.evidence)));
assert(rows.some(r=>r.status==='complete'&&/start was not recorded/.test(r.evidence)));

// Different local refs cannot be joined merely because hosts/times match.
rows=observer.summaries([start('DL5555'),start('DL6666'),end('DL5555')]);
assert.equal(rows.length,2);
assert.equal(rows.filter(r=>r.status==='complete').length,1);

// Legacy events without a trusted ref remain explicitly unpaired.
rows=observer.summaries([{...start(null),downloadRef:undefined},end('DL7777')]);
assert.equal(rows.length,2);
assert(rows.some(r=>/no trusted local download reference/.test(r.evidence)));

// Size fields must be safe integers, not arbitrary imported strings.
rows=observer.summaries([start('DL8888'),{...end('DL8888'),receivedBytes:'SECRET_TOKEN',totalBytes:-2}]);
assert.equal(rows.length,1);
assert.equal(rows[0].bytes,'');
assert(!JSON.stringify(rows).includes('SECRET_TOKEN'));

// No inferred connection between an HTTP lifecycle and a Chrome download.
rows=observer.summaries([
  {stage:'request',requestId:'q-1',method:'POST',host:'cdn.example',at:'2026-10-24T12:00:00.000Z'},
  start('DL9999'),end('DL9999')
]);
assert.equal(rows.length,2);
assert(rows.some(r=>r.method==='POST'));
assert(rows.some(r=>r.method==='DOWNLOAD'));

console.log('PASS v5.7.3 redacted browser download lifecycle summaries, missing stages and no inferred HTTP linkage');
