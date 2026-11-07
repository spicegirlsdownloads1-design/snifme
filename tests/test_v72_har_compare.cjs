'use strict';
const assert=require('node:assert/strict');
const S=require('../har_sequence.js');
const C=require('../har_stage_compare.js');
const make=(path,method='GET',status=200,mime='application/json',extra={})=>({startedDateTime:'2026-10-24T12:00:00.000Z',request:{url:'https://api.v72.example/'+path+'?token=SECRET_abcdefghijklmnopqrstuvwxyz',method,headers:[{name:'Authorization',value:'Bearer SECRET_abcdefghijklmnopqrstuvwxyz'}]},response:{status,headers:[],content:{mimeType:mime}},...extra});
const first={log:{entries:[make('export/create','POST',202),make('jobs/status'),make('download/file','GET',200,'image/jpeg',{response:{status:200,headers:[{name:'Content-Disposition',value:'attachment; filename="SECRET_PHOTO.jpg"'}],content:{mimeType:'image/jpeg'}}})]}};
const second={log:{entries:[make('export/create','POST',202),make('jobs/status'),make('jobs/status'),make('download/file','GET',200,'image/jpeg',{response:{status:200,headers:[{name:'Content-Disposition',value:'attachment; filename="SECRET_PHOTO2.jpg"'}],content:{mimeType:'image/jpeg'}}}),make('restricted/file','GET',403,'text/html')]}};
const r=C.audit(first,second,{sameSite:'yes',sameActions:'yes',sameAccount:'yes',sameScope:'yes',sameBrowserCoverage:'yes'});
assert.equal(r.format,'trufflehog-har-stage-comparison');
assert.equal(r.coverage[0].inspectedHttp,3);assert.equal(r.coverage[1].inspectedHttp,5);
const row=r.stageRows.find(x=>x.category==='Export status request clue');assert.equal(row.baseline,1);assert.equal(row.comparison,2);assert.equal(row.interpretation,'More observed');
assert.equal(r.patternRows[1].baseline,1);assert.equal(r.patternRows[1].comparison,1);
assert(r.warnings.some(s=>s.includes('fewer than 20')));
const redacted=JSON.stringify(r);for(const secret of ['SECRET_', 'example', '2026-10-24','authorization','jobs/status','PHOTO','?token='])assert(!redacted.includes(secret),secret);
const unknown=C.audit(first,second,{});assert.equal(unknown.readiness,'Context or coverage review needed');assert.equal(unknown.context[0].answer,'unknown');
const different=C.audit(first,second,{sameSite:'no',sameAccount:'yes',sameActions:'yes',sameScope:'yes',sameBrowserCoverage:'yes'});assert.equal(different.readiness,'Not comparable');
assert.equal(C.audit(first,{log:{entries:[]}}).readiness,'Not comparable');
const oversized={log:{entries:Array(12001).fill(null)}};assert.throws(()=>C.audit(oversized,second),/limit/);
const large={log:{entries:Array(270).fill(0).map((_,i)=>make('export/'+i,'POST',202))}};
const sr=S.audit(large);assert.equal(sr.coverage.candidateStageEvents,270);assert.equal(sr.coverage.shownStageEvents,240);assert.equal(sr.stageCounts.find(x=>x.category==='Export preparation request clue').count,270);
const drift=C.audit(large,first);assert(drift.warnings.some(s=>s.includes('truncated')));assert.equal(drift.stageRows.find(x=>x.category==='Export preparation request clue').baseline,270);
// Untrusted arbitrary HAR-provided text and identifiers must never survive in any report string.
const malicious='VERY_PRIVATE_CLIENT_SECRET_123 abc@example.com /private/admin?sig=TOP_SECRET';
const injected={log:{entries:[{...make('export/create','POST',200),request:{url:'https://example.org/export/'+encodeURIComponent(malicious),method:'POST',headers:[{name:'x-secret',value:malicious}]},response:{status:302,headers:[{name:'Location',value:'https://example.org/file?sig='+malicious}],content:{mimeType:'application/json',text:malicious}}}]}};
assert(!JSON.stringify(C.audit(injected,second)).includes('VERY_PRIVATE_CLIENT_SECRET'));
assert(!JSON.stringify(C.audit(injected,second)).includes('TOP_SECRET'));
// Ensure null rather than Infinity or NaN on empty samples.
const blank=C.audit({log:{entries:[]}},{log:{entries:[]}});assert.equal(blank.stageRows[0].baselinePer1000,null);
console.log('PASS v7.2: cross-HAR stage drift, rate normalisation, chronology warnings, context gates, cap visibility, privacy');
