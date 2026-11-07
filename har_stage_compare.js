/* Trufflehog v7.2 — offline, preflight-gated HAR stage comparison.
   Inputs can contain sensitive data. Reports are fixed labels, integers and rates only.
   No network, browser permissions, raw URLs, request IDs or credential exports.
*/
(function(root){'use strict';
const SEQ=root.THIHARSequence||(typeof module==='object'&&module.exports?require('./har_sequence.js'):null);
const ROLES=root.THIHARRoleFlow||(typeof module==='object'&&module.exports?require('./har_role_flow.js'):null);
const STAGES=Object.freeze(['Upload / resumable transfer clue','Export preparation request clue','Export status request clue','Attachment delivery response','HTTP redirect response','Access denied response','Partial-content response','Media response','Structured API response']);
const CONTEXT_FIELDS=Object.freeze(['sameSite','sameActions','sameAccount','sameScope','sameBrowserCoverage']);
const PANELS=Object.freeze([
 'Export preparation followed by attachment within 40 HAR entries',
 'Export preparation, status check, then attachment within 40 HAR entries',
 'Events excluded from bounded timeline'
]);
const pct=(num,den)=>den>0?Math.round(1000*num/den*100)/100:null;
const safeCount=n=>Number.isSafeInteger(n)&&n>=0?Math.min(n,12000):0;
function audit(first,second,declared={}){
 if(!SEQ||!ROLES)throw Error('HAR comparison dependencies unavailable');
 const a=SEQ.audit(first),b=SEQ.audit(second);
 const ra=ROLES.audit(first),rb=ROLES.audit(second);
 const context=Object.fromEntries(CONTEXT_FIELDS.map(k=>[k,['yes','no','unknown'].includes(declared?.[k])?declared[k]:'unknown']));
 const yes=CONTEXT_FIELDS.filter(k=>context[k]==='yes').length,no=CONTEXT_FIELDS.filter(k=>context[k]==='no').length;
 const baselineTotal=a.coverage.inspectedHttp,comparisonTotal=b.coverage.inspectedHttp;
 const warn=[];
 if(no)warn.push('At least one comparison context was declared different. Treat any change as potentially caused by context, not by a platform change.');
 if(yes<CONTEXT_FIELDS.length)warn.push('The operator has not confirmed equivalent site, actions, account, asset scope and browser capture context for both HARs.');
 if(baselineTotal<20||comparisonTotal<20)warn.push('One or both HARs have fewer than 20 inspected HTTP entries; rates may be unstable.');
 if(!baselineTotal||!comparisonTotal)warn.push('One or both HARs contain no eligible HTTP entries. Rates and comparisons are not interpretable.');
 if(a.coverage.omittedStageEvents||b.coverage.omittedStageEvents)warn.push('A timeline was truncated at 240 displayed stage events. Pattern counts use only the bounded timeline; full stage counts remain available.');
 if(a.coverage.missingTimestamps||b.coverage.missingTimestamps||a.coverage.nonMonotonicTimestamps||b.coverage.nonMonotonicTimestamps)warn.push('Missing or out-of-order HAR timestamps limit chronology and interval interpretation.');
 if(a.coverage.invalidEntries||b.coverage.invalidEntries)warn.push('One or both HARs include excluded or malformed entries; request capture may be incomplete.');
 if(baselineTotal&&comparisonTotal&&Math.max(baselineTotal,comparisonTotal)>Math.min(baselineTotal,comparisonTotal)*3)warn.push('The HARs have markedly different request volumes; compare rates and review capture scope.');
 const stageMap=r=>new Map((Array.isArray(r.stageCounts)?r.stageCounts:[]).map(x=>[x.category,safeCount(x.count)]));
 const am=stageMap(a),bm=stageMap(b);
 const stageRows=STAGES.map(category=>{
  const baseline=am.get(category)||0,comparison=bm.get(category)||0,baselineRate=pct(baseline,baselineTotal),comparisonRate=pct(comparison,comparisonTotal);
  return {category,baseline,comparison,baselinePer1000:baselineRate,comparisonPer1000:comparisonRate,
   rateChangePer1000:baselineRate===null||comparisonRate===null?null:Math.round((comparisonRate-baselineRate)*100)/100,
   interpretation:baselineRate===null||comparisonRate===null?'Not comparable':comparisonRate>baselineRate?'More observed':comparisonRate<baselineRate?'Fewer observed':'Same observed rate'};
 });
 const roleRows=ra.roleRows.map((x,i)=>({category:x.category,baseline:x.count,comparison:rb.roleRows[i].count,baselinePer1000:pct(x.count,baselineTotal),comparisonPer1000:pct(rb.roleRows[i].count,comparisonTotal)}));
 const roleStageRows=ra.stageRows.map((x,i)=>({service:x.service,stage:x.stage,baseline:x.count,comparison:rb.stageRows[i].count})).filter(x=>x.baseline||x.comparison);
 const handoffRows=ra.nearbyRows.map((x,i)=>({category:x.category,baseline:x.count,comparison:rb.nearbyRows[i].count}));
 const roleCoverage=[{capture:'Baseline HAR',...ra.coverage},{capture:'Comparison HAR',...rb.coverage}];
 const pMap=r=>new Map((Array.isArray(r.patterns)?r.patterns:[]).map(x=>[x.category,safeCount(x.count)]));
 const ap=pMap(a),bp=pMap(b);
 const patternRows=PANELS.map(category=>({category,baseline:ap.get(category)||0,comparison:bp.get(category)||0}));
 const snap=r=>({totalEntries:safeCount(r.coverage.totalEntries),inspectedHttp:safeCount(r.coverage.inspectedHttp),invalidEntries:safeCount(r.coverage.invalidEntries),unclassifiedHttp:safeCount(r.coverage.unclassifiedHttp),candidateStages:safeCount(r.coverage.candidateStageEvents),shownStages:safeCount(r.coverage.shownStageEvents),unshownStages:safeCount(r.coverage.omittedStageEvents),missingTimestamps:safeCount(r.coverage.missingTimestamps),nonMonotonicTimestamps:safeCount(r.coverage.nonMonotonicTimestamps)});
 const confidence=no||!baselineTotal||!comparisonTotal?'Not comparable':yes<CONTEXT_FIELDS.length||baselineTotal<20||comparisonTotal<20||a.coverage.omittedStageEvents||b.coverage.omittedStageEvents?'Context or coverage review needed':'Descriptive comparison only';
 return Object.freeze({format:'trufflehog-har-stage-comparison',version:1,readiness:confidence,
  context:[{question:'Same exact website context',answer:context.sameSite},{question:'Same browsing and workflow actions',answer:context.sameActions},{question:'Same account or role context',answer:context.sameAccount},{question:'Same gallery or asset scope',answer:context.sameScope},{question:'Equivalent DevTools and browser coverage',answer:context.sameBrowserCoverage}],
  coverage:[{capture:'Baseline HAR',...snap(a)},{capture:'Comparison HAR',...snap(b)}],stageRows,patternRows,roleCoverage,roleRows,roleStageRows,handoffRows,warnings:warn,
  limitations:[
   'A difference in HAR evidence is not proof of a DAM policy change, access-control failure, leaked file, authorised master download or completed backend job.',
   'Stage classifications are broad response/header/path-name indicators, not validated asset identities or linked transactions.',
   'Service-role counts use broad vendor/hosting domain patterns. Custom DAM domains often appear as Other/unknown service.',
   'Service-role adjacency uses consecutive classified stages up to five HAR entry positions apart across the full bounded file, NOT matched requests, redirects, asset identities or causal links.',
   'Counts include all classified HTTP entries within the bounded 12,000-entry HAR; adjacency patterns describe only the first 240 displayed stage events.',
   'Operator-declared context is not independently verified. HARs may omit requests, downloads, worker events and response bodies.',
   'No original HAR data, hostnames, URLs, credentials, identifiers, headers, timestamps or field values appear in this report.']});
}
root.THIHARStageCompare=Object.freeze({audit});
if(typeof module==='object'&&module.exports)module.exports={audit};
})(typeof self!=='undefined'?self:globalThis);
