/* v6.8 — Privacy-safe independent HAR reconciliation triage.
 * Input: the strictly redacted v6.7 report, optional operator declarations.
 * Output: only numerical counters and fixed category labels/advice; no URLs.
 */
(function(root){'use strict';
const CATEGORY=Object.freeze(['Documents','Scripts','Styles','API reads','API writes','Images','Other media','Downloads','Other']);
const CONTEXT=Object.freeze(['sameSession','sameActions','devtoolsBeforeNavigation','preserveLog','comparableSiteAccess']);
const normal=n=>Number.isSafeInteger(n)&&n>=0?Math.min(n,1000000):0;
const choice=x=>['yes','no','unknown'].includes(x)?x:'unknown';
function context(input){const out={};for(const f of CONTEXT)out[f]=choice(input&&input[f]);return out;}
function assess(report,answers={}){
 if(!report||report.format!=='trufflehog-har-coverage-reconciliation'||!Array.isArray(report.rows)||report.rows.length!==CATEGORY.length)throw Error('Run independent HAR reconciliation first');
 const c=report.coverage||{},ctx=context(answers);const signals=[];
 function add(id,level,count,explanation,nextStep){signals.push({id,level,count:normal(count),explanation,nextStep});}
 if(ctx.sameSession==='no'||ctx.sameActions==='no')add('not-comparable','high',1,'The operator reported that the files describe different sessions or workflows.','Repeat the same authorised workflow and capture in both observers.');
 if(ctx.sameSession==='unknown'||ctx.sameActions==='unknown')add('context-unconfirmed','review',1,'Matching browsing context has not been confirmed by the operator.','Confirm the sessions and user actions correspond before interpreting gaps.');
 if(ctx.devtoolsBeforeNavigation==='no')add('late-devtools','high',1,'DevTools was opened after navigation, potentially omitting early network activity.','Open DevTools Network before the first page load and repeat the benchmark.');
 if(ctx.devtoolsBeforeNavigation==='unknown')add('devtools-timing-unknown','review',1,'DevTools opening time was not confirmed.','Confirm DevTools was open before the first page navigation.');
 if(ctx.preserveLog==='no')add('har-navigation-gap','review',1,'DevTools Preserve log was disabled, so navigations may clear earlier requests.','Enable Preserve log before repeating a multi-page workflow.');
 if(ctx.comparableSiteAccess==='no')add('permissions-differ','high',1,'The investigator reports different extension permissions or access context.','Compare granted host/CDN permissions, accounts, and the same page scope.');
 if(normal(c.savedDropped))add('dropped-records','high',c.savedDropped,'Saved capture reports dropped records.','Inspect capture buffers and segment rollover; repeat a smaller, shorter controlled run.');
 if(normal(c.savedUnfinalized))add('unfinalized','review',c.savedUnfinalized,'Saved capture includes an unfinalized segment.','Stop capture, save, and verify saved-session readback before comparing.');
 if(normal(c.harInvalid))add('har-invalid','review',c.harInvalid,'Some HAR entries did not have usable HTTP URLs or structure.','Export a smaller HAR from the same tab and check its format.');
 if(normal(c.repeatedComparableKeys))add('repeated-identity','review',c.repeatedComparableKeys,'Repeated sanitized method/URL identities can make one-to-one matching ambiguous.','Interpret matching totals as counts, not unique request identities; inspect the source sessions locally.');
 const warnings=Array.isArray(report.warnings)?report.warnings.filter(x=>typeof x==='string'):[];
 if(warnings.includes('HAR and saved capture time windows do not overlap within five minutes'))add('time-disjoint','high',1,'Capture time ranges are disjoint.','Collect HAR and saved evidence during the same short controlled run.');
 else if(warnings.includes('One or both traces lack enough valid timestamps'))add('timestamps-missing','review',1,'Comparable timestamps are not available in both sources.','Use a fresh DevTools HAR and finalised capture with timestamps.');
 if(normal(c.statusDifferentMatches))add('status-differences','review',c.statusDifferentMatches,'Matched method/URL observations have different HTTP statuses.','Check redirects, authentication state and replay conditions in each original trace.');
 const scope=Array.isArray(report.scopeRows)?report.scopeRows:[];
 const ext=scope.find(x=>x.scope==='External origins');
 if(ext&&normal(ext.harOnly))add('har-only-external','review',ext.harOnly,'HAR contains external-origin responses not matched in saved capture.','Check whether access was granted to observed CDN/API origins; not all browser requests are observable.');
 if(ext&&normal(ext.captureOnly))add('saved-only-external','review',ext.captureOnly,'Saved capture contains external-origin observations absent from the HAR.','Check the HAR recording window, navigation history, and Network panel filtering.');
 const rows=CATEGORY.map(cat=>{
  const row=report.rows.find(r=>r&&r.category===cat)||{};
  const h=normal(row.harOnly),s=normal(row.captureOnly);
  return {category:cat,harOnly:h,captureOnly:s,unmatched:h+s};
 }).sort((a,b)=>b.unmatched-a.unmatched||CATEGORY.indexOf(a.category)-CATEGORY.indexOf(b.category));
 const main=rows.filter(r=>r.unmatched>0).slice(0,5);
 if(!main.length)add('no-count-gaps','info',0,'No per-category unmatched requests were observed in the comparison.','This is agreement between two limited observations, not proof of complete capture.');
 else for(const x of main){
  const id='category-'+CATEGORY.indexOf(x.category);
  const step=x.category==='Scripts'?'Open DevTools before navigation and verify script scan coverage.':x.category==='Images'?'Compare image host permissions, cache state and whether images actually loaded.':x.category==='API writes'?'Check opt-in Download Observer status and origin permissions without replaying requests.':x.category==='Downloads'?'Review browser download attribution and Network log timing.':'Repeat the same controlled browser actions with Network Preserve log enabled.';
  add(id,'review',x.unmatched,`Unpaired ${x.category} observations: ${x.harOnly} HAR-only, ${x.captureOnly} capture-only.`,step);
 }
 const attention=signals.some(x=>x.level==='high')?'Not comparable until high-priority issues are reviewed':main.length?'Observed gaps need investigation':'No numerical gaps observed; completeness unverified';
 return {format:'trufflehog-har-coverage-triage',version:1,assessment:attention,
  context:ctx,coverage:{exactMatches:normal(c.exactMatches),harOnly:normal(c.harOnly),savedOnly:normal(c.savedOnly),statusDifferentMatches:normal(c.statusDifferentMatches)},
  signals:signals.slice(0,18),categoryGaps:rows,
  explanation:'This report suggests checks for observed discrepancies, not proven root causes or complete network visibility. Two browsers traces can both omit the same request.',
  noAdditionalRequests:true,credentialsRetained:false};
}
const API={assess,context};root.THIHARTriage=API;
if(typeof module==='object'&&module.exports)module.exports=API;
})(typeof self!=='undefined'?self:globalThis);
