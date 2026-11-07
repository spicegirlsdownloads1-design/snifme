/* Trufflehog Intelligence v6.6 — strictly local, conservative synthesis.
 * Three existing evidence layers are combined but not conflated. This is
 * not a proof of equivalent permissions, a security defect, or a repair.
 * Only fixed labels, controlled operator choices, and numeric aggregates
 * are returned. No URL, host, group ID, asset ID or source value is returned.
 */
(function(root){'use strict';
const abs=Math.abs;
const FIXED_ACTIONS=Object.freeze({
 'Media returned 2xx':'Have the DAM owner compare authorised delivery logs and asset/role controls for the two sessions.',
 'Media returned 401/403':'Have the DAM owner review denied delivery events and the intended access policy.',
 'Media with signed URL indicators':'Have the DAM owner review intended signed-URL and token-lifetime configuration.',
 'Media with public cache TTL ≥24h':'Have the CDN owner review caching and withdrawal/invalidation configuration.',
 'Successful attachment responses':'Have the DAM owner inspect download-rights and export-job logs for the sessions.',
 'API request with credential-like query class':'Have the application owner verify that API credential material is not placed into public URLs.'
});
const safe=(n)=>Number.isFinite(n)&&n>=0?Math.min(1e9,Math.round(n*10)/10):0;
function synthesize(earlier,later,operatorContext){
 const policy=root.THIPolicyDrift?.compare?.(earlier,later);
 const pattern=root.THIWorkflowPattern?.compare?.(earlier,later);
 const readiness=root.THIComparisonReadiness?.assess?.(earlier,later,operatorContext);
 if(!policy||!pattern||!readiness)throw Error('Comparison analysis dependencies unavailable');
 // Use only declared choices and the fixed-string reports from the underlying
 // modules. Never pass through untrusted records or arbitrary string fields.
 const choices=root.THIComparisonReadiness.normalize(operatorContext);
 const operatorMismatch=Object.values(choices).some(v=>v==='different'||v==='not-both-early');
 const unknownContext=Object.values(choices).some(v=>v==='unknown');
 const noObservations=policy.overview.earlierRequests===0||policy.overview.laterRequests===0;
 const patternDivergent=pattern.assessment==='Materially different observed request pattern';
 const incomplete=!!policy.overview.blindspotCount || pattern.limitations.some(v=>/incomplete capture|cap|dropped|Unfinalized|Missing segment|lack request/i.test(v));
 const tooFew=!pattern.overview.enoughSamples;
 const blocked=operatorMismatch||noObservations;
 // Similar browser request patterns cannot establish the same privileges,
 // licence entitlement, resource scope, or actual user actions.
 let assessment='Operator context mismatch or missing HTTP evidence';
 if(!blocked){
  if(patternDivergent)assessment='Different observed workflows — policy attribution blocked';
  else if(incomplete||tooFew||unknownContext)assessment='Limited descriptive evidence';
  else assessment='Operator-declared alignment — descriptive review only';
 }
 const limitations=[];
 if(operatorMismatch)limitations.push('Operator reported differing comparison context');
 if(unknownContext)limitations.push('Some comparison-context answers are unconfirmed');
 if(noObservations)limitations.push('One or both groups have no usable HTTP requests');
 if(patternDivergent)limitations.push('Browser-observed traffic patterns differ materially');
 if(tooFew)limitations.push('Fewer than 40 requests in one or both captures');
 if(incomplete)limitations.push('Capture limits or missing records restrict interpretation');
 if(pattern.overview.sequenceEvidence!=='HTTP completion timestamps')limitations.push('Timeline phases are not based on complete HTTP timestamps');
 const rows=(Array.isArray(policy.rows)?policy.rows:[]).slice(0,6).map(row=>{
  // The only category strings we retain must belong to this local allowlist.
  const label=Object.prototype.hasOwnProperty.call(FIXED_ACTIONS,row.category)?row.category:'Other fixed observation';
  const a=Number.isFinite(row.earlierPerThousand)?safe(row.earlierPerThousand):null;
  const b=Number.isFinite(row.laterPerThousand)?safe(row.laterPerThousand):null;
  const delta=a===null||b===null?null:Math.round((b-a)*10)/10;
  const small=row.earlierSample<20||row.laterSample<20;
  const notable=delta!==null&&abs(delta)>=100; // ≥10 percentage points; triage threshold, not significance.
  let interpretation='No material recorded difference';
  if(a===null||b===null)interpretation='No comparable sample';
  else if(small)interpretation='Small sample — descriptive only';
  else if(blocked||patternDivergent)interpretation='Attribution blocked by context';
  else if(incomplete||unknownContext||tooFew)interpretation=notable?'Observed shift — review limitations':'Limited descriptive comparison';
  else if(notable)interpretation='Observed shift — owner review';
  else if(delta!==0)interpretation='Small observed difference';
  return {indicator:label,earlierPerThousand:a,laterPerThousand:b,differencePerThousand:delta,
   earlierSample:safe(row.earlierSample),laterSample:safe(row.laterSample),
   interpretation,ownerAction:FIXED_ACTIONS[label]||'Review against the system owner’s own records.'};
 });
 const reviewCount=rows.filter(r=>r.interpretation==='Observed shift — owner review'||r.interpretation==='Observed shift — review limitations').length;
 return {format:'trufflehog-evidence-weighted-dam-review',version:1,assessment,
  verifiedEquivalentContexts:false,securityDefectEstablished:false,
  overview:{baselineRequests:safe(policy.overview.earlierRequests),comparisonRequests:safe(policy.overview.laterRequests),
   requestMixDifferencePercent:safe(pattern.overview.requestMixDifferencePercent),
   phasePatternDifferencePercent:safe(pattern.overview.phasePatternDifferencePercent),
   capturedCoverageGaps:safe(policy.overview.blindspotCount),
   operatorMismatch,unknownContext,notableObservations:reviewCount},
  contextChecks:readiness.context.map(x=>({category:x.category,status:x.status})),
  limitations:limitations.slice(0,10),rows,
  caution:'Browser-observed request rates and operator context declarations do not prove an access-control flaw, CDN withdrawal failure, licence entitlement, identical asset scope, or a policy change. All differences require owner-authorised verification.'};
}
const API={synthesize};root.THIEvidenceSynthesis=API;
if(typeof module==='object'&&module.exports)module.exports=API;
})(typeof self!=='undefined'?self:globalThis);
