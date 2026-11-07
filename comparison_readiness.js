/* Trufflehog Intelligence v6.4 — offline case-comparability gate.
 * Browser metadata cannot establish equal roles, search scope or host permissions.
 * Only user-selected fixed categories are accepted; no free-form annotations,
 * credential data, raw URLs, group IDs or asset identifiers enter reports.
 */
(function(root){'use strict';
const CHOICES=Object.freeze({
 accessRole:['unknown','same','different'],
 workflow:['unknown','same','different'],
 assetScope:['unknown','same','different'],
 hostPermissions:['unknown','same','different'],
 devtoolsTiming:['unknown','both-early','not-both-early']
});
const TITLES=Object.freeze({
 accessRole:'Access role/account context',workflow:'Browsing and download actions',
 assetScope:'Asset/gallery/search scope',hostPermissions:'Site and CDN host grants',
 devtoolsTiming:'DevTools active before page loading'
});
const TEXT=Object.freeze({
 unknown:'Not confirmed',same:'Operator reports matching context',different:'Operator reports different context',
 'both-early':'Operator reports DevTools active early in both captures',
 'not-both-early':'DevTools not active early for both captures'
});
function norm(raw){const value=raw&&typeof raw==='object'&&!Array.isArray(raw)?raw:{};
 return Object.fromEntries(Object.entries(CHOICES).map(([key,valid])=>[key,valid.includes(value[key])?value[key]:'unknown']));}
function assess(olderRecords,newerRecords,operatorContext){
 if(!root.THIPolicyDrift||typeof root.THIPolicyDrift.aggregate!=='function')throw Error('DAM policy comparison dependency unavailable');
 const earlier=root.THIPolicyDrift.aggregate(olderRecords),later=root.THIPolicyDrift.aggregate(newerRecords);
 if(earlier.origin!==later.origin)throw Error('Captures must share the exact same HTTP origin');
 if(earlier.group&&later.group&&earlier.group===later.group)throw Error('Select different saved capture groups');
 const context=norm(operatorContext),checks=[],blocking=[],cautions=[];
 for(const [key,value] of Object.entries(context)){
  const disagreement=value==='different'||value==='not-both-early';
  const unknown=value==='unknown';
  const status=disagreement?'Mismatch reported':unknown?'Not established':'Operator-reported match';
  checks.push({category:TITLES[key],status,assessment:TEXT[value],source:'Operator declaration; not verified by browser'});
  if(disagreement)blocking.push(TITLES[key]);
  if(unknown)cautions.push(TITLES[key]+' not confirmed');
 }
 const requestsA=earlier.counts.requests,requestsB=later.counts.requests;
 const mediaA=earlier.counts.media,mediaB=later.counts.media;
 const apiA=earlier.counts.api,apiB=later.counts.api;
 const mediaShareA=requestsA?mediaA/requestsA:0,mediaShareB=requestsB?mediaB/requestsB:0;
 const apiShareA=requestsA?apiA/requestsA:0,apiShareB=requestsB?apiB/requestsB:0;
 if(!requestsA||!requestsB)blocking.push('One or both saved captures contain no usable HTTP observations');
 const tiny=requestsA<20||requestsB<20;
 if(tiny)cautions.push('Fewer than 20 request records in at least one capture');
 if(requestsA&&requestsB&&Math.max(requestsA,requestsB)/Math.min(requestsA,requestsB)>3)
  cautions.push('Captured request volumes differ by more than 3×');
 if(requestsA&&requestsB&&Math.abs(mediaShareA-mediaShareB)>0.25)
  cautions.push('Media-request share differs by over 25 percentage points');
 if(requestsA&&requestsB&&Math.abs(apiShareA-apiShareB)>0.25)
  cautions.push('API-request share differs by over 25 percentage points');
 for(const flag of earlier.blindspots)cautions.push('Baseline: '+flag);
 for(const flag of later.blindspots)cautions.push('Comparison: '+flag);
 // A passing readiness gate is a *self-reported* context match, never proof
 // of the same permissions, pages, repository contents or security controls.
 // v6.5: independent comparison of coarse observed request categories. The
 // operator answer remains distinct; browser traffic cannot certify a match.
 let observedPattern=null;
 if(root.THIWorkflowPattern&&typeof root.THIWorkflowPattern.compare==='function'){
  const p=root.THIWorkflowPattern.compare(olderRecords,newerRecords);
  observedPattern={assessment:p.assessment,requestMixDifferencePercent:p.overview.requestMixDifferencePercent,
   phasePatternDifferencePercent:p.overview.phasePatternDifferencePercent,
   enoughSamples:p.overview.enoughSamples,sequenceEvidence:p.overview.sequenceEvidence};
  if(p.assessment==='Materially different observed request pattern')
   cautions.push('Recorded request pattern differs materially; check whether browsing actions and cache state were comparable');
 }
 const outcome=blocking.length?'Do not compare as equivalent':
  cautions.length?'Limited descriptive comparison':'Operator-declared matching context';
 const counts={baselineRequests:requestsA,comparisonRequests:requestsB,
  baselineMedia:mediaA,comparisonMedia:mediaB,baselineAPI:apiA,comparisonAPI:apiB,
  baselineSegments:earlier.segments,comparisonSegments:later.segments};
 const safeCautions=[...new Set(cautions)].slice(0,20),safeBlocking=[...new Set(blocking)].slice(0,10);
 return {format:'trufflehog-case-comparison-readiness',version:1,
  outcome,comparisonAllowedAsEquivalent:false,
  context:checks,counts,observedPattern,blocking:safeBlocking,cautions:safeCautions,
  ownerReview:['If roles, filters, target assets, access grants or browsing actions differ, do not attribute observed request changes to a security-policy change.',
  'Even when the operator reports matching contexts, the browser cannot independently verify server-side permissions or the full set of resources.',
  'Retest relevant observations using owner-approved procedures; this report performs no new HTTP requests.'],
  caveat:'Context answers are operator declarations. Request-count and request-type similarity do not verify identical activity, account entitlements or security controls.'};
}
const API={assess,normalize:norm,choices:CHOICES,titles:TITLES};root.THIComparisonReadiness=API;
if(typeof module==='object'&&module.exports)module.exports=API;
})(typeof self!=='undefined'?self:globalThis);
