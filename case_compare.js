/* Trufflehog 5.9: Offline, same-origin comparison of SAVED evidence.
 * Strictly numeric/fixed-label output. No raw identifiers, paths, request headers,
 * URLs containing query strings, passwords, credential hashes or file contents.
 * Absence of an observation never establishes removal or an access-control change.
 */
(function(root){'use strict';
const CASE=root.THICase||(typeof require==='function'?require('./case_intel.js'):null);
const DELIVERY=root.THIDeliveryPolicy||(typeof require==='function'?require('./dam_delivery_policy.js'):null);
const METRIC_DEFS=Object.freeze([
 ['requests','Network','Recorded HTTP requests','Not an estimate of total site traffic'],
 ['status2xx','Network','Recorded 2xx responses','Success in a recorded browser session; not public access'],
 ['status4xx','Network','Recorded 4xx responses','Responses are not proof of a permission defect'],
 ['status5xx','Network','Recorded 5xx responses','Requires operator review of context'],
 ['findings','Security','Masked potential security indicators','Counts do not establish credential validity'],
 ['changedFindings','Security','Locally marked changed indicators','Change state depends on available fingerprint evidence'],
 ['downloadsComplete','Downloads','Observed completed browser downloads','May not be attributable to a particular API request'],
 ['downloadsInterrupted','Downloads','Observed interrupted browser downloads','Check the browser and server logs before assigning cause'],
 ['verifiedImages','Images','Received image verification records','Not proof of unwatermarked masters or licensing rights'],
 ['mediaDelivered','DAM delivery','Delivered media responses','Delivered in this browser session, not necessarily public'],
 ['mediaRestricted','DAM delivery','Media responses with 401/403','Denials cannot establish other renditions are accessible'],
 ['signedMedia','DAM delivery','Signed-query media indicators','Presence does not verify signature expiry or enforcement'],
 ['publicLongCache','DAM delivery','Public-cache responses with TTL of 24h+','Review withdrawal behaviour with archive owner'],
 ['scansEligible','Coverage','Reported scan-eligible resources','Unknown if DevTools was closed or metrics were not reported'],
 ['scansChecked','Coverage','Reported inspected resources','A saved scan count cannot certify all resources were inspected'],
 ['retentionDrops','Coverage','Reported dropped events','A zero recorded count does not prove absence of gaps'],
 ['missingSegments','Coverage','Missing numbered capture segments','Missing capture parts can bias all other comparisons'],
 ['unfinalized','Coverage','Unfinalized capture segments','Saved records may represent an unfinished investigation']
]);
const SAFE_VENDORS=Object.freeze(['Capture DAM','ResourceSpace','PhotoShelter','Bynder','Cloudinary','Canto','FotoWare / FotoWeb']);
const SAFE_CONFIDENCE=Object.freeze(['Strong indication','Moderate indication','Weak clue','Not observed']);
const SAFE_ASSESSMENTS=Object.freeze(['Observed in both selected captures','Newly observed in selected later capture','Not observed later; absence unverified']);
const BLINDSPOTS=Object.freeze(['No recorded HTTP traffic','Missing capture segments','Unfinalized captures','Reported dropped events','Resource scan coverage incomplete or unknown','Media policy analysis truncated or request records dropped']);
const SAFE_NOTES=Object.freeze([
 ['Owner review','More public long-cache media responses observed','Ask the archive owner whether cache lifetime and asset withdrawal are intentional; do not infer bypass or anonymous access.'],
 ['Owner review','Locally marked changed security indicators observed','Review the masked indicator history with the asset owner; no credential was tested.'],
 ['Information','More denied media responses observed','Review access and session context. A denial is evidence that a request was rejected, not evidence of a weakness.'],
 ['Coverage review','Comparison has capture blind spots','Verify DevTools timing, host permissions, record retention and capture completion before treating differences as changes.'],
 ['Ordering','Selected captures are not in chronological order','Select the earlier capture on the left if you want to describe a chronological change.']
]);
const LIMITATIONS=Object.freeze([
 'Changes are differences in saved observations, not proof of new vulnerabilities, removals or permission changes.',
 'Varying navigation, log-in state, host permissions, browser cache and DevTools timing can change measured counts.',
 'Missing platform hints do not establish that a provider is no longer in use.',
 'Neither a 2xx response nor an original-labelled URL establishes anonymous access or master-file rights.',
 'Only fixed descriptions, numeric counts and the selected origin are exported; no request data, signatures or IDs.'
]);
const safeNum=v=>Number.isSafeInteger(v)&&v>=0?Math.min(v,1000000000):0;
function groupKey(records){const r=records?.[0];return typeof (r?.captureGroupId||r?.sessionId)==='string'?(r.captureGroupId||r.sessionId):'';}
function snapshot(records){
 const doc=CASE.build(records);let deliveryAvailable=!!DELIVERY;
 const media={received:0,restricted:0,signed:0,publicLongCache:0};
 let policyTruncated=false;
 if(deliveryAvailable)for(const r of records){
  const requestList=Array.isArray(r?.requests)?r.requests.filter(x=>!x?.carriedFromSegment):[];
  if(requestList.length>4000)policyTruncated=true;
  const s=DELIVERY.analyze({...r,requests:requestList})?.summary||{};
  if(s.truncated)policyTruncated=true;
  for(const [k,src] of [['received','received'],['restricted','restricted'],['signed','signed'],['publicLongCache','publicLongCache']])media[k]+=safeNum(s[src]);
 }
 let changed=0;
 for(const r of records)for(const f of (Array.isArray(r?.findings)?r.findings:[]).slice(0,2000)){
  if(f?.carriedFromSegment)continue;
  if(String(f?.changeState||'').toLowerCase()==='changed')changed++;
 }
 const v={
  requests:safeNum(doc.counts.requests),status2xx:safeNum(doc.httpStatuses['2xx observed']),
  status4xx:safeNum(doc.httpStatuses['4xx observed']),status5xx:safeNum(doc.httpStatuses['5xx observed']),
  findings:safeNum(doc.counts.findings),changedFindings:safeNum(changed),
  downloadsComplete:safeNum(doc.downloads.completed),downloadsInterrupted:safeNum(doc.downloads.interrupted),
  verifiedImages:safeNum(doc.counts.verifications),
  mediaDelivered:deliveryAvailable?safeNum(media.received):null,
  mediaRestricted:deliveryAvailable?safeNum(media.restricted):null,
  signedMedia:deliveryAvailable?safeNum(media.signed):null,
  publicLongCache:deliveryAvailable?safeNum(media.publicLongCache):null,
  scansEligible:safeNum(doc.scanner.eligibleReported),scansChecked:safeNum(doc.scanner.scannedReported),
  retentionDrops:safeNum(doc.evidence.find(e=>e.category==='Retention')?.count),
  missingSegments:safeNum(doc.segmentSummary.missingCount),unfinalized:safeNum(doc.segmentSummary.unfinalized)
 };
 const blindspots=[];
 if(!doc.counts.requests)blindspots.push('No recorded HTTP traffic');
 if(doc.segmentSummary.missingCount)blindspots.push('Missing capture segments');
 if(doc.segmentSummary.unfinalized)blindspots.push('Unfinalized captures');
 if(v.retentionDrops)blindspots.push('Reported dropped events');
 if(doc.scanner.coverageIncompleteOrUnknown)blindspots.push('Resource scan coverage incomplete or unknown');
 if(policyTruncated)blindspots.push('Media policy analysis truncated or request records dropped');
 return {origin:doc.siteOrigin,period:doc.period,segments:doc.segmentSummary.included,counts:v,platforms:doc.platforms,
  blindspots,observedRequests:doc.counts.requests};
}
function compare(earlier,later){
 if(!Array.isArray(earlier)||!Array.isArray(later)||!earlier.length||!later.length)throw Error('Select two saved capture groups');
 const aId=groupKey(earlier),bId=groupKey(later);if(!aId||!bId||aId===bId)throw Error('Select different capture groups');
 const a=snapshot(earlier),b=snapshot(later);
 if(a.origin!==b.origin)throw Error('Case changes require the same website origin');
 const metrics=METRIC_DEFS.map(([id,category,label,qualification])=>{
  const x=a.counts[id],y=b.counts[id];const missing=x===null||y===null;
  return {category,label,earlier:missing?null:x,later:missing?null:y,
   delta:missing?null:y-x,observation:missing?'Not measured':y>x?'More recorded':y<x?'Fewer recorded':'Same recorded count',qualification};
 });
 const vendors=new Set([...a.platforms.map(p=>p.vendor),...b.platforms.map(p=>p.vendor)]);
 const profiles=[...vendors].sort().map(v=>{const left=a.platforms.find(p=>p.vendor===v),right=b.platforms.find(p=>p.vendor===v);
  return {vendor:v,earlier:left?.confidence||'Not observed',later:right?.confidence||'Not observed',
   assessment:left&&right?'Observed in both selected captures':right?'Newly observed in selected later capture':'Not observed later; absence unverified'};
 });
 const blindspots=[...new Set([...a.blindspots.map(x=>'Earlier: '+x),...b.blindspots.map(x=>'Later: '+x)])];
 const poor=blindspots.length>0||!a.observedRequests||!b.observedRequests;
 const notes=[];
 if(b.counts.publicLongCache>a.counts.publicLongCache)notes.push({priority:'Owner review',finding:'More public long-cache media responses observed',
  action:'Ask the archive owner whether cache lifetime and asset withdrawal are intentional; do not infer bypass or anonymous access.'});
 if(b.counts.changedFindings>0)notes.push({priority:'Owner review',finding:'Locally marked changed security indicators observed',
  action:'Review the masked indicator history with the asset owner; no credential was tested.'});
 if(b.counts.mediaRestricted>a.counts.mediaRestricted)notes.push({priority:'Information',finding:'More denied media responses observed',
  action:'Review access and session context. A denial is evidence that a request was rejected, not evidence of a weakness.'});
 if(poor)notes.push({priority:'Coverage review',finding:'Comparison has capture blind spots',
  action:'Verify DevTools timing, host permissions, record retention and capture completion before treating differences as changes.'});
 const orderWarning=!!(a.period.earliest&&b.period.earliest&&a.period.earliest>b.period.earliest);
 if(orderWarning)notes.push({priority:'Ordering',finding:'Selected captures are not in chronological order',
  action:'Select the earlier capture on the left if you want to describe a chronological change.'});
 return {format:'trufflehog-case-drift',schema:1,siteOrigin:a.origin,
  comparisonConfidence:poor?'Limited by missing or incomplete evidence':'Descriptive only; not a security certification',
  earlier:{segments:a.segments,period:a.period,blindspotCount:a.blindspots.length},
  later:{segments:b.segments,period:b.period,blindspotCount:b.blindspots.length},
  metrics,profiles,notes,blindspots:blindspots.slice(0,20),
  limitations:[...LIMITATIONS]
 };
}
function exportable(report){
 if(report?.format!=='trufflehog-case-drift'||report.schema!==1||!Array.isArray(report.metrics)||report.metrics.length!==METRIC_DEFS.length)
  throw Error('Invalid case comparison');
 let origin;try{const u=new URL(report.siteOrigin);if(!/^https?:$/.test(u.protocol)||u.username||u.password||u.origin!==report.siteOrigin)throw Error();origin=u.origin;}
 catch{throw Error('Invalid comparison site origin');}
 const number=v=>{if(v===null)return null;if(!Number.isSafeInteger(v)||v<0||v>1000000000)throw Error('Invalid comparison count');return v;};
 const metrics=METRIC_DEFS.map(([id,category,label,qualification],i)=>{
  const r=report.metrics[i];if(!r||r.category!==category||r.label!==label)throw Error('Unsupported comparison metric');
  const earlier=number(r.earlier),later=number(r.later),unknown=earlier===null||later===null;
  return {category,label,earlier:unknown?null:earlier,later:unknown?null:later,delta:unknown?null:later-earlier,
   observation:unknown?'Not measured':later>earlier?'More recorded':later<earlier?'Fewer recorded':'Same recorded count',qualification};
 });
 const time=v=>typeof v==='string'&&!Number.isNaN(Date.parse(v))?new Date(v).toISOString():null;
 const capture=part=>({segments:number(part?.segments),period:{earliest:time(part?.period?.earliest),latest:time(part?.period?.latest)},blindspotCount:number(part?.blindspotCount)});
 const profiles=(Array.isArray(report.profiles)?report.profiles:[]).slice(0,SAFE_VENDORS.length).map(p=>{
  if(!SAFE_VENDORS.includes(p?.vendor)||!SAFE_CONFIDENCE.includes(p.earlier)||!SAFE_CONFIDENCE.includes(p.later))throw Error('Invalid platform evidence');
  const assessment=p.earlier==='Not observed'?'Newly observed in selected later capture':p.later==='Not observed'?'Not observed later; absence unverified':'Observed in both selected captures';
  return {vendor:p.vendor,earlier:p.earlier,later:p.later,assessment};
 });
 const notes=(Array.isArray(report.notes)?report.notes:[]).slice(0,SAFE_NOTES.length).map(note=>{
  const match=SAFE_NOTES.find(([priority,finding,action])=>note?.priority===priority&&note?.finding===finding&&note?.action===action);
  if(!match)throw Error('Invalid case review note');return {priority:match[0],finding:match[1],action:match[2]};
 });
 const blindspots=(Array.isArray(report.blindspots)?report.blindspots:[]).slice(0,20).map(v=>{
  const match=/^(Earlier|Later): (.+)$/.exec(v);if(!match||!BLINDSPOTS.includes(match[2]))throw Error('Invalid capture limitation');return match[1]+': '+match[2];
 });
 return {format:'trufflehog-case-drift',schema:1,siteOrigin:origin,
  comparisonConfidence:blindspots.length?'Limited by missing or incomplete evidence':
   ['Limited by missing or incomplete evidence','Descriptive only; not a security certification'].includes(report.comparisonConfidence)?report.comparisonConfidence:'Descriptive only; not a security certification',
  earlier:capture(report.earlier),later:capture(report.later),metrics,profiles,notes,blindspots,limitations:[...LIMITATIONS]};
}
function csv(report){
 const clean=exportable(report);
 const quote=v=>'"'+String(v??'').replaceAll('"','""')+'"';
 return ['Category,Metric,Earlier,Later,Delta,Observation,Qualification',...clean.metrics.map(r=>[r.category,r.label,r.earlier,r.later,r.delta,r.observation,r.qualification].map(quote).join(','))].join('\r\n');
}
async function pack(report){const safe=exportable(report);
 const digest=await CASE.digest(safe);return {format:'trufflehog-case-drift-file',version:1,integrity:'sha256-not-authentication',sha256:digest,report:safe};
}
const api={snapshot,compare,csv,pack};root.THICaseCompare=api;
if(typeof module!=='undefined'&&module.exports)module.exports=api;
})(typeof self!=='undefined'?self:globalThis);
