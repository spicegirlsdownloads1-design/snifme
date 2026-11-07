/* v5.8 offline case dossier. Strict allowlists: no URLs beyond approved site origin,
 * no secret values, identifiers, source code or request bodies in reports. */
(function(root){'use strict';
const MAX_SEGMENTS=120,MAX_TIMELINE=250;
const types=['requests','assets','verifications','findings','resourceScans','downloadEvents','galleryAssets','responses'];
const n=v=>Number.isSafeInteger(v)&&v>=0?v:0;
const list=(r,key)=>Array.isArray(r?.[key])?r[key]:[];
const cleanTime=v=>{const d=typeof v==='string'?Date.parse(v):NaN;return Number.isFinite(d)?new Date(d).toISOString():null;};
const site=v=>{try{const u=new URL(v);return /^https?:$/.test(u.protocol)&&!u.username&&!u.password?u.origin:null;}catch{return null;}};
const CLASSIFICATIONS=Object.freeze(['Capture DAM','ResourceSpace','PhotoShelter','Bynder','Cloudinary','Canto','FotoWare / FotoWeb']);
const CONFIDENCES=['Strong indication','Moderate indication','Weak clue'];
const statuses=['2xx observed','3xx observed','4xx observed','5xx observed','Status unavailable'];
function build(records){
 if(!Array.isArray(records)||!records.length||records.length>MAX_SEGMENTS)throw Error('Select 1–120 saved capture segments');
 const rows=[...records].sort((a,b)=>(a?.segmentIndex||1)-(b?.segmentIndex||1));
 const origin=site(rows[0]?.origin),gid=rows[0]?.captureGroupId||rows[0]?.sessionId;
 if(!origin||typeof gid!=='string'||!gid||rows.some(r=>site(r?.origin)!==origin||(r.captureGroupId||r.sessionId)!==gid))throw Error('A case dossier needs one capture group and one site origin');
 const indices=new Set(),sessions=new Set();
 for(const r of rows){const idx=r.segmentIndex||1;
  if(!Number.isInteger(idx)||idx<1||idx>2000||indices.has(idx)||!r.sessionId||sessions.has(r.sessionId))throw Error('Invalid or repeated capture segment');
  indices.add(idx);sessions.add(r.sessionId);
 }
 const missing=[];for(let i=1;i<=Math.max(...indices);i++)if(!indices.has(i))missing.push(i);
 const counts=Object.fromEntries(types.map(t=>[t,0]));
 const http=Object.fromEntries(statuses.map(s=>[s,0]));
 const times=[],timeItems=[];
 const platformMap=new Map();
 let scanEligible=0,scanChecked=0,retentionLoss=0;
 let activeOrUnfinalized=0;
 let downloadCompleted=0,downloadInterrupted=0;
 const classify=(v)=>{const c=n(Number(v));return c>=200&&c<300?statuses[0]:c>=300&&c<400?statuses[1]:c>=400&&c<500?statuses[2]:c>=500&&c<600?statuses[3]:statuses[4];};
 const putTime=(at,kind)=>{const iso=cleanTime(at);if(iso&&timeItems.length<2500)timeItems.push({at:iso,kind});};
 for(const r of rows){
  if(cleanTime(r.createdAt))times.push(cleanTime(r.createdAt));
  if(cleanTime(r.endedAt))times.push(cleanTime(r.endedAt));else activeOrUnfinalized++;
  for(const t of types){let entries=list(r,t).filter(x=>!x?.carriedFromSegment);counts[t]+=entries.length;
   if(t==='requests')for(const x of entries){http[classify(x?.status||x?.statusCode)]++;putTime(x?.at,'HTTP request');}
   if(t==='findings')for(const x of entries)putTime(x?.at,'Masked security indicator');
   if(t==='downloadEvents')for(const x of entries){const k=String(x?.downloadStatus||x?.state||x?.status||'').toLowerCase();if(k==='complete')downloadCompleted++;if(k==='interrupted')downloadInterrupted++;putTime(x?.at,'Browser download event');}
   if(t==='verifications')for(const x of entries)putTime(x?.at,'Observed file verification');
  }
  const coverage=r.autoScanCoverage;
  if(coverage&&typeof coverage==='object'){
   // Coverage schemas vary across releases: use only explicit supported numeric fields.
   scanEligible+=n(coverage.eligibleResources??coverage.eligible??0);
   scanChecked+=n(coverage.scannedResources??coverage.scanned??0);
  }
  for(const [key,value]of Object.entries(r.counters||{}))if(/Dropped$/i.test(key))retentionLoss+=n(value);
  const profiles=root.THIDAMSpecialists?.analyze?.(r)?.profiles||[];
  for(const p of profiles){if(!CLASSIFICATIONS.includes(p.vendor)||!CONFIDENCES.includes(p.confidence))continue;
   const previous=platformMap.get(p.vendor);
   const confidence=!previous||CONFIDENCES.indexOf(p.confidence)<CONFIDENCES.indexOf(previous.confidence)?p.confidence:previous.confidence;
   platformMap.set(p.vendor,{vendor:p.vendor,confidence,observedSegments:(previous?.observedSegments||0)+1});
  }
 }
 const segments=rows.length;
 const evidence=[
  {category:'Network',status:counts.requests?'Observed':'Unverified',statement:counts.requests?'HTTP request metadata was recorded.':'No recorded HTTP requests in these segments.',count:counts.requests,qualification:'Requests not seen by Chrome may still have occurred.'},
  {category:'Image quality',status:counts.verifications?'Observed':'Unverified',statement:counts.verifications?'Some received image bytes were fingerprinted.':'No verified received-image byte evidence.',count:counts.verifications,qualification:'Verified image delivery does not establish master-file access.'},
  {category:'Masked indicators',status:counts.findings?'Observed':'Unverified',statement:counts.findings?'Masked potential security indicators were recorded.':'No masked indicators recorded in selected segments.',count:counts.findings,qualification:'Indicators are not confirmed working credentials; none recorded does not establish absence.'},
  {category:'Browser downloads',status:counts.downloadEvents?'Observed':'Unverified',statement:counts.downloadEvents?'Browser download lifecycle events were recorded.':'No browser download events recorded.',count:counts.downloadEvents,qualification:'Browser downloads may not be attributable to a specific HTTP POST.'},
  {category:'DAM identification',status:platformMap.size?'Inferred':'Unverified',statement:platformMap.size?'Supported vendor-specific recognition clues were detected.':'No supported vendor-specific clues recorded.',count:platformMap.size,qualification:'Vendor traffic does not establish repository ownership or security posture.'},
  {category:'Capture continuity',status:missing.length?'Unverified':segments>1?'Observed':'Unverified',statement:missing.length?'At least one numbered capture segment is absent.':segments>1?'Saved segment numbers are contiguous.':'Only one segment is in this dossier.',count:missing.length,qualification:'Contiguous segment numbers do not prove complete browser visibility.'},
  {category:'Retention',status:retentionLoss?'Unverified':'Observed',statement:retentionLoss?'Recorded event drops or truncations were reported.':'No supported retention-drop counters were recorded.',count:retentionLoss,qualification:'No recorded drops does not mean no uncaptured events.'},
  {category:'Capture finality',status:activeOrUnfinalized?'Unverified':'Observed',statement:activeOrUnfinalized?'Some saved segments lack an end timestamp.':'All selected segments have an end timestamp.',count:activeOrUnfinalized,qualification:'Completion of capture is not proof of complete collection.'}
 ];
 const findings=evidence.filter(e=>e.status==='Unverified').length;
 const timeline=timeItems.sort((a,b)=>a.at.localeCompare(b.at)||a.kind.localeCompare(b.kind));
 return {format:'trufflehog-investigation-dossier',schema:1,siteOrigin:origin,
  period:{earliest:times.sort()[0]||null,latest:times[times.length-1]||null},
  segmentSummary:{included:segments,highestSegment:Math.max(...indices),missingNumbers:missing.slice(0,80),missingCount:missing.length,unfinalized:activeOrUnfinalized},
  counts,httpStatuses:http,downloads:{completed:downloadCompleted,interrupted:downloadInterrupted},
  scanner:{eligibleReported:scanEligible,scannedReported:scanChecked,coverageIncompleteOrUnknown:!scanEligible||scanChecked<scanEligible},
  platforms:[...platformMap.values()].sort((a,b)=>a.vendor.localeCompare(b.vendor)),
  evidence,review:{unverifiedCategories:findings,statement:findings?'Some dossier categories cannot be verified from the saved observations.':'No category-level warning was identified, but this is not a complete-security or capture certification.'},
  timeline:timeline.slice(0,MAX_TIMELINE),timelineTotal:timeline.length,timelineTruncated:timeline.length>MAX_TIMELINE,
  limitations:[
   'This report is an offline summary of already stored browser observations, not a penetration test.',
   'Missing observations, especially when DevTools was closed, are not evidence that a system or asset does not exist.',
   'Request relationships, product identity and access permissions cannot be established from timing or hostnames alone.',
   'Neither a browser-delivered file nor its size proves access to a private original or a licensing entitlement.',
   'No raw credentials, signed URLs, POST values, trace IDs, local file paths or complete request routes are exported.'
  ]};
}
async function digest(value){const api=root.crypto?.subtle;if(!api)throw Error('WebCrypto unavailable');const bytes=new TextEncoder().encode(JSON.stringify(value));const hash=new Uint8Array(await api.digest('SHA-256',bytes));return [...hash].map(v=>v.toString(16).padStart(2,'0')).join('');}
async function pack(report){if(report?.format!=='trufflehog-investigation-dossier'||report.schema!==1)throw Error('Invalid dossier');return {format:'trufflehog-case-file',version:1,integrity:'sha256-not-authentication',sha256:await digest(report),report};}
async function verify(item){if(item?.format!=='trufflehog-case-file'||item.version!==1||!item.report||typeof item.sha256!=='string'||!/^[a-f0-9]{64}$/.test(item.sha256))throw Error('Unsupported case file');
 if(item.report.format!=='trufflehog-investigation-dossier'||item.report.schema!==1||!site(item.report.siteOrigin)||JSON.stringify(item.report).length>2000000)throw Error('Invalid case file contents');
 if(await digest(item.report)!==item.sha256)throw Error('Case file integrity mismatch');
 // Only display fields generated by the dossier builder. Never render arbitrary imported field values.
 const report=item.report;
 if(!report.counts||!Array.isArray(report.evidence)||report.evidence.length>12||!Array.isArray(report.timeline)||report.timeline.length>MAX_TIMELINE||!Array.isArray(report.platforms)||report.platforms.length>CLASSIFICATIONS.length)throw Error('Invalid case report shape');
 if(report.evidence.some(e=>!['Network','Image quality','Masked indicators','Browser downloads','DAM identification','Capture continuity','Retention','Capture finality'].includes(e.category)||!['Observed','Inferred','Unverified'].includes(e.status)))throw Error('Invalid case evidence');
 if(report.platforms.some(p=>!CLASSIFICATIONS.includes(p.vendor)||!CONFIDENCES.includes(p.confidence)))throw Error('Invalid case profile');
 if(report.timeline.some(t=>!['HTTP request','Masked security indicator','Browser download event','Observed file verification'].includes(t.kind)||!cleanTime(t.at)))throw Error('Invalid case timeline');
 return true;
}
function csv(report){const q=v=>'"'+String(v??'').replaceAll('"','""')+'"';return ['Category,Status,Count,Observation,Qualification',...report.evidence.map(e=>[e.category,e.status,n(e.count),e.statement,e.qualification].map(q).join(','))].join('\r\n');}
root.THICase={build,digest,pack,verify,csv};if(typeof module!=='undefined'&&module.exports)module.exports=root.THICase;
})(typeof self!=='undefined'?self:globalThis);
