/* v4.3: local evidence-quality audit. No URLs, credentials, or source contents in output.
 * A passing audit is not a security clearance or proof of site-wide capture completeness. */
(function(root){'use strict';
const safeCount=v=>Number.isSafeInteger(v)&&v>=0?v:0;
const size=v=>Array.isArray(v)?v.length:0;
const status=(id,result,detail)=>({id,status:result,detail});
function assess(record,recording,summaries=[],now=Date.now()){
 const checks=[];
 const add=(id,s,detail)=>checks.push(status(id,s,detail));
 if(!record){add('capture-record','unknown','No recorded investigation is selected.');
   return {version:1,createdAt:new Date(now).toISOString(),readiness:'Not assessable',summary:{pass:0,warn:0,unknown:1},checks,metrics:{}};}
 add('capture-record',record.sessionId&&record.createdAt?'pass':'warn',record.sessionId&&record.createdAt?'A session ID and creation timestamp are recorded.':'Capture identifier or timestamp is missing.');
 const rsize=size(record.requests),images=size(record.assets),findings=size(record.findings);
 add('observations',rsize+images>0?'pass':'unknown',rsize+images>0?`${rsize} request(s) and ${images} image record(s) observed.`:'No requests or images were recorded; browser coverage cannot be inferred.');
 const health=root.THIHealth?.assess?root.THIHealth.assess(record,recording,now):null;
 if(!health){add('devtools-coverage','unknown','Scan coverage helper unavailable.');}
 else if(health.code==='observed-complete')add('devtools-coverage','pass',`Inspected ${health.scanned} of ${health.eligible} eligible resources seen by DevTools; earlier resources remain unknown.`);
 else if(health.code==='partial')add('devtools-coverage','warn',`${health.scanned} scanned, ${health.excluded} excluded and ${health.unaccounted} unaccounted eligible resources.`);
 else if(health.code==='stale')add('devtools-coverage','warn','The DevTools scanner heartbeat is stale or absent during an active capture.');
 else add('devtools-coverage','unknown',`Scanner state: ${health.title}. This does not establish coverage.`);
 const losses=Object.entries(record.counters||{}).filter(([key])=>/Dropped$/i.test(key)).reduce((a,[,value])=>a+safeCount(value),0);
 add('retention-loss',losses?'warn':'pass',losses?`${losses} recorded retention drop(s) or overwrite(s).`:'No drops reported by supported capture counters; unobserved events remain unknown.');
 const ongoing=!!recording?.enabled;
 add('capture-finality',ongoing?'unknown':record.endedAt?'pass':'unknown',ongoing?'Capture is active; final counts may change.':record.endedAt?'A capture end timestamp is recorded.':'No end timestamp; this may be an interrupted or legacy session.');
 const seg=safeCount(record.segmentIndex)||1,groupId=record.captureGroupId||record.sessionId;
 const arr=Array.isArray(summaries)?summaries:[];
 const same=arr.filter(x=>x&&(x.captureGroupId||x.sessionId||x.id)===groupId).map(x=>safeCount(x.segmentIndex)||1);
 if(seg>1 || same.some(x=>x>1)){
   if(!same.length)add('segment-continuity','unknown','No saved segment summaries available to verify capture-group continuity.');
   else{
     const unique=new Set(same);if(!unique.has(seg)&&record.sessionId)unique.add(seg); // selected active/saved record
     const upper=Math.max(seg,...unique),missing=[];
     for(let i=1;i<=Math.min(upper,10000);i++)if(!unique.has(i))missing.push(i);
     add('segment-continuity',missing.length?'warn':'pass',missing.length?`Missing segment number(s): ${missing.slice(0,12).join(', ')}${missing.length>12?'…':''}.`:`${unique.size} numbered segment(s) accounted for in saved summaries/current record.`);
   }
 }else add('segment-continuity','pass','Single-segment record; no rollover continuity required.');
 add('sensitive-review',safeCount(record.unreviewedAlerts)>0?'warn':'pass',safeCount(record.unreviewedAlerts)>0?`${safeCount(record.unreviewedAlerts)} masked finding alert(s) await review.`:'No unreviewed alerts reported; this does not establish that secrets are absent.');
 const summary={pass:checks.filter(x=>x.status==='pass').length,warn:checks.filter(x=>x.status==='warn').length,unknown:checks.filter(x=>x.status==='unknown').length};
 const readiness=summary.warn?'Review required':summary.unknown?'Evidence incomplete':'No reported capture gaps';
 return {version:1,createdAt:new Date(now).toISOString(),readiness,summary,checks,
   metrics:{requests:rsize,images,findings,scanned:health?.scanned??0,eligible:health?.eligible??0,retentionDrops:losses,segmentCount:same.length||1},
   qualification:'Only previously recorded evidence is assessed. No result guarantees complete site scanning, no exposed secrets, or correct server authorisation.'};
}
root.THICaptureAudit={assess};
if(typeof module!=='undefined'&&module.exports)module.exports=root.THICaptureAudit;
})(typeof self!=='undefined'?self:globalThis);
