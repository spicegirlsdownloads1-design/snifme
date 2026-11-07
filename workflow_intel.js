/* Trufflehog v5.4 — entirely offline workflow reconstruction and coverage audit.
 * Only the existing REDACTED request events are consumed. Never export HTTP
 * request IDs, raw headers, URLs, POST bodies, secrets or file paths.
 * Across requests we make correlations, not server-side causation claims.
 */
'use strict';
const THIWorkflow = (() => {
  const stages=new Set(['request','headers','response-headers','redirect','complete','error','download-start','download-state']);
  const methods=new Set(['GET','POST','PUT','PATCH','DELETE','HEAD']);
  const statuses=new Set(['started','progress','complete','interrupted']);
  const categories=new Set(['network','server','filesystem','user action','browser','other','unknown']);
  const host=s=>typeof s==='string'&&s.length<=253&&/^[a-z0-9.-]+$/i.test(s)&&!s.includes('..')?s.toLowerCase():'';
  const date=s=>typeof s==='string'&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(s)&&Number.isFinite(Date.parse(s))?s:'';
  const count=n=>Number.isSafeInteger(n)&&n>=0?Math.min(1000000,n):0;
  const status=n=>Number.isInteger(n)&&n>=100&&n<=599?n:null;
  const mime=x=>typeof x==='string'&&/^(?:image|video|audio|application)\/[a-z0-9.+-]{1,40}$/.test(x)?x:'';
  const trace=x=>typeof x==='string'&&/^Trace [1-9]\d{0,3}$/.test(x)?x:'';
  const safeRef=x=>typeof x==='string'&&/^DL[1-9]\d{0,21}$/.test(x)?x:'';
  const time=e=>Date.parse(e.at)||0;
  function cleanEvent(e){
    if(!e||!stages.has(e.stage)||!date(e.at))return null;
    const result={stage:e.stage,at:date(e.at),host:host(e.host),method:methods.has(e.method)?e.method:'',
      status:status(e.status),redirectHost:host(e.redirectHost),traceRef:trace(e.traceRef),
      fileType:mime(e.fileType),attachment:e.attachment===true,
      signed: Array.isArray(e.signedIndicators)&&e.signedIndicators.some(x=>typeof x==='string'&&/^(?:URL signing fields|URL expiry field|URL credential field|Cloud signing algorithm field)$/.test(x)),
      downloadStatus:statuses.has(e.downloadStatus)?e.downloadStatus:'',
      downloadRef:safeRef(e.downloadRef),errorCategory:categories.has(e.errorCategory)?e.errorCategory:'',
      awsUpload:e.awsDam?.operation==='S3 presigned POST request observed'||e.awsDam?.operation==='S3 upload request observed',
      contentLength:Number.isSafeInteger(e.contentLengthBytes)&&e.contentLengthBytes>=0&&e.contentLengthBytes<=1e13?e.contentLengthBytes:null,
      totalBytes:Number.isSafeInteger(e.totalBytes)&&e.totalBytes>=0&&e.totalBytes<=1e13?e.totalBytes:null,
      receivedBytes:Number.isSafeInteger(e.receivedBytes)&&e.receivedBytes>=0&&e.receivedBytes<=1e13?e.receivedBytes:null
    };
    return result;
  }
  function compile(record){
    const raw=Array.isArray(record?.downloadEvents)?record.downloadEvents.slice(0,10000):[];
    const http=new Map(),downloads=new Map(),unidentified=[];
    for(const e of raw){
      const x=cleanEvent(e);if(!x)continue;
      if(['download-start','download-state'].includes(x.stage)){
        const ref=x.downloadRef;
        if(!ref){unidentified.push(x);continue;}
        if(!downloads.has(ref))downloads.set(ref,[]);
        downloads.get(ref).push(x);
      }else if(typeof e.requestId==='string'&&e.requestId&&e.requestId.length<=120){
        // Browser request IDs are private grouping keys; never returned by compile().
        if(!http.has(e.requestId))http.set(e.requestId,[]);
        http.get(e.requestId).push(x);
      }
    }
    const requests=[...http.values()].map(events=>{
      events.sort((a,b)=>time(a)-time(b));
      const first=events[0],last=events.at(-1);
      const completion=[...events].reverse().find(x=>x.stage==='complete'||x.stage==='error');
      const statusStage=[...events].reverse().find(x=>x.status!==null);
      const redirected=events.find(x=>x.stage==='redirect'&&x.redirectHost);
      const type=events.find(x=>x.fileType);
      const withTrace=events.find(x=>x.traceRef);
      const hasBody=events.some(x=>x.stage==='request');
      const method=events.find(x=>x.method)?.method||'';
      return {at:first.at,endedAt:last.at,host:events.find(x=>x.host)?.host||'',method,status:statusStage?.status??null,
        stages:[...new Set(events.map(e=>e.stage))],redirectHost:redirected?.redirectHost||'',
        traceRef:withTrace?.traceRef||'',fileType:type?.fileType||'',attachment:events.some(x=>x.attachment),
        signed:events.some(x=>x.signed),error:completion?.stage==='error',completed:completion?.stage==='complete',
        awsUpload:events.some(x=>x.awsUpload),contentLength:events.find(x=>x.contentLength!==null)?.contentLength??null,
        started:hasBody};
    }).sort((a,b)=>time(a)-time(b));
    const dl=[...downloads.entries()].map(([ref,events])=>{
      events.sort((a,b)=>time(a)-time(b));
      return {downloadRef:ref,at:events[0].at,host:events.find(x=>x.host)?.host||'',
        referrerHost:host(raw.find(e=>e.downloadRef===ref&&e.stage==='download-start')?.referrerHost),
        status:events.at(-1).downloadStatus,errorCategory:events.at(-1).errorCategory,
        totalBytes:events.at(-1).totalBytes??events[0].totalBytes,
        receivedBytes:events.at(-1).receivedBytes??events[0].receivedBytes,
        hasStart:events.some(x=>x.stage==='download-start'),hasEnd:events.some(x=>x.downloadStatus==='complete'||x.downloadStatus==='interrupted')};
    }).sort((a,b)=>time(a)-time(b));
    return {requests,downloads:dl,unattributedDownloads:unidentified};
  }
  const diffSeconds=(a,b)=>Math.round((Date.parse(b)-Date.parse(a))/1000);
  function analyse(record){
    const {requests,downloads,unattributedDownloads}=compile(record);
    const anchors=requests.filter(r=>['POST','PUT','PATCH'].includes(r.method)&&!r.awsUpload).slice(-150);
    const flows=[];
    const usedDownloads=new Set();
    for(let i=0;i<anchors.length;i++){
      const a=anchors[i],matches=[];
      // Observations on other HTTP request IDs are never promoted to "confirmed".
      for(const b of requests){
        if(a===b||b.method!=='GET')continue;
        const seconds=diffSeconds(a.at,b.at);
        if(seconds<0||seconds>120)continue;
        const traceMatch=a.traceRef&&a.traceRef===b.traceRef;
        const redirected=a.redirectHost&&a.redirectHost===b.host;
        const sameHost=a.host&&a.host===b.host;
        const delivery=b.attachment||b.signed||b.redirectHost||(/^(?:image|video|audio|application\/(?:zip|octet-stream|pdf))/.test(b.fileType));
        const potentialPoll=a.status===202&&sameHost;
        if(!(traceMatch||redirected||(sameHost&&(delivery||potentialPoll))))continue;
        const level=traceMatch?'shared local trace label':redirected?'redirect-host and timing match':sameHost?'same host and timing':'timing only';
        matches.push({b,seconds,level,score:traceMatch?3:redirected?2:1});
      }
      matches.sort((x,y)=>y.score-x.score||x.seconds-y.seconds);
      const related=matches.slice(0,5).map(({b,level})=>({at:b.at,host:b.host,method:b.method,status:b.status,
        step:b.attachment?'Attachment response':b.signed?'Signed-delivery indicator':b.status===202?'Accepted response':'Candidate follow-up',
        evidence:level}));
      const possiblePolls=matches.filter(x=>x.b.host===a.host&&x.b.method==='GET').length;
      const compatible=downloads.filter(d=>{
        const delta=diffSeconds(a.at,d.at);
        return delta>=0&&delta<=120&&d.referrerHost===a.host&&!usedDownloads.has(d.downloadRef);
      });
      // Deliberately do not attach a download when multiple eligible POSTs exist.
      const d=compatible.length===1 && anchors.filter(other=>other!==a&&other.host===a.host&&
        diffSeconds(other.at,compatible[0].at)>=0&&diffSeconds(other.at,compatible[0].at)<=120).length===0?compatible[0]:null;
      if(d)usedDownloads.add(d.downloadRef);
      const job=a.status===202?(possiblePolls?'Possible asynchronous export; polling-like GETs observed':'202 Accepted; follow-up job state not verified'):'Not established';
      const confidence=related.some(x=>x.evidence==='shared local trace label')?'Associated — shared trace label':
        related.some(x=>x.evidence==='redirect-host and timing match')?'Associated — redirect-host clue':
        d?'Associated — referrer and timing':related.length?'Hypothesis — host and timing':'Single HTTP request only';
      const outcome=d?(d.status==='complete'?'Download completed in browser':d.status==='interrupted'?'Download interrupted':'Download start observed'):
        (a.attachment?'Attachment response observed':a.error?'HTTP request failed':a.completed?'HTTP request completed':'Request completion not observed');
      flows.push({ref:`WF${flows.length+1}`,at:a.at,host:a.host,method:a.method,httpStatus:a.status,
        initialStages:a.stages,redirectHost:a.redirectHost,deliveryIndicator:a.signed||a.attachment,
        classification:job,confidence,outcome,
        related,downloadRef:d?.downloadRef||'',downloadBytes:d?.receivedBytes??null,
        evidence:['Initial request stages share one observed browser request ID.',
          ...related.map(x=>`Separate request: ${x.evidence}; causation unverified.`),
          ...(d?['Download referrer origin and timing match one candidate POST; not proof of causation.']:[])]});
    }
    // Downloads without an unambiguous POST match remain stand-alone observations.
    const orphans=downloads.filter(d=>!usedDownloads.has(d.downloadRef)).map(d=>({
      ref:d.downloadRef,at:d.at,host:d.host,status:d.status||'unknown',
      evidence:'Observed browser download; no unambiguous POST association',
      totalBytes:d.totalBytes,receivedBytes:d.receivedBytes,errorCategory:d.errorCategory}));
    return {format:'trufflehog-workflow-intelligence',version:1,workflows:flows,unassociatedDownloads:orphans,
      totals:{observedRequestLifecycles:requests.length,candidatePostWorkflows:flows.length,
        downloadsWithLocalRefs:downloads.length,downloadsWithoutLocalRefs:unattributedDownloads.length},
      limitations:['Same browser request ID confirms stages of one HTTP request, not the entire download process.',
        'Related requests are only correlations. Shared hosts, redirects or trace labels cannot establish backend causality.',
        'Only opted-in browser-visible activity is considered; other tabs, service workers and previous requests may be absent.']};
  }
  function coverage(record,recording){
    const {requests,downloads,unattributedDownloads}=compile(record);
    const saved=record&&typeof record==='object';
    const observedEnabled=record?.downloadObserverEverEnabled===true||recording?.downloadObserver===true;
    const drops=count(record?.downloadEventsDropped),n=count(record?.downloadEvents?.length);
    const checks=[];
    const add=(id,label,state,detail,quantity)=>checks.push({id,label,state,detail,count:quantity});
    add('opt-in','Observer activated',observedEnabled?'observed':saved?'unknown':'not-tested',
      observedEnabled?'Explicit opt-in recorded for this segment.':'Old/saved sessions may not record whether observation was enabled.',observedEnabled?1:0);
    add('lifecycle','Request lifecycle',!n?'not-tested':requests.some(r=>r.stages.includes('request')&&r.stages.includes('complete'))?'observed':'partial',
      'A started and completed request has been observed; no guarantee other requests were captured.',requests.length);
    const missingStart=requests.filter(r=>!r.stages.includes('request')).length;
    const missingEnd=requests.filter(r=>!r.stages.includes('complete')&&!r.stages.includes('error')).length;
    add('request-start','Unpaired HTTP starts',!requests.length?'not-tested':missingStart?'partial':'observed',
      'Request completion without a start can reflect late capture or browser visibility.',missingStart);
    add('request-end','Unpaired HTTP completions',!requests.length?'not-tested':missingEnd?'partial':'observed',
      'A request may still be active; missing completion is not necessarily an error.',missingEnd);
    add('downloads','Browser download attribution',!downloads.length&&!unattributedDownloads.length?'not-tested':unattributedDownloads.length?'partial':'observed',
      'Chrome does not provide the initiating tab ID on downloads. Referrer-origin matching is tentative.',downloads.length+unattributedDownloads.length);
    const unfinished=downloads.filter(d=>!d.hasStart||!d.hasEnd).length;
    add('download-pairs','Download completion linkage',!downloads.length?'not-tested':unfinished?'partial':'observed',
      'Local labels can be lost on a Manifest V3 worker restart; old sessions have no labels.',unfinished);
    add('retention','Event retention',!saved?'not-tested':drops?'partial':'observed',
      'A zero dropped count means only that no local cap overrun was recorded.',drops);
    const eligible=count(record?.autoScanCoverage?.eligible),scanned=count(record?.autoScanCoverage?.scanned);
    add('devtools','Optional DevTools coverage',!record?.autoScanCoverage?'not-tested':scanned>=eligible?'observed':'partial',
      'DevTools sees only responses observed after it was opened and cannot establish full-site coverage.',scanned);
    return {format:'trufflehog-workflow-coverage',version:1,checks,
      counts:{events:n,requests:requests.length,downloadLabels:downloads.length,dropped:drops,unpairedRequestStarts:missingStart,
        unpairedRequestEnds:missingEnd,unpairedDownloads:unfinished},
      conclusion:checks.some(c=>c.state==='partial')?'Coverage gaps observed':'No recorded gaps; completeness is not verified',
      limitations:['Cannot infer unseen requests or prove download initiation from timing.',
        'Only already saved, privacy-reduced evidence is analysed; this report makes no network requests.']};
  }
  function exportReport(record,recording){return {workflows:analyse(record),coverage:coverage(record,recording)};}
  return {analyse,coverage,exportReport};
})();
if(typeof globalThis!=='undefined')globalThis.THIWorkflow=THIWorkflow;
if(typeof module!=='undefined'&&module.exports)module.exports=THIWorkflow;
