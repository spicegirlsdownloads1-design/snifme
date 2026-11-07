/* v6.0 deterministic LOCAL fixture audit: summarises observed browser evidence; no requests. */
(function(root){'use strict';
const PATHS=Object.freeze([
 {id:'document',label:'Fixture page',path:'/v60-lab.html',method:'GET',status:200,description:'Top-level HTML was observed after capture began.'},
 {id:'script',label:'Fixture JavaScript',path:'/v60-lab.js',method:'GET',status:200,description:'JavaScript resource was delivered to this browser.'},
 {id:'style',label:'Fixture stylesheet',path:'/v60-lab.css',method:'GET',status:200,description:'CSS resource was delivered to this browser.'},
 {id:'json',label:'Fixture JSON',path:'/v60-lab.json',method:'GET',status:200,description:'An asynchronous JSON request was observed.'},
 {id:'image',label:'Fixture image',path:'/v60-lab.svg',method:'GET',status:200,description:'A local image request was observed.'},
 {id:'job',label:'Export API POST',path:'/v60-job',method:'POST',status:202,description:'The synthetic export POST completed with HTTP 202.'},
 {id:'status',label:'Job-status request',path:'/v60-state',method:'GET',status:200,description:'The synthetic job status request completed.'},
 {id:'file',label:'Attachment response',path:'/v60-file',method:'GET',status:200,description:'An attachment response was observed.'}
]);
function labOrigin(value){
 try{const u=new URL(String(value||''));return u.protocol==='http:'&&['localhost','127.0.0.1'].includes(u.hostname)&&u.port==='8770'&&u.pathname==='/'?u.origin:'';}catch{return '';}
}
function safeURL(value,origin){try{const u=new URL(String(value||''));return u.origin===origin?u:null;}catch{return null;}}
function count(v){return Number.isSafeInteger(v)&&v>=0?Math.min(v,1000000):0;}
function evaluate(record,recording){
 const origin=labOrigin(record?.origin);const eligible=!!origin;
 const requests=Array.isArray(record?.requests)?record.requests.slice(-750):[];
 const scans=Array.isArray(record?.resourceScans)?record.resourceScans.slice(-280):[];
 const events=Array.isArray(record?.downloadEvents)?record.downloadEvents.slice(-450):[];
 const seen=eligible&&requests.some(r=>{const u=safeURL(r?.url,origin);return !!u && (u.pathname.startsWith('/v60-'));});
 const checks=[];
 const add=(id,label,status,evidence)=>checks.push({id,label,status,evidence});
 if(!eligible){
  add('scope','Local fixture context','not-tested','Open the supplied local fixture at port 8770, start capture, and reload. No other site is evaluated.');
 }else if(!seen){
  add('scope','Local fixture traffic','not-tested','No v6.0 fixture requests are recorded. Start capture and reload the local page.');
 }
 for(const f of PATHS){
  const matching=eligible?requests.filter(r=>{const u=safeURL(r?.url,origin);return !!u&&u.pathname===f.path&&String(r?.method||'').toUpperCase()===f.method;}):[];
  const successful=matching.find(r=>Number(r?.status)===f.status && (f.id!=='file'||r.attachmentDisposition===true));
  const wrong=matching.length>0&&!successful;
  add(f.id,f.label,successful?'pass':wrong?'warn':seen?'warn':'not-tested',
   successful?f.description:wrong?'Fixture path observed, but the expected status/attachment evidence was not recorded.':seen?'Not observed; Chrome capture may be incomplete or the fixture action was not performed.':'Requires the local fixture capture.');
 }
 // Only a positively recorded response scan from our exact fixture path counts as proof of this stage.
 const scanObserved=eligible?scans.some(s=>{const u=safeURL(s?.url,origin);return !!u&&['/v60-lab.js','/v60-lab.css','/v60-lab.json'].includes(u.pathname) && /^[a-f0-9]{64}$/i.test(String(s?.sha256||''));}):false;
 add('scan','DevTools resource body inspected',scanObserved?'pass':seen?'warn':'not-tested',scanObserved?'At least one known fixture resource has a saved SHA-256 response digest.':'Open DevTools before reloading and verify the scanner is enabled; missing body evidence is not a pass.');
 const observerEnabled=record?.downloadObserverEverEnabled===true||recording?.downloadObserver===true;
 const sawPostEvent=observerEnabled&&events.some(e=>e?.method==='POST'&&e?.stage==='request'&&['localhost','127.0.0.1'].includes(e?.host));
 add('observer','Opt-in POST lifecycle evidence',sawPostEvent?'pass':seen&&observerEnabled?'warn':'not-tested',
  sawPostEvent?'A POST request stage was captured with observer enabled; no payload values saved.':observerEnabled?'Observer active or formerly enabled, but no matching local POST start event observed.':'Enable Download Observer before selecting Run synthetic export.');
 const fileCount=eligible?requests.filter(r=>{const u=safeURL(r?.url,origin);return u?.pathname==='/v60-file'&&r?.attachmentDisposition===true&&Number(r?.status)===200;}).length:0;
 const dropCount=Object.values(record?.counters||{}).reduce((n,v)=>n+count(v),0)+count(record?.downloadEventsDropped);
 add('retention','No reported record drops',!seen?'not-tested':dropCount?'warn':'pass',dropCount?'Reported record drops can invalidate completeness checks.':'No record drops were reported in this segment; earlier segments may still contain omissions.');
 const summary={pass:checks.filter(c=>c.status==='pass').length,warn:checks.filter(c=>c.status==='warn').length,notTested:checks.filter(c=>c.status==='not-tested').length};
 return {format:'trufflehog-local-capture-benchmark',version:1,verdict:!eligible||!seen?'not-run':summary.warn?'needs-review':summary.notTested?'partial':'observed-tests-pass',summary,
  totals:{fixtureRequests:eligible?requests.filter(r=>{const u=safeURL(r?.url,origin);return !!u&&u.pathname.startsWith('/v60-');}).length:0,
   fixtureAttachmentResponses:fileCount,fixtureScannedBodies:eligible?scans.filter(s=>{const u=safeURL(s?.url,origin);return !!u&&['/v60-lab.js','/v60-lab.css','/v60-lab.json'].includes(u.pathname);}).length:0,
   recordedDrops:dropCount},checks,
  limitations:['No network requests are made by this evaluator. It reads only current recorded browser evidence.',
   'The fixture is restricted to loopback origin on port 8770.',
   'The attachment response is observed independently; it does not prove Chrome associated a DownloadItem with a particular API POST.',
   'Only recorded stages can be checked; a successful local fixture cannot certify third-party DAM capture or prove complete-site visibility.',
   'Evidence Vault persistence and Windows notification display are independently tested under Capture acceptance.']};
}
root.THILabAcceptance={evaluate,labOrigin};
if(typeof module!=='undefined'&&module.exports)module.exports=root.THILabAcceptance;
})(typeof self!=='undefined'?self:globalThis);
