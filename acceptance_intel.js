/* v5.0 capture-to-report acceptance: aggregate evidence only; NEVER raw URLs, bodies or credentials. */
(function(root){'use strict';
const LIMITS={maxRequests:1000000,maxCount:1000000};
const count=x=>Number.isSafeInteger(x)&&x>=0?Math.min(x,LIMITS.maxCount):0;
const hasArr=x=>Array.isArray(x)&&x.length>0;
function evaluate(args={}){
 const {record=null,recording=null,permission=false,inspector=null,archive=null,health=null,notificationConfirmation=false}=args;
 const checks=[];
 const add=(id,title,status,detail,actual)=>checks.push({id,title,status,detail,actual:typeof actual==='number'?count(actual):undefined});
 const present=!!record&&typeof record==='object';
 add('worker','Background responding','pass','The extension service worker answered this diagnostic request.');
 add('permission','Site permission',permission?'pass':'not-tested',permission?'Chrome reports access to this site.':'No current site grant. Start capture and approve access to test.',undefined);
 add('capture','Capture session',recording?.enabled?'pass':present?'not-tested':'not-tested',recording?.enabled?'An active capture is registered for this tab.':present?'A local record exists; capture is not currently running.':'Start a capture to create a session.');
 if(inspector===true)add('content','Page inspector','pass','Content inspector replied from the selected page.');
 else if(inspector===false)add('content','Page inspector','warn','No valid content-inspector response; verify permission and injection.');
 else add('content','Page inspector','not-tested','Requires a live capture and an approved HTTP(S) page.');
 const requests=count(record?.requests?.length);
 add('requests','Network capture',requests?'pass':'not-tested',requests?'Browser request metadata recorded.':'No request metadata has been recorded; reload the test page while capturing.',requests);
 const scans=count(record?.autoScanCoverage?.scanned);
 const eligible=count(record?.autoScanCoverage?.eligible);
 const healthCode=String(health?.code||'not-observed');
 const scanning=healthCode==='observed-complete'?'pass':healthCode==='in-progress'?'not-tested':
    healthCode==='partial'||healthCode==='stale'?'warn':scans?'warn':'not-tested';
 add('response-scanning','DevTools resource inspection',scanning,
    healthCode==='observed-complete'?'All eligible responses OBSERVED by DevTools were inspected; full-page completeness remains unknown.':
    healthCode==='partial'?'Some eligible observed responses were missed or excluded.':
    healthCode==='stale'?'DevTools heartbeat is stale or missing during an active capture.':
    healthCode==='in-progress'?'Resource inspection is still running.':
    `Status: ${healthCode}. Open DevTools on the source tab before reloading.`,scans);
 const losses=Object.values(record?.counters||{}).reduce((sum,value)=>sum+count(value),0);
 add('retention','Record retention',!present?'not-tested':losses?'warn':'pass',
   !present?'No capture record yet.':losses?'Dropped or capped records reported; review capture segments.':'No dropped records reported within this record (not a guarantee of complete capture).',losses);
 if(archive===true)add('vault','Evidence Vault readback','pass','Saved session was read back by its identifier from IndexedDB.');
 else if(archive===false)add('vault','Evidence Vault readback','warn','A record exists but no matching saved session was read back. Stop capture and inspect the vault.');
 else add('vault','Evidence Vault readback','not-tested','Stop and archive the capture to verify persistence.');
 const findings=count(record?.findings?.length);
 add('masked-findings','Masked findings review','pass',`Local record contains ${findings} masked finding(s). Zero findings does not establish that no secrets exist.`,findings);
 add('desktop-notification','Windows notification visibility',notificationConfirmation?'pass':'not-tested',
    notificationConfirmation?'User confirmed a test notification was visible.':'Chrome API availability cannot prove Windows displayed a banner. Use Send test notification and verify visually.');
 const summary={pass:checks.filter(x=>x.status==='pass').length,warn:checks.filter(x=>x.status==='warn').length,notTested:checks.filter(x=>x.status==='not-tested').length};
 const verdict=summary.warn?'needs-review':summary.notTested?'incomplete':'observed-tests-pass';
 return {format:'trufflehog-capture-acceptance',version:1,verdict,summary,
  totals:{requests,eligibleResponses:eligible,scannedResponses:scans,maskedFindings:findings,reportedRecordDrops:losses},
  checks,limitations:['Only resources observed by Chrome are assessed; earlier or cross-origin responses may be absent.',
    'An extension self-test does not prove a site is secure or that every script was scanned.',
    'Notification visibility requires visual verification in Windows; this report does not exercise that UI.',
    'This diagnostic makes no network requests, does not inspect credential values, and does not modify saved findings.']};
}
root.THIAcceptance={evaluate};
if(typeof module!=='undefined'&&module.exports)module.exports=root.THIAcceptance;
})(typeof self!=='undefined'?self:globalThis);
