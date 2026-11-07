/* v6.1 - Explainable, read-only capture repair advisor.
 * No network access, arbitrary source values, tokens, URLs, request identifiers,
 * or personal data are copied into results. All messages are fixed strings.
 */
(function(root){'use strict';
const has=(obj,id,status)=>Array.isArray(obj?.checks) && obj.checks.some(x=>x?.id===id&&x?.status===status);
const defs=Object.freeze({
 local:{title:'Run the isolated local fixture',category:'Setup',priority:1,why:'No qualifying deterministic localhost benchmark was observed.',steps:['Run py tests\\v60_benchmark.py in the unpacked extension folder.','Open http://127.0.0.1:8770/v60-lab.html, grant this origin, and start capture.','Open DevTools before reloading, enable Download Observer, then select Run synthetic export.','Refresh the Local capture benchmark view.']},
 access:{title:'Grant access for the selected origin',category:'Permissions',priority:1,why:'The acceptance report did not confirm permission for this tab.',steps:['Confirm the correct target tab is selected in Chrome.','Start capture and approve the extension host-permission request for the exact site.','Do not use extension settings to grant unrestricted access to unrelated sites.']},
 capture:{title:'Start capture before reloading',category:'Capture',priority:1,why:'A live capture was not confirmed.',steps:['Start capture on the approved tab.','Reload the source tab to generate fresh observed network responses.','Re-run Capture acceptance and Local capture benchmark.']},
 inspector:{title:'Restore the page inspector',category:'Page inspector',priority:1,why:'The page content-inspector round trip did not succeed.',steps:['Confirm the extension is enabled and has permission on this origin.','Click Reload on the extension card in chrome://extensions if it was recently updated.','Reload the target tab, then re-run Capture acceptance.','Restricted chrome:// pages are not suitable for this test.']},
 network:{title:'Confirm Chrome network capture',category:'Network',priority:1,why:'The expected localhost response metadata was not observed.',steps:['Verify the fixture server is running on port 8770.','Make sure the capture was started on the same browser tab before reloading.','Check that the tab still uses the exact granted origin.','Re-run the fixture and inspect the Network view.']},
 devtools:{title:'Restore DevTools response scanning',category:'DevTools',priority:1,why:'Fixture scan evidence was absent or the DevTools scanner was incomplete.',steps:['Open DevTools (F12) on the source tab before reloading; opening DevTools on the dashboard is insufficient.','Keep DevTools open until the page resources finish loading.','Check that automatic file scanning is enabled for the current capture.','Review Resource scans for oversized, unavailable, unsupported, and unrecorded responses.']},
 observer:{title:'Enable Download Observer before export',category:'Download',priority:2,why:'The localhost POST start event was not confirmed by the observer.',steps:['With capture already running, enable Download Observer in the dashboard.','Return to the localhost fixture and select Run synthetic export.','Refresh the Download telemetry and Local capture benchmark views.','Browser download events without reliable tab attribution remain unassociated.']},
 attachment:{title:'Confirm the synthetic attachment response',category:'Download',priority:2,why:'The expected local attachment delivery was not recorded.',steps:['Select Run synthetic export on the localhost fixture.','Verify the fixture server remains running and no browser download rule blocked the response.','Inspect the Network view for the final attachment response.','Do not infer a direct causal link between the POST and DownloadItem event.']},
 retention:{title:'Investigate dropped observation records',category:'Storage',priority:1,why:'Capture reported lost or capped records.',steps:['Check Capture diagnostics for queue and retention limits.','Use shorter separate recording sessions and stop them cleanly.','Check the Evidence Vault for all rolled segments.','Treat a report with dropped events as incomplete.']},
 vault:{title:'Check Evidence Vault persistence',category:'Storage',priority:1,why:'An archived session failed readback.',steps:['Stop capture and open the Evidence Vault view.','Check that saved sessions appear and that the same group can be read back.','Verify there is sufficient browser storage space and inspect extension errors at chrome://extensions.','Export a backup before resetting or clearing anything.']},
 notification:{title:'Visually check Windows notifications',category:'Desktop',priority:3,why:'Notification visibility has not been confirmed by a person.',steps:['Run the extension test-notification action.','Check Windows notification and Do Not Disturb settings if no banner appears.','A Chrome API success is not proof that a Windows toast was displayed.']}
});
function evaluate(input={}){
 const acceptance=input.acceptance&&typeof input.acceptance==='object'?input.acceptance:null;
 const benchmark=input.benchmark&&typeof input.benchmark==='object'?input.benchmark:null;
 const live=input.recording?.enabled===true;
 const selected=[];
 const add=(id,state)=>{if(selected.some(x=>x.id===id))return;selected.push({id,status:state,...defs[id]});};
 const fixture=benchmark?.verdict && benchmark.verdict!=='not-run' && benchmark.verdict!=='unknown';
 if(!fixture)add('local','not-tested');
 if(acceptance){
  if(has(acceptance,'permission','not-tested'))add('access','not-tested');
  if(has(acceptance,'capture','not-tested')&&!live)add('capture','not-tested');
  if(has(acceptance,'content','warn'))add('inspector','needs-review');
  if(!fixture && has(acceptance,'requests','not-tested') && live)add('network','not-tested');
  if(has(acceptance,'response-scanning','warn'))add('devtools','needs-review');
  if(has(acceptance,'retention','warn'))add('retention','needs-review');
  if(has(acceptance,'vault','warn'))add('vault','needs-review');
  if(has(acceptance,'desktop-notification','not-tested'))add('notification','not-tested');
 }
 if(fixture){
  const networkIDs=['document','script','style','json','image','job','status'];
  if(networkIDs.some(id=>has(benchmark,id,'warn')))add('network','needs-review');
  if(has(benchmark,'scan','warn'))add('devtools','needs-review');
  if(has(benchmark,'observer','warn'))add('observer','needs-review');
  if(has(benchmark,'file','warn'))add('attachment','needs-review');
  if(has(benchmark,'retention','warn'))add('retention','needs-review');
 }
 if(!acceptance && !fixture)add('capture','not-tested');
 selected.sort((a,b)=>a.priority-b.priority || Number(b.status==='needs-review')-Number(a.status==='needs-review') || a.id.localeCompare(b.id));
 const summary={needsReview:selected.filter(x=>x.status==='needs-review').length,notTested:selected.filter(x=>x.status==='not-tested').length};
 const advice=selected.map(({id,status,title,category,priority,why,steps})=>({id,status,title,category,priority,why,steps}));
 const result={format:'trufflehog-capture-repair',version:1,
  assessment:summary.needsReview?'review-observed-gaps':fixture&&acceptance&&benchmark.verdict==='observed-tests-pass'&& !has(acceptance,'content','warn') && !has(acceptance,'vault','warn') ? 'observed-stages-pass-with-limits' : 'verification-incomplete',
  summary:{...summary,labExecuted:!!fixture,acceptanceAvailable:!!acceptance},
  actions:advice,
  limitations:['Recommendations are based only on saved local reports, not a live website inspection.',
   'A missing stage may reflect user actions, site permission, caching, DevTools timing, or browser limitations; the cause is not proven.',
   'No repairs, new network requests, credential tests or permission changes are performed.',
   'Successful fixture checks do not certify real-world DAM capture, authorisation, or Windows notifications.']};
 return result;
}
root.THICaptureRepair={evaluate};
if(typeof module!=='undefined'&&module.exports)module.exports=root.THICaptureRepair;
})(typeof self!=='undefined'?self:globalThis);
