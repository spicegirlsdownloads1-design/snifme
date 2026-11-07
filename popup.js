'use strict';
const $ = id => document.getElementById(id);
let targetId = null;
let sitePattern = '';
let siteOrigin = '';
const patternFor = url => {try {const u=new URL(url); return /^https?:$/.test(u.protocol)?u.protocol+'//'+u.hostname+'/*':'';}catch{return '';}};
const send = async (type, extra={}) => chrome.runtime.sendMessage({type, tabId:targetId, ...extra});
async function refresh() {
  try {
    const tabs = await chrome.tabs.query({active:true, currentWindow:true});
    const tab = tabs[0];
    const origin = tab?.url && /^https?:\/\//.test(tab.url) ? new URL(tab.url).origin : '';
    if (!origin) {
      $('origin').textContent = 'Open an ordinary website to capture';
      $('start').disabled = true; $('dashboard').disabled = true; return;
    }
    targetId = tab.id;
    siteOrigin=origin;sitePattern=patternFor(tab.url);
    $('origin').textContent = origin;
    const granted=sitePattern ? await chrome.permissions.contains({origins:[sitePattern]}) : false;
    $('accessStatus').textContent=granted?'Site access granted':'Site access not granted';
    $('accessDot').classList.toggle('on',granted);
    // Required all-site host permissions are controlled in Chrome's extension settings.
    $('revoke').hidden=true;
    $('start').textContent=granted?'Start capture in this tab':'Check Chrome site access';
    const response = await send('GET_STATE');
    if (!response?.ok) throw new Error(response?.error || 'Could not load state');
    const active = response.recording?.enabled && response.recording.origin === origin;
    $('start').hidden = !!active; $('stop').hidden = !active;
    $('statusDot').classList.toggle('on', !!active);
    $('status').textContent = active ? `Automatic recording · ${response.record?.requests?.length || 0} recent requests` : 'Not recording';
    const auto=await send('GET_AUTO_CAPTURE');
    $('autoCapture').checked=auto?.enabled!==false;
    const count=response.record?.unreviewedAlerts||0;
    $('alertStatus').textContent=count?`${count} potentially sensitive finding(s) awaiting review`:'No unreviewed sensitive findings';
    const pref=await send('GET_SECRET_NOTIFICATIONS');
    $('secretAlerts').checked=pref?.enabled!==false;
  } catch(e) {$('note').textContent = e.message;}
}
$('start').addEventListener('click', async () => {
  // All-sites permission is declared in the manifest; Chrome handles grants.
  $('start').disabled=true;
  try {
    const result=await send('START_CAPTURE');
    if (!result?.ok) $('note').textContent=result?.error||'Check Chrome extension site access';
  } catch(e){$('note').textContent=e.message||'Capture failed';}
  finally{$('start').disabled=false;await refresh();}
});
$('revoke').addEventListener('click', async()=>{
  if(!sitePattern || targetId===null)return;
  $('revoke').disabled=true;
  try{
    // Archive and stop before revoking access. No new capture follows.
    await send('STOP_CAPTURE');
    const removed=await chrome.permissions.remove({origins:[sitePattern]});
    $('note').textContent=removed?'Site access revoked. Saved evidence remains local.':'Chrome did not revoke this site permission; check extension site settings.';
    $('diagnosticStatus').textContent='';
  }catch(e){$('note').textContent=e.message||'Could not revoke permission';}
  finally{$('revoke').disabled=false;await refresh();}
});
$('diagnostics').addEventListener('click',async()=>{
  if(targetId===null)return;
  try{
    const result=await send('CHROME_DIAGNOSTICS');
    if(!result?.ok)throw new Error(result?.error||'Diagnostic failed');
    const c=result.checks;
    $('healthStatus').textContent=c.scanHealth ? `Scanner: ${c.scanHealth.title} · ${c.scanHealth.scanned}/${c.scanHealth.eligible} observed eligible files scanned` : 'Scanner status unavailable';
    $('diagnosticStatus').textContent=`Worker responsive · v${c.manifestVersion} · Site ${c.siteAccessGranted?'granted':'not granted'} · ${c.recording?'Recording':'Idle'} · ${c.recordedRequests} requests · ${c.scannedFiles} scanned files${c.devtoolsAutoScanSeen?' · DevTools scan observed':' · DevTools scan not yet observed'}`;
  }catch(e){$('diagnosticStatus').textContent='Diagnostic failed: '+e.message;}
});
$('stop').addEventListener('click', async () => {
  const result=await send('STOP_CAPTURE'); if(!result?.ok||result.archiveWarning)$('note').textContent=result?.archiveWarning||result?.error||'Stop failed'; await refresh();
});
$('dashboard').addEventListener('click', async () => {
  if (targetId === null) return;
  await chrome.tabs.create({url:chrome.runtime.getURL('dashboard.html?tabId=' + targetId)});
  window.close();
});
void refresh();

$('secretAlerts').addEventListener('change',async()=>{
  if(targetId===null)return;
  const response=await send('SET_SECRET_NOTIFICATIONS',{enabled:$('secretAlerts').checked});
  if(!response?.ok)$('note').textContent=response?.error||'Could not change alerts';
});

$('acceptance').addEventListener('click',async()=>{
 if(targetId===null)return;
 await chrome.tabs.create({url:chrome.runtime.getURL('dashboard.html?tabId='+targetId+'&view=acceptance')});
 window.close();
});

$('audit').addEventListener('click',async()=>{
 if(targetId===null)return;
 await chrome.tabs.create({url:chrome.runtime.getURL('dashboard.html?tabId='+targetId+'&view=capture-audit')});
 window.close();
});

$('vault').addEventListener('click', async () => {
  if (targetId===null)return;
  await chrome.tabs.create({url:chrome.runtime.getURL('dashboard.html?tabId='+targetId+'&view=vault')});
  window.close();
});

$('crossArchive').addEventListener('click',async()=>{
 if(targetId===null)return;
 await chrome.tabs.create({url:chrome.runtime.getURL('dashboard.html?tabId='+targetId+'&view=explorer')});
 window.close();
});

// Health tests are explicitly user-initiated; no unannounced synthetic alerts.
let lastHealthReport=null;
$('selfTest').addEventListener('click',async()=>{
  if(targetId===null)return;
  $('selfTest').disabled=true;
  $('selfTestStatus').textContent='Running local extension checks…';
  try{
    const result=await send('FULL_SELF_TEST');
    if(!result?.ok)throw new Error(result?.error||'Self-test unavailable');
    lastHealthReport=result;
    const rows=(result.results||[]).map(x=>`${x.status==='pass'?'PASS':x.status==='fail'?'FAIL':'SKIP'} · ${x.id}: ${x.detail}`);
    $('selfTestStatus').textContent=`v${result.version} · ${result.summary.passed} passed / ${result.summary.failed} failed / ${result.summary.skipped} skipped\n`+rows.join('\n');
    $('copyHealth').hidden=false;
  }catch(e){$('selfTestStatus').textContent='Self-test failed: '+(e.message||String(e));}
  finally{$('selfTest').disabled=false;}
});
$('copyHealth').addEventListener('click',async()=>{
  if(!lastHealthReport)return;
  try{await navigator.clipboard.writeText(JSON.stringify(lastHealthReport,null,2));$('note').textContent='Diagnostic report copied (no URLs, keys or page contents).';}
  catch(e){$('note').textContent='Copy unavailable; select and copy the results manually.';}
});
$('testNotice').addEventListener('click',async()=>{
  if(targetId===null)return;
  const result=await send('TEST_NOTIFICATION');
  $('note').textContent=result?.ok?result.message:'Test notification failed: '+(result?.error||'Unknown error');
});

$('recover').addEventListener('click',async()=>{
  if(targetId===null)return;
  $('recover').disabled=true;
  try{
    const result=await send('RECOVER_CAPTURE');
    $('healthStatus').textContent=result?.message||result?.error||'Recovery status unavailable';
  }catch(e){$('healthStatus').textContent='Capture recheck failed: '+(e.message||e);}
  finally{$('recover').disabled=false;await refresh();}
});

$('offlineInspector').addEventListener('click',async()=>{await chrome.tabs.create({url:chrome.runtime.getURL('offline.html')});window.close();});

$('downloadObserver').addEventListener('click',async()=>{if(targetId!==null){await chrome.tabs.create({url:chrome.runtime.getURL('dashboard.html?tabId='+targetId+'&view=download-traces')});window.close();}});

$('autoCapture').addEventListener('change',async()=>{
  const enabled=$('autoCapture').checked;
  $('autoCapture').disabled=true;
  try{
    const r=await chrome.runtime.sendMessage({type:'SET_AUTO_CAPTURE',enabled});
    if(!r?.ok)throw new Error(r?.error||'Could not change capture mode');
    $('note').textContent=enabled?'Automatic capture enabled for permitted websites.':'Automatic capture paused; current captures archived.';
  }catch(e){$('note').textContent=e.message;$('autoCapture').checked=!enabled;}
  finally{$('autoCapture').disabled=false;await refresh();}
});
