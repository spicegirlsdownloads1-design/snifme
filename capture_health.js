/* v3.8 — bounded, evidence-based inspection diagnostics. No raw URLs or secrets. */
(function(root){'use strict';
const LIMITS={staleMs:35000,clockSkewMs:5000};
function count(value){return Number.isSafeInteger(value)&&value>=0?value:0;}
function assess(record,recording,now=Date.now()){
  const stats=record?.autoScanCoverage||null;
  const isActive=!!recording?.enabled;
  const hb=Date.parse(record?.devtoolsHeartbeatAt||'');
  const last=Number.isFinite(hb)?hb:0;
  const hasHeartbeat=last>0;
  const ageMs=hasHeartbeat?Math.max(0,now-last):null;
  const fresh=hasHeartbeat && ageMs<=LIMITS.staleMs;
  const s=stats||{};
  const eligible=count(s.eligible),scanned=count(s.scanned),queued=count(s.queued),running=count(s.running);
  const missed= ['oversized','unavailable','timeout','unsupported','unrecorded','permissionBlocked','deliveryError','failed','capacity']
    .reduce((sum,k)=>sum+count(s[k]),0);
  const explained=scanned+missed+queued+running;
  const unaccounted=Math.max(0,eligible-explained);
  let code,title,detail;
  if(!stats&&!hasHeartbeat){
    code='not-observed'; title='Not observed'; detail='No DevTools scanner heartbeat or coverage report was recorded for this capture.';
  } else if(isActive && (!fresh)){
    code='stale';title='DevTools connection unconfirmed';detail='Last scanner heartbeat is missing or stale. Inspect DevTools and reload the page.';
  } else if(!stats||(!eligible&&!missed)){
    code='waiting';title='Connected; no eligible files recorded';detail='DevTools reports activity, but no qualifying file responses were counted.';
  } else if(queued+running>0){
    code='in-progress';title='File inspection in progress';detail='A queue is still running; coverage totals are not final.';
  } else if(missed||unaccounted){
    code='partial';title='Partial observed-file coverage';detail='Some eligible responses were excluded, failed, or could not be accounted for.';
  } else {
    code='observed-complete';title='Observed-file scans complete';detail='Every eligible file seen by this inspector was scanned. Earlier/unobserved page resources remain unknown.';
  }
  return {code,title,detail,active:isActive,heartbeatAt:hasHeartbeat?record.devtoolsHeartbeatAt:null,
    heartbeatAgeSeconds:ageMs===null?null:Math.round(ageMs/1000),fresh,
    eligible,scanned,excluded:missed,queued,running,unaccounted,
    cannotAssessEarlierResources:true,liveDevToolsObserved:!!fresh};
}
root.THIHealth={assess,LIMITS};
if(typeof module!=='undefined'&&module.exports)module.exports=root.THIHealth;
})(typeof self!=='undefined'?self:globalThis);
