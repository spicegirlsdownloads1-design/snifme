/* v4.4 Discovery Pulse: compare saved, browser-observed evidence only.
 * Nothing is fetched and no secrets, query strings, raw metadata or source bodies are retained.
 */
(function(root){'use strict';
const MAX_SEGMENTS=40,MAX_KEYS=1200;
function host(raw){try{const u=new URL(String(raw||''));if(!/^https?:$/.test(u.protocol)||u.username||u.password)return '';
 const h=u.hostname.toLowerCase();if(h.length>160||h.split('.').some(x=>x.length>50||/^[a-f0-9]{40,}$/.test(x)))return '';return h;
}catch{return '';}}
function originOf(raw){try{const u=new URL(String(raw||''));return /^https?:$/.test(u.protocol)?u.origin:'';}catch{return '';}}
function isGoodStatus(s){return Number.isInteger(s)&&s>=200&&s<400;}
function mediaRole(r){
 const mime=String(r?.mime||'').toLowerCase(),type=String(r?.type||'').toLowerCase();
 let path='';try{path=new URL(String(r?.url||'')).pathname.toLowerCase();}catch{return '';}
 if(type==='image'||mime.startsWith('image/'))return 'Image delivery';
 if(type==='script'||/(?:javascript|ecmascript)/.test(mime)||/\.m?js$/.test(path))return 'Script delivery';
 if(['xhr','xmlhttprequest','fetch'].includes(type)||/(?:json|graphql|\+json)/.test(mime)||/^\/(?:api|graphql|rest)(?:\/|$)/i.test(path))return 'API / data';
 return '';
}
function scanKind(r){
 const k=String(r?.kind||'').toLowerCase();return ['javascript','css','json','xml','html'].includes(k)?k:'';
}
function candidateKind(r){
 const mime=String(r?.mime||'').toLowerCase();let path='';try{path=new URL(String(r?.url||'')).pathname.toLowerCase();}catch{return '';}
 return /(?:javascript|ecmascript)/.test(mime)||/\.m?js$/.test(path)?'javascript':/html/.test(mime)||/\.x?html?$/.test(path)?'html':/css/.test(mime)||/\.css$/.test(path)?'css':/(?:json|\+json)/.test(mime)||/\.json$/.test(path)?'json':/(?:xml|\+xml)/.test(mime)||/\.xml$/.test(path)?'xml':'';
}
function snapshot(input){
 const records=(Array.isArray(input)?input:[input]).filter(x=>x&&typeof x==='object');
 if(!records.length||records.length>MAX_SEGMENTS)throw Error('Choose 1–40 saved capture segments.');
 const origins=new Set(records.map(x=>originOf(x.origin)).filter(Boolean));
 if(origins.size!==1||records.some(x=>!originOf(x.origin)))throw Error('A saved capture group must use one website origin.');
 const services=new Map(),scripts=new Map(),seenEligible=new Set(),scanned=new Set(),types=new Map();
 let totalRequests=0,fullyObserved=0, scanExcluded=0;
 for(const r of records){
  totalRequests+=(r.requests||[]).length;
  for(const req of (r.requests||[]).slice(0,2200)){
   const h=host(req.url),role=mediaRole(req);
   if(h&&role&&isGoodStatus(req.status)&&services.size<MAX_KEYS){const key=role+'|'+h;const a=services.get(key)||{key,host:h,role,sightings:0};a.sightings++;services.set(key,a);}
   const kind=candidateKind(req);
   if(h&&kind&&isGoodStatus(req.status)){
    // URL retained only transiently for matching already-recorded scan entries.
    const key=kind+'|'+String(req.url||'');seenEligible.add(key);
    types.set(kind,types.get(kind)||{kind,seen:0,inspected:0});
   }
  }
  for(const scan of (r.resourceScans||[]).slice(0,1300)){
   const kind=scanKind(scan);
   if(!kind||!host(scan.url))continue;
   scanned.add(kind+'|'+String(scan.url||''));
   if(kind==='javascript'&&/^[a-f0-9]{64}$/i.test(scan.sha256||'')){
    const key=host(scan.url)+'|'+(()=>{try{return new URL(scan.url).pathname;}catch{return ''}})();
    if(key.length<320&&scripts.size<MAX_KEYS){const s=scripts.get(key)||{key,host:host(scan.url),versions:new Set()};s.versions.add(scan.sha256.toLowerCase());scripts.set(key,s);}
   }
  }
  scanExcluded+=Math.max(0,Number(r.autoScanCoverage?.oversized||0))+Math.max(0,Number(r.autoScanCoverage?.timeout||0))+Math.max(0,Number(r.autoScanCoverage?.unavailable||0))+Math.max(0,Number(r.autoScanCoverage?.capacity||0));
  if(r.devtoolsHeartbeatAt)fullyObserved++;
 }
 const counted=new Map();for(const key of seenEligible){const kind=key.slice(0,key.indexOf('|'));const row=counted.get(kind)||{kind,observed:0,scanned:0,notConfirmedScanned:0};row.observed++;if(scanned.has(key))row.scanned++;else row.notConfirmedScanned++;counted.set(kind,row);}
 return {origin:[...origins][0],segments:records.length,requests:totalRequests,devtoolsHeartbeatSegments:fullyObserved,
 services:[...services.values()].sort((a,b)=>a.key.localeCompare(b.key)),
 scripts:[...scripts.values()].map(x=>({...x,versions:[...x.versions].sort()})).sort((a,b)=>a.key.localeCompare(b.key)),
 coverage:[...counted.values()].sort((a,b)=>a.kind.localeCompare(b.kind)),scanExcluded,
 assessment:'Only successful browser-observed resource host roles are inventoried. DevTools-free network metadata does not include response bodies; a resource not confirmed scanned may have been loaded before DevTools, excluded, or unreported. No result certifies site-wide coverage.'};
}
function compare(before,after){
 if(!before||!after||before.origin!==after.origin)throw Error('Choose two different saved capture groups from the same website.');
 const old=new Map((before.services||[]).map(x=>[x.key,x]));
 const recent=new Map((after.services||[]).map(x=>[x.key,x]));
 const rows=[];
 for(const [key,s] of recent){const prior=old.get(key);rows.push({kind:'Host role',identity:s.host,role:s.role,status:prior?'Observed in both':'Newly observed',previous:prior?.sightings||0,current:s.sightings,confidence:'Observed requests; backend ownership not proven'});}
 for(const [key,s] of old)if(!recent.has(key))rows.push({kind:'Host role',identity:s.host,role:s.role,status:'Not observed in latest',previous:s.sightings,current:0,confidence:'Not proof of removal'});
 const olderScripts=new Map((before.scripts||[]).map(x=>[x.key,x]));
 for(const s of after.scripts||[]){const prev=olderScripts.get(s.key);if(!prev)continue;
  if(s.versions.some(v=>!prev.versions.includes(v)))rows.push({kind:'Script digest',identity:s.host,role:'SHA-256 version difference',status:'Changed observed digest',previous:prev.versions.length,current:s.versions.length,confidence:'Exact file digest; no source content retained'});
 }
 const ranks={'Newly observed':0,'Changed observed digest':1,'Not observed in latest':2,'Observed in both':3};
 rows.sort((a,b)=>(ranks[a.status]??9)-(ranks[b.status]??9)||a.identity.localeCompare(b.identity)||a.role.localeCompare(b.role));
 return {origin:after.origin,rows:rows.slice(0,400),truncated:rows.length>400,
 counts:{newHosts:rows.filter(x=>x.status==='Newly observed'&&x.kind==='Host role').length,changedScripts:rows.filter(x=>x.kind==='Script digest').length,notSeen:rows.filter(x=>x.status==='Not observed in latest').length},
 before:{segments:before.segments,requests:before.requests,heartbeat:before.devtoolsHeartbeatSegments},after:{segments:after.segments,requests:after.requests,heartbeat:after.devtoolsHeartbeatSegments},
 coverage:after.coverage,
 assessment:'Newly observed means present in the later recorded session but not the earlier one, not necessarily newly deployed. Different browsing, incomplete inspection, and permissions can produce apparent changes. Static references and masked secrets are not replayed.'};
}
const api={snapshot,compare,mediaRole,candidateKind};root.THIDiscoveryPulse=api;
if(typeof module!=='undefined'&&module.exports)module.exports=api;
})(typeof self!=='undefined'?self:globalThis);
