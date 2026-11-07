/* MV3 service worker. Auto capture for browser-accessible HTTP(S) pages; pauseable, per-tab/origin-scoped. */
/* global THI */
importScripts('capture_journal.js','security_intelligence.js','product_asset_intel.js','asset_licensing_intel.js','dam_telemetry.js','aws_dam_intel.js','upload_api_intel.js','download_observer.js','workflow_intel.js','acceptance_intel.js','capture_health.js','self_test.js','metadata_intel.js','visual_intel.js','scanner.js','script_changes.js','secret_alerts.js','exposure_history.js','search_intel.js','app_intel.js','dam_intel.js','dam_security.js','lineage_intel.js','viewer_intel.js','gallery_intel.js','evidence_vault.js','vault_professional.js','cross_archive.js','discovery_pulse.js','frame_worker_intel.js','frame_scope.js','site_relationships.js');
'use strict';

const MAX = {securityObservations:350,pimObservations:140,pimMediaObservations:300,licensingObservations:150,downloadEvents:450,frameCoverage:140,workerScripts:80,embeddedContexts:150,interactions:160, resourceScans:280, galleryEvents:400,galleryAssets:1200,viewerResources:350,viewerManifests:100,viewerHints:120,assetLinks: 450, technologyHints: 160, maps: 120, operations: 160, configs: 160, verifications: 260, requests: 750, assets: 800, routes: 350, scripts: 180, findings: 200, clues: 150, responses: 120, pagination: 220};
// Navigation handlers are registered synchronously, before page requests complete.
// This map also lets onCompleted wait for the corresponding initial capture setup.
const autoStarts = new Map();
// A browser request may finish after the tab navigates to another site. Preserve
// a bounded, ephemeral request-start generation; completion time is not proof
// of the originating page. Unlinked cross-origin responses are conservatively
// excluded unless their document/initiator establishes the active page.
const tabNavigationEpoch = new Map();
const pendingHttpStarts = new Map();
function markHttpStart(d){
 if(!Number.isInteger(d?.tabId)||d.tabId<0)return;
 if(d.type==='main_frame')tabNavigationEpoch.set(d.tabId,(tabNavigationEpoch.get(d.tabId)||0)+1);
 if(typeof d.requestId!=='string'&&typeof d.requestId!=='number')return;
 if(pendingHttpStarts.size>=12000){
  const oldest=pendingHttpStarts.keys().next().value;
  pendingHttpStarts.delete(oldest);
 }
 pendingHttpStarts.set(String(d.requestId),{tabId:d.tabId,epoch:tabNavigationEpoch.get(d.tabId)||0,at:d.timeStamp||Date.now()});
}
function requestBelongsToCapture(d,state){
 if(!state?.enabled)return false;
 if(d.type==='main_frame')return originOf(d.url)===state.origin;
 const started=pendingHttpStarts.get(String(d.requestId));
 if(started)return started.tabId===d.tabId&&started.epoch===(tabNavigationEpoch.get(d.tabId)||0);
 const pageOrigin=originOf(d.documentUrl||d.initiator||'');
 if(pageOrigin)return pageOrigin===state.origin;
 // Same-origin requests may be attributed without a document URL. An
 // unlinked CDN request is excluded rather than assigned to the wrong site.
 return originOf(d.url)===state.origin;
}
function retireHttpStart(d){if(d?.requestId!==undefined)pendingHttpStarts.delete(String(d.requestId));}

async function autoCaptureEnabled(){
  const pref=await chrome.storage.local.get('autoCaptureEnabled');
  return pref.autoCaptureEnabled!==false;
}
const allActiveOptions=()=>({responseShapes:true,verifyImages:true,viewerManifests:true,
  autoSecretScan:true,verifyMetadata:true,verifyVisual:true,downloadObserver:true});
const workQueues = new Map();
// Journal snapshots are the authoritative live state when IndexedDB is available.
// A worker restart empties this cache; the next read replays durable deltas.
const liveCache = new Map();
const liveStorageErrors = new Map();
// These are bounded per-worker counters, not a claim about every browser event.
// We do not retain the unmatched URL, request ID, origin or headers.
const unassignedSinceWorker = new Map();
function noteUnassignedRequest(details){
  const tabId=details?.tabId;
  if(!Number.isSafeInteger(tabId)||tabId<0)return;
  const current=unassignedSinceWorker.get(tabId)||{total:0,priorNavigation:0,insufficientProvenance:0,originMismatch:0};
  const started=pendingHttpStarts.get(String(details.requestId));
  const reason=started&&started.epoch!==(tabNavigationEpoch.get(tabId)||0)?'priorNavigation':
    !started&&!originOf(details.documentUrl||details.initiator||'')?'insufficientProvenance':'originMismatch';
  current.total=Math.min(1000000,current.total+1);
  current[reason]=Math.min(1000000,current[reason]+1);
  unassignedSinceWorker.set(tabId,current);
}
const cloneRecord = record => JSON.parse(JSON.stringify(record));
const journalSupported = () => THICaptureJournal.supported();
function noteStorageFailure(tabId,error){
  liveStorageErrors.set(tabId,{failed:true,message:String(error?.message||error).slice(0,180),at:new Date().toISOString()});
}

const recordKey = tabId => `record:${tabId}`;
const stateKey = tabId => `active:${tabId}`;
const emptyRecord = (tabId, origin) => ({schema: 21, securityObservations:[],securityObservationsDropped:0,pimObservations:[],pimMediaObservations:[],pimObservationsDropped:0,pimMediaDropped:0,licensingObservations:[],licensingObservationsDropped:0,downloadObserverEverEnabled:false, downloadEvents:[], downloadEventsDropped:0, autoScanCoverage:null, devtoolsHeartbeatAt:null, sessionId:THIVault.newId(), tabId, origin, segmentIndex:1, captureGroupId:null, createdAt: new Date().toISOString(), unreviewedAlerts:0,
  frameCoverage:[],workerScripts:[],embeddedContexts:[],interactions:[],resourceScans:[], galleryEvents:[],galleryAssets:[],viewerResources:[],viewerManifests:[],viewerHints:[],requests: [], assets: [], assetLinks: [], routes: [], scripts: [], findings: [], clues: [], maps: [], operations: [], configs: [], responses: [], pagination: [], verifications: [], technologyHints: [], scannedScripts: [], counters: {requestsDropped: 0, assetsDropped: 0, responsesDropped: 0, paginationDropped: 0, verificationsDropped: 0, viewerResourcesDropped:0,contextsDropped:0,galleryEventsDropped:0,galleryAssetsDropped:0}});
const originOf = url => {try { const u = new URL(url); return /^https?:$/.test(u.protocol) ? u.origin : ''; } catch {return '';} };
// Chrome host grants are origin-scoped. The wildcard permits a specific origin to
// be requested at runtime; it is not itself a blanket site grant.
const hostPattern = origin => {
  try {
    const parsed = new URL(origin);
    if(!/^https?:$/.test(parsed.protocol))return '';
    return `${parsed.protocol}//${parsed.hostname}/*`;
  }catch{return '';}
};
async function hasHostAccess(origin){
  const pattern=hostPattern(origin);
  if(!pattern)return false;
  // The guard also permits isolated legacy tests with older Chrome mocks.
  return !chrome.permissions?.contains || await chrome.permissions.contains({origins:[pattern]});
}


function queue(tabId, action) {
  const prior = workQueues.get(tabId) || Promise.resolve();
  const next = prior.catch(() => {}).then(action);
  workQueues.set(tabId, next);
  next.finally(() => { if (workQueues.get(tabId) === next) workQueues.delete(tabId); }).catch(() => {});
  return next;
}
async function readRecord(tabId) {
  let rec=liveCache.get(tabId)||null;
  if(!rec&&journalSupported()){
    // If an IndexedDB read fails, do not silently return an outdated local mirror.
    try{rec=await THICaptureJournal.read(tabId);}
    catch(e){noteStorageFailure(tabId,e);throw e;}
    if(rec)liveCache.set(tabId,rec);
  }
  if(!rec){
    const key=recordKey(tabId);
    const data=await chrome.storage.local.get(key);
    rec=data[key]||null;
  }
  if(!rec)return null;
  // Do not give callers mutable references to the committed in-memory cache.
  rec=cloneRecord(rec);
  for (const key of ['securityObservations','pimObservations','pimMediaObservations','licensingObservations','downloadEvents','frameCoverage','workerScripts','embeddedContexts','interactions','resourceScans','galleryEvents','galleryAssets','viewerResources','viewerManifests','viewerHints','requests','assets','assetLinks','routes','scripts','findings','clues','maps','operations','configs','responses','pagination','verifications','technologyHints','scannedScripts']) {
    if (!Array.isArray(rec[key])) rec[key]=[];
  }
  rec.autoScanCoverage ||= null;
  rec.downloadEventsDropped ||= 0;
  rec.securityObservationsDropped ||= 0;
  rec.licensingObservationsDropped ||= 0;
  rec.pimObservationsDropped ||= 0;rec.pimMediaDropped ||= 0;
  if(typeof rec.devtoolsHeartbeatAt!=='string')rec.devtoolsHeartbeatAt=null;
  for(const finding of rec.findings)finding.reviewStatus ||= 'new';
  rec.unreviewedAlerts=Number.isInteger(rec.unreviewedAlerts)?Math.max(0,rec.unreviewedAlerts):0;
  rec.counters ||= {};
  for(const key of ['requestsDropped','assetsDropped','responsesDropped','paginationDropped','verificationsDropped','viewerResourcesDropped','contextsDropped','galleryEventsDropped','galleryAssetsDropped'])rec.counters[key] ||= 0;
  return rec;
}
async function updateRecord(tabId, edit) {
  return queue(tabId,async()=>{
    const previous=await readRecord(tabId);
    if(!previous)return null;
    const record=cloneRecord(previous);
    await edit(record);
    // Immutable archive segments are a backstop against ring-buffer overwrites.
    const thresholds={requests:700,assets:745,galleryAssets:1090,galleryEvents:360,
      verifications:225,responses:105,resourceScans:245,viewerResources:315,
      pagination:195,assetLinks:405,embeddedContexts:125,findings:175,downloadEvents:410,licensingObservations:130,pimObservations:125,pimMediaObservations:270,securityObservations:320};
    const full=Object.entries(thresholds).some(([name,limit])=>record[name]?.length>=limit);
    let current=record;
    if(full&&typeof indexedDB!=='undefined'){
      if(!record.sessionId)record.sessionId=THIVault.newId();
      record.endedAt=new Date().toISOString();
      record.rolloverReason='automatic segment boundary';
      await THIVault.save(record); // Archive before creating a new live segment.
      current=emptyRecord(tabId,record.origin);
      current.captureGroupId=record.captureGroupId||record.sessionId;
      current.segmentIndex=(Number(record.segmentIndex)||1)+1;
      current.captureStartedAt=record.captureStartedAt||record.createdAt;
      current.unreviewedAlerts=record.unreviewedAlerts||0;
      current.downloadObserverEverEnabled=record.downloadObserverEverEnabled===true;
      current.findings=(record.findings||[]).slice(-25).map(f=>({...f,carriedFromSegment:record.sessionId}));
      current.createdAt=new Date().toISOString();
      current.previousSegmentId=record.sessionId;
    }
    if(journalSupported()){
      try{
        // Upgrade old chrome.storage.local records exactly once on first write.
        await THICaptureJournal.ensure(tabId,previous);
        if(full)await THICaptureJournal.replace(tabId,current);
        else{
          const result=await THICaptureJournal.append(tabId,previous,current);
          if(!result.changed)return previous; // No-op: do not write to either store.
        }
        liveCache.set(tabId,cloneRecord(current));
        liveStorageErrors.delete(tabId);
        // Avoid rewriting potentially large live records for every HTTP event.
        // The journal transaction was committed before returning. The local
        // mirror is a legacy compatibility/recovery checkpoint, NOT the truth.
        if(full || (current.journalSequence||0)%48===0){
          try{await chrome.storage.local.set({[recordKey(tabId)]:current});}
          catch(error){noteStorageFailure(tabId,error);console.warn('[Trufflehog] legacy mirror unavailable',error.message);}
        }
      }catch(error){noteStorageFailure(tabId,error);throw error;}
    }else{
      await chrome.storage.local.set({[recordKey(tabId)]:current});
    }
    return current;
  });
}
// Save completed snapshots in IndexedDB. Older v2.8 tab records remain readable
// and are archived on the next capture or on opening the Evidence Vault.
async function archiveRecord(tabId, ended = false) {
  // Existing isolated worker tests lack IndexedDB; production Chrome always provides it.
  if(typeof indexedDB==='undefined')return null;
  return queue(tabId, async () => {
    const rec=await readRecord(tabId);
    if (!rec)return null;
    if (!rec.sessionId)rec.sessionId=THIVault.newId();
    if (ended && !rec.endedAt)rec.endedAt=new Date().toISOString();
    await THIVault.save(rec);
    if(journalSupported()){
      try{await THICaptureJournal.replace(tabId,rec);liveCache.set(tabId,cloneRecord(rec));}
      catch(e){noteStorageFailure(tabId,e);throw e;}
    }
    await chrome.storage.local.set({[recordKey(tabId)]:rec});
    return THIVault.summary(rec);
  });
}
async function archiveLegacyRecords(){
  const values=await chrome.storage.local.get(null);
  for(const [key,rec] of Object.entries(values)){
    if(!/^record:\d+$/.test(key)||!rec||!rec.origin)continue;
    const id=Number(key.split(':')[1]);
    if(!Number.isSafeInteger(id))continue;
    // An active capture is still usable. Store a checkpoint without changing its state.
    const existing=await THIVault.get(rec.sessionId||'');
    if(!existing || !(await active(id))?.enabled)await archiveRecord(id,!(await active(id))?.enabled);
  }
}
async function active(tabId) {
  const key = stateKey(tabId);
  return (await chrome.storage.session.get(key))[key] || null;
}
function addUnique(items, item, key, limit) {
  if (!item || !key) return false;
  if (items.some(x => x._key === key)) return false;
  if (items.length >= limit) return false;
  items.push({...item, _key: key});
  return true;
}
async function updateBadge(tabId, record, isActive) {
  try {
    const count=record?.unreviewedAlerts||0;
    await chrome.action.setBadgeText({tabId, text: count ? (count>99?'99+':String(count)) : isActive ? (record?.requests?.length ? String(Math.min(999, record.requests.length)) : 'ON') : ''});
    await chrome.action.setBadgeBackgroundColor({tabId, color: count?'#dc3545':'#16a58a'});
  } catch { /* tab may have closed */ }
}
// Desktop notifications are advisory: detection alone cannot establish validity or exposure.
async function showSecretAlert(tabId, record, changedOnly=false) {
  if(!record?.unreviewedAlerts)return;
  await updateBadge(tabId,record,true);
  if(!chrome.notifications?.create)return;
  const prefs=await chrome.storage.local.get('secretDesktopAlerts');
  const changes=changedOnly?await chrome.storage.local.get('secretChangeDesktopAlerts'):{};
  if(prefs.secretDesktopAlerts===false||(changedOnly&&changes.secretChangeDesktopAlerts===false))return;
  const key=`last-secret-notice:${tabId}`;
  const last=(await chrome.storage.session.get(key))[key]||0;
  if(Date.now()-last<60000)return; // one desktop notification per tab/minute
  await chrome.storage.session.set({[key]:Date.now()});
  const domain=(()=>{try{return new URL(record.origin).hostname.slice(0,72);}catch{return 'a captured website';}})();
  try{
    await chrome.notifications.create(`trufflehog-secret-${tabId}-${Date.now()}`,{
      type:'basic',iconUrl:'icon128.png',title:'Potentially sensitive secret detected',
      message:`${record.unreviewedAlerts} new or changed indicator(s) on ${domain}. Values are masked. Review findings.`,
      priority:2,buttons:[{title:'Review masked findings'}]
    });
  }catch(e){console.warn('[Trufflehog] notification unavailable:',e.message);}
}
async function openSecretFindings(id){
  const found=String(id).match(/^trufflehog-secret-(\d+)-\d+$/);
  if(!found)return;
  const tabId=Number(found[1]);
  if(!Number.isSafeInteger(tabId))return;
  await chrome.tabs.create({url:chrome.runtime.getURL(`dashboard.html?tabId=${tabId}&view=secrets`)});
}
async function openDiscoveryPulse(id){
 const match=String(id).match(/^trufflehog-discovery-(\d+)-\d+$/);if(!match)return;
 await chrome.tabs.create({url:chrome.runtime.getURL(`dashboard.html?tabId=${Number(match[1])}&view=discovery-pulse`)});
}
if(chrome.notifications?.onClicked)chrome.notifications.onClicked.addListener(id=>{void openSecretFindings(id).catch(()=>{});void openDiscoveryPulse(id).catch(()=>{});});
if(chrome.notifications?.onButtonClicked)chrome.notifications.onButtonClicked.addListener((id,index)=>{if(index===0){void openSecretFindings(id).catch(()=>{});void openDiscoveryPulse(id).catch(()=>{});}});

function routeCandidate(url, resourceType) {
  try {
    const path = new URL(url).pathname;
    return /(?:\/api(?:\/|$)|\/graphql(?:\/|$)|\/rest(?:\/|$)|\/v[1-9]\/)/i.test(path) || resourceType === 'xmlhttprequest';
  } catch {return false;}
}
function classifyHost(host) {
  if (/cloudfront\.net$/i.test(host)) return 'AWS CloudFront';
  if (/\.amazonaws\.com$/i.test(host)) return 'AWS service';
  if (/\.cloudflare(?:\.com|\.net)$/i.test(host)) return 'Cloudflare';
  if (/\.imgix\.net$/i.test(host)) return 'Imgix';
  if (/\.cloudinary\.com$/i.test(host)) return 'Cloudinary';
  if (/\.akamai(?:hd)?\.net$/i.test(host)) return 'Akamai';
  return 'Observed host';
}

async function recordNetwork(details, errorMessage = '') {
  if (details.tabId < 0 || !/^https?:\/\//i.test(details.url)) return;
  // Capture setup triggered by the first main-frame request must settle first.
  if(autoStarts.has(details.tabId))await autoStarts.get(details.tabId).catch(()=>{});
  const recording = await active(details.tabId);
  if (!recording || !recording.enabled) return;
  if (!requestBelongsToCapture(details,recording)){noteUnassignedRequest(details);return;}
  const info = THI.urlInfo(details.url);
  if (!info) return;
  const headers = {};
  for (const h of details.responseHeaders || []) {
    const k = (h.name || '').toLowerCase();
    if (['content-type', 'content-length', 'etag', 'last-modified', 'cache-control', 'access-control-allow-origin', 'content-disposition'].includes(k) && typeof h.value === 'string') headers[k] = h.value.slice(0, 160);
  }
  const search=THISearch.classify(details.url,details.method||'GET');
  const operationName=THIApp.graphqlRequestName(details.url);
  const viewer=THIViewer.classifyUrl(details.url);
  const entry = {
    searchProvider:search?.provider||'',searchEvidence:search?.evidence||'', operationName, url: info.url, host: info.host, queryKeys: info.queryKeys, signedQuery: info.signedQuery, authQueryClasses: info.authQueryClasses,
    signatureKeyPresent: info.signatureKeyPresent===true, signedValidityWindow: info.signedValidityWindow||'unknown',
    method: details.method || 'GET', type: details.type || 'other', status: details.statusCode ?? null,
    mime: (headers['content-type'] || '').split(';')[0], bytes: Number(headers['content-length']) || null,
    etag: headers.etag || '', modified: headers['last-modified'] || '',
    // Only store bounded cache semantics, never arbitrary header values.
    cacheScope: /(?:^|,)\s*public\b/i.test(headers['cache-control']||'')?'public':/(?:^|,)\s*private\b/i.test(headers['cache-control']||'')?'private':'unspecified',
    cacheMaxAge: Math.min(31536000,Math.max(0,Number((headers['cache-control']||'').match(/(?:^|,)\s*(?:s-maxage|max-age)\s*=\s*(\d+)/i)?.[1]||0)))||0,
    cacheNoStore: /(?:^|,)\s*no-store\b/i.test(headers['cache-control']||''),
    corsWildcard: (headers['access-control-allow-origin']||'').trim()==='*',
    // Record header presence only; never retain Content-Disposition filenames.
    attachmentDisposition: /^\s*attachment(?:\s*;|\s*$)/i.test(headers['content-disposition']||''),
    initiatorOrigin: originOf(details.initiator || ''),
    document: THI.sanitizedUrl(details.documentUrl || ''),
    frameId: Number.isInteger(details.frameId) ? details.frameId : null,
    error: errorMessage.slice(0, 120), at: new Date(details.timeStamp || Date.now()).toISOString()
  };
  // Reject requests completed after capture was stopped/restarted, even if a queue is busy.
  await updateRecord(details.tabId, rec => {
    if (rec.origin !== recording.origin || (rec.captureStartedAt||rec.createdAt)>entry.at || !requestBelongsToCapture(details,recording)) return;
    // Keep a rolling log so late requests remain visible during a long session.
    if (rec.requests.length >= MAX.requests) {
      rec.requests.shift(); rec.counters.requestsDropped++;
    }
    const prior=(rec.interactions||[]).at(-1);
    if(prior && Math.abs(Date.parse(entry.at)-Date.parse(prior.at))<4000)entry.nearInteraction=prior.kind;
    rec.requests.push(entry);
    if(viewer){
      // Viewer classification is derived exclusively from this already-observed
      // request. The family key is sanitized BEFORE local persistence.
      const fam=THI.sanitizedUrl(viewer.family);
      if(fam){
        const item={url:info.url,family:fam,format:viewer.format,kind:viewer.kind,
          level:viewer.level,status:entry.status,host:info.host,evidence:'observed request'};
        if(rec.viewerResources.length>=MAX.viewerResources)rec.counters.viewerResourcesDropped++;
        addUnique(rec.viewerResources,item,`${item.url}|${item.status}`,MAX.viewerResources);
      }
    }
    if (details.type === 'image' || info.image || entry.mime.startsWith('image/')) {
      const item = {url: info.url, host: info.host, source: 'network', width: null, height: null,
        mime: entry.mime, bytes: entry.bytes, etag: entry.etag, modified: entry.modified,
        signedQuery: info.signedQuery, queryKeys: info.queryKeys};
      if (rec.assets.length >= MAX.assets) rec.counters.assetsDropped++;
      addUnique(rec.assets, item, `network|${info.url}`, MAX.assets);
    }
    if (routeCandidate(info.url, details.type)) {
      addUnique(rec.routes, {url: info.url, host: info.host, kind: 'observed-request',
        method: entry.method, status: entry.status, observed: true, source: 'network'},
      `observed|${entry.method}|${info.url}`, MAX.routes);
      if (operationName) addUnique(rec.operations,{name:operationName,operationType:'unknown',source:info.url,confidence:'observed-URL-operationName'},`url|${operationName}|${info.url}`,MAX.operations);
    }
  }).then(rec => updateBadge(details.tabId, rec, true)).catch(e => console.warn('[Trufflehog] record error:', e.message));
}

// v7.18: generic passive security-condition observations. Only fixed rule metadata,
// safe path classes and classification names are persisted. No raw header,
// request-body, query value, cookie, token, signed URL or exploit proof is saved.
async function recordSecurityStage(stage,details){
 if(!details||!Number.isInteger(details.tabId)||details.tabId<0)return;
 if(autoStarts.has(details.tabId))await autoStarts.get(details.tabId).catch(()=>{});
 const state=await active(details.tabId);
 if(!state?.enabled||!requestBelongsToCapture(details,state))return;
 if(!(await hasHostAccess(state.origin)))return;
 const observations=THISecurityIntelligence.classify(stage,details);
 if(!observations.length)return;
 await updateRecord(details.tabId,rec=>{
  if(rec.origin!==state.origin||(rec.captureStartedAt||rec.createdAt)>state.startedAt||!requestBelongsToCapture(details,state))return;
  for(const fact of observations){
   // Keep one sample per finding/endpoint/host and track recurrence; don't
   // retain values or create a storage write for each uninteresting request.
   const existing=rec.securityObservations.find(o=>o.ruleId===fact.ruleId&&o.host===fact.host&&o.route===fact.route&&o.classification===fact.classification&&o.scope===fact.scope&&o.declaration===fact.declaration&&o.severity===fact.severity&&JSON.stringify(o.markers)===JSON.stringify(fact.markers));
   if(existing){existing.occurrences=Math.min(1000000,(existing.occurrences||1)+1);existing.lastSeenAt=fact.at;continue;}
   if(rec.securityObservations.length>=MAX.securityObservations){rec.securityObservations.shift();rec.securityObservationsDropped++;}
   rec.securityObservations.push({...fact,occurrences:1,lastSeenAt:fact.at});
  }
 });
}
// All listeners below are passive and conditional on a distinct opt-in toggle.
// We classify only field NAMES and HEADER NAMES. Raw requestBody/header values
// are never copied to storage or messages, nor are signed URLs preserved here.
async function recordDownloadStep(stage,details){
  if(!details||!Number.isInteger(details.tabId)||details.tabId<0)return;
  if(autoStarts.has(details.tabId))await autoStarts.get(details.tabId).catch(()=>{});
  const state=await active(details.tabId);
  if(!state?.enabled||state.downloadObserver!==true)return;
  if(!requestBelongsToCapture(details,state))return;
  if(!(await hasHostAccess(state.origin)))return;
  const fact=THIDownload.classify(stage,details,`${details.tabId}:${state.startedAt}`);
  if(!fact)return;
  await updateRecord(details.tabId,r=>{
    if(r.origin!==state.origin||(r.captureStartedAt||r.createdAt)>state.startedAt||!requestBelongsToCapture(details,state))return;
    if(r.downloadEvents.length>=MAX.downloadEvents){r.downloadEvents.shift();r.downloadEventsDropped++;}
    r.downloadEvents.push(fact);
  });
}
// Chrome exposes only part of the HTTP lifecycle; absent data means NOT OBSERVED.
if(chrome.webRequest.onBeforeRequest?.addListener)chrome.webRequest.onBeforeRequest.addListener(
  d=>{
    // Main-frame navigation is the earliest passive browser signal available.
    // No website probing, request replay, or blocking takes place.
    markHttpStart(d);
    if(d.type==='main_frame'&&d.tabId>=0)void beginAutoCapture(d.tabId,d.url,d.timeStamp).catch(e=>console.warn('[Trufflehog] auto-start',e.message));
    void recordDownloadStep('request',d).catch(()=>{});
    void recordSecurityStage('request',d).catch(()=>{});
  },
  {urls:['http://*/*','https://*/*']},['requestBody']);
if(chrome.webRequest.onBeforeSendHeaders?.addListener)chrome.webRequest.onBeforeSendHeaders.addListener(
  d=>{void recordDownloadStep('headers',d).catch(()=>{});void recordSecurityStage('request-headers',d).catch(()=>{});},
  {urls:['http://*/*','https://*/*']},['requestHeaders']);
if(chrome.webRequest.onHeadersReceived?.addListener)chrome.webRequest.onHeadersReceived.addListener(
  d=>{void recordDownloadStep('response-headers',d).catch(()=>{});void recordSecurityStage('response-headers',d).catch(()=>{});},
  {urls:['http://*/*','https://*/*']},['responseHeaders']);
if(chrome.webRequest.onBeforeRedirect?.addListener)chrome.webRequest.onBeforeRedirect.addListener(
  d=>{void recordDownloadStep('redirect',d).catch(()=>{});void recordSecurityStage('redirect',d).catch(()=>{});},
  {urls:['http://*/*','https://*/*']});
const downloadTabMap=new Map(); // Warm-cache; chrome.storage.session holds bounded restart recovery state.
const pendingDownloadKey=id=>'pending-download:'+String(id);
async function loadPendingDownload(id){
 const entry=downloadTabMap.get(id);
 if(entry)return entry;
 if(!Number.isSafeInteger(id)||id<0)return null;
 const stored=await chrome.storage.session.get(pendingDownloadKey(id));
 const v=stored?.[pendingDownloadKey(id)];
 if(!v||!Number.isInteger(v.tabId)||typeof v.downloadRef!=='string'||!/^DL[0-9]{8,24}$/.test(v.downloadRef))return null;
 if(!Number.isFinite(v.at)||Date.now()-v.at>4*3600*1000){
  await chrome.storage.session.remove?.(pendingDownloadKey(id));return null;
 }
 return v;
}
async function removePendingDownload(id){downloadTabMap.delete(id);await chrome.storage.session.remove?.(pendingDownloadKey(id));}

const downloadRefSeq=new Map(); // Per-tab counter; never persist Chrome's raw download ID.
function newDownloadRef(tabId){const next=(downloadRefSeq.get(tabId)||0)+1;downloadRefSeq.set(tabId,next);return 'DL'+Date.now()+String(next).padStart(4,'0');}
if(chrome.downloads?.onCreated?.addListener)chrome.downloads.onCreated.addListener(item=>{
 void (async()=>{
   // Chrome DownloadItem does NOT provide a tabId. Do not falsely attribute
   // a download to a tab based on a convenient matching URL or time alone.
   // We accept referrer-origin matches only when exactly one opt-in capture exists.
   if(!Number.isSafeInteger(item?.id)||item.id<0)return;
   const origin=originOf(item?.referrer||'');if(!origin)return;
   const states=await chrome.storage.session.get(null);
   const candidates=Object.entries(states).filter(([key,value])=>
     /^active:\d+$/.test(key)&&value?.enabled&&value.downloadObserver===true&&value.origin===origin);
   if(candidates.length!==1)return; // ambiguous or non-consenting context
   // Cap old incomplete-download checkpoints. Never permit a long browsing
   // session to accumulate unbounded background download references.
   const priorPending=Object.entries(states).filter(([key])=>/^pending-download:\d+$/.test(key)).sort((a,b)=>(a[1]?.at||0)-(b[1]?.at||0));
   const stale=priorPending.filter(([,v])=>!Number.isFinite(v?.at)||Date.now()-v.at>4*3600*1000).map(([key])=>key);
   const live=priorPending.filter(([key])=>!stale.includes(key));
   const overflow=live.slice(0,Math.max(0,live.length-499)).map(([key])=>key);
   for(const key of [...stale,...overflow]){
     const id=Number(key.slice('pending-download:'.length));downloadTabMap.delete(id);
   }
   if((stale.length||overflow.length)&&chrome.storage.session.remove)await chrome.storage.session.remove([...new Set([...stale,...overflow])]);
   const tabId=Number(candidates[0][0].slice(7));
   if(!(await hasHostAccess(origin)))return;
   const safe=THIDownload.download('created',item);if(!safe)return;
   const downloadRef=newDownloadRef(tabId);safe.downloadRef=downloadRef;
   const record=await readRecord(tabId);
   if(!record?.sessionId||record.origin!==origin)return;
   const match={tabId,downloadRef,sessionId:record.sessionId,origin,at:Date.now()};
   downloadTabMap.set(item.id,match);
   await chrome.storage.session.set({[pendingDownloadKey(item.id)]:match});
   await updateRecord(tabId,r=>{if(r.origin!==origin||r.sessionId!==match.sessionId)return;
     if(r.downloadEvents.length>=MAX.downloadEvents){r.downloadEvents.shift();r.downloadEventsDropped++;}
     r.downloadEvents.push(safe);
   });
 })().catch(()=>{});
});
if(chrome.downloads?.onChanged?.addListener)chrome.downloads.onChanged.addListener(change=>{
 void (async()=>{
   const match=await loadPendingDownload(change?.id);const tabId=match?.tabId;if(!Number.isInteger(tabId))return;
   const state=await active(tabId);if(!state?.enabled||!state.downloadObserver||state.origin!==match.origin){await removePendingDownload(change.id);return;}
   const status=change.state?.current;if(!['complete','interrupted'].includes(status))return;
   const at=new Date().toISOString();
   let item=null;
   if(typeof chrome.downloads.search==='function'){
     try{const found=await chrome.downloads.search({id:change.id});item=Array.isArray(found)?found[0]:null;}catch{}
   }
   const sizes=THITelemetry.sizeFacts(item||{});
   await updateRecord(tabId,r=>{if(r.origin!==state.origin||r.sessionId!==match.sessionId)return;
     if(r.downloadEvents.length>=MAX.downloadEvents){r.downloadEvents.shift();r.downloadEventsDropped++;}
     r.downloadEvents.push({stage:'download-state',downloadRef:match.downloadRef,at,host:'',referrerHost:'',type:'download',downloadStatus:status,
       errorCategory:status==='interrupted'?THITelemetry.errorCategory(change.error?.current||item?.error):null,
       fileType:/^(?:image\/(?:jpeg|png|webp|gif|avif|tiff|bmp)|application\/(?:zip|pdf|octet-stream))$/i.test(String(item?.mime||''))?String(item.mime).toLowerCase():'',...sizes});
   });
   await removePendingDownload(change.id);
 })().catch(()=>{});
});

chrome.webRequest.onCompleted.addListener(d => {void Promise.allSettled([recordDownloadStep('complete',d),recordNetwork(d)]).finally(()=>retireHttpStart(d));}, {urls: ['http://*/*', 'https://*/*']}, ['responseHeaders']);
chrome.webRequest.onErrorOccurred.addListener(d => {void Promise.allSettled([recordDownloadStep('error',d),recordNetwork(d,d.error || 'request failed')]).finally(()=>retireHttpStart(d));}, {urls: ['http://*/*', 'https://*/*']});

function makeScriptEntry(value, base) {
  const i = THI.urlInfo(value, base);
  return i && {url: i.url, host: i.host, signedQuery: i.signedQuery};
}
async function ingestReport(tabId, payload, allowFingerprints=false) {
  let newlyAlertable=0,newAlertable=0,changedAlertable=0;
  const updated=await updateRecord(tabId, async rec => {
    // Local, site-scoped memory of redacted indicator *locations* only.
    // Not a secret-value fingerprint and never an assertion of exploitability.
    const sightingsKey='thi-v39-seen:'+encodeURIComponent(rec.origin);
    const sightingsData=await chrome.storage.local.get(sightingsKey);
    const prior=Array.isArray(sightingsData[sightingsKey])?sightingsData[sightingsKey].slice(-1400):[];
    const known=new Set(prior),newSightings=[];
    // Per-installation keyed HMACs (not raw values or unkeyed hashes).
    // Kept in local extension storage; keys are never exported.
    const changeKey='thi-v46-seen:'+encodeURIComponent(rec.origin);
    const changeData=await chrome.storage.local.get(changeKey);
    const before=Array.isArray(changeData[changeKey])?changeData[changeKey].slice(-1400):[];
    const previous=new Map(before.filter(x=>x&&typeof x.signature==='string').map(x=>[x.signature,x]));
    const sightingsBySignature=new Map(previous);
    for(const raw of (payload.embeddedContexts||[]).slice(0,60)){
      const fact=THIContexts.clean(raw,rec.origin);
      if(!fact)continue;
      const identity=[fact.kind,fact.origin,fact.relationship,fact.sandboxed].join('|');
      if(rec.embeddedContexts.length>=MAX.embeddedContexts)rec.counters.contextsDropped++;
      addUnique(rec.embeddedContexts,fact,identity,MAX.embeddedContexts);
    }
    // Frame evidence is authored by the trusted top-frame inventory only.
    for(const raw of (payload.frameCoverage||[]).slice(0,35)){
      const row=THIFrameScope.cleanRow(raw,rec.origin);
      if(!row)continue;
      const key=`${row.index}|${row.origin}|${row.depth}`;
      const previous=rec.frameCoverage.findIndex(f=>f._key===key);
      const value={...row,at:new Date().toISOString(),_key:key};
      if(previous>=0)rec.frameCoverage[previous]=value;
      else if(rec.frameCoverage.length<MAX.frameCoverage)rec.frameCoverage.push(value);
      else rec.counters.contextsDropped++;
    }
    for(const raw of (payload.workerScripts||[]).slice(0,12)){
      if(raw?.kind!=='controller-reference'||raw.inspected!==false)continue;
      const url=THI.urlInfo(raw.url,rec.origin);
      if(!url||originOf(url.url)!==rec.origin)continue;
      addUnique(rec.workerScripts,{url:url.url,origin:url.host,kind:'controller-reference',inspected:false,
        evidence:'browser service worker controller reference'},url.url,MAX.workerScripts);
    }
    for (const raw of (payload.scripts || []).slice(0, MAX.scripts)) {
      const s = makeScriptEntry(typeof raw === 'string' ? raw : raw.url, rec.origin);
      if (s) s.signedQuery = !!raw.signedQuery || s.signedQuery;
      if (s) addUnique(rec.scripts, s, s.url, MAX.scripts);
    }
    for (const img of (payload.assets || []).slice(0, MAX.assets)) {
      const info = THI.urlInfo(img.url, rec.origin);
      if (!info) continue;
      const item = {url: info.url, host: info.host, source: 'page DOM',
        width: Number.isInteger(img.width) && img.width > 0 ? Math.min(img.width, 100000) : null,
        height: Number.isInteger(img.height) && img.height > 0 ? Math.min(img.height, 100000) : null,
        descriptor: String(img.descriptor || '').slice(0, 40),
        signedQuery: !!img.signedQuery || info.signedQuery, queryKeys: info.queryKeys, mime: '', bytes: null, etag: '', modified: ''};
      const key = `dom|${info.url}|${item.width || ''}|${item.height || ''}|${item.descriptor}`;
      if (rec.assets.length >= MAX.assets) rec.counters.assetsDropped++;
      addUnique(rec.assets, item, key, MAX.assets);
    }
    // v2.5: link only DOM-visible image/card relationships. The sender is already
    // gated to the opted-in top frame and current origin in PAGE_REPORT dispatch.
    for (const raw of (payload.assetLinks || []).slice(0, MAX.assetLinks)) {
      const img=THI.urlInfo(raw?.imageUrl,rec.origin);
      const page=THI.urlInfo(raw?.pageUrl,rec.origin);
      if(!img||!page||originOf(page.url)!==rec.origin)continue;
      const ident=THILineage.safeId(raw?.assetId)||'';
      const detail=raw?.detailUrl?THI.urlInfo(raw.detailUrl,rec.origin):null;
      const detailUrl=detail && originOf(detail.url)===rec.origin && !detail.signedQuery?detail.url:'';
      if(!ident&&!detailUrl)continue;
      // The claimed image must also occur in the same observed DOM payload or
      // in a prior inventory to prevent forged unattached asset relationships.
      const observedInPayload=(payload.assets||[]).some(a=>THI.sanitizedUrl(a.url,rec.origin)===img.url);
      const previouslyObserved=rec.assets.some(a=>a.url===img.url && a.source==='page DOM');
      if(!observedInPayload&&!previouslyObserved)continue;
      const item={imageUrl:img.url,pageUrl:page.url,detailUrl,assetId:ident,source:'visible gallery DOM',at:new Date().toISOString()};
      addUnique(rec.assetLinks,item,`${img.url}|${page.url}|${detailUrl}|${ident}`,MAX.assetLinks);
    }
    for (const raw of (payload.routes || []).slice(0, MAX.routes)) {
      const i = THI.urlInfo(raw.url, rec.origin);
      if (i) addUnique(rec.routes, {url: i.url, host: i.host, kind: 'static-clue',
        observed: false, method: '', status: null, source: String(raw.source || 'inline script').slice(0, 150)},
      `static|${i.url}`, MAX.routes);
    }
    for (const raw of (payload.findings || []).slice(0, MAX.findings)) {
      const type = String(raw.type || '').slice(0, 80), masked = String(raw.masked || '').slice(0, 150);
      if (!type || !masked.includes('[redacted]')) continue;
      const originalSource=String(raw.source || '').slice(0, 800);
      const source=/^https?:\/\//i.test(originalSource)?THI.sanitizedUrl(originalSource):
        originalSource.replace(/[^a-zA-Z0-9 _.-]/g,'').slice(0,100);
      const severity=THIAlerts.severity(type);
      const offset=Math.min(2000000,Math.max(0,Number(raw.offset)||0));
      const signature=THIChanges.signatureKey({type,source,offset,masked});
      const sourceIsExternal=/^https?:\/\//.test(source);
      const knownBefore=sourceIsExternal&&known.has(signature);
      const fp=allowFingerprints&&/^[a-f0-9]{64}$/.test(raw.fingerprint||'')?raw.fingerprint:'';
      const kid=fp&&/^[a-f0-9]{16}$/.test(raw.fingerprintKeyId||'')?raw.fingerprintKeyId:'';
      const locationSignature=THIChanges.signatureKey({type,source,offset,masked:''});
      const old=sourceIsExternal?previous.get(locationSignature):null;
      let changeState=!knownBefore?'new':'unverified';
      if(fp&&kid&&old?.fingerprint&&old?.fingerprintKeyId===kid){
        changeState=old.fingerprint===fp?'unchanged':'changed';
      }else if(knownBefore){changeState='unverified';}
      if(sourceIsExternal&&fp&&kid)sightingsBySignature.set(locationSignature,{signature:locationSignature,fingerprint:fp,fingerprintKeyId:kid,at:new Date().toISOString()});
      const line=Number.isSafeInteger(raw.line)&&raw.line>0&&raw.line<=2000000?raw.line:null;
      const column=Number.isSafeInteger(raw.column)&&raw.column>0&&raw.column<=2000000?raw.column:null;
      const wasAdded=addUnique(rec.findings,{type,masked,note:String(raw.note||'').slice(0,150),source,
        offset,line,column,knownPrevious:knownBefore,changeState,
        fingerprint:fp,fingerprintKeyId:kid,severity,reviewStatus:changeState==='changed'||changeState==='new'?'new':'reviewing',
        reviewHistory:[],at:new Date().toISOString()},
        `${type}|${source}|${masked}|${offset}|${fp}`,MAX.findings);
      if(wasAdded && !knownBefore && sourceIsExternal){known.add(signature);newSightings.push(signature);}
      if(wasAdded && THIAlerts.alertable(type)&&['new','changed'].includes(changeState)){
        newlyAlertable++;if(changeState==='changed')changedAlertable++;else newAlertable++;
        rec.unreviewedAlerts++;
      }
    }
    for (const raw of (payload.pagination || []).slice(0, 20)) {
      const pageUrl = THI.urlInfo(raw.url, rec.origin);
      if (!pageUrl || originOf(pageUrl.url) !== rec.origin) continue;
      const numberOrNull = (v, max) => Number.isInteger(v) && v > 0 && v <= max ? v : null;
      const page = numberOrNull(raw.page, 1000000);
      const totalPages = numberOrNull(raw.totalPages, 1000000);
      const totalResults = numberOrNull(raw.totalResults, 1000000000);
      if (!page && !totalPages && !totalResults) continue;
      const source = String(raw.source || 'page DOM').slice(0, 48);
      // Strip query values from the scope; distinct searches may still share a scope.
      const scope = new URL(pageUrl.url).pathname.slice(0, 250);
      const entry = {url: pageUrl.url, scope, page, totalPages, totalResults, source,
        observed: source === 'page DOM' || source === 'URL', at: new Date().toISOString()};
      if (!rec.pagination.some(x => x.scope === scope && x.page === page && x.totalPages === totalPages && x.totalResults === totalResults && x.source === source)) {
        if (rec.pagination.length >= MAX.pagination) {rec.pagination.shift();rec.counters.paginationDropped++;}
        rec.pagination.push(entry);
      }
    }
    for(const raw of (payload.maps||[]).slice(0,20)) {
      const info=THI.urlInfo(raw.url,rec.origin);
      if(!info||info.signedQuery||!info.url.endsWith('.map'))continue;
      const script=THI.sanitizedUrl(raw.script||'');
      if(!script)continue;
      addUnique(rec.maps,{url:info.url,script,source:String(raw.source||'').slice(0,200),status:'reference-only',summary:null},info.url,MAX.maps);
    }
    for(const raw of (payload.operations||[]).slice(0,70)) {
      const name=THIApp.safeOperationName(raw.name);
      const type=String(raw.operationType||'');
      if(!name||!['query','mutation','subscription'].includes(type))continue;
      const source=String(raw.source||'').slice(0,200);
      addUnique(rec.operations,{name,operationType:type,source,confidence:'static-GraphQL-clue'},`${type}|${name}|${source}`,MAX.operations);
    }
    for(const raw of (payload.configs||[]).slice(0,70)) {
      const key=String(raw.key||'');
      if(!/^(?:VITE_|NEXT_PUBLIC_|PUBLIC_|NUXT_PUBLIC_|REACT_APP_)[A-Z0-9_]{3,65}$/.test(key)||/(?:token|secret|password|auth|cookie|private|session|key)/i.test(key))continue;
      const framework=String(raw.framework||'').slice(0,40),source=String(raw.source||'').slice(0,200);
      addUnique(rec.configs,{key,framework,source,value:'not collected'},`${key}|${source}`,MAX.configs);
    }
    // Accept only allowlisted technology signals, never arbitrary HTML or JS.
    for (const hint of (payload.technologyHints || []).slice(0, 75)) {
      const profile = THIDAM.PROFILES.find(p=>p.id===hint?.id);
      if (!profile) continue;
      const signalId=String(hint.signalId||'').slice(0,75);
      const isSupported=THIDAM.analyze({technologyHints:[{id:profile.id,signalId}]}).profiles.length>0;
      if (!isSupported) continue;
      const kind=String(hint.kind||'').slice(0,45);
      const source=String(hint.source||'page DOM').slice(0,150);
      // Sanitize outbound source text: no raw query values or credentials.
      const safeSource=/^https?:/i.test(source)?THI.sanitizedUrl(source):/^(?:inline script \d+|page DOM)$/i.test(source)?source:'public JavaScript';
      addUnique(rec.technologyHints,{id:profile.id,signalId,kind,source:safeSource},
        `${profile.id}|${signalId}|${safeSource}`,MAX.technologyHints);
    }
    // v2.7: page-local gallery evidence, no cursor values or query/search terms.
    // Collection/asset IDs are data-attribute hints, never inferred originals.
    if (payload.gallerySnapshot) {
      const raw=payload.gallerySnapshot;
      const parsed=THIGallery.inspect(raw);
      const url=THI.urlInfo(raw.url,rec.origin);
      if (parsed&&url&&originOf(url.url)===rec.origin) {
        const scope=new URL(url.url).pathname.slice(0,250);
        const at=new Date().toISOString();
        const item={scope,url:url.url.split('?')[0],at,...parsed,assetCount:parsed.assetIds.length};
        delete item.assetIds;delete item.collectionIds;
        const prior=rec.galleryEvents.at(-1);
        const same=prior&&prior.scope===item.scope&&prior.url===item.url&&prior.page===item.page&&
          prior.galleryCards===item.galleryCards&&prior.imageCount===item.imageCount&&
          prior.scrollBucket===item.scrollBucket&&prior.cursorStep===item.cursorStep&&
          prior.assetCount===item.assetCount&&prior.atBottom===item.atBottom&&
          prior.loadMore===item.loadMore&&prior.nextControl===item.nextControl;
        if(!same){
          if(rec.galleryEvents.length>=MAX.galleryEvents){rec.galleryEvents.shift();rec.counters.galleryEventsDropped++;}
          rec.galleryEvents.push(item);
        }
        const collections=parsed.collectionIds.length?parsed.collectionIds:[''];
        for(const id of parsed.assetIds)for(const collectionId of collections){
          if(rec.galleryAssets.length>=MAX.galleryAssets){rec.counters.galleryAssetsDropped++;continue;}
          addUnique(rec.galleryAssets,{assetId:id,collectionId,scope,page:parsed.page,at},
            `${scope}|${parsed.page||''}|${collectionId}|${id}`,MAX.galleryAssets);
        }
      }
    }
    for(const raw of (payload.viewerHints||[]).slice(0,75)){
      const tech=String(raw.technology||'');
      if(!['Canvas','SmartFrame','OpenSeadragon','Deep Zoom','IIIF Image API','WebGL','Canvas 2D'].includes(tech))continue;
      const evidence=String(raw.evidence||'');
      if(!['rendered canvas elements (context unverified)','smartframe-embed DOM elements','openseadragon DOM class markers','static JavaScript reference'].includes(evidence))continue;
      const count=Number.isSafeInteger(raw.count)&&raw.count>0?Math.min(raw.count,10000):null;
      const origin=String(raw.source||'page DOM');
      const source=/^https?:/i.test(origin)?THI.sanitizedUrl(origin):/^inline script \d+$/i.test(origin)?origin:'page DOM';
      addUnique(rec.viewerHints,{technology:tech,evidence,source,count,
        maxWidth:Number.isSafeInteger(raw.maxWidth)&&raw.maxWidth>0?Math.min(raw.maxWidth,200000):null,
        maxHeight:Number.isSafeInteger(raw.maxHeight)&&raw.maxHeight>0?Math.min(raw.maxHeight,200000):null},
        `${tech}|${evidence}|${source}|${count??''}`,MAX.viewerHints);
    }
    for (const raw of (payload.clues || []).slice(0, MAX.clues)) {
      const label = String(raw.label || '').slice(0, 100), source = String(raw.source || '').slice(0, 150);
      if (label) addUnique(rec.clues, {label, source}, `${label}|${source}`, MAX.clues);
    }
    if(newSightings.length){
      // Legacy location history remains compatible with previously recorded captures.
      await chrome.storage.local.set({[sightingsKey]:[...prior,...newSightings].slice(-1500)});
    }
    if(sightingsBySignature.size!==previous.size||[...sightingsBySignature].some(([k,v])=>previous.get(k)?.fingerprint!==v.fingerprint)){
      await chrome.storage.local.set({[changeKey]:[...sightingsBySignature.values()].slice(-1400)});
    }
  });
  if(newlyAlertable && updated) await showSecretAlert(tabId,updated,changedAlertable>0&&newAlertable===0);
}
// Response bodies are never stored: only schema field paths and numeric pagination hints
// produced by the explicitly enabled DevTools inspector are accepted.
function safeSchemaPath(path) {
  if (typeof path !== 'string' || path.length > 150) return '';
  const segments = path.split('.');
  if (segments.length > 7 || !segments.every(s => /^([A-Za-z_$][A-Za-z0-9_$-]{0,49}|\[\])$/.test(s))) return '';
  if (segments.some(s => s!=='NextToken' && s!=='nextToken' && /(?:token|secret|pass|auth|session|cookie|credential|email|phone|address|user|personal|payment|card|name|jwt|key)/i.test(s))) return '';
  return path;
}
async function ingestResponseShape(tabId, payload) {
  const recording = await active(tabId);
  if (!recording?.enabled || !recording.responseShapes) return {ok:false,error:'Enable JSON structure inspection first.'};
  const info = THI.urlInfo(payload.url);
  if (!info || !/^https?:/.test(info.url)) return {ok:false};
  const mime = String(payload.mime || '').slice(0,100);
  if (!/(?:json|\+json)/i.test(mime)) return {ok:false};
  const licensing=THIAssetLicensing.sanitize(payload.licensing);
  const pim=THIProductAsset.sanitize(payload.pim);
  const fields = [];
  const seen = new Set();
  for (const raw of (Array.isArray(payload.fields) ? payload.fields : []).slice(0,100)) {
    const path = safeSchemaPath(raw?.path);
    const type = String(raw?.type || '');
    if (!path || !['null','array','string','number','boolean','object'].includes(type) || seen.has(path)) continue;
    seen.add(path); fields.push({path,type});
    if (fields.length >= 50) break;
  }
  if (!fields.length && (!licensing || licensing.categories.every(x=>x==='UNKNOWN')) && (!pim || pim.labels.every(x=>x==='UNKNOWN'))) return {ok:false};
  const pagination = {};
  for (const [key,limit] of Object.entries({page:1000000, currentPage:1000000, totalPages:1000000, totalResults:1000000000})) {
    const n = payload.pagination?.[key];
    if (Number.isInteger(n) && n > 0 && n <= limit) pagination[key] = n;
  }
  await updateRecord(tabId, rec => {
    if (rec.origin !== recording.origin) return;
    const entry = {url:info.url, host:info.host, method:String(payload.method||'GET').slice(0,12),
      status: Number.isInteger(payload.status) ? payload.status : null,
      mime, fields, pagination, at: new Date().toISOString(), confidence:'response-shape-observed'};
    const old = rec.responses.findIndex(r => r.url === entry.url && r.method === entry.method);
    if (old !== -1) rec.responses.splice(old,1);
    else if (rec.responses.length >= MAX.responses) {rec.responses.shift();rec.counters.responsesDropped++;}
    rec.responses.push(entry);
    if (pim && pim.labels.some(x=>x!=='UNKNOWN')) {
      const observed={...pim,at:entry.at,method:entry.method,httpStatus:entry.status};
      // A bounded evidence list; preserve separate product records and update repeated source shapes.
      const key=observed.products.map(x=>x.ref).join('|');
      const i=key?rec.pimObservations.findIndex(x=>x.products.map(z=>z.ref).join('|')===key):-1;
      if(i>=0)rec.pimObservations.splice(i,1);
      else if(rec.pimObservations.length>=MAX.pimObservations){rec.pimObservations.shift();rec.pimObservationsDropped++;}
      rec.pimObservations.push(observed);
    }
    if (licensing && licensing.categories.some(x=>x!=='UNKNOWN')) {
      // The DevTools-inspected JSON is reduced to allowlisted numeric/boolean
      // fields and randomized anonymous references. No raw IDs/body retained.
      const observed={...licensing,at:entry.at,method:entry.method,httpStatus:entry.status};
      const index=rec.licensingObservations.findIndex(x=>x.assetRef&&x.assetRef===observed.assetRef&&x.method===observed.method&&x.categories.join('|')===observed.categories.join('|'));
      if(index>=0)rec.licensingObservations.splice(index,1);
      else if(rec.licensingObservations.length>=MAX.licensingObservations){rec.licensingObservations.shift();rec.licensingObservationsDropped++;}
      rec.licensingObservations.push(observed);
    }
    const page = pagination.currentPage || pagination.page || null;
    if (page || pagination.totalPages || pagination.totalResults) {
      const scope = new URL(info.url).pathname.slice(0,250);
      const clue = {url:info.url,scope,page,totalPages:pagination.totalPages||null,totalResults:pagination.totalResults||null,
        source:'JSON response',observed:true,at:entry.at};
      if (!rec.pagination.some(p=>p.scope===scope&&p.page===clue.page&&p.totalPages===clue.totalPages&&p.totalResults===clue.totalResults&&p.source===clue.source)) {
        if (rec.pagination.length >= MAX.pagination) {rec.pagination.shift();rec.counters.paginationDropped++;}
        rec.pagination.push(clue);
      }
    }
  });
  return {ok:true};
}

async function ingestPimMedia(tabId,payload){
  const recording=await active(tabId);
  if(!recording?.enabled||!recording.responseShapes)return {ok:false};
  const m=THIProductAsset.sanitizeMedia(payload?.media);
  if(!m||(m.status===null)||(!m.routeRef&&!m.assetRef))return {ok:false};
  await updateRecord(tabId,rec=>{
    if(rec.origin!==recording.origin)return;
    const key=(x)=>[x.routeRef,x.assetRef,x.status].join('|');
    if(rec.pimMediaObservations.some(x=>key(x)===key(m)))return;
    if(rec.pimMediaObservations.length>=MAX.pimMediaObservations){rec.pimMediaObservations.shift();rec.pimMediaDropped++;}
    rec.pimMediaObservations.push({...m,at:new Date().toISOString()});
  });
  return {ok:true};
}

// Only accept cryptographic image fingerprints calculated locally in an explicitly
// enabled DevTools panel. No image bytes, raw query values or cookies are saved.
async function ingestVerifiedImage(tabId, payload) {
  const state=await active(tabId);
  if(!state?.enabled||!state.verifyImages)return {ok:false,error:'Enable image verification first.'};
  const info=THI.urlInfo(payload.url);
  if(!info||!/^https?:\/\//.test(info.url))return {ok:false};
  const hash=String(payload.sha256||'');
  if(!/^[a-f0-9]{64}$/.test(hash))return {ok:false};
  const size=Number(payload.byteLength);
  if(!Number.isSafeInteger(size)||size<1||size>4*1024*1024)return {ok:false};
  const dimension=n=>Number.isSafeInteger(n)&&n>0&&n<=100000?n:null;
  const width=dimension(payload.width),height=dimension(payload.height);
  const format=String(payload.format||'unknown').slice(0,16);
  if(!['PNG','JPEG','GIF','BMP','WebP','unknown'].includes(format))return {ok:false};
  const mime=String(payload.mime||'').slice(0,60);
  if(!/^image\/(?:jpeg|png|gif|webp|bmp|avif)$/i.test(mime))return {ok:false};
  // Only allow fingerprints from explicitly opted-in DevTools byte verification.
  // Reject arbitrary metadata text; retain no EXIF/IPTC/XMP values or image bytes.
  const validVisual=state.verifyVisual===true&&THIVisual.validate(payload.visual);
  const metaAllowed=state.verifyMetadata===true;
  const metaTypes=new Set(['EXIF','IPTC','XMP','ICC','C2PA']);
  const metadata=metaAllowed&&Array.isArray(payload.metadata)?payload.metadata.slice(0,16).filter(m=>
    metaTypes.has(m?.kind)&&/^[a-f0-9]{64}$/.test(m?.sha256||'')).map(m=>({kind:m.kind,sha256:m.sha256})):[];
  await updateRecord(tabId,rec=>{
    if(rec.origin!==state.origin||(rec.captureStartedAt||rec.createdAt)>state.startedAt)return;
    const entry={url:info.url,host:info.host,sha256:hash,byteLength:size,
      width,height,format,mime,metadata,visual:validVisual||null,at:new Date().toISOString()};
    const idx=rec.verifications.findIndex(v=>v.url===entry.url);
    if(idx>=0)rec.verifications.splice(idx,1);
    else if(rec.verifications.length>=MAX.verifications){rec.verifications.shift();rec.counters.verificationsDropped++;}
    rec.verifications.push(entry);
  });
  return {ok:true};
}

async function scanTab(tabId) {
  try {
    await chrome.tabs.sendMessage(tabId, {type: 'CAPTURE_SNAPSHOT'});
    return true;
  } catch {
    try {
      // For a tab which was open before installation or extension reload.
      await chrome.scripting.executeScript({target: {tabId}, files: ['scanner.js', 'frame_scope.js', 'app_intel.js', 'dam_intel.js', 'lineage_intel.js','viewer_intel.js','gallery_intel.js','content.js']});
      await chrome.tabs.sendMessage(tabId, {type: 'CAPTURE_SNAPSHOT'});
      return true;
    } catch {return false;}
  }
}
async function startCapture(tabId, navigationOrigin='', deferPageScan=false, navigationAt=0) {
  const tab = navigationOrigin ? null : await chrome.tabs.get(tabId);
  const origin = navigationOrigin || originOf(tab?.url);
  if (!origin) throw new Error('Open an HTTP or HTTPS website to begin.');
  if (!(await hasHostAccess(origin))) throw new Error('Chrome has not granted all-sites access to this origin. Review the extension site settings.');
  const current = await active(tabId);
  if (current && current.enabled && current.origin === origin) return {origin, alreadyRunning: true};
  // Save before asking the page to respond; reports are rejected without opt-in.
  // Archive the old tab record before replacing it (never silently discard it).
  const previous=await readRecord(tabId);
  if(previous)await archiveRecord(tabId,true);
  await queue(tabId, async () => {
    const rec=emptyRecord(tabId, origin);
    rec.downloadObserverEverEnabled=true;
    // The initial main-frame request precedes the async Chrome storage write.
    // Keep the browser event timestamp so it is not dropped as a stale event.
    if(Number.isFinite(navigationAt)&&navigationAt>0&&navigationAt<=Date.now()+60000)
      rec.captureStartedAt=new Date(Math.max(0,navigationAt-1)).toISOString();
    if(journalSupported()){
      try{await THICaptureJournal.replace(tabId,rec);liveCache.set(tabId,cloneRecord(rec));liveStorageErrors.delete(tabId);}
      catch(e){noteStorageFailure(tabId,e);throw e;}
    }
    await chrome.storage.local.set({[recordKey(tabId)]: rec});
    unassignedSinceWorker.delete(tabId);
  });
  await chrome.storage.session.set({[stateKey(tabId)]: {origin, enabled: true, ...allActiveOptions(),startedAt: new Date().toISOString()}});
  await updateBadge(tabId, null, true);
  // During onBeforeRequest the new document does not exist yet. Wait for load
  // instead of injecting into the *previous* origin's document.
  if (!deferPageScan) await scanTab(tabId);
  return {origin, alreadyRunning: false};
}
// Serialized per-tab to avoid races between navigation, tab updates, and downloads.
function beginAutoCapture(tabId,url,requestAt=0){
  const origin=originOf(url);
  if(!Number.isSafeInteger(tabId)||tabId<0||!origin)return Promise.resolve(false);
  const prior=autoStarts.get(tabId)||Promise.resolve();
  const next=prior.catch(()=>{}).then(async()=>{
    if(!(await autoCaptureEnabled())||!(await hasHostAccess(origin)))return false;
    const state=await active(tabId);
    if(state?.enabled&&state.origin===origin)return true;
    await startCapture(tabId,origin,true,requestAt);
    return true;
  });
  autoStarts.set(tabId,next);
  void next.finally(()=>{if(autoStarts.get(tabId)===next)autoStarts.delete(tabId);}).catch(()=>{});
  return next;
}
async function notifyDiscoveryOnStop(tabId){
 const prefs=await chrome.storage.local.get('discoveryDesktopAlerts');
 if(prefs.discoveryDesktopAlerts!==true||!chrome.notifications?.create)return {status:'disabled'};
 const recent=await readRecord(tabId);
 if(!recent?.sessionId||!recent?.origin)return {status:'no-capture'};
 // Only compare completed capture groups from the same exact origin.
 const sessions=(await THIVault.list()).filter(s=>s.origin===recent.origin);
 const groups=new Map();
 for(const s of sessions){const id=s.captureGroupId||s.id;
  if(!groups.has(id))groups.set(id,[]);groups.get(id).push(s);
 }
 const currentId=recent.captureGroupId||recent.sessionId;
 const nowGroup=groups.get(currentId)||[];
 const earlier=[...groups.entries()].filter(([id,arr])=>id!==currentId&&arr.length&&arr.every(s=>s.endedAt))
  .sort((a,b)=>String(b[1][0].startedAt||'').localeCompare(String(a[1][0].startedAt||'')))[0];
 if(!earlier||!nowGroup.length||nowGroup.length>40||earlier[1].length>40)return {status:'no-comparable-baseline'};
 const a=await Promise.all(earlier[1].map(s=>THIVault.get(s.id)));
 const b=await Promise.all(nowGroup.map(s=>THIVault.get(s.id)));
 if(a.some(x=>!x)||b.some(x=>!x))return {status:'incomplete-record'};
 const prior=THIDiscoveryPulse.snapshot(a),next=THIDiscoveryPulse.snapshot(b);
 if(!prior.requests||!next.requests)return {status:'missing-observations'};
 const pulse=THIDiscoveryPulse.compare(prior,next);
 // Distinct host roles are observable changes in browsing, not established platform changes.
 if(!pulse.counts.newHosts)return {status:'no-new-host-roles'};
 const id=`trufflehog-discovery-${tabId}-${Date.now()}`;
 await chrome.notifications.create(id,{type:'basic',iconUrl:'icon128.png',
  title:'Newly observed integration evidence',
  message:`${pulse.counts.newHosts} host role(s) not seen in the earlier saved capture. This may reflect different browsing; review offline evidence.`,
  priority:0,buttons:[{title:'Review discovery pulse'}]});
 return {status:'notified',count:pulse.counts.newHosts};
}
async function stopCapture(tabId) {
  // Evict volatile download associations on capture stop.
  for(const [id,match] of downloadTabMap)if(match?.tabId===tabId)downloadTabMap.delete(id);
  downloadRefSeq.delete(tabId);
  // Stop accepting new events before draining queued updates and archiving.
  await chrome.storage.session.remove(stateKey(tabId));
  try {await chrome.tabs.sendMessage(tabId, {type:'STOP_CAPTURE'});} catch {}
  let archiveWarning='';
  try{await archiveRecord(tabId,true);}catch(e){archiveWarning='Evidence vault could not archive this session: '+e.message;console.warn('[Trufflehog]',archiveWarning);}
  // Discovery notifications are opt-in, best-effort, and never block stop/archive.
  if(!archiveWarning){try{await notifyDiscoveryOnStop(tabId);}catch(e){console.warn('[Trufflehog] discovery review unavailable:',e.message);}}
  await updateBadge(tabId, await readRecord(tabId), false);
  return {archiveWarning};
}
async function analyzeScripts(tabId) {
  const recording = await active(tabId);
  if (!recording || !recording.enabled) throw new Error('Start a capture before analysing linked scripts.');
  const record = await readRecord(tabId);
  const scripts = (record?.scripts || []).filter(s => !s.signedQuery && /^https?:\/\//.test(s.url)).slice(0, 12);
  let checked = 0, skipped = 0;
  for (const script of scripts) {
    const currentState = await active(tabId);
    if (!currentState?.enabled || currentState.origin !== recording.origin) break;
    const now = await readRecord(tabId);
    if (now?.scannedScripts?.includes(script.url)) continue;
    try {
      // Explicit user request only. Never send page cookies or authorization.
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 6500);
      let response;
      try {response = await fetch(script.url, {credentials:'omit', referrerPolicy:'no-referrer', signal:controller.signal});}
      finally {clearTimeout(timeout);}
      if (!response.ok) {skipped++; continue;}
      const type = response.headers.get('content-type') || '';
      const len = Number(response.headers.get('content-length') || 0);
      if (len > 850000 || (type && !/(?:javascript|ecmascript|text\/plain)/i.test(type) && !/\.m?js(?:\?|$)/i.test(script.url))) {
        await response.body?.cancel(); skipped++; continue;
      }
      const reader = response.body?.getReader();
      if (!reader) {skipped++; continue;}
      const decoder = new TextDecoder(); let text = '', bytes = 0, excessive = false;
      while (true) {
        const {done, value} = await reader.read();
        if (done) break;
        bytes += value.byteLength;
        if (bytes > 850000) {excessive = true; await reader.cancel(); break;}
        text += decoder.decode(value, {stream:true});
      }
      if (excessive) {skipped++; continue;}
      text += decoder.decode();
      const intel=THIApp.inspectStatic(text,script.url,script.url);
      const payload = {viewerHints:THIViewer.staticHints(text,script.url),technologyHints:THIDAM.scanText(text,script.url), routes: THI.endpointClues(text, script.url, script.url),
        findings: THI.secretIndicators(text, script.url), clues: THI.frameworkClues(text, script.url),
        maps:intel.maps, operations:intel.operations, configs:intel.configs};
      await ingestReport(tabId, payload);
      await updateRecord(tabId, r => {if (!r.scannedScripts.includes(script.url)) r.scannedScripts.push(script.url);});
      checked++;
    } catch {skipped++;}
  }
  return {checked, skipped, total: scripts.length};
}


// Explicit, credential-free inspection of map URLs referenced in scripts already scanned.
// Maps may contain original source text; it is parsed ephemerally and NEVER persisted.
async function inspectReferencedMaps(tabId) {
  const state=await active(tabId);
  if(!state?.enabled)throw new Error('Start a capture first.');
  const initial=await readRecord(tabId);
  const candidates=(initial?.maps||[]).filter(m=>m.status==='reference-only'&&!m.url.includes('[redacted]')).slice(0,8);
  let inspected=0,skipped=0;
  for(const map of candidates){
    const live=await active(tabId);
    if(!live?.enabled||live.origin!==state.origin)break;
    try {
      const mapUrl=new URL(map.url),scriptUrl=new URL(map.script);
      if(mapUrl.origin!==scriptUrl.origin||!mapUrl.pathname.endsWith('.map')||mapUrl.search||mapUrl.hash){skipped++;continue;}
      const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),7000);
      let response;
      try{response=await fetch(mapUrl.href,{credentials:'omit',referrerPolicy:'no-referrer',redirect:'error',signal:controller.signal});}
      finally{clearTimeout(timer);}
      if(!response.ok){skipped++;continue;}
      const len=Number(response.headers.get('content-length')||0),mime=response.headers.get('content-type')||'';
      if(len>900000||(mime&&!/(?:json|octet-stream|text\/plain|javascript)/i.test(mime))){await response.body?.cancel();skipped++;continue;}
      const reader=response.body?.getReader();if(!reader){skipped++;continue;}
      const decoder=new TextDecoder();let body='',bytes=0,oversize=false;
      // 900 KiB hard limit independent of potentially untruthful Content-Length.
      while(true){const {done,value}=await reader.read();if(done)break;
        bytes+=value.byteLength;if(bytes>900000){oversize=true;await reader.cancel();break;}
        body+=decoder.decode(value,{stream:true});}
      if(oversize){skipped++;continue;}
      body+=decoder.decode();
      const summary=THIApp.sourceMapSummary(JSON.parse(body));
      body='';
      if(!summary){skipped++;continue;}
      await updateRecord(tabId,rec=>{
        if(rec.origin!==live.origin||(rec.captureStartedAt||rec.createdAt)>live.startedAt)return;
        const target=rec.maps.find(item=>item.url===map.url);
        if(target){target.status='inspected-public-map';target.summary=summary;target.at=new Date().toISOString();}
      });
      inspected++;
    }catch{skipped++;}
  }
  return {inspected,skipped,total:candidates.length};
}

// Opt-in manifest summary from an already-observed DevTools response.
// No arbitrary URL fetch, payload values or raw XML/JSON are saved.
async function ingestViewerManifest(tabId,payload){
  const state=await active(tabId);
  if(!state?.enabled||!state.viewerManifests)return {ok:false,error:'Enable viewer manifest inspection first.'};
  const info=THI.urlInfo(payload?.url);
  if(!info||info.signedQuery)return {ok:false};
  const classification=THIViewer.classifyUrl(info.url);
  if(!classification||!['manifest reference','image info reference','presentation reference'].includes(classification.kind))return {ok:false};
  const allowed=['Deep Zoom','Zoomify','IIIF Image API','IIIF Presentation'];
  const format=String(payload?.summary?.format||'');
  if(!allowed.includes(format))return {ok:false};
  if(classification.format==='Deep Zoom'&&format!=='Deep Zoom'||classification.format==='Zoomify'&&format!=='Zoomify'||classification.format==='Possible IIIF'&&!format.startsWith('IIIF'))return {ok:false};
  const safeDim=n=>Number.isSafeInteger(n)&&n>0&&n<=200000?n:null;
  const summary=payload.summary;
  const width=safeDim(summary.width),height=safeDim(summary.height),tileWidth=safeDim(summary.tileWidth),tileHeight=safeDim(summary.tileHeight);
  if(format!=='IIIF Presentation'&&(!width||!height))return {ok:false};
  if((tileWidth&&tileWidth>8192)||(tileHeight&&tileHeight>8192))return {ok:false};
  const scaleFactors=(Array.isArray(summary.scaleFactors)?summary.scaleFactors:[]).filter(n=>Number.isInteger(n)&&n>0&&n<=131072).slice(0,30);
  const levels=Number.isSafeInteger(summary.levels)&&summary.levels>0&&summary.levels<=40?summary.levels:null;
  const itemCount=Number.isSafeInteger(summary.itemCount)&&summary.itemCount>=0?Math.min(50000,summary.itemCount):null;
  const family=THI.sanitizedUrl(classification.family);
  if(!family)return {ok:false};
  const record=await readRecord(tabId);
  if(!record||!record.requests.some(r=>r.url===info.url&&r.status===200))return {ok:false,error:'No successful observed request for this manifest.'};
  await updateRecord(tabId,rec=>{
    if(rec.origin!==state.origin||(rec.captureStartedAt||rec.createdAt)>state.startedAt)return;
    const entry={url:info.url,host:info.host,family,format,width,height,tileWidth,tileHeight,levels,scaleFactors,itemCount,
      source:'DevTools-observed manifest response',at:new Date().toISOString()};
    const idx=rec.viewerManifests.findIndex(v=>v.url===entry.url);
    if(idx>=0)rec.viewerManifests.splice(idx,1);
    else if(rec.viewerManifests.length>=MAX.viewerManifests)rec.viewerManifests.shift();
    rec.viewerManifests.push(entry);
  });
  return {ok:true};
}

// Accept indicators only from resources that the inspected tab already loaded.
async function ingestAutoResource(tabId,payload){
 const state=await active(tabId);
 if(!state?.enabled || !state.autoSecretScan)return {ok:false};
 if(payload?.startedAt && payload.startedAt!==state.startedAt)return {ok:false,error:'Capture changed'};
 const info=THI.urlInfo(payload.url);
 if(!info||!['javascript','html','css','json','xml'].includes(payload.kind))return {ok:false};
 const type=String(payload.kind),bytes=payload.byteCount;
 if(!Number.isSafeInteger(bytes)||bytes<0||bytes>2*1024*1024)return {ok:false};
 // Require a successful browser-observed request; only passive DevTools responses qualify.
 const rec=await readRecord(tabId);
 if(!rec||rec.origin!==state.origin||!rec.requests.some(r=>r.url===info.url&&r.status>=200&&r.status<300))
   return {ok:false,error:'Response was not recorded in this capture.'};
 const sha256=type==='javascript'&&/^[a-f0-9]{64}$/i.test(payload.sha256||'')?payload.sha256.toLowerCase():'';
 const findings=(Array.isArray(payload.findings)?payload.findings:[]).slice(0,100)
   .filter(x=>x&&typeof x.type==='string'&&typeof x.masked==='string')
   .map(x=>({...x,source:info.url}));
 await ingestReport(tabId,{findings},true);
 await updateRecord(tabId,r=>{
   if(r.origin!==state.origin)return;
   addUnique(r.resourceScans,{url:info.url,host:info.host,kind:type,byteCount:bytes,sha256,
     indicatorCount:findings.length,at:new Date().toISOString()},`${type}|${info.url}|${sha256}`,MAX.resourceScans);
 });
 return {ok:true,indicators:findings.length};
}
async function ingestInteraction(tabId,payload,sender){
 const state=await active(tabId);
 if(!state?.enabled||originOf(sender.url)!==state.origin||sender.frameId!==0||sender.tab?.id!==tabId)return {ok:false};
 const kind=THISearch.interactionKind(payload?.kind);
 if(!kind)return {ok:false};
 await updateRecord(tabId,rec=>{
   if(rec.origin!==state.origin)return;
   const at=new Date().toISOString();
   const previous=rec.interactions.at(-1);
   if(previous?.kind===kind && Date.parse(at)-Date.parse(previous.at)<450)return;
   if(rec.interactions.length>=MAX.interactions)rec.interactions.shift();
   rec.interactions.push({at,kind});
 });
 return {ok:true};
}

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  const action = msg?.type;
  const dispatch = async () => {
    if (action === 'PAGE_READY' || action === 'PAGE_REPORT') {
      if (sender.frameId !== 0 || !sender.tab?.id) return {ok:false};
      const recording = await active(sender.tab.id);
      if (!recording?.enabled || originOf(sender.url) !== recording.origin) return {ok:false};
      if (action === 'PAGE_READY') {await scanTab(sender.tab.id); return {ok:true};}
      await ingestReport(sender.tab.id, msg.payload || {});
      return {ok:true};
    }
    if(action==='GALLERY_INTERACTION')return ingestInteraction(sender.tab?.id,msg.payload||{},sender);
    if(action==='DEVTOOLS_HEARTBEAT'){
      if(sender.url!==chrome.runtime.getURL('devtools.html'))return {ok:false,error:'Extension DevTools only'};
      const id=Number(msg?.tabId);
      if(!Number.isSafeInteger(id)||id<0)return {ok:false};
      const state=await active(id);
      if(!state?.enabled||!state.autoSecretScan||msg.startedAt!==state.startedAt)return {ok:false,error:'Capture changed'};
      const updated=await updateRecord(id,r=>{if(r.origin===state.origin)r.devtoolsHeartbeatAt=new Date().toISOString();});
      return {ok:!!updated};
    }
    if(action==='AUTO_SCAN_PROGRESS'){
      if(sender.url!==chrome.runtime.getURL('devtools.html'))return {ok:false,error:'Invalid source'};
      const id=Number(msg?.tabId);if(!Number.isSafeInteger(id)||id<0)return {ok:false};
      const state=await active(id);if(!state?.enabled||!state.autoSecretScan)return {ok:false};
      if(msg.startedAt!==state.startedAt)return {ok:false,error:'Capture changed'};
      const keys=['eligible','scanned','oversized','unavailable','timeout','unsupported','unrecorded','permissionBlocked','deliveryError','failed','capacity','duplicates','indicators','queued','running','seen'];
      const stats={};
      for(const key of keys){const n=msg.stats?.[key];stats[key]=Number.isSafeInteger(n)&&n>=0&&n<=1000000?n:0;}
      stats.updatedAt=new Date().toISOString();
      await updateRecord(id,r=>{if(r.origin===state.origin)r.autoScanCoverage=stats;});
      return {ok:true};
    }
    if(action==='AUTO_RESOURCE_SCAN'){
      if(sender.url!==chrome.runtime.getURL('devtools.html'))return {ok:false,error:'Invalid source'};
      const tabId=Number(msg?.tabId);
      if(!Number.isInteger(tabId)||tabId<0)return {ok:false};
      return ingestAutoResource(tabId,{...(msg.payload||{}),startedAt:msg.startedAt});
    }
    if (action === 'PIM_MEDIA_OBSERVATION') {
      if(sender.url!==chrome.runtime.getURL('devtools.html'))return {ok:false,error:'Invalid source'};
      const id=Number(msg?.tabId);if(!Number.isInteger(id)||id<0)return {ok:false};
      return ingestPimMedia(id,msg.payload||{});
    }

    if (action === 'RESPONSE_SHAPE') {
      // Only the extension's DevTools page may submit redacted structure metadata.
      if (sender.url !== chrome.runtime.getURL('devtools.html')) return {ok:false,error:'Invalid source'};
      const id = Number(msg?.tabId);
      if (!Number.isInteger(id) || id < 0) return {ok:false};
      return ingestResponseShape(id, msg.payload || {});
    }

    if(action==='VIEWER_MANIFEST'){
      if(sender.url!==chrome.runtime.getURL('devtools.html'))return {ok:false,error:'Invalid source'};
      const id=Number(msg?.tabId);
      if(!Number.isInteger(id)||id<0)return {ok:false};
      return ingestViewerManifest(id,msg.payload||{});
    }
    if(action==='VERIFIED_IMAGE') {
      if(sender.url!==chrome.runtime.getURL('devtools.html'))return {ok:false,error:'Invalid source'};
      const id=Number(msg?.tabId);
      if(!Number.isInteger(id)||id<0)return {ok:false};
      return ingestVerifiedImage(id,msg.payload||{});
    }
    if(action==='GET_AUTO_CAPTURE')return {ok:true,enabled:await autoCaptureEnabled()};
    if(action==='SET_AUTO_CAPTURE'){
      if(!String(sender.url||'').startsWith(chrome.runtime.getURL('')))return {ok:false,error:'Extension interface only'};
      const enabled=msg.enabled===true;
      await chrome.storage.local.set({autoCaptureEnabled:enabled});
      if(!enabled){
        // Stop observing immediately, including tabs whose navigation is settling.
        await Promise.allSettled([...autoStarts.values()]);
        const states=await chrome.storage.session.get(null);
        for(const [key,value] of Object.entries(states)){
          const match=/^active:(\d+)$/.exec(key);
          if(match&&value?.enabled)await stopCapture(Number(match[1]));
        }
      }else if(chrome.tabs?.query){
        const tabs=await chrome.tabs.query({});
        for(const tab of tabs.slice(0,100))if(originOf(tab?.url)){
          await beginAutoCapture(tab.id,tab.url);
          if((await active(tab.id))?.enabled)await scanTab(tab.id);
        }
      }
      return {ok:true,enabled};
    }
    const tabId = Number(msg?.tabId);
    if (!Number.isInteger(tabId) || tabId < 0) throw new Error('Invalid tab ID.');
    if (action === 'START_CAPTURE') return {ok:true, ...(await startCapture(tabId))};
    if (action === 'SITE_PERMISSION_STATUS') {
      const tab=await chrome.tabs.get(tabId);
      const origin=originOf(tab?.url);
      return {ok:true,origin,granted:await hasHostAccess(origin)};
    }
    if (action === 'FULL_SELF_TEST' || action === 'TEST_NOTIFICATION') {
      // A website/content script cannot invoke synthetic notification or storage tests.
      if (!String(sender.url||'').startsWith(chrome.runtime.getURL(''))) return {ok:false,error:'Extension UI only'};
      return action === 'FULL_SELF_TEST'
        ? await THISelfTest.run(tabId,{active,hasHostAccess,originOf,THIVault,readRecord,THIHealth})
        : await THISelfTest.notification();
    }
    if (action === 'GET_ACCEPTANCE_REPORT') {
      if (!String(sender.url||'').startsWith(chrome.runtime.getURL('')))
        return {ok:false,error:'Extension interface only'};
      const tab=await chrome.tabs.get(tabId);
      const origin=originOf(tab?.url||'');
      const state=await active(tabId);
      const rec=await readRecord(tabId);
      const permission=origin?await hasHostAccess(origin):false;
      let inspector=null;
      if(state?.enabled && permission && state.origin===origin) {
        try {
          const ping=await Promise.race([
            chrome.tabs.sendMessage(tabId,{type:'TRUFFLEHOG_HEALTH_PING'}),
            new Promise((_,reject)=>setTimeout(()=>reject(Error('Inspector response timeout')),2500))
          ]);
          inspector=ping?.ok===true && ping?.inspectorPresent===true && ping?.origin===origin && ping?.observing===true;
        } catch {inspector=false;}
      }
      let archive=null;
      if(rec?.sessionId && !state?.enabled && typeof indexedDB!=='undefined') {
        try { const saved=await THIVault.get(rec.sessionId);archive=!!saved && saved.sessionId===rec.sessionId; }
        catch {archive=false;}
      }
      const health=THIHealth.assess(rec,state);
      return {ok:true,report:THIAcceptance.evaluate({record:rec,recording:state,permission,
        inspector,archive,health})};
    }
    if (action === 'CHROME_DIAGNOSTICS') {
      const tab=await chrome.tabs.get(tabId);
      const origin=originOf(tab?.url);
      const granted=await hasHostAccess(origin);
      const current=await active(tabId);
      const permissions=await chrome.permissions?.getAll?.().catch(()=>({origins:[]}));
      const record=await readRecord(tabId);
      return {ok:true,checks:{serviceWorker:true,manifestVersion:chrome.runtime.getManifest?.().version||'test',
        origin,siteAccessGranted:granted,recording:!!current?.enabled,
        recordedRequests:record?.requests?.length||0,scannedFiles:record?.autoScanCoverage?.scanned||0,
        devtoolsAutoScanSeen:!!record?.autoScanCoverage,scanHealth:THIHealth.assess(record,current),
        grantedSiteCount:(permissions?.origins||[]).length,notificationsEnabled:(await chrome.storage.local.get('secretDesktopAlerts')).secretDesktopAlerts!==false}};
    }
    if(action==='GET_DISCOVERY_ALERTS'){
      const p=await chrome.storage.local.get('discoveryDesktopAlerts');return {ok:true,enabled:p.discoveryDesktopAlerts===true};
    }
    if(action==='SET_DISCOVERY_ALERTS'){
      if(!String(sender.url||'').startsWith(chrome.runtime.getURL('')))return {ok:false,error:'Extension UI only'};
      const enabled=msg.enabled===true;await chrome.storage.local.set({discoveryDesktopAlerts:enabled});return {ok:true,enabled};
    }
    if (action === 'TOGGLE_DOWNLOAD_OBSERVER') {
      if(!String(sender.url||'').startsWith(chrome.runtime.getURL('')))return {ok:false,error:'Extension UI only'};
      const state=await active(tabId);
      if(!state?.enabled)return {ok:false,error:'Start capture first'};
      if(!(await hasHostAccess(state.origin)))return {ok:false,error:'Site permission required'};
      const enabled=msg.enabled===true;
      await chrome.storage.session.set({[stateKey(tabId)]:{...state,downloadObserver:enabled}});
      if(enabled)await updateRecord(tabId,r=>{if(r.origin===state.origin)r.downloadObserverEverEnabled=true;});
      return {ok:true,enabled};
    }
    if (action === 'STOP_CAPTURE') return {ok:true,...(await stopCapture(tabId))};
    if (action === 'GET_SCAN_HEALTH'){
      const rec=await readRecord(tabId),state=await active(tabId);
      return {ok:true,health:THIHealth.assess(rec,state)};
    }
    if (action === 'RECOVER_CAPTURE') {
      if (!String(sender.url||'').startsWith(chrome.runtime.getURL('')))
        return {ok:false,error:'Extension interface only'};
      const state=await active(tabId);
      if(!state?.enabled)return {ok:false,error:'No active capture to recover'};
      const tab=await chrome.tabs.get(tabId);
      if(originOf(tab?.url)!==state.origin||!(await hasHostAccess(state.origin))){
        await stopCapture(tabId);
        return {ok:false,error:'Capture stopped: website changed or permission revoked'};
      }
      const inspectorReady=await scanTab(tabId);
      const record=await readRecord(tabId);
      await updateBadge(tabId,record,true);
      return {ok:inspectorReady,inspectorReady,health:THIHealth.assess(record,state),
        message:inspectorReady?'Content inspector responding; DevTools file scanning requires F12.':'Content inspector could not be reached'};
    }

    if (action === 'GET_STATE') return {ok:true, recording:await active(tabId), record:await readRecord(tabId)};
    if (action === 'LIST_SESSIONS') {
      await archiveLegacyRecords();
      return {ok:true,sessions:await THIVault.list()};
    }
    if (action === 'GET_SAVED_SESSION') {
      const record=await THIVault.get(msg.sessionId);
      return record?{ok:true,record}:{ok:false,error:'Saved session not found'};
    }
    if (action === 'COMPARE_SAVED_SESSIONS') {
      const a=await THIVault.get(msg.leftId),b=await THIVault.get(msg.rightId);
      if(!a||!b||a.sessionId===b.sessionId)return {ok:false,error:'Choose two different saved sessions'};
      return {ok:true,comparison:THIVault.compare(a,b)};
    }
    if (action === 'CROSS_ARCHIVE_EXPLORER') {
      const a=await THIVault.get(msg.leftId),b=await THIVault.get(msg.rightId);
      if(!a||!b||a.sessionId===b.sessionId)return {ok:false,error:'Select two distinct saved investigations'};
      return {ok:true,analysis:THICross.analyze(a,b)};
    }
    if(action==='CROSS_SITE_HOST_RELATIONS'){
      const ids=[msg.leftId,msg.rightId];
      if(!ids.every(x=>typeof x==='string'&&x.length>3&&x.length<150))return {ok:false,error:'Invalid saved session IDs'};
      const all=await THIVault.all();
      const first=all.find(r=>r.sessionId===ids[0]),second=all.find(r=>r.sessionId===ids[1]);
      if(!first||!second)return {ok:false,error:'Saved session not found'};
      const group=r=>r.captureGroupId||r.sessionId;
      if(group(first)===group(second))return {ok:false,error:'Choose different capture groups'};
      const gather=r=>{const result=all.filter(x=>group(x)===group(r));if(result.length>40)throw new Error('More than 40 capture segments: export groups separately');return result;};
      const a=THISiteRelations.snapshot(gather(first));
      const b=THISiteRelations.snapshot(gather(second));
      return {ok:true,analysis:THISiteRelations.compare(a,b)};
    }
    if (action === 'GET_CAPTURE_DIAGNOSTICS') {
      const record=await readRecord(tabId),state=await active(tabId);
      let bytes=null;
      try{if(chrome.storage.local.getBytesInUse)bytes=await chrome.storage.local.getBytesInUse(recordKey(tabId));}catch{}
      const diagnostics=THICross.diagnostics(record,state,bytes);
      let journal={mode:'unavailable'};
      try{journal=await THICaptureJournal.stats(tabId);}catch(error){noteStorageFailure(tabId,error);journal={mode:'error',message:'Capture journal unavailable; inspect extension errors'};}
      diagnostics.journal={...journal,storageError:liveStorageErrors.get(tabId)||null,
        unassignedSinceWorker:unassignedSinceWorker.get(tabId)||{total:0,priorNavigation:0,insufficientProvenance:0,originMismatch:0}};
      if(typeof navigator!=='undefined'&&navigator.storage?.estimate){
        try{const e=await navigator.storage.estimate();diagnostics.journal.browserStorageEstimate={usageBytes:Number(e.usage)||0,quotaBytes:Number(e.quota)||0};}
        catch{diagnostics.journal.browserStorageEstimate=null;}
      }
      return {ok:true,diagnostics};
    }
    if (action === 'DELETE_SAVED_SESSION') {
      const values=await chrome.storage.local.get(null);
      const legacy=[];
      for(const [key,rec] of Object.entries(values)) {
        if(!/^record:\d+$/.test(key)||rec?.sessionId!==msg.sessionId)continue;
        const recordTab=Number(key.split(':')[1]);
        if((await active(recordTab))?.enabled)throw new Error('Stop this capture before deleting its saved checkpoint.');
        legacy.push(key);
      }
      await THIVault.remove(msg.sessionId);
      for(const key of legacy){const id=Number(key.split(':')[1]);
        if(journalSupported())await THICaptureJournal.remove(id);
        liveCache.delete(id);liveStorageErrors.delete(id);
      }
      if(legacy.length)await chrome.storage.local.remove(legacy);
      return {ok:true};
    }
    if (action === 'IMPORT_SAVED_SESSION') {
      if (JSON.stringify(msg.payload||'').length>4500000)throw new Error('Import exceeds 4.5 MB metadata limit');
      const imported=THIVault.sanitizeImport(msg.payload,(value)=>THI.sanitizedUrl(value));
      await THIVault.save(imported);
      return {ok:true,session:THIVault.summary(imported)};
    }

    if(action==='GET_EXPOSURE_HISTORY'){
      if(!String(sender.url||'').startsWith(chrome.runtime.getURL('')))return {ok:false,error:'Extension UI only'};
      const live=await readRecord(tabId);
      const origin=live?.origin;
      if(!origin)return {ok:true,history:THIExposure.history([], '')};
      const records=(await THIVault.all()).filter(r=>r?.origin===origin);
      if(!records.some(r=>r.sessionId===live.sessionId))records.push(live);
      return {ok:true,history:THIExposure.history(records,origin)};
    }
    if(action==='LIST_CAPTURE_GROUPS'){
      await archiveLegacyRecords();
      return {ok:true,groups:THIPro.groupRows(await THIVault.list()).map(g=>({...g,segments:g.segments.map(x=>({id:x.id,segmentIndex:x.segmentIndex,startedAt:x.startedAt}))}))};
    }
    if(action==='SEARCH_ARCHIVED_FINDINGS'){
      const query=String(msg.query||'').trim();
      if(query.length<2||query.length>120)return {ok:false,error:'Enter 2-120 search characters'};
      const records=await THIVault.all();
      return {ok:true,...THIPro.search(records,query,300)};
    }
    if(action==='IMPORT_CAPTURE_GROUP'){
      // Verify checksum on original payload *before* any content is sanitised or saved.
      const raw=JSON.stringify(msg.payload||'');
      if(raw.length>16000000)throw new Error('Bundle exceeds the 16 MB local import limit. Split into smaller group backups.');
      const status=await THIPro.verify(msg.payload);
      const imported=msg.payload.records.map(r=>THIVault.sanitizeImport({format:'trufflehog-vault-session',version:1,record:r},value=>THI.sanitizedUrl(value)));
      const rebased=THIVault.newId(),ids=new Map();
      msg.payload.records.forEach((r,i)=>ids.set(r.sessionId,imported[i].sessionId));
      imported.forEach((r,i)=>{
        r.captureGroupId=rebased;r.segmentIndex=msg.payload.records[i].segmentIndex;
        r.previousSegmentId=ids.get(msg.payload.records[i].previousSegmentId)||null;
        r.groupImported=true;r.importIntegrityVerified=true;
      });
      await THIVault.saveMany(imported);
      return {ok:true,count:imported.length,group:rebased,missing:status.missing};
    }
    if(action==='GET_AUTO_SCAN_PERMISSION'){
      if(sender.url!==chrome.runtime.getURL('devtools.html'))return {ok:false};
      const state=await active(tabId);
      return {ok:true,enabled:!!state?.enabled&&!!state.autoSecretScan,startedAt:state?.startedAt||''};
    }
    if(action==='SET_FINDING_REVIEW'){
      const status=String(msg.status||'');
      if(!['new','reviewing','false-positive','resolved'].includes(status))return {ok:false,error:'Invalid review state'};
      const key=String(msg.findingKey||'');
      if(!key||key.length>500)return {ok:false,error:'Invalid finding reference'};
      let updated=false;
      const rec=await updateRecord(tabId,r=>{
        const finding=r.findings.find(f=>f._key===key);
        if(!finding)return;
        if(finding.reviewStatus!==status){
          finding.reviewHistory=(Array.isArray(finding.reviewHistory)?finding.reviewHistory:[]).slice(-11);
          finding.reviewHistory.push({from:finding.reviewStatus||'new',to:status,at:new Date().toISOString()});
          finding.reviewStatus=status;
        }
        updated=true;
        r.unreviewedAlerts=r.findings.filter(f=>THIAlerts.alertable(f.type)&&f.reviewStatus==='new').length;
      });
      if(rec)await updateBadge(tabId,rec,!!(await active(tabId))?.enabled);
      return {ok:updated};
    }
    if(action==='MARK_ALERTS_REVIEWED'){
      const rec=await updateRecord(tabId,r=>{
        for(const f of r.findings)if(THIAlerts.alertable(f.type)&&f.reviewStatus==='new'){
          f.reviewHistory=(Array.isArray(f.reviewHistory)?f.reviewHistory:[]).slice(-11);
          f.reviewHistory.push({from:'new',to:'reviewing',at:new Date().toISOString()});
          f.reviewStatus='reviewing';
        }
        r.unreviewedAlerts=0;
      });
      await updateBadge(tabId,rec,!!(await active(tabId))?.enabled);
      return {ok:true};
    }
    if(action==='SET_SECRET_NOTIFICATIONS'){
      await chrome.storage.local.set({secretDesktopAlerts:msg.enabled===true});
      return {ok:true,enabled:msg.enabled===true};
    }
    if(action==='SET_SECRET_CHANGE_NOTIFICATIONS'){
      if(!String(sender.url||'').startsWith(chrome.runtime.getURL('')))return {ok:false,error:'Extension UI only'};
      await chrome.storage.local.set({secretChangeDesktopAlerts:msg.enabled===true});
      return {ok:true,enabled:msg.enabled===true};
    }
    if(action==='GET_SECRET_CHANGE_NOTIFICATIONS'){
      const prefs=await chrome.storage.local.get('secretChangeDesktopAlerts');
      return {ok:true,enabled:prefs.secretChangeDesktopAlerts!==false};
    }
    if(action==='GET_SECRET_NOTIFICATIONS'){
      const prefs=await chrome.storage.local.get('secretDesktopAlerts');
      return {ok:true,enabled:prefs.secretDesktopAlerts!==false};
    }
    if(action==='GET_VIEWER_PERMISSION'){
      if(sender.url!==chrome.runtime.getURL('devtools.html'))return {ok:false};
      const state=await active(tabId);
      return {ok:true,enabled:!!state?.enabled&&!!state.viewerManifests};
    }
    if(action==='TOGGLE_VIEWER_MANIFESTS'){
      const state=await active(tabId);
      if(!state?.enabled)throw new Error('Start capture first.');
      const enabled=msg.enabled===true;
      await chrome.storage.session.set({[stateKey(tabId)]:{...state,viewerManifests:enabled}});
      return {ok:true,enabled};
    }
    if (action === 'GET_RESPONSE_PERMISSION') {
      if (sender.url !== chrome.runtime.getURL('devtools.html')) return {ok:false};
      const state = await active(tabId);
      return {ok:true, enabled:!!state?.enabled && !!state.responseShapes};
    }

    if(action==='GET_VISUAL_PERMISSION'){
      if(sender.url!==chrome.runtime.getURL('devtools.html'))return {ok:false};
      const state=await active(tabId);
      return {ok:true,enabled:!!state?.enabled&&!!state.verifyImages&&!!state.verifyVisual};
    }
    if(action==='TOGGLE_VISUAL_VERIFICATION'){
      const state=await active(tabId);
      if(!state?.enabled)throw new Error('Start capture first.');
      const enabled=msg.enabled===true;
      await chrome.storage.session.set({[stateKey(tabId)]:{...state,verifyVisual:enabled,verifyImages:enabled||state.verifyImages}});
      return {ok:true,enabled};
    }
    if(action==='GET_METADATA_PERMISSION'){
      if(sender.url!==chrome.runtime.getURL('devtools.html'))return {ok:false};
      const state=await active(tabId);
      return {ok:true,enabled:!!state?.enabled&&!!state.verifyImages&&!!state.verifyMetadata};
    }
    if(action==='TOGGLE_METADATA_VERIFICATION'){
      const state=await active(tabId);
      if(!state?.enabled)throw new Error('Start capture first.');
      const enabled=msg.enabled===true;
      await chrome.storage.session.set({[stateKey(tabId)]:{...state,verifyMetadata:enabled,verifyImages:enabled||state.verifyImages}});
      return {ok:true,enabled};
    }
    if(action==='GET_IMAGE_PERMISSION') {
      if(sender.url!==chrome.runtime.getURL('devtools.html'))return {ok:false};
      const state=await active(tabId);
      return {ok:true,enabled:!!state?.enabled&&!!state.verifyImages};
    }
    if(action==='TOGGLE_IMAGE_VERIFICATION') {
      const state=await active(tabId);
      if(!state?.enabled)throw new Error('Start capture first.');
      const verifyImages=msg.enabled===true;
      await chrome.storage.session.set({[stateKey(tabId)]:{...state,verifyImages,verifyMetadata:verifyImages?state.verifyMetadata:false,verifyVisual:verifyImages?state.verifyVisual:false}});
      return {ok:true,enabled:verifyImages};
    }
    if (action === 'TOGGLE_RESPONSE_SHAPES') {
      const state = await active(tabId);
      if (!state?.enabled) throw new Error('Start capture first.');
      const responseShapes = msg.enabled === true;
      await chrome.storage.session.set({[stateKey(tabId)]: {...state, responseShapes}});
      return {ok:true, enabled:responseShapes};
    }
    if (action === 'SCAN_NOW') return {ok:await scanTab(tabId)};
    if (action === 'ANALYZE_SCRIPTS') return {ok:true, ...(await analyzeScripts(tabId))};
    if (action === 'INSPECT_MAPS') return {ok:true,...(await inspectReferencedMaps(tabId))};
    if (action === 'CLEAR_RECORD') {
      const recording = await active(tabId);
      if (recording?.enabled) throw new Error('Stop recording before clearing it.');
      await queue(tabId,async()=>{
        if(journalSupported())await THICaptureJournal.remove(tabId);
        liveCache.delete(tabId);liveStorageErrors.delete(tabId);unassignedSinceWorker.delete(tabId);
        await chrome.storage.local.remove(recordKey(tabId));
      });
      await updateBadge(tabId, null, false);
      return {ok:true};
    }
    return {ok:false, error:'Unknown message type'};
  };
  dispatch().then(reply).catch(e => reply({ok:false, error:e.message || String(e)}));
  return true;
});

chrome.tabs.onUpdated.addListener((tabId, info) => {
  if (!info.url && info.status !== 'complete') return;
  void (async () => {
    // If the origin changes, begin a new independently archived capture.
    // The webRequest listener attempts this earlier, before first response.
    if(info.url&&originOf(info.url))await beginAutoCapture(tabId,info.url);
    if(info.status !== 'complete')return;
    const tab = await chrome.tabs.get(tabId);
    const origin=originOf(tab?.url);
    if(!origin)return;
    await beginAutoCapture(tabId,tab.url);
    const recording=await active(tabId);
    if(!recording?.enabled||recording.origin!==origin)return;
    if(!(await hasHostAccess(origin))){await stopCapture(tabId);return;}
    await scanTab(tabId);
  })().catch(e => console.warn('[Trufflehog] tab state:',e.message));
});
if(chrome.permissions?.onRemoved){
  chrome.permissions.onRemoved.addListener(() => {
    // Host access revoked externally or in the popup: stop recording for
    // affected sites even if their tabs remain open.
    void (async()=>{
      const sessions=await chrome.storage.session.get(null);
      for(const [key,state] of Object.entries(sessions)){
        const found=/^active:(\d+)$/.exec(key);
        if(!found || !state?.enabled)continue;
        if(!(await hasHostAccess(state.origin)))await stopCapture(Number(found[1]));
      }
    })().catch(e=>console.warn('[Trufflehog] permission removal:',e.message));
  });
}
chrome.tabs.onRemoved.addListener(tabId => {autoStarts.delete(tabId);tabNavigationEpoch.delete(tabId);unassignedSinceWorker.delete(tabId);liveCache.delete(tabId);liveStorageErrors.delete(tabId);for(const [id,started] of pendingHttpStarts)if(started.tabId===tabId)pendingHttpStarts.delete(id);void (async()=>{try{await archiveRecord(tabId,true);}catch(e){console.warn('[Trufflehog] archive on tab close failed',e.message);}finally{await chrome.storage.session.remove(stateKey(tabId));}})();});
// Existing records and user-modified preferences are kept on upgrade.
// Chrome separately asks for approval when the required all-sites permission grows.
chrome.runtime.onInstalled.addListener(details => {
  void (async()=>{
    const prefs=await chrome.storage.local.get(['autoCaptureEnabled','discoveryDesktopAlerts','secretDesktopAlerts','secretChangeDesktopAlerts']);
    const defaults={};
    for(const key of ['autoCaptureEnabled','discoveryDesktopAlerts','secretDesktopAlerts','secretChangeDesktopAlerts'])
      if(typeof prefs[key]!=='boolean')defaults[key]=true;
    if(Object.keys(defaults).length)await chrome.storage.local.set(defaults);
    // Upgrade in-progress captures once. User switches remain freely adjustable
    // afterwards; ordinary reloads do not silently override manual choices.
    if(details?.reason==='update'){
      const sessions=await chrome.storage.session.get(null);
      for(const [key,state] of Object.entries(sessions)){
        if(/^active:\d+$/.test(key)&&state?.enabled){
          await chrome.storage.session.set({[key]:{...state,...allActiveOptions()}});
        }
      }
    }
    await chrome.storage.local.set({installationVersion:'7.19.0'});
    if(chrome.tabs?.query){
      const tabs=await chrome.tabs.query({});
      for(const tab of tabs.slice(0,100))if(originOf(tab?.url)){
        await beginAutoCapture(tab.id,tab.url);
        if((await active(tab.id))?.enabled)await scanTab(tab.id);
      }
    }
  })().catch(e=>console.warn('[Trufflehog] initial auto capture:',e.message));
});
if(chrome.runtime.onStartup?.addListener)chrome.runtime.onStartup.addListener(()=>{
  void (async()=>{
    if(!(await autoCaptureEnabled())||!chrome.tabs?.query)return;
    const tabs=await chrome.tabs.query({});
    for(const tab of tabs.slice(0,100))if(originOf(tab?.url)){
      await beginAutoCapture(tab.id,tab.url);
      if((await active(tab.id))?.enabled)await scanTab(tab.id);
    }
  })().catch(e=>console.warn('[Trufflehog] startup auto capture:',e.message));
});

// Keep the local HMAC key and evidence out of content-script storage access.
if(chrome.storage.local?.setAccessLevel)void chrome.storage.local.setAccessLevel({accessLevel:'TRUSTED_CONTEXTS'}).catch(()=>{});
