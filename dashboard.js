'use strict';
const $ = id => document.getElementById(id);
const tabId = Number(new URL(location.href).searchParams.get('tabId'));
let view = 'overview';
let record = null;
let recording = null;
let busy = false;
let archivedId=null, sessionsCache=[], comparison=null,comparisonIds=null,lastVaultRefresh=0;
let caseDossier=null, caseSelectedGroup=null;
let caseChangeReport=null, caseChangeSelection=null;
let policyDriftReport=null, policyDriftSelection=null;
let readinessReport=null, readinessSelection=null, readinessContext=null;
let workflowPatternReport=null, workflowPatternSelection=null;
let harCoverageReport=null,harCoverageSelected=null,harTriageReport=null,harPrivacyReport=null,harDAMReport=null,harSequenceReport=null,harStageCompareReport=null;
let evidenceSynthesisReport=null,evidenceSynthesisSelection=null,evidenceSynthesisContext=null;
let crossAnalysis=null, crossSelection=null, diagnosticData=null;
let acceptanceReport=null;
let archiveSearchResult=null, replayResult=null, replayGroup=null;
let jsBaseline=null,jsComparison=null;
let apiSchemaBaseline=null,apiSchemaComparison=null;
let exposureHistoryResult=null,changeNotificationsEnabled=true;
let damHistoryResult=null,damHistorySelection=null;
let discoveryResult=null,discoverySelection=null,discoveryAlertsEnabled=false;
let customProfiles=[],editProfileId=null,activeWorkspace='overview';
const names = {'har-coverage':'Independent HAR coverage','evidence-synthesis':'Evidence-weighted DAM review','workflow-pattern':'Observed workflow patterns','compare-readiness':'Comparison readiness','policy-drift':'DAM policy comparison','capture-repair':'Capture repair guide','local-benchmark':'Local capture benchmark','case-compare':'Case change review','case-dossier':'Investigation dossier','dam-specialists':'DAM specialist profiles','upload-protocols':'Multipart & resumable upload observations','api-schema-diff':'API schema-change comparison','quality-ledger':'Verified asset rendition quality','quality-transfers':'Download and byte-range integrity','workflow-chains':'Download workflow reconstruction','workflow-coverage':'Workflow capture coverage','aws-dam':'AWS DAM ingestion and workflow clues','download-traces':'Authenticated download telemetry',acceptance:'Capture acceptance','frames-workers':'Frames & workers','site-relations':'Cross-site host roles','exposure-history':'Exposure history', 'discovery-pulse':'Discovery pulse', 'capture-audit':'Evidence quality audit','exposure-history':'Masked exposure history', 'dam-review-matrix':'DAM security review matrix','dam-risk':'DAM risk intelligence','dam-access':'DAM access states','cdn-policy':'CDN delivery policies','integration-boundaries':'Integration boundaries','dam-history':'DAM change history', 'profile-editor':'Custom DAM detection profiles',explorer:'Cross-archive explorer',diagnostics:'Capture diagnostics',vault:'Evidence vault', 'vault-search':'Archived findings search',visual:'Visual candidates','meta-rel':'Metadata relationships','variant-matrix':'CDN variant matrix', 'dam-security':'DAM security review', replay:'Offline timeline replay',gallery:'Gallery activity',collections:'Collections & duplicates',overview:'Overview',platforms:'DAM / CMS recognition',lineage:'Asset lineage',delivery:'Delivery pipelines',viewers:'Specialist viewers', 'viewer-manifests':'Tile manifests',network:'Network requests',api:'API endpoints',images:'Image provenance',variants:'Variant families',matches:'Cross-CDN matches',visual:'Visual similarity & crop candidates','meta-rel':'Shared embedded metadata fingerprints','variant-matrix':'Verified CDN delivery variant matrix',responses:'JSON shapes',coverage:'Pagination coverage',status:'Status & confidence',secrets:'Masked indicators', 'resource-scans':'Auto-scanned files','js-history':'JavaScript change history','profile-editor':'Custom DAM profiles','search-intel':'Search & interactions',infra:'Infrastructure',maps:'Source maps',graphql:'GraphQL operations',config:'Public configuration',graph:'Relationship graph'};
const send = async type => chrome.runtime.sendMessage({type, tabId});
names['generic-intelligence']='Universal traffic anatomy';
names['generic-sequence']='Traffic transitions & lifecycles';
names['generic-relationships']='Relationship evidence confidence';
names['universal-boundaries']='Universal delivery boundary review';
names['asset-licensing']='Asset Licensing & Delivery Intelligence';
names['product-assets']='Product & Asset Relationships';
names['hybrid-workflow']='Hybrid CMS/API/Delivery Stages';
names['import-preflight']='Local import privacy preflight';
names['security-intelligence']='Security Intelligence';
const elem = (tag, cls='', text='') => {const e=document.createElement(tag);e.className=cls;e.textContent=text === null ? '' : String(text);return e;};
const fmt = n => (n || 0).toLocaleString();
function notice(text, isError=false) { $('message').textContent = text; $('message').style.color=isError?'#ffafbf':'#91cdbd'; }
function stripInternal(x) {return Array.isArray(x) ? x.map(stripInternal) : x && typeof x === 'object' ? Object.fromEntries(Object.entries(x).filter(([k])=>k!=='_key').map(([k,v])=>[k,stripInternal(v)])) : x;}
function fileName() {let host = record?.origin || 'empty';try {host = new URL(host).hostname;}catch{} return 'trufflehog-' + host.replace(/[^a-z0-9.-]/ig,'_') + '-' + new Date().toISOString().slice(0,10);}
function download(name, data, type) {
  const blob = new Blob([data], {type});const uri = URL.createObjectURL(blob);
  const a = document.createElement('a');a.href=uri;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(uri),5000);
}
function csvValue(value) {
  const str = value === null || value === undefined ? '' : typeof value === 'object' ? JSON.stringify(value) : String(value);
  const injectionSafe = /^[\s]*[=+@-]/.test(str) ? "'" + str : str;
  return '"' + injectionSafe.replaceAll('"','""') + '"';
}
function currentCSV() {
  const fields = {
    'generic-intelligence':['category','count','evidence','meaning','qualification'],
    'generic-sequence':['transition','count','evidence','qualification'],
    'generic-relationships':['grade','signal','count','evidence','scope'],
    'universal-boundaries':['category','count','evidence','qualification'],
    'asset-licensing':['category','count','basis','confidence'],
    'product-assets':['productRef','variants','assets','channels','locales','confidence','delivery'],
    'security-intelligence':['at','ruleId','title','severity','confidence','host','route','method','classification','declaration','scope','markers','occurrences'],
    'hybrid-workflow':['name','count','quality','interpretation'],
    'har-coverage':['category','harObserved','captureObserved','harOnly','captureOnly'],
    'evidence-synthesis':['indicator','earlierPerThousand','laterPerThousand','differencePerThousand','earlierSample','laterSample','interpretation','ownerAction'],
    'workflow-pattern':['category','baseline','comparison','baselinePercent','comparisonPercent','differencePoints'],
    'compare-readiness':['category','status','assessment','source'],
    'policy-drift':['category','denominator','earlierCount','laterCount','earlierSample','laterSample','earlierPerThousand','laterPerThousand','assessment','evidenceQuality','qualification'],
    'case-compare':['category','label','earlier','later','delta','observation','qualification'],
    'case-dossier':['category','status','statement','count','qualification'],
    'dam-specialists':['vendor','kind','confidence','role','signalCount','observedRequests','networkEvidence','evidence','access','ownerReview','qualifier'],
    'upload-protocols':['reference','at','host','provider','method','phase','status','stages','markers','outcome'],
    'api-schema-diff':['endpoint','host','method','category','baselineFields','currentFields','added','removed','typeChanges','status','qualification'],
    'quality-ledger':['familyRef','host','observedVariants','verifiedFiles','highestVerifiedPixels','largestVerifiedBytes','verifiedPixelRatio','browserOnlySizes','biggestBrowserReported','formats','strongestEvidence','assessment'],
    'quality-transfers':['stage','metric','count','assessment'],
    'download-traces':['at','method','host','status','auth','body','fields','signature','redirect','file','trace','cdn','cache','bytes','error','evidence'],
    'aws-dam':['at','host','method','service','kind','signing','fields','signedQuery','status','evidence','policy'],
    'frames-workers':['kind','origin','relationship','sandboxed','evidence','sightings','status','scriptReferences','inlineScripts','maskedIndicators','inspected'],
    'site-relations':['host','firstRoles','secondRoles','sharedRoles','firstRequests','secondRequests','assessment','confidence'],
    explorer:['kind','grade','identity','leftEvidence','rightEvidence','meaning'],
    diagnostics:['field','observed','limit','dropped'],
    'capture-audit':['id','status','detail'],
    'discovery-pulse':['kind','identity','role','status','previous','current','confidence'],
    vault: ['id','origin','captureGroupId','segmentIndex','startedAt','endedAt','requests','images','findings','verified','apiRoutes','assetIds'],
    'exposure-history':['at','type','source','line','column','changeState','reviewStatus','reviewEvents','sessionId','segmentIndex'],
    'vault-search':['origin','segmentIndex','type','source','masked','reviewStatus','severity','at'],
    replay:['at','kind','detail','segmentIndex'],
    overview: ['origin','requests','routes','assets','findings'],
    network: ['at','method','status','type','url','host','initiatorOrigin','document','frameId','mime','bytes','etag','modified','signedQuery','error'],
    api: ['url','host','kind','method','status','observed','source'],
    responses: ['at','method','status','url','mime','fieldCount','fields','pagination','confidence'],
    coverage: ['scope','source','pagesSeen','knownTotal','missing','totalResults','assessment'],
    gallery: ['scope','observations','observedPages','cursorTransitions','scrollBuckets','highestCards','highestImages','growthEvents','bottomObservations','loadingControls','assessment'],
    collections:['collection','distinctAssets','sightings','repeatedSightings','pages','lastObserved'],
    status: ['category','count','example','assessment'],
    images: ['url','host','metadata','width','height','encodedWidth','encodedHeight','evidence','sha256','encodedBytes','descriptor','source','mime','bytes','etag','signedQuery'],
    variants: ['family','host','variantCount','verifiedCount','largest','largestEvidence','largestUrl','formats','urls'],
    matches: ['kind','confidence','identity','hosts','count','urls'],
    visual:['kind','distance','confidence','left','right','details'],
    'meta-rel':['kind','fingerprint','images','urls','assessment'],
    'variant-matrix':['family','observed','verified','visual','formats','resolutionRange','aspectRatios','cropClue','urls'],
    secrets: ['type','masked','severity','reviewStatus','changeState','reviewHistory','note','source','at','offset','line','column','knownPrevious'],
    'resource-scans':['at','url','host','kind','byteCount','indicatorCount','sha256'],
    'js-history':['url','status','previousHash','currentHash','previousBytes','currentBytes','at'],
    'search-intel':['at','category','kind','url','provider','evidence','nearInteraction'],
    infra: ['host','category','requests','assets','scripts','routes'],
    maps:['url','script','source','status','sourceCount','sourceTypes','packageNames','hasEmbeddedSources'],
    graphql:['operationType','name','source','confidence'], config:['key','framework','source','value'],
    graph:['from','to','relation','evidence'],
    platforms:['name','layer','confidence','score','independentSignals','assessment','evidence'],
    'dam-history':['kind','identity','layer','status','firstSightings','secondSightings','evidence'],
    'profile-editor':['name','layer','domains','prefixes','matched','assessment'],
    'dam-security':['level','kind','title','evidence','explanation','next','confidence'],
    'dam-review-matrix':['scope','scopeKind','category','observation','assessment','count','evidence','qualification','ownerAction','limit'],
    'dam-risk':['severity','category','title','observations','meaning','ownerAction','evidence'],
    'dam-access':['host','representation','status','signed','attachment','observations','confidence','ownerReview'],
    'cdn-policy':['host','representation','status','cachePolicy','signed','observations','ownerReview'],
    'integration-boundaries':['from','to','role','observedRequests','denied','evidence','limitation'],
    lineage:['assetId','otherIds','confidence','images','verified','largestObserved','largestEvidence','hosts','galleryPages','detailPages','observedApiRoutes','responseShapes','exactBytes','evidence','imageUrls'],
    viewers:['format','family','observedRequests','observedTiles','observedLevels','declaredDimensions','tileSize','declaredLevels','statuses','evidence'],
    'viewer-manifests':['format','url','family','width','height','tileWidth','tileHeight','levels','scaleFactors','itemCount','source'],
    delivery:['host','observedImages','verifiedResponses','transformationKeys','pathHints','imageTypes','signedRequests','largestVerified','assessment']
  };
  const headings = fields[view];
  const rows = view==='har-coverage' ? (harCoverageReport?.rows||[]) : view==='evidence-synthesis' ? (evidenceSynthesisReport?.rows||[]) : view==='workflow-pattern' ? (workflowPatternReport?.rows||[]) : view==='compare-readiness' ? (readinessReport?.context||[]) : view==='policy-drift' ? (policyDriftReport?.rows||[]) : view==='dam-review-matrix' ? THIDAMReview.evaluate(record).rows : view==='case-dossier' ? (caseDossier?.evidence||[]) : view==='upload-protocols' ? THIUploadAPI.rows(record) : view==='api-schema-diff' ? (apiSchemaComparison?.rows||[]) : view==='quality-transfers' ? qualityTransferRows() : view==='frames-workers' ? [...THIContexts.analyze(record).rows,...(record?.frameCoverage||[]).map(f=>({...f,kind:'frame-coverage',relationship:f.status==='inspected'?'same-origin':'unverified'})),...(record?.workerScripts||[]).map(f=>({...f,kind:'service-worker-script-reference',evidence:'controller reference; script body not inspected'}))] : view==='site-relations' ? (siteRelationAnalysis?.rows||[]) : view==='exposure-history' ? exposureHistoryResult?.rows||[] : view==='discovery-pulse' ? discoveryResult?.rows||[] : view==='js-history' ? jsComparison?.rows||[] : view === 'vault' ? sessionsCache : view === 'vault-search' ? archiveSearchResult?.rows||[] : view==='replay' ? replayResult?.rows||[] : view === 'explorer' ? crossRows() : view === 'diagnostics' ? diagnosticRows() : view === 'overview' ? [{origin:record?.origin || '',requests:record?.requests.length || 0,
    routes:record?.routes.length || 0,assets:record?.assets.length || 0,findings:record?.findings.length || 0}] : dataset();
  return [headings.map(csvValue).join(','),...rows.map(row=>headings.map(h=>csvValue(row[h])).join(','))].join('\r\n');
}
function qualityTransferRows(){const t=THIQuality.analyze(record).transfers;return [
  {stage:'Browser downloads',metric:'Started',count:t.starts,assessment:'Referrer correlation only'},
  {stage:'Browser downloads',metric:'Completed',count:t.complete,assessment:'No file/image identity match asserted'},
  {stage:'Browser downloads',metric:'Interrupted',count:t.interrupted,assessment:'Some failures may be unobserved'},
  {stage:'HTTP range evidence',metric:'Range requested',count:t.rangeRequests,assessment:'Range header presence; opt-in observer'},
  {stage:'HTTP range evidence',metric:'HTTP 206',count:t.partialResponses,assessment:'Partial response observed'},
  {stage:'HTTP range evidence',metric:'Valid Content-Range',count:t.measuredRanges,assessment:'Numeric range metadata only'},
  ...t.completedMimeTypes.map(x=>({stage:'Completed MIME',metric:x.kind,count:x.count,assessment:'Browser download classification'})),
  ...t.failureClasses.map(x=>({stage:'Failures',metric:x.kind,count:x.count,assessment:'Coarse browser error category'}))
 ];}
function crossRows(){return (crossAnalysis?.matches||[]).map(x=>({...x,leftEvidence:x.leftEvidence.join(' · '),rightEvidence:x.rightEvidence.join(' · ')}));}
function diagnosticRows(){return Object.entries(diagnosticData?.limits||{}).map(([field,r])=>({field,...r}));}
function technologyRows() {return THIDAM.analyze(record).profiles.map(p=>({...p,evidence:p.evidence.map(e=>`${e.kind}: ${e.detail} [${e.source}]`).join('; ')}));}
function customRows(){return THICustomProfiles.inspect(customProfiles,record).map(p=>({...p,domains:customProfiles.find(x=>x.id===p.id)?.domains.join(', '),prefixes:customProfiles.find(x=>x.id===p.id)?.prefixes.join(', '),matched:p.count}));}
function imageRows() {
 const images=THIImages.rows(record?.assets||[],record?.verifications||[]);
 const byUrl=new Map((record?.verifications||[]).map(v=>[v.url,v.metadata||[]]));
 return images.map(i=>({...i,metadata:(byUrl.get(i.url)||[]).map(m=>m.kind+': '+m.sha256.slice(0,16)+'…').join(' · ')}));
}
function variantRows() {return THIImages.variants(imageRows());}
function matchRows() {return THIImages.matches(imageRows());}
function lineageRows(){return THILineage.analyze(record).rows.map(r=>({...r,hosts:r.hosts.join(' · '),galleryPages:r.galleryPages.join(' · '),detailPages:r.detailPages.join(' · '),observedApiRoutes:r.observedApiRoutes.join(' · '),evidence:r.evidence.join(' · '),imageUrls:r.imageUrls.join(' · ')}));}
function deliveryRows(){return THILineage.pipeline(record);}
function viewerRows(){return THIViewer.summarize(record).rows;}
function manifestRows(){return [...(record?.viewerManifests||[])].reverse();}
function hostRows() {
  const map=new Map();
  const observe=(host,kind) => {
    if (!host) return;
    if (!map.has(host)) map.set(host,{host,category:category(host),requests:0,assets:0,scripts:0,routes:0});
    map.get(host)[kind]++;
  };
  for (const r of record?.requests || []) observe(r.host,'requests');
  for (const a of imageRows()) observe(a.host,'assets');
  for (const s of record?.scripts || []) observe(s.host,'scripts');
  for (const route of record?.routes || []) observe(route.host,'routes');
  return [...map.values()].sort((a,b)=>b.requests+b.assets+b.scripts+b.routes-(a.requests+a.assets+a.scripts+a.routes));
}
function category(host) {
  if (/cloudfront\.net$/i.test(host))return 'AWS CloudFront';
  if (/amazonaws\.com$/i.test(host))return 'AWS service';
  if (/\.imgix\.net$/i.test(host))return 'Imgix';
  if (/cloudinary\.com$/i.test(host))return 'Cloudinary';
  if (/\.akamai(?:hd)?\.net$/i.test(host))return 'Akamai';
  if (/cloudflare/i.test(host))return 'Cloudflare';
  return 'Observed host';
}
function responseRows() {
  return (record?.responses || []).map(r => ({...r,fieldCount:r.fields?.length||0,
    fields:(r.fields||[]).map(f => `${f.path}: ${f.type}`).join('; '),
    pagination: Object.entries(r.pagination||{}).map(([k,v])=>`${k}=${v}`).join(', ') || '—'})).reverse();
}
function galleryRows(){return THIGallery.analyze(record).sessions;}
function collectionsRows(){return THIGallery.analyze(record).collections;}
function coverageRows() {
  const groups = new Map();
  for (const p of record?.pagination || []) {
    // Different observed pathways may have independent pagination systems.
    const scope = p.scope || '(unknown)', source = p.source || 'unclassified';
    const key = `${source}|${scope}`;
    if (!groups.has(key)) groups.set(key,{scope,source,pages:new Set(),totals:new Set(),results:new Set()});
    const g=groups.get(key);
    if (p.page) g.pages.add(p.page);
    if (p.totalPages) g.totals.add(p.totalPages);
    if (p.totalResults) g.results.add(p.totalResults);
  }
  return [...groups.values()].map(g=>{
    const pages=[...g.pages].sort((a,b)=>a-b), totals=[...g.totals];
    const total=totals.length === 1 ? totals[0] : null;
    const missing=total && total<=500 ? Array.from({length:total},(_,i)=>i+1).filter(n=>!g.pages.has(n)) : [];
    const assessment= totals.length > 1 ? 'Conflicting totals' : !total ? 'Total not established' :
      pages.length === total && !missing.length ? 'Numbered pages seen (not verified complete)' : 'Gaps in observed page numbers';
    return {scope:g.scope,source:g.source,pagesSeen:pages.join(', ')||'—',knownTotal: total ?? '—',
      missing:total>500?'Not calculated (>500)':missing.slice(0,70).join(', ')||'None within 1…N',
      totalResults:[...g.results].join(', ')||'—',assessment};
  });
}
function statusRows() {
  const groups = new Map();
  function label(r) {
    if (r.error) return 'Transport error';
    if (r.status>=200 && r.status<300) return '2xx Successful';
    if (r.status>=300 && r.status<400) return '3xx Redirect';
    if ([401,403].includes(r.status))return '401/403 Access restricted';
    if (r.status===429)return '429 Rate limited';
    if (r.status>=400 && r.status<500)return '4xx Other client error';
    if (r.status>=500)return '5xx Server error';
    return 'No HTTP status';
  }
  for (const r of record?.requests||[]) {
    const category=label(r);
    if (!groups.has(category)) groups.set(category,{category,count:0,example:r.url||'',assessment:''});
    groups.get(category).count++;
  }
  const explanations={
    '2xx Successful':'Response received; not proof of accessible original assets',
    '3xx Redirect':'Chrome may not expose every redirect step',
    '401/403 Access restricted':'Do not bypass authentication or access controls',
    '429 Rate limited':'Respect site limits; no automatic retries',
    '4xx Other client error':'A request was not fulfilled',
    '5xx Server error':'Server-side failure reported',
    'Transport error':'Browser reported a network failure',
    'No HTTP status':'Completion status unavailable'};
  for(const v of groups.values()) v.assessment=explanations[v.category]||'';
  return [...groups.values()].sort((a,b)=>b.count-a.count);
}
function mapRows(){return (record?.maps||[]).map(m=>({...m,sourceCount:m.summary?.sourceCount??'—',sourceTypes:Object.entries(m.summary?.sourceTypes||{}).map(([k,v])=>`${k}: ${v}`).join(', '),packageNames:(m.summary?.packageNames||[]).join(', '),hasEmbeddedSources:m.summary?.hasEmbeddedSources?'Yes (discarded)':'No / unknown'}));}
function dataset(){
  if (!record)return [];
  switch(view){
    case 'generic-intelligence':return THIGenericIntelligence.analyze(record).rows;
    case 'generic-sequence':return THIGenericSequence.analyze(record).transitions;
    case 'security-intelligence':return [...(record.securityObservations||[])].reverse();
    case 'generic-relationships':return THIGenericRelationshipConfidence.analyze(record).rows;
    case 'universal-boundaries':return THIUniversalBoundaryReview.analyze(record).rows;
    case 'asset-licensing':return THIAssetLicensing.analyze(record).rows;
    case 'product-assets':return THIProductAsset.analyze(record).rows;
    case 'hybrid-workflow':return THIHybridWorkflow.analyze(record).rows;
    case 'case-compare':return caseChangeReport?.metrics||[];
    case 'case-dossier':return caseDossier?.evidence||[];
    case 'dam-history':return damHistoryResult?.rows||[];
    case 'vault':return sessionsCache;
    case 'vault-search':return archiveSearchResult?.rows||[];
    case 'replay':return replayResult?.rows||[];
    case 'explorer':return crossRows();
    case 'diagnostics':return diagnosticRows();
    case 'acceptance':return acceptanceReport?.checks||[];
    case 'discovery-pulse':return discoveryResult?.rows||[];
    case 'capture-audit':return THICaptureAudit.assess(record,recording,sessionsCache).checks;
    case 'platforms':return technologyRows();
    case 'dam-specialists':return THIDAMSpecialists.analyze(record).profiles;
    case 'profile-editor':return customRows();
    case 'dam-security':return THIDAMSecurity.analyze(record,THIDAM.analyze(record)).findings;
    case 'dam-review-matrix':return THIDAMReview.evaluate(record).rows;
    case 'dam-risk':return THIDAMRisk.analyze(record,THIDAM.analyze(record)).findings;
    case 'dam-access':return THIDeliveryPolicy.analyze(record).rows;
    case 'cdn-policy':return THIDeliveryPolicy.analyze(record).rows;
    case 'integration-boundaries':return THIDAMRisk.analyze(record,THIDAM.analyze(record)).connections;
    case 'lineage':return lineageRows();
    case 'delivery':return deliveryRows();
    case 'viewers':return viewerRows();
    case 'viewer-manifests':return manifestRows();
    case 'upload-protocols':return THIUploadAPI.rows(record);
    case 'api-schema-diff':return apiSchemaComparison?.rows||[];
    case 'quality-ledger':return THIQuality.analyze(record).families;
    case 'quality-transfers':return qualityTransferRows();
    case 'workflow-chains':return THIWorkflow.analyse(record).workflows;
    case 'workflow-coverage':return THIWorkflow.coverage(record,recording).checks;
    case 'download-traces':return THIDownload.summaries(record.downloadEvents||[]);
    case 'aws-dam':return THIAwsDam.rows(record);
    case 'network':return [...record.requests].reverse();
    case 'api':return [...record.routes].sort((a,b)=>Number(b.observed)-Number(a.observed));
    case 'images':return imageRows();
    case 'variants':return variantRows();
    case 'matches':return matchRows();
    case 'visual':return THIVisual.within(record);
    case 'meta-rel':return THIVisual.metadataGroups(record);
    case 'variant-matrix':return THIVisual.matrix(imageRows());
    case 'responses':return responseRows();
    case 'coverage':return coverageRows();
    case 'gallery':return galleryRows();
    case 'collections':return collectionsRows();
    case 'status':return statusRows();
    case 'secrets':return [...record.findings].reverse();
    case 'resource-scans':return [...(record.resourceScans||[])].reverse();
    case 'js-history':return jsComparison?.rows||[];
    case 'search-intel':return [
      ...(record.interactions||[]).map(x=>({at:x.at,category:'User interaction',kind:x.kind,url:'',provider:'',evidence:'Coarse action only; no form values',nearInteraction:''})),
      ...(record.requests||[]).filter(x=>x.searchProvider||x.nearInteraction).map(x=>({at:x.at,category:'Observed request',kind:x.type,url:x.url,provider:x.searchProvider||'',evidence:x.searchEvidence||'',nearInteraction:x.nearInteraction||''}))
    ].sort((a,b)=>b.at.localeCompare(a.at));
    case 'infra':return hostRows();
    case 'maps':return mapRows();
    case 'graphql':return record.operations||[];
    case 'config':return record.configs||[];
    case 'graph':return THIGraph.edges(record);
    default:return [];
  }
}
function matches(data) {
  const query=$('search').value.trim().toLowerCase();
  return query ? data.filter(x=>Object.values(x).some(v=>String(v??'').toLowerCase().includes(query))) : data;
}
function td(tr,value,css='') {
  tr.appendChild(elem('td',css,value));
}
function tag(value,type='') {
  const s=elem('span','tag '+type,value); return s;
}
function buildTable(columns, rows) {
  const wrapper=elem('div','table-wrap'),table=elem('table','data-table');
  const thead=document.createElement('thead'),head=document.createElement('tr');
  for (const c of columns) head.appendChild(elem('th','',c.label));
  thead.appendChild(head);table.appendChild(thead);
  const body=document.createElement('tbody');
  for (const row of rows.slice(0,900)) {
    const tr=document.createElement('tr');
    for (const c of columns) {
      const cell=elem('td',c.css||'',c.format ? c.format(row[c.key],row) : row[c.key] ?? '—');
      if (c.title) cell.title=String(row[c.title] || '');
      if (c.badge) {
        cell.textContent='';cell.appendChild(tag(c.format ? c.format(row[c.key],row) : row[c.key]??'—',c.badge(row[c.key],row)));
      }
      tr.appendChild(cell);
    }
    body.appendChild(tr);
  }
  table.appendChild(body);wrapper.appendChild(table);return wrapper;
}
function panel(title,body,extra='') {
  const box=elem('div','mini-panel');box.appendChild(elem('h3','',title));
  box.appendChild(elem('p','',body));if (extra) box.appendChild(elem('p','',extra));return box;
}
function overview(container) {
  const coverageState=typeof THIHealth!=='undefined'?THIHealth.assess(record,recording):null;
  if(coverageState){const summary=elem('div','simple-grid');summary.appendChild(panel('Loaded-file coverage',coverageState.title,coverageState.detail));summary.appendChild(panel('Observed files',String(coverageState.scanned)+' of '+coverageState.eligible+' eligible','Excluded: '+coverageState.excluded+' · Unaccounted: '+coverageState.unaccounted));summary.appendChild(panel('Unreviewed security alerts',String(record?.unreviewedAlerts||0),'Masked evidence only; absence does not indicate a secure site.'));container.appendChild(summary);}

  if (!record) {empty(container,'No capture yet','Open your target website, click the extension and start a capture.');return;}
  const wrap=elem('div','simple-grid');
  wrap.appendChild(panel('Generic traffic anatomy','Classify observed APIs, media, authentication indicators, redirects, downloads and coverage without identifying the website vendor.','No additional requests or permissions. Fixed-label, aggregate evidence only.'));
  wrap.appendChild(panel('Relationship evidence confidence','Separate exact browser stages, shared page/frame context and timing-only clues without assuming causality.','Private grouping keys never leave the report.'));
  wrap.appendChild(panel('Traffic transitions & lifecycles','Summarise how recorded HTTP response types followed one another and which opt-in browser request/download stages actually paired.','Timeline adjacency does not establish a workflow or causal connection.'));
  wrap.appendChild(panel('0 · DAM / CMS recognition','Identify known DAM, CMS, image delivery and viewer technologies from observed hostnames, DOM elements and optional public script signals.','Capture and other vendor signals are evidence of use, not proof that the gallery uses that vendor as its backend.'));
  wrap.appendChild(panel('0.5 · Asset lineage and delivery','Correlate image cards, explicit asset IDs, CDN variants, hashes and observed API path identifiers.','Associations are clearly graded; no original-file access or ownership is inferred.'));
  wrap.appendChild(panel('1 · Page inventory','Images, scripts and embedded public configuration already present in the page DOM.','Use “Refresh page inventory” after dynamic content finishes loading.'));
  wrap.appendChild(panel('2 · Observed network','HTTP(S) requests made normally by the selected website tab.','You can browse, scroll, search or paginate; the inspector does not initiate these actions.'));
  wrap.appendChild(panel('3 · Image provenance','Cross-reference page image natural sizes, srcset variants, observed image responses and ETag/Last-Modified where available.','Network image response headers are recorded only when exposed by Chrome.'));
  wrap.appendChild(panel('4 · Public JavaScript','Optionally re-fetch up to 12 already-linked public JavaScript files without session credentials.','No endpoint enumeration, credential checking or probing.'));
  wrap.appendChild(panel('5 · JSON response structures','Opt in to capture public JSON field names/types and pagination counters from DevTools-visible traffic.','Open Chrome DevTools on the original tab, enable JSON shapes here, and reload the site. No response bodies saved.'));
  wrap.appendChild(panel('6 · Image fingerprint verification','Optionally examine already-received image bytes in DevTools (max 4 MiB per response), recording exact SHA-256 and format-specific encoded dimensions.','No image contents or response bodies saved. Exact hashes identify identical bytes; filename matches remain unverified clues.'));
  wrap.appendChild(panel('8 · Deep application intelligence','Discover named GraphQL operations, public configuration keys and public source-map references, then map evidence in Relationship graph.','References are not probed automatically; Inspect referenced maps is an explicit, credential-free action.'));
  wrap.appendChild(panel('6.5 · Gallery Coverage Intelligence','Track DOM card growth, scroll buckets, cursor-step changes and collection-level asset sightings.', 'Capture records page observations, not search strings, cursor values or guaranteed complete results.'));
  wrap.appendChild(panel('7 · Coverage & status','Review observed page numbers, pagination hints and HTTP outcomes.','Pagination coverage is not proof of an exhaustive search when filters or query scopes vary.'));
  container.appendChild(wrap);
  const hosts=hostRows().slice(0,9);
  if (hosts.length) {
    container.appendChild(elem('h2','', 'Connected host map'));
    for (const h of hosts) {
      const line=elem('div','hostbar');line.appendChild(elem('div','host mono',h.host));
      line.appendChild(elem('small','',h.category));line.appendChild(elem('span','count',`${h.requests} req · ${h.assets} assets`));container.appendChild(line);
    }
  }
  container.appendChild(elem('p','helper','Recorded requests are capped to the latest 750 entries per capture. Static references are not verified endpoints; pagination is an observation, not proof of complete results.'));
}
function empty(container,title,details) {
  const div=elem('div','empty');div.appendChild(elem('strong','',title));div.appendChild(elem('span','',details));container.appendChild(div);
}
async function vaultRequest(message){
  const result=await chrome.runtime.sendMessage({tabId,...message});
  if(!result?.ok)throw new Error(result?.error||'Vault operation failed');
  return result;
}
async function loadVault(){
  const data=await vaultRequest({type:'LIST_SESSIONS'});
  sessionsCache=data.sessions||[];lastVaultRefresh=Date.now();
}
function choose(label,rows,selectedId){
 const wrap=document.createElement('label');wrap.className='vault-selector';
 wrap.appendChild(elem('span','',label));
 const el=document.createElement('select');
 for(const r of rows){const o=document.createElement('option');o.value=r.id;o.textContent=`${r.origin} · ${r.startedAt||'unknown date'}`;el.appendChild(o);}
 if(selectedId)el.value=selectedId;
 wrap.appendChild(el);return {wrap,select:el};
}
function vaultButton(title,onClick,css='alt'){
 const btn=elem('button','btn '+css,title);btn.addEventListener('click',()=>{void (async()=>{
  try{btn.disabled=true;await onClick();}catch(e){notice(e.message,true);}finally{btn.disabled=false;}
 })();});return btn;
}
async function loadGroupRecords(group){
 const result=[];
 for(const item of group.segments){
  const r=await vaultRequest({type:'GET_SAVED_SESSION',sessionId:item.id});
  if(!r.record)throw Error('Segment disappeared from vault: '+item.id);
  result.push(r.record);
 }
 return result;
}
async function backupGroup(group){
 const records=await loadGroupRecords(group),bundle=await THIPro.bundle(records);
 const body=JSON.stringify(bundle,null,2);
 if(body.length>16000000)throw Error('Bundle exceeds the 16 MB re-import limit. Save segments individually from the session list.');
 const audit=await THIPro.verify(bundle);
 download('trufflehog-group-'+group.id+'.json',body,'application/json');
 notice(`Backup exported: ${audit.segments} segment(s), integrity verified${audit.missing.length?', missing part numbers '+audit.missing.join(', '):''}.`);
}
function pickJSON(onFile,maxBytes=16000000){
 const input=document.createElement('input');input.type='file';input.accept='.json,application/json';
 input.onchange=async()=>{try{const file=input.files?.[0];if(!file)return;
  if(file.size>maxBytes)throw Error('Selected JSON exceeds '+Math.round(maxBytes/1000000)+' MB limit');
  const data=JSON.parse(await file.text());await onFile(data);
 }catch(e){notice('Backup inspection failed: '+e.message,true);}};
 input.click();
}
function renderDAMHistory(container){
 container.appendChild(elem('p','warn-note','Offline comparison only. Select two saved capture groups; no sites are contacted. User-defined profiles are applied retrospectively using their CURRENT rules. "Not observed" is not proof a DAM vendor, API, or CDN was removed.'));
 const tools=elem('div','vault-controls');
 tools.appendChild(vaultButton('↻ Refresh saved groups',async()=>{await loadVault();drawView();}));
 tools.appendChild(vaultButton('Manage custom profiles',async()=>navigateView('profile-editor')));
 container.appendChild(tools);
 const groups=THIPro.groupRows(sessionsCache);
 if(groups.length<2){empty(container,'At least two saved groups required','Start and stop captures on separate visits, then compare their observed platform and host evidence.');return;}
 const selectors=elem('div','vault-controls');
 const left=choose('Earlier / first capture group',groups.map(g=>({id:g.id,origin:g.origin,startedAt:g.first})),damHistorySelection?.[0]||groups[groups.length-1].id);
 const right=choose('Later / second capture group',groups.map(g=>({id:g.id,origin:g.origin,startedAt:g.first})),damHistorySelection?.[1]||groups[0].id);
 selectors.appendChild(left.wrap);selectors.appendChild(right.wrap);
 selectors.appendChild(vaultButton('Compare DAM evidence',async()=>{
  if(left.select.value===right.select.value)throw Error('Select two different capture groups');
  const a=groups.find(g=>g.id===left.select.value),b=groups.find(g=>g.id===right.select.value);
  if(!a||!b)throw Error('Capture group selection is no longer available');
  if(a.segments.length>THIDAMHistory.MAX_SEGMENTS||b.segments.length>THIDAMHistory.MAX_SEGMENTS)
   throw Error(`Too many segments for a bounded comparison (max ${THIDAMHistory.MAX_SEGMENTS} per group). Export the groups and compare subsets instead.`);
  const [first,second]=await Promise.all([loadGroupRecords(a),loadGroupRecords(b)]);
  damHistoryResult=THIDAMHistory.compare(THIDAMHistory.snapshot(first,customProfiles),THIDAMHistory.snapshot(second,customProfiles));
  damHistorySelection=[a.id,b.id];drawView();notice('Saved DAM evidence compared without visiting external websites.');
 },'primary'));
 container.appendChild(selectors);
 if(!damHistoryResult){empty(container,'Compare saved capture groups','The evidence comparison will identify newly observed platforms and host roles, without interpreting missing observations as verified removals.');return;}
 container.appendChild(elem('p','helper',damHistoryResult.assessment));
 const stats=elem('div','simple-grid');
 stats.appendChild(panel('First group',`${damHistoryResult.first.segments} segment(s)`,`${damHistoryResult.first.requests} recorded requests`));
 stats.appendChild(panel('Second group',`${damHistoryResult.second.segments} segment(s)`,`${damHistoryResult.second.requests} recorded requests`));
 stats.appendChild(panel('Compared signals',`${damHistoryResult.total}`,damHistoryResult.truncated?'Table restricted to first 260 rows':'Includes technology clues and observed host roles'));
 container.appendChild(stats);
 const toolbar=elem('div','vault-controls');
 toolbar.appendChild(vaultButton('Export comparison JSON',async()=>download('trufflehog-dam-history.json',JSON.stringify({format:'trufflehog-dam-change-history',version:1,selection:damHistorySelection,analysis:damHistoryResult},null,2),'application/json')));
 toolbar.appendChild(vaultButton('Export comparison CSV',async()=>download('trufflehog-dam-history.csv','\uFEFF'+currentCSV(),'text/csv;charset=utf-8')));
 container.appendChild(toolbar);
 const rows=matches(damHistoryResult.rows);
 if(!rows.length){empty(container,'No evidence matches this filter','Clear the view search to see all captured evidence.');return;}
 container.appendChild(buildTable([{key:'kind',label:'Evidence class'},{key:'identity',label:'Technology / observed host',css:'mono'},
  {key:'layer',label:'Layer / host role'},{key:'status',label:'Observation status'},
  {key:'firstSightings',label:'First'},{key:'secondSightings',label:'Second'},
  {key:'evidence',label:'Evidence limitation'}],rows));
}
function renderArchivedSearch(container){
 container.appendChild(elem('p','warn-note','Search the masked indicator metadata saved across all investigations. Search does not inspect websites, access raw values, or validate credentials. Enter at least two characters in the Search current view field above.'));
 const tools=elem('div','vault-controls');
 tools.appendChild(vaultButton('Search saved findings',async()=>{
  const query=$('search').value.trim();const data=await vaultRequest({type:'SEARCH_ARCHIVED_FINDINGS',query});
  archiveSearchResult=data;drawView();notice(`${data.total} matching masked finding(s).`);
 },'primary'));
 tools.appendChild(vaultButton('Export masked findings CSV',async()=>{
  if(!archiveSearchResult)throw Error('Run a saved-findings search first');
  download('trufflehog-archived-findings.csv','\uFEFF'+currentCSV(),'text/csv');
 }));container.appendChild(tools);
 if(!archiveSearchResult){empty(container,'Search archived evidence','Enter a finding type, resource hostname, severity or review state in the search field, then select Search saved findings.');return;}
 container.appendChild(elem('h2','spaced-heading',`${archiveSearchResult.total} matched indicator(s)${archiveSearchResult.truncated?' · showing the first 300':''}`));
 container.appendChild(buildTable([{key:'origin',label:'Investigation',css:'mono'},{key:'segmentIndex',label:'Part'},{key:'type',label:'Classification'},
 {key:'source',label:'Observed source',css:'url mono'},{key:'masked',label:'Value'},{key:'reviewStatus',label:'Review'},{key:'at',label:'Recorded'}],archiveSearchResult.rows));
}
function renderReplay(container){
 container.appendChild(elem('p','warn-note','Offline event replay uses saved timestamps only. It cannot reconstruct unobserved activity, prove event causation, or restore removed response bodies. All timeline events remain local.'));
 const groups=THIPro.groupRows(sessionsCache);
 if(!groups.length){empty(container,'No saved captures','Complete a capture to build a timeline.');return;}
 const controls=elem('div','vault-controls'),wrap=elem('label','vault-selector');wrap.appendChild(elem('span','','Capture group'));
 const select=document.createElement('select');for(const g of groups){const o=document.createElement('option');o.value=g.id;o.textContent=`${g.origin} · ${g.count} segment(s) · ${g.first||''}`;select.appendChild(o);}
 select.value=groups.some(g=>g.id===replayGroup)?replayGroup:groups[0].id;wrap.appendChild(select);controls.appendChild(wrap);
 controls.appendChild(vaultButton('Load offline timeline',async()=>{
  const group=groups.find(g=>g.id===select.value);if(!group)throw Error('Unknown capture group');
  const records=await loadGroupRecords(group);replayGroup=group.id;replayResult=THIPro.timeline(records,1500);
  drawView();notice(`Timeline loaded from ${records.length} saved segment(s), ${replayResult.total} timestamped events.`);
 },'primary'));
 controls.appendChild(vaultButton('Export timeline JSON',async()=>{
  if(!replayResult)throw Error('Load an offline timeline first');
  download('trufflehog-offline-timeline.json',JSON.stringify({format:'trufflehog-local-timeline',version:1,group:replayGroup,...replayResult},null,2),'application/json');
 }));
 controls.appendChild(vaultButton('Export timeline CSV',async()=>{
  if(!replayResult)throw Error('Load an offline timeline first');
  download('trufflehog-offline-timeline.csv','\uFEFF'+currentCSV(),'text/csv');
 }));container.appendChild(controls);
 if(!replayResult){empty(container,'Select a capture group','Load a saved investigation group to reconstruct its recorded event sequence.');return;}
 container.appendChild(elem('p','helper',`${replayResult.rows.length} of ${replayResult.total} timestamped events shown. ${replayResult.truncated?'Timeline capped at 1,500 entries. Export is subject to the same cap.':'No timeline truncation.'}`));
 container.appendChild(buildTable([{key:'at',label:'Time'},{key:'segmentIndex',label:'Part'},
 {key:'kind',label:'Observed event'},{key:'detail',label:'Redacted details',css:'mono'}],matches(replayResult.rows)));
}
function renderCaseChange(container){
 container.appendChild(elem('p','warn-note','Compare two local Evidence Vault capture groups from exactly the same site origin. Counts reflect recorded browser evidence, not a verified permission change, compromise, credential validity or complete-site scan. No websites are contacted.'));
 const groups=THIPro.groupRows(sessionsCache);
 const tools=elem('div','vault-controls');tools.appendChild(vaultButton('↻ Refresh saved groups',async()=>{await loadVault();drawView();}));container.appendChild(tools);
 if(groups.length<2){empty(container,'Two saved capture groups required','Save two separate capture sessions on the same site before comparing their evidence.');return;}
 const options=groups.map(g=>({id:g.id,origin:g.origin,startedAt:g.first}));
 const earlier=choose('Earlier / reference capture',options,caseChangeSelection?.[0]||groups[groups.length-1].id);
 const later=choose('Later / comparison capture',options,caseChangeSelection?.[1]||groups[0].id);
 tools.appendChild(earlier.wrap);tools.appendChild(later.wrap);
 tools.appendChild(vaultButton('Compare saved case evidence',async()=>{
  if(earlier.select.value===later.select.value)throw Error('Choose two different capture groups');
  const a=groups.find(g=>g.id===earlier.select.value),b=groups.find(g=>g.id===later.select.value);
  if(!a||!b)throw Error('Group not found');
  const [oldRows,newRows]=await Promise.all([loadGroupRecords(a),loadGroupRecords(b)]);
  caseChangeReport=THICaseCompare.compare(oldRows,newRows);
  caseChangeSelection=[a.id,b.id];drawView();notice('Offline same-site case evidence compared. Missing sightings are not removals.');
 },'primary'));
 if(!caseChangeReport){empty(container,'Compare investigations','Select two same-site groups to review platform indications, media-delivery policies, masked indicators and coverage.');return;}
 container.appendChild(elem('p','warn-note','Confidence: '+caseChangeReport.comparisonConfidence));
 const stats=elem('div','simple-grid');
 stats.appendChild(panel('Reference segments',String(caseChangeReport.earlier.segments),'Saved capture segments'));
 stats.appendChild(panel('Comparison segments',String(caseChangeReport.later.segments),'Saved capture segments'));
 stats.appendChild(panel('Blind-spot notices',String(caseChangeReport.blindspots.length),'Differences may be attributable to capture coverage'));
 container.appendChild(stats);
 container.appendChild(elem('h2','spaced-heading','Observed metrics: recorded counts only'));
 container.appendChild(buildTable([
  {key:'category',label:'Area'},{key:'label',label:'Observation'},
  {key:'earlier',label:'Earlier'},{key:'later',label:'Later'},{key:'delta',label:'Change'},
  {key:'observation',label:'Recorded difference'},{key:'qualification',label:'Interpretation limit'}
 ],matches(caseChangeReport.metrics)));
 if(caseChangeReport.profiles.length){container.appendChild(elem('h2','spaced-heading','DAM specialist evidence'));
  container.appendChild(buildTable([{key:'vendor',label:'Platform'},{key:'earlier',label:'Earlier'},{key:'later',label:'Later'},
   {key:'assessment',label:'What can be said'}],caseChangeReport.profiles));}
 if(caseChangeReport.notes.length){container.appendChild(elem('h2','spaced-heading','Review notes'));
  container.appendChild(buildTable([{key:'priority',label:'Type'},{key:'finding',label:'Observation'},
   {key:'action',label:'Owner-side verification'}],caseChangeReport.notes));}
 if(caseChangeReport.blindspots.length){container.appendChild(elem('h2','spaced-heading','Capture limitations'));
  for(const description of caseChangeReport.blindspots)container.appendChild(elem('p','helper',description));}
 const actions=elem('div','vault-controls');
 actions.appendChild(vaultButton('Export redacted comparison JSON',async()=>{
  const doc=await THICaseCompare.pack(caseChangeReport);download('trufflehog-case-comparison.json',JSON.stringify(doc,null,2),'application/json');
  notice('Offline comparison exported. Digest detects incidental edits but does not authenticate evidence.');
 }));
 actions.appendChild(vaultButton('Export comparison CSV',async()=>{
  download('trufflehog-case-comparison.csv','\uFEFF'+THICaseCompare.csv(caseChangeReport),'text/csv;charset=utf-8');
  notice('Redacted comparison metrics exported.');
 }));container.appendChild(actions);
}
function renderCaseDossier(container){
 container.appendChild(elem('p','warn-note','Offline, local case report from saved capture segments only. Observed facts are separate from vendor inferences and unverifiable coverage. No third-party sites are contacted. Integrity hashes detect accidental edits, not source authenticity.'));
 const groups=THIPro.groupRows(sessionsCache);
 const tools=elem('div','vault-controls');
 tools.appendChild(vaultButton('↻ Refresh saved groups',async()=>{await loadVault();drawView();}));
 container.appendChild(tools);
 if(!groups.length){empty(container,'No saved capture groups','Stop and save an investigation in Evidence Vault first.');return;}
 const selector=choose('Saved capture group',groups.map(g=>({id:g.id,origin:g.origin,startedAt:g.first})),caseSelectedGroup||groups[0].id);
 tools.appendChild(selector.wrap);
 tools.appendChild(vaultButton('Build local dossier',async()=>{
  const group=groups.find(g=>g.id===selector.select.value);if(!group)throw Error('Saved group not found');
  const records=await loadGroupRecords(group);
  caseDossier=THICase.build(records);caseSelectedGroup=group.id;drawView();
  notice('Case dossier built from '+records.length+' saved segment(s); no network requests.');
 },'primary'));
 if(!caseDossier)return;
 const grid=elem('div','simple-grid');
 for(const [name,value,detail] of [
  ['Included segments',caseDossier.segmentSummary.included,'Same capture group only'],
  ['Observed requests',caseDossier.counts.requests,'Not complete-site coverage'],
  ['Masked findings',caseDossier.counts.findings,'Potential indicators, not validated credentials'],
  ['Unverified categories',caseDossier.review.unverifiedCategories,'Missing evidence remains unverified']
 ])grid.appendChild(panel(name,String(value),detail));
 container.appendChild(grid);
 container.appendChild(elem('h2','spaced-heading','Evidence statements'));
 container.appendChild(buildTable([
  {key:'category',label:'Category'},{key:'status',label:'Evidence class'},
  {key:'count',label:'Count'},{key:'statement',label:'What the capture shows'},
  {key:'qualification',label:'Limitations'}],caseDossier.evidence));
 if(caseDossier.platforms.length){container.appendChild(elem('h2','spaced-heading','DAM platform indications'));
  container.appendChild(buildTable([{key:'vendor',label:'Platform'},{key:'confidence',label:'Strength'},{key:'observedSegments',label:'Segments'}],caseDossier.platforms));}
 const security=elem('p','warn-note','Only an approved site origin, numeric counts, fixed evidence labels, timeline event types and platform confidence are exported. This does not contain full requests, asset IDs, signed links, or discovered credentials.');container.appendChild(security);
 const passLabel=elem('label','profile-field','Optional encryption passphrase (minimum 12 characters)');
 const passInput=document.createElement('input');passInput.type='password';passInput.autocomplete='new-password';passInput.placeholder='Not saved';passInput.maxLength=256;passLabel.appendChild(passInput);container.appendChild(passLabel);
 const actions=elem('div','vault-controls');container.appendChild(actions);
 actions.appendChild(vaultButton('Export redacted case JSON',async()=>{
  const envelope=await THICase.pack(caseDossier);download('trufflehog-case.json',JSON.stringify(envelope,null,2),'application/json');notice('Case dossier exported. SHA-256 integrity is not a digital signature.');
 }));
 actions.appendChild(vaultButton('Export case CSV',async()=>{download('trufflehog-case.csv','\uFEFF'+THICase.csv(caseDossier),'text/csv;charset=utf-8');notice('Redacted case summary CSV exported.');}));
 actions.appendChild(vaultButton('Export encrypted case',async()=>{
  const phrase=passInput.value;passInput.value='';
  const envelope=await THICase.pack(caseDossier);const encrypted=await THICaseCrypto.seal(envelope,phrase);
  download('trufflehog-case.encrypted.json',JSON.stringify(encrypted),'application/json');notice('AES-GCM encrypted case exported. Safeguard the passphrase; it cannot be recovered.');
 }));
 actions.appendChild(vaultButton('Verify encrypted/JSON case file',async()=>{
  const phrase=passInput.value;passInput.value='';
  pickJSON(async data=>{
   const envelope=data?.format==='trufflehog-encrypted-case'?await THICaseCrypto.open(data,phrase):data;
   await THICase.verify(envelope);notice('Case digest verified. This does NOT authenticate its original author or captured observations.');
   // Imported cases are verified but not merged into Evidence Vault and not rendered as arbitrary input.
  },2500000);
 }));
}
function renderVault(container){
 container.appendChild(elem('p','warn-note','Saved sessions remain in local IndexedDB. Entire multi-part captures can now be exported as one checksum-verified group backup. Integrity checks detect accidental changes but do not authenticate a backup. Imported backups accept only recognised Trufflehog metadata exports; raw credentials and unexpected response fields are discarded. Exported files may contain asset IDs or website paths, so review them before sharing.'));
 const controls=elem('div','vault-controls');
 controls.appendChild(vaultButton('↻ Refresh investigations',async()=>{await loadVault();drawView();}));
 controls.appendChild(vaultButton('Import saved session',async()=>{
   const input=document.createElement('input');input.type='file';input.accept='.json,application/json';
   input.onchange=async()=>{try{
     const file=input.files?.[0];if(!file)return;if(file.size>4500000)throw new Error('File is larger than 4.5 MB');
     const imported=JSON.parse(await file.text());const result=await vaultRequest({type:'IMPORT_SAVED_SESSION',payload:imported});
     await loadVault();notice('Imported '+result.session.origin+' (metadata only)');drawView();
   }catch(e){notice('Import failed: '+e.message,true);}};input.click();
 }));
 controls.appendChild(vaultButton('Import capture group',async()=>{
   pickJSON(async payload=>{
     const check=await THIPro.verify(payload);
     const response=await vaultRequest({type:'IMPORT_CAPTURE_GROUP',payload});
     await loadVault();drawView();notice(`Imported ${response.count} verified segment(s) as new local group. ${check.missing.length?'Missing original part numbers: '+check.missing.join(', '):'Part-number sequence complete.'}`);
   });
 }));
 controls.appendChild(vaultButton('Verify backup integrity',async()=>{
   pickJSON(async payload=>{
     const check=await THIPro.verify(payload);
     notice(`Integrity OK for ${check.segments} segment(s). ${check.missing.length?'Gaps in part numbers: '+check.missing.join(', '):'No internal part-number gaps.'}`);
   });
 }));
 controls.appendChild(vaultButton('Export session index (CSV)',async()=>{
  const cols=['id','origin','startedAt','endedAt','requests','images','findings','verified','apiRoutes','assetIds'];
  const enc=x=>'"'+String(x??'').replaceAll('"','""')+'"';
  download('trufflehog-investigations.csv','\uFEFF'+[cols.join(','),...sessionsCache.map(x=>cols.map(c=>enc(x[c])).join(','))].join('\r\n'),'text/csv');
 }));
 container.appendChild(controls);
 const groups=THIPro.groupRows(sessionsCache);
 if(groups.length){
   container.appendChild(elem('h2','spaced-heading',`${groups.length} capture group(s) · one-click backup`));
   const groupArea=elem('div','vault-grid');
   for(const group of groups.slice(0,80)){
     const tile=elem('div','vault-session');
     tile.appendChild(elem('div','mono vault-origin',group.origin));
     tile.appendChild(elem('div','muted',`${group.count} segment(s) · ${group.requests} requests · ${group.findings} indicators · Group ${group.id}`));
     const buttons=elem('div','vault-controls');
     buttons.appendChild(vaultButton('Backup entire group',()=>backupGroup(group)));
     buttons.appendChild(vaultButton('Replay group',async()=>{replayGroup=group.id;const records=await loadGroupRecords(group);replayResult=THIPro.timeline(records);document.querySelector('[data-view="replay"]').click();}));
     tile.appendChild(buttons);groupArea.appendChild(tile);
   }
   container.appendChild(groupArea);
 }
 const filtered=matches(sessionsCache);
 if(!filtered.length){empty(container,'No saved investigations',sessionsCache.length?'Change the search filter.':'Start a capture, stop it, then return here. Existing v2.8 tab records are imported automatically.');return;}
 container.appendChild(elem('h2','spaced-heading',`${filtered.length} saved investigation(s)`));
 const table=buildTable([
  {key:'origin',label:'Website',css:'url mono'},{key:'segmentIndex',label:'Part'}, {key:'startedAt',label:'Started'},{key:'endedAt',label:'Finished'},
  {key:'requests',label:'Requests'},{key:'images',label:'Images'},{key:'findings',label:'Masked indicators'},
  {key:'verified',label:'Verified images'}],filtered);
 container.appendChild(table);
 const actions=elem('div','vault-grid');
 for(const r of filtered.slice(0,70)){
  const box=elem('div','vault-session');box.appendChild(elem('div','mono vault-origin',r.origin));
  box.appendChild(elem('div','muted',`Part ${r.segmentIndex||1} · ${r.startedAt||'?'} · ${r.requests} req · ${r.images} image references · Group: ${r.captureGroupId||r.id}`));
  const buttons=elem('div','vault-controls');
  buttons.appendChild(vaultButton('View',async()=>{archivedId=r.id;document.querySelector('[data-view="overview"]').click();notice('Viewing saved evidence · '+r.origin);}));
  buttons.appendChild(vaultButton('Backup',async()=>{
   const out=await vaultRequest({type:'GET_SAVED_SESSION',sessionId:r.id});
   download('trufflehog-session-'+r.id+'.json',JSON.stringify({format:'trufflehog-vault-session',version:1,record:stripInternal(out.record)},null,2),'application/json');
   notice('Exported '+r.origin);
  }));
  buttons.appendChild(vaultButton('Delete',async()=>{
   if(!confirm('Permanently delete this saved investigation? Export a backup first.'))return;
   await vaultRequest({type:'DELETE_SAVED_SESSION',sessionId:r.id});
   if(archivedId===r.id)archivedId=null;
   await loadVault();drawView();notice('Investigation deleted.');
  },'ghost'));
  box.appendChild(buttons);actions.appendChild(box);
 }
 container.appendChild(actions);
 if(sessionsCache.length<2)return;
 container.appendChild(elem('h2','spaced-heading','Compare two recorded investigations'));
 const selectRow=elem('div','vault-controls');
 const left=choose('First investigation',sessionsCache,comparisonIds?.[0]||sessionsCache[0].id),right=choose('Second investigation',sessionsCache,comparisonIds?.[1]||sessionsCache[1].id);
 selectRow.appendChild(left.wrap);selectRow.appendChild(right.wrap);
 selectRow.appendChild(vaultButton('Compare',async()=>{
   const result=await vaultRequest({type:'COMPARE_SAVED_SESSIONS',leftId:left.select.value,rightId:right.select.value});
   comparison=result.comparison;comparisonIds=[left.select.value,right.select.value];drawView();
 }));container.appendChild(selectRow);
 if(comparison){
  container.appendChild(elem('p','warn-note',comparison.assessment));
  const comps=Object.entries(comparison.groups).map(([kind,x])=>({kind,shared:x.sharedCount,onlyA:x.onlyACount,onlyB:x.onlyBCount,examples:x.shared.slice(0,5).join(' · ')}));
  container.appendChild(buildTable([{key:'kind',label:'Evidence type'},{key:'shared',label:'Shared'},{key:'onlyA',label:'Only first'},{key:'onlyB',label:'Only second'},{key:'examples',label:'Shared examples',css:'url mono'}],comps));
 }
}
let siteRelationAnalysis=null,siteRelationSelection=null;
function renderFrameWorkerEvidence(container){
 const info=THIContexts.analyze(record);
 container.appendChild(elem('p','warn-note',info.note+' Cross-origin frame contents are never read by the new module. Network-only sub-frame sightings do not imply content access.'));
 const summary=elem('div','simple-grid');
 summary.appendChild(panel('Observed frame origins',String(info.embedded)));
 summary.appendChild(panel('Worker-related clues',String(info.workerClues)));
 summary.appendChild(panel('Inspected same-origin frames',String((record?.frameCoverage||[]).filter(x=>x.status==='inspected').length)));
 summary.appendChild(panel('Service Worker controller references',String((record?.workerScripts||[]).length)));
 summary.appendChild(panel('Scope','Top-frame inventory + same-origin frame summaries'));
 container.appendChild(summary);
 const rows=matches(info.rows);
 if((record?.frameCoverage||[]).length){
  container.appendChild(elem('h3','', 'Same-origin iframe inspection coverage'));
  container.appendChild(buildTable([{key:'index',label:'Frame #'},{key:'status',label:'Inspection state'},
   {key:'origin',label:'Origin',css:'url mono'},{key:'inlineScripts',label:'Inline scripts scanned'},
   {key:'scriptReferences',label:'External script references'},{key:'maskedIndicators',label:'Masked indicators'}],(record.frameCoverage||[]).slice(0,100)));
 }
 if((record?.workerScripts||[]).length){container.appendChild(elem('h3','','Service Worker controller references — scripts NOT inspected'));
  container.appendChild(buildTable([{key:'url',label:'Sanitised script reference',css:'url mono'},{key:'inspected',label:'Inspected'}],record.workerScripts.slice(0,80)));}
 if(!rows.length){if(!(record?.frameCoverage||[]).length)empty(container,'No frame or worker evidence','Open a page with embedded frames or a controlling service worker while capture is active.');return;}
 container.appendChild(buildTable([{key:'kind',label:'Type'},{key:'origin',label:'Origin',css:'url mono'},
  {key:'relationship',label:'Origin relationship'},{key:'sandboxed',label:'Sandbox attribute present'},
  {key:'evidence',label:'Evidence'},{key:'sightings',label:'Sightings'}],rows));
}
function renderSiteRelations(container){
 container.appendChild(elem('p','warn-note','Offline comparison of observed third-party host roles from different website origins. Shared infrastructure does not establish shared asset databases, private storage, ownership or permissions. No additional requests are made.'));
 if(sessionsCache.length<2){empty(container,'Two saved investigations required','Stop and archive captures from different websites.');return;}
 const bar=elem('div','vault-controls');
 const left=choose('First investigation',sessionsCache,siteRelationSelection?.[0]||sessionsCache[0].id);
 const right=choose('Second investigation',sessionsCache,siteRelationSelection?.[1]||sessionsCache[1].id);
 bar.appendChild(left.wrap);bar.appendChild(right.wrap);
 bar.appendChild(vaultButton('Compare observed hosts',async()=>{
   const response=await vaultRequest({type:'CROSS_SITE_HOST_RELATIONS',leftId:left.select.value,rightId:right.select.value});
   siteRelationAnalysis=response.analysis;siteRelationSelection=[left.select.value,right.select.value];drawView();
 },'primary'));
 container.appendChild(bar);
 if(!siteRelationAnalysis)return;
 const r=siteRelationAnalysis;
 const summary=elem('div','simple-grid');
 summary.appendChild(panel('Shared observed hosts',String(r.sharedHostCount)));
 summary.appendChild(panel('First site',r.first.origin));
 summary.appendChild(panel('Second site',r.second.origin));
 container.appendChild(summary);
 container.appendChild(elem('p','helper',r.note));
 if(r.truncated)container.appendChild(elem('p','warn-note','Examples are capped at 160 hosts.'));
 const buttons=elem('div','vault-controls');
 buttons.appendChild(vaultButton('Export comparison JSON',async()=>download('trufflehog-site-hosts.json',JSON.stringify({format:'thi-site-relationships-v1',analysis:r},null,2),'application/json')));
 buttons.appendChild(vaultButton('Export comparison CSV',async()=>{
  const keys=['host','firstRoles','secondRoles','sharedRoles','firstRequests','secondRequests','assessment','confidence'];
  const table=[keys.map(csvValue).join(','),...r.rows.map(row=>keys.map(k=>csvValue(row[k])).join(','))].join('\r\n');
  download('trufflehog-site-hosts.csv','\uFEFF'+table,'text/csv;charset=utf-8');
 }));
 container.appendChild(buttons);
 const rows=matches(r.rows);
 if(!rows.length){empty(container,'No shared third-party hosts observed','Different captures may legitimately use different infrastructures, or may have incomplete coverage.');return;}
 container.appendChild(buildTable([{key:'host',label:'Observed host',css:'url mono'},
  {key:'firstRoles',label:'First site roles'},{key:'secondRoles',label:'Second site roles'},
  {key:'sharedRoles',label:'Role overlap'},{key:'assessment',label:'Interpretation'}],rows));
}
function renderExplorer(container){
 container.appendChild(elem('p','warn-note','Compare only metadata already saved in the Evidence Vault. Verified hash matches prove identical observed response bytes, NOT the availability of master images. Filename/ID/schema matches are clues, not proof of common ownership or backing storage. No requests are made to the investigated websites.'));
 const tools=elem('div','vault-controls');
 tools.appendChild(vaultButton('↻ Refresh saved sessions',async()=>{await loadVault();drawView();}));
 tools.appendChild(vaultButton('Open Evidence Vault',async()=>{document.querySelector('[data-view="vault"]').click();}));
 container.appendChild(tools);
 if(sessionsCache.length<2){empty(container,'Two saved sessions needed','Capture and stop investigations on two websites, then return here.');return;}
 const row=elem('div','vault-controls');
 const left=choose('First saved session',sessionsCache,crossSelection?.[0]||sessionsCache[0].id);
 const right=choose('Second saved session',sessionsCache,crossSelection?.[1]||sessionsCache[1].id);
 row.appendChild(left.wrap);row.appendChild(right.wrap);
 row.appendChild(vaultButton('Analyse recorded evidence',async()=>{
  const result=await vaultRequest({type:'CROSS_ARCHIVE_EXPLORER',leftId:left.select.value,rightId:right.select.value});
  crossAnalysis=result.analysis;crossSelection=[left.select.value,right.select.value];drawView();notice('Cross-archive evidence compared locally.');
 },'primary'));
 container.appendChild(row);
 if(!crossAnalysis)return;
 const summary=elem('div','simple-grid');
 for(const [label,v] of Object.entries(crossAnalysis.counts||{}))summary.appendChild(panel(label,`${v} overlap(s)`));
 container.appendChild(summary);
 container.appendChild(elem('p','helper',crossAnalysis.assessment));
 if(crossAnalysis.truncation)container.appendChild(elem('p','warn-note','Only a bounded number of detailed examples is shown; summary counts may be higher.'));
 const exports=elem('div','vault-controls');
 exports.appendChild(vaultButton('Export evidence report (JSON)',async()=>{
  const report={format:'trufflehog-cross-archive-report',version:1,createdAt:new Date().toISOString(),analysis:crossAnalysis};
  download('trufflehog-cross-archive-'+new Date().toISOString().slice(0,10)+'.json',JSON.stringify(report,null,2),'application/json');
 }));
 exports.appendChild(vaultButton('Export evidence table (CSV)',async()=>{
  const cols=['kind','grade','identity','leftEvidence','rightEvidence','meaning'];
  download('trufflehog-cross-archive.csv','\uFEFF'+[cols.map(csvValue).join(','),...crossRows().map(x=>cols.map(k=>csvValue(x[k])).join(','))].join('\r\n'),'text/csv;charset=utf-8');
 }));
 container.appendChild(exports);
 const rows=matches(crossRows());
 if(!rows.length){empty(container,'No matching evidence','Adjust search or compare other saved investigations.');return;}
 container.appendChild(elem('h2','spaced-heading',`${rows.length} evidence match(es) shown`));
 container.appendChild(buildTable([
  {key:'grade',label:'Evidence grade',badge:v=>v==='Verified'?'success':v==='Reference'?'warn':''},
  {key:'kind',label:'Match type'}, {key:'identity',label:'Recorded identity',css:'url mono'},
  {key:'leftEvidence',label:'First session evidence',css:'url mono'},
  {key:'rightEvidence',label:'Second session evidence',css:'url mono'},
  {key:'meaning',label:'Interpretation'}],rows));
}
function renderDiagnostics(container){
 const d=diagnosticData||THICross.diagnostics(record,recording,null);
 container.appendChild(elem('p','warn-note','Diagnostics are based on saved counters and currently visible extension state. A value of zero means no tracked losses, not a guarantee that every browser event was captured. DevTools connectivity, missed initial requests and browser storage persistence still require live Chrome verification.'));
 const panels=elem('div','simple-grid');
 panels.appendChild(panel('Capture state',d.capturing?'Recording':'Inactive / archived'));
 panels.appendChild(panel('Local live-record storage',d.bytes==null?'Not measured':`${(d.bytes/1024).toFixed(1)} KiB`,'Compatibility checkpoint size in Chrome storage.local; active journal changes reside in IndexedDB.'));
 panels.appendChild(panel('Unreviewed secret indicators',String(d.unreviewedAlerts),'Matches remain redacted.'));
 panels.appendChild(panel('Saved session ID',d.sessionId||'No session'));
 const journal=d.journal||null;
 if(journal){
  panels.appendChild(panel('Capture persistence',journal.mode==='indexeddb-journal'?'Durable IndexedDB journal':journal.mode==='legacy-local'?'Legacy local storage':journal.mode==='error'?'Storage error':'Not available',
   'Live events use transactional local deltas, with compacted snapshots every 96 changes when IndexedDB is available.'));
  if(journal.mode==='indexeddb-journal'){
   panels.appendChild(panel('Uncompacted changes',String(journal.pendingDeltas||0),
    'Pending changes are durable IndexedDB transactions, not unsaved RAM-only events.'));
   panels.appendChild(panel('Checkpoint revision',String(journal.checkpointSequence||0)));
  }
  const unmatched=journal.unassignedSinceWorker;
  if(unmatched){
   panels.appendChild(panel('Unassigned observed responses',String(unmatched.total||0),
    'Counted only since this service-worker instance started; excludes unseen browser traffic.'));
   if(unmatched.total)container.appendChild(elem('p','warn-note',
     `Unassigned responses: ${unmatched.priorNavigation||0} from older navigation generations, ${unmatched.insufficientProvenance||0} with insufficient provenance, and ${unmatched.originMismatch||0} with origin mismatch. These were not attributed to the current capture.`));
  }
  const quota=journal.browserStorageEstimate;
  if(quota?.quotaBytes>0)panels.appendChild(panel('Estimated browser storage',
   `${(quota.usageBytes/1048576).toFixed(1)} / ${(quota.quotaBytes/1048576).toFixed(0)} MiB`,
   'Origin-wide estimate, not a per-tab or guaranteed usable quota.'));
  if(journal.storageError)container.appendChild(elem('p','warn-note','Storage persistence error: '+journal.storageError.message+'. Capture may be incomplete; inspect the extension worker and export existing evidence.'));
 }
 if(record?.segmentIndex>1) panels.appendChild(panel('Capture segment',String(record.segmentIndex),'Earlier segments were archived automatically as separate sessions in the Evidence Vault.'));
 if(record?.captureGroupId)panels.appendChild(panel('Capture group',record.captureGroupId,'Use this identifier to associate automatically rotated evidence sessions.'));
 container.appendChild(panels);
 container.appendChild(elem('h2','spaced-heading','Capture retention limits'));
 container.appendChild(buildTable([{key:'field',label:'Record type'},{key:'observed',label:'Currently held'},
 {key:'limit',label:'Limit'},{key:'dropped',label:'Dropped / overwritten',badge:v=>v>0?'danger':'success'}],diagnosticRows()));
 container.appendChild(elem('h2','spaced-heading','Diagnostic warnings'));
 for(const message of d.warnings||[])container.appendChild(elem('p','helper',message));
}
function renderCaptureRepair(container){
 const benchmark=THILabAcceptance.evaluate(record,recording);
 const result=THICaptureRepair.evaluate({acceptance:acceptanceReport,benchmark,recording});
 container.appendChild(elem('p','warn-note','Guidance only. No page reloads, permission changes, additional requests or credential use are performed. Inferred causes are not verified facts. The local benchmark only evaluates the supplied localhost fixture.'));
 const cards=elem('div','simple-grid');
 cards.appendChild(panel('Assessment',result.assessment));
 cards.appendChild(panel('Needs review',String(result.summary.needsReview)));
 cards.appendChild(panel('Not tested',String(result.summary.notTested)));
 cards.appendChild(panel('Lab executed',result.summary.labExecuted?'Yes':'No'));
 container.appendChild(cards);
 const actions=elem('div','action-row');
 const again=elem('button','btn alt','Re-run diagnostics');again.type='button';again.addEventListener('click',()=>{void refresh();});actions.appendChild(again);
 const exp=elem('button','btn alt','Export redacted repair plan');exp.type='button';exp.addEventListener('click',()=>download('trufflehog-v61-capture-repair.json',JSON.stringify(result,null,2),'application/json'));actions.appendChild(exp);
 container.appendChild(actions);
 if(result.actions.length){
  container.appendChild(buildTable([{key:'priority',label:'Priority'},{key:'category',label:'Area'},{key:'title',label:'Recommended action'},{key:'status',label:'Evidence status',badge:v=>v==='needs-review'?'warning':''}],result.actions));
  for(const a of result.actions){
    const block=elem('div','detail-box');block.appendChild(elem('h3','','P'+a.priority+' · '+a.title));
    block.appendChild(elem('p','helper',a.why));
    const ol=elem('ol','');for(const step of a.steps)ol.appendChild(elem('li','',step));block.appendChild(ol);container.appendChild(block);
  }
 }else container.appendChild(elem('p','helper','No local diagnostic actions were generated. This does not certify complete capture; test the Windows browser workflow before relying on results.'));
 for(const line of result.limitations)container.appendChild(elem('p','helper',line));
}
function renderLocalBenchmark(container){
 const a=THILabAcceptance.evaluate(record,recording);
 container.appendChild(elem('p','warn-note','Run only against the included localhost fixture at port 8770. This report checks specific browser-recorded test stages; it cannot certify full browser integration or third-party DAM visibility. The report contains no URL, POST value, credential or filename.'));
 const panels=elem('div','simple-grid');
 panels.appendChild(panel('Lab assessment',a.verdict));
 panels.appendChild(panel('Passed',String(a.summary.pass)));
 panels.appendChild(panel('Needs review',String(a.summary.warn)));
 panels.appendChild(panel('Not tested',String(a.summary.notTested)));
 container.appendChild(panels);
 const actions=elem('div','action-row');
 const rerun=elem('button','btn alt','Refresh evidence');rerun.type='button';rerun.addEventListener('click',()=>{void refresh();});actions.appendChild(rerun);
 const exp=elem('button','btn alt','Export privacy-safe benchmark JSON');exp.type='button';exp.addEventListener('click',()=>download('trufflehog-local-benchmark.json',JSON.stringify(a,null,2),'application/json'));actions.appendChild(exp);
 container.appendChild(actions);
 container.appendChild(buildTable([{key:'label',label:'Expected fixture step'},{key:'status',label:'Result',badge:v=>v==='pass'?'success':v==='warn'?'warning':''},{key:'evidence',label:'Recorded evidence or missing step'}],a.checks));
 for(const note of a.limitations)container.appendChild(elem('p','helper',note));
}
function renderAcceptance(container){
 container.appendChild(elem('p','warn-note','This is a local evidence-path diagnostic, not a certification that the website is secure or all resources were inspected. A completed scan covers only files observed by DevTools. It makes no additional website requests.'));
 if(!acceptanceReport){empty(container,'No acceptance report','Open an HTTP(S) capture and refresh.');return;}
 const a=acceptanceReport;
 const panels=elem('div','simple-grid');
 panels.appendChild(panel('Assessment',a.verdict));
 panels.appendChild(panel('Passed',String(a.summary.pass)));
 panels.appendChild(panel('Needs review',String(a.summary.warn)));
 panels.appendChild(panel('Not tested',String(a.summary.notTested)));
 container.appendChild(panels);
 const buttons=elem('div','action-row');
 const rerun=elem('button','btn alt','Re-run acceptance checks');rerun.type='button';rerun.addEventListener('click',()=>{void refresh();});
 buttons.appendChild(rerun);
 const exportButton=elem('button','btn alt','Export acceptance report (JSON)');exportButton.type='button';
 exportButton.addEventListener('click',()=>download('trufflehog-acceptance-'+new Date().toISOString().slice(0,10)+'.json',JSON.stringify(a,null,2),'application/json'));
 buttons.appendChild(exportButton);container.appendChild(buttons);
 container.appendChild(buildTable([{key:'title',label:'Check'},{key:'status',label:'Result',badge:v=>v==='pass'?'success':v==='warn'?'warning':''},{key:'detail',label:'What this verifies'}],a.checks));
 for(const line of a.limitations||[])container.appendChild(elem('p','helper',line));
}
function renderCaptureAudit(container){
 const audit=THICaptureAudit.assess(record,recording,sessionsCache);
 container.appendChild(elem('p','warn-note','This is an audit of evidence already recorded, NOT a security certification. It cannot see resources loaded before DevTools opened or prove the whole site was scanned. No third-party requests are made.'));
 const cards=elem('div','simple-grid');
 cards.appendChild(panel('Audit assessment',audit.readiness));
 cards.appendChild(panel('Checks passed',String(audit.summary.pass)));
 cards.appendChild(panel('Needs review',String(audit.summary.warn)));
 cards.appendChild(panel('Unknown / incomplete',String(audit.summary.unknown)));
 container.appendChild(cards);
 const actions=elem('div','action-row');
 const button=elem('button','btn alt','Export privacy-safe audit (JSON)');button.type='button';
 button.addEventListener('click',()=>download('trufflehog-evidence-audit-'+new Date().toISOString().slice(0,10)+'.json',JSON.stringify(audit,null,2),'application/json'));
 actions.appendChild(button);container.appendChild(actions);
 container.appendChild(buildTable([{key:'id',label:'Evidence check'},{key:'status',label:'Result',badge:v=>v==='warn'?'danger':v==='pass'?'success':''},{key:'detail',label:'Interpretation'}],matches(audit.checks)));
 container.appendChild(elem('p','helper',audit.qualification));
}
function renderDiscoveryPulse(container){
 container.appendChild(elem('p','warn-note','Offline, observational comparison only. A newly observed service host may reflect different browsing, a new integration, or incomplete earlier capture. Resources visible in network metadata are NOT necessarily inspected for secrets. No credentials or URL query values are compared.'));
 const toggles=elem('div','vault-controls');
 const switcher=vaultButton(discoveryAlertsEnabled?'Disable discovery notifications':'Enable discovery notifications',async()=>{
  const answer=await chrome.runtime.sendMessage({type:'SET_DISCOVERY_ALERTS',tabId,enabled:!discoveryAlertsEnabled});
  if(!answer?.ok)throw Error(answer?.error||'Cannot update preference');
  discoveryAlertsEnabled=answer.enabled;drawView();notice('Discovery desktop notifications '+(answer.enabled?'enabled':'disabled')+'. Secret alerts use a separate preference.');
 });
 toggles.appendChild(switcher);container.appendChild(toggles);
 container.appendChild(elem('p','helper','Discovery notifications default to OFF. When enabled, stopping a capture may notify you of newly observed API, script or image host roles relative to one previous completed capture of the same origin. It does not prove newly deployed infrastructure.'));
 const groups=THIPro.groupRows(sessionsCache);
 if(groups.length<2){empty(container,'Two saved capture groups needed','Stop and archive at least two captures of the same site. No automatic extra requests will be made.');return;}
 const items=groups.map(g=>({id:g.id,origin:g.origin,startedAt:g.first}));
 const controls=elem('div','vault-controls');
 const first=choose('Baseline capture group',items,discoverySelection?.[0]||groups[groups.length-1].id);
 const second=choose('Later capture group',items,discoverySelection?.[1]||groups[0].id);
 controls.appendChild(first.wrap);controls.appendChild(second.wrap);
 controls.appendChild(vaultButton('Compare observed discoveries',async()=>{
  const a=groups.find(g=>g.id===first.select.value),b=groups.find(g=>g.id===second.select.value);
  if(!a||!b||a.id===b.id)throw Error('Choose two different capture groups');
  if(a.origin!==b.origin)throw Error('Discovery Pulse requires the same exact website origin');
  const [oldRecords,newRecords]=await Promise.all([loadGroupRecords(a),loadGroupRecords(b)]);
  discoveryResult=THIDiscoveryPulse.compare(THIDiscoveryPulse.snapshot(oldRecords),THIDiscoveryPulse.snapshot(newRecords));
  discoverySelection=[a.id,b.id];drawView();notice('Saved browser observations compared offline.');
 },'primary'));container.appendChild(controls);
 if(!discoveryResult){empty(container,'Compare two captures','Compare previously recorded network roles, JS versions and file-scan coverage.');return;}
 container.appendChild(elem('p','helper',discoveryResult.assessment));
 const metrics=elem('div','simple-grid');
 metrics.appendChild(panel('New host roles',String(discoveryResult.counts.newHosts),'Observed on a later visit, not necessarily new infrastructure'));
 metrics.appendChild(panel('Changed JavaScript digests',String(discoveryResult.counts.changedScripts),'Compared when both captures include the script hash'));
 metrics.appendChild(panel('Not seen in latest',String(discoveryResult.counts.notSeen),'Cannot prove removal'));
 metrics.appendChild(panel('Later DevTools heartbeats',`${discoveryResult.after.heartbeat}/${discoveryResult.after.segments}`,'Does not prove all loaded files were scanned'));
 container.appendChild(metrics);
 container.appendChild(elem('h2','spaced-heading','Already-observed resource coverage'));
 container.appendChild(buildTable([{key:'kind',label:'File kind'},{key:'observed',label:'Unique requests'},{key:'scanned',label:'Confirmed scanned'},{key:'notConfirmedScanned',label:'Not confirmed scanned'}],discoveryResult.coverage));
 const actions=elem('div','vault-controls');
 actions.appendChild(vaultButton('Export discovery report (JSON)',()=>download('trufflehog-discovery-pulse.json',JSON.stringify({format:'trufflehog-discovery-pulse',version:1,comparison:discoveryResult},null,2),'application/json')));
 actions.appendChild(vaultButton('Export comparison CSV',()=>download('trufflehog-discovery-pulse.csv','\uFEFF'+currentCSV(),'text/csv;charset=utf-8')));
 container.appendChild(actions);
 container.appendChild(elem('h2','spaced-heading','Changed observations'));
 const rows=matches(discoveryResult.rows);
 if(!rows.length)empty(container,'No changes recorded','This does not guarantee the two capture sessions saw the same pages or resource bodies.');
 else container.appendChild(buildTable([{key:'status',label:'Comparison'},{key:'identity',label:'Service hostname',css:'mono'},{key:'role',label:'Observed role'},{key:'previous',label:'Earlier'},{key:'current',label:'Later'},{key:'confidence',label:'Limitation'}],rows));
}
function renderDAMSpecialists(container){
 const result=THIDAMSpecialists.analyze(record);
 container.appendChild(elem('p','warn-note','Specialist recognition is passive, not a security assessment. A vendor-owned service can appear on sites powered by another DAM. ResourceSpace and Capture-style field names are not unique. No credentials are validated, no URLs are generated, and no media is downloaded.'));
 const stats=elem('div','simple-grid');
 stats.appendChild(panel('Platform candidates',String(result.stats.platforms),'Includes weak, unconfirmed field and code clues.'));
 stats.appendChild(panel('Network-supported candidates',String(result.stats.observed),'Indicates at least one matched observed HTTP request, not backend ownership.'));
 stats.appendChild(panel('Analysed requests',String(result.stats.requestCount),'Bounded to '+result.limits.requests+' recent requests.'));
 container.appendChild(stats);
 const rows=matches(result.profiles);
 if(!rows.length){empty(container,'No specialist DAM evidence observed','Browse an authorised DAM page with capture enabled. Third-party vendor references and self-hosted installations may remain ambiguous.');return;}
 container.appendChild(buildTable([
  {key:'vendor',label:'Platform / service'},
  {key:'kind',label:'Role'},
  {key:'confidence',label:'Evidence assessment',badge:v=>v==='Strong indication'?'success':'warn'},
  {key:'role',label:'Relationship to captured site'},
  {key:'observedRequests',label:'Unique observed indicators'},
  {key:'access',label:'Delivery/access evidence'},
  {key:'evidence',label:'Why identified'},
  {key:'ownerReview',label:'Owner-side review'}],rows));
 const btn=vaultButton('Export specialist report (redacted JSON)',()=>{
   download(fileName()+'-dam-specialists.json',JSON.stringify(THIDAMSpecialists.report(record),null,2),'application/json');
   notice('Exported specialist evidence with fixed labels and no raw URLs or credential values.');
 });
 container.appendChild(btn);
 container.appendChild(elem('p','helper','Evidence categories are validated against documented vendor conventions, but hostname matching and prior code recognition do not establish product version, licence entitlement or deployment architecture.'));
}

function renderHARPrivacyReport(container,report){
 container.replaceChildren();
 if(!report){container.appendChild(elem('p','helper','Select a HAR and run the local privacy preflight before comparing it with a saved capture.'));return;}
 container.appendChild(elem('h2','spaced-heading',report.assessment));
 const g=elem('div','simple-grid');
 g.appendChild(panel('HAR entries checked',String(report.coverage.entries),'Structure only'));
 g.appendChild(panel('Malformed entries',String(report.coverage.malformed),'Not inspected'));
 g.appendChild(panel('Non-HTTP entries',String(report.coverage.nonHttp),'Excluded'));
 container.appendChild(g);
 container.appendChild(buildTable([{key:'category',label:'Potentially sensitive structure'},{key:'count',label:'Affected entries'}],report.rows));
 for(const line of report.advice)container.appendChild(elem('p','helper',line));
 container.appendChild(elem('p','warn-note',report.limitations));
 const exp=elem('div','vault-controls');container.appendChild(exp);
 exp.appendChild(vaultButton('Export privacy preflight (redacted JSON)',()=>download('trufflehog-har-privacy.json',JSON.stringify(report,null,2),'application/json')));
 exp.appendChild(vaultButton('Export privacy counts CSV',()=>{
  const lines=[['category','count'].map(csvValue).join(','),...report.rows.map(row=>[row.category,row.count].map(csvValue).join(','))];
  download('trufflehog-har-privacy.csv','\uFEFF'+lines.join('\r\n'),'text/csv;charset=utf-8');
 }));
}
function renderGenericIntelligence(container){
 if(!record){empty(container,'No capture available','Start a permitted capture on any website. No platform identification is required.');return;}
 const report=THIGenericIntelligence.analyze(record),summary=elem('div','simple-grid');
 container.appendChild(elem('p','warn-note','Generic-first read-only analysis of this capture. No vendor recognition, extra requests, credential values or raw asset URLs. Header/signature indicators require prior explicit Download observer opt-in. Observed traffic never proves a vulnerability or original-file entitlement.'));
 summary.appendChild(panel('HTTP observations',String(report.overview.observedRequests),'Only completed or failed requests retained in this capture.'));
 summary.appendChild(panel('Site-origin requests',String(report.overview.sameOriginRequests),'Exact scheme, hostname and port comparison.'));
 summary.appendChild(panel('External-origin requests',String(report.overview.externalOriginRequests),'No origin or hostnames in this report.'));
 summary.appendChild(panel('Dropped observations',String(report.overview.droppedEvents),'Capped records can cause incomplete conclusions.'));
 container.appendChild(summary);
 container.appendChild(elem('h2','spaced-heading','Universal behaviour indicators'));
 container.appendChild(buildTable([{key:'category',label:'Behaviour'},{key:'count',label:'Observed'},{key:'meaning',label:'Interpretation'},{key:'qualification',label:'Evidence limit'}],matches(report.rows)));
 if(report.warnings.length){container.appendChild(elem('h3','spaced-heading','Capture limitations'));for(const warning of report.warnings)container.appendChild(elem('p','helper','• '+warning));}
 const actions=elem('div','vault-controls');container.appendChild(actions);
 actions.appendChild(vaultButton('Export generic report (redacted JSON)',()=>download('trufflehog-generic-traffic.json',JSON.stringify(report,null,2),'application/json')));
 actions.appendChild(vaultButton('Export generic report CSV',()=>{
  const cols=['category','count','evidence','meaning','qualification'];
  const lines=[cols.map(csvValue).join(','),...report.rows.map(r=>cols.map(k=>csvValue(r[k])).join(','))];
  download('trufflehog-generic-traffic.csv','\uFEFF'+lines.join('\r\n'),'text/csv;charset=utf-8');
 }));
 container.appendChild(elem('p','helper',report.caution));
}
function renderGenericSequence(container){
 if(!record){empty(container,'No capture available','Capture a website with permission. Request timelines and opt-in lifecycle facts are analysed entirely offline.');return;}
 const report=THIGenericSequence.analyze(record),summary=elem('div','simple-grid');
 container.appendChild(elem('p','warn-note','Observed ordering only: consecutive HTTP completion timestamps within 30 seconds are NOT proof of causation, a common asset, a workflow, authentication, or download linkage. Exact private browser labels link individual lifecycle stages internally but never leave this aggregate report.'));
 summary.appendChild(panel('Timed HTTP responses',String(report.overview.timedHTTP),'Valid completion timestamps within the retained sample.'));
 summary.appendChild(panel('Adjacent pairs',String(report.overview.adjacentPairs),'Consecutive, strictly ordered HTTP completions no more than 30 seconds apart.'));
 summary.appendChild(panel('HTTP lifecycle groups',String(report.overview.groupedHTTPLifecycles),'Opt-in events sharing a private local browser request ID.'));
 summary.appendChild(panel('Browser download groups',String(report.overview.groupedBrowserDownloads),'Opt-in events sharing a local download reference.'));
 container.appendChild(summary);
 container.appendChild(elem('h2','spaced-heading','Observed HTTP type transitions'));
 container.appendChild(buildTable([{key:'transition',label:'Consecutive types'},{key:'count',label:'Observed pairs'},{key:'qualification',label:'Interpretation limit'}],report.transitions.filter(row=>row.count>0)));
 container.appendChild(elem('h2','spaced-heading','Lifecycle stage coverage'));
 container.appendChild(buildTable([{key:'stage',label:'Observed lifecycle condition'},{key:'count',label:'Count'},{key:'evidence',label:'Grouping evidence'}],report.lifecycles));
 if(report.warnings.length){container.appendChild(elem('h3','spaced-heading','Capture limitations'));for(const warning of report.warnings)container.appendChild(elem('p','helper','• '+warning));}
 const actions=elem('div','vault-controls');container.appendChild(actions);
 actions.appendChild(vaultButton('Export transition report (redacted JSON)',()=>download('trufflehog-generic-sequence.json',JSON.stringify(report,null,2),'application/json')));
 actions.appendChild(vaultButton('Export transition counts CSV',()=>{
  const cols=['transition','count','evidence','qualification'];
  const lines=[cols.map(csvValue).join(','),...report.transitions.map(r=>cols.map(k=>csvValue(r[k])).join(','))];
  download('trufflehog-generic-sequence.csv','\uFEFF'+lines.join('\r\n'),'text/csv;charset=utf-8');
 }));
 container.appendChild(elem('p','helper',report.caution));
}
function renderAssetLicensing(container){
 if(!record){empty(container,'No capture available','Start a permitted capture, enable JSON shapes and open Chrome DevTools on the inspected page.');return;}
 const report=THIAssetLicensing.analyze(record),summary=elem('div','simple-grid');
 container.appendChild(elem('p','warn-note','Generic and passive: pricing and size listings are metadata, not file entitlements. Even a completed download does not prove the original master was delivered. To read licensing JSON, enable JSON shapes and keep DevTools open on the source tab. No raw IDs, URLs, credentials or response bodies are retained by this module.'));
 summary.appendChild(panel('Licensing JSON inspected',String(report.overview.inspectedJSON),'Requires DevTools + JSON-shape opt-in.'));
 summary.appendChild(panel('Original options advertised',String(report.overview.originalAdvertised),'A listed option is not a delivered file.'));
 summary.appendChild(panel('Original options selectable',String(report.overview.originalSelectable),'Licensing selection is not entitlement.'));
 summary.appendChild(panel('Original verified delivered',String(report.overview.originalDeliveredVerified),'No automatic promotion from names, labels or file size.'));
 summary.appendChild(panel('HTTP file responses',String(report.overview.httpFileResponses),'Observed network responses are not browser download completions.'));
 summary.appendChild(panel('Browser downloads completed',String(report.overview.browserDownloadsCompleted),'Requires separately enabled Download observer.'));
 container.appendChild(summary);
 container.appendChild(elem('h2','spaced-heading','Generic classifications'));
 if(report.rows.length)container.appendChild(buildTable([{key:'category',label:'Classification'},{key:'count',label:'Observations'},{key:'basis',label:'Evidence source'},{key:'confidence',label:'Assessment'}],report.rows));
 else container.appendChild(elem('p','helper','No licensing-related traffic detected in this capture. This is not proof the website has no licensing system.'));
 if(report.observations.length){
   container.appendChild(elem('h2','spaced-heading','Observed licensing trees'));
   const list=elem('div','simple-grid');
   for(const item of report.observations.slice(-30)){
     const originals=item.original?.advertised?'Original advertised'+(item.original.selectable?' · selectable':''):'Original unverified';
     list.appendChild(panel(item.assetRef||'Anonymous asset / schema',`${item.licences.length} licence nodes · ${item.sizes.length} sizes`,`${originals} · ${item.status} · ${item.prices.length} bounded price entries. No raw identifiers retained.`));
   }
   container.appendChild(list);
   container.appendChild(elem('h2','spaced-heading','Anonymous licence, size and price details'));
   const safe=[];
   for(const item of report.observations.slice(-30))for(const l of item.licences.slice(0,50))safe.push({asset:item.assetRef||'Unlinked',ref:l.ref||'Anonymous',parent:l.parentRef||'—',recommended:l.recommendedSizeRef||'—',maximum:l.maxSizeRef||'—',selectable:l.selectable===null?'Unknown':String(l.selectable),eligible:l.allowed===null?'Unknown':String(l.allowed),usage:l.usage});
   if(safe.length)container.appendChild(buildTable([{key:'asset',label:'Asset reference'},{key:'ref',label:'Licence ref'},{key:'parent',label:'Parent licence'},{key:'recommended',label:'Recommended size ID (anonymous)'},{key:'maximum',label:'Max size ID (anonymous)'},{key:'selectable',label:'Selectable'},{key:'eligible',label:'Eligible flag'},{key:'usage',label:'Use class'}],safe.slice(0,100)));
   const sizeRows=report.observations.flatMap(x=>x.sizes.map(s=>({asset:x.assetRef||'Unlinked',licence:s.licenceRef||'Unlinked',type:s.type,dimensions:s.width&&s.height?`${s.width}×${s.height} (advertised fields)`:s.labelPixels?`${s.labelPixels} pixels (advertised label)`:'Not specified',recommended:s.recommended===true?'Yes':s.recommended===false?'No':'Unknown'})));
   if(sizeRows.length)container.appendChild(buildTable([{key:'asset',label:'Asset'},{key:'licence',label:'Licence ref'},{key:'type',label:'Advertised size class'},{key:'dimensions',label:'Advertised dimensions'},{key:'recommended',label:'Recommended'}],sizeRows.slice(0,100)));
   const prices=report.observations.flatMap(x=>x.prices.map(p=>({asset:x.assetRef||'Unlinked',licence:p.licenceRef||'Unlinked',amount:p.amount===null?'Unknown':String(p.amount),net:p.net===null?'—':String(p.net),gross:p.gross===null?'—':String(p.gross),credits:p.credits===null?'—':String(p.credits),factor:p.factor===null?'—':String(p.factor),currency:p.currency||'Unknown',tax:p.tax===null?'Unknown':String(p.tax),classification:p.kind})));
   if(prices.length)container.appendChild(buildTable([{key:'asset',label:'Asset'},{key:'licence',label:'Licence ref'},{key:'amount',label:'Advertised amount'},{key:'net',label:'Net'},{key:'gross',label:'Gross'},{key:'credits',label:'Credits'},{key:'factor',label:'Factor'},{key:'currency',label:'Currency'},{key:'tax',label:'Tax rate'},{key:'classification',label:'Condition'}],prices.slice(0,100)));
 }
 if(report.deliveries.length){container.appendChild(elem('h2','spaced-heading','Observed file response evidence (unlinked)'));
 container.appendChild(buildTable([{key:'method',label:'Method'},{key:'status',label:'HTTP status'},{key:'mime',label:'MIME'},{key:'bytes',label:'Reported bytes'},{key:'attachment',label:'Attachment'},{key:'original',label:'Original-resolution verification'}],report.deliveries));}
 for(const warning of report.limitations)container.appendChild(elem('p','helper','• '+warning));
 const actions=elem('div','vault-controls');container.appendChild(actions);
 actions.appendChild(vaultButton('Export licensing intelligence (redacted JSON)',()=>download('trufflehog-asset-licensing.json',JSON.stringify(report,null,2),'application/json')));
 actions.appendChild(vaultButton('Export licensing counts CSV',()=>{
  const cols=['category','count','basis','confidence'];
  const lines=[cols.map(csvValue).join(','),...report.rows.map(r=>cols.map(k=>csvValue(r[k])).join(','))];
  download('trufflehog-asset-licensing.csv','\uFEFF'+lines.join('\r\n'),'text/csv;charset=utf-8');
 }));
}
function renderProductAssetRelationships(container){
 if(!record){empty(container,'No capture available','Navigate to a permitted site, open F12, then reload to inspect new JSON/media responses.');return;}
 const report=THIProductAsset.analyze(record),summary=elem('div','simple-grid');
 container.appendChild(elem('p','warn-note','Generic evidence only. A storefront product record does not prove PIM software. Rendition-level linkage needs matching transformation details; a shared asset ID or pathname establishes only an asset-family association. DevTools must be open for response-body interpretation. No native original, licence or purchase entitlement is inferred.'));
 for(const [label,value,tip] of [['Product records',report.overview.productRecords,'Responses with multiple product traits'],['Media responses',report.overview.mediaResponses,'DevTools-observed media HTTP'],['Matching renditions',report.overview.exactRelationships,'Matching observed rendition descriptor; not identical-byte proof'],['Asset-family matches',report.overview.assetFamilyRelationships,'Shared ID or path, rendition unverified'],['Matching HTTP media',report.overview.httpMediaDeliveries,'Not a verified native master'],['Unverified associations',report.overview.unverifiedRelations,'Listed but no matching media HTTP response'],['Dropped records',report.overview.dropped,'Coverage may be incomplete']])summary.appendChild(panel(label,String(value),tip));
 container.appendChild(summary);
 container.appendChild(elem('h2','spaced-heading','Structured product observations'));
 container.appendChild(report.types.length?buildTable([{key:'label',label:'Classification'},{key:'count',label:'Count'},{key:'evidence',label:'Source'},{key:'qualification',label:'Limit'}],report.types):elem('p','helper','No product JSON evidence. Keep DevTools open while loading a page that returns product metadata.'));
 container.appendChild(elem('h2','spaced-heading','Product-to-asset reference evidence'));
 container.appendChild(report.rows.length?buildTable([{key:'productRef',label:'Anonymous product'},{key:'variants',label:'Variants'},{key:'assets',label:'Media links'},{key:'channels',label:'Channels'},{key:'locales',label:'Localisations'},{key:'confidence',label:'Evidence'},{key:'delivery',label:'Observed outcome'}],report.rows):elem('p','helper','No cross-resource relationships identified.'));
 for(const message of report.limits)container.appendChild(elem('p','helper','• '+message));
 const actions=elem('div','vault-controls');container.appendChild(actions);
 actions.appendChild(vaultButton('Export product relationship JSON',()=>download('trufflehog-product-relationships.json',JSON.stringify(report,null,2),'application/json')));
 actions.appendChild(vaultButton('Export product relationships CSV',()=>download('trufflehog-product-relationships.csv','\uFEFF'+['productRef','variants','assets','channels','locales','confidence','delivery'].map(csvValue).join(',')+'\r\n'+report.rows.map(r=>['productRef','variants','assets','channels','locales','confidence','delivery'].map(k=>csvValue(r[k])).join(',')).join('\r\n'),'text/csv;charset=utf-8')));
}
function renderHybridWorkflow(container){
 if(!record){empty(container,'No capture available','This view analyses previously observed traffic only.');return;}
 const report=THIHybridWorkflow.analyze(record),summary=elem('div','simple-grid');
 container.appendChild(elem('p','warn-note','Vendor-neutral role inventory, not a reconstructed private backend. Counts of documents, API traffic, media, redirects and downloads must not be treated as causal links.'));
 summary.appendChild(panel('HTTP events',String(report.overview.requests),'Captured browser request metadata'));
 summary.appendChild(panel('Cross-origin requests',String(report.overview.externalOriginResponses),'Not proof of separate storage systems'));
 summary.appendChild(panel('Matching rendition references',String(report.overview.exactProductMediaMatches),'Matching observed transformation descriptors; not proof of identical bytes'));
 summary.appendChild(panel('Asset-family references',String(report.overview.assetFamilyProductMediaMatches),'Shared asset or path; rendition unverified'));
 container.appendChild(summary);
 container.appendChild(buildTable([{key:'name',label:'Observed stage'},{key:'count',label:'Events'},{key:'quality',label:'Evidence basis'},{key:'interpretation',label:'Limitation'}],report.rows));
 for(const message of report.limits)container.appendChild(elem('p','helper','• '+message));
 const actions=elem('div','vault-controls');container.appendChild(actions);
 actions.appendChild(vaultButton('Export workflow evidence JSON',()=>download('trufflehog-hybrid-workflow.json',JSON.stringify(report,null,2),'application/json')));
}
function renderSecurityIntelligence(container){
 const observations=record?.securityObservations||[];
 const aggregated=THISecurityIntelligence.summarize(observations);
 container.appendChild(elem('p','warn-note','This is passive, local security-condition intelligence—not an exploit scanner. Exact evidence means the browser observed the stated header, URL parameter or redirect; it does not establish a working credential, access-control bypass or affected CVE. Sensitive values are never stored in this view. Some headers may be unavailable without extraHeaders; response-body detection still requires DevTools.'));
 const summary=elem('div','simple-grid');
 summary.appendChild(panel('Unique observed patterns',String(observations.length),'Deduplicated by rule and safe path'));
 summary.appendChild(panel('Review-level patterns',String(observations.filter(x=>x.severity==='high-review'||x.severity==='review').length),'Investigation candidates, not confirmed vulnerabilities'));
 summary.appendChild(panel('Dropped security observations',String(record?.securityObservationsDropped||0),'Limited live storage buffer'));
 summary.appendChild(panel('Rule families',String(aggregated.length),'Generic, vendor-independent analysis'));
 container.appendChild(summary);
 container.appendChild(elem('h2','spaced-heading','Pattern summary'));
 if(aggregated.length)container.appendChild(buildTable([{key:'title',label:'Condition'},{key:'severity',label:'Review level'},{key:'count',label:'Distinct locations'}],aggregated));
 else container.appendChild(elem('p','helper','No security review indicators observed in the current session. This is not a security clearance.'));
 container.appendChild(elem('h2','spaced-heading','Evidence-linked observations'));
 if(observations.length){
  const rows=[...observations].reverse();
  container.appendChild(buildTable([{key:'at',label:'First seen'},{key:'title',label:'Rule'},{key:'severity',label:'Priority'},{key:'host',label:'Host'},{key:'route',label:'Safe route'},{key:'markers',label:'Indicators'},{key:'declaration',label:'Expiry declaration'},{key:'occurrences',label:'Sightings'}],rows));
 } else container.appendChild(elem('p','helper','Browse a permitted site with automatic capture running to collect passive metadata.'));
 for(const row of aggregated){const item=observations.find(o=>o.ruleId===row.ruleId);if(!item)continue;
  container.appendChild(elem('p','helper',`${row.title}: ${item.limitation} Suggested review: ${item.recommendation}`));
 }
 const actions=elem('div','vault-controls');container.appendChild(actions);
 actions.appendChild(vaultButton('Export sanitised findings JSON',()=>download('trufflehog-security-conditions.json',JSON.stringify({schema:'trufflehog-security-observations-v1',observations,limitations:['Passive observations only','No active checks','Not proof of CVE or exploitability']},null,2),'application/json')));
 const cols=['at','ruleId','title','severity','confidence','host','route','method','classification','declaration','scope','markers','occurrences'];
 actions.appendChild(vaultButton('Export sanitised CSV',()=>download('trufflehog-security-conditions.csv','\uFEFF'+[cols.map(csvValue).join(','),...observations.map(r=>cols.map(k=>csvValue(r[k])).join(','))].join('\r\n'),'text/csv;charset=utf-8')));
 container.appendChild(elem('h2','spaced-heading','Offline HAR security review'));
 container.appendChild(elem('p','helper','Choose a local HAR file. Only the listed HTTP entries are inspected in memory (12 MB / 3,000 entries maximum). This does not replay requests or export credentials.'));
 const controls=elem('div','vault-controls');container.appendChild(controls);
 const picker=document.createElement('input');picker.type='file';picker.accept='.har,.json,application/json';picker.setAttribute('aria-label','Choose a local HAR to analyse offline');controls.appendChild(picker);
 const resultNode=elem('div');container.appendChild(resultNode);
 picker.addEventListener('change',async()=>{
  resultNode.replaceChildren();const file=picker.files?.[0];if(!file)return;
  if(file.size>12*1024*1024){resultNode.appendChild(elem('p','warn-note','File exceeds local 12 MB cap. Nothing was read.'));picker.value='';return;}
  try{
   const analysis=THISecurityIntelligence.analyzeHar(await file.text());
   if(!analysis.ok){resultNode.appendChild(elem('p','warn-note',analysis.reason));return;}
   resultNode.appendChild(elem('h3','spaced-heading',`${analysis.reviewed} HAR entries reviewed · ${analysis.observations.length} observations`));
   if(analysis.truncated)resultNode.appendChild(elem('p','warn-note','Only the first 3,000 entries were analysed.')); 
   resultNode.appendChild(buildTable([{key:'title',label:'Condition'},{key:'severity',label:'Review level'},{key:'count',label:'Sightings'}],THISecurityIntelligence.summarize(analysis.observations)));
   resultNode.appendChild(vaultButton('Export HAR findings (safe JSON)',()=>download('trufflehog-har-security-observations.json',JSON.stringify(analysis,null,2),'application/json')));
  }catch{resultNode.appendChild(elem('p','warn-note','Could not analyse the selected HAR.'));}
  finally{picker.value='';}
 });
}
function renderImportPreflight(container){
 container.appendChild(elem('p','warn-note','Inspect a locally selected HAR, cURL or PowerShell capture for secret-looking patterns BEFORE importing or sharing it. The contents are examined in memory only; they are never submitted, stored or exported by this view. This is a warning heuristic, not a credential validator.'));
 const controls=elem('div','vault-controls');container.appendChild(controls);
 const picker=document.createElement('input');picker.type='file';picker.accept='.txt,.log,.har,.json,application/json,text/plain';
 picker.setAttribute('aria-label','Choose a local capture file to inspect');controls.appendChild(picker);
 const output=elem('div');container.appendChild(output);
 picker.addEventListener('change',async()=>{
   output.replaceChildren();const file=picker.files?.[0];if(!file)return;
   if(file.size>12*1024*1024){output.appendChild(elem('p','warn-note','File exceeds 12 MB inspection cap. Nothing was read.'));return;}
   try{
     const result=THIImportPrivacy.inspect(await file.text());
     if(!result.ok){output.appendChild(elem('p','warn-note',result.reason));return;}
     output.appendChild(elem('h2','spaced-heading',`${result.foundCategories} indicator categories · ${result.indicators} matches`));
     output.appendChild(elem('p','helper',result.advice));
     if(result.rows.length)output.appendChild(buildTable([{key:'category',label:'Potential sensitive data'},{key:'count',label:'Matches (capped)'},{key:'assessment',label:'Action'}],result.rows));
   }catch{output.appendChild(elem('p','warn-note','Could not inspect the selected file locally.'));}
   finally{picker.value='';}
 });
}
function renderUniversalBoundaries(container){
 if(!record){empty(container,'No capture available','Start an authorised opt-in capture. This offline view does not request any website.');return;}
 const report=THIUniversalBoundaryReview.analyze(record),summary=elem('div','simple-grid');
 container.appendChild(elem('p','warn-note',report.interpretation+' '+report.notTested));
 summary.appendChild(panel('HTTP records reviewed',String(report.overview.inspectedHTTP),'Only stored browser observations.'));
 summary.appendChild(panel('Observed signature markers',String(report.overview.explicitSigningRequests),'An observed marker does not validate a URL or a credential.'));
 summary.appendChild(panel('Observer stages reviewed',String(report.overview.inspectedObserverEvents),'Optional redirect observer requires separate opt-in.'));
 summary.appendChild(panel('Dropped observations',String(report.overview.droppedObservations),'Incomplete captures limit conclusions.'));
 container.appendChild(summary);
 container.appendChild(elem('h2','spaced-heading','Delivery, processing and access-boundary clues'));
 container.appendChild(buildTable([{key:'category',label:'Observed evidence type'},{key:'count',label:'Count'},{key:'evidence',label:'Basis'},{key:'qualification',label:'Interpretation limit'}],report.rows));
 if(report.warnings.length){container.appendChild(elem('h3','spaced-heading','Coverage warnings'));for(const warning of report.warnings)container.appendChild(elem('p','helper','• '+warning));}
 const actions=elem('div','vault-controls');container.appendChild(actions);
 actions.appendChild(vaultButton('Export delivery-boundary review (redacted JSON)',()=>download('trufflehog-universal-boundaries.json',JSON.stringify(report,null,2),'application/json')));
 actions.appendChild(vaultButton('Export delivery-boundary counts CSV',()=>{
  const cols=['category','count','evidence','qualification'];
  const lines=[cols.map(csvValue).join(','),...report.rows.map(r=>cols.map(k=>csvValue(r[k])).join(','))];
  download('trufflehog-universal-boundaries.csv','\uFEFF'+lines.join('\r\n'),'text/csv;charset=utf-8');
 }));
 container.appendChild(elem('p','helper','The table is a review inventory for site owners, not an exploit scanner or a verified vulnerability report.'));
}
function renderGenericRelationships(container){
 if(!record){empty(container,'No capture available','Capture an authorised website to inspect relationships from existing records, offline.');return;}
 const report=THIGenericRelationshipConfidence.analyze(record),summary=elem('div','simple-grid');
 container.appendChild(elem('p','warn-note',report.grading));
 summary.appendChild(panel('Exact HTTP lifecycles',String(report.overview.exactHTTPGroups),'Matching request and terminal browser event labels only.'));
 summary.appendChild(panel('Exact download lifecycles',String(report.overview.exactDownloadGroups),'Matching browser download stages, not HTTP request attribution.'));
 summary.appendChild(panel('Shared context pairs',String(report.overview.structuralContextPairs),'Same private document/frame/initiator, uniquely ordered within 30 seconds.'));
 summary.appendChild(panel('Timing-only pairs',String(report.overview.timingOnlyPairs),'Unique adjacent completion timestamps within 30 seconds.'));
 container.appendChild(summary);
 container.appendChild(elem('h2','spaced-heading','Relationship evidence grades'));
 container.appendChild(buildTable([{key:'grade',label:'Grade'},{key:'signal',label:'Observed signal'},{key:'count',label:'Count'},{key:'scope',label:'Interpretation limit'}],report.rows));
 if(report.warnings.length){container.appendChild(elem('h3','spaced-heading','Evidence limitations'));for(const warning of report.warnings)container.appendChild(elem('p','helper','• '+warning));}
 const actions=elem('div','vault-controls');container.appendChild(actions);
 actions.appendChild(vaultButton('Export relationship grades (redacted JSON)',()=>download('trufflehog-generic-relationships.json',JSON.stringify(report,null,2),'application/json')));
 actions.appendChild(vaultButton('Export relationship grades CSV',()=>{
  const cols=['grade','signal','count','evidence','scope'];
  const lines=[cols.map(csvValue).join(','),...report.rows.map(r=>cols.map(k=>csvValue(r[k])).join(','))];
  download('trufflehog-generic-relationships.csv','\uFEFF'+lines.join('\r\n'),'text/csv;charset=utf-8');
 }));
 container.appendChild(elem('p','helper',report.caution));
}
function renderHARCoverage(container){
 container.appendChild(elem('p','warn-note','Compare a Chrome DevTools HAR from the SAME authorised browser session with a saved Trufflehog capture. HAR files can still contain sensitive URLs, bodies and headers even when exported as sanitised. Review the HAR privacy preflight before reconciliation. Neither trace guarantees complete coverage.'));
 const groups=THIPro.groupRows(sessionsCache);
 const controls=elem('div','vault-controls');container.appendChild(controls);
 controls.appendChild(vaultButton('Refresh saved groups',async()=>{harCoverageReport=null;harTriageReport=null;await loadVault();drawView();}));
 const opts=groups.map(g=>({id:g.id,origin:g.origin,startedAt:g.first}));
 const selected=groups.length?choose('Saved capture group',opts,harCoverageSelected||groups[0].id):null;
 if(selected)controls.appendChild(selected.wrap);
 const label=document.createElement('label');label.className='vault-selector';
 label.appendChild(elem('span','','DevTools HAR file (JSON, maximum 12 MB)'));
 const input=document.createElement('input');input.type='file';input.accept='.har,.json,application/json';
 label.appendChild(input);controls.appendChild(label);
 let inspectedFile=null;
 const privacyHolder=elem('div');privacyHolder.dataset.harPrivacy='';container.appendChild(privacyHolder);
 renderHARPrivacyReport(privacyHolder,harPrivacyReport);
 const invalidate=()=>{harCoverageReport=null;harTriageReport=null;harPrivacyReport=null;harDAMReport=null;harSequenceReport=null;harStageCompareReport=null;inspectedFile=null;harCoverageSelected=selected?.select.value||null;drawView();};
 selected?.select.addEventListener('change',invalidate);
 input.addEventListener('change',()=>{
  inspectedFile=null;harPrivacyReport=null;harCoverageReport=null;harTriageReport=null;harDAMReport=null;harSequenceReport=null;harStageCompareReport=null;
  harDeliveryComparison=null;harAccessComparison=null;harBoundaryComparison=null;harRangeComparison=null;harCacheComparison=null;harNegotiationComparison=null;deliveryPostureReport=null;accessMatrixReport=null;redirectBoundaryReport=null;rangeEvidenceReport=null;cacheRevalidationReport=null;imageNegotiationReport=null;const ng=container.querySelector('[data-har-negotiation]');if(ng)ng.replaceChildren(elem('p','helper','First HAR changed; repeat privacy review.'));const am=container.querySelector('[data-har-access]');if(am)am.replaceChildren(elem('p','helper','First HAR changed; repeat privacy review.'));const rb=container.querySelector('[data-har-boundaries]');if(rb)rb.replaceChildren(elem('p','helper','First HAR changed; repeat privacy review.'));const re=container.querySelector('[data-har-ranges]');if(re)re.replaceChildren(elem('p','helper','First HAR changed; repeat privacy review.'));const cr=container.querySelector('[data-har-cache]');if(cr)cr.replaceChildren(elem('p','helper','First HAR changed; repeat privacy review.'));const dp=container.querySelector('[data-har-delivery]');if(dp)dp.replaceChildren(elem('p','helper','First HAR changed; repeat privacy preflight.'));
  renderHARPrivacyReport(privacyHolder,null);
  const dam=container.querySelector('[data-har-dam]');if(dam)dam.replaceChildren(elem('p','helper','New HAR selected. Run the privacy preflight again.'));
  const seq=container.querySelector('[data-har-sequence]');if(seq)seq.replaceChildren(elem('p','helper','New HAR selected. Run the privacy preflight again.'));
  const compare=container.querySelector('[data-har-stage-compare]');if(compare)compare.replaceChildren(elem('p','helper','First HAR changed. Repeat privacy preflight before comparing.'));
  const content=container.querySelector('[data-har-report]');if(content)content.replaceChildren(elem('p','helper','HAR changed. Run privacy preflight, then reconciliation.'));
 });
 async function readSelectedHar(){
  const file=input.files?.[0];if(!file)throw Error('Choose an exported HAR file');
  if(file.size>12*1024*1024)throw Error('HAR exceeds the 12 MB local safety limit');
  let parsed;try{parsed=JSON.parse(await file.text());}catch{throw Error('The selected file is not valid HAR JSON');}
  return {file,parsed};
 }
 controls.appendChild(vaultButton('1. Inspect HAR privacy locally',async()=>{
  const {file,parsed}=await readSelectedHar();
  const report=THIHARPrivacy.audit(parsed);
  harPrivacyReport=report;inspectedFile=file;
  renderHARPrivacyReport(privacyHolder,report);
  notice('HAR privacy preflight completed locally. The original HAR is not safe to share without separate review.');
 },'primary'));
 // v7.0: offline evidence inventory is independent of an extension capture.
 const damHolder=elem('div');damHolder.dataset.harDam='';container.appendChild(damHolder);
 function renderDAMWorkflowReport(){
  damHolder.replaceChildren();const r=harDAMReport;
  if(!r){damHolder.appendChild(elem('p','helper','Offline DAM workflow inventory is available after HAR privacy review, with or without a saved capture.'));return;}
  damHolder.appendChild(elem('h2','spaced-heading','Offline DAM & media workflow inventory'));
  const g=elem('div','simple-grid');
  for(const [label,key] of [['HAR entries','totalEntries'],['HTTP entries inspected','inspectedHttp'],['Excluded entries','excludedEntries']])g.appendChild(panel(label,String(r.coverage[key]),'Fixed-category evidence only'));
  damHolder.appendChild(g);
  for(const [heading,rows] of [['Observed service indicators',r.providers],['Request and delivery stages',r.stages],['Authentication, signature and cache signals',r.indicators],['HTTP methods',r.methods],['HTTP status classes',r.statuses]]){
   damHolder.appendChild(elem('h2','spaced-heading',heading));
   damHolder.appendChild(buildTable([{key:'category',label:'Fixed category'},{key:'count',label:'Observed count'}],rows));
  }
  for(const line of r.limitations)damHolder.appendChild(elem('p','helper',line));
  const exp=elem('div','vault-controls');damHolder.appendChild(exp);
  exp.appendChild(vaultButton('Export offline DAM report (redacted JSON)',()=>download('trufflehog-har-dam.json',JSON.stringify(r,null,2),'application/json')));
  exp.appendChild(vaultButton('Export offline DAM counts CSV',()=>{
   const lines=[['section','category','count'].map(csvValue).join(',')];
   for(const [section,rows] of [['providers',r.providers],['stages',r.stages],['indicators',r.indicators],['methods',r.methods],['statuses',r.statuses]])
    for(const row of rows)lines.push([section,row.category,row.count].map(csvValue).join(','));
   download('trufflehog-har-dam.csv','\uFEFF'+lines.join('\r\n'),'text/csv;charset=utf-8');
  }));
 }
 renderDAMWorkflowReport();
 controls.appendChild(vaultButton('2. Analyse DAM workflow (offline)',async()=>{
  const {file,parsed}=await readSelectedHar();
  if(inspectedFile!==file)throw Error('Run privacy preflight for this exact HAR before offline analysis');
  harPrivacyReport=THIHARPrivacy.audit(parsed); // re-evaluate the current bytes
  harDAMReport=THIHARDAM.audit(parsed);
  renderDAMWorkflowReport();
  notice('Offline DAM inventory produced. Only fixed category labels and numeric counts are exported.');
 },'primary'));
 // v7.5: credential/permission-indicator coverage matrix, no resource identifiers exported.
 const accessHolder=elem('div');accessHolder.dataset.harAccess='';container.appendChild(accessHolder);
 let accessMatrixReport=null;
 let redirectBoundaryReport=null;
 let rangeEvidenceReport=null;
 let cacheRevalidationReport=null;
 let imageNegotiationReport=null;
 function renderHARAccessMatrix(){
  accessHolder.replaceChildren();const r=accessMatrixReport;
  if(!r){accessHolder.appendChild(elem('p','helper','Delivery access matrix: requires a local privacy preflight on the selected HAR.'));return;}
  accessHolder.appendChild(elem('h2','spaced-heading','Offline access indicators × delivery outcomes'));
  accessHolder.appendChild(elem('p','warn-note','No authentication indicator observed is NOT evidence of public or anonymous access. Sanitised HAR exports can omit credentials. The matrix does not validate rights or test security.'));
  const stats=elem('div','simple-grid');for(const [title,key] of [['Delivery-relevant entries','deliveryRelevant'],['Missing request headers','missingRequestHeaders'],['Media-MIME 2xx','mediaMime2xx'],['Attachments 2xx','attachment2xx']])stats.appendChild(panel(title,String(r.coverage[key]),'HAR observation only'));
  accessHolder.appendChild(stats);
  accessHolder.appendChild(buildTable([{key:'authentication',label:'Observed request indicators'},{key:'outcome',label:'Response outcome'},{key:'count',label:'Count'}],r.authOutcomes.filter(x=>x.count>0)));
  accessHolder.appendChild(elem('h2','spaced-heading','Authentication indicators × cache policy'));
  accessHolder.appendChild(buildTable([{key:'authentication',label:'Observed request indicators'},{key:'policy',label:'Response cache category'},{key:'count',label:'Count'}],r.authCache.filter(x=>x.count>0)));
  for(const w of r.warnings)accessHolder.appendChild(elem('p','helper',w));
  const actions=elem('div','vault-controls');accessHolder.appendChild(actions);
  actions.appendChild(vaultButton('Export access observation matrix (redacted JSON)',()=>download('trufflehog-har-access-matrix.json',JSON.stringify(r,null,2),'application/json')));
  actions.appendChild(vaultButton('Export access observation matrix (redacted CSV)',()=>{
   const lines=[['section','request_indicator','outcome_or_cache','count'].map(csvValue).join(',')];
   for(const x of r.authOutcomes)lines.push(['outcome',x.authentication,x.outcome,x.count].map(csvValue).join(','));
   for(const x of r.authCache)lines.push(['cache',x.authentication,x.policy,x.count].map(csvValue).join(','));
   download('trufflehog-har-access-matrix.csv','\uFEFF'+lines.join('\r\n'),'text/csv;charset=utf-8');
  }));
 }
 renderHARAccessMatrix();

 // v7.6: Match only explicit redirect destinations to uniquely observed later requests.
 const boundaryHolder=elem('div');boundaryHolder.dataset.harBoundaries='';container.appendChild(boundaryHolder);
 function renderHARBoundaries(){
  boundaryHolder.replaceChildren();const r=redirectBoundaryReport;
  if(!r){boundaryHolder.appendChild(elem('p','helper','Redirect-boundary analysis requires a privacy-reviewed HAR.'));return;}
  boundaryHolder.appendChild(elem('h2','spaced-heading','Offline redirect & authentication boundaries'));
  boundaryHolder.appendChild(elem('p','warn-note','Only explicit, uniquely matched redirect targets count as linked requests. Cross-origin transitions or authentication header presence are observations, not access-control vulnerabilities.'));
  const summary=elem('div','simple-grid');
  for(const [label,key] of [['Redirect responses','redirectResponses'],['Explicit destinations','redirectLocations'],['Uniquely linked requests','uniquelyMatched'],['Cross-origin linked requests','matchedCrossOrigin']])summary.appendChild(panel(label,String(r.coverage[key]),'This HAR only'));
  boundaryHolder.appendChild(summary);
  boundaryHolder.appendChild(buildTable([{key:'category',label:'Redirect boundary'},{key:'count',label:'Count'}],r.boundaries));
  boundaryHolder.appendChild(elem('h2','spaced-heading','Cross-origin target indicators'));
  boundaryHolder.appendChild(buildTable([{key:'category',label:'Observed condition'},{key:'count',label:'Count'}],r.indicators));
  for(const warning of r.warnings)boundaryHolder.appendChild(elem('p','helper',warning));
  const buttons=elem('div','vault-controls');boundaryHolder.appendChild(buttons);
  buttons.appendChild(vaultButton('Export redirect boundaries (redacted JSON)',()=>download('trufflehog-har-redirect-boundaries.json',JSON.stringify(r,null,2),'application/json')));
  buttons.appendChild(vaultButton('Export redirect boundaries (redacted CSV)',()=>{
   const rows=[['section','category','count'].map(csvValue).join(',')];
   for(const [section,data] of [['boundaries',r.boundaries],['indicators',r.indicators]])for(const item of data)rows.push([section,item.category,item.count].map(csvValue).join(','));
   download('trufflehog-har-redirect-boundaries.csv','\uFEFF'+rows.join('\r\n'),'text/csv;charset=utf-8');
  }));
 }
 renderHARBoundaries();
 controls.appendChild(vaultButton('2d. Inspect redirect boundaries (offline)',async()=>{
  const {file,parsed}=await readSelectedHar();
  if(inspectedFile!==file)throw Error('Run privacy preflight on this exact HAR before redirect analysis');
  THIHARPrivacy.audit(parsed);redirectBoundaryReport=THIHARRedirectBoundaries.audit(parsed);
  renderHARBoundaries();notice('Only fixed redirect-boundary categories and counts are exported.');
 },'primary'));

 // v7.7: independent, fixed-category byte-range evidence; no parts are reassembled or fetched.
 const rangeHolder=elem('div');rangeHolder.dataset.harRanges='';container.appendChild(rangeHolder);
 function renderHARRanges(){
  rangeHolder.replaceChildren();const r=rangeEvidenceReport;
  if(!r){rangeHolder.appendChild(elem('p','helper','Byte-range evidence requires privacy preflight on this exact selected HAR.'));return;}
  rangeHolder.appendChild(elem('h2','spaced-heading','Offline byte-range and transfer evidence'));
  rangeHolder.appendChild(elem('p','warn-note','Reported byte spans are header claims, NOT verified file bytes or completed browser downloads. Repeated ranges are grouped only for exact URL + strong ETag + content coding.'));
  const stats=elem('div','simple-grid');
  for(const [label,key] of [['Partial HTTP 206','partialResponses'],['Valid single-part ranges','validRangeResponses'],['Strong-ETag groups','stableTagGroups'],['Groups with overlap','groupsWithOverlap']])stats.appendChild(panel(label,String(r.coverage[key]),'Observed HAR metadata only'));
  rangeHolder.appendChild(stats);
  rangeHolder.appendChild(buildTable([{key:'category',label:'Fixed response / request indicator'},{key:'count',label:'Count'}],r.signals));
  rangeHolder.appendChild(elem('h2','spaced-heading','Header-declared span buckets (NOT download completion)'));
  rangeHolder.appendChild(buildTable([{key:'category',label:'Conservative grouping'},{key:'count',label:'Count'}],r.spanBuckets));
  for(const w of r.warnings)rangeHolder.appendChild(elem('p','helper',w));
  const actions=elem('div','vault-controls');rangeHolder.appendChild(actions);
  actions.appendChild(vaultButton('Export byte-range evidence (redacted JSON)',()=>download('trufflehog-har-byte-range.json',JSON.stringify(r,null,2),'application/json')));
  actions.appendChild(vaultButton('Export byte-range evidence (redacted CSV)',()=>{
   const lines=[['section','category','count'].map(csvValue).join(',')];
   for(const [section,rows] of [['signals',r.signals],['span-buckets',r.spanBuckets]])for(const item of rows)lines.push([section,item.category,item.count].map(csvValue).join(','));
   download('trufflehog-har-byte-range.csv','\uFEFF'+lines.join('\r\n'),'text/csv;charset=utf-8');
  }));
 }
 renderHARRanges();
 controls.appendChild(vaultButton('2e. Inspect byte-range evidence (offline)',async()=>{
  const {file,parsed}=await readSelectedHar();
  if(inspectedFile!==file)throw Error('Run privacy preflight for this exact HAR before byte-range analysis');
  THIHARPrivacy.audit(parsed);rangeEvidenceReport=THIHARRangeEvidence.audit(parsed);
  renderHARRanges();notice('Only fixed byte-range evidence categories and aggregate counts are exported.');
 },'primary'));
 // v7.8: local HTTP cache validation header observations, distinct from image payloads.
 const cacheHolder=elem('div');cacheHolder.dataset.harCache='';container.appendChild(cacheHolder);
 function renderHARCache(){
  cacheHolder.replaceChildren();const r=cacheRevalidationReport;
  if(!r){cacheHolder.appendChild(elem('p','helper','Cache revalidation analysis requires privacy preflight on the exact selected HAR.'));return;}
  cacheHolder.appendChild(elem('h2','spaced-heading','Offline cache revalidation & 304 evidence'));
  cacheHolder.appendChild(elem('p','warn-note','A 304 validates a stored representation; it does NOT transmit an image or prove origin availability. All counts come from already recorded request/response headers.'));
  const stats=elem('div','simple-grid');
  for(const [label,key] of [['HTTP entries','inspectedHttp'],['Conditional GET/HEAD','conditionalSafeRequests'],['304 responses','notModifiedResponses'],['Missing header entries','missingHeaderEntries']])stats.appendChild(panel(label,String(r.coverage[key]),'HAR observation, not an access test'));
  cacheHolder.appendChild(stats);
  cacheHolder.appendChild(buildTable([{key:'category',label:'Observed fixed-category indicator'},{key:'count',label:'Count'}],r.signals));
  for(const w of r.warnings)cacheHolder.appendChild(elem('p','helper',w));
  const actions=elem('div','vault-controls');cacheHolder.appendChild(actions);
  actions.appendChild(vaultButton('Export cache revalidation (redacted JSON)',()=>download('trufflehog-har-cache-revalidation.json',JSON.stringify(r,null,2),'application/json')));
  actions.appendChild(vaultButton('Export cache revalidation (redacted CSV)',()=>{
   const lines=[['category','count'].map(csvValue).join(','),...r.signals.map(x=>[x.category,x.count].map(csvValue).join(','))];
   download('trufflehog-har-cache-revalidation.csv','\uFEFF'+lines.join('\r\n'),'text/csv;charset=utf-8');
  }));
 }
 renderHARCache();
 controls.appendChild(vaultButton('2f. Inspect cache revalidation (offline)',async()=>{
  const {file,parsed}=await readSelectedHar();
  if(inspectedFile!==file)throw Error('Run privacy preflight on this exact HAR before cache analysis');
  THIHARPrivacy.audit(parsed);cacheRevalidationReport=THIHARCacheRevalidation.audit(parsed);
  renderHARCache();notice('Only fixed cache-validation evidence categories and aggregate counts are exported.');
 },'primary'));
 // v7.9: already-captured image format and Client Hints observations; no network calls.
 const negotiationHolder=elem('div');negotiationHolder.dataset.harNegotiation='';container.appendChild(negotiationHolder);
 function renderHARImageNegotiation(){
  negotiationHolder.replaceChildren();const r=imageNegotiationReport;
  if(!r){negotiationHolder.appendChild(elem('p','helper','Image negotiation analysis requires privacy preflight on this exact local HAR.'));return;}
  negotiationHolder.appendChild(elem('h2','spaced-heading','Offline image formats & content negotiation'));
  negotiationHolder.appendChild(elem('p','warn-note','Format and client-hint header evidence does not establish that an unobserved alternative image exists, that higher quality is accessible, or that any origin/permission policy is misconfigured.'));
  const stats=elem('div','simple-grid');
  for(const [label,key] of [['HTTP entries','inspectedHttp'],['Observed image responses','imageResponses'],['304 media clues','media304Clues'],['Image responses with Accept','imageRequestsWithAcceptHeader']])stats.appendChild(panel(label,String(r.coverage[key]),'Only local HAR metadata'));
  negotiationHolder.appendChild(stats);
  negotiationHolder.appendChild(buildTable([{key:'category',label:'Fixed negotiation indicator'},{key:'count',label:'Count'}],r.signals));
  for(const w of r.warnings)negotiationHolder.appendChild(elem('p','helper',w));
  const exports=elem('div','vault-controls');negotiationHolder.appendChild(exports);
  exports.appendChild(vaultButton('Export negotiation (redacted JSON)',()=>download('trufflehog-har-image-negotiation.json',JSON.stringify(r,null,2),'application/json')));
  exports.appendChild(vaultButton('Export negotiation (redacted CSV)',()=>{
   const rows=[['category','count'].map(csvValue).join(','),...r.signals.map(s=>[s.category,s.count].map(csvValue).join(','))];
   download('trufflehog-har-image-negotiation.csv','\uFEFF'+rows.join('\r\n'),'text/csv;charset=utf-8');
  }));
 }
 renderHARImageNegotiation();
 controls.appendChild(vaultButton('2g. Inspect image negotiation (offline)',async()=>{
  const {file,parsed}=await readSelectedHar();
  if(inspectedFile!==file)throw Error('Run privacy preflight on this exact HAR before image negotiation analysis');
  THIHARPrivacy.audit(parsed);imageNegotiationReport=THIHARImageNegotiation.audit(parsed);
  renderHARImageNegotiation();notice('Only fixed image-format, client-hint and Vary categories with numeric counts are exported.');
 },'primary'));
 controls.appendChild(vaultButton('2c. Inspect access evidence (offline)',async()=>{
  const {file,parsed}=await readSelectedHar();
  if(inspectedFile!==file)throw Error('Run privacy preflight for this exact HAR before access analysis');
  THIHARPrivacy.audit(parsed);accessMatrixReport=THIHARAccessMatrix.audit(parsed);
  renderHARAccessMatrix();notice('Access indicators analysed locally. No credential, URL or source field values included in the report.');
 },'primary'));
 // v7.1: a bounded categorical timeline from the currently selected, reviewed HAR.
 // v7.4: single-HAR media delivery posture from an independently reviewed local HAR.
 const deliveryHolder=elem('div');deliveryHolder.dataset.harDelivery='';container.appendChild(deliveryHolder);
 let deliveryPostureReport=null;
 function renderHARDeliveryPosture(){
  deliveryHolder.replaceChildren();const r=deliveryPostureReport;
  if(!r){deliveryHolder.appendChild(elem('p','helper','Delivery policy inventory: run privacy review before inspecting media cache, signing and attachment indicators.'));return;}
  deliveryHolder.appendChild(elem('h2','spaced-heading','Offline asset delivery policy inventory'));
  deliveryHolder.appendChild(elem('p','warn-note','Headers describe the responses observed in THIS browser session. They do not prove anonymous image access, ownership, policy violations or that cached content remains retrievable.'));
  deliveryHolder.appendChild(buildTable([{key:'category',label:'Fixed delivery indicator'},{key:'count',label:'Observed count'}],r.rows));
  deliveryHolder.appendChild(elem('h2','spaced-heading','Owner-side review candidates (not vulnerabilities)'));
  deliveryHolder.appendChild(buildTable([{key:'category',label:'Combination'},{key:'count',label:'Observed count'}],r.reviewCandidates));
  for(const w of r.limitations)deliveryHolder.appendChild(elem('p','helper',w));
  deliveryHolder.appendChild(vaultButton('Export media delivery inventory (redacted JSON)',()=>download('trufflehog-har-delivery-posture.json',JSON.stringify(r,null,2),'application/json')));
 }
 renderHARDeliveryPosture();
 controls.appendChild(vaultButton('2b. Inspect delivery policies (offline)',async()=>{
  const {file,parsed}=await readSelectedHar();
  if(inspectedFile!==file)throw Error('Run privacy preflight on this HAR before analysing delivery policy');
  THIHARPrivacy.audit(parsed);deliveryPostureReport=THIHARDeliveryPosture.audit(parsed);
  renderHARDeliveryPosture();notice('Delivery policy inspected locally. Output contains only fixed categories and counts.');
 },'primary'));
 const sequenceHolder=elem('div');sequenceHolder.dataset.harSequence='';container.appendChild(sequenceHolder);
 function renderHARSequenceReport(){
  sequenceHolder.replaceChildren();const r=harSequenceReport;
  if(!r){sequenceHolder.appendChild(elem('p','helper','Offline stage timeline is available after privacy review; no Evidence Vault capture is required.'));return;}
  sequenceHolder.appendChild(elem('h2','spaced-heading','Offline DAM stage timeline'));
  const stats=elem('div','simple-grid');
  for(const [label,key] of [['HAR entries','totalEntries'],['Classified stages','candidateStageEvents'],['Shown events (bounded)','shownStageEvents'],['Unshown stages','omittedStageEvents'],['Missing timestamps','missingTimestamps'],['Non-monotonic timestamps','nonMonotonicTimestamps']])
   stats.appendChild(panel(label,String(r.coverage[key]),'Structural observation; not proof of causality'));
  sequenceHolder.appendChild(stats);
  sequenceHolder.appendChild(elem('p','warn-note','Events follow HAR entry order. Sequence proximity cannot establish that a POST authorised a subsequent download. No original timestamps, URLs or request identities are shown or exported.'));
  sequenceHolder.appendChild(buildTable([{key:'order',label:'HAR position'},{key:'stage',label:'Observed stage / clue'},{key:'method',label:'Method'},{key:'status',label:'HTTP class'},{key:'provider',label:'Service signal'},{key:'basis',label:'Classification basis'},{key:'timeBand',label:'Relative time band'}],r.events));
  sequenceHolder.appendChild(elem('h2','spaced-heading','Possible adjacent stage patterns'));
  sequenceHolder.appendChild(buildTable([{key:'category',label:'Ordered HAR pattern (NOT linked requests)'},{key:'count',label:'Count'}],r.patterns));
  for(const warning of r.limitations)sequenceHolder.appendChild(elem('p','helper',warning));
  const exports=elem('div','vault-controls');sequenceHolder.appendChild(exports);
  exports.appendChild(vaultButton('Export stage timeline (redacted JSON)',()=>download('trufflehog-har-sequence.json',JSON.stringify(r,null,2),'application/json')));
  exports.appendChild(vaultButton('Export stage timeline (redacted CSV)',()=>{
   const keys=['order','stage','method','status','provider','basis','timeBand'];
   const lines=[keys.map(csvValue).join(','),...r.events.map(row=>keys.map(k=>csvValue(row[k])).join(','))];
   download('trufflehog-har-sequence.csv','\uFEFF'+lines.join('\r\n'),'text/csv;charset=utf-8');
  }));
 }
 renderHARSequenceReport();
 controls.appendChild(vaultButton('3. Reconstruct observed stage sequence (offline)',async()=>{
  const {file,parsed}=await readSelectedHar();
  if(inspectedFile!==file)throw Error('Run privacy preflight for this exact HAR before stage analysis');
  harPrivacyReport=THIHARPrivacy.audit(parsed);
  harSequenceReport=THIHARSequence.audit(parsed);
  renderHARSequenceReport();notice('Local stage sequence analysed. Export contains fixed categories and numeric fields only.');
 },'primary'));
 // v7.2: privacy reviewed two-HAR comparison, independent of saved capture groups.
 const compareHolder=elem('div');compareHolder.dataset.harStageCompare='';container.appendChild(compareHolder);
 const compareOptions=elem('div','vault-controls');container.appendChild(compareOptions);
 const secondLabel=document.createElement('label');secondLabel.className='vault-selector';
 secondLabel.appendChild(elem('span','','Second HAR for offline stage comparison (maximum 12 MB)'));
 const secondFileInput=document.createElement('input');secondFileInput.type='file';secondFileInput.accept='.har,.json,application/json';
 secondLabel.appendChild(secondFileInput);compareOptions.appendChild(secondLabel);
 let reviewedSecondFile=null;
 let harDeliveryComparison=null;
 let harAccessComparison=null;
 let harBoundaryComparison=null;
 let harRangeComparison=null;
 let harCacheComparison=null;
 let harNegotiationComparison=null;
 const secondPrivacyHolder=elem('div');secondPrivacyHolder.dataset.harSecondPrivacy='';container.appendChild(secondPrivacyHolder);
 secondPrivacyHolder.appendChild(elem('p','helper','The second HAR must pass its own local privacy preflight. Files are not uploaded, saved or replayed.'));
 const stageContext={};
 for(const [id,title] of [
  ['sameSite','Same exact website context?'],['sameActions','Same browsing and workflow actions?'],
  ['sameAccount','Same account or role?'],['sameScope','Same gallery or asset scope?'],
  ['sameBrowserCoverage','Equivalent DevTools and browser coverage?']]){
  const wrap=document.createElement('label');wrap.className='vault-selector';wrap.appendChild(elem('span','',title));
  const sel=document.createElement('select');for(const [v,t] of [['unknown','Not confirmed'],['yes','Yes'],['no','No']]){const op=document.createElement('option');op.value=v;op.textContent=t;sel.appendChild(op);}
  wrap.appendChild(sel);compareOptions.appendChild(wrap);stageContext[id]=sel;
 }
 function renderHARStageCompareReport(){
  compareHolder.replaceChildren();const r=harStageCompareReport;
  if(!r){compareHolder.appendChild(elem('h2','spaced-heading','Two-HAR workflow comparison'));compareHolder.appendChild(elem('p','helper','Compare two independently privacy-reviewed, local HAR files. Different account or workflow context can explain observed changes.'));return;}
  compareHolder.appendChild(elem('h2','spaced-heading','Offline workflow-stage differences'));
  compareHolder.appendChild(elem('p','warn-note',r.readiness+' — observed changes do not prove policy changes or authorisation failures.'));
  compareHolder.appendChild(buildTable([{key:'capture',label:'HAR'},{key:'totalEntries',label:'Total entries'},{key:'inspectedHttp',label:'HTTP inspected'},{key:'candidateStages',label:'Classified stages'},{key:'unshownStages',label:'Timeline omitted'},{key:'missingTimestamps',label:'Missing times'}],r.coverage));
  compareHolder.appendChild(elem('h2','spaced-heading','Stage rates per 1,000 inspected HTTP entries'));
  compareHolder.appendChild(buildTable([{key:'category',label:'Stage'},{key:'baseline',label:'Baseline'},{key:'comparison',label:'Comparison'},{key:'baselinePer1000',label:'Baseline rate'},{key:'comparisonPer1000',label:'Comparison rate'},{key:'interpretation',label:'Interpretation'}],r.stageRows));
  // v7.3: full-bounded-HAR service-role matrix. All labels are fixed within the analyser.
  compareHolder.appendChild(elem('h2','spaced-heading','Observed service-role distribution'));
  compareHolder.appendChild(elem('p','warn-note','These are hostname-category heuristics, not claims about DAM ownership or the same asset. Normalised counts use inspected HTTP entries.'));
  compareHolder.appendChild(buildTable([{key:'category',label:'Service-role category'},{key:'baseline',label:'Baseline'},{key:'comparison',label:'Comparison'},{key:'baselinePer1000',label:'Baseline / 1,000 HTTP'},{key:'comparisonPer1000',label:'Comparison / 1,000 HTTP'}],r.roleRows));
  compareHolder.appendChild(elem('h2','spaced-heading','Service role × observed stage'));
  compareHolder.appendChild(buildTable([{key:'service',label:'Service role'},{key:'stage',label:'Observed stage'},{key:'baseline',label:'Baseline'},{key:'comparison',label:'Comparison'}],r.roleStageRows));
  compareHolder.appendChild(elem('h2','spaced-heading','Nearby cross-role observations (NOT request links)'));
  compareHolder.appendChild(elem('p','helper','Pairs mean consecutive classified HAR entries within five source positions, across all eligible entries. Do not interpret them as causal chains, CDN redirects or common asset identity.'));
  compareHolder.appendChild(buildTable([{key:'category',label:'Nearby category sequence'},{key:'baseline',label:'Baseline'},{key:'comparison',label:'Comparison'}],r.handoffRows));
  compareHolder.appendChild(buildTable([{key:'capture',label:'HAR'},{key:'classifiedStages',label:'Classified stages'},{key:'adjacentPairs',label:'Nearby pairs'},{key:'notNearbyPairs',label:'Distant pairs'}],r.roleCoverage));
  // v7.6: explicit redirect-to-next-request evidence, not proximity-inferred relationships.
  if(harBoundaryComparison){
   compareHolder.appendChild(elem('h2','spaced-heading','Offline redirect-boundary comparison'));
   compareHolder.appendChild(elem('p','warn-note',harBoundaryComparison.readiness+' — shared redirect patterns cannot prove identical entitlements or CDN policy.'));
   compareHolder.appendChild(buildTable([{key:'capture',label:'HAR'},{key:'redirectResponses',label:'Redirects'},{key:'uniquelyMatched',label:'Linked'},{key:'matchedCrossOrigin',label:'Cross-origin linked'}],harBoundaryComparison.coverage));
   compareHolder.appendChild(buildTable([{key:'category',label:'Boundary category'},{key:'baseline',label:'Baseline'},{key:'comparison',label:'Comparison'},{key:'baselinePer1000Redirect',label:'Baseline / 1,000 redirects'},{key:'comparisonPer1000Redirect',label:'Comparison / 1,000 redirects'}],harBoundaryComparison.boundaries));
   compareHolder.appendChild(elem('h2','spaced-heading','Cross-origin indicator comparison'));
   compareHolder.appendChild(buildTable([{key:'category',label:'Indicator'},{key:'baseline',label:'Baseline'},{key:'comparison',label:'Comparison'}],harBoundaryComparison.indicators));
   for(const w of harBoundaryComparison.warnings)compareHolder.appendChild(elem('p','helper',w));
  }
  // v7.7: observational byte-range and declared-span comparison only.
  if(harRangeComparison){
   compareHolder.appendChild(elem('h2','spaced-heading','Offline byte-range evidence comparison'));
   compareHolder.appendChild(elem('p','warn-note',harRangeComparison.readiness+' — these are HTTP header observations, NOT proof of complete received files or image access rights.'));
   compareHolder.appendChild(buildTable([{key:'capture',label:'HAR'},{key:'partialResponses',label:'206 responses'},{key:'validRangeResponses',label:'Valid Content-Range'},{key:'stableTagGroups',label:'Strong-ETag groups'}],harRangeComparison.coverage));
   compareHolder.appendChild(buildTable([{key:'category',label:'Observed range indicator'},{key:'baseline',label:'Baseline'},{key:'comparison',label:'Comparison'},{key:'baselinePer1000Partial',label:'Baseline / 1,000 partial'},{key:'comparisonPer1000Partial',label:'Comparison / 1,000 partial'}],harRangeComparison.signals.filter(x=>x.baseline||x.comparison)));
   compareHolder.appendChild(elem('h2','spaced-heading','Declared-span buckets (not file completeness)'));
   compareHolder.appendChild(buildTable([{key:'category',label:'Header coverage'},{key:'baseline',label:'Baseline'},{key:'comparison',label:'Comparison'}],harRangeComparison.spanBuckets));
   for(const w of harRangeComparison.warnings)compareHolder.appendChild(elem('p','helper',w));
  }
  // v7.8: two privacy-reviewed captures; no validator or URL values returned.
  if(harCacheComparison){
   compareHolder.appendChild(elem('h2','spaced-heading','Offline cache revalidation comparison'));
   compareHolder.appendChild(elem('p','warn-note',harCacheComparison.readiness+' — validation responses and cache headers cannot establish media access, revoked rights or actual stored bytes.'));
   compareHolder.appendChild(buildTable([{key:'capture',label:'HAR'},{key:'inspectedHttp',label:'HTTP entries'},{key:'conditionalSafeRequests',label:'Conditional GET/HEAD'},{key:'notModifiedResponses',label:'304 responses'}],harCacheComparison.coverage));
   compareHolder.appendChild(buildTable([{key:'category',label:'Observed fixed indicator'},{key:'baseline',label:'Baseline'},{key:'comparison',label:'Comparison'},{key:'baselinePer1000Http',label:'Baseline / 1,000 HTTP'},{key:'comparisonPer1000Http',label:'Comparison / 1,000 HTTP'}],harCacheComparison.signals.filter(x=>x.baseline||x.comparison)));
   for(const w of harCacheComparison.warnings)compareHolder.appendChild(elem('p','helper',w));
  }
  // v7.9: image representation negotiation and client-hint comparison, fixed labels only.
  if(harNegotiationComparison){
   compareHolder.appendChild(elem('h2','spaced-heading','Offline image negotiation comparison'));
   compareHolder.appendChild(elem('p','warn-note',harNegotiationComparison.readiness+' — changes in observed formats and Vary/Accept-CH indicators do not prove availability of other renditions.'));
   compareHolder.appendChild(buildTable([{key:'capture',label:'HAR'},{key:'inspectedHttp',label:'HTTP entries'},{key:'imageResponses',label:'Observed images'},{key:'media304Clues',label:'304 media clues'}],harNegotiationComparison.coverage));
   compareHolder.appendChild(buildTable([{key:'category',label:'Observed fixed indicator'},{key:'baseline',label:'Baseline'},{key:'comparison',label:'Comparison'},{key:'baselinePer1000Http',label:'Baseline / 1,000 HTTP'},{key:'comparisonPer1000Http',label:'Comparison / 1,000 HTTP'}],harNegotiationComparison.signals.filter(s=>s.baseline||s.comparison)));
   for(const w of harNegotiationComparison.warnings)compareHolder.appendChild(elem('p','helper',w));
  }
  // v7.5: request authentication signal vs observed media outcomes and cache directives.
  if(harAccessComparison){
   compareHolder.appendChild(elem('h2','spaced-heading','Offline access-indicator comparison'));
   compareHolder.appendChild(elem('p','warn-note',harAccessComparison.readiness+' — these are browser HAR observations, not permission, entitlement or exposure tests.'));
   compareHolder.appendChild(buildTable([{key:'capture',label:'HAR'},{key:'deliveryRelevant',label:'Relevant responses'},{key:'missingRequestHeaders',label:'Request headers unavailable'}],harAccessComparison.coverage));
   compareHolder.appendChild(buildTable([{key:'authentication',label:'Request indicators'},{key:'outcome',label:'Response outcome'},{key:'baseline',label:'Baseline'},{key:'comparison',label:'Comparison'},{key:'baselinePer1000Delivery',label:'Baseline / 1,000 relevant'},{key:'comparisonPer1000Delivery',label:'Comparison / 1,000 relevant'}],harAccessComparison.authOutcomes.filter(x=>x.baseline||x.comparison)));
   compareHolder.appendChild(elem('h2','spaced-heading','Auth indicator × cache directive'));
   compareHolder.appendChild(buildTable([{key:'authentication',label:'Request indicators'},{key:'policy',label:'Cache policy'},{key:'baseline',label:'Baseline'},{key:'comparison',label:'Comparison'}],harAccessComparison.authCache.filter(x=>x.baseline||x.comparison)));
   for(const w of harAccessComparison.warnings)compareHolder.appendChild(elem('p','helper',w));
  }
  // v7.4: only fixed labels and numbers from two independently reviewed HARs.
  if(harDeliveryComparison){
   compareHolder.appendChild(elem('h2','spaced-heading','Observed delivery policy and signing differences'));
   compareHolder.appendChild(elem('p','warn-note','Signed URL names, public-cache directives and request authentication may co-occur legitimately. Differences are descriptive only and do not establish public access, exposure or revocation failure.'));
   compareHolder.appendChild(buildTable([{key:'capture',label:'HAR'},{key:'inspectedHttp',label:'HTTP inspected'},{key:'deliveryRelevantResponses',label:'Delivery-relevant responses'},{key:'missingHeaderEntries',label:'Missing header arrays'}],harDeliveryComparison.coverage));
   compareHolder.appendChild(buildTable([{key:'category',label:'Fixed delivery indicator'},{key:'baseline',label:'Baseline'},{key:'comparison',label:'Comparison'},{key:'baselinePer1000Delivery',label:'Baseline / 1,000 delivery'},{key:'comparisonPer1000Delivery',label:'Comparison / 1,000 delivery'}],harDeliveryComparison.rows));
   compareHolder.appendChild(elem('h2','spaced-heading','Delivery policy owner-review combinations'));
   compareHolder.appendChild(buildTable([{key:'category',label:'Owner review (not a vulnerability)'},{key:'baseline',label:'Baseline'},{key:'comparison',label:'Comparison'}],harDeliveryComparison.reviewCandidates));
   for(const warning of harDeliveryComparison.warnings)compareHolder.appendChild(elem('p','helper',warning));
  }
  compareHolder.appendChild(elem('h2','spaced-heading','Ordered proximity patterns (not linked requests)'));
  compareHolder.appendChild(buildTable([{key:'category',label:'Observed HAR pattern'},{key:'baseline',label:'Baseline'},{key:'comparison',label:'Comparison'}],r.patternRows));
  for(const w of r.warnings)compareHolder.appendChild(elem('p','warn-note',w));
  for(const l of r.limitations)compareHolder.appendChild(elem('p','helper',l));
  const actions=elem('div','vault-controls');compareHolder.appendChild(actions);
  actions.appendChild(vaultButton('Export negotiation comparison (redacted JSON)',()=>{
   if(!harNegotiationComparison)throw Error('No image negotiation comparison');
   download('trufflehog-har-image-negotiation-compare.json',JSON.stringify(harNegotiationComparison,null,2),'application/json');
  }));
  actions.appendChild(vaultButton('Export negotiation comparison (redacted CSV)',()=>{
   if(!harNegotiationComparison)throw Error('No image negotiation comparison');
   const keys=['category','baseline','comparison','baselinePer1000Http','comparisonPer1000Http'];
   const lines=[keys.map(csvValue).join(','),...harNegotiationComparison.signals.map(s=>keys.map(k=>csvValue(s[k]??'')).join(','))];
   download('trufflehog-har-image-negotiation-compare.csv','\uFEFF'+lines.join('\r\n'),'text/csv;charset=utf-8');
  }));
  actions.appendChild(vaultButton('Export cache comparison (redacted JSON)',()=>{
   if(!harCacheComparison)throw Error('No cache revalidation comparison');
   download('trufflehog-har-cache-comparison.json',JSON.stringify(harCacheComparison,null,2),'application/json');
  }));
  actions.appendChild(vaultButton('Export cache comparison (redacted CSV)',()=>{
   if(!harCacheComparison)throw Error('No cache revalidation comparison');
   const keys=['category','baseline','comparison','baselinePer1000Http','comparisonPer1000Http'];
   const lines=[keys.map(csvValue).join(','),...harCacheComparison.signals.map(x=>keys.map(k=>csvValue(x[k]??'')).join(','))];
   download('trufflehog-har-cache-comparison.csv','\uFEFF'+lines.join('\r\n'),'text/csv;charset=utf-8');
  }));
  actions.appendChild(vaultButton('Export byte-range comparison (redacted JSON)',()=>{
   if(!harRangeComparison)throw Error('No byte-range comparison');
   download('trufflehog-har-byte-range-comparison.json',JSON.stringify(harRangeComparison,null,2),'application/json');
  }));
  actions.appendChild(vaultButton('Export byte-range comparison (redacted CSV)',()=>{
   if(!harRangeComparison)throw Error('No byte-range comparison');
   const keys=['section','category','baseline','comparison','baselinePer1000Partial','comparisonPer1000Partial'];
   const lines=[keys.map(csvValue).join(',')];
   for(const [section,rows] of [['signals',harRangeComparison.signals],['span-buckets',harRangeComparison.spanBuckets]])for(const row of rows)lines.push([section,row.category,row.baseline,row.comparison,row.baselinePer1000Partial??'',row.comparisonPer1000Partial??''].map(csvValue).join(','));
   download('trufflehog-har-byte-range-comparison.csv','\uFEFF'+lines.join('\r\n'),'text/csv;charset=utf-8');
  }));
  actions.appendChild(vaultButton('Export redirect comparison (redacted JSON)',()=>{if(!harBoundaryComparison)throw Error('No redirect comparison');download('trufflehog-har-redirect-comparison.json',JSON.stringify(harBoundaryComparison,null,2),'application/json');}));
  actions.appendChild(vaultButton('Export redirect comparison (redacted CSV)',()=>{
   if(!harBoundaryComparison)throw Error('No redirect comparison');
   const lines=[['section','category','baseline','comparison','baseline_per_1000_redirect','comparison_per_1000_redirect'].map(csvValue).join(',')];
   for(const [section,rows] of [['boundaries',harBoundaryComparison.boundaries],['indicators',harBoundaryComparison.indicators]])for(const row of rows)lines.push([section,row.category,row.baseline,row.comparison,row.baselinePer1000Redirect??'',row.comparisonPer1000Redirect??''].map(csvValue).join(','));
   download('trufflehog-har-redirect-comparison.csv','\uFEFF'+lines.join('\r\n'),'text/csv;charset=utf-8');
  }));
  actions.appendChild(vaultButton('Export access comparison (redacted JSON)',()=>{if(!harAccessComparison)throw Error('No access comparison');download('trufflehog-har-access-compare.json',JSON.stringify(harAccessComparison,null,2),'application/json');}));
  actions.appendChild(vaultButton('Export access comparison (redacted CSV)',()=>{
   if(!harAccessComparison)throw Error('No access comparison');
   const lines=[['section','request_indicator','outcome_or_cache','baseline','comparison','baseline_per_1000','comparison_per_1000'].map(csvValue).join(',')];
   for(const x of harAccessComparison.authOutcomes)lines.push(['outcome',x.authentication,x.outcome,x.baseline,x.comparison,x.baselinePer1000Delivery??'',x.comparisonPer1000Delivery??''].map(csvValue).join(','));
   for(const x of harAccessComparison.authCache)lines.push(['cache',x.authentication,x.policy,x.baseline,x.comparison,x.baselinePer1000Delivery??'',x.comparisonPer1000Delivery??''].map(csvValue).join(','));
   download('trufflehog-har-access-compare.csv','\uFEFF'+lines.join('\r\n'),'text/csv;charset=utf-8');
  }));
  actions.appendChild(vaultButton('Export delivery policy comparison (redacted JSON)' ,()=>{if(!harDeliveryComparison)throw Error('No delivery comparison');download('trufflehog-har-delivery-compare.json',JSON.stringify(harDeliveryComparison,null,2),'application/json');}));
  actions.appendChild(vaultButton('Export delivery policy comparison (redacted CSV)',()=>{
   if(!harDeliveryComparison)throw Error('No delivery comparison');
   const keys=['category','baseline','comparison','baselinePer1000Delivery','comparisonPer1000Delivery'];
   const lines=[keys.map(csvValue).join(','),...harDeliveryComparison.rows.map(x=>keys.map(k=>csvValue(x[k]??'')).join(','))];
   download('trufflehog-har-delivery-compare.csv','\uFEFF'+lines.join('\r\n'),'text/csv;charset=utf-8');
  }));
  actions.appendChild(vaultButton('Export stage comparison (redacted JSON)',()=>download('trufflehog-har-stage-compare.json',JSON.stringify(r,null,2),'application/json')));
  actions.appendChild(vaultButton('Export service-role comparison (redacted CSV)',()=>{
   const lines=[['section','role_or_category','stage','baseline','comparison'].map(csvValue).join(',')];
   for(const x of r.roleRows)lines.push(['role',x.category,'',x.baseline,x.comparison].map(csvValue).join(','));
   for(const x of r.roleStageRows)lines.push(['role-stage',x.service,x.stage,x.baseline,x.comparison].map(csvValue).join(','));
   for(const x of r.handoffRows)lines.push(['nearby-sequence',x.category,'',x.baseline,x.comparison].map(csvValue).join(','));
   download('trufflehog-har-role-flow-compare.csv','\uFEFF'+lines.join('\r\n'),'text/csv;charset=utf-8');
  }));
  actions.appendChild(vaultButton('Export stage comparison (redacted CSV)',()=>{
   const keys=['category','baseline','comparison','baselinePer1000','comparisonPer1000','rateChangePer1000','interpretation'];
   const lines=[keys.map(csvValue).join(','),...r.stageRows.map(x=>keys.map(k=>csvValue(x[k]??'')).join(','))];
   download('trufflehog-har-stage-compare.csv','\uFEFF'+lines.join('\r\n'),'text/csv;charset=utf-8');
  }));
 }
 secondFileInput.addEventListener('change',()=>{reviewedSecondFile=null;harStageCompareReport=null;harDeliveryComparison=null;harAccessComparison=null;harBoundaryComparison=null;harRangeComparison=null;harCacheComparison=null;harNegotiationComparison=null;renderHARStageCompareReport();secondPrivacyHolder.replaceChildren(elem('p','helper','Second HAR changed; repeat its privacy preflight.'));});
 async function readSecondHar(){
  const file=secondFileInput.files?.[0];if(!file)throw Error('Choose a second HAR file');
  if(file.size>12*1024*1024)throw Error('Second HAR exceeds 12 MB');
  let parsed;try{parsed=JSON.parse(await file.text());}catch{throw Error('Second file is not valid HAR JSON');}
  return {file,parsed};
 }
 compareOptions.appendChild(vaultButton('4. Inspect second HAR privacy locally',async()=>{
  const {file,parsed}=await readSecondHar();const report=THIHARPrivacy.audit(parsed);
  reviewedSecondFile=file;harStageCompareReport=null;harDeliveryComparison=null;harAccessComparison=null;harBoundaryComparison=null;harRangeComparison=null;harCacheComparison=null;harNegotiationComparison=null;renderHARPrivacyReport(secondPrivacyHolder,report);renderHARStageCompareReport();
  notice('Second HAR privacy preflight completed locally. Original files remain private.');
 },'primary'));
 compareOptions.appendChild(vaultButton('5. Compare two reviewed HARs (offline)',async()=>{
  const {file:firstFile,parsed:firstParsed}=await readSelectedHar();
  if(inspectedFile!==firstFile)throw Error('Review the first selected HAR with privacy preflight before comparison');
  const {file:secondFile,parsed:secondParsed}=await readSecondHar();
  if(reviewedSecondFile!==secondFile)throw Error('Review the second selected HAR with privacy preflight before comparison');
  THIHARPrivacy.audit(firstParsed);THIHARPrivacy.audit(secondParsed); // re-check both contents
  const declared=Object.fromEntries(Object.entries(stageContext).map(([k,select])=>[k,select.value]));
  harStageCompareReport=THIHARStageCompare.audit(firstParsed,secondParsed,declared);
  harDeliveryComparison=THIHARDeliveryPosture.compare(firstParsed,secondParsed);
  harAccessComparison=THIHARAccessMatrix.compare(firstParsed,secondParsed,declared);
  harBoundaryComparison=THIHARRedirectBoundaries.compare(firstParsed,secondParsed,declared);
  harRangeComparison=THIHARRangeEvidence.compare(firstParsed,secondParsed,declared);
  harCacheComparison=THIHARCacheRevalidation.compare(firstParsed,secondParsed,declared);
  harNegotiationComparison=THIHARImageNegotiation.compare(firstParsed,secondParsed,declared);
  renderHARStageCompareReport();notice('Two local HAR stage summaries compared. The exported report has fixed labels and counts only.');
 },'primary'));
 renderHARStageCompareReport();
 if(!groups.length){empty(container,'Saved capture needed for comparison','Privacy preflight is available above. Save a local Trufflehog investigation to enable HAR reconciliation.');return;}
 controls.appendChild(vaultButton('6. Reconcile reviewed HAR with capture',async()=>{
  const {file,parsed}=await readSelectedHar();
  if(inspectedFile!==file)throw Error('Run the local HAR privacy preflight on this exact file before comparing');
  // Independently validate current selected bytes: file handles may be replaced.
  harPrivacyReport=THIHARPrivacy.audit(parsed);
  const group=groups.find(g=>g.id===selected.select.value);if(!group)throw Error('Saved capture not found');
  const records=await loadGroupRecords(group);
  const report=THIHARCoverage.reconcile(parsed,records);
  harCoverageReport=report;harTriageReport=null;harCoverageSelected=group.id;
  drawView();notice('HAR reconciled locally. Reports contain only numerical and fixed-label evidence.');
 },'primary'));
 const holder=elem('div');holder.dataset.harReport='';container.appendChild(holder);
 if(!harCoverageReport){empty(holder,'No HAR comparison yet','Export a HAR from Chrome DevTools during a normal authorised capture, then select the corresponding saved group.');return;}
 const r=harCoverageReport;
 holder.appendChild(elem('h2','spaced-heading',r.assessment));
 const grid=elem('div','simple-grid');
 for(const [label,key] of [['HAR requests','harRequests'],['Saved requests','savedRequests'],['Exact identity matches','exactMatches'],['HAR-only observations','harOnly'],['Saved-only observations','savedOnly'],['Status-different matches','statusDifferentMatches']])grid.appendChild(panel(label,String(r.coverage[key]),'Recorded data only'));
 holder.appendChild(grid);
 holder.appendChild(elem('h2','spaced-heading','Same-site versus external-origin coverage'));
 if(Array.isArray(r.scopeRows))holder.appendChild(buildTable([{key:'scope',label:'Origin category'},
  {key:'harObserved',label:'HAR requests'},{key:'captureObserved',label:'Capture requests'},
  {key:'harOnly',label:'HAR only'},{key:'captureOnly',label:'Capture only'}],r.scopeRows));
 holder.appendChild(panel('Repeated comparable request keys',String(r.coverage.repeatedComparableKeys||0),'Repetition or sanitisation may make one-to-one attribution ambiguous.'));
 holder.appendChild(elem('h2','spaced-heading','Comparison by resource category'));
 holder.appendChild(buildTable([{key:'category',label:'Resource type'},{key:'harObserved',label:'HAR records'},
  {key:'captureObserved',label:'Trufflehog records'},{key:'harOnly',label:'HAR only'},
  {key:'captureOnly',label:'Capture only'}],r.rows));
 for(const warning of r.warnings)holder.appendChild(elem('p','helper',warning));
 holder.appendChild(elem('p','warn-note',r.certainty));
 const exp=elem('div','vault-controls');
 exp.appendChild(vaultButton('Export reconciliation (redacted JSON)',()=>download('trufflehog-har-coverage.json',JSON.stringify(r,null,2),'application/json')));
 exp.appendChild(vaultButton('Export category CSV',()=>download('trufflehog-har-coverage.csv','\uFEFF'+currentCSV(),'text/csv;charset=utf-8')));
 holder.appendChild(exp);
 // v6.8: User-declared collection context can improve triage, but never certify completeness.
 holder.appendChild(elem('h2','spaced-heading','Coverage gap triage'));
 holder.appendChild(elem('p','helper','Declare what you know about the two observations. Answers are not saved or sent to a website. Unknown is the default.'));
 const checkFields=[
  ['sameSession','Both sources cover the same short session?'],
  ['sameActions','Same pages and user actions in both?'],
  ['devtoolsBeforeNavigation','DevTools open before first navigation?'],
  ['preserveLog','DevTools Preserve log enabled?'],
  ['comparableSiteAccess','Same account and host permissions?']
 ];
 const contextFields={};const triageControls=elem('div','vault-controls');holder.appendChild(triageControls);
 for(const [id,title] of checkFields){
  const label=elem('label','vault-selector');label.appendChild(elem('span','',title));
  const sel=document.createElement('select');
  for(const [value,title] of [['unknown','Not confirmed'],['yes','Yes'],['no','No']]){
   const o=document.createElement('option');o.value=value;o.textContent=title;sel.appendChild(o);
  }
  label.appendChild(sel);triageControls.appendChild(label);contextFields[id]=sel;
 }
 const triageHolder=elem('div');holder.appendChild(triageHolder);
 const renderTriage=()=>{
  triageHolder.replaceChildren();const t=harTriageReport;if(!t)return;
  triageHolder.appendChild(elem('h2','spaced-heading',t.assessment));
  triageHolder.appendChild(buildTable([{key:'id',label:'Indicator'},{key:'level',label:'Review'},{key:'count',label:'Count'},
   {key:'explanation',label:'Observed meaning'},{key:'nextStep',label:'Suggested check'}],t.signals));
  triageHolder.appendChild(elem('p','warn-note',t.explanation));
  const actions=elem('div','vault-controls');triageHolder.appendChild(actions);
  actions.appendChild(vaultButton('Export triage (redacted JSON)',()=>download('trufflehog-har-triage.json',JSON.stringify(t,null,2),'application/json')));
  actions.appendChild(vaultButton('Export triage CSV',()=>{
   const cols=['id','level','count','explanation','nextStep'];const lines=[cols.join(',')].concat(t.signals.map(s=>cols.map(k=>csvValue(s[k])).join(',')));
   download('trufflehog-har-triage.csv','\uFEFF'+lines.join('\r\n'),'text/csv;charset=utf-8');
  }));
 };
 holder.appendChild(vaultButton('Run offline coverage triage',()=>{
  const answers=Object.fromEntries(Object.entries(contextFields).map(([key,select])=>[key,select.value]));
  harTriageReport=THIHARTriage.assess(r,answers);renderTriage();notice('Coverage triage generated locally; no identifiers or HAR contents exported.');
 },'primary'));
 holder.appendChild(elem('p','helper','The imported HAR is not retained in local storage, saved to Evidence Vault, transmitted or included in exported reports. Any HAR file on your own disk should still be treated as potentially sensitive.'));
}

function renderEvidenceSynthesis(container){
 container.appendChild(elem('p','warn-note','Evidence-weighted offline review of TWO saved same-origin captures. Context questions are operator declarations. Matching recorded traffic cannot verify equal privileges, asset scope or effective CDN/DAM authorisation. The synthesis performs no network requests and exports only fixed categories and numerical summaries.'));
 const groups=THIPro.groupRows(sessionsCache);
 const controls=elem('div','vault-controls');container.appendChild(controls);
 controls.appendChild(vaultButton('Refresh saved groups',async()=>{await loadVault();drawView();}));
 if(groups.length<2){empty(container,'Two saved capture groups needed','Record and stop two separate authorised browsing sessions on one site, then compare.');return;}
 const opts=groups.map(g=>({id:g.id,origin:g.origin,startedAt:g.first}));
 const baseline=choose('Baseline saved capture',opts,evidenceSynthesisSelection?.[0]||groups[groups.length-1].id);
 const current=choose('Comparison saved capture',opts,evidenceSynthesisSelection?.[1]||groups[0].id);
 controls.appendChild(baseline.wrap);controls.appendChild(current.wrap);
 const questions=[
  ['accessRole','Same account/access role?',[['unknown','Not confirmed'],['same','Yes — operator reports same'],['different','No — different context']]],
  ['workflow','Same browsing/download actions?',[['unknown','Not confirmed'],['same','Yes — same steps'],['different','No — different actions']]],
  ['assetScope','Same asset/gallery/filter/search scope?',[['unknown','Not confirmed'],['same','Yes — same scope'],['different','No — different scope']]],
  ['hostPermissions','Same Chrome site/CDN access grants?',[['unknown','Not confirmed'],['same','Yes — same grants'],['different','No — changed grants']]],
  ['devtoolsTiming','DevTools open before loading both?', [['unknown','Not confirmed'],['both-early','Yes — both sessions'],['not-both-early','No — not both']]]
 ];
 const answers={};
 for(const [key,title,items] of questions){
  const wrap=document.createElement('label');wrap.className='vault-selector';wrap.appendChild(elem('span','',title));
  const sel=document.createElement('select');
  for(const [v,label] of items){const opt=document.createElement('option');opt.value=v;opt.textContent=label;sel.appendChild(opt);}
  sel.value=evidenceSynthesisContext?.[key]||'unknown';wrap.appendChild(sel);controls.appendChild(wrap);answers[key]=sel;
 }
 // Invalidate prior findings immediately if the operator selects different
 // captures or changes context. Never present yesterday's review under today's
 // newly selected account/workflow assumptions.
 const invalidate=()=>{
  evidenceSynthesisSelection=[baseline.select.value,current.select.value];
  evidenceSynthesisContext=Object.fromEntries(Object.entries(answers).map(([key,el])=>[key,el.value]));
  evidenceSynthesisReport=null;
  drawView();
  notice('Inputs changed — run the evidence-weighted review again for the new selections.');
 };
 baseline.select.addEventListener('change',invalidate);
 current.select.addEventListener('change',invalidate);
 for(const select of Object.values(answers))select.addEventListener('change',invalidate);
 controls.appendChild(vaultButton('Run evidence-weighted review',async()=>{
  if(baseline.select.value===current.select.value)throw Error('Select two different saved captures');
  const a=groups.find(g=>g.id===baseline.select.value),b=groups.find(g=>g.id===current.select.value);
  if(!a||!b)throw Error('Saved capture groups not found');
  const [ar,br]=await Promise.all([loadGroupRecords(a),loadGroupRecords(b)]);
  const context=Object.fromEntries(Object.entries(answers).map(([key,el])=>[key,el.value]));
  const report=THIEvidenceSynthesis.synthesize(ar,br,context);
  evidenceSynthesisContext=context;evidenceSynthesisSelection=[a.id,b.id];evidenceSynthesisReport=report;
  drawView();notice('Offline evidence-weighted review completed. No permissions or server controls were tested.');
 },'primary'));
 if(!evidenceSynthesisReport){empty(container,'No evidence-weighted review yet','Choose two saved groups and document the comparison context. Unknown answers remain valid limitations.');return;}
 const r=evidenceSynthesisReport;
 container.appendChild(elem('h2','spaced-heading',r.assessment));
 const stats=elem('div','simple-grid');
 stats.appendChild(panel('Baseline HTTP responses',String(r.overview.baselineRequests),'Observed traffic, not a full request inventory'));
 stats.appendChild(panel('Comparison HTTP responses',String(r.overview.comparisonRequests),'Observed traffic only'));
 stats.appendChild(panel('Request mix difference',r.overview.requestMixDifferencePercent+'%','Category composition, not actions'));
 stats.appendChild(panel('Potential review shifts',String(r.overview.notableObservations),'Not verified security defects'));
 container.appendChild(stats);
 container.appendChild(elem('h2','spaced-heading','Observed DAM delivery indicators'));
 container.appendChild(buildTable([
  {key:'indicator',label:'Metric'}, {key:'earlierPerThousand',label:'Baseline / 1,000'},
  {key:'laterPerThousand',label:'Comparison / 1,000'},
  {key:'differencePerThousand',label:'Delta / 1,000'},
  {key:'earlierSample',label:'Baseline sample'}, {key:'laterSample',label:'Comparison sample'},
  {key:'interpretation',label:'Interpretation'}, {key:'ownerAction',label:'Owner verification'}],r.rows));
 container.appendChild(elem('h2','spaced-heading','Declared comparison context'));
 container.appendChild(buildTable([{key:'category',label:'Context'},{key:'status',label:'Status'}],r.contextChecks));
 if(r.limitations.length){container.appendChild(elem('h2','spaced-heading','Interpretation limitations'));
  for(const warning of r.limitations)container.appendChild(elem('p','helper',warning));}
 container.appendChild(elem('p','warn-note',r.caution));
 const exports=elem('div','vault-controls');
 exports.appendChild(vaultButton('Export review (strictly redacted JSON)',()=>{
  download('trufflehog-evidence-weighted-review.json',JSON.stringify(r,null,2),'application/json');
  notice('Only fixed categories, declared context statuses and numeric evidence exported.');
 }));
 exports.appendChild(vaultButton('Export indicator CSV',()=>{
  download('trufflehog-evidence-weighted-review.csv','\uFEFF'+currentCSV(),'text/csv;charset=utf-8');
 }));
 exports.appendChild(vaultButton('Inspect request patterns',()=>document.querySelector('[data-view="workflow-pattern"]').click()));
 container.appendChild(exports);
 container.appendChild(elem('p','helper','Context answers stay only in this open dashboard session. Raw account identities, URLs, credentials, headers and asset IDs are not included in this report.'));
}

function renderWorkflowPattern(container){
 container.appendChild(elem('p','warn-note','Offline comparison of *observed* HTTP completion patterns, not a reproduction of user actions. Cached resources, navigation timing, site grants and capture gaps can distort the result. No URLs, request IDs, secret values or endpoints are included in this report. No web requests are made.'));
 const groups=THIPro.groupRows(sessionsCache);
 const controls=elem('div','vault-controls');
 controls.appendChild(vaultButton('Refresh saved groups',async()=>{await loadVault();drawView();}));
 container.appendChild(controls);
 if(groups.length<2){empty(container,'Two saved capture groups required','Capture and stop two separate sessions from the same origin first.');return;}
 const opts=groups.map(g=>({id:g.id,origin:g.origin,startedAt:g.first}));
 const a=choose('Baseline capture',opts,workflowPatternSelection?.[0]||groups[groups.length-1].id);
 const b=choose('Comparison capture',opts,workflowPatternSelection?.[1]||groups[0].id);
 controls.appendChild(a.wrap);controls.appendChild(b.wrap);
 controls.appendChild(vaultButton('Compare observed patterns',async()=>{
  if(a.select.value===b.select.value)throw Error('Select two distinct capture groups');
  const ga=groups.find(g=>g.id===a.select.value),gb=groups.find(g=>g.id===b.select.value);
  if(!ga||!gb)throw Error('Saved capture groups not found');
  const [ar,br]=await Promise.all([loadGroupRecords(ga),loadGroupRecords(gb)]);
  workflowPatternReport=THIWorkflowPattern.compare(ar,br);
  workflowPatternSelection=[ga.id,gb.id];drawView();
  notice('Compared recorded request categories locally; similarity is not proof of equal access.');
 },'primary'));
 if(!workflowPatternReport){empty(container,'No pattern comparison yet','Choose two saved captures and compare their observed request patterns.');return;}
 const r=workflowPatternReport;
 container.appendChild(elem('h2','spaced-heading',r.assessment));
 const cards=elem('div','simple-grid');
 cards.appendChild(panel('Baseline requests',String(r.overview.baselineRequests),'Recorded HTTP responses only'));
 cards.appendChild(panel('Comparison requests',String(r.overview.comparisonRequests),'Not necessarily complete browser traffic'));
 cards.appendChild(panel('Request-mix difference',r.overview.requestMixDifferencePercent+'%','Coarse category distribution; descriptive only'));
 cards.appendChild(panel('Phase-pattern difference',r.overview.phasePatternDifferencePercent+'%','Four sequential parts, not verified actions'));
 container.appendChild(cards);
 container.appendChild(elem('p','helper','Sequence evidence: '+r.overview.sequenceEvidence));
 container.appendChild(buildTable([{key:'category',label:'Observed request kind'},
  {key:'baseline',label:'Earlier count'},{key:'comparison',label:'Later count'},
  {key:'baselinePercent',label:'Earlier %'},{key:'comparisonPercent',label:'Later %'},
  {key:'differencePoints',label:'Difference (percentage points)'}],r.rows));
 container.appendChild(elem('h2','spaced-heading','Four-phase pattern (request completion order)'));
 container.appendChild(buildTable([{key:'phase',label:'Phase'},{key:'baselineDominant',label:'Earlier dominant kind'},
  {key:'comparisonDominant',label:'Later dominant kind'},{key:'differencePercent',label:'Distribution difference %'}],r.phaseRows));
 for(const issue of r.limitations)container.appendChild(elem('p','helper',issue));
 container.appendChild(elem('p','warn-note',r.caution));
 const exports=elem('div','vault-controls');
 exports.appendChild(vaultButton('Export pattern report (redacted JSON)',()=>{
  download('trufflehog-observed-workflow-pattern.json',JSON.stringify(r,null,2),'application/json');
 }));
 exports.appendChild(vaultButton('Export category table CSV',()=>{
  const cols=['category','baseline','comparison','baselinePercent','comparisonPercent','differencePoints'];
  download('trufflehog-observed-workflow-pattern.csv','\uFEFF'+[cols.map(csvValue).join(','),...r.rows.map(x=>cols.map(k=>csvValue(x[k])).join(','))].join('\r\n'),'text/csv;charset=utf-8');
 }));
 exports.appendChild(vaultButton('Check comparison readiness',()=>document.querySelector('[data-view="compare-readiness"]').click()));
 container.appendChild(exports);
}
function renderComparisonReadiness(container){
 container.appendChild(elem('p','warn-note','Are these two investigations actually comparable? Browser requests cannot prove the same account, role, gallery, filter settings or CDN permissions. Context answers below are declared by you, not discovered by Trufflehog. This tool makes no network requests.'));
 const groups=THIPro.groupRows(sessionsCache);
 const controls=elem('div','vault-controls');
 controls.appendChild(vaultButton('Refresh saved groups',async()=>{await loadVault();drawView();}));container.appendChild(controls);
 if(groups.length<2){empty(container,'Two saved capture groups needed','Capture and save two distinct sessions before assessing comparison readiness.');return;}
 const options=groups.map(g=>({id:g.id,origin:g.origin,startedAt:g.first}));
 const older=choose('Baseline capture',options,readinessSelection?.[0]||groups[groups.length-1].id);
 const newer=choose('Comparison capture',options,readinessSelection?.[1]||groups[0].id);
 controls.appendChild(older.wrap);controls.appendChild(newer.wrap);
 const specs=[
  ['accessRole','Same account/access role?',[['unknown','Not confirmed'],['same','Yes, same access context'],['different','No, different roles/accounts']]],
  ['workflow','Same browsing actions?',[['unknown','Not confirmed'],['same','Yes, same workflow'],['different','No, different workflow']]],
  ['assetScope','Same galleries, assets, filters and searches?',[['unknown','Not confirmed'],['same','Yes, same scope'],['different','No, different scope']]],
  ['hostPermissions','Same Chrome host access grants?',[['unknown','Not confirmed'],['same','Yes, same grants'],['different','No, changed grants']]],
  ['devtoolsTiming','DevTools open before page load for both?', [['unknown','Not confirmed'],['both-early','Yes, both'],['not-both-early','No, not both']]]
 ];
 const selects={};
 for(const [key,title,items] of specs){
  const wrap=document.createElement('label');wrap.className='vault-selector';wrap.appendChild(elem('span','',title));
  const select=document.createElement('select');
  for(const [value,label] of items){const opt=document.createElement('option');opt.value=value;opt.textContent=label;select.appendChild(opt);}
  select.value=readinessContext?.[key]||'unknown';wrap.appendChild(select);controls.appendChild(wrap);selects[key]=select;
 }
 controls.appendChild(vaultButton('Assess comparison readiness',async()=>{
  if(older.select.value===newer.select.value)throw Error('Choose two different capture groups');
  const a=groups.find(g=>g.id===older.select.value),b=groups.find(g=>g.id===newer.select.value);
  if(!a||!b)throw Error('Saved group not found');
  const [ar,br]=await Promise.all([loadGroupRecords(a),loadGroupRecords(b)]);
  const answers=Object.fromEntries(Object.entries(selects).map(([k,el])=>[k,el.value]));
  const report=THIComparisonReadiness.assess(ar,br,answers);
  readinessContext=answers;readinessSelection=[a.id,b.id];readinessReport=report;
  drawView();notice('Readiness assessed using recorded evidence and operator declarations; no live tests were made.');
 },'primary'));
 if(!readinessReport){empty(container,'Comparison readiness not assessed','Select two captures and declare what is known about their browsing context. Unknown answers are permitted and treated as limitations.');return;}
 const outcome=elem('h2','spaced-heading','Readiness: '+readinessReport.outcome);container.appendChild(outcome);
 const stats=elem('div','simple-grid');
 stats.appendChild(panel('Baseline HTTP records',String(readinessReport.counts.baselineRequests),'Browser-observed; may be incomplete'));
 stats.appendChild(panel('Comparison HTTP records',String(readinessReport.counts.comparisonRequests),'Different activity changes counts'));
 stats.appendChild(panel('Blocking reasons',String(readinessReport.blocking.length),'Do not interpret as equivalent'));
 stats.appendChild(panel('Other limitations',String(readinessReport.cautions.length),'Further context or coverage needed'));
 container.appendChild(stats);
 if(readinessReport.observedPattern){container.appendChild(panel('Observed HTTP pattern',readinessReport.observedPattern.assessment,'Independent browser-data clue; not verification of equal roles or workflow.'));}
 container.appendChild(buildTable([{key:'category',label:'Context factor'},{key:'status',label:'Assessment'},{key:'assessment',label:'Operator answer'},{key:'source',label:'Evidence source'}],matches(readinessReport.context)));
 if(readinessReport.blocking.length){container.appendChild(elem('h2','spaced-heading','Differences or missing data'));
  for(const x of readinessReport.blocking)container.appendChild(elem('p','helper',x));}
 if(readinessReport.cautions.length){container.appendChild(elem('h2','spaced-heading','Capture and context cautions'));
  for(const x of readinessReport.cautions)container.appendChild(elem('p','helper',x));}
 container.appendChild(elem('h2','spaced-heading','Interpretation limits'));
 for(const x of readinessReport.ownerReview)container.appendChild(elem('p','helper',x));
 const actions=elem('div','vault-controls');
 actions.appendChild(vaultButton('Export readiness (redacted JSON)',()=>{
  download('trufflehog-comparison-readiness.json',JSON.stringify(readinessReport,null,2),'application/json');
  notice('Exported predefined context labels and numeric evidence only.');
 }));
 actions.appendChild(vaultButton('Export context checks CSV',()=>download('trufflehog-comparison-readiness.csv','\uFEFF'+currentCSV(),'text/csv;charset=utf-8')));
 container.appendChild(actions);
 container.appendChild(elem('p','helper','Context selections remain in this dashboard session only; no roles, user IDs or passwords are saved to Chrome storage.')); 
}

function renderPolicyDrift(container){
 container.appendChild(elem('p','warn-note','Compare two saved investigations from the exact same site origin. Shares are per 1,000 observed requests of the indicated type. Changed shares cannot prove a security defect, change in entitlements, leaked original, or revocation failure. No network requests are made.'));
 container.appendChild(vaultButton('Check comparison readiness first',()=>document.querySelector('[data-view=\"compare-readiness\"]').click()));
 const groups=THIPro.groupRows(sessionsCache);
 const controls=elem('div','vault-controls');
 controls.appendChild(vaultButton('Refresh saved groups',async()=>{await loadVault();drawView();}));container.appendChild(controls);
 if(groups.length<2){empty(container,'Two saved capture groups needed','Save two different captures on the same origin to compare passive DAM delivery policies.');return;}
 const options=groups.map(g=>({id:g.id,origin:g.origin,startedAt:g.first}));
 const earlier=choose('Baseline saved capture',options,policyDriftSelection?.[0]||groups[groups.length-1].id);
 const later=choose('Comparison saved capture',options,policyDriftSelection?.[1]||groups[0].id);
 controls.appendChild(earlier.wrap);controls.appendChild(later.wrap);
 controls.appendChild(vaultButton('Compare DAM policy evidence',async()=>{
  if(earlier.select.value===later.select.value)throw Error('Choose two different capture groups');
  const a=groups.find(g=>g.id===earlier.select.value),b=groups.find(g=>g.id===later.select.value);
  if(!a||!b)throw Error('Saved group not found');
  const [ar,br]=await Promise.all([loadGroupRecords(a),loadGroupRecords(b)]);
  policyDriftReport=THIPolicyDrift.compare(ar,br);
  policyDriftSelection=[a.id,b.id];drawView();notice('Comparison calculated offline from saved browser observations.');
 },'primary'));
 if(!policyDriftReport){empty(container,'Compare saved observations','Choose two captured sessions of the same site. No server permissions are tested.');return;}
 const s=policyDriftReport.overview,stats=elem('div','simple-grid');
 stats.appendChild(panel('Earlier requests',String(s.earlierRequests),'Recorded, not total site traffic'));
 stats.appendChild(panel('Later requests',String(s.laterRequests),'Different browsing can change counts'));
 stats.appendChild(panel('Coverage warnings',String(s.blindspotCount),'Check retention and capture state'));
 stats.appendChild(panel('Sample comparison',s.comparableSample?'Adequate sample':'Limited evidence','Descriptive only, never proof of policy enforcement'));
 container.appendChild(stats);
 container.appendChild(buildTable([
  {key:'category',label:'DAM delivery indicator'},{key:'denominator',label:'Compared across'},
  {key:'earlierCount',label:'Earlier count'},{key:'laterCount',label:'Later count'},
  {key:'earlierPerThousand',label:'Earlier per 1,000'},{key:'laterPerThousand',label:'Later per 1,000'},
  {key:'assessment',label:'Interpretation'},{key:'evidenceQuality',label:'Evidence confidence'},
  {key:'qualification',label:'Important limitation'}],matches(policyDriftReport.rows)));
 if(policyDriftReport.blindspots.length){container.appendChild(elem('h2','spaced-heading','Capture limitations'));
  policyDriftReport.blindspots.forEach(x=>container.appendChild(elem('p','helper',x)));}
 container.appendChild(elem('h2','spaced-heading','Owner-side verification'));
 policyDriftReport.ownerReview.forEach(x=>container.appendChild(elem('p','helper',x)));
 controls.appendChild(vaultButton('Export policy comparison (redacted JSON)',async()=>{
  download('trufflehog-dam-policy-comparison.json',JSON.stringify(policyDriftReport,null,2),'application/json');
  notice('Exported fixed-label, numeric DAM policy comparison; no raw site URLs or credentials.');
 }));
}

function renderDAMReviewMatrix(container){
 const report=THIDAMReview.evaluate(record);
 container.appendChild(elem('p','warn-note','This matrix is a passive owner-review aid. Site-wide signals are never automatically attributed to an identified DAM. A vendor-owned service host is not proof of repository ownership, public original-file access or a vulnerability.'));
 const stats=elem('div','simple-grid');
 stats.appendChild(panel('Recorded requests',String(report.overview.observedRequests),'Recent bounded metadata, not site-wide completeness.'));
 stats.appendChild(panel('Platform candidates',String(report.overview.platformCandidates),'Names and confidence drawn from the specialist detector.'));
 stats.appendChild(panel('Owner review signals',String(report.overview.reviewItems),'Not confirmed security vulnerabilities.'));
 stats.appendChild(panel('Retention drops',String(report.overview.retentionDrops),'Missing evidence can invalidate conclusions.'));
 container.appendChild(stats);
 const exportBtn=vaultButton('Export security matrix (redacted JSON)',()=>{
   download('trufflehog-dam-security-matrix.json',JSON.stringify(THIDAMReview.pack(record),null,2),'application/json');
   notice('Exported evidence-only DAM security review; no raw URLs, keys or request values.');
 });
 container.appendChild(exportBtn);
 container.appendChild(elem('h2','spaced-heading','Review observations'));
 container.appendChild(buildTable([
  {key:'scope',label:'Evidence scope'}, {key:'category',label:'Control area'},
  {key:'observation',label:'Observed indicator'}, {key:'assessment',label:'Assessment',badge:v=>v==='Owner review'?'warn':''},
  {key:'count',label:'Observations'}, {key:'qualification',label:'Limits'},
  {key:'ownerAction',label:'Owner verification'}],matches(report.rows)));
 container.appendChild(elem('h2','spaced-heading','Detected DAMs and owner checklists'));
 if(report.platforms.length)container.appendChild(buildTable([
  {key:'platform',label:'Platform clue'}, {key:'confidence',label:'Confidence'},
  {key:'relationship',label:'Browser evidence'}, {key:'observedRequests',label:'Vendor-host requests'},
  {key:'ownerChecklist',label:'Verify with owner'}],report.platforms));
 else empty(container,'No named DAM recognised','General security review observations are still shown above.');
 if(report.overview.requestSampleLimited)container.appendChild(elem('p','warn-note','Request sample was truncated: earlier records are not covered.'));
 container.appendChild(elem('p','helper',report.caveats.join(' ')));
}

function renderDAMAccess(container,rows){
 const info=THIDeliveryPolicy.analyze(record),stats=elem('div','simple-grid');
 container.appendChild(elem('p','warn-note',info.caveat));
 stats.appendChild(panel('Media requests',String(info.summary.mediaRequests),'Observed HTTP activity only'));
 stats.appendChild(panel('Delivered in session',String(info.summary.received),'Not proof of public or anonymous access'));
 stats.appendChild(panel('Denied 401/403',String(info.summary.restricted),'Current-session denials only'));
 stats.appendChild(panel('Download attachments',String(info.summary.attachments),'Header indicated an attachment, not a verified master'));
 container.appendChild(stats);
 if(rows.length)container.appendChild(buildTable([
  {key:'host',label:'Host'}, {key:'representation',label:'Rendition clue'}, {key:'status',label:'Observed state',badge:v=>v.startsWith('Restricted')?'warn':''},
  {key:'signed',label:'Signing'}, {key:'attachment',label:'Disposition'}, {key:'observations',label:'Occurrences'}, {key:'ownerReview',label:'Evidence limit'}],rows));
 else empty(container,'No media delivery requests observed','The absence of observed deliveries is not a finding. Capture normal browsing on an approved site.');
 container.appendChild(elem('h2','spaced-heading','Declared metadata field categories'));
 container.appendChild(elem('p','helper','These categories come from JSON field names only. They do not disclose field values, confirm access, or imply a valid download URL.'));
 if(info.metadata.length)container.appendChild(buildTable([{key:'category',label:'Field category'},{key:'sightings',label:'Sightings'},{key:'assessment',label:'Interpretation'}],info.metadata));
 else container.appendChild(elem('p','helper','No relevant JSON field names were observed. JSON response-shape inspection is optional and needs DevTools.'));
 if(info.summary.truncated)container.appendChild(elem('p','warn-note','Warning: the captured request inventory may be incomplete due to retention or grouping limits.'));
}
function renderCDNPolicy(container,rows){
 const info=THIDeliveryPolicy.analyze(record),stats=elem('div','simple-grid');
 container.appendChild(elem('p','warn-note','Only cache and signed-delivery facts recorded in this browsing session are shown. A public Cache-Control header does not mean a resource was delivered without authentication. TTL expiry, origin protection and revocation cannot be verified by passive observation. No alternate URLs are requested.'));
 stats.appendChild(panel('Signed delivery clues',String(info.summary.signed),'Signed URL values were discarded'));
 stats.appendChild(panel('Long public cache observed',String(info.summary.publicLongCache),'At least 24 hours; not proof of a revocation failure'));
 stats.appendChild(panel('Unclassified renditions',String(info.summary.unclassified),'No dependable preview/original label'));
 container.appendChild(stats);
 if(rows.length)container.appendChild(buildTable([
  {key:'host',label:'Delivery host'},{key:'representation',label:'Path/header clue'},{key:'status',label:'HTTP observation'},
  {key:'cachePolicy',label:'Cache policy'},{key:'signed',label:'Signed URL clue'},{key:'observations',label:'Count'},
  {key:'ownerReview',label:'Verification limit'}],rows));
 else empty(container,'No media delivery records observed','Visit a permitted gallery while recording to see cache policy evidence.');
 if(info.notes.length){container.appendChild(elem('h2','spaced-heading','Owner-side review prompts'));
  container.appendChild(buildTable([{key:'priority',label:'Priority'}, {key:'kind',label:'Area'}, {key:'count',label:'Observations'},
   {key:'evidence',label:'Observed evidence'},{key:'action',label:'Suggested review'}],info.notes));}
 if(info.summary.truncated)container.appendChild(elem('p','warn-note','Warning: available data may be truncated. This report is not an audit of all CDN resources.'));
}
function renderDAMRisk(container,rows){
 const result=THIDAMRisk.analyze(record,THIDAM.analyze(record));
 container.appendChild(elem('p','warn-note','Owner-review signals from already-observed data. Query-string credential classes contain no credential values. A matching URL, DAM signature, signed media parameter, or original-labelled image is NOT proof of a vulnerability or unrestricted original file. No extra requests are made.'));
 const stats=elem('div','simple-grid');
 stats.appendChild(panel('Recorded resources',String(result.stats.requests),'Only requests recorded in the selected capture; not the complete site.'));
 stats.appendChild(panel('Observed service hosts',String(result.stats.serviceHosts),'API, script, image and other host roles can overlap.'));
 stats.appendChild(panel('URL-based API auth clues',String(result.stats.credentialQueryRequests),'Query-key patterns, not credential validity or sensitivity.'));
 stats.appendChild(panel('Signed media clues',String(result.stats.signedMediaRequests),'Expected on authorised CDN delivery; no tokens retained.'));
 container.appendChild(stats);
 if(rows.length)container.appendChild(buildTable([
  {key:'severity',label:'Review priority',badge:v=>v==='Owner review'?'warn':''},
  {key:'category',label:'Area'},{key:'title',label:'Observation'},{key:'observations',label:'Count'},
  {key:'meaning',label:'Evidence limits'},{key:'ownerAction',label:'Suggested owner verification'}],rows));
 else empty(container,'No platform-aware security signals in captured data','This does not prove the website is secure. Load a permitted site with DevTools open and inspect the coverage view.');
 container.appendChild(elem('h2','spaced-heading','Platform-specific owner checklist'));
 if(result.reviews.length)container.appendChild(buildTable([
  {key:'platform',label:'Observed platform clue'},{key:'confidence',label:'Confidence'},
  {key:'checks',label:'Suggested owner review'},{key:'limitation',label:'Attribution limit'}],result.reviews));
 else container.appendChild(elem('p','helper','No supported named DAM platform recognised in this session. General review signals remain above.'));
 container.appendChild(elem('p','helper',result.stats.confidence+(result.stats.hostLimitExceeded?' · Host inventory truncated by internal limit.':'')));
 const jump=elem('button','btn alt','View observed integration boundaries');
 jump.type='button';jump.addEventListener('click',()=>navigateView('integration-boundaries'));container.appendChild(jump);
}
function renderIntegrationBoundaries(container,rows){
 const result=THIDAMRisk.analyze(record,THIDAM.analyze(record));
 container.appendChild(elem('p','warn-note','Integration boundary map is based on co-observed browser requests. It cannot prove shared storage, API authorisation, CMS service-account scopes, origin protection, or private-asset access. URLs and query values are never replayed.'));
 if(rows.length)container.appendChild(buildTable([
  {key:'from',label:'Current gallery origin'},{key:'to',label:'Observed host'},
  {key:'role',label:'Observed request role'},{key:'observedRequests',label:'Requests'},
  {key:'denied',label:'401/403'},{key:'evidence',label:'Basis'},{key:'limitation',label:'Limit'}],rows));
 else empty(container,'No observed integration boundaries','Start capture and browse normally. A JavaScript reference without a network request is not a verified connection.');
 container.appendChild(elem('h2','spaced-heading','Service-host inventory'));
 if(result.services.length)container.appendChild(buildTable([
  {key:'host',label:'Service host'},{key:'role',label:'Role'},
  {key:'requests',label:'Requests'},{key:'successful',label:'2xx/3xx'},
  {key:'denied',label:'401/403'},{key:'signedMedia',label:'Signed media clues'},
  {key:'legacyAuth',label:'API query-auth clues'}],result.services));
}
function renderDAMSecurity(container,rows){
 const result=THIDAMSecurity.analyze(record,THIDAM.analyze(record));
 container.appendChild(elem('p','warn-note','Passive evidence only. This review does not establish a vulnerability, verify credentials, test object access, or fetch private assets. Some cache/share settings are expected on public galleries. Software advisories are checked only against a version that you enter manually.'));
 const totals=elem('div','simple-grid');
 totals.appendChild(panel('Owner-review prompts',String(result.stats.riskReview),'Indicators that warrant owner verification; not confirmed issues.'));
 totals.appendChild(panel('Informational observations',String(result.findings.filter(r=>r.level==='Informational').length),'Expected security and delivery mechanisms may appear here.'));
 totals.appendChild(panel('Capture completeness',result.stats.incomplete?'Incomplete':'Unverified overall','The extension cannot measure requests Chrome never recorded.'));
 container.appendChild(totals);
 if(rows.length)container.appendChild(buildTable([
   {key:'level',label:'Review level',badge:v=>v==='Review promptly'?'danger':v==='Review'?'warn':''},
   {key:'kind',label:'Area'},{key:'title',label:'Finding'},
   {key:'evidence',label:'Evidence (redacted)'},{key:'explanation',label:'Limits'},{key:'next',label:'Owner verification'}],rows));
 else empty(container,'No current risk indicators','Start a capture and browse permitted pages with DevTools open. Absence of findings does not prove security.');
 container.appendChild(elem('h2','spaced-heading','DAM-specific review checklists'));
 if(result.profiles.length)container.appendChild(buildTable([
   {key:'name',label:'Platform hint'},{key:'confidence',label:'Recognition confidence'},
   {key:'check',label:'Owner checklist'},{key:'assessment',label:'Evidence limitation'}],result.profiles));
 else container.appendChild(elem('p','helper','No supported named DAM profile identified. Generic security evidence remains available above.'));
 container.appendChild(elem('h2','spaced-heading','Offline version advisory lookup'));
 container.appendChild(elem('p','helper','Enter a version YOU have independently verified. A platform name or JavaScript clue is not sufficient to establish the installed server version. This static lookup is not a live advisory feed.'));
 const tools=elem('div','vault-controls');
 const vendorSelect=elem('select');vendorSelect.setAttribute('aria-label','Advisory product');
 for(const [value,label] of [['resourcespace','ResourceSpace'],['opentext-dam','OpenText Digital Asset Management']]){
   const opt=elem('option','',label);opt.value=value;vendorSelect.appendChild(opt);
 }
 const versionInput=elem('input');versionInput.type='text';versionInput.placeholder='Verified version (e.g. 9.6.18273)';versionInput.maxLength=35;versionInput.setAttribute('aria-label','Verified product version');
 const advisoryMessage=elem('div','helper','No version checked.');
 const button=elem('button','btn alt','Check published advisories');button.type='button';
 button.addEventListener('click',()=>{
   const answer=THIDAMSecurity.advisoryLookup(vendorSelect.value,versionInput.value);
   advisoryMessage.replaceChildren();
   const txt=answer.status==='invalid-version'?'Enter a numeric dotted version.':answer.status==='review-build'?'Major version matches a historical advisory; exact build revision is required.':answer.status==='review-version'?'Version falls in a published affected range; check vendor remediation and deployment status.':answer.status==='no-identified-match'?'No match in the two bundled advisories. This does NOT establish that the version is safe.':'Product not recognised.';
   advisoryMessage.appendChild(elem('p','',txt));
   for(const a of answer.results){
      const link=document.createElement('a');link.textContent=a.id+' — '+a.title;link.href=a.source;link.target='_blank';link.rel='noopener noreferrer';
      advisoryMessage.appendChild(link);advisoryMessage.appendChild(elem('p','',a.detail));
   }
 });
 tools.appendChild(vendorSelect);tools.appendChild(versionInput);tools.appendChild(button);
 container.appendChild(tools);container.appendChild(advisoryMessage);
}
function renderJSHistory(container){
 container.appendChild(elem('p','warn-note','Compares already-scanned JavaScript responses across recorded sessions. No new network requests are made. Missing files may simply be outside the capture window. SHA-256 proves changed response bytes, not a vulnerable website. Masked indicator location matches cannot prove secret-value equality.'));
 const controls=elem('div','vault-controls');
 const sel=elem('select');sel.setAttribute('aria-label','Saved JavaScript baseline');
 const opt=elem('option','', 'Choose an earlier saved session');opt.value='';sel.appendChild(opt);
 const options=sessionsCache.filter(s=>s.origin===record?.origin&&s.id!==record?.sessionId);
 for(const s of options){const option=elem('option','',`${String(s.startedAt||'').slice(0,19)} · ${s.requests||0} requests · segment ${s.segmentIndex||1}`);option.value=s.id;sel.appendChild(option);}
 if(jsBaseline?.sessionId&&options.some(s=>s.id===jsBaseline.sessionId))sel.value=jsBaseline.sessionId;
 const btn=elem('button','btn alt','Compare JavaScript versions');
 btn.addEventListener('click',async()=>{if(!sel.value){notice('Choose a saved baseline.',true);return;}
  try{const reply=await chrome.runtime.sendMessage({type:'GET_SAVED_SESSION',tabId,sessionId:sel.value});
   if(!reply?.ok)throw new Error('Baseline unavailable');jsBaseline=reply.record;
   jsComparison=THIChanges.compare(jsBaseline,record);drawView();notice('Offline JavaScript comparison complete.');
  }catch(e){notice(e.message,true);}
 });
 controls.appendChild(sel);controls.appendChild(btn);
 controls.appendChild(vaultButton('Refresh saved baselines',async()=>{await loadVault();drawView();}));
 container.appendChild(controls);
 if(!options.length)container.appendChild(elem('p','helper','There are no archived investigations for this exact site origin yet. Stop a capture to archive it, then record another visit.'));
 if(!jsComparison)return;
 const s=jsComparison.stats;
 const grid=elem('div','simple-grid');
 for(const [title,val,description] of [
  ['Changed JS',s.changed,'Browser-decoded response text differs'],['Identical JS',s.unchanged,'Matching observed decoded text'],
  ['Newly observed URLs',s.newFiles,'May have been previously missed'],['Unverified comparisons',s.unverified,'Digest not available']])
   grid.appendChild(panel(title,String(val),description));
 container.appendChild(grid);
 container.appendChild(elem('p','helper',jsComparison.assessment));
 if(jsComparison.rows.length)container.appendChild(buildTable([
  {key:'url',label:'Observed JavaScript',css:'url mono'}, {key:'status',label:'Comparison'},
  {key:'previousHash',label:'Previous SHA-256',css:'mono',format:v=>v?String(v).slice(0,16)+'…':'Unverified'},
  {key:'currentHash',label:'Current SHA-256',css:'mono',format:v=>v?String(v).slice(0,16)+'…':'Unverified'},
  {key:'previousBytes',label:'Earlier size'}, {key:'currentBytes',label:'Current size'}],jsComparison.rows));
 container.appendChild(elem('h2','spaced-heading',`Newly recorded masked indicators (${jsComparison.newIndicators.length})`));
 container.appendChild(elem('p','helper','New to this comparison, not necessarily newly exposed. Contents remain masked and are not validated.'));
 if(jsComparison.newIndicators.length)container.appendChild(buildTable([
  {key:'type',label:'Indicator'}, {key:'source',label:'Source',css:'url mono'},
  {key:'line',label:'Line'}, {key:'column',label:'Column'}, {key:'masked',label:'Mask'}],jsComparison.newIndicators));
 else container.appendChild(elem('p','helper','No additional masked indicator locations were observed in the compared responses.'));
 container.appendChild(vaultButton('Export comparison JSON',async()=>download(fileName()+'-js-changes.json',JSON.stringify(jsComparison,null,2),'application/json')));
}
async function saveCustomProfiles(updated){
 const clean=THICustomProfiles.validateAll(updated);
 await chrome.storage.local.set({[THICustomProfiles.STORAGE_KEY]:clean});
 customProfiles=clean;notice('Custom detection profiles saved locally.');drawView();
}
function renderProfileEditor(container){
 container.appendChild(elem('p','warn-note','Profiles operate ONLY on observed/referrenced HTTP(S) resource hosts and literal paths. No arbitrary scripts, regular expressions, fetched endpoints or secret material are accepted. Evidence is heuristic, never proof of backend deployment.'));
 const editor=elem('div','profile-form');editor.appendChild(elem('h3','',editProfileId?'Edit custom technology profile':'Create custom technology profile'));
 const fields=elem('div','profile-fields');
 function control(label,kind,placeholder,value){
   const wrap=elem('label','profile-field',label);
   const node=document.createElement(kind);if(kind==='input')node.type='text';
   if(placeholder)node.placeholder=placeholder;
   if(value!==undefined)node.value=value;
   wrap.appendChild(node);fields.appendChild(wrap);return node;
 }
 const chosen=customProfiles.find(p=>p.id===editProfileId);
 const name=control('Provider / technology name','input','My photography DAM',chosen?.name||'');name.maxLength=64;
 const layer=control('Technology category','select');
 for(const type of THICustomProfiles.LAYERS){const opt=elem('option','',type);opt.value=type;layer.appendChild(opt);}
 layer.value=chosen?.layer||'DAM';
 const domains=control('Observed domain suffixes (one per line, maximum 5)','textarea','cdn.example.com\narchive.example.com',chosen?.domains?.join('\n')||'');domains.rows=3;
 const prefixes=control('Optional literal URL path prefixes (one per line, maximum 6)','textarea','/api/public/\n/images/',chosen?.prefixes?.join('\n')||'');prefixes.rows=3;
 editor.appendChild(fields);const actions=elem('div','profile-actions');
 const save=elem('button','btn primary',chosen?'Save changes':'Add local profile');
 save.addEventListener('click',async()=>{
 try{
 const updated=THICustomProfiles.add(customProfiles,{id:chosen?.id||'custom-'+Date.now().toString(36)+'-'+Math.random().toString(36).slice(2,10),name:name.value,layer:layer.value,domains:domains.value,prefixes:prefixes.value});
 editProfileId=null;await saveCustomProfiles(updated);
 }catch(e){notice(e.message,true);}
 });actions.appendChild(save);
 if(chosen){const cancel=elem('button','btn alt','Cancel edit');cancel.addEventListener('click',()=>{editProfileId=null;drawView();});actions.appendChild(cancel);}
 const exp=elem('button','btn alt','Export profile definitions');
 exp.addEventListener('click',()=>download('trufflehog-custom-profiles-v4.json',JSON.stringify({schemaVersion:1,profiles:customProfiles},null,2),'application/json'));actions.appendChild(exp);
 const upload=elem('input');upload.type='file';upload.accept='.json,application/json';upload.hidden=true;
 upload.addEventListener('change',async()=>{
 try{
 if(!upload.files?.[0])return;if(upload.files[0].size>32000)throw Error('Profile file exceeds 32 KB');
 const parsed=JSON.parse(await upload.files[0].text());if(parsed.schemaVersion!==1)throw Error('Unsupported profile schema');
 const clean=THICustomProfiles.validateAll(parsed.profiles);
 if(!confirm(`Replace your ${customProfiles.length} local profiles with ${clean.length} imported profiles?`))return;
 editProfileId=null;await saveCustomProfiles(clean);
 }catch(e){notice('Profile import blocked: '+e.message,true);}
 finally{upload.value='';}
 });editor.appendChild(upload);
 const imp=elem('button','btn alt','Import profile definitions');imp.addEventListener('click',()=>upload.click());actions.appendChild(imp);
 editor.appendChild(actions);container.appendChild(editor);
 const profiles=elem('div','profile-panel');profiles.appendChild(elem('h2','spaced-heading',`Saved profiles (${customProfiles.length}/${THICustomProfiles.MAX_PROFILES})`));
 const matches=new Map(THICustomProfiles.inspect(customProfiles,record).map(p=>[p.id,p]));
 for(const p of customProfiles){
  const line=elem('div','profile-entry'),content=elem('div');content.appendChild(elem('strong','',p.name+' · '+p.layer));
  content.appendChild(elem('div','small muted','Domains: '+p.domains.join(', ')+'; paths: '+(p.prefixes.join(', ')||'any path')));
  const hit=matches.get(p.id);content.appendChild(elem('div','small',hit?hit.count+' matching observed/referenced resource(s)':'No evidence matched in this capture'));
  line.appendChild(content);const controls=elem('div','profile-actions');
  const edit=elem('button','btn alt','Edit');edit.addEventListener('click',()=>{editProfileId=p.id;drawView();window.scrollTo?.(0,0);});controls.appendChild(edit);
  const del=elem('button','btn danger','Delete');del.addEventListener('click',async()=>{
    if(!confirm(`Delete custom profile "${p.name}"?`))return;
    editProfileId=null;try{await saveCustomProfiles(customProfiles.filter(x=>x.id!==p.id));}catch(e){notice(e.message,true);}
  });controls.appendChild(del);line.appendChild(controls);profiles.appendChild(line);
 }
 if(!customProfiles.length)profiles.appendChild(elem('p','helper','No custom technology profiles yet. Built-in Capture and other detection profiles remain unchanged.'));
 container.appendChild(profiles);
}
function renderExposureHistory(container){
 container.appendChild(elem('p','warn-note','Offline history of masked findings. Changed means two locally keyed fingerprints at a matching file location differed using the same key. Historical missing observations or imported evidence do not prove a secret changed or was removed. No values are exposed or validated.'));
 const tools=elem('div','toolbar');
 const toggle=elem('button','btn alt',changeNotificationsEnabled?'Changed-secret notifications: ON':'Changed-secret notifications: OFF');
 toggle.addEventListener('click',async()=>{
  const result=await chrome.runtime.sendMessage({type:'SET_SECRET_CHANGE_NOTIFICATIONS',tabId,enabled:!changeNotificationsEnabled});
  if(result?.ok){changeNotificationsEnabled=result.enabled;drawView();notice('Changed-secret desktop notifications '+(result.enabled?'enabled':'disabled'));}
  else notice('Notification preference could not be changed.',true);
 });tools.appendChild(toggle);
 const refreshHistory=elem('button','btn alt','Refresh saved history');refreshHistory.addEventListener('click',async()=>{
  const data=await chrome.runtime.sendMessage({type:'GET_EXPOSURE_HISTORY',tabId});
  if(data?.ok){exposureHistoryResult=data.history;drawView();}else notice('Could not load saved history.',true);
 });tools.appendChild(refreshHistory);
 const exportJson=elem('button','btn alt','Export history JSON');exportJson.addEventListener('click',()=>{
   download('trufflehog-exposure-history.json',JSON.stringify({format:'trufflehog-exposure-history',version:1,origin:record?.origin||'',...exposureHistoryResult},null,2),'application/json');
 });exportJson.disabled=!exposureHistoryResult;tools.appendChild(exportJson);
 container.appendChild(tools);
 const counts=exposureHistoryResult?.counts;
 if(counts){
  const cards=elem('div','simple-grid');
  for(const [label,num] of [['Saved sightings',counts.total],['New locations',counts.new],['Changed indicators',counts.changed],['Unverified',counts.unverified]]){
   cards.appendChild(panel(label,String(num),'Source and review metadata only'));
  }
  container.appendChild(cards);
 }
 if(exposureHistoryResult?.rows?.length){
  container.appendChild(buildTable([
   {key:'at',label:'Observed'},{key:'type',label:'Indicator'},{key:'source',label:'Resource',css:'url mono'},
   {key:'line',label:'Line'},{key:'column',label:'Column'},
   {key:'changeState',label:'Local comparison',badge:v=>v==='changed'?'warn':v==='new'?'success':''},
   {key:'reviewStatus',label:'Review state'},{key:'reviewEvents',label:'Review events'},{key:'segmentIndex',label:'Segment'}],exposureHistoryResult.rows));
 }else container.appendChild(elem('p','helper','No saved masked indicators for this origin. Finish a capture to archive findings.'));
}
function renderAwsDam(container){
  container.appendChild(elem('p','warn-note','AWS-hosted DAM evidence from already observed requests and optional DevTools JSON field names. Presigned S3 POST fields indicate an upload authorisation, not a download. No S3 policy decoding, bucket/object keys, credentials, signatures, execution ARNs, private payloads or guessed endpoints. AWS-compatible schema names alone do not prove AWS hosting.'));
  const all=THIAwsDam.rows(record);
  const cards=elem('div','simple-grid');
  cards.appendChild(panel('AWS-related requests',String(all.filter(x=>x.evidence==='Observed AWS service hostname').length),'Observed hostnames only; individual request lifecycles deduplicated.'));
  cards.appendChild(panel('Presigned POST field patterns',String(all.filter(x=>/presigned POST/i.test(x.kind)).length),'Upload field indicators, policy never decoded.'));
  cards.appendChild(panel('JSON workflow hints',String(all.filter(x=>/schema clues/.test(x.kind)).length),'Only when JSON response shapes were explicitly enabled.'));
  cards.appendChild(panel('Recording',recording?.downloadObserver?'Download observer on':'Off / saved','Enable Download observer for HTTP and form-field evidence.'));
  container.appendChild(cards);
  const exp=elem('button','btn alt','Export AWS observations JSON');
  exp.addEventListener('click',()=>download('trufflehog-aws-dam-observations.json',JSON.stringify({schema:'trufflehog-aws-dam-observations-v1',capturedSession:record?.sessionId||null,observations:THIAwsDam.rows(record)},null,2),'application/json'));
  container.appendChild(exp);
  const rows=matches(all);
  if(!rows.length){empty(container,'No AWS DAM observations','Start an opted-in Download Observer session. Optionally enable DevTools JSON shapes for workflow metadata field names. No active S3 or API probes are made.');return;}
  container.appendChild(buildTable([
    {key:'at',label:'Observed'},{key:'host',label:'Service host'}, {key:'method',label:'Method'},
    {key:'service',label:'Service classification'}, {key:'kind',label:'Workflow clue'},
    {key:'signing',label:'Signing indicators'}, {key:'fields',label:'Field types'},
    {key:'status',label:'HTTP status'}, {key:'evidence',label:'Confidence'},
    {key:'policy',label:'Privacy limit'}],rows));
}
function renderUploadProtocols(container){
  const report=THIUploadAPI.analyse(record);
  container.appendChild(elem('p','warn-note','OBSERVED REQUESTS ONLY. Upload protocols are classified from query parameter NAMES, recognised header NAMES, bounded enumerated operation types, and provider hostnames. No request bodies, upload IDs, object keys, signatures, CSRF values or signing policies are retained. A successful HTTP response is not evidence that a DAM has finished processing an asset.'));
  const cards=elem('div','simple-grid');
  cards.appendChild(panel('Upload-related requests',String(report.counts.observations),'Each grouped HTTP request; only opted-in browser observations.'));
  cards.appendChild(panel('Initiation clues',String(report.counts.initiations),'Session creation or multipart start indicators.'));
  cards.appendChild(panel('Part / block transfers',String(report.counts.transferRequests),'Part transfers, resumable transfers and form uploads.'));
  cards.appendChild(panel('Commit requests',String(report.counts.commitRequests),'Commit request observed; asset completion not verified.'));
  container.appendChild(cards);
  const exp=elem('button','btn alt','Export privacy-safe upload protocol JSON');
  exp.addEventListener('click',()=>download('trufflehog-v56-upload-protocols.json',JSON.stringify(report,null,2),'application/json'));
  container.appendChild(exp);
  const rows=matches(report.rows);
  if(rows.length)container.appendChild(buildTable([
    {key:'reference',label:'Local ref'},{key:'at',label:'Observed'},{key:'host',label:'Service host'},
    {key:'provider',label:'Protocol match'},{key:'phase',label:'Phase clue'},
    {key:'method',label:'Method'},{key:'status',label:'HTTP status'},
    {key:'markers',label:'Observed indicators'},{key:'outcome',label:'Interpretation'}],rows));
  else empty(container,'No upload protocol observations','Start an approved capture and explicitly enable Download Observer. Only request headers and parameters already visible to Chrome are classified.');
  for(const line of report.limitations)container.appendChild(elem('p','helper',line));
}
function renderSchemaDiff(container){
  container.appendChild(elem('p','warn-note','OFFLINE comparison only. DevTools JSON shapes must have been explicitly enabled during BOTH captures. Endpoint paths are used only transiently for matching and never included in the exported report. Missing endpoints may mean incomplete browsing, not server changes. Only the exact same origin can be compared.'));
  const options=(sessionsCache||[]).filter(s=>s.origin===record?.origin && s.id && s.id!==record?.sessionId );
  const controls=elem('div','vault-controls');
  if(options.length){
    const pick=choose('Baseline archived capture (same origin)',options,apiSchemaBaseline?.sessionId||options[0].id);
    controls.appendChild(pick.wrap);
    controls.appendChild(vaultButton('Compare observed JSON shapes',async()=>{
      const result=await chrome.runtime.sendMessage({type:'GET_SAVED_SESSION',tabId,sessionId:pick.select.value});
      if(!result?.ok||!result.record)throw Error('Baseline unavailable');
      apiSchemaBaseline=result.record;
      apiSchemaComparison=THIUploadAPI.compare(apiSchemaBaseline,record);
      if(apiSchemaComparison.error)throw Error(apiSchemaComparison.error);
      drawView();notice('Compared recorded JSON field/type shapes locally; no website requests.');
    }));
  }else controls.appendChild(elem('p','helper','No other archived capture of this exact origin with recorded JSON response shapes. Enable JSON shapes with DevTools open, record twice, and stop each capture.'));
  container.appendChild(controls);
  if(!apiSchemaComparison){empty(container,'No baseline comparison yet','Choose a saved baseline with JSON response shapes. Only names and type differences are compared.');return;}
  const report=apiSchemaComparison;
  const cards=elem('div','simple-grid');
  cards.appendChild(panel('Baseline endpoints',String(report.totals.baselineEndpoints||0)));
  cards.appendChild(panel('Current endpoints',String(report.totals.currentEndpoints||0)));
  cards.appendChild(panel('Observed shape differences',String(report.totals.changedShapes||0)));
  cards.appendChild(panel('Unmatched observations',String((report.totals.newlyObserved||0)+(report.totals.notObserved||0))));
  container.appendChild(cards);
  const exp=elem('button','btn alt','Export redacted schema-difference JSON');
  exp.addEventListener('click',()=>download('trufflehog-v56-api-shape-diff.json',JSON.stringify(report,null,2),'application/json'));
  container.appendChild(exp);
  const rows=matches(report.rows);
  if(rows.length)container.appendChild(buildTable([
    {key:'endpoint',label:'Local label'},{key:'host',label:'Observed host'},
    {key:'method',label:'Method'},{key:'category',label:'Route class'},
    {key:'baselineFields',label:'Before fields'},{key:'currentFields',label:'After fields'},
    {key:'added',label:'Added'},{key:'removed',label:'Missing'},
    {key:'typeChanges',label:'Type differences'},{key:'status',label:'Observation'},
    {key:'qualification',label:'Evidence limit'}],rows));
  else empty(container,'No comparable JSON shapes','Enable opt-in JSON shape capture in both sessions.');
  for(const line of report.limitations||[])container.appendChild(elem('p','helper',line));
}
function renderAssetQuality(container){
  const analysis=THIQuality.analyze(record),rows=matches(analysis.families);
  container.appendChild(elem('p','warn-note','BEST OBSERVED ≠ ORIGINAL MASTER. Pixel dimensions count as verified only when extracted from received encoded image bytes with explicit opt-in and DevTools open. Filename-family groupings are hypotheses. Browser download events are intentionally separate; image bytes and full file/asset URLs are not exported.'));
  const cards=elem('div','simple-grid');
  cards.appendChild(panel('Observed renditions',String(analysis.stats.imageObservations),'Asset observations and individually verified responses, bounded per capture.'));
  cards.appendChild(panel('Verified image files',String(analysis.stats.verifiedFiles),'SHA-256 of received bytes, opted in through DevTools.'));
  cards.appendChild(panel('Measured pixel sizes',String(analysis.stats.measuredDimensions),'Encoded pixel dimensions of verified bytes only.'));
  cards.appendChild(panel('Unverified families',String(analysis.stats.unverifiedFamilies),'No verified image dimensions available.'));
  cards.appendChild(panel('Exact duplicate groups',String(analysis.stats.exactDuplicateSets),'Matching SHA-256 of received bytes only.'));
  container.appendChild(cards);
  const exp=elem('button','btn alt','Export redacted asset quality JSON');
  exp.addEventListener('click',()=>download('trufflehog-v55-asset-quality.json',JSON.stringify(THIQuality.exportReport(record),null,2),'application/json'));
  container.appendChild(exp);
  if(rows.length)container.appendChild(buildTable([
    {key:'familyRef',label:'Family ref'}, {key:'host',label:'Observed host'},
    {key:'observedVariants',label:'Variants'}, {key:'verifiedFiles',label:'Hash verified'},
    {key:'highestVerifiedPixels',label:'Highest verified pixels'},
    {key:'largestVerifiedBytes',label:'Bytes of highest verified rendition'},
    {key:'verifiedPixelRatio',label:'Largest / smallest verified pixels'},
    {key:'biggestBrowserReported',label:'Largest browser-only hint'},
    {key:'differentAspectRatios',label:'Aspect differences'},
    {key:'formats',label:'Types'}, {key:'assessment',label:'Assessment'}],rows));
  else empty(container,'No observed image families','Start capture and browse images. Enable Verify image bytes and open DevTools before reloading for encoded pixel measurements.');
  container.appendChild(elem('h2','spaced-heading','Exact received-byte duplicate groups'));
  if(analysis.duplicates.length)container.appendChild(buildTable([
    {key:'duplicateRef',label:'Group'}, {key:'receivedCopies',label:'Copies'}, {key:'distinctHosts',label:'Hosts'},
    {key:'verifiedBytes',label:'Bytes'}, {key:'dimensions',label:'Measured pixels'},
    {key:'confidence',label:'Evidence'}, {key:'assessment',label:'Limitations'}],analysis.duplicates));
  else container.appendChild(elem('p','helper','No repeated verified SHA-256 values in this capture. Filename similarities are not counted as duplicates.'));
  if(analysis.stats.truncated||analysis.stats.verificationDrops)container.appendChild(elem('p','warn-note','Bounded analysis or dropped verification records: the quality ledger may be incomplete. Previous Evidence Vault segments may contain other observations.'));
}
function renderQualityTransfers(container){
 const intel=THIQuality.analyze(record),t=intel.transfers;
 container.appendChild(elem('p','warn-note','Transfer integrity is a summary of observed Chrome events, not proof of full file integrity. HTTP 206 can be a valid partial response. Browser downloads are not attributed to a photographed asset without exact verification; range values are numeric only, not usable signed requests.'));
 const cards=elem('div','simple-grid');
 cards.appendChild(panel('Browser completed',String(t.complete),'May be unrelated to an image capture.'));
 cards.appendChild(panel('Browser interrupted',String(t.interrupted),'Coarse error classes only.'));
 cards.appendChild(panel('HTTP 206 observed',String(t.partialResponses),'No assumption that delivery failed.'));
 cards.appendChild(panel('Validated byte ranges',String(t.measuredRanges),'Only responses with safe numeric Content-Range.'));
 container.appendChild(cards);
 container.appendChild(buildTable([
  {key:'stage',label:'Kind'}, {key:'metric',label:'Observation'}, {key:'count',label:'Count'}, {key:'assessment',label:'Evidence limit'}],matches(qualityTransferRows())));
 const exp=elem('button','btn alt','Export redacted transfer evidence');
 exp.addEventListener('click',()=>download('trufflehog-v55-transfer-evidence.json',JSON.stringify({version:'5.5',transfers:t},null,2),'application/json'));
 container.appendChild(exp);
}
function renderWorkflowChains(container){
  container.appendChild(elem('p','warn-note','A reconstructed request lifecycle uses its real browser request ID internally. Separate requests and browser downloads are ASSOCIATIONS ONLY, not verified causation. Raw request IDs, URLs, authorization material, filenames and field values are absent from this report.'));
  const result=THIWorkflow.analyse(record);
  const row=elem('div','simple-grid');
  row.appendChild(panel('Candidate POST workflows',String(result.totals.candidatePostWorkflows),'May include non-download API operations; no replay or new requests.'));
  row.appendChild(panel('HTTP lifecycles',String(result.totals.observedRequestLifecycles),'Grouped by request ID within locally observed traffic.'));
  row.appendChild(panel('Download observations',String(result.totals.downloadsWithLocalRefs),'Paired starts/ends only if the worker retained its ephemeral map.'));
  row.appendChild(panel('Unlinked downloads',String(result.unassociatedDownloads.length),'Not proof that downloads lacked an API request.'));
  container.appendChild(row);
  const exportButton=elem('button','btn alt','Export redacted workflow & coverage report');
  exportButton.addEventListener('click',()=>download('trufflehog-v54-workflow-report.json',JSON.stringify(THIWorkflow.exportReport(record,recording),null,2),'application/json'));
  container.appendChild(exportButton);
  const rows=matches(result.workflows.map(w=>({...w,followups:w.related.map(x=>x.step+' ('+x.evidence+')').join('; '),
    stages:w.initialStages.join(', '),download:w.downloadRef||'Unassociated'})));
  if(!rows.length)empty(container,'No candidate POST workflows','Start an approved capture, opt in to Download observer and perform an authorised download. Some flows use GET only and appear under Download telemetry.');
  else container.appendChild(buildTable([
    {key:'ref',label:'Workflow'}, {key:'at',label:'Observed'}, {key:'host',label:'Request host'},
    {key:'method',label:'Method'}, {key:'httpStatus',label:'HTTP status'}, {key:'stages',label:'Observed stages'},
    {key:'classification',label:'Export job clue'},{key:'followups',label:'Candidate follow-ups'},
    {key:'download',label:'Download ref'},{key:'outcome',label:'Observed outcome'},
    {key:'confidence',label:'Association confidence'}],rows));
  if(result.unassociatedDownloads.length){
    container.appendChild(elem('h3','','Browser downloads without unambiguous POST association'));
    container.appendChild(buildTable([{key:'ref',label:'Local ref'},{key:'at',label:'Observed'},
      {key:'host',label:'Host'},{key:'status',label:'State'},{key:'errorCategory',label:'Error class'},
      {key:'evidence',label:'Limits'}],matches(result.unassociatedDownloads)));
  }
}
function renderWorkflowCoverage(container){
  container.appendChild(elem('p','warn-note','Coverage is a report on events actually recorded—not proof of complete site capture. Chrome MV3 worker restarts can lose volatile download associations; DevTools does not see prior requests. Older saved sessions may lack the opt-in marker.'));
  const result=THIWorkflow.coverage(record,recording),row=elem('div','simple-grid');
  row.appendChild(panel('Observed lifecycle events',String(result.counts.events),'Locally recorded steps; not separate transfers.'));
  row.appendChild(panel('Missing starts',String(result.counts.unpairedRequestStarts),'Completed requests whose start was not recorded.'));
  row.appendChild(panel('Missing ends',String(result.counts.unpairedRequestEnds),'May still be in flight or unobserved.'));
  row.appendChild(panel('Dropped events',String(result.counts.dropped),'Evidence could be in a previous saved segment.'));
  container.appendChild(row);
  container.appendChild(elem('p','helper',result.conclusion));
  container.appendChild(buildTable([{key:'label',label:'Coverage stage'}, {key:'state',label:'Assessment'},
    {key:'count',label:'Count'}, {key:'detail',label:'Explanation'}],matches(result.checks)));
  const exportButton=elem('button','btn alt','Export coverage JSON');
  exportButton.addEventListener('click',()=>download('trufflehog-v54-coverage.json',JSON.stringify(result,null,2),'application/json'));
  container.appendChild(exportButton);
}
function renderDownloadTraces(container){
  container.appendChild(elem('p','warn-note','OPT-IN for the selected capture. Shows request field categories, signature schemes, locally labelled W3C traces, CDN header presence and download outcomes. Opaque trace IDs, header/POST values, cookies, full URLs and filenames are excluded. CloudEvents export is locally generated, NOT a server event. Absent means unobserved.'));
  const rows=matches(dataset());
  const panelRow=elem('div','simple-grid');
  panelRow.appendChild(panel('Recorded lifecycle events',String(record?.downloadEvents?.length||0),'Listener stages, not separate downloads.'));
  panelRow.appendChild(panel('Dropped by local limit',String(record?.downloadEventsDropped||0),'Long sessions may be split in Evidence Vault.'));
  panelRow.appendChild(panel('Observer',recording?.downloadObserver?'Enabled':'Off / saved','Enable using the Download observer button while capturing.'));
  panelRow.appendChild(panel('Trace indicators',String((record?.downloadEvents||[]).filter(e=>e.traceHeaderPresent||e.traceRef).length),'Session-local labels only; not backend spans.'));
  panelRow.appendChild(panel('Download failures',String((record?.downloadEvents||[]).filter(e=>e.downloadStatus==='interrupted').length),'Browser errors grouped by category.'));
  container.appendChild(panelRow);
  const exportEvents=elem('button','btn alt','Export local CloudEvents JSON');
  exportEvents.addEventListener('click',()=>{
    const events=THITelemetry.cloudEvents(record?.downloadEvents||[],record?.sessionId);
    download('trufflehog-local-download-events.json',JSON.stringify(events,null,2),'application/json');
  });container.appendChild(exportEvents);
  if(!rows.length){empty(container,'No observed download steps','Start capture, enable Download observer, then use a download you are authorised to perform.');return;}
  container.appendChild(buildTable([
    {key:'at',label:'Observed'}, {key:'method',label:'Method'}, {key:'host',label:'Host'},
    {key:'status',label:'Status'}, {key:'auth',label:'Auth header types'}, {key:'body',label:'Body state'},
    {key:'fields',label:'POST field categories'}, {key:'signature',label:'Signing indicators'},
    {key:'redirect',label:'Redirect host'}, {key:'file',label:'Delivery'},
    {key:'trace',label:'Trace label'}, {key:'cdn',label:'CDN header presence'},
    {key:'cache',label:'Cache policy'}, {key:'bytes',label:'Bytes received / declared'}, {key:'error',label:'Failure class'},
    {key:'evidence',label:'Correlation'}],rows));
}
function drawView() {
  $('sectionTitle').textContent = ({'asset-licensing':'Observed licensing options and prices are not permission to download; actual file delivery and original master status remain distinct.', 'generic-relationships':'Grade relationships in observed traffic without inventing causality','har-coverage':'Compare a saved capture against an independently exported browser HAR.','evidence-synthesis':'Evidence-weighted summary of two saved DAM captures with context, workflow and delivery checks.','workflow-pattern':'Compare recorded request-category patterns across two captures; no identical-action guarantee.','compare-readiness':'Check whether two saved captures have equivalent context and coverage','policy-drift':'Compare saved, same-origin DAM delivery-policy evidence without testing access','capture-repair':'Explainable fixes for capture coverage failures','local-benchmark':'Local-only deterministic browser capture acceptance','case-compare':'Compare two saved same-origin capture groups; no absence or count difference proves a security change.', 'case-dossier':'Offline investigation dossier and evidence confidence','dam-specialists':'Evidence-led DAM platform specialists','upload-protocols':'Observed multipart and resumable upload requests','api-schema-diff':'Compare observed JSON field/type structures','quality-ledger':'Verified observed image renditions', 'quality-transfers':'Download outcomes and HTTP range evidence', 'workflow-chains':'Download chain reconstruction (evidence-ranked)','workflow-coverage':'Download observer capture and blind spots','aws-dam':'Observed AWS-style asset ingestion and workflow evidence','download-traces':'Authenticated download workflow observations','frames-workers':'Embedded frames and worker-related evidence','site-relations':'Offline cross-site infrastructure correlations',explorer:'Cross-archive evidence explorer',diagnostics:'Capture retention and coverage diagnostics',vault:'Saved investigations and offline comparison', 'vault-search':'Search archived masked findings',replay:'Saved event timeline',overview:'Session overview',platforms:'Detected DAM, CMS, delivery and viewer technologies','dam-security':'DAM security observations and owner-review checklist','dam-review-matrix':'Privacy-safe DAM security and platform attribution review','dam-risk':'DAM platform-aware risk and credential-handling indicators','dam-access':'DAM asset delivery states','cdn-policy':'CDN signing and cache policies','integration-boundaries':'Observed CMS, API and image-delivery host relationships',lineage:'Observed asset lineage and CMS/DAM clues',delivery:'Observed image-delivery pipelines',viewers:'Specialist image viewer request families','viewer-manifests':'Observed IIIF / DZI / Zoomify technical manifests',network:'Observed HTTP requests',api:'API relationship map',images:'Observed image files',variants:'Observed variant families',matches:'Cross-CDN matches',visual:'Visual similarity & crop candidates','meta-rel':'Shared embedded metadata fingerprints','variant-matrix':'Verified CDN delivery variant matrix',secrets:'Masked sensitive indicators', 'resource-scans':'Loaded-file scan coverage','js-history':'Saved JavaScript response changes and masked indicator locations','dam-history':'Saved DAM/CMS signals compared across capture groups',infra:'Host and framework intelligence',responses:'DevTools-observed JSON structures',gallery:'Observed gallery activity and cursor changes',collections:'Collection membership & duplicate ID sightings',coverage:'Observed pagination and gaps',status:'HTTP status classes and evidence confidence',maps:'Public source-map references and summaries',graphql:'Named GraphQL operations and evidence',config:'Public configuration key inventory',graph:'Browser-observed application relationships'})[view];
  $('sectionInfo').textContent = ({'asset-licensing':'Only already-received opt-in JSON is inspected in DevTools. Original-file status remains unverified without independent native-resolution proof.','generic-relationships':'Exact local lifecycles are not cross-request dependencies; page context is structural evidence and timing is only a clue.','har-coverage':'HAR and extension recordings may each omit events. Matching redacted identities does not prove completeness; no HAR body is retained.','evidence-synthesis':'No new network activity: combine reported context, captured workflow-pattern evidence and same-site DAM delivery metrics. Never proof of equal entitlements or a security flaw.','compare-readiness':'Operator-declared context and capture-quality checks for saved same-site investigations. No new requests.','policy-drift':'Same-origin numerical differences require context and sufficient sample before interpreting.','capture-repair':'Offline diagnostics built from the current acceptance and loopback benchmark results. No website probing or automatic repairs.','local-benchmark':'Compares known synthetic fixture requests against captured HTTP, DevTools and opt-in download-observer evidence.','case-compare':'Stored observation counts, vendor recognition and delivery-policy clues are compared without new requests. Capture gaps limit confidence.','case-dossier':'Selected saved capture segments only; observed facts, qualified inferences and unknown gaps stay separate.','quality-ledger':'Offline summaries of already observed files. The largest verified response is not proof of an original.', 'quality-transfers':'Download lifecycle evidence and opt-in numeric byte-range metadata; no image association implied.', 'workflow-chains':'Offline request-ID lifecycles and bounded associations. Cross-request causality cannot be proven.','workflow-coverage':'Observed, partial and unknown states are separated; missing visibility never means no activity.','aws-dam':'Only witnessed AWS service hostnames, pre-signed POST field names, and optional JSON shape hints. No policy decoding, workflow execution or asset retrieval.','download-traces':'An explicitly enabled, read-only per-capture observer. No request values, usable signatures, raw URLs, file contents or replayable downloads are saved.','frames-workers':'Same-origin iframe DOM script summaries are inspected within an approved site. Cross-origin contents and worker script bodies remain uninspected.', 'site-relations':'Offline host and role overlaps; never proof of shared DAM ownership, repository or rights.', 'discovery-pulse':'Offline comparison of saved host roles, script digests and resource scan coverage. Missing sightings never prove removals or inspection completeness.','exposure-history':'Locally keyed change classifications from saved masked findings. No credential values or tests.', 'acceptance':'Real capture-to-vault diagnostic. Missing steps are NOT passes; Windows notification visibility needs manual confirmation.', 'capture-audit':'Readiness checks based only on recorded evidence; not a complete-site or security certification.',explorer:'Compare saved asset and API evidence without requesting the original websites.',diagnostics:'Check retention caps, dropped records and outstanding verification limits.',vault:'Local sessions, group backups and integrity checking. No remote requests.', 'vault-search':'Search redacted findings from saved sessions locally.', replay:'Recorded events ordered by timestamp, loaded entirely from your local Evidence Vault.',overview:'Local-only record of the current session',platforms:'Evidence-weighted technology hints from public, locally observed data. No active platform probes.','dam-security':'Evidence-led review prompts. No endpoint probes, credential validation or automatic CVE vulnerability claims.','dam-risk':'Query-parameter classes and sharing/cache evidence observed in a normal browsing session. No values, endpoint testing, or proof of vulnerabilities.','dam-access':'A 2xx delivered-in-session response does not prove anonymous public access or master-file delivery. URL labels are weak clues only.','cdn-policy':'Response cache-control and signing clues; link revocation, origin access and policy compliance require the system owner.','integration-boundaries':'Observed request roles between hosts; correlations do not verify shared DAM backends, access policies or ownership.',lineage:'DOM card associations, observed route IDs, URL variants and exact SHA-256 matches; evidence levels remain separate.',delivery:'Observed image hosts, media formats, signed-parameter presence and transformation hints, with no generated asset URLs.',viewers:'IIIF, DZI, Zoomify and IIPImage URLs already requested, plus Canvas and SmartFrame DOM hints. No tile reconstruction.', 'viewer-manifests':'Opt-in inspection of manifest responses already received by Chrome DevTools; only technical geometry is retained.',network:'Request metadata only. No headers carrying credentials, bodies or cookies are collected.',api:'Observed calls distinguished from unverified strings in scripts.',images:'Browser-reported sizes are distinct from encoded-pixel dimensions verified from response bytes. Opt-in metadata digests identify matching blocks, not matching original images or ownership.',variants:'Only URL families observed on the page or network. Suffix matching is a grouping heuristic.',matches:'Exact SHA-256 byte identity and unverified identifier clues. No extra image downloads.',visual:'Opt-in 64-bit perceptual fingerprints suggest similar images or crops. These are low-confidence candidates, not original-file proof.', 'meta-rel':'Same embedded metadata bytes may appear in unrelated images (including boilerplate). No values stored.', 'variant-matrix':'Only observed variant families; dimensions use verified received image bytes and ratio differences do not prove cropping.',secrets:'Potential indicators redacted at source. Review classifications are local annotations only.', 'resource-scans':'Queue, skipped-file counts and loaded resource summaries; DevTools must have been open when the response completed.','dam-history':'Compare saved capture groups using the currently installed custom rules. New and missing observations do not establish ownership or technology changes. No additional website requests.', 'profile-editor':'Custom profiles are local hostname/path rules only; no scripts, credentials, hidden endpoint probes or remote signature downloads.','js-history':'Offline comparison of observed JavaScript SHA-256 digests. Missing or unscanned files cannot be verified; masked indicator matches are location-level hints, not secret-value proof.',infra:'Discovered hosts and browser-visible framework hints.',responses:'Opt-in inspection with Chrome DevTools open on the original website; field names and primitive types only.',gallery:'Page-level snapshots; no cursor values, raw search terms or private response bodies.',collections:'Public DOM-declared IDs only; repeated IDs are not proof of identical files.',coverage:'Page totals are hints; redacted URL values may group different searches together.',status:'Statuses are actual observed HTTP results; static route clues have not been requested.',maps:'Only explicitly inspected referenced public maps yield module counts. No source content is saved.',graphql:'GraphQL named operations extracted from static JavaScript or observed URL operationName values; no GraphQL introspection.',config:'Only public configuration KEY NAMES are captured; values are deliberately discarded.',graph:'Graph edges are individual supported observations or static references, not proof of backend integration.'})[view];
  $('pageTitle').textContent=names[view];
  const container=$('content');container.replaceChildren();
  if(view==='generic-intelligence'){
    $('sectionTitle').textContent='Generic behaviour evidence';
    $('sectionInfo').textContent='Observed request structures and lifecycle counts, independent of website or DAM provider.';
    renderGenericIntelligence(container);return;
  }
  if(view==='generic-relationships'){
    renderGenericRelationships(container);return;
  }
  if(view==='security-intelligence'){
    $('sectionTitle').textContent='Passive security observations and review indicators';
    $('sectionInfo').textContent='Observed configuration and flow indicators. No vulnerability exploitation or CVE confirmed.';
    renderSecurityIntelligence(container);return;
  }
  if(view==='import-preflight'){
    $('sectionTitle').textContent='Private capture file review';
    $('sectionInfo').textContent='Local-only pattern scan. No source file contents are saved or uploaded.';
    renderImportPreflight(container);return;
  }
  if(view==='product-assets'){
    $('sectionTitle').textContent='Product catalogue, variants and observed media relationships';
    $('sectionInfo').textContent='Exact reference correlation across DevTools-observed JSON and media HTTP responses.';
    renderProductAssetRelationships(container);return;
  }
  if(view==='hybrid-workflow'){
    $('sectionTitle').textContent='Generic document → API → media → browser download stages';
    $('sectionInfo').textContent='Recorded traffic categories only. No inferred backend paths or causality.';
    renderHybridWorkflow(container);return;
  }
  if(view==='asset-licensing'){
    $('sectionTitle').textContent='Observed asset licensing, selectable options and delivery evidence';
    $('sectionInfo').textContent='Generic metadata review with anonymous identifiers; no master-file or free-download assumptions.';
    renderAssetLicensing(container);return;
  }
  if(view==='universal-boundaries'){
    $('sectionTitle').textContent='Passive trust-boundary indicators';
    $('sectionInfo').textContent='Generic, offline-only review of observed signed delivery, cache, redirects and job-like outcomes.';
    renderUniversalBoundaries(container);return;
  }
  if(view==='generic-sequence'){
    $('sectionTitle').textContent='Universal response sequence and lifecycle evidence';
    $('sectionInfo').textContent='Anonymous, recorded-only transitions and exact single-request/download stage coverage. No vendor detection or active requests.';
    renderGenericSequence(container);return;
  }
  if (view==='overview') {overview(container);return;}
  if(view==='capture-repair'){renderCaptureRepair(container);return;}
  if(view==='local-benchmark'){renderLocalBenchmark(container);return;}
  if(view==='har-coverage'){renderHARCoverage(container);return;}
  if(view==='evidence-synthesis'){renderEvidenceSynthesis(container);return;}
  if(view==='workflow-pattern'){renderWorkflowPattern(container);return;}
  if(view==='compare-readiness'){renderComparisonReadiness(container);return;}
  if(view==='policy-drift'){renderPolicyDrift(container);return;}
  if(view==='case-compare'){renderCaseChange(container);return;}
  if(view==='case-dossier'){renderCaseDossier(container);return;}
  if(view==='upload-protocols'){renderUploadProtocols(container);return;}
  if(view==='api-schema-diff'){renderSchemaDiff(container);return;}
  if(view==='quality-ledger'){renderAssetQuality(container);return;}
  if(view==='quality-transfers'){renderQualityTransfers(container);return;}
  if(view==='workflow-chains'){renderWorkflowChains(container);return;}
  if(view==='workflow-coverage'){renderWorkflowCoverage(container);return;}
  if(view==='download-traces'){renderDownloadTraces(container);return;}
  if(view==='aws-dam'){renderAwsDam(container);return;}
  if(view==='frames-workers'){renderFrameWorkerEvidence(container);return;}
  if(view==='site-relations'){renderSiteRelations(container);return;}
  if (view==='explorer') {renderExplorer(container);return;}
  if (view==='diagnostics') {renderDiagnostics(container);return;}
  if (view==='acceptance') {renderAcceptance(container);return;}
  if (view==='capture-audit') {renderCaptureAudit(container);return;}
  if(view==='discovery-pulse'){renderDiscoveryPulse(container);return;}
  if(view==='exposure-history'){renderExposureHistory(container);return;}
  if (view==='vault') {renderVault(container);return;}
  if(view==='vault-search'){renderArchivedSearch(container);return;}
  if(view==='replay'){renderReplay(container);return;}
  if(view==='js-history'){renderJSHistory(container);return;}
  if(view==='profile-editor'){renderProfileEditor(container);return;}
  if(view==='dam-history'){renderDAMHistory(container);return;}
  const rows=matches(dataset());
  if (!rows.length && !['infra','graph','platforms','dam-security','dam-risk','dam-access','cdn-policy','integration-boundaries','viewers','resource-scans','secrets'].includes(view)) {empty(container,'No matching results',record ? (view==='matches'?'Enable Verify image bytes for exact matches; filename hints appear only when observed across hosts.':view==='variants'?'No two observed image URLs share a detected family yet. Browse and scroll to collect more variants.':'Browse the source website with capture running or adjust the search.'):'Begin a capture to collect data.');return;}
  if(view==='gallery'||view==='collections') {
    const analysis=THIGallery.analyze(record);
    container.appendChild(elem('p','warn-note','Coverage is observational only. Scroll/card changes can reflect virtualised lists, different filters, or unrelated page content. Raw cursor values, search queries and response bodies are never saved; source URLs have sensitive parameters redacted. Collection IDs describe DOM clues and are not verified DAM ownership.'));
    const summary=elem('div','simple-grid');
    summary.appendChild(panel('Gallery observations',String(analysis.stats.observations),`Events dropped by cap: ${analysis.stats.recordsDropped}.`));
    summary.appendChild(panel('Distinct collection IDs',String(analysis.stats.distinctCollections),`${analysis.stats.distinctAssets} unique valid asset IDs recorded.`));
    summary.appendChild(panel('Observed loading growth',String(analysis.stats.growthEvents),`Cursor changes inferred only from URL transitions (maximum step ${analysis.stats.highestCursorStep}).`));
    summary.appendChild(panel('Cross-collection IDs',String(analysis.stats.overlappingAssets),`${analysis.stats.repeatedAcrossPages} IDs observed across more than one numbered page. Membership records dropped: ${analysis.stats.membersDropped}.`));
    container.appendChild(summary);
    if(rows.length){
      if(view==='gallery')container.appendChild(buildTable([
        {key:'scope',label:'Route scope',css:'url mono'}, {key:'observations',label:'Observations'},
        {key:'observedPages',label:'Page numbers'}, {key:'cursorTransitions',label:'Cursor changes'},
        {key:'scrollBuckets',label:'Scroll progress (0–20)',css:'mono'}, {key:'highestCards',label:'Max ID cards'},
        {key:'growthEvents',label:'Growth events'}, {key:'loadingControls',label:'Paging controls'},
        {key:'assessment',label:'Coverage assessment'}],rows));
      else container.appendChild(buildTable([
        {key:'collection',label:'DOM collection ID / unknown',css:'mono'},
        {key:'distinctAssets',label:'Distinct asset IDs'}, {key:'sightings',label:'Sightings'},
        {key:'repeatedSightings',label:'Repeated sightings'}, {key:'pages',label:'Numbered pages'},
        {key:'lastObserved',label:'Last observed'}],rows));
    } else empty(container,'No gallery evidence yet','On the source website, browse gallery pages or scroll while capture is active. This feature does not navigate automatically.');
    return;
  }
  if(view==='dam-security'){renderDAMSecurity(container,rows);return;}
  if(view==='dam-review-matrix'){renderDAMReviewMatrix(container);return;}
  if(view==='dam-risk'){renderDAMRisk(container,rows);return;}
  if(view==='dam-specialists'){renderDAMSpecialists(container);return;}
  if(view==='dam-access'){renderDAMAccess(container,rows);return;}
  if(view==='cdn-policy'){renderCDNPolicy(container,rows);return;}
  if(view==='integration-boundaries'){renderIntegrationBoundaries(container,rows);return;}
  if(view==='platforms') {
    const intel=THIDAM.analyze(record);
    container.appendChild(elem('p','warn-note','Detection is heuristic: a vendor-owned CDN or embedded widget is NOT proof that the whole website runs on that DAM. Captured requests, page-declared signals and static-code mentions have different evidential strength. No undocumented endpoints are tested.'));
    const summary=elem('div','simple-grid');
    summary.appendChild(panel('Named technologies',`${intel.profiles.length} evidence-led profiles`, 'Unknown platforms may not match this curated signature database.'));
    summary.appendChild(panel('CMS ↔ DAM coexistence',`${intel.relationships.length} possible pairings`, 'Only co-observed in the current tab; integrations are not confirmed.'));
    summary.appendChild(panel('Generic DAM/gallery clues',`${intel.generic.length} patterns`, 'Generic routes and schema clues are not platform fingerprints.'));
    container.appendChild(summary);
    if(rows.length)container.appendChild(buildTable([
      {key:'name',label:'Platform'}, {key:'layer',label:'Role'},
      {key:'confidence',label:'Assessment',badge:v=>v==='Strong indication'?'success':'warn'},
      {key:'score',label:'Evidence score (0–10)'}, {key:'independentSignals',label:'Independent signal types'},
      {key:'assessment',label:'Interpretation'}, {key:'evidence',label:'Traceable evidence',css:'url mono'}],rows));
    else empty(container,'No named technology identified','Browse a normal gallery and analyse already-linked public JavaScript if you want additional static clues. An unknown provider is not a failed capture.');
    const customMatches=customRows();
    container.appendChild(elem('h2','spaced-heading',`Custom DAM profiles (${customMatches.length} matched)`));
    container.appendChild(elem('p','helper','User-created hostname and path rules are local interpretation aids. Matching observed URLs does not verify the platform, rights, or endpoint accessibility.'));
    const editBtn=elem('button','btn alt','Manage custom profiles');
    editBtn.addEventListener('click',()=>navigateView('profile-editor'));container.appendChild(editBtn);
    if(customMatches.length)container.appendChild(buildTable([
      {key:'name',label:'Profile'},{key:'layer',label:'Type'},
      {key:'matched',label:'Matching evidence sightings'},
      {key:'assessment',label:'Confidence limit'}],customMatches));
    if(intel.relationships.length) {
      container.appendChild(elem('h2','spaced-heading','Possible CMS ↔ DAM relationships'));
      container.appendChild(buildTable([{key:'from',label:'CMS'},{key:'to',label:'DAM'},{key:'relation',label:'Evidence'},{key:'confidence',label:'Confidence'}],intel.relationships));
    }
    if(intel.generic.length) {
      container.appendChild(elem('h2','spaced-heading','Unattributed gallery clues'));
      container.appendChild(buildTable([{key:'type',label:'Clue type'},{key:'detail',label:'Observed clue'},{key:'evidence',label:'Interpretation'}],intel.generic));
    }
    return;
  }
  if(view==='viewers'){
    const intel=THIViewer.summarize(record);
    container.appendChild(elem('p','warn-note','Specialist viewer URL patterns are evidence of observed requests, not permission to request a full image. DOM canvas dimensions are rendering-surface sizes, not a source-image size. No tile URLs are generated or fetched.'));
    const summary=elem('div','simple-grid');
    summary.appendChild(panel('Viewer families',String(intel.stats.families),'Families inferred from URLs actually requested by this tab.'));
    summary.appendChild(panel('Observed tile/region requests',String(intel.stats.tiles),'A tile count is not image coverage or a complete tile pyramid.'));
    summary.appendChild(panel('Manifests inspected',String(intel.stats.manifests),'Requires DevTools open and opt-in inspection.'));
    container.appendChild(summary);
    const hints=intel.hints;
    if(hints.length){container.appendChild(elem('h2','spaced-heading','Viewer and canvas evidence'));
      container.appendChild(buildTable([{key:'technology',label:'Technology'},{key:'evidence',label:'Observation'},
        {key:'count',label:'Elements'}, {key:'maxWidth',label:'Max canvas width'},
        {key:'maxHeight',label:'Max canvas height'},{key:'source',label:'Source'}],hints));}
    if(rows.length){container.appendChild(elem('h2','spaced-heading','Observed image/tile families'));
      container.appendChild(buildTable([{key:'format',label:'Protocol'}, {key:'family',label:'Observed family',css:'url mono'},
       {key:'observedRequests',label:'Requests'}, {key:'observedTiles',label:'Tiles / regions'},
       {key:'observedLevels',label:'Observed levels'}, {key:'declaredDimensions',label:'Declared image size'},
       {key:'tileSize',label:'Tile size'}, {key:'evidence',label:'Evidence'}],rows));}
    return;
  }
  if(view==='viewer-manifests'){
    container.appendChild(elem('p','warn-note','This is read-only metadata from already-received DevTools responses, not a probe or download. Declared width/height do not indicate public access to a master image. Unobserved levels and tiles are not requested.'));
    container.appendChild(buildTable([{key:'format',label:'Format'}, {key:'url',label:'Observed manifest URL',css:'url mono'},
      {key:'width',label:'Declared width'},{key:'height',label:'Declared height'},
      {key:'tileWidth',label:'Tile width'}, {key:'tileHeight',label:'Tile height'},
      {key:'levels',label:'Scale levels'}, {key:'scaleFactors',label:'IIIF scale factors'},
      {key:'itemCount',label:'Presentation items'}],rows));return;
  }
  if(view==='lineage'){
    const intel=THILineage.analyze(record);
    container.appendChild(elem('p','warn-note','An asset lineage is a correlation of observations, not proof of a master image, ownership, licensing, a common DAM backend or a reachable download. No alternative URLs are generated or requested. DOM card IDs are declarations; path IDs are unverified filename clues.'));
    const summary=elem('div','simple-grid');
    summary.appendChild(panel('Lineage groups',String(intel.stats.groups),'Derived from up to 800 observed image URLs.'));
    summary.appendChild(panel('Explicit DOM IDs',String(intel.stats.domIdGroups),'Asset/image/photo/media identifiers already present in visible gallery markup.'));
    summary.appendChild(panel('Verified byte groups',String(intel.stats.byteExactGroups),'At least two distinct observed image URLs have the same SHA-256 digest.'));
    container.appendChild(summary);
    if(rows.length)container.appendChild(buildTable([
      {key:'assetId',label:'Observed ID / clue',css:'mono'},
      {key:'confidence',label:'Evidence level',badge:v=>v==='Verified identical bytes'?'success':v==='Declared DOM association'?'warn':''},
      {key:'images',label:'Images'}, {key:'verified',label:'Verified'},
      {key:'largestObserved',label:'Largest observed',css:'mono'}, {key:'largestEvidence',label:'Dimension evidence'},
      {key:'hosts',label:'Image hosts',css:'url mono'},
      {key:'galleryPages',label:'Gallery pages',css:'url mono'},
      {key:'detailPages',label:'Visible detail links',css:'url mono'},
      {key:'observedApiRoutes',label:'Matched observed API paths',css:'url mono'},
      {key:'evidence',label:'Evidence trace'},
      {key:'imageUrls',label:'Observed images',css:'url mono'}],rows));
    return;
  }
  if(view==='visual'||view==='meta-rel'||view==='variant-matrix'){
    container.appendChild(elem('p','warn-note',view==='visual'?'Perceptual matches and possible crops are heuristics requiring manual confirmation. No source images or original files are retrieved.':view==='meta-rel'?'Identical metadata-block hashes do not prove an image match, author, rights, or common origin.':'Only received image variants are compared. Different aspect ratios are clues, not proof of cropping.'));
    const keys=view==='visual'?['kind','distance','confidence','left','right','details']:view==='meta-rel'?['kind','fingerprint','images','urls','assessment']:['family','observed','verified','visual','formats','resolutionRange','aspectRatios','cropClue','urls'];
    container.appendChild(buildTable(keys.map(key=>({key,label:key.replace(/([A-Z])/g,' $1'),css:key==='urls'||key==='left'||key==='right'?'url mono':''})),rows));return;
  }
  if(view==='delivery'){
    container.appendChild(elem('p','warn-note','This is a passive inventory, not a CDN endpoint probe. Named /original/ or /master/ paths are URL labels only, not evidence of an obtainable master file. Signed URL values are never retained.'));
    container.appendChild(buildTable([
      {key:'host',label:'Image delivery host',css:'url mono'}, {key:'observedImages',label:'URLs'},
      {key:'verifiedResponses',label:'SHA-256 verified'},
      {key:'largestVerified',label:'Largest verified image'}, {key:'imageTypes',label:'MIME types'},
      {key:'transformationKeys',label:'Observed size/format query keys'},
      {key:'pathHints',label:'Path labels'}, {key:'signedRequests',label:'Signed URL flags'},
      {key:'assessment',label:'Evidence'}],rows));return;
  }
  if(view==='graph') {THIGraph.render(container,record);return;}
  if(view==='maps') {
    container.appendChild(elem('p','warn-note','Source-map references are not proof that a map is accessible. Inspect referenced maps makes up to eight explicit, credential-free GET requests to same-script-origin public .map URLs. Embedded source text is never retained.'));
    container.appendChild(buildTable([{key:'status',label:'Evidence',badge:v=>v==='inspected-public-map'?'success':'warn'},
      {key:'url',label:'Public map URL',css:'url mono'}, {key:'script',label:'Source script',css:'url mono'},
      {key:'sourceCount',label:'Modules'}, {key:'sourceTypes',label:'Source types'},
      {key:'packageNames',label:'Package names'}, {key:'hasEmbeddedSources',label:'Embedded source content?'}],rows));
  }
  if(view==='graphql') {
    container.appendChild(elem('p','helper','No GraphQL introspection or POST request bodies. Named operations from analysed JS are static clues; operationName observed in network URLs is stronger evidence but does not verify GraphQL execution.'));
    container.appendChild(buildTable([{key:'operationType',label:'Type'}, {key:'name',label:'Operation'}, {key:'confidence',label:'Evidence',badge:v=>v.startsWith('observed')?'success':'warn'}, {key:'source',label:'Observed in',css:'url mono'}],rows));
  }
  if(view==='config') {
    container.appendChild(elem('p','helper','Browser-visible PUBLIC-prefixed configuration key names only. Values, credentials and private settings are not saved.'));
    container.appendChild(buildTable([{key:'framework',label:'Framework hint'}, {key:'key',label:'Public field name',css:'mono'}, {key:'source',label:'Found in',css:'url mono'}, {key:'value',label:'Value'}],rows));
  }
  if (view==='network') container.appendChild(buildTable([
    {key:'at',label:'Time',format:v=>(v||'').slice(11,19)}, {key:'method',label:'Method',badge:r=>r==='GET'?'success':'',format:r=>r},
    {key:'status',label:'Status',badge:r=>r>=400?'danger':r>=200&&r<400?'success':'',format:(r,x)=>r||x.error||'—'},
    {key:'type',label:'Type'}, {key:'url',label:'Request URL',css:'url mono'}, {key:'initiatorOrigin',label:'Initiator origin',css:'url mono'}, {key:'mime',label:'MIME'},
    {key:'bytes',label:'Bytes',format:n=>n?fmt(n):'—'}],rows));
  if (view==='api') {
    container.appendChild(elem('p','helper','Observed requests are actual activity in your browser. “Static clue” means a route was mentioned in inline or explicitly analysed JavaScript; it has not been tested.'));
    container.appendChild(buildTable([
      {key:'kind',label:'Evidence',format:v=>v==='observed-request'?'Observed request':'Static clue',badge:r=>r==='observed-request'?'success':'warn'},
      {key:'method',label:'Method'}, {key:'status',label:'Status'}, {key:'url',label:'Endpoint / route',css:'url mono'},
      {key:'host',label:'Host'}, {key:'source',label:'Source'}],rows));
  }
  if (view==='responses') {
    container.appendChild(elem('p','helper','Inspect JSON field paths and types seen via Chrome DevTools on the original tab. Enable the toggle above, keep DevTools open, then browse or reload. This records no raw response bodies or field values.'));
    container.appendChild(buildTable([
      {key:'at',label:'Time',format:v=>(v||'').slice(11,19)}, {key:'method',label:'Method'}, {key:'status',label:'HTTP'},
      {key:'url',label:'Response URL',css:'url mono'}, {key:'fieldCount',label:'Fields'},
      {key:'fields',label:'Observed field paths:types',css:'url mono'}, {key:'pagination',label:'Pagination counters'}], rows));
  }
  if (view==='coverage') {
    container.appendChild(elem('p','warn-note','This view detects gaps in observed page numbers; it cannot certify that every search result was captured. Searches with different filters may share a redacted URL scope. A total count is only a clue, not evidence of downloaded items.'));
    container.appendChild(buildTable([
      {key:'scope',label:'Route scope',css:'url mono'}, {key:'source',label:'Source'},
      {key:'pagesSeen',label:'Observed pages',css:'url mono'}, {key:'knownTotal',label:'Total pages hint'},
      {key:'missing',label:'Missing page numbers',css:'url mono'}, {key:'totalResults',label:'Results hint'}, {key:'assessment',label:'Assessment'}],rows));
  }
  if (view==='status') {
    const hints=record?.routes||[];
    const observed=hints.filter(x=>x.observed).length, referenced=hints.filter(x=>!x.observed).length;
    const panels=elem('div','simple-grid');
    panels.appendChild(panel('Observed API route evidence',`${observed} unique URL/method combinations`, 'These requests were seen on the network; a 401/403 is not an accessible endpoint.'));
    panels.appendChild(panel('Unverified JavaScript references',`${referenced} static code clues`, 'Not automatically probed or tested.'));
    panels.appendChild(panel('Response shape evidence',`${record?.responses?.length||0} DevTools-observed JSON shapes`, 'Structure metadata only, not content or authentication success.'));
    container.appendChild(panels);container.appendChild(elem('h2','spaced-heading','HTTP outcomes'));
    container.appendChild(buildTable([{key:'category',label:'Class'}, {key:'count',label:'Requests'},
      {key:'example',label:'Example URL',css:'url mono'}, {key:'assessment',label:'Meaning'}],rows));
  }
  if (view==='images') {
    container.appendChild(elem('p','helper','Encoded pixels and SHA-256 are calculated from already-received DevTools image response bytes only when Verify image bytes is enabled. Browser size can be density-adjusted. Dimensions are not inferred from URL names.'));
    container.appendChild(buildTable([
      {key:'url',label:'Observed / declared URL',css:'url mono'},
      {key:'encodedWidth',label:'Encoded pixels',format:(_v,r)=>r.encodedWidth&&r.encodedHeight?`${fmt(r.encodedWidth)} × ${fmt(r.encodedHeight)}`:'—'},
      {key:'width',label:'Browser size',format:(_v,r)=>r.width&&r.height?`${fmt(r.width)} × ${fmt(r.height)}`:'—'},
      {key:'evidence',label:'Evidence',badge:v=>v.startsWith('Verified')||v.startsWith('SHA-256')?'success':'warn'},
      {key:'sha256',label:'SHA-256',css:'mono',format:v=>v?v.slice(0,16)+'…':'—'},
      {key:'encodedBytes',label:'Verified bytes',format:n=>n?fmt(n):'—'},
      {key:'metadata',label:'Metadata fingerprints',css:'mono'},
      {key:'source',label:'Seen in'}, {key:'mime',label:'MIME'},
      {key:'signedQuery',label:'Signed params?',format:n=>n?'Yes':'No'}],rows));
  }
  if (view==='variants') {
    container.appendChild(elem('p','warn-note','These families are inferred from observed file-path suffixes and URL size parameters. No alternative asset URLs are generated or requested. “Largest” considers only observed evidence; it does not mean maximum resolution on the server.'));
    container.appendChild(buildTable([
      {key:'family',label:'Host + file family',css:'url mono'},
      {key:'variantCount',label:'URLs'}, {key:'verifiedCount',label:'Verified'},
      {key:'largest',label:'Largest observed'},
      {key:'largestEvidence',label:'Pixel confidence',badge:v=>v.startsWith('Verified')?'success':'warn'},
      {key:'largestUrl',label:'Largest observed URL',css:'url mono'}, {key:'urls',label:'Family URLs',css:'url mono',format:v=>v.join(' · ')}],rows));
  }
  if (view==='matches') {
    container.appendChild(elem('p','warn-note','Byte-identical means two observed response bodies produced the same SHA-256. This is strong evidence of identical bytes, not evidence of ownership or licensing. Shared filename IDs are UNVERIFIED hints only; a re-encoded copy will have a different hash.'));
    container.appendChild(buildTable([
      {key:'kind',label:'Match class',badge:v=>v==='Byte-identical'?'success':'warn'},
      {key:'identity',label:'Fingerprint / ID',css:'mono'},
      {key:'hosts',label:'Hostnames',css:'url mono'},
      {key:'count',label:'URLs'}, {key:'confidence',label:'Evidence'},
      {key:'urls',label:'Observed URLs',css:'url mono',format:v=>v.join(' · ')}],rows));
  }
  if (view==='secrets') {
    container.appendChild(elem('p','warn-note','Indicators are NOT proof of exposed or usable credentials. Values stay masked. Review notes never validate or contact providers.'));
    if(!archivedId && rows.length){
      const review=elem('div','review-list');
      for(const finding of rows.slice(0,75)){
        if(!finding._key)continue;
        const line=elem('div','review-line');
        const desc=elem('span','mono',`${finding.type}: ${finding.masked} · ${finding.source}`);line.appendChild(desc);
        const select=elem('select');select.setAttribute('aria-label',`Review ${finding.type}`);
        for(const [value,label] of [['new','New'],['reviewing','Reviewing'],['false-positive','False positive'],['resolved','Resolved']]){
          const option=elem('option','',label);option.value=value;select.appendChild(option);
        }
        select.value=finding.reviewStatus||'new';
        select.disabled=!recording?.enabled;
        select.addEventListener('change',async()=>{
          const result=await chrome.runtime.sendMessage({type:'SET_FINDING_REVIEW',tabId,findingKey:finding._key,status:select.value});
          if(!result?.ok)notice('Could not save review state.',true);else await refresh();
        });
        line.appendChild(select);review.appendChild(line);
      }
      container.appendChild(review);
    }
    container.appendChild(buildTable([
      {key:'type',label:'Type'}, {key:'masked',label:'Redacted match',css:'url mono'},
      {key:'severity',label:'Classification'}, {key:'reviewStatus',label:'Review state'}, {key:'source',label:'Found in',css:'url mono'},
      {key:'line',label:'Line'}, {key:'column',label:'Column'}, {key:'changeState',label:'Value evidence',format:v=>v==='changed'?'Changed (keyed match)':v==='unchanged'?'Unchanged (keyed match)':v==='new'?'New location':'Unverified'}, {key:'reviewHistory',label:'Review history',format:v=>Array.isArray(v)?v.map(e=>e.from+' → '+e.to+' ('+e.at+')').join('; '):'—'}, {key:'knownPrevious',label:'Observed before',format:v=>v===true?'Location repeated':'New location'}, {key:'note',label:'Assessment note'}],rows));
  }
  if(view==='resource-scans'){
    container.appendChild(elem('p','helper','Queued inspections apply to already-delivered JavaScript, HTML, CSS, JSON and XML responses. No extra GETs are sent. Chrome DevTools must be open first; its historical gaps cannot be counted. Raw content and full credentials are never retained.'));
    const h=typeof THIHealth!=='undefined'?THIHealth.assess(record,recording):null;
    if(h){
      const title=elem('h3','',`Inspection status: ${h.title}`);
      container.appendChild(title);
      container.appendChild(elem('p',h.code==='observed-complete'?'helper':'warn-note',h.detail));
      if(h.heartbeatAt)container.appendChild(elem('p','helper',`Last DevTools heartbeat: ${h.heartbeatAt} (${h.heartbeatAgeSeconds}s ago).`));
      container.appendChild(elem('p','helper','Scope: observed, eligible response files only. Files loaded before DevTools opened cannot be counted.'));
    }
    const c=record?.autoScanCoverage;
    if(c){
      const summary=elem('div','simple-grid');
      for(const [label,note,value] of [
        ['Eligible responses','Recognised during this DevTools session',c.eligible],
        ['Inspected','Successful redacted scans',c.scanned],
        ['Queued / active','Waiting plus in flight',(c.queued||0)+(c.running||0)],
        ['Oversized','Beyond 2 MiB inspection limit',c.oversized],
        ['Unavailable','Chrome response missing, timed out or unsupported',(c.unavailable||0)+(c.timeout||0)+(c.unsupported||0)],
        ['Unverified / errors','Not observed by recorder, capacity drops and delivery failures',(c.unrecorded||0)+(c.capacity||0)+(c.deliveryError||0)+(c.failed||0)]
      ])summary.appendChild(panel(label,String(value||0),note));
      container.appendChild(summary);
      container.appendChild(elem('p','warn-note',`Only ${c.scanned||0} of ${c.eligible||0} eligible resource sightings were confirmed inspected. Duplicate sightings: ${c.duplicates||0}. Counts describe this DevTools session, not the entire website. Active captures may still have queued files.`));
    }else container.appendChild(elem('p','warn-note','No scanner coverage report yet. Start capture, open DevTools on the source tab and reload. Earlier captures may not contain these counters.'));
    if(rows.length)container.appendChild(buildTable([{key:'at',label:'Seen at'},{key:'url',label:'File',css:'url mono'},
      {key:'kind',label:'Type'},{key:'byteCount',label:'Inspected chars'},{key:'indicatorCount',label:'Indicators'},
      {key:'sha256',label:'Observed SHA-256',css:'mono',format:v=>v?String(v).slice(0,18)+'…':'Not verified'}],rows));
  }
  if(view==='search-intel'){
    container.appendChild(elem('p','helper','Search providers are heuristic; a request near a click is a timing correlation, not proven causation. Search terms and input values are never stored.'));
    container.appendChild(buildTable([{key:'at',label:'Time'},{key:'category',label:'Source'},
      {key:'kind',label:'Kind'},{key:'provider',label:'Provider clue'},{key:'nearInteraction',label:'Near interaction'},
      {key:'url',label:'Observed route',css:'url mono'}],rows));
  }
  if (view==='infra') {
    const clues=record?.clues||[];
    const group=elem('div','simple-grid');
    group.appendChild(panel('Hosts observed',`${rows.length} hosts represented in this view.`, 'Counts are sightings, not proof of shared storage or ownership.'));
    group.appendChild(panel('Public framework signatures',clues.length?clues.map(c=>c.label).filter((v,i,a)=>a.indexOf(v)===i).join(' · '):'None detected yet.','Framework signatures are heuristic.'));
    group.appendChild(panel('Already-linked scripts',`${record?.scripts?.length||0} discovered script URLs`,`${record?.scannedScripts?.length||0} explicitly analysed`));
    container.appendChild(group);
    container.appendChild(elem('h2','', 'Observed host catalogue'));
    container.appendChild(buildTable([
      {key:'host',label:'Hostname',css:'url mono'}, {key:'category',label:'Service hint'},
      {key:'requests',label:'Requests'},{key:'assets',label:'Assets'}, {key:'scripts',label:'Scripts'}, {key:'routes',label:'API references'}], rows));
  }
}
function cards() {
  const data=[['Gallery IDs',THIGallery.analyze(record).stats.distinctAssets,'DOM asset IDs in this capture'],['Lineage groups',THILineage.analyze(record).stats.groups,'observed asset correlations'],['Platforms hinted',THIDAM.analyze(record).profiles.length,'recognition is heuristic'],['Observed requests',record?.requests?.length||0,'latest request records'],
    ['API references',record?.routes?.length||0,'observed or static'],
    ['Observed images',imageRows().length,'unique URLs'],
    ['Viewer families',THIViewer.summarize(record).stats.families,'observed IIIF/DZI/Zoomify patterns'],
    ['Verified images',record?.verifications?.length||0,'opt-in SHA-256 fingerprints']];
  $('cards').replaceChildren(...data.map(([label,val,subtitle])=>{
    const div=elem('div','metric');div.appendChild(elem('div','label',label));div.appendChild(elem('div','value',fmt(val)));
    div.appendChild(elem('div','subtitle',subtitle));return div;
  }));
}
async function refresh() {
  if (!Number.isInteger(tabId) || tabId < 0) {notice('Open this dashboard from the extension popup.',true);return;}
  if (busy) return;
  try {
    const state=await send('GET_STATE');
    if (!state?.ok) throw new Error(state?.error||'No state returned');
    record=state.record;recording=state.recording;
    if(archivedId){
      const old=await chrome.runtime.sendMessage({type:'GET_SAVED_SESSION',tabId,sessionId:archivedId});
      if(!old?.ok){archivedId=null;notice('Saved session is no longer available.',true);}else {record=old.record;recording=null;}
    }
    if(['har-coverage','evidence-synthesis','workflow-pattern','compare-readiness','policy-drift','case-compare','case-dossier','api-schema-diff','vault','explorer','site-relations','vault-search','replay','js-history','dam-history','capture-audit','discovery-pulse'].includes(view)&&Date.now()-lastVaultRefresh>8500){
      const saved=await chrome.runtime.sendMessage({type:'LIST_SESSIONS',tabId});
      if(!saved?.ok)throw new Error(saved?.error||'Evidence Vault unavailable');
      sessionsCache=saved.sessions||[];lastVaultRefresh=Date.now();
    }
    if(view==='discovery-pulse'){const p=await chrome.runtime.sendMessage({type:'GET_DISCOVERY_ALERTS',tabId});discoveryAlertsEnabled=!!p?.enabled;}
    if(view==='exposure-history'){const [history,pref]=await Promise.all([chrome.runtime.sendMessage({type:'GET_EXPOSURE_HISTORY',tabId}),chrome.runtime.sendMessage({type:'GET_SECRET_CHANGE_NOTIFICATIONS',tabId})]);exposureHistoryResult=history?.history||null;changeNotificationsEnabled=pref?.enabled!==false;}
    if(['acceptance','capture-repair'].includes(view) && !archivedId){const result=await chrome.runtime.sendMessage({type:'GET_ACCEPTANCE_REPORT',tabId});acceptanceReport=result?.ok?result.report:null;}
    if(view==='diagnostics'){
      if(archivedId)diagnosticData=THICross.diagnostics(record,null,null);
      else{const info=await chrome.runtime.sendMessage({type:'GET_CAPTURE_DIAGNOSTICS',tabId});diagnosticData=info?.ok?info.diagnostics:THICross.diagnostics(record,recording,null);}
    }
    const active=!!recording?.enabled;
    $('origin').textContent=record?.origin ? record.origin+(archivedId?' · Archived investigation':''):'No saved investigation for this tab';
    $('liveBack').hidden=!archivedId;
    $('start').hidden=active;$('stop').hidden=!active;
    $('start').disabled=!!archivedId; $('stop').disabled=!!archivedId; $('clear').disabled=!!archivedId;
    $('scan').disabled=!active;$('scripts').disabled=!active;$('maps').disabled=!active;
    $('downloadToggle').disabled=!active;
    $('downloadToggle').textContent=recording?.downloadObserver?'Disable download observer':'Enable download observer';
    $('downloadToggle').classList.toggle('active',!!recording?.downloadObserver);
    $('responseToggle').disabled=!active; $('imageToggle').disabled=!active; $('metadataToggle').disabled=!active; $('visualToggle').disabled=!active; $('viewerToggle').disabled=!active;
    const viewersActive=!!recording?.viewerManifests;
    $('viewerToggle').textContent=viewersActive?'Disable viewer manifests':'Inspect viewer manifests';
    $('viewerToggle').classList.toggle('response-live',viewersActive);
    const inspecting=!!recording?.responseShapes;
    $('responseToggle').textContent=inspecting?'Disable JSON shapes':'Enable JSON shapes';
    $('responseToggle').classList.toggle('response-live',inspecting);
    const visualActive=!!recording?.verifyVisual;
    $('visualToggle').textContent=visualActive?'Disable visual fingerprints':'Enable visual fingerprints';
    $('visualToggle').classList.toggle('active',visualActive);
    const metadataActive=!!recording?.verifyMetadata;
    $('metadataToggle').textContent=metadataActive?'Disable metadata fingerprints':'Fingerprint image metadata';
    $('metadataToggle').classList.toggle('active',metadataActive);
    const imagesActive=!!recording?.verifyImages;
    $('imageToggle').textContent=imagesActive?'Disable image verification':'Verify image bytes';
    $('imageToggle').classList.toggle('response-live',imagesActive);
    $('statusPill').classList.toggle('live',active);
    $('statusPill').textContent=archivedId?'● Saved evidence':active?'● Recording this site':'● Capture stopped';
    $('ack').hidden=!!archivedId||!(record?.unreviewedAlerts>0);
    $('ack').textContent=`Mark ${record?.unreviewedAlerts||0} alert(s) reviewed`;
    cards();drawView();
  } catch(e){notice(e.message,true);}
}
async function run(type,button,done) {
  if(busy)return;busy=true;
  button.disabled=true;notice('Processing…');
  try {
    const result=await send(type);
    if(!result?.ok)throw new Error(result?.error||'Action could not be completed');
    notice(done ? done(result) : 'Action completed');
  } catch(e){notice(e.message,true);}
  finally {busy=false;button.disabled=false;await refresh();}
}
const WORKSPACES=[
 {id:'overview',label:'Overview',symbol:'◫'},
 {id:'security',label:'Security',symbol:'⚑'},
 {id:'network',label:'Network & APIs',symbol:'⇄'},
 {id:'images',label:'Images & DAM',symbol:'▧'},
 {id:'gallery',label:'Gallery research',symbol:'▦'},
 {id:'vault',label:'Evidence Vault',symbol:'▣'}
];
function switchWorkspace(id,{persist=true}={}){
 if(!WORKSPACES.some(w=>w.id===id))id='overview';
 activeWorkspace=id;
 for(const btn of document.querySelectorAll('.workspace-tab')){
   const selected=btn.dataset.workspace===id;btn.classList.toggle('active',selected);btn.setAttribute('aria-pressed',String(selected));
 }
 for(const btn of document.querySelectorAll('.nav-item'))btn.classList.toggle('workspace-visible',btn.dataset.workspace===id);
 const item=WORKSPACES.find(w=>w.id===id);$('moduleHeading').textContent=item.label.toUpperCase()+' MODULES';
 if(persist){chrome.storage.local.set({thiWorkspaceV4:id}).catch(()=>{});}
}
function navigateView(next){
 const btn=[...document.querySelectorAll('.nav-item')].find(x=>x.dataset.view===next);
 if(!btn)return;
 switchWorkspace(btn.dataset.workspace);document.querySelector('.nav-item.selected')?.classList.remove('selected');
 btn.classList.add('selected');view=next;$('search').value='';
 if(['har-coverage','evidence-synthesis','workflow-pattern','compare-readiness','policy-drift','case-compare','case-dossier','vault','explorer','vault-search','replay','js-history','dam-history','capture-audit','discovery-pulse'].includes(view))lastVaultRefresh=0;
 void refresh();
}
for(const w of WORKSPACES){
 const btn=elem('button','workspace-tab');btn.type='button';btn.dataset.workspace=w.id;
 btn.appendChild(elem('span','workspace-symbol',w.symbol));btn.appendChild(elem('span','',w.label));
 btn.addEventListener('click',()=>{
  switchWorkspace(w.id);const first=document.querySelector(`.nav-item[data-workspace="${w.id}"].selected`)||document.querySelector(`.nav-item[data-workspace="${w.id}"]`);
  if(first)navigateView(first.dataset.view);
 });$('workspaceSwitch').appendChild(btn);
}
for (const item of document.querySelectorAll('.nav-item'))item.addEventListener('click',()=>navigateView(item.dataset.view));
switchWorkspace('overview',{persist:false});
$('search').addEventListener('input',drawView);
$('liveBack').addEventListener('click',()=>{archivedId=null;comparison=null;void refresh();});
$('offlineInspector').addEventListener('click',()=>{void chrome.tabs.create({url:chrome.runtime.getURL('offline.html')});});
$('start').addEventListener('click',()=>run('START_CAPTURE',$('start'),()=> 'Capture started. Browse the original website and return here to review.'));
$('stop').addEventListener('click',()=>run('STOP_CAPTURE',$('stop'),r=> r.archiveWarning ? 'Capture stopped, but archive failed. Export the live record: '+r.archiveWarning : 'Capture stopped and saved in Evidence Vault.'));
$('ack').addEventListener('click',()=>run('MARK_ALERTS_REVIEWED',$('ack'),()=> 'Sensitive findings remain stored; the alert badge has been cleared.'));
$('scan').addEventListener('click',()=>run('SCAN_NOW',$('scan'),()=> 'Page inventory requested.'));
$('scripts').addEventListener('click',()=>run('ANALYZE_SCRIPTS',$('scripts'),r=>`Public script analysis: ${r.checked} scanned, ${r.skipped} skipped. No credentials sent.`));
$('maps').addEventListener('click',()=>run('INSPECT_MAPS',$('maps'),r=>`Public map inspection: ${r.inspected} summarised, ${r.skipped} skipped. No map source content saved.`));
$('downloadToggle').addEventListener('click',async()=>{
 if(busy)return;busy=true;
 const btn=$('downloadToggle');btn.disabled=true;
 try{
   const enabled=!recording?.downloadObserver;
   const res=await chrome.runtime.sendMessage({type:'TOGGLE_DOWNLOAD_OBSERVER',tabId,enabled});
   if(!res?.ok)throw new Error(res?.error||'Could not toggle download observer');
   notice(enabled?'Download observation enabled for this capture. Use a download you are authorised to perform; no request values are saved.':'Download observation disabled. Existing sanitized evidence remains locally saved.');
 }catch(e){notice(e.message,true);}finally{busy=false;btn.disabled=false;await refresh();}
});
$('responseToggle').addEventListener('click',async()=>{
  if (busy) return;
  busy=true;const btn=$('responseToggle');btn.disabled=true;
  const enabled=!recording?.responseShapes;
  try {
    const result=await chrome.runtime.sendMessage({type:'TOGGLE_RESPONSE_SHAPES',tabId,enabled});
    if (!result?.ok) throw new Error(result?.error||'Toggle failed');
    notice(enabled?'JSON structure and bounded licensing inspection enabled. Open DevTools on the source tab, then reload or browse normally.':'JSON structure inspection disabled. Previously observed shapes remain in the local record.');
  }catch(e){notice(e.message,true);}finally{busy=false;btn.disabled=false;await refresh();}
});
$('viewerToggle').addEventListener('click',async()=>{
  if(busy)return;busy=true;const btn=$('viewerToggle');btn.disabled=true;
  const enabled=!recording?.viewerManifests;
  try{const result=await chrome.runtime.sendMessage({type:'TOGGLE_VIEWER_MANIFESTS',tabId,enabled});
    if(!result?.ok)throw new Error(result?.error||'Viewer toggle failed');
    notice(enabled?'Viewer manifest inspection enabled. Open DevTools on the source tab and browse normally. No extra image or manifest requests will be sent.':'Viewer manifest inspection disabled. Captured metadata remains.');
  }catch(e){notice(e.message,true);}finally{busy=false;btn.disabled=false;await refresh();}
});
$('visualToggle').addEventListener('click',async()=>{
  if(busy)return;busy=true;const btn=$('visualToggle');btn.disabled=true;
  const enabled=!recording?.verifyVisual;
  try{const res=await chrome.runtime.sendMessage({type:'TOGGLE_VISUAL_VERIFICATION',tabId,enabled});
    if(!res?.ok)throw Error(res?.error||'Visual consent failed');
    notice(enabled?'Visual fingerprints enabled with byte verification. Open DevTools before reloading the original tab. Only compact hashes are saved.':'Visual fingerprinting disabled. Earlier findings remain in the Evidence Vault.');
  }catch(e){notice(e.message,true);}finally{busy=false;btn.disabled=false;await refresh();}
});
$('metadataToggle').addEventListener('click',async()=>{
  if(busy)return;busy=true;const btn=$('metadataToggle');btn.disabled=true;
  const enabled=!recording?.verifyMetadata;
  try{const result=await chrome.runtime.sendMessage({type:'TOGGLE_METADATA_VERIFICATION',tabId,enabled});
    if(!result?.ok)throw new Error(result?.error||'Metadata consent failed');
    notice(enabled?'Image metadata fingerprinting enabled, along with image-byte verification. Open DevTools on the source page before reloading. Only SHA-256 hashes of metadata blocks are saved.':'Metadata fingerprinting disabled. Existing fingerprints remain stored in evidence.');
  }catch(e){notice(e.message,true);}finally{busy=false;btn.disabled=false;await refresh();}
});
$('imageToggle').addEventListener('click',async()=>{
  if(busy)return;
  busy=true;const btn=$('imageToggle');btn.disabled=true;
  const enabled=!recording?.verifyImages;
  try {
    const result=await chrome.runtime.sendMessage({type:'TOGGLE_IMAGE_VERIFICATION',tabId,enabled});
    if(!result?.ok)throw new Error(result?.error||'Toggle failed');
    notice(enabled?'Image verification enabled. Keep DevTools open on the source tab and reload or browse to collect image response bytes already received.':'Image verification disabled. Verified metadata remains in the local record.');
  }catch(e){notice(e.message,true);}finally{busy=false;btn.disabled=false;await refresh();}
});
$('clear').addEventListener('click',()=>{
  if(recording?.enabled) {notice('Stop the capture before clearing its data.',true);return;}
  if (!confirm('Delete this tab\'s locally saved capture?'))return;
  void run('CLEAR_RECORD',$('clear'),()=> 'Locally stored capture cleared.');
});
$('json').addEventListener('click',()=>{
  if(!record){notice('No data to export.',true);return;}
  download(fileName()+'.json',JSON.stringify({...stripInternal(record),platformAnalysis:THIDAM.analyze(record),damSpecialists:THIDAMSpecialists.report(record),customPlatformMatches:THICustomProfiles.inspect(customProfiles,record),damSecurityAnalysis:THIDAMSecurity.analyze(record,THIDAM.analyze(record)),damRiskAnalysis:THIDAMRisk.analyze(record,THIDAM.analyze(record)),captureAudit:THICaptureAudit.assess(record,recording,sessionsCache),lineageAnalysis:THILineage.analyze(record),deliveryAnalysis:THILineage.pipeline(record),viewerAnalysis:THIViewer.summarize(record),galleryAnalysis:THIGallery.analyze(record),investigationProfile:THIGallery.profile($('profile').value).id},null,2),'application/json');notice('Full session and platform analysis JSON exported.');
});
$('csv').addEventListener('click',()=>{
  if(!record&&view!=='vault'){notice('No data to export.',true);return;}
  download(fileName()+'-'+view+'.csv','\uFEFF'+currentCSV(),'text/csv;charset=utf-8');notice(`CSV exported for ${names[view]}.`);
});
async function applyProfile(id,persist=true){
 const choice=THIGallery.profile(id);
 $('profile').value=choice.id;
 $('recipeDescription').textContent=choice.description+' — View focus only; permissions unchanged.';
 const nav=document.querySelector(`[data-view="${choice.start}"]`);
 if(nav){nav.click();}
 if(persist){try{await chrome.storage.local.set({preferredProfile:choice.id});}catch(e){notice('Could not save recipe: '+e.message,true);}}
}
$('profile').addEventListener('change',()=>{void applyProfile($('profile').value);});
const initialView=new URL(location.href).searchParams.get('view');
(async()=>{
 try{
  const pref=await chrome.storage.local.get(['preferredProfile',THICustomProfiles.STORAGE_KEY,'thiWorkspaceV4']);
  try{customProfiles=THICustomProfiles.validateAll(pref[THICustomProfiles.STORAGE_KEY]||[]);}
  catch(e){customProfiles=[];notice('Stored custom profiles could not be used: '+e.message,true);}
  const recipe=THIGallery.profile(pref.preferredProfile||'generic');
  $('profile').value=recipe.id;
  $('recipeDescription').textContent=recipe.description+' — View focus only; permissions unchanged.';
  const group=pref.thiWorkspaceV4||'overview';
  const defaultView={overview:'overview',security:'secrets',network:'network',images:'platforms',gallery:'gallery',vault:'vault'};
  navigateView(initialView&&names[initialView]?initialView:defaultView[group]||'overview');
 }catch(e){navigateView(initialView&&names[initialView]?initialView:'overview');notice('Preferences could not be loaded: '+e.message,true);}
})();
setInterval(()=>{if(document.visibilityState==='visible')void refresh();},2500);
