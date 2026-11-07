/* Trufflehog v2.7 — Passive gallery coverage evidence and local analysis.
   Never stores raw search terms, cursor values, response bodies or cookies.
   A count/asset sighting is not proof that all gallery results were retrieved. */
(function(root){
 'use strict';
 const cursorName=/^(?:cursor|after|before|endcursor|startcursor|pagecursor|nextcursor|starting_after|continuation|continuationtoken)$/i;
 const profiles=Object.freeze([
  {id:'generic',name:'Universal Research',start:'generic-intelligence',description:'Analyse unknown or custom systems by observed behaviour; platform recognition is optional.'},
  {id:'dam',name:'DAM / Capture',start:'platforms',description:'Recognise CMS/DAM integrations, gallery records and source relationships.'},
  {id:'cdn',name:'CDN & Image Delivery',start:'delivery',description:'Compare observed delivery hosts, image variants and byte-level evidence.'},
  {id:'gallery',name:'Gallery Coverage',start:'gallery',description:'Review cursor steps, scrolling growth, collection IDs and observed gaps.'},
  {id:'archive',name:'Cross-Archive Comparison',start:'matches',description:'Review cross-host relationships; exports remain per-site sessions.'}
 ]);
 function profile(id){return profiles.find(x=>x.id===id)||profiles.find(x=>x.id==='gallery');}
 function safeId(v){
  if(typeof v!=='string')return '';
  const s=v.trim();
  if(s.length<5||s.length>44||!/^[a-z0-9][a-z0-9_.-]*$/i.test(s)||!/[0-9]/.test(s)||/^(?:sk_|rk_|ghp_|gho_|xox|eyj|akia|asia|aiza|token|secret|apikey|clientsecret)/i.test(s)||/^[a-f\d]{32,}$/i.test(s))return '';
  return s.toLowerCase();
 }
 function safePage(n){return Number.isSafeInteger(n)&&n>0&&n<=1000000?n:null;}
 function safeCount(n){return Number.isSafeInteger(n)&&n>=0&&n<=1000000?n:null;}
 function inspect(raw){
  if(!raw||typeof raw!=='object')return null;
  let u;try{u=new URL(raw.url);if(!/^https?:$/.test(u.protocol))return null;}catch{return null;}
  const ids=[...new Set((Array.isArray(raw.assetIds)?raw.assetIds:[]).slice(0,250).map(safeId).filter(Boolean))].slice(0,160);
  const collections=[...new Set((Array.isArray(raw.collectionIds)?raw.collectionIds:[]).slice(0,15).map(safeId).filter(Boolean))].slice(0,8);
  const cursorNames=[...new Set([...u.searchParams.keys(),...(Array.isArray(raw.cursorNames)?raw.cursorNames.slice(0,8):[])].filter(k=>typeof k==='string'&&cursorName.test(k)).map(x=>x.toLowerCase()))].slice(0,8);
  const step=Number.isSafeInteger(raw.cursorStep)&&raw.cursorStep>=0&&raw.cursorStep<=100000?raw.cursorStep:null;
  const total=safeCount(raw.galleryCards),images=safeCount(raw.imageCount),scrollBucket=safeCount(raw.scrollBucket);
  const page=safePage(raw.page);
  // We only accept coarse browser scroll buckets (0..20), not scroll positions or page content.
  if(total===null||images===null||scrollBucket===null||scrollBucket>20)return null;
  const next=raw.nextControl===true,loadMore=raw.loadMore===true;
  return {assetIds:ids,collectionIds:collections,page,galleryCards:total,imageCount:images,
    scrollBucket,atBottom:raw.atBottom===true,cursorNames,cursorStep:cursorNames.length?step:null,
    nextControl:next,loadMore,moreLikely:next||loadMore||cursorNames.length>0};
 }
 function analyze(record){
  const events=Array.isArray(record?.galleryEvents)?record.galleryEvents:[];
  const membership=Array.isArray(record?.galleryAssets)?record.galleryAssets:[];
  const collections=new Map(),idToCollections=new Map(),idToPages=new Map();
  const collectionKey=id=>id||'(collection not identified)';
  for(const link of membership){
   const id=safeId(link.assetId),c=collectionKey(safeId(link.collectionId));
   if(!id)continue;
   if(!collections.has(c))collections.set(c,{id:c,assets:new Set(),pages:new Set(),lastObserved:'',sightings:0});
   const g=collections.get(c);g.assets.add(id);g.sightings++;
   if(link.page)g.pages.add(link.page);
   g.lastObserved=link.at||g.lastObserved;
   if(!idToCollections.has(id))idToCollections.set(id,new Set());idToCollections.get(id).add(c);
   if(!idToPages.has(id))idToPages.set(id,new Set());if(link.page)idToPages.get(id).add(link.page);
  }
  const byScope=new Map();
  let growth=0, bottom=0, maxStep=0, cursorSeen=false, loadMoreSeen=false;
  for(const e of events){
   const scope=e.scope||'(unknown)';
   if(!byScope.has(scope))byScope.set(scope,{scope,observations:0,maxCards:0,maxImages:0,pages:new Set(),scrollBuckets:new Set(),cursorSteps:new Set(),atBottom:0,loadMore:false,nextControl:false,firstCards:null,lastCards:0,growth:0,hasIds:false});
   const s=byScope.get(scope);s.observations++;
   if(s.firstCards===null)s.firstCards=e.galleryCards||0;
   if(Number.isInteger(e.galleryCards)&&e.galleryCards>s.lastCards&&s.observations>1){s.growth++;growth++;}
   s.lastCards=e.galleryCards||0;s.maxCards=Math.max(s.maxCards,e.galleryCards||0);s.maxImages=Math.max(s.maxImages,e.imageCount||0);
   if(e.page)s.pages.add(e.page);
   if(Number.isInteger(e.scrollBucket))s.scrollBuckets.add(e.scrollBucket);
   if(e.atBottom){s.atBottom++;bottom++;}
   if(e.cursorNames?.length){cursorSeen=true;if(Number.isInteger(e.cursorStep)){s.cursorSteps.add(e.cursorStep);maxStep=Math.max(maxStep,e.cursorStep);}}
   s.loadMore ||= !!e.loadMore;s.nextControl ||= !!e.nextControl;loadMoreSeen ||= !!e.loadMore;
   s.hasIds ||= (e.assetCount||0)>0;
  }
  const sessions=[...byScope.values()].map(s=>{
   const steps=[...s.cursorSteps].sort((a,b)=>a-b);
   const pages=[...s.pages].sort((a,b)=>a-b);
   const assessment=s.observations===1?'Single observation':s.growth?'Growth observed; completeness unknown':
     (s.loadMore||s.nextControl||steps.length)?'Further paging signalled; completion unverified':'No growth observed; completeness unknown';
   return {scope:s.scope,observations:s.observations,observedPages:pages.join(', ')||'—',
    cursorTransitions:steps.length>1?steps.length-1:0,scrollBuckets:[...s.scrollBuckets].sort((a,b)=>a-b).join(', '),
    highestCards:s.maxCards,highestImages:s.maxImages,growthEvents:s.growth,bottomObservations:s.atBottom,
    loadingControls:[s.loadMore?'Load more':'',s.nextControl?'Next':''].filter(Boolean).join(' / ')||'—',assessment};
  });
  const table=[...collections.values()].map(c=>({collection:c.id,distinctAssets:c.assets.size,sightings:c.sightings,
   repeatedSightings:Math.max(0,c.sightings-c.assets.size),pages:[...c.pages].sort((a,b)=>a-b).join(', ')||'—',lastObserved:c.lastObserved})).sort((a,b)=>b.distinctAssets-a.distinctAssets);
  const overlappingAssets=[...idToCollections.values()].filter(x=>x.size>1).length;
  const repeatedAcrossPages=[...idToPages.values()].filter(x=>x.size>1).length;
  return {sessions,collections:table,stats:{scopes:sessions.length,observations:events.length,
   distinctAssets:idToCollections.size,distinctCollections:table.filter(x=>x.collection!=='(collection not identified)').length,
   overlappingAssets,repeatedAcrossPages,growthEvents:growth,bottomObservations:bottom,
   cursorSeen,highestCursorStep:maxStep,loadMoreSeen,recordsDropped:record?.counters?.galleryEventsDropped||0,
   membersDropped:record?.counters?.galleryAssetsDropped||0},
   warnings:['Cursor values, query text and search filters are not stored. Redacted URL scopes may combine different searches.',
    'DOM card growth is evidence of loading, not proof all assets were delivered.',
    'Asset IDs may be reused across providers; overlap alone does not establish identical underlying photographs.']};
 }
 const api={profiles,profile,safeId,inspect,analyze};
 if(typeof module!=='undefined'&&module.exports)module.exports=api;
 root.THIGallery=api;
})(typeof globalThis!=='undefined'?globalThis:this);
