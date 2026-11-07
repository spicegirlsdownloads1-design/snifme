/* Isolated-world inventory. Sends URLs and masked indicators, never raw page HTML. */
/* global THI */
(() => {
  'use strict';
  if (globalThis.__THI_CONTENT_INITIALIZED) return;
  globalThis.__THI_CONTENT_INITIALIZED = true;
  let observing = false;
  let observer = null;
  let scheduled = null;
  const sent = {scripts: new Set(), assets: new Set(), routes: new Set(), findings: new Set(), clues: new Set(), pagination: new Set(), assetLinks:new Set(), maps:new Set(), operations:new Set(), configs:new Set(), technologyHints:new Set(),viewerHints:new Set(),embeddedContexts:new Set(),frameCoverage:new Set(),workerScripts:new Set()};
  const MAX_EACH = 350;
  // Cursor VALUES are used only to detect changes in-memory. They are never sent
  // or persisted; the step counter is scoped to this tab's current page context.
  let lastCursor = undefined, cursorStep = 0, lastGallerySnapshot = '', lastObservedGalleryIds = '';
  let snapshotBusy = false, lastFrameCoverageSignature='';
  const watchedFrameDocs=new WeakSet(),frameWatchers=[];
  function add(list, key, value, collection) {
    if (!key || collection.has(key) || collection.size >= MAX_EACH) return;
    collection.add(key); list.push(value);
  }
  function parseSrcset(srcset, push) {
    for (const entry of String(srcset || '').split(',').slice(0, 20)) {
      const parts = entry.trim().split(/\s+/);
      if (parts[0]) push(parts[0], null, null, parts[1] || 'srcset');
    }
  }
  async function snapshot() {
    if (!observing || snapshotBusy) return;
    snapshotBusy = true;
    try {
    const payload = {scripts:[], assets:[], routes:[], findings:[], clues:[], pagination:[], assetLinks:[], maps:[], operations:[], configs:[], technologyHints:[],viewerHints:[],embeddedContexts:[],frameCoverage:[],workerScripts:[],gallerySnapshot:null};
    const base = document.baseURI;
    const addAsset = (url, width, height, descriptor='') => {
      const info = THI.urlInfo(url, base);
      if (!info) return;
      const widthInt = Number.isInteger(width) ? width : null;
      const heightInt = Number.isInteger(height) ? height : null;
      const key = `${info.url}|${widthInt || ''}|${heightInt || ''}|${descriptor}`;
      add(payload.assets, key, {url:info.url, width:widthInt, height:heightInt, descriptor, signedQuery:info.signedQuery}, sent.assets);
    };
    for (const img of [...document.images].slice(0, 450)) {
      addAsset(img.currentSrc || img.src, img.naturalWidth, img.naturalHeight, 'currentSrc');
      if (img.src && img.src !== img.currentSrc) addAsset(img.src, null, null, 'src');
      parseSrcset(img.getAttribute('srcset'), addAsset);
      // DOM-only association between the displayed image and its own card/detail link.
      // These fields are visible in the gallery already; arbitrary data-* attributes
      // and links to external sites are ignored.
      const imageInfo=THI.urlInfo(img.currentSrc || img.src, base);
      if(imageInfo){
        const owner=img.closest('[data-asset-id],[data-image-id],[data-photo-id],[data-media-id]');
        let id='';
        if(owner)for(const attr of ['data-asset-id','data-image-id','data-photo-id','data-media-id']){
          id=THILineage.safeId(owner.getAttribute(attr)||'');if(id)break;
        }
        const anchor=img.closest('a[href]') || owner?.closest('a[href]');
        const detail=anchor?THI.urlInfo(anchor.href,base):null;
        let detailUrl='';
        if(detail){try{if(new URL(detail.url).origin===location.origin && !detail.signedQuery)detailUrl=detail.url;}catch{}}
        const pageInfo=THI.urlInfo(location.href);
        // Only collect a relationship when a card ID or a local detail link exists.
        if((id||detailUrl)&&pageInfo){
          const item={imageUrl:imageInfo.url,assetId:id,detailUrl,pageUrl:pageInfo.url,source:'visible gallery DOM'};
          const key=[item.imageUrl,item.assetId,item.detailUrl,item.pageUrl].join('|');
          add(payload.assetLinks,key,item,sent.assetLinks);
        }
      }
    }
    for (const source of [...document.querySelectorAll('picture source[srcset]')].slice(0, 100)) {
      parseSrcset(source.srcset, addAsset);
    }
    for (const link of [...document.querySelectorAll('link[rel="preload"],link[rel="prefetch"],meta[property="og:image"],meta[name="twitter:image"]')].slice(0, 100)) {
      const url = link.href || link.content;
      if (url && (link.as === 'image' || link.tagName === 'META')) addAsset(url, null, null, 'metadata');
      if (link.as === 'script' && url) {
        const i = THI.urlInfo(url, base);
        if (i) add(payload.scripts, i.url, {url:i.url, signedQuery:i.signedQuery}, sent.scripts);
      }
    }
    for (const script of [...document.querySelectorAll('script[src]')].slice(0, 200)) {
      const info = THI.urlInfo(script.src, base);
      if (info) add(payload.scripts, info.url, {url:info.url, signedQuery:info.signedQuery}, sent.scripts);
    }
    // Public image/network resource URLs already recorded by the page's Performance API.
    for (const resource of performance.getEntriesByType('resource').slice(-500)) {
      const i = THI.urlInfo(resource.name, base);
      if (!i) continue;
      if (i.image || resource.initiatorType === 'img') addAsset(i.url, null, null, 'resource');
      if (resource.initiatorType === 'script') add(payload.scripts, i.url, {url:i.url, signedQuery:i.signedQuery}, sent.scripts);
    }
    // v4.7: top-page-only embedded context inventory. NEVER inspect frame bodies.
    // Retain origins, not iframe paths, query strings, srcdoc or attributes.
    const pageOrigin = location.origin;
    const addContext=(kind,raw,evidence,sandboxed=false)=>{
      try{
        const u=new URL(raw,base);
        if(!/^https?:$/.test(u.protocol))return;
        const item={kind,origin:u.origin,evidence,sandboxed:!!sandboxed};
        add(payload.embeddedContexts, [kind,u.origin,evidence,sandboxed].join('|'),item,sent.embeddedContexts);
      }catch{}
    };
    for(const frame of [...document.querySelectorAll('iframe[src]')].slice(0,55)){
      addContext('embedded-frame',frame.getAttribute('src'),'iframe element',frame.hasAttribute('sandbox'));
    }
    const workerScript=navigator.serviceWorker?.controller?.scriptURL;
    if(workerScript)addContext('controlled-service-worker',workerScript,'service worker controller');
    for(const timing of performance.getEntriesByType('resource').slice(-400)){
      if(timing.initiatorType==='worker')
        addContext('worker-resource-hint',timing.name,'resource timing hint');
    }
    // v4.8: inspect only explicitly same-origin and DOM-accessible iframe documents.
    // Frames with another origin are classified without touching contentDocument.
    const scoped=THIFrameScope.inspect(document,location.origin,{indicators:THI.secretIndicators,urlInfo:THI.urlInfo});
    const frameSignature=JSON.stringify(scoped.rows);
    if(frameSignature!==lastFrameCoverageSignature){payload.frameCoverage=scoped.rows;lastFrameCoverageSignature=frameSignature;}
    for(const finding of scoped.findings){
      add(payload.findings,`${finding.source}|${finding.type}|${finding.offset}|${finding.masked}`,finding,sent.findings);
    }
    for(const script of scoped.scripts){
      add(payload.scripts,script.url,script,sent.scripts);
    }
    for(const child of scoped.documents){
      if(watchedFrameDocs.has(child)||frameWatchers.length>=35)continue;
      watchedFrameDocs.add(child);
      try{const obs=new MutationObserver(schedule);
        obs.observe(child.documentElement,{subtree:true,childList:true,attributes:true,
          attributeFilter:['src','srcset','data-asset-id','data-image-id']});
        frameWatchers.push(obs);
      }catch{}
    }
    // Service Worker controller references are NOT proof of inspecting its script.
    if(workerScript){
      const controller=THI.urlInfo(workerScript,base);
      if(controller){add(payload.workerScripts,controller.url,{url:controller.url,kind:'controller-reference',inspected:false},sent.workerScripts);}
    }

    // Pagination hints are observed locally, not requests to unvisited pages.
    const safePage = n => Number.isSafeInteger(n) && n > 0 && n <= 1000000 ? n : null;
    const fromUrl = (() => {
      try {const u=new URL(location.href);return safePage(Number(u.searchParams.get('page') || u.searchParams.get('p') || ''));}
      catch {return null;}
    })();
    let page = fromUrl;
    const current = document.querySelector('[aria-current="page"],.pagination .active,.pager .current');
    if (current && /^\d{1,6}$/.test((current.textContent || '').trim())) page = safePage(Number(current.textContent.trim()));
    let totalPages = null, totalResults = null;
    const selectors = ['[class*="pagin"]','[class*="pager"]','[data-testid*="pagination"]','[aria-label*="pagination" i]','[class*="result-count"]'];
    const candidates = [...document.querySelectorAll(selectors.join(','))].slice(0,25);
    for (const node of candidates) {
      const text = String(node.textContent||'').replace(/\s+/g,' ').slice(0,600);
      const matches = text.match(/\bpage\s+(\d{1,6})\s+of\s+(\d{1,6})\b/i);
      if (matches) {page ||= safePage(Number(matches[1]));totalPages ||= safePage(Number(matches[2]));}
      const explicitResults = text.match(/\b(?:total\s*[:=]\s*|of\s+)([\d,]{1,13})\s+(?:results|images|items|records)\b/i);
      const rangeResults = text.match(/\b\d{1,9}\s*[-–—]\s*\d{1,9}\s+of\s+([\d,]{1,13})\b/i);
      const results = explicitResults || rangeResults;
      if (results) {
        const count = Number(results[1].replaceAll(',', ''));
        if (Number.isSafeInteger(count) && count > 0 && count <= 1000000000) totalResults ||= count;
      }
    }
    // Do not infer total pages from numbered links: many pagers use sliding windows.
    if (page || totalPages || totalResults) {
      const loc = THI.urlInfo(location.href);
      if (loc) {
        const key = [loc.url,page,totalPages,totalResults].join('|');
        add(payload.pagination,key,{url:loc.url,page,totalPages,totalResults,source:'page DOM'},sent.pagination);
      }
    }
    // v2.7 gallery coverage: only IDs, coarse scroll progress and controls.
    // Query values, search text, arbitrary DOM strings, and raw cursor tokens stay local.
    const locGallery=THI.urlInfo(location.href);
    if(locGallery){
      const allGalleryCards=document.querySelectorAll('[data-asset-id],[data-image-id],[data-photo-id],[data-media-id]');
      // Prefer the most recently appended cards for long infinite-scroll lists.
      const galleryCards=[...allGalleryCards].slice(-200);
      const assetIds=new Set();
      for(const card of galleryCards){
        for(const name of ['data-asset-id','data-image-id','data-photo-id','data-media-id']){
          const id=THIGallery.safeId(card.getAttribute(name)||'');if(id){assetIds.add(id);break;}
        }
      }
      const collectionIds=new Set();
      for(const el of [...document.querySelectorAll('[data-collection-id],[data-gallery-id],[data-album-id]')].slice(0,25)){
        for(const name of ['data-collection-id','data-gallery-id','data-album-id']){
          const id=THIGallery.safeId(el.getAttribute(name)||'');if(id){collectionIds.add(id);break;}
        }
      }
      const parsed=new URL(location.href);
      const cursorNames=['cursor','after','before','endCursor','pageCursor','nextCursor','starting_after','continuation','continuationToken'];
      let cursorRaw=null,cursorKey=null;
      for(const name of cursorNames)if(parsed.searchParams.has(name)){cursorRaw=parsed.searchParams.get(name);cursorKey=name;break;}
      if(cursorRaw!==null){if(lastCursor!==cursorRaw){lastCursor=cursorRaw;cursorStep++;}}
      else {lastCursor=undefined;cursorStep=0;}
      const root=document.scrollingElement||document.documentElement;
      const maximum=Math.max(1,root.scrollHeight-innerHeight);
      const scrollBucket=Math.max(0,Math.min(20,Math.floor((root.scrollTop/maximum)*20)));
      const atBottom=maximum<=1 || root.scrollTop+innerHeight>=root.scrollHeight-35;
      const nextControl=!!document.querySelector('a[rel="next"], [aria-label="Next page" i], [aria-label="Next results" i]');
      const loadMore=!!document.querySelector('[data-testid*="load-more" i],[class*="load-more" i],button[aria-label*="load more" i]');
      const gallerySnapshot={url:locGallery.url.split('?')[0],assetIds:[...assetIds].slice(0,160),collectionIds:[...collectionIds].slice(0,8),
        page, galleryCards:allGalleryCards.length,imageCount:document.images.length,scrollBucket,atBottom,
        cursorStep,cursorNames:cursorKey?[cursorKey]:[],nextControl,loadMore};
      // Make one report per evidence change, and do not consume a snapshot slot
      // merely because other detectors found nothing new.
      const signature=JSON.stringify([locGallery.url,gallerySnapshot.assetIds,gallerySnapshot.collectionIds,page,
        gallerySnapshot.galleryCards,gallerySnapshot.imageCount,scrollBucket,atBottom,cursorStep,nextControl,loadMore]);
      if(signature!==lastGallerySnapshot){payload.gallerySnapshot=gallerySnapshot;lastGallerySnapshot=signature;}
    }
    // Viewer inventory uses only DOM element counts/dimensions; never read canvas
    // pixels, WebGL surfaces, embedded IDs, or image tiles.
    const canvases=[...document.querySelectorAll('canvas')].slice(0,200);
    const facts={canvasCount:canvases.length,
      canvasMaxWidth:Math.max(0,...canvases.map(c=>Number.isSafeInteger(c.width)?c.width:0)),
      canvasMaxHeight:Math.max(0,...canvases.map(c=>Number.isSafeInteger(c.height)?c.height:0)),
      smartFrameCount:document.querySelectorAll('smartframe-embed').length,
      openSeadragonCount:document.querySelectorAll('.openseadragon-container,.openseadragon-canvas').length};
    for(const hint of THIViewer.pageFacts(facts)){
      add(payload.viewerHints,`${hint.technology}|${hint.evidence}|${hint.count}|${hint.maxWidth||''}|${hint.maxHeight||''}`,
        {...hint,source:'page DOM'},sent.viewerHints);
    }
    // Only a tiny allowlisted set of vendor/CMS DOM facts, no raw page markup.
    const generator=document.querySelector('meta[name="generator" i]')?.getAttribute('content')||'';
    const elements=document.querySelector('smartframe-embed')?['smartframe-embed']:[];
    for(const hint of THIDAM.scanPageFacts({generator,elements}))
      add(payload.technologyHints,`${hint.id}|${hint.signalId}|${hint.source}`,hint,sent.technologyHints);
    // Embedded public configuration / inline JS. Only derived indicators leave the page.
    const inline = [...document.querySelectorAll('script:not([src])')].slice(0, 80);
    let processed = 0;
    for (let index = 0; index < inline.length; index++) {
      const code = inline[index].textContent || '';
      if (!code || code.length > 350000 || processed + code.length > 750000) continue;
      processed += code.length;
      const source = `inline script ${index + 1}`;
      for (const finding of THI.secretIndicators(code, source)) {
        add(payload.findings, `${source}|${finding.type}|${finding.offset}`, finding, sent.findings);
      }
      for(const hint of THIViewer.staticHints(code,source))
        add(payload.viewerHints,`${hint.technology}|${hint.source}`,hint,sent.viewerHints);
      for (const route of THI.endpointClues(code, source, base)) {
        add(payload.routes, route.url, route, sent.routes);
      }
      const application=THIApp.inspectStatic(code,source,base);
      for(const hint of THIDAM.scanText(code,source))
        add(payload.technologyHints,`${hint.id}|${hint.signalId}|${hint.source}`,hint,sent.technologyHints);
      for(const map of application.maps) add(payload.maps,map.url,map,sent.maps);
      for(const op of application.operations) add(payload.operations,`${op.operationType}|${op.name}|${source}`,op,sent.operations);
      for(const cfg of application.configs) add(payload.configs,`${cfg.key}|${source}`,cfg,sent.configs);
      for (const clue of THI.frameworkClues(code, source)) {
        add(payload.clues, `${clue.source}|${clue.label}`, clue, sent.clues);
      }
    }
    if (Object.values(payload).some(items => Array.isArray(items) ? items.length : !!items)) {
      try {await chrome.runtime.sendMessage({type:'PAGE_REPORT', payload});} catch { /* extension reloaded */ }
    }
    } finally {snapshotBusy=false;}
  }
  function schedule() {
    if (!observing || scheduled !== null) return;
    scheduled = setTimeout(() => {scheduled = null; void snapshot();}, 850);
  }
  function start() {
    if (observing) {schedule(); return;}
    // A stopped-and-restarted capture must resend the initial DOM snapshot.
    for(const set of Object.values(sent))set.clear();
    lastGallerySnapshot='';lastFrameCoverageSignature='';lastCursor=undefined;cursorStep=0;
    observing = true;
    observer = new MutationObserver(schedule);
    observer.observe(document.documentElement, {childList:true, subtree:true, attributes:true,
      attributeFilter:['src', 'srcset', 'href', 'content','data-asset-id','data-photo-id','data-image-id','data-media-id','data-collection-id','data-gallery-id','data-album-id']});
    window.addEventListener('load', schedule);
    document.addEventListener('load', schedule, true);
    window.addEventListener('scroll', schedule, {passive:true});
    window.addEventListener('popstate', schedule);
    schedule();
  }
  function stop() {
    observing = false;
    if (observer) observer.disconnect();
    for(const watcher of frameWatchers)watcher.disconnect();frameWatchers.length=0;
    if (scheduled !== null) clearTimeout(scheduled);
    scheduled = null;
    window.removeEventListener('load', schedule);
    document.removeEventListener('load', schedule, true);
    window.removeEventListener('scroll', schedule);
    window.removeEventListener('popstate', schedule);
  }
  // Interaction markers exclude selectors, text, search queries and form values.
  let lastInteractionAt=0;
  function markInteraction(kind){
    if(!observing||Date.now()-lastInteractionAt<180)return;
    lastInteractionAt=Date.now();
    try{chrome.runtime.sendMessage({type:'GALLERY_INTERACTION',payload:{kind}}).catch(()=>{});}catch{}
  }
  document.addEventListener('submit',e=>{
    if(e.target?.matches?.('form,[role="search"]'))markInteraction('search-submit');
  },true);
  document.addEventListener('change',e=>{
    if(!e.target?.matches?.('select,input[type="checkbox"],input[type="radio"]'))return;
    const el=e.target;const s=((el.name||'')+' '+(el.id||'')).slice(0,70);
    markInteraction(/sort|order/i.test(s)?'sort-change':'filter-change');
  },true);
  document.addEventListener('click',e=>{
    if(!e.target?.closest)return;
    if(e.target.closest('[data-lightbox],.lightbox-trigger,[aria-haspopup="dialog"]'))markInteraction('lightbox-open');
    else if(e.target.closest('[rel="next"],[data-load-more],.load-more'))markInteraction('load-more');
  },true);
  chrome.runtime.onMessage.addListener((message, _sender, reply) => {
    if (message?.type === 'TRUFFLEHOG_HEALTH_PING') {reply({ok:true,inspectorPresent:true,observing,origin:location.origin});return;}
    if (message?.type === 'CAPTURE_SNAPSHOT') {start(); reply({ok:true});}
    if (message?.type === 'STOP_CAPTURE') {stop(); reply({ok:true});}
  });
  try {chrome.runtime.sendMessage({type:'PAGE_READY'}).catch(() => {});} catch {}
})();
