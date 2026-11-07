/* Pure offline image grouping. No network operations, image downloads or URL guessing. */
(function (root) {
  'use strict';
  function extension(path) {
    const m=String(path).match(/\.(?:jpe?g|png|webp|gif|avif|tiff?|bmp|svg)$/i);
    return m ? m[0].toLowerCase() : '';
  }
  function normalizePath(url) {
    try {
      const u=new URL(url);
      const ext=extension(u.pathname);
      const base=ext ? u.pathname.slice(0,-ext.length) : u.pathname;
      // Conservative cleanup: only remove *trailing* well-known size/version suffixes.
      const clean=base.replace(/(?:[-_](?:\d{2,5}x\d{2,5}|w\d{2,5}|h\d{2,5}|\d{2,5}w|thumb(?:nail)?|small|medium|large|preview|original|full))+$/i,'');
      return {host:u.hostname, family:u.hostname+clean.toLowerCase(), basename:clean.split('/').pop().toLowerCase(), ext};
    } catch {return null;}
  }
  function rows(assets, verifications) {
    const byURL=new Map();
    for (const a of assets || []) {
      if (!a.url || !normalizePath(a.url)) continue;
      if (!byURL.has(a.url)) byURL.set(a.url,{...a, sources:[a.source]});
      else {
        const existing=byURL.get(a.url);
        if (a.width && a.height && (!existing.width || !existing.height)) Object.assign(existing,{width:a.width,height:a.height,descriptor:a.descriptor});
        for(const f of ['mime','bytes','etag','modified']) if (!existing[f] && a[f]) existing[f]=a[f];
        if(a.source && !existing.sources.includes(a.source))existing.sources.push(a.source);
        existing.signedQuery ||= a.signedQuery;
      }
    }
    const byVerification=new Map((verifications || []).map(v=>[v.url,v]));
    for (const [url,v] of byVerification) {
      if (!byURL.has(url)) byURL.set(url,{url,host:v.host,source:'DevTools',sources:['DevTools'],width:null,height:null});
      const r=byURL.get(url);
      r.encodedWidth=v.width||null;r.encodedHeight=v.height||null;r.sha256=v.sha256||'';
      r.encodedBytes=v.byteLength||null;r.format=v.format||'';r.visualHash=v.visual?.full||'';r.visual=v.visual||null;
      r.evidence=v.width&&v.height?'Verified response header':'SHA-256 verified bytes (dimensions unknown)';
    }
    return [...byURL.values()].map(r=>({...r,source:(r.sources||[r.source]).join(' + '),
      evidence:r.evidence||(r.width&&r.height?'Browser-reported size':'URL / request only'),
      pixelArea:r.encodedWidth&&r.encodedHeight?r.encodedWidth*r.encodedHeight:null,
      browserArea:r.width&&r.height?r.width*r.height:null,
      family:normalizePath(r.url)?.family||'',
      basename:normalizePath(r.url)?.basename||''}));
  }
  function variants(assets) {
    const groups=new Map();
    for(const a of assets) {
      if(!a.family)continue;
      if(!groups.has(a.family))groups.set(a.family,[]);
      groups.get(a.family).push(a);
    }
    return [...groups.entries()].filter(([,list])=>list.length>=2).map(([key,list])=>{
      const verified=list.filter(a=>a.pixelArea).sort((a,b)=>b.pixelArea-a.pixelArea);
      const browser=list.filter(a=>a.browserArea).sort((a,b)=>b.browserArea-a.browserArea);
      const best=verified[0]||browser[0]||null;
      return {family:key,variantCount:list.length,host:list[0].host,
        largest:best?(verified.length?`${best.encodedWidth} × ${best.encodedHeight}`:`${best.width} × ${best.height}`):'Unknown',
        largestEvidence:verified.length?'Verified encoded pixels':browser.length?'Browser-reported size only':'No dimensions',
        largestUrl:best?.url||'', verifiedCount:verified.length,
        formats:[...new Set(list.map(a=>a.format||a.mime||'').filter(Boolean))].join(', ')||'—',
        urls:list.map(a=>a.url)};
    }).sort((a,b)=>b.variantCount-a.variantCount);
  }
  function matches(assets) {
    const output=[];
    const hashed=new Map();
    for(const a of assets){
      if(!/^[a-f0-9]{64}$/.test(a.sha256||'')) continue;
      if(!hashed.has(a.sha256))hashed.set(a.sha256,[]);
      hashed.get(a.sha256).push(a);
    }
    const covered=new Set();
    for(const [hash,list] of hashed) {
      const hosts=[...new Set(list.map(x=>x.host))];
      if(hosts.length<2)continue;
      output.push({kind:'Byte-identical',confidence:'SHA-256 exact match',identity:hash.slice(0,16)+'…',hosts:hosts.join(' · '),count:list.length,urls:list.map(x=>x.url)});
      list.forEach(a=>covered.add(a.url));
    }
    const byId=new Map();
    for(const a of assets){
      if(covered.has(a.url))continue;
      const id=(a.basename.match(/(?:^|[-_.])([a-z]{0,4}\d{7,12})(?=$|[-_.])/i)||[])[1]?.toLowerCase();
      if(!id)continue;
      if(!byId.has(id))byId.set(id,[]);
      byId.get(id).push(a);
    }
    for(const [id,list] of byId) {
      const hosts=[...new Set(list.map(x=>x.host))];
      if(hosts.length<2)continue;
      output.push({kind:'Identifier hint',confidence:'Unverified filename similarity',identity:id,hosts:hosts.join(' · '),count:list.length,urls:list.map(x=>x.url)});
    }
    return output.sort((a,b)=>(a.kind==='Byte-identical'?-1:1)-(b.kind==='Byte-identical'?-1:1));
  }
  root.THIImages={normalizePath,rows,variants,matches};
})(globalThis);
