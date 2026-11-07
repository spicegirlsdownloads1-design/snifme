/* Trufflehog v2.5 — bounded, offline asset lineage from ALREADY OBSERVED facts.
   No URLs are fetched, generated or resolved by this module. An identifier or a
   filename match never establishes licensing, original-file access or ownership. */
(function (root) {
  'use strict';
  const MAX_GROUPS=800;
  const reserved=/^(?:thumb|thumbnail|small|medium|large|preview|full|original|image|images|asset|assets|photo|photos|media|gallery|galleries|download|private|public|content|index|default|master|watermarked|file|files|static|api|view|search)$/i;
  const hexLong=/^[a-f0-9]{40,}$/i;
  function safeId(value){
    if(typeof value!=='string')return '';
    const s=value.trim();
    if(s.length<5||s.length>44||!(/^[a-z0-9][a-z0-9_.-]*$/i).test(s)||reserved.test(s)||hexLong.test(s)||/^(?:gh[pousr]_|sk_(?:live|test)_|rk_(?:live|test)_|xox[bapors]-|aiza|akia|asia|eyj)/i.test(s)||/^[a-f0-9]{32}$/i.test(s))return '';
    // Avoid treating ordinary natural-language filename stems as asset identifiers.
    if(!/\d/.test(s)&&!(/^[a-f0-9]{8}-[a-f0-9-]{20,}$/i).test(s))return '';
    return s.toLowerCase();
  }
  function pathId(value){
    try {
      const u=new URL(value);
      if(!/^https?:$/.test(u.protocol))return '';
      const segments=u.pathname.split('/').filter(Boolean).map(x=>{try{return decodeURIComponent(x);}catch{return x;}});
      for(let i=0;i<segments.length-1;i++) {
        if(/^(?:asset|assets|image|images|photo|photos|media|picture|pictures|item|items|view)$/i.test(segments[i])) {
          const v=safeId(segments[i+1].replace(/\.(?:json|html|jpe?g|webp|png|gif|avif|tif)$/i,'')
            .replace(/(?:[-_](?:\d{2,5}x\d{2,5}|w\d{2,5}|h\d{2,5}|thumb(?:nail)?|preview|small|medium|large|full|\d{2,5}))+$/i,''));
          if(v)return v;
        }
      }
      const last=segments.at(-1)||'';
      const stem=last.replace(/\.(?:jpe?g|webp|png|gif|avif|tiff?|bmp|json|html)$/i,'')
        .replace(/(?:[-_](?:\d{2,5}x\d{2,5}|w\d{2,5}|h\d{2,5}|thumb(?:nail)?|preview|small|medium|large|full|\d{2,5}))+$/i,'');
      return safeId(stem);
    }catch{return '';}
  }
  function host(url){try{return new URL(url).hostname;}catch{return '';}}
  function imageRows(record){
    if(root.THIImages?.rows)return root.THIImages.rows(record?.assets||[],record?.verifications||[]);
    return (record?.assets||[]).filter(x=>x?.url).map(x=>({...x}));
  }
  function analyze(record){
    const images=imageRows(record).slice(0,MAX_GROUPS), links=(record?.assetLinks||[]).slice(0,500),
      routes=(record?.routes||[]).filter(x=>x.observed).slice(0,350),responses=(record?.responses||[]).slice(0,120);
    const index=new Map(images.map((a,i)=>[a.url,i]));
    const parent=images.map((_,i)=>i);const find=i=>parent[i]===i?i:(parent[i]=find(parent[i]));
    const union=(a,b)=>{const x=find(a),y=find(b);if(x!==y)parent[y]=x;};
    const evidenceByUrl=new Map();
    const addE=(url,e)=>{if(!evidenceByUrl.has(url))evidenceByUrl.set(url,new Set());evidenceByUrl.get(url).add(e);};
    const groupsOf=(keyOf,e)=>{
      const map=new Map();
      images.forEach((a,i)=>{const key=keyOf(a);if(!key)return;if(map.has(key))union(i,map.get(key));else map.set(key,i);addE(a.url,e);});
    };
    // These are different strength joins. The evidence column distinguishes them.
    groupsOf(a=>a.sha256&&/^[a-f0-9]{64}$/.test(a.sha256)?`hash:${a.sha256}`:'','byte-identical');
    groupsOf(a=>a.family?`family:${a.family}`:'','same-host URL variant heuristic');
    const linkMap=new Map();
    for(const l of links){
      if(!index.has(l.imageUrl))continue;
      if(!linkMap.has(l.imageUrl))linkMap.set(l.imageUrl,[]);
      linkMap.get(l.imageUrl).push(l);
    }
    // Explicit asset IDs on the actual rendered image/card are strongest DOM association.
    const domIDs=new Map();
    for(const l of links){
      if(!index.has(l.imageUrl))continue;
      const id=safeId(l.assetId);
      if(!id)continue;
      const i=index.get(l.imageUrl);
      if(domIDs.has(id))union(i,domIDs.get(id));else domIDs.set(id,i);
      addE(l.imageUrl,'DOM-declared asset identifier');
    }
    // Asset ID in a path is a clue, not proof of an identical underlying image.
    groupsOf(a=>{const id=pathId(a.url);return id?`path:${id}`:'';},'matching path identifier (unverified)');
    const groupMap=new Map();
    for(let i=0;i<images.length;i++){
      const k=find(i);
      if(!groupMap.has(k))groupMap.set(k,[]);
      groupMap.get(k).push(images[i]);
    }
    const out=[];
    for(const group of groupMap.values()){
      const urls=group.map(a=>a.url),urlSet=new Set(urls),gLinks=links.filter(l=>urlSet.has(l.imageUrl));
      const domIDs=[...new Set(gLinks.map(l=>safeId(l.assetId)).filter(Boolean))];
      const pathIDs=[...new Set(group.map(a=>pathId(a.url)).filter(Boolean))];
      const ids=new Set([...domIDs,...pathIDs]);
      const connectedRoutes=routes.filter(r=>ids.has(pathId(r.url)));
      const connectedResponses=responses.filter(r=>ids.has(pathId(r.url)));
      const exactHashes=new Map();
      for(const a of group){if(!/^[a-f0-9]{64}$/.test(a.sha256||''))continue;
        if(!exactHashes.has(a.sha256))exactHashes.set(a.sha256,new Set());exactHashes.get(a.sha256).add(a.url);}
      const exact=[...exactHashes.values()].some(s=>s.size>1);
      const evidence=[...new Set(group.flatMap(a=>[...(evidenceByUrl.get(a.url)||[])]))];
      const verified=group.filter(a=>a.encodedWidth&&a.encodedHeight);
      verified.sort((a,b)=>b.encodedWidth*b.encodedHeight-a.encodedWidth*a.encodedHeight);
      const browser=group.filter(a=>a.width&&a.height).sort((a,b)=>b.width*b.height-a.width*a.height);
      const top=verified[0]||browser[0];
      const dimensions=top?(verified.length?`${top.encodedWidth} × ${top.encodedHeight}`:`${top.width} × ${top.height}`):'Unknown';
      const pageLinks=[...new Set(gLinks.map(l=>l.pageUrl).filter(Boolean))];
      const details=[...new Set(gLinks.map(l=>l.detailUrl).filter(Boolean))];
      const groupHosts=[...new Set(group.map(a=>a.host||host(a.url)).filter(Boolean))];
      let confidence='URL-only observation';
      if(exact)confidence='Verified identical bytes';
      else if(domIDs.length)confidence='Declared DOM association';
      else if(group.length>1)confidence='Heuristic variant / ID grouping';
      const leadId=domIDs[0]||pathIDs[0]||'Unidentified';
      out.push({assetId:leadId,otherIds:[...ids].filter(i=>i!==leadId),confidence,images:group.length,
        verified:verified.length,largestObserved:dimensions,largestEvidence:verified.length?'Verified encoded pixels':browser.length?'Browser natural dimensions':'Not established',
        galleryPages:pageLinks,detailPages:details,hosts:groupHosts,observedApiRoutes:connectedRoutes.map(r=>r.url),
        responseShapes:connectedResponses.length,exactBytes:exact,evidence,
        imageUrls:urls,hasExplicitDomId:domIDs.length>0, signedUrls:group.filter(a=>a.signedQuery).length});
    }
    out.sort((a,b)=>Number(b.hasExplicitDomId)-Number(a.hasExplicitDomId)||Number(b.exactBytes)-Number(a.exactBytes)||b.images-a.images);
    return {rows:out,stats:{assets:images.length,groups:out.length,domLinks:links.length,
      domIdGroups:out.filter(x=>x.hasExplicitDomId).length,byteExactGroups:out.filter(x=>x.exactBytes).length,
      groupsWithObservedApi:out.filter(x=>x.observedApiRoutes.length).length},
      warnings:['Path and filename IDs are only clues; DOM card IDs describe page associations, not DAM ownership.',
        'Images shown are only observed/declared assets; no original or licensed file availability is inferred.',
        'Response structure contains field names and types, not asset values; it cannot prove image-to-API identity.']};
  }
  function pipeline(record){
    const images=imageRows(record);const out=new Map();
    for(const a of images){
      const h=a.host||host(a.url);if(!h)continue;
      if(!out.has(h))out.set(h,{host:h,files:0,verified:0,withSignedParameters:0,
        transformationKeys:new Set(),pathHints:new Set(),mime:new Set(),largestVerified:0,largestText:'—',confidence:'Observed image URL'});
      const r=out.get(h);r.files++;
      if(a.sha256)r.verified++;
      if(a.signedQuery)r.withSignedParameters++;
      try{
        const u=new URL(a.url);
        for(const k of u.searchParams.keys())if(/^(?:w|h|width|height|size|fit|crop|fm|format|quality|q|dpr|auto|resize)$/i.test(k))r.transformationKeys.add(k.toLowerCase());
        for(const [re,kind] of [[/\bthumb(?:nail)?\b/i,'thumbnail'],[/\bpreview\b/i,'preview'],[/\bresize|transform\b/i,'transformation path'],[/\/iiif\//i,'IIIF path'],[/\/(?:full|original|master)(?:\/|\.)/i,'named path (not access proof)']]){
          if(re.test(u.pathname))r.pathHints.add(kind);
        }
      }catch{}
      if(a.mime)r.mime.add(a.mime);
      const px=a.encodedWidth&&a.encodedHeight?a.encodedWidth*a.encodedHeight:0;
      if(px>r.largestVerified){r.largestVerified=px;r.largestText=`${a.encodedWidth} × ${a.encodedHeight}`;}
    }
    return [...out.values()].map(r=>({host:r.host,observedImages:r.files,verifiedResponses:r.verified,
      transformationKeys:[...r.transformationKeys].join(', ')||'—',pathHints:[...r.pathHints].join(', ')||'—',
      imageTypes:[...r.mime].join(', ')||'—',signedRequests:r.withSignedParameters,
      largestVerified:r.largestText,assessment:r.verified?'Observed assets, some cryptographically verified':'Observed/declared URLs only'}))
      .sort((a,b)=>b.observedImages-a.observedImages);
  }
  root.THILineage={safeId,pathId,analyze,pipeline};
})(globalThis);
