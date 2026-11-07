/* Trufflehog Intelligence v2.4 – local, evidence-led DAM/CMS/gallery recognition.
 * No endpoint guessing, probing, credential access or storage of raw HTML/text.
 * UMD-style global makes the same pure engine usable in MV3 background/content/dashboard/tests.
 */
(function(root){
  'use strict';
  const PROFILES = [
    {id:'capture', name:'Capture DAM', layer:'DAM', domains:['captureweb.net'], markers:[['capture-asset-fields',/(?:\bidasset\b[\s\S]{0,600}\borg_filename\b|\borg_filename\b[\s\S]{0,600}\bidasset\b)/i,2,'Capture-style asset field pair (not exclusive)']]},
    {id:'photoshelter',name:'PhotoShelter',layer:'DAM',domains:['photoshelter.com'],markers:[['photoshelter-code',/\b(?:PhotoShelter|photoshelter)\b/i,2,'PhotoShelter named in public script']]},
    {id:'resourcespace',name:'ResourceSpace',layer:'DAM',domains:['resourcespace.com'],markers:[['resourcespace-code',/\bResourceSpace\b/i,2,'ResourceSpace named in public script']]},
    {id:'bynder',name:'Bynder',layer:'DAM',domains:['bynder.com','bynder.io'],markers:[['bynder-code',/\bBynder(?:CompactView|AssetBank)?\b/i,2,'Bynder marker in public script']]},
    {id:'canto',name:'Canto',layer:'DAM',domains:['canto.com','canto.global'],markers:[['canto-code',/\bCanto\s+(?:DAM|Digital Asset Management)\b/i,2,'Canto DAM label in public script']]},
    {id:'fotoware',name:'FotoWare / FotoWeb',layer:'DAM',domains:['fotoware.com'],markers:[['fotoweb-code',/\b(?:FotoWare|FotoWeb)\b/i,2,'FotoWare/FotoWeb named in public script']]},
    {id:'wordpress',name:'WordPress',layer:'CMS',domains:['wordpress.com','wp.com'],paths:[['wordpress-content',/\/wp-content\/(?:plugins|themes|uploads)\//i,4,'WordPress content directory'],['wordpress-rest',/\/wp-json\//i,4,'WordPress REST API path'],['wordpress-includes',/\/wp-includes\//i,3,'WordPress core files']]},
    {id:'drupal',name:'Drupal',layer:'CMS',domains:['drupal.org'],paths:[['drupal-core',/\/core\/misc\/drupal\./i,4,'Drupal core asset'],['drupal-settings',/\/sites\/[^/]+\/files\//i,1,'Potential Drupal media path']]},
    {id:'contentful',name:'Contentful',layer:'Headless CMS',domains:['contentful.com','ctfassets.net','contentfulassets.net','contentful.com'],paths:[['contentful-content',/\/spaces\/[^/]+\/environments\//i,2,'Contentful-style content path']]},
    {id:'sanity',name:'Sanity',layer:'Headless CMS',domains:['sanity.io','sanitycdn.com']},
    {id:'strapi',name:'Strapi',layer:'Headless CMS',domains:['strapi.io'],markers:[['strapi-js',/\b(?:@strapi\/|strapi::|strapi\.config)\b/i,3,'Strapi framework script marker']]},
    {id:'directus',name:'Directus',layer:'Headless CMS',domains:['directus.io'],paths:[['directus-assets',/\/assets\/[0-9a-f]{8}-[0-9a-f-]{27,}/i,1,'Possible Directus asset path (generic)']]},
    {id:'cloudinary',name:'Cloudinary',layer:'Image delivery',domains:['cloudinary.com'],paths:[['cloudinary-delivery',/\/image\/upload\//i,1,'Cloudinary-style image delivery path']]},
    {id:'imgix',name:'imgix',layer:'Image delivery',domains:['imgix.net']},
    {id:'imagekit',name:'ImageKit',layer:'Image delivery',domains:['imagekit.io','ik.imagekit.io']},
    {id:'smartframe',name:'SmartFrame',layer:'Gallery viewer',domains:['smartframe.io'],markers:[['smartframe-embed',/<smartframe-embed\b|\bcustomer-id\s*=\s*['"][^'"]+['"][\s\S]{0,100}\bimage-id\s*=/i,3,'SmartFrame embed marker']]},
    {id:'openseadragon',name:'OpenSeadragon',layer:'Gallery viewer',markers:[['openseadragon-js',/\bOpenSeadragon\b/i,3,'OpenSeadragon JavaScript symbol']]},
    {id:'iiif',name:'IIIF image service',layer:'Image protocol',paths:[['iiif-info',/\/(?:iiif|iiif-img|iiif-images)(?:\/[^?#]+)*\/info\.json$/i,3,'IIIF image information URL']]},
    {id:'deepzoom',name:'Deep Zoom (DZI)',layer:'Image protocol',paths:[['dzi-file',/\.dzi$/i,4,'Deep Zoom image manifest URL']]},
    {id:'zoomify',name:'Zoomify',layer:'Image protocol',paths:[['zoomify-properties',/\/ImageProperties\.xml$/i,4,'Zoomify image properties URL']]}
  ];
  const BY_ID = Object.fromEntries(PROFILES.map(p=>[p.id,p]));
  function hostMatch(host,domain) {return host===domain||host.endsWith('.'+domain);}
  function cleanUrl(value) {
    try {const u=new URL(String(value));if(!/^https?:$/.test(u.protocol))return null;
      // Never return query values, fragments or usernames. The caller must supply URLs already sanitized upstream.
      return {host:u.hostname.toLowerCase(),path:u.pathname.slice(0,450)};
    }catch{return null;}
  }
  function scanText(value,source='public script') {
    const str=String(value||'').slice(0,500000),results=[];
    for(const p of PROFILES)for(const [signalId,re,weight,detail] of (p.markers||[])){
      if(re.test(str))results.push({id:p.id,signalId,weight,kind:'static-code',detail,source:String(source).slice(0,140)});
    }
    return results.slice(0,30);
  }
  function scanPageFacts(facts) {
    const hints=[];
    const generator=String(facts?.generator||'').slice(0,180);
    const genMap=[['wordpress',/\bWordPress\b/i],['drupal',/\bDrupal\b/i],['strapi',/\bStrapi\b/i],['fotoWare',/\bFotoWare\b/i]];
    for(const [rawId,re]of genMap){const id=rawId.toLowerCase();if(re.test(generator)&&BY_ID[id])hints.push({id,signalId:'generator-'+id,weight:4,kind:'declared-generator',detail:'HTML generator metadata',source:'page DOM'});}
    for(const name of (Array.isArray(facts?.elements)?facts.elements:[]).slice(0,20)){
      const e=String(name).toLowerCase();
      if(e==='smartframe-embed')hints.push({id:'smartframe',signalId:'smartframe-element',weight:4,kind:'DOM-element',detail:'SmartFrame embed element',source:'page DOM'});
    }
    // Only predefined tech-specific identifiers; never transmit raw DOM selectors/data attributes.
    return hints;
  }
  function analyze(record) {
    if(!record||typeof record!=='object')return {profiles:[],relationships:[],generic:[]};
    const evidence=new Map(),countByType={};
    function add(id,signalId,weight,kind,detail,source) {
      if(!BY_ID[id])return;
      if(!evidence.has(id))evidence.set(id,new Map());
      const unique=`${signalId}|${kind}|${source}`;
      if(evidence.get(id).size>=32||evidence.get(id).has(unique))return;
      evidence.get(id).set(unique,{signalId,weight,kind,detail,source:String(source||'').slice(0,170)});
    }
    function fromUrl(url,kind='observed-request') {
      const info=cleanUrl(url);if(!info)return;
      const weight=kind==='observed-request'?5:kind==='DOM-resource'?3:2;
      // Publicly observed vendor-owned host is evidence of vendor infrastructure use,
      // NOT proof that the website itself is powered by that vendor.
      for(const p of PROFILES){
        for(const domain of p.domains||[])if(hostMatch(info.host,domain)){
          add(p.id,'domain-'+domain,weight,kind,'Vendor-associated public host: '+domain,info.host);
          break;
        }
        for(const [signalId,re,baseWeight,detail]of p.paths||[])if(re.test(info.path)){
          add(p.id,signalId,Math.min(baseWeight,weight),kind,detail,info.host+':'+info.path.slice(0,130));
        }
      }
      // Generalised gallery/DAM architecture clues, never vendor attribution.
      for(const [type,re] of [['asset-metadata',/\/(?:api\/)?(?:assets?|media)(?:\/|$)/i],['collections',/\/(?:api\/)?(?:galleries|collections|albums|lightboxes)(?:\/|$)/i],['search',/\/(?:api\/)?search(?:\/|$)/i]]){
        if(re.test(info.path))countByType[type]=(countByType[type]||0)+1;
      }
    }
    if(record.origin)fromUrl(record.origin,'site-origin');
    for(const r of (record.requests||[]).slice(-1500))fromUrl(r.url,'observed-request');
    for(const a of (record.assets||[]).slice(0,1200))fromUrl(a.url,a.source==='network'?'observed-request':'DOM-resource');
    for(const s of (record.scripts||[]).slice(0,300))fromUrl(s.url,'DOM-resource');
    for(const r of (record.routes||[]).slice(0,600))fromUrl(r.url,r.observed?'observed-request':'static-reference');
    for(const m of (record.maps||[]).slice(0,150))fromUrl(m.url,'static-reference');
    // Page-generated hints and static script markers are validated against allowlisted IDs.
    for(const hint of (record.technologyHints||[]).slice(0,120)){
      const p=BY_ID[hint?.id];if(!p)continue;
      const allowed=(p.markers||[]).find(x=>x[0]===hint.signalId);
      const generator=hint.signalId==='generator-'+p.id&&['wordpress','drupal','strapi','fotoware'].includes(p.id);
      const element=hint.signalId==='smartframe-element'&&p.id==='smartframe';
      if(!allowed&&!generator&&!element)continue;
      const kind=allowed?'static-code':generator?'declared-generator':'DOM-element';
      const weight=allowed?allowed[2]:4;
      const detail=allowed?allowed[3]:generator?'HTML generator metadata':'SmartFrame embed element';
      add(p.id,hint.signalId,weight,kind,detail,String(hint.source||'page DOM').slice(0,150));
    }
    // Generic site software clues reported separately, without asserting a named DAM.
    const generic=[];
    const seenWords=new Set();
    for(const x of (record.responses||[]).slice(0,160)){
      const fields=(x.fields||[]).slice(0,80).map(f=>String(f.path||'').toLowerCase());
      // Capture's published API documents these specific asset field names.
      // Two names alone are only a clue, not unique platform identification.
      if(fields.some(f=>/(?:^|\.)idasset$/.test(f)) && fields.some(f=>/(?:^|\.)org_filename$/.test(f))){
        const info=cleanUrl(x.url||'');
        add('capture','capture-json-field-pair',3,'observed-JSON-shape',
          'Observed idasset and org_filename field names (not unique)',info?.host||'JSON shape');
      }
      for(const path of fields){
        if(/(?:^|\.)(?:asset|assets|gallery|galleries|collection|collections|lightbox|lightboxes)(?:\.|$|\[\])/i.test(path))seenWords.add(path.split('.')[0]);
      }
    }
    const profiles=[...evidence.entries()].map(([id,items])=>{
      const profile=BY_ID[id],ev=[...items.values()];
      const groups=new Map();for(const e of ev) {const prev=groups.get(e.signalId);if(!prev||e.weight>prev.weight)groups.set(e.signalId,e);}
      const strongest=[...groups.values()].sort((a,b)=>b.weight-a.weight);
      const independent=strongest.slice(0,4);
      const score=Math.min(10,independent.reduce((total,x)=>total+x.weight,0));
      const confidence=score>=7?'Strong indication':score>=4?'Moderate indication':'Weak clue';
      const observed=ev.some(e=>e.kind==='observed-request');
      return {id,name:profile.name,layer:profile.layer,confidence,score,
        assessment:observed?'Vendor/platform-related resource observed; deployment role unconfirmed':'Only declared or static references; deployment unconfirmed',
        evidence:ev.sort((a,b)=>b.weight-a.weight).slice(0,12),independentSignals:strongest.length};
    }).sort((a,b)=>b.score-a.score||a.name.localeCompare(b.name));
    if(seenWords.size)generic.push({type:'Asset-related JSON field paths',detail:[...seenWords].slice(0,8).join(', '),evidence:'Observed response schema only'});
    for(const [type,quantity] of Object.entries(countByType))generic.push({type,detail:`${quantity} URL sightings`,evidence:'Observed and/or referenced routes; may include duplicates'});
    const relationships=[];
    // Correlation is strictly site-session co-observation, never proof of a shared backend.
    const cms=profiles.filter(p=>['CMS','Headless CMS'].includes(p.layer));
    const dams=profiles.filter(p=>p.layer==='DAM');
    for(const c of cms.slice(0,4))for(const d of dams.slice(0,4))relationships.push({from:c.name,to:d.name,
      relation:'Co-observed in this browser capture',confidence:'Unverified integration',evidence:'Technology clues were seen in the same tab; no backend link is established'});
    return {profiles,relationships,generic:generic.slice(0,12)};
  }
  root.THIDAM={PROFILES:PROFILES.map(({id,name,layer})=>({id,name,layer})),scanText,scanPageFacts,analyze};
})(globalThis);
