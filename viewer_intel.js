/* v2.6 Specialist Viewer Intelligence. Pure, local, passive classification.
 * A URL is evidence of a request or reference, never authority to fetch tiles.
 */
(function(root){
 'use strict';
 const maxNumber=(n,max=200000)=>Number.isSafeInteger(Number(n))&&Number(n)>0&&Number(n)<=max?Number(n):null;
 function keyFromURL(url){try{const u=new URL(url);if(!/^https?:$/.test(u.protocol))return '';return u.origin+u.pathname;}catch{return '';}}
 function classifyUrl(value){
  let u;try{u=new URL(value);if(!/^https?:$/.test(u.protocol))return null;}catch{return null;}
  const p=u.pathname, low=p.toLowerCase();let format='',kind='',level=null,family='';
  const dziTile=p.match(/^(.*)_files\/(\d{1,4})\/(\d{1,8})_(\d{1,8})\.(?:jpe?g|png|webp)$/i);
  const zoomTile=p.match(/^(.*\/)(?:TileGroup\d{1,8})\/(\d{1,4})-(\d{1,8})-(\d{1,8})\.(?:jpe?g|png|webp)$/i);
  if(dziTile){format='Deep Zoom';kind='tile';level=maxNumber(Number(dziTile[2])+1,10000)-1;family=u.origin+dziTile[1]+'.dzi';}
  else if(/\.dzi$/i.test(low)){format='Deep Zoom';kind='manifest reference';family=u.origin+p;}
  else if(zoomTile){format='Zoomify';kind='tile';level=maxNumber(Number(zoomTile[2])+1,10000)-1;family=u.origin+zoomTile[1]+'ImageProperties.xml';}
  else if(/\/imageproperties\.xml$/i.test(low)){format='Zoomify';kind='manifest reference';family=u.origin+p;}
  else if(/\/(?:full|square|pct:\d+(?:\.\d+)?|\d+,\d+,\d+,\d+)\/(?:max|full|pct:\d+(?:\.\d+)?|!?\d+,\d*|\d+,)\/(?:!?\d+(?:\.\d+)?)\/(?:default|color|gray|bitonal)\.(?:jpe?g|png|webp|tif)$/i.test(p)){
    const parts=p.split('/');format='IIIF Image API';kind='image or region request';family=u.origin+parts.slice(0,-4).join('/');
  } else if(/\/info\.json$/i.test(low)){
    format='Possible IIIF';kind='image info reference';family=u.origin+p.slice(0,-10);
  } else if(/\/(?:manifest|collection)\.json$/i.test(low)&&/(?:iiif|presentation)/i.test(low)){
    format='Possible IIIF';kind='presentation reference';family=u.origin+p;
  } else if(u.searchParams.has('JTL')&&u.searchParams.has('FIF')){
    format='IIPImage';kind='tiled image request';family=u.origin+u.pathname; // Never retain FIF value.
  } else return null;
  return {format,kind,level,family:family.slice(0,600),strength:format.startsWith('Possible')?'candidate format':'URL format match'};
 }
 const STATIC_PATTERNS=[
  ['OpenSeadragon',/\bOpenSeadragon\s*\(|\bOpenSeadragon\.Viewer\b/],
  ['Deep Zoom',/\bZoomifyTileSource\b|\bDziTileSource\b|\btileSources\s*:/],
  ['IIIF Image API',/iiif\.io\/api\/image\/[23]|\bImageService3\b|\bImageService2\b/],
  ['SmartFrame',/<smartframe-embed\b|customElements\.define\(\s*['"]smartframe-embed['"]/i],
  ['Canvas 2D',/\.getContext\(\s*['"]2d['"]/],
  ['WebGL',/\.getContext\(\s*['"](?:webgl2?|experimental-webgl)['"]/]
 ];
 function staticHints(text,source){const s=String(text||'').slice(0,500000);return STATIC_PATTERNS.filter(([,re])=>re.test(s)).map(([technology])=>({technology,evidence:'static JavaScript reference',source:String(source||'').slice(0,150)}));}
 function pageFacts(facts){const out=[];
  const add=(technology,evidence,count,other={})=>{if(count>0)out.push({technology,evidence,count:Math.min(10000,Math.floor(count)),...other});};
  add('Canvas', 'rendered canvas elements (context unverified)',maxNumber(facts?.canvasCount,10000)||0,{maxWidth:maxNumber(facts?.canvasMaxWidth)||null,maxHeight:maxNumber(facts?.canvasMaxHeight)||null});
  add('SmartFrame','smartframe-embed DOM elements',maxNumber(facts?.smartFrameCount,10000)||0);
  add('OpenSeadragon','openseadragon DOM class markers',maxNumber(facts?.openSeadragonCount,10000)||0);
  return out;
 }
 function parseManifest(content,mime='',sourceUrl=''){
  if(typeof content!=='string'||content.length>262144)return null;
  const urlClass=classifyUrl(sourceUrl),mimeLower=String(mime).toLowerCase();
  if(!urlClass||!['manifest reference','image info reference','presentation reference'].includes(urlClass.kind))return null;
  const size=(v)=>maxNumber(v,200000);
  if(urlClass.format==='Deep Zoom'&&/xml|text\/plain|octet-stream/.test(mimeLower)){
    if(!/^\s*(?:<\?xml[^>]*>\s*)?<Image\b/i.test(content)||!(/deepzoom\/2008/i.test(content)))return null;
    const img=content.match(/<Image\b([^>]*)>/i)?.[1]||'',s=content.match(/<Size\b([^>]*)\/?\s*>/i)?.[1]||'';
    const attr=(src,name)=>src.match(new RegExp('\\b'+name+'\\s*=\\s*["\'](\\d{1,8})["\']','i'))?.[1];
    const width=size(attr(s,'Width')),height=size(attr(s,'Height')),tileSize=size(attr(img,'TileSize'));
    if(!width||!height||!tileSize||tileSize>8192)return null;
    return {format:'Deep Zoom',width,height,tileWidth:tileSize,tileHeight:tileSize,levels:null,source:'observed XML manifest'};
  }
  if(urlClass.format==='Zoomify'&&/xml|text\/plain|octet-stream/.test(mimeLower)){
    const attrs=content.match(/<\s*IMAGE_PROPERTIES\b([^>]*)\/?>/i)?.[1];if(!attrs)return null;
    const attr=(name)=>attrs.match(new RegExp('\\b'+name+'\\s*=\\s*["\'](\\d{1,8})["\']','i'))?.[1];
    const width=size(attr('WIDTH')),height=size(attr('HEIGHT')),tileSize=size(attr('TILESIZE'));
    if(!width||!height||!tileSize||tileSize>8192)return null;
    return {format:'Zoomify',width,height,tileWidth:tileSize,tileHeight:tileSize,levels:null,source:'observed XML manifest'};
  }
  if(!/(?:json|ld\+json|text\/plain)/.test(mimeLower))return null;
  let data;try{data=JSON.parse(content);}catch{return null;}
  if(!data||typeof data!=='object'||Array.isArray(data))return null;
  const context=String(Array.isArray(data['@context'])?data['@context'].join(' '):data['@context']||'');
  const dtype=String(data.type||data['@type']||'');
  const iiif=/iiif\.io\/api\/(?:image|presentation)\/[23]/.test(context)||/^(?:ImageService[23]|sc:Manifest|Manifest|Collection)$/.test(dtype);
  if(!iiif)return null;
  if(/Manifest|Collection/.test(dtype))return {format:'IIIF Presentation',width:null,height:null,tileWidth:null,tileHeight:null,levels:null,itemCount:Array.isArray(data.items)?Math.min(data.items.length,50000):null,source:'observed JSON manifest'};
  const width=size(data.width),height=size(data.height);
  if(!width||!height)return null;
  const t=Array.isArray(data.tiles)?data.tiles[0]:null;
  const scaleFactors=Array.isArray(t?.scaleFactors)?t.scaleFactors.filter(n=>Number.isInteger(n)&&n>0&&n<=131072).slice(0,30):[];
  return {format:'IIIF Image API',width,height,tileWidth:size(t?.width),tileHeight:size(t?.height)||size(t?.width),levels:scaleFactors.length||null,scaleFactors,source:'observed JSON image information'};
 }
 function summarize(record){
  const resources=(record?.viewerResources||[]).slice(0,500),manifests=(record?.viewerManifests||[]).slice(0,100),hints=(record?.viewerHints||[]).slice(0,150);
  const groups=new Map();
  const get=(key,format)=>{if(!groups.has(key))groups.set(key,{format,family:key,observedRequests:0,tiles:0,levels:new Set(),manifest:null,statuses:new Set(),evidence:new Set()});return groups.get(key);};
  for(const r of resources){const g=get(r.family,r.format);g.observedRequests++;if(r.kind==='tile'||r.kind==='image or region request'||r.kind==='tiled image request')g.tiles++;if(Number.isInteger(r.level))g.levels.add(r.level);if(r.status!==null)g.statuses.add(r.status);g.evidence.add('observed request');}
  for(const m of manifests){const g=get(m.family,m.format);g.manifest=m;g.evidence.add('DevTools-observed manifest content');}
  const rows=[...groups.values()].map(g=>({format:g.manifest?.format||g.format,family:g.family,observedRequests:g.observedRequests,observedTiles:g.tiles,observedLevels:[...g.levels].sort((a,b)=>a-b).join(', ')||'—',declaredDimensions:g.manifest?.width?`${g.manifest.width} × ${g.manifest.height}`:'Not established',tileSize:g.manifest?.tileWidth?`${g.manifest.tileWidth} × ${g.manifest.tileHeight}`:'—',declaredLevels:g.manifest?.levels??'—',evidence:[...g.evidence].join(' + '),statuses:[...g.statuses].join(', ')||'—'})).sort((a,b)=>b.observedTiles-a.observedTiles);
  return {rows,hints,stats:{families:rows.length,tiles:rows.reduce((s,x)=>s+x.observedTiles,0),manifests:manifests.length,viewerHints:hints.length},warnings:['Only already-observed requests and opted-in metadata are recorded.','Declared dimensions in IIIF/DZI/Zoomify manifests do not prove accessible master files.','Canvas presence does not establish WebGL, image access or render resolution.']};
 }
 root.THIViewer={classifyUrl,staticHints,pageFacts,parseManifest,summarize};
})(globalThis);
