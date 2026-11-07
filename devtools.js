/* Optional passive inspector for DevTools-visible JSON response schemas.
 * Runs only while DevTools is open for the selected tab AND the user has
 * explicitly enabled JSON shape inspection in the dashboard.
 * NEVER sends raw bodies, field values, cookies or authorization headers. */
'use strict';
const inspectedTabId = chrome.devtools.inspectedWindow.tabId;
const MAX_CONTENT = 256 * 1024;
const BAD_KEY = /(?:token|secret|pass|auth|session|cookie|credential|email|phone|address|user|personal|payment|card|name|jwt|key)/i;
// Random references are valid only for this DevTools lifetime. Actual asset,
// license and size IDs exist solely in this in-memory map; never message/storage.
const licensingRefs=new Map();
function privateLicensingRef(kind,raw) {
  const lookup=kind+':'+String(raw);
  if(licensingRefs.has(lookup))return licensingRefs.get(lookup);
  if(licensingRefs.size>=4000)licensingRefs.clear();
  const result='ref-'+crypto.randomUUID();
  licensingRefs.set(lookup,result);
  return result;
}
const PAGE_FIELDS = new Set(['page','currentPage','totalPages','totalResults','totalCount','pageCount']);
function extractShape(root) {
  const fields = [], pagination = {};
  const seen = new WeakSet();
  function walk(value, path, level, context) {
    if (fields.length >= 50 || level > 5) return;
    if (!value || typeof value !== 'object') return;
    if (seen.has(value)) return;
    seen.add(value);
    const entries = Array.isArray(value) ? [['[]',value[0]]] : Object.entries(value).slice(0,90);
    for (const [key, child] of entries) {
      if (fields.length >= 50) break;
      if (BAD_KEY.test(key) || !/^(?:[A-Za-z_$][\w$-]{0,49}|\[\])$/.test(key)) continue;
      const currentPath = path ? path + '.' + key : key;
      const type = child === null ? 'null' : Array.isArray(child) ? 'array' : typeof child;
      if (!['null','array','string','number','boolean','object'].includes(type)) continue;
      fields.push({path:currentPath,type});
      const pageContext = context || /^(?:pagination|pageInfo|paging|meta)$/i.test(key);
      if (PAGE_FIELDS.has(key) && Number.isSafeInteger(child) && child > 0 && child <= 1000000000) {
        if (key === 'totalCount') pagination.totalResults = child;
        else if (key === 'pageCount') pagination.totalPages = child;
        else if (key === 'page' && !pageContext && level > 2) {/* may be an unrelated nested object's page */}
        else pagination[key] = child;
      }
      if (level < 5 && (type === 'object' || type === 'array')) walk(child,currentPath,level+1,pageContext);
    }
  }
  walk(root,'',0,false);
  return {fields,pagination};
}
chrome.devtools.panels.create('Trufflehog Intel','icon16.png','devtools-panel.html');
chrome.devtools.network.onRequestFinished.addListener(request => {
  void (async () => {
    const mime = request.response?.content?.mimeType || '';
    const url = request.request?.url || '';
    if (!/^https?:\/\//i.test(url)) return;
    const isJSON=/(?:json|\+json)/i.test(mime);
    const isMedia=/^(?:image|video|audio)\//i.test(mime);
    if (!isJSON && !isMedia) return;
    if (isJSON && (request.response?.content?.size || 0) > MAX_CONTENT) return;
    const permitted = await chrome.runtime.sendMessage({type:'GET_RESPONSE_PERMISSION',tabId:inspectedTabId});
    if (!permitted?.ok || !permitted.enabled) return;
    if (isMedia) {
      const media=THIProductAsset.inspectMedia({url,mime,status:request.response?.status},privateLicensingRef);
      if(media)void chrome.runtime.sendMessage({type:'PIM_MEDIA_OBSERVATION',tabId:inspectedTabId,payload:{media}}).catch(()=>{});
      return;
    }
    request.getContent((content, encoding) => {
      if (typeof content !== 'string' || content.length > MAX_CONTENT || encoding === 'base64') return;
      try {
        const data=JSON.parse(content);
        const shape = extractShape(data);
        // Do not retain `data`. Only semantic types, safe numbers/booleans
        // and randomly replaced identifiers leave this DevTools page.
        const licensing=THIAssetLicensing.inspect(data,{
          method:request.request?.method||'GET',status:request.response?.status||null,url
        },privateLicensingRef);
        const pim=THIProductAsset.inspect(data,{url,status:request.response?.status},privateLicensingRef);
        if(!shape.fields.length && licensing.categories.every(x=>x==='UNKNOWN') && pim.labels.every(x=>x==='UNKNOWN'))return;
        void chrome.runtime.sendMessage({type:'RESPONSE_SHAPE',tabId:inspectedTabId,
          payload:{url,mime,method:request.request?.method||'GET',status:request.response?.status||null,
            fields:shape.fields,pagination:shape.pagination,licensing,pim}}).catch(()=>{});
      } catch {/* Not JSON or extension has been reloaded */}
    });
  })().catch(() => {});
});
