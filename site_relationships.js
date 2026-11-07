/* v4.7: offline cross-site, host-role correlation of recorded events only.
 * Never fetches URLs, reads bodies, or treats shared CDN as shared ownership.
 */
(function(root){'use strict';
function host(raw){try{const u=new URL(String(raw||''));return /^https?:$/.test(u.protocol)?u.hostname.toLowerCase():'';}catch{return '';}}
const MAX_SEGMENTS=40, MAX_REQUESTS=1500;
function snapshot(records){
 const items=(Array.isArray(records)?records:[records]).filter(Boolean);
 if(items.length>MAX_SEGMENTS)throw Error('Maximum 40 segments per comparison');
 const origin=host(items[0]?.origin),map=new Map();
 for(const rec of items){
  for(const request of (rec.requests||[]).slice(0,MAX_REQUESTS)){
   const h=host(request.url);if(!h||h===origin)continue;
   const type=String(request.type||'').toLowerCase();
   let role=type==='sub_frame'?'Embedded frame':type==='image'?'Image delivery':type==='script'?'JavaScript delivery':
     (['xmlhttprequest','fetch'].includes(type)||/(?:^|\/)api(?:\/|$)|(?:^|\/)graphql(?:\/|$)/.test((()=>{try{return new URL(request.url).pathname;}catch{return '';}})()))?'API / data':'Other resource';
   if(map.size>=240&&!map.has(h))continue;
   const row=map.get(h)||{host:h,roles:new Set(),requests:0};row.roles.add(role);row.requests++;map.set(h,row);
  }
 }
 return {origin,segments:items.length,hosts:[...map.values()].map(x=>({host:x.host,roles:[...x.roles].sort(),requests:x.requests}))};
}
function compare(a,b){
 if(!a||!b)throw Error('Two snapshots required');
 if(a.origin===b.origin)throw Error('Choose investigations from different website origins');
 const first=new Map(a.hosts.map(x=>[x.host,x]));const second=new Map(b.hosts.map(x=>[x.host,x]));
 const common=[...first.keys()].filter(x=>second.has(x)).sort();
 const rows=common.slice(0,160).map(h=>{
  const left=first.get(h),right=second.get(h),sharedRoles=left.roles.filter(x=>right.roles.includes(x));
  return {host:h,firstRoles:left.roles.join(' · '),secondRoles:right.roles.join(' · '),
   sharedRoles:sharedRoles.join(' · ')||'None',firstRequests:left.requests,secondRequests:right.requests,
   assessment:sharedRoles.length?'Shared observed host and request role':'Shared observed host, different roles',
   confidence:'Host-level correlation only'};
 });
 return {rows,sharedHostCount:common.length,truncated:common.length>160,
  first:{origin:a.origin,segments:a.segments,hosts:first.size},second:{origin:b.origin,segments:b.segments,hosts:second.size},
  note:'Shared hosts and request roles do not establish a shared DAM database, supplier, account, licence or private storage. Missing hosts are not proof of removal. All comparisons use saved metadata only.'};
}
const api={host,snapshot,compare};root.THISiteRelations=api;
if(typeof module!=='undefined'&&module.exports)module.exports=api;
})(typeof self!=='undefined'?self:globalThis);
