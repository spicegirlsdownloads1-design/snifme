/* v7.16 imported text/HTTP trace privacy preflight. Zero network/storage.
 * Intended for explicitly selected local HAR/cURL/PowerShell logs only.
 * Reports pattern counts, NEVER matching values or excerpts. */
(function(root,factory){const api=factory();if(typeof module==='object'&&module.exports)module.exports=api;else root.THIImportPrivacy=api;})(typeof globalThis!=='undefined'?globalThis:this,function(){'use strict';
const max=12*1024*1024;
const rules=[
 ['Cookies / sessions',/(?:\bCookie\s*:|(?:\s|^)\-b\s*[\"']|(?:wordpress_logged_in|wordpress_sec|PHPSESSID|cf_clearance|set-cookie)\s*[=:])/gi],
 ['Authentication headers',/(?:\bAuthorization\s*:|\bBearer\s+[a-z0-9._~+/=-]{10,}|\bApi[-_ ]Key\s*:)/gi],
 ['Password-like assignments',/(?:\b(?:password|passwd|pwd|passphrase)\b\s*(?:=|:|%3d)|[?&](?:password|passwd|pwd)=)/gi],
 ['Signed-link parameters',/(?:[?&](?:X-Amz-Signature|X-Goog-Signature|Signature|Policy|Key-Pair-Id|sig|token|access_token)=)/gi],
 ['Private account identifiers',/(?:\bemail\s*[=:]|\buser[_-]?id\s*[=:]|\bip_address\s*[=:])/gi],
 ['Request bodies / form submissions',/(?:\b(?:--data(?:-raw|-binary|-urlencode)?|Invoke-WebRequest|postData|requestBody)\b|\bContent-Type\s*:\s*application\/x-www-form-urlencoded)/gi]
];
function inspect(text){
 if(typeof text!=='string')return {ok:false,reason:'Unsupported input',rows:[]};
 if(text.length>max)return {ok:false,reason:'Input exceeds 12 MB cap; not inspected',rows:[]};
 const rows=[];let total=0;
 for(const [category,pattern] of rules){pattern.lastIndex=0;let count=0,m;
  while((m=pattern.exec(text))!==null){count++;if(count>=1000)break;}
  if(count){rows.push({category,count,assessment:'Review locally before sharing'});total+=count;}
 }
 return {ok:true,bytes:text.length,foundCategories:rows.length,indicators:total,rows,advice:rows.length?'Sensitive values may be present. Keep the source file private, change exposed credentials if live, and do not copy these requests to a remote service.':'No known patterns found; this does NOT certify that the file contains no secrets.'};
}
return Object.freeze({inspect});
});
