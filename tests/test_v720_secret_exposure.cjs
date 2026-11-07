'use strict';
const assert=require('node:assert/strict');
const S=require('../security_intelligence.js');
const THI=(()=>{require('../scanner.js');return globalThis.THI;})();
const token='gh'+'p_'+'SYNTHETICNONWORKINGTOKEN123456789';
const base={url:'https://api.example.invalid/api/data',method:'POST',requestId:'R-1',timeStamp:1794012000000,statusCode:200};
const ids=x=>x.map(v=>v.ruleId);

const req=S.classify('request-headers',{...base,requestHeaders:[{name:'Authorization',value:'Bearer '+token},{name:'X-Trace',value:token}]});
assert(ids(req).includes('CREDENTIAL_REQUEST_HEADER'));
assert.deepEqual(req.find(x=>x.ruleId==='CREDENTIAL_REQUEST_HEADER').markers,['authorization']);
const resp=S.classify('response-headers',{...base,responseHeaders:[{name:'X-Api-Key',value:token}]});
assert(ids(resp).includes('CREDENTIAL_RESPONSE_HEADER'));
const redir=S.classify('redirect',{...base,redirectUrl:'https://app.example.invalid/callback?client_secret='+token});
assert(ids(redir).includes('REDIRECT_SECRET'));

for(const [kind,text,marker] of [
 ['javascript',`window.config={client_secret:"${token}"}`,'named-secret-assignment'],
 ['html',`<script>const key="${token}"</script>`,'github-token'],
 ['json',JSON.stringify({access_token:token}),'named-secret-assignment']
]){
 const rows=S.classifyBody('response-body',base,text,kind);
 assert.equal(rows.length,1);assert(rows[0].markers.includes(marker));
 assert.equal(rows[0].classification,kind);
 assert(!JSON.stringify(rows).includes(token));
}
assert.equal(S.classifyBody('response-body',base,'x'.repeat(2*1024*1024+1),'json').length,0);
assert.equal(S.classifyBody('response-body',base,'{"api_key":"example"}','json').length,0);

const har={log:{entries:[{startedDateTime:'2026-11-07T01:00:00Z',request:{url:base.url,method:'POST',headers:[{name:'Authorization',value:'Bearer '+token}],postData:{mimeType:'application/json',text:JSON.stringify({access_token:token})}},response:{status:200,headers:[{name:'X-Api-Key',value:token}],content:{mimeType:'application/json',text:JSON.stringify({client_secret:token})},redirectURL:'https://app.example.invalid/cb?access_token='+token}}]}};
const analyzed=S.analyzeHar(har);const harIds=ids(analyzed.observations);
for(const id of ['CREDENTIAL_REQUEST_HEADER','CREDENTIAL_RESPONSE_HEADER','SECRET_REQUEST_BODY','SECRET_RESPONSE_BODY','REDIRECT_SECRET'])assert(harIds.includes(id),id);
assert(!JSON.stringify(analyzed).includes(token));

const npm='npm_'+'abcdefghijklmnopqrstuvwxyzABCDEFGH';
const hf='hf_'+'abcdefghijklmnopqrstuvwxyzABCDEFGH';
const extra=THI.secretIndicators(`${npm} ${hf} postgres://user:synthetic_password_123@db.example.invalid/app`,'fixture');
assert(extra.some(x=>x.type==='npm access-token indicator'));
assert(extra.some(x=>x.type==='Hugging Face token indicator'));
assert(extra.some(x=>x.type==='Database credential URI'));
assert(!JSON.stringify(extra).includes('synthetic_password_123'));
console.log('PASS v7.20 passive JS/HTML/JSON/header/redirect/HAR secret exposure detection and redaction');
