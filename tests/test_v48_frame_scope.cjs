const assert=require('node:assert/strict');
require('../scanner.js');const THI=globalThis.THI;
const X=require('../frame_scope.js');
const owner='https://gallery.test', token='ghp_'+'A'.repeat(25);
const node=(text,src)=>({textContent:text||'',getAttribute:n=>n==='src'?src:null,hasAttribute:n=>n==='src'&&!!src});
const inner={baseURI:owner+'/gallery/frame?secret=DO_NOT_STORE',images:[{},{}],
 querySelectorAll:(q)=>q==='script'?[node(`const s="${token}";`),node('','/js/asset.js?token=DO_NOT_STORE')]:[]};
const own={getAttribute:n=>n==='src'?'/gallery/frame?secret=DO_NOT_STORE':null,
 contentWindow:{location:{origin:owner}},contentDocument:inner};
let accessed=false;
const remote={getAttribute:n=>n==='src'?'https://foreign.test/private?token=DO_NOT_STORE':null,
 get contentDocument(){accessed=true;throw new Error('CROSS ORIGIN FRAME WAS READ')},
 get contentWindow(){accessed=true;throw new Error('CROSS ORIGIN FRAME WAS READ')}};
const blank={getAttribute:()=>'',hasAttribute:()=>false,get contentDocument(){accessed=true;throw new Error('SRCLESS FRAME SHOULD NOT BE READ')}};
const top={baseURI:owner+'/gallery/',querySelectorAll:q=>q==='iframe'?[own,remote,blank]:[]};
const out=X.inspect(top,owner,{indicators:THI.secretIndicators,urlInfo:THI.urlInfo});
assert.equal(accessed,false);
assert.equal(out.rows.length,3);
assert.equal(out.rows[0].status,'inspected');
assert.equal(out.rows[1].status,'cross-origin');
assert.equal(out.rows[2].status,'unsupported');
assert.equal(out.rows[0].images,2);
assert.equal(out.findings.length,1);
assert(out.findings[0].masked.includes('[redacted]'));
assert.equal(out.findings[0].line,1);
assert.equal(out.scripts.length,1);
assert(out.scripts[0].url.includes('/js/asset.js'));
assert(!JSON.stringify({rows:out.rows,findings:out.findings,scripts:out.scripts}).includes(token));
assert(!JSON.stringify({rows:out.rows,findings:out.findings,scripts:out.scripts}).includes('DO_NOT_STORE'));
assert.equal(X.cleanRow({status:'inspected',origin:'https://foreign.test',index:2},owner),null);
assert.equal(X.cleanRow({status:'inspected',origin:owner,index:1,inlineScripts:1},owner).status,'inspected');
assert.equal(X.cleanRow({status:'inspected',origin:owner,index:0},owner),null);
console.log('PASS v4.8 frame scopes: same-origin only, strict bounds, redaction, no cross-origin read');
