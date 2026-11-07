'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const ctx=vm.createContext({console,URL,URLSearchParams,atob,TextDecoder});ctx.globalThis=ctx;
for(const f of ['scanner.js','resource_decoder.js','offline_inspector.js'])vm.runInContext(fs.readFileSync(f,'utf8'),ctx,{filename:f});
const D=ctx.THIResourceDecoder,O=ctx.THIOffline;
const secret='ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop';
assert.equal(D.decode(Buffer.from('abc').toString('base64'),'base64','application/json').text,'abc');
assert.equal(D.decode('QUJD','base64','image/png').status,'unsupported');
assert.equal(D.decode('!!!!','base64','text/plain').status,'unsupported');
assert.equal(D.decode(Buffer.from('xxxxx').toString('base64'),'base64','text/plain',4).status,'oversized');
let r=O.textFile('Imported js #1','javascript','\nconst x="'+secret+'";');
assert.equal(r.status,'scanned');assert.equal(r.findings.length,1);assert.equal(r.findings[0].line,2);
assert.equal(r.findings[0].masked,'[redacted]');
assert(!JSON.stringify(r).includes('ABCDE'));
const src='https://static.example.com/app.js?api_key=REAL_PRIVATE_TOKEN';
const har={log:{entries:[
 {request:{url:src,headers:[{name:'authorization',value:secret}]},response:{content:{mimeType:'application/javascript',text:Buffer.from('let val="'+secret+'"').toString('base64'),encoding:'base64'}}},
 {request:{url:'https://static.example.com/second.js?token=NO'},response:{content:{mimeType:'text/javascript'}}},
 {request:{url:'https://cdn.example.com/logo.png'},response:{content:{mimeType:'image/png',text:'PNG DATA'}}}
 ]}};
r=O.harObject(har);assert.equal(r.length,3);assert.equal(r[0].status,'scanned');assert.equal(r[0].findings.length,1);assert.equal(r[1].status,'missingBody');assert.equal(r[2].status,'unsupported');
const report=JSON.stringify(O.exportReport(r));assert(!report.includes(secret));assert(!report.includes('REAL_PRIVATE_TOKEN'));assert(!report.includes('authorization'));
assert.equal(O.summarize(r).excluded,2);
const huge='a'.repeat(O.MAX_TEXT+1);assert.equal(O.textFile('item','javascript',huge).status,'oversized');
const ev=O.harObject({log:{entries:Array.from({length:O.MAX_HAR_ENTRIES+2},()=>({request:{url:'https://x.test/a.js'},response:{content:{mimeType:'application/javascript',text:'abc'}}}))}});
assert.equal(ev.at(-1).status,'capacity');assert.equal(O.summarize(ev).total,O.MAX_HAR_ENTRIES+2);
console.log('PASS v4.5 offline HAR, bounded base64 text, missing bodies, redaction, source lines, size/capacity');
