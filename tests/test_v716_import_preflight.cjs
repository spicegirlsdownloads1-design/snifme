'use strict';const a=require('node:assert/strict'),fs=require('node:fs');const moduleUnderTest=require('../import_privacy_preflight.js');
const sample='curl https://example.invalid/login -H "Cookie: PHPSESSID=TOP_SECRET" -H "Authorization: Bearer ABCDEFGHIJK123456" --data-raw "password=not-to-be-published&email=test@example.invalid"';
const result=moduleUnderTest.inspect(sample);
a(result.ok);a(result.foundCategories>=4);a(result.rows.some(x=>x.category==='Password-like assignments'));a(result.rows.some(x=>x.category==='Authentication headers'));a(result.rows.some(x=>x.category==='Cookies / sessions'));a(!JSON.stringify(result).includes('TOP_SECRET'));a(!JSON.stringify(result).includes('not-to-be-published'));a(!JSON.stringify(result).includes('ABCDEFG'));
a.equal(moduleUnderTest.inspect('hello world').foundCategories,0);a.equal(moduleUnderTest.inspect('x'.repeat(12*1024*1024+1)).ok,false);a.equal(moduleUnderTest.inspect(null).ok,false);
const html=fs.readFileSync('dashboard.html','utf8'),js=fs.readFileSync('dashboard.js','utf8');a(html.includes('data-view="import-preflight"'));a(html.includes('import_privacy_preflight.js'));a(js.includes('renderImportPreflight(container)'));
console.log('PASS v7.16 local-only sensitive-data warnings, no raw evidence persisted or emitted, file cap and dashboard wiring');
