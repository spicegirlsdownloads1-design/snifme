'use strict';
const fs=require('node:fs'),assert=require('node:assert/strict');
const m=require('../manifest.json'),html=fs.readFileSync('dashboard.html','utf8'),js=fs.readFileSync('dashboard.js','utf8');
assert.equal(m.version,'7.19.0');
assert(!m.permissions.includes('debugger'),'no debugger permission');
assert.deepEqual(m.permissions,['storage','tabs','scripting','webRequest','downloads','notifications']);
assert(html.includes('data-view="generic-intelligence"'));
assert(html.includes('<option value="generic">Universal Research</option>'));
assert(js.includes("preferredProfile||'generic'"));
assert(html.indexOf('src="generic_intelligence.js"')<html.indexOf('src="dashboard.js"'));
for(const clue of ['THIGenericIntelligence.analyze(record)','renderGenericIntelligence(container)',
 'Export generic report (redacted JSON)','Export generic report CSV','\\uFEFF'])assert(js.includes(clue),clue);
assert(!fs.readFileSync('generic_intelligence.js','utf8').includes('fetch('));
console.log('PASS v7.10 generic-only dashboard view, fixed redacted exports and no new permissions');
