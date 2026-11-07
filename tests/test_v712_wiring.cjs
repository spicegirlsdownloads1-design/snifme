'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs');
const html=fs.readFileSync('dashboard.html','utf8'),js=fs.readFileSync('dashboard.js','utf8'),source=fs.readFileSync('generic_relationship_confidence.js','utf8'),manifest=require('../manifest.json');
assert.equal(manifest.version,'7.19.0');
assert.deepEqual(manifest.permissions,['storage','tabs','scripting','webRequest','downloads','notifications']);
assert(html.includes('data-view="generic-relationships"'));
assert(html.includes('src="generic_relationship_confidence.js"'));
assert(html.indexOf('src="generic_relationship_confidence.js"')<html.indexOf('src="dashboard.js"'));
for(const part of ['THIGenericRelationshipConfidence.analyze(record)','renderGenericRelationships(container)','trufflehog-generic-relationships.json','trufflehog-generic-relationships.csv',"case 'generic-relationships'"])
 assert(js.includes(part),part);
assert(!/\b(?:fetch|XMLHttpRequest|sendBeacon)\s*\(/.test(source),'passive module');
assert(!source.includes('chrome.'),'no browser privileged calls');
assert(!source.includes('Cloudinary')&&!source.includes('Directus'),'no service-specific identification');
console.log('PASS v7.12 relationship report UI, no new permissions and no active requests');
