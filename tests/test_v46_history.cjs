'use strict';
const a=require('node:assert/strict'),h=require('../exposure_history.js');
const origin='https://gallery.example',fp='abc';
const record={origin,sessionId:'a',findings:[{type:'GitHub token indicator',source:'https://cdn.example/a.js',masked:'ghp_…[redacted]',line:1,column:2,changeState:'changed',reviewStatus:'resolved',reviewHistory:[{from:'new',to:'resolved',at:'2026-10-24T10:10:00Z'}],at:'2026-10-24T10:00:00Z',fingerprint:fp,fingerprintKeyId:'keyid'}]};
const result=h.history([record,{...record,origin:'https://another.example'}],origin);
a.equal(result.rows.length,1);a.equal(result.counts.changed,1);a.equal(result.rows[0].reviewEvents,1);
a(!JSON.stringify(result).includes('keyid'));a(!JSON.stringify(result).includes('"fingerprint"'));
a.equal(h.history([{...record,imported:true}],origin).rows[0].changeState,'unverified');
console.log('PASS v4.6: local history, imported evidence uncertainty and masked export fields');
