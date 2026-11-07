'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm'),crypto=require('node:crypto').webcrypto;
const db=new Map();let writes=0;
const store={get:async k=>({[k]:db.get(k)}),set:async obj=>{writes++;for(const [k,v]of Object.entries(obj))db.set(k,v);}};
function load(){const ctx=vm.createContext({crypto,URL,TextEncoder,console,Promise});ctx.globalThis=ctx;vm.runInContext(fs.readFileSync('secret_fingerprints.js','utf8'),ctx);return ctx.THISecretFingerprint;}
(async()=>{
 const one=load();const a=await one.fingerprint('ghp_abcdef01234567890123456789','GitHub token indicator','https://host.example/a.js',store,crypto);
 assert.match(a.fingerprint,/^[0-9a-f]{64}$/);assert.match(a.fingerprintKeyId,/^[0-9a-f]{16}$/);
 const same=await one.fingerprint('ghp_abcdef01234567890123456789','GitHub token indicator','https://host.example/b.js',store,crypto);
 assert.equal(a.fingerprint,same.fingerprint,'same value at same origin should match');
 const changed=await one.fingerprint('ghp_abcdef01234567890123456780','GitHub token indicator','https://host.example/a.js',store,crypto);
 assert.notEqual(a.fingerprint,changed.fingerprint,'different candidate must change digest');
 const otherHost=await one.fingerprint('ghp_abcdef01234567890123456789','GitHub token indicator','https://another.example/a.js',store,crypto);
 assert.notEqual(a.fingerprint,otherHost.fingerprint,'fingerprints are site scoped');
 const reloaded=await load().fingerprint('ghp_abcdef01234567890123456789','GitHub token indicator','https://host.example/a.js',store,crypto);
 assert.equal(reloaded.fingerprint,a.fingerprint,'same key across reloads');
 assert.equal(writes,1);
 assert(!JSON.stringify(a).includes('abcdef'));
 assert.equal((await one.fingerprint('short','GitHub token indicator','https://host.example',store,crypto)),null);
 console.log('PASS v4.6: non-exported per-install key, site-scoped HMAC, rotation/change and memory-only raw value');
})().catch(e=>{console.error(e);process.exitCode=1});
