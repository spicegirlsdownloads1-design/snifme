'use strict';
const assert=require('node:assert/strict'),C=require('../case_crypto.js');
(async()=>{
 const pw='a very long offline passphrase with spaces';
 const source={format:'trufflehog-case-file',version:1,sha256:'f'.repeat(64),report:{kind:'synthetic',count:1}};
 const encrypted=await C.seal(source,pw);
 assert.equal(encrypted.format,'trufflehog-encrypted-case');
 assert.equal(encrypted.iterations,250000);assert.equal(encrypted.cipher,'AES-256-GCM');
 assert(!JSON.stringify(encrypted).includes('synthetic'));assert(!JSON.stringify(encrypted).includes(pw));
 assert.deepEqual(await C.open(encrypted,pw),source);
 await assert.rejects(()=>C.open(encrypted,'wrong passphrase but sufficiently long'),/Incorrect passphrase/);
 await assert.rejects(()=>C.open({...encrypted,ciphertext:'!!!!!'},pw),/Invalid encoded content/);
 const modified={...encrypted,ciphertext:encrypted.ciphertext[0]==='A'?'B'+encrypted.ciphertext.slice(1):'A'+encrypted.ciphertext.slice(1)};
 await assert.rejects(()=>C.open(modified,pw),/Incorrect passphrase/);
 await assert.rejects(()=>C.seal(source,'1234'),/12/);
 console.log('PASS v5.8 encrypted case: authenticated encryption, passphrase, integrity tamper, strict input bounds');
})().catch(e=>{console.error(e);process.exitCode=1});
