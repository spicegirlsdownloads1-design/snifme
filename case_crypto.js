/* v5.8: optional local AES-256-GCM passphrase envelope for case dossiers only.
 * PBKDF2 cost is intentionally substantial; no passphrase storage, no network. */
(function(root){'use strict';
const ROUNDS=250000;
const b64=bytes=>{let s='';for(const b of bytes)s+=String.fromCharCode(b);return btoa(s);};
const un64=s=>{if(typeof s!=='string'||s.length>4000000||!/^[A-Za-z0-9+/]*={0,2}$/.test(s))throw Error('Invalid encoded content');return Uint8Array.from(atob(s),x=>x.charCodeAt(0));};
async function key(pass,salt,usage){const passbytes=new TextEncoder().encode(pass);const base=await root.crypto.subtle.importKey('raw',passbytes,'PBKDF2',false,['deriveKey']);return root.crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:ROUNDS,hash:'SHA-256'},base,{name:'AES-GCM',length:256},false,usage);}
function password(p){if(typeof p!=='string'||p.length<12||p.length>256)throw Error('Use a passphrase of 12–256 characters');}
async function seal(item,pass){password(pass);if(!root.crypto?.subtle||!root.crypto?.getRandomValues)throw Error('WebCrypto unavailable');
 if(typeof item!=='object'||item?.format!=='trufflehog-case-file')throw Error('Expected verified case file');
 const data=new TextEncoder().encode(JSON.stringify(item));if(data.length>2000000)throw Error('Case file exceeds 2 MB');
 const salt=root.crypto.getRandomValues(new Uint8Array(16)),iv=root.crypto.getRandomValues(new Uint8Array(12));
 const ciphertext=new Uint8Array(await root.crypto.subtle.encrypt({name:'AES-GCM',iv},await key(pass,salt,['encrypt']),data));
 return {format:'trufflehog-encrypted-case',version:1,kdf:'PBKDF2-SHA256',iterations:ROUNDS,cipher:'AES-256-GCM',salt:b64(salt),iv:b64(iv),ciphertext:b64(ciphertext),notice:'Encrypted case dossier, not an encrypted raw Evidence Vault backup.'};
}
async function open(item,pass){password(pass);if(item?.format!=='trufflehog-encrypted-case'||item.version!==1||item.kdf!=='PBKDF2-SHA256'||item.iterations!==ROUNDS||item.cipher!=='AES-256-GCM')throw Error('Unsupported encrypted case file');
 const salt=un64(item.salt),iv=un64(item.iv),ciphertext=un64(item.ciphertext);
 if(salt.length!==16||iv.length!==12||ciphertext.length<17||ciphertext.length>2100000)throw Error('Invalid encrypted case fields');
 try{const decrypted=await root.crypto.subtle.decrypt({name:'AES-GCM',iv},await key(pass,salt,['decrypt']),ciphertext);return JSON.parse(new TextDecoder().decode(decrypted));}
 catch{throw Error('Incorrect passphrase or damaged encrypted case file');}
}
root.THICaseCrypto={seal,open};if(typeof module!=='undefined'&&module.exports)module.exports=root.THICaseCrypto;
})(typeof self!=='undefined'?self:globalThis);
