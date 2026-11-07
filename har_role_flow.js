/* Trufflehog v7.3 - fixed-label service-role and nearby-stage analysis of an offline HAR.
 * Values, paths, hosts and identities are never retained. Neighbouring HAR entries
 * are NOT evidence of a causal request chain or a common asset.
 */
(function(root){'use strict';
const SEQ=root.THIHARSequence||(typeof module==='object'&&module.exports?require('./har_sequence.js'):null);
const ROLES=Object.freeze(['DAM vendor service','API gateway','Object storage','CDN delivery','Other/unknown service']);
const STAGES=Object.freeze(['Upload / resumable transfer clue','Export preparation request clue','Export status request clue','Attachment delivery response','HTTP redirect response','Access denied response','Partial-content response','Media response','Structured API response']);
const PAIRS=Object.freeze(['DAM/API to CDN','DAM/API to storage','Storage to CDN','CDN to storage','Same role class','Other cross-role adjacency']);
function role(provider){
 if(['Capture service','ResourceSpace service','PhotoShelter service','Bynder service','Cloudinary service','Canto service','FotoWare service'].includes(provider))return ROLES[0];
 if(provider==='AWS API gateway')return ROLES[1];
 if(['S3 storage','Google Cloud Storage','Azure Blob'].includes(provider))return ROLES[2];
 if(provider==='CloudFront CDN')return ROLES[3];
 return ROLES[4];
}
function pair(a,b){
 if(a===b)return PAIRS[4];
 if([ROLES[0],ROLES[1]].includes(a)&&b===ROLES[3])return PAIRS[0];
 if([ROLES[0],ROLES[1]].includes(a)&&b===ROLES[2])return PAIRS[1];
 if(a===ROLES[2]&&b===ROLES[3])return PAIRS[2];
 if(a===ROLES[3]&&b===ROLES[2])return PAIRS[3];
 return PAIRS[5];
}
function audit(har){
 if(!SEQ||typeof SEQ.stageSignal!=='function')throw Error('Stage classifier unavailable');
 const entries=har?.log?.entries;if(!Array.isArray(entries))throw Error('HAR must contain log.entries');
 if(entries.length>12000)throw Error('HAR exceeds the 12,000-entry limit');
 const roleTotals=new Map(ROLES.map(x=>[x,0]));
 const matrix=new Map(ROLES.flatMap(r=>STAGES.map(s=>[r+'|'+s,0])));
 const adjacent=new Map(PAIRS.map(x=>[x,0]));
 let valid=0,seen=0,nearPairs=0,distant=0;let last=null;
 for(let i=0;i<entries.length;i++){
  const signal=SEQ.stageSignal(entries[i]);if(!signal)continue;
  // Allow only fixed categories from our own classifier (never source-provided strings).
  if(!STAGES.includes(signal.stage))continue;
  const r=role(signal.provider);seen++;valid++;
  roleTotals.set(r,roleTotals.get(r)+1);
  matrix.set(r+'|'+signal.stage,matrix.get(r+'|'+signal.stage)+1);
  if(last){
   if(i-last.index<=5){const p=pair(last.role,r);adjacent.set(p,adjacent.get(p)+1);nearPairs++;}
   else distant++;
  }
  last={role:r,index:i};
 }
 const labelOnlyRows=ROLES.map(category=>({category,count:roleTotals.get(category)}));
 const stageRows=ROLES.flatMap(service=>STAGES.map(stage=>({service,stage,count:matrix.get(service+'|'+stage)})));
 const nearbyRows=PAIRS.map(category=>({category,count:adjacent.get(category)}));
 return Object.freeze({format:'trufflehog-har-role-flow',version:1,
  coverage:{harEntries:entries.length,classifiedStages:seen,adjacentPairs:nearPairs,notNearbyPairs:distant},
  roleRows:labelOnlyRows,stageRows,nearbyRows,
  limitations:[
   'Role labels are broad hostname-pattern heuristics; custom domains and privately hosted platforms usually appear as Other/unknown.',
   'Nearby means consecutive classified stage observations no more than five HAR entries apart; entries need not share an asset, browser tab, account, or causal relation.',
   'HAR order is not necessarily network chronology. No redirect, workflow or authenticated download is established by these counts.',
   'All eligible HAR entries contribute to fixed category counts (maximum 12,000). No raw hosts, URLs, identifiers, times, headers or credentials are retained.',
   'Provider classification is an observation of delivery domains, not proof of common DAM ownership or privilege.']});
}
const API=Object.freeze({audit});root.THIHARRoleFlow=API;
if(typeof module==='object'&&module.exports)module.exports=API;
})(typeof self!=='undefined'?self:globalThis);
