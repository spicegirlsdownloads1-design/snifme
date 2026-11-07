'use strict';
const fs=require('node:fs'),path=require('node:path');
const V=require('../har_access_matrix.js'),P=require('../har_privacy.js');
const load=x=>JSON.parse(fs.readFileSync(path.join(__dirname,'v75-access-'+x+'.har'),'utf8'));
const a=load('baseline'),b=load('comparison');
P.audit(a);P.audit(b);
const comparison=V.compare(a,b,{sameSite:'yes',sameActions:'yes',sameAccount:'yes',sameScope:'yes',sameBrowserCoverage:'yes'});
if(comparison.readiness!=='Context declared comparable')throw Error('Fixture should pass context/sample gate');
const nonzero=comparison.authOutcomes.filter(x=>x.baseline||x.comparison);
console.log(JSON.stringify({format:comparison.format,readiness:comparison.readiness,coverage:comparison.coverage,
 illustrativeChanges:nonzero.slice(0,12),privacy:'Fixed labels and aggregate numbers only. Not vulnerability evidence.'},null,2));
