'use strict';
const fs=require('node:fs'),path=require('node:path');
const P=require('../har_privacy.js'),B=require('../har_redirect_boundaries.js');
const read=s=>JSON.parse(fs.readFileSync(path.join(__dirname,'v76-redirect-'+s+'.har'),'utf8'));
const before=read('baseline'),after=read('comparison');
P.audit(before);P.audit(after);
const context={sameSite:'yes',sameActions:'yes',sameAccount:'yes',sameScope:'yes',sameBrowserCoverage:'yes'};
const result=B.compare(before,after,context);
if(result.readiness!=='Context declared comparable')throw Error('Expected comparison fixture to be context-declared comparable');
console.log(JSON.stringify({format:result.format,readiness:result.readiness,coverage:result.coverage,
 differences:result.indicators.filter(x=>x.baseline!==x.comparison),privacy:'Counts and fixed labels only. Synthetic data.'},null,2));
