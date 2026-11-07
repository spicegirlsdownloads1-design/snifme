'use strict';
const fs=require('node:fs'),path=require('node:path');
require('../dam_specialists.js');
const review=require('../dam_review_matrix.js');
const sample=JSON.parse(fs.readFileSync(path.join(__dirname,'v62-dam-review-demo.json'),'utf8'));
const x=review.evaluate(sample,{profiles:[{id:'capture',confidence:'Strong indication'}]});
const output=JSON.stringify(x,null,2);
if(output.includes('SYNTHETIC_NO_REAL_TOKEN')||output.includes('gallery.example.test'))throw Error('Sensitive fixture fields leaked');
process.stdout.write(output+'\n');
