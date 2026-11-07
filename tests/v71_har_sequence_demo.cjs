'use strict';
const fs=require('node:fs'),path=require('node:path');
const har=JSON.parse(fs.readFileSync(path.join(__dirname,'v71-stage-timeline.har'),'utf8'));
const result=require('../har_sequence.js').audit(har);
const secret='DUMMY_SECRET_NOT_A_REAL_CREDENTIAL';
if(JSON.stringify(result).includes(secret))throw Error('Private fixture text leaked');
console.log(JSON.stringify(result,null,2));
