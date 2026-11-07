'use strict';
const fs=require('node:fs'),path=require('node:path');
const F=require('../har_stage_compare.js');
const file=path.join(__dirname,'v71-stage-timeline.har');
const baseline=JSON.parse(fs.readFileSync(file,'utf8'));
const comparison=structuredClone(baseline);
comparison.log.entries.push({startedDateTime:'2026-10-24T11:01:00.000Z',request:{url:'https://api.captureweb.net/job/status?auth=DUMMY',method:'GET',headers:[]},response:{status:200,headers:[],content:{mimeType:'application/json'}}});
const report=F.audit(baseline,comparison,{});
console.log(JSON.stringify(report,null,2));
