 'use strict';
require('../scanner.js');const X=require('../har_coverage.js');
const url='http://127.0.0.1:8770/v60-lab.js';
const har={log:{entries:[{request:{url,method:'GET'},response:{status:200,content:{mimeType:'application/javascript'}}}]}};
const rec=[{origin:'http://127.0.0.1:8770',captureGroupId:'demo',segmentIndex:0,endedAt:'2026-10-24',requests:[{url,method:'GET',status:200,type:'script',mime:'text/javascript'}]}];
console.log(JSON.stringify(X.reconcile(har,rec),null,2));
