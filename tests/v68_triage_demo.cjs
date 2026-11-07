'use strict';
require('../scanner.js');
const h=require('../har_coverage.js'),t=require('../har_triage.js');
const base='http://127.0.0.1:8770',at='2026-10-24T12:00:10Z';
const entry=(suffix,method,status,mime)=>({startedDateTime:at,request:{url:base+suffix,method},response:{status,content:{mimeType:mime}}});
const har={log:{entries:[entry('/v60-lab.html','GET',200,'text/html'),entry('/v60-lab.js','GET',200,'text/javascript'),entry('/v60-lab.json','GET',200,'application/json'),entry('/v60-job','POST',202,'application/json')]}};
const captures=[{origin:base,captureGroupId:'synthetic',segmentIndex:0,endedAt:'2026-10-24T12:00:11Z',requests:[
{url:base+'/v60-lab.html',method:'GET',status:200,type:'main_frame',at},
{url:base+'/v60-lab.json',method:'GET',status:200,type:'xmlhttprequest',at}
],counters:{requestsDropped:0}}];
const result=h.reconcile(har,captures);
const triage=t.assess(result,{sameSession:'yes',sameActions:'yes',devtoolsBeforeNavigation:'yes',preserveLog:'yes',comparableSiteAccess:'yes'});
console.log(JSON.stringify(triage,null,2));
