'use strict';
const X=require('../workflow_pattern.js');
const make=(id,t)=>[{origin:'http://localhost:8767',captureGroupId:id,endedAt:'2026-10-24T12:00:00Z',requests:Array.from({length:160},(_,i)=>({type:t==='images'?(i%4?'image':'fetch'):(i%4?'fetch':'image'),method:i%15?'GET':'POST',mime:t==='images'?'image/jpeg':'application/json',status:200,at:new Date(Date.UTC(2026,9,24,12,0,i)).toISOString()}))}];
const report=X.compare(make('first','images'),make('second','api'));
console.log(JSON.stringify(report,null,2));
