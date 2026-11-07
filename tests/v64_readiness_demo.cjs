'use strict';
require('../dam_policy_compare.js');
const M=require('../comparison_readiness.js');
const make=(name,n)=>[{origin:'https://archive.example',captureGroupId:name,segmentIndex:0,endedAt:'2026-10-24T13:00:00Z',counters:{},requests:Array.from({length:n},(_,i)=>({type:i%2?'image':'fetch',status:200,mime:i%2?'image/jpeg':'application/json'}))}];
const out=M.assess(make('baseline',48),make('comparison',53),{accessRole:'same',workflow:'same',assetScope:'same',hostPermissions:'same',devtoolsTiming:'both-early'});
console.log(JSON.stringify(out,null,2));
