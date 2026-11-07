'use strict';
const fs=require('node:fs'),path=require('node:path');
const DP=require('../har_delivery_posture.js');
const p=path.join(__dirname,'v74-delivery-baseline.har'),q=path.join(__dirname,'v74-delivery-comparison.har');
const baseline=JSON.parse(fs.readFileSync(p,'utf8')),comparison=JSON.parse(fs.readFileSync(q,'utf8'));
const report=DP.compare(baseline,comparison);
console.log(JSON.stringify({format:report.format,coverage:report.coverage,
 selectedIndicators:report.rows.filter(x=>x.baseline||x.comparison).slice(0,24),
 reviewCandidates:report.reviewCandidates,warnings:report.warnings.slice(0,2)},null,2));
