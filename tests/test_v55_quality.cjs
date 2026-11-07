'use strict';
const assert=require('node:assert/strict');
require('../image_intel.js');
const Q=require('../asset_quality.js');
const D=require('../download_observer.js');
const secret='NEVER_EXPORT_ACCESS_SECRET_xYz142';
const sha='a'.repeat(64),sha2='b'.repeat(64);
const base='https://cdn-one.test/public/image/photo007';
const record={
  assets:[
    {url:base+'-300x200.jpg?token='+secret,width:300,height:200,source:'DOM'},
    {url:base+'-1200x800.jpg?token='+secret,width:1200,height:800,source:'DOM'},
    {url:base+'-9000x7000.jpg?token='+secret,width:9000,height:7000,source:'DOM'},
    {url:'https://cdn-two.test/x/photo007-thumb.jpg?secret='+secret,width:300,height:200,source:'DOM'}],
  verifications:[
    {url:base+'-300x200.jpg?token='+secret,sha256:sha,byteLength:1000,width:300,height:200,format:'JPEG',mime:'image/jpeg'},
    {url:base+'-1200x800.jpg?token='+secret,sha256:sha2,byteLength:3500,width:1200,height:800,format:'JPEG',mime:'image/jpeg'},
    {url:'https://cdn-two.test/x/photo007-thumb.jpg?secret='+secret,sha256:sha,byteLength:1000,width:300,height:200,format:'JPEG',mime:'image/jpeg'}],
  downloadEvents:[
    {stage:'download-start',downloadStatus:'started',host:'cdn-one.test'},
    {stage:'download-state',downloadStatus:'complete',receivedBytes:999999,totalBytes:999999,fileType:'image/jpeg',filename:'C:\\secret\\'+secret+'.jpg'},
    {stage:'headers',rangeRequested:true},
    {stage:'response-headers',status:206,rangeStart:0,rangeEnd:1023,rangeTotalBytes:5000},
    {stage:'download-state',downloadStatus:'interrupted',errorCategory:'network',filename:secret}],
  counters:{verificationsDropped:0}
};
let a=Q.analyze(record);
assert.equal(a.families.length,2);
const primary=a.families.find(x=>x.host==='cdn-one.test');
assert.equal(primary.verifiedFiles,2);
assert.equal(primary.highestVerifiedPixels,'1200 × 800');
assert.equal(primary.biggestBrowserReported,'9000 × 7000');
assert.equal(primary.verifiedPixelRatio,16);
assert.equal(primary.largestVerifiedBytes,3500);
assert.equal(primary.strongestEvidence,'Encoded image dimensions verified from received bytes');
assert.equal(a.duplicates.length,1);
assert.equal(a.duplicates[0].distinctHosts,2);
assert.equal(a.transfers.complete,1);
assert.equal(a.transfers.interrupted,1);
assert.equal(a.transfers.partialResponses,1);
assert.equal(a.transfers.measuredRanges,1);
assert(!JSON.stringify(Q.exportReport(record)).includes(secret));
assert(!JSON.stringify(Q.exportReport(record)).includes('/public/image/'));
assert(!JSON.stringify(Q.exportReport(record)).includes('photo007'));
assert(!JSON.stringify(Q.exportReport(record)).includes('999999 ×'));
assert(!JSON.stringify(Q.exportReport(record)).includes('sha256'));
// A download does not provide a valid image/original-file correspondence.
assert(!('downloadRef' in primary));
// No verified pixel dimensions: don't claim 6000×4000 is the original.
const unverified=Q.analyze({assets:[{url:'https://cdn.test/x/a.png',width:6000,height:4000}]});
assert.equal(unverified.families[0].highestVerifiedPixels,'Not measured');
assert.equal(unverified.families[0].strongestEvidence,'Browser-reported dimensions only');
assert.equal(Q.analyze({}).families.length,0);
// A Range header is only observed; raw header value and key material are never retained.
const request={tabId:4,requestId:'1',url:'https://cdn.test/download?token='+secret,method:'GET',type:'main_frame',timeStamp:Date.now()};
const header=D.classify('headers',{...request,requestHeaders:[{name:'Range',value:'bytes=0-999&token='+secret}]},'test');
assert.equal(header.rangeRequested,true);
assert(!JSON.stringify(header).includes(secret));
const r=D.classify('response-headers',{...request,statusCode:206,responseHeaders:[{name:'Content-Range',value:'bytes 100-200/500'}, {name:'Accept-Ranges',value:'bytes'}, {name:'Content-Disposition',value:'attachment; filename='+secret}]},'test');
assert.equal(r.rangeStart,100);
assert.equal(r.rangeEnd,200);
assert.equal(r.rangeTotalBytes,500);
assert.equal(r.rangeSupported,true);
assert(!JSON.stringify(r).includes(secret));
const corrupt=D.classify('response-headers',{...request,statusCode:206,responseHeaders:[{name:'Content-Range',value:'bytes 400-600/500'}]},'test');
assert.equal(corrupt.rangeStart,undefined);
const dl=D.download('created',{id:12,referrer:'https://cdn.test/',url:'https://cdn.test/file?token='+secret,mime:'image/jpeg',filename:'C:/'+secret+'.jpg'});
assert.equal(dl.fileType,'image/jpeg');
assert(!JSON.stringify(dl).includes(secret));
// Malformed imported metadata must not escape in reports.
const malicious=Q.analyze({assets:[{url:'https://'+secret+'.test/a.png',width:2,height:2}],verifications:[]});
assert(!JSON.stringify(malicious).includes(secret));
console.log('PASS v5.5: verified-best, browser-only clues, exact hash duplicates, unlinked downloads, safe range parsing, sanitised exports');
