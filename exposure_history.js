/* v4.6: historical masked-alert timeline from saved evidence; no requests. */
(function(root){'use strict';
 const STATES=new Set(['new','changed','unchanged','unverified']);
 function history(records,origin){
   const entries=[];
   for(const rec of (Array.isArray(records)?records:[])){
     if(!rec||rec.origin!==origin)continue;
     for(const f of (Array.isArray(rec.findings)?rec.findings:[])){
       if(!f||typeof f.type!=='string'||typeof f.source!=='string'||!String(f.masked||'').includes('[redacted]'))continue;
       entries.push({at:typeof f.at==='string'?f.at:rec.createdAt||'',
         type:f.type.slice(0,80),source:f.source.slice(0,400),line:Number(f.line)||null,
         column:Number(f.column)||null,changeState:rec.imported?'unverified':STATES.has(f.changeState)?f.changeState:'unverified',
         reviewStatus:String(f.reviewStatus||'new').slice(0,30),
         reviewEvents:(Array.isArray(f.reviewHistory)?f.reviewHistory:[]).length,
         sessionId:String(rec.sessionId||'').slice(0,90),segmentIndex:rec.segmentIndex||1});
     }
   }
   entries.sort((a,b)=>b.at.localeCompare(a.at));
   const rows=entries.slice(0,500);
   return {rows,counts:{total:entries.length,new:entries.filter(x=>x.changeState==='new').length,
     changed:entries.filter(x=>x.changeState==='changed').length,
     unverified:entries.filter(x=>x.changeState==='unverified').length,shown:rows.length},
     assessment:'Only recorded indicators from saved sessions. Unobserved or incomplete captures do not establish credential removal. Different local fingerprint keys cannot establish changes. Indicators have not been validated.'};
 }
 root.THIExposure={history};
 if(typeof module!=='undefined'&&module.exports)module.exports=root.THIExposure;
})(typeof self!=='undefined'?self:globalThis);
