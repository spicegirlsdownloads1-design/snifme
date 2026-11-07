/* Trufflehog v5.3 - AWS-hosted DAM ingestion/workflow OBSERVATION ONLY.
 * No policy/base64 decoding, object keys, bucket identifiers, signature bytes,
 * upload contents, JWTs, AWS credential scopes or execution ARNs are retained.
 * Field names are interpreted without values, and no requests are generated.
 */
'use strict';
const THIAwsDam = (() => {
  const knownFields = {
    'policy':'S3 POST policy field', 'x-amz-algorithm':'SigV4 algorithm field',
    'x-amz-credential':'AWS credential-scope field', 'x-amz-date':'AWS signing date field',
    'x-amz-signature':'AWS signature field','x-amz-security-token':'Temporary session-token field',
    'key':'S3 object-key field', 'acl':'Access-policy field',
    'success_action_status':'Upload response-code field',
    'content-length-range':'Size-range condition field',
    'content-type':'Content-Type field',
    'upload_preset':'Upload-preset field', 'asset_id':'Asset-reference field',
    'resource_type':'Resource-type field'
  };
  const labels=Object.values(knownFields);
  function hostClass(url){
    let u;try{u=new URL(url)}catch{return 'unclassified'}
    if(!['http:','https:'].includes(u.protocol))return 'unclassified';
    const host=u.hostname.toLowerCase();
    if(/^(?:[a-z0-9-]+\.)*execute-api\.[a-z0-9-]+\.amazonaws\.com(?:\.cn)?$/.test(host))return 'API Gateway hostname';
    if(/^s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com(?:\.cn)?$/.test(host) || /^.+\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com(?:\.cn)?$/.test(host))return 'S3 endpoint hostname';
    if(/\.cloudfront\.net$/.test(host))return 'CloudFront hostname';
    return 'unclassified';
  }
  function formFacts(requestBody){
    const obj=requestBody?.formData;
    if(!obj||typeof obj!=='object'||Array.isArray(obj))return {fieldTypes:[],postSignature:'not observed',constraints:'not inspected'};
    const names=new Set(Object.keys(obj).slice(0,100).map(s=>String(s).toLowerCase()));
    const fieldTypes=Object.entries(knownFields).filter(([key])=>names.has(key)).map(([,label])=>label).slice(0,18);
    const sig=names.has('x-amz-signature'),policy=names.has('policy'),credential=names.has('x-amz-credential');
    const postSignature=(sig&&policy&&credential)?'S3 presigned POST field structure':
      (sig||policy||credential)?'AWS-related form field indicators':'not observed';
    return {fieldTypes,postSignature,constraints:'not inspected'}; // NEVER decode policy.
  }
  const cleanMethod=s=>['POST','PUT','GET','PATCH','DELETE','HEAD'].includes(String(s||'').toUpperCase())?String(s).toUpperCase():'OTHER';
  function classify(stage,detail){
    if(!detail?.url)return null;
    let u;try{u=new URL(detail.url)}catch{return null}
    if(!['http:','https:'].includes(u.protocol))return null;
    const service=hostClass(detail.url),method=cleanMethod(detail.method),form=formFacts(detail.requestBody);
    const path=u.pathname.toLowerCase(); // Only used locally for category matching, never retained.
    const assetAction=/(?:^|\/)(?:assets?|ingest|upload|jobs?|analysis|search|workflow|process)(?:\/|$)/.test(path);
    const keyNames=new Set([...u.searchParams.keys()].map(x=>x.toLowerCase()));
    const signedQuery=[...keyNames].some(x=>['x-amz-signature','x-amz-algorithm','x-amz-credential','x-amz-expires','x-amz-security-token'].includes(x));
    const eligibility= service!=='unclassified'||form.postSignature!=='not observed';
    if(!eligibility)return null;
    let operation='AWS-related observation';
    if(method==='POST'&&form.postSignature==='S3 presigned POST field structure'){
      operation=service==='S3 endpoint hostname'?'S3 presigned POST request observed':'Presigned POST field pattern; service unverified';
    }else if(service==='S3 endpoint hostname'&&['POST','PUT'].includes(method))operation='S3 upload request observed';
    else if(service==='S3 endpoint hostname')operation='S3 request observed';
    else if(service==='API Gateway hostname'&&assetAction)operation='Asset/workflow API request observed';
    else if(service==='API Gateway hostname')operation='API Gateway request observed';
    else if(service==='CloudFront hostname')operation='CloudFront delivery request observed';
    // Everything stored is fixed enum text/booleans/HTTP status, never form values.
    return {service,operation,postSignature:form.postSignature,fieldTypes:form.fieldTypes,
      signedQueryPresent:signedQuery,method,
      status:Number.isInteger(detail.statusCode)&&detail.statusCode>=100&&detail.statusCode<=599?detail.statusCode:null,
      evidence:service!=='unclassified'?'Observed AWS service hostname':'Recognised form field names; provider unverified',
      policyContents:'not inspected'};
  }
  const schemaNames={
    executionarn:'Workflow execution reference field', overallstatus:'Workflow status field',
    schemaversion:'Catalogue schema-version field', aimlresults:'AI analysis result container',
    custommetadata:'Custom metadata object', dataclassification:'Data classification field',
    rekognition:'Recognition analysis reference', transcribe:'Transcription analysis reference',
    nexttoken:'Pagination continuation field', input:'Ingestion input object'
  };
  function responseHints(response){
    const seen=new Set();
    for(const f of (Array.isArray(response?.fields)?response.fields:[])){
      const path=String(f?.path||'').toLowerCase().split('.');
      for(const term of path){const normalized=term.replace(/\[\]$/,'');if(schemaNames[normalized])seen.add(schemaNames[normalized]);}
    }
    return [...seen].slice(0,12);
  }
  function rows(record){
    const grouped=new Map();
    const validKind=new Set(['S3 presigned POST request observed','Presigned POST field pattern; service unverified',
      'S3 upload request observed','S3 request observed','Asset/workflow API request observed',
      'API Gateway request observed','CloudFront delivery request observed','AWS-related observation']);
    const validService=new Set(['API Gateway hostname','S3 endpoint hostname','CloudFront hostname','unclassified']);
    const validSignature=new Set(['S3 presigned POST field structure','AWS-related form field indicators','not observed']);
    const safeHost=x=>typeof x==='string'&&x.length<=253&&/^[a-z0-9.-]+$/.test(x)&&!x.includes('..')?x:'';
    const safeDate=x=>typeof x==='string'&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(x)?x.slice(0,24):'';
    const safeStatus=x=>Number.isInteger(x)&&x>=100&&x<=599?x:null;
    for(const ev of (record?.downloadEvents||[])){
      const a=ev?.awsDam;if(!a||!validKind.has(a.operation)||!validService.has(a.service)||!ev.requestId)continue;
      const k=ev.requestId;
      if(!grouped.has(k))grouped.set(k,{at:safeDate(ev.at),host:safeHost(ev.host),method:cleanMethod(a.method),
        kind:a.operation,service:a.service,signing:validSignature.has(a.postSignature)?a.postSignature:'not observed',fields:[],signedQuery:a.signedQueryPresent===true,
        status:null,evidence:a.service!=='unclassified'?'Observed AWS service hostname':'Recognised form field names; provider unverified',policy:'Not decoded; no payload values stored'});
      const r=grouped.get(k);
      if(a.operation==='S3 presigned POST request observed'||a.operation==='Presigned POST field pattern; service unverified')r.kind=a.operation;
      if(validSignature.has(a.postSignature)&&a.postSignature!=='not observed')r.signing=a.postSignature;
      r.fields=[...new Set([...r.fields,...(a.fieldTypes||[]).filter(x=>labels.includes(x))])];
      r.signedQuery||=a.signedQueryPresent===true;
      if(safeStatus(a.status))r.status=a.status;
    }
    const output=[...grouped.values()].map(row=>({...row,fields:row.fields.join('; ')}));
    for(const res of (record?.responses||[])){
      const fields=responseHints(res);if(!fields.length)continue;
      // This is only a previously inspected JSON field-name shape, not a backend execution.
      output.push({at:safeDate(res.at),host:safeHost(res.host),method:cleanMethod(res.method),kind:'AWS-compatible JSON schema clues',
        service:hostClass(res.url||''),signing:'not observed',fields:fields.join('; '),signedQuery:false,
        status:safeStatus(res.status),evidence:'Observed JSON field-name structure; vendor unverified',
        policy:'No response values stored'});
    }
    return output.sort((a,b)=>String(b.at).localeCompare(String(a.at))).slice(0,500);
  }
  return {hostClass,formFacts,classify,responseHints,rows};
})();
if(typeof globalThis!=='undefined')globalThis.THIAwsDam=THIAwsDam;
if(typeof module!=='undefined'&&module.exports)module.exports=THIAwsDam;
