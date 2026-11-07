/* Public application metadata extraction. No credential values or payloads are returned. */
(function (root) {
  'use strict';
  const SAFE_WORD = /^[A-Za-z_][A-Za-z0-9_]{1,63}$/;
  const BAD_WORD = /(?:token|secret|password|credential|authorization|cookie|session|private|bearer|passwd|accesskey|apikey|clientsecret|jwt)/i;
  const CONFIG_PREFIX = /\b(?:VITE_|NEXT_PUBLIC_|PUBLIC_|NUXT_PUBLIC_|REACT_APP_)[A-Z][A-Z0-9_]{2,64}\b/g;
  const FRAMEWORKS = [
    ['Next.js', /__NEXT_DATA__|\/_next\/static\//],
    ['Nuxt', /__NUXT__|\/_nuxt\//],
    ['Vite', /import\.meta\.env|\bVITE_[A-Z]/],
    ['React', /ReactDOM\.createRoot|react-dom|__REACT_DEVTOOLS_GLOBAL_HOOK__/],
    ['Vue', /__VUE__|createApp\(|vue\.runtime/],
    ['Webpack', /__webpack_require__|webpackChunk/],
    ['Apollo GraphQL', /ApolloClient|@apollo\/client/],
    ['urql GraphQL', /\burql\b|@urql\//]
  ];
  function inspectStatic(value, source, base) {
    const text = String(value || '').slice(0, 850000);
    const configs = [], operations = [], maps = [];
    const frameworks = FRAMEWORKS.filter(([,re]) => re.test(text)).map(([name]) => name);
    const configSeen = new Set();
    CONFIG_PREFIX.lastIndex=0;
    let match, count=0;
    while ((match=CONFIG_PREFIX.exec(text)) && count++<200) {
      const key=match[0];
      if(BAD_WORD.test(key)||configSeen.has(key))continue;
      configSeen.add(key);
      configs.push({key, framework: key.startsWith('NEXT_')?'Next.js':key.startsWith('VITE_')?'Vite':key.startsWith('NUXT_')?'Nuxt':key.startsWith('REACT_')?'React':'Public config', source});
      if(configs.length>=30)break;
    }
    // GraphQL named operations only; no variables, arguments or full queries.
    const OP = /\b(query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]{1,63})(?=\s*(?:\(|\{|@))/g;
    const seenOps = new Set();count=0;
    while((match=OP.exec(text)) && count++<150) {
      const type=match[1],name=match[2];
      if(!SAFE_WORD.test(name)||BAD_WORD.test(name)||seenOps.has(type+'|'+name))continue;
      seenOps.add(type+'|'+name);
      operations.push({name,operationType:type,source,confidence:'static-GraphQL-clue'});
      if(operations.length>=35)break;
    }
    const RE = /(?:\/\/[#@]\s*sourceMappingURL\s*=\s*|\/\*#\s*sourceMappingURL\s*=\s*)([^\s*]+)(?:\s*\*\/)?/g;
    count=0;
    while ((match=RE.exec(text))&&count++<20) {
      const raw=match[1].trim();
      if(!raw || /^data:/i.test(raw) || raw.length>350 || /[\s<>"'`]/.test(raw))continue;
      let resolved;
      try {
        const parent=new URL(base);
        resolved=new URL(raw,parent);
        if(!/^https?:$/.test(resolved.protocol)||resolved.origin!==parent.origin)continue;
      }catch{continue;}
      const info=root.THI?.urlInfo(resolved.href);
      if(!info||info.signedQuery||!info.url.endsWith('.map'))continue;
      maps.push({url:info.url,source,script:root.THI.sanitizedUrl(base),status:'reference-only'});
      if(maps.length>=10)break;
    }
    return {maps,operations,configs,frameworks};
  }
  function sourceMapSummary(doc) {
    if(!doc || typeof doc!=='object'||doc.version!==3||!Array.isArray(doc.sources))return null;
    let ts=0,js=0,jsx=0,tsx=0,css=0,other=0;
    const packages=new Set();
    for(const item of doc.sources.slice(0,25000)) {
      if(typeof item!=='string')continue;
      const s=item.slice(0,350).replaceAll('\\','/');
      if(/\.tsx(?:\?|$)/i.test(s))tsx++;
      else if(/\.jsx(?:\?|$)/i.test(s))jsx++;
      else if(/\.ts(?:\?|$)/i.test(s))ts++;
      else if(/\.js(?:\?|$)/i.test(s))js++;
      else if(/\.css(?:\?|$)/i.test(s))css++;
      else other++;
      const packageName=s.match(/(?:^|\/)node_modules\/(?:@([a-z0-9._-]+)\/)?([a-z0-9._-]+)/i);
      if(packageName) {
        const name=packageName[1]?'@'+packageName[1]+'/'+packageName[2]:packageName[2];
        if(name.length<75&&!BAD_WORD.test(name))packages.add(name);
      }
    }
    return {sourceCount:doc.sources.length, sourceTypes:{ts,js,tsx,jsx,css,other},packageNames:[...packages].sort().slice(0,30),
      hasEmbeddedSources:Array.isArray(doc.sourcesContent)&&doc.sourcesContent.some(v=>typeof v==='string'&&v.length>0),
      mappedFileExtension:typeof doc.file==='string'?((doc.file.match(/\.(?:mjs|cjs|js|css)$/i)||[])[0]||'unknown'):'unknown'};
  }
  function safeOperationName(value) {return typeof value==='string'&&SAFE_WORD.test(value)&&!BAD_WORD.test(value)?value:'';}
  function graphqlRequestName(url) {
    try {const u=new URL(url);if(!/(?:graphql|gql)/i.test(u.pathname))return '';
      return safeOperationName(u.searchParams.get('operationName')||'');
    }catch{return '';}
  }
  root.THIApp={inspectStatic,sourceMapSummary,safeOperationName,graphqlRequestName};
})(globalThis);
