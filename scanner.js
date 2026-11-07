/* global self */
/* Shared, deliberately passive detection utilities; no credential validation. */
(function (root) {
  'use strict';
  const MAX_URL = 1500;
  const IMAGE_FORMAT = /\.(?:avif|bmp|gif|jpe?g|png|svg|webp|tiff?)(?:$|\?)/i;
  const TOKENISH = /^(?:eyJ[A-Za-z0-9_-]{25,}|gh[pousr]_[A-Za-z0-9_]{20,}|xox[bapors]-[\w-]{20,}|sk_live_[\w-]{15,}|rk_live_[\w-]{15,}|AKIA[A-Z0-9]{16}|AIza[A-Za-z0-9_-]{35}|[A-Za-z0-9_-]{110,})$/;
  const GOOD_PARAMS = new Set(['w', 'h', 'width', 'height', 'size', 's', 'q', 'quality', 'format', 'fm', 'fit', 'crop', 'auto', 'dpr', 'resize', 'page', 'p']);
  const SENSITIVE_PARAM = /(?:token|secret|key|pass|auth|signature|sig|session|credential|access|expires|jwt|policy)/i;

  function sanitizedUrl(value, base) {
    try {
      const u = new URL(value, base);
      if (u.protocol !== 'https:' && u.protocol !== 'http:') return '';
      let pathname = u.pathname.split('/').map(part => {
        const decode = (() => { try { return decodeURIComponent(part); } catch { return part; } })();
        return TOKENISH.test(decode) ? '[redacted]' : part.slice(0, 140);
      }).join('/');
      if (pathname.length > 600) pathname = pathname.slice(0, 600) + '…';
      const kept = new URLSearchParams();
      for (const [k, v] of u.searchParams.entries()) {
        // The short query key "q" is used for both JPEG quality and SEARCH TERMS.
        // Retain it only for numeric quality values. Page parameters also must
        // be numeric, preventing accidental capture of cursor-style values.
        const lower=k.toLowerCase();
        const guarded=lower==='q' ? /^\d{1,3}(?:\.\d{1,2})?$/.test(v) :
          ['p','page'].includes(lower) ? /^\d{1,7}$/.test(v) : true;
        if (GOOD_PARAMS.has(lower) && guarded && !SENSITIVE_PARAM.test(k) && v.length < 70 && !TOKENISH.test(v)) kept.append(k, v);
      }
      return (u.origin + pathname + (kept.size ? '?' + kept.toString() : '')).slice(0, MAX_URL);
    } catch { return ''; }
  }
  // Names are classified locally; query values and sensitive names never leave
  // this function. A parameter class is NOT evidence that a credential works.
  function authQueryClasses(keys) {
    const out = new Set();
    for(const key of keys){
      const k=String(key).toLowerCase().replace(/-/g,'_');
      if(['access_token','accesstoken','oauth_token'].includes(k))out.add('legacy-access-token-query');
      else if(['api_key','apikey','x_api_key','client_secret'].includes(k))out.add('api-credential-query');
      else if(['authorization','bearer','auth'].includes(k))out.add('auth-header-style-query');
      else if(['token','session_token'].includes(k))out.add('ambiguous-token-query');
      else if(['signature','sig','policy','expires','x_amz_signature','x_amz_credential','x_amz_expires','key_pair_id'].includes(k))out.add('signed-media-query');
    }
    return [...out];
  }
  // At capture time, classify a declared signing window while the incoming URL
  // is in memory. Never persist signing/query values, expiry timestamps, or IDs.
  function signingEvidence(value, base) {
    try {
      const u = new URL(value, base);
      if (!/^https?:$/.test(u.protocol)) return {signatureKeyPresent:false,signedValidityWindow:'unknown'};
      const keys = new Map([...u.searchParams].map(([key, val])=>[key.toLowerCase(), val]));
      const signatureKeyPresent = ['x-amz-signature','x-goog-signature','signature','sig','cloudfront-signature'].some(k=>keys.has(k));
      if (!signatureKeyPresent) return {signatureKeyPresent:false,signedValidityWindow:'unknown'};
      let numeric = null;
      // The X-Amz and X-Goog schemes use numeric durations in seconds.
      // Other schemes may use an epoch timestamp; never guess its units.
      if (keys.has('x-amz-signature') && keys.has('x-amz-expires')) numeric=keys.get('x-amz-expires');
      else if (keys.has('x-goog-signature') && keys.has('x-goog-expires')) numeric=keys.get('x-goog-expires');
      if (numeric === null) return {signatureKeyPresent:true,signedValidityWindow:'unknown'};
      if (!/^\d{1,9}$/.test(numeric)) return {signatureKeyPresent:true,signedValidityWindow:'invalid-declaration'};
      const seconds=Number(numeric);
      if (!Number.isSafeInteger(seconds)||seconds<1) return {signatureKeyPresent:true,signedValidityWindow:'invalid-declaration'};
      return {signatureKeyPresent:true,signedValidityWindow:seconds<=900?'up-to-15m':seconds<86400?'15m-to-24h':seconds<=604800?'24h-to-7d':'over-7d'};
    }catch{return {signatureKeyPresent:false,signedValidityWindow:'unknown'};}
  }
  function urlInfo(value, base) {
    try {
      const url = new URL(value, base);
      if (!/^https?:$/.test(url.protocol)) return null;
      return {
        url: sanitizedUrl(value, base),
        host: url.hostname.slice(0, 255),
        signedQuery: [...url.searchParams.keys()].some(k => SENSITIVE_PARAM.test(k)),
        image: IMAGE_FORMAT.test(url.pathname),
        authQueryClasses: authQueryClasses(url.searchParams.keys()),
        ...signingEvidence(value, base),
        queryKeys: [...new Set([...url.searchParams.keys()].map(k => SENSITIVE_PARAM.test(k) ? '[sensitive]' : k.slice(0, 40)))].slice(0, 15)
      };
    } catch { return null; }
  }
  function mask(value) {
    const s = String(value || '').slice(0, 1000);
    if (!s) return '[redacted]';
    // Deliberately never preserve a suffix of an apparent credential.
    return `${s.slice(0, Math.min(4, s.length))}…[redacted] (${s.length} chars)`;
  }
  const patterns = [
    ['AWS access-key identifier', /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, 'identifier, not proof of secret access'],
    ['GitHub token indicator', /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/g, 'possible private credential'],
    ['Slack token indicator', /\bxox[bapors]-[A-Za-z0-9-]{20,}\b/g, 'possible private credential'],
    ['Stripe secret-key indicator', /\b(?:sk|rk)_(?:test|live)_[A-Za-z0-9]{16,}\b/g, 'possible private credential'],
    ['Google API key indicator', /\bAIza[A-Za-z0-9_-]{35}\b/g, 'often a browser/public key; permissions determine exposure'],
    ['JWT-looking token', /\beyJ[A-Za-z0-9_-]{12,}\.eyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]*\b/g, 'format alone does not establish a vulnerability'],
    ['Twilio key indicator', /\bSK[0-9a-fA-F]{32}\b/g, 'format indicator only; may resemble unrelated identifiers'],
    ['SendGrid key indicator', /\bSG\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{20,}\b/g, 'possible private credential'],
    ['Mailgun key indicator', /\bkey-[0-9A-Za-z]{32}\b/g, 'possible private credential'],
    ['GitLab token indicator', /\bglpat-[A-Za-z0-9_-]{18,}\b/g, 'possible private credential'],
    ['Slack webhook indicator', /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9_\/-]{25,}/g, 'webhook URL may be sensitive'],
    ['Telegram bot-token indicator', /\b[0-9]{6,12}:AA[A-Za-z0-9_-]{33}\b/g, 'possible private credential'],
    ['Private key material', /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g, 'private-key header present']
  ];
  const namedAssignment = /\b(?:api[_-]?(?:secret|key)|client[_-]?secret|private[_-]?key|auth[_-]?token|secret[_-]?key)\b\s*[:=]\s*['"]([^'"\s]{16,180})['"]/gi;
  function secretIndicators(text, source, onRawIndicator) {
    const found = [], seen = new Set();
    const textToCheck = String(text || '').slice(0, 500000);
    for (const [label, pattern, note] of patterns) {
      pattern.lastIndex = 0;
      let match, count = 0;
      while ((match = pattern.exec(textToCheck)) && count++ < 30) {
        const marker = `${label}|${match.index}|${source}`;
        if (!seen.has(marker)) {
          seen.add(marker);
          if(typeof onRawIndicator==='function')onRawIndicator({type:label,value:match[0],offset:match.index});
          found.push({type: label, masked: mask(match[0]), note, source: String(source).slice(0, 400), offset: match.index});
        }
      }
    }
    namedAssignment.lastIndex = 0;
    let match, count = 0;
    while ((match = namedAssignment.exec(textToCheck)) && count++ < 30) {
      if (/^(?:undefined|placeholder|changeme|example|xxxxxxxx)/i.test(match[1])) continue;
      // Browser 'apiKey' assignments are often deliberately public (e.g., map SDK keys).
      // Report them, but do not categorise their appearance as a sensitive-secret alert.
      const keyName=match[0].split(/[:=]/,1)[0].trim();
      const type=/^api[_-]?key$/i.test(keyName)?'Public API-key assignment indicator':'Named secret assignment';
      const marker = `${type}|${match.index}|${source}`;
      if (!seen.has(marker)) {
        seen.add(marker);
        if(typeof onRawIndicator==='function')onRawIndicator({type,value:match[1],offset:match.index});
        found.push({type, masked: mask(match[1]), note: 'value not collected; validity and permissions unverified', source: String(source).slice(0, 400), offset: match.index});
      }
    }
    return found.slice(0, 120);
  }
  const URL_PATTERN = /https?:\/\/[a-z0-9._:-]+(?:\/[\w\-./~%+]*)(?:\?[^\s"'`<>\\]{0,160})?/ig;
  const PATH_PATTERN = /["'`]((?:\/api\/|\/graphql(?:\/|\b)|\/rest\/|\/v[1-9]\/)[^"'`\s<>\\]{0,180})["'`]/g;
  function endpointClues(text, source, base) {
    const found = [], seen = new Set();
    const input = String(text || '').slice(0, 500000);
    const add = (value, kind) => {
      const info = urlInfo(value, base);
      if (!info || !info.url) return;
      if (!/(?:\/api\/|\/graphql(?:\/|$)|\/rest\/|\/v[1-9]\/)/i.test(new URL(info.url).pathname) && !/^api[.-]/i.test(info.host)) return;
      if (seen.has(info.url)) return;
      seen.add(info.url);
      found.push({url: info.url, host: info.host, kind, source: String(source).slice(0, 400), observed: false});
    };
    URL_PATTERN.lastIndex = 0;
    let m, count = 0;
    while ((m = URL_PATTERN.exec(input)) && count++ < 250) {
      const url = m[0].replace(/[.,;)]+$/, '');
      if (/(?:api[.-]|\/api\/|\/graphql|\/rest\/|\/v[1-9]\/)/i.test(url)) add(url, 'static-js');
    }
    PATH_PATTERN.lastIndex = 0;
    count = 0;
    while ((m = PATH_PATTERN.exec(input)) && count++ < 250) add(m[1], 'static-js');
    return found.slice(0, 120);
  }
  function frameworkClues(text, source) {
    const input = String(text || '').slice(0, 500000);
    const tests = [
      ['Next.js hydration', /__NEXT_DATA__|\/_next\/static\//],
      ['Nuxt hydration', /__NUXT__|\/_nuxt\//],
      ['Vite public environment', /import\.meta\.env|\bVITE_[A-Z0-9_]+/],
      ['Next.js public environment', /\bNEXT_PUBLIC_[A-Z0-9_]+/],
      ['Webpack bundles', /webpackChunk|__webpack_require__/],
      ['GraphQL client', /graphql\b|ApolloClient|urql\b/i],
      ['CloudFront reference', /cloudfront\.net/i],
      ['Cloudflare reference', /cloudflare|cf-ray/i],
      ['S3 reference', /\.s3[.-][a-z0-9.-]*amazonaws\.com|s3:\/\//i]
    ];
    return tests.filter(([, re]) => re.test(input)).map(([label]) => ({label, source: String(source).slice(0, 400)}));
  }
  root.THI = {sanitizedUrl, urlInfo, authQueryClasses, signingEvidence, mask, secretIndicators, endpointClues, frameworkClues};
})(globalThis);
