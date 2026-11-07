/* Passive, heuristic classifications. No search requests made. */
(function(root){'use strict';
 function classify(url,method='GET'){
  try{
   const u=new URL(url),host=u.hostname.toLowerCase(),path=u.pathname.toLowerCase();
   if(/(?:^|\.)algolia\.(?:net|com)$/.test(host)||/\.algolianet\.com$/.test(host))return {provider:'Algolia',evidence:'observed provider hostname'};
   if(/(?:^|\.)typesense\.(?:org|cloud)$/.test(host)||/\/collections\/[^/]+\/documents\/search/.test(path))return {provider:'Typesense-like',evidence:'observed search route (heuristic)'};
   if(/\/solr\/[^/]+\/(?:select|query)$/.test(path))return {provider:'Apache Solr-like',evidence:'observed characteristic route'};
   if(/\/(?:_search|_msearch)$/.test(path))return {provider:'Elasticsearch/OpenSearch-like',evidence:'observed search route; vendor unverified'};
   if(/\/(?:search|find|filter|facets?)(?:\/|$)/.test(path))return {provider:'Custom / unknown search',evidence:'observed search-related route'};
   return null;
  }catch{return null;}
 }
 function interactionKind(kind){return ['search-submit','filter-change','sort-change','load-more','lightbox-open','gallery-click'].includes(kind)?kind:'';}
 root.THISearch={classify,interactionKind};
})(globalThis);
