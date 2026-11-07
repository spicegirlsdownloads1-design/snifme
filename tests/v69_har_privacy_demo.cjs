'use strict';
const P=require('../har_privacy.js');
const har={log:{entries:[{request:{url:'https://example.invalid/demo?token=synthetic-fake-token',headers:[{name:'Authorization',value:'dummy'}],postData:{text:'dummy'}},response:{headers:[{name:'Set-Cookie',value:'dummy'}],content:{text:'demo'}}}]}};
console.log(JSON.stringify(P.audit(har),null,2));
