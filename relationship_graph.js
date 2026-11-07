/* Small, dependency-free interactive evidence graph. Only labels of observed records. */
(function(root){
  'use strict';
  function edges(record){
    if(!record)return [];
    const result=[],seen=new Set();
    const origin=record.origin||'Site';
    function add(from,to,relation,evidence){
      if(!from||!to||from===to)return;
      const key=[from,to,relation].join('|');
      if(seen.has(key))return;
      seen.add(key);result.push({from,to,relation,evidence});
    }
    const requests=record.requests||[], scripts=record.scripts||[],routes=record.routes||[],assets=record.assets||[];
    for(const s of scripts.slice(0,30))add(origin,s.host,'Loads script host','DOM/performance reference');
    for(const r of requests.slice(-500)) {
      if(!r.host)continue;
      const isApi=/(?:\/api\/|\/graphql(?:\/|$)|\/rest\/|\/v[1-9]\/)/i.test(r.url||'') || r.type==='xmlhttprequest';
      if(isApi)add(origin,r.host,'API request',`Observed HTTP ${r.status||'?'}`);
      if(r.type==='image'||/^image\//.test(r.mime||''))add(origin,r.host,'Image resource',`Observed HTTP ${r.status||'?'}`);
    }
    for(const route of routes.slice(0,80)) {
      if(route.kind==='static-clue' && route.source && /^https?:\/\//.test(route.source)) {
        try{add(new URL(route.source).hostname,route.host,'References API','Static JavaScript clue');}catch{}
      }
    }
    for(const m of (record.maps||[]).slice(0,40)){
      try{add(new URL(m.script).hostname,m.url,'Source-map reference',m.status==='inspected-public-map'?'Inspected map':'Static mapping directive');}catch{}
    }
    for(const op of (record.operations||[]).slice(0,60)) {
      if(op.source && /^https?:\/\//.test(op.source)){
        try{add(new URL(op.source).hostname,`GraphQL: ${op.name}`,'Operation name',op.confidence);}catch{}
      }
    }
    for(const config of (record.configs||[]).slice(0,60)){
      if(config.source && /^https?:\/\//.test(config.source)){
        try{add(new URL(config.source).hostname,`Config: ${config.key}`,'Public config key','Static key only');}catch{}
      }
    }
    for(const a of assets.slice(0,100))if(a.host)add(origin,a.host,'Image reference','Page/observed asset URL');
    return result.slice(0,170);
  }
  function render(container,record){
    const all=edges(record);
    const helper=document.createElement('p');helper.className='warn-note';
    helper.textContent='Click a node to inspect its evidence. Lines reflect observed resource loads or static references, not proof that two backends share storage, authentication or asset ownership.';
    container.appendChild(helper);
    if(!all.length){const p=document.createElement('p');p.className='helper';p.textContent='No relationships recorded yet. Capture normal site activity or explicitly analyse linked JavaScript.';container.appendChild(p);return;}
    const rootNode=record.origin||'Site';
    const degree=new Map();for(const e of all){degree.set(e.from,(degree.get(e.from)||0)+1);degree.set(e.to,(degree.get(e.to)||0)+1);}
    const nodes=[...degree.keys()].filter(n=>n!==rootNode).sort((a,b)=>degree.get(b)-degree.get(a)).slice(0,22);
    const visible=new Set([rootNode,...nodes]);const links=all.filter(e=>visible.has(e.from)&&visible.has(e.to)).slice(0,70);
    const types=n=>n===rootNode?'site':/^GraphQL:/.test(n)?'operation':/^Config:/.test(n)?'config':/\.map$/.test(n)?'map':'host';
    const positions=new Map([[rootNode,{x:125,y:310}]]);
    const lanes={host:[],map:[],operation:[],config:[]};for(const n of nodes)lanes[types(n)].push(n);
    const coords={host:360,map:595,operation:755,config:920};
    for(const [kind,group]of Object.entries(lanes))group.forEach((n,i)=>{
      const count=group.length;
      positions.set(n,{x:coords[kind],y: 38 + (i+.5)*(560/Math.max(count,1))});
    });
    const box=document.createElement('div');box.className='graph-box';container.appendChild(box);
    const svg=document.createElementNS('http://www.w3.org/2000/svg','svg');
    svg.setAttribute('viewBox','0 0 1000 640');svg.setAttribute('role','img');
    svg.setAttribute('aria-label','Interactive relationship graph of visited website, hosts, maps and public application metadata');box.appendChild(svg);
    const svgEl=(name,attrs={})=>{const el=document.createElementNS('http://www.w3.org/2000/svg',name);for(const [k,v]of Object.entries(attrs))el.setAttribute(k,String(v));return el;};
    const lines=[];
    for(const e of links){const a=positions.get(e.from),b=positions.get(e.to);if(!a||!b)continue;
      const line=svgEl('path',{d:`M${a.x},${a.y} C${(a.x+b.x)/2},${a.y} ${(a.x+b.x)/2},${b.y} ${b.x},${b.y}`,class:'edge'});
      svg.appendChild(line);lines.push({line,e});}
    const elems=[];const details=document.createElement('div');details.className='graph-details';
    function selected(node){
      for(const {line,e}of lines)line.classList.toggle('chosen',e.from===node||e.to===node);
      for(const {circle,n}of elems)circle.classList.toggle('chosen',n===node);
      const found=links.filter(e=>e.from===node||e.to===node);
      details.replaceChildren();const title=document.createElement('strong');title.textContent=node;details.appendChild(title);
      const desc=document.createElement('p');desc.textContent=`${found.length} displayed connections. ${node===rootNode?'Source page': 'Evidence node'}.`;details.appendChild(desc);
      const ul=document.createElement('ul');for(const e of found.slice(0,16)){
        const li=document.createElement('li');li.textContent=`${e.from===node?e.to:e.from} — ${e.relation} (${e.evidence})`;ul.appendChild(li);
      }details.appendChild(ul);
    }
    for(const [n,p]of positions){
      const group=svgEl('g',{class:'graph-node',tabindex:0,role:'button','aria-label':n});
      const circle=svgEl('rect',{x:p.x-71,y:p.y-18,width:142,height:36,rx:8,class:'graph-'+types(n)});
      group.appendChild(circle);
      const text=svgEl('text',{x:p.x,y:p.y+4,'text-anchor':'middle'});text.textContent=n.length>21?n.slice(0,19)+'…':n;group.appendChild(text);
      group.addEventListener('click',()=>selected(n));group.addEventListener('keydown',ev=>{if(ev.key==='Enter'||ev.key===' '){ev.preventDefault();selected(n);}});
      svg.appendChild(group);elems.push({circle,n});
    }
    container.appendChild(details);selected(rootNode);
    const note=document.createElement('p');note.className='helper';note.textContent=`Graph shows up to 23 high-degree nodes and 70 connections; ${all.length} distinct relationships catalogued. See the CSV export for every catalogued edge.`;container.appendChild(note);
  }
  root.THIGraph={edges,render};
})(globalThis);
