/* Bounded, concurrency-controlled inspection scheduler. No response contents are stored here. */
(function(root){'use strict';
  function create({worker,onChange=()=>{},maxConcurrent=3,maxQueued=600,maxSeen=1500}={}){
    if(typeof worker!=='function')throw new TypeError('worker required');
    const seen=new Set(),pending=[];
    let running=0;
    const totals={eligible:0,scanned:0,oversized:0,unavailable:0,timeout:0,
      unsupported:0,unrecorded:0,permissionBlocked:0,deliveryError:0,failed:0,
      capacity:0,duplicates:0,indicators:0};
    const snapshot=()=>({...totals,queued:pending.length,running,seen:seen.size});
    const notify=()=>{try{onChange(snapshot());}catch{}};
    function finish(status,result){
      if(!Object.prototype.hasOwnProperty.call(totals,status))status='failed';
      totals[status]++;
      if(status==='scanned')totals.indicators+=Math.max(0,Number(result?.indicators)||0);
      running--;notify();drain();
    }
    function drain(){
      while(running<maxConcurrent&&pending.length){
        const item=pending.shift();running++;
        Promise.resolve().then(()=>worker(item)).then(
          result=>finish(String(result?.status||'scanned'),result),
          ()=>finish('failed'));
      }
      notify();
    }
    function enqueue(key,item){
      if(seen.has(key)){totals.duplicates++;notify();return 'duplicate';}
      if(seen.size>=maxSeen || pending.length>=maxQueued){totals.capacity++;notify();return 'capacity';}
      seen.add(key);totals.eligible++;pending.push(item);drain();return 'queued';
    }
    function skip(key,reason){
      if(seen.has(key)){totals.duplicates++;notify();return 'duplicate';}
      if(seen.size>=maxSeen){totals.capacity++;notify();return 'capacity';}
      seen.add(key);totals.eligible++;
      totals[Object.prototype.hasOwnProperty.call(totals,reason)?reason:'unsupported']++;
      notify();return reason;
    }
    return {enqueue,skip,snapshot};
  }
  root.THIAutoQueue={create};
})(globalThis);
