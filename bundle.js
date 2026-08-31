(function(){
var E={"salt":"ea21d3c3807dc4c4","iv":"f9e2469e8bd4b970966240f0","tag":"3d027210cd611f5ea9ae4ba5fc098995","data":"90d395dc2161adf8f7c357ffa24e8d"},KS="a2b361dfacf05ce5",REQ=["af1","af2"],FS={"af1":"5c0b26a3f7b4f46b","af2":"25cd20dcd365bf39"},FH={"af1":"99fcfd6c735d2ce5628535c27bd75c711e16383338173c89c9fe0db5366fae87","af2":"9ffe4a8b65a2dfb677c67277ba904130fe348d3ef8b608c2675b08f7556bdeb2"},FO=["af1","af2","af3","af4","af5","af6"];
function hx(h){return new Uint8Array(h.match(/../g).map(function(x){return parseInt(x,16)}))}
function toHex(bytes){var o='';for(var i=0;i<bytes.length;i++)o+=bytes[i].toString(16).padStart(2,'0');return o}
function sha(s){return crypto.subtle.digest('SHA-256',new TextEncoder().encode(s)).then(function(b){return toHex(new Uint8Array(b))})}
function fieldName(n){return 'af'+n}
function mkKey(values){return sha(KS+'|'+values.join('|'))}
function decryptWith(keyHex){
  var keyBytes=hx(keyHex);
  var iv=hx(E.iv),tagBytes=hx(E.tag),data=hx(E.data);
  return crypto.subtle.importKey('raw',keyBytes,{name:'AES-GCM'},false,['decrypt']).then(function(k){
    return crypto.subtle.decrypt({name:'AES-GCM',iv:iv,additionalData:tagBytes,tagLength:128},k,data);
  }).then(function(pt){return new TextDecoder().decode(pt)});
}
window.__check=function(){
  var filled=[];
  for(var i=1;i<=6;i++){var v=document.getElementById('f'+i).value.trim();if(v)filled.push(i)}
  if(!filled.length)return Promise.resolve({ok:false,why:'empty'});
  var order=REQ.slice();
  if(filled.length!==order.length)return Promise.resolve({ok:false,why:'wrong'});
  // verify each filled field against its per-field hash
  var tasks=[];var values=[];
  for(var j=0;j<order.length;j++){
    var k=order[j];var n=parseInt(k.replace('af',''),10);
    var val=document.getElementById('f'+n).value.trim();
    values.push(val);
    (function(kk,vv){tasks.push(sha(FS[kk]+vv).then(function(h){return FH[kk].indexOf(h)>-1}))})(k,val);
  }
  return Promise.all(tasks).then(function(r){
    var all=r.every(Boolean);
    if(!all)return {ok:false,why:'wrong'};
    return mkKey(values).then(function(key){
      return decryptWith(key).then(function(text){
        return {ok:true,text:text};
      },function(){return {ok:false,why:'wrong'}});
    });
  });
};
})();