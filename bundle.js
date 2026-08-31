(function(){
var E={"salt":"79ea755cba72808a","iv":"57ce64566258cefec9f1b395","tag":"659bcbea50355362e00ec74e37cf3fb3","data":"d3de7d495dab08dd1f335afc4cdf1d"},KS="dc4f173bef48d143",REQ=["af1","af2"],FS={"af1":"3edcedd303b44191","af2":"6a27b69afa629579"},FH={"af1":"ed1cda02719caf6fee9d57df076c6e47bd1fa14e782c7bf3bc82bc64a91c39d2","af2":"78520fb1630f72ea21933f0495b54d53fbe29778478afe3e918fd79757539283"},FO=["af1","af2","af3","af4","af5","af6"];
function hx(h){return new Uint8Array(h.match(/../g).map(function(x){return parseInt(x,16)}))}
function toHex(bytes){var o='';for(var i=0;i<bytes.length;i++)o+=bytes[i].toString(16).padStart(2,'0');return o}
function sha(s){return crypto.subtle.digest('SHA-256',new TextEncoder().encode(s)).then(function(b){return toHex(new Uint8Array(b))})}
function fieldName(n){return 'af'+n}
function mkKey(values){return sha(KS+'|'+values.join('|'))}
function decryptWith(keyHex){
  // WebCrypto expects GCM data to include the auth tag appended.
  var keyBytes=hx(keyHex);
  var iv=hx(E.iv),data=hx(E.data),tag=hx(E.tag);
  var combined=new Uint8Array(data.length+tag.length);
  combined.set(data,0);combined.set(tag,data.length);
  return crypto.subtle.importKey('raw',keyBytes,{name:'AES-GCM'},false,['decrypt']).then(function(k){
    return crypto.subtle.decrypt({name:'AES-GCM',iv:iv,tagLength:128},k,combined);
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