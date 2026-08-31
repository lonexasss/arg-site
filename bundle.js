(function(){
var E={"salt":"dfc0a3c0561524ce","iv":"2759a43b45e383935b02d10c","tag":"95bc4dc43e5f25ef8aac4f4151a5a9f6","data":"85a17ed7bb85fffcba98be2d1669e1"},KS="82423b275fa3042c",REQ=["af1","af2"],FS={"af1":"d3c7586e6706fcf5","af2":"f2a0a2d625a08091"},FH={"af1":"b6e0204591fd125c2ba6fe391567ac4b7291ff346d6fdcd980c4f816d6785420","af2":"ac1e340ef32c2899dda0bb20e3c350b3eaa71e41465131084d4f98c36a89c4e9"},FO=["af1","af2","af3","af4","af5","af6"];
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