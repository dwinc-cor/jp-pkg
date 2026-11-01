/* JAPRO - carregador com verificação de assinatura (gerado por build.py a partir de tools/carregador.js). */
(function(){
"use strict";
var R="japro-cicp/japro-app",F="japro-core.js",G="japro-core.sig";
var CDN="https://cdn.jsdelivr.net/gh/"+R,RAW="https://raw.githubusercontent.com/"+R;
var PK={"kty":"EC","crv":"P-256","x":"yejq88x4N2Dc4kIsILxpVMotTLLMyeNpa33_qL9GDQk","y":"uB9kehVIgSD3CupYSEckanpVv0q_jQaTE3Kk6iY0RVQ"},KID="f52aa7aa049bf1bb",LK="japro.ldr.ultimaValida";
var W=window,D=document;
function lsGet(k){try{return W.localStorage.getItem(k)}catch(e){return null}}
function lsSet(k,v){try{W.localStorage.setItem(k,v)}catch(e){}}
function aviso(m){try{console.warn("JAPRO carregador: "+m)}catch(e){}}
function tempo(p,ms){return new Promise(function(ok,no){var t=setTimeout(function(){no(new Error("tempo esgotado"))},ms);p.then(function(v){clearTimeout(t);ok(v)},function(e){clearTimeout(t);no(e)})})}
function baixa(u,bin,fixo){return tempo(fetch(u,{cache:fixo?"default":"no-store",credentials:"omit"}).then(function(r){if(!r.ok){var e=new Error("HTTP "+r.status);e.status=r.status;throw e}return bin?r.arrayBuffer():r.text()}),25000)}
/* falha de rede repete uma vez; 404 é resposta (arquivo ausente), não repete */
function tenta(fn){return fn().catch(function(e){if(e&&e.status===404)throw e;return new Promise(function(ok){setTimeout(ok,900)}).then(fn)})}
var SUB=null;try{SUB=W.crypto&&W.crypto.subtle&&typeof W.crypto.subtle.verify==="function"?W.crypto.subtle:null}catch(e){SUB=null}
var chaveP=null;function chave(){if(!chaveP)chaveP=SUB.importKey("jwk",PK,{name:"ECDSA",namedCurve:"P-256"},false,["verify"]);return chaveP}
function hex(buf){var u=new Uint8Array(buf),s="";for(var i=0;i<u.length;i++)s+=(u[i]<16?"0":"")+u[i].toString(16);return s}
function b64(s){var b=atob(s),u=new Uint8Array(b.length);for(var i=0;i<b.length;i++)u[i]=b.charCodeAt(i);return u}
function utf8(s){return new TextEncoder().encode(s)}
/* confere um par (pacote, assinatura) de uma origem. estrito = endereço imutável (commit fixo): divergência é adulteração, não cache */
function confere(u,estrito){
  var pc=tenta(function(){return baixa(u.core,true,estrito)}),ps=tenta(function(){return baixa(u.sig,false,estrito)});
  return pc.then(function(core){
    return ps.then(function(t){var o=null;try{o=JSON.parse(t)}catch(e){}return o},function(){return null}).then(function(o){
      if(!o||typeof o!=="object")return {st:"semAssinatura",core:core,u:u};
      if(typeof o.assinatura!=="string"||typeof o.sha256!=="string")return {st:"adulterado",motivo:"arquivo de assinatura sem os campos esperados",u:u};
      if(!SUB)return {st:"semVerificador",core:core,u:u};
      // assinatura presente com formato inválido (base64 quebrado, tamanho errado, SHA-256 malformado) é adulteração, nunca "sem verificador"
      var sg=null;try{sg=b64(o.assinatura)}catch(e){sg=null}
      if(!sg||sg.length!==64||!/^[0-9a-f]{64}$/.test(o.sha256))return {st:"adulterado",motivo:"assinatura em formato inválido",u:u};
      return chave().then(function(k){
        return SUB.verify({name:"ECDSA",hash:"SHA-256"},k,sg,utf8("JAPRO-CORE-SHA256:"+o.sha256)).then(function(v){return v},function(){return false})
          .then(function(v){if(!v)return {st:"adulterado",motivo:"assinatura inválida",u:u};
            return SUB.digest("SHA-256",core).then(function(h){h=hex(h);if(h===o.sha256)return {st:"ok",core:core,u:u,sig:o};
              return {st:estrito?"adulterado":"divergente",motivo:"pacote diferente do assinado",core:core,u:u}})})},
        function(e){return {st:"semVerificador",core:core,u:u,erro:String(e&&e.message||e)}})})},
    function(e){return {st:"semPacote",u:u,erro:String(e&&e.message||e)}})}
function origens(ref,estrito){return [{core:CDN+"@"+ref+"/"+F,sig:CDN+"@"+ref+"/"+G,ref:ref,estrito:estrito},{core:RAW+"/"+ref+"/"+F,sig:RAW+"/"+ref+"/"+G,ref:ref,estrito:estrito}]}
var feito=false;
function executa(r){if(feito)return;feito=true;
  if(r.st==="ok"&&/^[0-9a-f]{40}$/.test(r.u.ref))lsSet(LK,r.u.ref);
  if(r.st!=="ok")aviso("versão carregada sem conferência da assinatura ("+r.st+")");
  var txt=new TextDecoder("utf-8").decode(r.core);
  try{var s=D.createElement("script");s.textContent=txt;D.head.appendChild(s)}catch(e){}
  var rodou=false;try{rodou=typeof JAPRO_VERSION!=="undefined"}catch(e){rodou=false}
  // ambiente que proíbe script embutido: carrega o mesmo endereço já conferido
  // ambiente que proíbe script embutido: executa os MESMOS bytes conferidos (blob); só se também for proibido, o endereço já conferido
  if(!rodou){var s2=D.createElement("script");var bu=null;try{bu=URL.createObjectURL(new Blob([r.core],{type:"text/javascript"}))}catch(e){}
    s2.onerror=function(){var s3=D.createElement("script");s3.src=r.u.core;D.head.appendChild(s3)};s2.src=bu||r.u.core;D.head.appendChild(s2)}}
function recusa(lista){if(feito)return;feito=true;var m=lista.map(function(r){return r.u.ref+": "+(r.motivo||r.st)}).join("; ");aviso("versão recusada: "+m);
  D.body.innerHTML='<div style="max-width:640px;margin:40px auto;padding:22px 24px;border:1px solid #d5dbe8;border-top:5px solid #b3261e;border-radius:8px;font-family:sans-serif;line-height:1.5;color:#141b33;background:#fff">'+
  '<h1 style="font-size:20px;margin:0 0 10px">JAPRO não foi carregado por segurança</h1>'+
  '<p style="margin:0 0 10px">A versão do sistema disponível agora <b>não tem assinatura digital válida</b> da Corregedoria-Geral: o código pode ter sido alterado por terceiros. Por isso ele <b>não foi executado</b>; nenhum arquivo foi lido e nenhum dado foi enviado.</p>'+
  '<p style="margin:0 0 10px">Não use cópias de outra origem. Avise a Corregedoria-Geral (Plantão da Corregedoria, WhatsApp (65) 98170-0385) e tente de novo mais tarde.</p>'+
  '<p style="margin:0;font-size:12px;color:#5b6582">Detalhe técnico: '+m.replace(/[&<>"]/g,"")+'</p></div>'}
/* ordem: commit mais recente (imutável) → @main (cache do CDN pode estar defasado) → última versão válida já usada neste navegador.
   Só há tela de erro quando há assinatura presente e inválida (adulteração real) e nenhuma versão válida foi obtida. Assinatura
   indisponível (rede, CDN, navegador sem WebCrypto) nunca bloqueia: carrega a melhor versão disponível, como o carregador anterior. */
function decide(sha){var ult=lsGet(LK);var fila=[];
  if(sha)fila=fila.concat(origens(sha,true));
  fila=fila.concat(origens("main",false));
  if(ult&&ult!==sha)fila=fila.concat(origens(ult,true));
  var res=[];var i=0;
  function prox(){if(feito)return;if(i>=fila.length)return fim();var u=fila[i++];
    // o espelho (raw.githubusercontent) só é consultado se o CDN do mesmo endereço falhou ou não conferiu
    return confere(u,u.estrito).then(function(r){res.push(r);if(r.st==="ok")return executa(r);
      if(r.st==="semVerificador")return executa(r); // navegador sem WebCrypto: não há como conferir; carrega como o carregador anterior
      if(u.core.indexOf(CDN)===0&&r.st==="adulterado")i++; // adulteração no endereço imutável: o espelho do mesmo commit não muda o veredito
      return prox()})}
  function fim(){
    // @main divergente nos dois espelhos (CDN e GitHub) não é atraso de cache: o pacote publicado não é o assinado
    var dv=res.filter(function(r){return r.st==="divergente"});
    if(dv.length>=2)dv.forEach(function(r){r.st="adulterado"});
    var adult=res.filter(function(r){return r.st==="adulterado"});
    var usavel=res.filter(function(r){return r.core&&r.st!=="adulterado"});
    if(adult.length)return recusa(adult);
    if(usavel.length)return executa(usavel[0]);
    var p=D.getElementById("carregando");if(p)p.textContent="Não foi possível carregar o JAPRO agora (sem conexão com o servidor). Verifique a internet e recarregue a página.";}
  prox()}
var ini=false;function vai(sha){if(ini)return;ini=true;decide(sha)}
setTimeout(function(){vai(null)},6000);
try{fetch("https://api.github.com/repos/"+R+"/commits/main",{cache:"no-store",credentials:"omit"}).then(function(r){return r.json()}).then(function(j){var s=j&&j.sha;vai(/^[0-9a-f]{40}$/.test(s||"")?s:null)}).catch(function(){vai(null)})}catch(e){vai(null)}
})();
