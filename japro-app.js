/* JAPRO - carregador com verificação de assinatura (gerado por build.py a partir de tools/carregador.js). Versão 2 (Rodada S0).
   Raiz de confiança: este código e a chave PÚBLICA ficam embutidos no HTML do Canvas do Gemini (publicado uma vez); só o pacote
   (japro-core.js) e a assinatura dele (japro-core.sig) vêm do repositório. Regras:
   - executa SOMENTE pacote cuja assinatura (formato 2: SHA-256 + versão + data) confere com a chave embutida;
   - sem assinatura, pacote diferente do assinado, navegador sem o recurso de conferência: NÃO executa; usa a última versão válida
     já conferida (commit fixo) ou mostra a tela de recusa, que explica o que fazer;
   - anti-rebaixamento: recusa versão menor que a maior já conferida (versão mínima embutida, última válida neste navegador e no
     cofre, esta conferida pela assinatura antes de valer);
   - anota em JAPRO_CANAL a origem do programa (link oficial, SHA-256 do pacote, versão, data), que o documento gerado registra. */
(function(){
"use strict";
var R="japro-cicp/japro-app",F="japro-core.js",G="japro-core.sig";
var CDN="https://cdn.jsdelivr.net/gh/"+R,RAW="https://raw.githubusercontent.com/"+R;
var PK={"kty":"EC","crv":"P-256","x":"yejq88x4N2Dc4kIsILxpVMotTLLMyeNpa33_qL9GDQk","y":"uB9kehVIgSD3CupYSEckanpVv0q_jQaTE3Kk6iY0RVQ"},KID="f52aa7aa049bf1bb",VMIN="2026.11.08-0000",LK="japro.ldr.ultimaValida2";
var COFRE_URL="https://japro-cicp.github.io/cofre.html";
var W=window,D=document;
var EU=(D.currentScript&&D.currentScript.textContent)||"";
function lsGet(k){try{return W.localStorage.getItem(k)}catch(e){return null}}
function lsSet(k,v){try{W.localStorage.setItem(k,v)}catch(e){}}
function aviso(m){try{console.warn("JAPRO carregador: "+m)}catch(e){}}
function tempo(p,ms){return new Promise(function(ok,no){var t=setTimeout(function(){no(new Error("tempo esgotado"))},ms);p.then(function(v){clearTimeout(t);ok(v)},function(e){clearTimeout(t);no(e)})})}
function baixa(u,bin,fixo){return tempo(fetch(u,{cache:fixo?"default":"no-store",credentials:"omit"}).then(function(r){if(!r.ok){var e=new Error("HTTP "+r.status);e.status=r.status;throw e}return bin?r.arrayBuffer():r.text()}),25000)}
/* falha de rede repete uma vez; 404 é resposta (arquivo ausente), não repete */
function tenta(fn){return fn().catch(function(e){if(e&&e.status===404)throw e;return new Promise(function(ok){setTimeout(ok,900)}).then(fn)})}
var SUB=null;try{SUB=W.crypto&&W.crypto.subtle&&typeof W.crypto.subtle.verify==="function"&&typeof W.crypto.subtle.digest==="function"?W.crypto.subtle:null}catch(e){SUB=null}
var chaveP=null;function chave(){if(!chaveP)chaveP=SUB.importKey("jwk",PK,{name:"ECDSA",namedCurve:"P-256"},false,["verify"]);return chaveP}
function hex(buf){var u=new Uint8Array(buf),s="";for(var i=0;i<u.length;i++)s+=(u[i]<16?"0":"")+u[i].toString(16);return s}
function b64(s){var b=atob(s),u=new Uint8Array(b.length);for(var i=0;i<b.length;i++)u[i]=b.charCodeAt(i);return u}
function utf8(s){return new TextEncoder().encode(s)}
function b64h(h){var s="";for(var i=0;i<h.length;i+=2)s+=String.fromCharCode(parseInt(h.substr(i,2),16));return btoa(s)}
var VER_RE=/^\d{4}\.\d{2}\.\d{2}-\d{4}$/;
function msg2(o){return utf8("JAPRO-CORE-2\nsha256="+o.sha256+"\nversao="+o.versao+"\ndata="+o.data)}
/* confere a assinatura formato 2 de um objeto {sha256, versao, data, assinatura2}: true/false */
function confereSig(o){var sg=null;try{sg=b64(o.assinatura2)}catch(e){sg=null}
  if(!sg||sg.length!==64||!/^[0-9a-f]{64}$/.test(o.sha256||"")||!VER_RE.test(o.versao||"")||!/^\d{4}-\d{2}-\d{2}T[\d:.]+Z$/.test(o.data||""))return Promise.resolve(false);
  return chave().then(function(k){return SUB.verify({name:"ECDSA",hash:"SHA-256"},k,sg,msg2(o))}).then(function(v){return !!v},function(){return false})}
/* data: assinatura com data no futuro (além de agora + 2 dias) ou com data e versão divergentes (mais de 2 dias) é recusada.
   «Agora» = o maior entre o relógio deste computador e a data do último commit informada pelo GitHub (relógio atrasado não
   recusa versão legítima quando o GitHub responde). */
var AGORA_API=0,DIA=864e5;
function verMs(v){var m=/^(\d{4})\.(\d{2})\.(\d{2})-(\d{2})(\d{2})$/.exec(v||"");return m?Date.UTC(+m[1],+m[2]-1,+m[3],+m[4]+4,+m[5]):NaN} // versão no horário de Cuiabá (UTC-4)
function dataRuim(o){var d=Date.parse(o.data),v=verMs(o.versao),ag=Math.max(Date.now(),AGORA_API);
  if(isNaN(d)||isNaN(v))return "data ou versão ilegível";if(Math.abs(d-v)>2*DIA)return "data da assinatura diverge da versão";
  if(d>ag+2*DIA||v>ag+2*DIA)return "futura";return ""}
var PISO=VMIN; // maior versão já conferida (sobe com a última válida do navegador e do cofre)
function sobe(v){if(VER_RE.test(v||"")&&v>PISO)PISO=v}
/* confere um par (pacote, assinatura) de uma origem. estrito = endereço imutável (commit fixo): divergência é adulteração, não cache */
function confere(u,estrito){
  var pc=tenta(function(){return baixa(u.core,true,estrito)}),ps=tenta(function(){return baixa(u.sig,false,estrito)});
  return pc.then(function(core){
    return ps.then(function(t){var o=null;try{o=JSON.parse(t)}catch(e){}return o},function(){return null}).then(function(o){
      if(!o||typeof o!=="object")return {st:"semAssinatura",motivo:"pacote sem arquivo de assinatura",u:u};
      if(typeof o.assinatura2!=="string")return {st:"semAssinatura",motivo:"assinatura sem versão e data (formato antigo)",u:u};
      return confereSig(o).then(function(v){if(!v)return {st:"adulterado",motivo:"assinatura inválida",u:u};
        return SUB.digest("SHA-256",core).then(function(h){h=hex(h);
          if(h!==o.sha256)return {st:estrito?"adulterado":"divergente",motivo:"pacote diferente do assinado",u:u};
          var dr=dataRuim(o);if(dr==="futura")return {st:"futura",motivo:"versão "+o.versao+" com data no futuro em relação a este computador",u:u};
          if(dr)return {st:"adulterado",motivo:dr,u:u};
          if(o.versao<PISO)return {st:"antiga",motivo:"versão "+o.versao+" anterior à "+PISO+", já conferida",u:u};
          return {st:"ok",core:core,u:u,sig:o,sha:h}})})})},
    function(e){return {st:"semPacote",u:u,erro:String(e&&e.message||e)}})}
function origens(ref,estrito){return [{core:CDN+"@"+ref+"/"+F,sig:CDN+"@"+ref+"/"+G,ref:ref,estrito:estrito},{core:RAW+"/"+ref+"/"+F,sig:RAW+"/"+ref+"/"+G,ref:ref,estrito:estrito}]}
/* ---------- cofre (Gemini: cada recarga abre num endereço novo; a última versão válida fica no cofre) ---------- */
var CF={f:null,p:null,n:0,P:{}};
function cofreAtivo(){try{if(W.JAPRO_COFRE_URL)return true;if(/\.(?:usercontent\.goog|googleusercontent\.com)$/.test(location.hostname))return true;
  var ao=location.ancestorOrigins;if(ao)for(var i=0;i<ao.length;i++)if(/^https:\/\/gemini\.google\.com$/.test(ao[i]))return true}catch(e){}return false}
function cofre(){if(CF.p)return CF.p;var url=(W.JAPRO_COFRE_URL||COFRE_URL),orig;url+=(url.indexOf("?")<0?"?":"&")+"v=2";try{orig=new URL(url).origin}catch(e){return Promise.reject(e)}
  CF.p=tempo(new Promise(function(ok,no){var f=D.createElement("iframe");f.src=url;f.title="";f.setAttribute("aria-hidden","true");f.tabIndex=-1;f.style.cssText="position:absolute;width:1px;height:1px;border:0;left:-9999px;top:0";
    W.addEventListener("message",function(e){var m=e.data;if(e.origin!==orig||e.source!==f.contentWindow||!m||m.japroCofre!==1)return;
      if(m.pronto){if((+m.v||1)<2)no(new Error("cofre antigo"));else{CF.f=f;CF.o=orig;ok(f)}return}var r=CF.P[m.id];if(r){delete CF.P[m.id];r(m)}});
    D.documentElement.appendChild(f)}),3500);return CF.p}
function cofreOp(op,k,v){return cofre().then(function(f){return tempo(new Promise(function(ok,no){var id=++CF.n;CF.P[id]=function(m){m.ok?ok(m.v):no(new Error(m.erro||"recusado"))};f.contentWindow.postMessage({japroCofre:1,id:id,op:op,k:k,v:v},CF.o)}),3000)})}
/* última versão válida guardada (navegador e cofre): só vale se a assinatura dela conferir */
function ultimaLe(txt){var o=null;try{o=JSON.parse(txt)}catch(e){return Promise.resolve(null)}
  if(!o||typeof o!=="object"||!/^[0-9a-f]{40}$/.test(o.ref||""))return Promise.resolve(null);
  return confereSig(o).then(function(v){return v&&!dataRuim(o)?o:null})}
var ULT=[];
function preparaUltimas(){var L=[ultimaLe(lsGet(LK))];if(cofreAtivo())L.push(cofreOp("get","ldr:ultima").then(ultimaLe,function(){return null}));
  return Promise.all(L).then(function(A){A.forEach(function(o){if(o){sobe(o.versao);if(!ULT.some(function(x){return x.ref===o.ref}))ULT.push(o)}});
    ULT.sort(function(a,b){return a.versao<b.versao?1:-1})})}
function guarda(r){var o={ref:r.u.ref,sha256:r.sig.sha256,versao:r.sig.versao,data:r.sig.data,assinatura2:r.sig.assinatura2};var t=JSON.stringify(o);
  var atual=ULT[0];if(atual&&atual.versao>o.versao)return;lsSet(LK,t);if(cofreAtivo())cofreOp("put","ldr:ultima",t).catch(function(){})}
var feito=false;
function executa(r){if(feito)return;feito=true;
  if(/^[0-9a-f]{40}$/.test(r.u.ref))guarda(r);
  var canal={canal:"carregador",sha256:r.sha,versao:r.sig.versao,data:r.sig.data,ref:r.u.ref,kid:KID,carregador:""};
  var vai=function(){try{Object.defineProperty(W,"JAPRO_CANAL",{value:Object.freeze(canal),writable:false,configurable:false})}catch(e){}
    var txt=new TextDecoder("utf-8").decode(r.core);
    try{var s=D.createElement("script");s.textContent=txt;D.head.appendChild(s)}catch(e){}
    var rodou=false;try{rodou=typeof JAPRO_VERSION!=="undefined"}catch(e){rodou=false}
    // ambiente que proíbe script embutido: executa os MESMOS bytes conferidos (blob); só se também for proibido, o endereço imutável já conferido
    if(!rodou){var s2=D.createElement("script");var bu=null;try{bu=URL.createObjectURL(new Blob([r.core],{type:"text/javascript"}))}catch(e){}
      // último recurso: o mesmo endereço imutável, mas só com integrity= (SRI) igual ao SHA-256 já conferido; outro conteúdo não executa
      s2.onerror=function(){if(!r.u.estrito)return;var s3=D.createElement("script");s3.integrity="sha256-"+b64h(r.sha);s3.crossOrigin="anonymous";s3.src=r.u.core;D.head.appendChild(s3)};
      if(bu)s2.src=bu;else return s2.onerror();D.head.appendChild(s2)}};
  // impressão do próprio carregador (para conferir a publicação no Canvas)
  if(EU)SUB.digest("SHA-256",utf8(EU)).then(function(h){canal.carregador=hex(h)},function(){}).then(vai);else vai()}
var TXT={
  adult:"A versão do sistema disponível agora <b>não tem assinatura digital válida</b> da Corregedoria-Geral: o código pode ter sido alterado por terceiros. Por isso ele <b>não foi executado</b>; nenhum arquivo foi lido e nenhum dado foi enviado.",
  semsig:"A versão do sistema disponível agora <b>está sem a assinatura digital</b> da Corregedoria-Geral, ou com uma assinatura de formato antigo. Código sem assinatura conferida <b>não é executado</b>; nenhum arquivo foi lido e nenhum dado foi enviado.",
  futura:"A versão do sistema disponível agora tem data <b>posterior à data deste computador</b>. Confira se a data e a hora deste computador estão certas e recarregue a página. Por segurança, versão com data no futuro não é executada.",
  antiga:"A versão do sistema disponível agora é <b>mais antiga</b> do que a última versão já conferida neste navegador. Voltar a uma versão antiga pode reabrir falhas já corrigidas; por isso ela <b>não foi executada</b>.",
  divergente:"Uma nova versão do JAPRO está sendo publicada e ainda não chegou inteira a este computador. Por segurança, o sistema só abre quando o código confere com a assinatura. <b>Aguarde alguns minutos e recarregue a página.</b>",
  semver:"Este navegador não tem o recurso necessário para conferir a assinatura do código do JAPRO. Por segurança, o sistema <b>não foi aberto</b>. Abra o link oficial no Google Chrome atualizado."};
function recusa(tipo,lista){if(feito)return;feito=true;var m=(lista||[]).map(function(r){return r.u.ref+": "+(r.motivo||r.st)}).join("; ");aviso("versão recusada ("+tipo+"): "+m);
  var tr=tipo==="divergente"?"O JAPRO está sendo atualizado":"JAPRO não foi carregado por segurança";
  D.body.innerHTML='<div style="max-width:640px;margin:40px auto;padding:22px 24px;border:1px solid #d5dbe8;border-top:5px solid '+(tipo==="divergente"?"#1d3a8a":"#b3261e")+';border-radius:8px;font-family:sans-serif;line-height:1.5;color:#141b33;background:#fff">'+
  '<h1 style="font-size:20px;margin:0 0 10px">'+tr+'</h1>'+
  '<p style="margin:0 0 10px">'+(TXT[tipo]||TXT.adult)+'</p>'+
  '<p style="margin:0 0 10px">Use somente o link oficial (japro-cicp.github.io). '+(tipo==="divergente"?"Se o aviso continuar depois de 30 minutos, a":"A")+'vise a Corregedoria-Geral (Plantão da Corregedoria, WhatsApp (65) 98170-0385).</p>'+
  '<p style="margin:0;font-size:12px;color:#5b6582">Detalhe técnico: '+m.replace(/[&<>"]/g,"")+'</p></div>'}
/* ordem: commit mais recente (imutável) → @main (cache do CDN pode estar defasado) → últimas versões válidas já conferidas.
   Só executa o que confere; sem nenhuma versão conferida, mostra a tela de recusa com o motivo. */
function decide(sha){if(!SUB)return recusa("semver",[]);
  var fila=[];if(sha)fila=fila.concat(origens(sha,true));fila=fila.concat(origens("main",false));
  ULT.forEach(function(o){if(o.ref!==sha)fila=fila.concat(origens(o.ref,true))});
  var res=[];var i=0;
  function prox(){if(feito)return;if(i>=fila.length)return fim();var u=fila[i++];
    // o espelho (raw.githubusercontent) só é consultado se o CDN do mesmo endereço falhou ou não conferiu
    return confere(u,u.estrito).then(function(r){res.push(r);if(r.st==="ok")return executa(r);
      if(u.core.indexOf(CDN)===0&&(r.st==="adulterado"||r.st==="antiga"||r.st==="futura"))i++; // endereço imutável: o espelho do mesmo commit não muda o veredito
      return prox()})}
  function fim(){var tem=function(st){return res.filter(function(r){return r.st===st})};
    if(tem("adulterado").length)return recusa("adult",tem("adulterado"));
    if(tem("antiga").length)return recusa("antiga",tem("antiga"));
    if(tem("futura").length)return recusa("futura",tem("futura"));
    if(tem("semAssinatura").length)return recusa("semsig",tem("semAssinatura"));
    if(tem("divergente").length)return recusa("divergente",tem("divergente"));
    var p=D.getElementById("carregando");if(p)p.textContent="Não foi possível carregar o JAPRO agora (sem conexão com o servidor). Verifique a internet e recarregue a página."}
  prox()}
var ini=false,SHA=null,prontas=false,shaPronto=false;
function talvez(){if(ini||!prontas||!shaPronto)return;ini=true;decide(SHA)}
setTimeout(function(){shaPronto=true;talvez()},6000);
(SUB?preparaUltimas():Promise.resolve()).catch(function(){}).then(function(){prontas=true;talvez()});
try{fetch("https://api.github.com/repos/"+R+"/commits/main",{cache:"no-store",credentials:"omit"}).then(function(r){return r.json()}).then(function(j){var s=j&&j.sha;try{var dt=Date.parse(j.commit.committer.date);if(!isNaN(dt))AGORA_API=dt}catch(e){}SHA=/^[0-9a-f]{40}$/.test(s||"")?s:null;shaPronto=true;talvez()}).catch(function(){shaPronto=true;talvez()})}catch(e){shaPronto=true;talvez()}
})();
