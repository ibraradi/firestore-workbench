#!/usr/bin/env python3
"""
Firestore Workbench - a proxy + repeater for Google Cloud Firestore.

  * PROXY  : a Frida agent (firestore_agent.js) hooks the target app's Firestore
             SDK and streams every read/write into this tool -- with the app's
             projectId and auth token auto-captured. You don't type anything.
  * REPEATER: click a captured op -> it loads into the editor -> edit path / data
             / auth -> replay it over the Firestore REST API (optionally through
             Burp with --proxy). Or craft requests from scratch.

Pure standard library. No pip installs. Python 3.9+.

Run:
    python firestore_workbench.py                       # GUI at http://127.0.0.1:8799
    python firestore_workbench.py --proxy http://127.0.0.1:8080   # replay through Burp
    python firestore_workbench.py --port 8799 --host 0.0.0.0      # (default host 0.0.0.0 so the phone can post captures)

Then on the device:
    frida -U -f <package> -l firestore_agent.js        # (set WORKBENCH in that file to this PC's LAN IP:port)
"""

import argparse
import json
import ssl
import threading
import time
import urllib.request
import urllib.error
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

OPENER = urllib.request.build_opener()
PROXY = None

# live capture buffer (filled by the Frida agent via POST /api/capture)
CAP_LOCK = threading.Lock()
CAPTURES = []          # each: {seq, ts, op, path, collection, data, project, token, uid, source}
CAP_SEQ = 0
CAP_MAX = 1000

INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Firestore Workbench</title>
<style>
  :root{
    --bg:#0f1115;--panel:#171a21;--panel2:#1e222b;--line:#2a2f3a;--txt:#d8dee9;--muted:#8b93a7;
    --accent:#ff8a3d;--accent2:#4da3ff;--ok:#3ecf8e;--warn:#e0b341;--err:#ff5c5c;
    --mono:'JetBrains Mono',Consolas,Menlo,monospace;
  }
  *{box-sizing:border-box}
  body{margin:0;font-family:system-ui,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--txt);font-size:13px}
  header{display:flex;align-items:center;gap:12px;padding:8px 14px;background:#11141a;border-bottom:1px solid var(--line)}
  header h1{font-size:15px;margin:0;font-weight:600}header h1 b{color:var(--accent)}
  header .sp{flex:1}
  .pill{font-size:11px;color:var(--muted);border:1px solid var(--line);border-radius:20px;padding:3px 10px}
  .pill.on{color:var(--ok);border-color:#244}
  .pill.live{color:var(--accent);border-color:#5a3a1a}
  .wrap{display:grid;grid-template-columns:340px minmax(380px,1fr) minmax(360px,1fr);height:calc(100vh - 47px)}
  .col{overflow:auto;padding:12px}
  .col.cap{border-right:1px solid var(--line);background:#13161d}
  .col.mid{border-right:1px solid var(--line)}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px;margin-bottom:12px}
  .card h2{font-size:11px;text-transform:uppercase;letter-spacing:1px;color:var(--muted);margin:0 0 10px;display:flex;justify-content:space-between;align-items:center}
  label{display:block;font-size:11px;color:var(--muted);margin:8px 0 3px}
  input,select,textarea{width:100%;background:var(--panel2);color:var(--txt);border:1px solid var(--line);border-radius:7px;padding:7px 9px;font-size:12.5px;font-family:inherit}
  textarea{font-family:var(--mono);resize:vertical;line-height:1.45}
  input:focus,select:focus,textarea:focus{outline:none;border-color:var(--accent2)}
  .row{display:flex;gap:8px}.row>*{flex:1}.row.tight{gap:6px}
  button{cursor:pointer;border:1px solid var(--line);background:var(--panel2);color:var(--txt);border-radius:7px;padding:7px 12px;font-size:12.5px;font-weight:500}
  button:hover{border-color:var(--accent2)}
  button.primary{background:var(--accent);border-color:var(--accent);color:#101010;font-weight:700}
  button.primary:hover{filter:brightness(1.08)}
  button.ghost{background:transparent}button.sm{padding:4px 8px;font-size:11px}
  .grid2{display:grid;grid-template-columns:1fr 1fr;gap:8px}
  .muted{color:var(--muted)}.mono{font-family:var(--mono)}
  .status{font-weight:700}.s2{color:var(--ok)}.s3{color:var(--accent2)}.s4{color:var(--warn)}.s5{color:var(--err)}.s0{color:var(--err)}
  .tabs{display:flex;gap:4px;margin-bottom:8px}
  .tabs button{padding:4px 10px;font-size:11.5px}
  .tabs button.active{background:var(--accent2);border-color:var(--accent2);color:#06101c;font-weight:700}
  pre{background:#0c0e13;border:1px solid var(--line);border-radius:8px;padding:10px;margin:0;overflow:auto;max-height:48vh;font-family:var(--mono);font-size:12px;white-space:pre-wrap;word-break:break-word}
  .meta{font-size:11px;color:var(--muted);margin-top:6px}
  .hint{font-size:11px;color:var(--muted);margin-top:4px;line-height:1.5}
  details summary{cursor:pointer;color:var(--muted);font-size:11px;margin-top:6px}
  code{background:#0c0e13;padding:1px 5px;border-radius:4px;font-family:var(--mono);font-size:11.5px}
  /* capture list */
  .cap-item{border:1px solid var(--line);border-radius:8px;padding:7px 8px;margin-bottom:6px;cursor:pointer}
  .cap-item:hover{border-color:var(--accent2);background:var(--panel2)}
  .cap-item.sel{border-color:var(--accent)}
  .op{font-family:var(--mono);font-size:10px;font-weight:700;padding:2px 6px;border-radius:5px;text-transform:uppercase}
  .op.set,.op.add{background:#3a2a14;color:#ffb86b}
  .op.update{background:#14303a;color:#7fd3ff}
  .op.get,.op.list,.op.query{background:#1c2a1c;color:#9be29b}
  .op.delete{background:#3a1414;color:#ff9b9b}
  .cap-path{font-family:var(--mono);font-size:11.5px;margin:4px 0 2px;word-break:break-all}
  .cap-prev{font-family:var(--mono);font-size:10.5px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .cap-time{font-size:10px;color:var(--muted)}
  .bar{display:flex;gap:6px;margin-bottom:8px}
  .bar input{flex:1}
</style>
</head>
<body>
<header>
  <h1>fire<b>store</b> workbench</h1>
  <span class="pill" id="proj-pill">no project</span>
  <span class="pill" id="auth-pill">unauthenticated</span>
  <span class="pill" id="proxy-pill"></span>
  <span class="sp"></span>
  <span class="pill" id="agent-pill">agent: waiting…</span>
  <span class="muted" id="clock"></span>
</header>

<div class="wrap">
  <!-- LEFT: live capture (the "proxy") -->
  <div class="col cap">
    <div class="card" style="margin-bottom:8px">
      <h2>Live capture <span><button class="sm ghost" onclick="clearCaps()">clear</button></span></h2>
      <div class="bar"><input id="capFilter" placeholder="filter path/op…" oninput="renderCaps()"/></div>
      <label style="margin:0"><input type="checkbox" id="capAuto" checked style="width:auto;margin-right:6px">auto-scroll to newest</label>
      <label style="margin:4px 0 0"><input type="checkbox" id="autoBurp" style="width:auto;margin-right:6px">auto-send new → proxy/Burp <span class="muted">(replays each; ⚠ re-executes writes)</span></label>
    </div>
    <div id="caps"></div>
    <div class="hint" id="cap-empty">No captures yet.<br>Run <code>firestore_agent.js</code> on the device and use the app — reads/writes appear here.</div>
  </div>

  <!-- MIDDLE: target/auth + builder (the "repeater") -->
  <div class="col mid">
    <div class="card">
      <h2>Target &amp; Auth</h2>
      <div class="grid2">
        <div><label>Project ID</label><input id="project" placeholder="auto-filled from capture"/></div>
        <div><label>Web API key</label><input id="apiKey" placeholder="AIza… (only for manual auth)"/></div>
      </div>
      <label>Auth mode</label>
      <select id="authMode">
        <option value="none">None (unauthenticated)</option>
        <option value="captured">Use token from captured op</option>
        <option value="anon">Anonymous sign-in</option>
        <option value="password">Email + Password</option>
        <option value="idToken">Paste ID token</option>
        <option value="refresh">Refresh token</option>
      </select>
      <div id="auth-fields"></div>
      <div class="row" style="margin-top:10px">
        <button class="primary" onclick="authenticate()">Authenticate</button>
        <button class="ghost" onclick="clearAuth()">Clear token</button>
      </div>
      <div class="meta" id="auth-meta"></div>
    </div>

    <div class="card">
      <h2>Request</h2>
      <label>Method</label>
      <div class="row tight">
        <select id="method" style="max-width:120px"><option>GET</option><option>POST</option><option>PATCH</option><option>PUT</option><option>DELETE</option></select>
        <input id="url" class="mono" placeholder="loaded from a capture, or build manually"/>
      </div>
      <label>Auth header</label>
      <select id="useAuth">
        <option value="yes">Attach Bearer &lt;current token&gt;</option>
        <option value="no">Send WITHOUT Authorization (test anon/IDOR)</option>
      </select>
      <details><summary>Extra headers (Key: Value per line)</summary>
        <textarea id="headers" rows="2"></textarea></details>
      <label>Body (JSON)</label>
      <textarea id="body" rows="9" class="mono"></textarea>
      <details open><summary>Fields helper — plain JSON &harr; Firestore typed values</summary>
        <textarea id="plain" rows="4" class="mono" placeholder='{"badgeTypeId":9999}'></textarea>
        <div class="row tight" style="margin-top:6px">
          <button class="sm" onclick="plainToBody()">&darr; Encode into Body</button>
          <button class="sm" onclick="bodyToPlain()">&uarr; Decode Body</button>
        </div>
      </details>
      <div class="row" style="margin-top:12px">
        <button class="primary" onclick="send()">Send  &#9654;</button>
        <button class="ghost" onclick="idorSwap()">IDOR helper</button>
      </div>
      <div class="hint" id="warn"></div>
    </div>
  </div>

  <!-- RIGHT: response -->
  <div class="col">
    <div class="card">
      <h2>Response</h2>
      <div id="resp-status" class="muted">— send a request —</div>
      <div class="meta" id="resp-meta"></div>
      <div class="tabs" style="margin-top:10px">
        <button class="active" data-t="decoded" onclick="showTab('decoded')">Decoded</button>
        <button data-t="pretty" onclick="showTab('pretty')">Pretty</button>
        <button data-t="raw" onclick="showTab('raw')">Raw</button>
        <button data-t="hdr" onclick="showTab('hdr')">Headers</button>
      </div>
      <pre id="resp-body"></pre>
    </div>
  </div>
</div>

<script>
const $=id=>document.getElementById(id);
let TOKEN=null,UID=null,LASTRESP=null,CAPLIST=[],lastSeq=0,selSeq=null,lastCapTime=0;

function base(){const p=$('project').value.trim();return `https://firestore.googleapis.com/v1/projects/${p}/databases/(default)/documents`;}
function tick(){$('clock').textContent=new Date().toLocaleTimeString();
  $('agent-pill').textContent='agent: '+(Date.now()-lastCapTime<8000?'live':'idle');
  $('agent-pill').className='pill '+(Date.now()-lastCapTime<8000?'live':'');}
setInterval(tick,1000);tick();

/* typed value <-> plain */
function encVal(v){if(v===null)return{nullValue:null};if(typeof v==='boolean')return{booleanValue:v};
  if(typeof v==='number')return Number.isInteger(v)?{integerValue:String(v)}:{doubleValue:v};
  if(typeof v==='string')return{stringValue:v};if(Array.isArray(v))return{arrayValue:{values:v.map(encVal)}};
  if(typeof v==='object')return{mapValue:{fields:encFields(v)}};return{stringValue:String(v)};}
function encFields(o){const f={};for(const k in o)f[k]=encVal(o[k]);return f;}
function decVal(v){if(!v||typeof v!=='object')return v;
  if('nullValue'in v)return null;if('booleanValue'in v)return v.booleanValue;
  if('integerValue'in v)return Number(v.integerValue);if('doubleValue'in v)return v.doubleValue;
  if('stringValue'in v)return v.stringValue;if('timestampValue'in v)return v.timestampValue;
  if('referenceValue'in v)return v.referenceValue;if('arrayValue'in v)return(v.arrayValue.values||[]).map(decVal);
  if('mapValue'in v)return decFields(v.mapValue.fields||{});return v;}
function decFields(f){const o={};for(const k in f)o[k]=decVal(f[k]);return o;}
function decodeDoc(d){const o={'__name':d.name};if(d.fields)Object.assign(o,decFields(d.fields));return o;}
function decodeResponse(t){let j;try{j=JSON.parse(t)}catch(e){return null}
  if(Array.isArray(j))return j.map(x=>x.document?decodeDoc(x.document):x);
  if(j.documents)return j.documents.map(decodeDoc);if(j.fields||j.name)return decodeDoc(j);return j;}

/* proxy to backend */
async function proxy(method,url,headers,body){const t0=performance.now();
  const r=await fetch('/api/send',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({method,url,headers:headers||{},body:body==null?null:body})});
  const j=await r.json();j._ms=Math.round(performance.now()-t0);return j;}

/* ---- auth ---- */
function authFieldsHTML(m){
  if(m==='password')return`<label>Email</label><input id="a_email"/><label>Password</label><input id="a_pass" type="password"/>`;
  if(m==='idToken')return`<label>ID token</label><textarea id="a_idtok" rows="3" class="mono"></textarea>`;
  if(m==='refresh')return`<label>Refresh token</label><textarea id="a_refresh" rows="2" class="mono"></textarea>`;
  if(m==='captured')return`<div class="hint">Uses the Bearer token captured with the op you load from the left. Just click a capture, then Send.</div>`;
  if(m==='anon')return`<div class="hint">accounts:signUp (needs anonymous auth enabled).</div>`;
  return`<div class="hint">No token sent.</div>`;}
$('authMode').onchange=e=>$('auth-fields').innerHTML=authFieldsHTML(e.target.value);
$('auth-fields').innerHTML=authFieldsHTML('none');
async function authenticate(){const key=$('apiKey').value.trim(),m=$('authMode').value;
  if($('project').value.trim()){$('proj-pill').textContent=$('project').value.trim();$('proj-pill').className='pill on';}
  if(m==='none'||m==='captured'){$('auth-meta').textContent=m==='captured'?'Will use captured token on load.':'Unauthenticated.';return;}
  if(m==='idToken'){setToken($('a_idtok').value.trim(),'(pasted)');return;}
  let url,payload,form=false;
  if(m==='anon'){url=`https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=${key}`;payload={returnSecureToken:true};}
  else if(m==='password'){url=`https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${key}`;payload={email:$('a_email').value.trim(),password:$('a_pass').value,returnSecureToken:true};}
  else if(m==='refresh'){url=`https://securetoken.googleapis.com/v1/token?key=${key}`;payload=`grant_type=refresh_token&refresh_token=${encodeURIComponent($('a_refresh').value.trim())}`;form=true;}
  const res=await proxy('POST',url,{'Content-Type':form?'application/x-www-form-urlencoded':'application/json'},form?payload:JSON.stringify(payload));
  let j;try{j=JSON.parse(res.body)}catch(e){j={}}
  const tok=j.idToken||j.id_token||j.access_token;
  if(tok){setToken(tok,j.localId||j.user_id||'?');$('auth-meta').textContent=`OK (${res.status}) uid=${UID}`;}
  else $('auth-meta').innerHTML=`<span class="s5">Auth failed (${res.status})</span>`;}
function setToken(t,uid){TOKEN=t;UID=uid;$('auth-pill').textContent='authed: '+(uid||'token');$('auth-pill').className='pill on';}
function clearAuth(){TOKEN=null;UID=null;$('auth-pill').textContent='unauthenticated';$('auth-pill').className='pill';}
/* derive the Firebase project id from a captured ID token (aud / iss claim) */
function projFromJwt(t){try{const p=JSON.parse(atob(t.split('.')[1].replace(/-/g,'+').replace(/_/g,'/')));return p.aud||((p.iss||'').split('/').pop())||null;}catch(e){return null;}}

/* ---- live capture poll ---- */
async function poll(){
  try{const r=await fetch('/api/captures?since='+lastSeq);const arr=await r.json();
    if(arr.length){for(const c of arr){lastSeq=Math.max(lastSeq,c.seq);CAPLIST.push(c);
        if(c.token){ setToken(c.token,c.uid||'app');
          if($('project') && !$('project').value){ const p=c.project||projFromJwt(c.token); if(p){$('project').value=p;$('proj-pill').textContent=p;$('proj-pill').className='pill on';} } }
        else if($('project') && !$('project').value && c.project){ $('project').value=c.project; }
        if(c.op!=='auth' && $('autoBurp') && $('autoBurp').checked) autoSend(c); }
      if(CAPLIST.length>1000)CAPLIST=CAPLIST.slice(-1000);
      lastCapTime=Date.now();renderCaps();}
  }catch(e){}
}
setInterval(poll,1200);poll();
function clearCaps(){CAPLIST=[];renderCaps();}
function renderCaps(){
  const f=($('capFilter').value||'').toLowerCase();
  const items=CAPLIST.filter(c=>!f||((c.path||'')+(c.op||'')).toLowerCase().includes(f));
  $('cap-empty').style.display=items.length?'none':'block';
  $('caps').innerHTML=items.slice().reverse().map(c=>{
    let prev='';try{prev=c.data?JSON.stringify(c.data):'';}catch(e){}
    return `<div class="cap-item ${c.seq===selSeq?'sel':''}" onclick="loadCap(${c.seq})">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <span class="op ${c.op}">${c.op}</span><span class="cap-time">${new Date(c.ts*1000||Date.now()).toLocaleTimeString()}</span>
      </div>
      <div class="cap-path">${(c.path||c.collection||'').replace(/^/, '')}</div>
      ${prev?`<div class="cap-prev">${prev.slice(0,120)}</div>`:''}
    </div>`;}).join('');
  if($('capAuto').checked)$('caps').scrollTop=0;
}
function loadCap(seq){
  const c=CAPLIST.find(x=>x.seq===seq);if(!c)return;selSeq=seq;renderCaps();
  if(c.project){$('project').value=c.project;$('proj-pill').textContent=c.project;$('proj-pill').className='pill on';}
  if(c.token){setToken(c.token,c.uid||'app');$('authMode').value='captured';$('auth-fields').innerHTML=authFieldsHTML('captured');}
  $('useAuth').value='yes';
  const b=base();const op=(c.op||'get').toLowerCase();
  const data=c.data||{};
  if(op==='set'){$('method').value='PATCH';$('url').value=`${b}/${c.path}`;$('body').value=JSON.stringify({fields:encFields(data)},null,2);}
  else if(op==='update'){$('method').value='PATCH';const mask=Object.keys(data).map(k=>'updateMask.fieldPaths='+encodeURIComponent(k)).join('&');
    $('url').value=`${b}/${c.path}${mask?('?'+mask):''}`;$('body').value=JSON.stringify({fields:encFields(data)},null,2);}
  else if(op==='add'){$('method').value='POST';$('url').value=`${b}/${c.collection||c.path}`;$('body').value=JSON.stringify({fields:encFields(data)},null,2);}
  else if(op==='delete'){$('method').value='DELETE';$('url').value=`${b}/${c.path}`;$('body').value='';}
  else {$('method').value='GET';$('url').value=`${b}/${c.path}`;$('body').value='';}
  $('plain').value=Object.keys(data).length?JSON.stringify(data,null,2):'';
  $('warn').textContent='Loaded capture. Edit & Send — try swapping the doc id (IDOR) or toggling auth.';
}

/* IDOR helper: bump the last numeric/hex segment of the doc id so you can probe a neighbour */
function idorSwap(){const u=$('url').value;const m=u.match(/^(.*\/)([^\/?]+)(\?.*)?$/);if(!m){return;}
  $('warn').textContent='IDOR: doc id = '+m[2]+' — change it to another user\'s id and Send. (auth stays the same)';
  $('url').focus();}

/* fields helper */
function plainToBody(){try{$('body').value=JSON.stringify({fields:encFields(JSON.parse($('plain').value||'{}'))},null,2);}catch(e){alert('bad JSON: '+e);}}
function bodyToPlain(){try{const j=JSON.parse($('body').value||'{}');$('plain').value=JSON.stringify(j.fields?decFields(j.fields):decodeResponse($('body').value),null,2);}catch(e){alert('bad JSON: '+e);}}

/* auto-forward a capture through the proxy (-> Burp) without touching the editor */
function buildReq(c){
  const b=base(), op=(c.op||'get').toLowerCase(), data=c.data||{};
  let method='GET', url=`${b}/${c.path}`, body=null;
  if(op==='set'){method='PATCH';body=JSON.stringify({fields:encFields(data)});}
  else if(op==='update'){method='PATCH';const mask=Object.keys(data).map(k=>'updateMask.fieldPaths='+encodeURIComponent(k)).join('&');url=`${b}/${c.path}${mask?('?'+mask):''}`;body=JSON.stringify({fields:encFields(data)});}
  else if(op==='add'){method='POST';url=`${b}/${c.collection||c.path}`;body=JSON.stringify({fields:encFields(data)});}
  else if(op==='delete'){method='DELETE';}
  return {method,url,body};
}
async function autoSend(c){
  if(!$('project').value.trim()) return;            // need a project to form the URL
  const r=buildReq(c); const h={};
  if(TOKEN)h['Authorization']='Bearer '+TOKEN;
  if(['POST','PATCH','PUT'].includes(r.method))h['Content-Type']='application/json';
  try{ await proxy(r.method,r.url,h,r.body); }catch(e){}   // -> backend proxy -> Burp
}

/* send */
function buildHeaders(){const h={};if($('useAuth').value==='yes'&&TOKEN)h['Authorization']='Bearer '+TOKEN;
  ($('headers').value||'').split('\n').forEach(l=>{const i=l.indexOf(':');if(i>0)h[l.slice(0,i).trim()]=l.slice(i+1).trim();});
  const m=$('method').value;if(['POST','PATCH','PUT'].includes(m)&&!Object.keys(h).some(k=>k.toLowerCase()==='content-type'))h['Content-Type']='application/json';return h;}
async function send(){const method=$('method').value,url=$('url').value.trim();if(!url){alert('No URL');return;}
  const body=['GET','DELETE'].includes(method)?null:($('body').value||null);
  $('resp-status').innerHTML='<span class="muted">sending…</span>';
  const r=await proxy(method,url,buildHeaders(),body);LASTRESP=r;renderResp(r);}
function renderResp(r){const cls=r.error?'s0':('s'+String(r.status)[0]);
  $('resp-status').innerHTML=`<span class="status ${cls}">${r.error?'ERROR':r.status+' '+(r.statusText||'')}</span>`;
  $('resp-meta').textContent=`${r._ms} ms · ${(r.body||'').length} bytes`;showTab(curTab);}
let curTab='decoded';
function showTab(t){curTab=t;document.querySelectorAll('.tabs button').forEach(b=>b.classList.toggle('active',b.dataset.t===t));
  const r=LASTRESP;if(!r)return;let out='';
  if(r.error)out=r.error;else if(t==='raw')out=r.body||'';
  else if(t==='hdr')out=Object.entries(r.headers||{}).map(([k,v])=>k+': '+v).join('\n');
  else if(t==='pretty'){try{out=JSON.stringify(JSON.parse(r.body),null,2)}catch(e){out=r.body||''}}
  else{const d=decodeResponse(r.body||'');out=d?JSON.stringify(d,null,2):(r.body||'');}
  $('resp-body').textContent=out;}
window.addEventListener('keydown',e=>{if((e.ctrlKey||e.metaKey)&&e.key==='Enter'){e.preventDefault();send();}});
</script>
</body>
</html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        return

    def _send(self, code, body, ctype="application/json"):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        p = urlparse(self.path)
        if p.path in ("/", "/index.html"):
            self._send(200, INDEX_HTML, "text/html; charset=utf-8")
        elif p.path == "/api/captures":
            since = int((parse_qs(p.query).get("since", ["0"])[0]) or 0)
            with CAP_LOCK:
                out = [c for c in CAPTURES if c["seq"] > since]
            self._send(200, json.dumps(out))
        else:
            self._send(404, '{"error":"not found"}')

    def do_POST(self):
        global CAP_SEQ
        if self.path == "/api/capture":
            try:
                n = int(self.headers.get("Content-Length", 0))
                obj = json.loads(self.rfile.read(n) or b"{}")
            except Exception as e:
                self._send(400, json.dumps({"error": str(e)}))
                return
            with CAP_LOCK:
                CAP_SEQ += 1
                obj["seq"] = CAP_SEQ
                obj.setdefault("ts", time.time())
                CAPTURES.append(obj)
                if len(CAPTURES) > CAP_MAX:
                    del CAPTURES[: len(CAPTURES) - CAP_MAX]
            self._send(200, json.dumps({"ok": True, "seq": CAP_SEQ}))
            return
        if self.path != "/api/send":
            self._send(404, '{"error":"not found"}')
            return
        try:
            n = int(self.headers.get("Content-Length", 0))
            req = json.loads(self.rfile.read(n) or b"{}")
        except Exception as e:
            self._send(400, json.dumps({"error": "bad request: %s" % e}))
            return
        method = (req.get("method") or "GET").upper()
        url = req.get("url") or ""
        headers = req.get("headers") or {}
        body = req.get("body")
        if not url.startswith("https://"):
            self._send(400, json.dumps({"error": "only https URLs allowed"}))
            return
        data = body.encode("utf-8") if isinstance(body, str) else None
        out = {"status": 0, "statusText": "", "headers": {}, "body": "", "error": None}
        try:
            r = urllib.request.Request(url, data=data, method=method)
            for k, v in headers.items():
                r.add_header(k, v)
            with OPENER.open(r, timeout=30) as resp:
                out["status"] = resp.status
                out["statusText"] = resp.reason
                out["headers"] = {k: v for k, v in resp.getheaders()}
                out["body"] = resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            out["status"] = e.code
            out["statusText"] = e.reason
            try:
                out["headers"] = {k: v for k, v in e.headers.items()}
            except Exception:
                pass
            out["body"] = e.read().decode("utf-8", "replace")
        except Exception as e:
            out["error"] = "request failed: %s" % e
        self._send(200, json.dumps(out))


def main():
    global OPENER, PROXY
    ap = argparse.ArgumentParser(description="Firestore Workbench - proxy + repeater for Firestore")
    ap.add_argument("--port", type=int, default=8799)
    ap.add_argument("--host", default="0.0.0.0", help="bind address (0.0.0.0 so the device can post captures)")
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--proxy", default=None, help="route replays through this proxy, e.g. http://127.0.0.1:8080 (Burp)")
    args = ap.parse_args()

    if args.proxy:
        PROXY = args.proxy
        ctx = ssl._create_unverified_context()
        OPENER = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": args.proxy, "https": args.proxy}),
            urllib.request.HTTPSHandler(context=ctx),
        )

    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    gui = "http://127.0.0.1:%d" % args.port
    print("Firestore Workbench: GUI %s  | capture endpoint POST http://<this-PC-LAN-IP>:%d/api/capture" % (gui, args.port))
    if PROXY:
        print("Replays routed through proxy: %s (TLS verify OFF)" % PROXY)
    print("Point firestore_agent.js WORKBENCH at this PC's LAN IP:%d, then run it on the device." % args.port)
    if not args.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(gui)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")
        srv.shutdown()


if __name__ == "__main__":
    main()
