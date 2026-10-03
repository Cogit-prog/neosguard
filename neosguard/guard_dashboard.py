"""NEOS Guard 체감 대시보드 (self-contained HTML) — 실시간 차단 현황."""

DASH_HTML = """<!doctype html>
<html lang="ko"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>NEOS Guard Live</title>
<style>
:root{--bg:#0b0e14;--card:#151a23;--line:#232c3b;--fg:#e6ebf2;--mut:#8a97ab;
--safe:#2ecc71;--warn:#f4b740;--bad:#ff5470;--accent:#6ea8fe}
*{box-sizing:border-box}html,body{margin:0}
body{background:var(--bg);color:var(--fg);font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Apple SD Gothic Neo",sans-serif;
padding:env(safe-area-inset-top) 16px calc(env(safe-area-inset-bottom) + 32px)}
.wrap{max-width:860px;margin:0 auto}
header{padding:26px 0 6px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px}
h1{margin:0;font-size:21px;letter-spacing:-.3px}h1 .g{color:var(--accent)}
.live{display:inline-flex;align-items:center;gap:6px;font-size:12px;color:var(--safe);font-weight:600}
.dot{width:8px;height:8px;border-radius:50%;background:var(--safe);box-shadow:0 0 0 0 rgba(46,204,113,.6);animation:p 1.6s infinite}
@keyframes p{0%{box-shadow:0 0 0 0 rgba(46,204,113,.5)}70%{box-shadow:0 0 0 8px rgba(46,204,113,0)}100%{box-shadow:0 0 0 0 rgba(46,204,113,0)}}
.sub{color:var(--mut);font-size:13px;margin:2px 0 18px}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}
@media(max-width:620px){.grid{grid-template-columns:repeat(2,1fr)}}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:16px}
.kpi .n{font-size:30px;font-weight:800;letter-spacing:-1px}
.kpi .l{color:var(--mut);font-size:12px;margin-top:3px}
.kpi.bad .n{color:var(--bad)}.kpi.safe .n{color:var(--safe)}.kpi.acc .n{color:var(--accent)}
.row{display:flex;gap:10px;flex-wrap:wrap;margin-top:12px}
.badge{background:var(--card);border:1px solid var(--line);border-radius:999px;padding:6px 12px;font-size:12px;color:#cdd6e4}
.badge b{color:var(--safe)}
.sec{margin-top:24px;font-size:13px;color:var(--mut);font-weight:700;letter-spacing:.3px;text-transform:uppercase}
.feed{margin-top:10px;border:1px solid var(--line);border-radius:14px;background:var(--card);overflow:hidden}
.item{display:flex;align-items:center;gap:12px;padding:12px 14px;border-top:1px solid var(--line)}
.item:first-child{border-top:0}
.pill{flex:0 0 auto;font-size:11px;font-weight:800;padding:4px 9px;border-radius:7px}
.pill.mal{background:rgba(255,84,112,.15);color:var(--bad)}.pill.rev{background:rgba(244,183,64,.15);color:var(--warn)}
.it-main{flex:1;min-width:0}
.it-cat{font-size:12.5px;color:#dfe6f0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.it-sample{font-size:11.5px;color:var(--mut);font-family:ui-monospace,Menlo,monospace;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin-top:2px}
.it-meta{flex:0 0 auto;text-align:right;font-size:11px;color:var(--mut)}
.empty{padding:26px;text-align:center;color:var(--mut);font-size:13px}
.foot{color:var(--mut);font-size:12px;margin-top:24px;text-align:center;line-height:1.7}
.foot a{color:var(--accent);text-decoration:none}
</style></head><body>
<div class="wrap">
<header>
  <h1><span class="g">NEOS</span> Guard <span style="color:var(--mut);font-weight:500">Live</span></h1>
  <span class="live"><span class="dot"></span> Live — defending now</span>
</header>
<div class="sub">Live view of threats the AI-agent firewall is blocking right now.</div>

<div class="grid">
  <div class="kpi bad"><div class="n" id="k_blocked">–</div><div class="l">total blocked</div></div>
  <div class="kpi"><div class="n" id="k_total">–</div><div class="l">total scans</div></div>
  <div class="kpi bad"><div class="n" id="k_today">–</div><div class="l">blocked today</div></div>
  <div class="kpi acc"><div class="n" id="k_rate">–</div><div class="l">block rate</div></div>
</div>

<div class="row">
  <span class="badge">benchmark detection <b id="b_det">–</b></span>
  <span class="badge">false positives <b id="b_fp">–</b></span>
  <span class="badge" id="b_layers">3 layers: ①input ②output ③behavior</span>
  <span class="badge" id="b_engine">engine –</span>
</div>

<div class="sec">🔁 Self-improvement (verifier-grounded · red-team self-play)</div>
<div class="grid" style="grid-template-columns:repeat(4,1fr)">
  <div class="kpi"><div class="n" id="si_cycles">–</div><div class="l">improvement cycles</div></div>
  <div class="kpi"><div class="n" id="si_tested">–</div><div class="l">attacks tested</div></div>
  <div class="kpi acc"><div class="n" id="si_evad">–</div><div class="l">evasions found</div></div>
  <div class="kpi safe"><div class="n" id="si_learned">–</div><div class="l">rules learned</div></div>
</div>
<div class="sub" style="margin-top:8px">It learns from attacks that got through, so it blocks them next time. A new rule is adopted only if it passes a zero-false-positive check on the benign set.</div>

<div class="sec">🚨 Recently blocked threats (live)</div>
<div class="feed" id="feed"><div class="empty">No records yet — try an attack in the <a href="/guard/demo">demo</a>.</div></div>

<div class="foot">
  Auto-refresh · <a href="/guard/demo">interactive demo ↗</a><br>
  Verifier-grounded self-improvement · self-hostable
</div>
</div>
<script>
function ago(ts){var s=Math.floor(Date.now()/1000-ts);if(s<60)return s+"s ago";if(s<3600)return Math.floor(s/60)+"m ago";if(s<86400)return Math.floor(s/3600)+"h ago";return Math.floor(s/86400)+"d ago"}
function load(){
 fetch("/guard/stats").then(function(r){return r.json()}).then(function(d){
  document.getElementById("k_blocked").textContent=d.blocked;
  document.getElementById("k_total").textContent=d.total;
  document.getElementById("k_today").textContent=d.today_blocked;
  document.getElementById("k_rate").textContent=(d.block_rate||0)+"%";
  var b=d.benchmark||{};var fpl=b.full_pipeline||b;
  document.getElementById("b_det").textContent=(fpl.detection_rate!=null?fpl.detection_rate+"%":"–");
  document.getElementById("b_fp").textContent=(fpl.false_positive_rate!=null?fpl.false_positive_rate+"%":"–");
  document.getElementById("b_engine").textContent="engine "+((d.layers&&d.layers.engine)||"local LLM");
  var si=d.selfimprove||{};
  document.getElementById("si_cycles").textContent=si.cycles!=null?si.cycles:"–";
  document.getElementById("si_tested").textContent=si.attacks_tested!=null?si.attacks_tested:"–";
  document.getElementById("si_evad").textContent=si.evasions_found!=null?si.evasions_found:"–";
  document.getElementById("si_learned").textContent=si.learned_rules!=null?si.learned_rules:"–";
  var feed=document.getElementById("feed");
  var t=d.recent_threats||[];
  if(!t.length){feed.innerHTML='<div class="empty">No records yet — try an attack in the <a href="/guard/demo">demo</a>.</div>';return}
  feed.innerHTML="";
  t.forEach(function(x){
   var mal=x.risk>=70;
   var kind={input:"input",output:"output",behavior:"behavior"}[x.kind]||x.kind;
   var el=document.createElement("div");el.className="item";
   el.innerHTML='<span class="pill '+(mal?"mal":"rev")+'">'+x.risk+'</span>'+
    '<div class="it-main"><div class="it-cat">['+kind+'] '+(x.categories||[]).join(", ")+'</div>'+
    (x.sample?'<div class="it-sample">'+x.sample.replace(/</g,"&lt;")+'</div>':'')+'</div>'+
    '<div class="it-meta">'+ago(x.ts)+'</div>';
   feed.appendChild(el)})
 }).catch(function(){})}
load();setInterval(load,4000);
</script>
</body></html>"""
