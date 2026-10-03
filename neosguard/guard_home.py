"""NEOS Guard landing/pricing page (self-contained HTML). International, English-first."""
HOME_HTML = """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>NEOS Guard</title>
<style>
:root{--bg:#0b0e14;--card:#151a23;--line:#232c3b;--fg:#e6ebf2;--mut:#8a97ab;--accent:#6ea8fe;--safe:#2ecc71;--bad:#ff5470;--warn:#e8b339}
*{box-sizing:border-box}html,body{margin:0}
body{background:var(--bg);color:var(--fg);font:14px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;padding:env(safe-area-inset-top) 16px calc(env(safe-area-inset-bottom) + 44px)}
.wrap{max-width:880px;margin:0 auto}
.hero{padding:50px 0 24px;text-align:center}
.tag{display:inline-block;background:#1d2635;border:1px solid var(--line);border-radius:999px;padding:5px 13px;font-size:12px;color:var(--accent);margin-bottom:16px}
h1{margin:0;font-size:36px;letter-spacing:-.8px;line-height:1.15}h1 .g{color:var(--accent)}
.lead{color:var(--mut);font-size:16px;margin:14px auto 0;max-width:600px}
.cta{margin-top:24px;display:flex;gap:10px;justify-content:center;flex-wrap:wrap}
.btn{border:0;border-radius:11px;padding:12px 20px;font-size:14px;font-weight:700;cursor:pointer;text-decoration:none}
.btn.p{background:var(--accent);color:#08111f}.btn.s{background:var(--card);color:var(--fg);border:1px solid var(--line)}
.why{background:#1a1420;border:1px solid #3a2530;border-left:3px solid var(--bad);border-radius:10px;padding:14px 16px;margin:26px 0;font-size:13.5px;color:#e6d3d8}
.why b{color:#ff8fa3}
.metrics{display:flex;gap:12px;justify-content:center;flex-wrap:wrap;margin:26px 0}
.metric{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:16px 20px;min-width:120px}
.metric .n{font-size:24px;font-weight:800}.metric .n.safe{color:var(--safe)}.metric .n.acc{color:var(--accent)}.metric .l{color:var(--mut);font-size:12px;margin-top:2px}
h2{font-size:20px;margin:40px 0 6px;text-align:center}
.psub{color:var(--mut);text-align:center;margin:0 0 20px}
.layers{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}
@media(max-width:680px){.layers{grid-template-columns:1fr}}
.layer{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:18px}
.layer .no{color:var(--accent);font-weight:800;font-size:13px}
.layer h3{margin:6px 0;font-size:15px}.layer p{color:var(--mut);font-size:13px;margin:0}
.feat{display:grid;grid-template-columns:repeat(2,1fr);gap:10px;margin-top:8px}
@media(max-width:680px){.feat{grid-template-columns:1fr}}
.fitem{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px}
.fitem b{font-size:14px}.fitem p{color:var(--mut);font-size:12.5px;margin:4px 0 0}
pre{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px;overflow-x:auto;font:12.5px/1.5 ui-monospace,Menlo,monospace;color:#dfe6f0}
.plans{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}
@media(max-width:760px){.plans{grid-template-columns:repeat(2,1fr)}}
.plan{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:18px;text-align:center}
.plan.hi{border-color:var(--accent);box-shadow:inset 0 0 0 1px var(--accent)}
.plan .name{font-weight:700}.plan .price{font-size:22px;font-weight:800;margin:8px 0}
.plan .lim{color:var(--mut);font-size:12px;min-height:32px}
.plan .b{margin-top:10px;display:block}
.foot{color:var(--mut);font-size:12px;margin-top:40px;text-align:center;line-height:1.8}.foot a{color:var(--accent);text-decoration:none}
</style></head><body>
<div class="wrap">
<div class="hero">
  <div class="tag">🛡️ AI-native security · self-hostable · multilingual</div>
  <h1><span class="g">NEOS</span> Guard</h1>
  <div class="lead">A firewall for AI agents. Blocks prompt injection, data leakage, and autonomous attack patterns in real time — across input, output, and runtime behavior. Self-improving, with reproducible metrics.</div>
  <div class="cta">
    <a class="btn p" href="/guard/demo">Try the demo →</a>
    <a class="btn s" href="/guard/docs">Docs & SDK</a>
    <a class="btn s" href="/guard/report">Honest metrics</a>
  </div>
</div>

<div class="why">
  <b>Why now:</b> Autonomous, LLM-powered attack tools are now open-source and hitting real production systems — automating prompt injection, credential stuffing, and data exfiltration in multiple languages. Static filters written for yesterday's attacks can't keep up. AI-native threats need an AI-native, self-evolving defense.
</div>

<div class="metrics">
  <div class="metric"><div class="n safe">0%</div><div class="l">false positives (verified)</div></div>
  <div class="metric"><div class="n acc">99% / 83%</div><div class="l">known / novel injection</div></div>
  <div class="metric"><div class="n">3-layer</div><div class="l">input · output · behavior</div></div>
  <div class="metric"><div class="n acc">EN·KO·JA·ZH</div><div class="l">multilingual native</div></div>
</div>
<p class="psub" style="margin-top:-10px"><a href="/guard/report" style="color:var(--accent);text-decoration:none">All numbers are reproducible on held-out data → see the honest report</a></p>

<h2>3-layer defense</h2>
<p class="psub">The whole agent lifecycle — not just the prompt.</p>
<div class="layers">
  <div class="layer"><div class="no">① INPUT</div><h3>Injection blocking</h3><p>Detects hidden instructions, jailbreaks, and prompt-leak attempts in content your agent reads (web, email, tool output). Rules + Prompt Guard 2 + LLM ensemble.</p></div>
  <div class="layer"><div class="no">② OUTPUT</div><h3>Leak prevention</h3><p>Catches secret keys, credentials, PII (national IDs, cards), and system-prompt disclosure before they leave — deterministic secrets + PII engines.</p></div>
  <div class="layer"><div class="no">③ BEHAVIOR</div><h3>Runtime monitor</h3><p>Tracks the session's action sequence to catch exfiltration chains, hijack execution, credential stuffing, enumeration, and bot-speed automation.</p></div>
</div>

<h2>Drop in — in 5 seconds or 5 minutes</h2>
<p class="psub">No rewrite. Change one line, or add one decorator.</p>
<pre># Proxy mode — zero code change, guards any OpenAI-compatible API
client = OpenAI(base_url="https://api.cogitapp.com/guard/proxy/v1", api_key=KEY)

# or SDK — one decorator
from neosguard import Guard
guard = Guard(api_key="...")
@guard.protect
def agent(user_text): ...</pre>

<h2>What makes it different</h2>
<div class="feat">
  <div class="fitem"><b>🔁 Self-evolving</b><p>A red-team loop invents new attacks; a hard verifier adopts a defense only if it catches the attack with zero new false positives — so it strengthens monotonically, never degrades.</p></div>
  <div class="fitem"><b>🌏 Multilingual native</b><p>Attacks and leaks in English, Korean, Japanese, Chinese — not an English-only filter. Global agents face global attackers.</p></div>
  <div class="fitem"><b>🔒 Self-hostable & free tier</b><p>Run fully local (no data leaves your infra) or use the hosted API. Free to start.</p></div>
  <div class="fitem"><b>📊 Honest & reproducible</b><p>No "99% accuracy" marketing. Held-out metrics, OWASP LLM Top 10 coverage, and a self-improvement log — all public.</p></div>
</div>

<h2>Pricing</h2>
<p class="psub">Free to start. Scale as you grow.</p>
<div class="plans">
  <div class="plan"><div class="name">Anonymous</div><div class="price">Free</div><div class="lim">30 req/min · no key</div><a class="btn s b" href="/guard/demo">Try</a></div>
  <div class="plan hi"><div class="name">Trial</div><div class="price">Free</div><div class="lim">120 req/min · instant key</div><button class="btn p b" id="trial">Get key</button></div>
  <div class="plan"><div class="name">Pro</div><div class="price">Contact</div><div class="lim">600 req/min · priority</div><a class="btn s b" href="/guard/docs">Docs</a></div>
  <div class="plan"><div class="name">Self-host</div><div class="price">Open</div><div class="lim">Run it on your own infra</div><a class="btn s b" href="/guard/docs">Docs</a></div>
</div>
<pre id="keybox" style="display:none;white-space:pre-wrap"></pre>

<div class="foot">
  Runtime guard & session monitor — integrate via SDK or proxy. Not a network WAF.<br>
  <a href="/guard/demo">Demo</a> · <a href="/guard/docs">Docs & SDK</a> · <a href="/guard/report">Metrics</a> · <a href="/guard/owasp">OWASP coverage</a> · <a href="/guard/evolution">Self-evolution</a>
</div>
</div>
<script>
document.getElementById("trial").onclick=function(){
 var b=this;b.disabled=true;b.textContent="Issuing…";
 fetch("/guard/keys/trial",{method:"POST"}).then(function(r){return r.json().then(function(j){return{ok:r.ok,j:j}})})
 .then(function(o){var box=document.getElementById("keybox");box.style.display="block";
  box.textContent=o.ok?("\\u2705 Free trial key (120 req/min)\\n\\nX-API-Key: "+o.j.api_key+"\\n\\n"+o.j.usage+"\\nDocs: /guard/docs"):("Failed: "+(o.j.detail||"error"));
 }).catch(function(e){alert("error:"+e)}).finally(function(){b.disabled=false;b.textContent="Get key"})};
</script>
</body></html>"""
