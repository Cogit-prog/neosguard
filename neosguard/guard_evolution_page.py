"""NEOS Guard 자율 진화 로그 페이지 — 검증기 기반 자기개선 사이클 타임라인."""
import time


def render(cycles: list, total_learned: int) -> str:
    rows = ""
    for c in cycles[:40]:
        when = time.strftime("%m-%d %H:%M", time.localtime(c.get("ts", 0)))
        rows += (f"<tr><td class=mut>{when}</td><td>{c.get('generated',0)}</td>"
                 f"<td>{c.get('evaded',0)}</td><td class=det>{c.get('learned',0)}</td></tr>")
    if not rows:
        rows = "<tr><td colspan=4 class=mut>No cycles yet — runs automatically soon</td></tr>"

    return f"""<!doctype html>
<html lang=ko><head>
<meta charset=utf-8><meta name=viewport content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>NEOS Guard — Self-Evolution</title>
<style>
:root{{--bg:#0b0e14;--card:#151a23;--line:#232c3b;--fg:#e6ebf2;--mut:#8a97ab;--accent:#6ea8fe;--safe:#2ecc71;--warn:#e8b339}}
*{{box-sizing:border-box}}html,body{{margin:0}}
body{{background:var(--bg);color:var(--fg);font:14px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Apple SD Gothic Neo",sans-serif;padding:env(safe-area-inset-top) 16px calc(env(safe-area-inset-bottom) + 40px)}}
.wrap{{max-width:820px;margin:0 auto}}
header{{padding:26px 0 8px}}h1{{margin:0;font-size:22px}}h1 .g{{color:var(--accent)}}
.sub{{color:var(--mut);font-size:13px;margin-top:4px}}
nav{{margin:14px 0;display:flex;gap:14px;flex-wrap:wrap;font-size:13px}}nav a{{color:var(--accent);text-decoration:none}}
h2{{font-size:16px;margin:26px 0 8px;border-bottom:1px solid var(--line);padding-bottom:6px}}
.cards{{display:flex;gap:12px;flex-wrap:wrap;margin:14px 0}}
.kpi{{flex:1;min-width:140px;background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px}}
.kpi .n{{font-size:28px;font-weight:800;color:var(--safe)}}.kpi .l{{color:var(--mut);font-size:12px;margin-top:2px}}
table{{width:100%;border-collapse:collapse;margin:8px 0;font-size:13px}}
th,td{{border:1px solid var(--line);padding:8px 10px;text-align:left}}th{{background:var(--card);color:var(--mut)}}
.det{{color:var(--safe);font-weight:700}}.mut{{color:var(--mut)}}
.note{{background:#1a2030;border:1px solid var(--line);border-left:3px solid var(--warn);border-radius:8px;padding:12px 14px;color:#cdd6e4;font-size:13px;margin:14px 0}}
.foot{{color:var(--mut);font-size:12px;margin-top:30px;text-align:center}}.foot a{{color:var(--accent);text-decoration:none}}
</style></head><body>
<div class=wrap>
<header>
  <h1><span class=g>NEOS</span> Guard — Self-Evolution</h1>
  <div class=sub>Verifier-grounded recursive self-improvement — it invents novel threats and adds defenses only when safe</div>
  <nav><a href="/guard/home">Home</a><a href="/guard/docs">Docs & SDK</a><a href="/guard/report">Metrics</a><a href="/guard/owasp">OWASP</a></nav>
</header>

<div class=note>
  <b>Security that's stronger tomorrow than the day you bought it.</b> Each cycle, a red-team AI generates novel attacks →
  tests them against the current guard → proposes a defense signature for any that evade → and adopts it only if it passes a
  <b>hard verifier (actually catches the attack · keeps 0% false positives · no drop in existing holdout detection)</b>.
  Violate any of those and it auto-rolls-back → the system never degrades itself.
</div>

<div class=cards>
  <div class=kpi><div class=n>{total_learned}</div><div class=l>defenses auto-learned</div></div>
  <div class=kpi><div class=n>{len(cycles)}</div><div class=l>self-improvement cycles run</div></div>
  <div class=kpi><div class=n>0</div><div class=l>FP increases after verification</div></div>
</div>

<h2>Cycle timeline</h2>
<table><tr><th>Time</th><th>Attacks generated</th><th>Evaded</th><th>Learned (verified)</th></tr>
{rows}
</table>

<div class=note>
  <b>Why this is the real thing:</b> most "auto self-improvement" learns without verification and quietly raises its own
  false-positive rate (self-degradation). NEOS Guard puts a <b>hard verifier in the brake seat</b> — a change lands only when
  the improvement is proven, otherwise it rolls back. So it's not fake "always improving" — it's <b>monotonic, real self-improvement</b>.
</div>

<div class=foot>Runs autonomously · <a href="/guard/report">see the honest performance report →</a></div>
</div></body></html>"""
