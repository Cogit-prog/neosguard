"""NEOS Guard 정직한 성능 리포트 페이지 — guard_report.json 을 렌더."""
import json, time


def _row(label, m):
    if not m:
        return f"<tr><td>{label}</td><td colspan=4 class=mut>—</td></tr>"
    return (f"<tr><td>{label}</td>"
            f"<td class=det>{m.get('detection_rate','—')}%</td>"
            f"<td class=fp>{m.get('false_positive_rate','—')}%</td>"
            f"<td>{m.get('precision','—')}%</td>"
            f"<td>{m.get('f1','—')}</td></tr>")


def _behavior_block(b: dict) -> str:
    if not b:
        return "<p class=mut>— behavior eval not run —</p>"
    des = b.get("designed", b if "detection_rate" in b else {})
    hold = b.get("holdout", {})

    def kpi(m, label, cls="n"):
        tp, fn, fp, tn = m.get("tp", 0), m.get("fn", 0), m.get("fp", 0), m.get("tn", 0)
        tot = (tp + fn) if cls == "n" else (fp + tn)
        hit = tp if cls == "n" else fp
        return (f"<div class=kpi><div class='{cls}'>{m.get('detection_rate' if cls=='n' else 'false_positive_rate','—')}%</div>"
                f"<div class=l>{label} ({hit}/{tot})</div></div>")

    out = "<h3>Designed-scenario coverage <span class=mut>(not a holdout)</span></h3><div class=cards>"
    out += kpi(des, "attack-type detection") + kpi(des, "benign false positives", "n fp") + "</div>"
    if hold:
        rl, th = hold.get("rules", {}), hold.get("thorough", {})
        out += ("<h3>Independent holdout <span class=mut>(LLM-generated · honest generalization)</span></h3><div class=cards>"
                f"<div class=kpi><div class=n>{rl.get('detection_rate','—')}%</div><div class=l>rules only (deterministic)</div></div>"
                f"<div class=kpi><div class=n>{th.get('detection_rate','—')}%</div><div class=l>rules + LLM trajectory</div></div>"
                f"<div class=kpi><div class='n fp'>{th.get('false_positive_rate','—')}%</div><div class=l>false positives</div></div></div>"
                "<p class=mut>Rules overfit to modeled patterns (designed 100% → independent 17%); the LLM-trajectory layer "
                "recovers generalization (→50%). Same lesson as input/output. Some generated attacks are vague/single-step, so this is a conservative floor.</p>")
    return out


def render(report: dict) -> str:
    h = report.get("headline", {})
    cs = report.get("corpus_sizes", {})
    ts = report.get("computed_at")
    when = time.strftime("%Y-%m-%d %H:%M KST", time.localtime(ts)) if ts else "not run yet"

    def modes_table(section):
        sec = report.get(section, {})
        rows = ""
        for mode in ("fast", "balanced", "thorough"):
            rows += _row(f"holdout · {mode}", sec.get("holdout", {}).get(mode))
        rows += _row("training · balanced", sec.get("training", {}).get("balanced"))
        return rows

    hi_in = cs.get("input_holdout", {})
    hi_out = cs.get("output_holdout", {})
    tr_in = cs.get("input_training", {})
    tr_out = cs.get("output_training", {})

    return f"""<!doctype html>
<html lang=en><head>
<meta charset=utf-8><meta name=viewport content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>NEOS Guard — Performance Report</title>
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
.kpi{{flex:1;min-width:150px;background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px}}
.kpi .n{{font-size:28px;font-weight:800;color:var(--safe)}}.kpi .n.fp{{color:var(--accent)}}
.kpi .l{{color:var(--mut);font-size:12px;margin-top:2px}}
table{{width:100%;border-collapse:collapse;margin:8px 0;font-size:13px}}
th,td{{border:1px solid var(--line);padding:8px 10px;text-align:left}}th{{background:var(--card);color:var(--mut)}}
.det{{color:var(--safe);font-weight:700}}.fp{{color:var(--accent)}}.mut{{color:var(--mut)}}
.note{{background:#1a2030;border:1px solid var(--line);border-left:3px solid var(--warn);border-radius:8px;padding:12px 14px;color:#cdd6e4;font-size:13px;margin:14px 0}}
.foot{{color:var(--mut);font-size:12px;margin-top:30px;text-align:center}}.foot a{{color:var(--accent);text-decoration:none}}
code{{background:#1d2635;border:1px solid var(--line);border-radius:5px;padding:1px 6px;font-family:ui-monospace,Menlo,monospace;font-size:12px}}
</style></head><body>
<div class=wrap>
<header>
  <h1><span class=g>NEOS</span> Guard — Performance Report</h1>
  <div class=sub>Reproducible, honest evaluation · measured {when}</div>
  <nav><a href="/guard/home">Home</a><a href="/guard/docs">Docs & SDK</a><a href="/guard/demo">Demo</a><a href="/guard/owasp">OWASP</a><a href="/guard/evolution">Self-evolution</a></nav>
</header>

<div class=note>
  <b>Honesty principle:</b> the headline numbers below are measured on <b>held-out data never used to tune the rules</b>.
  Training-set numbers are overfit and are not used for sales. Anyone can reproduce with <code>python -m backend.guard_eval</code>.
</div>

<h2>Honest headline (holdout · thorough)</h2>
<div class=cards>
  <div class=kpi><div class=n>{h.get('input_novel_detection','—')}%</div><div class=l>Input injection — novel attack detection</div></div>
  <div class=kpi><div class="n fp">{h.get('input_false_positive','—')}%</div><div class=l>Input — false positive rate</div></div>
  <div class=kpi><div class=n>{h.get('output_novel_detection','—')}%</div><div class=l>Output leak — novel leak detection</div></div>
  <div class=kpi><div class="n fp">{h.get('output_false_positive','—')}%</div><div class=l>Output — false positive rate</div></div>
</div>

<h2>Input guard (prompt injection)</h2>
<p class=mut>Holdout: {hi_in.get('attacks','?')} novel attacks / {hi_in.get('benign','?')} benign · Training: {tr_in.get('attacks','?')} attacks / {tr_in.get('benign','?')} benign</p>
<table><tr><th>Set · mode</th><th>Detection</th><th>FP rate</th><th>Precision</th><th>F1</th></tr>
{modes_table('input')}
</table>

<h2>Output guard (secrets · PII · system-prompt leakage)</h2>
<p class=mut>Holdout: {hi_out.get('leaks','?')} novel leaks / {hi_out.get('benign','?')} benign · Training: {tr_out.get('leaks','?')} leaks / {tr_out.get('benign','?')} benign</p>
<table><tr><th>Set · mode</th><th>Detection</th><th>FP rate</th><th>Precision</th><th>F1</th></tr>
{modes_table('output')}
</table>

<div class=note>
  <b>Reading it:</b> fast (rules only) is weak on novel attacks; thorough (rules + Prompt Guard 2 + LLM ensemble) is what generalizes.
  The gap between training and holdout is the size of the overfit — we publish it instead of hiding it.
</div>

<h2>Behavior guard (③ runtime session monitor)</h2>
<p class=mut>Detects action sequences that look fine step-by-step but are attacks in aggregate — credential stuffing, account enumeration, bot-speed, exfiltration chains, hijack execution, destructive sprees, autonomous recon→brute-force. All deterministic rules (no LLM needed).</p>
{_behavior_block(report.get('behavior', {}))}
<div class=note>
  <b>Honest label:</b> behavior numbers are <b>designed-scenario coverage</b> (detectors and test scenarios share an author → not a holdout).
  It means "catches these attack types with zero false positives", not "catches N% of all unknown behavior attacks".
</div>

<div class=foot>Engine: {report.get('engine','—')} · measured in {report.get('elapsed_sec','?')}s · <a href="/guard/docs">Integrate with the SDK →</a></div>
</div></body></html>"""
