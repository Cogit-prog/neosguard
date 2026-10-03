"""NEOS Guard — OWASP LLM Top 10 (2025) 커버리지 매핑 (바이어 평가 체크리스트).
정직 원칙: 런타임 가드가 실제로 다루는 것만 '커버', 나머지는 '부분'/'범위 밖' 명시."""

# (id, 제목, 상태, NEOS Guard 대응, 근거)
OWASP = [
    ("LLM01", "Prompt Injection", "covered",
     "Input guard — rules + Meta Prompt Guard 2 + LLM ensemble, self-evolving",
     "Novel 83% / known 99% detection · 0% FP · holdout-verified"),
    ("LLM02", "Sensitive Information Disclosure", "covered",
     "Output guard — secrets engine (gitleaks-grade) + PII engine (Presidio-lite), self-evolving",
     "Known 100% / novel 67% deterministic detection · 0% FP"),
    ("LLM03", "Supply Chain", "out",
     "Out of scope — model/dependency supply-chain integrity is SCA/SBOM territory, not a runtime guard",
     "Honestly a different product category. NEOS Guard focuses on runtime defense"),
    ("LLM04", "Data & Model Poisoning", "out",
     "Out of scope — training-data/model poisoning is training-pipeline governance",
     "A runtime guard can't defend this. Marked honestly as not covered"),
    ("LLM05", "Improper Output Handling", "partial",
     "Dangerous-output detection (opt-in) — SQL/XSS/shell/path-traversal/exfil links in output",
     "Flags downstream-execution risk. Opt-in to avoid FPs for code assistants"),
    ("LLM06", "Excessive Agency", "partial",
     "Behavior guard — destructive actions, hijack execution, privilege escalation, session trajectory",
     "Known 100% / novel 50% · blocks excessive actions via runtime session monitor"),
    ("LLM07", "System Prompt Leakage", "covered",
     "Output guard prompt_leak + self-learned (internal-rule / hidden-rule disclosure)",
     "Deterministic detection of system-prompt / internal-rule disclosure · 0% FP"),
    ("LLM08", "Vector & Embedding Weaknesses", "out",
     "Out of scope — RAG embedding / vector-DB security is retrieval-infra territory",
     "Honestly a different layer. Could extend to a RAG guard later"),
    ("LLM09", "Misinformation", "out",
     "Out of scope — hallucination/factuality is fact-check/grounding product territory",
     "Not what a security guard does. Marked honestly as not covered"),
    ("LLM10", "Unbounded Consumption", "partial",
     "Behavior guard (runaway loops · bot-speed) + API rate limiting",
     "Detects automated/DoS-style consumption patterns + per-tier rate limits"),
]

_LABEL = {"covered": ("✅ Covered", "#2ecc71"), "partial": ("🟡 Partial", "#e8b339"),
          "out": ("⚪ Out of scope", "#8a97ab")}


def render() -> str:
    n_cov = sum(1 for x in OWASP if x[2] == "covered")
    n_par = sum(1 for x in OWASP if x[2] == "partial")
    n_out = sum(1 for x in OWASP if x[2] == "out")
    rows = ""
    for oid, title, status, resp, basis in OWASP:
        lbl, col = _LABEL[status]
        rows += (f"<tr><td class=mut>{oid}</td><td><b>{title}</b><div class=basis>{basis}</div></td>"
                 f"<td style='color:{col};white-space:nowrap'>{lbl}</td><td>{resp}</td></tr>")
    return f"""<!doctype html>
<html lang=ko><head>
<meta charset=utf-8><meta name=viewport content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>NEOS Guard — OWASP LLM Top 10 Coverage</title>
<style>
:root{{--bg:#0b0e14;--card:#151a23;--line:#232c3b;--fg:#e6ebf2;--mut:#8a97ab;--accent:#6ea8fe;--safe:#2ecc71;--warn:#e8b339}}
*{{box-sizing:border-box}}html,body{{margin:0}}
body{{background:var(--bg);color:var(--fg);font:14px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Apple SD Gothic Neo",sans-serif;padding:env(safe-area-inset-top) 16px calc(env(safe-area-inset-bottom) + 40px)}}
.wrap{{max-width:900px;margin:0 auto}}
header{{padding:26px 0 8px}}h1{{margin:0;font-size:22px}}h1 .g{{color:var(--accent)}}
.sub{{color:var(--mut);font-size:13px;margin-top:4px}}
nav{{margin:14px 0;display:flex;gap:14px;flex-wrap:wrap;font-size:13px}}nav a{{color:var(--accent);text-decoration:none}}
.cards{{display:flex;gap:12px;flex-wrap:wrap;margin:14px 0}}
.kpi{{flex:1;min-width:120px;background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px;text-align:center}}
.kpi .n{{font-size:26px;font-weight:800}}.kpi .l{{color:var(--mut);font-size:12px;margin-top:2px}}
table{{width:100%;border-collapse:collapse;margin:10px 0;font-size:13px}}
th,td{{border:1px solid var(--line);padding:9px 10px;text-align:left;vertical-align:top}}th{{background:var(--card);color:var(--mut)}}
.basis{{color:var(--mut);font-size:11.5px;margin-top:3px}}.mut{{color:var(--mut)}}
.note{{background:#1a2030;border:1px solid var(--line);border-left:3px solid var(--warn);border-radius:8px;padding:12px 14px;color:#cdd6e4;font-size:13px;margin:14px 0}}
.foot{{color:var(--mut);font-size:12px;margin-top:30px;text-align:center}}.foot a{{color:var(--accent);text-decoration:none}}
</style></head><body>
<div class=wrap>
<header>
  <h1><span class=g>NEOS</span> Guard — OWASP LLM Top 10 Coverage</h1>
  <div class=sub>Mapped to the enterprise LLM-security evaluation checklist · honest status (2025)</div>
  <nav><a href="/guard/home">Home</a><a href="/guard/docs">Docs & SDK</a><a href="/guard/report">Metrics</a><a href="/guard/evolution">Self-evolution</a></nav>
</header>
<div class=cards>
  <div class=kpi><div class=n style="color:var(--safe)">{n_cov}</div><div class=l>Covered</div></div>
  <div class=kpi><div class=n style="color:var(--warn)">{n_par}</div><div class=l>Partial</div></div>
  <div class=kpi><div class=n style="color:var(--mut)">{n_out}</div><div class=l>Out of scope (honest)</div></div>
</div>
<div class=note>
  <b>Honesty principle:</b> only what a runtime LLM firewall actually handles is marked 'covered'. Supply chain, data
  poisoning, embeddings and misinformation are separate product categories, so we <b>honestly mark them 'out of scope'</b> —
  that earns more trust than an inflated "covers everything" claim. Of the 6 runtime-defensible items: 3 fully covered + 3 partial.
</div>
<table><tr><th>ID</th><th>Threat</th><th>Status</th><th>NEOS Guard coverage</th></tr>
{rows}
</table>
<div class=foot>Numbers verified in the <a href="/guard/report">reproducible report</a> · self-improvement in the <a href="/guard/evolution">evolution log</a></div>
</div></body></html>"""
