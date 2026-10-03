"""
NEOS Guard — LLM05 출력 위험 페이로드 탐지 (opt-in)
===================================================
에이전트 출력이 다운스트림에서 '실행'될 때 위험한 페이로드(SQL삽입·XSS·쉘·경로우회·
exfil 링크·템플릿삽입)를 탐지. 코드 어시스턴트는 정상적으로 코드를 출력하므로 opt-in.

scan_output_risk(text) -> {"risk_score","verdict","categories","reasons"}
"""
import re

_RISK = [
    (re.compile(r"(?i)\b(union\s+select|or\s+1\s*=\s*1|';\s*drop\s+table|;\s*delete\s+from|--\s*$|xp_cmdshell|information_schema)"), "sql_injection", 45),
    (re.compile(r"(?i)(<script\b|javascript:\s*\w|onerror\s*=|onload\s*=|<img[^>]+onerror|document\.cookie|<iframe\b)"), "xss", 45),
    (re.compile(r"(?i)(rm\s+-rf\s+/|:\(\)\s*\{|curl\s+[^\s|]+\s*\|\s*(ba)?sh|wget\s+[^\s|]+\s*\|\s*(ba)?sh|\bchmod\s+777\b|>\s*/etc/|cat\s+/etc/(passwd|shadow))"), "shell_injection", 50),
    (re.compile(r"(\.\./){2,}|\.\.\\(\.\.\\)+|/etc/passwd|/etc/shadow|\bfile://"), "path_traversal", 40),
    (re.compile(r"(?i)(\$\{jndi:|\{\{\s*[\w.]+\s*\}\}|\{\{\s*\d+\s*[*+]\s*\d+|<%=|#\{)"), "template_injection", 42),
    (re.compile(r"!\[[^\]]*\]\(https?://(?!localhost|127\.0\.0\.1)[^)]+\?[^)]*(data|token|key|secret|cookie)=", re.I), "exfil_markdown", 45),
]


def scan_output_risk(text: str) -> dict:
    text = text or ""
    hits, score = [], 0
    for pat, cat, w in _RISK:
        m = pat.search(text)
        if m:
            score = max(score, w)
            hits.append(f"{cat}: {m.group(0)[:40]}")
    # 여러 유형 동시 = 가중
    cats = len({h.split(':')[0] for h in hits})
    if cats >= 2:
        score = min(score + 15, 100)
    verdict = "block" if score >= 70 else "review" if score >= 35 else "allow"
    return {"risk_score": score, "verdict": verdict,
            "categories": [h.split(':')[0] for h in hits],
            "reasons": hits or ["clean"],
            "note": "LLM05 다운스트림 실행 위험(opt-in). 코드 설명 맥락은 정상일 수 있음"}
