"""
NEOS Guard — 결정적 비밀/자격증명 탐지 엔진 (gitleaks급, 결정적·고정밀)
=====================================================================
provider-prefix 앵커 기반이라 오탐 거의 0. 출력 가드가 '알려진 비밀 유출'을
LLM 없이 결정적으로(재현 가능) 거의 100% 잡게 하는 백본.

confirmed provider 시크릿 = weight 70(단독 BLOCK). 포맷 설명/플레이스홀더는 제외.
scan_secrets(text) -> [{"category","weight","match"(마스킹)}]
"""
import re

# 플레이스홀더/예시는 유출 아님 (negative guard)
_PLACEHOLDER = re.compile(
    r"(?i)(your[_\s-]|<[^>]*>|xxx+|example|placeholder|changeme|redacted|\.\.\.|\*\*\*|"
    r"\{\{|token[_\s-]?here|api[_\s-]?key[_\s-]?here|dummy|sample|testkey|foobar)")

# (이름, 정규식, weight). weight 70=단독 차단, 40~=검토.
_SECRETS: list[tuple[str, re.Pattern, int]] = [
    # --- Cloud ---
    ("aws_access_key", re.compile(r"\b(A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA|AIDA)[A-Z0-9]{16}\b"), 70),
    ("aws_secret_ctx", re.compile(r"(?i)aws_?secret_?access_?key\s*[:=]\s*['\"]?[A-Za-z0-9/+]{40}"), 70),
    ("gcp_api_key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), 70),
    ("gcp_oauth", re.compile(r"\bya29\.[0-9A-Za-z\-_]{30,}"), 70),
    ("gcp_service_acct", re.compile(r'"private_key_id"\s*:\s*"[a-f0-9]{40}"'), 70),
    ("azure_storage", re.compile(r"(?i)AccountKey\s*=\s*[A-Za-z0-9+/]{66,}==")  , 70),
    # --- Payment ---
    ("stripe_secret", re.compile(r"\b(sk|rk)_(live|test)_[A-Za-z0-9]{16,}"), 70),
    ("stripe_webhook", re.compile(r"\bwhsec_[A-Za-z0-9]{32,}"), 60),
    ("square_token", re.compile(r"\b(sq0atp|sq0csp|EAAA)[A-Za-z0-9\-_]{22,}"), 70),
    ("paypal_braintree", re.compile(r"\baccess_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}\b"), 70),
    # --- Source / CI ---
    ("github_token", re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b"), 70),
    ("github_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}"), 70),
    ("gitlab_pat", re.compile(r"\bglpat-[A-Za-z0-9\-_]{20,}"), 70),
    ("npm_token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), 70),
    ("pypi_token", re.compile(r"\bpypi-AgEIcHlwaS[A-Za-z0-9\-_]{50,}"), 70),
    # --- Comms / SaaS ---
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"), 70),
    ("slack_webhook", re.compile(r"https://hooks\.slack\.com/services/T[A-Za-z0-9/]{20,}"), 60),
    ("discord_webhook", re.compile(r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d{17,}/[A-Za-z0-9\-_]{60,}"), 60),
    ("discord_bot", re.compile(r"\b[MNO][A-Za-z0-9]{23}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27,}"), 60),
    ("twilio_sk", re.compile(r"\bSK[0-9a-fA-F]{32}\b"), 60),
    ("sendgrid", re.compile(r"\bSG\.[A-Za-z0-9\-_]{16,}\.[A-Za-z0-9\-_]{16,}"), 70),
    ("mailgun", re.compile(r"\bkey-[0-9a-f]{32}\b"), 60),
    ("mailchimp", re.compile(r"\b[0-9a-f]{32}-us[0-9]{1,2}\b"), 60),
    ("shopify", re.compile(r"\bshp(at|ss|pa|ca)_[A-Fa-f0-9]{32}\b"), 70),
    ("telegram_bot", re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b"), 55),
    # --- AI providers ---
    ("openai_key", re.compile(r"\bsk-(proj-)?[A-Za-z0-9_\-]{20,}"), 70),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}"), 70),
    ("huggingface", re.compile(r"\bhf_[A-Za-z0-9]{30,}"), 70),
    ("groq_key", re.compile(r"\bgsk_[A-Za-z0-9]{40,}"), 70),
    # --- Infra ---
    ("digitalocean", re.compile(r"\b(dop|doo|dor)_v1_[a-f0-9]{64}\b"), 70),
    ("datadog", re.compile(r"(?i)dd(api|app)key\s*[:=]\s*['\"]?[a-f0-9]{32,40}"), 60),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), 50),
    ("bearer", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-]{20,}"), 45),
    # --- Keys / DB ---
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"), 70),
    ("db_conn_creds", re.compile(r"\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://[^\s:@/]+:[^\s:@/]+@"), 70),
    ("ssh_passphrase", re.compile(r"(?i)(ssh|key)\s*pass(phrase|word)\s*(is|:|=)\s*['\"]?\S{4,}"), 45),
    # --- Generic labeled (플레이스홀더 제외는 호출부에서) ---
    ("generic_labeled", re.compile(
        r"(?i)\b(password|passwd|pwd|secret|secret[_\s-]?key|api[_\s-]?key|access[_\s-]?token|"
        r"auth[_\s-]?token|client[_\s-]?secret|private[_\s-]?key|credential)s?\s*[:=]\s*['\"]?\S{6,}"), 40),
]


def scan_secrets(text: str) -> list[dict]:
    """결정적 비밀 패턴 스캔. 플레이스홀더/예시는 제외."""
    hits, seen = [], set()
    for name, pat, weight in _SECRETS:
        m = pat.search(text)
        if not m:
            continue
        frag = m.group(0)
        # 플레이스홀더/예시 값이면 스킵 (generic/bearer/jwt 등 완화계열만)
        if weight <= 50 and _PLACEHOLDER.search(frag):
            continue
        if name in seen:
            continue
        seen.add(name)
        masked = frag[:6] + "…" + frag[-2:] if len(frag) > 12 else frag[:3] + "…"
        hits.append({"category": f"secret_leak:{name}", "weight": weight, "match": masked})
    return hits
