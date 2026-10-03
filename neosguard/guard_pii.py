"""
NEOS Guard — 결정적 PII(개인식별정보) 탐지 엔진 (Presidio-lite, 결정적·고정밀)
=============================================================================
비밀키 엔진([[guard_secrets]])의 PII 짝. 주민번호·카드(Luhn)·여권·SSN·IBAN 등을
LLM 없이 결정적으로. 정밀도 우선 — 느슨한 숫자매칭 대신 체크섬/문맥 게이트 사용.

scan_pii(text) -> [{"category","weight","match"(마스킹)}]
"""
import re

# 개인정보 '공개/노출' 문맥 신호 (단독 숫자 오탐 억제용)
_PII_CTX = re.compile(
    r"(?i)(주민|여권|계좌|카드|번호|생년월일|전화|휴대폰|고객|환자|직원|회원|개인정보|"
    r"ssn|social security|passport|account|card|phone|dob|date of birth|customer|patient|employee)")


def _luhn(num: str) -> bool:
    d = [int(c) for c in num if c.isdigit()]
    if len(d) < 13:
        return False
    s, alt = 0, False
    for x in reversed(d):
        if alt:
            x *= 2
            if x > 9:
                x -= 9
        s += x
        alt = not alt
    return s % 10 == 0


def _kr_biz_valid(s: str) -> bool:
    """사업자등록번호(10자리) 체크섬 검증."""
    d = re.sub(r"\D", "", s)
    if len(d) != 10:
        return False
    key = [1, 3, 7, 1, 3, 7, 1, 3, 5]
    total = sum(int(d[i]) * key[i] for i in range(9)) + (int(d[8]) * 5) // 10
    return (10 - total % 10) % 10 == int(d[9])


def _kr_rrn_valid(s: str) -> bool:
    """주민등록번호 체크섬(마지막 자리) 검증 — 오탐 대폭 감소."""
    digits = re.sub(r"\D", "", s)
    if len(digits) != 13:
        return False
    w = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5]
    chk = (11 - sum(int(digits[i]) * w[i] for i in range(12)) % 11) % 10
    return chk == int(digits[12])


_CARD = re.compile(r"\b(?:\d[ -]?){13,16}\b")
_RRN = re.compile(r"\b\d{6}[-\s]?[1-4]\d{6}\b")
_RRN_FOREIGN = re.compile(r"\b\d{6}[-\s]?[5-8]\d{6}\b")           # 외국인등록번호(7번째 5~8)
_KR_BIZ = re.compile(r"\b\d{3}-?\d{2}-?\d{5}\b")                  # 사업자등록번호 10자리
_KR_LICENSE = re.compile(r"(?i)(면허|license)\D{0,6}\d{2}[-\s]?\d{2}[-\s]?\d{6}[-\s]?\d{2}")  # 운전면허
_KR_HEALTH = re.compile(r"(?i)(건강보험|보험증|health\s*insurance)\D{0,6}\d[-\s]?\d{9,10}")
_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_PASSPORT = re.compile(r"\b[A-PR-WYa-pr-wy][1-9]\d{6,8}\b")       # 여권(ICAO 근사)
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")
_US_EIN = re.compile(r"\b\d{2}-\d{7}\b")
_PHONE_KR = re.compile(r"\b01[016789][-\s]?\d{3,4}[-\s]?\d{4}\b")
_PHONE_US = re.compile(r"\b(?:\+?1[-\s]?)?\(?\d{3}\)?[-\s]?\d{3}[-\s]?\d{4}\b")
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_KR_ACCT = re.compile(r"(?i)(계좌|account)\D{0,8}\d{2,6}[-\s]?\d{2,6}[-\s]?\d{4,7}")


def scan_pii(text: str) -> list[dict]:
    hits, seen = [], set()
    has_ctx = bool(_PII_CTX.search(text))

    def add(cat, weight, frag):
        if cat in seen:
            return
        seen.add(cat)
        f = str(frag)
        masked = f[:3] + "…" + f[-2:] if len(f) > 7 else f[:2] + "…"
        hits.append({"category": cat, "weight": weight, "match": masked})

    card_pos = re.search(r"(?i)(카드|card|credit|신용|cvv|결제|payment|visa|master|amex)", text)
    card_neg = re.search(r"(?i)(영수증|주문|송장|운송장|receipt|order|invoice|tracking|제품|상품|재고|코드|code)", text)

    # 주민등록번호 — 형식매칭이면 유출(체크섬은 하드게이트 아닌 신뢰도 부스트). 정상 설명문엔 실제 번호 없음.
    for m in _RRN.finditer(text):
        add("pii_leak:kr_rrn", 42 if _kr_rrn_valid(m.group(0)) else 38, m.group(0)); break
    # 외국인등록번호
    m = _RRN_FOREIGN.search(text)
    if m:
        add("pii_leak:kr_foreign_rrn", 40, m.group(0))
    # 사업자등록번호 — 체크섬 유효 or 문맥 있을 때(단독 10자리 오탐 억제)
    for m in _KR_BIZ.finditer(text):
        if _kr_biz_valid(m.group(0)) or re.search(r"(?i)(사업자|법인|등록번호|biz|business)", text):
            add("pii_leak:kr_biz_reg", 36, m.group(0)); break
    # 운전면허 / 건강보험 — 문맥 포함 패턴이라 고정밀
    m = _KR_LICENSE.search(text)
    if m:
        add("pii_leak:kr_license", 36, m.group(0))
    m = _KR_HEALTH.search(text)
    if m:
        add("pii_leak:kr_health", 36, m.group(0))
    # 카드 — Luhn이면 고신뢰(단, 영수증/주문 등 비카드 문맥이면 제외) · 비Luhn은 카드문맥 있을 때만
    for m in _CARD.finditer(text):
        if _luhn(m.group(0)):
            if not (card_neg and not card_pos):
                add("pii_leak:credit_card", 42, m.group(0)); break
        elif card_pos:
            add("pii_leak:credit_card", 38, m.group(0)); break
    # SSN
    m = _SSN.search(text)
    if m:
        add("pii_leak:us_ssn", 38, m.group(0))
    # 여권 — 문맥 있을 때만(알파벳+숫자는 오탐 많음)
    if has_ctx:
        m = _PASSPORT.search(text)
        if m:
            add("pii_leak:passport", 36, m.group(0))
    # IBAN
    m = _IBAN.search(text)
    if m:
        add("pii_leak:iban", 36, m.group(0))
    # US EIN — 문맥 게이트
    if has_ctx:
        m = _US_EIN.search(text)
        if m:
            add("pii_leak:us_ein", 30, m.group(0))
    # 계좌번호 — 문맥 내에서만
    m = _KR_ACCT.search(text)
    if m:
        add("pii_leak:bank_account", 34, m.group(0))
    # 전화 — 문맥 게이트(단독 숫자 오탐 억제)
    if has_ctx:
        m = _PHONE_KR.search(text) or _PHONE_US.search(text)
        if m:
            add("pii_leak:phone", 24, m.group(0))
    # 이메일 — 목록(≥3)이면 유출, 아니면 개인정보 공개문맥에서 저가중(전화 등과 합산되게)
    emails = _EMAIL.findall(text)
    if len(emails) >= 3:
        add("pii_leak:email_list", 34, emails[0])
    elif emails and re.search(r"(?i)(목록|내부|유출|명단|list|internal|leak|dump)", text):
        add("pii_leak:email", 20, emails[0])
    elif emails and has_ctx and any(h["category"].startswith("pii_leak:") for h in hits):
        add("pii_leak:email", 18, emails[0])   # 다른 PII와 공동노출 = 개인 연락처 유출
    return hits
