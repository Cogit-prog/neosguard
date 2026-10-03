"""
NEOS Guard API 인증 + 레이트리밋 (상업화 게이트)
================================================
프리미엄 모델:
  · 익명(키 없음): 저속 제한 (데모/체험용) — 남용·DoS 방어
  · API 키: 고속 제한 (유료 고객)
키 저장: data/guard_api_keys.json  [{key, name, rpm}]
레이트리밋: 60초 슬라이딩 윈도우 (인메모리, 단일 인스턴스)
"""
import os, json, time, threading
from fastapi import Request, HTTPException

_KEYS_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "guard_api_keys.json")
_ANON_RPM = 30                 # 익명 분당 요청
_hits: dict[str, list] = {}
_lock = threading.Lock()


def _load_keys() -> dict:
    try:
        with open(_KEYS_PATH) as f:
            return {k["key"]: k for k in json.load(f) if k.get("active", True)}
    except Exception:
        return {}


def _read_keys_raw() -> list:
    try:
        with open(_KEYS_PATH) as f:
            return json.load(f)
    except Exception:
        return []


def issue_trial_key(request: Request) -> dict:
    """무료 체험키 자동 발급 (IP당 24시간 1개). Pro는 유료 업그레이드."""
    import secrets
    ip = request.client.host if request.client else "unknown"
    now = time.time()
    keys = _read_keys_raw()
    # 남용 방지: 같은 IP가 24h 내 발급한 trial 있으면 거부
    for k in keys:
        if k.get("created_ip") == ip and k.get("name") == "trial" and now - k.get("created_at", 0) < 86400:
            raise HTTPException(status_code=429, detail="이 IP에서 이미 체험키를 발급했어요. 24시간 후 다시 시도하거나 Pro로 업그레이드하세요.")
    key = "neosg_trial_" + secrets.token_hex(12)
    keys.append({"key": key, "name": "trial", "rpm": 120, "active": True,
                 "created_ip": ip, "created_at": now})
    with open(_KEYS_PATH, "w") as f:
        json.dump(keys, f, ensure_ascii=False, indent=2)
    return {"api_key": key, "tier": "trial", "rpm": 120,
            "usage": "요청 헤더에 X-API-Key: <key> 추가",
            "upgrade": "Pro(600rpm)·Enterprise 문의: /guard/home"}


def guard_gate(request: Request) -> dict:
    """스캔 엔드포인트 게이트: 인증 티어 판정 + 레이트리밋. 초과 시 429."""
    key = request.headers.get("x-api-key") or request.headers.get("X-API-Key") or ""
    keys = _load_keys()
    if key and key in keys:
        ident, rpm, tier, name = "key:" + key, int(keys[key].get("rpm", 600)), "keyed", keys[key].get("name", "")
    else:
        if key:  # 키를 줬는데 무효
            raise HTTPException(status_code=401, detail="invalid API key")
        ip = request.client.host if request.client else "unknown"
        ident, rpm, tier, name = "ip:" + ip, _ANON_RPM, "anonymous", ""

    now = time.time()
    cutoff = now - 60
    with _lock:
        win = _hits.setdefault(ident, [])
        while win and win[0] < cutoff:
            win.pop(0)
        if len(win) >= rpm:
            retry = int(60 - (now - win[0])) + 1
            raise HTTPException(
                status_code=429,
                detail=f"rate limit exceeded ({rpm}/min, tier={tier}). "
                       + ("Retry soon." if tier == "keyed" else "Use an API key for higher limits."),
                headers={"Retry-After": str(retry)},
            )
        win.append(now)
        remaining = rpm - len(win)
    return {"tier": tier, "rpm": rpm, "remaining": remaining, "name": name}
