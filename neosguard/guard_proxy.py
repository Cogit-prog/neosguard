"""
NEOS Guard — 프록시/게이트웨이 모드 (zero-code 드롭인)
=====================================================
개발자가 코드 한 줄 안 바꾸고 base_url만 바꾸면, 어떤 OpenAI-호환 LLM API 앞에
자동으로 입력/출력 가드가 낀다. 언어 무관 · 전 세계 공통 = 국제 채택 킬러기능.

사용:
    from openai import OpenAI
    client = OpenAI(base_url="https://api.cogitapp.com/guard/proxy/v1", api_key=OPENAI_KEY)
    # 이후 모든 호출이 자동으로 가드됨 (입력 인젝션 차단 + 출력 유출 마스킹)

헤더:
  Authorization: Bearer <상류 API 키>   (상류로 그대로 전달, 저장 안 함)
  X-NEOS-Upstream: https://api.openai.com/v1/chat/completions  (기본값, 다른 공급자로 교체 가능)
  X-NEOS-Mode: fast|balanced|thorough   (기본 balanced)
  X-NEOS-On-Block: refuse|error         (입력 차단 시 동작, 기본 refuse)
"""
import os, json, time, logging, requests


def _sse(obj) -> str:
    return f"data: {json.dumps(obj)}\n\n"


def stream_sse(body: dict, auth_header: str, upstream: str, mode: str, on_block: str):
    """스트리밍 요청용 제너레이터. 보안 제품이므로 '버퍼→가드→SSE 재전송'(부분 유출 방지).
    점진 토큰 UX는 포기하되 입력/출력 가드를 모두 적용하고 OpenAI SSE 포맷은 유지."""
    resp, status = proxy_chat(body, auth_header, upstream, mode, on_block)
    model = body.get("model", "unknown")
    if status != 200 or "choices" not in resp:
        # 에러/차단도 SSE 한 조각으로 전달 후 종료 (클라이언트 호환)
        content = ((resp.get("choices") or [{}])[0].get("message", {}) or {}).get("content") \
            or (resp.get("error", {}) or {}).get("message", "blocked")
        yield _sse({"id": f"ng-{int(time.time())}", "object": "chat.completion.chunk", "model": model,
                    "choices": [{"index": 0, "delta": {"role": "assistant", "content": content},
                                 "finish_reason": "content_filter"}],
                    "neos_guard": resp.get("neos_guard", {"blocked": True})})
        yield "data: [DONE]\n\n"
        return
    # 가드 통과(또는 마스킹)된 최종 콘텐츠를 청크로 재전송
    for ch in resp.get("choices", []):
        content = (ch.get("message") or {}).get("content") or ""
        yield _sse({"id": resp.get("id"), "object": "chat.completion.chunk", "model": model,
                    "choices": [{"index": ch.get("index", 0), "delta": {"role": "assistant", "content": content},
                                 "finish_reason": ch.get("finish_reason", "stop")}],
                    "neos_guard": resp.get("neos_guard", {"blocked": False})})
    yield "data: [DONE]\n\n"

log = logging.getLogger("guard.proxy")
_DEFAULT_UPSTREAM = "https://api.openai.com/v1/chat/completions"
_ALLOWED_UPSTREAM = ("https://api.openai.com", "https://api.groq.com",
                     "https://api.together.xyz", "https://api.anthropic.com",
                     "https://openrouter.ai", "https://api.mistral.ai",
                     "http://127.0.0.1", "http://localhost")


def _refusal_response(model: str, reason: str) -> dict:
    """OpenAI 포맷 거부 응답 (클라이언트 앱이 깨지지 않게)."""
    return {
        "id": f"neosguard-{int(time.time())}", "object": "chat.completion",
        "created": int(time.time()), "model": model,
        "choices": [{"index": 0, "finish_reason": "content_filter",
                     "message": {"role": "assistant",
                                 "content": "요청을 처리할 수 없습니다. (NEOS Guard: 보안 정책 위반 감지)"}}],
        "neos_guard": {"blocked": True, "stage": "input", "reason": reason},
    }


def proxy_chat(body: dict, auth_header: str, upstream: str, mode: str, on_block: str) -> tuple:
    """(응답dict, http_status) 반환. 입력 가드 → 상류 전달 → 출력 가드."""
    from neosguard.guard import analyze, analyze_output

    upstream = upstream or _DEFAULT_UPSTREAM
    if not any(upstream.startswith(a) for a in _ALLOWED_UPSTREAM):
        return {"error": {"message": f"upstream not allowed: {upstream}", "type": "neos_guard"}}, 400

    model = body.get("model", "unknown")
    msgs = body.get("messages", []) or []
    user_text = " ".join(m.get("content", "") for m in msgs
                         if isinstance(m, dict) and m.get("role") == "user"
                         and isinstance(m.get("content"), str))

    # ① 입력 가드
    guarded_in = None
    if user_text.strip():
        try:
            guarded_in = analyze(user_text, use_llm=True, mode=mode)
        except Exception as e:  # noqa: BLE001
            log.debug(f"[proxy] 입력가드 실패(통과): {e}")
    if guarded_in and guarded_in["risk_score"] >= 70:
        if on_block == "error":
            return {"error": {"message": f"blocked by NEOS Guard: {guarded_in['categories']}",
                              "type": "neos_guard_blocked"}}, 403
        return _refusal_response(model, str(guarded_in["categories"])), 200

    # ② 상류 전달 (스트리밍은 가드불가 → 강제 비스트림)
    fwd = dict(body); fwd["stream"] = False
    try:
        r = requests.post(upstream, headers={"Authorization": auth_header,
                                             "Content-Type": "application/json"},
                          json=fwd, timeout=60)
        up = r.json()
    except Exception as e:  # noqa: BLE001
        return {"error": {"message": f"upstream error: {e}", "type": "neos_guard"}}, 502
    if r.status_code != 200:
        return up, r.status_code

    # ③ 출력 가드 (유출 마스킹)
    try:
        for ch in up.get("choices", []):
            content = (ch.get("message") or {}).get("content")
            if isinstance(content, str) and content.strip():
                out = analyze_output(content, use_llm=(mode == "thorough"), mode=mode)
                if out["risk_score"] >= 70:
                    ch["message"]["content"] = "[NEOS Guard: 민감정보 유출이 감지되어 응답이 차단되었습니다]"
                    up.setdefault("neos_guard", {}).update(
                        {"blocked": True, "stage": "output", "categories": out["categories"]})
    except Exception as e:  # noqa: BLE001
        log.debug(f"[proxy] 출력가드 실패(통과): {e}")
    up.setdefault("neos_guard", {}).setdefault("blocked", False)
    return up, 200
