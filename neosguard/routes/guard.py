"""
NEOS Guard API — 프롬프트 인젝션 / AI 에이전트 위협 탐지
POST /guard          — 텍스트 위협 분석 (risk_score 0~100)
POST /guard/batch    — 여러 텍스트 일괄 분석
GET  /guard/health   — 룰셋/LLM 상태
"""
import os
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel
from neosguard.guard_auth import guard_gate

router = APIRouter(prefix="/guard", tags=["guard"])

_SDK_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                         "sdk", "neosguard.py")

# 스캔 엔드포인트 공통 게이트 (인증+레이트리밋). 데모/대시보드/stats/health 는 공개.
_GATE = [Depends(guard_gate)]


@router.get("/demo", response_class=HTMLResponse)
def guard_demo():
    from neosguard.guard_demo import DEMO_HTML
    return HTMLResponse(DEMO_HTML)


@router.get("/dashboard", response_class=HTMLResponse)
def guard_dashboard():
    from neosguard.guard_dashboard import DASH_HTML
    return HTMLResponse(DASH_HTML)


@router.get("/home", response_class=HTMLResponse)
def guard_home():
    from neosguard.guard_home import HOME_HTML
    return HTMLResponse(HOME_HTML)


@router.get("/docs", response_class=HTMLResponse)
def guard_docs_page():
    from neosguard.guard_docs import DOCS_HTML
    return HTMLResponse(DOCS_HTML)


@router.get("/report", response_class=HTMLResponse)
def guard_report_page():
    """재현 가능한 정직한 성능 리포트 (홀드아웃 기준)."""
    from neosguard.guard_eval import load_report
    from neosguard.guard_report_page import render
    return HTMLResponse(render(load_report()))


@router.get("/report/json")
def guard_report_json():
    from neosguard.guard_eval import load_report
    return load_report()


@router.get("/owasp", response_class=HTMLResponse)
def guard_owasp_page():
    """OWASP LLM Top 10 커버리지 매핑 (바이어 평가 체크리스트)."""
    from neosguard.guard_owasp import render
    return HTMLResponse(render())


@router.post("/output/risk", dependencies=_GATE)
def guard_output_risk(body: GuardRequest):
    """LLM05 — 에이전트 출력의 다운스트림 실행 위험 페이로드 탐지(SQL/XSS/쉘/exfil)."""
    from neosguard.guard_output_risk import scan_output_risk
    return scan_output_risk(body.text)


@router.post("/proxy/v1/chat/completions", dependencies=_GATE)
async def guard_proxy_chat(request: Request):
    """zero-code 드롭인 프록시 — base_url만 여기로 바꾸면 OpenAI-호환 API가 자동 가드됨."""
    from fastapi.responses import JSONResponse, StreamingResponse
    from neosguard.guard_proxy import proxy_chat, stream_sse
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": {"message": "invalid JSON", "type": "neos_guard"}}, status_code=400)
    auth = request.headers.get("authorization", "")
    upstream = request.headers.get("x-neos-upstream", "")
    mode = request.headers.get("x-neos-mode", "balanced")
    on_block = request.headers.get("x-neos-on-block", "refuse")
    if body.get("stream"):
        # 보안 제품: 버퍼→가드→SSE 재전송 (부분 유출 방지, 클라이언트 SSE 호환)
        return StreamingResponse(stream_sse(body, auth, upstream, mode, on_block),
                                 media_type="text/event-stream")
    resp, status = proxy_chat(body, auth, upstream, mode, on_block)
    return JSONResponse(resp, status_code=status)


@router.get("/evolution", response_class=HTMLResponse)
def guard_evolution_page():
    """자율 진화 로그 — 검증기 기반 자기개선 사이클 타임라인."""
    from neosguard.guard_redteam import get_cycles
    from neosguard.guard_evolution_page import render
    data = get_cycles(40)
    return HTMLResponse(render(data.get("cycles", []), data.get("total_learned_rules", 0)))


@router.post("/report/run", dependencies=_GATE)
def guard_report_run():
    """평가 하버스트 재실행 → 리포트 재생성 (인증 필요, 비용 있음)."""
    from neosguard.guard_eval import run_eval
    return run_eval()


@router.get("/sdk/python", response_class=PlainTextResponse)
def guard_sdk_python():
    """단일 파일 Python 클라이언트 다운로드 (의존성: requests)."""
    try:
        with open(_SDK_PATH, encoding="utf-8") as f:
            return PlainTextResponse(f.read(), media_type="text/x-python",
                                     headers={"Content-Disposition": "inline; filename=neosguard.py"})
    except Exception as e:  # noqa: BLE001
        return PlainTextResponse(f"# SDK 로드 실패: {e}", status_code=500)


@router.post("/keys/trial")
def guard_trial_key(request: Request):
    from neosguard.guard_auth import issue_trial_key
    return issue_trial_key(request)


@router.get("/stats")
def guard_stats():
    from neosguard.guard_stats import get_stats
    return get_stats()


class RedteamRequest(BaseModel):
    n: int = 6


@router.post("/redteam/run", dependencies=_GATE)
def guard_redteam_run(body: RedteamRequest):
    """자기개선 1사이클: 레드팀 공격 생성→방어 테스트→우회 학습(검증 게이트)."""
    from neosguard.guard_redteam import run_cycle
    return run_cycle(min(max(body.n, 1), 12))


@router.get("/redteam/log")
def guard_redteam_log():
    from neosguard.guard_redteam import get_cycles
    return get_cycles()


class GuardRequest(BaseModel):
    text: str
    use_llm: bool = True
    mode: str = "balanced"   # fast | balanced | thorough


class GuardBatchRequest(BaseModel):
    texts: list[str]
    use_llm: bool = True


@router.post("", dependencies=_GATE)
def guard_scan(body: GuardRequest):
    from neosguard.guard import analyze
    return analyze(body.text, use_llm=body.use_llm, mode=body.mode)


@router.post("/batch", dependencies=_GATE)
def guard_batch(body: GuardBatchRequest):
    from neosguard.guard import analyze
    return {"results": [analyze(t, use_llm=body.use_llm) for t in body.texts[:50]]}


@router.post("/output", dependencies=_GATE)
def guard_output(body: GuardRequest):
    """에이전트 출력(응답) 유출/순응 탐지 — 비밀키·개인정보·시스템프롬프트 유출, 인젝션 순응."""
    from neosguard.guard import analyze_output
    return analyze_output(body.text, use_llm=body.use_llm, mode=body.mode)


class EventRequest(BaseModel):
    agent_id: str
    session_id: str
    action: str
    target: str = ""
    content: str = ""
    risk: int = 0


class SessionRequest(BaseModel):
    session_id: str
    use_llm: bool = True


@router.post("/event", dependencies=_GATE)
def guard_event(body: EventRequest):
    """에이전트 행동 1건 기록 (③ 행동 모니터)."""
    from neosguard.guard_behavior import log_event
    return log_event(body.agent_id, body.session_id, body.action, body.target, body.content, body.risk)


@router.post("/session/analyze", dependencies=_GATE)
def guard_session_analyze(body: SessionRequest):
    """세션 행동 시퀀스 위협 분석 (③ 행동 모니터)."""
    from neosguard.guard_behavior import analyze_session
    return analyze_session(body.session_id, use_llm=body.use_llm)


@router.get("/health")
def guard_health():
    from neosguard.guard import _RULES, _OUT_RULES
    return {"status": "ok", "input_rules": len(_RULES), "output_rules": len(_OUT_RULES),
            "layers": ["input", "output", "behavior"], "llm": "local-qwen(mlx)"}
