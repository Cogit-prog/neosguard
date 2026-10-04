<div align="center">

# 🛡️ NEOS Guard

### The self-evolving firewall for AI agents

**Blocks prompt injection, data leakage, and autonomous attack patterns — across input, output, and runtime behavior. Multilingual. Self-hostable. And it rewrites its own defenses every night, with a hard verifier that proves it never got worse.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org)
[![False positives](https://img.shields.io/badge/false%20positives-0%25-brightgreen.svg)](#-honest-reproducible-benchmarks)
[![Self-hosted](https://img.shields.io/badge/self--host-air--gapped-success.svg)](#-self-host--air-gapped)

[**Live demo**](https://api.cogitapp.com/guard/demo) · [**Reproducible metrics**](https://api.cogitapp.com/guard/report) · [**OWASP coverage**](https://api.cogitapp.com/guard/owasp) · [**Self-evolution log**](https://api.cogitapp.com/guard/evolution)

<img src="docs/demo.gif" alt="NEOS Guard detecting a Korean prompt injection (100, blocked) and a Korean ID leak (masked) in real time" width="760">

<sub>Detecting a Korean prompt injection and a Korean PII leak in real time — multilingual, out of the box. [Try it live →](https://api.cogitapp.com/guard/demo)</sub>

</div>

---

## Why another AI guardrail?

Most LLM filters are English-only, single-layer, and ship a "99% accuracy" number you can't reproduce. AI-native attacks have moved on — autonomous, LLM-powered attack tools now automate injection, credential stuffing, and exfiltration in many languages. A static filter written for yesterday's attacks can't keep up.

NEOS Guard is different on four axes that actually matter:

| | NEOS Guard | Typical LLM filter |
|---|---|---|
| **Coverage** | Input **+ output + runtime behavior** | Input only |
| **False positives** | **0%** (verified on 200+ benign) | Often noisy → gets turned off |
| **Languages** | **EN · KO · JA · ZH** native | English-centric |
| **Improvement** | **Self-evolving** with a hard verifier | Manual rule updates |
| **Honesty** | Held-out metrics you can reproduce | "99% accuracy ✨" |
| **Deploy** | Self-host, **~3ms local**, air-gapped | SaaS, your data leaves |

---

## 30-second quickstart

```bash
git clone <this-repo> && cd neosguard-oss
pip install -r requirements.txt
python server.py                     # serves on :8080, fully local
```

**Option A — zero code change (proxy).** Point your OpenAI client at it:

```python
from openai import OpenAI
client = OpenAI(base_url="http://localhost:8080/guard/proxy/v1", api_key="YOUR_KEY")
# every call is now guarded: input injection blocked + output leaks masked
```

**Option B — SDK, one decorator:**

```python
from neosguard import Guard          # sdk/neosguard.py
guard = Guard(base_url="http://localhost:8080")

@guard.protect(on_block=lambda v: "[blocked]")
def agent(user_text: str) -> str:
    return llm(user_text)            # input + output auto-scanned
```

That's it. No account, no data leaving your machine.

---

## The three layers

```
          ┌─────────────┐      ┌──────────────┐      ┌───────────────┐
 web/mail │  ① INPUT    │ LLM  │  ② OUTPUT    │ user │  ③ BEHAVIOR   │
 /tools ─▶│  injection  │─────▶│  leakage     │─────▶│  runtime      │
          │  blocking   │      │  prevention  │      │  monitor      │
          └─────────────┘      └──────────────┘      └───────────────┘
```

1. **Input** — hidden instructions, jailbreaks, prompt-leak attempts in content your agent reads. Rules + [Meta Prompt Guard 2](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M) + an LLM ensemble.
2. **Output** — secret keys, credentials, PII (national IDs, cards), and system-prompt disclosure, caught before they leave. Deterministic secrets engine (gitleaks-grade) + PII engine (Presidio-lite, Luhn/checksum-validated).
3. **Behavior** — the *session's action sequence*: exfiltration chains, hijack execution, credential stuffing, account enumeration, bot-speed automation. Catches attacks that look fine one step at a time.

---

## 🔁 The part nobody else does honestly: it evolves

Every night a red-team routine invents novel attacks, tests them against the current guard, and proposes a defense for any that slip through. A new defense is adopted **only if a hard verifier confirms all three**:

- ✅ it actually catches the new attack,
- ✅ it keeps false positives at **0%** on the full benign set,
- ✅ it does **not** lower detection on the held-out test set.

Fail any one → **automatic rollback**. So the system can't quietly degrade itself (the classic failure mode of "auto-learning" filters). It improves *monotonically* — stronger tomorrow than today, provably. Watch it happen: [self-evolution log](https://api.cogitapp.com/guard/evolution).

---

## 📊 Honest, reproducible benchmarks

No marketing numbers. These are measured on **held-out data never used to tune the rules** — reproduce them yourself with `python -m neosguard.guard_eval`.

| Layer | Known attacks | Novel (held-out) | False positives |
|-------|---------------|------------------|-----------------|
| Input injection | 99% | **83%** | **0%** |
| Output leakage | 100% | **67%** | **0%** |
| Behavior (designed coverage) | 100% | 50%\* | **0%** |

\* Behavior novel = an independent LLM-generated holdout; a conservative floor. We publish the training↔holdout gap instead of hiding the overfit. Full report: [/guard/report](https://api.cogitapp.com/guard/report).

> We'd rather tell you it's 83% and reproducible than claim 99% you can't verify.

---

## 🔒 Self-host & air-gapped

In `fast` mode NEOS Guard is **fully local and deterministic** — rules + secrets + PII engines, **no network calls, no data leaves your machine** (~3ms/scan). Add a `GROQ_API_KEY` or a local MLX server for the ML layers.

| mode | layers | latency | data leaves machine? |
|------|--------|---------|----------------------|
| `fast` | rules + secrets + PII | **~3 ms** | **no — fully local** |
| `balanced` | + Prompt Guard 2 | ~0.2–0.5 s | only to your LLM provider |
| `thorough` | + LLM ensemble | ~1 s | only to your LLM provider |

```bash
docker build -t neosguard . && docker run -p 8080:8080 neosguard   # fully local
```

Perfect for finance, healthcare, and anyone who can't send prompts to a third party.

---

## 🧭 OWASP LLM Top 10 coverage

Mapped honestly to the enterprise evaluation checklist — covered / partial / out-of-scope (we don't claim to do supply-chain or embedding security; those are different products). See [/guard/owasp](https://api.cogitapp.com/guard/owasp).

Covered: **LLM01** Prompt Injection · **LLM02** Sensitive Info Disclosure · **LLM07** System Prompt Leakage.
Partial: **LLM05** Improper Output Handling · **LLM06** Excessive Agency · **LLM10** Unbounded Consumption.

---

## API

| Endpoint | Purpose |
|----------|---------|
| `POST /guard` | input injection scan |
| `POST /guard/output` | output leak scan (secrets · PII · prompt leak) |
| `POST /guard/output/risk` | dangerous-output payloads (SQLi/XSS/shell) — opt-in |
| `POST /guard/event` + `/guard/session/analyze` | runtime behavior monitor |
| `POST /guard/proxy/v1/chat/completions` | zero-code drop-in gateway (streaming supported) |
| `GET /guard/docs` · `/demo` · `/report` · `/owasp` · `/evolution` | docs & dashboards |

---

## Status & honesty

This is an early open-source release. It's genuinely useful today as a **defense-in-depth layer** for indie/SMB AI products — not a replacement for auth hardening or a network WAF, and not (yet) an audited enterprise SaaS. Issues and PRs welcome.

## License

MIT — see [LICENSE](LICENSE).
