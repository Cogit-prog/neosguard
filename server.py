"""NEOS Guard — standalone server.  python server.py  (serves on :8080)
fast mode is fully local & deterministic; set GROQ_API_KEY for the ML layers."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fastapi import FastAPI
from neosguard.routes.guard import router as guard_router

app = FastAPI(title="NEOS Guard", version="1.0.0")
app.include_router(guard_router)

@app.get("/")
def root():
    return {"service": "neos-guard", "docs": "/guard/docs", "demo": "/guard/demo",
            "local_only": not bool(os.getenv("GROQ_API_KEY"))}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
