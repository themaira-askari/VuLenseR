"""
main.py - FastAPI server for the Hybrid Requirements Vulnerability Analyzer.

Flow per request:
    1. Auth (X-API-Key) + per-IP rate limit
    2. rule_engine.scan_requirement_text()
    3. RAG context (server-side only, rag_engine.py / ChromaDB)
    4. ai_engine.analyze_requirement_with_ai()
    5. Combined JSON report ("success") ya rule-only report ("partial")

.env variables:
    GROQ_API_KEY   - ai_engine use karta hai
    APP_API_KEY    - is server ki apni key (clients X-API-Key header mein bhejte hain)
    RATE_LIMIT     - optional, default "30/minute" (slowapi format, per IP)
    CORS_ORIGINS   - optional, comma separated, e.g. "http://localhost:8501"

Run:
    uvicorn main:app --reload
"""

import logging
import os
import secrets
import time
from contextlib import asynccontextmanager
from typing import Any, Optional

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, ConfigDict, Field, field_validator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from ai_engine import analyze_requirement_with_ai
from rag_engine import is_ready as rag_is_ready
from rag_engine import retrieve_relevant_context, warm_up as rag_warm_up
from rule_engine import scan_requirement_text

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("srs_analyzer")

MIN_LEN = 5
MAX_LEN = 4000
RATE_LIMIT = os.getenv("RATE_LIMIT", "30/minute")

# Rule findings se ye keys response mein nahi jayengi (requirement dobara
# bhejna aur raw trigger text duplicate/noisy hai).
_STRIP_KEYS = {"requirement", "triggers_matched"}

limiter = Limiter(key_func=get_remote_address)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    # Pehli baar ChromaDB ka embedding model download hota hai (internet chahiye);
    # startup par kar lete hain taake pehli user request na atke.
    try:
        ok = rag_warm_up()
        logger.info("RAG warm-up %s", "ok" if ok else "failed (server bina RAG ke chalega)")
    except Exception:
        logger.exception("RAG warm-up crashed; continuing without RAG")
    yield


app = FastAPI(
    title="SRS Hybrid Security Analysis System",
    description=(
        "Hybrid security analysis: rule-based checks + server-side RAG (ChromaDB) + "
        "constrained Llama-3 analysis, mapped to OWASP Top 10 2021."
    ),
    version="1.2.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Sab origins ko allow karne ke liye
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

_cors_origins = [o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()]
if _cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins,
        allow_methods=["GET", "POST"],
        allow_headers=["X-API-Key", "Content-Type"],
    )

# auto_error=False: 401 hum khud dete hain; /docs mein "Authorize" button bhi aata hai.
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def verify_api_key(provided: Optional[str] = Depends(api_key_header)) -> None:
    expected = os.getenv("APP_API_KEY", "")
    if not expected:
        # Fail closed: key set nahi to server open nahi chalega.
        logger.error("APP_API_KEY is not set; refusing requests.")
        raise HTTPException(status_code=503, detail="Server authentication is not configured.")
    if not provided or not secrets.compare_digest(provided.encode(), expected.encode()):
        raise HTTPException(status_code=401, detail="Invalid or missing API key.")


class RequirementRequest(BaseModel):
    # extra="forbid": agar client rag_context (ya koi aur extra field) bheje to 422.
    model_config = ConfigDict(extra="forbid")

    requirement_text: str = Field(
        ...,
        max_length=MAX_LEN,
        description=f"The SRS requirement text to analyze ({MIN_LEN}-{MAX_LEN} characters).",
    )

    @field_validator("requirement_text")
    @classmethod
    def _strip_and_check_min(cls, value: str) -> str:
        value = value.strip()
        if len(value) < MIN_LEN:
            raise ValueError(f"requirement_text must be at least {MIN_LEN} characters.")
        return value


def get_rag_context(requirement_text: str) -> str:
    """Server-side RAG hook: ChromaDB se relevant OWASP / secure-requirement chunks.

    rag_engine fail ho to empty string deta hai (pipeline bina RAG ke chalti rahti hai).
    Ye kabhi client payload se nahi aana chahiye.
    """
    return retrieve_relevant_context(requirement_text)


def _scrub(obj: Any) -> Any:
    """Recursively _STRIP_KEYS hata kar naya object return karta hai (input mutate nahi hota)."""
    if isinstance(obj, dict):
        return {k: _scrub(v) for k, v in obj.items() if k not in _STRIP_KEYS}
    if isinstance(obj, list):
        return [_scrub(item) for item in obj]
    return obj


@app.get("/")
def home():
    return {
        "message": "Welcome to SRS Hybrid Security Analysis System API.",
        "documentation": "Go to /docs for interactive FastAPI testing.",
    }


@app.get("/health")
def health():
    return {
        "status": "ok",
        "ai_configured": bool(os.getenv("GROQ_API_KEY")),
        "auth_configured": bool(os.getenv("APP_API_KEY")),
        "rag_ready": rag_is_ready(),
    }


@app.post("/analyze-requirement")
@limiter.limit(RATE_LIMIT)
def analyze_requirement(
    request: Request,  # slowapi ko ye parameter chahiye
    payload: RequirementRequest,
    _auth: None = Depends(verify_api_key),
):
    start = time.perf_counter()
    req_text = payload.requirement_text  # validator pehle hi strip kar chuka hai

    # 1. Rule engine (ye fail ho to hamare paas kuch nahi, isliye 500)
    try:
        rule_findings = scan_requirement_text(req_text)
    except Exception:
        logger.exception("Rule engine crashed")
        raise HTTPException(status_code=500, detail="Rule engine failed.")

    # 2. RAG context: sirf server se
    rag_context = get_rag_context(req_text)

    # 3. AI engine (original rule_findings jati hain; ai_engine apni sanitizing khud karta hai)
    try:
        ai_response = analyze_requirement_with_ai(
            requirement_text=req_text,
            rule_findings=rule_findings,
            rag_context=rag_context,
        )
    except Exception:
        logger.exception("AI engine crashed")
        ai_response = {"status": "error", "message": "AI engine failed unexpectedly."}

    rule_view = _scrub(rule_findings)
    elapsed_ms = int((time.perf_counter() - start) * 1000)

    ai_ok = (
        isinstance(ai_response, dict)
        and ai_response.get("status") == "success"
        and ai_response.get("ai_analysis") is not None
    )

    if not ai_ok:
        message = (
            ai_response.get("message", "AI analysis failed.")
            if isinstance(ai_response, dict)
            else "AI analysis failed."
        )
        logger.warning("analysis partial: req_len=%d ms=%d error=%s", len(req_text), elapsed_ms, message)
        # 200 + partial: rule results zaya nahi hote
        return {
            "status": "partial",
            "rule_engine_analysis": rule_view,
            "ai_deep_analysis": None,
            "ai_error": message,
        }

    logger.info("analysis success: req_len=%d ms=%d", len(req_text), elapsed_ms)
    return {
        "status": "success",
        "rule_engine_analysis": rule_view,
        "ai_deep_analysis": ai_response["ai_analysis"],
    }