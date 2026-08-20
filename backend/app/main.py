"""FastAPI surface for the SatyaShield detection backend.

PRD v3.0 section 7.6 (F5, F6), 5.3.

Serves all four client surfaces (Android app, WhatsApp bot, web checker, browser
extension) from one implementation.

SECURITY NOTE, read before deploying anywhere reachable:
These endpoints are unauthenticated, which is acceptable for a local prototype
and NOT acceptable on a public host. Before exposing this service, add at
minimum an API key or token check, per-IP rate limiting, and request size caps.
Section 5.3 also requires that the website-fetch pillar (not yet implemented)
run in a sandbox with private address ranges blocked, because a server-side
fetcher driven by user-supplied URLs is a textbook SSRF vector.
"""

from __future__ import annotations

from fastapi import FastAPI
from pydantic import BaseModel, Field

from . import __version__, pipeline
from .schemas import Language, MessageInput, Verdict

app = FastAPI(
    title="SatyaShield Detection API",
    version=__version__,
    description=(
        "Unified phishing and manipulated-media risk signals. "
        "Returns a three-state verdict with plain-language explanation. "
        "Prototype risk signal, not a certified forensic determination."
    ),
)

# Maximum accepted body sizes. Generous for a prototype, but present so a
# pathological payload cannot exhaust memory.
MAX_TEXT_CHARS = 20_000
MAX_EMAIL_CHARS = 1_000_000


class UrlCheckRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2_048)
    language: Language = Language.EN


class EmailCheckRequest(BaseModel):
    raw_email: str = Field(min_length=1, max_length=MAX_EMAIL_CHARS)
    language: Language = Language.EN
    trusted_source: bool = Field(
        default=True,
        description="False when a user pasted the text, in which case "
        "Authentication-Results headers are ignored rather than believed.",
    )


class HealthResponse(BaseModel):
    status: str
    version: str


@app.get("/health", response_model=HealthResponse, tags=["meta"])
def health() -> HealthResponse:
    return HealthResponse(status="ok", version=__version__)


@app.post("/check/message", response_model=Verdict, tags=["detection"])
def check_message(payload: MessageInput) -> Verdict:
    """Analyse a message: text, links, sender context and optional email source.

    This is the endpoint the Android client and WhatsApp bot both call.
    """
    if payload.text and len(payload.text) > MAX_TEXT_CHARS:
        payload = payload.model_copy(update={"text": payload.text[:MAX_TEXT_CHARS]})
    return pipeline.check_message(payload)


@app.post("/check/url", response_model=Verdict, tags=["detection"])
def check_url(request: UrlCheckRequest) -> Verdict:
    """Analyse a single URL (PS clause 6)."""
    return pipeline.check_url(request.url, language=request.language)


@app.post("/check/email", response_model=Verdict, tags=["detection"])
def check_email(request: EmailCheckRequest) -> Verdict:
    """Analyse a raw email including headers (PS clauses 1 and 7)."""
    return pipeline.check_email(
        request.raw_email,
        language=request.language,
        trusted_source=request.trusted_source,
    )
