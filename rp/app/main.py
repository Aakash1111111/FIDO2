"""Relying party application factory.

Run locally (PC):   uvicorn app.main:app --port 8000        (from the rp/ folder)
Then open           http://localhost:8000
"""
import logging
import os
import time
from collections import defaultdict, deque

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from .challenges import ChallengeStore
from .config import Settings, load_settings
from .db import Database
from .errors import RPError
from .routes import router

STATIC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static")
log = logging.getLogger("rp")

SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:;"
                               " connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}
RATE_LIMITED_PREFIXES = ("/register/", "/login/")
RATE_LIMIT_PER_MIN = 60


def create_app(settings: Settings = None) -> FastAPI:
    s = settings or load_settings()
    app = FastAPI(title=s.rp_name, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = s
    app.state.db = Database(s.db_path)
    app.state.challenges = ChallengeStore(app.state.db, s.challenge_ttl_s)
    hits = defaultdict(deque)

    @app.middleware("http")
    async def security(request: Request, call_next):
        if request.url.path.startswith(RATE_LIMITED_PREFIXES):
            ip = request.client.host if request.client else "?"
            q, now = hits[ip], time.monotonic()
            while q and now - q[0] > 60:
                q.popleft()
            if len(q) >= RATE_LIMIT_PER_MIN:
                return JSONResponse({"ok": False, "reason": "RATE_LIMITED"}, status_code=429)
            q.append(now)
        response = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        return response

    # Signed session cookie holds only a random session id and the user id.
    app.add_middleware(SessionMiddleware, secret_key=s.session_secret, session_cookie="rp_session",
                       same_site="strict", https_only=s.secure_cookies, max_age=8 * 3600)

    @app.exception_handler(RPError)
    async def rp_error(request: Request, exc: RPError):
        return JSONResponse({"ok": False, "reason": exc.reason}, status_code=exc.status)

    app.include_router(router)
    app.mount("/static", StaticFiles(directory=STATIC), name="static")

    @app.get("/")
    async def index():
        return FileResponse(os.path.join(STATIC, "index.html"))

    @app.get("/dashboard")
    async def dashboard():
        return FileResponse(os.path.join(STATIC, "dashboard.html"))

    @app.get("/admin")
    async def admin():
        return FileResponse(os.path.join(STATIC, "admin.html"))

    log.warning("RP ready: rp_id=%s origins=%s admin=%s", s.rp_id, s.origins, bool(s.admin_token))
    return app


app = create_app() if os.environ.get("RP_NO_AUTOCREATE") != "1" else None
