"""FastAPI application entrypoint."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app import __version__
from app.core.config import settings
from app.core.logging import configure_logging, get_logger

log = get_logger("app")


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging()
    problems = settings.validate_runtime()
    if problems:
        for p in problems:
            log.error("CONFIG: %s", p)
        if settings.is_production:
            raise RuntimeError(
                "Refusing to start with insecure configuration: " + "; ".join(problems)
            )
    # For SQLite dev/test, ensure tables exist without requiring Alembic.
    if settings.is_sqlite:
        from app.core.db import create_all

        create_all()
    log.info("wp-audit-win API %s starting (env=%s)", __version__, settings.env)
    yield
    log.info("wp-audit-win API shutting down")


app = FastAPI(
    title="wp-audit-win API",
    version=__version__,
    description=(
        "WordPress Security Audit & Pentest Management platform API. "
        "Authorized security assessment only."
    ),
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# CORS — the dashboard is served same-origin via the reverse proxy; allow the
# configured public URL for direct API clients and local dev.
_origins = {settings.public_url, "http://localhost:3000", "http://localhost"}
app.add_middleware(
    CORSMiddleware,
    allow_origins=sorted(o for o in _origins if o),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    return response


from app.services.authorization import AuthorizationError  # noqa: E402


@app.exception_handler(AuthorizationError)
async def _authz_handler(_request: Request, exc: AuthorizationError):
    return JSONResponse(status_code=403, content={"detail": f"Not authorized: {exc}"})


from app.api.router import api_router  # noqa: E402

app.include_router(api_router)


@app.get("/", tags=["meta"])
def root():
    return {
        "name": "wp-audit-win",
        "version": __version__,
        "docs": "/docs",
        "note": "Authorized security assessment platform.",
    }
