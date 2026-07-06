import logging
import time

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.api import api_router
from app.core.config import get_settings
from app.core.db import Base, engine  # noqa: F401 -- Base bleibt fuer evtl. Tooling importierbar
from app.core.logging_config import configure_logging

# Modelle importieren, damit SQLAlchemy sie in Base.metadata kennt,
# bevor create_all aufgerufen wird.
from app.models import user as _user_models  # noqa: F401

configure_logging()
logger = logging.getLogger("toolbox")
access_logger = logging.getLogger("toolbox.access")

settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    description="Modulare Self-Hosted Netzwerk-, DNS- und Security-Toolbox.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["*"],
)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Eigenes Access-Log mit der ECHTEN Client-IP statt der internen
    Docker-IP. uvicorns eingebautes Access-Log zeigt nur den direkten TCP-
    Peer -- das ist im Docker-Netz immer toolbox-frontend, nie der
    tatsaechliche Besucher. `X-Real-IP` wird von Caddy gesetzt (im Idealfall
    aus Cloudflares 'CF-Connecting-IP', siehe docs/CADDY.md) und vom
    Frontend-BFF-Proxy 1:1 an das Backend durchgereicht. Der Zeitstempel
    kommt automatisch aus dem Logging-Format (siehe logging_config.py).
    """
    real_ip = request.headers.get("x-real-ip") or (request.client.host if request.client else "unknown")
    start = time.perf_counter()
    response = await call_next(request)
    duration_ms = (time.perf_counter() - start) * 1000

    access_logger.info(
        "%s %s %s -> %d (%.1fms)",
        real_ip, request.method, request.url.path, response.status_code, duration_ms,
    )
    return response


app.include_router(api_router, prefix="/api/v1")


@app.on_event("startup")
async def on_startup() -> None:
    # Schema-Migrationen laufen jetzt VOR diesem Prozess (siehe
    # app/scripts/run_migrations.py, aufgerufen im Dockerfile-CMD) --
    # hier nur noch Logging, kein create_all/ALTER TABLE mehr.
    logger.info("Toolbox API gestartet (env=%s)", settings.environment)
