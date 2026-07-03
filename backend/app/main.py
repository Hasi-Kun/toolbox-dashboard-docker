import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.api import api_router
from app.core.config import get_settings
from app.core.db import Base, engine
from app.core.logging_config import configure_logging
from app.core.migrations import run_light_migrations

# Modelle importieren, damit SQLAlchemy sie in Base.metadata kennt,
# bevor create_all aufgerufen wird.
from app.models import user as _user_models  # noqa: F401

configure_logging()
logger = logging.getLogger("toolbox")

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

app.include_router(api_router, prefix="/api/v1")


@app.on_event("startup")
async def on_startup() -> None:
    # Phase 3: einfache create_all statt Alembic-Migrationen -- reicht fuer
    # additive Schema-Aenderungen, siehe docs/ARCHITECTURE.md fuer den
    # Migrationspfad, sobald bestehende Spalten geaendert werden muessen.
    Base.metadata.create_all(bind=engine)
    run_light_migrations(engine)
    logger.info("Toolbox API gestartet (env=%s)", settings.environment)
