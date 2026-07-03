import asyncio
import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.config import get_settings
from app.core.db import get_db
from app.core.rate_limit import enforce_rate_limit
from app.models.user import ToolExecution, User
from app.modules import get_registry

logger = logging.getLogger("toolbox.tools")
settings = get_settings()
router = APIRouter(dependencies=[Depends(get_current_user)])


def _log_execution(db: Session, user_id: int, slug: str, success: bool) -> None:
    try:
        db.add(ToolExecution(user_id=user_id, tool_slug=slug, success=success))
        db.commit()
    except Exception:  # noqa: BLE001 -- Historie ist "nice to have", darf den Tool-Aufruf nie verhindern
        logger.exception("Konnte Tool-Ausfuehrung nicht protokollieren")
        db.rollback()


@router.get("/tools", tags=["tools"])
async def list_tools() -> list[dict]:
    """Alle registrierten Tools mit Metadaten -- Basis fuer Sidebar/Suche im Frontend."""
    return [module_cls.metadata() for module_cls in get_registry().values()]


@router.post("/tools/{slug}", tags=["tools"])
async def run_tool(
    slug: str,
    payload: dict,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    registry = get_registry()
    module_cls = registry.get(slug)
    if module_cls is None:
        raise HTTPException(status_code=404, detail=f"Unbekanntes Tool: {slug}")

    if module_cls.is_active_scan:
        limit = settings.scan_rate_limit_per_minute
    else:
        limit = settings.rate_limit_per_minute
    await enforce_rate_limit(request, bucket=module_cls.category, limit=limit)

    try:
        input_data = module_cls.Input(**payload)
    except ValidationError as exc:
        # exc.errors() enthaelt im "ctx"-Feld teils rohe Exception-Objekte
        # (z.B. die ValueError aus einem @field_validator), die nicht
        # JSON-serialisierbar sind. Nur die relevanten, serialisierbaren
        # Felder durchreichen.
        errors = [
            {"field": ".".join(str(p) for p in err["loc"]), "message": err["msg"]}
            for err in exc.errors()
        ]
        # Validierungsfehler landen bewusst NICHT in der Historie -- das
        # war kein tatsaechlicher Tool-Lauf, nur eine ungueltige Eingabe.
        raise HTTPException(status_code=422, detail=errors) from exc

    module = module_cls()
    timeout = module_cls.timeout_seconds or settings.default_timeout_seconds

    try:
        result = await asyncio.wait_for(module.run(input_data), timeout=timeout)
    except asyncio.TimeoutError as exc:
        _log_execution(db, user.id, slug, success=False)
        raise HTTPException(status_code=504, detail="Zeitueberschreitung bei der Ausfuehrung.") from exc
    except Exception as exc:  # noqa: BLE001
        logger.exception("Fehler beim Ausfuehren von Modul '%s'", slug)
        _log_execution(db, user.id, slug, success=False)
        raise HTTPException(status_code=500, detail="Interner Fehler beim Ausfuehren des Tools.") from exc

    _log_execution(db, user.id, slug, success=True)
    return result.model_dump()
