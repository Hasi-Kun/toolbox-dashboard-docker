import asyncio
import json
import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.config import get_settings
from app.core.db import get_db
from app.core.rate_limit import enforce_rate_limit
from app.core.scan_queue import delete_job_context, get_job_context, peek_result, stash_job_context, submit_job
from app.models.user import ToolExecution, User
from app.modules import get_registry

logger = logging.getLogger("toolbox.tools")
settings = get_settings()
router = APIRouter(dependencies=[Depends(get_current_user)])

MAX_STORED_CHARS = 19000  # etwas Puffer unter dem 20000-Zeichen-Spaltenlimit

# Zusaetzlich zum kategorieweiten Limit (settings.scan_rate_limit_per_minute,
# geteilt von ALLEN aktiven Scans der nmap-Kategorie) bekommen die
# schwersten/langsamsten Tools ein eigenes, strengeres Limit PRO SLUG --
# sonst koennte jemand mit 5 Nikto-Laeufen/Minute den einzigen Scanner-
# Worker fuer alle anderen nmap-Tools komplett verstopfen (Nikto/Full-
# Port-Scan/Vuln-Scan koennen jeweils mehrere Minuten dauern und werden
# vom Scanner-Container sequenziell abgearbeitet, nicht parallel).
_PER_SLUG_SCAN_LIMITS: dict[str, int] = {
    "nikto-scan": 2,
    "nmap-full-port-scan": 2,
    "nmap-vuln-scan": 2,
    "testssl-deep-scan": 2,
}


def _log_execution(
    db: Session,
    user_id: int,
    slug: str,
    success: bool,
    input_data: dict | None = None,
    output_data: dict | None = None,
    error_message: str | None = None,
) -> None:
    try:
        input_json = json.dumps(input_data)[:MAX_STORED_CHARS] if input_data is not None else None
        output_json = json.dumps(output_data)[:MAX_STORED_CHARS] if output_data is not None else None
        db.add(
            ToolExecution(
                user_id=user_id,
                tool_slug=slug,
                success=success,
                input_json=input_json,
                output_json=output_json,
                error_message=error_message[:500] if error_message else None,
            )
        )
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

    if module_cls.requires_admin and user.role != "admin":
        raise HTTPException(status_code=403, detail="Dieses Tool ist nur fuer Administratoren freigeschaltet.")

    if module_cls.is_active_scan:
        limit = settings.scan_rate_limit_per_minute
    else:
        limit = settings.rate_limit_per_minute
    await enforce_rate_limit(request, bucket=module_cls.category, limit=limit)

    # Zusaetzliches, strengeres Pro-Slug-Limit fuer die schwersten Tools
    # (siehe Kommentar bei _PER_SLUG_SCAN_LIMITS oben).
    if slug in _PER_SLUG_SCAN_LIMITS:
        await enforce_rate_limit(request, bucket=f"tool:{slug}", limit=_PER_SLUG_SCAN_LIMITS[slug])

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
    # Sensible Eingaben (z.B. ein zu pruefendes Passwort) duerfen unter
    # keinen Umstaenden in der Historie landen -- auch nicht im Fehlerfall.
    logged_input = {"redacted": True} if module_cls.redact_input_in_history else payload
    # +5s Puffer: das Modul soll seinen EIGENEN Timeout (z.B. httpx-Client)
    # zuerst ausloesen und sauber abfangen koennen. Ohne Puffer laufen
    # beide Timeouts im Wettlauf gegeneinander -- gewinnt der aeussere
    # asyncio.wait_for, gibt es einen 504 statt einer sauberen Fehlermeldung
    # (siehe Incident: certificate-transparency bei langsamer crt.sh-Antwort).
    timeout = (module_cls.timeout_seconds or settings.default_timeout_seconds) + 5

    try:
        result = await asyncio.wait_for(module.run(input_data), timeout=timeout)
    except asyncio.TimeoutError as exc:
        _log_execution(db, user.id, slug, success=False, input_data=logged_input, error_message="Zeitueberschreitung bei der Ausfuehrung.")
        raise HTTPException(status_code=504, detail="Zeitueberschreitung bei der Ausfuehrung.") from exc
    except Exception as exc:  # noqa: BLE001
        logger.exception("Fehler beim Ausfuehren von Modul '%s'", slug)
        _log_execution(db, user.id, slug, success=False, input_data=logged_input, error_message="Interner Fehler beim Ausfuehren des Tools.")
        raise HTTPException(status_code=500, detail="Interner Fehler beim Ausfuehren des Tools.") from exc

    result_dict = result.model_dump()
    _log_execution(db, user.id, slug, success=True, input_data=logged_input, output_data=result_dict)
    return result_dict


# --- Polling-Muster fuer lange aktive Scans -------------------------------
#
# Statt EINER einzelnen HTTP-Anfrage, die fuer die gesamte Scan-Dauer
# (bis zu 300s bei full-port-scan) offen bleibt, wird der Scan hier
# angestossen (gibt SOFORT eine job_id zurueck) und das Ergebnis danach
# per kurzen, wiederholten Anfragen abgefragt. Das macht jede einzelne
# HTTP-Anfrage kurz und unempfindlich gegen Timeouts von Reverse-Proxies
# oder CDNs (z.B. Cloudflare, das bei proxied Verbindungen ein eigenes,
# vom eigenen Server-Timeout unabhaengiges Zeitlimit hat).


def _check_scan_permissions_and_validate(slug: str, payload: dict, user: User):
    """Gemeinsame Pruefungen fuer den synchronen und den Polling-Pfad:
    Tool existiert, ist ein Scan-Tool mit Polling-Unterstuetzung, Admin-
    Berechtigung, Eingabe-Validierung. Gibt (module, input_data) zurueck
    oder wirft HTTPException."""
    registry = get_registry()
    module_cls = registry.get(slug)
    if module_cls is None:
        raise HTTPException(status_code=404, detail=f"Unbekanntes Tool: {slug}")
    if not module_cls.is_active_scan or module_cls.scan_template is None:
        raise HTTPException(status_code=400, detail="Dieses Tool unterstuetzt kein Scan-Polling.")
    if module_cls.requires_admin and user.role != "admin":
        raise HTTPException(status_code=403, detail="Dieses Tool ist nur fuer Administratoren freigeschaltet.")

    try:
        input_data = module_cls.Input(**payload)
    except ValidationError as exc:
        errors = [
            {"field": ".".join(str(p) for p in err["loc"]), "message": err["msg"]}
            for err in exc.errors()
        ]
        raise HTTPException(status_code=422, detail=errors) from exc

    return module_cls(), input_data


@router.post("/tools/{slug}/scan/start", tags=["tools"])
async def start_scan(
    slug: str,
    payload: dict,
    request: Request,
    user: User = Depends(get_current_user),
) -> dict:
    module, input_data = _check_scan_permissions_and_validate(slug, payload, user)
    module_cls = type(module)

    await enforce_rate_limit(request, bucket=module_cls.category, limit=settings.scan_rate_limit_per_minute)
    if slug in _PER_SLUG_SCAN_LIMITS:
        await enforce_rate_limit(request, bucket=f"tool:{slug}", limit=_PER_SLUG_SCAN_LIMITS[slug])

    job_id = await submit_job(module_cls.scan_template, module.build_scan_params(input_data))
    await stash_job_context(job_id, slug, payload, user.id)
    return {"job_id": job_id, "status": "pending"}


@router.get("/tools/{slug}/scan/status/{job_id}", tags=["tools"])
async def scan_status(
    slug: str,
    job_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    registry = get_registry()
    module_cls = registry.get(slug)
    if module_cls is None:
        raise HTTPException(status_code=404, detail=f"Unbekanntes Tool: {slug}")

    context = await get_job_context(job_id)
    if context is None:
        # Entweder noch nicht fertig UND noch nie ein Kontext gespeichert
        # (sollte nicht vorkommen) -- oder das Ergebnis wurde bereits
        # einmal abgeholt (Kontext + Ergebnis werden nach der ersten
        # erfolgreichen Abfrage geloescht, siehe unten).
        raw = await peek_result(job_id)
        if raw is None:
            return {"status": "pending"}
        # Kontext fehlt (z.B. abgelaufen), aber ein Ergebnis kam trotzdem
        # noch rein -- ohne die urspruengliche Eingabe koennen wir es
        # nicht sauber typisiert zurueckgeben.
        return {"status": "error", "detail": "Scan-Kontext nicht mehr verfuegbar (abgelaufen)."}

    if context.get("user_id") != user.id and user.role != "admin":
        raise HTTPException(status_code=403, detail="Dieser Scan gehoert einem anderen Nutzer.")

    raw = await peek_result(job_id)
    if raw is None:
        return {"status": "pending"}

    module = module_cls()
    try:
        input_data = module_cls.Input(**context["input"])
        output = module.parse_scan_result(input_data, raw)
        result_dict = output.model_dump()
        success = bool(result_dict.get("success"))
        logged_input = {"redacted": True} if module_cls.redact_input_in_history else context["input"]
        _log_execution(
            db, user.id, slug, success=success, input_data=logged_input,
            output_data=result_dict if success else None,
            error_message=result_dict.get("error") if not success else None,
        )
        return {"status": "done", "result": result_dict}
    finally:
        await delete_job_context(job_id)
