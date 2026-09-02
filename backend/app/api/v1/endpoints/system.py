import json
import logging
from datetime import datetime, timezone

import httpx
import psutil
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_admin
from app.core.audit import get_client_ip, log_audit_event
from app.core.config import get_settings
from app.core.db import get_db
from app.core.sessions import get_online_user_ids
from app.models.user import AuditLogEntry, ToolExecution, User
from app.modules import get_registry

logger = logging.getLogger("toolbox.system")
settings = get_settings()
router = APIRouter(prefix="/system", tags=["system"])

# Feste Allowlist statt Praefix-Matching -- explizit und unmissverstaendlich,
# welche Container ueberhaupt zur eigenen Toolbox-Stack gehoeren (siehe
# docker-compose.yml container_name:). Wird sowohl fuers Filtern der
# Uebersicht als auch als harte Grenze fuer den Neustart-Endpunkt genutzt --
# der Docker-Socket-Proxy selbst kennt keine Container-Namen, nur IDs/Namen
# als Pfad-Parameter, daher MUSS diese Pruefung hier im Backend passieren.
TOOLBOX_CONTAINER_NAMES = {
    "toolbox-frontend",
    "toolbox-backend",
    "toolbox-scanner",
    "toolbox-redis",
    "toolbox-docker-proxy",
}


@router.get("/info")
async def system_info(_admin: User = Depends(require_admin)) -> dict:
    """CPU/RAM/Uptime wie von INNERHALB des Containers sichtbar (via /proc,
    das der Host-Kernel bereitstellt). Ohne explizite cgroup-Limits auf dem
    Container entspricht das den echten Host-Werten -- mit Limits koennen
    die Werte abweichen. Bewusst admin-only, da das ueber den Toolbox-
    eigenen Betrieb hinaus Einblick in den gesamten Host gibt.
    """
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    boot_time = datetime.fromtimestamp(psutil.boot_time(), tz=timezone.utc)
    uptime_seconds = int((datetime.now(timezone.utc) - boot_time).total_seconds())

    return {
        "cpu_percent": psutil.cpu_percent(interval=0.3),
        "cpu_count": psutil.cpu_count(),
        "memory_total_bytes": memory.total,
        "memory_used_bytes": memory.used,
        "memory_percent": memory.percent,
        "disk_total_bytes": disk.total,
        "disk_used_bytes": disk.used,
        "disk_percent": disk.percent,
        "uptime_seconds": uptime_seconds,
    }


@router.get("/docker")
async def docker_status(_admin: User = Depends(require_admin)) -> dict:
    """Container-Liste ueber den read-only Docker-Socket-Proxy (siehe
    docker-compose.yml + docs/ARCHITECTURE.md) -- das Backend selbst
    beruehrt niemals /var/run/docker.sock direkt.

    Bewusst NUR auf die eigene Toolbox-Stack gefiltert (siehe
    TOOLBOX_CONTAINER_NAMES) -- der Host laeuft typischerweise noch
    weitere, voellig unabhaengige Container (z.B. andere selbst
    gehostete Dienste), die im Toolbox-Dashboard nichts verloren haben
    und deren Namen/Status auch nicht offengelegt werden sollen.
    """
    url = f"{settings.docker_proxy_url}/containers/json?all=1"
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            response = await client.get(url)
            response.raise_for_status()
    except httpx.HTTPError as exc:
        logger.warning("Docker-Socket-Proxy nicht erreichbar: %s", exc)
        raise HTTPException(status_code=502, detail="Docker-Status nicht erreichbar") from exc

    all_containers = response.json()
    toolbox_containers = [
        c for c in all_containers if c.get("Names", ["?"])[0].lstrip("/") in TOOLBOX_CONTAINER_NAMES
    ]

    result = [
        {
            "name": c.get("Names", ["?"])[0].lstrip("/"),
            "id": c.get("Id", "")[:12],
            "image": c.get("Image"),
            "state": c.get("State"),
            "status": c.get("Status"),
        }
        for c in toolbox_containers
    ]
    # Stabile, vorhersehbare Reihenfolge im Dashboard statt der
    # Docker-API-eigenen (nicht garantiert konsistenten) Reihenfolge.
    order = {name: i for i, name in enumerate(TOOLBOX_CONTAINER_NAMES)}
    result.sort(key=lambda c: order.get(c["name"], 99))

    return {
        "containers": result,
        "total": len(result),
        "running": sum(1 for c in result if c["state"] == "running"),
    }


@router.post("/docker/{container_name}/restart")
async def restart_docker_container(
    container_name: str, request: Request, db: Session = Depends(get_db), admin: User = Depends(require_admin)
) -> dict:
    """Startet einen einzelnen Container der eigenen Toolbox-Stack neu.

    Harte Allowlist-Pruefung HIER im Backend: der Docker-Socket-Proxy
    selbst kennt keine Container-Namen-Einschraenkung (ALLOW_RESTARTS=1
    dort wuerde technisch JEDEN Container auf dem Host erlauben) -- diese
    Pruefung ist die tatsaechliche Sicherheitsgrenze, nicht die
    Proxy-Konfiguration allein. Jeder Neustart wird zusaetzlich im
    Audit-Log festgehalten (wer, welcher Container, wann).
    """
    if container_name not in TOOLBOX_CONTAINER_NAMES:
        raise HTTPException(status_code=403, detail="Nur Container der eigenen Toolbox-Stack koennen neugestartet werden.")

    url = f"{settings.docker_proxy_url}/containers/{container_name}/restart?t=10"
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(url)
    except httpx.HTTPError as exc:
        logger.warning("Docker-Container-Neustart fehlgeschlagen (%s): %s", container_name, exc)
        log_audit_event(db, "docker_container_restart", success=False, username=admin.username, ip_address=get_client_ip(request), detail=f"{container_name}: {exc}")
        raise HTTPException(status_code=502, detail="Neustart fehlgeschlagen -- Docker-Socket-Proxy nicht erreichbar") from exc

    if response.status_code not in (204, 304):
        log_audit_event(db, "docker_container_restart", success=False, username=admin.username, ip_address=get_client_ip(request), detail=f"{container_name}: HTTP {response.status_code}")
        raise HTTPException(status_code=502, detail=f"Neustart fehlgeschlagen (HTTP {response.status_code})")

    log_audit_event(db, "docker_container_restart", success=True, username=admin.username, ip_address=get_client_ip(request), detail=container_name)
    return {"success": True, "container": container_name}


@router.get("/online-users")
async def online_users(db: Session = Depends(get_db), _user: User = Depends(get_current_user)) -> dict:
    """Sichtbar fuer alle eingeloggten Nutzer (nicht nur Admins) -- 'wer ist
    online' ist Teil der Shoutbox-Funktionalitaet, keine sensible Host-Info."""
    user_ids = await get_online_user_ids()
    if not user_ids:
        return {"count": 0, "usernames": []}

    users = db.query(User).filter(User.id.in_(user_ids)).all()
    return {"count": len(users), "usernames": sorted(u.username for u in users)}


# --- Audit-Log (admin-only) ---------------------------------------------

class AuditLogOut(BaseModel):
    id: int
    event_type: str
    username: str | None
    ip_address: str | None
    success: bool
    detail: str | None
    created_at: str


class PaginatedAuditLogOut(BaseModel):
    items: list[AuditLogOut]
    total: int
    page: int
    page_size: int
    total_pages: int


@router.get("/audit-log", response_model=PaginatedAuditLogOut)
async def get_audit_log(
    search: str | None = None,
    event_type: str | None = None,
    page: int = 1,
    page_size: int = 100,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
) -> PaginatedAuditLogOut:
    page = max(1, page)
    page_size = max(1, min(page_size, 500))

    query = db.query(AuditLogEntry)
    if event_type:
        query = query.filter(AuditLogEntry.event_type == event_type)
    if search:
        needle = f"%{search.strip()}%"
        query = query.filter(
            (AuditLogEntry.username.ilike(needle)) | (AuditLogEntry.detail.ilike(needle))
        )

    total = query.count()
    total_pages = max(1, (total + page_size - 1) // page_size)
    page = min(page, total_pages)

    entries = (
        query.order_by(AuditLogEntry.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    items = [
        AuditLogOut(
            id=e.id, event_type=e.event_type, username=e.username, ip_address=e.ip_address,
            success=e.success, detail=e.detail, created_at=e.created_at.isoformat(),
        )
        for e in entries
    ]
    return PaginatedAuditLogOut(items=items, total=total, page=page, page_size=page_size, total_pages=total_pages)


@router.get("/audit-log/event-types")
async def list_audit_event_types(db: Session = Depends(get_db), _admin: User = Depends(require_admin)) -> list[str]:
    rows = db.query(AuditLogEntry.event_type).distinct().all()
    return sorted({r[0] for r in rows})


# --- Scan-Historie fuer aktive Scans (admin-only) --------------------------
#
# Nutzt die bereits bestehende tool_executions-Tabelle (die JEDE
# Tool-Ausfuehrung protokolliert), gefiltert auf Tools mit
# is_active_scan=True -- eigene Uebersicht, weil diese Tools potenziell
# gegen Dritte eingesetzt werden koennen und daher besondere
# Nachvollziehbarkeit verdienen (wer hat wann gegen welches Ziel
# gescannt).

class ScanHistoryEntryOut(BaseModel):
    id: int
    tool_slug: str
    username: str
    target: str | None
    success: bool
    ran_at: str
    error_message: str | None


class PaginatedScanHistoryOut(BaseModel):
    items: list[ScanHistoryEntryOut]
    total: int
    page: int
    page_size: int
    total_pages: int


def _active_scan_slugs() -> set[str]:
    return {slug for slug, module_cls in get_registry().items() if module_cls.is_active_scan}


def _extract_target(input_json: str | None) -> str | None:
    if not input_json:
        return None
    try:
        data = json.loads(input_json)
    except (json.JSONDecodeError, TypeError):
        return None
    return data.get("target") or data.get("domain") or data.get("subdomain")


@router.get("/scan-history", response_model=PaginatedScanHistoryOut)
async def get_scan_history(
    search: str | None = None,
    tool_slug: str | None = None,
    page: int = 1,
    page_size: int = 50,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
) -> PaginatedScanHistoryOut:
    page = max(1, page)
    page_size = max(1, min(page_size, 200))

    active_slugs = _active_scan_slugs()
    query = db.query(ToolExecution).filter(ToolExecution.tool_slug.in_(active_slugs))
    if tool_slug:
        query = query.filter(ToolExecution.tool_slug == tool_slug)

    all_matching = query.order_by(ToolExecution.ran_at.desc()).all()

    user_ids = {e.user_id for e in all_matching}
    usernames = {u.id: u.username for u in db.query(User).filter(User.id.in_(user_ids)).all()} if user_ids else {}

    entries = []
    for e in all_matching:
        target = _extract_target(e.input_json)
        username = usernames.get(e.user_id, "?")
        if search:
            needle = search.strip().lower()
            haystack = f"{username} {target or ''}".lower()
            if needle not in haystack:
                continue
        entries.append(ScanHistoryEntryOut(
            id=e.id, tool_slug=e.tool_slug, username=username, target=target,
            success=e.success, ran_at=e.ran_at.isoformat(), error_message=e.error_message,
        ))

    total = len(entries)
    total_pages = max(1, (total + page_size - 1) // page_size)
    page = min(page, total_pages)
    start = (page - 1) * page_size
    page_items = entries[start : start + page_size]

    return PaginatedScanHistoryOut(items=page_items, total=total, page=page, page_size=page_size, total_pages=total_pages)


@router.get("/scan-history/tools")
async def list_scan_history_tools(_admin: User = Depends(require_admin)) -> list[str]:
    return sorted(_active_scan_slugs())


# --- Scan-Warteschlangen-Status (fuer alle eingeloggten Nutzer sichtbar) --
#
# Der isolierte toolbox-scanner-Container verarbeitet Jobs sequenziell
# (ein Worker, eine Warteschlange) -- damit ein neuer aktiver Scan nicht
# unerklaerlich lange bei "pending" haengt, zeigt das Frontend hier an,
# was gerade laeuft und wie viele Scans noch warten.

class CurrentScanJobOut(BaseModel):
    job_id: str
    template: str
    target: str | None
    started_at: str


class ScanQueueStatusOut(BaseModel):
    current_job: CurrentScanJobOut | None
    queue_length: int


@router.get("/scan-queue-status", response_model=ScanQueueStatusOut)
async def get_scan_queue_status(_user: User = Depends(get_current_user)) -> ScanQueueStatusOut:
    from app.core.scan_queue import get_queue_status

    status = await get_queue_status()
    current_job = CurrentScanJobOut(**status["current_job"]) if status["current_job"] else None
    return ScanQueueStatusOut(current_job=current_job, queue_length=status["queue_length"])


# --- Sicherheits-Hygiene-Uebersicht (admin-only) --------------------------
#
# Zeigt Konten, deren 2FA-Secret schon sehr lange nicht mehr rotiert
# wurde -- rein informativ, keine Erzwingung. Alte, nie rotierte Secrets
# sind ein (kleines, aber reales) Risiko: je laenger ein Secret im
# Umlauf ist, desto mehr Gelegenheiten gab es fuer eine Kompromittierung.

STALE_TOTP_THRESHOLD_DAYS = 180


class StaleTotpUserOut(BaseModel):
    username: str
    days_since_rotation: int | None  # None = nie rotiert (kein bekannter Zeitpunkt)


class SecurityHygieneOut(BaseModel):
    stale_totp_threshold_days: int
    users_with_stale_totp: list[StaleTotpUserOut]


@router.get("/security-hygiene", response_model=SecurityHygieneOut)
async def get_security_hygiene(db: Session = Depends(get_db), _admin: User = Depends(require_admin)) -> SecurityHygieneOut:
    now = datetime.now(timezone.utc)
    stale_users = []
    for user in db.query(User).filter(User.totp_enabled.is_(True)).all():
        if user.totp_rotated_at is None:
            stale_users.append(StaleTotpUserOut(username=user.username, days_since_rotation=None))
            continue
        rotated_at = user.totp_rotated_at
        if rotated_at.tzinfo is None:
            rotated_at = rotated_at.replace(tzinfo=timezone.utc)
        days = (now - rotated_at).days
        if days >= STALE_TOTP_THRESHOLD_DAYS:
            stale_users.append(StaleTotpUserOut(username=user.username, days_since_rotation=days))

    return SecurityHygieneOut(stale_totp_threshold_days=STALE_TOTP_THRESHOLD_DAYS, users_with_stale_totp=stale_users)


@router.post("/dns-cache/flush")
async def flush_dns_cache(request: Request, db: Session = Depends(get_db), admin: User = Depends(require_admin)) -> dict:
    """Leert den DNS-Cache von AdGuard Home ueber dessen EIGENE REST-API
    (POST /control/cache_clear, HTTP-Basic-Auth) -- bewusst NICHT ueber
    Host-Shell-Zugriff (siehe Kommentar bei den Settings-Feldern in
    app/core/config.py: ein containerisiertes Backend mit beliebiger
    Host-Befehlsausfuehrung waere praktisch ein Remote-Root-Zugriff auf
    den Server, das bauen wir nicht). Erfordert ADGUARD_HOME_URL/
    ADGUARD_HOME_USERNAME/ADGUARD_HOME_PASSWORD in der Server-Konfiguration.
    """
    if not settings.adguard_home_url or not settings.adguard_home_username:
        raise HTTPException(
            status_code=400,
            detail="AdGuard Home ist nicht konfiguriert (ADGUARD_HOME_URL/ADGUARD_HOME_USERNAME/ADGUARD_HOME_PASSWORD in der .env setzen).",
        )

    url = f"{settings.adguard_home_url.rstrip('/')}/control/cache_clear"
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.post(
                url,
                auth=(settings.adguard_home_username, settings.adguard_home_password or ""),
                headers={"Content-Type": "application/json"},
                content="{}",
            )
    except httpx.HTTPError as exc:
        log_audit_event(db, "dns_cache_flush", success=False, username=admin.username, ip_address=get_client_ip(request), detail=str(exc))
        raise HTTPException(status_code=502, detail=f"AdGuard Home nicht erreichbar: {exc}") from exc

    if response.status_code >= 400:
        log_audit_event(db, "dns_cache_flush", success=False, username=admin.username, ip_address=get_client_ip(request), detail=f"HTTP {response.status_code}")
        raise HTTPException(status_code=502, detail=f"AdGuard Home meldete einen Fehler (HTTP {response.status_code}).")

    log_audit_event(db, "dns_cache_flush", success=True, username=admin.username, ip_address=get_client_ip(request), detail=None)
    return {"success": True}
