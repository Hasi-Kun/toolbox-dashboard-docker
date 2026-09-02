"""DNS-Cache leeren (AdGuard Home) -- AdGuard Home cached DNS-Antworten
lokal; nach Aenderungen an eigenen DNS-Records kann ein veralteter
Cache-Eintrag die Aktualisierung verzoegern (von AdGuard Home selbst
als bekanntes Verhalten dokumentiert, siehe
github.com/AdguardTeam/AdGuardHome Issue #1905).

Ruft AdGuard Home's eigenen `POST /control/cache_clear`-Endpunkt auf
(Basic Auth, JSON-Content-Type -- beides von AdGuard Home zwingend
gefordert, siehe deren OpenAPI-Spezifikation).
"""

import logging

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from app.api.deps import require_admin
from app.core.audit import get_client_ip, log_audit_event
from app.core.db import get_db
from app.core.ssh_vault import encrypt_secret
from app.models.user import AdguardSettings, User

logger = logging.getLogger("toolbox.dns_flush")
router = APIRouter(prefix="/system/dns-flush", tags=["dns-flush"])


def _get_settings(db: Session) -> AdguardSettings:
    settings = db.get(AdguardSettings, 1)
    if settings is None:
        settings = AdguardSettings(id=1)
        db.add(settings)
        db.commit()
        db.refresh(settings)
    return settings


class AdguardConfigOut(BaseModel):
    configured: bool
    base_url: str | None
    username: str | None


class UpdateAdguardConfigRequest(BaseModel):
    base_url: str
    username: str
    password: str | None = None  # None = vorhandenes Passwort NICHT aendern

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, v: str) -> str:
        v = v.strip().rstrip("/")
        if not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError("base_url muss mit http:// oder https:// beginnen")
        return v


@router.get("/config", response_model=AdguardConfigOut)
async def get_config(db: Session = Depends(get_db), _admin: User = Depends(require_admin)) -> AdguardConfigOut:
    settings = _get_settings(db)
    return AdguardConfigOut(configured=settings.configured, base_url=settings.base_url, username=settings.username)


@router.put("/config", response_model=AdguardConfigOut)
async def update_config(
    payload: UpdateAdguardConfigRequest, db: Session = Depends(get_db), _admin: User = Depends(require_admin)
) -> AdguardConfigOut:
    settings = _get_settings(db)
    settings.base_url = payload.base_url
    settings.username = payload.username
    if payload.password is not None:
        settings.encrypted_password = encrypt_secret(payload.password)
    settings.configured = bool(settings.base_url and settings.username and settings.encrypted_password)
    db.add(settings)
    db.commit()
    db.refresh(settings)
    return AdguardConfigOut(configured=settings.configured, base_url=settings.base_url, username=settings.username)


@router.post("")
async def flush_dns_cache(request: Request, db: Session = Depends(get_db), admin: User = Depends(require_admin)) -> dict:
    from app.core.ssh_vault import decrypt_secret

    settings = _get_settings(db)
    if not settings.configured:
        raise HTTPException(status_code=400, detail="AdGuard Home ist nicht konfiguriert (siehe Einstellungen -> Sicherheit).")

    password = decrypt_secret(settings.encrypted_password)
    url = f"{settings.base_url}/control/cache_clear"

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.post(
                url, auth=(settings.username, password),
                headers={"Content-Type": "application/json"}, json={},
            )
    except httpx.HTTPError as exc:
        log_audit_event(db, "dns_cache_flush", success=False, username=admin.username, ip_address=get_client_ip(request), detail=str(exc))
        raise HTTPException(status_code=502, detail=f"AdGuard Home nicht erreichbar: {exc}") from exc

    if response.status_code != 200:
        log_audit_event(db, "dns_cache_flush", success=False, username=admin.username, ip_address=get_client_ip(request), detail=f"HTTP {response.status_code}: {response.text[:200]}")
        raise HTTPException(status_code=502, detail=f"AdGuard Home meldete einen Fehler (HTTP {response.status_code}).")

    log_audit_event(db, "dns_cache_flush", success=True, username=admin.username, ip_address=get_client_ip(request), detail=None)
    return {"success": True}
