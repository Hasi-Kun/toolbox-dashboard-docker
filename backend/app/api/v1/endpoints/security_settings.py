"""Instanzweite Captcha-Einstellungen (Cloudflare Turnstile oder Google
reCAPTCHA) fuer Login/Registrierung.

WICHTIG: strikt getrennte Endpunkte fuer oeffentliche und admin-only
Daten -- der Secret-Key darf NIE ueber den oeffentlichen Endpunkt
zurueckgegeben werden (den auch die Login-Seite vor jeder Anmeldung
abfragt, um zu wissen, ob/welches Captcha-Widget gerendert werden muss).
"""

from fastapi import APIRouter, Depends
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from app.api.deps import require_admin
from app.core.captcha import get_security_settings
from app.core.db import get_db
from app.models.user import SecuritySettings, User

router = APIRouter()

ALLOWED_PROVIDERS = {"none", "turnstile", "recaptcha"}


class PublicCaptchaOut(BaseModel):
    provider: str
    enabled: bool
    site_key: str | None
    on_login: bool
    on_register: bool


class AdminCaptchaOut(BaseModel):
    provider: str
    enabled: bool
    site_key: str | None
    secret_key: str | None
    on_login: bool
    on_register: bool


def _to_admin_out(settings: SecuritySettings) -> AdminCaptchaOut:
    return AdminCaptchaOut(
        provider=settings.captcha_provider,
        enabled=settings.captcha_enabled,
        site_key=settings.captcha_site_key,
        secret_key=settings.captcha_secret_key,
        on_login=settings.captcha_on_login,
        on_register=settings.captcha_on_register,
    )


class UpdateCaptchaRequest(BaseModel):
    provider: str
    enabled: bool
    site_key: str | None = None
    secret_key: str | None = None
    on_login: bool = True
    on_register: bool = True

    @field_validator("provider")
    @classmethod
    def validate_provider(cls, v: str) -> str:
        if v not in ALLOWED_PROVIDERS:
            raise ValueError(f"Ungueltiger Anbieter, erlaubt: {sorted(ALLOWED_PROVIDERS)}")
        return v

    @field_validator("site_key", "secret_key")
    @classmethod
    def validate_keys(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip()
        if len(v) > 255:
            raise ValueError("Schluessel zu lang")
        return v or None


@router.get("/security-settings/public", response_model=PublicCaptchaOut)
async def get_public_captcha_settings(db: Session = Depends(get_db)) -> PublicCaptchaOut:
    """Bewusst OHNE Auth -- die Login-/Registrierungsseite muss wissen,
    ob und welches Captcha-Widget sie rendern soll, bevor sich jemand
    angemeldet hat. Gibt absichtlich NIE den Secret-Key zurueck."""
    settings = get_security_settings(db)
    return PublicCaptchaOut(
        provider=settings.captcha_provider if settings.captcha_enabled else "none",
        enabled=settings.captcha_enabled and bool(settings.captcha_site_key) and bool(settings.captcha_secret_key),
        site_key=settings.captcha_site_key if settings.captcha_enabled else None,
        on_login=settings.captcha_on_login,
        on_register=settings.captcha_on_register,
    )


@router.get("/security-settings", response_model=AdminCaptchaOut)
async def get_admin_captcha_settings(db: Session = Depends(get_db), _admin: User = Depends(require_admin)) -> AdminCaptchaOut:
    return _to_admin_out(get_security_settings(db))


@router.patch("/security-settings", response_model=AdminCaptchaOut)
async def update_captcha_settings(
    payload: UpdateCaptchaRequest, db: Session = Depends(get_db), _admin: User = Depends(require_admin)
) -> AdminCaptchaOut:
    settings = get_security_settings(db)
    settings.captcha_provider = payload.provider
    settings.captcha_enabled = payload.enabled
    settings.captcha_site_key = payload.site_key
    # Secret-Key nur ueberschreiben, wenn tatsaechlich einer mitgeschickt
    # wurde -- so kann das Frontend den Secret-Key beim Bearbeiten leer
    # lassen (z.B. weil es ihn aus Sicherheitsgruenden nicht vorausfuellt),
    # ohne einen bereits gespeicherten Key versehentlich zu loeschen.
    if payload.secret_key is not None:
        settings.captcha_secret_key = payload.secret_key
    settings.captcha_on_login = payload.on_login
    settings.captcha_on_register = payload.on_register
    db.add(settings)
    db.commit()
    db.refresh(settings)
    return _to_admin_out(settings)
