"""Captcha-Verifikation (Cloudflare Turnstile oder Google reCAPTCHA).

Provider-agnostisch: liest die aktuelle Konfiguration aus der DB
(SecuritySettings, Singleton) und ruft den passenden Verify-Endpunkt des
Anbieters auf. Wenn Captcha nicht aktiviert/vollstaendig konfiguriert
ist, gilt jede Anfrage als bestanden (No-Op) -- das Feature ist optional
und darf niemanden aussperren, nur weil es nicht eingerichtet wurde.
"""

import httpx
from sqlalchemy.orm import Session

from app.models.user import SecuritySettings

_TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
_RECAPTCHA_VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify"


def get_security_settings(db: Session) -> SecuritySettings:
    settings = db.get(SecuritySettings, 1)
    if settings is None:
        settings = SecuritySettings(id=1)
        db.add(settings)
        db.commit()
        db.refresh(settings)
    return settings


def is_captcha_required(db: Session, context: str) -> bool:
    """context: 'login' oder 'register'."""
    settings = get_security_settings(db)
    if not settings.captcha_enabled or settings.captcha_provider == "none":
        return False
    if not settings.captcha_secret_key or not settings.captcha_site_key:
        # Unvollstaendig konfiguriert -- lieber durchlassen als versehentlich alle auszusperren.
        return False
    if context == "login":
        return settings.captcha_on_login
    if context == "register":
        return settings.captcha_on_register
    return False


async def verify_captcha(db: Session, token: str | None, remote_ip: str | None = None) -> bool:
    """Prueft ein Captcha-Token gegen den konfigurierten Provider. True,
    wenn Captcha nicht aktiv ist (No-Op) oder das Token gueltig war."""
    settings = get_security_settings(db)
    if not settings.captcha_enabled or settings.captcha_provider == "none" or not settings.captcha_secret_key:
        return True

    if not token:
        return False

    verify_url = _TURNSTILE_VERIFY_URL if settings.captcha_provider == "turnstile" else _RECAPTCHA_VERIFY_URL
    data = {"secret": settings.captcha_secret_key, "response": token}
    if remote_ip:
        data["remoteip"] = remote_ip

    try:
        async with httpx.AsyncClient(timeout=8) as client:
            resp = await client.post(verify_url, data=data)
        body = resp.json()
        return bool(body.get("success"))
    except (httpx.HTTPError, ValueError):
        # Fail-Closed bei Netzwerk-/Parsing-Fehlern: lieber eine echte
        # Anfrage kurz ablehnen (kann der Nutzer erneut versuchen), als
        # eine kaputte Captcha-Pruefung stillschweigend zu umgehen.
        return False
