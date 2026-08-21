"""Microsoft-365-SSO (OAuth2/OIDC Authorization-Code-Flow gegen
Microsoft Entra ID). Bewusst NUR fuer bereits per Admin angelegte und
ueber `microsoft_upn` verknuepfte Konten -- kein automatisches Anlegen
neuer Nutzer ueber SSO, konsistent mit dem bestehenden Invite-only-
Prinzip der Toolbox.

Ablauf:
1. GET /login  -- leitet zu Microsofts Login-Seite weiter (mit einem
   zufaelligen state-Parameter als CSRF-Schutz, kurzlebig in Redis
   zwischengespeichert).
2. Microsoft leitet nach erfolgreichem Login zu /callback zurueck.
3. /callback tauscht den Authorization Code gegen ein Access-Token,
   ruft damit Microsoft Graph (/me) ab, um die UPN/E-Mail zu ermitteln,
   sucht ein lokales Konto mit passendem microsoft_upn, und meldet den
   Nutzer an (setzt das normale Session-Cookie) -- SSO ersetzt dabei
   lokales Passwort UND 2FA (Microsofts eigene Login-/MFA-Richtlinien
   auf Tenant-Seite uebernehmen diese Rolle).
"""

import secrets
import urllib.parse

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.api.v1.endpoints.auth import _set_session_cookie
from app.core.audit import get_client_ip, log_audit_event
from app.core.config import get_settings
from app.core.db import get_db
from app.core.ip_restriction import is_ip_allowed
from app.core.sessions import create_session, get_transient, store_transient
from app.models.user import User

router = APIRouter(prefix="/auth/sso/microsoft", tags=["sso"])
settings = get_settings()

_AUTHORIZE_URL_TMPL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize"
_TOKEN_URL_TMPL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
_GRAPH_ME_URL = "https://graph.microsoft.com/v1.0/me"
_STATE_TTL_SECONDS = 600  # 10 Minuten Zeit, um den Microsoft-Login abzuschliessen


def _is_configured() -> bool:
    return bool(settings.ms_sso_enabled and settings.ms_sso_client_id and settings.ms_sso_tenant_id and settings.ms_sso_client_secret)


def _redirect_uri() -> str:
    # WICHTIG: dies ist die OEFFENTLICHE URL, die Microsoft nach dem
    # Login ansteuert -- ALLER oeffentlicher Traffic laeuft ueber Caddy
    # zum Next.js-Frontend (Port 3000), das erst INTERN an dieses
    # Backend weiterreicht (BFF-Muster). Das "/api/v1/..."-Praefix ist
    # rein intern (nur zwischen Next.js und diesem Backend-Container
    # sichtbar) -- die oeffentliche, bei Microsoft registrierte
    # Redirect-URI muss stattdessen Next.js' eigene Route treffen:
    # "/api/auth/sso/microsoft/callback" (ohne "/v1"). Diese Next.js-
    # Route reicht die Anfrage dann intern an genau diesen Endpunkt hier
    # weiter (siehe frontend/app/api/auth/sso/microsoft/callback/route.ts).
    return f"{settings.webauthn_origin}/api/auth/sso/microsoft/callback"


@router.get("/status")
async def sso_status() -> dict:
    """Oeffentlich (kein Login noetig) -- das Frontend fragt das ab, um
    den 'Mit Microsoft anmelden'-Button nur zu zeigen, wenn SSO
    tatsaechlich konfiguriert ist."""
    return {"enabled": _is_configured()}


@router.get("/login")
async def sso_login() -> RedirectResponse:
    if not _is_configured():
        raise HTTPException(status_code=404, detail="Microsoft SSO ist nicht konfiguriert.")

    state = secrets.token_urlsafe(32)
    await store_transient(f"sso-state:{state}", {"created": True}, ttl_seconds=_STATE_TTL_SECONDS)

    params = {
        "client_id": settings.ms_sso_client_id,
        "response_type": "code",
        "redirect_uri": _redirect_uri(),
        "response_mode": "query",
        "scope": "openid profile email User.Read",
        "state": state,
    }
    authorize_url = _AUTHORIZE_URL_TMPL.format(tenant=settings.ms_sso_tenant_id) + "?" + urllib.parse.urlencode(params)
    return RedirectResponse(authorize_url)


@router.get("/callback")
async def sso_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
    db: Session = Depends(get_db),
) -> RedirectResponse:
    if not _is_configured():
        raise HTTPException(status_code=404, detail="Microsoft SSO ist nicht konfiguriert.")

    if error:
        raise HTTPException(status_code=400, detail=f"Microsoft-Anmeldung fehlgeschlagen: {error_description or error}")
    if not code or not state:
        raise HTTPException(status_code=400, detail="Ungueltige SSO-Antwort (fehlender code/state-Parameter).")

    stored_state = await get_transient(f"sso-state:{state}")
    if stored_state is None:
        raise HTTPException(status_code=400, detail="Ungueltiger oder abgelaufener SSO-State (CSRF-Schutz) -- bitte erneut versuchen.")

    token_url = _TOKEN_URL_TMPL.format(tenant=settings.ms_sso_tenant_id)
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            token_response = await client.post(token_url, data={
                "client_id": settings.ms_sso_client_id,
                "client_secret": settings.ms_sso_client_secret,
                "code": code,
                "redirect_uri": _redirect_uri(),
                "grant_type": "authorization_code",
            })
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail=f"Microsoft nicht erreichbar: {exc}") from exc

        if token_response.status_code != 200:
            raise HTTPException(status_code=400, detail="Token-Austausch mit Microsoft fehlgeschlagen -- Client-Secret/Konfiguration pruefen.")

        access_token = token_response.json().get("access_token")
        if not access_token:
            raise HTTPException(status_code=400, detail="Microsoft hat kein Access-Token zurueckgegeben.")

        try:
            me_response = await client.get(_GRAPH_ME_URL, headers={"Authorization": f"Bearer {access_token}"})
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail=f"Microsoft Graph nicht erreichbar: {exc}") from exc

        if me_response.status_code != 200:
            raise HTTPException(status_code=400, detail="Profilabruf bei Microsoft Graph fehlgeschlagen.")
        me_data = me_response.json()

    upn = me_data.get("userPrincipalName") or me_data.get("mail")
    ip = get_client_ip(request)

    if not upn:
        log_audit_event(db, "sso_login_microsoft", success=False, username=None, ip_address=ip, detail="Keine UPN/E-Mail im Microsoft-Profil")
        raise HTTPException(status_code=400, detail="Konnte keine E-Mail/UPN aus dem Microsoft-Profil ermitteln.")

    user = db.query(User).filter(User.microsoft_upn == upn).first()

    if user is None or not user.is_active:
        log_audit_event(db, "sso_login_microsoft", success=False, username=upn, ip_address=ip, detail="Kein verknuepftes lokales Konto")
        raise HTTPException(
            status_code=403,
            detail="Kein lokales Konto mit dieser Microsoft-Identitaet verknuepft. Bitte einen Administrator bitten, dein Konto unter Benutzerverwaltung zu verknuepfen.",
        )

    if not is_ip_allowed(ip, user.allowed_login_ips):
        log_audit_event(db, "sso_login_microsoft", success=False, username=user.username, ip_address=ip, detail="Login von nicht erlaubter IP-Adresse blockiert")
        raise HTTPException(status_code=403, detail="Login von dieser IP-Adresse ist fuer dieses Konto nicht erlaubt.")

    log_audit_event(db, "sso_login_microsoft", success=True, username=user.username, ip_address=ip)

    session_id = await create_session(
        user.id, ttl_seconds=(user.session_timeout_minutes * 60) if user.session_timeout_minutes else None
    )
    redirect = RedirectResponse(url=settings.webauthn_origin, status_code=302)
    _set_session_cookie(redirect, session_id)
    return redirect
