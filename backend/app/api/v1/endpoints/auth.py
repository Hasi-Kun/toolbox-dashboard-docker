from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url

from app.api.deps import get_current_user
from app.core.audit import get_client_ip, log_audit_event
from app.core.config import get_settings
from app.core.db import get_db
from app.core.ip_restriction import is_ip_allowed
from app.core.rate_limit import clear_failed_login_count, enforce_account_lockout, enforce_rate_limit, record_failed_login
from app.core.security import hash_password, verify_password
from app.core.sessions import (
    create_pending,
    create_session,
    delete_pending,
    delete_session,
    get_pending,
    update_pending,
)
from app.core.totp import generate_secret, provisioning_uri, qr_code_data_uri, verify_code
from app.core.webauthn_helpers import (
    build_authentication_options,
    build_registration_options,
    verify_authentication,
    verify_registration,
)
from app.models.user import InviteCode, User, WebAuthnCredential

settings = get_settings()
router = APIRouter()


def _set_session_cookie(response: Response, session_id: str) -> None:
    response.set_cookie(
        key=settings.session_cookie_name,
        value=session_id,
        httponly=True,
        secure=settings.environment == "production",
        samesite="lax",
        max_age=settings.session_ttl_seconds,
        path="/",
    )


async def _resolve_pending(pending_id: str, db: Session) -> tuple[dict, User]:
    pending = await get_pending(pending_id)
    if pending is None:
        raise HTTPException(status_code=401, detail="Login-Vorgang abgelaufen, bitte erneut anmelden")
    user = db.get(User, pending["user_id"])
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="Account nicht (mehr) aktiv")
    return pending, user


# --- Request/Response Schemas ---------------------------------------------

class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    pending_token: str
    needs_2fa_setup: bool
    available_methods: list[str]


class PendingOnlyRequest(BaseModel):
    pending_token: str


class TotpVerifyRequest(PendingOnlyRequest):
    code: str


class TotpSetupStartResponse(BaseModel):
    secret: str
    otpauth_uri: str
    qr_code: str


class PasskeyVerifyRequest(PendingOnlyRequest):
    credential: dict


class PasskeyRegisterVerifyRequest(PendingOnlyRequest):
    credential: dict
    nickname: str | None = None


class MeResponse(BaseModel):
    id: int
    username: str
    role: str
    has_2fa: bool
    invite_quota: int
    is_premium: bool
    premium_badge_color: str
    display_name_style: str
    display_name_color: str
    display_name_gradient_color: str


# --- Schritt 1: Passwort -----------------------------------------------------

@router.post("/login", response_model=LoginResponse)
async def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)) -> LoginResponse:
    await enforce_rate_limit(request, bucket="auth-login", limit=settings.login_rate_limit_per_minute)
    # Zusaetzlich zum IP-basierten Limit: Konto-Sperre nach zu vielen
    # fehlgeschlagenen Versuchen, UNABHAENGIG von der IP -- schuetzt
    # gegen Brute-Force mit rotierenden IPs (z.B. Botnet), das das reine
    # IP-Limit sonst umgehen koennte.
    await enforce_account_lockout(payload.username)

    user = db.query(User).filter(User.username == payload.username).first()
    ip = get_client_ip(request)

    # Bewusst derselbe Fehlertext bei unbekanntem Username UND falschem
    # Passwort -- verhindert, dass ein Angreifer gueltige Usernamen erraten kann.
    if user is None or not user.is_active or not verify_password(payload.password, user.password_hash):
        log_audit_event(db, "login_password", success=False, username=payload.username, ip_address=ip)
        await record_failed_login(payload.username)
        raise HTTPException(status_code=401, detail="Ungueltiger Benutzername oder Passwort")

    log_audit_event(db, "login_password", success=True, username=user.username, ip_address=ip)
    await clear_failed_login_count(user.username)

    # Optionale, vom Nutzer selbst gesetzte IP-Beschraenkung -- greift
    # NACH dem Passwort-Check (verhindert, dass ein Angreifer per
    # Fehlermeldung unterscheiden kann "falsches Passwort" vs. "falsche
    # IP"), aber VOR der 2FA-Abfrage (kein Grund, ueberhaupt einen
    # 2FA-Code zu verlangen, wenn die IP ohnehin nicht erlaubt ist).
    if not is_ip_allowed(ip, user.allowed_login_ips):
        log_audit_event(
            db, "login_blocked_ip", success=False, username=user.username, ip_address=ip,
            detail="Login von nicht erlaubter IP-Adresse blockiert",
        )
        raise HTTPException(status_code=403, detail="Login von dieser IP-Adresse ist fuer dieses Konto nicht erlaubt.")

    pending_id = await create_pending(user.id, "login")

    methods: list[str] = []
    if user.totp_enabled:
        methods.append("totp")
    if user.webauthn_credentials:
        methods.append("passkey")

    return LoginResponse(
        pending_token=pending_id,
        needs_2fa_setup=not user.has_2fa,
        available_methods=methods,
    )


# --- Registrierung per Invite-Code ------------------------------------------

class RegisterRequest(BaseModel):
    invite_code: str
    username: str
    password: str

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        v = v.strip()
        if not v or len(v) > 64:
            raise ValueError("Ungueltiger Benutzername")
        return v

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if len(v) < 12:
            raise ValueError("Passwort muss mindestens 12 Zeichen haben")
        return v


@router.post("/register", response_model=LoginResponse)
async def register(payload: RegisterRequest, request: Request, db: Session = Depends(get_db)) -> LoginResponse:
    # Rate-Limit verhindert Brute-Forcing von Invite-Codes
    await enforce_rate_limit(request, bucket="auth-register", limit=settings.login_rate_limit_per_minute)

    invite = db.query(InviteCode).filter(InviteCode.code == payload.invite_code.strip()).first()
    if invite is None:
        raise HTTPException(status_code=400, detail="Ungueltiger Einladungscode")
    if invite.used_at is not None:
        raise HTTPException(status_code=400, detail="Dieser Einladungscode wurde bereits verwendet")
    if invite.expires_at is not None:
        expires_at = invite.expires_at
        if expires_at.tzinfo is None:
            # SQLite gibt DateTime(timezone=True)-Werte als naive datetimes
            # zurueck -- wir schreiben ausschliesslich UTC, also hier explizit
            # als UTC interpretieren statt versehentlich lokale Zeit anzunehmen.
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at < datetime.now(timezone.utc):
            raise HTTPException(status_code=400, detail="Dieser Einladungscode ist abgelaufen")

    if db.query(User).filter(User.username == payload.username).first() is not None:
        raise HTTPException(status_code=409, detail="Benutzername bereits vergeben")

    user = User(
        username=payload.username,
        password_hash=hash_password(payload.password),
        role=invite.role,
        is_active=True,
    )
    db.add(user)
    db.flush()  # user.id verfuegbar machen, ohne schon zu committen

    invite.used_by_id = user.id
    invite.used_at = datetime.now(timezone.utc)
    db.add(invite)
    db.commit()
    db.refresh(user)

    # Direkt in den 2FA-Setup-Flow uebergeben -- exakt derselbe Mechanismus
    # wie beim normalen Login, damit das Frontend dieselbe UI wiederverwenden kann.
    pending_id = await create_pending(user.id, "login")
    return LoginResponse(pending_token=pending_id, needs_2fa_setup=True, available_methods=[])


# --- Schritt 2a: TOTP-Verifikation (Account hat bereits 2FA) ----------------

@router.post("/2fa/totp/verify")
async def verify_totp_login(
    payload: TotpVerifyRequest, request: Request, response: Response, db: Session = Depends(get_db)
) -> dict:
    await enforce_rate_limit(request, bucket="auth-2fa", limit=settings.login_rate_limit_per_minute)
    _, user = await _resolve_pending(payload.pending_token, db)

    if not user.totp_enabled or not user.totp_secret:
        raise HTTPException(status_code=400, detail="TOTP ist fuer diesen Account nicht aktiviert")
    if not verify_code(user.totp_secret, payload.code):
        log_audit_event(db, "login_2fa", success=False, username=user.username, ip_address=get_client_ip(request))
        raise HTTPException(status_code=401, detail="Code ungueltig oder abgelaufen")

    log_audit_event(db, "login_2fa", success=True, username=user.username, ip_address=get_client_ip(request))
    session_id = await create_session(
        user.id, ttl_seconds=(user.session_timeout_minutes * 60) if user.session_timeout_minutes else None
    )
    await delete_pending(payload.pending_token)
    _set_session_cookie(response, session_id)
    return {"success": True}


# --- Schritt 2a (Setup): TOTP erstmalig einrichten --------------------------

@router.post("/2fa/totp/setup/start", response_model=TotpSetupStartResponse)
async def start_totp_setup(payload: PendingOnlyRequest, db: Session = Depends(get_db)) -> TotpSetupStartResponse:
    _, user = await _resolve_pending(payload.pending_token, db)
    if user.has_2fa:
        raise HTTPException(status_code=400, detail="2FA ist fuer diesen Account bereits eingerichtet")

    secret = generate_secret()
    uri = provisioning_uri(secret, user.username)
    await update_pending(payload.pending_token, {"totp_setup_secret": secret})

    return TotpSetupStartResponse(secret=secret, otpauth_uri=uri, qr_code=qr_code_data_uri(uri))


@router.post("/2fa/totp/setup/verify")
async def verify_totp_setup(payload: TotpVerifyRequest, request: Request, response: Response, db: Session = Depends(get_db)) -> dict:
    pending, user = await _resolve_pending(payload.pending_token, db)
    secret = pending.get("totp_setup_secret")
    if not secret:
        raise HTTPException(status_code=400, detail="Kein TOTP-Setup gestartet")
    if not verify_code(secret, payload.code):
        raise HTTPException(status_code=401, detail="Code ungueltig oder abgelaufen")

    user.totp_secret = secret
    user.totp_enabled = True
    user.totp_rotated_at = datetime.now(timezone.utc)
    db.add(user)
    db.commit()

    session_id = await create_session(
        user.id, ttl_seconds=(user.session_timeout_minutes * 60) if user.session_timeout_minutes else None
    )
    await delete_pending(payload.pending_token)
    _set_session_cookie(response, session_id)
    log_audit_event(
        db, "totp_enabled", success=True, username=user.username, ip_address=get_client_ip(request),
        detail="Ersteinrichtung waehrend Registrierung/Login",
    )
    return {"success": True}


# --- Schritt 2b: Passkey-Login (Account hat bereits einen Passkey) ---------

@router.post("/2fa/passkey/login/start")
async def start_passkey_login(payload: PendingOnlyRequest, db: Session = Depends(get_db)) -> dict:
    _, user = await _resolve_pending(payload.pending_token, db)
    if not user.webauthn_credentials:
        raise HTTPException(status_code=400, detail="Kein Passkey fuer diesen Account registriert")

    options_json, challenge = build_authentication_options(user)
    await update_pending(payload.pending_token, {"webauthn_challenge": bytes_to_base64url(challenge)})
    return {"options": options_json}


@router.post("/2fa/passkey/login/verify")
async def verify_passkey_login(payload: PasskeyVerifyRequest, response: Response, db: Session = Depends(get_db)) -> dict:
    pending, user = await _resolve_pending(payload.pending_token, db)
    challenge_b64 = pending.get("webauthn_challenge")
    if not challenge_b64:
        raise HTTPException(status_code=400, detail="Kein Passkey-Vorgang gestartet")

    credential_id = payload.credential.get("rawId") or payload.credential.get("id")
    stored = db.query(WebAuthnCredential).filter(WebAuthnCredential.credential_id == credential_id).first()
    if stored is None or stored.user_id != user.id:
        raise HTTPException(status_code=401, detail="Unbekannter Passkey")

    try:
        new_sign_count = verify_authentication(payload.credential, base64url_to_bytes(challenge_b64), stored)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=401, detail="Passkey-Verifikation fehlgeschlagen") from exc

    stored.sign_count = new_sign_count
    db.add(stored)
    db.commit()

    session_id = await create_session(
        user.id, ttl_seconds=(user.session_timeout_minutes * 60) if user.session_timeout_minutes else None
    )
    await delete_pending(payload.pending_token)
    _set_session_cookie(response, session_id)
    return {"success": True}


# --- Schritt 2b (Setup): Passkey erstmalig registrieren --------------------

@router.post("/2fa/passkey/register/start")
async def start_passkey_registration(payload: PendingOnlyRequest, db: Session = Depends(get_db)) -> dict:
    _, user = await _resolve_pending(payload.pending_token, db)
    options_json, challenge = build_registration_options(user)
    await update_pending(payload.pending_token, {"webauthn_challenge": bytes_to_base64url(challenge)})
    return {"options": options_json}


@router.post("/2fa/passkey/register/verify")
async def verify_passkey_registration(
    payload: PasskeyRegisterVerifyRequest, response: Response, db: Session = Depends(get_db)
) -> dict:
    pending, user = await _resolve_pending(payload.pending_token, db)
    if user.has_2fa:
        raise HTTPException(status_code=400, detail="2FA ist fuer diesen Account bereits eingerichtet")

    challenge_b64 = pending.get("webauthn_challenge")
    if not challenge_b64:
        raise HTTPException(status_code=400, detail="Kein Passkey-Setup gestartet")

    try:
        credential_id, public_key = verify_registration(payload.credential, base64url_to_bytes(challenge_b64))
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail="Passkey-Registrierung fehlgeschlagen") from exc

    db.add(
        WebAuthnCredential(
            user_id=user.id,
            credential_id=credential_id,
            public_key=public_key,
            nickname=payload.nickname or "Passkey",
        )
    )
    db.commit()

    session_id = await create_session(
        user.id, ttl_seconds=(user.session_timeout_minutes * 60) if user.session_timeout_minutes else None
    )
    await delete_pending(payload.pending_token)
    _set_session_cookie(response, session_id)
    return {"success": True}


# --- Logout / aktueller User -------------------------------------------------

@router.post("/logout")
async def logout(request: Request, response: Response) -> dict:
    session_id = request.cookies.get(settings.session_cookie_name)
    if session_id:
        await delete_session(session_id)
    response.delete_cookie(settings.session_cookie_name, path="/")
    return {"success": True}


@router.get("/me", response_model=MeResponse)
async def me(user: User = Depends(get_current_user)) -> MeResponse:
    return MeResponse(
        id=user.id, username=user.username, role=user.role, has_2fa=user.has_2fa,
        invite_quota=user.invite_quota, is_premium=user.is_premium, premium_badge_color=user.premium_badge_color,
        display_name_style=user.display_name_style, display_name_color=user.display_name_color,
        display_name_gradient_color=user.display_name_gradient_color,
    )
