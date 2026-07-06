import json
import re

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url

from app.api.deps import get_current_user
from app.core.config import get_settings
from app.core.db import get_db
from app.core.rate_limit import enforce_rate_limit
from app.core.security import hash_password, verify_password
from app.core.sessions import delete_transient, get_transient, store_transient
from app.core.totp import generate_secret, provisioning_uri, qr_code_data_uri, verify_code
from app.core.webauthn_helpers import build_registration_options, verify_registration
from app.models.user import Favorite, ToolExecution, User, WebAuthnCredential
from app.modules import get_registry

settings = get_settings()
router = APIRouter()

_HEX_COLOR_RE = re.compile(r"^#[0-9a-fA-F]{6}$")
_ALLOWED_DISPLAY_STYLES = {"default", "solid", "gradient", "particles"}


# --- Schemas -----------------------------------------------------------

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, v: str) -> str:
        if len(v) < 12:
            raise ValueError("Neues Passwort muss mindestens 12 Zeichen haben")
        return v


class PasskeyOut(BaseModel):
    id: int
    nickname: str
    created_at: str

    model_config = {"from_attributes": True}


class TwoFactorStatusResponse(BaseModel):
    totp_enabled: bool
    passkeys: list[PasskeyOut]


class TotpSetupStartResponse(BaseModel):
    secret: str
    otpauth_uri: str
    qr_code: str


class TotpCodeRequest(BaseModel):
    code: str


class PasskeyRegisterVerifyRequest(BaseModel):
    credential: dict
    nickname: str | None = None


def _two_factor_status(user: User) -> TwoFactorStatusResponse:
    return TwoFactorStatusResponse(
        totp_enabled=user.totp_enabled,
        passkeys=[
            PasskeyOut(id=c.id, nickname=c.nickname, created_at=c.created_at.isoformat())
            for c in user.webauthn_credentials
        ],
    )


def _remaining_factors_after(user: User, *, drop_totp: bool = False, drop_passkey_id: int | None = None) -> int:
    totp_count = 1 if (user.totp_enabled and not drop_totp) else 0
    passkey_count = sum(1 for c in user.webauthn_credentials if c.id != drop_passkey_id)
    return totp_count + passkey_count


# --- Passwort aendern -----------------------------------------------------

@router.post("/me/password")
async def change_password(
    payload: ChangePasswordRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    await enforce_rate_limit(request, bucket="auth-password-change", limit=settings.login_rate_limit_per_minute)

    if not verify_password(payload.current_password, user.password_hash):
        raise HTTPException(status_code=401, detail="Aktuelles Passwort ist falsch")

    user.password_hash = hash_password(payload.new_password)
    db.add(user)
    db.commit()
    return {"success": True}


# --- 2FA-Uebersicht ---------------------------------------------------------

@router.get("/me/2fa", response_model=TwoFactorStatusResponse)
async def get_two_factor_status(user: User = Depends(get_current_user)) -> TwoFactorStatusResponse:
    return _two_factor_status(user)


# --- TOTP: hinzufuegen/rotieren, ohne dass ein Passkey angetastet wird -----

@router.post("/me/2fa/totp/setup/start", response_model=TotpSetupStartResponse)
async def start_totp_setup(user: User = Depends(get_current_user)) -> TotpSetupStartResponse:
    secret = generate_secret()
    uri = provisioning_uri(secret, user.username)
    await store_transient(f"totp_setup:{user.id}", {"secret": secret})
    return TotpSetupStartResponse(secret=secret, otpauth_uri=uri, qr_code=qr_code_data_uri(uri))


@router.post("/me/2fa/totp/setup/verify", response_model=TwoFactorStatusResponse)
async def verify_totp_setup(
    payload: TotpCodeRequest, db: Session = Depends(get_db), user: User = Depends(get_current_user)
) -> TwoFactorStatusResponse:
    transient = await get_transient(f"totp_setup:{user.id}")
    if transient is None:
        raise HTTPException(status_code=400, detail="Kein TOTP-Setup gestartet oder abgelaufen")

    if not verify_code(transient["secret"], payload.code):
        raise HTTPException(status_code=401, detail="Code ungueltig oder abgelaufen")

    user.totp_secret = transient["secret"]
    user.totp_enabled = True
    db.add(user)
    db.commit()
    await delete_transient(f"totp_setup:{user.id}")
    return _two_factor_status(user)


@router.post("/me/2fa/totp/disable", response_model=TwoFactorStatusResponse)
async def disable_totp(db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> TwoFactorStatusResponse:
    if _remaining_factors_after(user, drop_totp=True) < 1:
        raise HTTPException(
            status_code=400,
            detail="TOTP ist deine einzige 2FA-Methode -- richte zuerst einen Passkey ein, bevor du TOTP deaktivierst.",
        )

    user.totp_enabled = False
    user.totp_secret = None
    db.add(user)
    db.commit()
    return _two_factor_status(user)


# --- Passkeys: hinzufuegen/entfernen, ohne dass TOTP angetastet wird -------

@router.post("/me/2fa/passkey/register/start")
async def start_passkey_registration(user: User = Depends(get_current_user)) -> dict:
    options_json, challenge = build_registration_options(user)
    await store_transient(f"webauthn_challenge:{user.id}", {"challenge": bytes_to_base64url(challenge)})
    return {"options": options_json}


@router.post("/me/2fa/passkey/register/verify", response_model=TwoFactorStatusResponse)
async def verify_passkey_registration(
    payload: PasskeyRegisterVerifyRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> TwoFactorStatusResponse:
    transient = await get_transient(f"webauthn_challenge:{user.id}")
    if transient is None:
        raise HTTPException(status_code=400, detail="Kein Passkey-Setup gestartet oder abgelaufen")

    try:
        credential_id, public_key = verify_registration(
            payload.credential, base64url_to_bytes(transient["challenge"])
        )
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
    db.refresh(user)
    await delete_transient(f"webauthn_challenge:{user.id}")
    return _two_factor_status(user)


@router.delete("/me/2fa/passkey/{credential_id}", response_model=TwoFactorStatusResponse)
async def delete_passkey(
    credential_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)
) -> TwoFactorStatusResponse:
    credential = next((c for c in user.webauthn_credentials if c.id == credential_id), None)
    if credential is None:
        raise HTTPException(status_code=404, detail="Passkey nicht gefunden")

    if _remaining_factors_after(user, drop_passkey_id=credential_id) < 1:
        raise HTTPException(
            status_code=400,
            detail="Das ist deine einzige 2FA-Methode -- richte zuerst TOTP oder einen weiteren Passkey ein.",
        )

    db.delete(credential)
    db.commit()
    db.refresh(user)
    return _two_factor_status(user)


# --- Favoriten ---------------------------------------------------------

class FavoriteRequest(BaseModel):
    tool_slug: str

    @field_validator("tool_slug")
    @classmethod
    def validate_slug(cls, v: str) -> str:
        if v not in get_registry():
            raise ValueError(f"Unbekanntes Tool: {v}")
        return v


class FavoriteOut(BaseModel):
    tool_slug: str


@router.get("/me/favorites", response_model=list[FavoriteOut])
async def list_favorites(db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> list[Favorite]:
    return db.query(Favorite).filter(Favorite.user_id == user.id).order_by(Favorite.created_at).all()


@router.post("/me/favorites", response_model=FavoriteOut)
async def add_favorite(
    payload: FavoriteRequest, db: Session = Depends(get_db), user: User = Depends(get_current_user)
) -> Favorite:
    existing = (
        db.query(Favorite)
        .filter(Favorite.user_id == user.id, Favorite.tool_slug == payload.tool_slug)
        .first()
    )
    if existing:
        return existing

    favorite = Favorite(user_id=user.id, tool_slug=payload.tool_slug)
    db.add(favorite)
    db.commit()
    db.refresh(favorite)
    return favorite


@router.delete("/me/favorites/{tool_slug}")
async def remove_favorite(
    tool_slug: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)
) -> dict:
    db.query(Favorite).filter(Favorite.user_id == user.id, Favorite.tool_slug == tool_slug).delete()
    db.commit()
    return {"success": True}


# --- Verlauf ("Letzte Scans") -----------------------------------------

class ExecutionOut(BaseModel):
    id: int
    tool_slug: str
    success: bool
    ran_at: str


class ExecutionDetailOut(BaseModel):
    id: int
    tool_slug: str
    success: bool
    ran_at: str
    input: dict | None
    output: dict | None
    error_message: str | None


@router.get("/me/history", response_model=list[ExecutionOut])
async def get_history(
    limit: int = 10, db: Session = Depends(get_db), user: User = Depends(get_current_user)
) -> list[ExecutionOut]:
    limit = max(1, min(limit, 50))
    executions = (
        db.query(ToolExecution)
        .filter(ToolExecution.user_id == user.id)
        .order_by(ToolExecution.ran_at.desc())
        .limit(limit)
        .all()
    )
    return [
        ExecutionOut(id=e.id, tool_slug=e.tool_slug, success=e.success, ran_at=e.ran_at.isoformat())
        for e in executions
    ]


@router.get("/me/history/{execution_id}", response_model=ExecutionDetailOut)
async def get_history_detail(
    execution_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)
) -> ExecutionDetailOut:
    execution = (
        db.query(ToolExecution)
        .filter(ToolExecution.id == execution_id, ToolExecution.user_id == user.id)
        .first()
    )
    if execution is None:
        raise HTTPException(status_code=404, detail="Eintrag nicht gefunden")

    return ExecutionDetailOut(
        id=execution.id,
        tool_slug=execution.tool_slug,
        success=execution.success,
        ran_at=execution.ran_at.isoformat(),
        input=json.loads(execution.input_json) if execution.input_json else None,
        output=json.loads(execution.output_json) if execution.output_json else None,
        error_message=execution.error_message,
    )


# --- Anzeigename-Customizing (nur Premium) ---------------------------------

class DisplayStyleOut(BaseModel):
    display_name_style: str
    display_name_color: str
    display_name_gradient_color: str


class UpdateDisplayStyleRequest(BaseModel):
    display_name_style: str
    display_name_color: str
    display_name_gradient_color: str

    @field_validator("display_name_style")
    @classmethod
    def validate_style(cls, v: str) -> str:
        if v not in _ALLOWED_DISPLAY_STYLES:
            raise ValueError(f"Ungueltiger Stil, erlaubt: {sorted(_ALLOWED_DISPLAY_STYLES)}")
        return v

    @field_validator("display_name_color", "display_name_gradient_color")
    @classmethod
    def validate_color(cls, v: str) -> str:
        if not _HEX_COLOR_RE.match(v):
            raise ValueError("Farbe muss ein Hex-Code sein, z.B. #35E0C0")
        return v


@router.get("/me/display-style", response_model=DisplayStyleOut)
async def get_display_style(user: User = Depends(get_current_user)) -> DisplayStyleOut:
    return DisplayStyleOut(
        display_name_style=user.display_name_style,
        display_name_color=user.display_name_color,
        display_name_gradient_color=user.display_name_gradient_color,
    )


@router.patch("/me/display-style", response_model=DisplayStyleOut)
async def update_display_style(
    payload: UpdateDisplayStyleRequest, db: Session = Depends(get_db), user: User = Depends(get_current_user)
) -> DisplayStyleOut:
    if not user.is_premium:
        raise HTTPException(
            status_code=403,
            detail="Anzeigename-Customizing ist ein Premium-Feature. Ein Administrator kann dir Premium freischalten.",
        )

    user.display_name_style = payload.display_name_style
    user.display_name_color = payload.display_name_color
    user.display_name_gradient_color = payload.display_name_gradient_color
    db.add(user)
    db.commit()
    db.refresh(user)

    return DisplayStyleOut(
        display_name_style=user.display_name_style,
        display_name_color=user.display_name_color,
        display_name_gradient_color=user.display_name_gradient_color,
    )
