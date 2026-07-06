import re
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_admin
from app.core.audit import get_client_ip, log_audit_event
from app.core.db import get_db
from app.core.security import hash_password
from app.models.user import InviteCode, User, UserRole

router = APIRouter()

_HEX_COLOR_RE = re.compile(r"^#[0-9a-fA-F]{6}$")


class UserOut(BaseModel):
    id: int
    username: str
    role: str
    is_active: bool
    has_2fa: bool
    invite_quota: int
    is_premium: bool
    premium_badge_color: str

    model_config = {"from_attributes": True}


class CreateUserRequest(BaseModel):
    username: str
    role: str = UserRole.MEMBER.value
    # Optional: wenn leer, wird ein zufaelliges Einmal-Passwort generiert
    # und in der Antwort zurueckgegeben (muss dem Nutzer sicher mitgeteilt werden).
    password: str | None = None

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        v = v.strip()
        if not v or len(v) > 64:
            raise ValueError("Ungueltiger Benutzername")
        return v

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str) -> str:
        if v not in {r.value for r in UserRole}:
            raise ValueError("Ungueltige Rolle")
        return v

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str | None) -> str | None:
        if v is not None and len(v) < 12:
            raise ValueError("Passwort muss mindestens 12 Zeichen haben")
        return v


class CreateUserResponse(BaseModel):
    user: UserOut
    generated_password: str | None = None


class UpdateUserRequest(BaseModel):
    role: str | None = None
    is_active: bool | None = None
    invite_quota: int | None = None
    is_premium: bool | None = None
    premium_badge_color: str | None = None

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str | None) -> str | None:
        if v is not None and v not in {r.value for r in UserRole}:
            raise ValueError("Ungueltige Rolle")
        return v

    @field_validator("invite_quota")
    @classmethod
    def validate_invite_quota(cls, v: int | None) -> int | None:
        if v is not None and not (0 <= v <= 1000):
            raise ValueError("Invite-Kontingent muss zwischen 0 und 1000 liegen")
        return v

    @field_validator("premium_badge_color")
    @classmethod
    def validate_color(cls, v: str | None) -> str | None:
        if v is not None and not _HEX_COLOR_RE.match(v):
            raise ValueError("Farbe muss ein Hex-Code sein, z.B. #F5C518")
        return v


@router.get("/users", response_model=list[UserOut])
async def list_users(db: Session = Depends(get_db), _admin: User = Depends(require_admin)) -> list[User]:
    return db.query(User).order_by(User.id).all()


@router.post("/users", response_model=CreateUserResponse)
async def create_user(
    payload: CreateUserRequest, request: Request, db: Session = Depends(get_db), admin: User = Depends(require_admin)
) -> CreateUserResponse:
    if db.query(User).filter(User.username == payload.username).first() is not None:
        raise HTTPException(status_code=409, detail="Benutzername bereits vergeben")

    generated_password = None
    if payload.password:
        raw_password = payload.password
    else:
        raw_password = secrets.token_urlsafe(12)
        generated_password = raw_password

    user = User(
        username=payload.username,
        password_hash=hash_password(raw_password),
        role=payload.role,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    log_audit_event(
        db, "admin_create_user", success=True, username=admin.username, ip_address=get_client_ip(request),
        detail=f"Neuer Benutzer '{user.username}' (Rolle: {user.role}) von Admin '{admin.username}' angelegt",
    )
    return CreateUserResponse(user=UserOut.model_validate(user), generated_password=generated_password)


@router.patch("/users/{user_id}", response_model=UserOut)
async def update_user(
    user_id: int,
    payload: UpdateUserRequest,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="Benutzer nicht gefunden")

    if user.id == admin.id and (payload.is_active is False or payload.role == UserRole.MEMBER.value):
        raise HTTPException(status_code=400, detail="Du kannst dich nicht selbst deaktivieren/degradieren")

    changes: list[str] = []
    if payload.role is not None:
        changes.append(f"role={payload.role}")
        user.role = payload.role
    if payload.is_active is not None:
        changes.append(f"is_active={payload.is_active}")
        user.is_active = payload.is_active
    if payload.invite_quota is not None:
        changes.append(f"invite_quota={payload.invite_quota}")
        user.invite_quota = payload.invite_quota
    if payload.is_premium is not None:
        changes.append(f"is_premium={payload.is_premium}")
        user.is_premium = payload.is_premium
    if payload.premium_badge_color is not None:
        changes.append(f"premium_badge_color={payload.premium_badge_color}")
        user.premium_badge_color = payload.premium_badge_color

    db.add(user)
    db.commit()
    db.refresh(user)

    if changes:
        log_audit_event(
            db, "admin_update_user", success=True, username=admin.username, ip_address=get_client_ip(request),
            detail=f"Benutzer '{user.username}' geaendert von '{admin.username}': {', '.join(changes)}",
        )
    return user


@router.delete("/users/{user_id}")
async def delete_user(
    user_id: int, request: Request, db: Session = Depends(get_db), admin: User = Depends(require_admin)
) -> dict:
    if user_id == admin.id:
        raise HTTPException(status_code=400, detail="Du kannst deinen eigenen Account nicht loeschen")

    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="Benutzer nicht gefunden")

    deleted_username = user.username
    db.delete(user)
    db.commit()
    log_audit_event(
        db, "admin_delete_user", success=True, username=admin.username, ip_address=get_client_ip(request),
        detail=f"Benutzer '{deleted_username}' geloescht von '{admin.username}'",
    )
    return {"success": True}


@router.post("/users/{user_id}/reset-2fa", response_model=UserOut)
async def reset_user_2fa(
    user_id: int, db: Session = Depends(get_db), _admin: User = Depends(require_admin)
) -> User:
    """Setzt 2FA fuer einen Benutzer zurueck -- beim naechsten Login muss die
    Person erneut TOTP oder Passkey einrichten. Sinnvoll z.B. bei
    Geraeteverlust.
    """
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="Benutzer nicht gefunden")

    user.totp_enabled = False
    user.totp_secret = None
    user.webauthn_credentials.clear()

    db.add(user)
    db.commit()
    db.refresh(user)
    return user


# --- Invite-Codes --------------------------------------------------------

class CreateInviteRequest(BaseModel):
    note: str | None = None
    role: str = UserRole.MEMBER.value
    expires_in_days: int | None = 7

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str) -> str:
        if v not in {r.value for r in UserRole}:
            raise ValueError("Ungueltige Rolle")
        return v

    @field_validator("expires_in_days")
    @classmethod
    def validate_expiry(cls, v: int | None) -> int | None:
        if v is not None and not (1 <= v <= 365):
            raise ValueError("expires_in_days muss zwischen 1 und 365 liegen (oder leer fuer unbegrenzt)")
        return v


class InviteOut(BaseModel):
    id: int
    code: str
    note: str | None
    role: str
    created_at: str
    expires_at: str | None
    used_by_username: str | None
    used_at: str | None

    @staticmethod
    def from_model(invite: InviteCode, db: Session) -> "InviteOut":
        used_by_username = None
        if invite.used_by_id:
            used_by = db.get(User, invite.used_by_id)
            used_by_username = used_by.username if used_by else None
        return InviteOut(
            id=invite.id, code=invite.code, note=invite.note, role=invite.role,
            created_at=invite.created_at.isoformat(),
            expires_at=invite.expires_at.isoformat() if invite.expires_at else None,
            used_by_username=used_by_username,
            used_at=invite.used_at.isoformat() if invite.used_at else None,
        )


@router.get("/invites", response_model=list[InviteOut])
async def list_invites(db: Session = Depends(get_db), _admin: User = Depends(require_admin)) -> list[InviteOut]:
    """Admin-Ansicht: ALLE Invites im System."""
    invites = db.query(InviteCode).order_by(InviteCode.created_at.desc()).all()
    return [InviteOut.from_model(i, db) for i in invites]


@router.get("/invites/mine", response_model=list[InviteOut])
async def list_my_invites(db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> list[InviteOut]:
    """Self-Service-Ansicht: nur die eigenen erstellten Invites -- damit
    sieht ein Member mit Invite-Kontingent, wer sich mit seinem Code
    registriert hat ('seine Invitees')."""
    invites = (
        db.query(InviteCode)
        .filter(InviteCode.created_by_id == user.id)
        .order_by(InviteCode.created_at.desc())
        .all()
    )
    return [InviteOut.from_model(i, db) for i in invites]


@router.post("/invites", response_model=InviteOut)
async def create_invite(
    payload: CreateInviteRequest, request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)
) -> InviteOut:
    is_admin = user.role == UserRole.ADMIN.value
    if not is_admin and user.invite_quota <= 0:
        raise HTTPException(
            status_code=403,
            detail="Du hast kein Invite-Kontingent mehr uebrig. Ein Administrator kann dir weitere Invites zuteilen.",
        )

    # Members duerfen NIEMALS admin-Invites erzeugen, unabhaengig davon,
    # was im Request steht -- nur echte Admins koennen Admin-Zugang vergeben.
    role = payload.role if is_admin else UserRole.MEMBER.value

    expires_at = None
    if payload.expires_in_days is not None:
        expires_at = datetime.now(timezone.utc) + timedelta(days=payload.expires_in_days)

    invite = InviteCode(
        code=secrets.token_urlsafe(9),  # kurz genug zum Abtippen/Diktieren, lang genug gegen Erraten
        created_by_id=user.id,
        note=payload.note,
        role=role,
        expires_at=expires_at,
    )
    db.add(invite)

    # Kontingent erst NACH erfolgreichem Anlegen herunterzaehlen (Admins
    # sind davon unabhaengig unbegrenzt).
    if not is_admin:
        user.invite_quota -= 1
        db.add(user)

    db.commit()
    db.refresh(invite)

    log_audit_event(
        db, "invite_created", success=True, username=user.username, ip_address=get_client_ip(request),
        detail=f"Invite erstellt von '{user.username}' (Rolle: {role}, verbleibendes Kontingent: "
        f"{'unbegrenzt' if is_admin else user.invite_quota})",
    )
    return InviteOut.from_model(invite, db)


@router.delete("/invites/{invite_id}")
async def revoke_invite(
    invite_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)
) -> dict:
    invite = db.get(InviteCode, invite_id)
    if invite is None:
        raise HTTPException(status_code=404, detail="Einladungscode nicht gefunden")

    is_admin = user.role == UserRole.ADMIN.value
    if not is_admin and invite.created_by_id != user.id:
        raise HTTPException(status_code=403, detail="Du kannst nur deine eigenen Einladungscodes widerrufen")
    if invite.used_at is not None:
        raise HTTPException(status_code=400, detail="Bereits verwendete Codes koennen nicht widerrufen werden (nur geloescht)")

    # Kontingent zurueckgeben, wenn ein Member seinen eigenen, nie
    # verwendeten Invite widerruft -- er soll dafuer nicht "bestraft" werden.
    if not is_admin and invite.created_by_id == user.id:
        user.invite_quota += 1
        db.add(user)

    db.delete(invite)
    db.commit()
    log_audit_event(
        db, "invite_revoked", success=True, username=user.username, ip_address=get_client_ip(request),
    )
    return {"success": True}
