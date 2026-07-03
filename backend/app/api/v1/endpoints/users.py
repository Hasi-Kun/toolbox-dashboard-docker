import secrets

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from app.api.deps import require_admin
from app.core.db import get_db
from app.core.security import hash_password
from app.models.user import User, UserRole

router = APIRouter()


class UserOut(BaseModel):
    id: int
    username: str
    role: str
    is_active: bool
    has_2fa: bool

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

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str | None) -> str | None:
        if v is not None and v not in {r.value for r in UserRole}:
            raise ValueError("Ungueltige Rolle")
        return v


@router.get("/users", response_model=list[UserOut])
async def list_users(db: Session = Depends(get_db), _admin: User = Depends(require_admin)) -> list[User]:
    return db.query(User).order_by(User.id).all()


@router.post("/users", response_model=CreateUserResponse)
async def create_user(
    payload: CreateUserRequest, db: Session = Depends(get_db), _admin: User = Depends(require_admin)
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

    return CreateUserResponse(user=UserOut.model_validate(user), generated_password=generated_password)


@router.patch("/users/{user_id}", response_model=UserOut)
async def update_user(
    user_id: int,
    payload: UpdateUserRequest,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="Benutzer nicht gefunden")

    if user.id == admin.id and (payload.is_active is False or payload.role == UserRole.MEMBER.value):
        raise HTTPException(status_code=400, detail="Du kannst dich nicht selbst deaktivieren/degradieren")

    if payload.role is not None:
        user.role = payload.role
    if payload.is_active is not None:
        user.is_active = payload.is_active

    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.delete("/users/{user_id}")
async def delete_user(
    user_id: int, db: Session = Depends(get_db), admin: User = Depends(require_admin)
) -> dict:
    if user_id == admin.id:
        raise HTTPException(status_code=400, detail="Du kannst deinen eigenen Account nicht loeschen")

    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="Benutzer nicht gefunden")

    db.delete(user)
    db.commit()
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
