"""Email-Aliase (Verwaltungsebene) -- anonyme Anmeldungen/Spam-Schutz
per weiterleitender Wegwerfadresse, aehnlich AnonAddy/SimpleLogin.

WICHTIG: das ist ausschliesslich die VERWALTUNG (welche Aliase
existieren, wohin sie weiterleiten sollen, an/aus) -- siehe
EmailAlias-Modell-Docstring in app/models/user.py fuer den
Infrastruktur-Hinweis: tatsaechliches Empfangen/Weiterleiten von Mail
braucht einen separaten SMTP-Empfangsdienst + eine echte Domain mit
passendem MX-Record, beides NICHT Teil dieses Moduls.
"""

import re
import secrets

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr, field_validator
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.config import get_settings
from app.core.db import get_db
from app.models.user import EmailAlias, User

router = APIRouter(prefix="/email-aliases", tags=["email-aliases"])
settings = get_settings()

_LOCAL_PART_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}[a-z0-9]$|^[a-z0-9]$")


def _random_local_part() -> str:
    # Kurz, aber praktisch kollisionsfrei genug fuer diesen Anwendungsfall
    # (Eindeutigkeit wird zusaetzlich per DB-Constraint erzwungen).
    return "a" + secrets.token_hex(5)


class AliasOut(BaseModel):
    id: int
    address: str
    target_email: str
    label: str | None
    enabled: bool
    forward_count: int

    @staticmethod
    def from_model(a: EmailAlias) -> "AliasOut":
        return AliasOut(
            id=a.id, address=f"{a.local_part}@{a.domain}", target_email=a.target_email,
            label=a.label, enabled=a.enabled, forward_count=a.forward_count,
        )


class CreateAliasRequest(BaseModel):
    domain: str
    target_email: EmailStr
    local_part: str | None = None  # None = zufaellig generieren
    label: str | None = None

    @field_validator("local_part")
    @classmethod
    def validate_local_part(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip().lower()
        if not v:
            return None
        if not _LOCAL_PART_RE.match(v):
            raise ValueError("Nur Kleinbuchstaben, Ziffern, Punkt/Bindestrich/Unterstrich erlaubt (nicht am Anfang/Ende)")
        return v

    @field_validator("label")
    @classmethod
    def validate_label(cls, v: str | None) -> str | None:
        if v is not None and len(v) > 100:
            raise ValueError("Bezeichnung zu lang")
        return v


class UpdateAliasRequest(BaseModel):
    enabled: bool | None = None
    target_email: EmailStr | None = None
    label: str | None = None


@router.get("/domains")
async def list_allowed_domains(_user: User = Depends(get_current_user)) -> dict:
    return {"domains": settings.email_alias_domains_list}


@router.get("", response_model=list[AliasOut])
async def list_my_aliases(db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> list[AliasOut]:
    aliases = db.query(EmailAlias).filter(EmailAlias.user_id == user.id).order_by(EmailAlias.created_at.desc()).all()
    return [AliasOut.from_model(a) for a in aliases]


@router.post("", response_model=AliasOut)
async def create_alias(
    payload: CreateAliasRequest, db: Session = Depends(get_db), user: User = Depends(get_current_user)
) -> AliasOut:
    if payload.domain not in settings.email_alias_domains_list:
        raise HTTPException(
            status_code=400,
            detail="Diese Domain ist nicht als Alias-Domain konfiguriert (siehe EMAIL_ALIAS_DOMAINS in der Server-Konfiguration).",
        )

    local_part = payload.local_part or _random_local_part()

    existing = db.query(EmailAlias).filter(EmailAlias.local_part == local_part, EmailAlias.domain == payload.domain).first()
    if existing is not None:
        raise HTTPException(status_code=400, detail="Dieser Alias ist bereits vergeben.")

    alias = EmailAlias(
        user_id=user.id, local_part=local_part, domain=payload.domain,
        target_email=payload.target_email, label=payload.label,
    )
    db.add(alias)
    db.commit()
    db.refresh(alias)
    return AliasOut.from_model(alias)


@router.patch("/{alias_id}", response_model=AliasOut)
async def update_alias(
    alias_id: int, payload: UpdateAliasRequest, db: Session = Depends(get_db), user: User = Depends(get_current_user)
) -> AliasOut:
    alias = db.query(EmailAlias).filter(EmailAlias.id == alias_id, EmailAlias.user_id == user.id).first()
    if alias is None:
        raise HTTPException(status_code=404, detail="Alias nicht gefunden")

    if payload.enabled is not None:
        alias.enabled = payload.enabled
    if payload.target_email is not None:
        alias.target_email = payload.target_email
    if "label" in payload.model_fields_set:
        alias.label = payload.label

    db.add(alias)
    db.commit()
    db.refresh(alias)
    return AliasOut.from_model(alias)


@router.delete("/{alias_id}")
async def delete_alias(alias_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> dict:
    alias = db.query(EmailAlias).filter(EmailAlias.id == alias_id, EmailAlias.user_id == user.id).first()
    if alias is None:
        raise HTTPException(status_code=404, detail="Alias nicht gefunden")
    db.delete(alias)
    db.commit()
    return {"success": True}
