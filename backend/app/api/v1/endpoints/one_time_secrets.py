"""OneTimePassword: verschluesselter Geheimnis-Link ("Burn after
reading") -- Passwoerter/Notizen sicher teilen, ohne sie per Chat/
E-Mail im Klartext zu verschicken. Standardmaessig genau EIN Abruf
erlaubt, der Ersteller kann das nachtraeglich erhoehen und die
Gueltigkeit verlaengern.

Erstellen erfordert Login (verhindert Missbrauch als anonymer
Geheimnis-Speicher). Ansehen ist bewusst OHNE Login moeglich -- der
Empfaenger hat typischerweise KEIN eigenes Toolbox-Konto. Der Token in
der URL ist die einzige "Berechtigung".
"""

import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.db import get_db
from app.core.ssh_vault import SshVaultError, decrypt_secret, encrypt_secret
from app.models.user import OneTimeSecret, User

router = APIRouter(prefix="/one-time-secrets", tags=["one-time-secrets"])

MAX_CONTENT_CHARS = 10_000
MAX_TTL_DAYS = 14
# Feste, vorgegebene Ablaufzeiten statt freier Zahleneingabe -- einfacher
# in der UI und verhindert Off-by-one-Verwirrung bei der Maximalgrenze.
ALLOWED_TTL_HOURS = {1, 24, 24 * 3, 24 * 7, 24 * MAX_TTL_DAYS}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime) -> datetime:
    """SQLite gibt DateTime(timezone=True)-Werte als naive datetimes
    zurueck -- wir schreiben ausschliesslich UTC, also hier explizit als
    UTC interpretieren statt versehentlich lokale Zeit anzunehmen (siehe
    dasselbe etablierte Muster in app/api/v1/endpoints/auth.py)."""
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


class CreateSecretRequest(BaseModel):
    content: str
    ttl_hours: int = 24

    @field_validator("content")
    @classmethod
    def validate_content(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Inhalt darf nicht leer sein")
        if len(v) > MAX_CONTENT_CHARS:
            raise ValueError(f"Inhalt zu lang (max. {MAX_CONTENT_CHARS} Zeichen)")
        return v

    @field_validator("ttl_hours")
    @classmethod
    def validate_ttl(cls, v: int) -> int:
        if v not in ALLOWED_TTL_HOURS:
            raise ValueError(f"ttl_hours muss einer von {sorted(ALLOWED_TTL_HOURS)} sein")
        return v


class CreateSecretResponse(BaseModel):
    token: str
    expires_at: datetime


class SecretMetadataOut(BaseModel):
    token: str
    created_at: datetime
    expires_at: datetime
    viewed_at: datetime | None
    is_expired: bool
    max_views: int
    view_count: int


class UpdateSecretRequest(BaseModel):
    # Beides optional -- nur mitschicken, was tatsaechlich geaendert
    # werden soll. Ansehen-Erhoehung und Verlaengerung sind unabhaengig
    # voneinander nutzbar.
    add_views: int | None = None
    extend_ttl_hours: int | None = None

    @field_validator("add_views")
    @classmethod
    def validate_add_views(cls, v: int | None) -> int | None:
        if v is not None and not (1 <= v <= 100):
            raise ValueError("add_views muss zwischen 1 und 100 liegen")
        return v

    @field_validator("extend_ttl_hours")
    @classmethod
    def validate_extend_ttl(cls, v: int | None) -> int | None:
        if v is not None and v not in ALLOWED_TTL_HOURS:
            raise ValueError(f"extend_ttl_hours muss einer von {sorted(ALLOWED_TTL_HOURS)} sein")
        return v


class ViewSecretResponse(BaseModel):
    content: str


@router.post("", response_model=CreateSecretResponse)
async def create_secret(
    payload: CreateSecretRequest, db: Session = Depends(get_db), user: User = Depends(get_current_user)
) -> CreateSecretResponse:
    token = secrets.token_urlsafe(32)
    expires_at = _utcnow() + timedelta(hours=payload.ttl_hours)

    entry = OneTimeSecret(
        token=token, creator_user_id=user.id,
        encrypted_content=encrypt_secret(payload.content), expires_at=expires_at,
    )
    db.add(entry)
    db.commit()
    return CreateSecretResponse(token=token, expires_at=expires_at)


@router.get("/mine", response_model=list[SecretMetadataOut])
async def list_my_secrets(db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> list[SecretMetadataOut]:
    """Nur Metadaten (wurde es schon abgerufen? wann laeuft es ab?) --
    NIE der Inhalt, auch nicht fuer den Ersteller selbst. Der Ersteller
    bekommt keinen Sonderzugriff auf den Inhalt nach dem Teilen -- exakt
    dasselbe Einmal-Prinzip gilt fuer alle, die den Link haben."""
    now = _utcnow()
    entries = (
        db.query(OneTimeSecret)
        .filter(OneTimeSecret.creator_user_id == user.id)
        .order_by(OneTimeSecret.created_at.desc())
        .limit(50)
        .all()
    )
    return [
        SecretMetadataOut(
            token=e.token, created_at=e.created_at, expires_at=e.expires_at,
            viewed_at=e.viewed_at, is_expired=_as_utc(e.expires_at) < now,
            max_views=e.max_views, view_count=e.view_count,
        )
        for e in entries
    ]


@router.patch("/mine/{token}", response_model=SecretMetadataOut)
async def update_my_secret(
    token: str, payload: UpdateSecretRequest, db: Session = Depends(get_db), user: User = Depends(get_current_user)
) -> SecretMetadataOut:
    """Erlaubt dem Ersteller nachtraeglich, die Anzahl erlaubter Abrufe
    zu erhoehen und/oder die Gueltigkeit zu verlaengern -- z.B. wenn
    mehrere Personen denselben Link abrufen sollen, oder der Empfaenger
    mehr Zeit braucht. Beides bewusst nur ERHOEHEND/VERLAENGERND nutzbar
    (kein Verkuerzen ueber diesen Endpunkt) -- fuer ein fruehzeitiges
    Beenden gibt es den expliziten Widerruf-Endpunkt."""
    entry = db.query(OneTimeSecret).filter(OneTimeSecret.token == token, OneTimeSecret.creator_user_id == user.id).first()
    if entry is None:
        raise HTTPException(status_code=404, detail="Nicht gefunden")

    if _as_utc(entry.expires_at) < _utcnow() or entry.view_count >= entry.max_views:
        raise HTTPException(status_code=400, detail="Dieser Link ist bereits abgelaufen bzw. aufgebraucht und kann nicht mehr geaendert werden.")

    if payload.add_views is not None:
        entry.max_views += payload.add_views
    if payload.extend_ttl_hours is not None:
        entry.expires_at = _utcnow() + timedelta(hours=payload.extend_ttl_hours)

    db.add(entry)
    db.commit()
    db.refresh(entry)

    now = _utcnow()
    return SecretMetadataOut(
        token=entry.token, created_at=entry.created_at, expires_at=entry.expires_at,
        viewed_at=entry.viewed_at, is_expired=_as_utc(entry.expires_at) < now,
        max_views=entry.max_views, view_count=entry.view_count,
    )


@router.delete("/mine/{token}")
async def revoke_my_secret(token: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> dict:
    """Fruehzeitiges Widerrufen (z.B. falscher Empfaenger) -- nur der
    Ersteller darf das. Funktioniert auch, wenn schon TEILWEISE abgerufen
    wurde (view_count > 0 aber < max_views) -- der Ersteller kann jederzeit
    sofort beenden, unabhaengig vom aktuellen Abruf-Stand."""
    entry = db.query(OneTimeSecret).filter(OneTimeSecret.token == token, OneTimeSecret.creator_user_id == user.id).first()
    if entry is None:
        raise HTTPException(status_code=404, detail="Nicht gefunden")
    db.delete(entry)
    db.commit()
    return {"success": True}


@router.get("/{token}", response_model=ViewSecretResponse)
async def view_secret(token: str, db: Session = Depends(get_db)) -> ViewSecretResponse:
    """Oeffentlich (kein Login) -- liest das Geheimnis und erhoeht den
    Abruf-Zaehler atomar innerhalb derselben DB-Transaktion. Standard-
    maessig ist nach EINEM Abruf Schluss (max_views=1) -- der Ersteller
    kann das aber vorher ueber PATCH /mine/{token} erhoehen. Sobald
    view_count das Limit erreicht, wird der Eintrag geloescht -- ein
    weiterer Abruf findet dann buchstaeblich nichts mehr vor (404).
    """
    entry = db.query(OneTimeSecret).filter(OneTimeSecret.token == token).first()
    if entry is None:
        raise HTTPException(status_code=404, detail="Dieser Link ist ungueltig, bereits aufgebraucht oder abgelaufen.")

    if _as_utc(entry.expires_at) < _utcnow():
        db.delete(entry)
        db.commit()
        raise HTTPException(status_code=404, detail="Dieser Link ist ungueltig, bereits aufgebraucht oder abgelaufen.")

    try:
        content = decrypt_secret(entry.encrypted_content)
    except SshVaultError as exc:
        db.delete(entry)
        db.commit()
        raise HTTPException(status_code=500, detail="Entschluesselung fehlgeschlagen.") from exc

    # Zaehler erhoehen, und ERST wenn das Limit erreicht ist loeschen --
    # das ist der eigentliche Kern der Abruf-Begrenzung. Beides in
    # derselben Anfrage-Transaktion: bei zwei zeitgleichen Anfragen auf
    # denselben Token (z.B. genau beim letzten erlaubten Abruf)
    # serialisiert SQLite (bzw. jede relationale DB) die beiden
    # Schreibzugriffe -- die zweite Anfrage sieht dann bereits den
    # erhoehten Zaehler bzw. die geloeschte Zeile (fuer eine wirklich
    # wasserdichte Race-Condition-Absicherung bei hoher Parallelitaet
    # waere ein SELECT ... FOR UPDATE noetig, hier fuer SQLite mit
    # geringer Parallelitaet ausreichend).
    entry.view_count += 1
    if entry.view_count >= entry.max_views:
        db.delete(entry)
    else:
        entry.viewed_at = _utcnow()
        db.add(entry)
    db.commit()

    return ViewSecretResponse(content=content)


async def cleanup_expired_secrets(db: Session) -> int:
    """Loescht abgelaufene, NIE abgerufene Geheimnisse -- diese wuerden
    sonst unbegrenzt in der DB liegen bleiben, wenn niemand je versucht,
    sie abzurufen (der Lazy-Cleanup in view_secret() greift nur bei
    einem tatsaechlichen Abrufversuch). Wird periodisch beim
    Anwendungsstart als Hintergrund-Task ausgefuehrt, siehe app/main.py.
    """
    now = _utcnow()
    deleted = db.query(OneTimeSecret).filter(OneTimeSecret.expires_at < now).delete(synchronize_session=False)
    db.commit()
    return deleted
