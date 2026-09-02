"""CRUD fuer gespeicherte SSH-Verbindungen (WebSSH-Webshell).

Strikte Nutzer-Isolation: JEDE Query filtert auf user_id == aktueller
Nutzer -- "diese sind nur als der jeweilige Nutzer aufrufbar", wie in
der Feature-Anfrage gefordert. Ein Nutzer kann also nicht einmal per
erratener ID auf die gespeicherte Verbindung eines anderen Nutzers
zugreifen (404 statt 403, um nicht einmal die Existenz zu verraten).
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from app.api.deps import require_admin
from app.core.db import get_db
from app.core.ssh_vault import encrypt_secret
from app.models.user import SavedSshConnection, User

router = APIRouter(prefix="/ssh-connections", tags=["ssh-connections"])

ALLOWED_AUTH_METHODS = {"none", "password", "key"}


class SavedConnectionOut(BaseModel):
    id: int
    label: str
    host: str
    port: int
    username: str
    auth_method: str
    has_stored_secret: bool

    @staticmethod
    def from_model(conn: SavedSshConnection) -> "SavedConnectionOut":
        return SavedConnectionOut(
            id=conn.id, label=conn.label, host=conn.host, port=conn.port,
            username=conn.username, auth_method=conn.auth_method,
            has_stored_secret=bool(conn.encrypted_secret),
        )


class CreateConnectionRequest(BaseModel):
    label: str
    host: str
    port: int = 22
    username: str
    auth_method: str = "none"
    # Optional: Passwort oder privater Schluessel, der verschluesselt
    # gespeichert werden soll. Leer lassen = kein Geheimnis speichern,
    # beim Verbinden jedes Mal neu eingeben (sicherer, aber weniger
    # bequem -- die Wahl liegt beim Nutzer).
    secret: str | None = None

    @field_validator("label")
    @classmethod
    def validate_label(cls, v: str) -> str:
        v = v.strip()
        if not v or len(v) > 100:
            raise ValueError("Bezeichnung muss 1-100 Zeichen lang sein")
        return v

    @field_validator("host")
    @classmethod
    def validate_host(cls, v: str) -> str:
        v = v.strip()
        if not v or len(v) > 255:
            raise ValueError("Ungueltiger Host")
        return v

    @field_validator("port")
    @classmethod
    def validate_port(cls, v: int) -> int:
        if not (1 <= v <= 65535):
            raise ValueError("Ungueltiger Port")
        return v

    @field_validator("auth_method")
    @classmethod
    def validate_auth_method(cls, v: str) -> str:
        if v not in ALLOWED_AUTH_METHODS:
            raise ValueError(f"auth_method muss einer von {sorted(ALLOWED_AUTH_METHODS)} sein")
        return v


@router.get("", response_model=list[SavedConnectionOut])
async def list_connections(db: Session = Depends(get_db), user: User = Depends(require_admin)) -> list[SavedConnectionOut]:
    connections = db.query(SavedSshConnection).filter(SavedSshConnection.user_id == user.id).order_by(SavedSshConnection.label).all()
    return [SavedConnectionOut.from_model(c) for c in connections]


@router.post("", response_model=SavedConnectionOut)
async def create_connection(
    payload: CreateConnectionRequest, db: Session = Depends(get_db), user: User = Depends(require_admin)
) -> SavedConnectionOut:
    existing = db.query(SavedSshConnection).filter(SavedSshConnection.user_id == user.id, SavedSshConnection.label == payload.label).first()
    if existing is not None:
        raise HTTPException(status_code=400, detail="Eine Verbindung mit dieser Bezeichnung existiert bereits.")

    encrypted_secret = encrypt_secret(payload.secret) if payload.secret else None
    conn = SavedSshConnection(
        user_id=user.id, label=payload.label, host=payload.host, port=payload.port,
        username=payload.username, auth_method=payload.auth_method, encrypted_secret=encrypted_secret,
    )
    db.add(conn)
    db.commit()
    db.refresh(conn)
    return SavedConnectionOut.from_model(conn)


@router.delete("/{connection_id}")
async def delete_connection(connection_id: int, db: Session = Depends(get_db), user: User = Depends(require_admin)) -> dict:
    conn = db.query(SavedSshConnection).filter(SavedSshConnection.id == connection_id, SavedSshConnection.user_id == user.id).first()
    if conn is None:
        raise HTTPException(status_code=404, detail="Verbindung nicht gefunden")
    db.delete(conn)
    db.commit()
    return {"success": True}
