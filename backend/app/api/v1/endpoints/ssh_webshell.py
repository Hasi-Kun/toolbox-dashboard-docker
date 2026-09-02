"""WebSSH-Webshell: interaktives SSH-Terminal im Browser ueber WebSocket.

WICHTIG (Architektur): diese Route laeuft NICHT ueber die normale
Next.js-BFF-Proxy-Schicht (die ist fuer zustandslose JSON-Requests
gebaut, kein WebSocket-Upgrade) -- Caddy leitet WebSocket-Verbindungen
zu diesem Pfad DIREKT an dieses Backend weiter (siehe docs/CADDY.md,
Abschnitt WebSSH). Auth funktioniert trotzdem gleich: der Browser
schickt das Session-Cookie automatisch mit (WebSocket-Handshake ist ein
normaler HTTP-Request mit Upgrade-Header), hier wird es genauso wie bei
jedem anderen Endpunkt gegen Redis geprueft.

Sicherheitsmodell:
- Nur fuer Admins (require_admin-aequivalente Pruefung, da WebSocket-
  Routen keine normalen FastAPI-Dependencies mit HTTPException nutzen
  koennen -- Verbindung wird stattdessen mit Klartext-Fehlermeldung +
  Schliessen sauber abgelehnt).
- Ziel-Host/Port/User/Credentials kommen IMMER vom Client (das Backend
  verbindet sich nirgendwo automatisch hin) -- der Nutzer verbindet sich
  mit eigenen Zielen und eigenen Zugangsdaten, analog zu einem normalen
  SSH-Client.
- Jede Verbindung (Ziel, Nutzer, Erfolg/Fehlschlag) wird im Audit-Log
  festgehalten.
- Begrenzung auf max_ssh_sessions_per_user GLEICHZEITIG offene
  Verbindungen (echte Serverressourcen, anders als die rein UI-seitige
  WebCLI-Fensterbegrenzung) -- ueber einen Redis-Zaehler durchgesetzt.
"""

import asyncio
import json
import logging

import asyncssh
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session

from app.core.audit import log_audit_event
from app.core.config import get_settings
import app.core.db as db_module
from app.core.sessions import get_session_user_id
from app.core.ssh_vault import SshVaultError, decrypt_secret
from app.models.user import SavedSshConnection, User

logger = logging.getLogger("toolbox.ssh_webshell")
settings = get_settings()
router = APIRouter()

_SESSION_COUNT_PREFIX = "ssh-webshell-sessions:"
_SESSION_COUNT_TTL_SECONDS = 60 * 60 * 4  # Sicherheitsnetz, falls ein Decrement je verloren geht


async def _authenticate(websocket: WebSocket) -> User | None:
    session_id = websocket.cookies.get(settings.session_cookie_name)
    if not session_id:
        return None
    user_id = await get_session_user_id(session_id)
    if user_id is None:
        return None

    db = db_module.SessionLocal()
    try:
        user = db.get(User, user_id)
        if user is None or not user.is_active or user.role != "admin":
            return None
        # Losgeloest von der DB-Session zurueckgeben (Attribute vorher lesen,
        # damit sie nach db.close() noch zugreifbar sind).
        _ = (user.id, user.username, user.role)
        return user
    finally:
        db.close()


async def _get_saved_connection_secret(user_id: int, connection_id: int) -> tuple[SavedSshConnection, str | None] | None:
    """Laedt eine gespeicherte Verbindung UND entschluesselt ihr Geheimnis
    -- mit striktem user_id-Filter (nie ueber die ID allein zugreifbar,
    siehe SavedSshConnection-Docstring: nur der jeweilige Nutzer darf
    seine eigenen gespeicherten Verbindungen nutzen)."""
    db = db_module.SessionLocal()
    try:
        conn = (
            db.query(SavedSshConnection)
            .filter(SavedSshConnection.id == connection_id, SavedSshConnection.user_id == user_id)
            .first()
        )
        if conn is None:
            return None
        secret = decrypt_secret(conn.encrypted_secret) if conn.encrypted_secret else None
        return conn, secret
    finally:
        db.close()


@router.websocket("/ws/ssh")
async def ssh_webshell(websocket: WebSocket) -> None:
    user = await _authenticate(websocket)
    if user is None:
        # 4401/4403 sind selbst gewaehlte App-Codes im per RFC6455 fuer
        # private Nutzung reservierten Bereich (4000-4999) -- WebSocket
        # kennt kein natives 401/403 wie HTTP.
        await websocket.close(code=4401, reason="Nicht angemeldet oder keine Admin-Berechtigung")
        return

    await websocket.accept()

    session_count_key = f"{_SESSION_COUNT_PREFIX}{user.id}"
    from app.core.sessions import _redis  # lokal importiert, um Zirkel-Imports zu vermeiden

    current_count = await _redis.get(session_count_key)
    if current_count is not None and int(current_count) >= settings.max_ssh_sessions_per_user:
        await websocket.send_json({
            "type": "error",
            "message": f"Maximal {settings.max_ssh_sessions_per_user} gleichzeitige SSH-Verbindungen pro Nutzer erreicht.",
        })
        await websocket.close(code=4429, reason="Zu viele gleichzeitige SSH-Verbindungen")
        return

    await _redis.incr(session_count_key)
    await _redis.expire(session_count_key, _SESSION_COUNT_TTL_SECONDS)

    db_for_audit = db_module.SessionLocal()
    connection_label = "?"
    try:
        try:
            connect_msg = await asyncio.wait_for(websocket.receive_json(), timeout=15)
        except (asyncio.TimeoutError, json.JSONDecodeError, WebSocketDisconnect):
            await websocket.close(code=4400, reason="Keine gueltige Verbindungsanfrage erhalten")
            return

        host, port, ssh_username, secret, auth_method = await _resolve_connect_params(connect_msg, user.id)
        if host is None:
            await websocket.send_json({"type": "error", "message": "Ungueltige Verbindungsdaten oder gespeicherte Verbindung nicht gefunden."})
            await websocket.close(code=4400)
            return

        connection_label = f"{ssh_username}@{host}:{port}"

        try:
            client_keys = None
            password = None
            if auth_method == "key" and secret:
                client_keys = [asyncssh.import_private_key(secret)]
            elif secret:
                password = secret

            conn = await asyncio.wait_for(
                asyncssh.connect(
                    host, port=port, username=ssh_username,
                    password=password, client_keys=client_keys,
                    known_hosts=None,  # bewusst: der Nutzer verbindet sich mit selbst gewaehlten Zielen,
                                       # eine feste known_hosts-Datei ist hier nicht sinnvoll pflegbar
                ),
                timeout=15,
            )
        except Exception as exc:  # noqa: BLE001
            log_audit_event(db_for_audit, "ssh_webshell_connect", success=False, username=user.username, ip_address=None, detail=f"{connection_label}: {exc}")
            await websocket.send_json({"type": "error", "message": f"Verbindung fehlgeschlagen: {exc}"})
            await websocket.close(code=4400)
            return

        log_audit_event(db_for_audit, "ssh_webshell_connect", success=True, username=user.username, ip_address=None, detail=connection_label)

        async with conn:
            process = await conn.create_process(term_type="xterm-256color", term_size=(80, 24), encoding=None)
            await websocket.send_json({"type": "connected"})
            await _pump(websocket, process)
    finally:
        await _redis.decr(session_count_key)
        db_for_audit.close()


async def _resolve_connect_params(msg: dict, user_id: int) -> tuple[str | None, int, str | None, str | None, str | None]:
    """Loest die Verbindungs-Nachricht auf: entweder eine gespeicherte
    Verbindung (per ID, mit user_id-Filter) oder Ad-hoc-Angaben direkt
    aus der Nachricht (Session-Key/Passwort gilt dann NUR fuer diese eine
    Verbindung, wird nirgendwo gespeichert)."""
    if msg.get("saved_connection_id"):
        result = await _get_saved_connection_secret(user_id, int(msg["saved_connection_id"]))
        if result is None:
            return None, 22, None, None, None
        conn, secret = result
        # Ad-hoc mitgeschicktes Geheimnis hat Vorrang (z.B. wenn fuer eine
        # OHNE gespeichertes Geheimnis angelegte Verbindung gerade ein
        # Passwort/Key fuer diese eine Sitzung eingegeben wurde).
        override_secret = msg.get("secret")
        return conn.host, conn.port, conn.username, (override_secret or secret), conn.auth_method

    host = msg.get("host")
    port = int(msg.get("port") or 22)
    ssh_username = msg.get("username")
    secret = msg.get("secret")
    auth_method = msg.get("auth_method", "password")
    if not host or not ssh_username:
        return None, port, None, None, None
    return host, port, ssh_username, secret, auth_method


async def _pump(websocket: WebSocket, process: "asyncssh.SSHClientProcess") -> None:
    """Reicht Daten in BEIDE Richtungen durch, bis eine Seite die
    Verbindung beendet."""

    async def read_from_ssh() -> None:
        try:
            while True:
                data = await process.stdout.read(65536)
                if not data:
                    break
                await websocket.send_json({"type": "data", "data": data.decode("utf-8", errors="replace")})
        except (asyncssh.ChannelOpenError, ConnectionError, OSError):
            pass
        except Exception:  # noqa: BLE001
            pass

    reader_task = asyncio.create_task(read_from_ssh())
    try:
        while True:
            msg = await websocket.receive_json()
            msg_type = msg.get("type")
            if msg_type == "input":
                process.stdin.write(msg.get("data", "").encode("utf-8"))
            elif msg_type == "resize":
                cols = int(msg.get("cols", 80))
                rows = int(msg.get("rows", 24))
                process.change_terminal_size(cols, rows)
            elif msg_type == "close":
                break
    except WebSocketDisconnect:
        pass
    except Exception:  # noqa: BLE001
        pass
    finally:
        reader_task.cancel()
        try:
            process.terminate()
        except Exception:  # noqa: BLE001
            pass
