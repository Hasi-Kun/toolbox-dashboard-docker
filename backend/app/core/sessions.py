"""Server-seitige Sessions und temporaere 'Pending-Login'-Zustaende, beide in Redis.

Bewusst KEIN JWT im Cookie: ein serverseitiger Session-Store erlaubt
sofortigen Logout/Revoke (z.B. bei Passwort-Reset oder Account-Deaktivierung
durch einen Admin), was mit einem selbst-validierenden JWT nicht ohne
zusaetzliche Blocklist moeglich waere.
"""

import json
import secrets
from typing import Any, Literal

import redis.asyncio as redis

from app.core.config import get_settings

settings = get_settings()
_redis = redis.from_url(settings.redis_url, decode_responses=True)

PendingPurpose = Literal["login", "setup_totp", "setup_passkey"]


# --- Sessions (nach vollstaendiger Authentifizierung) ---------------------

async def create_session(user_id: int) -> str:
    session_id = secrets.token_urlsafe(32)
    await _redis.set(
        f"session:{session_id}",
        json.dumps({"user_id": user_id}),
        ex=settings.session_ttl_seconds,
    )
    # Zusaetzlich in einem Set pro Nutzer vermerken -- ermoeglicht
    # invalidate_all_sessions() unten (z.B. bei einer Passwort-Aenderung
    # sollen ALLE anderen aktiven Sessions dieses Nutzers sofort
    # ungueltig werden, nicht nur die aktuelle).
    await _redis.sadd(f"user-sessions:{user_id}", session_id)
    await _redis.expire(f"user-sessions:{user_id}", settings.session_ttl_seconds)
    return session_id


async def get_session_user_id(session_id: str) -> int | None:
    raw = await _redis.get(f"session:{session_id}")
    if raw is None:
        return None
    return json.loads(raw)["user_id"]


async def delete_session(session_id: str) -> None:
    raw = await _redis.get(f"session:{session_id}")
    if raw is not None:
        user_id = json.loads(raw)["user_id"]
        await _redis.srem(f"user-sessions:{user_id}", session_id)
    await _redis.delete(f"session:{session_id}")


async def invalidate_all_sessions(user_id: int, except_session_id: str | None = None) -> int:
    """Beendet ALLE aktiven Sessions eines Nutzers sofort -- fuer
    sicherheitskritische Ereignisse wie eine Passwort-Aenderung (falls
    das Konto kompromittiert war, soll ein Angreifer mit einer alten
    Session sofort ausgesperrt werden). `except_session_id` laesst
    optional die AKTUELLE Session des Nutzers unangetastet (er soll sich
    nach der eigenen Passwort-Aenderung nicht selbst ausloggen)."""
    session_ids = await _redis.smembers(f"user-sessions:{user_id}")
    revoked = 0
    for session_id in session_ids:
        if session_id == except_session_id:
            continue
        await _redis.delete(f"session:{session_id}")
        await _redis.srem(f"user-sessions:{user_id}", session_id)
        revoked += 1
    return revoked


# --- Pending-Logins (zwischen Passwort-Check und 2FA-Abschluss) -----------

async def create_pending(user_id: int, purpose: PendingPurpose, extra: dict[str, Any] | None = None) -> str:
    pending_id = secrets.token_urlsafe(32)
    payload = {"user_id": user_id, "purpose": purpose, **(extra or {})}
    await _redis.set(
        f"pending:{pending_id}",
        json.dumps(payload),
        ex=settings.pending_login_ttl_seconds,
    )
    return pending_id


async def get_pending(pending_id: str) -> dict[str, Any] | None:
    raw = await _redis.get(f"pending:{pending_id}")
    if raw is None:
        return None
    return json.loads(raw)


async def update_pending(pending_id: str, extra: dict[str, Any]) -> None:
    current = await get_pending(pending_id)
    if current is None:
        return
    current.update(extra)
    await _redis.set(
        f"pending:{pending_id}",
        json.dumps(current),
        ex=settings.pending_login_ttl_seconds,
    )


async def delete_pending(pending_id: str) -> None:
    await _redis.delete(f"pending:{pending_id}")


async def get_online_user_ids() -> set[int]:
    """Ermittelt die eindeutigen User-IDs mit einer aktiven (nicht abgelaufenen)
    Session -- 'online' ist hier definiert als 'hat gerade eine gueltige Session',
    nicht als 'aktiv im Browser gerade jetzt' (kein Heartbeat/WebSocket).
    """
    user_ids: set[int] = set()
    async for key in _redis.scan_iter(match="session:*"):
        raw = await _redis.get(key)
        if raw:
            try:
                user_ids.add(json.loads(raw)["user_id"])
            except (KeyError, ValueError):
                continue
    return user_ids


# --- Transiente Werte fuer selbstbedienten 2FA-Setup (User ist bereits
# eingeloggt, daher an die user_id statt an einen pending_token gebunden) ---

async def store_transient(key: str, value: dict[str, Any], ttl_seconds: int = 300) -> None:
    await _redis.set(f"transient:{key}", json.dumps(value), ex=ttl_seconds)


async def get_transient(key: str) -> dict[str, Any] | None:
    raw = await _redis.get(f"transient:{key}")
    return json.loads(raw) if raw is not None else None


async def delete_transient(key: str) -> None:
    await _redis.delete(f"transient:{key}")
