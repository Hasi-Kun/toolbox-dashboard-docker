"""Simples Fixed-Window Rate Limiting pro Client-IP, ueber Redis.

Bewusst fail-open: wenn Redis nicht erreichbar ist, wird die Anfrage
durchgelassen (mit Warnung im Log) statt die gesamte API lahmzulegen.
Ein Ausfall des Rate-Limiters soll kein Ausfall des Tools sein --
die eigentliche Absicherung gegen Abuse bei aktiven Scans passiert
ohnehin zusaetzlich im isolierten toolbox-scanner (Phase 5).
"""

import logging

import redis.asyncio as redis
from fastapi import HTTPException, Request

from app.core.audit import get_client_ip
from app.core.config import get_settings

logger = logging.getLogger("toolbox.rate_limit")
settings = get_settings()

_redis_client = redis.from_url(settings.redis_url, decode_responses=True)


async def enforce_rate_limit(request: Request, bucket: str, limit: int | None = None) -> None:
    # Dieselbe robuste Fallback-Kette wie beim Audit-Log (X-Real-IP ->
    # CF-Connecting-IP -> X-Forwarded-For) -- vorher wurde hier NUR
    # X-Real-IP geprueft, wodurch bei fehlender/abweichender Caddy-
    # Konfiguration alle Nutzer die interne Docker-IP des Frontend-
    # Containers geteilt haetten (ein Nutzer haette dann versehentlich
    # ALLE anderen mit-limitieren koennen).
    client_ip = get_client_ip(request) or "unknown"
    key = f"ratelimit:{bucket}:{client_ip}"
    max_requests = limit if limit is not None else settings.rate_limit_per_minute

    try:
        count = await _redis_client.incr(key)
        if count == 1:
            await _redis_client.expire(key, 60)
    except Exception:  # noqa: BLE001 -- Redis-Ausfall darf die API nicht mitreissen
        logger.warning("Rate-Limiter nicht erreichbar, lasse Anfrage ohne Limit durch.")
        return

    if count > max_requests:
        raise HTTPException(status_code=429, detail="Zu viele Anfragen -- bitte kurz warten.")


async def enforce_account_lockout(username: str, window_seconds: int = 900, max_failed_attempts: int = 10) -> None:
    """Zusaetzlich zum IP-basierten Rate-Limit: begrenzt fehlgeschlagene
    Login-Versuche PRO ACCOUNT, unabhaengig von der IP -- ein Angreifer
    mit rotierenden IPs (z.B. ueber ein Botnet) koennte sonst ein
    einzelnes Konto durchgehend per Brute-Force angreifen, ohne je das
    IP-basierte Limit zu treffen (jede IP macht dabei nur wenige
    Versuche, bevor sie wechselt). 15 Minuten Fenster, 10 fehlgeschlagene
    Versuche -- bewusst grosszuegiger als das IP-Limit, damit ein
    legitimer Nutzer mit ein paar Tippfehlern nicht ausgesperrt wird.
    """
    key = f"ratelimit:account-lockout:{username.strip().lower()}"
    try:
        count = await _redis_client.get(key)
    except Exception:  # noqa: BLE001
        logger.warning("Rate-Limiter nicht erreichbar, ueberspringe Konto-Sperre.")
        return

    if count is not None and int(count) >= max_failed_attempts:
        raise HTTPException(
            status_code=429,
            detail="Zu viele fehlgeschlagene Anmeldeversuche fuer dieses Konto -- bitte spaeter erneut versuchen.",
        )


async def record_failed_login(username: str, window_seconds: int = 900) -> None:
    """Zaehlt einen fehlgeschlagenen Login-Versuch fuer die Konto-Sperre
    hoch -- wird NUR bei falschem Passwort aufgerufen, nie bei Erfolg,
    damit ein Nutzer, der sich nur vertippt, nicht faelschlich gesperrt wird."""
    key = f"ratelimit:account-lockout:{username.strip().lower()}"
    try:
        count = await _redis_client.incr(key)
        if count == 1:
            await _redis_client.expire(key, window_seconds)
    except Exception:  # noqa: BLE001
        logger.warning("Rate-Limiter nicht erreichbar, konnte fehlgeschlagenen Versuch nicht zaehlen.")


async def clear_failed_login_count(username: str) -> None:
    """Setzt den Zaehler nach einem ERFOLGREICHEN Login zurueck."""
    try:
        await _redis_client.delete(f"ratelimit:account-lockout:{username.strip().lower()}")
    except Exception:  # noqa: BLE001
        pass
