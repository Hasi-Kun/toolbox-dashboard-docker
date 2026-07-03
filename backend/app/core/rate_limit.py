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

from app.core.config import get_settings

logger = logging.getLogger("toolbox.rate_limit")
settings = get_settings()

_redis_client = redis.from_url(settings.redis_url, decode_responses=True)


async def enforce_rate_limit(request: Request, bucket: str, limit: int | None = None) -> None:
    client_ip = request.headers.get("x-real-ip") or (
        request.client.host if request.client else "unknown"
    )
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
