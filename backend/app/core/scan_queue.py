"""Job-Queue fuer aktive Scans (Nmap), die im isolierten `toolbox-scanner`-
Container laufen, nicht im Haupt-Backend.

Bewusst simple Redis-Liste statt eines vollen Task-Frameworks (Celery etc.)
-- fuer den Scope hier (ein Producer, ein Consumer-Typ) reicht das, und es
gibt keine zusaetzliche Infrastruktur-Abhaengigkeit.
"""

import asyncio
import json
import secrets
from typing import Any

import redis.asyncio as redis

from app.core.config import get_settings

settings = get_settings()
_redis = redis.from_url(settings.redis_url, decode_responses=True)

QUEUE_KEY = "scanner:jobs"
RESULT_TTL_SECONDS = 300


async def submit_job(template: str, params: dict[str, Any]) -> str:
    job_id = secrets.token_urlsafe(16)
    payload = {"job_id": job_id, "template": template, "params": params}
    await _redis.rpush(QUEUE_KEY, json.dumps(payload))
    return job_id


async def wait_for_result(job_id: str, timeout: float, poll_interval: float = 1.0) -> dict[str, Any] | None:
    """Pollt auf das Ergebnis, statt BLPOP direkt auf dem Result-Key zu nutzen --
    einfacher zu reasonen und der Scanner-Worker muss dafuer nichts Spezielles tun
    (nur ein normales SET mit TTL).
    """
    key = f"scanner:result:{job_id}"
    elapsed = 0.0
    while elapsed < timeout:
        raw = await _redis.get(key)
        if raw is not None:
            await _redis.delete(key)
            return json.loads(raw)
        await asyncio.sleep(poll_interval)
        elapsed += poll_interval
    return None
