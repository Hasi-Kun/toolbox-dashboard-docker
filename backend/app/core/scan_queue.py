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
# Der Job-KONTEXT (urspruengliche Eingabe + User-ID) muss die GESAMTE
# Scan-Dauer ueberleben (jetzt bis zu 30 Minuten), nicht nur kurz bis zum
# naechsten Poll wie das Ergebnis selbst -- sonst waere der Kontext schon
# abgelaufen, wenn ein langer Scan fertig wird, und das Ergebnis koennte
# nicht mehr korrekt in das typisierte Output-Modell umgewandelt werden.
JOB_CONTEXT_TTL_SECONDS = 2100  # 35 Minuten -- etwas Puffer ueber der 30-Minuten-Obergrenze


async def get_queue_status() -> dict[str, Any]:
    """Fuer die 'Aktuell laufende Scans'-Anzeige im Frontend: welcher Job
    laeuft gerade beim Scanner-Worker (falls einer), und wie viele
    warten noch in der Warteschlange (der Scanner verarbeitet Jobs
    sequenziell, ein Worker gleichzeitig -- das ist bewusst so, um den
    isolierten Scanner-Container nicht zu ueberlasten)."""
    current_raw = await _redis.get("scanner:current-job")
    current_job = json.loads(current_raw) if current_raw else None
    queue_length = await _redis.llen(QUEUE_KEY)
    return {"current_job": current_job, "queue_length": queue_length}


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


async def stash_job_context(job_id: str, slug: str, input_data: dict[str, Any], user_id: int) -> None:
    """Speichert Slug + Original-Eingabe + Ersteller neben dem Job -- der
    Status-Poll-Endpoint braucht das, um das rohe Scanner-Ergebnis wieder
    in das richtige, typisierte Output-Modell umzuwandeln (das Modul
    weiss z.B. "target" nur aus der urspruenglichen Eingabe, nicht aus
    dem rohen Scan-Ergebnis selbst) und um zu pruefen, dass nur der
    urspruengliche Ersteller (oder ein Admin) das Ergebnis abfragen darf."""
    key = f"scanner:job-context:{job_id}"
    await _redis.set(key, json.dumps({"slug": slug, "input": input_data, "user_id": user_id}), ex=JOB_CONTEXT_TTL_SECONDS)


async def get_job_context(job_id: str) -> dict[str, Any] | None:
    key = f"scanner:job-context:{job_id}"
    raw = await _redis.get(key)
    if raw is None:
        return None
    return json.loads(raw)


async def delete_job_context(job_id: str) -> None:
    await _redis.delete(f"scanner:job-context:{job_id}")


async def peek_result(job_id: str) -> dict[str, Any] | None:
    """Einmaliger, NICHT blockierender Check, ob das Ergebnis schon da ist --
    fuer das Polling-Muster vom Frontend aus (POST .../scan/start gibt
    sofort eine job_id zurueck, GET .../scan/status/{job_id} fragt dann in
    kurzen Abstaenden hier nach, statt eine einzelne HTTP-Verbindung fuer
    die gesamte Scan-Dauer offen zu halten -- das war anfaellig fuer
    Reverse-Proxy-/CDN-Timeouts bei langen Scans, siehe README).
    """
    key = f"scanner:result:{job_id}"
    raw = await _redis.get(key)
    if raw is None:
        return None
    await _redis.delete(key)
    return json.loads(raw)
