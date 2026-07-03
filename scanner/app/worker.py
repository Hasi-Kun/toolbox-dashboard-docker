"""Worker-Loop des toolbox-scanner-Containers.

Verbindet zu Redis, wartet auf Jobs in der Queue (vom Backend eingereiht),
fuehrt den passenden nmap-Aufruf aus (nur ueber die festen Templates in
templates.py, nie mit freien Nutzer-Flags) und schreibt das Ergebnis
zurueck. Laeuft dauerhaft, kein Restart pro Job.
"""

import asyncio
import json
import logging
import os

import redis.asyncio as redis

from app.templates import TEMPLATES, InvalidJobError
from app.xml_parser import parse_nmap_xml

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | scanner | %(message)s")
logger = logging.getLogger("scanner")

REDIS_URL = os.environ.get("REDIS_URL", "redis://toolbox-redis:6379/0")
QUEUE_KEY = "scanner:jobs"
RESULT_TTL_SECONDS = 300
SUBPROCESS_TIMEOUT_SECONDS = 120

_redis = redis.from_url(REDIS_URL, decode_responses=True)


async def run_nmap(args: list[str]) -> str:
    """Fuehrt nmap ueber argv-Liste aus (nie Shell), gibt stdout (XML) zurueck."""
    env = {**os.environ, "NMAP_PRIVILEGED": "1"}
    process = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
    )
    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            process.communicate(), timeout=SUBPROCESS_TIMEOUT_SECONDS
        )
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
        raise TimeoutError("nmap-Scan hat das Zeitlimit ueberschritten")

    if process.returncode != 0:
        raise RuntimeError(stderr_bytes.decode("utf-8", errors="replace")[:500] or "nmap ist fehlgeschlagen")

    return stdout_bytes.decode("utf-8", errors="replace")


async def handle_job(job: dict) -> None:
    job_id = job["job_id"]
    template_name = job["template"]
    params = job.get("params", {})

    logger.info("Job %s: Template=%s Ziel=%s", job_id, template_name, params.get("target"))

    result: dict = {}
    try:
        builder = TEMPLATES.get(template_name)
        if builder is None:
            raise InvalidJobError(f"Unbekanntes Template: {template_name}")

        args = builder(params)
        xml_output = await run_nmap(args)
        hosts = parse_nmap_xml(xml_output)
        result = {"hosts": hosts}
        logger.info("Job %s: fertig, %d Host(s)", job_id, len(hosts))
    except InvalidJobError as exc:
        result = {"error": f"Ungueltiger Job: {exc}"}
        logger.warning("Job %s: ungueltig -- %s", job_id, exc)
    except TimeoutError as exc:
        result = {"error": str(exc)}
        logger.warning("Job %s: Timeout", job_id)
    except Exception as exc:  # noqa: BLE001 -- Ergebnis soll immer zurueckgeschrieben werden
        result = {"error": f"Scan fehlgeschlagen: {exc}"}
        logger.exception("Job %s: unerwarteter Fehler", job_id)

    await _redis.set(f"scanner:result:{job_id}", json.dumps(result), ex=RESULT_TTL_SECONDS)


async def main() -> None:
    logger.info("Scanner-Worker gestartet, warte auf Jobs...")
    while True:
        try:
            item = await _redis.blpop(QUEUE_KEY, timeout=5)
        except Exception:  # noqa: BLE001 -- Redis kurz nicht erreichbar, weiter versuchen
            logger.warning("Redis nicht erreichbar, versuche erneut...")
            await asyncio.sleep(2)
            continue

        if item is None:
            continue  # Timeout, keine Jobs -- weiter warten

        _, raw_job = item
        try:
            job = json.loads(raw_job)
            await handle_job(job)
        except Exception:  # noqa: BLE001 -- ein kaputter Job darf den Worker nicht killen
            logger.exception("Konnte Job nicht verarbeiten: %s", raw_job)


if __name__ == "__main__":
    asyncio.run(main())
