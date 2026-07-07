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
import tempfile

import redis.asyncio as redis

from app.templates import TEMPLATES, InvalidJobError
from app.xml_parser import parse_nmap_xml
from app.nikto_parser import parse_nikto_json

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | scanner | %(message)s")
logger = logging.getLogger("scanner")

REDIS_URL = os.environ.get("REDIS_URL", "redis://toolbox-redis:6379/0")
QUEUE_KEY = "scanner:jobs"
RESULT_TTL_SECONDS = 300
SUBPROCESS_TIMEOUT_SECONDS = 120
NIKTO_SUBPROCESS_TIMEOUT_SECONDS = 200  # Nikto braucht laenger als ein nmap-Schnellscan

_redis = redis.from_url(REDIS_URL, decode_responses=True)


async def run_command(args: list[str], timeout: int) -> str:
    """Fuehrt ein beliebiges (fest vorgegebenes) Kommando ueber argv-Liste
    aus (nie Shell), gibt stdout zurueck. Gemeinsam fuer nmap UND nikto,
    da beide gleich aufgerufen werden (nur die Argument-Liste unterscheidet
    sich, die kommt bereits fertig validiert aus templates.py)."""
    process = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env={**os.environ, "NMAP_PRIVILEGED": "1"},
    )
    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            process.communicate(), timeout=timeout
        )
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
        raise TimeoutError(f"{args[0]}-Scan hat das Zeitlimit ueberschritten")

    if process.returncode != 0 and not stdout_bytes:
        raise RuntimeError(stderr_bytes.decode("utf-8", errors="replace")[:500] or f"{args[0]} ist fehlgeschlagen")

    return stdout_bytes.decode("utf-8", errors="replace")


async def handle_job(job: dict) -> None:
    job_id = job["job_id"]
    template_name = job["template"]
    params = job.get("params", {})

    logger.info("Job %s: Template=%s Ziel=%s", job_id, template_name, params.get("target"))

    result: dict = {}
    nikto_output_path: str | None = None
    try:
        builder = TEMPLATES.get(template_name)
        if builder is None:
            raise InvalidJobError(f"Unbekanntes Template: {template_name}")

        if template_name == "nikto":
            # Echter temporaerer Dateipfad statt '-' -- Nikto unterstuetzt
            # (anders als nmap) kein Stdout-Streaming fuer -output.
            fd, nikto_output_path = tempfile.mkstemp(suffix=".json", prefix="nikto_")
            os.close(fd)

            args = builder({**params, "_output_path": nikto_output_path})
            await run_command(args, timeout=NIKTO_SUBPROCESS_TIMEOUT_SECONDS)

            with open(nikto_output_path, encoding="utf-8", errors="replace") as f:
                raw_output = f.read()
            result = parse_nikto_json(raw_output)
        else:
            args = builder(params)
            raw_output = await run_command(args, timeout=SUBPROCESS_TIMEOUT_SECONDS)
            hosts = parse_nmap_xml(raw_output)
            result = {"hosts": hosts}

        logger.info("Job %s: fertig", job_id)
    except InvalidJobError as exc:
        result = {"error": f"Ungueltiger Job: {exc}"}
        logger.warning("Job %s: ungueltig -- %s", job_id, exc)
    except TimeoutError as exc:
        result = {"error": str(exc)}
        logger.warning("Job %s: Timeout", job_id)
    except Exception as exc:  # noqa: BLE001 -- Ergebnis soll immer zurueckgeschrieben werden
        result = {"error": f"Scan fehlgeschlagen: {exc}"}
        logger.exception("Job %s: unerwarteter Fehler", job_id)
    finally:
        # Temporaere Nikto-Ausgabedatei IMMER loeschen, unabhaengig vom
        # Ergebnis -- kein dauerhafter Speicher von Scan-Rohdaten.
        if nikto_output_path is not None:
            try:
                os.unlink(nikto_output_path)
            except OSError:
                pass

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
