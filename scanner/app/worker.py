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
from datetime import datetime, timezone

import redis.asyncio as redis

from app.templates import TEMPLATES, InvalidJobError
from app.xml_parser import parse_nmap_xml
from app.nikto_parser import parse_nikto_xml

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | scanner | %(message)s")
logger = logging.getLogger("scanner")

REDIS_URL = os.environ.get("REDIS_URL", "redis://toolbox-redis:6379/0")
QUEUE_KEY = "scanner:jobs"
RESULT_TTL_SECONDS = 300

# Pro-Template-Timeouts statt eines einzigen pauschalen Werts -- der Bug,
# der bei nmap-vuln-scan aufgefallen ist (Backend erwartet bis zu 180s,
# Scanner killte den Prozess pauschal nach 120s), haette genauso
# full-port-scan (Backend 300s) und aggressive (Backend 150s) treffen
# koennen. Werte hier jeweils knapp UNTER dem, was das Backend-Modul via
# `wait_for_result(timeout=self.timeout_seconds - 5)` einraeumt, damit
# der Scanner selbst sauber "Timeout" zurueckmelden kann, BEVOR das
# Backend seinerseits aufgibt (sonst kommt statt einer klaren Timeout-
# Meldung ein nichtssagendes "Scanner nicht erreichbar" beim Nutzer an).
#
# Auf bis zu 30 Minuten fuer die schwersten Tools angehoben (vorher
# einige Minuten) -- seit der Umstellung auf das Polling-Muster
# (POST .../scan/start + GET .../scan/status/{job_id}) ist eine lange
# Laufzeit kein Problem mehr fuer Reverse-Proxy-/CDN-Timeouts, da keine
# einzelne HTTP-Verbindung mehr so lange offen gehalten werden muss.
SUBPROCESS_TIMEOUT_BY_TEMPLATE: dict[str, int] = {
    "quick": 30,
    "top-ports": 50,
    "service-detection": 80,
    "os-detection": 80,
    "aggressive": 850,
    "udp": 280,
    "host-discovery": 15,
    "full-port-scan": 1750,
    "vuln-scan": 1750,
}
DEFAULT_SUBPROCESS_TIMEOUT_SECONDS = 90  # Fallback fuer unbekannte/neue Templates
NIKTO_SUBPROCESS_TIMEOUT_SECONDS = 1750  # Nikto kann bei grossen Sites sehr lange dauern

_redis = redis.from_url(REDIS_URL, decode_responses=True)


async def run_command(args: list[str], timeout: int, cwd: str | None = None) -> str:
    """Fuehrt ein beliebiges (fest vorgegebenes) Kommando ueber argv-Liste
    aus (nie Shell), gibt stdout zurueck. Gemeinsam fuer nmap UND nikto,
    da beide gleich aufgerufen werden (nur die Argument-Liste unterscheidet
    sich, die kommt bereits fertig validiert aus templates.py). `cwd` fuer
    Nikto gesetzt (siehe templates.py), da es Config-/Datenbank-Dateien
    ggf. relativ zum Arbeitsverzeichnis sucht."""
    process = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd,
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

    if stderr_bytes:
        # Immer loggen, auch bei Erfolg -- hilft beim Debuggen von Faellen,
        # in denen das Tool "erfolgreich" durchlief, aber trotzdem
        # Warnungen/Fehler auf stderr ausgegeben hat (z.B. fehlende
        # Perl-Module bei Nikto, die nicht zwingend zu einem Exit-Code
        # ungleich 0 fuehren).
        logger.info("%s stderr: %s", args[0], stderr_bytes.decode("utf-8", errors="replace")[:500])

    return stdout_bytes.decode("utf-8", errors="replace")


CURRENT_JOB_KEY = "scanner:current-job"
CURRENT_JOB_TTL_SECONDS = 2100  # Sicherheitsnetz: falls der Worker mitten im Job abstuerzt,
# soll der Eintrag nicht fuer immer "faelschlich beschaeftigt" anzeigen.


async def handle_job(job: dict) -> None:
    job_id = job["job_id"]
    template_name = job["template"]
    params = job.get("params", {})

    logger.info("Job %s: Template=%s Ziel=%s", job_id, template_name, params.get("target"))

    # Fuer die Warteschlangen-Anzeige im Frontend: welcher Job laeuft
    # gerade, seit wann, gegen welches Ziel.
    await _redis.set(
        CURRENT_JOB_KEY,
        json.dumps({
            "job_id": job_id, "template": template_name, "target": params.get("target"),
            "started_at": datetime.now(timezone.utc).isoformat(),
        }),
        ex=CURRENT_JOB_TTL_SECONDS,
    )

    result: dict = {}
    nikto_output_path: str | None = None
    try:
        builder = TEMPLATES.get(template_name)
        if builder is None:
            raise InvalidJobError(f"Unbekanntes Template: {template_name}")

        if template_name == "nikto":
            # Echter temporaerer Dateipfad statt '-' -- Nikto unterstuetzt
            # (anders als nmap) kein Stdout-Streaming fuer -output.
            fd, nikto_output_path = tempfile.mkstemp(suffix=".xml", prefix="nikto_")
            os.close(fd)

            args = builder({**params, "_output_path": nikto_output_path})
            console_output = await run_command(args, timeout=NIKTO_SUBPROCESS_TIMEOUT_SECONDS, cwd="/opt/nikto/program")

            with open(nikto_output_path, encoding="utf-8", errors="replace") as f:
                raw_output = f.read()

            try:
                result = parse_nikto_xml(raw_output)
            except ValueError as exc:
                # Diagnose-Hilfe: Niktos tatsaechliche Konsolenausgabe mit
                # anhaengen, statt nur "kein JSON gefunden" zu melden --
                # damit ein echtes Problem (z.B. fehlendes Perl-Modul)
                # beim naechsten Mal direkt im Fehlertext sichtbar ist,
                # statt erst muehsam im Container-Log gesucht werden zu muessen.
                snippet = console_output.strip()[:300] or "(keine Konsolenausgabe erfasst)"
                raise ValueError(f"{exc} -- Nikto-Konsolenausgabe: {snippet}") from exc
        else:
            args = builder(params)
            template_timeout = SUBPROCESS_TIMEOUT_BY_TEMPLATE.get(template_name, DEFAULT_SUBPROCESS_TIMEOUT_SECONDS)
            raw_output = await run_command(args, timeout=template_timeout)
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
        # "Aktuell laufender Job" zuruecksetzen, damit die Warteschlangen-
        # Anzeige im Frontend korrekt zeigt, dass wieder nichts laeuft.
        await _redis.delete(CURRENT_JOB_KEY)

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
