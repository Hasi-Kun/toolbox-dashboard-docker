"""Regressionstest fuer den gemeldeten Vorfall: nmap-vuln-scan (und
potenziell full-port-scan/aggressive) wurden vom Scanner-Worker nach
pauschal 120s abgebrochen, obwohl das jeweilige Backend-Modul deutlich
mehr Zeit einraeumt (z.B. 180s bei vuln-scan). Jeder Scan-Typ bekommt
jetzt sein eigenes, zum Backend passendes Timeout.

WICHTIG (Update nach Umstellung auf das Polling-Muster): Fuer die
schwersten Tools (aggressive/udp/full-port-scan/vuln-scan/nikto) wurde
die Verantwortung bewusst aufgeteilt -- das Backend-Modul-Timeout
(`timeout_seconds`) deckelt nur noch den ALTEN synchronen Fallback-Pfad
bei 5 Minuten (dieser Pfad haelt weiterhin eine einzelne HTTP-Verbindung
offen und soll deshalb nicht laenger laufen), waehrend der Scanner
selbst fuer den NEUEN Polling-Pfad (scan/start + scan/status, den
unsere eigene Oberflaeche ausschliesslich nutzt) bis zu 30 Minuten
bekommt. Der alte "Scanner-Timeout muss unter Backend-Budget liegen"-
Test gilt deshalb nur noch fuer die Tools, deren Backend-Timeout klein
geblieben ist (quick/top-ports/os-detection/host-discovery) -- fuer die
5 schweren Tools ist ein hoeherer Scanner-Timeout jetzt ABSICHTLICH.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app.worker as worker  # noqa: E402

# Nur noch fuer die Tools relevant, deren Backend-Timeout klein geblieben
# ist -- dort soll der Scanner weiterhin zuerst sauber "Timeout" melden
# koennen, bevor der (kurze) synchrone Backend-Wait aufgibt.
_BACKEND_WAIT_BUDGET_FOR_SHORT_TOOLS = {
    "quick": 35,
    "top-ports": 55,
    "service-detection": 85,
    "os-detection": 85,
    "host-discovery": 20,
}

# Die 5 schwersten Tools: Backend-Timeout ist jetzt bewusst ein fixer,
# niedriger Deckel (5 Minuten) NUR fuer den alten synchronen Fallback-Pfad --
# der Scanner selbst darf (und soll) fuer den neuen Polling-Pfad deutlich
# laenger laufen duerfen (bis zu 30 Minuten).
_HEAVY_TOOLS_WITH_EXTENDED_SCANNER_TIMEOUT = ["aggressive", "udp", "full-port-scan", "vuln-scan"]


def test_short_tools_keep_scanner_timeout_under_backend_budget():
    for template, backend_budget in _BACKEND_WAIT_BUDGET_FOR_SHORT_TOOLS.items():
        scanner_timeout = worker.SUBPROCESS_TIMEOUT_BY_TEMPLATE.get(template, worker.DEFAULT_SUBPROCESS_TIMEOUT_SECONDS)
        assert scanner_timeout < backend_budget, (
            f"{template}: Scanner-Timeout ({scanner_timeout}s) muss unter dem "
            f"Backend-Wartebudget ({backend_budget}s) liegen, sonst gewinnt das "
            f"Backend den Wettlauf mit einer nichtssagenden Fehlermeldung."
        )


def test_heavy_tools_get_extended_scanner_timeout_up_to_30_minutes():
    """Die schwersten Tools duerfen (und sollen) jetzt bis zu 30 Minuten
    beim Scanner selbst bekommen -- unabhaengig vom kleineren Backend-
    Fallback-Timeout, weil der neue Polling-Pfad das Backend-Timeout gar
    nicht mehr als blockierende Wartezeit nutzt."""
    for template in _HEAVY_TOOLS_WITH_EXTENDED_SCANNER_TIMEOUT:
        scanner_timeout = worker.SUBPROCESS_TIMEOUT_BY_TEMPLATE[template]
        assert scanner_timeout >= 280, f"{template}: sollte deutlich verlaengert sein, ist aber nur {scanner_timeout}s"
    assert worker.NIKTO_SUBPROCESS_TIMEOUT_SECONDS >= 280


def test_vuln_scan_gets_up_to_30_minutes():
    """Der eigentliche gemeldete Vorfall: vuln-scan brach nach 120s ab,
    jetzt soll es bis zu 30 Minuten (mit etwas Puffer) bekommen."""
    assert worker.SUBPROCESS_TIMEOUT_BY_TEMPLATE["vuln-scan"] >= 1700
    assert worker.SUBPROCESS_TIMEOUT_BY_TEMPLATE["vuln-scan"] <= 1800


def test_full_port_scan_gets_up_to_30_minutes():
    assert worker.SUBPROCESS_TIMEOUT_BY_TEMPLATE["full-port-scan"] >= 1700
    assert worker.SUBPROCESS_TIMEOUT_BY_TEMPLATE["full-port-scan"] <= 1800


def test_nikto_gets_up_to_30_minutes():
    assert worker.NIKTO_SUBPROCESS_TIMEOUT_SECONDS >= 1700
    assert worker.NIKTO_SUBPROCESS_TIMEOUT_SECONDS <= 1800


def test_unknown_template_falls_back_to_default():
    assert worker.SUBPROCESS_TIMEOUT_BY_TEMPLATE.get("brandneu-tool", worker.DEFAULT_SUBPROCESS_TIMEOUT_SECONDS) == 90
