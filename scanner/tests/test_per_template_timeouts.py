"""Regressionstest fuer den gemeldeten Vorfall: nmap-vuln-scan (und
potenziell full-port-scan/aggressive) wurden vom Scanner-Worker nach
pauschal 120s abgebrochen, obwohl das jeweilige Backend-Modul deutlich
mehr Zeit einraeumt (z.B. 180s bei vuln-scan). Jeder Scan-Typ bekommt
jetzt sein eigenes, zum Backend passendes Timeout.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app.worker as worker  # noqa: E402

# Muss zum jeweiligen Backend-Modul passen (app/modules/nmap/*.py,
# timeout_seconds), abzueglich des dortigen 5s-Puffers fuer
# wait_for_result -- der Scanner-Timeout muss darunter bleiben, sonst
# gibt das Backend statt einer klaren "Timeout"-Meldung ein
# nichtssagendes "Scanner nicht erreichbar" aus.
_BACKEND_WAIT_BUDGET = {
    "quick": 35,
    "top-ports": 55,
    "service-detection": 70,
    "os-detection": 55,
    "aggressive": 145,
    "udp": 95,
    "host-discovery": 20,
    "full-port-scan": 295,
    "vuln-scan": 175,
}


def test_every_known_template_has_a_timeout_under_the_backend_budget():
    for template, backend_budget in _BACKEND_WAIT_BUDGET.items():
        scanner_timeout = worker.SUBPROCESS_TIMEOUT_BY_TEMPLATE.get(template, worker.DEFAULT_SUBPROCESS_TIMEOUT_SECONDS)
        assert scanner_timeout < backend_budget, (
            f"{template}: Scanner-Timeout ({scanner_timeout}s) muss unter dem "
            f"Backend-Wartebudget ({backend_budget}s) liegen, sonst gewinnt das "
            f"Backend den Wettlauf mit einer nichtssagenden Fehlermeldung."
        )


def test_vuln_scan_gets_generous_timeout_not_the_old_120s_default():
    """Der eigentliche gemeldete Vorfall: vuln-scan brach nach 120s ab,
    obwohl das Backend bis zu 180s vorsieht."""
    assert worker.SUBPROCESS_TIMEOUT_BY_TEMPLATE["vuln-scan"] > 120


def test_full_port_scan_gets_generous_timeout():
    assert worker.SUBPROCESS_TIMEOUT_BY_TEMPLATE["full-port-scan"] > 120


def test_aggressive_gets_generous_timeout():
    assert worker.SUBPROCESS_TIMEOUT_BY_TEMPLATE["aggressive"] > 120


def test_unknown_template_falls_back_to_default():
    assert worker.SUBPROCESS_TIMEOUT_BY_TEMPLATE.get("brandneu-tool", worker.DEFAULT_SUBPROCESS_TIMEOUT_SECONDS) == 90
