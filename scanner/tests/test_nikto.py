"""Tests fuer die Nikto-Integration im Scanner-Container: festes
Argument-Template (keine frei waehlbaren Flags) und JSON-Parsing.
Eigenstaendige Tests, da der Scanner-Container eine eigene, von der
Haupt-Backend-Suite getrennte Python-Umgebung ist.
"""

import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.templates import TEMPLATES, InvalidJobError  # noqa: E402
from app.nikto_parser import parse_nikto_json  # noqa: E402


def test_nikto_template_builds_fixed_arguments():
    args = TEMPLATES["nikto"]({"target": "example.com", "_output_path": "/tmp/nikto_test.json"})
    assert args[0].endswith("nikto.pl")
    assert "-h" in args and "example.com" in args
    assert "-Format" in args and "json" in args


def test_nikto_template_rejects_invalid_target():
    with pytest.raises(InvalidJobError):
        TEMPLATES["nikto"]({"target": "; rm -rf /"})


def test_nikto_template_rejects_flag_injection_attempt():
    with pytest.raises(InvalidJobError):
        TEMPLATES["nikto"]({"target": "example.com --script=evil"})


def test_nikto_template_requires_output_path():
    """Regressionstest fuer den gemeldeten Vorfall: Nikto unterstuetzt
    (anders als nmap) kein '-' als Stdout-Platzhalter fuer -output --
    das fuehrte dazu, dass Niktos normale Statusmeldungen statt JSON
    erfasst wurden. Jetzt wird ein echter Dateipfad verlangt.
    """
    with pytest.raises(InvalidJobError):
        TEMPLATES["nikto"]({"target": "example.com"})  # kein _output_path gesetzt


def test_nikto_template_uses_real_file_path_not_dash():
    args = TEMPLATES["nikto"]({"target": "example.com", "_output_path": "/tmp/nikto_test.json"})
    output_index = args.index("-output")
    assert args[output_index + 1] == "/tmp/nikto_test.json"
    assert args[output_index + 1] != "-"


def test_nikto_json_parser_extracts_findings():
    sample = (
        '{"host": "example.com", "ip": "93.184.216.34", "port": "80", "banner": "Apache/2.4.41",'
        ' "vulnerabilities": ['
        '{"id": "999986", "method": "GET", "url": "/admin/", "msg": "Admin login page found"},'
        '{"id": "999987", "method": "GET", "url": "/.git/", "msg": "Git repository exposed"}'
        "]}"
    )
    result = parse_nikto_json(sample)
    assert result["host"] == "example.com"
    assert result["finding_count"] == 2
    assert result["findings"][1]["url"] == "/.git/"


def test_nikto_json_parser_handles_empty_output():
    result = parse_nikto_json("")
    assert result["findings"] == []


def test_nikto_json_parser_extracts_json_from_surrounding_text():
    messy = 'Some warning text\n{"host": "test.com", "vulnerabilities": []}\nTrailing text'
    result = parse_nikto_json(messy)
    assert result["host"] == "test.com"


@pytest.mark.asyncio
async def test_handle_job_writes_reads_and_cleans_up_temp_file(tmp_path, monkeypatch):
    """End-to-End-Regressionstest fuer den Produktions-Vorfall: simuliert
    einen erfolgreichen Nikto-Lauf (schreibt JSON in die uebergebene
    Ausgabedatei) und prueft, dass das Ergebnis korrekt geparst UND die
    temporaere Datei danach garantiert geloescht wird.
    """
    import json as json_module
    from unittest.mock import patch
    import app.worker as worker

    sample_json = (
        '{"host": "example.com", "ip": "93.184.216.34", "port": "80",'
        ' "vulnerabilities": [{"id": "1", "method": "GET", "url": "/admin/", "msg": "Found"}]}'
    )

    async def fake_run_command(args, timeout, cwd=None):
        output_path = args[args.index("-output") + 1]
        with open(output_path, "w") as f:
            f.write(sample_json)
        return ""

    stored = {}

    async def fake_set(key, value, ex=None):
        stored["value"] = json_module.loads(value)

    with patch.object(worker, "run_command", new=fake_run_command), patch.object(worker, "_redis") as mock_redis:
        mock_redis.set = fake_set
        job = {"job_id": "test-e2e", "template": "nikto", "params": {"target": "example.com"}}
        await worker.handle_job(job)

    assert stored["value"]["host"] == "example.com"
    assert stored["value"]["finding_count"] == 1

    leftover = [f for f in os.listdir(tempfile.gettempdir()) if f.startswith("nikto_")]
    assert leftover == [], f"Verbliebene temporaere Dateien: {leftover}"


@pytest.mark.asyncio
async def test_handle_job_cleans_up_temp_file_even_on_failure():
    """Die temporaere Ausgabedatei darf auch bei einem Absturz waehrend
    des Scans nicht liegen bleiben."""
    from unittest.mock import patch
    import app.worker as worker

    async def failing_run_command(args, timeout, cwd=None):
        raise RuntimeError("Simulierter Absturz")

    stored = {}

    async def fake_set(key, value, ex=None):
        stored["value"] = json.loads(value)

    with patch.object(worker, "run_command", new=failing_run_command), patch.object(worker, "_redis") as mock_redis:
        mock_redis.set = fake_set
        job = {"job_id": "test-fail", "template": "nikto", "params": {"target": "example.com"}}
        await worker.handle_job(job)

    assert "error" in stored["value"]
    leftover = [f for f in os.listdir(tempfile.gettempdir()) if f.startswith("nikto_")]
    assert leftover == [], f"Verbliebene temporaere Dateien nach Fehler: {leftover}"


@pytest.mark.asyncio
async def test_handle_job_includes_console_output_in_error_when_json_parsing_fails():
    """Regressionstest fuer die Diagnose-Verbesserung: wenn Nikto kein
    gueltiges JSON liefert (z.B. wegen eines fehlenden Perl-Moduls), soll
    die tatsaechliche Nikto-Konsolenausgabe im Fehlertext auftauchen,
    statt nur ein nichtssagendes 'kein JSON gefunden'.
    """
    from unittest.mock import patch
    import app.worker as worker

    async def fake_run_command_no_json(args, timeout, cwd=None):
        output_path = args[args.index("-output") + 1]
        # Simuliert exakt den gemeldeten Vorfall: Datei enthaelt keinen
        # gueltigen JSON-Inhalt (z.B. eine Perl-Fehlermeldung statt Scan-
        # Ergebnissen), waehrend Nikto selbst eine erklaerende Meldung auf
        # stdout ausgibt.
        with open(output_path, "w") as f:
            f.write("Nikto crashed unexpectedly, no valid output produced")
        return "ERROR: Required module not found: JSON"

    stored = {}

    async def fake_set(key, value, ex=None):
        stored["value"] = json.loads(value)

    with patch.object(worker, "run_command", new=fake_run_command_no_json), patch.object(worker, "_redis") as mock_redis:
        mock_redis.set = fake_set
        job = {"job_id": "test-diag", "template": "nikto", "params": {"target": "example.com"}}
        await worker.handle_job(job)

    assert "error" in stored["value"]
    assert "Required module not found: JSON" in stored["value"]["error"]
