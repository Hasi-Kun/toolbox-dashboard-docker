"""Tests fuer die testssl.sh-Integration im Scanner-Container: festes
Argument-Template (keine frei waehlbaren Flags), flaches JSON-Parsing,
und der komplette Worker-Durchlauf inkl. Temp-Datei-Aufraeumen.
"""

import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.templates import TEMPLATES, InvalidJobError  # noqa: E402
from app.testssl_parser import parse_testssl_json  # noqa: E402


SAMPLE_TESTSSL_JSON = json.dumps([
    {"id": "SSLv3", "ip": "93.184.216.34/93.184.216.34", "port": "443", "severity": "OK", "finding": "not offered"},
    {"id": "TLS1", "ip": "93.184.216.34/93.184.216.34", "port": "443", "severity": "INFO", "finding": "not offered"},
    {"id": "TLS1_2", "ip": "93.184.216.34/93.184.216.34", "port": "443", "severity": "OK", "finding": "offered (OK)"},
    {"id": "heartbleed", "ip": "93.184.216.34/93.184.216.34", "port": "443", "severity": "OK",
     "cve": "CVE-2014-0160", "finding": "not vulnerable (OK) (no heartbeat extension)"},
    {"id": "ROBOT", "ip": "93.184.216.34/93.184.216.34", "port": "443", "severity": "HIGH",
     "cve": "CVE-2017-13099", "finding": "VULNERABLE (NOT ok)"},
])


def test_testssl_template_builds_fixed_arguments():
    args = TEMPLATES["testssl"]({"target": "example.com", "_output_path": "/tmp/testssl_test.json"})
    assert args[0].endswith("testssl.sh")
    assert "--jsonfile" in args and "/tmp/testssl_test.json" in args
    assert "example.com:443" in args


def test_testssl_template_uses_custom_port():
    args = TEMPLATES["testssl"]({"target": "example.com", "port": 8443, "_output_path": "/tmp/x.json"})
    assert "example.com:8443" in args


def test_testssl_template_rejects_invalid_target():
    with pytest.raises(InvalidJobError):
        TEMPLATES["testssl"]({"target": "; rm -rf /", "_output_path": "/tmp/x.json"})


def test_testssl_template_rejects_invalid_port():
    with pytest.raises(InvalidJobError):
        TEMPLATES["testssl"]({"target": "example.com", "port": 99999, "_output_path": "/tmp/x.json"})


def test_testssl_template_requires_output_path():
    with pytest.raises(InvalidJobError):
        TEMPLATES["testssl"]({"target": "example.com"})


def test_testssl_template_uses_real_file_path_not_dash():
    args = TEMPLATES["testssl"]({"target": "example.com", "_output_path": "/tmp/testssl_test.json"})
    output_index = args.index("--jsonfile")
    assert args[output_index + 1] == "/tmp/testssl_test.json"
    assert args[output_index + 1] != "-"


def test_testssl_json_parser_extracts_findings_and_vulnerabilities():
    result = parse_testssl_json(SAMPLE_TESTSSL_JSON)
    assert result["target"] == "93.184.216.34/93.184.216.34"
    assert len(result["findings"]) == 5
    assert len(result["vulnerabilities"]) == 2

    robot = next(v for v in result["vulnerabilities"] if v["id"] == "ROBOT")
    assert robot["vulnerable"] is True
    heartbleed = next(v for v in result["vulnerabilities"] if v["id"] == "heartbleed")
    assert heartbleed["vulnerable"] is False


def test_testssl_json_parser_severity_counts():
    result = parse_testssl_json(SAMPLE_TESTSSL_JSON)
    assert result["severity_counts"]["OK"] == 3
    assert result["severity_counts"]["INFO"] == 1
    assert result["severity_counts"]["HIGH"] == 1


def test_testssl_json_parser_handles_empty_output():
    result = parse_testssl_json("")
    assert result["findings"] == []
    assert result["vulnerabilities"] == []


def test_testssl_json_parser_rejects_garbage_input():
    with pytest.raises(ValueError):
        parse_testssl_json("this is not json at all <<<")


def test_testssl_json_parser_rejects_non_array_json():
    with pytest.raises(ValueError):
        parse_testssl_json('{"not": "an array"}')


@pytest.mark.asyncio
async def test_handle_job_writes_reads_and_cleans_up_testssl_temp_file():
    """End-to-End-Regressionstest: simuliert einen erfolgreichen testssl.sh-
    Lauf (schreibt JSON in die uebergebene Ausgabedatei) und prueft, dass
    das Ergebnis korrekt geparst UND die temporaere Datei danach
    garantiert geloescht wird."""
    from unittest.mock import patch
    import app.worker as worker

    async def fake_run_command(args, timeout, cwd=None):
        output_path = args[args.index("--jsonfile") + 1]
        with open(output_path, "w") as f:
            f.write(SAMPLE_TESTSSL_JSON)
        return ""

    stored = {}

    async def fake_set(key, value, ex=None):
        stored["value"] = json.loads(value)

    with patch.object(worker, "run_command", new=fake_run_command), patch.object(worker, "_redis") as mock_redis:
        mock_redis.set = fake_set
        job = {"job_id": "test-testssl-e2e", "template": "testssl", "params": {"target": "example.com"}}
        await worker.handle_job(job)

    assert len(stored["value"]["vulnerabilities"]) == 2

    leftover = [f for f in os.listdir(tempfile.gettempdir()) if f.startswith("testssl_")]
    assert leftover == [], f"Verbliebene temporaere Dateien: {leftover}"


@pytest.mark.asyncio
async def test_handle_job_cleans_up_testssl_temp_file_even_on_failure():
    from unittest.mock import patch
    import app.worker as worker

    async def failing_run_command(args, timeout, cwd=None):
        raise RuntimeError("Simulierter Absturz")

    stored = {}

    async def fake_set(key, value, ex=None):
        stored["value"] = json.loads(value)

    with patch.object(worker, "run_command", new=failing_run_command), patch.object(worker, "_redis") as mock_redis:
        mock_redis.set = fake_set
        job = {"job_id": "test-testssl-fail", "template": "testssl", "params": {"target": "example.com"}}
        await worker.handle_job(job)

    assert "error" in stored["value"]
    leftover = [f for f in os.listdir(tempfile.gettempdir()) if f.startswith("testssl_")]
    assert leftover == [], f"Verbliebene temporaere Dateien nach Fehler: {leftover}"


@pytest.mark.asyncio
async def test_handle_job_includes_console_output_when_testssl_parsing_fails():
    from unittest.mock import patch
    import app.worker as worker

    async def fake_run_command_no_json(args, timeout, cwd=None):
        output_path = args[args.index("--jsonfile") + 1]
        with open(output_path, "w") as f:
            f.write("not valid json at all")
        return "Fatal error: could not connect"

    stored = {}

    async def fake_set(key, value, ex=None):
        stored["value"] = json.loads(value)

    with patch.object(worker, "run_command", new=fake_run_command_no_json), patch.object(worker, "_redis") as mock_redis:
        mock_redis.set = fake_set
        job = {"job_id": "test-testssl-diag", "template": "testssl", "params": {"target": "example.com"}}
        await worker.handle_job(job)

    assert "error" in stored["value"]
    assert "could not connect" in stored["value"]["error"]
