"""Tests fuer die Nikto-Integration im Scanner-Container: festes
Argument-Template (keine frei waehlbaren Flags) und XML-Parsing.

Auf XML umgestellt (statt JSON) nach drei erfolglosen Anlaeufen mit
Niktos JSON-Report-Plugin -- siehe nikto_parser.py fuer die ausfuehrliche
Begruendung. Eigenstaendige Tests, da der Scanner-Container eine eigene,
von der Haupt-Backend-Suite getrennte Python-Umgebung ist.
"""

import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.templates import TEMPLATES, InvalidJobError  # noqa: E402
from app.nikto_parser import parse_nikto_xml  # noqa: E402


SAMPLE_XML = """<?xml version="1.0" ?>
<!DOCTYPE niktoscan SYSTEM "/usr/share/doc/nikto/nikto.dtd">
<niktoscan hoststest="0" options="-h example.com -output x.xml" version="2.5.0" scanstart="Mon Jan 1 00:00:00 2026" scanend="Mon Jan 1 00:01:00 2026" scanelapsed=" 60 seconds" nxmlversion="1.2">
<scandetails targetip="93.184.216.34" targethostname="example.com" targetport="80" targetbanner="Apache/2.4.41" starttime="2026-01-01 00:00:00" sitename="http://example.com:80/" siteip="http://93.184.216.34:80/" hostheader="example.com" errors="0" checks="4587">
<item id="999986" osvdbid="0" osvdblink="http://osvdb.org/0" method="GET">
<description><![CDATA[Admin login page found]]></description>
<uri><![CDATA[/admin/]]></uri>
<namelink><![CDATA[http://example.com/admin/]]></namelink>
<iplink><![CDATA[http://93.184.216.34/admin/]]></iplink>
</item>
<item id="999987" osvdbid="0" osvdblink="http://osvdb.org/0" method="GET">
<description><![CDATA[Git repository exposed]]></description>
<uri><![CDATA[/.git/]]></uri>
<namelink><![CDATA[http://example.com/.git/]]></namelink>
<iplink><![CDATA[http://93.184.216.34/.git/]]></iplink>
</item>
</scandetails>
</niktoscan>
"""

# Reproduziert den bekannten Bug (GitHub-Issue #670): das Wurzelelement
# kann DOPPELT verschachtelt sein.
SAMPLE_XML_DOUBLE_WRAPPED = f"""<?xml version="1.0" ?>
<niktoscan>
{SAMPLE_XML.split('?>', 1)[1]}
</niktoscan>
"""


def test_nikto_template_builds_fixed_arguments():
    args = TEMPLATES["nikto"]({"target": "example.com", "_output_path": "/tmp/nikto_test.xml"})
    assert args[0].endswith("nikto.pl")
    assert "-h" in args and "example.com" in args
    assert "-Format" in args and "xml" in args


def test_nikto_template_rejects_invalid_target():
    with pytest.raises(InvalidJobError):
        TEMPLATES["nikto"]({"target": "; rm -rf /", "_output_path": "/tmp/x.xml"})


def test_nikto_template_rejects_flag_injection_attempt():
    with pytest.raises(InvalidJobError):
        TEMPLATES["nikto"]({"target": "example.com --script=evil", "_output_path": "/tmp/x.xml"})


def test_nikto_template_requires_output_path():
    with pytest.raises(InvalidJobError):
        TEMPLATES["nikto"]({"target": "example.com"})


def test_nikto_template_uses_real_file_path_not_dash():
    args = TEMPLATES["nikto"]({"target": "example.com", "_output_path": "/tmp/nikto_test.xml"})
    output_index = args.index("-output")
    assert args[output_index + 1] == "/tmp/nikto_test.xml"
    assert args[output_index + 1] != "-"


def test_nikto_xml_parser_extracts_findings():
    result = parse_nikto_xml(SAMPLE_XML)
    assert result["host"] == "example.com"
    assert result["ip"] == "93.184.216.34"
    assert result["port"] == "80"
    assert result["banner"] == "Apache/2.4.41"
    assert result["finding_count"] == 2
    assert result["findings"][1]["url"] == "/.git/"
    assert result["findings"][0]["message"] == "Admin login page found"


def test_nikto_xml_parser_handles_empty_output():
    result = parse_nikto_xml("")
    assert result["findings"] == []


def test_nikto_xml_parser_handles_double_wrapped_root():
    """Regressionstest fuer den bekannten Nikto-Bug (Issue #670): das
    <niktoscan>-Wurzelelement kann doppelt verschachtelt sein. Der
    Parser muss trotzdem die Ergebnisse finden."""
    result = parse_nikto_xml(SAMPLE_XML_DOUBLE_WRAPPED)
    assert result["host"] == "example.com"
    assert result["finding_count"] == 2


def test_nikto_xml_parser_rejects_garbage_input():
    with pytest.raises(ValueError):
        parse_nikto_xml("this is not xml at all <<<")


@pytest.mark.asyncio
async def test_handle_job_writes_reads_and_cleans_up_temp_file(tmp_path, monkeypatch):
    """End-to-End-Regressionstest: simuliert einen erfolgreichen Nikto-
    Lauf (schreibt XML in die uebergebene Ausgabedatei) und prueft, dass
    das Ergebnis korrekt geparst UND die temporaere Datei danach
    garantiert geloescht wird.
    """
    from unittest.mock import patch
    import app.worker as worker

    async def fake_run_command(args, timeout, cwd=None):
        output_path = args[args.index("-output") + 1]
        with open(output_path, "w") as f:
            f.write(SAMPLE_XML)
        return ""

    stored = {}

    async def fake_set(key, value, ex=None):
        stored["value"] = json.loads(value)

    with patch.object(worker, "run_command", new=fake_run_command), patch.object(worker, "_redis") as mock_redis:
        mock_redis.set = fake_set
        job = {"job_id": "test-e2e", "template": "nikto", "params": {"target": "example.com"}}
        await worker.handle_job(job)

    assert stored["value"]["host"] == "example.com"
    assert stored["value"]["finding_count"] == 2

    leftover = [f for f in os.listdir(tempfile.gettempdir()) if f.startswith("nikto_")]
    assert leftover == [], f"Verbliebene temporaere Dateien: {leftover}"


@pytest.mark.asyncio
async def test_handle_job_cleans_up_temp_file_even_on_failure():
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
async def test_handle_job_includes_console_output_in_error_when_xml_parsing_fails():
    """Falls die XML-Ausgabe trotzdem einmal nicht geparst werden kann,
    soll die Fehlermeldung Niktos tatsaechliche Konsolenausgabe enthalten."""
    from unittest.mock import patch
    import app.worker as worker

    async def fake_run_command_no_xml(args, timeout, cwd=None):
        output_path = args[args.index("-output") + 1]
        with open(output_path, "w") as f:
            f.write("not valid xml at all")
        return "ERROR: something went wrong internally"

    stored = {}

    async def fake_set(key, value, ex=None):
        stored["value"] = json.loads(value)

    with patch.object(worker, "run_command", new=fake_run_command_no_xml), patch.object(worker, "_redis") as mock_redis:
        mock_redis.set = fake_set
        job = {"job_id": "test-diag", "template": "nikto", "params": {"target": "example.com"}}
        await worker.handle_job(job)

    assert "error" in stored["value"]
    assert "something went wrong internally" in stored["value"]["error"]
