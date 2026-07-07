"""Tests fuer die Nikto-Integration im Scanner-Container: festes
Argument-Template (keine frei waehlbaren Flags) und JSON-Parsing.
Eigenstaendige Tests, da der Scanner-Container eine eigene, von der
Haupt-Backend-Suite getrennte Python-Umgebung ist.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.templates import TEMPLATES, InvalidJobError  # noqa: E402
from app.nikto_parser import parse_nikto_json  # noqa: E402


def test_nikto_template_builds_fixed_arguments():
    args = TEMPLATES["nikto"]({"target": "example.com"})
    assert args[0] == "nikto"
    assert "-h" in args and "example.com" in args
    assert "-Format" in args and "json" in args


def test_nikto_template_rejects_invalid_target():
    with pytest.raises(InvalidJobError):
        TEMPLATES["nikto"]({"target": "; rm -rf /"})


def test_nikto_template_rejects_flag_injection_attempt():
    with pytest.raises(InvalidJobError):
        TEMPLATES["nikto"]({"target": "example.com --script=evil"})


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
