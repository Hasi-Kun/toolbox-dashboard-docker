"""Tests fuer die Netzwerk-Module. Ping/Traceroute/Port-Check wurden vorab
manuell gegen echte lokale Prozesse/Sockets verifiziert (siehe Kommentare);
hier wird vor allem die Validierungslogik und das Parsing pruefbar
abgedeckt, ohne bei jedem Testlauf echte Subprozesse zu benoetigen.
"""

import pytest
from pydantic import ValidationError

from app.modules.network.ping import PingModule
from app.modules.network.port_check import MAX_PORTS, PortCheckModule
from app.modules.network.traceroute import _HOP_RE
from app.modules.network.whois import _FIELD_PATTERNS


def test_ping_count_is_clamped_between_1_and_10():
    assert PingModule.Input(host="127.0.0.1", count=0).count == 1
    assert PingModule.Input(host="127.0.0.1", count=500).count == 10
    assert PingModule.Input(host="127.0.0.1", count=4).count == 4


def test_ping_rejects_invalid_host():
    with pytest.raises(ValidationError):
        PingModule.Input(host="not a host; rm -rf /", count=4)


def test_port_check_rejects_too_many_ports():
    with pytest.raises(ValidationError):
        PortCheckModule.Input(host="127.0.0.1", ports=list(range(1, MAX_PORTS + 2)))


def test_port_check_rejects_out_of_range_port():
    with pytest.raises(ValidationError):
        PortCheckModule.Input(host="127.0.0.1", ports=[70000])
    with pytest.raises(ValidationError):
        PortCheckModule.Input(host="127.0.0.1", ports=[0])


def test_port_check_requires_at_least_one_port():
    with pytest.raises(ValidationError):
        PortCheckModule.Input(host="127.0.0.1", ports=[])


def test_port_check_accepts_valid_input():
    data = PortCheckModule.Input(host="127.0.0.1", ports=[22, 80, 443])
    assert data.ports == [22, 80, 443]


def test_traceroute_hop_regex_matches_real_output():
    # Echte Ausgabe von `traceroute -m 3 -w 1 -q 1 127.0.0.1` (manuell verifiziert)
    sample = (
        "traceroute to 127.0.0.1 (127.0.0.1), 3 hops max, 60 byte packets\n"
        " 1  localhost (127.0.0.1)  0.024 ms\n"
    )
    matches = list(_HOP_RE.finditer(sample))
    assert len(matches) == 1
    assert matches[0].group(1) == "1"
    assert "127.0.0.1" in matches[0].group(2)
    assert matches[0].group(3) == "0.024"


def test_whois_field_patterns_match_real_output():
    # Realistisches WHOIS-Format (RDAP-Style, wie es viele .com-Registries liefern)
    sample = (
        "Domain Name: EXAMPLE.COM\n"
        "Registrar: RESERVED-Internet Assigned Numbers Authority\n"
        "Creation Date: 1995-08-14T04:00:00Z\n"
        "Registry Expiry Date: 2026-08-13T04:00:00Z\n"
        "Name Server: A.IANA-SERVERS.NET\n"
        "Name Server: B.IANA-SERVERS.NET\n"
    )
    assert _FIELD_PATTERNS["registrar"].search(sample).group(1) == "RESERVED-Internet Assigned Numbers Authority"
    assert _FIELD_PATTERNS["creation_date"].search(sample).group(1) == "1995-08-14T04:00:00Z"
    assert _FIELD_PATTERNS["expiry_date"].search(sample).group(1) == "2026-08-13T04:00:00Z"
    name_servers = [m.group(1) for m in _FIELD_PATTERNS["name_servers"].finditer(sample)]
    assert name_servers == ["A.IANA-SERVERS.NET", "B.IANA-SERVERS.NET"]


@pytest.mark.asyncio
async def test_port_check_detects_open_and_closed_ports_on_loopback():
    """Echter End-to-End-Test ueber Loopback -- kein Mock, kein externes Netzwerk."""
    import asyncio

    server = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    try:
        module = PortCheckModule()
        result = await module.run(PortCheckModule.Input(host="127.0.0.1", ports=[port]))
        assert result.results[0].status == "open"
    finally:
        server.close()

    # Ohne Server dahinter sollte derselbe Port jetzt als geschlossen gelten
    result = await module.run(PortCheckModule.Input(host="127.0.0.1", ports=[port]))
    assert result.results[0].status == "closed"
