"""Tests fuer die Client-IP-Ermittlung (app.core.audit.get_client_ip)
und die Cloudflare-Bereichs-Diagnose. Ausgangspunkt: gemeldete
Audit-Log-Eintraege mit 172.71.x.x-Adressen -- das ist Cloudflares
eigener oeffentlicher IP-Bereich (172.64.0.0/13), keine echte
Besucher-IP. Siehe docs/CADDY.md fuer die Diagnose-Anleitung.
"""

from unittest.mock import MagicMock

from app.core.audit import _looks_like_cloudflare_edge_ip, get_client_ip


def test_recognizes_cloudflare_ip_ranges():
    # Genau die in der Meldung beobachteten Adressen
    assert _looks_like_cloudflare_edge_ip("172.71.144.39") is True
    assert _looks_like_cloudflare_edge_ip("172.71.164.81") is True
    assert _looks_like_cloudflare_edge_ip("172.71.172.68") is True


def test_does_not_flag_real_residential_ips():
    # Die aelteren, korrekten Eintraege aus der Meldung
    assert _looks_like_cloudflare_edge_ip("92.209.243.126") is False
    assert _looks_like_cloudflare_edge_ip("84.39.66.171") is False


def test_does_not_flag_docker_internal_ranges():
    # RFC1918 172.16.0.0/12 (Docker-Bridge-Netze) ueberschneidet sich
    # NICHT mit Cloudflares oeffentlichem 172.64.0.0/13 -- darf also
    # nicht faelschlich als Cloudflare erkannt werden.
    assert _looks_like_cloudflare_edge_ip("172.18.0.5") is False
    assert _looks_like_cloudflare_edge_ip("172.31.255.254") is False


def test_handles_invalid_input_gracefully():
    assert _looks_like_cloudflare_edge_ip("not-an-ip") is False
    assert _looks_like_cloudflare_edge_ip("") is False


def test_cf_connecting_ip_checked_first():
    request = MagicMock()
    request.headers.get.side_effect = lambda h: {
        "cf-connecting-ip": "203.0.113.7",
        "x-real-ip": "203.0.113.99",
    }.get(h)
    assert get_client_ip(request) == "203.0.113.7"


def test_falls_back_to_x_real_ip_when_cf_header_missing():
    request = MagicMock()
    request.headers.get.side_effect = lambda h: {"x-real-ip": "203.0.113.9"}.get(h)
    assert get_client_ip(request) == "203.0.113.9"


def test_falls_back_to_x_forwarded_for_and_takes_first_hop():
    request = MagicMock()
    request.headers.get.side_effect = lambda h: {"x-forwarded-for": "203.0.113.11, 10.0.0.1, 10.0.0.2"}.get(h)
    assert get_client_ip(request) == "203.0.113.11"


def test_falls_back_to_raw_peer_when_no_headers_present():
    request = MagicMock()
    request.headers.get.return_value = None
    request.client.host = "172.18.0.7"
    assert get_client_ip(request) == "172.18.0.7"


def test_returns_none_when_nothing_available():
    request = MagicMock()
    request.headers.get.return_value = None
    request.client = None
    assert get_client_ip(request) is None
