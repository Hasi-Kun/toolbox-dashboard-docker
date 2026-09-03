"""Tests fuer den Domain-Security-Check (BSI-orientierte, aggregierte
Bewertung ueber mehrere bestehende Tools). Mockt die aufgerufenen
Sub-Module direkt, um NUR die Aggregations-/Bewertungslogik zu testen --
die Sub-Module selbst haben bereits eigene Tests.
"""

from unittest.mock import AsyncMock, patch

import pytest


def _make_spf_output(found=True, qualifier="-all"):
    from app.modules.mail.spf import SpfCheckModule
    return SpfCheckModule.Output(
        domain="example.com", found=found, raw_record="v=spf1 -all" if found else None,
        mechanisms=[], lookup_count=1, catch_all_qualifier=qualifier if found else None,
        catch_all_severity=None, warnings=[], error=None,
    )


def _make_dkim_output(found=True):
    from app.modules.mail.dkim import DkimCheckModule, DkimSelectorResult
    results = [DkimSelectorResult(selector="default", found=found, raw_record=None, key_type="rsa", public_key_present=found)]
    return DkimCheckModule.Output(domain="example.com", selectors_checked=["default"], results=results, found_any=found)


def _make_dmarc_output(found=True, policy="reject", rua=True, ruf=False):
    from app.modules.mail.dmarc import DmarcCheckModule
    score, label = DmarcCheckModule._compute_strength(policy if found else None, 100, rua)
    return DmarcCheckModule.Output(
        domain="example.com", found=found, raw_record=None, policy=policy if found else None,
        subdomain_policy=policy if found else None, percentage=100 if found else None,
        aggregate_reports=["mailto:rua@example.com"] if rua else [],
        forensic_reports=["mailto:ruf@example.com"] if ruf else [],
        warnings=[], strength_score=score, strength_label=label, error=None,
    )


def _make_dane_output(found=True):
    from app.modules.mail.dane_check import DaneCheckModule
    return DaneCheckModule.Output(domain="example.com", port=25, found=found, records=[], warnings=[])


def _make_tls_output(risk="niedrig", success=True):
    from app.modules.security.tls_cipher_audit import TlsCipherAuditModule
    return TlsCipherAuditModule.Output(host="example.com", port=443, success=success, protocols=[], overall_risk=risk if success else None, error=None if success else "Fehler")


def _make_headers_output(score=90, max_score=100, grade="A"):
    from app.modules.security.headers import SecurityHeadersModule
    return SecurityHeadersModule.Output(domain="example.com", success=True, status_code=200, score=score, max_score=max_score, grade=grade, present_headers={}, missing_headers=[], warnings=[])


@pytest.mark.asyncio
async def test_strong_domain_gets_high_score():
    from app.modules.security.domain_security_check import DomainSecurityCheckModule, CategoryResult

    module = DomainSecurityCheckModule()
    dnssec_ok = CategoryResult(category="DNSSEC", score=100, status="bestanden", details=[])

    with patch("app.modules.security.domain_security_check.SpfCheckModule.run", new=AsyncMock(return_value=_make_spf_output(True, "-all"))), \
         patch("app.modules.security.domain_security_check.DkimCheckModule.run", new=AsyncMock(return_value=_make_dkim_output(True))), \
         patch("app.modules.security.domain_security_check.DmarcCheckModule.run", new=AsyncMock(return_value=_make_dmarc_output(True, "reject", rua=True, ruf=False))), \
         patch("app.modules.security.domain_security_check.DaneCheckModule.run", new=AsyncMock(return_value=_make_dane_output(True))), \
         patch("app.modules.security.domain_security_check.TlsCipherAuditModule.run", new=AsyncMock(return_value=_make_tls_output("niedrig"))), \
         patch("app.modules.security.domain_security_check.SecurityHeadersModule.run", new=AsyncMock(return_value=_make_headers_output(95, 100, "A+"))), \
         patch.object(DomainSecurityCheckModule, "_score_dnssec", new=AsyncMock(return_value=dnssec_ok)):
        result = await module.run(DomainSecurityCheckModule.Input(domain="example.com"))

    assert result.overall_grade in ("A", "B")
    assert result.overall_score >= 75


@pytest.mark.asyncio
async def test_weak_domain_gets_low_score():
    from app.modules.security.domain_security_check import DomainSecurityCheckModule

    module = DomainSecurityCheckModule()
    with patch("app.modules.security.domain_security_check.SpfCheckModule.run", new=AsyncMock(return_value=_make_spf_output(False))), \
         patch("app.modules.security.domain_security_check.DkimCheckModule.run", new=AsyncMock(return_value=_make_dkim_output(False))), \
         patch("app.modules.security.domain_security_check.DmarcCheckModule.run", new=AsyncMock(return_value=_make_dmarc_output(False))), \
         patch("app.modules.security.domain_security_check.DaneCheckModule.run", new=AsyncMock(return_value=_make_dane_output(False))), \
         patch("app.modules.security.domain_security_check.TlsCipherAuditModule.run", new=AsyncMock(return_value=_make_tls_output(success=False))), \
         patch("app.modules.security.domain_security_check.SecurityHeadersModule.run", new=AsyncMock(return_value=_make_headers_output(10, 100, "F"))):
        result = await module.run(DomainSecurityCheckModule.Input(domain="weak-example.com"))

    assert result.overall_grade in ("D", "F")


@pytest.mark.asyncio
async def test_spf_softfail_scores_lower_than_hardfail():
    from app.modules.security.domain_security_check import DomainSecurityCheckModule

    module = DomainSecurityCheckModule()
    with patch("app.modules.security.domain_security_check.SpfCheckModule.run", new=AsyncMock(return_value=_make_spf_output(True, "-all"))):
        hard_result = await module._score_spf("example.com")
    with patch("app.modules.security.domain_security_check.SpfCheckModule.run", new=AsyncMock(return_value=_make_spf_output(True, "~all"))):
        soft_result = await module._score_spf("example.com")
    with patch("app.modules.security.domain_security_check.SpfCheckModule.run", new=AsyncMock(return_value=_make_spf_output(True, "?all"))):
        neutral_result = await module._score_spf("example.com")

    assert hard_result.score > soft_result.score > neutral_result.score


@pytest.mark.asyncio
async def test_dmarc_penalizes_missing_rua():
    from app.modules.security.domain_security_check import DomainSecurityCheckModule

    module = DomainSecurityCheckModule()
    with patch("app.modules.security.domain_security_check.DmarcCheckModule.run", new=AsyncMock(return_value=_make_dmarc_output(True, "reject", rua=True))):
        with_rua = await module._score_dmarc("example.com")
    with patch("app.modules.security.domain_security_check.DmarcCheckModule.run", new=AsyncMock(return_value=_make_dmarc_output(True, "reject", rua=False))):
        without_rua = await module._score_dmarc("example.com")

    assert with_rua.score > without_rua.score


@pytest.mark.asyncio
async def test_dmarc_penalizes_ruf_presence_per_bsi_privacy_guidance():
    from app.modules.security.domain_security_check import DomainSecurityCheckModule

    module = DomainSecurityCheckModule()
    with patch("app.modules.security.domain_security_check.DmarcCheckModule.run", new=AsyncMock(return_value=_make_dmarc_output(True, "reject", rua=True, ruf=False))):
        without_ruf = await module._score_dmarc("example.com")
    with patch("app.modules.security.domain_security_check.DmarcCheckModule.run", new=AsyncMock(return_value=_make_dmarc_output(True, "reject", rua=True, ruf=True))):
        with_ruf = await module._score_dmarc("example.com")

    assert without_ruf.score > with_ruf.score
    assert any("DSGVO" in d for d in with_ruf.details)


def test_domain_security_check_registered():
    from app.modules import get_registry

    assert "domain-security-check" in get_registry()


@pytest.mark.asyncio
async def test_spf_message_never_double_appends_all():
    """Regressionstest fuer den gemeldeten Bug: die Fehlermeldung zeigte
    faelschlich 'Qualifier -allall' statt '-all', weil catch_all_qualifier
    (von spf.py) bereits den VOLLSTAENDIGEN String liefert, hier aber
    zusaetzlich nochmal 'all' angehaengt wurde."""
    from app.modules.security.domain_security_check import DomainSecurityCheckModule

    module = DomainSecurityCheckModule()
    for qualifier in ("-all", "~all", "?all", "+all"):
        with patch(
            "app.modules.security.domain_security_check.SpfCheckModule.run",
            new=AsyncMock(return_value=_make_spf_output(True, qualifier)),
        ):
            result = await module._score_spf("example.com")
        detail_text = " ".join(result.details)
        assert "allall" not in detail_text, f"Doppeltes 'all' fuer Qualifier {qualifier!r}: {detail_text}"


@pytest.mark.asyncio
async def test_spf_missing_all_mechanism_handled_without_crashing():
    """catch_all_qualifier kann auch None sein (kein 'all'-Mechanismus
    im Record) -- durfte vorher zu 'Qualifier Noneall' fuehren."""
    from app.modules.security.domain_security_check import DomainSecurityCheckModule

    module = DomainSecurityCheckModule()
    with patch(
        "app.modules.security.domain_security_check.SpfCheckModule.run",
        new=AsyncMock(return_value=_make_spf_output(True, None)),
    ):
        result = await module._score_spf("example.com")
    detail_text = " ".join(result.details)
    assert "None" not in detail_text
