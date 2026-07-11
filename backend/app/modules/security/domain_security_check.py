"""Kombinierte Domain-Sicherheitsbewertung -- ruft mehrere bereits
vorhandene Einzel-Tools auf (SPF, DKIM, DMARC, DANE, TLS, Security-
Header, DNSSEC-Praesenz) und aggregiert sie zu einem Gesamt-Score.

Orientiert an den Kriterien aus BSI TR-03108 ("Sicherer E-Mail-
Transport") und TR-03182 ("E-Mail-Authentifizierung"):
- SPF muss HardFail (-all) oder SoftFail (~all) nutzen, nicht
  Neutral/Pass (?all/+all) -- laut BSI schuetzen letztere nicht.
- DMARC-Policy muss reject oder quarantine sein (nicht none), braucht
  mindestens eine RUA-Adresse; von RUF (Forensic Reports) raet das BSI
  wegen der darin enthaltenen personenbezogenen Daten (DSGVO) ab.
- DANE/TLSA fuer den Mailtransport wird von TR-03108 empfohlen.

Kein Ersatz fuer eine formale BSI-Zertifizierung -- eine informelle,
automatisierte Annaeherung an die oeffentlich dokumentierten Kriterien.
"""

import asyncio

import dns.asyncresolver
import dns.exception
from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import is_valid_hostname
from app.modules.mail.dane_check import DaneCheckModule
from app.modules.mail.dkim import DkimCheckModule
from app.modules.mail.dmarc import DmarcCheckModule
from app.modules.mail.spf import SpfCheckModule
from app.modules.security.headers import SecurityHeadersModule
from app.modules.security.tls_cipher_audit import TlsCipherAuditModule


class CategoryResult(BaseModel):
    category: str
    score: int
    status: str  # "bestanden" | "warnung" | "fehlt"
    details: list[str] = []


def _grade_from_score(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


@register_module
class DomainSecurityCheckModule(ToolModule):
    slug = "domain-security-check"
    category = "security"
    name = "Domain-Security-Check (BSI-orientiert)"
    description = (
        "Kombinierte Sicherheitsbewertung einer Domain -- SPF/DKIM/DMARC/DANE-E-Mail-Sicherheit "
        "(orientiert an BSI TR-03108/TR-03182), TLS-Konfiguration, Security-Header und DNSSEC-Praesenz. "
        "Ergebnis als Gesamt-Note (A-F) mit Einzelbewertung je Kategorie. Kein Ersatz fuer eine formale "
        "BSI-Zertifizierung."
    )
    is_active_scan = False
    timeout_seconds = 45

    class Input(BaseModel):
        domain: str

        @field_validator("domain")
        @classmethod
        def validate_domain(cls, v: str) -> str:
            v = v.strip().rstrip(".")
            if not is_valid_hostname(v):
                raise ValueError("Ungueltige Domain")
            return v

    class Output(BaseModel):
        domain: str
        overall_score: int
        overall_grade: str
        categories: list[CategoryResult]
        error: str | None = None

    async def _score_spf(self, domain: str) -> CategoryResult:
        result = await SpfCheckModule().run(SpfCheckModule.Input(domain=domain))
        if not result.found:
            return CategoryResult(category="SPF", score=0, status="fehlt", details=["Kein SPF-Record gefunden."])

        qualifier = result.catch_all_qualifier
        if qualifier == "-":
            return CategoryResult(category="SPF", score=100, status="bestanden", details=["HardFail (-all) -- entspricht BSI-Empfehlung."])
        if qualifier == "~":
            return CategoryResult(category="SPF", score=70, status="warnung", details=["SoftFail (~all) -- von BSI akzeptiert, HardFail waere staerker."])
        return CategoryResult(
            category="SPF", score=20, status="warnung",
            details=[f"Qualifier '{qualifier}all' bietet laut BSI keinen ausreichenden Schutz (nur -all/~all empfohlen)."],
        )

    async def _score_dkim(self, domain: str) -> CategoryResult:
        result = await DkimCheckModule().run(DkimCheckModule.Input(domain=domain))
        if result.found_any:
            found_selector = next((r.selector for r in result.results if r.found), "?")
            return CategoryResult(category="DKIM", score=100, status="bestanden", details=[f"DKIM-Selector '{found_selector}' gefunden."])
        return CategoryResult(category="DKIM", score=0, status="fehlt", details=["Kein DKIM-Record ueber die gaengigen Selector-Namen gefunden."])

    async def _score_dmarc(self, domain: str) -> CategoryResult:
        result = await DmarcCheckModule().run(DmarcCheckModule.Input(domain=domain))
        if not result.found:
            return CategoryResult(category="DMARC", score=0, status="fehlt", details=["Kein DMARC-Record gefunden."])

        details = [f"Policy: {result.policy}"]
        score = result.strength_score

        if not result.aggregate_reports:
            score = max(0, score - 15)
            details.append("Keine RUA-Adresse -- BSI verlangt mindestens eine Aggregate-Report-Adresse.")
        if result.forensic_reports:
            score = max(0, score - 10)
            details.append("RUF (Forensic Reports) konfiguriert -- BSI raet davon wegen personenbezogener Daten in den Berichten (DSGVO) ab.")

        status = "bestanden" if score >= 75 else "warnung"
        return CategoryResult(category="DMARC", score=score, status=status, details=details)

    async def _score_dane(self, domain: str) -> CategoryResult:
        result = await DaneCheckModule().run(DaneCheckModule.Input(domain=domain, port=25))
        if result.found:
            return CategoryResult(category="DANE (Mailtransport)", score=100, status="bestanden", details=["TLSA-Record fuer den Mailtransport gefunden."])
        return CategoryResult(
            category="DANE (Mailtransport)", score=50, status="warnung",
            details=["Kein TLSA-Record -- DANE ist laut TR-03108 empfohlen, aber noch nicht flaechendeckend Pflicht."],
        )

    async def _score_tls(self, domain: str) -> CategoryResult:
        result = await TlsCipherAuditModule().run(TlsCipherAuditModule.Input(host=domain, port=443))
        if not result.success:
            return CategoryResult(category="TLS-Konfiguration", score=0, status="fehlt", details=[result.error or "TLS-Verbindung fehlgeschlagen."])

        risk_to_score = {"niedrig": 100, "mittel": 60, "hoch": 20}
        score = risk_to_score.get(result.overall_risk or "hoch", 20)
        status = "bestanden" if score >= 75 else "warnung"
        return CategoryResult(category="TLS-Konfiguration", score=score, status=status, details=[f"Risiko-Einstufung: {result.overall_risk}"])

    async def _score_headers(self, domain: str) -> CategoryResult:
        result = await SecurityHeadersModule().run(SecurityHeadersModule.Input(domain=domain))
        if not result.success or result.score is None:
            return CategoryResult(category="Security-Header", score=0, status="fehlt", details=[result.error or "Konnte nicht geprueft werden."])

        percent_score = round((result.score / result.max_score) * 100)
        status = "bestanden" if percent_score >= 75 else "warnung"
        return CategoryResult(category="Security-Header", score=percent_score, status=status, details=[f"Note: {result.grade}"])

    async def _score_dnssec(self, domain: str) -> CategoryResult:
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            await resolver.resolve(domain, "DNSKEY")
            return CategoryResult(category="DNSSEC", score=100, status="bestanden", details=["DNSKEY-Record gefunden -- DNSSEC ist wahrscheinlich aktiv."])
        except (dns.exception.DNSException, Exception):  # noqa: BLE001
            return CategoryResult(
                category="DNSSEC", score=50, status="warnung",
                details=["Kein DNSKEY-Record gefunden -- DNSSEC scheint nicht aktiv (reine Praesenzpruefung, keine vollstaendige Validierung)."],
            )

    async def run(self, data: Input) -> Output:
        try:
            results = await asyncio.gather(
                self._score_spf(data.domain),
                self._score_dkim(data.domain),
                self._score_dmarc(data.domain),
                self._score_dane(data.domain),
                self._score_tls(data.domain),
                self._score_headers(data.domain),
                self._score_dnssec(data.domain),
            )
        except Exception as exc:  # noqa: BLE001
            return self.Output(domain=data.domain, overall_score=0, overall_grade="F", categories=[], error=str(exc))

        overall_score = round(sum(c.score for c in results) / len(results))
        return self.Output(
            domain=data.domain, overall_score=overall_score,
            overall_grade=_grade_from_score(overall_score), categories=list(results),
        )
