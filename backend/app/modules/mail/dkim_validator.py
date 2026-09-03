"""DKIM Validator: vollstaendige kryptografische DKIM-Signaturpruefung
einer kompletten E-Mail -- der eigentliche dkimvalidator.com-Nachbau.

Unterschied zum bereits vorhandenen dkim-signature-inspector: der
Inspector prueft nur eine ISOLIERT eingefuegte DKIM-Signature-Kopfzeile
strukturell (Format, DNS-Key vorhanden, abgelaufen?) OHNE echte
kryptografische Verifikation -- dafuer fehlen ihm die vollstaendigen
Kopfzeilen + der Body zur Kanonikalisierung. Dieses Tool braucht
genau das: die KOMPLETTE Roh-E-Mail (Kopfzeilen + Body, z.B. per
"Original anzeigen"/"Quelltext anzeigen" im Mail-Client abgerufen) und
verifiziert die Signatur(en) tatsaechlich kryptografisch gegen den in
DNS veroeffentlichten Public Key -- per dkimpy (RFC 6376-konforme,
etablierte Bibliothek statt eigener Krypto-Implementierung).

WICHTIG (Infrastruktur-Hinweis, wie bei den anderen Mail-Themen):
dieses Tool ersetzt NICHT dkimvalidator.com's eigentlichen Workflow
(eine E-Mail-Adresse bekommen, eine Test-Mail DORTHIN schicken, Ergebnis
automatisch sehen) -- das braeuchte einen echten SMTP-Empfangsdienst
(siehe Email-Aliase-Feature, gleiche Einschraenkung). Stattdessen: der
Nutzer schickt sich selbst eine Test-Mail, ruft deren Rohquelltext ab
und fuegt ihn hier ein -- die eigentliche kryptografische Pruefung ist
danach identisch vollstaendig.
"""

import asyncio
import io
import logging

import dkim
from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module

MAX_EMAIL_CHARS = 500_000


def _normalize_line_endings(raw: str) -> bytes:
    """E-Mails erfordern CRLF-Zeilenenden (RFC 5322) -- beim Kopieren
    aus einem Mail-Client/Browser gehen die haeufig verloren (nur LF).
    Ohne Normalisierung wuerde die Kanonikalisierung falsche Hashes
    berechnen und JEDE Signatur faelschlich als ungueltig melden."""
    normalized = raw.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\r\n")
    return normalized.encode("utf-8", errors="replace")


def _count_dkim_signatures(headers: list[tuple[bytes, bytes]]) -> int:
    return sum(1 for name, _ in headers if name.strip().lower() == b"dkim-signature")


@register_module
class DkimValidatorModule(ToolModule):
    slug = "dkim-validator"
    category = "mail"
    name = "DKIM Validator"
    description = (
        "Vollstaendige kryptografische DKIM-Signaturpruefung einer kompletten E-Mail (Rohquelltext "
        "einfuegen) -- verifiziert echt gegen den in DNS veroeffentlichten Public Key (RFC 6376, per "
        "dkimpy). Anders als der DKIM Signature Inspector (nur die isolierte Kopfzeile, keine echte "
        "Kryptopruefung) wird hier die komplette Nachricht gebraucht."
    )
    is_active_scan = False
    timeout_seconds = 15

    class Input(BaseModel):
        raw_email: str

        @field_validator("raw_email")
        @classmethod
        def validate_raw_email(cls, v: str) -> str:
            v = v.strip("\n").strip("\r")
            if not v.strip():
                raise ValueError("E-Mail-Rohquelltext darf nicht leer sein")
            if len(v) > MAX_EMAIL_CHARS:
                raise ValueError(f"Zu lang (max. {MAX_EMAIL_CHARS} Zeichen)")
            if "dkim-signature" not in v.lower():
                raise ValueError("Kein DKIM-Signature-Header gefunden -- bitte den vollstaendigen Rohquelltext der E-Mail einfuegen (inkl. Kopfzeilen).")
            return v

    class SignatureResult(BaseModel):
        index: int
        valid: bool
        domain: str | None = None
        selector: str | None = None
        algorithm: str | None = None
        key_size_bits: int | None = None
        error: str | None = None
        log: list[str] = []

    class Output(BaseModel):
        signature_count: int
        results: list["DkimValidatorModule.SignatureResult"]
        overall_valid: bool

    async def run(self, data: "DkimValidatorModule.Input") -> "DkimValidatorModule.Output":
        message_bytes = _normalize_line_endings(data.raw_email)
        # dkimpy fuehrt eigene, SYNCHRONE DNS-Abfragen intern durch --
        # in einem Thread ausfuehren, um den Event-Loop nicht zu blockieren.
        return await asyncio.to_thread(self._verify_sync, message_bytes)

    def _verify_sync(self, message_bytes: bytes) -> "DkimValidatorModule.Output":
        results: list[DkimValidatorModule.SignatureResult] = []

        try:
            probe = dkim.DKIM(message_bytes)
            sig_count = _count_dkim_signatures(probe.headers)
        except Exception as exc:  # noqa: BLE001
            return self.Output(
                signature_count=0,
                results=[self.SignatureResult(index=0, valid=False, error=f"E-Mail konnte nicht geparst werden: {exc}")],
                overall_valid=False,
            )

        if sig_count == 0:
            return self.Output(signature_count=0, results=[], overall_valid=False)

        for i in range(sig_count):
            log_buffer = io.StringIO()
            handler = logging.StreamHandler(log_buffer)
            logger = logging.getLogger(f"dkim-validator-{id(message_bytes)}-{i}")
            logger.setLevel(logging.DEBUG)
            logger.addHandler(handler)
            logger.propagate = False

            d = dkim.DKIM(message_bytes, logger=logger, timeout=self.timeout_seconds)
            try:
                valid = d.verify(idx=i)
                results.append(
                    self.SignatureResult(
                        index=i, valid=valid, domain=d.domain, selector=d.selector,
                        algorithm=d.signature_fields.get(b"a", b"").decode("ascii", errors="replace") or None,
                        key_size_bits=d.keysize or None,
                        log=[line for line in log_buffer.getvalue().splitlines() if line.strip()],
                    )
                )
            except dkim.DKIMException as exc:
                results.append(
                    self.SignatureResult(
                        index=i, valid=False, domain=d.domain, selector=d.selector, error=str(exc),
                        log=[line for line in log_buffer.getvalue().splitlines() if line.strip()],
                    )
                )
            except Exception as exc:  # noqa: BLE001
                results.append(self.SignatureResult(index=i, valid=False, error=f"Unerwarteter Fehler: {exc}"))
            finally:
                logger.removeHandler(handler)

        return self.Output(
            signature_count=sig_count, results=results,
            overall_valid=all(r.valid for r in results) and len(results) > 0,
        )
