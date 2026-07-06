import base64
import re
from datetime import datetime, timezone

from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import is_valid_hostname, query

_HASH_ALGO_LENGTHS = {"sha1": 20, "sha256": 32}


class ParsedSignature(BaseModel):
    version: str | None = None
    algorithm: str | None = None
    canonicalization: str | None = None
    domain: str | None = None
    selector: str | None = None
    signed_headers: list[str] = []
    body_hash: str | None = None
    signature: str | None = None
    signed_at: str | None = None
    expires_at: str | None = None


@register_module
class DkimSignatureInspectorModule(ToolModule):
    slug = "dkim-signature-inspector"
    category = "mail"
    name = "DKIM Signature Inspector"
    description = (
        "Zerlegt eine eingefuegte DKIM-Signature-Kopfzeile aus einer E-Mail und prueft sie strukturell "
        "gegen den in DNS veroeffentlichten Public Key. Keine vollstaendige kryptografische Pruefung "
        "(dafuer wuerde die komplette Original-E-Mail benoetigt), aber deckt Format- und "
        "Plausibilitaetsfehler ab (abgelaufene Signatur, widerrufener Key, Algorithmus-Mismatch)."
    )
    is_active_scan = False
    timeout_seconds = 8

    class Input(BaseModel):
        dkim_signature_header: str

        @field_validator("dkim_signature_header")
        @classmethod
        def validate_header(cls, v: str) -> str:
            v = v.strip()
            if not v:
                raise ValueError("DKIM-Signature-Kopfzeile darf nicht leer sein")
            if len(v) > 4000:
                raise ValueError("Kopfzeile zu lang")
            return v

    class Output(BaseModel):
        parsed: ParsedSignature
        dns_key_found: bool
        dns_key_revoked: bool = False
        dns_key_type: str | None = None
        findings: list[str] = []
        warnings: list[str] = []
        error: str | None = None

    async def run(self, data: Input) -> Output:
        raw = re.sub(r"^\s*DKIM-Signature\s*:\s*", "", data.dkim_signature_header, flags=re.IGNORECASE)
        raw = re.sub(r"\s+", " ", raw)

        tags: dict[str, str] = {}
        for part in raw.split(";"):
            part = part.strip()
            if "=" in part:
                key, _, value = part.partition("=")
                tags[key.strip()] = value.strip()

        parsed = ParsedSignature(
            version=tags.get("v"),
            algorithm=tags.get("a"),
            canonicalization=tags.get("c"),
            domain=tags.get("d"),
            selector=tags.get("s"),
            signed_headers=[h.strip() for h in tags.get("h", "").split(":") if h.strip()],
            body_hash=tags.get("bh"),
            signature=tags.get("b", "").replace(" ", "") or None,
            signed_at=self._format_timestamp(tags.get("t")),
            expires_at=self._format_timestamp(tags.get("x")),
        )

        if not parsed.domain or not parsed.selector:
            return self.Output(
                parsed=parsed, dns_key_found=False,
                error="Kopfzeile enthaelt kein 'd=' (Domain) oder 's=' (Selector) -- kein gueltiges DKIM-Signature-Format.",
            )
        if not is_valid_hostname(parsed.domain):
            return self.Output(parsed=parsed, dns_key_found=False, error=f"'{parsed.domain}' ist keine gueltige Domain.")

        findings: list[str] = []
        warnings: list[str] = []

        if tags.get("x"):
            try:
                expiry = datetime.fromtimestamp(int(tags["x"]), tz=timezone.utc)
                if expiry < datetime.now(timezone.utc):
                    warnings.append(f"Signatur ist abgelaufen (x= zeigt auf {expiry.isoformat()}).")
            except (ValueError, OSError):
                warnings.append("'x='-Zeitstempel konnte nicht gelesen werden.")

        algo_hash_part = (parsed.algorithm or "").split("-")[-1].lower()
        expected_bytes = _HASH_ALGO_LENGTHS.get(algo_hash_part)
        if parsed.body_hash and expected_bytes:
            try:
                decoded_len = len(base64.b64decode(parsed.body_hash, validate=True))
                if decoded_len != expected_bytes:
                    warnings.append(
                        f"Body-Hash hat {decoded_len} Bytes, fuer '{parsed.algorithm}' werden {expected_bytes} erwartet."
                    )
                else:
                    findings.append(f"Body-Hash-Laenge passt zu '{parsed.algorithm}'.")
            except Exception:  # noqa: BLE001
                warnings.append("'bh='-Wert ist kein gueltiges Base64.")

        if parsed.signature:
            try:
                base64.b64decode(parsed.signature, validate=True)
                findings.append("Signatur ('b=') ist syntaktisch gueltiges Base64.")
            except Exception:  # noqa: BLE001
                warnings.append("'b='-Wert ist kein gueltiges Base64.")

        name = f"{parsed.selector}._domainkey.{parsed.domain}"
        dns_result = await query(name, "TXT", timeout=self.timeout_seconds - 2)

        if not dns_result["success"] or not dns_result["records"]:
            return self.Output(
                parsed=parsed, dns_key_found=False, findings=findings, warnings=warnings,
                error=f"Kein DKIM-Key unter '{name}' gefunden -- Signatur kann nicht gegengeprueft werden.",
            )

        dns_raw = dns_result["records"][0].strip('"')
        dns_tags = dict(p.strip().split("=", 1) for p in dns_raw.split(";") if "=" in p)
        key_type = dns_tags.get("k", "rsa").strip()
        is_revoked = not dns_tags.get("p", "").strip()

        if is_revoked:
            warnings.append("Der DNS-Key ist WIDERRUFEN (leeres 'p=') -- diese Signatur kann nicht mehr gueltig sein.")
        else:
            findings.append(f"DNS-Key gefunden und aktiv (Typ: {key_type}).")

        if parsed.algorithm and key_type and key_type.lower() not in parsed.algorithm.lower():
            warnings.append(f"Signatur-Algorithmus '{parsed.algorithm}' passt nicht zum DNS-Key-Typ '{key_type}'.")

        return self.Output(
            parsed=parsed, dns_key_found=True, dns_key_revoked=is_revoked, dns_key_type=key_type,
            findings=findings, warnings=warnings, error=None,
        )

    @staticmethod
    def _format_timestamp(value: str | None) -> str | None:
        if not value:
            return None
        try:
            return datetime.fromtimestamp(int(value), tz=timezone.utc).isoformat()
        except (ValueError, OSError):
            return None
