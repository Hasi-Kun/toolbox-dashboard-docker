import asyncio
import re
from datetime import datetime, timezone

from cryptography import x509
from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import is_valid_hostname, is_valid_ip

_CERT_BLOCK_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL
)


class ChainCertificate(BaseModel):
    position: int
    subject: str
    issuer: str
    not_after: str
    days_until_expiry: int
    is_ca: bool


@register_module
class CertificateChainModule(ToolModule):
    slug = "certificate-chain"
    category = "certificates"
    name = "Certificate Chain"
    description = "Zeigt die komplette Zertifikatskette (nicht nur das Leaf-Zertifikat) inkl. Gueltigkeit jedes Gliedes."
    is_active_scan = False
    timeout_seconds = 12

    class Input(BaseModel):
        host: str
        port: int = 443

        @field_validator("host")
        @classmethod
        def validate_host(cls, v: str) -> str:
            v = v.strip().rstrip(".")
            if not (is_valid_hostname(v) or is_valid_ip(v)):
                raise ValueError("Ungueltiger Host (Hostname oder IP erwartet)")
            return v

        @field_validator("port")
        @classmethod
        def validate_port(cls, v: int) -> int:
            if not (1 <= v <= 65535):
                raise ValueError("Ungueltiger Port")
            return v

    class Output(BaseModel):
        host: str
        port: int
        success: bool
        chain_length: int
        chain: list[ChainCertificate] = []
        warnings: list[str] = []
        error: str | None = None

    async def run(self, data: Input) -> Output:
        try:
            process = await asyncio.create_subprocess_exec(
                "openssl", "s_client", "-connect", f"{data.host}:{data.port}", "-showcerts",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_bytes, _ = await asyncio.wait_for(
                process.communicate(input=b""), timeout=self.timeout_seconds - 2
            )
        except asyncio.TimeoutError:
            return self.Output(host=data.host, port=data.port, success=False, chain_length=0, error="Zeitueberschreitung")
        except FileNotFoundError:
            return self.Output(host=data.host, port=data.port, success=False, chain_length=0, error="openssl nicht gefunden")

        output = stdout_bytes.decode("utf-8", errors="replace")
        pem_blocks = _CERT_BLOCK_RE.findall(output)

        if not pem_blocks:
            return self.Output(
                host=data.host, port=data.port, success=False, chain_length=0,
                error="Keine Zertifikate erhalten -- Verbindung fehlgeschlagen oder kein TLS auf diesem Port",
            )

        warnings: list[str] = []
        chain: list[ChainCertificate] = []

        for i, pem in enumerate(pem_blocks):
            try:
                cert = x509.load_pem_x509_certificate(pem.encode("ascii"))
            except Exception:  # noqa: BLE001
                continue

            try:
                not_after = cert.not_valid_after_utc
            except AttributeError:
                not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)

            days_left = (not_after - datetime.now(timezone.utc)).days
            is_ca = self._is_ca(cert)

            if days_left < 0:
                warnings.append(f"Zertifikat #{i + 1} ({cert.subject.rfc4514_string()}) ist abgelaufen.")
            elif days_left < 14:
                warnings.append(f"Zertifikat #{i + 1} ({cert.subject.rfc4514_string()}) laeuft in {days_left} Tagen ab.")

            chain.append(
                ChainCertificate(
                    position=i + 1,
                    subject=cert.subject.rfc4514_string(),
                    issuer=cert.issuer.rfc4514_string(),
                    not_after=not_after.isoformat(),
                    days_until_expiry=days_left,
                    is_ca=is_ca,
                )
            )

        if len(chain) == 1:
            warnings.append("Nur ein Zertifikat empfangen -- Zwischenzertifikate fehlen ggf. auf dem Server.")

        return self.Output(
            host=data.host, port=data.port, success=True,
            chain_length=len(chain), chain=chain, warnings=warnings, error=None,
        )

    @staticmethod
    def _is_ca(cert: x509.Certificate) -> bool:
        try:
            basic_constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints)
            return bool(basic_constraints.value.ca)
        except x509.ExtensionNotFound:
            return False
