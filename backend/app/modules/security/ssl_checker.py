import asyncio
import socket
import ssl
from datetime import datetime, timezone

from cryptography import x509
from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import is_valid_hostname, is_valid_ip


def _fetch_certificate(host: str, port: int, timeout: float) -> dict:
    """Blockierender Socket-Code -- wird ueber asyncio.to_thread aufgerufen.

    Verbindet OHNE Zertifikatsvalidierung, damit auch abgelaufene,
    selbstsignierte oder falsch benannte Zertifikate ausgelesen werden
    koennen (genau das will man bei einem Checker meistens sehen).
    Trust wird separat mit einer zweiten, validierenden Verbindung geprueft.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            der = ssock.getpeercert(binary_form=True)
            tls_version = ssock.version()
            cipher = ssock.cipher()

    cert = x509.load_der_x509_certificate(der)

    try:
        not_after = cert.not_valid_after_utc
        not_before = cert.not_valid_before_utc
    except AttributeError:
        # aeltere cryptography-Versionen: naive UTC-Datetimes
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
        not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)

    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        san = []

    trusted, trust_error = _check_trusted(host, port, timeout)

    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_until_expiry": (not_after - datetime.now(timezone.utc)).days,
        "san": san,
        "tls_version": tls_version,
        "cipher": cipher[0] if cipher else None,
        "trusted": trusted,
        "trust_error": trust_error,
    }


def _check_trusted(host: str, port: int, timeout: float) -> tuple[bool, str | None]:
    """Zweite, echte Verifikation nur um festzustellen, ob ein Standard-Trust-Store
    dem Zertifikat vertrauen wuerde -- unabhaengig vom obigen Auslesen.
    """
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                pass
        return True, None
    except ssl.SSLError as exc:
        return False, str(exc)
    except (socket.timeout, OSError) as exc:
        return False, str(exc)


@register_module
class SslCheckerModule(ToolModule):
    slug = "ssl-checker"
    category = "security"
    name = "SSL Checker"
    description = "Liest Zertifikat, TLS-Version und Cipher eines Servers aus und prueft die Gueltigkeit."
    is_active_scan = False
    timeout_seconds = 10

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
        subject: str | None = None
        issuer: str | None = None
        not_before: str | None = None
        not_after: str | None = None
        days_until_expiry: int | None = None
        san: list[str] = []
        tls_version: str | None = None
        cipher: str | None = None
        trusted: bool | None = None
        trust_error: str | None = None
        warnings: list[str] = []
        error: str | None = None

    async def run(self, data: Input) -> Output:
        try:
            info = await asyncio.to_thread(_fetch_certificate, data.host, data.port, float(self.timeout_seconds - 2))
        except Exception as exc:  # noqa: BLE001
            return self.Output(host=data.host, port=data.port, success=False, error=str(exc))

        warnings: list[str] = []
        if info["days_until_expiry"] < 0:
            warnings.append("Zertifikat ist bereits abgelaufen.")
        elif info["days_until_expiry"] < 14:
            warnings.append(f"Zertifikat laeuft in {info['days_until_expiry']} Tagen ab.")
        if not info["trusted"]:
            warnings.append("Zertifikat wird von Standard-Trust-Stores nicht als vertrauenswuerdig eingestuft.")
        if info["tls_version"] in {"TLSv1", "TLSv1.1"}:
            warnings.append(f"Veraltete TLS-Version im Einsatz: {info['tls_version']}.")

        return self.Output(host=data.host, port=data.port, success=True, warnings=warnings, **info)
