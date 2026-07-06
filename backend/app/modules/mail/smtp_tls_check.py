import asyncio
import smtplib
import ssl

from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import is_valid_hostname


def _check_smtp_tls_sync(host: str, port: int, timeout: float) -> dict:
    """Blockierender smtplib-Code -- ueber asyncio.to_thread aufgerufen.

    stdlib `smtplib` ist synchron; es lohnt sich hier nicht, eine eigene
    async-SMTP-Implementierung zu bauen, nur um STARTTLS zu pruefen.
    """
    with smtplib.SMTP(timeout=timeout) as smtp:
        smtp.connect(host, port)
        code, banner = smtp.ehlo()
        supports_starttls = smtp.has_extn("starttls")

        if not supports_starttls:
            return {
                "supports_starttls": False,
                "tls_version": None,
                "cipher": None,
                "banner": banner.decode("utf-8", errors="replace") if isinstance(banner, bytes) else str(banner),
            }

        context = ssl.create_default_context()
        smtp.starttls(context=context)
        sock = smtp.sock
        tls_version = sock.version() if hasattr(sock, "version") else None
        cipher = sock.cipher()[0] if hasattr(sock, "cipher") and sock.cipher() else None

        return {
            "supports_starttls": True,
            "tls_version": tls_version,
            "cipher": cipher,
            "banner": banner.decode("utf-8", errors="replace") if isinstance(banner, bytes) else str(banner),
        }


@register_module
class SmtpTlsCheckModule(ToolModule):
    slug = "smtp-tls-check"
    category = "mail"
    name = "SMTP TLS Check"
    description = "Prueft, ob ein Mailserver STARTTLS unterstuetzt und welche TLS-Version/Cipher dabei genutzt wird."
    is_active_scan = False
    timeout_seconds = 12

    class Input(BaseModel):
        host: str
        port: int = 25

        @field_validator("host")
        @classmethod
        def validate_host(cls, v: str) -> str:
            v = v.strip().rstrip(".")
            if not is_valid_hostname(v):
                raise ValueError("Ungueltiger Host")
            return v

        @field_validator("port")
        @classmethod
        def validate_port(cls, v: int) -> int:
            if v not in (25, 587, 465):
                raise ValueError("Port muss 25, 587 oder 465 sein")
            return v

    class Output(BaseModel):
        host: str
        port: int
        success: bool
        supports_starttls: bool | None = None
        tls_version: str | None = None
        cipher: str | None = None
        banner: str | None = None
        warnings: list[str] = []
        error: str | None = None

    async def run(self, data: Input) -> Output:
        try:
            info = await asyncio.wait_for(
                asyncio.to_thread(_check_smtp_tls_sync, data.host, data.port, float(self.timeout_seconds - 3)),
                timeout=self.timeout_seconds - 1,
            )
        except asyncio.TimeoutError:
            return self.Output(
                host=data.host, port=data.port, success=False,
                error="Zeitueberschreitung -- viele Netzwerke/Hoster blockieren ausgehenden Port 25.",
            )
        except (smtplib.SMTPException, OSError, ssl.SSLError) as exc:
            return self.Output(host=data.host, port=data.port, success=False, error=str(exc))

        warnings: list[str] = []
        if not info["supports_starttls"]:
            warnings.append("Server unterstuetzt kein STARTTLS -- Mails werden unverschluesselt uebertragen.")
        elif info["tls_version"] in {"TLSv1", "TLSv1.1"}:
            warnings.append(f"Veraltete TLS-Version: {info['tls_version']}.")

        return self.Output(host=data.host, port=data.port, success=True, warnings=warnings, **info)
