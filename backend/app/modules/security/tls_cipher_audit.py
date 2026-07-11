"""Prueft, welche TLS-Protokollversionen ein Server akzeptiert und welche
Cipher Suite dabei jeweils ausgehandelt wird -- markiert veraltete/
unsichere Kombinationen (SSLv3, TLS 1.0/1.1, RC4/3DES/EXPORT/NULL-Ciphers).
"""

import asyncio
import socket
import ssl

from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import is_valid_hostname, is_valid_ip

# Cipher-Namensmuster, die auf schwache/veraltete Verschluesselung hindeuten.
_WEAK_CIPHER_PATTERNS = ["RC4", "3DES", "DES-CBC", "EXPORT", "NULL", "MD5", "anon", "PSK"]

# Cipher-Namensmuster, die auf schwache/veraltete Verschluesselung hindeuten.
_WEAK_CIPHER_PATTERNS = ["RC4", "3DES", "DES-CBC", "EXPORT", "NULL", "MD5", "anon", "PSK"]

# Explizite Zuordnung statt fragiler String-Magie -- ssl.TLSVersion-Enum-
# Attribute (z.B. TLSv1_1) variieren nicht, aber ob eine Version je nach
# lokaler OpenSSL-Version/-Konfiguration ueberhaupt ANGEBOTEN werden kann,
# schon (getattr(..., None) faengt das ab).
_PROTOCOL_VERSIONS: list[tuple[str, "ssl.TLSVersion | None"]] = [
    ("SSLv3", getattr(ssl.TLSVersion, "SSLv3", None)),
    ("TLS 1.0", getattr(ssl.TLSVersion, "TLSv1", None)),
    ("TLS 1.1", getattr(ssl.TLSVersion, "TLSv1_1", None)),
    ("TLS 1.2", getattr(ssl.TLSVersion, "TLSv1_2", None)),
    ("TLS 1.3", getattr(ssl.TLSVersion, "TLSv1_3", None)),
]
_DEPRECATED_PROTOCOLS = {"SSLv3", "TLS 1.0", "TLS 1.1"}


def _test_protocol_version(host: str, port: int, version_name: str, version_const, timeout: float) -> dict:
    """Blockierender Socket-Code -- ueber asyncio.to_thread aufgerufen.
    Versucht, EXAKT diese eine TLS-Version auszuhandeln (min==max), um
    zu sehen, ob der Server sie akzeptiert."""
    if version_const is None:
        return {"supported": None, "cipher": None, "note": "Von der lokalen OpenSSL-Bibliothek nicht anbietbar"}

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = version_const
        ctx.maximum_version = version_const
    except (ValueError, OSError):
        return {"supported": None, "cipher": None, "note": "Von der lokalen OpenSSL-Bibliothek nicht anbietbar"}

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cipher_info = ssock.cipher()
                return {"supported": True, "cipher": cipher_info[0] if cipher_info else None, "note": None}
    except ssl.SSLError:
        return {"supported": False, "cipher": None, "note": None}
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        return {"supported": None, "cipher": None, "note": f"Verbindung fehlgeschlagen: {exc}"}


class ProtocolResult(BaseModel):
    protocol: str
    supported: bool | None  # None = konnte nicht getestet werden
    cipher: str | None = None
    deprecated: bool = False
    weak_cipher: bool = False
    note: str | None = None


@register_module
class TlsCipherAuditModule(ToolModule):
    slug = "tls-cipher-audit"
    category = "security"
    name = "TLS Cipher Suite Auditor"
    description = (
        "Prueft, welche TLS-Protokollversionen ein Server akzeptiert (SSLv3 bis TLS 1.3) und welche "
        "Cipher Suite dabei jeweils ausgehandelt wird -- markiert veraltete Protokolle und schwache "
        "Cipher (RC4/3DES/EXPORT/NULL/MD5)."
    )
    is_active_scan = False
    timeout_seconds = 25

    class Input(BaseModel):
        host: str
        port: int = 443

        @field_validator("host")
        @classmethod
        def validate_host(cls, v: str) -> str:
            v = v.strip().rstrip(".")
            if not (is_valid_hostname(v) or is_valid_ip(v)):
                raise ValueError("Ungueltiger Host")
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
        protocols: list[ProtocolResult] = []
        overall_risk: str | None = None  # "hoch" | "mittel" | "niedrig"
        error: str | None = None

    async def run(self, data: Input) -> Output:
        try:
            results = await asyncio.gather(
                *(
                    asyncio.to_thread(_test_protocol_version, data.host, data.port, name, version, 6.0)
                    for name, version in _PROTOCOL_VERSIONS
                )
            )
        except Exception as exc:  # noqa: BLE001
            return self.Output(host=data.host, port=data.port, success=False, error=str(exc))

        protocols = []
        any_reachable = False
        has_deprecated_protocol = False
        has_weak_cipher = False

        for (name, _), raw in zip(_PROTOCOL_VERSIONS, results):
            if raw["supported"] is not None:
                any_reachable = True
            cipher = raw["cipher"]
            is_deprecated = name in _DEPRECATED_PROTOCOLS and bool(raw["supported"])
            is_weak_cipher = bool(cipher) and any(p in cipher.upper() for p in _WEAK_CIPHER_PATTERNS)
            if is_deprecated:
                has_deprecated_protocol = True
            if is_weak_cipher:
                has_weak_cipher = True
            protocols.append(ProtocolResult(
                protocol=name, supported=raw["supported"], cipher=cipher,
                deprecated=is_deprecated, weak_cipher=is_weak_cipher, note=raw["note"],
            ))

        if not any_reachable:
            return self.Output(host=data.host, port=data.port, success=False, error="Host/Port nicht erreichbar")

        if has_deprecated_protocol or has_weak_cipher:
            risk = "hoch" if has_weak_cipher else "mittel"
        else:
            risk = "niedrig"

        return self.Output(host=data.host, port=data.port, success=True, protocols=protocols, overall_risk=risk)
