"""Prueft einen SSH-Dienst auf grundlegende Sicherheitsmerkmale, OHNE
sich anzumelden: Banner/Versions-Grab per rohem Socket, dann eine
absichtlich scheiternde Verbindung (kein gueltiges Credential), um den
Host-Key-Algorithmus und die vom Server angebotenen Auth-Methoden
auszulesen -- beides wird bereits waehrend des Schluesselaustauschs
bzw. der Auth-Verhandlung sichtbar, VOR einer erfolgreichen Anmeldung.

Rein passiv: es wird zu keinem Zeitpunkt versucht, sich tatsaechlich
anzumelden (kein Passwort-Raten, kein Schluessel-Ausprobieren) -- nur
das, was der Server VOR jeder Authentifizierung ohnehin offenlegt.
"""

import asyncio

import asyncssh
from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module
from app.modules.dns.common import is_valid_hostname, is_valid_ip

# Host-Key-Algorithmen, die als veraltet/schwach gelten (SHA1-basiert
# oder DSA) -- moderne Server bieten zusaetzlich staerkere Algorithmen
# an, aber wenn NUR diese angeboten werden, ist das ein Warnsignal.
_WEAK_HOST_KEY_ALGOS = {"ssh-rsa", "ssh-dss"}


class _ProbeClient(asyncssh.SSHClient):
    """Stashed die Connection, sobald sie steht, und liest die vom
    Server angebotenen Auth-Methoden INNERHALB von
    password_auth_requested() aus -- get_server_auth_methods() liefert
    ausserhalb dieses Callbacks (z.B. erst nach dem finalen
    PermissionDenied) leere Ergebnisse, das ist keine Ausnahme sondern
    das dokumentierte Verhalten von asyncssh: die Liste wird erst
    populiert, wenn der Client-State-Machine-Callback fuer eine
    konkrete Methode aufgerufen wird. Der Callback gibt bewusst `None`
    zurueck (kein Passwort anbieten) -- das laesst die Authentifizierung
    absichtlich fehlschlagen, ohne je ein echtes Credential zu senden."""

    def __init__(self):
        self.conn: asyncssh.SSHClientConnection | None = None
        self.auth_methods: list[str] = []

    def connection_made(self, conn: asyncssh.SSHClientConnection) -> None:
        self.conn = conn

    def password_auth_requested(self) -> None:
        if self.conn is not None:
            try:
                self.auth_methods = list(self.conn.get_server_auth_methods())
            except Exception:  # noqa: BLE001
                pass
        return None


async def _grab_banner(host: str, port: int, timeout: float) -> str | None:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=timeout)
            return line.decode("utf-8", errors="replace").strip() or None
        finally:
            writer.close()
    except (OSError, asyncio.TimeoutError):
        return None


@register_module
class SshSecurityCheckModule(ToolModule):
    slug = "ssh-security-check"
    category = "security"
    name = "SSH-Sicherheitscheck"
    description = (
        "Prueft einen SSH-Dienst OHNE sich anzumelden: liest das Banner, den Host-Key-Algorithmus "
        "und die vom Server angebotenen Authentifizierungsmethoden aus -- markiert veraltete "
        "Host-Key-Typen (ssh-rsa/SHA1, ssh-dss). Kein Anmeldeversuch, keine Passwoerter."
    )
    is_active_scan = False
    timeout_seconds = 15

    class Input(BaseModel):
        host: str
        port: int = 22

        @field_validator("host")
        @classmethod
        def validate_host(cls, v: str) -> str:
            v = v.strip()
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
        banner: str | None = None
        host_key_algorithm: str | None = None
        auth_methods: list[str] = []
        warnings: list[str] = []
        error: str | None = None

    async def run(self, data: Input) -> Output:
        banner = await _grab_banner(data.host, data.port, min(self.timeout_seconds - 8, 6))
        if banner is None:
            return self.Output(host=data.host, port=data.port, success=False, error="Kein SSH-Banner erhalten -- Port erreichbar?")

        probe_client = _ProbeClient()
        host_key_algorithm: str | None = None

        try:
            async with asyncssh.connect(
                data.host, port=data.port,
                username="toolbox-security-probe",
                known_hosts=None,
                preferred_auth=["password"],
                client_factory=lambda: probe_client,
                connect_timeout=min(self.timeout_seconds - 5, 8),
            ):
                pass  # wird nie erreicht -- der Callback liefert absichtlich kein Passwort
        except asyncssh.PermissionDenied:
            # Erwarteter, gewuenschter Fall: Authentifizierung (absichtlich)
            # abgelehnt, aber der Schluesselaustausch ist bereits gelaufen.
            if probe_client.conn is not None:
                try:
                    host_key = probe_client.conn.get_server_host_key()
                    if host_key is not None:
                        host_key_algorithm = host_key.get_algorithm()
                except Exception:  # noqa: BLE001
                    pass
        except (asyncssh.Error, OSError, asyncio.TimeoutError) as exc:
            return self.Output(host=data.host, port=data.port, success=True, banner=banner, error=f"Verbindung nach dem Banner fehlgeschlagen: {exc}")
        finally:
            if probe_client.conn is not None:
                probe_client.conn.close()

        auth_methods = probe_client.auth_methods
        warnings = []
        if host_key_algorithm and host_key_algorithm.lower() in _WEAK_HOST_KEY_ALGOS:
            warnings.append(f"Host-Key-Algorithmus '{host_key_algorithm}' gilt als veraltet (SHA1/DSA-basiert).")
        if "password" in auth_methods:
            warnings.append("Passwort-Authentifizierung ist aktiviert -- Public-Key-only gilt als sicherer.")

        return self.Output(
            host=data.host, port=data.port, success=True, banner=banner,
            host_key_algorithm=host_key_algorithm, auth_methods=auth_methods, warnings=warnings,
        )
