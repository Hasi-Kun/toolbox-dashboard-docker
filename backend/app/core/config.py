from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Zentrale Konfiguration, aus Environment-Variablen geladen.

    Wird per .env / docker-compose environment gesetzt. Nichts davon
    wird hart im Code hinterlegt.
    """

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "Toolbox API"
    environment: str = "development"

    # CORS: im Zweifel restriktiv, Frontend läuft intern im selben Netzwerk
    allowed_origins: list[str] = ["http://localhost:3000"]

    # Redis für Queue + Rate Limiting
    redis_url: str = "redis://toolbox-redis:6379/0"

    # SQLite Default, optional Postgres via DATABASE_URL überschreiben
    database_url: str = "sqlite:///./data/toolbox.db"

    # Harte Obergrenzen -- werden pro Modul ggf. weiter verschärft, nie gelockert
    default_timeout_seconds: int = 10
    rate_limit_per_minute: int = 30
    login_rate_limit_per_minute: int = 10  # deutlich strenger gegen Brute-Force
    scan_rate_limit_per_minute: int = 5  # aktive Scans sind ressourcenintensiv und koennen Dritte betreffen

    log_level: str = "INFO"

    # --- Auth ---
    # Zufaellig generieren: python -c "import secrets; print(secrets.token_hex(32))"
    session_secret: str = "changeme-generate-a-real-secret"
    session_cookie_name: str = "toolbox_session"
    session_ttl_seconds: int = 60 * 60 * 12  # 12h
    pending_login_ttl_seconds: int = 60 * 5  # 5 Minuten Zeit fuer den 2FA-Schritt

    # WebAuthn / Passkeys -- muss zur oeffentlichen Domain passen, sonst
    # schlaegt die Browser-Verifikation fehl.
    webauthn_rp_id: str = "{{TOOLBOX_DOMAIN}}"
    webauthn_rp_name: str = "Toolbox"
    webauthn_origin: str = "https://{{TOOLBOX_DOMAIN}}"

    # Read-only Docker-API-Proxy fuer die Dashboard-Container-Uebersicht
    # (siehe docs/ARCHITECTURE.md -- niemals direkter Socket-Zugriff)
    docker_proxy_url: str = "http://docker-socket-proxy:2375"

    # --- Microsoft 365 SSO (optional) ---
    # Registrierung in Azure AD / Microsoft Entra ID: App-Registrierung
    # anlegen, Redirect-URI auf <webauthn_origin>/api/v1/auth/sso/microsoft/callback
    # setzen, "openid", "profile", "email" als Berechtigungen. Client-
    # Secret NIE ins Repo, nur per .env/Umgebungsvariable.
    #
    # WICHTIG: SSO-Login ist bewusst nur fuer bereits per Admin angelegte
    # Konten moeglich (kein automatisches Anlegen neuer Nutzer ueber SSO)
    # -- konsistent mit dem bestehenden Invite-only-Prinzip. Ein Admin
    # verknuepft ein bestehendes Konto ueber dessen "microsoft_upn"-Feld
    # mit der M365-Identitaet.
    ms_sso_enabled: bool = False
    ms_sso_client_id: str | None = None
    ms_sso_client_secret: str | None = None
    ms_sso_tenant_id: str | None = None

    # --- WebSSH-Webshell (gespeicherte Verbindungen) ---
    # Symmetrischer Schluessel zum Verschluesseln gespeicherter SSH-
    # Passwoerter/private Schluessel in der DB. Generieren mit:
    #   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    # Falls NICHT gesetzt: wird ein Schluessel aus session_secret abgeleitet
    # (funktioniert sofort ohne Zusatzschritt, aber ein dedizierter Key wird
    # empfohlen -- getrennte Rotation von Session- und Verschluesselungs-
    # schluessel ist sauberer).
    ssh_vault_key: str | None = None
    # Maximale Anzahl gleichzeitig offener WebSSH-Verbindungen PRO NUTZER
    # (nicht zu verwechseln mit der rein UI-seitigen WebCLI-Fensterbegrenzung
    # -- hier handelt es sich um echte, serverseitige SSH-Verbindungen, die
    # tatsaechlich Ressourcen (Sockets, Prozesse) binden).
    max_ssh_sessions_per_user: int = 5

    # --- Email-Aliase (Verwaltungsebene, siehe EmailAlias-Docstring fuer
    # den wichtigen Infrastruktur-Hinweis: das hier ist NUR die
    # Verwaltung, kein tatsaechlicher Mail-Empfang) ---
    # Kommagetrennte Liste erlaubter Alias-Domains, z.B.
    # "alias.{{BASE_DOMAIN}},mail-alias.{{BASE_DOMAIN}}" -- bewusst eine feste
    # Admin-konfigurierte Allowlist statt freier Domain-Eingabe: nur
    # Domains, fuer die tatsaechlich MX-Records auf einen echten
    # Empfangsdienst zeigen, ergeben ueberhaupt funktionierende Aliase.
    email_alias_domains: str = ""

    @property
    def email_alias_domains_list(self) -> list[str]:
        return [d.strip() for d in self.email_alias_domains.split(",") if d.strip()]

    # --- AdGuard Home Integration (DNS-Cache leeren) ---
    # Bewusst ueber AdGuard Homes EIGENE, dafuer vorgesehene REST-API
    # (POST /control/cache_clear, HTTP-Basic-Auth) -- NICHT ueber
    # Host-Shell-Zugriff. Ein containerisiertes Backend, das beliebige
    # Befehle auf dem Host ausfuehren koennte, waere praktisch ein
    # Remote-Root-Zugriff auf den Server -- das bauen wir nicht. Diese
    # eng begrenzte, service-eigene Admin-Aktion ist der sichere Weg.
    adguard_home_url: str | None = None
    adguard_home_username: str | None = None
    adguard_home_password: str | None = None


@lru_cache
def get_settings() -> Settings:
    return Settings()
