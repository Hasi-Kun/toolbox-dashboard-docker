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
    webauthn_rp_id: str = "toolbox.domain.cc"
    webauthn_rp_name: str = "Toolbox"
    webauthn_origin: str = "https://toolbox.domain.cc"

    # Read-only Docker-API-Proxy fuer die Dashboard-Container-Uebersicht
    # (siehe docs/ARCHITECTURE.md -- niemals direkter Socket-Zugriff)
    docker_proxy_url: str = "http://docker-socket-proxy:2375"


@lru_cache
def get_settings() -> Settings:
    return Settings()
