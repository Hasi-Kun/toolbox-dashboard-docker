from __future__ import annotations

import enum
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.db import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    MEMBER = "member"


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(16), default=UserRole.MEMBER.value, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # TOTP -- Secret liegt nur verschluesselt-at-rest auf Volume-Ebene
    # (Docker-Volume), nicht zusaetzlich applikationsseitig verschluesselt
    # in Phase 3. Siehe docs/ARCHITECTURE.md fuer geplante Haertung.
    totp_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    webauthn_credentials: Mapped[list["WebAuthnCredential"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )

    @property
    def has_2fa(self) -> bool:
        return self.totp_enabled or len(self.webauthn_credentials) > 0


class WebAuthnCredential(Base):
    __tablename__ = "webauthn_credentials"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)

    # base64url-kodiert gespeichert (Text statt Bytes fuer einfaches Debugging)
    credential_id: Mapped[str] = mapped_column(String(512), unique=True, index=True, nullable=False)
    public_key: Mapped[str] = mapped_column(String(1024), nullable=False)
    sign_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    nickname: Mapped[str] = mapped_column(String(64), default="Passkey", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    user: Mapped["User"] = relationship(back_populates="webauthn_credentials")


class AppearanceSettings(Base):
    """Instanzweite Branding-Einstellung (Singleton, id=1) -- bewusst NICHT
    pro Benutzer, weil die Login-Seite den Hintergrund rendern muss BEVOR
    irgendjemand eingeloggt ist, also ohne zu wissen, welcher User das ist.
    """

    __tablename__ = "appearance_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    background_style: Mapped[str] = mapped_column(String(32), default="dots", nullable=False)  # "none" | "dots" | "gradient" | "starfield" | "custom"
    custom_background_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    animation_speed: Mapped[float] = mapped_column(default=1.0, nullable=False)
    gradient_color: Mapped[str] = mapped_column(String(9), default="#35E0C0", nullable=False)
    interactive_dots: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class Favorite(Base):
    """Ein favorisiertes Tool eines Benutzers. Einfache Slug-Referenz statt
    Fremdschluessel auf eine Tools-Tabelle -- Tools leben nur in der
    Modul-Registry zur Laufzeit, nicht in der Datenbank.
    """

    __tablename__ = "favorites"
    __table_args__ = (UniqueConstraint("user_id", "tool_slug", name="uq_favorite_user_tool"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    tool_slug: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class ToolExecution(Base):
    """Protokolliert jede Tool-Ausfuehrung fuer die 'Letzte Scans'-Anzeige
    im Dashboard. Bewusst schlank (kein vollstaendiges Audit-Log mit
    Ein-/Ausgabe-Daten -- das waere ein eigenes Thema, siehe
    docs/ARCHITECTURE.md fuer geplante Erweiterungen).
    """

    __tablename__ = "tool_executions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    tool_slug: Mapped[str] = mapped_column(String(64), nullable=False)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False)
    ran_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
