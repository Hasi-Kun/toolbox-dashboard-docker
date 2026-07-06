from __future__ import annotations

import enum
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, UniqueConstraint, text
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

    # Invite-Kontingent fuer normale Member (Admin-vergeben) -- ersetzt das
    # fruehere reine An/Aus (can_invite): jede erfolgreiche Invite-Erstellung
    # durch einen Member zieht das Kontingent um 1 herunter. 0 = keine
    # Berechtigung. Admins sind davon unabhaengig immer uneingeschraenkt.
    invite_quota: Mapped[int] = mapped_column(Integer, default=0, server_default=text("0"), nullable=False)

    # Premium/VIP-Fundament (noch ohne Feature-Gating -- reine Kennzeichnung
    # + Badge-Darstellung, echte Premium-only-Tools folgen spaeter).
    is_premium: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("0"), nullable=False)
    premium_badge_color: Mapped[str] = mapped_column(String(9), default="#F5C518", server_default=text("'#F5C518'"), nullable=False)

    # Eigenstaendiges Anzeigename-Customizing -- NUR fuer Premium-User
    # selbst editierbar (siehe /auth/me/display-style), nicht admin-verwaltet.
    # style: "default" | "solid" | "gradient" | "particles"
    display_name_style: Mapped[str] = mapped_column(String(16), default="default", server_default=text("'default'"), nullable=False)
    display_name_color: Mapped[str] = mapped_column(String(9), default="#35E0C0", server_default=text("'#35E0C0'"), nullable=False)
    display_name_gradient_color: Mapped[str] = mapped_column(String(9), default="#F5C518", server_default=text("'#F5C518'"), nullable=False)

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
    # Login-Formular: Transparenz (0=undurchsichtig, 100=komplett transparent) + Weichzeichnung in px
    form_opacity_percent: Mapped[int] = mapped_column(Integer, default=90, server_default=text("90"), nullable=False)
    form_blur_px: Mapped[int] = mapped_column(Integer, default=4, server_default=text("4"), nullable=False)
    # Nullable, KEIN server_default noetig (bewusst so gewaehlt -- ein
    # nullable Feld laesst sich per ALTER TABLE ADD COLUMN IMMER sicher
    # hinzufuegen, auch auf Tabellen mit bestehenden Zeilen. Siehe
    # docs/ARCHITECTURE.md fuer die Lehre aus einem frueheren Incident mit
    # NOT-NULL-Spalten ohne server_default).
    chat_last_cleared_date: Mapped[str | None] = mapped_column(String(10), nullable=True)


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
    im Dashboard -- inklusive Ein-/Ausgabe, damit ein Klick auf einen
    vergangenen Lauf das damalige Ergebnis zeigt (nicht nur, DASS er
    stattfand).
    """

    __tablename__ = "tool_executions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    tool_slug: Mapped[str] = mapped_column(String(64), nullable=False)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False)
    ran_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
    input_json: Mapped[str | None] = mapped_column(String(4000), nullable=True)
    output_json: Mapped[str | None] = mapped_column(String(20000), nullable=True)
    error_message: Mapped[str | None] = mapped_column(String(500), nullable=True)


class InviteCode(Base):
    """Einladungscode fuer die Selbstregistrierung. Erstellt von einem Admin,
    einmalig einlösbar. Damit bleibt die Registrierung geschlossen (kein
    offenes Signup-Formular fuer jeden), aber ein Admin kann gezielt
    Zugang gewaehren, ohne selbst ein Konto anlegen zu muessen.
    """

    __tablename__ = "invite_codes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    code: Mapped[str] = mapped_column(String(32), unique=True, index=True, nullable=False)
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    note: Mapped[str | None] = mapped_column(String(200), nullable=True)
    role: Mapped[str] = mapped_column(String(16), default=UserRole.MEMBER.value, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    used_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ChatMessage(Base):
    """Nachricht in der globalen Shoutbox. Username wird denormalisiert
    gespeichert (nicht nur user_id), damit Nachrichten lesbar bleiben,
    falls ein Account spaeter geloescht wird.
    """

    __tablename__ = "chat_messages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    username: Mapped[str] = mapped_column(String(64), nullable=False)
    message: Mapped[str] = mapped_column(String(500), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)


class FeatureRequestStatus(str, enum.Enum):
    OPEN = "open"
    PLANNED = "planned"
    DONE = "done"
    REJECTED = "rejected"


class FeatureRequest(Base):
    __tablename__ = "feature_requests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    username: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(150), nullable=False)
    description: Mapped[str] = mapped_column(String(3000), nullable=False)
    status: Mapped[str] = mapped_column(String(16), default=FeatureRequestStatus.OPEN.value, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)

    votes: Mapped[list["FeatureRequestVote"]] = relationship(back_populates="request", cascade="all, delete-orphan")
    comments: Mapped[list["FeatureRequestComment"]] = relationship(back_populates="request", cascade="all, delete-orphan")


class FeatureRequestVote(Base):
    __tablename__ = "feature_request_votes"
    __table_args__ = (UniqueConstraint("request_id", "user_id", name="uq_vote_request_user"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    request_id: Mapped[int] = mapped_column(ForeignKey("feature_requests.id"), nullable=False, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    request: Mapped["FeatureRequest"] = relationship(back_populates="votes")


class FeatureRequestComment(Base):
    __tablename__ = "feature_request_comments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    request_id: Mapped[int] = mapped_column(ForeignKey("feature_requests.id"), nullable=False, index=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    username: Mapped[str] = mapped_column(String(64), nullable=False)
    comment: Mapped[str] = mapped_column(String(1000), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    request: Mapped["FeatureRequest"] = relationship(back_populates="comments")


class AuditLogEntry(Base):
    """Sicherheitsrelevante Ereignisse fuer Admins: Login-Versuche
    (erfolgreich/fehlgeschlagen), 2FA-Fehlschlaege, Admin-Aktionen
    (Benutzer angelegt/geloescht, Invite erstellt, etc). Bewusst getrennt
    von ToolExecution (das ist Tool-Nutzung, hier geht es um Auth/Verwaltung).
    """

    __tablename__ = "audit_log_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    username: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False)
    detail: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
