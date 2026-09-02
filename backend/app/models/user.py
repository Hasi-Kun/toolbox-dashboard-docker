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
    # Fuer die "Secrets-Rotation-Erinnerung": wann wurde das TOTP-Secret
    # zuletzt (neu) eingerichtet -- Admins sehen so, welche Konten ihr
    # 2FA-Secret schon sehr lange nicht mehr rotiert haben. Nullable,
    # da bestehende Nutzer beim Migrieren keinen bekannten Zeitpunkt haben.
    totp_rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Optionale IP-Beschraenkung fuer den Login -- kommagetrennte Liste
    # aus IPs/CIDR-Bereichen (z.B. "203.0.113.5,198.51.100.0/24"). Leer/
    # NULL = keine Einschraenkung (Standard, abwaertskompatibel). Jeder
    # Nutzer verwaltet das selbst unter Sicherheitseinstellungen.
    allowed_login_ips: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    # Optionales, individuelles Session-Timeout in Minuten (gleitend --
    # verlaengert sich bei jeder Aktivitaet). NULL = globalen Standard
    # aus den Server-Einstellungen verwenden.
    session_timeout_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Microsoft-365-SSO: verknuepft dieses Konto mit einer M365-Identitaet
    # (User Principal Name, z.B. "max.muster@firma.de"). NULL = SSO fuer
    # dieses Konto nicht aktiviert -- ein Admin muss es explizit setzen
    # (kein automatisches Anlegen neuer Konten ueber SSO, konsistent mit
    # dem Invite-only-Prinzip). Unique, damit nicht zwei lokale Konten
    # versehentlich an dieselbe M365-Identitaet gebunden werden.
    microsoft_upn: Mapped[str | None] = mapped_column(String(255), nullable=True, unique=True)

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
    # Parallax-Effekt auf der Login-Seite: Hintergrund-Ebene und Formular-
    # Karte verschieben sich leicht gegenlaeufig zur Mausbewegung (Tiefen-
    # Illusion). Wirkt auf allen background_style-Varianten ausser "none".
    parallax_enabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("0"), nullable=False)
    # Staerke der Verschiebung, 0.25 (kaum merklich) bis 3 (sehr stark),
    # 1 = Standard. Skaliert sowohl die Bewegung selbst als auch den
    # noetigen Ueberstand des Hintergrunds ueber den Viewport hinaus
    # (siehe login/page.tsx) -- je staerker die Bewegung, desto mehr
    # Ueberstand ist noetig, damit nie eine Kante sichtbar wird.
    parallax_strength: Mapped[float] = mapped_column(default=1.0, server_default=text("1.0"), nullable=False)


class SecuritySettings(Base):
    """Instanzweite Sicherheits-Einstellung (Singleton, id=1) -- aktuell nur
    Captcha-Konfiguration (Cloudflare Turnstile oder Google reCAPTCHA) fuer
    Login/Registrierung. Bewusst getrennt von AppearanceSettings: der
    Secret-Key ist sensibel und darf NIE ueber den oeffentlichen
    (unauthentifizierten) Endpunkt zurueckgegeben werden, den die Login-
    Seite abfragt -- siehe app/api/v1/endpoints/security_settings.py fuer
    den Split zwischen dem oeffentlichen (nur Site-Key+Provider) und dem
    admin-only Endpunkt (inkl. Secret-Key).
    """

    __tablename__ = "security_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # "none" | "turnstile" | "recaptcha"
    captcha_provider: Mapped[str] = mapped_column(String(16), default="none", server_default=text("'none'"), nullable=False)
    captcha_enabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("0"), nullable=False)
    # Site-Key ist per Definition oeffentlich (steht im HTML der Login-Seite),
    # Secret-Key wird NUR serverseitig fuer die Verifikation genutzt.
    captcha_site_key: Mapped[str | None] = mapped_column(String(255), nullable=True)
    captcha_secret_key: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # Auf welchen Formularen der Captcha-Check greift.
    captcha_on_login: Mapped[bool] = mapped_column(Boolean, default=True, server_default=text("1"), nullable=False)
    captcha_on_register: Mapped[bool] = mapped_column(Boolean, default=True, server_default=text("1"), nullable=False)


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
    # Kommagetrennte, vorgefertigte Tags (z.B. "tools,dashboard") --
    # bewusst kein eigenes Tags-Table/Many-to-Many fuer diesen ueberschaubaren,
    # festen Satz an Kategorien -- einfacher zu pflegen fuer den Scope hier.
    tags: Mapped[str] = mapped_column(String(200), default="", server_default=text("''"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)

    votes: Mapped[list["FeatureRequestVote"]] = relationship(back_populates="request", cascade="all, delete-orphan")
    comments: Mapped[list["FeatureRequestComment"]] = relationship(back_populates="request", cascade="all, delete-orphan")


class FeatureRequestVote(Base):
    __tablename__ = "feature_request_votes"
    __table_args__ = (UniqueConstraint("request_id", "user_id", name="uq_vote_request_user"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    request_id: Mapped[int] = mapped_column(ForeignKey("feature_requests.id"), nullable=False, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    # +1 = Upvote, -1 = Downvote. server_default=1, weil alle VOR dieser
    # Erweiterung erstellten Stimmen reine Upvotes waren.
    vote_value: Mapped[int] = mapped_column(Integer, default=1, server_default=text("1"), nullable=False)
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


class SavedSshConnection(Base):
    """Gespeicherte SSH-Verbindung fuer die WebSSH-Webshell -- bewusst
    strikt pro Nutzer isoliert (user_id-Filter in JEDER Query, nie ueber
    die ID allein zugreifbar): "diese sind nur als der jeweilige Nutzer
    aufrufbar", wie in der Feature-Anfrage gefordert. Das gespeicherte
    Geheimnis (Passwort ODER privater Schluessel) liegt NIE im Klartext
    in der DB -- verschluesselt ueber app/core/ssh_vault.py (Fernet,
    symmetrischer Schluessel aus SSH_VAULT_KEY bzw. abgeleitet aus
    session_secret als Fallback).
    """

    __tablename__ = "saved_ssh_connections"
    __table_args__ = (UniqueConstraint("user_id", "label", name="uq_ssh_conn_user_label"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    label: Mapped[str] = mapped_column(String(100), nullable=False)
    host: Mapped[str] = mapped_column(String(255), nullable=False)
    port: Mapped[int] = mapped_column(Integer, default=22, server_default=text("22"), nullable=False)
    username: Mapped[str] = mapped_column(String(255), nullable=False)
    # "password" | "key" | "none" (none = beim Verbinden jedes Mal neu abfragen,
    # nur Host/Port/User werden gespeichert -- kein Geheimnis in der DB).
    auth_method: Mapped[str] = mapped_column(String(16), default="none", server_default=text("'none'"), nullable=False)
    encrypted_secret: Mapped[str | None] = mapped_column(String(8192), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    user: Mapped["User"] = relationship()


class OneTimeSecret(Base):
    """Abrufbarer, verschluesselter Geheimnis-Link ("Burn after reading"
    -- Passwoerter/Notizen sicher teilen). Der Token in der URL ist die
    einzige "Berechtigung", ihn zu lesen -- bewusst KEIN Login fuers
    Ansehen noetig, da der Empfaenger typischerweise KEIN eigenes
    Toolbox-Konto hat (Kollege, Kunde, ...). Erstellen erfordert aber
    Login, um Missbrauch der eigenen Infrastruktur als anonymer
    Geheimnis-Speicher zu verhindern.

    Der eigentliche Inhalt wird NIE im Klartext gespeichert (Fernet,
    siehe app/core/ssh_vault.py -- derselbe Verschluesselungs-Mechanismus
    wiederverwendet). Standardmaessig genau EIN Abruf erlaubt
    (max_views=1) -- der Ersteller kann das aber nachtraeglich erhoehen
    (z.B. wenn mehrere Personen denselben Link abrufen sollen) sowie die
    Gueltigkeit verlaengern. Sobald view_count >= max_views erreicht
    ist, wird der Eintrag geloescht -- ein weiterer Abruf findet dann
    buchstaeblich nichts mehr vor.
    """

    __tablename__ = "one_time_secrets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # Kryptographisch zufaelliger Token (secrets.token_urlsafe), NICHT
    # die numerische ID -- wird in der URL verwendet, muss also
    # unerratbar sein (die ID allein waere sequenziell/erratbar).
    token: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    creator_user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    encrypted_content: Mapped[str] = mapped_column(String(16384), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    viewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    max_views: Mapped[int] = mapped_column(Integer, default=1, server_default=text("1"), nullable=False)
    view_count: Mapped[int] = mapped_column(Integer, default=0, server_default=text("0"), nullable=False)

    creator: Mapped["User"] = relationship()


class EmailAlias(Base):
    """Email-Alias fuer anonyme Anmeldungen/Spam-Schutz (aehnlich
    AnonAddy/SimpleLogin): eine eindeutige Adresse alias@domain, die auf
    eine echte Zieladresse weiterleitet. Strikt pro Nutzer isoliert.

    WICHTIG (Infrastruktur-Hinweis): dieses Modell + die zugehoerigen
    Endpunkte sind die reine VERWALTUNGSEBENE (welche Aliase existieren,
    wohin sie weiterleiten sollen, an/aus). Das tatsaechliche EMPFANGEN
    und WEITERLEITEN von E-Mails braucht einen SEPARATEN, eigenstaendigen
    SMTP-Empfangsdienst (z.B. Postfix oder ein aiosmtpd-basierter
    Service) PLUS eine echte Domain mit MX-Record, der auf diesen
    Server zeigt -- das ist NICHT Teil dieses Modells und muss als
    eigenes Infrastruktur-Vorhaben aufgesetzt werden (aehnlich der
    CheckTLS-TestReceiver-Anfrage: ohne echten Mail-Empfang bleibt das
    hier nur die Verwaltungsoberflaeche, ohne dass tatsaechlich Mail
    fliesst).
    """

    __tablename__ = "email_aliases"
    __table_args__ = (UniqueConstraint("local_part", "domain", name="uq_alias_local_domain"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    local_part: Mapped[str] = mapped_column(String(64), nullable=False)
    domain: Mapped[str] = mapped_column(String(255), nullable=False)
    target_email: Mapped[str] = mapped_column(String(255), nullable=False)
    label: Mapped[str | None] = mapped_column(String(100), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default=text("1"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    last_forwarded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    forward_count: Mapped[int] = mapped_column(Integer, default=0, server_default=text("0"), nullable=False)

    user: Mapped["User"] = relationship()


class AdguardSettings(Base):
    """Instanzweite Verbindungsdaten fuer AdGuard Home (Singleton, id=1)
    -- fuer den "DNS-Cache leeren"-Button. AdGuard Home cached DNS-
    Antworten lokal; nach Aenderungen an eigenen DNS-Records kann ein
    veralteter Cache-Eintrag die Aktualisierung verzoegern (bekanntes,
    von AdGuard Home selbst dokumentiertes Verhalten). Das Passwort wird
    NIE im Klartext gespeichert -- Fernet-verschluesselt, siehe
    app/core/ssh_vault.py.
    """

    __tablename__ = "adguard_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    configured: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("0"), nullable=False)
    base_url: Mapped[str | None] = mapped_column(String(255), nullable=True)
    username: Mapped[str | None] = mapped_column(String(255), nullable=True)
    encrypted_password: Mapped[str | None] = mapped_column(String(2048), nullable=True)
