from sqlalchemy.orm import Session

from app.models.user import AuditLogEntry


def log_audit_event(
    db: Session,
    event_type: str,
    success: bool,
    username: str | None = None,
    ip_address: str | None = None,
    detail: str | None = None,
) -> None:
    """Schreibt einen Audit-Log-Eintrag. Darf niemals eine Anfrage zum
    Scheitern bringen -- Logging ist "nice to have", kein kritischer Pfad.
    """
    try:
        db.add(
            AuditLogEntry(
                event_type=event_type,
                username=username,
                ip_address=ip_address,
                success=success,
                detail=detail[:500] if detail else None,
            )
        )
        db.commit()
    except Exception:  # noqa: BLE001
        db.rollback()


def get_client_ip(request) -> str | None:  # noqa: ANN001 -- Request-Typ variiert (FastAPI Request)
    """Ermittelt die echte Besucher-IP, robust gegenueber verschiedenen
    Reverse-Proxy-Konfigurationen. Prueft mehrere ueblicherweise gesetzte
    Header der Reihe nach, statt sich auf genau einen zu verlassen --
    falls z.B. X-Real-IP (noch) nicht konfiguriert ist, greift stattdessen
    X-Forwarded-For (das Caddy standardmaessig automatisch setzt) oder
    CF-Connecting-IP (Cloudflares eigener Header, falls direkt
    durchgereicht). Erst wenn KEINER davon vorhanden ist, wird auf die
    rohe TCP-Peer-Adresse zurueckgefallen (im Docker-Netz dann die interne
    Container-IP -- das Signal, dass keiner der Header ankommt).
    """
    for header in ("x-real-ip", "cf-connecting-ip", "x-forwarded-for"):
        value = request.headers.get(header)
        if value:
            # X-Forwarded-For kann eine kommagetrennte Kette sein
            # (Client, Proxy1, Proxy2, ...) -- der erste Eintrag ist der
            # urspruengliche Client.
            return value.split(",")[0].strip()

    return request.client.host if request.client else None
