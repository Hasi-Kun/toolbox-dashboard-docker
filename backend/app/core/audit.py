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
    return request.headers.get("x-real-ip") or (request.client.host if request.client else None)
