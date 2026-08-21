import ipaddress
import logging

from sqlalchemy.orm import Session

from app.models.user import AuditLogEntry

logger = logging.getLogger("toolbox.audit")

# Cloudflares eigene, oeffentlich dokumentierte IP-Bereiche
# (https://www.cloudflare.com/ips/, Stand 2026). Eine ECHTE Besucher-IP
# sollte hier praktisch NIE hineinfallen -- taucht so ein Bereich in
# einem Audit-Log-Eintrag auf, ist das ein starkes Signal, dass
# irgendwo in der Kette (Caddy/Cloudflare-Konfiguration) statt der
# echten Client-IP versehentlich Cloudflares eigene Edge-IP
# durchgereicht wurde, statt der in CF-Connecting-IP mitgelieferten.
_CLOUDFLARE_RANGES = [
    ipaddress.ip_network(cidr)
    for cidr in (
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
        "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
        "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
        "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
    )
]


def _looks_like_cloudflare_edge_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(ip in net for net in _CLOUDFLARE_RANGES)


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
    Reverse-Proxy-Konfigurationen.

    Reihenfolge bewusst CF-Connecting-IP ZUERST (statt X-Real-IP): das ist
    Cloudflares eigener, dediziert dafuer gesetzter Header und damit die
    verlaesslichste Quelle, wenn die Instanz hinter Cloudflare laeuft --
    unabhaengig davon, ob eine zwischengeschaltete header_up-Regel (Caddy)
    X-Real-IP korrekt daraus ableitet oder nicht. X-Real-IP und
    X-Forwarded-For bleiben als Fallback fuer Deployments ohne Cloudflare.

    Diagnose-Log: faellt der ermittelte Wert selbst in einen von
    Cloudflares EIGENEN oeffentlichen IP-Bereichen, wird das als Warnung
    geloggt -- eine echte Besucher-IP sollte dort praktisch nie
    hineinfallen. Das deutet darauf hin, dass der jeweilige Header fuer
    diese Anfrage nicht die echte Client-IP enthielt (z.B. weil
    CF-Connecting-IP fehlte und auf X-Forwarded-For zurueckgefallen
    wurde, dessen naechster Hop dann Cloudflares eigener Edge-Server
    war) -- ein Hinweis, die Caddy-/Cloudflare-Konfiguration zu pruefen
    (siehe docs/CADDY.md), nicht automatisch behebbar.
    """
    for header in ("cf-connecting-ip", "x-real-ip", "x-forwarded-for"):
        value = request.headers.get(header)
        if value:
            # X-Forwarded-For kann eine kommagetrennte Kette sein
            # (Client, Proxy1, Proxy2, ...) -- der erste Eintrag ist der
            # urspruengliche Client.
            ip = value.split(",")[0].strip()
            if _looks_like_cloudflare_edge_ip(ip):
                logger.warning(
                    "get_client_ip: aus Header '%s' ermittelte IP %s liegt in einem "
                    "Cloudflare-eigenen Bereich -- vermutlich keine echte Besucher-IP. "
                    "Alle IP-Header dieser Anfrage: cf-connecting-ip=%r x-real-ip=%r x-forwarded-for=%r",
                    header, ip,
                    request.headers.get("cf-connecting-ip"),
                    request.headers.get("x-real-ip"),
                    request.headers.get("x-forwarded-for"),
                )
            return ip

    return request.client.host if request.client else None
