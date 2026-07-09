"""Gemeinsame Bausteine fuer alle DNS- und Mail-Module.

Bewusst zentral, damit Validierung und Query-Logik nur an einer Stelle
existieren -- neue Module (SPF, DKIM, DMARC, Propagation) bauen alle
auf `query()` auf statt eigene Resolver-Logik zu duplizieren.
"""

from __future__ import annotations

import ipaddress
import re

import dns.asyncresolver
import dns.exception
import dns.resolver

HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


def is_valid_hostname(value: str) -> bool:
    """Strenge Hostname-Validierung -- kein Freitext, keine Sonderzeichen.

    Bewusst restriktiv statt "escapend": lieber eine gueltige Domain
    ablehnen als ein Zeichen durchlassen, das spaeter Probleme macht.
    """
    return bool(HOSTNAME_RE.match(value))


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


# 10 global verteilte, oeffentliche Resolver fuer Propagation-Checks.
PUBLIC_RESOLVERS: dict[str, str] = {
    "Google": "8.8.8.8",
    "Cloudflare": "1.1.1.1",
    "Quad9": "9.9.9.9",
    "OpenDNS": "208.67.222.222",
    "Comodo Secure DNS": "8.26.56.26",
    "Level3": "4.2.2.1",
    "Verisign": "64.6.64.6",
    "CleanBrowsing": "185.228.168.9",
    "AdGuard DNS": "94.140.14.14",
    "DNS.WATCH": "84.200.69.80",
}

# Gaengige DKIM-Selectoren fuer den automatischen Fallback, wenn der
# User keinen Selector angibt.
COMMON_DKIM_SELECTORS: list[str] = [
    "default", "google", "selector1", "selector2", "k1", "k2",
    "dkim", "mail", "smtp", "s1", "s2", "mx", "email", "sig1", "dkim1",
    "hse1", "hse2",  # Hornetsecurity (Delegation per CNAME statt eigenem TXT-Key)
]


async def query(
    domain: str,
    record_type: str,
    nameserver: str | None = None,
    timeout: float = 5.0,
) -> dict:
    """Fuehrt einen einzelnen DNS-Query aus, immer mit Timeout, nie ueber Shell.

    Gibt immer ein einheitliches dict zurueck (nie eine Exception), damit
    aufrufende Module den Fehlerfall ohne try/except-Ketten behandeln
    koennen.
    """
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    if nameserver:
        resolver.nameservers = [nameserver]

    try:
        answer = await resolver.resolve(domain, record_type)
        records = [rdata.to_text() for rdata in answer]
        ttl = answer.rrset.ttl if answer.rrset is not None else None
        return {"success": True, "records": records, "ttl": ttl, "error": None}
    except dns.resolver.NXDOMAIN:
        return {"success": False, "records": [], "ttl": None, "error": "NXDOMAIN -- Domain existiert nicht"}
    except dns.resolver.NoAnswer:
        return {"success": False, "records": [], "ttl": None, "error": f"Kein {record_type}-Record vorhanden"}
    except dns.resolver.NoNameservers:
        return {"success": False, "records": [], "ttl": None, "error": "Keine Nameserver erreichbar"}
    except dns.exception.Timeout:
        return {"success": False, "records": [], "ttl": None, "error": "Zeitueberschreitung bei der Anfrage"}
    except Exception as exc:  # noqa: BLE001 -- bewusst breit, wird als Fehlertext zurueckgegeben
        return {"success": False, "records": [], "ttl": None, "error": str(exc)}
