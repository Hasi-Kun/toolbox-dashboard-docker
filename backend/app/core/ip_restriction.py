"""Hilfsfunktionen fuer die optionale Login-IP-Beschraenkung: validiert
eine kommagetrennte Liste aus IPs/CIDR-Bereichen und prueft, ob eine
gegebene Client-IP darin enthalten ist.
"""

import ipaddress

MAX_ENTRIES = 20


def parse_and_validate(raw: str) -> list[str]:
    """Parst eine kommagetrennte Liste aus IPs/CIDR-Bereichen, wirft
    ValueError bei ungueltigen Eintraegen. Gibt die normalisierte Liste
    zurueck (fuehrende/folgende Leerzeichen entfernt, Duplikate raus)."""
    entries = [e.strip() for e in raw.split(",") if e.strip()]
    if len(entries) > MAX_ENTRIES:
        raise ValueError(f"Maximal {MAX_ENTRIES} Eintraege erlaubt")

    normalized = []
    for entry in entries:
        try:
            if "/" in entry:
                network = ipaddress.ip_network(entry, strict=False)
                normalized.append(str(network))
            else:
                normalized.append(str(ipaddress.ip_address(entry)))
        except ValueError as exc:
            raise ValueError(f"Ungueltige IP/CIDR-Angabe: '{entry}'") from exc

    # Duplikate entfernen, Reihenfolge beibehalten
    seen = set()
    result = []
    for entry in normalized:
        if entry not in seen:
            seen.add(entry)
            result.append(entry)
    return result


def is_ip_allowed(client_ip: str, allowed_raw: str | None) -> bool:
    """Leer/None = keine Einschraenkung, immer erlaubt. Sonst muss die
    Client-IP zu mindestens einem Eintrag (einzelne IP oder CIDR-Bereich)
    passen."""
    if not allowed_raw or not allowed_raw.strip():
        return True

    try:
        client = ipaddress.ip_address(client_ip)
    except ValueError:
        return False  # Unparsebare Client-IP -- im Zweifel ablehnen

    for entry in (e.strip() for e in allowed_raw.split(",") if e.strip()):
        try:
            if "/" in entry:
                if client in ipaddress.ip_network(entry, strict=False):
                    return True
            elif client == ipaddress.ip_address(entry):
                return True
        except ValueError:
            continue  # Ein einzelner kaputter Eintrag soll nicht alles blockieren

    return False
