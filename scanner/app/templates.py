"""Feste Argument-Templates pro Scan-Profil.

WICHTIG: Der User (ueber das Backend) kann NIEMALS eigene nmap-Flags
uebergeben -- nur Zielwert und ggf. eine Portzahl/-liste, die bereits im
Backend validiert wurde und hier nochmal validiert wird. Die eigentlichen
Nmap-Flags sind hart in diesem Modul verdrahtet. Das verhindert strukturell,
dass jemand z.B. `--script` mit beliebigen NSE-Scripts einschleust.
"""

from app.common import is_valid_target


class InvalidJobError(Exception):
    pass


def _require_target(params: dict) -> str:
    target = params.get("target", "")
    if not is_valid_target(target):
        raise InvalidJobError(f"Ungueltiges Ziel: {target!r}")
    return target


def build_quick(params: dict) -> list[str]:
    target = _require_target(params)
    return ["nmap", "-T4", "-F", "-oX", "-", target]


def build_top_ports(params: dict) -> list[str]:
    target = _require_target(params)
    count = int(params.get("count", 100))
    count = max(1, min(count, 1000))
    return ["nmap", "-T4", "--top-ports", str(count), "-oX", "-", target]


def build_service_detection(params: dict) -> list[str]:
    target = _require_target(params)
    ports = params.get("ports", [])
    if not ports or not all(isinstance(p, int) and 1 <= p <= 65535 for p in ports):
        raise InvalidJobError(f"Ungueltige Ports: {ports!r}")
    if len(ports) > 20:
        raise InvalidJobError("Zu viele Ports fuer Service Detection (max. 20)")
    port_arg = ",".join(str(p) for p in ports)
    return ["nmap", "-T4", "-sV", "-p", port_arg, "-oX", "-", target]


def build_os_detection(params: dict) -> list[str]:
    target = _require_target(params)
    return ["nmap", "-T4", "-O", "-oX", "-", target]


def build_aggressive(params: dict) -> list[str]:
    target = _require_target(params)
    return ["nmap", "-T4", "-A", "-oX", "-", target]


def build_udp(params: dict) -> list[str]:
    target = _require_target(params)
    count = int(params.get("count", 20))
    count = max(1, min(count, 50))
    return ["nmap", "-T4", "-sU", "--top-ports", str(count), "-oX", "-", target]


def build_nikto(params: dict) -> list[str]:
    """Nikto-Webserver-Scan -- wie bei nmap ausschliesslich feste Flags,
    NIE vom Nutzer frei waehlbare Kommandozeilenargumente.

    WICHTIG: Anders als nmap (`-oX -` schreibt XML nach stdout) unterstuetzt
    Nikto KEIN '-' als Stdout-Platzhalter fuer '-output' -- das fuehrte in
    der Praxis dazu, dass Nikto stattdessen seine normalen Status-/
    Fortschrittsmeldungen auf stdout ausgab (kein gueltiges JSON), waehrend
    '-output -' vermutlich als woertlicher Dateiname interpretiert wurde.
    Der Worker uebergibt hier einen echten temporaeren Dateipfad
    (params['_output_path']), liest die Datei nach dem Lauf ein und
    loescht sie wieder -- kein dauerhafter Speicher der Scan-Ergebnisse
    auf der Platte.
    """
    target = _require_target(params)
    output_path = params.get("_output_path")
    if not output_path:
        raise InvalidJobError("Interner Fehler: kein Ausgabe-Pfad fuer Nikto gesetzt")
    return [
        "nikto", "-h", target, "-Format", "json", "-output", output_path,
        "-maxtime", "180s",  # harte Obergrenze, unabhaengig vom Subprocess-Timeout unten
        "-ask", "no",  # nie interaktiv nachfragen (z.B. bei SSL-Zertifikatsfehlern)
    ]


TEMPLATES = {
    "quick": build_quick,
    "top-ports": build_top_ports,
    "service-detection": build_service_detection,
    "os-detection": build_os_detection,
    "aggressive": build_aggressive,
    "udp": build_udp,
    "nikto": build_nikto,
}
