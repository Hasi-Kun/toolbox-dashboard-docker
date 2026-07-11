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


def build_host_discovery(params: dict) -> list[str]:
    """Reiner Ping-Scan (-sn) -- prueft nur, ob das Ziel erreichbar ist,
    OHNE irgendwelche Ports zu scannen. Schnell und unauffaellig."""
    target = _require_target(params)
    return ["nmap", "-T4", "-sn", "-oX", "-", target]


def build_full_port_scan(params: dict) -> list[str]:
    """Scannt ALLE 65535 Ports (-p-) statt nur der gaengigsten -- deutlich
    gruendlicher, aber auch deutlich langsamer als quick/top-ports."""
    target = _require_target(params)
    return ["nmap", "-T4", "-p-", "-oX", "-", target]


def build_vuln_scan(params: dict) -> list[str]:
    """Nutzt NUR nmaps eigene, mit dem Programm mitgelieferte 'vuln'-
    Script-Kategorie (bekannte, vom nmap-Projekt selbst gepflegte und
    read-only Pruefungen) -- bewusst NICHT '--script' mit einem vom Nutzer
    waehlbaren Skriptnamen, das waere eine strukturelle NSE-Injection-
    Luecke. Die Kategorie 'vuln' selbst ist fest verdrahtet, nicht
    variabel."""
    target = _require_target(params)
    return ["nmap", "-T4", "--script", "vuln", "-oX", "-", target]


NIKTO_BIN = "/opt/nikto/program/nikto.pl"


def build_nikto(params: dict) -> list[str]:
    """Nikto-Webserver-Scan -- wie bei nmap ausschliesslich feste Flags,
    NIE vom Nutzer frei waehlbare Kommandozeilenargumente.

    Nutzt XML-Ausgabe statt JSON (siehe nikto_parser.py fuer die
    Begruendung -- Niktos JSON-Report-Plugin hat sich in dieser Umgebung
    wiederholt als nicht funktionsfaehig erwiesen, XML ist der laenger
    etablierte, ausgereiftere Pfad).

    Echter temporaerer Dateipfad statt '-' -- Nikto unterstuetzt kein
    Stdout-Streaming fuer -output. Der Worker uebergibt hier
    params['_output_path'], liest die Datei nach dem Lauf ein und loescht
    sie wieder -- kein dauerhafter Speicher der Scan-Ergebnisse.
    """
    target = _require_target(params)
    output_path = params.get("_output_path")
    if not output_path:
        raise InvalidJobError("Interner Fehler: kein Ausgabe-Pfad fuer Nikto gesetzt")
    return [
        NIKTO_BIN, "-h", target, "-Format", "xml", "-output", output_path,
        "-maxtime", "180s",  # harte Obergrenze, unabhaengig vom Subprocess-Timeout unten
        "-ask", "no",  # nie interaktiv nachfragen (z.B. bei SSL-Zertifikatsfehlern)
    ]


TESTSSL_BIN = "/opt/testssl/testssl.sh"


def build_testssl(params: dict) -> list[str]:
    """testssl.sh -- gruendlicher TLS/SSL-Pruefer (Heartbleed, POODLE,
    ROBOT, DROWN, LOGJAM, Ticketbleed, CCS-Injection, BEAST, FREAK,
    LUCKY13, SWEET32 u.a.). Wie bei Nikto: NUR feste Flags, nie vom
    Nutzer frei waehlbare Kommandozeilenargumente.

    Echter temporaerer Dateipfad fuer --jsonfile statt Stdout -- testssl.sh
    unterstuetzt kein direktes JSON-Streaming nach stdout (--jsonfile -
    wuerde woertlich eine Datei namens '-' anlegen, siehe testssl-Issue
    #1290). Der Worker uebergibt hier params['_output_path'], liest die
    Datei nach dem Lauf ein und loescht sie wieder.
    """
    target = _require_target(params)
    port = params.get("port", 443)
    if not isinstance(port, int) or not (1 <= port <= 65535):
        raise InvalidJobError("Ungueltiger Port")

    output_path = params.get("_output_path")
    if not output_path:
        raise InvalidJobError("Interner Fehler: kein Ausgabe-Pfad fuer testssl.sh gesetzt")

    return [
        TESTSSL_BIN,
        "--quiet",  # keine interaktive Warnung/Bestaetigung noetig
        "--color", "0",
        "--jsonfile", output_path,
        "--severity", "LOW",  # alles ab LOW protokollieren (nicht nur HIGH/CRITICAL)
        f"{target}:{port}",
    ]


TEMPLATES = {
    "quick": build_quick,
    "top-ports": build_top_ports,
    "service-detection": build_service_detection,
    "os-detection": build_os_detection,
    "aggressive": build_aggressive,
    "udp": build_udp,
    "host-discovery": build_host_discovery,
    "full-port-scan": build_full_port_scan,
    "vuln-scan": build_vuln_scan,
    "nikto": build_nikto,
    "testssl": build_testssl,
}
