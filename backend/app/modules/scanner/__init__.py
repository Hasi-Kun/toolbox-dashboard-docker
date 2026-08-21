"""Scanner-Kategorie (frueher "nmap" + "testssl" getrennt, jetzt
zusammengefuehrt): alle Module sind is_active_scan=True und delegieren
die eigentliche Ausfuehrung an den isolierten toolbox-scanner-Container
ueber eine Redis-Queue (siehe app/core/scan_queue.py).
"""

from app.modules.scanner import (  # noqa: F401
    aggressive,
    full_port_scan,
    host_discovery,
    nikto_scan,
    os_detection,
    quick,
    service_detection,
    testssl_deep_scan,
    top_ports,
    udp,
    vuln_scan,
)
