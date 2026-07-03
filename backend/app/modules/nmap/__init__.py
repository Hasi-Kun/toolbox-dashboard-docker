"""Nmap-Kategorie: alle Module sind is_active_scan=True und delegieren die
eigentliche Ausfuehrung an den isolierten toolbox-scanner-Container ueber
eine Redis-Queue (siehe app/core/scan_queue.py).
"""

from app.modules.nmap import (  # noqa: F401
    aggressive,
    os_detection,
    quick,
    service_detection,
    top_ports,
    udp,
)
