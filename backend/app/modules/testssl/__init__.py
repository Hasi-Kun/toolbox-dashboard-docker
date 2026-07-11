"""testssl-Kategorie: gruendlicher TLS/SSL-Schwachstellen-Scanner
(testssl.sh) -- is_active_scan=True, delegiert an den isolierten
toolbox-scanner-Container ueber die Redis-Queue, genau wie die
nmap-Kategorie."""

from app.modules.testssl import deep_scan  # noqa: F401
