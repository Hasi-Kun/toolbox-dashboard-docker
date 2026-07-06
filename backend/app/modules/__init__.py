"""Modul-Package.

Sobald Kategorien (dns, network, security, ...) als Unterpakete existieren,
werden sie hier importiert, damit sich ihre Module ueber `register_module`
selbst eintragen. Phase 1 hat bewusst noch keine echten Module.

Beispiel (Phase 2):

    from app.modules.dns import lookup  # noqa: F401  (Registrierung per Import-Seiteneffekt)
"""

from app.modules.base import get_registry, list_modules_metadata  # noqa: F401
from app.modules import dns  # noqa: F401  (Registrierung per Import-Seiteneffekt)
from app.modules import mail  # noqa: F401  (Registrierung per Import-Seiteneffekt)
from app.modules import network  # noqa: F401  (Registrierung per Import-Seiteneffekt)
from app.modules import security  # noqa: F401  (Registrierung per Import-Seiteneffekt)
from app.modules import nmap  # noqa: F401  (Registrierung per Import-Seiteneffekt)
from app.modules import utilities  # noqa: F401  (Registrierung per Import-Seiteneffekt)
from app.modules import certificates  # noqa: F401  (Registrierung per Import-Seiteneffekt)
from app.modules import website  # noqa: F401  (Registrierung per Import-Seiteneffekt)
from app.modules import osint  # noqa: F401  (Registrierung per Import-Seiteneffekt)
