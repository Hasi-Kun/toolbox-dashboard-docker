"""Netzwerk-Kategorie: Ping, Traceroute, Whois, Port-Check -- plus
IP-Geolocation und FastViewer-Statuscheck (von "utilities"/"converter"
hierher verschoben, da beides Lookup-/Connectivity-Tools sind statt
Format-Konvertierungen).

Jedes Submodul registriert sich beim Import selbst per @register_module.
"""

from app.modules.network import fastviewer_status, ip_geolocation, ping, port_check, traceroute, whois  # noqa: F401
