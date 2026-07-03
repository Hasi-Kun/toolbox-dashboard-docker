"""Netzwerk-Kategorie: Ping, Traceroute, Whois, Port-Check.

Jedes Submodul registriert sich beim Import selbst per @register_module.
"""

from app.modules.network import ping, port_check, traceroute, whois  # noqa: F401