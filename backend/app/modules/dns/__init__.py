"""DNS-Kategorie: Lookup, Reverse Lookup, Propagation.

Jedes Submodul registriert sich beim Import selbst per
@register_module -- die Reihenfolge hier ist irrelevant.
"""

from app.modules.dns import lookup, propagation, reverse, zone_transfer_check  # noqa: F401
