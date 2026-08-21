"""Converter-Kategorie (frueher "utilities", jetzt auf reine Format-
Konvertierung/-Generierung verschlankt -- Lookup-Tools wie IP-
Geolocation und der FastViewer-Statuscheck sind nach "network"
umgezogen, da sie inhaltlich naeher an Whois/Ping als an einer
Formatumwandlung sind).

Jedes Submodul registriert sich beim Import selbst per @register_module.
"""

from app.modules.converter import (  # noqa: F401
    base64_tool,
    cidr_calculator,
    hash_generator,
    hash_identifier,
    json_formatter,
    jwt_decoder,
    ntlm_hash,
    password_generator,
    timestamp_converter,
    uuid_generator,
)
