"""Utilities-Kategorie: Hash Generator, Base64, JWT Decoder, UUID Generator,
Passwort Generator, CIDR Rechner, Timestamp Konverter.

Jedes Submodul registriert sich beim Import selbst per @register_module.
"""

from app.modules.utilities import (  # noqa: F401
    base64_tool,
    cidr_calculator,
    fastviewer_status,
    hash_generator,
    hash_identifier,
    ip_geolocation,
    jwt_decoder,
    ntlm_hash,
    password_generator,
    timestamp_converter,
    uuid_generator,
)
