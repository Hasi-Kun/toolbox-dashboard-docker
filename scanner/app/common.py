"""Eigenstaendige Validierung im Scanner-Container.

Bewusst dupliziert statt aus dem Backend importiert: Scanner und Backend
sind getrennte Container/Codebases (siehe Architektur -- der Scanner soll
nicht vom Backend-Code abhaengen). Das Backend validiert bereits vor dem
Einreihen in die Queue, aber der Scanner vertraut niemals blind auf das,
was in der Queue liegt -- Defense in Depth.
"""

import ipaddress
import re

HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


def is_valid_target(value: str) -> bool:
    if HOSTNAME_RE.match(value):
        return True
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
