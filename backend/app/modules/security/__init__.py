"""Security-Kategorie: SSL Checker, Security Headers, robots.txt, security.txt.

Jedes Submodul registriert sich beim Import selbst per @register_module.
"""

from app.modules.security import headers, robots, security_txt, ssl_checker, vulnerability_indicators  # noqa: F401
