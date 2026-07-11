"""Security-Kategorie: SSL Checker, Security Headers, robots.txt, security.txt.

Jedes Submodul registriert sich beim Import selbst per @register_module.
"""

from app.modules.security import cookie_security_analyzer, cors_checker, domain_security_check, headers, http_methods_checker, jwt_security_analyzer, open_redirect_checker, password_breach_check, reflected_input_checker, robots, security_txt, ssl_checker, sri_checker, tls_cipher_audit, vulnerability_indicators, waf_detector  # noqa: F401
