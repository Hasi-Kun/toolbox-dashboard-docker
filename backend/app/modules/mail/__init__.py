"""Mail-Kategorie: SPF, DKIM, DMARC.

Alle drei bauen auf den DNS-Basisfunktionen aus
`app.modules.dns.common` auf, sind aber inhaltlich Mail-Security-Tools,
daher eigene Kategorie/eigenes Package.
"""

from app.modules.mail import blacklist_check, dane_check, dkim, dkim_signature_inspector, dmarc, ghost_sender_check, smtp_debug, smtp_tls_check, spf  # noqa: F401
