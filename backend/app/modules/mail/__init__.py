"""Mail-Kategorie: SPF, DKIM, DMARC.

Alle drei bauen auf den DNS-Basisfunktionen aus
`app.modules.dns.common` auf, sind aber inhaltlich Mail-Security-Tools,
daher eigene Kategorie/eigenes Package.
"""

from app.modules.mail import dkim, dmarc, spf  # noqa: F401
