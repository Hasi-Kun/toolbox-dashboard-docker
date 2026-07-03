import logging
import sys

from app.core.config import get_settings


def configure_logging() -> None:
    """Einheitliches, strukturiertes Logging fuer alle Module.

    Bewusst simpel gehalten in Phase 1 -- JSON-Logging und Audit-Log
    (wer hat wann welches Modul mit welchem Ziel aufgerufen) folgt,
    sobald die ersten aktiven Module existieren.
    """
    settings = get_settings()

    logging.basicConfig(
        level=settings.log_level,
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        stream=sys.stdout,
    )
