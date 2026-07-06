"""Alembic-Umgebung. Nutzt die echte App-Konfiguration (DATABASE_URL aus
den Settings) statt eine zweite Config-Quelle zu pflegen, und importiert
Base.metadata direkt aus den App-Modellen fuer Autogenerate.
"""

import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import engine_from_config, pool

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.config import get_settings  # noqa: E402
from app.core.db import Base  # noqa: E402
from app.models import user as _user_models  # noqa: F401,E402  (registriert alle Modelle in Base.metadata)

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

settings = get_settings()
config.set_main_option("sqlalchemy.url", settings.database_url)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(url=url, target_metadata=target_metadata, literal_binds=True, dialect_opts={"paramstyle": "named"})
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(config.get_section(config.config_ini_section, {}), prefix="sqlalchemy.", poolclass=pool.NullPool)

    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata, render_as_batch=True)
        # render_as_batch=True: SQLite unterstuetzt kein ALTER COLUMN direkt --
        # Batch-Modus baut die Tabelle stattdessen neu auf, wenn noetig.
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
