"""Sehr leichtgewichtige Migrationshilfe fuer SQLite.

`Base.metadata.create_all()` legt nur FEHLENDE Tabellen an, aendert aber
niemals bestehende Tabellen. Wenn ein Modell um Spalten erweitert wird
(wie hier `appearance_settings`), muessen bestehende Installationen einen
Weg bekommen, diese Spalten nachtraeglich zu erhalten -- ohne dass die
Datenbank-Datei geloescht werden muss.

Das ist bewusst minimal (nur ADD COLUMN, keine Typaenderungen, keine
Downgrades) und ein Uebergangswerkzeug, bis das Projekt auf Alembic
umsteigt (siehe docs/ARCHITECTURE.md).
"""

import logging

from sqlalchemy import Engine, text

logger = logging.getLogger("toolbox.migrations")

# (Tabelle, Spalte, DDL-Fragment fuer ADD COLUMN)
_PENDING_COLUMNS: list[tuple[str, str, str]] = [
    ("appearance_settings", "animation_speed", "FLOAT DEFAULT 1.0"),
    ("appearance_settings", "gradient_color", "VARCHAR(9) DEFAULT '#35E0C0'"),
    ("appearance_settings", "interactive_dots", "BOOLEAN DEFAULT 1"),
]


def run_light_migrations(engine: Engine) -> None:
    with engine.connect() as conn:
        # Nur Tabellen anfassen, die tatsaechlich existieren (frische
        # Installationen haben sie schon vollstaendig ueber create_all).
        existing_tables = {
            row[0] for row in conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'"))
        }

        for table, column, ddl_type in _PENDING_COLUMNS:
            if table not in existing_tables:
                continue
            existing_columns = {row[1] for row in conn.execute(text(f"PRAGMA table_info({table})"))}
            if column in existing_columns:
                continue
            logger.info("Migration: fuege Spalte %s.%s hinzu", table, column)
            conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {ddl_type}"))

        conn.commit()
