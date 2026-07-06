"""Sehr leichtgewichtige Migrationshilfe fuer SQLite -- Sicherheitsnetz,
NICHT die primaere Migrationsstrategie (das ist Alembic, siehe
migrations/ und app/scripts/run_migrations.py).

`Base.metadata.create_all()` legt nur FEHLENDE Tabellen an, aendert aber
niemals bestehende Tabellen. Diese Funktion schliesst genau die Luecke:
fehlende SPALTEN an bereits existierenden Tabellen nachtraeglich anlegen.

WICHTIG -- Lehre aus einem echten Vorfall: Diese Liste war frueher eine
HANDGEPFLEGTE Aufzaehlung (Tabelle, Spalte, DDL-String), die bei jeder
neuen Migration manuell nachgezogen werden musste. Genau das wurde einmal
vergessen, wodurch der automatische Recovery-Pfad in
run_migrations.py (der bei einem 'already exists'-Fehler hierher
zurueckfaellt) fehlende SPALTEN nicht mitbekam, obwohl er fehlende
TABELLEN korrekt nachzog. Jetzt wird die Spalten-Liste automatisch aus
Base.metadata abgeleitet -- neue Modell-Felder brauchen dafuer KEINE
manuelle Pflege mehr an dieser Stelle.
"""

import logging

from sqlalchemy import Engine, text
from sqlalchemy.schema import CreateColumn

from app.core.db import Base

logger = logging.getLogger("toolbox.migrations")


def run_light_migrations(engine: Engine) -> None:
    with engine.connect() as conn:
        # Nur Tabellen anfassen, die tatsaechlich existieren (frische
        # Installationen haben sie schon vollstaendig ueber create_all/Alembic).
        existing_tables = {
            row[0] for row in conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'"))
        }

        for table_name, table in Base.metadata.tables.items():
            if table_name not in existing_tables:
                continue  # komplett fehlende Tabellen sind Alembics/create_all's Aufgabe, nicht hier

            existing_columns = {row[1] for row in conn.execute(text(f"PRAGMA table_info({table_name})"))}

            for column in table.columns:
                if column.name in existing_columns:
                    continue
                # DDL-Fragment direkt aus der SQLAlchemy-Spaltendefinition
                # kompilieren -- automatisch konsistent mit dem Modell,
                # keine manuell gepflegte Zweitliste mehr noetig.
                ddl_fragment = str(CreateColumn(column).compile(dialect=conn.dialect))
                logger.info("Migration: fuege Spalte %s.%s hinzu", table_name, column.name)
                try:
                    conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {ddl_fragment}"))
                except Exception:
                    logger.exception("Konnte Spalte %s.%s nicht automatisch hinzufuegen", table_name, column.name)
                    raise

        conn.commit()
