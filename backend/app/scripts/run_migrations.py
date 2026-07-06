"""Migrations-Runner: einmaliger Bootstrap von der alten Leichtgewicht-
Migration (app/core/migrations.py) zu echten Alembic-Migrationen, danach
nur noch normales `alembic upgrade head`.

Ablauf:
1. Frische Installation (keine 'users'-Tabelle) -> direkt `alembic upgrade
   head`, Alembic legt alles selbst an.
2. Bestehende Installation OHNE Alembic-Tracking (hat 'users', aber noch
   keine 'alembic_version') -> einmaliger Bootstrap: create_all() +
   run_light_migrations() bringen das Schema auf den aktuellen Modellstand,
   dann `alembic stamp head` (nur EINMAL, siehe Warnung unten).
3. Bestehende Installation MIT Alembic-Tracking -> normales `alembic
   upgrade head`. WICHTIG: hier laeuft niemals create_all(), weil das
   sonst mit den CREATE-TABLE-Anweisungen kuenftiger Migrationen
   kollidiert (siehe Incident unten).
4. Selbstheilung: falls die Datenbank durch einen fruehreren Absturz
   bereits Tabellen physisch enthaelt, die eine ausstehende Migration
   noch anlegen will (weil Schritt 3 vor dem Fix hier faelschlich
   create_all() aufgerufen hat), wird das erkannt und stattdessen
   gestempelt statt erneut zu versuchen, sie anzulegen.

INCIDENT (behoben): Eine fruehere Version dieses Skripts rief
create_all() bei JEDER bestehenden Installation auf, auch wenn Alembic
das Schema laengst selbst verwaltete. Beim Ausliefern der naechsten
Migration (chat_messages, feature_requests, ...) legte create_all() die
neuen Tabellen ueber SQLAlchemy direkt an, WORAUFHIN Alembics eigene
Migration dieselben Tabellen nochmal per CREATE TABLE anlegen wollte --
Kollision, Absturz, Backend startete nie ("table chat_messages already
exists"). Fix: create_all() laeuft jetzt ausschliesslich im einmaligen
Bootstrap-Fall (Schritt 2), nie wieder danach.

SELBSTHEILUNG bewusst NICHT ueber eine Vorab-Pruefung "existieren alle
Tabellen schon" geloest -- das wuerde bei einer kuenftigen Migration, die
nur eine SPALTE zu einer bestehenden Tabelle hinzufuegt (kein CREATE
TABLE), faelschlich "alles da, einfach stempeln" annehmen und die echte
Spaltenaenderung stillschweigend uebergehen. Stattdessen: normal
versuchen zu migrieren, und NUR wenn der Fehler explizit "already exists"
lautet (= Tabellen sind schon da, aber alembic_version ist veraltet),
gezielt nachstempeln. Jeder andere Fehler wird nicht verschluckt, sondern
wie bisher laut zum Absturz gebracht -- ein echter Migrationsfehler soll
sichtbar bleiben, nicht automatisch uebertuencht werden.

Wird als CMD-Vorstufe im Dockerfile ausgefuehrt, bevor uvicorn startet.
"""

import logging
import subprocess
from pathlib import Path

from sqlalchemy import inspect, text

from app.core.db import Base, engine
from app.core.migrations import run_light_migrations
from app.models import user as _user_models  # noqa: F401

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | migrations | %(message)s")
logger = logging.getLogger("toolbox.migrations.runner")

BACKEND_ROOT = Path(__file__).resolve().parent.parent.parent

# Revision-IDs, die in fruehreren Paketversionen kurzzeitig existierten und
# durch eine spaetere Korrektur umbenannt/ersetzt wurden (siehe README,
# Hotfix 4). Wurde ein Paket zwischenzeitlich per 'unzip -o' in denselben
# Ordner wie eine dieser Versionen entpackt, bleibt die alte Datei liegen
# (unzip loescht nie Dateien, die im neuen Archiv fehlen) und erzeugt
# einen zweiten Migrations-Kopf ("Multiple head revisions"). Wird beim
# Start automatisch entfernt, damit niemand manuell auf dem Server
# aufraeumen muss.
_KNOWN_STALE_REVISION_IDS = ["f6d9dcf0056d"]


def _remove_known_stale_migration_files() -> None:
    versions_dir = BACKEND_ROOT / "migrations" / "versions"
    if not versions_dir.is_dir():
        return
    for revision_id in _KNOWN_STALE_REVISION_IDS:
        for stale_file in versions_dir.glob(f"{revision_id}_*.py"):
            logger.warning("Entferne veraltete Migrationsdatei aus fruehrerem Paket: %s", stale_file.name)
            stale_file.unlink()


def _table_exists(name: str) -> bool:
    with engine.connect() as conn:
        result = conn.execute(
            text("SELECT name FROM sqlite_master WHERE type='table' AND name=:name"), {"name": name}
        ).fetchone()
        return result is not None


def _run_alembic(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["alembic", *args], cwd=str(BACKEND_ROOT), capture_output=True, text=True
    )


def _verify_schema_matches_models() -> None:
    """Letzte Sicherheitsnetz-Pruefung nach JEDER Migration: stimmt das,
    was die SQLAlchemy-Modelle erwarten, WIRKLICH mit der Datenbank
    ueberein? Deckt genau die Klasse von Fehlern ab, die sonst erst beim
    ersten echten Request als 500er auffaellt ("no such column: ..."),
    indem der Container hier stattdessen sofort und LAUT beim Start
    fehlschlaegt -- sichtbar in 'docker compose logs', nicht erst beim
    naechsten Login-Versuch eines Nutzers.
    """
    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())
    missing: list[str] = []

    for table_name, table in Base.metadata.tables.items():
        if table_name not in existing_tables:
            missing.append(f"Tabelle '{table_name}' fehlt komplett")
            continue
        existing_columns = {c["name"] for c in inspector.get_columns(table_name)}
        for column in table.columns:
            if column.name not in existing_columns:
                missing.append(f"Spalte '{table_name}.{column.name}' fehlt")

    if missing:
        details = "\n  - ".join(missing)
        raise RuntimeError(
            f"Schema-Verifikation nach der Migration fehlgeschlagen -- {len(missing)} Abweichung(en):\n  - {details}\n"
            "Der Container startet bewusst NICHT, um keine 500er im laufenden Betrieb zu riskieren. "
            "Pruefe 'docker compose exec toolbox-backend alembic current' und 'alembic heads'."
        )

    logger.info("Schema-Verifikation erfolgreich: alle %d Tabellen stimmen mit den Modellen ueberein.", len(Base.metadata.tables))


def _log_alembic_state(label: str) -> None:
    result = _run_alembic("current")
    logger.info("Alembic-Stand (%s): %s", label, result.stdout.strip() or "(leer)")


def _upgrade_head_with_recovery() -> None:
    result = _run_alembic("upgrade", "head")
    if result.returncode == 0:
        print(result.stdout, end="")
        return

    if "Multiple head revisions are present" in result.stderr:
        # Sehr haeufige Ursache: mehrfaches 'unzip -o' verschiedener
        # Paket-Versionen in denselben Ordner. 'unzip -o' UEBERSCHREIBT
        # gleichnamige Dateien, LOESCHT aber nie Dateien, die im alten
        # Ordner liegen, im neuen ZIP jedoch nicht mehr enthalten sind
        # (z.B. eine umbenannte Migration). Ergebnis: zwei Migrationsdateien
        # mit demselben Elternknoten -- Alembic sieht zwei "Koepfe" und
        # weiss nicht, welchem es folgen soll.
        heads_result = _run_alembic("heads", "--verbose")
        logger.error(
            "MEHRERE Migrations-Koepfe gefunden -- das deutet auf veraltete Dateien in "
            "migrations/versions/ hin, typischerweise von einem frueheren 'unzip -o' in "
            "denselben Ordner (unzip loescht nie Dateien, die im neuen Paket fehlen). "
            "Pruefe 'ls backend/migrations/versions/' auf dem Server -- es sollten NUR "
            "die Dateien aus dem aktuell ausgelieferten Paket vorhanden sein. Am "
            "sichersten: das komplette 'backend/'-Verzeichnis vor dem naechsten Entpacken "
            "loeschen (die Datenbank liegt separat im Docker-Volume und bleibt erhalten).\n%s",
            heads_result.stdout,
        )
        print(result.stdout, end="")
        print(result.stderr, end="")
        raise RuntimeError(
            "Mehrere Migrations-Koepfe gefunden -- vermutlich veraltete Dateien in "
            "migrations/versions/ von einem frueheren Deployment. Siehe Log oben."
        )

    # Nur EIN sehr spezifischer Fehler wird automatisch behandelt: die
    # Zieltabelle existiert bereits (= physisches Schema ist alembic_version
    # voraus, typischerweise nach dem oben beschriebenen Incident). Jeder
    # andere Fehler wird unveraendert weitergereicht.
    if "already exists" in result.stderr:
        logger.warning(
            "Migration schlug mit 'already exists' fehl -- Tabellen sind vermutlich schon "
            "vorhanden, aber alembic_version ist veraltet. Hole fehlende Tabellen/Spalten "
            "nach und stempele dann auf head, ohne die Migration erneut auszufuehren."
        )
        # WICHTIG: create_all() UND run_light_migrations() hier, nicht nur
        # stempeln -- sonst wuerden zwar fehlende Tabellen fehlen (die
        # 'already exists' ja gerade zeigt, dass sie schon da sind), aber
        # fehlende SPALTEN an bereits existierenden Tabellen (aus
        # ALTER-TABLE-Anteilen derselben Migration) unbemerkt bleiben.
        Base.metadata.create_all(bind=engine)
        run_light_migrations(engine)
        stamp_result = _run_alembic("stamp", "head")
        print(stamp_result.stdout, end="")
        if stamp_result.returncode != 0:
            print(stamp_result.stderr, end="")
            raise RuntimeError("Stempeln nach Recovery fehlgeschlagen -- manuelle Pruefung noetig.")
        return

    # Unbekannter/echter Fehler -- laut fehlschlagen, nicht verschlucken.
    print(result.stdout, end="")
    print(result.stderr, end="")
    raise RuntimeError(f"'alembic upgrade head' fehlgeschlagen (Exit-Code {result.returncode}).")


def main() -> None:
    _remove_known_stale_migration_files()

    was_pre_existing = _table_exists("users")
    alembic_initialized = _table_exists("alembic_version")

    if was_pre_existing and not alembic_initialized:
        logger.info("Bestehende Installation ohne Alembic-Tracking -- einmaliger Bootstrap")
        Base.metadata.create_all(bind=engine)
        run_light_migrations(engine)
        result = _run_alembic("stamp", "head")
        print(result.stdout, end="")
        if result.returncode != 0:
            print(result.stderr, end="")
            raise RuntimeError("Bootstrap-Stempeln fehlgeschlagen.")
    else:
        _log_alembic_state("vor der Migration")
        logger.info("Fuehre Alembic-Migrationen aus...")
        _upgrade_head_with_recovery()

    _log_alembic_state("nach der Migration")

    try:
        _verify_schema_matches_models()
    except RuntimeError as exc:
        # Letzter Selbstheilungs-Versuch: alembic_version behauptet, auf dem
        # neuesten Stand zu sein (sonst waere schon der 'already exists'-Pfad
        # oben gelaufen), aber das physische Schema stimmt trotzdem nicht.
        # Das ist z.B. genau der Zustand, den ein Nutzer nach einem frueheren
        # fehlerhaften Deployment gemeldet hat. Einmalig nachbessern statt
        # den Container endgueltig aufgeben zu lassen.
        logger.warning("Schema-Verifikation fehlgeschlagen, versuche einmalige Selbstheilung: %s", exc)
        Base.metadata.create_all(bind=engine)
        run_light_migrations(engine)
        _verify_schema_matches_models()  # schlaegt hier laut fehl, falls immer noch nicht behoben
        logger.info("Selbstheilung erfolgreich -- Schema war nach der Migration unvollstaendig, jetzt korrigiert.")

    logger.info("Migrationen abgeschlossen.")


if __name__ == "__main__":
    main()
