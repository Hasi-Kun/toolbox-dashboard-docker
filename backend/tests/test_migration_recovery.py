"""Regressionstests fuer app/scripts/run_migrations.py -- insbesondere den
Produktions-Incident, bei dem create_all() bei jeder bestehenden
Installation lief und mit einer echten Alembic-Migration kollidierte
("table chat_messages already exists"), was das Backend am Start
hinderte.
"""

import os
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parent.parent


def _run_migrations(db_path: str) -> subprocess.CompletedProcess:
    env = {**os.environ, "DATABASE_URL": f"sqlite:///{db_path}"}
    return subprocess.run(
        [sys.executable, "-m", "app.scripts.run_migrations"],
        cwd=str(BACKEND_ROOT), env=env, capture_output=True, text=True, timeout=30,
    )


def _get_version(db_path: str) -> str:
    conn = sqlite3.connect(db_path)
    row = conn.execute("SELECT version_num FROM alembic_version").fetchone()
    conn.close()
    return row[0]


def _current_head() -> str:
    result = subprocess.run(
        ["alembic", "heads"], cwd=str(BACKEND_ROOT), capture_output=True, text=True, check=True
    )
    return result.stdout.strip().split()[0]


@pytest.fixture()
def tmp_db_path(tmp_path):
    return str(tmp_path / "test.db")


def _insert_real_user(db_path: str) -> None:
    """Fuegt eine echte Zeile in 'users' ein -- entscheidend fuer
    Migrationstests. Ein leerer Tisch verschleiert genau die Klasse Bug,
    die den gemeldeten Produktions-Incident verursacht hat: SQLite
    verweigert 'ALTER TABLE ADD COLUMN ... NOT NULL' auf eine Tabelle mit
    bestehenden Zeilen, wenn kein server_default gesetzt ist -- das faellt
    bei einer leeren Tabelle nie auf, weil dort keine Zeile befuellt
    werden muss.
    """
    sys.path.insert(0, str(BACKEND_ROOT))
    from app.core.security import hash_password  # noqa: PLC0415

    conn = sqlite3.connect(db_path)
    conn.execute(
        "INSERT INTO users (username, password_hash, role, is_active, totp_enabled, created_at) "
        "VALUES ('realuser', ?, 'admin', 1, 1, datetime('now'))",
        (hash_password("irgendeinpasswort123"),),
    )
    conn.commit()
    conn.close()


def test_every_migration_succeeds_against_table_with_existing_rows(tmp_db_path):
    """Der eigentliche Regressionstest fuer den gemeldeten Incident:
    'ALTER TABLE users ADD COLUMN can_invite BOOLEAN NOT NULL' schlug in
    Produktion fehl, weil die Tabelle bereits eine echte Nutzerzeile
    enthielt und kein server_default gesetzt war. Alle bisherigen Tests
    liefen gegen leere Tabellen und haben das nicht bemerkt.
    """
    # Erst auf die Baseline (VOR den problematischen ADD COLUMNs), dann
    # eine echte Zeile einfuegen, dann den Rest der Kette laufen lassen --
    # simuliert exakt eine Produktionsdatenbank mit einem echten Admin-User.
    subprocess.run(
        ["alembic", "upgrade", "1b1325407b99"],
        cwd=str(BACKEND_ROOT), env={**os.environ, "DATABASE_URL": f"sqlite:///{tmp_db_path}"},
        check=True, capture_output=True, text=True,
    )
    _insert_real_user(tmp_db_path)

    result = _run_migrations(tmp_db_path)
    assert result.returncode == 0, f"Migration gegen Tabelle mit echten Daten fehlgeschlagen:\n{result.stdout}\n{result.stderr}"
    assert _get_version(tmp_db_path) == _current_head()

    conn = sqlite3.connect(tmp_db_path)
    row = conn.execute("SELECT username, invite_quota, premium_badge_color FROM users WHERE username='realuser'").fetchone()
    conn.close()
    assert row is not None, "Der bestehende Benutzer ist bei der Migration verlorengegangen!"
    assert row[1] == 0  # invite_quota Default
    assert row[2] == "#F5C518"  # premium_badge_color Default


def test_stale_migration_file_from_earlier_rename_is_auto_removed(tmp_path):
    """Reproduziert 'Multiple head revisions': eine fruehere Paketversion
    lieferte dieselbe Migration kurzzeitig unter einer anderen Revision-ID
    aus (f6d9dcf0056d, spaeter auf aa1c8e049141 zurueckbenannt). Wird ein
    neues Paket per 'unzip -o' in denselben Ordner entpackt, bleibt die
    alte Datei liegen (unzip loescht nie Dateien, die im neuen Archiv
    fehlen) -- zwei Dateien mit demselben Elternknoten erzeugen zwei
    Migrations-Koepfe. Muss automatisch bereinigt werden, ohne dass der
    Nutzer manuell auf dem Server aufraeumen muss.
    """
    fake_versions_dir = tmp_path / "backend_copy" / "migrations" / "versions"
    shutil.copytree(BACKEND_ROOT, tmp_path / "backend_copy", ignore=shutil.ignore_patterns("__pycache__", "*.db"))

    stale_file = fake_versions_dir / "f6d9dcf0056d_audit_log_premium_fields_invite_self_.py"
    stale_file.write_text(
        '"""stale duplicate for test"""\n'
        "from alembic import op\n"
        "import sqlalchemy as sa\n\n"
        'revision = "f6d9dcf0056d"\n'
        'down_revision = "1b1325407b99"\n'
        "branch_labels = None\n"
        "depends_on = None\n\n"
        "def upgrade() -> None:\n    pass\n\n"
        "def downgrade() -> None:\n    pass\n"
    )

    db_path = str(tmp_path / "test.db")
    env = {**os.environ, "DATABASE_URL": f"sqlite:///{db_path}"}
    result = subprocess.run(
        [sys.executable, "-m", "app.scripts.run_migrations"],
        cwd=str(tmp_path / "backend_copy"), env=env, capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, f"Haette sich selbst bereinigen sollen:\n{result.stdout}\n{result.stderr}"
    assert not stale_file.exists(), "Die veraltete Migrationsdatei haette entfernt werden muessen"
    assert "Entferne veraltete Migrationsdatei" in result.stdout or "Entferne veraltete Migrationsdatei" in result.stderr


def test_fresh_install_migrates_cleanly(tmp_db_path):
    result = _run_migrations(tmp_db_path)
    assert result.returncode == 0, result.stderr
    assert _get_version(tmp_db_path) == _current_head()


def test_repeated_run_on_fully_migrated_db_is_stable(tmp_db_path):
    _run_migrations(tmp_db_path)
    result = _run_migrations(tmp_db_path)
    assert result.returncode == 0, result.stderr
    assert _get_version(tmp_db_path) == _current_head()


def test_recovers_from_stale_alembic_version_with_tables_already_present(tmp_db_path):
    subprocess.run(
        ["alembic", "upgrade", "ca00304c2cd0"],
        cwd=str(BACKEND_ROOT), env={**os.environ, "DATABASE_URL": f"sqlite:///{tmp_db_path}"},
        check=True, capture_output=True, text=True,
    )

    env = {**os.environ, "DATABASE_URL": f"sqlite:///{tmp_db_path}"}
    subprocess.run(
        [sys.executable, "-c",
         "from app.core.db import Base, engine; from app.models import user; Base.metadata.create_all(bind=engine)"],
        cwd=str(BACKEND_ROOT), env=env, check=True, capture_output=True, text=True,
    )
    assert _get_version(tmp_db_path) == "ca00304c2cd0"

    conn = sqlite3.connect(tmp_db_path)
    tables_before = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    conn.close()
    assert "chat_messages" in tables_before

    result = _run_migrations(tmp_db_path)
    assert result.returncode == 0, f"Selbstheilung fehlgeschlagen:\n{result.stdout}\n{result.stderr}"
    assert _get_version(tmp_db_path) == _current_head()


def test_schema_verification_triggers_self_repair_on_falsely_stamped_database(tmp_path):
    """Reproduziert den gemeldeten Produktions-Vorfall: alembic_version
    behauptet, auf dem neuesten Stand zu sein, aber die Spalten/Tabellen
    fehlen tatsaechlich. Die Schema-Verifikation muss das erkennen UND
    automatisch reparieren (create_all + run_light_migrations), statt
    den Container dauerhaft nicht starten zu lassen.
    """
    db_path = str(tmp_path / "test.db")
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, username VARCHAR(64), password_hash VARCHAR(255), "
        "role VARCHAR(16), is_active BOOLEAN, totp_secret VARCHAR(64), totp_enabled BOOLEAN, created_at DATETIME)"
    )
    conn.execute("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)")
    conn.execute(f"INSERT INTO alembic_version VALUES ('{_current_head()}')")
    conn.commit()
    conn.close()

    result = _run_migrations(db_path)
    assert result.returncode == 0, f"Selbstheilung haette erfolgreich sein muessen:\n{result.stdout}\n{result.stderr}"
    assert "Selbstheilung erfolgreich" in result.stdout or "Selbstheilung erfolgreich" in result.stderr

    conn = sqlite3.connect(db_path)
    columns = [r[1] for r in conn.execute("PRAGMA table_info(users)")]
    conn.close()
    assert "invite_quota" in columns


def test_schema_verification_passes_on_correctly_migrated_database(tmp_db_path):
    result = _run_migrations(tmp_db_path)
    assert result.returncode == 0
    assert "Schema-Verifikation erfolgreich" in result.stdout or "Schema-Verifikation erfolgreich" in result.stderr


def test_genuine_pending_column_migration_is_not_silently_skipped(tmp_path):
    db_path = str(tmp_path / "test.db")
    _run_migrations(db_path)
    version_before = _get_version(db_path)

    fake_migrations_dir = tmp_path / "backend_copy"
    shutil.copytree(BACKEND_ROOT, fake_migrations_dir, ignore=shutil.ignore_patterns("__pycache__", "*.db"))

    fake_revision = fake_migrations_dir / "migrations" / "versions" / "zzz_test_fake_column.py"
    fake_revision.write_text(
        '"""fake column addition for testing"""\n'
        "from alembic import op\n"
        "import sqlalchemy as sa\n\n"
        'revision = "zzz_test_fake_column"\n'
        f'down_revision = "{version_before}"\n'
        "branch_labels = None\n"
        "depends_on = None\n\n"
        "def upgrade():\n"
        '    with op.batch_alter_table("users", schema=None) as batch_op:\n'
        '        batch_op.add_column(sa.Column("test_new_column", sa.String(length=50), nullable=True))\n\n'
        "def downgrade():\n"
        '    with op.batch_alter_table("users", schema=None) as batch_op:\n'
        '        batch_op.drop_column("test_new_column")\n'
    )

    env = {**os.environ, "DATABASE_URL": f"sqlite:///{db_path}"}
    result = subprocess.run(
        [sys.executable, "-m", "app.scripts.run_migrations"],
        cwd=str(fake_migrations_dir), env=env, capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr

    conn = sqlite3.connect(db_path)
    columns = [r[1] for r in conn.execute("PRAGMA table_info(users)")]
    version_after = conn.execute("SELECT version_num FROM alembic_version").fetchone()[0]
    conn.close()

    assert "test_new_column" in columns, "Echte Spalten-Migration wurde faelschlich uebersprungen!"
    assert version_after == "zzz_test_fake_column"
