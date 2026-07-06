"""Gemeinsame Fixtures fuer alle Tests, die einen DB- und Redis-Zustand
brauchen (Auth-Flow, Admin-Userverwaltung).
"""

import os
import tempfile

import fakeredis
import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client():
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(db_fd)

    import app.core.db as db_module
    import app.core.rate_limit as rate_limit_module
    import app.core.sessions as sessions_module
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    # WICHTIG: Modelle muessen importiert sein, BEVOR create_all laeuft --
    # sonst ist Base.metadata leer (keine Tabellen registriert) und
    # create_all legt still und leise gar nichts an. Das fiel bisher nur
    # nicht auf, wenn zufaellig schon ein anderer Test vorher die Modelle
    # importiert hatte (Reihenfolge-Zufall, kein verlaesslicher Fix).
    from app.models import user as _user_models  # noqa: F401

    # WICHTIG: engine/SessionLocal sind Modul-Level-Singletons, die beim
    # ersten Import gebunden werden. Nur die DATABASE_URL-Env-Variable zu
    # aendern reicht NICHT, weil app.core.db beim zweiten Test schon
    # importiert ist -- ohne dieses Monkeypatching wuerden sich alle Tests
    # eine einzige (stale) SQLite-Datei teilen.
    new_engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    db_module.engine = new_engine
    db_module.SessionLocal = sessionmaker(bind=new_engine, autoflush=False, autocommit=False)
    db_module.Base.metadata.create_all(bind=new_engine)

    fake_redis = fakeredis.FakeAsyncRedis(decode_responses=True)
    sessions_module._redis = fake_redis
    rate_limit_module._redis_client = fake_redis

    from app.main import app

    with TestClient(app) as test_client:
        yield test_client

    new_engine.dispose()
    os.remove(db_path)


def create_admin(username: str = "admin", password: str = "SuperSicheresPasswort123") -> str:
    from app.core.db import SessionLocal
    from app.core.security import hash_password
    from app.models.user import User, UserRole

    db = SessionLocal()
    db.add(User(username=username, password_hash=hash_password(password), role=UserRole.ADMIN.value, is_active=True))
    db.commit()
    db.close()
    return password
