"""Legt den ersten Admin-Account an -- es gibt bewusst keinen oeffentlichen
Registrierungs-Endpoint, daher muss der allererste Benutzer per CLI im
Container angelegt werden. Danach koennen weitere Benutzer ueber die
Verwaltungsseite im Dashboard (als Admin) erstellt werden.

Aufruf:
    docker exec -it toolbox-backend python -m app.scripts.create_admin
"""

import getpass
import sys

from app.core.db import Base, SessionLocal, engine
from app.core.security import hash_password
from app.models.user import User, UserRole


def main() -> None:
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    try:
        username = input("Benutzername: ").strip()
        if not username:
            print("Benutzername darf nicht leer sein.", file=sys.stderr)
            sys.exit(1)

        if db.query(User).filter(User.username == username).first() is not None:
            print(f"Benutzer '{username}' existiert bereits.", file=sys.stderr)
            sys.exit(1)

        password = getpass.getpass("Passwort: ")
        password_confirm = getpass.getpass("Passwort (Wiederholung): ")
        if password != password_confirm:
            print("Passwoerter stimmen nicht ueberein.", file=sys.stderr)
            sys.exit(1)
        if len(password) < 12:
            print("Passwort sollte mindestens 12 Zeichen haben.", file=sys.stderr)
            sys.exit(1)

        user = User(
            username=username,
            password_hash=hash_password(password),
            role=UserRole.ADMIN.value,
            is_active=True,
        )
        db.add(user)
        db.commit()

        print(f"\nAdmin-Account '{username}' angelegt.")
        print("Beim ersten Login wird die Einrichtung von 2FA (TOTP-App oder Passkey) erzwungen.")
    finally:
        db.close()


if __name__ == "__main__":
    main()
