"""Passwort-Hashing mit Argon2 (argon2id) -- aktueller OWASP-Standard,
bewusst statt bcrypt oder schlicht sha256.
"""

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

_hasher = PasswordHasher()


def hash_password(plain: str) -> str:
    return _hasher.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return _hasher.verify(hashed, plain)
    except VerifyMismatchError:
        return False
    except Exception:  # noqa: BLE001 -- z.B. korrupter Hash, nie als Server-Fehler durchreichen
        return False
