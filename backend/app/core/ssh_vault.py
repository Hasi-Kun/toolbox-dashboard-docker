"""Symmetrische Verschluesselung fuer gespeicherte SSH-Geheimnisse
(Passwoerter, private Schluessel) -- niemals im Klartext in der DB.

Nutzt Fernet (AES-128-CBC + HMAC, authentifizierte Verschluesselung) aus
der bereits vorhandenen `cryptography`-Abhaengigkeit.
"""

import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import get_settings


class SshVaultError(Exception):
    """Entschluesselung fehlgeschlagen (falscher/geaenderter Schluessel,
    manipulierte Daten)."""


def _get_fernet() -> Fernet:
    settings = get_settings()
    key_material = settings.ssh_vault_key or settings.session_secret
    # Fernet braucht einen 32-Byte, urlsafe-base64-kodierten Schluessel --
    # per SHA-256 aus dem konfigurierten Secret ableiten, falls kein
    # dedizierter SSH_VAULT_KEY gesetzt ist.
    derived = hashlib.sha256(key_material.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(derived))


def encrypt_secret(plaintext: str) -> str:
    return _get_fernet().encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt_secret(ciphertext: str) -> str:
    try:
        return _get_fernet().decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except InvalidToken as exc:
        raise SshVaultError("Geheimnis konnte nicht entschluesselt werden (Schluessel geaendert?)") from exc
