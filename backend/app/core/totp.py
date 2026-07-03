"""TOTP (RFC 6238) Helper -- kompatibel mit Google Authenticator, Authy,
Bitwarden, 1Password etc.
"""

import base64
import io

import pyotp
import qrcode


def generate_secret() -> str:
    return pyotp.random_base32()


def provisioning_uri(secret: str, username: str, issuer: str = "Toolbox") -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)


def verify_code(secret: str, code: str) -> bool:
    """Erlaubt ein Zeitfenster von +-1 Schritt (30s) gegen Uhr-Drift."""
    return pyotp.TOTP(secret).verify(code, valid_window=1)


def qr_code_data_uri(uri: str) -> str:
    """Rendert die Provisioning-URI als PNG und gibt sie als data:-URI zurueck,
    damit das Frontend keine eigene QR-Library braucht.
    """
    img = qrcode.make(uri)
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"
