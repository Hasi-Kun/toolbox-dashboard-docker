"""Wrapper um die `webauthn`-Library, damit die Auth-Endpoints schlank bleiben
und die RP-Konfiguration (Domain/Origin) an einer Stelle lebt.

Wichtig: RP-ID und Origin muessen exakt zur oeffentlichen Domain passen
(https://{{TOOLBOX_DOMAIN}}), sonst lehnt der Browser die Registrierung/
Verifikation ab. Passkeys funktionieren grundsaetzlich nur ueber HTTPS
(oder localhost fuer lokale Entwicklung).
"""

import webauthn
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from app.core.config import get_settings
from app.models.user import User, WebAuthnCredential

settings = get_settings()


def build_registration_options(user: User) -> tuple[str, bytes]:
    """Gibt (options_json, challenge_bytes) zurueck. challenge_bytes wird
    fuer die spaetere Verifikation in Redis zwischengespeichert.
    """
    exclude = [
        PublicKeyCredentialDescriptor(id=base64url_to_bytes(c.credential_id))
        for c in user.webauthn_credentials
    ]

    options = webauthn.generate_registration_options(
        rp_id=settings.webauthn_rp_id,
        rp_name=settings.webauthn_rp_name,
        user_id=str(user.id).encode("utf-8"),
        user_name=user.username,
        user_display_name=user.username,
        exclude_credentials=exclude,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
    )
    return webauthn.options_to_json(options), options.challenge


def verify_registration(credential: dict, expected_challenge: bytes) -> tuple[str, str]:
    """Verifiziert die Attestation-Response. Gibt (credential_id, public_key)
    base64url-kodiert zurueck, zum Speichern in der DB.
    """
    verified = webauthn.verify_registration_response(
        credential=credential,
        expected_challenge=expected_challenge,
        expected_rp_id=settings.webauthn_rp_id,
        expected_origin=settings.webauthn_origin,
    )
    credential_id = bytes_to_base64url(verified.credential_id)
    public_key = bytes_to_base64url(verified.credential_public_key)
    return credential_id, public_key


def build_authentication_options(user: User) -> tuple[str, bytes]:
    allow = [
        PublicKeyCredentialDescriptor(id=base64url_to_bytes(c.credential_id))
        for c in user.webauthn_credentials
    ]

    options = webauthn.generate_authentication_options(
        rp_id=settings.webauthn_rp_id,
        allow_credentials=allow,
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    return webauthn.options_to_json(options), options.challenge


def verify_authentication(
    credential: dict, expected_challenge: bytes, stored: WebAuthnCredential
) -> int:
    """Verifiziert die Assertion-Response gegen den gespeicherten Credential.
    Gibt den neuen sign_count zurueck (muss in der DB aktualisiert werden --
    ein stagnierender/fallender Counter kann auf einen geklonten Authenticator
    hindeuten).
    """
    verified = webauthn.verify_authentication_response(
        credential=credential,
        expected_challenge=expected_challenge,
        expected_rp_id=settings.webauthn_rp_id,
        expected_origin=settings.webauthn_origin,
        credential_public_key=base64url_to_bytes(stored.public_key),
        credential_current_sign_count=stored.sign_count,
    )
    return verified.new_sign_count
