import base64
import hashlib
import hmac
import json

from pydantic import BaseModel

from app.modules.base import ToolModule, register_module

_HMAC_ALGOS = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


@register_module
class JwtDecoderModule(ToolModule):
    slug = "jwt-decoder"
    category = "utilities"
    name = "JWT Decoder"
    description = "Dekodiert Header und Payload eines JWT; prueft optional die HMAC-Signatur (HS256/384/512)."
    is_active_scan = False
    timeout_seconds = 5

    class Input(BaseModel):
        token: str
        secret: str | None = None

    class Output(BaseModel):
        valid_format: bool
        header: dict | None = None
        payload: dict | None = None
        algorithm: str | None = None
        signature_valid: bool | None = None
        error: str | None = None

    async def run(self, data: Input) -> Output:
        parts = data.token.strip().split(".")
        if len(parts) != 3:
            return self.Output(valid_format=False, error="Kein gueltiges JWT-Format (erwartet 3 durch '.' getrennte Teile)")

        header_b64, payload_b64, signature_b64 = parts

        try:
            header = json.loads(_b64url_decode(header_b64))
            payload = json.loads(_b64url_decode(payload_b64))
        except Exception as exc:  # noqa: BLE001
            return self.Output(valid_format=False, error=f"Header/Payload konnten nicht dekodiert werden: {exc}")

        algorithm = header.get("alg")
        signature_valid: bool | None = None

        if data.secret and algorithm in _HMAC_ALGOS:
            signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
            expected_sig = hmac.new(data.secret.encode("utf-8"), signing_input, _HMAC_ALGOS[algorithm]).digest()
            try:
                actual_sig = _b64url_decode(signature_b64)
                signature_valid = hmac.compare_digest(expected_sig, actual_sig)
            except Exception:  # noqa: BLE001
                signature_valid = False
        elif data.secret and algorithm not in _HMAC_ALGOS:
            # z.B. RS256 -- Public-Key-Verifikation ist bewusst nicht implementiert
            # (braucht Key-Handling, das ueber den Scope eines simplen Decoders hinausgeht)
            signature_valid = None

        return self.Output(
            valid_format=True,
            header=header,
            payload=payload,
            algorithm=algorithm,
            signature_valid=signature_valid,
            error=None,
        )
