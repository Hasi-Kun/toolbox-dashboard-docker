"""Sicherheitsfokussierte JWT-Analyse -- ergaenzt den bestehenden reinen
Decoder (jwt-decoder) um Pruefungen auf bekannte Schwachstellenklassen:
alg=none, schwache/erratbare HMAC-Secrets (Woerterbuch-Check), fehlende
oder verdaechtige Zeitangaben.
"""

import base64
import hashlib
import hmac
import json
from datetime import datetime, timezone

from pydantic import BaseModel

from app.modules.base import ToolModule, register_module

_HMAC_ALGOS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}

# Bewusst eine kleine, dokumentierte Liste haeufiger Default-/Beispiel-
# Secrets aus Tutorials und Frameworks -- kein vollstaendiger
# Woerterbuch-Angriff, nur ein Check auf die offensichtlichsten Fehler.
_COMMON_WEAK_SECRETS = [
    "secret", "your-256-bit-secret", "changeme", "password", "jwt-secret",
    "supersecret", "secretkey", "your-secret-key", "test", "12345678",
    "mysecret", "keyboard cat", "your_jwt_secret", "s3cr3t", "please-change-me",
]

_MAX_REASONABLE_VALIDITY_SECONDS = 60 * 60 * 24 * 400  # ~13 Monate


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


class JwtFinding(BaseModel):
    severity: str  # "kritisch" | "hoch" | "mittel" | "info"
    title: str
    detail: str


@register_module
class JwtSecurityAnalyzerModule(ToolModule):
    slug = "jwt-security-analyzer"
    category = "security"
    name = "JWT Security-Analyse"
    description = (
        "Analysiert ein JWT auf bekannte Schwachstellenklassen: alg=none, schwache/erratbare "
        "HMAC-Secrets (Woerterbuch-Check gegen haeufige Default-Werte), fehlende oder verdaechtige "
        "Zeitangaben (exp/iat)."
    )
    is_active_scan = False
    timeout_seconds = 8

    class Input(BaseModel):
        token: str

    class Output(BaseModel):
        valid_format: bool
        algorithm: str | None = None
        header: dict | None = None
        payload: dict | None = None
        findings: list[JwtFinding] = []
        weak_secret_found: str | None = None
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
        findings: list[JwtFinding] = []
        weak_secret_found: str | None = None

        if str(algorithm).lower() == "none":
            findings.append(JwtFinding(
                severity="kritisch", title="alg=none akzeptiert unsignierte Tokens",
                detail="Der Header gibt 'none' als Algorithmus an. Server, die das unkritisch akzeptieren, "
                       "lassen sich mit einem selbst gebastelten, unsignierten Token austricksen -- eine der "
                       "bekanntesten JWT-Schwachstellen ueberhaupt.",
            ))

        if algorithm in _HMAC_ALGOS:
            for candidate in _COMMON_WEAK_SECRETS:
                signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
                expected_sig = hmac.new(candidate.encode("utf-8"), signing_input, _HMAC_ALGOS[algorithm]).digest()
                try:
                    actual_sig = _b64url_decode(signature_b64)
                except Exception:  # noqa: BLE001
                    break
                if hmac.compare_digest(expected_sig, actual_sig):
                    weak_secret_found = candidate
                    findings.append(JwtFinding(
                        severity="kritisch", title="Schwaches/erratbares HMAC-Secret gefunden",
                        detail=f"Das Token ist mit einem haeufigen Default-Secret signiert (aus einer kleinen, "
                               f"dokumentierten Woerterbuch-Liste haeufiger Tutorial-/Framework-Defaults) -- "
                               f"jeder kann damit gueltige Tokens faelschen.",
                    ))
                    break

        if "exp" not in payload:
            findings.append(JwtFinding(
                severity="hoch", title="Kein Ablaufdatum (exp) gesetzt",
                detail="Ohne 'exp'-Claim laeuft das Token nie ab -- ein gestohlenes Token bleibt fuer immer gueltig.",
            ))
        else:
            try:
                exp_ts = int(payload["exp"])
                now_ts = datetime.now(timezone.utc).timestamp()
                if exp_ts < now_ts:
                    findings.append(JwtFinding(
                        severity="info", title="Token ist abgelaufen",
                        detail=f"exp liegt in der Vergangenheit ({datetime.fromtimestamp(exp_ts, timezone.utc).isoformat()}).",
                    ))
                elif "iat" in payload:
                    validity_seconds = exp_ts - int(payload["iat"])
                    if validity_seconds > _MAX_REASONABLE_VALIDITY_SECONDS:
                        findings.append(JwtFinding(
                            severity="mittel", title="Ungewoehnlich lange Gueltigkeitsdauer",
                            detail=f"Token ist fuer {validity_seconds // 86400} Tage gueltig -- pruefen, ob das beabsichtigt ist.",
                        ))
            except (ValueError, TypeError, OSError):
                findings.append(JwtFinding(
                    severity="info", title="exp-Claim konnte nicht ausgewertet werden",
                    detail="Der Wert ist kein gueltiger Unix-Timestamp.",
                ))

        if "iat" not in payload:
            findings.append(JwtFinding(
                severity="info", title="Kein Ausstellungsdatum (iat) gesetzt",
                detail="Ohne 'iat'-Claim laesst sich das Alter des Tokens nicht nachvollziehen.",
            ))

        if algorithm in ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512"):
            findings.append(JwtFinding(
                severity="info", title="Asymmetrischer Algorithmus -- auf 'Alg-Confusion' pruefen",
                detail="Server, die RS/ES-Tokens akzeptieren, muessen den Algorithmus SERVERSEITIG festlegen "
                       "(nicht aus dem Token uebernehmen) -- sonst kann ein Angreifer mit dem OEFFENTLICHEN "
                       "Schluessel ein HS256-Token faelschen, das der Server faelschlich als per RSA "
                       "signiert akzeptiert (klassische 'Algorithm Confusion'-Schwachstelle).",
            ))

        return self.Output(
            valid_format=True, algorithm=algorithm, header=header, payload=payload,
            findings=findings, weak_secret_found=weak_secret_found,
        )
