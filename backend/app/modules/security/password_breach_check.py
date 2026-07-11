"""Prueft per k-Anonymity gegen die Have I Been Pwned-Datenbank, ob ein
Passwort in bekannten Datenlecks vorkommt.

WICHTIG (k-Anonymity-Prinzip): Das Passwort selbst verlaesst NIEMALS
unseren Server. Es wird lokal ein SHA1-Hash gebildet, und davon werden
NUR die ersten 5 Hex-Zeichen an die HIBP-API geschickt. Die API
antwortet mit ALLEN Hash-Suffixen, die mit diesem Praefix beginnen
(typischerweise hunderte) -- der Abgleich, ob UNSER konkretes Passwort
dabei ist, passiert danach lokal. HIBP selbst erfaehrt so nie, welches
konkrete Passwort geprueft wurde, nur dass IRGENDEIN Passwort mit diesem
5-stelligen Hash-Praefix angefragt wurde.

Das Passwort wird ausserdem bewusst NIE in der Tool-Ausfuehrungs-Historie
gespeichert (siehe redact_input_in_history).
"""

import hashlib

import httpx
from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module


@register_module
class PasswordBreachCheckModule(ToolModule):
    slug = "password-breach-check"
    category = "security"
    name = "Passwort-Leak-Check (HIBP)"
    description = (
        "Prueft per k-Anonymity gegen Have I Been Pwned, ob ein Passwort in bekannten Datenlecks "
        "vorkommt -- das Passwort selbst verlaesst nie den Server, nur 5 Zeichen eines Hash-Praefix. "
        "Wird NICHT in der Tool-Historie gespeichert."
    )
    is_active_scan = False
    timeout_seconds = 10
    redact_input_in_history = True

    class Input(BaseModel):
        password: str

        @field_validator("password")
        @classmethod
        def validate_password(cls, v: str) -> str:
            if not v:
                raise ValueError("Passwort darf nicht leer sein")
            if len(v) > 512:
                raise ValueError("Passwort zu lang (max. 512 Zeichen)")
            return v

    class Output(BaseModel):
        breached: bool
        times_seen: int = 0
        error: str | None = None

    async def run(self, data: Input) -> Output:
        sha1_hash = hashlib.sha1(data.password.encode("utf-8")).hexdigest().upper()
        prefix, suffix = sha1_hash[:5], sha1_hash[5:]

        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                response = await client.get(
                    f"https://api.pwnedpasswords.com/range/{prefix}",
                    headers={"User-Agent": "Toolbox-Password-Check/1.0 (k-Anonymity, siehe haveibeenpwned.com/API/v3)"},
                )
        except httpx.HTTPError as exc:
            return self.Output(breached=False, error=str(exc))

        if response.status_code != 200:
            return self.Output(breached=False, error=f"HIBP antwortete mit HTTP {response.status_code}")

        for line in response.text.splitlines():
            parts = line.strip().split(":")
            if len(parts) == 2 and parts[0].upper() == suffix:
                try:
                    count = int(parts[1])
                except ValueError:
                    count = 0
                return self.Output(breached=True, times_seen=count)

        return self.Output(breached=False, times_seen=0)
