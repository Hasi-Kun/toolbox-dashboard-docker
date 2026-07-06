import re

from pydantic import BaseModel

from app.modules.base import ToolModule, register_module

_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"^\$2[aby]\$\d{2}\$[A-Za-z0-9./]{53}$"), "bcrypt"),
    (re.compile(r"^\$argon2(id|i|d)\$"), "Argon2"),
    (re.compile(r"^\$6\$"), "SHA-512 crypt (Unix)"),
    (re.compile(r"^\$5\$"), "SHA-256 crypt (Unix)"),
    (re.compile(r"^\$1\$"), "MD5 crypt (Unix, veraltet)"),
    (re.compile(r"^\$y\$"), "yescrypt (moderner Unix-Standard)"),
    (re.compile(r"^[A-Fa-f0-9]{32}$"), "MD5, NTLM oder MD4 (identische Laenge, 32 Hex-Zeichen)"),
    (re.compile(r"^[A-Fa-f0-9]{40}$"), "SHA-1 (40 Hex-Zeichen)"),
    (re.compile(r"^[A-Fa-f0-9]{56}$"), "SHA-224 (56 Hex-Zeichen)"),
    (re.compile(r"^[A-Fa-f0-9]{64}$"), "SHA-256, SHA3-256 oder BLAKE2s (64 Hex-Zeichen)"),
    (re.compile(r"^[A-Fa-f0-9]{96}$"), "SHA-384 (96 Hex-Zeichen)"),
    (re.compile(r"^[A-Fa-f0-9]{128}$"), "SHA-512, SHA3-512 oder Whirlpool (128 Hex-Zeichen)"),
]


@register_module
class HashIdentifierModule(ToolModule):
    slug = "hash-identifier"
    category = "utilities"
    name = "Hash Identifier"
    description = (
        "Identifiziert den wahrscheinlichen Hash-Algorithmus anhand von Format und Laenge -- "
        "reine Identifikation, kein Cracking/Bruteforce."
    )
    is_active_scan = False
    timeout_seconds = 3

    class Input(BaseModel):
        hash_value: str

    class Output(BaseModel):
        hash_value: str
        length: int
        possible_algorithms: list[str]
        note: str | None = None

    async def run(self, data: Input) -> Output:
        value = data.hash_value.strip()
        matches = [name for pattern, name in _PATTERNS if pattern.match(value)]

        note = None
        if not matches:
            note = (
                "Kein bekanntes Standardformat erkannt. Moeglich: Base64-kodierter Hash, "
                "gesalzener Hash in einem unbekannten Format, oder kein Hash."
            )

        return self.Output(hash_value=value, length=len(value), possible_algorithms=matches, note=note)
