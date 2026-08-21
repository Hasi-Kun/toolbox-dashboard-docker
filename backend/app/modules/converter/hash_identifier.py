"""Hash Identifier -- rein passive Format-/Laengen-basierte Erkennung, kein Cracking/Bruteforce.

Die Struktur der Erkennungsdatenbank (Praefix-Formate + Laengen-Tabelle fuer
Hex-Digests) ist inspiriert von hash-identifier von Zion3R:
https://github.com/blackploit/hash-identifier/blob/master/hash-id.py

Anders als dort wird hier nicht jede einzelne laengen-identische Salt-Variante
(md5($pass.$salt), md5(md5($pass)), ...) als eigener Eintrag gefuehrt --
stattdessen werden die Klartext-Algorithmen einzeln gelistet und ein
Sammelhinweis ergaenzt, sobald eine Laenge mehrdeutig ist.
"""

import re

from pydantic import BaseModel

from app.modules.base import ToolModule, register_module


class AlgorithmMatch(BaseModel):
    name: str
    category: str
    confidence: str  # "hoch" (eindeutiges Format) | "mehrdeutig" (nur Laenge/Charset)


# --- Eindeutige Formate (Praefix/Struktur erkennbar) -----------------------
_PREFIX_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"^\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}$"), "bcrypt", "Modernes KDF"),
    (re.compile(r"^\$argon2(id|i|d)\$"), "Argon2", "Modernes KDF"),
    (re.compile(r"^\$y\$"), "yescrypt", "Unix crypt"),
    (re.compile(r"^\$7\$"), "scrypt (Unix crypt, $7$)", "Unix crypt"),
    (re.compile(r"^\$6\$"), "SHA-512 crypt (Unix)", "Unix crypt"),
    (re.compile(r"^\$5\$"), "SHA-256 crypt (Unix)", "Unix crypt"),
    (re.compile(r"^\$1\$"), "MD5 crypt (Unix, veraltet)", "Unix crypt"),
    (re.compile(r"^\$apr1\$"), "APR1-MD5 (Apache htpasswd)", "Webserver"),
    (re.compile(r"^\$H\$"), "phpBB3 / phpass (portable hash)", "Web-Framework"),
    (re.compile(r"^\$P\$"), "WordPress (phpass)", "Web-Framework"),
    (re.compile(r"^\$S\$"), "Drupal 7 (phpass-Variante)", "Web-Framework"),
    (re.compile(r"^\$md5,rounds=\d+\$|^\$md5\$"), "Sun MD5 crypt (Solaris)", "Unix crypt"),
    (re.compile(r"^_[./A-Za-z0-9]{19}$"), "BSDi crypt (DES, erweitert)", "Unix crypt"),
    (re.compile(r"^(pbkdf2_sha256|\$pbkdf2-sha256)\$"), "PBKDF2-SHA256 (Django/Passlib)", "Web-Framework"),
    (re.compile(r"^(pbkdf2_sha1|\$pbkdf2-sha1)\$"), "PBKDF2-SHA1 (Django/Passlib)", "Web-Framework"),
    (re.compile(r"^sha1\$[^$]*\$[A-Fa-f0-9]{40}$"), "SHA-1 (Django, gesalzen)", "Web-Framework"),
    (re.compile(r"^sha256\$[^$]*\$[A-Fa-f0-9]{64}$"), "SHA-256 (Django, gesalzen)", "Web-Framework"),
    (re.compile(r"^sha384\$[^$]*\$[A-Fa-f0-9]{96}$"), "SHA-384 (Django, gesalzen)", "Web-Framework"),
    (re.compile(r"^md5\$[^$]*\$[A-Fa-f0-9]{32}$"), "MD5 (Django, gesalzen)", "Web-Framework"),
    (re.compile(r"^\*[A-Fa-f0-9]{40}$"), "MySQL 4.1+/5.x Passwort-Hash", "Datenbank"),
    (re.compile(r"^[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32}$"), "SAM-Eintrag (LM-Hash:NT-Hash)", "Windows"),
    (re.compile(r"^0x[A-Fa-f0-9]{32,}$"), "Lineage II C4 (0x-Praefix)", "Spiel/Sonstiges"),
    (re.compile(r"^\{SSHA\}[A-Za-z0-9+/=]+$"), "Salted SHA-1 (LDAP, {SSHA})", "LDAP/Verzeichnisdienst"),
    (re.compile(r"^\{SHA\}[A-Za-z0-9+/=]+$"), "SHA-1, Base64 (LDAP, {SHA})", "LDAP/Verzeichnisdienst"),
    (re.compile(r"^\$vault\$"), "HashiCorp Vault Format", "Secrets-Management"),
    (re.compile(r"^grub\.pbkdf2\.sha512\."), "GRUB2 PBKDF2-SHA512", "Bootloader"),
]

# Base64-kodierte Digests (z.B. Content-MD5-Header, CSP/HPKP-Pins)
_BASE64_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"^[A-Za-z0-9+/]{22}==$"), "MD5 (Base64-kodiert, z.B. Content-MD5)", "Encoding"),
    (re.compile(r"^[A-Za-z0-9+/]{27}=$"), "SHA-1 (Base64-kodiert)", "Encoding"),
    (re.compile(r"^[A-Za-z0-9+/]{43}=$"), "SHA-256 (Base64-kodiert, z.B. CSP/HPKP-Pin)", "Encoding"),
    (re.compile(r"^[A-Za-z0-9+/]{64}$"), "SHA-384 (Base64-kodiert)", "Encoding"),
    (re.compile(r"^[A-Za-z0-9+/]{86}==$"), "SHA-512 (Base64-kodiert)", "Encoding"),
]

_JWT_PATTERN = re.compile(r"^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")

# --- Mehrdeutige, rein Laengen-/Charset-basierte Hex-Digests ---------------
_HEX_LENGTH_DB: dict[int, list[str]] = {
    4: ["CRC-16", "CRC-16-CCITT", "FCS-16"],
    8: ["CRC-32", "CRC-32B", "Adler-32", "XOR-32", "GHash-32-3", "GHash-32-5"],
    16: ["MD5 (Half/Middle)", "MySQL 3.x/4.0 (alt, ohne Salt-Praefix)", "Oracle 7-10g OLD-Password"],
    32: [
        "MD5",
        "MD4",
        "MD2",
        "NTLM",
        "Domain Cached Credentials (DCC / MSCache v1)",
        "Haval-128",
        "RipeMD-128",
        "Tiger-128",
        "SNEFRU-128",
        "LM-Hash (LAN Manager)",
        "Gesalzene/verkettete MD5-Varianten (z.B. md5($pass.$salt), md5(md5($pass)))",
    ],
    40: [
        "SHA-1",
        "RipeMD-160",
        "Haval-160",
        "Tiger-160",
        "MySQL5 -- SHA1(SHA1($pass)) ohne '*'-Praefix",
    ],
    56: ["SHA-224", "Haval-224"],
    64: ["SHA-256", "SHA3-256", "BLAKE2s", "GOST R 34.11-94", "RipeMD-256", "Haval-256", "SNEFRU-256"],
    80: ["RipeMD-320"],
    96: ["SHA-384", "Haval-384"],
    128: ["SHA-512", "SHA3-512", "Whirlpool", "Haval-512"],
}

_HEX_ONLY = re.compile(r"^[A-Fa-f0-9]+$")


def _identify_hex(value: str) -> list[str]:
    if _HEX_ONLY.fullmatch(value):
        return _HEX_LENGTH_DB.get(len(value), [])
    return []


@register_module
class HashIdentifierModule(ToolModule):
    slug = "hash-identifier"
    category = "converter"
    name = "Hash Identifier"
    description = (
        "Identifiziert den wahrscheinlichen Hash-/KDF-Algorithmus anhand von Format, Praefix und Laenge -- "
        "unterstuetzt Unix-crypt-Formate, Web-Framework-Hashes (Django/WordPress/Drupal/phpBB), LDAP, "
        "Base64-Digests und generische Hex-Hashes. Reine Identifikation, kein Cracking/Bruteforce."
    )
    is_active_scan = False
    timeout_seconds = 3

    class Input(BaseModel):
        hash_value: str

    class Output(BaseModel):
        hash_value: str
        length: int
        possible_algorithms: list[str]
        matches: list[AlgorithmMatch] = []
        note: str | None = None

    async def run(self, data: Input) -> Output:
        value = data.hash_value.strip()
        length = len(value)

        if _JWT_PATTERN.match(value):
            return self.Output(
                hash_value=value,
                length=length,
                possible_algorithms=["JSON Web Token (JWT) -- kein Hash"],
                matches=[
                    AlgorithmMatch(
                        name="JSON Web Token (JWT) -- kein Hash",
                        category="Token-Format",
                        confidence="hoch",
                    )
                ],
                note=(
                    "Das ist kein Hash, sondern ein JWT (Header.Payload.Signatur, Base64url-kodiert). "
                    "Fuer eine Detailanalyse den 'JWT Security Analyzer' in dieser Toolbox verwenden."
                ),
            )

        matches: list[AlgorithmMatch] = []

        for pattern, name, category in _PREFIX_PATTERNS:
            if pattern.match(value):
                matches.append(AlgorithmMatch(name=name, category=category, confidence="hoch"))

        salt_note: str | None = None
        if not matches and value.count(":") == 1 and not value.lower().startswith("0x"):
            left, right = value.split(":", 1)
            found_any = False
            for part, label in ((left, "erster Teil"), (right, "zweiter Teil")):
                for algo_name in _identify_hex(part):
                    matches.append(
                        AlgorithmMatch(
                            name=f"{algo_name} ({label} von 'hash:salt'-Format)",
                            category="Generisch (hash:salt-Format)",
                            confidence="mehrdeutig",
                        )
                    )
                    found_any = True
            if found_any:
                salt_note = (
                    "Doppelpunkt-getrenntes Format erkannt (haeufig hash:salt, hash:hash oder "
                    "Ausgabe eines Cracking-Tools wie hashcat/John the Ripper)."
                )

        if not matches:
            for algo_name in _identify_hex(value):
                matches.append(
                    AlgorithmMatch(name=algo_name, category="Generisch (Laengen-basiert)", confidence="mehrdeutig")
                )

        if not matches:
            for pattern, name, category in _BASE64_PATTERNS:
                if pattern.match(value):
                    matches.append(AlgorithmMatch(name=name, category=category, confidence="mehrdeutig"))

        note = salt_note
        if not matches:
            note = (
                "Kein bekanntes Standardformat erkannt. Moeglich: Base64-kodierter Hash in unueblicher Laenge, "
                "proprietaeres/gesalzenes Format, oder kein Hash."
            )
        elif note is None and len(matches) > 1 and all(m.confidence == "mehrdeutig" for m in matches):
            note = (
                "Mehrere Algorithmen haben dieselbe Laenge bzw. dasselbe Zeichenformat -- ohne Kontext "
                "(z.B. Herkunftssystem, fuehrender Salt) ist keine eindeutige Zuordnung moeglich."
            )

        return self.Output(
            hash_value=value,
            length=length,
            possible_algorithms=[m.name for m in matches],
            matches=matches,
            note=note,
        )
