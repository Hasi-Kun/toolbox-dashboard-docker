"""NTLM-Hash-Generator -- berechnet den NTLM-Hash eines Passworts
(MD4(UTF-16LE(Passwort))), z.B. zum Nachschlagen/Vergleichen in Windows-
Authentifizierungskontexten oder Pentest-Berichten.

WICHTIG: OpenSSL 3.x deaktiviert MD4 standardmaessig im "default"-
Provider (als veraltet/gebrochen eingestuft), Python's hashlib bietet es
deshalb in dieser Umgebung nicht mehr an. NTLM selbst basiert aber
zwingend auf MD4 (so spezifiziert von Microsoft, nicht aenderbar) --
daher hier eine minimale, in sich geschlossene reine-Python-Implementierung
statt einer neuen Fremdabhaengigkeit (z.B. pycryptodome) nur fuer diesen
einen Anwendungsfall.
"""

import struct

from pydantic import BaseModel, field_validator

from app.modules.base import ToolModule, register_module


def _md4(data: bytes) -> bytes:
    """Minimale MD4-Implementierung nach RFC 1320 -- reines Python, keine
    Fremdabhaengigkeit. NUR fuer den NTLM-Anwendungsfall hier gedacht,
    MD4 ist fuer sich genommen kryptographisch gebrochen und sollte fuer
    NICHTS anderes verwendet werden."""

    def left_rotate(x: int, c: int) -> int:
        x &= 0xFFFFFFFF
        return ((x << c) | (x >> (32 - c))) & 0xFFFFFFFF

    def f(x, y, z):
        return (x & y) | (~x & z)

    def g(x, y, z):
        return (x & y) | (x & z) | (y & z)

    def h(x, y, z):
        return x ^ y ^ z

    a0, b0, c0, d0 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

    msg = bytearray(data)
    orig_len_bits = (8 * len(data)) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack("<Q", orig_len_bits)

    for chunk_start in range(0, len(msg), 64):
        chunk = msg[chunk_start:chunk_start + 64]
        x = list(struct.unpack("<16I", chunk))
        a, b, c, d = a0, b0, c0, d0

        # Runde 1
        s1 = [3, 7, 11, 19]
        for i in range(16):
            k = i
            if i % 4 == 0:
                a = left_rotate((a + f(b, c, d) + x[k]) & 0xFFFFFFFF, s1[0])
            elif i % 4 == 1:
                d = left_rotate((d + f(a, b, c) + x[k]) & 0xFFFFFFFF, s1[1])
            elif i % 4 == 2:
                c = left_rotate((c + f(d, a, b) + x[k]) & 0xFFFFFFFF, s1[2])
            else:
                b = left_rotate((b + f(c, d, a) + x[k]) & 0xFFFFFFFF, s1[3])

        # Runde 2
        s2 = [3, 5, 9, 13]
        order2 = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
        for i in range(16):
            k = order2[i]
            if i % 4 == 0:
                a = left_rotate((a + g(b, c, d) + x[k] + 0x5A827999) & 0xFFFFFFFF, s2[0])
            elif i % 4 == 1:
                d = left_rotate((d + g(a, b, c) + x[k] + 0x5A827999) & 0xFFFFFFFF, s2[1])
            elif i % 4 == 2:
                c = left_rotate((c + g(d, a, b) + x[k] + 0x5A827999) & 0xFFFFFFFF, s2[2])
            else:
                b = left_rotate((b + g(c, d, a) + x[k] + 0x5A827999) & 0xFFFFFFFF, s2[3])

        # Runde 3
        s3 = [3, 9, 11, 15]
        order3 = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
        for i in range(16):
            k = order3[i]
            if i % 4 == 0:
                a = left_rotate((a + h(b, c, d) + x[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s3[0])
            elif i % 4 == 1:
                d = left_rotate((d + h(a, b, c) + x[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s3[1])
            elif i % 4 == 2:
                c = left_rotate((c + h(d, a, b) + x[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s3[2])
            else:
                b = left_rotate((b + h(c, d, a) + x[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s3[3])

        a0 = (a0 + a) & 0xFFFFFFFF
        b0 = (b0 + b) & 0xFFFFFFFF
        c0 = (c0 + c) & 0xFFFFFFFF
        d0 = (d0 + d) & 0xFFFFFFFF

    return struct.pack("<4I", a0, b0, c0, d0)


def ntlm_hash(password: str) -> str:
    return _md4(password.encode("utf-16-le")).hex()


@register_module
class NtlmHashGeneratorModule(ToolModule):
    slug = "ntlm-hash-generator"
    category = "utilities"
    name = "NTLM-Hash-Generator"
    description = (
        "Berechnet den NTLM-Hash (MD4 des UTF-16LE-codierten Passworts) eines Passworts -- z.B. "
        "zum Abgleich in Pentest-Berichten oder Windows-Authentifizierungskontexten. Das Passwort "
        "wird nicht gespeichert/geloggt."
    )
    is_active_scan = False
    timeout_seconds = 5
    redact_input_in_history = True  # Passwort darf nie in der Tool-Historie landen

    class Input(BaseModel):
        password: str

        @field_validator("password")
        @classmethod
        def validate_password(cls, v: str) -> str:
            if len(v) > 1024:
                raise ValueError("Eingabe zu lang (max. 1024 Zeichen)")
            return v

    class Output(BaseModel):
        ntlm_hash: str

    async def run(self, data: Input) -> Output:
        return self.Output(ntlm_hash=ntlm_hash(data.password))
